// Raw-tty <-> Unix-socket pump shared by `cogbox console` and
// `cogbox monitor`.
//
// Connects to a QEMU character-device socket (the guest serial console
// at <runtime>/console.sock, or the HMP monitor at <runtime>/monitor.sock),
// puts the controlling terminal into raw mode, and shuttles bytes both
// directions until the user hits the detach key (Ctrl-], 0x1d) or the
// socket closes. Detaching leaves the VM running in the background -- it is
// just a local disconnect, the daemon is untouched.
//
// The pump deliberately uses blocking posix syscalls (poll/read/write)
// rather than the std.Io async model: it is a tight two-fd relay and the
// raw byte handling (escape scanning, \r\n framing) is clearest at the
// syscall level. File reads for history replay go through std.Io to match
// the rest of the CLI.

const std = @import("std");
const posix = std.posix;

// Socket/close/write are not in std.posix on this Zig; use libc (we link it).
extern "c" fn connect(fd: c_int, addr: *const anyopaque, len: c_uint) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;

/// Ctrl-] -- the detach key. Telnet-style, rarely typed into a shell, so it
/// is a low-collision escape. A literal Ctrl-] cannot be sent to the guest;
/// that is an accepted trade-off for a single-key detach.
const DETACH_BYTE: u8 = 0x1d;

/// Saved terminal state for the signal-driven restore path. A SIGTERM/HUP/
/// QUIT while in raw mode would otherwise leave the user's shell unusable.
var g_orig_termios: ?posix.termios = null;
var g_stdin_fd: posix.fd_t = posix.STDIN_FILENO;

extern "c" fn _exit(code: c_int) noreturn;

fn restoreOnSignal(_: posix.SIG) callconv(.c) void {
    if (g_orig_termios) |t| posix.tcsetattr(g_stdin_fd, .FLUSH, t) catch {};
    // 128 + signal-ish; value is not inspected by callers.
    _exit(130);
}

pub const Target = enum { console, monitor };

/// Attach to `socket_path` and relay until detach or close.
/// `label` is the instance name shown in the banner. When `replay_log` is
/// non-null its tail is dumped before going live (serial history).
pub fn attach(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: Target,
    socket_path: []const u8,
    label: []const u8,
    replay_log: ?[]const u8,
) !void {
    // A write to the socket after QEMU has gone would otherwise raise SIGPIPE
    // and kill us mid-pump, leaving the terminal in raw mode. Ignore it; the
    // failed write surfaces as a short write and the next poll sees EOF/HUP.
    ignoreSigpipe();

    // Snapshot the serial-log end offset BEFORE connecting. The socket stream
    // and the logfile are the same bytes, so replaying the tail only up to
    // this point avoids duplicating the lines the live socket is about to
    // deliver.
    const replay_end: ?u64 = if (replay_log) |p| logSize(io, p) else null;

    // Connect first: anything the guest emits between now and the live pump
    // is buffered by the kernel on the socket, so nothing is lost across the
    // history replay below.
    const sock = connectUnix(socket_path) catch |err| {
        printErr(allocator, "could not connect to {s}: {s}", .{ socket_path, @errorName(err) });
        return error.ConnectFailed;
    };
    defer _ = close(sock);

    const stdin_fd = posix.STDIN_FILENO;
    const stdout_fd = posix.STDOUT_FILENO;
    g_stdin_fd = stdin_fd;

    // Raw mode on the controlling terminal. If stdin is not a tty (piped or
    // redirected) we run in cooked passthrough -- still useful for scripted
    // monitor commands like `echo info status | cogbox monitor`.
    const orig: ?posix.termios = blk: {
        const t = posix.tcgetattr(stdin_fd) catch break :blk null;
        var raw = t;
        raw.lflag.ECHO = false;
        raw.lflag.ECHONL = false;
        raw.lflag.ICANON = false;
        raw.lflag.ISIG = false; // Ctrl-C / Ctrl-\ pass through to the guest
        raw.lflag.IEXTEN = false;
        raw.iflag.IXON = false; // Ctrl-S / Ctrl-Q pass through
        raw.iflag.ICRNL = false; // deliver CR as CR, not translated to NL
        raw.iflag.INLCR = false;
        raw.iflag.IGNCR = false;
        raw.iflag.BRKINT = false;
        raw.oflag.OPOST = false; // don't post-process guest output
        raw.cc[@intFromEnum(posix.V.MIN)] = 1;
        raw.cc[@intFromEnum(posix.V.TIME)] = 0;
        posix.tcsetattr(stdin_fd, .FLUSH, raw) catch break :blk null;
        g_orig_termios = t;
        break :blk t;
    };
    defer if (orig) |t| posix.tcsetattr(stdin_fd, .FLUSH, t) catch {};

    if (orig != null) installRestoreHandlers();

    banner(target, label);

    if (replay_log) |p| {
        if (replay_end) |end| replayRange(io, stdout_fd, p, end);
    }

    var fds = [_]posix.pollfd{
        .{ .fd = stdin_fd, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = sock, .events = posix.POLL.IN, .revents = 0 },
    };
    var buf: [4096]u8 = undefined;

    while (true) {
        _ = posix.poll(&fds, -1) catch break;

        // Socket -> stdout.
        if (fds[1].revents & (posix.POLL.IN | posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) {
            const n = posix.read(sock, &buf) catch 0;
            if (n == 0) {
                if (orig) |t| posix.tcsetattr(stdin_fd, .FLUSH, t) catch {};
                writeAll(posix.STDERR_FILENO, "\r\n[connection closed -- the VM may have stopped]\r\n");
                return;
            }
            writeAll(stdout_fd, buf[0..n]);
        }

        // Stdin -> socket, watching for the detach key.
        // Darwin reports POLLNVAL for non-pollable input such as /dev/null.
        // Read it once to observe EOF/error instead of spinning on that event.
        if (fds[0].revents & (posix.POLL.IN | posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) {
            const n = posix.read(stdin_fd, &buf) catch 0;
            if (n == 0) break; // our stdin hit EOF -> detach
            if (std.mem.indexOfScalar(u8, buf[0..n], DETACH_BYTE)) |idx| {
                if (idx > 0) writeAll(sock, buf[0..idx]);
                break;
            }
            writeAll(sock, buf[0..n]);
        }
    }

    if (orig) |t| posix.tcsetattr(stdin_fd, .FLUSH, t) catch {};
    writeAll(posix.STDERR_FILENO, "\r\n[detached -- VM still running in the background]\r\n");
}

fn banner(target: Target, label: []const u8) void {
    const what = switch (target) {
        .console => "serial console",
        .monitor => "QEMU monitor",
    };
    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(
        &buf,
        "[attached to {s} of '{s}' -- detach: Ctrl-]]\r\n",
        .{ what, label },
    ) catch return;
    writeAll(posix.STDERR_FILENO, msg);
}

fn installRestoreHandlers() void {
    var act: posix.Sigaction = std.mem.zeroes(posix.Sigaction);
    act.handler.handler = restoreOnSignal;
    posix.sigaction(posix.SIG.TERM, &act, null);
    posix.sigaction(posix.SIG.HUP, &act, null);
    posix.sigaction(posix.SIG.QUIT, &act, null);
    // Ctrl-C passes through to the guest (ISIG off), but an external SIGINT
    // should still restore the terminal rather than leave it raw.
    posix.sigaction(posix.SIG.INT, &act, null);
}

fn ignoreSigpipe() void {
    var act: posix.Sigaction = std.mem.zeroes(posix.Sigaction);
    act.handler.handler = posix.SIG.IGN;
    posix.sigaction(posix.SIG.PIPE, &act, null);
}

fn connectUnix(path: []const u8) !posix.fd_t {
    var addr = posix.sockaddr.un{ .family = posix.AF.UNIX, .path = undefined };
    if (path.len >= addr.path.len) return error.PathTooLong;
    @memset(&addr.path, 0);
    @memcpy(addr.path[0..path.len], path);

    const fd = try @import("platform").streamSocket(posix.AF.UNIX);
    errdefer _ = close(fd);
    const len: c_uint = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + 1);
    if (connect(fd, @ptrCast(&addr), len) != 0) return error.ConnectFailed;
    return fd;
}

/// Size of `path` right now, or null if it can't be stat'd.
fn logSize(io: std.Io, path: []const u8) ?u64 {
    const cwd = std.Io.Dir.cwd();
    const file = cwd.openFile(io, path, .{}) catch return null;
    defer file.close(io);
    const st = file.stat(io) catch return null;
    return st.size;
}

/// Dump roughly the last `TAIL_BYTES` of the serial log to `out_fd`, but only
/// up to byte offset `end` (a size snapshot taken before connecting), so the
/// replayed history does not overlap the live socket stream. Best-effort: any
/// failure (missing file, short read) just skips replay.
fn replayRange(io: std.Io, out_fd: posix.fd_t, path: []const u8, end: u64) void {
    const TAIL_BYTES: u64 = 64 * 1024;
    if (end == 0) return;
    const cwd = std.Io.Dir.cwd();
    const file = cwd.openFile(io, path, .{}) catch return;
    defer file.close(io);

    const start: u64 = if (end > TAIL_BYTES) end - TAIL_BYTES else 0;
    if (start > 0) _ = std.c.lseek(file.handle, @intCast(start), posix.SEEK.SET);

    var remaining: u64 = end - start;
    var buf: [4096]u8 = undefined;
    while (remaining > 0) {
        const want: usize = @intCast(@min(remaining, buf.len));
        const n = posix.read(file.handle, buf[0..want]) catch break;
        if (n == 0) break;
        writeAll(out_fd, buf[0..n]);
        remaining -= n;
    }
}

fn writeAll(fd: posix.fd_t, bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = write(fd, bytes.ptr + off, bytes.len - off);
        if (n <= 0) return;
        off += @intCast(n);
    }
}

fn printErr(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) void {
    const msg = std.fmt.allocPrint(allocator, "cogbox: error: " ++ fmt ++ "\n", args) catch return;
    defer allocator.free(msg);
    writeAll(posix.STDERR_FILENO, msg);
}
