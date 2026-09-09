// Host OS interfaces shared by the CLI and its helpers. Linux keeps its
// syscall implementation; Darwin uses libc/libproc, never Linux syscall IDs.
const std = @import("std");
pub const darwin = @import("builtin").os.tag == .macos;
pub const getpid = std.c.getpid;
pub const getuid = std.c.getuid;
pub const getgid = std.c.getgid;

pub fn lockHeld(fd: std.posix.fd_t) !bool {
    if (std.c.flock(fd, 2 | 4) == 0) return false; // LOCK_EX | LOCK_NB
    if (std.c._errno().* == @intFromEnum(std.posix.E.AGAIN)) return true;
    return error.CannotInspectLaunchLock;
}

pub const PathStat = struct { gid: u32, ino: u64 };
pub fn statPath(path: [*:0]const u8) !PathStat {
    if (darwin) {
        var st: std.c.Stat = undefined;
        if (std.c.fstatat(std.posix.AT.FDCWD, path, &st, 0) != 0) return error.StatFailed;
        return .{ .gid = st.gid, .ino = st.ino };
    } else {
        var st: std.os.linux.Statx = undefined;
        if (std.os.linux.statx(std.posix.AT.FDCWD, path, 0, .{ .GID = true, .INO = true }, &st) != 0) return error.StatFailed;
        return .{ .gid = st.gid, .ino = st.ino };
    }
}

extern "c" fn cogbox_process(c_int, *u64, *c_int, *c_int) c_int;

pub const Process = struct { start: u64, parent: std.posix.pid_t, zombie: bool };
pub fn process(pid: std.posix.pid_t) !Process {
    if (!darwin) @compileError("libproc is only used on Darwin");
    var start: u64 = undefined;
    var parent: c_int = undefined;
    var zombie: c_int = undefined;
    if (cogbox_process(pid, &start, &parent, &zombie) != 0) {
        if (std.c._errno().* == @intFromEnum(std.posix.E.SRCH)) return error.ProcessExited;
        return error.CannotInspectProcess;
    }
    return .{ .start = start, .parent = parent, .zombie = zombie != 0 };
}

// A stop request is addressed to the launch nonce. The launcher consumes it
// itself, so there is no check-then-kill PID reuse race on systems without pidfd.
pub fn requestStop(path: [*:0]const u8, request: []const u8) !void {
    const flags: std.c.O = .{ .ACCMODE = .WRONLY, .NONBLOCK = true, .CLOEXEC = true };
    const fd = std.c.open(path, flags);
    if (fd < 0) return error.CannotOpenLauncher;
    defer _ = std.c.close(fd);
    if (std.c.write(fd, request.ptr, request.len) != request.len) return error.CannotSignalLauncher;
}

// Small shell-facing Darwin helpers, installed separately from the CLI.
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) return error.InvalidArguments;
    var buf: [256]u8 = undefined;
    const out = if (std.mem.eql(u8, args[1], "uuid")) blk: {
        var bytes: [16]u8 = undefined;
        init.io.random(&bytes);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        break :blk try std.fmt.bufPrint(&buf, "{x}-{x}-{x}-{x}-{x}\n", .{
            bytes[0..4], bytes[4..6], bytes[6..8], bytes[8..10], bytes[10..16],
        });
    } else if (std.mem.eql(u8, args[1], "now"))
        try std.fmt.bufPrint(&buf, "{d}\n", .{@divTrunc(std.Io.Timestamp.now(init.io, .awake).nanoseconds, 10_000_000)})
    else if (std.mem.eql(u8, args[1], "process") and args.len == 3) blk: {
        const p = process(try std.fmt.parseInt(std.posix.pid_t, args[2], 10)) catch |err| {
            if (err == error.ProcessExited) std.process.exit(3);
            return err;
        };
        break :blk try std.fmt.bufPrint(&buf, "{d} {d} {d}\n", .{ p.start, p.parent, @intFromBool(p.zombie) });
    } else if (std.mem.eql(u8, args[1], "flock") and args.len == 5 and std.mem.eql(u8, args[2], "-w")) blk: {
        const seconds = try std.fmt.parseFloat(f64, args[3]);
        const fd = try std.fmt.parseInt(std.posix.fd_t, args[4], 10);
        const start = std.Io.Timestamp.now(init.io, .awake);
        while (try lockHeld(fd)) {
            if (start.durationTo(std.Io.Timestamp.now(init.io, .awake)).toMilliseconds() >= @as(i64, @intFromFloat(seconds * 1000))) std.process.exit(1);
            try std.Io.sleep(init.io, .fromMilliseconds(10), .awake);
        }
        break :blk "";
    } else return error.InvalidArguments;
    var wbuf: [256]u8 = undefined;
    var writer = std.Io.File.stdout().writer(init.io, &wbuf);
    try writer.interface.writeAll(out);
    try writer.interface.flush();
}
