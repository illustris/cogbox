// `cogbox start` - the default launch verb (bare `cogbox` dispatches here).
//
// Always launches the VM as a background daemon, then -- depending on flags --
// hands the terminal to the guest:
//   default        wait for the guest's sshd, then exec `ssh` into it.
//   -f/--foreground attach the serial console (Ctrl-] detaches, VM keeps running).
//   --no-ssh       print how to connect and return, leaving the VM in the bg.
//
// Flow:
//   1. Validate args (shares run.zig::validate).
//   2. Refuse if an instance with this name is already running.
//   3. Run the launch script with --init-only in the FOREGROUND so first-run
//      prompts (harness selection, path creation) are interactive and any
//      custom-flake runner build happens where the user can see it.
//   4. fork(). Child: setsid, redirect stdio to <runtime>/cogbox.log, exec
//      the launch script in full-launch mode (passt + QEMU). QEMU's serial
//      console and HMP monitor are on <runtime>/{console,monitor}.sock.
//   5. Parent: wait for <runtime>/qemu.pid (proof QEMU launched) or daemon
//      death. Then, per the flags: probe the forwarded SSH port until sshd
//      sends its banner and exec `ssh` (default); attach the console (-f); or
//      print how to connect and return (--no-ssh).

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");
const launch = @import("../launch.zig");
const attach = @import("../attach.zig");
const run_verb = @import("run.zig");
const ssh = @import("ssh.zig");
const stop = @import("stop.zig");

extern "c" fn fork() c_int;
extern "c" fn setsid() c_int;
extern "c" fn execv(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;
extern "c" fn dup2(oldfd: c_int, newfd: c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn waitpid(pid: c_int, status: *c_int, options: c_int) c_int;
extern "c" fn _exit(code: c_int) noreturn;

const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;
const O_RDONLY: c_int = 0;
const WNOHANG: c_int = 1;

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *std.process.Environ.Map,
    p: *const paths.Paths,
    argv: []const []const u8,
) !void {
    const flags = [_]parse.Flag{
        .{ .long = "name", .short = 'n', .kind = .value },
        .{ .long = "vcpu", .kind = .value },
        .{ .long = "mem", .kind = .value },
        .{ .long = "network", .kind = .value },
        .{ .long = "add-dir", .kind = .value_multi },
        .{ .long = "add-dir-ro", .kind = .value_multi },
        .{ .long = "no-auto-keys", .kind = .bool },
        .{ .long = "yes", .short = 'y', .kind = .bool },
        .{ .long = "foreground", .short = 'f', .kind = .bool },
        .{ .long = "no-ssh", .kind = .bool },
        .{ .long = "help", .short = 'h', .kind = .bool },
    };
    var parsed = parse.parse(allocator, io, .{ .verb = "start", .flags = &flags }, argv);
    defer parsed.deinit();

    if (parsed.isSet("help")) {
        try help.print(io, help.START);
        return;
    }

    const opts = try run_verb.validate(&parsed, allocator, io, "start");

    const inst_runtime = try paths.instanceRuntime(allocator, p, opts.name);
    defer allocator.free(inst_runtime);
    if (try isRunning(allocator, io, inst_runtime)) {
        util.die(allocator, io, "start", exit_codes.tempfail, "instance is already running. Use 'cogbox stop' first, 'cogbox restart', or attach with 'cogbox console'.", .{});
    }

    const script_path = try launch.resolveScriptPath(allocator, io, env);
    defer allocator.free(script_path);

    // Step 1: foreground, interactive init. Seeds first-run state and warms
    // any custom-flake build. Exits non-zero if the user aborts.
    {
        const init_argv = try launch.buildLaunchArgs(allocator, opts, script_path, true);
        defer {
            for (init_argv) |a| allocator.free(a);
            allocator.free(init_argv);
        }
        const code = forkExecWait(allocator, init_argv);
        if (code != 0) std.process.exit(code);
    }

    // Step 2: daemonize the actual launch.
    const launch_argv = try launch.buildLaunchArgs(allocator, opts, script_path, false);
    defer {
        for (launch_argv) |a| allocator.free(a);
        allocator.free(launch_argv);
    }

    std.Io.Dir.cwd().createDirPath(io, inst_runtime) catch {};
    const log_path = try std.fs.path.join(allocator, &.{ inst_runtime, "cogbox.log" });
    defer allocator.free(log_path);

    const pid = fork();
    if (pid < 0) {
        util.die(allocator, io, "start", exit_codes.software, "fork failed", .{});
    }

    if (pid == 0) {
        // Child: detach into its own session. The bash script writes its own
        // pid (after re-exec, the post-re-exec bash) to <runtime>/pid, which
        // is what `cogbox stop` signals.
        _ = setsid();

        const log_z = allocator.dupeZ(u8, log_path) catch _exit(70);
        const devnull_z = allocator.dupeZ(u8, "/dev/null") catch _exit(70);
        const fd_in = open(devnull_z.ptr, O_RDONLY, 0);
        if (fd_in >= 0) {
            _ = dup2(fd_in, 0);
            _ = close(fd_in);
        }
        const fd_log = open(log_z.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
        if (fd_log >= 0) {
            _ = dup2(fd_log, 1);
            _ = dup2(fd_log, 2);
            _ = close(fd_log);
        }

        const argv_z = allocator.alloc(?[*:0]const u8, launch_argv.len + 1) catch _exit(70);
        for (launch_argv, 0..) |a, i| {
            argv_z[i] = (allocator.dupeZ(u8, a) catch _exit(70)).ptr;
        }
        argv_z[launch_argv.len] = null;
        const prog_z = allocator.dupeZ(u8, launch_argv[0]) catch _exit(70);
        const argv_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(argv_z.ptr);
        _ = execv(prog_z.ptr, argv_ptr);
        _exit(70);
    }

    // Parent: require a live QEMU child of THIS launch. A retained qemu.pid
    // from the previous run is not readiness while the new daemon initializes.
    const console_sock = try std.fs.path.join(allocator, &.{ inst_runtime, "console.sock" });
    defer allocator.free(console_sock);

    const cwd = std.Io.Dir.cwd();
    if (!waitForQemuOrDeath(allocator, io, pid, inst_runtime, 60_000)) {
        dieVmFailure(allocator, io, log_path, "VM did not come up.");
    }

    if (opts.foreground) {
        // console.sock can lag qemu.pid by a moment; poll briefly. If the
        // instance has no serial console at all, report rather than hang.
        if (!waitForFileOrDeath(io, pid, cwd, console_sock, 15_000)) {
            util.die(allocator, io, "start", exit_codes.software, "serial console did not become available (the VM is running; check {s}).", .{log_path});
        }
        const console_log = try std.fs.path.join(allocator, &.{ inst_runtime, "console.log" });
        defer allocator.free(console_log);
        attach.attach(allocator, io, .console, console_sock, opts.name orelse "default", console_log) catch |err| {
            util.die(allocator, io, "start", exit_codes.software, "could not attach console: {s} (VM is running; try 'cogbox console')", .{@errorName(err)});
        };
        return;
    }

    if (!opts.no_ssh) {
        // Default: wait for the guest's sshd to come up, then hand the terminal
        // to ssh. The VM is already a detached daemon, so exec'ing ssh over this
        // process is safe -- when ssh exits the user is back at their shell and
        // the VM keeps running. Ctrl-C during the wait also just leaves it up.
        const endpoint = ssh.readEndpoint(allocator, io, inst_runtime) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => util.die(allocator, io, "start", exit_codes.software, "VM is running but its SSH endpoint is unavailable ({s}); connect manually with 'cogbox ssh'.", .{@errorName(err)}),
        };
        defer endpoint.deinit(allocator);

        const label = opts.name orelse "default";
        const status_msg = try std.fmt.allocPrint(
            allocator,
            "cogbox: '{s}' started in the background; waiting for SSH... (Ctrl-C leaves it running; reconnect with 'cogbox ssh')\n",
            .{label},
        );
        defer allocator.free(status_msg);
        try util.writeStderr(io, status_msg);

        const ssh_wait_ms: i64 = 180_000;
        if (!ssh.waitForSshOrDeath(io, pid, endpoint.host, endpoint.port, ssh_wait_ms)) {
            var dead: c_int = 0;
            if (waitpid(pid, &dead, WNOHANG) == pid) {
                dieVmFailure(allocator, io, log_path, "VM exited during boot.");
            }
            util.die(allocator, io, "start", exit_codes.software, "SSH did not become available within {d}s (the VM is still running; check {s}, then 'cogbox ssh').", .{ @divTrunc(ssh_wait_ms, 1000), log_path });
        }

        const identity = ssh.defaultIdentity(allocator, io, p);
        ssh.exec(allocator, endpoint, identity, &.{}) catch |err| {
            util.die(allocator, io, "start", exit_codes.software, "could not exec ssh: {s} (VM is running; try 'cogbox ssh')", .{@errorName(err)});
        };
        return;
    }

    // --no-ssh: print how to attach and return, leaving the VM in the background.
    const label = opts.name orelse "default";
    const name_arg: []const u8 = if (opts.name) |n|
        try std.fmt.allocPrint(allocator, " -n {s}", .{n})
    else
        try allocator.dupe(u8, "");
    defer allocator.free(name_arg);
    try util.say(
        allocator,
        io,
        "Started '{s}' in the background.\n  ssh:     cogbox ssh{s}\n  console: cogbox console{s}\n  monitor: cogbox monitor{s}\n  logs:    {s}",
        .{ label, name_arg, name_arg, name_arg, log_path },
    );
}

/// fork + execv(argv) inheriting this process's stdio (terminal), then
/// waitpid. Returns the child's exit code (or 70 on fork/exec failure).
fn forkExecWait(allocator: std.mem.Allocator, argv: []const []const u8) u8 {
    const pid = fork();
    if (pid < 0) return 70;
    if (pid == 0) {
        const argv_z = allocator.alloc(?[*:0]const u8, argv.len + 1) catch _exit(70);
        for (argv, 0..) |a, i| {
            argv_z[i] = (allocator.dupeZ(u8, a) catch _exit(70)).ptr;
        }
        argv_z[argv.len] = null;
        const prog_z = allocator.dupeZ(u8, argv[0]) catch _exit(70);
        const argv_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(argv_z.ptr);
        _ = execv(prog_z.ptr, argv_ptr);
        _exit(70);
    }
    var status: c_int = 0;
    while (true) {
        const r = waitpid(pid, &status, 0);
        if (r == pid) break;
        if (r < 0) return 70;
    }
    // WIFEXITED && WEXITSTATUS
    if (status & 0x7f == 0) return @intCast((status >> 8) & 0xff);
    return 70; // killed by signal
}

/// Poll for `path` to appear, returning true when it does. Returns false if
/// the daemon `pid` exits first (reaped via WNOHANG, so it never lingers as a
/// zombie that kill(pid,0) would misreport as alive) or the timeout elapses.
fn waitForFileOrDeath(io: std.Io, pid: c_int, cwd: std.Io.Dir, path: []const u8, max_wait_ms: i64) bool {
    const step_ms: i64 = 200;
    var waited: i64 = 0;
    while (waited < max_wait_ms) : (waited += step_ms) {
        _ = std.Io.sleep(io, std.Io.Duration.fromMilliseconds(step_ms), .awake) catch {};
        var status: c_int = 0;
        if (waitpid(pid, &status, WNOHANG) == pid) return false; // daemon exited
        cwd.access(io, path, .{}) catch continue;
        return true;
    }
    return false;
}

fn waitForQemuOrDeath(allocator: std.mem.Allocator, io: std.Io, pid: c_int, runtime: []const u8, max_wait_ms: i64) bool {
    const began = std.Io.Timestamp.now(io, .awake);
    while (began.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds() < max_wait_ms) {
        _ = std.Io.sleep(io, std.Io.Duration.fromMilliseconds(200), .awake) catch {};
        var status: c_int = 0;
        if (waitpid(pid, &status, WNOHANG) == pid) return false;
        if (stop.ownsReadyChild(allocator, io, runtime, pid)) return true;
    }
    return false;
}

/// Report a boot failure, inlining the tail of the daemon log so the real
/// cause (e.g. "L7 proxy failed to bind 127.0.0.1:18443") is visible in the
/// terminal -- not just pointed at via a path. The launcher now preserves
/// cogbox.log on a failed start, so the tail is reliably present. `reason` is
/// a comptime literal so it can be concatenated into the format string.
fn dieVmFailure(allocator: std.mem.Allocator, io: std.Io, log_path: []const u8, comptime reason: []const u8) noreturn {
    const tail = logTail(allocator, io, log_path);
    if (tail.len > 0) {
        util.die(allocator, io, "start", exit_codes.software, reason ++ " Last lines of {s}:\n{s}", .{ log_path, tail });
    }
    util.die(allocator, io, "start", exit_codes.software, reason ++ " See {s} for details.", .{log_path});
}

/// Read up to the last ~15 lines of `path`. Returns an owned slice, or "" when
/// the file is missing/unreadable (caller treats "" as "no detail available").
/// We seek to a fixed-size tail window first so a large log still yields its
/// last lines -- allocRemaining errors out (returning nothing) once a limit is
/// exceeded, so reading the whole file would silently drop the tail on big logs.
fn logTail(allocator: std.mem.Allocator, io: std.Io, path: []const u8) []const u8 {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return "";
    defer file.close(io);
    const window: u64 = 16 * 1024;
    var buf: [16 * 1024]u8 = undefined;
    var reader = file.reader(io, &buf);
    const size = reader.getSize() catch return "";
    if (size > window) reader.seekTo(size - window) catch return "";
    // Reading from the (possibly seeked) position to EOF spans at most `window`
    // bytes, so the limit is never hit and allocRemaining returns the data.
    const data = reader.interface.allocRemaining(allocator, .limited(window + 1)) catch return "";
    const trimmed = std.mem.trim(u8, data, " \t\r\n");
    const max_lines: usize = 15;
    var seen: usize = 0;
    var idx: usize = trimmed.len;
    while (idx > 0) : (idx -= 1) {
        if (trimmed[idx - 1] == '\n') {
            seen += 1;
            if (seen >= max_lines) break;
        }
    }
    return trimmed[idx..];
}

fn isRunning(allocator: std.mem.Allocator, io: std.Io, runtime: []const u8) !bool {
    // The kernel-held lifetime lock covers the launcher AND surviving children.
    // A PID file alone cannot distinguish a dead launch from unrelated PID reuse.
    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{runtime});
    defer allocator.free(lock_path);
    const file = std.Io.Dir.cwd().openFile(io, lock_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer file.close(io);
    const linux = std.os.linux;
    return switch (linux.errno(linux.flock(file.handle, 2 | 4))) { // LOCK_EX | LOCK_NB
        .SUCCESS => false,
        .AGAIN => true,
        else => error.CannotInspectLaunchLock,
    };
}
