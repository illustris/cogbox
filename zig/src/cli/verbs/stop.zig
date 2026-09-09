// `cogbox stop`: request child-first shutdown and wait for a fenced outcome.

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");
const linux = std.os.linux;

const Identity = struct {
    nonce: [36]u8,
    pid: std.posix.pid_t,
    start: u64,

    fn same(a: Identity, b: Identity) bool {
        return a.pid == b.pid and a.start == b.start and std.mem.eql(u8, &a.nonce, &b.nonce);
    }
};

const Record = struct { identity: Identity, outcome: ?[]const u8 };

fn parseRecord(data: []const u8, result: bool) !Record {
    var words = std.mem.tokenizeAny(u8, data, " \r\n");
    if (!std.mem.eql(u8, words.next() orelse return error.InvalidRecord, "v1")) return error.InvalidRecord;
    const nonce = words.next() orelse return error.InvalidRecord;
    if (nonce.len != 36) return error.InvalidRecord;
    for (nonce, 0..) |c, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (c != '-') return error.InvalidRecord;
        } else if (!std.ascii.isHex(c)) return error.InvalidRecord;
    }
    const pid = try std.fmt.parseInt(std.posix.pid_t, words.next() orelse return error.InvalidRecord, 10);
    const start = try std.fmt.parseInt(u64, words.next() orelse return error.InvalidRecord, 10);
    if (pid <= 1 or start == 0) return error.InvalidRecord;
    const outcome = words.next();
    if (result) {
        const o = outcome orelse return error.InvalidRecord;
        if (!std.mem.eql(u8, o, "graceful") and !std.mem.eql(u8, o, "unverified") and !std.mem.eql(u8, o, "forced") and
            !std.mem.eql(u8, o, "already-stopped") and !std.mem.eql(u8, o, "failed") and
            !std.mem.eql(u8, o, "exited") and !std.mem.eql(u8, o, "start-failed")) return error.InvalidRecord;
    } else if (outcome != null) return error.InvalidRecord;
    if (words.next() != null) return error.InvalidRecord;
    return .{ .identity = .{ .nonce = nonce[0..36].*, .pid = pid, .start = start }, .outcome = outcome };
}

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    p: *const paths.Paths,
    argv: []const []const u8,
) !void {
    const flags = [_]parse.Flag{
        .{ .long = "name", .short = 'n', .kind = .value },
        .{ .long = "force", .kind = .bool },
        .{ .long = "help", .short = 'h', .kind = .bool },
    };
    var parsed = parse.parse(allocator, io, .{ .verb = "stop", .flags = &flags }, argv);
    defer parsed.deinit();

    if (parsed.isSet("help")) {
        try help.print(io, help.STOP);
        return;
    }

    const name = nameFlag(&parsed, allocator, io);
    const force = parsed.isSet("force");

    const inst_runtime = try paths.instanceRuntime(allocator, p, name);
    defer allocator.free(inst_runtime);
    const pid_path = try std.fs.path.join(allocator, &.{ inst_runtime, "pid" });
    defer allocator.free(pid_path);

    const launch_path = try std.fs.path.join(allocator, &.{ inst_runtime, "launch" });
    defer allocator.free(launch_path);
    const result_path = try std.fs.path.join(allocator, &.{ inst_runtime, "stop-result" });
    defer allocator.free(result_path);
    const launch_data = readSmall(allocator, io, launch_path, 192) catch |err| switch (err) {
        error.FileNotFound => null, // Compatibility with a pre-protocol launcher.
        else => return err,
    };
    defer if (launch_data) |data| allocator.free(data);
    const identity = if (launch_data) |data| (try parseRecord(data, false)).identity else null;
    const pid = readPid(allocator, io, pid_path) catch |err| switch (err) {
        error.FileNotFound => if (identity) |id| id.pid else {
            try reportNotRunning(allocator, io, name);
            return;
        },
        else => return err,
    };
    if (identity) |id| {
        if (id.pid != pid) return error.ChangedLaunch;
    }
    const start = processStart(allocator, io, pid) catch |err| switch (err) {
        error.FileNotFound, error.ProcessExited => return reportCompleted(allocator, io, result_path, identity),
        else => return err,
    };
    if (identity) |id| {
        // A retained completed run may outlive its PID. Never signal the
        // unrelated replacement; only its matching terminal record can make
        // this an idempotent completed stop. Missing/failed records still fail.
        if (id.start != start) return reportCompleted(allocator, io, result_path, identity);
    }
    // Linux signals through a pidfd. Darwin sends a nonce-bound request that
    // the launcher consumes itself; neither path signals a potentially reused PID.
    if (@import("platform").darwin) {
        const id = identity orelse return error.MissingLaunchIdentity;
        const control = try std.fmt.allocPrintSentinel(allocator, "{s}/control", .{inst_runtime}, 0);
        defer allocator.free(control);
        const request = try std.fmt.allocPrint(allocator, "{s} {s}\n", .{id.nonce, if (force) "force" else "stop"});
        defer allocator.free(request);
        try @import("platform").requestStop(control, request);
    } else {
        const opened = linux.pidfd_open(pid, 0);
        if (linux.errno(opened) == .SRCH) return reportCompleted(allocator, io, result_path, identity);
        if (linux.errno(opened) != .SUCCESS) return error.CannotOpenLauncher;
        const pidfd: std.posix.fd_t = @intCast(opened);
        defer _ = linux.close(pidfd);
        const verified = processStart(allocator, io, pid) catch |err| switch (err) {
            error.FileNotFound, error.ProcessExited => return reportCompleted(allocator, io, result_path, identity),
            else => return err,
        };
        if (verified != start) return reportCompleted(allocator, io, result_path, identity);
        const signal = if (force and identity != null) std.posix.SIG.USR1 else std.posix.SIG.TERM;
        const sent = linux.errno(linux.pidfd_send_signal(pidfd, signal, null, 0));
        if (sent == .SRCH) return reportCompleted(allocator, io, result_path, identity);
        if (sent != .SUCCESS) return error.CannotSignalLauncher;
    }

    const max_wait_ms: i64 = 65_000;
    const step_ms: i64 = 100;
    const began = std.Io.Timestamp.now(io, .awake);
    while (began.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds() < max_wait_ms) {
        _ = std.Io.sleep(io, std.Io.Duration.fromMilliseconds(step_ms), .awake) catch {};
        const current = processStart(allocator, io, pid) catch |err| switch (err) {
            error.FileNotFound, error.ProcessExited => null,
            else => return err,
        };
        if (current) |value| {
            if (value != start) return reportCompleted(allocator, io, result_path, identity);
            continue;
        }
        return reportCompleted(allocator, io, result_path, identity);
    }
    util.die(allocator, io, "stop", exit_codes.software, "launcher did not finish shutdown within 65s; termination is unconfirmed", .{});
}

fn reportCompleted(allocator: std.mem.Allocator, io: std.Io, result_path: []const u8, identity: ?Identity) !void {
    if (identity) |expected| {
        const data = readSmall(allocator, io, result_path, 192) catch |err| switch (err) {
            error.FileNotFound => return error.MissingShutdownResult,
            else => return err,
        };
        defer allocator.free(data);
        const record = try parseRecord(data, true);
        if (!record.identity.same(expected)) return error.ChangedLaunch;
        const outcome = record.outcome.?;
        if (std.mem.eql(u8, outcome, "failed")) return error.ShutdownUnconfirmed;
        if (std.mem.eql(u8, outcome, "exited")) {
            // The launcher recorded an UNREQUESTED end (reboot/poweroff/panic/
            // crash); this caller stopped nothing. Idempotent success, no claim.
            try util.writeStdout(io, "instance was not running (guest exited on its own)\n");
        } else if (std.mem.eql(u8, outcome, "start-failed")) {
            try util.writeStdout(io, "instance is not running (start failed; see cogbox.log)\n");
        } else if (std.mem.eql(u8, outcome, "forced")) {
            try util.writeStdout(io, "instance stopped with forced termination; recent writes might have been lost\n");
        } else if (std.mem.eql(u8, outcome, "graceful") or std.mem.eql(u8, outcome, "unverified")) {
            // Old graceful records used the same insufficient exit-zero proof.
            try util.writeStdout(io, "instance stopped; clean guest shutdown could not be verified, recent writes might have been lost\n");
        } else {
            try util.writeStdout(io, "instance stopped: no live guest required shutdown\n");
        }
    } else {
        try util.writeStdout(io, "launcher stopped; older runtime cannot verify guest shutdown or durability\n");
    }
}

fn reportNotRunning(allocator: std.mem.Allocator, io: std.Io, name: ?[]const u8) !void {
    const disp = name orelse "default";
    const msg = try std.fmt.allocPrint(allocator, "instance '{s}' is not running\n", .{disp});
    defer allocator.free(msg);
    try util.writeStdout(io, msg);
}

fn nameFlag(parsed: *const parse.Parsed, allocator: std.mem.Allocator, io: std.Io) ?[]const u8 {
    if (parsed.get("name")) |n| {
        if (std.mem.eql(u8, n, "default")) {
            util.die(allocator, io, "stop", exit_codes.dataerr, "'default' is reserved. Omit --name to use the default instance.", .{});
        }
        if (!parse.isValidName(n)) {
            util.die(allocator, io, "stop", exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
        }
        return n;
    }
    return null;
}

fn readPid(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.posix.pid_t {
    const data = try readSmall(allocator, io, path, 64);
    defer allocator.free(data);
    const pid = std.fmt.parseInt(std.posix.pid_t, std.mem.trim(u8, data, " \t\r\n"), 10) catch return error.InvalidPid;
    if (pid <= 1) return error.InvalidPid;
    return pid;
}

fn readSmall(allocator: std.mem.Allocator, io: std.Io, path: []const u8, limit: usize) ![]u8 {
    const cwd = std.Io.Dir.cwd();
    const file = try cwd.openFile(io, path, .{});
    defer file.close(io);
    var buf: [64]u8 = undefined;
    // procfs reports size zero despite containing data. Positional Reader's
    // size-based fast path would turn a live launcher's stat into empty input.
    var reader = file.readerStreaming(io, &buf);
    return reader.interface.allocRemaining(allocator, .limited(limit));
}

fn processStart(allocator: std.mem.Allocator, io: std.Io, pid: std.posix.pid_t) anyerror!u64 {
    if (@import("platform").darwin) {
        const p = try @import("platform").process(pid);
        if (p.zombie) return error.ProcessExited;
        return p.start;
    }
    const path = try std.fmt.allocPrint(allocator, "/proc/{d}/stat", .{pid});
    defer allocator.free(path);
    const data = try readSmall(allocator, io, path, 4096);
    defer allocator.free(data);
    return parseProcessStart(data);
}

// Start readiness must belong to the newly forked launcher and its live child,
// not merely to a retained qemu.pid. Shared with start; never signals a PID.
// The launcher persists the child's starttime (qemu.start) BEFORE qemu.pid, so
// a pid without a starttime, a zombie, or a reused PID is never readiness.
pub fn ownsReadyChild(allocator: std.mem.Allocator, io: std.Io, runtime: []const u8, launcher: std.posix.pid_t) bool {
    const launch_path = std.fs.path.join(allocator, &.{ runtime, "launch" }) catch return false;
    defer allocator.free(launch_path);
    const data = readSmall(allocator, io, launch_path, 192) catch return false;
    defer allocator.free(data);
    const record = parseRecord(data, false) catch return false;
    if (record.identity.pid != launcher) return false;
    const start = processStart(allocator, io, launcher) catch return false;
    if (record.identity.start != start) return false;
    const start_path = std.fs.path.join(allocator, &.{ runtime, "qemu.start" }) catch return false;
    defer allocator.free(start_path);
    const start_data = readSmall(allocator, io, start_path, 64) catch return false;
    defer allocator.free(start_data);
    const expected_start = std.fmt.parseInt(u64, std.mem.trim(u8, start_data, " \t\r\n"), 10) catch return false;
    const pid_path = std.fs.path.join(allocator, &.{ runtime, "qemu.pid" }) catch return false;
    defer allocator.free(pid_path);
    const pid = readPid(allocator, io, pid_path) catch return false;
    if (@import("platform").darwin) {
        const p = @import("platform").process(pid) catch return false;
        return !p.zombie and p.parent == launcher and p.start == expected_start;
    }
    const stat_path = std.fmt.allocPrint(allocator, "/proc/{d}/stat", .{pid}) catch return false;
    defer allocator.free(stat_path);
    const stat = readSmall(allocator, io, stat_path, 4096) catch return false;
    defer allocator.free(stat);
    return childProof(stat, launcher, expected_start);
}

// Proof that a /proc/<pid>/stat line describes the QEMU child THIS launcher
// forked and still owns: not a zombie/dead entry, parented by the launcher,
// and started when the launcher recorded it (so a reused PID cannot match).
// Comm may contain spaces and parentheses; fields follow the LAST ") ".
pub fn childProof(stat: []const u8, launcher: std.posix.pid_t, expected_start: u64) bool {
    const end = std.mem.lastIndexOf(u8, stat, ") ") orelse return false;
    var words = std.mem.tokenizeScalar(u8, stat[end + 2 ..], ' ');
    const state = words.next() orelse return false;
    if (std.mem.eql(u8, state, "Z") or std.mem.eql(u8, state, "X")) return false;
    const parent = std.fmt.parseInt(std.posix.pid_t, words.next() orelse return false, 10) catch return false;
    if (parent != launcher) return false;
    // state and ppid consumed; starttime is the 20th field after the comm.
    var i: usize = 2;
    while (i < 19) : (i += 1) _ = words.next() orelse return false;
    const start = std.fmt.parseInt(u64, words.next() orelse return false, 10) catch return false;
    return start == expected_start;
}

fn parseProcessStart(data: []const u8) !u64 {
    const end = std.mem.lastIndexOf(u8, data, ") ") orelse return error.InvalidProcess;
    var words = std.mem.tokenizeScalar(u8, data[end + 2 ..], ' ');
    const state = words.next() orelse return error.InvalidProcess;
    if (std.mem.eql(u8, state, "Z") or std.mem.eql(u8, state, "X")) return error.ProcessExited;
    var i: usize = 1;
    while (i < 19) : (i += 1) _ = words.next() orelse return error.InvalidProcess;
    return std.fmt.parseInt(u64, words.next() orelse return error.InvalidProcess, 10);
}

test "shutdown records fence run PID starttime and fixed outcomes" {
    const a = try parseRecord("v1 01234567-1234-1234-1234-123456789abc 42 99\n", false);
    const b = try parseRecord("v1 01234567-1234-1234-1234-123456789abc 42 99 forced\n", true);
    try std.testing.expect(a.identity.same(b.identity));
    const unverified = try parseRecord("v1 01234567-1234-1234-1234-123456789abc 42 99 unverified\n", true);
    try std.testing.expect(a.identity.same(unverified.identity));
    try std.testing.expectEqualStrings("unverified", unverified.outcome.?);
    // Unrequested ends and pre-QEMU start failures are distinct from a stop
    // this caller completed; both must parse so the CLI can render them.
    const exited = try parseRecord("v1 01234567-1234-1234-1234-123456789abc 42 99 exited\n", true);
    try std.testing.expectEqualStrings("exited", exited.outcome.?);
    const start_failed = try parseRecord("v1 01234567-1234-1234-1234-123456789abc 42 99 start-failed\n", true);
    try std.testing.expectEqualStrings("start-failed", start_failed.outcome.?);
    try std.testing.expectError(error.InvalidRecord, parseRecord("v1 bad 42 99 graceful", true));
    try std.testing.expectError(error.InvalidRecord, parseRecord("v1 01234567-1234-1234-1234-123456789abc 0 99", false));
    try std.testing.expectError(error.InvalidRecord, parseRecord("v1 01234567-1234-1234-1234-123456789abc 42 99 unknown", true));
    try std.testing.expectError(error.InvalidRecord, parseRecord("v1 01234567-1234-1234-1234-123456789abc 42 99 graceful extra", true));
    var changed = a.identity;
    changed.start += 1;
    try std.testing.expect(!changed.same(a.identity));
    changed = a.identity;
    changed.nonce[0] = 'a';
    try std.testing.expect(!changed.same(a.identity));
}

test "process start parser handles parentheses and rejects zombies" {
    try std.testing.expectEqual(@as(u64, 123), try parseProcessStart("42 (a ) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123 999"));
    try std.testing.expectError(error.ProcessExited, parseProcessStart("42 (a) Z 1"));
    try std.testing.expectError(error.InvalidProcess, parseProcessStart("invalid"));
}

test "child proof requires a live starttime-matched child of the launcher" {
    // ppid 7, starttime 123; comm carries a space and a nested parenthesis.
    const live = "42 (qemu (a ) vm) S 7 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123 999";
    try std.testing.expect(childProof(live, 7, 123));
    // A zombie QEMU keeps its ppid and starttime but is not a running guest.
    try std.testing.expect(!childProof("42 (qemu (a ) vm) Z 7 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123 999", 7, 123));
    try std.testing.expect(!childProof("42 (qemu) X 7 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123 999", 7, 123));
    // Somebody else's child, or a reused PID with a different starttime.
    try std.testing.expect(!childProof(live, 8, 123));
    try std.testing.expect(!childProof(live, 7, 124));
    try std.testing.expect(!childProof("42 (qemu) S 7", 7, 123));
    try std.testing.expect(!childProof("invalid", 7, 123));
}
