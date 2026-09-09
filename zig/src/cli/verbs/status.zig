// `cogbox status` - report whether a single instance is running.
// Exit codes: 0 running, 3 stopped, 64 unknown instance.
//
// Liveness is a two-step check. First the launch's lifetime flock
// (<runtime>.lock, held by the bash launch script and inherited by QEMU) must
// be held -- util.instanceRunning; the pid file is only a best-effort hint for
// the report line. That alone is NOT sufficient in general: a QEMU `microvm`
// machine can halt the guest on a guest-initiated power-off (`poweroff`,
// `shutdown -h now`, `systemctl poweroff`) yet keep the QEMU process alive, so
// the daemon's `wait` would never return and its PID would stay alive even
// though the VM is down. (Live observation 2026-09-07 on the current runner:
// power-off DID end QEMU, so this is a belt-and-braces check today, not the
// common path -- keep it, runners change.) To catch a halted guest, we then ask
// QEMU itself via the QMP control socket (`query-status`): a `shutdown`,
// `guest-panicked`, or `internal-error` run-state means the guest is down, so
// status reports stopped. QMP being unreachable (socket missing, no answer,
// older instance) falls back to the PID verdict, so a healthy VM is never
// spuriously flipped to stopped.

const std = @import("std");
const posix = std.posix;
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");

// Blocking libc socket primitives for the QMP handshake (mirrors attach.zig);
// std.posix lacks socket/connect on this Zig and a one-shot request/response is
// clearest at the syscall level.
extern "c" fn connect(fd: c_int, addr: *const anyopaque, len: c_uint) c_int;
extern "c" fn close(fd: c_int) c_int;
// std.posix dropped `write` on this Zig (only `read` remains); use libc directly.
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;

// The microvm runner is always built with `microvm.socket = "cogbox.socket"`
// (the config name is "cogbox" for every instance, prod and test), and the
// launch script `cd`s into $RUNTIME before exec'ing the runner, so QEMU's QMP
// control socket (`-qmp unix:cogbox.socket,...`) lands at this fixed basename
// under the instance runtime dir. Keep in sync with `microvm.socket` in
// flake.nix.
const qmp_socket_name = "cogbox.socket";

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	p: *const paths.Paths,
	argv: []const []const u8,
) !void {
	const flags = [_]parse.Flag{
		.{ .long = "name", .short = 'n', .kind = .value },
		.{ .long = "help", .short = 'h', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{ .verb = "status", .flags = &flags }, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, help.STATUS);
		return;
	}

	const name = nameFlag(&parsed, allocator, io);

	const inst_cfg = try paths.instanceConfigDir(allocator, p, name);
	defer allocator.free(inst_cfg);
	const cfg_path = try std.fs.path.join(allocator, &.{ inst_cfg, "config.json" });
	defer allocator.free(cfg_path);
	const inst_runtime = try paths.instanceRuntime(allocator, p, name);
	defer allocator.free(inst_runtime);

	const cwd = std.Io.Dir.cwd();
	cwd.access(io, cfg_path, .{}) catch {
		const eff = name orelse "default";
		util.die(allocator, io, "status", exit_codes.usage, "no such instance: \"{s}\"", .{eff});
	};

	// Liveness is the lifetime flock; pid (published after the launcher's port
	// probe) is read best-effort for the report line only.
	const pid_path = try std.fs.path.join(allocator, &.{ inst_runtime, "pid" });
	defer allocator.free(pid_path);

	const pid = readPid(allocator, io, pid_path) catch null;
	const alive = util.instanceRunningConservative(allocator, io, inst_runtime);

	if (!alive) {
		try util.writeStdout(io, "stopped\n");
		std.process.exit(exit_codes.status_stopped);
	}

	// The daemon PID is alive, but on a guest-initiated power-off QEMU lingers
	// (see the module header). Confirm the VM run-state via QMP: a halted
	// run-state means stopped even though the PID survives. A null answer (QMP
	// unreachable) keeps the PID verdict ("running").
	const qmp_sock = try std.fs.path.join(allocator, &.{ inst_runtime, qmp_socket_name });
	defer allocator.free(qmp_sock);
	if (queryQmpStatus(allocator, qmp_sock)) |state| {
		defer allocator.free(state);
		if (qmpStatusIsStopped(state)) {
			try util.writeStdout(io, "stopped\n");
			std.process.exit(exit_codes.status_stopped);
		}
	}

	const endpoint_path = try std.fs.path.join(allocator, &.{ inst_runtime, "ssh-endpoint" });
	defer allocator.free(endpoint_path);
	var ssh_host: []const u8 = "?";
	var ssh_port: []const u8 = "?";
	var endpoint_text: ?[]u8 = null;
	defer if (endpoint_text) |t| allocator.free(t);
	if (readSmall(allocator, io, endpoint_path)) |text| {
		endpoint_text = text;
		var iter = std.mem.tokenizeAny(u8, text, " \t\r\n");
		if (iter.next()) |port| ssh_port = port;
		if (iter.next()) |host| ssh_host = host;
	} else |_| {}

	const cfg_text = try readSmall(allocator, io, cfg_path);
	defer allocator.free(cfg_text);
	const parsed_cfg = std.json.parseFromSlice(std.json.Value, allocator, cfg_text, .{}) catch
		util.die(allocator, io, "status", exit_codes.software, "invalid JSON in {s}", .{cfg_path});
	defer parsed_cfg.deinit();

	const obj = if (parsed_cfg.value == .object) parsed_cfg.value.object else
		util.die(allocator, io, "status", exit_codes.software, "config is not an object: {s}", .{cfg_path});
	const http_port: i64 = blk: {
		const v = obj.get("httpPort") orelse break :blk 8080;
		break :blk if (v == .integer) v.integer else 8080;
	};
	const bind_addr: []const u8 = blk: {
		const v = obj.get("bindAddr") orelse break :blk "127.0.0.1";
		break :blk if (v == .string) v.string else "127.0.0.1";
	};

	const net_label = networkLabel(obj);

	var pid_buf: [16]u8 = undefined;
	const pid_text: []const u8 = if (pid) |v| (std.fmt.bufPrint(&pid_buf, "{d}", .{v}) catch "?") else "?";
	try util.say(allocator, io,
		"running pid={s} ssh={s}:{s} http={s}:{d} net={s}",
		.{ pid_text, if (ssh_host.len > 0) ssh_host else bind_addr, ssh_port, bind_addr, http_port, net_label },
	);
}

fn nameFlag(parsed: *const parse.Parsed, allocator: std.mem.Allocator, io: std.Io) ?[]const u8 {
	if (parsed.get("name")) |n| {
		if (std.mem.eql(u8, n, "default")) {
			util.die(allocator, io, "status", exit_codes.dataerr, "'default' is reserved. Omit --name to use the default instance.", .{});
		}
		if (!parse.isValidName(n)) {
			util.die(allocator, io, "status", exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
		}
		return n;
	}
	return null;
}

fn readPid(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.posix.pid_t {
	const text = try readSmall(allocator, io, path);
	defer allocator.free(text);
	const trimmed = std.mem.trim(u8, text, " \t\r\n");
	return std.fmt.parseInt(std.posix.pid_t, trimmed, 10) catch return error.InvalidPid;
}

/// Map a QEMU QMP `query-status` run-state string to cogbox's stopped verdict.
/// `running` (and the various transient/paused/migration states where the VM
/// is still live) -> false; the terminal halted states a guest power-off or
/// crash produces -> true. Unknown states default to NOT stopped so an
/// unrecognized but live run-state is never misreported as down.
pub fn qmpStatusIsStopped(state: []const u8) bool {
	const stopped_states = [_][]const u8{
		"shutdown", // guest reached S5 / `poweroff` / `shutdown -h now`
		"guest-panicked", // guest kernel panic with -no-reboot-style halt
		"internal-error", // QEMU internal error -> VM halted
	};
	for (stopped_states) |s| {
		if (std.mem.eql(u8, state, s)) return true;
	}
	return false;
}

/// Connect to the instance's QMP control socket, run the capabilities
/// handshake + `query-status`, and return the run-state string (caller owns
/// it), or null if QMP is unreachable / unparsable. Best-effort: any failure
/// yields null so the caller falls back to the PID-liveness verdict.
fn queryQmpStatus(allocator: std.mem.Allocator, sock_path: []const u8) ?[]u8 {
	const fd = connectUnix(sock_path) catch return null;
	defer _ = close(fd);

	// QMP greeting -> enter command mode -> query. The server speaks first
	// (the {"QMP":{...}} greeting); we don't need its contents, just to drain
	// up to the first newline before issuing commands.
	var buf: [4096]u8 = undefined;
	_ = readLine(fd, &buf) catch return null; // greeting
	writeAll(fd, "{\"execute\":\"qmp_capabilities\"}\n") catch return null;
	_ = readLine(fd, &buf) catch return null; // capabilities ack
	writeAll(fd, "{\"execute\":\"query-status\"}\n") catch return null;
	const line = readLine(fd, &buf) catch return null;

	const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch return null;
	defer parsed.deinit();
	return extractStatus(allocator, parsed.value);
}

/// Pull `.return.status` out of a parsed QMP `query-status` reply, duped for
/// the caller. Null if the shape is unexpected (e.g. an `{"error":...}`).
fn extractStatus(allocator: std.mem.Allocator, v: std.json.Value) ?[]u8 {
	if (v != .object) return null;
	const ret = v.object.get("return") orelse return null;
	if (ret != .object) return null;
	const status = ret.object.get("status") orelse return null;
	if (status != .string) return null;
	return allocator.dupe(u8, status.string) catch null;
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

fn writeAll(fd: posix.fd_t, bytes: []const u8) !void {
	var off: usize = 0;
	while (off < bytes.len) {
		const n = write(fd, bytes.ptr + off, bytes.len - off);
		if (n <= 0) return error.WriteFailed;
		off += @intCast(n);
	}
}

/// Read one '\n'-terminated line into `buf`, returning the slice up to (not
/// including) the newline. QMP frames every message as a single line, so a
/// per-byte read until '\n' is exact and avoids over-reading into the next
/// reply. Errors on EOF-before-newline or a line longer than `buf`.
fn readLine(fd: posix.fd_t, buf: []u8) ![]u8 {
	var n: usize = 0;
	while (n < buf.len) {
		const r = posix.read(fd, buf[n .. n + 1]) catch return error.ReadFailed;
		if (r == 0) return error.UnexpectedEof;
		if (buf[n] == '\n') return buf[0..n];
		n += 1;
	}
	return error.LineTooLong;
}

fn readSmall(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
	const cwd = std.Io.Dir.cwd();
	const file = try cwd.openFile(io, path, .{});
	defer file.close(io);
	var buf: [4096]u8 = undefined;
	var reader = file.reader(io, &buf);
	return try reader.interface.allocRemaining(allocator, .limited(1 << 20));
}

fn networkLabel(obj: std.json.ObjectMap) []const u8 {
	const v = obj.get("network") orelse return "full";
	switch (v) {
		.string => |s| {
			if (std.mem.eql(u8, s, "full")) return "full";
			if (std.mem.eql(u8, s, "none")) return "none";
			return "rules";
		},
		else => return "rules",
	}
}

const testing = std.testing;

test "qmpStatusIsStopped: a live VM run-state is not stopped" {
	// `running` is the steady state; the paused/transient/migration states all
	// still have a live guest, so status must keep reporting running.
	try testing.expect(!qmpStatusIsStopped("running"));
	try testing.expect(!qmpStatusIsStopped("paused"));
	try testing.expect(!qmpStatusIsStopped("prelaunch"));
	try testing.expect(!qmpStatusIsStopped("inmigrate"));
	try testing.expect(!qmpStatusIsStopped("postmigrate"));
	try testing.expect(!qmpStatusIsStopped("suspended"));
}

test "qmpStatusIsStopped: a guest power-off / crash run-state is stopped" {
	// This is the bug #13 case: a guest-initiated poweroff leaves QEMU alive
	// (microvm machine type does not exit), but query-status reports
	// `shutdown`, which must map to stopped.
	try testing.expect(qmpStatusIsStopped("shutdown"));
	try testing.expect(qmpStatusIsStopped("guest-panicked"));
	try testing.expect(qmpStatusIsStopped("internal-error"));
}

test "qmpStatusIsStopped: an unknown run-state defaults to not stopped" {
	// Fail open: a run-state we don't recognize must not flip a live VM to
	// stopped.
	try testing.expect(!qmpStatusIsStopped("some-future-state"));
	try testing.expect(!qmpStatusIsStopped(""));
}

test "extractStatus: pulls .return.status from a query-status reply" {
	const reply =
		\\{"return":{"status":"shutdown","running":false,"singlestep":false}}
	;
	const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, reply, .{});
	defer parsed.deinit();
	const status = extractStatus(testing.allocator, parsed.value) orelse
		return error.TestExpectedStatus;
	defer testing.allocator.free(status);
	try testing.expectEqualStrings("shutdown", status);
}

test "extractStatus: maps a running reply, end-to-end" {
	const reply =
		\\{"return":{"status":"running","running":true,"singlestep":false}}
	;
	const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, reply, .{});
	defer parsed.deinit();
	const status = extractStatus(testing.allocator, parsed.value) orelse
		return error.TestExpectedStatus;
	defer testing.allocator.free(status);
	try testing.expectEqualStrings("running", status);
	try testing.expect(!qmpStatusIsStopped(status));
}

test "extractStatus: returns null on an error reply or unexpected shape" {
	const cases = [_][]const u8{
		\\{"error":{"class":"CommandNotFound","desc":"nope"}}
		,
		\\{"return":{}}
		,
		\\{"return":"not-an-object"}
		,
		\\["not", "an", "object"]
		,
	};
	for (cases) |reply| {
		const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, reply, .{});
		defer parsed.deinit();
		try testing.expect(extractStatus(testing.allocator, parsed.value) == null);
	}
}
