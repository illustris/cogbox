// Stable per-instance serialization. The lock is outside the deletable instance
// tree; every config reader that later writes must take it before reading.
// Lock ordering is config, then runtime lifetime. Never inherit it across exec.
const std = @import("std");
const paths = @import("paths.zig");

pub const Lock = struct {
	file: std.Io.File,
	pub fn deinit(self: Lock, io: std.Io) void {
		self.file.close(io);
	}

	/// Drop the flock but keep the descriptor, so `reacquire` can take the same
	/// lock again later (the live apply releases the config lock for its build
	/// and retakes it to record).
	pub fn release(self: Lock) void {
		while (std.c.flock(self.file.handle, std.posix.LOCK.UN) != 0) {
			if (std.c._errno().* != @intFromEnum(std.posix.E.INTR)) return;
		}
	}

	/// Retake a `release`d lock on the same descriptor, with acquireTimeout's
	/// bound and cancel flag.
	pub fn reacquire(self: Lock, io: std.Io, timeout_ms: i64, cancel: ?*const std.atomic.Value(u8)) TimedError!void {
		return pollLock(io, self.file.handle, timeout_ms, cancel);
	}
};

/// Open (creating it if needed) `<config>/.locks/<name or "default"><suffix>`,
/// the one way every cogbox lock file is opened: mode 0600, close-on-exec (so
/// no ssh, systemd-run or nix child inherits the lock), and, under sudo, the
/// `.locks` directory and the file chowned to the real uid, so a lock first
/// created by `sudo cogbox ...` stays openable by later non-sudo verbs. The
/// config lock's suffix is ".lock"; the live apply's own flock uses
/// ".apply.lock". Takes no lock.
pub fn openLockFile(allocator: std.mem.Allocator, io: std.Io, p: *const paths.Paths, name: ?[]const u8, suffix: []const u8) !std.Io.File {
	const dir = try std.fs.path.join(allocator, &.{ p.config_dir, ".locks" });
	defer allocator.free(dir);
	var lock_dir = try std.Io.Dir.cwd().createDirPathOpen(io, dir, .{});
	defer lock_dir.close(io);
	// Keep genuine sudo CLI invocations consistent with launcher chown-back.
	if (std.c.geteuid() == 0 and p.real_uid != 0) try lock_dir.setOwner(io, p.real_uid, null);
	const path = try std.fmt.allocPrint(allocator, "{s}/{s}{s}", .{ dir, name orelse "default", suffix });
	defer allocator.free(path);
	const file = try std.Io.Dir.cwd().createFile(io, path, .{
		.truncate = false,
		.permissions = std.Io.File.Permissions.fromMode(0o600),
	});
	errdefer file.close(io);
	if (std.c.geteuid() == 0 and p.real_uid != 0) try file.setOwner(io, p.real_uid, null);
	if (std.c.fcntl(file.handle, std.posix.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC)) < 0) return error.CannotLockConfig;
	return file;
}

pub fn acquire(allocator: std.mem.Allocator, io: std.Io, p: *const paths.Paths, name: ?[]const u8) !Lock {
	const file = try openLockFile(allocator, io, p, name, ".lock");
	errdefer file.close(io);
	while (std.c.flock(file.handle, std.posix.LOCK.EX) != 0) {
		if (std.c._errno().* != @intFromEnum(std.posix.E.INTR)) return error.CannotLockConfig;
	}
	return .{ .file = file };
}

pub const TimedError = error{
	/// The lock was still held by someone else when the bound ran out.
	Timeout,
	/// The cancel flag was set (the caller's terminate flag).
	Canceled,
	CannotLockConfig,
};

/// Like `acquire`, but bounded: a LOCK_NB attempt every 100 ms until
/// `timeout_ms` has passed (error.Timeout) or `cancel` reads non-zero
/// (error.Canceled; checked before every attempt, so a set flag never takes
/// the lock). For the live apply's subcommands, whose callers must not queue
/// forever behind a booting launcher; the launcher, `delete` and the mutating
/// plugin verbs keep the blocking `acquire`.
pub fn acquireTimeout(allocator: std.mem.Allocator, io: std.Io, p: *const paths.Paths, name: ?[]const u8, timeout_ms: i64, cancel: ?*const std.atomic.Value(u8)) !Lock {
	const file = try openLockFile(allocator, io, p, name, ".lock");
	errdefer file.close(io);
	try pollLock(io, file.handle, timeout_ms, cancel);
	return .{ .file = file };
}

const poll_interval_ms: i64 = 100;

fn pollLock(io: std.Io, fd: std.posix.fd_t, timeout_ms: i64, cancel: ?*const std.atomic.Value(u8)) TimedError!void {
	const began = std.Io.Timestamp.now(io, .awake);
	while (true) {
		if (cancel) |c| if (c.load(.acquire) != 0) return error.Canceled;
		if (std.c.flock(fd, std.posix.LOCK.EX | std.posix.LOCK.NB) == 0) return;
		const e = std.c._errno().*;
		if (e == @intFromEnum(std.posix.E.INTR)) continue;
		if (e != @intFromEnum(std.posix.E.AGAIN)) return error.CannotLockConfig;
		const waited = began.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds();
		if (waited >= timeout_ms) return error.Timeout;
		std.Io.sleep(io, std.Io.Duration.fromMilliseconds(@min(poll_interval_ms, timeout_ms - waited)), .awake) catch {};
	}
}

// --- tests ---------------------------------------------------------------------

const t = std.testing;

/// A Paths whose config_dir is a fresh scratch dir under the cwd; the caller
/// deletes `config_dir` and frees it.
fn testPaths(io: std.Io) !paths.Paths {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	const dir = try std.fmt.allocPrint(t.allocator, "zig-config-lock-test-{x}", .{&rnd});
	try std.Io.Dir.cwd().createDirPath(io, dir);
	return .{
		.real_user = "",
		.real_home = "",
		.real_uid = std.c.getuid(),
		.config_dir = dir,
		.base_data = "",
		.base_runtime = "",
		.allocator = t.allocator,
	};
}

fn msSince(io: std.Io, began: std.Io.Timestamp) i64 {
	return began.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds();
}

test "acquireTimeout: times out while another description holds the lock, takes it once released" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const p = try testPaths(io);
	defer t.allocator.free(p.config_dir);
	defer std.Io.Dir.cwd().deleteTree(io, p.config_dir) catch {};

	// flock conflicts between open file descriptions, so two opens in one
	// process stand in for two processes.
	const holder = try acquire(t.allocator, io, &p, "inst");
	defer holder.deinit(io);

	const began = std.Io.Timestamp.now(io, .awake);
	try t.expectError(error.Timeout, acquireTimeout(t.allocator, io, &p, "inst", 300, null));
	const waited = msSince(io, began);
	try t.expect(waited >= 300);
	try t.expect(waited < 5_000);

	// Another instance's lock is independent.
	const other = try acquireTimeout(t.allocator, io, &p, "other", 300, null);
	other.deinit(io);

	// release() frees it for a waiter while the holder keeps its descriptor...
	holder.release();
	const second = try acquireTimeout(t.allocator, io, &p, "inst", 1_000, null);
	// ...and reacquire() is bounded the same way while the waiter holds it.
	try t.expectError(error.Timeout, holder.reacquire(io, 200, null));
	second.deinit(io);
	try holder.reacquire(io, 1_000, null);
	try t.expectError(error.Timeout, acquireTimeout(t.allocator, io, &p, "inst", 0, null));
}

test "acquireTimeout: the cancel flag ends the wait at once and never takes the lock" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const p = try testPaths(io);
	defer t.allocator.free(p.config_dir);
	defer std.Io.Dir.cwd().deleteTree(io, p.config_dir) catch {};

	var flag: std.atomic.Value(u8) = .init(0);
	const holder = try acquire(t.allocator, io, &p, null);
	defer holder.deinit(io);
	flag.store(1, .release);
	const began = std.Io.Timestamp.now(io, .awake);
	try t.expectError(error.Canceled, acquireTimeout(t.allocator, io, &p, null, 60_000, &flag));
	try t.expect(msSince(io, began) < 1_000);

	// Set even with the lock free: still canceled, and the lock stays free.
	holder.release();
	try t.expectError(error.Canceled, acquireTimeout(t.allocator, io, &p, null, 60_000, &flag));
	try t.expectError(error.Canceled, holder.reacquire(io, 60_000, &flag));
	flag.store(0, .release);
	const taken = try acquireTimeout(t.allocator, io, &p, null, 1_000, &flag);
	taken.deinit(io);
}

test "openLockFile: the config and apply locks are 0600, close-on-exec, and independent" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const p = try testPaths(io);
	defer t.allocator.free(p.config_dir);
	defer std.Io.Dir.cwd().deleteTree(io, p.config_dir) catch {};

	const cfg = try acquire(t.allocator, io, &p, "inst");
	defer cfg.deinit(io);
	const apply = try openLockFile(t.allocator, io, &p, "inst", ".apply.lock");
	defer apply.close(io);
	// Holding the config lock does not hold the apply lock.
	try t.expectEqual(@as(c_int, 0), std.c.flock(apply.handle, std.posix.LOCK.EX | std.posix.LOCK.NB));

	inline for (.{ "inst.lock", "inst.apply.lock" }) |leaf| {
		const path = try std.fmt.allocPrint(t.allocator, "{s}/.locks/" ++ leaf, .{p.config_dir});
		defer t.allocator.free(path);
		const st = try std.Io.Dir.cwd().statFile(io, path, .{});
		try t.expectEqual(@as(std.posix.mode_t, 0o600), @as(std.posix.mode_t, @intCast(st.permissions.toMode() & 0o777)));
	}
	for ([_]std.posix.fd_t{ cfg.file.handle, apply.handle }) |fd| {
		const flags = std.c.fcntl(fd, std.posix.F.GETFD);
		try t.expect(flags >= 0);
		try t.expect(flags & std.posix.FD_CLOEXEC != 0);
	}
}
