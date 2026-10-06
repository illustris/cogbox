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
};

pub fn acquire(allocator: std.mem.Allocator, io: std.Io, p: *const paths.Paths, name: ?[]const u8) !Lock {
	const dir = try std.fs.path.join(allocator, &.{ p.config_dir, ".locks" });
	defer allocator.free(dir);
	var lock_dir = try std.Io.Dir.cwd().createDirPathOpen(io, dir, .{});
	defer lock_dir.close(io);
	// Keep genuine sudo CLI invocations consistent with launcher chown-back.
	if (std.c.geteuid() == 0 and p.real_uid != 0) try lock_dir.setOwner(io, p.real_uid, null);
	const path = try std.fmt.allocPrint(allocator, "{s}/{s}.lock", .{ dir, name orelse "default" });
	defer allocator.free(path);
	const file = try std.Io.Dir.cwd().createFile(io, path, .{
		.truncate = false,
		.permissions = std.Io.File.Permissions.fromMode(0o600),
	});
	errdefer file.close(io);
	if (std.c.geteuid() == 0 and p.real_uid != 0) try file.setOwner(io, p.real_uid, null);
	if (std.c.fcntl(file.handle, std.posix.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC)) < 0) return error.CannotLockConfig;
	while (std.c.flock(file.handle, 2) != 0) {
		if (std.c._errno().* != @intFromEnum(std.posix.E.INTR)) return error.CannotLockConfig;
	}
	return .{ .file = file };
}
