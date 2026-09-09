// Shared I/O helpers and the `die` panic for the cogbox CLI.

const std = @import("std");
const exit_codes = @import("exit.zig");

pub fn writeStdout(io: std.Io, bytes: []const u8) !void {
	const stdout = std.Io.File.stdout();
	var buf: [4096]u8 = undefined;
	var w = stdout.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

pub fn writeStderr(io: std.Io, bytes: []const u8) !void {
	const stderr = std.Io.File.stderr();
	var buf: [4096]u8 = undefined;
	var w = stderr.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

pub fn say(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype) !void {
	const msg = try std.fmt.allocPrint(allocator, fmt ++ "\n", args);
	defer allocator.free(msg);
	try writeStdout(io, msg);
}

pub fn warn(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype) !void {
	const msg = try std.fmt.allocPrint(allocator, "cogbox: warning: " ++ fmt ++ "\n", args);
	defer allocator.free(msg);
	try writeStderr(io, msg);
}

/// Print `cogbox <verb>: error: <fmt>` to stderr and exit. Use prefix
/// `cogbox` (no verb) when called before a verb has been resolved.
pub fn die(
	allocator: std.mem.Allocator,
	io: std.Io,
	verb: ?[]const u8,
	code: u8,
	comptime fmt: []const u8,
	args: anytype,
) noreturn {
	const prefix = if (verb) |v|
		std.fmt.allocPrint(allocator, "cogbox {s}: error: ", .{v}) catch "cogbox: error: "
	else
		std.fmt.allocPrint(allocator, "cogbox: error: ", .{}) catch "cogbox: error: ";

	const body = std.fmt.allocPrint(allocator, fmt, args) catch "(message too long)";
	const msg = std.fmt.allocPrint(allocator, "{s}{s}\n", .{ prefix, body }) catch "cogbox: error: (alloc failed)\n";
	writeStderr(io, msg) catch {};

	// Parser-class errors (64/65) get a help hint. Runtime errors don't:
	// the user's invocation was syntactically fine, only the world was wrong.
	if (code == exit_codes.usage or code == exit_codes.dataerr) {
		const hint = if (verb) |v|
			std.fmt.allocPrint(allocator, "Run 'cogbox {s} --help' for usage.\n", .{v}) catch "Run 'cogbox --help' for usage.\n"
		else
			"Run 'cogbox --help' for usage.\n";
		writeStderr(io, hint) catch {};
	}

	std.process.exit(code);
}

/// Whether an instance launch is alive. The launcher holds an exclusive flock
/// on `<runtime>.lock` for its whole lifetime and QEMU/passt inherit the fd,
/// so the kernel releases it only once every owned process is gone. A PID
/// file cannot tell a dead launch from unrelated PID reuse, and the pid marker
/// is published only after the launcher's port probe, so a launch caught in
/// that window has no pid at all. The probe takes LOCK_EX|LOCK_NB and drops it
/// on close; the launcher's `flock -w` absorbs that flicker.
pub fn instanceRunning(allocator: std.mem.Allocator, io: std.Io, runtime: []const u8) !bool {
	const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{runtime});
	defer allocator.free(lock_path);
	const file = std.Io.Dir.cwd().openFile(io, lock_path, .{}) catch |err| switch (err) {
		error.FileNotFound => return false,
		else => return err,
	};
	defer file.close(io);
	return @import("platform").lockHeld(file.handle);
}

/// `instanceRunning` for callers that only need a verdict. An uninspectable
/// lock counts as RUNNING (fail closed): never delete, report "stopped" or
/// hint "next start" over a launch that may still be alive.
pub fn instanceRunningConservative(allocator: std.mem.Allocator, io: std.Io, runtime: []const u8) bool {
	return instanceRunning(allocator, io, runtime) catch true;
}
