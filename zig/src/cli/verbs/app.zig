// The browser frontend is a packaged Go helper; resolve host paths once here.
const std = @import("std");
const util = @import("../util.zig");
const help = @import("../help.zig");
const paths = @import("../paths.zig");
const ssh = @import("ssh.zig");

pub fn run(allocator: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map, p: *const paths.Paths, argv: []const []const u8) !void {
	if (argv.len == 0) return help.print(io, help.APP);
	for (argv) |a| {
		if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) return help.print(io, help.APP);
	}
	const helper = env.get("COGBOX_APP_HELPER") orelse "cogbox-app";
	var args: std.ArrayList([]const u8) = .empty;
	defer args.deinit(allocator);
	try args.appendSlice(allocator, &.{ helper, "--config-root", p.config_dir, "--data-root", p.base_data, "--runtime-root", p.base_runtime });
	try args.appendSlice(allocator, argv);
	ssh.execvpAlloc(allocator, args.items) catch {
		util.die(allocator, io, "app", 70, "could not execute the packaged app helper; reinstall cogbox", .{});
	};
}
