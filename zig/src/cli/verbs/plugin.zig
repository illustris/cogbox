// `cogbox plugin` - resolve --name to the instance's config/runtime/flake
// paths, then hand the rest of argv off to the plugin module's dispatch.
// Mirrors verbs/l7.zig.

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");
const config_lock = @import("../config_lock.zig");
const plugin_module = @import("plugin_module");

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *const std.process.Environ.Map,
	p: *const paths.Paths,
	argv: []const []const u8,
) !void {
	var name: ?[]const u8 = null;
	var rest: std.ArrayList([]const u8) = .empty;
	defer rest.deinit(allocator);

	var i: usize = 0;
	while (i < argv.len) : (i += 1) {
		const a = argv[i];
		if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
			try help.print(io, help.PLUGIN);
			return;
		}
		if (std.mem.eql(u8, a, "--name") or std.mem.eql(u8, a, "-n")) {
			i += 1;
			if (i >= argv.len) {
				util.die(allocator, io, "plugin", exit_codes.usage, "{s} requires a value", .{a});
			}
			name = argv[i];
			continue;
		}
		if (std.mem.startsWith(u8, a, "--name=")) {
			name = a[7..];
			continue;
		}
		if (std.mem.startsWith(u8, a, "-n=")) {
			name = a[3..];
			continue;
		}
		try rest.append(allocator, a);
	}

	if (name) |n| {
		if (std.mem.eql(u8, n, "default")) {
			util.die(allocator, io, "plugin", exit_codes.dataerr, "'default' is reserved. Omit --name to use the default instance.", .{});
		}
		if (!parse.isValidName(n)) {
			util.die(allocator, io, "plugin", exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
		}
	}

	const guard = try config_lock.acquire(allocator, io, p, name);
	defer guard.deinit(io);

	const inst_cfg = try paths.instanceConfigDir(allocator, p, name);
	defer allocator.free(inst_cfg);
	const cfg_path = try std.fs.path.join(allocator, &.{ inst_cfg, "config.json" });
	defer allocator.free(cfg_path);
	const inst_runtime = try paths.instanceRuntime(allocator, p, name);
	defer allocator.free(inst_runtime);
	const user_flake_dir = try paths.instanceFlakeDir(allocator, p, name);
	defer allocator.free(user_flake_dir);
	const plugins_flake_dir = try paths.instancePluginsFlakeDir(allocator, p, name);
	defer allocator.free(plugins_flake_dir);

	const cwd = std.Io.Dir.cwd();
	cwd.access(io, cfg_path, .{}) catch {
		util.die(allocator, io, "plugin", exit_codes.noinput, "no config found at {s}", .{cfg_path});
	};

	try plugin_module.dispatch(allocator, io, env, name, cfg_path, inst_runtime, user_flake_dir, plugins_flake_dir, rest.items);
}
