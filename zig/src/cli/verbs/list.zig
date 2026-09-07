// `cogbox list` - enumerate instances by walking $CONFIG_DIR/instances.

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	p: *const paths.Paths,
	argv: []const []const u8,
) !void {
	const flags = [_]parse.Flag{
		.{ .long = "json", .kind = .bool },
		.{ .long = "help", .short = 'h', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{
		.verb = "list",
		.flags = &flags,
	}, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, help.LIST);
		return;
	}

	const json_out = parsed.isSet("json");

	const instances_dir = try std.fs.path.join(allocator, &.{ p.config_dir, "instances" });
	defer allocator.free(instances_dir);

	const cwd = std.Io.Dir.cwd();
	var dir = cwd.openDir(io, instances_dir, .{ .iterate = true }) catch |err| switch (err) {
		error.FileNotFound => {
			if (!json_out) try util.writeStdout(io, "Instances:\n");
			return;
		},
		else => return err,
	};
	defer dir.close(io);

	var iter = dir.iterate();
	if (!json_out) try util.writeStdout(io, "Instances:\n");

	var first = true;
	if (json_out) try util.writeStdout(io, "[\n");

	while (try iter.next(io)) |entry| {
		if (entry.kind != .directory) continue;
		const name = entry.name;

		const cfg_path = try std.fs.path.join(allocator, &.{ instances_dir, name, "config.json" });
		defer allocator.free(cfg_path);

		const config_text = readSmall(allocator, io, cfg_path) catch continue;
		defer if (config_text) |t| allocator.free(t);
		if (config_text == null) continue;

		const parsed_json = std.json.parseFromSlice(std.json.Value, allocator, config_text.?, .{}) catch continue;
		defer parsed_json.deinit();
		if (parsed_json.value != .object) continue;
		const obj = parsed_json.value.object;

		const ssh_p = jsonInt(obj, "sshPort", 2222);
		const http_p = jsonInt(obj, "httpPort", 8080);
		const net_label = networkLabel(obj);

		// Resolve runtime dir for this instance to check if it's running.
		const inst_runtime = if (std.mem.eql(u8, name, "default"))
			try allocator.dupe(u8, p.base_runtime)
		else
			try std.fmt.allocPrint(allocator, "{s}-{s}", .{ p.base_runtime, name });
		defer allocator.free(inst_runtime);
		const running = util.instanceRunningConservative(allocator, io, inst_runtime);

		if (json_out) {
			if (!first) try util.writeStdout(io, ",\n");
			first = false;
			const line = try std.fmt.allocPrint(allocator,
				"  {{\"name\":\"{s}\",\"sshPort\":{d},\"httpPort\":{d},\"network\":\"{s}\",\"running\":{}}}",
				.{ name, ssh_p, http_p, net_label, running },
			);
			defer allocator.free(line);
			try util.writeStdout(io, line);
		} else {
			const label = if (std.mem.eql(u8, name, "default")) "(default)" else name;
			const running_str: []const u8 = if (running) " (running)" else "";
			const line = try std.fmt.allocPrint(allocator,
				"  {s}  ssh:{d}  http:{d}  net:{s}{s}\n",
				.{ label, ssh_p, http_p, net_label, running_str },
			);
			defer allocator.free(line);
			try util.writeStdout(io, line);
		}
	}

	if (json_out) try util.writeStdout(io, "\n]\n");
}

fn readSmall(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !?[]u8 {
	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(io, path, .{}) catch return null;
	defer file.close(io);
	var buf: [1024]u8 = undefined;
	var reader = file.reader(io, &buf);
	return try reader.interface.allocRemaining(allocator, .limited(1 << 20));
}

fn jsonInt(obj: std.json.ObjectMap, key: []const u8, default: i64) i64 {
	const v = obj.get(key) orelse return default;
	switch (v) {
		.integer => |i| return i,
		.number_string => |s| return std.fmt.parseInt(i64, s, 10) catch default,
		else => return default,
	}
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
