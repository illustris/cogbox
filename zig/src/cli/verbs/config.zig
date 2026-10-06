// Versioned read-only host context and stopped-instance resource configuration.
const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const paths = @import("../paths.zig");
const lock = @import("../config_lock.zig");
const run_verb = @import("run.zig");
const config = @import("rules_module").config;
const codes = @import("../exit.zig");

pub fn run(allocator: std.mem.Allocator, io: std.Io, p: *const paths.Paths, argv: []const []const u8) !void {
	if (argv.len == 0 or std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h")) {
		try help.print(io, help.CONFIG);
		return;
	}
	if (std.mem.eql(u8, argv[0], "context")) {
		if (argv.len != 2 or !std.mem.eql(u8, argv[1], "--json")) util.die(allocator, io, "config", codes.usage, "use config context --json", .{});
		const cfg = try paths.canonicalRoot(allocator, io, p.config_dir);
		defer allocator.free(cfg);
		const data = try paths.canonicalRoot(allocator, io, p.base_data);
		defer allocator.free(data);
		const runtime = try paths.canonicalRoot(allocator, io, p.base_runtime);
		defer allocator.free(runtime);
		const user = try paths.effectiveUsername(allocator);
		defer allocator.free(user);
		const out = try std.json.Stringify.valueAlloc(allocator, .{
			.version = @as(u32, 1), .uid = std.c.geteuid(), .user = user,
			.configDir = cfg, .dataDir = data, .runtimeDir = runtime,
		}, .{});
		defer allocator.free(out);
		try util.writeStdout(io, out);
		try util.writeStdout(io, "\n");
		return;
	}
	if (!std.mem.eql(u8, argv[0], "set")) util.die(allocator, io, "config", codes.usage, "expected context or set", .{});
	const flags = [_]parse.Flag{
		.{ .long = "name", .short = 'n', .kind = .value },
		.{ .long = "vcpu", .kind = .value },
		.{ .long = "mem", .kind = .value },
		.{ .long = "help", .short = 'h', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{ .verb = "config", .flags = &flags }, argv[1..]);
	defer parsed.deinit();
	if (parsed.isSet("help")) return help.print(io, help.CONFIG);
	const opts = try run_verb.validate(&parsed, allocator, io, "config");
	if (opts.vcpu == null and opts.mem == null) util.die(allocator, io, "config", codes.usage, "config set requires --vcpu or --mem", .{});
	const runtime = try paths.instanceRuntime(allocator, p, opts.name);
	defer allocator.free(runtime);
	if (util.instanceRunningConservative(allocator, io, runtime)) util.die(allocator, io, "config", codes.tempfail, "instance is running; stop it before changing resources", .{});
	const guard = try lock.acquire(allocator, io, p, opts.name);
	defer guard.deinit(io);
	if (util.instanceRunningConservative(allocator, io, runtime)) util.die(allocator, io, "config", codes.tempfail, "instance is running; stop it before changing resources", .{});
	const dir = try paths.instanceConfigDir(allocator, p, opts.name);
	defer allocator.free(dir);
	const path = try std.fs.path.join(allocator, &.{ dir, "config.json" });
	defer allocator.free(path);
	var loaded = config.load(allocator, io, path) catch |err| util.die(allocator, io, "config", codes.noinput, "cannot read existing instance config {s}: {s}", .{ path, @errorName(err) });
	defer loaded.deinit();
	if (loaded.root().* != .object) util.die(allocator, io, "config", codes.dataerr, "instance config must be a JSON object", .{});
	if (opts.vcpu) |n| try loaded.root().object.put(loaded.treeAllocator(), "vcpu", .{ .integer = n });
	if (opts.mem) |n| try loaded.root().object.put(loaded.treeAllocator(), "mem", .{ .integer = n });
	try config.save(allocator, io, path, loaded.root().*);
	try util.say(allocator, io, "Updated resources for '{s}'.", .{opts.name orelse "default"});
}
