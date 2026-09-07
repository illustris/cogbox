// `cogbox console` and `cogbox monitor` - attach to a running instance's
// serial console (<runtime>/console.sock) or HMP QEMU monitor
// (<runtime>/monitor.sock). Both relay raw bytes over the socket until the
// user detaches with Ctrl-]; detaching leaves the VM running.

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");
const attach = @import("../attach.zig");

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	p: *const paths.Paths,
	argv: []const []const u8,
	target: attach.Target,
) !void {
	const verb = switch (target) {
		.console => "console",
		.monitor => "monitor",
	};
	const flags = [_]parse.Flag{
		.{ .long = "name", .short = 'n', .kind = .value },
		.{ .long = "help", .short = 'h', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{ .verb = verb, .flags = &flags }, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, switch (target) {
			.console => help.CONSOLE,
			.monitor => help.MONITOR,
		});
		return;
	}

	const name = nameFlag(&parsed, allocator, io, verb);

	const inst_runtime = try paths.instanceRuntime(allocator, p, name);
	defer allocator.free(inst_runtime);

	if (!util.instanceRunningConservative(allocator, io, inst_runtime)) {
		const eff = name orelse "default";
		const hint_name: []const u8 = if (name) |n|
			try std.fmt.allocPrint(allocator, " --name {s}", .{n})
		else
			try allocator.dupe(u8, "");
		defer allocator.free(hint_name);
		try util.writeStderr(io, try std.fmt.allocPrint(allocator,
			"cogbox {s}: error: instance \"{s}\" is not running.\nStart it with: cogbox start{s}\n",
			.{ verb, eff, hint_name },
		));
		std.process.exit(exit_codes.software);
	}

	const sock_name = switch (target) {
		.console => "console.sock",
		.monitor => "monitor.sock",
	};
	const sock_path = try std.fs.path.join(allocator, &.{ inst_runtime, sock_name });
	defer allocator.free(sock_path);

	const cwd = std.Io.Dir.cwd();
	cwd.access(io, sock_path, .{}) catch {
		util.die(allocator, io, verb, exit_codes.software, "{s} not found. The instance may have been launched by an older cogbox; restart it with 'cogbox restart'.", .{sock_path});
	};

	const replay_log: ?[]const u8 = switch (target) {
		.console => try std.fs.path.join(allocator, &.{ inst_runtime, "console.log" }),
		.monitor => null,
	};
	defer if (replay_log) |rl| allocator.free(rl);

	attach.attach(allocator, io, target, sock_path, name orelse "default", replay_log) catch |err| {
		util.die(allocator, io, verb, exit_codes.software, "attach failed: {s}", .{@errorName(err)});
	};
}

fn nameFlag(parsed: *const parse.Parsed, allocator: std.mem.Allocator, io: std.Io, verb: []const u8) ?[]const u8 {
	if (parsed.get("name")) |n| {
		if (std.mem.eql(u8, n, "default")) {
			util.die(allocator, io, verb, exit_codes.dataerr, "'default' is reserved. Omit --name to use the default instance.", .{});
		}
		if (!parse.isValidName(n)) {
			util.die(allocator, io, verb, exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
		}
		return n;
	}
	return null;
}
