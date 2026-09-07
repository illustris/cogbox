// `cogbox delete` - remove an instance's config and persistent files.
//
// Wipes the per-instance config dir (config.json, flake/, plugins-flake/,
// authorized_keys, ...), the persistent data dir (disk overlays, guest
// state), and any leftover runtime dir (sockets, logs, pid). Refuses to
// touch a running instance -- stop it first. Prompts before deleting
// unless -y/--yes is given (or stdin is non-interactive, matching the rest
// of the CLI's prompts).

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
		.{ .long = "name", .short = 'n', .kind = .value },
		.{ .long = "yes", .short = 'y', .kind = .bool },
		.{ .long = "help", .short = 'h', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{ .verb = "delete", .flags = &flags }, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, help.DELETE);
		return;
	}

	const name = nameFlag(&parsed, allocator, io);
	const yes = parsed.isSet("yes");
	const label = name orelse "default";

	const cfg_dir = try paths.instanceConfigDir(allocator, p, name);
	defer allocator.free(cfg_dir);
	const data_dir = try paths.instanceDataDir(allocator, p, name);
	defer allocator.free(data_dir);
	const runtime_dir = try paths.instanceRuntime(allocator, p, name);
	defer allocator.free(runtime_dir);

	const cwd = std.Io.Dir.cwd();

	const has_cfg = exists(io, cwd, cfg_dir);
	const has_data = exists(io, cwd, data_dir);
	const has_runtime = exists(io, cwd, runtime_dir);

	// Nothing to remove: report and exit 0 so this is idempotent.
	if (!has_cfg and !has_data and !has_runtime) {
		try util.say(allocator, io, "instance '{s}' does not exist; nothing to delete", .{label});
		return;
	}

	// Never delete out from under a live VM. The lifetime flock, not the pid
	// hint, is the verdict (util.instanceRunning); an uninspectable lock refuses.
	if (util.instanceRunningConservative(allocator, io, runtime_dir)) {
		// die() exits immediately, so leaking this small format is fine.
		const hint = if (name) |n|
			std.fmt.allocPrint(allocator, " -n {s}", .{n}) catch ""
		else
			"";
		util.die(allocator, io, "delete", exit_codes.tempfail, "instance '{s}' is running. Stop it first with 'cogbox stop{s}'.", .{ label, hint });
	}

	if (!yes) {
		try util.say(allocator, io, "The following will be permanently deleted for instance '{s}':", .{label});
		if (has_cfg) try util.say(allocator, io, "  config:  {s}", .{cfg_dir});
		if (has_data) try util.say(allocator, io, "  data:    {s}", .{data_dir});
		if (has_runtime) try util.say(allocator, io, "  runtime: {s}", .{runtime_dir});
		const prompt = try std.fmt.allocPrint(allocator, "Delete instance '{s}'?", .{label});
		defer allocator.free(prompt);
		if (!try confirm(allocator, io, prompt)) {
			try util.say(allocator, io, "Aborted; nothing deleted.", .{});
			return;
		}
	}

	// deleteTree is a no-op on a path that doesn't exist, so the existence
	// checks above are only for the prompt -- it's safe to call all three.
	cwd.deleteTree(io, cfg_dir) catch |err| {
		util.die(allocator, io, "delete", exit_codes.software, "removing config dir {s}: {s}", .{ cfg_dir, @errorName(err) });
	};
	cwd.deleteTree(io, data_dir) catch |err| {
		util.die(allocator, io, "delete", exit_codes.software, "removing data dir {s}: {s}", .{ data_dir, @errorName(err) });
	};
	cwd.deleteTree(io, runtime_dir) catch |err| {
		util.die(allocator, io, "delete", exit_codes.software, "removing runtime dir {s}: {s}", .{ runtime_dir, @errorName(err) });
	};

	try util.say(allocator, io, "Deleted instance '{s}'.", .{label});
}

/// Resolve --name, applying the same rules as the other verbs: `default` is
/// reserved (omit --name for it) and names are validated.
fn nameFlag(parsed: *const parse.Parsed, allocator: std.mem.Allocator, io: std.Io) ?[]const u8 {
	if (parsed.get("name")) |n| {
		if (std.mem.eql(u8, n, "default")) {
			util.die(allocator, io, "delete", exit_codes.dataerr, "'default' is reserved. Omit --name to delete the default instance.", .{});
		}
		if (!parse.isValidName(n)) {
			util.die(allocator, io, "delete", exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
		}
		return n;
	}
	return null;
}

fn exists(io: std.Io, cwd: std.Io.Dir, path: []const u8) bool {
	cwd.access(io, path, .{}) catch return false;
	return true;
}

/// Interactive confirmation. Non-tty stdin auto-confirms, matching the rest
/// of the CLI's prompts (scripted/test use); pass -y to skip it on a tty.
fn confirm(allocator: std.mem.Allocator, io: std.Io, prompt: []const u8) !bool {
	const stdin = std.Io.File.stdin();
	const tty = stdin.isTty(io) catch false;
	if (!tty) return true;

	const msg = try std.fmt.allocPrint(allocator, "{s} [y/N] ", .{prompt});
	defer allocator.free(msg);
	try util.writeStdout(io, msg);

	var buf: [256]u8 = undefined;
	var reader = stdin.readerStreaming(io, &buf);
	const line = (reader.interface.takeDelimiter('\n') catch return false) orelse return false;
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	return trimmed.len > 0 and (trimmed[0] == 'y' or trimmed[0] == 'Y');
}
