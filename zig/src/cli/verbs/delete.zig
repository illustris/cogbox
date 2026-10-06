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
const config_lock = @import("../config_lock.zig");

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

	// Fail promptly during VM boot; repeat under the config lock for admission.
	if (util.instanceRunningConservative(allocator, io, runtime_dir)) util.die(allocator, io, "delete", exit_codes.tempfail, "instance is running; stop it first", .{});
	const guard = try config_lock.acquire(allocator, io, p, name);
	defer guard.deinit(io);

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

	const cfg_path = try std.fs.path.join(allocator, &.{ cfg_dir, "config.json" });
	defer allocator.free(cfg_path);
	const backup = readConfigBackup(allocator, io, cfg_path) catch |err| {
		util.die(allocator, io, "delete", exit_codes.software, "cannot preserve config for a failed delete: {s}", .{@errorName(err)});
	};
	defer if (backup) |b| allocator.free(b.bytes);

	// Keep the config discoverable until persistent and runtime cleanup both
	// succeed. A failed delete must remain visible to inventory clients so the
	// user can retry it. deleteTree is a no-op for already removed paths.
	cwd.deleteTree(io, data_dir) catch |err| {
		util.die(allocator, io, "delete", exit_codes.software, "removing data dir {s}: {s}", .{ data_dir, @errorName(err) });
	};
	cwd.deleteTree(io, runtime_dir) catch |err| {
		util.die(allocator, io, "delete", exit_codes.software, "removing runtime dir {s}: {s}", .{ runtime_dir, @errorName(err) });
	};
	cwd.deleteTree(io, cfg_dir) catch |err| {
		// deleteTree may unlink config.json before failing on a different child.
		// Restore its exact bytes so an inventory client can still offer a retry.
		if (backup) |b| {
			restoreConfig(allocator, io, p, cfg_dir, cfg_path, b) catch |restore_err| {
				util.die(allocator, io, "delete", exit_codes.software, "removing config dir {s}: {s}; restoring config for retry also failed: {s}", .{ cfg_dir, @errorName(err), @errorName(restore_err) });
			};
		}
		util.die(allocator, io, "delete", exit_codes.software, "removing config dir {s}: {s}", .{ cfg_dir, @errorName(err) });
	};

	try util.say(allocator, io, "Deleted instance '{s}'.", .{label});
}

const ConfigBackup = struct { bytes: []u8, permissions: std.Io.File.Permissions };

fn readConfigBackup(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !?ConfigBackup {
	const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
		error.FileNotFound => return null,
		else => return err,
	};
	defer file.close(io);
	const stat = try file.stat(io);
	var buf: [4096]u8 = undefined;
	var reader = file.reader(io, &buf);
	return .{ .bytes = try reader.interface.allocRemaining(allocator, .limited(1 << 20)), .permissions = stat.permissions };
}

fn restoreConfig(allocator: std.mem.Allocator, io: std.Io, p: *const paths.Paths, dir: []const u8, path: []const u8, backup: ConfigBackup) !void {
	const cwd = std.Io.Dir.cwd();
	// A failure before config.json was removed needs no repair (and may mean
	// the config directory itself is unwritable).
	if (exists(io, cwd, path)) return;
	try cwd.createDirPath(io, dir);
	var nonce: [16]u8 = undefined;
	io.random(&nonce);
	const tmp = try std.fmt.allocPrint(allocator, "{s}.{x}.tmp", .{ path, nonce });
	defer allocator.free(tmp);
	defer cwd.deleteFile(io, tmp) catch {};
	{
		const file = try cwd.createFile(io, tmp, .{ .exclusive = true, .permissions = backup.permissions });
		defer file.close(io);
		if (std.c.geteuid() == 0 and p.real_uid != 0) try file.setOwner(io, p.real_uid, null);
		var buf: [4096]u8 = undefined;
		var writer = file.writer(io, &buf);
		try writer.interface.writeAll(backup.bytes);
		try writer.flush();
		try file.sync(io);
	}
	try cwd.rename(tmp, cwd, path, io);
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
