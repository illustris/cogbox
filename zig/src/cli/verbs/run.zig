// `cogbox init` - validate args, then exec the bash launch script in
// the foreground with --init-only. The script seeds host state and (for
// customized per-instance flakes) warms the runner build, then stops before
// runtime setup. The VM launch itself is the `start` verb's job.
//
// This module also exports `validate`, shared by the `start` verb.

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");
const launch = @import("../launch.zig");

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	argv: []const []const u8,
) !void {
	const flags = [_]parse.Flag{
		.{ .long = "existing", .kind = .bool },
		.{ .long = "exclusive", .kind = .bool },
		.{ .long = "name", .short = 'n', .kind = .value },
		.{ .long = "vcpu", .kind = .value },
		.{ .long = "mem", .kind = .value },
		.{ .long = "network", .kind = .value },
		// Host-integration seeds, written into config.json on FIRST init only,
		// like every other init flag. Declared on `__launch` as well so the
		// custom-flake re-exec replays the argv it was handed verbatim.
		.{ .long = "bind-addr", .kind = .value },
		.{ .long = "no-implicit-dns", .kind = .bool },
		.{ .long = "dns-host", .kind = .value },
		.{ .long = "self-addr", .kind = .value_multi },
		.{ .long = "no-auto-keys", .kind = .bool },
		.{ .long = "yes", .short = 'y', .kind = .bool },
		.{ .long = "help", .short = 'h', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{ .verb = "init", .flags = &flags }, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, help.INIT);
		return;
	}

	const opts = try validate(&parsed, allocator, io, "init");
	try launch.execLaunchScript(allocator, io, env, opts, true);
}

/// Hidden `__launch` verb. Exec the launch script in full-launch mode in
/// place (no fork, no interactive init). Only used by the bash script's
/// custom-flake re-exec path (`nix run ... -- __launch`), which runs inside
/// the already-daemonized process and must not fork or prompt again.
pub fn launchInPlace(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	argv: []const []const u8,
) !void {
	// Only reachable via the bash re-exec, which runs under COGBOX_REEXECED=1.
	// A hand-typed `cogbox __launch` would launch QEMU in the foreground with
	// no daemonization, so reject it as an unknown verb.
	if (env.get("COGBOX_REEXECED") == null) {
		util.die(allocator, io, null, exit_codes.usage, "unknown verb '__launch'", .{});
	}
	const flags = [_]parse.Flag{
		.{ .long = "existing", .kind = .bool },
		.{ .long = "exclusive", .kind = .bool },
		.{ .long = "name", .short = 'n', .kind = .value },
		.{ .long = "vcpu", .kind = .value },
		.{ .long = "mem", .kind = .value },
		.{ .long = "network", .kind = .value },
		// Host-integration seeds, written into config.json on FIRST init only,
		// like every other init flag. Declared on `__launch` as well so the
		// custom-flake re-exec replays the argv it was handed verbatim.
		.{ .long = "bind-addr", .kind = .value },
		.{ .long = "no-implicit-dns", .kind = .bool },
		.{ .long = "dns-host", .kind = .value },
		.{ .long = "self-addr", .kind = .value_multi },
		// Launch-only host grants. Direct `init` deliberately does not declare
		// these; hidden `__launch` receives them after a custom-flake re-exec.
		.{ .long = "add-dir", .kind = .value_multi },
		.{ .long = "add-dir-ro", .kind = .value_multi },
		.{ .long = "no-auto-keys", .kind = .bool },
		.{ .long = "yes", .short = 'y', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{ .verb = "__launch", .flags = &flags }, argv);
	defer parsed.deinit();
	const opts = try validate(&parsed, allocator, io, "__launch");
	try launch.execLaunchScript(allocator, io, env, opts, false);
}

pub fn validate(
	parsed: *const parse.Parsed,
	allocator: std.mem.Allocator,
	io: std.Io,
	verb_name: []const u8,
) !launch.LaunchOpts {
	const name: ?[]const u8 = blk: {
		const v = parsed.get("name") orelse break :blk null;
		if (std.mem.eql(u8, v, "default")) {
			util.die(allocator, io, verb_name, exit_codes.dataerr, "'default' is reserved. Omit --name to use the default instance.", .{});
		}
		if (!parse.isValidName(v)) {
			util.die(allocator, io, verb_name, exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
		}
		break :blk v;
	};

	const vcpu: ?u32 = blk: {
		const v = parsed.get("vcpu") orelse break :blk null;
		break :blk parse.parseIntRange(v, 1, 256) catch |err| switch (err) {
			error.NotInteger => util.die(allocator, io, verb_name, exit_codes.dataerr, "--vcpu must be a positive integer", .{}),
			error.OutOfRange => util.die(allocator, io, verb_name, exit_codes.dataerr, "--vcpu must be between 1 and 256", .{}),
		};
	};

	const mem: ?u32 = blk: {
		const v = parsed.get("mem") orelse break :blk null;
		break :blk parse.parseIntRange(v, 256, 1_048_576) catch |err| switch (err) {
			error.NotInteger => util.die(allocator, io, verb_name, exit_codes.dataerr, "--mem must be a positive integer (megabytes)", .{}),
			error.OutOfRange => util.die(allocator, io, verb_name, exit_codes.dataerr, "--mem must be between 256 and 1048576 megabytes", .{}),
		};
	};

	const network: ?[]const u8 = blk: {
		const v = parsed.get("network") orelse break :blk null;
		_ = parse.parseNetworkMode(v) catch {
			util.die(allocator, io, verb_name, exit_codes.dataerr, "--network must be \"full\", \"none\", or \"rules\"", .{});
		};
		break :blk v;
	};

	// Caller-owned (the process execs immediately after; tests free it).
	const self_addrs = parsed.getAll(allocator, "self-addr") catch &.{};
	var additional_dirs: std.ArrayList(launch.AdditionalDir) = .empty;
	errdefer additional_dirs.deinit(allocator);
	for (parsed.multi.items) |m| {
		const read_only = if (std.mem.eql(u8, m.name, "add-dir"))
			false
		else if (std.mem.eql(u8, m.name, "add-dir-ro"))
			true
		else
			continue;
		validateAdditionalDirPath(allocator, io, verb_name, m.value);
		try additional_dirs.append(allocator, .{ .path = m.value, .read_only = read_only });
	}
	const additional_dirs_owned: []const launch.AdditionalDir = if (additional_dirs.items.len == 0) blk: {
		additional_dirs.deinit(allocator);
		break :blk &.{};
	} else try additional_dirs.toOwnedSlice(allocator);


	return .{
		.name = name,
		.existing = parsed.isSet("existing"),
		.exclusive = parsed.isSet("exclusive"),
		.vcpu = vcpu,
		.mem = mem,
		.network = network,
		.auto_keys = !parsed.isSet("no-auto-keys"),
		.yes = parsed.isSet("yes"),
		.bind_addr = parsed.get("bind-addr"),
		.no_implicit_dns = parsed.isSet("no-implicit-dns"),
		.dns_host = parsed.get("dns-host"),
		.self_addrs = self_addrs,
		.additional_dirs = additional_dirs_owned,
		.foreground = parsed.isSet("foreground"),
		.no_ssh = parsed.isSet("no-ssh"),
	};
}

fn validateAdditionalDirPath(
	allocator: std.mem.Allocator,
	io: std.Io,
	verb_name: []const u8,
	path: []const u8,
) void {
	for (path) |c| {
		if (std.ascii.isControl(c)) {
			util.die(allocator, io, verb_name, exit_codes.dataerr, "additional directory path contains an ASCII control character", .{});
		}
	}

	// The default follows a top-level symlink. Canonicalization and protected
	// path checks happen in the bash launcher, still relative to the caller's cwd.
	const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch {
		util.die(allocator, io, verb_name, exit_codes.noinput, "additional directory is missing or inaccessible: {s}", .{path});
	};
	if (stat.kind != .directory) {
		util.die(allocator, io, verb_name, exit_codes.dataerr, "additional directory option requires a directory: {s}", .{path});
	}
}
