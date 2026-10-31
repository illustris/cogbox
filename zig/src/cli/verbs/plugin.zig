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
const ssh_verb = @import("ssh.zig");
const plugin_module = @import("plugin_module");

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *const std.process.Environ.Map,
	p: *const paths.Paths,
	argv: []const []const u8,
) !void {
	// The live apply's whole-verb timer runs from process start.
	const started = std.Io.Timestamp.now(io, .awake);
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

	// `plugin apply` and its companions take the config lock with a bound (spec
	// 4.8) and hand the apply verb the lock descriptors; the mutating
	// subcommands pass the apply gate first and keep the blocking acquire, as
	// do list and resolve.
	const parsed_cmd: ?plugin_module.cli.Cmd = plugin_module.cli.parse(rest.items) catch null;
	const apply_args: ?plugin_module.cli.ApplyArgs = if (parsed_cmd) |cmd| switch (cmd) {
		.apply => |a| a,
		else => null,
	} else null;
	const mutating = if (parsed_cmd) |cmd| plugin_module.isMutating(cmd) else false;

	var host: plugin_module.apply.Host = .{
		.started = started,
		.real_uid = if (std.c.geteuid() == 0 and p.real_uid != 0) p.real_uid else null,
	};
	var guard: ?config_lock.Lock = null;
	defer if (guard) |g| g.deinit(io);
	var apply_lock: ?std.Io.File = null;
	defer if (apply_lock) |f| f.close(io);
	if (apply_args) |aa| {
		// Apply anyway is not in this cogbox yet: refused at once, before any
		// lock is opened or waited for (the config-lock wait below can take
		// 300 s behind a long plugin op).
		if (aa.force or aa.force_plan != null) {
			util.die(allocator, io, "plugin", exit_codes.usage, "{s}", .{plugin_module.apply.force_unsupported});
		}
		apply_lock = config_lock.openLockFile(allocator, io, p, name, ".apply.lock") catch |err| {
			util.die(allocator, io, "plugin", exit_codes.software, "cannot open the apply lock ({s})", .{@errorName(err)});
		};
		host.apply_fd = apply_lock.?.handle;
		switch (aa.mode) {
			.run => {
				// The verb's flags first, so the lock wait itself is ended by
				// SIGTERM/SIGINT/SIGHUP.
				plugin_module.apply.installSignals();
				guard = config_lock.acquireTimeout(allocator, io, p, name, plugin_module.apply.Bounds.dispatcher_lock_ms, &plugin_module.apply.terminate) catch |err| switch (err) {
					// The verb answers failed/busy.
					error.Timeout => null,
					error.Canceled => std.process.exit(128 +| plugin_module.apply.terminate.load(.acquire)),
					else => return err,
				};
			},
			.status, .cancel => {
				// Without the lock in 15 s these only report (and --cancel only
				// signals).
				guard = config_lock.acquireTimeout(allocator, io, p, name, plugin_module.apply.Bounds.status_lock_ms, null) catch |err| switch (err) {
					error.Timeout => null,
					else => return err,
				};
			},
			.abandon => {
				guard = config_lock.acquireTimeout(allocator, io, p, name, plugin_module.apply.Bounds.dispatcher_lock_ms, null) catch |err| switch (err) {
					error.Timeout => null,
					else => return err,
				};
			},
			// Reads one file; takes no lock.
			.log => {},
		}
		if (guard) |g| {
			host.config_fd = g.file.handle;
			host.config_held = true;
		}
		host.ssh_identity = ssh_verb.defaultIdentity(allocator, io, p);
	} else if (mutating) {
		// The apply gate (spec 4.8), before the blocking config-lock acquire:
		// the apply's own flock, held from here until this process exits. A
		// build-phase apply is superseded; one in its guest phase is waited for,
		// at most COGBOX_APPLY_WAIT_MAX, then exit 69 with nothing changed.
		apply_lock = config_lock.openLockFile(allocator, io, p, name, ".apply.lock") catch |err| {
			util.die(allocator, io, "plugin", exit_codes.software, "cannot open the apply lock ({s})", .{@errorName(err)});
		};
		{
			const icd = try paths.instanceConfigDir(allocator, p, name);
			defer allocator.free(icd);
			var arena_state = std.heap.ArenaAllocator.init(allocator);
			defer arena_state.deinit();
			const arena = arena_state.allocator();
			switch (plugin_module.apply.gate(arena, io, icd, apply_lock.?.handle, plugin_module.apply.gateCfg(env))) {
				.acquired => {},
				.busy => |g| util.die(allocator, io, "plugin", exit_codes.unavailable, "{s}", .{plugin_module.apply.busyMessage(arena, g)}),
				.failed => |err| util.die(allocator, io, "plugin", exit_codes.software, "cannot take the apply lock ({s})", .{@errorName(err)}),
			}
		}
		guard = try config_lock.acquire(allocator, io, p, name);
		host.apply_fd = apply_lock.?.handle;
		host.config_fd = guard.?.file.handle;
		host.config_held = true;
		host.gate_held = true;
		host.ssh_identity = ssh_verb.defaultIdentity(allocator, io, p);
	} else {
		guard = try config_lock.acquire(allocator, io, p, name);
	}
	defer if (host.ssh_identity) |id| allocator.free(id);

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

	try plugin_module.dispatch(allocator, io, env, name, cfg_path, inst_runtime, user_flake_dir, plugins_flake_dir, rest.items, host);
}
