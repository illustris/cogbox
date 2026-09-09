const std = @import("std");
pub const cli = @import("cli.zig");
pub const config = @import("config.zig");
pub const rule = @import("rule.zig");
pub const reload = @import("reload.zig");
const filter = @import("filter");
const secret_mod = @import("secret_module");
const secret_store = secret_mod.store;

/// The instance's L7 port base from config.json (`l7PortBase`), defaulting to
/// the canonical base. The funnel remap targets, the proxy's listeners, and
/// the mitmproxy hop all derive from this base (base / base+1 / base+2), so
/// multiple L7-enabled instances coexist without colliding on a shared port.
fn l7Base(loaded: *config.Loaded) u16 {
	const root = loaded.root().*;
	if (root == .object) {
		if (root.object.get("l7PortBase")) |v| {
			// Cap so base+2 stays a valid port.
			if (v == .integer and v.integer > 0 and v.integer <= 65533) return @intCast(v.integer);
		}
	}
	return filter.l7_default_base;
}

/// Entry point for the rules verb. The new top-level cogbox CLI parses
/// `--name` itself and constructs `--config`/`--runtime` from the active
/// instance, then forwards the remaining argv (subcommand + args) here.
///
/// `argv` is the slice after the verb (`rules`) but BEFORE `--config`/
/// `--runtime` are inserted; this function inserts them so the existing
/// `cli.parse` entry point keeps working unchanged.
pub fn dispatch(
	allocator: std.mem.Allocator,
	io: std.Io,
	config_path: []const u8,
	runtime_path: []const u8,
	rest: []const []const u8,
) !void {
	var argv = try allocator.alloc([]const u8, 4 + rest.len);
	defer allocator.free(argv);
	argv[0] = "--config";
	argv[1] = config_path;
	argv[2] = "--runtime";
	argv[3] = runtime_path;
	for (rest, 0..) |a, i| argv[4 + i] = a;

	const args = cli.parse(argv) catch |err| {
		try writeStderr(io, try std.fmt.allocPrint(allocator, "cogbox rules: error: {s}\n", .{@errorName(err)}));
		std.process.exit(64);
	};

	var loaded = config.load(allocator, io, args.config_path) catch |err| switch (err) {
		error.FileNotFound => return die(allocator, io, "no config found at {s}", .{args.config_path}, 66),
		error.InvalidJson => return die(allocator, io, "invalid JSON in {s}", .{args.config_path}, 65),
		else => return err,
	};
	defer loaded.deinit();

	const rules_arr = loaded.rules() catch |err| switch (err) {
		error.NotInRulesMode => return die(
			allocator,
			io,
			"instance is not in rules mode. Set network to rules mode first: edit {s} or reinit with --network rules.",
			.{args.config_path},
			65,
		),
		else => return err,
	};

	switch (args.cmd) {
		.list => try cmdList(allocator, io, rules_arr.*),
		.add => |a| try cmdAdd(allocator, io, args, rules_arr, a, &loaded),
		.del => |d| try cmdDel(allocator, io, args, rules_arr, d, &loaded),
		.set => try cmdSet(allocator, io, args, rules_arr, &loaded),
	}
}

/// Render the runtime rules file from the loaded config's .network value
/// (both CIDR and remap sections) and SIGUSR1 a running passt. No-op if
/// passt isn't running. Shared by `cogbox rules`, `cogbox remap`, `cogbox l7`,
/// `cogbox plugin` and any future verb that mutates rules-table state.
///
/// It seeds the managed inject specs for the same reason the boot render does:
/// netfilter-rules' L7 funnel and l7-rules' terminate-allow are DERIVED from
/// them, so re-rendering from the bare config would silently strip the funnel and
/// the api.anthropic.com terminate-allow off a running VM -- killing Claude auth
/// on the next `cogbox plugin add` / `rules add` until the instance restarted.
/// And it publishes the inject/auth confs the seeded specs imply, through the
/// same reload.writeWireFiles sequence the full render uses -- widening the rules
/// without them is the fail-open state (see the call site).
/// The seed reads only from the store; the config on disk (already saved by the
/// caller) is untouched, and `net_val` is a local copy for exactly that reason.
///
/// Store overrides: null env, i.e. the config-derived layout. The overrides exist
/// only for the container enforcer, which has no passt and therefore returns at
/// the guard above; were it ever reached there, an unresolvable store simply
/// reports nothing bound and no spec is seeded (fail closed, as today).
pub fn maybeReload(allocator: std.mem.Allocator, io: std.Io, runtime_path: []const u8, loaded: *config.Loaded) !void {
	const pid_path = try std.fs.path.join(allocator, &.{ runtime_path, "passt.pid" });
	defer allocator.free(pid_path);
	std.Io.Dir.cwd().access(io, pid_path, .{}) catch return;

	const net = try loaded.network();
	var net_val: std.json.Value = net.*;
	const dirs = try resolveSecretDirs(allocator, null, loaded.path);
	defer dirs.deinit(allocator);
	try seedManagedInjectSpecs(allocator, io, loaded, &net_val, dirs);

	// The SAME publish sequence renderFiles uses, for the same reason: this path
	// seeds the managed inject specs and therefore WIDENS l7-rules (the seeded
	// terminate-allow) and netfilter-rules (the funnel). Writing those two while
	// leaving l7-inject-conf.json as it was is exactly the fail-OPEN state the
	// ordering exists to prevent -- the proxy funnels and allows a host the addon
	// has no spec for, so the guest's placeholder Bearer goes upstream, the
	// provider 401s and claude-code drops into a re-auth. Reachable in the field:
	// cogworx binds claude-oauth with a `secret add` that carries no `-n` (so no
	// re-render) and the separate best-effort `secret reload -n <inst>` is skipped
	// on a non-live instance and only logged on failure; the next `plugin add` on
	// the VM/GCE backend then lands here with the store bound and the conf specless.
	//
	// Proxy gid: null, i.e. the confs are published but the store's group grants
	// are NOT reconciled on this path -- this entry point has no env (15 call
	// sites across `rules`, `remap`, `l7` and `plugin`, none of which carries
	// one). That is deliberately the SAFE half: `Grants` with a null gid neither
	// grants nor revokes, so the store's permissions are left exactly as the bind
	// (secret/store.zig stages the group on the value file) and the last full
	// render left them. A cred file this conf names but nothing has granted fails
	// CLOSED in the addon (403 "credential unavailable"), never open.
	//
	// Foreign specs: PRESERVED. l7-inject-conf.json has a second writer on the
	// VM/GCE path -- cogbox-launch.sh merges the HARNESS inject specs (the
	// host-side cred file + refresh block for api.anthropic.com) on top of the
	// boot render's output, and they exist nowhere this renderer can see. A live
	// render that replaced the file would strip them while leaving l7-rules'
	// terminate-allow and the :443 funnel standing, which is the very fail-open
	// this path publishes the conf to close. See reload.writeL7Inject.
	try reload.writeWireFiles(allocator, io, runtime_path, net_val, l7Base(loaded), dirs.global, dirs.instance, null, .preserve);
	const sent = try reload.maybeSignalPasst(allocator, io, runtime_path);
	_ = try reload.maybeSignalL7proxy(allocator, io, runtime_path);
	if (sent) try announce(allocator, io, "Rules reloaded.", .{});
}

/// Resolved secret-store directories (caller owns both slices).
pub const SecretDirs = struct {
	global: []const u8,
	instance: []const u8,

	pub fn deinit(self: SecretDirs, allocator: std.mem.Allocator) void {
		allocator.free(self.global);
		allocator.free(self.instance);
	}
};

/// Resolve the global + per-instance secret-store directories for the instance
/// whose config.json lives at `config_path`.
///
/// SECURITY (container enforcer): the store holds bound credential VALUES. In the
/// VM/launch path it derives from config_path's fixed layout -- the per-instance
/// store is a sibling `secrets/`, the global store is `<config>/secrets`. In the
/// container backend that layout lands on the state PVC the AGENT also mounts, so
/// a bound token would be readable from inside the sandbox. The
/// COGBOX_GLOBAL_SECRETS_DIR / COGBOX_INSTANCE_SECRETS_DIR env overrides repoint
/// the store at an ENFORCER-PRIVATE volume; both the `secret` verb (which WRITES
/// the store) and this renderer (which READS it) honor them, so a bind and its
/// inject-conf render always agree on one location. Each override is independent;
/// an unset var keeps the byte-for-byte config-derived path (VM path unchanged).
/// `env` is optional: a null map means "no overrides", i.e. the config-derived
/// layout. maybeReload passes null (see the note there).
pub fn resolveSecretDirs(
	allocator: std.mem.Allocator,
	env: ?*const std.process.Environ.Map,
	config_path: []const u8,
) !SecretDirs {
	const global = if (envGet(env, "COGBOX_GLOBAL_SECRETS_DIR")) |d|
		try allocator.dupe(u8, d)
	else blk: {
		const instance_dir = std.fs.path.dirname(config_path) orelse ".";
		const instances_dir = std.fs.path.dirname(instance_dir) orelse ".";
		const config_dir = std.fs.path.dirname(instances_dir) orelse ".";
		break :blk try std.fs.path.join(allocator, &.{ config_dir, "secrets" });
	};
	errdefer allocator.free(global);

	const instance = if (envGet(env, "COGBOX_INSTANCE_SECRETS_DIR")) |d|
		try allocator.dupe(u8, d)
	else blk: {
		const instance_dir = std.fs.path.dirname(config_path) orelse ".";
		break :blk try std.fs.path.join(allocator, &.{ instance_dir, "secrets" });
	};

	return .{ .global = global, .instance = instance };
}

fn envGet(env: ?*const std.process.Environ.Map, key: []const u8) ?[]const u8 {
	const e = env orelse return null;
	return e.get(key);
}

/// Seed the control-plane-owned inject specs (per-user Claude, per-user git) into
/// the network value THIS render will use, so a bound credential is not inert:
/// renderL7Inject only iterates specs the config declares, and renderL7 /
/// renderRules derive the terminate-allow + the L7 funnel from the same specs.
///
/// Runs on EVERY render path -- the VM boot render, `secret reload`, the container
/// enforcer render, and the rule/plugin-mutation reload -- because a bind is
/// equally inert on all of them. It used to be gated on the enforcer-private
/// secret-dir env overrides as a proxy for "am I the container enforcer", which
/// made Claude auth dead on every VM-family sandbox (the bind and the guest stub
/// both landed; nothing named the secret).
///
/// The gates that actually matter are per-seed and unchanged:
///   * claude: a VALUE FILE must exist for the reserved `claude-oauth` secret in
///     the store, so an owner who never connected Claude gets no spec, hence no
///     whole-host terminate-allow for api.anthropic.com (the L4 deny-list keeps
///     governing). Presence only -- see claudeOAuthBound for why that is enough
///     and where the stricter fail-closed check lives.
///   * git: a value file + kind=gitlab-oauth + an audience + an l7 rule already
///     naming that host (fail closed -- no grant rules, no spec).
/// Mutates `net_val` in place; new values are allocated in the config tree's arena.
fn seedManagedInjectSpecs(
	allocator: std.mem.Allocator,
	io: std.Io,
	loaded: *config.Loaded,
	net_val: *std.json.Value,
	dirs: SecretDirs,
) !void {
	var bound_arena = std.heap.ArenaAllocator.init(allocator);
	defer bound_arena.deinit();
	if (try reload.claudeOAuthBound(bound_arena.allocator(), io, dirs.instance, dirs.global)) {
		try reload.seedClaudeInjectSpec(loaded.treeAllocator(), net_val);
	}
	// Per-user git (GitLab) access: seed an inject spec for every BOUND
	// kind=gitlab-oauth secret in the global + instance stores (cogworx's
	// `secret bind` writes the GLOBAL store; an instance secret shadows a global
	// one of the same name, mirroring resolveSecret). Enumerates the stores
	// (secret names are `git-<provider>`, not knowable a priori).
	try reload.seedGitInjectSpecs(loaded.treeAllocator(), io, net_val, dirs.instance, dirs.global);
}

/// Full render: write EVERY runtime wire file from config.json. Backs the hidden
/// `cogbox __render-rules <config> <runtime>` verb that the launcher calls before
/// passt/the proxy start, so the boot path and hot-reload path share one renderer
/// (no jq/Zig drift), and the live re-render behind `secret add -n` / `secret
/// reload` / `l7 authpolicy replace`.
///
/// `foreign` says which of those the caller is: `.replace` for the BOOT render
/// (authoritative -- the launcher merges the harness inject specs back in right
/// afterwards), `.preserve` for a render against a RUNNING instance, whose conf
/// already carries that merge. reload.writeL7Inject documents the contract; a
/// live `.replace` here is the round-1 regression this parameter exists to make
/// un-writable by accident.
pub fn renderFiles(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	config_path: []const u8,
	runtime_path: []const u8,
	foreign: reload.ForeignSpecs,
) !void {
	var loaded = try config.load(allocator, io, config_path);
	defer loaded.deinit();
	const base = l7Base(&loaded);

	const dirs = try resolveSecretDirs(allocator, env, config_path);
	defer dirs.deinit(allocator);

	// "full"/"none" mode carries no .network object; render against null so the
	// runtime files (incl. an empty inject conf) are emitted defensively.
	var net_val: std.json.Value = blk: {
		const net = loaded.network() catch break :blk .null;
		break :blk net.*;
	};

	// Seed the control-plane-owned inject specs BEFORE the rule/L7 renders below,
	// so renderL7/renderRules also derive the terminate-allow + funnel for the
	// seeded hosts from them. Gated per-seed on the bound state of the credential
	// itself -- see seedManagedInjectSpecs.
	try seedManagedInjectSpecs(allocator, io, &loaded, &net_val, dirs);

	// A deployment that runs the L7 proxy on its OWN uid (COGBOX_PROXY_RUNAS: the
	// GCE host image, whose nftables floor needs a distinct skuid for the proxy)
	// has a reader that is not the store's owner, so the inject render also has to
	// grant that identity read on the cred files it names -- see credgrant.zig.
	// Resolved on EVERY render, which is what covers the runtime bind path:
	// `cogbox secret add -n <inst>` / `secret reload` come back through here, and
	// a rebind is an atomic rename that resets the file's group anyway.
	const proxy_gid = try reload.credgrant.proxyGidFromEnv(allocator, io, env);
	// ONE publish sequence, shared with maybeReload: netfilter-rules, then the
	// four inject/auth files, then the WIDENING l7-rules last (reload.zig's
	// writeWireFiles documents why the order is load-bearing, and a test pins it).
	try reload.writeWireFiles(allocator, io, runtime_path, net_val, base, dirs.global, dirs.instance, proxy_gid, foreign);
}

fn cmdList(allocator: std.mem.Allocator, io: std.Io, rules_arr: std.json.Array) !void {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);

	for (rules_arr.items, 0..) |r, i| {
		if (r != .object) continue;
		var line_buf: [32]u8 = undefined;
		const idx_str = std.fmt.bufPrint(&line_buf, "{d}: ", .{i + 1}) catch unreachable;
		try out.appendSlice(allocator, idx_str);

		const p = rule.ruleAction(r.object) orelse {
			try out.appendSlice(allocator, "unknown\n");
			continue;
		};
		try out.appendSlice(allocator, switch (p.action) {
			.allow => "allow ",
			.deny => "deny ",
		});
		try out.appendSlice(allocator, p.cidr);
		if (rule.ruleComment(r.object)) |c| {
			try out.appendSlice(allocator, "  # ");
			try out.appendSlice(allocator, c);
		}
		try out.append(allocator, '\n');
	}

	try writeStdout(io, out.items);
}

fn cmdAdd(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	rules_arr: *std.json.Array,
	a: cli.AddArgs,
	loaded: *config.Loaded,
) !void {
	const tree_alloc = loaded.treeAllocator();

	// The stored rule value is the whole spec after the action, matching the
	// on-disk/runtime grammar (`[tcp|udp] CIDR[:PORT]`). Fold an optional proto
	// qualifier into that spec so `list`/`set` round-trip it unchanged.
	const spec = if (a.proto) |pr|
		try std.fmt.allocPrint(allocator, "{s} {s}", .{ pr, a.cidr })
	else
		a.cidr;
	defer if (a.proto != null) allocator.free(spec);

	// The 0-based index of the rule object once inserted, so an optional --plugin
	// tag can be stamped onto exactly it.
	var inserted_idx: usize = undefined;
	if (a.pos) |p| {
		rule.insertAt(tree_alloc, rules_arr, p, a.action, spec) catch |err| switch (err) {
			error.IndexOutOfRange => return die(allocator, io, "position out of range (must be 1..{d})", .{rules_arr.items.len + 1}, 65),
			error.InvalidCidr => return die(allocator, io, "invalid rule: {s}", .{spec}, 65),
			else => return err,
		};
		inserted_idx = p - 1;
	} else {
		const n = rule.append(tree_alloc, rules_arr, a.action, spec) catch |err| switch (err) {
			error.InvalidCidr => return die(allocator, io, "invalid rule: {s}", .{spec}, 65),
			else => return err,
		};
		inserted_idx = n - 1;
	}

	// --plugin NAME: tag the inserted rule so `plugin del NAME` removes exactly it
	// (the same `"plugin"` field the plugin verb's merge stamps).
	if (a.plugin) |tag| {
		const obj = &rules_arr.items[inserted_idx].object;
		try obj.put(tree_alloc, try tree_alloc.dupe(u8, "plugin"), .{ .string = try tree_alloc.dupe(u8, tag) });
	}

	try config.save(allocator, io, args.config_path, loaded.root().*);
	const action_str = switch (a.action) {
		.allow => "allow",
		.deny => "deny",
	};
	if (a.pos) |p| {
		try announce(allocator, io, "Added: {s} {s} at position {d}", .{ action_str, spec, p });
	} else {
		try announce(allocator, io, "Added: {s} {s}", .{ action_str, spec });
	}
	try maybeReload(allocator, io, args.runtime_path, loaded);
}

fn cmdDel(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	rules_arr: *std.json.Array,
	d: cli.DelArgs,
	loaded: *config.Loaded,
) !void {
	rule.delete(rules_arr, d.index) catch {
		return die(allocator, io, "index {d} out of range (1..{d})", .{ d.index, rules_arr.items.len }, 65);
	};

	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "Deleted rule {d}.", .{d.index});
	try maybeReload(allocator, io, args.runtime_path, loaded);
}

fn cmdSet(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	rules_arr: *std.json.Array,
	loaded: *config.Loaded,
) !void {
	const stdin = std.Io.File.stdin();
	var stdin_buf: [4096]u8 = undefined;
	var stdin_reader = stdin.readerStreaming(io, &stdin_buf);

	var pairs: std.ArrayList(rule.Pair) = .empty;
	defer pairs.deinit(allocator);
	var owned_storage: std.ArrayList(u8) = .empty;
	defer owned_storage.deinit(allocator);
	var owned_offsets: std.ArrayList(struct { off: usize, len: usize }) = .empty;
	defer owned_offsets.deinit(allocator);

	while (true) {
		const maybe_line = try stdin_reader.interface.takeDelimiter('\n');
		const line = maybe_line orelse break;
		const parsed = rule.parseSetLine(line) catch {
			return die(allocator, io, "invalid line: {s}", .{line}, 65);
		};
		if (parsed) |p| {
			const off = owned_storage.items.len;
			try owned_storage.appendSlice(allocator, p.cidr);
			try owned_offsets.append(allocator, .{ .off = off, .len = p.cidr.len });
			try pairs.append(allocator, .{ .action = p.action, .cidr = "" });
		}
	}
	for (pairs.items, owned_offsets.items) |*p, o| {
		p.cidr = owned_storage.items[o.off .. o.off + o.len];
	}

	try rule.replaceAll(loaded.treeAllocator(), rules_arr, pairs.items);
	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "Rules replaced.", .{});
	try maybeReload(allocator, io, args.runtime_path, loaded);
}

fn writeStdout(io: std.Io, bytes: []const u8) !void {
	const stdout = std.Io.File.stdout();
	var buf: [4096]u8 = undefined;
	var w = stdout.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn writeStderr(io: std.Io, bytes: []const u8) !void {
	const stderr = std.Io.File.stderr();
	var buf: [4096]u8 = undefined;
	var w = stderr.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn announce(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype) !void {
	const msg = try std.fmt.allocPrint(allocator, fmt ++ "\n", args);
	defer allocator.free(msg);
	try writeStdout(io, msg);
}

fn die(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype, code: u8) noreturn {
	const msg = std.fmt.allocPrint(allocator, "cogbox rules: error: " ++ fmt ++ "\n", args) catch "cogbox rules: error: (message too long)\n";
	writeStderr(io, msg) catch {};
	std.process.exit(code);
}

test "resolveSecretDirs honors env overrides, else derives from config_path" {
	const t = std.testing;
	const cfg = "/var/lib/cogbox-state/config/cogbox/instances/web/config.json";

	// No overrides -> the historical config-derived layout (VM path, unchanged).
	{
		var env = std.process.Environ.Map.init(t.allocator);
		defer env.deinit();
		const d = try resolveSecretDirs(t.allocator, &env, cfg);
		defer d.deinit(t.allocator);
		try t.expectEqualStrings("/var/lib/cogbox-state/config/cogbox/secrets", d.global);
		try t.expectEqualStrings("/var/lib/cogbox-state/config/cogbox/instances/web/secrets", d.instance);
	}

	// Both overrides set -> used verbatim (the enforcer-private store, never the
	// agent-readable PVC -- the secret-leak guard).
	{
		var env = std.process.Environ.Map.init(t.allocator);
		defer env.deinit();
		try env.put("COGBOX_GLOBAL_SECRETS_DIR", "/run/cogbox-secrets/global");
		try env.put("COGBOX_INSTANCE_SECRETS_DIR", "/run/cogbox-secrets/instance");
		const d = try resolveSecretDirs(t.allocator, &env, cfg);
		defer d.deinit(t.allocator);
		try t.expectEqualStrings("/run/cogbox-secrets/global", d.global);
		try t.expectEqualStrings("/run/cogbox-secrets/instance", d.instance);
	}

	// Each override is independent: only the global set -> instance still derived.
	{
		var env = std.process.Environ.Map.init(t.allocator);
		defer env.deinit();
		try env.put("COGBOX_GLOBAL_SECRETS_DIR", "/run/cogbox-secrets/global");
		const d = try resolveSecretDirs(t.allocator, &env, cfg);
		defer d.deinit(t.allocator);
		try t.expectEqualStrings("/run/cogbox-secrets/global", d.global);
		try t.expectEqualStrings("/var/lib/cogbox-state/config/cogbox/instances/web/secrets", d.instance);
	}
}

/// A throwaway instance layout mirroring the VM/launch path's fixed shape:
///   <root>/instances/<name>/config.json   (the config the renderer loads)
///   <root>/secrets/                       (the GLOBAL store `cogbox secret add` writes)
///   <root>/rt/                            (the runtime dir the render targets)
/// Returns the root; caller deletes the tree.
fn tmpInstanceLayout(gpa: std.mem.Allocator, io: std.Io, network_json: []const u8) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	const root = try std.fmt.allocPrint(gpa, "zig-render-test-{s}", .{hexb});
	const cwd = std.Io.Dir.cwd();

	const inst_dir = try std.fs.path.join(gpa, &.{ root, "instances", "web" });
	defer gpa.free(inst_dir);
	try cwd.createDirPath(io, inst_dir);
	const rt = try std.fs.path.join(gpa, &.{ root, "rt" });
	defer gpa.free(rt);
	try cwd.createDirPath(io, rt);

	const cfg_path = try std.fs.path.join(gpa, &.{ inst_dir, "config.json" });
	defer gpa.free(cfg_path);
	const body = try std.fmt.allocPrint(gpa, "{{\"network\":{s}}}\n", .{network_json});
	defer gpa.free(body);
	const f = try cwd.createFile(io, cfg_path, .{ .truncate = true });
	defer f.close(io);
	var wbuf: [4096]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll(body);
	try w.flush();
	return root;
}

fn readWholeFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
	const f = try std.Io.Dir.cwd().openFile(io, path, .{});
	defer f.close(io);
	var rbuf: [4096]u8 = undefined;
	var r = f.reader(io, &rbuf);
	return r.interface.allocRemaining(gpa, .limited(1 << 20));
}

fn readRuntimeFile(gpa: std.mem.Allocator, io: std.Io, root: []const u8, name: []const u8) ![]u8 {
	const path = try std.fs.path.join(gpa, &.{ root, "rt", name });
	defer gpa.free(path);
	return readWholeFile(gpa, io, path);
}

/// The default rules-mode network cogworx/cogbox writes for a sandbox whose HOST
/// user never logged into a harness: L4 allow-list, NO `.l7` key at all (the
/// launcher's harness seed is skipped -- `[ -f "$cred" ] || continue`). This is
/// the exact shape every cogworx-managed GCE / k8s-microVM sandbox boots with.
const vm_default_network =
	\\{"rules":[{"deny":"169.254.0.0/16","comment":"link-local"},{"allow":"0.0.0.0/0","comment":"public internet"}]}
;

fn bindClaudeOAuth(gpa: std.mem.Allocator, io: std.Io, store_dir: []const u8) !void {
	try secret_store.add(gpa, io, store_dir, secret_mod.claude_oauth_secret, "sk-ant-oat01-FAKEFAKEFAKEFAKEFAKE", .{
		.audience = secret_mod.anthropic_api_host,
		.kind = secret_mod.anthropic_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	});
}

test "renderFiles: a VM-shaped render (NO secret-dir overrides) seeds the claude spec, terminate-allow and funnel once claude-oauth is bound" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpInstanceLayout(gpa, io, vm_default_network);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};
	const cfg_path = try std.fs.path.join(gpa, &.{ root, "instances", "web", "config.json" });
	defer gpa.free(cfg_path);
	const rt = try std.fs.path.join(gpa, &.{ root, "rt" });
	defer gpa.free(rt);

	// The bind cogworx's claude reconcile performs on a VM backend: `cogbox secret
	// add claude-oauth --audience api.anthropic.com --kind anthropic-oauth`, which
	// lands in the GLOBAL store (<config>/secrets) -- no env overrides anywhere,
	// because only the container enforcer/worker sets those.
	const global_store = try std.fs.path.join(gpa, &.{ root, "secrets" });
	defer gpa.free(global_store);
	try bindClaudeOAuth(gpa, io, global_store);

	var env = std.process.Environ.Map.init(gpa);
	defer env.deinit();
	try renderFiles(gpa, io, &env, cfg_path, rt, .replace);

	// 1. l7-inject-conf.json NAMES the bound secret for the host, in the
	//    anthropic-oauth style, over the shared guest stub sentinel.
	const conf = try readRuntimeFile(gpa, io, root, "l7-inject-conf.json");
	defer gpa.free(conf);
	try std.testing.expect(std.mem.indexOf(u8, conf, secret_mod.anthropic_api_host) != null);
	try std.testing.expect(std.mem.indexOf(u8, conf, "\"style\": \"anthropic-oauth\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, conf, secret_mod.claude_stub_token) != null);

	// 2. l7-rules terminate-allows the host: the addon can only stamp a Bearer on
	//    a MITM-terminated flow.
	const l7 = try readRuntimeFile(gpa, io, root, "l7-rules");
	defer gpa.free(l7);
	var allow_buf: [64]u8 = undefined;
	const allow_line = std.fmt.bufPrint(&allow_buf, "allow {s} terminate\n", .{secret_mod.anthropic_api_host}) catch unreachable;
	try std.testing.expect(std.mem.indexOf(u8, l7, allow_line) != null);

	// 3. netfilter-rules funnels guest web egress at the proxy (l7Active is derived
	//    from the same specs) -- without it the guest reaches the API directly and
	//    the placeholder Bearer is never replaced.
	const nf = try readRuntimeFile(gpa, io, root, "netfilter-rules");
	defer gpa.free(nf);
	try std.testing.expect(std.mem.indexOf(u8, nf, "remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:") != null);
}

test "renderFiles: a VM-shaped render with NOTHING bound leaves api.anthropic.com untouched (never-connected owner)" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpInstanceLayout(gpa, io, vm_default_network);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};
	const cfg_path = try std.fs.path.join(gpa, &.{ root, "instances", "web", "config.json" });
	defer gpa.free(cfg_path);
	const rt = try std.fs.path.join(gpa, &.{ root, "rt" });
	defer gpa.free(rt);

	var env = std.process.Environ.Map.init(gpa);
	defer env.deinit();
	try renderFiles(gpa, io, &env, cfg_path, rt, .replace);

	// No spec, no inject entry, NO whole-host terminate-allow (the L4 deny-list
	// keeps governing api.anthropic.com), and no funnel: an owner who never
	// connected Claude must not have the host L7-terminated.
	const conf = try readRuntimeFile(gpa, io, root, "l7-inject-conf.json");
	defer gpa.free(conf);
	try std.testing.expect(std.mem.indexOf(u8, conf, secret_mod.anthropic_api_host) == null);
	const hosts = try readRuntimeFile(gpa, io, root, "l7-inject-hosts");
	defer gpa.free(hosts);
	try std.testing.expect(std.mem.indexOf(u8, hosts, secret_mod.anthropic_api_host) == null);
	const l7 = try readRuntimeFile(gpa, io, root, "l7-rules");
	defer gpa.free(l7);
	try std.testing.expect(std.mem.indexOf(u8, l7, secret_mod.anthropic_api_host) == null);
	const nf = try readRuntimeFile(gpa, io, root, "netfilter-rules");
	defer gpa.free(nf);
	try std.testing.expect(std.mem.indexOf(u8, nf, "127.0.0.1:") == null);
}

test "renderFiles: a CONTAINER-shaped render (both secret-dir overrides, enforcer-private store) renders exactly one claude spec from the override store" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpInstanceLayout(gpa, io, vm_default_network);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};
	const cfg_path = try std.fs.path.join(gpa, &.{ root, "instances", "web", "config.json" });
	defer gpa.free(cfg_path);
	const rt = try std.fs.path.join(gpa, &.{ root, "rt" });
	defer gpa.free(rt);

	// The enforcer keeps the store on a private volume, NOT the config-derived
	// (agent-readable) path: bind there and leave <config>/secrets empty.
	const priv_global = try std.fs.path.join(gpa, &.{ root, "enforcer-global" });
	defer gpa.free(priv_global);
	const priv_instance = try std.fs.path.join(gpa, &.{ root, "enforcer-instance" });
	defer gpa.free(priv_instance);
	try bindClaudeOAuth(gpa, io, priv_global);

	var env = std.process.Environ.Map.init(gpa);
	defer env.deinit();
	try env.put("COGBOX_GLOBAL_SECRETS_DIR", priv_global);
	try env.put("COGBOX_INSTANCE_SECRETS_DIR", priv_instance);
	try renderFiles(gpa, io, &env, cfg_path, rt, .replace);

	// Byte-exact render, so this test also pins the pre-existing container output:
	// ONE spec, cred_file inside the enforcer-private store, plus the terminate
	// allow + the two funnel remaps. (Dropping the env-override seed gate must not
	// change any of it, and must not seed twice.)
	const conf = try readRuntimeFile(gpa, io, root, "l7-inject-conf.json");
	defer gpa.free(conf);
	// (jq --tab formatting, so the expected bytes carry literal tabs -- which a
	// multiline string literal cannot hold.)
	const expected_conf = try std.fmt.allocPrint(gpa, "[\n" ++
		"\t{{\n" ++
		"\t\t\"host\": \"api.anthropic.com\",\n" ++
		// The provenance stamp every RENDERED spec carries, so the next live
		// render can tell its own elements from the ones the launcher merged in
		// (reload.ForeignSpecs). Inert on the wire: both readers of this file
		// look up named keys only.
		"\t\t\"origin\": \"render\",\n" ++
		"\t\t\"style\": \"anthropic-oauth\",\n" ++
		"\t\t\"cred_file\": \"{s}/claude-oauth\",\n" ++
		"\t\t\"cred_format\": \"raw\",\n" ++
		"\t\t\"stub_token\": \"{s}\"\n" ++
		"\t}}\n" ++
		"]\n", .{ priv_global, secret_mod.claude_stub_token });
	defer gpa.free(expected_conf);
	try std.testing.expectEqualStrings(expected_conf, conf);

	const hosts = try readRuntimeFile(gpa, io, root, "l7-inject-hosts");
	defer gpa.free(hosts);
	try std.testing.expectEqualStrings("api.anthropic.com\n", hosts);

	const l7 = try readRuntimeFile(gpa, io, root, "l7-rules");
	defer gpa.free(l7);
	try std.testing.expectEqualStrings("mode terminate\nallow api.anthropic.com terminate\n", l7);
}

test "maybeReload: a live-VM re-render (rule/plugin mutation) keeps the claude funnel + terminate-allow instead of stripping them" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpInstanceLayout(gpa, io, vm_default_network);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};
	const cfg_path = try std.fs.path.join(gpa, &.{ root, "instances", "web", "config.json" });
	defer gpa.free(cfg_path);
	const rt = try std.fs.path.join(gpa, &.{ root, "rt" });
	defer gpa.free(rt);
	const global_store = try std.fs.path.join(gpa, &.{ root, "secrets" });
	defer gpa.free(global_store);
	try bindClaudeOAuth(gpa, io, global_store);

	// maybeReload only fires for a RUNNING instance (passt.pid present). Point the
	// pidfile at a pid that cannot exist so signalPidfile's kill(pid, 0) probe
	// fails and nothing is signalled -- we assert on the rendered files.
	{
		const pidf = try std.fs.path.join(gpa, &.{ rt, "passt.pid" });
		defer gpa.free(pidf);
		const f = try cwd.createFile(io, pidf, .{ .truncate = true });
		defer f.close(io);
		var wbuf: [16]u8 = undefined;
		var w = f.writer(io, &wbuf);
		try w.interface.writeAll("2147483647\n");
		try w.flush();
	}

	var loaded = try config.load(gpa, io, cfg_path);
	defer loaded.deinit();
	try maybeReload(gpa, io, rt, &loaded);

	const l7 = try readRuntimeFile(gpa, io, root, "l7-rules");
	defer gpa.free(l7);
	try std.testing.expectEqualStrings("mode terminate\nallow api.anthropic.com terminate\n", l7);
	const nf = try readRuntimeFile(gpa, io, root, "netfilter-rules");
	defer gpa.free(nf);
	try std.testing.expect(std.mem.indexOf(u8, nf, "remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:") != null);

	// ...and the INJECT CONF the widened rules assume, from the same pass. This
	// path used to write the funnel + terminate-allow and no conf at all, which is
	// the fail-OPEN interleave: the proxy funnels and allows api.anthropic.com
	// while the addon has no spec for it, so the guest's placeholder Bearer goes
	// upstream, the provider 401s and claude-code drops into a re-auth. Reachable
	// whenever a bind happened without a render (cogworx's `secret add` carries no
	// `-n`) and the next `plugin add` on a live VM lands here.
	const conf = try readRuntimeFile(gpa, io, root, "l7-inject-conf.json");
	defer gpa.free(conf);
	try std.testing.expect(std.mem.indexOf(u8, conf, "\"host\": \"api.anthropic.com\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, conf, "/claude-oauth") != null);
	const inj_hosts = try readRuntimeFile(gpa, io, root, "l7-inject-hosts");
	defer gpa.free(inj_hosts);
	try std.testing.expectEqualStrings("api.anthropic.com\n", inj_hosts);
	// The auth-proxy half of the same pass is published too (empty, but VALID:
	// its reader caches a version-1 document instead of re-parsing a refusal).
	const auth_conf = try readRuntimeFile(gpa, io, root, "l7-auth-conf.json");
	defer gpa.free(auth_conf);
	try std.testing.expect(std.mem.indexOf(u8, auth_conf, "\"version\": 1") != null);

	// The config on disk is NOT rewritten: the seed is a render-time overlay, so a
	// spec never becomes a persisted (and therefore un-revocable) config entry.
	const on_disk = try readWholeFile(gpa, io, cfg_path);
	defer gpa.free(on_disk);
	try std.testing.expect(std.mem.indexOf(u8, on_disk, "inject") == null);
}

/// Point <rt>/passt.pid at a pid that cannot exist, so maybeReload runs (it fires
/// only for an instance with a pidfile) while signalPidfile's kill(pid, 0) probe
/// fails and nothing is signalled -- the assertions are on the rendered files.
fn writeDeadPasstPid(gpa: std.mem.Allocator, io: std.Io, rt: []const u8) !void {
	const pidf = try std.fs.path.join(gpa, &.{ rt, "passt.pid" });
	defer gpa.free(pidf);
	const f = try std.Io.Dir.cwd().createFile(io, pidf, .{ .truncate = true });
	defer f.close(io);
	var wbuf: [16]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll("2147483647\n");
	try w.flush();
}

/// How many times `needle` occurs in `hay` (non-overlapping).
fn countOccurrences(hay: []const u8, needle: []const u8) usize {
	var n: usize = 0;
	var i: usize = 0;
	while (std.mem.indexOfPos(u8, hay, i, needle)) |at| : (i = at + needle.len) n += 1;
	return n;
}

/// Write `body` into <rt>/<name>, standing in for a writer that is not this
/// renderer (cogbox-launch.sh's `jq -s add` + `mv` merge).
fn writeRuntimeFileRaw(gpa: std.mem.Allocator, io: std.Io, rt: []const u8, name: []const u8, body: []const u8) !void {
	const path = try std.fs.path.join(gpa, &.{ rt, name });
	defer gpa.free(path);
	const f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
	defer f.close(io);
	var wbuf: [4096]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll(body);
	try w.flush();
}

/// One HARNESS inject spec exactly as cogbox-launch.sh's gen_inject_conf emits it
/// for claude-code: a host-side cred file with a token_path, the NESTED `refresh`
/// object (the four optional TSV fields plus the `expires_at_unit` jq adds), the
/// redaction stub, and NO `origin` -- the whole thing is projected from the
/// launcher's shell state, so no render can reproduce any of it.
///
/// The refresh block matters more than the rest of the spec: it is what lets the
/// addon do the OAuth refresh-token grant host-side for a harness whose token is
/// EVICTED from the guest, so dropping it on a live render would leave the
/// injection working only until the access token expired.
const launcher_merged_conf =
	\\[
	\\  {"host":"api.anthropic.com","style":"anthropic-oauth",
	\\   "cred_file":"/home/testuser/.claude/.credentials.json",
	\\   "token_path":"claudeAiOauth.accessToken",
	\\   "refresh":{"refresh_token_path":"claudeAiOauth.refreshToken",
	\\              "expires_at_path":"claudeAiOauth.expiresAt",
	\\              "token_url":"https://platform.claude.com/v1/oauth/token",
	\\              "client_id":"9d1c250a-e61b-44d9-88ed-5944d1962f5e",
	\\              "expires_at_unit":"ms"},
	\\   "stub_token":"sk-ant-oat01-cogbox-host-injected-placeholder"}
	\\]
;

/// The instance shape tests/test_script.py boots as the inject-auto case and the
/// field's stock rules-mode sandbox: terminate mode, a whole-host allow, and the
/// LEGACY BOOL `inject` (which carries no specs at all). Nothing here can produce
/// an inject spec -- the launcher's merge is the only thing that puts one in the
/// conf, which is precisely why a live render must not replace that file.
const harness_only_network =
	\\{"rules":[{"allow":"0.0.0.0/0","comment":"public internet"}],
	\\ "l7":{"mode":"terminate","inject":true,"rules":[{"allow":"api.anthropic.com"}]}}
;

test "maybeReload: the HARNESS inject spec cogbox-launch.sh merged in survives a live re-render (two-writer contract)" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpInstanceLayout(gpa, io, harness_only_network);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};
	const cfg_path = try std.fs.path.join(gpa, &.{ root, "instances", "web", "config.json" });
	defer gpa.free(cfg_path);
	const rt = try std.fs.path.join(gpa, &.{ root, "rt" });
	defer gpa.free(rt);
	try writeDeadPasstPid(gpa, io, rt);
	// Boot state: __render-rules wrote an EMPTY conf (nothing in config or the
	// store names a spec), then the launcher merged the harness half on top.
	try writeRuntimeFileRaw(gpa, io, rt, "l7-inject-conf.json", launcher_merged_conf);

	// The routine live verb: `cogbox plugin add`, `rules add`, or cogworx's git
	// reconcile `cogbox l7 replace`.
	var loaded = try config.load(gpa, io, cfg_path);
	defer loaded.deinit();
	try maybeReload(gpa, io, rt, &loaded);

	// The conf still names the harness credential. Replacing it here would leave
	// the terminate-allow + funnel below standing for a host the addon has no spec
	// for -- and a SUCCESSFUL read of a valid empty array is not stale, so none of
	// the addon's fail-closed machinery fires: the guest's placeholder Bearer goes
	// upstream, api.anthropic.com 401s, and claude-code reports an expired login.
	const conf = try readRuntimeFile(gpa, io, root, "l7-inject-conf.json");
	defer gpa.free(conf);
	try std.testing.expect(std.mem.indexOf(u8, conf, "/home/testuser/.claude/.credentials.json") != null);
	try std.testing.expect(std.mem.indexOf(u8, conf, "\"host\": \"api.anthropic.com\"") != null);
	// Carried over verbatim: no `origin` stamp is invented for someone else's spec.
	try std.testing.expect(std.mem.indexOf(u8, conf, "\"origin\"") == null);
	// The NESTED refresh object survives the round-trip through std.json and the
	// re-serialisation, keys and all. Losing it is the quiet half of this bug: the
	// injection would keep working until the access token expired and only then
	// start 401ing, with nothing in the conf to point at. Both a leaf key the
	// launcher sourced from its TSV and one jq synthesises are asserted, because a
	// reconstruct-from-known-fields regression would drop exactly the latter.
	try std.testing.expect(std.mem.indexOf(u8, conf, "\"refresh_token_path\": \"claudeAiOauth.refreshToken\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, conf, "\"expires_at_unit\": \"ms\"") != null);

	// IDEMPOTENT: a second live render must carry the same spec over ONCE, not
	// append its own copy of what it just preserved. An accumulating conf would
	// grow without bound across a session's plugin/rule edits, and the addon takes
	// the LAST spec for a host -- so a duplicate is also a silent way for a stale
	// copy to win over a fresh one.
	try maybeReload(gpa, io, rt, &loaded);
	const conf2 = try readRuntimeFile(gpa, io, root, "l7-inject-conf.json");
	defer gpa.free(conf2);
	try std.testing.expectEqual(@as(usize, 1), countOccurrences(conf2, "/home/testuser/.claude/.credentials.json"));
	try std.testing.expectEqual(@as(usize, 1), countOccurrences(conf2, "\"refresh\""));

	const l7 = try readRuntimeFile(gpa, io, root, "l7-rules");
	defer gpa.free(l7);
	try std.testing.expectEqualStrings("mode terminate\nallow api.anthropic.com\n", l7);

	// A preserved spec is inert beyond the conf: its host does NOT join the
	// plain-HTTP inject-routing list (the launcher keeps harness hosts out of it so
	// the guest cannot force a cleartext send of the real token).
	const inj_hosts = try readRuntimeFile(gpa, io, root, "l7-inject-hosts");
	defer gpa.free(inj_hosts);
	try std.testing.expectEqualStrings("", inj_hosts);
}

test "maybeReload: rendered specs are replaced (a withdrawn one goes) while the harness spec is preserved LAST" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpInstanceLayout(gpa, io, vm_default_network);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};
	const cfg_path = try std.fs.path.join(gpa, &.{ root, "instances", "web", "config.json" });
	defer gpa.free(cfg_path);
	const rt = try std.fs.path.join(gpa, &.{ root, "rt" });
	defer gpa.free(rt);
	const global_store = try std.fs.path.join(gpa, &.{ root, "secrets" });
	defer gpa.free(global_store);
	try bindClaudeOAuth(gpa, io, global_store);
	try writeDeadPasstPid(gpa, io, rt);

	// The conf as a live instance carries it: one spec a PREVIOUS render authored
	// for a host nothing names any more (a git grant since revoked), plus the
	// launcher's harness spec.
	const before =
		\\[
		\\  {"host":"git.example.com","origin":"render","style":"gitlab-oauth",
		\\   "cred_file":"/nonexistent/git-gitlab","cred_format":"raw","rules_tag":"git-grants"},
		\\  {"host":"api.anthropic.com","style":"anthropic-oauth",
		\\   "cred_file":"/home/testuser/.claude/.credentials.json",
		\\   "token_path":"claudeAiOauth.accessToken"}
		\\]
	;
	try writeRuntimeFileRaw(gpa, io, rt, "l7-inject-conf.json", before);

	var loaded = try config.load(gpa, io, cfg_path);
	defer loaded.deinit();
	try maybeReload(gpa, io, rt, &loaded);

	const conf = try readRuntimeFile(gpa, io, root, "l7-inject-conf.json");
	defer gpa.free(conf);
	// Withdrawal still works: an element THIS renderer stamped is re-rendered from
	// config + store, so the revoked git spec is gone.
	try std.testing.expect(std.mem.indexOf(u8, conf, "git.example.com") == null);
	// The seeded claude spec (bound store secret) is rendered...
	const rendered_at = std.mem.indexOf(u8, conf, "/claude-oauth") orelse return error.MissingRenderedSpec;
	// ...and the harness spec is carried over AFTER it, so the addon's
	// last-write-by-host resolution gives the harness spec the host -- the same
	// precedence cogbox-launch.sh's `jq -s add` establishes at boot.
	const foreign_at = std.mem.indexOf(u8, conf, "/home/testuser/.claude/.credentials.json") orelse return error.HarnessSpecDropped;
	try std.testing.expect(foreign_at > rendered_at);
}

test "maybeReload: an UNSTAMPED spec naming a store path is re-rendered, not preserved (pre-stamp image skew)" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpInstanceLayout(gpa, io, vm_default_network);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};
	const cfg_path = try std.fs.path.join(gpa, &.{ root, "instances", "web", "config.json" });
	defer gpa.free(cfg_path);
	const rt = try std.fs.path.join(gpa, &.{ root, "rt" });
	defer gpa.free(rt);
	const global_store = try std.fs.path.join(gpa, &.{ root, "secrets" });
	defer gpa.free(global_store);
	try bindClaudeOAuth(gpa, io, global_store);
	try writeDeadPasstPid(gpa, io, rt);

	// The conf a cogbox OLDER than the provenance stamp left behind: a rendered
	// spec with no `origin`, naming a store path, alongside the launcher's
	// harness spec. Preserving the first would pin a stale spec on the host
	// forever (appended last, it would even outrank the fresh render).
	const before = try std.fmt.allocPrint(gpa,
		\\[
		\\  {{"host":"api.anthropic.com","style":"anthropic-oauth",
		\\   "cred_file":"{s}/claude-oauth","cred_format":"raw","stub_token":"stale-render-stub"}},
		\\  {{"host":"api.anthropic.com","style":"anthropic-oauth",
		\\   "cred_file":"/home/testuser/.claude/.credentials.json",
		\\   "token_path":"claudeAiOauth.accessToken"}}
		\\]
	, .{global_store});
	defer gpa.free(before);
	try writeRuntimeFileRaw(gpa, io, rt, "l7-inject-conf.json", before);

	var loaded = try config.load(gpa, io, cfg_path);
	defer loaded.deinit();
	try maybeReload(gpa, io, rt, &loaded);

	const conf = try readRuntimeFile(gpa, io, root, "l7-inject-conf.json");
	defer gpa.free(conf);
	// Only this renderer emits a cred_file inside the store, so the unstamped
	// store-path spec is recognized as ours and re-rendered (the stale stub is
	// gone, the current stub is back)...
	try std.testing.expect(std.mem.indexOf(u8, conf, "stale-render-stub") == null);
	try std.testing.expect(std.mem.indexOf(u8, conf, secret_mod.claude_stub_token) != null);
	// ...while the launcher's host-side spec, which no render can reproduce, stays.
	try std.testing.expect(std.mem.indexOf(u8, conf, "/home/testuser/.claude/.credentials.json") != null);
}

test "renderFiles(.replace): the BOOT render resets the conf, dropping the previous boot's merge" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpInstanceLayout(gpa, io, harness_only_network);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};
	const cfg_path = try std.fs.path.join(gpa, &.{ root, "instances", "web", "config.json" });
	defer gpa.free(cfg_path);
	const rt = try std.fs.path.join(gpa, &.{ root, "rt" });
	defer gpa.free(rt);
	// The runtime dir outlives a stop/start within a host session, so the previous
	// boot's merged conf is sitting there.
	try writeRuntimeFileRaw(gpa, io, rt, "l7-inject-conf.json", launcher_merged_conf);

	var env = std.process.Environ.Map.init(gpa);
	defer env.deinit();
	try renderFiles(gpa, io, &env, cfg_path, rt, .replace);

	// Gone -- and correctly so: cogbox-launch.sh re-merges the CURRENT harness half
	// immediately after this call, so carrying the old one over would resurrect a
	// spec for a harness the owner may have logged out of, whose cred file the
	// addon would then fail closed on for the whole session.
	const conf = try readRuntimeFile(gpa, io, root, "l7-inject-conf.json");
	defer gpa.free(conf);
	try std.testing.expectEqualStrings("[]\n", conf);
}

/// A bound secret with NOTHING in the config or the seeds naming it: the other
/// audiences an instance's store legitimately holds, which the L7 proxy has no
/// business reading. `cookie`-kind so it is not picked up by the git seed either.
fn bindUnrelatedSecret(gpa: std.mem.Allocator, io: std.Io, store_dir: []const u8) !void {
	try secret_store.add(gpa, io, store_dir, "app-session", "unrelated-operator-secret", .{
		.audience = "app.example.com",
		.kind = "cookie",
		.tier = "durable",
		.bound_at = 1,
	});
}

fn modeOfPath(io: std.Io, path: []const u8) !std.posix.mode_t {
	const st = try std.Io.Dir.cwd().statFile(io, path, .{});
	return st.permissions.toMode() & 0o7777;
}

/// The group owner, which `Io.File.Stat` does not carry.
fn gidOfPath(path: []const u8) !std.Io.File.Gid {
	var buf: [std.fs.max_path_bytes]u8 = undefined;
	const path_z = try std.fmt.bufPrintZ(&buf, "{s}", .{path});
	return (try @import("platform").statPath(path_z)).gid;
}

test "renderFiles: a GCE-shaped render (COGBOX_PROXY_RUNAS set) makes the NAMED cred file readable by the proxy gid and leaves an unnamed one unreadable" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpInstanceLayout(gpa, io, vm_default_network);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};
	const cfg_path = try std.fs.path.join(gpa, &.{ root, "instances", "web", "config.json" });
	defer gpa.free(cfg_path);
	const rt = try std.fs.path.join(gpa, &.{ root, "rt" });
	defer gpa.free(rt);

	// Two binds into the one global store cogworx writes: the per-user Claude
	// setup-token (which the seed names) and an unrelated operator credential for
	// another audience (which nothing names).
	const global_store = try std.fs.path.join(gpa, &.{ root, "secrets" });
	defer gpa.free(global_store);
	try bindClaudeOAuth(gpa, io, global_store);
	try bindUnrelatedSecret(gpa, io, global_store);
	const store_mode_before = try modeOfPath(io, global_store);

	// The GCE host image's uid split, spelled exactly as supervisor.nix exports it
	// (`user:group`) and as the wrapper hands it to a control-channel exec. The
	// group is given numerically as the TEST PROCESS's own gid: the one group a
	// non-root test may chown its own files to, standing in for cogbox-proxy's.
	const gid: std.Io.File.Gid = @intCast(@import("platform").getgid());
	const runas = try std.fmt.allocPrint(gpa, "cogbox-proxy:{d}", .{gid});
	defer gpa.free(runas);
	var env = std.process.Environ.Map.init(gpa);
	defer env.deinit();
	try env.put("COGBOX_PROXY_RUNAS", runas);
	try renderFiles(gpa, io, &env, cfg_path, rt, .replace);

	// The render named this file to a proxy that does NOT own it. Before this
	// existed the store stayed 0600 root:root, the addon's open() raised OSError,
	// token_for returned None, and every request on the host was denied with
	// "credential unavailable" -- with the bind, the seed, the spec, the
	// terminate-allow and the funnel all correct.
	const cred = try std.fs.path.join(gpa, &.{ global_store, secret_mod.claude_oauth_secret });
	defer gpa.free(cred);
	const conf = try readRuntimeFile(gpa, io, root, "l7-inject-conf.json");
	defer gpa.free(conf);
	try std.testing.expect(std.mem.indexOf(u8, conf, cred) != null);
	try std.testing.expectEqual(@as(std.posix.mode_t, 0o640), try modeOfPath(io, cred));
	try std.testing.expectEqual(gid, try gidOfPath(cred));

	// THE CONSTRAINT: scoped to the files the specs name, never the store. The
	// other bound credential in the same directory is untouched, and so is the
	// named secret's metadata sidecar.
	const unrelated = try std.fs.path.join(gpa, &.{ global_store, "app-session" });
	defer gpa.free(unrelated);
	try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), try modeOfPath(io, unrelated));
	const meta = try std.fmt.allocPrint(gpa, "{s}.meta", .{cred});
	defer gpa.free(meta);
	try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), try modeOfPath(io, meta));

	// The store directory gains group SEARCH so a granted path can be opened by
	// name, and nothing else: no bit other than 0o010 differs from how `secret
	// add` created it, so no enumeration right is added by this code. (The store
	// is 0755 out of createDirPath today, which makes the bit a no-op in
	// authority; it is set so that later TIGHTENING the store cannot silently
	// re-break credential access.)
	try std.testing.expectEqual(store_mode_before | 0o010, try modeOfPath(io, global_store));

	// REVOCATION, on the same code path a `secret rm` + re-render takes: with the
	// credential unbound the seed stops naming it, so the grant comes off again.
	try std.testing.expect(try secret_store.remove(gpa, io, global_store, secret_mod.claude_oauth_secret));
	try secret_store.add(gpa, io, global_store, secret_mod.claude_oauth_secret, "sk-ant-oat01-FAKEFAKEFAKEFAKEFAKE", .{});
	// (Re-bound with NO audience: still present, so the host stays funnelled, but
	// renderL7Inject's audience gate drops the spec -- nothing names the file.)
	try renderFiles(gpa, io, &env, cfg_path, rt, .replace);
	const conf2 = try readRuntimeFile(gpa, io, root, "l7-inject-conf.json");
	defer gpa.free(conf2);
	try std.testing.expect(std.mem.indexOf(u8, conf2, cred) == null);
	try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), try modeOfPath(io, cred));
}

/// The mtime, which `Io.File.Stat` carries but `modeOfPath` throws away.
fn mtimeOfPath(io: std.Io, path: []const u8) !i96 {
	const st = try std.Io.Dir.cwd().statFile(io, path, .{});
	return st.mtime.nanoseconds;
}

test "renderFiles: a GCE-shaped render over a STAGED bind is a permission no-op (mode and mtime both unmoved)" {
	// store.addForProxy stages the proxy group + 0640 onto the value file inside
	// the bind's own atomic write, and its doc claims that makes the render's
	// chmod "a no-op (its `want == mode` short-circuit) rather than the moment of
	// readability". This pins the claim, and the mtime half is the load-bearing
	// one: the addon caches a cred file's VALUE keyed on the file's mtime, so a
	// render that moved it would throw a good entry away on every unrelated `l7
	// add` and look like a concurrent rotation to the addon's post-refresh
	// clobber guard, which would then skip a legitimate refresh.
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpInstanceLayout(gpa, io, vm_default_network);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};
	const cfg_path = try std.fs.path.join(gpa, &.{ root, "instances", "web", "config.json" });
	defer gpa.free(cfg_path);
	const rt = try std.fs.path.join(gpa, &.{ root, "rt" });
	defer gpa.free(rt);
	const global_store = try std.fs.path.join(gpa, &.{ root, "secrets" });
	defer gpa.free(global_store);

	// The test process's own gid, standing in for cogbox-proxy's -- the one group
	// a non-root test may chown its own files to.
	const gid: std.Io.File.Gid = @intCast(@import("platform").getgid());

	// The bind cogworx issues on the GCE host image: `secret add` resolves
	// COGBOX_PROXY_RUNAS and hands the gid straight to addForProxy, so the value
	// file is group-readable the instant it is nameable.
	const outcome = try secret_store.addForProxy(gpa, io, global_store, secret_mod.claude_oauth_secret, "sk-ant-oat01-FAKEFAKEFAKEFAKEFAKE", .{
		.audience = secret_mod.anthropic_api_host,
		.kind = secret_mod.anthropic_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	}, gid);
	try std.testing.expect(outcome.proxy_readable);

	const cred = try std.fs.path.join(gpa, &.{ global_store, secret_mod.claude_oauth_secret });
	defer gpa.free(cred);
	try std.testing.expectEqual(@as(std.posix.mode_t, 0o640), try modeOfPath(io, cred));
	const mode_before = try modeOfPath(io, cred);
	const mtime_before = try mtimeOfPath(io, cred);

	const runas = try std.fmt.allocPrint(gpa, "cogbox-proxy:{d}", .{gid});
	defer gpa.free(runas);
	var env = std.process.Environ.Map.init(gpa);
	defer env.deinit();
	try env.put("COGBOX_PROXY_RUNAS", runas);
	try renderFiles(gpa, io, &env, cfg_path, rt, .replace);

	// The render names this cred file (the seed fires: bound, audienced, kinded),
	// so credgrant walks it -- and finds nothing to change.
	const conf = try readRuntimeFile(gpa, io, root, "l7-inject-conf.json");
	defer gpa.free(conf);
	try std.testing.expect(std.mem.indexOf(u8, conf, cred) != null);
	try std.testing.expectEqual(mode_before, try modeOfPath(io, cred));
	try std.testing.expectEqual(gid, try gidOfPath(cred));
	try std.testing.expectEqual(mtime_before, try mtimeOfPath(io, cred));
}

test "renderFiles: a CONTAINER-shaped render (no COGBOX_PROXY_RUNAS) touches no store permission at all" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const root = try tmpInstanceLayout(gpa, io, vm_default_network);
	defer gpa.free(root);
	defer cwd.deleteTree(io, root) catch {};
	const cfg_path = try std.fs.path.join(gpa, &.{ root, "instances", "web", "config.json" });
	defer gpa.free(cfg_path);
	const rt = try std.fs.path.join(gpa, &.{ root, "rt" });
	defer gpa.free(rt);

	// The enforcer's private store, and the same two binds. On the container
	// backend the proxy runs inside the enforcer pod and IS the store's owner, so
	// there is no identity to grant to -- nothing sets COGBOX_PROXY_RUNAS on that
	// path (nor on k8s or local), and the store must come out of the render
	// byte-for-byte as `secret add` left it: 0600, group unchanged.
	const priv_global = try std.fs.path.join(gpa, &.{ root, "enforcer-global" });
	defer gpa.free(priv_global);
	const priv_instance = try std.fs.path.join(gpa, &.{ root, "enforcer-instance" });
	defer gpa.free(priv_instance);
	try bindClaudeOAuth(gpa, io, priv_global);
	try bindUnrelatedSecret(gpa, io, priv_global);

	const cred = try std.fs.path.join(gpa, &.{ priv_global, secret_mod.claude_oauth_secret });
	defer gpa.free(cred);
	const unrelated = try std.fs.path.join(gpa, &.{ priv_global, "app-session" });
	defer gpa.free(unrelated);
	const before_cred_gid = try gidOfPath(cred);
	const before_store_gid = try gidOfPath(priv_global);
	const before_store_mode = try modeOfPath(io, priv_global);

	var env = std.process.Environ.Map.init(gpa);
	defer env.deinit();
	try env.put("COGBOX_GLOBAL_SECRETS_DIR", priv_global);
	try env.put("COGBOX_INSTANCE_SECRETS_DIR", priv_instance);
	try renderFiles(gpa, io, &env, cfg_path, rt, .replace);

	// The render DID name the credential (so this is not vacuous -- the grant leg
	// would have fired had a proxy gid been configured)...
	const conf = try readRuntimeFile(gpa, io, root, "l7-inject-conf.json");
	defer gpa.free(conf);
	try std.testing.expect(std.mem.indexOf(u8, conf, cred) != null);
	// ...and nothing about the store changed.
	try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), try modeOfPath(io, cred));
	try std.testing.expectEqual(before_cred_gid, try gidOfPath(cred));
	try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), try modeOfPath(io, unrelated));
	try std.testing.expectEqual(before_store_mode, try modeOfPath(io, priv_global));
	try std.testing.expectEqual(before_store_gid, try gidOfPath(priv_global));
}
