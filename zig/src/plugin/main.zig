// `cogbox plugin` verb dispatcher. Manages the `.plugins` array in
// config.json: each entry is a flake (resolved + pinned by nix at add time)
// whose cogboxPlugins.<attr>.module gets folded into the guest via the generated
// composition flake. A plugin may also suggest firewall rules through the
// optional `cogboxPlugins.<attr>.networkRules` flake output; those merge into
// .network.rules tagged with the plugin's name (shown for confirmation, and
// removed/replaced exactly by del/update).
//
// Module changes need an instance restart; merged rules hot-reload through
// the shared rules_module path like every other rules-table edit.

const std = @import("std");
const builtin_mod = @import("builtin");
pub const cli = @import("cli.zig");
pub const name_mod = @import("name.zig");
pub const compose = @import("compose.zig");
pub const mutate = @import("mutate.zig");
pub const units = @import("units.zig");
pub const nix = @import("nix.zig");
pub const gitcred = @import("gitcred.zig");
pub const snapshot = @import("snapshot.zig");
pub const preboot = @import("preboot.zig");
pub const rollback = @import("rollback.zig");
pub const unitplan = @import("unitplan.zig");
pub const apply = @import("apply.zig");

const rules_module = @import("rules_module");
const config = rules_module.config;
const rule = rules_module.rule;
const l7_module = @import("l7_module");
const l7_rule = l7_module.rule;

pub fn dispatch(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *const std.process.Environ.Map,
	instance: ?[]const u8,
	config_path: []const u8,
	runtime_path: []const u8,
	user_flake_dir: []const u8,
	plugins_flake_dir: []const u8,
	rest: []const []const u8,
	host: apply.Host,
) !void {
	const cmd = cli.parse(rest) catch |err| {
		const msg = switch (err) {
			error.MissingSubcommand => "missing subcommand (list, add, del, update, resolve, reconcile, apply)",
			error.UnknownSubcommand => "unknown subcommand (expected list, add, del, update, resolve, reconcile, apply)",
			error.MissingUrl => "add requires a FLAKE_URL",
			error.MissingPlugin => "del requires a plugin name",
			error.InvalidArgs => "invalid arguments",
		};
		die(allocator, io, "{s}", .{msg}, 64);
	};

	// plugin-sources/ and plugin-cache/ are SIBLINGS of plugins-flake/ (under
	// the instance config dir): putting them INSIDE plugins-flake/ would change
	// the composition flake's source hash. plugins-flake/ holds only flake.nix
	// + flake.lock. plugin-sources/<name>/ is the materialized (writable) copy
	// of each plugin's source, referenced as a path: input; plugin-cache/ is a
	// file:// binary cache for the launch-time substituter.
	const instance_config_dir = std.fs.path.dirname(plugins_flake_dir) orelse ".";
	const sources_dir = try std.fs.path.join(allocator, &.{ instance_config_dir, "plugin-sources" });
	defer allocator.free(sources_dir);
	const cache_dir = try std.fs.path.join(allocator, &.{ instance_config_dir, "plugin-cache" });
	defer allocator.free(cache_dir);

	var ctx: Ctx = .{
		.allocator = allocator,
		.io = io,
		.parent_env = env,
		.instance = instance,
		.config_path = config_path,
		.runtime_path = runtime_path,
		.user_flake_dir = user_flake_dir,
		.plugins_flake_dir = plugins_flake_dir,
		.sources_dir = sources_dir,
		.cache_dir = cache_dir,
		.real_uid = host.real_uid,
		.host = host,
		.live = switch (cmd) {
			inline .add, .del, .update => |a| a.live,
			else => null,
		},
	};

	// The apply subcommands manage their own locks, recovery and rollback
	// finish (apply.zig), and read config.json themselves.
	if (cmd == .apply) {
		const code = apply.run(&ctx, cmd.apply, host);
		if (code != 0) std.process.exit(code);
		return;
	}

	// The apply gate's last step (spec 4.8): the CLI's gate holds the apply
	// flock, and the config lock is held. An inflight.json its verb left (it
	// died, releasing the flock) is recovered before this change commits, so a
	// rejection it still holds is rolled back first; one that cannot be
	// resolved refuses the change (exit 69), nothing read or written.
	var gate_arena = std.heap.ArenaAllocator.init(allocator);
	defer gate_arena.deinit();
	// The finishPending the recovery's rollback ran: the dispatcher's one
	// finish (its bound, 240 s, counts one).
	var rec_fin: ?rollback.FinishResult = null;
	if (isMutating(cmd) and host.gate_held) {
		switch (apply.recoverBeforeCommit(gate_arena.allocator(), &ctx, host.ssh_identity, &rec_fin)) {
			.clear => {},
			.busy => |g| die(allocator, io, "{s}", .{apply.busyMessage(gate_arena.allocator(), g)}, 69),
		}
	}

	// Finish a pending automatic rollback before config.json is read (spec
	// 4.6, "Finishing a pending intent"), under the config lock the CLI holds
	// (and, for a mutating verb, the gate's apply flock, so leftover intent tmp
	// names are swept). One that cannot finish makes the mutating verbs refuse
	// (exit 78), so no newer commit lands on top of it; list and resolve report
	// it and go on.
	finishPendingRollback(&ctx, cmd, host.gate_held, rec_fin);

	var loaded = config.load(allocator, io, config_path) catch |err| switch (err) {
		error.FileNotFound => return die(allocator, io, "no config found at {s}", .{config_path}, 66),
		error.InvalidJson => return die(allocator, io, "invalid JSON in {s}", .{config_path}, 65),
		else => return err,
	};
	defer loaded.deinit();

	switch (cmd) {
		.list => try cmdList(&ctx, &loaded),
		.add => |a| try cmdAdd(&ctx, &loaded, a),
		.del => |d| try cmdDel(&ctx, &loaded, d),
		.update => |u| try cmdUpdate(&ctx, &loaded, u),
		.resolve => |r| try cmdResolve(&ctx, &loaded, r),
		.reconcile => try cmdReconcile(&ctx, &loaded),
		.apply => unreachable,
	}
	// An inline apply that rolled the change back (finishLive) exits 1, after
	// the verb's own output (the deferred-rules line included).
	if (ctx.exit_code != 0) std.process.exit(ctx.exit_code);
}

/// The subcommands that write plugin entries, sources, tagged policy or the
/// composition: a rollback that cannot finish blocks them.
pub fn isMutating(cmd: cli.Cmd) bool {
	return switch (cmd) {
		.add, .del, .update, .reconcile => true,
		.list, .resolve, .apply => false,
	};
}

/// rollback.finishPending for the plugin dispatcher (the caller holds the
/// config lock; `holds_apply_flock` when the apply gate also holds the apply
/// flock, the only case in which leftover intent tmp names are swept), unless
/// the gate's recovery already ran one (`prior`, whose warnings it printed).
/// Warnings go to stderr. An intent that stays makes a mutating subcommand
/// exit 78 with the stamped message; the others print it and carry on.
fn finishPendingRollback(ctx: *const Ctx, cmd: cli.Cmd, holds_apply_flock: bool, prior: ?rollback.FinishResult) void {
	var arena_state = std.heap.ArenaAllocator.init(ctx.allocator);
	defer arena_state.deinit();
	const fin = prior orelse rollback.finishPending(arena_state.allocator(), ctx, .{ .holds_apply_flock = holds_apply_flock });
	var buf: [4096]u8 = undefined;
	var w: std.Io.Writer = .fixed(&buf);
	if (prior == null) rollback.writeWarnings(&w, fin.warnings) catch {};
	if (fin.pending > 0) rollback.writePendingMessage(&w, fin.pending_error orelse error.RollbackPending, ctx.instance) catch {};
	writeStderr(ctx.io, w.buffered()) catch {};
	if (fin.pending > 0 and isMutating(cmd)) std.process.exit(78);
}

// --- resolve (truthful pre-install preview; no mutation) -----------------

// cmdResolve previews a flake URL the way cmdAdd's read-only prefix does --
// flake metadata + the cogboxPlugins.<attr> contract check + the host-side
// networkRules/l7Rules/inject readout -- and emits ONE JSON line on stdout for
// the control plane (cogworx's Backend.ResolvePin). It installs nothing: no
// config mutation, no source materialization, no composition regen. Human
// chatter routes to stderr (the defer_rules flag) so stdout carries only JSON.
fn cmdResolve(ctx: *Ctx, loaded: *config.Loaded, r: cli.ResolveArgs) !void {
	_ = loaded;
	const allocator = ctx.allocator;
	const io = ctx.io;
	ctx.defer_rules = true;

	var fetch_env: ?gitcred.FetchEnv = null;
	defer if (fetch_env) |*fe| fe.deinit();
	if (r.git_credential_stdin) {
		const raw = gitcred.readStdin(allocator, io) catch {
			die(allocator, io, "could not read git credential from stdin", .{}, 65);
		};
		defer allocator.free(raw);
		const cred = gitcred.parseLine(raw) catch {
			die(allocator, io, "malformed git credential on stdin (want host<TAB>user<TAB>token)", .{}, 65);
		};
		fetch_env = gitcred.FetchEnv.setup(allocator, io, ctx.parent_env, cred) catch {
			die(allocator, io, "could not set up authenticated fetch", .{}, 70);
		};
		ctx.fetch_env = fetch_env.?.map();
	}

	const split = name_mod.splitFragment(r.url) catch |err| switch (err) {
		error.EmptyFragment => die(allocator, io, "empty #fragment in '{s}'", .{r.url}, 65),
		error.InvalidAttr => die(allocator, io, "invalid module attr in '{s}' (allowed: [a-zA-Z0-9_-])", .{r.url}, 65),
	};
	const ref = split.ref;
	const attr: ?[]const u8 = if (split.attr) |sa|
		(if (std.mem.eql(u8, sa, "default")) null else sa)
	else
		null;

	// Best-effort name (preview only): from the attr, else the URL, else "plugin".
	const name: []const u8 = blk: {
		if (attr) |at| break :blk name_mod.deriveNameFromAttr(allocator, at) catch try allocator.dupe(u8, "plugin");
		break :blk name_mod.deriveName(allocator, ref) catch try allocator.dupe(u8, "plugin");
	};
	defer allocator.free(name);

	try announce(ctx, "Resolving '{s}'...", .{ref});
	var meta = resolveFlake(ctx, ref);
	defer meta.deinit(allocator);
	const dirty = meta.rev == null and nix.isGitOrHgUrl(meta.locked_url);

	const module_attr = attr orelse "default";
	const present = switch (try nix.evalHasCogboxPlugin(allocator, io, ctx.fetch_env, meta.locked_url, module_attr)) {
		.present => true,
		.missing => false,
		.failed => |stderr| die(allocator, io, "could not evaluate flake '{s}':\n{s}", .{ meta.locked_url, nix.stderrTail(stderr) }, 65),
	};

	// Host-side policy readout (only meaningful when the contract is present).
	var l4_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (l4_parsed) |*p| p.deinit();
	var l7_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (l7_parsed) |*p| p.deinit();
	var inject_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (inject_parsed) |*p| p.deinit();
	var l4: []const std.json.Value = &.{};
	var l7: []const std.json.Value = &.{};
	var inject: []const std.json.Value = &.{};
	if (present) {
		l4_parsed = evalRules(ctx, meta.locked_url, attr);
		if (l4_parsed) |p| l4 = p.value.array.items;
		l7_parsed = evalL7Rules(ctx, meta.locked_url, attr);
		if (l7_parsed) |p| l7 = p.value.array.items;
		inject_parsed = evalInjectSpecs(ctx, meta.locked_url, attr);
		if (inject_parsed) |p| inject = p.value.array.items;
	}

	const line = try renderResolveJson(allocator, name, attr, ref, &meta, dirty, present, l4, l7, inject);
	defer allocator.free(line);
	try writeStdout(io, line);
}

/// Build the one-line resolve JSON the control plane consumes:
///   {"name","attr","url","lockedUrl","rev","narHash","dirty","present",
///    "networkRules":[...],"l7Rules":[...],"inject":[...]}
/// The rule/inject objects are the SAME validated shapes evalRules/evalL7Rules/
/// evalInjectSpecs produced. Caller frees.
fn renderResolveJson(
	allocator: std.mem.Allocator,
	name: []const u8,
	attr: ?[]const u8,
	url: []const u8,
	meta: *const nix.Meta,
	dirty: bool,
	present: bool,
	l4: []const std.json.Value,
	l7: []const std.json.Value,
	inject: []const std.json.Value,
) ![]u8 {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	try out.appendSlice(allocator, "{\"name\":");
	try writeCompactString(allocator, &out, name);
	try out.appendSlice(allocator, ",\"attr\":");
	try writeCompactString(allocator, &out, attr orelse "default");
	try out.appendSlice(allocator, ",\"url\":");
	try writeCompactString(allocator, &out, url);
	try out.appendSlice(allocator, ",\"lockedUrl\":");
	try writeCompactString(allocator, &out, meta.locked_url);
	try out.appendSlice(allocator, ",\"rev\":");
	if (meta.rev) |rev| try writeCompactString(allocator, &out, rev) else try out.appendSlice(allocator, "null");
	try out.appendSlice(allocator, ",\"narHash\":");
	try writeCompactString(allocator, &out, meta.nar_hash);
	try out.appendSlice(allocator, ",\"dirty\":");
	try out.appendSlice(allocator, if (dirty) "true" else "false");
	try out.appendSlice(allocator, ",\"present\":");
	try out.appendSlice(allocator, if (present) "true" else "false");
	try out.appendSlice(allocator, ",\"networkRules\":");
	try writeCompactArray(allocator, &out, l4);
	try out.appendSlice(allocator, ",\"l7Rules\":");
	try writeCompactArray(allocator, &out, l7);
	try out.appendSlice(allocator, ",\"inject\":");
	try writeCompactArray(allocator, &out, inject);
	try out.appendSlice(allocator, "}\n");
	return out.toOwnedSlice(allocator);
}

pub const Ctx = struct {
	allocator: std.mem.Allocator,
	io: std.Io,
	// The parent environment, used to clone a per-fetch env when a credential
	// is supplied. The nix fetch otherwise inherits this unchanged.
	parent_env: *const std.process.Environ.Map,
	instance: ?[]const u8,
	config_path: []const u8,
	runtime_path: []const u8,
	user_flake_dir: []const u8,
	plugins_flake_dir: []const u8,
	// Siblings of plugins_flake_dir (see dispatch): plugin-sources/ holds the
	// materialized writable source of each plugin (referenced as a path: input
	// so launch resolves it offline); plugin-cache/ is the file:// binary cache
	// the launcher uses as an extra substituter for transitive inputs.
	sources_dir: []const u8,
	cache_dir: []const u8,
	// Per-fetch credential env. null => the nix
	// fetch runs with the inherited parent env (public/unauthenticated). When a
	// `--git-credential-stdin` add/update supplies a token, cmdAdd/cmdUpdate set
	// this to the temp-netrc env for the duration of the fetch, then tear it down.
	fetch_env: ?*const std.process.Environ.Map = null,
	// --defer-rules: when true, every human announce() is redirected to STDERR so
	// the only thing on STDOUT is the one `{"deferred":...}` JSON line cmdAdd /
	// cmdUpdate emits. The control plane parses that line; routing chatter to
	// stderr keeps it clean. Set by cmdAdd/cmdUpdate/cmdResolve for the run.
	defer_rules: bool = false,
	// The invoking user's uid under sudo (null otherwise): the live apply's
	// snapshot and rollback state is handed to it, as config_lock hands over
	// the lock files, so later non-sudo verbs can still write it.
	real_uid: ?u32 = null,
	// The CLI's lock descriptors and ssh identity (apply.Host): what an inline
	// apply after add, del or update runs under (finishLive).
	host: apply.Host = .{},
	// add/del/update's --apply (true) or --no-apply (false); null: the default.
	live: cli.LiveChoice = null,
	// Set by finishLive when an inline apply rolled the change back: the
	// dispatcher exits with it once the verb has returned.
	exit_code: u8 = 0,
	// The inline apply rejected the change (its rollback done or pending):
	// cmdAdd then withholds its deferred-rules line, which would name rules
	// of a plugin that is no longer there.
	live_rejected: bool = false,
};

/// A Ctx for the instance `name` (null: the default) whose config dir is `icd`
/// and runtime dir `runtime`, for the verbs outside `cogbox plugin` that run a
/// live-apply step (`cogbox stop`). Its strings are `arena`'s.
pub fn instanceCtx(arena: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map, name: ?[]const u8, icd: []const u8, runtime: []const u8) !Ctx {
	const join = std.fs.path.join;
	return .{
		.allocator = arena,
		.io = io,
		.parent_env = env,
		.instance = name,
		.config_path = try join(arena, &.{ icd, "config.json" }),
		.runtime_path = runtime,
		.user_flake_dir = try join(arena, &.{ icd, "flake" }),
		.plugins_flake_dir = try join(arena, &.{ icd, "plugins-flake" }),
		.sources_dir = try join(arena, &.{ icd, "plugin-sources" }),
		.cache_dir = try join(arena, &.{ icd, "plugin-cache" }),
	};
}

// --- list ---------------------------------------------------------------

fn cmdList(ctx: *const Ctx, loaded: *config.Loaded) !void {
	const arr = mutate.existingPluginsArray(loaded.root());
	if (arr == null or arr.?.items.len == 0) {
		try announce(ctx, "(no plugins)", .{});
		return;
	}

	const rules_arr = rulesOrNull(loaded);
	const l7_arr = l7RulesOrNull(loaded);
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(ctx.allocator);

	for (arr.?.items) |item| {
		if (item != .object) continue;
		const n = mutate.entryField(item.object, "name") orelse "?";
		const u = mutate.entryField(item.object, "url") orelse "?";
		const rules_n = (if (rules_arr) |ra| mutate.countTaggedRules(ra, n) else 0) +
			(if (l7_arr) |la| mutate.countTaggedRules(la, n) else 0);
		const frag: []const u8 = if (mutate.entryField(item.object, "attr")) |a| a else "";
		const line = try std.fmt.allocPrint(
			ctx.allocator,
			"{s}  {s}{s}{s}  rev={s}  rules={d}\n",
			.{ n, u, if (frag.len > 0) "#" else "", frag, shortRev(item.object), rules_n },
		);
		defer ctx.allocator.free(line);
		try out.appendSlice(ctx.allocator, line);
	}
	try writeStdout(ctx.io, out.items);
}

/// Display pin: short rev when there is one, else a narHash prefix
/// (dirty path: flakes have no rev).
fn shortRev(obj: std.json.ObjectMap) []const u8 {
	if (mutate.entryField(obj, "rev")) |r| {
		return r[0..@min(r.len, 7)];
	}
	if (mutate.entryField(obj, "narHash")) |h| {
		const stripped = if (std.mem.startsWith(u8, h, "sha256-")) h[7..] else h;
		return stripped[0..@min(stripped.len, 8)];
	}
	return "?";
}

// --- add ----------------------------------------------------------------

fn cmdAdd(ctx: *Ctx, loaded: *config.Loaded, a: cli.AddArgs) !void {
	const allocator = ctx.allocator;
	const io = ctx.io;

	// Under --defer-rules every human announce()/warn() routes to stderr so the
	// only thing on stdout is the one deferred-rules JSON line emitted at the end.
	ctx.defer_rules = a.defer_rules;

	// --git-credential-stdin: read the one credential line, materialize a temp
	// 0600 netrc + clear-helper gitconfig, and scope a per-fetch env to it for
	// every nix call below. Torn down (temp dir removed) when this verb returns.
	// The token is never in argv/env-of-record/log; it lives only in the temp
	// netrc for the lifetime of the fetch.
	var fetch_env: ?gitcred.FetchEnv = null;
	defer if (fetch_env) |*fe| fe.deinit();
	if (a.git_credential_stdin) {
		const raw = gitcred.readStdin(allocator, io) catch {
			die(allocator, io, "could not read git credential from stdin", .{}, 65);
		};
		defer allocator.free(raw);
		const cred = gitcred.parseLine(raw) catch {
			die(allocator, io, "malformed git credential on stdin (want host<TAB>user<TAB>token)", .{}, 65);
		};
		fetch_env = gitcred.FetchEnv.setup(allocator, io, ctx.parent_env, cred) catch {
			die(allocator, io, "could not set up authenticated fetch", .{}, 70);
		};
		ctx.fetch_env = fetch_env.?.map();
	}

	// `URL#attr` selects cogboxPlugins.<attr>; bare URL means `default`.
	const split = name_mod.splitFragment(a.url) catch |err| switch (err) {
		error.EmptyFragment => die(allocator, io, "empty #fragment in '{s}'", .{a.url}, 65),
		error.InvalidAttr => die(allocator, io, "invalid module attr in '{s}' (allowed: [a-zA-Z0-9_-])", .{a.url}, 65),
	};
	const ref = split.ref;
	// An explicit `#default` is the same as no fragment.
	const attr: ?[]const u8 = if (split.attr) |sa|
		(if (std.mem.eql(u8, sa, "default")) null else sa)
	else
		null;

	const plugin_name: []const u8 = blk: {
		if (a.as) |as| {
			if (!name_mod.isValidPluginName(as)) {
				die(allocator, io, "invalid plugin name '{s}' (must start with a letter, [a-zA-Z0-9-], max 64; 'user' and 'git-grants' are reserved)", .{as}, 65);
			}
			break :blk try allocator.dupe(u8, as);
		}
		if (attr) |at| {
			break :blk name_mod.deriveNameFromAttr(allocator, at) catch {
				die(allocator, io, "cannot derive a plugin name from attr '{s}'; pass --as NAME", .{at}, 65);
			};
		}
		break :blk name_mod.deriveName(allocator, ref) catch {
			die(allocator, io, "cannot derive a plugin name from '{s}'; pass --as NAME", .{ref}, 65);
		};
	};
	defer allocator.free(plugin_name);

	const plugins_arr = mutate.pluginsArray(loaded.root(), loaded.treeAllocator()) catch {
		die(allocator, io, "invalid JSON in {s} (.plugins is not an array)", .{ctx.config_path}, 65);
	};
	if (mutate.findPlugin(plugins_arr, plugin_name) != null) {
		die(allocator, io, "plugin '{s}' already exists (choose another name with --as)", .{plugin_name}, 65);
	}

	// Flake-level versioning: if another module of this same flake URL is
	// already installed, reuse its pin instead of resolving the tip again,
	// so all plugins from one flake stay at one rev (`update` moves them
	// together). A different rev can still be forced by pinning it in the
	// URL itself, which makes the URL string distinct.
	var meta: nix.Meta = blk: {
		if (mutate.findByUrl(plugins_arr, ref)) |sibling| {
			const locked = mutate.entryField(sibling.object, "lockedUrl");
			const hash = mutate.entryField(sibling.object, "narHash");
			if (locked != null and hash != null) {
				try announce(ctx, "Reusing pin of installed flake '{s}' ({s}).", .{ ref, shortRev(sibling.object) });
				break :blk .{
					.locked_url = try allocator.dupe(u8, locked.?),
					.rev = if (mutate.entryField(sibling.object, "rev")) |r| try allocator.dupe(u8, r) else null,
					.nar_hash = try allocator.dupe(u8, hash.?),
					// No metadata call on this path: resolve the source store
					// path lazily via flakeSourcePath when we materialize.
					.source_path = try allocator.dupe(u8, ""),
				};
			}
		}
		try announce(ctx, "Resolving '{s}'...", .{ref});
		break :blk resolveFlake(ctx, ref);
	};
	defer meta.deinit(allocator);

	// A git/hg lock without a rev is a dirty worktree: the locked URL can't
	// carry a narHash (the fetcher would hand it to the remote) and has no
	// rev, so nothing pins it -- the guest module floats with the worktree
	// across restarts.
	if (meta.rev == null and nix.isGitOrHgUrl(meta.locked_url)) {
		try warn(ctx, "source tree is dirty: the lock has no rev, so the plugin floats with the worktree (commit, then `cogbox plugin update`, to pin)", .{});
	}

	const module_attr = attr orelse "default";
	switch (try nix.evalHasCogboxPlugin(allocator, io, ctx.fetch_env, meta.locked_url, module_attr)) {
		.present => {},
		.missing => die(allocator, io, "plugin flake does not expose cogboxPlugins.{s} (see docs/plugins.md)", .{module_attr}, 65),
		.failed => |stderr| die(allocator, io, "could not evaluate flake '{s}':\n{s}", .{ meta.locked_url, nix.stderrTail(stderr) }, 65),
	}

	// Materialize the plugin source onto the PVC so the composition can point
	// a path: input at it (offline at launch -- the git+ URL needs a token we
	// don't have at start). Done here, under the still-authenticated fetch env,
	// so the source store path is already realized. Best-effort: on failure the
	// composition falls back to the locked URL (has_source=false).
	materializeSource(ctx, plugin_name, &meta, ref) catch |err| {
		warn(ctx, "could not materialize plugin source (launch may need network): {s}", .{@errorName(err)}) catch {};
	};

	// Now that this plugin's contents/ is on disk next to every installed
	// plugin's, say what its unit names will collide with -- and refuse the add
	// outright for the shapes the build cannot resolve. Deliberately BEFORE the
	// rule/inject confirmation below: there is no point asking an operator to
	// approve firewall rules for a plugin that would make the guest system
	// unbuildable. The plugin being added is not in `plugins_arr` yet, so its
	// `?dir=` subdir comes straight off the locked URL (regenComposition reads
	// the same param off the stored entry for every installed plugin).
	const add_root = try std.fs.path.join(allocator, &.{ ctx.sources_dir, plugin_name, nix.dirParam(meta.locked_url) orelse "." });
	defer allocator.free(add_root);
	// Exiting here is the whole point: nothing about this add has been written
	// yet (config.json, the composition and the lock are all still the state the
	// instance booted with), and lintUnitNames has already torn the freshly
	// materialized source down, so the refusal costs the instance nothing.
	if (try lintUnitNames(ctx, plugins_arr, plugin_name, add_root, true)) std.process.exit(65);

	archiveFlake(ctx, meta.locked_url);

	// Optional plugin contributions: L4 CIDR + L7 vhost rules, plus credential
	// injection requests -- one confirmation. Injection gets its own louder
	// section: granting a host-side credential is a different kind of trust
	// than a firewall rule.
	var l4_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (l4_parsed) |*p| p.deinit();
	const incoming_l4: []const std.json.Value = blk: {
		l4_parsed = evalRules(ctx, meta.locked_url, attr);
		const p = l4_parsed orelse break :blk &.{};
		break :blk p.value.array.items;
	};
	var l7_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (l7_parsed) |*p| p.deinit();
	const incoming_l7: []const std.json.Value = blk: {
		l7_parsed = evalL7Rules(ctx, meta.locked_url, attr);
		const p = l7_parsed orelse break :blk &.{};
		break :blk p.value.array.items;
	};
	var inject_parsed: ?std.json.Parsed(std.json.Value) = null;
	defer if (inject_parsed) |*p| p.deinit();
	const incoming_inject: []const std.json.Value = blk: {
		inject_parsed = evalInjectSpecs(ctx, meta.locked_url, attr);
		const p = inject_parsed orelse break :blk &.{};
		break :blk p.value.array.items;
	};

	// --defer-rules: withhold the plugin's L4/L7 networkRules from config.json and
	// report them on stdout instead (the control plane routes them through admin
	// approval). The module install and the inject-spec merge are UNCHANGED:
	// injection is a separate trust class, gated host-side by `secret bind`, so it
	// keeps its own confirm/merge path. That gate covers the credential only:
	// renderL7 still unions every inject-spec host into `allow <host> terminate`,
	// bound or not, so a plugin's inject host is reachable without review (a known
	// residual, docs/plugins.md). The withheld L4/L7 rules count zero toward the
	// prompt below; only inject specs prompt under defer.
	const merge_l4 = if (a.defer_rules) &[_]std.json.Value{} else incoming_l4;
	const merge_l7 = if (a.defer_rules) &[_]std.json.Value{} else incoming_l7;

	var merged = false;
	var merged_inject = false;
	const total = merge_l4.len + merge_l7.len + incoming_inject.len;
	if (total > 0) {
		if (rulesOrNull(loaded)) |rules_arr| {
			if (merge_l4.len + merge_l7.len > 0) {
				try announce(ctx, "Suggested network rules from '{s}':", .{plugin_name});
				for (merge_l4) |r| try printRuleLine(ctx, "+", r);
				for (merge_l7) |r| try printL7RuleLine(ctx, "+", r);
			}
			if (incoming_inject.len > 0) {
				try announce(ctx, "Credential injection requests from '{s}' (host-side; the secret stays OUT of the guest):", .{plugin_name});
				for (incoming_inject) |s| try printInjectLine(ctx, "+", s);
			}
			const prompt = try std.fmt.allocPrint(allocator, "Apply these {d} change(s) at the top of the lists?", .{total});
			defer allocator.free(prompt);
			// Under defer the confirm prompt is suppressed (stdout stays the JSON
			// line; the deferred rules are not applied here regardless).
			if (!a.yes and !a.defer_rules and !try confirm(ctx, prompt)) {
				try announce(ctx, "Aborted.", .{});
				return;
			}
			if (merge_l4.len > 0) {
				try mutate.prependTaggedRules(loaded.treeAllocator(), rules_arr, plugin_name, merge_l4);
			}
			if (merge_l7.len > 0) {
				const l7_arr = try ensureL7Rules(loaded);
				try mutate.prependTaggedRules(loaded.treeAllocator(), l7_arr, plugin_name, merge_l7);
			}
			if (incoming_inject.len > 0) {
				const inj_arr = try ensureInjectSpecs(loaded);
				try mutate.prependTaggedRules(loaded.treeAllocator(), inj_arr, plugin_name, incoming_inject);
				merged_inject = true;
			}
			merged = true;
		} else {
			try warn(ctx, "instance is not in rules mode; skipping {d} suggested change(s)", .{total});
		}
	}

	try mutate.appendPlugin(loaded.treeAllocator(), plugins_arr, .{
		.name = plugin_name,
		.url = ref,
		.attr = attr,
		.locked_url = meta.locked_url,
		.rev = meta.rev,
		.nar_hash = meta.nar_hash,
	});

	try config.save(allocator, io, ctx.config_path, loaded.root().*);
	try regenComposition(ctx, plugins_arr);
	finalizeComposition(ctx, plugins_arr, null);
	if (merged) try rules_module.maybeReload(allocator, io, ctx.runtime_path, loaded);

	try announce(ctx, "Plugin '{s}' added at {s}.", .{ plugin_name, pinLabel(&meta) });
	if (merged_inject) try printBindChecklist(ctx, incoming_inject);
	try finishLive(ctx, plugin_name, "to load its NixOS module");

	// Under --defer-rules emit the withheld L4/L7 rules as one JSON line on
	// stdout (the ONLY stdout output; all human chatter went to stderr). The
	// control plane parses this and files one admin-approval request per rule.
	// Not after an inline apply (--apply) rolled the add back: the plugin is
	// gone, and approving its rules would grant them to nothing.
	if (a.defer_rules and !ctx.live_rejected) {
		const line = try renderDeferredJson(allocator, plugin_name, incoming_l4, incoming_l7);
		defer allocator.free(line);
		try writeStdout(io, line);
	}
}

/// cmdUpdate's merge of plugin `n`'s contributed rules into a rules-mode config
/// (`rules_arr`, `old_l7` and `old_inject` are its arrays as the caller found
/// them). The plugin's tagged inject specs are always replaced by the incoming
/// ones. Live, its tagged L4/L7 rules are too. Under --defer-rules
/// (`defer_rules`) those stay exactly as they are -- a version that stops
/// declaring a rule does not narrow it here -- and the incoming rules the plugin
/// does not already carry (mutate.novelRules: ignoring tag and comment) come
/// back as the rendered deferred line, or null when there are none. The caller
/// owns the line and prints it only once config.save has committed. Touches
/// nothing but the loaded tree, so the defer/live split is unit-tested.
///
/// Inject specs are not reviewed: `secret bind` gates the credential, but
/// renderL7 unions every inject-spec host into `allow <host> terminate`, bound
/// or not, so a new version's inject host is reachable after a deferred update
/// as after `add --defer-rules` (a known residual, docs/plugins.md).
fn updatePluginRules(
	allocator: std.mem.Allocator,
	loaded: *config.Loaded,
	rules_arr: *std.json.Array,
	old_l7: ?*std.json.Array,
	old_inject: ?*std.json.Array,
	n: []const u8,
	incoming_l4: []const std.json.Value,
	incoming_l7: []const std.json.Value,
	incoming_inject: []const std.json.Value,
	defer_rules: bool,
) !?[]u8 {
	var line: ?[]u8 = null;
	errdefer if (line) |l| allocator.free(l);
	if (defer_rules) {
		const novel_l4 = try mutate.novelRules(allocator, rules_arr, n, incoming_l4, .l4);
		defer allocator.free(novel_l4);
		const novel_l7 = try mutate.novelRules(allocator, old_l7, n, incoming_l7, .l7);
		defer allocator.free(novel_l7);
		if (novel_l4.len + novel_l7.len > 0) {
			line = try renderDeferredJson(allocator, n, novel_l4, novel_l7);
		}
	} else {
		_ = mutate.removeTaggedRules(rules_arr, n);
		try mutate.prependTaggedRules(loaded.treeAllocator(), rules_arr, n, incoming_l4);
		if (old_l7) |la| _ = mutate.removeTaggedRules(la, n);
		if (incoming_l7.len > 0) {
			const l7_arr = try ensureL7Rules(loaded);
			try mutate.prependTaggedRules(loaded.treeAllocator(), l7_arr, n, incoming_l7);
		}
	}
	if (old_inject) |ia| _ = mutate.removeTaggedRules(ia, n);
	if (incoming_inject.len > 0) {
		const inj_arr = try ensureInjectSpecs(loaded);
		try mutate.prependTaggedRules(loaded.treeAllocator(), inj_arr, n, incoming_inject);
	}
	return line;
}

/// Unit-name lint for an incoming plugin version, shared by `add` and
/// `update`. Compares the incoming plugin's `contents/` against the
/// already-materialized `contents/` of every installed plugin (units.zig),
/// then:
///
///   - REFUSES anything the composed guest would decline to evaluate. That is
///     the whole reason this exists: until the build resolved collisions
///     itself, a same-named skill in two plugins meant the guest system did not
///     evaluate at all -- `cogbox init` non-zero, the GCE supervisor
///     restart-looping, and the one line of Nix error that explained it visible
///     only from inside the VM. The messages mirror flake.nix's throws word for
///     word so the CLI and the build can never disagree;
///   - otherwise ANNOUNCES the names cogbox will qualify. Both sides stay
///     installed and usable, so this is information the operator wants at
///     install time, not a refusal.
///
/// A refusal RETURNS TRUE with every fatal already printed, rather than exiting
/// here: what it costs is the caller's to decide, because the two verbs sit at
/// different points in their own state machines. `add` has written nothing yet,
/// so it exits 65 on the spot. `update` is part-way through a loop over several
/// plugins, and exiting from the middle of it would strand the ones already
/// re-materialized -- their new tree on disk, `config.json` and the composition
/// lock still naming the old rev, and nix honouring the stale lock rather than
/// erroring -- so it marks the plugin failed and lets the loop finish.
///
/// Nothing is persisted. Qualification is derived in Nix from the installed
/// set, so `del`/`update` recompute it for free and there is no host-side
/// state to drift out of step with config.json.
///
/// `plugins_arr` is the array as it stands BEFORE this mutation. The incoming
/// plugin is appended LAST, matching where mutate.appendPlugin puts it and
/// therefore the order the composition flake imports the modules in; an entry
/// already carrying `new_name` (the update path) is dropped from the pre-state
/// so the old and new copies are never counted as two roots of one plugin.
///
/// `new_root` is the directory that CONTAINS the incoming plugin's `contents/`
/// -- for a `?dir=` monorepo flake that is `<tree>/<dir>`, not `<tree>`, and
/// getting it wrong makes the whole lint a silent no-op. Every installed
/// plugin's is recovered the same way, from its stored lockedUrl.
///
/// `remove_on_refusal` tears the materialized source down again when the lint
/// refuses. True for `add` (the plugin was never installed, so an orphan
/// plugin-sources/<name>/ only confuses the next reader); false for `update`,
/// which lints the incoming version straight out of the store BEFORE it
/// replaces anything, and must leave the installed old version intact.
fn lintUnitNames(ctx: *const Ctx, plugins_arr: *std.json.Array, new_name: []const u8, new_root: []const u8, remove_on_refusal: bool) !bool {
	var arena_state = std.heap.ArenaAllocator.init(ctx.allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();

	var providers: std.ArrayList(units.Provider) = .empty;
	for (plugins_arr.items) |item| {
		if (item != .object) continue;
		const nm = mutate.entryField(item.object, "name") orelse continue;
		// The incoming plugin's OWN entry, on the update path. It is appended
		// below from the new version; counting it here as well would read as one
		// plugin providing the same unit from two of its own roots, which is a
		// refusal rather than a collision.
		if (std.mem.eql(u8, nm, new_name)) continue;
		const dir = nix.dirParam(mutate.entryField(item.object, "lockedUrl") orelse "");
		const root = try std.fs.path.join(arena, &.{ ctx.sources_dir, nm, dir orelse "." });
		try providers.append(arena, .{ .plugin = nm, .units = try pluginUnits(ctx, arena, root) });
	}
	// The state BEFORE this mutation, so the diff below can tell what this
	// mutation is responsible for from what the instance was already carrying.
	const before = try units.analyze(arena, providers.items);
	try providers.append(arena, .{ .plugin = new_name, .units = try pluginUnits(ctx, arena, new_root) });
	const report = try units.delta(arena, before, try units.analyze(arena, providers.items), new_name);

	if (report.fatals.len > 0) {
		// Leave nothing behind on an ADD: the source was materialized moments
		// ago, and an orphan plugin-sources/<name>/ for a plugin that was never
		// installed only confuses the next reader.
		if (remove_on_refusal) removeSource(ctx, new_name);
		// Every unresolvable name, not just the first -- flake.nix throws them
		// as one joined message, so an operator gets the same set either way.
		// Printed with `die`'s own prefix, since the caller does the exiting.
		for (report.fatals) |m| {
			const line = try std.fmt.allocPrint(ctx.allocator, "cogbox plugin: error: {s}\n", .{m});
			defer ctx.allocator.free(line);
			try writeStderr(ctx.io, line);
		}
		return true;
	}

	if (report.collisions.len == 0) return false;
	try announce(ctx, "Name collisions with installed plugins (cogbox qualifies both sides):", .{});
	for (report.collisions) |c| {
		// "also provided by" lists the OTHER side; the arrow line lists every
		// final name, in install order, because neither side keeps the bare one.
		// The final names come from the report, never re-derived here -- one
		// place owns the qualification rule.
		var others: std.ArrayList(u8) = .empty;
		for (c.plugins) |p| {
			if (std.mem.eql(u8, p, new_name)) continue;
			if (others.items.len > 0) try others.appendSlice(arena, ", ");
			try others.appendSlice(arena, try std.fmt.allocPrint(arena, "'{s}'", .{p}));
		}
		var finals: std.ArrayList(u8) = .empty;
		for (c.finals) |f| {
			if (finals.items.len > 0) try finals.appendSlice(arena, ", ");
			try finals.appendSlice(arena, f);
		}
		try announce(ctx, "  ~ {s} '{s}' also provided by {s}", .{ c.kind.label(), c.name, others.items });
		try announce(ctx, "      -> {s}", .{finals.items});
	}
	return false;
}

/// The units one plugin contributes, read from `<flake_root>/contents`.
/// `contents/` is the conventional root docs/plugins.md documents; the CLI
/// never evaluates the plugin module, so a plugin that points cogbox.contents
/// somewhere else is invisible here and the build stays the authority
/// (units.zig says why that trade is the right one).
///
/// `flake_root` is the directory holding the plugin's flake.nix, which for a
/// `?dir=` monorepo plugin is a SUBDIRECTORY of the materialized tree (that
/// tree is always the repo root). Passing the repo root there instead makes
/// enumerate() open nothing and the lint pass everything -- including the
/// refusals, which then surface as a guest that will not evaluate.
fn pluginUnits(ctx: *const Ctx, arena: std.mem.Allocator, flake_root: []const u8) ![]units.Unit {
	const root = try std.fs.path.join(arena, &.{ flake_root, "contents" });
	return units.enumerate(arena, ctx.io, root);
}

/// Build the one-line deferred-rules JSON the control plane consumes:
///   {"deferred":{"plugin":"<name>","l4":[<L4 rule objects>],"l7":[<L7 rule objects>]}}
/// The rule objects are the SAME validated shapes evalRules/evalL7Rules produced
/// (so the control plane never re-encodes CIDR/host semantics), serialized
/// compactly on a single line. Caller frees. Pure (testable) function.
fn renderDeferredJson(
	allocator: std.mem.Allocator,
	plugin_name: []const u8,
	l4: []const std.json.Value,
	l7: []const std.json.Value,
) ![]u8 {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	try out.appendSlice(allocator, "{\"deferred\":{\"plugin\":");
	try writeCompactString(allocator, &out, plugin_name);
	try out.appendSlice(allocator, ",\"l4\":");
	try writeCompactArray(allocator, &out, l4);
	try out.appendSlice(allocator, ",\"l7\":");
	try writeCompactArray(allocator, &out, l7);
	try out.appendSlice(allocator, "}}\n");
	return out.toOwnedSlice(allocator);
}

fn writeCompactArray(allocator: std.mem.Allocator, out: *std.ArrayList(u8), items: []const std.json.Value) std.mem.Allocator.Error!void {
	try out.append(allocator, '[');
	for (items, 0..) |item, i| {
		if (i > 0) try out.append(allocator, ',');
		try writeCompactValue(allocator, out, item);
	}
	try out.append(allocator, ']');
}

/// Compact (no-whitespace, single-line) JSON serializer for a std.json.Value.
/// Mirrors config.writeJqTab's escaping but emits no indentation/newlines, so
/// the deferred line parses as exactly one line.
fn writeCompactValue(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: std.json.Value) std.mem.Allocator.Error!void {
	switch (value) {
		.null => try out.appendSlice(allocator, "null"),
		.bool => |b| try out.appendSlice(allocator, if (b) "true" else "false"),
		.integer => |i| {
			var buf: [32]u8 = undefined;
			const s = std.fmt.bufPrint(&buf, "{d}", .{i}) catch unreachable;
			try out.appendSlice(allocator, s);
		},
		.float => |f| {
			var buf: [64]u8 = undefined;
			const s = std.fmt.bufPrint(&buf, "{d}", .{f}) catch unreachable;
			try out.appendSlice(allocator, s);
		},
		.number_string => |s| try out.appendSlice(allocator, s),
		.string => |s| try writeCompactString(allocator, out, s),
		.array => |arr| try writeCompactArray(allocator, out, arr.items),
		.object => |obj| {
			try out.append(allocator, '{');
			var it = obj.iterator();
			var i: usize = 0;
			while (it.next()) |entry| {
				if (i > 0) try out.append(allocator, ',');
				try writeCompactString(allocator, out, entry.key_ptr.*);
				try out.append(allocator, ':');
				try writeCompactValue(allocator, out, entry.value_ptr.*);
				i += 1;
			}
			try out.append(allocator, '}');
		},
	}
}

fn writeCompactString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
	try out.append(allocator, '"');
	for (s) |c| {
		switch (c) {
			'"' => try out.appendSlice(allocator, "\\\""),
			'\\' => try out.appendSlice(allocator, "\\\\"),
			'\n' => try out.appendSlice(allocator, "\\n"),
			'\r' => try out.appendSlice(allocator, "\\r"),
			'\t' => try out.appendSlice(allocator, "\\t"),
			0x08 => try out.appendSlice(allocator, "\\b"),
			0x0c => try out.appendSlice(allocator, "\\f"),
			0...0x07, 0x0b, 0x0e...0x1f => {
				var buf: [8]u8 = undefined;
				const esc = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c}) catch unreachable;
				try out.appendSlice(allocator, esc);
			},
			else => try out.append(allocator, c),
		}
	}
	try out.append(allocator, '"');
}

// --- del ----------------------------------------------------------------

fn cmdDel(ctx: *Ctx, loaded: *config.Loaded, d: cli.DelArgs) !void {
	const allocator = ctx.allocator;
	const io = ctx.io;

	const plugins_arr = mutate.existingPluginsArray(loaded.root()) orelse {
		die(allocator, io, "no such plugin '{s}'", .{d.plugin}, 65);
	};
	const idx = mutate.findPlugin(plugins_arr, d.plugin) orelse {
		die(allocator, io, "no such plugin '{s}'", .{d.plugin}, 65);
	};

	const rules_arr = rulesOrNull(loaded);
	const l7_arr = l7RulesOrNull(loaded);
	const inject_arr = injectSpecsOrNull(loaded);
	const tagged = (if (rules_arr) |ra| mutate.countTaggedRules(ra, d.plugin) else 0) +
		(if (l7_arr) |la| mutate.countTaggedRules(la, d.plugin) else 0) +
		(if (inject_arr) |ia| mutate.countTaggedRules(ia, d.plugin) else 0);

	const prompt = try std.fmt.allocPrint(allocator, "Remove plugin '{s}' and its {d} contributed rule(s)/inject spec(s)?", .{ d.plugin, tagged });
	defer allocator.free(prompt);
	if (!d.yes and !try confirm(ctx, prompt)) {
		try announce(ctx, "Aborted.", .{});
		return;
	}

	_ = plugins_arr.orderedRemove(idx);
	var removed = if (rules_arr) |ra| mutate.removeTaggedRules(ra, d.plugin) else 0;
	removed += if (l7_arr) |la| mutate.removeTaggedRules(la, d.plugin) else 0;
	removed += if (inject_arr) |ia| mutate.removeTaggedRules(ia, d.plugin) else 0;

	// Drop the materialized source for the removed plugin so it stops being a
	// path: input and its disk space is reclaimed.
	removeSource(ctx, d.plugin);

	try config.save(allocator, io, ctx.config_path, loaded.root().*);
	try regenComposition(ctx, plugins_arr);
	// No fetch needed: remaining inputs are local path: refs. Best-effort.
	finalizeComposition(ctx, plugins_arr, null);
	if (removed > 0) try rules_module.maybeReload(allocator, io, ctx.runtime_path, loaded);

	try announce(ctx, "Plugin '{s}' removed ({d} contributed entr(ies) dropped).", .{ d.plugin, removed });
	try finishLive(ctx, d.plugin, "to unload its NixOS module");
}

// --- update -------------------------------------------------------------

fn cmdUpdate(ctx: *Ctx, loaded: *config.Loaded, u: cli.UpdateArgs) !void {
	const allocator = ctx.allocator;
	const io = ctx.io;
	// --defer-rules: announce/print/restart-hint chatter goes to stderr; stdout
	// carries only the deferred JSON line (cli guarantees PLUGIN is named).
	ctx.defer_rules = u.defer_rules;

	// --git-credential-stdin: same single-fetch netrc setup as add. update
	// re-resolves the flake (nix flake metadata + archive), so the private repo
	// needs the acting user's token for those fetches too.
	var fetch_env: ?gitcred.FetchEnv = null;
	defer if (fetch_env) |*fe| fe.deinit();
	if (u.git_credential_stdin) {
		const raw = gitcred.readStdin(allocator, io) catch {
			die(allocator, io, "could not read git credential from stdin", .{}, 65);
		};
		defer allocator.free(raw);
		const cred = gitcred.parseLine(raw) catch {
			die(allocator, io, "malformed git credential on stdin (want host<TAB>user<TAB>token)", .{}, 65);
		};
		fetch_env = gitcred.FetchEnv.setup(allocator, io, ctx.parent_env, cred) catch {
			die(allocator, io, "could not set up authenticated fetch", .{}, 70);
		};
		ctx.fetch_env = fetch_env.?.map();
	}

	const plugins_arr = mutate.existingPluginsArray(loaded.root()) orelse {
		if (u.plugin) |p| die(allocator, io, "no such plugin '{s}'", .{p}, 65);
		try announce(ctx, "(no plugins)", .{});
		return;
	};
	if (u.plugin) |p| {
		if (mutate.findPlugin(plugins_arr, p) == null) {
			die(allocator, io, "no such plugin '{s}'", .{p}, 65);
		}
	} else if (plugins_arr.items.len == 0) {
		try announce(ctx, "(no plugins)", .{});
		return;
	}

	var changed = false;
	var rules_touched = false;
	var failed = false;
	// An up-to-date plugin whose on-disk source was re-copied (see below).
	var healed = false;

	// Versioning is per flake: resolve each distinct URL once per run and
	// apply the same pin to every plugin that came from it, so siblings
	// can't drift apart across an update.
	var resolved: std.ArrayList(struct { url: []const u8, meta: nix.Meta }) = .empty;
	defer {
		for (resolved.items) |*r| r.meta.deinit(allocator);
		resolved.deinit(allocator);
	}
	// --defer-rules: the one `{"deferred":...}` line for the named plugin,
	// rendered inside the loop (the incoming rule trees are freed per
	// iteration) and written only after config.save commits the update.
	var deferred_line: ?[]u8 = null;
	defer if (deferred_line) |l| allocator.free(l);

	for (plugins_arr.items) |*item| {
		if (item.* != .object) continue;
		const n = mutate.entryField(item.object, "name") orelse {
			try warn(ctx, "skipping malformed plugin entry (no name)", .{});
			failed = true;
			continue;
		};
		if (u.plugin) |p| {
			if (!std.mem.eql(u8, p, n)) continue;
		}
		const url = mutate.entryField(item.object, "url") orelse {
			try warn(ctx, "{s}: malformed entry (no url); re-add it", .{n});
			failed = true;
			continue;
		};
		const attr = mutate.entryField(item.object, "attr");
		if (attr) |at| {
			if (!name_mod.isValidAttr(at)) {
				try warn(ctx, "{s}: malformed entry (bad attr); re-add it", .{n});
				failed = true;
				continue;
			}
		}
		const old_hash = mutate.entryField(item.object, "narHash") orelse "";

		const meta: *nix.Meta = blk: {
			for (resolved.items) |*r| {
				if (std.mem.eql(u8, r.url, url)) break :blk &r.meta;
			}
			// --refresh: bypass nix's flake eval cache so a mutable ref re-resolves
			// to the current tip. Without it, update can keep returning the cached
			// rev and never actually move the pin.
			var meta_out = nix.flakeMetadata(allocator, io, ctx.fetch_env, url, true) catch {
				die(allocator, io, "failed to run nix (is it on PATH?)", .{}, 70);
			};
			defer meta_out.deinit(allocator);
			if (!meta_out.ok) {
				try warn(ctx, "{s}: could not resolve '{s}': {s}", .{ n, url, nix.stderrTail(meta_out.stderr) });
				failed = true;
				break :blk null;
			}
			const m = nix.parseMetadata(allocator, meta_out.stdout) catch {
				try warn(ctx, "{s}: unexpected nix flake metadata output", .{n});
				failed = true;
				break :blk null;
			};
			try resolved.append(allocator, .{ .url = url, .meta = m });
			break :blk &resolved.items[resolved.items.len - 1].meta;
		} orelse continue;

		if (std.mem.eql(u8, meta.nar_hash, old_hash)) {
			try announce(ctx, "{s}: up to date ({s})", .{ n, pinLabel(meta) });
			// The pin did not move, but the materialized copy may not BE the pin:
			// an older cogbox stripped exec bits while copying (so the tree's
			// NAR hash never equals the recorded narHash), or a killed op left a
			// half-copied tree. The composition re-pin refuses such a tree
			// (compose.repinVerdict -> .disagrees_with_record), so without this
			// a stale lock entry for it could never heal. Re-copy it from the
			// store path the resolve above just produced, which IS the recorded
			// pin; finalizeComposition then re-pins it.
			if (sourceTreeDiverges(ctx, n, meta.nar_hash)) {
				if (materializeSource(ctx, n, meta, url)) |_| {
					try announce(ctx, "{s}: re-materialized its plugin source (the on-disk copy did not match the recorded pin)", .{n});
					healed = true;
				} else |err| {
					try warn(ctx, "{s}: on-disk source does not match the recorded pin and could not be re-materialized: {s}", .{ n, @errorName(err) });
				}
			}
			continue;
		}

		// The SAME lint `add` runs, and BEFORE materializeSource replaces the
		// installed copy. An update installs code nobody has seen: a new version
		// can rename a skill onto the reserved index name, or onto a name cogbox
		// qualifies something else to, and until this ran the update simply
		// succeeded -- leaving a config.json whose very next `cogbox start`
		// cannot evaluate the guest, which on GCE is the restart loop this whole
		// mechanism exists to prevent. Read out of the STORE, not out of
		// plugin-sources/, precisely so that refusing is safe: at this point
		// config.json, the on-disk source and the composition are all still the
		// working old pin, and exit 65 leaves all three that way. `source_path`
		// resolution mirrors materializeSource's; an empty one (nix did not
		// report `.path` and the lazy lookup failed) means there is nothing to
		// read, so the build stays the only authority for this one update.
		var owned_src: ?[]u8 = null;
		defer if (owned_src) |s| allocator.free(s);
		const new_src: []const u8 = blk: {
			if (meta.source_path.len > 0) break :blk meta.source_path;
			owned_src = nix.flakeSourcePath(allocator, io, ctx.fetch_env, url) catch null;
			break :blk owned_src orelse "";
		};
		if (new_src.len > 0) {
			const new_root = try std.fs.path.join(allocator, &.{ new_src, nix.dirParam(meta.locked_url) orelse "." });
			defer allocator.free(new_root);
			// A refusal is this PLUGIN's failure, not the run's: skip it the same
			// way a bad entry or an unresolvable ref is skipped above. Exiting
			// from inside the loop instead would strand every plugin already
			// updated in this run -- materializeSource has replaced their trees
			// and relockPlugin has moved their JSON, but config.save and the
			// regenComposition/finalizeComposition self-heal all run AFTER the
			// loop, so config.json would keep reporting the old rev/narHash and
			// the composition lock the old path: narHash. nix honours a stale
			// lock rather than erroring, so the guest would go on building the
			// old tree until some later add/del/update silently jumped it to a
			// version `cogbox plugin list` never recorded. `failed` still exits
			// 65 at the tail, so a refused update keeps the add path's code.
			if (try lintUnitNames(ctx, plugins_arr, n, new_root, false)) {
				try warn(ctx, "{s}: not updated; the new version's unit names cannot be composed (pin, source and composition left on the working version)", .{n});
				failed = true;
				continue;
			}
		}

		// Re-materialize this plugin's source at the new rev so its path: input
		// tracks the update (offline at launch). `url` is the original ref, used
		// only as the lazy fallback for flakeSourcePath. Best-effort.
		materializeSource(ctx, n, meta, url) catch |err| {
			warn(ctx, "{s}: could not materialize plugin source (launch may need network): {s}", .{ n, @errorName(err) }) catch {};
		};

		archiveFlake(ctx, meta.locked_url);

		var l4_parsed: ?std.json.Parsed(std.json.Value) = null;
		defer if (l4_parsed) |*p| p.deinit();
		const incoming_l4: []const std.json.Value = blk: {
			l4_parsed = evalRules(ctx, meta.locked_url, attr);
			const p = l4_parsed orelse break :blk &.{};
			break :blk p.value.array.items;
		};
		var l7_parsed: ?std.json.Parsed(std.json.Value) = null;
		defer if (l7_parsed) |*p| p.deinit();
		const incoming_l7: []const std.json.Value = blk: {
			l7_parsed = evalL7Rules(ctx, meta.locked_url, attr);
			const p = l7_parsed orelse break :blk &.{};
			break :blk p.value.array.items;
		};
		var inject_parsed: ?std.json.Parsed(std.json.Value) = null;
		defer if (inject_parsed) |*p| p.deinit();
		const incoming_inject: []const std.json.Value = blk: {
			inject_parsed = evalInjectSpecs(ctx, meta.locked_url, attr);
			const p = inject_parsed orelse break :blk &.{};
			break :blk p.value.array.items;
		};

		if (rulesOrNull(loaded)) |rules_arr| {
			const old_l7 = l7RulesOrNull(loaded);
			const old_inject = injectSpecsOrNull(loaded);
			const old_count = mutate.countTaggedRules(rules_arr, n) +
				(if (old_l7) |la| mutate.countTaggedRules(la, n) else 0) +
				(if (old_inject) |ia| mutate.countTaggedRules(ia, n) else 0);
			if (old_count > 0 or incoming_l4.len + incoming_l7.len + incoming_inject.len > 0) {
				try announce(ctx, "{s}: contributed rules + inject specs", .{n});
				if (u.defer_rules) {
					// The applied L4/L7 rules stay as they are (updatePluginRules); a -/+
					// diff of them would read as replaced. Only the inject specs move.
					try announce(ctx, "{s}: L4/L7 rules kept; incoming ones not already applied are withheld for review", .{n});
				} else {
					for (rules_arr.items) |r| {
						if (mutate.ruleTag(r)) |tag| {
							if (std.mem.eql(u8, tag, n)) try printRuleLine(ctx, "-", r);
						}
					}
					if (old_l7) |la| {
						for (la.items) |r| {
							if (mutate.ruleTag(r)) |tag| {
								if (std.mem.eql(u8, tag, n)) try printL7RuleLine(ctx, "-", r);
							}
						}
					}
				}
				if (old_inject) |ia| {
					for (ia.items) |r| {
						if (mutate.ruleTag(r)) |tag| {
							if (std.mem.eql(u8, tag, n)) try printInjectLine(ctx, "-", r);
						}
					}
				}
				if (!u.defer_rules) {
					for (incoming_l4) |r| try printRuleLine(ctx, "+", r);
					for (incoming_l7) |r| try printL7RuleLine(ctx, "+", r);
				}
				for (incoming_inject) |s| try printInjectLine(ctx, "+", s);
				if (try updatePluginRules(allocator, loaded, rules_arr, old_l7, old_inject, n, incoming_l4, incoming_l7, incoming_inject, u.defer_rules)) |line| {
					if (deferred_line) |prev| allocator.free(prev);
					deferred_line = line;
				}
				rules_touched = true;
			}
		} else if (incoming_l4.len + incoming_l7.len + incoming_inject.len > 0) {
			try warn(ctx, "{s}: instance is not in rules mode; skipping {d} suggested change(s)", .{ n, incoming_l4.len + incoming_l7.len + incoming_inject.len });
		}

		try mutate.relockPlugin(loaded.treeAllocator(), item, .{
			.name = n,
			.url = url,
			.locked_url = meta.locked_url,
			.rev = meta.rev,
			.nar_hash = meta.nar_hash,
		});
		changed = true;
		try announce(ctx, "{s}: updated to {s}", .{ n, pinLabel(meta) });
	}

	if (changed) {
		try config.save(allocator, io, ctx.config_path, loaded.root().*);
		// The withheld rules are reported only once the update is committed: a
		// failure above leaves nothing for the control plane to file.
		if (deferred_line) |line| try writeStdout(io, line);
		if (rules_touched) try rules_module.maybeReload(allocator, io, ctx.runtime_path, loaded);
	}
	// Regenerate even without changes: update doubles as the self-heal for
	// a missing/stale composition flake (it is a pure function of config +
	// on-disk sources) AND for a stale lock (finalizeComposition re-pins every
	// path: input). On a no-op update (nothing changed, nothing failed) the
	// pre-regen flake.nix/flake.lock bytes are the baseline: when regen + the
	// re-pin leave both byte-identical and the recorded container toplevel is
	// current and seeded, finalizeComposition skips the brain/toplevel
	// prebuild (the expensive part) instead of redoing it for nothing.
	var baseline: NoopBaseline = .{ .flake_nix = null, .flake_lock = null };
	defer baseline.deinit(allocator);
	const noop = !changed and !failed;
	if (noop) {
		baseline.flake_nix = readCompositionFile(ctx, "flake.nix");
		baseline.flake_lock = readCompositionLock(ctx);
	}
	try regenComposition(ctx, plugins_arr);
	finalizeComposition(ctx, plugins_arr, if (noop) &baseline else null);
	if (changed or healed) try finishLive(ctx, u.plugin, "to load the updated NixOS modules");
	if (failed) std.process.exit(65);
}

/// True when plugin `name`'s materialized source (plugin-sources/<name>) is
/// absent, unhashable, or hashes to something other than `nar_hash` (its
/// recorded pin) -- i.e. re-copying it from the store would change it.
fn sourceTreeDiverges(ctx: *const Ctx, name: []const u8, nar_hash: []const u8) bool {
	const allocator = ctx.allocator;
	const input = std.fmt.allocPrint(allocator, "p-{s}", .{name}) catch return false;
	defer allocator.free(input);
	const disk = hashInputTree(ctx, input) orelse return true;
	defer allocator.free(disk);
	return !std.mem.eql(u8, disk, nar_hash);
}

// --- shared helpers ------------------------------------------------------

/// nix flake metadata + parse, with fatal errors on failure. Backs cmdAdd + cmdResolve.
/// `--refresh` (true) so an install/preview of a MUTABLE ref (e.g. a catalog plugin's
/// `?ref=master`) ALWAYS re-resolves to the current tip: nix's tarball-ttl cache is
/// shared across instances/ops, so a prior resolve elsewhere could otherwise pin a
/// stale rev (and an install would silently ship an old plugin). The extra re-resolve
/// is one ls-remote-class round-trip; correctness beats the cache here.
fn resolveFlake(ctx: *const Ctx, url: []const u8) nix.Meta {
	var out = nix.flakeMetadata(ctx.allocator, ctx.io, ctx.fetch_env, url, true) catch {
		die(ctx.allocator, ctx.io, "failed to run nix (is it on PATH?)", .{}, 70);
	};
	defer out.deinit(ctx.allocator);
	if (!out.ok) {
		die(ctx.allocator, ctx.io, "could not resolve flake '{s}':\n{s}", .{ url, nix.stderrTail(out.stderr) }, 65);
	}
	return nix.parseMetadata(ctx.allocator, out.stdout) catch {
		die(ctx.allocator, ctx.io, "unexpected nix flake metadata output for '{s}'", .{url}, 70);
	};
}

/// Pre-fetch the plugin and its transitive inputs into the store so later
/// (offline) starts resolve the pinned URLs locally. Failure is non-fatal:
/// the plugin still works, the first start just needs network.
fn archiveFlake(ctx: *const Ctx, locked_url: []const u8) void {
	var out = nix.flakeArchive(ctx.allocator, ctx.io, ctx.fetch_env, locked_url) catch return;
	defer out.deinit(ctx.allocator);
	if (!out.ok) {
		warn(ctx, "could not pre-fetch flake inputs (offline starts may fail): {s}", .{nix.stderrTail(out.stderr)}) catch {};
	}
}

/// Whether the plugin's source has been materialized -- the marker that lets
/// render emit a path: input. For a subdir flake (`?dir=`) the flake.nix lives
/// at <sources_dir>/<name>/<dir>/flake.nix (the materialized tree is the repo
/// root); `dir` null means the repo root.
fn sourceHydrated(ctx: *const Ctx, name: []const u8, dir: ?[]const u8) bool {
	const cwd = std.Io.Dir.cwd();
	const flake = std.fs.path.join(ctx.allocator, &.{ ctx.sources_dir, name, dir orelse ".", "flake.nix" }) catch return false;
	defer ctx.allocator.free(flake);
	cwd.access(ctx.io, flake, .{}) catch return false;
	return true;
}

/// Copy a plugin's locked source tree onto the PVC at <sources_dir>/<name>/ as
/// a WRITABLE directory, so the composition can reference it as a `path:` input
/// that launch resolves offline (no fetcher, no credential). The store source
/// path is read-only, so the copy is reset to writable modes.
///
/// `meta.source_path` is used when present (the metadata path); otherwise (the
/// cmdAdd sibling-reuse path, which built Meta WITHOUT a metadata call) the
/// store path is resolved lazily via `flakeSourcePath` for `url`, under the
/// authenticated fetch env. An empty resolved path is a hard error (the caller
/// downgrades it to a warning and falls back to the locked URL).
fn materializeSource(ctx: *const Ctx, name: []const u8, meta: *const nix.Meta, url: []const u8) !void {
	const allocator = ctx.allocator;

	var owned_src: ?[]u8 = null;
	defer if (owned_src) |s| allocator.free(s);
	const src: []const u8 = blk: {
		if (meta.source_path.len > 0) break :blk meta.source_path;
		owned_src = try nix.flakeSourcePath(allocator, ctx.io, ctx.fetch_env, url);
		break :blk owned_src.?;
	};
	if (src.len == 0) return error.NoSourcePath;

	const dest = try std.fs.path.join(allocator, &.{ ctx.sources_dir, name });
	defer allocator.free(dest);

	const cwd = std.Io.Dir.cwd();
	try cwd.createDirPath(ctx.io, ctx.sources_dir);
	// Replace any prior copy so a downgrade/re-add can't leave stale files.
	cwd.deleteTree(ctx.io, dest) catch {};

	// Recursive copy with writable reset. Coreutils are present in the pod
	// image (the launcher already uses cp/mv/rm); a native walk would have to
	// re-implement mode reset for read-only store trees. `cp -a SRC/. DEST`
	// copies SRC's contents into DEST (DEST is the plugin's own dir), and chmod
	// then forces u+w across the tree so a later deleteTree/replace and nix's
	// path: read both work. The MODE is preserved (only ownership is dropped):
	// the NAR serialisation records each file's executable bit, so a copy that
	// strips it hashes differently from the store path whose narHash
	// config.json records, and the composition re-pin (compose.repinVerdict),
	// which gates on exactly that equality, would refuse every plugin shipping
	// a script forever. Keeping the bit also leaves plugin scripts executable,
	// as their authors shipped them (older cogbox stripped it; cmdUpdate
	// re-materializes such a tree).
	const src_dot = try std.fmt.allocPrint(allocator, "{s}/.", .{src});
	defer allocator.free(src_dot);
	try runTool(ctx, &(materialize_cp_flags ++ [_][]const u8{ src_dot, dest }));
	try runTool(ctx, &.{ "chmod", "-R", "u+rwX", dest });
}

/// materializeSource's copy, before its SRC/. and DEST operands.
///
/// --remove-destination: a live-apply snapshot holds a `cp -al` of
/// plugin-sources/, i.e. its files SHARE inodes with this tree, so no verb may
/// write into an existing source file. The deleteTree before the copy is
/// best-effort, and a file that survives it (an undeletable directory) must get
/// a new inode, never a truncate-and-rewrite of the shared one. GNU `cp -a`
/// already unlinks a destination with more than one link before writing it, but
/// only as a side effect of preserving hard links (coreutils copy.c); the flag
/// makes the unlink unconditional and keeps it if the preserve set ever
/// changes. Where even the unlink fails, cp fails, and the caller warns as for
/// any failed materialize.
const materialize_cp_flags = [_][]const u8{ "cp", "-a", "--no-preserve=ownership", "--remove-destination" };

/// Remove a plugin's materialized source dir (del path). Best-effort.
fn removeSource(ctx: *const Ctx, name: []const u8) void {
	const dest = std.fs.path.join(ctx.allocator, &.{ ctx.sources_dir, name }) catch return;
	defer ctx.allocator.free(dest);
	std.Io.Dir.cwd().deleteTree(ctx.io, dest) catch {};
}

/// Run a host tool (cp/chmod), inheriting the parent env so PATH resolves the
/// coreutils binaries. Errors if the tool can't run or exits non-zero.
fn runTool(ctx: *const Ctx, argv: []const []const u8) !void {
	const res = try std.process.run(ctx.allocator, ctx.io, .{ .argv = argv, .environ_map = null });
	defer {
		ctx.allocator.free(res.stdout);
		ctx.allocator.free(res.stderr);
	}
	if (res.term != .exited or res.term.exited != 0) return error.ToolFailed;
}

/// The pre-regen composition bytes of a no-op `update` (cmdUpdate), used by
/// finalizeComposition to decide whether the brain/toplevel prebuild can be
/// skipped. Null fields mean the file was absent/unreadable (never "equal").
const NoopBaseline = struct {
	flake_nix: ?[]const u8,
	flake_lock: ?[]const u8,

	fn deinit(self: *NoopBaseline, allocator: std.mem.Allocator) void {
		if (self.flake_nix) |b| allocator.free(b);
		if (self.flake_lock) |b| allocator.free(b);
	}
};

/// After regenerating the composition: reconcile its flake.lock, re-pin its
/// path: inputs, and populate the launch-time binary cache. All best-effort
/// (warn, never die): the lock makes launch deterministic (resolved from a
/// coherent pin, offline for path: inputs), and the cache substitutes any
/// transitive tarball/narHash input on a fresh store. The re-pin exists
/// because the materialized plugin sources and the `user` flake are path:
/// inputs, and plain `nix flake lock` keeps their OLD narHash when their
/// content changed (a content-changing update would otherwise be a silent
/// false success on a warm store and a narHash mismatch on a cold one).
/// Skipped when no composition exists (no plugins).
///
/// `noop` (cmdUpdate only, else null) carries the pre-regen flake.nix /
/// flake.lock bytes of an update that changed nothing: when regen and the
/// re-pin leave both byte-identical and the recorded toplevel is current and
/// seeded (toplevelSeeded), the brain/toplevel prebuild is skipped.
fn finalizeComposition(ctx: *const Ctx, plugins_arr: *const std.json.Array, noop: ?*const NoopBaseline) void {
	const allocator = ctx.allocator;
	const cwd = std.Io.Dir.cwd();

	// Only run when the composition flake actually exists.
	const flake = std.fs.path.join(allocator, &.{ ctx.plugins_flake_dir, "flake.nix" }) catch return;
	defer allocator.free(flake);
	cwd.access(ctx.io, flake, .{}) catch return;

	const flake_url = std.fmt.allocPrint(allocator, "path:{s}", .{ctx.plugins_flake_dir}) catch return;
	defer allocator.free(flake_url);

	// Reconcile/write the lock so launch resolves deterministically offline.
	if (nix.flakeLock(allocator, ctx.io, ctx.fetch_env, flake_url)) |out| {
		var o = out;
		defer o.deinit(allocator);
		if (!o.ok) warn(ctx, "could not lock composition (launch may re-resolve inputs): {s}", .{nix.stderrTail(o.stderr)}) catch {};
	} else |_| {}

	// Re-pin the STALE path: inputs (plain lock above keeps a changed path:
	// input's old narHash), gated on config.json's recorded pins. Before the
	// archive so the cache holds the NEW content. A lock that moved is not yet
	// proven: snapshot the pre-re-pin bytes (composition.lock.prev) so a boot
	// can fall back to them if this op is killed before the prebuild below
	// seeds the new content, or if that content fails to build.
	const repinned = blk: {
		const before = repinPathInputs(ctx, flake_url, plugins_arr) orelse break :blk false;
		defer allocator.free(before);
		savePrevLock(ctx, before);
		break :blk true;
	};

	// Populate the file:// binary cache the launcher uses as a substituter.
	const cache_url = std.fmt.allocPrint(allocator, "file://{s}", .{ctx.cache_dir}) catch return;
	defer allocator.free(cache_url);
	if (nix.flakeArchiveTo(allocator, ctx.io, ctx.fetch_env, cache_url, flake_url)) |out| {
		var o = out;
		defer o.deinit(allocator);
		if (!o.ok) warn(ctx, "could not populate offline plugin cache (transitive inputs may need network at launch): {s}", .{nix.stderrTail(o.stderr)}) catch {};
	} else |_| {}

	// Pre-build the microvm runner and push it to the configured remote cache so
	// boot SUBSTITUTES it instead of rebuilding the expensive closure from source.
	// Gated on cogworx opting in via env;
	// best-effort throughout -- a failure here only means boot rebuilds, never a
	// failed plugin verb.
	const runner = prebuildAndPushRunner(ctx);

	// No-op update fast path: skip BOTH container prebuilds when nothing moved.
	// The per-instance toplevel closure contains the per-instance brain, and the
	// toplevel record is written only after a successful copy into the
	// plugin-cache (doToplevelBuild), so a record that is current (image rev +
	// composition hash) AND seeded (its narinfo is in the cache) proves both
	// artifacts are already there for this image rev and composition. An image
	// bump, a cache loss or a content re-pin all fail the predicate, so `update`
	// stays the self-heal. The runner push above stays unconditional so the VM
	// runner-push record is still rewritten.
	if (noop) |b| {
		if (!repinned and compositionUnchanged(ctx, b) and toplevelSeeded(ctx)) {
			writeStderr(ctx.io, "cogbox plugin: composition unchanged and toplevel already seeded; skipping brain/toplevel prebuild\n") catch {};
			// The seeded toplevel closure carries the brain for THIS lock.
			clearPrevLock(ctx);
			return;
		}
	}

	// Container backend counterpart: pre-build cogbox-brain (which now carries the
	// plugins' cogbox.packages as $out/bin) and copy its closure into the LOCAL
	// per-instance plugin-cache, so the agent's egress-less boot substitutes it
	// offline instead of failing to build the plugin tools. Gated on
	// COGBOX_BRAIN_PUSH_LOCAL (the container backend); a no-op on the VM.
	const brain = prebuildBrainLocal(ctx);

	// Container full-module: pre-build the per-instance toplevel (the plugin's WHOLE
	// NixOS module folded in), seed its closure into the plugin-cache, and record the
	// out-path so agentInit boots it directly instead of the baked plugin-less base.
	// Gated on COGBOX_TOPLEVEL_PUSH_LOCAL; a no-op on the VM and when disabled.
	const toplevel = prebuildToplevelLocal(ctx);

	// The live lock is confirmed once a prebuild built from it (the VM runner
	// push, or a container brain/toplevel) and none failed. None ran (a VM/GCE
	// op without cogworx's runner push): keep the snapshot for the launcher,
	// whose pre-exec build is then that path's confirmation -- confirming here
	// instead spares the next boot that extra full eval.
	const any_ok = runner == .ok or brain == .ok or toplevel == .ok;
	const any_failed = runner == .failed or brain == .failed or toplevel == .failed;
	if (any_ok and !any_failed) clearPrevLock(ctx);
}

/// Outcome of an env-gated container prebuild.
const Prebuild = enum { skipped, ok, failed };

/// Re-pin the composition's STALE path: inputs (materialized plugin sources and
/// the `user` flake) so their locked narHash tracks their on-disk content; plain
/// `nix flake lock` keeps the old one. Never blind (compose.repinVerdict):
///   - an input whose locked narHash already equals `nix hash path` of its tree
///     is left alone, so a current input's transitive inputs never float (an
///     input without its own flake.lock re-resolves them on every update);
///   - a stale `p-<name>` is re-pinned only when its on-disk tree IS the narHash
///     config.json records for that plugin. materializeSource is not atomic
///     (deleteTree, then cp) and a killed or failed op can leave plugin-sources
///     at a rev config.json never recorded; pinning that would make the lock
///     disagree with `cogbox plugin list` / the mirror, or pin a half-copied
///     tree. Those keep their old, coherent pin and are warned about by name.
/// The stale set is updated in one batched `nix flake update`, then (a single
/// call is all-or-nothing) one retry per input, with ONE warning naming whatever
/// still failed. Afterwards every re-pinned plugin input must lock exactly the
/// hash checked above; if one does not, the pre-re-pin bytes are restored whole.
/// Returns the pre-re-pin lock bytes (caller frees) iff the lock moved, else
/// null. Best-effort: never dies, never changes the exit code; an unreadable
/// lock is silently a no-op.
fn repinPathInputs(ctx: *const Ctx, flake_url: []const u8, plugins_arr: *const std.json.Array) ?[]u8 {
	const allocator = ctx.allocator;
	const before = readCompositionLock(ctx) orelse return null;
	var keep_before = false;
	defer if (!keep_before) allocator.free(before);

	const names = compose.pathInputsToRepin(allocator, before) catch return null;
	defer compose.freeInputNames(allocator, names);
	if (names.len == 0) return null;

	// stale[i] (borrowed from names) is re-pinned expecting expected[i] (owned).
	var stale: std.ArrayList([]const u8) = .empty;
	defer stale.deinit(allocator);
	var expected: std.ArrayList([]u8) = .empty;
	defer {
		for (expected.items) |e| allocator.free(e);
		expected.deinit(allocator);
	}
	for (names) |n| {
		const disk = hashInputTree(ctx, n);
		defer if (disk) |d| allocator.free(d);
		const locked = compose.lockedNarHash(allocator, before, n) catch null;
		defer if (locked) |l| allocator.free(l);
		const recorded = if (std.mem.startsWith(u8, n, "p-")) recordedNarHash(plugins_arr, n[2..]) else null;
		switch (compose.repinVerdict(n, locked, disk, recorded)) {
			.current => {},
			.repin => {
				const dup = allocator.dupe(u8, disk.?) catch return null;
				expected.append(allocator, dup) catch {
					allocator.free(dup);
					return null;
				};
				stale.append(allocator, n) catch return null;
			},
			.disagrees_with_record => warn(ctx, "{s}: on-disk source {s} does not match the pin config.json records ({s}); keeping its locked narHash (the guest keeps serving the previously locked content until a successful update)", .{ n, disk.?, recorded orelse "none" }) catch {},
			.unverifiable => warn(ctx, "{s}: could not hash its on-disk source; keeping its locked narHash", .{n}) catch {},
		}
	}
	if (stale.items.len == 0) return null;

	// ONE deadline for the batch and every retry (repin_budget_s): this runs
	// inside the control plane's install budget, and a re-pin that needs the
	// network (an input without its own flake.lock, unreachable substituters)
	// must cost a bounded slice of it, not 120s per stale input.
	const start = std.Io.Timestamp.now(ctx.io, .awake);
	var last_err: ?[]u8 = null;
	defer if (last_err) |e| allocator.free(e);
	var timed_out = false;
	if (!runRepin(ctx, flake_url, stale.items, repin_budget_s, &last_err, &timed_out)) {
		var failed: std.ArrayList(u8) = .empty;
		defer failed.deinit(allocator);
		for (stale.items) |n| {
			// A batch that TIMED OUT failed on the network, not on one bad
			// input: per-input retries would only hang the same way.
			const remaining: ?u32 = if (timed_out) null else repinRemaining(start.durationTo(std.Io.Timestamp.now(ctx.io, .awake)).toMilliseconds(), repin_budget_s);
			if (remaining) |secs| {
				if (runRepin(ctx, flake_url, &.{n}, secs, &last_err, &timed_out)) continue;
			} else if (last_err == null) {
				setLastErr(allocator, &last_err, "re-pin time budget exhausted");
			}
			if (failed.items.len > 0) failed.appendSlice(allocator, ", ") catch {};
			failed.appendSlice(allocator, n) catch {};
		}
		if (failed.items.len > 0) {
			warn(ctx, "could not re-pin composition input(s) {s} (the guest may serve stale plugin content): {s}", .{ failed.items, last_err orelse "" }) catch {};
		}
	}

	const after = readCompositionLock(ctx) orelse return null;
	defer allocator.free(after);
	if (std.mem.eql(u8, before, after)) return null;

	// Post-check: each re-pinned plugin input must now lock either the tree
	// hashed above or (its own re-pin failed, warned above) its old pin -- a tree
	// that changed underneath us, or a nix that hashed it differently, would
	// otherwise pin something nobody checked. `user` is not checked: it has no
	// recorded pin to be coherent with.
	for (stale.items, expected.items) |n, want| {
		if (!std.mem.startsWith(u8, n, "p-")) continue;
		const got = compose.lockedNarHash(allocator, after, n) catch null;
		defer if (got) |g| allocator.free(g);
		const old = compose.lockedNarHash(allocator, before, n) catch null;
		defer if (old) |o| allocator.free(o);
		if (got) |g| {
			if (std.mem.eql(u8, g, want)) continue;
			if (old != null and std.mem.eql(u8, g, old.?)) continue;
		} else if (old == null) continue;
		warn(ctx, "{s}: re-pinned lock entry does not match its checked source ({s}); restoring the previous composition lock", .{ n, want }) catch {};
		if (!writeCompositionLock(ctx, before)) {
			warn(ctx, "could not restore the previous composition lock", .{}) catch {};
		}
		return null;
	}

	const msg = std.fmt.allocPrint(allocator, "cogbox plugin: re-pinned composition lock ({d} of {d} path input(s) stale)\n", .{ stale.items.len, names.len }) catch null;
	if (msg) |m| {
		defer allocator.free(m);
		writeStderr(ctx.io, m) catch {};
	}
	keep_before = true;
	return before;
}

/// `nix hash path` of a composition input's source ROOT (for a `?dir=` plugin
/// the root is the materialized repo, which is what its path: input locks):
/// `user` -> the per-instance user flake dir, `p-<name>` -> plugin-sources/
/// <name>. The trimmed SRI hash (caller frees), or null on any failure.
fn hashInputTree(ctx: *const Ctx, input_name: []const u8) ?[]u8 {
	const allocator = ctx.allocator;
	const dir = if (std.mem.eql(u8, input_name, "user"))
		allocator.dupe(u8, ctx.user_flake_dir) catch return null
	else
		std.fs.path.join(allocator, &.{ ctx.sources_dir, input_name[2..] }) catch return null;
	defer allocator.free(dir);
	var out = nix.hashPath(allocator, ctx.io, null, dir) catch return null;
	defer out.deinit(allocator);
	if (!out.ok) return null;
	const h = std.mem.trim(u8, out.stdout, " \t\r\n");
	if (h.len == 0) return null;
	return allocator.dupe(u8, h) catch null;
}

/// config.json's recorded narHash for plugin `name` (borrowed), or null.
fn recordedNarHash(plugins_arr: *const std.json.Array, name: []const u8) ?[]const u8 {
	for (plugins_arr.items) |item| {
		if (item != .object) continue;
		const n = mutate.entryField(item.object, "name") orelse continue;
		if (!std.mem.eql(u8, n, name)) continue;
		return mutate.entryField(item.object, "narHash");
	}
	return null;
}

/// Atomically (tmp + rename) replace the composition flake.lock. False on any
/// failure (the old file is left in place).
fn writeCompositionLock(ctx: *const Ctx, bytes: []const u8) bool {
	const path = std.fs.path.join(ctx.allocator, &.{ ctx.plugins_flake_dir, "flake.lock" }) catch return false;
	defer ctx.allocator.free(path);
	return writeFileAtomic(ctx, path, bytes);
}

/// Atomically (unique tmp + rename) write `bytes` to `path`. False on any
/// failure. The tmp name carries a random nonce and is created exclusively
/// (same as compose.writeCompositionFlake), so concurrent writers never share
/// a tmp, and it is always removed: a stray tmp inside plugins-flake/ would
/// change the composition's own source hash.
pub fn writeFileAtomic(ctx: *const Ctx, path: []const u8, bytes: []const u8) bool {
	const allocator = ctx.allocator;
	const cwd = std.Io.Dir.cwd();
	var nonce: [16]u8 = undefined;
	ctx.io.random(&nonce);
	const tmp_path = std.fmt.allocPrint(allocator, "{s}.{x}.tmp", .{ path, nonce }) catch return false;
	defer allocator.free(tmp_path);
	defer cwd.deleteFile(ctx.io, tmp_path) catch {};
	{
		const f = cwd.createFile(ctx.io, tmp_path, .{ .exclusive = true }) catch return false;
		defer f.close(ctx.io);
		var write_buf: [4096]u8 = undefined;
		var writer = f.writer(ctx.io, &write_buf);
		writer.interface.writeAll(bytes) catch return false;
		writer.flush() catch return false;
		f.sync(ctx.io) catch {};
	}
	cwd.rename(tmp_path, cwd, path, ctx.io) catch return false;
	return true;
}

/// The unconfirmed-re-pin snapshot: <instance_config_dir>/composition.lock.prev
/// holds the composition flake.lock as it was BEFORE a re-pin whose new content
/// has not yet been proven buildable/seeded. It is a sibling of plugins-flake/
/// (inside it would change the composition's own source hash). Written when a
/// re-pin moves the lock and no snapshot exists yet (so it always holds the
/// last lock that booted, not an intermediate unconfirmed one), removed once
/// the new lock is confirmed: by the container brain/toplevel prebuild or the
/// boot reconcile (here), or by the VM/GCE launcher's pre-exec build. Readers:
/// brainResolveContainer (flake.nix) retries the brain with it when the live
/// lock fails offline; cogbox-launch.sh restores it when the re-pinned
/// composition fails to build. Without it a re-pin that is killed (the CP's
/// install budget) or fails to build turns a stale-but-working instance into
/// a plugin-less (container) or restart-looping (GCE) one.
fn prevLockPath(ctx: *const Ctx) ?[]u8 {
	const instance_config_dir = std.fs.path.dirname(ctx.plugins_flake_dir) orelse return null;
	return std.fs.path.join(ctx.allocator, &.{ instance_config_dir, "composition.lock.prev" }) catch null;
}

/// Record `before` as the unconfirmed-re-pin snapshot unless one already exists.
fn savePrevLock(ctx: *const Ctx, before: []const u8) void {
	const path = prevLockPath(ctx) orelse return;
	defer ctx.allocator.free(path);
	if (std.Io.Dir.cwd().access(ctx.io, path, .{})) |_| return else |_| {}
	if (!writeFileAtomic(ctx, path, before)) {
		warn(ctx, "could not save the pre-re-pin composition lock (no fallback if the re-pinned content fails to build)", .{}) catch {};
	}
}

/// Drop the unconfirmed-re-pin snapshot: the live lock is confirmed. Best-effort.
pub fn clearPrevLock(ctx: *const Ctx) void {
	const path = prevLockPath(ctx) orelse return;
	defer ctx.allocator.free(path);
	std.Io.Dir.cwd().deleteFile(ctx.io, path) catch {};
	clearPrevBootMarker(ctx);
}

/// Drop <instance_config_dir>/composition.lock.prev.boot. cogbox-launch.sh
/// writes it next to a composition.lock.prev the LAUNCHER snapshotted (a boot
/// re-pin), and it vouches that runner.path still names the runner booted
/// under that snapshot -- so a failed confirmation may keep runner.path when it
/// restores the snapshot. Any op invalidates that: regenComposition removes or
/// rewrites runner.path (removeRunnerRecord) and clearPrevLock drops the
/// snapshot itself, so both drop the marker. Best-effort.
fn clearPrevBootMarker(ctx: *const Ctx) void {
	const instance_config_dir = std.fs.path.dirname(ctx.plugins_flake_dir) orelse return;
	const path = std.fs.path.join(ctx.allocator, &.{ instance_config_dir, "composition.lock.prev.boot" }) catch return;
	defer ctx.allocator.free(path);
	std.Io.Dir.cwd().deleteFile(ctx.io, path) catch {};
}

/// Total wall-clock budget, in seconds, for one op's composition re-pin (the
/// batched `nix flake update` plus every per-input retry). Matches the
/// launcher's (cogbox-launch.sh).
const repin_budget_s: u32 = 120;

/// Seconds left of a `budget_s` deadline after `elapsed_ms`, or null once
/// less than one second remains (the caller then stops retrying). Pure.
fn repinRemaining(elapsed_ms: i64, budget_s: u32) ?u32 {
	const left_ms = @as(i64, budget_s) * 1000 - elapsed_ms;
	if (left_ms < 1000) return null;
	return @intCast(@divTrunc(left_ms, 1000));
}

/// One `nix flake update <names> --flake <url>`, killed after `timeout_s`. On
/// failure stores the stderr tail (or a launch-failure / timeout note) in
/// `last_err`, replacing any previous one, and sets `timed_out` when the
/// timeout fired.
fn runRepin(ctx: *const Ctx, flake_url: []const u8, names: []const []const u8, timeout_s: u32, last_err: *?[]u8, timed_out: *bool) bool {
	const allocator = ctx.allocator;
	var out = nix.flakeUpdateInputs(allocator, ctx.io, ctx.fetch_env, flake_url, names, timeout_s) catch {
		setLastErr(allocator, last_err, "failed to run nix");
		return false;
	};
	defer out.deinit(allocator);
	if (out.ok) return true;
	if (out.timed_out) {
		timed_out.* = true;
		setLastErr(allocator, last_err, "timed out (network unreachable?)");
		return false;
	}
	setLastErr(allocator, last_err, nix.stderrTail(out.stderr));
	return false;
}

fn setLastErr(allocator: std.mem.Allocator, last_err: *?[]u8, msg: []const u8) void {
	if (last_err.*) |e| allocator.free(e);
	last_err.* = allocator.dupe(u8, msg) catch null;
}

/// True iff the current composition flake.nix AND flake.lock are both present
/// and byte-identical to the no-op baseline (which must have both too).
fn compositionUnchanged(ctx: *const Ctx, b: *const NoopBaseline) bool {
	const allocator = ctx.allocator;
	const base_nix = b.flake_nix orelse return false;
	const base_lock = b.flake_lock orelse return false;
	const cur_nix = readCompositionFile(ctx, "flake.nix") orelse return false;
	defer allocator.free(cur_nix);
	const cur_lock = readCompositionLock(ctx) orelse return false;
	defer allocator.free(cur_lock);
	return std.mem.eql(u8, cur_nix, base_nix) and std.mem.eql(u8, cur_lock, base_lock);
}

/// The env-driven runner pre-build + push (Stage 1 of the offline-launch
/// optimization). Runs only when cogworx (the worker pod) requests it:
/// COGBOX_RUNNER_PUSH == "1" AND COGBOX_PUSH_CONFIG is set. It builds the SAME
/// microvm runner the boot path would build (identical flake ref +
/// --override-input set => byte-identical out-path; nothing instance-specific
/// is in the closure -- hostname/ports/keys are launch-time sed rewrites on the
/// OUTPUT), then pushes that out-path's closure to the cache so a fresh-store
/// boot substitutes it. Every failure is logged and swallowed.
fn prebuildAndPushRunner(ctx: *const Ctx) Prebuild {
	const allocator = ctx.allocator;
	const env = ctx.parent_env;

	const push = env.get("COGBOX_RUNNER_PUSH") orelse return .skipped;
	if (!std.mem.eql(u8, push, "1")) return .skipped;
	const push_config = env.get("COGBOX_PUSH_CONFIG") orelse return .skipped;
	if (push_config.len == 0) return .skipped;

	// The cogbox flake + nixpkgs store paths, baked by mkCogbox (--set-default).
	const flake_source = env.get("COGBOX_FLAKE_SOURCE") orelse {
		warn(ctx, "runner push: COGBOX_FLAKE_SOURCE unset; skipping pre-build", .{}) catch {};
		return .failed;
	};
	const nixpkgs_source = env.get("COGBOX_NIXPKGS_SOURCE") orelse {
		warn(ctx, "runner push: COGBOX_NIXPKGS_SOURCE unset; skipping pre-build", .{}) catch {};
		return .failed;
	};

	// The config-name suffix: cogbox-x86_64 / cogbox-aarch64. builtin.cpu.arch
	// is fixed at compile time to the arch this cogbox image was built for, and
	// its tag name (x86_64 / aarch64) matches flake.nix's archSuffix exactly.
	const arch = if (@import("platform").darwin) "aarch64-darwin" else @tagName(builtin_mod.cpu.arch);

	// The package whose launcher will boot this runner, which picks the config the
	// runner is built from (nix.configSuffixFor) AND keys the record below, so the
	// two can never disagree. A package that does not re-exec has no config to
	// build: skip rather than guess (the boot evaluates).
	const reexec_package = reexecPackage(ctx);
	if (nix.configSuffixFor(reexec_package) == null) {
		warn(ctx, "runner push: unknown COGBOX_REEXEC_PACKAGE '{s}'; skipping pre-build (boot will rebuild)", .{reexec_package}) catch {};
		return .failed;
	}

	// The comp of the composition bytes this build reads (runner.path line 3),
	// taken right before the build and checked again before the record is
	// written. The dispatcher's config lock keeps them stable; the re-check makes
	// the record's line 3 provably the comp of what was built.
	const comp_before = snapshot.compOfDir(ctx.io, ctx.plugins_flake_dir);

	// Combine the per-instance file:// cache with cogworx's remote substituters
	// so the runner's transitive deps substitute rather than build from source.
	const extra_subs = env.get("COGBOX_EXTRA_SUBSTITUTERS") orelse "";
	const substituters = blk: {
		if (extra_subs.len == 0) break :blk std.fmt.allocPrint(allocator, "file://{s}", .{ctx.cache_dir}) catch return .failed;
		break :blk std.fmt.allocPrint(allocator, "file://{s} {s}", .{ ctx.cache_dir, extra_subs }) catch return .failed;
	};
	defer allocator.free(substituters);

	const out = nix.buildRunner(allocator, ctx.io, env, .{
		.flake_source = flake_source,
		.nixpkgs_source = nixpkgs_source,
		.plugins_flake_dir = ctx.plugins_flake_dir,
		.arch = arch,
		.substituters = substituters,
		.trusted_public_keys = env.get("COGBOX_EXTRA_TRUSTED_PUBLIC_KEYS") orelse "",
		.netrc_file = env.get("COGBOX_NETRC_FILE") orelse "",
		.reexec_package = reexec_package,
	}) catch {
		warn(ctx, "runner push: build failed to launch (boot will rebuild)", .{}) catch {};
		return .failed;
	};
	var o = out;
	defer o.deinit(allocator);
	if (!o.ok) {
		warn(ctx, "runner push: build failed (boot will rebuild): {s}", .{nix.stderrTail(o.stderr)}) catch {};
		return .failed;
	}
	// --print-out-paths emits the store path(s), one per line; take the first.
	const out_path = std.mem.trim(u8, o.stdout, " \t\r\n");
	const first = if (std.mem.indexOfScalar(u8, out_path, '\n')) |i| out_path[0..i] else out_path;
	if (first.len == 0) {
		warn(ctx, "runner push: build produced no out-path (boot will rebuild)", .{}) catch {};
		return .failed;
	}

	const pushed = pushToCache(ctx, push_config, first);

	// Pre-write the launcher's skip-eval fast-path record so a FRESH instance's
	// FIRST boot fast-paths instead of paying the ~18min --override-input eval.
	// Normally that record ($INSTANCE_CONFIG_DIR/runner.path) is written only by
	// a prior eval boot (cogbox-launch.sh); a brand-new instance would have to
	// eval once. Since we already built the composed runner and pushed it here,
	// record it now so the very first boot realises it from the cache (a fetch,
	// no eval). We ONLY record after a successful push: on a new instance the
	// persistent /nix is empty, so the launcher's fast path runs
	// `nix-store --realise` to fetch the recorded runner from the cache -- a
	// record pointing at a closure that never made it into the cache would make
	// that realise fail (the launcher then falls back to eval, so it's still
	// safe, but recording it would be pointless). The key we write is
	// "<flake_source>#<reexec package>", which equals the launcher's baked
	// @flakeSource@#@reexecPackage@ (both the worker pod and the sandbox launcher
	// run the SAME cogbox image, so the same COGBOX_FLAKE_SOURCE and
	// COGBOX_REEXEC_PACKAGE) -- the key therefore matches, and the record
	// self-heals across image bumps and across a different composed package alike
	// (either one fails the launcher's `[ "$FP_REV" = "$RUNNER_KEY" ]` guard and
	// re-evals). See writeRunnerRecord for why the package attribute is in there.
	// Line 3 is the comp of the composition it was built from; the launcher's
	// fast path requires it to equal the comp of the bytes it is about to boot.
	if (pushed) switch (prebuiltRecordComp(ctx, comp_before)) {
		.comp => |comp| writeRunnerRecord(ctx, flake_source, first, &comp),
		.no_comp => warn(ctx, "runner push: could not hash the composition; not recording the runner (boot will eval)", .{}) catch {},
		.changed => warn(ctx, "runner push: the composition changed during the pre-build; not recording the runner (boot will eval)", .{}) catch {},
	};
	// The composed runner BUILT from the live lock, which is all the launcher's
	// pre-exec confirmation would prove (the push is only a cache optimization).
	return .ok;
}

/// Resolve the node-shared CoW base store a container pre-build can substitute the
/// BASE closure from over LOCAL DISK instead of the shared cache (the base-store substitution). COGBOX_BASE_STORE_ROOT names a dir cogworx mounts
/// the frozen agent-image lower into at `<root>/nix`, so `<root>/nix/store` is the
/// store and `<root>/nix/var/nix/db` its chroot-store DB. Returns the root ONLY when
/// that DB is present -- an absent/unseeded lower (fresh node, image never ran here,
/// or the DirectoryOrCreate hostPath made an EMPTY dir) is a cache MISS: return null
/// so the build falls back to the shared-cache substituter, never fails. cogworx sets
/// the env only under CoW mode.
fn baseStoreRoot(ctx: *const Ctx) ?[]const u8 {
	const root = ctx.parent_env.get("COGBOX_BASE_STORE_ROOT") orelse return null;
	if (root.len == 0) return null;
	const cwd = std.Io.Dir.cwd();
	// A real local store carries a nix DB; the db dir (or its db.sqlite) present =>
	// a seeded lower we can substitute from. Either signal is enough.
	inline for (.{ "nix/var/nix/db", "nix/var/nix/db/db.sqlite" }) |rel| {
		const p = std.fs.path.join(ctx.allocator, &.{ root, rel }) catch return null;
		defer ctx.allocator.free(p);
		if (cwd.access(ctx.io, p, .{})) |_| return root else |_| {}
	}
	return null;
}

/// Assemble the `--extra-substituters` string a container pre-build passes to nix:
/// the per-instance file:// plugin-cache, any COGBOX_EXTRA_SUBSTITUTERS shared cache,
/// and -- when a node-shared CoW base store is mounted (base_root non-null, the base-store substitution) --
/// that local store FIRST (`local?root=<r>&read-only=true`) so the BASE closure comes
/// off local disk ahead of the network. Caller owns the result (allocator.free); null
/// on OOM (the caller aborts the pre-build, best-effort, so boot rebuilds).
fn buildSubstituters(allocator: std.mem.Allocator, cache_dir: []const u8, extra_subs: []const u8, base_root: ?[]const u8) ?[]const u8 {
	const base = base_root orelse "";
	if (base.len > 0 and extra_subs.len > 0)
		return std.fmt.allocPrint(allocator, "local?root={s}&read-only=true file://{s} {s}", .{ base, cache_dir, extra_subs }) catch null;
	if (base.len > 0)
		return std.fmt.allocPrint(allocator, "local?root={s}&read-only=true file://{s}", .{ base, cache_dir }) catch null;
	if (extra_subs.len > 0)
		return std.fmt.allocPrint(allocator, "file://{s} {s}", .{ cache_dir, extra_subs }) catch null;
	return std.fmt.allocPrint(allocator, "file://{s}", .{cache_dir}) catch null;
}

/// The container backend's local brain pre-build (the offline-boot counterpart
/// of prebuildAndPushRunner). Runs only when cogworx's container backend requests
/// it: COGBOX_BRAIN_PUSH_LOCAL == "1". Unlike the VM path there is NO remote push
/// and NO runner.path record -- the container's cogbox-brain-materialize always
/// evaluates then substitutes. It builds the SAME cogbox-brain out-path the
/// container boot evaluates (identical flake ref + --override-input set; the brain
/// now carries the plugins' cogbox.packages as $out/bin), then `nix copy`s that
/// out-path's closure into the LOCAL per-instance plugin-cache (file://cache_dir,
/// on the state PVC). The agent's boot has no egress, so without this seed the
/// brain rebuild cannot realise the plugin tools; with it, boot substitutes the
/// whole closure offline. Every failure is logged and swallowed; a boot that
/// then cannot build the brain falls back to the plugin-less base brain (no
/// plugin skills, agents, commands, rules or tools, and the materializer also
/// removes links left by earlier boots; see brain.fallback). Determinism
/// mirrors the runner path: nothing
/// instance-specific is in the brain closure, so the pre-built out-path is
/// byte-identical to the one boot's brainResolveContainer evaluates.
fn prebuildBrainLocal(ctx: *const Ctx) Prebuild {
	const allocator = ctx.allocator;
	const env = ctx.parent_env;

	const local = env.get("COGBOX_BRAIN_PUSH_LOCAL") orelse return .skipped;
	if (!std.mem.eql(u8, local, "1")) return .skipped;

	// The cogbox flake + nixpkgs store paths, baked by mkCogbox (--set-default)
	// into the same cogbox image the container boot evaluates against.
	const flake_source = env.get("COGBOX_FLAKE_SOURCE") orelse {
		warn(ctx, "brain prebuild: COGBOX_FLAKE_SOURCE unset; skipping (boot rebuilds)", .{}) catch {};
		return .failed;
	};
	const nixpkgs_source = env.get("COGBOX_NIXPKGS_SOURCE") orelse {
		warn(ctx, "brain prebuild: COGBOX_NIXPKGS_SOURCE unset; skipping (boot rebuilds)", .{}) catch {};
		return .failed;
	};

	// cogbox-x86_64 / cogbox-aarch64: the config-name suffix (compile-time arch,
	// matching flake.nix's archSuffix), same derivation as the runner path.
	const arch = @tagName(builtin_mod.cpu.arch);

	// Combine the per-instance file:// cache with any remote substituters so the
	// brain's transitive nixpkgs deps (e.g. the plugin tools' closure) substitute
	// rather than build from source at add-time. the base-store substitution:
	// when cogworx RO-mounted the node-shared CoW lower (COGBOX_BASE_STORE_ROOT,
	// CoW mode), prefer it for base paths over local disk; absent/unseeded =>
	// null => today's shared-cache-only path (a cache miss, never a failure).
	const base_root = baseStoreRoot(ctx);
	const extra_subs = env.get("COGBOX_EXTRA_SUBSTITUTERS") orelse "";
	const substituters = buildSubstituters(allocator, ctx.cache_dir, extra_subs, base_root) orelse return .failed;
	defer allocator.free(substituters);

	const out = nix.buildBrain(allocator, ctx.io, env, .{
		.flake_source = flake_source,
		.nixpkgs_source = nixpkgs_source,
		.plugins_flake_dir = ctx.plugins_flake_dir,
		.arch = arch,
		.substituters = substituters,
		.trusted_public_keys = env.get("COGBOX_EXTRA_TRUSTED_PUBLIC_KEYS") orelse "",
		.netrc_file = env.get("COGBOX_NETRC_FILE") orelse "",
		.base_store_root = base_root orelse "",
	}) catch {
		warn(ctx, "brain prebuild: build failed to launch (boot rebuilds)", .{}) catch {};
		return .failed;
	};
	var o = out;
	defer o.deinit(allocator);
	if (!o.ok) {
		warn(ctx, "brain prebuild: build failed (boot rebuilds): {s}", .{nix.stderrTail(o.stderr)}) catch {};
		return .failed;
	}
	// --print-out-paths emits the store path(s), one per line; take the first.
	const out_path = std.mem.trim(u8, o.stdout, " \t\r\n");
	const first = if (std.mem.indexOfScalar(u8, out_path, '\n')) |i| out_path[0..i] else out_path;
	if (first.len == 0) {
		warn(ctx, "brain prebuild: build produced no out-path (boot rebuilds)", .{}) catch {};
		return .failed;
	}

	// Seed the per-instance plugin-cache with the realized closure so boot
	// substitutes it (require-sigs false on the read side -- flake.nix
	// brainResolveContainer). Local file:// dest, no signing/push config needed.
	// compression=zstd: nix's file:// default is xz, which is pathologically slow
	// single-threaded -- on a 1-vCPU sandbox it compresses a multi-GB tool closure
	// (e.g. a headless-browser bundle) at well under 1 MB/s and blows the plugin
	// install deadline, failing the add. zstd is ~20-50x faster for a small ratio
	// cost, and the boot reads the compression from each narinfo, so the read side
	// needs no change. (A local single-node cache read once at boot; none/zstd both
	// fine -- zstd keeps the PVC footprint down.)
	const cache_url = std.fmt.allocPrint(allocator, "file://{s}?compression=zstd", .{ctx.cache_dir}) catch return .failed;
	defer allocator.free(cache_url);
	if (nix.copyClosureTo(allocator, ctx.io, env, cache_url, first)) |cp| {
		var c = cp;
		defer c.deinit(allocator);
		if (!c.ok) {
			warn(ctx, "brain prebuild: copy to plugin-cache failed (boot rebuilds): {s}", .{nix.stderrTail(c.stderr)}) catch {};
			return .failed;
		}
		return .ok;
	} else |_| {
		warn(ctx, "brain prebuild: copy to plugin-cache failed to launch (boot rebuilds)", .{}) catch {};
		return .failed;
	}
}

/// The container backend's per-instance FULL-TOPLEVEL pre-build. Runs when the container
/// backend requests it: COGBOX_TOPLEVEL_PUSH_LOCAL == "1". It builds the SAME
/// config.system.build.toplevel out-path agentInit realises and boots as PID1 -- the base
/// container system with the plugin's WHOLE NixOS module folded in (environment.systemPackages,
/// services, environment.etc, ...) -- copies its closure into the LOCAL per-instance
/// plugin-cache (so the egress-less boot substitutes it offline), and records the out-path
/// in `toplevel.path` (image-rev marker + out-path) so agentInit boots it instead of the
/// baked plugin-less base. Unlike the brain (which the boot always re-evaluates), the
/// toplevel MUST be recorded: agentInit reads the record before systemd to decide which
/// toplevel's /init to exec. Best-effort throughout: any failure leaves no/stale record, so
/// agentInit falls back to the baked base toplevel and the sandbox always boots (the plugin's
/// tools still reach PATH via the cogbox.packages brain path; only the non-package module
/// surface waits for a successful toplevel prebuild). Determinism mirrors the brain/runner:
/// nothing instance-specific is in the toplevel closure, so the pre-built out-path is
/// byte-identical to the one agentInit would derive. v1 copies the WHOLE closure (base
/// included); a delta-vs-baked-base copy is a follow-up space/latency optimization.
fn prebuildToplevelLocal(ctx: *const Ctx) Prebuild {
	const env = ctx.parent_env;
	const local = env.get("COGBOX_TOPLEVEL_PUSH_LOCAL") orelse return .skipped;
	if (!std.mem.eql(u8, local, "1")) return .skipped;
	return if (doToplevelBuild(ctx)) .ok else .failed;
}

/// the delta-only copy: write narinfo STUBS for the node CoW base
/// closure into the per-instance plugin-cache so the toplevel copyClosureTo skips the
/// ~2.3 GB base and copies only the plugin DELTA to the state PVC. Each stub carries the
/// real narHash/narSize/references (from the lower's nix DB via `nix path-info`, so NO NAR
/// I/O) but a DANGLING NAR URL -- harmless because the egress-less boot realises the base
/// from its OWN CoW lower, never from the cache. Best-effort: any failure just leaves the
/// base to be copied whole (correct, slower). `base_root` is the validated (db-present)
/// CoW lower root, same one the base-store substitution substitutes from.
fn seedBaseNarinfos(ctx: *const Ctx, base_root: []const u8) void {
	const allocator = ctx.allocator;
	const info = nix.basePathInfoJson(allocator, ctx.io, ctx.parent_env, base_root) catch {
		warn(ctx, "toplevel build: base path-info failed to launch (copying whole closure)", .{}) catch {};
		return;
	};
	var o = info;
	defer o.deinit(allocator);
	if (!o.ok) {
		warn(ctx, "toplevel build: base path-info failed (copying whole closure): {s}", .{nix.stderrTail(o.stderr)}) catch {};
		return;
	}
	const parsed = std.json.parseFromSlice(std.json.Value, allocator, o.stdout, .{}) catch {
		warn(ctx, "toplevel build: base path-info JSON unparseable (copying whole closure)", .{}) catch {};
		return;
	};
	defer parsed.deinit();
	if (parsed.value != .object) return;

	// Ensure the plugin-cache dir exists (the brain prebuild usually created it, but do not
	// depend on that): createDirPathOpen is a no-op if present.
	{
		var d = std.Io.Dir.cwd().createDirPathOpen(ctx.io, ctx.cache_dir, .{}) catch return;
		d.close(ctx.io);
	}
	const cwd = std.Io.Dir.cwd();

	var count: usize = 0;
	var it = parsed.value.object.iterator();
	while (it.next()) |entry| {
		const path = entry.key_ptr.*;
		const v = entry.value_ptr.*;
		if (v != .object) continue;
		const nh = v.object.get("narHash") orelse continue;
		const ns = v.object.get("narSize") orelse continue;
		if (nh != .string or ns != .integer) continue;
		const base = std.fs.path.basename(path);
		if (base.len < 32) continue;
		const hash = base[0..32];

		// References -> space-joined basenames (the on-disk narinfo form).
		var refs: std.ArrayList(u8) = .empty;
		defer refs.deinit(allocator);
		if (v.object.get("references")) |rv| {
			if (rv == .array) {
				for (rv.array.items, 0..) |rp, i| {
					if (rp != .string) continue;
					if (i != 0) refs.append(allocator, ' ') catch {};
					refs.appendSlice(allocator, std.fs.path.basename(rp.string)) catch {};
				}
			}
		}

		// Dangling URL + Compression: none -- never fetched (boot has the base locally).
		const narinfo = std.fmt.allocPrint(allocator, "StorePath: {s}\nURL: nar/base-{s}.nar\nCompression: none\nNarHash: {s}\nNarSize: {d}\nReferences: {s}\n", .{ path, hash, nh.string, ns.integer, refs.items }) catch continue;
		defer allocator.free(narinfo);
		const fname = std.fmt.allocPrint(allocator, "{s}/{s}.narinfo", .{ ctx.cache_dir, hash }) catch continue;
		defer allocator.free(fname);

		const f = cwd.createFile(ctx.io, fname, .{ .truncate = true }) catch continue;
		defer f.close(ctx.io);
		var wbuf: [512]u8 = undefined;
		var w = f.writer(ctx.io, &wbuf);
		w.interface.writeAll(narinfo) catch continue;
		w.flush() catch continue;
		count += 1;
	}
	warn(ctx, "toplevel build: seeded {d} base narinfo stubs into the plugin-cache (delta copy)", .{count}) catch {};
}

/// Build the per-instance CONTAINER toplevel (the plugin's whole module folded in), seed its
/// closure into the plugin-cache, and write the toplevel.path record agentInit boots from.
/// Returns true iff the record was written. Best-effort; every failure warns + returns false.
/// Shared by the plugin-add gate (prebuildToplevelLocal, running-agent only) and the boot
/// reconcile (cmdReconcile, which covers stopped/fresh adds). Determinism: nothing
/// instance-specific is in the toplevel closure, so the out-path is byte-identical to the one
/// agentInit derives. the delta-only copy (seedBaseNarinfos) trims the copy to the plugin delta when the
/// node CoW base store is mounted; otherwise the whole closure is copied.
fn doToplevelBuild(ctx: *const Ctx) bool {
	const allocator = ctx.allocator;
	const env = ctx.parent_env;

	const flake_source = env.get("COGBOX_FLAKE_SOURCE") orelse {
		warn(ctx, "toplevel build: COGBOX_FLAKE_SOURCE unset; skipping (boot uses baked base)", .{}) catch {};
		return false;
	};
	const nixpkgs_source = env.get("COGBOX_NIXPKGS_SOURCE") orelse {
		warn(ctx, "toplevel build: COGBOX_NIXPKGS_SOURCE unset; skipping (boot uses baked base)", .{}) catch {};
		return false;
	};
	const arch = @tagName(builtin_mod.cpu.arch);

	// the base-store substitution: the transient stopped-add worker's /nix
	// is COLD for the base, so substitute the container-toplevel BASE closure from the
	// node-shared CoW lower (COGBOX_BASE_STORE_ROOT, RO-mounted by cogworx under cow)
	// over LOCAL DISK instead of the shared cache. Absent/unseeded => null => today's
	// shared-cache-only path (a cache miss, never a failure).
	const base_root = baseStoreRoot(ctx);
	const extra_subs = env.get("COGBOX_EXTRA_SUBSTITUTERS") orelse "";
	const substituters = buildSubstituters(allocator, ctx.cache_dir, extra_subs, base_root) orelse return false;
	defer allocator.free(substituters);

	// nix --max-jobs for the toplevel build. cogworx sets COGBOX_WORKER_BUILD_JOBS ONLY
	// on a transient worker pod sized with extra cores (never the live agent), so a
	// parallel build can't OOM a running sandbox. Parse defensively: absent, unparseable,
	// or <1 => "" => nix.zig keeps its hardcoded -j1 guard. Clamp against garbage (the
	// worker is operator-sized, so a high ceiling is fine). Owned through buildToplevel.
	const build_jobs: []const u8 = blk: {
		const raw = env.get("COGBOX_WORKER_BUILD_JOBS") orelse break :blk "";
		const n = std.fmt.parseInt(usize, std.mem.trim(u8, raw, " \t\r\n"), 10) catch break :blk "";
		if (n < 1) break :blk "";
		const clamped = @min(n, 64);
		break :blk std.fmt.allocPrint(allocator, "{d}", .{clamped}) catch break :blk "";
	};
	defer if (build_jobs.len > 0) allocator.free(build_jobs);

	const out = nix.buildToplevel(allocator, ctx.io, env, .{
		.flake_source = flake_source,
		.nixpkgs_source = nixpkgs_source,
		.plugins_flake_dir = ctx.plugins_flake_dir,
		.arch = arch,
		.substituters = substituters,
		.trusted_public_keys = env.get("COGBOX_EXTRA_TRUSTED_PUBLIC_KEYS") orelse "",
		.netrc_file = env.get("COGBOX_NETRC_FILE") orelse "",
		.base_store_root = base_root orelse "",
		.build_jobs = build_jobs,
	}) catch {
		warn(ctx, "toplevel build: failed to launch (boot uses baked base)", .{}) catch {};
		return false;
	};
	var o = out;
	defer o.deinit(allocator);
	if (!o.ok) {
		warn(ctx, "toplevel build: failed (boot uses baked base): {s}", .{nix.stderrTail(o.stderr)}) catch {};
		return false;
	}
	const out_path = std.mem.trim(u8, o.stdout, " \t\r\n");
	const first = if (std.mem.indexOfScalar(u8, out_path, '\n')) |i| out_path[0..i] else out_path;
	if (first.len == 0) {
		warn(ctx, "toplevel build: produced no out-path (boot uses baked base)", .{}) catch {};
		return false;
	}

	// the delta-only copy: when the node CoW base store is mounted
	// (base_root non-null -- the same warm-node condition as the base-store substitution), pre-seed narinfo
	// STUBS for the base closure into the plugin-cache so the copyClosureTo below skips the
	// ~2.3 GB base and writes only the plugin DELTA to the state PVC (the boot reads the base
	// from its own CoW lower, never from the cache). Best-effort: on any failure the whole
	// closure is copied (correct, just slower).
	if (base_root) |br| seedBaseNarinfos(ctx, br);

	// Seed the per-instance plugin-cache with the toplevel closure so the egress-less boot
	// substitutes it (zstd; require-sigs false on the read side -- agentInit).
	const cache_url = std.fmt.allocPrint(allocator, "file://{s}?compression=zstd", .{ctx.cache_dir}) catch return false;
	defer allocator.free(cache_url);
	const copied = blk: {
		if (nix.copyClosureTo(allocator, ctx.io, env, cache_url, first)) |cp| {
			var c = cp;
			defer c.deinit(allocator);
			if (!c.ok) {
				warn(ctx, "toplevel build: copy to plugin-cache failed (boot uses baked base): {s}", .{nix.stderrTail(c.stderr)}) catch {};
				break :blk false;
			}
			break :blk true;
		} else |_| {
			warn(ctx, "toplevel build: copy to plugin-cache failed to launch (boot uses baked base)", .{}) catch {};
			break :blk false;
		}
	};

	// Record ONLY after a successful copy: agentInit realises the recorded out-path offline
	// from the cache, so a record pointing at an un-cached path would fall back to base anyway.
	// The rev marker (flake_source == the baked ${self} agentInit compares against) self-heals
	// across image bumps; the comphash (composition flake.lock hash) is the reconcile guard.
	if (!copied) return false;
	writeToplevelRecord(ctx, flake_source, first, compositionHash(ctx));
	return true;
}

/// The container boot reconcile (`cogbox plugin reconcile`, run by the cogbox-toplevel-reconcile
/// oneshot post-boot when egress is up). It builds + records the per-instance toplevel from the
/// ALREADY-materialized composition -- so a stopped/fresh add (which only ran the cheap brain
/// prebuild in the worker, not the toplevel one) is picked up on the NEXT boot -- and self-heals
/// after an image bump. Runs in the live agent pod, whose store has the base, so the build is the
/// fast delta path (same as the running-agent add). No-op fast paths: (a) no plugins -> remove any
/// stale record so boot reverts to the baked base; (b) the recorded toplevel is already current
/// (rev marker + composition hash unchanged) -> skip the expensive rebuild. Best-effort.
fn cmdReconcile(ctx: *Ctx, loaded: *config.Loaded) !void {
	const arr = mutate.existingPluginsArray(loaded.root());
	if (arr == null or arr.?.items.len == 0) {
		// No plugins: drop any stale toplevel record so agentInit boots the baked base.
		removeToplevelRecord(ctx);
		return;
	}
	// Skip when the recorded toplevel is already current for this (image rev, composition).
	// Either way a current toplevel (whose closure carries this lock's brain) confirms
	// the live composition lock, so the unconfirmed-re-pin snapshot is dropped.
	if (toplevelRecordCurrent(ctx) or doToplevelBuild(ctx)) clearPrevLock(ctx);
}

/// Hash of the composition identity: the plugins-flake flake.lock, which pins the plugin set
/// AND each plugin source's narHash, so it changes on any add/del/update. The reconcile guard
/// compares it against the record's stored hash to skip an unchanged rebuild. Null when the
/// lock is unreadable (treated as "changed" -> rebuild, which is safe).
fn compositionHash(ctx: *const Ctx) ?u64 {
	const data = readCompositionLock(ctx) orelse return null;
	defer ctx.allocator.free(data);
	return std.hash.Wyhash.hash(0, data);
}

/// The composition flake.lock bytes (caller frees), or null when unreadable.
fn readCompositionLock(ctx: *const Ctx) ?[]u8 {
	return readCompositionFile(ctx, "flake.lock");
}

/// Read <plugins_flake_dir>/<name> (4 MiB cap; caller frees), or null.
fn readCompositionFile(ctx: *const Ctx, name: []const u8) ?[]u8 {
	const allocator = ctx.allocator;
	const path = std.fs.path.join(allocator, &.{ ctx.plugins_flake_dir, name }) catch return null;
	defer allocator.free(path);
	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(ctx.io, path, .{}) catch return null;
	defer file.close(ctx.io);
	var buf: [4096]u8 = undefined;
	var reader = file.reader(ctx.io, &buf);
	return reader.interface.allocRemaining(allocator, .limited(4 << 20)) catch return null;
}

/// True iff the toplevel record is current (toplevelRecordCurrent) AND the
/// narinfo for its recorded out-path (line 2) exists in the plugin-cache --
/// i.e. the closure the record names is actually seeded for the boot to
/// substitute. Any read failure returns false (-> the prebuild runs).
fn toplevelSeeded(ctx: *const Ctx) bool {
	if (!toplevelRecordCurrent(ctx)) return false;
	const allocator = ctx.allocator;
	const instance_config_dir = std.fs.path.dirname(ctx.plugins_flake_dir) orelse return false;
	const path = std.fs.path.join(allocator, &.{ instance_config_dir, "toplevel.path" }) catch return false;
	defer allocator.free(path);
	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(ctx.io, path, .{}) catch return false;
	defer file.close(ctx.io);
	var buf: [1024]u8 = undefined;
	var reader = file.reader(ctx.io, &buf);
	const data = reader.interface.allocRemaining(allocator, .limited(64 << 10)) catch return false;
	defer allocator.free(data);

	var lines = std.mem.splitScalar(u8, data, '\n');
	_ = lines.next() orelse return false; // rev (line 1)
	const out = lines.next() orelse return false; // out-path (line 2)
	var name_buf: [64]u8 = undefined;
	const fname = narinfoName(&name_buf, out) orelse return false;
	const narinfo = std.fs.path.join(allocator, &.{ ctx.cache_dir, fname }) catch return false;
	defer allocator.free(narinfo);
	cwd.access(ctx.io, narinfo, .{}) catch return false;
	return true;
}

/// "<hash32>.narinfo" for a store out-path (surrounding whitespace trimmed),
/// written into `buf` -- the same naming seedBaseNarinfos and nix's file://
/// cache use. Null when the basename is shorter than the 32-char hash.
fn narinfoName(buf: []u8, out_path: []const u8) ?[]const u8 {
	const trimmed = std.mem.trim(u8, out_path, " \t\r\n");
	const base = std.fs.path.basename(trimmed);
	if (base.len < 32) return null;
	return std.fmt.bufPrint(buf, "{s}.narinfo", .{base[0..32]}) catch null;
}

/// True iff toplevel.path exists AND line1 == COGBOX_FLAKE_SOURCE (image rev current) AND
/// line3 == the current compositionHash (nothing added/removed/updated since it was built).
/// Any read failure / mismatch / absent hash returns false (-> rebuild), which is safe.
fn toplevelRecordCurrent(ctx: *const Ctx) bool {
	const allocator = ctx.allocator;
	const env = ctx.parent_env;
	const flake_source = env.get("COGBOX_FLAKE_SOURCE") orelse return false;
	const cur = compositionHash(ctx) orelse return false;

	const instance_config_dir = std.fs.path.dirname(ctx.plugins_flake_dir) orelse return false;
	const path = std.fs.path.join(allocator, &.{ instance_config_dir, "toplevel.path" }) catch return false;
	defer allocator.free(path);
	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(ctx.io, path, .{}) catch return false;
	defer file.close(ctx.io);
	var buf: [1024]u8 = undefined;
	var reader = file.reader(ctx.io, &buf);
	const data = reader.interface.allocRemaining(allocator, .limited(64 << 10)) catch return false;
	defer allocator.free(data);

	var lines = std.mem.splitScalar(u8, data, '\n');
	const rev = lines.next() orelse return false;
	_ = lines.next() orelse return false; // out-path (line 2)
	const rec_hash = lines.next() orelse return false; // comphash (line 3)
	if (!std.mem.eql(u8, std.mem.trim(u8, rev, " \t\r"), flake_source)) return false;

	var hex: [16]u8 = undefined;
	const cur_hex = std.fmt.bufPrint(&hex, "{x}", .{cur}) catch return false;
	return std.mem.eql(u8, std.mem.trim(u8, rec_hash, " \t\r"), cur_hex);
}

/// Remove the launcher's runner.path fast-path record. Called from
/// regenComposition, i.e. on every plugin mutation, because the record names a
/// runner composed from the PREVIOUS plugin set and nothing else in it changes
/// when that set does. Best-effort: the record is an optimization, so a delete
/// that fails costs at worst nothing, and a delete that succeeds costs at worst
/// one eval boot.
pub fn removeRunnerRecord(ctx: *const Ctx) void {
	const allocator = ctx.allocator;
	const instance_config_dir = std.fs.path.dirname(ctx.plugins_flake_dir) orelse return;
	const p = std.fs.path.join(allocator, &.{ instance_config_dir, "runner.path" }) catch return;
	defer allocator.free(p);
	std.Io.Dir.cwd().deleteFile(ctx.io, p) catch {};
	// The launcher's snapshot marker vouches for the record just removed.
	clearPrevBootMarker(ctx);
	clearRepinFailed(ctx);
}

/// Drop <instance_config_dir>/composition.repin.failed: cogbox-launch.sh records
/// there the plugin content whose boot re-pin failed its confirmation build, and
/// skips re-pinning exactly that content on later launches (so `cogbox start`'s
/// two launcher passes and every boot do not repeat one failing full eval). Any
/// op changes the composition, so its verdict no longer holds and the next boot
/// must retry. Best-effort: a stale file only keeps already-failed content at its
/// previous pin until the next op, never pins anything.
pub fn clearRepinFailed(ctx: *const Ctx) void {
	const instance_config_dir = std.fs.path.dirname(ctx.plugins_flake_dir) orelse return;
	const path = std.fs.path.join(ctx.allocator, &.{ instance_config_dir, "composition.repin.failed" }) catch return;
	defer ctx.allocator.free(path);
	std.Io.Dir.cwd().deleteFile(ctx.io, path) catch {};
}

/// Remove the toplevel record (+ its crash-loop attempt marker) so agentInit boots the baked
/// base. Called by the reconcile when an instance has no plugins (all removed). Best-effort.
fn removeToplevelRecord(ctx: *const Ctx) void {
	const allocator = ctx.allocator;
	const instance_config_dir = std.fs.path.dirname(ctx.plugins_flake_dir) orelse return;
	const cwd = std.Io.Dir.cwd();
	const names = [_][]const u8{ "toplevel.path", "toplevel.attempt" };
	for (names) |name| {
		const p = std.fs.path.join(allocator, &.{ instance_config_dir, name }) catch continue;
		defer allocator.free(p);
		cwd.deleteFile(ctx.io, p) catch {};
	}
}

/// The flake package attribute this cogbox re-execs through
/// (COGBOX_REEXEC_PACKAGE, baked next to COGBOX_FLAKE_SOURCE by mkCogboxAttr).
/// Absent (an unwrapped binary, or an image predating it) it means the default
/// package, "cogbox".
pub fn reexecPackage(ctx: *const Ctx) []const u8 {
	return ctx.parent_env.get("COGBOX_REEXEC_PACKAGE") orelse "cogbox";
}

/// Whether a pre-built runner may be recorded for the launcher's fast path, and
/// with which line 3: only when the composition still has the comp
/// `comp_before` it had right before the build, so line 3 names exactly the
/// bytes the runner was built from. A composition that cannot be hashed, or
/// that changed during the build, gets no record (the boot evaluates, which is
/// always correct).
const PrebuiltRecord = union(enum) { comp: snapshot.Comp, no_comp, changed };

fn prebuiltRecordComp(ctx: *const Ctx, comp_before: ?snapshot.Comp) PrebuiltRecord {
	const before = comp_before orelse return .no_comp;
	const after = snapshot.compOfDir(ctx.io, ctx.plugins_flake_dir) orelse return .no_comp;
	if (!std.mem.eql(u8, &before, &after)) return .changed;
	return .{ .comp = after };
}

/// Best-effort pre-write of cogbox-launch.sh's runner.path fast-path record.
/// The file lives at <instance_config_dir>/runner.path on the shared state PVC
/// (the worker pod mounts it at the SAME XDG_CONFIG_HOME the sandbox launcher
/// does), where instance_config_dir = dirname(plugins_flake_dir). Contents must
/// byte-match what the launcher writes/reads:
/// `printf '%s\n%s\n%s\n' <key> <runner> <comp>` -- three newline-terminated
/// lines, line1 = the record KEY, line2 = the composed runner out-path, line3 =
/// the comp (snapshot.compOfBytes) of the composition the runner was built from.
/// The fast path requires line 3 to equal the comp of the bytes it boots, so a
/// record can never vouch for a runner built from a different composition; a
/// launcher older than line 3 reads only lines 1-2 and is unaffected. Written
/// atomically (tmp + rename) so a partial write can't leave a half-record the
/// launcher would misread; any failure is warned and swallowed (a
/// missing/short record just makes the first boot fall back to eval, never a
/// failed verb).
///
/// The key is "<flakeSource>#<reexecPackage>", not the flakeSource alone. One
/// flake source builds SEVERAL cogbox packages whose composed runners differ
/// (cogbox vs cogbox-hosted), and their @flakeSource@ is byte-identical, so a
/// rev-only key let a record written for one validate for the other -- the
/// launcher would then realize a runner built for a different guest storage
/// layout and skip the re-exec that would have rebuilt it. The key comes from
/// reexecPackage, and prebuildAndPushRunner builds its runner from that same
/// package's config (nix.configSuffixFor), so the record and the runner it
/// names always agree on the package. Spelling the key differently from the
/// launcher is not dangerous -- the launcher simply rejects the record and
/// evals -- but it silently costs a fresh instance the entire point of this
/// pre-write, so the two must move together.
fn writeRunnerRecord(ctx: *const Ctx, flake_source: []const u8, runner: []const u8, comp: []const u8) void {
	_ = tryWriteRunnerRecord(ctx, flake_source, runner, comp);
}

/// writeRunnerRecord that also says whether the record was written (the live
/// apply's rollback treats a failed write as a failed restore step). Warns on
/// failure exactly as writeRunnerRecord does.
pub fn tryWriteRunnerRecord(ctx: *const Ctx, flake_source: []const u8, runner: []const u8, comp: []const u8) bool {
	const allocator = ctx.allocator;
	const cwd = std.Io.Dir.cwd();
	const reexec_package = reexecPackage(ctx);

	const instance_config_dir = std.fs.path.dirname(ctx.plugins_flake_dir) orelse {
		warn(ctx, "runner push: plugins-flake dir has no parent; skipping record (boot will eval)", .{}) catch {};
		return false;
	};
	const path = std.fs.path.join(allocator, &.{ instance_config_dir, "runner.path" }) catch return false;
	defer allocator.free(path);
	const tmp_path = std.fmt.allocPrint(allocator, "{s}.tmp", .{path}) catch return false;
	defer allocator.free(tmp_path);

	const contents = std.fmt.allocPrint(allocator, "{s}#{s}\n{s}\n{s}\n", .{ flake_source, reexec_package, runner, comp }) catch return false;
	defer allocator.free(contents);

	{
		const f = cwd.createFile(ctx.io, tmp_path, .{ .truncate = true }) catch {
			warn(ctx, "runner push: could not write runner record (boot will eval)", .{}) catch {};
			return false;
		};
		defer f.close(ctx.io);
		var write_buf: [512]u8 = undefined;
		var writer = f.writer(ctx.io, &write_buf);
		writer.interface.writeAll(contents) catch {
			warn(ctx, "runner push: could not write runner record (boot will eval)", .{}) catch {};
			return false;
		};
		writer.flush() catch {
			warn(ctx, "runner push: could not write runner record (boot will eval)", .{}) catch {};
			return false;
		};
		f.sync(ctx.io) catch {};
	}
	cwd.rename(tmp_path, cwd, path, ctx.io) catch {
		cwd.deleteFile(ctx.io, tmp_path) catch {};
		warn(ctx, "runner push: could not finalize runner record (boot will eval)", .{}) catch {};
		return false;
	};
	return true;
}

/// Best-effort atomic write of agentInit's `toplevel.path` fast-path record: three
/// newline-terminated lines, line1 = the image-rev marker (flake_source == the baked ${self}
/// agentInit compares against), line2 = the per-instance toplevel out-path, line3 = the
/// composition hash (compositionHash; empty when unknown) that the boot reconcile guard reads
/// to skip an unchanged rebuild. Lives at <instance_config_dir>/toplevel.path on the state PVC
/// (dirname of plugins_flake_dir). agentInit/confirm read only lines 1-2 (head/tail), so the
/// 3rd line is invisible to them. Any failure is warned + swallowed -- a missing/partial record
/// just makes agentInit boot the baked base, never a failed verb. Mirrors writeRunnerRecord.
fn writeToplevelRecord(ctx: *const Ctx, flake_source: []const u8, toplevel: []const u8, comphash: ?u64) void {
	const allocator = ctx.allocator;
	const cwd = std.Io.Dir.cwd();

	const instance_config_dir = std.fs.path.dirname(ctx.plugins_flake_dir) orelse {
		warn(ctx, "toplevel build: plugins-flake dir has no parent; skipping record (boot uses baked base)", .{}) catch {};
		return;
	};
	const path = std.fs.path.join(allocator, &.{ instance_config_dir, "toplevel.path" }) catch return;
	defer allocator.free(path);
	const tmp_path = std.fmt.allocPrint(allocator, "{s}.tmp", .{path}) catch return;
	defer allocator.free(tmp_path);

	var hex_buf: [16]u8 = undefined;
	const hash_hex: []const u8 = if (comphash) |h| (std.fmt.bufPrint(&hex_buf, "{x}", .{h}) catch "") else "";
	const contents = std.fmt.allocPrint(allocator, "{s}\n{s}\n{s}\n", .{ flake_source, toplevel, hash_hex }) catch return;
	defer allocator.free(contents);

	{
		const f = cwd.createFile(ctx.io, tmp_path, .{ .truncate = true }) catch {
			warn(ctx, "toplevel prebuild: could not write toplevel record (boot uses baked base)", .{}) catch {};
			return;
		};
		defer f.close(ctx.io);
		var write_buf: [512]u8 = undefined;
		var writer = f.writer(ctx.io, &write_buf);
		writer.interface.writeAll(contents) catch {
			warn(ctx, "toplevel prebuild: could not write toplevel record (boot uses baked base)", .{}) catch {};
			return;
		};
		writer.flush() catch {
			warn(ctx, "toplevel prebuild: could not write toplevel record (boot uses baked base)", .{}) catch {};
			return;
		};
		f.sync(ctx.io) catch {};
	}
	cwd.rename(tmp_path, cwd, path, ctx.io) catch {
		cwd.deleteFile(ctx.io, tmp_path) catch {};
		warn(ctx, "toplevel prebuild: could not finalize toplevel record (boot uses baked base)", .{}) catch {};
		return;
	};
}

/// Push `out_path` (and its closure) to the attic cache described by the
/// config.toml at `config_path`. attic has no config-path env override; it
/// reads $XDG_CONFIG_HOME/attic/config.toml, so we stand up a throwaway
/// XDG_CONFIG_HOME whose attic/config.toml symlinks the supplied config, then
/// run `attic push <cache> <path>` (attic computes the closure by default).
/// The cache name comes from COGBOX_PUSH_CACHE (generic; the config's
/// default-server resolves the server) or defaults to "store". Best-effort;
/// returns true iff `attic push` exited 0 (every failure path returns false).
fn pushToCache(ctx: *const Ctx, config_path: []const u8, out_path: []const u8) bool {
	const allocator = ctx.allocator;
	const cwd = std.Io.Dir.cwd();

	// Throwaway XDG_CONFIG_HOME/attic/config.toml -> config_path.
	const base = ctx.parent_env.get("TMPDIR") orelse "/tmp";
	var rnd: [12]u8 = undefined;
	ctx.io.random(&rnd);
	var hex: [24]u8 = undefined;
	_ = std.fmt.bufPrint(&hex, "{x}", .{&rnd}) catch unreachable;
	const xdg = std.fmt.allocPrint(allocator, "{s}/cogbox-attic-{s}", .{ base, hex }) catch return false;
	defer allocator.free(xdg);
	defer cwd.deleteTree(ctx.io, xdg) catch {};

	const attic_dir = std.fs.path.join(allocator, &.{ xdg, "attic" }) catch return false;
	defer allocator.free(attic_dir);
	cwd.createDirPath(ctx.io, attic_dir) catch {
		warn(ctx, "runner push: could not stage attic config dir (boot will rebuild)", .{}) catch {};
		return false;
	};
	const link = std.fs.path.join(allocator, &.{ attic_dir, "config.toml" }) catch return false;
	defer allocator.free(link);
	cwd.symLink(ctx.io, config_path, link, .{}) catch {
		warn(ctx, "runner push: could not link attic config (boot will rebuild)", .{}) catch {};
		return false;
	};

	const cache = ctx.parent_env.get("COGBOX_PUSH_CACHE") orelse "store";

	// Run attic with the staged XDG_CONFIG_HOME; clone the parent env so PATH
	// (attic lives next to git in the pod image) and any netrc/SSL vars survive.
	var env = cloneEnvMap(allocator, ctx.parent_env) catch return false;
	defer env.deinit();
	env.put("XDG_CONFIG_HOME", xdg) catch return false;

	const res = std.process.run(allocator, ctx.io, .{
		.argv = &.{ "attic", "push", cache, out_path },
		.environ_map = &env,
	}) catch {
		warn(ctx, "runner push: could not run attic (boot will rebuild)", .{}) catch {};
		return false;
	};
	defer {
		allocator.free(res.stdout);
		allocator.free(res.stderr);
	}
	if (res.term != .exited or res.term.exited != 0) {
		warn(ctx, "runner push: attic push failed (boot will rebuild): {s}", .{nix.stderrTail(res.stderr)}) catch {};
		return false;
	}
	return true;
}

/// Clone an Environ.Map (every key/value copied; Map.put dupes internally) so a
/// single child exec can run with an overridden variable without mutating ours.
fn cloneEnvMap(allocator: std.mem.Allocator, src: *const std.process.Environ.Map) !std.process.Environ.Map {
	var out = std.process.Environ.Map.init(allocator);
	errdefer out.deinit();
	const ks = src.keys();
	const vs = src.values();
	for (ks, vs) |k, v| try out.put(k, v);
	return out;
}

/// Evaluate one of the plugin's suggested-rule lists:
/// cogboxPlugins."<attr>".<leaf>, with the flat path cogboxPlugins.<leaf> as
/// fallback for the default module. Returns the parsed tree when the output
/// exists and is a JSON list; null when the flake doesn't declare it.
fn evalRuleList(ctx: *const Ctx, locked_url: []const u8, attr: ?[]const u8, leaf: []const u8) ?std.json.Parsed(std.json.Value) {
	const allocator = ctx.allocator;
	var out = nix.evalPluginRules(allocator, ctx.io, ctx.fetch_env, locked_url, attr orelse "default", leaf) catch return null;
	if (!out.ok and attr == null and nix.stderrSaysMissingAttribute(out.stderr)) {
		// No cogboxPlugins.default -- fall back to the flat form.
		out.deinit(allocator);
		out = nix.evalPluginRules(allocator, ctx.io, ctx.fetch_env, locked_url, null, leaf) catch return null;
	}
	defer out.deinit(allocator);
	if (!out.ok) {
		if (!nix.stderrSaysMissingAttribute(out.stderr)) {
			warn(ctx, "could not read cogboxPlugins.{s}: {s}", .{ leaf, nix.stderrTail(out.stderr) }) catch {};
		}
		return null;
	}

	const parsed = std.json.parseFromSlice(std.json.Value, allocator, out.stdout, .{}) catch {
		die(allocator, ctx.io, "cogboxPlugins.{s} did not evaluate to JSON", .{leaf}, 65);
	};
	if (parsed.value != .array) {
		die(allocator, ctx.io, "cogboxPlugins.{s} must be a list of rule objects", .{leaf}, 65);
	}
	return parsed;
}

/// L4 CIDR rules (cogboxPlugins.<attr>.networkRules), validated.
fn evalRules(ctx: *const Ctx, locked_url: []const u8, attr: ?[]const u8) ?std.json.Parsed(std.json.Value) {
	const parsed = evalRuleList(ctx, locked_url, attr, "networkRules") orelse return null;
	for (parsed.value.array.items, 0..) |r, i| {
		mutate.validatePluginRule(r) catch |err| {
			const what: []const u8 = switch (err) {
				error.NotAnObject => "not an object",
				error.BadAction => "must have exactly one of allow/deny",
				error.InvalidCidr => "invalid CIDR",
				error.OutOfMemory => "out of memory",
			};
			die(ctx.allocator, ctx.io, "invalid cogboxPlugins.networkRules[{d}]: {s}", .{ i, what }, 65);
		};
	}
	return parsed;
}

/// L7 vhost rules (cogboxPlugins.<attr>.l7Rules), validated with the same
/// constraints `l7 add` enforces.
fn evalL7Rules(ctx: *const Ctx, locked_url: []const u8, attr: ?[]const u8) ?std.json.Parsed(std.json.Value) {
	const parsed = evalRuleList(ctx, locked_url, attr, "l7Rules") orelse return null;
	for (parsed.value.array.items, 0..) |r, i| {
		mutate.validatePluginL7Rule(r) catch |err| {
			const what: []const u8 = switch (err) {
				error.NotAnObject => "not an object",
				error.BadAction => "must have exactly one of allow/deny",
				error.InvalidHost => "invalid host pattern",
				error.BadPath => "path must be a string starting with / made of printable ASCII with no whitespace (rules match the decoded request path, so a path with whitespace or non-ASCII cannot be expressed; do not percent-encode it)",
				error.BadMethods => "methods must be upper-case HTTP methods joined by commas (e.g. \"GET,POST\")",
				error.BadService => "service must be a non-empty string of printable ASCII with no whitespace",
				error.BadFlag => "tier flags must be booleans",
				error.ConflictingTier => "passthrough excludes terminate/path/insecure_upstream",
				error.OutOfMemory => "out of memory",
			};
			die(ctx.allocator, ctx.io, "invalid cogboxPlugins.l7Rules[{d}]: {s}", .{ i, what }, 65);
		};
	}
	return parsed;
}

/// Credential injection specs (cogboxPlugins.<attr>.inject), validated:
/// name-only, exact audience host, no inline secret material.
fn evalInjectSpecs(ctx: *const Ctx, locked_url: []const u8, attr: ?[]const u8) ?std.json.Parsed(std.json.Value) {
	const parsed = evalRuleList(ctx, locked_url, attr, "inject") orelse return null;
	for (parsed.value.array.items, 0..) |s, i| {
		mutate.validatePluginInjectSpec(s) catch |err| {
			const what: []const u8 = switch (err) {
				error.NotAnObject => "not an object",
				error.MissingHost => "missing/empty host",
				error.InvalidHost => "invalid host pattern",
				error.WildcardHost => "host must be exact (no wildcard)",
				error.BadStyle => "style must be \"bearer\", \"cookie\", or \"basic\"",
				error.BadStub => "stub must be a string",
				error.MissingSecret => "missing secret name",
				error.BadSecretName => "secret name must be [A-Za-z0-9_-] (max 64)",
				error.MissingCookieName => "cookie style requires a non-empty cookieName",
				error.BadCookieName => "invalid cookieName",
				error.InlineSecretForbidden => "may not inline a value or a path (path/cred_file/token/refresh/...); name a secret instead",
				error.BadPort => "port must be an integer in 1..65535",
				error.OutOfMemory => "out of memory",
			};
			die(ctx.allocator, ctx.io, "invalid cogboxPlugins.inject[{d}]: {s}", .{ i, what }, 65);
		};
	}
	return parsed;
}

/// .network.l7.rules, created on demand (merge path; rules mode is already
/// established by the caller).
pub fn ensureL7Rules(loaded: *config.Loaded) !*std.json.Array {
	const net = try loaded.network();
	const l7 = try l7_module.ensureL7Object(net, loaded.treeAllocator());
	return &l7.object.getPtr("rules").?.array;
}

/// .network.l7.inject.specs, created on demand (merge path). Coerces a legacy
/// bool `.network.l7.inject` into the object form { enabled, specs } -- only
/// ever reached on an explicit `plugin add` that brings inject specs, so the
/// bool->object migration happens on a verb, never on a plain start/read.
fn ensureInjectSpecs(loaded: *config.Loaded) !*std.json.Array {
	const arena = loaded.treeAllocator();
	const net = try loaded.network();
	const l7 = try l7_module.ensureL7Object(net, arena);

	if (l7.object.getPtr("inject")) |inj| {
		if (inj.* == .bool) {
			const enabled = inj.bool;
			var obj: std.json.ObjectMap = .empty;
			try obj.put(arena, try arena.dupe(u8, "enabled"), .{ .bool = enabled });
			try obj.put(arena, try arena.dupe(u8, "specs"), .{ .array = std.json.Array.init(arena) });
			try l7.object.put(arena, try arena.dupe(u8, "inject"), .{ .object = obj });
		}
	} else {
		var obj: std.json.ObjectMap = .empty;
		try obj.put(arena, try arena.dupe(u8, "enabled"), .{ .bool = true });
		try obj.put(arena, try arena.dupe(u8, "specs"), .{ .array = std.json.Array.init(arena) });
		try l7.object.put(arena, try arena.dupe(u8, "inject"), .{ .object = obj });
	}

	const inj = l7.object.getPtr("inject").?;
	if (inj.* != .object) return error.InvalidJson;
	if (inj.object.getPtr("specs") == null) {
		try inj.object.put(arena, try arena.dupe(u8, "specs"), .{ .array = std.json.Array.init(arena) });
	}
	if (inj.object.getPtr("specs").?.* != .array) return error.InvalidJson;
	return &inj.object.getPtr("specs").?.array;
}

/// .network.l7.inject.specs if it already exists (del/update/count path);
/// null when inject is absent or still in the legacy bool form.
pub fn injectSpecsOrNull(loaded: *config.Loaded) ?*std.json.Array {
	const net = loaded.network() catch return null;
	const l7 = net.object.getPtr("l7") orelse return null;
	if (l7.* != .object) return null;
	const inj = l7.object.getPtr("inject") orelse return null;
	if (inj.* != .object) return null;
	const specs = inj.object.getPtr("specs") orelse return null;
	if (specs.* != .array) return null;
	return &specs.array;
}

/// .network.l7.rules if it already exists; never creates it (del/list path).
pub fn l7RulesOrNull(loaded: *config.Loaded) ?*std.json.Array {
	const net = loaded.network() catch return null;
	const l7 = net.object.getPtr("l7") orelse return null;
	if (l7.* != .object) return null;
	const r = l7.object.getPtr("rules") orelse return null;
	if (r.* != .array) return null;
	return &r.array;
}

/// Regenerate (or remove, when no plugins are left) the composition flake
/// from the current .plugins array. Pure function of config.json, rebuilt on
/// every mutation, so a crash between config save and this write self-heals
/// on the next plugin command.
pub fn regenComposition(ctx: *const Ctx, plugins_arr: *std.json.Array) !void {
	const allocator = ctx.allocator;

	// The composition is about to change, so ANY recorded composed runner is now
	// stale -- drop it before writing the new flake. Without this the launcher's
	// skip-eval fast path is keyed on the image rev and the package attribute and
	// on nothing else, so a SECOND plugin add against an unchanged image matched
	// the record written for the first, realized that runner and skipped the
	// re-exec that would have composed the new one: the plugin is installed, the
	// UI says so, and the guest never gets it. On k8s that was masked, because the
	// worker's prebuildAndPushRunner overwrites the record moments later from
	// finalizeComposition; on a backend with no worker pod (GCE) nothing rewrote
	// it and the staleness was permanent until the image rev moved.
	//
	// Unconditional, including the no-plugins branch below: an instance whose last
	// plugin was just removed must not keep a record either, and a delete of a
	// file that is not there is free. Best-effort by construction -- removeRecord
	// swallows its errors -- and losing the record can only cost one eval boot,
	// which is exactly what correctness requires here anyway.
	removeRunnerRecord(ctx);

	if (plugins_arr.items.len == 0) {
		try compose.removeCompositionFlake(allocator, ctx.io, ctx.plugins_flake_dir);
		// The lock is gone, so is any snapshot of it: a later re-add must never
		// fall back to a composition from before the removal.
		clearPrevLock(ctx);
		return;
	}

	var refs: std.ArrayList(compose.PluginRef) = .empty;
	defer refs.deinit(allocator);
	for (plugins_arr.items) |item| {
		if (item != .object) continue;
		const n = mutate.entryField(item.object, "name") orelse continue;
		const locked = mutate.entryField(item.object, "lockedUrl") orelse continue;
		const attr = mutate.entryField(item.object, "attr") orelse "default";
		// The attr lands quoted inside the generated flake; never emit one
		// that fails the safe-charset check (hand-edited config).
		if (!name_mod.isValidAttr(attr)) continue;
		// The plugin's subdir, if it lives in one (`?dir=` on the locked URL);
		// the materialized source is the repo root, so both the hydration check
		// and the path: input use it.
		const dir = nix.dirParam(locked);
		// has_source is a pure filesystem check (the flake.nix under the
		// materialized source exists), so render stays a function of config +
		// on-disk sources and self-heals: a materialize that failed earlier just
		// keeps the locked URL until a later add/update succeeds.
		try refs.append(allocator, .{
			.name = n,
			.locked_url = locked,
			.attr = attr,
			.has_source = sourceHydrated(ctx, n, dir),
			.dir = dir,
		});
	}

	const rendered = compose.render(allocator, ctx.instance orelse "default", ctx.user_flake_dir, ctx.sources_dir, refs.items) catch |err| switch (err) {
		error.NoPlugins => {
			try compose.removeCompositionFlake(allocator, ctx.io, ctx.plugins_flake_dir);
			return;
		},
		else => return err,
	};
	defer allocator.free(rendered);
	try compose.writeCompositionFlake(allocator, ctx.io, ctx.plugins_flake_dir, rendered);
}

fn pinLabel(meta: *const nix.Meta) []const u8 {
	if (meta.rev) |r| return r[0..@min(r.len, 7)];
	const h = meta.nar_hash;
	const stripped = if (std.mem.startsWith(u8, h, "sha256-")) h[7..] else h;
	return stripped[0..@min(stripped.len, 8)];
}

fn printRuleLine(ctx: *const Ctx, sign: []const u8, r: std.json.Value) !void {
	if (r != .object) return;
	const p = rule.ruleAction(r.object) orelse return;
	const action = switch (p.action) {
		.allow => "allow",
		.deny => "deny",
	};
	if (rule.ruleComment(r.object)) |c| {
		try announce(ctx, "  {s} {s} {s}  # {s}", .{ sign, action, p.cidr, c });
	} else {
		try announce(ctx, "  {s} {s} {s}", .{ sign, action, p.cidr });
	}
}

fn printL7RuleLine(ctx: *const Ctx, sign: []const u8, r: std.json.Value) !void {
	if (r != .object) return;
	const p = l7_rule.ruleAction(r.object) orelse return;
	const action = switch (p.action) {
		.allow => "allow",
		.deny => "deny",
	};

	var suffix: std.ArrayList(u8) = .empty;
	defer suffix.deinit(ctx.allocator);
	var is_terminate = false;
	if (r.object.get("path")) |pv| {
		if (pv == .string) {
			try suffix.append(ctx.allocator, ' ');
			try suffix.appendSlice(ctx.allocator, pv.string);
			is_terminate = true;
		}
	}
	if (r.object.get("terminate")) |tv| {
		if (tv == .bool and tv.bool) is_terminate = true;
	}
	var is_insecure = false;
	if (r.object.get("insecure_upstream")) |iv| {
		if (iv == .bool and iv.bool) {
			is_insecure = true;
			is_terminate = true;
		}
	}
	var is_passthrough = false;
	if (r.object.get("passthrough")) |pv| {
		if (pv == .bool and pv.bool) is_passthrough = true;
	}
	if (is_passthrough) {
		try suffix.appendSlice(ctx.allocator, " [passthrough]");
	} else {
		if (is_terminate) try suffix.appendSlice(ctx.allocator, " [terminate]");
		if (is_insecure) try suffix.appendSlice(ctx.allocator, " [insecure]");
	}

	if (l7_rule.ruleComment(r.object)) |c| {
		try announce(ctx, "  {s} l7 {s} {s}{s}  # {s}", .{ sign, action, p.host, suffix.items, c });
	} else {
		try announce(ctx, "  {s} l7 {s} {s}{s}", .{ sign, action, p.host, suffix.items });
	}
}

fn printInjectLine(ctx: *const Ctx, sign: []const u8, s: std.json.Value) !void {
	if (s != .object) return;
	const host = blk: {
		const h = s.object.get("host") orelse return;
		if (h != .string) return;
		break :blk h.string;
	};
	const style = if (s.object.get("style")) |sv| (if (sv == .string) sv.string else "bearer") else "bearer";
	const secret = if (s.object.get("secret")) |sv| (if (sv == .string) sv.string else "?") else "?";
	// Show :port only when a non-standard one is declared, so the operator can
	// see the funnel will cover it (a bare host implies 80/443).
	var port_buf: [8]u8 = undefined;
	const port_sfx: []const u8 = if (s.object.get("port")) |pv|
		(if (pv == .integer) (std.fmt.bufPrint(&port_buf, ":{d}", .{pv.integer}) catch "") else "")
	else
		"";
	if (std.mem.eql(u8, style, "cookie")) {
		const cn = if (s.object.get("cookieName")) |cv| (if (cv == .string) cv.string else "?") else "?";
		try announce(ctx, "  {s} inject {s}{s} cookie({s}) secret={s}", .{ sign, host, port_sfx, cn, secret });
	} else {
		try announce(ctx, "  {s} inject {s}{s} {s} secret={s}", .{ sign, host, port_sfx, style, secret });
	}
}

/// After merging inject specs, tell the operator exactly which secrets to bind
/// host-side. We don't (yet) check bound state here -- the point is the
/// command to run; an unbound secret simply renders no conf and injection
/// stays inert (fail closed) until bound.
fn printBindChecklist(ctx: *const Ctx, specs: []const std.json.Value) !void {
	if (specs.len == 0) return;
	try announce(ctx, "Bind these secrets host-side so injection takes effect (they stay OUT of the guest):", .{});
	for (specs) |s| {
		if (s != .object) continue;
		const secret = if (s.object.get("secret")) |sv| (if (sv == .string) sv.string else continue) else continue;
		const host = if (s.object.get("host")) |hv| (if (hv == .string) hv.string else "?") else "?";
		const kind = if (s.object.get("style")) |sv| (if (sv == .string) sv.string else "bearer") else "bearer";
		try announce(ctx, "  cogbox secret add {s} --from-file FILE --audience {s} --kind {s}", .{ secret, host, kind });
	}
}

fn printRestartHint(ctx: *const Ctx, why: []const u8) !void {
	if (ctx.instance) |n| {
		try announce(ctx, "Restart the instance ('cogbox restart -n {s}') {s}.", .{ n, why });
	} else {
		try announce(ctx, "Restart the instance ('cogbox restart') {s}.", .{why});
	}
}

pub const LiveDecision = enum {
	/// The instance is not running: the change loads at the next start.
	not_running,
	/// Left for `cogbox plugin apply` or a restart.
	deferred,
	/// Applied inline, right after the commit.
	inline_apply,
};

/// Whether a committed add, del or update is applied live right away (spec
/// section 2 step 1, CLI). Only on a running instance, and then only with
/// --apply, or, without --no-apply, when stderr is an interactive terminal and
/// COGBOX_ENVIRONMENT is not cogworx (a control plane runs its own apply).
/// COGBOX_LIVE_APPLY=0 (environment only) defers in every case. Never on a
/// non-terminal stderr without --apply.
pub fn liveDecision(running: bool, choice: cli.LiveChoice, stderr_tty: bool, env: *const std.process.Environ.Map) LiveDecision {
	if (!running) return .not_running;
	if (env.get("COGBOX_LIVE_APPLY")) |v| if (std.mem.eql(u8, v, "0")) return .deferred;
	if (choice) |c| return if (c) .inline_apply else .deferred;
	if (!stderr_tty) return .deferred;
	if (env.get("COGBOX_ENVIRONMENT")) |e| if (std.mem.eql(u8, e, "cogworx")) return .deferred;
	return .inline_apply;
}

/// The end of a committed add, del or update (was printRestartHint; spec
/// section 6 "Restart hint"): not running, the change loads at the next start
/// (unchanged); deferred (--no-apply, the default off a terminal, or
/// COGBOX_LIVE_APPLY=0), the apply-or-restart hint; otherwise the inline live
/// apply under the gate's locks, worded for this change. A change the inline
/// apply rolled back sets exit 1 (the dispatcher exits with it after the
/// verb); the apply's own non-zero exit (78, or the terminate path's) ends the
/// process at once.
fn finishLive(ctx: *Ctx, plugin_name: ?[]const u8, why: []const u8) !void {
	const tty = std.Io.File.stderr().isTty(ctx.io) catch false;
	var d = liveDecision(isRunning(ctx), ctx.live, tty, ctx.parent_env);
	// Only a verb that passed the apply gate holds the locks the apply needs.
	if (d == .inline_apply and !ctx.host.gate_held) d = .deferred;
	switch (d) {
		.not_running => return announce(ctx, "It will take effect at the next start.", .{}),
		.deferred => {
			if (ctx.instance) |n| return announce(ctx, "Run 'cogbox plugin apply -n {s}' to load it live, or restart the instance ('cogbox restart -n {s}') {s}.", .{ n, n, why });
			return announce(ctx, "Run 'cogbox plugin apply' to load it live, or restart the instance ('cogbox restart') {s}.", .{why});
		},
		.inline_apply => {},
	}
	try announce(ctx, "Loading it into the running instance (live apply)...", .{});
	var arena_state = std.heap.ArenaAllocator.init(ctx.allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();
	const res = apply.runInline(arena, ctx, ctx.host);
	const rep = res.report orelse {
		// No report: a rollback that cannot finish blocked the apply (its
		// stamped message is on stderr), or the apply was interrupted.
		if (res.code != 0) std.process.exit(res.code);
		return printRestartHint(ctx, why);
	};
	const result = jsonStr(rep.get("result")) orelse "";
	const reason = jsonStr(rep.get("reason"));
	const gen = jsonStr(rep.get("gen")) orelse "";
	const n_opt: []const u8 = if (ctx.instance) |n| try std.fmt.allocPrint(arena, " -n {s}", .{n}) else "";
	if (std.mem.eql(u8, result, "applied") or std.mem.eql(u8, result, "applied_with_failures") or std.mem.eql(u8, result, "already_live")) {
		try announce(ctx, "Loaded into the running instance (generation {s}).", .{gen});
		if (rep.get("units")) |u| if (u == .array and u.array.items.len > 0) {
			var names: std.ArrayList(u8) = .empty;
			for (u.array.items, 0..) |item, i| {
				if (item != .string) continue;
				if (i > 0) try names.appendSlice(arena, ", ");
				try names.appendSlice(arena, item.string);
			}
			try announce(ctx, "Units that failed to start: {s}.", .{names.items});
		};
	} else if (std.mem.eql(u8, result, "rejected")) {
		try announce(ctx, "{s}", .{try rejectedLine(arena, plugin_name, rep, res.code, n_opt)});
		ctx.exit_code = 1;
		ctx.live_rejected = true;
	} else if (std.mem.eql(u8, result, "not_running")) {
		try announce(ctx, "It will take effect at the next start.", .{});
	} else {
		var detail: std.ArrayList(u8) = .empty;
		if (rep.get("detail")) |dv| if (dv == .array) for (dv.array.items) |item| {
			if (item != .string) continue;
			try detail.appendSlice(arena, if (detail.items.len == 0) ": " else ", ");
			try detail.appendSlice(arena, item.string);
		};
		try announce(ctx, "Not loaded live ({s}{s}{s}{s}).", .{ result, if (reason != null) "/" else "", reason orelse "", detail.items });
		try printRestartHint(ctx, why);
	}
	if (res.code != 0) std.process.exit(res.code);
}

/// The inline apply's line for a rejected change, from its report `rep` and
/// exit `code`. Rolled back only when the report's rollback is `done`; any
/// other state (`removed`, the fail-closed tier; `pending`, or no status; and
/// pending with exit 78, a finish that could not complete) gets the sentence
/// `cogbox plugin apply` prints for the same report (apply.rollbackSentence).
fn rejectedLine(arena: std.mem.Allocator, plugin_name: ?[]const u8, rep: std.json.ObjectMap, code: u8, n_opt: []const u8) ![]const u8 {
	const text = apply.rejectionText(jsonStr(rep.get("reason")) orelse "");
	const gen = jsonStr(rep.get("gen")) orelse "";
	const what: []const u8 = if (plugin_name) |p| try std.fmt.allocPrint(arena, "'{s}'", .{p}) else "The plugin update";
	if (apply.rollbackSentenceJson(rep.get("rollback"), code == 78)) |state| return std.fmt.allocPrint(arena, "{s} was not applied: {s}. {s}. Build log: cogbox plugin apply{s} --log {s}", .{ what, text, state, n_opt, gen });
	return std.fmt.allocPrint(arena, "{s} was not applied and has been rolled back: {s}. Build log: cogbox plugin apply{s} --log {s}", .{ what, text, n_opt, gen });
}

fn jsonStr(v: ?std.json.Value) ?[]const u8 {
	const x = v orelse return null;
	return if (x == .string) x.string else null;
}

/// Same probe as cli/util.zig instanceRunningConservative, inlined because the
/// CLI module imports this one (build.zig) and cannot be imported back. The
/// launcher holds an exclusive flock on <runtime>.lock for its whole lifetime
/// (inherited by QEMU), so a held lock is the verdict; a pid file cannot tell a
/// dead launch from PID reuse. Fail closed: an uninspectable lock counts as
/// running, so the hint says "restart" rather than "at the next start".
pub fn isRunning(ctx: *const Ctx) bool {
	const lock_path = std.fmt.allocPrint(ctx.allocator, "{s}.lock", .{ctx.runtime_path}) catch return true;
	defer ctx.allocator.free(lock_path);
	const file = std.Io.Dir.cwd().openFile(ctx.io, lock_path, .{}) catch |err| switch (err) {
		error.FileNotFound => return false,
		else => return true,
	};
	defer file.close(ctx.io);
	return @import("platform").lockHeld(file.handle) catch true;
}

/// Interactive confirmation. Non-tty stdin auto-confirms, matching the
/// launcher's behavior for its own prompts (scripted/test use).
fn confirm(ctx: *const Ctx, prompt: []const u8) !bool {
	const stdin = std.Io.File.stdin();
	const tty = stdin.isTty(ctx.io) catch false;
	if (!tty) return true;

	const msg = try std.fmt.allocPrint(ctx.allocator, "{s} [y/N] ", .{prompt});
	defer ctx.allocator.free(msg);
	try writeStdout(ctx.io, msg);

	var buf: [256]u8 = undefined;
	var reader = stdin.readerStreaming(ctx.io, &buf);
	const line = (reader.interface.takeDelimiter('\n') catch return false) orelse return false;
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	return trimmed.len > 0 and (trimmed[0] == 'y' or trimmed[0] == 'Y');
}

pub fn rulesOrNull(loaded: *config.Loaded) ?*std.json.Array {
	return loaded.rules() catch null;
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

fn announce(ctx: *const Ctx, comptime fmt: []const u8, args: anytype) !void {
	const msg = try std.fmt.allocPrint(ctx.allocator, fmt ++ "\n", args);
	defer ctx.allocator.free(msg);
	// Under --defer-rules the only thing on stdout is the deferred-rules JSON
	// line; send all human chatter to stderr so that line parses cleanly.
	if (ctx.defer_rules) {
		try writeStderr(ctx.io, msg);
	} else {
		try writeStdout(ctx.io, msg);
	}
}

fn warn(ctx: *const Ctx, comptime fmt: []const u8, args: anytype) !void {
	const msg = try std.fmt.allocPrint(ctx.allocator, "cogbox plugin: warning: " ++ fmt ++ "\n", args);
	defer ctx.allocator.free(msg);
	try writeStderr(ctx.io, msg);
}

fn die(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype, code: u8) noreturn {
	const msg = std.fmt.allocPrint(allocator, "cogbox plugin: error: " ++ fmt ++ "\n", args) catch "cogbox plugin: error: (message too long)\n";
	writeStderr(io, msg) catch {};
	std.process.exit(code);
}

// --- tests ---------------------------------------------------------------

const t = std.testing;

test "repinRemaining: one shared deadline, null once under a second is left" {
	try t.expectEqual(@as(?u32, 120), repinRemaining(0, 120));
	try t.expectEqual(@as(?u32, 70), repinRemaining(50_000, 120));
	try t.expectEqual(@as(?u32, 1), repinRemaining(118_999, 120));
	try t.expect(repinRemaining(119_001, 120) == null);
	try t.expect(repinRemaining(400_000, 120) == null);
}

test "narinfoName derives <hash32>.narinfo from an out-path" {
	var buf: [64]u8 = undefined;
	try t.expectEqualStrings("0123456789abcdfghijklmnpqrsvwxyz.narinfo", narinfoName(&buf, "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-nixos-system-cogbox").?);
	try t.expectEqualStrings("0123456789abcdfghijklmnpqrsvwxyz.narinfo", narinfoName(&buf, "  /nix/store/0123456789abcdfghijklmnpqrsvwxyz-x\r\n").?);
	try t.expect(narinfoName(&buf, "/nix/store/short-name") == null);
	try t.expect(narinfoName(&buf, "") == null);
}

test "renderDeferredJson emits one line with the validated rule shapes" {
	const a = t.allocator;
	// The exact validated shapes evalRules/evalL7Rules produce: an L4 allow on a
	// CIDR, and an L7 deny on a host with a terminate flag + comment.
	var l4_parsed = try std.json.parseFromSlice(std.json.Value, a, "[{\"allow\":\"203.0.113.0/24\"}]", .{});
	defer l4_parsed.deinit();
	var l7_parsed = try std.json.parseFromSlice(std.json.Value, a, "[{\"deny\":\"api.example.com\",\"terminate\":true,\"comment\":\"x\"}]", .{});
	defer l7_parsed.deinit();

	const line = try renderDeferredJson(a, "obs-plugin", l4_parsed.value.array.items, l7_parsed.value.array.items);
	defer a.free(line);

	// Trailing newline, single line otherwise (no embedded newlines in the body).
	try t.expect(line.len > 0 and line[line.len - 1] == '\n');
	try t.expect(std.mem.indexOfScalar(u8, line[0 .. line.len - 1], '\n') == null);

	// It round-trips to the documented contract.
	var rt = try std.json.parseFromSlice(std.json.Value, a, line, .{});
	defer rt.deinit();
	const deferred = rt.value.object.get("deferred").?.object;
	try t.expectEqualStrings("obs-plugin", deferred.get("plugin").?.string);
	const l4 = deferred.get("l4").?.array;
	try t.expectEqual(@as(usize, 1), l4.items.len);
	try t.expectEqualStrings("203.0.113.0/24", l4.items[0].object.get("allow").?.string);
	const l7 = deferred.get("l7").?.array;
	try t.expectEqual(@as(usize, 1), l7.items.len);
	try t.expectEqualStrings("api.example.com", l7.items[0].object.get("deny").?.string);
	try t.expect(l7.items[0].object.get("terminate").?.bool);
	try t.expectEqualStrings("x", l7.items[0].object.get("comment").?.string);
}

// updatePluginRules fixtures: plugin p carries a tagged L4 allow, a tagged L7
// allow and a tagged inject spec; an untagged deny sits beside them.
const update_rules_doc =
	\\{"network":{"rules":[{"allow":"10.0.0.0/8","plugin":"p","comment":"old"},{"deny":"192.0.2.0/24"}],
	\\"l7":{"rules":[{"allow":"a.example.com","plugin":"p"}],
	\\"inject":{"enabled":true,"specs":[{"host":"old.example.com","style":"bearer","secret":"api-token","plugin":"p"}]}}}}
;

fn updateRulesTestLoaded(doc: []const u8) !config.Loaded {
	return .{ .parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, doc, .{}), .path = "" };
}

fn updateRulesCompact(items: []const std.json.Value) ![]u8 {
	var out: std.ArrayList(u8) = .empty;
	errdefer out.deinit(t.allocator);
	try writeCompactArray(t.allocator, &out, items);
	return out.toOwnedSlice(t.allocator);
}

const UpdateRulesIncoming = struct {
	l4: std.json.Parsed(std.json.Value),
	l7: std.json.Parsed(std.json.Value),
	inject: std.json.Parsed(std.json.Value),

	fn init(l4: []const u8, l7: []const u8, inject: []const u8) !UpdateRulesIncoming {
		const a = t.allocator;
		var p4 = try std.json.parseFromSlice(std.json.Value, a, l4, .{});
		errdefer p4.deinit();
		var p7 = try std.json.parseFromSlice(std.json.Value, a, l7, .{});
		errdefer p7.deinit();
		return .{ .l4 = p4, .l7 = p7, .inject = try std.json.parseFromSlice(std.json.Value, a, inject, .{}) };
	}

	fn deinit(self: *UpdateRulesIncoming) void {
		self.l4.deinit();
		self.l7.deinit();
		self.inject.deinit();
	}

	fn apply(self: *UpdateRulesIncoming, loaded: *config.Loaded, defer_rules: bool) !?[]u8 {
		return updatePluginRules(t.allocator, loaded, rulesOrNull(loaded).?, l7RulesOrNull(loaded), injectSpecsOrNull(loaded), "p", self.l4.value.array.items, self.l7.value.array.items, self.inject.value.array.items, defer_rules);
	}
};

test "updatePluginRules --defer-rules: L4/L7 untouched, inject replaced, only novel rules reported" {
	const a = t.allocator;
	var loaded = try updateRulesTestLoaded(update_rules_doc);
	defer loaded.deinit();
	var in = try UpdateRulesIncoming.init(
		"[{\"allow\":\"10.0.0.0/8\"},{\"allow\":\"198.51.100.0/24\"}]",
		"[{\"allow\":\"a.example.com\"},{\"allow\":\"b.example.com\",\"path\":\"/x\"}]",
		"[{\"host\":\"new.example.com\",\"style\":\"bearer\",\"secret\":\"api-token\"}]",
	);
	defer in.deinit();

	const l4_before = try updateRulesCompact(rulesOrNull(&loaded).?.items);
	defer a.free(l4_before);
	const l7_before = try updateRulesCompact(l7RulesOrNull(&loaded).?.items);
	defer a.free(l7_before);

	const line = (try in.apply(&loaded, true)) orelse return error.TestExpectedDeferredLine;
	defer a.free(line);

	// The applied L4/L7 arrays are byte-identical: nothing removed, nothing added.
	const l4_after = try updateRulesCompact(rulesOrNull(&loaded).?.items);
	defer a.free(l4_after);
	try t.expectEqualStrings(l4_before, l4_after);
	const l7_after = try updateRulesCompact(l7RulesOrNull(&loaded).?.items);
	defer a.free(l7_after);
	try t.expectEqualStrings(l7_before, l7_after);

	// The inject specs are replaced as on a live update.
	const specs = injectSpecsOrNull(&loaded).?.items;
	try t.expectEqual(@as(usize, 1), specs.len);
	try t.expectEqualStrings("new.example.com", specs[0].object.get("host").?.string);
	try t.expectEqualStrings("p", specs[0].object.get("plugin").?.string);

	// The line names only the rules p does not already carry.
	var rt = try std.json.parseFromSlice(std.json.Value, a, line, .{});
	defer rt.deinit();
	const d = rt.value.object.get("deferred").?.object;
	try t.expectEqualStrings("p", d.get("plugin").?.string);
	const l4 = d.get("l4").?.array.items;
	try t.expectEqual(@as(usize, 1), l4.len);
	try t.expectEqualStrings("198.51.100.0/24", l4[0].object.get("allow").?.string);
	const l7 = d.get("l7").?.array.items;
	try t.expectEqual(@as(usize, 1), l7.len);
	try t.expectEqualStrings("b.example.com", l7[0].object.get("allow").?.string);
}

test "updatePluginRules --defer-rules: an up-to-date rule set reports nothing" {
	var loaded = try updateRulesTestLoaded(update_rules_doc);
	defer loaded.deinit();
	var in = try UpdateRulesIncoming.init("[{\"allow\":\"10.0.0.0/8\"}]", "[{\"allow\":\"a.example.com\"}]", "[]");
	defer in.deinit();
	try t.expect((try in.apply(&loaded, true)) == null);
	// No inject spec incoming: the old one is gone, as on a live update.
	try t.expectEqual(@as(usize, 0), injectSpecsOrNull(&loaded).?.items.len);
}

test "updatePluginRules live: the tagged L4/L7 rules are replaced, nothing reported" {
	var loaded = try updateRulesTestLoaded(update_rules_doc);
	defer loaded.deinit();
	var in = try UpdateRulesIncoming.init(
		"[{\"allow\":\"198.51.100.0/24\"}]",
		"[{\"allow\":\"b.example.com\"}]",
		"[]",
	);
	defer in.deinit();
	try t.expect((try in.apply(&loaded, false)) == null);
	const rules = rulesOrNull(&loaded).?.items;
	try t.expectEqual(@as(usize, 2), rules.len);
	try t.expectEqualStrings("198.51.100.0/24", rules[0].object.get("allow").?.string);
	try t.expectEqualStrings("p", rules[0].object.get("plugin").?.string);
	try t.expectEqualStrings("192.0.2.0/24", rules[1].object.get("deny").?.string);
	const l7 = l7RulesOrNull(&loaded).?.items;
	try t.expectEqual(@as(usize, 1), l7.len);
	try t.expectEqualStrings("b.example.com", l7[0].object.get("allow").?.string);
}

test "renderDeferredJson with no rules emits empty arrays" {
	const a = t.allocator;
	const line = try renderDeferredJson(a, "p", &.{}, &.{});
	defer a.free(line);
	try t.expectEqualStrings("{\"deferred\":{\"plugin\":\"p\",\"l4\":[],\"l7\":[]}}\n", line);
}

// the base-store substitution substituter-string assembly. The base
// store (when present) goes FIRST as local?root=<r>&read-only=true so nix prefers it
// for base paths; the per-instance file:// cache always follows; the shared cache is
// last. Absent base store => today's file://cache string, unchanged.
test "buildSubstituters: base store prepended, shared cache appended" {
	const a = t.allocator;

	// base store + shared cache: base first, then cache, then the shared cache.
	{
		const s = buildSubstituters(a, "/icd/plugin-cache", "https://cache.example.com", "/cogbox-basestore").?;
		defer a.free(s);
		try t.expectEqualStrings("local?root=/cogbox-basestore&read-only=true file:///icd/plugin-cache https://cache.example.com", s);
	}
	// base store, no shared cache: base first, then cache.
	{
		const s = buildSubstituters(a, "/icd/plugin-cache", "", "/cogbox-basestore").?;
		defer a.free(s);
		try t.expectEqualStrings("local?root=/cogbox-basestore&read-only=true file:///icd/plugin-cache", s);
	}
	// no base store (unseeded/absent), shared cache present: unchanged from today.
	{
		const s = buildSubstituters(a, "/icd/plugin-cache", "https://cache.example.com", null).?;
		defer a.free(s);
		try t.expectEqualStrings("file:///icd/plugin-cache https://cache.example.com", s);
	}
	// no base store, no shared cache: just the per-instance cache.
	{
		const s = buildSubstituters(a, "/icd/plugin-cache", "", null).?;
		defer a.free(s);
		try t.expectEqualStrings("file:///icd/plugin-cache", s);
	}
}

// --- live-apply Phase 0: runner record line 3, materializeSource vs snapshots ---

/// An instance config dir under the cwd for the Ctx-driven tests below, with the
/// Ctx paths dispatch derives from it. The caller deletes `root`.
const TestInstance = struct {
	root: []u8,
	plugins_flake_dir: []u8,
	sources_dir: []u8,
	cache_dir: []u8,
	env: std.process.Environ.Map,

	fn init(io: std.Io, tag: []const u8) !TestInstance {
		const a = t.allocator;
		var rnd: [8]u8 = undefined;
		io.random(&rnd);
		const rel = try std.fmt.allocPrint(a, "zig-plugin-test-{s}-{x}", .{ tag, &rnd });
		defer a.free(rel);
		const cwd = std.Io.Dir.cwd();
		try cwd.createDirPath(io, rel);
		const root_z = try cwd.realPathFileAlloc(io, rel, a);
		defer a.free(root_z);
		const root = try a.dupe(u8, root_z);
		const pf = try std.fmt.allocPrint(a, "{s}/plugins-flake", .{root});
		try cwd.createDirPath(io, pf);
		return .{
			.root = root,
			.plugins_flake_dir = pf,
			.sources_dir = try std.fmt.allocPrint(a, "{s}/plugin-sources", .{root}),
			.cache_dir = try std.fmt.allocPrint(a, "{s}/plugin-cache", .{root}),
			.env = std.process.Environ.Map.init(a),
		};
	}

	fn ctx(self: *const TestInstance, io: std.Io) Ctx {
		return .{
			.allocator = t.allocator,
			.io = io,
			.parent_env = &self.env,
			.instance = null,
			.config_path = "",
			.runtime_path = "",
			.user_flake_dir = "",
			.plugins_flake_dir = self.plugins_flake_dir,
			.sources_dir = self.sources_dir,
			.cache_dir = self.cache_dir,
		};
	}

	fn deinit(self: *TestInstance, io: std.Io) void {
		std.Io.Dir.cwd().deleteTree(io, self.root) catch {};
		const a = t.allocator;
		a.free(self.root);
		a.free(self.plugins_flake_dir);
		a.free(self.sources_dir);
		a.free(self.cache_dir);
		self.env.deinit();
	}

	fn path(self: *const TestInstance, comptime rel: []const u8) ![]u8 {
		return std.fmt.allocPrint(t.allocator, "{s}/" ++ rel, .{self.root});
	}
};

fn testWriteFile(io: std.Io, p: []const u8, bytes: []const u8) !void {
	const f = try std.Io.Dir.cwd().createFile(io, p, .{ .truncate = true });
	defer f.close(io);
	var buf: [256]u8 = undefined;
	var w = f.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn testReadFile(io: std.Io, p: []const u8) ![]u8 {
	return std.Io.Dir.cwd().readFileAlloc(io, p, t.allocator, .limited(1 << 20));
}

test "runner record: three lines, line 3 the comp of the composition the runner was built from" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	var inst = try TestInstance.init(io, "record");
	defer inst.deinit(io);
	try inst.env.put("COGBOX_REEXEC_PACKAGE", "cogbox-hosted");
	const c = inst.ctx(io);

	const nix_path = try inst.path("plugins-flake/flake.nix");
	defer t.allocator.free(nix_path);
	const lock_path = try inst.path("plugins-flake/flake.lock");
	defer t.allocator.free(lock_path);
	const rec_path = try inst.path("runner.path");
	defer t.allocator.free(rec_path);
	try testWriteFile(io, nix_path, "{ outputs = _: {}; }\n");
	try testWriteFile(io, lock_path, "{\"nodes\":{},\"version\":7}\n");

	// Unchanged bytes across the build: recordable, and the record is keyed on
	// the package with line 3 = comp of exactly those bytes.
	const before = snapshot.compOfDir(io, inst.plugins_flake_dir);
	const want_comp = snapshot.compOfBytes("{ outputs = _: {}; }\n", "{\"nodes\":{},\"version\":7}\n");
	const verdict = prebuiltRecordComp(&c, before);
	try t.expectEqualStrings(&want_comp, &verdict.comp);
	writeRunnerRecord(&c, "/nix/store/aaa-cogbox-source", "/nix/store/bbb-microvm-run", &verdict.comp);
	const rec = try testReadFile(io, rec_path);
	defer t.allocator.free(rec);
	const want = try std.fmt.allocPrint(t.allocator, "/nix/store/aaa-cogbox-source#cogbox-hosted\n/nix/store/bbb-microvm-run\n{s}\n", .{&want_comp});
	defer t.allocator.free(want);
	try t.expectEqualStrings(want, rec);
	// A two-line reader (an older launcher) still sees the same key and runner.
	var lines = std.mem.splitScalar(u8, rec, '\n');
	try t.expectEqualStrings("/nix/store/aaa-cogbox-source#cogbox-hosted", lines.next().?);
	try t.expectEqualStrings("/nix/store/bbb-microvm-run", lines.next().?);

	// The bytes changed during the build: not recordable.
	try testWriteFile(io, lock_path, "{\"nodes\":{\"p-x\":{}},\"version\":7}\n");
	try t.expect(prebuiltRecordComp(&c, before) == .changed);

	// No comp before the build, or none after it (no flake.nix): not recordable.
	try t.expect(prebuiltRecordComp(&c, null) == .no_comp);
	try std.Io.Dir.cwd().deleteFile(io, nix_path);
	try t.expect(prebuiltRecordComp(&c, before) == .no_comp);

	// A composition without a lock (its `nix flake lock` failed) is recordable,
	// with the comp of an empty lock, which the launcher computes for it too;
	// a lock that vanished during the build is a change like any other.
	try testWriteFile(io, nix_path, "{ outputs = _: {}; }\n");
	try std.Io.Dir.cwd().deleteFile(io, lock_path);
	try t.expect(prebuiltRecordComp(&c, before) == .changed);
	const lockless = snapshot.compOfDir(io, inst.plugins_flake_dir);
	try t.expectEqualStrings(&snapshot.compOfBytes("{ outputs = _: {}; }\n", ""), &prebuiltRecordComp(&c, lockless).comp);
}

test "runner record: the key defaults to the cogbox package" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	var inst = try TestInstance.init(io, "record-default");
	defer inst.deinit(io);
	const c = inst.ctx(io);
	const rec_path = try inst.path("runner.path");
	defer t.allocator.free(rec_path);
	const comp = snapshot.compOfBytes("n", "l");
	writeRunnerRecord(&c, "/src", "/runner", &comp);
	const rec = try testReadFile(io, rec_path);
	defer t.allocator.free(rec);
	const want = try std.fmt.allocPrint(t.allocator, "/src#cogbox\n/runner\n{s}\n", .{&comp});
	defer t.allocator.free(want);
	try t.expectEqualStrings(want, rec);
}

// A live-apply snapshot is a `cp -al` of plugin-sources/: its files share
// inodes with the live tree. materializeSource and removeSource must therefore
// never write into an existing source file, including when materialize's
// best-effort deleteTree fails and leaves files behind.
test "materializeSource/removeSource never rewrite a file a hard-linked snapshot shares" {
	if (std.c.geteuid() == 0) return error.SkipZigTest; // root ignores directory modes
	// The process environment, so runTool's cp/chmod resolve through PATH.
	var threaded: std.Io.Threaded = .init(t.allocator, .{ .environ = std.testing.environ });
	defer threaded.deinit();
	const io = threaded.io();
	const a = t.allocator;
	const cwd = std.Io.Dir.cwd();
	var inst = try TestInstance.init(io, "materialize");
	defer {
		// Give the planted read-only directory its write bit back for teardown.
		if (inst.path("plugin-sources/p/sub")) |locked| {
			defer a.free(locked);
			cwd.setFilePermissions(io, locked, .fromMode(0o755), .{}) catch {};
		} else |_| {}
		inst.deinit(io);
	}
	const c = inst.ctx(io);

	// The plugin's new (v2) source, standing in for its store path.
	const src = try inst.path("store-src");
	defer a.free(src);
	const src_sub = try inst.path("store-src/sub");
	defer a.free(src_sub);
	try cwd.createDirPath(io, src_sub);
	inline for (.{ "store-src/default.nix", "store-src/sub/a.txt" }) |rel| {
		const p = try inst.path(rel);
		defer a.free(p);
		try testWriteFile(io, p, "v2\n");
	}
	const meta: nix.Meta = .{ .locked_url = "", .rev = null, .nar_hash = "", .source_path = src };

	// The live v1 tree and a snapshot that hard-links its files (cp -al).
	const live_sub = try inst.path("plugin-sources/p/sub");
	defer a.free(live_sub);
	const snap_sub = try inst.path("snap/src/p/sub");
	defer a.free(snap_sub);
	const files = [_][]const u8{ "default.nix", "sub/a.txt" };
	const plant = struct {
		fn run(i: *const TestInstance, tio: std.Io, live: []const u8, snap: []const u8) !void {
			const d = std.Io.Dir.cwd();
			try d.createDirPath(tio, live);
			try d.createDirPath(tio, snap);
			for (files) |rel| {
				const lp = try std.fmt.allocPrint(t.allocator, "{s}/plugin-sources/p/{s}", .{ i.root, rel });
				defer t.allocator.free(lp);
				const sp = try std.fmt.allocPrint(t.allocator, "{s}/snap/src/p/{s}", .{ i.root, rel });
				defer t.allocator.free(sp);
				d.deleteFile(tio, sp) catch {};
				try testWriteFile(tio, lp, "v1\n");
				try d.hardLink(lp, d, sp, tio, .{});
			}
		}
	}.run;
	const expectSnapV1 = struct {
		fn run(i: *const TestInstance, tio: std.Io) !void {
			for (files) |rel| {
				const sp = try std.fmt.allocPrint(t.allocator, "{s}/snap/src/p/{s}", .{ i.root, rel });
				defer t.allocator.free(sp);
				const got = try testReadFile(tio, sp);
				defer t.allocator.free(got);
				try t.expectEqualStrings("v1\n", got);
			}
		}
	}.run;

	// 1. A normal re-materialize: live becomes v2, the snapshot keeps v1.
	try plant(&inst, io, live_sub, snap_sub);
	try materializeSource(&c, "p", &meta, "unused");
	try expectSnapV1(&inst, io);
	{
		const lp = try inst.path("plugin-sources/p/sub/a.txt");
		defer a.free(lp);
		const got = try testReadFile(io, lp);
		defer a.free(got);
		try t.expectEqualStrings("v2\n", got);
	}

	// 2. removeSource (del) leaves the snapshot's files intact.
	removeSource(&c, "p");
	try expectSnapV1(&inst, io);

	// 3. materialize's deleteTree fails: sub/ is read-only, so sub/a.txt survives
	// it. cp must not truncate that surviving file in place (it is the
	// snapshot's inode); unable to unlink it, it fails instead, and the caller
	// warns as for any failed materialize.
	try plant(&inst, io, live_sub, snap_sub);
	try cwd.setFilePermissions(io, live_sub, .fromMode(0o555), .{});
	materializeSource(&c, "p", &meta, "unused") catch {};
	try expectSnapV1(&inst, io);
}

// The same guarantee end to end: a snapshot taken by snapshot.take (the
// apply's S, the shape of the launcher's boot snapshot) keeps the version it
// took through a later update's re-materialize and a del's removeSource.
test "a snapshot.take src/ survives materializeSource and removeSource unchanged" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{ .environ = std.testing.environ });
	defer threaded.deinit();
	const io = threaded.io();
	const a = t.allocator;
	var inst = try TestInstance.init(io, "snap-take");
	defer inst.deinit(io);
	const c = inst.ctx(io);

	const src_sub = try inst.path("store-src/sub");
	defer a.free(src_sub);
	try std.Io.Dir.cwd().createDirPath(io, src_sub);
	inline for (.{ "store-src/flake.nix", "store-src/sub/a.txt" }) |rel| {
		const p = try inst.path(rel);
		defer a.free(p);
		try testWriteFile(io, p, "v2\n");
	}
	const src = try inst.path("store-src");
	defer a.free(src);
	const meta: nix.Meta = .{ .locked_url = "", .rev = null, .nar_hash = "", .source_path = src };

	const live_sub = try inst.path("plugin-sources/p/sub");
	defer a.free(live_sub);
	try std.Io.Dir.cwd().createDirPath(io, live_sub);
	inline for (.{ "plugin-sources/p/flake.nix", "plugin-sources/p/sub/a.txt" }) |rel| {
		const p = try inst.path(rel);
		defer a.free(p);
		try testWriteFile(io, p, "v1\n");
	}
	const cfg = try std.json.parseFromSlice(std.json.Value, a, "{\"plugins\": [{\"name\": \"p\"}]}", .{});
	defer cfg.deinit();
	const id = try snapshot.take(a, io, inst.root, cfg.value, .{});

	const expectSnapV1 = struct {
		fn run(i: *const TestInstance, tio: std.Io, sid: []const u8) !void {
			for ([_][]const u8{ "flake.nix", "sub/a.txt" }) |rel| {
				const sp = try std.fmt.allocPrint(t.allocator, "{s}/apply/snap/{s}/src/p/{s}", .{ i.root, sid, rel });
				defer t.allocator.free(sp);
				const got = try testReadFile(tio, sp);
				defer t.allocator.free(got);
				try t.expectEqualStrings("v1\n", got);
			}
		}
	}.run;

	try materializeSource(&c, "p", &meta, "unused");
	try expectSnapV1(&inst, io, &id);
	{
		const lp = try inst.path("plugin-sources/p/sub/a.txt");
		defer a.free(lp);
		const got = try testReadFile(io, lp);
		defer a.free(got);
		try t.expectEqualStrings("v2\n", got);
	}
	removeSource(&c, "p");
	try expectSnapV1(&inst, io, &id);
}

// The unlink-before-write must not hinge on cp's link-preserving heuristic
// (which unlinks only a destination with more than one link): the flag is
// pinned, next to the -a whose mode preservation the narHash needs.
test "materializeSource copies with cp -a --remove-destination" {
	var has_a = false;
	var has_remove = false;
	for (materialize_cp_flags) |f| {
		if (std.mem.eql(u8, f, "-a")) has_a = true;
		if (std.mem.eql(u8, f, "--remove-destination")) has_remove = true;
	}
	try t.expectEqualStrings("cp", materialize_cp_flags[0]);
	try t.expect(has_a and has_remove);
}

test "liveDecision: inline only on a running instance, with --apply or on a terminal outside cogworx; COGBOX_LIVE_APPLY=0 defers" {
	var env = std.process.Environ.Map.init(t.allocator);
	defer env.deinit();
	// A stopped instance: the change loads at the next start, whatever the flags.
	for ([_]cli.LiveChoice{ null, true, false }) |c| try t.expectEqual(LiveDecision.not_running, liveDecision(false, c, true, &env));
	// A terminal applies by default; a non-terminal never does without --apply.
	try t.expectEqual(LiveDecision.inline_apply, liveDecision(true, null, true, &env));
	try t.expectEqual(LiveDecision.deferred, liveDecision(true, null, false, &env));
	// --apply applies on any stderr; --no-apply defers on a terminal.
	try t.expectEqual(LiveDecision.inline_apply, liveDecision(true, true, false, &env));
	try t.expectEqual(LiveDecision.deferred, liveDecision(true, false, true, &env));
	// Under cogworx a terminal is not enough (the control plane runs its own
	// apply); --apply still applies.
	try env.put("COGBOX_ENVIRONMENT", "cogworx");
	try t.expectEqual(LiveDecision.deferred, liveDecision(true, null, true, &env));
	try t.expectEqual(LiveDecision.inline_apply, liveDecision(true, true, false, &env));
	// The local off switch defers everything, --apply included.
	try env.put("COGBOX_LIVE_APPLY", "0");
	try t.expectEqual(LiveDecision.deferred, liveDecision(true, true, true, &env));
	try env.put("COGBOX_ENVIRONMENT", "local");
	try t.expectEqual(LiveDecision.deferred, liveDecision(true, null, true, &env));
	try env.put("COGBOX_LIVE_APPLY", "1");
	try t.expectEqual(LiveDecision.inline_apply, liveDecision(true, null, true, &env));
}

test "rejectedLine: rolled back only when the rollback is done; removed, pending and blocked each say what happened" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	// The report as the inline apply reads it back: the line runApply writes.
	const Rep = struct {
		fn of(al: std.mem.Allocator, reason: apply.Reason, out: ?apply.RollbackOut) !std.json.ObjectMap {
			const line = try apply.reportLine(al, .{ .gen = "0123456789abcdef", .op = "update", .result = .rejected, .reason = reason, .detail = null, .overridable = false, .plan = null, .forced = null, .rollback = out, .runner = null, .toplevel = null, .units = null, .rolled_back_guest = null, .cap = null, .base_id = null, .built_id = null });
			const v = try std.json.parseFromSliceLeaky(std.json.Value, al, line, .{});
			return v.object.get("apply").?.object;
		}
		fn rb(status: apply.RollbackStatus, names: []const rollback.RecordName) apply.RollbackOut {
			return .{ .status = status, .target = .base, .target_id = "00000000000000bb", .names = names };
		}
	};
	const upd: []const rollback.RecordName = &.{.{ .name = "x", .action = .restored }};
	const del: []const rollback.RecordName = &.{.{ .name = "x", .action = .reinserted }};

	try t.expectEqualStrings("'x' was not applied and has been rolled back: its activation did not finish. Build log: cogbox plugin apply -n demo --log 0123456789abcdef", try rejectedLine(a, "x", try Rep.of(a, .activation_hang, Rep.rb(.done, upd)), 0, " -n demo"));

	// The fail-closed tier: an update's plugin is gone, not back at its old
	// version; a del's plugin is not put back.
	const removed = try rejectedLine(a, "x", try Rep.of(a, .activation_hang, Rep.rb(.removed, upd)), 0, " -n demo");
	try t.expect(std.mem.indexOf(u8, removed, "rolled back") == null);
	try t.expectEqualStrings("'x' was not applied: its activation did not finish. Its previous plugin state could not be restored, so the plugins it added or updated were removed. Build log: cogbox plugin apply -n demo --log 0123456789abcdef", removed);
	try t.expectEqualStrings("'x' was not applied: its activation did not finish. Its previous plugin state could not be restored, so the plugins it removed stay removed. Build log: cogbox plugin apply -n demo --log 0123456789abcdef", try rejectedLine(a, "x", try Rep.of(a, .activation_hang, Rep.rb(.removed, del)), 0, " -n demo"));

	// Pending (the step-10 config lock could not be had), and a report without
	// a rollback object, which never reads as done.
	const pending = "'x' was not applied: its NixOS configuration does not evaluate. Its rollback is pending; the next plugin command or start of the instance finishes it. Build log: cogbox plugin apply --log 0123456789abcdef";
	try t.expectEqualStrings(pending, try rejectedLine(a, "x", try Rep.of(a, .eval_error, Rep.rb(.pending, &.{})), 0, ""));
	try t.expectEqualStrings(pending, try rejectedLine(a, "x", try Rep.of(a, .eval_error, null), 0, ""));

	// Exit 78: the finish could not complete, its stamped message is already
	// on stderr, and the next plugin command or start does not finish it.
	const blocked = try rejectedLine(a, "x", try Rep.of(a, .activation_hang, Rep.rb(.pending, &.{})), 78, " -n demo");
	try t.expect(std.mem.indexOf(u8, blocked, "next plugin command") == null);
	try t.expectEqualStrings("'x' was not applied: its activation did not finish. Its rollback could not be finished (see the message above). Build log: cogbox plugin apply -n demo --log 0123456789abcdef", blocked);

	try t.expect(std.mem.startsWith(u8, try rejectedLine(a, null, try Rep.of(a, .unit_hang, Rep.rb(.pending, &.{})), 0, ""), "The plugin update was not applied: a unit it starts"));
}
