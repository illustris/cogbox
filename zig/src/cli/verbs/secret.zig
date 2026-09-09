// `cogbox secret` - bind/list/remove operator-held credentials in the global
// host-side secret store (<config>/secrets/). Plugins REQUEST a secret by name
// + audience (cogboxPlugins.<attr>.inject); the operator binds the value here so
// it stays host-side and out of the guest. Mirrors verbs/l7.zig's shape but
// resolves the GLOBAL store (no --name), since operator secrets are shared
// across an account's instances.
//
// Binding/removing a secret changes which credentials are injectable, but the
// per-instance inject conf the running L7 proxy reads (l7-inject-conf.json) is
// only rendered at boot. So when an instance is named with -n, after the
// mutation we re-render THAT instance's runtime files (rules_module.renderFiles,
// which calls writeL7Inject) and signal BOTH consumers -- SIGHUP the L7 proxy and
// SIGUSR1 passt (whose LD_PRELOAD shim owns netfilter-rules) -- so a bind takes
// effect on a RUNNING VM without a restart: the addon hot-reloads the conf on
// mtime, and the shim reloads the funnel the render may have just added.
// `cogbox secret reload -n NAME` does only the re-render (no store change), for a
// secret that was already bound (e.g. before this behavior existed).

const std = @import("std");
const help = @import("../help.zig");
const parse = @import("../parse.zig");
const util = @import("../util.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");
const secret_module = @import("secret_module");
const rules_module = @import("rules_module");

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	p: *const paths.Paths,
	argv: []const []const u8,
) !void {
	// Pull out -n/--name and -h/--help; the rest is the secret subcommand. The
	// secret store itself is global (no -n), but -n names the instance whose
	// inject conf to re-render after a mutation.
	var name: ?[]const u8 = null;
	var rest: std.ArrayList([]const u8) = .empty;
	defer rest.deinit(allocator);

	var i: usize = 0;
	while (i < argv.len) : (i += 1) {
		const a = argv[i];
		if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
			try help.print(io, help.SECRET);
			return;
		}
		if (std.mem.eql(u8, a, "--name") or std.mem.eql(u8, a, "-n")) {
			i += 1;
			if (i >= argv.len) util.die(allocator, io, "secret", exit_codes.usage, "{s} requires a value", .{a});
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
			util.die(allocator, io, "secret", exit_codes.dataerr, "'default' is reserved. Omit --name to use the default instance.", .{});
		}
		if (!parse.isValidName(n)) {
			util.die(allocator, io, "secret", exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
		}
	}

	// `secret reload -n NAME`: re-render an instance's inject conf from the
	// already-bound store + signal its proxy. No store mutation.
	if (rest.items.len > 0 and std.mem.eql(u8, rest.items[0], "reload")) {
		const n = name orelse util.die(allocator, io, "secret", exit_codes.usage, "secret reload requires -n NAME", .{});
		try reRenderInstance(allocator, io, env, p, n, true);
		return;
	}

	// The store the operator binds into. The container enforcer keeps it on an
	// ENFORCER-PRIVATE volume (never the agent-readable PVC), so honor the same
	// COGBOX_GLOBAL_SECRETS_DIR override the renderer (resolveSecretDirs) reads;
	// otherwise the historical <config>/secrets is used. WRITE and READ must
	// agree on one location, else a bind would render against the wrong store.
	const secrets_dir = if (env.get("COGBOX_GLOBAL_SECRETS_DIR")) |d|
		try allocator.dupe(u8, d)
	else
		try paths.globalSecretsDir(allocator, p);
	defer allocator.free(secrets_dir);

	// `env` reaches the store so a bind can stage the L7 proxy's read access
	// (COGBOX_PROXY_RUNAS) into the same atomic write -- the same variable the
	// re-render below resolves for its grant pass, so the two cannot name
	// different identities.
	try secret_module.dispatch(allocator, io, secrets_dir, rest.items, env);

	// After a bind/remove that changes injectable state, re-render the named
	// instance so a running proxy picks it up without a restart. Best-effort:
	// the store mutation already succeeded, so a render failure (instance not
	// running / not inited) must not fail the command.
	if (name) |n| {
		if (rest.items.len > 0 and isMutation(rest.items[0])) {
			reRenderInstance(allocator, io, env, p, n, false) catch |err| {
				util.warn(allocator, io, "secret bound, but re-rendering {s}'s inject conf failed ({s}); it will apply on the instance's next start", .{ n, @errorName(err) }) catch {};
			};
		}
	}
}

fn isMutation(sub: []const u8) bool {
	return std.mem.eql(u8, sub, "add") or std.mem.eql(u8, sub, "rm") or
		std.mem.eql(u8, sub, "del") or std.mem.eql(u8, sub, "delete");
}

/// Re-render instance `name`'s runtime files (incl. l7-inject-conf.json) from
/// its config + the now-current secret store, then signal both live consumers
/// (SIGHUP the L7 proxy, SIGUSR1 passt's shim -- see below). Skips
/// quietly when the instance isn't inited or isn't running (no live runtime dir)
/// -- the boot render covers that case. `announce` adds a user-facing line (for
/// the explicit `reload` verb).
fn reRenderInstance(allocator: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map, p: *const paths.Paths, name: []const u8, announce: bool) !void {
	const inst_cfg = try paths.instanceConfigDir(allocator, p, name);
	defer allocator.free(inst_cfg);
	const cfg_path = try std.fs.path.join(allocator, &.{ inst_cfg, "config.json" });
	defer allocator.free(cfg_path);
	const inst_runtime = try paths.instanceRuntime(allocator, p, name);
	defer allocator.free(inst_runtime);

	const cwd = std.Io.Dir.cwd();
	cwd.access(io, cfg_path, .{}) catch {
		if (announce) try util.say(allocator, io, "No config for '{s}' -- nothing to render.", .{name});
		return;
	};
	// No live runtime dir => the instance isn't running; the boot render will
	// pick up the binding on next start.
	cwd.access(io, inst_runtime, .{}) catch {
		if (announce) try util.say(allocator, io, "Instance '{s}' is not running; inject conf will render at its next start.", .{name});
		return;
	};

	// A LIVE instance (the access() above proved it): its l7-inject-conf.json
	// already carries the launcher's harness merge, so preserve what this render
	// does not author -- see reload.writeL7Inject's two-writer contract.
	try rules_module.renderFiles(allocator, io, env, cfg_path, inst_runtime, .preserve);
	_ = rules_module.reload.maybeSignalL7proxy(allocator, io, inst_runtime) catch {};
	// BOTH signals, for the same reason rules_module.maybeReload sends both: the
	// render now SEEDS the control-plane inject specs, and netfilter-rules' L7
	// funnel remaps + fail-closed denies are DERIVED from those specs -- so a
	// secret mutation on this path can change netfilter-rules, not just l7-rules
	// and the inject conf. The LD_PRELOAD shim inside passt re-reads that file
	// ONLY on SIGUSR1 (netfilter/main.zig handleSigusr1), so without this a
	// connect-later bind on a live VM would render the funnel to disk while the
	// guest's :443 kept egressing directly -- the placeholder credential goes
	// upstream and the harness stays logged out until a restart. No-op wherever
	// there is no passt (the container enforcer writes no passt.pid).
	_ = rules_module.reload.maybeSignalPasst(allocator, io, inst_runtime) catch {};
	if (announce) try util.say(allocator, io, "Re-rendered inject conf for '{s}' and signalled its proxy.", .{name});
}

// --- tests ------------------------------------------------------------------
//
// The live-reload signalling contract of `secret reload`. Since the render seeds
// the control-plane inject specs, a secret mutation can now change
// netfilter-rules (the L7 funnel remaps and the fail-closed denies are derived
// from the specs) -- and netfilter-rules is owned by the LD_PRELOAD shim inside
// passt, which re-reads it ONLY on SIGUSR1. Signalling just the L7 proxy is
// therefore not enough on a running VM.
//
// "Was a signal attempted" needs a real process to observe, so the tests point
// the runtime pidfiles at the test process itself and catch the two signals.

/// One throwaway instance under a random root, in the fixed shape `paths`
/// resolves: `<root>/cfg` is `<config>/cogbox` (so the instance config lands at
/// `<root>/cfg/instances/web/config.json` and the GLOBAL secret store -- what
/// cogworx's claude bind writes -- at `<root>/cfg/secrets`), and the per-instance
/// runtime dir is `<root>/rt-web`. Returns the root; caller deletes the tree.
fn tmpRoot(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	return std.fmt.allocPrint(gpa, "zig-secretreload-test-{s}", .{hexb});
}

fn writeTestFile(io: std.Io, path: []const u8, bytes: []const u8) !void {
	const f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
	defer f.close(io);
	var wbuf: [4096]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn readTestFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
	const f = try std.Io.Dir.cwd().openFile(io, path, .{});
	defer f.close(io);
	var rbuf: [4096]u8 = undefined;
	var r = f.reader(io, &rbuf);
	return r.interface.allocRemaining(gpa, .limited(1 << 20));
}

/// Lay the instance out and return the four paths the caller needs (and frees).
/// `pidfiles` are created in the runtime dir pointing at THIS process, so a signal
/// the verb sends lands on our handlers. `bind_claude` performs the bind cogworx's
/// claude reconcile does (kind=anthropic-oauth, audience=api.anthropic.com) into
/// the global store.
fn stageInstance(
	gpa: std.mem.Allocator,
	io: std.Io,
	pidfiles: []const []const u8,
	bind_claude: bool,
) !struct { root: []u8, runtime: []u8, config_dir: []u8, base_runtime: []u8 } {
	const cwd = std.Io.Dir.cwd();
	const root = try tmpRoot(gpa, io);
	const config_dir = try std.fmt.allocPrint(gpa, "{s}/cfg", .{root});
	const base_runtime = try std.fmt.allocPrint(gpa, "{s}/rt", .{root});

	const inst_dir = try std.fmt.allocPrint(gpa, "{s}/instances/web", .{config_dir});
	defer gpa.free(inst_dir);
	try cwd.createDirPath(io, inst_dir);
	const cfg_path = try std.fmt.allocPrint(gpa, "{s}/config.json", .{inst_dir});
	defer gpa.free(cfg_path);
	// The default rules-mode network a cogworx-managed sandbox boots with: an L4
	// allow-list and NO `.l7` key at all, so the funnel appears only once a seed
	// lands.
	try writeTestFile(io, cfg_path,
		\\{"network":{"rules":[{"deny":"169.254.0.0/16"},{"allow":"0.0.0.0/0"}]}}
		\\
	);

	// `paths.instanceRuntime` = `<base_runtime>-<name>`.
	const runtime = try std.fmt.allocPrint(gpa, "{s}-web", .{base_runtime});
	try cwd.createDirPath(io, runtime);
	const pid = std.c.getpid();
	for (pidfiles) |pf| {
		const path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ runtime, pf });
		defer gpa.free(path);
		const body = try std.fmt.allocPrint(gpa, "{d}\n", .{pid});
		defer gpa.free(body);
		try writeTestFile(io, path, body);
	}

	if (bind_claude) {
		const store_dir = try std.fmt.allocPrint(gpa, "{s}/secrets", .{config_dir});
		defer gpa.free(store_dir);
		try secret_module.store.add(gpa, io, store_dir, secret_module.claude_oauth_secret, "sk-ant-oat01-FAKEFAKEFAKEFAKEFAKE", .{
			.audience = secret_module.anthropic_api_host,
			.kind = secret_module.anthropic_oauth_kind,
			.tier = "durable",
			.bound_at = 1,
		});
	}

	return .{ .root = root, .runtime = runtime, .config_dir = config_dir, .base_runtime = base_runtime };
}

test "secret re-render signals BOTH passt and the L7 proxy (the seeded funnel is netfilter-rules state)" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const S = struct {
		var usr1 = std.atomic.Value(bool).init(false);
		var hup = std.atomic.Value(bool).init(false);
		fn onUsr1(_: std.posix.SIG) callconv(.c) void {
			usr1.store(true, .release);
		}
		fn onHup(_: std.posix.SIG) callconv(.c) void {
			hup.store(true, .release);
		}
	};

	// A RUNNING VM: passt and the L7 proxy are both up, so both pidfiles exist.
	const st = try stageInstance(gpa, io, &.{ "passt.pid", "l7proxy.pid" }, true);
	defer gpa.free(st.root);
	defer gpa.free(st.runtime);
	defer gpa.free(st.config_dir);
	defer gpa.free(st.base_runtime);
	defer cwd.deleteTree(io, st.root) catch {};

	// SA_RESTART so a caught signal can't surface as EINTR in the surrounding I/O.
	var act: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
	act.flags = std.posix.SA.RESTART;
	act.handler.handler = S.onUsr1;
	var old_usr1: std.posix.Sigaction = undefined;
	std.posix.sigaction(std.posix.SIG.USR1, &act, &old_usr1);
	defer std.posix.sigaction(std.posix.SIG.USR1, &old_usr1, null);
	act.handler.handler = S.onHup;
	var old_hup: std.posix.Sigaction = undefined;
	std.posix.sigaction(std.posix.SIG.HUP, &act, &old_hup);
	defer std.posix.sigaction(std.posix.SIG.HUP, &old_hup, null);

	const p: paths.Paths = .{
		.real_user = "test",
		.real_home = st.root,
		.real_uid = 1000,
		.config_dir = st.config_dir,
		.base_data = st.root,
		.base_runtime = st.base_runtime,
		.allocator = gpa,
	};
	var env = std.process.Environ.Map.init(gpa);
	defer env.deinit();
	// Straight at reRenderInstance rather than `run(... "reload" ...)`: the verb
	// wrapper's only extra work is argv parsing plus the announce line, and under
	// `zig build test` the test runner owns stdout for its wire protocol -- a
	// util.say from inside a test would corrupt it. announce=false keeps this quiet.
	try reRenderInstance(gpa, io, &env, &p, "web", false);

	// The re-render DID change what the shim enforces: the seeded claude spec makes
	// l7Active true, so netfilter-rules now carries the funnel remap that was
	// absent from the config on disk.
	const nf_path = try std.fmt.allocPrint(gpa, "{s}/netfilter-rules", .{st.runtime});
	defer gpa.free(nf_path);
	const nf = try readTestFile(gpa, io, nf_path);
	defer gpa.free(nf);
	try std.testing.expect(std.mem.indexOf(u8, nf, "remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:") != null);

	// ...so BOTH consumers must have been told. SIGHUP alone (the omission this
	// test pins) leaves the shim on its stale ruleset: the guest's :443 keeps
	// egressing directly, the placeholder credential goes upstream, and the
	// harness stays logged out until a restart.
	try std.testing.expect(S.hup.load(.acquire));
	try std.testing.expect(S.usr1.load(.acquire));
}

test "secret re-render on a passt-less runtime (the container enforcer shape) signals only the proxy" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const S = struct {
		var usr1 = std.atomic.Value(bool).init(false);
		var hup = std.atomic.Value(bool).init(false);
		fn onUsr1(_: std.posix.SIG) callconv(.c) void {
			usr1.store(true, .release);
		}
		fn onHup(_: std.posix.SIG) callconv(.c) void {
			hup.store(true, .release);
		}
	};

	// The enforcer pod runs no VM: cogbox-enforce.sh writes l7mitm.pid and
	// l7proxy.pid, never passt.pid (only cogbox-launch.sh does). So the added
	// SIGUSR1 leg must be a genuine no-op there -- not an error, not a stray
	// signal at some unrelated pid.
	const st = try stageInstance(gpa, io, &.{"l7proxy.pid"}, true);
	defer gpa.free(st.root);
	defer gpa.free(st.runtime);
	defer gpa.free(st.config_dir);
	defer gpa.free(st.base_runtime);
	defer cwd.deleteTree(io, st.root) catch {};

	var act: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
	act.flags = std.posix.SA.RESTART;
	act.handler.handler = S.onUsr1;
	var old_usr1: std.posix.Sigaction = undefined;
	std.posix.sigaction(std.posix.SIG.USR1, &act, &old_usr1);
	defer std.posix.sigaction(std.posix.SIG.USR1, &old_usr1, null);
	act.handler.handler = S.onHup;
	var old_hup: std.posix.Sigaction = undefined;
	std.posix.sigaction(std.posix.SIG.HUP, &act, &old_hup);
	defer std.posix.sigaction(std.posix.SIG.HUP, &old_hup, null);

	const p: paths.Paths = .{
		.real_user = "test",
		.real_home = st.root,
		.real_uid = 1000,
		.config_dir = st.config_dir,
		.base_data = st.root,
		.base_runtime = st.base_runtime,
		.allocator = gpa,
	};
	var env = std.process.Environ.Map.init(gpa);
	defer env.deinit();
	// Straight at reRenderInstance rather than `run(... "reload" ...)`: the verb
	// wrapper's only extra work is argv parsing plus the announce line, and under
	// `zig build test` the test runner owns stdout for its wire protocol -- a
	// util.say from inside a test would corrupt it. announce=false keeps this quiet.
	try reRenderInstance(gpa, io, &env, &p, "web", false);

	try std.testing.expect(S.hup.load(.acquire));
	try std.testing.expect(!S.usr1.load(.acquire));
}

test "a RUNTIME bind's re-render grants the dropped L7 proxy read on the credential (not just the boot render)" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	// No pidfiles: this test is about the store permissions the re-render leaves
	// behind, and an unhandled SIGHUP at our own pid would kill the test process.
	const st = try stageInstance(gpa, io, &.{}, true);
	defer gpa.free(st.root);
	defer gpa.free(st.runtime);
	defer gpa.free(st.config_dir);
	defer gpa.free(st.base_runtime);
	defer cwd.deleteTree(io, st.root) catch {};

	const p: paths.Paths = .{
		.real_user = "test",
		.real_home = st.root,
		.real_uid = 1000,
		.config_dir = st.config_dir,
		.base_data = st.root,
		.base_runtime = st.base_runtime,
		.allocator = gpa,
	};

	// THE PATH THAT MATTERS. A Claude connect on a RUNNING sandbox arrives here --
	// `cogbox secret add ... -n <inst>` then `secret reload -n <inst>` over the
	// control channel -- long after the boot render. A one-shot chown in the host
	// image's boot script would have missed exactly this, so the environment the
	// control exec carries has to name the proxy identity (which is why the GCE
	// cogbox wrapper sets COGBOX_PROXY_RUNAS, asserted by gce-cogbox-wrapper-env).
	const gid: std.Io.File.Gid = @intCast(@import("platform").getgid());
	const runas = try std.fmt.allocPrint(gpa, "cogbox-proxy:{d}", .{gid});
	defer gpa.free(runas);
	var env = std.process.Environ.Map.init(gpa);
	defer env.deinit();
	try env.put("COGBOX_PROXY_RUNAS", runas);
	try reRenderInstance(gpa, io, &env, &p, "web", false);

	const cred = try std.fs.path.join(gpa, &.{ st.config_dir, "secrets", secret_module.claude_oauth_secret });
	defer gpa.free(cred);
	const st_cred = try cwd.statFile(io, cred, .{});
	try std.testing.expectEqual(@as(std.posix.mode_t, 0o640), st_cred.permissions.toMode() & 0o7777);
}
