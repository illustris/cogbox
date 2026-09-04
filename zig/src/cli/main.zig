// Top-level dispatcher for the cogbox CLI.

const std = @import("std");
const util = @import("util.zig");
const help = @import("help.zig");
const exit_codes = @import("exit.zig");
const paths = @import("paths.zig");
const preflight = @import("preflight.zig");

const list_verb = @import("verbs/list.zig");
const status_verb = @import("verbs/status.zig");
const stop_verb = @import("verbs/stop.zig");
const delete_verb = @import("verbs/delete.zig");
const restart_verb = @import("verbs/restart.zig");
const ssh_verb = @import("verbs/ssh.zig");
const rules_verb = @import("verbs/rules.zig");
const remap_verb = @import("verbs/remap.zig");
const l7_verb = @import("verbs/l7.zig");
const plugin_verb = @import("verbs/plugin.zig");
const secret_verb = @import("verbs/secret.zig");
const run_verb = @import("verbs/run.zig");
const rules_module = @import("rules_module");
const l7proxy_module = @import("l7proxy_module");
const authproxy_module = @import("authproxy_module");
const divertshim_module = @import("divertshim_module");
const filter_mod = @import("filter");
const start_verb = @import("verbs/start.zig");
const attach_verb = @import("verbs/attach_verb.zig");
const attach = @import("attach.zig");
const enforce_verb = @import("verbs/enforce.zig");
const claude_stub_verb = @import("verbs/claude_stub.zig");

const KNOWN_VERBS = [_][]const u8{
	"start", "stop",  "restart", "status",  "list",    "init",
	"ssh",   "rules", "remap",   "l7",      "plugin",  "secret",
	"console", "monitor", "delete", "help",
	// Hidden re-exec / helper targets, recognized below but omitted from
	// help: "__launch" (re-exec), "__l7proxy" (the host-side L7 proxy),
	// "__render-rules" (boot-time runtime-file renderer), "enforce" (the
	// container enforcer sidecar's PID1 supervisor entrypoint),
	// "__divertshim" (the separate-pod enforcer's in-pod nft-REDIRECT shim),
	// "__claude-stub" (the container agent's marker-gated Claude stub-staging),
	// "__authproxy" (the per-sandbox pluggable auth proxy for migrated git
	// providers).
	"__launch", "__l7proxy", "__render-rules", "enforce", "__divertshim",
	"__claude-stub", "__authproxy",
};

pub fn main(init: std.process.Init) !void {
	const allocator = init.gpa;
	const io = init.io;
	const env = init.environ_map;

	const argv_full = try init.minimal.args.toSlice(init.arena.allocator());
	const argv: []const []const u8 = blk: {
		const slice = try init.arena.allocator().alloc([]const u8, argv_full.len);
		for (argv_full, 0..) |a, i| slice[i] = a;
		break :blk if (slice.len > 0) slice[1..] else &.{};
	};

	// Top-level --help / -h before any verb resolution. This way
	// `cogbox --help` and `cogbox` both behave intuitively.
	if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
		try help.print(io, help.TOP_LEVEL);
		return;
	}

	// Reject removed flags with a clear redirect.
	if (argv.len > 0) {
		if (std.mem.eql(u8, argv[0], "--list")) {
			util.die(allocator, io, null, exit_codes.usage, "--list was removed; use 'cogbox list'", .{});
		}
		if (std.mem.eql(u8, argv[0], "--init-only")) {
			util.die(allocator, io, null, exit_codes.usage, "--init-only was removed; use 'cogbox init'", .{});
		}
		if (std.mem.eql(u8, argv[0], "run")) {
			util.die(allocator, io, null, exit_codes.usage, "'run' was removed. Bare 'cogbox' now starts in the background; add -f/--foreground to attach the console.", .{});
		}
	}

	// Determine verb. If argv[0] is a known verb, that's the verb.
	// Otherwise (no args, or first arg looks like a flag), default to
	// `start` -- bare `cogbox` launches in the background.
	var verb: []const u8 = "start";
	var rest = argv;
	if (argv.len > 0) {
		if (isKnownVerb(argv[0])) {
			verb = argv[0];
			rest = argv[1..];
		}
	}

	// Resolve XDG paths and check for legacy migration before dispatch.
	var p = paths.resolve(allocator, io, env) catch |err| {
		util.die(allocator, io, null, exit_codes.software, "failed to resolve paths: {s}", .{@errorName(err)});
	};
	defer p.deinit();

	try preflight.run(allocator, io, env, &p);

	if (std.mem.eql(u8, verb, "help")) {
		if (rest.len == 0) {
			try help.print(io, help.TOP_LEVEL);
			return;
		}
		const body = help.forVerb(rest[0]) orelse {
			util.die(allocator, io, null, exit_codes.usage, "unknown verb '{s}'", .{rest[0]});
		};
		try help.print(io, body);
		return;
	}

	if (std.mem.eql(u8, verb, "list")) return list_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "status")) return status_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "stop")) return stop_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "delete")) return delete_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "restart")) return restart_verb.run(allocator, io, env, &p, rest);
	if (std.mem.eql(u8, verb, "ssh")) return ssh_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "rules")) return rules_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "remap")) return remap_verb.run(allocator, io, &p, rest);
	if (std.mem.eql(u8, verb, "l7")) return l7_verb.run(allocator, io, env, &p, rest);
	if (std.mem.eql(u8, verb, "plugin")) return plugin_verb.run(allocator, io, env, &p, rest);
	if (std.mem.eql(u8, verb, "secret")) return secret_verb.run(allocator, io, env, &p, rest);
	if (std.mem.eql(u8, verb, "enforce")) return enforce_verb.run(allocator, io, env, rest);
	if (std.mem.eql(u8, verb, "__l7proxy")) {
		if (rest.len < 1) util.die(allocator, io, null, exit_codes.usage, "__l7proxy requires a runtime dir [l7-base-port]", .{});
		// Optional L7 port base (default canonical); the launcher passes the
		// instance's allocated base so per-instance ports don't collide.
		const base: u16 = if (rest.len >= 2)
			std.fmt.parseInt(u16, rest[1], 10) catch filter_mod.l7_default_base
		else
			filter_mod.l7_default_base;
		// Accept mode: COGBOX_L7_ACCEPT=redirect selects the container enforcer's
		// nft-REDIRECT front door (orig dst via SO_ORIGINAL_DST); anything else
		// (incl. unset / "socks5") keeps the unchanged SOCKS5 VM/launch path.
		const accept_mode: l7proxy_module.AcceptMode = if (env.get("COGBOX_L7_ACCEPT")) |v|
			(if (std.mem.eql(u8, v, "redirect")) .redirect else .socks5)
		else
			.socks5;
		// Front-door bind address (COGBOX_L7_LISTEN_ADDR, IPv4 dotted-quad). Default
		// 127.0.0.1 keeps the VM/launch path byte-identical; the enforcer pod sets
		// 0.0.0.0 so the agent pod's shim reaches it cross-pod. Fail-closed: an
		// unparseable value falls back to loopback (never accidentally 0.0.0.0).
		const listen_addr: u32 = if (env.get("COGBOX_L7_LISTEN_ADDR")) |v|
			(if (filter_mod.parseIpv4(v)) |b| std.mem.readInt(u32, &b, .big) else 0x7f000001)
		else
			0x7f000001;
		// COGBOX_L7_FUNNEL_ALL=1: route the socks5 .deny arm to the raw-L4 gate (the
		// separate-pod enforcer funnels every port over one socks5 hop). Default off.
		const funnel_all = if (env.get("COGBOX_L7_FUNNEL_ALL")) |v|
			(std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "true"))
		else
			false;
		// COGBOX_L7_PEEK_MS: fast-path classification-peek deadline (ms) for the
		// raw-L4-eligible silent-client case (SSH/SMTP/...). Default 300. Fail-safe
		// both directions in run(): an unparseable/non-positive value falls back to
		// the default (never uncaps the peek), and a tiny positive value is floored
		// (never small enough to skip classifying a prompt client).
		const peek_ms: i32 = if (env.get("COGBOX_L7_PEEK_MS")) |v|
			(std.fmt.parseInt(i32, v, 10) catch 300)
		else
			300;
		return l7proxy_module.run(allocator, rest[0], base, accept_mode, listen_addr, funnel_all, peek_ms);
	}
	if (std.mem.eql(u8, verb, "__authproxy")) {
		if (rest.len < 1) util.die(allocator, io, null, exit_codes.usage, "__authproxy requires a runtime dir [l7-base-port]", .{});
		// Optional L7 port base (default canonical); the launcher passes the
		// instance's allocated base so the auth listen port (base - 400)
		// doesn't collide -- mirrors __l7proxy's parse exactly. Unlike
		// __l7proxy, the auth proxy is threaded std.Io (init.io) for the
		// trust-store load and the conf/cred file reads.
		const base: u16 = if (rest.len >= 2)
			std.fmt.parseInt(u16, rest[1], 10) catch filter_mod.l7_default_base
		else
			filter_mod.l7_default_base;
		return authproxy_module.run(allocator, io, env, rest[0], base);
	}
	if (std.mem.eql(u8, verb, "__divertshim")) {
		// The separate-pod enforcer's in-pod nft-REDIRECT shim. Listens on
		// COGBOX_DIVERT_LISTEN, recovers SO_ORIGINAL_DST, and SOCKS5-CONNECTs the
		// dst to COGBOX_ENFORCER_ADDR (the enforcer's stable ClusterIP:base). Both
		// env vars are required; fail-closed (no default enforcer) on either.
		const lp = env.get("COGBOX_DIVERT_LISTEN") orelse util.die(allocator, io, null, exit_codes.usage, "__divertshim requires COGBOX_DIVERT_LISTEN", .{});
		const listen_port = std.fmt.parseInt(u16, lp, 10) catch util.die(allocator, io, null, exit_codes.usage, "COGBOX_DIVERT_LISTEN must be a port number", .{});
		if (listen_port == 0) util.die(allocator, io, null, exit_codes.usage, "COGBOX_DIVERT_LISTEN must be a non-zero port", .{});
		const ea = env.get("COGBOX_ENFORCER_ADDR") orelse util.die(allocator, io, null, exit_codes.usage, "__divertshim requires COGBOX_ENFORCER_ADDR (ip:port)", .{});
		const enforcer = divertshim_module.parseEnforcerAddr(ea) orelse util.die(allocator, io, null, exit_codes.usage, "COGBOX_ENFORCER_ADDR must be IPv4 ip:port", .{});
		return divertshim_module.run(listen_port, enforcer);
	}
	if (std.mem.eql(u8, verb, "__render-rules")) {
		if (rest.len < 2) util.die(allocator, io, null, exit_codes.usage, "__render-rules requires <config> <runtime>", .{});
		// The launcher/enforcer render, and the only `.replace` caller. On the VM
		// path it is the BOOT render: cogbox-launch.sh runs it before the proxies
		// start and then merges the harness inject specs on top of what it wrote,
		// so this is the authoritative reset -- carrying the PREVIOUS boot's merge
		// over would outlive the credentials it names (the runtime dir survives a
		// stop/start within a host session). On the container path (cogbox-enforce.sh
		// at start, plus cogworx's courier reconcile on a live enforcer) this
		// renderer is the file's ONLY writer, so there is nothing to preserve.
		// The choice is PINNED in the renderer (reload.boot_foreign_specs) with a
		// test on its value, so flipping the boot render to `.preserve` fails the
		// gate instead of silently carrying a dead spec into the next boot.
		return rules_module.renderFiles(allocator, io, env, rest[0], rest[1], rules_module.reload.boot_foreign_specs);
	}
	if (std.mem.eql(u8, verb, "__claude-stub")) return claude_stub_verb.run(allocator, io, rest);
	if (std.mem.eql(u8, verb, "console")) return attach_verb.run(allocator, io, &p, rest, attach.Target.console);
	if (std.mem.eql(u8, verb, "monitor")) return attach_verb.run(allocator, io, &p, rest, attach.Target.monitor);
	if (std.mem.eql(u8, verb, "init")) return run_verb.run(allocator, io, env, rest);
	if (std.mem.eql(u8, verb, "__launch")) return run_verb.launchInPlace(allocator, io, env, rest);
	if (std.mem.eql(u8, verb, "start")) return start_verb.run(allocator, io, env, &p, rest);

	util.die(allocator, io, null, exit_codes.usage, "unknown verb '{s}'", .{verb});
}

fn isKnownVerb(s: []const u8) bool {
	for (KNOWN_VERBS) |v| {
		if (std.mem.eql(u8, v, s)) return true;
	}
	return false;
}
