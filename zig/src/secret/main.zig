// `cogbox secret` verb. Binds operator-held credentials by NAME into the
// host-only secret store (see store.zig). Plugins REQUEST a secret by name +
// audience; the operator binds the actual value here. Values arrive only via
// --from-file or --from-stdin -- never on argv, which would leak into the
// process table / shell history.
//
//   cogbox secret add <name> --from-file F | --from-stdin
//        [--audience HOST] [--kind bearer|cookie|basic|anthropic-oauth] [-n INST]
//   cogbox secret ls [--json]
//   cogbox secret rm <name> [-n INST]
//   cogbox secret reload -n INST   (-n + reload handled by the cli verb layer:
//      re-render INST's inject conf so a bind applies to a running VM; this
//      module only writes the store.)

const std = @import("std");
pub const store = @import("store.zig");
pub const proxygid = @import("proxygid.zig");

/// The secret `kind` that selects HOST-SIDE Bearer injection for a Claude
/// `setup-token` (the per-user "Connect Claude" bind). It is admitted by the `--kind` allowlist below, and renderL7Inject
/// keys the `anthropic-oauth` inject style + the stub_token off a resolved
/// secret carrying this kind. Single-sourced here so the verb (which writes the
/// meta) and the renderer (which reads it) can never drift.
pub const anthropic_oauth_kind = "anthropic-oauth";

/// The redacted setup-token sentinel the host stamps into a Claude harness's
/// in-guest credential so it boots "logged-in but tokenless": the VM launcher's
/// write_stub_cred (cogbox-launch.sh harness_stub_token "claude-code") and the
/// container-backend stub-staging both write THIS exact string, and
/// renderL7Inject emits it as a kind=anthropic-oauth spec's `stub_token`. The
/// addon then REWRITES the real Bearer ONLY over this placeholder (should_inject)
/// and forwards any secondary credential the guest legitimately obtained
/// untouched. MUST equal harness_stub_token "claude-code" in cogbox-launch.sh.
pub const claude_stub_token = "sk-ant-oat01-cogbox-host-injected-placeholder";

/// The single host the per-user Claude credential may be stamped at: the
/// audience the `claude-oauth` secret is pinned to (renderL7Inject's exfiltration
/// gate) AND the host the container harness inject-spec seed targets
/// (rules/reload.zig seedClaudeInjectSpec). Single-sourced so the seed and the
/// bind can never name different hosts.
pub const anthropic_api_host = "api.anthropic.com";

/// The secret `kind` that selects HOST-SIDE path-dependent git injection (basic
/// auth `oauth2:<token>` on git smart-HTTP paths, Bearer elsewhere) for a
/// per-user GitLab (or any OAuth2 git host) access token. Admitted by the
/// `--kind` allowlist; renderL7Inject keys the `gitlab-oauth` inject style +
/// git_user off a resolved secret carrying this kind, and the container enforcer
/// SEEDS an inject spec for every bound secret of this kind (seedGitInjectSpecs).
/// Single-sourced so the verb, the seed and the renderer never drift.
pub const gitlab_oauth_kind = "gitlab-oauth";

/// The redacted git-token sentinel the host would stamp into a `glab` config so
/// a git harness boots "logged-in but tokenless" -- the addon's should_inject
/// stamps the real token ONLY over this placeholder (never a real one, which
/// lives only in the enforcer secret store). Wired here for when glab
/// stub-staging arrives (Phase 2); Phase 1 covers credential-less `git`, which
/// needs no in-guest stub. Single-sourced so the (future) stub-stager and the
/// renderer name one sentinel.
pub const gitlab_stub_token = "glpat-cogbox-host-injected-placeholder"; // gitleaks:allow

/// The default git username for basic-auth git smart-HTTP injection. GitLab
/// accepts any non-empty username paired with an OAuth2/PAT token as the
/// password; `oauth2` is the documented convention. renderL7Inject emits this
/// as the spec's `git_user` (a per-provider override is deferred to Phase 2).
pub const default_git_user = "oauth2";

/// The secret `kind` that routes a per-user git credential through the
/// per-sandbox AUTH PROXY (cogbox __authproxy) instead of addon injection.
/// It is a CROSS-REPO CONTRACT string doing DOUBLE DUTY by design:
///   1. the VERSION GATE -- an old binary's validKind refuses it with exit 65,
///      so on a pre-authproxy image no credential can exist at all (the control
///      plane's bind fails by the old binary's own hand, no CP bookkeeping);
///   2. the INJECT SUPPRESSOR -- seedGitInjectSpecs (rules/reload.zig) keys on
///      gitlab_oauth_kind, so a secret bound under THIS kind is never seeded
///      into an inject spec: no spec, no whole-host terminate-allow union, and
///      the mitm addon can never double-stamp a host the auth proxy already
///      authenticates. renderAuthProxyConf is this kind's only render consumer.
pub const gitlab_authproxy_kind = "gitlab-authproxy";

/// The reserved secret NAME cogworx binds the per-user Claude setup-token into
/// kind=anthropic-oauth, audience=api.anthropic.com. // gitleaks:allow
/// The container enforcer seeds an inject spec referencing THIS name so a bound
/// token actually renders; the bind alone is inert without the spec. Single-sourced
/// here so the seed, the renderer, and the cogworx bind all name one secret -- a
/// typo would silently break injection (fail-closed, but invisibly).
pub const claude_oauth_secret = "claude-oauth";

/// The redacted in-guest Claude credential the CONTAINER agent stages so
/// claude-code boots "logged-in but tokenless" (the step-5b container stub-staging). It mirrors the VM launcher's
/// write_stub_cred (cogbox-launch.sh): accessToken = the shared stub sentinel
/// (claude_stub_token -- the enforcer's mitm addon stamps the real Bearer ONLY
/// over THIS placeholder, never a real token, which lives only in the enforcer
/// secret store), a sentinel refreshToken that can never refresh in-guest, a
/// far-future expiry so the guest never tries (and fails) to refresh the
/// placeholder locally, and the read-only OAuth scopes that keep a logged-in
/// identity. Single-sourced off claude_stub_token so the staged stub, the VM
/// redactor, and the addon's should_inject can never name different sentinels.
/// Caller owns the returned bytes.
pub fn stubCredentialJson(allocator: std.mem.Allocator) ![]u8 {
	return std.fmt.allocPrint(allocator,
		"{{\"claudeAiOauth\":{{\"accessToken\":\"{s}\",\"refreshToken\":\"cogbox-evicted-no-refresh-token-in-guest\",\"expiresAt\":9999999999000,\"scopes\":[\"user:inference\",\"user:profile\"]}}}}\n",
		.{claude_stub_token},
	);
}

/// The injection styles a `cogbox secret add --kind` may carry. `bearer`,
/// `cookie` and `basic` are the operator/plugin credential primitives; the
/// per-user Claude bind adds `anthropic-oauth` (a long-lived setup-token the
/// enforcer stamps as a Bearer, gated by the redacted in-guest stub), and the
/// auth-proxy git bind adds `gitlab-authproxy` (whose acceptance here IS the
/// rollout's version gate -- see gitlab_authproxy_kind). Pure, so the allowlist
/// is unit-testable without IO.
pub fn validKind(kind: []const u8) bool {
	return eql(kind, "bearer") or eql(kind, "cookie") or eql(kind, "basic") or
		eql(kind, anthropic_oauth_kind) or eql(kind, gitlab_oauth_kind) or
		eql(kind, gitlab_authproxy_kind);
}

/// `env` is only consulted for COGBOX_PROXY_RUNAS (the L7 proxy's uid split, see
/// proxygid.zig) so a bind can stage the proxy's read access into the same
/// atomic write. Null -- and an env without that variable -- keeps the store
/// exactly as it was: 0600, owner-only.
pub fn dispatch(
	allocator: std.mem.Allocator,
	io: std.Io,
	secrets_dir: []const u8,
	argv: []const []const u8,
	env: ?*const std.process.Environ.Map,
) !void {
	if (argv.len == 0) {
		return die(allocator, io, "usage: cogbox secret <add|ls|rm> ...", .{}, 64);
	}
	const sub = argv[0];
	const rest = argv[1..];
	if (eql(sub, "add")) return cmdAdd(allocator, io, secrets_dir, rest, env);
	if (eql(sub, "ls") or eql(sub, "list")) return cmdList(allocator, io, secrets_dir, rest);
	if (eql(sub, "rm") or eql(sub, "del") or eql(sub, "delete")) return cmdRm(allocator, io, secrets_dir, rest);
	return die(allocator, io, "unknown subcommand '{s}' (expected add|ls|rm)", .{sub}, 64);
}

fn cmdAdd(allocator: std.mem.Allocator, io: std.Io, secrets_dir: []const u8, argv: []const []const u8, env: ?*const std.process.Environ.Map) !void {
	var name: ?[]const u8 = null;
	var from_file: ?[]const u8 = null;
	var from_stdin = false;
	var audience: ?[]const u8 = null;
	var kind: []const u8 = "bearer";

	var i: usize = 0;
	while (i < argv.len) : (i += 1) {
		const a = argv[i];
		if (flagValue(a, "--from-file", argv, &i)) |v| {
			from_file = v;
		} else if (eql(a, "--from-stdin")) {
			from_stdin = true;
		} else if (flagValue(a, "--audience", argv, &i)) |v| {
			audience = v;
		} else if (flagValue(a, "--kind", argv, &i)) |v| {
			kind = v;
		} else if (std.mem.startsWith(u8, a, "-")) {
			return die(allocator, io, "unknown flag '{s}'", .{a}, 64);
		} else if (name == null) {
			name = a;
		} else {
			return die(allocator, io, "unexpected argument '{s}'", .{a}, 64);
		}
	}

	const nm = name orelse return die(allocator, io, "secret add requires a <name>", .{}, 64);
	if (!store.validName(nm)) {
		return die(allocator, io, "invalid secret name '{s}' (use [A-Za-z0-9_-], max 64)", .{nm}, 65);
	}
	if (!validKind(kind)) {
		return die(allocator, io, "invalid --kind '{s}' (expected bearer|cookie|basic|anthropic-oauth|gitlab-oauth|gitlab-authproxy)", .{kind}, 65);
	}
	if (from_file != null and from_stdin) {
		return die(allocator, io, "--from-file and --from-stdin are mutually exclusive", .{}, 64);
	}

	const raw = blk: {
		if (from_file) |f| break :blk readFileAll(allocator, io, f) catch {
			return die(allocator, io, "cannot read --from-file {s}", .{f}, 66);
		};
		if (from_stdin) break :blk try readStdinAll(allocator, io);
		return die(allocator, io, "secret add needs a value source: --from-file F or --from-stdin", .{}, 64);
	};
	defer allocator.free(raw);
	const value = trimTrailingNewline(raw);
	if (value.len == 0) {
		return die(allocator, io, "refusing to bind an empty secret value", .{}, 65);
	}

	// Stamp the bind time into the meta so `secret ls --json` (and the cogworx
	// DB mirror of it) records WHEN a secret was bound -- groundwork for a UI
	// surface (nothing renders it yet; consumers treat 0/null as unset).
	const bound_at: i64 = @intCast(@divTrunc(std.Io.Clock.now(.real, io).nanoseconds, std.time.ns_per_s));
	const meta: store.Meta = .{
		.audience = audience,
		.kind = kind,
		.tier = "durable",
		.bound_at = bound_at,
	};
	// The L7 proxy's gid, where the deployment runs a uid split. Staged onto the
	// value file inside the same atomic write so the credential is readable by
	// the proxy the instant it lands, instead of only after the SEPARATE inject
	// render that follows this bind (rules/credgrant.zig) -- the window in which
	// the addon answered 403 "credential unavailable". A group the deployment
	// names but /etc/group does not define is reported, not fatal: the bind is
	// still correct and the render warns about the same thing.
	const runas = try proxygid.fromEnv(allocator, io, env);
	if (runas.unresolved_group) |g| {
		try warnLine(allocator, io, "COGBOX_PROXY_RUNAS names group '{s}', which /etc/group does not define; the L7 proxy will not be able to read bound credentials.", .{g});
	}

	const outcome = store.addForProxy(allocator, io, secrets_dir, nm, value, meta, runas.gid) catch |err| {
		return die(allocator, io, "failed to bind secret '{s}': {s}", .{ nm, @errorName(err) }, 73);
	};
	// Loud on the failure path only: a staged grant that did NOT land leaves the
	// pre-existing behavior (unreadable until the next render grants it), which
	// is recoverable but would otherwise be invisible.
	if (runas.gid != null and audience != null and !outcome.proxy_readable) {
		try warnLine(allocator, io, "bound '{s}', but could not stage the L7 proxy's read access on it; it stays unreadable until the next inject render grants it.", .{nm});
	}

	if (audience) |aud| {
		try announce(allocator, io, "Bound secret '{s}' (kind={s}, audience={s}).", .{ nm, kind, aud });
	} else {
		try announce(allocator, io, "Bound secret '{s}' (kind={s}). NOTE: no --audience set -> not injectable until you set one (cogbox secret add '{s}' --audience HOST ...).", .{ nm, kind, nm });
	}
}

fn cmdRm(allocator: std.mem.Allocator, io: std.Io, secrets_dir: []const u8, argv: []const []const u8) !void {
	if (argv.len != 1 or std.mem.startsWith(u8, argv[0], "-")) {
		return die(allocator, io, "usage: cogbox secret rm <name>", .{}, 64);
	}
	const nm = argv[0];
	if (!store.validName(nm)) return die(allocator, io, "invalid secret name '{s}'", .{nm}, 65);
	const existed = store.remove(allocator, io, secrets_dir, nm) catch |err| {
		return die(allocator, io, "failed to remove secret '{s}': {s}", .{ nm, @errorName(err) }, 73);
	};
	if (existed) {
		try announce(allocator, io, "Removed secret '{s}'.", .{nm});
	} else {
		try announce(allocator, io, "No secret named '{s}'.", .{nm});
	}
}

fn cmdList(allocator: std.mem.Allocator, io: std.Io, secrets_dir: []const u8, argv: []const []const u8) !void {
	var json = false;
	for (argv) |a| {
		if (eql(a, "--json")) {
			json = true;
		} else {
			return die(allocator, io, "unknown argument '{s}' (secret ls accepts only --json)", .{a}, 64);
		}
	}

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);

	// store.lookup allocates the value path + meta strings into the allocator it's
	// given; an arena frees them all at once (the bytes we keep are copied into
	// `out`). Without this, listing N secrets leaks N*(path+meta) allocations.
	var arena_inst = std.heap.ArenaAllocator.init(allocator);
	defer arena_inst.deinit();
	const arena = arena_inst.allocator();

	const cwd = std.Io.Dir.cwd();
	var dir = cwd.openDir(io, secrets_dir, .{ .iterate = true }) catch |err| switch (err) {
		error.FileNotFound => {
			// A never-bound store has no dir yet. The JSON form must still be a
			// valid (empty) array so a machine reader doesn't choke.
			try writeStdout(io, if (json) "[]\n" else "No secrets bound.\n");
			return;
		},
		else => return err,
	};
	defer dir.close(io);

	var count: usize = 0;
	if (json) try out.append(allocator, '[');
	var iter = dir.iterate();
	while (try iter.next(io)) |entry| {
		if (entry.kind != .file) continue;
		// The value file is the secret; skip its .meta sidecar and any .tmp.
		if (std.mem.endsWith(u8, entry.name, ".meta")) continue;
		if (std.mem.endsWith(u8, entry.name, ".tmp")) continue;
		if (!store.validName(entry.name)) continue;

		const resolved = (try store.lookup(arena, io, secrets_dir, entry.name)) orelse continue;
		if (json) {
			if (count != 0) try out.append(allocator, ',');
			try appendSecretJson(allocator, &out, entry.name, resolved.meta, resolved.bound);
		} else {
			try out.appendSlice(allocator, entry.name);
			try out.appendSlice(allocator, "  kind=");
			try out.appendSlice(allocator, resolved.meta.kind);
			try out.appendSlice(allocator, " audience=");
			try out.appendSlice(allocator, resolved.meta.audience orelse "(unset, not injectable)");
			if (!resolved.bound) try out.appendSlice(allocator, " [MISSING VALUE]");
			try out.append(allocator, '\n');
		}
		count += 1;
	}

	if (json) {
		try out.appendSlice(allocator, "]\n");
		try writeStdout(io, out.items);
		return;
	}
	if (count == 0) {
		try writeStdout(io, "No secrets bound.\n");
		return;
	}
	try writeStdout(io, out.items);
}

/// Append one secret's `--json` object to `out`. The control plane (cogworx)
/// reads this to learn the per-instance bound/audience state of each named
/// secret, so it can show a plugin's inject request as bound vs unbound without
/// ever seeing the value. Pure (no IO); exposed for tests. `bound` is whether
/// the value file exists; an unbound or audience-null secret is not injectable.
pub fn appendSecretJson(allocator: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, meta: store.Meta, bound: bool) !void {
	try out.appendSlice(allocator, "{\"name\":");
	try store.appendJsonString(allocator, out, name);
	try out.appendSlice(allocator, ",\"kind\":");
	try store.appendJsonString(allocator, out, meta.kind);
	try out.appendSlice(allocator, ",\"audience\":");
	if (meta.audience) |a| try store.appendJsonString(allocator, out, a) else try out.appendSlice(allocator, "null");
	try out.appendSlice(allocator, ",\"tier\":");
	try store.appendJsonString(allocator, out, meta.tier);
	try out.appendSlice(allocator, ",\"bound\":");
	try out.appendSlice(allocator, if (bound) "true" else "false");
	try out.appendSlice(allocator, ",\"bound_at\":");
	if (meta.bound_at) |b| {
		var nb: [32]u8 = undefined;
		try out.appendSlice(allocator, std.fmt.bufPrint(&nb, "{d}", .{b}) catch unreachable);
	} else try out.appendSlice(allocator, "null");
	try out.append(allocator, '}');
}

// --- small helpers ---------------------------------------------------------

fn eql(a: []const u8, b: []const u8) bool {
	return std.mem.eql(u8, a, b);
}

/// Match `--flag value` or `--flag=value`. Advances `*i` past the consumed
/// value form. Returns the value, or null if `arg` isn't this flag.
fn flagValue(arg: []const u8, comptime flag: []const u8, argv: []const []const u8, i: *usize) ?[]const u8 {
	if (eql(arg, flag)) {
		if (i.* + 1 < argv.len) {
			i.* += 1;
			return argv[i.*];
		}
		return null;
	}
	if (std.mem.startsWith(u8, arg, flag ++ "=")) {
		return arg[flag.len + 1 ..];
	}
	return null;
}

fn trimTrailingNewline(s: []const u8) []const u8 {
	var end = s.len;
	while (end > 0 and (s[end - 1] == '\n' or s[end - 1] == '\r')) end -= 1;
	return s[0..end];
}

fn readFileAll(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
	const cwd = std.Io.Dir.cwd();
	const f = try cwd.openFile(io, path, .{});
	defer f.close(io);
	var rbuf: [4096]u8 = undefined;
	var r = f.reader(io, &rbuf);
	return r.interface.allocRemaining(allocator, .limited(1 << 20));
}

fn readStdinAll(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
	const stdin = std.Io.File.stdin();
	var sbuf: [4096]u8 = undefined;
	var r = stdin.readerStreaming(io, &sbuf);
	return r.interface.allocRemaining(allocator, .limited(1 << 20));
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

fn warnLine(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype) !void {
	const msg = try std.fmt.allocPrint(allocator, "cogbox secret: warning: " ++ fmt ++ "\n", args);
	defer allocator.free(msg);
	try writeStderr(io, msg);
}

fn die(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype, code: u8) noreturn {
	const msg = std.fmt.allocPrint(allocator, "cogbox secret: error: " ++ fmt ++ "\n", args) catch "cogbox secret: error: (message too long)\n";
	writeStderr(io, msg) catch {};
	std.process.exit(code);
}
