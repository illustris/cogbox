// Argument parser for `cogbox plugin`. The verb wrapper resolves the
// instance (-n/--name) and paths; this parses what's left:
//
//   cogbox plugin ... list
//   cogbox plugin ... add FLAKE_URL [--as PLUGIN] [-y]
//   cogbox plugin ... del PLUGIN [-y]
//   cogbox plugin ... update [PLUGIN] [--defer-rules]
//   cogbox plugin ... apply [--json] [--op RUN] [--force | --force-plan ID]
//   cogbox plugin ... apply --status [--json] [--since N]
//   cogbox plugin ... apply --cancel [--json] [--op RUN]
//   cogbox plugin ... apply --log G
//   cogbox plugin ... apply --abandon-rollback [-y]
//
// add, del and update also take --apply / --no-apply (load the change live
// now, or defer it; see LiveChoice).
//
// The plugin-name override is --as (not --name) so it can't collide with the
// instance selector, which every cogbox verb spells -n/--name.

const std = @import("std");

pub const Cmd = union(enum) {
	list,
	add: AddArgs,
	del: DelArgs,
	update: UpdateArgs,
	resolve: ResolveArgs,
	// `cogbox plugin reconcile` (no args): the boot-time reconcile for the container
	// full-toplevel path. Builds + records the per-instance toplevel from the ALREADY
	// materialized composition (no fetch/mutation), so a stopped/fresh add that never
	// prebuilt the toplevel (only the running-agent add does) is picked up on the next
	// boot. Run by the cogbox-toplevel-reconcile oneshot post-boot (egress up). No-op
	// when nothing changed since the last record; removes the record when no plugins.
	reconcile,
	// `cogbox plugin apply`: load the committed plugin state into the running
	// guest without relaunching it (the live apply, apply.zig), or one of its
	// status/cancel/log/abandon companions.
	apply: ApplyArgs,
};

/// --apply / --no-apply on add, del and update: apply the change live right
/// after it commits, or leave it for `cogbox plugin apply` or the next start.
/// Null: the default (an interactive terminal on a running instance applies).
pub const LiveChoice = ?bool;

pub const ApplyMode = enum {
	/// Apply whatever is pending.
	run,
	/// Report whether an apply is in flight, the last outcome and the rollback
	/// records.
	status,
	/// Stop a running apply (idempotent).
	cancel,
	/// Print a generation's build log.
	log,
	/// Move every pending rollback intent aside (the escape when a rollback
	/// cannot finish).
	abandon,
};

pub const ApplyArgs = struct {
	mode: ApplyMode = .run,
	json: bool = false,
	/// The control plane's run token (`--op RUN`), echoed into every record of
	/// the run; with --cancel it selects the holder to signal.
	op: ?[]const u8 = null,
	/// --status --since N: only rollback records with seq > N.
	since: u64 = 0,
	/// --log G: the generation whose build log to print.
	gen: ?[]const u8 = null,
	/// --force / --force-plan ID (Apply anyway). Parsed so the CLI surface is
	/// stable; the verb refuses both until forced plans are supported.
	force: bool = false,
	force_plan: ?[]const u8 = null,
	/// --abandon-rollback -y: skip the confirmation.
	yes: bool = false,
};

pub const AddArgs = struct {
	url: []const u8,
	as: ?[]const u8 = null,
	yes: bool = false,
	// --git-credential-stdin: read one `host\tuser\ttoken` line from stdin and
	// authenticate the single nix fetch with it.
	git_credential_stdin: bool = false,
	// --defer-rules: install the module + merge inject specs as usual, but DON'T
	// merge the plugin's L4/L7 networkRules into config.json. Instead emit the
	// withheld rules as one JSON line on stdout for the control plane to route
	// through its admin-approval flow. Suppresses the human "suggested rules"
	// block + the confirm prompt so stdout carries only the JSON line.
	defer_rules: bool = false,
	live: LiveChoice = null,
};

pub const DelArgs = struct {
	plugin: []const u8,
	yes: bool = false,
	live: LiveChoice = null,
};

pub const UpdateArgs = struct {
	plugin: ?[]const u8 = null,
	// update re-resolves the flake, so it takes the same single-fetch credential.
	git_credential_stdin: bool = false,
	// --defer-rules (control plane, like AddArgs.defer_rules): update the module +
	// replace inject specs as usual, but leave the plugin's applied tagged L4/L7
	// rules exactly as they are. Incoming rules the plugin does not already carry
	// are emitted as one JSON line on stdout for the admin-approval flow. Needs
	// PLUGIN: the deferred line names exactly one plugin.
	defer_rules: bool = false,
	live: LiveChoice = null,
};

pub const ResolveArgs = struct {
	// resolve previews a flake URL WITHOUT installing it: flake metadata +
	// the cogboxPlugins.<attr> contract check + the host-side
	// networkRules/l7Rules/inject readout, emitted as one JSON line on stdout
	// (the control plane's truthful pre-install preview). No mutation.
	url: []const u8,
	// Same single-fetch credential as add/update, for a private-repo preview.
	git_credential_stdin: bool = false,
};

pub const ParseError = error{
	MissingSubcommand,
	UnknownSubcommand,
	MissingUrl,
	MissingPlugin,
	InvalidArgs,
};

pub fn parse(argv: []const []const u8) ParseError!Cmd {
	if (argv.len == 0) return error.MissingSubcommand;
	const sub = argv[0];
	const rest = argv[1..];

	if (std.mem.eql(u8, sub, "list")) {
		if (rest.len != 0) return error.InvalidArgs;
		return .list;
	}
	if (std.mem.eql(u8, sub, "add")) return parseAdd(rest);
	if (std.mem.eql(u8, sub, "del")) return parseDel(rest);
	if (std.mem.eql(u8, sub, "update")) return parseUpdate(rest);
	if (std.mem.eql(u8, sub, "resolve")) return parseResolve(rest);
	if (std.mem.eql(u8, sub, "reconcile")) {
		if (rest.len != 0) return error.InvalidArgs;
		return .reconcile;
	}
	if (std.mem.eql(u8, sub, "apply")) return parseApply(rest);
	return error.UnknownSubcommand;
}

/// --apply / --no-apply. True when `a` was one of them (recorded in `live`);
/// both on one command line is an error.
fn parseLive(a: []const u8, live: *LiveChoice) ParseError!bool {
	const v: bool = if (std.mem.eql(u8, a, "--apply")) true else if (std.mem.eql(u8, a, "--no-apply")) false else return false;
	if (live.*) |prev| if (prev != v) return error.InvalidArgs;
	live.* = v;
	return true;
}

/// A run token: 1-64 of [A-Za-z0-9._-] (what the rollback records accept).
pub fn isOpToken(s: []const u8) bool {
	if (s.len == 0 or s.len > 64) return false;
	for (s) |c| switch (c) {
		'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => {},
		else => return false,
	};
	return true;
}

/// A generation or plan id: 16 lowercase hex digits.
pub fn isHex16(s: []const u8) bool {
	if (s.len != 16) return false;
	for (s) |c| switch (c) {
		'0'...'9', 'a'...'f' => {},
		else => return false,
	};
	return true;
}

fn parseApply(args: []const []const u8) ParseError!Cmd {
	var r: ApplyArgs = .{};
	var mode: ?ApplyMode = null;
	var since_set = false;
	var i: usize = 0;
	while (i < args.len) : (i += 1) {
		const a = args[i];
		const Valued = struct {
			fn take(argv: []const []const u8, idx: *usize, flag: []const u8) ParseError![]const u8 {
				const cur = argv[idx.*];
				if (std.mem.eql(u8, cur, flag)) {
					idx.* += 1;
					if (idx.* >= argv.len) return error.InvalidArgs;
					return argv[idx.*];
				}
				return cur[flag.len + 1 ..];
			}
			fn is(cur: []const u8, flag: []const u8) bool {
				return std.mem.eql(u8, cur, flag) or (std.mem.startsWith(u8, cur, flag) and cur.len > flag.len and cur[flag.len] == '=');
			}
		};
		var new_mode: ?ApplyMode = null;
		if (std.mem.eql(u8, a, "--json")) {
			r.json = true;
		} else if (Valued.is(a, "--op")) {
			if (r.op != null) return error.InvalidArgs;
			const v = try Valued.take(args, &i, "--op");
			if (!isOpToken(v)) return error.InvalidArgs;
			r.op = v;
		} else if (std.mem.eql(u8, a, "--status")) {
			new_mode = .status;
		} else if (Valued.is(a, "--since")) {
			if (since_set) return error.InvalidArgs;
			r.since = std.fmt.parseInt(u64, try Valued.take(args, &i, "--since"), 10) catch return error.InvalidArgs;
			since_set = true;
		} else if (std.mem.eql(u8, a, "--cancel")) {
			new_mode = .cancel;
		} else if (Valued.is(a, "--log")) {
			const v = try Valued.take(args, &i, "--log");
			if (!isHex16(v)) return error.InvalidArgs;
			r.gen = v;
			new_mode = .log;
		} else if (std.mem.eql(u8, a, "--abandon-rollback")) {
			new_mode = .abandon;
		} else if (std.mem.eql(u8, a, "-y") or std.mem.eql(u8, a, "--yes")) {
			r.yes = true;
		} else if (std.mem.eql(u8, a, "--force")) {
			r.force = true;
		} else if (Valued.is(a, "--force-plan")) {
			if (r.force_plan != null) return error.InvalidArgs;
			const v = try Valued.take(args, &i, "--force-plan");
			if (!isHex16(v)) return error.InvalidArgs;
			r.force_plan = v;
		} else {
			// No positional arguments, and no unknown flags.
			return error.InvalidArgs;
		}
		if (new_mode) |m| {
			if (mode != null) return error.InvalidArgs;
			mode = m;
		}
	}
	r.mode = mode orelse .run;
	if (since_set and r.mode != .status) return error.InvalidArgs;
	if (r.op != null and r.mode != .run and r.mode != .cancel) return error.InvalidArgs;
	if ((r.force or r.force_plan != null) and r.mode != .run) return error.InvalidArgs;
	if (r.force and r.force_plan != null) return error.InvalidArgs;
	if (r.yes and r.mode != .abandon) return error.InvalidArgs;
	if (r.json and (r.mode == .log or r.mode == .abandon)) return error.InvalidArgs;
	return .{ .apply = r };
}

fn parseAdd(args: []const []const u8) ParseError!Cmd {
	var url: ?[]const u8 = null;
	var as: ?[]const u8 = null;
	var yes = false;
	var git_cred = false;
	var defer_rules = false;
	var live: LiveChoice = null;

	var i: usize = 0;
	while (i < args.len) : (i += 1) {
		const a = args[i];
		if (std.mem.eql(u8, a, "--as")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			as = args[i];
		} else if (std.mem.startsWith(u8, a, "--as=")) {
			as = a[5..];
		} else if (std.mem.eql(u8, a, "-y") or std.mem.eql(u8, a, "--yes")) {
			yes = true;
		} else if (std.mem.eql(u8, a, "--git-credential-stdin")) {
			git_cred = true;
		} else if (std.mem.eql(u8, a, "--defer-rules")) {
			defer_rules = true;
		} else if (try parseLive(a, &live)) {
			// recorded
		} else if (std.mem.startsWith(u8, a, "-") and a.len > 1) {
			return error.InvalidArgs;
		} else {
			if (url != null) return error.InvalidArgs;
			url = a;
		}
	}

	const u = url orelse return error.MissingUrl;
	return .{ .add = .{ .url = u, .as = as, .yes = yes, .git_credential_stdin = git_cred, .defer_rules = defer_rules, .live = live } };
}

fn parseDel(args: []const []const u8) ParseError!Cmd {
	var plugin: ?[]const u8 = null;
	var yes = false;
	var live: LiveChoice = null;

	for (args) |a| {
		if (std.mem.eql(u8, a, "-y") or std.mem.eql(u8, a, "--yes")) {
			yes = true;
		} else if (try parseLive(a, &live)) {
			// recorded
		} else if (std.mem.startsWith(u8, a, "-") and a.len > 1) {
			return error.InvalidArgs;
		} else {
			if (plugin != null) return error.InvalidArgs;
			plugin = a;
		}
	}

	const p = plugin orelse return error.MissingPlugin;
	return .{ .del = .{ .plugin = p, .yes = yes, .live = live } };
}

fn parseUpdate(args: []const []const u8) ParseError!Cmd {
	var plugin: ?[]const u8 = null;
	var git_cred = false;
	var defer_rules = false;
	var live: LiveChoice = null;
	for (args) |a| {
		if (std.mem.eql(u8, a, "--git-credential-stdin")) {
			git_cred = true;
		} else if (std.mem.eql(u8, a, "--defer-rules")) {
			defer_rules = true;
		} else if (try parseLive(a, &live)) {
			// recorded
		} else if (std.mem.startsWith(u8, a, "-") and a.len > 1) {
			return error.InvalidArgs;
		} else {
			if (plugin != null) return error.InvalidArgs;
			plugin = a;
		}
	}
	// The deferred line names exactly one plugin.
	if (defer_rules and plugin == null) return error.InvalidArgs;
	return .{ .update = .{ .plugin = plugin, .git_credential_stdin = git_cred, .defer_rules = defer_rules, .live = live } };
}

fn parseResolve(args: []const []const u8) ParseError!Cmd {
	var url: ?[]const u8 = null;
	var git_cred = false;
	for (args) |a| {
		if (std.mem.eql(u8, a, "--git-credential-stdin")) {
			git_cred = true;
		} else if (std.mem.startsWith(u8, a, "-") and a.len > 1) {
			return error.InvalidArgs;
		} else {
			if (url != null) return error.InvalidArgs;
			url = a;
		}
	}
	const u = url orelse return error.MissingUrl;
	return .{ .resolve = .{ .url = u, .git_credential_stdin = git_cred } };
}

// --- Tests ---

const t = std.testing;

test "list parses, rejects extra args" {
	try t.expect((try parse(&.{"list"})) == .list);
	try t.expectError(error.InvalidArgs, parse(&.{ "list", "x" }));
}

test "reconcile parses, rejects extra args" {
	try t.expect((try parse(&.{"reconcile"})) == .reconcile);
	try t.expectError(error.InvalidArgs, parse(&.{ "reconcile", "x" }));
}

test "add with url only" {
	const c = try parse(&.{ "add", "github:owner/repo" });
	try t.expectEqualStrings("github:owner/repo", c.add.url);
	try t.expect(c.add.as == null);
	try t.expect(!c.add.yes);
}

test "add with --as and -y" {
	const c = try parse(&.{ "add", "path:/x/y", "--as", "dev", "-y" });
	try t.expectEqualStrings("dev", c.add.as.?);
	try t.expect(c.add.yes);
	const c2 = try parse(&.{ "add", "--as=dev2", "path:/x/y", "--yes" });
	try t.expectEqualStrings("dev2", c2.add.as.?);
	try t.expect(c2.add.yes);
}

test "add missing url / extra positional / unknown flag" {
	try t.expectError(error.MissingUrl, parse(&.{"add"}));
	try t.expectError(error.InvalidArgs, parse(&.{ "add", "a", "b" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "add", "a", "--frob" }));
}

test "add --git-credential-stdin" {
	const c = try parse(&.{ "add", "git+https://git.example.com/g/r", "--git-credential-stdin" });
	try t.expect(c.add.git_credential_stdin);
	try t.expectEqualStrings("git+https://git.example.com/g/r", c.add.url);
	// Default is off.
	const c2 = try parse(&.{ "add", "git+https://git.example.com/g/r" });
	try t.expect(!c2.add.git_credential_stdin);
	// Combines with --as / -y.
	const c3 = try parse(&.{ "add", "u", "--as", "p", "--git-credential-stdin", "-y" });
	try t.expect(c3.add.git_credential_stdin);
	try t.expectEqualStrings("p", c3.add.as.?);
	try t.expect(c3.add.yes);
}

test "add --defer-rules" {
	const c = try parse(&.{ "add", "github:owner/repo", "--defer-rules" });
	try t.expect(c.add.defer_rules);
	try t.expectEqualStrings("github:owner/repo", c.add.url);
	// Default is off.
	const c2 = try parse(&.{ "add", "github:owner/repo" });
	try t.expect(!c2.add.defer_rules);
	// Combines with --as / -y / --git-credential-stdin.
	const c3 = try parse(&.{ "add", "u", "--as", "p", "--defer-rules", "--git-credential-stdin", "-y" });
	try t.expect(c3.add.defer_rules);
	try t.expect(c3.add.git_credential_stdin);
	try t.expectEqualStrings("p", c3.add.as.?);
	try t.expect(c3.add.yes);
}

test "del parses" {
	const c = try parse(&.{ "del", "myplugin" });
	try t.expectEqualStrings("myplugin", c.del.plugin);
	const c2 = try parse(&.{ "del", "myplugin", "-y" });
	try t.expect(c2.del.yes);
	try t.expectError(error.MissingPlugin, parse(&.{"del"}));
}

test "update with and without name" {
	const all = try parse(&.{"update"});
	try t.expect(all.update.plugin == null);
	try t.expect(!all.update.git_credential_stdin);
	const one = try parse(&.{ "update", "myplugin" });
	try t.expectEqualStrings("myplugin", one.update.plugin.?);
	try t.expectError(error.InvalidArgs, parse(&.{ "update", "a", "b" }));
}

test "update --git-credential-stdin (with and without name)" {
	const c = try parse(&.{ "update", "--git-credential-stdin" });
	try t.expect(c.update.git_credential_stdin);
	try t.expect(c.update.plugin == null);
	const c2 = try parse(&.{ "update", "myplugin", "--git-credential-stdin" });
	try t.expect(c2.update.git_credential_stdin);
	try t.expectEqualStrings("myplugin", c2.update.plugin.?);
}

test "update --defer-rules (PLUGIN required)" {
	const c = try parse(&.{ "update", "p", "--defer-rules" });
	try t.expect(c.update.defer_rules);
	try t.expectEqualStrings("p", c.update.plugin.?);
	const c2 = try parse(&.{ "update", "--defer-rules", "p", "--git-credential-stdin" });
	try t.expect(c2.update.defer_rules);
	try t.expect(c2.update.git_credential_stdin);
	try t.expectEqualStrings("p", c2.update.plugin.?);
	try t.expectError(error.InvalidArgs, parse(&.{ "update", "--defer-rules" }));
	const c3 = try parse(&.{ "update", "p" });
	try t.expect(!c3.update.defer_rules);
}

test "resolve parses (url required, optional --git-credential-stdin)" {
	const c = try parse(&.{ "resolve", "github:owner/repo#mod" });
	try t.expectEqualStrings("github:owner/repo#mod", c.resolve.url);
	try t.expect(!c.resolve.git_credential_stdin);
	const c2 = try parse(&.{ "resolve", "git+https://g/r", "--git-credential-stdin" });
	try t.expect(c2.resolve.git_credential_stdin);
	try t.expectEqualStrings("git+https://g/r", c2.resolve.url);
	try t.expectError(error.MissingUrl, parse(&.{"resolve"}));
	try t.expectError(error.InvalidArgs, parse(&.{ "resolve", "a", "b" }));
}

test "unknown / missing subcommand" {
	try t.expectError(error.UnknownSubcommand, parse(&.{"frob"}));
	try t.expectError(error.MissingSubcommand, parse(&.{}));
}

test "apply: a plain run, --json and --op" {
	const c = try parse(&.{"apply"});
	try t.expect(c.apply.mode == .run);
	try t.expect(!c.apply.json);
	try t.expect(c.apply.op == null);
	const c2 = try parse(&.{ "apply", "--json", "--op", "42" });
	try t.expect(c2.apply.json);
	try t.expectEqualStrings("42", c2.apply.op.?);
	const c3 = try parse(&.{ "apply", "--op=run-7.a_b" });
	try t.expectEqualStrings("run-7.a_b", c3.apply.op.?);
	// A run token is 1-64 of [A-Za-z0-9._-]; it is echoed into records.
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--op", "a b" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--op", "" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--op", "x" ** 65 }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--op" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--op", "1", "--op", "2" }));
	// No positionals, no unknown flags.
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "myplugin" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--frob" }));
}

test "apply: --status [--since N], --cancel [--op], --log G, --abandon-rollback [-y]" {
	const st = try parse(&.{ "apply", "--status", "--json", "--since", "12" });
	try t.expect(st.apply.mode == .status);
	try t.expectEqual(@as(u64, 12), st.apply.since);
	try t.expect(st.apply.json);
	try t.expectEqual(@as(u64, 0), (try parse(&.{ "apply", "--status" })).apply.since);
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--since", "3" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--status", "--since", "-1" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--status", "--op", "4" }));

	const ca = try parse(&.{ "apply", "--cancel", "--op", "9" });
	try t.expect(ca.apply.mode == .cancel);
	try t.expectEqualStrings("9", ca.apply.op.?);
	try t.expect((try parse(&.{ "apply", "--cancel" })).apply.op == null);

	const lg = try parse(&.{ "apply", "--log", "0123456789abcdef" });
	try t.expect(lg.apply.mode == .log);
	try t.expectEqualStrings("0123456789abcdef", lg.apply.gen.?);
	// G is exactly 16 lowercase hex digits (it names files).
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--log", "../../etc/passwd" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--log", "0123456789ABCDEF" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--log" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--log", "0123456789abcdef", "--json" }));

	const ab = try parse(&.{ "apply", "--abandon-rollback", "-y" });
	try t.expect(ab.apply.mode == .abandon);
	try t.expect(ab.apply.yes);
	try t.expect(!(try parse(&.{ "apply", "--abandon-rollback" })).apply.yes);
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "-y" }));

	// One mode at a time.
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--status", "--cancel" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--status", "--status" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--cancel", "--abandon-rollback" }));
}

test "apply: --force and --force-plan parse on a plain run only, never together" {
	try t.expect((try parse(&.{ "apply", "--force" })).apply.force);
	try t.expectEqualStrings("fedcba9876543210", (try parse(&.{ "apply", "--force-plan", "fedcba9876543210" })).apply.force_plan.?);
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--force", "--force-plan", "fedcba9876543210" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--force-plan", "nothex" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--status", "--force" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "apply", "--cancel", "--force-plan", "fedcba9876543210" }));
}

test "add, del and update take --apply or --no-apply, not both" {
	try t.expect((try parse(&.{ "add", "u" })).add.live == null);
	try t.expect((try parse(&.{ "add", "u", "--apply" })).add.live.? == true);
	try t.expect((try parse(&.{ "add", "--no-apply", "u", "-y" })).add.live.? == false);
	try t.expect((try parse(&.{ "del", "p", "--no-apply" })).del.live.? == false);
	try t.expect((try parse(&.{ "update", "--apply" })).update.live.? == true);
	try t.expect((try parse(&.{ "update", "p", "--apply", "--apply" })).update.live.? == true);
	try t.expectError(error.InvalidArgs, parse(&.{ "add", "u", "--apply", "--no-apply" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "del", "p", "--no-apply", "--apply" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "update", "--apply", "--no-apply" }));
	// list, resolve and reconcile take neither.
	try t.expectError(error.InvalidArgs, parse(&.{ "list", "--apply" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "resolve", "u", "--no-apply" }));
}
