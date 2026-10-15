// Argument parser for `cogbox plugin`. The verb wrapper resolves the
// instance (-n/--name) and paths; this parses what's left:
//
//   cogbox plugin ... list
//   cogbox plugin ... add FLAKE_URL [--as PLUGIN] [-y]
//   cogbox plugin ... del PLUGIN [-y]
//   cogbox plugin ... update [PLUGIN] [--defer-rules]
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
};

pub const DelArgs = struct {
	plugin: []const u8,
	yes: bool = false,
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
	return error.UnknownSubcommand;
}

fn parseAdd(args: []const []const u8) ParseError!Cmd {
	var url: ?[]const u8 = null;
	var as: ?[]const u8 = null;
	var yes = false;
	var git_cred = false;
	var defer_rules = false;

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
		} else if (std.mem.startsWith(u8, a, "-") and a.len > 1) {
			return error.InvalidArgs;
		} else {
			if (url != null) return error.InvalidArgs;
			url = a;
		}
	}

	const u = url orelse return error.MissingUrl;
	return .{ .add = .{ .url = u, .as = as, .yes = yes, .git_credential_stdin = git_cred, .defer_rules = defer_rules } };
}

fn parseDel(args: []const []const u8) ParseError!Cmd {
	var plugin: ?[]const u8 = null;
	var yes = false;

	for (args) |a| {
		if (std.mem.eql(u8, a, "-y") or std.mem.eql(u8, a, "--yes")) {
			yes = true;
		} else if (std.mem.startsWith(u8, a, "-") and a.len > 1) {
			return error.InvalidArgs;
		} else {
			if (plugin != null) return error.InvalidArgs;
			plugin = a;
		}
	}

	const p = plugin orelse return error.MissingPlugin;
	return .{ .del = .{ .plugin = p, .yes = yes } };
}

fn parseUpdate(args: []const []const u8) ParseError!Cmd {
	var plugin: ?[]const u8 = null;
	var git_cred = false;
	var defer_rules = false;
	for (args) |a| {
		if (std.mem.eql(u8, a, "--git-credential-stdin")) {
			git_cred = true;
		} else if (std.mem.eql(u8, a, "--defer-rules")) {
			defer_rules = true;
		} else if (std.mem.startsWith(u8, a, "-") and a.len > 1) {
			return error.InvalidArgs;
		} else {
			if (plugin != null) return error.InvalidArgs;
			plugin = a;
		}
	}
	// The deferred line names exactly one plugin.
	if (defer_rules and plugin == null) return error.InvalidArgs;
	return .{ .update = .{ .plugin = plugin, .git_credential_stdin = git_cred, .defer_rules = defer_rules } };
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
