// `cogbox l7` verb dispatcher. Manages `.network.l7` (an object with `mode`
// and a `rules` array of SNI/Host allow/deny entries). Shares config load/
// save + the shared reload path with `rules`/`remap` via rules_module, so an
// l7 edit re-renders BOTH the netfilter-rules funnel lines and the proxy's
// l7-rules file, and signals passt (SIGUSR1) + the L7 proxy (SIGHUP).

const std = @import("std");
pub const cli = @import("cli.zig");
pub const rule = @import("rule.zig");

const rules_module = @import("rules_module");
const config = rules_module.config;
const reload = rules_module.reload;

pub fn dispatch(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
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
		try writeStderr(io, try std.fmt.allocPrint(allocator, "cogbox l7: error: {s}\n", .{@errorName(err)}));
		std.process.exit(64);
	};

	var loaded = config.load(allocator, io, args.config_path) catch |err| switch (err) {
		error.FileNotFound => return die(allocator, io, "no config found at {s}", .{args.config_path}, 66),
		error.InvalidJson => return die(allocator, io, "invalid JSON in {s}", .{args.config_path}, 65),
		else => return err,
	};
	defer loaded.deinit();

	const net = loaded.network() catch |err| switch (err) {
		error.NotInRulesMode => return die(
			allocator,
			io,
			"instance is not in rules mode. Set network to rules mode first: edit {s} or reinit with --network rules.",
			.{args.config_path},
			65,
		),
		else => return err,
	};

	const l7 = try ensureL7Object(net, loaded.treeAllocator());
	const rules_arr = &l7.object.getPtr("rules").?.array;

	switch (args.cmd) {
		.list => try cmdList(allocator, io, l7.*, rules_arr.*),
		.add => |a| try cmdAdd(allocator, io, args, rules_arr, a, &loaded),
		.del => |d| try cmdDel(allocator, io, args, rules_arr, d, &loaded),
		.clear => |c| try cmdClear(allocator, io, args, rules_arr, c, &loaded),
		.set => try cmdSet(allocator, io, args, rules_arr, &loaded),
		.replace => |r| try cmdReplace(allocator, io, args, net, rules_arr, r, &loaded),
		.policy => try cmdPolicy(allocator, io, env, args, l7, &loaded),
		.mode => |m| try cmdMode(allocator, io, args, l7, m, &loaded),
	}
}

/// Ensure `.network.l7` is `{ "rules": [] }`-shaped. No `mode` is written:
/// an absent mode means the default tier (terminate), and `l7 mode passthrough`
/// writes it explicitly when the operator opts the instance out.
/// Pub: the plugin verb merges plugin-declared L7 rules through this too.
pub fn ensureL7Object(net: *std.json.Value, arena: std.mem.Allocator) !*std.json.Value {
	if (net.object.getPtr("l7") == null) {
		var obj: std.json.ObjectMap = .empty;
		try obj.put(arena, try arena.dupe(u8, "rules"), .{ .array = std.json.Array.init(arena) });
		try net.object.put(arena, try arena.dupe(u8, "l7"), .{ .object = obj });
	}
	const l7 = net.object.getPtr("l7").?;
	if (l7.* != .object) return error.InvalidJson;
	if (l7.object.getPtr("rules") == null) {
		try l7.object.put(arena, try arena.dupe(u8, "rules"), .{ .array = std.json.Array.init(arena) });
	}
	if (l7.object.getPtr("rules").?.* != .array) return error.InvalidJson;
	return l7;
}

/// The instance's default tier. Terminate is the default; only an explicit
/// `mode: passthrough` opts the whole instance out.
fn modeTerminate(l7: std.json.Value) bool {
	if (l7.object.get("mode")) |m| {
		if (m == .string and std.mem.eql(u8, m.string, "passthrough")) return false;
	}
	return true;
}

fn cmdList(allocator: std.mem.Allocator, io: std.Io, l7: std.json.Value, rules_arr: std.json.Array) !void {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);

	try out.appendSlice(allocator, "mode: ");
	try out.appendSlice(allocator, if (modeTerminate(l7)) "terminate\n" else "passthrough\n");

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
		try out.appendSlice(allocator, p.host);
		var is_terminate = false;
		if (r.object.get("methods")) |mv| {
			if (mv == .string and mv.string.len > 0) {
				try out.appendSlice(allocator, " ");
				try out.appendSlice(allocator, mv.string);
				is_terminate = true; // a method constraint implies terminate
			}
		}
		if (r.object.get("path")) |pv| {
			if (pv == .string) {
				try out.appendSlice(allocator, " ");
				try out.appendSlice(allocator, pv.string);
				is_terminate = true; // a path constraint implies terminate
			}
		}
		if (r.object.get("pathmode")) |pm| {
			if (pm == .string and std.mem.eql(u8, pm.string, "exact")) {
				try out.appendSlice(allocator, " exact");
				is_terminate = true;
			}
		}
		if (r.object.get("service")) |sv| {
			if (sv == .string and sv.string.len > 0) {
				try out.appendSlice(allocator, " service=");
				try out.appendSlice(allocator, sv.string);
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
				is_terminate = true; // insecure-upstream only applies under terminate
			}
		}
		var is_passthrough = false;
		if (r.object.get("passthrough")) |pv| {
			if (pv == .bool and pv.bool) is_passthrough = true;
		}
		if (is_passthrough) {
			try out.appendSlice(allocator, " [passthrough]");
		} else {
			if (is_terminate) try out.appendSlice(allocator, " [terminate]");
			if (is_insecure) try out.appendSlice(allocator, " [insecure]");
		}
		if (rule.ruleComment(r.object)) |co| {
			try out.appendSlice(allocator, "  # ");
			try out.appendSlice(allocator, co);
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
	// The 0-based index of the rule object once inserted, so an optional --plugin
	// tag can be stamped onto exactly it.
	var inserted_idx: usize = undefined;
	// cli.attrsOf, never a struct literal here: cmdReplace projects the same
	// AddArgs, and a second copy of the mapping is how the two verbs would come to
	// emit different rule objects for the same input.
	const attrs = cli.attrsOf(a);
	if (a.pos) |p| {
		rule.insertAt(tree_alloc, rules_arr, p, a.action, a.host, attrs) catch |err| switch (err) {
			error.IndexOutOfRange => return die(allocator, io, "position out of range (must be 1..{d})", .{rules_arr.items.len + 1}, 65),
			error.InvalidHost => return die(allocator, io, "invalid host pattern: {s}", .{a.host}, 65),
			else => return err,
		};
		inserted_idx = p - 1;
	} else {
		const n = rule.append(tree_alloc, rules_arr, a.action, a.host, attrs) catch |err| switch (err) {
			error.InvalidHost => return die(allocator, io, "invalid host pattern: {s}", .{a.host}, 65),
			else => return err,
		};
		inserted_idx = n - 1;
	}

	// --plugin NAME: tag the inserted rule so `plugin del NAME` removes exactly it
	// (the same `"plugin"` field the plugin verb's merge stamps).
	if (a.plugin) |tag| {
		try stampPlugin(tree_alloc, &rules_arr.items[inserted_idx], tag);
	}

	try config.save(allocator, io, args.config_path, loaded.root().*);
	const action_str = switch (a.action) {
		.allow => "allow",
		.deny => "deny",
	};
	var suffix_buf: std.ArrayList(u8) = .empty;
	defer suffix_buf.deinit(allocator);
	if (a.path) |p| {
		try suffix_buf.append(allocator, ' ');
		try suffix_buf.appendSlice(allocator, p);
	}
	if (a.passthrough) {
		try suffix_buf.appendSlice(allocator, " [passthrough]");
	} else {
		if (a.terminate) try suffix_buf.appendSlice(allocator, " [terminate]");
		if (a.insecure) try suffix_buf.appendSlice(allocator, " [insecure]");
	}
	const suffix = suffix_buf.items;
	if (a.pos) |p| {
		try announce(allocator, io, "Added: {s} {s}{s} at position {d}", .{ action_str, a.host, suffix, p });
	} else {
		try announce(allocator, io, "Added: {s} {s}{s}", .{ action_str, a.host, suffix });
	}
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

/// Stamp `"plugin": <tag>` onto a rule object. Shared by `l7 add --plugin` and
/// `l7 replace --plugin` so a batched rule and a singly-added one carry the tag
/// through the SAME code path -- the tag is what `clear`/`replace`/`plugin del`
/// match on, so a second spelling of it here would be a silent ownership leak.
fn stampPlugin(tree_alloc: std.mem.Allocator, item: *std.json.Value, tag: []const u8) !void {
	try item.object.put(tree_alloc, try tree_alloc.dupe(u8, "plugin"), .{ .string = try tree_alloc.dupe(u8, tag) });
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
	try announce(allocator, io, "Deleted l7 rule {d}.", .{d.index});
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

fn cmdClear(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	rules_arr: *std.json.Array,
	c: cli.ClearArgs,
	loaded: *config.Loaded,
) !void {
	const removed = rule.deleteByPlugin(rules_arr, c.plugin);
	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "Cleared {d} l7 rule(s) tagged '{s}'.", .{ removed, c.plugin });
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

/// `l7 replace --plugin TAG --from-stdin`: drop every TAG-tagged rule and append
/// the stdin set in its place, as ONE config edit and ONE reload.
///
/// This subsumes `clear --plugin TAG` + N flagless `add`s. Doing it as a batch
/// ADD would not: that still needs a separate clear, i.e. two saves, two
/// reloads, and a real window in between where the previous grants are gone and
/// the new ones are not yet in force.
///
/// The result is bit-identical to the clear-then-add sequence it replaces:
/// append-only in stdin order, after every other rule. First-match evaluation
/// makes position relative to OTHER rules load-bearing (an earlier user `deny`
/// must still win), and "after everything else" is exactly the old behaviour.
///
/// Over-cap is a LOUD refusal, never a truncation: the enforcer compiles the
/// first filter.max_l7_rules rule lines of the rendered document while the
/// terminate-tier addon reading the same document has no cap, so a silently
/// dropped tail would make the two enforcement layers disagree about what is
/// allowed. The bound is on the RESULTING RENDERED DOCUMENT, not on the batch
/// and not on `.l7.rules[]` either: the batch is appended to every rule that
/// survives deleteByPlugin, AND renderL7 adds a terminate-allow line for each
/// inject-spec host no rule names, so a batch that fits on its own -- or even a
/// result whose array fits -- can still overflow (cli.checkRenderedCap). It
/// binds only a replace that GROWS the rule set, though: a revoke or a narrowing
/// edit on an instance that is already over cap must always succeed, or the
/// withdrawn grant's rules would stay in force with no way to remove them.
fn cmdReplace(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	net: *std.json.Value,
	rules_arr: *std.json.Array,
	r: cli.ReplaceArgs,
	loaded: *config.Loaded,
) !void {
	const payload = try readStdinAll(allocator, io);
	defer allocator.free(payload);

	var parsed: std.ArrayList(cli.AddArgs) = .empty;
	defer parsed.deinit(allocator);
	var bad_line: []const u8 = "";
	cli.parseReplacePayload(allocator, payload, &parsed, &bad_line) catch |err| switch (err) {
		error.OutOfMemory => return err,
		error.TooManyRules => return die(
			allocator,
			io,
			"{d} rules on stdin exceeds the {d}-rule limit; refusing to truncate",
			.{ parsed.items.len, cli.max_total_rules },
			65,
		),
		else => return die(allocator, io, "invalid rule line: {s}", .{bad_line}, 65),
	};

	const tree_alloc = loaded.treeAllocator();
	const removed = rule.deleteByPlugin(rules_arr, r.plugin);
	// deleteByPlugin has already run, so rules_arr now holds exactly what the
	// batch is being appended TO: every user rule and every other plugin's rules.
	const surviving = rules_arr.items.len;
	for (parsed.items) |a| {
		// The SAME projection cmdAdd uses; see cli.attrsOf.
		const attrs = cli.attrsOf(a);
		const n = rule.append(tree_alloc, rules_arr, a.action, a.host, attrs) catch |err| switch (err) {
			error.InvalidHost => return die(allocator, io, "invalid host pattern: {s}", .{a.host}, 65),
			else => return err,
		};
		// Every rule in the batch is stamped from the SINGLE argv --plugin value.
		try stampPlugin(tree_alloc, &rules_arr.items[n - 1], r.plugin);
	}

	// The cap is checked AFTER the append and against the whole tree, because the
	// quantity the enforcer bounds is rendered LINES, and renderL7 emits one extra
	// `allow <host> terminate` per inject-spec host that no rule names -- a set the
	// batch itself changes (a batched allow for a git host suppresses that host's
	// union line). `surviving` + that delta is what the batch is landing on top of;
	// `removed` goes in too, so a batch that does not GROW the rule set is never
	// refused -- otherwise an already-over-cap instance could never be revoked or
	// narrowed. Dying here is still a clean no-op on disk: die() exits before
	// config.save, so the whole edit so far is only in the in-memory tree.
	const inject_lines = reload.injectUnionCount(net.*);
	cli.checkRenderedCap(net.*, surviving, parsed.items.len, removed) catch return die(
		allocator,
		io,
		"{d} rendered rule lines ({d} already present + {d} on stdin + {d} inject-union allow(s)) exceeds the {d}-rule limit; refusing to truncate",
		.{ surviving + parsed.items.len + inject_lines, surviving, parsed.items.len, inject_lines, cli.max_total_rules },
		65,
	);

	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "Replaced {d} l7 rule(s) tagged '{s}' with {d}.", .{ removed, r.plugin, parsed.items.len });
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

/// Read all of stdin with a 1 MiB cap, mirroring `secret add --from-stdin`.
fn readStdinAll(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
	const stdin = std.Io.File.stdin();
	var sbuf: [4096]u8 = undefined;
	var r = stdin.readerStreaming(io, &sbuf);
	return r.interface.allocRemaining(allocator, .limited(1 << 20));
}

/// Read all of stdin under `limit` bytes; `error.StreamTooLong` past it, so an
/// over-cap payload is a LOUD refusal (never a truncation).
fn readStdinCapped(allocator: std.mem.Allocator, io: std.Io, limit: usize) ![]u8 {
	const stdin = std.Io.File.stdin();
	var sbuf: [4096]u8 = undefined;
	var r = stdin.readerStreaming(io, &sbuf);
	return r.interface.allocRemaining(allocator, .limited(limit));
}

/// The auth-proxy policy document's byte cap (CROSS-REPO CONTRACT: cogworx's
/// compiler refuses an over-cap document at compile time, this verb refuses one
/// at delivery). A cap, not a truncation: a truncated JSON document would parse
/// as malformed anyway, but refusing BEFORE the parse keeps the failure named.
pub const max_policy_bytes: usize = 64 * 1024;

/// The auth-proxy policy document schema versions this binary understands.
/// Version 2 adds the fine-grained cap vocabulary (`issues:read`, `mr:merge`,
/// `pipelines:*`, `repo:read`, `wiki:*`) and per-grant push rules; version 1
/// stays accepted FOREVER, because the control plane renders the LOWEST
/// version that carries the grant set losslessly and the empty
/// share-suspension document `{"version":1,"providers":[]}` is byte-pinned at
/// version 1. An unknown value is refused BEFORE any write (fail closed both
/// here and in the enforcer-side conf render, which treats an out-of-range doc
/// as dead text).
pub const policy_doc_versions = [_]i64{ 1, 2 };

fn policyDocVersionKnown(v: i64) bool {
	for (policy_doc_versions) |known| {
		if (v == known) return true;
	}
	return false;
}

pub const PolicyDocError = error{ MalformedPolicy, UnknownPolicyVersion, OutOfMemory };

/// Validate a policy document WITHOUT writing anything: a JSON object carrying
/// a KNOWN `"version"` (1 or 2) and a `providers` array. The EMPTY document
/// `{"version":1,"providers":[]}` is ACCEPTED -- refusing it would leave the
/// previous policy live with the control plane unable to withdraw it, the same
/// reason `l7 replace` accepts an empty batch. Deeper validation is deliberately
/// the consumers': renderAuthProxyConf drops what it cannot gate and the auth
/// proxy's own conf reader refuses what it does not fully understand, so a doc
/// this binary is too old to interpret can only ever DENY, never widen.
pub fn validatePolicyDoc(allocator: std.mem.Allocator, payload: []const u8) PolicyDocError!void {
	var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch |err| switch (err) {
		error.OutOfMemory => return error.OutOfMemory,
		else => return error.MalformedPolicy,
	};
	defer parsed.deinit();
	const root = parsed.value;
	if (root != .object) return error.MalformedPolicy;
	const v = root.object.get("version") orelse return error.MalformedPolicy;
	if (v != .integer or !policyDocVersionKnown(v.integer)) return error.UnknownPolicyVersion;
	const p = root.object.get("providers") orelse return error.MalformedPolicy;
	if (p != .array) return error.MalformedPolicy;
}

fn providerCount(doc: std.json.Value) usize {
	if (doc != .object) return 0;
	const p = doc.object.get("providers") orelse return 0;
	if (p != .array) return 0;
	return p.array.items.len;
}

/// `l7 policy --from-stdin`: whole-document replace of `.network.l7.authpolicy`,
/// the per-instance auth-proxy policy. Read stdin under the byte cap, validate
/// (malformed / unknown version refused BEFORE anything is written), set the
/// config section, save -- then render via rules_module.renderFiles, NOT
/// maybeReload. renderFiles is the pass that writes the inject/auth confs inside
/// ONE credgrant.Grants transaction (Grants.apply revokes group-read on every
/// bound value file and re-grants only the ones that render noted, so a second
/// render pass that noted only the inject conf's files would silently revoke the
/// auth proxy's read access on the next `secret reload`), and it is the only
/// render path that resolves the secret dirs from `env` -- which is why env is
/// threaded into this verb at all. Mirrors `secret reload`'s reRenderInstance
/// shape, both signals included: the render can seed inject specs, and
/// netfilter-rules' funnel is derived from them, so passt must re-read too.
fn cmdPolicy(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	args: cli.Args,
	l7: *std.json.Value,
	loaded: *config.Loaded,
) !void {
	const payload = readStdinCapped(allocator, io, max_policy_bytes) catch |err| switch (err) {
		error.StreamTooLong => return die(
			allocator,
			io,
			"policy document exceeds the {d}-byte cap; refusing",
			.{max_policy_bytes},
			65,
		),
		else => return err,
	};
	defer allocator.free(payload);

	validatePolicyDoc(allocator, payload) catch |err| switch (err) {
		error.OutOfMemory => return err,
		error.MalformedPolicy => return die(allocator, io, "invalid policy document (expected a JSON object with version + providers[])", .{}, 65),
		// The control plane's classifier keys on the SUBSTRING
		// "cogbox l7: error: unknown policy document version" (a newer control
		// plane re-renders the narrowed v1 document on it), so the prefix is a
		// cross-repo contract; only the parenthetical moves as versions land.
		error.UnknownPolicyVersion => return die(allocator, io, "unknown policy document version (expected 1 or 2)", .{}, 65),
	};

	// Re-parse INTO THE CONFIG TREE's arena. alloc_always: the stdin buffer is
	// freed when this function returns, so no parsed string may alias it.
	const arena = loaded.treeAllocator();
	const doc = std.json.parseFromSliceLeaky(std.json.Value, arena, payload, .{ .allocate = .alloc_always }) catch |err| switch (err) {
		error.OutOfMemory => return err,
		else => unreachable, // validatePolicyDoc already parsed these bytes
	};
	try l7.object.put(arena, try arena.dupe(u8, "authpolicy"), doc);

	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "Auth-proxy policy replaced ({d} provider(s)).", .{providerCount(doc)});

	// No live runtime dir => the instance isn't running; the boot render picks
	// the document up on next start (same shape as `secret add -n`).
	const cwd = std.Io.Dir.cwd();
	cwd.access(io, args.runtime_path, .{}) catch {
		try announce(allocator, io, "Instance is not running; the policy renders at its next start.", .{});
		return;
	};
	try rules_module.renderFiles(allocator, io, env, args.config_path, args.runtime_path);
	_ = reload.maybeSignalL7proxy(allocator, io, args.runtime_path) catch {};
	_ = reload.maybeSignalPasst(allocator, io, args.runtime_path) catch {};
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
	var owned: std.ArrayList(u8) = .empty;
	defer owned.deinit(allocator);
	const Slot = struct { off: usize, len: usize };
	var slots: std.ArrayList(Slot) = .empty;
	defer slots.deinit(allocator);

	while (true) {
		const maybe_line = try stdin_reader.interface.takeDelimiter('\n');
		const line = maybe_line orelse break;
		const parsed = rule.parseSetLine(line) catch {
			return die(allocator, io, "invalid line: {s}", .{line}, 65);
		};
		if (parsed) |p| {
			const off = owned.items.len;
			try owned.appendSlice(allocator, p.host);
			try slots.append(allocator, .{ .off = off, .len = p.host.len });
			try pairs.append(allocator, .{ .action = p.action, .host = "" });
		}
	}
	for (pairs.items, slots.items) |*p, s| {
		p.host = owned.items[s.off .. s.off + s.len];
	}

	try rule.replaceAll(loaded.treeAllocator(), rules_arr, pairs.items);
	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "L7 rules replaced.", .{});
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

fn cmdMode(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	l7: *std.json.Value,
	m: cli.ModeArgs,
	loaded: *config.Loaded,
) !void {
	const arena = loaded.treeAllocator();
	const mode_str = if (m.terminate) "terminate" else "passthrough";
	try l7.object.put(arena, try arena.dupe(u8, "mode"), .{ .string = try arena.dupe(u8, mode_str) });
	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "L7 mode set to {s}.", .{mode_str});
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
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
	const msg = std.fmt.allocPrint(allocator, "cogbox l7: error: " ++ fmt ++ "\n", args) catch "cogbox l7: error: (message too long)\n";
	writeStderr(io, msg) catch {};
	std.process.exit(code);
}

// --- Tests ---

const t = std.testing;

test "validatePolicyDoc: the empty document is accepted" {
	// {"version":1,"providers":[]} is the share-suspension form the control
	// plane pushes; refusing it would leave the previous policy live with no
	// way to withdraw it.
	try validatePolicyDoc(t.allocator, "{\"version\":1,\"providers\":[]}");
}

test "validatePolicyDoc: a populated v1 document is accepted" {
	try validatePolicyDoc(t.allocator,
		\\{"version":1,"providers":[{
		\\  "provider":"GitLab","plugin":"gitlab","hosts":["git.example.com"],
		\\  "secret":"git-gitlab","git_user":"oauth2","scheme":"https",
		\\  "grants":[{"id":"gg-1","scope":"project","repo":"grp/proj",
		\\             "project_id":"1234","caps":["git-read","issues"]}]}]}
	);
}

test "validatePolicyDoc: a populated v2 document (fine caps + push rules) is accepted" {
	// Version 2 is the fine-grained vocabulary plus per-grant push rules. This
	// verb still validates only the envelope: what the caps and the push object
	// MEAN is the auth proxy plugin's `compile`, which fails closed on anything
	// it does not fully understand.
	try validatePolicyDoc(t.allocator,
		\\{"version":2,"providers":[{
		\\  "provider":"GitLab","plugin":"gitlab","hosts":["git.example.com"],
		\\  "secret":"git-gitlab","git_user":"oauth2","scheme":"https",
		\\  "grants":[{"id":"gg-1","scope":"project","repo":"grp/proj","project_id":"1234",
		\\             "caps":["git-read","git-write","issues:read","mr:merge"],
		\\             "push":{"deny_delete":true,"deny_tags":true,"refs":["refs/heads/agent/*"]}}]}]}
	);
	// ...and the empty document stays valid at BOTH versions (the control plane
	// pins the share-suspension form at v1, but a v2 empty doc is not malformed).
	try validatePolicyDoc(t.allocator, "{\"version\":2,\"providers\":[]}");
}

test "validatePolicyDoc: malformed and unknown-version documents are refused" {
	// Malformed JSON / wrong shapes -- all refused BEFORE any write.
	try t.expectError(error.MalformedPolicy, validatePolicyDoc(t.allocator, ""));
	try t.expectError(error.MalformedPolicy, validatePolicyDoc(t.allocator, "not json"));
	try t.expectError(error.MalformedPolicy, validatePolicyDoc(t.allocator, "[]"));
	try t.expectError(error.MalformedPolicy, validatePolicyDoc(t.allocator, "{\"providers\":[]}"));
	try t.expectError(error.MalformedPolicy, validatePolicyDoc(t.allocator, "{\"version\":1}"));
	try t.expectError(error.MalformedPolicy, validatePolicyDoc(t.allocator, "{\"version\":1,\"providers\":{}}"));
	// An unknown (or non-integer) version is its own named refusal: a NEWER
	// schema must never be half-interpreted by an older binary. 3 is the next
	// unlanded one; 0 and a negative are the rolled-back/hand-edited forms.
	try t.expectError(error.UnknownPolicyVersion, validatePolicyDoc(t.allocator, "{\"version\":3,\"providers\":[]}"));
	try t.expectError(error.UnknownPolicyVersion, validatePolicyDoc(t.allocator, "{\"version\":0,\"providers\":[]}"));
	try t.expectError(error.UnknownPolicyVersion, validatePolicyDoc(t.allocator, "{\"version\":-1,\"providers\":[]}"));
	try t.expectError(error.UnknownPolicyVersion, validatePolicyDoc(t.allocator, "{\"version\":\"1\",\"providers\":[]}"));
}

test "max_policy_bytes: an over-cap stdin read is a loud StreamTooLong, not a truncation" {
	// readStdinCapped's limit surfaces as error.StreamTooLong (asserted here on
	// the underlying reader primitive, since stdin itself isn't scriptable in a
	// unit test) -- which cmdPolicy maps to the named exit-65 refusal.
	const big = try t.allocator.alloc(u8, max_policy_bytes + 1);
	defer t.allocator.free(big);
	@memset(big, 'x');
	var r = std.Io.Reader.fixed(big);
	try t.expectError(error.StreamTooLong, r.allocRemaining(t.allocator, .limited(max_policy_bytes)));
}
