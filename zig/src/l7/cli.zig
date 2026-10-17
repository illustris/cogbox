// Argument parser for `cogbox l7`. Mirrors `cogbox rules` so the operator's
// mental model is identical, with one extra subcommand (`mode`).
//
//   cogbox l7 --config CFG --runtime RT list
//   cogbox l7 --config CFG --runtime RT add allow|deny HOST [--at N]
//        [--path P] [--method M[,M]] [--exact] [--service SVC]
//        [--terminate|--passthrough|--insecure-upstream] [--plugin TAG]
//   cogbox l7 --config CFG --runtime RT del INDEX
//   cogbox l7 --config CFG --runtime RT clear --plugin TAG  (drop all TAG rules)
//   cogbox l7 --config CFG --runtime RT set                 (reads stdin)
//   cogbox l7 --config CFG --runtime RT replace --plugin TAG --from-stdin
//   cogbox l7 --config CFG --runtime RT policy --from-stdin
//   cogbox l7 --config CFG --runtime RT mode passthrough|terminate

const std = @import("std");
const filter = @import("filter");
const reload = @import("rules_module").reload;
const rule = @import("rule.zig");

pub const Cmd = union(enum) {
	list,
	add: AddArgs,
	del: DelArgs,
	clear: ClearArgs,
	set,
	replace: ReplaceArgs,
	// `policy --from-stdin`: replace `.network.l7.authpolicy` (the per-instance
	// auth-proxy policy document) with the JSON document on stdin. A subcommand
	// of `l7` ON PURPOSE: an OLD binary answers exit 64 with stderr exactly
	// `cogbox l7: error: UnknownSubcommand` -- the byte-exact payload the
	// control plane already classifies as "fall back to the legacy path".
	policy,
	mode: ModeArgs,
};

pub const AddArgs = struct {
	action: rule.Action,
	host: []const u8,
	pos: ?usize = null, // 1-based; null = append
	path: ?[]const u8 = null, // URL path prefix; implies terminate
	terminate: bool = false, // route this host through the terminate tier
	insecure: bool = false, // skip upstream cert verification; implies terminate
	passthrough: bool = false, // opt OUT of the terminate default (SNI-only)
	// --plugin NAME: tag the inserted rule with `"plugin": "<name>"` so a later
	// `plugin del <name>` / `l7 clear --plugin <name>` removes exactly it
	// (admin-approved deferred plugin rule, or a git-grant-tagged rule).
	plugin: ?[]const u8 = null,
	// --method M[,M]: constrain the rule to an uppercase HTTP method list.
	methods: ?[]const u8 = null,
	// --exact: match the path by full equality instead of the default prefix.
	exact: bool = false,
	// --service SVC: constrain to a git smart-HTTP service (git-upload-pack /
	// git-receive-pack).
	service: ?[]const u8 = null,
};

pub const DelArgs = struct {
	index: usize, // 1-based
};

pub const ClearArgs = struct {
	// Remove every rule tagged with this `"plugin"` value (e.g. `git-grants`).
	plugin: []const u8,
};

pub const ReplaceArgs = struct {
	// Drop every rule tagged with this `"plugin"` value, then append the rules
	// read from stdin stamped with the SAME tag -- one config edit, one reload.
	// The tag is argv-level and appears exactly once per invocation: that is the
	// tag-integrity mechanism, so a stdin line may not carry one of its own.
	plugin: []const u8,
};

pub const ModeArgs = struct {
	terminate: bool,
};

pub const Args = struct {
	config_path: []const u8,
	runtime_path: []const u8,
	cmd: Cmd,
};

pub const ParseError = error{
	MissingConfig,
	MissingRuntime,
	MissingSubcommand,
	UnknownSubcommand,
	InvalidArgs,
	InvalidAction,
	InvalidMode,
	InvalidIndex,
};

pub fn parse(argv: []const []const u8) ParseError!Args {
	var config: ?[]const u8 = null;
	var runtime: ?[]const u8 = null;
	var i: usize = 0;

	while (i < argv.len) : (i += 1) {
		const a = argv[i];
		if (std.mem.eql(u8, a, "--config")) {
			i += 1;
			if (i >= argv.len) return error.InvalidArgs;
			config = argv[i];
		} else if (std.mem.eql(u8, a, "--runtime")) {
			i += 1;
			if (i >= argv.len) return error.InvalidArgs;
			runtime = argv[i];
		} else if (std.mem.startsWith(u8, a, "--")) {
			return error.InvalidArgs;
		} else {
			break;
		}
	}

	const cfg_path = config orelse return error.MissingConfig;
	const rt_path = runtime orelse return error.MissingRuntime;
	if (i >= argv.len) return error.MissingSubcommand;

	const sub = argv[i];
	i += 1;
	const sub_args = argv[i..];

	if (std.mem.eql(u8, sub, "list")) {
		if (sub_args.len != 0) return error.InvalidArgs;
		return .{ .config_path = cfg_path, .runtime_path = rt_path, .cmd = .list };
	}
	if (std.mem.eql(u8, sub, "set")) {
		if (sub_args.len != 0) return error.InvalidArgs;
		return .{ .config_path = cfg_path, .runtime_path = rt_path, .cmd = .set };
	}
	if (std.mem.eql(u8, sub, "add")) return parseAdd(cfg_path, rt_path, sub_args);
	if (std.mem.eql(u8, sub, "del")) return parseDel(cfg_path, rt_path, sub_args);
	if (std.mem.eql(u8, sub, "clear")) return parseClear(cfg_path, rt_path, sub_args);
	if (std.mem.eql(u8, sub, "replace")) return parseReplace(cfg_path, rt_path, sub_args);
	if (std.mem.eql(u8, sub, "policy")) return parsePolicy(cfg_path, rt_path, sub_args);
	if (std.mem.eql(u8, sub, "mode")) return parseMode(cfg_path, rt_path, sub_args);
	return error.UnknownSubcommand;
}

fn parseAdd(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .add = try parseAddTail(args) },
	};
}

/// The argv tail of `l7 add`: `allow|deny HOST [flags...]`. Factored out of
/// parseAdd so `l7 replace`'s stdin lines go through the SAME grammar -- there
/// is no second rule syntax to keep in step, per rule the two are the same
/// function.
///
/// Deliberately carries NO whitespace/control-character restriction on its
/// values. That restriction is a property of the LINE FORMAT, not of the rule
/// grammar, so it lives in parseReplaceLine (see lineSafeValue): `l7 add` is the
/// verb an old control plane falls back to, and its argv grammar is a
/// back-compat pin -- tightening it here would turn an invocation that works in
/// the field today into an exit-64 after an agent-image roll.
pub fn parseAddTail(args: []const []const u8) ParseError!AddArgs {
	if (args.len < 2) return error.InvalidArgs;
	const action = parseAction(args[0]) orelse return error.InvalidAction;
	const host = args[1];
	var pos: ?usize = null;
	var path: ?[]const u8 = null;
	var terminate = false;
	var insecure = false;
	var passthrough = false;
	var plugin: ?[]const u8 = null;
	var methods: ?[]const u8 = null;
	var exact = false;
	var service: ?[]const u8 = null;

	var i: usize = 2;
	while (i < args.len) : (i += 1) {
		if (std.mem.eql(u8, args[i], "--at")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			pos = std.fmt.parseInt(usize, args[i], 10) catch return error.InvalidIndex;
			if (pos.? == 0) return error.InvalidIndex;
		} else if (std.mem.eql(u8, args[i], "--path")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			path = args[i];
			if (path.?.len == 0 or path.?[0] != '/') return error.InvalidArgs;
		} else if (std.mem.eql(u8, args[i], "--terminate")) {
			terminate = true;
		} else if (std.mem.eql(u8, args[i], "--insecure-upstream")) {
			insecure = true;
		} else if (std.mem.eql(u8, args[i], "--passthrough")) {
			passthrough = true;
		} else if (std.mem.eql(u8, args[i], "--plugin")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			plugin = args[i];
		} else if (std.mem.eql(u8, args[i], "--method")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			methods = args[i];
			if (!validMethods(methods.?)) return error.InvalidArgs;
		} else if (std.mem.eql(u8, args[i], "--exact")) {
			exact = true;
		} else if (std.mem.eql(u8, args[i], "--service")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			service = args[i];
			if (service.?.len == 0) return error.InvalidArgs;
		} else {
			return error.InvalidArgs;
		}
	}

	// A path constraint is only enforceable on a terminated stream, and
	// skipping upstream cert verification only makes sense when we terminate
	// (it governs the proxy<->upstream TLS leg); both imply terminate. A
	// method/exact/service constraint is likewise only meaningful on the
	// terminated leg, so it implies terminate too.
	if (path != null or insecure or methods != null or exact or service != null) terminate = true;

	// --passthrough is the opt-OUT of the terminate default; it can't be
	// combined with anything that forces (or implies) terminate.
	if (passthrough and (terminate or path != null or insecure or methods != null or exact or service != null)) return error.InvalidArgs;

	return .{ .action = action, .host = host, .pos = pos, .path = path, .terminate = terminate, .insecure = insecure, .passthrough = passthrough, .plugin = plugin, .methods = methods, .exact = exact, .service = service };
}

/// Project a parsed AddArgs onto the rule-object attributes it writes. ONE
/// function, called by both `cmdAdd` and `cmdReplace`, so the emit half of the
/// pipeline is shared the way parseAddTail shares the parse half.
///
/// Field-for-field duplication of this mapping is how `l7 add` and `l7 replace`
/// would come to emit DIFFERENT config objects for the same input: adding a
/// field to AddArgs/rule.Attrs and wiring it into one verb only is a silent
/// divergence, and per-rule equivalence is the property the whole batch verb
/// rests on. Structure, not convention.
pub fn attrsOf(a: AddArgs) rule.Attrs {
	return .{
		.path = a.path,
		.terminate = a.terminate,
		.insecure = a.insecure,
		.passthrough = a.passthrough,
		.methods = a.methods,
		.exact = a.exact,
		.service = a.service,
	};
}

/// Reject a token that cannot survive the whitespace-tokenized, newline-
/// delimited wire formats a BATCHED rule rides in -- the `l7 replace` stdin
/// payload, and the rendered `l7-rules` document filter.parseL7Line reads back.
///
/// This is a property of the line FORMAT, not of the rule grammar, which is why
/// it is applied here to the raw tokens rather than inside parseAddTail:
/// parseAddTail is also `l7 add`'s argv parser, and `l7 add` is byte-untouched
/// (it is the verb an old control plane falls back to, so its grammar is the
/// back-compat pin -- see the note there). A newline is the case that matters:
/// it would split one rule into two, and the second half would be appended
/// stamped with the invocation's `--plugin` tag.
///
/// Space, tab and newline cannot actually reach a token (the first two are the
/// tokenizer's delimiters, and parseReplacePayload splits the payload on the
/// third), so what this catches in practice is an embedded CR or other control
/// byte, plus any caller that hands parseReplaceLine a whole multi-line string
/// directly. --method needs no separate check (validMethods admits only [A-Z,]).
///
/// Note what it does NOT need to catch: a whitespace-PADDED host. The tokenizer
/// eats the padding, so a batch can only ever store the bare spelling -- which
/// is also the spelling reload.hostNamedInRules compares, so a batched rule
/// always suppresses its host's inject-union line. (`l7 add` can still store a
/// padded host, because filter.parseDnsPattern trims before validating; that
/// costs an extra rendered line, which the cap in cmdReplace now counts.)
fn lineSafeValue(s: []const u8) bool {
	for (s) |c| if (c <= ' ' or c == 0x7f) return false;
	return true;
}

/// Parse ONE `l7 replace` stdin line: the argv tail of `l7 add`, tokenized on
/// space/tab. Blank and `#` lines are skipped (null), matching parseSetLine.
///
/// No quoting layer: every value a line can carry (host, path, method list,
/// service) is a single whitespace-delimited token, and lineSafeValue rejects a
/// token carrying anything the format could not round-trip. So a space is always
/// a token boundary and never part of a value.
///
/// `--at`, `--plugin` and a `tag=` token are hard errors. The tag is argv-level
/// and stamped once per invocation; a line that could carry its own would let a
/// caller with one plugin's tag write rules under another's. `--at` is refused
/// because a batch is append-only in stdin order (bit-identical to the
/// `clear --plugin` + N flagless adds it replaces).
///
/// Tokens alias `line`, so the caller must keep the backing buffer alive.
pub fn parseReplaceLine(allocator: std.mem.Allocator, line: []const u8) (ParseError || error{OutOfMemory})!?AddArgs {
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	if (trimmed.len == 0 or trimmed[0] == '#') return null;

	var toks: std.ArrayList([]const u8) = .empty;
	defer toks.deinit(allocator);
	var it = std.mem.tokenizeAny(u8, trimmed, " \t");
	while (it.next()) |tok| {
		if (std.mem.eql(u8, tok, "--at")) return error.InvalidArgs;
		if (std.mem.eql(u8, tok, "--plugin")) return error.InvalidArgs;
		if (std.mem.startsWith(u8, tok, "tag=")) return error.InvalidArgs;
		if (!lineSafeValue(tok)) return error.InvalidArgs;
		try toks.append(allocator, tok);
	}
	return try parseAddTail(toks.items);
}

/// The enforcer's own L7 rule bound, single-sourced: filter.parseL7Rules
/// compiles the first this-many rule LINES of the rendered `l7-rules` document
/// and SILENTLY DROPS the rest, while the terminate-tier addon parsing the same
/// document has no cap. So letting a tail fall off does not degrade, it leaves
/// the two enforcement layers disagreeing about what is allowed. Over-cap is
/// therefore a refusal, never a truncation.
///
/// It bounds the resulting TOTAL, not the batch: a replace appends its rules to
/// whatever survives `deleteByPlugin` (every user rule and every OTHER plugin's
/// rules), so a batch that fits on its own can still overflow. The batch-only
/// check in parseReplacePayload is just a cheap early bail; the binding check is
/// checkRenderedCap, applied in cmdReplace once the whole result is known.
///
/// NOT enforced on `l7 add`, which is uncapped and stays byte-untouched -- so
/// the pre-`replace` fallback path (clear + N add) can still overflow the array
/// one rule at a time. Closing that would change a verb old agents depend on.
pub const max_total_rules = filter.max_l7_rules;

/// Refuse a replace whose RESULT would not fit the enforcer's rule array.
/// `existing` is how many rendered rule LINES the document will carry that did
/// NOT come from this batch, `batch` is the number of rules on stdin, and
/// `removed` is how many the tag drop took out.
///
/// LINES, not `.l7.rules[]` entries: renderL7 emits more lines than the config
/// array holds (see checkRenderedCap), and lines are what the enforcer caps.
/// Callers go through checkRenderedCap so that arithmetic is done in one place.
///
/// Only a replace that GROWS the rule set is refused. It can ALREADY be over
/// cap: `l7 add` is uncapped by design (it is the verb old agents depend on, so
/// the pre-`replace` clear-then-add fallback can drive it there one rule at a
/// time). Bounding the result unconditionally would then refuse EVERY replace on
/// such an instance -- including the empty batch that REVOKES the tagged set,
/// and including a narrowing edit -- leaving the previous git-grant allow rules
/// in force with no self-heal path, while the uncapped `l7 clear` the batch verb
/// replaced would have revoked them. A batch no larger than what it removed
/// cannot worsen the overflow, so it always goes through: on an allow list,
/// taking rules AWAY must never be the operation that fails. (A shrinking batch
/// CAN still lengthen the document by one line -- dropping the only rule that
/// named an inject host un-suppresses that host's union line -- and that is
/// accepted: the escape hatch must never become the trap it exists to avoid.)
pub fn checkTotalCap(existing: usize, batch: usize, removed: usize) error{TooManyRules}!void {
	if (batch <= removed) return; // a revoke or a narrowing edit: never refused
	if (existing + batch > max_total_rules) return error.TooManyRules;
}

/// The binding cap check for `l7 replace`, over the RENDERED document rather
/// than the config array.
///
/// `.l7.rules[]` is NOT what the enforcer measures. renderL7 appends one
/// `allow <host> terminate` line for every `.l7.inject.specs[].host` that no
/// rule names (reload.injectUnionCount), so a result of `existing + batch`
/// array entries can render `existing + batch + delta` lines -- and
/// filter.parseL7Rules drops the tail past max_total_rules in silence while the
/// terminate-tier addon reading the same document keeps honouring it. Bounding
/// the array alone would let exactly the divergence this refusal advertises
/// itself as preventing through the check. The delta is counted with
/// reload.injectUnionCount, i.e. the same iterator renderL7 emits from, so the
/// budget and the document cannot drift apart.
///
/// `network` must be the tree AFTER the batch has been appended, and `surviving`
/// the `.l7.rules[]` length from BEFORE it: a batch rule that names an inject
/// host suppresses that host's union line, so counting the delta against the
/// post-drop tree instead would over-count and refuse a replace that in fact
/// fits -- which is the common re-grant shape, since the git-grant rules being
/// replaced are themselves the rules naming the git inject hosts.
pub fn checkRenderedCap(network: std.json.Value, surviving: usize, batch: usize, removed: usize) error{TooManyRules}!void {
	return checkTotalCap(surviving + reload.injectUnionCount(network), batch, removed);
}

pub const BatchParseError = ParseError || error{ OutOfMemory, TooManyRules };

/// Parse a whole `l7 replace` stdin payload, appending one AddArgs per rule line
/// to `out` in stdin order. On a per-line failure `bad_line` is set to the
/// offending line so the caller can name it. Both failure modes are the caller's
/// exit-65 (EX_DATAERR) path.
///
/// Tokens alias `payload`, so the caller must keep it alive until the rules are
/// duped into the config tree.
///
/// The TooManyRules check here is only a cheap early bail on a batch that could
/// not fit even an empty array; the binding one is checkTotalCap in cmdReplace,
/// which knows how many rules the batch is being appended TO.
pub fn parseReplacePayload(
	allocator: std.mem.Allocator,
	payload: []const u8,
	out: *std.ArrayList(AddArgs),
	bad_line: *[]const u8,
) BatchParseError!void {
	var lines = std.mem.splitScalar(u8, payload, '\n');
	while (lines.next()) |line| {
		const maybe = parseReplaceLine(allocator, line) catch |err| {
			bad_line.* = line;
			return err;
		};
		if (maybe) |a| try out.append(allocator, a);
	}
	if (out.items.len > max_total_rules) return error.TooManyRules;
}

/// A `--method` value is a non-empty comma-separated list of uppercase-ASCII
/// method tokens (`GET` / `GET,POST`). Rejects lowercase / empty / stray chars
/// so the rendered l7-rules line's METHODS token round-trips through the zig
/// parser (which admits only all-uppercase-and-comma method tokens).
pub fn validMethods(s: []const u8) bool {
	if (s.len == 0) return false;
	var saw_letter = false;
	for (s) |c| switch (c) {
		'A'...'Z' => saw_letter = true,
		',' => {},
		else => return false,
	};
	return saw_letter;
}

fn parseClear(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len != 2 or !std.mem.eql(u8, args[0], "--plugin")) return error.InvalidArgs;
	if (args[1].len == 0) return error.InvalidArgs;
	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .clear = .{ .plugin = args[1] } },
	};
}

/// `replace --plugin TAG --from-stdin`. Both flags are required: --from-stdin is
/// mandatory (and not a default) so the verb can never be invoked in a form that
/// silently wipes a tagged set from an empty argv.
fn parseReplace(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	var plugin: ?[]const u8 = null;
	var from_stdin = false;
	var i: usize = 0;
	while (i < args.len) : (i += 1) {
		if (std.mem.eql(u8, args[i], "--plugin")) {
			i += 1;
			if (i >= args.len) return error.InvalidArgs;
			plugin = args[i];
		} else if (std.mem.eql(u8, args[i], "--from-stdin")) {
			from_stdin = true;
		} else {
			return error.InvalidArgs;
		}
	}
	const tag = plugin orelse return error.InvalidArgs;
	if (tag.len == 0 or !from_stdin) return error.InvalidArgs;
	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .replace = .{ .plugin = tag } },
	};
}

/// `policy --from-stdin`. The flag is required (and not a default) for the same
/// reason parseReplace's is: the verb replaces the WHOLE policy document, so it
/// must never be invocable in a form that silently wipes it from an empty argv.
fn parsePolicy(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len != 1 or !std.mem.eql(u8, args[0], "--from-stdin")) return error.InvalidArgs;
	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .policy,
	};
}

fn parseDel(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len != 1) return error.InvalidArgs;
	const idx = std.fmt.parseInt(usize, args[0], 10) catch return error.InvalidIndex;
	if (idx == 0) return error.InvalidIndex;
	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .del = .{ .index = idx } },
	};
}

fn parseMode(cfg: []const u8, rt: []const u8, args: []const []const u8) ParseError!Args {
	if (args.len != 1) return error.InvalidArgs;
	var terminate: bool = undefined;
	if (std.mem.eql(u8, args[0], "passthrough")) {
		terminate = false;
	} else if (std.mem.eql(u8, args[0], "terminate")) {
		terminate = true;
	} else {
		return error.InvalidMode;
	}
	return .{
		.config_path = cfg,
		.runtime_path = rt,
		.cmd = .{ .mode = .{ .terminate = terminate } },
	};
}

fn parseAction(s: []const u8) ?rule.Action {
	if (std.mem.eql(u8, s, "allow")) return .allow;
	if (std.mem.eql(u8, s, "deny")) return .deny;
	return null;
}

// --- Tests ---

const t = std.testing;

test "list parses" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "list" });
	try t.expect(a.cmd == .list);
}

test "add allow host without --at" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "vhost-a.test" });
	try t.expect(a.cmd == .add);
	try t.expectEqual(rule.Action.allow, a.cmd.add.action);
	try t.expectEqualStrings("vhost-a.test", a.cmd.add.host);
	try t.expect(a.cmd.add.pos == null);
}

test "add with --at" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "deny", "*.evil.test", "--at", "2" });
	try t.expectEqual(@as(?usize, 2), a.cmd.add.pos);
	try t.expectEqual(rule.Action.deny, a.cmd.add.action);
}

test "add rejects bad action and --at 0" {
	try t.expectError(error.InvalidAction, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "permit", "a.test" }));
	try t.expectError(error.InvalidIndex, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "a.test", "--at", "0" }));
}

test "add --path implies terminate" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "api.test", "--path", "/v1/" });
	try t.expectEqualStrings("/v1/", a.cmd.add.path.?);
	try t.expect(a.cmd.add.terminate);
}

test "add --terminate without path" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "api.test", "--terminate" });
	try t.expect(a.cmd.add.path == null);
	try t.expect(a.cmd.add.terminate);
}

test "add --insecure-upstream implies terminate" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "internal.svc", "--insecure-upstream" });
	try t.expect(a.cmd.add.insecure);
	try t.expect(a.cmd.add.terminate);
	try t.expect(a.cmd.add.path == null);
}

test "add --insecure-upstream composes with --path" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "internal.svc", "--path", "/api/", "--insecure-upstream" });
	try t.expectEqualStrings("/api/", a.cmd.add.path.?);
	try t.expect(a.cmd.add.insecure);
	try t.expect(a.cmd.add.terminate);
}

test "add rejects malformed --path" {
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "a.test", "--path", "noslash" }));
}

// BACK-COMPAT PIN. `l7 add` is the verb the control plane's rolling-upgrade
// fallback drives, so its argv grammar must keep accepting byte-for-byte what it
// accepted before `l7 replace` existed: an invocation working in the field today
// cannot start exiting 64 after an agent-image roll. Every case below was
// measured against the pre-`replace` parser. The line-format whitespace ban is
// parseReplaceLine's, not this parser's.
test "l7 add's grammar is byte-untouched: padded host, whitespace path/service" {
	// filter.parseDnsPattern TRIMS leading/trailing space and tab before
	// isValidHostName, so a padded host has always parsed AND validated -- and is
	// stored with its padding.
	for ([_][]const u8{ " git.example.com", "git.example.com ", "\tgit.example.com", " git.example.com " }) |padded| {
		const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", padded });
		try t.expectEqualStrings(padded, a.cmd.add.host);
		try t.expect(rule.validateHost(a.cmd.add.host));
	}
	// A host parseDnsPattern will NOT trim (it trims only space and tab) still
	// parses here and is still rejected DOWNSTREAM, by rule.validateHost as the
	// cmdAdd exit-65 "invalid host pattern" -- which is exactly where it was
	// rejected before, not at parse with exit 64.
	const nl = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "git.example.com\n" });
	try t.expectEqualStrings("git.example.com\n", nl.cmd.add.host);
	try t.expect(!rule.validateHost(nl.cmd.add.host));
	// --path keeps its only rule (non-empty, leading slash) and --service its only
	// rule (non-empty); neither has ever been whitespace-checked on argv.
	const ws = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "a.test", "--path", "/a b/", "--service", "git upload pack" });
	try t.expectEqualStrings("/a b/", ws.cmd.add.path.?);
	try t.expectEqualStrings("git upload pack", ws.cmd.add.service.?);
	const pnl = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "a.test", "--path", "/a\nallow evil.test" });
	try t.expectEqualStrings("/a\nallow evil.test", pnl.cmd.add.path.?);
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "a.test", "--path", "noslash" }));
	// The ordinary values still parse.
	const ok = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "a.test", "--path", "/a/b.git/info/refs", "--service", "git-upload-pack" });
	try t.expectEqualStrings("/a/b.git/info/refs", ok.cmd.add.path.?);
	try t.expectEqualStrings("git-upload-pack", ok.cmd.add.service.?);
}

test "parseReplaceLine rejects a token the line format cannot round-trip" {
	// The whitespace/control ban belongs to the LINE format and is enforced on the
	// raw tokens. Space and tab are the tokenizer's delimiters and a newline is
	// parseReplacePayload's record separator, so what is left to catch is an
	// embedded CR or other control byte -- and a caller handing this function a
	// whole multi-line string, where the second half would be appended stamped
	// with the invocation's --plugin tag.
	for ([_][]const u8{
		"allow a.test --path /a\rb",
		"allow a.test --path /a\nallow",
		"allow a.test --service git-upload-pack\x0bevil",
		"allow git.example.com\x7f",
		"allow a.test\x00 --path /v1/",
	}) |bad| {
		try t.expectError(error.InvalidArgs, parseReplaceLine(t.allocator, bad));
	}
	// A padded host is not expressible as a line at all: the tokenizer eats the
	// padding, so a batch can only ever store the bare spelling -- the spelling
	// reload.hostNamedInRules compares.
	const line = (try parseReplaceLine(t.allocator, " allow \t git.example.com ")).?;
	try t.expectEqualStrings("git.example.com", line.host);
}

test "add --passthrough opts out, and rejects mixing with terminate flags" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "pinned.test", "--passthrough" });
	try t.expect(a.cmd.add.passthrough);
	try t.expect(!a.cmd.add.terminate);
	// --passthrough can't be combined with anything that forces terminate
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "x.test", "--passthrough", "--terminate" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "x.test", "--passthrough", "--path", "/v1/" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "x.test", "--passthrough", "--insecure-upstream" }));
}

test "add --plugin tag" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "api.example.com", "--plugin", "obs-plugin" });
	try t.expectEqualStrings("obs-plugin", a.cmd.add.plugin.?);
	try t.expectEqualStrings("api.example.com", a.cmd.add.host);
	// Default is no tag (backward compat).
	const b = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "api.example.com" });
	try t.expect(b.cmd.add.plugin == null);
	// Combines with --path / --at.
	const c = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "api.example.com", "--path", "/v1/", "--plugin", "p", "--at", "1" });
	try t.expectEqualStrings("p", c.cmd.add.plugin.?);
	try t.expect(c.cmd.add.terminate);
	// --plugin without a value errors.
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "api.example.com", "--plugin" }));
}

test "add --method/--exact/--service parse and imply terminate" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "git.example.internal", "--method", "POST", "--exact", "--service", "git-upload-pack", "--path", "/g/p.git/git-upload-pack", "--plugin", "git-grants" });
	try t.expect(a.cmd == .add);
	try t.expectEqualStrings("POST", a.cmd.add.methods.?);
	try t.expect(a.cmd.add.exact);
	try t.expectEqualStrings("git-upload-pack", a.cmd.add.service.?);
	try t.expectEqualStrings("git-grants", a.cmd.add.plugin.?);
	try t.expect(a.cmd.add.terminate); // any of method/exact/service implies terminate
	// A comma method list is accepted.
	const b = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "h.test", "--method", "GET,POST" });
	try t.expectEqualStrings("GET,POST", b.cmd.add.methods.?);
	// Back-compat: no new flags -> all empty/false.
	const c = try parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "h.test" });
	try t.expect(c.cmd.add.methods == null);
	try t.expect(!c.cmd.add.exact);
	try t.expect(c.cmd.add.service == null);
	// lowercase / empty method values reject; --passthrough can't mix with them.
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "h.test", "--method", "get" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "h.test", "--passthrough", "--exact" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "add", "allow", "h.test", "--service" }));
}

test "clear --plugin parses; rejects missing/other flag" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "clear", "--plugin", "git-grants" });
	try t.expect(a.cmd == .clear);
	try t.expectEqualStrings("git-grants", a.cmd.clear.plugin);
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "clear" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "clear", "git-grants" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "clear", "--plugin", "" }));
}

test "mode terminate parses (no longer rejected at parse)" {
	const m = try parse(&.{ "--config", "/c", "--runtime", "/r", "mode", "terminate" });
	try t.expect(m.cmd.mode.terminate);
}

test "del + mode parse" {
	const d = try parse(&.{ "--config", "/c", "--runtime", "/r", "del", "3" });
	try t.expectEqual(@as(usize, 3), d.cmd.del.index);
	const m = try parse(&.{ "--config", "/c", "--runtime", "/r", "mode", "terminate" });
	try t.expect(m.cmd.mode.terminate);
	try t.expectError(error.InvalidMode, parse(&.{ "--config", "/c", "--runtime", "/r", "mode", "sideways" }));
}

test "unknown subcommand" {
	try t.expectError(error.UnknownSubcommand, parse(&.{ "--config", "/c", "--runtime", "/r", "blast" }));
	// `replace` is now known, but a genuinely unknown verb must still produce the
	// exact exit-64 UnknownSubcommand signature the control plane classifies on.
	try t.expectError(error.UnknownSubcommand, parse(&.{ "--config", "/c", "--runtime", "/r", "reeplace" }));
	// Same guard for a near-miss of `policy` -- the verb the classified
	// old-binary refusal is FOR, so its own typo class must keep the signature.
	try t.expectError(error.UnknownSubcommand, parse(&.{ "--config", "/c", "--runtime", "/r", "policyy" }));
}

test "policy --from-stdin parses; the flag is mandatory and exclusive" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "policy", "--from-stdin" });
	try t.expect(a.cmd == .policy);
	// --from-stdin is required (never a default), and nothing else is accepted:
	// the verb replaces the WHOLE document, so a stray argv form must not be
	// able to invoke it.
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "policy" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "policy", "--from-stdin", "extra" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "policy", "--plugin", "gitlab" }));
}

test "replace --plugin --from-stdin parses; rejects missing/empty flags" {
	const a = try parse(&.{ "--config", "/c", "--runtime", "/r", "replace", "--plugin", "git-grants", "--from-stdin" });
	try t.expect(a.cmd == .replace);
	try t.expectEqualStrings("git-grants", a.cmd.replace.plugin);
	// Flag order does not matter.
	const b = try parse(&.{ "--config", "/c", "--runtime", "/r", "replace", "--from-stdin", "--plugin", "obs-plugin" });
	try t.expectEqualStrings("obs-plugin", b.cmd.replace.plugin);
	// --plugin is mandatory, non-empty, and needs a value; so is --from-stdin.
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "replace" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "replace", "--from-stdin" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "replace", "--plugin", "--from-stdin" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "replace", "--plugin" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "replace", "--plugin", "", "--from-stdin" }));
	try t.expectError(error.InvalidArgs, parse(&.{ "--config", "/c", "--runtime", "/r", "replace", "--plugin", "p", "--from-stdin", "extra" }));
}

// The equivalence pin: for the SAME rule, a stdin line and an `l7 add` argv tail
// must produce the same AddArgs. If they ever diverge, a batched grant and a
// singly-added one would enforce differently -- with the batch being the path
// every git grant now takes.
test "parseReplaceLine equals parseAddTail per rule" {
	const cases: []const []const []const u8 = &.{
		&.{ "allow", "git.example.com" },
		&.{ "deny", "*.evil.test" },
		&.{ "allow", "api.example.com", "--path", "/v1/" },
		&.{ "allow", "pinned.example.com", "--passthrough" },
		&.{ "allow", "internal.svc", "--insecure-upstream" },
		&.{ "allow", "git.example.com", "--method", "GET,POST", "--path", "/acme/", "--service", "git-upload-pack" },
		&.{ "allow", "git.example.com", "--path", "/acme/repo.git", "--exact" },
		&.{ "deny", "api.example.com", "--method", "POST", "--path", "/api/v4/", "--terminate" },
	};
	for (cases) |argv| {
		const want = try parseAddTail(argv);
		// Render the same rule as one stdin line, then parse it back.
		var buf: [256]u8 = undefined;
		var used: usize = 0;
		for (argv, 0..) |tok, i| {
			if (i > 0) {
				buf[used] = ' ';
				used += 1;
			}
			@memcpy(buf[used..][0..tok.len], tok);
			used += tok.len;
		}
		const got = (try parseReplaceLine(t.allocator, buf[0..used])).?;
		try t.expectEqual(want.action, got.action);
		try t.expectEqualStrings(want.host, got.host);
		try t.expectEqual(want.pos, got.pos);
		try t.expectEqual(want.terminate, got.terminate);
		try t.expectEqual(want.insecure, got.insecure);
		try t.expectEqual(want.passthrough, got.passthrough);
		try t.expectEqual(want.exact, got.exact);
		try t.expect(want.plugin == null and got.plugin == null);
		if (want.path) |p| try t.expectEqualStrings(p, got.path.?) else try t.expect(got.path == null);
		if (want.methods) |m| try t.expectEqualStrings(m, got.methods.?) else try t.expect(got.methods == null);
		if (want.service) |s| try t.expectEqualStrings(s, got.service.?) else try t.expect(got.service == null);
	}
	// Tab is a token separator too.
	const tabbed = (try parseReplaceLine(t.allocator, "allow\tgit.example.com\t--path\t/acme/")).?;
	try t.expectEqualStrings("git.example.com", tabbed.host);
	try t.expectEqualStrings("/acme/", tabbed.path.?);
}

// The equivalence pin, one layer further down: the same rule must produce the
// same CONFIG OBJECT whether it arrived as an `l7 add` argv tail or an
// `l7 replace` stdin line. parseAddTail shares the parse half; attrsOf shares
// the emit half. Without the latter the two verbs' AddArgs -> rule.Attrs
// mappings were duplicated struct literals, agreeing by convention only -- a new
// field wired into one verb and not the other would have diverged silently, and
// nothing anywhere compared the emitted objects.
test "attrsOf makes add and replace emit the same rule object" {
	var arena = std.heap.ArenaAllocator.init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();

	const cases: []const []const []const u8 = &.{
		&.{ "allow", "git.example.com" },
		&.{ "deny", "*.evil.test" },
		&.{ "allow", "pinned.example.com", "--passthrough" },
		&.{ "allow", "internal.svc", "--insecure-upstream" },
		&.{ "allow", "git.example.com", "--method", "GET,POST", "--path", "/acme/repo.git/info/refs", "--exact", "--service", "git-upload-pack" },
		&.{ "deny", "api.example.com", "--method", "POST", "--path", "/api/v4/projects/1/access_tokens", "--exact" },
	};
	for (cases) |argv| {
		const from_argv = try parseAddTail(argv);

		var buf: [256]u8 = undefined;
		var used: usize = 0;
		for (argv, 0..) |tok, i| {
			if (i > 0) {
				buf[used] = ' ';
				used += 1;
			}
			@memcpy(buf[used..][0..tok.len], tok);
			used += tok.len;
		}
		const from_line = (try parseReplaceLine(t.allocator, buf[0..used])).?;

		const want = try rule.newRuleObject(a, from_argv.action, from_argv.host, attrsOf(from_argv));
		const got = try rule.newRuleObject(a, from_line.action, from_line.host, attrsOf(from_line));
		try t.expectEqual(want.object.count(), got.object.count());
		var it = want.object.iterator();
		while (it.next()) |e| {
			const g = got.object.get(e.key_ptr.*) orelse {
				std.debug.print("missing key {s} for {s}\n", .{ e.key_ptr.*, buf[0..used] });
				return error.TestUnexpectedResult;
			};
			switch (e.value_ptr.*) {
				.string => |s| try t.expectEqualStrings(s, g.string),
				.bool => |b| try t.expectEqual(b, g.bool),
				else => return error.TestUnexpectedResult,
			}
		}
	}
}

test "parseReplaceLine skips blank and # lines" {
	try t.expect((try parseReplaceLine(t.allocator, "")) == null);
	try t.expect((try parseReplaceLine(t.allocator, "   \t ")) == null);
	try t.expect((try parseReplaceLine(t.allocator, "\r")) == null);
	try t.expect((try parseReplaceLine(t.allocator, "# a comment")) == null);
	try t.expect((try parseReplaceLine(t.allocator, "   # indented comment")) == null);
	// A trailing \r (CRLF payload) does not corrupt the last token.
	const a = (try parseReplaceLine(t.allocator, "allow api.example.com\r")).?;
	try t.expectEqualStrings("api.example.com", a.host);
}

// Tag integrity: the --plugin value is argv-level, exactly once per invocation.
// A line that could carry --plugin (or a rendered `tag=`) would let one tagged
// batch write rules owned by another tag -- e.g. a plugin spoofing `git-grants`.
// --at is refused for the same reason ordering is not per-line: a batch is
// append-only.
test "parseReplaceLine rejects --at / --plugin / tag= inside a line" {
	try t.expectError(error.InvalidArgs, parseReplaceLine(t.allocator, "allow a.test --at 1"));
	try t.expectError(error.InvalidArgs, parseReplaceLine(t.allocator, "allow a.test --plugin git-grants"));
	try t.expectError(error.InvalidArgs, parseReplaceLine(t.allocator, "allow a.test tag=git-grants"));
	try t.expectError(error.InvalidArgs, parseReplaceLine(t.allocator, "allow a.test --plugin"));
	// Still rejected when it is not the last token.
	try t.expectError(error.InvalidArgs, parseReplaceLine(t.allocator, "allow a.test --plugin p --path /v1/"));
	// And a line that is simply malformed is an error, not a skip.
	try t.expectError(error.InvalidAction, parseReplaceLine(t.allocator, "permit a.test"));
	try t.expectError(error.InvalidArgs, parseReplaceLine(t.allocator, "allow"));
	try t.expectError(error.InvalidArgs, parseReplaceLine(t.allocator, "allow a.test --path noslash"));
}

test "parseReplacePayload keeps stdin order and skips blank / # lines" {
	var out: std.ArrayList(AddArgs) = .empty;
	defer out.deinit(t.allocator);
	var bad: []const u8 = "";
	const payload =
		"# git-grants for acme/repo\n" ++
		"allow git.example.com --method GET --path /acme/repo.git/info/refs --exact --service git-upload-pack\n" ++
		"\n" ++
		"   \n" ++
		"allow git.example.com --method POST --path /acme/repo.git/git-upload-pack --exact\n" ++
		"deny api.example.com --method POST --path /api/v4/projects/1/access_tokens --exact\n";
	try parseReplacePayload(t.allocator, payload, &out, &bad);
	try t.expectEqual(@as(usize, 3), out.items.len);
	try t.expectEqualStrings("/acme/repo.git/info/refs", out.items[0].path.?);
	try t.expectEqualStrings("/acme/repo.git/git-upload-pack", out.items[1].path.?);
	try t.expectEqual(rule.Action.deny, out.items[2].action);
	// An empty payload is a valid batch: it is how a revoke-everything clears the tag.
	var empty: std.ArrayList(AddArgs) = .empty;
	defer empty.deinit(t.allocator);
	try parseReplacePayload(t.allocator, "", &empty, &bad);
	try t.expectEqual(@as(usize, 0), empty.items.len);
}

test "parseReplacePayload names the offending line and refuses over-cap" {
	var out: std.ArrayList(AddArgs) = .empty;
	defer out.deinit(t.allocator);
	var bad: []const u8 = "";
	try t.expectError(error.InvalidArgs, parseReplacePayload(t.allocator, "allow a.test\nallow b.test --plugin p\n", &out, &bad));
	try t.expectEqualStrings("allow b.test --plugin p", bad);

	// A batch that could not fit even an EMPTY array is bailed out here. This is
	// only the cheap pre-filter -- see checkTotalCap for the binding bound.
	var buf: std.ArrayList(u8) = .empty;
	defer buf.deinit(t.allocator);
	for (0..max_total_rules) |_| try buf.appendSlice(t.allocator, "allow a.test\n");
	var at_cap: std.ArrayList(AddArgs) = .empty;
	defer at_cap.deinit(t.allocator);
	try parseReplacePayload(t.allocator, buf.items, &at_cap, &bad);
	try t.expectEqual(max_total_rules, at_cap.items.len);

	try buf.appendSlice(t.allocator, "allow a.test\n");
	var over: std.ArrayList(AddArgs) = .empty;
	defer over.deinit(t.allocator);
	try t.expectError(error.TooManyRules, parseReplacePayload(t.allocator, buf.items, &over, &bad));
}

test "checkTotalCap bounds the resulting total, not the batch" {
	// The bound that matters is the one the ENFORCER has: filter.parseL7Rules
	// compiles the first max_total_rules rules of the rendered document and
	// silently drops the rest, while the terminate-tier addon reading the same
	// document has no cap. A batch is appended to whatever survives
	// deleteByPlugin, so an in-cap batch landing on a populated array still
	// overflows -- and it is precisely the dropped git-grant tail that the addon
	// would keep honouring.
	try checkTotalCap(0, max_total_rules, 0);
	try checkTotalCap(max_total_rules, 0, 0);
	try checkTotalCap(max_total_rules - 8, 8, 0);
	// The regression: a batch well under the cap, refused because of what is
	// already there. Before the total check this saved a 131-rule array.
	try t.expectError(error.TooManyRules, checkTotalCap(3, max_total_rules, 0));
	try t.expectError(error.TooManyRules, checkTotalCap(max_total_rules - 8, 9, 0));
	try t.expectError(error.TooManyRules, checkTotalCap(max_total_rules, 1, 0));
}

test "checkTotalCap never refuses a replace that does not grow the array" {
	// An already-over-cap array is reachable: `l7 add` is uncapped, so the
	// pre-`replace` clear-then-add fallback can leave more than max_total_rules
	// rules behind. On such an instance the bound must not become a trap.

	// REVOKE. The empty batch that withdraws a grant: refusing it would leave the
	// previous allow rules live, with `l7 clear` (uncapped) the only remedy -- and
	// the control plane cannot reach it, because exit 65 is not UnknownSubcommand
	// so ApplyGitL7Rules returns the error instead of falling back.
	try checkTotalCap(max_total_rules + 2, 0, 2);
	try checkTotalCap(max_total_rules + 2, 0, 0);

	// NARROWING. A batch strictly smaller than the tagged set it replaces reduces
	// the total; refusing it would pin the overflow in place permanently.
	try checkTotalCap(100, 30, 40);
	try checkTotalCap(max_total_rules, 1, 1); // exactly break-even, still over cap

	// GROWING by even one rule past the cap is still refused: the enforcer
	// silently drops the tail while the terminate-tier addon keeps honouring it.
	try t.expectError(error.TooManyRules, checkTotalCap(max_total_rules, 2, 1));
	try t.expectError(error.TooManyRules, checkTotalCap(100, 41, 40));
}

/// Build a `.network` tree with `n` plain allow rules (plus any extra rule JSON)
/// and one inject spec per host in `inject_hosts`. Caller deinits.
fn testNetwork(
	allocator: std.mem.Allocator,
	n: usize,
	extra_rules_json: []const u8,
	inject_hosts: []const []const u8,
) !std.json.Parsed(std.json.Value) {
	var src: std.ArrayList(u8) = .empty;
	defer src.deinit(allocator);
	try src.appendSlice(allocator, "{\"l7\":{\"rules\":[");
	for (0..n) |i| {
		if (i > 0) try src.appendSlice(allocator, ",");
		try src.appendSlice(allocator, "{\"allow\":\"a.test\"}");
	}
	if (extra_rules_json.len > 0) {
		if (n > 0) try src.appendSlice(allocator, ",");
		try src.appendSlice(allocator, extra_rules_json);
	}
	try src.appendSlice(allocator, "],\"inject\":{\"enabled\":true,\"specs\":[");
	for (inject_hosts, 0..) |h, i| {
		if (i > 0) try src.appendSlice(allocator, ",");
		try src.appendSlice(allocator, "{\"style\":\"bearer\",\"secret\":\"api-token\",\"host\":\"");
		try src.appendSlice(allocator, h);
		try src.appendSlice(allocator, "\"}");
	}
	try src.appendSlice(allocator, "]}}}");
	return std.json.parseFromSlice(std.json.Value, allocator, src.items, .{});
}

// The regression: `.l7.rules[]` is not the thing the enforcer bounds. renderL7
// appends a terminate-allow line per inject-spec host no rule names, so a result
// whose ARRAY fits the cap can still render a document whose tail
// filter.parseL7Rules silently drops while the uncapped terminate-tier addon
// keeps honouring it -- precisely the two-layers-disagree outcome the exit-65
// refusal exists to prevent. Phase 4.3's `deny` carve-outs make a dropped line
// permit rather than deny, so the delta has to be inside the budget.
test "checkRenderedCap counts renderL7's inject-union lines, not just the array" {
	const gpa = t.allocator;
	// Each tree below is the POST-APPEND one cmdReplace hands in: `surviving` rules
	// plus the batch. 127 + 1 lands the ARRAY exactly on the cap.
	const surviving = max_total_rules - 1;

	// THE REGRESSION. Array = 128, in cap. One inject-spec host no rule names --
	// e.g. a claude-oauth bind on a sandbox that never allow-listed the audience --
	// so renderL7 emits a 129th line. The array-only arithmetic sees 128 and waves
	// it through; the enforcer then drops that line and the addon does not.
	{
		var net = try testNetwork(gpa, max_total_rules, "", &.{"api.example.com"});
		defer net.deinit();
		try t.expectError(error.TooManyRules, checkRenderedCap(net.value, surviving, 1, 0));
		try checkTotalCap(surviving, 1, 0); // what it used to be checked against
	}

	// No inject specs -> the delta is zero and the bound is exactly what it was, so
	// nothing that used to fit stops fitting.
	{
		var net = try testNetwork(gpa, max_total_rules, "", &.{});
		defer net.deinit();
		try checkRenderedCap(net.value, surviving, 1, 0);
	}

	// A spec host that IS named costs no line -- including when the naming rule is
	// one the batch just appended. That is why the delta is measured against the
	// post-append tree: the ordinary re-grant drops the very git-grant rules that
	// named the git inject host and re-adds them, so counting against the post-drop
	// tree would see a phantom extra line and refuse a replace that fits.
	{
		var net = try testNetwork(gpa, surviving, "{\"allow\":\"git.example.com\",\"plugin\":\"git-grants\"}", &.{"git.example.com"});
		defer net.deinit();
		try checkRenderedCap(net.value, surviving, 1, 0);
	}

	// And the non-growing exemption still wins over the larger count: a revoke on an
	// already-over-cap instance must never be the operation that fails.
	{
		var net = try testNetwork(gpa, max_total_rules + 2, "", &.{"api.example.com"});
		defer net.deinit();
		try checkRenderedCap(net.value, max_total_rules + 2, 0, 2);
	}
}
