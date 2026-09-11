// Pure config-tree mutations for the plugin verb: the .plugins array and the
// plugin-tagged entries in .network.rules. All inserted values are duplicated
// into the document's arena so they free with the tree.
//
// Plugin-contributed rules carry a `"plugin": "<name>"` field; that tag is
// how del/update remove or replace exactly the rules a plugin brought in,
// and it's preserved through save because config.zig keeps unknown fields.

const std = @import("std");
const rules_module = @import("rules_module");
const rule = rules_module.rule;
const l7_rule = @import("l7_module").rule;
const secret_store = @import("secret_module").store;

pub const Entry = struct {
	name: []const u8,
	url: []const u8, // flake ref WITHOUT the #attr fragment
	attr: ?[]const u8 = null, // nixosModules attr; null means "default"
	locked_url: []const u8,
	rev: ?[]const u8,
	nar_hash: []const u8,
};

/// Ensure root has a .plugins array and return it.
pub fn pluginsArray(root: *std.json.Value, arena: std.mem.Allocator) !*std.json.Array {
	if (root.* != .object) return error.InvalidJson;
	if (root.object.getPtr("plugins") == null) {
		try root.object.put(arena, try arena.dupe(u8, "plugins"), .{ .array = std.json.Array.init(arena) });
	}
	const v = root.object.getPtr("plugins").?;
	if (v.* != .array) return error.InvalidJson;
	return &v.array;
}

/// .plugins array if present, without creating it.
pub fn existingPluginsArray(root: *std.json.Value) ?*std.json.Array {
	if (root.* != .object) return null;
	const v = root.object.getPtr("plugins") orelse return null;
	if (v.* != .array) return null;
	return &v.array;
}

pub fn findPlugin(arr: *std.json.Array, plugin_name: []const u8) ?usize {
	for (arr.items, 0..) |item, i| {
		if (item != .object) continue;
		const n = item.object.get("name") orelse continue;
		if (n == .string and std.mem.eql(u8, n.string, plugin_name)) return i;
	}
	return null;
}

pub fn entryField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
	const v = obj.get(key) orelse return null;
	if (v != .string) return null;
	return v.string;
}

pub fn appendPlugin(arena: std.mem.Allocator, arr: *std.json.Array, e: Entry) !void {
	var obj: std.json.ObjectMap = .empty;
	try obj.put(arena, try arena.dupe(u8, "name"), .{ .string = try arena.dupe(u8, e.name) });
	try obj.put(arena, try arena.dupe(u8, "url"), .{ .string = try arena.dupe(u8, e.url) });
	if (e.attr) |a| {
		try obj.put(arena, try arena.dupe(u8, "attr"), .{ .string = try arena.dupe(u8, a) });
	}
	try putLockFields(arena, &obj, e);
	try arr.append(.{ .object = obj });
}

/// First plugin entry with the given (fragment-less) url, if any. Used to
/// reuse an installed flake's pin when enabling another of its modules:
/// versioning is per flake, so siblings share one rev.
pub fn findByUrl(arr: *std.json.Array, url: []const u8) ?*std.json.Value {
	for (arr.items) |*item| {
		if (item.* != .object) continue;
		const u = entryField(item.object, "url") orelse continue;
		if (std.mem.eql(u8, u, url)) return item;
	}
	return null;
}

/// Refresh lockedUrl/rev/narHash on an existing entry (plugin update).
pub fn relockPlugin(arena: std.mem.Allocator, item: *std.json.Value, e: Entry) !void {
	if (item.* != .object) return error.InvalidJson;
	_ = item.object.orderedRemove("lockedUrl");
	_ = item.object.orderedRemove("rev");
	_ = item.object.orderedRemove("narHash");
	try putLockFields(arena, &item.object, e);
}

fn putLockFields(arena: std.mem.Allocator, obj: *std.json.ObjectMap, e: Entry) !void {
	try obj.put(arena, try arena.dupe(u8, "lockedUrl"), .{ .string = try arena.dupe(u8, e.locked_url) });
	if (e.rev) |r| {
		try obj.put(arena, try arena.dupe(u8, "rev"), .{ .string = try arena.dupe(u8, r) });
	}
	try obj.put(arena, try arena.dupe(u8, "narHash"), .{ .string = try arena.dupe(u8, e.nar_hash) });
}

pub const RuleError = error{
	NotAnObject,
	BadAction,
	InvalidCidr,
	OutOfMemory,
};

/// Validate one plugin-declared rule: an object with exactly one of
/// allow/deny keyed to a valid CIDR. Extra fields (comment, ...) are fine.
pub fn validatePluginRule(v: std.json.Value) RuleError!void {
	if (v != .object) return error.NotAnObject;
	const has_allow = v.object.get("allow") != null;
	const has_deny = v.object.get("deny") != null;
	if (has_allow == has_deny) return error.BadAction; // both or neither
	const p = rule.ruleAction(v.object) orelse return error.BadAction;
	var line_buf: [128]u8 = undefined;
	if (!rule.validateActionCidr(p.action, p.cidr, &line_buf)) return error.InvalidCidr;
}

pub const L7RuleError = error{
	NotAnObject,
	BadAction,
	InvalidHost,
	BadPath,
	BadFlag,
	ConflictingTier,
	OutOfMemory,
};

/// Validate one plugin-declared L7 rule: an object with exactly one of
/// allow/deny keyed to a valid SNI/Host pattern, plus the optional tier
/// fields the `l7` verb writes (`path`, `terminate`, `insecure_upstream`,
/// `passthrough`), with the same constraints `l7 add` enforces:
/// passthrough excludes everything that forces terminate.
pub fn validatePluginL7Rule(v: std.json.Value) L7RuleError!void {
	if (v != .object) return error.NotAnObject;
	const has_allow = v.object.get("allow") != null;
	const has_deny = v.object.get("deny") != null;
	if (has_allow == has_deny) return error.BadAction;
	const p = l7_rule.ruleAction(v.object) orelse return error.BadAction;
	if (!l7_rule.validateHost(p.host)) return error.InvalidHost;

	var has_path = false;
	if (v.object.get("path")) |pv| {
		if (pv != .string or pv.string.len == 0 or pv.string[0] != '/') return error.BadPath;
		has_path = true;
	}
	var terminate = has_path;
	var insecure = false;
	var passthrough = false;
	for ([_]struct { key: []const u8, dst: *bool }{
		.{ .key = "terminate", .dst = &terminate },
		.{ .key = "insecure_upstream", .dst = &insecure },
		.{ .key = "passthrough", .dst = &passthrough },
	}) |f| {
		if (v.object.get(f.key)) |fv| {
			if (fv != .bool) return error.BadFlag;
			if (fv.bool) f.dst.* = true;
		}
	}
	if (insecure) terminate = true;
	if (passthrough and terminate) return error.ConflictingTier;
}

pub const InjectSpecError = error{
	NotAnObject,
	MissingHost,
	InvalidHost,
	WildcardHost,
	BadStyle,
	BadStub,
	MissingSecret,
	BadSecretName,
	MissingCookieName,
	BadCookieName,
	InlineSecretForbidden,
	BadPort,
	OutOfMemory,
};

/// Validate one plugin-declared injection spec (cogboxPlugins.<attr>.inject[]).
/// A plugin may only NAME a credential plus the exact host it targets; it can
/// never express a value or a host-side path. Shape:
///   { host = "api.x"; style = "bearer"|"cookie"|"basic"; secret = "name";
///     cookieName = "app.sid"  (required iff style == "cookie");
///     port = 9200  (optional; non-standard service port to funnel);
///     stub = "..."  (optional) }
/// SECURITY: any inline secret material / path-naming field
/// ({path, cred_file, credFile, token, token_path, refresh, secretValue,
/// value}) is rejected outright so a hostile/misformed manifest fails loud at
/// `plugin add` rather than being silently ignored. The host must be EXACT (no
/// wildcard): the addon keys injection by exact host, and an audience is bound
/// per-host, so a wildcard would broaden where a credential can be stamped.
pub fn validatePluginInjectSpec(v: std.json.Value) InjectSpecError!void {
	if (v != .object) return error.NotAnObject;

	for ([_][]const u8{
		"path", "cred_file", "credFile", "token", "token_path",
		"refresh", "secretValue", "value",
	}) |forbidden| {
		if (v.object.get(forbidden) != null) return error.InlineSecretForbidden;
	}

	const host_v = v.object.get("host") orelse return error.MissingHost;
	if (host_v != .string or host_v.string.len == 0) return error.MissingHost;
	if (std.mem.indexOfScalar(u8, host_v.string, '*') != null) return error.WildcardHost;
	if (!l7_rule.validateHost(host_v.string)) return error.InvalidHost;

	var style: []const u8 = "bearer";
	if (v.object.get("style")) |sv| {
		if (sv != .string) return error.BadStyle;
		style = sv.string;
	}
	if (!std.mem.eql(u8, style, "bearer") and !std.mem.eql(u8, style, "cookie") and !std.mem.eql(u8, style, "basic")) return error.BadStyle;

	const secret_v = v.object.get("secret") orelse return error.MissingSecret;
	if (secret_v != .string) return error.MissingSecret;
	if (!secret_store.validName(secret_v.string)) return error.BadSecretName;

	if (std.mem.eql(u8, style, "cookie")) {
		const cn = v.object.get("cookieName") orelse return error.MissingCookieName;
		if (cn != .string or cn.string.len == 0) return error.MissingCookieName;
		if (!secret_store.validCookieName(cn.string)) return error.BadCookieName;
	}

	if (v.object.get("stub")) |st| {
		if (st != .string) return error.BadStub;
	}

	// Optional service port for a host reached on a non-standard port (e.g. an
	// Elasticsearch cluster on :9200). renderRules funnels this port through the
	// L7 proxy so the credential is stamped; without it the host's 80/443 alone
	// is funnelled and a :9200 request egresses uninjected. A Nix manifest yields
	// an integer; require a valid 1..65535 so a typo fails loud at `plugin add`.
	if (v.object.get("port")) |pv| {
		if (pv != .integer or pv.integer < 1 or pv.integer > 65535) return error.BadPort;
	}
	// A manifest `on_guest_credential` key is IGNORED (neither validated nor
	// merged): guest-credential precedence is the operator's choice at bind
	// time (`cogbox secret add --on-guest-credential`, secret_store.Meta) and
	// the inject render reads it from the secret's meta, never from a spec.
}

/// Prepend `incoming` as a contiguous block at the head of the rules array
/// (first match wins; a plugin's allows must precede the seeded RFC1918
/// denies to be reachable). Each rule is deep-copied into the document arena
/// and tagged with `"plugin": tag` (overwriting any tag the flake declared).
pub fn prependTaggedRules(
	arena: std.mem.Allocator,
	rules_arr: *std.json.Array,
	tag: []const u8,
	incoming: []const std.json.Value,
) !void {
	// Insert in reverse so the block lands in declared order.
	var i = incoming.len;
	while (i > 0) {
		i -= 1;
		var copied = try deepCopy(arena, incoming[i]);
		_ = copied.object.orderedRemove("plugin");
		try copied.object.put(arena, try arena.dupe(u8, "plugin"), .{ .string = try arena.dupe(u8, tag) });
		try rules_arr.insert(0, copied);
	}
}

/// Remove every rule tagged with `tag`. Returns how many were dropped.
pub fn removeTaggedRules(rules_arr: *std.json.Array, tag: []const u8) usize {
	var removed: usize = 0;
	var i: usize = 0;
	while (i < rules_arr.items.len) {
		if (ruleTag(rules_arr.items[i])) |t| {
			if (std.mem.eql(u8, t, tag)) {
				_ = rules_arr.orderedRemove(i);
				removed += 1;
				continue;
			}
		}
		i += 1;
	}
	return removed;
}

pub fn countTaggedRules(rules_arr: *const std.json.Array, tag: []const u8) usize {
	var n: usize = 0;
	for (rules_arr.items) |item| {
		if (ruleTag(item)) |t| {
			if (std.mem.eql(u8, t, tag)) n += 1;
		}
	}
	return n;
}

pub fn ruleTag(v: std.json.Value) ?[]const u8 {
	if (v != .object) return null;
	const t = v.object.get("plugin") orelse return null;
	if (t != .string) return null;
	return t.string;
}

/// Deep-copy a JSON value into `arena` (rule objects from the eval'd plugin
/// output live in a different parse tree than the config document).
pub fn deepCopy(arena: std.mem.Allocator, v: std.json.Value) std.mem.Allocator.Error!std.json.Value {
	switch (v) {
		.null, .bool, .integer, .float => return v,
		.number_string => |s| return .{ .number_string = try arena.dupe(u8, s) },
		.string => |s| return .{ .string = try arena.dupe(u8, s) },
		.array => |arr| {
			var out = std.json.Array.init(arena);
			try out.ensureTotalCapacity(arr.items.len);
			for (arr.items) |item| {
				out.appendAssumeCapacity(try deepCopy(arena, item));
			}
			return .{ .array = out };
		},
		.object => |obj| {
			var out: std.json.ObjectMap = .empty;
			var it = obj.iterator();
			while (it.next()) |entry| {
				try out.put(
					arena,
					try arena.dupe(u8, entry.key_ptr.*),
					try deepCopy(arena, entry.value_ptr.*),
				);
			}
			return .{ .object = out };
		},
	}
}
