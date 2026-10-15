const std = @import("std");
const mutate = @import("mutate.zig");
const rules_module = @import("rules_module");
const config = rules_module.config;
const t = std.testing;

const doc_with_rules =
	\\{
	\\  "vcpu": 4,
	\\  "network": {
	\\    "rules": [
	\\      {"deny": "10.0.0.0/8", "comment": "rfc1918"},
	\\      {"allow": "0.0.0.0/0"}
	\\    ]
	\\  }
	\\}
;

fn parseDoc(text: []const u8) !std.json.Parsed(std.json.Value) {
	return std.json.parseFromSlice(std.json.Value, t.allocator, text, .{});
}

fn rulesOf(v: *std.json.Value) *std.json.Array {
	return &v.object.getPtr("network").?.object.getPtr("rules").?.array;
}

test "pluginsArray creates the array once and reuses it" {
	var parsed = try parseDoc(doc_with_rules);
	defer parsed.deinit();
	const arena = parsed.arena.allocator();

	const arr = try mutate.pluginsArray(&parsed.value, arena);
	try t.expectEqual(@as(usize, 0), arr.items.len);
	try t.expect(mutate.existingPluginsArray(&parsed.value) != null);

	try mutate.appendPlugin(arena, arr, .{
		.name = "myplugin",
		.url = "github:o/myplugin",
		.locked_url = "github:o/myplugin/abc?narHash=sha256-A",
		.rev = "abc",
		.nar_hash = "sha256-A",
	});
	const again = try mutate.pluginsArray(&parsed.value, arena);
	try t.expectEqual(@as(usize, 1), again.items.len);
	try t.expectEqual(@as(?usize, 0), mutate.findPlugin(again, "myplugin"));
	try t.expect(mutate.findPlugin(again, "nope") == null);

	const obj = again.items[0].object;
	try t.expectEqualStrings("github:o/myplugin", mutate.entryField(obj, "url").?);
	try t.expectEqualStrings("abc", mutate.entryField(obj, "rev").?);
}

test "appendPlugin records attr; findByUrl matches the fragment-less url" {
	var parsed = try parseDoc("{}");
	defer parsed.deinit();
	const arena = parsed.arena.allocator();
	const arr = try mutate.pluginsArray(&parsed.value, arena);
	try mutate.appendPlugin(arena, arr, .{
		.name = "hello",
		.url = "path:/x/multi",
		.locked_url = "path:/x/multi?narHash=sha256-M",
		.rev = null,
		.nar_hash = "sha256-M",
	});
	try mutate.appendPlugin(arena, arr, .{
		.name = "extra",
		.url = "path:/x/multi",
		.attr = "extra",
		.locked_url = "path:/x/multi?narHash=sha256-M",
		.rev = null,
		.nar_hash = "sha256-M",
	});
	try t.expect(mutate.entryField(arr.items[0].object, "attr") == null);
	try t.expectEqualStrings("extra", mutate.entryField(arr.items[1].object, "attr").?);
	const sib = mutate.findByUrl(arr, "path:/x/multi").?;
	try t.expectEqualStrings("hello", mutate.entryField(sib.object, "name").?);
	try t.expect(mutate.findByUrl(arr, "path:/x/other") == null);
}

test "appendPlugin without rev omits the field" {
	var parsed = try parseDoc("{}");
	defer parsed.deinit();
	const arena = parsed.arena.allocator();
	const arr = try mutate.pluginsArray(&parsed.value, arena);
	try mutate.appendPlugin(arena, arr, .{
		.name = "dev",
		.url = "path:/x/dev",
		.locked_url = "path:/x/dev?narHash=sha256-B",
		.rev = null,
		.nar_hash = "sha256-B",
	});
	try t.expect(mutate.entryField(arr.items[0].object, "rev") == null);
	try t.expectEqualStrings("sha256-B", mutate.entryField(arr.items[0].object, "narHash").?);
}

test "relockPlugin replaces lock fields, keeps name/url" {
	var parsed = try parseDoc(
		\\{"plugins": [{"name": "p", "url": "github:o/p", "lockedUrl": "old", "rev": "oldrev", "narHash": "sha256-old"}]}
	);
	defer parsed.deinit();
	const arena = parsed.arena.allocator();
	const arr = mutate.existingPluginsArray(&parsed.value).?;

	try mutate.relockPlugin(arena, &arr.items[0], .{
		.name = "p",
		.url = "github:o/p",
		.locked_url = "github:o/p/new?narHash=sha256-new",
		.rev = "newrev",
		.nar_hash = "sha256-new",
	});
	const obj = arr.items[0].object;
	try t.expectEqualStrings("github:o/p", mutate.entryField(obj, "url").?);
	try t.expectEqualStrings("github:o/p/new?narHash=sha256-new", mutate.entryField(obj, "lockedUrl").?);
	try t.expectEqualStrings("newrev", mutate.entryField(obj, "rev").?);
	try t.expectEqualStrings("sha256-new", mutate.entryField(obj, "narHash").?);
}

test "prependTaggedRules lands at the head in declared order, tagged" {
	var parsed = try parseDoc(doc_with_rules);
	defer parsed.deinit();
	const arena = parsed.arena.allocator();
	const rules_arr = rulesOf(&parsed.value);

	var incoming = try parseDoc(
		\\[{"allow": "10.1.0.1/32", "comment": "api"}, {"deny": "10.1.0.0/16"}]
	);
	defer incoming.deinit();

	try mutate.prependTaggedRules(arena, rules_arr, "plug", incoming.value.array.items);

	try t.expectEqual(@as(usize, 4), rules_arr.items.len);
	// Block order preserved, both tagged, existing rules pushed down.
	try t.expectEqualStrings("10.1.0.1/32", rules_arr.items[0].object.get("allow").?.string);
	try t.expectEqualStrings("api", rules_arr.items[0].object.get("comment").?.string);
	try t.expectEqualStrings("plug", mutate.ruleTag(rules_arr.items[0]).?);
	try t.expectEqualStrings("10.1.0.0/16", rules_arr.items[1].object.get("deny").?.string);
	try t.expectEqualStrings("plug", mutate.ruleTag(rules_arr.items[1]).?);
	try t.expectEqualStrings("10.0.0.0/8", rules_arr.items[2].object.get("deny").?.string);
	try t.expect(mutate.ruleTag(rules_arr.items[2]) == null);

	try t.expectEqual(@as(usize, 2), mutate.countTaggedRules(rules_arr, "plug"));
	try t.expectEqual(@as(usize, 0), mutate.countTaggedRules(rules_arr, "other"));
}

test "prepended rules are deep copies, independent of the source tree" {
	var parsed = try parseDoc(doc_with_rules);
	defer parsed.deinit();
	const arena = parsed.arena.allocator();
	const rules_arr = rulesOf(&parsed.value);

	{
		var incoming = try parseDoc("[{\"allow\": \"10.1.0.1/32\"}]");
		defer incoming.deinit(); // freed before we read the copy below
		try mutate.prependTaggedRules(arena, rules_arr, "plug", incoming.value.array.items);
	}
	try t.expectEqualStrings("10.1.0.1/32", rules_arr.items[0].object.get("allow").?.string);
}

test "removeTaggedRules drops only the tagged block" {
	var parsed = try parseDoc(
		\\{"network": {"rules": [
		\\  {"allow": "1.1.1.1/32", "plugin": "a"},
		\\  {"deny": "10.0.0.0/8"},
		\\  {"allow": "2.2.2.2/32", "plugin": "b"},
		\\  {"allow": "3.3.3.3/32", "plugin": "a"}
		\\]}}
	);
	defer parsed.deinit();
	const rules_arr = rulesOf(&parsed.value);

	try t.expectEqual(@as(usize, 2), mutate.removeTaggedRules(rules_arr, "a"));
	try t.expectEqual(@as(usize, 2), rules_arr.items.len);
	try t.expectEqualStrings("10.0.0.0/8", rules_arr.items[0].object.get("deny").?.string);
	try t.expectEqualStrings("b", mutate.ruleTag(rules_arr.items[1]).?);
	try t.expectEqual(@as(usize, 0), mutate.removeTaggedRules(rules_arr, "a"));
}

test "validatePluginRule" {
	var ok_rules = try parseDoc(
		\\[{"allow": "10.0.0.1/32"}, {"deny": "0.0.0.0/0", "comment": "x"}]
	);
	defer ok_rules.deinit();
	for (ok_rules.value.array.items) |r| try mutate.validatePluginRule(r);

	var bad = try parseDoc(
		\\[42, {"comment": "no action"}, {"allow": "1.1.1.1/32", "deny": "2.2.2.2/32"}, {"allow": "not-a-cidr"}]
	);
	defer bad.deinit();
	const items = bad.value.array.items;
	try t.expectError(error.NotAnObject, mutate.validatePluginRule(items[0]));
	try t.expectError(error.BadAction, mutate.validatePluginRule(items[1]));
	try t.expectError(error.BadAction, mutate.validatePluginRule(items[2]));
	try t.expectError(error.InvalidCidr, mutate.validatePluginRule(items[3]));
}

test "validatePluginL7Rule" {
	var ok_rules = try parseDoc(
		\\[{"allow": "api.example.com"},
		\\ {"allow": "api.example.com", "terminate": true, "comment": "x"},
		\\ {"allow": "git.example.com", "path": "/org/"},
		\\ {"allow": "pinned.example.com", "passthrough": true},
		\\ {"allow": "internal.svc", "insecure_upstream": true},
		\\ {"deny": "*.evil.example"},
		\\ {"deny": "*"}]
	);
	defer ok_rules.deinit();
	for (ok_rules.value.array.items) |r| try mutate.validatePluginL7Rule(r);

	var bad = try parseDoc(
		\\[{"comment": "no action"},
		\\ {"allow": "a.test", "deny": "b.test"},
		\\ {"allow": "not a host!"},
		\\ {"allow": "a.test", "path": "noslash"},
		\\ {"allow": "a.test", "terminate": "yes"},
		\\ {"allow": "a.test", "passthrough": true, "terminate": true},
		\\ {"allow": "a.test", "passthrough": true, "path": "/v1/"}]
	);
	defer bad.deinit();
	const items = bad.value.array.items;
	try t.expectError(error.BadAction, mutate.validatePluginL7Rule(items[0]));
	try t.expectError(error.BadAction, mutate.validatePluginL7Rule(items[1]));
	try t.expectError(error.InvalidHost, mutate.validatePluginL7Rule(items[2]));
	try t.expectError(error.BadPath, mutate.validatePluginL7Rule(items[3]));
	try t.expectError(error.BadFlag, mutate.validatePluginL7Rule(items[4]));
	try t.expectError(error.ConflictingTier, mutate.validatePluginL7Rule(items[5]));
	try t.expectError(error.ConflictingTier, mutate.validatePluginL7Rule(items[6]));
}

// Every string renderL7 copies onto the whitespace-tokenized l7-rules line must
// be ONE printable-ASCII token, or a plugin manifest -- which plugin update and
// archive add apply without admin review -- can split the line or forge a
// `tag=git-grants` token in the mitm addon. The ok_rules of the test above
// (`{"deny": "*"}` included) must all still pass; this adds the full git-grant
// shape.
test "validatePluginL7Rule refuses values the l7-rules line cannot carry" {
	var ok_rules = try parseDoc(
		\\[{"allow": "git.example.com", "path": "/org/repo.git/info/refs", "methods": "GET,POST", "service": "git-upload-pack"},
		\\ {"deny": "*"}]
	);
	defer ok_rules.deinit();
	for (ok_rules.value.array.items) |r| try mutate.validatePluginL7Rule(r);

	var bad_path = try parseDoc(
		\\[{"allow": "a.test", "path": "/a b"},
		\\ {"allow": "a.test", "path": "/a\tb"},
		\\ {"allow": "a.test", "path": "/a\nallow evil.test tag=git-grants"},
		\\ {"allow": "a.test", "path": "/a\rb"},
		\\ {"allow": "a.test", "path": "/a\u007f"},
		\\ {"allow": "a.test", "path": "/a\u00a0b"},
		\\ {"allow": "a.test", "path": "/a\u3000tag=git-grants"}]
	);
	defer bad_path.deinit();
	for (bad_path.value.array.items) |r| try t.expectError(error.BadPath, mutate.validatePluginL7Rule(r));

	var bad_host = try parseDoc(
		\\[{"allow": " a.test"}, {"deny": "a.test "}]
	);
	defer bad_host.deinit();
	for (bad_host.value.array.items) |r| try t.expectError(error.InvalidHost, mutate.validatePluginL7Rule(r));

	var bad_methods = try parseDoc(
		\\[{"allow": "a.test", "methods": "GET\nallow x"},
		\\ {"allow": "a.test", "methods": "get"},
		\\ {"allow": "a.test", "methods": ""},
		\\ {"allow": "a.test", "methods": ["GET"]}]
	);
	defer bad_methods.deinit();
	for (bad_methods.value.array.items) |r| try t.expectError(error.BadMethods, mutate.validatePluginL7Rule(r));

	var bad_service = try parseDoc(
		\\[{"allow": "a.test", "service": "git-upload-pack x"},
		\\ {"allow": "a.test", "service": ""},
		\\ {"allow": "a.test", "service": 5}]
	);
	defer bad_service.deinit();
	for (bad_service.value.array.items) |r| try t.expectError(error.BadService, mutate.validatePluginL7Rule(r));
}

test "tagged-rule helpers work on an l7 rules array" {
	var parsed = try parseDoc(
		\\{"network": {"l7": {"rules": [{"allow": "keep.test"}]}}}
	);
	defer parsed.deinit();
	const arena = parsed.arena.allocator();
	const l7_arr = &parsed.value.object.getPtr("network").?.object.getPtr("l7").?.object.getPtr("rules").?.array;

	var incoming = try parseDoc("[{\"allow\": \"api.test\", \"terminate\": true}]");
	defer incoming.deinit();
	try mutate.prependTaggedRules(arena, l7_arr, "plug", incoming.value.array.items);
	try t.expectEqual(@as(usize, 2), l7_arr.items.len);
	try t.expectEqualStrings("plug", mutate.ruleTag(l7_arr.items[0]).?);
	try t.expect(l7_arr.items[0].object.get("terminate").?.bool);
	try t.expectEqual(@as(usize, 1), mutate.countTaggedRules(l7_arr, "plug"));
	try t.expectEqual(@as(usize, 1), mutate.removeTaggedRules(l7_arr, "plug"));
	try t.expectEqualStrings("keep.test", l7_arr.items[0].object.get("allow").?.string);
}

test "round-trip: tagged rules and plugins survive writeJqTab" {
	var parsed = try parseDoc(doc_with_rules);
	defer parsed.deinit();
	const arena = parsed.arena.allocator();
	const rules_arr = rulesOf(&parsed.value);

	var incoming = try parseDoc("[{\"allow\": \"9.9.9.9/32\"}]");
	defer incoming.deinit();
	try mutate.prependTaggedRules(arena, rules_arr, "plug", incoming.value.array.items);
	const plugins = try mutate.pluginsArray(&parsed.value, arena);
	try mutate.appendPlugin(arena, plugins, .{
		.name = "plug",
		.url = "path:/x/plug",
		.locked_url = "path:/x/plug?narHash=sha256-C",
		.rev = null,
		.nar_hash = "sha256-C",
	});

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(t.allocator);
	try config.writeJqTab(t.allocator, &out, parsed.value);

	try t.expect(std.mem.indexOf(u8, out.items, "\"plugin\": \"plug\"") != null);
	try t.expect(std.mem.indexOf(u8, out.items, "\"narHash\": \"sha256-C\"") != null);
	try t.expect(std.mem.indexOf(u8, out.items, "\"comment\": \"rfc1918\"") != null);
}

test "validatePluginInjectSpec" {
	var ok = try parseDoc(
		\\[{"host": "api.example.com", "style": "bearer", "secret": "api-bearer"},
		\\ {"host": "api.internal", "secret": "api_token"},
		\\ {"host": "es.internal", "style": "basic", "secret": "es-creds", "port": 9200},
		\\ {"host": "app.example.com", "style": "cookie", "cookieName": "app.sid", "secret": "app-session", "stub": "cogbox-stub"}]
	);
	defer ok.deinit();
	for (ok.value.array.items) |s| try mutate.validatePluginInjectSpec(s);

	var bad = try parseDoc(
		\\[{"style": "bearer", "secret": "x"},
		\\ {"host": "not a host!", "secret": "x"},
		\\ {"host": "*.example.com", "secret": "x"},
		\\ {"host": "a.test", "style": "anthropic-oauth", "secret": "x"},
		\\ {"host": "a.test"},
		\\ {"host": "a.test", "secret": "bad/name"},
		\\ {"host": "a.test", "style": "cookie", "secret": "x"},
		\\ {"host": "a.test", "secret": "x", "secretValue": "leak"},
		\\ {"host": "a.test", "secret": "x", "cred_file": "/etc/passwd"},
		\\ {"host": "a.test", "secret": "x", "token": "abc"},
		\\ {"host": "a.test", "secret": "x", "refresh": {"u": "v"}},
		\\ {"host": "a.test", "secret": "x", "port": 0},
		\\ {"host": "a.test", "secret": "x", "port": 70000},
		\\ {"host": "a.test", "secret": "x", "port": "9200"}]
	);
	defer bad.deinit();
	const items = bad.value.array.items;
	try t.expectError(error.MissingHost, mutate.validatePluginInjectSpec(items[0]));
	try t.expectError(error.InvalidHost, mutate.validatePluginInjectSpec(items[1]));
	try t.expectError(error.WildcardHost, mutate.validatePluginInjectSpec(items[2]));
	try t.expectError(error.BadStyle, mutate.validatePluginInjectSpec(items[3]));
	try t.expectError(error.MissingSecret, mutate.validatePluginInjectSpec(items[4]));
	try t.expectError(error.BadSecretName, mutate.validatePluginInjectSpec(items[5]));
	try t.expectError(error.MissingCookieName, mutate.validatePluginInjectSpec(items[6]));
	// inline secret material / path naming is rejected outright (defense in depth)
	try t.expectError(error.InlineSecretForbidden, mutate.validatePluginInjectSpec(items[7]));
	try t.expectError(error.InlineSecretForbidden, mutate.validatePluginInjectSpec(items[8]));
	try t.expectError(error.InlineSecretForbidden, mutate.validatePluginInjectSpec(items[9]));
	try t.expectError(error.InlineSecretForbidden, mutate.validatePluginInjectSpec(items[10]));
	// port must be an in-range integer -- a typo (0, overflow, or a string) fails loud
	try t.expectError(error.BadPort, mutate.validatePluginInjectSpec(items[11]));
	try t.expectError(error.BadPort, mutate.validatePluginInjectSpec(items[12]));
	try t.expectError(error.BadPort, mutate.validatePluginInjectSpec(items[13]));
}
