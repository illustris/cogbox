// Unit tests for the secret store's PURE layer (validName + meta
// serialize/parse). The IO layer (add/lookup/remove on disk) is covered by the
// launcher + NixOS VM integration tests, mirroring how rules/config_test.zig
// leaves load/save IO to integration coverage. refAllDecls forces the verb
// dispatch code (main.zig) to type-check here too.

const std = @import("std");
const store = @import("store.zig");
const main = @import("main.zig");
const proxygid = @import("proxygid.zig");
const t = std.testing;

test {
	std.testing.refAllDecls(main);
	std.testing.refAllDecls(store);
	std.testing.refAllDecls(proxygid);
}

test "validName accepts valid names, rejects traversal/charset/length" {
	try t.expect(store.validName("api-bearer"));
	try t.expect(store.validName("app_session"));
	try t.expect(store.validName("a"));
	try t.expect(store.validName("A0-_z"));
	try t.expect(!store.validName(""));
	try t.expect(!store.validName("has.dot")); // '.' excluded so <name>.meta is unambiguous
	try t.expect(!store.validName("has/slash"));
	try t.expect(!store.validName(".."));
	try t.expect(!store.validName("../etc/passwd"));
	try t.expect(!store.validName("with space"));
	try t.expect(!store.validName("x" ** 65)); // > 64 chars
}

test "validKind allowlist accepts the injection styles incl. anthropic-oauth" {
	try t.expect(main.validKind("bearer"));
	try t.expect(main.validKind("cookie"));
	try t.expect(main.validKind("basic"));
	// The per-user Claude setup-token bind without
	// this the `claude-oauth` bind FAILS CLOSED at `secret add`.
	try t.expect(main.validKind("anthropic-oauth"));
	try t.expectEqualStrings("anthropic-oauth", main.anthropic_oauth_kind);
	// The per-user GitLab (git OAuth) access-token bind; without this the
	// `git-<provider>` bind FAILS CLOSED at `secret add`.
	try t.expect(main.validKind("gitlab-oauth"));
	try t.expectEqualStrings("gitlab-oauth", main.gitlab_oauth_kind);
	try t.expectEqualStrings("oauth2", main.default_git_user);
	// The auth-proxy git bind. Acceptance here IS the rollout's version gate:
	// an OLD binary (whose allowlist lacks this arm) refuses it with exit 65,
	// so no credential can exist on a pre-authproxy image.
	try t.expect(main.validKind("gitlab-authproxy"));
	try t.expectEqualStrings("gitlab-authproxy", main.gitlab_authproxy_kind);
	// unknown styles are still rejected (fail closed)
	try t.expect(!main.validKind("oauth"));
	try t.expect(!main.validKind("anthropic"));
	try t.expect(!main.validKind("gitlab"));
	try t.expect(!main.validKind(""));
}

test "stubCredentialJson stages ONLY the shared sentinel, never a real token" {
	const a = t.allocator;
	const json = try main.stubCredentialJson(a);
	defer a.free(json);
	// The accessToken is the single shared stub sentinel (the addon stamps the real
	// Bearer over exactly this -- the real token never enters the agent).
	try t.expect(std.mem.indexOf(u8, json, main.claude_stub_token) != null);
	try t.expect(std.mem.indexOf(u8, json, "\"accessToken\":\"" ++ main.claude_stub_token ++ "\"") != null);
	// The refresh token is the in-guest eviction sentinel, never a usable one, and a
	// far-future expiry stops the guest from refreshing the placeholder locally.
	try t.expect(std.mem.indexOf(u8, json, "cogbox-evicted-no-refresh-token-in-guest") != null);
	try t.expect(std.mem.indexOf(u8, json, "9999999999000") != null);
	// Read-only scopes keep a logged-in identity without inference-write power.
	try t.expect(std.mem.indexOf(u8, json, "user:inference") != null);
	// It parses as the credential shape claude-code reads.
	var parsed = try std.json.parseFromSlice(std.json.Value, a, json, .{});
	defer parsed.deinit();
	const at = parsed.value.object.get("claudeAiOauth").?.object.get("accessToken").?.string;
	try t.expectEqualStrings(main.claude_stub_token, at);
}

test "buildMeta/parseMeta round-trip" {
	const a = t.allocator;
	const m: store.Meta = .{ .audience = "api.example.com", .kind = "bearer", .tier = "durable", .bound_at = 1234 };
	const json = try store.buildMeta(a, m);
	defer a.free(json);

	var arena = std.heap.ArenaAllocator.init(a);
	defer arena.deinit();
	const parsed = try store.parseMeta(arena.allocator(), json);
	try t.expectEqualStrings("api.example.com", parsed.audience.?);
	try t.expectEqualStrings("bearer", parsed.kind);
	try t.expectEqualStrings("durable", parsed.tier);
	try t.expectEqual(@as(i64, 1234), parsed.bound_at.?);
	// A bind without the operator inject flags round-trips to the inert defaults.
	try t.expect(!parsed.inject);
	try t.expect(parsed.cookie_name == null);
	try t.expect(parsed.port == null);
	try t.expectEqualStrings(store.on_guest_replace, parsed.on_guest_credential);
}

test "buildMeta/parseMeta round-trip the operator inject keys (inject / cookie_name / port / on_guest_credential)" {
	const a = t.allocator;
	const m: store.Meta = .{
		.audience = "app.example.com",
		.kind = "cookie",
		.tier = "durable",
		.bound_at = 1234,
		.inject = true,
		.cookie_name = "session",
		.port = 9200,
		.on_guest_credential = store.on_guest_keep,
	};
	const json = try store.buildMeta(a, m);
	defer a.free(json);
	// The on-disk shape carries the four keys literally (jq --tab layout), after bound_at.
	try t.expect(std.mem.indexOf(u8, json, "\"bound_at\": 1234,\n\t\"inject\": true,\n\t\"cookie_name\": \"session\",\n\t\"port\": 9200,\n\t\"on_guest_credential\": \"keep\"\n}\n") != null);

	var arena = std.heap.ArenaAllocator.init(a);
	defer arena.deinit();
	const parsed = try store.parseMeta(arena.allocator(), json);
	try t.expect(parsed.inject);
	try t.expectEqualStrings("session", parsed.cookie_name.?);
	try t.expectEqual(@as(?u16, 9200), parsed.port);
	try t.expectEqualStrings("keep", parsed.on_guest_credential);
}

test "parseMeta handles null audience and missing fields with defaults" {
	const a = t.allocator;
	var arena = std.heap.ArenaAllocator.init(a);
	defer arena.deinit();
	const parsed = try store.parseMeta(arena.allocator(), "{\"audience\": null, \"kind\": \"cookie\"}");
	try t.expect(parsed.audience == null);
	try t.expectEqualStrings("cookie", parsed.kind);
	try t.expectEqualStrings("durable", parsed.tier); // default kept
	try t.expect(parsed.bound_at == null);
	// A meta written before the operator inject keys existed (every pre-feature
	// bind) reads as an inert, replace-mode bind: nothing seeds, nothing changes.
	try t.expect(!parsed.inject);
	try t.expect(parsed.cookie_name == null);
	try t.expect(parsed.port == null);
	try t.expectEqualStrings("replace", parsed.on_guest_credential);
}

test "parseMeta types the operator inject keys: a non-bool inject, an empty cookie name, an out-of-range port and an unknown precedence fall back to the inert defaults" {
	const a = t.allocator;
	var arena = std.heap.ArenaAllocator.init(a);
	defer arena.deinit();
	{
		const parsed = try store.parseMeta(arena.allocator(),
			\\{"audience":"a.test","inject":"yes","cookie_name":"","port":70000,"on_guest_credential":"maybe"}
		);
		try t.expect(!parsed.inject);
		try t.expect(parsed.cookie_name == null);
		try t.expect(parsed.port == null);
		try t.expectEqualStrings("replace", parsed.on_guest_credential);
	}
	{
		const parsed = try store.parseMeta(arena.allocator(),
			\\{"audience":"a.test","inject":true,"cookie_name":"sid","port":65535,"on_guest_credential":"keep"}
		);
		try t.expect(parsed.inject);
		try t.expectEqualStrings("sid", parsed.cookie_name.?);
		try t.expectEqual(@as(?u16, 65535), parsed.port);
		try t.expectEqualStrings("keep", parsed.on_guest_credential);
	}
	// The port range is 1..65535: 0 is out, 1 is in, a string is not a port.
	try t.expect((try store.parseMeta(arena.allocator(), "{\"port\": 0}")).port == null);
	try t.expectEqual(@as(?u16, 1), (try store.parseMeta(arena.allocator(), "{\"port\": 1}")).port);
	try t.expect((try store.parseMeta(arena.allocator(), "{\"port\": \"9200\"}")).port == null);
}

test "validCookieName (moved from plugin/mutate.zig) and validOnGuestCredential tables" {
	try t.expect(store.validCookieName("session"));
	try t.expect(store.validCookieName("app.sid"));
	try t.expect(store.validCookieName("_gl_session"));
	try t.expect(!store.validCookieName("a=b")); // separator
	try t.expect(!store.validCookieName("a;b"));
	try t.expect(!store.validCookieName("a,b"));
	try t.expect(!store.validCookieName("a b"));
	try t.expect(!store.validCookieName("a\"b"));
	try t.expect(!store.validCookieName("a\tb")); // control char
	try t.expect(!store.validCookieName("a\x7fb"));
	// (The empty name is refused by the verb, not here -- the manifest validator
	// checks emptiness itself before calling this.)
	try t.expect(store.validOnGuestCredential("replace"));
	try t.expect(store.validOnGuestCredential("keep"));
	try t.expectEqualStrings("replace", store.on_guest_replace);
	try t.expectEqualStrings("keep", store.on_guest_keep);
	try t.expect(!store.validOnGuestCredential(""));
	try t.expect(!store.validOnGuestCredential("Keep"));
	try t.expect(!store.validOnGuestCredential("prefer-guest"));
}

test "parseMeta tolerates malformed json -> defaults (fail safe)" {
	const a = t.allocator;
	var arena = std.heap.ArenaAllocator.init(a);
	defer arena.deinit();
	const parsed = try store.parseMeta(arena.allocator(), "not json{");
	try t.expect(parsed.audience == null);
	try t.expectEqualStrings("bearer", parsed.kind);
}

test "buildMeta emits null audience/bound_at literally" {
	const a = t.allocator;
	const m: store.Meta = .{ .audience = null, .kind = "cookie", .tier = "derived", .bound_at = null };
	const json = try store.buildMeta(a, m);
	defer a.free(json);
	try t.expect(std.mem.indexOf(u8, json, "\"audience\": null") != null);
	try t.expect(std.mem.indexOf(u8, json, "\"kind\": \"cookie\"") != null);
	try t.expect(std.mem.indexOf(u8, json, "\"tier\": \"derived\"") != null);
	try t.expect(std.mem.indexOf(u8, json, "\"bound_at\": null") != null);
	// The operator inject keys are ALWAYS written, defaults included.
	try t.expect(std.mem.indexOf(u8, json, "\"inject\": false") != null);
	try t.expect(std.mem.indexOf(u8, json, "\"cookie_name\": null") != null);
	try t.expect(std.mem.indexOf(u8, json, "\"port\": null") != null);
	try t.expect(std.mem.indexOf(u8, json, "\"on_guest_credential\": \"replace\"") != null);
}

// `secret ls --json` shape the control plane (cogworx) parses. A bound secret
// carries its audience + bound_at; an unset audience / missing value render as
// JSON null / bound:false so cogworx shows the inject request as not injectable.
// The four operator-inject keys are ALWAYS present (defaults included): their
// absence is how cogworx recognises an agent that predates them.
test "appendSecretJson emits bound and unbound shapes" {
	const a = t.allocator;
	{
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(a);
		try main.appendSecretJson(a, &out, "api-token", .{ .audience = "api.example.com", .kind = "bearer", .tier = "durable", .bound_at = 1700000000 }, true);
		try t.expectEqualStrings(
			"{\"name\":\"api-token\",\"kind\":\"bearer\",\"audience\":\"api.example.com\",\"tier\":\"durable\",\"bound\":true,\"bound_at\":1700000000,\"inject\":false,\"cookie_name\":null,\"port\":null,\"on_guest_credential\":\"replace\"}",
			out.items,
		);
	}
	{
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(a);
		try main.appendSecretJson(a, &out, "app-session", .{ .audience = null, .kind = "cookie", .tier = "durable", .bound_at = null }, false);
		try t.expectEqualStrings(
			"{\"name\":\"app-session\",\"kind\":\"cookie\",\"audience\":null,\"tier\":\"durable\",\"bound\":false,\"bound_at\":null,\"inject\":false,\"cookie_name\":null,\"port\":null,\"on_guest_credential\":\"replace\"}",
			out.items,
		);
	}
	{
		// An operator inject bind: every key set, the cookie name JSON-escaped
		// like any other string.
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(a);
		try main.appendSecretJson(a, &out, "app-session", .{ .audience = "app.example.com", .kind = "cookie", .tier = "durable", .bound_at = 1700000000, .inject = true, .cookie_name = "session", .port = 8443, .on_guest_credential = "keep" }, true);
		try t.expectEqualStrings(
			"{\"name\":\"app-session\",\"kind\":\"cookie\",\"audience\":\"app.example.com\",\"tier\":\"durable\",\"bound\":true,\"bound_at\":1700000000,\"inject\":true,\"cookie_name\":\"session\",\"port\":8443,\"on_guest_credential\":\"keep\"}",
			out.items,
		);
	}
}

// --- staged L7-proxy read access (GCE uid split) ----------------------------
//
// On a deployment that sets COGBOX_PROXY_RUNAS the proxy reads bound credentials
// through a GROUP grant that the inject render makes (rules/credgrant.zig). A
// bind and its render are two separate control execs, so a credential used to
// exist unreadable for ~an SSH round-trip and the addon answered 403 "credential
// unavailable" in that window. These pin the write end of the fix: the group is
// on the file before it is nameable, so the render's chmod is a no-op rather
// than the moment of readability.

/// The group owner, which `Io.File.Stat` does not carry.
fn gidOf(path: []const u8) !store.Gid {
	var buf: [std.fs.max_path_bytes]u8 = undefined;
	const path_z = try std.fmt.bufPrintZ(&buf, "{s}", .{path});
	return (try @import("platform").statPath(path_z)).gid;
}

fn modeOf(io: std.Io, path: []const u8) !std.posix.mode_t {
	const st = try std.Io.Dir.cwd().statFile(io, path, .{});
	return st.permissions.toMode() & 0o7777;
}

fn tmpStoreDir(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	return std.fmt.allocPrint(gpa, "zig-secret-store-{s}", .{hexb});
}

fn expectStoreEntries(io: std.Io, path: []const u8, names: []const []const u8) !void {
	var dir = try std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
	defer dir.close(io);
	var iter = dir.iterate();
	var count: usize = 0;
	while (try iter.next(io)) |entry| {
		for (names) |name| {
			if (std.mem.eql(u8, entry.name, name)) break;
		} else return error.UnexpectedStoreEntry;
		count += 1;
	}
	try t.expectEqual(names.len, count);
}

test "addForProxy stages the proxy group + 0640 on the value file, leaving the meta owner-only" {
	const gpa = t.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const dir = try tmpStoreDir(gpa, io);
	defer gpa.free(dir);
	defer cwd.deleteTree(io, dir) catch {};

	// The test process's own primary gid: the one group it may chown a file it
	// owns to without privileges. It stands in for the proxy's gid.
	const gid: store.Gid = @intCast(@import("platform").getgid());

	const outcome = try store.addForProxy(gpa, io, dir, "api-token", "tok-abc123", .{
		.audience = "api.example.com",
		.kind = "bearer",
	}, gid);
	try t.expect(outcome.proxy_readable);

	const vpath = try std.fs.path.join(gpa, &.{ dir, "api-token" });
	defer gpa.free(vpath);
	// Exactly credgrant.grantedMode(0600): owner rw, group read, other nothing.
	try t.expectEqual(@as(std.posix.mode_t, 0o640), try modeOf(io, vpath));
	try t.expectEqual(gid, try gidOf(vpath));

	// The proxy reads VALUES, never metadata, so the sidecar is not widened.
	const mpath = try std.fs.path.join(gpa, &.{ dir, "api-token.meta" });
	defer gpa.free(mpath);
	try t.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(io, mpath));

	// The widening happened on the temp path and the rename published it whole:
	// the value is intact and no `.tmp` is left behind for listBound to trip on.
	const f = try cwd.openFile(io, vpath, .{});
	defer f.close(io);
	var rbuf: [64]u8 = undefined;
	var r = f.reader(io, &rbuf);
	const got = try r.interface.allocRemaining(gpa, .limited(1 << 10));
	defer gpa.free(got);
	try t.expectEqualStrings("tok-abc123", got);

	try expectStoreEntries(io, dir, &.{ "api-token", "api-token.meta" });
}

test "addForProxy cleans a failed staged rename before an owner-only retry" {
	const gpa = t.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();
	const dir = try tmpStoreDir(gpa, io);
	defer gpa.free(dir);
	defer cwd.deleteTree(io, dir) catch {};
	const path = try std.fs.path.join(gpa, &.{ dir, "api-token" });
	defer gpa.free(path);
	// A directory at the destination forces rename to fail AFTER staging 0640.
	try cwd.createDirPath(io, path);
	const gid: store.Gid = @intCast(@import("platform").getgid());
	if (store.addForProxy(gpa, io, dir, "api-token", "fake-proxy-value", .{ .audience = "api.example.com" }, gid)) |_| {
		return error.ExpectedRenameFailure;
	} else |_| {}
	try expectStoreEntries(io, dir, &.{"api-token"});
	try cwd.deleteDir(io, path);
	const outcome = try store.addForProxy(gpa, io, dir, "api-token", "fake-owner-only-value", .{}, gid);
	try t.expect(!outcome.proxy_readable);
	try t.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(io, path));
	const got = try cwd.readFileAlloc(io, path, gpa, .limited(1 << 10));
	defer gpa.free(got);
	try t.expectEqualStrings("fake-owner-only-value", got);
	try expectStoreEntries(io, dir, &.{ "api-token", "api-token.meta" });
}

test "addForProxy ignores legacy group-readable temps and symlinks" {
	const gpa = t.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();
	const dir = try tmpStoreDir(gpa, io);
	defer gpa.free(dir);
	defer cwd.deleteTree(io, dir) catch {};
	try cwd.createDirPath(io, dir);
	const legacy = try std.fs.path.join(gpa, &.{ dir, "api-token.tmp" });
	defer gpa.free(legacy);
	{
		const f = try cwd.createFile(io, legacy, .{});
		defer f.close(io);
		try f.setPermissions(io, .fromMode(0o640));
		var buf: [64]u8 = undefined;
		var writer = f.writer(io, &buf);
		try writer.interface.writeAll("fake-stale-value");
		try writer.flush();
	}
	const link = try std.fs.path.join(gpa, &.{ dir, "app-session.tmp" });
	defer gpa.free(link);
	try cwd.symLink(io, "api-token.tmp", link, .{});
	const gid: store.Gid = @intCast(@import("platform").getgid());
	for ([_][]const u8{ "api-token", "app-session" }) |name| {
		const outcome = try store.addForProxy(gpa, io, dir, name, "fake-owner-only-value", .{}, gid);
		try t.expect(!outcome.proxy_readable);
		const path = try std.fs.path.join(gpa, &.{ dir, name });
		defer gpa.free(path);
		try t.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(io, path));
		const got = try cwd.readFileAlloc(io, path, gpa, .limited(1 << 10));
		defer gpa.free(got);
		try t.expectEqualStrings("fake-owner-only-value", got);
	}
	const stale = try cwd.readFileAlloc(io, legacy, gpa, .limited(1 << 10));
	defer gpa.free(stale);
	try t.expectEqualStrings("fake-stale-value", stale);
	try t.expectEqual(@as(std.posix.mode_t, 0o640), try modeOf(io, legacy));
	try t.expectEqual(.sym_link, (try cwd.statFile(io, link, .{ .follow_symlinks = false })).kind);
	try expectStoreEntries(io, dir, &.{ "api-token.tmp", "app-session.tmp", "api-token", "api-token.meta", "app-session", "app-session.meta" });
}

const ConcurrentBind = struct {
	dir: []const u8,
	value: []const u8,
	start: *std.atomic.Value(bool),
	failure: ?anyerror = null,

	fn run(self: *@This()) void {
		var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
		defer threaded.deinit();
		while (!self.start.load(.acquire)) std.atomic.spinLoopHint();
		for (0..10) |_| {
			_ = store.addForProxy(std.heap.page_allocator, threaded.io(), self.dir, "api-token", self.value, .{
				.audience = "api.example.com",
			}, @intCast(@import("platform").getgid())) catch |err| {
				self.failure = err;
				return;
			};
		}
	}
};

test "addForProxy overlapping binds publish whole values without sharing temps" {
	const gpa = t.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();
	const dir = try tmpStoreDir(gpa, io);
	defer gpa.free(dir);
	defer cwd.deleteTree(io, dir) catch {};
	try cwd.createDirPath(io, dir);
	// Payloads span many buffer flushes. Metadata is identical: concurrent
	// value/metadata pairs are not a transaction, and this does not claim one.
	const a = "a" ** (128 * 1024);
	const b = "b" ** (128 * 1024);
	var start: std.atomic.Value(bool) = .init(false);
	var first: ConcurrentBind = .{ .dir = dir, .value = a, .start = &start };
	var second: ConcurrentBind = .{ .dir = dir, .value = b, .start = &start };
	{
		const th1 = try std.Thread.spawn(.{}, ConcurrentBind.run, .{&first});
		defer th1.join();
		// Release the first thread even if spawning the second one fails.
		defer start.store(true, .release);
		const th2 = try std.Thread.spawn(.{}, ConcurrentBind.run, .{&second});
		defer th2.join();
		start.store(true, .release);
	}
	if (first.failure) |err| return err;
	if (second.failure) |err| return err;
	const path = try std.fs.path.join(gpa, &.{ dir, "api-token" });
	defer gpa.free(path);
	const got = try cwd.readFileAlloc(io, path, gpa, .limited(a.len + 1));
	defer gpa.free(got);
	try t.expect(std.mem.eql(u8, got, a) or std.mem.eql(u8, got, b));
	try t.expectEqual(@as(std.posix.mode_t, 0o640), try modeOf(io, path));
	try t.expectEqual(@as(store.Gid, @intCast(@import("platform").getgid())), try gidOf(path));
	try expectStoreEntries(io, dir, &.{ "api-token", "api-token.meta" });
}

test "addForProxy leaves the store owner-only with no proxy gid, and for a secret with no audience" {
	const gpa = t.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const dir = try tmpStoreDir(gpa, io);
	defer gpa.free(dir);
	defer cwd.deleteTree(io, dir) catch {};

	const gid: store.Gid = @intCast(@import("platform").getgid());

	// No uid split configured (container/k8s/local): byte-for-byte the old
	// behavior, 0600 and nothing granted.
	const unsplit = try store.addForProxy(gpa, io, dir, "app-session", "sess", .{
		.audience = "app.example.com",
		.kind = "cookie",
	}, null);
	try t.expect(!unsplit.proxy_readable);
	const spath = try std.fs.path.join(gpa, &.{ dir, "app-session" });
	defer gpa.free(spath);
	try t.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(io, spath));

	// A secret with no audience is not injectable at all (the renderer skips
	// it), so there is no window to close and nothing is widened for it even
	// where a proxy gid IS configured.
	const no_aud = try store.addForProxy(gpa, io, dir, "api-token", "tok", .{
		.audience = null,
		.kind = "bearer",
	}, gid);
	try t.expect(!no_aud.proxy_readable);
	const npath = try std.fs.path.join(gpa, &.{ dir, "api-token" });
	defer gpa.free(npath);
	try t.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(io, npath));

	// The plain `add` wrapper every other caller uses is the no-gid case.
	try store.add(gpa, io, dir, "git-example", "glpat-FAKE", .{ .audience = "git.example.com", .kind = "bearer" });
	const gpath = try std.fs.path.join(gpa, &.{ dir, "git-example" });
	defer gpa.free(gpath);
	try t.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(io, gpath));
}

test "proxygid.fromEnv yields no gid without a COGBOX_PROXY_RUNAS spec" {
	const gpa = t.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();

	// No env at all (the container enforcer's render/bind path).
	const none = try proxygid.fromEnv(gpa, io, null);
	try t.expect(none.gid == null);
	try t.expect(none.unresolved_group == null);

	// An env that simply does not set the variable.
	var env = std.process.Environ.Map.init(gpa);
	defer env.deinit();
	try env.put("PATH", "/usr/bin");
	const unset = try proxygid.fromEnv(gpa, io, &env);
	try t.expect(unset.gid == null);
	try t.expect(unset.unresolved_group == null);

	// A numeric spelling resolves without a name service, so this is the one
	// arm that can assert a gid without depending on the host's /etc/group.
	try env.put("COGBOX_PROXY_RUNAS", "998:998");
	const numeric = try proxygid.fromEnv(gpa, io, &env);
	try t.expectEqual(@as(?store.Gid, 998), numeric.gid);
	try t.expect(numeric.unresolved_group == null);

	// A name the group file does not define: no gid, but the caller is told
	// which group so it can warn instead of silently behaving unsplit.
	try env.put("COGBOX_PROXY_RUNAS", "cogbox-proxy:definitely-not-a-real-group-name");
	const missing = try proxygid.fromEnv(gpa, io, &env);
	try t.expect(missing.gid == null);
	try t.expectEqualStrings("definitely-not-a-real-group-name", missing.unresolved_group.?);
}

test "secret add: COGBOX_PROXY_RUNAS reaches the store through dispatch, so the BIND itself lands 0640/proxy-gid" {
	// The two tests above pin store.addForProxy with a gid handed straight in,
	// and proxygid.fromEnv in isolation; neither covers the wiring BETWEEN them
	// (`secret add` -> fromEnv -> addForProxy), which is the whole of this leg.
	// Hard-coding the gid to null at the call site left both of them green.
	const gpa = t.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const dir = try tmpStoreDir(gpa, io);
	defer gpa.free(dir);
	defer cwd.deleteTree(io, dir) catch {};

	// The value arrives by --from-file so the test never touches stdin. It lives
	// OUTSIDE the store dir: anything beside a value file there is store content.
	const src_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(src_dir);
	defer cwd.deleteTree(io, src_dir) catch {};
	try cwd.createDirPath(io, src_dir);
	const src = try std.fs.path.join(gpa, &.{ src_dir, "value" });
	defer gpa.free(src);
	{
		const f = try cwd.createFile(io, src, .{ .truncate = true });
		defer f.close(io);
		var wbuf: [64]u8 = undefined;
		var w = f.writer(io, &wbuf);
		try w.interface.writeAll("tok-abc123\n");
		try w.flush();
	}

	var env = std.process.Environ.Map.init(gpa);
	defer env.deinit();
	// The test process's own primary gid, spelled NUMERICALLY (the one gid it may
	// chown to unprivileged, and the one spelling that needs no /etc/group).
	const gid: store.Gid = @intCast(@import("platform").getgid());
	const spec = try std.fmt.allocPrint(gpa, "cogbox-proxy:{d}", .{gid});
	defer gpa.free(spec);
	try env.put("COGBOX_PROXY_RUNAS", spec);

	// `secret add` ANNOUNCES on stdout, and under `zig build test` stdout is the
	// build runner's message-protocol pipe: raw bytes there wedge the whole run
	// (the runner waits for a message it can parse, the test binary waits for its
	// next command, neither times out). Point fd 1 at /dev/null across the two
	// dispatch calls -- every other test in this file drives the store directly,
	// which is why this is the only one that needs it.
	const devnull = try std.posix.openatZ(std.posix.AT.FDCWD, "/dev/null", .{ .ACCMODE = .WRONLY }, 0);
	defer _ = std.c.close(devnull);
	const saved_stdout: i32 = @intCast(std.c.dup(1));
	defer {
		_ = std.c.dup2(saved_stdout, 1);
		_ = std.c.close(saved_stdout);
	}
	_ = std.c.dup2(devnull, 1);

	try main.dispatch(gpa, io, dir, &.{ "add", "api-token", "--from-file", src, "--audience", "api.example.com", "--kind", "bearer" }, &env);

	const vpath = try std.fs.path.join(gpa, &.{ dir, "api-token" });
	defer gpa.free(vpath);
	try t.expectEqual(@as(std.posix.mode_t, 0o640), try modeOf(io, vpath));
	try t.expectEqual(gid, try gidOf(vpath));
	// The trailing newline is trimmed and the value is intact -- the staged
	// chown/chmod happened on the temp, so the rename published a whole file.
	const f = try cwd.openFile(io, vpath, .{});
	defer f.close(io);
	var rbuf: [64]u8 = undefined;
	var r = f.reader(io, &rbuf);
	const got = try r.interface.allocRemaining(gpa, .limited(1 << 10));
	defer gpa.free(got);
	try t.expectEqualStrings("tok-abc123", got);
	// The sidecar is never widened, on this path either.
	const mpath = try std.fs.path.join(gpa, &.{ dir, "api-token.meta" });
	defer gpa.free(mpath);
	try t.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(io, mpath));

	// No uid split configured (container/k8s/local, and every deployment before
	// this feature): the same command binds owner-only, exactly as it always did.
	var plain = std.process.Environ.Map.init(gpa);
	defer plain.deinit();
	try plain.put("PATH", "/usr/bin");
	try main.dispatch(gpa, io, dir, &.{ "add", "app-session", "--from-file", src, "--audience", "app.example.com", "--kind", "cookie" }, &plain);
	const spath = try std.fs.path.join(gpa, &.{ dir, "app-session" });
	defer gpa.free(spath);
	try t.expectEqual(@as(std.posix.mode_t, 0o600), try modeOf(io, spath));
}

// --- operator inject flags at the verb (`secret add --inject ...`) ----------
//
// die() exits the PROCESS, so an exit-code assertion cannot run in-process: each
// refusal case forks, runs dispatch in the child with stdout at /dev/null (under
// `zig build test` fd 1 is the build runner's protocol pipe) and stderr captured
// through a pipe, and the parent asserts on the code + the bytes. The child's
// stdin is a pipe the parent PRE-FILLS with a value and reads back afterwards,
// which is how "nothing was read before the refusal" is proven rather than
// assumed -- the exit-64 contract cogworx relies on is exactly that.

const ChildResult = struct { code: u8, stderr: []u8, stdin_left: []u8 };

fn dispatchInChild(gpa: std.mem.Allocator, dir: []const u8, argv: []const []const u8, stdin_payload: []const u8) !ChildResult {
	var err_fds: [2]i32 = undefined;
	if (std.os.linux.pipe(&err_fds) != 0) return error.PipeFailed;
	var in_fds: [2]i32 = undefined;
	if (std.os.linux.pipe(&in_fds) != 0) return error.PipeFailed;
	// The whole payload sits in the pipe buffer before the child starts, and
	// EVERY write end is closed right after the fork (below, in both
	// processes): a child that wrongly reaches the stdin read then sees the
	// payload followed by EOF, binds it and exits 0 -- a clean exit-code
	// failure for the caller, never a hang on a pipe nobody will close.
	if (std.os.linux.write(in_fds[1], stdin_payload.ptr, stdin_payload.len) != stdin_payload.len) return error.WriteFailed;
	const devnull = try std.posix.openatZ(std.posix.AT.FDCWD, "/dev/null", .{ .ACCMODE = .WRONLY }, 0);

	const rc = std.os.linux.fork();
	if (std.os.linux.errno(rc) != .SUCCESS) return error.ForkFailed;
	if (rc == 0) {
		// CHILD. Only this thread survived the fork, so touch no parent-owned
		// lock: page_allocator and a fresh Io.
		_ = std.os.linux.close(err_fds[0]);
		_ = std.os.linux.close(in_fds[1]);
		_ = std.os.linux.dup2(err_fds[1], 2);
		_ = std.os.linux.dup2(in_fds[0], 0);
		_ = std.os.linux.dup2(devnull, 1);
		var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
		main.dispatch(std.heap.page_allocator, threaded.io(), dir, argv, null) catch std.process.exit(99);
		std.process.exit(0);
	}
	// PARENT. in_fds[0] stays open here: it is read back below, once the
	// child is gone, for whatever the child left unconsumed; in_fds[1] goes
	// now so that read (and any read the child makes) ends at EOF.
	_ = std.os.linux.close(err_fds[1]);
	_ = std.os.linux.close(in_fds[1]);
	_ = std.os.linux.close(devnull);
	var err_out: std.ArrayList(u8) = .empty;
	errdefer err_out.deinit(gpa);
	var buf: [4096]u8 = undefined;
	while (true) {
		// std.posix.read retries EINTR (the child's exit can interrupt a
		// blocking read) and types any other failure.
		const n = try std.posix.read(err_fds[0], &buf);
		if (n == 0) break;
		try err_out.appendSlice(gpa, buf[0..n]);
	}
	_ = std.os.linux.close(err_fds[0]);
	var status: u32 = 0;
	while (true) {
		const wr = std.os.linux.waitpid(@intCast(rc), &status, 0);
		if (std.os.linux.errno(wr) == .INTR) continue;
		if (std.os.linux.errno(wr) != .SUCCESS) return error.WaitFailed;
		break;
	}
	if (!std.os.linux.W.IFEXITED(status)) return error.ChildSignalled;
	// Whatever the child did not consume is still in the stdin pipe.
	var left: std.ArrayList(u8) = .empty;
	errdefer left.deinit(gpa);
	while (true) {
		const n = try std.posix.read(in_fds[0], &buf);
		if (n == 0) break;
		try left.appendSlice(gpa, buf[0..n]);
	}
	_ = std.os.linux.close(in_fds[0]);
	return .{ .code = std.os.linux.W.EXITSTATUS(status), .stderr = try err_out.toOwnedSlice(gpa), .stdin_left = try left.toOwnedSlice(gpa) };
}

fn expectRefused(gpa: std.mem.Allocator, dir: []const u8, argv: []const []const u8, code: u8, needle: []const u8) !void {
	const r = try dispatchInChild(gpa, dir, argv, "tok-never-read\n");
	defer gpa.free(r.stderr);
	defer gpa.free(r.stdin_left);
	try t.expectEqual(code, r.code);
	try t.expect(std.mem.startsWith(u8, r.stderr, "cogbox secret: error: "));
	try t.expect(std.mem.indexOf(u8, r.stderr, needle) != null);
	// Refused BEFORE the value was read: the payload is still in the pipe...
	try t.expectEqualStrings("tok-never-read\n", r.stdin_left);
	// ...and nothing landed in the store (no dir is ever created).
	try t.expectError(error.FileNotFound, std.Io.Dir.cwd().access(io_for_access, dir, .{}));
}

// expectRefused needs an Io for the access probe; a file-scope Threaded keeps
// the helper's signature small.
var access_threaded: ?std.Io.Threaded = null;
var io_for_access: std.Io = undefined;

test "secret add: an unknown flag is exit 64 with the byte-exact `cogbox secret: error: unknown flag '<flag>'` payload cogworx classifies, before any value is read or validated" {
	const gpa = t.allocator;
	access_threaded = .init(gpa, .{});
	defer {
		access_threaded.?.deinit();
		access_threaded = null;
	}
	io_for_access = access_threaded.?.io();
	const dir = try tmpStoreDir(gpa, io_for_access);
	defer gpa.free(dir);

	// The exact rendering (prefix, quotes, newline) is the CROSS-REPO CONTRACT:
	// cogworx matches `cogbox secret: error: unknown flag '--inject'` /
	// `... '--on-guest-credential'` on exit 64 to turn an old-agent bind into a
	// coded "agent update required" refusal. This binary knows those flags, so
	// the rendering is pinned on a flag no binary knows, with the SAME die.
	{
		const r = try dispatchInChild(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--no-such-flag", "--audience", "api.example.com" }, "tok-never-read\n");
		defer gpa.free(r.stderr);
		defer gpa.free(r.stdin_left);
		try t.expectEqual(@as(u8, 64), r.code);
		try t.expectEqualStrings("cogbox secret: error: unknown flag '--no-such-flag'\n", r.stderr);
		try t.expectEqualStrings("tok-never-read\n", r.stdin_left);
	}
	// Parse order: the unknown flag fires where it is met, ahead of a later
	// value flag's exit-65 validation (`--kind bogus` never gets a say) -- so an
	// old binary's refusal of `--inject` can never be masked by a 65.
	{
		const r = try dispatchInChild(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--no-such-flag", "--kind", "bogus" }, "x\n");
		defer gpa.free(r.stderr);
		defer gpa.free(r.stdin_left);
		try t.expectEqual(@as(u8, 64), r.code);
		try t.expectEqualStrings("cogbox secret: error: unknown flag '--no-such-flag'\n", r.stderr);
	}
	// The payload string as cogworx spells it, produced by the same format.
	const rendered = try std.fmt.allocPrint(gpa, "cogbox secret: error: unknown flag '{s}'\n", .{"--inject"});
	defer gpa.free(rendered);
	try t.expectEqualStrings("cogbox secret: error: unknown flag '--inject'\n", rendered);
	try t.expectError(error.FileNotFound, std.Io.Dir.cwd().access(io_for_access, dir, .{}));
}

test "secret add: operator-inject validation exits 65 BEFORE the value is read, binding nothing" {
	const gpa = t.allocator;
	access_threaded = .init(gpa, .{});
	defer {
		access_threaded.?.deinit();
		access_threaded = null;
	}
	io_for_access = access_threaded.?.io();
	const dir = try tmpStoreDir(gpa, io_for_access);
	defer gpa.free(dir);

	// --inject without an audience: nothing to seed the spec's host from.
	try expectRefused(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--inject" }, 65, "--inject requires --audience");
	// --inject is for the operator kinds only; the platform kinds are seeded by
	// the control plane and must never get a whole-host operator spec.
	try expectRefused(gpa, dir, &.{ "add", "git-example", "--from-stdin", "--audience", "git.example.com", "--kind", "gitlab-oauth", "--inject" }, 65, "applies to bearer|cookie|basic");
	try expectRefused(gpa, dir, &.{ "add", "claude-oauth", "--from-stdin", "--audience", "api.anthropic.com", "--kind", "anthropic-oauth", "--inject" }, 65, "applies to bearer|cookie|basic");
	try expectRefused(gpa, dir, &.{ "add", "git-example", "--from-stdin", "--audience", "git.example.com", "--kind", "gitlab-authproxy", "--inject" }, 65, "applies to bearer|cookie|basic");
	// A cookie inject bind needs the cookie name (the addon's cookie arm is a
	// no-op without one); a cookie name is meaningless on any other kind.
	try expectRefused(gpa, dir, &.{ "add", "app-session", "--from-stdin", "--audience", "app.example.com", "--kind", "cookie", "--inject" }, 65, "requires --cookie-name");
	try expectRefused(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--audience", "api.example.com", "--kind", "bearer", "--cookie-name", "session" }, 65, "applies only to --kind cookie");
	try expectRefused(gpa, dir, &.{ "add", "app-session", "--from-stdin", "--audience", "app.example.com", "--kind", "cookie", "--cookie-name", "a;b", "--inject" }, 65, "invalid --cookie-name");
	try expectRefused(gpa, dir, &.{ "add", "app-session", "--from-stdin", "--audience", "app.example.com", "--kind", "cookie", "--cookie-name=", "--inject" }, 65, "invalid --cookie-name");
	// Port 1..65535, digits only.
	try expectRefused(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--audience", "api.example.com", "--inject", "--port", "0" }, 65, "invalid --port");
	try expectRefused(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--audience", "api.example.com", "--inject", "--port", "70000" }, 65, "invalid --port");
	try expectRefused(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--audience", "api.example.com", "--inject", "--port=nine" }, 65, "invalid --port");
	// Precedence is exactly replace|keep.
	try expectRefused(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--audience", "api.example.com", "--inject", "--on-guest-credential", "maybe" }, 65, "invalid --on-guest-credential");
	try expectRefused(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--audience", "api.example.com", "--on-guest-credential=Keep" }, 65, "invalid --on-guest-credential");
	// With --inject the audience becomes a policy LINE (l7-rules and
	// l7-inject-hosts are whitespace-tokenized), so it must be one exact bare
	// host: no rule tokens after a space (`insecure`), no extra lines after a
	// newline (`mode passthrough`), no wildcard, no port, no trailing dot.
	try expectRefused(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--inject", "--audience", "a.example.com insecure" }, 65, "invalid --audience");
	try expectRefused(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--inject", "--audience", "b.example.com\nmode passthrough" }, 65, "invalid --audience");
	try expectRefused(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--inject", "--audience", "*.example.com" }, 65, "invalid --audience");
	try expectRefused(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--inject", "--audience=c.example.com:9200" }, 65, "invalid --audience");
	try expectRefused(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--inject", "--audience", "d.example.com." }, 65, "invalid --audience");
	try expectRefused(gpa, dir, &.{ "add", "api-token", "--from-stdin", "--audience", " api.example.com", "--kind", "bearer", "--inject" }, 65, "invalid --audience");
}

test "secret add --inject --port=9200 --on-guest-credential keep binds the meta the render seeds from; a plain bind and a plugin-spec bind choosing keep stay inject=false" {
	const gpa = t.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const dir = try tmpStoreDir(gpa, io);
	defer gpa.free(dir);
	defer cwd.deleteTree(io, dir) catch {};

	// The value arrives by --from-file (never stdin under the test runner).
	const src_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(src_dir);
	defer cwd.deleteTree(io, src_dir) catch {};
	try cwd.createDirPath(io, src_dir);
	const src = try std.fs.path.join(gpa, &.{ src_dir, "value" });
	defer gpa.free(src);
	{
		const f = try cwd.createFile(io, src, .{ .truncate = true });
		defer f.close(io);
		var wbuf: [64]u8 = undefined;
		var w = f.writer(io, &wbuf);
		try w.interface.writeAll("elastic:FAKE\n");
		try w.flush();
	}

	// stdout is the build runner's protocol pipe under `zig build test`; the
	// announce line must not reach it (see the COGBOX_PROXY_RUNAS test above).
	const devnull = try std.posix.openatZ(std.posix.AT.FDCWD, "/dev/null", .{ .ACCMODE = .WRONLY }, 0);
	defer _ = std.os.linux.close(devnull);
	const saved_stdout: i32 = @intCast(std.os.linux.dup(1));
	defer {
		_ = std.os.linux.dup2(saved_stdout, 1);
		_ = std.os.linux.close(saved_stdout);
	}
	_ = std.os.linux.dup2(devnull, 1);

	var arena = std.heap.ArenaAllocator.init(gpa);
	defer arena.deinit();

	// The cogworx argv for an injecting basic bind on a non-standard port, keep
	// precedence (both flag spellings).
	try main.dispatch(gpa, io, dir, &.{ "add", "es-creds", "--from-file", src, "--audience", "es.example.com", "--kind", "basic", "--inject", "--on-guest-credential", "keep", "--port=9200" }, null);
	{
		const r = (try store.lookup(arena.allocator(), io, dir, "es-creds")).?;
		try t.expect(r.bound);
		try t.expectEqualStrings("es.example.com", r.meta.audience.?);
		try t.expectEqualStrings("basic", r.meta.kind);
		try t.expect(r.meta.inject);
		try t.expectEqual(@as(?u16, 9200), r.meta.port);
		try t.expect(r.meta.cookie_name == null);
		try t.expectEqualStrings("keep", r.meta.on_guest_credential);
	}
	// A cookie inject bind records the cookie the proxy replaces.
	try main.dispatch(gpa, io, dir, &.{ "add", "app-session", "--from-file", src, "--audience", "app.example.com", "--kind", "cookie", "--cookie-name", "session", "--inject" }, null);
	{
		const r = (try store.lookup(arena.allocator(), io, dir, "app-session")).?;
		try t.expect(r.meta.inject);
		try t.expectEqualStrings("session", r.meta.cookie_name.?);
		try t.expect(r.meta.port == null);
		try t.expectEqualStrings("replace", r.meta.on_guest_credential);
	}
	// Today's argv (plugin "Bind now", claude/git reconcile): inert defaults.
	try main.dispatch(gpa, io, dir, &.{ "add", "api-token", "--from-file", src, "--audience", "api.example.com", "--kind", "bearer" }, null);
	{
		const r = (try store.lookup(arena.allocator(), io, dir, "api-token")).?;
		try t.expect(!r.meta.inject);
		try t.expect(r.meta.cookie_name == null);
		try t.expect(r.meta.port == null);
		try t.expectEqualStrings("replace", r.meta.on_guest_credential);
	}
	// A plugin-spec bind may choose keep WITHOUT --inject: the precedence rides
	// through the plugin's spec (the render reads it from this meta).
	try main.dispatch(gpa, io, dir, &.{ "add", "plugin-tok", "--from-file", src, "--audience", "api.example.com", "--kind", "bearer", "--on-guest-credential", "keep" }, null);
	{
		const r = (try store.lookup(arena.allocator(), io, dir, "plugin-tok")).?;
		try t.expect(!r.meta.inject);
		try t.expectEqualStrings("keep", r.meta.on_guest_credential);
	}
	// The audience grammar gate admits an IP literal and mixed case (the render
	// compares case-insensitively, the rules reader too) with --inject...
	try main.dispatch(gpa, io, dir, &.{ "add", "ip-token", "--from-file", src, "--audience", "10.0.0.5", "--kind", "bearer", "--inject" }, null);
	try main.dispatch(gpa, io, dir, &.{ "add", "cased-token", "--from-file", src, "--audience", "Api.Example.Com", "--kind", "bearer", "--inject" }, null);
	{
		const r = (try store.lookup(arena.allocator(), io, dir, "ip-token")).?;
		try t.expect(r.meta.inject);
		try t.expectEqualStrings("10.0.0.5", r.meta.audience.?);
		const c = (try store.lookup(arena.allocator(), io, dir, "cased-token")).?;
		try t.expect(c.meta.inject);
		try t.expectEqualStrings("Api.Example.Com", c.meta.audience.?);
	}
	// ...and applies ONLY with --inject: today's argv keeps accepting an audience
	// the render only ever compares against a plugin spec's host (folded, so a
	// trailing dot still matches), never renders as a line.
	try main.dispatch(gpa, io, dir, &.{ "add", "dotted-plain", "--from-file", src, "--audience", "api.example.com.", "--kind", "bearer" }, null);
	{
		const r = (try store.lookup(arena.allocator(), io, dir, "dotted-plain")).?;
		try t.expect(r.bound);
		try t.expect(!r.meta.inject);
		try t.expectEqualStrings("api.example.com.", r.meta.audience.?);
	}
}
