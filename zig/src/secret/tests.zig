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
}

// `secret ls --json` shape the control plane (cogworx) parses. A bound secret
// carries its audience + bound_at; an unset audience / missing value render as
// JSON null / bound:false so cogworx shows the inject request as not injectable.
test "appendSecretJson emits bound and unbound shapes" {
	const a = t.allocator;
	{
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(a);
		try main.appendSecretJson(a, &out, "api-token", .{ .audience = "api.example.com", .kind = "bearer", .tier = "durable", .bound_at = 1700000000 }, true);
		try t.expectEqualStrings(
			"{\"name\":\"api-token\",\"kind\":\"bearer\",\"audience\":\"api.example.com\",\"tier\":\"durable\",\"bound\":true,\"bound_at\":1700000000}",
			out.items,
		);
	}
	{
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(a);
		try main.appendSecretJson(a, &out, "app-session", .{ .audience = null, .kind = "cookie", .tier = "durable", .bound_at = null }, false);
		try t.expectEqualStrings(
			"{\"name\":\"app-session\",\"kind\":\"cookie\",\"audience\":null,\"tier\":\"durable\",\"bound\":false,\"bound_at\":null}",
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
	var sx: std.os.linux.Statx = undefined;
	const rc = std.os.linux.statx(std.posix.AT.FDCWD, path_z, 0, .{ .GID = true }, &sx);
	if (rc != 0) return error.StatxFailed;
	return sx.gid;
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
	const gid: store.Gid = @intCast(std.os.linux.getgid());

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
	const gid: store.Gid = @intCast(std.os.linux.getgid());
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
	const gid: store.Gid = @intCast(std.os.linux.getgid());
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
			}, @intCast(std.os.linux.getgid())) catch |err| {
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
	try t.expectEqual(@as(store.Gid, @intCast(std.os.linux.getgid())), try gidOf(path));
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

	const gid: store.Gid = @intCast(std.os.linux.getgid());

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
	const gid: store.Gid = @intCast(std.os.linux.getgid());
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
	defer _ = std.os.linux.close(devnull);
	const saved_stdout: i32 = @intCast(std.os.linux.dup(1));
	defer {
		_ = std.os.linux.dup2(saved_stdout, 1);
		_ = std.os.linux.close(saved_stdout);
	}
	_ = std.os.linux.dup2(devnull, 1);

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
