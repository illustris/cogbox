// Aggregator for `zig build test`. refAllDecls(main) forces full analysis of
// the server code so its compile errors surface here (not only at exe link),
// and pulls in every module's unit tests; the standalone oracle file is
// imported directly. The in-memory end-to-end tests below drive the WHOLE
// server path with no sockets (addendum G.2): a fake mitmproxy client via
// Io.Reader.fixed, a response sink via Io.Writer.Allocating, and a fake
// upstream behind the UpstreamIO transport seam.

const std = @import("std");
const t = std.testing;

const main = @import("main.zig");
const canon = @import("canon.zig");
const framing = @import("framing.zig");
const conf = @import("conf.zig");
const plugin_mod = @import("plugin.zig");
const upstream = @import("upstream.zig");
const gitlab = @import("plugins/gitlab.zig");

test {
	std.testing.refAllDecls(@import("main.zig"));
	std.testing.refAllDecls(@import("canon.zig"));
	std.testing.refAllDecls(@import("framing.zig"));
	std.testing.refAllDecls(@import("conf.zig"));
	std.testing.refAllDecls(@import("upstream.zig"));
	std.testing.refAllDecls(@import("plugin.zig"));
	std.testing.refAllDecls(@import("pktline.zig"));
	std.testing.refAllDecls(@import("plugins/gitlab.zig"));
	_ = @import("route_vectors_test.zig");
}

// --- e2e harness -----------------------------------------------------------

const Harness = struct {
	gpa: std.mem.Allocator,
	threaded: std.Io.Threaded,
	io: std.Io,
	dir: []u8,
	cred_path: []u8,

	fn init(gpa: std.mem.Allocator) !Harness {
		var threaded: std.Io.Threaded = .init(gpa, .{});
		const io = threaded.io();
		var rnd: [8]u8 = undefined;
		io.random(&rnd);
		var hexb: [16]u8 = undefined;
		_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
		const dir = try std.fmt.allocPrint(gpa, "zig-authproxy-e2e-{s}", .{hexb});
		try std.Io.Dir.cwd().createDirPath(io, dir);
		const cred_path = try std.fs.path.join(gpa, &.{ dir, "git-gitlab" });
		try writeFile(io, cred_path, "glpat-FAKEFAKEFAKE\n");
		return .{ .gpa = gpa, .threaded = threaded, .io = io, .dir = dir, .cred_path = cred_path };
	}

	fn deinit(self: *Harness) void {
		std.Io.Dir.cwd().deleteTree(self.io, self.dir) catch {};
		self.gpa.free(self.cred_path);
		self.gpa.free(self.dir);
		self.threaded.deinit();
	}

	/// A conf naming the temp cred file, one gitlab provider on git.example.com
	/// (http), with an instance grant carrying every gitlab cap.
	fn confJson(self: *Harness) ![]u8 {
		return std.fmt.allocPrint(self.gpa,
			\\{{"version":1,"providers":[{{"host":"git.example.com","plugin":"gitlab","scheme":"http","insecure":false,
			\\"cred_file":"{s}","cred_format":"raw","git_user":"oauth2",
			\\"grants":[{{"id":"gg-inst","scope":"instance","caps":["git-read","git-write","issues","mr"]}}]}}]}}
		, .{self.cred_path});
	}
};

fn writeFile(io: std.Io, path: []const u8, bytes: []const u8) !void {
	const cwd = std.Io.Dir.cwd();
	const f = try cwd.createFile(io, path, .{ .truncate = true });
	defer f.close(io);
	var wbuf: [4096]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

/// Drive one connection: build a static store over `gen`, run serveConnection
/// with `request_bytes` as the client stream and `transport` as the upstream,
/// capturing the response and the audit line. Caller owns both returned slices.
const Run = struct {
	response: []u8,
	audit: []u8,
	fn deinit(self: *Run, gpa: std.mem.Allocator) void {
		gpa.free(self.response);
		gpa.free(self.audit);
	}
};

fn serve(gpa: std.mem.Allocator, io: std.Io, gen: *conf.Generation, transport: *const upstream.Transport, request_bytes: []const u8) !Run {
	return serveClocked(gpa, io, gen, transport, request_bytes, upstream.nowMs);
}

/// serve() on a substituted clock (the C.4 deadline tests jump it).
fn serveClocked(gpa: std.mem.Allocator, io: std.Io, gen: *conf.Generation, transport: *const upstream.Transport, request_bytes: []const u8, now_ms: *const fn (io: std.Io) i64) !Run {
	var store = conf.Store.initStatic(gpa, io, gen);
	defer store.deinit();
	var audit = std.Io.Writer.Allocating.init(gpa);
	defer audit.deinit();
	var ctx = main.Context{
		.gpa = gpa,
		.io = io,
		.store = &store,
		.transport = transport,
		.audit = &audit.writer,
		.now_ms = now_ms,
	};
	var in = std.Io.Reader.fixed(request_bytes);
	var out = std.Io.Writer.Allocating.init(gpa);
	defer out.deinit();
	main.serveConnection(&ctx, &in, &out.writer);
	return .{
		.response = try gpa.dupe(u8, out.written()),
		.audit = try gpa.dupe(u8, audit.written()),
	};
}

fn gitReq(comptime target: []const u8) []const u8 {
	return "GET " ++ target ++ " HTTP/1.1\r\n" ++
		"Host: git.example.com\r\n" ++
		"X-Cogbox-Host: git.example.com\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"X-Cogbox-Proto: https\r\n" ++
		"Accept: */*\r\n\r\n";
}

test "e2e: an allowed API read injects Bearer, strips the inbound auth, reaches the fake upstream once" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	// serve() takes ownership via the static store's deinit.

	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nset-cookie: s=1\r\n\r\nok"});
	defer fake.deinit();

	const req = "GET /api/v4/user HTTP/1.1\r\n" ++
		"Host: git.example.com\r\n" ++
		"X-Cogbox-Host: git.example.com\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"Authorization: Bearer GUEST-STUB\r\n" ++
		"Accept: */*\r\n\r\n";
	var run = try serve(gpa, h.io, gen, fake.t(), req);
	defer run.deinit(gpa);

	try t.expect(std.mem.indexOf(u8, run.response, "200 OK") != null);
	// Set-Cookie was stripped from the downstream response.
	try t.expect(std.mem.indexOf(u8, run.response, "set-cookie") == null);
	try t.expectEqual(@as(usize, 1), fake.calls);
	const up_req = fake.captured.items[0];
	try t.expect(std.mem.startsWith(u8, up_req, "GET /api/v4/user HTTP/1.1\r\n"));
	// the OWNER token, not the guest stub; the inbound Authorization is gone
	try t.expect(std.mem.indexOf(u8, up_req, "authorization: Bearer glpat-FAKEFAKEFAKE\r\n") != null);
	try t.expect(std.mem.indexOf(u8, up_req, "GUEST-STUB") == null);
	// audit is token-free
	try t.expect(std.mem.indexOf(u8, run.audit, "glpat") == null);
	try t.expect(std.mem.indexOf(u8, run.audit, "decision=allow") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "route=api-user") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "method=GET") != null);
}

test "e2e: a git clone injects Basic and re-emits the canonical .git path" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"});
	defer fake.deinit();

	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/grp/proj/info/refs?service=git-upload-pack"));
	defer run.deinit(gpa);
	try t.expectEqual(@as(usize, 1), fake.calls);
	const up_req = fake.captured.items[0];
	try t.expect(std.mem.startsWith(u8, up_req, "GET /grp/proj.git/info/refs?service=git-upload-pack HTTP/1.1\r\n"));
	// base64("oauth2:glpat-FAKEFAKEFAKE")
	try t.expect(std.mem.indexOf(u8, up_req, "authorization: Basic b2F1dGgyOmdscGF0LUZBS0VGQUtFRkFLRQ==\r\n") != null);
}

test "e2e: a gate-1 deny (unrouted) NEVER dials the upstream" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	var refusing = upstream.RefusingTransport{};
	var run = try serve(gpa, h.io, gen, refusing.t(), gitReq("/api/v4/projects/1234/access_tokens"));
	defer run.deinit(gpa);
	try t.expect(std.mem.indexOf(u8, run.response, "403") != null);
	try t.expectEqual(@as(usize, 0), refusing.calls); // the whole point
	try t.expect(std.mem.indexOf(u8, run.audit, "decision=deny") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "gate=1") != null);
	// the raw path never reaches the audit line by default
	try t.expect(std.mem.indexOf(u8, run.audit, "access_tokens") == null);
}

test "e2e: a framing refusal (CL+TE) is a 400 with no upstream and the connection closes" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var refusing = upstream.RefusingTransport{};
	const req = "POST /api/v4/projects/1234/issues HTTP/1.1\r\n" ++
		"Host: git.example.com\r\nX-Cogbox-Host: git.example.com\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
	var run = try serve(gpa, h.io, gen, refusing.t(), req);
	defer run.deinit(gpa);
	try t.expect(std.mem.indexOf(u8, run.response, "400") != null);
	try t.expect(std.mem.indexOf(u8, run.response, "connection: close") != null);
	try t.expectEqual(@as(usize, 0), refusing.calls);
}

test "e2e: a forged/duplicated X-Cogbox-Host and a Host!=X-Cogbox-Host are refused" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var refusing = upstream.RefusingTransport{};

	const forged = "GET /api/v4/user HTTP/1.1\r\nHost: git.example.com\r\n" ++
		"X-Cogbox-Host: git.example.com\r\nX-Cogbox-Host: evil.example.com\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n";
	var r1 = try serve(gpa, h.io, gen, refusing.t(), forged);
	defer r1.deinit(gpa);
	try t.expect(std.mem.indexOf(u8, r1.response, "400") != null);

	const mismatch = "GET /api/v4/user HTTP/1.1\r\nHost: evil.example.com\r\n" ++
		"X-Cogbox-Host: git.example.com\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n";
	var r2 = try serve(gpa, h.io, gen, refusing.t(), mismatch);
	defer r2.deinit(gpa);
	try t.expect(std.mem.indexOf(u8, r2.response, "400") != null);
	try t.expectEqual(@as(usize, 0), refusing.calls);
}

test "e2e: a 3xx is returned verbatim and NOT followed" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var fake = upstream.FakeTransport.init(gpa, &.{
		"HTTP/1.1 302 Found\r\nlocation: http://elsewhere.example.com/x\r\nset-cookie: s=1\r\ncontent-length: 0\r\n\r\n",
	});
	defer fake.deinit();
	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/user"));
	defer run.deinit(gpa);
	try t.expect(std.mem.indexOf(u8, run.response, "302") != null);
	try t.expect(std.mem.indexOf(u8, run.response, "location: http://elsewhere.example.com/x") != null);
	try t.expect(std.mem.indexOf(u8, run.response, "set-cookie") == null); // stripped even on a redirect
	try t.expectEqual(@as(usize, 1), fake.calls); // the follow-up was never issued
}

test "e2e: torn conf denies in both directions, no upstream" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	var refusing = upstream.RefusingTransport{};

	// hosts-ahead-of-conf: the host is not in the (empty) conf -> no-policy 403.
	const empty = try conf.parseGeneration(gpa, h.io, "{\"version\":1,\"providers\":[]}", 1, .skip, null);
	var r1 = try serve(gpa, h.io, empty, refusing.t(), gitReq("/api/v4/user"));
	defer r1.deinit(gpa);
	try t.expect(std.mem.indexOf(u8, r1.response, "403") != null);

	// conf-ahead-of-grants: an entry with zero grants -> no_grant 403.
	const zero = try conf.parseGeneration(gpa, h.io,
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http",
		\\"cred_file":"/x","git_user":"oauth2","grants":[]}]}
	, 1, .skip, null);
	var r2 = try serve(gpa, h.io, zero, refusing.t(), gitReq("/api/v4/user"));
	defer r2.deinit(gpa);
	try t.expect(std.mem.indexOf(u8, r2.response, "403") != null);
	try t.expectEqual(@as(usize, 0), refusing.calls);
}

test "e2e: two hosts back-to-back on one pooled connection route independently" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	// A two-provider conf: two hosts, both gitlab, same cred file for the test.
	const cj = try std.fmt.allocPrint(gpa,
		\\{{"version":1,"providers":[
		\\{{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"{s}","git_user":"oauth2",
		\\"grants":[{{"id":"gg-a","scope":"instance","caps":["issues","mr"]}}]}},
		\\{{"host":"api.example.com","plugin":"gitlab","scheme":"http","cred_file":"{s}","git_user":"oauth2",
		\\"grants":[{{"id":"gg-b","scope":"instance","caps":["git-write"]}}]}}
		\\]}}
	, .{ h.cred_path, h.cred_path });
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	var fake = upstream.FakeTransport.init(gpa, &.{
		"HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\nA",
		"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n", // never reached; the 2nd denies at gate 2
	});
	defer fake.deinit();

	// Request 1: git.example.com, an ambient read -> allowed. Request 2:
	// api.example.com, whose grant is git-write only, asking for that host's
	// ISSUES tracker: `issues:read` is absent, so gate 2 denies with
	// cap_missing and the upstream is NOT dialed for it. (The ambient two are
	// reachable by ANY capability under v2 -- they name the owner's identity
	// and the server version, nothing resource-scoped -- so a resource route is
	// what separates the two hosts' policies here.)
	const two = "GET /api/v4/user HTTP/1.1\r\nHost: git.example.com\r\n" ++
		"X-Cogbox-Host: git.example.com\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n" ++
		"GET /api/v4/projects/1234/issues HTTP/1.1\r\nHost: api.example.com\r\n" ++
		"X-Cogbox-Host: api.example.com\r\nX-Cogbox-Vetted: 10.0.0.6:443\r\nConnection: close\r\n\r\n";
	var run = try serve(gpa, h.io, gen, fake.t(), two);
	defer run.deinit(gpa);
	// exactly one upstream dial (the first request); the second denied at gate 2
	try t.expectEqual(@as(usize, 1), fake.calls);
	// two audit lines, one allow (git.example.com) and one deny (api.example.com)
	try t.expect(std.mem.indexOf(u8, run.audit, "host=git.example.com decision=allow") == null); // fields are spaced differently
	try t.expect(std.mem.indexOf(u8, run.audit, "host=git.example.com") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "host=api.example.com") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "reason=cap_missing") != null);
}

test "e2e: an unreadable cred file is a 403, never a fallthrough" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	// point the conf at a cred file that does not exist
	const cj = try std.fmt.allocPrint(gpa,
		\\{{"version":1,"providers":[{{"host":"git.example.com","plugin":"gitlab","scheme":"http",
		\\"cred_file":"{s}/nonesuch","git_user":"oauth2",
		\\"grants":[{{"id":"gg","scope":"instance","caps":["issues","mr"]}}]}}]}}
	, .{h.dir});
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"});
	defer fake.deinit();
	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/user"));
	defer run.deinit(gpa);
	try t.expect(std.mem.indexOf(u8, run.response, "403") != null);
	// the cred was unreadable, so the upstream was never dialed with it
	try t.expectEqual(@as(usize, 0), fake.calls);
	try t.expect(std.mem.indexOf(u8, run.audit, "cred-unavailable") != null);
}

test "e2e: a HEAD whose origin declares content-length is relayed head-only, never crashing the relay (B1)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	// The origin's HEAD answer: a 200 with the GET body's size and NO body.
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 40\r\netag: \"abc\"\r\n\r\n"});
	defer fake.deinit();
	const req = "HEAD /api/v4/version HTTP/1.1\r\n" ++
		"Host: git.example.com\r\nX-Cogbox-Host: git.example.com\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n";
	var run = try serve(gpa, h.io, gen, fake.t(), req);
	defer run.deinit(gpa);

	try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 200 OK\r\n"));
	// the origin's content-length rides through as a plain header (the GET
	// body's size, RFC 9110 §9.3.2), no body follows, no chunk terminator
	try t.expect(std.mem.indexOf(u8, run.response, "content-length: 40\r\n") != null);
	try t.expect(std.mem.indexOf(u8, run.response, "etag: \"abc\"\r\n") != null);
	try t.expect(std.mem.indexOf(u8, run.response, "transfer-encoding") == null);
	// the response is EXACTLY the head: nothing after the first blank line
	try t.expectEqual(run.response.len, std.mem.indexOf(u8, run.response, "\r\n\r\n").? + 4);
	try t.expect(std.mem.indexOf(u8, run.audit, "decision=allow") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "method=HEAD") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "status=200") != null);
}

test "e2e: a 304 carrying content-length is relayed head-only (B1)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 304 Not Modified\r\ncontent-length: 40\r\netag: \"abc\"\r\n\r\n"});
	defer fake.deinit();
	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/user"));
	defer run.deinit(gpa);
	try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 304 "));
	try t.expect(std.mem.indexOf(u8, run.response, "content-length: 40\r\n") != null);
	// exactly the head: no body, no chunk terminator
	try t.expectEqual(run.response.len, std.mem.indexOf(u8, run.response, "\r\n\r\n").? + 4);
}

test "e2e: an upstream 1xx is a 502 to the client, never relayed (B1)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"});
	defer fake.deinit();
	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/user"));
	defer run.deinit(gpa);
	try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 502 "));
	try t.expect(std.mem.indexOf(u8, run.response, "100 Continue") == null);
	try t.expect(std.mem.indexOf(u8, run.audit, "reason=InformationalResponse") != null);
}

test "e2e: a content-length upstream body that ends early aborts the connection, never asserting (B1's sibling)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	// declares 10, delivers 3, then the origin is gone
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nabc"});
	defer fake.deinit();
	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/user"));
	defer run.deinit(gpa);
	// the head went out with the origin's length, the 3 bytes followed, then
	// the connection was cut -- a short body under a full-length header is
	// how the client learns of the truncation
	try t.expect(std.mem.indexOf(u8, run.response, "content-length: 10\r\n") != null);
	try t.expect(std.mem.endsWith(u8, run.response, "\r\n\r\nabc"));
	try t.expect(std.mem.indexOf(u8, run.audit, "reason=upstream-truncated") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "bytes_out=3") != null);
}

test "e2e: a duplicate Content-Type is a 400 with no upstream (the 415-bypass, S4)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var refusing = upstream.RefusingTransport{};
	const req = "POST /api/v4/projects/1234/issues HTTP/1.1\r\n" ++
		"Host: git.example.com\r\nX-Cogbox-Host: git.example.com\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"Content-Type: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\n" ++
		"Content-Length: 14\r\n\r\n_method=DELETE";
	var run = try serve(gpa, h.io, gen, refusing.t(), req);
	defer run.deinit(gpa);
	try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 400 "));
	try t.expect(std.mem.indexOf(u8, run.response, "connection: close") != null);
	try t.expectEqual(@as(usize, 0), refusing.calls);
	try t.expect(std.mem.indexOf(u8, run.audit, "reason=duplicate_header") != null);
}

test "e2e: a chunked request body carrying a trailer is refused after the relay (S9)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 201 Created\r\ncontent-length: 2\r\n\r\nok"});
	defer fake.deinit();
	const req = "POST /api/v4/projects/1234/issues HTTP/1.1\r\n" ++
		"Host: git.example.com\r\nX-Cogbox-Host: git.example.com\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" ++
		"5\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n";
	var run = try serve(gpa, h.io, gen, fake.t(), req);
	defer run.deinit(gpa);
	// the body reached the origin re-framed (a framing refusal can only be
	// decided once the chunked body has ended), but the client gets a 400 and
	// the connection closes; the origin's 201 is never relayed
	try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 400 "));
	try t.expect(std.mem.indexOf(u8, run.response, "201") == null);
	try t.expect(std.mem.indexOf(u8, run.audit, "reason=trailers") != null);
	// and the same body WITHOUT a trailer is fine
	const clean = "POST /api/v4/projects/1234/issues HTTP/1.1\r\n" ++
		"Host: git.example.com\r\nX-Cogbox-Host: git.example.com\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" ++
		"5\r\nhello\r\n0\r\n\r\n";
	var fake2 = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 201 Created\r\ncontent-length: 2\r\n\r\nok"});
	defer fake2.deinit();
	const gen2 = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var run2 = try serve(gpa, h.io, gen2, fake2.t(), clean);
	defer run2.deinit(gpa);
	try t.expect(std.mem.startsWith(u8, run2.response, "HTTP/1.1 201 "));
	// the body was re-framed from scratch (content-length, never the guest's chunks)
	try t.expect(std.mem.indexOf(u8, fake2.captured.items[0], "transfer-encoding: chunked\r\n") != null);
	try t.expect(std.mem.endsWith(u8, fake2.captured.items[0], "5\r\nhello\r\n0\r\n\r\n"));
}

test "e2e: a raw CR in the request line is refused at framing (S7)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var refusing = upstream.RefusingTransport{};
	const req = "GET /api/v4/projects/1234/issues?a=b\rc HTTP/1.1\r\n" ++
		"Host: git.example.com\r\nX-Cogbox-Host: git.example.com\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n";
	var run = try serve(gpa, h.io, gen, refusing.t(), req);
	defer run.deinit(gpa);
	try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 400 "));
	try t.expectEqual(@as(usize, 0), refusing.calls);
	// and the percent-encoded twin is refused by the query parser, with no upstream either
	const enc = try serve(gpa, h.io, try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null), refusing.t(), gitReq("/api/v4/projects/1234/issues?a=b%0Dc"));
	var enc_run = enc;
	defer enc_run.deinit(gpa);
	try t.expect(std.mem.startsWith(u8, enc_run.response, "HTTP/1.1 400 "));
	try t.expect(std.mem.indexOf(u8, enc_run.audit, "reason=query_invalid") != null);
	try t.expectEqual(@as(usize, 0), refusing.calls);
}

test "e2e: the audit line meters bytes_in and dur_ms and names the plugin (N1/N7)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 201 Created\r\ncontent-length: 2\r\n\r\nok"});
	defer fake.deinit();
	const req = "POST /api/v4/projects/1234/issues HTTP/1.1\r\n" ++
		"Host: git.example.com\r\nX-Cogbox-Host: git.example.com\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"Content-Type: application/json\r\nContent-Length: 5\r\n\r\nhello";
	var run = try serve(gpa, h.io, gen, fake.t(), req);
	defer run.deinit(gpa);
	try t.expect(std.mem.indexOf(u8, run.audit, " plugin=gitlab ") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, " bytes_in=5 ") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, " bytes_out=2 ") != null);
	// dur_ms is measured (a number), not the literal 0 placeholder
	const at = std.mem.indexOf(u8, run.audit, " dur_ms=").?;
	const tail = run.audit[at + " dur_ms=".len ..];
	try t.expect(tail.len > 0 and tail[0] >= '0' and tail[0] <= '9');
	// no path field by default
	try t.expect(std.mem.indexOf(u8, run.audit, " path=") == null);

	// a pre-entry deny (framing) carries plugin=- : no entry was selected
	var refusing = upstream.RefusingTransport{};
	const gen2 = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var r2 = try serve(gpa, h.io, gen2, refusing.t(), "GET /x HTTP/1.1\r\nHost: git.example.com\r\n\r\n");
	defer r2.deinit(gpa);
	try t.expect(std.mem.indexOf(u8, r2.audit, " plugin=- ") != null);
}

test "e2e: COGBOX_L7_AUTH_DEBUG_PATH adds a quoted path with query values dropped except service (N5)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var store = conf.Store.initStatic(gpa, h.io, gen);
	defer store.deinit();
	var audit = std.Io.Writer.Allocating.init(gpa);
	defer audit.deinit();
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"});
	defer fake.deinit();
	var ctx = main.Context{ .gpa = gpa, .io = h.io, .store = &store, .transport = fake.t(), .audit = &audit.writer, .debug_path = true };
	var in = std.Io.Reader.fixed(gitReq("/grp/proj/info/refs?service=git-upload-pack&foo=SECRETVALUE"));
	var out = std.Io.Writer.Allocating.init(gpa);
	defer out.deinit();
	main.serveConnection(&ctx, &in, &out.writer);
	try t.expect(std.mem.indexOf(u8, audit.written(), " path=\"/grp/proj/info/refs?service=git-upload-pack&foo\"") != null);
	try t.expect(std.mem.indexOf(u8, audit.written(), "SECRETVALUE") == null);
}

test "e2e: the empty-bundle https refusal is a 502 and logs once per generation (N6)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	// an https entry parsed with the bundle SKIPPED -> empty bundle -> refused
	const cj = try std.fmt.allocPrint(gpa,
		\\{{"version":1,"providers":[{{"host":"git.example.com","plugin":"gitlab","scheme":"https","insecure":false,
		\\"cred_file":"{s}","git_user":"oauth2","grants":[{{"id":"gg","scope":"instance","caps":["issues","mr"]}}]}}]}}
	, .{h.cred_path});
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	_ = gen.refs.fetchAdd(1, .monotonic); // hold it past serve()'s store teardown
	defer {
		gen.arena.deinit();
		gpa.destroy(gen);
	}
	var refusing = upstream.RefusingTransport{};
	try t.expect(!gen.https_refusal_logged.load(.acquire));
	var run = try serve(gpa, h.io, gen, refusing.t(), gitReq("/api/v4/user"));
	defer run.deinit(gpa);
	try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 502 "));
	try t.expect(std.mem.indexOf(u8, run.audit, "reason=HttpsRefused") != null);
	try t.expectEqual(@as(usize, 0), refusing.calls); // refused BEFORE any dial
	try t.expect(gen.https_refusal_logged.load(.acquire)); // the one-shot fired
	// the flag is one-shot: a second refusal on the same generation is silent
	try t.expect(!gen.noteHttpsRefusal("git.example.com"));
}

var arm_log: [16]i32 = undefined;
var arm_n: usize = 0;
fn recordArm(fd: c_int, secs: i32) void {
	_ = fd;
	if (arm_n < arm_log.len) {
		arm_log[arm_n] = secs;
		arm_n += 1;
	}
}

test "e2e: the inbound socket is re-armed per phase -- head bound, idle bound for the relay, head bound again (S6 pin)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var store = conf.Store.initStatic(gpa, h.io, gen);
	defer store.deinit();
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nPACK"});
	defer fake.deinit();
	arm_n = 0;
	var ctx = main.Context{ .gpa = gpa, .io = h.io, .store = &store, .transport = fake.t(), .arm_socket = recordArm };
	var in = std.Io.Reader.fixed(gitReq("/api/v4/projects/1234/repository/archive.tar.gz"));
	var out = std.Io.Writer.Allocating.init(gpa);
	defer out.deinit();
	main.serveConnectionOn(&ctx, &in, &out.writer, 7); // 7: a placeholder fd the recorder never touches
	try t.expect(std.mem.indexOf(u8, out.written(), "PACK") != null);
	// head (10s) -> relay idle (60s) -> the next head (10s), then EOF
	try t.expectEqualSlices(i32, &.{ main.read_header_timeout_secs, upstream.body_idle_timeout_secs, main.read_header_timeout_secs }, arm_log[0..arm_n]);
	// the upstream side was re-armed to the idle bound once its head came in
	try t.expectEqualSlices(i32, &.{upstream.body_idle_timeout_secs}, fake.arms.items);
}

test "e2e: a body-bearing pack request is relayed under the idle bound in BOTH directions (S6 pin, request direction)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var store = conf.Store.initStatic(gpa, h.io, gen);
	defer store.deinit();
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"});
	defer fake.deinit();
	arm_n = 0;
	var ctx = main.Context{ .gpa = gpa, .io = h.io, .store = &store, .transport = fake.t(), .arm_socket = recordArm };
	// git push: the addon streams the pack (a pack endpoint sets
	// flow.request.stream), so any gap > 10 s in it used to trip the head bound
	const req = "POST /grp/proj.git/git-receive-pack HTTP/1.1\r\n" ++
		"Host: git.example.com\r\n" ++
		"X-Cogbox-Host: git.example.com\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"X-Cogbox-Proto: https\r\n" ++
		"Content-Type: application/x-git-receive-pack-request\r\n" ++
		"Content-Length: 4\r\n\r\nPACK";
	var in = std.Io.Reader.fixed(req);
	var out = std.Io.Writer.Allocating.init(gpa);
	defer out.deinit();
	main.serveConnectionOn(&ctx, &in, &out.writer, 7);
	try t.expect(std.mem.startsWith(u8, out.written(), "HTTP/1.1 200 OK\r\n"));
	try t.expect(std.mem.endsWith(u8, fake.captured.items[0], "\r\n\r\nPACK"));
	// inbound: head (10s) -> the request-body relay (idle 60s) -> the response
	// relay (idle 60s) -> the next head (10s), then EOF
	try t.expectEqualSlices(i32, &.{ main.read_header_timeout_secs, upstream.body_idle_timeout_secs, upstream.body_idle_timeout_secs, main.read_header_timeout_secs }, arm_log[0..arm_n]);
	// upstream: the upload (idle 60s) -> the head wait (30s) -> the relay (idle 60s)
	try t.expectEqualSlices(i32, &.{ upstream.body_idle_timeout_secs, upstream.response_head_timeout_secs, upstream.body_idle_timeout_secs }, fake.arms.items);
}

// The C.4 clock seam: a clock that jumps a fixed step per reading, so a
// deadline is crossed by counting, never by sleeping.
var jump_clock_ms: i64 = 0;
var jump_clock_step_ms: i64 = 0;
fn jumpClock(io: std.Io) i64 {
	_ = io;
	jump_clock_ms += jump_clock_step_ms;
	return jump_clock_ms;
}

test "e2e: the C.4 total deadline covers the request-body upload on an API route, and only there (S6, upload leg)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);

	// A body two relay slices long with its tail marked, so a refused upload
	// is told apart from a relayed one by what the fake origin captured.
	const body = ("x" ** (2 * upstream.relay_chunk)) ++ "TAIL";
	const api_req = std.fmt.comptimePrint("POST /api/v4/projects/1234/issues HTTP/1.1\r\n" ++
		"Host: git.example.com\r\nX-Cogbox-Host: git.example.com\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"Content-Type: application/json\r\nContent-Length: {d}\r\n\r\n", .{body.len}) ++ body;
	const pack_req = std.fmt.comptimePrint("POST /grp/proj.git/git-receive-pack HTTP/1.1\r\n" ++
		"Host: git.example.com\r\nX-Cogbox-Host: git.example.com\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"Content-Type: application/x-git-receive-pack-request\r\nContent-Length: {d}\r\n\r\n", .{body.len}) ++ body;

	// Every reading jumps past the whole budget: the first check, after the
	// first upload slice, is already late. Before this pin the upload had only
	// the 60 s IDLE bound, so a byte every 59 s held an inflight slot forever.
	jump_clock_ms = 0;
	jump_clock_step_ms = main.api_relay_total_ms + 1;
	{
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 201 Created\r\ncontent-length: 0\r\n\r\n"});
		defer fake.deinit();
		var run = try serveClocked(gpa, h.io, gen, fake.t(), api_req, jumpClock);
		defer run.deinit(gpa);
		// no response head was out, so the guest is told and the connection closes
		try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 408 "));
		try t.expect(std.mem.indexOf(u8, run.response, "connection: close\r\n") != null);
		try t.expect(std.mem.indexOf(u8, run.audit, " decision=deny ") != null);
		try t.expect(std.mem.indexOf(u8, run.audit, " reason=RelayDeadline ") != null);
		try t.expect(std.mem.indexOf(u8, run.audit, " status=408 ") != null);
		// the origin got the head and at most a slice, never the whole body
		try t.expectEqual(@as(usize, 1), fake.calls);
		try t.expect(std.mem.indexOf(u8, fake.captured.items[0], "TAIL") == null);
	}
	// The same clock on a STREAM route: no deadline, the whole pack goes up.
	jump_clock_ms = 0;
	{
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"});
		defer fake.deinit();
		var run = try serveClocked(gpa, h.io, gen, fake.t(), pack_req, jumpClock);
		defer run.deinit(gpa);
		try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 200 OK\r\n"));
		try t.expect(std.mem.endsWith(u8, fake.captured.items[0], "TAIL"));
		try t.expect(std.mem.indexOf(u8, run.audit, " decision=allow ") != null);
	}
	// And the API route under a clock that stands still: the sliced upload
	// completes and the origin sees every byte.
	jump_clock_ms = 0;
	jump_clock_step_ms = 0;
	{
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 201 Created\r\ncontent-length: 0\r\n\r\n"});
		defer fake.deinit();
		var run = try serveClocked(gpa, h.io, gen, fake.t(), api_req, jumpClock);
		defer run.deinit(gpa);
		try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 201 "));
		try t.expect(std.mem.endsWith(u8, fake.captured.items[0], "TAIL"));
		try t.expect(std.mem.indexOf(u8, run.audit, std.fmt.comptimePrint(" bytes_in={d} ", .{body.len})) != null);
	}
}

test "e2e: an origin head the relay cannot carry whole is a 502 to the guest, never a partial relay (N3)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	// multi-valued headers relay whole: both Vary copies reach the guest
	{
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		var fake = upstream.FakeTransport.init(gpa, &.{
			"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nvary: Accept-Encoding\r\nvary: Cookie\r\n\r\nok",
		});
		defer fake.deinit();
		var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/user"));
		defer run.deinit(gpa);
		try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 200 OK\r\n"));
		try t.expect(std.mem.indexOf(u8, run.response, "vary: Accept-Encoding\r\n") != null);
		try t.expect(std.mem.indexOf(u8, run.response, "vary: Cookie\r\n") != null);
		try t.expect(std.mem.indexOf(u8, run.audit, "decision=allow") != null);
	}
	// a header with a bare LF, a duplicated singleton: the exchange is refused
	// -- a 502 the audit names, and not one origin header line (good or bad)
	// reaches the guest
	const bad = [_][]const u8{
		"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nvary: Accept-Encoding\r\nx-split: a\nb\r\n\r\nok",
		"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nvary: Accept-Encoding\r\ncontent-type: text/plain\r\ncontent-type: text/html\r\n\r\nok",
	};
	for (bad) |script| {
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		var fake = upstream.FakeTransport.init(gpa, &.{script});
		defer fake.deinit();
		var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/user"));
		defer run.deinit(gpa);
		try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 502 "));
		try t.expect(std.mem.indexOf(u8, run.response, "vary:") == null);
		try t.expect(std.mem.indexOf(u8, run.response, "x-split") == null);
		try t.expect(std.mem.indexOf(u8, run.response, "a\nb") == null);
		try t.expect(std.mem.indexOf(u8, run.response, "text/") == null);
		try t.expect(std.mem.indexOf(u8, run.response, "\r\n\r\nok") == null);
		try t.expect(std.mem.indexOf(u8, run.audit, "reason=BadResponseHeader") != null);
		try t.expect(std.mem.indexOf(u8, run.audit, "decision=deny") != null);
		try t.expect(std.mem.indexOf(u8, run.audit, "status=502") != null);
	}
}

test "e2e: a large response body streams without being buffered whole" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	// A 40 KiB body -- larger than the response BodyWriter buffer (16 KiB), so
	// it must drain downstream mid-stream rather than after the whole read.
	const body_len = 40 * 1024;
	var script = std.Io.Writer.Allocating.init(gpa);
	defer script.deinit();
	try script.writer.print("HTTP/1.1 200 OK\r\ncontent-length: {d}\r\n\r\n", .{body_len});
	try script.writer.splatByteAll('Z', body_len);

	var fake = upstream.FakeTransport.init(gpa, &.{script.written()});
	defer fake.deinit();

	// Instrument the downstream sink: on its FIRST drain, record how far the
	// upstream script reader has been consumed. Streaming (not buffering)
	// means the first downstream bytes leave BEFORE the last upstream byte is
	// read -- a structural assertion, not a flaky timing one.
	var rec = RecordingWriter.init(gpa, &fake.reader);
	defer rec.deinit();

	var store = conf.Store.initStatic(gpa, h.io, gen);
	defer store.deinit();
	var ctx = main.Context{ .gpa = gpa, .io = h.io, .store = &store, .transport = fake.t() };
	var in = std.Io.Reader.fixed(gitReq("/api/v4/projects/1234/repository/archive.tar.gz"));
	main.serveConnection(&ctx, &in, &rec.writer);

	try t.expect(rec.first_drain_upstream_seek != null);
	// the upstream was not fully consumed when the first downstream bytes left
	try t.expect(rec.first_drain_upstream_seek.? < script.written().len);
	// and the whole body round-tripped intact
	try t.expectEqual(@as(usize, body_len), std.mem.count(u8, rec.sink.items, "Z"));
}

/// A downstream sink with a tiny buffer that records, on its first drain, how
/// far the upstream reader had been consumed.
const RecordingWriter = struct {
	gpa: std.mem.Allocator,
	upstream_reader: *std.Io.Reader,
	sink: std.ArrayList(u8) = .empty,
	first_drain_upstream_seek: ?usize = null,
	buf: [64]u8 = undefined,
	writer: std.Io.Writer = undefined,

	fn init(gpa: std.mem.Allocator, upstream_reader: *std.Io.Reader) RecordingWriter {
		var self = RecordingWriter{ .gpa = gpa, .upstream_reader = upstream_reader };
		self.writer = .{ .vtable = &.{ .drain = drain }, .buffer = &self.buf, .end = 0 };
		return self;
	}
	fn deinit(self: *RecordingWriter) void {
		self.sink.deinit(self.gpa);
	}
	fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
		const self: *RecordingWriter = @alignCast(@fieldParentPtr("writer", w));
		if (self.first_drain_upstream_seek == null) self.first_drain_upstream_seek = self.upstream_reader.seek;
		self.sink.appendSlice(self.gpa, w.buffered()) catch return error.WriteFailed;
		w.end = 0;
		var total: usize = 0;
		for (data[0 .. data.len - 1]) |d| {
			self.sink.appendSlice(self.gpa, d) catch return error.WriteFailed;
			total += d.len;
		}
		const pattern = data[data.len - 1];
		var i: usize = 0;
		while (i < splat) : (i += 1) {
			self.sink.appendSlice(self.gpa, pattern) catch return error.WriteFailed;
			total += pattern.len;
		}
		return total;
	}
};

test "e2e: Expect: 100-continue on a bodiless request is ignored, never asserting (B: readerExpectNone)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const variants = [_][]const u8{
		// bare, on a GET
		"GET /api/v4/user HTTP/1.1\r\nHost: git.example.com\r\nX-Cogbox-Host: git.example.com\r\n" ++
			"X-Cogbox-Vetted: 10.0.0.5:443\r\nExpect: 100-continue\r\n\r\n",
		// duplicated -- the form mitmproxy folds to "x, 100-continue", does NOT
		// answer, and forwards both lines; std's Head.parse keeps the LAST copy
		"GET /api/v4/user HTTP/1.1\r\nHost: git.example.com\r\nX-Cogbox-Host: git.example.com\r\n" ++
			"X-Cogbox-Vetted: 10.0.0.5:443\r\nExpect: x\r\nExpect: 100-continue\r\n\r\n",
		// a body method that declares NO body
		"POST /api/v4/projects/1234/issues HTTP/1.1\r\nHost: git.example.com\r\nX-Cogbox-Host: git.example.com\r\n" ++
			"X-Cogbox-Vetted: 10.0.0.5:443\r\nContent-Type: application/json\r\nContent-Length: 0\r\nExpect: 100-continue\r\n\r\n",
	};
	for (variants) |req| {
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"});
		defer fake.deinit();
		var run = try serve(gpa, h.io, gen, fake.t(), req);
		defer run.deinit(gpa);
		// served normally: the origin's answer relayed, no interim response
		try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 200 OK\r\n"));
		try t.expect(std.mem.indexOf(u8, run.response, "100 Continue") == null);
		try t.expectEqual(@as(usize, 1), fake.calls);
		// the expectation itself is never forwarded (not in the allowlist)
		try t.expect(std.ascii.indexOfIgnoreCase(fake.captured.items[0], "expect") == null);
		try t.expect(std.mem.indexOf(u8, run.audit, "decision=allow") != null);
	}
	// an UNKNOWN expectation is still a 417, with no upstream
	var refusing = upstream.RefusingTransport{};
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var run = try serve(gpa, h.io, gen, refusing.t(), "GET /api/v4/user HTTP/1.1\r\nHost: git.example.com\r\n" ++
		"X-Cogbox-Host: git.example.com\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\nExpect: x\r\n\r\n");
	defer run.deinit(gpa);
	try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 417 "));
	try t.expectEqual(@as(usize, 0), refusing.calls);
}

test "e2e: a 204 never relays the origin's content-length (RFC 9110 §8.6), head-only (N6)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	// a non-conforming origin: 204 WITH content-length
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\netag: \"abc\"\r\n\r\n"});
	defer fake.deinit();
	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/user"));
	defer run.deinit(gpa);
	try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 204 "));
	try t.expect(std.ascii.indexOfIgnoreCase(run.response, "content-length") == null);
	try t.expect(std.mem.indexOf(u8, run.response, "etag: \"abc\"\r\n") != null);
	// exactly the head: no body, no chunk terminator
	try t.expectEqual(run.response.len, std.mem.indexOf(u8, run.response, "\r\n\r\n").? + 4);
	try t.expect(std.mem.indexOf(u8, run.audit, "status=204") != null);
}

/// An inbound stream that delivers its bytes in 1 KiB pieces into a
/// production-sized (32 KiB) reader buffer, so std's own head bound
/// (max_head_len) is what trips on an oversize head -- with Io.Reader.fixed
/// the whole head is already buffered and only handleRequest's copy guard runs.
const TrickleReader = struct {
	src: []const u8,
	pos: usize = 0,
	buf: [32 * 1024]u8 = undefined,
	interface: std.Io.Reader = undefined,

	fn init(self: *TrickleReader) void {
		self.interface = .{ .vtable = &.{ .stream = stream }, .buffer = &self.buf, .seek = 0, .end = 0 };
	}
	fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
		const self: *TrickleReader = @alignCast(@fieldParentPtr("interface", r));
		if (self.pos >= self.src.len) return error.EndOfStream;
		const dest = limit.slice(w.writableSliceGreedy(1) catch return error.WriteFailed);
		const n: usize = @min(dest.len, 1024, self.src.len - self.pos);
		@memcpy(dest[0..n], self.src[self.pos .. self.pos + n]);
		self.pos += n;
		w.advance(n);
		return n;
	}
};

test "e2e: an oversize head answers 431 on BOTH guards -- std's head bound and the copy guard (N3)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	// a ~20 KiB head: one padded header over the 16 KiB bound
	var big = std.Io.Writer.Allocating.init(gpa);
	defer big.deinit();
	try big.writer.writeAll("GET /api/v4/user HTTP/1.1\r\nHost: git.example.com\r\nX-Cogbox-Host: git.example.com\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nX-Pad: ");
	try big.writer.splatByteAll('p', 20 * 1024);
	try big.writer.writeAll("\r\n\r\n");
	var refusing = upstream.RefusingTransport{};

	// std's bound: the head arrives in pieces and receiveHead trips max_head_len
	{
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		var store = conf.Store.initStatic(gpa, h.io, gen);
		defer store.deinit();
		var ctx = main.Context{ .gpa = gpa, .io = h.io, .store = &store, .transport = refusing.t() };
		var tr = TrickleReader{ .src = big.written() };
		tr.init();
		var out = std.Io.Writer.Allocating.init(gpa);
		defer out.deinit();
		main.serveConnection(&ctx, &tr.interface, &out.writer);
		try t.expect(std.mem.startsWith(u8, out.written(), "HTTP/1.1 431 "));
		try t.expect(std.mem.indexOf(u8, out.written(), "connection: close") != null);
	}
	// the copy guard: with the whole head already buffered, std hands it back
	// past the bound and handleRequest refuses the copy
	{
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		var run = try serve(gpa, h.io, gen, refusing.t(), big.written());
		defer run.deinit(gpa);
		try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 431 "));
		try t.expect(std.mem.indexOf(u8, run.audit, "reason=head-oversize") != null);
	}
	try t.expectEqual(@as(usize, 0), refusing.calls);
}

test "e2e: a credential carrying an interior CRLF is unavailable -- 403, no dial, nothing injected (F1)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	// the tail trim reaches only the LAST CRLF; the interior one would have
	// been spliced raw into `Bearer <value>` -- header injection into the
	// constructed upstream head under the owner's identity
	try writeFile(h.io, h.cred_path, "glpat-AAA\r\nX-Injected-By-Cred: 1\r\n");
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var refusing = upstream.RefusingTransport{};
	var run = try serve(gpa, h.io, gen, refusing.t(), gitReq("/api/v4/user"));
	defer run.deinit(gpa);
	try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 403 "));
	try t.expectEqual(@as(usize, 0), refusing.calls);
	try t.expect(std.mem.indexOf(u8, run.audit, "reason=cred-unavailable") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "glpat") == null);
	try t.expect(std.mem.indexOf(u8, run.audit, "Injected") == null);
}

/// An allocator that hands out from `backing` but RETAINS every block the code
/// under test frees -- still mapped, still readable -- so a test can inspect
/// retired memory. The blocks are released on deinit.
const RetainingAllocator = struct {
	backing: std.mem.Allocator,
	retired: std.ArrayList(Retired) = .empty,

	const Retired = struct { block: []u8, alignment: std.mem.Alignment };

	fn allocator(self: *RetainingAllocator) std.mem.Allocator {
		return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
	}
	fn deinit(self: *RetainingAllocator) void {
		for (self.retired.items) |r| self.backing.rawFree(r.block, r.alignment, @returnAddress());
		self.retired.deinit(self.backing);
	}
	fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
		const self: *RetainingAllocator = @ptrCast(@alignCast(ctx));
		return self.backing.rawAlloc(len, alignment, ret_addr);
	}
	fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
		const self: *RetainingAllocator = @ptrCast(@alignCast(ctx));
		return self.backing.rawResize(memory, alignment, new_len, ret_addr);
	}
	fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
		const self: *RetainingAllocator = @ptrCast(@alignCast(ctx));
		return self.backing.rawRemap(memory, alignment, new_len, ret_addr);
	}
	fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
		_ = ret_addr;
		const self: *RetainingAllocator = @ptrCast(@alignCast(ctx));
		self.retired.append(self.backing, .{ .block = memory, .alignment = alignment }) catch {};
	}
};

test "e2e: every buffer that carried the credential is scrubbed before its block is retired (S5 pin)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson();
	defer gpa.free(cj);
	const raw_token = "glpat-FAKEFAKEFAKE";
	const basic_form = "b2F1dGgyOmdscGF0LUZBS0VGQUtFRkFLRQ=="; // base64("oauth2:" ++ raw_token)
	var ra = RetainingAllocator{ .backing = gpa };
	defer ra.deinit();

	// An API route (Bearer <raw>) and a git route (Basic <base64>): the raw
	// token is read into cred_buf on both, the Authorization value lands in
	// auth_headers, and the serialized head passes through storage.wbuf.
	const reqs = [_][]const u8{ gitReq("/api/v4/user"), gitReq("/grp/proj/info/refs?service=git-upload-pack") };
	const forms = [_][]const u8{ raw_token, basic_form };
	for (reqs, forms) |req, form| {
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		var store = conf.Store.initStatic(gpa, h.io, gen);
		defer store.deinit();
		var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"});
		defer fake.deinit();
		// the request path allocates its scratch block from ctx.gpa
		var ctx = main.Context{ .gpa = ra.allocator(), .io = h.io, .store = &store, .transport = fake.t() };
		var in = std.Io.Reader.fixed(req);
		var out = std.Io.Writer.Allocating.init(gpa);
		defer out.deinit();
		const before = ra.retired.items.len;
		main.serveConnection(&ctx, &in, &out.writer);
		// positive control: the credential DID flow through the scratch block
		// to the origin, in this route's form
		try t.expect(std.mem.startsWith(u8, out.written(), "HTTP/1.1 200 OK\r\n"));
		try t.expect(std.mem.indexOf(u8, fake.captured.items[0], form) != null);
		// the scratch block was retired, and neither form of the token survives
		// in it -- nor in any other block this request freed
		var saw_scratch = false;
		for (ra.retired.items[before..]) |r| {
			if (r.block.len >= @sizeOf(main.RequestScratch)) saw_scratch = true;
			try t.expect(std.mem.indexOf(u8, r.block, raw_token) == null);
			try t.expect(std.mem.indexOf(u8, r.block, basic_form) == null);
		}
		try t.expect(saw_scratch);
	}
}

// --- the mediate seam: a fake harbor-style plugin driving 401 -> token -> replay ---

const FakeMediate = struct {
	host: []const u8,

	fn compiled(ctx: *const anyopaque) *const FakeMediate {
		return @ptrCast(@alignCast(ctx));
	}
	fn classify(ctx: *const anyopaque, req: *const plugin_mod.Request) ?plugin_mod.Route {
		_ = ctx;
		_ = req;
		return .{ .id = "reg-manifest", .layer = .api, .method_class = .read, .params = .{}, .stream = true };
	}
	fn authorize(ctx: *const anyopaque, route: *const plugin_mod.Route, req: *const plugin_mod.Request) plugin_mod.Decision {
		_ = ctx;
		_ = route;
		_ = req;
		return .{ .allow = "gg-registry" };
	}
	fn upstreamFn(ctx: *const anyopaque, route: *const plugin_mod.Route, req: *const plugin_mod.Request, out: *plugin_mod.Upstream) plugin_mod.UpstreamError!void {
		_ = route;
		_ = req;
		const self = compiled(ctx);
		out.scheme = .http;
		out.host = self.host;
		try out.appendPath("/v2/proj/img/manifests/latest");
	}
	fn authenticate(ctx: *const anyopaque, route: *const plugin_mod.Route, req: *const plugin_mod.Request, cred: *plugin_mod.Cred, out: *plugin_mod.HeaderSet) plugin_mod.AuthError!void {
		_ = ctx;
		_ = route;
		_ = req;
		_ = cred;
		_ = out;
	}
	/// 401 -> parse the challenge, CLAMP push->pull, GET the token realm with
	/// the clamped scope, then replay the manifest with Bearer <jwt>. The scope
	/// clamp is the entire security value of mediating rather than proxying.
	fn mediate(ctx: *const anyopaque, route: *const plugin_mod.Route, req: *const plugin_mod.Request, cred: *plugin_mod.Cred, io: *upstream.UpstreamIO, out: *plugin_mod.Response) plugin_mod.MediateError!bool {
		_ = route;
		_ = req;
		const self = compiled(ctx);

		var manifest: plugin_mod.Upstream = .{ .scheme = .http, .host = self.host };
		manifest.appendPath("/v2/proj/img/manifests/latest") catch return error.MediateFailed;
		var h0: plugin_mod.HeaderSet = .{};
		const ex1 = io.roundtrip(&manifest, .GET, &h0, null) catch return error.UpstreamFailed;
		if (ex1.status != 401) {
			out.exchange = ex1;
			return true;
		}
		const challenge = ex1.headers.get("www-authenticate") orelse return error.MediateFailed;
		// The grant here allows pull only; clamp a "pull,push" challenge to pull.
		const clamped = if (std.mem.indexOf(u8, challenge, "push") != null)
			"service=harbor&scope=repository:proj/img:pull"
		else
			"service=harbor&scope=repository:proj/img:pull";

		var token_req: plugin_mod.Upstream = .{ .scheme = .http, .host = self.host };
		token_req.appendPath("/service/token") catch return error.MediateFailed;
		token_req.appendQuery(clamped) catch return error.MediateFailed;
		var h1: plugin_mod.HeaderSet = .{};
		// the owner's robot credential authorizes the token exchange
		const tok = cred.token() catch return error.CredentialUnavailable;
		var basic: [256]u8 = undefined;
		const v = std.fmt.bufPrint(&basic, "Bearer {s}", .{tok}) catch return error.MediateFailed;
		h1.set("authorization", v) catch return error.MediateFailed;
		const ex2 = io.roundtrip(&token_req, .GET, &h1, null) catch return error.UpstreamFailed;
		if (ex2.status != 200) return error.MediateFailed;

		// read the minted JWT out of ex2's body BEFORE the next leg reuses storage
		var jwt_buf: [256]u8 = undefined;
		var jw: std.Io.Writer = .fixed(&jwt_buf);
		const jn = (ex2.body orelse return error.MediateFailed).streamRemaining(&jw) catch return error.UpstreamFailed;
		const jwt = jwt_buf[0..jn];

		var replay: plugin_mod.Upstream = .{ .scheme = .http, .host = self.host };
		replay.appendPath("/v2/proj/img/manifests/latest") catch return error.MediateFailed;
		var h2: plugin_mod.HeaderSet = .{};
		var bearer: [512]u8 = undefined;
		const bv = std.fmt.bufPrint(&bearer, "Bearer {s}", .{jwt}) catch return error.MediateFailed;
		h2.set("authorization", bv) catch return error.MediateFailed;
		const ex3 = io.open(&replay, .GET, &h2, null, null) catch return error.UpstreamFailed;
		out.exchange = ex3;
		return true;
	}

	const vtable: plugin_mod.Policy.VTable = .{
		.classify = classify,
		.authorize = authorize,
		.upstream = upstreamFn,
		.authenticate = authenticate,
		.mediate = mediate,
	};
};

/// Build a one-entry generation whose policy is a supplied vtable/ctx -- lets a
/// test inject a plugin without touching the comptime registry.
fn staticGen(gpa: std.mem.Allocator, host: []const u8, cred_file: []const u8, policy: plugin_mod.Policy) !*conf.Generation {
	const g = try gpa.create(conf.Generation);
	g.* = .{
		.arena = std.heap.ArenaAllocator.init(gpa),
		.refs = .init(1),
		.gen = 1,
		.entries = &.{},
		.bundle = .empty,
		.bundle_lock = .init,
		.https_refusal_logged = .init(false),
	};
	const arena = g.arena.allocator();
	const entries = try arena.alloc(conf.Entry, 1);
	entries[0] = .{
		.host = try arena.dupe(u8, host),
		.plugin_name = "reg",
		.scheme = .http,
		.insecure = false,
		.cred_file = try arena.dupe(u8, cred_file),
		.cred_format = "raw",
		.git_user = "robot",
		.grants = &.{},
		.policy = policy,
	};
	g.entries = entries;
	return g;
}

test "e2e: the mediate seam drives 401 -> token(clamped scope) -> replay, token-free audit" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	try writeFile(h.io, h.cred_path, "robot-secret-FAKE\n");

	var fm = FakeMediate{ .host = "git.example.com" };
	const policy: plugin_mod.Policy = .{ .ctx = &fm, .vtable = &FakeMediate.vtable };
	const gen = try staticGen(gpa, "git.example.com", h.cred_path, policy);

	var fake = upstream.FakeTransport.init(gpa, &.{
		"HTTP/1.1 401 Unauthorized\r\nwww-authenticate: Bearer realm=\"http://git.example.com/service/token\",service=\"harbor\",scope=\"repository:proj/img:pull,push\"\r\ncontent-length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\nJWTVALUE",
		"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nMFEST",
	});
	defer fake.deinit();

	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/v2/proj/img/manifests/latest"));
	defer run.deinit(gpa);

	try t.expect(std.mem.indexOf(u8, run.response, "MFEST") != null); // the client got the replayed manifest
	try t.expectEqual(@as(usize, 3), fake.calls); // 401, token, replay
	// leg 2 (the token request) carries the CLAMPED scope -- no `push`
	const token_req = fake.captured.items[1];
	try t.expect(std.mem.indexOf(u8, token_req, "scope=repository:proj/img:pull") != null);
	try t.expect(std.mem.indexOf(u8, token_req, "push") == null);
	// leg 3 (the replay) carries the minted JWT, not the robot secret
	const replay_req = fake.captured.items[2];
	try t.expect(std.mem.indexOf(u8, replay_req, "authorization: Bearer JWTVALUE\r\n") != null);
	// the audit line carries neither the robot secret nor the minted JWT
	try t.expect(std.mem.indexOf(u8, run.audit, "robot-secret") == null);
	try t.expect(std.mem.indexOf(u8, run.audit, "JWTVALUE") == null);
	try t.expect(std.mem.indexOf(u8, run.audit, "decision=allow") != null);
}

// --- a mediate plugin that hands back an exchange it filled by HAND, one `open` never produced ---

const SynthMediate = struct {
	host: []const u8,

	fn classify(ctx: *const anyopaque, req: *const plugin_mod.Request) ?plugin_mod.Route {
		_ = ctx;
		_ = req;
		return .{ .id = "reg-manifest", .layer = .api, .method_class = .read, .params = .{}, .stream = false };
	}
	fn authorize(ctx: *const anyopaque, route: *const plugin_mod.Route, req: *const plugin_mod.Request) plugin_mod.Decision {
		_ = ctx;
		_ = route;
		_ = req;
		return .{ .allow = "gg-registry" };
	}
	fn upstreamFn(ctx: *const anyopaque, route: *const plugin_mod.Route, req: *const plugin_mod.Request, out: *plugin_mod.Upstream) plugin_mod.UpstreamError!void {
		_ = route;
		_ = req;
		const self: *const SynthMediate = @ptrCast(@alignCast(ctx));
		out.scheme = .http;
		out.host = self.host;
		try out.appendPath("/v2/proj/img/manifests/latest");
	}
	fn authenticate(ctx: *const anyopaque, route: *const plugin_mod.Route, req: *const plugin_mod.Request, cred: *plugin_mod.Cred, out: *plugin_mod.HeaderSet) plugin_mod.AuthError!void {
		_ = ctx;
		_ = route;
		_ = req;
		_ = cred;
		_ = out;
	}
	/// A 401 challenge minted locally rather than relayed -- with a bare LF in
	/// the value, which std's response parser would have let through and
	/// respondStreaming never inspects.
	fn mediate(ctx: *const anyopaque, route: *const plugin_mod.Route, req: *const plugin_mod.Request, cred: *plugin_mod.Cred, io: *upstream.UpstreamIO, out: *plugin_mod.Response) plugin_mod.MediateError!bool {
		_ = ctx;
		_ = route;
		_ = req;
		_ = cred;
		const ex = &io.storage.exchange;
		ex.* = .{ .status = 401, .headers = .{}, .content_length = null, .chunked = false, .body = null };
		ex.headers.append("www-authenticate", "Bearer realm=\"x\"\nx-injected: 1") catch return error.MediateFailed;
		out.exchange = ex;
		return true;
	}

	const vtable: plugin_mod.Policy.VTable = .{
		.classify = classify,
		.authorize = authorize,
		.upstream = upstreamFn,
		.authenticate = authenticate,
		.mediate = mediate,
	};
};

test "e2e: a mediate-synthesized exchange with a header the relay cannot emit is refused whole, never split into the response (belt under N3)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();

	var sm = SynthMediate{ .host = "git.example.com" };
	const policy: plugin_mod.Policy = .{ .ctx = &sm, .vtable = &SynthMediate.vtable };
	const gen = try staticGen(gpa, "git.example.com", h.cred_path, policy);
	var refusing = upstream.RefusingTransport{};

	var run = try serve(gpa, h.io, gen, refusing.t(), gitReq("/v2/proj/img/manifests/latest"));
	defer run.deinit(gpa);
	try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 502 "));
	try t.expect(std.mem.indexOf(u8, run.response, "www-authenticate") == null);
	try t.expect(std.mem.indexOf(u8, run.response, "x-injected") == null);
	try t.expect(std.mem.indexOf(u8, run.audit, " decision=deny ") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, " reason=BadResponseHeader ") != null);
	try t.expectEqual(@as(usize, 0), refusing.calls); // minted locally: no dial to refuse
}

test "e2e: a deny carries the X-Cogbox-Deny reason header (fixed enum, no secret, no dial)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try h.confJson(); // an instance grant carrying every cap
	defer gpa.free(cj);
	var refusing = upstream.RefusingTransport{};

	// gate-1 (unrouted) -> no_route on the header AND the audit line
	{
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		var run = try serve(gpa, h.io, gen, refusing.t(), gitReq("/api/v4/projects/1234/access_tokens"));
		defer run.deinit(gpa);
		try t.expect(std.mem.indexOf(u8, run.response, "403") != null);
		try t.expect(std.ascii.indexOfIgnoreCase(run.response, "X-Cogbox-Deny: no_route") != null);
		try t.expect(std.mem.indexOf(u8, run.audit, "reason=no_route") != null);
	}
	// gate-2 (scope) -> scope_mismatch: an instance grant does NOT enumerate a
	// namespace group, and the coarse reason says so (never "no grant at all")
	{
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		var run = try serve(gpa, h.io, gen, refusing.t(), gitReq("/api/v4/groups/acme/projects"));
		defer run.deinit(gpa);
		try t.expect(std.mem.indexOf(u8, run.response, "403") != null);
		try t.expect(std.ascii.indexOfIgnoreCase(run.response, "X-Cogbox-Deny: scope_mismatch") != null);
	}
	// the header never carries a secret and the deny never dialed the upstream
	try t.expectEqual(@as(usize, 0), refusing.calls);
}

test "e2e: a namespace git-read grant enumerates its group -- simple=true forced, owner Bearer, no client override" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	// a NAMESPACE git-read grant on acme/* -- the enumeration case
	const cj = try std.fmt.allocPrint(gpa,
		\\{{"version":1,"providers":[{{"host":"git.example.com","plugin":"gitlab","scheme":"http","insecure":false,
		\\"cred_file":"{s}","cred_format":"raw","git_user":"oauth2",
		\\"grants":[{{"id":"gg-ns","scope":"namespace","repo":"acme/*","prefix":"/acme/","caps":["git-read"]}}]}}]}}
	, .{h.cred_path});
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n[]"});
	defer fake.deinit();

	// the guest tries to force the raw representation and a subgroup toggle off;
	// both are dropped, and a pagination param survives
	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/groups/acme/projects?simple=false&include_subgroups=false&per_page=50"));
	defer run.deinit(gpa);
	try t.expect(std.mem.indexOf(u8, run.response, "200 OK") != null);
	try t.expectEqual(@as(usize, 1), fake.calls);
	const up_req = fake.captured.items[0];
	// the constructed upstream line: simple=true + include_subgroups=true FORCED,
	// the pagination param kept, the client's simple=false / include_subgroups=false gone
	try t.expect(std.mem.startsWith(u8, up_req, "GET /api/v4/groups/acme/projects?simple=true&include_subgroups=true&per_page=50 HTTP/1.1\r\n"));
	try t.expect(std.mem.indexOf(u8, up_req, "simple=false") == null);
	try t.expect(std.mem.indexOf(u8, up_req, "include_subgroups=false") == null);
	// the OWNER token as Bearer (an API route), not the guest stub
	try t.expect(std.mem.indexOf(u8, up_req, "authorization: Bearer glpat-FAKEFAKEFAKE\r\n") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "route=api-group-projects") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "decision=allow") != null);
}

// --- api-project response-body projection (the runners_token fix) -----------

/// The body of an HTTP response the harness captured: the bytes after the first
/// CRLFCRLF.
fn httpBody(resp: []const u8) []const u8 {
	const i = std.mem.indexOf(u8, resp, "\r\n\r\n") orelse return "";
	return resp[i + 4 ..];
}

/// The declared Content-Length of a captured response (case-insensitive).
fn contentLength(resp: []const u8) ?usize {
	const key = "content-length:";
	const i = std.ascii.indexOfIgnoreCase(resp, key) orelse return null;
	const rest = resp[i + key.len ..];
	const end = std.mem.indexOf(u8, rest, "\r\n") orelse return null;
	return std.fmt.parseInt(usize, std.mem.trim(u8, rest[0..end], " "), 10) catch null;
}

/// An `HTTP/1.1 <status> <phrase>` response over a JSON body, Content-Length
/// computed from the body (the fake upstream's script bytes; caller frees).
fn jsonResponse(gpa: std.mem.Allocator, status_line: []const u8, body: []const u8) ![]u8 {
	return std.fmt.allocPrint(gpa, "HTTP/1.1 {s}\r\ncontent-type: application/json\r\ncontent-length: {d}\r\n\r\n{s}", .{ status_line, body.len, body });
}

/// A conf naming the temp cred file with an instance grant carrying exactly the
/// given caps -- so a test can prove the api-project projection is route-driven,
/// not cap-driven (it runs the same under git-read and under issues).
fn instanceConf(gpa: std.mem.Allocator, cred_path: []const u8, caps_json: []const u8) ![]u8 {
	return std.fmt.allocPrint(gpa,
		\\{{"version":1,"providers":[{{"host":"git.example.com","plugin":"gitlab","scheme":"http","insecure":false,
		\\"cred_file":"{s}","cred_format":"raw","git_user":"oauth2",
		\\"grants":[{{"id":"gg-inst","scope":"instance","caps":{s}}}]}}]}}
	, .{ cred_path, caps_json });
}

/// A GitLab single-project GET body carrying BOTH the allowlisted safe fields
/// and the secret/omitted ones (runners_token, import_url, permissions, _links,
/// a registry field, and a bogus namespace.runners_token) -- the projection must
/// keep the former and drop the latter.
const full_project_json =
	\\{"id":1234,"description":"a repo","name":"proj","name_with_namespace":"grp / proj","path":"proj","path_with_namespace":"grp/proj","created_at":"2026-01-02T03:04:05Z","default_branch":"main","tag_list":["x"],"topics":["x"],"ssh_url_to_repo":"git@git.example.com:grp/proj.git","http_url_to_repo":"http://git.example.com/grp/proj.git","web_url":"http://git.example.com/grp/proj","readme_url":null,"avatar_url":null,"forks_count":0,"star_count":1,"last_activity_at":"2026-01-02T03:04:05Z","visibility":"private","archived":false,"empty_repo":false,"runners_token":"GR1348secret","import_url":"http://internal/import","permissions":{"project_access":{"access_level":40}},"_links":{"self":"http://git.example.com/x"},"container_registry_image_prefix":"reg.example.com/grp/proj","namespace":{"id":5,"name":"grp","path":"grp","kind":"group","full_path":"grp","parent_id":null,"avatar_url":null,"web_url":"http://git.example.com/groups/grp","runners_token":"NSsecret"}}
;

fn assertProjected(gpa: std.mem.Allocator, resp: []const u8) !void {
	try t.expect(std.mem.indexOf(u8, resp, "200 OK") != null);
	const body = httpBody(resp);
	// the secret / omitted fields are all gone -- by name AND by value
	const gone = [_][]const u8{ "runners_token", "import_url", "permissions", "_links", "GR1348secret", "NSsecret", "container_registry_image_prefix" };
	for (gone) |needle| try t.expect(std.mem.indexOf(u8, body, needle) == null);
	// the allowlisted fields the agent needs are kept
	const kept = [_][]const u8{ "path_with_namespace", "default_branch", "http_url_to_repo", "visibility" };
	for (kept) |needle| try t.expect(std.mem.indexOf(u8, body, needle) != null);
	// the nested namespace was projected through its own allowlist (kept, minus
	// its bogus secret already asserted gone above)
	try t.expect(std.mem.indexOf(u8, body, "\"namespace\":") != null);
	try t.expect(std.mem.indexOf(u8, body, "full_path") != null);
	// Content-Length was recomputed for the projected body, and it shrank
	try t.expectEqual(body.len, contentLength(resp).?);
	try t.expect(body.len < full_project_json.len);
	// the projected body is still valid JSON (parses as an object)
	const parsed = try std.json.parseFromSlice(std.json.Value, gpa, body, .{});
	defer parsed.deinit();
	try t.expect(parsed.value == .object);
}

test "e2e: api-project projects the response body -- secret fields stripped, allowlist kept, Content-Length recomputed (git-read)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try instanceConf(gpa, h.cred_path, "[\"git-read\"]");
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	const script = try jsonResponse(gpa, "200 OK", full_project_json);
	defer gpa.free(script);
	var fake = upstream.FakeTransport.init(gpa, &.{script});
	defer fake.deinit();

	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/projects/1234"));
	defer run.deinit(gpa);
	try t.expectEqual(@as(usize, 1), fake.calls);
	// the upstream still saw the owner Bearer and the forced simple=true
	const up_req = fake.captured.items[0];
	try t.expect(std.mem.startsWith(u8, up_req, "GET /api/v4/projects/1234?simple=true HTTP/1.1\r\n"));
	try t.expect(std.mem.indexOf(u8, up_req, "authorization: Bearer glpat-FAKEFAKEFAKE\r\n") != null);
	try assertProjected(gpa, run.response);
	try t.expect(std.mem.indexOf(u8, run.audit, "route=api-project") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "decision=allow") != null);
	// the audit line never carried the leaked secret
	try t.expect(std.mem.indexOf(u8, run.audit, "runners_token") == null);
}

test "e2e: the api-project projection runs regardless of which cap authorized it (issues grant)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	// an issues-only instance grant: api-project is authorized by issues too, and
	// the projection is route-driven, so it must strip the secret just the same
	const cj = try instanceConf(gpa, h.cred_path, "[\"issues\"]");
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	const script = try jsonResponse(gpa, "200 OK", full_project_json);
	defer gpa.free(script);
	var fake = upstream.FakeTransport.init(gpa, &.{script});
	defer fake.deinit();

	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/projects/1234"));
	defer run.deinit(gpa);
	try t.expectEqual(@as(usize, 1), fake.calls);
	try assertProjected(gpa, run.response);
	try t.expect(std.mem.indexOf(u8, run.audit, "route=api-project") != null);
}

test "e2e: an api-project 200 body over the cap fails closed (502), never relaying the secret" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try instanceConf(gpa, h.cred_path, "[\"git-read\"]");
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	// a 200 body larger than project_response_cap, with the secret up front
	const filler = try gpa.alloc(u8, main.project_response_cap + 4096);
	defer gpa.free(filler);
	@memset(filler, 'x');
	const body = try std.fmt.allocPrint(gpa, "{{\"runners_token\":\"GR1348secret\",\"description\":\"{s}\",\"id\":1}}", .{filler});
	defer gpa.free(body);
	const script = try jsonResponse(gpa, "200 OK", body);
	defer gpa.free(script);
	var fake = upstream.FakeTransport.init(gpa, &.{script});
	defer fake.deinit();

	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/projects/1234"));
	defer run.deinit(gpa);
	try t.expectEqual(@as(usize, 1), fake.calls); // it dialed and read...
	try t.expect(std.mem.indexOf(u8, run.response, "502") != null); // ...then failed closed
	try t.expect(std.ascii.indexOfIgnoreCase(run.response, "X-Cogbox-Deny: response_too_large") != null);
	// the oversize (unprojected) body was NEVER relayed -- no secret on the wire
	try t.expect(std.mem.indexOf(u8, run.response, "GR1348secret") == null);
	try t.expect(std.mem.indexOf(u8, run.response, "runners_token") == null);
	try t.expect(std.mem.indexOf(u8, run.audit, "reason=response_too_large") != null);
}

test "e2e: a non-200 api-project response is relayed unchanged (the projection is success-only)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try instanceConf(gpa, h.cred_path, "[\"git-read\"]");
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	// a 404 error body carries no project secret and must pass through verbatim
	const err_body = "{\"message\":\"404 Project Not Found\"}";
	const script = try jsonResponse(gpa, "404 Not Found", err_body);
	defer gpa.free(script);
	var fake = upstream.FakeTransport.init(gpa, &.{script});
	defer fake.deinit();

	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/projects/1234"));
	defer run.deinit(gpa);
	try t.expectEqual(@as(usize, 1), fake.calls);
	try t.expect(std.mem.indexOf(u8, run.response, "404 Not Found") != null);
	// relayed unchanged: the exact upstream body, not a projected object
	try t.expectEqualStrings(err_body, httpBody(run.response));
	try t.expectEqual(err_body.len, contentLength(run.response).?);
}

test "e2e: the group-projects LIST route is NOT projected -- its body relays verbatim" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	// a namespace git-read grant authorizes the enumeration LIST
	const cj = try std.fmt.allocPrint(gpa,
		\\{{"version":1,"providers":[{{"host":"git.example.com","plugin":"gitlab","scheme":"http","insecure":false,
		\\"cred_file":"{s}","cred_format":"raw","git_user":"oauth2",
		\\"grants":[{{"id":"gg-ns","scope":"namespace","repo":"acme/*","prefix":"/acme/","caps":["git-read"]}}]}}]}}
	, .{h.cred_path});
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	// GitLab's simple=true already stripped this list upstream; the fake carries a
	// field that api-project WOULD strip, to prove no proxy-side projection runs
	// on the list route -- the body must relay byte for byte.
	const list_body = "[{\"id\":1,\"path_with_namespace\":\"acme/a\",\"_links\":{\"self\":\"http://x\"}}]";
	const script = try jsonResponse(gpa, "200 OK", list_body);
	defer gpa.free(script);
	var fake = upstream.FakeTransport.init(gpa, &.{script});
	defer fake.deinit();

	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/groups/acme/projects"));
	defer run.deinit(gpa);
	try t.expectEqual(@as(usize, 1), fake.calls);
	try t.expect(std.mem.indexOf(u8, run.response, "200 OK") != null);
	try t.expectEqualStrings(list_body, httpBody(run.response)); // verbatim, unprojected
	try t.expectEqual(list_body.len, contentLength(run.response).?);
	try t.expect(std.mem.indexOf(u8, run.audit, "route=api-group-projects") != null);
}

test "e2e: api-project forces identity + full response -- accept-encoding and range are NOT forwarded (projection soundness)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try instanceConf(gpa, h.cred_path, "[\"git-read\"]");
	defer gpa.free(cj);

	// A guest that advertises gzip and asks for a byte range: forwarding either
	// to GitLab would break or bypass the projection -- a gzip 200 body fails the
	// JSON parse (502), and a 206 Partial Content falls outside the status==200
	// guard and would stream the raw, secret-bearing partial body. On api-project
	// both must be stripped so the origin returns a full, identity-encoded 200.
	const proj_req = "GET /api/v4/projects/1234 HTTP/1.1\r\n" ++
		"Host: git.example.com\r\n" ++
		"X-Cogbox-Host: git.example.com\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"Accept: */*\r\n" ++
		"Accept-Encoding: gzip, deflate\r\n" ++
		"Range: bytes=0-100\r\n\r\n";
	{
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		const script = try jsonResponse(gpa, "200 OK", full_project_json);
		defer gpa.free(script);
		var fake = upstream.FakeTransport.init(gpa, &.{script});
		defer fake.deinit();
		var run = try serve(gpa, h.io, gen, fake.t(), proj_req);
		defer run.deinit(gpa);
		try t.expectEqual(@as(usize, 1), fake.calls);
		const up_req = fake.captured.items[0];
		// neither guest-forwarded header reached the origin on this route
		try t.expect(std.ascii.indexOfIgnoreCase(up_req, "accept-encoding:") == null);
		try t.expect(std.ascii.indexOfIgnoreCase(up_req, "range:") == null);
		// the projection still ran (secret stripped, allowlist kept)
		try assertProjected(gpa, run.response);
	}

	// The strip is route-scoped: a NON-project route (api-archive, which streams)
	// still forwards both headers unchanged.
	{
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		const arch_req = "GET /api/v4/projects/1234/repository/archive.tar.gz HTTP/1.1\r\n" ++
			"Host: git.example.com\r\n" ++
			"X-Cogbox-Host: git.example.com\r\n" ++
			"X-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
			"Accept: */*\r\n" ++
			"Accept-Encoding: gzip, deflate\r\n" ++
			"Range: bytes=0-100\r\n\r\n";
		var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nPACK"});
		defer fake.deinit();
		var run = try serve(gpa, h.io, gen, fake.t(), arch_req);
		defer run.deinit(gpa);
		try t.expectEqual(@as(usize, 1), fake.calls);
		const up_req = fake.captured.items[0];
		try t.expect(std.ascii.indexOfIgnoreCase(up_req, "accept-encoding:") != null);
		try t.expect(std.ascii.indexOfIgnoreCase(up_req, "range:") != null);
	}
}

test "e2e: api-project drops a non-object namespace and a pathologically deep field (allowlist posture, no re-emit overflow)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try instanceConf(gpa, h.cred_path, "[\"git-read\"]");
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	// A hostile/buggy upstream: `namespace` is an ARRAY (not an object) hiding a
	// secret, and `tag_list` is nested far deeper than any real value. The
	// projection must DROP both -- the array namespace whole (never passed
	// through) and the deep field (jw.write recurses natively per level, so it is
	// dropped rather than re-serialized) -- while keeping the flat allowlist
	// fields, and never crash.
	const depth = 40; // > the re-emit depth bound
	var deep_buf: [2 * depth]u8 = undefined;
	@memset(deep_buf[0..depth], '[');
	@memset(deep_buf[depth..], ']');
	const body = try std.fmt.allocPrint(gpa, "{{\"id\":7,\"path_with_namespace\":\"grp/proj\",\"default_branch\":\"main\"," ++
		"\"http_url_to_repo\":\"http://git.example.com/grp/proj.git\",\"visibility\":\"private\"," ++
		"\"tag_list\":{s},\"namespace\":[{{\"runners_token\":\"ARRSECRET\"}}]}}", .{deep_buf[0..]});
	defer gpa.free(body);
	const script = try jsonResponse(gpa, "200 OK", body);
	defer gpa.free(script);
	var fake = upstream.FakeTransport.init(gpa, &.{script});
	defer fake.deinit();

	var run = try serve(gpa, h.io, gen, fake.t(), gitReq("/api/v4/projects/1234"));
	defer run.deinit(gpa);
	try t.expectEqual(@as(usize, 1), fake.calls);
	try t.expect(std.mem.indexOf(u8, run.response, "200 OK") != null);
	const rbody = httpBody(run.response);
	// the array namespace was dropped whole -- neither the key nor its secret
	// (the substring "namespace" still rides in the kept `path_with_namespace`,
	// so match the quoted namespace field key, as assertProjected does)
	try t.expect(std.mem.indexOf(u8, rbody, "\"namespace\":") == null);
	try t.expect(std.mem.indexOf(u8, rbody, "ARRSECRET") == null);
	// the deep field was dropped (and the re-emit did not overflow)
	try t.expect(std.mem.indexOf(u8, rbody, "tag_list") == null);
	// the flat allowlist fields survive, and it is still a valid JSON object
	for ([_][]const u8{ "path_with_namespace", "default_branch", "http_url_to_repo", "visibility" }) |k| {
		try t.expect(std.mem.indexOf(u8, rbody, k) != null);
	}
	try t.expectEqual(rbody.len, contentLength(run.response).?);
	const parsed = try std.json.parseFromSlice(std.json.Value, gpa, rbody, .{});
	defer parsed.deinit();
	try t.expect(parsed.value == .object);
}

// --- /_cogbox/grants: the local self-discovery reflection route ------------
//
// These drive the WHOLE core over an inline conf and a REFUSING upstream: the
// local answer must never dial (refusing.calls stays 0), reads no credential,
// and carries no X-Cogbox-Deny on the success path. Fictional names only
// (git.example.com, org `acme`), per the OSS convention.

fn cogboxReq(comptime method: []const u8, comptime target: []const u8) []const u8 {
	return method ++ " " ++ target ++ " HTTP/1.1\r\n" ++
		"Host: git.example.com\r\n" ++
		"X-Cogbox-Host: git.example.com\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"X-Cogbox-Proto: https\r\n" ++
		"Accept: */*\r\n\r\n";
}

/// Parse an inline conf and drive one local-route request against a REFUSING
/// upstream. The local route reads no credential, so the conf's cred_file need
/// not exist. Caller owns the Run; the gen is owned by serve's static store.
fn serveLocalReq(gpa: std.mem.Allocator, conf_json: []const u8, request_bytes: []const u8, refusing: *upstream.RefusingTransport) !Run {
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const gen = try conf.parseGeneration(gpa, io, conf_json, 1, .skip, null);
	return serve(gpa, io, gen, refusing.t(), request_bytes);
}

const ns_grant_conf =
	\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","insecure":false,
	\\"cred_file":"/nonexistent/store/git-gitlab","cred_format":"raw","git_user":"oauth2",
	\\"grants":[{"id":"gg-ns","scope":"namespace","repo":"acme/iac/*","prefix":"/acme/iac/","caps":["git-read"]}]}]}
;

const empty_grant_conf =
	\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","insecure":false,
	\\"cred_file":"/nonexistent/store/git-gitlab","cred_format":"raw","git_user":"oauth2",
	\\"grants":[]}]}
;

// The exact self-discovery JSON the ns_grant_conf reflects (the skill's contract).
const ns_grants_body =
	\\{"grants":[{"scope":"namespace","repo":"acme/iac/*","prefix":"acme/iac","caps":["git-read"]}]}
;

test "e2e: /_cogbox/grants reflects a namespace grant locally -- exact JSON, no upstream, no deny header, no token/numeric id" {
	const gpa = t.allocator;
	var refusing = upstream.RefusingTransport{};
	var run = try serveLocalReq(gpa, ns_grant_conf, cogboxReq("GET", "/_cogbox/grants"), &refusing);
	defer run.deinit(gpa);

	// answered LOCALLY: the refusing upstream was never dialed
	try t.expectEqual(@as(usize, 0), refusing.calls);
	// 200 application/json, and NO X-Cogbox-Deny on the success path
	try t.expect(std.mem.indexOf(u8, run.response, "200 OK") != null);
	try t.expect(std.mem.indexOf(u8, run.response, "content-type: application/json") != null);
	try t.expect(std.ascii.indexOfIgnoreCase(run.response, "Cogbox-Deny") == null);
	// the EXACT contract body: one tuple, path-form prefix, git-read
	const body = httpBody(run.response);
	try t.expectEqualStrings(ns_grants_body, body);
	try t.expectEqual(body.len, contentLength(run.response).?);
	// never a numeric id or the owner credential
	try t.expect(std.mem.indexOf(u8, body, "project_id") == null);
	try t.expect(std.mem.indexOf(u8, body, "glpat") == null);
	// audit: an allow on the local route, token-free, and no grant behind it
	try t.expect(std.mem.indexOf(u8, run.audit, "decision=allow") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "route=cogbox-grants") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "status=200") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "grant=-") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, "glpat") == null);
}

test "e2e: /_cogbox/grants on an ungranted sandbox is a 200 {grants:[]}, still local, still no deny header" {
	const gpa = t.allocator;
	var refusing = upstream.RefusingTransport{};
	var run = try serveLocalReq(gpa, empty_grant_conf, cogboxReq("GET", "/_cogbox/grants"), &refusing);
	defer run.deinit(gpa);
	try t.expectEqual(@as(usize, 0), refusing.calls);
	try t.expect(std.mem.indexOf(u8, run.response, "200 OK") != null);
	try t.expect(std.ascii.indexOfIgnoreCase(run.response, "Cogbox-Deny") == null);
	try t.expectEqualStrings("{\"grants\":[]}", httpBody(run.response));
}

test "e2e: /_cogbox/grants HEAD is head-only (Content-Length declared, no body), answered locally" {
	const gpa = t.allocator;
	var refusing = upstream.RefusingTransport{};
	var run = try serveLocalReq(gpa, ns_grant_conf, cogboxReq("HEAD", "/_cogbox/grants"), &refusing);
	defer run.deinit(gpa);
	try t.expectEqual(@as(usize, 0), refusing.calls);
	try t.expect(std.mem.indexOf(u8, run.response, "200 OK") != null);
	// the GET body's Content-Length is declared, but no body follows (std omits it)
	try t.expectEqual(@as(usize, ns_grants_body.len), contentLength(run.response).?);
	try t.expectEqualStrings("", httpBody(run.response));
}

fn cogboxBodyReq(comptime method: []const u8, comptime target: []const u8) []const u8 {
	// A body-bearing method MUST declare its framing (framing 411s a bodyless
	// one), so a request that reaches gate 2 carries a Content-Length body.
	return method ++ " " ++ target ++ " HTTP/1.1\r\n" ++
		"Host: git.example.com\r\n" ++
		"X-Cogbox-Host: git.example.com\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"Content-Type: application/json\r\n" ++
		"Content-Length: 2\r\n\r\n{}";
}

test "e2e: /_cogbox/grants refuses a non-GET/HEAD method with method_not_allowed, never dialing upstream" {
	const gpa = t.allocator;
	// POST/DELETE carrying a body reach gate 2 and get the SAME method_not_allowed
	// deny the API tier gives DELETE -- never the grants body, never an upstream
	// dial. (The pure classify/authorize clamp is also pinned by the route_vectors
	// authz rows and the gitlab unit test.)
	const reqs = [_][]const u8{
		cogboxBodyReq("POST", "/_cogbox/grants"), // a body-bearing POST reaches gate 2
		cogboxReq("DELETE", "/_cogbox/grants"), // a bodyless DELETE also reaches gate 2
	};
	for (reqs) |req| {
		var refusing = upstream.RefusingTransport{};
		var run = try serveLocalReq(gpa, ns_grant_conf, req, &refusing);
		defer run.deinit(gpa);
		try t.expectEqual(@as(usize, 0), refusing.calls);
		try t.expect(std.mem.indexOf(u8, run.response, "403") != null);
		try t.expect(std.mem.indexOf(u8, run.response, "method_not_allowed") != null);
		try t.expect(std.mem.indexOf(u8, run.audit, "reason=method_not_allowed") != null);
		try t.expect(std.mem.indexOf(u8, run.audit, "route=cogbox-grants") != null);
		// the grants body is NEVER rendered for a refused method
		try t.expect(std.mem.indexOf(u8, run.response, "acme/iac") == null);
	}
}

// --- push rules: the gitlab mediate hook, end to end -------------------------
//
// The pins here are the ones the units structurally cannot reach: that an
// admitted push arrives at the origin BYTE-IDENTICAL under the owner's Basic
// credential, that a refused one never opens a socket, and that a deny taken
// AFTER the body reader was handed to the plugin still closes the connection
// cleanly instead of tripping std's discard-and-reuse assert.

const pktline = @import("pktline.zig");

const push_oid_a = "1" ** 40;
const push_oid_b = "2" ** 40;
const push_oid_zero = "0" ** 40;

/// One command line plus the flush that ends the section. `inline` so the
/// fixtures below stay comptime-known and can be `++`ed with a packfile.
inline fn cmdSection(comptime line: []const u8) []const u8 {
	return pktline.frame(line) ++ pktline.flush_pkt;
}

/// A conf whose single instance grant may push ONLY under refs/heads/agent/**,
/// with deletes and tags denied -- the shape the control plane renders for a
/// branch-fenced grant.
fn confJsonPush(h: *Harness) ![]u8 {
	return std.fmt.allocPrint(h.gpa,
		\\{{"version":1,"providers":[{{"host":"git.example.com","plugin":"gitlab","scheme":"http","insecure":false,
		\\"cred_file":"{s}","cred_format":"raw","git_user":"oauth2",
		\\"grants":[{{"id":"gg-push","scope":"instance","caps":["git-read","git-write"],
		\\"push":{{"refs":["refs/heads/agent/**"],"deny_delete":true,"deny_tags":true}}}}]}}]}}
	, .{h.cred_path});
}

fn pushReq(gpa: std.mem.Allocator, body: []const u8) ![]u8 {
	return std.fmt.allocPrint(gpa, "POST /grp/proj.git/git-receive-pack HTTP/1.1\r\n" ++
		"Host: git.example.com\r\n" ++
		"X-Cogbox-Host: git.example.com\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"X-Cogbox-Proto: https\r\n" ++
		"Content-Type: application/x-git-receive-pack-request\r\n" ++
		"Content-Length: {d}\r\n\r\n{s}", .{ body.len, body });
}

/// serve() with the request-path counters handed back. An ADMITTED push and the
/// same push on the default relay put identical bytes on the wire -- that is the
/// whole point of the forwarding path -- so the counters are the only way a test
/// can tell which arm ran, and every byte-identity assertion below is paired
/// with one.
const Metered = struct {
	run: Run,
	mediate: u64,
	deny_gate3: u64,
	allow: u64,

	fn deinit(self: *Metered, gpa: std.mem.Allocator) void {
		self.run.deinit(gpa);
	}
};

fn serveMetered(gpa: std.mem.Allocator, io: std.Io, gen: *conf.Generation, transport: *const upstream.Transport, request_bytes: []const u8) !Metered {
	var store = conf.Store.initStatic(gpa, io, gen);
	defer store.deinit();
	var audit = std.Io.Writer.Allocating.init(gpa);
	defer audit.deinit();
	var ctx = main.Context{ .gpa = gpa, .io = io, .store = &store, .transport = transport, .audit = &audit.writer };
	var in = std.Io.Reader.fixed(request_bytes);
	var out = std.Io.Writer.Allocating.init(gpa);
	defer out.deinit();
	main.serveConnection(&ctx, &in, &out.writer);
	return .{
		.run = .{ .response = try gpa.dupe(u8, out.written()), .audit = try gpa.dupe(u8, audit.written()) },
		.mediate = ctx.counters.mediate.load(.monotonic),
		.deny_gate3 = ctx.counters.deny_gate3.load(.monotonic),
		.allow = ctx.counters.allow.load(.monotonic),
	};
}

/// The bytes after the head of a captured upstream request.
fn upstreamBody(req: []const u8) []const u8 {
	const sep = std.mem.indexOf(u8, req, "\r\n\r\n") orelse return "";
	return req[sep + 4 ..];
}

/// Decode a chunked body back to its bytes, so "re-framed, not rewritten" is
/// asserted on the CONTENT rather than on the framing that carries it.
fn dechunk(gpa: std.mem.Allocator, body: []const u8) ![]u8 {
	var out = std.Io.Writer.Allocating.init(gpa);
	errdefer out.deinit();
	var i: usize = 0;
	while (true) {
		const eol = std.mem.indexOfPos(u8, body, i, "\r\n") orelse return error.BadChunk;
		const n = try std.fmt.parseInt(usize, body[i..eol], 16);
		i = eol + 2;
		if (n == 0) break;
		if (i + n + 2 > body.len) return error.BadChunk;
		try out.writer.writeAll(body[i .. i + n]);
		i += n + 2;
	}
	return out.toOwnedSlice();
}

test "e2e: an admitted push forwards the WHOLE body byte-identically under the owner's Basic credential" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try confJsonPush(&h);
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	// A real push shape: the command line with its capability list, the flush,
	// then a packfile carrying bytes no text encoding would survive.
	const body = cmdSection(push_oid_a ++ " " ++ push_oid_b ++ " refs/heads/agent/x\x00report-status side-band-64k") ++
		"PACK\x00\x02\x00\x00\x00\x01\xff\xfe";
	const req = try pushReq(gpa, body);
	defer gpa.free(req);

	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"});
	defer fake.deinit();
	var met = try serveMetered(gpa, h.io, gen, fake.t(), req);
	defer met.deinit(gpa);
	const run = met.run;

	try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 200 OK\r\n"));
	// the MEDIATE arm ran (and admitted): without this the assertions below hold
	// just as well on the default relay, which is exactly the trap
	try t.expectEqual(@as(u64, 1), met.mediate);
	try t.expectEqual(@as(u64, 0), met.deny_gate3);
	try t.expectEqual(@as(u64, 1), met.allow);
	try t.expectEqual(@as(usize, 1), fake.calls);
	const up_req = fake.captured.items[0];
	try t.expect(std.mem.startsWith(u8, up_req, "POST /grp/proj.git/git-receive-pack HTTP/1.1\r\n"));
	// the OWNER credential, in the git tier's Basic form -- base64("oauth2:glpat-FAKEFAKEFAKE")
	try t.expect(std.mem.indexOf(u8, up_req, "authorization: Basic b2F1dGgyOmdscGF0LUZBS0VGQUtFRkFLRQ==\r\n") != null);
	// the framing is UNCHANGED: the same declared length, and the same bytes --
	// the buffered command section replayed ahead of the live packfile
	var cl_buf: [64]u8 = undefined;
	try t.expect(std.mem.indexOf(u8, up_req, std.fmt.bufPrint(&cl_buf, "content-length: {d}\r\n", .{body.len}) catch unreachable) != null);
	try t.expectEqualStrings(body, upstreamBody(up_req));
	// the whole guest body was consumed by the forward, so the connection is
	// still reusable -- a mediate arm that left a tail unread would show up here
	// as a forced close
	try t.expect(std.mem.indexOf(u8, run.response, "connection: close\r\n") == null);
	try t.expect(std.mem.indexOf(u8, run.audit, " decision=allow ") != null);
	try t.expect(std.mem.indexOf(u8, run.audit, " route=git-receive ") != null);
	var bi_buf: [64]u8 = undefined;
	try t.expect(std.mem.indexOf(u8, run.audit, std.fmt.bufPrint(&bi_buf, " bytes_in={d} ", .{body.len}) catch unreachable) != null);
}

test "e2e: the same push under a grant with NO rules never enters the mediate arm (fast-path pin)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	// the ordinary conf: git-write, no push object anywhere
	const cj = try h.confJson();
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	const body = cmdSection(push_oid_a ++ " " ++ push_oid_b ++ " refs/heads/main\x00report-status") ++ "PACKDATA";
	const req = try pushReq(gpa, body);
	defer gpa.free(req);
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"});
	defer fake.deinit();
	var met = try serveMetered(gpa, h.io, gen, fake.t(), req);
	defer met.deinit(gpa);

	// the hook was consulted and declined BEFORE reading a byte: the counter
	// stays at zero and the core's default relay carried the request
	try t.expectEqual(@as(u64, 0), met.mediate);
	try t.expectEqual(@as(u64, 0), met.deny_gate3);
	try t.expect(std.mem.startsWith(u8, met.run.response, "HTTP/1.1 200 OK\r\n"));
	// ...to the same bytes: `refs/heads/main` is refused under rules and relayed
	// without them, which is the whole difference push rules make
	try t.expectEqualStrings(body, upstreamBody(fake.captured.items[0]));
}

test "e2e: a push the rules refuse is a 403 ref_denied at gate 3 with NO dial" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try confJsonPush(&h);
	defer gpa.free(cj);

	const Case = struct { body: []const u8, why: []const u8 };
	const cases = [_]Case{
		.{
			.body = cmdSection(push_oid_a ++ " " ++ push_oid_b ++ " refs/heads/main\x00report-status") ++ "PACKDATA",
			.why = "a branch outside the patterns",
		},
		.{
			// a DELETE of an ALLOWED ref: deny_delete, not the patterns, refuses it
			.body = cmdSection(push_oid_a ++ " " ++ push_oid_zero ++ " refs/heads/agent/x"),
			.why = "a delete under deny_delete",
		},
		.{
			.body = cmdSection(push_oid_a ++ " " ++ push_oid_b ++ " refs/tags/v1.0") ++ "PACKDATA",
			.why = "a tag under deny_tags",
		},
	};
	for (cases) |c| {
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		const req = try pushReq(gpa, c.body);
		defer gpa.free(req);
		var refusing = upstream.RefusingTransport{};
		var met = try serveMetered(gpa, h.io, gen, refusing.t(), req);
		defer met.deinit(gpa);
		const run = met.run;
		if (!std.mem.startsWith(u8, run.response, "HTTP/1.1 403 ")) {
			std.debug.print("{s}: response was {s}\n", .{ c.why, run.response });
			return error.NotRefused;
		}
		try t.expect(std.ascii.indexOfIgnoreCase(run.response, "X-Cogbox-Deny: ref_denied") != null);
		try t.expect(std.mem.indexOf(u8, run.response, "connection: close\r\n") != null);
		// NOTHING of the push reached the origin -- not the commands, not the pack
		try t.expectEqual(@as(usize, 0), refusing.calls);
		try t.expectEqual(@as(u64, 1), met.mediate);
		try t.expectEqual(@as(u64, 1), met.deny_gate3);
		try t.expectEqual(@as(u64, 0), met.allow);
		try t.expect(std.mem.indexOf(u8, run.audit, " gate=3 ") != null);
		try t.expect(std.mem.indexOf(u8, run.audit, " reason=ref_denied ") != null);
		try t.expect(std.mem.indexOf(u8, run.audit, " route=git-receive ") != null);
		try t.expect(std.mem.indexOf(u8, run.audit, " status=403 ") != null);
		// the audit never names a ref (the C04 rule: route ids, never request data)
		try t.expect(std.mem.indexOf(u8, run.audit, "refs/") == null);
	}
}

test "e2e: git's lone-flush probe body and an unparseable one -- one forwards, the other is a 400 with no dial" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try confJsonPush(&h);
	defer gpa.free(cj);

	// The probe POST git sends ahead of a chunked push is exactly `0000`: zero
	// commands is a legitimate parse and MUST relay, or every push over
	// http.postBuffer breaks.
	{
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		const req = try pushReq(gpa, pktline.flush_pkt);
		defer gpa.free(req);
		var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"});
		defer fake.deinit();
		var met = try serveMetered(gpa, h.io, gen, fake.t(), req);
		defer met.deinit(gpa);
		try t.expect(std.mem.startsWith(u8, met.run.response, "HTTP/1.1 200 OK\r\n"));
		// parsed by the mediate arm (zero commands is a PARSE, not a bypass) and
		// then relayed unchanged
		try t.expectEqual(@as(u64, 1), met.mediate);
		try t.expectEqual(@as(u64, 0), met.deny_gate3);
		try t.expectEqual(@as(usize, 1), fake.calls);
		try t.expectEqualStrings(pktline.flush_pkt, upstreamBody(fake.captured.items[0]));
	}
	// A body whose framing this proxy cannot read is a 400 -- never forwarded on
	// the theory that the origin will sort it out.
	{
		const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
		const req = try pushReq(gpa, "zzzz" ++ pktline.flush_pkt);
		defer gpa.free(req);
		var refusing = upstream.RefusingTransport{};
		var run = try serve(gpa, h.io, gen, refusing.t(), req);
		defer run.deinit(gpa);
		try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 400 "));
		try t.expect(std.ascii.indexOfIgnoreCase(run.response, "X-Cogbox-Deny: push_malformed") != null);
		try t.expectEqual(@as(usize, 0), refusing.calls);
	}
}

test "e2e: a chunked push is re-framed upstream with the buffered prefix intact" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try confJsonPush(&h);
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	// A push over http.postBuffer arrives chunked: the command section and the
	// pack land in separate chunks, and the guest's framing is never forwarded.
	const section = cmdSection(push_oid_a ++ " " ++ push_oid_b ++ " refs/heads/agent/deep/x\x00report-status");
	const pack = "PACK\x00\x02CHUNKEDPAYLOAD";
	const req = try std.fmt.allocPrint(gpa, "POST /grp/proj.git/git-receive-pack HTTP/1.1\r\n" ++
		"Host: git.example.com\r\n" ++
		"X-Cogbox-Host: git.example.com\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"Content-Type: application/x-git-receive-pack-request\r\n" ++
		"Transfer-Encoding: chunked\r\n\r\n" ++
		"{x}\r\n{s}\r\n{x}\r\n{s}\r\n0\r\n\r\n", .{ section.len, section, pack.len, pack });
	defer gpa.free(req);

	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"});
	defer fake.deinit();
	var met = try serveMetered(gpa, h.io, gen, fake.t(), req);
	defer met.deinit(gpa);

	try t.expect(std.mem.startsWith(u8, met.run.response, "HTTP/1.1 200 OK\r\n"));
	try t.expectEqual(@as(u64, 1), met.mediate);
	try t.expectEqual(@as(usize, 1), fake.calls);
	const up_req = fake.captured.items[0];
	// re-framed by the emitter (never the guest's chunk sizes), and no length
	try t.expect(std.mem.indexOf(u8, up_req, "transfer-encoding: chunked\r\n") != null);
	try t.expect(std.mem.indexOf(u8, up_req, "content-length:") == null);
	// ...and the CONTENT is the original stream: prefix first, then the pack
	const decoded = try dechunk(gpa, upstreamBody(up_req));
	defer gpa.free(decoded);
	try t.expectEqualStrings(section ++ pack, decoded);
}

test "e2e: a gate-3 deny with the body reader already taken closes the connection cleanly" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try confJsonPush(&h);
	defer gpa.free(cj);
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);

	// 40 KiB of packfile the verdict never reads: before this arm existed, no
	// deny had ever been taken after `readerExpectContinue` handed the body out,
	// and std's discard-and-reuse path asserts on a half-read body. keep_alive
	// is false, so that path is never entered -- and the unread tail must not be
	// parsed as a second request either.
	const body = cmdSection(push_oid_a ++ " " ++ push_oid_b ++ " refs/heads/main\x00report-status") ++
		("P" ** (40 * 1024));
	const req = try pushReq(gpa, body);
	defer gpa.free(req);
	var refusing = upstream.RefusingTransport{};
	var run = try serve(gpa, h.io, gen, refusing.t(), req);
	defer run.deinit(gpa);

	try t.expect(std.mem.startsWith(u8, run.response, "HTTP/1.1 403 "));
	try t.expect(std.mem.indexOf(u8, run.response, "connection: close\r\n") != null);
	try t.expect(std.mem.endsWith(u8, run.response, "\r\n\r\n")); // head only, empty body
	try t.expectEqual(@as(usize, 0), refusing.calls);
	// EXACTLY one request was served: the unread pack was not re-parsed
	try t.expectEqual(@as(usize, 1), std.mem.count(u8, run.audit, "authproxy request "));
	try t.expectEqual(@as(usize, 1), std.mem.count(u8, run.response, "HTTP/1.1 "));
}

test "e2e: a mediated push scrubs its credential too -- mediate_headers is inside the scratch block (S5 pin extension)" {
	const gpa = t.allocator;
	var h = try Harness.init(gpa);
	defer h.deinit();
	const cj = try confJsonPush(&h);
	defer gpa.free(cj);
	const raw_token = "glpat-FAKEFAKEFAKE";
	const basic_form = "b2F1dGgyOmdscGF0LUZBS0VGQUtFRkFLRQ==";

	var ra = RetainingAllocator{ .backing = gpa };
	defer ra.deinit();
	const gen = try conf.parseGeneration(gpa, h.io, cj, 1, .skip, null);
	var store = conf.Store.initStatic(gpa, h.io, gen);
	defer store.deinit();
	var fake = upstream.FakeTransport.init(gpa, &.{"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"});
	defer fake.deinit();

	const body = cmdSection(push_oid_a ++ " " ++ push_oid_b ++ " refs/heads/agent/x") ++ "PACKDATA";
	const req = try pushReq(gpa, body);
	defer gpa.free(req);
	// the request path (and the mediate hook's prefix buffer) allocate from ctx.gpa
	var ctx = main.Context{ .gpa = ra.allocator(), .io = h.io, .store = &store, .transport = fake.t() };
	var in = std.Io.Reader.fixed(req);
	var out = std.Io.Writer.Allocating.init(gpa);
	defer out.deinit();
	main.serveConnection(&ctx, &in, &out.writer);

	// positive control: the credential DID reach the origin through the mediate
	// leg's own header set
	try t.expect(std.mem.startsWith(u8, out.written(), "HTTP/1.1 200 OK\r\n"));
	try t.expect(std.mem.indexOf(u8, fake.captured.items[0], basic_form) != null);
	var saw_scratch = false;
	for (ra.retired.items) |r| {
		if (r.block.len >= @sizeOf(main.RequestScratch)) saw_scratch = true;
		try t.expect(std.mem.indexOf(u8, r.block, raw_token) == null);
		try t.expect(std.mem.indexOf(u8, r.block, basic_form) == null);
	}
	try t.expect(saw_scratch);
}
