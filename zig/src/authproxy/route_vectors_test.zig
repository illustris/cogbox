// The new engine's oracle harness. Drives the REAL request-side pipeline
// (canon.splitTarget + canon.canonicalize + canon.parseQuery) and the REAL
// gitlab plugin (classify + authorize), so a semantics change in either fails
// here -- exactly as path_vectors_test.zig does for the legacy matcher, but
// with the oracle re-stated for a route engine (addendum G.4).
//
// Kinds and per-kind floors keep the table honest: a typo'd kind is the one
// way it could stop asserting silently, so every row must be a known kind, and
// each kind carries a `seen >= N` floor.

const std = @import("std");
const t = std.testing;
const canon = @import("canon.zig");
const conf = @import("conf.zig");
const plugin_mod = @import("plugin.zig");

const vectors: []const u8 = @embedFile("route_vectors.tsv");

// --- grant fixtures, named by the table's authz rows ---
const fixtures = [_]struct { name: []const u8, json: []const u8 }{
	.{ .name = "full", .json = conf.test_conf_json },
	.{ .name = "inst-read", .json =
	\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2",
	\\"grants":[{"id":"gg-ir","scope":"instance","caps":["git-read"]}]}]}
	},
	.{ .name = "issues-only", .json =
	\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2",
	\\"grants":[{"id":"gg-io","scope":"instance","caps":["issues"]}]}]}
	},
	// A namespace grant carrying BOTH mr and git-read: mr drives the api-mr/
	// api-project rows, git-read the api-group-projects enumeration rows.
	.{ .name = "ns-mr", .json =
	\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2",
	\\"grants":[{"id":"gg-ns","scope":"namespace","repo":"grp/sub/*","prefix":"/grp/sub/","caps":["git-read","mr"],
	\\"projects":[{"id":42,"path":"grp/sub/a"},{"id":77,"path":"grp/sub/b"}]}]}]}
	},
	// A CONCRETE issues grant and nothing else: the api-project scope rows
	// (B2) need a fixture whose owner token can see more than the sandbox may.
	.{ .name = "proj-issues", .json =
	\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2",
	\\"grants":[{"id":"gg-pi","scope":"project","repo":"grp/proj","project_id":"1234","caps":["issues"]}]}]}
	},
};

const Row = struct {
	kind: []const u8,
	fields: [8][]const u8,
	n: usize,
};

fn rows(it: *std.mem.SplitIterator(u8, .scalar)) ?Row {
	while (it.next()) |raw| {
		const line = std.mem.trimEnd(u8, raw, " \r");
		if (line.len == 0 or line[0] == '#') continue;
		var f = std.mem.splitScalar(u8, line, '\t');
		var out = Row{ .kind = f.next() orelse continue, .fields = undefined, .n = 0 };
		while (f.next()) |v| {
			if (out.n == out.fields.len) break;
			out.fields[out.n] = v;
			out.n += 1;
		}
		return out;
	}
	return null;
}

fn methodOf(s: []const u8) ?std.http.Method {
	return std.meta.stringToEnum(std.http.Method, s);
}

// A parsed request, materialized from a raw target into caller buffers.
const ParsedReq = struct {
	seg_buf: [16 * 1024]u8 = undefined,
	segs: [canon.max_segments][]const u8 = undefined,
	nseg: usize = 0,
	key_buf: [8 * 1024]u8 = undefined,
	qbuf: [canon.max_query_params]canon.QueryParam = undefined,
	nq: usize = 0,
	refused: bool = false,

	fn parse(self: *ParsedReq, raw: []const u8) void {
		const target = canon.splitTarget(raw);
		switch (canon.canonicalize(target.path, &self.seg_buf, &self.segs)) {
			.ok => |n| self.nseg = n,
			.refuse => {
				self.refused = true;
				return;
			},
		}
		switch (canon.parseQuery(target.query, &self.key_buf, &self.qbuf)) {
			.ok => |n| self.nq = n,
			.refuse => self.refused = true,
		}
	}

	fn request(self: *ParsedReq, method: std.http.Method) plugin_mod.Request {
		return .{
			.method = method,
			.segments = self.segs[0..self.nseg],
			.query = self.qbuf[0..self.nq],
			.headers = &empty_headers,
			.content_type = null,
			.content_length = null,
			.body = null,
			.host = "git.example.com",
			.raw_target = "",
		};
	}
};
const empty_headers: plugin_mod.HeaderSet = .{};

test "route_vectors: canon rows split segment-first and decode once" {
	var it = std.mem.splitScalar(u8, vectors, '\n');
	var seen: usize = 0;
	var buf: [16 * 1024]u8 = undefined;
	var segs: [canon.max_segments][]const u8 = undefined;
	while (rows(&it)) |r| {
		if (!std.mem.eql(u8, r.kind, "canon")) continue;
		try t.expect(r.n >= 1);
		const target = canon.splitTarget(r.fields[0]);
		const res = canon.canonicalize(target.path, &buf, &segs);
		if (res != .ok) {
			std.debug.print("canon vector {s}: refused\n", .{r.fields[0]});
			return error.CanonRefused;
		}
		const want_n = r.n - 1;
		if (res.ok != want_n) {
			std.debug.print("canon vector {s}: got {d} segs, want {d}\n", .{ r.fields[0], res.ok, want_n });
			return error.SegmentCountMismatch;
		}
		var i: usize = 0;
		while (i < want_n) : (i += 1) {
			t.expectEqualStrings(r.fields[i + 1], segs[i]) catch |e| {
				std.debug.print("canon vector {s}: seg {d} mismatch\n", .{ r.fields[0], i });
				return e;
			};
		}
		seen += 1;
	}
	try t.expect(seen >= 12);
}

test "route_vectors: refuse rows are refused outright (by the path canonicalizer OR the query parser)" {
	var it = std.mem.splitScalar(u8, vectors, '\n');
	var seen: usize = 0;
	var query_refusals: usize = 0;
	while (rows(&it)) |r| {
		if (!std.mem.eql(u8, r.kind, "refuse")) continue;
		try t.expect(r.n >= 1);
		// The same request-side pipeline the core runs: canonicalize the path,
		// then parse the query. A row is refused iff either step refuses.
		var pr: ParsedReq = .{};
		pr.parse(r.fields[0]);
		if (!pr.refused) {
			std.debug.print("refuse vector {s}: ACCEPTED -- the decision path and the forwarded path can now differ\n", .{r.fields[0]});
			return error.CanonAccepted;
		}
		if (std.mem.indexOfScalar(u8, r.fields[0], '?') != null) query_refusals += 1;
		seen += 1;
	}
	try t.expect(seen >= 8);
	// At least one row must exercise the QUERY-side refusal (S7).
	try t.expect(query_refusals >= 1);
}

test "route_vectors: route rows classify to the expected route id" {
	const gpa = t.allocator;
	const g = try conf.parseGeneration(gpa, undefined, conf.test_conf_json, 1, .skip, null);
	defer {
		g.arena.deinit();
		gpa.destroy(g);
	}
	const policy = g.entries[0].policy;

	var it = std.mem.splitScalar(u8, vectors, '\n');
	var seen: usize = 0;
	while (rows(&it)) |r| {
		if (!std.mem.eql(u8, r.kind, "route")) continue;
		try t.expect(r.n >= 3);
		const method = methodOf(r.fields[0]) orelse return error.BadMethod;
		var pr: ParsedReq = .{};
		pr.parse(r.fields[1]);
		try t.expect(!pr.refused); // a refusing target belongs in a `refuse` row
		const req = pr.request(method);
		const got = policy.vtable.classify(policy.ctx, &req);
		const want = r.fields[2];
		if (std.mem.eql(u8, want, "-")) {
			if (got != null) {
				std.debug.print("route vector {s} {s}: expected gate-1 deny, got {s}\n", .{ r.fields[0], r.fields[1], got.?.id });
				return error.UnexpectedRoute;
			}
		} else {
			if (got == null) {
				std.debug.print("route vector {s} {s}: expected {s}, got no route\n", .{ r.fields[0], r.fields[1], want });
				return error.MissingRoute;
			}
			t.expectEqualStrings(want, got.?.id) catch |e| {
				std.debug.print("route vector {s} {s}: route mismatch\n", .{ r.fields[0], r.fields[1] });
				return e;
			};
		}
		seen += 1;
	}
	try t.expect(seen >= 20);
}

test "route_vectors: authz rows allow/deny under their fixture (incl. the six escape rows)" {
	const gpa = t.allocator;
	var gens: [fixtures.len]*conf.Generation = undefined;
	for (fixtures, 0..) |fx, i| {
		gens[i] = try conf.parseGeneration(gpa, undefined, fx.json, 1, .skip, null);
	}
	defer for (gens) |g| {
		g.arena.deinit();
		gpa.destroy(g);
	};

	var it = std.mem.splitScalar(u8, vectors, '\n');
	var seen: usize = 0;
	var escape_rows: usize = 0;
	while (rows(&it)) |r| {
		if (!std.mem.eql(u8, r.kind, "authz")) continue;
		try t.expect(r.n >= 4);
		const want_allow = std.mem.eql(u8, r.fields[0], "allow");
		if (!want_allow and !std.mem.eql(u8, r.fields[0], "deny")) return error.BadVerdict;
		const policy = fixturePolicy(&gens, r.fields[1]) orelse {
			std.debug.print("authz vector names unknown fixture {s}\n", .{r.fields[1]});
			return error.UnknownFixture;
		};
		const method = methodOf(r.fields[2]) orelse return error.BadMethod;
		var pr: ParsedReq = .{};
		pr.parse(r.fields[3]);
		try t.expect(!pr.refused);
		const req = pr.request(method);

		var got_allow = false;
		if (policy.vtable.classify(policy.ctx, &req)) |route| {
			got_allow = policy.vtable.authorize(policy.ctx, &route, &req) == .allow;
		}
		if (got_allow != want_allow) {
			std.debug.print("authz vector [{s}] {s} {s} {s}: want {s}, got {s}\n", .{
				r.fields[1],                         r.fields[0],                        r.fields[2], r.fields[3],
				if (want_allow) "allow" else "deny", if (got_allow) "allow" else "deny",
			});
			return error.AuthzMismatch;
		}
		if (r.n > 4 and std.mem.startsWith(u8, r.fields[4], ":")) escape_rows += 1;
		seen += 1;
	}
	try t.expect(seen >= 20);
	// The labelled six-escape block must all be present and all deny.
	try t.expect(escape_rows >= 6);
}

fn fixturePolicy(gens: *const [fixtures.len]*conf.Generation, name: []const u8) ?plugin_mod.Policy {
	inline for (fixtures, 0..) |fx, i| {
		if (std.mem.eql(u8, fx.name, name)) return gens[i].entries[0].policy;
	}
	return null;
}

test "route_vectors: every row is a known kind" {
	var it = std.mem.splitScalar(u8, vectors, '\n');
	while (rows(&it)) |r| {
		if (std.mem.eql(u8, r.kind, "canon") or std.mem.eql(u8, r.kind, "refuse") or
			std.mem.eql(u8, r.kind, "route") or std.mem.eql(u8, r.kind, "authz")) continue;
		std.debug.print("unknown vector kind {s}\n", .{r.kind});
		return error.UnknownVectorKind;
	}
}
