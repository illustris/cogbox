// The per-service plugin interface: a comptime-registered vtable over
// `*const anyopaque`, chosen so forgejo and harbor slot in with NO interface
// change (spec §3) -- the shape is exhaustively known at compile time, needs no
// allocator for dispatch, and makes `mediate` / `onUpstreamStatus` genuinely
// ABSENT (null) rather than no-op implementations, which is what the contract
// says and what a reviewer can check by looking for a null.
//
// Hook discipline (spec §3.1): `classify` and `authorize` are PURE -- no IO, no
// credential, no allocation. `upstream` CONSTRUCTS the upstream request into
// caller-provided fixed buffers; the core then refuses any host not equal to
// the conf entry's -- a gate the plugin cannot bypass. `authenticate` SETS
// headers, never appends. A plugin that reads `Request.raw_target` for a
// decision is a review finding: that field exists for audit only.

const std = @import("std");
const canon = @import("canon.zig");
const conf = @import("conf.zig");
const upstream_mod = @import("upstream.zig");

pub const Scheme = enum { http, https };

pub const CompileError = error{ InvalidEntry, OutOfMemory };
pub const UpstreamError = error{Overflow};
pub const AuthError = error{ CredentialUnavailable, AuthFailed };
pub const MediateError = error{ CredentialUnavailable, UpstreamFailed, MediateFailed };
/// A `localResponse` render fails only when the caller's BOUNDED body writer
/// overflows -- the core turns that into a 500 (never a partial body).
pub const LocalError = std.Io.Writer.Error;

pub const Plugin = struct {
	/// Must equal the doc's "plugin" value. Selection is exact match; an
	/// unknown value fails the whole conf load, and every host is then
	/// refused (fail closed, addendum F.1 step 5).
	name: []const u8,
	/// Called once per conf generation, on that generation's arena. MUST fail
	/// on anything it does not fully understand (unknown cap, unknown scope,
	/// missing required field) -- the core then refuses. No IO.
	compile: *const fn (arena: std.mem.Allocator, entry: *const conf.Entry) CompileError!Policy,
};

pub const Policy = struct {
	ctx: *const anyopaque, // the plugin's compiled, immutable policy; arena-owned
	vtable: *const VTable,

	pub const VTable = struct {
		// gate 1: routing. PURE. No IO, no credential. null => the core denies
		// with `no_route`.
		classify: *const fn (ctx: *const anyopaque, req: *const Request) ?Route,
		// gate 2: authorization. PURE. Evaluated over the compiled policy only,
		// never over raw grant rows, never over a live lookup in v1.
		authorize: *const fn (ctx: *const anyopaque, route: *const Route, req: *const Request) Decision,
		// the upstream request, CONSTRUCTED, never copied. scheme/host come from
		// the entry's config; path/query are rebuilt from the route's typed
		// params and the route's query allowlist.
		upstream: *const fn (ctx: *const anyopaque, route: *const Route, req: *const Request, out: *Upstream) UpstreamError!void,
		// the simple credential case. Headers to SET (never append) on the
		// upstream request. cred.token() reads the store file lazily.
		authenticate: *const fn (ctx: *const anyopaque, route: *const Route, req: *const Request, cred: *Cred, out: *HeaderSet) AuthError!void,
		// the INLINE data-plane case (harbor's token dance; gitlab's push-rule
		// body inspection). null == "use the default single round trip" --
		// absent, not a no-op implementation. Returning false also falls back to
		// the default round trip, with the body reader UNTOUCHED -- which is
		// what makes gitlab's fast path (no grant carries rules) byte-identical
		// to the unmediated relay. Returning true with `out.deny` set is a
		// pre-dial refusal (gate 3).
		mediate: ?*const fn (ctx: *const anyopaque, route: *const Route, req: *const Request, cred: *Cred, io: *upstream_mod.UpstreamIO, out: *Response) MediateError!bool = null,
		// derived-token invalidation (drop a plugin-minted token on 401).
		// null == none.
		onUpstreamStatus: ?*const fn (ctx: *const anyopaque, route: *const Route, status: u16, headers: *const HeaderSet, cred: *Cred) void = null,
		// the LOCAL-answer case (a Route the plugin's classify marked `local`):
		// the plugin RENDERS the whole response body from its compiled policy
		// into the caller's BOUNDED writer, and the core relays it as a 200 with
		// NO upstream leg and NO credential use -- the self-discovery reflection
		// surface (gitlab's /_cogbox/grants). null == the plugin exposes no local
		// routes; a non-null hook is REQUIRED once its classify can set
		// Route.local (a local route with no renderer is the core's 500). PURE
		// over the compiled policy, like authorize: no IO, no credential.
		localResponse: ?*const fn (ctx: *const anyopaque, route: *const Route, req: *const Request, out: *std.Io.Writer) LocalError!void = null,
	};
};

/// Comptime, exhaustive: every plugin is analyzed by `zig build test`, and an
/// entry naming anything else fails the conf load.
pub const registry = [_]Plugin{@import("plugins/gitlab.zig").plugin};

pub fn find(name: []const u8) ?*const Plugin {
	inline for (&registry) |*p| {
		if (std.mem.eql(u8, p.name, name)) return p;
	}
	return null;
}

/// The core's canonical value object -- the ONLY view a plugin gets of the
/// request. Headers have already been stripped and allowlisted by the core.
pub const Request = struct {
	method: std.http.Method,
	/// Segment-first, single-decoded (canon.zig). A segment MAY contain '/'.
	segments: []const []const u8,
	/// Parsed once at the first '?', never re-concatenated unparsed.
	query: []const canon.QueryParam,
	/// The allowlisted inbound headers.
	headers: *const HeaderSet,
	content_type: ?[]const u8,
	content_length: ?u64,
	/// Bounded body reader; null when the framing proved there is no body.
	body: ?*std.Io.Reader,
	/// From X-Cogbox-Host, cross-checked equal to the Host header.
	host: []const u8,
	/// AUDIT ONLY. A plugin that reads this for a decision is a review finding.
	raw_target: []const u8,
};

pub const Layer = enum { git, api };
pub const MethodClass = enum { read, write };
pub const Service = enum { upload_pack, receive_pack };

pub const ProjectId = union(enum) {
	numeric: i64,
	path: []const u8,
};

/// Typed route parameters. Extracted by `classify`; `upstream` rebuilds the
/// forwarded path from these, never from the raw target.
pub const Params = struct {
	/// API routes' `:id` (numeric or single-segment path form).
	project: ?ProjectId = null,
	/// git routes' project reference, viewed as flattened path components: the
	/// leading canonicalized segments (which may each contain `/`) up to the
	/// recognized suffix, plus the final segment with `.git` stripped. Empty
	/// last means "not a git route".
	project_ref_segs: []const []const u8 = &.{},
	project_ref_last: []const u8 = "",
	/// git-refs only: the validated `?service=`; null == absent/duplicated/
	/// invalid, which authorize turns into `service_invalid`.
	service: ?Service = null,
	/// api-archive only: the validated extension (from a closed set), or null
	/// for the bare `archive` form.
	archive_ext: ?[]const u8 = null,
	/// API subtree routes: the segments after the collection segment,
	/// re-emitted (re-encoded) by `upstream`.
	rest: []const []const u8 = &.{},
};

pub const Route = struct {
	/// The audit label: a stable literal, never a formatted path.
	id: []const u8,
	layer: Layer,
	method_class: MethodClass,
	params: Params,
	/// Body-bearing bulk route (git pack, archive): no total response
	/// deadline, idle timeout only.
	stream: bool,
	/// The core projects this route's SUCCESS response body through the
	/// ProjectSimpleEntity allowlist before relaying it (main.zig
	/// projectProjectResponse): a single-project GET returns GitLab's FULL
	/// project object -- `runners_token` and other secret fields -- which
	/// `simple=true` does NOT strip on a single-project GET. Set TRUE only on
	/// api-project; every other route streams its body unfiltered.
	project_response: bool = false,
	/// A LOCAL-answer route: the core answers it from the plugin's
	/// `localResponse` hook -- rendering the body from the compiled policy --
	/// with NO upstream leg and NO credential use, then closes the connection
	/// (the deny path's local-answer idiom, a body instead of empty). Set TRUE
	/// only on a self-discovery reflection route (gitlab's /_cogbox/grants);
	/// authorize still runs (the method clamp), but `upstream`/`authenticate`
	/// never do.
	local: bool = false,
};

pub const DenyReason = enum {
	no_route,
	no_grant,
	cap_missing,
	scope_mismatch,
	method_not_allowed,
	service_invalid,
	// The four a `mediate` hook can reach, all of them decided over a request
	// BODY and all of them BEFORE any dial (gate 3): a pushed ref the grant's
	// push rules do not admit, a receive-pack command section this proxy cannot
	// parse, one larger than the bounded prefix (or with more commands than the
	// cap), and a signed push, whose commands live inside a certificate the
	// rules cannot be evaluated over.
	ref_denied,
	push_malformed,
	too_many_refs,
	push_cert_unsupported,
};

pub const Decision = union(enum) {
	allow: []const u8, // grant id
	deny: DenyReason,
};

/// Fixed-capacity header set with inline value storage (filter.L7Rule's
/// buffer style): the request path allocates nothing on the heap. `set`
/// replaces an existing name (case-insensitive) rather than appending;
/// `append` keeps every copy (a response's repeated `Vary:` /
/// `WWW-Authenticate:` lines are each meaningful).
///
/// NOT copy-safe by struct assignment: every name/value slice points into
/// the set's OWN `storage`, so `a = b` leaves `a` reading `b`'s buffer -- a
/// use-after-scope the moment `b` dies first. Copy with `copyFrom`.
///
/// 64 slots, not 32: the response relay REFUSES an over-capacity origin head
/// whole (upstream.Error.BadResponseHeader) rather than dropping a tail, and
/// a header-rich provider (pagination, rate-limit and security headers on
/// one API response) sits near 30 -- the headroom keeps that refusal for the
/// pathological head, never the honest one. The head itself is bounded at
/// framing.max_head_bytes, so `storage` always holds every byte of a head
/// that fits.
pub const max_headers = 64;
pub const max_header_storage = 16 * 1024;

pub const HeaderSet = struct {
	storage: [max_header_storage]u8 = undefined,
	used: usize = 0,
	names: [max_headers][]const u8 = undefined,
	values: [max_headers][]const u8 = undefined,
	len: usize = 0,

	pub const Error = error{HeaderSetFull};

	pub fn set(self: *HeaderSet, name: []const u8, value: []const u8) Error!void {
		// Scan BEFORE copying anything in: a replacement re-homes only the new
		// value (the name slice already lives here), so repeated sets of one
		// name cannot exhaust the storage with dead name copies.
		var i: usize = 0;
		while (i < self.len) : (i += 1) {
			if (std.ascii.eqlIgnoreCase(self.names[i], name)) {
				if (self.used + value.len > self.storage.len) return error.HeaderSetFull;
				self.values[i] = self.copyIn(value); // SET semantics: replace, never append
				return;
			}
		}
		return self.append(name, value);
	}

	/// APPEND semantics: a second entry under an existing name is kept, in
	/// order. For sets that must preserve multi-valued headers verbatim (the
	/// relayed response head); `get` still answers the FIRST match.
	pub fn append(self: *HeaderSet, name: []const u8, value: []const u8) Error!void {
		if (self.len >= max_headers) return error.HeaderSetFull;
		if (self.used + name.len + value.len > self.storage.len) return error.HeaderSetFull;
		self.names[self.len] = self.copyIn(name);
		self.values[self.len] = self.copyIn(value);
		self.len += 1;
	}

	/// Re-home `other`'s entries into this set's own storage (the copy that
	/// struct assignment does NOT do -- see the type comment). Entries and
	/// their order are preserved exactly, duplicates included. Cannot fail:
	/// the live bytes of a set never exceed one set's capacity. `other` must
	/// not alias `self`: the copy resets this set's storage cursor before it
	/// walks `other`'s slices, so an in-place compaction would @memcpy each
	/// value over itself.
	pub fn copyFrom(self: *HeaderSet, other: *const HeaderSet) void {
		std.debug.assert(self != other);
		self.used = 0;
		self.len = 0;
		var i: usize = 0;
		while (i < other.len) : (i += 1) {
			self.append(other.names[i], other.values[i]) catch unreachable;
		}
	}

	pub fn get(self: *const HeaderSet, name: []const u8) ?[]const u8 {
		var i: usize = 0;
		while (i < self.len) : (i += 1) {
			if (std.ascii.eqlIgnoreCase(self.names[i], name)) return self.values[i];
		}
		return null;
	}

	/// Drop the FIRST entry named `name` (case-insensitive), shifting the tail
	/// down; a no-op if absent. Used to strip a forwarded request header the
	/// core must not send on a particular route (the api-project projection
	/// removes `range`/`accept-encoding` so the origin returns a full,
	/// identity-encoded 200 the projection can parse and never a 206 it would
	/// skip). The dropped value's bytes stay in `storage` (unreferenced); a set
	/// later scrubbed by `zeroize` zeroes them with the rest.
	pub fn remove(self: *HeaderSet, name: []const u8) void {
		var i: usize = 0;
		while (i < self.len) : (i += 1) {
			if (std.ascii.eqlIgnoreCase(self.names[i], name)) {
				var j = i;
				while (j + 1 < self.len) : (j += 1) {
					self.names[j] = self.names[j + 1];
					self.values[j] = self.values[j + 1];
				}
				self.len -= 1;
				return;
			}
		}
	}

	/// Zero the storage (a set that carried an Authorization value is scrubbed
	/// before the worker frame is reused).
	pub fn zeroize(self: *HeaderSet) void {
		std.crypto.secureZero(u8, self.storage[0..self.used]);
		self.used = 0;
		self.len = 0;
	}

	fn copyIn(self: *HeaderSet, bytes: []const u8) []const u8 {
		const start = self.used;
		@memcpy(self.storage[start .. start + bytes.len], bytes);
		self.used += bytes.len;
		return self.storage[start .. start + bytes.len];
	}
};

/// The constructed upstream request target. Fixed inline buffers, filled by
/// the plugin's `upstream` hook; the socket target (ip:port) is NOT here -- it
/// comes only from X-Cogbox-Vetted, and the core refuses any `host` that is
/// not the conf entry's.
pub const max_upstream_path = 4096;
pub const max_upstream_query = 4096;

pub const Upstream = struct {
	scheme: Scheme = .http,
	host: []const u8 = "",
	/// 0 == "the vetted port". No conf element carries a port (addendum I.2
	/// item 11): the socket target's port is X-Cogbox-Vetted's, already gated
	/// by l7proxy.
	port: u16 = 0,
	path_buf: [max_upstream_path]u8 = undefined,
	path_len: u16 = 0,
	query_buf: [max_upstream_query]u8 = undefined,
	query_len: u16 = 0,

	pub fn appendPath(self: *Upstream, bytes: []const u8) UpstreamError!void {
		if (self.path_len + bytes.len > self.path_buf.len) return error.Overflow;
		@memcpy(self.path_buf[self.path_len .. self.path_len + bytes.len], bytes);
		self.path_len += @intCast(bytes.len);
	}

	pub fn appendQuery(self: *Upstream, bytes: []const u8) UpstreamError!void {
		if (self.query_len + bytes.len > self.query_buf.len) return error.Overflow;
		@memcpy(self.query_buf[self.query_len .. self.query_len + bytes.len], bytes);
		self.query_len += @intCast(bytes.len);
	}

	pub fn path(self: *const Upstream) []const u8 {
		return self.path_buf[0..self.path_len];
	}

	pub fn query(self: *const Upstream) []const u8 {
		return self.query_buf[0..self.query_len];
	}
};

/// Lazy handle on the owner credential. Reading goes through the core's
/// mtime-cached store-file reader; failure (EACCES, ENOENT, unbound, revoked
/// grant) is `error.CredentialUnavailable` and the core answers 403 --
/// never a fallthrough that forwards the guest's stub as if it were auth.
pub const Cred = struct {
	ctx: *anyopaque,
	tokenFn: *const fn (ctx: *anyopaque) TokenError![]const u8,

	pub const TokenError = error{CredentialUnavailable};

	pub fn token(self: *Cred) TokenError![]const u8 {
		return self.tokenFn(self.ctx);
	}
};

/// A mediate plugin's final answer: EITHER the last upstream leg's exchange,
/// handed back still-open so the core streams its body downstream through the
/// same relay the default path uses, OR a deny the hook decided on its own.
///
/// `deny` is the seam gitlab's push rules need: the verdict is reached over the
/// request BODY, which only `mediate` sees, and it must be reached BEFORE any
/// dial -- a rejected push must not reach the origin at all. It is a
/// `@tagName(DenyReason)` (the fixed vocabulary `X-Cogbox-Deny` and the audit
/// line share), never free text; the core answers it as gate 3. A hook that
/// sets both is denied: fail closed.
pub const Response = struct {
	exchange: ?*upstream_mod.Exchange = null,
	deny: ?[]const u8 = null,
	deny_status: u16 = 403,
};

// --- Tests ---

const t = std.testing;

test "HeaderSet: set replaces case-insensitively, get is case-insensitive" {
	var h: HeaderSet = .{};
	try h.set("Authorization", "Bearer a");
	try h.set("Accept", "*/*");
	try h.set("authorization", "Bearer b"); // SET semantics: replaces
	try t.expectEqual(@as(usize, 2), h.len);
	try t.expectEqualStrings("Bearer b", h.get("AUTHORIZATION").?);
	try t.expectEqualStrings("*/*", h.get("accept").?);
	try t.expect(h.get("cookie") == null);
	h.zeroize();
	try t.expectEqual(@as(usize, 0), h.len);
	try t.expect(h.get("accept") == null);
}

test "HeaderSet: append keeps duplicates in order; set's replacement re-homes only the value (N3)" {
	var h: HeaderSet = .{};
	try h.append("vary", "Accept-Encoding");
	try h.append("Vary", "Cookie");
	try h.append("www-authenticate", "Bearer realm=\"a\"");
	try t.expectEqual(@as(usize, 3), h.len);
	try t.expectEqualStrings("Accept-Encoding", h.values[0]);
	try t.expectEqualStrings("Cookie", h.values[1]);
	try t.expectEqualStrings("Accept-Encoding", h.get("VARY").?); // first match
	// set on an existing name replaces (never appends) and copies ONLY the
	// value: 1000 replacements of a 4-byte value cost 4 KiB of storage, not
	// 1000 x (name + value), so the set cannot be exhausted by repetition.
	var s: HeaderSet = .{};
	try s.set("authorization", "Bearer a");
	const used_after_first = s.used;
	var i: usize = 0;
	while (i < 1000) : (i += 1) try s.set("Authorization", "Bearer b");
	try t.expectEqual(@as(usize, 1), s.len);
	try t.expectEqual(used_after_first + 1000 * "Bearer b".len, s.used);
	// capacity: the (max_headers+1)th distinct name is refused, the set left intact
	var full: HeaderSet = .{};
	var nb: [8]u8 = undefined;
	i = 0;
	while (i < max_headers) : (i += 1) {
		try full.append(std.fmt.bufPrint(&nb, "x-{d}", .{i}) catch unreachable, "v");
	}
	try t.expectError(error.HeaderSetFull, full.append("x-overflow", "v"));
	try t.expectEqual(@as(usize, max_headers), full.len);
}

test "HeaderSet: copyFrom re-homes the slices; struct assignment does not (N4)" {
	var src: HeaderSet = .{};
	try src.set("accept", "*/*");
	try src.append("vary", "a");
	try src.append("vary", "b");
	var by_assign: HeaderSet = undefined;
	by_assign = src;
	var by_copy: HeaderSet = .{};
	by_copy.copyFrom(&src);
	// the assigned copy's slices still point into src.storage...
	try t.expect(@intFromPtr(by_assign.values[0].ptr) >= @intFromPtr(&src.storage));
	try t.expect(@intFromPtr(by_assign.values[0].ptr) < @intFromPtr(&src.storage) + src.storage.len);
	// ...the re-homed copy's point into its OWN storage
	var i: usize = 0;
	while (i < by_copy.len) : (i += 1) {
		for ([_][]const u8{ by_copy.names[i], by_copy.values[i] }) |sl| {
			try t.expect(@intFromPtr(sl.ptr) >= @intFromPtr(&by_copy.storage));
			try t.expect(@intFromPtr(sl.ptr) + sl.len <= @intFromPtr(&by_copy.storage) + by_copy.used);
		}
	}
	// so scrubbing the source leaves the copy intact, order and duplicates kept
	src.zeroize();
	try t.expectEqual(@as(usize, 3), by_copy.len);
	try t.expectEqualStrings("*/*", by_copy.get("accept").?);
	try t.expectEqualStrings("a", by_copy.values[1]);
	try t.expectEqualStrings("b", by_copy.values[2]);
	// copyFrom over a populated set replaces it wholesale
	var again: HeaderSet = .{};
	try again.set("stale", "x");
	again.copyFrom(&by_copy);
	try t.expect(again.get("stale") == null);
	try t.expectEqual(@as(usize, 3), again.len);
}

test "HeaderSet: remove drops the first match, shifts the tail, is a no-op when absent (api-project strip)" {
	var h: HeaderSet = .{};
	try h.append("accept", "*/*");
	try h.append("accept-encoding", "gzip");
	try h.append("range", "bytes=0-1");
	try h.append("user-agent", "git/2.43");
	try t.expectEqual(@as(usize, 4), h.len);
	h.remove("Accept-Encoding"); // case-insensitive
	try t.expectEqual(@as(usize, 3), h.len);
	try t.expect(h.get("accept-encoding") == null);
	// order preserved, the tail shifted down over the removed slot
	try t.expectEqualStrings("accept", h.names[0]);
	try t.expectEqualStrings("range", h.names[1]);
	try t.expectEqualStrings("user-agent", h.names[2]);
	// removing an absent name is a no-op, the remaining values intact
	h.remove("if-none-match");
	try t.expectEqual(@as(usize, 3), h.len);
	try t.expectEqualStrings("bytes=0-1", h.get("range").?);
	try t.expectEqualStrings("git/2.43", h.get("user-agent").?);
}

test "Upstream: fixed-buffer append with overflow refusal" {
	var u: Upstream = .{};
	try u.appendPath("/api/v4/projects/");
	try u.appendPath("grp%2Fproj");
	try t.expectEqualStrings("/api/v4/projects/grp%2Fproj", u.path());
	try u.appendQuery("service=git-upload-pack");
	try t.expectEqualStrings("service=git-upload-pack", u.query());
	const big: [max_upstream_path]u8 = @splat('x');
	try t.expectError(error.Overflow, u.appendPath(&big));
}

test "registry: gitlab is present and found by exact match only" {
	try t.expect(find("gitlab") != null);
	try t.expect(find("GitLab") == null);
	try t.expect(find("gitlab2") == null);
	try t.expect(find("") == null);
}
