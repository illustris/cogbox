// cogbox __authproxy <runtime-dir> [<l7-base>]
//
// The per-sandbox auth proxy: one process per sandbox, inline on the data
// path, pluggable per service (gitlab is plugin #1). mitmproxy on loopback
// retargets migrated hosts here; the core does framing, canonicalization,
// the reserved-header cross-check, the header allowlists, streaming, the
// credential-file reads, the audit line and the counters, and the plugin
// classifies -> authorizes -> constructs the upstream -> authenticates (or
// mediates). NO upstream field is ever derived from the request: scheme and
// Host come from the conf, the socket target only from X-Cogbox-Vetted.
//
// The server path is transport-agnostic over *std.Io.Reader / *std.Io.Writer
// (std.http.Server), so `serveConnection` is unit-testable end to end with
// in-memory streams and a fake upstream behind the UpstreamIO seam -- no
// sockets, no fixture process (addendum G.2). The production listener wraps
// real fds around exactly that core.

const std = @import("std");
const builtin = @import("builtin");
const filter = @import("filter");
const framing = @import("framing.zig");
const canon = @import("canon.zig");
const conf = @import("conf.zig");
const plugin_mod = @import("plugin.zig");
const upstream = @import("upstream.zig");

pub const max_conns: usize = 64;
pub const max_inflight: u32 = 8;
const inflight_wait_ms: i64 = 5000;
const inbound_buf_len: usize = 32 * 1024; // must exceed max_head_bytes
/// C.4: the request head must arrive within this bound. Re-armed on the
/// inbound socket before EVERY head read (a body relay re-arms it to the
/// idle bound in between).
pub const read_header_timeout_secs: i32 = 10;
/// C.4: API routes get a TOTAL relay deadline, started ahead of the request
/// body upload and spanning both directions (UpstreamIO checks it between
/// upload slices, streamResponse between response slices); stream routes (git
/// pack, archive, registry blob) get none -- only the idle bound the sockets
/// carry, because a multi-GB pack is legitimate.
pub const api_relay_total_ms: i64 = 60_000;
/// H#27: the counters rollup cadence. A line is emitted only when the request
/// counter moved since the last one.
pub const stats_interval_ms: i64 = 60_000;
/// COGBOX_L7_AUTH_DEBUG_PATH: the raw path is capped at this many SOURCE
/// bytes before quoting.
pub const debug_path_cap: usize = 256;

// --- counters (spec §7): a periodic rollup, no scrape path ---
pub const Counters = struct {
	requests: std.atomic.Value(u64) = .init(0),
	allow: std.atomic.Value(u64) = .init(0),
	deny_gate1: std.atomic.Value(u64) = .init(0),
	deny_gate2: std.atomic.Value(u64) = .init(0),
	cred_unavailable: std.atomic.Value(u64) = .init(0),
	upstream_err: std.atomic.Value(u64) = .init(0),
	mediate: std.atomic.Value(u64) = .init(0),

	pub fn rollup(self: *const Counters, w: *std.Io.Writer) !void {
		try w.print("authproxy stats requests={d} allow={d} deny_gate1={d} deny_gate2={d} cred_unavailable={d} upstream_err={d} mediate={d}\n", .{
			self.requests.load(.monotonic),         self.allow.load(.monotonic),
			self.deny_gate1.load(.monotonic),       self.deny_gate2.load(.monotonic),
			self.cred_unavailable.load(.monotonic), self.upstream_err.load(.monotonic),
			self.mediate.load(.monotonic),
		});
	}
};

/// One place gate/decision/reason are assembled for the audit line, so the
/// vocabulary stays a fixed enum and never free text.
const Outcome = struct {
	/// The matched entry's plugin name (H#26), "-" before an entry is selected.
	plugin: []const u8 = "-",
	method: []const u8 = "-",
	decision: enum { allow, deny } = .deny,
	gate: u8 = 0, // 0 = framing/canon (pre-plugin), 1 = classify, 2 = authorize
	reason: []const u8 = "-",
	route_id: []const u8 = "-",
	service: []const u8 = "-",
	grant: []const u8 = "-",
	status: u16 = 0,
	bytes_in: u64 = 0,
	bytes_out: u64 = 0,
};

/// Per-request audit metadata carried through every exit path: the request
/// id, its start time (the audit line's dur_ms) and -- under
/// COGBOX_L7_AUTH_DEBUG_PATH only -- the redacted, quoted raw path.
const ReqMeta = struct {
	id: u64,
	started_ms: i64,
	debug_path: []const u8 = "",
};

pub const Context = struct {
	gpa: std.mem.Allocator,
	io: std.Io,
	store: *conf.Store,
	transport: *const upstream.Transport,
	/// null => stderr via std.debug.print (production); a writer in tests
	/// (addendum G.2: the audit line through an injectable writer). The
	/// counters rollup rides the same writer.
	audit: ?*std.Io.Writer = null,
	counters: Counters = .{},
	/// COGBOX_L7_AUTH_DEBUG_PATH: include a quoted, length-capped raw path
	/// with every query VALUE dropped except `service`. Off by default; never
	/// on in production without the operator setting it.
	debug_path: bool = false,
	/// Socket-timeout re-arm for the INBOUND socket (C.4). The production
	/// listener arms real fds; tests substitute a recorder to pin the call
	/// sites (their in-memory streams have no socket, so they pass sock=null
	/// or a placeholder fd the recorder never touches).
	arm_socket: *const fn (fd: c_int, secs: i32) void = upstream.setSocketTimeouts,
	/// The clock behind the C.4 total deadline and the audit line's dur_ms.
	/// Tests substitute one that jumps, so a trickled upload crosses the
	/// deadline without anyone waiting a minute.
	now_ms: *const fn (io: std.Io) i64 = upstream.nowMs,
	inflight: std.atomic.Value(u32) = .init(0),
	reqid: std.atomic.Value(u64) = .init(0),
	stats_last_ms: i64 = std.math.minInt(i64),
	stats_last_requests: u64 = 0,

	fn acquireInflight(self: *Context) bool {
		var waited: i64 = 0;
		while (true) {
			const cur = self.inflight.load(.monotonic);
			if (cur < max_inflight) {
				if (self.inflight.cmpxchgWeak(cur, cur + 1, .acq_rel, .monotonic) == null) return true;
				continue;
			}
			if (waited >= inflight_wait_ms) return false;
			sleepMs(1);
			waited += 1;
		}
	}

	fn releaseInflight(self: *Context) void {
		_ = self.inflight.fetchSub(1, .acq_rel);
	}

	fn armInbound(self: *Context, sock: ?c_int, secs: i32) void {
		if (sock) |fd| self.arm_socket(fd, secs);
	}

	/// The H#27 rollup, on the accept-loop tick: at most once per
	/// stats_interval_ms, and only when the request counter moved -- an idle
	/// sandbox emits nothing. Returns whether a line was emitted.
	pub fn maybeEmitStats(self: *Context, now_ms: i64) bool {
		if (self.stats_last_ms != std.math.minInt(i64) and now_ms - self.stats_last_ms < stats_interval_ms) return false;
		self.stats_last_ms = now_ms;
		const requests = self.counters.requests.load(.monotonic);
		if (requests == self.stats_last_requests) return false;
		self.stats_last_requests = requests;
		if (self.audit) |w| {
			self.counters.rollup(w) catch {};
		} else if (!builtin.is_test) {
			var buf: [256]u8 = undefined;
			var fw: std.Io.Writer = .fixed(&buf);
			self.counters.rollup(&fw) catch {};
			std.debug.print("{s}", .{fw.buffered()});
		}
		return true;
	}

	/// The audit line: ONE line per request, metadata only, and the C04 wart
	/// avoided by construction -- the matched ROUTE ID, never the raw path;
	/// coarse reasons from a fixed enum; never a credential byte, a header
	/// value or a body byte. A raw path appears only under
	/// COGBOX_L7_AUTH_DEBUG_PATH, quoted and capped, with query VALUES dropped
	/// (except `service`).
	fn finishAudit(self: *Context, m: *const ReqMeta, host: []const u8, o: Outcome) void {
		const dur_ms: i64 = @max(0, self.now_ms(self.io) - m.started_ms);
		if (self.audit) |w| {
			writeAudit(w, m, host, o, dur_ms) catch {};
		} else if (!builtin.is_test) {
			// One print call so a line can never interleave with another
			// worker's; the buffer holds the longest line the fields allow.
			var buf: [2048]u8 = undefined;
			var fw: std.Io.Writer = .fixed(&buf);
			writeAudit(&fw, m, host, o, dur_ms) catch {};
			std.debug.print("{s}", .{fw.buffered()});
		}
	}

	fn writeAudit(w: *std.Io.Writer, m: *const ReqMeta, host: []const u8, o: Outcome, dur_ms: i64) !void {
		try w.print("authproxy request id={d} host={s} plugin={s} method={s} route={s} service={s} decision={s} gate={d} reason={s} grant={s} status={d} bytes_in={d} bytes_out={d} dur_ms={d}", .{
			m.id, host, o.plugin, o.method, o.route_id, o.service, @tagName(o.decision), o.gate, o.reason, o.grant, o.status, o.bytes_in, o.bytes_out, dur_ms,
		});
		if (m.debug_path.len > 0) try w.print(" path={s}", .{m.debug_path});
		try w.writeAll("\n");
	}
};

/// Serve one connection to completion: a keep-alive loop of framed requests
/// over `in`/`out`. Any framing refusal (or any per-request error) responds
/// with keep_alive=false and ends the connection -- which is also what makes
/// std's bare-LF head/body boundary ambiguity unexploitable and side-steps
/// the Server.zig bodiless-POST assert (it lives in the keep-alive branch).
pub fn serveConnection(ctx: *Context, in: *std.Io.Reader, out: *std.Io.Writer) void {
	serveConnectionOn(ctx, in, out, null);
}

/// serveConnection with the inbound socket named: its SO_RCVTIMEO/SO_SNDTIMEO
/// are re-armed per phase (C.4) -- the head bound before every head read, the
/// idle bound for the body relay. `null` (the in-memory tests) arms nothing.
pub fn serveConnectionOn(ctx: *Context, in: *std.Io.Reader, out: *std.Io.Writer, sock: ?c_int) void {
	var server = std.http.Server.init(in, out);
	server.reader.max_head_len = framing.max_head_bytes;
	while (true) {
		ctx.armInbound(sock, read_header_timeout_secs);
		var request = server.receiveHead() catch |err| switch (err) {
			error.HttpConnectionClosing => return, // clean keep-alive close
			error.HttpHeadersOversize => {
				// std's own head bound (max_head_len): the same client condition
				// handleRequest's copy guard answers, so the same 431 -- which
				// std's doc for this error also suggests.
				writeCannedError(out, .request_header_fields_too_large);
				return;
			},
			else => {
				// A head std itself rejected: 400 and close.
				writeCannedError(out, .bad_request);
				return;
			},
		};
		const keep_alive = handleRequest(ctx, &request, sock) catch false;
		if (!keep_alive) return;
	}
}

/// Handle one request. Returns whether the connection may be kept alive
/// (true only after a fully proxied request whose body was drained).
fn handleRequest(ctx: *Context, request: *std.http.Server.Request, sock: ?c_int) !bool {
	_ = ctx.counters.requests.fetchAdd(1, .monotonic);
	var m = ReqMeta{ .id = ctx.reqid.fetchAdd(1, .monotonic), .started_ms = ctx.now_ms(ctx.io) };

	// Copy the head OUT of the reader's buffer up front: body reads clobber it,
	// and framing/canon/forward-header slices all point into it.
	var head_copy: [framing.max_head_bytes]u8 = undefined;
	if (request.head_buffer.len > head_copy.len) {
		deny(ctx, request, &m, "-", .{ .reason = "head-oversize", .status = 431 });
		return false;
	}
	@memcpy(head_copy[0..request.head_buffer.len], request.head_buffer);
	const head = head_copy[0..request.head_buffer.len];

	// --- framing pre-parse (mandatory; addendum C.2/C.3) ---
	const checked = switch (framing.check(head, request.head.method)) {
		.ok => |chk| chk,
		.refuse => |r| {
			const status = framing.statusFor(r);
			deny(ctx, request, &m, "-", .{ .reason = @tagName(r), .status = @intFromEnum(status) });
			return false;
		},
	};

	// The 100-continue expectation, handled here so a body-bearing allow can
	// signal it before reading (an unrecognized expectation is 417).
	if (request.head.expect) |e| {
		if (!std.mem.eql(u8, e, "100-continue")) {
			deny(ctx, request, &m, checked.host, .{ .reason = "bad-expect", .status = 417 });
			return false;
		}
	}

	// --- canonicalize (segment-first, single-decode; §7) ---
	const target = canon.splitTarget(checked.target);
	// COGBOX_L7_AUTH_DEBUG_PATH: from here on the audit line carries the
	// redacted raw path (never by default).
	var dbg_buf: [debug_path_cap * 4 + 8]u8 = undefined;
	if (ctx.debug_path) m.debug_path = redactedPath(&dbg_buf, target.path, target.query);
	var seg_buf: [16 * 1024]u8 = undefined;
	var segs: [canon.max_segments][]const u8 = undefined;
	const nseg = switch (canon.canonicalize(target.path, &seg_buf, &segs)) {
		.ok => |n| n,
		.refuse => |r| {
			deny(ctx, request, &m, checked.host, .{ .reason = @tagName(r), .status = 400 });
			return false;
		},
	};
	var key_buf: [8 * 1024]u8 = undefined;
	var qparams: [canon.max_query_params]canon.QueryParam = undefined;
	const nq = switch (canon.parseQuery(target.query, &key_buf, &qparams)) {
		.ok => |n| n,
		.refuse => |r| {
			deny(ctx, request, &m, checked.host, .{ .reason = @tagName(r), .status = 400 });
			return false;
		},
	};
	// Forbidden credential/override query keys refused on EVERY route (§7).
	for (qparams[0..nq]) |p| {
		if (canon.forbiddenQueryKey(p.key)) {
			deny(ctx, request, &m, checked.host, .{ .reason = "forbidden-query", .status = 400 });
			return false;
		}
	}
	// A urlencoded body on an API write route closes the _method form residual.
	// (framing refuses a duplicate Content-Type, so the one read here is the
	// one the origin would see.)
	if (request.head.method == .POST or request.head.method == .PUT) {
		if (checked_content_type(checked)) |ct| {
			if (std.ascii.startsWithIgnoreCase(ct, "application/x-www-form-urlencoded")) {
				deny(ctx, request, &m, checked.host, .{ .reason = "form-body", .status = 415 });
				return false;
			}
		}
	}

	// --- inbound headers into an owned set (copies bytes off head_copy) ---
	var inbound: plugin_mod.HeaderSet = .{};
	for (checked.fwd[0..checked.fwd_len]) |h| {
		inbound.set(h.name, h.value) catch {};
	}
	const content_type = checked_content_type(checked);

	const req: plugin_mod.Request = .{
		.method = request.head.method,
		.segments = segs[0..nseg],
		.query = qparams[0..nq],
		.headers = &inbound,
		.content_type = content_type,
		.content_length = checked.content_length,
		.body = null, // set below, after the pure hooks
		.host = checked.host,
		.raw_target = checked.target,
	};

	// --- the routing entry for this host ---
	const gen = ctx.store.acquire() orelse {
		deny(ctx, request, &m, checked.host, .{ .reason = "no-policy", .status = 403 });
		return false;
	};
	defer ctx.store.release(gen);
	const entry = gen.findEntry(checked.host) orelse {
		deny(ctx, request, &m, checked.host, .{ .reason = "no-policy", .status = 403 });
		return false;
	};

	// --- gate 1: classify (PURE) ---
	const route = entry.policy.vtable.classify(entry.policy.ctx, &req) orelse {
		_ = ctx.counters.deny_gate1.fetchAdd(1, .monotonic);
		deny(ctx, request, &m, checked.host, .{ .plugin = entry.plugin_name, .gate = 1, .reason = "no_route", .status = 403 });
		return false;
	};

	// --- gate 2: authorize (PURE) ---
	const grant = switch (entry.policy.vtable.authorize(entry.policy.ctx, &route, &req)) {
		.deny => |reason| {
			_ = ctx.counters.deny_gate2.fetchAdd(1, .monotonic);
			deny(ctx, request, &m, checked.host, .{
				.plugin = entry.plugin_name,
				.gate = 2,
				.reason = @tagName(reason),
				.route_id = route.id,
				.service = serviceLabel(&route),
				.status = 403,
			});
			return false;
		},
		.allow => |g| g,
	};
	// Every deny above returned WITHOUT taking a body reader and WITHOUT any
	// upstream dial -- the "no upstream call on deny" invariant.

	// A LOCAL self-discovery route (Route.local, set by the plugin's classify on
	// its reflection surface -- gitlab's /_cogbox/grants): answered HERE from the
	// plugin's compiled policy, with NO inflight slot, NO credential and NO
	// upstream leg. authorize has already run (the method clamp), so a
	// non-GET/HEAD reached a method_not_allowed deny above.
	if (route.local) {
		var outcome: Outcome = .{
			.plugin = entry.plugin_name,
			.method = @tagName(request.head.method),
			.decision = .allow,
			.gate = 2,
			.reason = "ok",
			.route_id = route.id,
			.grant = grant,
		};
		return serveLocal(ctx, request, &m, checked.host, &outcome, entry, &route, &req);
	}

	// --- the acting-request phase: credential + upstream ---
	if (!ctx.acquireInflight()) {
		deny(ctx, request, &m, checked.host, .{ .plugin = entry.plugin_name, .route_id = route.id, .reason = "overloaded", .status = 503 });
		return false;
	}
	defer ctx.releaseInflight();

	var outcome: Outcome = .{
		.plugin = entry.plugin_name,
		.method = @tagName(request.head.method),
		.decision = .allow,
		.gate = 2,
		.reason = "ok",
		.route_id = route.id,
		.service = serviceLabel(&route),
		.grant = grant,
	};

	// Take the body reader NOW (addendum C.3: always before responding). The
	// pure hooks are done, so head-string invalidation is harmless.
	var body_buf: [8 * 1024]u8 = undefined;
	var mut_req = req;
	if (checked.has_body) {
		mut_req.body = request.readerExpectContinue(&body_buf) catch {
			outcome.decision = .deny;
			outcome.reason = "expect-failed";
			outcome.status = 417;
			ctx.finishAudit(&m, checked.host, outcome);
			return false;
		};
		// C.4 (S6, the request direction): the body is about to be pumped off
		// THIS socket to the origin (uio.open's upload loop, or a mediate
		// leg's), so the inbound socket moves to the IDLE bound now. Under the
		// 10 s head bound a pack-objects stall mid-push (delta compression of
		// a large blob, a slow guest, mitmproxy backpressure) tripped
		// SO_RCVTIMEO, the relay saw ReadFailed, and the guest got a 502 with
		// no retry. The response relay re-arms the same bound.
		ctx.armInbound(sock, upstream.body_idle_timeout_secs);
	} else {
		// A 100-continue expectation on a request with no body is ignored (RFC
		// 9110 §10.1.1 lets a server omit the interim response when the framing
		// shows no content) -- and it MUST be cleared first: readerExpectNone
		// asserts head.expect == null (Server.zig), which a bare `Expect:
		// 100-continue` on a GET, or a duplicated `Expect` that mitmproxy folds
		// and forwards (std's Head.parse takes the LAST copy), would otherwise
		// reach and abort the process. framing never touches `expect`.
		request.head.expect = null;
		_ = request.readerExpectNone(&.{});
	}

	// The per-request scratch block (CUSTODY, spec §7): every buffer the
	// owner credential passes through lives in it and ONE scrub covers them
	// all on every exit path. Scrub BEFORE the block is freed (defers run
	// LIFO, so uio.close below has already run): a reused block can never hand
	// the next request's frame a stale token or serialized Authorization.
	const scratch = ctx.gpa.create(RequestScratch) catch {
		deny2(ctx, request, &m, checked.host, &outcome, "oom", 500);
		return false;
	};
	defer {
		scratch.scrub();
		ctx.gpa.destroy(scratch);
	}
	scratch.* = .{};

	// Credential handle backed by the store's mtime-cached reader; the token
	// copy the plugin reads lands in the scratch block.
	var cred_ctx = CredCtx{ .cache = &ctx.store.cred, .io = ctx.io, .path = entry.cred_file, .buf = &scratch.cred_buf };
	var cred: plugin_mod.Cred = .{ .ctx = &cred_ctx, .tokenFn = CredCtx.token };

	// C.4: an API route's TOTAL relay deadline starts HERE, ahead of the
	// upload -- every leg's upload loop checks it, then the response relay --
	// so a body trickled one byte per idle bound cannot hold an inflight slot
	// for as long as the guest cares to. A stream route has none.
	const deadline = relayDeadline(route.stream, ctx.now_ms(ctx.io));
	var uio = upstream.UpstreamIO{
		.transport = ctx.transport,
		.gpa = ctx.gpa,
		.io = ctx.io,
		.entry_host = entry.host,
		.insecure = entry.insecure,
		.vetted_ip = checked.vetted_ip,
		.vetted_port = checked.vetted_port,
		.bundle = &gen.bundle,
		.bundle_lock = &gen.bundle_lock,
		.bundle_empty = gen.bundleEmpty(),
		.storage = &scratch.storage,
		.deadline_ms = deadline,
		.now_ms = ctx.now_ms,
	};
	defer uio.close();

	// Construct the upstream request (CONSTRUCTED, never copied).
	var up: plugin_mod.Upstream = .{};
	entry.policy.vtable.upstream(entry.policy.ctx, &route, &mut_req, &up) catch {
		deny2(ctx, request, &m, checked.host, &outcome, "upstream-build", 500);
		return false;
	};

	// Either the plugin mediates (harbor's token dance) or the core does the
	// default single round trip. Both yield one *Exchange to stream back.
	var exchange: *upstream.Exchange = undefined;
	var mediated = false;
	// The header set handed to the origin: after authenticate it carries the
	// owner credential, so it lives in the scratch block (scrubbed with it).
	const auth_headers = &scratch.auth_headers;
	if (entry.policy.vtable.mediate) |mediateFn| {
		_ = ctx.counters.mediate.fetchAdd(1, .monotonic);
		var resp: plugin_mod.Response = .{};
		const used = mediateFn(entry.policy.ctx, &route, &mut_req, &cred, &uio, &resp) catch |err| {
			return upstreamErrorResponse(ctx, request, &m, checked.host, &outcome, gen, err);
		};
		if (used) {
			exchange = resp.exchange orelse {
				deny2(ctx, request, &m, checked.host, &outcome, "mediate-empty", 502);
				return false;
			};
			mediated = true;
		}
	}
	if (!mediated) {
		// Start from the allowlisted inbound set -- RE-HOMED into the scratch
		// block, never struct-assigned: HeaderSet slices point into their own
		// storage, and `inbound` is a stack local that this heap block would
		// otherwise keep reading through (a use-after-free the moment a later
		// refactor lets the block outlive this frame).
		auth_headers.copyFrom(&inbound);
		// The projection re-emits a FRESH 200 body parsed from the origin's, so
		// two guest-forwarded headers must not reach the origin on this route:
		//   - accept-encoding: a gzip 200 body would fail the JSON parse (502
		//     bad_upstream_json), breaking the route for clients that default to
		//     gzip -- so force identity by dropping it.
		//   - range: a 206 Partial Content falls outside the status==200
		//     projection guard and would stream the raw, secret-bearing partial
		//     body -- so forbid a partial response by construction (never trust
		//     the origin to ignore a guest-controlled Range).
		// Only api-project sets project_response; every other route keeps
		// forwarding both unchanged.
		if (route.project_response) {
			auth_headers.remove("accept-encoding");
			auth_headers.remove("range");
		}
		entry.policy.vtable.authenticate(entry.policy.ctx, &route, &mut_req, &cred, auth_headers) catch |err| {
			switch (err) {
				error.CredentialUnavailable => {
					_ = ctx.counters.cred_unavailable.fetchAdd(1, .monotonic);
					deny2(ctx, request, &m, checked.host, &outcome, "cred-unavailable", 403);
					return false;
				},
				error.AuthFailed => {
					deny2(ctx, request, &m, checked.host, &outcome, "auth-failed", 500);
					return false;
				},
			}
		};
		exchange = uio.open(&up, request.head.method, auth_headers, mut_req.body, if (up_body_len(&mut_req)) |n| n else null) catch |err| {
			return upstreamErrorResponse(ctx, request, &m, checked.host, &outcome, gen, err);
		};
		if (entry.policy.vtable.onUpstreamStatus) |cb| {
			cb(entry.policy.ctx, &route, exchange.status, &exchange.headers, &cred);
		}
	}

	// Trailers on a chunked request body are refused (spec §7's framing list,
	// addendum C.3). They can only be seen once the body has been consumed --
	// which the leg above did, so std has parsed any trailer block by now.
	// The origin has the body already; this is a framing refusal, so the
	// answer is a 400 and the connection closes on both sides.
	if (checked.chunked and request.server.reader.trailers.len != 0) {
		deny2(ctx, request, &m, checked.host, &outcome, "trailers", 400);
		return false;
	}
	// A request body a mediate plugin left unread would sit in the inbound
	// stream and be parsed as the next request on a reused connection: never
	// keep such a connection alive.
	const body_drained = !checked.has_body or request.server.reader.state == .ready;

	_ = ctx.counters.allow.fetchAdd(1, .monotonic);
	outcome.status = exchange.status;
	outcome.bytes_in = uio.body_bytes;

	// The api-project response-body projection (route.project_response, set only
	// on that route): a single-project GET returns GitLab's FULL project object,
	// and `simple=true` does NOT strip runners_token (et al.) on a single-project
	// GET -- GitLab honours `simple` only on LIST endpoints. So the SUCCESS body
	// is read into a bounded buffer and re-emitted as the ProjectSimpleEntity
	// allowlist, fail-closed (502, never the raw body) over the cap or on
	// unparseable JSON. A non-200 (403/404) carries no project secret and is
	// relayed unchanged; a HEAD / 204 / 304 carries no body to project. The
	// projected bytes live in `proj_slice` (freed after the relay completes,
	// which is before this frame's defers run) behind `proj_reader`; they never
	// carry the credential, so they stay outside the scratch block's scrub.
	var proj_reader: std.Io.Reader = undefined;
	var proj_slice: ?[]u8 = null;
	defer if (proj_slice) |p| ctx.gpa.free(p);
	if (route.project_response and exchange.status == 200 and exchange.body != null) {
		const slice = projectProjectResponse(ctx.gpa, exchange) catch |err| {
			const reason: []const u8 = switch (err) {
				error.ResponseTooLarge => "response_too_large",
				error.BadUpstreamJson => "bad_upstream_json",
				error.UpstreamRead => "upstream-read",
				error.OutOfMemory => "oom",
			};
			_ = ctx.counters.upstream_err.fetchAdd(1, .monotonic);
			deny2(ctx, request, &m, checked.host, &outcome, reason, 502);
			return false;
		};
		proj_slice = slice;
		proj_reader = std.Io.Reader.fixed(slice);
		exchange.body = &proj_reader;
		exchange.content_length = slice.len; // streamResponse re-frames Content-Length
		exchange.chunked = false;
	}
	return streamResponse(ctx, request, &m, checked.host, &outcome, exchange, deadline, body_drained, sock);
}

/// Stream the upstream response back to the client: status + stripped headers
/// + body, never following a 3xx (the 3xx is returned verbatim). Content-length
/// when the upstream declared one, chunked otherwise. Bodies are not filtered.
///
/// A BODYLESS response (a HEAD response, 204, 304 -- `ex.body == null`) is
/// NEVER emitted through a content-length framed BodyWriter: BodyWriter.end
/// asserts the declared length was written, and nothing ever is (B1: a HEAD
/// with the origin's `content-length: 40` aborted the process). Those are sent
/// head-only with NO framing of our own (transfer_encoding .none): the origin's
/// content-length rides as a plain header -- for HEAD it is the GET body's
/// size, for 304 what the 200 would carry (RFC 9110 §8.6) -- EXCEPT on a 204,
/// where the same section says a server MUST NOT send one (a non-conforming
/// origin's `content-length: 0` is dropped rather than relayed one hop on);
/// and std closes the connection after a .none response, the honest posture
/// for close-delimited framing. One extra loopback reconnect per HEAD/204/304
/// is the accepted cost.
fn streamResponse(ctx: *Context, request: *std.http.Server.Request, m: *const ReqMeta, host: []const u8, outcome: *Outcome, ex: *upstream.Exchange, deadline: ?i64, body_drained: bool, sock: ?c_int) !bool {
	var extra: [plugin_mod.max_headers + 1]std.http.Header = undefined;
	var ne: usize = 0;
	var i: usize = 0;
	// Every header in the set is emittable and singletons are unique: an
	// origin head the relay could not carry whole never got here (the upstream
	// leg refused the exchange, Error.BadResponseHeader -> 502). The belt under
	// that invariant is the same check, per header: `ex` is whatever a mediate
	// plugin handed back, which need not be an exchange `open` produced, and
	// std's respondStreaming asserts only a non-empty name -- a bare LF in a
	// hand-filled value would otherwise reach the guest as a header-splitting
	// sequence. Nothing is on the wire yet, so the refusal is the leg's 502.
	while (i < ex.headers.len and ne < plugin_mod.max_headers) : (i += 1) {
		if (!upstream.headerEmittable(ex.headers.names[i], ex.headers.values[i])) {
			_ = ctx.counters.upstream_err.fetchAdd(1, .monotonic);
			deny2(ctx, request, m, host, outcome, "BadResponseHeader", 502);
			return false;
		}
		extra[ne] = .{ .name = ex.headers.names[i], .value = ex.headers.values[i] };
		ne += 1;
	}
	var resp_buf: [16 * 1024]u8 = undefined;

	const body = ex.body orelse {
		var cl_buf: [24]u8 = undefined;
		if (ex.content_length) |cl| {
			if (ex.status != 204) {
				extra[ne] = .{ .name = "content-length", .value = std.fmt.bufPrint(&cl_buf, "{d}", .{cl}) catch unreachable };
				ne += 1;
			}
		}
		var bw = request.respondStreaming(&resp_buf, .{
			.content_length = null,
			.respond_options = .{
				.status = @enumFromInt(ex.status),
				.keep_alive = false,
				.transfer_encoding = .none,
				.extra_headers = extra[0..ne],
			},
		}) catch return false;
		bw.end() catch return false;
		ctx.finishAudit(m, host, outcome.*);
		return false;
	};

	var bw = request.respondStreaming(&resp_buf, .{
		.content_length = ex.content_length,
		.respond_options = .{
			.status = @enumFromInt(ex.status),
			.keep_alive = body_drained,
			.extra_headers = extra[0..ne],
		},
	}) catch return false;

	// The relay (C.4): the inbound socket moves to the IDLE bound (the
	// upstream side was re-armed by UpstreamIO when its head came in); API
	// routes additionally carry the TOTAL deadline handleRequest started ahead
	// of the upload, checked between slices; stream routes carry none.
	ctx.armInbound(sock, upstream.body_idle_timeout_secs);
	var total: u64 = 0;
	relay: while (true) {
		const n = body.stream(&bw.writer, .limited(upstream.relay_chunk)) catch |err| switch (err) {
			error.EndOfStream => break :relay,
			else => {
				// A failed upstream read mid-body: the response head is already
				// sent, so the only honest signal left is to abort the
				// connection (never a clean terminator over a short body).
				outcome.bytes_out = total;
				outcome.reason = "upstream-read";
				abortRelay(request, &bw);
				ctx.finishAudit(m, host, outcome.*);
				return false;
			},
		};
		total += n;
		if (deadline) |d| {
			if (ctx.now_ms(ctx.io) > d) {
				outcome.bytes_out = total;
				outcome.reason = "relay-deadline";
				abortRelay(request, &bw);
				ctx.finishAudit(m, host, outcome.*);
				return false;
			}
		}
	}
	outcome.bytes_out = total;
	// A content-length body that ended EARLY (the origin closed mid-body: std's
	// content-length reader surfaces that as a plain EndOfStream) must never
	// reach BodyWriter.end, which asserts the declared length was written.
	// Abort the connection instead -- the client sees a short body under a
	// full-length header and knows it was truncated.
	if (ex.content_length) |cl| {
		if (total != cl) {
			outcome.reason = "upstream-truncated";
			abortRelay(request, &bw);
			ctx.finishAudit(m, host, outcome.*);
			return false;
		}
	}
	bw.end() catch return false;
	ctx.finishAudit(m, host, outcome.*);
	// Keep-alive only when the whole exchange completed cleanly and the
	// request body was drained.
	return body_drained;
}

/// Abort a body relay mid-stream: push whatever partial body is buffered to
/// the client (so it sees exactly the bytes the origin delivered), then let
/// the caller close the connection WITHOUT the terminator BodyWriter.end
/// would write (which asserts on a content-length shortfall, and would
/// otherwise claim a clean end over a short body).
fn abortRelay(request: *std.http.Server.Request, bw: *std.http.BodyWriter) void {
	bw.writer.flush() catch {};
	request.server.out.flush() catch {};
}

/// The api-project response projection cap: a single-project JSON is a few KB,
/// so 256 KiB is generous; a body larger than this is refused (fail closed),
/// never streamed unprojected. Read into an allocation, not the stack.
pub const project_response_cap: usize = 256 * 1024;

const ProjectionError = error{
	/// The 200 body exceeded project_response_cap -> 502, never a partial or
	/// unprojected relay.
	ResponseTooLarge,
	/// The body did not parse as a JSON object -> 502, never the raw body.
	BadUpstreamJson,
	/// The upstream read failed mid-body (before any response head is out) -> 502.
	UpstreamRead,
	OutOfMemory,
};

/// The GitLab 18.5 ProjectSimpleEntity allowlist -- the safe subset an agent
/// needs, with NO runners_token, import_url, permissions, _links or CI/registry
/// config. A VERSIONED artifact, like the route table: re-review it against the
/// deployment's GitLab on each release, and err toward FEWER fields (an omitted
/// field just isn't shown; a wrongly-included one could be a future leak). An
/// ALLOWLIST, not a denylist, so a new secret field GitLab adds is dropped by
/// default.
const project_simple_fields = [_][]const u8{
	"id",
	"description",
	"name",
	"name_with_namespace",
	"path",
	"path_with_namespace",
	"created_at",
	"default_branch",
	"tag_list",
	"topics",
	"ssh_url_to_repo",
	"http_url_to_repo",
	"web_url",
	"readme_url",
	"avatar_url",
	"forks_count",
	"star_count",
	"last_activity_at",
	"visibility",
	"archived",
	"empty_repo",
	"namespace",
};

/// The nested `namespace` object's own allowlist (GitLab's namespace simple form
/// carries no secret, but it is allowlisted rather than passed through whole, so
/// a future secret field there is dropped too).
const project_namespace_fields = [_][]const u8{
	"id",
	"name",
	"path",
	"kind",
	"full_path",
	"parent_id",
	"avatar_url",
	"web_url",
};

/// Read the exchange's 200 body into a bounded buffer, parse it, and re-emit a
/// NEW object carrying only the ProjectSimpleEntity allowlist. Returns the
/// projected bytes (caller-owned; the caller frees them after the relay). The
/// read buffer and parse arena are internal and released here; none of them
/// carries the credential.
fn projectProjectResponse(gpa: std.mem.Allocator, ex: *upstream.Exchange) ProjectionError![]u8 {
	const body_reader = ex.body.?;
	// .limited(cap + 1): allocRemaining returns StreamTooLong once it has read
	// `limit` bytes, so cap+1 admits a body of exactly the cap and refuses only a
	// strictly larger one.
	const body = body_reader.allocRemaining(gpa, .limited(project_response_cap + 1)) catch |err| switch (err) {
		error.StreamTooLong => return error.ResponseTooLarge,
		error.ReadFailed => return error.UpstreamRead,
		error.OutOfMemory => return error.OutOfMemory,
	};
	defer gpa.free(body);

	var arena = std.heap.ArenaAllocator.init(gpa);
	defer arena.deinit();
	const root = std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), body, .{}) catch |err| switch (err) {
		error.OutOfMemory => return error.OutOfMemory,
		else => return error.BadUpstreamJson,
	};
	if (root != .object) return error.BadUpstreamJson;

	var out: std.Io.Writer.Allocating = .init(gpa);
	errdefer out.deinit();
	writeProjectSimple(&out.writer, root.object) catch |err| switch (err) {
		// The only failure of an Allocating writer is OOM.
		error.WriteFailed => return error.OutOfMemory,
	};
	return out.toOwnedSlice();
}

/// The re-emit recursion bound. `std.json.Stringify.write` (and `Value`'s own
/// `jsonStringify`) recurses NATIVELY once per nesting level, while std's parse
/// is iterative (a heap BitStack) -- so a value nested deeper than any real
/// project field is DROPPED by writeProjectSimple rather than re-serialized,
/// which on a compromised/buggy upstream's deeply-nested response would risk a
/// native-stack overflow. 32 is far above a real ProjectSimpleEntity (an object
/// one or two levels deep; tag_list/topics are one-level string arrays).
const max_reemit_depth: usize = 32;

/// Whether `v` nests no deeper than `budget` levels. Recurses at most `budget`
/// frames (it decrements on every array/object descent and stops at 0), so the
/// CHECK is itself overflow-safe on arbitrarily deep input.
fn depthOk(v: std.json.Value, budget: usize) bool {
	if (budget == 0) return false;
	switch (v) {
		.array => |a| {
			for (a.items) |item| {
				if (!depthOk(item, budget - 1)) return false;
			}
		},
		.object => |o| {
			var it = o.iterator();
			while (it.next()) |e| {
				if (!depthOk(e.value_ptr.*, budget - 1)) return false;
			}
		},
		else => {},
	}
	return true;
}

/// Emit `{ <allowlisted project fields> }`, projecting the nested `namespace`
/// object through its own allowlist. Absent fields are simply skipped -- the
/// projection is future-proof against new (possibly secret) fields by
/// construction.
fn writeProjectSimple(w: *std.Io.Writer, obj: std.json.ObjectMap) std.Io.Writer.Error!void {
	var jw: std.json.Stringify = .{ .writer = w };
	try jw.beginObject();
	for (project_simple_fields) |key| {
		const v = obj.get(key) orelse continue;
		// A non-object `namespace` (a hostile or future upstream returning an
		// array or a scalar) is DROPPED, not passed through whole -- the same
		// "emit only what the allowlist covers" rule the field list itself is.
		if (std.mem.eql(u8, key, "namespace") and v != .object) continue;
		// Bound the re-emit recursion (see max_reemit_depth): a pathologically
		// deep value is dropped rather than re-serialized.
		if (!depthOk(v, max_reemit_depth)) continue;
		try jw.objectField(key);
		if (std.mem.eql(u8, key, "namespace")) {
			try jw.beginObject();
			for (project_namespace_fields) |nk| {
				const nv = v.object.get(nk) orelse continue;
				try jw.objectField(nk);
				try jw.write(nv);
			}
			try jw.endObject();
		} else {
			try jw.write(v);
		}
	}
	try jw.endObject();
}

/// C.4: the total relay deadline -- none on a stream route, now + 60s on an
/// API route, `now` being the moment before the upload. Pure, so the policy
/// is pinned by a unit test.
pub fn relayDeadline(stream_route: bool, now_ms: i64) ?i64 {
	if (stream_route) return null;
	return now_ms + api_relay_total_ms;
}

fn upstreamErrorResponse(ctx: *Context, request: *std.http.Server.Request, m: *const ReqMeta, host: []const u8, outcome: *Outcome, gen: *conf.Generation, err: anyerror) bool {
	const status: u16 = switch (err) {
		error.HostNotAllowed => 403,
		error.HttpsRefused => blk: {
			// D.3 item 3: loud, once per conf generation.
			_ = gen.noteHttpsRefusal(host);
			break :blk 502;
		},
		error.TooManyLegs => 502,
		// The total deadline passed with the request body still in flight: the
		// guest never finished its upload within the bound, and no response
		// head is out yet, so it is told so (RFC 9110 §15.5.9) and the
		// connection closes -- never a 502 blamed on the origin.
		error.RelayDeadline => 408,
		error.CredentialUnavailable => blk: {
			_ = ctx.counters.cred_unavailable.fetchAdd(1, .monotonic);
			break :blk 403;
		},
		else => 502,
	};
	if (status == 502) _ = ctx.counters.upstream_err.fetchAdd(1, .monotonic);
	deny2(ctx, request, m, host, outcome, @errorName(err), status);
	return false;
}

fn deny(ctx: *Context, request: *std.http.Server.Request, m: *const ReqMeta, host: []const u8, o: Outcome) void {
	var outcome = o;
	outcome.decision = .deny;
	if (outcome.method.len == 1 and outcome.method[0] == '-') outcome.method = @tagName(request.head.method);
	// Clear any 100-continue expectation so respond() does not tell a denied
	// client to send its body.
	request.head.expect = null;
	// A coarse machine-readable deny reason for the guest: a fixed enum
	// (outcome.reason -- the same vocabulary the audit line carries), never free
	// text and never a secret, so the in-sandbox agent can tell scope_mismatch /
	// cap_missing / no_route / no_grant apart from "no grant at all" instead of
	// reading a bare empty-body 403 as "no access". Header only: the empty body,
	// keep_alive=false and the framing-ambiguity posture are untouched.
	// Every deny closes the connection (keep_alive=false): assert-safe and it
	// makes the framing boundary ambiguity unexploitable.
	request.respond("", .{
		.status = @enumFromInt(outcome.status),
		.keep_alive = false,
		.extra_headers = &.{.{ .name = "X-Cogbox-Deny", .value = outcome.reason }},
	}) catch {};
	ctx.finishAudit(m, host, outcome);
}

fn deny2(ctx: *Context, request: *std.http.Server.Request, m: *const ReqMeta, host: []const u8, outcome: *Outcome, reason: []const u8, status: u16) void {
	outcome.decision = .deny;
	outcome.reason = reason;
	outcome.status = status;
	deny(ctx, request, m, host, outcome.*);
}

/// The local self-discovery body cap. The reflected policy cannot exceed the
/// policy document it is derived from (the verb refuses a document over 64 KiB),
/// so 64 KiB with margin is generous; a render that overflows it is fail-closed
/// to a 500, never a partial or unbounded body.
pub const local_response_cap: usize = 64 * 1024;

/// The local self-discovery answer (Route.local, set by a plugin's classify on
/// its reflection surface -- gitlab's /_cogbox/grants). The plugin RENDERS the
/// full body from its compiled policy; the core relays it as a 200
/// application/json with NO upstream leg and NO credential use, then closes the
/// connection -- the deny path's local-answer idiom (`request.respond`), a body
/// instead of empty, and NO `X-Cogbox-Deny` on the success path. std's respond
/// frames Content-Length and omits the body on a HEAD. Fail-closed: a route
/// marked local by a plugin that exposes no renderer, an OOM, or a render that
/// overflows the bounded buffer is a 500 -- never a partial or a raw byte.
fn serveLocal(ctx: *Context, request: *std.http.Server.Request, m: *const ReqMeta, host: []const u8, outcome: *Outcome, entry: *const conf.Entry, route: *const plugin_mod.Route, req: *const plugin_mod.Request) bool {
	const render = entry.policy.vtable.localResponse orelse {
		deny2(ctx, request, m, host, outcome, "local-unsupported", 500);
		return false;
	};
	const buf = ctx.gpa.alloc(u8, local_response_cap) catch {
		deny2(ctx, request, m, host, outcome, "oom", 500);
		return false;
	};
	defer ctx.gpa.free(buf);
	var w: std.Io.Writer = .fixed(buf);
	render(entry.policy.ctx, route, req, &w) catch {
		deny2(ctx, request, m, host, outcome, "local-too-large", 500);
		return false;
	};
	const body = w.buffered();

	_ = ctx.counters.allow.fetchAdd(1, .monotonic);
	outcome.status = 200;
	outcome.bytes_out = body.len;
	// Clear any 100-continue expectation so respond() does not tell the client
	// to send a body (a GET/HEAD carries none, but the field can be set).
	request.head.expect = null;
	// The success path carries NO X-Cogbox-Deny -- only Content-Type. keep_alive
	// is false, the local-answer idiom (deny closes too): a body a client left
	// unread cannot then be parsed as the next request on a reused connection.
	request.respond(body, .{
		.status = .ok,
		.keep_alive = false,
		.extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
	}) catch {};
	ctx.finishAudit(m, host, outcome.*);
	return false;
}

fn writeCannedError(out: *std.Io.Writer, status: std.http.Status) void {
	out.print("HTTP/1.1 {d} {s}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n", .{
		@intFromEnum(status), status.phrase() orelse "",
	}) catch {};
	out.flush() catch {};
}

fn checked_content_type(checked: framing.Checked) ?[]const u8 {
	for (checked.fwd[0..checked.fwd_len]) |h| {
		if (std.ascii.eqlIgnoreCase(h.name, "content-type")) return h.value;
	}
	return null;
}

fn serviceLabel(route: *const plugin_mod.Route) []const u8 {
	return if (route.params.service) |s| switch (s) {
		.upload_pack => "git-upload-pack",
		.receive_pack => "git-receive-pack",
	} else "-";
}

fn up_body_len(req: *const plugin_mod.Request) ?u64 {
	return req.content_length;
}

/// The COGBOX_L7_AUTH_DEBUG_PATH field (spec §7): the raw path, capped at
/// debug_path_cap source bytes, then `?` and the query with every VALUE
/// dropped except `service`'s -- a provider accepting `?private_token=` in the
/// query means an unredacted query string would reproduce the C04 wart in a
/// new place. The whole thing is double-quoted with every byte outside
/// printable ASCII (and `"`, `\`) escaped as `\xNN`, so the line stays one
/// line whatever the guest sent. Keys/values are taken RAW (undecoded): this
/// is a debug field, and decoding here would be a second decoder.
pub fn redactedPath(buf: []u8, path: []const u8, query: []const u8) []const u8 {
	var w: std.Io.Writer = .fixed(buf);
	redactInto(&w, path, query) catch {
		// Overflow (a long key list): keep what fits, close the quote so the
		// field is still one well-formed token.
		const keep = @min(w.end, buf.len - 1);
		buf[keep] = '"';
		return buf[0 .. keep + 1];
	};
	return w.buffered();
}

fn redactInto(w: *std.Io.Writer, path: []const u8, query: []const u8) !void {
	try w.writeByte('"');
	try quoteInto(w, path[0..@min(path.len, debug_path_cap)]);
	if (path.len > debug_path_cap) try w.writeAll("...");
	if (query.len > 0) {
		try w.writeByte('?');
		var it = std.mem.splitScalar(u8, query, '&');
		var first = true;
		while (it.next()) |pair| {
			if (pair.len == 0) continue;
			if (!first) try w.writeByte('&');
			first = false;
			const eq = std.mem.indexOfScalar(u8, pair, '=');
			const key = if (eq) |e| pair[0..e] else pair;
			try quoteInto(w, key);
			if (std.mem.eql(u8, key, "service")) {
				try quoteInto(w, if (eq) |e| pair[e..] else "");
			}
		}
	}
	try w.writeByte('"');
}

fn quoteInto(w: *std.Io.Writer, bytes: []const u8) !void {
	for (bytes) |b| {
		if (b >= 0x20 and b < 0x7f and b != '"' and b != '\\') {
			try w.writeByte(b);
		} else {
			try w.print("\\x{X:0>2}", .{b});
		}
	}
}

/// The per-request scratch block (heap, one per acting request): EVERY buffer
/// the owner credential passes through, so that one scrub covers the whole of
/// custody -- the raw token copy the plugin reads (`cred_buf`), the header set
/// that carries `Authorization` to the origin (`auth_headers`), and the
/// connection buffers it is serialized through (`storage`). Keeping all three
/// in one block is what lets the S5 e2e PIN the scrub: it serves a request
/// through a retaining allocator and scans the retired block for the token.
/// A buffer that carries the credential and does not live here is a custody
/// bug by construction.
pub const RequestScratch = struct {
	cred_buf: [conf.cred_value_cap]u8 = undefined,
	auth_headers: plugin_mod.HeaderSet = .{},
	storage: upstream.ConnStorage = .{},

	pub fn scrub(self: *RequestScratch) void {
		std.crypto.secureZero(u8, &self.cred_buf);
		self.auth_headers.zeroize();
		self.storage.scrub();
	}
};

const CredCtx = struct {
	cache: *conf.CredCache,
	io: std.Io,
	path: []const u8,
	/// The request's RequestScratch.cred_buf (scrubbed with the block).
	buf: *[conf.cred_value_cap]u8,

	fn token(ptr: *anyopaque) plugin_mod.Cred.TokenError![]const u8 {
		const self: *CredCtx = @ptrCast(@alignCast(ptr));
		const n = try self.cache.read(self.io, self.path, self.buf);
		return self.buf[0..n];
	}
};

// --- production listener / accept loop ---

const c = @cImport({
	@cDefine("_GNU_SOURCE", "1");
	@cDefine("_FORTIFY_SOURCE", "0");
	@cInclude("sys/socket.h");
	@cInclude("netinet/in.h");
	@cInclude("poll.h");
	@cInclude("unistd.h");
});

const c_bind = @extern(*const fn (c_int, *const c.struct_sockaddr, c.socklen_t) callconv(.c) c_int, .{ .name = "bind" });
const c_accept = @extern(*const fn (c_int, ?*c.struct_sockaddr, ?*c.socklen_t) callconv(.c) c_int, .{ .name = "accept" });

var g_ctx: ?*Context = null;
var g_conn_count = std.atomic.Value(usize).init(0);

fn sleepMs(ms: i64) void {
	_ = c.poll(null, 0, @intCast(ms));
}

/// cogbox __authproxy entry. Threaded server on 127.0.0.1 only (correction
/// X1: the peer is always mitmproxy on the same loopback); the listen port is
/// derived from the L7 base in Zig (filter.l7AuthPortForBase), never a second
/// differently-sourced port. `io` is threaded in (unlike __l7proxy) for the
/// trust-store load and the conf/cred file reads.
pub fn run(gpa: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map, runtime_dir: []const u8, l7_base: u16) !void {
	const port = filter.l7AuthPortForBase(l7_base) orelse {
		std.debug.print("authproxy: l7 base {d} too low for the -400 auth-port offset; refusing to start\n", .{l7_base});
		return error.PortUnavailable;
	};

	var conf_path_buf: [4096]u8 = undefined;
	// COGBOX_L7_AUTH_CONF defaults to <runtime>/l7-auth-conf.json -- the
	// runtime dir is argv[0], so the default cannot be wrong (addendum A.2).
	const conf_path = env.get("COGBOX_L7_AUTH_CONF") orelse
		try std.fmt.bufPrint(&conf_path_buf, "{s}/l7-auth-conf.json", .{runtime_dir});
	const ssl_cert_file = env.get("SSL_CERT_FILE");
	const debug_path = if (env.get("COGBOX_L7_AUTH_DEBUG_PATH")) |v|
		std.mem.eql(u8, v, "1")
	else
		false;

	var store = conf.Store.init(gpa, io, conf_path, ssl_cert_file);
	defer store.deinit();
	// The first parse. Its verdict gates the pid file (spec §2.2 / addendum
	// A.3: written only after the listener binds AND the first conf parse
	// succeeds); a failed first parse leaves the empty policy live and the
	// pid file absent until a later poll parses one.
	const first_parse_ok = store.poll();

	var ctx = Context{
		.gpa = gpa,
		.io = io,
		.store = &store,
		.transport = &upstream.real_transport,
		.debug_path = debug_path,
	};
	g_ctx = &ctx;

	const listen_fd = try listenLoopback(port);
	std.debug.print("authproxy: listening on 127.0.0.1:{d} (l7 base {d}); conf {s}\n", .{ port, l7_base, conf_path });

	var pid_written = false;
	var pid_report: PidFileReport = .{};
	_ = pid_report.note(maybeWritePidFile(io, runtime_dir, first_parse_ok, &pid_written), runtime_dir);

	acceptLoop(&ctx, &store, listen_fd, runtime_dir, &pid_written, &pid_report);
}

fn listenLoopback(port: u16) !c_int {
	const fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
	if (fd < 0) return error.Socket;
	var one: c_int = 1;
	_ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_REUSEADDR, &one, @sizeOf(c_int));
	var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
	sa.sin_family = c.AF_INET;
	sa.sin_port = std.mem.nativeToBig(u16, port);
	sa.sin_addr.s_addr = std.mem.nativeToBig(u32, 0x7f000001); // 127.0.0.1 only
	if (c_bind(fd, @ptrCast(&sa), @sizeOf(c.struct_sockaddr_in)) != 0) {
		_ = c.close(fd);
		return error.Bind;
	}
	// Backlog 16: the queue is kernel-bounded; max_conns caps thread count.
	if (c.listen(fd, 16) != 0) {
		_ = c.close(fd);
		return error.Listen;
	}
	return fd;
}

/// One accept tick's housekeeping, run before the poll(2): it doubles as the
/// conf-poll tick (at most once/second), the pid-file gate (a first successful
/// parse after a failed one, or a write that failed last tick) and the counters
/// rollup tick (H#27). Factored out of the loop so a test can run the tick the
/// loop runs -- the FIRST tick, against a fresh store, is the one that trapped
/// in the field, and no in-memory request test reaches it.
fn tickOnce(ctx: *Context, store: *conf.Store, runtime_dir: []const u8, pid_written: *bool, pid_report: *PidFileReport) void {
	const now = ctx.now_ms(ctx.io);
	store.maybePoll(now);
	_ = pid_report.note(maybeWritePidFile(ctx.io, runtime_dir, store.has_cache, pid_written), runtime_dir);
	_ = ctx.maybeEmitStats(now);
}

fn acceptLoop(ctx: *Context, store: *conf.Store, listen_fd: c_int, runtime_dir: []const u8, pid_written: *bool, pid_report: *PidFileReport) void {
	var pfd = [_]c.struct_pollfd{.{ .fd = listen_fd, .events = c.POLLIN, .revents = 0 }};
	while (true) {
		tickOnce(ctx, store, runtime_dir, pid_written, pid_report);
		const pr = c.poll(&pfd, 1, 1000);
		if (pr <= 0) continue;
		if ((pfd[0].revents & c.POLLIN) == 0) continue;
		const cfd = c_accept(listen_fd, null, null);
		if (cfd < 0) continue;
		if (g_conn_count.fetchAdd(1, .monotonic) >= max_conns) {
			_ = g_conn_count.fetchSub(1, .monotonic);
			// The 65th connection gets a canned 503 + close, written directly.
			var tmp: [128]u8 = undefined;
			var ow = framing.FdWriter.init(cfd, &tmp);
			writeCannedError(&ow.interface, .service_unavailable);
			_ = c.close(cfd);
			continue;
		}
		const th = std.Thread.spawn(.{}, worker, .{ ctx, cfd }) catch {
			_ = g_conn_count.fetchSub(1, .monotonic);
			_ = c.close(cfd);
			continue;
		};
		th.detach();
	}
}

fn worker(ctx: *Context, cfd: c_int) void {
	defer _ = c.close(cfd);
	defer _ = g_conn_count.fetchSub(1, .monotonic);
	var in_buf: [inbound_buf_len]u8 = undefined;
	var out_buf: [16 * 1024]u8 = undefined;
	var fr = framing.FdReader.init(cfd, &in_buf);
	var fw = framing.FdWriter.init(cfd, &out_buf);
	// The per-phase socket timeouts (C.4) are armed by serveConnectionOn.
	serveConnectionOn(ctx, &fr.interface, &fw.interface, cfd);
}

/// What one pid-file attempt did. `run` and the accept loop report these
/// HONESTLY and SEPARATELY: a withheld file names the failed conf parse, a
/// failed write names the write -- never the other way round. (The first cut
/// printed the parse-gate line whenever the file was absent, which on GCE --
/// where the proxy uid could not create a file in the root-owned runtime dir
/// -- sent an operator hunting a policy-render bug that did not exist.)
pub const PidFileOutcome = union(enum) {
	already_written,
	parse_pending,
	written,
	write_failed: anyerror,
};

/// The v1 health signal: `<runtime>/authproxy.pid`, its CONTENTS written ONCE
/// by this process, only after the listener bound and a conf parse SUCCEEDED
/// (spec §2.2 / addendum A.3) -- so "non-empty" means healthy. The launch/
/// enforce scripts never write a pid into it: a script-written pid would name
/// a process that may already have died on a bind failure, which is exactly
/// what the file exists to rule out. BOTH scripts do PRE-CREATE it empty --
/// the VM launcher chowned to the proxy uid, because under COGBOX_PROXY_RUNAS
/// this process cannot create files in the root-owned runtime dir, while
/// truncate-writing into an existing owned file needs no directory permission;
/// the enforcer for the same contract on both paths (and so a supervised
/// restart truncates the dead child's stale pid away).
pub fn maybeWritePidFile(io: std.Io, runtime_dir: []const u8, parsed_ok: bool, written: *bool) PidFileOutcome {
	if (written.*) return .already_written;
	if (!parsed_ok) return .parse_pending;
	var path_buf: [4096]u8 = undefined;
	const path = std.fmt.bufPrint(&path_buf, "{s}/authproxy.pid", .{runtime_dir}) catch |err| return .{ .write_failed = err };
	const cwd = std.Io.Dir.cwd();
	const f = cwd.createFile(io, path, .{ .truncate = true }) catch |err| return .{ .write_failed = err };
	defer f.close(io);
	var wbuf: [32]u8 = undefined;
	var w = f.writer(io, &wbuf);
	w.interface.print("{d}\n", .{std.os.linux.getpid()}) catch |err| return .{ .write_failed = err };
	w.flush() catch |err| return .{ .write_failed = err };
	written.* = true;
	return .written;
}

/// One-shot reporting for the pid-file outcomes: the accept loop re-attempts
/// the write every tick, and each cause is printed once, by name.
pub const PidFileReport = struct {
	parse_pending_logged: bool = false,
	write_failed_logged: bool = false,

	/// Returns whether a line was (or, under test, would have been) emitted.
	pub fn note(self: *PidFileReport, outcome: PidFileOutcome, runtime_dir: []const u8) bool {
		switch (outcome) {
			.already_written => return false,
			.written => {
				if (!builtin.is_test) std.debug.print("authproxy: wrote {s}/authproxy.pid (listener bound, conf parsed)\n", .{runtime_dir});
				return true;
			},
			.parse_pending => {
				if (self.parse_pending_logged) return false;
				self.parse_pending_logged = true;
				if (!builtin.is_test) std.debug.print("authproxy: first conf parse failed; pid file withheld until a conf parses (every host refused meanwhile)\n", .{});
				return true;
			},
			.write_failed => |err| {
				if (self.write_failed_logged) return false;
				self.write_failed_logged = true;
				if (!builtin.is_test) std.debug.print("authproxy: cannot write {s}/authproxy.pid: {s} -- the conf parsed and requests are served regardless, but the v1 health signal is unavailable (is the file pre-created and owned by this uid?)\n", .{ runtime_dir, @errorName(err) });
				return true;
			},
		}
	}
};

// --- Tests: see tests.zig for the full in-memory e2e; these cover the small
// pieces here. ---

const t = std.testing;

test "Counters.rollup renders the fixed field set" {
	var counters: Counters = .{};
	_ = counters.requests.fetchAdd(3, .monotonic);
	_ = counters.allow.fetchAdd(2, .monotonic);
	_ = counters.deny_gate1.fetchAdd(1, .monotonic);
	var alloc = std.Io.Writer.Allocating.init(t.allocator);
	defer alloc.deinit();
	try counters.rollup(&alloc.writer);
	try t.expect(std.mem.indexOf(u8, alloc.written(), "requests=3") != null);
	try t.expect(std.mem.indexOf(u8, alloc.written(), "allow=2") != null);
	try t.expect(std.mem.indexOf(u8, alloc.written(), "deny_gate1=1") != null);
}

test "maybeEmitStats: on the cadence, only when requests moved (S1)" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var store = conf.Store.init(t.allocator, threaded.io(), "", null); // static, no file
	defer store.deinit();
	var audit = std.Io.Writer.Allocating.init(t.allocator);
	defer audit.deinit();
	var ctx = Context{ .gpa = t.allocator, .io = threaded.io(), .store = &store, .transport = &upstream.real_transport, .audit = &audit.writer };
	try t.expect(!ctx.maybeEmitStats(0)); // idle: nothing to say
	_ = ctx.counters.requests.fetchAdd(1, .monotonic);
	try t.expect(!ctx.maybeEmitStats(1000)); // not due yet
	try t.expect(ctx.maybeEmitStats(stats_interval_ms)); // due, and requests moved
	try t.expect(std.mem.indexOf(u8, audit.written(), "authproxy stats requests=1 ") != null);
	try t.expect(!ctx.maybeEmitStats(2 * stats_interval_ms)); // due, but unchanged
	try t.expectEqual(@as(i64, 60_000), stats_interval_ms);
}

test "relayDeadline: none on a stream route, 60s total on an API route (S6 pin)" {
	try t.expectEqual(@as(?i64, null), relayDeadline(true, 1000));
	try t.expectEqual(@as(?i64, 1000 + api_relay_total_ms), relayDeadline(false, 1000));
	try t.expectEqual(@as(i64, 60_000), api_relay_total_ms);
	try t.expectEqual(@as(i32, 10), read_header_timeout_secs);
}

test "redactedPath: quoted, capped, query values dropped except service (N5)" {
	var buf: [debug_path_cap * 4 + 8]u8 = undefined;
	try t.expectEqualStrings("\"/grp/proj.git/info/refs?service=git-upload-pack&foo\"", redactedPath(&buf, "/grp/proj.git/info/refs", "service=git-upload-pack&foo=SECRET"));
	try t.expectEqualStrings("\"/a\"", redactedPath(&buf, "/a", ""));
	// non-printable and quote bytes are escaped, never emitted raw
	try t.expectEqualStrings("\"/a\\x0D\\x22b\"", redactedPath(&buf, "/a\r\"b", ""));
	// the cap: a 300-byte path keeps 256 and marks the cut
	var long: [300]u8 = @splat('x');
	long[0] = '/';
	const out = redactedPath(&buf, &long, "");
	try t.expect(std.mem.endsWith(u8, out, "...\""));
	try t.expectEqual(@as(usize, 1 + debug_path_cap + 3 + 1), out.len);
}

test "maybeWritePidFile: absent while the first conf parse failed, written once it succeeds (S3)" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	const dir = try std.fmt.allocPrint(t.allocator, "zig-authproxy-pid-test-{s}", .{&hexb});
	defer t.allocator.free(dir);
	try cwd.createDirPath(io, dir);
	defer cwd.deleteTree(io, dir) catch {};
	const pid_path = try std.fs.path.join(t.allocator, &.{ dir, "authproxy.pid" });
	defer t.allocator.free(pid_path);

	var written = false;
	// A failed first parse: no pid file, and the flag stays down.
	try t.expect(maybeWritePidFile(io, dir, false, &written) == .parse_pending);
	try t.expect(!written);
	try t.expectError(error.FileNotFound, cwd.statFile(io, pid_path, .{}));
	// The first successful parse writes it once...
	try t.expect(maybeWritePidFile(io, dir, true, &written) == .written);
	try t.expect(written);
	const st = try cwd.statFile(io, pid_path, .{});
	try t.expect(st.size > 1);
	// ...and later ticks never rewrite it (a second successful parse is a
	// reload, not a restart).
	try t.expect(maybeWritePidFile(io, dir, true, &written) == .already_written);
	try t.expect(written);
	// A pre-created EMPTY file (the VM launcher's shape under a runas uid) is
	// filled in place: the pid lands in the existing inode.
	var written2 = false;
	try writeTestFile(io, pid_path, "");
	try t.expect(maybeWritePidFile(io, dir, true, &written2) == .written);
	try t.expect((try cwd.statFile(io, pid_path, .{})).size > 1);
}

test "maybeWritePidFile: a write that fails is reported as a WRITE failure, never as a parse failure, once (S3 log)" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	// a runtime dir that does not exist: createFile fails whatever uid runs
	// the test (a mode-based refusal would not reproduce under root)
	const dir = "zig-authproxy-pid-test-no-such-dir";
	var written = false;
	const outcome = maybeWritePidFile(io, dir, true, &written);
	try t.expect(!written);
	try t.expect(outcome == .write_failed);
	try t.expectEqual(error.FileNotFound, outcome.write_failed);
	// the report names the write, once; a parse-pending tick is its own
	// line, also once; a successful write is always named
	var rep: PidFileReport = .{};
	try t.expect(rep.note(outcome, dir));
	try t.expect(!rep.note(outcome, dir)); // one-shot: the loop retries every second
	try t.expect(!rep.parse_pending_logged); // the write failure did NOT claim a parse failure
	try t.expect(rep.note(.parse_pending, dir));
	try t.expect(!rep.note(.parse_pending, dir));
	try t.expect(!rep.note(.already_written, dir));
	try t.expect(rep.note(.written, dir));
}

test "tickOnce: the accept loop's FIRST tick on a fresh store polls and opens the pid gate, it does not trap" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	// The launcher's shape: a runtime dir holding a parseable conf.
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	const dir = try std.fmt.allocPrint(t.allocator, "zig-authproxy-tick-test-{s}", .{&hexb});
	defer t.allocator.free(dir);
	try cwd.createDirPath(io, dir);
	defer cwd.deleteTree(io, dir) catch {};
	const conf_path = try std.fs.path.join(t.allocator, &.{ dir, "l7-auth-conf.json" });
	defer t.allocator.free(conf_path);
	try writeTestFile(io, conf_path, "{\"version\":1,\"providers\":[]}");

	var store = conf.Store.init(t.allocator, io, conf_path, null);
	store.bundle_mode = .skip;
	defer store.deinit();
	var ctx = Context{ .gpa = t.allocator, .io = io, .store = &store, .transport = &upstream.real_transport };
	var pid_written = false;
	var pid_report: PidFileReport = .{};

	// The real clock against a store that has never polled: `run` polls once
	// itself but never records the time, so this tick is always the first one
	// to meet the sentinel.
	tickOnce(&ctx, &store, dir, &pid_written, &pid_report);
	try t.expect(store.has_cache); // it polled...
	try t.expect(pid_written); // ...and the parse gate released the pid file
	const pid_path = try std.fs.path.join(t.allocator, &.{ dir, "authproxy.pid" });
	defer t.allocator.free(pid_path);
	try t.expect((try cwd.statFile(io, pid_path, .{})).size > 1);

	// Every later tick is a no-op on an unchanged conf and never rewrites the
	// pid file.
	tickOnce(&ctx, &store, dir, &pid_written, &pid_report);
	try t.expect(store.has_cache);
	try t.expect(!pid_report.write_failed_logged);
	try t.expect(!pid_report.parse_pending_logged);
}

fn writeTestFile(io: std.Io, path: []const u8, bytes: []const u8) !void {
	const f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
	defer f.close(io);
	var wbuf: [64]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll(bytes);
	try w.flush();
}
