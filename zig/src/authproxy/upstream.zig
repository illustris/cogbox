// The upstream leg: hand-rolled dial to the X-Cogbox-Vetted ip:port on the
// repo's libc socket style, std.crypto.tls.Client for https,
// std.http.Client.Response.Head.parse as a pure response-head parser,
// std.http.Reader for response body framing, std.http.BodyWriter for the
// request body. std.http.Client itself is NOT instantiated (addendum D.2: no
// insecure switch so finding N2 is unimplementable there, a connect timeout
// that panics in Io.Threaded, Io-flavoured locks foreign to raw std.Thread
// workers, and IPv6 literals unreachable through HostName).
//
// NO POOLING in v1 -- one upstream connection per request (addendum D.4): the
// credential is set per request, "no request-derived upstream" is trivially
// true when every connection serves exactly one request, std TLS has no
// resumption to amortize anyway, and mitmproxy's lazy connection strategy
// already opens one upstream connection per flow today. Named residual: a
// chatty API workload pays one handshake per request.
//
// getaddrinfo is NEVER called here: resolution and the SSRF floor are
// l7proxy's alone (correction X3). The dial target is the vetted literal, and
// the core refuses any plugin-returned host that is not the conf entry's.

const std = @import("std");
const filter = @import("filter");
const framing = @import("framing.zig");
const plugin_mod = @import("plugin.zig");

const c = @cImport({
	@cDefine("_GNU_SOURCE", "1");
	// Disable glibc FORTIFY -- same reason as l7proxy/main.zig: the checked
	// inline wrappers fail to compile under translate-c in ReleaseSafe.
	@cDefine("_FORTIFY_SOURCE", "0");
	@cInclude("sys/socket.h");
	@cInclude("netinet/in.h");
	@cInclude("sys/time.h");
	@cInclude("unistd.h");
});

// connect takes glibc's transparent __SOCKADDR_ARG through @cImport, which Zig
// can't pass a plain pointer to; bind the raw symbol (l7proxy's idiom).
const c_connect = @extern(*const fn (c_int, *const c.struct_sockaddr, c.socklen_t) callconv(.c) c_int, .{ .name = "connect" });

pub const tls_min_len = std.crypto.tls.Client.min_buffer_len;

/// C.4 timeouts. Consts, not env knobs.
pub const connect_timeout_secs: i32 = 10;
pub const response_head_timeout_secs: i32 = 30;
pub const body_idle_timeout_secs: i32 = 60;
/// Both relays (the upload here, the response in the core) pump in bounded
/// slices so the API route's total deadline is checked between them.
pub const relay_chunk: usize = 64 * 1024;

/// The clock the C.4 total deadline is measured on (the core's audit dur_ms
/// reads the same one).
pub fn nowMs(io: std.Io) i64 {
	const ts = std.Io.Timestamp.now(io, .awake);
	return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}

pub const Error = error{
	HostNotAllowed,
	TooManyLegs,
	HttpsRefused,
	ConnectFailed,
	TlsFailed,
	WriteFailed,
	ReadFailed,
	BadResponse,
	BodyTruncated,
	/// The origin answered 1xx. An interim response is never relayed: the
	/// final response follows it on the same connection and this client does
	/// not consume interim ones, and std's respondStreaming asserts on
	/// `.continue`. Mapped to a 502 by the core.
	InformationalResponse,
	/// Something handed to the emitter cannot be printed into the constructed
	/// head without changing its line structure -- a control byte in a header
	/// value (a credential with an interior CRLF), a non-token header name, a
	/// host that is not a DNS name, a control byte or space in the path/query.
	/// Refused BEFORE any dial; mapped to a 502 by the core.
	BadHeader,
	/// An origin response header the relay refuses to carry downstream, so the
	/// WHOLE exchange is refused (a 502, never a partial relay): a name or
	/// value with a line-structure byte -- the response-side mirror of
	/// BadHeader (std's response parser splits on CRLF and never inspects the
	/// bytes of a name or value, and respondStreaming asserts only a non-empty
	/// name, so a lone LF/CR, a NUL or DEL in a value, or a space in a name
	/// would reach the guest verbatim as a header-splitting sequence); a
	/// duplicated SINGLETON header (Content-Length, Content-Type, Location --
	/// std keeps one copy silently); or more forwardable headers than the
	/// relay's set holds (a dropped tail behind a 200 the guest takes at face
	/// value is a fidelity gap it cannot see). Mapped to a 502 by the core.
	BadResponseHeader,
	/// C.4: the API route's TOTAL relay deadline passed with the request body
	/// still being relayed (an upload trickled past it). Refused before any
	/// response head; mapped to a 408 by the core. Never on a stream route,
	/// which carries no deadline.
	RelayDeadline,
};

pub const Conn = struct {
	r: *std.Io.Reader,
	w: *std.Io.Writer,
};

pub const ConnectParams = struct {
	ip: filter.IpAddr,
	port: u16,
	tls: bool,
	/// SNI + certificate name: the conf entry's host, never request-derived.
	host: []const u8,
	insecure: bool,
	bundle: *std.crypto.Certificate.Bundle,
	bundle_lock: *std.Io.RwLock,
	gpa: std.mem.Allocator,
	io: std.Io,
};

/// Per-request connection state, sized for the worst (TLS) case and owned by
/// the worker's frame -- the request path allocates nothing on the heap. The
/// TLS buffer sizes are ASSERTS in std, not errors (addendum D.3): the socket
/// reader/writer hold min_buffer_len and the plaintext read buffer holds
/// min_buffer_len + 8192 so a full record and a response head coexist.
pub const ConnStorage = struct {
	fd: c_int = -1,
	rd: framing.FdReader = undefined,
	wr: framing.FdWriter = undefined,
	rbuf: [tls_min_len]u8 = undefined,
	wbuf: [tls_min_len]u8 = undefined,
	tls_client: std.crypto.tls.Client = undefined,
	tls_read_buf: [tls_min_len + 8192]u8 = undefined,
	tls_write_buf: [1024]u8 = undefined,
	tls_active: bool = false,
	conn: ?Conn = null,
	http_reader: std.http.Reader = undefined,
	transfer_buf: [4096]u8 = undefined,
	body_buf: [4096]u8 = undefined,
	mediate_body_reader: std.Io.Reader = undefined,
	/// The header set a `mediate` hook hands its own leg. The default path uses
	/// the core's `scratch.auth_headers`, which a hook cannot reach; this is its
	/// twin, and it lives HERE precisely so it is inside the per-request scratch
	/// block and one `scrub()` covers it -- it carries `Authorization` exactly
	/// as the default path's set does (spec §7 custody).
	mediate_headers: plugin_mod.HeaderSet = .{},
	exchange: Exchange = undefined,

	/// Scrub the write-side buffers before the storage is freed: the serialized
	/// request head -- Authorization included -- sat in `wbuf` (and, for TLS,
	/// `tls_write_buf`), the request body in `body_buf`, and a mediate leg's
	/// Authorization in `mediate_headers`. Custody (spec §7): the credential
	/// lives in memory for one upstream request and nowhere after it, so heap
	/// reuse can never hand the next request's frame a stale token. The read
	/// side carries the origin's response, never the credential, and is left
	/// alone.
	pub fn scrub(self: *ConnStorage) void {
		std.crypto.secureZero(u8, &self.wbuf);
		std.crypto.secureZero(u8, &self.tls_write_buf);
		std.crypto.secureZero(u8, &self.body_buf);
		self.mediate_headers.zeroize();
	}
};

/// One completed upstream request: the parsed status, the already-stripped
/// forwardable response headers, and the (possibly still-streaming) body.
pub const Exchange = struct {
	status: u16,
	headers: plugin_mod.HeaderSet,
	content_length: ?u64,
	chunked: bool,
	body: ?*std.Io.Reader,
};

/// The dial seam (addendum G.2): tests substitute an in-memory transport, so
/// every core e2e assertion runs as an ordinary `zig test` with no sockets.
pub const Transport = struct {
	ctx: ?*anyopaque = null,
	connectFn: *const fn (t: *const Transport, storage: *ConnStorage, p: ConnectParams) Error!Conn,
	closeFn: *const fn (t: *const Transport, storage: *ConnStorage) void,
	/// Re-arm the connection's socket timeouts (C.4: the response-head phase
	/// runs at response_head_timeout_secs; once the head is in, the body relay
	/// is re-armed to the body_idle_timeout_secs IDLE bound -- an idle bound,
	/// not a deadline, because a multi-GB pack is legitimate). Null for a
	/// transport with no socket; the fake records the calls so the re-arm
	/// site is pinned by a test.
	armFn: ?*const fn (t: *const Transport, storage: *ConnStorage, secs: i32) void = null,

	pub fn arm(self: *const Transport, storage: *ConnStorage, secs: i32) void {
		if (self.armFn) |f| f(self, storage, secs);
	}
};

pub const real_transport: Transport = .{
	.connectFn = realConnect,
	.closeFn = realClose,
	.armFn = realArm,
};

fn realArm(t: *const Transport, storage: *ConnStorage, secs: i32) void {
	_ = t;
	if (storage.fd >= 0) setSocketTimeouts(storage.fd, secs);
}

fn realConnect(t: *const Transport, storage: *ConnStorage, p: ConnectParams) Error!Conn {
	_ = t;
	const fd = switch (p.ip) {
		.ipv4 => c.socket(c.AF_INET, c.SOCK_STREAM, 0),
		.ipv6 => c.socket(c.AF_INET6, c.SOCK_STREAM, 0),
	};
	if (fd < 0) return error.ConnectFailed;
	errdefer _ = c.close(fd);
	// SO_SNDTIMEO bounds connect(2) on Linux -- the l7proxy connectRaw shape,
	// preferred over a nonblocking-connect poll dance for the same deadline.
	setSocketTimeouts(fd, connect_timeout_secs);
	switch (p.ip) {
		.ipv4 => |b| {
			var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
			sa.sin_family = c.AF_INET;
			sa.sin_port = std.mem.nativeToBig(u16, p.port);
			sa.sin_addr.s_addr = @bitCast(b);
			if (c_connect(fd, @ptrCast(&sa), @sizeOf(c.struct_sockaddr_in)) != 0) return error.ConnectFailed;
		},
		.ipv6 => |b| {
			var sa: c.struct_sockaddr_in6 = std.mem.zeroes(c.struct_sockaddr_in6);
			sa.sin6_family = c.AF_INET6;
			sa.sin6_port = std.mem.nativeToBig(u16, p.port);
			@memcpy(@as([*]u8, @ptrCast(&sa.sin6_addr))[0..16], &b);
			if (c_connect(fd, @ptrCast(&sa), @sizeOf(c.struct_sockaddr_in6)) != 0) return error.ConnectFailed;
		},
	}
	// Response-head phase timeout; the body relay re-arms to the idle bound.
	setSocketTimeouts(fd, response_head_timeout_secs);
	storage.fd = fd;
	storage.rd = .init(fd, &storage.rbuf);
	storage.wr = .init(fd, &storage.wbuf);
	if (!p.tls) {
		storage.tls_active = false;
		return .{ .r = &storage.rd.interface, .w = &storage.wr.interface };
	}
	var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
	p.io.random(&entropy);
	storage.tls_client = std.crypto.tls.Client.init(&storage.rd.interface, &storage.wr.interface, .{
		.host = if (p.insecure) .no_verification else .{ .explicit = p.host },
		.ca = if (p.insecure)
			.no_verification
		else
			.{ .bundle = .{ .gpa = p.gpa, .io = p.io, .lock = p.bundle_lock, .bundle = p.bundle } },
		.write_buffer = &storage.tls_write_buf,
		.read_buffer = &storage.tls_read_buf,
		.entropy = &entropy,
		.realtime_now = std.Io.Timestamp.now(p.io, .real),
	}) catch return error.TlsFailed;
	storage.tls_active = true;
	return .{ .r = &storage.tls_client.reader, .w = &storage.tls_client.writer };
}

fn realClose(t: *const Transport, storage: *ConnStorage) void {
	_ = t;
	if (storage.fd >= 0) {
		_ = c.close(storage.fd);
		storage.fd = -1;
	}
	storage.tls_active = false;
	storage.conn = null;
}

pub fn setSocketTimeouts(fd: c_int, secs: i32) void {
	var tv: c.struct_timeval = .{ .tv_sec = secs, .tv_usec = 0 };
	_ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_RCVTIMEO, &tv, @sizeOf(c.struct_timeval));
	_ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_SNDTIMEO, &tv, @sizeOf(c.struct_timeval));
}

/// Explicit trust-store resolution (addendum D.3): honour SSL_CERT_FILE
/// (Bundle.rescan does NOT -- and the enforcer image's pkgs.cacert layout
/// matches none of rescan's file candidates, working only via its directory
/// arm by accident), else rescan. The caller treats an EMPTY resulting bundle
/// as "refuse https legs loudly", never as trust-nothing-opaquely.
pub fn loadTrustStore(gpa: std.mem.Allocator, io: std.Io, ssl_cert_file: ?[]const u8) !std.crypto.Certificate.Bundle {
	var cb: std.crypto.Certificate.Bundle = .empty;
	errdefer cb.deinit(gpa);
	const now = std.Io.Timestamp.now(io, .real);
	if (ssl_cert_file) |path| {
		if (path.len > 0) {
			try cb.addCertsFromFilePathAbsolute(gpa, io, now, path);
			return cb;
		}
	}
	try cb.rescan(gpa, io, now);
	return cb;
}

/// Response headers never forwarded downstream: Set-Cookie (an owner session
/// cookie would be a credential escape by another route) and the hop-by-hop
/// set. Content-Length/Transfer-Encoding are re-framed by the relay.
fn stripResponseHeader(name: []const u8) bool {
	const strip = [_][]const u8{
		"set-cookie", "connection", "keep-alive", "transfer-encoding",
		"trailer",    "te",         "upgrade",    "content-length",
	};
	for (&strip) |s| {
		if (std.ascii.eqlIgnoreCase(name, s)) return true;
	}
	if (std.ascii.startsWithIgnoreCase(name, "proxy-")) return true;
	return false;
}

/// Response headers that may appear at most ONCE (RFC 9110 §8.3, §8.6,
/// §10.2.2). A second copy REFUSES the exchange rather than collapsing: std's
/// response parser keeps the last Content-Type/Location silently and accepts
/// two equal Content-Lengths (only unequal ones are HttpHeadersInvalid), and
/// the relay re-frames from whichever copy it kept.
const Singleton = enum { content_length, content_type, location };

fn singletonResponseHeader(name: []const u8) ?Singleton {
	if (std.ascii.eqlIgnoreCase(name, "content-length")) return .content_length;
	if (std.ascii.eqlIgnoreCase(name, "content-type")) return .content_type;
	if (std.ascii.eqlIgnoreCase(name, "location")) return .location;
	return null;
}

/// The core's upstream client. Every leg -- the default single round trip and
/// each leg a mediate plugin drives -- goes through here, so the host
/// allowlist, the leg budget, the timeouts and the header emission rules are
/// enforced on a path the plugin cannot bypass.
pub const UpstreamIO = struct {
	transport: *const Transport,
	gpa: std.mem.Allocator,
	io: std.Io,
	/// The conf entry's host: the allowlist gate for every plugin-returned
	/// Upstream. This is the entire SSRF control on this leg (the provider is
	/// on RFC1918, so private-range refusal is unavailable as a second line).
	entry_host: []const u8,
	insecure: bool,
	vetted_ip: filter.IpAddr,
	vetted_port: u16,
	bundle: *std.crypto.Certificate.Bundle,
	bundle_lock: *std.Io.RwLock,
	bundle_empty: bool,
	storage: *ConnStorage,
	legs_used: u8 = 0,
	/// Request-body bytes relayed to the origin across every leg of this
	/// request (the audit line's bytes_in, H#26).
	body_bytes: u64 = 0,
	/// C.4: the API route's TOTAL relay deadline (null on a stream route),
	/// checked between upload slices on every leg; the core's response relay
	/// checks the same one. `now_ms` is the clock seam a test substitutes to
	/// trickle past it without waiting.
	deadline_ms: ?i64 = null,
	now_ms: *const fn (io: std.Io) i64 = nowMs,

	/// A mediate leg budget so a plugin cannot loop a token dance (§7).
	pub const max_legs: u8 = 4;

	/// The simple (mediate-facing) form: the request body, if any, as a slice.
	pub fn roundtrip(self: *UpstreamIO, up: *const plugin_mod.Upstream, method: std.http.Method, headers: *const plugin_mod.HeaderSet, body: ?[]const u8) Error!*Exchange {
		if (body) |b| {
			self.storage.mediate_body_reader = .fixed(b);
			return self.open(up, method, headers, &self.storage.mediate_body_reader, b.len);
		}
		return self.open(up, method, headers, null, null);
	}

	/// One full leg: dial the vetted address, emit the constructed head,
	/// stream the body (content-length when known, chunked otherwise), parse
	/// the response head, refuse a CL+TE response, strip Set-Cookie + hop
	/// headers, hand back the still-open exchange. Never follows a 3xx.
	pub fn open(self: *UpstreamIO, up: *const plugin_mod.Upstream, method: std.http.Method, headers: *const plugin_mod.HeaderSet, body: ?*std.Io.Reader, content_length: ?u64) Error!*Exchange {
		if (self.legs_used >= max_legs) return error.TooManyLegs;
		self.legs_used += 1;
		// The gate the plugin cannot bypass (spec §7): the upstream host is
		// the conf entry's, or the leg does not happen.
		if (!std.ascii.eqlIgnoreCase(up.host, self.entry_host)) return error.HostNotAllowed;
		if (up.scheme == .https and !self.insecure and self.bundle_empty) return error.HttpsRefused;
		// The emitter's own guard (§7 "construct every byte"): every line below
		// is printed verbatim, so nothing reaching it may carry a line break or
		// any other control byte -- the credential a plugin spliced into
		// Authorization, a mediate plugin's minted token, the conf host, the
		// rebuilt target. The inbound set was framing-checked, the cred reader
		// refuses control bytes, the conf validates the host and canon the
		// target; this is the belt under all four, decided BEFORE any dial.
		if (!filter.isValidHostName(up.host)) return error.BadHeader;
		if (!lineSafe(up.path()) or !lineSafe(up.query())) return error.BadHeader;
		if (!headersEmittable(headers)) return error.BadHeader;

		if (self.storage.conn != null) self.close();
		const conn = try self.transport.connectFn(self.transport, self.storage, .{
			.ip = self.vetted_ip,
			.port = self.vetted_port,
			.tls = up.scheme == .https,
			.host = up.host,
			.insecure = self.insecure,
			.bundle = self.bundle,
			.bundle_lock = self.bundle_lock,
			.gpa = self.gpa,
			.io = self.io,
		});
		self.storage.conn = conn;
		errdefer self.close();

		// --- the request head, constructed byte by byte (§7) ---
		const w = conn.w;
		w.print("{s} {s}", .{ @tagName(method), up.path() }) catch return error.WriteFailed;
		if (up.query().len > 0) w.print("?{s}", .{up.query()}) catch return error.WriteFailed;
		w.writeAll(" HTTP/1.1\r\n") catch return error.WriteFailed;
		w.print("host: {s}\r\n", .{up.host}) catch return error.WriteFailed;
		// One connection per request, and the origin is told so.
		w.writeAll("connection: close\r\n") catch return error.WriteFailed;
		var i: usize = 0;
		while (i < headers.len) : (i += 1) {
			const name = headers.names[i];
			// Owned by the emitter / never forwarded, even if a plugin put one
			// in the set: framing fields, Host, and the reserved namespace.
			if (std.ascii.eqlIgnoreCase(name, "host") or
				std.ascii.eqlIgnoreCase(name, "connection") or
				std.ascii.eqlIgnoreCase(name, "content-length") or
				std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
				std.ascii.startsWithIgnoreCase(name, "x-cogbox-")) continue;
			w.print("{s}: {s}\r\n", .{ name, headers.values[i] }) catch return error.WriteFailed;
		}
		if (body != null) {
			if (content_length) |cl| {
				w.print("content-length: {d}\r\n", .{cl}) catch return error.WriteFailed;
			} else {
				w.writeAll("transfer-encoding: chunked\r\n") catch return error.WriteFailed;
			}
		}
		w.writeAll("\r\n") catch return error.WriteFailed;

		// --- the request body, re-framed from scratch (never the guest's
		// chunk framing), streamed without buffering ---
		if (body) |body_reader| {
			// C.4 (S6, the request direction): the upload runs under the IDLE
			// bound, not the 30 s response-head bound the dial armed -- a
			// SO_SNDTIMEO trip while the origin is busy (index-pack on a large
			// push, a full send buffer) would otherwise cut the pack mid-stream
			// and surface as BodyTruncated. The head bound is restored below
			// once the body is out, for the head wait it was specified for.
			self.transport.arm(self.storage, body_idle_timeout_secs);
			var bw: std.http.BodyWriter = .{
				.http_protocol_output = w,
				.state = if (content_length) |cl| .{ .content_length = cl } else .init_chunked,
				.writer = .{
					.buffer = &self.storage.body_buf,
					.vtable = if (content_length != null)
						&.{ .drain = std.http.BodyWriter.contentLengthDrain }
					else
						&.{ .drain = std.http.BodyWriter.chunkedDrain },
				},
			};
			// Pumped in bounded slices so the API route's TOTAL deadline (C.4)
			// is checked between them, as the core's response relay does: a
			// body trickled one byte per idle bound would otherwise hold one
			// of the core's inflight slots for as long as the guest kept it
			// coming, with neither socket bound ever tripping.
			upload: while (true) {
				const n = body_reader.stream(&bw.writer, .limited(relay_chunk)) catch |err| switch (err) {
					error.EndOfStream => break :upload,
					else => return error.BodyTruncated,
				};
				self.body_bytes += n;
				if (self.deadline_ms) |d| {
					if (self.now_ms(self.io) > d) return error.RelayDeadline;
				}
			}
			// Drain the BodyWriter's buffer BEFORE reading its state: the
			// content-length countdown moves on drain, not on write, so a body
			// under one buffer's worth would otherwise still read as "not yet
			// sent" here and be refused as truncated.
			bw.writer.flush() catch return error.WriteFailed;
			switch (bw.state) {
				// The guest declared more than it sent: never complete a short
				// body under a full-length header (the origin sees the cut
				// connection and discards it; BodyWriter.end would assert).
				.content_length => |left| if (left != 0) return error.BodyTruncated,
				else => {},
			}
			bw.end() catch return error.WriteFailed;
			self.transport.arm(self.storage, response_head_timeout_secs);
		} else {
			w.flush() catch return error.WriteFailed;
		}
		// A TLS flush does not flush the underlying socket writer (D.3).
		if (self.storage.tls_active) self.storage.wr.interface.flush() catch return error.WriteFailed;

		// --- the response head ---
		self.storage.http_reader = .{
			.in = conn.r,
			.interface = undefined,
			.state = .ready,
			.max_head_len = @min(framing.max_head_bytes, conn.r.buffer.len),
		};
		const head_bytes = self.storage.http_reader.receiveHead() catch return error.BadResponse;
		const head = std.http.Client.Response.Head.parse(head_bytes) catch return error.BadResponse;
		// std's response parser sets CL and TE independently (Client.zig:596-606);
		// a response carrying both is refused, mirroring the request side.
		if (head.transfer_encoding == .chunked and head.content_length != null) return error.BadResponse;
		// A 1xx is NEVER relayed (see Error.InformationalResponse): the guest
		// gets a 502, and the final response this client never reads is dropped
		// with the connection.
		if (@intFromEnum(head.status) < 200) return error.InformationalResponse;
		// The head is in: the relay runs on the IDLE bound from here (C.4).
		self.transport.arm(self.storage, body_idle_timeout_secs);

		const ex = &self.storage.exchange;
		ex.* = .{
			.status = @intFromEnum(head.status),
			.headers = .{},
			.content_length = head.content_length,
			.chunked = head.transfer_encoding == .chunked,
			.body = null,
		};
		// Copy the forwardable headers OUT of the head bytes now: they alias
		// the socket buffer, which the body stream refills. APPEND, not set:
		// a repeated `Vary:` / `WWW-Authenticate:` / `Link:` is each meaningful
		// and the guest (and a mediate plugin reading a multi-challenge 401)
		// must see every copy. Anything the relay cannot carry WHOLE refuses
		// the exchange (Error.BadResponseHeader): never a header dropped or a
		// tail truncated behind a status the guest would take at face value.
		var seen_singleton: [3]bool = @splat(false);
		var it = head.iterateHeaders();
		while (it.next()) |h| {
			// A duplicated singleton is checked BEFORE the strip: Content-Length
			// is re-framed from head.content_length, which std filled from
			// whichever copy it kept (two equal copies parse clean).
			if (singletonResponseHeader(h.name)) |s| {
				if (seen_singleton[@intFromEnum(s)]) return error.BadResponseHeader;
				seen_singleton[@intFromEnum(s)] = true;
			}
			if (stripResponseHeader(h.name)) continue;
			// The response-side mirror of the request emitter's guard (F1).
			if (!headerEmittable(h.name, h.value)) return error.BadResponseHeader;
			// Over-capacity: refuse whole, never a value truncated or a tail
			// dropped.
			ex.headers.append(h.name, h.value) catch return error.BadResponseHeader;
		}

		// Bodyless by HTTP semantics (RFC 9110 §6.4.1): a HEAD response, 204,
		// 304. The core relays these as head-only (never a content-length
		// framed body it would then fail to write -- see streamResponse).
		const status_int: u16 = @intFromEnum(head.status);
		const bodyless = method == .HEAD or status_int == 204 or status_int == 304;
		if (!bodyless) {
			ex.body = self.storage.http_reader.bodyReader(&self.storage.transfer_buf, head.transfer_encoding, head.content_length);
		}
		return ex;
	}

	pub fn close(self: *UpstreamIO) void {
		self.transport.closeFn(self.transport, self.storage);
		self.storage.conn = null;
	}
};

/// Whether every header in the set can be printed as `name: value\r\n` without
/// altering the head's line structure: tchar-only, non-empty names; values
/// with no C0 byte but HTAB and no DEL (framing.check's inbound rule, applied
/// to the outbound set).
pub fn headersEmittable(headers: *const plugin_mod.HeaderSet) bool {
	var i: usize = 0;
	while (i < headers.len) : (i += 1) {
		if (!headerEmittable(headers.names[i], headers.values[i])) return false;
	}
	return true;
}

/// The single-header form of the same rule, shared by the request emitter
/// (refuse the leg) and the response relay (refuse the exchange).
pub fn headerEmittable(name: []const u8, value: []const u8) bool {
	if (name.len == 0) return false;
	for (name) |ch| {
		if (!framing.isTchar(ch)) return false;
	}
	for (value) |ch| {
		if ((ch < 0x20 and ch != '\t') or ch == 0x7f) return false;
	}
	return true;
}

/// Request-line safety for the rebuilt path/query: no control byte, no DEL,
/// no space (the request line is space-delimited).
fn lineSafe(bytes: []const u8) bool {
	for (bytes) |ch| {
		if (ch <= 0x20 or ch == 0x7f) return false;
	}
	return true;
}

// --- Test seam: an in-memory transport ---

/// Scripted fake upstream (pub: the core e2e tests in tests.zig drive the
/// whole server path through it). Each connect consumes the next script as
/// the response bytes and captures the emitted request.
pub const FakeTransport = struct {
	gpa: std.mem.Allocator,
	scripts: []const []const u8,
	calls: usize = 0,
	reader: std.Io.Reader = undefined,
	capture: std.Io.Writer.Allocating,
	/// Finished request bytes, one per completed connect.
	captured: std.ArrayList([]u8) = .empty,
	transport: Transport = undefined,
	/// Set by tests that need a custom (instrumented) response reader.
	override_reader: ?*std.Io.Reader = null,
	/// Every socket-timeout re-arm the core requested, in order (seconds).
	arms: std.ArrayList(i32) = .empty,
	/// The request-side writer: buffered in the SAME `storage.wbuf` production
	/// routes the head through (realConnect's FdWriter), draining into
	/// `capture` -- so a custody test sees the serialized Authorization where
	/// it really lands, and ConnStorage.scrub is pinned by an e2e (S5).
	wr: std.Io.Writer = undefined,
	wr_live: bool = false,

	pub fn init(gpa: std.mem.Allocator, scripts: []const []const u8) FakeTransport {
		return .{ .gpa = gpa, .scripts = scripts, .capture = .init(gpa) };
	}

	pub fn deinit(self: *FakeTransport) void {
		for (self.captured.items) |b| self.gpa.free(b);
		self.captured.deinit(self.gpa);
		self.capture.deinit();
		self.arms.deinit(self.gpa);
	}

	pub fn t(self: *FakeTransport) *const Transport {
		self.transport = .{ .ctx = self, .connectFn = connect, .closeFn = closeFn, .armFn = armFn };
		return &self.transport;
	}

	fn armFn(tr: *const Transport, storage: *ConnStorage, secs: i32) void {
		_ = storage;
		const self: *FakeTransport = @ptrCast(@alignCast(tr.ctx.?));
		self.arms.append(self.gpa, secs) catch {};
	}

	fn connect(tr: *const Transport, storage: *ConnStorage, p: ConnectParams) Error!Conn {
		_ = p;
		const self: *FakeTransport = @ptrCast(@alignCast(tr.ctx.?));
		if (self.calls >= self.scripts.len) return error.ConnectFailed;
		self.reader = .fixed(self.scripts[self.calls]);
		self.calls += 1;
		self.capture.clearRetainingCapacity();
		self.wr = .{ .vtable = &.{ .drain = captureDrain }, .buffer = &storage.wbuf, .end = 0 };
		self.wr_live = true;
		return .{
			.r = self.override_reader orelse &self.reader,
			.w = &self.wr,
		};
	}

	/// FdWriter.drain's shape over the capture sink: the buffered bytes first,
	/// then the vectored data, then the splat pattern.
	fn captureDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
		const self: *FakeTransport = @alignCast(@fieldParentPtr("wr", w));
		const sink = &self.capture.writer;
		sink.writeAll(w.buffered()) catch return error.WriteFailed;
		w.end = 0;
		if (data.len == 0) return 0;
		var total: usize = 0;
		for (data[0 .. data.len - 1]) |d| {
			sink.writeAll(d) catch return error.WriteFailed;
			total += d.len;
		}
		const pattern = data[data.len - 1];
		var i: usize = 0;
		while (i < splat) : (i += 1) {
			sink.writeAll(pattern) catch return error.WriteFailed;
			total += pattern.len;
		}
		return total;
	}

	fn closeFn(tr: *const Transport, storage: *ConnStorage) void {
		_ = storage;
		const self: *FakeTransport = @ptrCast(@alignCast(tr.ctx.?));
		if (self.wr_live) {
			self.wr.flush() catch {};
			self.wr_live = false;
		}
		if (self.capture.written().len > 0 or self.calls > self.captured.items.len) {
			const copy = self.gpa.dupe(u8, self.capture.written()) catch return;
			self.captured.append(self.gpa, copy) catch {
				self.gpa.free(copy);
				return;
			};
			self.capture.clearRetainingCapacity();
		}
	}
};

/// A transport that always refuses -- the "upstream never dialed" assertion.
pub const RefusingTransport = struct {
	calls: usize = 0,
	transport: Transport = undefined,

	pub fn t(self: *RefusingTransport) *const Transport {
		self.transport = .{ .ctx = self, .connectFn = connect, .closeFn = closeFn };
		return &self.transport;
	}

	fn connect(tr: *const Transport, storage: *ConnStorage, p: ConnectParams) Error!Conn {
		_ = storage;
		_ = p;
		const self: *RefusingTransport = @ptrCast(@alignCast(tr.ctx.?));
		self.calls += 1;
		return error.ConnectFailed;
	}

	fn closeFn(tr: *const Transport, storage: *ConnStorage) void {
		_ = tr;
		_ = storage;
	}
};

// --- Tests ---

const t_ = std.testing;

var test_bundle: std.crypto.Certificate.Bundle = .empty;
var test_lock: std.Io.RwLock = .init;

/// A heap ConnStorage (far too large for a test frame), zero-INITIALIZED and
/// not merely allocated: production builds it as part of `RequestScratch.{}`,
/// and the request path reads defaulted fields off it -- `conn` before a dial,
/// and now `mediate_headers.used` in `scrub`.
fn testStorage() *ConnStorage {
	const s = t_.allocator.create(ConnStorage) catch unreachable;
	s.* = .{};
	return s;
}

fn testUio(tr: *const Transport, storage: *ConnStorage, scheme_https_refused: bool) UpstreamIO {
	return .{
		.transport = tr,
		.gpa = t_.allocator,
		.io = undefined, // the fake transport never touches io
		.entry_host = "git.example.com",
		.insecure = false,
		.vetted_ip = .{ .ipv4 = .{ 10, 0, 0, 5 } },
		.vetted_port = 443,
		.bundle = &test_bundle,
		.bundle_lock = &test_lock,
		.bundle_empty = scheme_https_refused,
		.storage = storage,
	};
}

test "UpstreamIO: constructs the head, re-frames the body, parses the response, strips" {
	var fake = FakeTransport.init(t_.allocator, &.{
		"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nset-cookie: s=1\r\nx-custom: keep\r\nconnection: close\r\n\r\nhello",
	});
	defer fake.deinit();
	const storage = testStorage();
	defer t_.allocator.destroy(storage);
	var uio = testUio(fake.t(), storage, false);

	var up: plugin_mod.Upstream = .{ .scheme = .http, .host = "git.example.com" };
	try up.appendPath("/api/v4/user");
	var hdrs: plugin_mod.HeaderSet = .{};
	try hdrs.set("authorization", "Bearer FAKE");
	try hdrs.set("user-agent", "git/2.43");
	try hdrs.set("host", "evil.example.com"); // must be ignored: Host comes from the conf

	const ex = try uio.open(&up, .GET, &hdrs, null, null);
	try t_.expectEqual(@as(u16, 200), ex.status);
	try t_.expectEqual(@as(?u64, 5), ex.content_length);
	// stripped + kept response headers
	try t_.expect(ex.headers.get("set-cookie") == null);
	try t_.expect(ex.headers.get("connection") == null);
	try t_.expectEqualStrings("keep", ex.headers.get("x-custom").?);
	// body streams
	var out: [16]u8 = undefined;
	var fw: std.Io.Writer = .fixed(&out);
	const n = try ex.body.?.streamRemaining(&fw);
	try t_.expectEqualStrings("hello", out[0..n]);
	uio.close();

	const req = fake.captured.items[0];
	try t_.expect(std.mem.startsWith(u8, req, "GET /api/v4/user HTTP/1.1\r\n"));
	try t_.expect(std.mem.indexOf(u8, req, "host: git.example.com\r\n") != null);
	try t_.expect(std.mem.indexOf(u8, req, "evil.example.com") == null);
	try t_.expect(std.mem.indexOf(u8, req, "authorization: Bearer FAKE\r\n") != null);
	try t_.expect(std.mem.indexOf(u8, req, "connection: close\r\n") != null);
	// never synthesized
	try t_.expect(std.mem.indexOf(u8, req, "X-Forwarded-For") == null);
	try t_.expect(std.mem.indexOf(u8, req, "x-forwarded-for") == null);
	// The fake serialized the head through storage.wbuf exactly as production
	// does (the buffer still holds it after the flush) -- which is what lets
	// the S5 custody e2e assert scrub() emptied it.
	try t_.expect(std.mem.indexOf(u8, &storage.wbuf, "authorization: Bearer FAKE\r\n") != null);
	storage.scrub();
	try t_.expect(std.mem.indexOf(u8, &storage.wbuf, "Bearer FAKE") == null);
}

test "UpstreamIO: the emitter refuses a control byte in any header, the host or the target BEFORE dialing (F1)" {
	var refusing = RefusingTransport{};
	const storage = testStorage();
	defer t_.allocator.destroy(storage);
	var uio = testUio(refusing.t(), storage, false);
	var up: plugin_mod.Upstream = .{ .scheme = .http, .host = "git.example.com" };
	try up.appendPath("/api/v4/user");

	// a credential with an interior CRLF, spliced as the gitlab plugin would
	var h1: plugin_mod.HeaderSet = .{};
	try h1.set("authorization", "Bearer glpat-AAA\r\nx-injected-by-cred: 1");
	try t_.expectError(error.BadHeader, uio.open(&up, .GET, &h1, null, null));
	// a DEL in a value; a name that is not a token; an empty name
	var h2: plugin_mod.HeaderSet = .{};
	try h2.set("user-agent", "git\x7f");
	try t_.expectError(error.BadHeader, uio.open(&up, .GET, &h2, null, null));
	var h3: plugin_mod.HeaderSet = .{};
	try h3.set("x injected", "1");
	try t_.expectError(error.BadHeader, uio.open(&up, .GET, &h3, null, null));
	try t_.expectEqual(@as(usize, 0), refusing.calls); // decided before any dial
	uio.legs_used = 0;

	// the host line: entry and plugin agree on a value that is not a DNS name
	uio.entry_host = "git.example.com\r\nx-injected: 1";
	var bad_host: plugin_mod.Upstream = .{ .scheme = .http, .host = "git.example.com\r\nx-injected: 1" };
	try bad_host.appendPath("/");
	var h4: plugin_mod.HeaderSet = .{};
	try t_.expectError(error.BadHeader, uio.open(&bad_host, .GET, &h4, null, null));
	uio.entry_host = "git.example.com";
	// the request line: a control byte or a space in the rebuilt path/query
	var bad_path: plugin_mod.Upstream = .{ .scheme = .http, .host = "git.example.com" };
	try bad_path.appendPath("/api/v4/user HTTP/1.1\r\nx-injected: 1\r\n");
	try t_.expectError(error.BadHeader, uio.open(&bad_path, .GET, &h4, null, null));
	var bad_query: plugin_mod.Upstream = .{ .scheme = .http, .host = "git.example.com" };
	try bad_query.appendPath("/api/v4/user");
	try bad_query.appendQuery("a=b\rc");
	try t_.expectError(error.BadHeader, uio.open(&bad_query, .GET, &h4, null, null));
	try t_.expectEqual(@as(usize, 0), refusing.calls);

	// HTAB inside a value is legal field content and still emits
	var fake = FakeTransport.init(t_.allocator, &.{"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"});
	defer fake.deinit();
	var ok_uio = testUio(fake.t(), storage, false);
	var h5: plugin_mod.HeaderSet = .{};
	try h5.set("user-agent", "git\t2.43");
	_ = try ok_uio.open(&up, .GET, &h5, null, null);
	try t_.expectEqual(@as(usize, 1), fake.calls);
}

test "headersEmittable: the outbound rule mirrors framing's inbound one" {
	var h: plugin_mod.HeaderSet = .{};
	try h.set("accept", "*/*");
	try h.set("git-protocol", "version=2");
	try t_.expect(headersEmittable(&h));
	try h.set("accept", "a\nb");
	try t_.expect(!headersEmittable(&h));
	try h.set("accept", "a\x00b");
	try t_.expect(!headersEmittable(&h));
	try h.set("accept", "a\tb"); // HTAB admitted
	try t_.expect(headersEmittable(&h));
	try h.set("bad name", "1");
	try t_.expect(!headersEmittable(&h));
}

test "UpstreamIO: the host gate refuses a plugin-returned host outside the entry" {
	var refusing = RefusingTransport{};
	const storage = testStorage();
	defer t_.allocator.destroy(storage);
	var uio = testUio(refusing.t(), storage, false);
	var up: plugin_mod.Upstream = .{ .scheme = .http, .host = "api.example.com" };
	try up.appendPath("/");
	var hdrs: plugin_mod.HeaderSet = .{};
	try t_.expectError(error.HostNotAllowed, uio.open(&up, .GET, &hdrs, null, null));
	// and the transport was never dialed
	try t_.expectEqual(@as(usize, 0), refusing.calls);
}

test "UpstreamIO: an https leg over an empty bundle is refused before any dial" {
	var refusing = RefusingTransport{};
	const storage = testStorage();
	defer t_.allocator.destroy(storage);
	var uio = testUio(refusing.t(), storage, true);
	var up: plugin_mod.Upstream = .{ .scheme = .https, .host = "git.example.com" };
	try up.appendPath("/");
	var hdrs: plugin_mod.HeaderSet = .{};
	try t_.expectError(error.HttpsRefused, uio.open(&up, .GET, &hdrs, null, null));
	try t_.expectEqual(@as(usize, 0), refusing.calls);
}

test "UpstreamIO: a CL+TE response is refused; the leg budget caps a mediate loop" {
	var fake = FakeTransport.init(t_.allocator, &.{
		"HTTP/1.1 200 OK\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n",
	});
	defer fake.deinit();
	const storage = testStorage();
	defer t_.allocator.destroy(storage);
	var uio = testUio(fake.t(), storage, false);
	var up: plugin_mod.Upstream = .{ .scheme = .http, .host = "git.example.com" };
	try up.appendPath("/");
	var hdrs: plugin_mod.HeaderSet = .{};
	try t_.expectError(error.BadResponse, uio.open(&up, .GET, &hdrs, null, null));

	uio.legs_used = UpstreamIO.max_legs;
	try t_.expectError(error.TooManyLegs, uio.open(&up, .GET, &hdrs, null, null));
}

test "UpstreamIO: an upstream 1xx is refused, never relayed (B1's second arm)" {
	var fake = FakeTransport.init(t_.allocator, &.{
		"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n",
	});
	defer fake.deinit();
	const storage = testStorage();
	defer t_.allocator.destroy(storage);
	var uio = testUio(fake.t(), storage, false);
	var up: plugin_mod.Upstream = .{ .scheme = .http, .host = "git.example.com" };
	try up.appendPath("/");
	var hdrs: plugin_mod.HeaderSet = .{};
	try t_.expectError(error.InformationalResponse, uio.open(&up, .GET, &hdrs, null, null));
}

test "UpstreamIO: the body relay is re-armed to the idle bound once the head is in (S6 pin)" {
	var fake = FakeTransport.init(t_.allocator, &.{"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"});
	defer fake.deinit();
	const storage = testStorage();
	defer t_.allocator.destroy(storage);
	var uio = testUio(fake.t(), storage, false);
	var up: plugin_mod.Upstream = .{ .scheme = .http, .host = "git.example.com" };
	try up.appendPath("/");
	var hdrs: plugin_mod.HeaderSet = .{};
	_ = try uio.open(&up, .GET, &hdrs, null, null);
	// Exactly one re-arm, to the idle bound, after the response head parsed.
	try t_.expectEqualSlices(i32, &.{body_idle_timeout_secs}, fake.arms.items);
	// The C.4 constants, pinned: connect 10s, response head 30s, idle 60s.
	try t_.expectEqual(@as(i32, 10), connect_timeout_secs);
	try t_.expectEqual(@as(i32, 30), response_head_timeout_secs);
	try t_.expectEqual(@as(i32, 60), body_idle_timeout_secs);
}

test "UpstreamIO: a body-bearing leg uploads under the idle bound, waits for the head under the head bound, then relays idle (S6, request direction)" {
	var fake = FakeTransport.init(t_.allocator, &.{"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"});
	defer fake.deinit();
	const storage = testStorage();
	defer t_.allocator.destroy(storage);
	var uio = testUio(fake.t(), storage, false);
	var up: plugin_mod.Upstream = .{ .scheme = .http, .host = "git.example.com" };
	try up.appendPath("/grp/proj.git/git-receive-pack");
	var hdrs: plugin_mod.HeaderSet = .{};
	var body: std.Io.Reader = .fixed("PACK");
	_ = try uio.open(&up, .POST, &hdrs, &body, 4);
	// idle (the upload) -> head bound (the wait for the response head) -> idle
	// (the response relay). Before this pin the upload ran under the 30 s head
	// bound the dial armed, so a stall longer than that mid-push was a 502.
	try t_.expectEqualSlices(i32, &.{ body_idle_timeout_secs, response_head_timeout_secs, body_idle_timeout_secs }, fake.arms.items);
	uio.close(); // the fake captures the emitted request on close
	try t_.expect(std.mem.endsWith(u8, fake.captured.items[0], "\r\n\r\nPACK"));
}

test "UpstreamIO: an origin header std parsed without inspecting REFUSES the exchange, never relays it (response-side mirror of F1)" {
	// One offending header per script, among good ones: a lone LF in a value
	// (not the \n\n head terminator, not the \r\n the splitter uses), a lone
	// CR, a NUL, a DEL, a space in a name.
	const scripts = [_][]const u8{
		"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nx-first: ok\r\nx-lf: a\nb\r\nx-last: ok\r\n\r\n",
		"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nx-cr: a\rb\r\n\r\n",
		"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nx-nul: a\x00b\r\n\r\n",
		"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nx-del: a\x7fb\r\n\r\n",
		"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nbad name: 1\r\n\r\n",
	};
	var fake = FakeTransport.init(t_.allocator, &scripts);
	defer fake.deinit();
	const storage = testStorage();
	defer t_.allocator.destroy(storage);
	var uio = testUio(fake.t(), storage, false);
	var up: plugin_mod.Upstream = .{ .scheme = .http, .host = "git.example.com" };
	try up.appendPath("/");
	var hdrs: plugin_mod.HeaderSet = .{};
	for (scripts) |_| {
		try t_.expectError(error.BadResponseHeader, uio.open(&up, .GET, &hdrs, null, null));
		uio.legs_used = 0;
	}
	try t_.expectEqual(scripts.len, fake.calls); // every script was consumed, i.e. each one refused on its own

	// HTAB inside a value is field content and relays
	var ok_fake = FakeTransport.init(t_.allocator, &.{"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nx-tab: a\tb\r\n\r\n"});
	defer ok_fake.deinit();
	var ok_uio = testUio(ok_fake.t(), storage, false);
	const ex = try ok_uio.open(&up, .GET, &hdrs, null, null);
	try t_.expectEqual(@as(u16, 200), ex.status);
	try t_.expectEqualStrings("a\tb", ex.headers.get("x-tab").?);
}

test "UpstreamIO: multi-valued origin headers are all relayed; a duplicated singleton or an over-capacity head refuses the exchange (N3)" {
	var fake = FakeTransport.init(t_.allocator, &.{
		"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nvary: Accept-Encoding\r\nvary: Cookie\r\n" ++
			"www-authenticate: Bearer realm=\"a\"\r\nwww-authenticate: Basic realm=\"b\"\r\n\r\n",
		// the three singletons, each duplicated: two EQUAL Content-Lengths
		// parse clean in std (only unequal ones are HttpHeadersInvalid); a
		// second Content-Type / Location silently wins there
		"HTTP/1.1 200 OK\r\ncontent-length: 0\r\ncontent-length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\ncontent-length: 0\r\ncontent-type: text/plain\r\ncontent-type: text/html\r\n\r\n",
		"HTTP/1.1 302 Found\r\ncontent-length: 0\r\nlocation: /a\r\nlocation: /b\r\n\r\n",
	});
	defer fake.deinit();
	const storage = testStorage();
	defer t_.allocator.destroy(storage);
	var uio = testUio(fake.t(), storage, false);
	var up: plugin_mod.Upstream = .{ .scheme = .http, .host = "git.example.com" };
	try up.appendPath("/");
	var hdrs: plugin_mod.HeaderSet = .{};
	const ex = try uio.open(&up, .GET, &hdrs, null, null);
	try t_.expectEqual(@as(usize, 4), ex.headers.len);
	try t_.expectEqualStrings("vary", ex.headers.names[0]);
	try t_.expectEqualStrings("Accept-Encoding", ex.headers.values[0]);
	try t_.expectEqualStrings("Cookie", ex.headers.values[1]);
	try t_.expectEqualStrings("Bearer realm=\"a\"", ex.headers.values[2]);
	try t_.expectEqualStrings("Basic realm=\"b\"", ex.headers.values[3]);
	uio.close();
	var k: usize = 0;
	while (k < 3) : (k += 1) {
		uio.legs_used = 0;
		try t_.expectError(error.BadResponseHeader, uio.open(&up, .GET, &hdrs, null, null));
	}
	try t_.expectEqual(@as(usize, 4), fake.calls);

	// exactly max_headers forwardable headers are carried whole...
	var script = std.Io.Writer.Allocating.init(t_.allocator);
	defer script.deinit();
	try script.writer.writeAll("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n");
	var i: usize = 0;
	while (i < plugin_mod.max_headers) : (i += 1) try script.writer.print("x-h{d}: v{d}\r\n", .{ i, i });
	try script.writer.writeAll("\r\n");
	var fake2 = FakeTransport.init(t_.allocator, &.{script.written()});
	defer fake2.deinit();
	var uio2 = testUio(fake2.t(), storage, false);
	const ex2 = try uio2.open(&up, .GET, &hdrs, null, null);
	try t_.expectEqual(@as(usize, plugin_mod.max_headers), ex2.headers.len);
	try t_.expectEqualStrings("v0", ex2.headers.get("x-h0").?);
	uio2.close();
	// ...and one more refuses the exchange whole: never a tail dropped behind
	// a 200 the guest would take at face value
	var over = std.Io.Writer.Allocating.init(t_.allocator);
	defer over.deinit();
	try over.writer.writeAll(script.written()[0 .. script.written().len - 2]);
	try over.writer.print("x-h{d}: v{d}\r\n\r\n", .{ plugin_mod.max_headers, plugin_mod.max_headers });
	var fake3 = FakeTransport.init(t_.allocator, &.{over.written()});
	defer fake3.deinit();
	var uio3 = testUio(fake3.t(), storage, false);
	try t_.expectError(error.BadResponseHeader, uio3.open(&up, .GET, &hdrs, null, null));
}

test "UpstreamIO: bytes_in meters the relayed request body across legs" {
	var fake = FakeTransport.init(t_.allocator, &.{
		"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n",
	});
	defer fake.deinit();
	const storage = testStorage();
	defer t_.allocator.destroy(storage);
	var uio = testUio(fake.t(), storage, false);
	var up: plugin_mod.Upstream = .{ .scheme = .http, .host = "git.example.com" };
	try up.appendPath("/x");
	var hdrs: plugin_mod.HeaderSet = .{};
	_ = try uio.roundtrip(&up, .POST, &hdrs, "hello");
	_ = try uio.roundtrip(&up, .POST, &hdrs, "wor");
	try t_.expectEqual(@as(u64, 8), uio.body_bytes);
}

test "ConnStorage.scrub zeroes the write-side buffers that carried the credential" {
	const storage = testStorage();
	defer t_.allocator.destroy(storage);
	@memset(&storage.wbuf, 0x41);
	@memset(&storage.tls_write_buf, 0x42);
	@memset(&storage.body_buf, 0x43);
	// the mediate leg's own header set is inside the block, and carries the
	// credential exactly as the default path's does
	try storage.mediate_headers.set("authorization", "Basic SECRETSECRET");
	storage.scrub();
	try t_.expect(std.mem.allEqual(u8, &storage.wbuf, 0));
	try t_.expect(std.mem.allEqual(u8, &storage.tls_write_buf, 0));
	try t_.expect(std.mem.allEqual(u8, &storage.body_buf, 0));
	try t_.expectEqual(@as(usize, 0), storage.mediate_headers.len);
	try t_.expect(std.mem.indexOf(u8, &storage.mediate_headers.storage, "SECRET") == null);
}

test "UpstreamIO: a body shorter than its declared length never reaches the origin whole" {
	var fake = FakeTransport.init(t_.allocator, &.{"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"});
	defer fake.deinit();
	const storage = testStorage();
	defer t_.allocator.destroy(storage);
	var uio = testUio(fake.t(), storage, false);
	var up: plugin_mod.Upstream = .{ .scheme = .http, .host = "git.example.com" };
	try up.appendPath("/x");
	var hdrs: plugin_mod.HeaderSet = .{};
	var short: std.Io.Reader = .fixed("abc"); // declared 10, delivers 3
	try t_.expectError(error.BodyTruncated, uio.open(&up, .POST, &hdrs, &short, 10));
}
