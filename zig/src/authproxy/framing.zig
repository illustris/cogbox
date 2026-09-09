// The MANDATORY strict pre-parse over std.http.Server's head bytes, plus the
// fd-backed Io.Reader/Io.Writer adapters the socket layer uses.
//
// std.http.Server is used for framing, body decode, keep-alive and response
// emission -- but its validation cannot be trusted alone (addendum C.2, read
// from source): it ACCEPTS Content-Length together with Transfer-Encoding
// (TE silently winning -- the CL.TE smuggling primitive), never parses Host at
// all, accepts a space-bearing target, silently ignores a header whose name
// has trailing whitespace, leaves a GET-declared body in the stream on a
// reusable connection, and asserts (panics in ReleaseSafe) on a bodiless POST
// answered without reading the body. This pre-parse runs over the EXACT bytes
// std parsed (Request.head_buffer, whose doc comment invites re-parsing) and
// closes each of those, extending l7proxy/http.zig parseRequestHead's
// discipline -- not copying it: that parser runs on a peeked prefix and
// returns a normalized path, which canonicalization deliberately does NOT
// want here (canon.zig is segment-first).
//
// THE HARD RULE (addendum I.2 item 12): every framing refusal responds with
// keep_alive=false and the connection then closes. That is what makes std's
// bare-LF head/body boundary difference unexploitable, and it side-steps the
// bodiless-POST assert (which lives inside the keep-alive discard path).

const std = @import("std");
const filter = @import("filter");

pub const max_head_bytes: usize = 16 * 1024;
pub const max_request_line: usize = 8 * 1024; // mirrors l7proxy/http.zig max_head
pub const max_fwd_headers = 16;

/// Why the pre-parse refused. Coarse, fixed vocabulary for the audit line.
pub const Refusal = enum {
	bad_request_line,
	bad_version,
	connect_refused,
	h2_refused,
	asterisk_form,
	authority_form,
	absolute_form_mismatch,
	bare_lf,
	obs_fold,
	bad_header_name,
	duplicate_content_length,
	bad_content_length,
	cl_and_te,
	bad_transfer_encoding,
	body_on_bodiless_method,
	missing_length_on_body_method,
	duplicate_host,
	/// A second copy of a FORWARDED header. The forwarded set has SET
	/// semantics (last wins) while a policy check may read the first, so a
	/// duplicate is a decision/forward desync -- `Content-Type: json` then
	/// `Content-Type: x-www-form-urlencoded` would pass the 415 gate on the
	/// first and hand the origin the second (Rack::MethodOverride's `_method`).
	duplicate_header,
	missing_host,
	reserved_header,
	host_mismatch,
	bad_vetted,
	oversize_request_line,
	upgrade_refused,
};

pub fn statusFor(r: Refusal) std.http.Status {
	return switch (r) {
		.missing_length_on_body_method => .length_required,
		else => .bad_request,
	};
}

/// What the pre-parse hands the core. Every slice points into head_buffer,
/// which body reads CLOBBER -- the core copies what it needs past the body
/// (the audit host) before streaming.
pub const Checked = struct {
	method: std.http.Method,
	/// Origin-form target (path + optional query); for a Host-matching
	/// absolute-form request, the extracted origin-form part.
	target: []const u8,
	/// The Host header value, port stripped.
	host: []const u8,
	/// X-Cogbox-Host: the route key (== host, cross-checked).
	x_host: []const u8,
	/// X-Cogbox-Vetted: l7proxy's vetted, pinned address -- the ONLY upstream
	/// socket target. Never re-resolved here (correction X3).
	vetted_ip: filter.IpAddr,
	vetted_port: u16,
	/// X-Cogbox-Proto. AUDIT ONLY, never consulted for routing (H#25).
	proto: ?[]const u8,
	content_length: ?u64,
	chunked: bool,
	has_body: bool,
	/// The allowlisted inbound headers, in arrival order.
	fwd: [max_fwd_headers]std.http.Header,
	fwd_len: usize,
};

pub const Result = union(enum) {
	ok: Checked,
	refuse: Refusal,
};

/// Forward ONLY these inbound headers (allowlist, not denylist -- spec §7).
/// Authorization, cookies, hop-by-hop, proxy/forwarding metadata, the three
/// method-override headers and every X-Cogbox-* are simply not in this list.
/// Content-Length/Transfer-Encoding are owned by the re-framing emitter, and
/// Host is emitted from the conf.
const fwd_allowlist = [_][]const u8{
	"accept",
	"accept-encoding",
	"content-type",
	"git-protocol", // protocol-v2 clone breaks without it
	"if-none-match",
	"if-modified-since",
	"range",
	"user-agent",
};

pub fn check(head: []const u8, method: std.http.Method) Result {
	// Reject any bare LF in the head: std's HeadParser will consume a `\n\n`
	// boundary that a CRLF-strict peer would place elsewhere. (std's own
	// Head.parse then errors, so this is belt -- but the belt is cheap.)
	for (head, 0..) |ch, i| {
		if (ch == '\n' and (i == 0 or head[i - 1] != '\r')) return .{ .refuse = .bare_lf };
	}

	var lines = std.mem.splitSequence(u8, head, "\r\n");
	const request_line = lines.next() orelse return .{ .refuse = .bad_request_line };
	if (request_line.len > max_request_line) return .{ .refuse = .oversize_request_line };
	// No control byte anywhere in the request line. The bare-LF scan above
	// cannot see a LONE CR (splitSequence on "\r\n" leaves it inside the line,
	// still three tokens), and a CR that survives into a query value would be
	// re-emitted into the constructed upstream request line, where an origin
	// that takes CR as a line terminator reads header injection.
	for (request_line) |ch| {
		if (ch < 0x20 or ch == 0x7f) return .{ .refuse = .bad_request_line };
	}

	// --- request line: METHOD SP TARGET SP HTTP/1.x, no extra tokens ---
	// (std takes the LAST space as the version separator, so `GET /a b HTTP/1.1`
	// yields target "/a b" there; here it is an extra token and refused.)
	var rl = std.mem.splitScalar(u8, request_line, ' ');
	const method_tok = rl.next() orelse return .{ .refuse = .bad_request_line };
	const raw_target = rl.next() orelse return .{ .refuse = .bad_request_line };
	const version = rl.next() orelse return .{ .refuse = .bad_request_line };
	if (rl.next() != null) return .{ .refuse = .bad_request_line };
	if (method_tok.len == 0 or method_tok.len > 16) return .{ .refuse = .bad_request_line };
	for (method_tok) |ch| {
		if (ch < 'A' or ch > 'Z') return .{ .refuse = .bad_request_line };
	}
	if (std.mem.eql(u8, method_tok, "PRI")) return .{ .refuse = .h2_refused };
	if (method == .CONNECT) return .{ .refuse = .connect_refused };
	if (!std.mem.eql(u8, version, "HTTP/1.1") and !std.mem.eql(u8, version, "HTTP/1.0")) {
		return .{ .refuse = .bad_version };
	}

	// --- headers ---
	var out: Checked = .{
		.method = method,
		.target = undefined,
		.host = undefined,
		.x_host = undefined,
		.vetted_ip = undefined,
		.vetted_port = 0,
		.proto = null,
		.content_length = null,
		.chunked = false,
		.has_body = false,
		.fwd = undefined,
		.fwd_len = 0,
	};
	var host_val: ?[]const u8 = null;
	var x_host: ?[]const u8 = null;
	var vetted: ?[]const u8 = null;
	var proto_count: usize = 0;
	var saw_cl = false;
	var seen_fwd: [fwd_allowlist.len]bool = @splat(false);
	while (lines.next()) |line| {
		if (line.len == 0) continue; // the terminator's empty splits
		if (line[0] == ' ' or line[0] == '\t') return .{ .refuse = .obs_fold };
		const colon = std.mem.indexOfScalar(u8, line, ':') orelse return .{ .refuse = .bad_header_name };
		const name = line[0..colon];
		const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
		if (name.len == 0) return .{ .refuse = .bad_header_name };
		// A non-token byte -- whitespace before the colon included -- is a
		// header std silently IGNORES ("Content-Length " misses its
		// eqlIgnoreCase) while a trimming upstream might honour it: the
		// classic desync. Refuse instead.
		for (name) |ch| {
			if (!isTchar(ch)) return .{ .refuse = .bad_header_name };
		}
		// A control byte in a VALUE (a lone CR especially, which some origins
		// take as a line terminator) is a header-injection vector on the
		// re-emitted upstream head. Refuse.
		for (value) |ch| {
			if ((ch < 0x20 and ch != '\t') or ch == 0x7f) return .{ .refuse = .bad_header_name };
		}

		if (std.ascii.eqlIgnoreCase(name, "host")) {
			if (host_val != null) return .{ .refuse = .duplicate_host };
			host_val = value;
		} else if (std.ascii.eqlIgnoreCase(name, "content-length")) {
			if (saw_cl) return .{ .refuse = .duplicate_content_length };
			saw_cl = true;
			if (value.len == 0) return .{ .refuse = .bad_content_length };
			for (value) |ch| {
				if (ch < '0' or ch > '9') return .{ .refuse = .bad_content_length };
			}
			out.content_length = std.fmt.parseInt(u64, value, 10) catch return .{ .refuse = .bad_content_length };
		} else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
			// ONLY exactly `chunked`. std accepts compression combos
			// ("deflate, chunked"); a second TE line trips its duplicate check,
			// and everything else is refused here.
			if (out.chunked or !std.ascii.eqlIgnoreCase(value, "chunked")) {
				return .{ .refuse = .bad_transfer_encoding };
			}
			out.chunked = true;
		} else if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
			// No protocol switches through the auth proxy: h2c is §7's named
			// refusal and nothing routed here upgrades legitimately.
			return .{ .refuse = .upgrade_refused };
		} else if (std.ascii.eqlIgnoreCase(name, "x-cogbox-host")) {
			if (x_host != null) return .{ .refuse = .reserved_header };
			x_host = value;
		} else if (std.ascii.eqlIgnoreCase(name, "x-cogbox-vetted")) {
			if (vetted != null) return .{ .refuse = .reserved_header };
			vetted = value;
		} else if (std.ascii.eqlIgnoreCase(name, "x-cogbox-proto")) {
			proto_count += 1;
			if (proto_count > 1) return .{ .refuse = .reserved_header };
			out.proto = value;
		} else if (std.ascii.startsWithIgnoreCase(name, "x-cogbox-")) {
			// The addon strips the whole reserved namespace unconditionally on
			// every flow, so an unknown X-Cogbox-* here is a forgery.
			return .{ .refuse = .reserved_header };
		} else {
			for (&fwd_allowlist, 0..) |allowed, ai| {
				if (std.ascii.eqlIgnoreCase(name, allowed)) {
					// Every forwarded header is a SINGLETON here: the forwarded
					// set keeps one value per name, so a repeat can only be a
					// decision/forward desync (Refusal.duplicate_header). Refused
					// before the accept-encoding sanitizer so a dropped first copy
					// cannot launder a second.
					if (seen_fwd[ai]) return .{ .refuse = .duplicate_header };
					seen_fwd[ai] = true;
					if (std.ascii.eqlIgnoreCase(name, "accept-encoding") and !tokenListSafe(value)) break;
					if (out.fwd_len < out.fwd.len) {
						out.fwd[out.fwd_len] = .{ .name = allowed, .value = value };
						out.fwd_len += 1;
					}
					break;
				}
			}
		}
	}

	// --- body framing sanity (the CL.TE class) ---
	if (out.content_length != null and out.chunked) return .{ .refuse = .cl_and_te };
	const declares_body = out.chunked or (out.content_length orelse 0) > 0;
	if (!method.requestHasBody() and declares_body) return .{ .refuse = .body_on_bodiless_method };
	// A body-bearing method MUST declare its framing: std would otherwise
	// treat the body as read-until-close (a keep-alive desync) or trip the
	// Server.zig discardBody assert. 411 Length Required.
	if (method.requestHasBody() and out.content_length == null and !out.chunked) {
		return .{ .refuse = .missing_length_on_body_method };
	}
	out.has_body = method.requestHasBody() and declares_body;

	// --- Host and the reserved-header cross-check (spec §1.3) ---
	const host_hdr = host_val orelse return .{ .refuse = .missing_host };
	const host = stripPort(host_hdr) orelse return .{ .refuse = .missing_host };
	if (host.len == 0) return .{ .refuse = .missing_host };
	out.host = host;
	out.x_host = x_host orelse return .{ .refuse = .reserved_header };
	if (out.x_host.len == 0) return .{ .refuse = .reserved_header };
	if (!std.ascii.eqlIgnoreCase(out.host, out.x_host)) return .{ .refuse = .host_mismatch };
	const v = vetted orelse return .{ .refuse = .reserved_header };
	if (parseVetted(v)) |vp| {
		out.vetted_ip = vp.ip;
		out.vetted_port = vp.port;
	} else return .{ .refuse = .bad_vetted };

	// --- target form ---
	if (std.mem.eql(u8, raw_target, "*")) return .{ .refuse = .asterisk_form };
	if (raw_target.len > 0 and raw_target[0] == '/') {
		out.target = raw_target;
	} else if (std.mem.startsWith(u8, raw_target, "http://") or std.mem.startsWith(u8, raw_target, "https://")) {
		// absolute-form: the authority must agree with Host (anti-fronting).
		const after = raw_target[(std.mem.indexOf(u8, raw_target, "://").?) + 3 ..];
		const slash = std.mem.indexOfScalar(u8, after, '/');
		const authority = if (slash) |s| after[0..s] else after;
		const abs_host = stripPort(authority) orelse return .{ .refuse = .absolute_form_mismatch };
		if (!std.ascii.eqlIgnoreCase(abs_host, out.host)) return .{ .refuse = .absolute_form_mismatch };
		out.target = if (slash) |s| after[s..] else "/";
	} else {
		return .{ .refuse = .authority_form };
	}

	return .{ .ok = out };
}

/// X-Cogbox-Vetted: a BARE IP literal plus a non-zero port. IPv4 `a.b.c.d:p`;
/// IPv6 bracketed `[..]:p` (an unbracketed v6+port is ambiguous and refused).
/// Never a hostname -- resolution stays l7proxy's job alone.
pub const VettedAddr = struct { ip: filter.IpAddr, port: u16 };

pub fn parseVetted(s: []const u8) ?VettedAddr {
	if (s.len == 0) return null;
	var ip: filter.IpAddr = undefined;
	var port_str: []const u8 = undefined;
	if (s[0] == '[') {
		const close = std.mem.indexOfScalar(u8, s, ']') orelse return null;
		const v6 = filter.parseIpv6(s[1..close]) orelse return null;
		ip = .{ .ipv6 = v6 };
		if (close + 1 >= s.len or s[close + 1] != ':') return null;
		port_str = s[close + 2 ..];
	} else {
		const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
		const v4 = filter.parseIpv4(s[0..colon]) orelse return null;
		ip = .{ .ipv4 = v4 };
		port_str = s[colon + 1 ..];
	}
	if (port_str.len == 0 or port_str.len > 5) return null;
	for (port_str) |ch| {
		if (ch < '0' or ch > '9') return null;
	}
	const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
	if (port == 0) return null;
	return .{ .ip = ip, .port = port };
}

/// RFC 9110 tchar: the only bytes a header NAME may carry. Shared with the
/// upstream emitter's guard so the two ends of the proxy agree on it.
pub fn isTchar(ch: u8) bool {
	return switch (ch) {
		'a'...'z', 'A'...'Z', '0'...'9' => true,
		'!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
		else => false,
	};
}

/// Accept-Encoding is forwarded only when it is a plain token list -- anything
/// outside this charset is silently dropped (the upstream then sends identity,
/// which is always safe).
fn tokenListSafe(value: []const u8) bool {
	for (value) |ch| {
		switch (ch) {
			'a'...'z', 'A'...'Z', '0'...'9', ',', ';', '=', '.', '-', '*', ' ', '\t' => {},
			else => return false,
		}
	}
	return true;
}

/// Strip a trailing `:port` from a Host value. Bracketed IPv6 literal hosts
/// are not names the conf routes; refuse them.
fn stripPort(h: []const u8) ?[]const u8 {
	if (h.len == 0) return null;
	if (h[0] == '[') return null;
	if (std.mem.lastIndexOfScalar(u8, h, ':')) |idx| return h[0..idx];
	return h;
}

// --- fd-backed Io.Reader / Io.Writer adapters ---
//
// std.http.Server and std.crypto.tls.Client are transport-agnostic over
// *std.Io.Reader / *std.Io.Writer, which is what makes the whole server path
// unit-testable with in-memory streams. These adapters supply the real-socket
// case. Raw libc symbols (the repo's proven socket style; std.posix carries no
// socket calls in 0.16) with MSG_NOSIGNAL so a peer reset cannot SIGPIPE the
// process; timeouts ride SO_RCVTIMEO/SO_SNDTIMEO set by the owner of the fd.

extern "c" fn recv(fd: c_int, buf: [*]u8, len: usize, flags: c_int) isize;
extern "c" fn send(fd: c_int, buf: [*]const u8, len: usize, flags: c_int) isize;

// Use the target libc flag: Darwin and Linux assign different values.
const MSG_NOSIGNAL: c_int = std.c.MSG.NOSIGNAL;

pub const FdReader = struct {
	fd: c_int,
	interface: std.Io.Reader,

	pub fn init(fd: c_int, buffer: []u8) FdReader {
		return .{
			.fd = fd,
			.interface = .{
				.vtable = &.{ .stream = stream },
				.buffer = buffer,
				.seek = 0,
				.end = 0,
			},
		};
	}

	fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
		const self: *FdReader = @alignCast(@fieldParentPtr("interface", r));
		const dest = limit.slice(w.writableSliceGreedy(1) catch return error.WriteFailed);
		const n = recv(self.fd, dest.ptr, dest.len, 0);
		if (n < 0) return error.ReadFailed; // timeout (SO_RCVTIMEO) or socket error
		if (n == 0) return error.EndOfStream;
		w.advance(@intCast(n));
		return @intCast(n);
	}
};

pub const FdWriter = struct {
	fd: c_int,
	interface: std.Io.Writer,

	pub fn init(fd: c_int, buffer: []u8) FdWriter {
		return .{
			.fd = fd,
			.interface = .{
				.vtable = &.{ .drain = drain },
				.buffer = buffer,
				.end = 0,
			},
		};
	}

	fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
		const self: *FdWriter = @alignCast(@fieldParentPtr("interface", w));
		if (!sendAll(self.fd, w.buffered())) return error.WriteFailed;
		w.end = 0;
		if (data.len == 0) return 0;
		var total: usize = 0;
		for (data[0 .. data.len - 1]) |d| {
			if (!sendAll(self.fd, d)) return error.WriteFailed;
			total += d.len;
		}
		const pattern = data[data.len - 1];
		var i: usize = 0;
		while (i < splat) : (i += 1) {
			if (!sendAll(self.fd, pattern)) return error.WriteFailed;
			total += pattern.len;
		}
		return total;
	}
};

pub fn sendAll(fd: c_int, buf: []const u8) bool {
	var off: usize = 0;
	while (off < buf.len) {
		const n = send(fd, buf.ptr + off, buf.len - off, MSG_NOSIGNAL);
		if (n <= 0) return false;
		off += @intCast(n);
	}
	return true;
}

// --- Tests ---

const t = std.testing;

fn checkBytes(bytes: []const u8) Result {
	const head = std.http.Server.Request.Head.parse(bytes) catch return .{ .refuse = .bad_request_line };
	return check(bytes, head.method);
}

const good_head = "GET /api/v4/user HTTP/1.1\r\n" ++
	"Host: git.example.com\r\n" ++
	"X-Cogbox-Host: git.example.com\r\n" ++
	"X-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
	"X-Cogbox-Proto: https\r\n" ++
	"Accept: */*\r\n" ++
	"\r\n";

test "check: the good head passes with everything extracted" {
	const r = checkBytes(good_head);
	try t.expect(r == .ok);
	const c = r.ok;
	try t.expectEqual(std.http.Method.GET, c.method);
	try t.expectEqualStrings("/api/v4/user", c.target);
	try t.expectEqualStrings("git.example.com", c.host);
	try t.expectEqualStrings("git.example.com", c.x_host);
	try t.expectEqual(@as(u16, 443), c.vetted_port);
	try t.expectEqualStrings("https", c.proto.?);
	try t.expect(!c.has_body);
	try t.expectEqual(@as(usize, 1), c.fwd_len);
	try t.expectEqualStrings("accept", c.fwd[0].name);
}

fn refusedAs(bytes: []const u8, want: Refusal) !void {
	const r = checkBytes(bytes);
	try t.expect(r == .refuse);
	try t.expectEqual(want, r.refuse);
}

test "check: CL+TE together is the one real smuggling primitive std leaves open" {
	try refusedAs("POST /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n", .cl_and_te);
}

test "check: transfer-encoding must be exactly chunked" {
	try refusedAs("POST /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nTransfer-Encoding: deflate, chunked\r\n\r\n", .bad_transfer_encoding);
	try refusedAs("POST /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nTransfer-Encoding: gzip\r\n\r\n", .bad_transfer_encoding);
}

test "check: body-framing method rules close the GET-with-body desync" {
	// a bodiless method declaring a body: std leaves those bytes in the stream
	// as the "next request" on a reusable connection
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nContent-Length: 5\r\n\r\n", .body_on_bodiless_method);
	// a body method with no framing: std would read-until-close or assert
	try refusedAs("POST /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n", .missing_length_on_body_method);
	// Content-Length: 0 on GET is fine
	const r = checkBytes("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nContent-Length: 0\r\n\r\n");
	try t.expect(r == .ok);
	try t.expect(!r.ok.has_body);
}

test "check: a duplicate forwarded header is refused (the Content-Type 415-bypass, S4)" {
	// json first (passes the urlencoded 415 gate, which reads the FIRST), then
	// urlencoded (which SET semantics would forward, the LAST): refused.
	try refusedAs("POST /api/v4/projects/1234/issues HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nContent-Length: 14\r\n" ++
		"Content-Type: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n", .duplicate_header);
	// every forwarded name is a singleton, not just Content-Type
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nUser-Agent: a\r\nuser-agent: b\r\n\r\n", .duplicate_header);
	// and a sanitizer-dropped first copy does not launder a second
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nAccept-Encoding: gzip\"x\"\r\nAccept-Encoding: gzip\r\n\r\n", .duplicate_header);
	// a single copy of each still forwards
	const r = checkBytes("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nContent-Type: application/json\r\nUser-Agent: a\r\n\r\n");
	try t.expect(r == .ok);
	try t.expectEqual(@as(usize, 2), r.ok.fwd_len);
}

test "check: a control byte in the request line is refused (a lone CR survives the bare-LF scan, S7)" {
	try refusedAs("GET /api/v4/projects/1234/issues?a=b\rc HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n", .bad_request_line);
	try refusedAs("GET /x\x01 HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n", .bad_request_line);
	// a percent-ENCODED CR in the raw line is bytes, not a control byte: the
	// framing layer passes it and canonicalization decides
	const r = checkBytes("GET /x?a=b%0Dc HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n");
	try t.expect(r == .ok);
}

test "check: header-name strictness closes the trailing-whitespace desync" {
	// std silently IGNORES "Content-Length " (the eqlIgnoreCase misses); a
	// trimming upstream would honour it. Refused here.
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nContent-Length : 5\r\n\r\n", .bad_header_name);
}

test "check: the reserved-header cross-check" {
	// missing X-Cogbox-Host
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n", .reserved_header);
	// missing X-Cogbox-Vetted
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n\r\n", .reserved_header);
	// duplicated X-Cogbox-Host (a forged second copy)
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\nX-Cogbox-Host: b.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n", .reserved_header);
	// Host != X-Cogbox-Host (the forged-Host case: the addon computed x-host
	// from the SNI-checked pretty_host, so a disagreement is an attack)
	try refusedAs("GET /x HTTP/1.1\r\nHost: b.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n", .host_mismatch);
	// an unknown X-Cogbox-* name is a forgery (the addon strips the namespace)
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nX-Cogbox-Extra: 1\r\n\r\n", .reserved_header);
	// two X-Cogbox-Proto
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nX-Cogbox-Proto: https\r\nX-Cogbox-Proto: http\r\n\r\n", .reserved_header);
	// duplicate Host
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n", .duplicate_host);
	// no Host at all (HTTP/1.0 style) is refused on a migrated host
	try refusedAs("GET /x HTTP/1.0\r\nX-Cogbox-Host: a.test\r\nX-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n", .missing_host);
}

test "check: vetted must be a bare IP literal + non-zero port" {
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: a.test:443\r\n\r\n", .bad_vetted); // a hostname is never dialed
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:0\r\n\r\n", .bad_vetted); // port 0
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5\r\n\r\n", .bad_vetted); // no port
	// bracketed v6 accepted
	const r = checkBytes("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: [fd00::5]:443\r\n\r\n");
	try t.expect(r == .ok);
	try t.expect(r.ok.vetted_ip == .ipv6);
	// unbracketed v6+port is ambiguous -> refused
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: fd00::5:443\r\n\r\n", .bad_vetted);
}

test "check: target forms" {
	// space-bearing target: std's LAST-space split calls it "/a b"; the
	// three-token rule here refuses it
	try refusedAs("GET /a b HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n", .bad_request_line);
	try refusedAs("OPTIONS * HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n", .asterisk_form);
	// authority-form (no scheme, no slash)
	try refusedAs("GET a.test:443 HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n", .authority_form);
	// absolute-form with a matching authority: accepted, origin-form extracted
	const ok = checkBytes("GET http://a.test/p?q=1 HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n");
	try t.expect(ok == .ok);
	try t.expectEqualStrings("/p?q=1", ok.ok.target);
	// absolute-form with a DISAGREEING authority: the fronting shape
	try refusedAs("GET http://b.test/p HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n\r\n", .absolute_form_mismatch);
}

test "check: upgrade refused; accept-encoding sanitized; allowlist filters" {
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nUpgrade: h2c\r\n\r\n", .upgrade_refused);
	const r = checkBytes("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\n" ++
		"Authorization: Bearer sneaky\r\nCookie: s=1\r\nX-Forwarded-For: 1.2.3.4\r\n" ++
		"X-HTTP-Method-Override: DELETE\r\n" ++
		"Accept-Encoding: gzip, br\r\nGit-Protocol: version=2\r\nUser-Agent: git/2.43\r\n\r\n");
	try t.expect(r == .ok);
	const c = r.ok;
	// only the allowlisted three made it through
	try t.expectEqual(@as(usize, 3), c.fwd_len);
	for (c.fwd[0..c.fwd_len]) |h| {
		try t.expect(!std.ascii.eqlIgnoreCase(h.name, "authorization"));
		try t.expect(!std.ascii.eqlIgnoreCase(h.name, "cookie"));
	}
	// a non-token-list accept-encoding is DROPPED (upstream then sends
	// identity), while a control byte anywhere in a value refuses outright
	const r2 = checkBytes("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nAccept-Encoding: gzip\"midnight\"\r\n\r\n");
	try t.expect(r2 == .ok);
	try t.expectEqual(@as(usize, 0), r2.ok.fwd_len);
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nUser-Agent: git\x01x\r\n\r\n", .bad_header_name);
	// a header line with no colon at all
	try refusedAs("GET /x HTTP/1.1\r\nHost: a.test\r\nX-Cogbox-Host: a.test\r\n" ++
		"X-Cogbox-Vetted: 10.0.0.5:443\r\nno-colon-here\r\n\r\n", .bad_header_name);
}

test "parseVetted forms" {
	try t.expect(parseVetted("10.0.0.5:443") != null);
	try t.expect(parseVetted("[::1]:8443") != null);
	try t.expect(parseVetted("10.0.0.5:") == null);
	try t.expect(parseVetted(":443") == null);
	try t.expect(parseVetted("10.0.0.5:65536") == null);
	try t.expect(parseVetted("git.example.com:443") == null);
	try t.expect(parseVetted("") == null);
}
