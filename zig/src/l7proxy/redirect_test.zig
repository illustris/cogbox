// Conformance tests for the l7proxy redirect accept mode + raw-L4 splice arm
// (Part 2 of the container enforcer). These cover the NEW security-critical
// code:
//   - kernel original-dst recovery via SO_ORIGINAL_DST (the conntrack original
//     tuple): correct extraction, the loopback/own-listener anti-loop refusal,
//     and the v4-only guard;
//   - the raw-L4 gate matrix: the non-overridable SSRF hard floor + ordered
//     first-match CIDR policy, default-deny, incl. the IPv4-mapped cloud
//     metadata address;
//   - the classify-vs-raw-L4 boundary: 80/443 still classify (TLS/HTTP, ->
//     terminate, not raw-L4); an unclassifiable flow on :443 is GATED, not
//     auto-allowed; an ECH ClientHello is still refused on the splice tier.
//
// The redirect path takes NO CAP_NET_ADMIN: it binds a normal listener and
// reads only SO_ORIGINAL_DST (no IP_TRANSPARENT, no getsockname, no fwmark).
// The existing filter.zig / tls.zig / http.zig test blocks remain the L4 +
// classification parity proof and run unchanged.

const std = @import("std");
const t = std.testing;
const filter = @import("filter");
const main = @import("main.zig");

// Own cImport so the tests can construct libc-ABI sockaddrs to feed the
// kernel-sockaddr parser. The pointers cross into main as type-erased anyopaque,
// so this distinct cImport instance is fine -- the memory layout is identical.
const c = @cImport({
	@cDefine("_GNU_SOURCE", "1");
	@cInclude("sys/socket.h");
	@cInclude("netinet/in.h");
	@cInclude("sys/time.h"); // struct timeval for the SO_RCVTIMEO fallback test
});

// libc bits the socketpair-driven classify tests need.
extern "c" fn socketpair(domain: c_int, type: c_int, protocol: c_int, sv: *[2]c_int) c_int;
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern "c" fn shutdown(fd: c_int, how: c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const SHUT_WR: c_int = 1;

fn inetV4(a: u8, b: u8, cc: u8, d: u8, port: u16) c.struct_sockaddr_in {
	var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
	sa.sin_family = c.AF_INET;
	sa.sin_port = std.mem.nativeToBig(u16, port);
	sa.sin_addr.s_addr = @bitCast([4]u8{ a, b, cc, d });
	return sa;
}

fn inetV6Loopback(port: u16) c.struct_sockaddr_in6 {
	var sa: c.struct_sockaddr_in6 = std.mem.zeroes(c.struct_sockaddr_in6);
	sa.sin6_family = c.AF_INET6;
	sa.sin6_port = std.mem.nativeToBig(u16, port);
	@as([*]u8, @ptrCast(&sa.sin6_addr))[15] = 1; // ::1
	return sa;
}

// --- original-dst extraction (origFromStorage / origDstFromStorage) ---

test "origFromStorage extracts the v4 dst from a kernel sockaddr" {
	const sa = inetV4(203, 0, 113, 7, 8443);
	const o = main.origFromStorage(&sa).?;
	try t.expectEqual(filter.IpAddr{ .ipv4 = .{ 203, 0, 113, 7 } }, o.addr);
	try t.expectEqual(@as(u16, 8443), o.port);
}

test "origFromStorage refuses a non-v4 (v6) family" {
	const sa6 = inetV6Loopback(443);
	try t.expect(main.origFromStorage(&sa6) == null);
}

test "origDstFromStorage: SO_ORIGINAL_DST yields the right Orig" {
	// The conntrack original tuple as the kernel would fill it: the real
	// pre-redirect destination the guest aimed at.
	const od = inetV4(93, 184, 216, 34, 443);
	const o = main.origDstFromStorage(&od).?;
	try t.expectEqual(filter.IpAddr{ .ipv4 = .{ 93, 184, 216, 34 } }, o.addr);
	try t.expectEqual(@as(u16, 443), o.port);
}

test "origDstFromStorage: loopback / own-listener orig dst refused (anti-loop)" {
	// SO_ORIGINAL_DST returns loopback only when there was no DNAT: a direct hit
	// on our own 127.0.0.1 listener (an accept loop) -> refuse.
	const own = inetV4(127, 0, 0, 1, 18443);
	try t.expect(main.origDstFromStorage(&own) == null);
	// Any other loopback dst is likewise refused.
	const lo = inetV4(127, 0, 0, 53, 53);
	try t.expect(main.origDstFromStorage(&lo) == null);
}

test "origDstFromStorage: a non-v4 dst is refused" {
	const od6 = inetV6Loopback(443);
	try t.expect(main.origDstFromStorage(&od6) == null);
}

// --- raw-L4 gate matrix (rawL4Allowed) ---

test "rawL4Allowed: default-deny gates an unclassifiable flow" {
	const rs = filter.parseRules(""); // empty -> default deny
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 443 }));
}

test "rawL4Allowed: explicit allow admits, ordered first-match on port + cidr" {
	const rs = filter.parseRules(
		\\allow tcp 93.184.216.0/24:443
		\\deny 0.0.0.0/0
	);
	try t.expect(main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 443 }));
	// wrong port -> not matched by the :443 allow -> falls to deny
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 22 }));
	// outside the /24 -> deny
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 198, 51, 100, 1 } }, .port = 443 }));
}

test "rawL4Allowed: an earlier deny wins over a later allow (ordered)" {
	const rs = filter.parseRules(
		\\deny 10.0.0.0/8
		\\allow 0.0.0.0/0
	);
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 10, 1, 2, 3 } }, .port = 443 }));
	try t.expect(main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 8, 8, 8, 8 } }, .port = 443 }));
}

test "rawL4Allowed: SSRF hard floor cannot be overridden by allow-all" {
	// Even `allow 0.0.0.0/0` must not let raw-L4 reach loopback / this-net /
	// link-local(+metadata). The hard floor is checked first and is final.
	const rs = filter.parseRules("allow 0.0.0.0/0");
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 443 }));
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 169, 254, 169, 254 } }, .port = 80 })); // cloud metadata
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 0, 0, 0, 0 } }, .port = 443 }));
}

test "rawL4Allowed: IPv4-mapped metadata (::ffff:169.254.169.254) is dropped" {
	const rs = filter.parseRules("allow 0.0.0.0/0");
	const mapped = filter.IpAddr{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 169, 254, 169, 254 } };
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = mapped, .port = 80 }));
}

test "rawL4Allowed: a hard-deny address is refused even under allow-all" {
	// The per-instance half of the floor: the
	// enclosing host's own address is not in the built-in set, so before
	// `hard-deny` an `allow 0.0.0.0/0` instance could raw-L4 splice straight
	// back into the machine running the proxy.
	const rs = filter.parseRules(
		\\hard-deny 10.0.0.7/32
		\\allow 0.0.0.0/0
	);
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 10, 0, 0, 7 } }, .port = 22 }));
	// The v4-mapped form of the same address is folded, not smuggled through.
	const mapped = filter.IpAddr{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 7 } };
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = mapped, .port = 22 }));
	// A neighbouring address is unaffected -- the floor is the host's OWN
	// addresses, not a subnet-wide block nobody asked for.
	try t.expect(main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 10, 0, 0, 8 } }, .port = 22 }));
}

test "rawL4Allowed: an instance with no hard-deny line is unchanged" {
	// Default-preserving guarantee for the local and k8s backends, which render
	// no `hard-deny`: identical verdicts to the pre-feature floor.
	const rs = filter.parseRules("allow 0.0.0.0/0");
	try t.expect(main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 10, 0, 0, 7 } }, .port = 22 }));
	try t.expect(main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 443 }));
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 443 }));
}

// --- classify vs raw-L4 boundary (peekClassify on a real fd) ---

// Minimal single-record TLS ClientHello builder -- mirrors tls.zig's test
// fixture so the classify path is exercised on real bytes over a real socket.
fn buildHello(buf: []u8, server_name: []const u8, with_ech: bool) []u8 {
	var hs: [1024]u8 = undefined;
	var n: usize = 0;
	hs[n] = 0x03;
	hs[n + 1] = 0x03;
	n += 2; // client_version TLS1.2
	@memset(hs[n .. n + 32], 0);
	n += 32; // random
	hs[n] = 0;
	n += 1; // session_id len 0
	hs[n] = 0x00;
	hs[n + 1] = 0x02;
	hs[n + 2] = 0x13;
	hs[n + 3] = 0x01;
	n += 4; // cipher_suites len2 + one suite
	hs[n] = 0x01;
	hs[n + 1] = 0x00;
	n += 2; // compression: len1 + null
	const ext_len_pos = n;
	n += 2; // placeholder for extensions length
	const ext_start = n;
	if (server_name.len > 0) {
		const sni_inner = 2 + 1 + 2 + server_name.len;
		hs[n] = 0x00;
		hs[n + 1] = 0x00;
		n += 2; // ext type server_name
		hs[n] = @intCast((sni_inner >> 8) & 0xff);
		hs[n + 1] = @intCast(sni_inner & 0xff);
		n += 2; // ext data len
		const list_len = 1 + 2 + server_name.len;
		hs[n] = @intCast((list_len >> 8) & 0xff);
		hs[n + 1] = @intCast(list_len & 0xff);
		n += 2; // server_name_list length
		hs[n] = 0x00;
		n += 1; // name_type host_name
		hs[n] = @intCast((server_name.len >> 8) & 0xff);
		hs[n + 1] = @intCast(server_name.len & 0xff);
		n += 2; // name length
		@memcpy(hs[n .. n + server_name.len], server_name);
		n += server_name.len;
	}
	if (with_ech) {
		hs[n] = 0xfe;
		hs[n + 1] = 0x0d;
		n += 2; // ext type ECH
		hs[n] = 0x00;
		hs[n + 1] = 0x01;
		n += 2; // ext data len 1
		hs[n] = 0x00;
		n += 1;
	}
	const ext_total = n - ext_start;
	hs[ext_len_pos] = @intCast((ext_total >> 8) & 0xff);
	hs[ext_len_pos + 1] = @intCast(ext_total & 0xff);

	var msg: [1100]u8 = undefined;
	msg[0] = 0x01; // handshake type client_hello
	msg[1] = @intCast((n >> 16) & 0xff);
	msg[2] = @intCast((n >> 8) & 0xff);
	msg[3] = @intCast(n & 0xff);
	@memcpy(msg[4 .. 4 + n], hs[0..n]);
	const msg_len = 4 + n;

	buf[0] = 0x16; // TLS record: handshake
	buf[1] = 0x03;
	buf[2] = 0x01;
	buf[3] = @intCast((msg_len >> 8) & 0xff);
	buf[4] = @intCast(msg_len & 0xff);
	@memcpy(buf[5 .. 5 + msg_len], msg[0..msg_len]);
	return buf[0 .. 5 + msg_len];
}

// Feed `bytes` through a socketpair and classify the reading end. SHUT_WR after
// the write so a classifier that needs more bytes hits EOF rather than blocking.
// The out buffers are caller-owned: a .tls/.http result aliases out_sni/out_host,
// so they must outlive this call.
fn classifyBytes(bytes: []const u8, oh: []u8, op: []u8, os: []u8) main.Classified {
	var sv: [2]c_int = undefined;
	std.debug.assert(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv) == 0);
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);
	_ = write(sv[1], bytes.ptr, bytes.len);
	_ = shutdown(sv[1], SHUT_WR);

	var buf: [16 * 1024]u8 = undefined; // peek buffer; not aliased by the result
	var buffered: usize = 0;
	// deadline 0: block on SO_RCVTIMEO / EOF -- byte-identical to the original
	// classify path. The SHUT_WR above turns a "need more" into EOF, so this never
	// hangs on the socketpair.
	return main.peekClassify(sv[0], &buf, &buffered, oh, op, os, 0);
}

test "classify: a TLS ClientHello on :443 classifies as .tls (not raw-L4)" {
	var raw: [1200]u8 = undefined;
	const hello = buildHello(&raw, "app.example.com", false);
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	const cl = classifyBytes(hello, &oh, &op, &os);
	try t.expect(cl == .tls);
	try t.expectEqualStrings("app.example.com", cl.tls.name);
	try t.expect(!cl.tls.ech);
}

test "classify: an allowed TLS host routes to the terminate tier (no regression)" {
	var rs: filter.L7RuleSet = .{};
	filter.parseL7Rules("allow app.example.com", &rs);
	// default mode_terminate == true: a matched allow host is MITM-terminated
	// (handed to mitmproxy), NOT raw-L4 spliced.
	try t.expect(rs.needsTerminate("app.example.com"));
	try t.expect(rs.evaluate("app.example.com", null) == .allow);
}

test "classify: an HTTP/1.1 request on :80 classifies as .http (not raw-L4)" {
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	const cl = classifyBytes("GET /v1/x HTTP/1.1\r\nHost: app.example.com\r\n\r\n", &oh, &op, &os);
	try t.expect(cl == .http);
	try t.expectEqualStrings("app.example.com", cl.http.host);
}

test "classify: an unclassifiable flow on :443 is .deny -> raw-L4 GATED, not auto-allowed" {
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	// Random first byte: not 0x16 (TLS), not an uppercase HTTP method -> .deny.
	const cl = classifyBytes(&[_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44 }, &oh, &op, &os);
	try t.expect(cl == .deny);

	// .deny on :443 does NOT imply allow -- the raw-L4 arm still gates it. Under
	// the instance default-deny it is dropped; only an explicit L4 allow lets it
	// reach its kernel orig dst. Port 443 carries no special privilege.
	const orig = main.Orig{ .addr = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 443 };
	const deny_rs = filter.parseRules("");
	try t.expect(!main.rawL4Allowed(&deny_rs, orig));
	const allow_rs = filter.parseRules("allow tcp 93.184.216.0/24:443");
	try t.expect(main.rawL4Allowed(&allow_rs, orig));
}

// --- FUNNEL_ALL (separate-pod enforcer, socks5 front door) routing ---
//
// The enforcer reuses the EXISTING socks5 accept path; its in-pod shim funnels
// EVERY port over one SOCKS5 hop, so the socks5 front door now sees non-HTTP/TLS
// flows. COGBOX_L7_FUNNEL_ALL routes those .deny flows to the SAME rawL4Splice
// double-gate the redirect arm uses, instead of a hard drop. The decision is
// rawL4Eligible(mode, funnel) AND rawL4Allowed(rules, orig) -- the latter is the
// non-overridable SSRF floor + the instance's default-deny L4 CIDR policy, both
// already proven above. These tests pin the NEW routing predicate + its
// composition, and that plain socks5 (the VM/launch path) still hard-drops.

test "funnel-all: routing predicate -- socks5 drops unless funnel-all; redirect always eligible" {
	// Plain socks5 (VM/launch): a .deny flow is NOT eligible -> hard drop. This is
	// the byte-identical guarantee.
	try t.expect(!main.rawL4Eligible(.socks5, false));
	// socks5 + FUNNEL_ALL (the enforcer): eligible -> raw-L4 gate (NOT auto-allow).
	try t.expect(main.rawL4Eligible(.socks5, true));
	// redirect front door is always eligible, independent of the funnel flag.
	try t.expect(main.rawL4Eligible(.redirect, false));
	try t.expect(main.rawL4Eligible(.redirect, true));
}

test "funnel-all: a default-deny instance drops an eligible unclassifiable flow" {
	// Eligible under funnel-all, but the instance's empty (default-deny) L4 policy
	// gates it -> dropped. Eligibility is necessary, never sufficient.
	const orig = main.Orig{ .addr = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 443 };
	const rs = filter.parseRules(""); // default deny
	try t.expect(main.rawL4Eligible(.socks5, true));
	try t.expect(!main.rawL4Allowed(&rs, orig));
}

test "funnel-all: an explicit L4 allow lets an eligible flow reach its orig dst" {
	const orig = main.Orig{ .addr = .{ .ipv4 = .{ 93, 184, 216, 34 } }, .port = 5432 };
	const rs = filter.parseRules("allow tcp 93.184.216.0/24:5432");
	try t.expect(main.rawL4Eligible(.socks5, true));
	try t.expect(main.rawL4Allowed(&rs, orig)); // both gates pass -> spliced
	// wrong port under the same allow -> default-deny -> dropped.
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = orig.addr, .port = 22 }));
}

test "funnel-all: the SSRF hard floor still bounds an eligible flow (incl mapped metadata)" {
	// Even `allow 0.0.0.0/0` cannot let a funnel-all flow reach the hard floor.
	const rs = filter.parseRules("allow 0.0.0.0/0");
	try t.expect(main.rawL4Eligible(.socks5, true));
	// cloud metadata, both literal and IPv4-mapped IPv6 form.
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 169, 254, 169, 254 } }, .port = 80 }));
	const mapped = filter.IpAddr{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 169, 254, 169, 254 } };
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = mapped, .port = 80 }));
	// loopback is likewise off-limits.
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 443 }));
}

test "funnel-all: plain socks5 (no funnel) drops even an L4-allowed unclassifiable flow" {
	// The routing predicate short-circuits BEFORE rawL4Allowed: a VM-socks5 .deny
	// flow is hard-dropped regardless of how permissive the L4 rules are.
	const orig = main.Orig{ .addr = .{ .ipv4 = .{ 8, 8, 8, 8 } }, .port = 443 };
	const rs = filter.parseRules("allow 0.0.0.0/0");
	try t.expect(main.rawL4Allowed(&rs, orig)); // L4 would allow it...
	try t.expect(!main.rawL4Eligible(.socks5, false)); // ...but it's never routed there.
}

// --- no-SNI TLS (HTTPS to an IP literal) -> L4-gated splice on every front door ---
//
// RFC 6066 forbids IP literals in server_name, so HTTPS to a bare IP is a
// well-formed ClientHello with NO SNI. The worker's .no_sni arm splices it to its
// orig dst iff rawL4Allowed passes -- regardless of accept mode or FUNNEL_ALL --
// because there is no vhost for an L7 rule to apply to. There is no worker-level
// socket harness (worker() needs a SOCKS5 handshake + a live upstream), so the
// arm's wiring is proven by the exhaustive switch over Classified (a missing
// .no_sni arm is a compile error) plus the classification + gate tests below,
// exactly as the funnel-all tests prove theirs.

test "classify: a well-formed ClientHello with no SNI is .no_sni (not .deny)" {
	var raw: [1200]u8 = undefined;
	const hello = buildHello(&raw, "", false);
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	const cl = classifyBytes(hello, &oh, &op, &os);
	try t.expect(cl == .no_sni);
}

test "no-sni: an L4-allowed orig dst splices, a non-allowed one drops, on plain socks5" {
	const orig = main.Orig{ .addr = .{ .ipv4 = .{ 198, 51, 100, 10 } }, .port = 443 };
	const allow_rs = filter.parseRules("allow tcp 198.51.100.0/24:443\ndeny 0.0.0.0/0");
	try t.expect(main.rawL4Allowed(&allow_rs, orig)); // gate passes -> spliced
	// Eligibility is NOT consulted for .no_sni: the plain-socks5 VM front door,
	// where .deny is hard-dropped, still L4-gates a no-SNI hello.
	try t.expect(!main.rawL4Eligible(.socks5, false));
	// default-deny instance -> dropped (logged no-sni-not-l4-allowed).
	const deny_rs = filter.parseRules("");
	try t.expect(!main.rawL4Allowed(&deny_rs, orig));
	// wrong port under the same allow -> dropped.
	try t.expect(!main.rawL4Allowed(&allow_rs, .{ .addr = orig.addr, .port = 8443 }));
}

test "no-sni: the hard floor still bounds it under allow-all" {
	const rs = filter.parseRules("hard-deny 198.51.100.7/32\nallow 0.0.0.0/0");
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 198, 51, 100, 7 } }, .port = 443 }));
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 443 }));
	try t.expect(!main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 169, 254, 169, 254 } }, .port = 443 }));
	try t.expect(main.rawL4Allowed(&rs, .{ .addr = .{ .ipv4 = .{ 198, 51, 100, 8 } }, .port = 443 }));
}

test "classify: malformed TLS is still .deny (never .no_sni)" {
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	// Handshake type 2 (ServerHello) inside a client-side record: not a ClientHello.
	const cl = classifyBytes(&[_]u8{ 0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00 }, &oh, &op, &os);
	try t.expect(cl == .deny);

	// A truncated valid hello: .need_more until the SHUT_WR EOF -> peekClassify deny.
	var raw: [1200]u8 = undefined;
	const hello = buildHello(&raw, "app.example.com", false);
	const cl2 = classifyBytes(hello[0 .. hello.len - 4], &oh, &op, &os);
	try t.expect(cl2 == .deny);

	// An ECH hello with NO outer SNI is well-formed but must stay .deny: its
	// encrypted inner name could be an L7-denied vhost on the orig IP, which
	// the L4-only no-SNI splice could never see.
	const ech_hello = buildHello(&raw, "", true);
	const cl3 = classifyBytes(ech_hello, &oh, &op, &os);
	try t.expect(cl3 == .deny);
}

test "classify: an ECH ClientHello is still refused on the splice tier" {
	var raw: [1200]u8 = undefined;
	const hello = buildHello(&raw, "app.example.com", true); // GREASE/real ECH present
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	const cl = classifyBytes(hello, &oh, &op, &os);
	try t.expect(cl == .tls);
	try t.expect(cl.tls.ech); // ECH flagged for the worker

	// On the splice (passthrough) tier the worker refuses an ECH-bearing hello:
	// the production condition is `is_tls and ech and !needs_term`. A passthrough
	// host's needsTerminate is false, so the refusal holds.
	var rs: filter.L7RuleSet = .{};
	filter.parseL7Rules("mode passthrough\nallow app.example.com", &rs);
	const needs_term = rs.needsTerminate("app.example.com");
	try t.expect(!needs_term);
	const is_tls = true;
	try t.expect(is_tls and cl.tls.ech and !needs_term);
}

test "peek: COGBOX_L7_PEEK_MS override is clamped both directions" {
	// A sane override passes through.
	try t.expectEqual(@as(i32, 300), main.clampPeekMs(300));
	try t.expectEqual(@as(i32, 120), main.clampPeekMs(120));
	// Non-positive would uncap the peek -> default (300).
	try t.expectEqual(@as(i32, 300), main.clampPeekMs(0));
	try t.expectEqual(@as(i32, 300), main.clampPeekMs(-1));
	// A tiny positive typo would skip classification -> floored to 50.
	try t.expectEqual(@as(i32, 50), main.clampPeekMs(5));
	try t.expectEqual(@as(i32, 50), main.clampPeekMs(50));
}

// --- peek deadline / precheck (the server-speaks-first stall fix) ---
//
// The bug: an SSH-style silent-or-uppercase-banner client made peekClassify
// block for the whole io_timeout_secs before the flow fell through to raw-L4.
// Part 1 (http.requestLinePrecheck) denies an SSH banner instantly; Part 2 (the
// injected classify deadline) bounds a truly silent client on the raw-L4-eligible
// fast path. The deadline is a peekClassify parameter precisely so these tests
// inject a small value instead of sleeping out the production 300ms.

test "peek: an SSH banner is classified .deny immediately (precheck, no timeout)" {
	// Uppercase 'S' start routes it to the HTTP arm; the precheck denies on the
	// '-' at offset 3 without waiting for a CRLF. classifyBytes SHUT_WRs, but the
	// precheck fires before EOF would even matter.
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	const cl = classifyBytes("SSH-2.0-OpenSSH_9.9\r\n", &oh, &op, &os);
	try t.expect(cl == .deny);
}

// Drive peekClassify on a socketpair whose write end stays OPEN (no bytes, no
// SHUT_WR) so recv would block forever -- only the injected deadline can return
// it. Returns the result and the elapsed wall time.
fn classifySilent(deadline_ms: i32) struct { cl: main.Classified, elapsed_ms: i64 } {
	var sv: [2]c_int = undefined;
	std.debug.assert(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv) == 0);
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);
	var buf: [16 * 1024]u8 = undefined;
	var buffered: usize = 0;
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	const start = main.monotonicMs();
	const cl = main.peekClassify(sv[0], &buf, &buffered, &oh, &op, &os, deadline_ms);
	return .{ .cl = cl, .elapsed_ms = main.monotonicMs() - start };
}

test "peek: a silent client returns .deny within the injected fast deadline" {
	const r = classifySilent(100);
	try t.expect(r.cl == .deny);
	// It waited roughly the deadline (not an instant deny) but nowhere near the
	// 15s SO_RCVTIMEO the non-fast path would incur.
	try t.expect(r.elapsed_ms >= 80);
	try t.expect(r.elapsed_ms < 2000);
}

test "peek: with no fast deadline a silent client relies on SO_RCVTIMEO (unchanged)" {
	// deadline 0 disables the poll fast-path -> classification blocks on the fd's
	// own SO_RCVTIMEO, exactly as the original code did. We set a short timeout so
	// the suite doesn't stall the production 15s.
	var sv: [2]c_int = undefined;
	std.debug.assert(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv) == 0);
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);
	var tv: c.struct_timeval = .{ .tv_sec = 0, .tv_usec = 200 * 1000 };
	_ = c.setsockopt(sv[0], c.SOL_SOCKET, c.SO_RCVTIMEO, &tv, @sizeOf(c.struct_timeval));
	var buf: [16 * 1024]u8 = undefined;
	var buffered: usize = 0;
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	const start = main.monotonicMs();
	const cl = main.peekClassify(sv[0], &buf, &buffered, &oh, &op, &os, 0);
	const elapsed = main.monotonicMs() - start;
	try t.expect(cl == .deny);
	try t.expect(elapsed >= 150); // it actually waited on SO_RCVTIMEO, not the poll deadline
}

test "peek: a fast deadline still lets a prompt TLS ClientHello classify" {
	// The deadline bounds the silent case without breaking a client that speaks
	// first: a full ClientHello is already buffered, so classification wins the
	// race well inside the deadline.
	var raw: [1200]u8 = undefined;
	const hello = buildHello(&raw, "app.example.com", false);
	var sv: [2]c_int = undefined;
	std.debug.assert(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv) == 0);
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);
	_ = write(sv[1], hello.ptr, hello.len);
	var buf: [16 * 1024]u8 = undefined;
	var buffered: usize = 0;
	var oh: [256]u8 = undefined;
	var op: [2048]u8 = undefined;
	var os: [256]u8 = undefined;
	const cl = main.peekClassify(sv[0], &buf, &buffered, &oh, &op, &os, 300);
	try t.expect(cl == .tls);
	try t.expectEqualStrings("app.example.com", cl.tls.name);
}
