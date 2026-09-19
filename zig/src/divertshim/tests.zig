// Conformance tests for `cogbox __divertshim` (the agent pod's nft-REDIRECT
// divert shim). Cover the security-critical seams:
//   - original-dst recovery from a kernel SO_ORIGINAL_DST sockaddr (the
//     conntrack original tuple), and the refusals: loopback/own-listener
//     (anti-loop) and a non-AF_INET family (v4-only guard);
//   - COGBOX_ENFORCER_ADDR parsing (the stable ClusterIP:port carve-out);
//   - the SOCKS5 carry: the recovered dst flows verbatim into the SOCKS5 CONNECT
//     the enforcer's socks5 accept path parses (zig/src/socks5).
//
// refAllDecls(main) forces full analysis of the shim's server code so its compile
// errors surface in `zig build test`, not only at exe link.

const std = @import("std");
const t = std.testing;
const filter = @import("filter");
const socks5 = @import("socks5");
const main = @import("main.zig");

test {
	std.testing.refAllDecls(main);
}

// Own cImport to construct libc-ABI sockaddrs for the kernel-sockaddr parser.
// The pointers cross into main as type-erased anyopaque; the memory layout is
// identical, so a distinct cImport instance is fine (same pattern as
// l7proxy/redirect_test.zig).
const c = @cImport({
	@cDefine("_GNU_SOURCE", "1");
	@cInclude("sys/socket.h");
	@cInclude("netinet/in.h");
});

extern "c" fn socketpair(domain: c_int, type: c_int, protocol: c_int, sv: *[2]c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;

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

// --- original-dst recovery ---

test "origDstFromStorage: recovers the external v4 dst from a kernel sockaddr" {
	// The conntrack original tuple as the kernel fills it after a REDIRECT: the
	// real pre-redirect destination the agent aimed at.
	const od = inetV4(93, 184, 216, 34, 5432);
	const got = main.origDstFromStorage(&od).?;
	try t.expectEqual(filter.IpAddr{ .ipv4 = .{ 93, 184, 216, 34 } }, got.addr);
	try t.expectEqual(@as(u16, 5432), got.port);
}

test "origDstFromStorage: a loopback / own-listener dst is refused (anti-loop)" {
	// SO_ORIGINAL_DST returns loopback only when there was NO DNAT -- a direct hit
	// on our own listener, never a real REDIRECT'd flow. Refuse it.
	const own = inetV4(127, 0, 0, 1, 18443);
	try t.expect(main.origDstFromStorage(&own) == null);
	const lo = inetV4(127, 0, 0, 9, 443);
	try t.expect(main.origDstFromStorage(&lo) == null);
}

test "origDstFromStorage: a non-v4 (v6) family is refused" {
	const od6 = inetV6Loopback(443);
	try t.expect(main.origDstFromStorage(&od6) == null);
}

// --- enforcer address parsing ---

test "parseEnforcerAddr: a ClusterIP:port pair parses" {
	const e = main.parseEnforcerAddr("10.96.12.34:18443").?;
	try t.expectEqual(filter.IpAddr{ .ipv4 = .{ 10, 96, 12, 34 } }, e.addr);
	try t.expectEqual(@as(u16, 18443), e.port);
}

test "parseEnforcerAddr: malformed inputs are rejected" {
	try t.expect(main.parseEnforcerAddr("10.96.12.34") == null); // no port
	try t.expect(main.parseEnforcerAddr("10.96.12.34:0") == null); // port 0 reserved
	try t.expect(main.parseEnforcerAddr("not-an-ip:18443") == null);
	try t.expect(main.parseEnforcerAddr("10.96.12.34:99999") == null); // > u16
	try t.expect(main.parseEnforcerAddr("") == null);
}

// --- SOCKS5 carry: the recovered dst flows into the CONNECT verbatim ---

test "socks5 carry: the recovered orig dst becomes the SOCKS5 CONNECT target" {
	var sv: [2]c_int = undefined;
	try t.expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv) == 0);
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);

	// Recover the dst exactly as the shim does, then carry it on the SOCKS5 hop.
	const od = inetV4(93, 184, 216, 34, 5432);
	const orig = main.origDstFromStorage(&od).?;

	// Pre-stage the enforcer's SOCKS5 server replies, then drive the client side.
	try writeAll(sv[1], &.{ 0x05, 0x00 }); // method select: no-auth
	try writeAll(sv[1], &.{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }); // CONNECT ok
	try socks5.handshake(sv[0], main.handshake_budget_ms, orig.addr, orig.port);

	// Inspect the greeting + CONNECT the shim wrote: it must carry the recovered
	// IP:port verbatim (this is what the enforcer's socks5 accept path parses).
	var got: [13]u8 = undefined;
	try readExact(sv[1], &got);
	const expected = [_]u8{
		0x05, 0x01, 0x00, // greeting
		0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x15, 0x38, // CONNECT 93.184.216.34:5432
	};
	try t.expectEqualSlices(u8, &expected, &got);
}

fn writeAll(fd: c_int, buf: []const u8) !void {
	var off: usize = 0;
	while (off < buf.len) {
		const n = write(fd, buf.ptr + off, buf.len - off);
		if (n <= 0) return error.Io;
		off += @intCast(n);
	}
}

fn readExact(fd: c_int, buf: []u8) !void {
	var off: usize = 0;
	while (off < buf.len) {
		const n = read(fd, buf.ptr + off, buf.len - off);
		if (n <= 0) return error.Io;
		off += @intCast(n);
	}
}
