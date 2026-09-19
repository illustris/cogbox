// cogbox __divertshim
//
// The separate-pod enforcer's in-pod divert shim. It is a native sidecar in the
// AGENT pod (no caps). The nft-init sidecar REDIRECTs (DNAT) the agent's
// locally-originated TCP egress to this shim's loopback listener; the KERNEL
// hands us the pre-redirect original destination via getsockopt(SO_ORIGINAL_DST)
// -- the conntrack original tuple, which the agent cannot forge. We then open a
// SOCKS5 CONNECT to the ENFORCER pod (COGBOX_ENFORCER_ADDR, the enforcer's stable
// ClusterIP) carrying that original dst, and relay the bytes. The enforcer's
// l7proxy (socks5 accept mode + FUNNEL_ALL) re-resolves/peeks/gates from there.
//
// Why a shim instead of an in-pod l7proxy: the enforcement core lives in a
// SEPARATE pod (different netns), reachable only over the pod network. You cannot
// nft-REDIRECT across pods, so this shim does the local REDIRECT recovery and
// carries the dst to the enforcer over the SAME SOCKS5 hop the enforcer already
// parses (zig/src/socks5). It holds NO CAP_NET_ADMIN: a plain listener +
// SO_ORIGINAL_DST, no IP_TRANSPARENT / fwmark.

const std = @import("std");
const filter = @import("filter");
const socks5 = @import("socks5");

const c = @cImport({
	@cDefine("_GNU_SOURCE", "1");
	// Disable glibc FORTIFY (same reasoning as l7proxy/main.zig): the checked
	// inline wrappers fail to compile under translate-c in ReleaseSafe.
	@cDefine("_FORTIFY_SOURCE", "0");
	@cInclude("sys/socket.h");
	@cInclude("netinet/in.h");
	@cInclude("sys/time.h");
	@cInclude("poll.h");
	@cInclude("unistd.h");
	@cInclude("string.h");
});

// bind/connect/accept take glibc's transparent __SOCKADDR_ARG union through
// @cImport, which Zig can't pass a plain pointer to. Bind the raw libc symbols
// with explicit sockaddr-pointer signatures (mirrors l7proxy/main.zig).
const c_bind = @extern(*const fn (c_int, *const c.struct_sockaddr, c.socklen_t) callconv(.c) c_int, .{ .name = "bind" });
const c_connect = @extern(*const fn (c_int, *const c.struct_sockaddr, c.socklen_t) callconv(.c) c_int, .{ .name = "connect" });
const c_accept = @extern(*const fn (c_int, ?*c.struct_sockaddr, ?*c.socklen_t) callconv(.c) c_int, .{ .name = "accept" });
const c_getsockopt = @extern(*const fn (c_int, c_int, c_int, *anyopaque, *c.socklen_t) callconv(.c) c_int, .{ .name = "getsockopt" });

// SOL_IP == IPPROTO_IP == 0; SO_ORIGINAL_DST reads the conntrack ORIGINAL tuple
// the netfilter REDIRECT recorded (the guest cannot forge it). Numeric per the
// stable kernel ABI -- they live in linux/netfilter_ipv4.h, not netinet/in.h.
const SOL_IP: c_int = 0;
const SO_ORIGINAL_DST: c_int = 80;
const MSG_NOSIGNAL: c_int = c.MSG_NOSIGNAL;

const io_timeout_secs: i32 = 15;
/// Budget for the whole SOCKS5 handshake to the enforcer. Stated here
/// rather than inherited from the socks5 client, which has no default.
pub const handshake_budget_ms: u32 = @as(u32, @intCast(io_timeout_secs)) * 1000;
const relay_idle_ms: c_int = 120_000;
const relay_buf: usize = 32 * 1024;
const max_conns: usize = 512;

// --- shared state (set once in run(), read by per-connection workers) ---
var enforcer_addr: filter.IpAddr = .{ .ipv4 = .{ 0, 0, 0, 0 } };
var enforcer_port: u16 = 0;
var conn_count = std.atomic.Value(usize).init(0);

pub const Target = struct { addr: filter.IpAddr, port: u16 };
pub const EnforcerAddr = struct { addr: filter.IpAddr, port: u16 };

/// Parse COGBOX_ENFORCER_ADDR ("A.B.C.D:port"). v4-only: the enforcer is a
/// Kubernetes ClusterIP, always IPv4 here. Returns null on any malformed input.
pub fn parseEnforcerAddr(s: []const u8) ?EnforcerAddr {
	const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
	const ip_str = s[0..colon];
	const port_str = s[colon + 1 ..];
	const ip = filter.parseIpv4(ip_str) orelse return null;
	const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
	if (port == 0) return null;
	return .{ .addr = .{ .ipv4 = ip }, .port = port };
}

/// Parse a kernel-filled SO_ORIGINAL_DST sockaddr into a Target. v4/TCP-only:
/// a non-AF_INET family returns null (the caller refuses). A loopback result is
/// also refused: SO_ORIGINAL_DST yields loopback only when there was NO DNAT --
/// i.e. a direct hit on our own listener (an anti-loop refusal), never a real
/// REDIRECT'd flow (whose original tuple is the external dst the agent aimed at).
/// Type-erased pointer so a test can feed a libc-laid-out sockaddr from its own
/// cImport; the alignment bound matches struct sockaddr_in.
pub fn origDstFromStorage(ss: *align(@alignOf(c.struct_sockaddr_in)) const anyopaque) ?Target {
	const sa: *const c.struct_sockaddr = @ptrCast(ss);
	if (sa.sa_family != c.AF_INET) return null;
	const a4: *const c.struct_sockaddr_in = @ptrCast(ss);
	const addr: filter.IpAddr = .{ .ipv4 = @bitCast(a4.sin_addr.s_addr) };
	if (filter.isLoopback(addr)) return null;
	return .{ .addr = addr, .port = std.mem.bigToNative(u16, a4.sin_port) };
}

pub fn run(listen_port: u16, enforcer: EnforcerAddr) !void {
	enforcer_addr = enforcer.addr;
	enforcer_port = enforcer.port;

	const listen_fd = try listenLoopback(listen_port);
	logLine("divertshim: REDIRECT listener on 127.0.0.1:{d} -> enforcer socks5 (carrying SO_ORIGINAL_DST)", .{listen_port});

	var pfd = [_]c.struct_pollfd{.{ .fd = listen_fd, .events = c.POLLIN, .revents = 0 }};
	while (true) {
		const pr = c.poll(&pfd, 1, 1000);
		if (pr <= 0) continue;
		if ((pfd[0].revents & c.POLLIN) == 0) continue;
		const cfd = c_accept(listen_fd, null, null);
		if (cfd < 0) continue;
		if (conn_count.fetchAdd(1, .monotonic) >= max_conns) {
			_ = conn_count.fetchSub(1, .monotonic);
			_ = c.close(cfd);
			continue;
		}
		const th = std.Thread.spawn(.{}, worker, .{cfd}) catch {
			_ = conn_count.fetchSub(1, .monotonic);
			_ = c.close(cfd);
			continue;
		};
		th.detach();
	}
}

fn worker(client_fd: c_int) void {
	defer _ = c.close(client_fd);
	defer _ = conn_count.fetchSub(1, .monotonic);

	setTimeouts(client_fd);

	// Recover the pre-redirect original destination from the kernel; refuse on
	// getsockopt failure, a non-v4 family, or a loopback/own-listener dst.
	const orig = originalDst(client_fd) orelse return;

	// Reach the enforcer pod and SOCKS5-CONNECT carrying the recovered dst -- the
	// SAME wire format the enforcer's socks5 accept path parses.
	const efd = connectV4(enforcer_addr, enforcer_port) orelse return;
	defer _ = c.close(efd);
	setTimeouts(efd);

	// The shim states its own handshake budget rather than inheriting the
	// passt remap's much tighter one: this hop is a pod-network call to the
	// enforcer's ClusterIP, sized like every other I/O here (io_timeout_secs).
	socks5.handshake(efd, handshake_budget_ms, orig.addr, orig.port) catch return;
	relay(client_fd, efd);
}

fn originalDst(fd: c_int) ?Target {
	var od: c.struct_sockaddr_storage = std.mem.zeroes(c.struct_sockaddr_storage);
	var od_len: c.socklen_t = @sizeOf(c.struct_sockaddr_storage);
	if (c_getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, @ptrCast(&od), &od_len) != 0) return null;
	return origDstFromStorage(&od);
}

// --- listener / connect ---

fn listenLoopback(port: u16) !c_int {
	const fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
	if (fd < 0) return error.Socket;
	var one: c_int = 1;
	_ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_REUSEADDR, &one, @sizeOf(c_int));
	var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
	sa.sin_family = c.AF_INET;
	sa.sin_port = std.mem.nativeToBig(u16, port);
	// 127.0.0.1: an OUTPUT-chain REDIRECT maps locally-originated packets to the
	// loopback address, and the pod shares one netns across containers, so the
	// agent's REDIRECT'd egress lands here. Loopback-only keeps the shim
	// unreachable from the pod network.
	sa.sin_addr.s_addr = std.mem.nativeToBig(u32, 0x7f000001);
	if (c_bind(fd, @ptrCast(&sa), @sizeOf(c.struct_sockaddr_in)) != 0) {
		_ = c.close(fd);
		return error.Bind;
	}
	if (c.listen(fd, 128) != 0) {
		_ = c.close(fd);
		return error.Listen;
	}
	return fd;
}

fn connectV4(addr: filter.IpAddr, port: u16) ?c_int {
	const b = switch (addr) {
		.ipv4 => |v| v,
		.ipv6 => return null, // ClusterIP is v4; the shim never dials v6.
	};
	var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
	sa.sin_family = c.AF_INET;
	sa.sin_port = std.mem.nativeToBig(u16, port);
	sa.sin_addr.s_addr = @bitCast(b);
	const fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
	if (fd < 0) return null;
	if (c_connect(fd, @ptrCast(&sa), @sizeOf(c.struct_sockaddr_in)) != 0) {
		_ = c.close(fd);
		return null;
	}
	return fd;
}

// --- bidirectional splice (mirrors l7proxy's relay) ---

fn relay(a: c_int, b: c_int) void {
	var fds = [_]c.struct_pollfd{
		.{ .fd = a, .events = c.POLLIN, .revents = 0 },
		.{ .fd = b, .events = c.POLLIN, .revents = 0 },
	};
	var a_open = true;
	var b_open = true;
	var rbuf: [relay_buf]u8 = undefined;

	while (a_open or b_open) {
		fds[0].events = if (a_open) c.POLLIN else 0;
		fds[1].events = if (b_open) c.POLLIN else 0;
		const pr = c.poll(&fds, 2, relay_idle_ms);
		if (pr <= 0) return;

		if (a_open and (fds[0].revents & (c.POLLIN | c.POLLHUP | c.POLLERR)) != 0) {
			const n = c.recv(a, &rbuf, rbuf.len, 0);
			if (n <= 0) {
				a_open = false;
				_ = c.shutdown(b, c.SHUT_WR);
			} else if (!writeAll(b, rbuf[0..@intCast(n)])) return;
		}
		if (b_open and (fds[1].revents & (c.POLLIN | c.POLLHUP | c.POLLERR)) != 0) {
			const n = c.recv(b, &rbuf, rbuf.len, 0);
			if (n <= 0) {
				b_open = false;
				_ = c.shutdown(a, c.SHUT_WR);
			} else if (!writeAll(a, rbuf[0..@intCast(n)])) return;
		}
	}
}

// --- small io helpers ---

fn writeAll(fd: c_int, buf: []const u8) bool {
	var off: usize = 0;
	while (off < buf.len) {
		const n = c.send(fd, @ptrCast(buf.ptr + off), buf.len - off, MSG_NOSIGNAL);
		if (n <= 0) return false;
		off += @intCast(n);
	}
	return true;
}

fn setTimeouts(fd: c_int) void {
	var tv: c.struct_timeval = .{ .tv_sec = io_timeout_secs, .tv_usec = 0 };
	_ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_RCVTIMEO, &tv, @sizeOf(c.struct_timeval));
	_ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_SNDTIMEO, &tv, @sizeOf(c.struct_timeval));
}

fn logLine(comptime fmt: []const u8, args: anytype) void {
	std.debug.print(fmt ++ "\n", args);
}
