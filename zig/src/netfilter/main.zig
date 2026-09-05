const std = @import("std");
const filter = @import("filter");
const socks5 = @import("socks5");

const c = @cImport({
	@cDefine("_GNU_SOURCE", "1");
	@cInclude("dlfcn.h");
	@cInclude("sys/socket.h");
	@cInclude("netinet/in.h");
	@cInclude("errno.h");
	@cInclude("stdlib.h");
	@cInclude("string.h");
});

// netdb / arpa constants and prototypes -- declared directly. @cInclude of
// netdb.h and arpa/inet.h drags in glibc's FORTIFY_SOURCE wrappers which
// translate badly through @cImport in ReleaseSafe builds.
const EAI_NONAME: c_int = -2;
const HOST_NOT_FOUND: c_int = 1;
const AF_INET_LOCAL: c_int = 2;
const AF_INET6_LOCAL: c_int = 10;

extern "c" fn __h_errno_location() *c_int;
extern "c" fn inet_pton(af: c_int, src: [*:0]const u8, dst: *anyopaque) c_int;

// POSIX I/O -- declared directly to avoid glibc macro issues with fcntl.h.
// `open`, `read`, `lseek` are only used during init for the rules file; we
// don't intercept them. `close` is intercepted (see real_close below).
const O_RDONLY: c_int = 0;
const SEEK_SET: c_int = 0;
extern "c" fn @"open"(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn lseek(fd: c_int, offset: c_long, whence: c_int) c_long;

// getsockname is not intercepted; the shim calls it itself (see
// isForwardReplySocket) and passt's seccomp profile already carries it
// (udp_flow.c `#syscalls getsockname`, unprofiled so in every profile).
extern "c" fn getsockname(fd: c_int, addr: *c.struct_sockaddr, len: *c.socklen_t) c_int;

// SOCK_* flag bits from <sys/socket.h>. The type argument to socket(2) can
// include SOCK_NONBLOCK / SOCK_CLOEXEC ORed in; the actual type lives in
// the low 8 bits.
const SOCK_TYPE_MASK: c_int = 0xff;

// fcntl bits used to toggle O_NONBLOCK around the remap+SOCKS5 path.
// passt creates non-blocking sockets; the SOCKS5 handshake needs the
// connect()+read+write to block until each step completes.
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const O_NONBLOCK: c_int = 0o4000;
extern "c" fn fcntl(fd: c_int, cmd: c_int, ...) c_int;

// RTLD_NEXT = ((void *)-1)
const RTLD_NEXT: *anyopaque = @ptrFromInt(~@as(usize, 0));

// --- State ---

var ruleset: filter.RuleSet = .{};
var initialized: bool = false;
var reload_pending = std.atomic.Value(bool).init(false);

// Rules file descriptor -- opened during lazy init (after passt's
// close_open_files but before seccomp), kept open for lseek+read reloads.
var rules_fd: c_int = -1;

// COGBOX_MOSH_UDP_FORWARD=lo-hi, read once in init(). Null (unset or
// malformed) means the reply-socket exemption below is OFF and every
// connect/send decision is exactly what it was before the knob existed.
var reply_range: ?filter.PortRange = null;

// --- Real libc function pointers ---

const ConnectFn = *const fn (c_int, ?*const c.struct_sockaddr, c.socklen_t) callconv(.c) c_int;
const SendtoFn = *const fn (c_int, ?*const anyopaque, usize, c_int, ?*const c.struct_sockaddr, c.socklen_t) callconv(.c) isize;
const SendmsgFn = *const fn (c_int, ?*const c.struct_msghdr, c_int) callconv(.c) isize;
const SendmmsgFn = *const fn (c_int, ?[*]c.struct_mmsghdr, c_uint, c_int) callconv(.c) c_int;
const SocketFn = *const fn (c_int, c_int, c_int) callconv(.c) c_int;
const CloseFn = *const fn (c_int) callconv(.c) c_int;

// Resolver entry points. The struct types are kept opaque -- we never
// dereference them in the shim, only forward to libc.
const GetaddrinfoFn = *const fn (?[*:0]const u8, ?[*:0]const u8, ?*const anyopaque, ?*?*anyopaque) callconv(.c) c_int;
const GethostbynameFn = *const fn (?[*:0]const u8) callconv(.c) ?*anyopaque;
const Gethostbyname2Fn = *const fn (?[*:0]const u8, c_int) callconv(.c) ?*anyopaque;
const GethostbynameRFn = *const fn (?[*:0]const u8, ?*anyopaque, [*]u8, usize, ?*?*anyopaque, ?*c_int) callconv(.c) c_int;
const Gethostbyname2RFn = *const fn (?[*:0]const u8, c_int, ?*anyopaque, [*]u8, usize, ?*?*anyopaque, ?*c_int) callconv(.c) c_int;

var real_connect: ?ConnectFn = null;
var real_sendto: ?SendtoFn = null;
var real_sendmsg: ?SendmsgFn = null;
var real_sendmmsg: ?SendmmsgFn = null;
var real_socket: ?SocketFn = null;
var real_close: ?CloseFn = null;
var real_getaddrinfo: ?GetaddrinfoFn = null;
var real_gethostbyname: ?GethostbynameFn = null;
var real_gethostbyname2: ?Gethostbyname2Fn = null;
var real_gethostbyname_r: ?GethostbynameRFn = null;
var real_gethostbyname2_r: ?Gethostbyname2RFn = null;

// --- Per-fd table ---
//
// Tracks (proto, optional connected-UDP peer) for every fd we see go
// through socket(). Used by connect() to know whether a remap rule
// applies (remap is tcp-only in v1) and by sendto/sendmsg to honor the
// CIDR check on connected UDP (which passes NULL dest_addr).

const max_tracked_fds: usize = 4096;

const FdEntry = struct {
	proto: filter.Proto = .any,
	peer_addr: ?filter.IpAddr = null,
	peer_port: u16 = 0,
	// passt inbound-flow reply socket: bound to a specific forward
	// address:port inside `reply_range` and connect()ed to the datagram's
	// sender (peer_addr:peer_port). Sends to THAT peer bypass the rule
	// walk; any other destination is still evaluated. Reset by socket()
	// (trackSocket rewrites the entry) and close() (untrackFd).
	reply_exempt: bool = false,
};

var fd_table: [max_tracked_fds]?FdEntry = [_]?FdEntry{null} ** max_tracked_fds;

fn trackSocket(fd: c_int, sock_type: c_int) void {
	if (fd < 0 or @as(usize, @intCast(fd)) >= max_tracked_fds) return;
	const masked = sock_type & SOCK_TYPE_MASK;
	const proto: filter.Proto = if (masked == c.SOCK_STREAM)
		.tcp
	else if (masked == c.SOCK_DGRAM)
		.udp
	else
		return;
	fd_table[@intCast(fd)] = .{ .proto = proto };
}

fn untrackFd(fd: c_int) void {
	if (fd < 0 or @as(usize, @intCast(fd)) >= max_tracked_fds) return;
	fd_table[@intCast(fd)] = null;
}

fn fdProto(fd: c_int) filter.Proto {
	if (fd < 0 or @as(usize, @intCast(fd)) >= max_tracked_fds) return .any;
	if (fd_table[@intCast(fd)]) |e| return e.proto;
	return .any;
}

fn fdPeer(fd: c_int) ?AddrInfo {
	if (fd < 0 or @as(usize, @intCast(fd)) >= max_tracked_fds) return null;
	if (fd_table[@intCast(fd)]) |e| {
		if (e.peer_addr) |a| return .{ .addr = a, .port = e.peer_port };
	}
	return null;
}

fn setFdPeer(fd: c_int, addr: filter.IpAddr, port: u16) void {
	if (fd < 0 or @as(usize, @intCast(fd)) >= max_tracked_fds) return;
	if (fd_table[@intCast(fd)]) |*e| {
		e.peer_addr = addr;
		e.peer_port = port;
	} else {
		// Fd never went through our socket() wrapper. Track it now with
		// an unknown proto so subsequent NULL-dest sendto calls still
		// pick up the peer.
		fd_table[@intCast(fd)] = .{
			.proto = .any,
			.peer_addr = addr,
			.peer_port = port,
		};
	}
}

fn markReplyExempt(fd: c_int) void {
	if (fd < 0 or @as(usize, @intCast(fd)) >= max_tracked_fds) return;
	if (fd_table[@intCast(fd)]) |*e| e.reply_exempt = true;
}

fn clearReplyExempt(fd: c_int) void {
	if (fd < 0 or @as(usize, @intCast(fd)) >= max_tracked_fds) return;
	if (fd_table[@intCast(fd)]) |*e| e.reply_exempt = false;
}

/// Send-path half of the reply-socket exemption: true iff `fd` was marked by
/// connect() and `dest` (the explicit sendto/sendmsg destination, or null for
/// a connected send) is the peer recorded there. Pure logic in
/// filter.replySendAllowed (tested); this only does the table lookup.
fn replyExemptTo(fd: c_int, dest: ?AddrInfo) bool {
	if (fd < 0 or @as(usize, @intCast(fd)) >= max_tracked_fds) return false;
	const e = fd_table[@intCast(fd)] orelse return false;
	if (!e.reply_exempt) return false;
	return filter.replySendAllowed(true, fdPeer(fd), dest);
}

/// Connect-path half: is `fd` one of passt's inbound-flow reply sockets?
/// Judged on the socket's LOCAL address as bound BEFORE connect() -- passt
/// bind()s every flow socket first (sock_l4), and a guest-originated flow
/// is bound to the unspecified address with the guest sport, which
/// isForwardReplyLocal rejects. Must run before real connect: an implicit
/// bind after connect would report the route's source address instead.
fn isForwardReplySocket(fd: c_int, range: filter.PortRange) bool {
	var sa: c.struct_sockaddr_storage = std.mem.zeroes(c.struct_sockaddr_storage);
	var len: c.socklen_t = @sizeOf(c.struct_sockaddr_storage);
	if (getsockname(fd, @ptrCast(&sa), &len) != 0) return false;
	const local = extractAddr(@ptrCast(&sa)) orelse return false;
	return filter.isForwardReplyLocal(local.addr, local.port, range);
}

fn resolve(comptime name: [*:0]const u8) *anyopaque {
	return c.dlsym(RTLD_NEXT, name) orelse @panic("netfilter: dlsym failed");
}

// --- Initialization ---
// Lazy init on first intercepted call. passt's startup sequence:
//   1. .init_array constructors run (before main)
//   2. main() → isolate_initial() → close_open_files() closes all fds > 2
//   3. main() setup: creates sockets, calls connect() for probing etc.
//   4. main() → isolate_postfork() → seccomp applied
//
// Our wrappers intercept connect() calls during step 3, which triggers
// init(). At this point close_open_files is done (so our fd won't be
// closed) and seccomp isn't applied yet (so open() works). This is the
// only safe window for initialization.

fn init() void {
	if (initialized) return;

	real_connect = @ptrCast(resolve("connect"));
	real_sendto = @ptrCast(resolve("sendto"));
	real_sendmsg = @ptrCast(resolve("sendmsg"));
	real_sendmmsg = @ptrCast(resolve("sendmmsg"));
	real_socket = @ptrCast(resolve("socket"));
	real_close = @ptrCast(resolve("close"));
	real_getaddrinfo = @ptrCast(resolve("getaddrinfo"));
	real_gethostbyname = @ptrCast(resolve("gethostbyname"));
	real_gethostbyname2 = @ptrCast(resolve("gethostbyname2"));
	real_gethostbyname_r = @ptrCast(resolve("gethostbyname_r"));
	real_gethostbyname2_r = @ptrCast(resolve("gethostbyname2_r"));

	// Install SIGUSR1 handler for rule reload.
	// Requires rt_sigreturn in passt's seccomp allowlist.
	var act: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
	act.handler.handler = handleSigusr1;
	std.posix.sigaction(std.posix.SIG.USR1, &act, null);

	// Open rules file and keep fd for seccomp-safe reloads.
	const env: ?[*:0]const u8 = c.getenv("NETFILTER_RULES");
	if (env) |ptr| {
		const fd = @"open"(ptr, O_RDONLY, 0);
		if (fd >= 0) {
			rules_fd = fd;
		}
	}

	// Mosh UDP forward range (see isForwardReplySocket). Read once here,
	// pre-seccomp like everything else in init; a malformed value leaves
	// the exemption off (the launcher already refuses that shape with 64).
	if (c.getenv("COGBOX_MOSH_UDP_FORWARD")) |p| {
		reply_range = filter.parsePortRange(std.mem.span(p));
	}

	loadRules();
	initialized = true;
}

/// Re-read rules from the pre-opened fd. Seccomp-safe: uses only lseek+read.
fn loadRules() void {
	if (rules_fd < 0) return;

	if (lseek(rules_fd, 0, SEEK_SET) < 0) return;

	var buf: [8192]u8 = undefined;
	var total: usize = 0;
	while (total < buf.len) {
		const n = read(rules_fd, @ptrCast(&buf[total]), buf.len - total);
		if (n <= 0) break;
		total += @intCast(n);
	}
	if (total == 0) return;
	ruleset = filter.parseRules(buf[0..total]);
}

fn handleSigusr1(_: std.posix.SIG) callconv(.c) void {
	reload_pending.store(true, .release);
}

fn checkReload() void {
	if (reload_pending.load(.acquire)) {
		reload_pending.store(false, .release);
		loadRules();
	}
}

// --- Address extraction ---

// Same shape as filter.Endpoint; aliased so the reply-socket peer can be
// handed to filter.replySendAllowed without a copy.
const AddrInfo = filter.Endpoint;

fn extractAddr(sa: *const c.struct_sockaddr) ?AddrInfo {
	if (sa.sa_family == c.AF_INET) {
		const a4: *const c.struct_sockaddr_in = @ptrCast(@alignCast(sa));
		return .{
			.addr = .{ .ipv4 = @bitCast(a4.sin_addr.s_addr) },
			.port = std.mem.bigToNative(u16, a4.sin_port),
		};
	} else if (sa.sa_family == c.AF_INET6) {
		const a6: *const c.struct_sockaddr_in6 = @ptrCast(@alignCast(sa));
		return .{
			.addr = .{ .ipv6 = @as(*const [16]u8, @ptrCast(&a6.sin6_addr)).* },
			.port = std.mem.bigToNative(u16, a6.sin6_port),
		};
	}
	return null;
}

fn denyErrno() void {
	std.c._errno().* = c.ENETUNREACH;
}

fn buildIpv4Sockaddr(addr: filter.IpAddr, port: u16) c.struct_sockaddr_in {
	var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
	sa.sin_family = c.AF_INET;
	sa.sin_port = std.mem.nativeToBig(u16, port);
	const ipv4: [4]u8 = switch (addr) {
		.ipv4 => |ip| ip,
		.ipv6 => unreachable, // v1 remap targets are ipv4 only
	};
	sa.sin_addr.s_addr = @bitCast(ipv4);
	return sa;
}

// --- Exported wrappers ---

export fn socket(domain: c_int, sock_type: c_int, protocol_: c_int) callconv(.c) c_int {
	init();
	const fd = real_socket.?(domain, sock_type, protocol_);
	if (fd >= 0) trackSocket(fd, sock_type);
	return fd;
}

export fn close(fd: c_int) callconv(.c) c_int {
	// Order: untrack first so we never read stale state after close
	// returns. close() does NOT trigger full init() because passt's
	// early-startup close_open_files() runs before any socket() and
	// would clobber our rules_fd if init opened the rules file too
	// early. Lazy-resolve real_close via dlsym instead.
	untrackFd(fd);
	if (real_close == null) {
		real_close = @ptrCast(c.dlsym(RTLD_NEXT, "close") orelse @panic("netfilter: dlsym close failed"));
	}
	return real_close.?(fd);
}

export fn connect(fd: c_int, addr: ?*const c.struct_sockaddr, len: c.socklen_t) callconv(.c) c_int {
	init();
	checkReload();

	const a = addr orelse return real_connect.?(fd, addr, len);
	const info = extractAddr(a) orelse return real_connect.?(fd, addr, len);
	const proto = fdProto(fd);

	// Remap is consulted FIRST for non-loopback TCP. A remap hit means
	// "allow but divert": it intentionally bypasses the CIDR allow/deny
	// pass, because the connection never reaches the original destination
	// -- it is rewritten to a loopback proxy and a SOCKS5 handshake carries
	// the original dest. This keeps the L7 funnel ("remap any :443 -> the
	// L7 proxy") fail-CLOSED: the single rendered remap line is the only
	// thing that both authorizes and diverts the port, so dropping it
	// yields ENETUNREACH rather than direct unfiltered egress.
	//
	// The !isLoopback guard is load-bearing: the funnel's broad LHS
	// (0.0.0.0/0:443) would otherwise divert the guest's own 127.0.0.1:443
	// probes. Loopback stays subject to the implicit loopback-deny below.
	if (proto == .tcp and !filter.isLoopback(info.addr)) {
		if (ruleset.evaluateRemap(.tcp, info.addr, info.port)) |target| {
			return doRemappedConnect(fd, info.addr, info.port, target);
		}
	}

	// The ONE exemption from the default deny: passt's per-flow reply
	// socket for a datagram that arrived at a `-u <addr>/lo-hi` listener
	// (udp_flow_from_sock -> flow_initiate_sa: PKTINFO dst = the listener
	// address; udp_flow_sock: bind that, connect the sender). Keyed on the
	// socket's LOCAL address being a specific non-loopback address with a
	// port in COGBOX_MOSH_UDP_FORWARD. A guest-originated UDP flow never
	// passes: passt binds it to the UNSPECIFIED address with the guest's
	// source port (fwd_nat_from_tap + sock_l4; -o/--outbound-addr is never
	// passed), so even a guest sport inside the range fails the address
	// half. The peer is recorded so the send wrappers can exempt exactly
	// that destination and nothing else. A loopback peer is not exempted:
	// the loopback deny stays whole, and passt itself refuses non-unicast
	// senders, so only a host-local process could ever seed one.
	if (proto == .udp) {
		if (reply_range) |range| {
			// Only exempt a fd the table can actually mark: for fd >=
			// max_tracked_fds setFdPeer/markReplyExempt are no-ops, so an
			// exempt return here would admit the connect but then deny every
			// reply datagram one-by-one in sendmmsg. Falling through to the
			// ordinary deny path instead fails once, cleanly, at connect.
			const trackable = fd >= 0 and @as(usize, @intCast(fd)) < max_tracked_fds;
			if (trackable and !filter.isLoopback(info.addr) and isForwardReplySocket(fd, range)) {
				setFdPeer(fd, info.addr, info.port);
				markReplyExempt(fd);
				return real_connect.?(fd, addr, len);
			}
		}
	}

	// A UDP connect that did not re-qualify above drops any earlier
	// exemption on the fd BEFORE the rule walk, whatever its outcome: a
	// denied re-connect leaves the kernel association (and so the peer the
	// exemption was granted for) untouched, but the mark expressed an intent
	// this connect no longer has, so it must not survive the denial either.
	if (proto == .udp) clearReplyExempt(fd);

	// CIDR check against the ORIGINAL destination (no remap matched).
	if (ruleset.evaluate(proto, info.addr, info.port) == .deny) {
		denyErrno();
		return -1;
	}

	// Track connected-UDP peer for subsequent sendto/sendmsg with NULL
	// dest_addr (typical glibc resolver pattern).
	if (proto == .udp) setFdPeer(fd, info.addr, info.port);

	return real_connect.?(fd, addr, len);
}

/// Execute a TCP connect with destination rewritten to `target` and a
/// SOCKS5 CONNECT handshake driven on the fd to carry the original
/// destination to the proxy. The handshake is synchronous, so we must
/// clear O_NONBLOCK for its duration (passt sets it on every socket).
fn doRemappedConnect(
	fd: c_int,
	orig_addr: filter.IpAddr,
	orig_port: u16,
	target: filter.RemapTarget,
) c_int {
	const old_flags = fcntl(fd, F_GETFL);
	if (old_flags < 0) {
		denyErrno();
		return -1;
	}
	const was_nonblock = (old_flags & O_NONBLOCK) != 0;
	if (was_nonblock) {
		if (fcntl(fd, F_SETFL, old_flags & ~O_NONBLOCK) < 0) {
			denyErrno();
			return -1;
		}
	}

	var target_sa = buildIpv4Sockaddr(target.addr, target.port);
	const target_len: c.socklen_t = @intCast(@sizeOf(c.struct_sockaddr_in));
	const sa_ptr: *const c.struct_sockaddr = @ptrCast(&target_sa);

	const rc = real_connect.?(fd, sa_ptr, target_len);
	if (rc != 0) {
		const saved = std.c._errno().*;
		if (was_nonblock) _ = fcntl(fd, F_SETFL, old_flags);
		std.c._errno().* = saved;
		return rc;
	}

	const hs = socks5.handshake(fd, orig_addr, orig_port);
	if (was_nonblock) _ = fcntl(fd, F_SETFL, old_flags);
	if (hs) |_| {
		return 0;
	} else |_| {
		std.c._errno().* = c.EHOSTUNREACH;
		return -1;
	}
}

export fn sendto(fd: c_int, buf: ?*const anyopaque, len: usize, flags: c_int, dest_addr: ?*const c.struct_sockaddr, addrlen: c.socklen_t) callconv(.c) isize {
	init();
	checkReload();

	const proto = fdProto(fd);

	// Reply-socket exemption (see connect): the destination is worked out
	// FIRST, and only a send to the recorded peer skips the rule walk.
	if (dest_addr) |a| {
		if (extractAddr(a)) |info| {
			if (replyExemptTo(fd, info)) return real_sendto.?(fd, buf, len, flags, dest_addr, addrlen);
			if (ruleset.evaluate(proto, info.addr, info.port) == .deny) {
				denyErrno();
				return -1;
			}
		}
	} else if (replyExemptTo(fd, null)) {
		return real_sendto.?(fd, buf, len, flags, dest_addr, addrlen);
	} else if (fdPeer(fd)) |peer| {
		// Connected UDP / TCP send with implicit peer.
		if (ruleset.evaluate(proto, peer.addr, peer.port) == .deny) {
			denyErrno();
			return -1;
		}
	}
	return real_sendto.?(fd, buf, len, flags, dest_addr, addrlen);
}

export fn sendmsg(fd: c_int, msg: ?*const c.struct_msghdr, flags: c_int) callconv(.c) isize {
	init();
	checkReload();

	const proto = fdProto(fd);

	if (msg) |m| {
		if (m.msg_name) |name| {
			const sa: *const c.struct_sockaddr = @ptrCast(@alignCast(name));
			if (extractAddr(sa)) |info| {
				if (replyExemptTo(fd, info)) return real_sendmsg.?(fd, msg, flags);
				if (ruleset.evaluate(proto, info.addr, info.port) == .deny) {
					denyErrno();
					return -1;
				}
			}
		} else if (replyExemptTo(fd, null)) {
			return real_sendmsg.?(fd, msg, flags);
		} else if (fdPeer(fd)) |peer| {
			if (ruleset.evaluate(proto, peer.addr, peer.port) == .deny) {
				denyErrno();
				return -1;
			}
		}
	}
	return real_sendmsg.?(fd, msg, flags);
}

export fn sendmmsg(fd: c_int, msgvec: ?[*]c.struct_mmsghdr, vlen: c_uint, flags: c_int) callconv(.c) c_int {
	init();
	checkReload();

	const proto = fdProto(fd);

	// vec[0]-only inspection, as before. passt's reply path
	// (udp_tap_handler) sets the same to_sa on every entry, so for an
	// exempt fd the first entry naming the recorded peer is the whole
	// batch naming it.
	if (msgvec) |vec| {
		if (vlen > 0) {
			if (vec[0].msg_hdr.msg_name) |name| {
				const sa: *const c.struct_sockaddr = @ptrCast(@alignCast(name));
				if (extractAddr(sa)) |info| {
					if (replyExemptTo(fd, info)) return real_sendmmsg.?(fd, msgvec, vlen, flags);
					if (ruleset.evaluate(proto, info.addr, info.port) == .deny) {
						denyErrno();
						return -1;
					}
				}
			} else if (replyExemptTo(fd, null)) {
				return real_sendmmsg.?(fd, msgvec, vlen, flags);
			} else if (fdPeer(fd)) |peer| {
				if (ruleset.evaluate(proto, peer.addr, peer.port) == .deny) {
					denyErrno();
					return -1;
				}
			}
		}
	}
	return real_sendmmsg.?(fd, msgvec, vlen, flags);
}

// --- DNS resolver wrappers ---
//
// Gate libc-level name resolution by consulting `ruleset.evaluateDns()`.
// On deny we never call libc, so no DNS packet is emitted upstream and the
// caller sees the standard "host not found" return.
//
// Numeric IP literals (e.g. `getaddrinfo("1.2.3.4", ...)`) bypass DNS
// rules -- they aren't names, and blocking them here would surprise
// callers that happen to use the resolver API for numeric lookups.

fn isNumericLiteralC(name: [*:0]const u8) bool {
	var buf4: [4]u8 = undefined;
	var buf6: [16]u8 = undefined;
	if (inet_pton(AF_INET_LOCAL, name, &buf4) == 1) return true;
	if (inet_pton(AF_INET6_LOCAL, name, &buf6) == 1) return true;
	return false;
}

fn dnsDenies(name_c: [*:0]const u8) bool {
	if (isNumericLiteralC(name_c)) return false;
	const slice = std.mem.span(name_c);
	return ruleset.evaluateDns(slice) == .deny;
}

fn setHostNotFound() void {
	__h_errno_location().* = HOST_NOT_FOUND;
}

export fn getaddrinfo(
	node: ?[*:0]const u8,
	service: ?[*:0]const u8,
	hints: ?*const anyopaque,
	res: ?*?*anyopaque,
) callconv(.c) c_int {
	init();
	checkReload();

	if (node) |n| {
		if (dnsDenies(n)) return EAI_NONAME;
	}
	return real_getaddrinfo.?(node, service, hints, res);
}

export fn gethostbyname(name: ?[*:0]const u8) callconv(.c) ?*anyopaque {
	init();
	checkReload();

	if (name) |n| {
		if (dnsDenies(n)) {
			setHostNotFound();
			return null;
		}
	}
	return real_gethostbyname.?(name);
}

export fn gethostbyname2(name: ?[*:0]const u8, af: c_int) callconv(.c) ?*anyopaque {
	init();
	checkReload();

	if (name) |n| {
		if (dnsDenies(n)) {
			setHostNotFound();
			return null;
		}
	}
	return real_gethostbyname2.?(name, af);
}

export fn gethostbyname_r(
	name: ?[*:0]const u8,
	ret: ?*anyopaque,
	buf: [*]u8,
	buflen: usize,
	result: ?*?*anyopaque,
	h_errnop: ?*c_int,
) callconv(.c) c_int {
	init();
	checkReload();

	if (name) |n| {
		if (dnsDenies(n)) {
			// glibc convention: return 0, set *result = NULL, set *h_errnop
			// = HOST_NOT_FOUND. Callers that read errno also expect 0.
			if (result) |r| r.* = null;
			if (h_errnop) |hep| hep.* = HOST_NOT_FOUND;
			return 0;
		}
	}
	return real_gethostbyname_r.?(name, ret, buf, buflen, result, h_errnop);
}

export fn gethostbyname2_r(
	name: ?[*:0]const u8,
	af: c_int,
	ret: ?*anyopaque,
	buf: [*]u8,
	buflen: usize,
	result: ?*?*anyopaque,
	h_errnop: ?*c_int,
) callconv(.c) c_int {
	init();
	checkReload();

	if (name) |n| {
		if (dnsDenies(n)) {
			if (result) |r| r.* = null;
			if (h_errnop) |hep| hep.* = HOST_NOT_FOUND;
			return 0;
		}
	}
	return real_gethostbyname2_r.?(name, af, ret, buf, buflen, result, h_errnop);
}
