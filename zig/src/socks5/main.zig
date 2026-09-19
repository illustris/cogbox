// Minimal synchronous SOCKS5 v5 CONNECT client. The shim drives this
// over the fd it just connected to a SOCKS5-speaking proxy, carrying the
// original destination (IP, port) as the CONNECT target. Only the
// no-auth (METHOD 0) variant is implemented -- the proxy we ship runs
// on loopback and isn't reachable from anywhere else.
//
// Designed to be safe to call from inside the LD_PRELOAD shim: no
// allocator, fixed-size stack buffers, deadline-bounded libc I/O.

const std = @import("std");
const filter = @import("filter");
const darwin = @import("builtin").os.tag == .macos;
const c = @cImport({
	@cDefine("_FORTIFY_SOURCE", "0");
	@cDefine("_GNU_SOURCE", "1");
	@cInclude("sys/socket.h");
	@cInclude("sys/time.h");
	@cInclude("time.h");
	@cInclude("fcntl.h");
	@cInclude("errno.h");
});

pub const Error = error{
	TimedOut,
	/// The dial itself failed and libc's errno already names the reason
	/// (ECONNREFUSED, ENETUNREACH, EAGAIN from ephemeral-port exhaustion...).
	/// Callers surface that errno unchanged rather than inventing one.
	ConnectFailed,
	AuthMethodRejected,
	ConnectRejected,
	ProtocolError,
	Truncated,
	IoError,
};

extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern "c" fn fcntl(fd: c_int, cmd: c_int, ...) c_int;

// poll() declared directly rather than through @cImport of <poll.h>: the
// struct layout and POLLOUT are identical on Linux and Darwin, and keeping
// the declaration local makes it obvious that the only caller is the Darwin
// dial below. poll is NOT in passt's seccomp allowlist (its profiles carry
// epoll_ctl/epoll_wait only), so it must never be reached on Linux.
const pollfd = extern struct { fd: c_int, events: c_short, revents: c_short };
const POLLOUT: c_short = 0x004;
const nfds_t = if (darwin) c_uint else c_ulong;
extern "c" fn poll(fds: [*]pollfd, nfds: nfds_t, timeout: c_int) c_int;

/// The connect function the session dials with. The LD_PRELOAD shim must
/// pass its dlsym'd `real_connect` (calling libc's `connect` from inside the
/// shim would re-enter the shim's own wrapper), so the sockaddr is untyped:
/// the shim's @cImport produces a `struct sockaddr` distinct from this one.
pub const ConnectFn = *const fn (c_int, *const anyopaque, u32) callconv(.c) c_int;

fn monotonicMicros() Error!i64 {
	var ts: c.struct_timespec = undefined;
	if (c.clock_gettime(c.CLOCK_MONOTONIC, &ts) != 0) return error.IoError;
	return @as(i64, @intCast(ts.tv_sec)) * 1_000_000 + @divTrunc(ts.tv_nsec, 1000);
}

/// Temporarily use blocking I/O with an absolute monotonic deadline. Socket
/// timeouts are refreshed from the remaining budget, never from the full
/// timeout: partial replies and EINTR cannot extend the exchange forever.
/// Every syscall this uses on Linux (fcntl, getsockopt, setsockopt, read,
/// write, connect, clock_gettime) is in passt's seccomp allowlist.
pub const Session = struct {
	fd: c_int,
	/// The caller's O_* flags, as found.
	flags: c_int,
	/// Absolute monotonic expiry, in microseconds. Read and written
	/// atomically: the tests move it from a peer thread while the session is
	/// parked in a read, and a plain load beside that store would be a race.
	deadline: i64,
	/// Caller-owned socket timeouts, saved on first arm and restored by
	/// finish(). An option that was never armed is never touched.
	recv_timeout: c.struct_timeval = .{ .tv_sec = 0, .tv_usec = 0 },
	send_timeout: c.struct_timeval = .{ .tv_sec = 0, .tv_usec = 0 },
	rcv_armed: bool = false,
	snd_armed: bool = false,
	/// Set by any path that pushed the fd's flags away from `flags`, so
	/// finish() restores the caller's blocking mode whoever changed it.
	flags_dirty: bool = false,

	const Which = enum { recv, send };

	pub fn init(fd: c_int, budget_ms: u32) Error!Session {
		// Read the clock before touching the fd: a failure here must leave
		// the caller's socket exactly as it was.
		const deadline = try monotonicMicros() + @as(i64, budget_ms) * 1000;
		const flags = fcntl(fd, c.F_GETFL);
		if (flags < 0) return error.IoError;
		// passt creates non-blocking sockets; the dial and the handshake are
		// synchronous, so they need the fd to block until each step completes.
		if (flags & c.O_NONBLOCK != 0) {
			if (fcntl(fd, c.F_SETFL, flags & ~@as(c_int, c.O_NONBLOCK)) != 0) return error.IoError;
			return .{ .fd = fd, .flags = flags, .deadline = deadline, .flags_dirty = true };
		}
		return .{ .fd = fd, .flags = flags, .deadline = deadline };
	}

	/// Restore all caller-owned state on success and failure. Do not leak the
	/// handshake timeout into the application's subsequent traffic. errno is
	/// preserved so a caller reporting the body's failure still sees it.
	/// Restore the caller's blocking mode -- on every path, whichever path
	/// changed it -- and the socket timeouts this session armed. Failing to
	/// put the fd's O_NONBLOCK back is the one restore failure that matters:
	/// passt would drive a blocking fd from its single-threaded epoll loop
	/// and the next read or write could wedge the whole loop, so that is
	/// reported as error.IoError with the fcntl errno. A timeout that could
	/// not be restored is discarded: it costs this fd a wrong SO_RCVTIMEO,
	/// nothing more, and is not worth failing a working connection for.
	pub fn finish(self: *Session) Error!void {
		const saved_errno = std.c._errno().*;
		if (self.rcv_armed) {
			_ = c.setsockopt(self.fd, c.SOL_SOCKET, c.SO_RCVTIMEO, &self.recv_timeout, @sizeOf(c.struct_timeval));
			self.rcv_armed = false;
		}
		if (self.snd_armed) {
			_ = c.setsockopt(self.fd, c.SOL_SOCKET, c.SO_SNDTIMEO, &self.send_timeout, @sizeOf(c.struct_timeval));
			self.snd_armed = false;
		}
		if (self.flags_dirty) {
			std.c._errno().* = 0;
			if (fcntl(self.fd, c.F_SETFL, self.flags) != 0) {
				const e = std.c._errno().*;
				std.c._errno().* = if (e == 0) c.EIO else e;
				return error.IoError;
			}
			self.flags_dirty = false;
		}
		std.c._errno().* = saved_errno;
	}

	/// init + body + finish for one deadline-bounded exchange. finish() always
	/// runs. A failed body always wins, errno included: a restore failure can
	/// never mask the real error. A successful body wins over everything
	/// except a blocking-mode restore that failed, which finish() reports and
	/// which must fail the call -- see finish().
	pub fn run(
		fd: c_int,
		budget_ms: u32,
		ctx: anytype,
		comptime body: fn (*Session, @TypeOf(ctx)) Error!void,
	) Error!void {
		var session = try Session.init(fd, budget_ms);
		if (body(&session, ctx)) |_| {
			return session.finish();
		} else |err| {
			const saved_errno = std.c._errno().*;
			session.finish() catch {};
			std.c._errno().* = saved_errno;
			return err;
		}
	}

	fn remaining(self: *const Session) Error!i64 {
		const left = @atomicLoad(i64, &self.deadline, .monotonic) - try monotonicMicros();
		if (left <= 0) return error.TimedOut;
		return left;
	}

	fn setTimeout(self: *Session, which: Which) Error!void {
		const left = try self.remaining();
		const option: c_int = if (which == .recv) c.SO_RCVTIMEO else c.SO_SNDTIMEO;
		const armed = if (which == .recv) &self.rcv_armed else &self.snd_armed;
		const saved = if (which == .recv) &self.recv_timeout else &self.send_timeout;
		if (!armed.*) {
			// One getsockopt per option, on first use only; an option we never
			// arm costs nothing here and nothing in finish().
			var len: c.socklen_t = @sizeOf(c.struct_timeval);
			if (c.getsockopt(self.fd, c.SOL_SOCKET, option, saved, &len) != 0) return error.IoError;
			armed.* = true;
		}
		// A zero timeval means infinity, so retain the remaining microseconds.
		const tv: c.struct_timeval = .{ .tv_sec = @intCast(@divTrunc(left, 1_000_000)), .tv_usec = @intCast(@mod(left, 1_000_000)) };
		if (c.setsockopt(self.fd, c.SOL_SOCKET, option, &tv, @sizeOf(c.struct_timeval)) != 0) return error.IoError;
	}

	/// Dial `sa` on the session fd inside the shared deadline.
	pub fn connect(self: *Session, connect_fn: ConnectFn, sa: *const anyopaque, len: u32) Error!void {
		// Two strategies, because the two hosts of this code differ in both
		// what bounds a connect and what syscalls they may make.
		if (darwin) return self.connectPolled(connect_fn, sa, len);
		return self.connectBlocking(connect_fn, sa, len);
	}

	/// Linux: a blocking connect() is bounded by SO_SNDTIMEO
	/// (inet_wait_for_connect takes sk_sndtimeo), which is what the shim can
	/// use -- poll/ppoll/select are absent from passt's seccomp profiles.
	fn connectBlocking(self: *Session, connect_fn: ConnectFn, sa: *const anyopaque, len: u32) Error!void {
		while (true) {
			// Re-armed from the remaining budget, so a retry stays inside the
			// one deadline the dial and the handshake share.
			try self.setTimeout(.send);
			if (connect_fn(self.fd, sa, len) == 0) return;
			switch (std.c._errno().*) {
				// A signal (passt's SIGUSR1 rule reload) interrupts a connect
				// armed with a finite SO_SNDTIMEO as EINTR, not ERESTARTSYS
				// (sock_intr_errno), and the SYN is already out. Re-calling
				// connect() is the correct resume for a BLOCKING socket:
				// inet_stream_connect sets EALREADY for the SS_CONNECTING
				// state but then waits in inet_wait_for_connect and reports 0
				// once the socket reaches ESTABLISHED. The familiar "a retry
				// returns EALREADY" rule describes NON-blocking sockets, which
				// never wait. The budget check above bounds the retry loop.
				c.EINTR => continue,
				// Already up -- nothing left to wait for.
				c.EISCONN => return,
				// A blocking connect reports EINPROGRESS when SO_SNDTIMEO
				// expires, and EALREADY when a retry's re-armed budget expires
				// with the socket still in SYN_SENT. Both are the deadline.
				c.EINPROGRESS, c.EALREADY => return error.TimedOut,
				// Everything else is a real dial failure, errno included.
				// EAGAIN in particular is ephemeral-port exhaustion here, not
				// a timeout, and must reach the caller as itself.
				else => return error.ConnectFailed,
			}
		}
	}

	/// Darwin: SO_SNDTIMEO does not bound connect(), and a retry after EINTR
	/// returns EALREADY without waiting, so the dial is issued non-blocking
	/// and completion is waited for with poll(). The macOS host of this shim
	/// is cogbox-slirp, which runs under no seccomp filter, so poll is
	/// available there; see connectBlocking for why Linux cannot use it.
	fn connectPolled(self: *Session, connect_fn: ConnectFn, sa: *const anyopaque, len: u32) Error!void {
		// An exhausted budget must not dial at all, exactly as on Linux where
		// arming SO_SNDTIMEO is what rejects it.
		_ = try self.remaining();
		const blocking = self.flags & ~@as(c_int, c.O_NONBLOCK);
		// Flagged before the change, not after: if either fcntl below fails
		// the fd may be left non-blocking, and finish() must still put the
		// caller's mode back even when the caller's mode was blocking.
		self.flags_dirty = true;
		if (fcntl(self.fd, c.F_SETFL, blocking | @as(c_int, c.O_NONBLOCK)) != 0) return error.IoError;
		const rc = connect_fn(self.fd, sa, len);
		const dial_errno = std.c._errno().*;
		// Back to blocking for the handshake whatever the dial said.
		if (fcntl(self.fd, c.F_SETFL, blocking) != 0) return error.IoError;
		if (rc == 0) return;
		if (dial_errno != c.EINPROGRESS and dial_errno != c.EINTR) {
			std.c._errno().* = dial_errno;
			return error.ConnectFailed;
		}
		while (true) {
			// Round up: a sub-millisecond remainder must still poll once.
			const left_ms = @divTrunc(try self.remaining() + 999, 1000);
			var fds = [_]pollfd{.{ .fd = self.fd, .events = POLLOUT, .revents = 0 }};
			const pr = poll(&fds, 1, @intCast(left_ms));
			if (pr < 0) {
				// Recomputed budget on the next pass, so signals cannot
				// extend the dial.
				if (std.c._errno().* == c.EINTR) continue;
				return error.IoError;
			}
			if (pr == 0) return error.TimedOut;
			var so_error: c_int = 0;
			var olen: c.socklen_t = @sizeOf(c_int);
			if (c.getsockopt(self.fd, c.SOL_SOCKET, c.SO_ERROR, &so_error, &olen) != 0) return error.IoError;
			if (so_error == 0) return;
			std.c._errno().* = so_error;
			return error.ConnectFailed;
		}
	}

	fn ioError() Error {
		const e = std.c._errno().*;
		return if (e == c.EAGAIN or e == c.EWOULDBLOCK) error.TimedOut else error.IoError;
	}

	fn writeAll(self: *Session, buf: []const u8) Error!void {
		var off: usize = 0;
		while (off < buf.len) {
			try self.setTimeout(.send);
			const n = write(self.fd, buf.ptr + off, buf.len - off);
			if (n < 0 and std.c._errno().* == c.EINTR) continue;
			if (n < 0) return ioError();
			if (n == 0) {
				// write() returning 0 sets no errno; do not let a stale one
				// be reported to the guest as if it were this call's.
				std.c._errno().* = c.EIO;
				return error.IoError;
			}
			off += @intCast(n);
		}
	}

	fn readExact(self: *Session, buf: []u8) Error!void {
		var off: usize = 0;
		while (off < buf.len) {
			try self.setTimeout(.recv);
			const n = read(self.fd, buf.ptr + off, buf.len - off);
			if (n < 0 and std.c._errno().* == c.EINTR) continue;
			if (n < 0) return ioError();
			if (n == 0) return error.Truncated;
			off += @intCast(n);
		}
	}

	/// A handshake that reached its last byte inside the budget has succeeded.
	/// There is deliberately no deadline check after the exchange: the reply
	/// is in hand and the session is live, so reporting a timeout here would
	/// abandon a working connection.
	pub fn handshake(self: *Session, target_addr: filter.IpAddr, target_port: u16) Error!void {
		return handshakeSession(self, target_addr, target_port);
	}
};

pub const Target = struct { addr: filter.IpAddr, port: u16 };

/// Perform a SOCKS5 v5 CONNECT handshake on `fd` (which must already be
/// connected to a SOCKS5 server), within `budget_ms` total. On success the
/// fd is in passthrough mode: subsequent reads/writes flow to/from the
/// original destination. Every caller states its own budget; there is no
/// default, because the two callers are wired very differently (see
/// docs/network-filtering.md).
pub fn handshake(fd: c_int, budget_ms: u32, target_addr: filter.IpAddr, target_port: u16) Error!void {
	return Session.run(fd, budget_ms, Target{ .addr = target_addr, .port = target_port }, runHandshake);
}

fn runHandshake(session: *Session, target: Target) Error!void {
	return session.handshake(target.addr, target.port);
}

fn handshakeSession(session: *Session, target_addr: filter.IpAddr, target_port: u16) Error!void {
	// Greeting: VER=5, NMETHODS=1, METHODS=[0 (no auth)]
	try session.writeAll(&.{ 0x05, 0x01, 0x00 });

	// Server method selection: VER, METHOD
	var sel: [2]u8 = undefined;
	try session.readExact(&sel);
	if (sel[0] != 0x05) return error.ProtocolError;
	if (sel[1] != 0x00) return error.AuthMethodRejected;

	// CONNECT request: VER=5, CMD=1, RSV=0, ATYP, ADDR, PORT(big-endian)
	var req: [22]u8 = undefined;
	req[0] = 0x05;
	req[1] = 0x01;
	req[2] = 0x00;
	var req_len: usize = 4;
	switch (target_addr) {
		.ipv4 => |ip| {
			req[3] = 0x01;
			@memcpy(req[4..8], &ip);
			req_len = 8;
		},
		.ipv6 => |ip| {
			req[3] = 0x04;
			@memcpy(req[4..20], &ip);
			req_len = 20;
		},
	}
	req[req_len] = @intCast((target_port >> 8) & 0xff);
	req[req_len + 1] = @intCast(target_port & 0xff);
	req_len += 2;
	try session.writeAll(req[0..req_len]);

	// Server reply: VER, REP, RSV, ATYP, BIND_ADDR, BIND_PORT
	var head: [4]u8 = undefined;
	try session.readExact(&head);
	if (head[0] != 0x05) return error.ProtocolError;
	if (head[1] != 0x00) return error.ConnectRejected;
	const tail_len: usize = switch (head[3]) {
		0x01 => 4 + 2,
		0x04 => 16 + 2,
		0x03 => blk: {
			var lb: [1]u8 = undefined;
			try session.readExact(&lb);
			break :blk @as(usize, lb[0]) + 2;
		},
		else => return error.ProtocolError,
	};
	var tail: [256 + 2]u8 = undefined;
	if (tail_len > tail.len) return error.ProtocolError;
	try session.readExact(tail[0..tail_len]);
}

// --- Tests ---

const t = std.testing;

const test_budget_ms: u32 = 5000;

extern "c" fn socketpair(domain: c_int, type_: c_int, proto_: c_int, sv: *[2]c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn shutdown(fd: c_int, how: c_int) c_int;
extern "c" fn usleep(usec: c_uint) c_int;
const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const SHUT_WR: c_int = 1;

fn newPair() ![2]c_int {
	var sv: [2]c_int = undefined;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, &sv) != 0) return error.IoError;
	return sv;
}

fn writeAll(fd: c_int, buf: []const u8) Error!void {
	var off: usize = 0;
	while (off < buf.len) {
		const n = write(fd, buf.ptr + off, buf.len - off);
		if (n <= 0) return error.IoError;
		off += @intCast(n);
	}
}

fn readExact(fd: c_int, buf: []u8) Error!void {
	var off: usize = 0;
	while (off < buf.len) {
		const n = read(fd, buf.ptr + off, buf.len - off);
		if (n < 0) return error.IoError;
		if (n == 0) return error.Truncated;
		off += @intCast(n);
	}
}

test "handshake ipv4 success" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);

	// Pre-stage server replies on sv[1]; handshake reads them on sv[0].
	try writeAll(sv[1], &.{ 0x05, 0x00 });
	try writeAll(sv[1], &.{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });

	try handshake(sv[0], test_budget_ms, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443);

	// Inspect what handshake wrote into sv[0]; readable on sv[1].
	var got: [13]u8 = undefined;
	try readExact(sv[1], &got);

	const expected = [_]u8{
		0x05, 0x01, 0x00, // greeting
		0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xbb, // connect 1.2.3.4:443
	};
	try t.expectEqualSlices(u8, &expected, &got);
}

test "handshake ipv6 success" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);

	try writeAll(sv[1], &.{ 0x05, 0x00 });
	// Reply with ipv4 BIND form (server's choice; client doesn't care)
	try writeAll(sv[1], &.{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });

	const v6: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	try handshake(sv[0], test_budget_ms, .{ .ipv6 = v6 }, 80);

	var got: [25]u8 = undefined;
	try readExact(sv[1], &got);
	try t.expectEqualSlices(u8, &.{ 0x05, 0x01, 0x00 }, got[0..3]); // greeting
	try t.expectEqual(@as(u8, 0x04), got[6]); // ATYP=ipv6
	try t.expectEqualSlices(u8, &v6, got[7..23]);
	try t.expectEqual(@as(u16, 80), std.mem.readInt(u16, got[23..25], .big));
}

test "handshake rejects when server picks unknown auth method" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);

	try writeAll(sv[1], &.{ 0x05, 0xff }); // METHOD = NO ACCEPTABLE METHODS

	try t.expectError(error.AuthMethodRejected, handshake(sv[0], test_budget_ms, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
}

test "handshake reports connect rejected on non-zero REP" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);

	try writeAll(sv[1], &.{ 0x05, 0x00 });
	// REP=0x05 (connection refused), ATYP=ipv4, junk addr/port
	try writeAll(sv[1], &.{ 0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });

	try t.expectError(error.ConnectRejected, handshake(sv[0], test_budget_ms, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
}

test "handshake reports protocol error on wrong server version" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);

	try writeAll(sv[1], &.{ 0x04, 0x00 }); // wrong VER

	try t.expectError(error.ProtocolError, handshake(sv[0], test_budget_ms, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
}

test "handshake reports truncated when server EOFs mid-reply" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);

	try writeAll(sv[1], &.{ 0x05, 0x00 });
	// Only write 3 bytes of the connect reply, then half-close the
	// write side so the client gets EOF mid-read but its own writes to
	// the peer still go through.
	try writeAll(sv[1], &.{ 0x05, 0x00, 0x00 });
	_ = shutdown(sv[1], SHUT_WR);

	try t.expectError(error.Truncated, handshake(sv[0], test_budget_ms, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
}

test "silent proxy expires and restores nonblocking flags and socket timeouts" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);
	const flags = fcntl(sv[0], c.F_GETFL);
	try t.expectEqual(@as(c_int, 0), fcntl(sv[0], c.F_SETFL, flags | @as(c_int, c.O_NONBLOCK)));
	const tv: c.struct_timeval = .{ .tv_sec = 2, .tv_usec = 125000 };
	try t.expectEqual(@as(c_int, 0), c.setsockopt(sv[0], c.SOL_SOCKET, c.SO_RCVTIMEO, &tv, @sizeOf(c.struct_timeval)));
	var session = try Session.init(sv[0], 100);
	const start = try monotonicMicros();
	try t.expectError(error.TimedOut, session.handshake(.{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
	const elapsed = try monotonicMicros() - start;
	try t.expect(elapsed >= 80_000 and elapsed < 1_000_000);
	const saved_recv = session.recv_timeout;
	const saved_send = session.send_timeout;
	try session.finish();
	try t.expectEqual(flags | @as(c_int, c.O_NONBLOCK), fcntl(sv[0], c.F_GETFL));
	var restored: c.struct_timeval = undefined;
	var len: c.socklen_t = @sizeOf(c.struct_timeval);
	try t.expectEqual(@as(c_int, 0), c.getsockopt(sv[0], c.SOL_SOCKET, c.SO_RCVTIMEO, &restored, &len));
	try t.expectEqual(saved_recv.tv_sec, restored.tv_sec);
	try t.expectEqual(saved_recv.tv_usec, restored.tv_usec);
	len = @sizeOf(c.struct_timeval);
	try t.expectEqual(@as(c_int, 0), c.getsockopt(sv[0], c.SOL_SOCKET, c.SO_SNDTIMEO, &restored, &len));
	try t.expectEqual(saved_send.tv_sec, restored.tv_sec);
	try t.expectEqual(saved_send.tv_usec, restored.tv_usec);
}

test "finish leaves an option the session never armed alone" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);
	const tv: c.struct_timeval = .{ .tv_sec = 3, .tv_usec = 500_000 };
	try t.expectEqual(@as(c_int, 0), c.setsockopt(sv[0], c.SOL_SOCKET, c.SO_RCVTIMEO, &tv, @sizeOf(c.struct_timeval)));
	var session = try Session.init(sv[0], 1000);
	try t.expect(!session.rcv_armed);
	try t.expect(!session.snd_armed);
	try session.finish();
	// Nothing was armed, so nothing was written back and the caller's own
	// SO_RCVTIMEO is untouched.
	var restored: c.struct_timeval = undefined;
	var len: c.socklen_t = @sizeOf(c.struct_timeval);
	try t.expectEqual(@as(c_int, 0), c.getsockopt(sv[0], c.SOL_SOCKET, c.SO_RCVTIMEO, &restored, &len));
	try t.expectEqual(@as(@TypeOf(restored.tv_sec), 3), restored.tv_sec);
	try t.expectEqual(@as(@TypeOf(restored.tv_usec), 500_000), restored.tv_usec);
}

fn trickleReply(fd: c_int) void {
	const reply = [_]u8{ 5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
	for (reply) |byte| {
		_ = usleep(50000);
		_ = write(fd, &.{byte}, 1);
	}
}

test "partial progress across SOCKS phases cannot reset the deadline" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);
	const worker = try std.Thread.spawn(.{}, trickleReply, .{sv[1]});
	defer worker.join();
	var session = try Session.init(sv[0], 200);
	defer session.finish() catch {};
	const start = try monotonicMicros();
	try t.expectError(error.TimedOut, session.handshake(.{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
	try t.expect(try monotonicMicros() - start < 500_000);
}

test "a blocked handshake write also expires" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);
	const flags = fcntl(sv[0], c.F_GETFL);
	try t.expectEqual(@as(c_int, 0), fcntl(sv[0], c.F_SETFL, flags | @as(c_int, c.O_NONBLOCK)));
	const buf = [_]u8{0} ** 8192;
	while (write(sv[0], &buf, buf.len) >= 0) {}
	try t.expect(std.c._errno().* == c.EAGAIN or std.c._errno().* == c.EWOULDBLOCK);
	var session = try Session.init(sv[0], 100);
	defer session.finish() catch {};
	try t.expectError(error.TimedOut, session.handshake(.{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
}

test "connect and handshake consume one shared budget" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);
	var session = try Session.init(sv[0], 20);
	defer session.finish() catch {};
	try session.setTimeout(.send);
	_ = usleep(40000);
	// Even a fully buffered reply cannot grant a fresh handshake budget: the
	// first write's arming rejects the exhausted budget before any I/O.
	try writeAll(sv[1], &.{ 5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
	try t.expectError(error.TimedOut, session.handshake(.{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
}

/// Serve the handshake so that its last bytes land after the budget has run
/// out, while every read still completes. The peer reads the client's own
/// greeting and CONNECT request first, so it knows the client has reached the
/// reply phase rather than guessing; it then hands over the four-byte reply
/// header and, once the client is certainly parked in the final read, expires
/// the deadline and writes the six trailing bytes in ONE write -- an AF_UNIX
/// SOCK_STREAM socketpair delivers that as a single chunk, so the reader never
/// loops back to re-arm against the now-expired budget. The reply was waited
/// for inside the budget, so the handshake must report success however little
/// time is left when it returns.
fn replyAtTheDeadline(fd: c_int, session: *Session) void {
	var greeting: [3]u8 = undefined;
	readExact(fd, &greeting) catch return;
	writeAll(fd, &.{ 5, 0 }) catch return;
	var request: [10]u8 = undefined;
	readExact(fd, &request) catch return;
	writeAll(fd, &.{ 5, 0, 0, 1 }) catch return;
	_ = usleep(50_000);
	@atomicStore(i64, &session.deadline, monotonicMicros() catch return, .monotonic);
	writeAll(fd, &.{ 0, 0, 0, 0, 0, 0 }) catch return;
}

test "a reply that arrives inside the budget is not reported as a timeout" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);
	var session = try Session.init(sv[0], 5000);
	defer session.finish() catch {};
	const worker = try std.Thread.spawn(.{}, replyAtTheDeadline, .{ sv[1], &session });
	defer worker.join();
	try session.handshake(.{ .ipv4 = .{ 1, 2, 3, 4 } }, 443);
	// The budget really is gone by now; the handshake still succeeded.
	try t.expectError(error.TimedOut, session.remaining());
}

fn closeTheFd(session: *Session, _: void) Error!void {
	_ = close(session.fd);
}

fn failAfterClosingTheFd(session: *Session, _: void) Error!void {
	_ = close(session.fd);
	return error.ConnectRejected;
}

test "a failed blocking-mode restore fails an otherwise successful exchange" {
	const sv = try newPair();
	defer _ = close(sv[1]);
	const flags = fcntl(sv[0], c.F_GETFL);
	try t.expectEqual(@as(c_int, 0), fcntl(sv[0], c.F_SETFL, flags | @as(c_int, c.O_NONBLOCK)));
	// The body succeeds but the fd cannot be handed back non-blocking. Passt
	// drives its sockets from one epoll loop, so returning success here would
	// leave a blocking fd in it; the flow must fail instead. (Closing the fd
	// is simply the cheapest way to make fcntl fail.)
	try t.expectError(error.IoError, Session.run(sv[0], 1000, {}, closeTheFd));
	try t.expectEqual(@as(c_int, c.EBADF), std.c._errno().*);
}

test "a failed restore never masks the body's own error" {
	const sv = try newPair();
	defer _ = close(sv[1]);
	const flags = fcntl(sv[0], c.F_GETFL);
	try t.expectEqual(@as(c_int, 0), fcntl(sv[0], c.F_SETFL, flags | @as(c_int, c.O_NONBLOCK)));
	try t.expectError(error.ConnectRejected, Session.run(sv[0], 1000, {}, failAfterClosingTheFd));
}

test "a timeout that cannot be restored does not fail the exchange" {
	const sv = try newPair();
	defer _ = close(sv[1]);
	// The fd was already blocking, so finish() has no blocking mode to put
	// back; only the armed SO_RCVTIMEO restore can fail, and that is discarded.
	var session = try Session.init(sv[0], 1000);
	try session.setTimeout(.recv);
	try t.expect(session.rcv_armed);
	try t.expect(!session.flags_dirty);
	_ = close(sv[0]);
	try session.finish();
}

test "successful handshake restores blocking socket settings" {
	const sv = try newPair();
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);
	const flags = fcntl(sv[0], c.F_GETFL);
	try writeAll(sv[1], &.{ 5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
	try handshake(sv[0], test_budget_ms, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443);
	try t.expectEqual(flags, fcntl(sv[0], c.F_GETFL));
	for ([_]c_int{ c.SO_RCVTIMEO, c.SO_SNDTIMEO }) |opt| {
		var tv: c.struct_timeval = undefined;
		var len: c.socklen_t = @sizeOf(c.struct_timeval);
		try t.expectEqual(@as(c_int, 0), c.getsockopt(sv[0], c.SOL_SOCKET, opt, &tv, &len));
		try t.expectEqual(@as(@TypeOf(tv.tv_sec), 0), tv.tv_sec);
		try t.expectEqual(@as(@TypeOf(tv.tv_usec), 0), tv.tv_usec);
	}
}

// --- connect tests ---
//
// Both dial strategies are exercised here, including the Darwin one: poll()
// is perfectly usable in a test binary, and compiling and running it on Linux
// is the only coverage the macOS path can get from this repo's CI.

extern "c" fn socket(domain: c_int, type_: c_int, proto: c_int) c_int;
extern "c" fn bind(fd: c_int, addr: *const anyopaque, len: u32) c_int;
extern "c" fn listen(fd: c_int, backlog: c_int) c_int;
extern "c" fn getsockname(fd: c_int, addr: *anyopaque, len: *u32) c_int;
// glibc's connect() comes through @cImport as __SOCKADDR_ARG, which Zig
// cannot hand a plain pointer to; bind the raw symbol with the ConnectFn
// shape instead (the same shape the shim passes its dlsym'd real_connect in).
const rawConnect: ConnectFn = @extern(ConnectFn, .{ .name = "connect" });

const SockaddrIn = extern struct {
	sin_family: u16,
	sin_port: u16,
	sin_addr: u32,
	pad: [8]u8 = .{0} ** 8,
};

const AF_INET: c_int = 2;

fn loopbackListener(backlog: c_int) !struct { fd: c_int, addr: SockaddrIn } {
	const fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return error.IoError;
	var sa: SockaddrIn = .{ .sin_family = @intCast(AF_INET), .sin_port = 0, .sin_addr = std.mem.nativeToBig(u32, 0x7f000001) };
	if (bind(fd, &sa, @sizeOf(SockaddrIn)) != 0) return error.IoError;
	if (listen(fd, backlog) != 0) return error.IoError;
	var len: u32 = @sizeOf(SockaddrIn);
	if (getsockname(fd, &sa, &len) != 0) return error.IoError;
	return .{ .fd = fd, .addr = sa };
}

test "both dial strategies reach a live listener" {
	const listener = try loopbackListener(8);
	defer _ = close(listener.fd);
	for ([_]bool{ false, true }) |polled| {
		const fd = socket(AF_INET, SOCK_STREAM, 0);
		try t.expect(fd >= 0);
		defer _ = close(fd);
		var session = try Session.init(fd, 2000);
		defer session.finish() catch {};
		const addr = listener.addr;
		if (polled) {
			try session.connectPolled(rawConnect, &addr, @sizeOf(SockaddrIn));
		} else {
			try session.connectBlocking(rawConnect, &addr, @sizeOf(SockaddrIn));
		}
		// The fd is blocking again, ready for the synchronous handshake.
		try t.expectEqual(@as(c_int, 0), fcntl(fd, c.F_GETFL) & @as(c_int, c.O_NONBLOCK));
	}
}

test "a refused dial keeps its own errno instead of becoming a timeout" {
	// Bind and listen, then close: the port is now nobody's and loopback
	// answers with RST, so connect fails with ECONNREFUSED immediately.
	const listener = try loopbackListener(1);
	const addr = listener.addr;
	_ = close(listener.fd);
	for ([_]bool{ false, true }) |polled| {
		const fd = socket(AF_INET, SOCK_STREAM, 0);
		try t.expect(fd >= 0);
		defer _ = close(fd);
		var session = try Session.init(fd, 2000);
		defer session.finish() catch {};
		const err = if (polled)
			session.connectPolled(rawConnect, &addr, @sizeOf(SockaddrIn))
		else
			session.connectBlocking(rawConnect, &addr, @sizeOf(SockaddrIn));
		try t.expectError(error.ConnectFailed, err);
		try t.expectEqual(@as(c_int, c.ECONNREFUSED), std.c._errno().*);
	}
}

test "a dial with no budget left never touches the socket" {
	const listener = try loopbackListener(8);
	defer _ = close(listener.fd);
	const fd = socket(AF_INET, SOCK_STREAM, 0);
	try t.expect(fd >= 0);
	defer _ = close(fd);
	var session = try Session.init(fd, 0);
	defer session.finish() catch {};
	const addr = listener.addr;
	try t.expectError(error.TimedOut, session.connectBlocking(rawConnect, &addr, @sizeOf(SockaddrIn)));
	try t.expectError(error.TimedOut, session.connectPolled(rawConnect, &addr, @sizeOf(SockaddrIn)));
}

// A signal storm against a dial that cannot complete. The point is the EINTR
// handling: without it the very first SIGUSR1 aborts the connect in a
// millisecond or two. An AF_UNIX listener with a full backlog parks connect()
// in unix_wait_for_peer, the same sk_sndtimeo-bounded, signal-interruptible
// wait a TCP SYN_SENT sits in, and needs no network -- which is what makes it
// runnable in the nix build sandbox.
//
// What this test does NOT cover is the TCP resume semantics connectBlocking
// relies on: that re-calling connect() on a BLOCKING socket in SS_CONNECTING
// waits again rather than failing, that EALREADY surfaces only once the
// re-armed budget expires, and that a peer RST is delivered as ECONNREFUSED on
// the retry. Those were checked by hand with C probes on Linux 6.18 and are
// left out of CI because the sandbox has no egress to a destination that can
// be held in SYN_SENT.

extern "c" fn pthread_self() usize;
extern "c" fn pthread_kill(thread: usize, sig: c_int) c_int;
const SIGUSR1: c_int = @intFromEnum(std.posix.SIG.USR1);

fn noopHandler(_: std.posix.SIG) callconv(.c) void {}

var storm_stop = std.atomic.Value(bool).init(false);

fn signalStorm(target: usize) void {
	while (!storm_stop.load(.seq_cst)) {
		_ = pthread_kill(target, SIGUSR1);
		_ = usleep(2000);
	}
}

const SockaddrUn = extern struct {
	sun_family: u16,
	sun_path: [108]u8,
};

test "a signal storm cannot cut a dial short" {
	if (darwin) return error.SkipZigTest; // no abstract sockets, different SIGUSR1
	// An abstract-namespace socket (leading NUL): no filesystem, no cleanup.
	var sa: SockaddrUn = .{ .sun_family = @intCast(AF_UNIX), .sun_path = .{0} ** 108 };
	const name = try std.fmt.bufPrint(sa.sun_path[1..], "cogbox-socks5-dial-{d}", .{std.c.getpid()});
	const sa_len: u32 = @intCast(@offsetOf(SockaddrUn, "sun_path") + 1 + name.len);

	const listener = socket(AF_UNIX, SOCK_STREAM, 0);
	try t.expect(listener >= 0);
	defer _ = close(listener);
	try t.expectEqual(@as(c_int, 0), bind(listener, &sa, sa_len));
	try t.expectEqual(@as(c_int, 0), listen(listener, 1));

	// Fill the accept queue so the next dial has to wait.
	var parked: [4]c_int = .{ -1, -1, -1, -1 };
	defer for (parked) |p| {
		if (p >= 0) _ = close(p);
	};
	for (&parked) |*p| {
		const fd = socket(AF_UNIX, SOCK_STREAM, 0);
		try t.expect(fd >= 0);
		p.* = fd;
		var probe = try Session.init(fd, 50);
		defer probe.finish() catch {};
		probe.connectBlocking(rawConnect, &sa, sa_len) catch break;
	}

	var act: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
	act.handler.handler = noopHandler;
	var old: std.posix.Sigaction = undefined;
	std.posix.sigaction(std.posix.SIG.USR1, &act, &old);
	defer std.posix.sigaction(std.posix.SIG.USR1, &old, null);

	const fd = socket(AF_UNIX, SOCK_STREAM, 0);
	try t.expect(fd >= 0);
	defer _ = close(fd);
	var session = try Session.init(fd, 300);
	defer session.finish() catch {};

	storm_stop.store(false, .seq_cst);
	const storm = try std.Thread.spawn(.{}, signalStorm, .{pthread_self()});
	defer {
		storm_stop.store(true, .seq_cst);
		storm.join();
	}
	const start = try monotonicMicros();
	// AF_UNIX reports an expired SO_SNDTIMEO as EAGAIN rather than the
	// EINPROGRESS a TCP socket uses, so either outcome is acceptable here.
	// What matters is that it took the whole budget: an unhandled EINTR
	// would have ended the dial after the first signal, ~2ms in.
	session.connectBlocking(rawConnect, &sa, sa_len) catch |err| {
		try t.expect(err == error.TimedOut or err == error.ConnectFailed);
		const elapsed = try monotonicMicros() - start;
		try t.expect(elapsed >= 250_000);
		return;
	};
	return error.SkipZigTest; // the queue drained; nothing was waited for
}
