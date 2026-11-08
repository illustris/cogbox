// cogbox __l7proxy <runtime-dir>
//
// Host-side L7 proxy. The guest's 80/443 egress is funneled here by the
// netfilter shim's remap (a SOCKS5 CONNECT carrying the ORIGINAL ip:port).
// We accept the SOCKS5 connection, peek the first app bytes to learn the
// vhost (TLS SNI or HTTP Host), evaluate it against the L7 rules, then
// RE-RESOLVE that name host-side and splice -- never trusting the guest's
// chosen IP. Every re-resolved address is vetted against a non-overridable
// SSRF floor AND the instance's own CIDR deny-list before we connect.
//
// Runs as a normal host process (NOT under the LD_PRELOAD shim), so its own
// getaddrinfo()+connect() reach the real internet -- which is exactly why
// the SSRF/CIDR re-check below is mandatory.
//
// Two tiers: passthrough hosts are spliced without TLS termination; hosts
// needing the terminate tier (the instance default; path rules / Host==SNI
// enforcement) are handed to the per-instance mitmproxy backend over SOCKS5
// (see terminateHandoff).

const std = @import("std");
const filter = @import("filter");
const tls = @import("tls.zig");
const http = @import("http.zig");
const clock = @import("clock.zig");
/// The ECH-capability probe's protocol half and result cache. Public so the CLI
/// (`cogbox __ech-probe`) and the tests reach its types; the socket half
/// (echProbeAddr, echGate) lives below with the rest of the connect plumbing.
pub const echprobe = @import("echprobe.zig");

const c = @cImport({
	@cDefine("_GNU_SOURCE", "1");
	// Disable glibc FORTIFY: in ReleaseSafe, translate-c renders the checked
	// inline wrappers (__poll_chk / __recv_chk ...) with an object_size() call
	// whose FORTIFY-level argument comes out as bool, which fails to compile.
	// We don't want the checked variants anyway.
	@cDefine("_FORTIFY_SOURCE", "0");
	@cInclude("sys/socket.h");
	@cInclude("netinet/in.h");
	@cInclude("netdb.h");
	@cInclude("sys/time.h");
	@cInclude("poll.h");
	@cInclude("unistd.h");
	@cInclude("errno.h");
	@cInclude("string.h");
});

/// Monotonic milliseconds (clock.zig), re-exported so the peek-deadline callers
/// and their tests keep reaching it here.
pub const monotonicMs = clock.monotonicMs;

// open(2) -- declared directly to dodge fcntl.h's FORTIFY macros (same
// reasoning as the netfilter shim).
const O_RDONLY: c_int = 0;
extern "c" fn @"open"(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;

// bind/connect/accept take glibc's transparent `__SOCKADDR_ARG` union through
// @cImport, which Zig can't pass a plain pointer to. Bind the raw libc symbols
// with sane sockaddr-pointer signatures instead.
const c_bind = @extern(*const fn (c_int, *const c.struct_sockaddr, c.socklen_t) callconv(.c) c_int, .{ .name = "bind" });
const c_connect = @extern(*const fn (c_int, *const c.struct_sockaddr, c.socklen_t) callconv(.c) c_int, .{ .name = "connect" });
const c_accept = @extern(*const fn (c_int, ?*c.struct_sockaddr, ?*c.socklen_t) callconv(.c) c_int, .{ .name = "accept" });
// getsockopt for SO_ORIGINAL_DST. Bound as a raw libc symbol with an explicit
// signature (the @cImport variant is fine, but binding it directly keeps the
// pointer types unambiguous). Used only by the redirect accept path.
const c_getsockopt = @extern(*const fn (c_int, c_int, c_int, *anyopaque, *c.socklen_t) callconv(.c) c_int, .{ .name = "getsockopt" });

// Linux socket constants the netinet/in.h cImport doesn't surface (they live in
// linux/netfilter_ipv4.h). Numeric per the stable kernel ABI; SOL_IP ==
// IPPROTO_IP == 0. SO_ORIGINAL_DST reads the conntrack ORIGINAL tuple recorded
// by a netfilter REDIRECT (DNAT) -- i.e. the pre-redirect destination the guest
// aimed at, supplied by the kernel and not forgeable by the guest.
const SOL_IP: c_int = 0;
const SO_ORIGINAL_DST: c_int = 80;

const peek_cap: usize = 16 * 1024;
const relay_buf: usize = 32 * 1024;
const io_timeout_secs: i32 = 15;
const relay_idle_ms: c_int = 120_000;
const max_conns: usize = 512;

// Fast-path classification-peek deadline (ms) for the raw-L4-eligible silent
// server-speaks-first case (SSH/SMTP/...). Overridable via COGBOX_L7_PEEK_MS.
// 300ms comfortably covers a real TLS ClientHello / HTTP request (both arrive in
// the first RTT) while bounding a silent client that would otherwise hold the
// peek for the full io_timeout_secs before falling through to the raw-L4 splice.
// Set once in run(); read by worker(). Applies ONLY when a raw-L4 splice to the
// flow's dst would be allowed anyway (see worker) -- never on the L7/hostname
// path, where classification is the flow's only way forward.
const peek_fast_ms_default: i32 = 300;
// Lower bound for a COGBOX_L7_PEEK_MS override. A real TLS ClientHello / HTTP
// request lands within the first RTT, so 50ms is comfortably enough to classify
// a prompt client on the fast path; flooring here stops an operator typo from
// shrinking the deadline so far that a legitimate first-flight is cut off.
const peek_fast_ms_floor: i32 = 50;
var peek_fast_ms: i32 = peek_fast_ms_default;

/// Sanitize a COGBOX_L7_PEEK_MS override into the effective fast-path deadline.
/// Fail-safe both directions: a non-positive value would UNCAP the peek (a silent
/// client stalls the full io_timeout_secs) -> fall back to the default; a tiny
/// positive value (an operator typo like 5) would effectively skip classifying a
/// prompt client on the fast path -> floor it at peek_fast_ms_floor.
pub fn clampPeekMs(peek_ms: i32) i32 {
	if (peek_ms <= 0) return peek_fast_ms_default;
	return @max(peek_ms, peek_fast_ms_floor);
}

// --- shared state ---
var runtime_dir_buf: [4096]u8 = undefined;
var runtime_dir_len: usize = 0;

// Loopback port of this instance's mitmproxy terminate backend (base + 2),
// set in run() from the instance's L7 port base.
var mitm_port: u16 = filter.l7_default_base + 2;

/// Front-door accept mode, selected once at startup from COGBOX_L7_ACCEPT.
///   socks5 (DEFAULT): the unchanged VM/launch path -- the guest's 80/443
///     egress arrives as a SOCKS5 CONNECT carrying the original ip:port.
///   redirect: the container enforcer path -- a normal listener receives flows
///     that an nft REDIRECT (DNAT) sent here, and the KERNEL hands us the
///     pre-redirect original dst via getsockopt(SO_ORIGINAL_DST), which a guest
///     cannot forge. The enforcer holds NO CAP_NET_ADMIN, so this path uses
///     neither IP_TRANSPARENT nor fwmark policy-routing (both NET_ADMIN-gated).
/// Anything other than "redirect" resolves to socks5, so the existing path is
/// byte-for-byte unchanged.
pub const AcceptMode = enum { socks5, redirect };
var accept_mode: AcceptMode = .socks5;

// COGBOX_L7_FUNNEL_ALL: when set, the socks5 accept path routes its
// unclassifiable (.deny) flows to the same rawL4Splice double-gate the redirect
// arm already uses, instead of the hard drop. Set for the separate-pod enforcer:
// the agent pod's in-pod shim funnels EVERY diverted port over one SOCKS5 hop,
// so the socks5 front door now sees non-HTTP/TLS flows too. Default false keeps
// the VM/launch socks5 path byte-identical (a .deny is hard-dropped there).
// A well-formed no-SNI ClientHello (.no_sni) is not governed by this flag: it is
// L4-gated on every front door (see worker).
var funnel_all: bool = false;

// COGBOX_L7_LISTEN_ADDR (host-order IPv4): the front-door listener bind address.
// Default 127.0.0.1 == the unchanged VM/launch path (the guest's funnel and the
// mitm hop are loopback-local). The enforcer pod sets 0.0.0.0 so the agent pod's
// cross-pod shim can reach the SOCKS5 front door over the pod network. The mitm
// terminate hop (connectLoopback) is ALWAYS 127.0.0.1, never this address.
var listen_addr_host: u32 = 0x7f000001;

// Tiny test-and-set spinlock guarding the two rulesets. Critical sections are
// microsecond-short memory scans; reloads (the only writer, in the accept
// thread) are rare, so spinning is cheaper than a futex.
var rules_lock = std.atomic.Value(bool).init(false);
var cidr_rs: filter.RuleSet = .{};
var l7_rs: filter.L7RuleSet = .{};
// Hosts the terminate-tier addon injects a host-side credential into (read from
// <runtime>/l7-inject-hosts, reloaded alongside the rules). Used to route a
// host's PLAIN-HTTP egress through the terminate backend so its credential is
// stamped -- TLS injection already rides l7_rs.needsTerminate.
var inject_hosts: filter.InjectHosts = .{};

fn lockRules() void {
	while (rules_lock.swap(true, .acquire)) std.atomic.spinLoopHint();
}
fn unlockRules() void {
	rules_lock.store(false, .release);
}

var reload_pending = std.atomic.Value(bool).init(false);
var conn_count = std.atomic.Value(usize).init(0);

// The ECH gate's process-wide inputs, set once in run() before any accept
// loop starts (workers only read them): the Io the probe draws its entropy
// from, and whether the probe may run at all. On unless the operator set the
// kill switch COGBOX_L7_ECH_PROBE=0 (the CLI reads it; a value it does not
// know is off too): off, every ECH hello on the splice tier is refused, as
// before the probe existed. The initial false only matters before run().
var ech_io: std.Io = undefined;
var ech_probe_enabled: bool = false;

pub fn run(_: std.mem.Allocator, io: std.Io, runtime_dir: []const u8, l7_base: u16, mode: AcceptMode, listen_addr: u32, funnel: bool, peek_ms: i32, ech_probe: bool) !void {
	if (runtime_dir.len >= runtime_dir_buf.len) return error.PathTooLong;
	@memcpy(runtime_dir_buf[0..runtime_dir.len], runtime_dir);
	runtime_dir_len = runtime_dir.len;

	accept_mode = mode;
	listen_addr_host = listen_addr;
	funnel_all = funnel;
	peek_fast_ms = clampPeekMs(peek_ms);
	ech_io = io;
	ech_probe_enabled = ech_probe;
	const ech_state: []const u8 = if (ech_probe) "on" else "off";
	installSignals();
	loadRules();

	// Per-instance loopback ports (base / base+1 / base+2). Binding is
	// fail-closed: if a port is already taken (e.g. another instance picked
	// the same base, or a stale proxy), the listen* helper returns error.Bind
	// and the process exits non-zero -- the launcher treats that as a hard
	// failure and aborts the start rather than leaving the funnel pointed
	// elsewhere.
	const ports = filter.l7PortsForBase(l7_base);
	mitm_port = ports.mitm;

	switch (mode) {
		// DEFAULT path -- byte-for-byte identical to the original SOCKS5 proxy.
		// The VM/launch path only ever reaches here.
		.socks5 => {
			const tls_fd = try listenFront(ports.tls);
			const http_fd = try listenFront(ports.http);

			const la: [4]u8 = @bitCast(std.mem.nativeToBig(u32, listen_addr_host));
			logLine("l7proxy: listening on {d}.{d}.{d}.{d}:{d} (tls) :{d} (http); terminate backend 127.0.0.1:{d}; funnel_all={} ech_probe={s}", .{ la[0], la[1], la[2], la[3], ports.tls, ports.http, ports.mitm, funnel_all, ech_state });

			const th = try std.Thread.spawn(.{}, acceptLoop, .{http_fd});
			th.detach();
			acceptLoop(tls_fd);
		},
		// Container enforcer path: ONE normal listener on `base`. An nft REDIRECT
		// (DNAT) funnels both :80 and :443 (and any other diverted port) here;
		// peekClassify distinguishes TLS/HTTP/neither off the first byte, so the
		// base+1 (http) listener is unused. The original destination is recovered
		// from the kernel per connection (originalDst -> SO_ORIGINAL_DST), never
		// from the guest. No IP_TRANSPARENT bind -- that needs NET_ADMIN, which
		// the enforcer deliberately lacks.
		.redirect => {
			const r_fd = try listenFront(ports.tls);

			const la: [4]u8 = @bitCast(std.mem.nativeToBig(u32, listen_addr_host));
			logLine("l7proxy: REDIRECT listener on {d}.{d}.{d}.{d}:{d}; terminate backend 127.0.0.1:{d} ech_probe={s}", .{ la[0], la[1], la[2], la[3], ports.tls, ports.mitm, ech_state });

			acceptLoop(r_fd);
		},
	}
}

// --- signals / reload ---

fn onReloadSignal(_: std.posix.SIG) callconv(.c) void {
	reload_pending.store(true, .release);
}

fn installSignals() void {
	var act: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
	act.handler.handler = onReloadSignal;
	std.posix.sigaction(std.posix.SIG.HUP, &act, null);
	std.posix.sigaction(std.posix.SIG.USR1, &act, null);
}

/// A polled runtime file's cache key -- BOTH halves, for the reason every other
/// reader of these files states (authproxy/conf.zig, l7-mitm-addon.py's
/// `_PolledFile`): a truncate-then-rewrite of the same length inside one
/// timestamp tick moves neither mtime nor ctime at second granularity but moves
/// size, and the nanosecond mtime closes the same-size case.
pub const FileKey = struct { mtime_ns: i128, size: u64 };

/// Stat the OPEN fd (statx on Linux, fstat on Darwin): this file is the one
/// the renderer must NOT rename, so the inode under the path cannot change
/// underneath the two stats and keying on the fd removes the path-resolution
/// TOCTOU the addon's path-based readers have to live with.
fn statKeyOf(fd: c_int) ?FileKey {
	if (!@import("platform").darwin) {
		var sx: std.os.linux.Statx = undefined;
		if (std.os.linux.statx(fd, "", std.posix.AT.EMPTY_PATH, .{ .MTIME = true, .SIZE = true }, &sx) != 0) return null;
		return .{ .mtime_ns = @as(i128, sx.mtime.sec) * std.time.ns_per_s + sx.mtime.nsec, .size = sx.size };
	}
	var st: std.c.Stat = undefined;
	if (std.c.fstat(fd, &st) != 0) return null;
	return .{
		.mtime_ns = @as(i128, st.mtime().sec) * std.time.ns_per_s + @as(i128, st.mtime().nsec),
		.size = @intCast(st.size),
	};
}

/// Read one runtime file the renderer writes TRUNCATE-IN-PLACE, with the polled
/// reader's shape the addon and authproxy/conf.zig already use: stat -> read ->
/// re-stat over (mtime_ns, size), and discard the read if the key moved.
///
/// `netfilter-rules` is the only such file. passt's seccomp-boxed shim holds an
/// fd on it and a rename would strand the shim on the unlinked inode, so it
/// cannot be published atomically (reload.writeRuntimeFileInPlace) -- and this
/// proxy is its SECOND reader, opening by path, driven by a `reload_pending`
/// flag its SIGHUP handler may have taken from an EARLIER render while a later,
/// overlapping one is still inside that window. An empty CIDR set is deny-all
/// egress (RuleSet.evaluate's default), so installing a torn read blackholes the
/// guest until some later render signals again.
///
/// Returns null when the read must be DISCARDED: the caller keeps the set it
/// already installed and re-raises `reload_pending`, so the next accept-loop
/// iteration retries on settled bytes. That retry is not immediate: the loop's
/// poll(..., 1000) bounds one iteration at ~1s, so a discard costs up to a second
/// of the PREVIOUS set standing, and a settled narrowing-to-empty -- which needs
/// two rounds, refuse then install -- up to ~1-2s. Fail-STATIC for that window is
/// the trade, and it is the right one here: the alternative is deny-all egress.
///
/// Two discard conditions for a TEAR, and the second is the one the key alone
/// misses. A reader that lands wholly inside the truncate -- after createFile
/// emptied the file, before the writer's first flush -- sees a STABLE key of
/// (t, 0) across both stats and reads zero bytes. So a zero-length read is
/// discarded too while the caller says its current set came from a file that HAD
/// content.
///
/// But only until the same empty is seen twice, which is what `settle` carries.
/// An instance whose rules legitimately narrow to nothing renders an EMPTY
/// netfilter-rules (renderRules emits nothing for an L4-only config with no
/// rules left), and refusing that forever would pin the previous, WIDER set --
/// the mirror image of the fail-open this reader exists to avoid, and worse,
/// because it would never clear. So: the first empty read is discarded and its
/// key remembered; if the very next read returns the same key, the file is
/// settled-empty and the empty set is installed. A render cannot hold the same
/// mtime_ns across two of our reads -- the whole in-place write is a truncate
/// plus a few KB of writeAll -- so this cannot launder a tear.
///
/// One thing this reader does NOT defend, and the reason the "never installs
/// torn or partial bytes" claim is scoped to a TEAR: a SETTLED file larger than
/// the caller's buffer. readAllInto fills the 16 KiB loadRules gives this file
/// (nf_buf) and stops, so what installs is a PREFIX of the render -- a
/// pre-existing cap, not a tear, and one the key cannot tell from a whole read.
/// The cap stays (16 KiB is ~500 CIDR rules, well past anything the renderer
/// emits in the field) and the truncation is at least the NARROWING direction --
/// an unrendered rule stops being allowed, deny-all being this file's default --
/// but it is no longer SILENT: the first read that hits it is refused with a
/// warning, and the prefix installs on the retry that finds the same key.
/// Refusing it forever is the one thing that would be worse: it would pin the
/// previous, WIDER set with nothing left to clear it, exactly the never-clearing
/// fail-open the settled-empty rule above exists to avoid.
pub fn readPolledInto(
	rt: []const u8,
	name: []const u8,
	buf: []u8,
	prev_had_content: bool,
	settle: *?FileKey,
) ?[]const u8 {
	var path_buf: [4096]u8 = undefined;
	const path = std.fmt.bufPrintZ(&path_buf, "{s}/{s}", .{ rt, name }) catch {
		settle.* = null;
		return buf[0..0];
	};
	const fd = @"open"(path.ptr, O_RDONLY, 0);
	// A missing or unreadable file is NOT a tear: it is the honest empty state
	// (deny-all), exactly as this reader treated it before the hardening.
	if (fd < 0) {
		settle.* = null;
		return buf[0..0];
	}
	defer _ = c.close(fd);

	const k1 = statKeyOf(fd) orelse return null;
	const total = readAllInto(fd, buf);
	const k2 = statKeyOf(fd) orelse return null;
	if (k1.mtime_ns != k2.mtime_ns or k1.size != k2.size) return null;

	// Settled, but bigger than the buffer: refuse once (loudly), install the
	// prefix on the retry. `settle` carries the once-ness for the same reason it
	// does for the empty read -- the key is stable, so nothing else can tell a
	// first sighting from a retry -- and is deliberately LEFT set on the install
	// so a permanently oversized file warns per render, not per poll.
	if (total == buf.len and k1.size > total) {
		if (settle.*) |s| {
			if (s.mtime_ns == k1.mtime_ns and s.size == k1.size) return buf[0..total];
		}
		settle.* = k1;
		// Suppressed under `zig build test` the way the auth proxy's pid lines
		// are: the oversize path HAS a test (reload_test.zig), and a warning on
		// stderr from a passing test is reported by the build runner as an
		// unexpected write.
		if (!@import("builtin").is_test) {
			logLine("l7proxy: netfilter-rules is {d} bytes, over the {d}-byte read buffer; installing the first {d} on the next reload", .{ k1.size, buf.len, total });
		}
		return null;
	}

	if (total == 0 and prev_had_content) {
		if (settle.*) |s| {
			if (s.mtime_ns == k1.mtime_ns and s.size == k1.size) {
				settle.* = null;
				return buf[0..0];
			}
		}
		settle.* = k1;
		return null;
	}
	settle.* = null;
	return buf[0..total];
}

/// readPolledInto's caller-side state for `netfilter-rules`: the byte count the
/// installed CIDR set was parsed from (0 before the first install, and 0 again
/// once a settled-empty file is installed), and the key of a read already refused
/// for a reason the key alone cannot re-check on the retry -- a zero-length read,
/// or one the 16 KiB buffer truncated. Guarded by `rules_lock` like the rulesets
/// themselves -- socks5 mode runs TWO accept loops (one per front-door
/// listener), so two loadRules calls can be in flight at once.
var nf_installed_len: usize = 0;
var nf_settle: ?FileKey = null;

/// Re-read the three wire files this proxy owns. Every read opens BY PATH (not a
/// held fd, unlike passt's seccomp-boxed shim in netfilter/main.zig), so for the
/// two the renderer writes atomically -- l7-rules and l7-inject-hosts -- a reload
/// resolves either the old inode or the new one and neither can be half-written.
///
/// `netfilter-rules` is the EXCEPTION: it is still written truncate-then-rewrite
/// IN PLACE (reload.writeRuntimeFileInPlace), so it goes through readPolledInto
/// instead -- a torn read leaves the previous CIDR set standing and re-raises
/// `reload_pending`, which the accept loop consumes on its next iteration. Render
/// serialisation is no longer what bounds this window.
///
/// The multi-file window survives regardless -- these are three separate files --
/// which is why the renderer still pins its write order (reload.writeWireFiles).
fn loadRules() void {
	const rt = runtime_dir_buf[0..runtime_dir_len];
	var nf_buf: [16384]u8 = undefined;
	var l7_buf: [16384]u8 = undefined;
	var inj_buf: [16384]u8 = undefined;

	// Snapshot the polled reader's state, do the I/O outside the lock (the
	// critical sections here are meant to stay memory-scan short), publish it
	// back below. Two accept loops racing this is bounded: they read the SAME
	// file, so the worst a lost update costs is one extra discard-and-retry.
	lockRules();
	const prev_had_content = nf_installed_len > 0;
	var settle = nf_settle;
	unlockRules();

	const nf = readPolledInto(rt, "netfilter-rules", &nf_buf, prev_had_content, &settle);
	const l7 = readFileInto(rt, "l7-rules", &l7_buf);
	const inj = readFileInto(rt, "l7-inject-hosts", &inj_buf);

	lockRules();
	defer unlockRules();
	nf_settle = settle;
	if (nf) |bytes| {
		cidr_rs = filter.parseRules(bytes);
		nf_installed_len = bytes.len;
	} else {
		// Raised AFTER the accept loop's swap consumed the flag, so it survives
		// to the next iteration rather than being cleared by the caller.
		reload_pending.store(true, .release);
	}
	filter.parseL7Rules(l7, &l7_rs);
	filter.parseInjectHosts(inj, &inject_hosts);
}

fn readFileInto(rt: []const u8, name: []const u8, buf: []u8) []const u8 {
	var path_buf: [4096]u8 = undefined;
	const path = std.fmt.bufPrintZ(&path_buf, "{s}/{s}", .{ rt, name }) catch return buf[0..0];
	const fd = @"open"(path.ptr, O_RDONLY, 0);
	if (fd < 0) return buf[0..0];
	defer _ = c.close(fd);
	return buf[0..readAllInto(fd, buf)];
}

fn readAllInto(fd: c_int, buf: []u8) usize {
	var total: usize = 0;
	while (total < buf.len) {
		const n = c.read(fd, @ptrCast(buf.ptr + total), buf.len - total);
		if (n <= 0) break;
		total += @intCast(n);
	}
	return total;
}

// --- listener / accept ---

// Bind the front-door listener on listen_addr_host:port (default 127.0.0.1; the
// enforcer pod sets 0.0.0.0 via COGBOX_L7_LISTEN_ADDR for cross-pod reach).
fn listenFront(port: u16) !c_int {
	const fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
	if (fd < 0) return error.Socket;
	var one: c_int = 1;
	_ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_REUSEADDR, &one, @sizeOf(c_int));
	var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
	sa.sin_family = c.AF_INET;
	sa.sin_port = std.mem.nativeToBig(u16, port);
	sa.sin_addr.s_addr = std.mem.nativeToBig(u32, listen_addr_host);
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

fn acceptLoop(listen_fd: c_int) void {
	var pfd = [_]c.struct_pollfd{.{ .fd = listen_fd, .events = c.POLLIN, .revents = 0 }};
	while (true) {
		if (reload_pending.swap(false, .acq_rel)) loadRules();
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

// --- per-connection worker ---

pub const Orig = struct { addr: filter.IpAddr, port: u16 };

pub const Classified = union(enum) {
	tls: tls.Sni, // SNI + whether an ECH extension accompanied it
	http: http.Parsed,
	no_sni, // well-formed TLS ClientHello with no cleartext SNI (HTTPS to an IP literal): no vhost to evaluate, L4-gated splice only
	deny,
};

fn worker(client_fd: c_int) void {
	defer _ = c.close(client_fd);
	defer _ = conn_count.fetchSub(1, .monotonic);

	setTimeouts(client_fd);

	// Recover the original dst. socks5 mode reads it from the SOCKS5 CONNECT the
	// shim sent; redirect mode recovers it from the kernel conntrack original
	// tuple via SO_ORIGINAL_DST (never guest-forgeable).
	const orig = switch (accept_mode) {
		.socks5 => socks5Accept(client_fd) orelse return,
		.redirect => originalDst(client_fd) orelse return,
	};

	var buf: [peek_cap]u8 = undefined;
	var out_host: [256]u8 = undefined;
	var out_path: [2048]u8 = undefined;
	var out_sni: [256]u8 = undefined;
	var buffered: usize = 0;

	// Latency heuristic ONLY -- the authoritative gate stays in rawL4Splice under
	// the rules lock. If a raw-L4 splice to this exact orig dst would be allowed
	// anyway (the flow's .deny arm would splice it), cap the classification peek at
	// a short deadline: a silent server-speaks-first client (SSH/SMTP/...) sends no
	// first byte, so classification can't progress and would otherwise stall the
	// full io_timeout_secs before falling through to that same splice. When NOT
	// fast-raw (the dst is reachable only via an L7/hostname rule), classification
	// is the flow's only path forward -- keep the full blocking peek (browsers
	// preconnect idle sockets and send the request seconds later; those must still
	// classify). Rules changing between this snapshot and rawL4Splice's re-check is
	// harmless: this only sets a timeout, it never authorizes a connect.
	var peek_deadline_ms: i32 = 0;
	if (rawL4Eligible(accept_mode, funnel_all)) {
		lockRules();
		const fast_raw = rawL4Allowed(&cidr_rs, orig);
		unlockRules();
		if (fast_raw) peek_deadline_ms = peek_fast_ms;
	}

	const cl = peekClassify(client_fd, &buf, &buffered, &out_host, &out_path, &out_sni, peek_deadline_ms);

	var host: []const u8 = undefined;
	var path: ?[]const u8 = null;
	var method: ?[]const u8 = null;
	var is_tls = false;
	var ech = false;
	switch (cl) {
		.deny => {
			// A flow we can't classify as HTTP/TLS. Eligible for the raw-L4 splice
			// arm when the front door funnels arbitrary ports: redirect mode (the
			// nft REDIRECT hands us any port) OR socks5 + COGBOX_L7_FUNNEL_ALL (the
			// separate-pod enforcer's shim funnels every port over one SOCKS5 hop).
			// Either way the flow is spliced to its orig dst ONLY behind the hard
			// floor + CIDR gate (rawL4Splice). Plain socks5 (VM/launch, no funnel)
			// hard-drops here -- byte-identical to the original proxy.
			if (rawL4Eligible(accept_mode, funnel_all)) {
				rawL4Splice(client_fd, orig, buf[0..buffered], "rawl4-deny");
			} else {
				logReject(orig, "?", "unclassifiable-or-no-sni");
			}
			return;
		},
		.no_sni => {
			// A well-formed ClientHello with no cleartext SNI: HTTPS to an IP literal
			// (RFC 6066 forbids IP literals in server_name), e.g. an appliance with no
			// DNS name. There is no vhost to evaluate, so no L7 rule -- allow or deny
			// by name -- can apply. Splice it to its orig dst iff that dst clears the
			// raw-L4 gate (hard floor + the instance L4 CIDR policy), on EVERY front
			// door and independent of COGBOX_L7_FUNNEL_ALL: this is exactly what the
			// guest may already do to that IP on any non-funneled port, so it is no
			// wider than L4 itself. A malformed hello (.deny) never reaches this arm,
			// nor does an ECH hello with no outer SNI (tls.zig keeps it .deny, so it
			// takes the .deny arm above, not this one: its encrypted inner name
			// could be an L7-denied vhost on this IP).
			rawL4Splice(client_fd, orig, buf[0..buffered], "no-sni-not-l4-allowed");
			return;
		},
		.tls => |s| {
			host = s.name;
			is_tls = true;
			ech = s.ech;
		},
		.http => |p| {
			host = p.host;
			path = p.path;
			method = p.method;
		},
	}
	if (!filter.isValidHostName(host)) {
		logReject(orig, host, "invalid-hostname");
		return;
	}

	lockRules();
	const needs_term = l7_rs.needsTerminate(host);
	const verdict = l7_rs.evaluateFull(host, path, method);
	const needs_inject = inject_hosts.contains(host);
	unlockRules();

	// Route to the terminate backend (mitmproxy + the enforcement/injection
	// addon) when:
	//   - TLS  and the host needs MITM termination (the existing tier choice), OR
	//   - plain HTTP and the host has host-side credential injection configured.
	// The HTTP arm is the credless-injection fix: a plain `http://` vhost
	// otherwise bypasses the addon (the native splice below), so its bearer/
	// cookie would never be stamped. We gate the HTTP arm on `needs_inject` (NOT
	// `needs_term`) deliberately -- under the terminate-by-default tier almost
	// every allowed host "needs terminate", so reusing it would shove ALL plain
	// HTTP through mitmproxy; and a cert-pinned host the operator left in
	// `passthrough` must keep its TLS un-MITM'd. mitmproxy mints a per-SNI leaf
	// (TLS) or speaks plain HTTP (no SNI), and the addon enforces allow/deny +
	// path (+ Host==SNI for TLS); that allow/deny decision is made there, not
	// here -- so we do NOT consult `verdict` on this branch.
	const route_terminate = if (is_tls) needs_term else needs_inject;
	if (route_terminate) {
		terminateHandoff(client_fd, host, orig, buf[0..buffered]);
		return;
	}
	if (verdict == .deny) {
		logReject(orig, host, "l7-deny");
		return;
	}

	// ECH policy. Every TLS flow left here is spliced on its cleartext SNI. An
	// ECH extension means that SNI is the OUTER name and may be a decoy: on a
	// client-facing server that decrypts ECH for many names (a CDN), a real ECH
	// hello can name an allowed outer host while its encrypted inner hello
	// names a denied one, and the splice would carry it there unseen. So an
	// ECH hello is spliced only when the ECH-capability probe (echGate) shows
	// that the very address we connected to, asked with this outer SNI, does
	// not take ECH: RFC 9849 section 7.1 says "If the server is configured
	// with any ECHConfigs, it MUST include the encrypted_client_hello extension
	// in its EncryptedExtensions with the retry_configs field", so a GREASE
	// probe answered by a decrypted EncryptedExtensions without it is evidence
	// that this server instance, right now, holds no ECHConfigs it advertises.
	// Evidence, not proof: a server whose keys are not sent as retry configs
	// (Go SendAsRetry=false, OpenSSL keys loaded no-retry, a split-mode
	// frontend) or a load-balanced frontend whose probe and connection land on
	// different machines can still decrypt real ECH -- the residual
	// docs/network-filtering.md states, accepted on 2026-11-08 when the probe
	// went on by default (the operator's kill switch: COGBOX_L7_ECH_PROBE=0).
	// Everything else (capable, any probe error, a hello the probe cannot
	// mirror, the probe off) is refused, logged reason=ech-on-splice
	// with the outcome and a hint naming the fix. The terminate tier never gets
	// here: mitmproxy is the TLS endpoint and its addon re-checks Host==SNI on
	// the decrypted request, so ECH (GREASE or real) cannot smuggle a different
	// host past it. The gate sits after the l7-deny check (a denied host is
	// refused for that, never probed) and before any dial for a hello the
	// probe would refuse anyway.
	const ech_splice = is_tls and ech;
	var shape: tls.EchShape = undefined;
	if (ech_splice) {
		const refused: ?echprobe.Result = switch (tls.echShape(buf[0..buffered], &shape)) {
			.malformed => .{ .outcome = .unknown, .detail = .ech_malformed },
			.unsupported => .{ .outcome = .unknown, .detail = .ech_unsupported },
			.ok => if (ech_probe_enabled) null else .{ .outcome = .unknown, .detail = .disabled },
		};
		if (refused) |r| {
			logEchReject(orig, host, null, r);
			return;
		}
	}

	// L7 allow SUPERSEDES the L4 CIDR deny-list for the re-resolved IP (still
	// gated by the non-overridable hard floor). A no_match host falls back to
	// the instance L4 policy. Either way the hard floor always applies.
	const supersede_l4 = verdict == .allow;
	const up = dialUpstream(host, orig.port, supersede_l4) orelse {
		logReject(orig, host, "no-vetted-upstream");
		return;
	};
	defer _ = c.close(up.fd);

	// The probe goes to exactly the address the splice is connected to, on the
	// same port, with the guest's outer SNI bytes: no new reach, and nothing
	// learned for one address vouches for another.
	if (ech_splice) {
		const g = echGate(ech_io, up.ip, orig.port, host, &shape);
		if (g.probed) logEchProbe(host, up.ip, orig.port, g);
		if (!echprobe.allowsSplice(g.result)) {
			logEchReject(orig, host, up.ip, g.result);
			return;
		}
	}

	if (!writeAll(up.fd, buf[0..buffered])) return;
	relay(client_fd, up.fd);
}

// --- terminate-tier handoff to the mitmproxy backend ---

fn terminateHandoff(client_fd: c_int, host: []const u8, orig: Orig, buffered: []const u8) void {
	// Pick the first re-resolved address that clears the SSRF floor + instance
	// CIDR policy. vet-then-pin: mitmproxy connects to exactly this IP.
	const vetted = firstVettedAddr(host, orig.port) orelse {
		logReject(orig, host, "no-vetted-upstream");
		return;
	};

	const mfd = connectLoopback(mitm_port) orelse {
		logReject(orig, host, "terminate-backend-down");
		return;
	};
	defer _ = c.close(mfd);
	setTimeouts(mfd);

	// SOCKS5 client to mitmproxy carrying the vetted IP as the CONNECT target.
	if (!socks5ClientHandshake(mfd, vetted, orig.port)) {
		logReject(orig, host, "terminate-socks-failed");
		return;
	}
	if (!writeAll(mfd, buffered)) return;
	relay(client_fd, mfd);
}

/// First resolved address for a terminate host, gated only by the
/// non-overridable hard floor. Terminate hosts always matched an explicit L7
/// `allow` (needsTerminate is true only for matched hosts), so the name allow
/// supersedes the L4 IP deny-list -- same composition as the passthrough
/// `dialUpstream(..., supersede_l4=true)` path. Does NOT connect (the backend does).
fn firstVettedAddr(host: []const u8, port: u16) ?filter.IpAddr {
	_ = port;
	var name_z: [256]u8 = undefined;
	if (host.len >= name_z.len) return null;
	@memcpy(name_z[0..host.len], host);
	name_z[host.len] = 0;

	var hints: c.struct_addrinfo = std.mem.zeroes(c.struct_addrinfo);
	hints.ai_family = c.AF_UNSPEC;
	hints.ai_socktype = c.SOCK_STREAM;

	var res: ?*c.struct_addrinfo = null;
	if (c.getaddrinfo(@ptrCast(&name_z), null, &hints, &res) != 0) return null;
	const list = res orelse return null;
	defer c.freeaddrinfo(list);

	var it: ?*c.struct_addrinfo = list;
	while (it) |ai| : (it = ai.ai_next) {
		const sa = ai.ai_addr orelse continue;
		const ip = sockaddrToIp(sa) orelse continue;
		// Ruleset-aware floor: the built-in set PLUS this instance's
		// `hard-deny` lines (the enclosing host's own addresses). Terminate
		// hosts always matched an explicit allow, so this is the only gate
		// standing between a hostile owner's A record and the host half.
		lockRules();
		const hard = cidr_rs.hardBlocked(ip);
		unlockRules();
		if (hard) continue;
		return ip;
	}
	return null;
}

fn connectLoopback(port: u16) ?c_int {
	const fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
	if (fd < 0) return null;
	var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
	sa.sin_family = c.AF_INET;
	sa.sin_port = std.mem.nativeToBig(u16, port);
	sa.sin_addr.s_addr = std.mem.nativeToBig(u32, 0x7f000001);
	if (c_connect(fd, @ptrCast(&sa), @sizeOf(c.struct_sockaddr_in)) != 0) {
		_ = c.close(fd);
		return null;
	}
	return fd;
}

/// Minimal SOCKS5 CONNECT client (no-auth) used to reach the mitmproxy
/// backend, carrying the vetted upstream IP as the target.
fn socks5ClientHandshake(fd: c_int, ip: filter.IpAddr, port: u16) bool {
	if (!writeAll(fd, &.{ 0x05, 0x01, 0x00 })) return false;
	var sel: [2]u8 = undefined;
	if (!readExact(fd, &sel)) return false;
	if (sel[0] != 0x05 or sel[1] != 0x00) return false;

	var req: [22]u8 = undefined;
	req[0] = 0x05;
	req[1] = 0x01;
	req[2] = 0x00;
	var n: usize = 4;
	switch (ip) {
		.ipv4 => |b| {
			req[3] = 0x01;
			@memcpy(req[4..8], &b);
			n = 8;
		},
		.ipv6 => |b| {
			req[3] = 0x04;
			@memcpy(req[4..20], &b);
			n = 20;
		},
	}
	req[n] = @intCast((port >> 8) & 0xff);
	req[n + 1] = @intCast(port & 0xff);
	n += 2;
	if (!writeAll(fd, req[0..n])) return false;

	var head: [4]u8 = undefined;
	if (!readExact(fd, &head)) return false;
	if (head[0] != 0x05 or head[1] != 0x00) return false;
	const tail_len: usize = switch (head[3]) {
		0x01 => 4 + 2,
		0x04 => 16 + 2,
		0x03 => blk: {
			var lb: [1]u8 = undefined;
			if (!readExact(fd, &lb)) return false;
			break :blk @as(usize, lb[0]) + 2;
		},
		else => return false,
	};
	var tail: [256 + 2]u8 = undefined;
	if (tail_len > tail.len) return false;
	return readExact(fd, tail[0..tail_len]);
}

// --- SOCKS5 server side ---

fn socks5Accept(fd: c_int) ?Orig {
	var greet: [2]u8 = undefined;
	if (!readExact(fd, &greet)) return null;
	if (greet[0] != 0x05) return null;
	const nmethods = greet[1];
	if (nmethods > 0) {
		var methods: [255]u8 = undefined;
		if (!readExact(fd, methods[0..nmethods])) return null;
	}
	if (!writeAll(fd, &.{ 0x05, 0x00 })) return null; // select no-auth

	var rh: [4]u8 = undefined;
	if (!readExact(fd, &rh)) return null;
	if (rh[0] != 0x05 or rh[1] != 0x01) { // VER, CMD=CONNECT
		_ = writeAll(fd, &.{ 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }); // command not supported
		return null;
	}

	var orig: Orig = undefined;
	switch (rh[3]) { // ATYP
		0x01 => {
			var b: [4]u8 = undefined;
			if (!readExact(fd, &b)) return null;
			orig.addr = .{ .ipv4 = b };
		},
		0x04 => {
			var b: [16]u8 = undefined;
			if (!readExact(fd, &b)) return null;
			orig.addr = .{ .ipv6 = b };
		},
		else => {
			// Our shim never sends ATYP 0x03 (domain); refuse.
			_ = writeAll(fd, &.{ 0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });
			return null;
		},
	}
	var pb: [2]u8 = undefined;
	if (!readExact(fd, &pb)) return null;
	orig.port = (@as(u16, pb[0]) << 8) | pb[1];

	// Success: BND.ADDR 0.0.0.0:0. MUST precede the client's app bytes.
	if (!writeAll(fd, &.{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 })) return null;
	return orig;
}

// --- redirect original-destination recovery (kernel-provided, never forgeable) ---

/// Parse a kernel-filled sockaddr into an Orig. v4/TCP-only: any non-AF_INET
/// family returns null and the caller refuses the connection (the v6 guard).
/// The address/port bytes come straight from the kernel's conntrack record of
/// the connection, so a guest cannot forge them. Takes a type-erased pointer
/// (so a test can feed a libc-laid-out sockaddr from its own cImport); the
/// alignment bound matches struct sockaddr_in, the smallest thing read here.
pub fn origFromStorage(ss: *align(@alignOf(c.struct_sockaddr_in)) const anyopaque) ?Orig {
	const sa: *const c.struct_sockaddr = @ptrCast(ss);
	if (sa.sa_family != c.AF_INET) return null;
	const a4: *const c.struct_sockaddr_in = @ptrCast(ss);
	return .{
		.addr = .{ .ipv4 = @bitCast(a4.sin_addr.s_addr) },
		.port = std.mem.bigToNative(u16, a4.sin_port),
	};
}

/// The checked original destination from the SO_ORIGINAL_DST sockaddr. Parses
/// it (v4-only guard) then refuses a loopback result: SO_ORIGINAL_DST returns a
/// loopback dst only when there was no DNAT -- i.e. a direct hit on our own
/// 127.0.0.1 listener (an accept loop) or a guest probe of loopback the REDIRECT
/// must never have funneled here. Both are anti-loop refusals.
pub fn origDstFromStorage(ss: *align(@alignOf(c.struct_sockaddr_in)) const anyopaque) ?Orig {
	const o = origFromStorage(ss) orelse return null;
	if (filter.isLoopback(o.addr)) return null;
	return o;
}

/// Recover the connection's original destination from the kernel conntrack
/// original tuple. redirect mode only. Returns null (refuse) on getsockopt
/// failure, a non-IPv4 family, or a loopback/own-listener dst. The dst is
/// authoritative kernel state -- the guest never supplies it on this path.
fn originalDst(fd: c_int) ?Orig {
	var od: c.struct_sockaddr_storage = std.mem.zeroes(c.struct_sockaddr_storage);
	var od_len: c.socklen_t = @sizeOf(c.struct_sockaddr_storage);
	if (c_getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, @ptrCast(&od), &od_len) != 0) return null;
	return origDstFromStorage(&od);
}

// --- peek + classify ---

fn isHttpStart(b: u8) bool {
	return b >= 'A' and b <= 'Z';
}

/// Peek + classify the client's first app bytes. `deadline_ms > 0` bounds the
/// TOTAL classification time (poll before each recv, .deny on expiry with
/// whatever is buffered) -- the fast path for a raw-L4-eligible silent client.
/// `deadline_ms <= 0` disables it and classification blocks on the socket's own
/// SO_RCVTIMEO, byte-identical to the original behavior (used on the L7/hostname
/// path and by the unit tests that feed a socketpair + EOF).
pub fn peekClassify(
	fd: c_int,
	buf: []u8,
	buffered: *usize,
	out_host: []u8,
	out_path: []u8,
	out_sni: []u8,
	deadline_ms: i32,
) Classified {
	var n: usize = 0;
	const deadline_at: i64 = if (deadline_ms > 0) monotonicMs() + deadline_ms else 0;
	while (true) {
		if (deadline_ms > 0) {
			const now = monotonicMs();
			if (now >= deadline_at) {
				buffered.* = n;
				return .deny;
			}
			const remaining_ms: c_int = @intCast(deadline_at - now); // >= 1 (now < deadline_at)
			var pfd = [_]c.struct_pollfd{.{ .fd = fd, .events = c.POLLIN, .revents = 0 }};
			const pr = c.poll(&pfd, 1, remaining_ms);
			if (pr == 0) { // deadline reached with no readable data -> deny
				buffered.* = n;
				return .deny;
			}
			if (pr < 0) {
				// EINTR (e.g. a SIGHUP reload delivered to this worker thread): retry
				// within the remaining budget. Any other, persistent poll error ->
				// fail closed rather than busy-spin until the deadline.
				if (std.c._errno().* == c.EINTR) continue;
				buffered.* = n;
				return .deny;
			}
		}
		const got = c.recv(fd, @ptrCast(buf.ptr + n), buf.len - n, 0);
		if (got <= 0) {
			buffered.* = n;
			return .deny;
		}
		n += @intCast(got);
		buffered.* = n;

		if (buf[0] == 0x16) {
			switch (tls.extractSni(buf[0..n], out_sni)) {
				.sni => |s| return .{ .tls = s },
				.need_more => if (n >= buf.len) return .deny,
				.no_sni => return .no_sni,
				.deny => return .deny,
			}
		} else if (isHttpStart(buf[0])) {
			// Fail-fast: reject a non-HTTP flow that merely starts with an uppercase
			// byte (an SSH banner) the instant it can't be a request line, instead of
			// waiting out the peek for a "\r\n\r\n" that never comes. Genuine HTTP is
			// .plausible here and parseRequestHead makes the byte-identical decision.
			if (http.requestLinePrecheck(buf[0..n]) == .deny) return .deny;
			switch (http.parseRequestHead(buf[0..n], out_host, out_path)) {
				.ok => |p| return .{ .http = p },
				.need_more => if (n >= buf.len) return .deny,
				.deny => return .deny,
			}
		} else {
			return .deny;
		}
	}
}

// --- upstream dial with SSRF + CIDR re-check ---

/// A connected upstream: the fd and the vetted address it is connected to (the
/// ECH gate probes exactly that address).
const Upstream = struct { fd: c_int, ip: filter.IpAddr };

/// Dial the re-resolved upstream. `supersede_l4` is true when an explicit L7
/// `allow` matched the vhost -- then the only gate is the non-overridable hard
/// floor (the name allow overrides the L4 IP deny-list). When false (the vhost
/// matched no L7 rule), the resolved IP must also pass the instance L4 policy.
fn dialUpstream(host: []const u8, port: u16, supersede_l4: bool) ?Upstream {
	var name_z: [256]u8 = undefined;
	if (host.len >= name_z.len) return null;
	@memcpy(name_z[0..host.len], host);
	name_z[host.len] = 0;

	var hints: c.struct_addrinfo = std.mem.zeroes(c.struct_addrinfo);
	hints.ai_family = c.AF_UNSPEC;
	hints.ai_socktype = c.SOCK_STREAM;

	var res: ?*c.struct_addrinfo = null;
	if (c.getaddrinfo(@ptrCast(&name_z), null, &hints, &res) != 0) return null;
	const list = res orelse return null;
	defer c.freeaddrinfo(list);

	var it: ?*c.struct_addrinfo = list;
	while (it) |ai| : (it = ai.ai_next) {
		const sa = ai.ai_addr orelse continue;
		const ip = sockaddrToIp(sa) orelse continue;

		// Non-overridable hard floor (loopback / this-net / link-local+metadata,
		// plus this instance's `hard-deny` addresses -- the enclosing host's
		// own, which an owner-controlled A record would otherwise turn into a
		// guest-triggered relay into the host half under the proxy's uid).
		// Applies even to an explicitly-allowed vhost.
		lockRules();
		const hard = cidr_rs.hardBlocked(ip);
		unlockRules();
		if (hard) {
			logLine("l7proxy: refusing {s}: resolves into a hard-blocked range (loopback/link-local/metadata/self)", .{host});
			continue;
		}
		// For an unlisted (no_match) vhost, defer to the instance L4 policy. An
		// explicit L7 allow skips this -- the name allow supersedes the IP deny.
		if (!supersede_l4) {
			lockRules();
			const denied = cidr_rs.evaluate(.tcp, ip, port) == .deny;
			unlockRules();
			if (denied) {
				logLine("l7proxy: refusing {s}: unlisted vhost, resolved IP denied by L4 policy", .{host});
				continue;
			}
		}

		// Vet-then-pin: connect to exactly the sockaddr we just vetted.
		if (connectVetted(ai, port, ip)) |up| return up;
	}
	return null;
}

/// Connect to `ai` (whose address is `ip`, already vetted) on `port`.
fn connectVetted(ai: *c.struct_addrinfo, port: u16, ip: filter.IpAddr) ?Upstream {
	var storage: c.struct_sockaddr_storage = std.mem.zeroes(c.struct_sockaddr_storage);
	const alen = ai.ai_addrlen;
	if (alen == 0 or alen > @sizeOf(c.struct_sockaddr_storage)) return null;
	const dst: [*]u8 = @ptrCast(&storage);
	const src: [*]const u8 = @ptrCast(ai.ai_addr.?);
	@memcpy(dst[0..alen], src[0..alen]);

	if (ai.ai_family == c.AF_INET) {
		const sin: *c.struct_sockaddr_in = @ptrCast(@alignCast(&storage));
		sin.sin_port = std.mem.nativeToBig(u16, port);
	} else if (ai.ai_family == c.AF_INET6) {
		const sin6: *c.struct_sockaddr_in6 = @ptrCast(@alignCast(&storage));
		sin6.sin6_port = std.mem.nativeToBig(u16, port);
	} else return null;

	const fd = c.socket(ai.ai_family, c.SOCK_STREAM, 0);
	if (fd < 0) return null;
	setTimeouts(fd);
	if (c_connect(fd, @ptrCast(&storage), alen) != 0) {
		_ = c.close(fd);
		return null;
	}
	return .{ .fd = fd, .ip = ip };
}

// --- raw-L4 splice arm (redirect or socks5+funnel-all) ---

/// Whether an unclassifiable (.deny) flow is eligible for the raw-L4 splice arm
/// (still gated by rawL4Allowed's double check) instead of a hard drop. True for
/// the redirect front door, OR for the socks5 front door when COGBOX_L7_FUNNEL_ALL
/// is set (the separate-pod enforcer, whose shim funnels every port over socks5).
/// FALSE for plain socks5 (the VM/launch path) -> hard drop, byte-identical.
/// Applies to the .deny arm only; a .no_sni hello is L4-gated regardless.
pub fn rawL4Eligible(mode: AcceptMode, funnel: bool) bool {
	return mode == .redirect or funnel;
}

/// The gate for an unclassifiable (non-HTTP/TLS) redirect flow. It may be spliced
/// to its LITERAL kernel-provided orig dst only when BOTH gates pass: the
/// non-overridable SSRF hard floor admits the IP -- the built-in ranges plus
/// this instance's `hard-deny` addresses -- AND the instance's ordered
/// first-match L4 CIDR policy does not deny (tcp, IP, port). Pure + default-deny
/// (an empty/no-match ruleset evaluates to .deny -> false). Deliberately
/// STRICTER than the named splice path: there is no vhost name to `allow`, so
/// the L4 CIDR policy is ALWAYS consulted -- it is never superseded here. This
/// mirrors the in-guest LD_PRELOAD shim, which evaluates the literal connect()
/// destination against the same rule engine.
pub fn rawL4Allowed(rs: *const filter.RuleSet, orig: Orig) bool {
	if (rs.hardBlocked(orig.addr)) return false;
	return rs.evaluate(.tcp, orig.addr, orig.port) != .deny;
}

/// Splice a flow that carries no routable name (an unclassifiable non-HTTP/TLS
/// .deny flow, or a well-formed TLS ClientHello with no SNI) straight to its
/// original destination, from either front door. In redirect mode the dst is
/// the kernel-recovered orig; in socks5 mode it is the CONNECT target the shim
/// sent, which a hostile guest can forge -- so rawL4Allowed is re-checked here
/// under the rules lock and is the only thing that authorizes the dial. NO
/// name -> no re-resolve. Connects only after rawL4Allowed clears both gates;
/// otherwise it logs and drops. deny_reason names the arm in the reject line
/// (`rawl4-deny` for an unclassifiable flow, `no-sni-not-l4-allowed` for a
/// no-SNI hello).
fn rawL4Splice(client_fd: c_int, orig: Orig, buffered: []const u8, deny_reason: []const u8) void {
	lockRules();
	const allowed = rawL4Allowed(&cidr_rs, orig);
	unlockRules();
	if (!allowed) {
		logReject(orig, "?", deny_reason);
		return;
	}

	const up_fd = connectRaw(orig.addr, orig.port) orelse {
		logReject(orig, "?", "rawl4-no-upstream");
		return;
	};
	defer _ = c.close(up_fd);

	if (!writeAll(up_fd, buffered)) return;
	relay(client_fd, up_fd);
}

/// Connect to a literal IP:port (no name resolution). Used only by the raw-L4
/// arm, on an orig dst that already cleared rawL4Allowed. originalDst only ever
/// yields IPv4, but the v6 branch is kept for completeness.
fn connectRaw(addr: filter.IpAddr, port: u16) ?c_int {
	var storage: c.struct_sockaddr_storage = undefined;
	const alen = sockaddrFor(addr, port, &storage);
	const fd = c.socket(familyOf(addr), c.SOCK_STREAM, 0);
	if (fd < 0) return null;
	setTimeouts(fd);
	if (c_connect(fd, @ptrCast(&storage), alen) != 0) {
		_ = c.close(fd);
		return null;
	}
	return fd;
}

fn familyOf(addr: filter.IpAddr) c_int {
	return switch (addr) {
		.ipv4 => c.AF_INET,
		.ipv6 => c.AF_INET6,
	};
}

/// The sockaddr for a literal IP:port, zeroed first; returns its length.
fn sockaddrFor(addr: filter.IpAddr, port: u16, storage: *c.struct_sockaddr_storage) c.socklen_t {
	storage.* = std.mem.zeroes(c.struct_sockaddr_storage);
	switch (addr) {
		.ipv4 => |b| {
			const sa: *c.struct_sockaddr_in = @ptrCast(@alignCast(storage));
			sa.sin_family = c.AF_INET;
			sa.sin_port = std.mem.nativeToBig(u16, port);
			sa.sin_addr.s_addr = @bitCast(b);
			return @sizeOf(c.struct_sockaddr_in);
		},
		.ipv6 => |b| {
			const sa: *c.struct_sockaddr_in6 = @ptrCast(@alignCast(storage));
			sa.sin6_family = c.AF_INET6;
			sa.sin6_port = std.mem.nativeToBig(u16, port);
			@memcpy(@as([*]u8, @ptrCast(&sa.sin6_addr))[0..16], &b);
			return @sizeOf(c.struct_sockaddr_in6);
		},
	}
}

// --- ECH-capability probe: the socket half (echprobe.zig has the protocol) ---

const o_nonblock: c_int = @bitCast(@as(u32, @bitCast(std.c.O{ .NONBLOCK = true })));

/// Connect `fd` to `sa` before `deadline_at_ms` (monotonic): non-blocking
/// connect + poll(POLLOUT) + SO_ERROR, the shape that bounds a dial on both
/// Linux and Darwin (a blocking connect is not bounded by SO_SNDTIMEO on
/// Darwin; see socks5/main.zig connectPolled). Back to blocking afterwards,
/// with SO_RCVTIMEO/SO_SNDTIMEO set to what is left of the deadline as a
/// backstop under probeFd's own polls.
fn connectBounded(fd: c_int, sa: *const c.struct_sockaddr_storage, alen: c.socklen_t, deadline_at_ms: i64) bool {
	const flags = std.c.fcntl(fd, std.c.F.GETFL);
	if (flags < 0) return false;
	if (std.c.fcntl(fd, std.c.F.SETFL, flags | o_nonblock) != 0) return false;
	if (c_connect(fd, @ptrCast(sa), alen) != 0) {
		const e = std.c._errno().*;
		// EINTR leaves a non-blocking connect running in the background, so it
		// is waited for exactly like EINPROGRESS.
		if (e != c.EINPROGRESS and e != c.EINTR) return false;
		while (true) {
			const now = monotonicMs();
			if (now >= deadline_at_ms) return false;
			var pfd = [_]c.struct_pollfd{.{ .fd = fd, .events = c.POLLOUT, .revents = 0 }};
			const pr = c.poll(&pfd, 1, @intCast(@min(deadline_at_ms - now, std.math.maxInt(c_int))));
			if (pr < 0) {
				if (std.c._errno().* == c.EINTR) continue;
				return false;
			}
			if (pr == 0) return false;
			break;
		}
		var so_error: c_int = 0;
		var olen: c.socklen_t = @sizeOf(c_int);
		if (c_getsockopt(fd, c.SOL_SOCKET, c.SO_ERROR, @ptrCast(&so_error), &olen) != 0 or so_error != 0) return false;
	}
	if (std.c.fcntl(fd, std.c.F.SETFL, flags) != 0) return false;
	const now = monotonicMs();
	if (now >= deadline_at_ms) return false;
	const left = deadline_at_ms - now;
	var tv: c.struct_timeval = .{ .tv_sec = @intCast(@divTrunc(left, 1000)), .tv_usec = @intCast(@mod(left, 1000) * 1000) };
	if (c.setsockopt(fd, c.SOL_SOCKET, c.SO_RCVTIMEO, &tv, @sizeOf(c.struct_timeval)) != 0) return false;
	if (c.setsockopt(fd, c.SOL_SOCKET, c.SO_SNDTIMEO, &tv, @sizeOf(c.struct_timeval)) != 0) return false;
	return true;
}

/// Probe one literal ip:port with `sni` and the guest-derived `shape`: a
/// bounded connect, then echprobe.probeFd, all inside `deadline_at_ms`. Callers
/// pass exactly the address a splice dialled (vet-then-pin: no resolution
/// here). Any socket or connect failure, or the deadline, is
/// unknown/connect_failed. The probe fd is always closed.
pub fn echProbeAddr(ip: filter.IpAddr, port: u16, sni: []const u8, shape: *const tls.EchShape, entropy: []const u8, deadline_at_ms: i64) echprobe.Result {
	const failed: echprobe.Result = .{ .outcome = .unknown, .detail = .connect_failed };
	var storage: c.struct_sockaddr_storage = undefined;
	const alen = sockaddrFor(ip, port, &storage);
	const fd = c.socket(familyOf(ip), c.SOCK_STREAM, 0);
	if (fd < 0) return failed;
	defer _ = c.close(fd);
	if (!connectBounded(fd, &storage, alen, deadline_at_ms)) return failed;
	return echprobe.probeFd(fd, sni, shape, entropy, deadline_at_ms);
}

/// One ECH gate decision. `probed` is true only when this call ran a probe
/// (not a cache hit, a wait on another connection's probe, or a refusal before
/// any probe); `ms` is the time the call took.
pub const GateResult = struct { result: echprobe.Result, probed: bool, ms: i64 };

// The proxy-wide probe cache (echGate). Static: no allocator on this path.
var ech_cache: echprobe.Cache = .{};

/// The ECH gate against the proxy-wide cache. Does not log: the worker logs
/// the decision (and one line per real probe).
pub fn echGate(io: std.Io, ip: filter.IpAddr, port: u16, sni: []const u8, shape: *const tls.EchShape) GateResult {
	return echGateWith(&ech_cache, io, ip, port, sni, shape);
}

/// The ECH gate against `cache`: a cached result, or a wait on another
/// connection's probe of the same key (single-flight) or for a free in-flight
/// slot (max_inflight), both bounded by wait_budget_ms, or a fresh probe with
/// fresh entropy. Never cached: busy, pending_timeout, entropy (see
/// echprobe.cacheTtlMs). Pass the result to echprobe.allowsSplice; nothing
/// else decides.
pub fn echGateWith(cache: *echprobe.Cache, io: std.Io, ip: filter.IpAddr, port: u16, sni: []const u8, shape: *const tls.EchShape) GateResult {
	const start = monotonicMs();
	// A shape tls.echShape would not have produced, or an SNI no key can hold,
	// is refused before it can claim a slot.
	const unsupported: GateResult = .{ .result = .{ .outcome = .unknown, .detail = .ech_unsupported }, .probed = false, .ms = 0 };
	if (shape.payload_len == 0 or echprobe.entropyLen(shape) > echprobe.max_entropy_len) return unsupported;
	const key = echprobe.Key.init(ip, port, sni, shape) orelse return unsupported;
	while (true) {
		const now = monotonicMs();
		const claim = cache.lookupOrClaim(&key, now);
		switch (claim) {
			.hit => |r| return .{ .result = r, .probed = false, .ms = now - start },
			// Wait rather than refuse at once: a page load opens many new
			// spliced connections inside one probe RTT, and a burst over the
			// cap should queue. The cap still bounds the probes running.
			.pending, .busy => {
				if (now - start >= echprobe.wait_budget_ms) {
					const d: echprobe.Detail = if (claim == .busy) .busy else .pending_timeout;
					return .{ .result = .{ .outcome = .unknown, .detail = d }, .probed = false, .ms = now - start };
				}
				_ = c.poll(null, 0, 10);
			},
			.claimed => |cl| {
				var entropy_buf: [echprobe.max_entropy_len]u8 = undefined;
				const entropy = entropy_buf[0..echprobe.entropyLen(shape)];
				io.randomSecure(entropy) catch {
					const r: echprobe.Result = .{ .outcome = .unknown, .detail = .entropy };
					cache.complete(cl, &key, r, monotonicMs());
					return .{ .result = r, .probed = false, .ms = monotonicMs() - start };
				};
				const r = echProbeAddr(ip, port, sni, shape, entropy, monotonicMs() + echprobe.probe_deadline_ms);
				const end = monotonicMs();
				cache.complete(cl, &key, r, end);
				return .{ .result = r, .probed = true, .ms = end - start };
			},
		}
	}
}

fn sockaddrToIp(sa: *c.struct_sockaddr) ?filter.IpAddr {
	if (sa.sa_family == c.AF_INET) {
		const a4: *c.struct_sockaddr_in = @ptrCast(@alignCast(sa));
		return .{ .ipv4 = @bitCast(a4.sin_addr.s_addr) };
	} else if (sa.sa_family == c.AF_INET6) {
		const a6: *c.struct_sockaddr_in6 = @ptrCast(@alignCast(sa));
		return .{ .ipv6 = @as(*const [16]u8, @ptrCast(&a6.sin6_addr)).* };
	}
	return null;
}

// --- bidirectional splice ---

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
		if (pr <= 0) return; // error or idle timeout -> tear down

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

const MSG_NOSIGNAL: c_int = c.MSG_NOSIGNAL;

fn writeAll(fd: c_int, buf: []const u8) bool {
	var off: usize = 0;
	while (off < buf.len) {
		const n = c.send(fd, @ptrCast(buf.ptr + off), buf.len - off, MSG_NOSIGNAL);
		if (n <= 0) return false;
		off += @intCast(n);
	}
	return true;
}

fn readExact(fd: c_int, buf: []u8) bool {
	var off: usize = 0;
	while (off < buf.len) {
		const n = c.recv(fd, @ptrCast(buf.ptr + off), buf.len - off, 0);
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

// --- logging (stderr; the launcher redirects it to cogbox.log) ---

fn logLine(comptime fmt: []const u8, args: anytype) void {
	std.debug.print(fmt ++ "\n", args);
}

fn logReject(orig: Orig, host: []const u8, reason: []const u8) void {
	var ipbuf: [46]u8 = undefined;
	const ips = formatIp(orig.addr, &ipbuf);
	std.debug.print("l7proxy: reject host={s} orig={s}:{d} reason={s}\n", .{ host, ips, orig.port, reason });
}

/// The fixed tail of every ech-on-splice line. The client only ever sees a
/// closed connection (Chromium: ERR_CONNECTION_CLOSED), so the log has to name
/// ECH and both fixes. Logged in double quotes, so it holds none.
pub const ech_reject_hint = "client sent an Encrypted ClientHello (ECH, GREASE included) to a host spliced on its cleartext SNI; turn ECH off in the client (Chromium policy EncryptedClientHelloEnabled=false, Playwright channel chromium) or have the host terminated (listed under allowed hosts, not passthrough)";
comptime {
	std.debug.assert(std.mem.indexOfScalar(u8, ech_reject_hint, '"') == null);
}

/// The splice-tier ECH refusal: `reason=ech-on-splice` (the token tests and
/// operators grep for) plus the gate's outcome and detail, the address the
/// gate probed (`upstream=-` when the hello was refused before any dial) and
/// ech_reject_hint, quoted so a key=value reader sees where it ends.
fn logEchReject(orig: Orig, host: []const u8, upstream: ?filter.IpAddr, r: echprobe.Result) void {
	var ipbuf: [46]u8 = undefined;
	const ips = formatIp(orig.addr, &ipbuf);
	var upbuf: [64]u8 = undefined;
	const ups = if (upstream) |ip| formatIpPort(ip, orig.port, &upbuf) else "-";
	var alertbuf: [16]u8 = undefined;
	std.debug.print("l7proxy: reject host={s} orig={s}:{d} reason=ech-on-splice ech={s} detail={s}{s} upstream={s} hint=\"{s}\"\n", .{ host, ips, orig.port, echprobe.outcomeName(r.outcome), echprobe.detailName(r.detail), alertField(r, &alertbuf), ups, ech_reject_hint });
}

/// One line per probe the gate actually ran (not per cache hit or wait).
fn logEchProbe(sni: []const u8, ip: filter.IpAddr, port: u16, g: GateResult) void {
	var upbuf: [64]u8 = undefined;
	var alertbuf: [16]u8 = undefined;
	std.debug.print("l7proxy: ech-probe host={s} upstream={s} result={s} detail={s}{s} ms={d}\n", .{ sni, formatIpPort(ip, port, &upbuf), echprobe.outcomeName(g.result.outcome), echprobe.detailName(g.result.detail), alertField(g.result, &alertbuf), g.ms });
}

/// ` alert=<n>` for an alert outcome, else empty.
fn alertField(r: echprobe.Result, buf: []u8) []const u8 {
	if (r.detail != .alert) return "";
	return std.fmt.bufPrint(buf, " alert={d}", .{r.alert}) catch "";
}

fn formatIpPort(addr: filter.IpAddr, port: u16, buf: []u8) []const u8 {
	var ipbuf: [46]u8 = undefined;
	return std.fmt.bufPrint(buf, "{s}:{d}", .{ formatIp(addr, &ipbuf), port }) catch "?";
}

fn formatIp(addr: filter.IpAddr, buf: []u8) []const u8 {
	return switch (addr) {
		.ipv4 => |ip| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "?",
		.ipv6 => "v6",
	};
}
