const std = @import("std");

pub const Action = enum {
	allow,
	deny,
};

pub const Proto = enum {
	any,
	tcp,
	udp,
};

pub const IpAddr = union(enum) {
	ipv4: [4]u8,
	ipv6: [16]u8,
};

pub const Rule = struct {
	proto: Proto = .any,
	network: IpAddr,
	prefix_len: u8,
	port: u16 = 0, // 0 == "any port"
	action: Action,
};

pub const RemapTarget = struct {
	proto: Proto, // tcp or udp; never .any
	addr: IpAddr,
	port: u16,
};

pub const RemapRule = struct {
	proto: Proto, // must be tcp or udp (no .any)
	network: IpAddr,
	prefix_len: u8,
	port: u16, // explicit; 0 disallowed
	target: RemapTarget,
};

pub const max_rules = 256;
pub const max_remap_rules = 64;
pub const max_dns_rules = 256;
pub const max_dns_pattern_len: u8 = 253; // RFC 1035 FQDN length cap
// Per-instance additions to the L7 proxy's hard floor (`hard-deny <cidr>`).
// A VM has one or two of its own addresses, so this is deliberately small.
pub const max_hard_rules = 16;

pub const DnsPatternKind = enum { exact, left_wildcard, any };

pub const DnsPattern = struct {
	kind: DnsPatternKind,
	buf: [max_dns_pattern_len]u8 = undefined,
	len: u8 = 0,

	pub fn slice(self: *const DnsPattern) []const u8 {
		return self.buf[0..self.len];
	}
};

pub const DnsRule = struct {
	pattern: DnsPattern,
	action: Action,
};

/// One `hard-deny <cidr>` line: a per-instance addition to the L7 proxy's
/// non-overridable hard floor (see `isHardBlocked` / `RuleSet.hardBlocked`).
pub const HardRule = struct {
	network: IpAddr,
	prefix_len: u8,
};

pub const RuleSet = struct {
	rules: [max_rules]Rule = undefined,
	len: usize = 0,

	// Remap rules consulted by the shim's TCP connect() wrapper to
	// rewrite outbound destinations. Walked AFTER the CIDR allow/deny
	// pass, so a remap hit implicitly says "allow but divert".
	remap_rules: [max_remap_rules]RemapRule = undefined,
	remap_len: usize = 0,

	// DNS rules consulted by the libc-resolver wrappers in the shim.
	// Independent of CIDR rules: a DNS allow does not imply IP allow.
	dns_rules: [max_dns_rules]DnsRule = undefined,
	dns_len: usize = 0,
	dns_default: Action = .allow,

	// Per-instance extension of the L7 proxy's hard floor, from `hard-deny`
	// lines. Empty by default: an instance that renders no `hard-deny` line
	// gets exactly `isHardBlocked`'s floor, as before.
	hard_rules: [max_hard_rules]HardRule = undefined,
	hard_len: usize = 0,

	// The implicit port-53 allow below. TRUE preserves the historical
	// behavior (DNS to any destination escapes the rule walk, which is what
	// makes a loopback resolver like 127.0.0.53 usable); a `no-implicit-dns`
	// line turns it off so the seeded link-local/RFC1918 denies apply to DNS
	// too. Hosts whose resolver IS the cloud metadata address (GCE, where the
	// VPC resolver is 169.254.169.254) must turn it off or port 53 is an
	// unfiltered egress path.
	implicit_dns_allow: bool = true,

	// The enclosing host's own DNS forwarder, from a `dns-host <addr>` line.
	// null by default, so an instance that renders no such line evaluates
	// exactly as it did before this field existed.
	//
	// It exists because `no-implicit-dns` and passt's `--dns-forward` are only
	// usable TOGETHER. `--dns-forward <X>` makes passt intercept the guest's
	// queries to X and re-emit them host-side to its `--dns-host` address --
	// which is the whole point on a host whose real resolver is an address the
	// guest must not reach: the guest's DNS then terminates at a LOOPBACK
	// forwarder on the trusted half, and resolves exactly what the host
	// resolves. But that re-emitted socket is an ordinary loopback connect made
	// by passt, so with the implicit port-53 allow off it hits the loopback deny
	// below and guest DNS dies silently.
	//
	// The exception is therefore address- AND port-scoped to that one socket: it
	// is NOT a port-53 pass (that is what `no-implicit-dns` removed, and what
	// would restore an arbitrary-destination DNS tunnel past every seeded deny),
	// and it is not a loopback pass (127.0.0.1:<l7base+2>, the mitmproxy SOCKS5
	// hop, stays denied like the rest of loopback). One address, port 53.
	dns_host: ?IpAddr = null,

	/// Evaluate a destination (proto, addr, port) against the CIDR rules.
	/// Callers that don't know the protocol may pass `.any`; rules with an
	/// explicit proto qualifier won't match a `.any` query.
	pub fn evaluate(self: *const RuleSet, proto: Proto, addr: IpAddr, port: u16) Action {
		// Implicit: allow DNS (port 53) -- checked first so DNS to
		// loopback resolvers (e.g. 127.0.0.53 systemd-resolved) works.
		// Parameterized: `no-implicit-dns` removes the short-circuit so DNS
		// walks the ordered rules like every other port.
		if (port == 53 and self.implicit_dns_allow) return .allow;

		// The one exception to the loopback deny below: the host's own DNS
		// forwarder, on port 53 and at that exact address. See `dns_host`.
		if (port == 53) {
			if (self.dns_host) |h| {
				if (addrEquals(h, addr)) return .allow;
			}
		}

		// Implicit: deny loopback -- passt maps its gateway and the
		// host's IP to 127.0.0.1, so allowing loopback would expose
		// all host services to the sandbox. The remap path bypasses
		// this check because it never calls evaluate() against the
		// rewritten destination.
		if (isLoopback(addr)) return .deny;

		const check_addr = normalizeMapped(addr);

		// Walk user rules in order, first match wins
		for (self.rules[0..self.len]) |rule| {
			if (ruleMatches(rule, proto, check_addr, port)) {
				return rule.action;
			}
		}

		// Default: deny
		return .deny;
	}

	/// If a remap rule matches the (proto, addr, port) tuple, return its
	/// target. Otherwise null. Caller is expected to have already passed
	/// the CIDR check -- this method does not consult `rules`.
	pub fn evaluateRemap(self: *const RuleSet, proto: Proto, addr: IpAddr, port: u16) ?RemapTarget {
		const check_addr = normalizeMapped(addr);
		for (self.remap_rules[0..self.remap_len]) |r| {
			if (remapMatches(r, proto, check_addr, port)) return r.target;
		}
		return null;
	}

	/// The L7 proxy's hard floor for THIS instance: the built-in
	/// `isHardBlocked` set plus every `hard-deny` CIDR. The built-in set is
	/// topology-independent (loopback / this-net / link-local), but the
	/// enclosing host's OWN addresses are not knowable at build time -- and an
	/// explicit L7 `allow` supersedes the L4 CIDR re-check, so without this a
	/// sandbox owner could point an A record they control at the machine
	/// running the proxy and get a guest-triggered connection back into it
	/// under the proxy's uid. Prefer this over `isHardBlocked` on every
	/// production dial path; the bare function survives for callers with no
	/// ruleset in hand.
	pub fn hardBlocked(self: *const RuleSet, addr: IpAddr) bool {
		if (isHardBlocked(addr)) return true;
		const a = normalizeMapped(addr);
		for (self.hard_rules[0..self.hard_len]) |h| {
			if (cidrContains(h.network, h.prefix_len, a)) return true;
		}
		return false;
	}

	/// Evaluate a hostname against the DNS rule table. The host may carry a
	/// trailing `.` (root label) -- it is stripped before matching.
	pub fn evaluateDns(self: *const RuleSet, host: []const u8) Action {
		var h = host;
		if (h.len > 0 and h[h.len - 1] == '.') h = h[0 .. h.len - 1];
		for (self.dns_rules[0..self.dns_len]) |r| {
			if (matchDnsPattern(r.pattern, h)) return r.action;
		}
		return self.dns_default;
	}
};

fn matchDnsPattern(p: DnsPattern, host: []const u8) bool {
	switch (p.kind) {
		.any => return true,
		.exact => return std.ascii.eqlIgnoreCase(p.slice(), host),
		.left_wildcard => {
			const suffix = p.slice();
			// `*.example.com` must match >=1 subdomain label, so the host
			// needs at least one char and a `.` before the suffix.
			if (host.len <= suffix.len + 1) return false;
			const sep_idx = host.len - suffix.len - 1;
			if (host[sep_idx] != '.') return false;
			return std.ascii.eqlIgnoreCase(host[sep_idx + 1 ..], suffix);
		},
	}
}

/// Validate a hostname-shaped string. Permissive enough for real-world
/// names (LDH labels), strict enough to reject empty labels, leading/
/// trailing dots, and stray punctuation.
pub fn isValidHostName(s: []const u8) bool {
	if (s.len == 0 or s.len > max_dns_pattern_len) return false;
	if (s[0] == '.' or s[s.len - 1] == '.') return false;
	var prev_dot = true;
	for (s) |c| {
		switch (c) {
			'a'...'z', 'A'...'Z', '0'...'9', '_' => prev_dot = false,
			'-' => {
				if (prev_dot) return false; // label can't start with hyphen
				prev_dot = false;
			},
			'.' => {
				if (prev_dot) return false; // empty label
				prev_dot = true;
			},
			else => return false,
		}
	}
	return true;
}

/// Parse a DNS pattern. Returns null for malformed input.
///   `*`             -> .any
///   `*.example.com` -> .left_wildcard("example.com")
///   `example.com`   -> .exact("example.com")
///   anything with `*` not at the leftmost position is rejected.
pub fn parseDnsPattern(s: []const u8) ?DnsPattern {
	const t = std.mem.trim(u8, s, " \t");
	if (t.len == 0) return null;
	if (std.mem.eql(u8, t, "*")) {
		return .{ .kind = .any, .len = 0 };
	}
	if (std.mem.startsWith(u8, t, "*.")) {
		const rest = t[2..];
		if (std.mem.indexOfScalar(u8, rest, '*') != null) return null;
		if (!isValidHostName(rest)) return null;
		var p: DnsPattern = .{ .kind = .left_wildcard, .len = @intCast(rest.len) };
		@memcpy(p.buf[0..rest.len], rest);
		return p;
	}
	if (std.mem.indexOfScalar(u8, t, '*') != null) return null; // right-anchor or middle
	if (!isValidHostName(t)) return null;
	var p: DnsPattern = .{ .kind = .exact, .len = @intCast(t.len) };
	@memcpy(p.buf[0..t.len], t);
	return p;
}

pub const DnsLine = struct {
	action: Action,
	pattern: DnsPattern,
};

/// Parse a single `dns ...` line body (i.e. text after the `dns ` prefix).
/// Recognises:
///   `default allow` / `default deny`  -> returns null + writes to *default_out (if non-null)
///   `allow PATTERN` / `deny PATTERN`  -> returns DnsLine
/// Returns null on malformed input, on the `default` form, or on empty input.
pub fn parseDnsBody(body: []const u8, default_out: ?*Action) ?DnsLine {
	const t = std.mem.trim(u8, body, " \t");
	if (t.len == 0) return null;
	if (std.mem.startsWith(u8, t, "default ")) {
		const v = std.mem.trim(u8, t[8..], " \t");
		if (default_out) |out| {
			if (std.mem.eql(u8, v, "allow")) out.* = .allow;
			if (std.mem.eql(u8, v, "deny")) out.* = .deny;
		}
		return null;
	}
	var action: Action = undefined;
	var rest: []const u8 = undefined;
	if (std.mem.startsWith(u8, t, "allow ")) {
		action = .allow;
		rest = t[6..];
	} else if (std.mem.startsWith(u8, t, "deny ")) {
		action = .deny;
		rest = t[5..];
	} else {
		return null;
	}
	const pat = parseDnsPattern(rest) orelse return null;
	return .{ .action = action, .pattern = pat };
}

const ipv6_loopback = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const ipv4_mapped_prefix = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

pub fn isIpv4Mapped(ip: [16]u8) bool {
	return std.mem.eql(u8, ip[0..12], &ipv4_mapped_prefix);
}

fn normalizeMapped(addr: IpAddr) IpAddr {
	return switch (addr) {
		.ipv6 => |ip| if (isIpv4Mapped(ip))
			.{ .ipv4 = .{ ip[12], ip[13], ip[14], ip[15] } }
		else
			addr,
		.ipv4 => addr,
	};
}

/// Exact address equality, v4-mapped-v6 normalized on both sides. Used by the
/// `dns_host` exception, which must match ONE address rather than a prefix (a
/// prefix there would be a loopback carve-out, not a socket carve-out), and by
/// `replySendAllowed` for the same one-socket reason.
pub fn addrEquals(a: IpAddr, b: IpAddr) bool {
	return switch (normalizeMapped(a)) {
		.ipv4 => |x| switch (normalizeMapped(b)) {
			.ipv4 => |y| std.mem.eql(u8, &x, &y),
			.ipv6 => false,
		},
		.ipv6 => |x| switch (normalizeMapped(b)) {
			.ipv6 => |y| std.mem.eql(u8, &x, &y),
			.ipv4 => false,
		},
	};
}

/// True for loopback destinations (127.0.0.0/8, ::1, and the IPv4-mapped
/// form of 127/8). Lifted out of `evaluate()` so the shim's connect()
/// reorder can reuse it: a remap rule's broad LHS (e.g. 0.0.0.0/0:443)
/// must NOT divert the guest's own loopback probes.
pub fn isLoopback(addr: IpAddr) bool {
	return switch (normalizeMapped(addr)) {
		.ipv4 => |ip| ip[0] == 127,
		.ipv6 => |ip| std.mem.eql(u8, &ip, &ipv6_loopback),
	};
}

// --- passt inbound-flow reply sockets (the mosh UDP forward) ---
//
// Pure helpers behind the shim's ONE exemption from the default deny. passt
// serves a datagram arriving at a `-u <addr>/lo-hi` listener by opening a
// per-flow socket bound to the datagram's destination (PKTINFO dst, i.e. the
// listener's own address and port) and connect()ing it to the sender; the
// guest's replies then leave through sendmmsg() on that socket with the
// sender as explicit msg_name. Under the default deny that connect() fails
// ("Couldn't connect flow socket"), so an inbound UDP forward is dead unless
// the shim can tell such a socket apart from one the guest opened.

/// One endpoint (address + port). The shim records a connected UDP socket's
/// peer in this shape and compares send destinations against it.
pub const Endpoint = struct {
	addr: IpAddr,
	port: u16,
};

/// A closed port interval, as carried by `COGBOX_MOSH_UDP_FORWARD=lo-hi`.
pub const PortRange = struct {
	lo: u16,
	hi: u16,

	pub fn contains(self: PortRange, p: u16) bool {
		return p >= self.lo and p <= self.hi;
	}
};

/// Parse exactly `<digits>-<digits>`, each 1..65535, lo <= hi. Every other
/// shape (empty, `lo:hi`, spaces, a bare port, a sign, zero, > 65535) is
/// null: a malformed knob leaves the exemption OFF rather than guessing.
pub fn parsePortRange(s: []const u8) ?PortRange {
	const dash = std.mem.indexOfScalar(u8, s, '-') orelse return null;
	const lo = parseStrictPort(s[0..dash]) orelse return null;
	const hi = parseStrictPort(s[dash + 1 ..]) orelse return null;
	if (lo > hi) return null;
	return .{ .lo = lo, .hi = hi };
}

/// Decimal digits only (std.fmt.parseInt would also take a sign and `_`
/// separators), 1..65535.
fn parseStrictPort(s: []const u8) ?u16 {
	if (s.len == 0 or s.len > 5) return null;
	for (s) |ch| {
		if (ch < '0' or ch > '9') return null;
	}
	const v = std.fmt.parseInt(u32, s, 10) catch return null;
	if (v == 0 or v > 65535) return null;
	return @intCast(v);
}

/// True iff `addr:port` -- the LOCAL address of a socket, as getsockname()
/// reports it at connect() time -- is one of passt's inbound-flow reply
/// sockets for the forward: the port sits inside `range` AND the address is
/// a specific, non-loopback unicast address (v4-mapped v6 judged as v4).
///
/// The address half is what keeps guest-originated traffic out: passt binds
/// a guest-originated UDP flow to the UNSPECIFIED address with the guest's
/// source port preserved (fwd_nat_from_tap sets oaddr = addr_out, which stays
/// unspecified because the launcher never passes -o/--outbound-addr, and
/// oport = the guest sport; sock_l4 then bind()s exactly that), so a guest
/// picking a source port inside the range still fails here. Only the socket
/// passt opens for a datagram that ARRIVED at a `-u` listener carries that
/// listener's address (udp_flow_from_sock -> flow_initiate_sa with the
/// PKTINFO destination). The port check lives here so a caller cannot forget
/// it.
pub fn isForwardReplyLocal(addr: IpAddr, port: u16, range: PortRange) bool {
	if (!range.contains(port)) return false;
	if (isLoopback(addr)) return false;
	return switch (normalizeMapped(addr)) {
		// not 0.0.0.0, not multicast/reserved/broadcast (224.0.0.0/3)
		.ipv4 => |ip| !std.mem.eql(u8, &ip, &[4]u8{ 0, 0, 0, 0 }) and ip[0] < 224,
		// not ::, not multicast (ff00::/8)
		.ipv6 => |ip| !std.mem.eql(u8, &ip, &([_]u8{0} ** 16)) and ip[0] != 0xff,
	};
}

/// Pure decision behind the shim's send-path half of the exemption. `exempt`
/// is what connect() recorded via isForwardReplyLocal and `peer` the address
/// it was connected to. A NULL destination sends to the connected peer by
/// definition; an explicit destination is exempt only when it IS that peer
/// (v4-mapped normalized). Anything else falls back to the ruleset walk, so
/// an exempt fd cannot be steered at a third party.
pub fn replySendAllowed(exempt: bool, peer: ?Endpoint, dest: ?Endpoint) bool {
	if (!exempt) return false;
	const p = peer orelse return false;
	const d = dest orelse return true;
	return d.port == p.port and addrEquals(d.addr, p.addr);
}

// The L7 proxy's NON-OVERRIDABLE hard floor: addresses it must never dial no
// matter what the instance rules say. The proxy runs OUTSIDE the LD_PRELOAD
// shim, so its host-side getaddrinfo()+connect() faces no L4 policy except
// what we enforce here plus the instance CIDR re-check.
//
// This floor is deliberately MINIMAL -- only targets that are never a
// legitimate egress destination and are the classic SSRF pivots: loopback,
// "this-network", and link-local (which includes cloud metadata
// 169.254.169.254). Private ranges (RFC1918 / CGNAT / ULA) are NOT here: they
// are blocked by the instance's seeded default-deny rules, but a user can
// legitimately reach an internal vhost on a private LB by adding an explicit
// `allow` -- exactly as they would for a direct L4 connection. Deferring those
// to the CIDR re-check makes the proxy's egress identical to L4 for them,
// rather than strictly more restrictive.
const hard_blocked_v4 = [_]struct { net: [4]u8, prefix: u8 }{
	.{ .net = .{ 0, 0, 0, 0 }, .prefix = 8 }, // "this network" (0.0.0.0/8, localhost alias on Linux)
	.{ .net = .{ 127, 0, 0, 0 }, .prefix = 8 }, // loopback
	.{ .net = .{ 169, 254, 0, 0 }, .prefix = 16 }, // link-local incl. cloud metadata 169.254.169.254
};

/// True if the L7 proxy must refuse to dial this resolved address regardless
/// of instance rules. Folds IPv4-mapped IPv6 into IPv4 first so
/// `::ffff:169.254.169.254` is caught. Private ranges are intentionally NOT
/// hard-blocked -- they are governed by the instance CIDR policy (see above).
///
/// This is the TOPOLOGY-INDEPENDENT half of the floor. The enclosing host's own
/// addresses are not knowable at build time and are carried per instance as
/// `hard-deny` lines; production dial paths call `RuleSet.hardBlocked`, which is
/// this set plus those. Callers with no ruleset in hand may still use this.
pub fn isHardBlocked(addr: IpAddr) bool {
	switch (normalizeMapped(addr)) {
		.ipv4 => |ip| {
			for (hard_blocked_v4) |b| {
				if (ipv4Matches(b.net, ip, b.prefix)) return true;
			}
			return false;
		},
		.ipv6 => |ip| {
			if (std.mem.eql(u8, &ip, &ipv6_loopback)) return true; // ::1
			if (std.mem.eql(u8, &ip, &([_]u8{0} ** 16))) return true; // :: unspecified
			if (ip[0] == 0xfe and (ip[1] & 0xc0) == 0x80) return true; // fe80::/10 link-local
			return false;
		},
	}
}

fn cidrContains(network: IpAddr, prefix_len: u8, addr: IpAddr) bool {
	return switch (network) {
		.ipv4 => |net| switch (addr) {
			.ipv4 => |ip| ipv4Matches(net, ip, prefix_len),
			.ipv6 => false,
		},
		.ipv6 => |net| switch (addr) {
			.ipv6 => |ip| ipv6Matches(net, ip, prefix_len),
			.ipv4 => false,
		},
	};
}

fn cidrMatches(rule: Rule, addr: IpAddr) bool {
	return cidrContains(rule.network, rule.prefix_len, addr);
}

fn ruleMatches(rule: Rule, proto: Proto, addr: IpAddr, port: u16) bool {
	if (rule.proto != .any and rule.proto != proto) return false;
	if (rule.port != 0 and rule.port != port) return false;
	return cidrContains(rule.network, rule.prefix_len, addr);
}

fn remapMatches(r: RemapRule, proto: Proto, addr: IpAddr, port: u16) bool {
	if (r.proto != proto) return false;
	if (r.port != port) return false;
	return cidrContains(r.network, r.prefix_len, addr);
}

fn ipv4Matches(net: [4]u8, ip: [4]u8, prefix_len: u8) bool {
	if (prefix_len == 0) return true;
	if (prefix_len > 32) return false;
	if (prefix_len == 32) return std.mem.eql(u8, &net, &ip);

	const net_u32 = std.mem.readInt(u32, &net, .big);
	const ip_u32 = std.mem.readInt(u32, &ip, .big);
	const shift: u5 = @intCast(32 - prefix_len);
	const mask: u32 = ~@as(u32, 0) << shift;
	return (net_u32 & mask) == (ip_u32 & mask);
}

fn ipv6Matches(net: [16]u8, ip: [16]u8, prefix_len: u8) bool {
	if (prefix_len == 0) return true;
	if (prefix_len > 128) return false;

	const full_bytes: usize = prefix_len / 8;
	const remaining_bits: u3 = @intCast(prefix_len % 8);

	if (!std.mem.eql(u8, net[0..full_bytes], ip[0..full_bytes])) return false;

	if (remaining_bits > 0 and full_bytes < 16) {
		const shift: u3 = @intCast(8 - @as(u4, remaining_bits));
		const mask: u8 = ~@as(u8, 0) << shift;
		if ((net[full_bytes] & mask) != (ip[full_bytes] & mask)) return false;
	}

	return true;
}

/// Parse a single allow/deny rule line. Accepted forms:
///   allow|deny CIDR                       (proto=any, port=any)
///   allow|deny tcp|udp CIDR               (port=any)
///   allow|deny CIDR:PORT                  (proto=any)
///   allow|deny tcp|udp CIDR:PORT
/// IPv6 CIDRs are matched port-less only; `:PORT` suffixes are IPv4-only in v1.
pub fn parseLine(line: []const u8) ?Rule {
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	if (trimmed.len == 0 or trimmed[0] == '#') return null;

	var action: Action = undefined;
	var rest: []const u8 = undefined;

	if (std.mem.startsWith(u8, trimmed, "allow ")) {
		action = .allow;
		rest = trimmed[6..];
	} else if (std.mem.startsWith(u8, trimmed, "deny ")) {
		action = .deny;
		rest = trimmed[5..];
	} else {
		return null;
	}

	const pcp = parseProtoCidrPort(rest, .{ .require_cidr_slash = true }) orelse return null;
	return .{
		.proto = pcp.proto,
		.network = pcp.network,
		.prefix_len = pcp.prefix_len,
		.port = pcp.port,
		.action = action,
	};
}

const ProtoCidrPort = struct {
	proto: Proto,
	network: IpAddr,
	prefix_len: u8,
	port: u16, // 0 == not specified
};

const ParseOpts = struct {
	require_proto: bool = false,
	require_cidr_slash: bool = false,
};

/// Parse the trailing form `[tcp|udp ] CIDR[:port]`. When
/// `require_cidr_slash` is false, a bare IP without `/N` defaults to /32
/// (useful for remap targets).
fn parseProtoCidrPort(s: []const u8, opts: ParseOpts) ?ProtoCidrPort {
	var rest = std.mem.trim(u8, s, " \t");

	var proto: Proto = .any;
	if (std.mem.startsWith(u8, rest, "tcp ")) {
		proto = .tcp;
		rest = std.mem.trim(u8, rest[4..], " \t");
	} else if (std.mem.startsWith(u8, rest, "udp ")) {
		proto = .udp;
		rest = std.mem.trim(u8, rest[4..], " \t");
	}
	if (opts.require_proto and proto == .any) return null;

	// IPv6 path: any textual IPv6 address carries >=2 colons. v1 supports
	// PORT-LESS IPv6 CIDRs only (used for the L7 v6 fail-closed denies, e.g.
	// `deny tcp ::/0`); bracketed IPv6+port is not supported.
	if (std.mem.count(u8, rest, ":") >= 2) {
		var prefix6: u8 = 128;
		var ip6_str: []const u8 = rest;
		if (std.mem.indexOfScalar(u8, rest, '/')) |sp| {
			ip6_str = rest[0..sp];
			prefix6 = std.fmt.parseInt(u8, rest[sp + 1 ..], 10) catch return null;
		} else if (opts.require_cidr_slash) {
			return null;
		}
		if (prefix6 > 128) return null;
		const ipv6 = parseIpv6(ip6_str) orelse return null;
		return .{ .proto = proto, .network = .{ .ipv6 = ipv6 }, .prefix_len = prefix6, .port = 0 };
	}

	// Split off `:port` if present. The IPv4 path treats any single colon as
	// the port separator.
	var addr_part: []const u8 = rest;
	var port: u16 = 0;
	if (std.mem.indexOfScalar(u8, rest, ':')) |colon| {
		// If there's more than one colon (IPv6 textual form), bail out.
		if (std.mem.lastIndexOfScalar(u8, rest, ':').? != colon) return null;
		addr_part = rest[0..colon];
		const port_str = std.mem.trim(u8, rest[colon + 1 ..], " \t");
		port = std.fmt.parseInt(u16, port_str, 10) catch return null;
		if (port == 0) return null; // port 0 reserved for "any"
	}

	var prefix_len: u8 = 32;
	var ip_str: []const u8 = addr_part;
	if (std.mem.indexOfScalar(u8, addr_part, '/')) |sp| {
		ip_str = addr_part[0..sp];
		prefix_len = std.fmt.parseInt(u8, addr_part[sp + 1 ..], 10) catch return null;
	} else if (opts.require_cidr_slash) {
		return null;
	}
	if (prefix_len > 32) return null;

	const ipv4 = parseIpv4(ip_str) orelse return null;
	return .{
		.proto = proto,
		.network = .{ .ipv4 = ipv4 },
		.prefix_len = prefix_len,
		.port = port,
	};
}

/// Parse a single `remap` rule line:
///   remap PROTO CIDR:PORT -> PROTO IP[:PORT]
/// v1 restricts both sides to `tcp` and remap targets to single hosts
/// (/32). Returns null for malformed input.
pub fn parseRemapLine(line: []const u8) ?RemapRule {
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	if (trimmed.len == 0 or trimmed[0] == '#') return null;
	if (!std.mem.startsWith(u8, trimmed, "remap ")) return null;
	const body = trimmed[6..];

	const arrow = std.mem.indexOf(u8, body, "->") orelse return null;
	const lhs = std.mem.trim(u8, body[0..arrow], " \t");
	const rhs = std.mem.trim(u8, body[arrow + 2 ..], " \t");

	const lhs_p = parseProtoCidrPort(lhs, .{ .require_proto = true, .require_cidr_slash = true }) orelse return null;
	if (lhs_p.port == 0) return null;
	if (lhs_p.proto != .tcp) return null; // v1: tcp -> tcp only

	const rhs_p = parseProtoCidrPort(rhs, .{ .require_proto = true }) orelse return null;
	if (rhs_p.port == 0) return null;
	if (rhs_p.prefix_len != 32) return null; // single host
	if (rhs_p.proto != .tcp) return null;

	return .{
		.proto = lhs_p.proto,
		.network = lhs_p.network,
		.prefix_len = lhs_p.prefix_len,
		.port = lhs_p.port,
		.target = .{
			.proto = rhs_p.proto,
			.addr = rhs_p.network,
			.port = rhs_p.port,
		},
	};
}

/// Parse a textual IPv6 address (with optional `::` compression) into 16
/// bytes. Embedded IPv4 (`::ffff:1.2.3.4`) is not accepted in v1. Returns
/// null on malformed input.
pub fn parseIpv6(s: []const u8) ?[16]u8 {
	var result = [_]u8{0} ** 16;
	if (std.mem.indexOf(u8, s, "::")) |dc| {
		const head = s[0..dc];
		const tail = s[dc + 2 ..];
		if (std.mem.indexOf(u8, tail, "::") != null) return null; // only one ::
		var front: [8]u16 = undefined;
		var fcount: usize = 0;
		if (head.len > 0) fcount = parseV6Groups(head, &front) orelse return null;
		var back: [8]u16 = undefined;
		var bcount: usize = 0;
		if (tail.len > 0) bcount = parseV6Groups(tail, &back) orelse return null;
		if (fcount + bcount > 8) return null; // :: must elide >=1 group... unless whole-zero
		var i: usize = 0;
		while (i < fcount) : (i += 1) {
			result[i * 2] = @intCast(front[i] >> 8);
			result[i * 2 + 1] = @intCast(front[i] & 0xff);
		}
		const back_start = 8 - bcount;
		i = 0;
		while (i < bcount) : (i += 1) {
			const idx = back_start + i;
			result[idx * 2] = @intCast(back[i] >> 8);
			result[idx * 2 + 1] = @intCast(back[i] & 0xff);
		}
		return result;
	}
	var groups: [8]u16 = undefined;
	const n = parseV6Groups(s, &groups) orelse return null;
	if (n != 8) return null;
	var i: usize = 0;
	while (i < 8) : (i += 1) {
		result[i * 2] = @intCast(groups[i] >> 8);
		result[i * 2 + 1] = @intCast(groups[i] & 0xff);
	}
	return result;
}

fn parseV6Groups(s: []const u8, out: *[8]u16) ?usize {
	var n: usize = 0;
	var it = std.mem.splitScalar(u8, s, ':');
	while (it.next()) |grp| {
		if (n >= 8) return null;
		if (grp.len == 0 or grp.len > 4) return null;
		if (std.mem.indexOfScalar(u8, grp, '.') != null) return null; // no embedded v4
		out[n] = std.fmt.parseInt(u16, grp, 16) catch return null;
		n += 1;
	}
	return n;
}

pub fn parseIpv4(s: []const u8) ?[4]u8 {
	var result: [4]u8 = undefined;
	var octet_idx: usize = 0;
	var iter = std.mem.splitScalar(u8, s, '.');

	while (iter.next()) |part| {
		if (octet_idx >= 4) return null;
		result[octet_idx] = std.fmt.parseInt(u8, part, 10) catch return null;
		octet_idx += 1;
	}

	if (octet_idx != 4) return null;
	return result;
}

/// Parse the body of a `hard-deny <cidr>` line. A bare address is accepted and
/// means the single host (/32 or /128) -- the renderer emits the instance's own
/// addresses, which are naturally written without a prefix. No proto and no
/// port: the floor is address-scoped by construction, so anything narrower
/// would be a rule that pretends to be a floor. Pure: it returns the rule and
/// touches no shared state, so the shim (which parses the same file but never
/// consults this table) is unaffected.
fn parseHardDenyBody(body: []const u8) ?HardRule {
	const pcp = parseProtoCidrPort(body, .{}) orelse return null;
	if (pcp.proto != .any or pcp.port != 0) return null;
	return .{ .network = pcp.network, .prefix_len = pcp.prefix_len };
}

/// Parse the body of a `dns-host <addr>` line: the ONE loopback address the
/// enclosing host runs its DNS forwarder on (`RuleSet.dns_host`).
///
/// A BARE ADDRESS only. A prefix is refused rather than accepted-and-narrowed,
/// and that is the whole safety property of this parser: `dns-host 127.0.0.0/8`
/// would turn a one-socket exception into a port-53 pass to every loopback
/// listener. A proto or port qualifier is refused for the same reason -- the
/// port is fixed at 53 by `evaluate`, so accepting one here would only create a
/// second, disagreeing statement of it.
fn parseDnsHostBody(body: []const u8) ?IpAddr {
	const trimmed = std.mem.trim(u8, body, " \t");
	if (std.mem.indexOfScalar(u8, trimmed, '/') != null) return null;
	const pcp = parseProtoCidrPort(trimmed, .{}) orelse return null;
	if (pcp.proto != .any or pcp.port != 0) return null;
	return pcp.network;
}

/// Parse a multi-line rules string into a RuleSet.
pub fn parseRules(content: []const u8) RuleSet {
	var ruleset = RuleSet{};
	var lines = std.mem.splitScalar(u8, content, '\n');

	while (lines.next()) |line| {
		const trimmed = std.mem.trim(u8, line, " \t\r\n");
		if (trimmed.len == 0 or trimmed[0] == '#') continue;

		// Both of the following are matched BEFORE the `dns ` branch: an
		// unparseable `dns ...` body is silently dropped there, so a
		// `dns`-prefixed spelling of either keyword would fail closed-mouthed
		// instead of loudly. They are distinct keywords for that reason.
		if (std.mem.eql(u8, trimmed, "no-implicit-dns")) {
			ruleset.implicit_dns_allow = false;
			continue;
		}

		// Also ahead of the `dns ` branch, and it does NOT collide with it:
		// "dns-host " has no space after "dns", so `startsWith("dns ")` is
		// false for it either way. Kept here beside the other two keywords so
		// the ordering argument above holds for all three by inspection.
		// FIRST line wins: passt carries one --dns-host per family, so a second
		// line is a config that means two things and must not silently pick one.
		if (std.mem.startsWith(u8, trimmed, "dns-host ")) {
			if (ruleset.dns_host == null) {
				if (parseDnsHostBody(trimmed["dns-host ".len..])) |a| {
					ruleset.dns_host = a;
				}
			}
			continue;
		}

		if (std.mem.startsWith(u8, trimmed, "hard-deny ")) {
			if (parseHardDenyBody(trimmed["hard-deny ".len..])) |h| {
				if (ruleset.hard_len < max_hard_rules) {
					ruleset.hard_rules[ruleset.hard_len] = h;
					ruleset.hard_len += 1;
				}
			}
			continue;
		}

		if (std.mem.startsWith(u8, trimmed, "dns ")) {
			const body = trimmed[4..];
			if (parseDnsBody(body, &ruleset.dns_default)) |entry| {
				if (ruleset.dns_len < max_dns_rules) {
					ruleset.dns_rules[ruleset.dns_len] = .{
						.pattern = entry.pattern,
						.action = entry.action,
					};
					ruleset.dns_len += 1;
				}
			}
			continue;
		}

		if (std.mem.startsWith(u8, trimmed, "remap ")) {
			if (parseRemapLine(trimmed)) |r| {
				if (ruleset.remap_len < max_remap_rules) {
					ruleset.remap_rules[ruleset.remap_len] = r;
					ruleset.remap_len += 1;
				}
			}
			continue;
		}

		if (parseLine(trimmed)) |rule| {
			if (ruleset.len < max_rules) {
				ruleset.rules[ruleset.len] = rule;
				ruleset.len += 1;
			}
		}
	}

	return ruleset;
}

// --- L7 (vhost) rules ---
//
// Consumed by the host-side L7 proxy (cogbox __l7proxy), NOT by the shim.
// Each rule whitelists/blacklists an SNI/Host pattern (reusing DnsPattern),
// optionally narrowed to a URL path prefix and/or marked `terminate`. The
// proxy reads these from <runtime>/l7-rules; the shim never sees them.

pub const max_l7_rules = 128;
pub const max_l7_path_len = 256;
// A rule's optional HTTP-method constraint is stored as the raw uppercase
// comma-separated token (e.g. `GET,POST`); 0 length == "any method".
pub const max_l7_methods_len = 64;
// A rule's optional `service=<svc>` git-service constraint (e.g.
// `git-upload-pack`); 0 length == "no service constraint".
pub const max_l7_service_len = 32;
// Upper bound on hosts the terminate-tier addon injects a credential into (the
// `l7-inject-hosts` set the proxy reads to route their plain-HTTP egress
// through the addon too). Generous: harness specs are HTTPS-only and don't need
// it, so in practice this only counts plugin/operator inject hosts.
pub const max_inject_hosts = 64;

// Loopback ports the L7 proxy listens on, and the funnel remap targets.
// PER-INSTANCE: each instance is assigned a contiguous triple derived from a
// base port (`l7PortBase` in config.json, default `l7_default_base`), so
// multiple L7-enabled instances coexist on one host without colliding on a
// shared port (which would funnel one instance's guest traffic into another
// instance's proxy -- a cross-instance policy bleed). The renderer, the proxy
// and the launch script all derive the same triple from the base:
//
//   tls  = base       (HTTPS funnel listener / remap target for :443)
//   http = base + 1    (HTTP funnel listener / remap target for :80)
//   mitm = base + 2    (proxy -> mitmproxy terminate-backend SOCKS5 hop)
//
// 18080 is intentionally avoided as a base (the test SOCKS5 stub uses it).
// The default instance keeps the canonical base; named instances allocate
// above it in steps of 3. The mitm slot is the swappable seam a future
// in-process (OpenSSL) terminator can take.
pub const l7_default_base: u16 = 18443;

pub const L7Ports = struct { tls: u16, http: u16, mitm: u16 };

/// The contiguous loopback-port triple for the instance whose L7 base is
/// `base`. Single source of truth for the renderer and the proxy (the bash
/// launcher mirrors `base + 2` for the mitmproxy invocation).
pub fn l7PortsForBase(base: u16) L7Ports {
	return .{ .tls = base, .http = base +| 1, .mitm = base +| 2 };
}

// The per-sandbox auth proxy's loopback listen port, derived DOWNWARD from the
// same L7 base: `auth = base - 400`. Downward is collision-free forever --
// instance k has base = 18443+3k and auth = 18043+3k, so the auth band and the
// stride-3 triple band both grow upward and cannot meet for any realistic k,
// while within each band the stride keeps them disjoint. It also stays well
// below the ephemeral range (an upward offset would race bind() against
// outbound ephemeral allocation). The port is TOPOLOGY, never policy: it lives
// only in env (COGBOX_L7_AUTH_PORT), never in config.json or a wire file.
pub const l7_auth_port_offset: u16 = 400;

/// The auth proxy's listen port for the instance whose L7 base is `base`.
/// Refuses a base at or below the offset (which would underflow / collide with
/// the low reserved ports): `cogbox __authproxy` then declines to start and
/// mitmproxy's retarget fails closed (an error to the guest, no credential).
pub fn l7AuthPortForBase(base: u16) ?u16 {
	if (base <= l7_auth_port_offset + 1024) return null; // base <= 1424 is refused
	return base - l7_auth_port_offset;
}

pub const L7Rule = struct {
	action: Action,
	host: DnsPattern,
	has_path: bool = false,
	path_buf: [max_l7_path_len]u8 = undefined,
	path_len: u16 = 0,
	terminate: bool = false,
	// Skip upstream TLS cert verification for this host in the terminate tier
	// (the operator's per-host equivalent of `curl -k` on the proxy->upstream
	// leg). Only meaningful for terminated hosts; implies terminate.
	insecure_upstream: bool = false,
	// Opt this host OUT of the terminate tier (back to SNI-only passthrough:
	// TLS not intercepted, cert pinning preserved). Default is terminate, so
	// this is the escape hatch for cert-pinned clients. Mutually exclusive with
	// path/terminate/insecure_upstream.
	passthrough: bool = false,
	// Optional HTTP-method constraint: the raw uppercase comma-separated token
	// (`GET` or `GET,POST`). 0 length == any method. Used to distinguish read
	// vs write git smart-HTTP verbs (GET info/refs vs POST git-*-pack).
	methods_buf: [max_l7_methods_len]u8 = undefined,
	methods_len: u8 = 0,
	// When true, `path` is matched by full normalized-path EQUALITY instead of
	// the default boundary-aware prefix (`exact` rule token).
	exact: bool = false,
	// Optional git-service constraint (`service=<svc>`). Matched against the
	// request's effective git service (endpoint-derived here; the addon also
	// consults the `?service=` query on the terminated leg). 0 length == none.
	service_buf: [max_l7_service_len]u8 = undefined,
	service_len: u8 = 0,

	pub fn pathSlice(self: *const L7Rule) ?[]const u8 {
		if (!self.has_path) return null;
		return self.path_buf[0..self.path_len];
	}

	pub fn methodsSlice(self: *const L7Rule) ?[]const u8 {
		if (self.methods_len == 0) return null;
		return self.methods_buf[0..self.methods_len];
	}

	pub fn serviceSlice(self: *const L7Rule) ?[]const u8 {
		if (self.service_len == 0) return null;
		return self.service_buf[0..self.service_len];
	}
};

/// The effective git smart-HTTP service of a request, DERIVED FROM THE PATH's
/// final segment: `git-upload-pack` (fetch/clone) or `git-receive-pack` (push).
/// The `info/refs` advertisement carries the service in the `?service=` query
/// instead -- that lives in the stripped query, so this endpoint-derivation
/// returns null for it (the terminate-tier addon, which sees the query, is
/// authoritative there; this is the cleartext defense-in-depth). Returns null
/// when the final segment is neither pack endpoint.
pub fn effectiveGitService(path: []const u8) ?[]const u8 {
	var p = path;
	while (p.len > 0 and p[p.len - 1] == '/') p = p[0 .. p.len - 1];
	const seg = if (std.mem.lastIndexOfScalar(u8, p, '/')) |i| p[i + 1 ..] else p;
	if (std.mem.eql(u8, seg, "git-upload-pack")) return "git-upload-pack";
	if (std.mem.eql(u8, seg, "git-receive-pack")) return "git-receive-pack";
	return null;
}

/// True iff `method` is one of the uppercase comma-separated methods in
/// `methods_csv` (case-insensitive). Empty entries are ignored.
pub fn methodInList(methods_csv: []const u8, method: []const u8) bool {
	var it = std.mem.tokenizeScalar(u8, methods_csv, ',');
	while (it.next()) |m| {
		if (std.ascii.eqlIgnoreCase(m, method)) return true;
	}
	return false;
}

/// Result of evaluating a vhost against the L7 rules. Distinct from a bare
/// allow/deny so the proxy can compose with the L4 layer: an explicit `allow`
/// supersedes an L4 IP block, an explicit `deny` supersedes an L4 IP allow,
/// and `no_match` defers to the instance's L4 CIDR policy.
pub const L7Verdict = enum { allow, deny, no_match };

pub const L7RuleSet = struct {
	// Instance default tier. TRUE (the default) means every matched allow host
	// is MITM-terminated unless its rule says `passthrough`; FALSE (set by a
	// `mode passthrough` line) means hosts pass through unless their rule says
	// `terminate`/`path`/`insecure`. (Unlisted hosts are never intercepted --
	// they fall back to the L4 decision.)
	mode_terminate: bool = true,
	rules: [max_l7_rules]L7Rule = undefined,
	len: usize = 0,

	/// First-match allow/deny over (host[, path]); `no_match` when no rule
	/// matches (the caller then defers to the L4 CIDR policy). `path` is the
	/// request path the proxy already normalized (percent-decoded,
	/// dot-segments collapsed, query stripped). When `path` is null (HTTPS
	/// passthrough, host-only), rules that require a path simply don't match.
	///
	/// Path fail-closed: if an `allow` rule names this host but no matching
	/// rule covers the request path, the result is `deny`, not `no_match`.
	/// Otherwise a path-restricted host (`allow api.x /v1/`) accessed over
	/// cleartext HTTP would fall through to the L4 policy and bypass the path
	/// constraint whenever the IP is independently L4-allowed (the common
	/// "allow the internet at L4, restrict vhosts at L7" supersede setup).
	/// A `deny` rule whose host matches but whose path does not is NOT a
	/// fail-closed trigger -- `deny api.x /admin/` blocks only /admin/ and
	/// leaves every other path to the L4 policy.
	pub fn evaluate(self: *const L7RuleSet, host: []const u8, path: ?[]const u8) L7Verdict {
		return self.evaluateFull(host, path, null);
	}

	/// As `evaluate`, but also enforces a rule's optional method / `exact` /
	/// `service=` constraints against the request's `method` (null when the
	/// caller doesn't know it -- e.g. TLS passthrough -- in which case a
	/// method-constrained rule simply doesn't match). `exact` compares the
	/// normalized path for equality; `service=` compares the endpoint-derived
	/// git service (query-based service is stripped before we get here, so the
	/// addon is authoritative for it on the terminated leg).
	pub fn evaluateFull(self: *const L7RuleSet, host: []const u8, path: ?[]const u8, method: ?[]const u8) L7Verdict {
		const h = stripRootDot(host);
		var allow_host_matched = false;
		for (self.rules[0..self.len]) |r| {
			if (!matchDnsPattern(r.host, h)) continue;
			if (r.action == .allow) allow_host_matched = true;
			if (r.methodsSlice()) |m| {
				const req_m = method orelse continue; // unknown method -> can't confirm
				if (!methodInList(m, req_m)) continue;
			}
			if (r.has_path) {
				const p = path orelse continue;
				const rp = r.pathSlice().?;
				if (r.exact) {
					if (!std.mem.eql(u8, rp, p)) continue;
				} else {
					if (!pathPrefixMatches(rp, p)) continue;
				}
			}
			if (r.serviceSlice()) |svc| {
				const p = path orelse continue;
				const eff = effectiveGitService(p) orelse continue;
				if (!std.mem.eql(u8, eff, svc)) continue;
			}
			return switch (r.action) {
				.allow => .allow,
				.deny => .deny,
			};
		}
		if (allow_host_matched) return .deny;
		return .no_match;
	}

	/// Should this host be served through the terminating tier (MITM)? Only
	/// matched allow hosts are candidates -- unlisted hosts are never
	/// intercepted (L4-governed). Precedence, first-match over the rules:
	///   1. explicit `passthrough` on the rule  -> NO  (cert-pinning escape)
	///   2. explicit `path`/`terminate`/`insecure` -> YES
	///   3. a built-in harness API endpoint      -> NO  (keep agents working,
	///      tokens end-to-end; an explicit per-host flag in 1/2 still wins)
	///   4. otherwise the instance default (`mode_terminate`, default TRUE)
	pub fn needsTerminate(self: *const L7RuleSet, host: []const u8) bool {
		const h = stripRootDot(host);
		var matched_allow = false;
		for (self.rules[0..self.len]) |r| {
			if (!matchDnsPattern(r.host, h)) continue;
			if (r.passthrough) return false;
			if (r.has_path or r.terminate or r.insecure_upstream or r.exact or
				r.methodsSlice() != null or r.serviceSlice() != null) return true;
			if (r.action == .allow) matched_allow = true;
		}
		if (matched_allow and isHarnessPassthroughHost(h)) return false;
		return self.mode_terminate and matched_allow;
	}
};

/// Harness control-plane API endpoints auto-kept in passthrough under the
/// terminate-by-default tier, so the in-guest agents keep working (notably
/// rustls clients that may not honor the injected CA) and their API tokens
/// stay end-to-end (never decrypted by the host proxy). The operator must
/// still `allow` these; this only governs the tier, not allow/deny. An
/// explicit per-host `--terminate` overrides it. Provider-agnostic harnesses
/// (opencode, pi, hermes-agent) should `--passthrough` their configured
/// provider host.
/// Note: new instances seed an explicit `terminate`+inject rule for the
/// provider hosts of harnesses you're logged into (cogbox-launch.sh), which
/// wins over this fallback; the auto-passthrough below then applies only to
/// such a host with NO explicit rule.
const harness_passthrough_hosts = [_][]const u8{
	"api.anthropic.com", // claude-code
	"api.openai.com", // codex
	"chatgpt.com", // codex (ChatGPT auth/backend)
	"auth.openai.com", // codex auth
	"api.deepseek.com", // dsh
};

pub fn isHarnessPassthroughHost(host: []const u8) bool {
	const h = stripRootDot(host);
	for (harness_passthrough_hosts) |hh| {
		if (std.ascii.eqlIgnoreCase(h, hh)) return true;
	}
	return false;
}

/// Hosts the terminate-tier addon injects a host-side credential into -- the
/// `host` of every emitted inject-conf entry, written one-per-line to
/// `<runtime>/l7-inject-hosts` by the renderer. The L7 proxy consults this so a
/// host's PLAIN-HTTP egress is also routed through the terminate backend: TLS
/// injection already rides `needsTerminate` (inject hosts carry a terminate
/// rule), but plain HTTP otherwise bypasses the addon via the native splice, so
/// a bearer/cookie destined for an `http://` vhost would never be stamped.
///
/// Matching is EXACT host (case-insensitive). The addon injects by an exact
/// dict lookup on the request host (CredStore.spec_for), so a `*.suffix` or
/// bare-`*` entry would NEVER actually inject there -- but it WOULD over-route
/// plain HTTP through mitmproxy here (bare `*` = all of it). Keeping this set
/// exact-only keeps the proxy's HTTP routing in lockstep with what the addon
/// can inject; wildcards are dropped at parse time (see `parseInjectHosts`).
pub const InjectHosts = struct {
	hosts: [max_inject_hosts]DnsPattern = undefined,
	len: usize = 0,

	pub fn contains(self: *const InjectHosts, host: []const u8) bool {
		const h = stripRootDot(host);
		for (self.hosts[0..self.len]) |p| {
			if (matchDnsPattern(p, h)) return true;
		}
		return false;
	}
};

/// Parse `<runtime>/l7-inject-hosts` (one host per line; blank lines and `#`
/// comments skipped) into `out`. Only EXACT hostnames are admitted -- a
/// wildcard / bare-`*` line is dropped (it can't correspond to an addon-injected
/// host, which is keyed exactly, and would over-route HTTP). Per-line fail-open
/// otherwise, matching the other runtime-file parsers: a bad line can only drop
/// an injection's HTTP routing, never widen it.
pub fn parseInjectHosts(content: []const u8, out: *InjectHosts) void {
	out.* = .{};
	var lines = std.mem.splitScalar(u8, content, '\n');
	while (lines.next()) |line| {
		const t = std.mem.trim(u8, line, " \t\r\n");
		if (t.len == 0 or t[0] == '#') continue;
		const pat = parseDnsPattern(t) orelse continue;
		if (pat.kind != .exact) continue; // drop wildcards: addon injects exact-keyed only
		if (out.len < max_inject_hosts) {
			out.hosts[out.len] = pat;
			out.len += 1;
		}
	}
}

fn stripRootDot(host: []const u8) []const u8 {
	if (host.len > 0 and host[host.len - 1] == '.') return host[0 .. host.len - 1];
	return host;
}

/// Boundary-aware left-anchored prefix match, with two single-segment wildcards.
/// `rule_path` matches `req_path` iff they are equal, or `req_path` extends
/// `rule_path` at a `/` boundary. e.g. `/api` matches `/api`, `/api/`, `/api/v1`
/// but NOT `/apifoo`.
///
/// A rule segment that is exactly `*` matches EXACTLY ONE request segment and
/// never spans a `/`: `/a/*/c` matches `/a/b/c` but not `/a/b/x/c` and not
/// `/a/c`. A rule segment that is exactly `#` is the same thing NARROWED TO
/// ASCII DIGITS: it matches one segment of `[0-9]+` and nothing else, so
/// `/a/#/c` matches `/a/12/c` but not `/a/b/c`. A `*` or `#` that is not a whole
/// rule segment (`/a*`, `/a/#b`) is a literal character, and either character in
/// the REQUEST is always literal -- the request side is data and is never
/// interpreted.
///
/// The rule stays a PREFIX: a rule ending in a wildcard (`/a/*`) still matches
/// deeper paths, so an ALLOW must always terminate at a literal segment. That is
/// necessary but NOT sufficient, which is why `#` exists. `req_path` is
/// percent-DECODED before it gets here, so an encoded slash inflates one
/// addressed segment into several, and `*` will happily absorb the first of
/// them: with rule `/a/*/tail`, the request `/a/x%2Ftail/anything` decodes to
/// `/a/x/tail/anything`, the literal tail lands on the id's OWN last component,
/// and `/anything` rides through as ordinary prefix continuation. `#` closes
/// that for an identifier that is numeric by construction (a GitLab project or
/// group id), because the absorbed component would have to be all digits.
/// A DENY still cannot be rescued either way -- a left-anchored matcher can
/// never suffix-anchor one, so a tail deny simply stops matching the encoded
/// form. Put the boundary in the allow, and make it `#` wherever the segment is
/// a numeric id. See path_vectors.tsv.
///
/// `--exact` rules compare literally (`std.mem.eql`) and do NOT honour `*`/`#`.
///
/// Both inputs are expected pre-normalized on the REQUEST side only: rule paths
/// are matched verbatim, never normalized. The shared vector table
/// `l7proxy/path_vectors.tsv` is the oracle for this function AND for the
/// mitmproxy addon's `path_match`; the two must agree byte for byte.
pub fn pathPrefixMatches(rule_path: []const u8, req_path: []const u8) bool {
	var ri: usize = 0;
	var qi: usize = 0;
	while (ri < rule_path.len) {
		const c = rule_path[ri];
		if ((c == '*' or c == '#') and
			(ri == 0 or rule_path[ri - 1] == '/') and
			(ri + 1 == rule_path.len or rule_path[ri + 1] == '/'))
		{
			const seg_start = qi;
			while (qi < req_path.len and req_path[qi] != '/') : (qi += 1) {
				// ASCII digits ONLY -- not a locale/unicode "is a digit" test. The
				// addon side must make the same choice or the two matchers diverge on
				// a UTF-8 decoded segment.
				if (c == '#' and (req_path[qi] < '0' or req_path[qi] > '9')) return false;
			}
			if (qi == seg_start) return false; // never matches an empty segment
			ri += 1;
			continue;
		}
		if (qi >= req_path.len) return false;
		if (c != req_path[qi]) return false;
		ri += 1;
		qi += 1;
	}
	if (qi == req_path.len) return true;
	if (rule_path.len > 0 and rule_path[rule_path.len - 1] == '/') return true;
	return req_path[qi] == '/';
}

pub const L7Line = union(enum) {
	rule: L7Rule,
	mode_terminate: bool,
	none, // blank / comment / malformed
};

/// A METHODS token is all uppercase ASCII letters and commas, with at least one
/// letter (e.g. `GET` or `GET,POST`). The keyword tokens (`terminate`,
/// `passthrough`, `insecure`, `exact`) and `service=` are all lowercase, so an
/// all-uppercase token is unambiguously the optional method list.
fn isMethodsToken(tok: []const u8) bool {
	if (tok.len == 0) return false;
	var saw_letter = false;
	for (tok) |c| switch (c) {
		'A'...'Z' => saw_letter = true,
		',' => {},
		else => return false,
	};
	return saw_letter;
}

/// Parse a single `l7-rules` line:
///   mode passthrough|terminate
///   allow|deny  <host-pattern>  [<path>]  [terminate|passthrough]  [insecure]
/// Tokens are whitespace-separated. A token starting with `/` is the path;
/// `terminate` forces the terminate tier, `passthrough` forces SNI-only
/// passthrough, `insecure` skips upstream cert verification (terminate tier
/// only). Order of the trailing tokens is not significant. Malformed lines
/// return `.none` (dropped, fail-closed).
pub fn parseL7Line(line: []const u8) L7Line {
	const trimmed = std.mem.trim(u8, line, " \t\r\n");
	if (trimmed.len == 0 or trimmed[0] == '#') return .none;

	var it = std.mem.tokenizeAny(u8, trimmed, " \t");
	const head = it.next() orelse return .none;

	if (std.mem.eql(u8, head, "mode")) {
		const v = it.next() orelse return .none;
		if (std.mem.eql(u8, v, "terminate")) return .{ .mode_terminate = true };
		if (std.mem.eql(u8, v, "passthrough")) return .{ .mode_terminate = false };
		return .none;
	}

	var action: Action = undefined;
	if (std.mem.eql(u8, head, "allow")) {
		action = .allow;
	} else if (std.mem.eql(u8, head, "deny")) {
		action = .deny;
	} else {
		return .none;
	}

	const host_tok = it.next() orelse return .none;
	const pat = parseDnsPattern(host_tok) orelse return .none;

	var rule: L7Rule = .{ .action = action, .host = pat };
	while (it.next()) |tok| {
		if (std.mem.eql(u8, tok, "terminate")) {
			rule.terminate = true;
		} else if (std.mem.eql(u8, tok, "passthrough")) {
			rule.passthrough = true;
		} else if (std.mem.eql(u8, tok, "insecure")) {
			rule.insecure_upstream = true;
		} else if (std.mem.eql(u8, tok, "exact")) {
			rule.exact = true;
		} else if (std.mem.startsWith(u8, tok, "service=")) {
			if (rule.service_len != 0) return .none; // duplicate
			const svc = tok["service=".len..];
			if (svc.len == 0 or svc.len > max_l7_service_len) return .none;
			@memcpy(rule.service_buf[0..svc.len], svc);
			rule.service_len = @intCast(svc.len);
		} else if (tok.len > 0 and tok[0] == '/') {
			if (rule.has_path) return .none; // duplicate path
			if (tok.len > max_l7_path_len) return .none;
			@memcpy(rule.path_buf[0..tok.len], tok);
			rule.path_len = @intCast(tok.len);
			rule.has_path = true;
		} else if (isMethodsToken(tok)) {
			if (rule.methods_len != 0) return .none; // duplicate
			if (tok.len > max_l7_methods_len) return .none;
			@memcpy(rule.methods_buf[0..tok.len], tok);
			rule.methods_len = @intCast(tok.len);
		} else if (std.mem.startsWith(u8, tok, "tag=")) {
			// Injection-gating tag (renderL7 emits `tag=git-grants`). The proxy
			// does not gate injection (the mitmproxy addon does); it only
			// enforces allow/deny + tier, so this token is accepted and IGNORED
			// here. Accepting it is the rolling-upgrade parity guard: a new
			// rules file's tagged lines must not be fail-closed dropped by the
			// proxy. `tagx=foo` does NOT match (char 3 is `x` not `=`), so a
			// genuinely-unknown token still hits the reject below.
		} else {
			return .none; // unknown token -> reject the whole line
		}
	}
	return .{ .rule = rule };
}

/// Parse a multi-line `l7-rules` document into `out` (passed by pointer to
/// avoid copying the large fixed-size table).
pub fn parseL7Rules(content: []const u8, out: *L7RuleSet) void {
	out.* = .{};
	var lines = std.mem.splitScalar(u8, content, '\n');
	while (lines.next()) |line| {
		switch (parseL7Line(line)) {
			.none => {},
			.mode_terminate => |t| out.mode_terminate = t,
			.rule => |r| {
				if (out.len < max_l7_rules) {
					out.rules[out.len] = r;
					out.len += 1;
				}
			},
		}
	}
}

// --- Tests ---

test "parseIpv4 valid" {
	const result = parseIpv4("192.168.1.1").?;
	try std.testing.expectEqual([4]u8{ 192, 168, 1, 1 }, result);
}

test "parseIpv4 zeros" {
	const result = parseIpv4("0.0.0.0").?;
	try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, result);
}

test "parseIpv4 invalid" {
	try std.testing.expect(parseIpv4("256.0.0.0") == null);
	try std.testing.expect(parseIpv4("1.2.3") == null);
	try std.testing.expect(parseIpv4("1.2.3.4.5") == null);
	try std.testing.expect(parseIpv4("abc") == null);
	try std.testing.expect(parseIpv4("") == null);
}

test "parseIpv6 :: forms" {
	try std.testing.expectEqual([_]u8{0} ** 16, parseIpv6("::").?);
	const lo = parseIpv6("::1").?;
	try std.testing.expectEqual(@as(u8, 1), lo[15]);
	const full = parseIpv6("2001:db8::1").?;
	try std.testing.expectEqual([_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, full);
	try std.testing.expect(parseIpv6("2001:::1") == null);
	try std.testing.expect(parseIpv6("xyz") == null);
	try std.testing.expect(parseIpv6("::ffff:1.2.3.4") == null); // embedded v4 not supported
}

// --- mosh reply-socket exemption helpers ---

test "parsePortRange accepts exactly lo-hi" {
	const r = parsePortRange("60000-60031").?;
	try std.testing.expectEqual(@as(u16, 60000), r.lo);
	try std.testing.expectEqual(@as(u16, 60031), r.hi);
	try std.testing.expect(r.contains(60000));
	try std.testing.expect(r.contains(60031));
	try std.testing.expect(!r.contains(59999));
	try std.testing.expect(!r.contains(60032));
	const full = parsePortRange("1-65535").?;
	try std.testing.expectEqual(@as(u16, 1), full.lo);
	try std.testing.expectEqual(@as(u16, 65535), full.hi);
	const one = parsePortRange("7-7").?;
	try std.testing.expectEqual(@as(u16, 7), one.lo);
	try std.testing.expectEqual(@as(u16, 7), one.hi);
}

test "parsePortRange rejects every other shape" {
	const bad = [_][]const u8{
		"",        "60000", "60000:60031", "60031-60000", "0-5",
		"1-70000", "a-b",   " 1-2",        "1-2 ",        "1-2-3",
		"-5",      "5-",    "+1-2",        "1_0-20",      "60000-60031\n",
	};
	for (bad) |s| {
		try std.testing.expect(parsePortRange(s) == null);
	}
}

test "isForwardReplyLocal needs a specific non-loopback unicast address in range" {
	const range = PortRange{ .lo = 60000, .hi = 60031 };
	// guest-originated flows: wildcard bind with the guest sport preserved
	try std.testing.expect(!isForwardReplyLocal(.{ .ipv4 = .{ 0, 0, 0, 0 } }, 60005, range));
	try std.testing.expect(!isForwardReplyLocal(.{ .ipv6 = [_]u8{0} ** 16 }, 60005, range));
	// loopback
	try std.testing.expect(!isForwardReplyLocal(.{ .ipv4 = .{ 127, 0, 0, 1 } }, 60005, range));
	try std.testing.expect(!isForwardReplyLocal(.{ .ipv6 = ipv6_loopback }, 60005, range));
	// the -u listener address, inside and just outside the range
	const vm = IpAddr{ .ipv4 = .{ 10, 1, 2, 3 } };
	try std.testing.expect(isForwardReplyLocal(vm, 60005, range));
	try std.testing.expect(isForwardReplyLocal(vm, 60000, range));
	try std.testing.expect(isForwardReplyLocal(vm, 60031, range));
	try std.testing.expect(!isForwardReplyLocal(vm, 59999, range));
	try std.testing.expect(!isForwardReplyLocal(vm, 60032, range));
	try std.testing.expect(!isForwardReplyLocal(vm, 0, range));
	// v4-mapped v6 is unwrapped and judged as v4
	const mapped = ipv4_mapped_prefix ++ [4]u8{ 10, 1, 2, 3 };
	try std.testing.expect(isForwardReplyLocal(.{ .ipv6 = mapped }, 60005, range));
	const mapped_lo = ipv4_mapped_prefix ++ [4]u8{ 127, 0, 0, 1 };
	try std.testing.expect(!isForwardReplyLocal(.{ .ipv6 = mapped_lo }, 60005, range));
	const mapped_any = ipv4_mapped_prefix ++ [4]u8{ 0, 0, 0, 0 };
	try std.testing.expect(!isForwardReplyLocal(.{ .ipv6 = mapped_any }, 60005, range));
	// global v6 unicast
	const v6 = IpAddr{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
	try std.testing.expect(isForwardReplyLocal(v6, 60005, range));
	try std.testing.expect(!isForwardReplyLocal(v6, 60032, range));
	// multicast / broadcast are not unicast
	try std.testing.expect(!isForwardReplyLocal(.{ .ipv4 = .{ 224, 0, 0, 1 } }, 60005, range));
	try std.testing.expect(!isForwardReplyLocal(.{ .ipv4 = .{ 255, 255, 255, 255 } }, 60005, range));
	try std.testing.expect(!isForwardReplyLocal(.{ .ipv6 = [_]u8{0xff} ++ [_]u8{0} ** 15 }, 60005, range));
}

test "replySendAllowed exempts only the recorded peer" {
	const peer = Endpoint{ .addr = .{ .ipv4 = .{ 10, 9, 8, 7 } }, .port = 41000 };
	const peer_mapped = Endpoint{ .addr = .{ .ipv6 = ipv4_mapped_prefix ++ [4]u8{ 10, 9, 8, 7 } }, .port = 41000 };
	// exempt fd: implicit peer, the peer itself, the peer's v4-mapped spelling
	try std.testing.expect(replySendAllowed(true, peer, null));
	try std.testing.expect(replySendAllowed(true, peer, peer));
	try std.testing.expect(replySendAllowed(true, peer, peer_mapped));
	// exempt fd steered elsewhere: port or address differs -> ruleset walk
	try std.testing.expect(!replySendAllowed(true, peer, .{ .addr = peer.addr, .port = 41001 }));
	try std.testing.expect(!replySendAllowed(true, peer, .{ .addr = .{ .ipv4 = .{ 10, 9, 8, 6 } }, .port = 41000 }));
	// not exempt: never, whatever the destination
	try std.testing.expect(!replySendAllowed(false, peer, null));
	try std.testing.expect(!replySendAllowed(false, peer, peer));
	// exempt but no recorded peer (cannot happen; fail closed anyway)
	try std.testing.expect(!replySendAllowed(true, null, null));
}

test "parseLine accepts port-less IPv6 CIDR" {
	const r = parseLine("deny tcp ::/0").?;
	try std.testing.expectEqual(Proto.tcp, r.proto);
	try std.testing.expectEqual(@as(u8, 0), r.prefix_len);
	try std.testing.expectEqual(@as(u16, 0), r.port);
	try std.testing.expectEqual([_]u8{0} ** 16, r.network.ipv6);
}

test "evaluate honors v6 deny-all but keeps DNS" {
	const rs = parseRules(
		\\deny tcp ::/0
		\\deny udp ::/0
	);
	const v6 = IpAddr{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, v6, 443));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.udp, v6, 443));
	// DNS (port 53) stays implicitly allowed
	try std.testing.expectEqual(Action.allow, rs.evaluate(.udp, v6, 53));
}

// The implicit port-53 allow sits ABOVE every rule, including the L7-mode
// fail-closed v6 prologue, so today port 53 escapes the v6 fail-close, the
// seeded 169.254.0.0/16 deny and every RFC1918 deny, in both families and both
// protocols -- a DNS tunnel no filter sees. `no-implicit-dns` is the
// parameterization the GCE backend requires, where
// the VPC resolver IS the metadata address; the mirrored cases below are the
// same inputs with the flag off.
test "no-implicit-dns subjects port 53 to the v6 fail-close" {
	const rs = parseRules(
		\\no-implicit-dns
		\\deny tcp ::/0
		\\deny udp ::/0
	);
	try std.testing.expect(!rs.implicit_dns_allow);
	const v6 = IpAddr{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
	try std.testing.expectEqual(Action.deny, rs.evaluate(.udp, v6, 53));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, v6, 53));
}

test "no-implicit-dns subjects port 53 to the seeded link-local deny" {
	const rs = parseRules(
		\\no-implicit-dns
		\\deny 169.254.0.0/16
		\\allow 0.0.0.0/0
	);
	const metadata = IpAddr{ .ipv4 = .{ 169, 254, 169, 254 } };
	const public = IpAddr{ .ipv4 = .{ 8, 8, 8, 8 } };
	try std.testing.expectEqual(Action.deny, rs.evaluate(.udp, metadata, 53));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, metadata, 53));
	// An operator-configured public resolver still resolves: the guest's DNS
	// now walks the ordered rules and hits the seeded public allow.
	try std.testing.expectEqual(Action.allow, rs.evaluate(.udp, public, 53));
}

test "no-implicit-dns restores the loopback deny for port 53" {
	// The implicit allow sits ABOVE the loopback deny deliberately (for
	// 127.0.0.53/systemd-resolved). Turning it off puts loopback DNS back
	// under the deny -- correct where the host resolver is not the guest's,
	// and exactly why the default must stay on for a local dev box.
	const rs = parseRules("no-implicit-dns");
	try std.testing.expectEqual(Action.deny, rs.evaluate(.udp, .{ .ipv4 = .{ 127, 0, 0, 53 } }, 53));
}

test "parseRules keeps the implicit DNS allow when no-implicit-dns is absent" {
	// The default-preserving guarantee: every instance that does not ask for
	// the parameterization behaves byte-for-byte as before (local + k8s).
	const rs = parseRules(
		\\deny 169.254.0.0/16
		\\allow 0.0.0.0/0
	);
	try std.testing.expect(rs.implicit_dns_allow);
	try std.testing.expectEqual(Action.allow, rs.evaluate(.udp, .{ .ipv4 = .{ 169, 254, 169, 254 } }, 53));
}

test "no-implicit-dns is matched as a whole keyword, not a dns-prefixed spelling" {
	// `dns <body>` bodies that fail to parse are silently dropped, so a
	// `dns no-implicit` spelling would fail silently. Guard the distinct
	// keyword: a near-miss must NOT flip the flag.
	try std.testing.expect(parseRules("dns no-implicit-dns").implicit_dns_allow);
	try std.testing.expect(parseRules("no-implicit-dns-please").implicit_dns_allow);
	try std.testing.expect(parseRules("# no-implicit-dns").implicit_dns_allow);
}

// --- dns-host: the host-side forwarder's ONE loopback socket ---------------
//
// THE REGRESSION THESE PIN. `no-implicit-dns` (which this backend passes
// unconditionally) puts loopback DNS back under the loopback deny, and passt's
// `--dns-forward` re-emits the guest's queries as an ordinary loopback connect
// under the passt uid. Without `dns-host` the shim drops that connect and every
// rules-mode guest has NO DNS -- silently, since a dropped packet surfaces
// nothing. The counterpart hazard is the fix that over-corrects: anything
// broader than one address + port 53 hands the guest either an
// arbitrary-destination DNS tunnel or the trusted half's other loopback
// listeners, both of which the rule set exists to deny.

test "dns-host admits exactly the host forwarder's port-53 socket under no-implicit-dns" {
	const rs = parseRules(
		\\no-implicit-dns
		\\dns-host 127.0.0.53
		\\deny 169.254.0.0/16
		\\allow 0.0.0.0/0
	);
	const fwd = IpAddr{ .ipv4 = .{ 127, 0, 0, 53 } };
	// The one socket passt re-emits the guest's queries on, both protocols.
	try std.testing.expectEqual(Action.allow, rs.evaluate(.udp, fwd, 53));
	try std.testing.expectEqual(Action.allow, rs.evaluate(.tcp, fwd, 53));
	// ... and nothing else about it. Another port on the SAME address is the
	// sharpest case: it proves the exception is a socket, not an address.
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, fwd, 22));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, fwd, 853));
	// Port 53 to any OTHER loopback listener stays denied -- 127.0.0.1:18445 is
	// the mitmproxy SOCKS5 hop, the target rule 3 of the GCE floor names.
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, .{ .ipv4 = .{ 127, 0, 0, 1 } }, 53));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, .{ .ipv4 = .{ 127, 0, 0, 1 } }, 18445));
	// And it is NOT a port-53 pass: the seeded link-local deny still applies,
	// which is the tunnel `no-implicit-dns` was added to close.
	try std.testing.expectEqual(Action.deny, rs.evaluate(.udp, .{ .ipv4 = .{ 169, 254, 169, 254 } }, 53));
}

test "dns-host normalizes the v4-mapped form" {
	const rs = parseRules(
		\\no-implicit-dns
		\\dns-host 127.0.0.53
	);
	var mapped = IpAddr{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 53 } };
	try std.testing.expectEqual(Action.allow, rs.evaluate(.udp, mapped, 53));
	mapped.ipv6[15] = 1;
	try std.testing.expectEqual(Action.deny, rs.evaluate(.udp, mapped, 53));
}

test "dns-host refuses a prefix, a port and a proto" {
	// Each of these is the tempting widening. A prefix is the dangerous one:
	// `dns-host 127.0.0.0/8` would be a port-53 pass to every loopback listener
	// while still reading like a one-host exception.
	try std.testing.expect(parseRules("dns-host 127.0.0.0/8").dns_host == null);
	try std.testing.expect(parseRules("dns-host 127.0.0.53/32").dns_host == null);
	try std.testing.expect(parseRules("dns-host 127.0.0.53:53").dns_host == null);
	try std.testing.expect(parseRules("dns-host udp 127.0.0.53").dns_host == null);
	try std.testing.expect(parseRules("dns-host").dns_host == null);
	try std.testing.expect(parseRules("dns-host ").dns_host == null);
}

test "dns-host takes the FIRST line, so a second cannot move the exception" {
	const rs = parseRules(
		\\dns-host 127.0.0.53
		\\dns-host 127.0.0.1
	);
	try std.testing.expectEqual(Action.allow, rs.evaluate(.udp, .{ .ipv4 = .{ 127, 0, 0, 53 } }, 53));
	const rs2 = parseRules(
		\\no-implicit-dns
		\\dns-host 127.0.0.53
		\\dns-host 127.0.0.1
	);
	try std.testing.expectEqual(Action.deny, rs2.evaluate(.udp, .{ .ipv4 = .{ 127, 0, 0, 1 } }, 53));
}

test "parseRules leaves dns_host null when no line asks for it" {
	// The default-preserving guarantee at the ruleset layer: local, k8s and
	// container instances render no `dns-host` line, so the loopback deny is
	// exactly what it was before this field existed.
	const rs = parseRules(
		\\no-implicit-dns
		\\deny 169.254.0.0/16
		\\allow 0.0.0.0/0
	);
	try std.testing.expect(rs.dns_host == null);
	try std.testing.expectEqual(Action.deny, rs.evaluate(.udp, .{ .ipv4 = .{ 127, 0, 0, 53 } }, 53));
}

test "parseLine allow" {
	const rule = parseLine("allow 10.0.0.0/8").?;
	try std.testing.expectEqual(Action.allow, rule.action);
	try std.testing.expectEqual([4]u8{ 10, 0, 0, 0 }, rule.network.ipv4);
	try std.testing.expectEqual(@as(u8, 8), rule.prefix_len);
}

test "parseLine deny" {
	const rule = parseLine("deny 0.0.0.0/0").?;
	try std.testing.expectEqual(Action.deny, rule.action);
	try std.testing.expectEqual(@as(u8, 0), rule.prefix_len);
}

test "parseLine skip empty and comments" {
	try std.testing.expect(parseLine("") == null);
	try std.testing.expect(parseLine("# comment") == null);
	try std.testing.expect(parseLine("   ") == null);
}

test "parseLine invalid" {
	try std.testing.expect(parseLine("allow 10.0.0.0") == null);
	try std.testing.expect(parseLine("allow 10.0.0.0/33") == null);
	try std.testing.expect(parseLine("block 10.0.0.0/8") == null);
}

test "ipv4 CIDR /8" {
	try std.testing.expect(ipv4Matches(.{ 10, 0, 0, 0 }, .{ 10, 1, 2, 3 }, 8));
	try std.testing.expect(!ipv4Matches(.{ 10, 0, 0, 0 }, .{ 11, 0, 0, 0 }, 8));
}

test "ipv4 CIDR /32 exact" {
	try std.testing.expect(ipv4Matches(.{ 1, 2, 3, 4 }, .{ 1, 2, 3, 4 }, 32));
	try std.testing.expect(!ipv4Matches(.{ 1, 2, 3, 4 }, .{ 1, 2, 3, 5 }, 32));
}

test "ipv4 CIDR /0 matches all" {
	try std.testing.expect(ipv4Matches(.{ 0, 0, 0, 0 }, .{ 255, 255, 255, 255 }, 0));
}

test "ipv4 CIDR /24" {
	try std.testing.expect(ipv4Matches(.{ 192, 168, 1, 0 }, .{ 192, 168, 1, 254 }, 24));
	try std.testing.expect(!ipv4Matches(.{ 192, 168, 1, 0 }, .{ 192, 168, 2, 1 }, 24));
}

test "ipv6 CIDR matching" {
	const net = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	const ip_match = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	const ip_no = [16]u8{ 0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	try std.testing.expect(ipv6Matches(net, ip_match, 32));
	try std.testing.expect(!ipv6Matches(net, ip_no, 32));
	try std.testing.expect(ipv6Matches(net, ip_no, 0));
}

test "isIpv4Mapped" {
	const mapped = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1 };
	const not_mapped = [16]u8{ 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

	try std.testing.expect(isIpv4Mapped(mapped));
	try std.testing.expect(!isIpv4Mapped(not_mapped));
}

test "RuleSet evaluate loopback denied" {
	const rs = RuleSet{};
	try std.testing.expectEqual(Action.deny, rs.evaluate(.any, .{ .ipv4 = .{ 127, 0, 0, 1 } }, 80));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.any, .{ .ipv6 = ipv6_loopback }, 80));
}

test "RuleSet evaluate loopback DNS allowed" {
	const rs = RuleSet{};
	try std.testing.expectEqual(Action.allow, rs.evaluate(.any, .{ .ipv4 = .{ 127, 0, 0, 53 } }, 53));
	try std.testing.expectEqual(Action.allow, rs.evaluate(.any, .{ .ipv6 = ipv6_loopback }, 53));
}

test "RuleSet evaluate DNS" {
	const rs = RuleSet{};
	try std.testing.expectEqual(Action.allow, rs.evaluate(.any, .{ .ipv4 = .{ 8, 8, 8, 8 } }, 53));
}

test "RuleSet evaluate DNS with implicit_dns_allow off falls through to default deny" {
	// Mirror of the two tests above, driven through the struct field rather
	// than the parser: with the short-circuit off an empty ruleset denies
	// port 53 like any other port.
	const rs = RuleSet{ .implicit_dns_allow = false };
	try std.testing.expectEqual(Action.deny, rs.evaluate(.any, .{ .ipv4 = .{ 8, 8, 8, 8 } }, 53));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.any, .{ .ipv4 = .{ 127, 0, 0, 53 } }, 53));
}

test "RuleSet evaluate default deny" {
	const rs = RuleSet{};
	try std.testing.expectEqual(Action.deny, rs.evaluate(.any, .{ .ipv4 = .{ 8, 8, 8, 8 } }, 443));
}

test "RuleSet evaluate user rules in order" {
	const rs = parseRules(
		\\allow 10.0.0.0/8
		\\deny 192.168.0.0/16
		\\allow 0.0.0.0/0
	);
	try std.testing.expectEqual(Action.allow, rs.evaluate(.any, .{ .ipv4 = .{ 10, 1, 2, 3 } }, 443));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.any, .{ .ipv4 = .{ 192, 168, 1, 1 } }, 443));
	try std.testing.expectEqual(Action.allow, rs.evaluate(.any, .{ .ipv4 = .{ 8, 8, 8, 8 } }, 443));
}

test "RuleSet evaluate IPv4-mapped IPv6" {
	const rs = parseRules("deny 10.0.0.0/8");
	const mapped = IpAddr{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 2, 3 } };
	try std.testing.expectEqual(Action.deny, rs.evaluate(.any, mapped, 443));
}

test "parseRules multi-line with comments" {
	const content =
		\\# Allow internal
		\\allow 10.0.0.0/8
		\\
		\\deny 0.0.0.0/0
	;
	const rs = parseRules(content);
	try std.testing.expectEqual(@as(usize, 2), rs.len);
	try std.testing.expectEqual(Action.allow, rs.rules[0].action);
	try std.testing.expectEqual(Action.deny, rs.rules[1].action);
}

// --- DNS ---

test "parseDnsPattern exact" {
	const p = parseDnsPattern("api.anthropic.com").?;
	try std.testing.expectEqual(DnsPatternKind.exact, p.kind);
	try std.testing.expectEqualStrings("api.anthropic.com", p.slice());
}

test "parseDnsPattern left wildcard strips star-dot" {
	const p = parseDnsPattern("*.githubusercontent.com").?;
	try std.testing.expectEqual(DnsPatternKind.left_wildcard, p.kind);
	try std.testing.expectEqualStrings("githubusercontent.com", p.slice());
}

test "parseDnsPattern bare star" {
	const p = parseDnsPattern("*").?;
	try std.testing.expectEqual(DnsPatternKind.any, p.kind);
}

test "parseDnsPattern rejects right-anchored wildcard" {
	try std.testing.expect(parseDnsPattern("api.*") == null);
	try std.testing.expect(parseDnsPattern("foo.*.com") == null);
	try std.testing.expect(parseDnsPattern("*.foo.*") == null);
}

test "parseDnsPattern rejects malformed names" {
	try std.testing.expect(parseDnsPattern("") == null);
	try std.testing.expect(parseDnsPattern(".") == null);
	try std.testing.expect(parseDnsPattern(".com") == null);
	try std.testing.expect(parseDnsPattern("com.") == null);
	try std.testing.expect(parseDnsPattern("foo..bar") == null);
	try std.testing.expect(parseDnsPattern("foo bar") == null);
	try std.testing.expect(parseDnsPattern("-foo.com") == null);
	try std.testing.expect(parseDnsPattern("*.") == null);
}

test "matchDnsPattern exact case-insensitive" {
	const p = parseDnsPattern("api.anthropic.com").?;
	try std.testing.expect(matchDnsPattern(p, "api.anthropic.com"));
	try std.testing.expect(matchDnsPattern(p, "API.Anthropic.COM"));
	try std.testing.expect(!matchDnsPattern(p, "x.api.anthropic.com"));
	try std.testing.expect(!matchDnsPattern(p, "anthropic.com"));
}

test "matchDnsPattern left wildcard requires >=1 subdomain label" {
	const p = parseDnsPattern("*.example.com").?;
	try std.testing.expect(matchDnsPattern(p, "a.example.com"));
	try std.testing.expect(matchDnsPattern(p, "a.b.example.com"));
	try std.testing.expect(matchDnsPattern(p, "A.Example.COM"));
	try std.testing.expect(!matchDnsPattern(p, "example.com"));
	try std.testing.expect(!matchDnsPattern(p, "evilexample.com"));
	try std.testing.expect(!matchDnsPattern(p, "com"));
}

test "matchDnsPattern bare star matches everything" {
	const p = parseDnsPattern("*").?;
	try std.testing.expect(matchDnsPattern(p, "x"));
	try std.testing.expect(matchDnsPattern(p, "anything.example.com"));
}

test "RuleSet evaluateDns default allow" {
	const rs = RuleSet{};
	try std.testing.expectEqual(Action.allow, rs.evaluateDns("anywhere.example"));
}

test "RuleSet evaluateDns first match wins, default applies" {
	const rs = parseRules(
		\\dns default deny
		\\dns allow api.anthropic.com
		\\dns allow *.githubusercontent.com
		\\dns deny telemetry.example.com
	);
	try std.testing.expectEqual(Action.allow, rs.evaluateDns("api.anthropic.com"));
	try std.testing.expectEqual(Action.allow, rs.evaluateDns("raw.githubusercontent.com"));
	try std.testing.expectEqual(Action.deny, rs.evaluateDns("telemetry.example.com"));
	try std.testing.expectEqual(Action.deny, rs.evaluateDns("unspecified.example"));
}

test "RuleSet evaluateDns strips trailing root dot" {
	const rs = parseRules(
		\\dns default deny
		\\dns allow api.anthropic.com
	);
	try std.testing.expectEqual(Action.allow, rs.evaluateDns("api.anthropic.com."));
}

test "parseRules mixed CIDR + DNS rules go to separate tables" {
	const rs = parseRules(
		\\allow 10.0.0.0/8
		\\dns default deny
		\\dns allow api.anthropic.com
		\\deny 0.0.0.0/0
	);
	try std.testing.expectEqual(@as(usize, 2), rs.len);
	try std.testing.expectEqual(@as(usize, 1), rs.dns_len);
	try std.testing.expectEqual(Action.deny, rs.dns_default);
	try std.testing.expectEqual(Action.allow, rs.dns_rules[0].action);
	try std.testing.expectEqualStrings("api.anthropic.com", rs.dns_rules[0].pattern.slice());
}

// --- proto/port qualifiers + remap ---

test "parseLine with tcp proto qualifier" {
	const r = parseLine("allow tcp 10.0.0.0/8").?;
	try std.testing.expectEqual(Proto.tcp, r.proto);
	try std.testing.expectEqual(@as(u16, 0), r.port);
}

test "parseLine with port qualifier" {
	const r = parseLine("deny 0.0.0.0/0:25").?;
	try std.testing.expectEqual(Proto.any, r.proto);
	try std.testing.expectEqual(@as(u16, 25), r.port);
}

test "parseLine with proto + port" {
	const r = parseLine("allow tcp 10.0.0.0/8:443").?;
	try std.testing.expectEqual(Proto.tcp, r.proto);
	try std.testing.expectEqual(@as(u16, 443), r.port);
}

test "parseLine backward compat: no qualifiers" {
	const r = parseLine("allow 10.0.0.0/8").?;
	try std.testing.expectEqual(Proto.any, r.proto);
	try std.testing.expectEqual(@as(u16, 0), r.port);
}

test "evaluate honors proto qualifier" {
	const rs = parseRules("allow tcp 8.8.8.8/32");
	try std.testing.expectEqual(Action.allow, rs.evaluate(.tcp, .{ .ipv4 = .{ 8, 8, 8, 8 } }, 443));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.udp, .{ .ipv4 = .{ 8, 8, 8, 8 } }, 443));
}

test "evaluate honors port qualifier" {
	const rs = parseRules("deny 0.0.0.0/0:25");
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 25));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 26)); // default-deny on no match
}

test "evaluate proto+port qualifier matches narrowly" {
	const rs = parseRules(
		\\allow tcp 0.0.0.0/0:443
		\\deny 0.0.0.0/0
	);
	try std.testing.expectEqual(Action.allow, rs.evaluate(.tcp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.tcp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 80));
	try std.testing.expectEqual(Action.deny, rs.evaluate(.udp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443));
}

test "parseRemapLine basic" {
	const r = parseRemapLine("remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:18080").?;
	try std.testing.expectEqual(Proto.tcp, r.proto);
	try std.testing.expectEqual(@as(u8, 0), r.prefix_len);
	try std.testing.expectEqual(@as(u16, 443), r.port);
	try std.testing.expectEqual(Proto.tcp, r.target.proto);
	try std.testing.expectEqual(@as(u16, 18080), r.target.port);
	try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, r.target.addr.ipv4);
}

test "parseRemapLine narrow source CIDR" {
	const r = parseRemapLine("remap tcp 1.2.3.0/24:80 -> tcp 127.0.0.1:18081").?;
	try std.testing.expectEqual([4]u8{ 1, 2, 3, 0 }, r.network.ipv4);
	try std.testing.expectEqual(@as(u8, 24), r.prefix_len);
}

test "parseRemapLine rejects missing proto, missing port, udp, multi-host target" {
	try std.testing.expect(parseRemapLine("remap 0.0.0.0/0:443 -> tcp 127.0.0.1:8080") == null);
	try std.testing.expect(parseRemapLine("remap tcp 0.0.0.0/0 -> tcp 127.0.0.1:8080") == null);
	try std.testing.expect(parseRemapLine("remap udp 0.0.0.0/0:53 -> udp 127.0.0.1:1053") == null);
	try std.testing.expect(parseRemapLine("remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.0/24:8080") == null);
	try std.testing.expect(parseRemapLine("remap tcp 0.0.0.0/0:443") == null);
}

test "evaluateRemap returns target on match, null otherwise" {
	const rs = parseRules("remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:18080");
	const tgt = rs.evaluateRemap(.tcp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443).?;
	try std.testing.expectEqual(@as(u16, 18080), tgt.port);
	try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, tgt.addr.ipv4);
	try std.testing.expect(rs.evaluateRemap(.tcp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 80) == null);
	try std.testing.expect(rs.evaluateRemap(.udp, .{ .ipv4 = .{ 1, 2, 3, 4 } }, 443) == null);
}

test "parseRules mixes CIDR + remap + DNS into three tables" {
	const rs = parseRules(
		\\allow 10.0.0.0/8
		\\remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:18080
		\\dns default deny
		\\dns allow api.anthropic.com
	);
	try std.testing.expectEqual(@as(usize, 1), rs.len);
	try std.testing.expectEqual(@as(usize, 1), rs.remap_len);
	try std.testing.expectEqual(@as(usize, 1), rs.dns_len);
}

// --- isLoopback / isHardBlocked ---

test "isLoopback v4/v6/mapped" {
	try std.testing.expect(isLoopback(.{ .ipv4 = .{ 127, 0, 0, 1 } }));
	try std.testing.expect(isLoopback(.{ .ipv4 = .{ 127, 9, 9, 9 } }));
	try std.testing.expect(!isLoopback(.{ .ipv4 = .{ 8, 8, 8, 8 } }));
	try std.testing.expect(isLoopback(.{ .ipv6 = ipv6_loopback }));
	const mapped_lo = IpAddr{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 } };
	try std.testing.expect(isLoopback(mapped_lo));
}

test "isHardBlocked: loopback/this-net/link-local only; private ranges deferred to CIDR" {
	// Hard-blocked (non-overridable): loopback, this-network, link-local/metadata.
	try std.testing.expect(isHardBlocked(.{ .ipv4 = .{ 127, 0, 0, 1 } }));
	try std.testing.expect(isHardBlocked(.{ .ipv4 = .{ 0, 0, 0, 0 } }));
	try std.testing.expect(isHardBlocked(.{ .ipv4 = .{ 169, 254, 169, 254 } }));
	// v4-mapped metadata
	try std.testing.expect(isHardBlocked(.{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 169, 254, 169, 254 } }));
	// v6 loopback / unspecified / link-local
	try std.testing.expect(isHardBlocked(.{ .ipv6 = ipv6_loopback }));
	try std.testing.expect(isHardBlocked(.{ .ipv6 = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }));

	// NOT hard-blocked: RFC1918 / CGNAT / ULA -- governed by the instance CIDR
	// policy (default-denied by seeded rules, reachable via an explicit allow).
	try std.testing.expect(!isHardBlocked(.{ .ipv4 = .{ 10, 1, 2, 3 } }));
	try std.testing.expect(!isHardBlocked(.{ .ipv4 = .{ 172, 16, 5, 5 } }));
	try std.testing.expect(!isHardBlocked(.{ .ipv4 = .{ 192, 168, 1, 1 } }));
	try std.testing.expect(!isHardBlocked(.{ .ipv4 = .{ 100, 64, 0, 1 } }));
	try std.testing.expect(!isHardBlocked(.{ .ipv6 = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }));

	// Public addresses always pass.
	try std.testing.expect(!isHardBlocked(.{ .ipv4 = .{ 1, 1, 1, 1 } }));
	try std.testing.expect(!isHardBlocked(.{ .ipv4 = .{ 93, 184, 216, 34 } }));
	try std.testing.expect(!isHardBlocked(.{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }));
}

// --- hard-deny: the per-instance extension of that floor ---
//
// The built-in floor cannot know the enclosing host's own address, and an
// explicit L7 `allow` supersedes the L4 CIDR re-check -- so a sandbox owner who
// controls a DNS zone can point a name at the machine running the proxy, allow
// that name, and obtain a guest-triggered connection into the host half under
// the PROXY's uid. `hard-deny` closes that without depending on nftables
// so the property does not rest on nftables alone.

test "parseRules parses hard-deny into the per-instance floor" {
	const rs = parseRules(
		\\hard-deny 10.0.0.7/32
		\\hard-deny 10.0.4.0/24
		\\allow 0.0.0.0/0
	);
	try std.testing.expectEqual(@as(usize, 2), rs.hard_len);
	// hard-deny is a floor, not a rule: it does not enter the ordered walk.
	try std.testing.expectEqual(@as(usize, 1), rs.len);
	try std.testing.expectEqual(Action.allow, rs.evaluate(.tcp, .{ .ipv4 = .{ 10, 0, 0, 7 } }, 443));
}

test "hard-deny accepts a bare address and means that single host" {
	const rs = parseRules("hard-deny 10.0.0.7");
	try std.testing.expectEqual(@as(usize, 1), rs.hard_len);
	try std.testing.expect(rs.hardBlocked(.{ .ipv4 = .{ 10, 0, 0, 7 } }));
	try std.testing.expect(!rs.hardBlocked(.{ .ipv4 = .{ 10, 0, 0, 8 } }));
}

test "hardBlocked matches an in-range address and its v4-mapped form" {
	const rs = parseRules("hard-deny 10.0.4.0/24");
	try std.testing.expect(rs.hardBlocked(.{ .ipv4 = .{ 10, 0, 4, 21 } }));
	try std.testing.expect(rs.hardBlocked(.{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 4, 21 } }));
	// A neighbouring address outside the rendered set stays reachable: the
	// floor is the VM's OWN addresses, not its whole subnet.
	try std.testing.expect(!rs.hardBlocked(.{ .ipv4 = .{ 10, 0, 5, 21 } }));
}

test "hardBlocked over IPv6 hard-deny" {
	const rs = parseRules("hard-deny 2001:db8::/32");
	try std.testing.expect(rs.hardBlocked(.{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 } }));
	try std.testing.expect(!rs.hardBlocked(.{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 } }));
}

test "hardBlocked with no hard-deny lines is exactly isHardBlocked" {
	// The default-preserving guarantee for the local and k8s backends, which
	// render no hard-deny line: the ruleset-aware floor must not block one
	// address more than the built-in one.
	const rs = parseRules("allow 0.0.0.0/0");
	try std.testing.expectEqual(@as(usize, 0), rs.hard_len);
	const probes = [_]IpAddr{
		.{ .ipv4 = .{ 127, 0, 0, 1 } },
		.{ .ipv4 = .{ 169, 254, 169, 254 } },
		.{ .ipv4 = .{ 10, 1, 2, 3 } },
		.{ .ipv4 = .{ 1, 1, 1, 1 } },
		.{ .ipv6 = ipv6_loopback },
		.{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
	};
	for (probes) |p| try std.testing.expectEqual(isHardBlocked(p), rs.hardBlocked(p));
}

test "hard-deny leaves the loopback remap funnel alone" {
	// The L7 funnel is a shim-side connect() rewrite to 127.0.0.1:<l7base>,
	// and the proxy's own backend hop is loopback too. Those never pass
	// through hardBlocked (the proxy dials them directly), but assert the
	// intent anyway: rendering the VM's own address must not change how
	// loopback is treated relative to the built-in floor.
	const rs = parseRules("hard-deny 10.0.0.7/32");
	try std.testing.expect(rs.hardBlocked(.{ .ipv4 = .{ 127, 0, 0, 1 } })); // built-in, unchanged
	try std.testing.expect(isHardBlocked(.{ .ipv4 = .{ 127, 0, 0, 1 } }));
	try std.testing.expect(!isHardBlocked(.{ .ipv4 = .{ 10, 0, 0, 7 } })); // ONLY the ruleset-aware form catches it
}

test "hard-deny rejects malformed bodies and never partially applies" {
	try std.testing.expectEqual(@as(usize, 0), parseRules("hard-deny").hard_len);
	try std.testing.expectEqual(@as(usize, 0), parseRules("hard-deny ").hard_len);
	try std.testing.expectEqual(@as(usize, 0), parseRules("hard-deny not-an-ip").hard_len);
	try std.testing.expectEqual(@as(usize, 0), parseRules("hard-deny 10.0.0.7/33").hard_len);
	// A floor entry must not be narrowable to a proto or a port -- a
	// port-scoped "floor" is a rule wearing a floor's name.
	try std.testing.expectEqual(@as(usize, 0), parseRules("hard-deny tcp 10.0.0.7/32").hard_len);
	try std.testing.expectEqual(@as(usize, 0), parseRules("hard-deny 10.0.0.7:443").hard_len);
	// An unparseable line is dropped like any other, leaving the rest intact.
	const rs = parseRules(
		\\hard-deny nonsense
		\\hard-deny 10.0.0.7/32
	);
	try std.testing.expectEqual(@as(usize, 1), rs.hard_len);
}

test "hard-deny is capped at max_hard_rules without corrupting the set" {
	var buf: [64 * (max_hard_rules + 4)]u8 = undefined;
	var n: usize = 0;
	var i: usize = 0;
	while (i < max_hard_rules + 4) : (i += 1) {
		const line = try std.fmt.bufPrint(buf[n..], "hard-deny 10.0.0.{d}/32\n", .{i});
		n += line.len;
	}
	const rs = parseRules(buf[0..n]);
	try std.testing.expectEqual(max_hard_rules, rs.hard_len);
	try std.testing.expect(rs.hardBlocked(.{ .ipv4 = .{ 10, 0, 0, 0 } }));
}

// --- L7 rules ---

test "pathPrefixMatches boundary-aware" {
	try std.testing.expect(pathPrefixMatches("/api", "/api"));
	try std.testing.expect(pathPrefixMatches("/api", "/api/"));
	try std.testing.expect(pathPrefixMatches("/api", "/api/v1"));
	try std.testing.expect(!pathPrefixMatches("/api", "/apifoo"));
	try std.testing.expect(!pathPrefixMatches("/api", "/ap"));
	try std.testing.expect(pathPrefixMatches("/v1/", "/v1/x"));
	try std.testing.expect(pathPrefixMatches("/v1/", "/v1/"));
	try std.testing.expect(!pathPrefixMatches("/v1/", "/v1"));
}

test "L7 evaluate first-match: allow / deny / no_match" {
	var rs: L7RuleSet = undefined;
	parseL7Rules(
		\\mode passthrough
		\\allow vhost-a.test
		\\allow *.cdn.test
		\\deny telemetry.test
	, &rs);
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("vhost-a.test", null));
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("x.cdn.test", null));
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluate("telemetry.test", null));
	// a sibling not in any rule is NO_MATCH -> the proxy defers to L4
	// (so allowing vhost-a does not by itself grant vhost-b; vhost-b is only
	// reachable if its IP is L4-allowed)
	try std.testing.expectEqual(L7Verdict.no_match, rs.evaluate("vhost-b.test", null));
	// trailing root dot is stripped
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("vhost-a.test.", null));
	try std.testing.expect(!rs.mode_terminate);
}

test "L7 evaluate no_match falls through (no implicit deny)" {
	var rs: L7RuleSet = undefined;
	parseL7Rules("allow only.test", &rs);
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("only.test", null));
	try std.testing.expectEqual(L7Verdict.no_match, rs.evaluate("other.test", null));
}

test "L7 explicit deny * supersedes L4 (catch-all)" {
	var rs: L7RuleSet = undefined;
	parseL7Rules(
		\\allow a.test
		\\deny *
	, &rs);
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("a.test", null));
	// deny * makes everything else an explicit deny, not no_match
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluate("b.test", null));
}

test "L7 path rules + needsTerminate" {
	var rs: L7RuleSet = undefined;
	parseL7Rules(
		\\mode passthrough
		\\allow api.example.com /v1/ terminate
		\\allow plain.test
		\\deny *
	, &rs);
	// host with a path rule needs the terminating tier; a plain allow doesn't
	try std.testing.expect(rs.needsTerminate("api.example.com"));
	try std.testing.expect(!rs.needsTerminate("plain.test"));
	// an unlisted host is never terminated (passthrough / L4)
	try std.testing.expect(!rs.needsTerminate("unlisted.test"));
	// path enforcement: only /v1/* allowed for api.example.com
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("api.example.com", "/v1/x"));
	// /v2/x doesn't match the path rule, but `deny *` catches it
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluate("api.example.com", "/v2/x"));
}

test "L7 path fail-closed: allow-host + uncovered path is deny, not no_match" {
	var rs: L7RuleSet = undefined;
	// No catch-all `deny *` -- the supersede setup relies on no_match
	// deferring to L4, so a path miss must NOT silently defer to an
	// L4-allowed IP. An allow rule named the host, so an uncovered path
	// fails closed.
	parseL7Rules(
		\\allow api.example.com /v1/ terminate
		\\allow plain.test
	, &rs);
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("api.example.com", "/v1/sub"));
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluate("api.example.com", "/v2/x"));
	// host with no path constraint is still a clean allow
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("plain.test", "/anything"));
	// a wholly unlisted host stays no_match (defers to L4)
	try std.testing.expectEqual(L7Verdict.no_match, rs.evaluate("other.test", "/v1/"));
}

test "L7 deny-path rule does not fail closed for other paths" {
	var rs: L7RuleSet = undefined;
	// `deny api.example.com /admin/` blocks only /admin/; other paths
	// defer to L4 (no_match), because no allow rule names the host.
	parseL7Rules(
		\\deny api.example.com /admin/ terminate
	, &rs);
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluate("api.example.com", "/admin/panel"));
	try std.testing.expectEqual(L7Verdict.no_match, rs.evaluate("api.example.com", "/public/"));
}

test "l7PortsForBase: contiguous triple, no cross-instance overlap" {
	const a = l7PortsForBase(l7_default_base); // default instance
	try std.testing.expectEqual(@as(u16, 18443), a.tls);
	try std.testing.expectEqual(@as(u16, 18444), a.http);
	try std.testing.expectEqual(@as(u16, 18445), a.mitm);
	// next instance's base is +3, so its triple is disjoint from the default's
	const b = l7PortsForBase(l7_default_base + 3);
	try std.testing.expectEqual(@as(u16, 18446), b.tls);
	try std.testing.expectEqual(@as(u16, 18448), b.mitm);
	try std.testing.expect(b.tls > a.mitm); // no overlap
}

test "l7AuthPortForBase: downward -400 offset, disjoint across instances, refuses a low base" {
	try std.testing.expectEqual(@as(?u16, 18043), l7AuthPortForBase(l7_default_base)); // 18443 -> 18043
	// two consecutive instances (stride 3): their auth ports stay disjoint, and
	// well below their triple bands.
	const a = l7AuthPortForBase(l7_default_base).?;
	const b = l7AuthPortForBase(l7_default_base + 3).?;
	try std.testing.expectEqual(@as(u16, 18046), b);
	try std.testing.expect(b > a);
	try std.testing.expect(a < l7PortsForBase(l7_default_base).tls); // the auth band is below the triple band
	// a base at or below 1424 has no safe downward offset and is refused.
	try std.testing.expectEqual(@as(?u16, null), l7AuthPortForBase(1424));
	try std.testing.expectEqual(@as(?u16, null), l7AuthPortForBase(400));
	try std.testing.expectEqual(@as(?u16, null), l7AuthPortForBase(0));
	try std.testing.expectEqual(@as(?u16, 1025), l7AuthPortForBase(1425)); // first accepted base
}

test "L7 mode terminate floor applies to matched allow hosts only" {
	var rs: L7RuleSet = undefined;
	parseL7Rules(
		\\mode terminate
		\\allow a.test
	, &rs);
	try std.testing.expect(rs.mode_terminate);
	try std.testing.expect(rs.needsTerminate("a.test"));
	// unlisted host is NOT terminated even under the mode floor
	try std.testing.expect(!rs.needsTerminate("unlisted.test"));
}

test "L7 terminate-by-default + passthrough opt-out + harness safety" {
	var rs: L7RuleSet = undefined;
	// No mode line -> the instance default tier is TERMINATE.
	parseL7Rules(
		\\allow plain.test
		\\allow pinned.test passthrough
		\\allow api.anthropic.com
		\\allow api.deepseek.com
		\\allow api.openai.com terminate
	, &rs);
	try std.testing.expect(rs.mode_terminate); // default tier is terminate
	// a bare allow host is terminated by default
	try std.testing.expect(rs.needsTerminate("plain.test"));
	// --passthrough opts a host out (cert-pinning escape)
	try std.testing.expect(!rs.needsTerminate("pinned.test"));
	// a harness API endpoint stays passthrough automatically...
	try std.testing.expect(!rs.needsTerminate("api.anthropic.com"));
	try std.testing.expect(!rs.needsTerminate("api.deepseek.com"));
	try std.testing.expect(isHarnessPassthroughHost("API.Anthropic.Com")); // case-insensitive
	// ...unless explicitly --terminate'd
	try std.testing.expect(rs.needsTerminate("api.openai.com"));
	// unlisted host is never terminated
	try std.testing.expect(!rs.needsTerminate("unlisted.test"));
}

test "L7 mode passthrough flips the default back" {
	var rs: L7RuleSet = undefined;
	parseL7Rules(
		\\mode passthrough
		\\allow plain.test
		\\allow api.test /v1/ terminate
	, &rs);
	try std.testing.expect(!rs.mode_terminate);
	try std.testing.expect(!rs.needsTerminate("plain.test")); // passthrough default
	try std.testing.expect(rs.needsTerminate("api.test")); // explicit terminate still wins
}

test "parseL7Line rejects malformed" {
	try std.testing.expect(parseL7Line("") == .none);
	try std.testing.expect(parseL7Line("# comment") == .none);
	try std.testing.expect(parseL7Line("allow") == .none); // no host
	try std.testing.expect(parseL7Line("allow *.foo.*") == .none); // bad pattern
	try std.testing.expect(parseL7Line("allow a.test bogustoken") == .none);
	try std.testing.expect(parseL7Line("mode sideways") == .none);
	const r = parseL7Line("allow a.test /p/ terminate");
	try std.testing.expect(r == .rule);
	try std.testing.expect(r.rule.terminate);
	try std.testing.expectEqualStrings("/p/", r.rule.pathSlice().?);
}

test "parseL7Line insecure token + needsTerminate" {
	// `insecure` parses, is order-independent, and on its own implies the
	// terminate tier (it only governs the proxy<->upstream TLS leg).
	const r = parseL7Line("allow internal.svc insecure");
	try std.testing.expect(r == .rule);
	try std.testing.expect(r.rule.insecure_upstream);
	try std.testing.expect(!r.rule.has_path);

	const r2 = parseL7Line("allow internal.svc /api/ insecure terminate");
	try std.testing.expect(r2 == .rule);
	try std.testing.expect(r2.rule.insecure_upstream);
	try std.testing.expect(r2.rule.terminate);
	try std.testing.expectEqualStrings("/api/", r2.rule.pathSlice().?);

	// a host whose only flag is `insecure` (no path, no explicit terminate)
	// is still routed through the terminating tier.
	var rs: L7RuleSet = undefined;
	parseL7Rules("allow internal.svc insecure", &rs);
	try std.testing.expect(rs.needsTerminate("internal.svc"));
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluate("internal.svc", null));
}

test "parseL7Line: method / exact / service tokens parse, garbage still rejected" {
	// A single method.
	{
		const r = parseL7Line("allow git.example.internal GET /g/p.git/info/refs exact service=git-upload-pack");
		try std.testing.expect(r == .rule);
		try std.testing.expectEqualStrings("GET", r.rule.methodsSlice().?);
		try std.testing.expect(r.rule.exact);
		try std.testing.expectEqualStrings("git-upload-pack", r.rule.serviceSlice().?);
		try std.testing.expectEqualStrings("/g/p.git/info/refs", r.rule.pathSlice().?);
	}
	// A comma method list, order-independent tokens.
	{
		const r = parseL7Line("allow git.example.internal /g/ service=git-upload-pack GET,POST");
		try std.testing.expect(r == .rule);
		try std.testing.expectEqualStrings("GET,POST", r.rule.methodsSlice().?);
		try std.testing.expectEqualStrings("git-upload-pack", r.rule.serviceSlice().?);
		try std.testing.expect(!r.rule.exact);
	}
	// Back-compat: a bare allow parses with all new fields empty.
	{
		const r = parseL7Line("allow plain.test");
		try std.testing.expect(r == .rule);
		try std.testing.expect(r.rule.methodsSlice() == null);
		try std.testing.expect(r.rule.serviceSlice() == null);
		try std.testing.expect(!r.rule.exact);
	}
	// A genuinely-unknown (lowercase, non-keyword) token still rejects the line.
	try std.testing.expect(parseL7Line("allow a.test bogustoken") == .none);
	// A bare `service=` with no value rejects.
	try std.testing.expect(parseL7Line("allow a.test service=") == .none);
	// Duplicate method / service tokens reject.
	try std.testing.expect(parseL7Line("allow a.test GET POST") == .none);
	try std.testing.expect(parseL7Line("allow a.test service=x service=y") == .none);
}

test "parseL7Line: tag= token is tolerated + parse-identical; lookalike still rejects" {
	// The proxy does not gate injection (the addon does); it accepts and IGNORES
	// `tag=`, so a tagged line parses byte-for-byte like the same line without it.
	const tagged = parseL7Line("allow git.example.internal GET /g/ tag=git-grants");
	const plain = parseL7Line("allow git.example.internal GET /g/");
	try std.testing.expect(tagged == .rule);
	try std.testing.expect(plain == .rule);
	try std.testing.expectEqual(plain.rule.action, tagged.rule.action);
	try std.testing.expectEqual(plain.rule.has_path, tagged.rule.has_path);
	try std.testing.expectEqualStrings(plain.rule.pathSlice().?, tagged.rule.pathSlice().?);
	try std.testing.expectEqualStrings(plain.rule.methodsSlice().?, tagged.rule.methodsSlice().?);
	try std.testing.expect(tagged.rule.serviceSlice() == null);
	try std.testing.expect(!tagged.rule.exact);
	// The `tag=` prefix guard is tight: a lookalike token (char 3 is `x`, not `=`)
	// is genuinely-unknown and still fails closed.
	try std.testing.expect(parseL7Line("allow a.test tagx=foo") == .none);
	// A doc with one tagged + one bogus line keeps the tagged rule, drops the bogus.
	var rs: L7RuleSet = undefined;
	parseL7Rules("allow git.example.internal GET /g/ tag=git-grants\nallow bad.test bogustoken\n", &rs);
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluateFull("git.example.internal", "/g/x", "GET"));
	// the bogus line was dropped -> its host has no rule at all (no_match).
	try std.testing.expectEqual(L7Verdict.no_match, rs.evaluateFull("bad.test", "/", "GET"));
}

test "effectiveGitService: endpoint-derived from the final path segment" {
	try std.testing.expectEqualStrings("git-upload-pack", effectiveGitService("/g/p.git/git-upload-pack").?);
	try std.testing.expectEqualStrings("git-receive-pack", effectiveGitService("/g/p.git/git-receive-pack").?);
	// info/refs carries the service in the (stripped) query -> not derivable here.
	try std.testing.expect(effectiveGitService("/g/p.git/info/refs") == null);
	try std.testing.expect(effectiveGitService("/g/p.git/") == null);
}

test "L7 evaluateFull: methods + exact + endpoint-derived service" {
	var rs: L7RuleSet = undefined;
	// git-read (exact) + git-write (exact) for one repo, compiled the way cogworx does.
	parseL7Rules(
		\\allow git.example.internal GET /g/p.git/info/refs exact service=git-upload-pack
		\\allow git.example.internal POST /g/p.git/git-upload-pack exact
		\\allow git.example.internal GET /g/p.git/info/refs exact service=git-receive-pack
		\\allow git.example.internal POST /g/p.git/git-receive-pack exact
	, &rs);
	// Git host always terminates (it carries paths).
	try std.testing.expect(rs.needsTerminate("git.example.internal"));
	// Clone POST allowed; push POST allowed (separate grant here).
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluateFull("git.example.internal", "/g/p.git/git-upload-pack", "POST"));
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluateFull("git.example.internal", "/g/p.git/git-receive-pack", "POST"));
	// Wrong method on the pack endpoint fails closed (host named -> deny).
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluateFull("git.example.internal", "/g/p.git/git-upload-pack", "GET"));
	// exact path: a sibling/extension path under the same prefix is NOT allowed.
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluateFull("git.example.internal", "/g/p.git/git-upload-pack/extra", "POST"));
	// info/refs over cleartext: the service is query-only (stripped) so endpoint
	// derivation yields null and the service= rule can't match -> fail closed.
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluateFull("git.example.internal", "/g/p.git/info/refs", "GET"));
}

test "L7 wildcard git-read: prefix + service denies push (git-receive-pack) under the same prefix" {
	var rs: L7RuleSet = undefined;
	parseL7Rules(
		\\allow git.example.internal GET /grp/ service=git-upload-pack
		\\allow git.example.internal POST /grp/ service=git-upload-pack
	, &rs);
	// A clone POST anywhere under the group is allowed (upload-pack endpoint).
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluateFull("git.example.internal", "/grp/proj.git/git-upload-pack", "POST"));
	// A push POST under the same prefix is DENIED: endpoint-derived service is
	// git-receive-pack, which no rule allows -> fail closed.
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluateFull("git.example.internal", "/grp/proj.git/git-receive-pack", "POST"));
}

test "L7 evaluateFull: unknown method (null) skips a method-constrained rule" {
	var rs: L7RuleSet = undefined;
	parseL7Rules("allow a.test POST /p", &rs);
	// method known + matching -> allow
	try std.testing.expectEqual(L7Verdict.allow, rs.evaluateFull("a.test", "/p", "POST"));
	// method unknown (e.g. TLS passthrough) -> can't confirm -> host named,
	// rule skipped -> fail closed deny
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluateFull("a.test", "/p", null));
	// plain 2-arg evaluate delegates with null method (back-compat)
	try std.testing.expectEqual(L7Verdict.deny, rs.evaluate("a.test", "/p"));
}

test "parseInjectHosts: exact-only, drops wildcards, comments, fail-open" {
	var ih: InjectHosts = undefined;
	parseInjectHosts(
		\\# inject hosts, one per line
		\\notes.internal.test
		\\
		\\  *.apps.example
		\\*
		\\*.foo.*
		\\metrics.example
	, &ih);
	// blank line + comment skipped; the wildcard `*.apps.example`, the bare `*`,
	// and the malformed `*.foo.*` are ALL dropped (exact-only) -- so only the 2
	// exact hosts remain. This is the load-bearing guard: a bare `*` must NOT
	// turn into "route every plain-HTTP flow through mitmproxy".
	try std.testing.expectEqual(@as(usize, 2), ih.len);

	// exact match, case-insensitive; a trailing root dot on the QUERY is
	// stripped by contains() (the FILE side rejects trailing dots, as l7-rules
	// does, so we don't test that as a positive).
	try std.testing.expect(ih.contains("notes.internal.test"));
	try std.testing.expect(ih.contains("NOTES.INTERNAL.test"));
	try std.testing.expect(ih.contains("notes.internal.test."));
	try std.testing.expect(ih.contains("metrics.example"));
	try std.testing.expect(!ih.contains("other.internal.test"));

	// the dropped wildcard does NOT match a subdomain (it was never admitted),
	// and the dropped bare `*` does NOT match an unrelated host.
	try std.testing.expect(!ih.contains("a.apps.example"));
	try std.testing.expect(!ih.contains("apps.example"));
	try std.testing.expect(!ih.contains("anything.unrelated.test"));

	// empty input -> empty set, contains() never matches
	var empty: InjectHosts = undefined;
	parseInjectHosts("", &empty);
	try std.testing.expectEqual(@as(usize, 0), empty.len);
	try std.testing.expect(!empty.contains("notes.internal.test"));
}
