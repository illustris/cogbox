// Pure TLS ClientHello SNI extraction. No allocation, no IO -- the proxy
// feeds it the bytes it has peeked so far and gets back one of:
//   .sni       -> the cleartext host_name (copied into the caller's out
//                 buffer) plus an `ech` flag noting whether an
//                 encrypted_client_hello extension accompanied it
//   .need_more -> the ClientHello isn't fully buffered yet; read more, retry
//   .no_sni    -> a well-formed ClientHello with no cleartext host_name (no
//                 server_name extension, or one whose list has no host_name
//                 entry) and NO ECH extension. RFC 6066 forbids IP literals in
//                 SNI, so this is what HTTPS to a bare IP looks like; the
//                 worker L4-gates it
//   .deny      -> malformed or unsupported (incl. a hello with no extensions
//                 block at all, and an ECH hello with no outer server_name:
//                 the worker must never treat it as a nameless hello, since
//                 its encrypted inner name could be any vhost on the IP; it
//                 takes the unclassifiable path instead -- see parseClientHello)
//
// We do NOT deny merely because ECH is present: Chrome/Chromium send a GREASE
// ECH extension on every handshake by default, so a blanket deny would drop
// every browser client even though the real SNI is sitting in cleartext right
// beside it. The cleartext SNI *can* be a decoy for an encrypted inner name,
// so the `ech` flag is surfaced for the caller to act on per tier (the worker
// allows ECH on the terminate tier, where mitmproxy enforces Host==SNI on the
// decrypted request, and refuses it on the splice tier, which trusts the
// cleartext SNI for routing).
//
// All length fields are bounds-checked against a hostile guest; every
// out-of-range access yields .deny rather than a panic.

const std = @import("std");

pub const Sni = struct {
	name: []const u8, // aliases the caller's out buffer
	ech: bool, // an ECH extension accompanied this cleartext SNI
};

pub const PeekResult = union(enum) {
	sni: Sni,
	need_more,
	no_sni,
	deny,
};

const rec_handshake: u8 = 0x16;
const hs_client_hello: u8 = 0x01;
const ext_server_name: u16 = 0x0000;
const ext_ech: u16 = 0xfe0d; // encrypted_client_hello (draft-ietf-tls-esni)
const sni_host_name: u8 = 0x00;
const max_handshake: usize = 16 * 1024; // sane ClientHello cap

const Cursor = struct {
	b: []const u8,
	i: usize = 0,

	fn remaining(self: *const Cursor) usize {
		return self.b.len - self.i;
	}
	fn readU8(self: *Cursor) ?u8 {
		if (self.i + 1 > self.b.len) return null;
		const v = self.b[self.i];
		self.i += 1;
		return v;
	}
	fn readU16(self: *Cursor) ?u16 {
		if (self.i + 2 > self.b.len) return null;
		const v = (@as(u16, self.b[self.i]) << 8) | self.b[self.i + 1];
		self.i += 2;
		return v;
	}
	fn skip(self: *Cursor, n: usize) bool {
		if (self.i + n > self.b.len) return false;
		self.i += n;
		return true;
	}
	fn take(self: *Cursor, n: usize) ?[]const u8 {
		if (self.i + n > self.b.len) return null;
		const s = self.b[self.i .. self.i + n];
		self.i += n;
		return s;
	}
};

/// Extract the SNI host_name from a (possibly partial) TLS stream prefix.
/// On `.sni`, the returned slice lives in `out_sni`.
pub fn extractSni(buf: []const u8, out_sni: []u8) PeekResult {
	// Reassemble the ClientHello handshake message, which MAY be fragmented
	// across multiple TLS handshake records. We copy record payloads into a
	// contiguous scratch so the rest of the parse can index linearly.
	var scratch: [max_handshake]u8 = undefined;
	var filled: usize = 0;
	var off: usize = 0;

	while (true) {
		if (off + 5 > buf.len) return .need_more; // need full record header
		const ctype = buf[off];
		const ver_major = buf[off + 1];
		const ver_minor = buf[off + 2];
		const rlen = (@as(usize, buf[off + 3]) << 8) | buf[off + 4];

		if (ctype != rec_handshake) return .deny; // only handshake records expected
		if (off == 0) {
			// legacy_record_version: 0x03 0x01..0x04 (TLS 1.0..1.3 record framing)
			if (ver_major != 0x03 or ver_minor < 0x01 or ver_minor > 0x04) return .deny;
		}
		if (rlen == 0) return .deny;
		if (off + 5 + rlen > buf.len) return .need_more; // record body still arriving

		if (filled + rlen > scratch.len) return .deny; // ClientHello too large
		@memcpy(scratch[filled .. filled + rlen], buf[off + 5 .. off + 5 + rlen]);
		filled += rlen;
		off += 5 + rlen;

		if (filled >= 4) {
			if (scratch[0] != hs_client_hello) return .deny;
			const hlen = (@as(usize, scratch[1]) << 16) |
				(@as(usize, scratch[2]) << 8) | scratch[3];
			const need = 4 + hlen;
			if (need > scratch.len) return .deny;
			if (filled >= need) return parseClientHello(scratch[4..need], out_sni);
			// otherwise keep consuming records (loop re-checks buf bounds)
		}
	}
}

fn parseClientHello(body: []const u8, out_sni: []u8) PeekResult {
	var c = Cursor{ .b = body };
	if (!c.skip(2 + 32)) return .deny; // client_version + random
	const sid_len = c.readU8() orelse return .deny;
	if (!c.skip(sid_len)) return .deny; // session_id
	const cs_len = c.readU16() orelse return .deny;
	if (!c.skip(cs_len)) return .deny; // cipher_suites
	const cm_len = c.readU8() orelse return .deny;
	if (!c.skip(cm_len)) return .deny; // compression_methods

	const ext_total = c.readU16() orelse return .deny;
	const ext_bytes = c.take(ext_total) orelse return .deny;

	var ec = Cursor{ .b = ext_bytes };
	var found: ?[]const u8 = null;
	var ech = false;
	// 1-3 trailing bytes after the last complete extension header are ignored
	// (pre-existing leniency; a .no_sni result is still bounded by the L4 gate).
	while (ec.remaining() >= 4) {
		const etype = ec.readU16().?;
		const elen = ec.readU16().?;
		const edata = ec.take(elen) orelse return .deny;
		// Note ECH but keep parsing: the cleartext SNI is still extracted and
		// the caller decides what to do with an ECH-bearing hello per tier
		// (the inner name could be a denied sibling, so the splice path refuses
		// it; terminate is safe because mitmproxy re-checks Host==SNI).
		if (etype == ext_ech) ech = true;
		if (etype == ext_server_name and found == null) {
			found = parseServerName(edata) catch return .deny;
		}
	}

	// No cleartext host_name. With ECH present the client may be naming any
	// vhost on the IP in its encrypted inner hello -- including an L7-denied
	// sibling -- and the L4-only splice could not see that deny, so it stays
	// .deny (the passthrough tier refuses ECH for the same reason). Without ECH
	// the hello is well-formed and nameless: the worker L4-gates it.
	const name = found orelse return if (ech) .deny else .no_sni;
	if (name.len == 0 or name.len > out_sni.len) return .deny; // empty HostName violates RFC 6066 (malformed); oversize is unsupported
	@memcpy(out_sni[0..name.len], name);
	return .{ .sni = .{ .name = out_sni[0..name.len], .ech = ech } };
}

/// null = well-formed list with no host_name entry; error = the list's lengths do not fit.
fn parseServerName(data: []const u8) error{Malformed}!?[]const u8 {
	var c = Cursor{ .b = data };
	const list_len = c.readU16() orelse return error.Malformed;
	const list = c.take(list_len) orelse return error.Malformed;
	var lc = Cursor{ .b = list };
	// 1-2 trailing bytes after the last complete entry are ignored (same leniency).
	while (lc.remaining() >= 3) {
		const ntype = lc.readU8().?;
		const nlen = lc.readU16().?;
		const name = lc.take(nlen) orelse return error.Malformed;
		if (ntype == sni_host_name) return name;
	}
	return null;
}

// --- Tests ---

const t = std.testing;

// Build a minimal TLS record-wrapped ClientHello whose extensions block is the
// raw `ext` blob (already-encoded extension entries; may be empty). Lets a test
// hand-craft a server_name extension the higher-level builder can't express
// (empty list, non-host_name entry, overrunning lengths).
fn buildHelloExt(buf: []u8, ext: []const u8) []u8 {
	var hs: [1024]u8 = undefined;
	var n: usize = 0;
	// ClientHello body
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
	// extensions: length + the caller's raw blob
	hs[n] = @intCast((ext.len >> 8) & 0xff);
	hs[n + 1] = @intCast(ext.len & 0xff);
	n += 2;
	@memcpy(hs[n .. n + ext.len], ext);
	n += ext.len;

	// Wrap in handshake header
	var msg: [1100]u8 = undefined;
	msg[0] = hs_client_hello;
	msg[1] = @intCast((n >> 16) & 0xff);
	msg[2] = @intCast((n >> 8) & 0xff);
	msg[3] = @intCast(n & 0xff);
	@memcpy(msg[4 .. 4 + n], hs[0..n]);
	const msg_len = 4 + n;

	// Wrap in TLS record
	buf[0] = rec_handshake;
	buf[1] = 0x03;
	buf[2] = 0x01;
	buf[3] = @intCast((msg_len >> 8) & 0xff);
	buf[4] = @intCast(msg_len & 0xff);
	@memcpy(buf[5 .. 5 + msg_len], msg[0..msg_len]);
	return buf[0 .. 5 + msg_len];
}

// Build a minimal TLS record-wrapped ClientHello. `server_name` is emitted as
// an SNI extension unless empty; `with_ech` adds a stub ECH extension.
fn buildHello(buf: []u8, server_name: []const u8, with_ech: bool) []u8 {
	var ext: [512]u8 = undefined;
	var n: usize = 0;
	// server_name extension (omitted when server_name is empty)
	if (server_name.len > 0) {
		const sni_inner = 2 + 1 + 2 + server_name.len; // list_len + type + name_len + name
		ext[n] = 0x00;
		ext[n + 1] = 0x00;
		n += 2; // ext type server_name
		ext[n] = @intCast((sni_inner >> 8) & 0xff);
		ext[n + 1] = @intCast(sni_inner & 0xff);
		n += 2; // ext data len
		const list_len = 1 + 2 + server_name.len;
		ext[n] = @intCast((list_len >> 8) & 0xff);
		ext[n + 1] = @intCast(list_len & 0xff);
		n += 2; // server_name_list length
		ext[n] = 0x00;
		n += 1; // name_type host_name
		ext[n] = @intCast((server_name.len >> 8) & 0xff);
		ext[n + 1] = @intCast(server_name.len & 0xff);
		n += 2; // name length
		@memcpy(ext[n .. n + server_name.len], server_name);
		n += server_name.len;
	}
	if (with_ech) {
		ext[n] = 0xfe;
		ext[n + 1] = 0x0d;
		n += 2; // ext type ECH
		ext[n] = 0x00;
		ext[n + 1] = 0x01;
		n += 2; // ext data len 1
		ext[n] = 0x00;
		n += 1;
	}
	return buildHelloExt(buf, ext[0..n]);
}

test "extractSni single record" {
	var raw: [1200]u8 = undefined;
	const hello = buildHello(&raw, "vhost-a.test", false);
	var out: [256]u8 = undefined;
	const r = extractSni(hello, &out);
	try t.expect(r == .sni);
	try t.expectEqualStrings("vhost-a.test", r.sni.name);
	try t.expect(!r.sni.ech);
}

test "extractSni need_more on truncation" {
	var raw: [1200]u8 = undefined;
	const hello = buildHello(&raw, "vhost-a.test", false);
	var out: [256]u8 = undefined;
	// chop the last few bytes -> incomplete record body
	const r = extractSni(hello[0 .. hello.len - 4], &out);
	try t.expect(r == .need_more);
}

test "extractSni reports ECH alongside a cleartext SNI (does not deny)" {
	// Chrome's default GREASE ECH lands here: the real name is in cleartext, so
	// we return it with .ech = true and let the worker decide per tier. A
	// blanket deny here would drop every Chromium client.
	var raw: [1200]u8 = undefined;
	const hello = buildHello(&raw, "vhost-a.test", true);
	var out: [256]u8 = undefined;
	const r = extractSni(hello, &out);
	try t.expect(r == .sni);
	try t.expectEqualStrings("vhost-a.test", r.sni.name);
	try t.expect(r.sni.ech);
}

test "extractSni denies ECH with no cleartext SNI (never .no_sni)" {
	// Pure-ECH hello (no outer server_name): the encrypted inner hello could
	// name an L7-denied vhost on the IP, and the L4-only no-SNI splice could
	// not see that deny. So it must stay .deny, not .no_sni.
	var raw: [1200]u8 = undefined;
	const hello = buildHello(&raw, "", true);
	var out: [256]u8 = undefined;
	try t.expect(extractSni(hello, &out) == .deny);
}

test "extractSni denies non-handshake record" {
	const bogus = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5 };
	var out: [256]u8 = undefined;
	try t.expect(extractSni(&bogus, &out) == .deny);
}

test "extractSni denies malformed length (no OOB)" {
	// handshake record claiming a huge inner length but truncated
	const bad = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x06, 0x01, 0xff, 0xff, 0xff, 0x00, 0x00 };
	var out: [256]u8 = undefined;
	const r = extractSni(&bad, &out);
	try t.expect(r == .deny or r == .need_more);
}

test "extractSni no-extensions hello is .no_sni" {
	// A hello with no extensions at all (and thus no SNI) is well-formed but
	// carries no vhost: HTTPS to an IP literal looks like this.
	var raw: [1200]u8 = undefined;
	const hello = buildHello(&raw, "", false);
	var out: [256]u8 = undefined;
	try t.expect(extractSni(hello, &out) == .no_sni);
}

test "extractSni empty server_name list is .no_sni" {
	// server_name ext (type 0, ext_len 2) carrying a zero-length list.
	var raw: [1200]u8 = undefined;
	const hello = buildHelloExt(&raw, &[_]u8{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00 });
	var out: [256]u8 = undefined;
	try t.expect(extractSni(hello, &out) == .no_sni);
}

test "extractSni server_name list with no host_name entry is .no_sni" {
	// One entry of name_type 1 (not host_name): well-formed, nothing to route on.
	var raw: [1200]u8 = undefined;
	const hello = buildHelloExt(&raw, &[_]u8{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x01, 0x00, 0x01, 'A' });
	var out: [256]u8 = undefined;
	try t.expect(extractSni(hello, &out) == .no_sni);
}

test "extractSni malformed server_name list is .deny, not .no_sni" {
	// list_len 9 overruns the 2 remaining bytes of the extension.
	var raw: [1200]u8 = undefined;
	const hello = buildHelloExt(&raw, &[_]u8{ 0x00, 0x00, 0x00, 0x04, 0x00, 0x09, 0x00, 0x00 });
	var out: [256]u8 = undefined;
	try t.expect(extractSni(hello, &out) == .deny);
}

test "extractSni empty host_name is .deny" {
	// A zero-length HostName violates RFC 6066: malformed, never .no_sni.
	var raw: [1200]u8 = undefined;
	const hello = buildHelloExt(&raw, &[_]u8{ 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00 });
	var out: [256]u8 = undefined;
	try t.expect(extractSni(hello, &out) == .deny);
}

// A server_name extension with an empty list, and one carrying host_name
// "vhost-a.test" (ext_len 17, list_len 15, name_len 12), for the duplicate
// extension tests below.
const sni_ext_empty = [_]u8{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00 };
const sni_ext_named = [_]u8{ 0x00, 0x00, 0x00, 0x11, 0x00, 0x0f, 0x00, 0x00, 0x0c } ++ "vhost-a.test".*;

test "extractSni uses a later server_name extension when the first has no host_name" {
	// The loop keeps `found` null after an empty list, so a later server_name
	// extension is still consulted: this must be .sni, never .no_sni (a .no_sni
	// here would raw-splice a flow the server routes on the second name).
	var raw: [1200]u8 = undefined;
	const hello = buildHelloExt(&raw, &(sni_ext_empty ++ sni_ext_named));
	var out: [256]u8 = undefined;
	const r = extractSni(hello, &out);
	try t.expect(r == .sni);
	try t.expectEqualStrings("vhost-a.test", r.sni.name);
}

test "extractSni keeps the first host_name when a later server_name list is empty" {
	// Mirror case: host_name first, empty list second -> still .sni.
	var raw: [1200]u8 = undefined;
	const hello = buildHelloExt(&raw, &(sni_ext_named ++ sni_ext_empty));
	var out: [256]u8 = undefined;
	const r = extractSni(hello, &out);
	try t.expect(r == .sni);
	try t.expectEqualStrings("vhost-a.test", r.sni.name);
}
