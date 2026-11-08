// Unit tests for the l7proxy's ECH-capability probe (echprobe.zig, plus the
// socket glue in main.zig):
//   - tls.echShape: what the probe mirrors from a guest's ECH hello, and the
//     guest shapes it refuses without probing (malformed / unsupported);
//   - buildClientHello: the probe's own hello round-trips through the proxy's
//     parsers, carries only fresh entropy, and fits at the caps;
//   - probeFd against a fake TLS 1.3 server over a socketpair, one case per
//     outcome the handshake reader can reach;
//   - the result cache (pure, injected clock) and allowsSplice over every
//     Outcome/Detail pair;
//   - single-flight through main.echGateWith over real loopback TCP, and its
//     wait for a free in-flight slot at max_inflight.
//
// The fake server derives its keys from echprobe.serverHandshakeKeys, so these
// tests cannot catch a key-schedule bug shared by both halves: that is what
// checks.l7-ech-probe-interop (real Go crypto/tls servers) is for.

const std = @import("std");
const builtin = @import("builtin");
const t = std.testing;
const filter = @import("filter");
const tls = @import("tls.zig");
const echprobe = @import("echprobe.zig");
const main = @import("main.zig");
const X25519 = std.crypto.dh.X25519;

// libc bits the socket-driven tests need (declared directly, as in
// redirect_test.zig).
extern "c" fn socketpair(domain: c_int, type: c_int, protocol: c_int, sv: *[2]c_int) c_int;
extern "c" fn socket(domain: c_int, type: c_int, protocol: c_int) c_int;
extern "c" fn bind(fd: c_int, addr: *const anyopaque, len: u32) c_int;
extern "c" fn listen(fd: c_int, backlog: c_int) c_int;
extern "c" fn accept(fd: c_int, addr: ?*anyopaque, len: ?*u32) c_int;
extern "c" fn getsockname(fd: c_int, addr: *anyopaque, len: *u32) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern "c" fn shutdown(fd: c_int, how: c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
const PollFd = extern struct { fd: c_int, events: c_short, revents: c_short };
extern "c" fn poll(fds: [*]PollFd, nfds: c_ulong, timeout: c_int) c_int;
const AF_UNIX: c_int = 1;
const AF_INET: c_int = 2;
const SOCK_STREAM: c_int = 1;
const SHUT_RDWR: c_int = 2;
const POLLIN: c_short = 0x001;

fn sleepMs(ms: c_int) void {
	var none: [1]PollFd = undefined;
	_ = poll(&none, 0, ms);
}

fn writeAll(fd: c_int, buf: []const u8) void {
	var off: usize = 0;
	while (off < buf.len) {
		const n = write(fd, buf.ptr + off, buf.len - off);
		if (n <= 0) return;
		off += @intCast(n);
	}
}

fn readExact(fd: c_int, buf: []u8) bool {
	var off: usize = 0;
	while (off < buf.len) {
		const n = read(fd, buf.ptr + off, buf.len - off);
		if (n <= 0) return false;
		off += @intCast(n);
	}
	return true;
}

/// Read one TLS record (the probe's ClientHello) off `fd` into `buf`.
fn readRecord(fd: c_int, buf: []u8) ?[]u8 {
	if (!readExact(fd, buf[0..5])) return null;
	const n = std.mem.readInt(u16, buf[3..5], .big);
	if (5 + n > buf.len or !readExact(fd, buf[5 .. 5 + n])) return null;
	return buf[0 .. 5 + n];
}

// --- byte builders ---

const Buf = struct {
	b: []u8,
	n: usize = 0,

	fn put(self: *Buf, s: []const u8) void {
		@memcpy(self.b[self.n..][0..s.len], s);
		self.n += s.len;
	}
	fn int(self: *Buf, comptime T: type, v: T) void {
		var tmp: [@divExact(@bitSizeOf(T), 8)]u8 = undefined;
		std.mem.writeInt(T, &tmp, v, .big);
		self.put(&tmp);
	}
	fn bytes(self: *const Buf) []u8 {
		return self.b[0..self.n];
	}
};

/// A ClientHello handshake message (4-byte header + body) whose extensions
/// block is the raw `ext` blob.
fn helloMsg(out: []u8, ext: []const u8) []u8 {
	var w = Buf{ .b = out };
	w.int(u8, 0x01);
	w.int(u24, @intCast(2 + 32 + 1 + 4 + 2 + 2 + ext.len));
	w.int(u16, 0x0303);
	w.put(&([_]u8{0x22} ** 32));
	w.int(u8, 0); // session_id
	w.int(u16, 2);
	w.int(u16, 0x1301);
	w.int(u8, 1);
	w.int(u8, 0);
	w.int(u16, @intCast(ext.len));
	w.put(ext);
	return w.bytes();
}

/// Wrap a handshake message in records of at most `frag` bytes each.
fn records(out: []u8, ctype: u8, msg: []const u8, frag: usize) []u8 {
	var w = Buf{ .b = out };
	var off: usize = 0;
	while (off < msg.len) {
		const k = @min(frag, msg.len - off);
		w.int(u8, ctype);
		w.int(u16, 0x0303);
		w.int(u16, @intCast(k));
		w.put(msg[off .. off + k]);
		off += k;
	}
	return w.bytes();
}

fn sniExt(w: *Buf, name: []const u8) void {
	w.int(u16, 0x0000);
	w.int(u16, @intCast(5 + name.len));
	w.int(u16, @intCast(3 + name.len));
	w.int(u8, 0);
	w.int(u16, @intCast(name.len));
	w.put(name);
}

/// An ECH extension of `ech_type` with the given fields, a payload of
/// `payload_len` 0xab bytes and `trailing` appended inside the extension.
fn echExt(w: *Buf, ech_type: u8, config_id: u8, enc: []const u8, payload_len: usize, trailing: []const u8) void {
	w.int(u16, 0xfe0d);
	w.int(u16, @intCast(1 + 2 + 2 + 1 + 2 + enc.len + 2 + payload_len + trailing.len));
	w.int(u8, ech_type);
	w.int(u16, 0x0001);
	w.int(u16, 0x0003);
	w.int(u8, config_id);
	w.int(u16, @intCast(enc.len));
	w.put(enc);
	w.int(u16, @intCast(payload_len));
	for (0..payload_len) |_| w.int(u8, 0xab);
	w.put(trailing);
}

fn alpnExt(w: *Buf, data: []const u8) void {
	w.int(u16, 0x0010);
	w.int(u16, @intCast(data.len));
	w.put(data);
}

const alpn_h2_h11 = [_]u8{ 0x00, 0x0c, 0x02, 'h', '2', 0x08 } ++ "http/1.1".*;
const enc32 = [_]u8{0x5a} ** 32;

/// echShape over a single-record hello built from `ext`.
fn shapeOf(ext: []const u8, out: *tls.EchShape) tls.EchShapeResult {
	var msg_buf: [16384]u8 = undefined;
	var rec_buf: [17000]u8 = undefined;
	const msg = helloMsg(&msg_buf, ext);
	return tls.echShape(records(&rec_buf, 0x16, msg, 16384), out);
}

// --- tls.echShape ---

test "echShape copies a GREASE-shaped ECH extension and the ALPN list" {
	var eb: [1024]u8 = undefined;
	var w = Buf{ .b = &eb };
	sniExt(&w, "allowed.example.com");
	alpnExt(&w, &alpn_h2_h11);
	echExt(&w, 0, 0x42, &enc32, 160, "");
	var s: tls.EchShape = undefined;
	try t.expectEqual(tls.EchShapeResult.ok, shapeOf(w.bytes(), &s));
	try t.expectEqual(@as(u16, 0x0001), s.kdf_id);
	try t.expectEqual(@as(u16, 0x0003), s.aead_id);
	try t.expectEqual(@as(u8, 0x42), s.config_id);
	try t.expectEqualSlices(u8, &enc32, s.enc[0..s.enc_len]);
	try t.expectEqual(@as(u16, 160), s.payload_len);
	try t.expectEqualSlices(u8, &alpn_h2_h11, s.alpn[0..s.alpn_len]);
}

test "echShape: no ALPN extension leaves alpn_len 0" {
	var eb: [1024]u8 = undefined;
	var w = Buf{ .b = &eb };
	sniExt(&w, "allowed.example.com");
	echExt(&w, 0, 1, &enc32, 32, "");
	var s: tls.EchShape = undefined;
	s.alpn_len = 99;
	try t.expectEqual(tls.EchShapeResult.ok, shapeOf(w.bytes(), &s));
	try t.expectEqual(@as(u16, 0), s.alpn_len);
}

test "echShape refuses the 1-byte stub ECH extension as malformed" {
	// The stub redirect_test.zig / tls.zig buildHello send (fe0d 0001 00), and
	// VM Phase K: a bare type byte, no suite, no payload.
	var eb: [256]u8 = undefined;
	var w = Buf{ .b = &eb };
	sniExt(&w, "allowed.example.com");
	w.put(&.{ 0xfe, 0x0d, 0x00, 0x01, 0x00 });
	var s: tls.EchShape = undefined;
	try t.expectEqual(tls.EchShapeResult.malformed, shapeOf(w.bytes(), &s));
}

test "echShape malformed shapes" {
	var s: tls.EchShape = undefined;
	const Case = struct { name: []const u8, build: *const fn (*Buf) void };
	const cases = [_]Case{
		.{ .name = "inner type", .build = struct {
			fn f(w: *Buf) void {
				w.put(&.{ 0xfe, 0x0d, 0x00, 0x01, 0x01 }); // ECHClientHello type inner
			}
		}.f },
		.{ .name = "unknown type", .build = struct {
			fn f(w: *Buf) void {
				echExt(w, 2, 1, &enc32, 32, "");
			}
		}.f },
		.{ .name = "trailing byte", .build = struct {
			fn f(w: *Buf) void {
				echExt(w, 0, 1, &enc32, 32, &.{0x00});
			}
		}.f },
		.{ .name = "payload_len 0", .build = struct {
			fn f(w: *Buf) void {
				echExt(w, 0, 1, &enc32, 0, "");
			}
		}.f },
		.{ .name = "duplicate ECH", .build = struct {
			fn f(w: *Buf) void {
				echExt(w, 0, 1, &enc32, 32, "");
				echExt(w, 0, 1, &enc32, 32, "");
			}
		}.f },
		.{ .name = "duplicate ALPN", .build = struct {
			fn f(w: *Buf) void {
				alpnExt(w, &alpn_h2_h11);
				alpnExt(w, &alpn_h2_h11);
				echExt(w, 0, 1, &enc32, 32, "");
			}
		}.f },
		.{ .name = "ALPN list length off by one", .build = struct {
			fn f(w: *Buf) void {
				alpnExt(w, &.{ 0x00, 0x04, 0x02, 'h', '2' });
				echExt(w, 0, 1, &enc32, 32, "");
			}
		}.f },
		.{ .name = "ALPN zero-length name", .build = struct {
			fn f(w: *Buf) void {
				alpnExt(w, &.{ 0x00, 0x04, 0x02, 'h', '2', 0x00 });
				echExt(w, 0, 1, &enc32, 32, "");
			}
		}.f },
		.{ .name = "ALPN empty list", .build = struct {
			fn f(w: *Buf) void {
				alpnExt(w, &.{ 0x00, 0x00 });
				echExt(w, 0, 1, &enc32, 32, "");
			}
		}.f },
		.{ .name = "no ECH extension", .build = struct {
			fn f(w: *Buf) void {
				alpnExt(w, &alpn_h2_h11);
			}
		}.f },
	};
	for (cases) |cs| {
		var eb: [2048]u8 = undefined;
		var w = Buf{ .b = &eb };
		sniExt(&w, "allowed.example.com");
		cs.build(&w);
		t.expectEqual(tls.EchShapeResult.malformed, shapeOf(w.bytes(), &s)) catch |err| {
			std.debug.print("case: {s}\n", .{cs.name});
			return err;
		};
	}
}

test "echShape: enc, payload or ALPN past the caps is unsupported" {
	var s: tls.EchShape = undefined;
	{
		var eb: [4096]u8 = undefined;
		var w = Buf{ .b = &eb };
		echExt(&w, 0, 1, &([_]u8{1} ** (tls.max_ech_enc + 1)), 32, "");
		try t.expectEqual(tls.EchShapeResult.unsupported, shapeOf(w.bytes(), &s));
	}
	{
		var eb: [8192]u8 = undefined;
		var w = Buf{ .b = &eb };
		echExt(&w, 0, 1, &enc32, tls.max_ech_payload + 1, "");
		try t.expectEqual(tls.EchShapeResult.unsupported, shapeOf(w.bytes(), &s));
	}
	{
		// 103 five-byte names: a valid 517-byte ALPN extension.
		var ab: [1024]u8 = undefined;
		var aw = Buf{ .b = &ab };
		aw.int(u16, 103 * 5);
		for (0..103) |_| aw.put(&.{ 4, 'p', 'r', 'o', 't' });
		var eb: [4096]u8 = undefined;
		var w = Buf{ .b = &eb };
		alpnExt(&w, aw.bytes());
		echExt(&w, 0, 1, &enc32, 32, "");
		try t.expectEqual(tls.EchShapeResult.unsupported, shapeOf(w.bytes(), &s));
	}
	{
		// At the caps exactly: still ok.
		var eb: [8192]u8 = undefined;
		var w = Buf{ .b = &eb };
		echExt(&w, 0, 1, &([_]u8{1} ** tls.max_ech_enc), tls.max_ech_payload, "");
		try t.expectEqual(tls.EchShapeResult.ok, shapeOf(w.bytes(), &s));
	}
}

test "echShape reads a ClientHello fragmented across two records" {
	var eb: [1024]u8 = undefined;
	var w = Buf{ .b = &eb };
	sniExt(&w, "allowed.example.com");
	alpnExt(&w, &alpn_h2_h11);
	echExt(&w, 0, 9, &enc32, 200, "");
	var msg_buf: [2048]u8 = undefined;
	const msg = helloMsg(&msg_buf, w.bytes());
	var rec_buf: [4096]u8 = undefined;
	const recs = records(&rec_buf, 0x16, msg, msg.len / 2 + 1);
	var s: tls.EchShape = undefined;
	try t.expectEqual(tls.EchShapeResult.ok, tls.echShape(recs, &s));
	try t.expectEqual(@as(u8, 9), s.config_id);
	try t.expectEqual(@as(u16, 200), s.payload_len);
	// A truncated stream is malformed (the probe only runs on a complete hello).
	try t.expectEqual(tls.EchShapeResult.malformed, tls.echShape(recs[0 .. recs.len - 1], &s));
}

// --- greaseShape / buildClientHello ---

test "greaseShape encodes the ALPN list and refuses a bad one" {
	var rnd: [33]u8 = undefined;
	for (&rnd, 0..) |*b, i| b.* = @intCast(i);
	const s = echprobe.greaseShape(&rnd, "h2,http/1.1").?;
	try t.expectEqual(@as(u8, 0), s.config_id);
	try t.expectEqualSlices(u8, rnd[1..33], s.enc[0..s.enc_len]);
	try t.expectEqual(@as(u16, 160), s.payload_len);
	try t.expectEqualSlices(u8, &alpn_h2_h11, s.alpn[0..s.alpn_len]);
	try t.expectEqual(@as(u16, 0), echprobe.greaseShape(&rnd, "").?.alpn_len);
	try t.expect(echprobe.greaseShape(&rnd, "h2,,http/1.1") == null);
	try t.expect(echprobe.greaseShape(&rnd, "h2,") == null);
	try t.expect(echprobe.greaseShape(&rnd, &([_]u8{'x'} ** 256)) == null);
}

/// The extension_data of `etype` in a single-record ClientHello, or null.
fn helloExt(record: []const u8, etype: u16) ?[]const u8 {
	const body = record[9..];
	var i: usize = 2 + 32;
	i += 1 + body[i];
	i += 2 + std.mem.readInt(u16, body[i..][0..2], .big);
	i += 1 + body[i];
	const end = i + 2 + std.mem.readInt(u16, body[i..][0..2], .big);
	i += 2;
	while (i + 4 <= end) {
		const et = std.mem.readInt(u16, body[i..][0..2], .big);
		const el = std.mem.readInt(u16, body[i + 2 ..][0..2], .big);
		if (et == etype) return body[i + 4 .. i + 4 + el];
		i += 4 + el;
	}
	return null;
}

fn fillEntropy(buf: []u8, seed: u8) void {
	for (buf, 0..) |*b, i| b.* = @truncate(i *% 31 +% seed);
}

test "buildClientHello round-trips through extractSni and echShape with only fresh entropy" {
	var rnd: [33]u8 = undefined;
	fillEntropy(&rnd, 3);
	const shape = echprobe.greaseShape(&rnd, "h2,http/1.1").?;
	var entropy: [96 + 160]u8 = undefined;
	fillEntropy(&entropy, 77);
	var out: [echprobe.hello_buf_len]u8 = undefined;
	const built = echprobe.buildClientHello(&out, "Allowed.Example.com", &shape, &entropy).?;
	try t.expectEqualSlices(u8, built.record[5..], built.handshake);

	var sni: [256]u8 = undefined;
	const r = tls.extractSni(built.record, &sni);
	try t.expect(r == .sni);
	try t.expectEqualStrings("Allowed.Example.com", r.sni.name); // exact bytes, no folding
	try t.expect(r.sni.ech);

	var back: tls.EchShape = undefined;
	try t.expectEqual(tls.EchShapeResult.ok, tls.echShape(built.record, &back));
	try t.expectEqual(shape.kdf_id, back.kdf_id);
	try t.expectEqual(shape.aead_id, back.aead_id);
	try t.expectEqual(shape.config_id, back.config_id);
	try t.expectEqualSlices(u8, shape.enc[0..shape.enc_len], back.enc[0..back.enc_len]);
	try t.expectEqual(shape.payload_len, back.payload_len);
	// ECH is the last extension, so the payload is the record's tail.
	try t.expectEqualSlices(u8, entropy[96..], built.record[built.record.len - 160 ..]);

	// random, session_id and the key share are the entropy's, never the guest's.
	try t.expectEqualSlices(u8, entropy[0..32], built.handshake[6..38]);
	try t.expectEqual(@as(u8, 32), built.handshake[38]);
	try t.expectEqualSlices(u8, entropy[32..64], built.handshake[39..71]);
	const pub_key = try X25519.recoverPublicKey(entropy[64..96].*);
	const ks = helloExt(built.record, 0x0033).?;
	try t.expectEqualSlices(u8, &.{ 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 }, ks[0..6]);
	try t.expectEqualSlices(u8, &pub_key, ks[6..38]);
	try t.expectEqualSlices(u8, entropy[64..96], &built.secret);

	try t.expectEqualSlices(u8, &.{ 0x02, 0x03, 0x04 }, helloExt(built.record, 0x002b).?); // TLS 1.3 only
	try t.expectEqualSlices(u8, &.{ 0x00, 0x02, 0x00, 0x1d }, helloExt(built.record, 0x000a).?); // X25519 only
	try t.expectEqualSlices(u8, &alpn_h2_h11, helloExt(built.record, 0x0010).?);
}

test "buildClientHello sends no ALPN when the guest sent none" {
	var rnd: [33]u8 = undefined;
	fillEntropy(&rnd, 1);
	const shape = echprobe.greaseShape(&rnd, "").?;
	var entropy: [96 + 160]u8 = undefined;
	fillEntropy(&entropy, 2);
	var out: [echprobe.hello_buf_len]u8 = undefined;
	const built = echprobe.buildClientHello(&out, "allowed.example.com", &shape, &entropy).?;
	try t.expect(helloExt(built.record, 0x0010) == null);
	try t.expect(helloExt(built.record, 0xfe0d) != null);
}

test "buildClientHello fits a 255-byte SNI with enc, payload and ALPN at their caps" {
	var shape: tls.EchShape = undefined;
	shape.kdf_id = 1;
	shape.aead_id = 1;
	shape.config_id = 0;
	@memset(&shape.enc, 0x11);
	shape.enc_len = tls.max_ech_enc;
	shape.payload_len = tls.max_ech_payload;
	// 102 five-byte names: a 512-byte ALPN extension.
	std.mem.writeInt(u16, shape.alpn[0..2], 510, .big);
	for (0..102) |i| @memcpy(shape.alpn[2 + i * 5 ..][0..5], &[_]u8{ 4, 'p', 'r', 'o', 't' });
	shape.alpn_len = tls.max_alpn;
	var entropy: [echprobe.max_entropy_len]u8 = undefined;
	fillEntropy(&entropy, 9);
	const sni = [_]u8{'a'} ** 255;
	var out: [echprobe.hello_buf_len]u8 = undefined;
	const built = echprobe.buildClientHello(&out, &sni, &shape, &entropy).?;
	var back: tls.EchShape = undefined;
	try t.expectEqual(tls.EchShapeResult.ok, tls.echShape(built.record, &back));
	try t.expectEqual(@as(u16, tls.max_alpn), back.alpn_len);
	// Short entropy, an empty SNI or a 256-byte one: refused.
	try t.expect(echprobe.buildClientHello(&out, &sni, &shape, entropy[0 .. entropy.len - 1]) == null);
	try t.expect(echprobe.buildClientHello(&out, "", &shape, &entropy) == null);
	try t.expect(echprobe.buildClientHello(&out, &([_]u8{'a'} ** 256), &shape, &entropy) == null);
}

// --- probeFd against a fake TLS 1.3 server ---

const test_sni = "allowed.example.com";
const server_seed = [_]u8{0x55} ** 32;

/// One probe scenario: the probe's deterministic ClientHello (from fixed
/// entropy) and the server's key share, so a server response can be built
/// before the probe runs.
const Scenario = struct {
	shape: tls.EchShape,
	entropy: [96 + 160]u8,
	hello: [echprobe.hello_buf_len]u8,
	built: echprobe.Built,
	server: X25519.KeyPair,

	fn init(self: *Scenario) !void {
		var rnd: [33]u8 = undefined;
		fillEntropy(&rnd, 5);
		self.shape = echprobe.greaseShape(&rnd, "h2").?;
		fillEntropy(&self.entropy, 41);
		self.built = echprobe.buildClientHello(&self.hello, test_sni, &self.shape, &self.entropy).?;
		self.server = try X25519.KeyPair.generateDeterministic(server_seed);
	}

	fn sessionId(self: *const Scenario) []const u8 {
		return self.entropy[32..64];
	}

	fn keys(self: *const Scenario, suite: u16, sh_msg: []const u8) !echprobe.Keys {
		const client_pub = try X25519.recoverPublicKey(self.entropy[64..96].*);
		const shared = try X25519.scalarmult(self.server.secret_key, client_pub);
		return echprobe.serverHandshakeKeys(suite, shared, &.{ self.built.handshake, sh_msg }).?;
	}
};

const ShOpts = struct {
	random: [32]u8 = [_]u8{0x11} ** 32,
	session_id: ?[]const u8 = null, // null = echo the probe's
	suite: u16 = 0x1301,
	supported_versions: ?u16 = 0x0304,
	group: u16 = 0x001d,
	key_share: bool = true,
};

/// A ServerHello handshake message (4-byte header + body).
fn serverHello(out: []u8, sc: *const Scenario, o: ShOpts) []u8 {
	var w = Buf{ .b = out };
	w.int(u8, 0x02);
	const len_at = w.n;
	w.int(u24, 0);
	w.int(u16, 0x0303);
	w.put(&o.random);
	const sid = o.session_id orelse sc.sessionId();
	w.int(u8, @intCast(sid.len));
	w.put(sid);
	w.int(u16, o.suite);
	w.int(u8, 0);
	const ext_at = w.n;
	w.int(u16, 0);
	if (o.supported_versions) |v| {
		w.int(u16, 0x002b);
		w.int(u16, 2);
		w.int(u16, v);
	}
	if (o.key_share) {
		w.int(u16, 0x0033);
		w.int(u16, 36);
		w.int(u16, o.group);
		w.int(u16, 32);
		w.put(&sc.server.public_key);
	}
	std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(w.n - ext_at - 2), .big);
	std.mem.writeInt(u24, out[len_at..][0..3], @intCast(w.n - len_at - 3), .big);
	return w.bytes();
}

/// An EncryptedExtensions handshake message carrying `exts`.
fn encryptedExtensions(out: []u8, exts: []const u8) []u8 {
	var w = Buf{ .b = out };
	w.int(u8, 0x08);
	w.int(u24, @intCast(2 + exts.len));
	w.int(u16, @intCast(exts.len));
	w.put(exts);
	return w.bytes();
}

/// One encrypted TLS 1.3 record: `content` + inner type + `pad` zero bytes.
fn seal(out: []u8, keys: *const echprobe.Keys, seq: u64, content: []const u8, inner_type: u8, pad: usize) []u8 {
	const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
	const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
	const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
	var pt: [20000]u8 = undefined;
	@memcpy(pt[0..content.len], content);
	pt[content.len] = inner_type;
	@memset(pt[content.len + 1 ..][0..pad], 0);
	const pt_len = content.len + 1 + pad;
	out[0] = 0x17;
	out[1] = 0x03;
	out[2] = 0x03;
	std.mem.writeInt(u16, out[3..5], @intCast(pt_len + 16), .big);
	var tag: [16]u8 = undefined;
	const nonce = keys.nonce(seq);
	switch (keys.suite) {
		0x1301 => Aes128Gcm.encrypt(out[5..][0..pt_len], &tag, pt[0..pt_len], out[0..5], nonce, keys.key[0..16].*),
		0x1302 => Aes256Gcm.encrypt(out[5..][0..pt_len], &tag, pt[0..pt_len], out[0..5], nonce, keys.key[0..32].*),
		0x1303 => ChaCha20Poly1305.encrypt(out[5..][0..pt_len], &tag, pt[0..pt_len], out[0..5], nonce, keys.key[0..32].*),
		else => unreachable,
	}
	@memcpy(out[5 + pt_len ..][0..16], &tag);
	return out[0 .. 5 + pt_len + 16];
}

const ccs_record = [_]u8{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };

/// The fake server: drains the probe's ClientHello, then writes `chunks` in
/// order with a short gap, then holds the socket open until released (or, with
/// `hangup`, shuts it down at once without reading anything).
const Fake = struct {
	fd: c_int,
	chunks: []const []const u8 = &.{},
	hangup: bool = false,
	release: std.atomic.Value(bool) = .init(false),

	fn run(self: *Fake) void {
		if (self.hangup) {
			_ = shutdown(self.fd, SHUT_RDWR);
			return;
		}
		var hello: [echprobe.hello_buf_len]u8 = undefined;
		_ = readRecord(self.fd, &hello);
		for (self.chunks) |ch| {
			writeAll(self.fd, ch);
			sleepMs(5);
		}
		while (!self.release.load(.acquire)) sleepMs(5);
	}
};

/// Run probeFd over a socketpair against `fake` (its fd is filled in here).
fn probeAgainst(sc: *const Scenario, fake: *Fake, deadline_ms: i64) !echprobe.Result {
	var sv: [2]c_int = undefined;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, &sv) != 0) return error.SocketPair;
	defer _ = close(sv[0]);
	defer _ = close(sv[1]);
	fake.fd = sv[1];
	const th = try std.Thread.spawn(.{}, Fake.run, .{fake});
	const r = echprobe.probeFd(sv[0], test_sni, &sc.shape, &sc.entropy, main.monotonicMs() + deadline_ms);
	fake.release.store(true, .release);
	th.join();
	return r;
}

/// The usual happy-path response: SH, CCS, then EE (with `ee_exts`) in
/// separate writes, under `suite`.
fn standardProbe(sc: *const Scenario, suite: u16, ee_exts: []const u8) !echprobe.Result {
	var sh_buf: [512]u8 = undefined;
	const sh = serverHello(&sh_buf, sc, .{ .suite = suite });
	var shr_buf: [600]u8 = undefined;
	const sh_rec = records(&shr_buf, 0x16, sh, 16384);
	const keys = try sc.keys(suite, sh);
	var ee_buf: [512]u8 = undefined;
	const ee = encryptedExtensions(&ee_buf, ee_exts);
	var eer_buf: [600]u8 = undefined;
	const ee_rec = seal(&eer_buf, &keys, 0, ee, 0x16, 7);
	var fake = Fake{ .fd = -1, .chunks = &.{ sh_rec, &ccs_record, ee_rec } };
	return probeAgainst(sc, &fake, 2000);
}

const ee_alpn = [_]u8{ 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2' };
const ee_ech = [_]u8{ 0xfe, 0x0d, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef };

fn expectResult(want_outcome: echprobe.Outcome, want_detail: echprobe.Detail, got: echprobe.Result) !void {
	t.expectEqual(want_detail, got.detail) catch |err| {
		std.debug.print("want {s}/{s}, got {s}/{s}\n", .{ echprobe.outcomeName(want_outcome), echprobe.detailName(want_detail), echprobe.outcomeName(got.outcome), echprobe.detailName(got.detail) });
		return err;
	};
	try t.expectEqual(want_outcome, got.outcome);
}

test "probeFd: an EncryptedExtensions without ECH is not-capable under every suite" {
	var sc: Scenario = undefined;
	try sc.init();
	for ([_]u16{ 0x1301, 0x1302, 0x1303 }) |suite| {
		try expectResult(.not_capable, .ee_without_ech, try standardProbe(&sc, suite, &ee_alpn));
	}
	try expectResult(.not_capable, .ee_without_ech, try standardProbe(&sc, 0x1301, ""));
}

test "probeFd: encrypted_client_hello in EncryptedExtensions is capable" {
	var sc: Scenario = undefined;
	try sc.init();
	try expectResult(.capable, .retry_configs, try standardProbe(&sc, 0x1303, &(ee_alpn ++ ee_ech)));
	try expectResult(.capable, .retry_configs, try standardProbe(&sc, 0x1301, &ee_ech));
}

test "probeFd: ServerHello, CCS and EncryptedExtensions coalesced into one write" {
	var sc: Scenario = undefined;
	try sc.init();
	var sh_buf: [512]u8 = undefined;
	const sh = serverHello(&sh_buf, &sc, .{});
	const keys = try sc.keys(0x1301, sh);
	var ee_buf: [512]u8 = undefined;
	const ee = encryptedExtensions(&ee_buf, &ee_ech);
	var all: [2048]u8 = undefined;
	var w = Buf{ .b = &all };
	var tmp: [600]u8 = undefined;
	w.put(records(&tmp, 0x16, sh, 16384));
	w.put(&ccs_record);
	w.put(seal(&tmp, &keys, 0, ee, 0x16, 0));
	var fake = Fake{ .fd = -1, .chunks = &.{w.bytes()} };
	try expectResult(.capable, .retry_configs, try probeAgainst(&sc, &fake, 2000));
}

test "probeFd: EncryptedExtensions split across two records, and a fragmented ServerHello" {
	var sc: Scenario = undefined;
	try sc.init();
	var sh_buf: [512]u8 = undefined;
	const sh = serverHello(&sh_buf, &sc, .{ .suite = 0x1302 });
	var shr_buf: [600]u8 = undefined;
	const sh_rec = records(&shr_buf, 0x16, sh, 30); // SH over several records
	const keys = try sc.keys(0x1302, sh);
	var ee_buf: [512]u8 = undefined;
	const ee = encryptedExtensions(&ee_buf, &ee_alpn);
	var r1: [600]u8 = undefined;
	var r2: [600]u8 = undefined;
	// The first fragment stops inside the 4-byte message header.
	const e1 = seal(&r1, &keys, 0, ee[0..3], 0x16, 0);
	const e2 = seal(&r2, &keys, 1, ee[3..], 0x16, 0);
	var fake = Fake{ .fd = -1, .chunks = &.{ sh_rec, e1, &ccs_record, e2 } };
	try expectResult(.not_capable, .ee_without_ech, try probeAgainst(&sc, &fake, 2000));
}

test "probeFd: EncryptedExtensions sharing a record with the Certificate that follows" {
	var sc: Scenario = undefined;
	try sc.init();
	var sh_buf: [512]u8 = undefined;
	const sh = serverHello(&sh_buf, &sc, .{});
	var shr_buf: [600]u8 = undefined;
	const sh_rec = records(&shr_buf, 0x16, sh, 16384);
	const keys = try sc.keys(0x1301, sh);
	var msgs: [1024]u8 = undefined;
	var w = Buf{ .b = &msgs };
	var ee_buf: [512]u8 = undefined;
	w.put(encryptedExtensions(&ee_buf, &ee_alpn));
	w.put(&.{ 0x0b, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4 }); // a Certificate stub
	var er: [2048]u8 = undefined;
	var fake = Fake{ .fd = -1, .chunks = &.{ sh_rec, seal(&er, &keys, 0, w.bytes(), 0x16, 0) } };
	try expectResult(.not_capable, .ee_without_ech, try probeAgainst(&sc, &fake, 2000));
}

/// A probe whose only server output is a ServerHello record built with `o`.
fn shOnlyProbe(sc: *const Scenario, o: ShOpts, extra: []const u8) !echprobe.Result {
	var sh_buf: [512]u8 = undefined;
	var msg_buf: [600]u8 = undefined;
	var w = Buf{ .b = &msg_buf };
	w.put(serverHello(&sh_buf, sc, o));
	w.put(extra);
	var rec_buf: [700]u8 = undefined;
	const rec = records(&rec_buf, 0x16, w.bytes(), 16384);
	var fake = Fake{ .fd = -1, .chunks = &.{rec} };
	return probeAgainst(sc, &fake, 2000);
}

test "probeFd: ServerHello refusals" {
	var sc: Scenario = undefined;
	try sc.init();
	try expectResult(.unknown, .hrr, try shOnlyProbe(&sc, .{ .random = std.crypto.tls.hello_retry_request_sequence }, ""));
	try expectResult(.unknown, .not_tls13, try shOnlyProbe(&sc, .{ .supported_versions = null }, ""));
	try expectResult(.unknown, .not_tls13, try shOnlyProbe(&sc, .{ .supported_versions = 0x0303 }, ""));
	try expectResult(.unknown, .unoffered_suite, try shOnlyProbe(&sc, .{ .suite = 0x1304 }, ""));
	try expectResult(.unknown, .bad_server_hello, try shOnlyProbe(&sc, .{ .session_id = &([_]u8{0x99} ** 32) }, ""));
	try expectResult(.unknown, .bad_key_share, try shOnlyProbe(&sc, .{ .group = 0x0017 }, ""));
	try expectResult(.unknown, .bad_key_share, try shOnlyProbe(&sc, .{ .key_share = false }, ""));
	// A byte after the ServerHello inside its record.
	try expectResult(.unknown, .bad_record, try shOnlyProbe(&sc, .{}, &.{0x00}));
}

test "probeFd: a plaintext alert is reported with its description" {
	var sc: Scenario = undefined;
	try sc.init();
	var fake = Fake{ .fd = -1, .chunks = &.{&.{ 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 }} };
	const r = try probeAgainst(&sc, &fake, 2000);
	try expectResult(.unknown, .alert, r);
	try t.expectEqual(@as(u8, 40), r.alert);
}

test "probeFd: an immediate close is eof" {
	var sc: Scenario = undefined;
	try sc.init();
	var fake = Fake{ .fd = -1, .hangup = true };
	try expectResult(.unknown, .eof, try probeAgainst(&sc, &fake, 2000));
}

test "probeFd: silence hits the deadline" {
	var sc: Scenario = undefined;
	try sc.init();
	var fake = Fake{ .fd = -1 };
	const start = main.monotonicMs();
	try expectResult(.unknown, .timeout, try probeAgainst(&sc, &fake, 200));
	try t.expect(main.monotonicMs() - start < 1000);
}

test "probeFd: encrypted-phase refusals" {
	var sc: Scenario = undefined;
	try sc.init();
	var sh_buf: [512]u8 = undefined;
	const sh = serverHello(&sh_buf, &sc, .{});
	var shr_buf: [600]u8 = undefined;
	const sh_rec = records(&shr_buf, 0x16, sh, 16384);
	const keys = try sc.keys(0x1301, sh);
	var ee_buf: [512]u8 = undefined;
	const ee = encryptedExtensions(&ee_buf, &ee_alpn);
	var rb: [20000]u8 = undefined;

	// A tampered tag.
	{
		const rec = seal(&rb, &keys, 0, ee, 0x16, 0);
		rec[rec.len - 1] ^= 0x01;
		var fake = Fake{ .fd = -1, .chunks = &.{ sh_rec, rec } };
		try expectResult(.unknown, .decrypt_failed, try probeAgainst(&sc, &fake, 2000));
	}
	// The first encrypted message is not EncryptedExtensions.
	{
		const cert = [_]u8{ 0x0b, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 };
		var fake = Fake{ .fd = -1, .chunks = &.{ sh_rec, seal(&rb, &keys, 0, &cert, 0x16, 0) } };
		try expectResult(.unknown, .ee_not_first, try probeAgainst(&sc, &fake, 2000));
	}
	// An EncryptedExtensions over max_ee.
	{
		var hdr: [4]u8 = .{ 0x08, 0, 0, 0 };
		std.mem.writeInt(u24, hdr[1..4], echprobe.max_ee + 1, .big);
		var fake = Fake{ .fd = -1, .chunks = &.{ sh_rec, seal(&rb, &keys, 0, &hdr, 0x16, 0) } };
		try expectResult(.unknown, .ee_too_large, try probeAgainst(&sc, &fake, 2000));
	}
	// An encrypted alert.
	{
		var fake = Fake{ .fd = -1, .chunks = &.{ sh_rec, seal(&rb, &keys, 0, &.{ 0x02, 0x50 }, 0x15, 0) } };
		const r = try probeAgainst(&sc, &fake, 2000);
		try expectResult(.unknown, .alert, r);
		try t.expectEqual(@as(u8, 0x50), r.alert);
	}
	// A malformed EncryptedExtensions (its list overruns the message).
	{
		const bad = [_]u8{ 0x08, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x10, 0x00, 0x09 };
		var fake = Fake{ .fd = -1, .chunks = &.{ sh_rec, seal(&rb, &keys, 0, &bad, 0x16, 0) } };
		try expectResult(.unknown, .malformed_ee, try probeAgainst(&sc, &fake, 2000));
	}
	// A CCS that is not the single byte 0x01.
	{
		var fake = Fake{ .fd = -1, .chunks = &.{ sh_rec, &.{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x02 } } };
		try expectResult(.unknown, .bad_record, try probeAgainst(&sc, &fake, 2000));
	}
	// A cleartext handshake record after the ServerHello.
	{
		var fake = Fake{ .fd = -1, .chunks = &.{ sh_rec, records(&rb, 0x16, ee, 16384) } };
		try expectResult(.unknown, .bad_record, try probeAgainst(&sc, &fake, 2000));
	}
	// An application_data record longer than RFC 8446 allows.
	{
		var fake = Fake{ .fd = -1, .chunks = &.{ sh_rec, &.{ 0x17, 0x03, 0x03, 0x41, 0x01 } } };
		try expectResult(.unknown, .bad_record, try probeAgainst(&sc, &fake, 2000));
	}
}

test "probeFd: a record header that can never be valid is refused before its body" {
	var sc: Scenario = undefined;
	try sc.init();
	// No body follows any of these headers, so a probe that waited for one
	// would report timeout instead.
	for ([_][]const u8{
		&.{ 0x16, 0x03, 0x03, 0x40, 0x01 }, // handshake record over 2^14
		&.{ 0x17, 0x03, 0x03, 0x00, 0x20 }, // application_data before the ServerHello
		&.{ 0x14, 0x03, 0x03, 0x00, 0x01 }, // change_cipher_spec before the ServerHello
		&.{ 0x16, 0x04, 0x03, 0x00, 0x20 }, // not a TLS record version
		&.{ 0x16, 0x03, 0x03, 0x00, 0x00 }, // empty record
	}) |hdr| {
		var fake = Fake{ .fd = -1, .chunks = &.{hdr} };
		try expectResult(.unknown, .bad_record, try probeAgainst(&sc, &fake, 2000));
	}
}

test "probeFd: a byte flood of CCS records hits max_read_total" {
	var sc: Scenario = undefined;
	try sc.init();
	var sh_buf: [512]u8 = undefined;
	const sh = serverHello(&sh_buf, &sc, .{});
	var shr_buf: [600]u8 = undefined;
	const sh_rec = records(&shr_buf, 0x16, sh, 16384);
	var flood: [6 * 11000]u8 = undefined;
	for (0..11000) |i| @memcpy(flood[i * 6 ..][0..6], &ccs_record);
	var fake = Fake{ .fd = -1, .chunks = &.{ sh_rec, &flood } };
	try expectResult(.unknown, .bad_record, try probeAgainst(&sc, &fake, 3000));
}

// --- the result cache ---

/// A GREASE shape (HKDF-SHA256 / AES-128-GCM, 32-byte enc) with `alpn_csv`;
/// `seed` varies its random fields (config_id, enc).
fn keyShape(alpn_csv: []const u8, seed: u8) tls.EchShape {
	var rnd: [33]u8 = undefined;
	fillEntropy(&rnd, seed);
	return echprobe.greaseShape(&rnd, alpn_csv).?;
}

fn key4(a: u8, port: u16, sni: []const u8) echprobe.Key {
	return echprobe.Key.init(.{ .ipv4 = .{ 192, 0, 2, a } }, port, sni, &keyShape("", 3)).?;
}

const r_not_capable: echprobe.Result = .{ .outcome = .not_capable, .detail = .ee_without_ech };
const r_capable: echprobe.Result = .{ .outcome = .capable, .detail = .retry_configs };
const r_timeout: echprobe.Result = .{ .outcome = .unknown, .detail = .timeout };

fn claimOf(c: echprobe.Claim) !echprobe.Claimed {
	return switch (c) {
		.claimed => |cl| cl,
		else => error.NotClaimed,
	};
}

test "cache: a result is served until its outcome's TTL ends" {
	const Case = struct { r: echprobe.Result, ttl: i64 };
	for ([_]Case{
		.{ .r = r_not_capable, .ttl = echprobe.ttl_not_capable_ms },
		.{ .r = r_capable, .ttl = echprobe.ttl_capable_ms },
		.{ .r = r_timeout, .ttl = echprobe.ttl_unknown_ms },
	}) |cs| {
		var cache: echprobe.Cache = .{};
		const k = key4(1, 443, "allowed.example.com");
		const cl = try claimOf(cache.lookupOrClaim(&k, 1000));
		cache.complete(cl, &k, cs.r, 1000);
		try t.expectEqual(@as(usize, 0), cache.inflight);
		const hit = cache.lookupOrClaim(&k, 1000 + cs.ttl - 1);
		try t.expect(hit == .hit);
		try t.expectEqual(cs.r.detail, hit.hit.detail);
		// Expired: the same slot is claimed again for a fresh probe.
		const again = try claimOf(cache.lookupOrClaim(&k, 1000 + cs.ttl));
		try t.expectEqual(cl.slot, again.slot);
		try t.expectEqual(@as(usize, 1), cache.inflight);
	}
}

test "cache: uncacheable results leave the slot empty" {
	for ([_]echprobe.Detail{ .entropy, .busy, .pending_timeout, .ech_malformed, .ech_unsupported, .disabled }) |d| {
		var cache: echprobe.Cache = .{};
		const k = key4(1, 443, "allowed.example.com");
		const cl = try claimOf(cache.lookupOrClaim(&k, 0));
		cache.complete(cl, &k, .{ .outcome = .unknown, .detail = d }, 0);
		try t.expect(cache.slots[cl.slot] == .empty);
		try t.expectEqual(@as(usize, 0), cache.inflight);
		try t.expect(cache.lookupOrClaim(&k, 1) == .claimed);
	}
}

test "cache: max_inflight probes at once, then busy" {
	var cache: echprobe.Cache = .{};
	var names: [echprobe.max_inflight][16]u8 = undefined;
	for (0..echprobe.max_inflight) |i| {
		const name = try std.fmt.bufPrint(&names[i], "h{d}.example.com", .{i});
		const k = key4(1, 443, name);
		_ = try claimOf(cache.lookupOrClaim(&k, 0));
	}
	try t.expectEqual(echprobe.max_inflight, cache.inflight);
	const extra = key4(2, 443, "extra.example.com");
	try t.expect(cache.lookupOrClaim(&extra, 0) == .busy);
	// A cached hit is still served at the cap.
	var c2: echprobe.Cache = .{};
	const done = key4(3, 443, "done.example.com");
	const dcl = try claimOf(c2.lookupOrClaim(&done, 0));
	c2.complete(dcl, &done, r_capable, 0);
	for (0..echprobe.max_inflight) |i| {
		const name = try std.fmt.bufPrint(&names[i], "h{d}.example.com", .{i});
		const k = key4(1, 443, name);
		_ = try claimOf(c2.lookupOrClaim(&k, 0));
	}
	try t.expect(c2.lookupOrClaim(&done, 1) == .hit);
	// ...but an expired one cannot be re-probed: busy.
	try t.expect(c2.lookupOrClaim(&done, echprobe.ttl_capable_ms) == .busy);
}

test "cache: single-flight, stale-pending reclaim, and a stale complete is ignored" {
	var cache: echprobe.Cache = .{};
	const k = key4(1, 443, "allowed.example.com");
	const first = try claimOf(cache.lookupOrClaim(&k, 0));
	try t.expect(cache.lookupOrClaim(&k, 10) == .pending);
	try t.expect(cache.lookupOrClaim(&k, echprobe.pending_stale_ms - 1) == .pending);
	const second = try claimOf(cache.lookupOrClaim(&k, echprobe.pending_stale_ms));
	try t.expectEqual(first.slot, second.slot);
	try t.expect(second.gen != first.gen);
	try t.expectEqual(@as(usize, 1), cache.inflight); // inherited, not added
	// The first prober's late answer changes nothing.
	cache.complete(first, &k, r_not_capable, echprobe.pending_stale_ms + 1);
	try t.expect(cache.slots[second.slot] == .pending);
	try t.expectEqual(@as(usize, 1), cache.inflight);
	cache.complete(second, &k, r_capable, echprobe.pending_stale_ms + 2);
	try t.expectEqual(@as(usize, 0), cache.inflight);
	const hit = cache.lookupOrClaim(&k, echprobe.pending_stale_ms + 3);
	try t.expect(hit == .hit);
	try t.expectEqual(echprobe.Outcome.capable, hit.hit.outcome);
}

test "cache: eviction takes the earliest-expiring done slot and never a pending one" {
	var cache: echprobe.Cache = .{};
	var names: [echprobe.cache_slots][20]u8 = undefined;
	var keys: [echprobe.cache_slots]echprobe.Key = undefined;
	for (0..echprobe.cache_slots) |i| {
		keys[i] = key4(1, 443, try std.fmt.bufPrint(&names[i], "h{d}.example.com", .{i}));
		const cl = try claimOf(cache.lookupOrClaim(&keys[i], @intCast(i)));
		try t.expectEqual(i, cl.slot);
		cache.complete(cl, &keys[i], r_not_capable, @intCast(i)); // expires ttl + i
	}
	// At ttl + 3, slots 0..3 have expired; re-claiming them makes them pending.
	const now = echprobe.ttl_not_capable_ms + 3;
	for (0..4) |i| _ = try claimOf(cache.lookupOrClaim(&keys[i], now));
	// A new key must take slot 4 (the earliest-expiring done), not 0..3.
	const fresh = key4(9, 443, "fresh.example.com");
	const cl = try claimOf(cache.lookupOrClaim(&fresh, now));
	try t.expectEqual(@as(usize, 4), cl.slot);
	for (0..4) |i| try t.expect(cache.slots[i] == .pending);
	// An already-expired done slot wins over an earlier-expiring live one.
	var c2: echprobe.Cache = .{};
	for (0..echprobe.cache_slots) |i| {
		const cl2 = try claimOf(c2.lookupOrClaim(&keys[i], 0));
		const r = if (i == 200) r_timeout else r_capable; // slot 200 expires first
		c2.complete(cl2, &keys[i], r, 0);
	}
	const cl3 = try claimOf(c2.lookupOrClaim(&fresh, 1));
	try t.expectEqual(@as(usize, 200), cl3.slot);
}

test "cache keys: exact SNI bytes, address family, port, ALPN and ECH suite all distinguish" {
	const ip: filter.IpAddr = .{ .ipv4 = .{ 192, 0, 2, 1 } };
	const sni = "allowed.example.com";
	const none = keyShape("", 3);
	const a = key4(1, 443, sni);
	const upper = key4(1, 443, "Allowed.example.com");
	const port = key4(1, 8443, sni);
	const other_ip = key4(2, 443, sni);
	const v6 = echprobe.Key.init(.{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1 } }, 443, sni, &none).?;
	// ALPN: the exact extension, so no ALPN, h2, "h2,http/1.1", "http/1.1,h2"
	// and acme-tls/1 are five keys. A server may pick its ECH keys per ALPN
	// (Go's GetEncryptedClientHelloKeys), so an answer learned under acme-tls/1
	// must not serve an h2 hello.
	const h2 = echprobe.Key.init(ip, 443, sni, &keyShape("h2", 3)).?;
	const h2h1 = echprobe.Key.init(ip, 443, sni, &keyShape("h2,http/1.1", 3)).?;
	const h1h2 = echprobe.Key.init(ip, 443, sni, &keyShape("http/1.1,h2", 3)).?;
	const acme = echprobe.Key.init(ip, 443, sni, &keyShape("acme-tls/1", 3)).?;
	// The ECH suite and the enc length the probe copies.
	var s_kdf = none;
	s_kdf.kdf_id = 0x0002;
	var s_aead = none;
	s_aead.aead_id = 0x0003;
	var s_enc = none;
	s_enc.enc_len = 65;
	const kdf = echprobe.Key.init(ip, 443, sni, &s_kdf).?;
	const aead = echprobe.Key.init(ip, 443, sni, &s_aead).?;
	const enc = echprobe.Key.init(ip, 443, sni, &s_enc).?;
	const distinct = [_]*const echprobe.Key{ &upper, &port, &other_ip, &v6, &h2, &h2h1, &h1h2, &acme, &kdf, &aead, &enc };
	try t.expect(a.eql(&key4(1, 443, sni)));
	for (distinct) |k| try t.expect(!a.eql(k));
	for (distinct, 0..) |x, i| {
		for (distinct[i + 1 ..]) |y| try t.expect(!x.eql(y));
	}
	// Random per Chromium GREASE hello, so not part of the key: config_id, the
	// enc bytes and the payload length.
	try t.expect(h2.eql(&echprobe.Key.init(ip, 443, sni, &keyShape("h2", 77)).?));
	var s_rand = none;
	s_rand.config_id +%= 1;
	s_rand.enc[0] +%= 1;
	s_rand.payload_len = 192;
	try t.expect(a.eql(&echprobe.Key.init(ip, 443, sni, &s_rand).?));
	try t.expect(echprobe.Key.init(.{ .ipv4 = .{ 1, 2, 3, 4 } }, 443, "", &none) == null);
	try t.expect(echprobe.Key.init(.{ .ipv4 = .{ 1, 2, 3, 4 } }, 443, &([_]u8{'a'} ** 256), &none) == null);
	var cache: echprobe.Cache = .{};
	const cl = try claimOf(cache.lookupOrClaim(&a, 0));
	cache.complete(cl, &a, r_not_capable, 0);
	try t.expect(cache.lookupOrClaim(&a, 1) == .hit);
	for (distinct) |k| try t.expect(cache.lookupOrClaim(k, 1) == .claimed);
	// The poisoning order: not-capable learned under acme-tls/1 first, then an
	// h2 hello to the same address and name is a miss, not that answer.
	var c2: echprobe.Cache = .{};
	const acl = try claimOf(c2.lookupOrClaim(&acme, 0));
	c2.complete(acl, &acme, r_not_capable, 0);
	try t.expect(c2.lookupOrClaim(&acme, 1) == .hit);
	try t.expect(c2.lookupOrClaim(&h2, 1) == .claimed);
}

test "allowsSplice is true for not_capable alone, over every Outcome/Detail pair" {
	for (std.enums.values(echprobe.Outcome)) |o| {
		for (std.enums.values(echprobe.Detail)) |d| {
			const r: echprobe.Result = .{ .outcome = o, .detail = d };
			try t.expectEqual(o == .not_capable, echprobe.allowsSplice(r));
		}
	}
}

test "outcome and detail names are kebab-case tokens" {
	for (std.enums.values(echprobe.Detail)) |d| {
		const n = echprobe.detailName(d);
		try t.expect(n.len > 0);
		try t.expect(std.mem.indexOfAny(u8, n, "_ ") == null);
	}
	try t.expectEqualStrings("not-capable", echprobe.outcomeName(.not_capable));
	try t.expectEqualStrings("capable", echprobe.outcomeName(.capable));
	try t.expectEqualStrings("unknown", echprobe.outcomeName(.unknown));
}

// --- main.zig glue over loopback TCP ---

const SockaddrIn = extern struct { family: u16, port: u16, addr: [4]u8, zero: [8]u8 = [_]u8{0} ** 8 };

/// A 127.0.0.1:0 listener; returns its fd and port.
fn loopbackListener() !struct { fd: c_int, port: u16 } {
	const fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return error.Socket;
	errdefer _ = close(fd);
	var sa = SockaddrIn{ .family = @intCast(AF_INET), .port = 0, .addr = .{ 127, 0, 0, 1 } };
	if (@import("platform").darwin) {
		// BSD sockaddr: sin_len then a one-byte family.
		const b: *[2]u8 = @ptrCast(&sa.family);
		b.* = .{ @sizeOf(SockaddrIn), @intCast(AF_INET) };
	}
	if (bind(fd, &sa, @sizeOf(SockaddrIn)) != 0) return error.Bind;
	if (listen(fd, 16) != 0) return error.Listen;
	var len: u32 = @sizeOf(SockaddrIn);
	if (getsockname(fd, &sa, &len) != 0) return error.GetSockName;
	return .{ .fd = fd, .port = std.mem.bigToNative(u16, sa.port) };
}

test "echProbeAddr: a refused connect, or a spent deadline, is connect_failed" {
	const l = try loopbackListener();
	const port = l.port;
	_ = close(l.fd); // nothing listens on `port` now
	var sc: Scenario = undefined;
	try sc.init();
	const ip: filter.IpAddr = .{ .ipv4 = .{ 127, 0, 0, 1 } };
	try expectResult(.unknown, .connect_failed, main.echProbeAddr(ip, port, test_sni, &sc.shape, &sc.entropy, main.monotonicMs() + 2000));
	const l2 = try loopbackListener();
	defer _ = close(l2.fd);
	try expectResult(.unknown, .connect_failed, main.echProbeAddr(ip, l2.port, test_sni, &sc.shape, &sc.entropy, main.monotonicMs() - 1));
}

// The single-flight server: counts accepts; each connection waits 100 ms, then
// answers the probe with a ServerHello that has no supported_versions.
const SlowServer = struct {
	fd: c_int,
	accepts: std.atomic.Value(usize) = .init(0),
	stop: std.atomic.Value(bool) = .init(false),
	server: X25519.KeyPair,

	fn run(self: *SlowServer) void {
		while (!self.stop.load(.acquire)) {
			var pfd = [_]PollFd{.{ .fd = self.fd, .events = POLLIN, .revents = 0 }};
			if (poll(&pfd, 1, 20) <= 0) continue;
			const cfd = accept(self.fd, null, null);
			if (cfd < 0) continue;
			_ = self.accepts.fetchAdd(1, .acq_rel);
			sleepMs(100);
			var hello: [echprobe.hello_buf_len]u8 = undefined;
			if (readRecord(cfd, &hello)) |rec| {
				// record(5) + handshake header(4) + legacy_version(2) + random(32),
				// then session_id: length byte, 32 bytes.
				var sh_buf: [256]u8 = undefined;
				var w = Buf{ .b = &sh_buf };
				w.int(u8, 0x02);
				w.int(u24, 2 + 32 + 1 + 32 + 2 + 1 + 2 + 40);
				w.int(u16, 0x0303);
				w.put(&([_]u8{0x33} ** 32));
				w.int(u8, 32);
				w.put(rec[44..76]);
				w.int(u16, 0x1301);
				w.int(u8, 0);
				w.int(u16, 40);
				w.int(u16, 0x0033);
				w.int(u16, 36);
				w.int(u16, 0x001d);
				w.int(u16, 32);
				w.put(&self.server.public_key);
				var rb: [300]u8 = undefined;
				writeAll(cfd, records(&rb, 0x16, w.bytes(), 16384));
			}
			_ = close(cfd);
		}
	}
};

const GateCtx = struct {
	cache: *echprobe.Cache,
	io: std.Io,
	port: u16,
	shape: *const tls.EchShape,
	out: main.GateResult = undefined,

	fn run(self: *GateCtx) void {
		self.out = main.echGateWith(self.cache, self.io, .{ .ipv4 = .{ 127, 0, 0, 1 } }, self.port, test_sni, self.shape);
	}
};

test "echGateWith: eight concurrent connections to one key run one probe" {
	if (builtin.os.tag != .linux) return error.SkipZigTest;
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();

	const l = try loopbackListener();
	defer _ = close(l.fd);
	var srv = SlowServer{ .fd = l.fd, .server = try X25519.KeyPair.generateDeterministic(server_seed) };
	const srv_th = try std.Thread.spawn(.{}, SlowServer.run, .{&srv});

	var rnd: [33]u8 = undefined;
	fillEntropy(&rnd, 8);
	const shape = echprobe.greaseShape(&rnd, "").?;
	var cache: echprobe.Cache = .{};
	var ctxs: [8]GateCtx = undefined;
	var ths: [8]std.Thread = undefined;
	for (&ctxs, &ths) |*cx, *th| {
		cx.* = .{ .cache = &cache, .io = io, .port = l.port, .shape = &shape };
		th.* = try std.Thread.spawn(.{}, GateCtx.run, .{cx});
	}
	for (ths) |th| th.join();
	srv.stop.store(true, .release);
	srv_th.join();

	try t.expectEqual(@as(usize, 1), srv.accepts.load(.acquire));
	var probed: usize = 0;
	for (ctxs) |cx| {
		try expectResult(.unknown, .not_tls13, cx.out.result);
		if (cx.out.probed) probed += 1;
	}
	try t.expectEqual(@as(usize, 1), probed);
	try t.expectEqual(@as(usize, 0), cache.inflight);
}

// Frees one in-flight slot after a delay, as a finishing probe would.
const Release = struct {
	cache: *echprobe.Cache,
	claim: echprobe.Claimed,
	key: *const echprobe.Key,

	fn run(self: *Release) void {
		sleepMs(150);
		self.cache.complete(self.claim, self.key, r_not_capable, main.monotonicMs());
	}
};

/// Fill `cache` to max_inflight with pending claims for other keys.
fn fillInflight(cache: *echprobe.Cache, keys: *[echprobe.max_inflight]echprobe.Key, claims: *[echprobe.max_inflight]echprobe.Claimed, names: *[echprobe.max_inflight][16]u8) !void {
	for (0..echprobe.max_inflight) |i| {
		keys[i] = key4(1, 443, try std.fmt.bufPrint(&names[i], "h{d}.example.com", .{i}));
		claims[i] = try claimOf(cache.lookupOrClaim(&keys[i], main.monotonicMs()));
	}
	try t.expectEqual(echprobe.max_inflight, cache.inflight);
}

test "echGateWith: at max_inflight a new key waits for a free slot, then probes" {
	if (builtin.os.tag != .linux) return error.SkipZigTest;
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();

	const l = try loopbackListener();
	defer _ = close(l.fd);
	var srv = SlowServer{ .fd = l.fd, .server = try X25519.KeyPair.generateDeterministic(server_seed) };
	const srv_th = try std.Thread.spawn(.{}, SlowServer.run, .{&srv});

	var cache: echprobe.Cache = .{};
	var keys: [echprobe.max_inflight]echprobe.Key = undefined;
	var claims: [echprobe.max_inflight]echprobe.Claimed = undefined;
	var names: [echprobe.max_inflight][16]u8 = undefined;
	try fillInflight(&cache, &keys, &claims, &names);
	var rel = Release{ .cache = &cache, .claim = claims[0], .key = &keys[0] };
	const rel_th = try std.Thread.spawn(.{}, Release.run, .{&rel});

	const shape = keyShape("", 8);
	var cx = GateCtx{ .cache = &cache, .io = io, .port = l.port, .shape = &shape };
	cx.run();
	rel_th.join();
	srv.stop.store(true, .release);
	srv_th.join();

	// Not refused as busy: it waited for the freed slot and ran the probe.
	try expectResult(.unknown, .not_tls13, cx.out.result);
	try t.expect(cx.out.probed);
	try t.expect(cx.out.ms >= 100);
	try t.expectEqual(@as(usize, 1), srv.accepts.load(.acquire));
	try t.expectEqual(echprobe.max_inflight - 1, cache.inflight);
}

test "echGateWith: at max_inflight with no slot freed, busy after wait_budget_ms" {
	if (builtin.os.tag != .linux) return error.SkipZigTest;
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();

	var cache: echprobe.Cache = .{};
	var keys: [echprobe.max_inflight]echprobe.Key = undefined;
	var claims: [echprobe.max_inflight]echprobe.Claimed = undefined;
	var names: [echprobe.max_inflight][16]u8 = undefined;
	try fillInflight(&cache, &keys, &claims, &names);

	// Nothing listens on port 9: a probe that ran anyway would be connect_failed.
	const shape = keyShape("", 8);
	var cx = GateCtx{ .cache = &cache, .io = io, .port = 9, .shape = &shape };
	cx.run();
	try expectResult(.unknown, .busy, cx.out.result);
	try t.expect(!cx.out.probed);
	try t.expect(cx.out.ms >= echprobe.wait_budget_ms);
	try t.expect(!echprobe.allowsSplice(cx.out.result));
	try t.expectEqual(echprobe.max_inflight, cache.inflight);
}
