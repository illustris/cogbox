// ECH-capability probe: the protocol half and the result cache. No name
// resolution and no connect here -- main.zig owns the socket half
// (echProbeAddr: a bounded connect to the exact address the splice dialled,
// then probeFd; echGate: cache, entropy, probe).
//
// Why a probe at all: on the splice tier the proxy routes on the cleartext
// (outer) SNI alone, so an ECH hello whose outer name is allowed can front a
// DENIED inner name on a client-facing server that decrypts ECH for many
// names (a CDN) -- the decoy-SNI hole the `ech-on-splice` refusal closes.
// Chromium sends GREASE ECH on every TLS 1.3 handshake, so that refusal also
// drops every browser connection to a spliced host. The probe asks the server
// the splice would reach whether it is configured for ECH at all.
//
// RFC 9849 basis. Section 7.1: a client-facing server that cannot decrypt the
// extension "MUST ignore the extension and proceed with ClientHelloOuter",
// and "If the server is configured with any ECHConfigs, it MUST include the
// encrypted_client_hello extension in its EncryptedExtensions with the
// retry_configs field". Section 8.1.1: a server that does not understand ECH
// ignores the extension. So a GREASE hello (section 6.2: random payload no
// key can decrypt) that reaches EncryptedExtensions (EE) learns:
//   - 0xfe0d in EE        -> `capable` (retry_configs): refuse the splice;
//   - a well-formed EE without it -> `not_capable`: THIS instance, right now,
//     holds no ECHConfigs it advertises. That is evidence, not proof: a server
//     whose keys are not sent as retry configs (Go SendAsRetry=false, OpenSSL
//     NO_RETRY keys, a split-mode frontend) still decrypts real ECH and looks
//     the same. That residual is documented in docs/network-filtering.md and
//     checks.l7-ech-probe-interop pins it (Go SendAsRetry=false reads as
//     not-capable). It is why the probe is OFF unless the operator sets
//     COGBOX_L7_ECH_PROBE=1 (read by the CLI, enforced by the worker's ECH
//     gate in main.zig): off, every ECH hello on the splice tier is refused.
//   - anything else      -> `unknown`: refuse.
// allowsSplice is the single predicate that may let an ECH hello through.
//
// What the probe sends mirrors the guest's hello where it could change which
// server answers or how: the exact outer SNI bytes (no case folding), the
// guest's ECH kdf/aead/config_id/enc (so a server holding that config_id
// really attempts and fails a decryption) and its ALPN. Everything secret or
// replayable is fresh: client random, legacy_session_id, the X25519 share and
// the payload are entropy the caller draws per probe, so nothing the guest
// encrypted ever leaves the host and a guest cannot steer a key schedule. It
// offers TLS 1.3 only, X25519 only, suites 1301/1302/1303, validates no
// certificate, and sends nothing after the ClientHello.
//
// Threat model (the guest is hostile): it chooses the outer SNI, the ECH
// shape, the ALPN, the timing and the DNS answers it can influence. Defences
// here: a hard deadline on every read (probeFd), a byte cap on everything read
// (max_read_total), size caps on every buffered message, a cache keyed by the
// exact (ip, port, sni) the splice dials plus the guest's ALPN and ECH
// kdf/aead/enc length (Key) -- so a result learned for one address, name,
// ALPN or suite never vouches for another -- with short TTLs for
// `not_capable` (anycast and load-balanced frontends: the probe and the real
// connection can reach different machines, and a rollout can add ECH keys at
// any moment), single-flight per key, and a global in-flight cap
// (max_inflight) so a guest cannot turn the proxy into a probe cannon.
// Eviction only ever forces a fresh probe; it can never turn a refusal into a
// splice.

const std = @import("std");
const filter = @import("filter");
const tls = @import("tls.zig");
const clock = @import("clock.zig");
const stdtls = std.crypto.tls;
const X25519 = std.crypto.dh.X25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const c = @cImport({
	// Same preamble as main.zig's cImport (see the FORTIFY note there),
	// restricted to what probeFd needs.
	@cDefine("_GNU_SOURCE", "1");
	@cDefine("_FORTIFY_SOURCE", "0");
	@cInclude("sys/socket.h");
	@cInclude("poll.h");
	@cInclude("errno.h");
});

const MSG_NOSIGNAL: c_int = c.MSG_NOSIGNAL;

/// Re-exported for the CLI (`cogbox __ech-probe`), which builds a shape too.
pub const EchShape = tls.EchShape;

// --- limits ---

/// Hard deadline for one probe, connect included (main.zig echProbeAddr).
pub const probe_deadline_ms: i64 = 3000;
/// How long a connection waits on another connection's probe of the same key,
/// or for a free in-flight slot.
pub const wait_budget_ms: i64 = 3500;
/// A pending entry older than this may be reclaimed: its prober is past its
/// own deadline, so it is stuck or gone.
pub const pending_stale_ms: i64 = 4000;
pub const ttl_capable_ms: i64 = 600_000;
/// Short on purpose: anycast/load-balanced frontends and key rollouts.
pub const ttl_not_capable_ms: i64 = 60_000;
/// An attempted probe that learned nothing (timeout, alert, HRR...).
pub const ttl_unknown_ms: i64 = 15_000;
pub const cache_slots: usize = 256;
/// Probes in flight per proxy process; above it a connection waits (up to
/// wait_budget_ms) for a free slot, then is refused as busy.
pub const max_inflight: usize = 16;
/// Largest EncryptedExtensions the probe buffers.
pub const max_ee: usize = 16384;
/// Every byte probeFd reads, records and headers included.
pub const max_read_total: usize = 65536;
pub const hello_buf_len: usize = 8192;
/// Upper bound of entropyLen, for a caller's stack buffer.
pub const max_entropy_len: usize = 96 + tls.max_ech_payload;

const max_plaintext: usize = 1 << 14; // RFC 8446 5.1
const max_ciphertext: usize = (1 << 14) + 256; // RFC 8446 5.2
const max_server_hello: usize = 4096;
const aead_tag_len: usize = 16; // every suite offered

const rec_ccs: u8 = 0x14;
const rec_alert: u8 = 0x15;
const rec_handshake: u8 = 0x16;
const rec_app_data: u8 = 0x17;
const hs_server_hello: u8 = 0x02;
const hs_encrypted_extensions: u8 = 0x08;
const ext_supported_versions: u16 = 0x002b;
const ext_key_share: u16 = 0x0033;
const ext_ech: u16 = 0xfe0d;
const group_x25519: u16 = 0x001d;
const tls13: u16 = 0x0304;

// --- outcomes ---

pub const Outcome = enum { not_capable, capable, unknown };

pub const Detail = enum {
	retry_configs,
	ee_without_ech,
	hrr,
	not_tls13,
	alert,
	eof,
	timeout,
	connect_failed,
	bad_record,
	bad_server_hello,
	bad_key_share,
	unoffered_suite,
	decrypt_failed,
	ee_not_first,
	ee_too_large,
	malformed_ee,
	entropy,
	busy,
	pending_timeout,
	ech_malformed,
	ech_unsupported,
	disabled,
};

pub const Result = struct {
	outcome: Outcome,
	detail: Detail,
	alert: u8 = 0, // the alert description when detail == .alert
};

pub fn outcomeName(o: Outcome) []const u8 {
	return switch (o) {
		.not_capable => "not-capable",
		.capable => "capable",
		.unknown => "unknown",
	};
}

pub fn detailName(d: Detail) []const u8 {
	return switch (d) {
		.retry_configs => "retry-configs",
		.ee_without_ech => "ee-without-ech",
		.hrr => "hrr",
		.not_tls13 => "not-tls13",
		.alert => "alert",
		.eof => "eof",
		.timeout => "timeout",
		.connect_failed => "connect-failed",
		.bad_record => "bad-record",
		.bad_server_hello => "bad-server-hello",
		.bad_key_share => "bad-key-share",
		.unoffered_suite => "unoffered-suite",
		.decrypt_failed => "decrypt-failed",
		.ee_not_first => "ee-not-first",
		.ee_too_large => "ee-too-large",
		.malformed_ee => "malformed-ee",
		.entropy => "entropy",
		.busy => "busy",
		.pending_timeout => "pending-timeout",
		.ech_malformed => "ech-malformed",
		.ech_unsupported => "ech-unsupported",
		.disabled => "disabled",
	};
}

/// The ONLY predicate that may permit splicing an ECH-bearing hello. True for
/// `not_capable` alone -- a fully parsed, decrypted EncryptedExtensions with no
/// encrypted_client_hello after a TLS 1.3 ServerHello that was not an HRR.
/// `capable` and every `unknown` (any error, timeout, busy, disabled...)
/// refuse. Callers must not re-derive this from the fields.
pub fn allowsSplice(r: Result) bool {
	return r.outcome == .not_capable;
}

/// How long a result may be served from the cache; null = never cached. The
/// uncached results describe this connection, not the server: the proxy was
/// busy, a wait ran out, entropy failed, the guest's own ECH extension was
/// refused before any probe, or the probe is switched off.
pub fn cacheTtlMs(r: Result) ?i64 {
	return switch (r.outcome) {
		.capable => ttl_capable_ms,
		.not_capable => ttl_not_capable_ms,
		.unknown => switch (r.detail) {
			.entropy, .busy, .pending_timeout, .ech_malformed, .ech_unsupported, .disabled => null,
			else => ttl_unknown_ms,
		},
	};
}

fn unknown(d: Detail) Result {
	return .{ .outcome = .unknown, .detail = d };
}

/// Entropy one probe consumes, in order: client random (32), legacy_session_id
/// (32), X25519 secret seed (32), then the ECH payload (shape.payload_len).
pub fn entropyLen(shape: *const EchShape) usize {
	return 32 + 32 + 32 + @as(usize, shape.payload_len);
}

/// The shape `cogbox __ech-probe` sends: an RFC 9849 section 6.2 GREASE
/// extension (HKDF-SHA256 / AES-128-GCM, the random config_id random[0], a
/// 32-byte X25519-sized enc random[1..33], a 160-byte payload) with `alpn_csv`
/// (comma-separated protocol names; empty for none) as the ALPN extension.
/// null when the list does not encode (an empty name, a name over 255 bytes,
/// or an extension over tls.max_alpn).
pub fn greaseShape(random: *const [33]u8, alpn_csv: []const u8) ?EchShape {
	var s: EchShape = undefined;
	s.kdf_id = 0x0001;
	s.aead_id = 0x0001;
	s.config_id = random[0];
	@memcpy(s.enc[0..32], random[1..33]);
	s.enc_len = 32;
	s.payload_len = 160;
	s.alpn_len = 0;
	if (alpn_csv.len == 0) return s;
	var n: usize = 2;
	var it = std.mem.splitScalar(u8, alpn_csv, ',');
	while (it.next()) |name| {
		if (name.len == 0 or name.len > 255 or n + 1 + name.len > tls.max_alpn) return null;
		s.alpn[n] = @intCast(name.len);
		@memcpy(s.alpn[n + 1 ..][0..name.len], name);
		n += 1 + name.len;
	}
	std.mem.writeInt(u16, s.alpn[0..2], @intCast(n - 2), .big);
	s.alpn_len = @intCast(n);
	return s;
}

// --- ClientHello ---

pub const Built = struct {
	record: []const u8, // 5-byte record header + the handshake message: what is sent
	handshake: []const u8, // the handshake message alone: the transcript's first entry
	secret: [X25519.secret_length]u8,
};

// Bounded big-endian writer: an overflow latches `ok = false` and the caller
// returns null, so no size arithmetic has to be trusted up front.
const Out = struct {
	b: []u8,
	n: usize = 0,
	ok: bool = true,

	fn bytes(self: *Out, s: []const u8) void {
		if (!self.ok or self.n + s.len > self.b.len) {
			self.ok = false;
			return;
		}
		@memcpy(self.b[self.n..][0..s.len], s);
		self.n += s.len;
	}
	fn int(self: *Out, comptime T: type, v: T) void {
		var tmp: [@divExact(@bitSizeOf(T), 8)]u8 = undefined;
		std.mem.writeInt(T, &tmp, v, .big);
		self.bytes(&tmp);
	}
	/// Fill the length field of type T at `at` with the bytes written after it.
	fn patch(self: *Out, comptime T: type, at: usize) void {
		if (!self.ok) return;
		const w = @divExact(@bitSizeOf(T), 8);
		const len = self.n - at - w;
		if (len > std.math.maxInt(T)) {
			self.ok = false;
			return;
		}
		std.mem.writeInt(T, self.b[at..][0..w], @intCast(len), .big);
	}
};

const sig_algs = [_]u16{ 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0807 };

/// Build the probe's ClientHello as ONE record. null when the SNI is empty or
/// over 255 bytes, the shape is out of range, `entropy` is short of
/// entropyLen, or the hello does not fit `out` or one plaintext record. Every
/// random field comes from `entropy` (see entropyLen); from the guest only the
/// SNI, the ECH kdf/aead/config_id/enc and the ALPN extension are mirrored.
pub fn buildClientHello(out: *[hello_buf_len]u8, sni: []const u8, shape: *const EchShape, entropy: []const u8) ?Built {
	if (sni.len == 0 or sni.len > 255) return null;
	if (shape.enc_len > tls.max_ech_enc or shape.payload_len == 0 or
		shape.payload_len > tls.max_ech_payload or shape.alpn_len > tls.max_alpn) return null;
	if (entropy.len < entropyLen(shape)) return null;
	const kp = X25519.KeyPair.generateDeterministic(entropy[64..96].*) catch return null;

	var w = Out{ .b = out };
	w.int(u8, rec_handshake);
	w.int(u16, 0x0301); // legacy_record_version of a first ClientHello
	const rec_len_at = w.n;
	w.int(u16, 0);
	const hs_start = w.n;
	w.int(u8, 0x01); // client_hello
	const hs_len_at = w.n;
	w.int(u24, 0);
	w.int(u16, 0x0303); // legacy_version
	w.bytes(entropy[0..32]); // random
	w.int(u8, 32);
	w.bytes(entropy[32..64]); // legacy_session_id (middlebox compatibility mode)
	w.int(u16, 6);
	w.int(u16, 0x1301);
	w.int(u16, 0x1302);
	w.int(u16, 0x1303);
	w.int(u8, 1);
	w.int(u8, 0); // legacy_compression_methods: null
	const ext_at = w.n;
	w.int(u16, 0);

	// server_name: the exact outer SNI bytes, host_name type.
	w.int(u16, 0x0000);
	w.int(u16, @intCast(5 + sni.len));
	w.int(u16, @intCast(3 + sni.len));
	w.int(u8, 0);
	w.int(u16, @intCast(sni.len));
	w.bytes(sni);
	// supported_versions: TLS 1.3 only.
	w.int(u16, ext_supported_versions);
	w.int(u16, 3);
	w.int(u8, 2);
	w.int(u16, tls13);
	// supported_groups: X25519 only.
	w.int(u16, 0x000a);
	w.int(u16, 4);
	w.int(u16, 2);
	w.int(u16, group_x25519);
	// key_share: one fresh X25519 share.
	w.int(u16, ext_key_share);
	w.int(u16, 2 + 2 + 2 + 32);
	w.int(u16, 2 + 2 + 32);
	w.int(u16, group_x25519);
	w.int(u16, 32);
	w.bytes(&kp.public_key);
	// signature_algorithms (nothing is verified; a server needs the extension).
	w.int(u16, 0x000d);
	w.int(u16, 2 + 2 * sig_algs.len);
	w.int(u16, 2 * sig_algs.len);
	for (sig_algs) |s| w.int(u16, s);
	// ALPN, verbatim from the guest's hello.
	if (shape.alpn_len > 0) {
		w.int(u16, 0x0010);
		w.int(u16, shape.alpn_len);
		w.bytes(shape.alpn[0..shape.alpn_len]);
	}
	// encrypted_client_hello: outer, the guest's suite/config_id/enc, a fresh
	// random payload of the guest's length (RFC 9849 section 6.2 GREASE).
	w.int(u16, ext_ech);
	const ech_at = w.n;
	w.int(u16, 0);
	w.int(u8, 0);
	w.int(u16, shape.kdf_id);
	w.int(u16, shape.aead_id);
	w.int(u8, shape.config_id);
	w.int(u16, shape.enc_len);
	w.bytes(shape.enc[0..shape.enc_len]);
	w.int(u16, shape.payload_len);
	w.bytes(entropy[96..][0..shape.payload_len]);

	w.patch(u16, ech_at);
	w.patch(u16, ext_at);
	w.patch(u24, hs_len_at);
	w.patch(u16, rec_len_at);
	if (!w.ok or w.n - hs_start > max_plaintext) return null;
	return .{ .record = out[0..w.n], .handshake = out[hs_start..w.n], .secret = kp.secret_key };
}

// --- key schedule (RFC 8446 7.1; mirrors std/crypto/tls/Client.zig) ---

pub const Keys = struct {
	suite: u16,
	key: [32]u8 = [_]u8{0} ** 32, // the first key_len bytes are the key
	iv: [12]u8,

	/// The per-record nonce: iv XOR the big-endian sequence number.
	pub fn nonce(self: *const Keys, seq: u64) [12]u8 {
		var n = self.iv;
		var sb: [8]u8 = undefined;
		std.mem.writeInt(u64, &sb, seq, .big);
		for (0..8) |i| n[4 + i] ^= sb[i];
		return n;
	}

	/// Decrypt one TLS 1.3 record body (ciphertext + tag) with its 5-byte
	/// header as additional data. false on any authentication failure.
	pub fn open(self: *const Keys, seq: u64, header: *const [5]u8, body: []const u8, out: []u8) bool {
		return switch (self.suite) {
			0x1301 => openWith(Aes128Gcm, self, seq, header, body, out),
			0x1302 => openWith(Aes256Gcm, self, seq, header, body, out),
			0x1303 => openWith(ChaCha20Poly1305, self, seq, header, body, out),
			else => false,
		};
	}
};

fn openWith(comptime Aead: type, keys: *const Keys, seq: u64, header: *const [5]u8, body: []const u8, out: []u8) bool {
	if (body.len < Aead.tag_length) return false;
	const n = body.len - Aead.tag_length;
	if (out.len < n) return false;
	Aead.decrypt(out[0..n], body[0..n], body[n..][0..Aead.tag_length].*, header, keys.nonce(seq), keys.key[0..Aead.key_length].*) catch return false;
	return true;
}

/// The server handshake traffic key and iv for `suite` from the X25519 shared
/// secret and the transcript (ClientHello || ServerHello handshake messages).
/// Public so the tests can stand up a fake server. null for a suite the probe
/// never offers.
pub fn serverHandshakeKeys(suite: u16, shared: [32]u8, transcript: []const []const u8) ?Keys {
	return switch (suite) {
		0x1301 => keysFor(Sha256, Aes128Gcm, suite, shared, transcript),
		0x1302 => keysFor(Sha384, Aes256Gcm, suite, shared, transcript),
		0x1303 => keysFor(Sha256, ChaCha20Poly1305, suite, shared, transcript),
		else => null,
	};
}

fn keysFor(comptime Hash: type, comptime Aead: type, suite: u16, shared: [32]u8, transcript: []const []const u8) Keys {
	const Hkdf = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.Hmac(Hash));
	var th = Hash.init(.{});
	for (transcript) |part| th.update(part);
	var hello_hash: [Hash.digest_length]u8 = undefined;
	th.final(&hello_hash);
	const zeroes = [1]u8{0} ** Hash.digest_length;
	const early_secret = Hkdf.extract(&[1]u8{0}, &zeroes);
	const empty_hash = stdtls.emptyHash(Hash);
	const derived = stdtls.hkdfExpandLabel(Hkdf, early_secret, "derived", &empty_hash, Hash.digest_length);
	const handshake_secret = Hkdf.extract(&derived, &shared);
	const server_secret = stdtls.hkdfExpandLabel(Hkdf, handshake_secret, "s hs traffic", &hello_hash, Hash.digest_length);
	var k = Keys{ .suite = suite, .iv = stdtls.hkdfExpandLabel(Hkdf, server_secret, "iv", "", Aead.nonce_length) };
	const key = stdtls.hkdfExpandLabel(Hkdf, server_secret, "key", "", Aead.key_length);
	@memcpy(k.key[0..Aead.key_length], &key);
	return k;
}

// --- the probe over a connected fd ---

// Deadline- and byte-bounded reader. Reads exactly what the record framing
// asks for, so nothing past EncryptedExtensions is ever pulled off the socket.
const Conn = struct {
	fd: c_int,
	deadline: i64,
	total: usize = 0,

	fn readExact(self: *Conn, buf: []u8) ?Detail {
		if (self.total + buf.len > max_read_total) return .bad_record;
		var off: usize = 0;
		while (off < buf.len) {
			const now = clock.monotonicMs();
			if (now >= self.deadline) return .timeout;
			const remaining: c_int = @intCast(@min(self.deadline - now, std.math.maxInt(c_int)));
			var pfd = [_]c.struct_pollfd{.{ .fd = self.fd, .events = c.POLLIN, .revents = 0 }};
			const pr = c.poll(&pfd, 1, remaining);
			if (pr == 0) return .timeout;
			if (pr < 0) {
				// EINTR (a SIGHUP reload landing on this thread): retry inside the
				// same deadline. Anything else is a dead socket.
				if (std.c._errno().* == c.EINTR) continue;
				return .eof;
			}
			const got = c.recv(self.fd, @ptrCast(buf.ptr + off), buf.len - off, 0);
			if (got < 0 and std.c._errno().* == c.EINTR) continue;
			if (got <= 0) return .eof;
			off += @intCast(got);
		}
		self.total += buf.len;
		return null;
	}

	/// One record: header into `hdr`, body into `body_buf`; returns the body
	/// length in `len`. Framing per RFC 8446 5.1/5.2: version 0x03 0x01..0x03
	/// before the ServerHello, exactly 0x03 0x03 after it. The content type is
	/// judged at the header, so a record that can never be valid here is
	/// refused without waiting for its body: before the ServerHello only
	/// handshake and alert; after it only change_cipher_spec, alert and
	/// application_data.
	fn readRecord(self: *Conn, hdr: *[5]u8, body_buf: *[max_ciphertext]u8, after_sh: bool, len: *usize) ?Detail {
		if (self.readExact(hdr)) |d| return d;
		if (hdr[1] != 0x03) return .bad_record;
		if (after_sh) {
			if (hdr[2] != 0x03) return .bad_record;
			if (hdr[0] != rec_ccs and hdr[0] != rec_alert and hdr[0] != rec_app_data) return .bad_record;
		} else {
			if (hdr[2] < 0x01 or hdr[2] > 0x03) return .bad_record;
			if (hdr[0] != rec_handshake and hdr[0] != rec_alert) return .bad_record;
		}
		const n: usize = std.mem.readInt(u16, hdr[3..5], .big);
		if (hdr[0] == rec_app_data) {
			if (n < aead_tag_len + 1 or n > max_ciphertext) return .bad_record;
		} else if (n < 1 or n > max_plaintext) return .bad_record;
		if (self.readExact(body_buf[0..n])) |d| return d;
		len.* = n;
		return null;
	}
};

fn sendAll(fd: c_int, buf: []const u8) bool {
	var off: usize = 0;
	while (off < buf.len) {
		const n = c.send(fd, @ptrCast(buf.ptr + off), buf.len - off, MSG_NOSIGNAL);
		if (n < 0 and std.c._errno().* == c.EINTR) continue;
		if (n <= 0) return false;
		off += @intCast(n);
	}
	return true;
}

fn alertOf(body: []const u8) Result {
	if (body.len != 2) return unknown(.bad_record);
	return .{ .outcome = .unknown, .detail = .alert, .alert = body[1] };
}

const ShParsed = union(enum) {
	ok: struct { suite: u16, peer: [32]u8 },
	fail: Detail,
};

fn shFail(d: Detail) ShParsed {
	return .{ .fail = d };
}

/// Judge a ServerHello body (after its 4-byte header), in this order: version,
/// HRR, session_id echo, suite, compression, extensions, TLS 1.3, key share.
fn parseServerHello(body: []const u8, session_id: []const u8) ShParsed {
	var i: usize = 0;
	if (body.len < 2 + 32 + 1) return shFail(.bad_server_hello);
	if (std.mem.readInt(u16, body[0..2], .big) != 0x0303) return shFail(.bad_server_hello);
	i = 2;
	if (std.mem.eql(u8, body[i .. i + 32], &stdtls.hello_retry_request_sequence)) return shFail(.hrr);
	i += 32;
	const sid_len = body[i];
	i += 1;
	if (i + sid_len > body.len or !std.mem.eql(u8, body[i .. i + sid_len], session_id)) return shFail(.bad_server_hello);
	i += sid_len;
	if (i + 3 > body.len) return shFail(.bad_server_hello);
	const suite = std.mem.readInt(u16, body[i..][0..2], .big);
	if (suite != 0x1301 and suite != 0x1302 and suite != 0x1303) return shFail(.unoffered_suite);
	if (body[i + 2] != 0) return shFail(.bad_server_hello);
	i += 3;

	var version: ?u16 = null;
	var share: ?[]const u8 = null;
	// A TLS 1.2 ServerHello may end here, with no extensions block at all.
	if (i < body.len) {
		if (i + 2 > body.len) return shFail(.bad_server_hello);
		const ext_len = std.mem.readInt(u16, body[i..][0..2], .big);
		i += 2;
		if (ext_len != body.len - i) return shFail(.bad_server_hello);
		while (i < body.len) {
			if (i + 4 > body.len) return shFail(.bad_server_hello);
			const et = std.mem.readInt(u16, body[i..][0..2], .big);
			const el = std.mem.readInt(u16, body[i + 2 ..][0..2], .big);
			i += 4;
			if (i + el > body.len) return shFail(.bad_server_hello);
			const ed = body[i .. i + el];
			i += el;
			switch (et) {
				ext_supported_versions => {
					if (version != null or ed.len != 2) return shFail(.bad_server_hello);
					version = std.mem.readInt(u16, ed[0..2], .big);
				},
				ext_key_share => {
					if (share != null) return shFail(.bad_server_hello);
					share = ed;
				},
				else => return shFail(.bad_server_hello),
			}
		}
	}
	if (version == null or version.? != tls13) return shFail(.not_tls13);
	const ks = share orelse return shFail(.bad_key_share);
	if (ks.len != 2 + 2 + 32 or std.mem.readInt(u16, ks[0..2], .big) != group_x25519 or
		std.mem.readInt(u16, ks[2..4], .big) != 32) return shFail(.bad_key_share);
	return .{ .ok = .{ .suite = suite, .peer = ks[4..36].* } };
}

/// Judge a complete EncryptedExtensions body. An encrypted_client_hello at any
/// extension header is `capable`, however malformed what follows is; otherwise
/// only an exactly consumed, correctly sized list is `not_capable`.
fn parseEncryptedExtensions(ee: []const u8) Result {
	if (ee.len < 2) return unknown(.malformed_ee);
	var well_formed = std.mem.readInt(u16, ee[0..2], .big) == ee.len - 2;
	var i: usize = 2;
	while (i + 4 <= ee.len) {
		const et = std.mem.readInt(u16, ee[i..][0..2], .big);
		if (et == ext_ech) return .{ .outcome = .capable, .detail = .retry_configs };
		const el = std.mem.readInt(u16, ee[i + 2 ..][0..2], .big);
		i += 4;
		if (i + el > ee.len) {
			well_formed = false;
			break;
		}
		i += el;
	}
	if (i != ee.len) well_formed = false;
	if (!well_formed) return unknown(.malformed_ee);
	return .{ .outcome = .not_capable, .detail = .ee_without_ech };
}

/// Run one probe over `fd`, already connected to the address the splice
/// dialled: send the ClientHello, then read through EncryptedExtensions and
/// stop. Every read is bounded by `deadline_at_ms` (monotonic) and the whole
/// exchange by max_read_total. The caller closes `fd`; nothing is ever sent
/// after the ClientHello. See allowsSplice for the one result that permits a
/// splice; everything that is not a clean answer is `unknown`.
pub fn probeFd(fd: c_int, sni: []const u8, shape: *const EchShape, entropy: []const u8, deadline_at_ms: i64) Result {
	var hello_buf: [hello_buf_len]u8 = undefined;
	const built = buildClientHello(&hello_buf, sni, shape, entropy) orelse return unknown(.ech_unsupported);
	if (!sendAll(fd, built.record)) return unknown(.eof);

	var conn = Conn{ .fd = fd, .deadline = deadline_at_ms };
	var hdr: [5]u8 = undefined;
	var rec: [max_ciphertext]u8 = undefined;
	var len: usize = 0;

	// ServerHello: one handshake message, possibly fragmented over records.
	var sh: [max_server_hello]u8 = undefined;
	var sh_len: usize = 0;
	while (true) {
		if (conn.readRecord(&hdr, &rec, false, &len)) |d| return unknown(d);
		switch (hdr[0]) {
			rec_alert => return alertOf(rec[0..len]),
			rec_handshake => {},
			else => return unknown(.bad_record),
		}
		if (sh_len + len > sh.len) return unknown(.bad_record);
		@memcpy(sh[sh_len..][0..len], rec[0..len]);
		sh_len += len;
		if (sh_len < 4) continue;
		if (sh[0] != hs_server_hello) return unknown(.bad_server_hello);
		const need = 4 + @as(usize, std.mem.readInt(u24, sh[1..4], .big));
		if (need > sh.len) return unknown(.bad_record);
		if (sh_len < need) continue;
		// Anything after the ServerHello in its record would be a cleartext
		// handshake message, which TLS 1.3 never sends.
		if (sh_len != need) return unknown(.bad_record);
		break;
	}
	const sh_msg = sh[0..sh_len];
	const parsed = switch (parseServerHello(sh_msg[4..], entropy[32..64])) {
		.ok => |p| p,
		.fail => |d| return unknown(d),
	};
	const shared = X25519.scalarmult(built.secret, parsed.peer) catch return unknown(.bad_key_share);
	const keys = serverHandshakeKeys(parsed.suite, shared, &.{ built.handshake, sh_msg }) orelse return unknown(.unoffered_suite);

	// Encrypted handshake: the first message must be EncryptedExtensions. Only
	// its bytes are kept; whatever follows it in the same record is ignored.
	var hs: [4 + max_ee]u8 = undefined;
	var hs_len: usize = 0;
	var ee_len: usize = 0;
	var seq: u64 = 0;
	var pt: [max_ciphertext]u8 = undefined;
	while (true) {
		if (conn.readRecord(&hdr, &rec, true, &len)) |d| return unknown(d);
		switch (hdr[0]) {
			rec_ccs => {
				// Middlebox-compatibility change_cipher_spec: exactly 0x01.
				if (len != 1 or rec[0] != 0x01) return unknown(.bad_record);
				continue;
			},
			rec_alert => return alertOf(rec[0..len]),
			rec_app_data => {},
			else => return unknown(.bad_record),
		}
		const n = len - aead_tag_len;
		if (n > max_plaintext + 1) return unknown(.bad_record); // TLSInnerPlaintext cap
		if (!keys.open(seq, &hdr, rec[0..len], pt[0..n])) return unknown(.decrypt_failed);
		seq += 1;
		// Strip the zero padding; the last nonzero byte is the inner type.
		var end = n;
		while (end > 0 and pt[end - 1] == 0) end -= 1;
		if (end == 0) return unknown(.bad_record);
		const content = pt[0 .. end - 1];
		switch (pt[end - 1]) {
			rec_alert => return alertOf(content),
			rec_handshake => {},
			else => return unknown(.bad_record),
		}
		var frag: []const u8 = content;
		if (hs_len < 4) {
			const k = @min(4 - hs_len, frag.len);
			@memcpy(hs[hs_len..][0..k], frag[0..k]);
			hs_len += k;
			frag = frag[k..];
			if (hs_len < 4) continue;
			if (hs[0] != hs_encrypted_extensions) return unknown(.ee_not_first);
			ee_len = std.mem.readInt(u24, hs[1..4], .big);
			if (ee_len > max_ee) return unknown(.ee_too_large);
		}
		const need = 4 + ee_len;
		const k = @min(need - hs_len, frag.len);
		@memcpy(hs[hs_len..][0..k], frag[0..k]);
		hs_len += k;
		if (hs_len == need) return parseEncryptedExtensions(hs[4..need]);
	}
}

// --- result cache ---

/// Cache key: exactly what the splice dials, plus every field the probe mirrors
/// from the guest that is stable per client and may change the server's
/// answer -- the resolved address, the port, the outer SNI bytes as the guest
/// sent them (no case folding: a server may route `A.example` and `a.example`
/// differently), the guest's ALPN extension (a server may choose its ECH keys
/// per ALPN: Go's Config.GetEncryptedClientHelloKeys sees it, so a result
/// learned under one ALPN must not answer for another), and the ECH kdf/aead
/// and enc length. The ALPN extension is held as its length and a SHA-256 of
/// its bytes, so "no ALPN" (length 0) is a key of its own. Deliberately left
/// out, because Chromium's GREASE draws them at random per hello and keying on
/// them would make every lookup a miss: the config_id, the enc value and the
/// payload length. A server whose answer depends on those can be steered
/// through the cache; docs/network-filtering.md lists that residual.
pub const Key = struct {
	ip: filter.IpAddr,
	port: u16,
	sni_len: u8,
	sni: [255]u8,
	alpn_len: u16,
	alpn_hash: [Sha256.digest_length]u8,
	kdf_id: u16,
	aead_id: u16,
	enc_len: u16,

	/// null for an empty SNI, one over 255 bytes, or an ALPN past tls.max_alpn.
	pub fn init(ip: filter.IpAddr, port: u16, sni: []const u8, shape: *const EchShape) ?Key {
		if (sni.len == 0 or sni.len > 255 or shape.alpn_len > tls.max_alpn) return null;
		var k = Key{
			.ip = ip,
			.port = port,
			.sni_len = @intCast(sni.len),
			.sni = [_]u8{0} ** 255,
			.alpn_len = shape.alpn_len,
			.alpn_hash = [_]u8{0} ** Sha256.digest_length,
			.kdf_id = shape.kdf_id,
			.aead_id = shape.aead_id,
			.enc_len = shape.enc_len,
		};
		@memcpy(k.sni[0..sni.len], sni);
		if (shape.alpn_len > 0) Sha256.hash(shape.alpn[0..shape.alpn_len], &k.alpn_hash, .{});
		return k;
	}

	pub fn eql(a: *const Key, b: *const Key) bool {
		if (a.port != b.port or a.sni_len != b.sni_len or a.alpn_len != b.alpn_len or
			a.kdf_id != b.kdf_id or a.aead_id != b.aead_id or a.enc_len != b.enc_len) return false;
		if (!std.mem.eql(u8, &a.alpn_hash, &b.alpn_hash)) return false;
		const same_ip = switch (a.ip) {
			.ipv4 => |x| switch (b.ip) {
				.ipv4 => |y| std.mem.eql(u8, &x, &y),
				.ipv6 => false,
			},
			.ipv6 => |x| switch (b.ip) {
				.ipv6 => |y| std.mem.eql(u8, &x, &y),
				.ipv4 => false,
			},
		};
		return same_ip and std.mem.eql(u8, a.sni[0..a.sni_len], b.sni[0..b.sni_len]);
	}
};

pub const Slot = union(enum) {
	empty,
	pending: struct { key: Key, since_ms: i64, gen: u64 },
	done: struct { key: Key, result: Result, expires_ms: i64 },
};

pub const Claimed = struct { slot: usize, gen: u64 };

pub const Claim = union(enum) {
	hit: Result, // a live cached result
	claimed: Claimed, // the caller probes, then calls complete()
	pending, // another connection is probing this key: wait and retry
	busy, // max_inflight probes already running: wait and retry, then refuse
};

/// Bounded, static result cache with single-flight per key. A key is in at
/// most one slot. Every pending slot counts once in `inflight` (a reclaimed
/// stale slot keeps its count), and a pending slot is never evicted, so a
/// probe in flight can always deposit its result.
pub const Cache = struct {
	// Test-and-set spinlock like main.zig's rules_lock: the critical sections
	// are short scans of static memory.
	lock: std.atomic.Value(bool) = .init(false),
	slots: [cache_slots]Slot = [_]Slot{.empty} ** cache_slots,
	inflight: usize = 0,
	gen: u64 = 0,

	fn acquire(self: *Cache) void {
		while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
	}
	fn release(self: *Cache) void {
		self.lock.store(false, .release);
	}

	pub fn lookupOrClaim(self: *Cache, key: *const Key, now_ms: i64) Claim {
		self.acquire();
		defer self.release();
		for (&self.slots, 0..) |*s, i| {
			switch (s.*) {
				.empty => {},
				.done => |*d| if (d.key.eql(key)) {
					if (now_ms < d.expires_ms) return .{ .hit = d.result };
					if (self.inflight >= max_inflight) return .busy;
					return self.claimSlot(i, key, now_ms, true);
				},
				.pending => |*p| if (p.key.eql(key)) {
					if (now_ms - p.since_ms < pending_stale_ms) return .pending;
					// The prober is past its own deadline: take the slot over with
					// a new gen, inheriting its inflight count. Its late complete()
					// no longer matches and changes nothing.
					return self.claimSlot(i, key, now_ms, false);
				},
			}
		}
		if (self.inflight >= max_inflight) return .busy;
		const slot = self.pickVictim(now_ms) orelse return .busy;
		return self.claimSlot(slot, key, now_ms, true);
	}

	/// Deposit a probe's result: done with cacheTtlMs(r), or empty when the
	/// result is never cached. A stale claim (the slot was reclaimed) changes
	/// nothing.
	pub fn complete(self: *Cache, claim: Claimed, key: *const Key, r: Result, now_ms: i64) void {
		self.acquire();
		defer self.release();
		if (claim.slot >= cache_slots) return;
		const s = &self.slots[claim.slot];
		switch (s.*) {
			.pending => |*p| {
				if (p.gen != claim.gen or !p.key.eql(key)) return;
				s.* = if (cacheTtlMs(r)) |ttl|
					.{ .done = .{ .key = key.*, .result = r, .expires_ms = now_ms + ttl } }
				else
					.empty;
				self.inflight -= 1;
			},
			.empty, .done => {},
		}
	}

	fn claimSlot(self: *Cache, i: usize, key: *const Key, now_ms: i64, count: bool) Claim {
		self.gen += 1;
		self.slots[i] = .{ .pending = .{ .key = key.*, .since_ms = now_ms, .gen = self.gen } };
		if (count) self.inflight += 1;
		return .{ .claimed = .{ .slot = i, .gen = self.gen } };
	}

	/// An empty slot, else an expired done slot, else the done slot that
	/// expires first. Never a pending slot.
	fn pickVictim(self: *const Cache, now_ms: i64) ?usize {
		var expired: ?usize = null;
		var earliest: ?usize = null;
		var earliest_ms: i64 = std.math.maxInt(i64);
		for (&self.slots, 0..) |*s, i| {
			switch (s.*) {
				.empty => return i,
				.pending => {},
				.done => |*d| {
					if (expired == null and d.expires_ms <= now_ms) expired = i;
					if (d.expires_ms < earliest_ms) {
						earliest_ms = d.expires_ms;
						earliest = i;
					}
				},
			}
		}
		return expired orelse earliest;
	}
};
