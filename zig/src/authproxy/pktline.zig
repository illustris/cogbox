// The smart-HTTP receive-pack COMMAND SECTION reader -- the one place the auth
// proxy looks inside a request body, and only when a grant carries push rules.
//
// A `git push` body is
//
//   *shallow-line (command-list | push-cert) [push-options] [packfile]
//
// where every line is a pkt-line (a 4-hex length INCLUDING the four bytes,
// max 65520) and the command list ends at the first flush-pkt `0000`:
//
//   PKT-LINE(<old-oid> SP <new-oid> SP <refname> [NUL cap-list] [LF])
//
// The reader stops AT that flush and never touches a byte after it: the
// packfile is multi-GB material that must stream, so the caller forwards
// `prefix_len` buffered bytes and then the live body through `PrefixReader`,
// unchanged. Protocol facts that shape this parser:
//
//   - Protocol v2 has NO receive-pack. `git -c protocol.version=2 push` still
//     negotiates v2 on info/refs and the server answers v0, so the POST body is
//     always the v0/v1 command list -- which is why `0001`/`0002` (v2's delim
//     and response-end) are refused here rather than skipped.
//   - git never gzips a push (`remote-curl.c` sets gzip_request only in
//     fetch_git), and `Content-Encoding` is not forwarded by the core anyway --
//     an encoded body simply fails the hex-length check as `push_malformed`.
//   - A push over http.postBuffer (1 MiB) is chunked and PRECEDED by a probe
//     POST whose body is a lone `0000`. Zero commands is a legitimate parse,
//     not an error: the caller forwards it untouched.
//   - A signed push (`push-cert`) wraps the commands inside a certificate.
//     GitLab does not verify push certs and the rules cannot be evaluated over
//     one, so it is refused rather than waved through.
//   - sha256 repositories use 64-hex oids; a delete is a NEW oid of all zeros,
//     so the zero-oid is per length.
//
// Everything the parser refuses fails CLOSED at the caller (a 4xx before any
// dial); nothing here ever truncates, skips or repairs a malformed section.

const std = @import("std");

/// The command section is buffered whole before any of it is forwarded, so it
/// is bounded twice. 256 KiB, not 64 KiB: ONE pkt-line may be 65520 bytes, and
/// 1024 commands of a realistic ~120 bytes already exceed 64 KiB.
pub const max_prefix_bytes: usize = 256 * 1024;
/// At most this many ref updates in one push. A real push moves a handful; a
/// `git push --all` on a huge repo is the realistic tail.
pub const max_commands: usize = 1024;
/// The protocol's own pkt-line ceiling (4 length bytes + 65516 payload).
pub const max_pkt_len: usize = 65520;
/// A refname is matched component-wise against the grant's patterns, so the
/// component count is bounded rather than walked unbounded per command. 64 is
/// far past any real branch name (`refs/heads/` is already two).
pub const max_ref_components: usize = 64;

/// One ref update from the command list. The slices point into the caller's
/// prefix buffer and live exactly as long as it does.
pub const Command = struct {
	old_oid: []const u8,
	new_oid: []const u8,
	ref: []const u8,
	/// The new oid is all zeros: this command DELETES the ref.
	is_delete: bool,
	/// `refs/tags/...` -- the `deny_tags` rule's subject.
	is_tag: bool,
};

/// Why the section could not be evaluated. Each maps to one `X-Cogbox-Deny`
/// reason and status at the caller; none of them ever forwards the body.
pub const Refusal = enum {
	/// Bad framing, a v2-only pkt type, a malformed command line, or an
	/// unusable refname -- 400.
	push_malformed,
	/// More commands than `cmds` holds, or a section larger than `buf` -- 413.
	too_many_refs,
	/// A signed push: the commands live inside a certificate this parser does
	/// not read -- 403.
	push_cert_unsupported,
};

pub const Section = struct {
	/// Bytes of `buf` filled -- the whole command section INCLUDING its
	/// terminating flush-pkt. Exactly the bytes the caller must replay before
	/// the live body.
	prefix_len: usize,
	/// The parsed commands, borrowed from the caller's `cmds` array. Empty is
	/// legitimate (the lone-flush probe body).
	commands: []const Command,
};

pub const Result = union(enum) {
	ok: Section,
	refuse: Refusal,
};

/// The body read itself failed (the guest's connection, not its bytes). Kept
/// distinct from a `Refusal` so a transport failure is never reported to the
/// guest as a malformed push.
pub const ReadError = error{ReadFailed};

/// Read pkt-lines from `body` into `buf` up to and including the first
/// flush-pkt, parsing the command list into `cmds`. Reads EXACTLY the section's
/// bytes -- never one byte of the packfile behind it.
pub fn readCommandSection(body: *std.Io.Reader, buf: []u8, cmds: []Command) ReadError!Result {
	var used: usize = 0; // bytes of buf filled == bytes consumed from body
	var n: usize = 0; // commands parsed
	// The capability list rides the FIRST command line only; a NUL on a later
	// line is a client the parser does not understand, so it fails closed.
	var seen_command = false;
	while (true) {
		if (used + 4 > buf.len) return .{ .refuse = .too_many_refs };
		if (!try readExact(body, buf[used .. used + 4])) return .{ .refuse = .push_malformed };
		const len = parseHex4(buf[used .. used + 4]) orelse return .{ .refuse = .push_malformed };
		used += 4;
		if (len == 0) {
			// flush-pkt: the command section ends HERE. push-options and the
			// packfile behind it stream live and are never inspected.
			return .{ .ok = .{ .prefix_len = used, .commands = cmds[0..n] } };
		}
		// 1..3 is not a length at all; `0001`/`0002` are protocol-v2 framing and
		// receive-pack is v0/v1 only; a length of 4 is an empty line, which no
		// client sends in a command section.
		if (len <= 4 or len > max_pkt_len) return .{ .refuse = .push_malformed };
		const payload_len = len - 4;
		if (used + payload_len > buf.len) return .{ .refuse = .too_many_refs };
		if (!try readExact(body, buf[used .. used + payload_len])) return .{ .refuse = .push_malformed };
		var payload = buf[used .. used + payload_len];
		used += payload_len;
		// The trailing LF is optional on the wire (git omits it when it appends
		// a capability list); strip at most one.
		if (payload[payload.len - 1] == '\n') payload = payload[0 .. payload.len - 1];
		if (isPushCert(payload)) return .{ .refuse = .push_cert_unsupported };
		// `shallow <oid>` lines may precede the commands.
		if (std.mem.startsWith(u8, payload, "shallow ")) continue;
		if (std.mem.indexOfScalar(u8, payload, 0)) |nul| {
			if (seen_command) return .{ .refuse = .push_malformed };
			payload = payload[0..nul];
		}
		if (n >= cmds.len) return .{ .refuse = .too_many_refs };
		cmds[n] = parseCommand(payload) orelse return .{ .refuse = .push_malformed };
		n += 1;
		seen_command = true;
	}
}

/// Fill `dest` completely. False means the body ENDED early (a truncated
/// command section), which is the guest's framing, not a transport failure.
fn readExact(body: *std.Io.Reader, dest: []u8) ReadError!bool {
	const got = body.readSliceShort(dest) catch return error.ReadFailed;
	return got == dest.len;
}

/// The 4-hex pkt length, including the four bytes themselves. Both cases
/// accepted (git emits lowercase); anything else is not a length.
fn parseHex4(bytes: []const u8) ?usize {
	var v: usize = 0;
	for (bytes) |b| {
		const d = std.fmt.charToDigit(b, 16) catch return null;
		v = v * 16 + d;
	}
	return v;
}

/// The first line of a signed push: `push-cert` alone or `push-cert NUL caps`.
fn isPushCert(payload: []const u8) bool {
	const lit = "push-cert";
	if (!std.mem.startsWith(u8, payload, lit)) return false;
	return payload.len == lit.len or payload[lit.len] == 0;
}

/// `<old-oid> SP <new-oid> SP <refname>`, the capability list already stripped.
fn parseCommand(payload: []const u8) ?Command {
	const sp1 = std.mem.indexOfScalar(u8, payload, ' ') orelse return null;
	const rest = payload[sp1 + 1 ..];
	const sp2 = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
	const old = payload[0..sp1];
	const new = rest[0..sp2];
	const ref = rest[sp2 + 1 ..];
	if (!isOid(old) or !isOid(new)) return null;
	// One object format per repository: a 40-hex old with a 64-hex new is a
	// client this parser does not understand.
	if (old.len != new.len) return null;
	if (!refNameSane(ref)) return null;
	return .{
		.old_oid = old,
		.new_oid = new,
		.ref = ref,
		.is_delete = isZeroOid(new),
		.is_tag = std.mem.startsWith(u8, ref, "refs/tags/"),
	};
}

/// sha1 (40) or sha256 (64) hex, nothing else.
fn isOid(s: []const u8) bool {
	if (s.len != 40 and s.len != 64) return false;
	for (s) |b| {
		_ = std.fmt.charToDigit(b, 16) catch return false;
	}
	return true;
}

/// The all-zeros oid, per length -- a delete on a sha256 repo is 64 zeros.
fn isZeroOid(s: []const u8) bool {
	for (s) |b| {
		if (b != '0') return false;
	}
	return true;
}

/// A subset of `git check-ref-format` sufficient to make the glob match
/// meaningful and to keep a hostile refname out of the pattern walker: anchored
/// at `refs/`, no empty component, no `..` anywhere, no component starting with
/// `.` (which covers `.` and `..` as whole components), no `.lock` suffix, no
/// `@{`, no `\`, none of `~^:?*[`, no space or control byte, no trailing `/` or
/// `.`, and at most `max_ref_components` components. A violation is
/// `push_malformed`: a refname the proxy cannot reason about is never matched
/// against a pattern and never forwarded.
fn refNameSane(ref: []const u8) bool {
	if (!std.mem.startsWith(u8, ref, "refs/")) return false;
	const last = ref[ref.len - 1];
	if (last == '/' or last == '.') return false;
	if (std.mem.indexOf(u8, ref, "..") != null) return false;
	var comps: usize = 0;
	var it = std.mem.splitScalar(u8, ref, '/');
	while (it.next()) |comp| {
		comps += 1;
		if (comps > max_ref_components) return false;
		if (comp.len == 0) return false;
		if (comp[0] == '.') return false;
		if (std.mem.endsWith(u8, comp, ".lock")) return false;
		for (comp, 0..) |b, i| {
			if (b <= 0x20 or b == 0x7f) return false; // space and every control byte
			switch (b) {
				'~', '^', ':', '?', '*', '[', '\\' => return false,
				'@' => if (i + 1 < comp.len and comp[i + 1] == '{') return false,
				else => {},
			}
		}
	}
	return true;
}

/// Frame one pkt-line: the 4-hex length INCLUDES itself. Nothing in the proxy
/// ever writes a pkt-line -- the parser only reads them -- but the fixtures in
/// three test files build them, and a hand-computed length is exactly the kind
/// of typo that makes a test pass for the wrong reason. `inline` so a comptime
/// payload yields a comptime-known line the fixtures can `++` together.
pub inline fn frame(comptime payload: []const u8) []const u8 {
	return std.fmt.comptimePrint("{x:0>4}", .{payload.len + 4}) ++ payload;
}

/// The flush-pkt that ends the command section.
pub const flush_pkt = "0000";

/// Replay a buffered prefix and then the live body, byte for byte. The command
/// section has already been read off the body reader, so the upstream leg would
/// otherwise send a headless packfile; this hands `open` the ORIGINAL byte
/// stream, which is what keeps `Content-Length` and the pack's own framing
/// valid. The generic `Reader.stream` drains `buffer[seek..end]` (the prefix)
/// before it ever calls the vtable, so the delegation below runs only once the
/// prefix is out.
pub const PrefixReader = struct {
	rest: *std.Io.Reader,
	interface: std.Io.Reader,

	pub fn init(prefix: []u8, rest: *std.Io.Reader) PrefixReader {
		return .{
			.rest = rest,
			.interface = .{
				.vtable = &.{ .stream = stream },
				.buffer = prefix,
				.seek = 0,
				.end = prefix.len,
			},
		};
	}

	fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
		const self: *PrefixReader = @alignCast(@fieldParentPtr("interface", r));
		return self.rest.stream(w, limit);
	}
};

// --- Tests ---

const t = std.testing;

const zero40 = "0" ** 40;
const oid_a = "1111111111111111111111111111111111111111";
const oid_b = "2222222222222222222222222222222222222222";
const zero64 = "0" ** 64;
const oid_s256 = "3" ** 64;

const pkt = frame;
const flush = flush_pkt;

fn parse(bytes: []const u8, cmds: []Command) !Result {
	var body: std.Io.Reader = .fixed(bytes);
	var buf: [8 * 1024]u8 = undefined;
	return readCommandSection(&body, &buf, cmds);
}

test "pktline: one create with a capability list and a trailing LF" {
	var cmds: [8]Command = undefined;
	const body = pkt(zero40 ++ " " ++ oid_a ++ " refs/heads/agent/x\x00report-status side-band-64k agent=git/2.43\n") ++
		flush ++ "PACK\x00\x01\x02";
	const r = try parse(body, &cmds);
	const s = r.ok;
	try t.expectEqual(@as(usize, 1), s.commands.len);
	try t.expectEqualStrings(zero40, s.commands[0].old_oid);
	try t.expectEqualStrings(oid_a, s.commands[0].new_oid);
	try t.expectEqualStrings("refs/heads/agent/x", s.commands[0].ref);
	try t.expect(!s.commands[0].is_delete); // a CREATE zeroes the OLD oid, not the new
	try t.expect(!s.commands[0].is_tag);
	// the prefix stops at the flush: the packfile behind it was never read
	try t.expectEqual(body.len - "PACK\x00\x01\x02".len, s.prefix_len);
}

test "pktline: the lone-flush probe body parses as zero commands" {
	// git sends this as the probe POST ahead of a chunked push; forwarding it
	// untouched is the whole point of admitting a zero-command section.
	var cmds: [4]Command = undefined;
	const r = try parse(flush, &cmds);
	try t.expectEqual(@as(usize, 0), r.ok.commands.len);
	try t.expectEqual(@as(usize, 4), r.ok.prefix_len);
}

test "pktline: shallow lines are skipped; a delete and a tag are flagged" {
	var cmds: [8]Command = undefined;
	const body = pkt("shallow " ++ oid_a) ++
		pkt("shallow " ++ oid_b) ++
		pkt(oid_a ++ " " ++ zero40 ++ " refs/heads/gone\x00report-status") ++
		pkt(oid_a ++ " " ++ oid_b ++ " refs/tags/v1.0") ++
		flush;
	const r = try parse(body, &cmds);
	const s = r.ok;
	try t.expectEqual(@as(usize, 2), s.commands.len);
	try t.expect(s.commands[0].is_delete);
	try t.expect(!s.commands[0].is_tag);
	try t.expect(!s.commands[1].is_delete);
	try t.expect(s.commands[1].is_tag);
	try t.expectEqual(body.len, s.prefix_len);
}

test "pktline: sha256 oids are accepted, with the zero-oid per length" {
	var cmds: [4]Command = undefined;
	const body = pkt(oid_s256 ++ " " ++ zero64 ++ " refs/heads/main") ++ flush;
	const r = try parse(body, &cmds);
	try t.expect(r.ok.commands[0].is_delete);
	try t.expectEqual(@as(usize, 64), r.ok.commands[0].new_oid.len);

	// ...but a 40-hex old with a 64-hex new is a client we do not understand
	const mixed = pkt(oid_a ++ " " ++ zero64 ++ " refs/heads/main") ++ flush;
	try t.expectEqual(Refusal.push_malformed, (try parse(mixed, &cmds)).refuse);
}

test "pktline: a signed push is refused, never waved through" {
	var cmds: [4]Command = undefined;
	const body = pkt("push-cert\x00atomic") ++ pkt("certificate version 0.1\n") ++ flush;
	try t.expectEqual(Refusal.push_cert_unsupported, (try parse(body, &cmds)).refuse);
	const bare = pkt("push-cert") ++ flush;
	try t.expectEqual(Refusal.push_cert_unsupported, (try parse(bare, &cmds)).refuse);
}

test "pktline: bad framing, v2 pkt types and malformed commands all refuse" {
	var cmds: [8]Command = undefined;
	const Case = struct { body: []const u8, why: []const u8 };
	const cases = [_]Case{
		.{ .body = "zzzz" ++ flush, .why = "a non-hex length" },
		.{ .body = "0001" ++ flush, .why = "the v2 delim pkt" },
		.{ .body = "0002" ++ flush, .why = "the v2 response-end pkt" },
		.{ .body = "0003" ++ flush, .why = "a length shorter than its own header" },
		.{ .body = "0004" ++ flush, .why = "an empty pkt-line" },
		.{ .body = "00ff" ++ "short", .why = "a payload the body never delivered" },
		.{ .body = "00", .why = "a truncated length header" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b), .why = "no flush at all" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b ++ " refs/heads/x"), .why = "...even with a whole command" },
		.{ .body = pkt(oid_a ++ " refs/heads/x") ++ flush, .why = "one field short" },
		.{ .body = pkt("notanoid " ++ oid_b ++ " refs/heads/x") ++ flush, .why = "a non-hex old oid" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b ++ " heads/x") ++ flush, .why = "a refname outside refs/" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b ++ " refs/heads/x/") ++ flush, .why = "a trailing slash" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b ++ " refs//x") ++ flush, .why = "an empty component" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b ++ " refs/heads/../etc") ++ flush, .why = "a dot-dot component" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b ++ " refs/heads/a..b") ++ flush, .why = "an interior dot-dot" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b ++ " refs/heads/.hidden") ++ flush, .why = "a dot-leading component" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b ++ " refs/heads/x.lock") ++ flush, .why = "a .lock suffix" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b ++ " refs/heads/x@{0}") ++ flush, .why = "an @{ sequence" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b ++ " refs/heads/x^") ++ flush, .why = "a revision-syntax byte" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b ++ " refs/heads/x*") ++ flush, .why = "a glob byte" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b ++ " refs/heads/a\\b") ++ flush, .why = "a backslash" },
		.{ .body = pkt(oid_a ++ " " ++ oid_b ++ " refs/heads/a\x7fb") ++ flush, .why = "a DEL byte" },
		.{
			.body = pkt(oid_a ++ " " ++ oid_b ++ " refs/heads/a") ++
				pkt(oid_a ++ " " ++ oid_b ++ " refs/heads/b\x00report-status") ++ flush,
			.why = "a capability list on a line that is not the first",
		},
	};
	for (cases) |c| {
		const r = try parse(c.body, &cmds);
		if (r != .refuse or r.refuse != .push_malformed) {
			std.debug.print("pkt-line case not refused as push_malformed: {s}\n", .{c.why});
			return error.NotRefused;
		}
	}
}

test "pktline: over the command cap and over the buffer cap are both too_many_refs" {
	// 1025 commands against a 1024-slot array: the 1025th refuses, and nothing
	// is truncated into a shorter (and therefore weaker) rule evaluation.
	var line = std.Io.Writer.Allocating.init(t.allocator);
	defer line.deinit();
	var i: usize = 0;
	while (i < max_commands + 1) : (i += 1) {
		const payload = try std.fmt.allocPrint(t.allocator, "{s} {s} refs/heads/b{d}", .{ oid_a, oid_b, i });
		defer t.allocator.free(payload);
		try line.writer.print("{x:0>4}{s}", .{ payload.len + 4, payload });
	}
	try line.writer.writeAll(flush);

	const cmds = try t.allocator.alloc(Command, max_commands);
	defer t.allocator.free(cmds);
	const buf = try t.allocator.alloc(u8, max_prefix_bytes);
	defer t.allocator.free(buf);
	var body: std.Io.Reader = .fixed(line.written());
	const r = try readCommandSection(&body, buf, cmds);
	try t.expectEqual(Refusal.too_many_refs, r.refuse);

	// A section larger than the prefix buffer refuses the same way -- the parser
	// never keeps a partial section.
	var small: [256]u8 = undefined;
	var body2: std.Io.Reader = .fixed(line.written());
	const r2 = try readCommandSection(&body2, &small, cmds);
	try t.expectEqual(Refusal.too_many_refs, r2.refuse);
}

test "pktline: a body read failure is an error, never a malformed verdict" {
	const Failing = struct {
		fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
			_ = r;
			_ = w;
			_ = limit;
			return error.ReadFailed;
		}
	};
	var body: std.Io.Reader = .{ .vtable = &.{ .stream = Failing.stream }, .buffer = &.{}, .seek = 0, .end = 0 };
	var buf: [64]u8 = undefined;
	var cmds: [2]Command = undefined;
	try t.expectError(error.ReadFailed, readCommandSection(&body, &buf, &cmds));
}

test "PrefixReader: replays the buffered prefix then the live body, byte for byte" {
	var prefix = "0000".*;
	var rest: std.Io.Reader = .fixed("PACKREST");
	var pr = PrefixReader.init(&prefix, &rest);
	var out = std.Io.Writer.Allocating.init(t.allocator);
	defer out.deinit();
	// streamRemaining pumps in slices, so the handover from prefix to body is
	// exercised rather than papered over by one big copy.
	_ = try pr.interface.streamRemaining(&out.writer);
	try t.expectEqualStrings("0000PACKREST", out.written());
}
