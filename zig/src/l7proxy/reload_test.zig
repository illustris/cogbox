// The torn-read contract on `netfilter-rules`: the ONE wire file the renderer
// cannot publish atomically (passt's seccomp-boxed shim holds an fd on it, so a
// rename would strand the shim on the unlinked inode -- rules/reload.zig
// writeRuntimeFileInPlace), and this proxy is its second reader, opening by path
// while a render may be inside the truncate-then-writeAll window.
//
// An empty CIDR set is deny-all egress (filter.RuleSet.evaluate's default), so a
// torn read installed here blackholes the guest until some later render signals
// again. main.readPolledInto is the fix; these tests are its two halves -- a
// deterministic walk of the decision table, and a hammer against the REAL writer.

const std = @import("std");
const main = @import("main.zig");
const reload = @import("rules_module").reload;

fn tmpRuntimeDir(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	const dir = try std.fmt.allocPrint(gpa, "zig-l7proxy-reload-{s}", .{hexb});
	try std.Io.Dir.cwd().createDirPath(io, dir);
	return dir;
}

/// A rendered netfilter-rules body, sized to fit the 16 KiB buffer loadRules
/// gives this file and big enough to span many of the writer's 4 KiB flushes.
/// Documentation addresses only (RFC 5737) -- a fixture is committed code.
///
/// The hammer renders THREE of these and both axes are load-bearing. Two vary
/// only by `proto`, so they are byte-for-byte the same LENGTH: neither a length
/// check nor a spot content check can pass a torn read of one off as a settled
/// read of the other. The third is SHORTER, and that is what actually lands the
/// reader on partial NONZERO bytes -- a read straddling a render to or from it
/// moves `size` across the two stats. With same-length payloads alone the
/// moved-key discard was reached hundreds of times a run but never load-bearing:
/// every read it refused would have come back one whole payload anyway, so
/// deleting the comparison from readPolledInto left the whole suite green.
///
/// No payload may be a PREFIX of another, or a torn read of a longer one could be
/// taken for a settled read of a shorter: hence the separate `net` on the short
/// one rather than just a shorter run of the same lines.
fn rulesBody(gpa: std.mem.Allocator, proto: []const u8, net: []const u8, lines: usize) ![]u8 {
	var out: std.ArrayList(u8) = .empty;
	errdefer out.deinit(gpa);
	var line: [64]u8 = undefined;
	var i: usize = 0;
	while (i < lines) : (i += 1) {
		const l = try std.fmt.bufPrint(&line, "allow {s} {s}.{d}/32:443\n", .{ proto, net, i % 256 });
		try out.appendSlice(gpa, l);
	}
	return out.toOwnedSlice(gpa);
}

test "readPolledInto: a settled read installs, a zero-length read is refused, a missing file is the honest empty" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const rt = try tmpRuntimeDir(gpa, io);
	defer gpa.free(rt);
	defer cwd.deleteTree(io, rt) catch {};

	var buf: [16384]u8 = undefined;
	var settle: ?main.FileKey = null;

	// No file at all: NOT a tear, it is the state a runtime dir has before its
	// first render, and deny-all is the right answer for it.
	const absent = main.readPolledInto(rt, "netfilter-rules", &buf, false, &settle);
	try std.testing.expect(absent != null);
	try std.testing.expectEqual(@as(usize, 0), absent.?.len);

	const body = try rulesBody(gpa, "tcp", "198.51.100", 400);
	defer gpa.free(body);
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", body);

	const settled = main.readPolledInto(rt, "netfilter-rules", &buf, false, &settle);
	try std.testing.expect(settled != null);
	try std.testing.expectEqualSlices(u8, body, settled.?);
	try std.testing.expect(settle == null);

	// The zero-length branch: a reader that lands wholly inside the truncate sees
	// a STABLE key over an empty file, which is the case the re-stat alone cannot
	// tell from a settled read. Refused here because the caller says its current
	// set came from a file that had content -- installing it would be deny-all
	// egress. (The MOVED-key branch needs a writer running under the reader; the
	// hammer test below is what drives it.)
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", "");
	const torn = main.readPolledInto(rt, "netfilter-rules", &buf, true, &settle);
	try std.testing.expect(torn == null);
	try std.testing.expect(settle != null);

	// Same file, but a caller with nothing to lose (no set installed yet): the
	// empty is its honest answer and it is taken, so a fresh proxy whose instance
	// really has no CIDR rules is not stuck refusing its own config forever.
	var fresh: ?main.FileKey = null;
	const first = main.readPolledInto(rt, "netfilter-rules", &buf, false, &fresh);
	try std.testing.expect(first != null);
	try std.testing.expectEqual(@as(usize, 0), first.?.len);
}

test "readPolledInto: a SETTLED empty file is installed on the retry, so a legitimate narrowing is not refused forever" {
	// The refusal above must not be permanent. An instance whose rules narrow to
	// nothing renders an EMPTY netfilter-rules, and pinning the previous, WIDER
	// set on it would be fail-OPEN -- and would never clear, because the retry
	// sees the same file every time. So the second read of the SAME key installs.
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const rt = try tmpRuntimeDir(gpa, io);
	defer gpa.free(rt);
	defer cwd.deleteTree(io, rt) catch {};

	var buf: [16384]u8 = undefined;
	var settle: ?main.FileKey = null;

	const body = try rulesBody(gpa, "tcp", "198.51.100", 400);
	defer gpa.free(body);
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", body);
	_ = main.readPolledInto(rt, "netfilter-rules", &buf, false, &settle);

	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", "");
	try std.testing.expect(main.readPolledInto(rt, "netfilter-rules", &buf, true, &settle) == null);

	// Nothing moved between the two reads, so this empty is the renderer's, not a
	// writer's truncate.
	const second = main.readPolledInto(rt, "netfilter-rules", &buf, true, &settle);
	try std.testing.expect(second != null);
	try std.testing.expectEqual(@as(usize, 0), second.?.len);
	try std.testing.expect(settle == null);

	// And the state is clean afterwards: a later render's content loads on the
	// first read, with no refusal carried over.
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", body);
	const back = main.readPolledInto(rt, "netfilter-rules", &buf, false, &settle);
	try std.testing.expect(back != null);
	try std.testing.expectEqualSlices(u8, body, back.?);
}

const ObserveState = struct {
	rt: []const u8,
	/// Every payload the writer renders. Anything the reader INSTALLS must be one
	/// of these ENTIRE; a prefix of one is a torn read.
	bodies: []const []const u8,
	stop: std.atomic.Value(bool) = .init(false),
	ready: std.atomic.Value(bool) = .init(false),
	/// A read that came back as something other than one whole payload: torn
	/// bytes installed. Must stay zero.
	torn: std.atomic.Value(bool) = .init(false),
	/// The empty set installed. Must stay zero -- see the settle note below.
	empty_installed: std.atomic.Value(u32) = .init(0),
	seen: std.atomic.Value(u32) = .init(0),
	discarded: std.atomic.Value(u32) = .init(0),
	/// `discarded` split by BRANCH, which is what gives the re-stat comparison a
	/// test of its own: the total stays healthily non-zero on the zero-length
	/// branch alone, so only the split can tell whether the moved-key discard ran
	/// at all. Which branch fired is readable off `settle` -- the zero-length
	/// refusal REMEMBERS the key it refused, the moved-key discard returns without
	/// touching it, and this observer hands in a fresh null on every read.
	moved: std.atomic.Value(u32) = .init(0),
	empty_refused: std.atomic.Value(u32) = .init(0),
};

fn isWholePayload(bodies: []const []const u8, got: []const u8) bool {
	for (bodies) |body| {
		if (std.mem.eql(u8, got, body)) return true;
	}
	return false;
}

fn observeNetfilterRules(st: *ObserveState) void {
	var buf: [16384]u8 = undefined;
	while (!st.stop.load(.acquire)) {
		// A FRESH settle state on every read, deliberately: it makes the
		// settled-empty install unreachable here, so any empty this observer
		// installs is a torn read and nothing else. The settle rule has its own
		// deterministic test above.
		var settle: ?main.FileKey = null;
		const got = main.readPolledInto(st.rt, "netfilter-rules", &buf, true, &settle) orelse {
			_ = st.discarded.fetchAdd(1, .monotonic);
			if (settle == null) {
				_ = st.moved.fetchAdd(1, .monotonic);
			} else {
				_ = st.empty_refused.fetchAdd(1, .monotonic);
			}
			st.ready.store(true, .release);
			continue;
		};
		if (got.len == 0) {
			_ = st.empty_installed.fetchAdd(1, .monotonic);
		} else if (!isWholePayload(st.bodies, got)) {
			st.torn.store(true, .release);
		}
		_ = st.seen.fetchAdd(1, .monotonic);
		st.ready.store(true, .release);
	}
}

test "writeRuntimeFileInPlace: a truncate-in-place render never lets the L7 proxy install an empty or partial CIDR set" {
	// The mirror of reload.zig's "writeRuntimeFile: a render is atomic" for the
	// one file that CANNOT be atomic: payloads hammered under a reader running the
	// production read path. THREE of them, and the mix is the point: two of the
	// same length, so no length or spot content check can pass a tear off as
	// settled, plus a shorter one, so a read straddling a render moves `size` and
	// comes back PARTIAL. That last part is what makes the moved-key discard
	// load-bearing rather than merely reached -- with same-length payloads only,
	// deleting the re-stat comparison from readPolledInto left the suite green:
	// it discarded plenty, but only reads that were whole anyway.
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const rt = try tmpRuntimeDir(gpa, io);
	defer gpa.free(rt);
	defer cwd.deleteTree(io, rt) catch {};

	const a = try rulesBody(gpa, "tcp", "198.51.100", 400);
	defer gpa.free(a);
	const b = try rulesBody(gpa, "udp", "198.51.100", 400);
	defer gpa.free(b);
	const c = try rulesBody(gpa, "udp", "203.0.113", 130);
	defer gpa.free(c);
	try std.testing.expectEqual(a.len, b.len);
	try std.testing.expect(c.len != a.len);
	const bodies = [_][]const u8{ a, b, c };

	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", a);

	var st: ObserveState = .{ .rt = rt, .bodies = &bodies };
	const th = try std.Thread.spawn(.{}, observeNetfilterRules, .{&st});

	var spins: usize = 0;
	while (!st.ready.load(.acquire) and spins < 100_000_000) : (spins += 1) {}
	try std.testing.expect(st.ready.load(.acquire));
	const seen_before = st.seen.load(.monotonic);

	var i: usize = 0;
	while (i < 400) : (i += 1) {
		try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", bodies[i % bodies.len]);
		if (st.torn.load(.acquire)) break;
	}
	st.stop.store(true, .release);
	th.join();

	// The two that matter. Everything the reader INSTALLED was one whole payload,
	// and it never once fell to the empty set -- which on this file is not a
	// cosmetic loss but deny-all egress for the guest.
	try std.testing.expect(!st.torn.load(.acquire));
	try std.testing.expectEqual(@as(u32, 0), st.empty_installed.load(.monotonic));
	// The observations that matter are the ones taken WHILE the writer ran.
	try std.testing.expect(st.seen.load(.monotonic) > seen_before);
	// And the re-stat comparison is what did the refusing. The two assertions
	// above hold on their own with the comparison DELETED -- the zero-length
	// branch keeps the empty out by itself, and the reads the moved key would have
	// caught mostly come back whole -- so without this line the comparison is dead
	// code as far as the suite can tell. Delete it and this goes red every run.
	//
	// Each HALF of the key is a weaker story, deliberately left so: the writer
	// truncates to zero before it rewrites, so a tear moves `size` as well, and
	// dropping the `mtime_ns` half alone stays green here. That half earns its
	// place against a same-length render that completes ENTIRELY between the two
	// stats -- which this hammer only lands on some runs.
	try std.testing.expect(st.moved.load(.monotonic) > 0);

	// The settled content round-trips. Pinned by an explicit last render rather
	// than by whichever payload the loop's final index landed on.
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", a);
	var buf: [16384]u8 = undefined;
	var settle: ?main.FileKey = null;
	const final = main.readPolledInto(rt, "netfilter-rules", &buf, true, &settle);
	try std.testing.expect(final != null);
	try std.testing.expectEqualSlices(u8, a, final.?);
}

test "readPolledInto: a file OVER the read buffer is refused once, warned about, and installs truncated on the retry" {
	// The cap is pre-existing (loadRules hands this file a 16 KiB nf_buf) and
	// stays; what must not regress is either end of it. Refusing forever would
	// pin the previous, WIDER set with nothing left to clear it -- the same
	// never-clearing fail-open the settled-empty rule exists to avoid -- and
	// installing silently is how an operator loses rules without a log line.
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const rt = try tmpRuntimeDir(gpa, io);
	defer gpa.free(rt);
	defer cwd.deleteTree(io, rt) catch {};

	// A small buffer stands in for nf_buf: the branch keys on `buf.len`, not on
	// 16 KiB, and a fixture that had to exceed the real cap would be 500 rules of
	// committed noise.
	var buf: [1024]u8 = undefined;
	var settle: ?main.FileKey = null;

	const big = try rulesBody(gpa, "tcp", "198.51.100", 400);
	defer gpa.free(big);
	try std.testing.expect(big.len > buf.len);
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", big);

	// First sighting: refused, and the key remembered so the retry can tell
	// itself apart from it.
	try std.testing.expect(main.readPolledInto(rt, "netfilter-rules", &buf, true, &settle) == null);
	try std.testing.expect(settle != null);

	// Retry on the same settled file: the prefix installs, so the reader is not
	// stuck on a set no render can ever replace.
	const got = main.readPolledInto(rt, "netfilter-rules", &buf, true, &settle);
	try std.testing.expect(got != null);
	try std.testing.expectEqual(@as(usize, buf.len), got.?.len);
	try std.testing.expectEqualSlices(u8, big[0..buf.len], got.?);
	// The key is KEPT across the install, so a file that stays oversized warns
	// once per render rather than once per poll.
	try std.testing.expect(settle != null);

	// A render that brings the file back under the cap loads whole, on the first
	// read, with no refusal carried over from the oversized one.
	const small = try rulesBody(gpa, "udp", "203.0.113", 4);
	defer gpa.free(small);
	try std.testing.expect(small.len < buf.len);
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", small);
	const back = main.readPolledInto(rt, "netfilter-rules", &buf, true, &settle);
	try std.testing.expect(back != null);
	try std.testing.expectEqualSlices(u8, small, back.?);
	try std.testing.expect(settle == null);
}
