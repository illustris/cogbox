// The torn-read contract on `netfilter-rules`: the ONE wire file the renderer
// cannot publish atomically (passt's seccomp-boxed shim holds an fd on it, so a
// rename would strand the shim on the unlinked inode -- rules/reload.zig
// writeRuntimeFileInPlace). It has TWO loaders and either can catch it
// mid-write: this proxy's main.readPolledInto, which opens by path, and the
// shim's filter.readHeldRuleFile, which rewinds a held fd. Both reload on a flag
// a signal raised, so either can read while a later render is still writing,
// and two overlapping renders can leave a mix of both on disk.
//
// The renderer seals every render with a CRC-32 trailer inside one shared byte
// budget, and both loaders install a read only through filter.ruleFileBody. An
// empty, cut, mixed or over-budget read keeps the set already installed: it is
// never parsed into a narrower set (an empty CIDR set is deny-all egress) nor a
// WIDER one (a cut that loses the L7 funnel remaps, rendered last, lets :443 out
// past the proxy). These tests are the halves of that: a deterministic walk of
// the decision table, a hammer of each loader against the REAL writer, and both
// loaders at the table caps. The last tests cover the proxy's other two wire
// files, which are renamed into place and now read whole instead of cut to a
// fixed buffer, and what the proxy does with a wire file that is there but
// cannot be read: never take it for a missing file, never decide a new flow
// from the tables it holds until a retry reads it (main.WireState).

const std = @import("std");
const filter = @import("filter");
const main = @import("main.zig");
const rules_module = @import("rules_module");
const reload = rules_module.reload;

fn tmpRuntimeDir(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	const dir = try std.fmt.allocPrint(gpa, "zig-l7proxy-reload-{s}", .{hexb});
	try std.Io.Dir.cwd().createDirPath(io, dir);
	return dir;
}

/// A rendered netfilter-rules body, big enough to span many of the writer's
/// 4 KiB flushes. Documentation addresses only (RFC 5737) -- a fixture is
/// committed code.
///
/// The hammers render THREE of these and both axes are load-bearing. Two vary
/// only by `proto`, so they are byte-for-byte the same LENGTH: neither a length
/// check nor a spot content check can pass a torn read of one off as a settled
/// read of the other. The third is SHORTER, so a read straddling a render to or
/// from it moves `size` across the proxy's two stats and lands on partial
/// NONZERO bytes.
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

/// `body` sealed the way reload.writeRuntimeRules seals a render.
fn sealed(gpa: std.mem.Allocator, body: []const u8) ![]u8 {
	const trailer = filter.ruleFileTrailer(body);
	const out = try gpa.alloc(u8, body.len + trailer.len);
	@memcpy(out[0..body.len], body);
	@memcpy(out[body.len..], &trailer);
	return out;
}

test "readPolledInto: only a sealed render installs; empty and unsealed files are refused, a missing one is absent" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const rt = try tmpRuntimeDir(gpa, io);
	defer gpa.free(rt);
	defer cwd.deleteTree(io, rt) catch {};

	var buf: [filter.rule_file_read_len]u8 = undefined;
	var refused: ?main.FileKey = null;

	// No file at all: the state a runtime dir has before its first render. There
	// is no policy to keep, so the caller enforces deny-all (RuleSet.fail_closed).
	try std.testing.expect(main.readPolledInto(rt, "netfilter-rules", &buf, &refused) == .absent);

	const body = try rulesBody(gpa, "tcp", "198.51.100", 400);
	defer gpa.free(body);
	const file = try sealed(gpa, body);
	defer gpa.free(file);
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", file);
	switch (main.readPolledInto(rt, "netfilter-rules", &buf, &refused)) {
		.install => |got| try std.testing.expectEqualSlices(u8, body, got),
		else => return error.TestUnexpectedResult,
	}
	try std.testing.expect(refused == null);

	// The truncate window a reader can land in, or a writer that died before it
	// wrote: refused, NOT installed as the empty (deny-all) set.
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", "");
	try std.testing.expect(main.readPolledInto(rt, "netfilter-rules", &buf, &refused) == .refused);

	// The same rules without the trailer -- what an older cogbox or a hand edit
	// leaves -- are not a render either.
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", body);
	try std.testing.expect(main.readPolledInto(rt, "netfilter-rules", &buf, &refused) == .refused);
	try std.testing.expect(refused != null);

	// A render with no rules at all is the trailer alone, and it installs on the
	// FIRST read: a legitimate narrowing to nothing needs no second look.
	const empty_render = filter.ruleFileTrailer("");
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", &empty_render);
	switch (main.readPolledInto(rt, "netfilter-rules", &buf, &refused)) {
		.install => |got| try std.testing.expectEqual(@as(usize, 0), got.len),
		else => return error.TestUnexpectedResult,
	}
	try std.testing.expect(refused == null);
}

test "cidrSetFor: a refused, moved or unreadable read installs nothing, a missing file is deny-all" {
	// loadRules' CIDR step. Anything but one complete render leaves the installed
	// set standing (null: keep it and retry): a refusal is never parsed into some
	// set of its own, neither the empty one (deny-all egress for a running guest)
	// nor a prefix.
	try std.testing.expect(main.cidrSetFor(.refused) == null);
	try std.testing.expect(main.cidrSetFor(.moved) == null);

	// Nor is a file that is there but cannot be opened swapped for deny-all: the
	// proxy stops deciding new flows instead (WireState). The swap would deny
	// none of the flows that matter -- an L7 `allow` and the terminate tier are
	// checked against this set's hard floor only -- and it would take the
	// `hard-deny` lines (the enclosing host's own addresses) out of that floor
	// for every flow still resolving its upstream.
	try std.testing.expect(main.cidrSetFor(.unreadable) == null);
	const self_addr: filter.IpAddr = .{ .ipv4 = .{ 192, 0, 2, 7 } };
	const kept = filter.parseRules("hard-deny 192.0.2.7/32\nallow 0.0.0.0/0\n");
	try std.testing.expect(kept.hardBlocked(self_addr));
	try std.testing.expect(!filter.RuleSet.fail_closed.hardBlocked(self_addr));

	// No file: no rendered policy at all, so nothing goes out, DNS included.
	const dns: filter.IpAddr = .{ .ipv4 = .{ 198, 51, 100, 1 } };
	const web: filter.IpAddr = .{ .ipv4 = .{ 203, 0, 113, 9 } };
	const absent = main.cidrSetFor(.absent) orelse return error.TestUnexpectedResult;
	try std.testing.expectEqual(filter.Action.deny, absent.evaluate(.udp, dns, 53));
	try std.testing.expectEqual(filter.Action.deny, absent.evaluate(.tcp, web, 443));

	const rs = main.cidrSetFor(.{ .install = "allow 0.0.0.0/0\n" }) orelse return error.TestUnexpectedResult;
	try std.testing.expectEqual(filter.Action.allow, rs.evaluate(.tcp, web, 443));
}

test "readPolledInto: an empty file is refused on every read, and remembered once" {
	// The reader this replaced installed a SETTLED empty file on its second look,
	// so a rules set narrowed to nothing was not refused forever. A render never
	// writes an empty file now (no rules is the trailer alone), so an empty file
	// stays what it is on every look -- not a render -- however long it sits.
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const rt = try tmpRuntimeDir(gpa, io);
	defer gpa.free(rt);
	defer cwd.deleteTree(io, rt) catch {};

	var buf: [filter.rule_file_read_len]u8 = undefined;
	var refused: ?main.FileKey = null;

	const body = try rulesBody(gpa, "tcp", "198.51.100", 400);
	defer gpa.free(body);
	const file = try sealed(gpa, body);
	defer gpa.free(file);
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", file);
	try std.testing.expect(main.readPolledInto(rt, "netfilter-rules", &buf, &refused) == .install);

	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", "");
	try std.testing.expect(main.readPolledInto(rt, "netfilter-rules", &buf, &refused) == .refused);
	const first = refused orelse return error.TestUnexpectedResult;
	try std.testing.expectEqual(@as(u64, 0), first.size);
	// Nothing moved between the two reads; still refused, and under the SAME key,
	// which is what keeps a settled refusal to one log line.
	try std.testing.expect(main.readPolledInto(rt, "netfilter-rules", &buf, &refused) == .refused);
	try std.testing.expectEqual(first, refused orelse return error.TestUnexpectedResult);

	// The next render loads whole on the first read and clears the memory.
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", file);
	switch (main.readPolledInto(rt, "netfilter-rules", &buf, &refused)) {
		.install => |got| try std.testing.expectEqualSlices(u8, body, got),
		else => return error.TestUnexpectedResult,
	}
	try std.testing.expect(refused == null);
}

fn isWholePayload(bodies: []const []const u8, got: []const u8) bool {
	for (bodies) |body| {
		if (std.mem.eql(u8, got, body)) return true;
	}
	return false;
}

const ObserveState = struct {
	rt: []const u8,
	/// The body of every payload the writer renders. Anything the reader
	/// INSTALLS must be one of these ENTIRE; anything else is a torn install.
	bodies: []const []const u8,
	stop: std.atomic.Value(bool) = .init(false),
	ready: std.atomic.Value(bool) = .init(false),
	/// A read installed as something other than one whole payload. Must stay
	/// false.
	torn: std.atomic.Value(bool) = .init(false),
	/// `.absent` or `.unreadable` from a path that is never unlinked, with
	/// descriptors to spare. Must stay zero.
	missing: std.atomic.Value(u32) = .init(0),
	seen: std.atomic.Value(u32) = .init(0),
	moved: std.atomic.Value(u32) = .init(0),
	refused: std.atomic.Value(u32) = .init(0),
};

fn observeNetfilterRules(st: *ObserveState) void {
	var buf: [filter.rule_file_read_len]u8 = undefined;
	while (!st.stop.load(.acquire)) {
		// A fresh refusal memory on every read: it only dedupes the log.
		var refused: ?main.FileKey = null;
		switch (main.readPolledInto(st.rt, "netfilter-rules", &buf, &refused)) {
			.install => |got| {
				if (!isWholePayload(st.bodies, got)) st.torn.store(true, .release);
				_ = st.seen.fetchAdd(1, .monotonic);
			},
			.moved => _ = st.moved.fetchAdd(1, .monotonic),
			.refused => _ = st.refused.fetchAdd(1, .monotonic),
			.absent, .unreadable => _ = st.missing.fetchAdd(1, .monotonic),
		}
		st.ready.store(true, .release);
	}
}

test "writeRuntimeFileInPlace: a truncate-in-place render never lets the L7 proxy install an empty or partial CIDR set" {
	// The mirror of reload.zig's "writeRuntimeFile: a render is atomic" for the
	// one file that CANNOT be atomic: sealed payloads hammered under a reader
	// running the production read path. THREE of them, and the mix is the point:
	// two of the same length, so no length or spot content check can pass a tear
	// off as settled, plus a shorter one, so a read straddling a render moves
	// `size` and comes back PARTIAL.
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
	const sa = try sealed(gpa, a);
	defer gpa.free(sa);
	const sb = try sealed(gpa, b);
	defer gpa.free(sb);
	const sc = try sealed(gpa, c);
	defer gpa.free(sc);
	const files = [_][]const u8{ sa, sb, sc };
	for (files) |f| try std.testing.expect(f.len <= filter.rule_file_budget);

	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", sa);

	var st: ObserveState = .{ .rt = rt, .bodies = &bodies };
	const th = try std.Thread.spawn(.{}, observeNetfilterRules, .{&st});

	var spins: usize = 0;
	while (!st.ready.load(.acquire) and spins < 100_000_000) : (spins += 1) {}
	try std.testing.expect(st.ready.load(.acquire));
	const seen_before = st.seen.load(.monotonic);

	// At least `min_renders`, then on until the two events asserted below have
	// both happened: a read straddled a render (`moved`) and the reader installed
	// while the writer ran. When they happen is the scheduler's call -- under CPU
	// oversubscription a fixed 400 renders missed `moved` about one run in twenty
	// -- so the loop waits for the events themselves, yielding so the reader gets
	// the CPU, and only the generous `max_renders` cap turns a reader that never
	// ran into a (loudly reported) failure.
	const min_renders = 400;
	const max_renders = 2_000_000;
	var i: usize = 0;
	while (i < max_renders) : (i += 1) {
		if (i >= min_renders and st.moved.load(.monotonic) > 0 and st.seen.load(.monotonic) > seen_before) break;
		try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", files[i % files.len]);
		if (st.torn.load(.acquire)) break;
		if (i >= min_renders) std.Thread.yield() catch {};
	}
	st.stop.store(true, .release);
	th.join();
	if (i == max_renders) std.debug.print("in-place hammer: gave up after {d} renders: moved={d} seen={d} (before {d})\n", .{ i, st.moved.load(.monotonic), st.seen.load(.monotonic), seen_before });

	// The one that matters: everything the reader INSTALLED was one whole payload.
	// On this file a partial install is not cosmetic -- an empty set is deny-all
	// egress, and a cut that loses the funnel is direct :443 past the proxy.
	try std.testing.expect(!st.torn.load(.acquire));
	try std.testing.expectEqual(@as(u32, 0), st.missing.load(.monotonic));
	// The observations that matter are the ones taken WHILE the writer ran.
	try std.testing.expect(st.seen.load(.monotonic) > seen_before);
	// And reads did straddle renders, so `!torn` was earned under a moving file,
	// not by a reader that only ever saw settled bytes. The trailer would refuse
	// these reads on its own now; the re-stat in front of it makes them a retry
	// (`.moved`) rather than a logged refusal.
	try std.testing.expect(st.moved.load(.monotonic) > 0);

	// The settled content round-trips. Pinned by an explicit last render rather
	// than by whichever payload the loop's final index landed on.
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", sa);
	var buf: [filter.rule_file_read_len]u8 = undefined;
	var refused: ?main.FileKey = null;
	switch (main.readPolledInto(rt, "netfilter-rules", &buf, &refused)) {
		.install => |got| try std.testing.expectEqualSlices(u8, a, got),
		else => return error.TestUnexpectedResult,
	}
}

test "readPolledInto: a file over the budget is refused on every read and never installs a prefix" {
	// The reader this replaced refused an oversized settled file once, warned,
	// and then installed the PREFIX its buffer held -- and a prefix of a render
	// loses the funnel remaps first. The buffer is now the shared budget plus one
	// byte, so filling it proves the file is over the budget, and nothing past
	// the budget is ever a render: refused on the first look and every look after.
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const rt = try tmpRuntimeDir(gpa, io);
	defer gpa.free(rt);
	defer cwd.deleteTree(io, rt) catch {};

	var buf: [filter.rule_file_read_len]u8 = undefined;
	var refused: ?main.FileKey = null;

	const big_body = try rulesBody(gpa, "tcp", "198.51.100", 1100);
	defer gpa.free(big_body);
	const big = try sealed(gpa, big_body);
	defer gpa.free(big);
	try std.testing.expect(big.len > filter.rule_file_budget);
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", big);

	try std.testing.expect(main.readPolledInto(rt, "netfilter-rules", &buf, &refused) == .refused);
	const first = refused orelse return error.TestUnexpectedResult;
	try std.testing.expectEqual(@as(u64, big.len), first.size);
	try std.testing.expect(main.readPolledInto(rt, "netfilter-rules", &buf, &refused) == .refused);
	try std.testing.expectEqual(first, refused orelse return error.TestUnexpectedResult);

	// A render that brings the file back under the budget loads whole, on the
	// first read, with no refusal carried over from the oversized one.
	const small_body = try rulesBody(gpa, "udp", "203.0.113", 4);
	defer gpa.free(small_body);
	const small = try sealed(gpa, small_body);
	defer gpa.free(small);
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", small);
	switch (main.readPolledInto(rt, "netfilter-rules", &buf, &refused)) {
		.install => |got| try std.testing.expectEqualSlices(u8, small_body, got),
		else => return error.TestUnexpectedResult,
	}
	try std.testing.expect(refused == null);
}

const HeldObserveState = struct {
	fd: std.posix.fd_t,
	bodies: []const []const u8,
	stop: std.atomic.Value(bool) = .init(false),
	ready: std.atomic.Value(bool) = .init(false),
	torn: std.atomic.Value(bool) = .init(false),
	seen: std.atomic.Value(u32) = .init(0),
	refused: std.atomic.Value(u32) = .init(0),
	/// Installs observed after the first refusal: the loader came BACK from a
	/// refused read to a whole one, which is the retry the shim relies on.
	seen_after_refused: std.atomic.Value(u32) = .init(0),
};

fn observeHeldFd(st: *HeldObserveState) void {
	var buf: [filter.rule_file_read_len]u8 = undefined;
	while (!st.stop.load(.acquire)) {
		if (filter.readHeldRuleFile(st.fd, &buf)) |got| {
			if (!isWholePayload(st.bodies, got)) st.torn.store(true, .release);
			_ = st.seen.fetchAdd(1, .monotonic);
			if (st.refused.load(.monotonic) > 0) _ = st.seen_after_refused.fetchAdd(1, .monotonic);
		} else {
			_ = st.refused.fetchAdd(1, .monotonic);
		}
		st.ready.store(true, .release);
	}
}

/// Open `<rt>/<name>` once, read-only, the way the shim's init does before
/// seccomp; the caller closes it.
fn holdFd(gpa: std.mem.Allocator, rt: []const u8, name: []const u8) !std.posix.fd_t {
	const path = try std.fs.path.joinZ(gpa, &.{ rt, name });
	defer gpa.free(path);
	return std.posix.openatZ(std.posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0);
}

test "the shim's loader never installs a partial rule set while the writer rewrites in place" {
	// passt's shim holds ONE fd on the file and reloads with lseek+read on it,
	// from the next intercepted call after SIGUSR1 -- so a reload can run while a
	// later render is inside its truncate-then-write. This drives the shim's own
	// reload step (filter.readHeldRuleFile, the function netfilter/main.zig calls)
	// on a held fd against the real writer.
	//
	// What a hammer mostly lands on is the EMPTY window between the truncate and
	// the write (the writer issues its bytes in one call); a non-empty mid-file
	// tear is rare here, which is why filter.zig walks every cut of a sealed file
	// and reload.zig every prefix of a real render. This test's job is the empty
	// window plus the real writer: the loader must refuse it and come back to a
	// whole render on a later read.
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
	const bodies = [_][]const u8{ a, b, c };
	const sa = try sealed(gpa, a);
	defer gpa.free(sa);
	const sb = try sealed(gpa, b);
	defer gpa.free(sb);
	const sc = try sealed(gpa, c);
	defer gpa.free(sc);
	const files = [_][]const u8{ sa, sb, sc };

	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", sa);
	const fd = try holdFd(gpa, rt, "netfilter-rules");
	defer _ = std.c.close(fd);

	var st: HeldObserveState = .{ .fd = fd, .bodies = &bodies };
	const th = try std.Thread.spawn(.{}, observeHeldFd, .{&st});

	var spins: usize = 0;
	while (!st.ready.load(.acquire) and spins < 100_000_000) : (spins += 1) {}
	try std.testing.expect(st.ready.load(.acquire));
	const seen_before = st.seen.load(.monotonic);

	// At least as many renders as the proxy hammer, then on until the loader has
	// both refused a read and installed after it (capped).
	var i: usize = 0;
	while (i < 20_000) : (i += 1) {
		try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", files[i % files.len]);
		if (st.torn.load(.acquire)) break;
		if (i >= 400 and st.refused.load(.monotonic) > 0 and st.seen_after_refused.load(.monotonic) > 0) break;
	}
	st.stop.store(true, .release);
	th.join();

	try std.testing.expect(!st.torn.load(.acquire));
	try std.testing.expect(st.seen.load(.monotonic) > seen_before);
	try std.testing.expect(st.refused.load(.monotonic) > 0);
	try std.testing.expect(st.seen_after_refused.load(.monotonic) > 0);

	// The held fd follows the inode: an explicit last render reads back whole.
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", sb);
	var buf: [filter.rule_file_read_len]u8 = undefined;
	try std.testing.expectEqualSlices(u8, b, filter.readHeldRuleFile(fd, &buf) orelse return error.TestUnexpectedResult);
}

/// Append `{"from": from, "to": to}` to `arr`, strings in `arena`.
fn appendRemap(arena: std.mem.Allocator, arr: *std.json.Array, from: []const u8, to: []const u8) !void {
	var obj: std.json.ObjectMap = .empty;
	try obj.put(arena, "from", .{ .string = try arena.dupe(u8, from) });
	try obj.put(arena, "to", .{ .string = try arena.dupe(u8, to) });
	try arr.append(.{ .object = obj });
}

/// A `.network` with L7 on (one allow rule), `rules`, and `remaps` remap
/// objects on 192.0.2.x:8000+i, none of which matches the funnel probe.
fn capNetwork(arena: std.mem.Allocator, rules: std.json.Array, remaps: usize) !std.json.Value {
	var remap_arr = std.json.Array.init(arena);
	for (0..remaps) |i| {
		var from: [64]u8 = undefined;
		var to: [64]u8 = undefined;
		try appendRemap(arena, &remap_arr, try std.fmt.bufPrint(&from, "tcp 192.0.2.{d}/32:{d}", .{ i, 8000 + i }), try std.fmt.bufPrint(&to, "tcp 127.0.0.1:{d}", .{9000 + i}));
	}
	var net: std.json.ObjectMap = .empty;
	try net.put(arena, "rules", .{ .array = rules });
	try net.put(arena, "remap", .{ .array = remap_arr });
	try net.put(arena, "l7", try std.json.parseFromSliceLeaky(std.json.Value, arena, "{\"rules\":[{\"allow\":\"a.example.com\"}]}", .{}));
	return .{ .object = net };
}

test "both loaders take 256 maximum-length rules whole or not at all" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const rt = try tmpRuntimeDir(gpa, io);
	defer gpa.free(rt);
	defer cwd.deleteTree(io, rt) catch {};

	var arena_state = std.heap.ArenaAllocator.init(gpa);
	defer arena_state.deinit();
	const arena = arena_state.allocator();
	const ports = filter.l7PortsForBase(filter.l7_default_base);
	const web: filter.IpAddr = .{ .ipv4 = .{ 203, 0, 113, 9 } };

	// (a) The longest line `rules add` takes in natural form, 256 times over: an
	// IPv6 /128 with a proto, 54 bytes a line. Every one goes through the verb's
	// own validation (rule.append). Plus 62 user remaps, which with the two L7
	// funnel remaps fill the filter's remap table exactly.
	var v6_rules = std.json.Array.init(arena);
	for (0..filter.max_rules) |i| {
		var cidr: [64]u8 = undefined;
		_ = try rules_module.rule.append(arena, &v6_rules, .allow, try std.fmt.bufPrint(&cidr, "tcp 2001:0db8:0000:0000:0000:0000:{x:0>4}:{x:0>4}/128", .{ i / 256, i % 256 }));
	}
	const net_a = try capNetwork(arena, v6_rules, filter.max_remap_rules - 2);
	try reload.writeRuntimeRules(gpa, io, rt, net_a, filter.l7_default_base);

	var want: std.ArrayList(u8) = .empty;
	defer want.deinit(gpa);
	try reload.renderRules(gpa, net_a, filter.l7_default_base, &want);

	// The shim's loader, on an fd held from here on, and the proxy's: each takes
	// exactly what renderRules produced, trailer stripped.
	const fd = try holdFd(gpa, rt, "netfilter-rules");
	defer _ = std.c.close(fd);
	var shim_buf: [filter.rule_file_read_len]u8 = undefined;
	try std.testing.expectEqualSlices(u8, want.items, filter.readHeldRuleFile(fd, &shim_buf) orelse return error.TestUnexpectedResult);
	var proxy_buf: [filter.rule_file_read_len]u8 = undefined;
	var refused: ?main.FileKey = null;
	switch (main.readPolledInto(rt, "netfilter-rules", &proxy_buf, &refused)) {
		.install => |got| try std.testing.expectEqualSlices(u8, want.items, got),
		else => return error.TestUnexpectedResult,
	}

	// Parsed: both funnels present and the remap table exactly full. The CIDR
	// table is full too, and it is the LAST four user rules that do not fit (the
	// L7 prologue's four lines come first): the unchanged cap dropping the tail of
	// a first-match list whose default is deny, which only ever narrows.
	const rs = filter.parseRules(want.items);
	try std.testing.expectEqual(ports.tls, (rs.evaluateRemap(.tcp, web, 443) orelse return error.TestUnexpectedResult).port);
	try std.testing.expectEqual(ports.http, (rs.evaluateRemap(.tcp, web, 80) orelse return error.TestUnexpectedResult).port);
	try std.testing.expectEqual(@as(usize, filter.max_remap_rules), rs.remap_len);
	try std.testing.expectEqual(@as(usize, filter.max_rules), rs.len);

	// (b) 256 rules at the verb's 128-byte line maximum (`rules add` accepts a
	// spec padded with whitespace after the proto): 129 bytes a line with the
	// newline, past the budget before L7 adds a byte. Built through rule.append,
	// so the verb provably accepts every one of them.
	var padded_rules = std.json.Array.init(arena);
	for (0..filter.max_rules) |i| {
		var addr_buf: [32]u8 = undefined;
		const addr = try std.fmt.bufPrint(&addr_buf, "198.51.100.{d}/32", .{i});
		var cidr: [128]u8 = undefined;
		const spec_len = 128 - "allow ".len;
		@memcpy(cidr[0..3], "tcp");
		@memset(cidr[3 .. spec_len - addr.len], ' ');
		@memcpy(cidr[spec_len - addr.len .. spec_len], addr);
		_ = try rules_module.rule.append(arena, &padded_rules, .allow, cidr[0..spec_len]);
	}
	const net_b = try capNetwork(arena, padded_rules, 0);
	try std.testing.expectError(error.RuleFileOverBudget, reload.writeRuntimeRules(gpa, io, rt, net_b, filter.l7_default_base));

	// Refused, so neither loader can see any of it: the file is still (a), whole.
	try std.testing.expectEqualSlices(u8, want.items, filter.readHeldRuleFile(fd, &shim_buf) orelse return error.TestUnexpectedResult);
	switch (main.readPolledInto(rt, "netfilter-rules", &proxy_buf, &refused)) {
		.install => |got| try std.testing.expectEqualSlices(u8, want.items, got),
		else => return error.TestUnexpectedResult,
	}
}

fn writeWireFile(io: std.Io, rt: []const u8, name: []const u8, bytes: []const u8) !void {
	var path_buf: [std.fs.max_path_bytes]u8 = undefined;
	const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ rt, name });
	const f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
	defer f.close(io);
	var wbuf: [4096]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

test "readWholeAlloc: l7-rules past the old 16 KiB buffer is read whole, so its trailing host deny survives" {
	// The proxy read l7-rules and l7-inject-hosts into 16 KiB buffers and parsed
	// whatever prefix fit. A prefix of l7-rules is WIDER than the file: a cut
	// path allows more than the rule did, and renderL7 puts the `deny <host>`
	// lines last, so a host they name falls back to L4 when they are cut off.
	// Both files are renamed into place, so a whole read is always available.
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const rt = try tmpRuntimeDir(gpa, io);
	defer gpa.free(rt);
	defer cwd.deleteTree(io, rt) catch {};

	var doc: std.ArrayList(u8) = .empty;
	defer doc.deinit(gpa);
	try doc.appendSlice(gpa, "mode terminate\n");
	var path: [240]u8 = undefined;
	@memset(&path, 'p');
	path[0] = '/';
	for (0..100) |i| {
		var line: [320]u8 = undefined;
		try doc.appendSlice(gpa, try std.fmt.bufPrint(&line, "allow host{d}.example.com {s}\n", .{ i, &path }));
	}
	try doc.appendSlice(gpa, "deny tail.example.com\n");
	try std.testing.expect(doc.items.len > 16 * 1024);
	try writeWireFile(io, rt, "l7-rules", doc.items);

	// What the old prefix left: the trailing deny gone, the host unnamed.
	var prefix_rs: filter.L7RuleSet = undefined;
	filter.parseL7Rules(doc.items[0 .. 16 * 1024], &prefix_rs);
	try std.testing.expectEqual(filter.L7Verdict.no_match, prefix_rs.evaluate("tail.example.com", "/"));

	const got = main.readWholeAlloc(rt, "l7-rules");
	defer got.deinit();
	switch (got) {
		.bytes => |b| {
			try std.testing.expectEqualSlices(u8, doc.items, b.content);
			var rs: filter.L7RuleSet = undefined;
			filter.parseL7Rules(b.content, &rs);
			try std.testing.expectEqual(filter.L7Verdict.deny, rs.evaluate("tail.example.com", "/"));
		},
		.keep => return error.TestUnexpectedResult,
	}

	// Missing is the empty document, as it always was.
	const none = main.readWholeAlloc(rt, "l7-inject-hosts");
	defer none.deinit();
	switch (none) {
		.bytes => |b| try std.testing.expectEqual(@as(usize, 0), b.content.len),
		.keep => return error.TestUnexpectedResult,
	}

	// Past the ceiling, not read at all: the caller keeps the table it has
	// rather than parse a part of it.
	const huge = try gpa.alloc(u8, main.wire_file_read_limit + 1);
	defer gpa.free(huge);
	@memset(huge, '#');
	try writeWireFile(io, rt, "l7-inject-hosts", huge);
	const big = main.readWholeAlloc(rt, "l7-inject-hosts");
	defer big.deinit();
	try std.testing.expect(big == .keep);
}

test "readWholeAlloc and readPolledInto: only a file that is not there reads as missing; one that cannot be opened is not read" {
	// readWholeAlloc took ANY failed open(2) for a missing file, so an l7-rules
	// it merely could not open parsed as the empty document -- and an empty
	// l7-rules sends every host to the L4 decision, past the deny lines the file
	// holds. Missing (ENOENT, or ENOTDIR under a path component that is not a
	// directory) is still the empty document there, and still deny-all for
	// netfilter-rules; any other failure is a file not read, which stops the
	// proxy deciding new flows until a retry reads it (the WireState test).
	// A symlink to itself (ELOOP) stands in for "there but not openable" because
	// it fails with or without root, where a mode-000 file would not; the next
	// test is the field case, a descriptor shortage.
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const rt = try tmpRuntimeDir(gpa, io);
	defer gpa.free(rt);
	defer cwd.deleteTree(io, rt) catch {};

	var buf: [filter.rule_file_read_len]u8 = undefined;
	var refused: ?main.FileKey = null;

	// ENOENT.
	const none = main.readWholeAlloc(rt, "l7-rules");
	defer none.deinit();
	switch (none) {
		.bytes => |b| try std.testing.expectEqual(@as(usize, 0), b.content.len),
		.keep => return error.TestUnexpectedResult,
	}
	try std.testing.expect(main.readPolledInto(rt, "netfilter-rules", &buf, &refused) == .absent);

	// ENOTDIR: the runtime dir path names a regular file.
	try writeWireFile(io, rt, "not-a-dir", "x\n");
	const file_rt = try std.fs.path.join(gpa, &.{ rt, "not-a-dir" });
	defer gpa.free(file_rt);
	const under_file = main.readWholeAlloc(file_rt, "l7-rules");
	defer under_file.deinit();
	switch (under_file) {
		.bytes => |b| try std.testing.expectEqual(@as(usize, 0), b.content.len),
		.keep => return error.TestUnexpectedResult,
	}
	try std.testing.expect(main.readPolledInto(file_rt, "netfilter-rules", &buf, &refused) == .absent);

	// ELOOP: each name is a symlink to itself (the target is relative to the
	// link's own directory).
	for ([_][:0]const u8{ "l7-rules", "netfilter-rules" }) |name| {
		const link = try std.fs.path.joinZ(gpa, &.{ rt, name });
		defer gpa.free(link);
		try std.testing.expectEqual(@as(c_int, 0), std.c.symlink(name.ptr, link.ptr));
	}
	const looped = main.readWholeAlloc(rt, "l7-rules");
	defer looped.deinit();
	try std.testing.expect(looped == .keep);
	// Not a refusal either: the memory of the last settled refusal (which only
	// dedupes its log line) is left as it was.
	const prior: main.FileKey = .{ .mtime_ns = 1, .size = 1 };
	refused = prior;
	try std.testing.expect(main.readPolledInto(rt, "netfilter-rules", &buf, &refused) == .unreadable);
	try std.testing.expectEqual(prior, refused orelse return error.TestUnexpectedResult);
}

/// The descriptor-shortage test's child: lowers its own descriptor limit to the
/// lowest free descriptor, so every open(2) fails with EMFILE, then runs one
/// reload's three reads on files that are there. 0 when none of them is read
/// and a proxy that had read everything stops deciding new flows and retries;
/// otherwise which step failed.
fn readUnderEmfile(rt: []const u8) c_int {
	const probe = std.c.open("/dev/null", .{ .ACCMODE = .RDONLY });
	if (probe < 0) return 10;
	_ = std.c.close(probe);
	var lim = std.posix.getrlimit(.NOFILE) catch return 11;
	lim.cur = @intCast(probe);
	std.posix.setrlimit(.NOFILE, lim) catch return 12;
	// The shortage is real before any reader is asked.
	const fd = std.c.open("/dev/null", .{ .ACCMODE = .RDONLY });
	if (fd >= 0 or std.posix.errno(fd) != .MFILE) return 13;

	var buf: [filter.rule_file_read_len]u8 = undefined;
	var refused: ?main.FileKey = null;
	const nf = main.readPolledInto(rt, "netfilter-rules", &buf, &refused);
	if (nf != .unreadable) return 1;
	const l7 = main.readWholeAlloc(rt, "l7-rules");
	if (l7 != .keep) return 2;
	const inj = main.readWholeAlloc(rt, "l7-inject-hosts");
	if (inj != .keep) return 3;
	const loaded: main.WireState = .{ .netfilter_rules = true, .l7_rules = true, .l7_inject_hosts = true };
	if (loaded.after(nf, l7, inj).complete()) return 4;
	if (!main.reloadAgain(nf, l7, inj)) return 5;
	return 0;
}

test "a descriptor shortage at the open stops the proxy deciding new flows, and is never read as a missing file" {
	// Linux only: the child is forked with the raw Linux syscall, which the
	// Darwin run of these tests (darwin/checks.nix) must never execute. The test
	// above takes both readers through the same branch on every platform.
	if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
	// The field case: two descriptors per spliced flow, max_conns of them, past
	// a soft limit the proxy could not raise, so a guest holding the proxy's
	// connections open can leave a reload's open(2) of a wire file that is
	// there failing with EMFILE. Read as missing, that was an empty L7 table
	// (every host to the L4 decision) or a deny-all CIDR set with no retry.
	// Kept on, it let the guest keep its new flows on tables an operator had
	// since narrowed, for as long as it held the shortage. Now the proxy decides
	// no new flow until a retry reads every file. The limit is lowered in a
	// forked child so it never reaches the rest of this test binary.
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const rt = try tmpRuntimeDir(gpa, io);
	defer gpa.free(rt);
	defer cwd.deleteTree(io, rt) catch {};

	const l7_doc = "mode terminate\nallow git.example.com /acme/\ndeny tracker.example.com\n";
	try writeWireFile(io, rt, "l7-rules", l7_doc);
	const inj_doc = "api.example.com\n";
	try writeWireFile(io, rt, "l7-inject-hosts", inj_doc);
	const body = "allow 0.0.0.0/0\n";
	const file = try sealed(gpa, body);
	defer gpa.free(file);
	try reload.writeRuntimeFileInPlace(gpa, io, rt, "netfilter-rules", file);

	const rc = std.os.linux.fork();
	if (std.os.linux.errno(rc) != .SUCCESS) return error.ForkFailed;
	// CHILD: only this thread survived the fork, and the readers take no lock
	// (page_allocator, raw libc I/O); no exit handlers run.
	if (rc == 0) std.c._exit(readUnderEmfile(rt));
	var status: u32 = 0;
	while (true) {
		const wr = std.os.linux.waitpid(@intCast(rc), &status, 0);
		if (std.os.linux.errno(wr) == .INTR) continue;
		if (std.os.linux.errno(wr) != .SUCCESS) return error.WaitFailed;
		break;
	}
	try std.testing.expect(std.os.linux.W.IFEXITED(status));
	try std.testing.expectEqual(@as(u32, 0), std.os.linux.W.EXITSTATUS(status));

	// With descriptors to spare the same files read whole, so what the child
	// could not read was the shortage, not the files -- and the retry that gets
	// through takes new flows again.
	const l7 = main.readWholeAlloc(rt, "l7-rules");
	defer l7.deinit();
	switch (l7) {
		.bytes => |b| try std.testing.expectEqualSlices(u8, l7_doc, b.content),
		.keep => return error.TestUnexpectedResult,
	}
	const inj = main.readWholeAlloc(rt, "l7-inject-hosts");
	defer inj.deinit();
	switch (inj) {
		.bytes => |b| try std.testing.expectEqualSlices(u8, inj_doc, b.content),
		.keep => return error.TestUnexpectedResult,
	}
	var buf: [filter.rule_file_read_len]u8 = undefined;
	var refused: ?main.FileKey = null;
	const nf = main.readPolledInto(rt, "netfilter-rules", &buf, &refused);
	switch (nf) {
		.install => |got| try std.testing.expectEqualSlices(u8, body, got),
		else => return error.TestUnexpectedResult,
	}
	const shut: main.WireState = .{ .netfilter_rules = false, .l7_rules = false, .l7_inject_hosts = false };
	try std.testing.expect(shut.after(nf, l7, inj).complete());
}

test "reloadAgain: a reload that kept any table runs again" {
	// loadRules' retry. A kept table may lack a deny the render that signalled
	// this reload just added, and that render's signal is spent, so without a
	// retry the table would stand until some unrelated later render. The L7
	// files count as much as netfilter-rules: a descriptor shortage at
	// l7-rules' open while netfilter-rules installs fine is the case this
	// exists for.
	const whole: main.WholeRead = .{ .bytes = .{ .content = "" } };
	try std.testing.expect(!main.reloadAgain(.{ .install = "" }, whole, whole));
	try std.testing.expect(!main.reloadAgain(.absent, whole, whole));
	try std.testing.expect(main.reloadAgain(.moved, whole, whole));
	try std.testing.expect(main.reloadAgain(.refused, whole, whole));
	try std.testing.expect(main.reloadAgain(.unreadable, whole, whole));
	try std.testing.expect(main.reloadAgain(.{ .install = "" }, .keep, whole));
	try std.testing.expect(main.reloadAgain(.{ .install = "" }, whole, .keep));
}

test "WireState: the proxy decides new flows only while it holds a current reading of every wire file" {
	// What the worker checks, in the critical section it decides a flow in,
	// before it reads any table. A table cannot say deny-all for the proxy -- an
	// L7 allow and the terminate tier only meet the CIDR set's hard floor -- so a
	// reload that cannot read the policy has to stop new flows outright, and a
	// guest that holds the proxy at EMFILE then gets no flow decided on tables an
	// operator has since narrowed.
	const whole: main.WholeRead = .{ .bytes = .{ .content = "" } };
	const sealed_read: main.PolledRead = .{ .install = "" };

	// Start: nothing counts until a reload reads every file. A missing
	// netfilter-rules counts (it is deny-all, RuleSet.fail_closed); one that
	// holds no complete render yet -- an older cogbox's file, a writer killed
	// mid-write, a render still writing -- does not.
	const start: main.WireState = .{};
	try std.testing.expect(!start.complete());
	try std.testing.expect(start.after(sealed_read, whole, whole).complete());
	try std.testing.expect(start.after(.absent, whole, whole).complete());
	try std.testing.expect(!start.after(.refused, whole, whole).complete());
	try std.testing.expect(!start.after(.moved, whole, whole).complete());
	try std.testing.expect(!start.after(.unreadable, whole, whole).complete());
	try std.testing.expect(!start.after(sealed_read, .keep, whole).complete());
	try std.testing.expect(!start.after(sealed_read, whole, .keep).complete());

	// Running: a tear or a mix leaves the last complete render in force and the
	// proxy taking flows -- cutting a running guest off on every overlapping
	// render is what keeping the set avoids.
	const running = start.after(sealed_read, whole, whole);
	try std.testing.expect(running.after(.refused, whole, whole).complete());
	try std.testing.expect(running.after(.moved, whole, whole).complete());

	// A file that is there but cannot be opened stops new flows, and only a
	// complete read (or a missing file) starts them again: a refused or moved
	// read in between says nothing about the policy the proxy failed to read.
	const shut = running.after(.unreadable, whole, whole);
	try std.testing.expect(!shut.complete());
	try std.testing.expect(!shut.after(.refused, whole, whole).complete());
	try std.testing.expect(!shut.after(.moved, whole, whole).complete());
	try std.testing.expect(shut.after(sealed_read, whole, whole).complete());
	try std.testing.expect(shut.after(.absent, whole, whole).complete());

	// An L7 file not read whole stops new flows too, until it is read. The CIDR
	// set it leaves alone is still the last complete render, so a refused
	// netfilter-rules on that retry does not hold the proxy shut.
	const l7_shut = running.after(sealed_read, .keep, whole);
	try std.testing.expect(!l7_shut.complete());
	try std.testing.expect(l7_shut.after(.refused, whole, whole).complete());
	const inj_shut = running.after(sealed_read, whole, .keep);
	try std.testing.expect(!inj_shut.complete());
	try std.testing.expect(inj_shut.after(sealed_read, whole, whole).complete());

	// And a proxy that refuses always reads again: no reload leaves it shut
	// without raising the retry, or it would stay shut until some later render.
	const nfs = [_]main.PolledRead{ sealed_read, .absent, .unreadable, .moved, .refused };
	const l7s = [_]main.WholeRead{ whole, .keep };
	for ([_]main.WireState{ start, running }) |prev| {
		for (nfs) |nf| {
			for (l7s) |l7| {
				for (l7s) |inj| {
					if (!prev.after(nf, l7, inj).complete()) {
						try std.testing.expect(main.reloadAgain(nf, l7, inj));
					}
				}
			}
		}
	}
}
