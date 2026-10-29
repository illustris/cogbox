// `cogbox __plugin-apply-preboot <icd> [--init-only]`: the launcher's per-pass
// live-apply housekeeping. cogbox-launch.sh runs it right after it takes the
// instance config lock, whose fd this process inherits; it never takes that
// lock itself (a second open file description would conflict with its own
// caller's flock).
//
// Phase 0 ships exactly one step: with --init-only (which the launcher passes
// exactly when INIT_ONLY=1), empty <icd>/apply/trash/, bounded at 30 s. The
// snapshot GC fills the trash by renames in the daemon pass, which must never
// pay an O(files) delete before QEMU owns its ports; `cogbox start` runs its
// init pass before that window, so the trash is emptied there. Without the flag
// no tree is ever deleted. Later phases add the holder signal, the orphan build
// unit stop (Phase 1: the cogbox-apply-build-* units it stops do not exist
// before then, so Phase 0 ships no orphan stop), the inflight.json resolution
// and the rollback finish.
//
// It never fails a boot: every problem (a bad argument included) is a warning
// on stderr, and the verb always returns normally (exit 0).

const std = @import("std");
const snapshot = @import("snapshot.zig");

pub const Args = struct {
	icd: ?[]const u8 = null,
	init_only: bool = false,
	/// Unknown options and extra positionals: counted and ignored.
	ignored: usize = 0,
	first_ignored: ?[]const u8 = null,
};

/// Parse `<icd> [--init-only]`. Never fails: an unknown option or a second
/// positional is counted and ignored (the caller warns), so a launcher from a
/// later phase that passes more cannot fail an older binary's boot.
pub fn parseArgs(argv: []const []const u8) Args {
	var args: Args = .{};
	for (argv) |a| {
		if (std.mem.eql(u8, a, "--init-only")) {
			args.init_only = true;
		} else if (args.icd == null and !std.mem.startsWith(u8, a, "-")) {
			args.icd = a;
		} else {
			args.ignored += 1;
			if (args.first_ignored == null) args.first_ignored = a;
		}
	}
	return args;
}

/// What one call did, for the caller to report.
pub const Outcome = struct {
	args: Args,
	/// The trash step's result; null when it did not run (no --init-only, or no
	/// icd).
	trash: ?snapshot.TrashResult = null,
	budget_ms: i64,
};

/// Do the work, printing nothing. `budget_ms` bounds the trash emptying.
pub fn execute(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8, budget_ms: i64) Outcome {
	var o: Outcome = .{ .args = parseArgs(argv), .budget_ms = budget_ms };
	const icd = o.args.icd orelse return o;
	if (o.args.init_only) o.trash = snapshot.emptyTrash(allocator, io, icd, budget_ms);
	return o;
}

/// The CLI entry: execute with the default bound, then print a warning line on
/// stderr for anything that needs one. Silent when all went well.
pub fn run(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) void {
	const o = execute(allocator, io, argv, snapshot.trash_budget_ms);
	var buf: [2048]u8 = undefined;
	var w: std.Io.Writer = .fixed(&buf);
	writeWarnings(&w, o) catch {};
	const out = w.buffered();
	if (out.len == 0) return;
	const stderr = std.Io.File.stderr();
	var wbuf: [256]u8 = undefined;
	var ew = stderr.writer(io, &wbuf);
	ew.interface.writeAll(out) catch return;
	ew.flush() catch {};
}

/// One `cogbox: warning: ...` line per problem in `o`.
pub fn writeWarnings(w: *std.Io.Writer, o: Outcome) !void {
	const prefix = "cogbox: warning: plugin apply preboot: ";
	if (o.args.first_ignored) |first| try w.print(prefix ++ "ignoring {d} unknown argument(s), first '{s}'\n", .{ o.args.ignored, first });
	const icd = o.args.icd orelse return w.writeAll(prefix ++ "no instance config dir given; nothing done\n");
	const r = o.trash orelse return;
	switch (r.outcome) {
		.absent, .emptied => {},
		.deadline => try w.print(prefix ++ "emptying {s}/apply/trash stopped after {d} s ({d} removed); the rest waits for the next init pass\n", .{ icd, @divTrunc(o.budget_ms, 1000), r.removed }),
		.failed => try w.print(prefix ++ "could not empty {s}/apply/trash ({s}; {d} removed); the rest waits for the next init pass\n", .{ icd, if (r.first_error) |e| @errorName(e) else "unknown error", r.removed }),
	}
}

// --- tests ---------------------------------------------------------------------

const t = std.testing;

test "parseArgs: <icd> [--init-only]; unknown options and extra arguments are only counted" {
	{
		const a = parseArgs(&.{"/icd"});
		try t.expectEqualStrings("/icd", a.icd.?);
		try t.expect(!a.init_only);
		try t.expectEqual(@as(usize, 0), a.ignored);
	}
	{
		const a = parseArgs(&.{ "/icd", "--init-only" });
		try t.expectEqualStrings("/icd", a.icd.?);
		try t.expect(a.init_only);
	}
	{
		const a = parseArgs(&.{ "--init-only", "/icd" });
		try t.expectEqualStrings("/icd", a.icd.?);
		try t.expect(a.init_only);
		try t.expectEqual(@as(usize, 0), a.ignored);
	}
	{
		const a = parseArgs(&.{ "/icd", "--from-a-later-phase", "/other" });
		try t.expectEqualStrings("/icd", a.icd.?);
		try t.expect(!a.init_only);
		try t.expectEqual(@as(usize, 2), a.ignored);
		try t.expectEqualStrings("--from-a-later-phase", a.first_ignored.?);
	}
	try t.expect(parseArgs(&.{}).icd == null);
}

fn scratchIcd(io: std.Io) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	const rel = try std.fmt.allocPrint(t.allocator, "zig-preboot-test-{x}", .{&rnd});
	defer t.allocator.free(rel);
	const trash = try std.fmt.allocPrint(t.allocator, "{s}/apply/trash/old-snap/src/p", .{rel});
	defer t.allocator.free(trash);
	try std.Io.Dir.cwd().createDirPath(io, trash);
	const f = try std.fmt.allocPrint(t.allocator, "{s}/default.nix", .{trash});
	defer t.allocator.free(f);
	(try std.Io.Dir.cwd().createFile(io, f, .{})).close(io);
	const abs = try std.Io.Dir.cwd().realPathFileAlloc(io, rel, t.allocator);
	defer t.allocator.free(abs);
	return t.allocator.dupe(u8, abs);
}

fn trashPlanted(io: std.Io, icd: []const u8) bool {
	var buf: [std.fs.max_path_bytes]u8 = undefined;
	const p = std.fmt.bufPrint(&buf, "{s}/apply/trash/old-snap", .{icd}) catch return false;
	std.Io.Dir.cwd().access(io, p, .{}) catch return false;
	return true;
}

test "execute: without --init-only a planted trash tree stays; with it the trash is emptied" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const icd = try scratchIcd(io);
	defer t.allocator.free(icd);
	defer std.Io.Dir.cwd().deleteTree(io, icd) catch {};

	// A daemon pass (no --init-only) never deletes a tree.
	const daemon = execute(t.allocator, io, &.{icd}, snapshot.trash_budget_ms);
	try t.expect(daemon.trash == null);
	try t.expect(trashPlanted(io, icd));

	const init_pass = execute(t.allocator, io, &.{ icd, "--init-only" }, snapshot.trash_budget_ms);
	try t.expectEqual(snapshot.TrashOutcome.emptied, init_pass.trash.?.outcome);
	try t.expect(!trashPlanted(io, icd));
	var buf: [std.fs.max_path_bytes]u8 = undefined;
	try std.Io.Dir.cwd().access(io, try std.fmt.bufPrint(&buf, "{s}/apply/trash", .{icd}), .{});
	try expectWarnings(init_pass, "");
}

test "execute: never fails -- no icd, a missing icd, a relative icd, an unknown flag, no budget" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();

	const none = execute(t.allocator, io, &.{}, snapshot.trash_budget_ms);
	try t.expect(none.trash == null);
	try expectWarnings(none, "cogbox: warning: plugin apply preboot: no instance config dir given; nothing done\n");

	const missing = execute(t.allocator, io, &.{ "/nonexistent/cogbox-preboot-test/icd", "--init-only" }, snapshot.trash_budget_ms);
	try t.expectEqual(snapshot.TrashOutcome.absent, missing.trash.?.outcome);
	try expectWarnings(missing, "");

	const relative = execute(t.allocator, io, &.{ "relative/icd", "--init-only" }, snapshot.trash_budget_ms);
	try t.expectEqual(snapshot.TrashOutcome.failed, relative.trash.?.outcome);
	try expectWarnings(relative, "cogbox: warning: plugin apply preboot: could not empty relative/icd/apply/trash (RelativeInstanceDir; 0 removed); the rest waits for the next init pass\n");

	const icd = try scratchIcd(io);
	defer t.allocator.free(icd);
	defer std.Io.Dir.cwd().deleteTree(io, icd) catch {};
	// An unknown option is ignored (and warned about); the known flag applies.
	const later = execute(t.allocator, io, &.{ icd, "--some-later-flag", "--init-only" }, snapshot.trash_budget_ms);
	try t.expect(!trashPlanted(io, icd));
	try expectWarnings(later, "cogbox: warning: plugin apply preboot: ignoring 1 unknown argument(s), first '--some-later-flag'\n");

	// An exhausted budget leaves the tree, says so, and still returns.
	const icd2 = try scratchIcd(io);
	defer t.allocator.free(icd2);
	defer std.Io.Dir.cwd().deleteTree(io, icd2) catch {};
	const late = execute(t.allocator, io, &.{ icd2, "--init-only" }, 0);
	try t.expectEqual(snapshot.TrashOutcome.deadline, late.trash.?.outcome);
	try t.expect(trashPlanted(io, icd2));
	var want_buf: [std.fs.max_path_bytes + 160]u8 = undefined;
	try expectWarnings(late, try std.fmt.bufPrint(&want_buf, "cogbox: warning: plugin apply preboot: emptying {s}/apply/trash stopped after 0 s (0 removed); the rest waits for the next init pass\n", .{icd2}));
}

fn expectWarnings(o: Outcome, want: []const u8) !void {
	var buf: [2048]u8 = undefined;
	var w: std.Io.Writer = .fixed(&buf);
	try writeWarnings(&w, o);
	try t.expectEqualStrings(want, w.buffered());
}
