// `cogbox __plugin-apply-preboot <icd> [--init-only] [--runtime DIR] [--name NAME]`:
// the launcher's per-pass live-apply housekeeping. cogbox-launch.sh runs it
// right after it takes the instance config lock, whose fd this process
// inherits; it never takes that lock itself (a second open file description
// would conflict with its own caller's flock). `--runtime` is the instance's
// runtime dir (its `<runtime>.lock` is the lifetime lock that says whether the
// instance runs) and `--name` the instance name the stamped message names;
// without `--runtime` the instance counts as running.
//
// In one call, in this order (spec section 6, "Internal verb"):
//   1. on a stopped instance, signal the live apply holder apply/active names
//      through a pidfd (SIGTERM, at most 30 s, then SIGKILL, at most 10 s);
//   2. with the apply flock free (LOCK_NB), stop an orphaned build unit whose
//      InvocationID still matches;
//   3. on a stopped instance with the apply flock free, resolve inflight.json
//      (`unknown`, unless an intent or a record exists, which is rolled back);
//      otherwise leave it for a recoverer that can still read the guest (an
//      init pass on a running instance never interferes with an apply);
//   4. rollback.finishPending, sweeping leftover intent tmp names only when it
//      holds the apply flock;
//   5. only with --init-only (which the launcher passes exactly when
//      INIT_ONLY=1), empty <icd>/apply/trash/, bounded at 30 s; without the
//      flag it never deletes a tree.
// It exits 78 with the stamped `cogbox: ` message when an intent remains and
// the instance is not running (the launcher checks for intents itself too,
// whatever this exit). Every other problem (a bad argument included) is a
// warning on stderr, and the exit is 0.

const std = @import("std");
const builtin = @import("builtin");
const snapshot = @import("snapshot.zig");
const plugin = @import("main.zig");
const apply = @import("apply.zig");
const rollback = @import("rollback.zig");

pub const Args = struct {
	icd: ?[]const u8 = null,
	init_only: bool = false,
	runtime: ?[]const u8 = null,
	name: ?[]const u8 = null,
	/// Unknown options and extra positionals: counted and ignored.
	ignored: usize = 0,
	first_ignored: ?[]const u8 = null,
};

/// Parse `<icd> [--init-only] [--runtime DIR] [--name NAME]`. Never fails: an
/// unknown option, a valued option without its value, or a second positional
/// is counted and ignored (the caller warns), so a launcher from a later
/// phase that passes more cannot fail an older binary's boot.
pub fn parseArgs(argv: []const []const u8) Args {
	var args: Args = .{};
	var i: usize = 0;
	while (i < argv.len) : (i += 1) {
		const a = argv[i];
		if (std.mem.eql(u8, a, "--init-only")) {
			args.init_only = true;
			continue;
		}
		var matched = false;
		inline for (.{ "--runtime", "--name" }) |flag| {
			var hit = false;
			var value: ?[]const u8 = null;
			if (std.mem.eql(u8, a, flag)) {
				hit = true;
				if (i + 1 < argv.len) {
					i += 1;
					value = argv[i];
				}
			} else if (std.mem.startsWith(u8, a, flag ++ "=")) {
				hit = true;
				value = a[flag.len + 1 ..];
			}
			if (hit) {
				matched = true;
				const v = value orelse "";
				if (v.len == 0) {
					args.ignored += 1;
					if (args.first_ignored == null) args.first_ignored = a;
				} else if (comptime std.mem.eql(u8, flag, "--runtime")) {
					args.runtime = v;
				} else {
					args.name = v;
				}
			}
		}
		if (matched) continue;
		if (args.icd == null and !std.mem.startsWith(u8, a, "-")) {
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
	/// Owns what steps 1-4 allocated (deinit frees it).
	arena: ?*std.heap.ArenaAllocator = null,
	/// Whether the instance runs; null without --runtime (counts as running).
	running: ?bool = null,
	/// Steps 1-3; null when they did not run (no icd).
	apply: ?apply.PrebootApply = null,
	/// Step 4's warnings and what stayed pending.
	finish_warnings: []const []const u8 = &.{},
	pending: usize = 0,
	pending_error: ?anyerror = null,

	/// 78 when an intent remains on a stopped instance, else 0.
	pub fn exitCode(o: Outcome) u8 {
		return if (o.pending > 0 and o.running == false) 78 else 0;
	}

	pub fn deinit(o: *Outcome, allocator: std.mem.Allocator) void {
		if (o.arena) |a| {
			a.deinit();
			allocator.destroy(a);
			o.arena = null;
		}
	}
};

/// The instance config dir's owner when it is not root and this runs as root
/// (a launcher under sudo): new apply state is handed to it.
fn ownerOf(allocator: std.mem.Allocator, icd: []const u8) ?u32 {
	if (comptime builtin.os.tag != .linux) return null;
	if (std.c.geteuid() != 0) return null;
	const z = allocator.dupeZ(u8, icd) catch return null;
	defer allocator.free(z);
	var stx: std.os.linux.Statx = undefined;
	const rc = std.os.linux.statx(std.os.linux.AT.FDCWD, z, 0, .{ .UID = true }, &stx);
	if (std.os.linux.errno(rc) != .SUCCESS or stx.uid == 0) return null;
	return stx.uid;
}

/// Steps 1-4 against `icd` (an existing absolute dir). Allocates in `arena`.
fn applySteps(arena: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map, icd: []const u8, o: *Outcome) void {
	const join = std.fs.path.join;
	const rt = o.args.runtime;
	const name = std.fs.path.basename(icd);
	const instance: ?[]const u8 = o.args.name orelse if (std.mem.eql(u8, name, "default")) null else name;
	const ctx: plugin.Ctx = .{
		.allocator = arena,
		.io = io,
		.parent_env = env,
		.instance = instance,
		.config_path = join(arena, &.{ icd, "config.json" }) catch return,
		// Without --runtime no runtime is known: a path that cannot exist, so
		// a rollback's policy reload finds no passt and skips (the instance
		// counts as running for every other step).
		.runtime_path = rt orelse (join(arena, &.{ icd, ".preboot-no-runtime" }) catch return),
		.user_flake_dir = join(arena, &.{ icd, "flake" }) catch return,
		.plugins_flake_dir = join(arena, &.{ icd, "plugins-flake" }) catch return,
		.sources_dir = join(arena, &.{ icd, "plugin-sources" }) catch return,
		.cache_dir = join(arena, &.{ icd, "plugin-cache" }) catch return,
		.real_uid = ownerOf(arena, icd),
	};
	if (rt != null) o.running = plugin.isRunning(&ctx);
	// The apply flock: `<config>/.locks/<name>.apply.lock`, where <config> is
	// the icd's grandparent. Opened, never created (no lock file: no apply or
	// plugin change ever ran under this cogbox), close-on-exec.
	var lock: ?std.Io.File = null;
	defer if (lock) |f| f.close(io);
	if (std.fs.path.dirname(icd)) |instances| if (std.fs.path.dirname(instances)) |config_dir| {
		const lp = std.fmt.allocPrint(arena, "{s}/.locks/{s}.apply.lock", .{ config_dir, name }) catch return;
		lock = std.Io.Dir.cwd().openFile(io, lp, .{}) catch null;
	};
	const pa = apply.prebootApply(arena, &ctx, o.running, if (lock) |f| f.handle else null);
	o.apply = pa;
	// One finish per pass (its bound, 240 s, counts one inside the launcher's
	// 360 s): the recovery's, when its rollback ran one and printed its own
	// warnings.
	const fin = pa.fin orelse rollback.finishPending(arena, &ctx, .{ .holds_apply_flock = pa.flock == .taken });
	o.finish_warnings = if (pa.fin != null) &.{} else fin.warnings;
	o.pending = fin.pending;
	o.pending_error = fin.pending_error;
}

/// Do the work, printing nothing. `budget_ms` bounds the trash emptying.
pub fn execute(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, argv: []const []const u8, budget_ms: i64) Outcome {
	var o: Outcome = .{ .args = parseArgs(argv), .budget_ms = budget_ms };
	const icd = o.args.icd orelse return o;
	if (std.fs.path.isAbsolute(icd)) {
		if (std.Io.Dir.cwd().access(io, icd, .{})) |_| {
			if (allocator.create(std.heap.ArenaAllocator)) |arena_state| {
				arena_state.* = .init(allocator);
				o.arena = arena_state;
				const arena = arena_state.allocator();
				var empty = std.process.Environ.Map.init(arena);
				applySteps(arena, io, env orelse &empty, icd, &o);
			} else |_| {}
		} else |_| {}
	}
	if (o.args.init_only) o.trash = snapshot.emptyTrash(allocator, io, icd, budget_ms);
	return o;
}

/// The CLI entry: execute with the default bound, then print a warning line on
/// stderr for anything that needs one, and the stamped message when an intent
/// remains on a stopped instance. Returns the exit code (78 or 0).
pub fn run(allocator: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map, argv: []const []const u8) u8 {
	var o = execute(allocator, io, env, argv, snapshot.trash_budget_ms);
	defer o.deinit(allocator);
	var buf: [8192]u8 = undefined;
	var w: std.Io.Writer = .fixed(&buf);
	writeWarnings(&w, o) catch {};
	const out = w.buffered();
	if (out.len > 0) {
		const stderr = std.Io.File.stderr();
		var wbuf: [256]u8 = undefined;
		var ew = stderr.writer(io, &wbuf);
		ew.interface.writeAll(out) catch {};
		ew.flush() catch {};
	}
	return o.exitCode();
}

/// One `cogbox: warning: ...` line per problem in `o`, and the stamped
/// `cogbox: ` message for an intent that remains on a stopped instance.
pub fn writeWarnings(w: *std.Io.Writer, o: Outcome) !void {
	const prefix = "cogbox: warning: plugin apply preboot: ";
	if (o.args.first_ignored) |first| try w.print(prefix ++ "ignoring {d} unknown argument(s), first '{s}'\n", .{ o.args.ignored, first });
	const icd = o.args.icd orelse return w.writeAll(prefix ++ "no instance config dir given; nothing done\n");
	if (o.apply) |pa| {
		if (pa.holder == .alive) try w.writeAll(prefix ++ "a live apply did not exit after SIGTERM and SIGKILL; continuing\n");
		if (pa.orphan_stopped) try w.writeAll(prefix ++ "stopped the build unit an interrupted live apply left running\n");
		if (pa.inflight) |rec| switch (rec) {
			.resolved => try w.writeAll(prefix ++ "settled a live apply that was interrupted; see 'cogbox plugin apply --status' (if it was not rolled back, the next boot may include a change the sandbox rejected)\n"),
			.unresolved => try w.writeAll(prefix ++ "could not settle an interrupted live apply; it stays for the next plugin command\n"),
		};
	}
	for (o.finish_warnings) |line| try w.print("cogbox: warning: {s}\n", .{line});
	if (o.pending > 0) {
		if (o.running == false) {
			try rollback.writePendingMessage(w, o.pending_error orelse error.RollbackPending, o.args.name);
		} else {
			try w.writeAll(prefix ++ "an automatic plugin rollback is pending; it finishes before the next plugin change or start\n");
		}
	}
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
	var daemon = execute(t.allocator, io, null, &.{icd}, snapshot.trash_budget_ms);
	defer daemon.deinit(t.allocator);
	try t.expect(daemon.trash == null);
	try t.expect(trashPlanted(io, icd));

	var init_pass = execute(t.allocator, io, null, &.{ icd, "--init-only" }, snapshot.trash_budget_ms);
	defer init_pass.deinit(t.allocator);
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

	var none = execute(t.allocator, io, null, &.{}, snapshot.trash_budget_ms);
	defer none.deinit(t.allocator);
	try t.expect(none.trash == null);
	try expectWarnings(none, "cogbox: warning: plugin apply preboot: no instance config dir given; nothing done\n");

	var missing = execute(t.allocator, io, null, &.{ "/nonexistent/cogbox-preboot-test/icd", "--init-only" }, snapshot.trash_budget_ms);
	defer missing.deinit(t.allocator);
	try t.expectEqual(snapshot.TrashOutcome.absent, missing.trash.?.outcome);
	try expectWarnings(missing, "");

	var relative = execute(t.allocator, io, null, &.{ "relative/icd", "--init-only" }, snapshot.trash_budget_ms);
	defer relative.deinit(t.allocator);
	try t.expectEqual(snapshot.TrashOutcome.failed, relative.trash.?.outcome);
	try expectWarnings(relative, "cogbox: warning: plugin apply preboot: could not empty relative/icd/apply/trash (RelativeInstanceDir; 0 removed); the rest waits for the next init pass\n");

	const icd = try scratchIcd(io);
	defer t.allocator.free(icd);
	defer std.Io.Dir.cwd().deleteTree(io, icd) catch {};
	// An unknown option is ignored (and warned about); the known flag applies.
	var later = execute(t.allocator, io, null, &.{ icd, "--some-later-flag", "--init-only" }, snapshot.trash_budget_ms);
	defer later.deinit(t.allocator);
	try t.expect(!trashPlanted(io, icd));
	try expectWarnings(later, "cogbox: warning: plugin apply preboot: ignoring 1 unknown argument(s), first '--some-later-flag'\n");

	// An exhausted budget leaves the tree, says so, and still returns.
	const icd2 = try scratchIcd(io);
	defer t.allocator.free(icd2);
	defer std.Io.Dir.cwd().deleteTree(io, icd2) catch {};
	var late = execute(t.allocator, io, null, &.{ icd2, "--init-only" }, 0);
	defer late.deinit(t.allocator);
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

test "parseArgs: --runtime and --name, spaced or with '='; a missing value is only counted" {
	const a = parseArgs(&.{ "/icd", "--runtime", "/run/x/cogbox-demo", "--name=demo", "--init-only" });
	try t.expectEqualStrings("/icd", a.icd.?);
	try t.expectEqualStrings("/run/x/cogbox-demo", a.runtime.?);
	try t.expectEqualStrings("demo", a.name.?);
	try t.expect(a.init_only);
	try t.expectEqual(@as(usize, 0), a.ignored);
	const b = parseArgs(&.{ "/icd", "--runtime=/rt", "--name" });
	try t.expectEqualStrings("/rt", b.runtime.?);
	try t.expect(b.name == null);
	try t.expectEqual(@as(usize, 1), b.ignored);
	try t.expectEqualStrings("--name", b.first_ignored.?);
}

test "execute: a rollback intent that cannot finish exits 78 with the stamped line on a stopped instance, and only warns on a running one" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const icd = try scratchIcd(io);
	defer t.allocator.free(icd);
	defer std.Io.Dir.cwd().deleteTree(io, icd) catch {};
	// A zero-length intent: it never parses, so no finish can complete it.
	var buf: [std.fs.max_path_bytes]u8 = undefined;
	try std.Io.Dir.cwd().createDirPath(io, try std.fmt.bufPrint(&buf, "{s}/apply/rollback", .{icd}));
	(try std.Io.Dir.cwd().createFile(io, try std.fmt.bufPrint(&buf, "{s}/apply/rollback/0123456789abcdef.intent", .{icd}), .{})).close(io);
	const rt = try std.fmt.allocPrint(t.allocator, "{s}/run/cogbox-demo", .{icd});
	defer t.allocator.free(rt);

	// Stopped (no lifetime lock held): 78, and the message names the instance.
	var stopped = execute(t.allocator, io, null, &.{ icd, "--runtime", rt, "--name", "demo" }, snapshot.trash_budget_ms);
	defer stopped.deinit(t.allocator);
	try t.expectEqual(@as(u8, 78), stopped.exitCode());
	try t.expectEqual(@as(usize, 1), stopped.pending);
	{
		var wbuf: [4096]u8 = undefined;
		var w: std.Io.Writer = .fixed(&wbuf);
		try writeWarnings(&w, stopped);
		try t.expect(std.mem.endsWith(u8, w.buffered(), "); free disk space, or run 'cogbox plugin apply --abandon-rollback -n demo'\n"));
		try t.expect(std.mem.indexOf(u8, w.buffered(), "cogbox: an automatic plugin rollback could not be finished (") != null);
	}

	// Running (another description holds <runtime>.lock): exit 0, a warning.
	try std.Io.Dir.cwd().createDirPath(io, try std.fmt.bufPrint(&buf, "{s}/run", .{icd}));
	const lock = try std.Io.Dir.cwd().createFile(io, try std.fmt.bufPrint(&buf, "{s}.lock", .{rt}), .{});
	defer lock.close(io);
	try t.expect(std.c.flock(lock.handle, std.posix.LOCK.EX) == 0);
	var running = execute(t.allocator, io, null, &.{ icd, "--runtime", rt }, snapshot.trash_budget_ms);
	defer running.deinit(t.allocator);
	try t.expectEqual(@as(u8, 0), running.exitCode());
	try t.expect(running.running.?);
	{
		var wbuf: [4096]u8 = undefined;
		var w: std.Io.Writer = .fixed(&wbuf);
		try writeWarnings(&w, running);
		try t.expectEqualStrings("cogbox: warning: plugin apply preboot: an automatic plugin rollback is pending; it finishes before the next plugin change or start\n", w.buffered());
	}

	// Without --runtime the state is unknown, which counts as running.
	var unknown = execute(t.allocator, io, null, &.{icd}, snapshot.trash_budget_ms);
	defer unknown.deinit(t.allocator);
	try t.expect(unknown.running == null);
	try t.expectEqual(@as(u8, 0), unknown.exitCode());
	try t.expectEqual(@as(usize, 1), unknown.pending);
}
