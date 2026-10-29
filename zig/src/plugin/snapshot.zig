// Live plugin apply: snapshot helpers.
//
// Phase 0 ships the two pieces the boot path needs before any apply exists:
//   - `comp`, the identity of a composition's bytes that a runner record
//     (runner.path line 3) and every snapshot's meta.json carry:
//     sha256(flake.nix || 0x00 || flake.lock) as 64 lowercase hex digits, a
//     missing flake.lock hashing as empty. The launcher computes the same
//     bytes in bash (`{ cat flake.nix; printf '\0'; cat flake.lock; } |
//     sha256sum`, the lock only when it exists), so the test vectors below pin
//     the format both sides must agree on.
//   - the trash emptier. The snapshot GC only RENAMES trees nothing names into
//     <icd>/apply/trash/ (O(1) on the same filesystem, so it is safe inside the
//     launcher's daemon pass, which must own a live QEMU within `cogbox start`'s
//     60 s). Emptying the trash is the one O(files) delete, and it runs bounded
//     (30 s by default) outside that window: from an init-only launcher pass
//     (`__plugin-apply-preboot --init-only`) and, later, in an apply's build phase.
//
// Snapshot source trees are `cp -al` hard links of plugin-sources/, so the
// emptier only ever unlinks names: a file still linked from plugin-sources/ (or
// from another snapshot) keeps its inode and bytes. It never follows a symlink.

const std = @import("std");

pub const comp_hex_len = 64;
/// A composition identity: lowercase hex sha256 (see the file comment).
pub const Comp = [comp_hex_len]u8;

/// comp of an in-memory composition.
pub fn compOfBytes(flake_nix: []const u8, flake_lock: []const u8) Comp {
	var h = std.crypto.hash.sha2.Sha256.init(.{});
	h.update(flake_nix);
	h.update(&[_]u8{0});
	h.update(flake_lock);
	var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
	h.final(&digest);
	return std.fmt.bytesToHex(digest, .lower);
}

/// comp of the composition stored in `dir` (`<dir>/flake.nix` and
/// `<dir>/flake.lock`), streamed so no size cap applies. A missing flake.lock
/// hashes as an empty one: a composition whose `nix flake lock` failed (only a
/// warning in finalizeComposition) still has a comp, so its runner record keeps
/// the launcher's fast path, which computes the same value (cogbox-launch.sh
/// comp_of_dir). nix refuses a zero-length lock, so no runner is ever recorded
/// for one that shares that comp. Null when flake.nix is missing or either file
/// exists but cannot be read: a caller with no comp writes no fast-path record
/// (the boot then evaluates, which is always correct).
pub fn compOfDir(io: std.Io, dir: []const u8) ?Comp {
	var h = std.crypto.hash.sha2.Sha256.init(.{});
	var path_buf: [std.fs.max_path_bytes]u8 = undefined;
	const nix_path = std.fmt.bufPrint(&path_buf, "{s}/flake.nix", .{dir}) catch return null;
	hashFileInto(io, &h, nix_path) catch return null;
	h.update(&[_]u8{0});
	const lock_path = std.fmt.bufPrint(&path_buf, "{s}/flake.lock", .{dir}) catch return null;
	// FileNotFound comes only from the open, before any byte was hashed.
	hashFileInto(io, &h, lock_path) catch |err| switch (err) {
		error.FileNotFound => {},
		else => return null,
	};
	var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
	h.final(&digest);
	return std.fmt.bytesToHex(digest, .lower);
}

fn hashFileInto(io: std.Io, h: *std.crypto.hash.sha2.Sha256, path: []const u8) !void {
	const file = try std.Io.Dir.cwd().openFile(io, path, .{});
	defer file.close(io);
	var buf: [8192]u8 = undefined;
	var reader = file.reader(io, &buf);
	var chunk: [8192]u8 = undefined;
	while (true) {
		const n = try reader.interface.readSliceShort(&chunk);
		h.update(chunk[0..n]);
		if (n < chunk.len) return;
	}
}

// --- trash emptier -------------------------------------------------------------

/// The emptier's default bound (spec: "bounded at 30 s each time").
pub const trash_budget_ms: i64 = 30_000;

pub const TrashOutcome = enum {
	/// <icd>/apply/trash does not exist: nothing to do.
	absent,
	/// Every entry was removed (or the trash was already empty).
	emptied,
	/// The budget ran out first; what is left waits for the next emptier.
	deadline,
	/// Something could not be removed (or the trash could not be opened); the
	/// rest was still removed while the budget lasted. `first_error` names it.
	failed,
};

pub const TrashResult = struct {
	outcome: TrashOutcome,
	/// Names unlinked (files, symlinks and directories).
	removed: usize = 0,
	first_error: ?anyerror = null,
};

/// Empty `<icd>/apply/trash/` (keeping the directory itself), giving up once
/// `budget_ms` has elapsed. Best-effort and never fatal: the result says what
/// happened, and the caller only warns. `icd` must be absolute; neither `apply`
/// nor `trash` is followed when it is a symlink, and nothing below the trash is
/// either, so only names under the instance's own trash are ever unlinked.
pub fn emptyTrash(allocator: std.mem.Allocator, io: std.Io, icd: []const u8, budget_ms: i64) TrashResult {
	if (!std.fs.path.isAbsolute(icd)) return .{ .outcome = .failed, .first_error = error.RelativeInstanceDir };
	var icd_dir = std.Io.Dir.cwd().openDir(io, icd, .{}) catch |err| return switch (err) {
		error.FileNotFound => .{ .outcome = .absent },
		else => .{ .outcome = .failed, .first_error = err },
	};
	defer icd_dir.close(io);
	var apply_dir = icd_dir.openDir(io, "apply", .{ .follow_symlinks = false }) catch |err| return switch (err) {
		error.FileNotFound => .{ .outcome = .absent },
		else => .{ .outcome = .failed, .first_error = err },
	};
	defer apply_dir.close(io);
	var trash = apply_dir.openDir(io, "trash", .{ .follow_symlinks = false, .iterate = true }) catch |err| return switch (err) {
		error.FileNotFound => .{ .outcome = .absent },
		else => .{ .outcome = .failed, .first_error = err },
	};
	defer trash.close(io);

	var w: Walk = .{ .io = io, .began = std.Io.Timestamp.now(io, .awake), .budget_ms = budget_ms };
	w.emptyDir(allocator, trash);
	const outcome: TrashOutcome = if (w.hit_deadline) .deadline else if (w.first_error != null) .failed else .emptied;
	return .{ .outcome = outcome, .removed = w.removed, .first_error = w.first_error };
}

/// One bounded walk. Errors on single names are recorded and skipped (so one
/// undeletable entry never keeps the rest of the trash forever); the deadline
/// stops the walk outright.
const Walk = struct {
	io: std.Io,
	began: std.Io.Timestamp,
	budget_ms: i64,
	removed: usize = 0,
	first_error: ?anyerror = null,
	hit_deadline: bool = false,

	/// Directory nesting the walk keeps open at once (one fd each). A deeper
	/// subtree is handed to std's deleteTree, which needs no fd per level.
	const max_depth = 128;
	/// Rescans of one directory after a pass that removed something, so a
	/// readdir that skipped an entry while its siblings were unlinked cannot
	/// leave it behind.
	const max_passes = 3;

	const Frame = struct {
		dir: std.Io.Dir,
		iter: std.Io.Dir.Iterator,
		/// The directory's name in its parent; null for the trash root, which is
		/// kept. Owned.
		name: ?[]u8,
		failed: bool = false,
		pass_removed: usize = 0,
		passes: u8 = 1,
	};

	fn expired(w: *Walk) bool {
		if (w.hit_deadline) return true;
		if (w.began.durationTo(std.Io.Timestamp.now(w.io, .awake)).toMilliseconds() >= w.budget_ms) w.hit_deadline = true;
		return w.hit_deadline;
	}

	fn note(w: *Walk, err: anyerror) void {
		if (w.first_error == null) w.first_error = err;
	}

	fn emptyDir(w: *Walk, allocator: std.mem.Allocator, root: std.Io.Dir) void {
		const io = w.io;
		var stack: std.ArrayList(Frame) = .empty;
		defer {
			// Only reached with frames left on the deadline or an allocation
			// failure; the root is the caller's.
			for (stack.items) |*f| if (f.name) |n| {
				f.dir.close(io);
				allocator.free(n);
			};
			stack.deinit(allocator);
		}
		stack.append(allocator, .{ .dir = root, .iter = root.iterate(), .name = null }) catch |err| return w.note(err);

		while (stack.items.len > 0) {
			const top = &stack.items[stack.items.len - 1];
			const next = top.iter.next(io) catch |err| {
				w.note(err);
				top.failed = true;
				w.finishFrame(allocator, &stack);
				continue;
			};
			if (next) |entry| {
				if (w.expired()) return;
				if (entry.kind == .directory) {
					w.enter(allocator, &stack, entry.name);
					continue;
				}
				// Files, symlinks (never followed: unlink removes the link) and
				// anything of unknown kind, which is retried as a directory.
				top.dir.deleteFile(io, entry.name) catch |err| switch (err) {
					error.FileNotFound => continue,
					error.IsDir => {
						w.enter(allocator, &stack, entry.name);
						continue;
					},
					else => {
						w.note(err);
						top.failed = true;
						continue;
					},
				};
				w.removed += 1;
				top.pass_removed += 1;
				continue;
			}
			// The directory is exhausted. Rescan it once something was removed in
			// this pass, then remove it (unless it is the root).
			if (!top.failed and top.pass_removed > 0 and top.passes < max_passes) {
				top.iter = top.dir.iterate();
				top.passes += 1;
				top.pass_removed = 0;
				continue;
			}
			if (w.expired()) return;
			w.finishFrame(allocator, &stack);
		}
	}

	/// Push `name` (a directory in the top frame) onto the stack, or, past
	/// max_depth, delete it with std's deleteTree.
	fn enter(w: *Walk, allocator: std.mem.Allocator, stack: *std.ArrayList(Frame), name: []const u8) void {
		const io = w.io;
		const top = &stack.items[stack.items.len - 1];
		if (stack.items.len >= max_depth) {
			top.dir.deleteTree(io, name) catch |err| {
				w.note(err);
				top.failed = true;
				return;
			};
			w.removed += 1;
			top.pass_removed += 1;
			return;
		}
		const sub = top.dir.openDir(io, name, .{ .follow_symlinks = false, .iterate = true }) catch |err| switch (err) {
			error.FileNotFound => return,
			// Not a directory after all (a symlink to one, or it was replaced):
			// unlink the name itself.
			error.NotDir, error.SymLinkLoop => {
				top.dir.deleteFile(io, name) catch |e| switch (e) {
					error.FileNotFound => return,
					else => {
						w.note(e);
						top.failed = true;
						return;
					},
				};
				w.removed += 1;
				top.pass_removed += 1;
				return;
			},
			else => {
				w.note(err);
				top.failed = true;
				return;
			},
		};
		const owned = allocator.dupe(u8, name) catch |err| {
			sub.close(io);
			w.note(err);
			top.failed = true;
			return;
		};
		stack.append(allocator, .{ .dir = sub, .iter = sub.iterate(), .name = owned }) catch |err| {
			allocator.free(owned);
			sub.close(io);
			w.note(err);
			top.failed = true;
		};
	}

	/// Pop the top frame; remove its directory from the parent unless it is the
	/// root or something under it could not be removed.
	fn finishFrame(w: *Walk, allocator: std.mem.Allocator, stack: *std.ArrayList(Frame)) void {
		const io = w.io;
		const f = stack.pop().?;
		const name = f.name orelse return; // the root: kept
		defer allocator.free(name);
		f.dir.close(io);
		const parent = &stack.items[stack.items.len - 1];
		if (f.failed) {
			parent.failed = true;
			return;
		}
		parent.dir.deleteDir(io, name) catch |err| switch (err) {
			error.FileNotFound => return,
			else => {
				w.note(err);
				parent.failed = true;
				return;
			},
		};
		w.removed += 1;
		parent.pass_removed += 1;
	}
};

// --- tests ---------------------------------------------------------------------

const t = std.testing;

// The format the launcher's bash must reproduce byte for byte:
//   { printf 'A'; printf '\0'; printf 'B'; } | sha256sum
// (flake.nix "A", flake.lock "B"), the lockless composition's value
// (flake.nix "A", no flake.lock: `printf 'A\0' | sha256sum`), and the empty
// composition's value. tests/test_launch_flags.sh pins the first two against
// the launcher's own comp_of_dir.
test "compOfBytes: sha256(flake.nix || NUL || flake.lock) as lowercase hex" {
	try t.expectEqualStrings("76fe3925c7167317f2df68454339f5ec3650e4062178b4f2be219b105a507907", &compOfBytes("A", "B"));
	try t.expectEqualStrings("e61c21ca716b3b1aefb7d1198f83679c4ca4d596e5792275dd6203b49216237d", &compOfBytes("A", ""));
	try t.expectEqualStrings("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", &compOfBytes("", ""));
	// The separator keeps the boundary: moving a byte across it changes comp.
	try t.expect(!std.mem.eql(u8, &compOfBytes("AB", ""), &compOfBytes("A", "B")));
}

fn testIo() std.Io.Threaded {
	return .init(t.allocator, .{});
}

/// A fresh absolute scratch dir under the cwd; the caller deletes it.
fn scratchDir(io: std.Io, tag: []const u8) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	const rel = try std.fmt.allocPrint(t.allocator, "zig-snapshot-test-{s}-{x}", .{ tag, &rnd });
	defer t.allocator.free(rel);
	try std.Io.Dir.cwd().createDirPath(io, rel);
	const abs = try std.Io.Dir.cwd().realPathFileAlloc(io, rel, t.allocator);
	defer t.allocator.free(abs);
	return t.allocator.dupe(u8, abs);
}

fn writeFile(io: std.Io, path: []const u8, bytes: []const u8) !void {
	const f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
	defer f.close(io);
	var buf: [256]u8 = undefined;
	var w = f.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn readFile(io: std.Io, path: []const u8) ![]u8 {
	return std.Io.Dir.cwd().readFileAlloc(io, path, t.allocator, .limited(1 << 20));
}

fn exists(io: std.Io, path: []const u8) bool {
	std.Io.Dir.cwd().access(io, path, .{}) catch return false;
	return true;
}

test "compOfDir: hashes the files' bytes; a missing flake.lock hashes as empty" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	const root = try scratchDir(io, "comp");
	defer t.allocator.free(root);
	defer std.Io.Dir.cwd().deleteTree(io, root) catch {};

	const nix_path = try std.fmt.allocPrint(t.allocator, "{s}/flake.nix", .{root});
	defer t.allocator.free(nix_path);
	const lock_path = try std.fmt.allocPrint(t.allocator, "{s}/flake.lock", .{root});
	defer t.allocator.free(lock_path);

	// No flake.nix: no comp.
	try t.expect(compOfDir(io, root) == null);
	try writeFile(io, nix_path, "{ outputs = _: {}; }\n");
	// No flake.lock: the comp of an empty lock, which the launcher computes too.
	try t.expectEqualStrings(&compOfBytes("{ outputs = _: {}; }\n", ""), &compOfDir(io, root).?);
	try writeFile(io, nix_path, "A");
	try t.expectEqualStrings("e61c21ca716b3b1aefb7d1198f83679c4ca4d596e5792275dd6203b49216237d", &compOfDir(io, root).?);
	try writeFile(io, nix_path, "{ outputs = _: {}; }\n");
	// A flake.lock that exists but cannot be read is not "missing": no comp.
	try std.Io.Dir.cwd().createDirPath(io, lock_path);
	try t.expect(compOfDir(io, root) == null);
	try std.Io.Dir.cwd().deleteDir(io, lock_path);
	try writeFile(io, lock_path, "{\"version\":7}\n");
	try t.expectEqualStrings(&compOfBytes("{ outputs = _: {}; }\n", "{\"version\":7}\n"), &compOfDir(io, root).?);

	// Larger than one read chunk still hashes the whole file.
	const big = try t.allocator.alloc(u8, 3 * 8192 + 17);
	defer t.allocator.free(big);
	for (big, 0..) |*b, i| b.* = @intCast(i % 251);
	try writeFile(io, lock_path, big);
	try t.expectEqualStrings(&compOfBytes("{ outputs = _: {}; }\n", big), &compOfDir(io, root).?);
}

/// <root>/icd/apply/trash with: a nested tree, a file hard-linked from
/// <root>/icd/plugin-sources, and a symlink pointing at a file outside the trash.
const TrashFixture = struct {
	root: []u8,
	icd: []u8,
	trash: []u8,
	live_src: []u8,
	outside: []u8,

	fn init(io: std.Io) !TrashFixture {
		const a = t.allocator;
		const root = try scratchDir(io, "trash");
		errdefer a.free(root);
		const icd = try std.fmt.allocPrint(a, "{s}/icd", .{root});
		const trash = try std.fmt.allocPrint(a, "{s}/apply/trash", .{icd});
		const live_src = try std.fmt.allocPrint(a, "{s}/plugin-sources/p/default.nix", .{icd});
		const outside = try std.fmt.allocPrint(a, "{s}/outside.txt", .{root});
		const cwd = std.Io.Dir.cwd();

		const deep = try std.fmt.allocPrint(a, "{s}/s1/src/p/sub/deeper", .{trash});
		defer a.free(deep);
		try cwd.createDirPath(io, deep);
		const live_dir = try std.fmt.allocPrint(a, "{s}/plugin-sources/p", .{icd});
		defer a.free(live_dir);
		try cwd.createDirPath(io, live_dir);
		const comp_dir = try std.fmt.allocPrint(a, "{s}/s2/composition", .{trash});
		defer a.free(comp_dir);
		try cwd.createDirPath(io, comp_dir);

		try writeFile(io, live_src, "live plugin source\n");
		try writeFile(io, outside, "outside the trash\n");
		inline for (.{ "s1/src/p/sub/deeper/a.txt", "s1/src/p/sub/b.txt", "s1/meta.json", "s2/composition/flake.nix", "loose-file" }) |rel| {
			const p = try std.fmt.allocPrint(a, "{s}/" ++ rel, .{trash});
			defer a.free(p);
			try writeFile(io, p, rel);
		}
		// The cp -al shape: the trash's copy shares the live file's inode.
		const linked = try std.fmt.allocPrint(a, "{s}/s1/src/p/default.nix", .{trash});
		defer a.free(linked);
		try cwd.hardLink(live_src, cwd, linked, io, .{});
		// A symlink in the trash to a file outside it, and one to a directory.
		const sl = try std.fmt.allocPrint(a, "{s}/s1/link-out", .{trash});
		defer a.free(sl);
		try cwd.symLink(io, outside, sl, .{});
		const sld = try std.fmt.allocPrint(a, "{s}/s2/link-dir", .{trash});
		defer a.free(sld);
		try cwd.symLink(io, live_dir, sld, .{ .is_directory = true });
		return .{ .root = root, .icd = icd, .trash = trash, .live_src = live_src, .outside = outside };
	}

	fn deinit(f: *TrashFixture, io: std.Io) void {
		std.Io.Dir.cwd().deleteTree(io, f.root) catch {};
		const a = t.allocator;
		a.free(f.root);
		a.free(f.icd);
		a.free(f.trash);
		a.free(f.live_src);
		a.free(f.outside);
	}

	fn trashEntries(f: *const TrashFixture, io: std.Io) !usize {
		var d = try std.Io.Dir.cwd().openDir(io, f.trash, .{ .iterate = true });
		defer d.close(io);
		var it = d.iterate();
		var n: usize = 0;
		while (try it.next(io)) |_| n += 1;
		return n;
	}
};

test "emptyTrash: removes every tree, keeps the trash dir, never follows a link" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	var fx = try TrashFixture.init(io);
	defer fx.deinit(io);

	const r = emptyTrash(t.allocator, io, fx.icd, trash_budget_ms);
	try t.expectEqual(TrashOutcome.emptied, r.outcome);
	try t.expect(r.first_error == null);
	try t.expect(r.removed > 0);
	try t.expect(exists(io, fx.trash));
	try t.expectEqual(@as(usize, 0), try fx.trashEntries(io));

	// The hard-linked live source and the symlinks' targets are untouched.
	const live = try readFile(io, fx.live_src);
	defer t.allocator.free(live);
	try t.expectEqualStrings("live plugin source\n", live);
	const out = try readFile(io, fx.outside);
	defer t.allocator.free(out);
	try t.expectEqualStrings("outside the trash\n", out);

	// A second run over the empty trash is a no-op that still reports emptied.
	const again = emptyTrash(t.allocator, io, fx.icd, trash_budget_ms);
	try t.expectEqual(TrashOutcome.emptied, again.outcome);
	try t.expectEqual(@as(usize, 0), again.removed);
}

test "emptyTrash: an exhausted budget removes nothing and reports the deadline" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	var fx = try TrashFixture.init(io);
	defer fx.deinit(io);

	const before = try fx.trashEntries(io);
	const r = emptyTrash(t.allocator, io, fx.icd, 0);
	try t.expectEqual(TrashOutcome.deadline, r.outcome);
	try t.expectEqual(@as(usize, 0), r.removed);
	try t.expectEqual(before, try fx.trashEntries(io));

	// The next emptier with a budget finishes the job.
	try t.expectEqual(TrashOutcome.emptied, emptyTrash(t.allocator, io, fx.icd, trash_budget_ms).outcome);
	try t.expectEqual(@as(usize, 0), try fx.trashEntries(io));
}

test "emptyTrash: absent pieces are a no-op; a symlinked trash or a relative icd is never walked" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	const a = t.allocator;
	const cwd = std.Io.Dir.cwd();
	const root = try scratchDir(io, "trash-edge");
	defer a.free(root);
	defer cwd.deleteTree(io, root) catch {};

	const icd = try std.fmt.allocPrint(a, "{s}/icd", .{root});
	defer a.free(icd);
	try t.expectEqual(TrashOutcome.absent, emptyTrash(a, io, icd, trash_budget_ms).outcome);
	try cwd.createDirPath(io, icd);
	try t.expectEqual(TrashOutcome.absent, emptyTrash(a, io, icd, trash_budget_ms).outcome);
	const apply = try std.fmt.allocPrint(a, "{s}/apply", .{icd});
	defer a.free(apply);
	try cwd.createDirPath(io, apply);
	try t.expectEqual(TrashOutcome.absent, emptyTrash(a, io, icd, trash_budget_ms).outcome);

	// apply/trash -> a directory elsewhere: refused, and its contents survive.
	const elsewhere = try std.fmt.allocPrint(a, "{s}/elsewhere", .{root});
	defer a.free(elsewhere);
	try cwd.createDirPath(io, elsewhere);
	const victim = try std.fmt.allocPrint(a, "{s}/keep.txt", .{elsewhere});
	defer a.free(victim);
	try writeFile(io, victim, "keep\n");
	const trash = try std.fmt.allocPrint(a, "{s}/trash", .{apply});
	defer a.free(trash);
	try cwd.symLink(io, elsewhere, trash, .{ .is_directory = true });
	const r = emptyTrash(a, io, icd, trash_budget_ms);
	try t.expectEqual(TrashOutcome.failed, r.outcome);
	try t.expect(exists(io, victim));

	// A relative icd is refused outright.
	try t.expectEqual(TrashOutcome.failed, emptyTrash(a, io, "relative/icd", trash_budget_ms).outcome);
}

test "emptyTrash: an undeletable entry is skipped, the rest is still removed" {
	if (std.c.geteuid() == 0) return error.SkipZigTest; // root ignores the mode
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	const a = t.allocator;
	const cwd = std.Io.Dir.cwd();
	var fx = try TrashFixture.init(io);
	defer {
		// Restore write access so the fixture teardown can remove it.
		if (std.fmt.allocPrint(a, "{s}/locked", .{fx.trash})) |locked| {
			defer a.free(locked);
			cwd.setFilePermissions(io, locked, .fromMode(0o755), .{}) catch {};
		} else |_| {}
		fx.deinit(io);
	}

	const locked = try std.fmt.allocPrint(a, "{s}/locked", .{fx.trash});
	defer a.free(locked);
	try cwd.createDirPath(io, locked);
	const stuck = try std.fmt.allocPrint(a, "{s}/stuck.txt", .{locked});
	defer a.free(stuck);
	try writeFile(io, stuck, "stuck\n");
	try cwd.setFilePermissions(io, locked, .fromMode(0o555), .{});

	const r = emptyTrash(a, io, fx.icd, trash_budget_ms);
	try t.expectEqual(TrashOutcome.failed, r.outcome);
	try t.expect(r.first_error != null);
	// Only the locked tree is left.
	try t.expectEqual(@as(usize, 1), try fx.trashEntries(io));
	try t.expect(exists(io, stuck));
}
