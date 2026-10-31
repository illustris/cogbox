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
//
// Phase 1 adds what the apply verb and the rollback (rollback.zig) need on top:
// taking a snapshot (S, at apply preflight), reading one back, comparing two
// (the rollback scope, and the composition consistency check), the base/built
// role flips, recording a runner in meta.json, and the snapshot GC in Zig with
// the launcher's keep rules (cogbox-launch.sh apply_snapshot_gc).

const std = @import("std");
const builtin = @import("builtin");

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
	return emptyTrashUntil(allocator, io, icd, budget_ms, null);
}

/// emptyTrash that also gives up once `stop` answers true (checked between
/// names, like the deadline): the apply verb's build-phase emptier, which its
/// supersede and terminate flags end. A stop reads as `.deadline`.
pub fn emptyTrashUntil(allocator: std.mem.Allocator, io: std.Io, icd: []const u8, budget_ms: i64, stop: ?*const fn () bool) TrashResult {
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

	var w: Walk = .{ .io = io, .began = std.Io.Timestamp.now(io, .awake), .budget_ms = budget_ms, .stop = stop };
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
	stop: ?*const fn () bool = null,
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
		if (w.stop) |f| if (f()) {
			w.hit_deadline = true;
		};
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

/// Remove the tree `name` in `parent` (never following a symlink), giving up
/// once `budget_ms` has elapsed: the trash emptier's bounded walk applied to one
/// tree, for a cleanup that cannot rename into the trash (a fail-closed
/// rollback removing a plugin source on a disk too full for apply/trash/).
pub fn removeTree(allocator: std.mem.Allocator, io: std.Io, parent: std.Io.Dir, name: []const u8, budget_ms: i64) TrashResult {
	var sub = parent.openDir(io, name, .{ .follow_symlinks = false, .iterate = true }) catch |err| switch (err) {
		error.FileNotFound => return .{ .outcome = .absent },
		error.NotDir, error.SymLinkLoop => {
			parent.deleteFile(io, name) catch |e| return .{ .outcome = .failed, .first_error = e };
			return .{ .outcome = .emptied, .removed = 1 };
		},
		else => return .{ .outcome = .failed, .first_error = err },
	};
	var w: Walk = .{ .io = io, .began = std.Io.Timestamp.now(io, .awake), .budget_ms = budget_ms };
	w.emptyDir(allocator, sub);
	sub.close(io);
	if (w.hit_deadline) return .{ .outcome = .deadline, .removed = w.removed };
	if (w.first_error) |e| return .{ .outcome = .failed, .removed = w.removed, .first_error = e };
	parent.deleteDir(io, name) catch |err| return .{ .outcome = .failed, .removed = w.removed, .first_error = err };
	return .{ .outcome = .emptied, .removed = w.removed + 1 };
}

// --- snapshots -----------------------------------------------------------------
//
// <icd>/apply/snap/<id>/, the shape the launcher's boot snapshot also writes:
//   composition/{flake.nix,flake.lock}  BYTE copies of plugins-flake/ (absent with
//                                       no plugins; a lockless composition has
//                                       no flake.lock)
//   state.json                          the plugin entries in order, and per
//                                       plugin its tagged L4, L7 and inject entries
//   src/                                a hard-link copy (`cp -al`) of
//                                       plugin-sources/, the only linked part
//   meta.json                           {id, comp, runner, key}, written LAST: the
//                                       completeness marker
// The roles apply/base and apply/built are symlinks to snap/<id>, flipped by an
// atomic rename. Every file is written as a NEW file (tmp + fsync + rename),
// never in place, so no inode a snapshot shares is ever rewritten. Everything
// here runs under the instance config lock.

pub const id_len = 16;
/// A snapshot id (also the shape of a live-apply generation G): 16 lowercase
/// hex digits.
pub const Id = [id_len]u8;

fn isLowerHex(s: []const u8) bool {
	for (s) |c| switch (c) {
		'0'...'9', 'a'...'f' => {},
		else => return false,
	};
	return true;
}

pub fn isId(s: []const u8) bool {
	return s.len == id_len and isLowerHex(s);
}

/// A snapshot's comp: `none` (no composition), or 64 lowercase hex digits.
pub fn isComp(s: []const u8) bool {
	return std.mem.eql(u8, s, "none") or (s.len == comp_hex_len and isLowerHex(s));
}

pub fn newId(io: std.Io) Id {
	var raw: [id_len / 2]u8 = undefined;
	io.random(&raw);
	return std.fmt.bytesToHex(raw, .lower);
}

/// The bound of one rollback-side or apply-side operation, measured on the
/// monotonic clock.
pub const Deadline = struct {
	io: std.Io,
	began: std.Io.Timestamp,
	budget_ms: i64,

	pub fn init(io: std.Io, budget_ms: i64) Deadline {
		return .{ .io = io, .began = std.Io.Timestamp.now(io, .awake), .budget_ms = budget_ms };
	}

	pub fn leftMs(d: *const Deadline) i64 {
		return d.budget_ms - d.began.durationTo(std.Io.Timestamp.now(d.io, .awake)).toMilliseconds();
	}

	pub fn check(d: *const Deadline) error{Timeout}!void {
		if (d.leftMs() <= 0) return error.Timeout;
	}
};

/// Hand a name this process just created to `owner` when it runs as root
/// (cogbox under sudo), like the launcher's apply_own and config_lock's lock
/// files. Best-effort: a failed chown leaves the name root-owned, as before.
/// Never follows a symlink.
pub fn own(io: std.Io, dir: std.Io.Dir, name: []const u8, owner: ?u32) void {
	_ = io;
	const uid = owner orelse return;
	if (uid == 0 or std.c.geteuid() != 0) return;
	chownNoFollow(dir, name, uid, null) catch {};
}

/// fchownat(AT_SYMLINK_NOFOLLOW) through libc (std.Io.Dir.setFileOwner does
/// not compile in this std); a null gid is left unchanged.
fn chownNoFollow(dir: std.Io.Dir, name: []const u8, uid: u32, gid: ?u32) !void {
	var name_buf: [std.fs.max_name_bytes + 1]u8 = undefined;
	const z = try zName(&name_buf, name);
	const g: std.c.gid_t = if (gid) |x| @intCast(x) else @bitCast(@as(i32, -1));
	if (std.c.fchownat(dir.handle, z, @intCast(uid), g, std.c.AT.SYMLINK_NOFOLLOW) != 0) return error.ChownFailed;
}

fn zName(buf: *[std.fs.max_name_bytes + 1]u8, name: []const u8) ![:0]const u8 {
	if (name.len > std.fs.max_name_bytes) return error.NameTooLong;
	@memcpy(buf[0..name.len], name);
	buf[name.len] = 0;
	return buf[0..name.len :0];
}

/// mkdir `name` in `parent` unless it exists (handed to `owner` when new). An
/// existing name that is not a real directory (a symlink included) is refused,
/// so under sudo nothing is ever written through a planted link.
pub fn ensureDir(io: std.Io, parent: std.Io.Dir, name: []const u8, owner: ?u32) !void {
	parent.createDir(io, name, .default_dir) catch |err| switch (err) {
		error.PathAlreadyExists => {
			const st = try parent.statFile(io, name, .{ .follow_symlinks = false });
			if (st.kind != .directory) return error.NotDir;
			return;
		},
		else => return err,
	};
	own(io, parent, name, owner);
}

/// Write `bytes` as a NEW file `name` in `dir`: a unique tmp name beside it
/// (`.<name>.tmp.<nonce>`), fsync, rename over `name`. The tmp name is removed
/// on failure. Never an in-place write.
pub fn writeNew(io: std.Io, dir: std.Io.Dir, name: []const u8, bytes: []const u8, owner: ?u32) !void {
	var nonce: [8]u8 = undefined;
	io.random(&nonce);
	var tmp_buf: [std.fs.max_name_bytes]u8 = undefined;
	const tmp = try std.fmt.bufPrint(&tmp_buf, ".{s}.tmp.{x}", .{ name, &nonce });
	writeTmp(io, dir, tmp, bytes) catch |err| {
		dir.deleteFile(io, tmp) catch {};
		return err;
	};
	own(io, dir, tmp, owner);
	dir.rename(tmp, dir, name, io) catch |err| {
		dir.deleteFile(io, tmp) catch {};
		return err;
	};
}

fn writeTmp(io: std.Io, dir: std.Io.Dir, tmp: []const u8, bytes: []const u8) !void {
	const f = try dir.createFile(io, tmp, .{ .exclusive = true });
	defer f.close(io);
	var wbuf: [4096]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll(bytes);
	try w.flush();
	try f.sync(io);
}

/// Read `name` in `dir` (at most `limit` bytes) without following a symlink in
/// its last component: under sudo a planted link must not make root read, and
/// then restore into config.json, a file the user cannot.
pub fn readNoFollow(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, name: []const u8, limit: usize) ![]u8 {
	const f = try dir.openFile(io, name, .{ .follow_symlinks = false });
	defer f.close(io);
	var buf: [4096]u8 = undefined;
	var r = f.reader(io, &buf);
	return r.interface.allocRemaining(allocator, .limited(limit));
}

pub fn openIcd(io: std.Io, icd: []const u8) !std.Io.Dir {
	if (!std.fs.path.isAbsolute(icd)) return error.RelativeInstanceDir;
	return std.Io.Dir.cwd().openDir(io, icd, .{});
}

/// Caps on the snapshot files read back (a composition, state.json, meta.json).
pub const max_flake_bytes: usize = 16 << 20;
pub const max_state_bytes: usize = 16 << 20;
const max_meta_bytes: usize = 64 << 10;

// --- hard-link copy ------------------------------------------------------------

/// Directory nesting a link copy follows (one pair of open fds per level).
const max_link_depth = 256;

/// `cp -al`, natively: create the NEW directory `dst_name` in `dst_parent` and
/// fill it with hard links to every regular file under `src_name` in
/// `src_parent`, recreating its directories (their mode, and as root their
/// owner, kept as `cp -a` keeps them) and symlinks (copied, never followed).
/// Anything else (a device, a fifo, a socket) fails the copy, as does crossing
/// `deadline`, a cross-device link, EMLINK or ENOSPC. No child process: a
/// rollback spawns none, and the live apply forks every child itself with a
/// death signal. A failed copy leaves its partial tree for the caller.
pub fn linkTree(io: std.Io, src_parent: std.Io.Dir, src_name: []const u8, dst_parent: std.Io.Dir, dst_name: []const u8, deadline: *const Deadline) anyerror!void {
	var src = try src_parent.openDir(io, src_name, .{ .follow_symlinks = false, .iterate = true });
	defer src.close(io);
	const st = try dirAttrs(io, src_parent, src_name);
	// Owner-writable while it is filled; finishDir applies the source's mode.
	try dst_parent.createDir(io, dst_name, .fromMode(0o700));
	{
		var dst = try dst_parent.openDir(io, dst_name, .{ .follow_symlinks = false });
		defer dst.close(io);
		try linkContents(io, src, dst, deadline, 1);
	}
	try finishDir(io, dst_parent, dst_name, st);
}

fn linkContents(io: std.Io, src: std.Io.Dir, dst: std.Io.Dir, deadline: *const Deadline, depth: usize) anyerror!void {
	if (depth > max_link_depth) return error.TreeTooDeep;
	var it = src.iterate();
	while (try it.next(io)) |entry| {
		try deadline.check();
		var kind = entry.kind;
		if (kind == .unknown) kind = (try src.statFile(io, entry.name, .{ .follow_symlinks = false })).kind;
		switch (kind) {
			.file => try src.hardLink(entry.name, dst, entry.name, io, .{}),
			.sym_link => {
				var target: [std.fs.max_path_bytes]u8 = undefined;
				const n = try src.readLink(io, entry.name, &target);
				try dst.symLink(io, target[0..n], entry.name, .{});
				if (std.c.geteuid() == 0) {
					if (try ownerOf(src, entry.name)) |o| try chownNoFollow(dst, entry.name, o.uid, o.gid);
				}
			},
			.directory => {
				const st = try dirAttrs(io, src, entry.name);
				var sub_src = try src.openDir(io, entry.name, .{ .follow_symlinks = false, .iterate = true });
				defer sub_src.close(io);
				try dst.createDir(io, entry.name, .fromMode(0o700));
				{
					var sub_dst = try dst.openDir(io, entry.name, .{ .follow_symlinks = false });
					defer sub_dst.close(io);
					try linkContents(io, sub_src, sub_dst, deadline, depth + 1);
				}
				try finishDir(io, dst, entry.name, st);
			},
			else => return error.UnsupportedFileType,
		}
	}
}

const Owner = struct { uid: u32, gid: u32 };

/// The owner of `name` in `dir` (not following a symlink), which std.Io's Stat
/// does not carry; read only as root, to keep it as `cp -a` does. Null where
/// statx is unavailable (non-Linux), and the copy then keeps root's.
fn ownerOf(dir: std.Io.Dir, name: []const u8) !?Owner {
	if (comptime builtin.os.tag == .linux) {
		const linux = std.os.linux;
		var name_buf: [std.fs.max_name_bytes + 1]u8 = undefined;
		const z = try zName(&name_buf, name);
		var stx: linux.Statx = undefined;
		const rc = linux.statx(dir.handle, z, linux.AT.SYMLINK_NOFOLLOW, .{ .UID = true, .GID = true }, &stx);
		if (linux.errno(rc) != .SUCCESS) return error.StatFailed;
		return .{ .uid = stx.uid, .gid = stx.gid };
	}
	return null;
}

const DirAttrs = struct { mode: std.posix.mode_t, owner: ?Owner };

fn dirAttrs(io: std.Io, dir: std.Io.Dir, name: []const u8) !DirAttrs {
	const st = try dir.statFile(io, name, .{ .follow_symlinks = false });
	return .{
		.mode = st.permissions.toMode() & 0o7777,
		.owner = if (std.c.geteuid() == 0) try ownerOf(dir, name) else null,
	};
}

fn finishDir(io: std.Io, parent: std.Io.Dir, name: []const u8, attrs: DirAttrs) !void {
	try parent.setFilePermissions(io, name, .fromMode(attrs.mode), .{});
	if (attrs.owner) |o| try chownNoFollow(parent, name, o.uid, o.gid);
}

// --- state.json ----------------------------------------------------------------

fn objectGet(v: ?std.json.Value, key: []const u8) ?std.json.Value {
	const x = v orelse return null;
	if (x != .object) return null;
	return x.object.get(key);
}

fn arrayItems(v: ?std.json.Value) []const std.json.Value {
	const x = v orelse return &.{};
	if (x != .array) return &.{};
	return x.array.items;
}

fn stringOf(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
	const v = obj.get(key) orelse return null;
	if (v != .string) return null;
	return v.string;
}

/// state.json of a config.json tree: the extract the launcher's
/// APPLY_STATE_FILTER (jq) writes, `{plugins: [entries in order], tagged:
/// {<name>: {l4: [...], l7: [...], inject: [...]}}}`, where a plugin's tagged
/// entries are the objects carrying `"plugin": <name>` in .network.rules,
/// .network.l7.rules and .network.l7.inject.specs, in their order there. A
/// missing or ill-typed piece reads as empty (a string .network, i.e. not rules
/// mode, has no tagged policy). Caller frees.
pub fn stateJson(allocator: std.mem.Allocator, root: std.json.Value) ![]u8 {
	const plugins = arrayItems(objectGet(root, "plugins"));
	const net = objectGet(root, "network");
	const l7 = objectGet(net, "l7");
	const lists = [_]struct { key: []const u8, items: []const std.json.Value }{
		.{ .key = "l4", .items = arrayItems(objectGet(net, "rules")) },
		.{ .key = "l7", .items = arrayItems(objectGet(l7, "rules")) },
		.{ .key = "inject", .items = arrayItems(objectGet(objectGet(l7, "inject"), "specs")) },
	};
	var seen: std.StringHashMapUnmanaged(void) = .empty;
	defer seen.deinit(allocator);
	var aw: std.Io.Writer.Allocating = .init(allocator);
	defer aw.deinit();
	var s: std.json.Stringify = .{ .writer = &aw.writer };
	writeState(allocator, &s, plugins, &lists, &seen) catch |err| switch (err) {
		error.WriteFailed => return error.OutOfMemory,
		else => |e| return e,
	};
	aw.writer.writeByte('\n') catch return error.OutOfMemory;
	return aw.toOwnedSlice();
}

fn writeState(
	allocator: std.mem.Allocator,
	s: *std.json.Stringify,
	plugins: []const std.json.Value,
	lists: anytype,
	seen: *std.StringHashMapUnmanaged(void),
) !void {
	try s.beginObject();
	try s.objectField("plugins");
	try s.beginArray();
	for (plugins) |p| try s.write(p);
	try s.endArray();
	try s.objectField("tagged");
	try s.beginObject();
	for (plugins) |p| {
		if (p != .object) continue;
		const n = stringOf(p.object, "name") orelse continue;
		if (seen.contains(n)) continue;
		try seen.put(allocator, n, {});
		try s.objectField(n);
		try s.beginObject();
		for (lists) |l| {
			try s.objectField(l.key);
			try s.beginArray();
			for (l.items) |item| {
				if (item != .object) continue;
				const tag = stringOf(item.object, "plugin") orelse continue;
				if (std.mem.eql(u8, tag, n)) try s.write(item);
			}
			try s.endArray();
		}
		try s.endObject();
	}
	try s.endObject();
	try s.endObject();
}

/// meta.json: `{"id","comp","runner","key"}` (null runner and key until one is
/// recorded), as the launcher's take writes it.
pub const Meta = struct {
	id: []const u8,
	comp: []const u8,
	runner: ?[]const u8 = null,
	key: ?[]const u8 = null,
};

fn metaJson(allocator: std.mem.Allocator, meta: Meta) ![]u8 {
	var aw: std.Io.Writer.Allocating = .init(allocator);
	defer aw.deinit();
	std.json.Stringify.value(meta, .{}, &aw.writer) catch return error.OutOfMemory;
	aw.writer.writeByte('\n') catch return error.OutOfMemory;
	return aw.toOwnedSlice();
}

// --- take ------------------------------------------------------------------------

pub const TakeOptions = struct {
	/// The whole take's bound. The apply's preflight passes what is left of its
	/// snapshot-and-checks allowance; past it the take fails like any other.
	budget_ms: i64 = 20_000,
	/// The invoking user under sudo: new names are handed to it.
	owner: ?u32 = null,
};

/// Take a snapshot of the instance's plugin state at <icd>/apply/snap/<id>/ and
/// return its id: the composition bytes of plugins-flake/ (only when
/// config.json lists a plugin and plugins-flake/flake.nix exists, the
/// launcher's rule), state.json from `config_root` (config.json as the caller
/// loaded it under the config lock), a hard-link copy of plugin-sources/ (an
/// empty src/ when it does not exist yet), then meta.json with comp = that of
/// the copied bytes, or `none`. Runs under the config lock. A take that fails
/// (the bound, ENOSPC, EMLINK, an I/O error, a file in plugin-sources/ that is
/// not a regular file, directory or symlink) returns its error and leaves a
/// partial tree WITHOUT meta.json, which nothing uses and the GC collects (the
/// apply answers failed/snapshot).
pub fn take(allocator: std.mem.Allocator, io: std.Io, icd: []const u8, config_root: std.json.Value, opts: TakeOptions) !Id {
	const deadline = Deadline.init(io, opts.budget_ms);
	var icd_dir = try openIcd(io, icd);
	defer icd_dir.close(io);
	try ensureDir(io, icd_dir, "apply", opts.owner);
	var apply = try icd_dir.openDir(io, "apply", .{ .follow_symlinks = false });
	defer apply.close(io);
	try ensureDir(io, apply, "snap", opts.owner);
	// The trash too, before anything fills the disk (the launcher's order): the
	// GC must still be able to rename a partial tree on a disk the take filled.
	ensureDir(io, apply, "trash", opts.owner) catch {};
	var snap = try apply.openDir(io, "snap", .{ .follow_symlinks = false });
	defer snap.close(io);
	const id = newId(io);
	try snap.createDir(io, &id, .default_dir);
	own(io, snap, &id, opts.owner);
	var dir = try snap.openDir(io, &id, .{ .follow_symlinks = false });
	defer dir.close(io);

	var comp_buf: Comp = undefined;
	var comp: []const u8 = "none";
	if (arrayItems(objectGet(config_root, "plugins")).len > 0) compose: {
		const nix_bytes = readNoFollow(allocator, io, icd_dir, "plugins-flake/flake.nix", max_flake_bytes) catch |err| switch (err) {
			error.FileNotFound => break :compose,
			else => return err,
		};
		defer allocator.free(nix_bytes);
		const lock_bytes: ?[]u8 = readNoFollow(allocator, io, icd_dir, "plugins-flake/flake.lock", max_flake_bytes) catch |err| switch (err) {
			error.FileNotFound => null,
			else => return err,
		};
		defer if (lock_bytes) |b| allocator.free(b);
		try deadline.check();
		try dir.createDir(io, "composition", .default_dir);
		own(io, dir, "composition", opts.owner);
		var cdir = try dir.openDir(io, "composition", .{ .follow_symlinks = false });
		defer cdir.close(io);
		try writeNew(io, cdir, "flake.nix", nix_bytes, opts.owner);
		// A composition without a lock is copied without one; its comp hashes an
		// empty lock, on both sides.
		if (lock_bytes) |b| try writeNew(io, cdir, "flake.lock", b, opts.owner);
		comp_buf = compOfBytes(nix_bytes, lock_bytes orelse "");
		comp = &comp_buf;
	}
	try deadline.check();
	const state = try stateJson(allocator, config_root);
	defer allocator.free(state);
	try writeNew(io, dir, "state.json", state, opts.owner);
	try deadline.check();
	if (icd_dir.statFile(io, "plugin-sources", .{ .follow_symlinks = false })) |_| {
		try linkTree(io, icd_dir, "plugin-sources", dir, "src", &deadline);
	} else |err| switch (err) {
		// No plugin has materialized yet: the first plugin on a fresh instance
		// still gets a base.
		error.FileNotFound => try dir.createDir(io, "src", .default_dir),
		else => return err,
	}
	// Only src/ itself: the copy keeps plugin-sources' owners, as `cp -a` does.
	own(io, dir, "src", opts.owner);
	try deadline.check();
	const meta = try metaJson(allocator, .{ .id = &id, .comp = comp });
	defer allocator.free(meta);
	try writeNew(io, dir, "meta.json", meta, opts.owner);
	return id;
}

// --- read --------------------------------------------------------------------------

/// A plugin's tagged policy as a snapshot recorded it.
pub const Tagged = struct {
	l4: []const std.json.Value = &.{},
	l7: []const std.json.Value = &.{},
	inject: []const std.json.Value = &.{},
};

/// A complete snapshot, read back. Every slice lives in the reader's arena.
pub const Snapshot = struct {
	id: Id,
	meta: Meta,
	/// state.json's plugin entries, in order.
	plugins: []const std.json.Value,
	/// state.json's `tagged` value (an object, or null).
	tagged: ?std.json.Value,
	/// composition/ bytes; null when the snapshot has no composition (comp
	/// `none`), and flake_lock also for a lockless one.
	flake_nix: ?[]const u8,
	flake_lock: ?[]const u8,

	pub fn taggedOf(self: *const Snapshot, name: []const u8) Tagged {
		const v = objectGet(self.tagged, name);
		return .{
			.l4 = arrayItems(objectGet(v, "l4")),
			.l7 = arrayItems(objectGet(v, "l7")),
			.inject = arrayItems(objectGet(v, "inject")),
		};
	}

	/// The first plugin entry named `name`.
	pub fn entry(self: *const Snapshot, name: []const u8) ?std.json.ObjectMap {
		return findEntry(self.plugins, name);
	}
};

fn findEntry(plugins: []const std.json.Value, name: []const u8) ?std.json.ObjectMap {
	for (plugins) |p| {
		if (p != .object) continue;
		const n = stringOf(p.object, "name") orelse continue;
		if (std.mem.eql(u8, n, name)) return p.object;
	}
	return null;
}

/// Read the complete snapshot `id` into `arena`. error.Incomplete when it has no
/// meta.json (a take cut short: never used, whatever names it);
/// error.InvalidSnapshot when a part does not parse, its meta.json names another
/// id, its composition bytes no longer hash to its comp, or it has no src/;
/// FileNotFound when it does not exist.
pub fn read(arena: std.mem.Allocator, io: std.Io, icd: []const u8, id: []const u8) !Snapshot {
	if (!isId(id)) return error.InvalidSnapshot;
	var icd_dir = try openIcd(io, icd);
	defer icd_dir.close(io);
	var path_buf: [32]u8 = undefined;
	const rel = std.fmt.bufPrint(&path_buf, "apply/snap/{s}", .{id}) catch unreachable;
	var dir = try icd_dir.openDir(io, rel, .{ .follow_symlinks = false });
	defer dir.close(io);

	const meta_bytes = readNoFollow(arena, io, dir, "meta.json", max_meta_bytes) catch |err| switch (err) {
		error.FileNotFound => return error.Incomplete,
		else => return err,
	};
	const meta = std.json.parseFromSliceLeaky(Meta, arena, meta_bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidSnapshot;
	if (!std.mem.eql(u8, meta.id, id) or !isComp(meta.comp)) return error.InvalidSnapshot;

	const state_bytes = try readNoFollow(arena, io, dir, "state.json", max_state_bytes);
	const state = std.json.parseFromSliceLeaky(std.json.Value, arena, state_bytes, .{}) catch return error.InvalidSnapshot;
	if (state != .object) return error.InvalidSnapshot;
	const plugins_v = state.object.get("plugins") orelse return error.InvalidSnapshot;
	if (plugins_v != .array) return error.InvalidSnapshot;
	const tagged = state.object.get("tagged");
	if (tagged) |tv| if (tv != .object) return error.InvalidSnapshot;

	const flake_nix: ?[]u8 = readNoFollow(arena, io, dir, "composition/flake.nix", max_flake_bytes) catch |err| switch (err) {
		error.FileNotFound => null,
		else => return err,
	};
	const flake_lock: ?[]u8 = readNoFollow(arena, io, dir, "composition/flake.lock", max_flake_bytes) catch |err| switch (err) {
		error.FileNotFound => null,
		else => return err,
	};
	if (std.mem.eql(u8, meta.comp, "none")) {
		if (flake_nix != null or flake_lock != null) return error.InvalidSnapshot;
	} else {
		const nix_bytes = flake_nix orelse return error.InvalidSnapshot;
		const c = compOfBytes(nix_bytes, flake_lock orelse "");
		if (!std.mem.eql(u8, &c, meta.comp)) return error.InvalidSnapshot;
	}
	const src = dir.statFile(io, "src", .{ .follow_symlinks = false }) catch |err| switch (err) {
		error.FileNotFound => return error.InvalidSnapshot,
		else => return err,
	};
	if (src.kind != .directory) return error.InvalidSnapshot;

	return .{
		.id = id[0..id_len].*,
		.meta = meta,
		.plugins = plugins_v.array.items,
		.tagged = tagged,
		.flake_nix = flake_nix,
		.flake_lock = flake_lock,
	};
}

// --- compare -----------------------------------------------------------------------

/// A plugin's identity: presence plus url, attr, lockedUrl and narHash, each as
/// stored (an absent field equals only an absent one). The preflight's
/// composition consistency check makes it equal to the content its lock entry
/// builds.
pub fn sameIdentity(a: std.json.ObjectMap, b: std.json.ObjectMap) bool {
	for ([_][]const u8{ "url", "attr", "lockedUrl", "narHash" }) |key| {
		const x = stringOf(a, key);
		const y = stringOf(b, key);
		if (x == null or y == null) {
			if (x != null or y != null) return false;
			continue;
		}
		if (!std.mem.eql(u8, x.?, y.?)) return false;
	}
	return true;
}

/// What a rollback does to one name.
pub const Action = enum {
	/// In S, not in the target: a rolled-back add.
	removed,
	/// In both with different identities: a rolled-back update.
	restored,
	/// In the target, not in S: a rolled-back del.
	reinserted,
};

/// One name of a rollback scope. The revs travel with the scope (in
/// inflight.json and the intent), so the rollback record can be written even
/// when a snapshot can no longer be read.
pub const ScopeEntry = struct {
	name: []const u8,
	action: Action,
	/// The version rolled back: S's rev, else its narHash. Null for reinserted.
	from_rev: ?[]const u8 = null,
	/// The version restored: the target's rev, else its narHash. Null for removed.
	to_rev: ?[]const u8 = null,
	/// S's narHash of the version rolled back (the record's repeat count). Null
	/// for reinserted.
	from_nar_hash: ?[]const u8 = null,
};

fn revOf(obj: std.json.ObjectMap) ?[]const u8 {
	return stringOf(obj, "rev") orelse stringOf(obj, "narHash");
}

/// The rollback scope from S's plugin entries `s_plugins` back to a target's
/// `z_plugins`: every name whose identity differs, with its action, S's names
/// first in S's order, then the target's reinserted names in its order. An entry
/// without a string name is skipped, and only a name's first entry counts.
/// Slices alias the inputs; the list is allocated in `arena`.
pub fn scope(arena: std.mem.Allocator, s_plugins: []const std.json.Value, z_plugins: []const std.json.Value) ![]ScopeEntry {
	var out: std.ArrayList(ScopeEntry) = .empty;
	var seen: std.StringHashMapUnmanaged(void) = .empty;
	for (s_plugins) |p| {
		if (p != .object) continue;
		const n = stringOf(p.object, "name") orelse continue;
		if ((try seen.getOrPut(arena, n)).found_existing) continue;
		if (findEntry(z_plugins, n)) |z| {
			if (sameIdentity(p.object, z)) continue;
			try out.append(arena, .{ .name = n, .action = .restored, .from_rev = revOf(p.object), .to_rev = revOf(z), .from_nar_hash = stringOf(p.object, "narHash") });
		} else {
			try out.append(arena, .{ .name = n, .action = .removed, .from_rev = revOf(p.object), .from_nar_hash = stringOf(p.object, "narHash") });
		}
	}
	for (z_plugins) |p| {
		if (p != .object) continue;
		const n = stringOf(p.object, "name") orelse continue;
		if ((try seen.getOrPut(arena, n)).found_existing) continue;
		try out.append(arena, .{ .name = n, .action = .reinserted, .to_rev = revOf(p.object) });
	}
	return out.toOwnedSlice(arena);
}

/// The preflight's composition consistency check on one snapshot: every
/// `p-<name>` root input of its flake.lock whose original type is `path` must
/// lock the narHash its state.json records for that plugin. False when one does
/// not (a failed op re-pin, which only warns, leaves exactly that), when no
/// entry records one, or when the lock does not parse. A snapshot without a lock
/// is consistent: nothing in it is locked.
pub fn compositionConsistent(allocator: std.mem.Allocator, snap: *const Snapshot) bool {
	const lock = snap.flake_lock orelse return true;
	const parsed = std.json.parseFromSlice(std.json.Value, allocator, lock, .{}) catch return false;
	defer parsed.deinit();
	const nodes = objectGet(parsed.value, "nodes") orelse return false;
	if (nodes != .object) return false;
	const inputs = objectGet(objectGet(nodes, "root"), "inputs") orelse return false;
	if (inputs != .object) return false;
	var it = inputs.object.iterator();
	while (it.next()) |e| {
		const input = e.key_ptr.*;
		if (!std.mem.startsWith(u8, input, "p-")) continue;
		// A `follows` input is an array path, not a node.
		if (e.value_ptr.* != .string) continue;
		const node = nodes.object.get(e.value_ptr.string) orelse return false;
		const ty = objectGet(objectGet(node, "original"), "type") orelse continue;
		if (ty != .string or !std.mem.eql(u8, ty.string, "path")) continue;
		const locked = objectGet(objectGet(node, "locked"), "narHash") orelse return false;
		if (locked != .string) return false;
		const entry_obj = findEntry(snap.plugins, input[2..]) orelse return false;
		const recorded = stringOf(entry_obj, "narHash") orelse return false;
		if (!std.mem.eql(u8, recorded, locked.string)) return false;
	}
	return true;
}

// --- roles ---------------------------------------------------------------------------

pub const Role = enum { base, built };

fn parseRoleTarget(target: []const u8) ?Id {
	if (!std.mem.startsWith(u8, target, "snap/")) return null;
	const rest = target["snap/".len..];
	if (!isId(rest)) return null;
	return rest[0..id_len].*;
}

/// The snapshot id `apply/<role>` links to; null when the link is absent,
/// unreadable, or not `snap/<id>`.
pub fn roleId(io: std.Io, icd: []const u8, role: Role) ?Id {
	var icd_dir = openIcd(io, icd) catch return null;
	defer icd_dir.close(io);
	var path_buf: [16]u8 = undefined;
	const rel = std.fmt.bufPrint(&path_buf, "apply/{s}", .{@tagName(role)}) catch return null;
	var buf: [64]u8 = undefined;
	const n = icd_dir.readLink(io, rel, &buf) catch return null;
	return parseRoleTarget(buf[0..n]);
}

/// Point `apply/<role>` at snapshot `id` with an atomic flip: a new symlink
/// renamed over the old one, so no crash leaves a half-moved role. Refuses an
/// incomplete snapshot (error.Incomplete): one is never promoted.
pub fn setRole(io: std.Io, icd: []const u8, role: Role, id: []const u8, owner: ?u32) !void {
	if (!isId(id)) return error.InvalidSnapshot;
	var icd_dir = try openIcd(io, icd);
	defer icd_dir.close(io);
	var apply = try icd_dir.openDir(io, "apply", .{ .follow_symlinks = false });
	defer apply.close(io);
	var meta_buf: [48]u8 = undefined;
	const meta_rel = std.fmt.bufPrint(&meta_buf, "snap/{s}/meta.json", .{id}) catch unreachable;
	const st = apply.statFile(io, meta_rel, .{ .follow_symlinks = false }) catch |err| switch (err) {
		error.FileNotFound => return error.Incomplete,
		else => return err,
	};
	if (st.kind != .file) return error.Incomplete;
	var target_buf: [32]u8 = undefined;
	const target = std.fmt.bufPrint(&target_buf, "snap/{s}", .{id}) catch unreachable;
	var nonce: [8]u8 = undefined;
	io.random(&nonce);
	var tmp_buf: [48]u8 = undefined;
	const tmp = std.fmt.bufPrint(&tmp_buf, ".{s}.tmp.{x}", .{ @tagName(role), &nonce }) catch unreachable;
	try apply.symLink(io, target, tmp, .{ .is_directory = true });
	own(io, apply, tmp, owner);
	apply.rename(tmp, apply, @tagName(role), io) catch |err| {
		apply.deleteFile(io, tmp) catch {};
		return err;
	};
}

/// Unlink `apply/<role>`; an absent role (or instance) is already the target.
pub fn clearRole(io: std.Io, icd: []const u8, role: Role) !void {
	var icd_dir = openIcd(io, icd) catch |err| switch (err) {
		error.FileNotFound => return,
		else => return err,
	};
	defer icd_dir.close(io);
	var apply = icd_dir.openDir(io, "apply", .{ .follow_symlinks = false }) catch |err| switch (err) {
		error.FileNotFound => return,
		else => return err,
	};
	defer apply.close(io);
	apply.deleteFile(io, @tagName(role)) catch |err| switch (err) {
		error.FileNotFound => {},
		else => return err,
	};
}

/// Record `runner` and the key it was built under in snapshot `id`'s meta.json
/// (a new file, tmp + rename), as the launcher's promotion records the booted
/// runner: a confirmed S and a restart_required K remember R, so a later
/// rollback to that snapshot keeps the fast path. error.Incomplete without
/// meta.json.
pub fn recordRunner(allocator: std.mem.Allocator, io: std.Io, icd: []const u8, id: []const u8, runner: []const u8, key: []const u8, owner: ?u32) !void {
	if (!isId(id)) return error.InvalidSnapshot;
	var icd_dir = try openIcd(io, icd);
	defer icd_dir.close(io);
	var path_buf: [32]u8 = undefined;
	const rel = std.fmt.bufPrint(&path_buf, "apply/snap/{s}", .{id}) catch unreachable;
	var dir = try icd_dir.openDir(io, rel, .{ .follow_symlinks = false });
	defer dir.close(io);
	var arena_state = std.heap.ArenaAllocator.init(allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();
	const bytes = readNoFollow(arena, io, dir, "meta.json", max_meta_bytes) catch |err| switch (err) {
		error.FileNotFound => return error.Incomplete,
		else => return err,
	};
	var meta = std.json.parseFromSliceLeaky(Meta, arena, bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidSnapshot;
	if (!std.mem.eql(u8, meta.id, id)) return error.InvalidSnapshot;
	meta.runner = runner;
	meta.key = key;
	try writeNew(io, dir, "meta.json", try metaJson(arena, meta), owner);
}

// --- GC ----------------------------------------------------------------------------

pub const GcResult = struct {
	/// Snapshots and pins renamed into apply/trash/.
	moved: usize = 0,
	/// A file that names snapshots did not parse, so the GC could not know what
	/// it names and moved nothing.
	kept_everything: bool = false,
	/// Renames that failed (each leaves its tree in place for the next GC).
	failed: usize = 0,
	first_error: ?anyerror = null,
};

/// Launcher pin directories (apply/pin/<id>/) older than this are collected.
pub const pin_max_age_s: i64 = 3600;

/// Tmp names that only a config-lock holder writes directly under apply/ (the
/// launcher's booting and base flips, this module's role flips, the rollback
/// records); under the lock every one that exists is a killed writer's.
const gc_stale_tmp_prefixes = [_][]const u8{ ".booting.tmp.", ".base.tmp.", ".built.tmp.", ".rollbacks.jsonl.tmp.", ".rollbacks.id.tmp." };

/// The snapshot GC, under the config lock, with the launcher's keep rules
/// (apply_snapshot_gc): every snapshot without meta.json (incomplete, whatever
/// names it) and every complete one nothing names is RENAMED into
/// apply/trash/<id>, an O(1) rename. The names that keep one are `keep` (the
/// caller's own), `base`, `built`, `booting`, and every 16-hex string anywhere
/// in apply/active, apply/inflight.json and apply/rollback/*.intent; when one of
/// those does not parse, nothing is moved. An intent's tmp name (a writer
/// between its fsync and its link(2), which may not hold the config lock) keeps
/// what it names too, scanned as raw text. Launcher pins older than an hour go
/// to apply/trash/pin-<id>. Never deletes a tree; never fails: the result says
/// what happened.
pub fn gc(allocator: std.mem.Allocator, io: std.Io, icd: []const u8, keep: []const []const u8, owner: ?u32) GcResult {
	var r: GcResult = .{};
	var arena_state = std.heap.ArenaAllocator.init(allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();
	gcInner(arena, io, icd, keep, owner, &r) catch |err| {
		if (r.first_error == null) r.first_error = err;
	};
	return r;
}

fn gcInner(arena: std.mem.Allocator, io: std.Io, icd: []const u8, keep: []const []const u8, owner: ?u32, r: *GcResult) !void {
	var icd_dir = openIcd(io, icd) catch |err| switch (err) {
		error.FileNotFound => return,
		else => return err,
	};
	defer icd_dir.close(io);
	var apply = icd_dir.openDir(io, "apply", .{ .follow_symlinks = false, .iterate = true }) catch |err| switch (err) {
		// A symlinked apply/ is never written through.
		error.FileNotFound, error.NotDir, error.SymLinkLoop => return,
		else => return err,
	};
	defer apply.close(io);

	// Stale tmp names first (collected, then unlinked).
	{
		var stale: std.ArrayList([]const u8) = .empty;
		var it = apply.iterate();
		while (try it.next(io)) |e| {
			for (gc_stale_tmp_prefixes) |pfx| {
				if (std.mem.startsWith(u8, e.name, pfx)) {
					try stale.append(arena, try arena.dupe(u8, e.name));
					break;
				}
			}
		}
		for (stale.items) |n| apply.deleteFile(io, n) catch {};
	}

	var keep_set: std.StringHashMapUnmanaged(void) = .empty;
	for (keep) |k| try keep_set.put(arena, k, {});
	for ([_]Role{ .base, .built }) |role| {
		var buf: [64]u8 = undefined;
		const n = apply.readLink(io, @tagName(role), &buf) catch continue;
		const target = buf[0..n];
		const last = if (std.mem.lastIndexOfScalar(u8, target, '/')) |k| target[k + 1 ..] else target;
		try keep_set.put(arena, try arena.dupe(u8, last), {});
	}
	if (readNoFollow(arena, io, apply, "booting", max_meta_bytes)) |b| {
		const line = std.mem.sliceTo(b, '\n');
		try keep_set.put(arena, std.mem.trim(u8, line, " \t\r"), {});
	} else |_| {}
	for ([_][]const u8{ "active", "inflight.json" }) |name| {
		if (!try collectFileIds(arena, io, apply, name, &keep_set)) {
			r.kept_everything = true;
			return;
		}
	}
	if (apply.openDir(io, "rollback", .{ .follow_symlinks = false, .iterate = true })) |rb_const| {
		var rb = rb_const;
		defer rb.close(io);
		var it = rb.iterate();
		while (try it.next(io)) |e| {
			if (e.name.len > 0 and e.name[0] == '.') {
				if (std.mem.indexOf(u8, e.name, ".intent.") == null) continue;
				const bytes = readNoFollow(arena, io, rb, e.name, max_state_bytes) catch continue;
				try scanIds(arena, bytes, &keep_set);
				continue;
			}
			if (!std.mem.endsWith(u8, e.name, ".intent")) continue;
			if (!try collectFileIds(arena, io, rb, e.name, &keep_set)) {
				r.kept_everything = true;
				return;
			}
		}
	} else |err| switch (err) {
		error.FileNotFound => {},
		else => {
			r.kept_everything = true;
			return;
		},
	}

	try ensureDir(io, apply, "trash", owner);

	if (apply.openDir(io, "snap", .{ .follow_symlinks = false, .iterate = true })) |snap_const| {
		var snap = snap_const;
		defer snap.close(io);
		var ids: std.ArrayList([]const u8) = .empty;
		var it = snap.iterate();
		while (try it.next(io)) |e| {
			if (!isId(e.name)) continue;
			var kind = e.kind;
			if (kind == .unknown) kind = (snap.statFile(io, e.name, .{ .follow_symlinks = false }) catch continue).kind;
			if (kind != .directory) continue;
			try ids.append(arena, try arena.dupe(u8, e.name));
		}
		for (ids.items) |id| {
			var meta_buf: [32]u8 = undefined;
			const meta_rel = std.fmt.bufPrint(&meta_buf, "{s}/meta.json", .{id}) catch unreachable;
			const complete = if (snap.statFile(io, meta_rel, .{})) |st| st.kind == .file else |_| false;
			if (complete and keep_set.contains(id)) continue;
			var dst_buf: [32]u8 = undefined;
			const dst = std.fmt.bufPrint(&dst_buf, "trash/{s}", .{id}) catch unreachable;
			snap.rename(id, apply, dst, io) catch |err| {
				r.failed += 1;
				if (r.first_error == null) r.first_error = err;
				continue;
			};
			r.moved += 1;
		}
	} else |err| switch (err) {
		error.FileNotFound => {},
		else => return err,
	}

	if (apply.openDir(io, "pin", .{ .follow_symlinks = false, .iterate = true })) |pin_const| {
		var pin = pin_const;
		defer pin.close(io);
		const now_s = std.Io.Timestamp.now(io, .real).toSeconds();
		var old: std.ArrayList([]const u8) = .empty;
		var it = pin.iterate();
		while (try it.next(io)) |e| {
			const st = pin.statFile(io, e.name, .{ .follow_symlinks = false }) catch continue;
			if (st.kind != .directory) continue;
			if (now_s - st.mtime.toSeconds() < pin_max_age_s) continue;
			try old.append(arena, try arena.dupe(u8, e.name));
		}
		for (old.items) |n| {
			const dst = try std.fmt.allocPrint(arena, "trash/pin-{s}", .{n});
			pin.rename(n, apply, dst, io) catch |err| {
				r.failed += 1;
				if (r.first_error == null) r.first_error = err;
				continue;
			};
			r.moved += 1;
		}
	} else |err| switch (err) {
		error.FileNotFound => {},
		else => return err,
	}
}

/// Add every 16-hex string value in the JSON file `name` to `set`. False when
/// the file exists but cannot be read or parsed (the GC then keeps
/// everything); true when it is absent.
fn collectFileIds(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, name: []const u8, set: *std.StringHashMapUnmanaged(void)) !bool {
	const bytes = readNoFollow(arena, io, dir, name, max_state_bytes) catch |err| switch (err) {
		error.FileNotFound => return true,
		else => return false,
	};
	const v = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch return false;
	try collectIds(arena, v, set);
	return true;
}

fn collectIds(arena: std.mem.Allocator, v: std.json.Value, set: *std.StringHashMapUnmanaged(void)) error{OutOfMemory}!void {
	switch (v) {
		.string => |s| if (isId(s)) try set.put(arena, s, {}),
		.array => |a| for (a.items) |x| try collectIds(arena, x, set),
		.object => |o| {
			var it = o.iterator();
			while (it.next()) |e| try collectIds(arena, e.value_ptr.*, set);
		},
		else => {},
	}
}

/// Every run of exactly 16 lowercase hex digits in `bytes`, as raw text.
fn scanIds(arena: std.mem.Allocator, bytes: []const u8, set: *std.StringHashMapUnmanaged(void)) !void {
	var i: usize = 0;
	while (i < bytes.len) {
		if (!isLowerHex(bytes[i .. i + 1])) {
			i += 1;
			continue;
		}
		var j = i;
		while (j < bytes.len and isLowerHex(bytes[j .. j + 1])) j += 1;
		if (j - i == id_len) try set.put(arena, try arena.dupe(u8, bytes[i..j]), {});
		i = j;
	}
}

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

// --- snapshot tests ----------------------------------------------------------------

/// An instance config dir under a scratch root: config.json, plugins-flake/
/// and plugin-sources/ as the plugin verb lays them out.
const SnapFixture = struct {
	root: []u8,
	icd: []u8,

	fn init(io: std.Io, tag: []const u8) !SnapFixture {
		const root = try scratchDir(io, tag);
		const icd = try std.fmt.allocPrint(t.allocator, "{s}/icd", .{root});
		try std.Io.Dir.cwd().createDirPath(io, icd);
		return .{ .root = root, .icd = icd };
	}

	fn deinit(f: *SnapFixture, io: std.Io) void {
		std.Io.Dir.cwd().deleteTree(io, f.root) catch {};
		t.allocator.free(f.root);
		t.allocator.free(f.icd);
	}

	fn path(f: *const SnapFixture, rel: []const u8) ![]u8 {
		return std.fmt.allocPrint(t.allocator, "{s}/{s}", .{ f.icd, rel });
	}

	fn write(f: *const SnapFixture, io: std.Io, rel: []const u8, bytes: []const u8) !void {
		const p = try f.path(rel);
		defer t.allocator.free(p);
		if (std.fs.path.dirname(p)) |d| try std.Io.Dir.cwd().createDirPath(io, d);
		std.Io.Dir.cwd().deleteFile(io, p) catch {};
		try writeFile(io, p, bytes);
	}

	fn read(f: *const SnapFixture, io: std.Io, rel: []const u8) ![]u8 {
		const p = try f.path(rel);
		defer t.allocator.free(p);
		return readFile(io, p);
	}

	fn has(f: *const SnapFixture, io: std.Io, rel: []const u8) bool {
		const p = f.path(rel) catch return false;
		defer t.allocator.free(p);
		std.Io.Dir.cwd().access(io, p, .{}) catch return false;
		return true;
	}

	fn take(f: *const SnapFixture, io: std.Io, cfg: []const u8, budget_ms: i64) !Id {
		const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator, cfg, .{});
		defer parsed.deinit();
		return snapshotTake(t.allocator, io, f.icd, parsed.value, .{ .budget_ms = budget_ms });
	}
};

/// `take`, under a name the fixture's method does not shadow.
const snapshotTake = take;

const fixture_config =
	\\{"network": {"rules": [
	\\  {"allow": "203.0.113.10/32", "plugin": "obs-plugin"},
	\\  {"deny": "198.51.100.0/24", "plugin": "obs-plugin"},
	\\  {"allow": "192.0.2.0/24", "plugin": "other"},
	\\  {"deny": "10.0.0.0/8"}],
	\\ "l7": {"rules": [{"allow": "api.example.com", "plugin": "obs-plugin"}],
	\\        "inject": {"enabled": true, "specs": [{"host": "api.example.com", "secret": "api-token", "plugin": "obs-plugin"}]}}},
	\\ "plugins": [{"name": "obs-plugin", "url": "git+https://git.example.com/acme/obs-plugin", "lockedUrl": "git+https://git.example.com/acme/obs-plugin?rev=1111", "rev": "1111", "narHash": "sha256-v1"}]}
;

test "take: byte copies, a tagged state.json, a hard-linked src/ and meta.json last; read gives it back" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	var fx = try SnapFixture.init(io, "take");
	defer fx.deinit(io);
	try fx.write(io, "plugins-flake/flake.nix", "nix-bytes\n");
	try fx.write(io, "plugins-flake/flake.lock", "{\"version\":7}\n");
	try fx.write(io, "plugin-sources/obs-plugin/flake.nix", "v1\n");
	try fx.write(io, "plugin-sources/obs-plugin/sub/a.txt", "a\n");
	const link_target = try fx.path("plugin-sources/obs-plugin/flake.nix");
	defer t.allocator.free(link_target);
	const link = try fx.path("plugin-sources/obs-plugin/sub/link");
	defer t.allocator.free(link);
	try std.Io.Dir.cwd().symLink(io, "../flake.nix", link, .{});
	const sub = try fx.path("plugin-sources/obs-plugin/sub");
	defer t.allocator.free(sub);
	try std.Io.Dir.cwd().setFilePermissions(io, sub, .fromMode(0o750), .{});

	const id = try fx.take(io, fixture_config, 20_000);
	try t.expect(isId(&id));

	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();
	const snap = try read(arena, io, fx.icd, &id);
	try t.expectEqualStrings("nix-bytes\n", snap.flake_nix.?);
	try t.expectEqualStrings("{\"version\":7}\n", snap.flake_lock.?);
	try t.expectEqualStrings(&compOfBytes("nix-bytes\n", "{\"version\":7}\n"), snap.meta.comp);
	try t.expect(snap.meta.runner == null and snap.meta.key == null);
	try t.expectEqual(@as(usize, 1), snap.plugins.len);
	const tagged = snap.taggedOf("obs-plugin");
	try t.expectEqual(@as(usize, 2), tagged.l4.len);
	try t.expectEqualStrings("203.0.113.10/32", tagged.l4[0].object.get("allow").?.string);
	try t.expectEqualStrings("198.51.100.0/24", tagged.l4[1].object.get("deny").?.string);
	try t.expectEqual(@as(usize, 1), tagged.l7.len);
	try t.expectEqual(@as(usize, 1), tagged.inject.len);
	try t.expectEqual(@as(usize, 0), snap.taggedOf("other").l4.len);

	// src/ shares the live files' inodes; the symlink is copied, not followed;
	// a directory keeps its mode.
	const rel_src = try std.fmt.allocPrint(t.allocator, "apply/snap/{s}/src/obs-plugin", .{&id});
	defer t.allocator.free(rel_src);
	const snap_file = try std.fmt.allocPrint(t.allocator, "{s}/{s}/flake.nix", .{ fx.icd, rel_src });
	defer t.allocator.free(snap_file);
	const live_st = try std.Io.Dir.cwd().statFile(io, link_target, .{});
	const snap_st = try std.Io.Dir.cwd().statFile(io, snap_file, .{});
	try t.expectEqual(live_st.inode, snap_st.inode);
	const snap_link = try std.fmt.allocPrint(t.allocator, "{s}/{s}/sub/link", .{ fx.icd, rel_src });
	defer t.allocator.free(snap_link);
	var lbuf: [64]u8 = undefined;
	try t.expectEqualStrings("../flake.nix", lbuf[0..try std.Io.Dir.cwd().readLink(io, snap_link, &lbuf)]);
	const snap_sub = try std.fmt.allocPrint(t.allocator, "{s}/{s}/sub", .{ fx.icd, rel_src });
	defer t.allocator.free(snap_sub);
	try t.expectEqual(@as(std.posix.mode_t, 0o750), (try std.Io.Dir.cwd().statFile(io, snap_sub, .{})).permissions.toMode() & 0o777);

	// The composition is a byte copy: nix rewriting plugins-flake/flake.lock in
	// place (or the launcher's cp restore) leaves the snapshot and its comp alone.
	{
		const lock_path = try fx.path("plugins-flake/flake.lock");
		defer t.allocator.free(lock_path);
		const f = try std.Io.Dir.cwd().openFile(io, lock_path, .{ .mode = .write_only });
		defer f.close(io);
		try f.writePositionalAll(io, "{\"version\":8}\n", 0);
	}
	var arena2 = std.heap.ArenaAllocator.init(t.allocator);
	defer arena2.deinit();
	const again = try read(arena2.allocator(), io, fx.icd, &id);
	try t.expectEqualStrings("{\"version\":7}\n", again.flake_lock.?);
	try t.expectEqualStrings(snap.meta.comp, again.meta.comp);
}

test "take: no plugin-sources/ snapshots as an empty src/, no plugins as comp none" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	var fx = try SnapFixture.init(io, "take-empty");
	defer fx.deinit(io);
	// A composition left behind with zero plugins is not copied (the launcher's rule).
	try fx.write(io, "plugins-flake/flake.nix", "stale\n");
	const id = try fx.take(io, "{\"network\": \"full\"}", 20_000);
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const snap = try read(arena_state.allocator(), io, fx.icd, &id);
	try t.expectEqualStrings("none", snap.meta.comp);
	try t.expect(snap.flake_nix == null);
	try t.expectEqual(@as(usize, 0), snap.plugins.len);
	const src = try std.fmt.allocPrint(t.allocator, "apply/snap/{s}/src", .{&id});
	defer t.allocator.free(src);
	try t.expect(fx.has(io, src));

	// The first plugin of a fresh instance: plugins listed, no source yet.
	try fx.write(io, "plugins-flake/flake.nix", "nix\n");
	const id2 = try fx.take(io, "{\"plugins\": [{\"name\": \"obs-plugin\", \"url\": \"u\"}]}", 20_000);
	const snap2 = try read(arena_state.allocator(), io, fx.icd, &id2);
	try t.expectEqualStrings(&compOfBytes("nix\n", ""), snap2.meta.comp);
	try t.expect(snap2.flake_lock == null);
}

test "take: a failed or out-of-bound take leaves no meta.json; read refuses it and the GC collects it" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	var fx = try SnapFixture.init(io, "take-fail");
	defer fx.deinit(io);
	try fx.write(io, "plugin-sources/obs-plugin/flake.nix", "v1\n");

	// The bound: an exhausted budget fails the take before meta.json.
	try t.expectError(error.Timeout, fx.take(io, fixture_config, 0));
	// A file that is not a regular file, directory or symlink fails the copy.
	const fifo = try fx.path("plugin-sources/obs-plugin/pipe");
	defer t.allocator.free(fifo);
	const fifo_z = try t.allocator.dupeZ(u8, fifo);
	defer t.allocator.free(fifo_z);
	const libc = struct {
		extern "c" fn mkfifo(path: [*:0]const u8, mode: std.c.mode_t) c_int;
	};
	try t.expectEqual(@as(c_int, 0), libc.mkfifo(fifo_z, 0o600));
	try t.expectError(error.UnsupportedFileType, fx.take(io, fixture_config, 20_000));

	// Both partial trees are incomplete: read refuses them, setRole will not
	// promote one, and the GC moves them even when a role names one.
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();
	const snap_path = try fx.path("apply/snap");
	defer t.allocator.free(snap_path);
	var snap_dir = try std.Io.Dir.cwd().openDir(io, snap_path, .{ .iterate = true });
	defer snap_dir.close(io);
	var ids: std.ArrayList([]const u8) = .empty;
	var it = snap_dir.iterate();
	while (try it.next(io)) |e| try ids.append(arena, try arena.dupe(u8, e.name));
	try t.expectEqual(@as(usize, 2), ids.items.len);
	for (ids.items) |id| {
		try t.expectError(error.Incomplete, read(arena, io, fx.icd, id));
		try t.expectError(error.Incomplete, setRole(io, fx.icd, .base, id, null));
	}
	const base_link = try fx.path("apply/base");
	defer t.allocator.free(base_link);
	const target = try std.fmt.allocPrint(t.allocator, "snap/{s}", .{ids.items[0]});
	defer t.allocator.free(target);
	try std.Io.Dir.cwd().symLink(io, target, base_link, .{ .is_directory = true });
	const r = gc(t.allocator, io, fx.icd, ids.items, null);
	try t.expectEqual(@as(usize, 2), r.moved);
	for (ids.items) |id| {
		const moved = try std.fmt.allocPrint(arena, "apply/trash/{s}", .{id});
		try t.expect(fx.has(io, moved));
	}
}

test "read: composition bytes that no longer hash to meta.json's comp are refused" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	var fx = try SnapFixture.init(io, "read-tamper");
	defer fx.deinit(io);
	try fx.write(io, "plugins-flake/flake.nix", "nix\n");
	const id = try fx.take(io, fixture_config, 20_000);
	const rel = try std.fmt.allocPrint(t.allocator, "apply/snap/{s}/composition/flake.nix", .{&id});
	defer t.allocator.free(rel);
	try fx.write(io, rel, "other\n");
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	try t.expectError(error.InvalidSnapshot, read(arena_state.allocator(), io, fx.icd, &id));
	try t.expectError(error.InvalidSnapshot, read(arena_state.allocator(), io, fx.icd, "not-an-id"));
	try t.expectError(error.FileNotFound, read(arena_state.allocator(), io, fx.icd, "0123456789abcdef"));
}

test "stateJson: the launcher filter's extract, empty pieces where config.json has none" {
	const cfg = try std.json.parseFromSlice(std.json.Value, t.allocator,
		\\{"network": {"rules": [{"allow": "203.0.113.0/24", "plugin": "a"}, "junk", {"deny": "10.0.0.0/8"}],
		\\             "l7": {"rules": [], "inject": true}},
		\\ "plugins": [{"name": "a"}, {"name": "b"}, {"name": "a"}, {"url": "nameless"}]}
	, .{});
	defer cfg.deinit();
	const out = try stateJson(t.allocator, cfg.value);
	defer t.allocator.free(out);
	try t.expectEqualStrings(
		\\{"plugins":[{"name":"a"},{"name":"b"},{"name":"a"},{"url":"nameless"}],"tagged":{"a":{"l4":[{"allow":"203.0.113.0/24","plugin":"a"}],"l7":[],"inject":[]},"b":{"l4":[],"l7":[],"inject":[]}}}
		\\
	, out);
	const full = try std.json.parseFromSlice(std.json.Value, t.allocator, "{\"network\": \"full\", \"plugins\": [{\"name\": \"a\"}]}", .{});
	defer full.deinit();
	const out2 = try stateJson(t.allocator, full.value);
	defer t.allocator.free(out2);
	try t.expectEqualStrings("{\"plugins\":[{\"name\":\"a\"}],\"tagged\":{\"a\":{\"l4\":[],\"l7\":[],\"inject\":[]}}}\n", out2);
}

test "scope: removed, restored and reinserted names by identity, with their revs" {
	const s = try std.json.parseFromSlice(std.json.Value, t.allocator,
		\\[{"name": "kept", "url": "u", "lockedUrl": "l", "rev": "r1", "narHash": "h1"},
		\\ {"name": "upd", "url": "u", "lockedUrl": "l2", "rev": "r2", "narHash": "h2"},
		\\ {"name": "added", "url": "u", "lockedUrl": "l", "narHash": "h3"},
		\\ {"name": "attr", "url": "u", "attr": "x", "lockedUrl": "l", "narHash": "h4"},
		\\ {"name": "content", "url": "path:/p", "lockedUrl": "path:/p", "narHash": "h5"}]
	, .{});
	defer s.deinit();
	const z = try std.json.parseFromSlice(std.json.Value, t.allocator,
		\\[{"name": "deleted", "url": "u", "lockedUrl": "l", "rev": "r0", "narHash": "h0"},
		\\ {"name": "attr", "url": "u", "lockedUrl": "l", "narHash": "h4"},
		\\ {"name": "upd", "url": "u", "lockedUrl": "l1", "rev": "r1", "narHash": "h1"},
		\\ {"name": "kept", "url": "u", "lockedUrl": "l", "rev": "r1", "narHash": "h1", "extra": true},
		\\ {"name": "content", "url": "path:/p", "lockedUrl": "path:/p", "narHash": "h6"}]
	, .{});
	defer z.deinit();
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const sc = try scope(arena_state.allocator(), s.value.array.items, z.value.array.items);
	try t.expectEqual(@as(usize, 5), sc.len);
	try t.expectEqualStrings("upd", sc[0].name);
	try t.expectEqual(Action.restored, sc[0].action);
	try t.expectEqualStrings("r2", sc[0].from_rev.?);
	try t.expectEqualStrings("r1", sc[0].to_rev.?);
	try t.expectEqualStrings("h2", sc[0].from_nar_hash.?);
	try t.expectEqualStrings("added", sc[1].name);
	try t.expectEqual(Action.removed, sc[1].action);
	// No rev: the narHash stands in.
	try t.expectEqualStrings("h3", sc[1].from_rev.?);
	try t.expect(sc[1].to_rev == null);
	// An attr is part of the identity (absent equals only absent).
	try t.expectEqualStrings("attr", sc[2].name);
	try t.expectEqual(Action.restored, sc[2].action);
	// The same locked URL with other content (a path: input): the narHash alone.
	try t.expectEqualStrings("content", sc[3].name);
	try t.expectEqual(Action.restored, sc[3].action);
	try t.expectEqualStrings("h5", sc[3].from_rev.?);
	try t.expectEqualStrings("h6", sc[3].to_rev.?);
	try t.expectEqualStrings("deleted", sc[4].name);
	try t.expectEqual(Action.reinserted, sc[4].action);
	try t.expect(sc[4].from_rev == null and sc[4].from_nar_hash == null);
	try t.expectEqualStrings("r0", sc[4].to_rev.?);

	// An eval_error's scope against K: an earlier restart_required update of a
	// plugin K already has is not in it, while against B it is.
	try t.expectEqual(@as(usize, 0), (try scope(arena_state.allocator(), s.value.array.items, s.value.array.items)).len);
}

test "compositionConsistent: each path p-<name> input locks the narHash state.json records" {
	const plugins = try std.json.parseFromSlice(std.json.Value, t.allocator,
		\\[{"name": "obs-plugin", "narHash": "sha256-v1"}, {"name": "git-only", "narHash": "sha256-g"}]
	, .{});
	defer plugins.deinit();
	const lock_ok =
		\\{"nodes": {"root": {"inputs": {"p-obs-plugin": "p-obs-plugin", "p-git-only": "p-git-only", "user": "user", "p-follows": ["user"]}},
		\\  "p-obs-plugin": {"locked": {"narHash": "sha256-v1", "type": "path"}, "original": {"type": "path"}},
		\\  "p-git-only": {"locked": {"narHash": "sha256-other", "type": "git"}, "original": {"type": "git"}},
		\\  "user": {"locked": {"narHash": "sha256-u"}, "original": {"type": "path"}}}, "root": "root", "version": 7}
	;
	var snap: Snapshot = .{ .id = "0123456789abcdef".*, .meta = .{ .id = "0123456789abcdef", .comp = "none" }, .plugins = plugins.value.array.items, .tagged = null, .flake_nix = "x", .flake_lock = lock_ok };
	try t.expect(compositionConsistent(t.allocator, &snap));
	// A failed op re-pin: the lock still pins the old tree.
	snap.flake_lock = "{\"nodes\": {\"root\": {\"inputs\": {\"p-obs-plugin\": \"n\"}}, \"n\": {\"locked\": {\"narHash\": \"sha256-v0\"}, \"original\": {\"type\": \"path\"}}}}";
	try t.expect(!compositionConsistent(t.allocator, &snap));
	// A locked plugin no entry records.
	snap.flake_lock = "{\"nodes\": {\"root\": {\"inputs\": {\"p-gone\": \"n\"}}, \"n\": {\"locked\": {\"narHash\": \"sha256-v1\"}, \"original\": {\"type\": \"path\"}}}}";
	try t.expect(!compositionConsistent(t.allocator, &snap));
	snap.flake_lock = "not json";
	try t.expect(!compositionConsistent(t.allocator, &snap));
	snap.flake_lock = null;
	try t.expect(compositionConsistent(t.allocator, &snap));
}

test "roles: an atomic symlink flip to a complete snapshot; clear; recordRunner rewrites meta.json" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	var fx = try SnapFixture.init(io, "roles");
	defer fx.deinit(io);
	const a = try fx.take(io, fixture_config, 20_000);
	const b = try fx.take(io, fixture_config, 20_000);
	try t.expect(roleId(io, fx.icd, .base) == null);
	try setRole(io, fx.icd, .base, &a, null);
	try t.expectEqualStrings(&a, &roleId(io, fx.icd, .base).?);
	try setRole(io, fx.icd, .base, &b, null);
	try t.expectEqualStrings(&b, &roleId(io, fx.icd, .base).?);
	var lbuf: [64]u8 = undefined;
	const base_path = try fx.path("apply/base");
	defer t.allocator.free(base_path);
	const expect_target = try std.fmt.allocPrint(t.allocator, "snap/{s}", .{&b});
	defer t.allocator.free(expect_target);
	try t.expectEqualStrings(expect_target, lbuf[0..try std.Io.Dir.cwd().readLink(io, base_path, &lbuf)]);
	try setRole(io, fx.icd, .built, &a, null);
	try t.expectEqualStrings(&a, &roleId(io, fx.icd, .built).?);
	try clearRole(io, fx.icd, .built);
	try t.expect(roleId(io, fx.icd, .built) == null);
	try clearRole(io, fx.icd, .built);
	// No tmp name is left behind.
	const apply_path = try fx.path("apply");
	defer t.allocator.free(apply_path);
	var apply = try std.Io.Dir.cwd().openDir(io, apply_path, .{ .iterate = true });
	defer apply.close(io);
	var it = apply.iterate();
	while (try it.next(io)) |e| try t.expect(!std.mem.startsWith(u8, e.name, "."));

	try recordRunner(t.allocator, io, fx.icd, &b, "/nix/store/r-microvm-run", "/nix/store/s-source#cogbox", null);
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const snap = try read(arena_state.allocator(), io, fx.icd, &b);
	try t.expectEqualStrings("/nix/store/r-microvm-run", snap.meta.runner.?);
	try t.expectEqualStrings("/nix/store/s-source#cogbox", snap.meta.key.?);
	try t.expectEqualStrings("none", snap.meta.comp);
}

test "gc: the launcher's keep rules; renames only; an unparseable keep source keeps everything" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	var fx = try SnapFixture.init(io, "gc");
	defer fx.deinit(io);
	var ids: [8]Id = undefined;
	for (&ids) |*id| id.* = try fx.take(io, fixture_config, 20_000);
	try setRole(io, fx.icd, .base, &ids[0], null);
	try setRole(io, fx.icd, .built, &ids[1], null);
	const booting = try std.fmt.allocPrint(t.allocator, "{s}\n", .{&ids[2]});
	defer t.allocator.free(booting);
	try fx.write(io, "apply/booting", booting);
	const active = try std.fmt.allocPrint(t.allocator, "{{\"pid\": 1, \"scratch_id\": \"{s}\"}}", .{&ids[3]});
	defer t.allocator.free(active);
	try fx.write(io, "apply/active", active);
	const inflight = try std.fmt.allocPrint(t.allocator, "{{\"scope\": [{{\"x\": [\"{s}\"]}}]}}", .{&ids[4]});
	defer t.allocator.free(inflight);
	try fx.write(io, "apply/inflight.json", inflight);
	const intent = try std.fmt.allocPrint(t.allocator, "{{\"target_id\": \"{s}\"}}", .{&ids[5]});
	defer t.allocator.free(intent);
	try fx.write(io, "apply/rollback/aaaaaaaaaaaaaaaa.intent", intent);
	// An intent mid-write (between its fsync and its link) keeps what it names.
	const tmp_intent = try std.fmt.allocPrint(t.allocator, "{{\"target_id\": \"{s}", .{&ids[6]});
	defer t.allocator.free(tmp_intent);
	try fx.write(io, "apply/rollback/.aaaaaaaaaaaaaaaa.intent.0102.tmp", tmp_intent);
	// Stale launcher tmp names, and an old and a fresh pin.
	try fx.write(io, "apply/.base.tmp.123", "x");
	try fx.write(io, "apply/.booting.tmp.9", "x");
	try fx.write(io, "apply/pin/old/flake.nix", "x");
	try fx.write(io, "apply/pin/new/flake.nix", "x");
	const old_pin = try fx.path("apply/pin/old");
	defer t.allocator.free(old_pin);
	const two_hours_ago = std.Io.Timestamp.now(io, .real).subDuration(.fromSeconds(7200));
	try std.Io.Dir.cwd().setTimestamps(io, old_pin, .{ .modify_timestamp = .{ .new = two_hours_ago } });

	// An unparseable active: nothing moves.
	try fx.write(io, "apply/active", "{\"scratch_id\": \"");
	const blocked = gc(t.allocator, io, fx.icd, &.{}, null);
	try t.expect(blocked.kept_everything);
	try t.expectEqual(@as(usize, 0), blocked.moved);
	try fx.write(io, "apply/active", active);

	const r = gc(t.allocator, io, fx.icd, &.{}, null);
	try t.expect(!r.kept_everything);
	try t.expectEqual(@as(usize, 0), r.failed);
	// Only ids[7] is named by nothing; plus the old pin.
	try t.expectEqual(@as(usize, 2), r.moved);
	var buf: [64]u8 = undefined;
	for (ids[0..7]) |id| try t.expect(fx.has(io, try std.fmt.bufPrint(&buf, "apply/snap/{s}/meta.json", .{&id})));
	try t.expect(fx.has(io, try std.fmt.bufPrint(&buf, "apply/trash/{s}/meta.json", .{&ids[7]})));
	try t.expect(fx.has(io, "apply/trash/pin-old"));
	try t.expect(fx.has(io, "apply/pin/new"));
	try t.expect(!fx.has(io, "apply/.base.tmp.123"));
	try t.expect(!fx.has(io, "apply/.booting.tmp.9"));
	// The caller's own keep list.
	try clearRole(io, fx.icd, .base);
	const kept = gc(t.allocator, io, fx.icd, &.{&ids[0]}, null);
	try t.expectEqual(@as(usize, 0), kept.moved);
	try t.expect(fx.has(io, try std.fmt.bufPrint(&buf, "apply/snap/{s}", .{&ids[0]})));
}

test "removeTree: bounded removal of one tree, never through a symlink" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	var fx = try SnapFixture.init(io, "rmtree");
	defer fx.deinit(io);
	try fx.write(io, "victim/a/b/c.txt", "x");
	try fx.write(io, "keep/k.txt", "k");
	const link = try fx.path("link");
	defer t.allocator.free(link);
	try std.Io.Dir.cwd().symLink(io, "keep", link, .{ .is_directory = true });
	var icd = try std.Io.Dir.cwd().openDir(io, fx.icd, .{});
	defer icd.close(io);
	try t.expectEqual(TrashOutcome.deadline, removeTree(t.allocator, io, icd, "victim", 0).outcome);
	try t.expectEqual(TrashOutcome.emptied, removeTree(t.allocator, io, icd, "victim", 30_000).outcome);
	try t.expect(!fx.has(io, "victim"));
	try t.expectEqual(TrashOutcome.emptied, removeTree(t.allocator, io, icd, "link", 30_000).outcome);
	try t.expect(fx.has(io, "keep/k.txt"));
	try t.expectEqual(TrashOutcome.absent, removeTree(t.allocator, io, icd, "victim", 30_000).outcome);
}
