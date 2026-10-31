// Live plugin apply: the automatic commit rollback (spec section 4.6).
//
// A live apply that proves a plugin change broken (the guest rejected it, or
// its composition does not evaluate) writes a per-generation INTENT, and
// finishPending restores the plugin state on the host to the intent's target
// snapshot Z: `base` (B, what the guest runs) for a live rejection, `built` (K,
// else B) for an eval_error. It runs under the instance config lock its caller
// already holds (the plugin dispatcher, the apply verb, the launcher's preboot
// through the inherited fd) and never takes it itself.
//
// Restoring is a set of target-state assignments, so re-running it from the
// intent after a crash is a no-op and no journal exists:
//   (a) plugin-sources/ := a hard-link copy of Z's src/, built beside it and
//       renamed into place (the old tree is renamed into apply/trash/);
//   (b) config.json's plugin entries := Z's, and per scope name the tagged host
//       policy narrowed (policy rule below), then config.save;
//   (c) plugins-flake/{flake.nix,flake.lock} := Z's composition bytes (new
//       files), or removed when Z has none -- Z's own bytes lock Z's narHashes,
//       so no nix runs;
//   (d) runner.path := Z's runner when it was built under the current key, else
//       removed: a record is trusted on its key alone, so a newer cogbox must
//       never file an older image's runner under its own key;
//   (e) in rules mode, the live policy re-rendered (best-effort once (b) saved);
//   (f) for a live rejection, apply/built unlinked: K may hold what was just
//       rolled back, and a later eval_error must then target B;
//   (g) the rollback record appended (once per generation), the intent
//       deleted, the snapshot GC run.
// Any failure in (a)-(d) switches, in the same call, to the FAIL-CLOSED tier:
// pure file operations that remove every `removed` and `restored` name (entry,
// tagged allows and injections, a removed name's denies too, source, root lock
// input), regenerate flake.nix, remove runner.path and unlink built; a
// `reinserted` name stays deleted (one (b) already put back loses its entry,
// source and root lock input again). Only a host fault reaches it, and of the
// three actions only a rolled-back update can lose a plugin the guest runs;
// that is preferred to booting the rejected version.
// If that tier fails too, the intent stays and the mutating plugin verbs and the
// launcher refuse (exit 78) until a finish succeeds or `--abandon-rollback`.
//
// Policy rule (decision 5: a rollback never re-grants). For a `removed` name
// every tagged entry goes, denies included, which returns policy to its state
// before that add. For `restored` and `reinserted` names: an allow tagged X
// that carries `approved: true` (written only by `rules add --plugin` /
// `l7 add --plugin`, the approval path) stays as it is in C; every other allow,
// and every injection, := C intersect Z (mutate.sameRule; C's element kept, in
// C's order); denies := C union Z (Z's missing denies prepended in Z's order, as
// a merge prepends). C is config.json as read at rollback time; names outside
// the scope keep their policy as it is in C.

const std = @import("std");
const plugin = @import("main.zig");
const snapshot = @import("snapshot.zig");
const mutate = @import("mutate.zig");
const rules_module = @import("rules_module");
const config = rules_module.config;
const rule = rules_module.rule;
const l7_module = @import("l7_module");
const l7_rule = l7_module.rule;

/// The rejections that trigger a rollback. Every other outcome keeps the
/// commit.
pub const Reason = enum {
	breaks_base,
	activation_failed,
	activation_hang,
	unit_hang,
	@"unreachable",
	eval_error,

	/// A live rejection (the guest's verdict, or the host losing the guest)
	/// targets B and unlinks K; only eval_error, decided by the host's own
	/// reproduced evaluation, targets K.
	pub fn live(r: Reason) bool {
		return r != .eval_error;
	}
};

pub const Target = enum { base, built };

/// `done`: the normal tier restored the target. `removed`: the fail-closed tier
/// removed the scope's removed and restored names.
pub const Status = enum { done, removed };

/// `<icd>/apply/rollback/<G>.intent`: everything a finish needs, so no finisher
/// re-derives anything from a snapshot. `target_id` is the snapshot the target
/// role linked to at preflight; `scope` was computed then (snapshot.scope), so
/// the fail-closed tier knows its names even when the target cannot be read.
/// `op` is the cogworx run token (absent for a CLI apply).
pub const Intent = struct {
	G: []const u8,
	op: ?[]const u8 = null,
	reason: Reason,
	target: Target,
	target_id: []const u8,
	scope: []const snapshot.ScopeEntry,
};

const rollback_dir = "rollback";
const abandoned_dir = "abandoned";
const intent_suffix = ".intent";
pub const records_file = "rollbacks.jsonl";
pub const records_id_file = "rollbacks.id";
pub const audit_file = "audit.log";
/// Records kept in rollbacks.jsonl (the oldest drop off).
pub const max_records = 64;
/// audit.log's cap; past it the oldest half is dropped.
pub const audit_cap: usize = 1 << 20;
/// One finish call: the normal tier, then on any failure the fail-closed tier.
pub const finish_budget_ms: i64 = 240_000;
/// The share of a finish call's bound the normal tier leaves to the fail-closed
/// tier.
const fail_closed_reserve_ms: i64 = 60_000;
const max_intent_bytes: usize = 4 << 20;
const max_records_bytes: usize = 16 << 20;

/// A plugin name that can be a path component (plugin-sources/<name>). Real
/// names are stricter (name.isValidPluginName); this only keeps a hand-edited
/// one from escaping the directory.
fn safeName(name: []const u8) bool {
	if (name.len == 0 or name.len > 255) return false;
	if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
	return std.mem.indexOfAny(u8, name, "/\x00") == null;
}

/// An op token: what cogworx passes as `--op` (its run number), echoed into
/// records. At most 64 of [A-Za-z0-9._-].
fn validOp(op: []const u8) bool {
	if (op.len == 0 or op.len > 64) return false;
	for (op) |c| switch (c) {
		'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => {},
		else => return false,
	};
	return true;
}

fn validateIntent(intent: Intent) error{InvalidIntent}!void {
	if (!snapshot.isId(intent.G) or !snapshot.isId(intent.target_id)) return error.InvalidIntent;
	if (intent.op) |op| if (!validOp(op)) return error.InvalidIntent;
	for (intent.scope) |e| if (!safeName(e.name)) return error.InvalidIntent;
}

fn intentName(buf: []u8, gen: []const u8) []const u8 {
	return std.fmt.bufPrint(buf, "{s}" ++ intent_suffix, .{gen}) catch unreachable;
}

fn jsonLine(arena: std.mem.Allocator, value: anytype) error{OutOfMemory}![]u8 {
	var aw: std.Io.Writer.Allocating = .init(arena);
	std.json.Stringify.value(value, .{ .emit_null_optional_fields = false }, &aw.writer) catch return error.OutOfMemory;
	aw.writer.writeByte('\n') catch return error.OutOfMemory;
	return aw.toOwnedSlice();
}

/// Parse an intent file. Anything that does not parse, does not validate, or
/// names another generation than its file is error.UnparseableIntent: such an
/// intent is never discarded, it counts as an unfinished rollback.
pub fn parseIntent(arena: std.mem.Allocator, bytes: []const u8, file_name: []const u8) error{UnparseableIntent}!Intent {
	const intent = std.json.parseFromSliceLeaky(Intent, arena, bytes, .{ .ignore_unknown_fields = true }) catch return error.UnparseableIntent;
	validateIntent(intent) catch return error.UnparseableIntent;
	var buf: [32]u8 = undefined;
	if (!std.mem.eql(u8, intentName(&buf, intent.G), file_name)) return error.UnparseableIntent;
	return intent;
}

fn syncDir(dir: std.Io.Dir) void {
	_ = std.c.fsync(dir.handle);
}

fn deleteIfExists(io: std.Io, path: []const u8) !void {
	std.Io.Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
		error.FileNotFound => {},
		else => return err,
	};
}

/// The warnings of one call, collected rather than printed: the caller decides
/// where they go (the apply verb's stdout is its JSON report), and writes them
/// with writeWarnings.
pub const Notes = struct {
	arena: std.mem.Allocator,
	items: std.ArrayList([]const u8) = .empty,

	fn add(self: *Notes, comptime fmt: []const u8, args: anytype) void {
		const msg = std.fmt.allocPrint(self.arena, fmt, args) catch return;
		self.items.append(self.arena, msg) catch {};
	}
};

/// One `cogbox plugin: warning: ...` line per warning.
pub fn writeWarnings(w: *std.Io.Writer, warnings: []const []const u8) std.Io.Writer.Error!void {
	for (warnings) |msg| try w.print("cogbox plugin: warning: {s}\n", .{msg});
}

// --- intent --------------------------------------------------------------------

pub const WriteIntentResult = enum {
	written,
	/// An intent for G already exists (an earlier classification of the same
	/// generation): it is kept.
	exists,
	/// G already has a rollback record: a finished generation is never rolled
	/// back again, so nothing is written.
	recorded,
};

/// The points of an intent write a test can stop at, as a SIGKILL there would.
pub const IntentWriteStep = enum { tmp_created, tmp_written, tmp_synced, linked, tmp_unlinked };

pub const WriteIntentOptions = struct {
	owner: ?u32 = null,
	/// Tests only: return error.SimulatedCrash right after this point, leaving
	/// the files as a SIGKILL there would.
	crash_after: ?IntentWriteStep = null,
};

/// Write `<icd>/apply/rollback/<G>.intent` atomically, only when no record for
/// G exists. The writer holds the apply flock (the apply verb and every
/// recoverer), not necessarily the config lock. The content goes to
/// `.<G>.intent.<nonce>.tmp`, which is fsynced and then link(2)ed to
/// `<G>.intent` (EEXIST: the O_EXCL semantics), after which the tmp name is
/// unlinked and the directory fsynced. So a SIGKILL or a host cut-off at any
/// point leaves either no intent or a complete one, never a partial one. A
/// leftover tmp name is removed only by a finish whose caller holds the apply
/// flock. The rollback paths never create <icd>: a deleted instance gets no
/// intent (error.FileNotFound).
pub fn writeIntent(allocator: std.mem.Allocator, io: std.Io, icd: []const u8, intent: Intent, opts: WriteIntentOptions) !WriteIntentResult {
	try validateIntent(intent);
	var arena_state = std.heap.ArenaAllocator.init(allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();

	var icd_dir = try snapshot.openIcd(io, icd);
	defer icd_dir.close(io);
	try snapshot.ensureDir(io, icd_dir, "apply", opts.owner);
	var apply = try icd_dir.openDir(io, "apply", .{ .follow_symlinks = false });
	defer apply.close(io);
	if ((try readRecordsIn(arena, io, apply)).find(intent.G) != null) return .recorded;
	// apply/abandoned/ exists before any intent can be pending, so
	// --abandon-rollback, the escape from a full disk, only renames into it
	// (a mkdir needs a free inode and block). Best-effort: it never costs the
	// intent.
	snapshot.ensureDir(io, apply, abandoned_dir, opts.owner) catch {};
	try snapshot.ensureDir(io, apply, rollback_dir, opts.owner);
	var rb = try apply.openDir(io, rollback_dir, .{ .follow_symlinks = false });
	defer rb.close(io);

	var name_buf: [32]u8 = undefined;
	const final = intentName(&name_buf, intent.G);
	if (rb.statFile(io, final, .{ .follow_symlinks = false })) |_| {
		return .exists;
	} else |err| switch (err) {
		error.FileNotFound => {},
		else => return err,
	}

	const bytes = try jsonLine(arena, intent);
	var nonce: [8]u8 = undefined;
	io.random(&nonce);
	var tmp_buf: [64]u8 = undefined;
	// Never matches *.intent: a reader never takes a tmp name for an intent.
	const tmp = std.fmt.bufPrint(&tmp_buf, ".{s}" ++ intent_suffix ++ ".{x}.tmp", .{ intent.G, &nonce }) catch unreachable;
	writeIntentTmp(io, rb, tmp, bytes, opts.crash_after) catch |err| {
		// A simulated crash leaves the tmp name, as a SIGKILL would.
		if (err != error.SimulatedCrash) rb.deleteFile(io, tmp) catch {};
		return err;
	};
	if (opts.crash_after == .tmp_synced) return error.SimulatedCrash;
	snapshot.own(io, rb, tmp, opts.owner);
	if (rb.hardLink(tmp, rb, final, io, .{})) |_| {} else |err| {
		rb.deleteFile(io, tmp) catch {};
		if (err == error.PathAlreadyExists) return .exists;
		return err;
	}
	if (opts.crash_after == .linked) return error.SimulatedCrash;
	rb.deleteFile(io, tmp) catch {};
	if (opts.crash_after == .tmp_unlinked) return error.SimulatedCrash;
	syncDir(rb);
	return .written;
}

fn writeIntentTmp(io: std.Io, rb: std.Io.Dir, tmp: []const u8, bytes: []const u8, crash_after: ?IntentWriteStep) !void {
	const f = try rb.createFile(io, tmp, .{ .exclusive = true });
	defer f.close(io);
	if (crash_after == .tmp_created) return error.SimulatedCrash;
	var wbuf: [4096]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll(bytes);
	try w.flush();
	if (crash_after == .tmp_written) return error.SimulatedCrash;
	try f.sync(io);
}

/// The intent files left in <icd>/apply/rollback/ (`*.intent`, unparseable ones
/// included; tmp names, which start with '.', are not intents), sorted. What the
/// launcher checks after its preboot call, and what makes the mutating verbs
/// refuse.
pub fn pendingIntents(arena: std.mem.Allocator, io: std.Io, icd: []const u8) ![]const []const u8 {
	var icd_dir = snapshot.openIcd(io, icd) catch |err| switch (err) {
		error.FileNotFound => return &.{},
		else => return err,
	};
	defer icd_dir.close(io);
	var rb = icd_dir.openDir(io, "apply/" ++ rollback_dir, .{ .follow_symlinks = false, .iterate = true }) catch |err| switch (err) {
		error.FileNotFound => return &.{},
		else => return err,
	};
	defer rb.close(io);
	const listing = try listRollbackDir(arena, io, rb);
	return listing.intents;
}

const Listing = struct {
	intents: []const []const u8,
	tmps: []const []const u8,
};

fn listRollbackDir(arena: std.mem.Allocator, io: std.Io, rb: std.Io.Dir) !Listing {
	var intents: std.ArrayList([]const u8) = .empty;
	var tmps: std.ArrayList([]const u8) = .empty;
	var it = rb.iterate();
	while (try it.next(io)) |e| {
		if (e.name.len > 0 and e.name[0] == '.') {
			if (std.mem.indexOf(u8, e.name, intent_suffix ++ ".") != null and std.mem.endsWith(u8, e.name, ".tmp")) {
				try tmps.append(arena, try arena.dupe(u8, e.name));
			}
			continue;
		}
		if (std.mem.endsWith(u8, e.name, intent_suffix)) try intents.append(arena, try arena.dupe(u8, e.name));
	}
	std.mem.sort([]const u8, intents.items, {}, lessThan);
	return .{ .intents = intents.items, .tmps = tmps.items };
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
	return std.mem.lessThan(u8, a, b);
}

/// The stamped message for an intent a finish left behind. It starts with
/// `cogbox: `, so the GCE/PVE supervisor's allowlist publishes it as the boot
/// error. `instance` fills `-n NAME` (omitted for the default instance).
pub fn writePendingMessage(w: *std.Io.Writer, err: anyerror, instance: ?[]const u8) std.Io.Writer.Error!void {
	try w.print("cogbox: an automatic plugin rollback could not be finished ({s}); free disk space, or run 'cogbox plugin apply --abandon-rollback", .{@errorName(err)});
	if (instance) |n| try w.print(" -n {s}", .{n});
	try w.writeAll("'\n");
}

// --- records ---------------------------------------------------------------------

pub const RecordName = struct {
	name: []const u8,
	action: snapshot.Action,
	from_rev: ?[]const u8 = null,
	to_rev: ?[]const u8 = null,
	/// The narHash of the version rolled back (`repeat` counts on it).
	from_nar_hash: ?[]const u8 = null,
};

/// One line of <icd>/apply/rollbacks.jsonl. At most one exists per `gen`.
pub const Record = struct {
	seq: u64 = 0,
	gen: []const u8,
	op: ?[]const u8 = null,
	reason: Reason,
	/// Unix seconds.
	at: i64,
	target: Target,
	target_id: []const u8,
	status: Status,
	names: []const RecordName,
	/// Z's allows and injections of restored and reinserted names that are not
	/// in C (decision 5: they stay withdrawn).
	policy_not_restored: u64 = 0,
	/// Earlier records (in the file) that rolled back the same name at the same
	/// narHash: a pattern of vetoes.
	repeat: u64 = 0,
};

pub const Records = struct {
	/// rollbacks.id: the records file's identity. A recreated file gets a new
	/// one, which is how cogworx notices one whose seqs restart. Null when absent
	/// or malformed.
	id: ?snapshot.Id = null,
	/// The parseable records, oldest first, and their lines as stored.
	items: []const Record = &.{},
	lines: []const []const u8 = &.{},

	pub fn find(self: Records, gen: []const u8) ?Record {
		for (self.items) |r| if (std.mem.eql(u8, r.gen, gen)) return r;
		return null;
	}

	pub fn maxSeq(self: Records) u64 {
		var m: u64 = 0;
		for (self.items) |r| m = @max(m, r.seq);
		return m;
	}
};

/// Read the rollback records and their file's id (empty when there are none).
/// A line that does not parse is skipped.
pub fn readRecords(arena: std.mem.Allocator, io: std.Io, icd: []const u8) !Records {
	var icd_dir = snapshot.openIcd(io, icd) catch |err| switch (err) {
		error.FileNotFound => return .{},
		else => return err,
	};
	defer icd_dir.close(io);
	var apply = icd_dir.openDir(io, "apply", .{ .follow_symlinks = false }) catch |err| switch (err) {
		error.FileNotFound => return .{},
		else => return err,
	};
	defer apply.close(io);
	return readRecordsIn(arena, io, apply);
}

fn readRecordsIn(arena: std.mem.Allocator, io: std.Io, apply: std.Io.Dir) !Records {
	var out: Records = .{};
	if (snapshot.readNoFollow(arena, io, apply, records_id_file, 256)) |b| {
		const id = std.mem.trim(u8, b, " \t\r\n");
		if (snapshot.isId(id)) out.id = id[0..snapshot.id_len].*;
	} else |err| switch (err) {
		error.FileNotFound => {},
		else => return err,
	}
	const bytes = snapshot.readNoFollow(arena, io, apply, records_file, max_records_bytes) catch |err| switch (err) {
		error.FileNotFound => return out,
		else => return err,
	};
	var items: std.ArrayList(Record) = .empty;
	var lines: std.ArrayList([]const u8) = .empty;
	var it = std.mem.splitScalar(u8, bytes, '\n');
	while (it.next()) |line| {
		if (std.mem.trim(u8, line, " \t\r").len == 0) continue;
		const r = std.json.parseFromSliceLeaky(Record, arena, line, .{ .ignore_unknown_fields = true }) catch continue;
		try items.append(arena, r);
		try lines.append(arena, line);
	}
	out.items = items.items;
	out.lines = lines.items;
	return out;
}

fn countRepeat(earlier: []const Record, names: []const RecordName) u64 {
	var n: u64 = 0;
	for (earlier) |r| {
		if (sharesVersion(r.names, names)) n += 1;
	}
	return n;
}

/// Whether two records rolled back some name at the same narHash.
fn sharesVersion(a: []const RecordName, b: []const RecordName) bool {
	for (a) |x| for (b) |y| {
		if (std.mem.eql(u8, x.name, y.name) and optEql(x.from_nar_hash, y.from_nar_hash)) return true;
	};
	return false;
}

fn optEql(a: ?[]const u8, b: ?[]const u8) bool {
	if (a == null or b == null) return a == null and b == null;
	return std.mem.eql(u8, a.?, b.?);
}

/// Append `rec` (its seq and repeat assigned here) unless a record for its
/// generation exists, which is returned instead. A new records file first gets a
/// new random rollbacks.id. The file keeps the last max_records records and is
/// rewritten as a new file (tmp + fsync + rename); audit.log mirrors the new
/// record. Runs under the config lock.
fn appendRecord(arena: std.mem.Allocator, io: std.Io, apply: std.Io.Dir, rec_in: Record, owner: ?u32, notes: *Notes) !Record {
	const existing = try readRecordsIn(arena, io, apply);
	if (existing.find(rec_in.gen)) |r| return r;
	if (existing.items.len == 0 or existing.id == null) {
		var id_line: [snapshot.id_len + 1]u8 = undefined;
		id_line[0..snapshot.id_len].* = snapshot.newId(io);
		id_line[snapshot.id_len] = '\n';
		try snapshot.writeNew(io, apply, records_id_file, &id_line, owner);
	}
	var rec = rec_in;
	rec.seq = existing.maxSeq() + 1;
	rec.repeat = countRepeat(existing.items, rec.names);
	const line = try jsonLine(arena, rec);
	var out: std.ArrayList(u8) = .empty;
	const keep_from = existing.lines.len -| (max_records - 1);
	for (existing.lines[keep_from..]) |l| {
		try out.appendSlice(arena, l);
		try out.append(arena, '\n');
	}
	try out.appendSlice(arena, line);
	try snapshot.writeNew(io, apply, records_file, out.items, owner);
	const audit_line = std.fmt.allocPrint(arena, "{{\"event\":\"rollback\",\"record\":{s}}}\n", .{std.mem.trimEnd(u8, line, "\n")}) catch return rec;
	appendAudit(arena, io, apply, audit_line, owner, notes);
	return rec;
}

/// Append `line` (one JSON object and its newline) to <icd>/apply/audit.log,
/// best-effort, under the config lock the caller holds: the apply verb logs its
/// forced runs here, beside the records this module mirrors.
pub fn audit(allocator: std.mem.Allocator, io: std.Io, icd: []const u8, line: []const u8, owner: ?u32) !void {
	var arena_state = std.heap.ArenaAllocator.init(allocator);
	defer arena_state.deinit();
	var icd_dir = try snapshot.openIcd(io, icd);
	defer icd_dir.close(io);
	try snapshot.ensureDir(io, icd_dir, "apply", owner);
	var apply = try icd_dir.openDir(io, "apply", .{ .follow_symlinks = false });
	defer apply.close(io);
	try appendAuditInner(arena_state.allocator(), io, apply, line, owner);
}

/// Append one line to <icd>/apply/audit.log, best-effort. Past audit_cap the
/// newest half is kept (rewritten as a new file). Every writer holds the config
/// lock.
fn appendAudit(arena: std.mem.Allocator, io: std.Io, apply: std.Io.Dir, line: []const u8, owner: ?u32, notes: *Notes) void {
	appendAuditInner(arena, io, apply, line, owner) catch |err| notes.add("could not write apply/{s} ({s})", .{ audit_file, @errorName(err) });
}

fn appendAuditInner(arena: std.mem.Allocator, io: std.Io, apply: std.Io.Dir, line: []const u8, owner: ?u32) !void {
	const size: u64 = if (apply.statFile(io, audit_file, .{ .follow_symlinks = false })) |st| st.size else |err| switch (err) {
		error.FileNotFound => 0,
		else => return err,
	};
	if (size + line.len > audit_cap) {
		const old = try snapshot.readNoFollow(arena, io, apply, audit_file, audit_cap + 1);
		var start = old.len -| (audit_cap / 2);
		if (std.mem.indexOfScalarPos(u8, old, start, '\n')) |nl| start = nl + 1 else start = old.len;
		const kept = try std.mem.concat(arena, u8, &.{ old[start..], line });
		return snapshot.writeNew(io, apply, audit_file, kept, owner);
	}
	const f = apply.openFile(io, audit_file, .{ .mode = .write_only, .follow_symlinks = false }) catch |err| switch (err) {
		error.FileNotFound => blk: {
			const nf = try apply.createFile(io, audit_file, .{ .exclusive = true, .truncate = false });
			snapshot.own(io, apply, audit_file, owner);
			break :blk nf;
		},
		else => return err,
	};
	defer f.close(io);
	try f.writePositionalAll(io, line, size);
}

// --- finish ------------------------------------------------------------------------

/// The steps of one finish, for the tests' crash and failure hooks.
pub const Step = enum { sources, config, composition, runner, reload, built, record, intent };

pub const Hooks = struct {
	/// Return error.SimulatedCrash right after this step, leaving every file as
	/// a SIGKILL there would (and ending the whole call). Tests only.
	crash_after: ?Step = null,
	/// Fail this normal-tier step (sources, config, composition or runner), so
	/// the fail-closed tier runs. Tests only.
	fail_at: ?Step = null,
	/// Fail the fail-closed tier before it writes anything. Tests only.
	fail_closed_fails: bool = false,
};

pub const FinishOptions = struct {
	/// The caller holds the apply flock, so no intent writer is between its
	/// fsync and its link(2): leftover intent tmp names are stale and removed.
	/// Without it (the launcher's preboot while an apply runs) they are left.
	holds_apply_flock: bool = false,
	budget_ms: i64 = finish_budget_ms,
	hooks: Hooks = .{},
};

pub const RunnerRecord = enum {
	/// runner.path names the target's runner (built under the current key).
	target,
	/// runner.path was removed; the next boot evaluates.
	removed,
};

pub const Reload = enum {
	/// Not rules mode (.network is not an object): no policy to render.
	skipped,
	/// Rendered from the saved config (passt signalled when it runs).
	reloaded,
	/// The render failed after config.save; the saved policy takes effect at the
	/// next rules op or boot.
	failed,
};

pub const Finished = struct {
	record: Record,
	/// False when the record already existed and the intent was only discarded.
	fresh: bool,
	runner_record: RunnerRecord = .removed,
	reload: Reload = .skipped,
	/// Why the normal tier gave way to the fail-closed tier (status removed).
	normal_error: ?anyerror = null,

	/// The `rollback` object of the apply report (`apply --json`, last.json).
	pub fn report(self: Finished) Report {
		return .{
			.status = self.record.status,
			.target = self.record.target,
			.target_id = self.record.target_id,
			.names = self.record.names,
			.policy_not_restored = self.record.policy_not_restored,
			.runner_record = if (self.fresh) self.runner_record else null,
			.seq = self.record.seq,
		};
	}
};

/// `{"status","target","target_id","names","policy_not_restored","runner_record","seq"}`.
/// runner_record is absent for a generation another finisher recorded.
pub const Report = struct {
	status: Status,
	target: Target,
	target_id: []const u8,
	names: []const RecordName,
	policy_not_restored: u64,
	runner_record: ?RunnerRecord,
	seq: u64,
};

pub const Outcome = struct {
	/// The intent's file name under apply/rollback/.
	file: []const u8,
	result: union(enum) {
		finished: Finished,
		/// config.json is gone (the instance was deleted): the intent was
		/// discarded, nothing else touched.
		discarded,
		/// The intent stays: it does not parse, both tiers failed, or a later
		/// step (the built unlink, the record, the intent delete) failed.
		pending: anyerror,
	},
};

pub const FinishResult = struct {
	outcomes: []const Outcome = &.{},
	/// Intents left behind. Non-zero makes the mutating plugin verbs exit 78
	/// and a launcher on a stopped instance refuse to boot.
	pending: usize = 0,
	pending_error: ?anyerror = null,
	/// Leftover intent tmp names removed (only with holds_apply_flock).
	swept_tmp: usize = 0,
	gc: ?snapshot.GcResult = null,
	/// A test hook stopped the call; nothing after that point ran.
	crashed: bool = false,
	/// What went wrong short of leaving an intent (a tier switch, a failed
	/// reload, a source left behind), for the caller to print (writeWarnings).
	warnings: []const []const u8 = &.{},
};

/// The instance config dir: plugins-flake/'s parent, as the dispatcher derives
/// plugin-sources/ from it.
fn icdOf(ctx: *const plugin.Ctx) ?[]const u8 {
	return std.fs.path.dirname(ctx.plugins_flake_dir);
}

/// Finish every pending intent, under the config lock the caller holds (this
/// never takes it). One call is bounded at `opts.budget_ms` (240 s): file
/// operations only, no nix, no child process. It never fails as a whole: each
/// intent's outcome is reported, and `pending` says how many stay. At the end
/// (unless a test hook crashed it) the snapshot GC runs. Allocates in `arena`.
pub fn finishPending(arena: std.mem.Allocator, ctx: *const plugin.Ctx, opts: FinishOptions) FinishResult {
	var r: FinishResult = .{};
	var notes: Notes = .{ .arena = arena };
	if (icdOf(ctx)) |icd| {
		finishAll(arena, ctx, icd, opts, &r, &notes) catch |err| {
			// The rollback directory could not be read: whether an intent is
			// pending is unknown, which counts as pending.
			r.pending += 1;
			if (r.pending_error == null) r.pending_error = err;
		};
		if (!r.crashed) r.gc = snapshot.gc(arena, ctx.io, icd, &.{}, ctx.real_uid);
	}
	r.warnings = notes.items.items;
	return r;
}

fn finishAll(arena: std.mem.Allocator, ctx: *const plugin.Ctx, icd: []const u8, opts: FinishOptions, r: *FinishResult, notes: *Notes) !void {
	const io = ctx.io;
	var icd_dir = snapshot.openIcd(io, icd) catch |err| switch (err) {
		error.FileNotFound => return,
		else => return err,
	};
	defer icd_dir.close(io);
	var apply = icd_dir.openDir(io, "apply", .{ .follow_symlinks = false }) catch |err| switch (err) {
		error.FileNotFound => return,
		else => return err,
	};
	defer apply.close(io);
	var rb = apply.openDir(io, rollback_dir, .{ .follow_symlinks = false, .iterate = true }) catch |err| switch (err) {
		error.FileNotFound => return,
		else => return err,
	};
	defer rb.close(io);
	const listing = try listRollbackDir(arena, io, rb);
	if (opts.holds_apply_flock) {
		for (listing.tmps) |tmp| {
			rb.deleteFile(io, tmp) catch continue;
			r.swept_tmp += 1;
		}
	}

	const total = snapshot.Deadline.init(io, opts.budget_ms);
	const normal: snapshot.Deadline = .{ .io = io, .began = total.began, .budget_ms = @max(opts.budget_ms - fail_closed_reserve_ms, @divTrunc(opts.budget_ms, 2)) };
	var outcomes: std.ArrayList(Outcome) = .empty;
	for (listing.intents) |file| {
		const o = finishOne(arena, ctx, icd, icd_dir, apply, rb, file, opts.hooks, &total, &normal, notes);
		try outcomes.append(arena, o);
		switch (o.result) {
			.pending => |err| {
				if (err == error.SimulatedCrash) {
					r.crashed = true;
					break;
				}
				r.pending += 1;
				if (r.pending_error == null) r.pending_error = err;
			},
			else => {},
		}
	}
	r.outcomes = outcomes.items;
}

/// What the tiers report back for the record and the outcome.
const Exec = struct {
	runner_record: RunnerRecord = .removed,
	reload: Reload = .skipped,
	policy_not_restored: u64 = 0,
};

fn crashAfter(hooks: Hooks, step: Step) error{SimulatedCrash}!void {
	if (hooks.crash_after == step) return error.SimulatedCrash;
}

fn failAt(hooks: Hooks, step: Step) error{InjectedFailure}!void {
	if (hooks.fail_at == step) return error.InjectedFailure;
}

fn finishOne(
	arena: std.mem.Allocator,
	ctx: *const plugin.Ctx,
	icd: []const u8,
	icd_dir: std.Io.Dir,
	apply: std.Io.Dir,
	rb: std.Io.Dir,
	file: []const u8,
	hooks: Hooks,
	total: *const snapshot.Deadline,
	normal: *const snapshot.Deadline,
	notes: *Notes,
) Outcome {
	const io = ctx.io;
	const pending = struct {
		fn of(f: []const u8, err: anyerror) Outcome {
			return .{ .file = f, .result = .{ .pending = err } };
		}
	}.of;

	const bytes = snapshot.readNoFollow(arena, io, rb, file, max_intent_bytes) catch |err| return pending(file, err);
	// An intent that does not parse is never discarded: with atomic writes only a
	// host-disk fault produces one, and --abandon-rollback moves it.
	const intent = parseIntent(arena, bytes, file) catch |err| return pending(file, err);

	// A deleted instance: discard the intent, create nothing.
	std.Io.Dir.cwd().access(io, ctx.config_path, .{}) catch |err| switch (err) {
		error.FileNotFound => {
			rb.deleteFile(io, file) catch |e| return pending(file, e);
			return .{ .file = file, .result = .discarded };
		},
		else => return pending(file, err),
	};

	// A generation already recorded (another finisher completed it, or a crash
	// fell between the record and the intent delete): discard, report it.
	const records = readRecordsIn(arena, io, apply) catch |err| return pending(file, err);
	if (records.find(intent.G)) |rec| {
		rb.deleteFile(io, file) catch |err| return pending(file, err);
		return .{ .file = file, .result = .{ .finished = .{ .record = rec, .fresh = false } } };
	}

	var ex: Exec = .{};
	var status: Status = .done;
	var normal_error: ?anyerror = null;
	const z: ?snapshot.Snapshot = snapshot.read(arena, io, icd, intent.target_id) catch |err| blk: {
		normal_error = err;
		break :blk null;
	};
	if (z) |*zs| {
		restore(arena, ctx, icd_dir, apply, intent, zs, hooks, normal, &ex, notes) catch |err| {
			if (err == error.SimulatedCrash) return pending(file, err);
			normal_error = err;
		};
	}
	if (normal_error) |nerr| {
		status = .removed;
		notes.add("rollback of generation {s}: restoring snapshot {s} failed ({s}); removing the rolled-back plugins instead", .{ intent.G, intent.target_id, @errorName(nerr) });
		failClosed(arena, ctx, icd, icd_dir, apply, intent, if (z) |*zs| zs else null, hooks, total, &ex, notes) catch |err| {
			if (err == error.SimulatedCrash) return pending(file, err);
			notes.add("rollback of generation {s}: removing the rolled-back plugins failed too ({s}); the rollback stays pending", .{ intent.G, @errorName(err) });
			return pending(file, err);
		};
	}

	// (f) K may hold the content just rolled back; a later eval_error must then
	// target B. Until this succeeds the intent stays, and no apply can start.
	if (intent.reason.live()) snapshot.clearRole(io, icd, .built) catch |err| return pending(file, err);
	crashAfter(hooks, .built) catch |err| return pending(file, err);

	// (g)
	var names = arena.alloc(RecordName, intent.scope.len) catch |err| return pending(file, err);
	for (intent.scope, 0..) |e, i| names[i] = .{
		.name = e.name,
		.action = e.action,
		.from_rev = e.from_rev,
		// The fail-closed tier restores nothing.
		.to_rev = if (status == .done) e.to_rev else null,
		.from_nar_hash = e.from_nar_hash,
	};
	const rec = appendRecord(arena, io, apply, .{
		.gen = intent.G,
		.op = intent.op,
		.reason = intent.reason,
		.at = std.Io.Timestamp.now(io, .real).toSeconds(),
		.target = intent.target,
		.target_id = intent.target_id,
		.status = status,
		.names = names,
		.policy_not_restored = ex.policy_not_restored,
	}, ctx.real_uid, notes) catch |err| return pending(file, err);
	crashAfter(hooks, .record) catch |err| return pending(file, err);
	rb.deleteFile(io, file) catch |err| switch (err) {
		error.FileNotFound => {},
		else => return pending(file, err),
	};
	syncDir(rb);
	crashAfter(hooks, .intent) catch |err| return pending(file, err);
	return .{ .file = file, .result = .{ .finished = .{
		.record = rec,
		.fresh = true,
		.runner_record = ex.runner_record,
		.reload = ex.reload,
		.normal_error = normal_error,
	} } };
}

/// The normal tier, steps (a)-(e).
fn restore(
	arena: std.mem.Allocator,
	ctx: *const plugin.Ctx,
	icd_dir: std.Io.Dir,
	apply: std.Io.Dir,
	intent: Intent,
	z: *const snapshot.Snapshot,
	hooks: Hooks,
	deadline: *const snapshot.Deadline,
	ex: *Exec,
	notes: *Notes,
) !void {
	const io = ctx.io;
	// (a)
	try failAt(hooks, .sources);
	try restoreSources(arena, ctx, icd_dir, apply, &z.id, deadline);
	try crashAfter(hooks, .sources);

	// (b)
	try failAt(hooks, .config);
	try deadline.check();
	var loaded = try config.load(arena, io, ctx.config_path);
	defer loaded.deinit();
	try setPlugins(&loaded, z.plugins);
	ex.policy_not_restored = countNotRestored(&loaded, intent.scope, z);
	if (loaded.network()) |net| {
		const tree = loaded.treeAllocator();
		for (intent.scope) |e| switch (e.action) {
			.removed => dropTagged(net, e.name, .everything),
			.restored, .reinserted => try narrowToTarget(tree, net, e.name, z.taggedOf(e.name)),
		};
	} else |_| {}
	try config.save(arena, io, ctx.config_path, loaded.root().*);
	try crashAfter(hooks, .config);

	// (c)
	try failAt(hooks, .composition);
	try restoreComposition(arena, ctx, z);
	try crashAfter(hooks, .composition);

	// (d)
	try failAt(hooks, .runner);
	ex.runner_record = try restoreRunner(arena, ctx, z);
	try crashAfter(hooks, .runner);

	// (e)
	ex.reload = reloadPolicy(arena, ctx, &loaded, notes);
	try crashAfter(hooks, .reload);
}

/// (a): plugin-sources/ := a hard-link copy of the target's src/, built beside
/// it under a unique name and renamed into place; the old tree is renamed into
/// apply/trash/ (emptied later, bounded). Work trees an interrupted finish left
/// are moved into the trash first.
fn restoreSources(arena: std.mem.Allocator, ctx: *const plugin.Ctx, icd_dir: std.Io.Dir, apply: std.Io.Dir, z_id: []const u8, deadline: *const snapshot.Deadline) !void {
	const io = ctx.io;
	const sources = std.fs.path.basename(ctx.sources_dir);
	try snapshot.ensureDir(io, apply, "trash", ctx.real_uid);
	const work_prefix = try std.fmt.allocPrint(arena, ".{s}.rollback.", .{sources});
	sweepWork(arena, ctx, apply, work_prefix);

	const snap_rel = try std.fmt.allocPrint(arena, "snap/{s}", .{z_id});
	var zdir = try apply.openDir(io, snap_rel, .{ .follow_symlinks = false });
	defer zdir.close(io);
	var nonce: [8]u8 = undefined;
	io.random(&nonce);
	const work = try std.fmt.allocPrint(arena, "{s}{x}", .{ work_prefix, &nonce });
	try snapshot.linkTree(io, zdir, "src", icd_dir, work, deadline);
	// The copy keeps the snapshot's owners (as cp -a does); its top goes to the
	// invoking user, as a take's src/ does.
	snapshot.own(io, icd_dir, work, ctx.real_uid);
	const old = try std.fmt.allocPrint(arena, "trash/{s}-{x}", .{ sources, &nonce });
	var moved_old = true;
	icd_dir.rename(sources, apply, old, io) catch |err| switch (err) {
		error.FileNotFound => moved_old = false,
		else => return err,
	};
	icd_dir.rename(work, icd_dir, sources, io) catch |err| {
		if (moved_old) apply.rename(old, icd_dir, sources, io) catch {};
		return err;
	};
}

/// Move into the trash the work trees (`.plugin-sources.rollback.*`) a finish
/// cut short left beside plugin-sources/. Only a config-lock holder creates
/// them, so under the lock every one is stale. Best-effort.
fn sweepWork(arena: std.mem.Allocator, ctx: *const plugin.Ctx, apply: std.Io.Dir, prefix: []const u8) void {
	const io = ctx.io;
	const icd = icdOf(ctx) orelse return;
	var dir = std.Io.Dir.cwd().openDir(io, icd, .{ .iterate = true }) catch return;
	defer dir.close(io);
	var stale: std.ArrayList([]const u8) = .empty;
	var it = dir.iterate();
	while (it.next(io) catch return) |e| {
		if (std.mem.startsWith(u8, e.name, prefix)) stale.append(arena, arena.dupe(u8, e.name) catch return) catch return;
	}
	for (stale.items) |n| {
		const dst = std.fmt.allocPrint(arena, "trash/{s}", .{n[1..]}) catch return;
		dir.rename(n, apply, dst, io) catch {
			_ = snapshot.removeTree(arena, io, dir, n, 10_000);
		};
	}
}

/// config.json's .plugins := a deep copy of `plugins` (the target's entries).
fn setPlugins(loaded: *config.Loaded, plugins: []const std.json.Value) !void {
	const root = loaded.root();
	if (root.* != .object) return error.InvalidJson;
	const tree = loaded.treeAllocator();
	var arr = std.json.Array.init(tree);
	try arr.ensureTotalCapacity(plugins.len);
	for (plugins) |p| arr.appendAssumeCapacity(try mutate.deepCopy(tree, p));
	if (root.object.getPtr("plugins")) |ptr| {
		ptr.* = .{ .array = arr };
	} else {
		try root.object.put(tree, try tree.dupe(u8, "plugins"), .{ .array = arr });
	}
}

// --- policy --------------------------------------------------------------------------

const List = enum {
	l4,
	l7,
	inject,

	fn kind(l: List) mutate.RuleKind {
		return switch (l) {
			.l4 => .l4,
			.l7 => .l7,
			.inject => .inject,
		};
	}

	fn of(l: List, t: snapshot.Tagged) []const std.json.Value {
		return switch (l) {
			.l4 => t.l4,
			.l7 => t.l7,
			.inject => t.inject,
		};
	}
};

fn arrayPtr(v: ?*std.json.Value) ?*std.json.Array {
	const p = v orelse return null;
	if (p.* != .array) return null;
	return &p.array;
}

fn objectPtrGet(v: ?*std.json.Value, key: []const u8) ?*std.json.Value {
	const p = v orelse return null;
	if (p.* != .object) return null;
	return p.object.getPtr(key);
}

/// The list in C (`net` is the .network object), when it exists as an array.
fn existingList(net: *std.json.Value, l: List) ?*std.json.Array {
	return switch (l) {
		.l4 => arrayPtr(objectPtrGet(net, "rules")),
		.l7 => arrayPtr(objectPtrGet(objectPtrGet(net, "l7"), "rules")),
		.inject => arrayPtr(objectPtrGet(objectPtrGet(objectPtrGet(net, "l7"), "inject"), "specs")),
	};
}

/// The L4 or L7 list, created empty when absent; error.InvalidJson when the
/// config holds something else there. Only denies are ever added.
fn ensureList(tree: std.mem.Allocator, net: *std.json.Value, l: List) !*std.json.Array {
	if (existingList(net, l)) |a| return a;
	switch (l) {
		.l4 => {
			if (net.object.get("rules") != null) return error.InvalidJson;
			try net.object.put(tree, try tree.dupe(u8, "rules"), .{ .array = std.json.Array.init(tree) });
		},
		.l7 => _ = try l7_module.ensureL7Object(net, tree),
		.inject => return error.InvalidJson,
	}
	return existingList(net, l) orelse error.InvalidJson;
}

fn isDeny(l: List, v: std.json.Value) bool {
	if (v != .object) return false;
	return switch (l) {
		.l4 => if (rule.ruleAction(v.object)) |p| p.action == .deny else false,
		.l7 => if (l7_rule.ruleAction(v.object)) |p| p.action == .deny else false,
		.inject => false,
	};
}

fn isApproved(v: std.json.Value) bool {
	if (v != .object) return false;
	const a = v.object.get("approved") orelse return false;
	return a == .bool and a.bool;
}

fn taggedAs(v: std.json.Value, name: []const u8) bool {
	const t = mutate.ruleTag(v) orelse return false;
	return std.mem.eql(u8, t, name);
}

/// Whether `arr` holds an entry tagged `name` with the same identity as `v`.
fn hasTagged(arr: ?*std.json.Array, name: []const u8, kind: mutate.RuleKind, v: std.json.Value) bool {
	const a = arr orelse return false;
	for (a.items) |c| {
		if (taggedAs(c, name) and mutate.sameRule(kind, c, v)) return true;
	}
	return false;
}

fn hasSame(items: []const std.json.Value, kind: mutate.RuleKind, v: std.json.Value) bool {
	for (items) |z| if (mutate.sameRule(kind, v, z)) return true;
	return false;
}

/// policy_not_restored: the target's allows and injections, of the scope's
/// restored and reinserted names, that C does not have.
fn countNotRestored(loaded: *config.Loaded, scope: []const snapshot.ScopeEntry, z: *const snapshot.Snapshot) u64 {
	const net_opt: ?*std.json.Value = loaded.network() catch null;
	var n: u64 = 0;
	for (scope) |e| {
		if (e.action == .removed) continue;
		const zt = z.taggedOf(e.name);
		for ([_]List{ .l4, .l7, .inject }) |l| {
			const arr = if (net_opt) |net| existingList(net, l) else null;
			for (l.of(zt)) |zv| {
				if (isDeny(l, zv)) continue;
				if (!hasTagged(arr, e.name, l.kind(), zv)) n += 1;
			}
		}
	}
	return n;
}

/// What dropTagged removes of a name's tagged entries.
const Drop = enum {
	/// Everything, denies included (a rolled-back add).
	everything,
	/// Allows and injections; denies stay (the fail-closed tier's restored name).
	keep_denies,
};

fn dropTagged(net: *std.json.Value, name: []const u8, what: Drop) void {
	for ([_]List{ .l4, .l7, .inject }) |l| {
		const arr = existingList(net, l) orelse continue;
		var i: usize = 0;
		while (i < arr.items.len) {
			const c = arr.items[i];
			if (taggedAs(c, name) and (what == .everything or !isDeny(l, c))) {
				_ = arr.orderedRemove(i);
				continue;
			}
			i += 1;
		}
	}
}

/// The policy rule for a restored or reinserted name: approved allows stay,
/// other allows and injections := C intersect Z (C's element, in C's order),
/// denies := C union Z (Z's missing denies prepended in Z's order, as a merge
/// prepends).
fn narrowToTarget(tree: std.mem.Allocator, net: *std.json.Value, name: []const u8, zt: snapshot.Tagged) !void {
	for ([_]List{ .l4, .l7, .inject }) |l| {
		const kind = l.kind();
		const z_items = l.of(zt);
		if (existingList(net, l)) |arr| {
			var i: usize = 0;
			while (i < arr.items.len) {
				const c = arr.items[i];
				const keep = !taggedAs(c, name) or isDeny(l, c) or (l != .inject and isApproved(c)) or hasSame(z_items, kind, c);
				if (!keep) {
					_ = arr.orderedRemove(i);
					continue;
				}
				i += 1;
			}
		}
		if (l == .inject) continue;
		var add: std.ArrayList(std.json.Value) = .empty;
		defer add.deinit(tree);
		for (z_items) |zv| {
			if (!isDeny(l, zv)) continue;
			if (hasTagged(existingList(net, l), name, kind, zv)) continue;
			try add.append(tree, zv);
		}
		if (add.items.len > 0) try mutate.prependTaggedRules(tree, try ensureList(tree, net, l), name, add.items);
	}
}

// --- composition and runner --------------------------------------------------------

/// (c): plugins-flake/{flake.nix,flake.lock} := the target's composition bytes,
/// as new files (writeFileAtomic), or removed when it has none (and the lock
/// removed for a lockless one).
fn restoreComposition(arena: std.mem.Allocator, ctx: *const plugin.Ctx, z: *const snapshot.Snapshot) !void {
	const io = ctx.io;
	const nix_path = try std.fs.path.join(arena, &.{ ctx.plugins_flake_dir, "flake.nix" });
	const lock_path = try std.fs.path.join(arena, &.{ ctx.plugins_flake_dir, "flake.lock" });
	const nix_bytes = z.flake_nix orelse {
		try deleteIfExists(io, nix_path);
		try deleteIfExists(io, lock_path);
		return;
	};
	std.Io.Dir.cwd().createDir(io, ctx.plugins_flake_dir, .default_dir) catch |err| switch (err) {
		error.PathAlreadyExists => {},
		else => return err,
	};
	if (!plugin.writeFileAtomic(ctx, nix_path, nix_bytes)) return error.CompositionWriteFailed;
	if (z.flake_lock) |lock| {
		if (!plugin.writeFileAtomic(ctx, lock_path, lock)) return error.CompositionWriteFailed;
	} else {
		try deleteIfExists(io, lock_path);
	}
}

/// `COGBOX_FLAKE_SOURCE#COGBOX_REEXEC_PACKAGE`, the key the launcher trusts a
/// runner record on; null without a flake source (nothing is then recorded).
fn currentKey(arena: std.mem.Allocator, ctx: *const plugin.Ctx) ?[]const u8 {
	const src = ctx.parent_env.get("COGBOX_FLAKE_SOURCE") orelse return null;
	return std.fmt.allocPrint(arena, "{s}#{s}", .{ src, plugin.reexecPackage(ctx) }) catch null;
}

/// (d): the target's runner when it has one built under the current key (and a
/// composition comp to vouch for), with the prev lock and the repin verdict
/// cleared as a confirmed runner clears them; otherwise runner.path removed.
fn restoreRunner(arena: std.mem.Allocator, ctx: *const plugin.Ctx, z: *const snapshot.Snapshot) !RunnerRecord {
	if (currentKey(arena, ctx)) |key| {
		if (z.meta.runner) |runner| {
			const zkey = z.meta.key orelse "";
			if (std.mem.eql(u8, zkey, key) and z.meta.comp.len == snapshot.comp_hex_len) {
				const src = ctx.parent_env.get("COGBOX_FLAKE_SOURCE").?;
				if (!plugin.tryWriteRunnerRecord(ctx, src, runner, z.meta.comp)) return error.RunnerRecordWriteFailed;
				plugin.clearPrevLock(ctx);
				plugin.clearRepinFailed(ctx);
				return .target;
			}
		}
	}
	try removeRunnerChecked(arena, ctx);
	return .removed;
}

/// removeRunnerRecord, but a runner.path that cannot be removed is an error.
fn removeRunnerChecked(arena: std.mem.Allocator, ctx: *const plugin.Ctx) !void {
	const icd = icdOf(ctx) orelse return error.NoInstanceDir;
	try deleteIfExists(ctx.io, try std.fs.path.join(arena, &.{ icd, "runner.path" }));
	// The launcher's snapshot marker and the repin verdict vouch for the record
	// just removed.
	plugin.removeRunnerRecord(ctx);
}

/// (e): in rules mode, render the saved policy into the running instance
/// (gated as the mutation verbs gate it). Best-effort once config.save has
/// committed: it renders from config.json, so a later rules op, a retry after a
/// crash, or the next boot still narrows live egress.
fn reloadPolicy(arena: std.mem.Allocator, ctx: *const plugin.Ctx, loaded: *config.Loaded, notes: *Notes) Reload {
	_ = loaded.network() catch return .skipped;
	_ = rules_module.reloadLive(arena, ctx.io, ctx.runtime_path, loaded) catch |err| {
		notes.add("rollback: could not reload the restored network policy ({s}); it takes effect at the next rules change or boot", .{@errorName(err)});
		return .failed;
	};
	return .reloaded;
}

// --- fail-closed tier ------------------------------------------------------------

/// The fail-closed tier: for every `removed` and `restored` name, remove the
/// entry, its tagged allows and injections (a removed name's denies too) and its
/// source, save, regenerate flake.nix, drop those names' root inputs from
/// flake.lock (an unparseable lock is unlinked: the re-exec then locks in memory,
/// and its path: inputs need no network), remove runner.path, unlink built, and
/// reload as in (e). `reinserted` names stay deleted: when the normal tier's
/// (a) and (b) already put one back before (c) or (d) failed, its entry, source
/// and root input go again; its tagged policy stays as (b) left it (C's own
/// entries, and Z's denies, which only narrow). Pure file operations.
fn failClosed(
	arena: std.mem.Allocator,
	ctx: *const plugin.Ctx,
	icd: []const u8,
	icd_dir: std.Io.Dir,
	apply: std.Io.Dir,
	intent: Intent,
	z: ?*const snapshot.Snapshot,
	hooks: Hooks,
	deadline: *const snapshot.Deadline,
	ex: *Exec,
	notes: *Notes,
) !void {
	const io = ctx.io;
	if (hooks.fail_closed_fails) return error.InjectedFailure;
	var loaded = try config.load(arena, io, ctx.config_path);
	defer loaded.deinit();
	ex.policy_not_restored = if (z) |zs| countNotRestored(&loaded, intent.scope, zs) else 0;
	const plugins_arr = try mutate.pluginsArray(loaded.root(), loaded.treeAllocator());
	const net_opt: ?*std.json.Value = loaded.network() catch null;
	for (intent.scope) |e| {
		var i: usize = 0;
		while (i < plugins_arr.items.len) {
			const p = plugins_arr.items[i];
			if (p == .object and mutate.entryField(p.object, "name") != null and std.mem.eql(u8, mutate.entryField(p.object, "name").?, e.name)) {
				_ = plugins_arr.orderedRemove(i);
				continue;
			}
			i += 1;
		}
		if (e.action == .reinserted) continue;
		if (net_opt) |net| dropTagged(net, e.name, if (e.action == .removed) .everything else .keep_denies);
	}
	try config.save(arena, io, ctx.config_path, loaded.root().*);

	for (intent.scope) |e| removeSource(arena, ctx, icd_dir, apply, e.name, deadline, notes);
	try plugin.regenComposition(ctx, plugins_arr);
	try dropLockInputs(arena, ctx, intent.scope);
	try removeRunnerChecked(arena, ctx);
	try snapshot.clearRole(io, icd, .built);
	ex.runner_record = .removed;
	ex.reload = reloadPolicy(arena, ctx, &loaded, notes);
}

/// Remove plugin-sources/<name>: an O(1) rename into the trash, else a bounded
/// removal. A source left behind is only garbage (its entry is gone), so this
/// warns and never fails the tier.
fn removeSource(arena: std.mem.Allocator, ctx: *const plugin.Ctx, icd_dir: std.Io.Dir, apply: std.Io.Dir, name: []const u8, deadline: *const snapshot.Deadline, notes: *Notes) void {
	const io = ctx.io;
	var src = icd_dir.openDir(io, std.fs.path.basename(ctx.sources_dir), .{ .follow_symlinks = false }) catch return;
	defer src.close(io);
	snapshot.ensureDir(io, apply, "trash", ctx.real_uid) catch {};
	var nonce: [8]u8 = undefined;
	io.random(&nonce);
	const dst = std.fmt.allocPrint(arena, "trash/src-{s}-{x}", .{ name, &nonce }) catch return;
	src.rename(name, apply, dst, io) catch |err| switch (err) {
		error.FileNotFound => return,
		else => {
			const res = snapshot.removeTree(arena, io, src, name, @max(deadline.leftMs(), 1_000));
			switch (res.outcome) {
				.absent, .emptied => {},
				.deadline, .failed => notes.add("rollback: could not remove the source of plugin '{s}'; it is no longer installed, the directory is only left behind", .{name}),
			}
		},
	};
}

/// Drop the scope's root inputs (`p-<name>`; a reinserted name has one only
/// when (c) restored the target's lock) from plugins-flake/flake.lock, and the
/// lock nodes nothing reaches any more; a lock that does not parse (or cannot
/// be rewritten) is unlinked instead.
fn dropLockInputs(arena: std.mem.Allocator, ctx: *const plugin.Ctx, scope: []const snapshot.ScopeEntry) !void {
	const io = ctx.io;
	const lock_path = try std.fs.path.join(arena, &.{ ctx.plugins_flake_dir, "flake.lock" });
	const bytes = std.Io.Dir.cwd().readFileAlloc(io, lock_path, arena, .limited(snapshot.max_flake_bytes)) catch |err| switch (err) {
		error.FileNotFound => return,
		else => return deleteIfExists(io, lock_path),
	};
	var drop: std.ArrayList([]const u8) = .empty;
	for (scope) |e| try drop.append(arena, try std.fmt.allocPrint(arena, "p-{s}", .{e.name}));
	if (editLock(arena, bytes, drop.items)) |edited| {
		if (plugin.writeFileAtomic(ctx, lock_path, edited)) return;
	} else |_| {}
	try deleteIfExists(io, lock_path);
}

/// `lock_json` without the root inputs `inputs` and without the nodes no longer
/// reachable from the root. error.InvalidLock for anything not shaped like a
/// flake.lock.
pub fn editLock(arena: std.mem.Allocator, lock_json: []const u8, inputs: []const []const u8) ![]u8 {
	var v = std.json.parseFromSliceLeaky(std.json.Value, arena, lock_json, .{}) catch return error.InvalidLock;
	if (v != .object) return error.InvalidLock;
	const nodes = objectPtr(v.object.getPtr("nodes")) orelse return error.InvalidLock;
	const root_key = if (v.object.get("root")) |rk| (if (rk == .string) rk.string else return error.InvalidLock) else "root";
	const root = objectPtr(nodes.object.getPtr(root_key)) orelse return error.InvalidLock;
	if (objectPtr(root.object.getPtr("inputs"))) |root_inputs| {
		for (inputs) |name| _ = root_inputs.object.orderedRemove(name);
	}
	// Reachability from the root: an input naming a node key is an edge; a
	// `follows` input (an array path) is not.
	var reach: std.StringHashMapUnmanaged(void) = .empty;
	var queue: std.ArrayList([]const u8) = .empty;
	try queue.append(arena, root_key);
	while (queue.pop()) |k| {
		if ((try reach.getOrPut(arena, k)).found_existing) continue;
		const node = nodes.object.getPtr(k) orelse continue;
		const node_inputs = objectPtr(objectPtrGet(node, "inputs")) orelse continue;
		var it = node_inputs.object.iterator();
		while (it.next()) |e| if (e.value_ptr.* == .string) try queue.append(arena, e.value_ptr.string);
	}
	var dead: std.ArrayList([]const u8) = .empty;
	var it = nodes.object.iterator();
	while (it.next()) |e| if (!reach.contains(e.key_ptr.*)) try dead.append(arena, e.key_ptr.*);
	for (dead.items) |k| _ = nodes.object.orderedRemove(k);
	var aw: std.Io.Writer.Allocating = .init(arena);
	std.json.Stringify.value(v, .{ .whitespace = .indent_2 }, &aw.writer) catch return error.OutOfMemory;
	aw.writer.writeByte('\n') catch return error.OutOfMemory;
	return aw.toOwnedSlice();
}

/// `v` when it is an object.
fn objectPtr(v: ?*std.json.Value) ?*std.json.Value {
	const p = v orelse return null;
	if (p.* != .object) return null;
	return p;
}

// --- abandon -------------------------------------------------------------------------

pub const AbandonResult = struct {
	/// The intent files moved to apply/abandoned/ (their original names).
	moved: []const []const u8 = &.{},
	warnings: []const []const u8 = &.{},
};

/// `cogbox plugin apply --abandon-rollback`'s work, under the config lock the
/// caller holds (after its TTY confirmation or -y): take the apply flock on
/// `apply_lock` with LOCK_NB and refuse with error.ApplyBusy while anyone holds
/// it -- an apply or a plugin change may have just written the intent it is
/// still acting on -- then move every intent, unparseable ones included, to
/// apply/abandoned/<name>.<nonce> and audit each move (best-effort). The config
/// then boots as it is. writeIntent created apply/abandoned/ before the intent,
/// so on the full disk that left the intent pending the move is only renames;
/// on a read-only disk nothing can move. Pass an fd opened for this call
/// (config_lock.openLockFile with ".apply.lock"); the lock is held until the
/// caller closes it.
pub fn abandon(arena: std.mem.Allocator, io: std.Io, icd: []const u8, apply_lock: std.posix.fd_t, owner: ?u32) !AbandonResult {
	while (std.c.flock(apply_lock, std.posix.LOCK.EX | std.posix.LOCK.NB) != 0) {
		const e = std.c._errno().*;
		if (e == @intFromEnum(std.posix.E.INTR)) continue;
		if (e == @intFromEnum(std.posix.E.AGAIN)) return error.ApplyBusy;
		return error.CannotLock;
	}
	var icd_dir = try snapshot.openIcd(io, icd);
	defer icd_dir.close(io);
	var apply = icd_dir.openDir(io, "apply", .{ .follow_symlinks = false }) catch |err| switch (err) {
		error.FileNotFound => return .{},
		else => return err,
	};
	defer apply.close(io);
	var rb = apply.openDir(io, rollback_dir, .{ .follow_symlinks = false, .iterate = true }) catch |err| switch (err) {
		error.FileNotFound => return .{},
		else => return err,
	};
	defer rb.close(io);
	const listing = try listRollbackDir(arena, io, rb);
	if (listing.intents.len == 0) return .{};
	try snapshot.ensureDir(io, apply, abandoned_dir, owner);
	var moved: std.ArrayList([]const u8) = .empty;
	var notes: Notes = .{ .arena = arena };
	for (listing.intents) |name| {
		var nonce: [8]u8 = undefined;
		io.random(&nonce);
		const dst = try std.fmt.allocPrint(arena, abandoned_dir ++ "/{s}.{x}", .{ name, &nonce });
		try rb.rename(name, apply, dst, io);
		try moved.append(arena, name);
		const line = try jsonLine(arena, .{
			.event = "abandon",
			.at = std.Io.Timestamp.now(io, .real).toSeconds(),
			.intent = name,
			.moved_to = dst,
		});
		appendAudit(arena, io, apply, line, owner, &notes);
	}
	syncDir(rb);
	return .{ .moved = moved.items, .warnings = notes.items.items };
}
