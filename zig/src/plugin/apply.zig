// Live plugin apply: the host half of `cogbox plugin apply` (spec sections 2, 3
// and 6):
//   - preflight (spec 2 step 2): the apply flock, apply/active, pending work,
//     the identity of what the guest runs, the refusal checks, the user-flake
//     check, the scratch snapshot S and the rollback scopes;
//   - the build (step 3): a two-stage, bounded and contained build of the
//     runner the next boot would build from S's composition, with the
//     positive-evidence eval_error classifier;
//   - tier 1 (step 4, gateBootShape) and tier 2 (step 5): the guest's
//     `settled` and `plan` hops, the guest data merged into the host unit plan
//     (unitplan.zig), the propagation closure and the verdict;
//   - the guest phase (steps 6-8, runGuestPhase): the flip to `phase: guest`,
//     apply/inflight.json, the `start` hop, the long-poll to a terminal state
//     with the hop-evidence rule, the early verdict and its rollback intent,
//     and the confirm on a fresh, unmultiplexed connection;
//   - the record (step 10): the confirmed record (B := S, live-runner,
//     runner.path), K := S, and every rollback through rollback.zig; the report
//     (step 11); and the companions --status, --cancel, --log and
//     --abandon-rollback (step 12);
//   - the recovery of an orphaned inflight.json (spec 4.6, "Interrupted
//     applies", recoverInflight), with the recoverers' own hop evidence.
//
// Every leg is bounded (spec section 2, "Bounds"), and every child process
// (nix, ssh, systemd-run, systemctl) is forked by this verb from its main
// thread with PR_SET_PDEATHSIG=SIGKILL, stays in its process group and is
// waited for through a pidfd in a loop that sees the terminate and supersede
// flags within 250 ms (runChild). Nothing here runs under coreutils `timeout`
// or std.process.run.
//
// Output: one JSON line on stdout with --json (written to apply/last.json
// first), else a human line. Every value is an enumerated token, a host-derived
// store path or snapshot id, or a unit name that exists as a unit file in T or
// P; no guest free text reaches the report.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const linux = std.os.linux;
const plugin = @import("main.zig");
const cli = @import("cli.zig");
const nix = @import("nix.zig");
const snapshot = @import("snapshot.zig");
const rollback = @import("rollback.zig");
const unitplan = @import("unitplan.zig");
const sshargv = @import("sshargv");
const rules_module = @import("rules_module");
const config = rules_module.config;

const is_linux = builtin.os.tag == .linux;

// --- bounds ------------------------------------------------------------------------

/// The legs' bounds (spec section 2, "Bounds"). The tunable ones read their
/// environment variable per run (envSeconds/envMb).
pub const Bounds = struct {
	/// The dispatcher's config-lock wait: `apply`, then `--status`/`--cancel`.
	pub const dispatcher_lock_ms: i64 = 300_000;
	pub const status_lock_ms: i64 = 15_000;
	/// Step 10's timed retake of the config lock.
	pub const record_lock_ms: i64 = 300_000;
	/// apply/active deadlines: preflight (recovery 115 + finish 240 + user
	/// flake 30 + snapshot and checks 60), and the record phase after an
	/// eval_error (step-10 lock 300 + rollback 240).
	pub const preflight_s: i64 = 445;
	pub const record_s: i64 = 540;
	pub const user_flake_ms: i64 = 30_000;
	pub const snapshot_ms: i64 = 20_000;
	/// COGBOX_APPLY_BUILD_TIMEOUT: instantiate, reproduction and realise share it.
	pub const build_s: i64 = 1800;
	/// COGBOX_APPLY_TIMEOUT, from process start (5335 s of legs, spec "whole verb").
	pub const whole_s: i64 = 5340;
	pub const trash_ms: i64 = 30_000;
	/// The instance watch during the build and the guest hops.
	pub const watch_ms: i64 = 10_000;
	/// Every guest hop's wall-clock kill; `plan` gets longer (its dry-activate).
	pub const hop_ms: i64 = 45_000;
	pub const plan_hop_ms: i64 = 90_000;
	/// The `plan` reply's cap. The helper lists every loaded unit's state and
	/// runtime reverse edges uncapped (a real guest's reply is tens of KiB); a
	/// reply past this fails the hop, and the apply ends failed/plan.
	pub const plan_reply_cap: usize = 8 << 20;
	/// The settled-boot wait, and the busy predecessor's abort-and-wait.
	pub const settled_ms: i64 = 180_000;
	pub const busy_wait_ms: i64 = 420_000;
	/// One systemctl call (show, stop).
	pub const systemctl_ms: i64 = 10_000;
	/// A stopper's wait, after its stop of a build unit was queued, for the
	/// unit to end (polled every child_poll_ms).
	pub const stop_settle_ms: i64 = 10_000;
	/// The child-wait loop's poll slice: a flag is seen within it.
	pub const child_poll_ms: i32 = 250;
	/// Signalling a holder: SIGTERM, wait, then (with the config lock) SIGKILL.
	pub const term_wait_ms: i64 = 30_000;
	pub const kill_wait_ms: i64 = 10_000;
	/// COGBOX_APPLY_MIN_AVAILABLE_MB, COGBOX_APPLY_MIN_FREE_MB.
	pub const min_available_mb: u64 = 2048;
	pub const min_free_mb: u64 = 64;
	/// The build unit's MemoryMax is MemAvailable minus this.
	pub const memory_headroom: u64 = 512 << 20;
	/// <G>.build.log's cap, and what `apply --log` prints of it.
	pub const build_log_cap: usize = 64 << 10;
	pub const log_print_cap: usize = 32 << 10;
	/// Build logs kept in apply/ (the oldest go when an apply starts).
	pub const build_logs_kept: usize = 16;
	/// The guest phase (spec section 2 steps 6-8): the apply unit's bound S,
	/// the dead-man window W = S + 120, the start leg, and the poll's margin
	/// past W (the poll runs W + 390 = 1350 s).
	pub const apply_unit_s: i64 = 840;
	pub const window_s: i64 = 960;
	pub const start_leg_ms: i64 = 45_000;
	pub const poll_margin_s: i64 = 390;
	/// apply/active's guest-phase deadline past W: start 45 + poll margin 390
	/// + confirm 45 + step-10 lock 300 + record or rollback 240.
	pub const guest_extra_s: i64 = 1020;
	/// SIGINT's or SIGHUP's one `abort` hop.
	pub const abort_hop_ms: i64 = 15_000;
	/// A recoverer's `abort` and its wait for a recorded verdict.
	pub const recover_abort_ms: i64 = 60_000;
	/// `cogbox stop`'s one `status` hop (never counts toward rfails).
	pub const stop_hop_ms: i64 = 3_000;
	/// Failed hops in a row that are evidence of a lost guest; while the
	/// streak is at least this, only `status` polls are sent.
	pub const streak_evidence: u32 = 3;
	/// <G>.guest.log's cap.
	pub const guest_log_cap: usize = 64 << 10;
	/// The apply gate of a plugin change (spec 4.8): it re-reads apply/active
	/// this often, waits at most this long after superseding a build-phase
	/// apply, reprints its waiting line this often, and caps its whole wait
	/// behind an apply at COGBOX_APPLY_WAIT_MAX (the control plane is to pass
	/// 90 s once it drives live apply).
	pub const gate_poll_ms: i64 = 1_000;
	pub const supersede_wait_ms: i64 = 60_000;
	pub const gate_reprint_ms: i64 = 60_000;
	pub const wait_max_s: i64 = 1200;
	/// `cogbox stop`'s apply step: SIGTERM to the holder and this grace (no
	/// SIGKILL), then at most one `status` hop under stop_hop_ms: 5 s in all.
	pub const stop_term_ms: i64 = 2_000;
	/// Apply anyway (spec 4.7): a stored plan is valid this long (CLOCK_BOOTTIME
	/// seconds from its store), and apply/plans/ keeps at most this many (and
	/// the one a run's --force-plan names); the interactive form runs at most
	/// this many forced applies, however many of them answered plan_changed
	/// or plan_expired, and asks about no plan after the last.
	pub const plan_ttl_s: i64 = 1800;
	pub const plans_kept: usize = 16;
	pub const force_rounds: u32 = 3;
	/// The guest helper's limits on `start --force-units -` (its `head -c
	/// 65536` and 1..256 names): a plan whose force list exceeds them is never
	/// offered.
	pub const force_units_max: usize = 256;
	pub const force_input_cap: usize = 65536;
	/// A stored plan file's read cap.
	pub const plan_file_cap: usize = 4 << 20;
};

// --- outcome vocabulary -------------------------------------------------------------

pub const Result = enum {
	applied,
	applied_with_failures,
	already_live,
	restart_required,
	rejected,
	undone,
	failed,
	superseded,
	unknown,
	not_running,
};

/// Every `reason` token (spec section 3, "Overridable versus never-overridable",
/// and the outcome table). The report carries exactly one.
pub const Reason = enum {
	// restart_required, tier 1 (never overridable)
	base_changed,
	boot_shape,
	kernel_modules,
	fstab,
	init_interface,
	no_boot_record,
	customized_flake,
	unsupported_platform,
	// restart_required, preflight
	booting,
	air_gapped,
	insufficient_memory,
	insufficient_disk,
	no_containment,
	disabled,
	user_flake_changed,
	composition_stale,
	plan_expired,
	plan_changed,
	// restart_required, guest state
	foreign_system,
	store_fallback,
	guest_tainted,
	no_helper,
	// restart_required, the plan
	restart_only_units,
	skipped_units,
	pre_switch_check,
	// restart_required, overridable with Apply anyway
	disruptive_units,
	network_config,
	systemd_reexec,
	// failed
	busy,
	snapshot,
	build,
	build_timeout,
	inputs_changed,
	build_inputs_uncached,
	plan,
	switch_locked,
	timeout,
	/// The guest refused G as a no-op for a reason with no token of its own
	/// (detail: the guest's refusal token, or `start_error`, `not_started`):
	/// nothing changed in the guest.
	guest_refused,
	// rejected (rolled back)
	breaks_base,
	activation_failed,
	activation_hang,
	unit_hang,
	@"unreachable",
	eval_error,
	// undone (the commit is kept)
	aborted,
	stop_hang,
	switch_timeout,
	unplanned_disruption,
	forced_unit_failed,
	host_lost,
	/// The switch exited with a code that is none of 0, 2 or 4 after the
	/// activation began (detail: `exit_<n>`), and the guest was reverted: not
	/// proven to break the base, so the commit is kept.
	switch_failed,

	/// Only class B, C and D plans can be forced (spec 4.7).
	pub fn overridable(r: Reason) bool {
		return switch (r) {
			.disruptive_units, .network_config, .systemd_reexec => true,
			else => false,
		};
	}

	/// For a restart_required outcome after a build: whether R is recorded for
	/// the next boot (spec section 3, outcome table, the exclusion list).
	pub fn recordsRunner(r: Reason) bool {
		return switch (r) {
			.base_changed, .no_boot_record, .foreign_system, .unsupported_platform, .air_gapped, .insufficient_memory, .insufficient_disk, .booting, .no_containment, .disabled, .user_flake_changed, .composition_stale, .plan_expired, .plan_changed => false,
			else => true,
		};
	}

	pub fn fromPlan(r: unitplan.Reason) Reason {
		return switch (r) {
			.restart_only_units => .restart_only_units,
			.skipped_units => .skipped_units,
			.disruptive_units => .disruptive_units,
			.network_config => .network_config,
			.systemd_reexec => .systemd_reexec,
		};
	}

	pub fn fromBootShape(r: unitplan.BootShapeReason) Reason {
		return switch (r) {
			.boot_shape => .boot_shape,
			.kernel_modules => .kernel_modules,
			.fstab => .fstab,
			.init_interface => .init_interface,
		};
	}

	pub fn fromRollback(r: rollback.Reason) Reason {
		return switch (r) {
			.breaks_base => .breaks_base,
			.activation_failed => .activation_failed,
			.activation_hang => .activation_hang,
			.unit_hang => .unit_hang,
			.@"unreachable" => .@"unreachable",
			.eval_error => .eval_error,
		};
	}
};

/// How the build is contained (spec section 2 step 3): `unit`, a transient
/// systemd system unit with RuntimeMaxSec, MemoryMax and OOMScoreAdjust; `none`,
/// a daemon client whose builds run in the nix daemon and which is bounded by
/// its own death signal and the daemon's hangup handling.
pub const Cap = enum { unit, none };

/// The phase apply/active advertises to a plugin change waiting at the gate.
pub const Phase = enum { preflight, build, guest, record };

/// What an Apply anyway run forced (spec 4.7): the confirmed plan's id and the
/// unit names sent to the guest's `start --force-units -` (forceUnits: sorted,
/// unique, the units the plan only reloads and the repair unit excluded; empty
/// for a plan that relaxes no unit, one that only reloads units or
/// re-executes systemd, so empty never means a re-exec). The report carries it
/// once a forced `start` was attempted, with or without the list, and so does
/// inflight.json.
pub const Forced = struct { plan: []const u8, units: []const []const u8 };

pub const RollbackStatus = enum { done, removed, pending };

/// The report's `rollback` object: rollback.Report with a `pending` status for
/// an intent that stays (the target is known from the intent either way).
pub const RollbackOut = struct {
	status: RollbackStatus,
	target: rollback.Target,
	target_id: []const u8,
	names: []const rollback.RecordName = &.{},
	policy_not_restored: u64 = 0,
	runner_record: ?rollback.RunnerRecord = null,
	seq: ?u64 = null,

	pub fn fromReport(r: rollback.Report) RollbackOut {
		return .{
			.status = switch (r.status) {
				.done => .done,
				.removed => .removed,
			},
			.target = r.target,
			.target_id = r.target_id,
			.names = r.names,
			.policy_not_restored = r.policy_not_restored,
			.runner_record = r.runner_record,
			.seq = r.seq,
		};
	}
};

/// One unit of a host-derived plan (spec 4.7): its action, why it is in the
/// plan (`changed`, `removed`, `new`, `induced`, `guest_reported`, or
/// `propagated:<edge>:<from>`), and its deny-list class.
pub const PlanUnit = struct {
	unit: []const u8,
	action: unitplan.Action,
	why: []const u8,
	class: []const u8,
};

/// The plan of an overridable (or mixed) refusal. `id` is the first 16 hex of
/// sha256 over the canonical JSON of everything but itself (planId).
pub const Plan = struct {
	id: []const u8,
	boot_id: []const u8,
	comp: []const u8,
	P: []const u8,
	T: []const u8,
	units: []const PlanUnit,
	repair: []const []const u8,
	reexec: bool,
};

/// What one run decided, before it is reported.
pub const Outcome = struct {
	result: Result,
	reason: ?Reason = null,
	detail: []const []const u8 = &.{},
	plan: ?Plan = null,
	rollback: ?RollbackOut = null,
	units: ?[]const []const u8 = null,
	rolled_back_guest: ?bool = null,
	/// The guest phase's terminate path (spec 4.8): exit at once with this
	/// code, leaving apply/inflight.json for a recoverer. No record and no
	/// report; `result` is meaningless then.
	exit_now: ?u8 = null,

	pub fn of(result: Result, reason: ?Reason) Outcome {
		return .{ .result = result, .reason = reason };
	}

	pub fn with(result: Result, reason: ?Reason, detail: []const []const u8) Outcome {
		return .{ .result = result, .reason = reason, .detail = detail };
	}

	/// Apply anyway is offered: an overridable reason with a plan to force. A
	/// plan that could not be stored (or whose force list the guest would
	/// refuse, buildPlan) is not offered.
	pub fn overridable(o: Outcome) bool {
		return o.result == .restart_required and o.reason != null and o.reason.?.overridable() and o.plan != null;
	}
};

/// The report line: `{"apply":{...}}`, every key always present (null when it
/// does not apply), in the spec's order.
pub const Report = struct {
	gen: ?[]const u8,
	op: ?[]const u8,
	result: Result,
	reason: ?Reason,
	detail: ?[]const []const u8,
	overridable: bool,
	plan: ?Plan,
	forced: ?Forced,
	rollback: ?RollbackOut,
	runner: ?[]const u8,
	toplevel: ?[]const u8,
	units: ?[]const []const u8,
	rolled_back_guest: ?bool,
	cap: ?Cap,
	base_id: ?[]const u8,
	built_id: ?[]const u8,
};

/// `{"apply":<report>}` and its newline.
pub fn reportLine(arena: Allocator, rep: Report) Allocator.Error![]u8 {
	var aw: Io.Writer.Allocating = .init(arena);
	std.json.Stringify.value(.{ .apply = rep }, .{}, &aw.writer) catch return error.OutOfMemory;
	aw.writer.writeByte('\n') catch return error.OutOfMemory;
	return aw.toOwnedSlice();
}

// --- the terminate and supersede flags ------------------------------------------------

/// Set by the TERM, INT and HUP handlers (the signal number) and by the USR1
/// handler; the handlers only store. The main flow acts on them at its
/// checkpoints and in the child-wait loop.
pub var terminate: std.atomic.Value(u8) = .init(0);
pub var supersede: std.atomic.Value(u8) = .init(0);

fn onTerminate(sig: std.posix.SIG) callconv(.c) void {
	terminate.store(@truncate(@intFromEnum(sig)), .release);
}

fn onSupersede(_: std.posix.SIG) callconv(.c) void {
	supersede.store(1, .release);
}

/// Install the verb's handlers (without SA_RESTART, so a blocked wait returns
/// EINTR) and ignore SIGPIPE: a lost reader never aborts the verb mid-flow.
/// Called by the CLI before it waits for the config lock.
pub fn installSignals() void {
	var act: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
	act.handler.handler = onTerminate;
	std.posix.sigaction(std.posix.SIG.TERM, &act, null);
	std.posix.sigaction(std.posix.SIG.INT, &act, null);
	std.posix.sigaction(std.posix.SIG.HUP, &act, null);
	act.handler.handler = onSupersede;
	std.posix.sigaction(std.posix.SIG.USR1, &act, null);
	ignoreSigpipe();
}

pub fn ignoreSigpipe() void {
	var act: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
	act.handler.handler = std.posix.SIG.IGN;
	std.posix.sigaction(std.posix.SIG.PIPE, &act, null);
}

// --- the host's handoff ------------------------------------------------------------------

/// What the CLI hands the apply subcommands besides the plugin Ctx.
pub const Host = struct {
	/// The config lock's descriptor and whether it is held (the dispatcher's
	/// timed acquire may have run out); -1 when none was opened.
	config_fd: std.posix.fd_t = -1,
	config_held: bool = false,
	/// The apply flock's descriptor (opened, never locked by the CLI).
	apply_fd: std.posix.fd_t = -1,
	/// cogbox's own ssh key (`<data>/cogbox_ed25519`), when it exists.
	ssh_identity: ?[]const u8 = null,
	/// When the process started (the whole-verb timer runs from here).
	started: ?Io.Timestamp = null,
	/// The invoking user under sudo: new apply state is handed to it.
	real_uid: ?u32 = null,
	/// A mutating plugin verb passed the apply gate: the CLI holds the apply
	/// flock on `apply_fd` (and the config lock on `config_fd`) for the whole
	/// verb, so its recovery, its rollback finish and an inline apply run under
	/// both (spec 4.8).
	gate_held: bool = false,
	/// Where the report goes instead of stdout (tests: the test runner owns
	/// stdout). Null: stdout.
	sink: ?*std.ArrayList(u8) = null,
	sink_allocator: ?Allocator = null,
	/// Where report() also hands the Report it built (forceLoop reads the
	/// plan to ask about from it). Null: nowhere.
	report_out: ?*?Report = null,

	/// Write `bytes` to the sink, else stdout (never fatal).
	pub fn emit(h: Host, io: Io, bytes: []const u8) void {
		if (h.sink) |sk| {
			sk.appendSlice(h.sink_allocator.?, bytes) catch {};
			return;
		}
		out(io, bytes);
	}
};

// --- small helpers ------------------------------------------------------------------------

fn nowMs(io: Io) i64 {
	return Io.Timestamp.now(io, .awake).toMilliseconds();
}

/// CLOCK_BOOTTIME seconds: apply/active's deadline (and, later, inflight.json's
/// expires_at), compared across processes and immune to wall-clock steps.
pub fn bootSeconds(io: Io) i64 {
	return Io.Timestamp.now(io, .boot).toSeconds();
}

fn envSeconds(env: *const std.process.Environ.Map, key: []const u8, default: i64) i64 {
	const v = env.get(key) orelse return default;
	const n = std.fmt.parseInt(i64, std.mem.trim(u8, v, " \t"), 10) catch return default;
	return if (n > 0) n else default;
}

fn envMb(env: *const std.process.Environ.Map, key: []const u8, default: u64) u64 {
	const v = env.get(key) orelse return default;
	return std.fmt.parseInt(u64, std.mem.trim(u8, v, " \t"), 10) catch default;
}

/// Read a small file whole. A streaming reader, because procfs (/proc/meminfo,
/// /proc/<pid>/stat, the boot id) reports size zero despite its data, and the
/// positional reader under readFileAlloc then reads nothing (as stop.zig's
/// readSmall notes).
fn readSmall(arena: Allocator, io: Io, path: []const u8, limit: usize) ![]u8 {
	const file = try Io.Dir.cwd().openFile(io, path, .{});
	defer file.close(io);
	var buf: [512]u8 = undefined;
	var reader = file.readerStreaming(io, &buf);
	return reader.interface.allocRemaining(arena, .limited(limit));
}

fn pathExists(io: Io, path: []const u8) bool {
	Io.Dir.cwd().access(io, path, .{}) catch return false;
	return true;
}

/// A streaming writer: it writes at the descriptor's own offset. The default
/// positional one starts every new writer at offset 0, so with stdout a file
/// (`apply --force > out`, which reports once per round) each write would
/// overwrite the one before.
fn writeAllTo(io: Io, file: Io.File, bytes: []const u8) void {
	var buf: [4096]u8 = undefined;
	var w = file.writerStreaming(io, &buf);
	w.interface.writeAll(bytes) catch return;
	w.flush() catch {};
}

/// stdout and stderr writes are never fatal (a closed reader must not abort the
/// verb, spec section 2 step 11).
fn out(io: Io, bytes: []const u8) void {
	writeAllTo(io, Io.File.stdout(), bytes);
}

fn errOut(io: Io, bytes: []const u8) void {
	_ = errOutChecked(io, bytes);
}

/// errOut that says whether every byte was written: forceLoop never asks about
/// a plan the person could not have read.
fn errOutChecked(io: Io, bytes: []const u8) bool {
	if (stderr_sink) |sk| {
		sk.appendSlice(stderr_sink_allocator.?, bytes) catch return false;
		if (stderr_sink_hook) |h| h(bytes);
		return true;
	}
	var buf: [4096]u8 = undefined;
	var w = Io.File.stderr().writerStreaming(io, &buf);
	w.interface.writeAll(bytes) catch return false;
	w.flush() catch return false;
	return true;
}

/// Tests only: where the verb's diagnostics go instead of stderr (the zig test
/// runner reports a test binary's stderr output as a failed command), and what
/// sees each write once it is there (a terminal's reader, who answers a
/// question once it is shown).
pub var stderr_sink: ?*std.ArrayList(u8) = null;
pub var stderr_sink_allocator: ?Allocator = null;
pub var stderr_sink_hook: ?*const fn ([]const u8) void = null;

/// The durable writes a classification makes, in the order they land, and
/// every apply/active write (setActiveStrict).
pub const DurableWrite = enum { intent, hops, active };
/// Tests only: told of each, after it landed.
pub var durable_write_hook: ?*const fn (DurableWrite) void = null;

fn noteDurable(w: DurableWrite) void {
	if (durable_write_hook) |h| h(w);
}

fn warnf(arena: Allocator, io: Io, comptime fmt: []const u8, args: anytype) void {
	const msg = std.fmt.allocPrint(arena, "cogbox plugin: warning: " ++ fmt ++ "\n", args) catch return;
	errOut(io, msg);
}

fn errorf(arena: Allocator, io: Io, comptime fmt: []const u8, args: anytype) void {
	const msg = std.fmt.allocPrint(arena, "cogbox plugin: error: " ++ fmt ++ "\n", args) catch return;
	errOut(io, msg);
}

fn isStorePath(s: []const u8) bool {
	const prefix = "/nix/store/";
	if (!std.mem.startsWith(u8, s, prefix)) return false;
	const rest = s[prefix.len..];
	if (rest.len < 34 or rest[32] != '-') return false;
	for (rest[0..32]) |c| switch (c) {
		'0'...'9', 'a'...'z' => {},
		else => return false,
	};
	for (rest[33..]) |c| switch (c) {
		'A'...'Z', 'a'...'z', '0'...'9', '+', '-', '.', '_', '?', '=' => {},
		else => return false,
	};
	return true;
}

fn isBootId(s: []const u8) bool {
	if (s.len != 36) return false;
	for (s, 0..) |c, i| {
		if (i == 8 or i == 13 or i == 18 or i == 23) {
			if (c != '-') return false;
			continue;
		}
		switch (c) {
			'0'...'9', 'a'...'f' => {},
			else => return false,
		}
	}
	return true;
}

/// A unit name as the helper's charset check passes it (systemd's escaping
/// keeps names to this set). Names are then intersected with T's and P's unit
/// files before any use.
pub fn isUnitToken(s: []const u8) bool {
	if (s.len == 0 or s.len > 260) return false;
	const dot = std.mem.lastIndexOfScalar(u8, s, '.') orelse return false;
	if (dot == 0 or dot > 250) return false;
	const sfx = s[dot + 1 ..];
	if (sfx.len < 3 or sfx.len > 9) return false;
	for (sfx) |c| if (c < 'a' or c > 'z') return false;
	for (s[0..dot]) |c| switch (c) {
		'A'...'Z', 'a'...'z', '0'...'9', '-', ':', '_', '.', '@', '\\' => {},
		else => return false,
	};
	return true;
}

/// `/proc/<pid>/stat`'s starttime (field 22); null for a zombie, a dead pid or
/// an unreadable entry. Fields follow the LAST ") " (comm may hold either).
pub fn procStarttime(arena: Allocator, io: Io, pid: i32) ?u64 {
	const path = std.fmt.allocPrint(arena, "/proc/{d}/stat", .{pid}) catch return null;
	const data = readSmall(arena, io, path, 4096) catch return null;
	return parseStarttime(data);
}

pub fn parseStarttime(data: []const u8) ?u64 {
	const end = std.mem.lastIndexOf(u8, data, ") ") orelse return null;
	var words = std.mem.tokenizeScalar(u8, data[end + 2 ..], ' ');
	const state = words.next() orelse return null;
	if (std.mem.eql(u8, state, "Z") or std.mem.eql(u8, state, "X")) return null;
	var i: usize = 1;
	while (i < 19) : (i += 1) _ = words.next() orelse return null;
	return std.fmt.parseInt(u64, words.next() orelse return null, 10) catch null;
}

// --- child processes ---------------------------------------------------------------------

/// How a child ended.
pub const ChildExit = union(enum) {
	exited: u8,
	signaled: u32,
};

/// Why the wait loop stopped a child before it ended on its own.
pub const Stop = enum {
	/// The hop's or the build's bound (or the whole-verb timer: the caller
	/// tells them apart).
	deadline,
	terminate,
	supersede,
	/// The instance stopped or relaunched (the 10 s watch).
	watch,
	/// The output passed its cap and the caller asked to stop on that (a guest
	/// reply is untrusted and capped).
	overflow,
};

/// A bounded capture of one output stream: the first `cap` bytes, and the last
/// `tail_cap` bytes in a ring so the end is kept even past the cap.
pub const Capture = struct {
	cap: usize,
	head: std.ArrayList(u8) = .empty,
	ring: [tail_cap]u8 = undefined,
	total: u64 = 0,

	pub const tail_cap = 4096;

	pub fn add(c: *Capture, arena: Allocator, bytes: []const u8) void {
		const room = c.cap -| c.head.items.len;
		const take = @min(room, bytes.len);
		if (take > 0) c.head.appendSlice(arena, bytes[0..take]) catch {};
		for (bytes) |b| {
			c.ring[@intCast(c.total % tail_cap)] = b;
			c.total += 1;
		}
	}

	pub fn truncated(c: *const Capture) bool {
		return c.total > c.head.items.len;
	}

	pub fn data(c: *const Capture) []const u8 {
		return c.head.items;
	}

	/// The last min(total, tail_cap) bytes, in order.
	pub fn tail(c: *const Capture, arena: Allocator) []const u8 {
		const n: usize = @intCast(@min(c.total, tail_cap));
		const buf = arena.alloc(u8, n) catch return "";
		const start = c.total - n;
		for (0..n) |i| buf[i] = c.ring[@intCast((start + i) % tail_cap)];
		return buf;
	}
};

/// A periodic check the wait loop runs (every Bounds.watch_ms): false stops the
/// child with Stop.watch.
pub const Watch = struct {
	ctx: *anyopaque,
	check: *const fn (*anyopaque) bool,
};

pub const ChildSpec = struct {
	argv: []const []const u8,
	env: *const std.process.Environ.Map,
	/// Absolute monotonic (awake) deadline in ms.
	deadline_ms: i64,
	out_cap: usize = 64 << 10,
	err_cap: usize = 64 << 10,
	/// Stop with Stop.overflow once stdout passes its cap.
	stop_on_overflow: bool = false,
	/// Stop on the supersede flag (only in the build phase).
	honour_supersede: bool = false,
	/// Run on through the terminate flag (the terminate path's own bounded
	/// children: the `abort` hop, the build unit's systemctl calls).
	ignore_terminate: bool = false,
	watch: ?Watch = null,
	watch_ms: i64 = Bounds.watch_ms,
	/// Called with everything captured from stderr so far, after each read
	/// (the build records the unit's InvocationID, a diagnostic, as soon as
	/// systemd-run prints it; stoppers stop the unit by its name).
	on_stderr: ?Hook = null,
	/// The child's stdin: these bytes, then EOF (null: /dev/null). Only the
	/// `start` hop of an Apply anyway run has any (its --force-units -).
	stdin: ?[]const u8 = null,
};

pub const Hook = struct {
	ctx: *anyopaque,
	f: *const fn (*anyopaque, []const u8) void,
};

pub const ChildResult = struct {
	exit: ?ChildExit = null,
	stopped: ?Stop = null,
	/// The child could not be started (no such program, fork failed).
	spawn_error: ?anyerror = null,
	stdout: Capture,
	stderr: Capture,

	pub fn exitedWith(r: *const ChildResult, code: u8) bool {
		if (r.exit) |e| return e == .exited and e.exited == code;
		return false;
	}
};

/// `name` searched in the PATH of `env` (a name with a '/' is taken as is).
pub fn findExe(arena: Allocator, env: *const std.process.Environ.Map, name: []const u8) ?[:0]const u8 {
	if (std.mem.indexOfScalar(u8, name, '/') != null) return arena.dupeZ(u8, name) catch null;
	const path = env.get("PATH") orelse "/run/current-system/sw/bin:/usr/bin:/bin";
	var it = std.mem.splitScalar(u8, path, ':');
	while (it.next()) |dir| {
		if (dir.len == 0) continue;
		const p = std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ dir, name }, 0) catch return null;
		if (std.c.access(p, std.c.X_OK) == 0) return p;
	}
	return null;
}

/// Run a child to completion (or until the loop stops it), capturing its stdout
/// and stderr through pipes into bounded buffers. Its stdin is /dev/null, or
/// `spec.stdin`'s bytes from a memfd filled before the fork (a fresh one per
/// spawn, read from offset 0, so a retried hop sends the whole input again;
/// not a pipe, which would need a writer in the wait loop once the input
/// passes a pipe's capacity).
///
/// The child is forked here, from the calling (main) thread, and makes only raw
/// syscalls between fork and exec: prctl(PR_SET_PDEATHSIG, SIGKILL), getppid
/// (exiting at once if this process already died), SIGPIPE back to its default
/// (this process ignores it; an ignored signal would survive exec), dup2 for
/// its three fds, execve, and _exit if the exec fails. argv, envp and every path
/// are built before the fork, so the child allocates nothing: a worker thread
/// of the I/O runtime may hold the allocator's lock at the moment of the fork,
/// and a child stuck before execve would keep the lock descriptions it
/// inherited. The child stays in this process group, so a group signal reaches
/// it, and its death signal follows this (forking) thread.
///
/// The wait is a pidfd poll of at most Bounds.child_poll_ms that drains the
/// pipes and checks the terminate flag, the supersede flag (when honoured), the
/// deadline and the watch; a stop SIGKILLs the child and reaps it (bounded).
pub fn runChild(arena: Allocator, io: Io, spec: ChildSpec) ChildResult {
	var res: ChildResult = .{ .stdout = .{ .cap = spec.out_cap }, .stderr = .{ .cap = spec.err_cap } };
	if (comptime !is_linux) {
		res.spawn_error = error.Unsupported;
		return res;
	}
	runChildLinux(arena, io, spec, &res) catch |err| {
		res.spawn_error = err;
	};
	return res;
}

fn sysOk(rc: usize) !usize {
	if (linux.errno(rc) != .SUCCESS) return error.SyscallFailed;
	return rc;
}

/// Close every descriptor in `fds` that is still open (>= 0).
fn closeAll(fds: []const i32) void {
	for (fds) |fd| {
		if (fd >= 0) _ = linux.close(fd);
	}
}

fn runChildLinux(arena: Allocator, io: Io, spec: ChildSpec, res: *ChildResult) !void {
	if (spec.argv.len == 0) return error.NoArgv;
	const exe = findExe(arena, spec.env, spec.argv[0]) orelse return error.FileNotFound;

	const argv_z = try arena.allocSentinel(?[*:0]const u8, spec.argv.len, null);
	for (spec.argv, 0..) |a, i| argv_z[i] = (try arena.dupeZ(u8, a)).ptr;
	const env_keys = spec.env.keys();
	const env_vals = spec.env.values();
	const envp_z = try arena.allocSentinel(?[*:0]const u8, env_keys.len, null);
	for (env_keys, env_vals, 0..) |k, v, i| envp_z[i] = (try std.fmt.allocPrintSentinel(arena, "{s}={s}", .{ k, v }, 0)).ptr;

	const devnull = try Io.Dir.cwd().openFile(io, "/dev/null", .{});
	defer devnull.close(io);
	// The input, written whole at offset 0 (pwrite leaves the file offset at 0
	// for the child's reads). Close-on-exec here; the child's dup2 clears it.
	var in_fds = [1]i32{-1};
	defer closeAll(&in_fds);
	if (spec.stdin) |bytes| {
		in_fds[0] = @intCast(try sysOk(linux.memfd_create("cogbox-apply-stdin", linux.MFD.CLOEXEC)));
		var off: usize = 0;
		while (off < bytes.len) {
			const n = try sysOk(linux.pwrite(in_fds[0], bytes[off..].ptr, bytes.len - off, @intCast(off)));
			if (n == 0) return error.ShortWrite;
			off += n;
		}
	}
	// out read, out write, err read, err write; -1 once closed.
	var pipes = [4]i32{ -1, -1, -1, -1 };
	defer closeAll(&pipes);
	var out_fds: [2]i32 = undefined;
	_ = try sysOk(linux.pipe2(&out_fds, .{ .CLOEXEC = true }));
	pipes[0] = out_fds[0];
	pipes[1] = out_fds[1];
	var err_fds: [2]i32 = undefined;
	_ = try sysOk(linux.pipe2(&err_fds, .{ .CLOEXEC = true }));
	pipes[2] = err_fds[0];
	pipes[3] = err_fds[1];
	const o_nonblock: usize = 1 << @bitOffsetOf(linux.O, "NONBLOCK");
	for ([_]i32{ out_fds[0], err_fds[0] }) |fd| {
		const fl = try sysOk(linux.fcntl(fd, linux.F.GETFL, 0));
		_ = try sysOk(linux.fcntl(fd, linux.F.SETFL, fl | o_nonblock));
	}

	var dfl: linux.Sigaction = std.mem.zeroes(linux.Sigaction);
	dfl.handler.handler = linux.SIG.DFL;
	const parent = linux.getpid();
	const stdin_fd = if (in_fds[0] >= 0) in_fds[0] else devnull.handle;
	const out_w = out_fds[1];
	const err_w = err_fds[1];

	const forked = linux.fork();
	if (linux.errno(forked) != .SUCCESS) return error.ForkFailed;
	if (forked == 0) {
		// The child: raw syscalls only, nothing allocated (see the doc comment).
		_ = linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @intFromEnum(linux.SIG.KILL), 0, 0, 0);
		if (linux.getppid() != parent) linux.exit_group(127);
		_ = linux.sigaction(.PIPE, &dfl, null);
		if (linux.errno(linux.dup2(stdin_fd, 0)) != .SUCCESS) linux.exit_group(127);
		if (linux.errno(linux.dup2(out_w, 1)) != .SUCCESS) linux.exit_group(127);
		if (linux.errno(linux.dup2(err_w, 2)) != .SUCCESS) linux.exit_group(127);
		_ = linux.execve(exe.ptr, argv_z.ptr, envp_z.ptr);
		linux.exit_group(127);
	}
	const pid: i32 = @intCast(forked);
	_ = linux.close(out_w);
	pipes[1] = -1;
	_ = linux.close(err_w);
	pipes[3] = -1;

	const pidfd_rc = linux.pidfd_open(pid, 0);
	const pidfd: i32 = if (linux.errno(pidfd_rc) == .SUCCESS) @intCast(pidfd_rc) else -1;
	const pidfds = [1]i32{pidfd};
	defer closeAll(&pidfds);

	var last_watch = nowMs(io);
	var out_open = true;
	var err_open = true;
	var buf: [16 << 10]u8 = undefined;
	while (true) {
		var fds: [3]linux.pollfd = undefined;
		var n: usize = 0;
		if (pidfd >= 0) {
			fds[n] = .{ .fd = pidfd, .events = linux.POLL.IN, .revents = 0 };
			n += 1;
		}
		const out_idx = n;
		if (out_open) {
			fds[n] = .{ .fd = out_fds[0], .events = linux.POLL.IN, .revents = 0 };
			n += 1;
		}
		const err_idx = n;
		if (err_open) {
			fds[n] = .{ .fd = err_fds[0], .events = linux.POLL.IN, .revents = 0 };
			n += 1;
		}
		const left = spec.deadline_ms - nowMs(io);
		const slice: i32 = @intCast(std.math.clamp(left, 0, Bounds.child_poll_ms));
		_ = linux.poll(&fds, n, slice);
		if (out_open and fds[out_idx].revents != 0) out_open = drain(arena, out_fds[0], &res.stdout, &buf);
		if (err_open and fds[err_idx].revents != 0) {
			err_open = drain(arena, err_fds[0], &res.stderr, &buf);
			if (spec.on_stderr) |h| h.f(h.ctx, res.stderr.data());
		}

		var status: u32 = 0;
		const w = linux.wait4(pid, &status, linux.W.NOHANG, null);
		if (linux.errno(w) == .SUCCESS and w == @as(usize, @intCast(pid))) {
			res.exit = decodeStatus(status);
			// A child that failed while the terminate flag is set died of the
			// interrupt, most likely of the same group signal (a terminal's
			// SIGINT or SIGHUP, the local backend's SIGTERM to the group),
			// which a group signal queues for this process before the child it
			// killed can be reaped: its failure is the interrupt's, never
			// evidence (a lost guest, a failed build). A success is kept: it is
			// the child's own answer.
			if (!spec.ignore_terminate and terminate.load(.acquire) != 0 and !res.exitedWith(0)) res.stopped = .terminate;
			break;
		}

		const stop: ?Stop = blk: {
			if (!spec.ignore_terminate and terminate.load(.acquire) != 0) break :blk .terminate;
			if (spec.honour_supersede and supersede.load(.acquire) != 0) break :blk .supersede;
			if (spec.stop_on_overflow and res.stdout.truncated()) break :blk .overflow;
			if (nowMs(io) >= spec.deadline_ms) break :blk .deadline;
			if (spec.watch) |wch| {
				if (nowMs(io) - last_watch >= spec.watch_ms) {
					last_watch = nowMs(io);
					if (!wch.check(wch.ctx)) break :blk .watch;
				}
			}
			break :blk null;
		};
		if (stop) |s| {
			res.stopped = s;
			_ = linux.kill(pid, .KILL);
			res.exit = reapBounded(io, pid, pidfd);
			break;
		}
	}
	// What the child wrote before it ended. A grandchild that kept a pipe open
	// (a builder, an ssh mux) is not waited for: one non-blocking drain.
	if (out_open) _ = drain(arena, out_fds[0], &res.stdout, &buf);
	if (err_open) _ = drain(arena, err_fds[0], &res.stderr, &buf);
}

/// Read what is available; false at EOF (or an error), true when the pipe is
/// still open.
fn drain(arena: Allocator, fd: i32, cap: *Capture, buf: []u8) bool {
	while (true) {
		const rc = linux.read(fd, buf.ptr, buf.len);
		switch (linux.errno(rc)) {
			.SUCCESS => {
				if (rc == 0) return false;
				cap.add(arena, buf[0..rc]);
			},
			.INTR => continue,
			.AGAIN => return true,
			else => return false,
		}
	}
}

fn decodeStatus(status: u32) ChildExit {
	if (linux.W.IFEXITED(status)) return .{ .exited = linux.W.EXITSTATUS(status) };
	return .{ .signaled = status & 0x7f };
}

/// Reap a SIGKILLed child, waiting at most Bounds.kill_wait_ms (a child stuck in
/// an uninterruptible sleep is left to init).
fn reapBounded(io: Io, pid: i32, pidfd: i32) ?ChildExit {
	const until = nowMs(io) + Bounds.kill_wait_ms;
	while (true) {
		var status: u32 = 0;
		const w = linux.wait4(pid, &status, linux.W.NOHANG, null);
		if (linux.errno(w) == .SUCCESS and w == @as(usize, @intCast(pid))) return decodeStatus(status);
		if (linux.errno(w) == .CHILD) return null;
		const left = until - nowMs(io);
		if (left <= 0) return null;
		if (pidfd >= 0) {
			var fds = [1]linux.pollfd{.{ .fd = pidfd, .events = linux.POLL.IN, .revents = 0 }};
			_ = linux.poll(&fds, 1, @intCast(@min(left, Bounds.child_poll_ms)));
		} else {
			Io.sleep(io, Io.Duration.fromMilliseconds(@min(left, 50)), .awake) catch {};
		}
	}
}

// --- containment ---------------------------------------------------------------------------

/// The containment mode by Nix's own store selection (an unset or `auto`
/// NIX_REMOTE: a writable state dir is a local store, else an existing daemon
/// socket is the daemon, else a local store; `daemon` or `unix://...` is the
/// daemon; anything else is taken as a local store). A daemon client builds in
/// the daemon, so this process's child is all there is to contain (`none`). A
/// local store builds in the client's own children, which only a systemd unit
/// can bound and cap: that needs root and a system manager (`unit`). Null: no
/// usable mode (restart_required/no_containment).
pub fn chooseCap(nix_remote: ?[]const u8, euid: u32, has_systemd: bool, state_writable: bool, daemon_socket: bool) ?Cap {
	const remote = nix_remote orelse "";
	const daemon = if (remote.len == 0 or std.mem.eql(u8, remote, "auto"))
		(!state_writable and daemon_socket)
	else
		std.mem.eql(u8, remote, "daemon") or std.mem.startsWith(u8, remote, "unix://");
	if (daemon) return .none;
	if (euid == 0 and has_systemd) return .unit;
	return null;
}

fn detectCap(env: *const std.process.Environ.Map) ?Cap {
	if (comptime !is_linux) return null;
	const state_writable = std.c.access("/nix/var/nix", std.c.W_OK | std.c.R_OK) == 0;
	const sock = std.c.access("/nix/var/nix/daemon-socket/socket", std.c.F_OK) == 0;
	const sd = std.c.access("/run/systemd/system", std.c.F_OK) == 0;
	return chooseCap(env.get("NIX_REMOTE"), std.c.geteuid(), sd, state_writable, sock);
}

/// `cogbox-apply-build-<first 12 hex of sha256(icd)>`: one per instance, so an
/// orphan of this instance is found by name, and two instances never collide.
/// The icd is hashed as normalIcd spells it, so the launcher's bash spelling
/// (`//` after a trailing slash in XDG_CONFIG_HOME or HOME) and the verb's
/// (path.join) name one unit; a canonical icd hashes as itself.
pub fn buildUnitName(arena: Allocator, icd: []const u8) ![]const u8 {
	var h: [32]u8 = undefined;
	std.crypto.hash.sha2.Sha256.hash(try normalIcd(arena, icd), &h, .{});
	const hex = std.fmt.bytesToHex(h, .lower);
	return std.fmt.allocPrint(arena, "cogbox-apply-build-{s}", .{hex[0..12]});
}

/// `p` lexically normalized: repeated and trailing `/` and `.` components
/// dropped. `..` is kept: across a symlink it names another directory, and
/// two instances must never share a unit name.
fn normalIcd(arena: Allocator, p: []const u8) ![]const u8 {
	var n: std.ArrayList(u8) = .empty;
	if (std.mem.startsWith(u8, p, "/")) try n.append(arena, '/');
	var it = std.mem.tokenizeScalar(u8, p, '/');
	while (it.next()) |c| {
		if (std.mem.eql(u8, c, ".")) continue;
		if (n.items.len > 0 and n.items[n.items.len - 1] != '/') try n.append(arena, '/');
		try n.appendSlice(arena, c);
	}
	return n.items;
}

/// The environment variables passed into the build unit by name (systemd-run
/// imports the value from its own environment, so no value is ever in argv).
/// A unit inherits nothing otherwise. Nothing that can carry a credential
/// (NIX_CONFIG, a netrc) is passed: no git credential reaches the build.
const unit_env_names = [_][]const u8{ "PATH", "HOME", "NIX_REMOTE", "NIX_SSL_CERT_FILE", "SSL_CERT_FILE", "TMPDIR", "XDG_CACHE_HOME" };

/// The `systemd-run ... -- <inner>` argv of a contained build stage.
pub fn unitArgv(arena: Allocator, unit: []const u8, runtime_max_s: i64, memory_max: u64, env: *const std.process.Environ.Map, inner: []const []const u8) ![]const []const u8 {
	var argv: std.ArrayList([]const u8) = .empty;
	try argv.appendSlice(arena, &.{
		"systemd-run",
		try std.fmt.allocPrint(arena, "--unit={s}", .{unit}),
		"--service-type=exec",
		"--collect",
		"--wait",
		"--pipe",
		"-p",
		try std.fmt.allocPrint(arena, "RuntimeMaxSec={d}", .{@max(runtime_max_s, 1)}),
		"-p",
		"KillMode=control-group",
		"-p",
		try std.fmt.allocPrint(arena, "MemoryMax={d}", .{memory_max}),
		"-p",
		"OOMScoreAdjust=1000",
	});
	for (unit_env_names) |name| {
		if (env.get(name) != null) try argv.append(arena, try std.fmt.allocPrint(arena, "--setenv={s}", .{name}));
	}
	try argv.append(arena, "--");
	try argv.appendSlice(arena, inner);
	return argv.items;
}

/// systemd-run's own summary line, `Finished with result: <r>`, the LAST one in
/// its stderr (the unit's output precedes it on the same pipe, and a plugin's
/// eval output could print a lookalike earlier). Null when absent.
pub fn unitResult(stderr_tail: []const u8) ?[]const u8 {
	const needle = "Finished with result: ";
	const at = std.mem.lastIndexOf(u8, stderr_tail, needle) orelse return null;
	const rest = stderr_tail[at + needle.len ..];
	const end = std.mem.indexOfAny(u8, rest, "\r\n") orelse rest.len;
	const r = std.mem.trim(u8, rest[0..end], " \t");
	return if (r.len > 0) r else null;
}

/// systemd-run's `Running as unit: X; invocation ID: <32 hex>` (systemd 254+).
/// With --wait it carries the ID only when PID 1 ran the start job before
/// systemd-run read it (systemd 261 often prints the line without): null then.
pub fn unitInvocation(stderr_head: []const u8) ?[]const u8 {
	const needle = "invocation ID: ";
	const at = std.mem.indexOf(u8, stderr_head, needle) orelse return null;
	const rest = stderr_head[at + needle.len ..];
	if (rest.len < 32) return null;
	for (rest[0..32]) |c| switch (c) {
		'0'...'9', 'a'...'f' => {},
		else => return null,
	};
	return rest[0..32];
}

// --- the eval_error classifier --------------------------------------------------------------

/// What one build stage ended as, for the classifier.
pub const StageExit = struct {
	exit: ?ChildExit,
	/// The loop stopped it (the bound, a flag, the watch).
	stopped: ?Stop = null,
	/// The unit's Result (unit containment only).
	unit_result: ?[]const u8 = null,
	stderr: []const u8,
	stderr_truncated: bool = false,
};

pub const StageClass = enum {
	ok,
	/// Positive evidence of an evaluation error; a reproduction decides.
	eval_candidate,
	inputs_changed,
	inputs_uncached,
	build,
	build_timeout,
	oom,
};

/// Evaluation markers: one must appear beside `error:`.
const eval_markers = [_][]const u8{ "while evaluating", "while calling", "The option", "undefined variable", "infinite recursion", "assertion", "cogbox: " };
/// Infrastructure markers (spec section 2 step 3): any one rules eval_error out.
const infra_markers = [_][]const u8{ "No space left", "bad_alloc", "out of memory", "unexpected end-of-file", "cannot connect to socket", "Connection reset", "interrupted", "timed out", "unable to download", "HTTP error", "NAR hash mismatch", "Cannot build '" };
/// A fetch that could not be served (failed/build_inputs_uncached).
const fetch_markers = [_][]const u8{ "unable to download", "HTTP error", "Could not resolve host", "Couldn't resolve host", "Failed to connect to" };

fn containsAny(hay: []const u8, needles: []const []const u8) bool {
	for (needles) |n| if (std.mem.indexOf(u8, hay, n) != null) return true;
	return false;
}

/// An `attribute '...' missing` line.
fn hasMissingAttribute(stderr: []const u8) bool {
	var it = std.mem.splitScalar(u8, stderr, '\n');
	while (it.next()) |line| {
		const a = std.mem.indexOf(u8, line, "attribute '") orelse continue;
		if (std.mem.indexOfPos(u8, line, a + "attribute '".len, "' missing") != null) return true;
	}
	return false;
}

fn timedOut(s: StageExit) bool {
	if (s.stopped == .deadline) return true;
	if (s.unit_result) |r| return std.mem.eql(u8, r, "timeout");
	return false;
}

fn unitResultIs(s: StageExit, which: []const []const u8) bool {
	const r = s.unit_result orelse return false;
	for (which) |w| if (std.mem.eql(u8, r, w)) return true;
	return false;
}

/// Classify stage (a), the instantiate. eval_candidate needs every one of:
/// exit status exactly 1 and no signal (no 137/143, no unit Result oom-kill,
/// timeout or signal); `error:` with an evaluation marker; no infrastructure
/// marker; and the whole stderr seen (a truncated one could hide a marker).
/// When unsure, `build`.
pub fn classifyInstantiate(s: StageExit) StageClass {
	if (timedOut(s)) return .build_timeout;
	if (unitResultIs(s, &.{"oom-kill"})) return .oom;
	if (s.stopped != null) return .build;
	const e = s.exit orelse return .build;
	if (e == .exited and e.exited == 0 and (s.unit_result == null or unitResultIs(s, &.{"success"}))) return .ok;
	if (std.mem.indexOf(u8, s.stderr, "NAR hash mismatch") != null) return .inputs_changed;
	if (containsAny(s.stderr, &fetch_markers)) return .inputs_uncached;
	if (e != .exited or e.exited != 1) return .build;
	if (unitResultIs(s, &.{ "oom-kill", "timeout", "signal", "core-dump", "watchdog" })) return .build;
	if (s.stderr_truncated) return .build;
	if (std.mem.indexOf(u8, s.stderr, "error:") == null) return .build;
	if (!containsAny(s.stderr, &eval_markers) and !hasMissingAttribute(s.stderr)) return .build;
	if (containsAny(s.stderr, &infra_markers)) return .build;
	return .eval_candidate;
}

/// Classify stage (b), the realise: never an eval_error, and a hash mismatch of
/// a realised path is not an input change.
pub fn classifyRealise(s: StageExit) StageClass {
	if (timedOut(s)) return .build_timeout;
	if (unitResultIs(s, &.{"oom-kill"})) return .oom;
	if (s.stopped != null) return .build;
	const e = s.exit orelse return .build;
	if (e == .exited and e.exited == 0 and (s.unit_result == null or unitResultIs(s, &.{"success"}))) return .ok;
	if (containsAny(s.stderr, &fetch_markers)) return .inputs_uncached;
	return .build;
}

/// The first `error:` line that carries a message (nix prints a bare `error:`
/// above an evaluation trace; the message is on a later `error: ...` line),
/// trimmed, with ANSI escapes removed. The reproduction must fail with the same
/// one.
pub fn firstErrorLine(arena: Allocator, stderr: []const u8) ?[]const u8 {
	var it = std.mem.splitScalar(u8, stderr, '\n');
	while (it.next()) |raw| {
		const line = stripAnsi(arena, raw);
		const at = std.mem.indexOf(u8, line, "error:") orelse continue;
		const msg = std.mem.trim(u8, line[at + "error:".len ..], " \t\r");
		if (msg.len == 0) continue;
		return std.mem.trim(u8, line[at..], " \t\r");
	}
	return null;
}

/// Whether a reproduction confirms an eval_error: it must be an eval_candidate
/// too, with the same first error line.
pub fn reproduced(arena: Allocator, first: StageExit, second: StageExit) bool {
	if (classifyInstantiate(first) != .eval_candidate) return false;
	if (classifyInstantiate(second) != .eval_candidate) return false;
	const a = firstErrorLine(arena, first.stderr) orelse return false;
	const b = firstErrorLine(arena, second.stderr) orelse return false;
	return std.mem.eql(u8, a, b);
}

/// Remove ANSI escape sequences (CSI and OSC) and every control character but
/// newline and tab.
pub fn stripAnsi(arena: Allocator, in: []const u8) []const u8 {
	var o: std.ArrayList(u8) = .empty;
	var i: usize = 0;
	while (i < in.len) {
		const c = in[i];
		if (c == 0x1b) {
			i += 1;
			if (i < in.len and in[i] == '[') {
				i += 1;
				while (i < in.len and !(in[i] >= 0x40 and in[i] <= 0x7e)) i += 1;
				i += 1;
			} else if (i < in.len and in[i] == ']') {
				while (i < in.len and in[i] != 0x07) {
					if (in[i] == 0x1b and i + 1 < in.len and in[i + 1] == '\\') {
						i += 1;
						break;
					}
					i += 1;
				}
				i += 1;
			} else if (i < in.len) {
				i += 1;
			}
			continue;
		}
		if (c == '\n' or c == '\t' or (c >= 0x20 and c != 0x7f)) o.append(arena, c) catch return in;
		i += 1;
	}
	return o.items;
}

// --- runtime records -----------------------------------------------------------------------

/// `$RUNTIME/booted-runner`: the launcher's record of what this boot runs.
pub const Booted = struct {
	key: []const u8,
	runner: []const u8,
	comp: []const u8,
};

/// Exactly three lines (key, runner store path, comp); null otherwise.
pub fn parseBooted(data: []const u8) ?Booted {
	var lines: [4][]const u8 = undefined;
	var n: usize = 0;
	var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, data, "\n"), '\n');
	while (it.next()) |l| {
		if (n == lines.len) return null;
		lines[n] = l;
		n += 1;
	}
	if (n != 3) return null;
	if (lines[0].len == 0 or !isStorePath(lines[1]) or !snapshot.isComp(lines[2])) return null;
	return .{ .key = lines[0], .runner = lines[1], .comp = lines[2] };
}

/// `$RUNTIME/live-runner`: written by a confirmed (or already-live) apply:
/// key, R, comp, and the boot nonce it was written under. A file whose nonce is
/// not the current boot's is from an earlier boot of this runtime dir and is
/// ignored (the launcher keeps the runtime dir across a stop/start).
pub const Live = struct {
	key: []const u8,
	runner: []const u8,
	comp: []const u8,
	nonce: []const u8,
};

pub fn parseLive(data: []const u8) ?Live {
	var lines: [5][]const u8 = undefined;
	var n: usize = 0;
	var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, data, "\n"), '\n');
	while (it.next()) |l| {
		if (n == lines.len) return null;
		lines[n] = l;
		n += 1;
	}
	if (n != 4) return null;
	if (lines[0].len == 0 or !isStorePath(lines[1]) or !snapshot.isComp(lines[2]) or lines[3].len == 0) return null;
	return .{ .key = lines[0], .runner = lines[1], .comp = lines[2], .nonce = lines[3] };
}

/// `$RUNTIME/qemu.start`, trimmed; null when absent or empty (still booting).
pub fn readNonce(arena: Allocator, io: Io, runtime: []const u8) ?[]const u8 {
	const p = std.fs.path.join(arena, &.{ runtime, "qemu.start" }) catch return null;
	const data = readSmall(arena, io, p, 64) catch return null;
	const v = std.mem.trim(u8, data, " \t\r\n");
	return if (v.len > 0) v else null;
}

/// Whether the instance still runs boot `nonce` (and, given `host_boot`, on
/// that host boot): `changed` when it stopped or runs another qemu.start or
/// host boot; `unknown` when it runs but either cannot be read (a transient
/// read failure, or a relaunch still booting). A record that needs the same
/// boot is neither made nor given up on `unknown`: inflight.json stays for a
/// recoverer, so a confirmed change never loses its record to a failed read.
pub const BootState = enum { same, changed, unknown };

pub fn bootState(arena: Allocator, ctx: *const plugin.Ctx, nonce: []const u8, host_boot: ?[]const u8) BootState {
	if (!plugin.isRunning(ctx)) return .changed;
	const nc = readNonce(arena, ctx.io, ctx.runtime_path) orelse return .unknown;
	if (!std.mem.eql(u8, nc, nonce)) return .changed;
	if (host_boot) |want| {
		const hb = hostBootId(arena, ctx.io) orelse return .unknown;
		if (!std.mem.eql(u8, hb, want)) return .changed;
	}
	return .same;
}

/// What preflight's identity check established: the booted runner B, the
/// runner P the guest runs now (live-runner's R when an apply moved it this
/// boot, else B), and the comp the base snapshot must carry.
pub const Identity = struct {
	booted: Booted,
	live: ?Live,
	base_id: snapshot.Id,

	pub fn currentRunner(id: Identity) []const u8 {
		return if (id.live) |l| l.runner else id.booted.runner;
	}

	pub fn expectedComp(id: Identity) []const u8 {
		return if (id.live) |l| l.comp else id.booted.comp;
	}
};

pub const IdentityCheck = union(enum) {
	ok: struct { identity: Identity, base: snapshot.Snapshot },
	refuse: Reason,
};

/// Preflight's identity (spec section 2 step 2, and tier 1 (a)):
/// `booted-runner` exists with three lines (else no_boot_record) and its key is
/// the current `COGBOX_FLAKE_SOURCE#COGBOX_REEXEC_PACKAGE` (else base_changed);
/// `apply/base` names a complete snapshot whose comp equals live-runner's comp
/// when this boot has one, else booted-runner's line 3 -- strictly the one,
/// never "either" (else no_boot_record).
pub fn checkIdentity(arena: Allocator, io: Io, icd: []const u8, runtime: []const u8, key: []const u8, nonce: ?[]const u8) IdentityCheck {
	const bp = std.fs.path.join(arena, &.{ runtime, "booted-runner" }) catch return .{ .refuse = .no_boot_record };
	const bdata = readSmall(arena, io, bp, 64 << 10) catch return .{ .refuse = .no_boot_record };
	const booted = parseBooted(bdata) orelse return .{ .refuse = .no_boot_record };
	if (!std.mem.eql(u8, booted.key, key)) return .{ .refuse = .base_changed };
	var live: ?Live = null;
	if (nonce) |nc| {
		const lp = std.fs.path.join(arena, &.{ runtime, "live-runner" }) catch return .{ .refuse = .no_boot_record };
		if (readSmall(arena, io, lp, 64 << 10)) |ldata| {
			if (parseLive(ldata)) |l| {
				if (std.mem.eql(u8, l.nonce, nc) and std.mem.eql(u8, l.key, key)) live = l;
			}
		} else |_| {}
	}
	const base_id = snapshot.roleId(io, icd, .base) orelse return .{ .refuse = .no_boot_record };
	const base = snapshot.read(arena, io, icd, &base_id) catch return .{ .refuse = .no_boot_record };
	const id: Identity = .{ .booted = booted, .live = live, .base_id = base_id };
	if (!std.mem.eql(u8, base.meta.comp, id.expectedComp())) return .{ .refuse = .no_boot_record };
	return .{ .ok = .{ .identity = id, .base = base } };
}

/// The launcher's per-instance flake scaffold (cogbox-launch.sh SCAFFOLD_FLAKE),
/// byte for byte. With no plugins the launcher boots its own base runner only
/// while flake/flake.nix is this text; an edited one is re-executed from, which
/// a live apply cannot reproduce (customized_flake).
pub const scaffold_flake =
	"{\n"
	++ "\tdescription = \"cogbox per-instance extensions\";\n"
	++ "\n"
	++ "\t# `pkgs` in nixosModules.default below comes from cogbox's nixpkgs.\n"
	++ "\t# To use a different nixpkgs, add an input here (e.g.\n"
	++ "\t# inputs.nixpkgs-custom.url = \"...\";) and reference it explicitly.\n"
	++ "\t# cogbox always overrides any \"nixpkgs\" input you declare to its\n"
	++ "\t# own, so use a different name (like nixpkgs-custom) to escape that.\n"
	++ "\n"
	++ "\toutputs = { self }: {\n"
	++ "\t\tnixosModules.default = { pkgs, lib, ... }: {\n"
	++ "\t\t\t# Add per-instance packages and modules here. Examples:\n"
	++ "\t\t\t#   environment.systemPackages = with pkgs; [ hbase openjdk21 ];\n"
	++ "\t\t\t#   system.extraDependencies  = with pkgs; [ hbase openjdk21 ];\n"
	++ "\t\t};\n"
	++ "\t};\n"
	++ "}\n";

/// Whether the instance's user flake is customized (an existing flake.nix that
/// is not the scaffold). Unreadable counts as customized (fail closed).
pub fn userFlakeCustomized(arena: Allocator, io: Io, user_flake_dir: []const u8) bool {
	const p = std.fs.path.join(arena, &.{ user_flake_dir, "flake.nix" }) catch return true;
	const data = readSmall(arena, io, p, 1 << 20) catch |err| return err != error.FileNotFound;
	return !std.mem.eql(u8, data, scaffold_flake);
}

/// The narHash the composition lock pins for its `user` input; null when the
/// lock does not parse or has none.
pub fn userLockedNarHash(arena: Allocator, lock: []const u8) ?[]const u8 {
	const v = std.json.parseFromSliceLeaky(std.json.Value, arena, lock, .{}) catch return null;
	const nodes = objGet(v, "nodes") orelse return null;
	const inputs = objGet(objGet(nodes, "root") orelse return null, "inputs") orelse return null;
	const name = objGet(inputs, "user") orelse return null;
	if (name != .string) return null;
	const node = objGet(nodes, name.string) orelse return null;
	const h = objGet(objGet(node, "locked") orelse return null, "narHash") orelse return null;
	return if (h == .string) h.string else null;
}

fn objGet(v: ?std.json.Value, key: []const u8) ?std.json.Value {
	const x = v orelse return null;
	if (x != .object) return null;
	return x.object.get(key);
}

/// `MemAvailable` from /proc/meminfo text, in bytes.
pub fn parseMemAvailable(meminfo: []const u8) ?u64 {
	var it = std.mem.splitScalar(u8, meminfo, '\n');
	while (it.next()) |line| {
		if (!std.mem.startsWith(u8, line, "MemAvailable:")) continue;
		var w = std.mem.tokenizeAny(u8, line["MemAvailable:".len..], " \t");
		const kb = std.fmt.parseInt(u64, w.next() orelse return null, 10) catch return null;
		return kb * 1024;
	}
	return null;
}

pub fn memAvailable(arena: Allocator, io: Io) ?u64 {
	const data = readSmall(arena, io, "/proc/meminfo", 64 << 10) catch return null;
	return parseMemAvailable(data);
}

/// The kernel's struct statfs on the 64-bit Linux targets cogbox builds for.
const KStatfs = extern struct {
	f_type: i64,
	f_bsize: i64,
	f_blocks: u64,
	f_bfree: u64,
	f_bavail: u64,
	f_files: u64,
	f_ffree: u64,
	f_fsid: [2]i32,
	f_namelen: i64,
	f_frsize: i64,
	f_flags: i64,
	f_spare: [4]i64,
};

/// Bytes available to an unprivileged writer on the filesystem holding `path`;
/// null when it cannot be read (the caller fails closed).
pub fn freeBytes(arena: Allocator, path: []const u8) ?u64 {
	if (comptime !is_linux or @sizeOf(usize) != 8) return null;
	const pz = arena.dupeZ(u8, path) catch return null;
	var st: KStatfs = std.mem.zeroes(KStatfs);
	const rc = linux.syscall2(.statfs, @intFromPtr(pz.ptr), @intFromPtr(&st));
	if (linux.errno(rc) != .SUCCESS) return null;
	return st.f_bavail * @as(u64, @intCast(@max(st.f_bsize, 0)));
}

// --- apply/active -------------------------------------------------------------------------

/// `<icd>/apply/active`: who is applying, in which phase, and until when. The
/// gate of a waiting plugin change reads it every second; `--status` and
/// `--cancel` name the holder from it (pid and starttime, signalled through a
/// pidfd); the snapshot GC keeps the scratch snapshot it names.
pub const Active = struct {
	pid: i32,
	starttime: ?u64 = null,
	/// The build unit (unit containment); every stopper stops it by this name.
	unit: ?[]const u8 = null,
	/// The running stage's InvocationID, or null: a diagnostic.
	invocation: ?[]const u8 = null,
	op: ?[]const u8 = null,
	gen: ?[]const u8 = null,
	scratch_id: []const u8,
	phase: Phase,
	/// CLOCK_BOOTTIME seconds.
	deadline: i64,
};

fn applyDir(io: Io, icd: []const u8, owner: ?u32) !Io.Dir {
	var icd_dir = try snapshot.openIcd(io, icd);
	defer icd_dir.close(io);
	try snapshot.ensureDir(io, icd_dir, "apply", owner);
	return icd_dir.openDir(io, "apply", .{ .follow_symlinks = false });
}

fn writeApplyFile(arena: Allocator, io: Io, icd: []const u8, name: []const u8, bytes: []const u8, owner: ?u32) !void {
	_ = arena;
	var dir = try applyDir(io, icd, owner);
	defer dir.close(io);
	try snapshot.writeNew(io, dir, name, bytes, owner);
}

pub fn writeActive(arena: Allocator, io: Io, icd: []const u8, a: Active, owner: ?u32) !void {
	var aw: Io.Writer.Allocating = .init(arena);
	std.json.Stringify.value(a, .{}, &aw.writer) catch return error.OutOfMemory;
	aw.writer.writeByte('\n') catch return error.OutOfMemory;
	try writeApplyFile(arena, io, icd, "active", aw.written(), owner);
}

/// apply/active as a stopper reads it: absent (nothing can be recorded
/// there), a record, or a file that is there but cannot be read or parsed
/// (EACCES, too large, malformed), whose unit may still run.
pub const ActiveRead = union(enum) {
	absent,
	record: Active,
	unreadable: anyerror,
};

pub fn readActiveForStop(arena: Allocator, io: Io, icd: []const u8) ActiveRead {
	var dir = snapshot.openIcd(io, icd) catch |err| return switch (err) {
		error.FileNotFound, error.NotDir, error.RelativeInstanceDir => .absent,
		else => .{ .unreadable = err },
	};
	defer dir.close(io);
	const bytes = snapshot.readNoFollow(arena, io, dir, "apply/active", 64 << 10) catch |err| return switch (err) {
		error.FileNotFound, error.NotDir => .absent,
		else => .{ .unreadable = err },
	};
	const a = std.json.parseFromSliceLeaky(Active, arena, bytes, .{ .ignore_unknown_fields = true }) catch |err| return .{ .unreadable = err };
	return .{ .record = a };
}

/// apply/active, or null when it is absent or cannot be read (readers that
/// stop nothing: the gate, `--status`, the snapshot GC).
pub fn readActive(arena: Allocator, io: Io, icd: []const u8) ?Active {
	return switch (readActiveForStop(arena, io, icd)) {
		.record => |a| a,
		else => null,
	};
}

pub fn clearActive(io: Io, icd: []const u8) void {
	var dir = snapshot.openIcd(io, icd) catch return;
	defer dir.close(io);
	dir.deleteFile(io, "apply/active") catch {};
}

/// Whether `a` names a live process (same pid and starttime).
pub fn holderAlive(arena: Allocator, io: Io, a: Active) bool {
	const st = procStarttime(arena, io, a.pid) orelse return false;
	const want = a.starttime orelse return false;
	return st == want;
}

/// Whether `<icd>/apply/inflight.json` exists (an unbuildable path counts as
/// existing: fail closed).
fn inflightExists(io: Io, icd: []const u8) bool {
	var buf: [std.fs.max_path_bytes]u8 = undefined;
	const p = std.fmt.bufPrint(&buf, "{s}/apply/inflight.json", .{icd}) catch return true;
	return pathExists(io, p);
}

// --- locks --------------------------------------------------------------------------------

/// flock with LOCK_NB: true when taken, false when someone else holds it.
fn tryFlock(fd: std.posix.fd_t) !bool {
	while (std.c.flock(fd, std.posix.LOCK.EX | std.posix.LOCK.NB) != 0) {
		const e = std.c._errno().*;
		if (e == @intFromEnum(std.posix.E.INTR)) continue;
		if (e == @intFromEnum(std.posix.E.AGAIN)) return false;
		return error.CannotLock;
	}
	return true;
}

fn unlockFd(fd: std.posix.fd_t) void {
	if (fd < 0) return;
	while (std.c.flock(fd, std.posix.LOCK.UN) != 0) {
		if (std.c._errno().* != @intFromEnum(std.posix.E.INTR)) return;
	}
}

/// config_lock.pollLock on a descriptor the CLI opened: a LOCK_NB attempt every
/// 100 ms until `timeout_ms` (error.Timeout) or the cancel flag (error.Canceled).
/// With `give_way`, a wait (never a free lock) also ends once that flag is set
/// (error.Superseded).
pub fn pollFlock(io: Io, fd: std.posix.fd_t, timeout_ms: i64, cancel: ?*const std.atomic.Value(u8), give_way: ?*const std.atomic.Value(u8)) !void {
	const began = nowMs(io);
	while (true) {
		if (cancel) |c| if (c.load(.acquire) != 0) return error.Canceled;
		if (try tryFlock(fd)) return;
		if (give_way) |g| if (g.load(.acquire) != 0) return error.Superseded;
		const waited = nowMs(io) - began;
		if (waited >= timeout_ms) return error.Timeout;
		Io.sleep(io, Io.Duration.fromMilliseconds(@min(100, timeout_ms - waited)), .awake) catch {};
	}
}

// --- guest hops ---------------------------------------------------------------------------

pub const helper_path = "/run/booted-system/cogbox-live-switch";

/// One key=value pair of a helper reply.
pub const Kv = struct { key: []const u8, value: []const u8 };

/// A helper reply: `key=value` lines, `proto=2` first and `end=1` last (a reply
/// without it was cut off and is never used).
pub const Reply = struct {
	pairs: []const Kv,

	pub fn get(r: Reply, key: []const u8) ?[]const u8 {
		for (r.pairs) |p| if (std.mem.eql(u8, p.key, key)) return p.value;
		return null;
	}

	pub fn all(r: Reply, arena: Allocator, key: []const u8) []const []const u8 {
		var o: std.ArrayList([]const u8) = .empty;
		for (r.pairs) |p| if (std.mem.eql(u8, p.key, key)) o.append(arena, p.value) catch {};
		return o.items;
	}
};

/// Lines and line length a reply may have (the guest is untrusted; the hop's
/// own output cap bounds the bytes).
const max_reply_lines = 1 << 18;
const max_reply_line = 1024;

pub fn parseReply(arena: Allocator, bytes: []const u8) !Reply {
	var pairs: std.ArrayList(Kv) = .empty;
	var it = std.mem.splitScalar(u8, bytes, '\n');
	while (it.next()) |line| {
		if (line.len == 0) continue;
		if (line.len > max_reply_line) return error.MalformedReply;
		const eq = std.mem.indexOfScalar(u8, line, '=') orelse return error.MalformedReply;
		if (eq == 0) return error.MalformedReply;
		if (pairs.items.len >= max_reply_lines) return error.MalformedReply;
		try pairs.append(arena, .{ .key = line[0..eq], .value = line[eq + 1 ..] });
	}
	const p = pairs.items;
	if (p.len < 2) return error.MalformedReply;
	if (!std.mem.eql(u8, p[0].key, "proto") or !std.mem.eql(u8, p[0].value, "2")) return error.MalformedReply;
	if (!std.mem.eql(u8, p[p.len - 1].key, "end") or !std.mem.eql(u8, p[p.len - 1].value, "1")) return error.MalformedReply;
	return .{ .pairs = p[1 .. p.len - 1] };
}

/// The argv of one guest hop: ssh with the apply-hop options (bounded, never
/// multiplexed), the helper at its fixed path, and the verb's arguments (each
/// single-quoted for the guest shell by sshargv).
pub fn hopArgv(arena: Allocator, endpoint: sshargv.Endpoint, identity: ?[]const u8, verb: []const []const u8) ![]const []const u8 {
	return hopArgvKind(arena, endpoint, identity, verb, .apply);
}

/// hopArgv with the hop kind: `.confirm` is the fresh-connection confirm
/// (spec section 2 step 8), which with the cogbox key also reads no ssh
/// config file (`-F /dev/null`).
pub fn hopArgvKind(arena: Allocator, endpoint: sshargv.Endpoint, identity: ?[]const u8, verb: []const []const u8, kind: sshargv.Hop) ![]const []const u8 {
	std.debug.assert(kind != .interactive);
	var remote: std.ArrayList([]const u8) = .empty;
	try remote.append(arena, helper_path);
	try remote.appendSlice(arena, verb);
	var argv: std.ArrayList([]const u8) = .empty;
	try sshargv.buildArgvOpts(arena, &argv, endpoint, identity, remote.items, .{ .hop = kind });
	return argv.items;
}

pub const HopResult = struct {
	reply: ?Reply = null,
	/// A raw hop's output (`log`), control characters and ANSI stripped.
	raw: ?[]const u8 = null,
	/// The hop failed: ssh could not connect, the kill fired, the reply was
	/// cut off, malformed or over its cap.
	failed: bool = false,
	/// The helper is missing (exit 126 or 127).
	no_helper: bool = false,
	stopped: ?Stop = null,
};

pub const HopSpec = struct {
	kind: sshargv.Hop = .apply,
	/// Absolute monotonic (awake) deadline in ms: the hop's wall-clock kill.
	deadline_ms: i64,
	out_cap: usize = 64 << 10,
	honour_supersede: bool = false,
	ignore_terminate: bool = false,
	watch: ?Watch = null,
	/// The reply is raw text (`log`), not key=value lines.
	raw: bool = false,
	/// What the remote verb reads on stdin (ChildSpec.stdin): only an Apply
	/// anyway `start`'s force list.
	stdin: ?[]const u8 = null,
};

/// One guest hop: ssh (the apply-hop options; `.confirm` adds `-F /dev/null`
/// with the cogbox key) to the endpoint the instance publishes in
/// <runtime>/ssh-endpoint, running the booted system's helper with `verb`,
/// killed at `spec.deadline_ms`. The core of the live verb's hops and the
/// recoverers'. The reply is untrusted: capped, and used only when it parses
/// (`proto=2` first, `end=1` last).
pub fn guestHop(arena: Allocator, io: Io, env: *const std.process.Environ.Map, runtime: []const u8, identity: ?[]const u8, verb: []const []const u8, spec: HopSpec) HopResult {
	const endpoint = sshargv.readEndpoint(arena, io, runtime) catch return .{ .failed = true };
	const argv = hopArgvKind(arena, endpoint, identity, verb, spec.kind) catch return .{ .failed = true };
	const res = runChild(arena, io, .{
		.argv = argv,
		.env = env,
		.deadline_ms = spec.deadline_ms,
		.out_cap = spec.out_cap,
		.err_cap = 16 << 10,
		.stop_on_overflow = !spec.raw,
		.honour_supersede = spec.honour_supersede,
		.ignore_terminate = spec.ignore_terminate,
		.watch = spec.watch,
		.stdin = spec.stdin,
	});
	if (res.stopped) |s| switch (s) {
		.terminate, .supersede, .watch => return .{ .failed = true, .stopped = s },
		.deadline, .overflow => return .{ .failed = true },
	};
	if (res.exit) |e| {
		if (e == .exited and (e.exited == 126 or e.exited == 127)) return .{ .failed = true, .no_helper = true };
		if (e != .exited or e.exited != 0) return .{ .failed = true };
	} else return .{ .failed = true };
	if (spec.raw) return .{ .raw = stripAnsi(arena, res.stdout.data()) };
	if (res.stdout.truncated()) return .{ .failed = true };
	const reply = parseReply(arena, res.stdout.data()) catch return .{ .failed = true };
	return .{ .reply = reply };
}

// --- the plan (tier 2 merge) -------------------------------------------------------------

pub const DryAction = enum { stop, skip, reload, restart, start };
pub const DryEntry = struct { action: DryAction, unit: []const u8 };
/// A runtime reverse edge: `x`'s property lists `u`.
pub const EdgeEntry = struct { edge: unitplan.Edge, x: []const u8, u: []const u8 };

/// What a `plan T` reply carries for tier 2, after validation (unit names that
/// pass the charset; they are intersected with the T/P unit files in merge).
pub const GuestPlan = struct {
	boot_id: []const u8,
	booted: ?[]const u8,
	current: ?[]const u8,
	store_overlay: bool,
	dry_result: []const u8,
	dry: []const DryEntry = &.{},
	reexec: bool = false,
	/// Units whose state is exactly `inactive` (only ever drop a planned stop,
	/// restart or reload of that unit).
	inactive: []const []const u8 = &.{},
	/// Units the guest runs (active, reloading, refreshing): a start the
	/// closure propagates to one is a no-op. A real reply always has some (its
	/// own sshd), so guestPlanOf refuses one without any.
	active: []const []const u8 = &.{},
	/// Units the guest cannot load (load state not-found).
	not_found: []const []const u8 = &.{},
	/// The once-markers present (unit names without their type).
	once: []const []const u8 = &.{},
	induced: []const []const u8 = &.{},
	edges: []const EdgeEntry = &.{},
};

fn edgeOf(tok: []const u8) ?unitplan.Edge {
	const map = [_]struct { []const u8, unitplan.Edge }{
		.{ "required_by", .rt_required_by },
		.{ "bound_by", .rt_bound_by },
		.{ "consists_of", .rt_consists_of },
		.{ "propagates_stop_to", .rt_propagates_stop_to },
		.{ "propagates_reload_to", .rt_propagates_reload_to },
		.{ "conflicted_by", .rt_conflicted_by },
	};
	for (map) |m| if (std.mem.eql(u8, tok, m[0])) return m[1];
	return null;
}

/// Read a `result=ok` plan reply into a GuestPlan. error.MalformedReply for a
/// missing or invalid field; list entries that fail their charset are dropped.
pub fn guestPlanOf(arena: Allocator, r: Reply) !GuestPlan {
	const boot_id = r.get("boot_id") orelse return error.MalformedReply;
	if (!isBootId(boot_id)) return error.MalformedReply;
	const booted = r.get("booted") orelse return error.MalformedReply;
	const current = r.get("current") orelse return error.MalformedReply;
	const store = r.get("store") orelse return error.MalformedReply;
	const dry_result = r.get("dry_result") orelse return error.MalformedReply;
	var g: GuestPlan = .{
		.boot_id = boot_id,
		.booted = if (isStorePath(booted)) booted else null,
		.current = if (isStorePath(current)) current else null,
		.store_overlay = std.mem.eql(u8, store, "overlay"),
		.dry_result = dry_result,
		.reexec = if (r.get("reexec")) |v| std.mem.eql(u8, v, "yes") else false,
	};
	var dry: std.ArrayList(DryEntry) = .empty;
	for (r.all(arena, "dry")) |v| {
		const sp = std.mem.indexOfScalar(u8, v, ' ') orelse continue;
		const action = std.meta.stringToEnum(DryAction, v[0..sp]) orelse continue;
		const unit = v[sp + 1 ..];
		if (!isUnitToken(unit)) continue;
		try dry.append(arena, .{ .action = action, .unit = unit });
	}
	g.dry = dry.items;
	var inactive: std.ArrayList([]const u8) = .empty;
	for (r.all(arena, "inactive")) |u| if (isUnitToken(u)) try inactive.append(arena, u);
	g.inactive = inactive.items;
	var active: std.ArrayList([]const u8) = .empty;
	for (r.all(arena, "active")) |u| if (isUnitToken(u)) try active.append(arena, u);
	// No unit the guest runs (not even the sshd this hop came in through):
	// the listing failed, and the plan would know nothing of the guest.
	if (active.items.len == 0) return error.MalformedReply;
	g.active = active.items;
	var not_found: std.ArrayList([]const u8) = .empty;
	for (r.all(arena, "notfound")) |u| if (isUnitToken(u)) try not_found.append(arena, u);
	g.not_found = not_found.items;
	var once: std.ArrayList([]const u8) = .empty;
	for (r.all(arena, "once")) |m| {
		// A marker is a unit name without its type: give it one to check it.
		if (isUnitToken(std.fmt.allocPrint(arena, "{s}.service", .{m}) catch continue)) try once.append(arena, m);
	}
	g.once = once.items;
	var induced: std.ArrayList([]const u8) = .empty;
	for (r.all(arena, "induced")) |u| if (isUnitToken(u)) try induced.append(arena, u);
	g.induced = induced.items;
	var edges: std.ArrayList(EdgeEntry) = .empty;
	for (r.all(arena, "edge")) |v| {
		var w = std.mem.tokenizeScalar(u8, v, ' ');
		const kind = edgeOf(w.next() orelse continue) orelse continue;
		const x = w.next() orelse continue;
		const u = w.next() orelse continue;
		if (w.next() != null or !isUnitToken(x) or !isUnitToken(u)) continue;
		try edges.append(arena, .{ .edge = kind, .x = x, .u = u });
	}
	g.edges = edges.items;
	return g;
}

/// The merged tier-2 verdict.
pub const Tier2 = struct {
	hazards: []const unitplan.Hazard,
	/// Units switch-ng will not restart (host and guest), node names.
	skipped: []const []const u8,
	reexec: bool,
	refusal: ?unitplan.Refusal,
	/// Every name in `hazards` (units and path units) -> the name a report
	/// shows for it (Graph.reportName).
	shown: std.array_hash_map.String([]const u8) = .empty,

	/// The name a report shows for a hazard's unit or path unit: a template
	/// instance only P's or T's listings show, never one only the guest named.
	pub fn reportName(t2: Tier2, arena: Allocator, name: []const u8) Allocator.Error![]const u8 {
		return t2.shown.get(name) orelse unitplan.nodeName(arena, name);
	}
};

/// Merge the guest's data into the host plan and decide (spec section 3, tier 2
/// items 3, 5 and 6). Guest data refuses, and narrows only for the guest's own
/// units:
///   - every name is intersected with the T/P unit files and the fstab mounts
///     (Graph.files), so a name outside them is dropped;
///   - an `inactive` claim drops only that unit's stop, restart or reload (and
///     only for a name that is its own node: a template instance never drops
///     the template's other instances); a lie only exposes the guest's own unit;
///   - the unit states (`active`, `notfound`) and once-markers decide whether a
///     start the closure propagates changes anything (unitplan.classify), and
///     which active targets the switch starts again (HostPlan.seeds);
///   - dry-activate's lists are ADDED (why guest_reported), never removed, and
///     its `skip` list joins the skipped units;
///   - induced starts (units active targets want at runtime that are not
///     running, generator wants included) are added as propagated starts;
///   - runtime reverse edges are added to the graph.
/// The user units the user pass would change are class A (Why.user_unit), and
/// so is every generator T adds, removes or retargets (Why.generator): what it
/// generates at the daemon-reload is in no unit directory the plan reads.
/// Then the propagation closure and the verdict. Guest data may refuse, but
/// what a report shows is the host's: a template instance only the guest
/// named is shown as its template (Tier2.reportName).
pub fn mergeTier2(arena: Allocator, plan: *unitplan.HostPlan, g: GuestPlan, host_reexec: bool) !Tier2 {
	const graph = &plan.graph;
	var inactive: unitplan.StrSet = .empty;
	for (g.inactive) |u| {
		const node = try graph.nodeOf(arena, u);
		if (!std.mem.eql(u8, node, u) or !graph.files.contains(node)) continue;
		try inactive.put(arena, node, {});
	}
	var rt: unitplan.Runtime = .{ .known = g.active.len > 0 };
	for (g.active) |u| {
		if (!graph.files.contains(try graph.nodeOf(arena, u))) continue;
		try rt.active.put(arena, try graph.nameOf(arena, u), {});
	}
	// A not-found claim counts only for a name no file defines (classify).
	for (g.not_found) |u| try rt.not_found.put(arena, try graph.nameOf(arena, u), {});
	for (g.once) |m| try rt.once.put(arena, m, {});
	var seeds: std.ArrayList(unitplan.Seed) = .empty;
	for (try plan.seeds(arena, &rt)) |s| {
		const node = try graph.nodeOf(arena, s.unit);
		// The target bookkeeping runs whatever the target's state: a restart
		// of an inactive sysinit-reactivation.target starts it.
		if (s.action != .start and s.why != .target and inactive.contains(node)) continue;
		try seeds.append(arena, s);
	}
	var skipped: unitplan.StrSet = .empty;
	for (plan.sets.skip.keys()) |u| try skipped.put(arena, try graph.nodeOf(arena, u), {});
	for (g.dry) |d| {
		const node = try graph.nodeOf(arena, d.unit);
		if (!graph.files.contains(node)) continue;
		const action: unitplan.Action = switch (d.action) {
			.skip => {
				try skipped.put(arena, node, {});
				continue;
			},
			.stop => .stop,
			.reload => .reload,
			.restart => .restart,
			.start => .start,
		};
		try seeds.append(arena, .{ .unit = node, .action = action, .why = .guest_reported });
	}
	for (g.induced) |u| {
		const node = try graph.nodeOf(arena, u);
		if (!graph.files.contains(node)) continue;
		try seeds.append(arena, .{ .unit = try graph.nameOf(arena, u), .action = .start, .why = .induced });
	}
	for (g.edges) |e| {
		const x = try graph.nodeOf(arena, e.x);
		const u = try graph.nodeOf(arena, e.u);
		if (!graph.files.contains(x) or !graph.files.contains(u)) continue;
		try graph.addRuntimeEdge(arena, x, e.edge, e.u);
	}
	const reexec = host_reexec or g.reexec;
	var hazards: std.ArrayList(unitplan.Hazard) = .empty;
	try hazards.appendSlice(arena, try unitplan.closure(arena, graph, seeds.items, &plan.new_units, &rt));
	for ([_][]const unitplan.PlannedUnit{ plan.user, plan.generators }) |list| {
		for (list) |u| {
			const path = try arena.alloc(unitplan.Hop, 1);
			path[0] = .{ .unit = u.unit, .action = u.action, .edge = null };
			try hazards.append(arena, .{ .class = .a, .unit = u.unit, .action = u.action, .path = path, .why = u.why });
		}
	}
	const skipped_names = try unitplan.sortedKeys(arena, &skipped);
	var shown: std.array_hash_map.String([]const u8) = .empty;
	for (hazards.items) |h| {
		try shown.put(arena, h.unit, try graph.reportName(arena, h.unit));
		for (h.path) |step| try shown.put(arena, step.unit, try graph.reportName(arena, step.unit));
	}
	return .{
		.hazards = hazards.items,
		.skipped = skipped_names,
		.reexec = reexec,
		.refusal = unitplan.verdict(hazards.items, skipped_names.len, reexec),
		.shown = shown,
	};
}

fn classLetter(c: unitplan.Class) []const u8 {
	return switch (c) {
		.a => "A",
		.b => "B",
		.c => "C",
		.d => "D",
		.skip => "skip",
	};
}

/// A hazard's `why`: its seed's for the seed itself, else
/// `propagated:<edge>:<from>` for the last hop (`from` as a report shows it).
fn hazardWhy(arena: Allocator, t2: Tier2, h: unitplan.Hazard) ![]const u8 {
	if (h.path.len < 2) return switch (h.why) {
		.reconfigured => "changed",
		else => h.why.name(),
	};
	const last = h.path[h.path.len - 1];
	const prev = h.path[h.path.len - 2];
	const edge = if (last.edge) |e| e.name() else "edge";
	return std.fmt.allocPrint(arena, "propagated:{s}:{s}", .{ edge, try t2.reportName(arena, prev.unit) });
}

/// A plan unit's `why` as listings and reports may carry it: `changed`,
/// `removed`, `new`, `target`, `induced`, `guest_reported`, or
/// `propagated:<edge>:<from>` with an edge of 1-32 of [a-z_] and a `from` the
/// helper's charset check passes (isUnitToken). `from` is a unit of T or P,
/// named by plugin code, so a byte outside that set (an escape sequence that
/// would redraw the listing a person agrees to) makes the plan one no one can
/// be asked about. The control plane checks the same shape.
pub fn isPlanWhy(why: []const u8) bool {
	const seeds = [_][]const u8{ "changed", "removed", "new", "target", "induced", "guest_reported" };
	for (seeds) |s| if (std.mem.eql(u8, why, s)) return true;
	const prefix = "propagated:";
	if (!std.mem.startsWith(u8, why, prefix)) return false;
	const rest = why[prefix.len..];
	const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return false;
	if (colon == 0 or colon > 32) return false;
	for (rest[0..colon]) |c| if ((c < 'a' or c > 'z') and c != '_') return false;
	return isUnitToken(rest[colon + 1 ..]);
}

pub const repair_unit = "cogbox-reply-route.service";

/// The plan of a refusal that has a class B, C or D part (spec 4.7): the class
/// B and C hazards as units (named as a report shows them, Tier2.reportName),
/// `reexec` for D, the repair unit when a class C unit or firewall.service is
/// in it; null when nothing in it can be forced, or when its force list is one
/// the guest helper would refuse or a name in it one a listing may not show
/// (forceUnits), so an offered plan always fits and can always be listed.
pub fn buildPlan(arena: Allocator, t2: Tier2, boot_id: []const u8, comp: []const u8, p_sys: []const u8, t_sys: []const u8) !?Plan {
	var units: std.ArrayList(PlanUnit) = .empty;
	var repair = false;
	for (t2.hazards) |h| {
		if (h.class != .b and h.class != .c) continue;
		const name = try t2.reportName(arena, h.unit);
		var dup = false;
		for (units.items) |u| {
			if (std.mem.eql(u8, u.unit, name) and u.action == h.action) dup = true;
		}
		if (dup) continue;
		if (h.class == .c or std.mem.eql(u8, h.unit, "firewall.service")) repair = true;
		try units.append(arena, .{ .unit = name, .action = h.action, .why = try hazardWhy(arena, t2, h), .class = classLetter(h.class) });
	}
	if (units.items.len == 0 and !t2.reexec) return null;
	std.mem.sort(PlanUnit, units.items, {}, planUnitLess);
	var p: Plan = .{
		.id = "",
		.boot_id = boot_id,
		.comp = comp,
		.P = p_sys,
		.T = t_sys,
		.units = units.items,
		.repair = if (repair) &.{repair_unit} else &.{},
		.reexec = t2.reexec,
	};
	p.id = try planId(arena, p);
	_ = forceUnits(arena, p) catch |err| switch (err) {
		error.OutOfMemory => return error.OutOfMemory,
		else => return null,
	};
	return p;
}

fn planUnitLess(_: void, a: PlanUnit, b: PlanUnit) bool {
	switch (std.mem.order(u8, a.unit, b.unit)) {
		.lt => return true,
		.gt => return false,
		.eq => {},
	}
	if (a.action != b.action) return @intFromEnum(a.action) < @intFromEnum(b.action);
	switch (std.mem.order(u8, a.why, b.why)) {
		.lt => return true,
		.gt => return false,
		.eq => return std.mem.lessThan(u8, a.class, b.class),
	}
}

/// The plan's id: the first 16 hex of sha256 over the canonical JSON of
/// {P, T, boot_id, comp, reexec, repair, units} (keys sorted, compact, units
/// sorted by unit, action, why, class; each unit's keys sorted too). Any change
/// to a unit, an action, T, P, the boot or the composition changes it, and the
/// input order never does.
pub fn planId(arena: Allocator, p: Plan) ![]const u8 {
	const units = try arena.dupe(PlanUnit, p.units);
	std.mem.sort(PlanUnit, units, {}, planUnitLess);
	var aw: Io.Writer.Allocating = .init(arena);
	writeCanonicalPlan(&aw.writer, p, units) catch return error.OutOfMemory;
	var h: [32]u8 = undefined;
	std.crypto.hash.sha2.Sha256.hash(aw.written(), &h, .{});
	const hex = std.fmt.bytesToHex(h, .lower);
	return arena.dupe(u8, hex[0..16]);
}

fn writeCanonicalPlan(w: *Io.Writer, p: Plan, units: []const PlanUnit) Io.Writer.Error!void {
	try w.writeAll("{\"P\":");
	try std.json.Stringify.value(p.P, .{}, w);
	try w.writeAll(",\"T\":");
	try std.json.Stringify.value(p.T, .{}, w);
	try w.writeAll(",\"boot_id\":");
	try std.json.Stringify.value(p.boot_id, .{}, w);
	try w.writeAll(",\"comp\":");
	try std.json.Stringify.value(p.comp, .{}, w);
	try w.writeAll(if (p.reexec) ",\"reexec\":true,\"repair\":[" else ",\"reexec\":false,\"repair\":[");
	for (p.repair, 0..) |rp, i| {
		if (i > 0) try w.writeByte(',');
		try std.json.Stringify.value(rp, .{}, w);
	}
	try w.writeAll("],\"units\":[");
	for (units, 0..) |u, i| {
		if (i > 0) try w.writeByte(',');
		try w.writeAll("{\"action\":");
		try std.json.Stringify.value(u.action.name(), .{}, w);
		try w.writeAll(",\"class\":");
		try std.json.Stringify.value(u.class, .{}, w);
		try w.writeAll(",\"unit\":");
		try std.json.Stringify.value(u.unit, .{}, w);
		try w.writeAll(",\"why\":");
		try std.json.Stringify.value(u.why, .{}, w);
		try w.writeByte('}');
	}
	try w.writeAll("]}");
}

/// The detail of a plan refusal: the units behind its reason as a report shows
/// them (Tier2.reportName), sorted, unique, capped (every one a name T's or P's
/// own data gives: a unit file, an fstab mount, a user unit, a generator).
pub fn refusalDetail(arena: Allocator, t2: Tier2, reason: unitplan.Reason) ![]const []const u8 {
	var set: unitplan.StrSet = .empty;
	for (t2.hazards) |h| {
		if (h.class.reason() == reason) try set.put(arena, try t2.reportName(arena, h.unit), {});
	}
	if (reason == .skipped_units) for (t2.skipped) |u| try set.put(arena, u, {});
	const names = try unitplan.sortedKeys(arena, &set);
	return names[0..@min(names.len, 64)];
}

// --- Apply anyway: the force list and the plan store (spec 4.7) ---------------------------

/// The unit names an Apply anyway run relaxes in the guest (`start
/// --force-units -`): the plan's units that it stops, starts or restarts,
/// unique and sorted (a unit can be listed with two actions). A unit the plan
/// only reloads is left out: a reload keeps its InvocationID and its running
/// state, so it passes every post-check comparison unexempted, and the guest
/// exempts a listed unit from all of them (a new InvocationID, a stop or start,
/// a reported failure), not only from what its planned action does. The repair
/// unit is not among them either (it travels as --repair). The guest exempts
/// exactly these names (`grep -qxF` against each unit's Id): the plan names
/// units as a report shows them, and among class B and C units only `sshd@`
/// can be a template (unitplan.classify), which is no protected unit in the
/// guest. An error for a plan whose names the helper's charset check refuses
/// (every unit's, as the report shows them all, and every `why`'s, isPlanWhy),
/// or a list it would refuse: more than Bounds.force_units_max names, or more
/// than Bounds.force_input_cap bytes of forceInput.
pub fn forceUnits(arena: Allocator, p: Plan) ![]const []const u8 {
	var set: unitplan.StrSet = .empty;
	for (p.units) |u| {
		if (!isUnitToken(u.unit) or !isPlanWhy(u.why)) return error.BadUnitName;
		if (u.action != .reload) try set.put(arena, u.unit, {});
	}
	if (set.count() > Bounds.force_units_max) return error.TooManyUnits;
	const names = try unitplan.sortedKeys(arena, &set);
	var bytes: usize = 0;
	for (names) |n| bytes += n.len + 1;
	if (bytes > Bounds.force_input_cap) return error.TooLong;
	return names;
}

/// What `start --force-units -` reads on stdin: each name and a newline.
pub fn forceInput(arena: Allocator, units: []const []const u8) ![]const u8 {
	var o: std.ArrayList(u8) = .empty;
	for (units) |u| {
		try o.appendSlice(arena, u);
		try o.append(arena, '\n');
	}
	return o.items;
}

/// `<icd>/apply/plans/<id>.json`: an overridable refusal's plan, kept so a
/// later `--force-plan <id>` can be bound to it (spec section 2 step 2, "Force
/// only"). `reason` is the plan's own overridable reason; `created` is
/// CLOCK_BOOTTIME seconds (a wall-clock step never ages a plan); `nonce` and
/// `host_boot` are the boot it was made in (qemu.start can repeat across boots
/// of identical hosts, so the host boot id is compared too); `gen` is the run
/// that planned it. The guest's boot id and the composition are in `plan`.
/// Unit names, store paths and ids only: nothing in it is secret.
pub const StoredPlan = struct {
	plan: Plan,
	reason: Reason,
	created: i64,
	nonce: []const u8,
	host_boot: []const u8,
	gen: []const u8,
};

const plans_dir = "plans";

/// `<id>.json` for a plan id; null for any other name.
fn planFileId(name: []const u8) ?[]const u8 {
	const sfx = ".json";
	if (name.len != snapshot.id_len + sfx.len or !std.mem.endsWith(u8, name, sfx)) return null;
	const id = name[0..snapshot.id_len];
	return if (cli.isHex16(id)) id else null;
}

/// Write `sp` as a new file (tmp + fsync + rename) under the apply flock. Under
/// sudo the directory and the file go to `owner`; an existing `plans` that is
/// not a real directory (a planted symlink) is refused.
pub fn storePlan(arena: Allocator, io: Io, icd: []const u8, sp: StoredPlan, owner: ?u32) !void {
	var aw: Io.Writer.Allocating = .init(arena);
	std.json.Stringify.value(sp, .{}, &aw.writer) catch return error.OutOfMemory;
	aw.writer.writeByte('\n') catch return error.OutOfMemory;
	var apply = try applyDir(io, icd, owner);
	defer apply.close(io);
	try snapshot.ensureDir(io, apply, plans_dir, owner);
	var dir = try apply.openDir(io, plans_dir, .{ .follow_symlinks = false });
	defer dir.close(io);
	const name = try std.fmt.allocPrint(arena, "{s}.json", .{sp.plan.id});
	try snapshot.writeNew(io, dir, name, aw.written(), owner);
}

fn parseStoredPlan(arena: Allocator, bytes: []const u8) !StoredPlan {
	return std.json.parseFromSliceLeaky(StoredPlan, arena, bytes, .{ .ignore_unknown_fields = true }) catch error.InvalidPlan;
}

/// The stored plan `id` (FileNotFound when there is none, error.InvalidPlan
/// when it does not parse). It is only read: planAdmits decides.
pub fn readStoredPlan(arena: Allocator, io: Io, icd: []const u8, id: []const u8) !StoredPlan {
	if (!cli.isHex16(id)) return error.InvalidPlan;
	var dir = try snapshot.openIcd(io, icd);
	defer dir.close(io);
	const rel = try std.fmt.allocPrint(arena, "apply/" ++ plans_dir ++ "/{s}.json", .{id});
	return parseStoredPlan(arena, try snapshot.readNoFollow(arena, io, dir, rel, Bounds.plan_file_cap));
}

/// What any stored plan must be, whatever boot reads it: filed under its own
/// id, which is also the id its content hashes to (a hand-edited unit list
/// cannot keep it), for one of the three overridable reasons, with a force
/// list the guest takes.
fn storedPlanValid(arena: Allocator, sp: StoredPlan, id: []const u8) bool {
	if (!cli.isHex16(id) or !std.mem.eql(u8, sp.plan.id, id)) return false;
	const hashed = planId(arena, sp.plan) catch return false;
	if (!std.mem.eql(u8, hashed, id)) return false;
	if (!sp.reason.overridable()) return false;
	_ = forceUnits(arena, sp.plan) catch return false;
	return true;
}

/// The binding (spec section 2 step 2, "Force only"): `--force-plan id` is
/// admitted only for a valid stored plan (storedPlanValid) of this boot (the
/// same qemu.start and host boot), of S's composition, and younger than
/// Bounds.plan_ttl_s by CLOCK_BOOTTIME `now` (a plan from the future, another
/// host boot's clock, is not). The guest phase then still runs only when the
/// re-plan gives this same id.
pub fn planAdmits(arena: Allocator, sp: StoredPlan, id: []const u8, nonce: []const u8, host_boot: []const u8, comp: []const u8, now: i64) bool {
	if (!storedPlanValid(arena, sp, id)) return false;
	if (!std.mem.eql(u8, sp.nonce, nonce) or !std.mem.eql(u8, sp.host_boot, host_boot)) return false;
	if (!std.mem.eql(u8, sp.plan.comp, comp)) return false;
	const age = now - sp.created;
	return age >= 0 and age < Bounds.plan_ttl_s;
}

/// The plan store's GC, run by the apply verb only (it holds both locks; no
/// other verb touches apply/plans). Inside apply/plans it deletes every name
/// starting with `.` (a writer's leftover tmp: every writer holds the apply
/// flock, so none is live), and every `<id>.json` that does not parse or
/// validate, is Bounds.plan_ttl_s old or more, is from the future, or carries
/// another boot nonce or host boot (a null `host_boot`, unreadable here, is not
/// compared); then all but the Bounds.plans_kept newest of the rest, never
/// counting `keep` (the plan this run's --force-plan names, which its binding
/// reads next: the cut would end the run plan_expired). Any other name is left
/// alone. Best-effort.
pub fn prunePlans(arena: Allocator, io: Io, icd: []const u8, nonce: []const u8, host_boot: ?[]const u8, keep: ?[]const u8, now: i64) void {
	var icd_dir = snapshot.openIcd(io, icd) catch return;
	defer icd_dir.close(io);
	var apply = icd_dir.openDir(io, "apply", .{ .follow_symlinks = false }) catch return;
	defer apply.close(io);
	var dir = apply.openDir(io, plans_dir, .{ .follow_symlinks = false, .iterate = true }) catch return;
	defer dir.close(io);
	const Kept = struct {
		name: []const u8,
		created: i64,
		fn newer(_: void, x: @This(), y: @This()) bool {
			if (x.created != y.created) return x.created > y.created;
			return std.mem.order(u8, x.name, y.name) == .gt;
		}
	};
	var drop: std.ArrayList([]const u8) = .empty;
	var kept: std.ArrayList(Kept) = .empty;
	var it = dir.iterate();
	while (it.next(io) catch null) |e| {
		const name = arena.dupe(u8, e.name) catch return;
		if (name.len > 0 and name[0] == '.') {
			drop.append(arena, name) catch return;
			continue;
		}
		const id = planFileId(name) orelse continue;
		const bytes = snapshot.readNoFollow(arena, io, dir, name, Bounds.plan_file_cap) catch {
			drop.append(arena, name) catch return;
			continue;
		};
		const sp = parseStoredPlan(arena, bytes) catch {
			drop.append(arena, name) catch return;
			continue;
		};
		const age = now - sp.created;
		const stale = !storedPlanValid(arena, sp, id) or age < 0 or age >= Bounds.plan_ttl_s or
			!std.mem.eql(u8, sp.nonce, nonce) or (host_boot != null and !std.mem.eql(u8, sp.host_boot, host_boot.?));
		if (stale) {
			drop.append(arena, name) catch return;
			continue;
		}
		if (keep) |k| if (std.mem.eql(u8, id, k)) continue;
		kept.append(arena, .{ .name = name, .created = sp.created }) catch return;
	}
	std.mem.sort(Kept, kept.items, {}, Kept.newer);
	if (kept.items.len > Bounds.plans_kept) {
		for (kept.items[Bounds.plans_kept..]) |k| drop.append(arena, k.name) catch return;
	}
	for (drop.items) |n| dir.deleteFile(io, n) catch {};
}

/// One Apply anyway line of apply/audit.log (spec 4.7, "Audit": cogbox appends
/// the forced run): `admitted` when the binding admitted a plan, under the
/// config lock and before anything is forced; `done` once the run (or the
/// recoverer that resolved it, `recovered`) is over, with whether a forced
/// `start` was attempted (`forced`, also for a plan that relaxes no unit and
/// sent no list), the units it relaxed and the outcome. `uid` is the invoking
/// user (the real uid under sudo), `euid` the effective one.
pub const ForceAudit = struct {
	event: []const u8 = "force",
	phase: enum { admitted, done },
	at: i64,
	gen: []const u8,
	op: ?[]const u8 = null,
	uid: u32,
	euid: u32,
	plan: []const u8,
	forced: ?bool = null,
	units: []const []const u8,
	result: ?Result = null,
	reason: ?Reason = null,
	recovered: ?bool = null,
};

/// Append `line` to apply/audit.log (rollback.audit, positional: the caller
/// holds the config lock). A failure warns and never fails the run.
fn appendForceAudit(arena: Allocator, io: Io, icd: []const u8, owner: ?u32, line: ForceAudit) void {
	var aw: Io.Writer.Allocating = .init(arena);
	std.json.Stringify.value(line, .{ .emit_null_optional_fields = false }, &aw.writer) catch return;
	aw.writer.writeByte('\n') catch return;
	rollback.audit(arena, io, icd, aw.written(), owner) catch |err| {
		warnf(arena, io, "could not write apply/{s} ({s})", .{ rollback.audit_file, @errorName(err) });
	};
}

fn auditUid(real_uid: ?u32) u32 {
	return real_uid orelse std.c.getuid();
}

// --- the run --------------------------------------------------------------------------------

/// One `cogbox plugin apply` run (the run mode). Everything allocates in
/// `arena`, which lives as long as the verb. Public for the guest-phase tests
/// (apply_guest_test.zig), which build one as preflight and the build leave it.
pub const Run = struct {
	ctx: *const plugin.Ctx,
	arena: Allocator,
	io: Io,
	args: cli.ApplyArgs,
	host: Host,
	icd: []const u8,
	owner: ?u32,
	gen: snapshot.Id,
	scratch_id: snapshot.Id,
	/// The whole-verb deadline (awake ms), from process start.
	whole_deadline_ms: i64,
	/// The build's deadline once it started.
	build_deadline_ms: i64 = 0,
	config_held: bool,
	flock_held: bool = false,
	active_written: bool = false,
	phase: Phase = .preflight,
	/// The deadline apply/active carries now (CLOCK_BOOTTIME seconds).
	active_deadline: i64 = 0,
	/// The running stage's unit already reported its InvocationID.
	stage_invocation_seen: bool = false,
	key: []const u8 = "",
	nonce: []const u8 = "",
	cap: ?Cap = null,
	identity: ?Identity = null,
	base: ?snapshot.Snapshot = null,
	s: ?snapshot.Snapshot = null,
	s_taken: bool = false,
	scope_live: []const snapshot.ScopeEntry = &.{},
	eval_target: rollback.Target = .base,
	eval_target_id: []const u8 = "",
	scope_eval: []const snapshot.ScopeEntry = &.{},
	stage_a_ok: bool = false,
	runner: ?[]const u8 = null,
	toplevel: ?[]const u8 = null,
	/// The build unit's name (unit containment), in apply/active from the
	/// write that names S on, before any systemd-run.
	unit: ?[]const u8 = null,
	/// The running stage's InvocationID as systemd-run reported it, else null
	/// (diagnostic only: systemd-run --wait often prints none).
	invocation: ?[]const u8 = null,
	/// A build stage's unit may still run: systemd-run did not report its end
	/// (the loop stopped it, a signal ended it first, or it died without its
	/// `Finished with result:` line) and no stop of it was confirmed.
	/// apply/active, its only record, then stays when the verb exits.
	unit_live: bool = false,
	build_log: std.ArrayList(u8) = .empty,
	/// Set by a stop for the whole-verb timer (failed/timeout, not build_timeout).
	whole_timer_fired: bool = false,
	/// A pending rollback that cannot finish blocks this apply (exit 78, the
	/// stamped message on stderr, no report).
	blocked: bool = false,
	exit_code: u8 = 0,
	/// The guest phase's timing (only the tests change it).
	gcfg: GuestCfg = .{},
	/// The guest phase, from the flip to `phase: guest` on.
	guest: ?GuestRun = null,
	/// apply/inflight.json was written (deleted at the record, or left for a
	/// recoverer on the terminate path).
	inflight_written: bool = false,
	/// The confirmed record could not run (the step-10 lock was not had, the
	/// boot could not be told) or failed part-way, or the poll expired while
	/// the boot could not be told: G keeps inflight.json, so a recoverer
	/// performs its record.
	keep_inflight: bool = false,
	/// The host's boot id, read at preflight (null: unreadable): the plan store
	/// and inflight.json carry it.
	host_boot: ?[]const u8 = null,
	/// Apply anyway: the stored plan `--force-plan` was admitted for at
	/// preflight (admitForcePlan); its admission is in audit.log.
	force_admitted: ?StoredPlan = null,
	/// What this run forces, once the re-plan gave the admitted id (null for a
	/// plain run, and for a forced run whose re-plan needed no force), and
	/// whether the guest runs the repair.
	forced: ?Forced = null,
	force_repair: bool = false,

	fn env(r: *const Run) *const std.process.Environ.Map {
		return r.ctx.parent_env;
	}

	fn activeRecord(r: *const Run, deadline: i64) Active {
		return .{
			.pid = if (is_linux) linux.getpid() else 0,
			.starttime = if (is_linux) procStarttime(r.arena, r.io, linux.getpid()) else null,
			.unit = r.unit,
			.invocation = r.invocation,
			.op = r.args.op,
			.gen = &r.gen,
			.scratch_id = &r.scratch_id,
			.phase = r.phase,
			.deadline = deadline,
		};
	}

	/// Rewrite apply/active. Best-effort for a phase change (a gate that cannot
	/// read it waits without a bound, the safe direction); setActiveStrict for
	/// the writes that must land.
	fn setPhase(r: *Run, phase: Phase, deadline: i64) void {
		r.setActiveStrict(phase, deadline) catch |err| {
			warnf(r.arena, r.io, "could not update apply/active ({s})", .{@errorName(err)});
		};
	}

	/// The writes the apply cannot go on without: the first one (the gate and
	/// --status find the holder by it) and the one that names S (the snapshot
	/// GC keeps S only while apply/active names it).
	fn setActiveStrict(r: *Run, phase: Phase, deadline: i64) !void {
		r.phase = phase;
		r.active_deadline = deadline;
		try writeActive(r.arena, r.io, r.icd, r.activeRecord(deadline), r.owner);
		r.active_written = true;
		noteDurable(.active);
	}

	fn wholeLeftMs(r: *const Run) i64 {
		return r.whole_deadline_ms - nowMs(r.io);
	}

	/// Whether the instance still runs the boot preflight saw (no host boot
	/// check: a host reboot stops QEMU). Only `changed` ends anything: on
	/// `unknown` (a transient qemu.start read failure on a running instance)
	/// the watch and the poll go on, the next check tells, and every guest hop
	/// carries the boot id, so a guest that booted again answers stale_boot.
	fn bootNow(r: *Run) BootState {
		return bootState(r.arena, r.ctx, r.nonce, null);
	}

	/// The watch: false once the instance stopped or runs another boot.
	fn watch(r: *Run) Watch {
		return .{ .ctx = r, .check = struct {
			fn f(p: *anyopaque) bool {
				const self: *Run = @ptrCast(@alignCast(p));
				return self.bootNow() != .changed;
			}
		}.f };
	}

	fn appendLog(r: *Run, label: []const u8, cap: *const Capture) void {
		const a = r.arena;
		r.build_log.appendSlice(a, "== ") catch return;
		r.build_log.appendSlice(a, label) catch return;
		r.build_log.appendSlice(a, " ==\n") catch return;
		r.build_log.appendSlice(a, cap.data()) catch return;
		if (cap.truncated()) {
			r.build_log.appendSlice(a, "\n[... output truncated ...]\n") catch return;
			r.build_log.appendSlice(a, cap.tail(a)) catch return;
		}
		if (r.build_log.items.len > 0 and r.build_log.items[r.build_log.items.len - 1] != '\n') r.build_log.append(a, '\n') catch return;
		r.flushLog();
	}

	/// `<icd>/apply/<G>.build.log`, the last Bounds.build_log_cap bytes.
	fn flushLog(r: *Run) void {
		const items = r.build_log.items;
		const keep = items[items.len -| Bounds.build_log_cap ..];
		const name = std.fmt.allocPrint(r.arena, "{s}.build.log", .{&r.gen}) catch return;
		writeApplyFile(r.arena, r.io, r.icd, name, keep, r.owner) catch |err| {
			warnf(r.arena, r.io, "could not write apply/{s} ({s})", .{ name, @errorName(err) });
		};
	}
};

/// The CLI's entry for every apply subcommand. Returns the exit code.
pub fn run(ctx: *const plugin.Ctx, args: cli.ApplyArgs, host: Host) u8 {
	var arena_state = std.heap.ArenaAllocator.init(ctx.allocator);
	defer arena_state.deinit();
	const arena = arena_state.allocator();
	return switch (args.mode) {
		.run => if (args.force) runForce(arena, ctx, args, host) else runApply(arena, ctx, args, host),
		.status => runStatus(arena, ctx, args, host),
		.cancel => runCancel(arena, ctx, args, host),
		.log => runLog(arena, ctx, args, host),
		.abandon => runAbandon(arena, ctx, args, host),
	};
}

/// The whole-verb timer (COGBOX_APPLY_TIMEOUT, 5340 s by default; the GCE/PVE
/// wrapper bakes the same default, and a caller's value wins).
pub fn wholeSeconds(env: *const std.process.Environ.Map) i64 {
	return envSeconds(env, "COGBOX_APPLY_TIMEOUT", Bounds.whole_s);
}

fn icdOf(ctx: *const plugin.Ctx) []const u8 {
	return std.fs.path.dirname(ctx.plugins_flake_dir) orelse ".";
}

fn currentKey(arena: Allocator, ctx: *const plugin.Ctx) ?[]const u8 {
	const src = ctx.parent_env.get("COGBOX_FLAKE_SOURCE") orelse return null;
	return std.fmt.allocPrint(arena, "{s}#{s}", .{ src, plugin.reexecPackage(ctx) }) catch null;
}

/// The refusals of `apply --force` (exit 64), the interactive Apply anyway.
/// It shows the plan on stderr and reads the answer from stdin, so it needs
/// both on a terminal (stdin alone would let `2>/dev/null` hide the list being
/// consented to); and it can run up to four applies, so it takes no --json
/// (one report line per invocation): a caller that is not a person passes the
/// reported plan id with `--force-plan`, a plain run. The dispatcher prints
/// them before it opens or waits for any lock; forceLoop checks again.
pub const force_needs_tty = "apply --force shows the plan and asks on a terminal (stdin and stderr); without one, pass the plan id an apply reported: --force-plan PLAN";
pub const force_json_refused = "apply --force is interactive and takes no --json; use --force-plan PLAN";

/// Whether stdin and stderr are both terminals, as `apply --force` needs.
pub fn forceTerminals(io: Io) bool {
	return (Io.File.stdin().isTty(io) catch false) and (Io.File.stderr().isTty(io) catch false);
}

fn runApply(arena: Allocator, ctx: *const plugin.Ctx, args: cli.ApplyArgs, host: Host) u8 {
	const io = ctx.io;
	ignoreSigpipe();
	const started = host.started orelse Io.Timestamp.now(io, .awake);
	const whole_s = wholeSeconds(ctx.parent_env);
	var r: Run = .{
		.ctx = ctx,
		.arena = arena,
		.io = io,
		.args = args,
		.host = host,
		.icd = icdOf(ctx),
		.owner = ctx.real_uid,
		.gen = snapshot.newId(io),
		.scratch_id = snapshot.newId(io),
		.whole_deadline_ms = started.toMilliseconds() + whole_s * 1000,
		.config_held = host.config_held,
		.gcfg = guestCfgOf(ctx.parent_env),
	};
	const o = applyFlow(&r);
	return finish(&r, o);
}

/// Preflight through the plan and the guest phase. Returns the outcome; finish
/// records and reports it.
fn applyFlow(r: *Run) Outcome {
	const io = r.io;
	const arena = r.arena;
	// The dispatcher's timed config-lock wait ran out: another holder (a long
	// plugin op, a booting launcher) has it.
	if (!r.config_held) return Outcome.of(.failed, .busy);
	if (comptime !is_linux) return Outcome.of(.restart_required, .unsupported_platform);

	// The apply flock, never waited for under the config lock (spec 4.8 lock
	// order). Held: an apply or a plugin change is running.
	r.flock_held = tryFlock(r.host.apply_fd) catch false;
	if (!r.flock_held) return Outcome.of(.failed, .busy);

	if (r.ctx.parent_env.get("COGBOX_LIVE_APPLY")) |v| {
		if (std.mem.eql(u8, v, "0")) return Outcome.of(.restart_required, .disabled);
	}

	// A build unit a dead apply left running (its apply/active still names it)
	// is an orphan: holding the apply flock proves no live apply owns the
	// name, so it is stopped by that name. A stop that cannot be confirmed
	// keeps apply/active, the unit's only record, and the apply waits.
	if (!stopOrphanBuild(r)) return Outcome.of(.failed, .busy);

	r.setActiveStrict(.preflight, bootSeconds(io) + Bounds.preflight_s) catch |err| {
		warnf(arena, io, "could not write apply/active ({s})", .{@errorName(err)});
		return Outcome.of(.failed, .snapshot);
	};
	pruneBuildLogs(r);

	// Pending work first: an orphaned inflight.json, then any pending intent,
	// in one finish (the recovery's, when it ran one).
	var rec_fin: ?rollback.FinishResult = null;
	if (inflightExists(io, r.icd)) {
		const rec = recoverInflight(r.arena, r.ctx, .{ .holds_config_lock = true, .ssh_identity = r.host.ssh_identity, .fin_out = &rec_fin });
		if (terminate.load(.acquire) != 0) exitOnTerminate(r);
		switch (rec) {
			.resolved => {},
			.unresolved => return Outcome.with(.failed, .busy, &.{"inflight_unresolved"}),
		}
	}
	{
		const fin = rec_fin orelse blk: {
			const f = rollback.finishPending(arena, r.ctx, .{ .holds_apply_flock = true });
			writeFinishWarnings(arena, io, f);
			break :blk f;
		};
		if (fin.pending > 0) {
			r.blocked = true;
			var buf: [512]u8 = undefined;
			var w: Io.Writer = .fixed(&buf);
			rollback.writePendingMessage(&w, fin.pending_error orelse error.RollbackPending, r.ctx.instance) catch {};
			errOut(io, w.buffered());
			return Outcome.of(.failed, .busy);
		}
	}

	if (!plugin.isRunning(r.ctx)) return Outcome.of(.not_running, null);
	r.key = currentKey(arena, r.ctx) orelse return Outcome.of(.restart_required, .no_boot_record);
	const nonce = readNonce(arena, io, r.ctx.runtime_path);
	switch (checkIdentity(arena, io, r.icd, r.ctx.runtime_path, r.key, nonce)) {
		.refuse => |why| return Outcome.of(.restart_required, why),
		.ok => |ok| {
			r.identity = ok.identity;
			r.base = ok.base;
		},
	}
	if (!snapshot.compositionConsistent(arena, &r.base.?)) return Outcome.of(.restart_required, .composition_stale);

	var loaded = config.load(arena, io, r.ctx.config_path) catch return Outcome.of(.failed, .snapshot);
	const plugins_n = blk: {
		const root = loaded.root().*;
		if (root != .object) break :blk 0;
		const p = root.object.get("plugins") orelse break :blk 0;
		break :blk if (p == .array) p.array.items.len else 0;
	};
	if (plugins_n == 0 and userFlakeCustomized(arena, io, r.ctx.user_flake_dir)) return Outcome.of(.restart_required, .customized_flake);

	r.nonce = nonce orelse return Outcome.of(.restart_required, .booting);
	// The boot this run is in, as the plan store and inflight.json name it;
	// plans of any other boot (or too old) go now, the one this run's
	// --force-plan names never for the count alone.
	r.host_boot = hostBootId(arena, io);
	prunePlans(arena, io, r.icd, r.nonce, r.host_boot, r.args.force_plan, bootSeconds(io));

	if (r.ctx.parent_env.get("COGBOX_ENVIRONMENT")) |e| {
		if (std.mem.eql(u8, e, "cogworx")) {
			const net = objGet(loaded.root().*, "network");
			if (net != null and net.? == .string and std.mem.eql(u8, net.?.string, "none")) return Outcome.of(.restart_required, .air_gapped);
		}
	}

	const min_avail = envMb(r.ctx.parent_env, "COGBOX_APPLY_MIN_AVAILABLE_MB", Bounds.min_available_mb) << 20;
	const avail = memAvailable(arena, io) orelse 0;
	if (avail < min_avail) return Outcome.of(.restart_required, .insufficient_memory);
	if (!diskAboveFloor(r)) return Outcome.of(.restart_required, .insufficient_disk);

	r.cap = detectCap(r.ctx.parent_env) orelse return Outcome.of(.restart_required, .no_containment);
	nameBuildUnit(r) catch return Outcome.of(.failed, .build);

	if (plugins_n > 0) {
		if (userFlakeCheck(r)) |o| return o;
	}

	// S, the scratch snapshot. take() picks its id; apply/active names it
	// before the config lock is released, and the snapshot GC only runs under
	// that lock, so nothing can collect S while this apply runs.
	r.scratch_id = snapshot.take(arena, io, r.icd, loaded.root().*, .{ .budget_ms = Bounds.snapshot_ms, .owner = r.owner }) catch |err| {
		warnf(arena, io, "could not snapshot the plugin state ({s})", .{@errorName(err)});
		return Outcome.of(.failed, .snapshot);
	};
	// The deadline stays the one preflight began with (spec section 2 step 2):
	// naming S does not extend the gate's wait. Under unit containment this
	// write also names the build unit, before any systemd-run.
	r.setActiveStrict(.preflight, r.active_deadline) catch |err| {
		warnf(arena, io, "could not name the snapshot in apply/active ({s})", .{@errorName(err)});
		return Outcome.of(.failed, .snapshot);
	};
	r.s = snapshot.read(arena, io, r.icd, &r.scratch_id) catch return Outcome.of(.failed, .snapshot);
	r.s_taken = true;
	if (!snapshot.compositionConsistent(arena, &r.s.?)) return Outcome.of(.restart_required, .composition_stale);

	// The rollback scopes, computed while S, B and K are all readable: against
	// B for a live rejection, against K (else B) for an eval_error.
	r.scope_live = snapshot.scope(arena, r.s.?.plugins, r.base.?.plugins) catch return Outcome.of(.failed, .snapshot);
	r.eval_target = .base;
	r.eval_target_id = arena.dupe(u8, &r.identity.?.base_id) catch return Outcome.of(.failed, .snapshot);
	r.scope_eval = r.scope_live;
	if (snapshot.roleId(io, r.icd, .built)) |kid| {
		if (snapshot.read(arena, io, r.icd, &kid)) |k| {
			r.eval_target = .built;
			r.eval_target_id = arena.dupe(u8, &kid) catch return Outcome.of(.failed, .snapshot);
			r.scope_eval = snapshot.scope(arena, r.s.?.plugins, k.plugins) catch return Outcome.of(.failed, .snapshot);
		} else |_| {}
	}

	if (admitForcePlan(r)) |o| return o;

	// Release the config lock (the apply flock stays held) and enter the build
	// phase: from here a plugin change supersedes this apply.
	unlockFd(r.host.config_fd);
	r.config_held = false;
	r.setPhase(.build, bootSeconds(io) + @divTrunc(@max(r.wholeLeftMs(), 0), 1000));

	return buildAndPlan(r);
}

/// Force only (spec section 2 step 2), the last preflight check, under the
/// config lock: `--force-plan id` needs a stored plan planAdmits takes, else
/// the run ends restart_required/plan_expired before anything is built or the
/// guest is asked. The admission is appended to audit.log here, under the
/// config lock and before anything is forced.
fn admitForcePlan(r: *Run) ?Outcome {
	const id = r.args.force_plan orelse return null;
	const expired = Outcome.of(.restart_required, .plan_expired);
	const host_boot = r.host_boot orelse return expired;
	const sp = readStoredPlan(r.arena, r.io, r.icd, id) catch return expired;
	if (!planAdmits(r.arena, sp, id, r.nonce, host_boot, r.s.?.meta.comp, bootSeconds(r.io))) return expired;
	r.force_admitted = sp;
	appendForceAudit(r.arena, r.io, r.icd, r.owner, .{
		.phase = .admitted,
		.at = Io.Timestamp.now(r.io, .real).toSeconds(),
		.gen = &r.gen,
		.op = r.args.op,
		.uid = auditUid(r.owner),
		.euid = std.c.geteuid(),
		.plan = sp.plan.id,
		.units = forceUnits(r.arena, sp.plan) catch &.{},
		.reason = sp.reason,
	});
	return null;
}

fn diskAboveFloor(r: *Run) bool {
	const floor = envMb(r.ctx.parent_env, "COGBOX_APPLY_MIN_FREE_MB", Bounds.min_free_mb) << 20;
	const free = freeBytes(r.arena, r.icd) orelse return false;
	return free >= floor;
}

/// The user flake (spec section 2 step 2): `nix hash path <icd>/flake`, bounded
/// at 30 s, must equal the composition lock's `user` narHash; the launcher
/// re-pins it at boot otherwise. Null when it matches.
fn userFlakeCheck(r: *Run) ?Outcome {
	const arena = r.arena;
	const lock_path = std.fs.path.join(arena, &.{ r.ctx.plugins_flake_dir, "flake.lock" }) catch return Outcome.of(.failed, .inputs_changed);
	const lock = readSmall(arena, r.io, lock_path, snapshot.max_flake_bytes) catch return Outcome.of(.restart_required, .user_flake_changed);
	const want = userLockedNarHash(arena, lock) orelse return Outcome.of(.restart_required, .user_flake_changed);
	const res = runChild(arena, r.io, .{
		.argv = &.{ "nix", "--extra-experimental-features", "nix-command flakes", "hash", "path", r.ctx.user_flake_dir },
		.env = r.env(),
		.deadline_ms = @min(nowMs(r.io) + Bounds.user_flake_ms, r.whole_deadline_ms),
		.out_cap = 4096,
		.err_cap = 16 << 10,
	});
	if (res.stopped == .terminate) exitOnTerminate(r);
	if (!res.exitedWith(0)) return Outcome.of(.failed, .inputs_changed);
	const got = std.mem.trim(u8, res.stdout.data(), " \t\r\n");
	if (!std.mem.eql(u8, got, want)) return Outcome.of(.restart_required, .user_flake_changed);
	return null;
}

/// The terminate flag before `start` (spec 4.8): stop the build unit, clear
/// apply/active and exit at once (128 + the signal). Nothing is reported: no
/// outcome was reached, and nothing of the guest was touched. From `start` on
/// the guest phase returns its terminate path through the flow instead
/// (guestTerminate); a call here then takes that path too.
fn exitOnTerminate(r: *Run) noreturn {
	if (r.inflight_written) {
		const x = guestTerminate(r, false);
		std.process.exit(exitNow(r, x.exit_now.?));
	}
	std.process.exit(terminateBuild(r));
}

/// exitOnTerminate before `start`, short of the exit (public for the tests):
/// stop the build unit a stage left running, under the flag (the stop is
/// bounded by its own Bounds.systemctl_ms, not cut at the loop's slice), and
/// clear apply/active only once nothing of this run's build can still run.
/// When the stop is not confirmed, apply/active stays as the record of the
/// unit: its holder is dead, so no gate waits on it, and the next preflight,
/// `apply --cancel`, `cogbox delete` and the preboot stop the unit by the
/// name it records. Returns the exit code (128 + the signal).
pub fn terminateBuild(r: *Run) u8 {
	if (r.unit_live) {
		const stopped = if (r.unit) |u| systemctlStop(r, u) else true;
		if (stopped) r.unit_live = false;
	}
	if (r.active_written and !r.unit_live) clearActive(r.io, r.icd);
	const sig = terminate.load(.acquire);
	return 128 +| sig;
}

/// The build phase's checkpoint: the terminate flag exits, the supersede flag
/// ends the apply superseded, the whole-verb timer ends it failed/timeout.
fn checkpoint(r: *Run) ?Outcome {
	if (terminate.load(.acquire) != 0) exitOnTerminate(r);
	if (r.phase == .build and supersede.load(.acquire) != 0) return Outcome.of(.superseded, null);
	if (r.wholeLeftMs() <= 0) return Outcome.of(.failed, .timeout);
	return null;
}

/// What a stop by the loop means for the run (null: not stopped).
fn stopOutcome(r: *Run, stopped: ?Stop, deadline_is_build: bool) ?Outcome {
	const s = stopped orelse return null;
	return switch (s) {
		.terminate => exitOnTerminate(r),
		.supersede, .watch => Outcome.of(.superseded, null),
		.deadline => if (deadline_is_build) null else Outcome.of(.failed, .timeout),
		.overflow => null,
	};
}

/// Preflight, under the apply flock: stop the build unit a dead apply's
/// apply/active still names, by that name (stopActiveUnit; an unreadable
/// record by this instance's own unit name). True when no record names a
/// unit, or nothing of it can run any more; false keeps the record, which
/// this apply must not overwrite.
fn stopOrphanBuild(r: *Run) bool {
	return stopActiveUnit(r.arena, r.io, r.env(), r.icd, readActiveForStop(r.arena, r.io, r.icd)) != .failed;
}

/// Under unit containment, the build unit's name, set before anything records
/// it: the strict write that names S then records it, so apply/active names
/// the unit before any systemd-run starts it, and a stopper finds an orphan by
/// that record alone (public for the tests).
pub fn nameBuildUnit(r: *Run) !void {
	if (r.cap == .unit) r.unit = try buildUnitName(r.arena, r.icd);
}

/// `systemctl stop --no-block <unit>`, bounded by Bounds.systemctl_ms and run
/// through the terminate flag: the terminate path is the one that needs it,
/// and a slow PID 1 (a host the build itself loads) must not cut it at the
/// loop's slice. True when the stop was queued, or the unit is not loaded
/// (nothing to stop); otherwise the unit's own RuntimeMaxSec still ends it.
fn systemctlStop(r: *Run, unit: []const u8) bool {
	if (comptime !is_linux) return true;
	const res = runChild(r.arena, r.io, .{
		.argv = &.{ "systemctl", "stop", "--no-block", unit },
		.env = r.env(),
		.deadline_ms = nowMs(r.io) + Bounds.systemctl_ms,
		.out_cap = 1024,
		.err_cap = 4096,
		.ignore_terminate = true,
	});
	if (res.exitedWith(0)) return true;
	if (res.exit != null and std.mem.indexOf(u8, res.stderr.data(), " not loaded") != null) return true;
	warnf(r.arena, r.io, "could not stop {s}", .{unit});
	return false;
}

/// Keep the newest Bounds.build_logs_kept - 1 build logs, and as many guest
/// logs, leaving room for this run's own.
fn pruneBuildLogs(r: *Run) void {
	pruneLogs(r, ".build.log");
	pruneLogs(r, ".guest.log");
}

fn pruneLogs(r: *Run, suffix: []const u8) void {
	var icd_dir = snapshot.openIcd(r.io, r.icd) catch return;
	defer icd_dir.close(r.io);
	var dir = icd_dir.openDir(r.io, "apply", .{ .follow_symlinks = false, .iterate = true }) catch return;
	defer dir.close(r.io);
	const Ent = struct { name: []const u8, mtime: i96 };
	var logs: std.ArrayList(Ent) = .empty;
	var it = dir.iterate();
	while (it.next(r.io) catch null) |e| {
		if (e.kind != .file or !std.mem.endsWith(u8, e.name, suffix)) continue;
		const st = dir.statFile(r.io, e.name, .{ .follow_symlinks = false }) catch continue;
		logs.append(r.arena, .{ .name = r.arena.dupe(u8, e.name) catch continue, .mtime = st.mtime.nanoseconds }) catch continue;
	}
	if (logs.items.len < Bounds.build_logs_kept) return;
	std.mem.sort(Ent, logs.items, {}, struct {
		fn lt(_: void, a: Ent, b: Ent) bool {
			return a.mtime > b.mtime;
		}
	}.lt);
	// Keep room for this run's own log.
	for (logs.items[Bounds.build_logs_kept - 1 ..]) |e| dir.deleteFile(r.io, e.name) catch {};
}

fn writeFinishWarnings(arena: Allocator, io: Io, fin: rollback.FinishResult) void {
	var aw: Io.Writer.Allocating = .init(arena);
	rollback.writeWarnings(&aw.writer, fin.warnings) catch return;
	errOut(io, aw.written());
}

// --- the build --------------------------------------------------------------------------------

const BuildStage = struct {
	exit: StageExit,
	stdout: []const u8,
};

/// Run one build stage under the run's containment and the build bound
/// (public for the tests).
pub fn runStage(r: *Run, label: []const u8, inner: []const []const u8) !BuildStage {
	const arena = r.arena;
	const now = nowMs(r.io);
	const left_ms = r.build_deadline_ms - now;
	const deadline = @min(r.build_deadline_ms, r.whole_deadline_ms);
	if (deadline <= now) {
		r.whole_timer_fired = r.whole_deadline_ms <= r.build_deadline_ms;
		return .{ .exit = .{ .exit = null, .stopped = .deadline, .stderr = "" }, .stdout = "" };
	}
	var argv = inner;
	if (r.cap == .unit) {
		const unit = r.unit orelse unreachable;
		const avail = memAvailable(arena, r.io) orelse Bounds.memory_headroom * 2;
		const mem_max = avail -| Bounds.memory_headroom;
		argv = try unitArgv(arena, unit, @divTrunc(left_ms + 999, 1000), @max(mem_max, 256 << 20), r.env(), inner);
	}
	// The unit's own RuntimeMaxSec ends it; the loop's deadline is the backstop
	// (a little later, so the unit's Result=timeout is what is seen).
	const grace: i64 = if (r.cap == .unit) 15_000 else 0;
	// Each stage is a new run of the unit: apply/active names this stage's
	// InvocationID or none, never an earlier stage's.
	r.stage_invocation_seen = false;
	if (r.invocation != null) {
		r.invocation = null;
		r.setPhase(r.phase, r.active_deadline);
	}
	const res = runChild(arena, r.io, .{
		.argv = argv,
		.env = r.env(),
		.deadline_ms = if (deadline == r.build_deadline_ms) deadline + grace else deadline,
		.out_cap = 64 << 10,
		.err_cap = 256 << 10,
		.honour_supersede = r.phase == .build,
		.watch = r.watch(),
		.on_stderr = if (r.cap == .unit) .{ .ctx = r, .f = noteInvocation } else null,
	});
	if (res.spawn_error) |err| {
		warnf(arena, r.io, "could not start the {s} stage ({s})", .{ label, @errorName(err) });
		return error.SpawnFailed;
	}
	// systemd-run --wait prints `Finished with result:` only once it saw its
	// unit end (or never started one). One the loop stopped, that a terminate
	// signal ended first, or that died without that line (killed on its own,
	// its bus lost) may leave the unit running: the terminate path stops it
	// (terminateBuild), any other end is stopped here.
	const tail = res.stderr.tail(arena);
	r.unit_live = r.cap == .unit and (res.stopped != null or unitResult(tail) == null);
	if (r.unit_live and res.stopped != .terminate) {
		if (systemctlStop(r, r.unit.?)) r.unit_live = false;
	}
	r.appendLog(label, &res.stderr);
	var stopped = res.stopped;
	if (stopped == .deadline and r.whole_deadline_ms < r.build_deadline_ms and nowMs(r.io) >= r.whole_deadline_ms) r.whole_timer_fired = true;
	if (stopped == .overflow) stopped = null;
	return .{
		.exit = .{
			.exit = res.exit,
			.stopped = stopped,
			.unit_result = if (r.cap == .unit) unitResult(tail) else null,
			.stderr = stripAnsi(arena, res.stderr.data()),
			.stderr_truncated = res.stderr.truncated(),
		},
		.stdout = res.stdout.data(),
	};
}

/// The build unit's InvocationID, from systemd-run's `Running as unit` line,
/// into apply/active as soon as it is printed (best-effort). A diagnostic:
/// systemd-run --wait prints it only when PID 1 ran the start job before it
/// read the property, so the line often has none, and every stopper stops the
/// unit by its name instead (stopBuildUnit). Each stage is a new unit run, so
/// each records its own (runStage clears the last one first).
fn noteInvocation(p: *anyopaque, stderr: []const u8) void {
	const r: *Run = @ptrCast(@alignCast(p));
	if (r.stage_invocation_seen) return;
	const inv = unitInvocation(stderr) orelse return;
	r.stage_invocation_seen = true;
	r.invocation = r.arena.dupe(u8, inv) catch return;
	r.setPhase(r.phase, r.active_deadline);
}

fn substituters(r: *Run) []const u8 {
	const arena = r.arena;
	const extra = r.ctx.parent_env.get("COGBOX_EXTRA_SUBSTITUTERS") orelse "";
	const cache = if (pathExists(r.io, r.ctx.cache_dir)) std.fmt.allocPrint(arena, "file://{s}", .{r.ctx.cache_dir}) catch "" else "";
	if (cache.len > 0 and extra.len > 0) return std.fmt.allocPrint(arena, "{s} {s}", .{ cache, extra }) catch cache;
	return if (cache.len > 0) cache else extra;
}

fn stageOutcome(r: *Run, class: StageClass, stopped: ?Stop) Outcome {
	if (stopOutcome(r, stopped, true)) |o| return o;
	if (stopped == .deadline and r.whole_timer_fired) return Outcome.of(.failed, .timeout);
	return switch (class) {
		.ok, .eval_candidate => unreachable,
		.inputs_changed => Outcome.of(.failed, .inputs_changed),
		.inputs_uncached => Outcome.of(.failed, .build_inputs_uncached),
		.build => Outcome.of(.failed, .build),
		.build_timeout => if (r.whole_timer_fired) Outcome.of(.failed, .timeout) else Outcome.of(.failed, .build_timeout),
		.oom => Outcome.of(.restart_required, .insufficient_memory),
	};
}

/// Steps 3 to 8: the build, tier 1, tier 2 and the guest phase.
fn buildAndPlan(r: *Run) Outcome {
	const arena = r.arena;
	const io = r.io;
	// The trash, emptied while no lock but the apply flock is held (bounded,
	// ended by the supersede and terminate flags).
	{
		const tr = snapshot.emptyTrashUntil(arena, io, r.icd, Bounds.trash_ms, stopRequested);
		if (tr.outcome == .failed) warnf(arena, io, "could not empty apply/trash ({s})", .{if (tr.first_error) |e| @errorName(e) else "unknown"});
	}
	if (checkpoint(r)) |o| return o;

	const build_s = envSeconds(r.ctx.parent_env, "COGBOX_APPLY_BUILD_TIMEOUT", Bounds.build_s);
	r.build_deadline_ms = nowMs(io) + build_s * 1000;

	const s = &r.s.?;
	if (s.plugins.len > 0 and s.flake_nix == null) {
		// The launcher refuses to boot this state ("lists N plugin(s) but
		// plugins-flake/flake.nix is missing"); nothing here can be built.
		return Outcome.with(.failed, .build, &.{"no_composition"});
	}
	if (s.plugins.len == 0) {
		// No plugins: the target is the image's own base runner; nothing builds.
		const base_runner = r.ctx.parent_env.get("COGBOX_BASE_RUNNER") orelse return Outcome.with(.failed, .build, &.{"no_base_runner"});
		if (!isStorePath(base_runner)) return Outcome.with(.failed, .build, &.{"no_base_runner"});
		r.runner = base_runner;
		r.stage_a_ok = true;
	} else {
		const comp_dir = std.fmt.allocPrint(arena, "{s}/apply/snap/{s}/composition", .{ r.icd, &r.scratch_id }) catch return Outcome.of(.failed, .build);
		const flake_source = r.ctx.parent_env.get("COGBOX_FLAKE_SOURCE") orelse return Outcome.of(.failed, .build);
		const nixpkgs_source = r.ctx.parent_env.get("COGBOX_NIXPKGS_SOURCE") orelse return Outcome.with(.failed, .build, &.{"no_nixpkgs_source"});
		const b: nix.ApplyBuild = .{
			.flake_source = flake_source,
			.nixpkgs_source = nixpkgs_source,
			.composition_dir = comp_dir,
			.arch = archName(),
			.reexec_package = plugin.reexecPackage(r.ctx),
			.substituters = substituters(r),
			.trusted_public_keys = r.ctx.parent_env.get("COGBOX_EXTRA_TRUSTED_PUBLIC_KEYS") orelse "",
			.netrc_file = r.ctx.parent_env.get("COGBOX_NETRC_FILE") orelse "",
		};
		const inst_argv = nix.applyInstantiateArgv(arena, b) catch return Outcome.with(.failed, .build, &.{"unknown_package"});
		const first = runStage(r, "instantiate", inst_argv) catch return Outcome.of(.failed, .build);
		var drv: []const u8 = undefined;
		switch (classifyInstantiate(first.exit)) {
			.ok => drv = std.mem.trim(u8, first.stdout, " \t\r\n"),
			.eval_candidate => {
				if (checkpoint(r)) |o| return o;
				const second = runStage(r, "instantiate (reproduction)", inst_argv) catch return Outcome.of(.failed, .build);
				switch (classifyInstantiate(second.exit)) {
					// Not reproduced: nothing is proven.
					.ok => return Outcome.of(.failed, .build),
					.eval_candidate => {},
					else => |c| return stageOutcome(r, c, second.exit.stopped),
				}
				if (reproduced(arena, first.exit, second.exit)) return evalError(r);
				return Outcome.of(.failed, .build);
			},
			else => |c| return stageOutcome(r, c, first.exit.stopped),
		}
		if (!isStorePath(drv) or !std.mem.endsWith(u8, drv, ".drv")) return Outcome.of(.failed, .build);
		r.stage_a_ok = true;
		if (checkpoint(r)) |o| return o;

		const out_link = gcrootFor(r) catch return Outcome.of(.failed, .build);
		const real_argv = nix.applyRealiseArgv(arena, b, drv, out_link) catch return Outcome.of(.failed, .build);
		const realise = runStage(r, "realise", real_argv) catch return Outcome.of(.failed, .build);
		switch (classifyRealise(realise.exit)) {
			.ok => {},
			else => |c| return stageOutcome(r, c, realise.exit.stopped),
		}
		var lbuf: [std.fs.max_path_bytes]u8 = undefined;
		const n = Io.Dir.cwd().readLink(io, out_link, &lbuf) catch return Outcome.of(.failed, .build);
		const runner = arena.dupe(u8, lbuf[0..n]) catch return Outcome.of(.failed, .build);
		if (!isStorePath(runner)) return Outcome.of(.failed, .build);
		r.runner = runner;
	}
	if (checkpoint(r)) |o| return o;

	const sys_link = std.fmt.allocPrint(arena, "{s}/share/microvm/system", .{r.runner.?}) catch return Outcome.of(.failed, .build);
	r.toplevel = Io.Dir.cwd().realPathFileAlloc(io, sys_link, arena) catch return Outcome.with(.failed, .build, &.{"no_system"});

	// Tier 1 (spec section 3): (b) and (c); (a) and (e) were preflight's.
	const booted = r.identity.?.booted;
	if (unitplan.bootShape(arena, io, booted.runner, r.runner.?)) |shape| {
		if (shape) |why| return Outcome.of(.restart_required, Reason.fromBootShape(why));
	} else |_| return Outcome.with(.failed, .build, &.{"boot_shape_unreadable"});
	if (checkpoint(r)) |o| return o;

	return planAndApply(r);
}

fn archName() []const u8 {
	return if (@import("platform").darwin) "aarch64-darwin" else @tagName(builtin.cpu.arch);
}

/// `<icd>/gcroots/applied/<G>` (its directory created on demand).
fn gcrootFor(r: *Run) ![]const u8 {
	var icd_dir = try snapshot.openIcd(r.io, r.icd);
	defer icd_dir.close(r.io);
	try snapshot.ensureDir(r.io, icd_dir, "gcroots", r.owner);
	var g = try icd_dir.openDir(r.io, "gcroots", .{ .follow_symlinks = false });
	defer g.close(r.io);
	try snapshot.ensureDir(r.io, g, "applied", r.owner);
	return std.fmt.allocPrint(r.arena, "{s}/gcroots/applied/{s}", .{ r.icd, &r.gen });
}

fn stopRequested() bool {
	return terminate.load(.acquire) != 0 or supersede.load(.acquire) != 0;
}

/// A reproduced eval_error (spec section 2 step 3): from here the supersede
/// flag is ignored. Flip apply/active to `record` at once, then write the
/// intent (rolled back in the record step) against K, else B.
fn evalError(r: *Run) Outcome {
	r.setPhase(.record, bootSeconds(r.io) + Bounds.record_s);
	const intent: rollback.Intent = .{
		.G = &r.gen,
		.op = r.args.op,
		.reason = .eval_error,
		.target = r.eval_target,
		.target_id = r.eval_target_id,
		.scope = r.scope_eval,
	};
	_ = rollback.writeIntent(r.arena, r.io, r.icd, intent, .{ .owner = r.owner }) catch |err| {
		// No durable intent: nothing can be rolled back. The commit stays and
		// the next boot evaluates it, which fails as loudly as this did.
		warnf(r.arena, r.io, "could not write the rollback intent ({s})", .{@errorName(err)});
		return Outcome.with(.failed, .build, &.{"intent_unwritten"});
	};
	return Outcome.of(.rejected, .eval_error);
}

// --- tier 2 and the guest ---------------------------------------------------------------------

/// One guest hop under `kill_ms` (and the whole-verb timer), with the watch.
fn hop(r: *Run, verb: []const []const u8, kill_ms: i64, out_cap: usize) HopResult {
	return hopKind(r, verb, kill_ms, out_cap, .apply, null);
}

fn hopKind(r: *Run, verb: []const []const u8, kill_ms: i64, out_cap: usize, kind: sshargv.Hop, stdin: ?[]const u8) HopResult {
	return guestHop(r.arena, r.io, r.env(), r.ctx.runtime_path, r.host.ssh_identity, verb, .{
		.kind = kind,
		.deadline_ms = @min(nowMs(r.io) + kill_ms, r.whole_deadline_ms),
		.out_cap = out_cap,
		.honour_supersede = r.phase == .build,
		.watch = r.watch(),
		.stdin = stdin,
	});
}

fn hopStop(r: *Run, h: HopResult) ?Outcome {
	const s = h.stopped orelse return null;
	return switch (s) {
		.terminate => exitOnTerminate(r),
		.supersede, .watch => Outcome.of(.superseded, null),
		else => null,
	};
}

/// Tier 2 (spec section 3): a settled boot, the guest's `plan`, the identity of
/// what it runs, and the merged unit plan.
fn planAndApply(r: *Run) Outcome {
	const arena = r.arena;
	const io = r.io;

	// 1. Settled boot: `settled --wait 25` hops for at most 180 s.
	var boot_id: []const u8 = "";
	{
		const until = nowMs(io) + Bounds.settled_ms;
		var settled = false;
		while (!settled) {
			const left = until - nowMs(io);
			if (left <= 0) break;
			const h = hop(r, &.{ "settled", "--wait", "25" }, @min(Bounds.hop_ms, left), 4096);
			if (hopStop(r, h)) |o| return o;
			if (h.no_helper) return Outcome.of(.restart_required, .no_helper);
			if (h.reply) |rep| {
				if (rep.get("settled")) |v| settled = std.mem.eql(u8, v, "yes");
				if (rep.get("boot_id")) |b| {
					if (isBootId(b)) boot_id = b;
				}
			} else {
				// A failed hop (the guest's sshd not up yet): try again shortly.
				Io.sleep(io, Io.Duration.fromMilliseconds(@min(2_000, @max(until - nowMs(io), 0))), .awake) catch {};
			}
			if (checkpoint(r)) |o| return o;
		}
		if (!settled or boot_id.len == 0) return Outcome.of(.restart_required, .booting);
	}

	// 2. The guest's plan data (with one abort-and-wait of a busy predecessor).
	const t_arg = r.toplevel.?;
	const rep = blk: {
		var tries: u8 = 0;
		while (true) : (tries += 1) {
			const h = hop(r, &.{ "plan", t_arg }, Bounds.plan_hop_ms, Bounds.plan_reply_cap);
			if (hopStop(r, h)) |o| return o;
			if (h.no_helper) return Outcome.of(.restart_required, .no_helper);
			const rp = h.reply orelse return Outcome.of(.failed, .plan);
			const result = rp.get("result") orelse return Outcome.of(.failed, .plan);
			if (std.mem.eql(u8, result, "ok")) break :blk rp;
			if (std.mem.eql(u8, result, "guest_tainted")) return Outcome.of(.restart_required, .guest_tainted);
			if (!std.mem.eql(u8, result, "busy") or tries > 0) return Outcome.of(.failed, .busy);
			const busy_gen = rp.get("busy_gen") orelse return Outcome.of(.failed, .busy);
			if (!cli.isHex16(busy_gen)) return Outcome.of(.failed, .busy);
			if (abortAndWait(r, busy_gen, boot_id)) |o| return o;
		}
	};
	const g = guestPlanOf(arena, rep) catch return Outcome.of(.failed, .plan);

	// Identity, derived on the host: the guest booted B's system and runs P
	// (live-runner's system, else B's); anything else is a foreign system.
	const idt = r.identity.?;
	const b_sys = realSystem(r, idt.booted.runner) orelse return Outcome.of(.failed, .plan);
	if (g.booted == null or !std.mem.eql(u8, g.booted.?, b_sys)) return Outcome.of(.restart_required, .no_boot_record);
	const p_sys = realSystem(r, idt.currentRunner()) orelse return Outcome.of(.failed, .plan);
	if (g.current == null or !std.mem.eql(u8, g.current.?, p_sys)) return Outcome.of(.restart_required, .foreign_system);
	return planAndApplyWith(r, g, b_sys, p_sys);
}

/// planAndApply once the guest's plan data `g` passed the identity check
/// against the systems the host resolved: B's (`b_sys`) and the one the guest
/// runs (`p_sys`, P's). Tier 1 (d), the guest's refusals, the merged plan, the
/// phase flip's checks and the guest phase. The tests enter here, with
/// systems that are not store paths.
pub fn planAndApplyWith(r: *Run, g: GuestPlan, b_sys: []const u8, p_sys: []const u8) Outcome {
	const arena = r.arena;
	const io = r.io;
	const p_runner = r.identity.?.currentRunner();
	// Tier 1 (d): nothing to switch.
	if (std.mem.eql(u8, r.runner.?, p_runner) and std.mem.eql(u8, r.toplevel.?, p_sys)) return Outcome.of(.already_live, null);
	if (!g.store_overlay) return Outcome.of(.restart_required, .store_fallback);
	if (!std.mem.eql(u8, g.dry_result, "ok")) {
		if (std.mem.eql(u8, g.dry_result, "pre_switch_check")) return Outcome.of(.restart_required, .pre_switch_check);
		if (std.mem.eql(u8, g.dry_result, "init_interface")) return Outcome.of(.restart_required, .init_interface);
		if (std.mem.eql(u8, g.dry_result, "switch_locked")) return Outcome.of(.failed, .switch_locked);
		return Outcome.with(.failed, .plan, &.{if (std.mem.eql(u8, g.dry_result, "timeout")) "dry_activate_timeout" else "dry_activate_failed"});
	}

	// The host plan over P's and T's unit files, the guest's data merged in.
	var host_plan = unitplan.planHost(arena, io, p_sys, r.toplevel.?) catch return Outcome.with(.failed, .plan, &.{"unit_plan"});
	var reexec = unitplan.reexecNeeded(arena, io, b_sys, r.toplevel.?) catch return Outcome.with(.failed, .plan, &.{"unit_plan"});
	if (!std.mem.eql(u8, p_sys, b_sys)) reexec = reexec or (unitplan.reexecNeeded(arena, io, p_sys, r.toplevel.?) catch return Outcome.with(.failed, .plan, &.{"unit_plan"}));
	const t2 = mergeTier2(arena, &host_plan, g, reexec) catch return Outcome.with(.failed, .plan, &.{"unit_plan"});
	var forced: ?Forced = null;
	var repair = false;
	if (t2.refusal) |ref| {
		const why = Reason.fromPlan(ref.reason);
		var o = Outcome.of(.restart_required, why);
		o.detail = refusalDetail(arena, t2, ref.reason) catch &.{};
		o.plan = buildPlan(arena, t2, g.boot_id, r.s.?.meta.comp, p_sys, r.toplevel.?) catch null;
		const want = r.args.force_plan orelse {
			// An overridable refusal's plan is stored for Apply anyway; a mixed
			// one only lists its plan.
			if (o.overridable()) storePlanFor(r, &o, why);
			return o;
		};
		// Spec section 2 step 5, "Forced run": the guest phase never starts
		// with a stale list. A refusal that is never overridable (a mixed one
		// included) stays refused under force, unchanged.
		if (!o.overridable() or r.force_admitted == null) return o;
		if (!std.mem.eql(u8, o.plan.?.id, want)) {
			// Another plan than the one confirmed: nothing is forced, and the
			// new plan (overridable by construction) is stored to be offered.
			storePlanFor(r, &o, why);
			o.reason = .plan_changed;
			return o;
		}
		forced = .{ .plan = o.plan.?.id, .units = forceUnits(arena, o.plan.?) catch return o };
		repair = o.plan.?.repair.len > 0;
	}
	// A forced run whose re-plan is clean (the disruption went away) applies
	// as a plain one: nothing is relaxed.

	// The phase flip's checks (spec section 2 step 6), then the guest phase.
	if (checkpoint(r)) |o| return o;
	if (!diskAboveFloor(r)) return Outcome.of(.restart_required, .insufficient_disk);
	r.forced = forced;
	r.force_repair = repair;
	return runGuestPhase(r, g.boot_id, p_sys);
}

/// Store an overridable refusal's plan (StoredPlan) for Apply anyway. A plan
/// that cannot be stored is not offered: it warns and drops `o.plan` (the
/// report then says `overridable: false`; the units stay in `detail`).
fn storePlanFor(r: *Run, o: *Outcome, why: Reason) void {
	const p = o.plan orelse return;
	const err = blk: {
		const host_boot = r.host_boot orelse break :blk error.NoHostBootId;
		storePlan(r.arena, r.io, r.icd, .{ .plan = p, .reason = why, .created = bootSeconds(r.io), .nonce = r.nonce, .host_boot = host_boot, .gen = &r.gen }, r.owner) catch |e| break :blk e;
		return;
	};
	warnf(r.arena, r.io, "could not store the plan to apply anyway ({s})", .{@errorName(err)});
	o.plan = null;
}

fn realSystem(r: *Run, runner: []const u8) ?[]const u8 {
	const link = std.fmt.allocPrint(r.arena, "{s}/share/microvm/system", .{runner}) catch return null;
	return Io.Dir.cwd().realPathFileAlloc(r.io, link, r.arena) catch null;
}

/// A busy predecessor (spec section 2 step 5): this run holds the apply flock
/// and no inflight.json survived, so no host verb tracks the busy generation;
/// abort it and wait (at most 420 s) for it to end, polling `status`.
fn abortAndWait(r: *Run, gen: []const u8, boot_id: []const u8) ?Outcome {
	const h = hop(r, &.{ "abort", gen, "--boot-id", boot_id }, Bounds.hop_ms, 64 << 10);
	if (hopStop(r, h)) |o| return o;
	const until = nowMs(r.io) + Bounds.busy_wait_ms;
	while (nowMs(r.io) < until) {
		const s = hop(r, &.{ "status", gen, "--boot-id", boot_id, "--wait", "25" }, @min(Bounds.hop_ms, until - nowMs(r.io)), 64 << 10);
		if (hopStop(r, s)) |o| return o;
		if (s.reply) |rp| {
			const result = rp.get("result") orelse "";
			if (!std.mem.eql(u8, result, "ok")) return null;
			const state = rp.get("state") orelse "";
			for ([_][]const u8{ "refused", "confirmed", "reverted", "revert_failed", "stale" }) |term| {
				if (std.mem.eql(u8, state, term)) return null;
			}
		} else {
			Io.sleep(r.io, Io.Duration.fromMilliseconds(2_000), .awake) catch {};
		}
		if (checkpoint(r)) |o| return o;
	}
	return null;
}

// --- the guest phase (spec section 2 steps 6-8) ---------------------------------------------

/// The guest phase's timing (spec section 2 steps 6-8 and the bounds table).
/// The defaults are the spec's; only the tests shorten them.
pub const GuestCfg = struct {
	/// S: the apply unit's RuntimeMaxSec.
	bound_s: i64 = Bounds.apply_unit_s,
	/// W: the dead-man's window from `start`.
	window_s: i64 = Bounds.window_s,
	/// The `start` leg: every attempt starts within it, from the first.
	start_leg_ms: i64 = Bounds.start_leg_ms,
	/// The poll ends at the first `start` + the start leg + W + this margin.
	margin_s: i64 = Bounds.poll_margin_s,
	/// Every hop's wall-clock kill, and SIGINT's abort hop.
	hop_ms: i64 = Bounds.hop_ms,
	abort_ms: i64 = Bounds.abort_hop_ms,
	/// A poll that came back at once without news waits this long before the
	/// next (the helper long-polls, so only a guest that does not pays it); a
	/// failed hop waits fail_pause_ms.
	pause_ms: i64 = 1_000,
	fail_pause_ms: i64 = 2_000,

	/// inflight.json's `expires_at` for a `start` sent at CLOCK_BOOTTIME
	/// `boot_s`: by then a dead-man that start armed has fired and the live
	/// verb's own poll has expired.
	pub fn expiresAt(c: GuestCfg, boot_s: i64) i64 {
		return boot_s + @divTrunc(c.start_leg_ms + 999, 1000) + c.window_s + c.margin_s;
	}
};

/// The guest phase's timing for a run: the spec's defaults, with the apply
/// unit's bound S from COGBOX_APPLY_SWITCH_TIMEOUT (clamped to the helper's
/// 60..3600 s) and the dead-man window following it, W = S + 120, so every
/// leg derived from W (the poll, expires_at, apply/active's deadline) follows
/// too.
pub fn guestCfgOf(env: *const std.process.Environ.Map) GuestCfg {
	const s = std.math.clamp(envSeconds(env, "COGBOX_APPLY_SWITCH_TIMEOUT", Bounds.apply_unit_s), 60, 3600);
	return .{ .bound_s = s, .window_s = s + (Bounds.window_s - Bounds.apply_unit_s) };
}

/// A generation's state as the helper reports it (spec 4.3).
pub const GState = enum {
	starting,
	switching,
	switched,
	failed,
	reverting,
	refused,
	confirmed,
	reverted,
	revert_failed,
	stale,
	/// A state the helper could not name (it prints `invalid`), or one this
	/// host does not know.
	invalid,

	pub fn terminal(s: GState) bool {
		return switch (s) {
			.refused, .confirmed, .reverted, .revert_failed, .stale => true,
			else => false,
		};
	}

	/// The states whose read never resets the failed-hop streak: the hop that
	/// observes a dead-man revert must not erase the evidence for it.
	pub fn keepsStreak(s: GState) bool {
		return s == .reverting or s == .reverted or s == .revert_failed;
	}
};

/// A verdict, cause or refusal token as the helper prints them (its own
/// charset; anything else reads as `invalid`).
pub fn isGuestToken(s: []const u8) bool {
	if (s.len == 0 or s.len > 32) return false;
	for (s) |c| switch (c) {
		'a'...'z', '0'...'9', '_', '-' => {},
		else => return false,
	};
	return true;
}

fn isExitToken(s: []const u8) bool {
	if (!std.mem.startsWith(u8, s, "exit_")) return false;
	const n = s["exit_".len..];
	if (n.len == 0 or n.len > 3) return false;
	for (n) |c| if (c < '0' or c > '9') return false;
	return true;
}

/// What one helper status block says about G (the replies of `status`,
/// `start`, `abort` and `confirm` carry one).
pub const GuestView = struct {
	state: GState,
	reached: ?GState = null,
	refusal: ?[]const u8 = null,
	verdict: ?[]const u8 = null,
	cause: ?[]const u8 = null,
	during_activation: bool = false,
	/// The T switch's exit code.
	exit: ?u16 = null,
	/// Unit names (charset-checked; checked against T's and P's unit
	/// directories before they are reported, finalOutcome).
	detail: []const []const u8 = &.{},
	failed_units: []const []const u8 = &.{},
	tainted: bool = false,

	/// What `seen` keeps: the recorded verdict or cause, final in the guest,
	/// or `confirmed`.
	pub fn recorded(v: GuestView) ?[]const u8 {
		if (v.state == .confirmed) return "confirmed";
		return v.verdict orelse v.cause;
	}
};

fn guestTokenOf(v: ?[]const u8) ?[]const u8 {
	const x = v orelse return null;
	return if (isGuestToken(x)) x else "invalid";
}

fn unitListOf(arena: Allocator, rep: Reply, key: []const u8) []const []const u8 {
	var o: std.ArrayList([]const u8) = .empty;
	for (rep.all(arena, key)) |u| {
		if (!isUnitToken(u)) continue;
		o.append(arena, u) catch break;
		if (o.items.len == 64) break;
	}
	return o.items;
}

/// The status block of generation `gen` in a reply; null when there is none or
/// it is about another generation.
pub fn viewOf(arena: Allocator, rep: Reply, gen: []const u8) ?GuestView {
	const g = rep.get("gen") orelse return null;
	if (!std.mem.eql(u8, g, gen)) return null;
	const st = rep.get("state") orelse return null;
	var v: GuestView = .{ .state = std.meta.stringToEnum(GState, st) orelse .invalid };
	if (rep.get("reached")) |x| v.reached = std.meta.stringToEnum(GState, x);
	v.refusal = guestTokenOf(rep.get("refusal"));
	v.verdict = guestTokenOf(rep.get("verdict"));
	v.cause = guestTokenOf(rep.get("cause"));
	if (rep.get("during_activation")) |x| v.during_activation = std.mem.eql(u8, x, "yes");
	if (rep.get("exit")) |x| v.exit = std.fmt.parseInt(u16, x, 10) catch null;
	v.detail = unitListOf(arena, rep, "detail");
	v.failed_units = unitListOf(arena, rep, "failed_unit");
	if (rep.get("tainted")) |x| v.tainted = std.mem.eql(u8, x, "yes");
	return v;
}

/// What a recorded verdict or cause means for the commit (spec section 3,
/// "Outcomes"): a rollback trigger; the dead-man, a trigger only with hop
/// evidence; or a cause that keeps the commit (`undone`).
pub const TokenClass = union(enum) {
	rejecting: rollback.Reason,
	dead_man,
	keeps: Reason,
};

/// Unknown tokens (an `exit_<n>` verdict, `invalid`) keep the commit: a
/// rollback needs positive evidence.
pub fn classOf(tok: []const u8) TokenClass {
	const map = [_]struct { []const u8, TokenClass }{
		.{ "breaks_base", .{ .rejecting = .breaks_base } },
		.{ "activation_failed", .{ .rejecting = .activation_failed } },
		.{ "activation_hang", .{ .rejecting = .activation_hang } },
		.{ "unit_hang", .{ .rejecting = .unit_hang } },
		.{ "dead-man", .dead_man },
		.{ "aborted", .{ .keeps = .aborted } },
		.{ "stop_hang", .{ .keeps = .stop_hang } },
		.{ "switch_timeout", .{ .keeps = .switch_timeout } },
		.{ "unplanned_disruption", .{ .keeps = .unplanned_disruption } },
		.{ "forced_unit_failed", .{ .keeps = .forced_unit_failed } },
	};
	for (map) |m| if (std.mem.eql(u8, tok, m[0])) return m[1];
	return .{ .keeps = .switch_failed };
}

/// A decided guest outcome, before it becomes the run's Outcome.
pub const Final = struct {
	result: Result,
	reason: ?Reason = null,
	/// A rollback trigger: the intent's reason.
	rejecting: ?rollback.Reason = null,
	/// The guest is done with G (a terminal state); otherwise it still reverts.
	terminal: bool = false,
	rolled_back_guest: ?bool = null,
	/// Enumerated `detail` tokens (recovered, unrecovered, during_activation,
	/// revert_failed, exit_<n>, a refusal), before the units.
	tokens: []const []const u8 = &.{},
	/// Unit names the guest gave, reported only when they exist as unit files
	/// in T or P.
	units: []const []const u8 = &.{},
	/// applied_with_failures: the failed units (the report's `units`).
	failed_units: []const []const u8 = &.{},
};

pub const Judgement = union(enum) {
	/// No verdict or cause yet, and not terminal: poll on.
	pending,
	/// Switched with every post-check passing: confirm it.
	switched,
	final: Final,
};

/// Whether the persisted hop evidence says the host lost the guest: a streak
/// of at least 3 failed hops, or a failed fresh-connection confirm.
pub fn lossEvidence(h: Hops) bool {
	return h.streak >= Bounds.streak_evidence or h.confirm_failed;
}

/// A recorded verdict or cause as an outcome. A dead-man revert is
/// `rejected/unreachable` only with hop evidence, `recovered` once the guest
/// is seen reverted; without evidence it is `undone/host_lost`.
fn tokenFinal(arena: Allocator, tok: []const u8, h: Hops, recovered: bool) Final {
	switch (classOf(tok)) {
		.rejecting => |rr| return .{ .result = .rejected, .reason = Reason.fromRollback(rr), .rejecting = rr },
		.dead_man => {
			if (lossEvidence(h)) return .{
				.result = .rejected,
				.reason = .@"unreachable",
				.rejecting = .@"unreachable",
				.tokens = if (recovered) &.{"recovered"} else &.{"unrecovered"},
			};
			return .{ .result = .undone, .reason = .host_lost };
		},
		.keeps => |reason| {
			var f: Final = .{ .result = .undone, .reason = reason };
			if (reason == .switch_failed and isExitToken(tok)) f.tokens = arena.dupe([]const u8, &.{tok}) catch &.{};
			return f;
		},
	}
}

/// The helper's refusal vocabulary without a host reason of its own (its
/// tok_refusal), plus `invalid`: what `detail` may carry of a refusal.
const guest_refusals = [_][]const u8{ "store_path_hidden", "store_whiteout", "register_failed", "run_failed", "start_failed", "deadman_failed", "busy_gc", "invalid" };

/// A no-op refusal (state `refused`): nothing changed in the guest. The
/// token reaches `detail` only when it is one of the helper's own: root in the
/// guest can print any charset-clean word, and `detail` is enumerated tokens
/// only (spec section 2 step 11, section 4.11), so anything else is `invalid`.
fn refusalFinal(arena: Allocator, tok_in: []const u8) Final {
	const map = [_]struct { []const u8, Result, Reason }{
		.{ "store_fallback", .restart_required, .store_fallback },
		.{ "pre_switch_check", .restart_required, .pre_switch_check },
		.{ "init_interface", .restart_required, .init_interface },
		.{ "switch_locked", .failed, .switch_locked },
	};
	for (map) |m| if (std.mem.eql(u8, tok_in, m[0])) return .{ .result = m[1], .reason = m[2], .terminal = true };
	const tok = for (guest_refusals) |k| {
		if (std.mem.eql(u8, tok_in, k)) break k;
	} else "invalid";
	const tokens = arena.dupe([]const u8, &.{tok}) catch &.{};
	if (std.mem.eql(u8, tok, "busy_gc")) return .{ .result = .failed, .reason = .busy, .terminal = true, .tokens = tokens };
	return .{ .result = .failed, .reason = .guest_refused, .terminal = true, .tokens = tokens };
}

/// Judge one status block of G under the hop evidence `h` (spec section 3,
/// "Outcomes"; section 4.3):
///   - confirmed: applied, or applied_with_failures after a switch exit of 2
///     or 4 (every post-check passed, or the guest would not have switched);
///   - refused: the no-op refusal's outcome; stale: unknown;
///   - a recorded verdict or cause, in any state: its outcome (final in the
///     guest), terminal once the guest reverted or failed to;
///   - switched without one: confirm it; anything else: poll on.
pub fn judge(arena: Allocator, v: GuestView, h: Hops) Judgement {
	switch (v.state) {
		.confirmed => {
			const failures = if (v.exit) |e| e == 2 or e == 4 else false;
			return .{ .final = .{ .result = if (failures) .applied_with_failures else .applied, .terminal = true, .failed_units = v.failed_units } };
		},
		.refused => return .{ .final = refusalFinal(arena, v.refusal orelse "invalid") },
		.stale => return .{ .final = .{ .result = .unknown, .terminal = true } },
		.invalid => return .pending,
		else => {},
	}
	const tok = v.verdict orelse v.cause orelse {
		if (v.state == .switched) return .switched;
		// A revert records its cause before it moves the state: a reverted
		// generation without one cannot be classified.
		if (v.state.terminal()) return .{ .final = .{ .result = .unknown, .terminal = true } };
		return .pending;
	};
	var f = tokenFinal(arena, tok, h, v.state == .reverted);
	f.terminal = v.state.terminal();
	f.rolled_back_guest = switch (v.state) {
		.reverted => true,
		.revert_failed => false,
		else => null,
	};
	var tokens: std.ArrayList([]const u8) = .empty;
	tokens.appendSlice(arena, f.tokens) catch {};
	if (std.mem.eql(u8, tok, "aborted") and v.during_activation) tokens.append(arena, "during_activation") catch {};
	if (v.state == .revert_failed) tokens.append(arena, "revert_failed") catch {};
	f.tokens = tokens.items;
	if (std.mem.eql(u8, tok, "unit_hang") or std.mem.eql(u8, tok, "unplanned_disruption") or std.mem.eql(u8, tok, "forced_unit_failed")) f.units = v.detail;
	return .{ .final = f };
}

/// The expiry rule (spec section 2 step 7; section 4.6 for a recoverer whose
/// three full-length hops in a row failed past `expires_at`), from the
/// persisted evidence alone: `seen` decides when set (`confirmed` is the
/// confirmed record, a non-rejecting cause `undone/<cause>`, a rejecting
/// verdict its rejection); otherwise (no `seen`, or `dead-man`) hop evidence
/// gives `rejected/unreachable` (`unrecovered`), and its absence `unknown`
/// (`undone/host_lost` for a seen `dead-man`). So a confirmed or aborted
/// change is never rolled back on missing evidence.
pub fn expiryFinal(arena: Allocator, h: Hops) Final {
	if (h.seen) |s| {
		if (std.mem.eql(u8, s, "confirmed")) return .{ .result = .applied };
		return tokenFinal(arena, s, h, false);
	}
	if (lossEvidence(h)) return .{ .result = .rejected, .reason = .@"unreachable", .rejecting = .@"unreachable", .tokens = &.{"unrecovered"} };
	return .{ .result = .unknown };
}

/// The exact unit names T's and P's unit directories show (unitplan.addListed);
/// a directory that cannot be listed shows none.
fn listedIn(arena: Allocator, io: Io, t_sys: []const u8, p_sys: []const u8) unitplan.StrSet {
	var set: unitplan.StrSet = .empty;
	for ([_][]const u8{ t_sys, p_sys }) |sys| {
		const dir = std.fmt.allocPrint(arena, "{s}/etc/systemd/system", .{sys}) catch continue;
		const l = unitplan.listUnitDir(arena, io, dir) catch continue;
		unitplan.addListed(arena, &set, &l) catch {};
	}
	return set;
}

/// The guest's unit names a report may carry (spec 4.11): a name T's or P's
/// unit directory shows exactly (listedIn); a template instance neither shows,
/// as its template when one shows that (any instance of an existing template
/// is a valid name, so the instance text is the guest's own); nothing else.
/// Unique, in the guest's order.
fn unitsInSystems(arena: Allocator, listed: *const unitplan.StrSet, units: []const []const u8) []const []const u8 {
	var o: unitplan.StrSet = .empty;
	for (units) |u| {
		const name = if (listed.contains(u)) u else blk: {
			const tmpl = unitplan.nodeName(arena, u) catch break;
			if (tmpl.ptr == u.ptr or !listed.contains(tmpl)) continue;
			break :blk tmpl;
		};
		o.put(arena, name, {}) catch break;
	}
	return o.keys();
}

/// A Final as the run's Outcome: `detail` is its tokens, then the guest's unit
/// names a report may carry (unitsInSystems; the report carries nothing else).
pub fn finalOutcome(arena: Allocator, io: Io, f: Final, t_sys: []const u8, p_sys: []const u8) Outcome {
	const failures = f.result == .applied_with_failures;
	const listed = if (f.units.len > 0 or (failures and f.failed_units.len > 0)) listedIn(arena, io, t_sys, p_sys) else unitplan.StrSet.empty;
	var detail: std.ArrayList([]const u8) = .empty;
	detail.appendSlice(arena, f.tokens) catch {};
	detail.appendSlice(arena, unitsInSystems(arena, &listed, f.units)) catch {};
	var o: Outcome = .{ .result = f.result, .reason = f.reason, .detail = detail.items, .rolled_back_guest = f.rolled_back_guest };
	if (failures) o.units = unitsInSystems(arena, &listed, f.failed_units);
	return o;
}

// --- apply/inflight.json -----------------------------------------------------------------------

/// The hop evidence (spec section 2 step 7, and section 4.6 "Recoverer hop
/// evidence").
pub const Hops = struct {
	/// The live verb's failed hops in a row. No recoverer changes it.
	streak: u32 = 0,
	/// A fresh-connection confirm failed: sticky for G.
	confirm_failed: bool = false,
	/// Recoverers' failed full-length hops in a row: any successful recoverer
	/// hop resets it, and `cogbox stop`'s short hop never changes it.
	rfails: u32 = 0,
	/// The recorded verdict or cause, or `confirmed`, the latest successful hop
	/// read for G (the live verb's, the SIGINT path's abort reply, a successful
	/// confirm, or a recoverer's); absent while G has none.
	seen: ?[]const u8 = null,
};

fn hopsEql(a: Hops, b: Hops) bool {
	if (a.streak != b.streak or a.confirm_failed != b.confirm_failed or a.rfails != b.rfails) return false;
	if (a.seen == null or b.seen == null) return a.seen == null and b.seen == null;
	return std.mem.eql(u8, a.seen.?, b.seen.?);
}

/// What one live-verb hop tells the evidence.
pub const HopNote = union(enum) {
	/// No reply (ssh failed, the kill fired, the reply was cut off or is no
	/// answer). `confirm`: the fresh-connection confirm.
	failed: struct { confirm: bool = false },
	/// A reply that read G: its state (null when the guest does not know G)
	/// and its recorded verdict, cause or `confirmed`.
	read: struct { state: ?GState = null, recorded: ?[]const u8 = null },
	/// A reply that read nothing of G (`lock_timeout`).
	nothing,
};

/// The live verb's hop-evidence rule (spec section 2 step 7); true when `h`
/// changed, and the verb then rewrites inflight.json:
///   - a failed hop increments `streak`; a failed confirm also sets the
///     sticky `confirm_failed`;
///   - a successful hop resets `streak` only when it reads G in a state other
///     than reverting, reverted or revert_failed, so the hop that observes a
///     dead-man revert never erases the evidence for it;
///   - `seen` takes the recorded verdict or cause (or `confirmed`) a hop reads.
/// Once `seen` is set the streak no longer moves: the verdict or cause is
/// final in the guest, so the streak that stood when it was first read is the
/// one every classification of it uses, the live verb's and a later
/// recoverer's alike.
pub fn noteHop(h: *Hops, note: HopNote) bool {
	const before = h.*;
	switch (note) {
		.failed => |f| {
			if (h.seen == null) h.streak +|= 1;
			if (f.confirm) h.confirm_failed = true;
		},
		.read => |rd| if (h.seen == null) {
			const keeps_streak = if (rd.state) |s| s.keepsStreak() else false;
			if (!keeps_streak) h.streak = 0;
			if (rd.recorded) |tok| h.seen = tok;
		},
		.nothing => {},
	}
	return !hopsEql(before, h.*);
}

/// A recoverer's hop (spec section 4.6, "Recoverer hop evidence"); true when
/// `h` changed. A failed full-length hop increments `rfails`; a successful one
/// resets it and updates `seen` as the live verb does. `cogbox stop`'s short
/// hop (`short`) never changes `rfails`. No recoverer touches `streak`.
pub fn noteRecoverHop(h: *Hops, ok: bool, recorded: ?[]const u8, short: bool) bool {
	const before = h.*;
	if (!short) {
		if (ok) h.rfails = 0 else h.rfails +|= 1;
	}
	if (ok and h.seen == null) {
		if (recorded) |tok| h.seen = tok;
	}
	return !hopsEql(before, h.*);
}

/// `<icd>/apply/inflight.json`: written before the first `start` (spec section
/// 2 step 6), rewritten atomically before every `start` attempt (a fresh
/// `expires_at`) and whenever `hops` changes, and deleted after the step-10
/// record or rollback, or when a recoverer resolves it. `T` and `P` (the
/// toplevel switched to and the system switched from) are beyond the spec's
/// field list: a recovery's report names T, and the unit names of a recovered
/// verdict are checked against T's and P's unit files.
pub const Inflight = struct {
	G: []const u8,
	op: ?[]const u8 = null,
	scratch_id: []const u8,
	base_id: []const u8,
	/// qemu.start at preflight: the boot this apply runs against.
	nonce: []const u8,
	/// The guest's boot id (read at plan time), and the host's.
	boot_id: []const u8,
	host_boot: []const u8,
	/// The runner R and the COGBOX_FLAKE_SOURCE#COGBOX_REEXEC_PACKAGE it was
	/// built under.
	R: []const u8,
	key: []const u8,
	T: []const u8,
	P: []const u8,
	/// The live-rejection scope (against B), computed at preflight.
	scope: []const snapshot.ScopeEntry,
	/// CLOCK_BOOTTIME seconds: a wall-clock step never moves it.
	expires_at: i64,
	hops: Hops = .{},
	/// Apply anyway: the plan and the units every `start` of G carried (a
	/// recovered run reports them, and audits its completion). Absent in a
	/// file an older cogbox wrote.
	forced: ?Forced = null,
};

/// qemu.start's value: the launcher writes QEMU's start tick.
fn isNonce(s: []const u8) bool {
	if (s.len == 0 or s.len > 64) return false;
	for (s) |c| switch (c) {
		'0'...'9', 'a'...'z', 'A'...'Z', '.', '_', '-' => {},
		else => return false,
	};
	return true;
}

fn isScopeName(s: []const u8) bool {
	if (s.len == 0 or s.len > 255) return false;
	if (std.mem.eql(u8, s, ".") or std.mem.eql(u8, s, "..")) return false;
	return std.mem.indexOfAny(u8, s, "/\x00") == null;
}

/// Parse inflight.json; error.InvalidInflight when it does not parse or a
/// field fails its check (nothing in such a file is acted on).
pub fn parseInflight(arena: Allocator, bytes: []const u8) !Inflight {
	const inf = std.json.parseFromSliceLeaky(Inflight, arena, bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidInflight;
	if (!snapshot.isId(inf.G) or !snapshot.isId(inf.scratch_id) or !snapshot.isId(inf.base_id)) return error.InvalidInflight;
	if (!isNonce(inf.nonce) or !isBootId(inf.boot_id) or !isBootId(inf.host_boot)) return error.InvalidInflight;
	if (!isStorePath(inf.R) or !isStorePath(inf.T) or !isStorePath(inf.P) or inf.key.len == 0) return error.InvalidInflight;
	if (inf.op) |op| if (!cli.isOpToken(op)) return error.InvalidInflight;
	if (inf.hops.seen) |s| if (!isGuestToken(s)) return error.InvalidInflight;
	for (inf.scope) |e| if (!isScopeName(e.name)) return error.InvalidInflight;
	if (inf.forced) |f| {
		if (!cli.isHex16(f.plan) or f.units.len > Bounds.force_units_max) return error.InvalidInflight;
		for (f.units) |u| if (!isUnitToken(u)) return error.InvalidInflight;
	}
	return inf;
}

pub fn writeInflight(arena: Allocator, io: Io, icd: []const u8, inf: Inflight, owner: ?u32) !void {
	var aw: Io.Writer.Allocating = .init(arena);
	std.json.Stringify.value(inf, .{}, &aw.writer) catch return error.OutOfMemory;
	aw.writer.writeByte('\n') catch return error.OutOfMemory;
	try writeApplyFile(arena, io, icd, "inflight.json", aw.written(), owner);
}

/// FileNotFound when there is none; error.InvalidInflight when it cannot be
/// read or does not parse.
pub fn readInflight(arena: Allocator, io: Io, icd: []const u8) !Inflight {
	var dir = snapshot.openIcd(io, icd) catch |err| switch (err) {
		error.FileNotFound => return error.FileNotFound,
		else => return error.InvalidInflight,
	};
	defer dir.close(io);
	const bytes = snapshot.readNoFollow(arena, io, dir, "apply/inflight.json", 4 << 20) catch |err| switch (err) {
		error.FileNotFound => return error.FileNotFound,
		else => return error.InvalidInflight,
	};
	return parseInflight(arena, bytes);
}

fn deleteInflight(io: Io, icd: []const u8) void {
	var dir = snapshot.openIcd(io, icd) catch return;
	defer dir.close(io);
	dir.deleteFile(io, "apply/inflight.json") catch {};
}

/// The host's boot id; null when unreadable.
pub fn hostBootId(arena: Allocator, io: Io) ?[]const u8 {
	const data = readSmall(arena, io, "/proc/sys/kernel/random/boot_id", 128) catch return null;
	const v = std.mem.trim(u8, data, " \t\r\n");
	return if (isBootId(v)) v else null;
}

/// The value of the `regInfo=` kernel parameter in a runner script (microvm's
/// registerClosure: T's closure registration, which the guest's `start`
/// registers); null when absent or not a store path's `/registration`.
pub fn parseRegInfo(script: []const u8) ?[]const u8 {
	const key = "regInfo=";
	const stops = " \t\n\r'\"";
	var p: usize = 0;
	while (std.mem.indexOfPos(u8, script, p, key)) |at| {
		p = at + key.len;
		if (at != 0 and std.mem.indexOfScalar(u8, stops, script[at - 1]) == null) continue;
		var end = p;
		while (end < script.len and std.mem.indexOfScalar(u8, stops, script[end]) == null) end += 1;
		const v = script[p..end];
		const suffix = "/registration";
		if (!std.mem.endsWith(u8, v, suffix) or !isStorePath(v[0 .. v.len - suffix.len])) return null;
		return v;
	}
	return null;
}

/// REGINFO for `start`: R's bin/microvm-run's `regInfo=`.
pub fn regInfoOf(arena: Allocator, io: Io, runner: []const u8) ?[]const u8 {
	const p = std.fmt.allocPrint(arena, "{s}/bin/microvm-run", .{runner}) catch return null;
	const script = readSmall(arena, io, p, unitplan.max_runner_script_bytes) catch return null;
	return parseRegInfo(script);
}

// --- the live verb's guest phase -------------------------------------------------------------

/// The live verb's guest phase, from the flip to `phase: guest` on.
pub const GuestRun = struct {
	inf: Inflight,
	reginfo: []const u8,
	/// The guest knows G: a `start` answered started or recorded, or a hop read
	/// G's block.
	started: bool = false,
	/// A `start` attempt was lost in transport: it may still land late.
	start_lost: bool = false,
	/// A successful hop read that the guest does not know G.
	unknown: bool = false,
	/// Every `start` attempt begins before this (awake ms).
	start_until: i64 = 0,
	/// The poll's end (awake ms); 0 until the first `start` attempt.
	poll_until: i64 = 0,
	view: ?GuestView = null,
	/// The latest decided judgement: a verdict or cause was seen.
	final: ?Final = null,
	/// The rejection whose intent this run wrote.
	intent: ?rollback.Reason = null,
	/// Apply anyway: what every `start` attempt sends on stdin with
	/// `--force-units -` (forceInput of Forced.units; null for a plain run and
	/// for a plan that relaxes no unit, one that only reloads units or
	/// re-executes systemd, since the helper refuses an empty list), and
	/// whether it passes `--repair`.
	force_input: ?[]const u8 = null,
	repair: bool = false,
};

/// Spec section 2 steps 6-8: the phase flip, inflight.json, the `start` hop
/// (the guest arms its dead-man before any mutation and starts a detached,
/// bounded apply unit), the long-poll to a terminal state, and the confirm on
/// a fresh connection. From the flip on a supersede request is ignored (no
/// hop honours it); the terminate flag and the whole-verb timer take the
/// terminate path (guestTerminate), which leaves inflight.json for a
/// recoverer. A rejecting verdict becomes the rollback intent as soon as a hop
/// reads it; the rollback itself runs in the record step (finish).
pub fn runGuestPhase(r: *Run, boot_id: []const u8, p_sys: []const u8) Outcome {
	const reginfo = regInfoOf(r.arena, r.io, r.runner.?) orelse return Outcome.with(.failed, .plan, &.{"no_reginfo"});
	const host_boot = r.host_boot orelse return Outcome.with(.failed, .snapshot, &.{"no_host_boot_id"});
	return runGuestPhaseWith(r, boot_id, p_sys, reginfo, host_boot);
}

/// runGuestPhase once REGINFO (R's closure registration) and the host's boot
/// id are known. The guest-phase tests enter here.
pub fn runGuestPhaseWith(r: *Run, boot_id: []const u8, p_sys: []const u8, reginfo: []const u8, host_boot: []const u8) Outcome {
	const io = r.io;
	var force_input: ?[]const u8 = null;
	if (r.forced) |f| if (f.units.len > 0) {
		force_input = forceInput(r.arena, f.units) catch return Outcome.with(.failed, .plan, &.{"force_input"});
	};
	r.setPhase(.guest, bootSeconds(io) + r.gcfg.window_s + Bounds.guest_extra_s);
	r.guest = .{
		.inf = .{
			.G = &r.gen,
			.op = r.args.op,
			.scratch_id = &r.scratch_id,
			.base_id = &r.identity.?.base_id,
			.nonce = r.nonce,
			.boot_id = boot_id,
			.host_boot = host_boot,
			.R = r.runner.?,
			.key = r.key,
			.T = r.toplevel.?,
			.P = p_sys,
			.scope = r.scope_live,
			.expires_at = 0,
			.forced = r.forced,
		},
		.reginfo = reginfo,
		.start_until = nowMs(io) + r.gcfg.start_leg_ms,
		.force_input = force_input,
		.repair = r.force_repair,
	};
	const o = pollGuest(r);
	if (o.exit_now != null) return o;
	switch (o.result) {
		.rejected, .undone, .failed, .restart_required => if (r.guest.?.started) {
			if (fetchGuestLog(r)) |x| return x;
		},
		else => {},
	}
	return o;
}

fn pollGuest(r: *Run) Outcome {
	const g = &r.guest.?;
	while (true) {
		if (guestInterrupted(r)) |o| return o;
		if (r.bootNow() == .changed) return guestEnd(r, .gone);
		const now = nowMs(r.io);
		if (g.poll_until != 0 and now >= g.poll_until) return guestEnd(r, .expired);
		// After Bounds.streak_evidence failed hops in a row only status polls go
		// out, until one reads the guest again.
		const quiet = g.inf.hops.streak < Bounds.streak_evidence;
		const step: ?Outcome = if (!g.started and quiet and now < g.start_until)
			startHop(r)
		else if (quiet and g.unknown and !g.started)
			// The start leg is over and the guest does not know G: tombstone it,
			// so a start still in flight answers stale and arms nothing.
			tombstoneHop(r, null)
		else if (quiet and g.final == null and g.view != null and g.view.?.state == .switched)
			confirmHop(r)
		else
			statusHop(r);
		if (step) |o| return o;
	}
}

/// The terminate flag or the whole-verb timer, checked at every iteration.
fn guestInterrupted(r: *Run) ?Outcome {
	if (terminate.load(.acquire) != 0) return guestTerminate(r, false);
	if (r.wholeLeftMs() <= 0) return guestTerminate(r, true);
	return null;
}

/// The terminate path from `start` until the step-10 lock is held, the acquire
/// included (spec 4.8). SIGTERM, and the whole-verb timer: exit at once,
/// leaving inflight.json (every SIGTERM sender runs a recovery afterwards).
/// SIGINT or SIGHUP (interactive; no recoverer follows): first one `abort G`
/// (a no-op once a verdict is recorded or G is confirmed), bounded at 15 s,
/// whose reply's state is persisted in `seen`; a rejecting verdict it carries
/// becomes the intent, as at any classification. An abort without a reply is
/// no evidence: a second Ctrl-C reaches its ssh too (the verb's group).
fn guestTerminate(r: *Run, timer: bool) Outcome {
	const sig = terminate.load(.acquire);
	const interactive = !timer and (sig == @intFromEnum(std.posix.SIG.INT) or sig == @intFromEnum(std.posix.SIG.HUP));
	if (interactive and r.guest != null) {
		const g = &r.guest.?;
		const h = guestHop(r.arena, r.io, r.env(), r.ctx.runtime_path, r.host.ssh_identity, &.{ "abort", g.inf.G, "--boot-id", g.inf.boot_id }, .{
			.deadline_ms = nowMs(r.io) + r.gcfg.abort_ms,
			.ignore_terminate = true,
		});
		const view = if (h.reply) |rep| viewOf(r.arena, rep, g.inf.G) else null;
		if (view) |v| _ = noteView(r, v);
	}
	if (timer) warnf(r.arena, r.io, "the live apply ran out of time (COGBOX_APPLY_TIMEOUT) in its guest phase; apply/inflight.json is left for recovery", .{});
	const code: u8 = if (timer) 128 + 15 else 128 +| sig;
	return .{ .result = .unknown, .exit_now = code };
}

const EndWhy = enum {
	/// The instance stopped or relaunched, or the guest booted again.
	gone,
	/// The poll's bound passed.
	expired,
};

/// The poll ended without a terminal state. A verdict already seen decides (a
/// rejecting one is already an intent, which the record step rolls back
/// whatever the instance did). Otherwise a gone guest is `unknown`, and an
/// expired poll takes the expiry rule, which needs the same boot still
/// running. An expired poll whose boot cannot be told is `unknown` too, but
/// keeps inflight.json: a recoverer reads G from the guest once the boot can
/// be told, so a confirmed or rejected G is not lost to a failed read.
fn guestEnd(r: *Run, why: EndWhy) Outcome {
	const g = &r.guest.?;
	if (g.final) |f| return finalOutcome(r.arena, r.io, f, g.inf.T, g.inf.P);
	if (why == .gone) return Outcome.of(.unknown, null);
	switch (r.bootNow()) {
		.same => {},
		.changed => return Outcome.of(.unknown, null),
		.unknown => {
			warnf(r.arena, r.io, "could not tell whether the instance still runs the boot this apply saw; apply/inflight.json is left for recovery", .{});
			r.keep_inflight = true;
			return Outcome.of(.unknown, null);
		},
	}
	const f = expiryFinal(r.arena, g.inf.hops);
	if (f.rejecting) |rr| {
		if (writeLiveIntent(r, rr)) |o| return o;
	}
	return finalOutcome(r.arena, r.io, f, g.inf.T, g.inf.P);
}

/// Rewrite inflight.json when the evidence changed (best-effort: the live
/// verb classifies from memory; a recoverer then sees older evidence, which
/// errs toward `unknown`).
fn persistHops(r: *Run, changed: bool) void {
	if (!changed or !r.inflight_written) return;
	writeInflight(r.arena, r.io, r.icd, r.guest.?.inf, r.owner) catch |err| {
		warnf(r.arena, r.io, "could not update apply/inflight.json ({s})", .{@errorName(err)});
		return;
	};
	noteDurable(.hops);
}

fn noteFailed(r: *Run, confirm: bool) void {
	persistHops(r, noteHop(&r.guest.?.inf.hops, .{ .failed = .{ .confirm = confirm } }));
}

/// A hop without an answer. Not evidence when a terminate signal, the
/// whole-verb timer, the poll's end or a stopped instance cut it: those end
/// the poll instead. (The hop's ssh is in the verb's group, so a group signal
/// can end it before the loop sees the flag.)
fn failedHop(r: *Run, confirm: bool) ?Outcome {
	const g = &r.guest.?;
	if (terminate.load(.acquire) != 0) return guestTerminate(r, false);
	if (r.wholeLeftMs() <= 0) return guestTerminate(r, true);
	if (r.bootNow() == .changed) return guestEnd(r, .gone);
	if (g.poll_until != 0 and nowMs(r.io) >= g.poll_until) return null;
	noteFailed(r, confirm);
	pause(r, r.gcfg.fail_pause_ms);
	return null;
}

fn hopStopped(r: *Run, s: Stop) Outcome {
	return switch (s) {
		.terminate => guestTerminate(r, false),
		// The watch: the instance stopped or relaunched.
		else => guestEnd(r, .gone),
	};
}

/// Sleep `ms` in slices that see the terminate flag, never past the poll's end.
fn pause(r: *Run, ms: i64) void {
	const g = &r.guest.?;
	var until = nowMs(r.io) + ms;
	if (g.poll_until != 0) until = @min(until, g.poll_until);
	while (terminate.load(.acquire) == 0) {
		const left = until - nowMs(r.io);
		if (left <= 0) return;
		Io.sleep(r.io, Io.Duration.fromMilliseconds(@min(left, Bounds.child_poll_ms)), .awake) catch return;
	}
}

/// A hop's kill, never past the poll's end once the poll runs.
fn pollKill(r: *Run, ms: i64) i64 {
	const g = &r.guest.?;
	if (g.poll_until == 0) return ms;
	return @max(@min(ms, g.poll_until - nowMs(r.io)), 1);
}

fn guestVerbHop(r: *Run, verb: []const []const u8, kill_ms: i64, kind: sshargv.Hop) HopResult {
	return hopKind(r, verb, kill_ms, 64 << 10, kind, null);
}

/// Record a status block: the evidence rule, `seen`, the judgement. A rejecting
/// verdict becomes the intent at once (spec section 2 step 7, "Early verdict"),
/// before inflight.json records it in `seen`: a `seen` without its intent is
/// what a recoverer on another boot would settle `unknown`. The poll goes on
/// to a terminal state for rolled_back_guest. Returns the outcome once the
/// guest is done with G.
fn noteView(r: *Run, v: GuestView) ?Outcome {
	const g = &r.guest.?;
	g.started = true;
	g.unknown = false;
	const changed = noteHop(&g.inf.hops, .{ .read = .{ .state = v.state, .recorded = v.recorded() } });
	g.view = v;
	switch (judge(r.arena, v, g.inf.hops)) {
		.pending, .switched => {
			persistHops(r, changed);
			return null;
		},
		.final => |f| {
			g.final = f;
			if (f.rejecting) |rr| {
				const unwritten = writeLiveIntent(r, rr);
				persistHops(r, changed);
				if (unwritten) |o| return o;
			} else persistHops(r, changed);
			if (f.terminal) return finalOutcome(r.arena, r.io, f, g.inf.T, g.inf.P);
			return null;
		},
	}
}

/// The intent for a live rejection (target B, the live scope), once per run.
/// Written by the main flow at classification time, never by a handler. When
/// it cannot be written nothing can be rolled back: the commit stays, and the
/// verb says so (`failed/snapshot`, `intent_unwritten`).
fn writeLiveIntent(r: *Run, reason: rollback.Reason) ?Outcome {
	const g = &r.guest.?;
	if (g.intent != null) return null;
	_ = rollback.writeIntent(r.arena, r.io, r.icd, .{
		.G = g.inf.G,
		.op = g.inf.op,
		.reason = reason,
		.target = .base,
		.target_id = g.inf.base_id,
		.scope = g.inf.scope,
	}, .{ .owner = r.owner }) catch |err| {
		warnf(r.arena, r.io, "could not write the rollback intent ({s}); the change stays committed", .{@errorName(err)});
		return Outcome.with(.failed, .snapshot, &.{"intent_unwritten"});
	};
	noteDurable(.intent);
	g.intent = reason;
	return null;
}

/// Step 6's `start`, under the start leg. inflight.json is written first, with
/// a fresh `expires_at`, before every attempt (`start` is idempotent: a G the
/// guest already recorded answers its state and arms nothing). An Apply anyway
/// run adds `--force-units -` (the list on stdin) and `--repair`, the same
/// argv and bytes on every attempt; a plain run's argv is unchanged.
fn startHop(r: *Run) ?Outcome {
	const g = &r.guest.?;
	const io = r.io;
	const cfg = r.gcfg;
	g.inf.expires_at = cfg.expiresAt(bootSeconds(io));
	writeInflight(r.arena, io, r.icd, g.inf, r.owner) catch |err| {
		warnf(r.arena, io, "could not write apply/inflight.json ({s})", .{@errorName(err)});
		// Nothing was sent: the guest is untouched.
		if (!r.inflight_written) return Outcome.with(.failed, .snapshot, &.{"inflight_unwritten"});
		// No start goes out under an older expires_at; the poll continues.
		g.start_until = 0;
		return null;
	};
	r.inflight_written = true;
	const now = nowMs(io);
	if (g.poll_until == 0) g.poll_until = now + cfg.start_leg_ms + (cfg.window_s + cfg.margin_s) * 1000;
	const bound = std.fmt.allocPrint(r.arena, "{d}", .{cfg.bound_s}) catch return Outcome.of(.failed, .plan);
	const window = std.fmt.allocPrint(r.arena, "{d}", .{cfg.window_s}) catch return Outcome.of(.failed, .plan);
	const kill = @min(cfg.hop_ms, @max(g.start_until - now, 1_000));
	var verb: std.ArrayList([]const u8) = .empty;
	verb.appendSlice(r.arena, &.{ "start", g.inf.G, g.inf.T, g.reginfo, "--prev", g.inf.P, "--boot-id", g.inf.boot_id, "--bound", bound, "--window", window }) catch return Outcome.of(.failed, .plan);
	if (g.force_input != null) verb.appendSlice(r.arena, &.{ "--force-units", "-" }) catch return Outcome.of(.failed, .plan);
	if (g.repair) verb.appendSlice(r.arena, &.{ "--repair", repair_unit }) catch return Outcome.of(.failed, .plan);
	const h = hopKind(r, verb.items, kill, 64 << 10, .apply, g.force_input);
	if (h.stopped) |s| return hopStopped(r, s);
	const rep = h.reply orelse {
		g.start_lost = true;
		return failedHop(r, false);
	};
	const result = rep.get("result") orelse "";
	if (std.mem.eql(u8, result, "started") or std.mem.eql(u8, result, "recorded")) {
		const v = viewOf(r.arena, rep, g.inf.G) orelse return failedHop(r, false);
		return noteView(r, v);
	}
	if (std.mem.eql(u8, result, "lock_timeout")) {
		_ = noteHop(&g.inf.hops, .nothing);
		pause(r, cfg.pause_ms);
		return null;
	}
	// A refusal: the guest answers a G it recorded before any of these, so G
	// was not created.
	const refusal: Outcome = if (std.mem.eql(u8, result, "busy"))
		Outcome.of(.failed, .busy)
	else if (std.mem.eql(u8, result, "guest_tainted"))
		Outcome.of(.restart_required, .guest_tainted)
	else if (std.mem.eql(u8, result, "superseded"))
		Outcome.of(.superseded, null)
	else if (std.mem.eql(u8, result, "stale_boot"))
		return Outcome.of(.unknown, null)
	else if (std.mem.eql(u8, result, "error"))
		Outcome.with(.failed, .guest_refused, &.{"start_error"})
	else
		return failedHop(r, false);
	persistHops(r, noteHop(&g.inf.hops, .{ .read = .{} }));
	// An attempt lost in transport may still land: tombstone G first, so it
	// answers stale, unless it already created G (then G is polled).
	if (g.start_lost) return tombstoneHop(r, refusal);
	return refusal;
}

/// `abort G` for a G the guest does not know (or may not): the helper writes a
/// stale tombstone under the lock `start` takes, so a `start` still in flight
/// answers stale and arms nothing. A G a late `start` created is polled as
/// usual. `refusal`: the outcome to end with when G is tombstoned (or the hop
/// fails); without one, a tombstone is `failed/guest_refused` (`not_started`):
/// the guest never ran G.
fn tombstoneHop(r: *Run, refusal: ?Outcome) ?Outcome {
	const g = &r.guest.?;
	const h = guestVerbHop(r, &.{ "abort", g.inf.G, "--boot-id", g.inf.boot_id }, pollKill(r, r.gcfg.hop_ms), .apply);
	if (h.stopped) |s| return hopStopped(r, s);
	const rep = h.reply orelse {
		if (refusal) |o| return o;
		return failedHop(r, false);
	};
	const result = rep.get("result") orelse "";
	if (std.mem.eql(u8, result, "tombstoned")) {
		persistHops(r, noteHop(&g.inf.hops, .{ .read = .{} }));
		return refusal orelse Outcome.with(.failed, .guest_refused, &.{"not_started"});
	}
	if (std.mem.eql(u8, result, "ok")) {
		const v = viewOf(r.arena, rep, g.inf.G) orelse return failedHop(r, false);
		return noteView(r, v);
	}
	if (std.mem.eql(u8, result, "stale_boot")) return refusal orelse guestEnd(r, .gone);
	if (refusal) |o| return o;
	// lock_timeout, error: try again shortly.
	_ = noteHop(&g.inf.hops, .nothing);
	pause(r, r.gcfg.pause_ms);
	return null;
}

/// Step 7's long-poll: `status G --wait 25`.
fn statusHop(r: *Run) ?Outcome {
	const g = &r.guest.?;
	const began = nowMs(r.io);
	const h = guestVerbHop(r, &.{ "status", g.inf.G, "--boot-id", g.inf.boot_id, "--wait", "25" }, pollKill(r, r.gcfg.hop_ms), .apply);
	if (h.stopped) |s| return hopStopped(r, s);
	const rep = h.reply orelse return failedHop(r, false);
	const result = rep.get("result") orelse "";
	if (std.mem.eql(u8, result, "ok")) {
		const before = g.view;
		const v = viewOf(r.arena, rep, g.inf.G) orelse return failedHop(r, false);
		if (noteView(r, v)) |o| return o;
		const same = if (before) |b| b.state == v.state and (b.verdict == null) == (v.verdict == null) and (b.cause == null) == (v.cause == null) else false;
		if (same and v.state != .switched and nowMs(r.io) - began < r.gcfg.pause_ms) pause(r, r.gcfg.pause_ms);
		return null;
	}
	if (std.mem.eql(u8, result, "unknown")) {
		persistHops(r, noteHop(&g.inf.hops, .{ .read = .{} }));
		g.unknown = true;
		if (nowMs(r.io) - began < r.gcfg.pause_ms) pause(r, r.gcfg.pause_ms);
		return null;
	}
	if (std.mem.eql(u8, result, "stale_boot")) return guestEnd(r, .gone);
	// Anything else is not an answer.
	return failedHop(r, false);
}

/// Step 8: `confirm G` on a fresh connection: no multiplexing, and with the
/// cogbox key no ssh config at all (`-F /dev/null`), so a lockout a new login
/// would meet is met here. A failed confirm is recorded (sticky) before the
/// next attempt; a successful one sets `seen: confirmed`.
fn confirmHop(r: *Run) ?Outcome {
	const g = &r.guest.?;
	const began = nowMs(r.io);
	const h = guestVerbHop(r, &.{ "confirm", g.inf.G, "--boot-id", g.inf.boot_id }, pollKill(r, r.gcfg.hop_ms), .confirm);
	if (h.stopped) |s| return hopStopped(r, s);
	const rep = h.reply orelse return failedHop(r, true);
	const result = rep.get("result") orelse "";
	if (std.mem.eql(u8, result, "confirmed") or std.mem.eql(u8, result, "not_switched")) {
		const v = viewOf(r.arena, rep, g.inf.G) orelse return failedHop(r, true);
		return noteView(r, v);
	}
	if (std.mem.eql(u8, result, "unknown")) {
		persistHops(r, noteHop(&g.inf.hops, .{ .read = .{} }));
		g.unknown = true;
		// The view still reads switched, so the next step is another confirm:
		// paced as the status poll is, not a stream of fresh connections.
		if (nowMs(r.io) - began < r.gcfg.pause_ms) pause(r, r.gcfg.pause_ms);
		return null;
	}
	if (std.mem.eql(u8, result, "stale_boot")) return guestEnd(r, .gone);
	if (std.mem.eql(u8, result, "lock_timeout")) {
		_ = noteHop(&g.inf.hops, .nothing);
		pause(r, r.gcfg.pause_ms);
		return null;
	}
	return failedHop(r, true);
}

/// The guest's log of G (its units' output and both switches') into
/// `<G>.guest.log` only, never exported: when the poll ended early enough to
/// leave a hop's time inside its own bound.
fn fetchGuestLog(r: *Run) ?Outcome {
	const g = &r.guest.?;
	const left = g.poll_until - nowMs(r.io);
	if (left < 5_000) return null;
	const h = guestHop(r.arena, r.io, r.env(), r.ctx.runtime_path, r.host.ssh_identity, &.{ "log", g.inf.G }, .{
		.deadline_ms = nowMs(r.io) + @min(r.gcfg.hop_ms, left),
		.out_cap = Bounds.guest_log_cap,
		.raw = true,
		.watch = r.watch(),
	});
	if (h.stopped) |s| if (s == .terminate) return guestTerminate(r, false);
	const text = h.raw orelse return null;
	const name = std.fmt.allocPrint(r.arena, "{s}.guest.log", .{g.inf.G}) catch return null;
	writeApplyFile(r.arena, r.io, r.icd, name, text, r.owner) catch |err| {
		warnf(r.arena, r.io, "could not write apply/{s} ({s})", .{ name, @errorName(err) });
	};
	return null;
}

// --- inflight recovery (spec 4.6, "Interrupted applies") ----------------------------------------

pub const RecoverOptions = struct {
	/// The caller holds the config lock. A lock-free recoverer (`cogbox stop`, a
	/// lock-free `apply --cancel`) acts only on a rejecting verdict, which
	/// becomes an intent; everything else is left for the next holder.
	holds_config_lock: bool,
	/// cogbox's own ssh key, when it exists.
	ssh_identity: ?[]const u8 = null,
	/// `cogbox stop`'s one hop: never changes `rfails`, never settles a G by
	/// expiry (its kill is `hop_ms`, 3 s there).
	short_hop: bool = false,
	/// The status hop's kill.
	hop_ms: i64 = Bounds.hop_ms,
	/// The abort and the wait for a verdict after it (tests shorten it).
	abort_wait_ms: i64 = Bounds.recover_abort_ms,
	pause_ms: i64 = 1_000,
	/// Set to the result of the finishPending a rollback here ran (a config-lock
	/// holder's): the caller's one finish, which it then does not repeat (its
	/// bound counts one).
	fin_out: ?*?rollback.FinishResult = null,
};

pub const Recovery = enum {
	/// inflight.json was settled and removed.
	resolved,
	/// inflight.json stays (the guest could not be read, its generation has no
	/// verdict yet, or this recoverer may not settle what it read).
	unresolved,
};

/// Resolve an orphaned apply/inflight.json (spec 4.6, "Interrupted applies").
/// The caller holds the apply flock (a lock-free caller took it by LOCK_NB);
/// with `holds_config_lock` it also holds the config lock, and then a rejecting
/// verdict is rolled back here (one finishPending) so last.json carries the
/// rollback. Every resolution is written to last.json with the op from
/// inflight.json. At most 45 s (status) + 60 s (abort and wait) + the record.
///   - Stopped or relaunched (not running, another qemu.start, or another host
///     boot): `unknown`, or the rejection whose intent the dead verb wrote. A
///     lock-free recoverer leaves the file for the launcher.
///   - Same boot: one `status G` hop. A rejecting verdict or cause, in any
///     state, becomes an intent at once (a dead-man revert is rejecting only
///     with the persisted hop evidence); `confirmed` gets the confirmed
///     record; other verdicts and causes are `undone/<cause>`; stale is
///     `unknown`. A verdict-less G is aborted (a config-lock holder only; a
///     no-op once a verdict is recorded) and waited for at most 60 s; still
///     none: the file stays. An unknown G is aborted too, which tombstones it,
///     so a `start` the dead verb left in flight answers stale.
///   - A failed hop increments `rfails`; before `expires_at`, or past it while
///     `rfails` is below 3, the file stays. Past it, once three full-length
///     hops in a row have failed, the expiry rule settles it (expiryFinal).
pub fn recoverInflight(arena: Allocator, ctx: *const plugin.Ctx, opts: RecoverOptions) Recovery {
	const io = ctx.io;
	const icd = icdOf(ctx);
	var inf = readInflight(arena, io, icd) catch |err| switch (err) {
		error.FileNotFound => return .resolved,
		else => {
			// The file is replaced atomically, so only a host-disk fault writes
			// one that does not parse. Nothing in it can be acted on; on a
			// stopped instance nothing is left to read either.
			if (opts.holds_config_lock and !plugin.isRunning(ctx)) {
				deleteInflight(io, icd);
				writeRecovered(arena, ctx, null, Outcome.with(.unknown, null, &.{"relaunched"}));
				return .resolved;
			}
			return .unresolved;
		},
	};
	var rc: Recoverer = .{ .arena = arena, .ctx = ctx, .opts = opts, .icd = icd, .inf = &inf };
	return rc.run();
}

const Recoverer = struct {
	arena: Allocator,
	ctx: *const plugin.Ctx,
	opts: RecoverOptions,
	icd: []const u8,
	inf: *Inflight,

	fn io(rc: *const Recoverer) Io {
		return rc.ctx.io;
	}

	fn run(rc: *Recoverer) Recovery {
		switch (rc.boot()) {
			.same => {},
			// Neither this boot nor another can be told (qemu.start or the host
			// boot id unreadable on a running instance): settling now could drop
			// a confirmed G's record, so the file stays.
			.unknown => return .unresolved,
			.changed => {
				if (!rc.opts.holds_config_lock) return .unresolved;
				// The dead verb's rejection is rolled back before the next boot.
				if (rc.pendingIntent()) |intent| return rc.resolveRejected(.{ .result = .rejected, .reason = Reason.fromRollback(intent.reason), .rejecting = intent.reason }, intent.target, intent.target_id);
				// A launcher pass or a plugin verb may have finished it already.
				const recs = rollback.readRecords(rc.arena, rc.io(), rc.icd) catch rollback.Records{};
				if (recs.find(rc.inf.G)) |rec| return rc.resolveRejected(.{ .result = .rejected, .reason = Reason.fromRollback(rec.reason), .rejecting = rec.reason }, rec.target, rec.target_id);
				// A rejection `seen` records whose intent never became durable
				// (its writer died between the two writes, or the intent write
				// failed): the host saw it, so it is an intent now.
				if (rc.inf.hops.seen) |seen| if (!std.mem.eql(u8, seen, "confirmed")) {
					const f = tokenFinal(rc.arena, seen, rc.inf.hops, false);
					if (f.rejecting != null) return rc.settle(f);
				};
				return rc.resolve(Outcome.with(.unknown, null, &.{"relaunched"}));
			},
		}
		const h = rc.hop(&.{ "status", rc.inf.G, "--boot-id", rc.inf.boot_id }, rc.opts.hop_ms);
		if (h.stopped != null) return .unresolved;
		const rep = h.reply orelse return rc.hopFailed();
		return rc.onReply(rep, true);
	}

	/// Whether the instance runs the boot inflight.json names, on the same host
	/// boot (bootState).
	fn boot(rc: *const Recoverer) BootState {
		return bootState(rc.arena, rc.ctx, rc.inf.nonce, rc.inf.host_boot);
	}

	fn hop(rc: *const Recoverer, verb: []const []const u8, kill_ms: i64) HopResult {
		return guestHop(rc.arena, rc.io(), rc.ctx.parent_env, rc.ctx.runtime_path, rc.opts.ssh_identity, verb, .{ .deadline_ms = nowMs(rc.io()) + kill_ms });
	}

	fn persist(rc: *Recoverer, changed: bool) void {
		if (!changed) return;
		writeInflight(rc.arena, rc.io(), rc.icd, rc.inf.*, rc.ctx.real_uid) catch |err| {
			warnf(rc.arena, rc.io(), "could not update apply/inflight.json ({s})", .{@errorName(err)});
			return;
		};
		noteDurable(.hops);
	}

	fn noteOk(rc: *Recoverer, recorded: ?[]const u8) void {
		rc.persist(noteRecoverHop(&rc.inf.hops, true, recorded, rc.opts.short_hop));
	}

	fn hopFailed(rc: *Recoverer) Recovery {
		if (rc.opts.short_hop) return .unresolved;
		rc.persist(noteRecoverHop(&rc.inf.hops, false, null, false));
		if (bootSeconds(rc.io()) < rc.inf.expires_at or rc.inf.hops.rfails < Bounds.streak_evidence) return .unresolved;
		return rc.settle(expiryFinal(rc.arena, rc.inf.hops));
	}

	fn onReply(rc: *Recoverer, rep: Reply, may_abort: bool) Recovery {
		const result = rep.get("result") orelse "";
		if (std.mem.eql(u8, result, "ok")) {
			const v = viewOf(rc.arena, rep, rc.inf.G) orelse {
				rc.noteOk(null);
				return .unresolved;
			};
			// A rejecting verdict becomes the intent before `seen` records it,
			// as in the live verb (noteView). The recoverer's own evidence
			// (`rfails`, `seen`) never changes the judgement.
			const j = judge(rc.arena, v, rc.inf.hops);
			if (j == .final) if (j.final.rejecting) |reason| {
				if (!rc.writeIntentFor(reason)) {
					rc.noteOk(v.recorded());
					return .unresolved;
				}
			};
			rc.noteOk(v.recorded());
			return rc.onView(v, may_abort);
		}
		rc.noteOk(null);
		// The guest booted again, or G is a tombstone: nothing of G remains.
		if (std.mem.eql(u8, result, "stale_boot") or std.mem.eql(u8, result, "tombstoned")) return rc.settle(.{ .result = .unknown, .terminal = true });
		if (std.mem.eql(u8, result, "unknown")) {
			if (!rc.opts.holds_config_lock or !may_abort) return .unresolved;
			return rc.abortThenWait();
		}
		// lock_timeout, error, anything else: the file stays.
		return .unresolved;
	}

	fn onView(rc: *Recoverer, v: GuestView, may_abort: bool) Recovery {
		switch (judge(rc.arena, v, rc.inf.hops)) {
			.final => |f| return rc.settle(f),
			.pending, .switched => {
				if (!rc.opts.holds_config_lock or !may_abort) return .unresolved;
				return rc.abortThenWait();
			},
		}
	}

	/// `abort G` (a no-op once a verdict is recorded; it tombstones an unknown
	/// G), then status polls until a verdict or cause is recorded, at most
	/// abort_wait_ms in all. Still none: the file stays for the next recoverer.
	fn abortThenWait(rc: *Recoverer) Recovery {
		const until = nowMs(rc.io()) + rc.opts.abort_wait_ms;
		const a = rc.hop(&.{ "abort", rc.inf.G, "--boot-id", rc.inf.boot_id }, @min(Bounds.hop_ms, rc.opts.abort_wait_ms));
		if (a.stopped != null) return .unresolved;
		if (a.reply) |rep| {
			const result = rep.get("result") orelse "";
			if (std.mem.eql(u8, result, "ok") or std.mem.eql(u8, result, "tombstoned") or std.mem.eql(u8, result, "stale_boot")) {
				const res = rc.onReply(rep, false);
				if (res == .resolved) return res;
			}
		} else rc.persist(noteRecoverHop(&rc.inf.hops, false, null, rc.opts.short_hop));
		while (true) {
			const left = until - nowMs(rc.io());
			if (left <= 0) return .unresolved;
			const wait_s = std.fmt.allocPrint(rc.arena, "{d}", .{std.math.clamp(@divTrunc(left, 1000) - 2, 0, 25)}) catch return .unresolved;
			const s = rc.hop(&.{ "status", rc.inf.G, "--boot-id", rc.inf.boot_id, "--wait", wait_s }, @max(@min(Bounds.hop_ms, left), 1));
			if (s.stopped != null) return .unresolved;
			if (s.reply) |rep| {
				const result = rep.get("result") orelse "";
				if (!std.mem.eql(u8, result, "lock_timeout")) {
					const res = rc.onReply(rep, false);
					if (res == .resolved) return res;
					// A verdict was read but could not be settled (its intent
					// could not be written): nothing more to wait for.
					if (rc.inf.hops.seen != null) return res;
				}
			}
			const slice = @min(rc.opts.pause_ms, until - nowMs(rc.io()));
			if (slice > 0) Io.sleep(rc.io(), Io.Duration.fromMilliseconds(slice), .awake) catch {};
		}
	}

	/// Act on a decided outcome. A rejecting one becomes an intent whatever the
	/// lock (spec 4.6: any recoverer); everything else, and the rollback, needs
	/// the config lock.
	fn settle(rc: *Recoverer, f: Final) Recovery {
		if (f.rejecting) |reason| {
			if (!rc.writeIntentFor(reason)) return .unresolved;
			if (!rc.opts.holds_config_lock) return .unresolved;
			return rc.resolveRejected(f, .base, rc.inf.base_id);
		}
		if (!rc.opts.holds_config_lock) return .unresolved;
		// Every record but the rollback requires the boot inflight.json names
		// (a relaunch re-promoted B at boot). A confirmed record that fails, or
		// a boot that cannot be told, keeps the file: the next recoverer redoes
		// the record, and until then applies and plugin changes wait on it.
		switch (rc.boot()) {
			.same => switch (f.result) {
				.applied, .applied_with_failures => confirmedRecord(rc.arena, rc.ctx, rc.icd, rc.ctx.real_uid, rc.inf.scratch_id, rc.inf.R, rc.inf.key, rc.inf.nonce) catch return .unresolved,
				.undone, .failed, .restart_required => builtRecord(rc.arena, rc.ctx, rc.icd, rc.ctx.real_uid, rc.inf.scratch_id, rc.inf.R, rc.inf.key, Outcome.of(f.result, f.reason)),
				else => {},
			},
			.unknown => return .unresolved,
			.changed => {},
		}
		return rc.resolve(finalOutcome(rc.arena, rc.io(), f, rc.inf.T, rc.inf.P));
	}

	/// The intent for a rejection of G read from inflight.json (target B, its
	/// scope). Idempotent: an intent or a record G already has is kept.
	fn writeIntentFor(rc: *Recoverer, reason: rollback.Reason) bool {
		_ = rollback.writeIntent(rc.arena, rc.io(), rc.icd, .{
			.G = rc.inf.G,
			.op = rc.inf.op,
			.reason = reason,
			.target = .base,
			.target_id = rc.inf.base_id,
			.scope = rc.inf.scope,
		}, .{ .owner = rc.ctx.real_uid }) catch |err| {
			warnf(rc.arena, rc.io(), "could not write the rollback intent ({s})", .{@errorName(err)});
			return false;
		};
		noteDurable(.intent);
		return true;
	}

	/// The rollback of a rejection whose intent is on disk: one finishPending
	/// under the locks the caller holds; last.json carries its rollback object.
	fn resolveRejected(rc: *Recoverer, f: Final, target: rollback.Target, target_id: []const u8) Recovery {
		var o = finalOutcome(rc.arena, rc.io(), f, rc.inf.T, rc.inf.P);
		const rf = finishRollbackFor(rc.arena, rc.ctx, rc.inf.G, target, target_id);
		if (rc.opts.fin_out) |p| p.* = rf.fin;
		o.rollback = rf.out;
		return rc.resolve(o);
	}

	/// Always under the config lock (every caller checks holds_config_lock). A
	/// forced G's completion goes to audit.log after the file is gone, so a
	/// crash between the two loses the line rather than writing it twice.
	fn resolve(rc: *Recoverer, o: Outcome) Recovery {
		deleteInflight(rc.io(), rc.icd);
		writeRecovered(rc.arena, rc.ctx, rc.inf, o);
		if (rc.inf.forced) |f| appendForceAudit(rc.arena, rc.io(), rc.icd, rc.ctx.real_uid, .{
			.phase = .done,
			.at = Io.Timestamp.now(rc.io(), .real).toSeconds(),
			.gen = rc.inf.G,
			.op = rc.inf.op,
			.uid = auditUid(rc.ctx.real_uid),
			.euid = std.c.geteuid(),
			.plan = f.plan,
			.forced = true,
			.units = f.units,
			.result = o.result,
			.reason = o.reason,
			.recovered = true,
		});
		return .resolved;
	}

	/// The intent the dead verb wrote for G, when one is on disk and parses.
	fn pendingIntent(rc: *const Recoverer) ?rollback.Intent {
		var dir = snapshot.openIcd(rc.io(), rc.icd) catch return null;
		defer dir.close(rc.io());
		const name = std.fmt.allocPrint(rc.arena, "{s}.intent", .{rc.inf.G}) catch return null;
		const rel = std.fmt.allocPrint(rc.arena, "apply/rollback/{s}", .{name}) catch return null;
		const bytes = snapshot.readNoFollow(rc.arena, rc.io(), dir, rel, 4 << 20) catch return null;
		return rollback.parseIntent(rc.arena, bytes, name) catch null;
	}
};

/// last.json for a recovered (or abandoned) generation: the report a live verb
/// would have written, with the op from inflight.json.
fn writeRecovered(arena: Allocator, ctx: *const plugin.Ctx, inf: ?*const Inflight, o: Outcome) void {
	const io = ctx.io;
	const icd = icdOf(ctx);
	const rep: Report = .{
		.gen = if (inf) |x| x.G else null,
		.op = if (inf) |x| x.op else null,
		.result = o.result,
		.reason = o.reason,
		.detail = if (o.detail.len > 0) o.detail else null,
		.overridable = false,
		.plan = null,
		.forced = if (inf) |x| x.forced else null,
		.rollback = o.rollback,
		.runner = if (inf) |x| x.R else null,
		.toplevel = if (inf) |x| x.T else null,
		.units = o.units,
		.rolled_back_guest = o.rolled_back_guest,
		.cap = null,
		.base_id = roleIdIn(arena, io, icd, .base),
		.built_id = roleIdIn(arena, io, icd, .built),
	};
	const line = reportLine(arena, rep) catch return;
	writeApplyFile(arena, io, icd, "last.json", line, ctx.real_uid) catch |err| {
		warnf(arena, io, "could not write apply/last.json ({s})", .{@errorName(err)});
	};
}

fn roleIdIn(arena: Allocator, io: Io, icd: []const u8, role: snapshot.Role) ?[]const u8 {
	const id = snapshot.roleId(io, icd, role) orelse return null;
	return arena.dupe(u8, &id) catch null;
}

// --- record and report (steps 10 and 11) -------------------------------------------------------

/// Whether an outcome needs step 10's config lock: every rollback (an
/// eval_error's and a live rejection's), the confirmed record (`applied`,
/// `applied_with_failures`, `already_live`), and K := S after a successful
/// stage (a). Everything else (last.json, apply/active, inflight.json) is
/// written under the apply flock alone, so a superseded run never waits for the
/// config lock while a plugin change waits for its flock.
fn needsRecordLock(r: *const Run, o: Outcome) bool {
	switch (o.result) {
		.rejected, .already_live, .applied, .applied_with_failures => return true,
		.restart_required, .failed, .undone => return r.stage_a_ok and r.s_taken,
		.superseded, .unknown, .not_running => return false,
	}
}

/// What a rejection rolls back to: K (else B) for an eval_error, B for a live
/// rejection (spec 4.6).
fn rollbackTarget(r: *const Run, o: Outcome) struct { rollback.Target, []const u8 } {
	if (o.reason == .eval_error) return .{ r.eval_target, r.eval_target_id };
	return .{ .base, &r.identity.?.base_id };
}

/// The guest phase's terminate path: no record, no report, inflight.json left
/// for a recoverer; apply/active goes and both locks are released.
fn exitNow(r: *Run, code: u8) u8 {
	if (r.flock_held and r.active_written) clearActive(r.io, r.icd);
	if (r.config_held) unlockFd(r.host.config_fd);
	if (r.flock_held) unlockFd(r.host.apply_fd);
	return code;
}

/// Step 10, then the report. Returns the exit code. The config lock is
/// retaken with a timed acquire that the terminate flag interrupts; from the
/// moment it is held until the report the flag is ignored (the step-10
/// section: no signaller that holds the config lock can be waiting then, and a
/// SIGKILL there is covered by the intent and by inflight.json). Every record
/// but the rollback requires the boot preflight saw (a relaunch re-promoted B
/// at boot).
pub fn finish(r: *Run, o_in: Outcome) u8 {
	var o = o_in;
	const io = r.io;
	const arena = r.arena;
	if (r.blocked) {
		if (r.active_written) clearActive(io, r.icd);
		if (r.config_held) unlockFd(r.host.config_fd);
		if (r.flock_held) unlockFd(r.host.apply_fd);
		return 78;
	}
	if (o.exit_now) |code| return exitNow(r, code);
	// From `start` on, the acquire is part of the guest phase's terminate path
	// and of the whole-verb timer.
	const in_guest = r.inflight_written;
	if (r.flock_held and !r.config_held and needsRecordLock(r, o)) {
		const lock_ms = if (in_guest) std.math.clamp(r.wholeLeftMs(), 0, Bounds.record_lock_ms) else Bounds.record_lock_ms;
		// A build-phase run that waits only to record K := S gives the wait up
		// to a plugin change's supersede request (spec 4.8: honoured in phase
		// build outside the step-10 section, which starts once the lock is
		// held), so that change does not wait out its 60 s bound and exit 69.
		const k_only = !in_guest and r.phase == .build and switch (o.result) {
			.restart_required, .failed, .undone => true,
			else => false,
		};
		if (pollFlock(io, r.host.config_fd, lock_ms, &terminate, if (k_only) &supersede else null)) |_| {
			r.config_held = true;
		} else |err| {
			if (in_guest and (err == error.Canceled or r.wholeLeftMs() <= 0)) {
				const x = guestTerminate(r, err != error.Canceled);
				return exitNow(r, x.exit_now.?);
			}
			if (err == error.Canceled and o.reason != .eval_error) exitOnTerminate(r);
			if (err == error.Superseded) o = Outcome.of(.superseded, null);
			// The record waits. K := S and the runner record are skipped: the
			// older K (else B) stays the eval_error target, so a later
			// eval_error this boot also undoes this change, which the guest
			// does not run (a residual, as for a K := S the boot could not be
			// told for or whose apply/built write failed). A rollback stays
			// pending (its intent is durable, and the next plugin verb or
			// launch finishes it); a confirmed generation keeps inflight.json,
			// whose recovery records it.
			if (o.result == .rejected) {
				const tg = rollbackTarget(r, o);
				o.rollback = .{ .status = .pending, .target = tg[0], .target_id = tg[1] };
			}
			if (o.result == .applied or o.result == .applied_with_failures) r.keep_inflight = true;
		}
	}
	if (r.flock_held and r.config_held) {
		const boot: BootState = if (r.nonce.len > 0) bootState(arena, r.ctx, r.nonce, null) else .changed;
		switch (o.result) {
			.rejected => {
				const tg = rollbackTarget(r, o);
				o.rollback = finishOwnRollback(r, tg[0], tg[1]);
			},
			// A confirmed record that fails part-way, or a boot that cannot be
			// told, keeps inflight.json, whose recovery redoes the record; until
			// then every apply and plugin change waits on it.
			.already_live, .applied, .applied_with_failures => switch (boot) {
				.same => recordConfirmed(r) catch {
					r.keep_inflight = true;
				},
				.unknown => {
					warnf(arena, io, "could not tell whether the instance still runs the boot this apply saw; the record is not made{s}", .{if (in_guest) " (a recovery of apply/inflight.json makes it)" else ""});
					r.keep_inflight = true;
				},
				.changed => {},
			},
			.restart_required, .failed, .undone => if (r.stage_a_ok and r.s_taken and boot == .same) recordBuilt(r, o),
			else => {},
		}
	}
	if (r.flock_held and in_guest and !r.keep_inflight) deleteInflight(io, r.icd);
	auditForceDone(r, o);
	if (r.flock_held and r.config_held and r.s_taken) _ = snapshot.gc(arena, io, r.icd, &.{}, r.owner);
	// A build unit whose stop was not confirmed keeps apply/active, its record
	// (terminateBuild).
	if (r.flock_held and r.active_written and !r.unit_live) clearActive(io, r.icd);
	return report(r, o);
}

/// An admitted Apply anyway run's completion line in audit.log, once its
/// inflight.json is gone (one that keeps it gets the line from the recoverer
/// that resolves it, Recoverer.resolve): under the config lock when this run
/// holds it, else after a LOCK_NB try (a try never waits, so the lock order
/// holds), released right after. A run whose config lock is busy then (a
/// superseded run behind its superseder, a step-10 wait that ran out) keeps
/// only its admission line and last.json.
fn auditForceDone(r: *Run, o: Outcome) void {
	const sp = r.force_admitted orelse return;
	if (!r.flock_held or r.keep_inflight) return;
	var took = false;
	if (!r.config_held) {
		took = tryFlock(r.host.config_fd) catch false;
		if (!took) {
			warnf(r.arena, r.io, "could not record the end of the apply anyway in apply/{s} (the config lock is busy)", .{rollback.audit_file});
			return;
		}
	}
	defer if (took) unlockFd(r.host.config_fd);
	const sent = if (r.inflight_written) r.forced else null;
	appendForceAudit(r.arena, r.io, r.icd, r.owner, .{
		.phase = .done,
		.at = Io.Timestamp.now(r.io, .real).toSeconds(),
		.gen = &r.gen,
		.op = r.args.op,
		.uid = auditUid(r.owner),
		.euid = std.c.geteuid(),
		.plan = sp.plan.id,
		.forced = sent != null,
		.units = if (sent) |f| f.units else &.{},
		.result = o.result,
		.reason = o.reason,
		.recovered = false,
	});
}

/// This run's rollback, from the on-disk intent for G (spec 4.6); exit 78 when
/// it stays pending.
fn finishOwnRollback(r: *Run, target: rollback.Target, target_id: []const u8) RollbackOut {
	const fin = finishRollbackFor(r.arena, r.ctx, &r.gen, target, target_id);
	if (fin.blocked) r.exit_code = 78;
	return fin.out;
}

const RollbackFin = struct {
	out: RollbackOut,
	blocked: bool = false,
	/// The finishPending's own result (every intent it finished or left).
	fin: rollback.FinishResult = .{},
};

/// Finish generation `gen`'s rollback: one finishPending under the config
/// lock and the apply flock the caller holds. The report's rollback object
/// (`pending` with `target`, when the intent stays); `blocked` when an intent
/// stays, after the stamped message went to stderr. When another config-lock
/// holder (a launcher pass, a plugin verb) already finished it, its record is
/// reported.
fn finishRollbackFor(arena: Allocator, ctx: *const plugin.Ctx, gen: []const u8, target: rollback.Target, target_id: []const u8) RollbackFin {
	const io = ctx.io;
	const pending: RollbackOut = .{ .status = .pending, .target = target, .target_id = target_id };
	const fin = rollback.finishPending(arena, ctx, .{ .holds_apply_flock = true });
	writeFinishWarnings(arena, io, fin);
	const file = std.fmt.allocPrint(arena, "{s}.intent", .{gen}) catch return .{ .out = pending, .blocked = fin.pending > 0, .fin = fin };
	for (fin.outcomes) |oc| {
		if (!std.mem.eql(u8, oc.file, file)) continue;
		switch (oc.result) {
			.finished => |f| return .{ .out = RollbackOut.fromReport(f.report()), .fin = fin },
			.discarded => return .{ .out = pending, .fin = fin },
			.pending => {
				var buf: [512]u8 = undefined;
				var w: Io.Writer = .fixed(&buf);
				rollback.writePendingMessage(&w, oc.result.pending, ctx.instance) catch {};
				errOut(io, w.buffered());
				return .{ .out = pending, .blocked = true, .fin = fin };
			},
		}
	}
	const recs = rollback.readRecords(arena, io, icdOf(ctx)) catch return .{ .out = pending, .blocked = fin.pending > 0, .fin = fin };
	if (recs.find(gen)) |rec| return .{ .out = .{
		.status = switch (rec.status) {
			.done => .done,
			.removed => .removed,
		},
		.target = rec.target,
		.target_id = rec.target_id,
		.names = rec.names,
		.policy_not_restored = rec.policy_not_restored,
		.seq = rec.seq,
	}, .fin = fin };
	return .{ .out = pending, .blocked = fin.pending > 0, .fin = fin };
}

/// Whether plugins-flake/ still holds exactly snapshot `s`'s composition bytes.
fn pluginsFlakeEquals(arena: Allocator, ctx: *const plugin.Ctx, s: *const snapshot.Snapshot) bool {
	const nix_p = std.fs.path.join(arena, &.{ ctx.plugins_flake_dir, "flake.nix" }) catch return false;
	const lock_p = std.fs.path.join(arena, &.{ ctx.plugins_flake_dir, "flake.lock" }) catch return false;
	const cur_nix: ?[]u8 = readSmall(arena, ctx.io, nix_p, snapshot.max_flake_bytes) catch |err| if (err == error.FileNotFound) null else return false;
	const cur_lock: ?[]u8 = readSmall(arena, ctx.io, lock_p, snapshot.max_flake_bytes) catch |err| if (err == error.FileNotFound) null else return false;
	if ((cur_nix == null) != (s.flake_nix == null)) return false;
	if ((cur_lock == null) != (s.flake_lock == null)) return false;
	if (cur_nix) |b| if (!std.mem.eql(u8, b, s.flake_nix.?)) return false;
	if (cur_lock) |b| if (!std.mem.eql(u8, b, s.flake_lock.?)) return false;
	return true;
}

/// runner.path for a runner realised from snapshot `s` under `key`: only when
/// `key` is the current COGBOX_FLAKE_SOURCE#COGBOX_REEXEC_PACKAGE (a record is
/// trusted on its key alone, so a newer cogbox never files an older image's
/// runner under its own key; under another key the record is removed), and
/// only while plugins-flake/ still byte-equals `s` (R was realised from exactly
/// these bytes, so composition.lock.prev and the repin verdict go with it).
fn runnerRecordFor(arena: Allocator, ctx: *const plugin.Ctx, s: *const snapshot.Snapshot, runner: []const u8, key: []const u8) void {
	const current = currentKey(arena, ctx) orelse return plugin.removeRunnerRecord(ctx);
	if (!std.mem.eql(u8, current, key)) return plugin.removeRunnerRecord(ctx);
	if (s.meta.comp.len != snapshot.comp_hex_len or !pluginsFlakeEquals(arena, ctx, s)) return;
	const src = ctx.parent_env.get("COGBOX_FLAKE_SOURCE") orelse return;
	if (plugin.tryWriteRunnerRecord(ctx, src, runner, s.meta.comp)) {
		plugin.clearPrevLock(ctx);
		plugin.clearRepinFailed(ctx);
	}
}

/// K := S after a successful stage (a) (spec section 2 step 10), and for the
/// restart_required kinds that record R: R and its key into S's meta.json and
/// runner.path (runnerRecordFor). Never for a rejection.
fn builtRecord(arena: Allocator, ctx: *const plugin.Ctx, icd: []const u8, owner: ?u32, scratch_id: []const u8, runner: ?[]const u8, key: []const u8, o: Outcome) void {
	const io = ctx.io;
	if (o.result == .restart_required and o.reason != null and o.reason.?.recordsRunner()) {
		if (runner) |rn| {
			snapshot.recordRunner(arena, io, icd, scratch_id, rn, key, owner) catch |err| {
				warnf(arena, io, "could not record the built runner in the snapshot ({s})", .{@errorName(err)});
			};
			if (snapshot.read(arena, io, icd, scratch_id)) |s| runnerRecordFor(arena, ctx, &s, rn, key) else |_| {}
		}
	}
	snapshot.setRole(io, icd, .built, scratch_id, owner) catch |err| {
		warnf(arena, io, "could not record the built snapshot ({s})", .{@errorName(err)});
	};
}

fn recordBuilt(r: *Run, o: Outcome) void {
	builtRecord(r.arena, r.ctx, r.icd, r.owner, &r.scratch_id, r.runner, r.key, o);
}

/// The confirmed record (spec section 2 step 10; a recovery redoes it from
/// inflight.json), under the config lock while the instance runs the boot
/// `nonce`: R and its key into S's meta.json (a later rollback to this base
/// keeps the fast path); B := S by an atomic symlink flip, and K unlinked;
/// $RUNTIME/live-runner = key, R, S's comp, nonce; then runner.path
/// (runnerRecordFor). Each step is a target-state assignment, so a crash
/// between the flip and the live-runner write (a base that matches neither
/// record: no_boot_record) is repaired by the next recovery of the
/// inflight.json the crash left. A step that fails (ENOSPC, EIO) leaves the
/// base, and K, behind what the guest now runs, and a later rollback to either
/// would drop this live change: both are unlinked (an unlink needs no free
/// space), so preflight answers no_boot_record until the record is redone or a
/// relaunch re-promotes B, and the error is returned, so the caller keeps
/// inflight.json for a recoverer.
fn confirmedRecord(arena: Allocator, ctx: *const plugin.Ctx, icd: []const u8, owner: ?u32, scratch_id: []const u8, runner: []const u8, key: []const u8, nonce: []const u8) !void {
	const io = ctx.io;
	errdefer dropRoles(arena, io, icd);
	const s = snapshot.read(arena, io, icd, scratch_id) catch |err| {
		warnf(arena, io, "could not read the applied snapshot ({s})", .{@errorName(err)});
		return err;
	};
	snapshot.recordRunner(arena, io, icd, scratch_id, runner, key, owner) catch |err| {
		warnf(arena, io, "could not record the runner in the snapshot ({s})", .{@errorName(err)});
		return err;
	};
	snapshot.setRole(io, icd, .base, scratch_id, owner) catch |err| {
		warnf(arena, io, "could not promote the snapshot to the base ({s})", .{@errorName(err)});
		return err;
	};
	snapshot.clearRole(io, icd, .built) catch |err| {
		warnf(arena, io, "could not unlink the built snapshot ({s})", .{@errorName(err)});
		return err;
	};
	writeLiveRunner(arena, io, ctx.runtime_path, owner, key, runner, s.meta.comp, nonce) catch |err| {
		warnf(arena, io, "could not write live-runner ({s})", .{@errorName(err)});
		return err;
	};
	runnerRecordFor(arena, ctx, &s, runner, key);
}

/// A failed confirmed record's base and K go: neither holds what the guest runs.
fn dropRoles(arena: Allocator, io: Io, icd: []const u8) void {
	for ([_]snapshot.Role{ .base, .built }) |role| snapshot.clearRole(io, icd, role) catch |err| {
		warnf(arena, io, "could not unlink apply/{s} ({s})", .{ @tagName(role), @errorName(err) });
	};
	warnf(arena, io, "the live plugin state could not be recorded; live applies answer no_boot_record until it is or the instance restarts", .{});
}

fn recordConfirmed(r: *Run) !void {
	const runner = r.runner orelse return;
	try confirmedRecord(r.arena, r.ctx, r.icd, r.owner, &r.scratch_id, runner, r.key, r.nonce);
}

/// `$RUNTIME/live-runner` (key, R, comp, boot nonce), a new file.
fn writeLiveRunner(arena: Allocator, io: Io, runtime: []const u8, owner: ?u32, key: []const u8, runner: []const u8, comp: []const u8, nonce: []const u8) !void {
	var dir = try Io.Dir.cwd().openDir(io, runtime, .{});
	defer dir.close(io);
	const bytes = try std.fmt.allocPrint(arena, "{s}\n{s}\n{s}\n{s}\n", .{ key, runner, comp, nonce });
	try snapshot.writeNew(io, dir, "live-runner", bytes, owner);
}

/// Step 11: last.json first (when this run owns apply/), then stdout. Both
/// locks are released before stdout is written, so a stalled reader never
/// holds them.
fn report(r: *Run, o: Outcome) u8 {
	const io = r.io;
	const arena = r.arena;
	const rep: Report = .{
		.gen = if (r.flock_held) @as([]const u8, &r.gen) else null,
		.op = r.args.op,
		.result = o.result,
		.reason = o.reason,
		.detail = if (o.detail.len > 0) o.detail else null,
		.overridable = o.overridable(),
		.plan = o.plan,
		// Exactly when a forced `start` was attempted, whether or not it
		// sent a list (inflight.json, written before every attempt, carries
		// it too).
		.forced = if (r.inflight_written) r.forced else null,
		.rollback = o.rollback,
		.runner = r.runner,
		.toplevel = r.toplevel,
		.units = o.units,
		.rolled_back_guest = o.rolled_back_guest,
		.cap = r.cap,
		.base_id = if (r.flock_held) roleIdOrNull(r, .base) else null,
		.built_id = if (r.flock_held) roleIdOrNull(r, .built) else null,
	};
	const line = reportLine(arena, rep) catch "{\"apply\":null}\n";
	if (r.flock_held) {
		writeApplyFile(arena, io, r.icd, "last.json", line, r.owner) catch |err| {
			warnf(arena, io, "could not write apply/last.json ({s})", .{@errorName(err)});
		};
	}
	if (r.config_held) unlockFd(r.host.config_fd);
	if (r.flock_held) unlockFd(r.host.apply_fd);
	if (r.host.report_out) |dst| {
		// It outlives this Run: `gen` points into it, everything else into
		// the arena (or argv).
		dst.* = rep;
		dst.*.?.gen = if (rep.gen) |g| (arena.dupe(u8, g) catch null) else null;
	}
	if (r.args.json) {
		r.host.emit(io, line);
	} else {
		// `--force` asks about the plan itself: no hint to run it.
		r.host.emit(io, humanLine(arena, r.ctx.instance, &r.gen, r.exit_code == 78, o, rep.forced, !r.args.force));
		if (o.result == .rejected and r.exit_code == 0) return 1;
	}
	return r.exit_code;
}

fn roleIdOrNull(r: *Run, role: snapshot.Role) ?[]const u8 {
	const id = snapshot.roleId(r.io, r.icd, role) orelse return null;
	return r.arena.dupe(u8, &id) catch null;
}

/// The non-JSON report: one line, plus the units behind a plan refusal.
/// `instance` and `gen` go into the build-log hint; `blocked` when the run's
/// own rollback could not be finished (exit 78, its stamped message already on
/// stderr). `forced`, the report's: the units an Apply anyway forced get a
/// line of their own. `hint`: an overridable refusal, and the new plan of a
/// plan_changed, say how to apply it anyway, on a terminal and off one with
/// its plan id (`--force-plan`; not for `--force`, which lists the plan and
/// asks about it next). `detail` names only the units behind the refusal's
/// own reason, so the plan id comes after the whole plan (writePlanItems: every
/// unit and action, the re-exec, the repair), never before it; a plan that
/// cannot be listed gets no hint.
fn humanLine(arena: Allocator, instance: ?[]const u8, gen: []const u8, blocked: bool, o: Outcome, forced: ?Forced, hint: bool) []const u8 {
	const tag = if (o.reason) |why| std.fmt.allocPrint(arena, "{s}/{s}", .{ @tagName(o.result), @tagName(why) }) catch "" else @tagName(o.result);
	const changed = "nothing was applied: the plan changed since it was shown";
	const text: []const u8 = switch (o.result) {
		.applied, .applied_with_failures => "the plugin changes are live",
		.already_live => "the plugin state is already live",
		.restart_required => if (o.reason == .plan_expired)
			"nothing was applied: the plan to apply anyway is unknown, older than 30 minutes, or from another boot or plugin state"
		else if (o.reason == .plan_changed)
			(if (o.plan != null) changed else changed ++ " (no new plan could be stored)")
		else if (o.overridable())
			"saved; it loads at the next restart (a live apply would disrupt the units listed)"
		else
			"saved; it loads at the next restart",
		.rejected => rejectedText(arena, o.rollback, instance, gen, blocked),
		.undone => "the live apply was undone; the change loads at the next restart",
		.failed => "saved but could not be applied live; it loads at the next restart",
		.superseded => "superseded by a newer plugin change",
		.unknown => "the live apply did not report an outcome",
		.not_running => "the instance is not running; the change loads at the next start",
	};
	var line: std.ArrayList(u8) = .empty;
	line.appendSlice(arena, "plugin apply: ") catch return "";
	line.appendSlice(arena, tag) catch return "";
	line.appendSlice(arena, ": ") catch return "";
	line.appendSlice(arena, text) catch return "";
	line.append(arena, '\n') catch return "";
	if (o.detail.len > 0) {
		line.appendSlice(arena, "  ") catch return "";
		for (o.detail, 0..) |d, i| {
			if (i > 0) line.appendSlice(arena, ", ") catch return "";
			line.appendSlice(arena, d) catch return "";
		}
		line.append(arena, '\n') catch return "";
	}
	if (o.units) |units| if (units.len > 0) {
		line.appendSlice(arena, "  failed units: ") catch return "";
		for (units, 0..) |u, i| {
			if (i > 0) line.appendSlice(arena, ", ") catch return "";
			line.appendSlice(arena, u) catch return "";
		}
		line.append(arena, '\n') catch return "";
	};
	if (forced) |f| {
		line.appendSlice(arena, "  forced units: ") catch return "";
		if (f.units.len == 0) line.appendSlice(arena, "none (it only reloads units or re-executes systemd, which every check still covers)") catch return "";
		for (f.units, 0..) |u, i| {
			if (i > 0) line.appendSlice(arena, ", ") catch return "";
			line.appendSlice(arena, u) catch return "";
		}
		line.append(arena, '\n') catch return "";
	}
	// The plan a person may apply anyway: an overridable refusal's, or the new
	// one a plan_changed stored (wholly overridable by construction).
	const offer: ?Plan = if (o.overridable() or (o.result == .restart_required and o.reason == .plan_changed)) o.plan else null;
	if (hint) if (offer) |p| {
		var items: Io.Writer.Allocating = .init(arena);
		const listed = if (writePlanItems(&items.writer, p, "    ")) |_| items.written().len > 0 else |_| false;
		if (listed) {
			const n_opt: []const u8 = if (instance) |n| (std.fmt.allocPrint(arena, " -n {s}", .{n}) catch return "") else "";
			const which: []const u8 = if (o.overridable()) "it" else "the new plan";
			line.print(arena, "  to apply it now anyway: cogbox plugin apply --force{s}\n", .{n_opt}) catch return "";
			line.print(arena, "  applying {s} anyway would:\n", .{which}) catch return "";
			line.appendSlice(arena, items.written()) catch return "";
			line.print(arena, "  without a terminal, after reading the plan above: cogbox plugin apply --force-plan {s}{s}\n", .{ p.id, n_opt }) catch return "";
		}
	};
	return line.items;
}

/// humanLine's text for a rejection, from the report's rollback object: rolled
/// back (`done`), else "not applied" and rollbackSentence. The build-log hint
/// names the instance.
fn rejectedText(arena: Allocator, rb: ?RollbackOut, instance: ?[]const u8, gen: []const u8, blocked: bool) []const u8 {
	const n_opt: []const u8 = if (instance) |n| (std.fmt.allocPrint(arena, " -n {s}", .{n}) catch "") else "";
	const sentence = rollbackSentence(if (rb) |x| x.status else null, blocked, if (rb) |x| ScopeKinds.of(x.names) else .{}) orelse {
		const done = "the change was not applied and has been rolled back";
		return std.fmt.allocPrint(arena, "{s}. Build log: cogbox plugin apply{s} --log {s}", .{ done, n_opt, gen }) catch done;
	};
	return std.fmt.allocPrint(arena, "the change was not applied. {s}. Build log: cogbox plugin apply{s} --log {s}", .{ sentence, n_opt, gen }) catch sentence;
}

/// What a rejection's rollback left when it is not simply done, as one
/// sentence (no final period) that both lines reporting it use: the apply
/// verb's (humanLine) and the inline add/del/update's (main.zig rejectedLine),
/// so one report never reads two ways. null for `done`, which each line words
/// itself. A missing status reads as pending: neither line claims a rollback it
/// cannot show. `pending` is finished by the next plugin command or start when
/// only the step-10 config lock was missing; `blocked` when the finish itself
/// could not complete (exit 78, its stamped message already on stderr), which
/// every later plugin change and start repeats until the disk is fixed or the
/// rollback abandoned. `removed` (the fail-closed tier) follows the scope: a
/// name the change added or updated was removed, and a name it removed (a
/// rolled-back del's `reinserted`) stays removed.
pub fn rollbackSentence(status: ?RollbackStatus, blocked: bool, scope: ScopeKinds) ?[]const u8 {
	return switch (status orelse .pending) {
		.done => null,
		.removed => if (!scope.deleted)
			"Its previous plugin state could not be restored, so the plugins it added or updated were removed"
		else if (!scope.changed)
			"Its previous plugin state could not be restored, so the plugins it removed stay removed"
		else
			"Its previous plugin state could not be restored, so the plugins it added or updated were removed and those it removed stay removed",
		.pending => if (blocked)
			"Its rollback could not be finished (see the message above)"
		else
			"Its rollback is pending; the next plugin command or start of the instance finishes it",
	};
}

/// rollbackSentence for a report read back as JSON (the inline apply's): the
/// `rollback` object's status (missing or unknown reads as pending) and its
/// names' actions.
pub fn rollbackSentenceJson(rb: ?std.json.Value, blocked: bool) ?[]const u8 {
	const obj = if (rb) |v| (if (v == .object) v.object else null) else null;
	var status: ?RollbackStatus = null;
	var scope: ScopeKinds = .{};
	if (obj) |o| {
		if (o.get("status")) |s| if (s == .string) {
			status = std.meta.stringToEnum(RollbackStatus, s.string);
		};
		if (o.get("names")) |n| if (n == .array) for (n.array.items) |item| {
			if (item != .object) continue;
			const a = item.object.get("action") orelse continue;
			if (a != .string) continue;
			if (std.meta.stringToEnum(snapshot.Action, a.string)) |act| scope.add(act);
		};
	}
	return rollbackSentence(status, blocked, scope);
}

/// The kinds of name a rollback's scope holds (rollbackSentence).
pub const ScopeKinds = struct {
	/// A name the change added or updated (`removed`, `restored`).
	changed: bool = false,
	/// A name the change removed (`reinserted`).
	deleted: bool = false,

	pub fn add(self: *ScopeKinds, action: snapshot.Action) void {
		switch (action) {
			.removed, .restored => self.changed = true,
			.reinserted => self.deleted = true,
		}
	}

	pub fn of(names: []const rollback.RecordName) ScopeKinds {
		var k: ScopeKinds = .{};
		for (names) |n| k.add(n.action);
		return k;
	}
};

// --- --status ---------------------------------------------------------------------------------

/// `apply --status`'s JSON object.
pub const StatusReport = struct {
	in_flight: bool,
	/// `active` (a live holder) or `inflight_unresolved`; null when idle.
	in_flight_reason: ?[]const u8,
	/// last.json's `apply` object, as stored.
	last: ?std.json.Value,
	base_id: ?[]const u8,
	built_id: ?[]const u8,
	rollbacks: []const rollback.Record,
	records_id: ?[]const u8,
	/// Intents that stay (a rollback that could not finish).
	rollback_pending: usize,
};

fn runStatus(arena: Allocator, ctx: *const plugin.Ctx, args: cli.ApplyArgs, host: Host) u8 {
	const io = ctx.io;
	ignoreSigpipe();
	const icd = icdOf(ctx);
	// With the config lock and the apply flock (LOCK_NB: a plugin change that
	// holds it recovers on its own), recover an orphaned inflight.json and
	// finish a pending rollback. Without the config lock, only report.
	var finished_here = false;
	if (host.config_held) {
		if (tryFlock(host.apply_fd) catch false) {
			defer unlockFd(host.apply_fd);
			finished_here = true;
			var rec_fin: ?rollback.FinishResult = null;
			if (inflightExists(io, icd)) _ = recoverInflight(arena, ctx, .{ .holds_config_lock = true, .ssh_identity = host.ssh_identity, .fin_out = &rec_fin });
			// One finish: the recovery's, when it ran one.
			if (rec_fin == null) {
				const fin = rollback.finishPending(arena, ctx, .{ .holds_apply_flock = true });
				writeFinishWarnings(arena, io, fin);
			}
		}
	}
	const pending = rollback.pendingIntents(arena, io, icd) catch &.{};
	// Only an intent this call's own finish left is one that could not be
	// finished. Without the locks it may be a live apply's or a plugin
	// change's rollback in progress; rollback_pending still counts it.
	if (pending.len > 0 and finished_here) {
		var buf: [512]u8 = undefined;
		var w: Io.Writer = .fixed(&buf);
		rollback.writePendingMessage(&w, error.RollbackPending, ctx.instance) catch {};
		errOut(io, w.buffered());
	}
	const st = statusOf(arena, io, icd, args.since, pending.len);
	if (host.config_held) unlockFd(host.config_fd);
	if (args.json) {
		var aw: Io.Writer.Allocating = .init(arena);
		std.json.Stringify.value(.{ .status = st }, .{}, &aw.writer) catch return 70;
		aw.writer.writeByte('\n') catch return 70;
		host.emit(io, aw.written());
	} else {
		var aw: Io.Writer.Allocating = .init(arena);
		const w = &aw.writer;
		w.print("in flight: {s}{s}{s}\n", .{ if (st.in_flight) "yes" else "no", if (st.in_flight_reason != null) " " else "", st.in_flight_reason orelse "" }) catch {};
		if (st.last) |l| {
			const result = if (objGet(l, "result")) |v| (if (v == .string) v.string else "?") else "?";
			const reason = if (objGet(l, "reason")) |v| (if (v == .string) v.string else "") else "";
			const gen = if (objGet(l, "gen")) |v| (if (v == .string) v.string else "") else "";
			w.print("last: {s}{s}{s} (generation {s})\n", .{ result, if (reason.len > 0) "/" else "", reason, gen }) catch {};
		} else w.writeAll("last: none\n") catch {};
		w.print("base: {s}\nbuilt: {s}\nrollbacks: {d}, pending: {d}\n", .{ st.base_id orelse "none", st.built_id orelse "none", st.rollbacks.len, st.rollback_pending }) catch {};
		host.emit(io, aw.written());
	}
	return 0;
}

pub fn statusOf(arena: Allocator, io: Io, icd: []const u8, since: u64, pending: usize) StatusReport {
	var st: StatusReport = .{
		.in_flight = false,
		.in_flight_reason = null,
		.last = null,
		.base_id = null,
		.built_id = null,
		.rollbacks = &.{},
		.records_id = null,
		.rollback_pending = pending,
	};
	if (readActive(arena, io, icd)) |a| {
		if (holderAlive(arena, io, a)) {
			st.in_flight = true;
			st.in_flight_reason = "active";
		}
	}
	if (!st.in_flight and inflightExists(io, icd)) {
		st.in_flight = true;
		st.in_flight_reason = "inflight_unresolved";
	}
	if (snapshot.openIcd(io, icd)) |d| {
		var dir = d;
		defer dir.close(io);
		if (snapshot.readNoFollow(arena, io, dir, "apply/last.json", 1 << 20)) |bytes| {
			if (std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{})) |v| st.last = objGet(v, "apply") else |_| {}
		} else |_| {}
	} else |_| {}
	if (snapshot.roleId(io, icd, .base)) |id| st.base_id = arena.dupe(u8, &id) catch null;
	if (snapshot.roleId(io, icd, .built)) |id| st.built_id = arena.dupe(u8, &id) catch null;
	if (rollback.readRecords(arena, io, icd)) |recs| {
		var sel: std.ArrayList(rollback.Record) = .empty;
		for (recs.items) |rec| if (rec.seq > since) sel.append(arena, rec) catch {};
		st.rollbacks = sel.items;
		if (recs.id) |id| st.records_id = arena.dupe(u8, &id) catch null;
	} else |_| {}
	return st;
}

// --- --cancel ---------------------------------------------------------------------------------

pub const CancelResult = enum {
	/// No apply was running (or none with the requested op).
	none,
	/// The holder ended and the follow-up ran.
	done,
	/// The holder is still in its step-10 section (no config lock here): it
	/// finishes and exits on the flag.
	pending,
	/// The apply flock is held by a plugin change that recovers on its own.
	busy,
};

fn runCancel(arena: Allocator, ctx: *const plugin.Ctx, args: cli.ApplyArgs, host: Host) u8 {
	const io = ctx.io;
	ignoreSigpipe();
	const icd = icdOf(ctx);
	var result: CancelResult = .none;
	var signalled = false;
	// A live holder of another run (`--op` names a run that is not the one
	// apply/active records): not this cancel's to stop, and its flock, build
	// unit and inflight.json are its own. Nothing is signalled or touched, and
	// the answer is `none`, as for no apply at all.
	var other_run = false;
	const active = readActive(arena, io, icd);
	if (active) |a| {
		if (holderAlive(arena, io, a)) {
			const op_ok = if (args.op) |want| (a.op != null and std.mem.eql(u8, a.op.?, want)) else true;
			if (op_ok) {
				signalled = true;
				const ended = signalHolder(arena, io, a, host.config_held);
				if (!ended) result = .pending;
			} else other_run = true;
		}
	}
	if (result != .pending and !other_run) {
		if (tryFlock(host.apply_fd) catch false) {
			defer unlockFd(host.apply_fd);
			// The holder is gone: stop the build unit its apply/active names,
			// by that name (holding the flock proves no live apply owns it; an
			// unreadable record, by this instance's own unit name). A stop
			// that cannot be confirmed keeps apply/active, the unit's only
			// record, for the next stopper. The record is read again under the
			// flock: before it ended, the holder may have rewritten it, or
			// cleared it once its own stop was accepted.
			const cur = readActiveForStop(arena, io, icd);
			const unit_settled = stopActiveUnit(arena, io, ctx.parent_env, icd, cur) != .failed;
			var rec_fin: ?rollback.FinishResult = null;
			if (inflightExists(io, icd)) _ = recoverInflight(arena, ctx, .{ .holds_config_lock = host.config_held, .ssh_identity = host.ssh_identity, .fin_out = &rec_fin });
			if (host.config_held) {
				// One finish: the recovery's, when it ran one.
				if (rec_fin == null) {
					const fin = rollback.finishPending(arena, ctx, .{ .holds_apply_flock = true });
					writeFinishWarnings(arena, io, fin);
				}
				if (unit_settled and cur != .absent and !(if (readActive(arena, io, icd)) |now| holderAlive(arena, io, now) else false)) clearActive(io, icd);
			}
			result = if (signalled) .done else .none;
		} else {
			result = .busy;
		}
	}
	if (host.config_held) unlockFd(host.config_fd);
	if (args.json) {
		var aw: Io.Writer.Allocating = .init(arena);
		std.json.Stringify.value(.{ .cancel = .{ .result = result, .signalled = signalled } }, .{}, &aw.writer) catch return 70;
		aw.writer.writeByte('\n') catch return 70;
		host.emit(io, aw.written());
	} else {
		const msg = switch (result) {
			.none => "cancel: no live apply is running\n",
			.done => "cancel: the live apply was stopped\n",
			.pending => "cancel: pending; the live apply finishes its record and exits\n",
			.busy => "cancel: a plugin change holds the apply lock and recovers on its own\n",
		};
		host.emit(io, msg);
	}
	return 0;
}

/// Signal the holder named by apply/active through a pidfd after the starttime
/// check: SIGTERM, wait at most 30 s; with the config lock, then SIGKILL and
/// wait at most 10 s (the holder cannot be inside its step-10 section then).
/// True when it ended.
fn signalHolder(arena: Allocator, io: Io, a: Active, with_config_lock: bool) bool {
	if (comptime !is_linux) return false;
	const rc = linux.pidfd_open(a.pid, 0);
	if (linux.errno(rc) != .SUCCESS) return true;
	const pidfd: i32 = @intCast(rc);
	defer _ = linux.close(pidfd);
	if (!holderAlive(arena, io, a)) return true;
	if (linux.errno(linux.pidfd_send_signal(pidfd, .TERM, null, 0)) == .SRCH) return true;
	if (waitPidfd(io, pidfd, holder_waits.term_ms)) return true;
	if (!with_config_lock) return false;
	_ = linux.pidfd_send_signal(pidfd, .KILL, null, 0);
	return waitPidfd(io, pidfd, holder_waits.kill_ms);
}

/// signalHolder's waits after SIGTERM and after SIGKILL (only the tests
/// shorten them).
pub const HolderWaits = struct {
	term_ms: i64 = Bounds.term_wait_ms,
	kill_ms: i64 = Bounds.kill_wait_ms,
};
pub var holder_waits: HolderWaits = .{};

/// Wait for a (non-child) process's pidfd to become readable: it exited.
fn waitPidfd(io: Io, pidfd: i32, ms: i64) bool {
	const until = nowMs(io) + ms;
	while (true) {
		const left = until - nowMs(io);
		var fds = [1]linux.pollfd{.{ .fd = pidfd, .events = linux.POLL.IN, .revents = 0 }};
		const rc = linux.poll(&fds, 1, @intCast(std.math.clamp(left, 0, Bounds.child_poll_ms)));
		if (linux.errno(rc) == .SUCCESS and rc > 0) return true;
		if (left <= 0) return false;
	}
}

pub const UnitStop = enum {
	/// Nothing of this instance runs under the name (the unit is not loaded,
	/// or it failed; for an unreadable apply/active, no systemd runs here),
	/// or apply/active names another instance's unit.
	none,
	/// The stop was queued, and the unit then ended (stop_settle_ms).
	stopped,
	/// systemctl could not tell, could not stop it, or it still ran
	/// stop_settle_ms after its stop was queued: the unit may still run.
	failed,
};

/// A stopper's wait for a stopped unit to end (Bounds.stop_settle_ms; only
/// the tests shorten it).
pub var stop_settle_ms: i64 = Bounds.stop_settle_ms;

/// sd_booted(3)'s probe: without it no systemd runs here, so no unit can
/// (only the tests point it elsewhere).
pub var systemd_dir: [:0]const u8 = "/run/systemd/system";

/// What `systemctl show -p LoadState -p ActiveState <unit>` says (KEY=VALUE
/// lines, in systemd's own order).
const UnitState = struct {
	/// `loaded`, `not-found`, ...; null when systemctl printed none.
	load: ?[]const u8 = null,
	active: []const u8,

	/// Whether something of the unit may run, or will: a loaded unit that is
	/// still inactive may have its start job queued (between
	/// StartTransientUnit and PID 1 dispatching it, the window in which
	/// systemd-run prints no InvocationID), which a stop cancels. A failed
	/// unit runs nothing, and systemd starts no transient unit under a name
	/// that is still loaded.
	fn mayRun(s: UnitState) bool {
		if (std.mem.eql(u8, s.active, "failed")) return false;
		if (s.active.len == 0 or std.mem.eql(u8, s.active, "inactive")) {
			const load = s.load orelse return true;
			return std.mem.eql(u8, load, "loaded");
		}
		return true;
	}

	/// After this stopper's stop: nothing of it runs (unloaded, inactive or
	/// failed; the stop replaced any queued start job).
	fn ended(s: UnitState) bool {
		return s.active.len == 0 or std.mem.eql(u8, s.active, "inactive") or std.mem.eql(u8, s.active, "failed");
	}
};

/// One `systemctl show` of `unit` (run through the terminate flag, killed at
/// `deadline_ms`); null when it failed or printed no ActiveState.
fn unitState(arena: Allocator, io: Io, env: *const std.process.Environ.Map, unit: []const u8, deadline_ms: i64) ?UnitState {
	const res = runChild(arena, io, .{
		.argv = &.{ "systemctl", "show", "-p", "LoadState", "-p", "ActiveState", unit },
		.env = env,
		.deadline_ms = deadline_ms,
		.out_cap = 1024,
		.err_cap = 4096,
		.ignore_terminate = true,
	});
	if (!res.exitedWith(0)) return null;
	var load: ?[]const u8 = null;
	var active: ?[]const u8 = null;
	var it = std.mem.splitScalar(u8, res.stdout.data(), '\n');
	while (it.next()) |raw| {
		const line = std.mem.trim(u8, raw, " \t\r");
		if (std.mem.startsWith(u8, line, "LoadState=")) load = line["LoadState=".len..];
		if (std.mem.startsWith(u8, line, "ActiveState=")) active = line["ActiveState=".len..];
	}
	return .{ .load = load, .active = active orelse return null };
}

/// After a queued stop: poll the unit every child_poll_ms until it ended,
/// at most stop_settle_ms (each show is cut at that bound too). A stopper
/// that went on while it is still loaded would have the next apply's stage
/// refused under the same name (failed/build). True once it ended.
fn waitUnitEnded(arena: Allocator, io: Io, env: *const std.process.Environ.Map, unit: []const u8) bool {
	const until = nowMs(io) + stop_settle_ms;
	while (true) {
		if (unitState(arena, io, env, unit, until)) |s| if (s.ended()) return true;
		const left = until - nowMs(io);
		if (left <= 0) return false;
		Io.sleep(io, Io.Duration.fromMilliseconds(@min(left, Bounds.child_poll_ms)), .awake) catch {};
	}
}

/// Stop this instance's build unit `unit` by its name, when systemd says it
/// may run, and wait for it to end. Not by InvocationID: systemd-run --wait
/// often reports none, and one apply runs several stages under the name. A
/// by-name stop is only for a holder of the apply flock (no live apply then
/// owns the name: every apply holds that flock from preflight until it
/// exits) or for `cogbox delete` under the config lock on a stopped
/// instance; a stopper with neither would need the run's own identity. The
/// name check is the guard against a copied apply/active naming another
/// instance's unit. `--no-ask-password`: a stopper without the right to stop
/// a root apply's unit fails rather than asking on the caller's terminal.
/// Bounded by two systemctl calls (10 s each) and the wait for the unit to
/// end (10 s), all run through the terminate flag: 30 s.
fn stopBuildUnit(arena: Allocator, io: Io, env: *const std.process.Environ.Map, icd: []const u8, unit: []const u8) UnitStop {
	const mine = buildUnitName(arena, icd) catch return .failed;
	if (!std.mem.eql(u8, unit, mine)) return .none;
	const state = unitState(arena, io, env, unit, nowMs(io) + Bounds.systemctl_ms) orelse {
		warnf(arena, io, "could not tell whether {s}, a build an earlier live apply started, still runs; apply/active keeps it", .{unit});
		return .failed;
	};
	if (!state.mayRun()) return .none;
	const stop = runChild(arena, io, .{
		.argv = &.{ "systemctl", "--no-ask-password", "stop", "--no-block", unit },
		.env = env,
		.deadline_ms = nowMs(io) + Bounds.systemctl_ms,
		.out_cap = 1024,
		.err_cap = 4096,
		.ignore_terminate = true,
	});
	if (stop.exitedWith(0)) {
		if (waitUnitEnded(arena, io, env, unit)) return .stopped;
		warnf(arena, io, "{s}, a build an earlier live apply left running, had not ended {d} s after its stop; apply/active keeps it", .{ unit, @divTrunc(stop_settle_ms, 1000) });
		return .failed;
	}
	// It ended in between.
	if (stop.exit != null and std.mem.indexOf(u8, stop.stderr.data(), " not loaded") != null) return .none;
	warnf(arena, io, "could not stop {s}, a build an earlier live apply left running; apply/active keeps it", .{unit});
	return .failed;
}

/// The by-name stop a stopper owes what apply/active says (stopBuildUnit):
/// the unit a record names, `.none` without a record or a unit. A file that
/// is there but cannot be read or parsed may be the only record of a unit
/// that runs: this instance's own unit is stopped by its name (the name does
/// not depend on the record), and `.none` (the file may go) only when that
/// stop settled, or when systemd does not run here, so that no unit can.
fn stopActiveUnit(arena: Allocator, io: Io, env: *const std.process.Environ.Map, icd: []const u8, rec: ActiveRead) UnitStop {
	switch (rec) {
		.absent => return .none,
		.record => |a| return if (a.unit) |u| stopBuildUnit(arena, io, env, icd, u) else .none,
		.unreadable => |err| {
			const mine = buildUnitName(arena, icd) catch return .failed;
			warnf(arena, io, "cannot read {s}/apply/active ({s}); stopping {s}, this instance's build unit, by its name", .{ icd, @errorName(err), mine });
			if (std.c.access(systemd_dir, std.c.F_OK) != 0) return .none;
			return stopBuildUnit(arena, io, env, icd, mine);
		},
	}
}

// --- --log ------------------------------------------------------------------------------------

fn runLog(arena: Allocator, ctx: *const plugin.Ctx, args: cli.ApplyArgs, host: Host) u8 {
	const io = ctx.io;
	ignoreSigpipe();
	const gen = args.gen orelse return 64;
	var dir = snapshot.openIcd(io, icdOf(ctx)) catch {
		errorf(arena, io, "no build log for generation {s}", .{gen});
		return 66;
	};
	defer dir.close(io);
	const name = std.fmt.allocPrint(arena, "apply/{s}.build.log", .{gen}) catch return 70;
	const bytes = snapshot.readNoFollow(arena, io, dir, name, Bounds.build_log_cap * 2) catch {
		errorf(arena, io, "no build log for generation {s}", .{gen});
		return 66;
	};
	host.emit(io, logTail(arena, bytes));
	return 0;
}

/// What `apply --log` prints: the last 32 KiB, from a line start, ANSI and
/// control characters stripped.
pub fn logTail(arena: Allocator, bytes: []const u8) []const u8 {
	var b = bytes;
	if (b.len > Bounds.log_print_cap) {
		b = b[b.len - Bounds.log_print_cap ..];
		if (std.mem.indexOfScalar(u8, b, '\n')) |nl| b = b[nl + 1 ..];
	}
	return stripAnsi(arena, b);
}

// --- --abandon-rollback -----------------------------------------------------------------------

fn runAbandon(arena: Allocator, ctx: *const plugin.Ctx, args: cli.ApplyArgs, host: Host) u8 {
	const io = ctx.io;
	ignoreSigpipe();
	const icd = icdOf(ctx);
	if (!host.config_held) {
		errorf(arena, io, "the instance config is locked by another cogbox command; try again", .{});
		return 75;
	}
	defer unlockFd(host.config_fd);
	const pending = rollback.pendingIntents(arena, io, icd) catch &.{};
	if (pending.len == 0) {
		host.emit(io, "no pending rollback\n");
		return 0;
	}
	if (!args.yes) {
		const stdin = Io.File.stdin();
		if (!(stdin.isTty(io) catch false)) {
			errorf(arena, io, "--abandon-rollback needs a terminal to confirm, or -y", .{});
			return 64;
		}
		out(io, std.fmt.allocPrint(arena, "Abandon {d} pending plugin rollback(s)? The instance then boots its config as it is, including the change that was rejected. [y/N] ", .{pending.len}) catch "Abandon the pending plugin rollback? [y/N] ");
		// The answer can take as long as the operator likes: the config lock is
		// not held across it (a launcher pass or a plugin verb would wait on
		// it), and is retaken, with the dispatcher's bound, before anything moves.
		unlockFd(host.config_fd);
		var buf: [256]u8 = undefined;
		var reader = stdin.readerStreaming(io, &buf);
		const line = (reader.interface.takeDelimiter('\n') catch null) orelse "";
		const ans = std.mem.trim(u8, line, " \t\r\n");
		if (ans.len == 0 or (ans[0] != 'y' and ans[0] != 'Y')) {
			out(io, "nothing changed\n");
			return 1;
		}
		pollFlock(io, host.config_fd, Bounds.dispatcher_lock_ms, null, null) catch {
			errorf(arena, io, "the instance config is locked by another cogbox command; try again", .{});
			return 75;
		};
		// Only what the operator confirmed moves: a launcher pass may have
		// finished it meanwhile, and nothing else may have become pending.
		const now = rollback.pendingIntents(arena, io, icd) catch &.{};
		if (now.len == 0) {
			host.emit(io, "no pending rollback\n");
			return 0;
		}
		if (!sameNames(now, pending)) {
			errorf(arena, io, "the pending rollbacks changed while the prompt waited; nothing was moved, run it again", .{});
			return 75;
		}
	}
	const res = rollback.abandon(arena, io, icd, host.apply_fd, ctx.real_uid) catch |err| {
		if (err == error.ApplyBusy) {
			errorf(arena, io, "a live apply or a plugin change is running; try again when it has finished", .{});
			return 75;
		}
		errorf(arena, io, "could not move the pending rollback aside ({s})", .{@errorName(err)});
		return 70;
	};
	defer unlockFd(host.apply_fd);
	var aw: Io.Writer.Allocating = .init(arena);
	rollback.writeWarnings(&aw.writer, res.warnings) catch {};
	errOut(io, aw.written());
	for (res.moved) |m| host.emit(io, std.fmt.allocPrint(arena, "abandoned {s}\n", .{m}) catch "");
	// An interrupted apply's inflight.json is not abandoned: its recovery (the
	// next plugin change, apply, --status, or the launcher's preboot) can read
	// the rejection again and write a new intent.
	if (res.moved.len > 0 and inflightExists(io, icd)) {
		warnf(arena, io, "apply/inflight.json remains from an interrupted live apply, and its recovery can write the rollback again; run 'cogbox plugin apply --status{s}{s}' to settle it, then '--abandon-rollback' again if a rollback is still pending", .{ if (ctx.instance != null) " -n " else "", ctx.instance orelse "" });
	}
	return 0;
}

fn sameNames(a: []const []const u8, b: []const []const u8) bool {
	if (a.len != b.len) return false;
	for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
	return true;
}

// --- --force (Apply anyway on a terminal) --------------------------------------------------------

/// Where forceLoop asks: whether stdin and stderr are both terminals, and the
/// reader of stdin, one for the whole loop. `fd`, the terminal `in` reads:
/// what was typed on it before a question was shown is discarded
/// (discardTypeahead); null discards only what `in` holds.
pub const Prompt = struct {
	tty: bool,
	in: *Io.Reader,
	fd: ?std.posix.fd_t = null,
};

/// One apply of forceLoop: its exit code and the Report it built (null when it
/// built none: a rollback that cannot finish blocked it).
pub const Round = struct { code: u8, report: ?Report };
pub const RoundFn = *const fn (Allocator, *const plugin.Ctx, cli.ApplyArgs, Host) Round;

/// `apply --force`: forceLoop on this process's own terminal.
fn runForce(arena: Allocator, ctx: *const plugin.Ctx, args: cli.ApplyArgs, host: Host) u8 {
	var buf: [256]u8 = undefined;
	var reader = Io.File.stdin().readerStreaming(ctx.io, &buf);
	return forceLoop(arena, ctx, args, host, .{ .tty = forceTerminals(ctx.io), .in = &reader.interface, .fd = Io.File.stdin().handle }, applyRound);
}

/// forceLoop's round: one apply, with the Report it built handed back.
pub fn applyRound(arena: Allocator, ctx: *const plugin.Ctx, args: cli.ApplyArgs, host: Host) Round {
	var rep: ?Report = null;
	var h = host;
	h.report_out = &rep;
	const code = runApply(arena, ctx, args, h);
	return .{ .code = code, .report = rep };
}

/// The interactive Apply anyway (spec 4.7, CLI). Round 0 is a plain apply
/// (`args.force` only drops its Apply anyway hint). When it ends overridable,
/// the plan is listed on stderr and asked about on the terminal (never through
/// confirm(), which says yes off a terminal); a yes runs the apply again bound
/// to that plan (`force_plan`), which forces it when its re-plan gives the
/// same id. A plan that changed meanwhile (plan_changed, which stores the new
/// one) is listed and asked about again. Nothing is held while the person
/// reads: the round released both locks and cleared apply/active, and nothing
/// reached the guest (an overridable outcome is decided before `start`), so
/// TERM, INT and HUP get their default action there and a Ctrl-C simply ends
/// the process; a plugin change made meanwhile is caught by the binding:
/// plan_changed, or plan_expired for a changed plugin state (as for a plan
/// that aged, or a restart, while the question waited), after which a plain
/// apply plans again, as round 0 did, and the plan it offers is the one asked
/// about next. There are at most Bounds.force_rounds forced runs, whichever
/// of the two their binding answered: after the last one's plan_changed or
/// plan_expired nothing is asked about or planned again, and nothing is
/// applied anyway. Each round after the first restarts the whole-verb
/// timer, which bounds one apply, not the time spent reading, and then
/// retakes the config lock with the dispatcher's bound: the timer counts that
/// wait, as the dispatcher's does from process start. A decline, EOF and the
/// abort exit 1; otherwise the last round's exit code.
pub fn forceLoop(arena: Allocator, ctx: *const plugin.Ctx, args: cli.ApplyArgs, host: Host, p: Prompt, round: RoundFn) u8 {
	const io = ctx.io;
	// The dispatcher refused both already, before any lock.
	if (args.json) {
		errorf(arena, io, "{s}", .{force_json_refused});
		return 64;
	}
	if (!p.tty) {
		errorf(arena, io, "{s}", .{force_needs_tty});
		return 64;
	}
	const n_opt: []const u8 = if (ctx.instance) |n| (std.fmt.allocPrint(arena, " -n {s}", .{n}) catch "") else "";
	const again = std.fmt.allocPrint(arena, "The plan changed again; nothing was applied anyway. Run 'cogbox plugin apply --force{s}' to see the current plan.\n", .{n_opt}) catch "";
	var h = host;
	var res = round(arena, ctx, args, h);
	var forced_rounds: u32 = 0;
	// Whether `res` is a plain apply's (round 0, or the re-plan after a
	// forced round's plan_expired), and the id of the plan asked about last.
	var plain = true;
	var shown: ?[]const u8 = null;
	while (true) {
		const rep = res.report orelse return res.code;
		if (!plain and rep.reason == .plan_expired) {
			// The plan expired while the question waited (a plugin change, a
			// restart, its half hour): plan again with a plain apply, as round
			// 0 did, and ask about what it offers.
			if (forced_rounds >= Bounds.force_rounds) {
				errOut(io, again);
				return 1;
			}
			if (retakeForRound(io, &h)) |code| return code;
			res = round(arena, ctx, args, h);
			plain = true;
			continue;
		}
		// A plain apply offers an overridable plan; a forced round only the
		// new plan of a plan_changed (anything else is its answer).
		const offered: ?Plan = if (plain)
			(if (rep.overridable) rep.plan else null)
		else if (rep.reason == .plan_changed) rep.plan else null;
		const plan = offered orelse {
			// A mixed refusal lists its plan, but nothing can force it.
			if (plain and rep.result == .restart_required and rep.plan != null) {
				errOut(io, std.fmt.allocPrint(arena, "Apply anyway cannot override this change: {s} is never overridable.\n", .{if (rep.reason) |why| @tagName(why) else "its reason"}) catch "");
			}
			return res.code;
		};
		if (forced_rounds >= Bounds.force_rounds) {
			errOut(io, again);
			return 1;
		}
		if (terminate.load(.acquire) != 0) return 128 +| terminate.load(.acquire);
		// A yes agrees to the listing: none (it could not be made or
		// written), no question.
		const changed = if (shown) |id| !std.mem.eql(u8, id, plan.id) else false;
		const listing = planListing(arena, ctx.instance, plan, changed);
		if (listing.len == 0 or !errOutChecked(io, listing)) {
			errOut(io, "Nothing was applied anyway; the change loads at the next restart.\n");
			return 1;
		}
		shown = plan.id;
		defaultTerminateSignals();
		const question = std.fmt.allocPrint(arena, "Apply anyway (plan {s})? [y/N] ", .{plan.id}) catch "Apply anyway? [y/N] ";
		if (!askYes(io, p, question)) {
			errOut(io, "Nothing was applied anyway; the change loads at the next restart.\n");
			return 1;
		}
		installSignals();
		if (retakeForRound(io, &h)) |code| return code;
		forced_rounds += 1;
		plain = false;
		var forced_args = args;
		forced_args.force_plan = plan.id;
		res = round(arena, ctx, forced_args, h);
	}
}

/// Before each forceLoop round after the first, with the verb's handlers
/// installed: a supersede request the round before got after its last check
/// is dropped, so it cannot end the next round's build at once (the plugin
/// change that sent it is caught by that round's binding), the whole-verb
/// timer restarts, and the config lock is taken again with the dispatcher's
/// bound (the timer counts that wait). The exit code when a signal ends it,
/// else null; a lock that stays busy is the round's own failed/busy, as after
/// the dispatcher's wait.
fn retakeForRound(io: Io, h: *Host) ?u8 {
	supersede.store(0, .release);
	if (terminate.load(.acquire) != 0) return 128 +| terminate.load(.acquire);
	// The timer first: the whole verb's sum counts the lock wait.
	h.started = Io.Timestamp.now(io, .awake);
	h.config_held = false;
	if (pollFlock(io, h.config_fd, Bounds.dispatcher_lock_ms, &terminate, null)) |_| {
		h.config_held = true;
	} else |err| switch (err) {
		error.Canceled => return 128 +| terminate.load(.acquire),
		// The round answers failed/busy, as the dispatcher's wait would.
		else => {},
	}
	return null;
}

/// Ask `question` on stderr and read one line: yes only when it starts with y
/// or Y (as confirm() and --abandon-rollback's prompt read it); an empty
/// line, EOF, a read error and a question that could not be written are no.
/// Only a line typed once the question is shown answers it: what was typed
/// ahead (during a round, before the listing, or past the last answer) is
/// discarded first, from the terminal and from the reader's buffer, before
/// the question is written, so an answer typed on seeing it is never lost.
pub fn askYes(io: Io, p: Prompt, question: []const u8) bool {
	p.in.tossBuffered();
	if (p.fd) |fd| discardTypeahead(fd);
	if (!errOutChecked(io, question)) return false;
	const line = (p.in.takeDelimiter('\n') catch return false) orelse {
		// EOF (Ctrl-D): end the question's line.
		errOut(io, "\n");
		return false;
	};
	const ans = std.mem.trim(u8, line, " \t\r\n");
	return ans.len > 0 and (ans[0] == 'y' or ans[0] == 'Y');
}

/// Drop the input terminal `fd` holds unread (tcflush TCIFLUSH). Linux only:
/// elsewhere `apply` answers unsupported_platform before anything is asked.
pub fn discardTypeahead(fd: std.posix.fd_t) void {
	const tciflush = 0;
	if (is_linux) _ = linux.ioctl(fd, linux.T.CFLSH, tciflush);
}

/// TERM, INT and HUP back to their default action, while forceLoop waits for
/// an answer (installSignals puts the verb's handlers back).
pub fn defaultTerminateSignals() void {
	var act: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
	act.handler.handler = std.posix.SIG.DFL;
	std.posix.sigaction(std.posix.SIG.TERM, &act, null);
	std.posix.sigaction(std.posix.SIG.INT, &act, null);
	std.posix.sigaction(std.posix.SIG.HUP, &act, null);
}

/// What forceLoop lists before it asks (spec 4.7): every unit of the plan with
/// its action, why it is in the plan, its class and, for the units whose
/// effect has a name (unitEffect), what that action ends; then the systemd
/// re-exec (part of the switch) and the repair (after it), then what they do
/// to the people using the sandbox and which of the post-checks force relaxes
/// (forceUnits: the units it stops, starts or restarts, never one it only
/// reloads). `changed`: the plan the person was shown last changed meanwhile.
/// The question itself is askYes's. Empty for a plan with a unit name or a
/// `why` a listing may not show (isUnitToken, isPlanWhy).
pub fn planListing(arena: Allocator, instance: ?[]const u8, p: Plan, changed: bool) []const u8 {
	var aw: Io.Writer.Allocating = .init(arena);
	writePlanListing(&aw.writer, instance, p, changed) catch return "";
	return aw.written();
}

fn writePlanListing(w: *Io.Writer, instance: ?[]const u8, p: Plan, changed: bool) Io.Writer.Error!void {
	try w.writeAll(if (changed) "The plan changed since it was shown. Apply anyway would now act on these units in the running instance" else "Apply anyway would act on these units in the running instance");
	if (instance) |n| try w.print(" '{s}':\n", .{n}) else try w.writeAll(":\n");
	try writePlanItems(w, p, "  ");
	try w.writeAll("They end or interrupt the sessions, containers and connections they serve, for everyone who uses the sandbox, " ++
		"and they restart again if the change is undone. The units it stops, starts or restarts may end up restarted, stopped or started " ++
		"without that undoing the change (one that fails undoes it); a unit it only reloads must keep running as it was. " ++
		"The checks of logins, sshd and the network still run, and a change they prove broken is rolled back.\n");
}

/// The whole of what plan `p` does, one line each under `indent`: every unit
/// with its action, why, class and named effect (unitEffect), then the systemd
/// re-exec and the repair. planListing's body, and what humanLine shows before
/// the plan id that forces it off a terminal. What reaches a person is checked
/// text only (buildPlan offers no other plan): error.WriteFailed, before
/// anything is written, for a unit name or a `why` a listing may not show
/// (isUnitToken, isPlanWhy), so the caller shows none rather than a listing
/// that is not what it says.
fn writePlanItems(w: *Io.Writer, p: Plan, indent: []const u8) Io.Writer.Error!void {
	for (p.units) |u| if (!isUnitToken(u.unit) or !isPlanWhy(u.why)) return error.WriteFailed;
	for (p.units) |u| {
		try w.print("{s}{s} {s} ({s}; class {s})", .{ indent, @tagName(u.action), u.unit, u.why, u.class });
		if (unitEffect(u.unit, u.action)) |effect| try w.print(": {s}", .{effect});
		try w.writeByte('\n');
	}
	if (p.reexec) try w.print("{s}re-execute systemd\n", .{indent});
	for (p.repair) |unit| try w.print("{s}then restart {s} (repairs the uplink's reply routing)\n", .{ indent, unit });
}

/// What a plan action ends for the people using the sandbox (spec 4.2, "Forced
/// plans say what they end"), in the control plane's words, for the units
/// whose effect has a name; null for every other unit and action (the listing
/// names the action alone).
fn unitEffect(unit: []const u8, action: unitplan.Action) ?[]const u8 {
	if (std.mem.eql(u8, unit, "docker.service") and (action == .stop or action == .restart)) return "stops every running container";
	if (std.mem.eql(u8, unit, "sshd.service") and action == .restart) return "existing sessions survive, new logins pause briefly";
	if (std.mem.eql(u8, unit, "systemd-resolved.service") and action == .restart) return "name lookups fail briefly";
	return null;
}

/// Units forceHint's one-line form (on a terminal) names before it counts
/// the rest.
const hint_units_max = 8;

/// The inline add/update/del's hint after an overridable refusal (they never
/// prompt): how to apply it anyway and what that would do, from the report's
/// `plan` object. `tty`, stdin and stderr are terminals (forceTerminals), so
/// `--force` runs there: one line naming it, at most 8 units, the re-exec and
/// the repair (`--force` lists the whole plan before it asks). Off one, where
/// `--force` refuses: the whole plan as the verb's own human line lists it
/// (writePlanItems), and only after it the `--force-plan` line with its id.
/// Null when `plan` is not a well-formed plan (nothing is printed then).
pub fn forceHint(arena: Allocator, instance: ?[]const u8, plan: std.json.Value, tty: bool) ?[]const u8 {
	const units = objGet(plan, "units") orelse return null;
	const reexec = objGet(plan, "reexec") orelse return null;
	const repair = objGet(plan, "repair") orelse return null;
	if (units != .array or reexec != .bool or repair != .array) return null;
	for (repair.array.items) |u| if (u != .string or !isUnitToken(u.string)) return null;
	const n_opt: []const u8 = if (instance) |n| (std.fmt.allocPrint(arena, " -n {s}", .{n}) catch return null) else "";
	var aw: Io.Writer.Allocating = .init(arena);
	const w = &aw.writer;
	if (!tty) {
		const p = std.json.parseFromValueLeaky(Plan, arena, plan, .{ .ignore_unknown_fields = true }) catch return null;
		if (!cli.isHex16(p.id)) return null;
		w.writeAll("Or apply it now anyway, which would:\n") catch return null;
		const head = aw.written().len;
		writePlanItems(w, p, "  ") catch return null;
		if (aw.written().len == head) return null;
		w.print("To apply it anyway, after reading the plan above: cogbox plugin apply --force-plan {s}{s}", .{ p.id, n_opt }) catch return null;
		return aw.written();
	}
	w.print("Or run 'cogbox plugin apply --force{s}' to apply it now anyway; it would: ", .{n_opt}) catch return null;
	var items: usize = 0;
	for (units.array.items) |u| {
		const unit = objGet(u, "unit") orelse return null;
		const action = objGet(u, "action") orelse return null;
		if (unit != .string or action != .string) return null;
		if (!isUnitToken(unit.string) or std.meta.stringToEnum(unitplan.Action, action.string) == null) return null;
		if (items == hint_units_max) continue;
		w.print("{s}{s} {s}", .{ if (items > 0) ", " else "", action.string, unit.string }) catch return null;
		items += 1;
	}
	if (units.array.items.len > items) w.print(", and {d} more", .{units.array.items.len - items}) catch return null;
	if (reexec.bool) {
		w.print("{s}re-execute systemd", .{if (items > 0) ", " else ""}) catch return null;
		items += 1;
	}
	for (repair.array.items) |u| {
		w.print("{s}restart {s}", .{ if (items > 0) ", then " else "", u.string }) catch return null;
		items += 1;
	}
	if (items == 0) return null;
	w.writeByte('.') catch return null;
	return aw.written();
}

// --- the apply gate of a plugin change (spec 4.8) ------------------------------------------

/// The gate's timing. Bounds' values except COGBOX_APPLY_WAIT_MAX, which the
/// environment sets (gateCfg); the tests shorten the rest.
pub const GateCfg = struct {
	poll_ms: i64 = Bounds.gate_poll_ms,
	supersede_wait_ms: i64 = Bounds.supersede_wait_ms,
	reprint_ms: i64 = Bounds.gate_reprint_ms,
	wait_max_ms: i64 = Bounds.wait_max_s * 1000,
};

/// The gate's timing for this process: COGBOX_APPLY_WAIT_MAX (seconds, 1200 by
/// default; the control plane is to pass 90 once it drives live apply) caps
/// the whole wait. Read from the environment
/// only, so a caller's value always wins over a wrapper's --set-default.
pub fn gateCfg(env: *const std.process.Environ.Map) GateCfg {
	return .{ .wait_max_ms = envSeconds(env, "COGBOX_APPLY_WAIT_MAX", Bounds.wait_max_s) * 1000 };
}

pub const GateResult = union(enum) {
	/// The apply flock is held on the descriptor: go on to the config lock.
	acquired,
	/// A bound behind a live apply expired: exit 69, nothing read or written.
	/// The apply's generation when apply/active named one.
	busy: ?[]const u8,
	/// flock itself failed.
	failed: anyerror,
};

/// What is left of a CLOCK_BOOTTIME deadline, in ms (never negative).
fn deadlineLeftMs(io: Io, deadline: i64) i64 {
	return @max(deadline - bootSeconds(io), 0) * 1000;
}

/// Signal the holder `a` names through a pidfd, after the starttime check (as
/// stop.zig signals its launcher). Returns the pidfd (the caller closes it),
/// or null when the holder is gone or could not be signalled.
fn signalHolderFd(arena: Allocator, io: Io, a: Active, sig: linux.SIG) ?i32 {
	if (comptime !is_linux) return null;
	const rc = linux.pidfd_open(a.pid, 0);
	if (linux.errno(rc) != .SUCCESS) return null;
	const pidfd: i32 = @intCast(rc);
	if (!holderAlive(arena, io, a) or linux.errno(linux.pidfd_send_signal(pidfd, sig, null, 0)) != .SUCCESS) {
		_ = linux.close(pidfd);
		return null;
	}
	return pidfd;
}

/// The apply gate (spec 4.8 steps 1-2), run by `add`, `update`, `del` and
/// `reconcile` before the blocking config-lock acquire, on the apply flock's
/// descriptor `fd`. Free: it is taken and the verb goes on. Held: apply/active
/// is re-read every poll and the bound follows the latest read:
///   - no live apply named (another plugin change holds the flock, or an apply
///     has not written apply/active yet): wait without a bound, as the config
///     lock waits today;
///   - `preflight`: until its deadline (its recovery and finish are not
///     supersedable);
///   - `build`: SIGUSR1 (supersede) once per holder (pid and starttime, through
///     a pidfd), then at most supersede_wait_ms from that signal;
///   - `guest` or `record`: until its deadline, printing the waiting line and
///     reprinting it with the time left every reprint_ms.
/// Every wait behind a live apply is capped at wait_max_ms from the first read
/// that named one. The gate holds no other lock while it waits (the global
/// order is apply flock, then config lock).
pub fn gate(arena: Allocator, io: Io, icd: []const u8, fd: std.posix.fd_t, cfg: GateCfg) GateResult {
	if (tryFlock(fd)) |got| {
		if (got) return .acquired;
	} else |err| return .{ .failed = err };
	var cap_from: ?i64 = null;
	var signalled: ?struct { pid: i32, starttime: ?u64, at: i64 } = null;
	var printed_at: ?i64 = null;
	var gen: ?[]const u8 = null;
	while (true) {
		const now = nowMs(io);
		var bound: ?i64 = null;
		if (readActive(arena, io, icd)) |a| if (holderAlive(arena, io, a)) {
			if (a.gen) |g| gen = g;
			const cap_at = (cap_from orelse blk: {
				cap_from = now;
				break :blk now;
			}) + cfg.wait_max_ms;
			const g = gen orelse "unknown";
			const until = switch (a.phase) {
				.preflight => now + deadlineLeftMs(io, a.deadline),
				.build => blk: {
					const same = if (signalled) |s| s.pid == a.pid and s.starttime == a.starttime else false;
					if (!same) {
						if (signalHolderFd(arena, io, a, .USR1)) |pfd| _ = linux.close(pfd);
						signalled = .{ .pid = a.pid, .starttime = a.starttime, .at = now };
						errOut(io, std.fmt.allocPrint(arena, "cogbox plugin: superseding the live apply of generation {s}, which is still building\n", .{g}) catch "");
					}
					break :blk signalled.?.at + cfg.supersede_wait_ms;
				},
				.guest, .record => blk: {
					const u = now + deadlineLeftMs(io, a.deadline);
					if (printed_at == null or now - printed_at.? >= cfg.reprint_ms) {
						printed_at = now;
						const left_s = @divTrunc(@max(@min(u, cap_at) - now, 0) + 999, 1000);
						errOut(io, std.fmt.allocPrint(arena, "cogbox plugin: waiting for the live apply of generation {s} to finish (at most {d} s)\n", .{ g, left_s }) catch "");
					}
					break :blk u;
				},
			};
			bound = @min(until, cap_at);
		};
		if (bound) |b| if (now >= b) return .{ .busy = gen };
		const slice = if (bound) |b| std.math.clamp(b - now, 1, cfg.poll_ms) else cfg.poll_ms;
		Io.sleep(io, Io.Duration.fromMilliseconds(slice), .awake) catch {};
		if (tryFlock(fd)) |got| {
			if (got) return .acquired;
		} else |err| return .{ .failed = err };
	}
}

/// The gate's refusal (exit 69), after the CLI's `cogbox plugin: error: `
/// prefix. Nothing has been read or written.
pub fn busyMessage(arena: Allocator, gen: ?[]const u8) []const u8 {
	if (gen) |g| return std.fmt.allocPrint(arena, "busy: a live apply is finishing (generation {s}); try again in a few minutes", .{g}) catch "busy: a live apply is finishing; try again in a few minutes";
	return "busy: a live apply is finishing; try again in a few minutes";
}

pub const CommitGate = union(enum) {
	/// Nothing is in flight: the mutation may commit.
	clear,
	/// An orphaned inflight.json survived its recovery: exit 69 (its G).
	busy: ?[]const u8,
};

/// The gate's step 4 (spec 4.8), under the apply flock the gate took and the
/// config lock: an inflight.json whose verb died (which released the flock) is
/// recovered before the mutation commits (at most 115 s), so a rejection it
/// still holds is rolled back first and the mutation commits on the restored
/// config. One that survives the recovery refuses the mutation. `fin_out` gets
/// the finishPending the recovery's rollback ran (it printed its own
/// warnings), the dispatcher's one finish, which it then does not repeat.
pub fn recoverBeforeCommit(arena: Allocator, ctx: *const plugin.Ctx, ssh_identity: ?[]const u8, fin_out: ?*?rollback.FinishResult) CommitGate {
	const icd = icdOf(ctx);
	if (!inflightExists(ctx.io, icd)) return .clear;
	const gen: ?[]const u8 = if (readInflight(arena, ctx.io, icd)) |inf| inf.G else |_| null;
	return switch (recoverInflight(arena, ctx, .{ .holds_config_lock = true, .ssh_identity = ssh_identity, .fin_out = fin_out })) {
		.resolved => .clear,
		.unresolved => .{ .busy = gen },
	};
}

// --- cogbox stop's apply step (spec 4.8) -----------------------------------------------------

pub const StopStepCfg = struct {
	term_ms: i64 = Bounds.stop_term_ms,
	hop_ms: i64 = Bounds.stop_hop_ms,
};

pub const StopStep = struct {
	/// apply/active named a live holder, which got SIGTERM.
	signalled: bool = false,
	/// It was still alive after the grace: it leaves inflight.json for the next
	/// recoverer (it is never SIGKILLed here).
	holder_alive: bool = false,
	/// A plugin change or another recoverer held the apply flock.
	flock_busy: bool = false,
	/// The one-hop, lock-free recovery of inflight.json, when it ran.
	recovered: ?Recovery = null,
};

/// `cogbox stop`'s apply step, before QEMU is signalled (spec 4.8; at most 5 s,
/// no config lock, never a SIGKILL): when apply/active or inflight.json
/// exists, SIGTERM the live holder through a pidfd and wait at most 2 s; if it
/// exited (or none was alive) and the apply flock (`apply_fd`) is free by
/// LOCK_NB, one `status G` hop under a 3 s kill, in the lock-free recoverer's
/// form: only a rejecting verdict becomes an intent, everything else is left
/// for `apply --cancel`, the next apply or plugin change, or the launcher, and
/// the hop never counts toward `rfails`.
pub fn stopStep(arena: Allocator, ctx: *const plugin.Ctx, apply_fd: std.posix.fd_t, ssh_identity: ?[]const u8, cfg: StopStepCfg) StopStep {
	const io = ctx.io;
	const icd = icdOf(ctx);
	var st: StopStep = .{};
	var buf: [std.fs.max_path_bytes]u8 = undefined;
	const active_path = std.fmt.bufPrint(&buf, "{s}/apply/active", .{icd}) catch return st;
	if (!pathExists(io, active_path) and !inflightExists(io, icd)) return st;
	if (readActive(arena, io, icd)) |a| if (holderAlive(arena, io, a)) {
		st.signalled = true;
		if (signalHolderFd(arena, io, a, .TERM)) |pfd| {
			defer _ = linux.close(pfd);
			if (!waitPidfd(io, pfd, cfg.term_ms)) {
				st.holder_alive = true;
				return st;
			}
		}
	};
	if (!inflightExists(io, icd) or apply_fd < 0) return st;
	if (!(tryFlock(apply_fd) catch false)) {
		st.flock_busy = true;
		return st;
	}
	defer unlockFd(apply_fd);
	st.recovered = recoverInflight(arena, ctx, .{ .holds_config_lock = false, .ssh_identity = ssh_identity, .short_hop = true, .hop_ms = cfg.hop_ms });
	return st;
}

// --- cogbox delete's apply step ----------------------------------------------------------

/// `cogbox delete`, under the config lock on a stopped instance, before it
/// removes the instance dir: stop the build unit apply/active records, by its
/// name (stopActiveUnit; an unreadable record by this instance's own unit
/// name; a live apply's own watch then ends it `superseded`). `.none`
/// without a record naming a unit. On `.failed` the unit may still run, and
/// the caller must not remove its only record.
pub fn stopRecordedBuild(arena: Allocator, io: Io, env: *const std.process.Environ.Map, icd: []const u8) UnitStop {
	return stopActiveUnit(arena, io, env, icd, readActiveForStop(arena, io, icd));
}

// --- the launcher's preboot steps (spec section 6, "Internal verb") ----------------------

pub const PrebootApply = struct {
	/// apply/active named a live holder (signalled only on a stopped instance).
	holder: enum { none, ended, alive } = .none,
	/// The orphaned build unit was stopped (by its name).
	orphan_stopped: bool = false,
	/// The apply flock: taken by LOCK_NB, held by someone else, or no lock file.
	flock: enum { taken, busy, absent } = .absent,
	/// inflight.json's resolution, when one ran.
	inflight: ?Recovery = null,
	/// inflight.json was left (a running instance, or the flock was busy).
	inflight_left: bool = false,
	/// The finishPending the recovery's rollback ran (it printed its own
	/// warnings): the caller's one finish, which it then does not repeat.
	fin: ?rollback.FinishResult = null,
};

/// The live-apply part of `__plugin-apply-preboot`, under the launcher's config
/// lock (inherited; never taken here), on a launcher pass for an instance that
/// is `running` or not (null: unknown, which counts as running). On a stopped
/// instance: signal the holder apply/active names (SIGTERM, at most 30 s, then
/// SIGKILL, at most 10 s; with the config lock held it cannot be in its step-10
/// section); with the apply flock free (LOCK_NB on `apply_fd`), stop an
/// orphaned build unit by its name (clearing its apply/active once nothing of
/// it runs) and resolve inflight.json (`unknown`, unless an intent or a
/// record exists, which is rolled back). On a running instance (`cogbox init` on a live one)
/// it never interferes with an apply. The caller then runs finishPending
/// (sweeping tmp names only when `.flock == .taken`), unless the recovery
/// already ran one (`.fin`), and releases the flock.
pub fn prebootApply(arena: Allocator, ctx: *const plugin.Ctx, running: ?bool, apply_fd: ?std.posix.fd_t) PrebootApply {
	const io = ctx.io;
	const icd = icdOf(ctx);
	var pa: PrebootApply = .{};
	const stopped = if (running) |r| !r else false;
	const active = readActive(arena, io, icd);
	if (stopped) if (active) |a| if (holderAlive(arena, io, a)) {
		pa.holder = if (signalHolder(arena, io, a, true)) .ended else .alive;
	};
	if (apply_fd) |fd| {
		pa.flock = if (tryFlock(fd) catch false) .taken else .busy;
	}
	if (pa.flock == .taken) {
		// Read again under the flock: a holder signalled above may have
		// rewritten it before it ended. The flock proves no live apply owns
		// the unit's name, so it is stopped by that name (an unreadable
		// record, by this instance's own unit name). Once nothing of the dead
		// holder's build runs (stopped, or not running), its record goes, so
		// later passes repeat no systemctl call; a stop that failed keeps it
		// for the next stopper.
		const cur = readActiveForStop(arena, io, icd);
		const owed = switch (cur) {
			.absent => false,
			.record => |a| a.unit != null and !holderAlive(arena, io, a),
			.unreadable => true,
		};
		if (owed) {
			const st = stopActiveUnit(arena, io, ctx.parent_env, icd, cur);
			pa.orphan_stopped = st == .stopped;
			if (st != .failed) clearActive(io, icd);
		}
	}
	if (inflightExists(io, icd)) {
		if (stopped and pa.flock == .taken) {
			pa.inflight = recoverInflight(arena, ctx, .{ .holds_config_lock = true, .fin_out = &pa.fin });
		} else pa.inflight_left = true;
	}
	return pa;
}

// --- the inline apply after add, del and update ------------------------------------------

pub const InlineResult = struct {
	/// The apply's exit code (0, 78 for a rollback that cannot finish, or the
	/// terminate path's 128 + signal).
	code: u8,
	/// The report's `apply` object, when one was written.
	report: ?std.json.ObjectMap,
};

/// The inline apply (spec section 2 step 1, CLI): run right after a committed
/// add, del or update, still under the gate's apply flock and the dispatcher's
/// config lock (`host`), which its preflight keeps; the report is captured, not
/// printed (the caller words it). The verb's flags are installed here: from now
/// on SIGINT asks the guest to undo a switch instead of killing the process. The
/// whole-verb timer runs from here, not from process start (the commit before
/// it is not part of the apply).
pub fn runInline(arena: Allocator, ctx: *const plugin.Ctx, host: Host) InlineResult {
	installSignals();
	var sink: std.ArrayList(u8) = .empty;
	var h = host;
	h.started = Io.Timestamp.now(ctx.io, .awake);
	if (h.sink == null) {
		h.sink = &sink;
		h.sink_allocator = arena;
	}
	const code = runApply(arena, ctx, .{ .mode = .run, .json = true }, h);
	const bytes = h.sink.?.items;
	const v = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch return .{ .code = code, .report = null };
	const ap = objGet(v, "apply") orelse return .{ .code = code, .report = null };
	return .{ .code = code, .report = if (ap == .object) ap.object else null };
}

/// The words for a rejection's reason in the inline apply's rolled-back line.
pub fn rejectionText(reason: []const u8) []const u8 {
	const map = .{
		.{ "breaks_base", "it broke logins, the network or the sandbox's base services" },
		.{ "activation_failed", "its activation failed" },
		.{ "activation_hang", "its activation did not finish" },
		.{ "unit_hang", "a unit it starts did not finish starting" },
		.{ "unreachable", "the sandbox stopped answering after the switch" },
		.{ "eval_error", "its NixOS configuration does not evaluate" },
	};
	inline for (map) |m| if (std.mem.eql(u8, reason, m[0])) return m[1];
	return "the sandbox rejected it";
}

// --- tests (the record step needs the private Run) ---------------------------------------

const t = std.testing;

/// A scratch instance for the record-step tests: <root>/icd (config.json,
/// plugins-flake/, plugin-sources/), <root>/run/inst, two lock files, a sink.
const RecordFx = struct {
	arena_state: std.heap.ArenaAllocator,
	threaded: Io.Threaded,
	root: []const u8,
	env: std.process.Environ.Map,
	sink: std.ArrayList(u8) = .empty,
	err: std.ArrayList(u8) = .empty,
	cfg_lock: Io.File,
	apply_lock: Io.File,
	runtime_lock: ?Io.File = null,

	const flake_src = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-cogbox-source";
	const the_key = flake_src ++ "#cogbox";
	const r_runner = "/nix/store/rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr-microvm-run";

	fn init(fx: *RecordFx, tag: []const u8) !void {
		fx.arena_state = .init(t.allocator);
		fx.threaded = .init(t.allocator, .{});
		fx.sink = .empty;
		fx.err = .empty;
		fx.runtime_lock = null;
		const ar = fx.arena_state.allocator();
		stderr_sink = &fx.err;
		stderr_sink_allocator = ar;
		const tio = fx.threaded.io();
		var rnd: [8]u8 = undefined;
		tio.random(&rnd);
		const rel = try std.fmt.allocPrint(ar, "zig-apply-record-{s}-{x}", .{ tag, &rnd });
		try Io.Dir.cwd().createDirPath(tio, rel);
		fx.root = try Io.Dir.cwd().realPathFileAlloc(tio, rel, ar);
		for ([_][]const u8{ "icd/plugins-flake", "icd/plugin-sources", "run/inst" }) |d| try Io.Dir.cwd().createDirPath(tio, fx.path(d));
		fx.env = std.process.Environ.Map.init(ar);
		try fx.env.put("COGBOX_FLAKE_SOURCE", flake_src);
		fx.cfg_lock = try Io.Dir.cwd().createFile(tio, fx.path("cfg.lock"), .{ .truncate = false });
		fx.apply_lock = try Io.Dir.cwd().createFile(tio, fx.path("apply.lock"), .{ .truncate = false });
		std.debug.assert(std.c.flock(fx.cfg_lock.handle, std.posix.LOCK.EX) == 0);
		std.debug.assert(std.c.flock(fx.apply_lock.handle, std.posix.LOCK.EX) == 0);
	}

	fn deinit(fx: *RecordFx) void {
		stderr_sink = null;
		stderr_sink_allocator = null;
		const tio = fx.threaded.io();
		if (fx.runtime_lock) |f| f.close(tio);
		fx.cfg_lock.close(tio);
		fx.apply_lock.close(tio);
		Io.Dir.cwd().deleteTree(tio, fx.root) catch {};
		fx.threaded.deinit();
		fx.arena_state.deinit();
	}

	fn a(fx: *RecordFx) Allocator {
		return fx.arena_state.allocator();
	}

	fn io(fx: *RecordFx) Io {
		return fx.threaded.io();
	}

	fn path(fx: *RecordFx, rel: []const u8) []const u8 {
		return std.fmt.allocPrint(fx.arena_state.allocator(), "{s}/{s}", .{ fx.root, rel }) catch @panic("oom");
	}

	fn write(fx: *RecordFx, rel: []const u8, bytes: []const u8) !void {
		const p = fx.path(rel);
		if (std.fs.path.dirname(p)) |d| try Io.Dir.cwd().createDirPath(fx.io(), d);
		const f = try Io.Dir.cwd().createFile(fx.io(), p, .{ .truncate = true });
		defer f.close(fx.io());
		var buf: [256]u8 = undefined;
		var w = f.writer(fx.io(), &buf);
		try w.interface.writeAll(bytes);
		try w.flush();
	}

	fn read(fx: *RecordFx, rel: []const u8) ![]u8 {
		return Io.Dir.cwd().readFileAlloc(fx.io(), fx.path(rel), fx.a(), .limited(1 << 20));
	}

	fn exists(fx: *RecordFx, rel: []const u8) bool {
		Io.Dir.cwd().access(fx.io(), fx.path(rel), .{}) catch return false;
		return true;
	}

	fn running(fx: *RecordFx, nonce: []const u8) !void {
		const f = try Io.Dir.cwd().createFile(fx.io(), fx.path("run/inst.lock"), .{ .truncate = false });
		std.debug.assert(std.c.flock(f.handle, std.posix.LOCK.EX | std.posix.LOCK.NB) == 0);
		fx.runtime_lock = f;
		try fx.write("run/inst/qemu.start", nonce);
	}

	/// Take a snapshot of the config.json (and composition) on disk now.
	fn take(fx: *RecordFx) !snapshot.Id {
		const cfg = try std.json.parseFromSliceLeaky(std.json.Value, fx.a(), try fx.read("icd/config.json"), .{});
		return snapshot.take(fx.a(), fx.io(), fx.path("icd"), cfg, .{});
	}

	fn ctx(fx: *RecordFx) *plugin.Ctx {
		const c = fx.a().create(plugin.Ctx) catch @panic("oom");
		c.* = .{
			.allocator = fx.a(),
			.io = fx.io(),
			.parent_env = &fx.env,
			.instance = null,
			.config_path = fx.path("icd/config.json"),
			.runtime_path = fx.path("run/inst"),
			.user_flake_dir = fx.path("icd/flake"),
			.plugins_flake_dir = fx.path("icd/plugins-flake"),
			.sources_dir = fx.path("icd/plugin-sources"),
			.cache_dir = fx.path("icd/plugin-cache"),
		};
		return c;
	}

	/// A run that holds both locks, as step 10 does once its timed retake
	/// succeeded.
	fn run(fx: *RecordFx, gen: snapshot.Id, scratch: snapshot.Id) !Run {
		const c = fx.ctx();
		return .{
			.ctx = c,
			.arena = fx.a(),
			.io = fx.io(),
			.args = .{ .json = true },
			.host = .{ .config_fd = fx.cfg_lock.handle, .config_held = true, .apply_fd = fx.apply_lock.handle, .sink = &fx.sink, .sink_allocator = fx.a() },
			.icd = fx.path("icd"),
			.owner = null,
			.gen = gen,
			.scratch_id = scratch,
			.whole_deadline_ms = nowMs(fx.io()) + 60_000,
			.config_held = true,
			.flock_held = true,
			.key = the_key,
			.s = try snapshot.read(fx.a(), fx.io(), fx.path("icd"), &scratch),
			.s_taken = true,
		};
	}

	fn reportObj(fx: *RecordFx) !std.json.ObjectMap {
		const v = try std.json.parseFromSliceLeaky(std.json.Value, fx.a(), fx.sink.items, .{});
		return v.object.get("apply").?.object;
	}
};

const plugin_x_config = "{\"plugins\": [{\"name\": \"x\", \"url\": \"path:/src/x\", \"narHash\": \"sha256-XX=\"}], \"network\": \"full\"}\n";

test "record: an eval_error is rolled back to its target, and the report's rollback object carries target, in last.json too" {
	var fx: RecordFx = undefined;
	try fx.init("eval");
	defer fx.deinit();
	// B: no plugins. S: plugin x added (its composition and source).
	try fx.write("icd/config.json", "{\"plugins\": [], \"network\": \"full\"}\n");
	const b = try fx.take();
	try snapshot.setRole(fx.io(), fx.path("icd"), .base, &b, null);
	try fx.write("icd/config.json", plugin_x_config);
	try fx.write("icd/plugins-flake/flake.nix", "{ }\n");
	try fx.write("icd/plugin-sources/x/flake.nix", "{ }\n");
	const s = try fx.take();
	const gen = snapshot.newId(fx.io());
	var r = try fx.run(gen, s);
	r.eval_target = .base;
	r.eval_target_id = &b;
	r.scope_eval = try snapshot.scope(fx.a(), r.s.?.plugins, (try snapshot.read(fx.a(), fx.io(), fx.path("icd"), &b)).plugins);
	r.phase = .record;
	try t.expectEqual(Outcome.of(.rejected, .eval_error), evalError(&r));
	try t.expect(fx.exists(try std.fmt.allocPrint(fx.a(), "icd/apply/rollback/{s}.intent", .{&gen})));

	try t.expectEqual(@as(u8, 0), finish(&r, Outcome.of(.rejected, .eval_error)));
	const rep = try fx.reportObj();
	try t.expectEqualStrings("rejected", rep.get("result").?.string);
	try t.expectEqualStrings("eval_error", rep.get("reason").?.string);
	const rb = rep.get("rollback").?.object;
	try t.expectEqualStrings("done", rb.get("status").?.string);
	try t.expectEqualStrings("base", rb.get("target").?.string);
	try t.expectEqualStrings(&b, rb.get("target_id").?.string);
	try t.expectEqualStrings("x", rb.get("names").?.array.items[0].object.get("name").?.string);
	try t.expectEqualStrings(fx.sink.items, try fx.read("icd/apply/last.json"));
	// The restore happened: no plugin entry, no composition, no intent; K
	// untouched by an eval_error rollback (none was set); the record exists.
	try t.expect(std.mem.indexOf(u8, try fx.read("icd/config.json"), "\"x\"") == null);
	try t.expect(!fx.exists("icd/plugins-flake/flake.nix"));
	try t.expect(!fx.exists(try std.fmt.allocPrint(fx.a(), "icd/apply/rollback/{s}.intent", .{&gen})));
	const recs = try rollback.readRecords(fx.a(), fx.io(), fx.path("icd"));
	try t.expect(recs.find(&gen) != null);
	// Both locks were released.
	try t.expectEqual(@as(c_int, 0), std.c.flock(fx.apply_lock.handle, std.posix.LOCK.EX | std.posix.LOCK.NB));
}

test "record: restart_required after stage (a) sets K := S and records R; a non-recording reason sets K only" {
	var fx: RecordFx = undefined;
	try fx.init("built");
	defer fx.deinit();
	try fx.running("77");
	try fx.write("icd/config.json", plugin_x_config);
	try fx.write("icd/plugins-flake/flake.nix", "{ }\n");
	try fx.write("icd/plugins-flake/flake.lock", "{\"nodes\":{\"root\":{}},\"root\":\"root\",\"version\":7}\n");
	try fx.write("icd/composition.lock.prev", "old\n");
	const s = try fx.take();
	var r = try fx.run(snapshot.newId(fx.io()), s);
	r.nonce = "77";
	r.stage_a_ok = true;
	r.runner = RecordFx.r_runner;
	try t.expect(needsRecordLock(&r, Outcome.of(.restart_required, .disruptive_units)));
	_ = finish(&r, Outcome.of(.restart_required, .disruptive_units));
	try t.expectEqualStrings(&s, &snapshot.roleId(fx.io(), fx.path("icd"), .built).?);
	const snap = try snapshot.read(fx.a(), fx.io(), fx.path("icd"), &s);
	try t.expectEqualStrings(RecordFx.r_runner, snap.meta.runner.?);
	try t.expectEqualStrings(RecordFx.the_key, snap.meta.key.?);
	// plugins-flake still equals S: runner.path = R with S's comp, and the
	// prev lock an update's re-pin left is cleared.
	const rec = try fx.read("icd/runner.path");
	try t.expectEqualStrings(try std.fmt.allocPrint(fx.a(), "{s}\n{s}\n{s}\n", .{ RecordFx.the_key, RecordFx.r_runner, snap.meta.comp }), rec);
	try t.expect(!fx.exists("icd/composition.lock.prev"));
	try t.expectEqualStrings(&s, (try fx.reportObj()).get("built_id").?.string);
	// apply/active is cleared at the end.
	try t.expect(!fx.exists("icd/apply/active"));

	// A reason that never records R (the guest booted something else): K only.
	std.debug.assert(std.c.flock(fx.cfg_lock.handle, std.posix.LOCK.EX) == 0);
	std.debug.assert(std.c.flock(fx.apply_lock.handle, std.posix.LOCK.EX) == 0);
	try Io.Dir.cwd().deleteFile(fx.io(), fx.path("icd/runner.path"));
	const s2 = try fx.take();
	var r2 = try fx.run(snapshot.newId(fx.io()), s2);
	r2.nonce = "77";
	r2.stage_a_ok = true;
	r2.runner = RecordFx.r_runner;
	fx.sink.clearRetainingCapacity();
	_ = finish(&r2, Outcome.of(.restart_required, .foreign_system));
	try t.expectEqualStrings(&s2, &snapshot.roleId(fx.io(), fx.path("icd"), .built).?);
	try t.expect((try snapshot.read(fx.a(), fx.io(), fx.path("icd"), &s2)).meta.runner == null);
	try t.expect(!fx.exists("icd/runner.path"));
}

test "record: no K for a superseded run, a failure before stage (a), or a relaunched instance" {
	var fx: RecordFx = undefined;
	try fx.init("nok");
	defer fx.deinit();
	try fx.running("77");
	try fx.write("icd/config.json", plugin_x_config);
	const s = try fx.take();
	var r = try fx.run(snapshot.newId(fx.io()), s);
	r.nonce = "77";
	r.stage_a_ok = true;
	try t.expect(!needsRecordLock(&r, Outcome.of(.superseded, null)));
	_ = finish(&r, Outcome.of(.superseded, null));
	try t.expect(snapshot.roleId(fx.io(), fx.path("icd"), .built) == null);

	std.debug.assert(std.c.flock(fx.cfg_lock.handle, std.posix.LOCK.EX) == 0);
	std.debug.assert(std.c.flock(fx.apply_lock.handle, std.posix.LOCK.EX) == 0);
	var r2 = try fx.run(snapshot.newId(fx.io()), try fx.take());
	r2.nonce = "77";
	r2.stage_a_ok = false;
	try t.expect(!needsRecordLock(&r2, Outcome.of(.failed, .build)));
	_ = finish(&r2, Outcome.of(.failed, .build));
	try t.expect(snapshot.roleId(fx.io(), fx.path("icd"), .built) == null);

	// The instance relaunched since preflight (another nonce): K is not set,
	// the launcher re-promoted B at boot.
	std.debug.assert(std.c.flock(fx.cfg_lock.handle, std.posix.LOCK.EX) == 0);
	std.debug.assert(std.c.flock(fx.apply_lock.handle, std.posix.LOCK.EX) == 0);
	var r3 = try fx.run(snapshot.newId(fx.io()), try fx.take());
	r3.nonce = "76";
	r3.stage_a_ok = true;
	r3.runner = RecordFx.r_runner;
	_ = finish(&r3, Outcome.of(.restart_required, .disruptive_units));
	try t.expect(snapshot.roleId(fx.io(), fx.path("icd"), .built) == null);
}

test "record: an already-live runner gets the confirmed record (B := S, K unlinked, live-runner)" {
	var fx: RecordFx = undefined;
	try fx.init("live");
	defer fx.deinit();
	try fx.running("77");
	try fx.write("icd/config.json", plugin_x_config);
	try fx.write("icd/plugins-flake/flake.nix", "{ }\n");
	const k = try fx.take();
	try snapshot.setRole(fx.io(), fx.path("icd"), .built, &k, null);
	const s = try fx.take();
	var r = try fx.run(snapshot.newId(fx.io()), s);
	r.nonce = "77";
	r.stage_a_ok = true;
	r.runner = RecordFx.r_runner;
	_ = finish(&r, Outcome.of(.already_live, null));
	try t.expectEqualStrings(&s, &snapshot.roleId(fx.io(), fx.path("icd"), .base).?);
	try t.expect(snapshot.roleId(fx.io(), fx.path("icd"), .built) == null);
	const live = parseLive(try fx.read("run/inst/live-runner")).?;
	try t.expectEqualStrings(RecordFx.r_runner, live.runner);
	try t.expectEqualStrings("77", live.nonce);
	try t.expectEqualStrings(RecordFx.the_key, live.key);
	try t.expectEqualStrings("already_live", (try fx.reportObj()).get("result").?.string);
}

test "build: an eval_error reproduced, then SIGUSR1: the verb flips to record and rolls back, never superseded" {
	var fx: RecordFx = undefined;
	try fx.init("eval-usr1");
	defer fx.deinit();
	defer {
		var act: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
		act.handler.handler = std.posix.SIG.DFL;
		for ([_]std.posix.SIG{ .TERM, .INT, .HUP, .USR1 }) |sig| std.posix.sigaction(sig, &act, null);
		terminate.store(0, .release);
		supersede.store(0, .release);
	}
	// A fake `nix` whose evaluation fails with a trace, the same way twice. On
	// its second run (the reproduction) it stops the verb, waits until the
	// verb's main thread is stopped (a SIGUSR1 queued earlier could be handled
	// first, and the loop would then stop the stage on the flag), queues
	// SIGUSR1 for it, exits, and lets the verb go on 0.3 s later: the flag is
	// set by the time the verb reaps the reproduction, and the stage itself
	// was not stopped by it.
	var base_env = try std.testing.environ.createMap(fx.a());
	const sh = findExe(fx.a(), &base_env, "sh") orelse return error.SkipZigTest;
	try fx.write("bin/nix", try std.mem.concat(fx.a(), u8, &.{ "#!", sh, "\n",
		\\n=$(cat "$FAKE_NIX_DIR/n" 2>/dev/null || echo 0)
		\\n=$((n + 1))
		\\echo "$n" > "$FAKE_NIX_DIR/n"
		\\printf 'error:\n       ... while evaluating the attribute %s\n\n       error: The option %s does not exist.\n' "'config'" "'la.bad'" >&2
		\\if [ "$n" = 2 ]; then
		\\  kill -s STOP "$PPID"
		\\  i=0
		\\  while [ "$i" -lt 500 ]; do
		\\    read -r st < "/proc/$PPID/stat" || break
		\\    set -- ${st##*')'}
		\\    case $1 in T|t) break ;; esac
		\\    i=$((i + 1))
		\\    sleep 0.01
		\\  done
		\\  kill -s USR1 "$PPID"
		\\  (sleep 0.3; kill -s CONT "$PPID") </dev/null >/dev/null 2>&1 &
		\\fi
		\\exit 1
		\\
	}));
	if (std.c.chmod(try fx.a().dupeZ(u8, fx.path("bin/nix")), 0o755) != 0) return error.SkipZigTest;
	try fx.env.put("PATH", try std.fmt.allocPrint(fx.a(), "{s}:{s}", .{ fx.path("bin"), base_env.get("PATH") orelse "/bin" }));
	try fx.env.put("FAKE_NIX_DIR", fx.root);
	try fx.env.put("COGBOX_NIXPKGS_SOURCE", "/nix/store/nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn-source");

	// B: no plugins. S: plugin x added (its composition and source).
	try fx.write("icd/config.json", "{\"plugins\": [], \"network\": \"full\"}\n");
	const b = try fx.take();
	try snapshot.setRole(fx.io(), fx.path("icd"), .base, &b, null);
	try fx.write("icd/config.json", plugin_x_config);
	try fx.write("icd/plugins-flake/flake.nix", "{ }\n");
	try fx.write("icd/plugin-sources/x/flake.nix", "{ }\n");
	const s = try fx.take();
	const gen = snapshot.newId(fx.io());
	var r = try fx.run(gen, s);
	r.eval_target = .base;
	r.eval_target_id = &b;
	r.scope_eval = try snapshot.scope(fx.a(), r.s.?.plugins, (try snapshot.read(fx.a(), fx.io(), fx.path("icd"), &b)).plugins);
	// The build phase as preflight leaves it: the config lock released, the
	// apply flock held, a daemon client's containment.
	r.config_held = false;
	r.cap = .none;
	r.setPhase(.build, bootSeconds(fx.io()) + 600);
	installSignals();

	const o = buildAndPlan(&r);
	// The flag arrived, after the reproduction ended on its own.
	try t.expectEqual(@as(u8, 1), supersede.load(.acquire));
	try t.expectEqualStrings("2\n", try fx.read("n"));
	try t.expectEqual(Outcome.of(.rejected, .eval_error), o);
	try t.expectEqual(Phase.record, r.phase);
	try t.expectEqual(Phase.record, readActive(fx.a(), fx.io(), fx.path("icd")).?.phase);
	try t.expect(fx.exists(try std.fmt.allocPrint(fx.a(), "icd/apply/rollback/{s}.intent", .{&gen})));

	// The record step ignores the flag too: the rollback runs.
	try t.expectEqual(@as(u8, 0), finish(&r, o));
	const rep = try fx.reportObj();
	try t.expectEqualStrings("rejected", rep.get("result").?.string);
	try t.expectEqualStrings("eval_error", rep.get("reason").?.string);
	try t.expectEqualStrings("done", rep.get("rollback").?.object.get("status").?.string);
	try t.expect(std.mem.indexOf(u8, try fx.read("icd/config.json"), "\"x\"") == null);
}

test "writeAllTo: a stdout redirected to a file gets every write after the one before (apply --force reports once per round)" {
	var fx: RecordFx = undefined;
	try fx.init("stdout-file");
	defer fx.deinit();
	const f = try Io.Dir.cwd().createFile(fx.io(), fx.path("out"), .{ .truncate = true });
	defer f.close(fx.io());
	writeAllTo(fx.io(), f, "plugin apply: restart_required/disruptive_units: saved\n");
	writeAllTo(fx.io(), f, "plugin apply: applied\n");
	try t.expectEqualStrings("plugin apply: restart_required/disruptive_units: saved\nplugin apply: applied\n", try fx.read("out"));
}

test "humanLine: a rejection says rolled back only when it was, and the build-log hint names the instance" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const gen = "0123456789abcdef";
	const rb = struct {
		fn of(status: RollbackStatus) RollbackOut {
			return .{ .status = status, .target = .base, .target_id = "00000000000000bb" };
		}
	}.of;
	var o = Outcome.of(.rejected, .activation_hang);

	o.rollback = rb(.done);
	try t.expectEqualStrings("plugin apply: rejected/activation_hang: the change was not applied and has been rolled back. " ++
		"Build log: cogbox plugin apply -n work --log 0123456789abcdef\n", humanLine(a, "work", gen, false, o, null, false));
	// The default instance takes no -n.
	try t.expect(std.mem.endsWith(u8, humanLine(a, null, gen, false, o, null, false), "Build log: cogbox plugin apply --log 0123456789abcdef\n"));

	// The step-10 config lock could not be had: the intent stays for the next
	// plugin command or start, and nothing is said to be rolled back.
	o.rollback = rb(.pending);
	const pending = humanLine(a, "work", gen, false, o, null, false);
	try t.expect(std.mem.indexOf(u8, pending, "rolled back") == null);
	try t.expectEqualStrings("plugin apply: rejected/activation_hang: the change was not applied. Its rollback is pending; " ++
		"the next plugin command or start of the instance finishes it. Build log: cogbox plugin apply -n work --log 0123456789abcdef\n", pending);
	// The finish itself could not complete (exit 78; the stamped message is on
	// stderr), and a rejection without a rollback object is not called done.
	const blocked = humanLine(a, "work", gen, true, o, null, false);
	try t.expect(std.mem.indexOf(u8, blocked, "rolled back") == null);
	try t.expectEqualStrings("plugin apply: rejected/activation_hang: the change was not applied. Its rollback could not be finished " ++
		"(see the message above). Build log: cogbox plugin apply -n work --log 0123456789abcdef\n", blocked);
	o.rollback = null;
	try t.expect(std.mem.indexOf(u8, humanLine(a, "work", gen, false, o, null, false), "Its rollback is pending") != null);

	// The fail-closed tier removed what the change added or updated.
	o.rollback = rb(.removed);
	o.rollback.?.names = &.{.{ .name = "x", .action = .restored }};
	const removed = humanLine(a, "work", gen, false, o, null, false);
	try t.expect(std.mem.indexOf(u8, removed, "rolled back") == null);
	try t.expectEqualStrings("plugin apply: rejected/activation_hang: the change was not applied. Its previous plugin state could not be restored, " ++
		"so the plugins it added or updated were removed. Build log: cogbox plugin apply -n work --log 0123456789abcdef\n", removed);
	// A rolled-back del: the name it removed is not put back.
	o.rollback.?.names = &.{.{ .name = "x", .action = .reinserted }};
	try t.expect(std.mem.indexOf(u8, humanLine(a, "work", gen, false, o, null, false), "so the plugins it removed stay removed. Build log:") != null);
}

test "humanLine: Apply anyway's own outcomes, the hint to apply anyway, and the units a run forced" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const gen = "0123456789abcdef";
	const plan: Plan = .{ .id = "fedcba9876543210", .boot_id = "", .comp = "", .P = "", .T = "", .units = &.{
		.{ .unit = "docker.service", .action = .restart, .why = "changed", .class = "B" },
	}, .repair = &.{}, .reexec = false };
	const docker = "    restart docker.service (changed; class B): stops every running container\n";

	try t.expectEqualStrings("plugin apply: restart_required/plan_expired: nothing was applied: the plan to apply anyway is unknown, older than 30 minutes, " ++
		"or from another boot or plugin state\n", humanLine(a, "work", gen, false, Outcome.of(.restart_required, .plan_expired), null, true));
	// A plan_changed's new plan is listed whole before its id, as an
	// overridable refusal's is; under --force (no hint) forceLoop lists it.
	var changed = Outcome.with(.restart_required, .plan_changed, &.{ "docker.service", "sshd.service" });
	changed.plan = plan;
	const changed_head = "plugin apply: restart_required/plan_changed: nothing was applied: the plan changed since it was shown\n  docker.service, sshd.service\n";
	try t.expectEqualStrings(changed_head ++ "  to apply it now anyway: cogbox plugin apply --force -n work\n" ++
		"  applying the new plan anyway would:\n" ++ docker ++
		"  without a terminal, after reading the plan above: cogbox plugin apply --force-plan fedcba9876543210 -n work\n", humanLine(a, "work", gen, false, changed, null, true));
	try t.expectEqualStrings(changed_head, humanLine(a, "work", gen, false, changed, null, false));
	changed.plan = null;
	try t.expectEqualStrings("plugin apply: restart_required/plan_changed: nothing was applied: the plan changed since it was shown (no new plan could be stored)\n" ++
		"  docker.service, sshd.service\n", humanLine(a, "work", gen, false, changed, null, true));

	// An overridable refusal says how to apply it anyway, after its units;
	// not under --force (which asks next), and not for a plan it cannot offer.
	var offered = Outcome.with(.restart_required, .disruptive_units, &.{"docker.service"});
	offered.plan = plan;
	const saved = "plugin apply: restart_required/disruptive_units: saved; it loads at the next restart (a live apply would disrupt the units listed)\n  docker.service\n";
	// Off a terminal `--force` is refused: the plan id is what --force-plan
	// takes, and a human line shows it only after the whole plan.
	try t.expectEqualStrings(saved ++ "  to apply it now anyway: cogbox plugin apply --force -n work\n" ++
		"  applying it anyway would:\n" ++ docker ++
		"  without a terminal, after reading the plan above: cogbox plugin apply --force-plan fedcba9876543210 -n work\n", humanLine(a, "work", gen, false, offered, null, true));
	try t.expectEqualStrings(saved ++ "  to apply it now anyway: cogbox plugin apply --force\n" ++
		"  applying it anyway would:\n" ++ docker ++
		"  without a terminal, after reading the plan above: cogbox plugin apply --force-plan fedcba9876543210\n", humanLine(a, null, gen, false, offered, null, true));
	try t.expectEqualStrings(saved, humanLine(a, "work", gen, false, offered, null, false));
	// A plan that cannot be listed (a name outside the charset) is offered
	// nowhere, its id included; nor is one with nothing to list.
	var unlisted = offered;
	unlisted.plan.?.units = &.{.{ .unit = "doc\x1b[2Jker.service", .action = .restart, .why = "changed", .class = "B" }};
	try t.expectEqualStrings(saved, humanLine(a, "work", gen, false, unlisted, null, true));
	unlisted.plan.?.units = &.{.{ .unit = "docker.service", .action = .restart, .why = "propagated:x:\x1b[2J", .class = "B" }};
	try t.expectEqualStrings(saved, humanLine(a, "work", gen, false, unlisted, null, true));
	unlisted.plan.?.units = &.{};
	try t.expectEqualStrings(saved, humanLine(a, "work", gen, false, unlisted, null, true));
	var mixed = Outcome.with(.restart_required, .restart_only_units, &.{"docker.service"});
	mixed.plan = plan;
	try t.expect(std.mem.indexOf(u8, humanLine(a, "work", gen, false, mixed, null, true), "apply it now anyway") == null);

	// What a forced run forced, whatever its outcome.
	const forced: Forced = .{ .plan = plan.id, .units = &.{ "docker.service", "docker.socket" } };
	try t.expectEqualStrings("plugin apply: applied: the plugin changes are live\n  forced units: docker.service, docker.socket\n", humanLine(a, "work", gen, false, Outcome.of(.applied, null), forced, true));
	var failed = Outcome.with(.undone, .forced_unit_failed, &.{"docker.service"});
	failed.units = &.{"docker.service"};
	try t.expectEqualStrings("plugin apply: undone/forced_unit_failed: the live apply was undone; the change loads at the next restart\n  docker.service\n" ++
		"  failed units: docker.service\n  forced units: docker.service, docker.socket\n", humanLine(a, "work", gen, false, failed, forced, true));
	// A plan that only reloads units or re-executes systemd relaxes nothing.
	try t.expectEqualStrings("plugin apply: applied: the plugin changes are live\n  forced units: none (it only reloads units or re-executes systemd, which every check still covers)\n", humanLine(a, "work", gen, false, Outcome.of(.applied, null), .{ .plan = plan.id, .units = &.{} }, true));
}

test "humanLine: the plan id to apply anyway off a terminal comes after the whole plan, not only the units of the refusal's reason" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const gen = "0123456789abcdef";
	// A docker setting (class B) beside a .network change (class C) that also
	// re-executes systemd (class D): the refusal is disruptive_units, so its
	// detail names the class B units alone, while the plan also reloads
	// networkd, re-executes systemd and repairs the reply route.
	const plan: Plan = .{ .id = "fedcba9876543210", .boot_id = "", .comp = "", .P = "", .T = "", .units = &.{
		.{ .unit = "docker.service", .action = .stop, .why = "changed", .class = "B" },
		.{ .unit = "docker.socket", .action = .restart, .why = "induced", .class = "B" },
		.{ .unit = "systemd-networkd.service", .action = .reload, .why = "changed", .class = "C" },
	}, .repair = &.{repair_unit}, .reexec = true };
	const whole = "    stop docker.service (changed; class B): stops every running container\n" ++
		"    restart docker.socket (induced; class B)\n" ++
		"    reload systemd-networkd.service (changed; class C)\n" ++
		"    re-execute systemd\n" ++
		"    then restart cogbox-reply-route.service (repairs the uplink's reply routing)\n";
	var o = Outcome.with(.restart_required, .disruptive_units, &.{ "docker.service", "docker.socket" });
	o.plan = plan;
	const line = humanLine(a, "la", gen, false, o, null, true);
	try t.expectEqualStrings("plugin apply: restart_required/disruptive_units: saved; it loads at the next restart (a live apply would disrupt the units listed)\n" ++
		"  docker.service, docker.socket\n" ++
		"  to apply it now anyway: cogbox plugin apply --force -n la\n" ++
		"  applying it anyway would:\n" ++ whole ++
		"  without a terminal, after reading the plan above: cogbox plugin apply --force-plan fedcba9876543210 -n la\n", line);
	// Every unit with its action, the re-exec and the repair precede the
	// --force-plan line, the only mention of the plan's id.
	const force_plan = std.mem.indexOf(u8, line, "--force-plan").?;
	try t.expectEqual(force_plan + "--force-plan ".len, std.mem.indexOf(u8, line, plan.id).?);
	for ([_][]const u8{ "stop docker.service", "restart docker.socket", "reload systemd-networkd.service", "re-execute systemd", "then restart cogbox-reply-route.service" }) |item| {
		const at = std.mem.indexOf(u8, line, item) orelse return error.TestUnexpectedResult;
		try t.expect(at < force_plan);
	}

	// A systemd_reexec-only plan has no units and an empty detail: the
	// re-exec is still shown before its id.
	var reexec = Outcome.of(.restart_required, .systemd_reexec);
	reexec.plan = .{ .id = "0011223344556677", .boot_id = "", .comp = "", .P = "", .T = "", .units = &.{}, .repair = &.{}, .reexec = true };
	try t.expectEqualStrings("plugin apply: restart_required/systemd_reexec: saved; it loads at the next restart (a live apply would disrupt the units listed)\n" ++
		"  to apply it now anyway: cogbox plugin apply --force -n la\n" ++
		"  applying it anyway would:\n    re-execute systemd\n" ++
		"  without a terminal, after reading the plan above: cogbox plugin apply --force-plan 0011223344556677 -n la\n", humanLine(a, "la", gen, false, reexec, null, true));

	// The new plan of a plan_changed, the same way: its id comes only after
	// the whole of it, never in the head line.
	var changed = Outcome.with(.restart_required, .plan_changed, &.{ "docker.service", "docker.socket" });
	changed.plan = plan;
	const cl = humanLine(a, "la", gen, false, changed, null, true);
	try t.expectEqualStrings("plugin apply: restart_required/plan_changed: nothing was applied: the plan changed since it was shown\n" ++
		"  docker.service, docker.socket\n" ++
		"  to apply it now anyway: cogbox plugin apply --force -n la\n" ++
		"  applying the new plan anyway would:\n" ++ whole ++
		"  without a terminal, after reading the plan above: cogbox plugin apply --force-plan fedcba9876543210 -n la\n", cl);
	try t.expectEqual(@as(usize, 1), std.mem.count(u8, cl, plan.id));
	try t.expect(std.mem.indexOf(u8, cl, plan.id).? > std.mem.indexOf(u8, cl, "then restart cogbox-reply-route.service").?);
}

test "rollbackSentence: each rollback state has its own sentence, and a report read back as JSON gets the same one" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const changed: ScopeKinds = .{ .changed = true };
	const deleted: ScopeKinds = .{ .deleted = true };
	const both: ScopeKinds = .{ .changed = true, .deleted = true };
	try t.expect(rollbackSentence(.done, false, changed) == null);
	try t.expect(rollbackSentence(.done, true, changed) == null);
	// Five distinct sentences, and no state but done is called rolled back.
	const all = [_][]const u8{
		rollbackSentence(.pending, false, .{}).?,
		rollbackSentence(.pending, true, .{}).?,
		rollbackSentence(.removed, false, changed).?,
		rollbackSentence(.removed, false, deleted).?,
		rollbackSentence(.removed, false, both).?,
	};
	for (all, 0..) |x, i| {
		try t.expect(std.mem.indexOf(u8, x, "rolled back") == null);
		for (all[i + 1 ..]) |y| try t.expect(!std.mem.eql(u8, x, y));
	}
	// A missing status is pending, and an empty scope reads as an add or update.
	try t.expectEqualStrings(all[0], rollbackSentence(null, false, .{}).?);
	try t.expectEqualStrings(all[1], rollbackSentence(null, true, .{}).?);
	try t.expectEqualStrings(all[2], rollbackSentence(.removed, false, .{}).?);
	try t.expectEqualStrings(all[2], rollbackSentence(.removed, true, changed).?);

	// The JSON form, through the report line the inline apply reads back.
	const Case = struct { status: RollbackStatus, names: []const rollback.RecordName, blocked: bool };
	const cases = [_]Case{
		.{ .status = .done, .names = &.{.{ .name = "x", .action = .restored }}, .blocked = false },
		.{ .status = .pending, .names = &.{}, .blocked = false },
		.{ .status = .pending, .names = &.{}, .blocked = true },
		.{ .status = .removed, .names = &.{ .{ .name = "x", .action = .removed }, .{ .name = "y", .action = .restored } }, .blocked = false },
		.{ .status = .removed, .names = &.{.{ .name = "x", .action = .reinserted }}, .blocked = false },
		.{ .status = .removed, .names = &.{ .{ .name = "x", .action = .reinserted }, .{ .name = "y", .action = .removed } }, .blocked = false },
	};
	for (cases) |c| {
		var o = Outcome.of(.rejected, .activation_hang);
		o.rollback = .{ .status = c.status, .target = .base, .target_id = "00000000000000bb", .names = c.names };
		const line = try reportLine(a, .{ .gen = "0123456789abcdef", .op = "update", .result = o.result, .reason = o.reason, .detail = null, .overridable = false, .plan = null, .forced = null, .rollback = o.rollback, .runner = null, .toplevel = null, .units = null, .rolled_back_guest = null, .cap = null, .base_id = null, .built_id = null });
		const v = try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{});
		const want = rollbackSentence(c.status, c.blocked, ScopeKinds.of(c.names));
		const got = rollbackSentenceJson(v.object.get("apply").?.object.get("rollback"), c.blocked);
		if (want) |w| try t.expectEqualStrings(w, got.?) else try t.expect(got == null);
	}
	// No rollback object, a null one, or an unknown status: pending.
	try t.expectEqualStrings(all[0], rollbackSentenceJson(null, false).?);
	try t.expectEqualStrings(all[0], rollbackSentenceJson(.null, false).?);
	const odd = try std.json.parseFromSliceLeaky(std.json.Value, a, "{\"status\":\"later\"}", .{});
	try t.expectEqualStrings(all[1], rollbackSentenceJson(odd, true).?);
}

test "record: a non-JSON rejected run prints its rollback and the instance's build-log hint, and exits 1" {
	var fx: RecordFx = undefined;
	try fx.init("human");
	defer fx.deinit();
	try fx.write("icd/config.json", "{\"plugins\": [], \"network\": \"full\"}\n");
	const b = try fx.take();
	try snapshot.setRole(fx.io(), fx.path("icd"), .base, &b, null);
	try fx.write("icd/config.json", plugin_x_config);
	try fx.write("icd/plugins-flake/flake.nix", "{ }\n");
	try fx.write("icd/plugin-sources/x/flake.nix", "{ }\n");
	const s = try fx.take();
	const gen = snapshot.newId(fx.io());
	var r = try fx.run(gen, s);
	const c = fx.ctx();
	c.instance = "work";
	r.ctx = c;
	r.args = .{ .json = false };
	r.eval_target = .base;
	r.eval_target_id = &b;
	r.scope_eval = try snapshot.scope(fx.a(), r.s.?.plugins, (try snapshot.read(fx.a(), fx.io(), fx.path("icd"), &b)).plugins);
	r.phase = .record;
	try t.expectEqual(Outcome.of(.rejected, .eval_error), evalError(&r));
	try t.expectEqual(@as(u8, 1), finish(&r, Outcome.of(.rejected, .eval_error)));
	const want = try std.fmt.allocPrint(fx.a(), "plugin apply: rejected/eval_error: the change was not applied and has been rolled back. " ++
		"Build log: cogbox plugin apply -n work --log {s}\n", .{&gen});
	try t.expectEqualStrings(want, fx.sink.items);
}
