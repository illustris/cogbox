// Tests for apply.zig: the eval_error classifier, the refusal matrix (the
// reason vocabulary and the preflight through `apply.run` on fixture
// instances), plan determinism and the tier-2 merge, the report schema, the
// guest reply parser, the child-process loop and containment. No nix, ssh or
// systemd runs; the child tests use the shell from PATH.

const std = @import("std");
const plugin = @import("main.zig");
const apply = @import("apply.zig");
const cli = @import("cli.zig");
const snapshot = @import("snapshot.zig");
const rollback = @import("rollback.zig");
const unitplan = @import("unitplan.zig");
const t = std.testing;

const flake_source = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-cogbox-source";
const key = flake_source ++ "#cogbox";
const runner_b = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-microvm-run";
const runner_r = "/nix/store/rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr-microvm-run";

// --- the eval_error classifier ---------------------------------------------------

const trace =
	\\error:
	\\       ... while evaluating the attribute 'config.microvm.declaredRunner.drvPath'
	\\         at /nix/store/x-source/flake.nix:12:3:
	\\
	\\       error: The option `services.frob' does not exist.
	\\
;

fn exited(code: u8) ?apply.ChildExit {
	return .{ .exited = code };
}

test "classifier: exit 1 with an evaluation trace is an eval_error candidate" {
	try t.expectEqual(apply.StageClass.eval_candidate, apply.classifyInstantiate(.{ .exit = exited(1), .stderr = trace }));
	// Each evaluation marker counts, and `attribute '...' missing`.
	for ([_][]const u8{
		"error: undefined variable 'pkgs'\n",
		"error: infinite recursion encountered\n",
		"error: assertion '(x == 1)' failed\n",
		"error: cogbox: two plugins define skill 'x'\n",
		"error: attribute 'frob' missing\n",
		"error:\n       ... while calling the 'import' builtin\n       error: syntax\n",
	}) |stderr| {
		try t.expectEqual(apply.StageClass.eval_candidate, apply.classifyInstantiate(.{ .exit = exited(1), .stderr = stderr }));
	}
	// The unit containment's Result must not say it was killed.
	try t.expectEqual(apply.StageClass.eval_candidate, apply.classifyInstantiate(.{ .exit = exited(1), .unit_result = "exit-code", .stderr = trace }));
}

test "classifier: infrastructure, signals and timeouts are never eval_error" {
	const build = apply.StageClass.build;
	// SIGKILL with empty stderr; exit 137/143 (a killed nix behind a wrapper).
	try t.expectEqual(build, apply.classifyInstantiate(.{ .exit = .{ .signaled = 9 }, .stderr = "" }));
	try t.expectEqual(build, apply.classifyInstantiate(.{ .exit = exited(137), .stderr = trace }));
	try t.expectEqual(build, apply.classifyInstantiate(.{ .exit = exited(143), .stderr = trace }));
	// ENOSPC, bad_alloc, a daemon EOF, an interrupted call: an eval trace beside
	// any infrastructure marker is not evidence.
	for ([_][]const u8{
		trace ++ "error: writing to file: No space left on device\n",
		trace ++ "error: std::bad_alloc\n",
		trace ++ "error: unexpected end-of-file\n",
		trace ++ "error: cannot connect to socket at '/nix/var/nix/daemon-socket/socket'\n",
		trace ++ "error: interrupted by the user\n",
		trace ++ "error: Cannot build '/nix/store/x.drv'.\n",
		trace ++ "error: out of memory\n",
		trace ++ "error: Connection reset by peer\n",
		trace ++ "error: operation timed out\n",
	}) |stderr| {
		try t.expectEqual(build, apply.classifyInstantiate(.{ .exit = exited(1), .stderr = stderr }));
	}
	// `error:` without an evaluation marker, and an exit other than 1.
	try t.expectEqual(build, apply.classifyInstantiate(.{ .exit = exited(1), .stderr = "error: something else\n" }));
	try t.expectEqual(build, apply.classifyInstantiate(.{ .exit = exited(2), .stderr = trace }));
	// A stderr the capture truncated could hide a marker.
	try t.expectEqual(build, apply.classifyInstantiate(.{ .exit = exited(1), .stderr = trace, .stderr_truncated = true }));
	// The unit says it was signalled.
	try t.expectEqual(build, apply.classifyInstantiate(.{ .exit = exited(1), .unit_result = "signal", .stderr = trace }));
	// A timeout, by the loop's bound or the unit's RuntimeMaxSec.
	try t.expectEqual(apply.StageClass.build_timeout, apply.classifyInstantiate(.{ .exit = .{ .signaled = 9 }, .stopped = .deadline, .stderr = trace }));
	try t.expectEqual(apply.StageClass.build_timeout, apply.classifyInstantiate(.{ .exit = exited(1), .unit_result = "timeout", .stderr = trace }));
	// The unit's OOM kill.
	try t.expectEqual(apply.StageClass.oom, apply.classifyInstantiate(.{ .exit = exited(1), .unit_result = "oom-kill", .stderr = trace }));
	// Stopped by a flag: not a verdict on the change.
	try t.expectEqual(build, apply.classifyInstantiate(.{ .exit = .{ .signaled = 9 }, .stopped = .supersede, .stderr = trace }));
	// No exit at all (the reap gave up).
	try t.expectEqual(build, apply.classifyInstantiate(.{ .exit = null, .stderr = trace }));
}

test "classifier: NAR hash mismatch is inputs_changed, a fetch failure is uncached, success is ok" {
	try t.expectEqual(apply.StageClass.inputs_changed, apply.classifyInstantiate(.{ .exit = exited(1), .stderr = "error: NAR hash mismatch in input 'path:/x'\n" ++ trace }));
	try t.expectEqual(apply.StageClass.inputs_uncached, apply.classifyInstantiate(.{ .exit = exited(1), .stderr = "error: unable to download 'https://cache.example.com/x.narinfo': HTTP error 503\n" }));
	try t.expectEqual(apply.StageClass.inputs_uncached, apply.classifyInstantiate(.{ .exit = exited(1), .stderr = "error: Could not resolve host: cache.example.com\n" }));
	try t.expectEqual(apply.StageClass.ok, apply.classifyInstantiate(.{ .exit = exited(0), .stderr = "" }));
	try t.expectEqual(apply.StageClass.ok, apply.classifyInstantiate(.{ .exit = exited(0), .unit_result = "success", .stderr = "" }));
}

test "classifier: the realise is never an eval_error" {
	try t.expectEqual(apply.StageClass.build, apply.classifyRealise(.{ .exit = exited(1), .stderr = trace }));
	try t.expectEqual(apply.StageClass.build, apply.classifyRealise(.{ .exit = exited(1), .stderr = "error: NAR hash mismatch in path '/nix/store/x'\n" }));
	try t.expectEqual(apply.StageClass.inputs_uncached, apply.classifyRealise(.{ .exit = exited(1), .stderr = "error: unable to download 'x'\n" }));
	try t.expectEqual(apply.StageClass.build_timeout, apply.classifyRealise(.{ .exit = null, .stopped = .deadline, .stderr = "" }));
	try t.expectEqual(apply.StageClass.oom, apply.classifyRealise(.{ .exit = exited(1), .unit_result = "oom-kill", .stderr = "" }));
	try t.expectEqual(apply.StageClass.ok, apply.classifyRealise(.{ .exit = exited(0), .stderr = "" }));
}

test "classifier: only a reproduction with the same first error line confirms an eval_error" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	// The bare `error:` above a trace is skipped; the message line counts, ANSI
	// colours removed.
	try t.expectEqualStrings("error: The option `services.frob' does not exist.", apply.firstErrorLine(a, trace).?);
	try t.expectEqualStrings("error: x", apply.firstErrorLine(a, "\x1b[31;1merror:\x1b[0m x\n").?);
	try t.expect(apply.firstErrorLine(a, "error:\n") == null);

	const first: apply.StageExit = .{ .exit = exited(1), .stderr = trace };
	try t.expect(apply.reproduced(a, first, first));
	// Not reproduced: the second run succeeded, or failed differently.
	try t.expect(!apply.reproduced(a, first, .{ .exit = exited(0), .stderr = "" }));
	try t.expect(!apply.reproduced(a, first, .{ .exit = exited(1), .stderr = "error: undefined variable 'y'\n" }));
	try t.expect(!apply.reproduced(a, first, .{ .exit = exited(1), .stderr = trace ++ "error: No space left on device\n" }));
	try t.expect(!apply.reproduced(a, .{ .exit = exited(1), .stderr = "error: z\n" }, .{ .exit = exited(1), .stderr = "error: z\n" }));
}

// --- the reason vocabulary ---------------------------------------------------------

test "overridability matrix: only disruptive_units, network_config and systemd_reexec can be forced" {
	var n: usize = 0;
	inline for (@typeInfo(apply.Reason).@"enum".fields) |f| {
		const r: apply.Reason = @enumFromInt(f.value);
		const want = r == .disruptive_units or r == .network_config or r == .systemd_reexec;
		try t.expectEqual(want, r.overridable());
		if (r.overridable()) n += 1;
		// Only a restart_required outcome with a plan is ever overridable.
		var o = apply.Outcome.of(.restart_required, r);
		o.plan = samplePlan(&.{});
		try t.expectEqual(want, o.overridable());
		o.result = .failed;
		try t.expect(!o.overridable());
		o.result = .rejected;
		try t.expect(!o.overridable());
	}
	try t.expectEqual(@as(usize, 3), n);
	try t.expect(!apply.Outcome.of(.restart_required, null).overridable());
	// Without a plan (none to force, or one that could not be stored) Apply
	// anyway is never offered.
	for ([_]apply.Reason{ .disruptive_units, .network_config, .systemd_reexec }) |r| {
		try t.expect(!apply.Outcome.of(.restart_required, r).overridable());
	}
	// The plan's reasons map one to one, with the same overridability.
	inline for (@typeInfo(unitplan.Reason).@"enum".fields) |f| {
		const pr: unitplan.Reason = @enumFromInt(f.value);
		try t.expectEqualStrings(f.name, @tagName(apply.Reason.fromPlan(pr)));
		try t.expectEqual(pr.overridable(), apply.Reason.fromPlan(pr).overridable());
	}
	inline for (@typeInfo(unitplan.BootShapeReason).@"enum".fields) |f| {
		try t.expectEqualStrings(f.name, @tagName(apply.Reason.fromBootShape(@enumFromInt(f.value))));
	}
}

test "whole-verb timer: COGBOX_APPLY_TIMEOUT, 5340 s by default, above the 5335 s its legs add up to" {
	var env = std.process.Environ.Map.init(t.allocator);
	defer env.deinit();
	try t.expectEqual(@as(i64, 5340), apply.wholeSeconds(&env));
	try env.put("COGBOX_APPLY_TIMEOUT", "60");
	try t.expectEqual(@as(i64, 60), apply.wholeSeconds(&env));
	try env.put("COGBOX_APPLY_TIMEOUT", "never");
	try t.expectEqual(@as(i64, 5340), apply.wholeSeconds(&env));
	// The legs it covers (spec section 2, "Bounds", whole verb): dispatcher
	// lock, recovery (status hop, abort wait, confirmed record), finish, user
	// flake, snapshot and other checks, build, settled, plan, busy, re-plan,
	// start, poll (W + margin), confirm, step-10 lock, record or rollback,
	// trash. A leg that grows past the timer is caught here.
	const B = apply.Bounds;
	const s = struct {
		fn of(ms: i64) i64 {
			return @divTrunc(ms, 1000);
		}
	}.of;
	const finish = s(rollback.finish_budget_ms);
	const recovery = s(B.hop_ms) + s(B.recover_abort_ms) + 10;
	const legs = s(B.dispatcher_lock_ms) + recovery + finish + s(B.user_flake_ms) + 60 + B.build_s +
		s(B.settled_ms) + s(B.plan_hop_ms) + s(B.busy_wait_ms) + s(B.plan_hop_ms) + s(B.start_leg_ms) +
		B.window_s + B.poll_margin_s + s(B.hop_ms) + s(B.record_lock_ms) + finish + s(B.trash_ms);
	try t.expectEqual(@as(i64, 5335), legs);
	try t.expect(B.whole_s > legs);
}

test "a restart_required R is recorded except for the spec's exclusion list" {
	for ([_]apply.Reason{ .base_changed, .no_boot_record, .foreign_system, .unsupported_platform, .air_gapped, .insufficient_memory, .insufficient_disk, .booting, .no_containment, .disabled, .user_flake_changed, .composition_stale, .plan_expired, .plan_changed }) |r| {
		try t.expect(!r.recordsRunner());
	}
	for ([_]apply.Reason{ .boot_shape, .kernel_modules, .fstab, .init_interface, .store_fallback, .guest_tainted, .no_helper, .restart_only_units, .skipped_units, .pre_switch_check, .disruptive_units, .network_config, .systemd_reexec }) |r| {
		try t.expect(r.recordsRunner());
	}
}

// --- the plan ------------------------------------------------------------------------

fn samplePlan(units: []const apply.PlanUnit) apply.Plan {
	return .{
		.id = "",
		.boot_id = "0123abcd-0000-4000-8000-0123456789ab",
		.comp = "c" ** 64,
		.P = "/nix/store/pppppppppppppppppppppppppppppppp-nixos-system",
		.T = "/nix/store/tttttttttttttttttttttttttttttttt-nixos-system",
		.units = units,
		.repair = &.{},
		.reexec = false,
	};
}

test "plan id: deterministic, independent of order, and moved by every input" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const unit_a: apply.PlanUnit = .{ .unit = "docker.service", .action = .start, .why = "propagated:wants:plug.service", .class = "B" };
	const unit_b: apply.PlanUnit = .{ .unit = "systemd-networkd.service", .action = .reload, .why = "changed", .class = "C" };
	const base = try apply.planId(a, samplePlan(&.{ unit_a, unit_b }));
	try t.expectEqual(@as(usize, 16), base.len);
	try t.expect(cli.isHex16(base));
	try t.expectEqualStrings(base, try apply.planId(a, samplePlan(&.{ unit_a, unit_b })));
	try t.expectEqualStrings(base, try apply.planId(a, samplePlan(&.{ unit_b, unit_a })));

	var ids: std.ArrayList([]const u8) = .empty;
	try ids.append(a, base);
	var p = samplePlan(&.{ unit_a, unit_b });
	p.boot_id = "0123abcd-0000-4000-8000-0123456789ac";
	try ids.append(a, try apply.planId(a, p));
	p = samplePlan(&.{ unit_a, unit_b });
	p.comp = "d" ** 64;
	try ids.append(a, try apply.planId(a, p));
	p = samplePlan(&.{ unit_a, unit_b });
	p.P = "/nix/store/qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq-nixos-system";
	try ids.append(a, try apply.planId(a, p));
	p = samplePlan(&.{ unit_a, unit_b });
	p.T = "/nix/store/uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu-nixos-system";
	try ids.append(a, try apply.planId(a, p));
	p = samplePlan(&.{ .{ .unit = "docker.service", .action = .restart, .why = unit_a.why, .class = "B" }, unit_b });
	try ids.append(a, try apply.planId(a, p));
	p = samplePlan(&.{ .{ .unit = "containerd.service", .action = .start, .why = unit_a.why, .class = "B" }, unit_b });
	try ids.append(a, try apply.planId(a, p));
	p = samplePlan(&.{unit_a});
	try ids.append(a, try apply.planId(a, p));
	p = samplePlan(&.{ unit_a, unit_b });
	p.reexec = true;
	try ids.append(a, try apply.planId(a, p));
	p = samplePlan(&.{ unit_a, unit_b });
	p.repair = &.{apply.repair_unit};
	try ids.append(a, try apply.planId(a, p));
	for (ids.items, 0..) |x, i| for (ids.items[i + 1 ..]) |y| try t.expect(!std.mem.eql(u8, x, y));
}

// --- Apply anyway: the force list, the plan store and its binding ----------------------

const test_host_boot = "0123abcd-0000-4000-8000-0123456789ab";
const docker_restart: apply.PlanUnit = .{ .unit = "docker.service", .action = .restart, .why = "changed", .class = "B" };

/// A stored disruptive_units plan of `units` over composition `comp`, made at
/// CLOCK_BOOTTIME `created` in the boot `nonce`/`host_boot`.
fn storedOf(a: std.mem.Allocator, units: []const apply.PlanUnit, comp: []const u8, created: i64, nonce: []const u8, host_boot: []const u8) !apply.StoredPlan {
	var p = samplePlan(units);
	p.comp = comp;
	p.id = try apply.planId(a, p);
	return .{ .plan = p, .reason = .disruptive_units, .created = created, .nonce = nonce, .host_boot = host_boot, .gen = "fedcba9876543210" };
}

/// `n` class B restarts, `u<first>.service` on.
fn unitsOf(a: std.mem.Allocator, first: usize, n: usize) ![]apply.PlanUnit {
	const units = try a.alloc(apply.PlanUnit, n);
	for (units, first..) |*u, i| u.* = .{ .unit = try std.fmt.allocPrint(a, "u{d:0>3}.service", .{i}), .action = .restart, .why = "changed", .class = "B" };
	return units;
}

test "force list: the names of the units the plan stops, starts or restarts, sorted and unique; one it only reloads is left out; one the guest helper would refuse is an error, and no such plan is built" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	var p = samplePlan(&.{
		.{ .unit = "systemd-networkd.service", .action = .reload, .why = "changed", .class = "C" },
		.{ .unit = "nftables.service", .action = .reload, .why = "changed", .class = "C" },
		.{ .unit = "nftables.service", .action = .restart, .why = "propagated:requires:x.service", .class = "C" },
		.{ .unit = "docker.socket", .action = .restart, .why = "changed", .class = "B" },
		.{ .unit = "docker.service", .action = .stop, .why = "changed", .class = "B" },
		.{ .unit = "docker.service", .action = .start, .why = "induced", .class = "B" },
	});
	p.repair = &.{apply.repair_unit};
	const units = try apply.forceUnits(a, p);
	// The guest exempts a listed unit from every comparison, whatever its
	// action; a reload keeps the InvocationID and the running state, so a
	// unit only reloaded stays held to them (a stop or a restart of it outside
	// the plan is still unplanned_disruption). One reloaded and restarted is
	// listed.
	try t.expectEqual(@as(usize, 3), units.len);
	try t.expectEqualStrings("docker.service", units[0]);
	try t.expectEqualStrings("docker.socket", units[1]);
	try t.expectEqualStrings("nftables.service", units[2]);
	try t.expectEqualStrings("docker.service\ndocker.socket\nnftables.service\n", try apply.forceInput(a, units));
	// A re-exec-only plan forces no unit, and neither does one that only
	// reloads.
	try t.expectEqual(@as(usize, 0), (try apply.forceUnits(a, samplePlan(&.{}))).len);
	try t.expectEqual(@as(usize, 0), (try apply.forceUnits(a, samplePlan(p.units[0..2]))).len);
	// A reloaded unit's name still has to be one the report may carry.
	try t.expectError(error.BadUnitName, apply.forceUnits(a, samplePlan(&.{.{ .unit = "a b.service", .action = .reload, .why = "changed", .class = "C" }})));

	// The helper's limits (cogbox-live-switch start): 1..256 names, its
	// charset, and what `head -c 65536` reads whole.
	const many = try unitsOf(a, 0, 257);
	try t.expectEqual(@as(usize, 256), (try apply.forceUnits(a, samplePlan(many[0..256]))).len);
	try t.expectError(error.TooManyUnits, apply.forceUnits(a, samplePlan(many)));
	try t.expectError(error.BadUnitName, apply.forceUnits(a, samplePlan(&.{.{ .unit = "a b.service", .action = .restart, .why = "changed", .class = "B" }})));
	// 256 names of 255 bytes and their newlines fill 65536 bytes exactly;
	// one byte more is refused.
	const long = try a.alloc(apply.PlanUnit, 256);
	for (long, 0..) |*u, i| u.* = .{ .unit = try std.fmt.allocPrint(a, "{s}{d:0>3}.service", .{ "x" ** 244, i }), .action = .restart, .why = "changed", .class = "B" };
	const full = try apply.forceUnits(a, samplePlan(long));
	try t.expectEqual(@as(usize, 65536), (try apply.forceInput(a, full)).len);
	long[0].unit = try std.fmt.allocPrint(a, "{s}000.service", .{"x" ** 245});
	try t.expectError(error.TooLong, apply.forceUnits(a, samplePlan(long)));

	// buildPlan offers no plan the helper would refuse.
	const hz = try a.alloc(unitplan.Hazard, many.len);
	for (hz, many) |*h, u| {
		const path = try a.alloc(unitplan.Hop, 1);
		path[0] = .{ .unit = u.unit, .action = .restart, .edge = null };
		h.* = .{ .class = .b, .unit = u.unit, .action = .restart, .path = path, .why = .changed };
	}
	const refusal: unitplan.Refusal = .{ .reason = .disruptive_units, .overridable = true };
	const sp = samplePlan(&.{});
	const fits = (try apply.buildPlan(a, .{ .hazards = hz[0..256], .skipped = &.{}, .reexec = false, .refusal = refusal }, sp.boot_id, sp.comp, sp.P, sp.T)).?;
	try t.expectEqual(@as(usize, 256), fits.units.len);
	try t.expect(try apply.buildPlan(a, .{ .hazards = hz, .skipped = &.{}, .reexec = false, .refusal = refusal }, sp.boot_id, sp.comp, sp.P, sp.T) == null);
}

test "plan why: a propagated why names a unit as a report may; a plan whose why carries any other byte is not built, forced or listed" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	for ([_][]const u8{ "changed", "removed", "new", "target", "induced", "guest_reported", "propagated:part_of:x.service", "propagated:rt_propagates_reload_to:sshd@x-y\\x2d1.service" }) |w| {
		try t.expect(apply.isPlanWhy(w));
	}
	for ([_][]const u8{ "", "Changed", "user_unit", "propagated:", "propagated:part_of:", "propagated::x.service", "propagated:Part:x.service", "propagated:" ++ "e" ** 33 ++ ":x.service", "propagated:part_of:a b.service", "propagated:part_of:\x1b[1A\x1b[2Kx.service", "changed\n" }) |w| {
		try t.expect(!apply.isPlanWhy(w));
	}
	// A plugin's unit whose name carries an escape sequence, and a PartOf=
	// drop-in that ties docker.service to it: the docker restart's why names
	// it. Printed raw, the sequence would erase the line above it in the
	// listing a person agrees to.
	const evil = "\x1b[1A\x1b[2Kx.service";
	const Hz = struct {
		fn via(al: std.mem.Allocator, from: []const u8) ![]unitplan.Hazard {
			const path = try al.alloc(unitplan.Hop, 2);
			path[0] = .{ .unit = from, .action = .restart, .edge = null };
			path[1] = .{ .unit = "docker.service", .action = .restart, .edge = .part_of };
			const hz = try al.alloc(unitplan.Hazard, 1);
			hz[0] = .{ .class = .b, .unit = "docker.service", .action = .restart, .path = path, .why = .changed };
			return hz;
		}
	};
	const refusal: unitplan.Refusal = .{ .reason = .disruptive_units, .overridable = true };
	const sp = samplePlan(&.{});
	const clean = (try apply.buildPlan(a, .{ .hazards = try Hz.via(a, "x.service"), .skipped = &.{}, .reexec = false, .refusal = refusal }, sp.boot_id, sp.comp, sp.P, sp.T)).?;
	try t.expectEqualStrings("propagated:part_of:x.service", clean.units[0].why);
	try t.expect(try apply.buildPlan(a, .{ .hazards = try Hz.via(a, evil), .skipped = &.{}, .reexec = false, .refusal = refusal }, sp.boot_id, sp.comp, sp.P, sp.T) == null);
	// However such a plan came to be, it is no force list and no listing.
	const bad = samplePlan(&.{.{ .unit = "docker.service", .action = .restart, .why = "propagated:part_of:" ++ evil, .class = "B" }});
	try t.expectError(error.BadUnitName, apply.forceUnits(a, bad));
	try t.expectEqualStrings("", apply.planListing(a, "la", bad, false));
	try t.expect(apply.planListing(a, "la", samplePlan(&.{.{ .unit = "docker.service", .action = .restart, .why = "propagated:part_of:x.service", .class = "B" }}), false).len > 0);
}

test "force binding: planAdmits takes a valid plan of this boot and composition from the last half hour, and nothing else" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const comp = "c" ** 64;
	const now: i64 = 50_000;
	const good = try storedOf(a, &.{docker_restart}, comp, now - 60, "4242", test_host_boot);
	const id = good.plan.id;
	const admits = struct {
		fn f(al: std.mem.Allocator, sp: apply.StoredPlan, want: []const u8, at: i64) bool {
			return apply.planAdmits(al, sp, want, "4242", test_host_boot, "c" ** 64, at);
		}
	}.f;
	try t.expect(admits(a, good, id, now));
	// Age: [0, 1800) s by CLOCK_BOOTTIME; a plan from the future never.
	try t.expect(admits(a, good, id, good.created));
	try t.expect(admits(a, good, id, good.created + apply.Bounds.plan_ttl_s - 1));
	try t.expect(!admits(a, good, id, good.created + apply.Bounds.plan_ttl_s));
	try t.expect(!admits(a, good, id, good.created - 1));
	// Another id than the file's, another boot, another composition.
	try t.expect(!admits(a, good, "ffffffffffffffff", now));
	try t.expect(!apply.planAdmits(a, good, id, "4243", test_host_boot, comp, now));
	try t.expect(!apply.planAdmits(a, good, id, "4242", "0123abcd-0000-4000-8000-0123456789ac", comp, now));
	try t.expect(!apply.planAdmits(a, good, id, "4242", test_host_boot, "d" ** 64, now));
	// A content that no longer hashes to its id (an edited unit list).
	var edited = good;
	edited.plan.units = &.{.{ .unit = "sshd.service", .action = .restart, .why = "changed", .class = "B" }};
	try t.expect(!admits(a, edited, id, now));
	// A reason that is never overridable.
	var reason = good;
	reason.reason = .restart_only_units;
	try t.expect(!admits(a, reason, id, now));
	// A force list the helper would refuse, its id recomputed.
	const bad = try storedOf(a, &.{.{ .unit = "a;b.service", .action = .restart, .why = "changed", .class = "B" }}, comp, now - 60, "4242", test_host_boot);
	try t.expect(!admits(a, bad, bad.plan.id, now));
}

test "plan store: a stored plan reads back as written; prune drops leftovers, unusable, aged, future and other boots' plans, and keeps the 16 newest and the one --force-plan names" {
	var s: Scratch = undefined;
	try s.init("plans");
	defer s.deinit();
	const a = s.a();
	const io = s.io();
	const icd = s.path("icd");
	try std.Io.Dir.cwd().createDirPath(io, icd);
	const comp = "c" ** 64;
	const now: i64 = 100_000;
	const of = struct {
		fn f(al: std.mem.Allocator, first: usize, created: i64, nonce: []const u8, host_boot: []const u8) !apply.StoredPlan {
			return storedOf(al, try unitsOf(al, first, 1), "c" ** 64, created, nonce, host_boot);
		}
	}.f;
	const fresh = try of(a, 0, now - 10, "4242", test_host_boot);
	try apply.storePlan(a, io, icd, fresh, null);
	const back = try apply.readStoredPlan(a, io, icd, fresh.plan.id);
	try t.expectEqualStrings(fresh.plan.id, back.plan.id);
	try t.expectEqualStrings(fresh.plan.units[0].unit, back.plan.units[0].unit);
	try t.expectEqual(fresh.created, back.created);
	try t.expectEqual(apply.Reason.disruptive_units, back.reason);
	try t.expect(apply.planAdmits(a, back, fresh.plan.id, "4242", test_host_boot, comp, now));

	const gone = [_]apply.StoredPlan{
		try of(a, 1, now - apply.Bounds.plan_ttl_s, "4242", test_host_boot),
		try of(a, 2, now + 1, "4242", test_host_boot),
		try of(a, 3, now - 10, "4243", test_host_boot),
		try of(a, 4, now - 10, "4242", "0123abcd-0000-4000-8000-0123456789ac"),
	};
	for (gone) |sp| try apply.storePlan(a, io, icd, sp, null);
	var edited = try of(a, 5, now - 10, "4242", test_host_boot);
	edited.plan.units = (try unitsOf(a, 6, 1));
	try apply.storePlan(a, io, icd, edited, null);
	var reason = try of(a, 7, now - 10, "4242", test_host_boot);
	reason.reason = .skipped_units;
	try apply.storePlan(a, io, icd, reason, null);
	try s.write("icd/apply/plans/0123456789abcdef.json", "{\"plan\":");
	try s.write("icd/apply/plans/.0123456789abcdef.json.tmp.00112233", "{}");
	try s.write("icd/apply/plans/notes.txt", "kept\n");
	apply.prunePlans(a, io, icd, "4242", test_host_boot, null, now);
	try t.expect(s.exists(try std.fmt.allocPrint(a, "icd/apply/plans/{s}.json", .{fresh.plan.id})));
	for (gone) |sp| try t.expect(!s.exists(try std.fmt.allocPrint(a, "icd/apply/plans/{s}.json", .{sp.plan.id})));
	try t.expect(!s.exists(try std.fmt.allocPrint(a, "icd/apply/plans/{s}.json", .{edited.plan.id})));
	try t.expect(!s.exists(try std.fmt.allocPrint(a, "icd/apply/plans/{s}.json", .{reason.plan.id})));
	try t.expect(!s.exists("icd/apply/plans/0123456789abcdef.json"));
	try t.expect(!s.exists("icd/apply/plans/.0123456789abcdef.json.tmp.00112233"));
	try t.expect(s.exists("icd/apply/plans/notes.txt"));

	// 18 usable plans: the 16 newest stay.
	var ids: std.ArrayList([]const u8) = .empty;
	for (0..17) |i| {
		const sp = try of(a, 100 + i, now - 100 + @as(i64, @intCast(i)), "4242", test_host_boot);
		try apply.storePlan(a, io, icd, sp, null);
		try ids.append(a, sp.plan.id);
	}
	apply.prunePlans(a, io, icd, "4242", test_host_boot, null, now);
	for (ids.items, 0..) |id, i| try t.expectEqual(i >= 2, s.exists(try std.fmt.allocPrint(a, "icd/apply/plans/{s}.json", .{id})));
	try t.expect(s.exists(try std.fmt.allocPrint(a, "icd/apply/plans/{s}.json", .{fresh.plan.id})));
	// The plan a run's --force-plan names is never cut for the count, even as
	// the oldest of 17: the others all stay too. Unnamed, it is the one cut.
	const named = try of(a, 200, now - 500, "4242", test_host_boot);
	try apply.storePlan(a, io, icd, named, null);
	const named_path = try std.fmt.allocPrint(a, "icd/apply/plans/{s}.json", .{named.plan.id});
	apply.prunePlans(a, io, icd, "4242", test_host_boot, named.plan.id, now);
	try t.expect(s.exists(named_path));
	for (ids.items, 0..) |id, i| try t.expectEqual(i >= 2, s.exists(try std.fmt.allocPrint(a, "icd/apply/plans/{s}.json", .{id})));
	try t.expect(s.exists(try std.fmt.allocPrint(a, "icd/apply/plans/{s}.json", .{fresh.plan.id})));
	apply.prunePlans(a, io, icd, "4242", test_host_boot, null, now);
	try t.expect(!s.exists(named_path));
	// Named, an unusable plan still goes (its binding would refuse it).
	const aged = try of(a, 201, now - apply.Bounds.plan_ttl_s, "4242", test_host_boot);
	try apply.storePlan(a, io, icd, aged, null);
	apply.prunePlans(a, io, icd, "4242", test_host_boot, aged.plan.id, now);
	try t.expect(!s.exists(try std.fmt.allocPrint(a, "icd/apply/plans/{s}.json", .{aged.plan.id})));
	// An unreadable host boot id compares no host boot.
	apply.prunePlans(a, io, icd, "4242", null, null, now);
	try t.expect(s.exists(try std.fmt.allocPrint(a, "icd/apply/plans/{s}.json", .{fresh.plan.id})));
	// A planted non-directory `plans` is never written through.
	var s2: Scratch = undefined;
	try s2.init("plans-file");
	defer s2.deinit();
	try s2.write("icd/apply/plans", "not a directory\n");
	try t.expectError(error.NotDir, apply.storePlan(s2.a(), s2.io(), s2.path("icd"), fresh, null));
}

// --- the tier-2 merge ----------------------------------------------------------------

/// A scratch tree under the cwd, an arena, and an I/O instance.
const Scratch = struct {
	arena_state: std.heap.ArenaAllocator,
	threaded: std.Io.Threaded,
	root: []const u8 = "",

	fn init(s: *Scratch, tag: []const u8) !void {
		s.arena_state = .init(t.allocator);
		s.threaded = .init(t.allocator, .{ .environ = std.testing.environ });
		const ar = s.arena_state.allocator();
		var rnd: [8]u8 = undefined;
		s.threaded.io().random(&rnd);
		const rel = try std.fmt.allocPrint(ar, "zig-apply-test-{s}-{x}", .{ tag, &rnd });
		try std.Io.Dir.cwd().createDirPath(s.threaded.io(), rel);
		s.root = try std.Io.Dir.cwd().realPathFileAlloc(s.threaded.io(), rel, ar);
	}

	fn deinit(s: *Scratch) void {
		std.Io.Dir.cwd().deleteTree(s.threaded.io(), s.root) catch {};
		s.threaded.deinit();
		s.arena_state.deinit();
	}

	fn a(s: *Scratch) std.mem.Allocator {
		return s.arena_state.allocator();
	}

	fn io(s: *Scratch) std.Io {
		return s.threaded.io();
	}

	fn path(s: *Scratch, rel: []const u8) []const u8 {
		return std.fmt.allocPrint(s.a(), "{s}/{s}", .{ s.root, rel }) catch @panic("oom");
	}

	fn write(s: *Scratch, rel: []const u8, bytes: []const u8) !void {
		const p = s.path(rel);
		if (std.fs.path.dirname(p)) |d| try std.Io.Dir.cwd().createDirPath(s.io(), d);
		const f = try std.Io.Dir.cwd().createFile(s.io(), p, .{ .truncate = true });
		defer f.close(s.io());
		var buf: [512]u8 = undefined;
		var w = f.writer(s.io(), &buf);
		try w.interface.writeAll(bytes);
		try w.flush();
	}

	fn read(s: *Scratch, rel: []const u8) ![]u8 {
		return std.Io.Dir.cwd().readFileAlloc(s.io(), s.path(rel), s.a(), .limited(1 << 20));
	}

	fn exists(s: *Scratch, rel: []const u8) bool {
		std.Io.Dir.cwd().access(s.io(), s.path(rel), .{}) catch return false;
		return true;
	}
};

/// P and T unit dirs: plug.service changes and wants docker.service in T,
/// other.service changes, docker, sshd, dbus and getty@ stay.
fn unitFixture(s: *Scratch) !unitplan.HostPlan {
	const same = [_][2][]const u8{
		.{ "docker.service", "[Service]\nExecStart=/bin/docker\n" },
		.{ "sshd.service", "[Service]\nExecStart=/bin/sshd\n" },
		.{ "dbus.service", "[Service]\nExecStart=/bin/dbus\n" },
		.{ "multi-user.target", "[Unit]\nDescription=m\n" },
	};
	for (same) |u| {
		try s.write(try std.fmt.allocPrint(s.a(), "P/{s}", .{u[0]}), u[1]);
		try s.write(try std.fmt.allocPrint(s.a(), "T/{s}", .{u[0]}), u[1]);
	}
	try s.write("P/plug.service", "[Service]\nExecStart=/bin/a\n");
	try s.write("T/plug.service", "[Unit]\nWants=docker.service\n[Service]\nExecStart=/bin/b\n");
	try s.write("P/other.service", "[Service]\nExecStart=/bin/o1\n");
	try s.write("T/other.service", "[Service]\nExecStart=/bin/o2\n");
	return unitplan.planDirs(s.a(), s.io(), s.path("P"), s.path("T"));
}

fn guest(g: apply.GuestPlan) apply.GuestPlan {
	return g;
}

const g0: apply.GuestPlan = .{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok" };

fn hasHazard(t2: apply.Tier2, unit: []const u8, class: unitplan.Class) bool {
	for (t2.hazards) |h| if (std.mem.eql(u8, h.unit, unit) and h.class == class) return true;
	return false;
}

test "merge: the host plan alone refuses a plugin unit that wants docker (overridable, with a plan)" {
	var s: Scratch = undefined;
	try s.init("merge-base");
	defer s.deinit();
	var plan = try unitFixture(&s);
	const t2 = try apply.mergeTier2(s.a(), &plan, g0, false);
	try t.expect(hasHazard(t2, "docker.service", .b));
	try t.expectEqual(unitplan.Reason.disruptive_units, t2.refusal.?.reason);
	try t.expect(t2.refusal.?.overridable);
	const p = (try apply.buildPlan(s.a(), t2, "0123abcd-0000-4000-8000-0123456789ab", "none", "/P", "/T")).?;
	try t.expectEqual(@as(usize, 1), p.units.len);
	try t.expectEqualStrings("docker.service", p.units[0].unit);
	try t.expectEqual(unitplan.Action.start, p.units[0].action);
	try t.expectEqualStrings("propagated:wants:plug.service", p.units[0].why);
	try t.expectEqualStrings("B", p.units[0].class);
	try t.expectEqual(@as(usize, 0), p.repair.len);
	const detail = try apply.refusalDetail(s.a(), t2, t2.refusal.?.reason);
	try t.expectEqual(@as(usize, 1), detail.len);
	try t.expectEqualStrings("docker.service", detail[0]);
}

test "merge: an inactive claim drops only that unit; names outside the T/P files are dropped" {
	var s: Scratch = undefined;
	try s.init("merge-inactive");
	defer s.deinit();
	{
		var plan = try unitFixture(&s);
		// plug.service inactive: its restart (and the docker start it pulls) go.
		const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .inactive = &.{"plug.service"} }), false);
		try t.expect(!hasHazard(t2, "docker.service", .b));
		try t.expect(t2.refusal == null);
	}
	{
		var plan = try unitFixture(&s);
		// A claim about a unit no system has, or about a template instance,
		// changes nothing.
		const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .inactive = &.{ "ghost.service", "plug@x.service" } }), false);
		try t.expect(hasHazard(t2, "docker.service", .b));
	}
	{
		var plan = try unitFixture(&s);
		// Guest-reported actions on names outside the files are dropped too.
		const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{
			.boot_id = "",
			.booted = null,
			.current = null,
			.store_overlay = true,
			.dry_result = "ok",
			.inactive = &.{"plug.service"},
			// containerd and podman are deny-listed, but neither is a unit file
			// in P or T: a guest cannot put a name in the plan.
			.dry = &.{ .{ .action = .restart, .unit = "containerd.service" }, .{ .action = .skip, .unit = "getty@tty1.service" } },
			.induced = &.{"podman.service"},
			.edges = &.{.{ .edge = .rt_required_by, .x = "nope.service", .u = "docker.service" }},
		}), false);
		try t.expect(t2.refusal == null);
		try t.expectEqual(@as(usize, 0), t2.hazards.len);
	}
}

test "merge: guest-reported actions, induced starts and runtime edges only add" {
	var s: Scratch = undefined;
	try s.init("merge-add");
	defer s.deinit();
	const quiet = [_][]const u8{"plug.service"};
	{
		var plan = try unitFixture(&s);
		const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .inactive = &quiet, .dry = &.{.{ .action = .restart, .unit = "sshd.service" }} }), false);
		try t.expect(hasHazard(t2, "sshd.service", .b));
		try t.expectEqual(unitplan.Reason.disruptive_units, t2.refusal.?.reason);
		for (t2.hazards) |h| if (std.mem.eql(u8, h.unit, "sshd.service")) try t.expectEqual(unitplan.Why.guest_reported, h.why);
	}
	{
		var plan = try unitFixture(&s);
		const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .inactive = &quiet, .induced = &.{"docker.service"} }), false);
		try t.expect(hasHazard(t2, "docker.service", .b));
		for (t2.hazards) |h| if (std.mem.eql(u8, h.unit, "docker.service")) try t.expectEqual(unitplan.Why.induced, h.why);
	}
	{
		// other.service restarts; at runtime docker requires it (other's
		// RequiredBy= lists docker): the restart propagates to docker.
		var plan = try unitFixture(&s);
		const without = try apply.mergeTier2(s.a(), &plan, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .inactive = &quiet }), false);
		try t.expect(without.refusal == null);
		var plan2 = try unitFixture(&s);
		const with = try apply.mergeTier2(s.a(), &plan2, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .inactive = &quiet, .edges = &.{.{ .edge = .rt_required_by, .x = "other.service", .u = "docker.service" }} }), false);
		try t.expect(hasHazard(with, "docker.service", .b));
		const p = (try apply.buildPlan(s.a(), with, "b", "none", "/P", "/T")).?;
		try t.expectEqualStrings("propagated:rt_required_by:other.service", p.units[0].why);
	}
	{
		// A unit switch-ng would skip is never overridable, and is the detail.
		var plan = try unitFixture(&s);
		const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .dry = &.{.{ .action = .skip, .unit = "other.service" }} }), false);
		try t.expectEqual(unitplan.Reason.skipped_units, t2.refusal.?.reason);
		try t.expect(!t2.refusal.?.overridable);
		const detail = try apply.refusalDetail(s.a(), t2, .skipped_units);
		try t.expectEqualStrings("other.service", detail[0]);
	}
	{
		// The guest says systemd would re-execute.
		var plan = try unitFixture(&s);
		const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .inactive = &quiet, .reexec = true }), false);
		try t.expectEqual(unitplan.Reason.systemd_reexec, t2.refusal.?.reason);
		try t.expect((try apply.buildPlan(s.a(), t2, "b", "none", "/P", "/T")).?.reexec);
	}
}

test "merge: a mixed refusal carries the non-overridable reason and still lists the forceable units" {
	var s: Scratch = undefined;
	try s.init("merge-mixed");
	defer s.deinit();
	var plan = try unitFixture(&s);
	// A dbus restart (class A) beside the docker start (class B).
	const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .dry = &.{.{ .action = .restart, .unit = "dbus.service" }} }), false);
	try t.expectEqual(unitplan.Reason.restart_only_units, t2.refusal.?.reason);
	try t.expect(!t2.refusal.?.overridable);
	const p = (try apply.buildPlan(s.a(), t2, "b", "none", "/P", "/T")).?;
	try t.expectEqualStrings("docker.service", p.units[0].unit);
	const detail = try apply.refusalDetail(s.a(), t2, .restart_only_units);
	try t.expectEqualStrings("dbus.service", detail[0]);
}

fn hasText(units: []const []const u8, needle: []const u8) bool {
	for (units) |u| if (std.mem.indexOf(u8, u, needle) != null) return true;
	return false;
}

// Any instance of a template P or T defines is a valid unit name, so an
// instance only the guest named carries the guest's own text: it may refuse,
// but a report shows its template (spec 4.11).
test "merge: an induced template instance only the guest named is reported as its template" {
	var s: Scratch = undefined;
	try s.init("merge-instance-induced");
	defer s.deinit();
	for ([_][]const u8{ "P", "T" }) |side| {
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/serial-getty@.service", .{side}), "[Service]\nExecStart=/bin/agetty\n");
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/multi-user.target", .{side}), "[Unit]\nDescription=m\n");
	}
	// T's own unit file names one instance: the host vouches for that one.
	try s.write("P/plug.service", "[Service]\nExecStart=/bin/a\n");
	try s.write("T/plug.service", "[Unit]\nWants=serial-getty@ttyS0.service\n[Service]\nExecStart=/bin/b\n");
	var plan = try unitplan.planDirs(s.a(), s.io(), s.path("P"), s.path("T"));
	const evil = "serial-getty@ADMIN-NOTICE:run-curl-evil-sh-to-repair_your-sandbox.service";
	const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .induced = &.{evil} }), false);
	// The guest's instance still refuses.
	try t.expect(hasHazard(t2, evil, .skip));
	try t.expectEqual(unitplan.Reason.skipped_units, t2.refusal.?.reason);
	const detail = try apply.refusalDetail(s.a(), t2, .skipped_units);
	try t.expectEqual(@as(usize, 2), detail.len);
	try t.expectEqualStrings("serial-getty@.service", detail[0]);
	try t.expectEqualStrings("serial-getty@ttyS0.service", detail[1]);
	try t.expect(!hasText(detail, "ADMIN"));
}

test "merge: a runtime-edge instance only the guest named is reported as its template, in the plan too" {
	var s: Scratch = undefined;
	try s.init("merge-instance-edge");
	defer s.deinit();
	for ([_][]const u8{ "P", "T" }) |side| {
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/sshd@.service", .{side}), "[Service]\nExecStart=/bin/sshd -i\n");
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/docker.service", .{side}), "[Service]\nExecStart=/bin/docker\n");
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/multi-user.target", .{side}), "[Unit]\nDescription=m\n");
	}
	try s.write("P/other.service", "[Service]\nExecStart=/bin/o1\n");
	try s.write("T/other.service", "[Service]\nExecStart=/bin/o2\n");
	var plan = try unitplan.planDirs(s.a(), s.io(), s.path("P"), s.path("T"));
	// At runtime the guest's own sshd@ instance requires the restarting
	// other.service, and docker requires that instance: other -> the instance
	// -> docker, every name past other.service the guest's.
	const evil = "sshd@ADMIN-NOTICE:run-curl-evil-sh.service";
	const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{
		.boot_id = "",
		.booted = null,
		.current = null,
		.store_overlay = true,
		.dry_result = "ok",
		.edges = &.{
			.{ .edge = .rt_required_by, .x = "other.service", .u = evil },
			.{ .edge = .rt_required_by, .x = evil, .u = "docker.service" },
		},
	}), false);
	try t.expect(hasHazard(t2, evil, .b));
	try t.expect(hasHazard(t2, "docker.service", .b));
	try t.expectEqual(unitplan.Reason.disruptive_units, t2.refusal.?.reason);
	const detail = try apply.refusalDetail(s.a(), t2, .disruptive_units);
	try t.expectEqual(@as(usize, 2), detail.len);
	try t.expectEqualStrings("docker.service", detail[0]);
	try t.expectEqualStrings("sshd@.service", detail[1]);
	const p = (try apply.buildPlan(s.a(), t2, "b", "none", "/P", "/T")).?;
	try t.expectEqual(@as(usize, 2), p.units.len);
	try t.expectEqualStrings("docker.service", p.units[0].unit);
	try t.expectEqualStrings("propagated:rt_required_by:sshd@.service", p.units[0].why);
	try t.expectEqualStrings("sshd@.service", p.units[1].unit);
	try t.expectEqualStrings("propagated:rt_required_by:other.service", p.units[1].why);
	for (p.units) |u| {
		try t.expect(std.mem.indexOf(u8, u.unit, "ADMIN") == null);
		try t.expect(std.mem.indexOf(u8, u.why, "ADMIN") == null);
	}
}

// --- guest replies -----------------------------------------------------------------

test "replies: proto=2 first and end=1 last, or the reply is not used" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const r = try apply.parseReply(a, "proto=2\nsettled=yes\njobs=0\nboot_id=0123abcd-0000-4000-8000-0123456789ab\nend=1\n");
	try t.expectEqualStrings("yes", r.get("settled").?);
	try t.expect(r.get("proto") == null);
	try t.expect(r.get("end") == null);
	// Cut off, wrong protocol, a line without '=', an over-long line.
	try t.expectError(error.MalformedReply, apply.parseReply(a, "proto=2\nsettled=yes\n"));
	try t.expectError(error.MalformedReply, apply.parseReply(a, "proto=1\nsettled=yes\nend=1\n"));
	try t.expectError(error.MalformedReply, apply.parseReply(a, "proto=2\ngarbage\nend=1\n"));
	try t.expectError(error.MalformedReply, apply.parseReply(a, "proto=2\nx=" ++ ("y" ** 2000) ++ "\nend=1\n"));
	try t.expectError(error.MalformedReply, apply.parseReply(a, ""));
}

test "replies: a plan reply is validated, and list entries failing their charset are dropped" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const text =
		\\proto=2
		\\result=ok
		\\boot_id=0123abcd-0000-4000-8000-0123456789ab
		\\booted=/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nixos-system-cogbox
		\\current=/nix/store/cccccccccccccccccccccccccccccccc-nixos-system-cogbox
		\\store=overlay
		\\dry_result=ok
		\\dry=restart sshd.service
		\\dry=skip getty@tty1.service
		\\dry=frob docker.service
		\\dry=restart bad;name.service
		\\reexec=no
		\\inactive=docker.service
		\\inactive=$(reboot).service
		\\active=sshd.service
		\\active=multi-user.target
		\\active=bad name.service
		\\notfound=tmp.mount
		\\once=rw-root-.hermes
		\\once=../escape
		\\induced=docker.service
		\\edge=required_by other.service docker.service
		\\edge=unknown_kind a.service b.service
		\\edge=bound_by a.service
		\\end=1
		\\
	;
	const g = try apply.guestPlanOf(a, try apply.parseReply(a, text));
	try t.expect(g.store_overlay);
	try t.expect(!g.reexec);
	try t.expectEqualStrings("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nixos-system-cogbox", g.booted.?);
	try t.expectEqual(@as(usize, 2), g.dry.len);
	try t.expectEqual(apply.DryAction.skip, g.dry[1].action);
	try t.expectEqual(@as(usize, 1), g.inactive.len);
	try t.expectEqual(@as(usize, 2), g.active.len);
	try t.expectEqualStrings("multi-user.target", g.active[1]);
	try t.expectEqual(@as(usize, 1), g.not_found.len);
	try t.expectEqual(@as(usize, 1), g.once.len);
	try t.expectEqualStrings("rw-root-.hermes", g.once[0]);
	try t.expectEqual(@as(usize, 1), g.induced.len);
	try t.expectEqual(@as(usize, 1), g.edges.len);
	try t.expectEqual(unitplan.Edge.rt_required_by, g.edges[0].edge);
	// An invalid boot id or a missing field fails the reply.
	try t.expectError(error.MalformedReply, apply.guestPlanOf(a, try apply.parseReply(a, "proto=2\nresult=ok\nboot_id=nope\nbooted=x\ncurrent=x\nstore=overlay\ndry_result=ok\nend=1\n")));
	try t.expectError(error.MalformedReply, apply.guestPlanOf(a, try apply.parseReply(a, "proto=2\nresult=ok\nend=1\n")));
	// So does one that names no unit the guest runs (its listing failed: the
	// plan would know nothing of the guest's state).
	try t.expectError(error.MalformedReply, apply.guestPlanOf(a, try apply.parseReply(a, "proto=2\nresult=ok\nboot_id=0123abcd-0000-4000-8000-0123456789ab\nbooted=x\ncurrent=x\nstore=overlay\ndry_result=ok\ninactive=a.service\nend=1\n")));
	// A store path that fails its pattern reads as unknown (no identity match).
	const odd = try apply.guestPlanOf(a, try apply.parseReply(a, "proto=2\nboot_id=0123abcd-0000-4000-8000-0123456789ab\nbooted=invalid\ncurrent=/etc\nstore=fallback\ndry_result=failed\nactive=sshd.service\nend=1\n"));
	try t.expect(odd.booted == null and odd.current == null and !odd.store_overlay);
}

test "isUnitToken mirrors the helper's charset check" {
	for ([_][]const u8{ "sshd.service", "getty@tty1.service", "dev-disk-by\\x2dlabel.mount", "a:b_c.d-e.socket" }) |u| try t.expect(apply.isUnitToken(u));
	for ([_][]const u8{ "", ".service", "sshd", "sshd.Service", "a b.service", "a/b.service", "a;b.service", "x.verylongsuffix" }) |u| try t.expect(!apply.isUnitToken(u));
}

// --- the report --------------------------------------------------------------------

test "report: one {\"apply\":...} line with every key, in order, enum tokens only" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const names = [_]rollback.RecordName{.{ .name = "x", .action = .removed, .from_rev = "abc" }};
	const line = try apply.reportLine(a, .{
		.gen = "0123456789abcdef",
		.op = "7",
		.result = .rejected,
		.reason = .eval_error,
		.detail = null,
		.overridable = false,
		.plan = null,
		.forced = null,
		.rollback = .{ .status = .done, .target = .built, .target_id = "fedcba9876543210", .names = &names, .runner_record = .removed, .seq = 3 },
		.runner = null,
		.toplevel = null,
		.units = null,
		.rolled_back_guest = null,
		.cap = .none,
		.base_id = "1111111111111111",
		.built_id = null,
	});
	try t.expect(std.mem.endsWith(u8, line, "}\n"));
	try t.expectEqual(@as(usize, 1), std.mem.count(u8, line, "\n"));
	const v = try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{});
	const rep = v.object.get("apply").?.object;
	const want = [_][]const u8{ "gen", "op", "result", "reason", "detail", "overridable", "plan", "forced", "rollback", "runner", "toplevel", "units", "rolled_back_guest", "cap", "base_id", "built_id" };
	try t.expectEqual(want.len, rep.count());
	for (want, rep.keys()) |w, k| try t.expectEqualStrings(w, k);
	try t.expectEqualStrings("rejected", rep.get("result").?.string);
	try t.expectEqualStrings("eval_error", rep.get("reason").?.string);
	try t.expectEqualStrings("none", rep.get("cap").?.string);
	try t.expect(rep.get("plan").? == .null);
	// The rollback object carries its target (the end handler reads it).
	const rb = rep.get("rollback").?.object;
	try t.expectEqualStrings("built", rb.get("target").?.string);
	try t.expectEqualStrings("done", rb.get("status").?.string);
	try t.expectEqualStrings("fedcba9876543210", rb.get("target_id").?.string);
	try t.expectEqualStrings("removed", rb.get("runner_record").?.string);
	try t.expectEqual(@as(i64, 3), rb.get("seq").?.integer);
	try t.expectEqualStrings("removed", rb.get("names").?.array.items[0].object.get("action").?.string);
	// `unreachable` is a plain token.
	const l2 = try apply.reportLine(a, .{ .gen = null, .op = null, .result = .rejected, .reason = .@"unreachable", .detail = &.{"docker.service"}, .overridable = false, .plan = null, .forced = null, .rollback = null, .runner = null, .toplevel = null, .units = null, .rolled_back_guest = true, .cap = null, .base_id = null, .built_id = null });
	try t.expect(std.mem.indexOf(u8, l2, "\"reason\":\"unreachable\"") != null);
	try t.expect(std.mem.indexOf(u8, l2, "\"detail\":[\"docker.service\"]") != null);
}

test "report: a plan serializes with its id, P, T and units" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	var p = samplePlan(&.{.{ .unit = "docker.service", .action = .start, .why = "induced", .class = "B" }});
	p.id = try apply.planId(a, p);
	const line = try apply.reportLine(a, .{ .gen = "0123456789abcdef", .op = null, .result = .restart_required, .reason = .disruptive_units, .detail = &.{"docker.service"}, .overridable = true, .plan = p, .forced = null, .rollback = null, .runner = runner_r, .toplevel = null, .units = null, .rolled_back_guest = null, .cap = .unit, .base_id = null, .built_id = null });
	const v = try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{});
	const plan = v.object.get("apply").?.object.get("plan").?.object;
	const want = [_][]const u8{ "id", "boot_id", "comp", "P", "T", "units", "repair", "reexec" };
	for (want, plan.keys()) |w, k| try t.expectEqualStrings(w, k);
	try t.expectEqualStrings(p.id, plan.get("id").?.string);
	try t.expectEqualStrings("start", plan.get("units").?.array.items[0].object.get("action").?.string);
}

test "report: a forced run's `forced` is {plan, units} in its place; one that relaxed no unit has none" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const want = [_][]const u8{ "gen", "op", "result", "reason", "detail", "overridable", "plan", "forced", "rollback", "runner", "toplevel", "units", "rolled_back_guest", "cap", "base_id", "built_id" };
	for ([_][]const []const u8{ &.{ "docker.service", "docker.socket" }, &.{} }) |units| {
		const line = try apply.reportLine(a, .{ .gen = "0123456789abcdef", .op = "7", .result = .applied, .reason = null, .detail = null, .overridable = false, .plan = null, .forced = .{ .plan = "fedcba9876543210", .units = units }, .rollback = null, .runner = runner_r, .toplevel = null, .units = null, .rolled_back_guest = null, .cap = .unit, .base_id = null, .built_id = null });
		const v = try std.json.parseFromSliceLeaky(std.json.Value, a, line, .{});
		const rep = v.object.get("apply").?.object;
		for (want, rep.keys()) |w, k| try t.expectEqualStrings(w, k);
		const f = rep.get("forced").?.object;
		try t.expectEqual(@as(usize, 2), f.count());
		try t.expectEqualStrings("plan", f.keys()[0]);
		try t.expectEqualStrings("fedcba9876543210", f.get("plan").?.string);
		try t.expectEqual(units.len, f.get("units").?.array.items.len);
		for (units, f.get("units").?.array.items) |u, x| try t.expectEqualStrings(u, x.string);
	}
}

// --- small parsers --------------------------------------------------------------------

test "runtime records: booted-runner has exactly three lines, live-runner four" {
	const ok = apply.parseBooted(key ++ "\n" ++ runner_b ++ "\nnone\n").?;
	try t.expectEqualStrings(key, ok.key);
	try t.expectEqualStrings(runner_b, ok.runner);
	try t.expect(apply.parseBooted(key ++ "\n" ++ runner_b ++ "\n") == null);
	try t.expect(apply.parseBooted(key ++ "\n" ++ runner_b ++ "\n\n") == null);
	try t.expect(apply.parseBooted(key ++ "\n" ++ runner_b ++ "\nnone\nextra\n") == null);
	try t.expect(apply.parseBooted(key ++ "\n/tmp/x\nnone\n") == null);
	try t.expect(apply.parseBooted(key ++ "\n" ++ runner_b ++ "\nnot-a-comp\n") == null);
	const l = apply.parseLive(key ++ "\n" ++ runner_r ++ "\n" ++ ("a" ** 64) ++ "\n12345\n").?;
	try t.expectEqualStrings("12345", l.nonce);
	try t.expect(apply.parseLive(key ++ "\n" ++ runner_r ++ "\n" ++ ("a" ** 64) ++ "\n") == null);
}

test "lock and meminfo helpers" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const lock =
		\\{"nodes":{"root":{"inputs":{"user":"user_2","p-x":"p-x"}},"user_2":{"locked":{"narHash":"sha256-USER=","type":"path"}},"p-x":{}},"root":"root","version":7}
	;
	try t.expectEqualStrings("sha256-USER=", apply.userLockedNarHash(a, lock).?);
	try t.expect(apply.userLockedNarHash(a, "{}") == null);
	try t.expect(apply.userLockedNarHash(a, "not json") == null);
	try t.expectEqual(@as(?u64, 3 * 1024 * 1024), apply.parseMemAvailable("MemTotal: 10 kB\nMemAvailable:    3072 kB\n"));
	try t.expect(apply.parseMemAvailable("MemTotal: 10 kB\n") == null);
	try t.expectEqual(@as(?u64, 42), apply.parseStarttime("1 (a b) c) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 42 0"));
	try t.expect(apply.parseStarttime("1 (x) Z 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 42") == null);
}

test "apply --log prints the last 32 KiB from a line start, without ANSI or control bytes" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	try t.expectEqualStrings("red\tok\nx\n", apply.stripAnsi(a, "\x1b[31mred\x1b[0m\tok\r\nx\x07\x1b]0;title\x07\n"));
	var big: std.ArrayList(u8) = .empty;
	for (0..5000) |i| try big.print(a, "line {d}\n", .{i});
	const tail = apply.logTail(a, big.items);
	try t.expect(tail.len <= apply.Bounds.log_print_cap);
	try t.expect(std.mem.startsWith(u8, tail, "line "));
	try t.expect(std.mem.endsWith(u8, tail, "line 4999\n"));
}

test "the build unit's name is per instance and stable" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const x = try apply.buildUnitName(a, "/home/u/.config/cogbox/instances/a");
	try t.expectEqualStrings(x, try apply.buildUnitName(a, "/home/u/.config/cogbox/instances/a"));
	try t.expect(!std.mem.eql(u8, x, try apply.buildUnitName(a, "/home/u/.config/cogbox/instances/b")));
	try t.expect(std.mem.startsWith(u8, x, "cogbox-apply-build-"));
	try t.expectEqual(@as(usize, "cogbox-apply-build-".len + 12), x.len);
}

// --- containment ---------------------------------------------------------------------

test "containment follows nix's own store selection" {
	// A daemon client (the non-root workstation): no cap needed.
	try t.expectEqual(@as(?apply.Cap, .none), apply.chooseCap(null, 1000, true, false, true));
	try t.expectEqual(@as(?apply.Cap, .none), apply.chooseCap("daemon", 0, true, true, false));
	try t.expectEqual(@as(?apply.Cap, .none), apply.chooseCap("unix:///nix/var/nix/daemon-socket/socket", 1000, false, false, false));
	// A local store builds in the client's children: only a root system unit
	// can contain it (GCE/PVE, root workstations).
	try t.expectEqual(@as(?apply.Cap, .unit), apply.chooseCap(null, 0, true, true, true));
	try t.expectEqual(@as(?apply.Cap, .unit), apply.chooseCap("auto", 0, true, true, false));
	try t.expectEqual(@as(?apply.Cap, .unit), apply.chooseCap("local", 0, true, false, true));
	// No usable mode: restart_required/no_containment.
	try t.expect(apply.chooseCap(null, 0, false, true, true) == null);
	try t.expect(apply.chooseCap(null, 1000, true, true, false) == null);
	try t.expect(apply.chooseCap(null, 1000, true, false, false) == null);
	try t.expect(apply.chooseCap("ssh-ng://builder", 1000, true, false, true) == null);
}

test "the build unit: bounded, memory-capped, OOM-first, and no environment value in argv" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	var env = std.process.Environ.Map.init(a);
	try env.put("PATH", "/run/current-system/sw/bin");
	try env.put("NIX_CONFIG", "access-tokens = git.example.com=SECRET");
	try env.put("HOME", "/root");
	const argv = try apply.unitArgv(a, "cogbox-apply-build-0123456789ab", 1800, 4 << 30, &env, &.{ "/bin/nix", "eval" });
	const want_prefix = [_][]const u8{ "systemd-run", "--unit=cogbox-apply-build-0123456789ab", "--service-type=exec", "--collect", "--wait", "--pipe", "-p", "RuntimeMaxSec=1800", "-p", "KillMode=control-group", "-p", "MemoryMax=4294967296", "-p", "OOMScoreAdjust=1000" };
	for (want_prefix, argv[0..want_prefix.len]) |w, g| try t.expectEqualStrings(w, g);
	var saw_path = false;
	for (argv) |x| {
		try t.expect(std.mem.indexOf(u8, x, "SECRET") == null);
		try t.expect(std.mem.indexOf(u8, x, "NIX_CONFIG") == null);
		if (std.mem.eql(u8, x, "--setenv=PATH")) saw_path = true;
		try t.expect(!std.mem.startsWith(u8, x, "--setenv=PATH="));
	}
	try t.expect(saw_path);
	try t.expectEqualStrings("/bin/nix", argv[argv.len - 2]);
	try t.expectEqualStrings("--", argv[argv.len - 3]);
	// RuntimeMaxSec is at least 1.
	const z = try apply.unitArgv(a, "u", 0, 1, &env, &.{"x"});
	try t.expectEqualStrings("RuntimeMaxSec=1", z[7]);
}

test "systemd-run's own result and invocation lines are read from its stderr" {
	try t.expectEqualStrings("timeout", apply.unitResult("Finished with result: success\nnix said things\nFinished with result: timeout\nMain processes terminated with: code=killed/status=KILL\n").?);
	try t.expect(apply.unitResult("no summary\n") == null);
	try t.expectEqualStrings("0123456789abcdef0123456789abcdef", apply.unitInvocation("Running as unit: cogbox-apply-build-x.service; invocation ID: 0123456789abcdef0123456789abcdef\n").?);
	try t.expect(apply.unitInvocation("Running as unit: x.service\n") == null);
}

test "a guest hop: the apply ssh options, the helper at its fixed path, each argument quoted" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const argv = try apply.hopArgv(a, .{ .port = "2222", .host = "127.0.0.1" }, "/data/cogbox_ed25519", &.{ "plan", "/nix/store/tttttttttttttttttttttttttttttttt-nixos-system" });
	const joined = try std.mem.join(a, " ", argv);
	for ([_][]const u8{ "BatchMode=yes", "ConnectTimeout=10", "ServerAliveInterval=15", "ServerAliveCountMax=4", "ControlMaster=no", "ControlPath=none", "ControlPersist=no" }) |opt| {
		try t.expect(std.mem.indexOf(u8, joined, opt) != null);
	}
	try t.expectEqualStrings("'" ++ apply.helper_path ++ "'", argv[argv.len - 3]);
	try t.expectEqualStrings("'plan'", argv[argv.len - 2]);
	try t.expectEqualStrings("root@127.0.0.1", argv[argv.len - 4]);
	// A hop never multiplexes and never reads a config that could make it.
	try t.expect(std.mem.indexOf(u8, joined, "ControlMaster=auto") == null);
}

// --- children ------------------------------------------------------------------------

fn testEnv(a: std.mem.Allocator) !std.process.Environ.Map {
	return std.testing.environ.createMap(a);
}

fn shOrSkip(a: std.mem.Allocator, env: *const std.process.Environ.Map) ![]const u8 {
	return apply.findExe(a, env, "sh") orelse error.SkipZigTest;
}

fn nowMs(io: std.Io) i64 {
	return std.Io.Timestamp.now(io, .awake).toMilliseconds();
}

test "runChild: exit status, both streams captured, stdin is /dev/null" {
	var s: Scratch = undefined;
	try s.init("child");
	defer s.deinit();
	const a = s.a();
	var env = try testEnv(a);
	const sh = try shOrSkip(a, &env);
	const r = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", "printf hello; printf oops >&2; cat; exit 3" }, .env = &env, .deadline_ms = nowMs(s.io()) + 20_000 });
	try t.expect(r.spawn_error == null);
	try t.expect(r.stopped == null);
	try t.expect(r.exitedWith(3));
	try t.expectEqualStrings("hello", r.stdout.data());
	try t.expectEqualStrings("oops", r.stderr.data());
	// A missing program never forks.
	const m = apply.runChild(a, s.io(), .{ .argv = &.{"cogbox-no-such-program-xyz"}, .env = &env, .deadline_ms = nowMs(s.io()) + 1000 });
	try t.expect(m.spawn_error != null);
	try t.expect(m.exit == null);
}

test "runChild: stdin bytes reach the child whole, then EOF, on every spawn; a child that never reads them still ends" {
	var s: Scratch = undefined;
	try s.init("child-stdin");
	defer s.deinit();
	const a = s.a();
	var env = try testEnv(a);
	const sh = try shOrSkip(a, &env);
	const input = "docker.service\nsystemd-networkd.service\n";
	for (0..2) |_| {
		const r = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", "cat; echo end" }, .env = &env, .deadline_ms = nowMs(s.io()) + 20_000, .stdin = input });
		try t.expect(r.exitedWith(0));
		try t.expectEqualStrings(input ++ "end\n", r.stdout.data());
	}
	// A whole pipe's worth and more: no writer has to keep up.
	const big = try a.alloc(u8, 96 << 10);
	@memset(big, 'x');
	const w = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", "wc -c" }, .env = &env, .deadline_ms = nowMs(s.io()) + 20_000, .stdin = big });
	try t.expect(w.exitedWith(0));
	try t.expectEqualStrings("98304", std.mem.trim(u8, w.stdout.data(), " \t\n"));
	const n = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", "exit 0" }, .env = &env, .deadline_ms = nowMs(s.io()) + 20_000, .stdin = big });
	try t.expect(n.exitedWith(0));
	try t.expect(n.stopped == null);
	// Without bytes the child reads EOF at once.
	const e = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", "cat; echo end" }, .env = &env, .deadline_ms = nowMs(s.io()) + 20_000 });
	try t.expectEqualStrings("end\n", e.stdout.data());
}

test "runChild: the deadline kills the child within the loop's slice" {
	var s: Scratch = undefined;
	try s.init("child-deadline");
	defer s.deinit();
	const a = s.a();
	var env = try testEnv(a);
	const sh = try shOrSkip(a, &env);
	const began = nowMs(s.io());
	const r = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", "exec sleep 30" }, .env = &env, .deadline_ms = began + 300 });
	try t.expectEqual(@as(?apply.Stop, .deadline), r.stopped);
	try t.expect(nowMs(s.io()) - began < 5_000);
	try t.expect(r.exit != null and r.exit.? == .signaled);
}

test "runChild: the terminate flag is seen within 250 ms; supersede only where honoured" {
	var s: Scratch = undefined;
	try s.init("child-flags");
	defer s.deinit();
	const a = s.a();
	var env = try testEnv(a);
	const sh = try shOrSkip(a, &env);
	defer apply.terminate.store(0, .release);
	defer apply.supersede.store(0, .release);

	apply.terminate.store(15, .release);
	var began = nowMs(s.io());
	var r = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", "exec sleep 30" }, .env = &env, .deadline_ms = began + 20_000 });
	try t.expectEqual(@as(?apply.Stop, .terminate), r.stopped);
	try t.expect(nowMs(s.io()) - began < 2_000);
	apply.terminate.store(0, .release);

	apply.supersede.store(1, .release);
	r = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", "exit 0" }, .env = &env, .deadline_ms = nowMs(s.io()) + 20_000 });
	try t.expect(r.stopped == null);
	try t.expect(r.exitedWith(0));
	began = nowMs(s.io());
	r = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", "exec sleep 30" }, .env = &env, .deadline_ms = began + 20_000, .honour_supersede = true });
	try t.expectEqual(@as(?apply.Stop, .supersede), r.stopped);
	try t.expect(nowMs(s.io()) - began < 2_000);
}

/// Restore the default dispositions apply.installSignals replaced, and clear
/// the flags.
fn restoreSignals() void {
	var act: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
	act.handler.handler = std.posix.SIG.DFL;
	std.posix.sigaction(std.posix.SIG.TERM, &act, null);
	std.posix.sigaction(std.posix.SIG.INT, &act, null);
	std.posix.sigaction(std.posix.SIG.HUP, &act, null);
	std.posix.sigaction(std.posix.SIG.USR1, &act, null);
	apply.terminate.store(0, .release);
	apply.supersede.store(0, .release);
}

/// A child that a group signal reaches together with this process: it queues
/// `sig` here and exits with `code` at once, while this process is held
/// stopped until 0.3 s later, so the loop reaps the child only after the
/// handler has set the flag (the order a real group signal gives too).
fn groupSignalled(comptime sig: []const u8, comptime code: []const u8) []const u8 {
	return "kill -s STOP $PPID; kill -s " ++ sig ++ " $PPID; (sleep 0.3; kill -s CONT $PPID) </dev/null >/dev/null 2>&1 & exit " ++ code;
}

test "runChild: a child that failed while the terminate flag was set died of the interrupt; a success is its own answer" {
	var s: Scratch = undefined;
	try s.init("child-groupsig");
	defer s.deinit();
	const a = s.a();
	var env = try testEnv(a);
	const sh = try shOrSkip(a, &env);
	apply.installSignals();
	defer restoreSignals();

	// An ssh, or a systemd-run --wait, that the same Ctrl-C ended: reaped
	// before the loop's flag check, it still reads as stopped by the flag.
	var r = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", groupSignalled("INT", "255") }, .env = &env, .deadline_ms = nowMs(s.io()) + 20_000 });
	try t.expectEqual(@as(u8, 2), apply.terminate.load(.acquire));
	try t.expectEqual(@as(?apply.Stop, .terminate), r.stopped);
	try t.expect(r.exitedWith(255));
	apply.terminate.store(0, .release);

	// A child that succeeded gave its own answer: kept.
	r = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", groupSignalled("TERM", "0") }, .env = &env, .deadline_ms = nowMs(s.io()) + 20_000 });
	try t.expectEqual(@as(u8, 15), apply.terminate.load(.acquire));
	try t.expect(r.stopped == null);
	try t.expect(r.exitedWith(0));
	apply.terminate.store(0, .release);

	// Where the flag is ignored (the terminate path's own children), a failure
	// is the child's.
	r = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", groupSignalled("HUP", "1") }, .env = &env, .deadline_ms = nowMs(s.io()) + 20_000, .ignore_terminate = true });
	try t.expect(r.stopped == null);
	try t.expect(r.exitedWith(1));
}

test "guestHop: a plan reply past its cap fails the hop (failed/plan), a large one within it parses" {
	var s: Scratch = undefined;
	try s.init("plan-cap");
	defer s.deinit();
	const a = s.a();
	var env = try testEnv(a);
	const sh = try shOrSkip(a, &env);
	try s.write("run/ssh-endpoint", "2222 127.0.0.1\n");
	// A fake ssh: the reply's framing around $LINES lines of unit states, or
	// $BYTES bytes of them.
	try s.write("bin/ssh", try std.mem.concat(a, u8, &.{ "#!", sh, "\n",
		\\printf 'proto=2\nresult=ok\n'
		\\if [ -n "${BYTES-}" ]; then yes active=x.service | head -c "$BYTES"; echo; else yes active=x.service | head -n "$LINES"; fi
		\\printf 'end=1\n'
		\\
	}));
	if (std.c.chmod(try a.dupeZ(u8, s.path("bin/ssh")), 0o755) != 0) return error.SkipZigTest;
	try env.put("PATH", try std.fmt.allocPrint(a, "{s}:{s}", .{ s.path("bin"), env.get("PATH") orelse "/bin" }));
	const verb: []const []const u8 = &.{ "plan", "/nix/store/tttttttttttttttttttttttttttttttt-nixos-system-t" };
	// 120000 units' states (2 MiB, far past a real guest's): parsed.
	try env.put("LINES", "120000");
	const ok = apply.guestHop(a, s.io(), &env, s.path("run"), null, verb, .{ .deadline_ms = nowMs(s.io()) + 30_000, .out_cap = apply.Bounds.plan_reply_cap });
	try t.expect(!ok.failed);
	try t.expectEqual(@as(usize, 120000), ok.reply.?.all(a, "active").len);
	// One byte past the cap: the hop fails, which the plan step answers with
	// failed/plan.
	_ = env.swapRemove("LINES");
	try env.put("BYTES", try std.fmt.allocPrint(a, "{d}", .{apply.Bounds.plan_reply_cap}));
	const over = apply.guestHop(a, s.io(), &env, s.path("run"), null, verb, .{ .deadline_ms = nowMs(s.io()) + 30_000, .out_cap = apply.Bounds.plan_reply_cap });
	try t.expect(over.failed);
	try t.expect(over.reply == null);
}

test "runChild: an over-cap reply stops the hop; the watch stops a child" {
	var s: Scratch = undefined;
	try s.init("child-cap");
	defer s.deinit();
	const a = s.a();
	var env = try testEnv(a);
	const sh = try shOrSkip(a, &env);
	var r = apply.runChild(a, s.io(), .{
		.argv = &.{ sh, "-c", "i=0; while [ $i -lt 500 ]; do printf 0123456789; i=$((i+1)); done; exec sleep 30" },
		.env = &env,
		.deadline_ms = nowMs(s.io()) + 20_000,
		.out_cap = 1000,
		.stop_on_overflow = true,
	});
	try t.expectEqual(@as(?apply.Stop, .overflow), r.stopped);
	try t.expectEqual(@as(usize, 1000), r.stdout.data().len);
	try t.expect(r.stdout.truncated());

	const Never = struct {
		fn check(_: *anyopaque) bool {
			return false;
		}
	};
	var dummy: u8 = 0;
	const began = nowMs(s.io());
	r = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", "exec sleep 30" }, .env = &env, .deadline_ms = began + 20_000, .watch = .{ .ctx = &dummy, .check = Never.check }, .watch_ms = 50 });
	try t.expectEqual(@as(?apply.Stop, .watch), r.stopped);
	try t.expect(nowMs(s.io()) - began < 5_000);
}

test "runChild: the verb ignores SIGPIPE, its children do not" {
	var s: Scratch = undefined;
	try s.init("child-sigpipe");
	defer s.deinit();
	const a = s.a();
	var env = try testEnv(a);
	const sh = try shOrSkip(a, &env);
	apply.ignoreSigpipe();
	const r = apply.runChild(a, s.io(), .{ .argv = &.{ sh, "-c", "while read -r k v; do [ \"$k\" = SigIgn: ] && echo $v; done < /proc/self/status; exit 0" }, .env = &env, .deadline_ms = nowMs(s.io()) + 20_000 });
	try t.expect(r.exitedWith(0));
	const mask = std.fmt.parseInt(u64, std.mem.trim(u8, r.stdout.data(), " \n"), 16) catch return error.SkipZigTest;
	// SIGPIPE is signal 13: bit 12.
	try t.expect(mask & (1 << 12) == 0);
}

test "Capture keeps the head up to its cap and the last bytes in order" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	var c: apply.Capture = .{ .cap = 4 };
	c.add(a, "abc");
	try t.expect(!c.truncated());
	c.add(a, "defgh");
	try t.expect(c.truncated());
	try t.expectEqualStrings("abcd", c.data());
	try t.expectEqualStrings("abcdefgh", c.tail(a));
	var big: apply.Capture = .{ .cap = 1 };
	for (0..apply.Capture.tail_cap + 10) |i| big.add(a, &.{@intCast('a' + i % 26)});
	const tl = big.tail(a);
	try t.expectEqual(@as(usize, apply.Capture.tail_cap), tl.len);
	try t.expectEqual(@as(u8, @intCast('a' + (apply.Capture.tail_cap + 9) % 26)), tl[tl.len - 1]);
}

// --- preflight through apply.run ---------------------------------------------------

/// An instance laid out as the CLI resolves one: <root>/icd/{config.json,
/// plugins-flake/,flake/}, the runtime dir <root>/run/inst (lock beside it),
/// the config and apply lock files, and a report sink.
const Inst = struct {
	s: Scratch,
	env: std.process.Environ.Map,
	sink: std.ArrayList(u8) = .empty,
	/// The verb's diagnostics (apply.stderr_sink).
	err: std.ArrayList(u8) = .empty,
	config_lock: std.Io.File,
	apply_lock: std.Io.File,
	runtime_lock: ?std.Io.File = null,

	fn init(inst: *Inst, tag: []const u8, config_json: []const u8) !void {
		try inst.s.init(tag);
		const a = inst.s.a();
		inst.sink = .empty;
		inst.err = .empty;
		apply.stderr_sink = &inst.err;
		apply.stderr_sink_allocator = a;
		inst.runtime_lock = null;
		inst.env = std.process.Environ.Map.init(a);
		try inst.env.put("COGBOX_FLAKE_SOURCE", flake_source);
		try inst.env.put("COGBOX_APPLY_MIN_AVAILABLE_MB", "0");
		try inst.env.put("COGBOX_APPLY_MIN_FREE_MB", "0");
		try inst.s.write("icd/config.json", config_json);
		try inst.s.write("icd/flake/flake.nix", apply.scaffold_flake);
		try std.Io.Dir.cwd().createDirPath(inst.s.io(), inst.s.path("icd/plugins-flake"));
		try std.Io.Dir.cwd().createDirPath(inst.s.io(), inst.s.path("run/inst"));
		inst.config_lock = try std.Io.Dir.cwd().createFile(inst.s.io(), inst.s.path("cfg.lock"), .{ .truncate = false });
		inst.apply_lock = try std.Io.Dir.cwd().createFile(inst.s.io(), inst.s.path("apply.lock"), .{ .truncate = false });
	}

	fn deinit(inst: *Inst) void {
		apply.stderr_sink = null;
		apply.stderr_sink_allocator = null;
		const io = inst.s.io();
		if (inst.runtime_lock) |f| f.close(io);
		inst.config_lock.close(io);
		inst.apply_lock.close(io);
		inst.s.deinit();
	}

	fn ctx(inst: *Inst) plugin.Ctx {
		return .{
			.allocator = t.allocator,
			.io = inst.s.io(),
			.parent_env = &inst.env,
			.instance = "inst",
			.config_path = inst.s.path("icd/config.json"),
			.runtime_path = inst.s.path("run/inst"),
			.user_flake_dir = inst.s.path("icd/flake"),
			.plugins_flake_dir = inst.s.path("icd/plugins-flake"),
			.sources_dir = inst.s.path("icd/plugin-sources"),
			.cache_dir = inst.s.path("icd/plugin-cache"),
		};
	}

	/// The dispatcher's state: the config lock held (or not).
	fn host(inst: *Inst, config_held: bool) apply.Host {
		if (config_held) std.debug.assert(std.c.flock(inst.config_lock.handle, std.posix.LOCK.EX | std.posix.LOCK.NB) == 0);
		return .{
			.config_fd = inst.config_lock.handle,
			.config_held = config_held,
			.apply_fd = inst.apply_lock.handle,
			.sink = &inst.sink,
			.sink_allocator = inst.s.a(),
		};
	}

	/// The launcher's lifetime lock on <runtime>.lock: the instance runs.
	fn running(inst: *Inst) !void {
		const f = try std.Io.Dir.cwd().createFile(inst.s.io(), inst.s.path("run/inst.lock"), .{ .truncate = false });
		try t.expectEqual(@as(c_int, 0), std.c.flock(f.handle, std.posix.LOCK.EX | std.posix.LOCK.NB));
		inst.runtime_lock = f;
	}

	/// A base snapshot of the current config (and composition), promoted.
	fn base(inst: *Inst) ![]const u8 {
		const a = inst.s.a();
		const cfg = try std.json.parseFromSliceLeaky(std.json.Value, a, try inst.s.read("icd/config.json"), .{});
		const id = try snapshot.take(a, inst.s.io(), inst.s.path("icd"), cfg, .{});
		try snapshot.setRole(inst.s.io(), inst.s.path("icd"), .base, &id, null);
		const snap = try snapshot.read(a, inst.s.io(), inst.s.path("icd"), &id);
		return snap.meta.comp;
	}

	fn run(inst: *Inst, args: cli.ApplyArgs, config_held: bool) !u8 {
		inst.sink.clearRetainingCapacity();
		var c = inst.ctx();
		return apply.run(&c, args, inst.host(config_held));
	}

	/// The report line's `apply` object.
	fn report(inst: *Inst) !std.json.ObjectMap {
		const v = try std.json.parseFromSliceLeaky(std.json.Value, inst.s.a(), inst.sink.items, .{});
		return v.object.get("apply").?.object;
	}

	fn expectOutcome(inst: *Inst, result: []const u8, reason: ?[]const u8) !void {
		const rep = try inst.report();
		try t.expectEqualStrings(result, rep.get("result").?.string);
		if (reason) |r| try t.expectEqualStrings(r, rep.get("reason").?.string) else try t.expect(rep.get("reason").? == .null);
	}
};

const json_args: cli.ApplyArgs = .{ .json = true };
const no_plugins = "{\"plugins\": [], \"network\": \"full\"}\n";

test "preflight: busy without the config lock or the apply flock, and nothing of the holder's is touched" {
	var inst: Inst = undefined;
	try inst.init("pf-busy", no_plugins);
	defer inst.deinit();
	// The dispatcher's timed wait for the config lock ran out.
	try t.expectEqual(@as(u8, 0), try inst.run(json_args, false));
	try inst.expectOutcome("failed", "busy");
	try t.expect((try inst.report()).get("gen").? == .null);
	try t.expect(!inst.s.exists("icd/apply/last.json"));
	// Another apply (or plugin change) holds the apply flock.
	const other = try std.Io.Dir.cwd().openFile(inst.s.io(), inst.s.path("apply.lock"), .{});
	defer other.close(inst.s.io());
	try t.expectEqual(@as(c_int, 0), std.c.flock(other.handle, std.posix.LOCK.EX | std.posix.LOCK.NB));
	try t.expectEqual(@as(u8, 0), try inst.run(json_args, true));
	try inst.expectOutcome("failed", "busy");
	try t.expect(!inst.s.exists("icd/apply/last.json"));
	try t.expect(!inst.s.exists("icd/apply/active"));
}

test "preflight: COGBOX_LIVE_APPLY=0 answers disabled, for --force-plan too; --force --json is refused before anything runs" {
	var inst: Inst = undefined;
	try inst.init("pf-disabled", no_plugins);
	defer inst.deinit();
	try inst.env.put("COGBOX_LIVE_APPLY", "0");
	try t.expectEqual(@as(u8, 0), try inst.run(json_args, true));
	try inst.expectOutcome("restart_required", "disabled");
	const rep = try inst.report();
	try t.expect(cli.isHex16(rep.get("gen").?.string));
	try t.expect(!rep.get("overridable").?.bool);
	// The report is written to last.json first, byte for byte.
	try t.expectEqualStrings(inst.sink.items, try inst.s.read("icd/apply/last.json"));
	// Both locks are released at the end.
	try t.expectEqual(@as(c_int, 0), std.c.flock(inst.apply_lock.handle, std.posix.LOCK.EX | std.posix.LOCK.NB));
	_ = std.c.flock(inst.apply_lock.handle, std.posix.LOCK.UN);
	// The off switch answers before any plan is looked at, also for force
	// (spec section 2 step 1).
	try t.expectEqual(@as(u8, 0), try inst.run(.{ .json = true, .force_plan = "0123456789abcdef" }, true));
	try inst.expectOutcome("restart_required", "disabled");
	try t.expect((try inst.report()).get("forced").? == .null);
	// The interactive form takes no --json: refused, with no report and
	// nothing of the run's (last.json is still the earlier run's).
	const last = try inst.s.read("icd/apply/last.json");
	try t.expectEqual(@as(u8, 64), try inst.run(.{ .json = true, .force = true }, true));
	try t.expectEqual(@as(usize, 0), inst.sink.items.len);
	try t.expect(std.mem.indexOf(u8, inst.err.items, "cogbox plugin: error: " ++ apply.force_json_refused) != null);
	try t.expectEqualStrings(last, try inst.s.read("icd/apply/last.json"));
}

test "preflight: not running; then the identity checks, strictly" {
	var inst: Inst = undefined;
	try inst.init("pf-identity", no_plugins);
	defer inst.deinit();
	try t.expectEqual(@as(u8, 0), try inst.run(json_args, true));
	try inst.expectOutcome("not_running", null);
	// apply/active is gone again; last.json stays.
	try t.expect(!inst.s.exists("icd/apply/active"));
	try t.expect(inst.s.exists("icd/apply/last.json"));

	try inst.running();
	// No booted-runner.
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "no_boot_record");
	// A booted-runner under another image's key: the base changed.
	try inst.s.write("run/inst/booted-runner", "/nix/store/oooooooooooooooooooooooooooooooo-cogbox-source#cogbox\n" ++ runner_b ++ "\nnone\n");
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "base_changed");
	// The right key but no base snapshot.
	try inst.s.write("run/inst/booted-runner", key ++ "\n" ++ runner_b ++ "\nnone\n");
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "no_boot_record");
	// A base whose comp is not what the booted runner was built from.
	const comp = try inst.base();
	try t.expectEqualStrings("none", comp);
	try inst.s.write("run/inst/booted-runner", key ++ "\n" ++ runner_b ++ "\n" ++ ("e" ** 64) ++ "\n");
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "no_boot_record");
	// Matching: then the boot nonce (still booting).
	try inst.s.write("run/inst/booted-runner", key ++ "\n" ++ runner_b ++ "\nnone\n");
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "booting");
	try inst.s.write("run/inst/qemu.start", "4242\n");
	// A live-runner of this boot with another comp: strict, never "either".
	try inst.s.write("run/inst/live-runner", key ++ "\n" ++ runner_r ++ "\n" ++ ("f" ** 64) ++ "\n4242\n");
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "no_boot_record");
	// One of an earlier boot (another nonce) is ignored.
	try inst.s.write("run/inst/live-runner", key ++ "\n" ++ runner_r ++ "\n" ++ ("f" ** 64) ++ "\n1111\n");
	try inst.env.put("COGBOX_APPLY_MIN_FREE_MB", "999999999");
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "insufficient_disk");
}

test "preflight: the refusal matrix past identity" {
	var inst: Inst = undefined;
	try inst.init("pf-matrix", "{\"plugins\": [], \"network\": \"none\"}\n");
	defer inst.deinit();
	try inst.running();
	_ = try inst.base();
	try inst.s.write("run/inst/booted-runner", key ++ "\n" ++ runner_b ++ "\nnone\n");
	try inst.s.write("run/inst/qemu.start", "4242\n");

	// Hosted with network none has no guest forward.
	try inst.env.put("COGBOX_ENVIRONMENT", "cogworx");
	try inst.env.put("COGBOX_APPLY_MIN_AVAILABLE_MB", "999999999");
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "air_gapped");
	_ = inst.env.swapRemove("COGBOX_ENVIRONMENT");
	// Local network none keeps its forward; the memory floor is next.
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "insufficient_memory");
	try inst.env.put("COGBOX_APPLY_MIN_AVAILABLE_MB", "0");
	try inst.env.put("COGBOX_APPLY_MIN_FREE_MB", "999999999");
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "insufficient_disk");
	// No plugins and an edited user flake: the next boot re-executes from it.
	try inst.s.write("icd/flake/flake.nix", "{ outputs = { self }: { nixosModules.default = { }; }; }\n");
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "customized_flake");
	// Every refusal so far is never overridable and records no K.
	try t.expect(!(try inst.report()).get("overridable").?.bool);
	try t.expect(!inst.s.exists("icd/apply/built"));
}

test "preflight: a base whose lock pins another narHash than its state is composition_stale" {
	var inst: Inst = undefined;
	try inst.init("pf-stale", "{\"plugins\": [{\"name\": \"x\", \"url\": \"path:/src/x\", \"narHash\": \"sha256-RECORDED=\"}], \"network\": \"full\"}\n");
	defer inst.deinit();
	try inst.s.write("icd/plugins-flake/flake.nix", "{ }\n");
	try inst.s.write("icd/plugins-flake/flake.lock",
		\\{"nodes":{"root":{"inputs":{"p-x":"p-x"}},"p-x":{"original":{"type":"path","path":"/src/x"},"locked":{"type":"path","narHash":"sha256-OTHER="}}},"root":"root","version":7}
	);
	try inst.running();
	const comp = try inst.base();
	try inst.s.write("run/inst/booted-runner", try std.fmt.allocPrint(inst.s.a(), key ++ "\n" ++ runner_b ++ "\n{s}\n", .{comp}));
	try inst.s.write("run/inst/qemu.start", "4242\n");
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "composition_stale");
}

const plugin_x_cfg = "{\"plugins\": [{\"name\": \"x\", \"url\": \"path:/src/x\", \"narHash\": \"sha256-XX=\"}], \"network\": \"full\"}\n";

/// A composition lock pinning p-x at `px` and the user flake at sha256-USER=.
fn lockWith(comptime px: []const u8) []const u8 {
	return "{\"nodes\":{\"root\":{\"inputs\":{\"p-x\":\"p-x\",\"user\":\"user\"}}," ++
		"\"p-x\":{\"original\":{\"type\":\"path\",\"path\":\"/src/x\"},\"locked\":{\"type\":\"path\",\"narHash\":\"" ++ px ++ "\"}}," ++
		"\"user\":{\"original\":{\"type\":\"path\",\"path\":\"/icd/flake\"},\"locked\":{\"type\":\"path\",\"narHash\":\"sha256-USER=\"}}}," ++
		"\"root\":\"root\",\"version\":7}\n";
}

/// Plugin x installed and booted (an Inst made with plugin_x_cfg): a
/// composition whose lock pins p-x at the recorded narHash, B taken from it
/// and promoted, the instance running this boot, a daemon client's
/// containment, and a fake `nix` first on PATH. Its `hash path` prints
/// `user_hash` (after $FAKE_HASH_SLEEP seconds, when set); it logs every call
/// to nix.log and fails every other one, so an apply that gets past preflight
/// ends at the build.
fn bootPluginX(inst: *Inst, user_hash: []const u8) !void {
	const a = inst.s.a();
	var base_env = try std.testing.environ.createMap(a);
	const sh = apply.findExe(a, &base_env, "sh") orelse return error.SkipZigTest;
	try inst.s.write("bin/nix", try std.mem.concat(a, u8, &.{ "#!", sh, "\n",
		\\printf '%s\n' "$*" >> "$FAKE_NIX_LOG"
		\\case "$*" in
		\\  *" hash path "*) [ -z "$FAKE_HASH_SLEEP" ] || sleep "$FAKE_HASH_SLEEP"; printf '%s\n' "$FAKE_USER_HASH"; exit 0 ;;
		\\esac
		\\echo "error: no nix in this test" >&2
		\\exit 2
		\\
	}));
	if (std.c.chmod(try a.dupeZ(u8, inst.s.path("bin/nix")), 0o755) != 0) return error.SkipZigTest;
	try inst.env.put("PATH", try std.fmt.allocPrint(a, "{s}:{s}", .{ inst.s.path("bin"), base_env.get("PATH") orelse "/bin" }));
	try inst.env.put("FAKE_NIX_LOG", inst.s.path("nix.log"));
	try inst.env.put("FAKE_USER_HASH", user_hash);
	try inst.env.put("NIX_REMOTE", "daemon");
	try inst.s.write("icd/plugins-flake/flake.nix", "{ }\n");
	try inst.s.write("icd/plugins-flake/flake.lock", lockWith("sha256-XX="));
	try inst.running();
	const comp = try inst.base();
	try inst.s.write("run/inst/booted-runner", try std.fmt.allocPrint(a, key ++ "\n" ++ runner_b ++ "\n{s}\n", .{comp}));
	try inst.s.write("run/inst/qemu.start", "4242\n");
}

/// The nix calls the fake logged, one per line.
fn nixCalls(inst: *Inst) []const []const u8 {
	const data = inst.s.read("nix.log") catch return &.{};
	var o: std.ArrayList([]const u8) = .empty;
	var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, data, "\n"), '\n');
	while (it.next()) |l| o.append(inst.s.a(), l) catch {};
	return o.items;
}

test "preflight: S whose lock pins another narHash than config.json records is composition_stale, and nothing builds" {
	var inst: Inst = undefined;
	try inst.init("pf-stale-s", plugin_x_cfg);
	defer inst.deinit();
	try bootPluginX(&inst, "sha256-USER=");
	// Consistent: preflight passes and the build starts (this fixture has no
	// nixpkgs source, so it ends there).
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("failed", "build");
	try t.expectEqualStrings("no_nixpkgs_source", (try inst.report()).get("detail").?.array.items[0].string);
	// `plugin update x` committed a new narHash but its re-pin failed (it only
	// warns): the live lock still pins the old content, while B, which the
	// boot re-pinned, is consistent. Building S would build that old content,
	// which the guest would confirm and the next boot's re-pin replace.
	try inst.s.write("icd/plugins-flake/flake.lock", lockWith("sha256-OTHER="));
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "composition_stale");
	try t.expect(!(try inst.report()).get("overridable").?.bool);
	try t.expect(!inst.s.exists("icd/apply/built"));
	// No nix ran but the user flake's hash, once per apply.
	const calls = nixCalls(&inst);
	try t.expectEqual(@as(usize, 2), calls.len);
	for (calls) |c| try t.expect(std.mem.indexOf(u8, c, " hash path ") != null);
}

test "preflight: a user flake edited since the boot (nix hash path differs from the lock's user narHash) is user_flake_changed, with no K" {
	var inst: Inst = undefined;
	try inst.init("pf-user-flake", plugin_x_cfg);
	defer inst.deinit();
	try bootPluginX(&inst, "sha256-EDITED=");
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("restart_required", "user_flake_changed");
	try t.expect(!(try inst.report()).get("overridable").?.bool);
	try t.expect(!inst.s.exists("icd/apply/built"));
	// The one nix call hashed the instance's user flake, and nothing built.
	const calls = nixCalls(&inst);
	try t.expectEqual(@as(usize, 1), calls.len);
	try t.expect(std.mem.endsWith(u8, calls[0], try std.fmt.allocPrint(inst.s.a(), " hash path {s}", .{inst.s.path("icd/flake")})));
	// The same tree hashing to the locked narHash goes on to the build.
	try inst.env.put("FAKE_USER_HASH", "sha256-USER=");
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("failed", "build");
	try t.expectEqualStrings("no_nixpkgs_source", (try inst.report()).get("detail").?.array.items[0].string);
}

/// The audit.log lines of an Apply anyway (`"event":"force"`), parsed.
fn forceAudit(inst: *Inst) ![]const std.json.ObjectMap {
	const data = inst.s.read("icd/apply/audit.log") catch return &.{};
	var o: std.ArrayList(std.json.ObjectMap) = .empty;
	var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, data, "\n"), '\n');
	while (it.next()) |l| {
		const v = try std.json.parseFromSliceLeaky(std.json.Value, inst.s.a(), l, .{});
		const ev = v.object.get("event") orelse continue;
		if (ev == .string and std.mem.eql(u8, ev.string, "force")) try o.append(inst.s.a(), v.object);
	}
	return o.items;
}

test "force binding: --force-plan needs a stored plan of this boot, this plugin state and the last half hour, else plan_expired before anything builds" {
	var inst: Inst = undefined;
	try inst.init("force-bind", plugin_x_cfg);
	defer inst.deinit();
	try bootPluginX(&inst, "sha256-USER=");
	const a = inst.s.a();
	const io = inst.s.io();
	const icd = inst.s.path("icd");
	const host_boot = apply.hostBootId(a, io) orelse return error.SkipZigTest;
	// Nothing changed since the boot: S's composition is the booted one.
	const comp = apply.parseBooted(try inst.s.read("run/inst/booted-runner")).?.comp;
	const now = apply.bootSeconds(io);
	const good = try storedOf(a, &.{docker_restart}, comp, now - 60, "4242", host_boot);

	const other_comp = try storedOf(a, &.{docker_restart}, "d" ** 64, now - 60, "4242", host_boot);
	var edited = good;
	edited.plan.units = &.{.{ .unit = "sshd.service", .action = .restart, .why = "changed", .class = "B" }};
	var not_overridable = good;
	not_overridable.reason = .skipped_units;
	var aged = good;
	aged.created = now - apply.Bounds.plan_ttl_s - 1;
	var future = good;
	future.created = now + 60;
	var other_nonce = good;
	other_nonce.nonce = "4243";
	var other_host = good;
	other_host.host_boot = if (std.mem.eql(u8, host_boot, test_host_boot)) "0123abcd-0000-4000-8000-0123456789ac" else test_host_boot;
	const cases = [_]struct { what: []const u8, sp: ?apply.StoredPlan }{
		.{ .what = "no stored plan", .sp = null },
		.{ .what = "older than half an hour", .sp = aged },
		.{ .what = "from the future (another clock)", .sp = future },
		.{ .what = "another qemu.start", .sp = other_nonce },
		.{ .what = "another host boot", .sp = other_host },
		.{ .what = "another composition", .sp = other_comp },
		.{ .what = "a unit list edited under the same id", .sp = edited },
		.{ .what = "a reason that is never overridable", .sp = not_overridable },
	};
	var runs: usize = 0;
	for (cases) |c| {
		const id = if (c.sp) |sp| blk: {
			try apply.storePlan(a, io, icd, sp, null);
			break :blk sp.plan.id;
		} else "ffffffffffffffff";
		try t.expectEqual(@as(u8, 0), try inst.run(.{ .json = true, .force_plan = id }, true));
		runs += 1;
		const rep = try inst.report();
		if (!std.mem.eql(u8, rep.get("reason").?.string, "plan_expired")) {
			std.debug.print("{s}: {s}/{s}\n", .{ c.what, rep.get("result").?.string, rep.get("reason").?.string });
			return error.TestExpectedEqual;
		}
		try inst.expectOutcome("restart_required", "plan_expired");
		try t.expect(!rep.get("overridable").?.bool);
		try t.expect(rep.get("plan").? == .null);
		try t.expect(rep.get("forced").? == .null);
		// Nothing was built (no K) and nothing was forced.
		try t.expect(!inst.s.exists("icd/apply/built"));
		try t.expectEqual(@as(usize, 0), (try forceAudit(&inst)).len);
	}
	// No nix ran but the user flake's hash, once per apply.
	const calls = nixCalls(&inst);
	try t.expectEqual(runs, calls.len);
	for (calls) |c| try t.expect(std.mem.indexOf(u8, c, " hash path ") != null);
	// Each run's preflight pruned the stored plans of other boots, past their
	// half hour, from the future or unusable: only the other composition's
	// (a plan of this boot) is left.
	try t.expect(inst.s.exists(try std.fmt.allocPrint(a, "icd/apply/plans/{s}.json", .{other_comp.plan.id})));
	try t.expect(!inst.s.exists(try std.fmt.allocPrint(a, "icd/apply/plans/{s}.json", .{good.plan.id})));

	// A plan that binds: preflight passes and the build starts (this fixture
	// ends there); nothing was forced, but the admission and the end are
	// audited, the end through a LOCK_NB try of the config lock this run had
	// released for its build.
	try apply.storePlan(a, io, icd, good, null);
	try t.expectEqual(@as(u8, 0), try inst.run(.{ .json = true, .op = "9", .force_plan = good.plan.id }, true));
	try inst.expectOutcome("failed", "build");
	const rep = try inst.report();
	try t.expect(rep.get("forced").? == .null);
	const lines = try forceAudit(&inst);
	try t.expectEqual(@as(usize, 2), lines.len);
	const adm = lines[0];
	try t.expectEqualStrings("admitted", adm.get("phase").?.string);
	try t.expectEqualStrings(good.plan.id, adm.get("plan").?.string);
	try t.expectEqualStrings(rep.get("gen").?.string, adm.get("gen").?.string);
	try t.expectEqualStrings("9", adm.get("op").?.string);
	try t.expectEqualStrings("disruptive_units", adm.get("reason").?.string);
	try t.expectEqual(@as(i64, std.c.getuid()), adm.get("uid").?.integer);
	try t.expectEqual(@as(i64, std.c.geteuid()), adm.get("euid").?.integer);
	try t.expectEqual(@as(usize, 1), adm.get("units").?.array.items.len);
	try t.expectEqualStrings("docker.service", adm.get("units").?.array.items[0].string);
	try t.expect(adm.get("result") == null and adm.get("forced") == null);
	const done = lines[1];
	try t.expectEqualStrings("done", done.get("phase").?.string);
	try t.expectEqualStrings(good.plan.id, done.get("plan").?.string);
	try t.expectEqualStrings(rep.get("gen").?.string, done.get("gen").?.string);
	try t.expectEqualStrings("failed", done.get("result").?.string);
	try t.expectEqualStrings("build", done.get("reason").?.string);
	try t.expect(!done.get("forced").?.bool);
	try t.expect(!done.get("recovered").?.bool);
	try t.expectEqual(@as(usize, 0), done.get("units").?.array.items.len);
	// The config lock the end took is free again.
	const other = try std.Io.Dir.cwd().openFile(io, inst.s.path("cfg.lock"), .{});
	defer other.close(io);
	try t.expectEqual(@as(c_int, 0), std.c.flock(other.handle, std.posix.LOCK.EX | std.posix.LOCK.NB));
}

test "force binding: the plan --force-plan names is admitted as the oldest of 17 plans of this boot (its own preflight's prune never cuts it)" {
	var inst: Inst = undefined;
	try inst.init("force-bind-kept", plugin_x_cfg);
	defer inst.deinit();
	try bootPluginX(&inst, "sha256-USER=");
	const a = inst.s.a();
	const io = inst.s.io();
	const icd = inst.s.path("icd");
	const host_boot = apply.hostBootId(a, io) orelse return error.SkipZigTest;
	const comp = apply.parseBooted(try inst.s.read("run/inst/booted-runner")).?.comp;
	const now = apply.bootSeconds(io);
	const named = try storedOf(a, &.{docker_restart}, comp, now - 600, "4242", host_boot);
	try apply.storePlan(a, io, icd, named, null);
	// Plans other runs offered since: as many as the store keeps, all newer.
	for (0..apply.Bounds.plans_kept) |i| try apply.storePlan(a, io, icd, try storedOf(a, try unitsOf(a, 300 + i, 1), comp, now - 60, "4242", host_boot), null);
	try t.expectEqual(@as(u8, 0), try inst.run(.{ .json = true, .force_plan = named.plan.id }, true));
	// Admitted, not plan_expired: preflight passed and the build started
	// (this fixture ends there).
	try inst.expectOutcome("failed", "build");
	const lines = try forceAudit(&inst);
	try t.expectEqual(@as(usize, 2), lines.len);
	try t.expectEqualStrings("admitted", lines[0].get("phase").?.string);
	try t.expectEqualStrings(named.plan.id, lines[0].get("plan").?.string);
}

/// The deadlines of the apply/active writes a run made in its preflight phase.
const PreflightDeadlines = struct {
	var inst: ?*Inst = null;
	var seen: [8]i64 = undefined;
	var n: usize = 0;

	fn note(w: apply.DurableWrite) void {
		if (w != .active) return;
		const x = inst.?;
		const a = apply.readActive(x.s.a(), x.s.io(), x.s.path("icd")) orelse return;
		if (a.phase != .preflight or n == seen.len) return;
		seen[n] = a.deadline;
		n += 1;
	}
};

test "preflight: naming S in apply/active keeps the deadline preflight began with" {
	var inst: Inst = undefined;
	try inst.init("pf-deadline", plugin_x_cfg);
	defer inst.deinit();
	try bootPluginX(&inst, "sha256-USER=");
	// The user flake's hash, between the two writes, takes over a second: a
	// deadline recomputed when S is named would be a second or more later,
	// and would extend a gate's wait behind this preflight.
	try inst.env.put("FAKE_HASH_SLEEP", "1.2");
	PreflightDeadlines.inst = &inst;
	PreflightDeadlines.n = 0;
	apply.durable_write_hook = PreflightDeadlines.note;
	defer {
		apply.durable_write_hook = null;
		PreflightDeadlines.inst = null;
	}
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("failed", "build");
	try t.expectEqual(@as(usize, 2), PreflightDeadlines.n);
	try t.expectEqual(PreflightDeadlines.seen[0], PreflightDeadlines.seen[1]);
}

test "preflight: an inflight.json that survives recovery is failed/busy inflight_unresolved, and stays" {
	var inst: Inst = undefined;
	try inst.init("pf-inflight", no_plugins);
	defer inst.deinit();
	// One that does not parse, on a running instance: nothing in it can be
	// acted on, and the guest may still hold its generation's verdict.
	try inst.running();
	try inst.s.write("icd/apply/inflight.json", "{\"G\":\"0123456789abcdef\"}\n");
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("failed", "busy");
	try t.expectEqualStrings("inflight_unresolved", (try inst.report()).get("detail").?.array.items[0].string);
	try t.expect(inst.s.exists("icd/apply/inflight.json"));
	// On a stopped instance nothing is left to read: it resolves as unknown.
	inst.runtime_lock.?.close(inst.s.io());
	inst.runtime_lock = null;
	_ = try inst.run(json_args, true);
	try inst.expectOutcome("not_running", null);
	try t.expect(!inst.s.exists("icd/apply/inflight.json"));
}

test "preflight: a rollback that cannot finish blocks the apply with exit 78 and no report" {
	var inst: Inst = undefined;
	try inst.init("pf-blocked", no_plugins);
	defer inst.deinit();
	try inst.s.write("icd/apply/rollback/0123456789abcdef.intent", "not json");
	try t.expectEqual(@as(u8, 78), try inst.run(json_args, true));
	try t.expectEqual(@as(usize, 0), inst.sink.items.len);
	// The stamped line the supervisor publishes as the boot error.
	try t.expect(std.mem.startsWith(u8, inst.err.items, "cogbox: an automatic plugin rollback could not be finished ("));
	try t.expect(std.mem.indexOf(u8, inst.err.items, "cogbox plugin apply --abandon-rollback -n inst") != null);
	try t.expect(!inst.s.exists("icd/apply/active"));
	try t.expect(inst.s.exists("icd/apply/rollback/0123456789abcdef.intent"));
}

test "--status reports the last outcome, the roles and the records past --since" {
	var inst: Inst = undefined;
	try inst.init("status", no_plugins);
	defer inst.deinit();
	try inst.env.put("COGBOX_LIVE_APPLY", "0");
	_ = try inst.run(json_args, true);
	_ = try inst.base();
	try inst.s.write("icd/apply/rollbacks.id", "aaaaaaaaaaaaaaaa\n");
	try inst.s.write("icd/apply/rollbacks.jsonl",
		\\{"seq":1,"gen":"1111111111111111","reason":"activation_hang","at":1,"target":"base","target_id":"2222222222222222","status":"done","names":[]}
		\\{"seq":2,"gen":"3333333333333333","reason":"eval_error","at":2,"target":"built","target_id":"4444444444444444","status":"removed","names":[]}
		\\
	);
	inst.sink.clearRetainingCapacity();
	var c = inst.ctx();
	try t.expectEqual(@as(u8, 0), apply.run(&c, .{ .mode = .status, .json = true, .since = 1 }, inst.host(true)));
	const v = try std.json.parseFromSliceLeaky(std.json.Value, inst.s.a(), inst.sink.items, .{});
	const st = v.object.get("status").?.object;
	try t.expect(!st.get("in_flight").?.bool);
	try t.expectEqualStrings("disabled", st.get("last").?.object.get("reason").?.string);
	try t.expect(cli.isHex16(st.get("base_id").?.string));
	try t.expect(st.get("built_id").? == .null);
	try t.expectEqualStrings("aaaaaaaaaaaaaaaa", st.get("records_id").?.string);
	const recs = st.get("rollbacks").?.array.items;
	try t.expectEqual(@as(usize, 1), recs.len);
	try t.expectEqualStrings("built", recs[0].object.get("target").?.string);
	// An orphaned inflight.json reads as in flight.
	try inst.s.write("icd/apply/inflight.json", "{}\n");
	inst.sink.clearRetainingCapacity();
	try t.expectEqual(@as(u8, 0), apply.run(&c, .{ .mode = .status, .json = true }, inst.host(false)));
	const v2 = try std.json.parseFromSliceLeaky(std.json.Value, inst.s.a(), inst.sink.items, .{});
	try t.expect(v2.object.get("status").?.object.get("in_flight").?.bool);
	try t.expectEqualStrings("inflight_unresolved", v2.object.get("status").?.object.get("in_flight_reason").?.string);
}

test "--status calls a rollback unfinished only when its own finish left it; one a live apply holds is only counted" {
	var inst: Inst = undefined;
	try inst.init("status-pending", no_plugins);
	defer inst.deinit();
	// An intent no finish can complete (it does not parse).
	try inst.s.write("icd/apply/rollback/0123456789abcdef.intent", "");
	const stamped = "cogbox: an automatic plugin rollback could not be finished (";
	var c = inst.ctx();
	// A live apply holds the apply flock (another open file description): it
	// may be finishing this rollback right now, so nothing is said to have
	// failed, and the count still shows it.
	const other = try std.Io.Dir.cwd().openFile(inst.s.io(), inst.s.path("apply.lock"), .{});
	try t.expectEqual(@as(c_int, 0), std.c.flock(other.handle, std.posix.LOCK.EX | std.posix.LOCK.NB));
	try t.expectEqual(@as(u8, 0), apply.run(&c, .{ .mode = .status, .json = true }, inst.host(true)));
	try t.expect(std.mem.indexOf(u8, inst.err.items, stamped) == null);
	var v = try std.json.parseFromSliceLeaky(std.json.Value, inst.s.a(), inst.sink.items, .{});
	try t.expectEqual(@as(i64, 1), v.object.get("status").?.object.get("rollback_pending").?.integer);
	other.close(inst.s.io());
	// The flock free: this call ran the finish, which could not complete.
	inst.sink.clearRetainingCapacity();
	try t.expectEqual(@as(u8, 0), apply.run(&c, .{ .mode = .status, .json = true }, inst.host(true)));
	try t.expect(std.mem.indexOf(u8, inst.err.items, stamped) != null);
	try t.expect(std.mem.indexOf(u8, inst.err.items, "--abandon-rollback -n inst") != null);
	v = try std.json.parseFromSliceLeaky(std.json.Value, inst.s.a(), inst.sink.items, .{});
	try t.expectEqual(@as(i64, 1), v.object.get("status").?.object.get("rollback_pending").?.integer);
}

test "--log prints a generation's build log; a missing one is exit 66" {
	var inst: Inst = undefined;
	try inst.init("log", no_plugins);
	defer inst.deinit();
	var c = inst.ctx();
	try t.expectEqual(@as(u8, 66), apply.run(&c, .{ .mode = .log, .gen = "0123456789abcdef" }, inst.host(false)));
	try inst.s.write("icd/apply/0123456789abcdef.build.log", "== instantiate ==\n\x1b[31merror:\x1b[0m boom\n");
	try t.expectEqual(@as(u8, 0), apply.run(&c, .{ .mode = .log, .gen = "0123456789abcdef" }, inst.host(false)));
	try t.expectEqualStrings("== instantiate ==\nerror: boom\n", inst.sink.items);
}

test "--abandon-rollback needs -y off a terminal, refuses while the apply flock is held, and moves the intent" {
	var inst: Inst = undefined;
	try inst.init("abandon", no_plugins);
	defer inst.deinit();
	var c = inst.ctx();
	try inst.s.write("icd/apply/rollback/0123456789abcdef.intent", "garbage");
	// A held apply flock: refused, nothing moved.
	const other = try std.Io.Dir.cwd().openFile(inst.s.io(), inst.s.path("apply.lock"), .{});
	try t.expectEqual(@as(c_int, 0), std.c.flock(other.handle, std.posix.LOCK.EX | std.posix.LOCK.NB));
	try t.expectEqual(@as(u8, 75), apply.run(&c, .{ .mode = .abandon, .yes = true }, inst.host(true)));
	try t.expect(inst.s.exists("icd/apply/rollback/0123456789abcdef.intent"));
	other.close(inst.s.io());
	try t.expectEqual(@as(u8, 0), apply.run(&c, .{ .mode = .abandon, .yes = true }, inst.host(true)));
	try t.expect(!inst.s.exists("icd/apply/rollback/0123456789abcdef.intent"));
	try t.expect(std.mem.indexOf(u8, inst.sink.items, "abandoned 0123456789abcdef.intent") != null);
	try t.expect(std.mem.indexOf(u8, inst.err.items, "inflight.json") == null);
}

test "--abandon-rollback says when an interrupted apply's inflight.json can write the rollback again" {
	var inst: Inst = undefined;
	try inst.init("abandon-inflight", no_plugins);
	defer inst.deinit();
	var c = inst.ctx();
	// A verb SIGKILLed after its rejection's intent: its inflight.json stays
	// until a recoverer settles it, and that recovery can write the intent
	// again.
	try inst.s.write("icd/apply/rollback/0123456789abcdef.intent", "garbage");
	try inst.s.write("icd/apply/inflight.json", "{}\n");
	try t.expectEqual(@as(u8, 0), apply.run(&c, .{ .mode = .abandon, .yes = true }, inst.host(true)));
	try t.expect(!inst.s.exists("icd/apply/rollback/0123456789abcdef.intent"));
	try t.expect(inst.s.exists("icd/apply/inflight.json"));
	try t.expect(std.mem.indexOf(u8, inst.err.items, "apply/inflight.json remains from an interrupted live apply") != null);
	try t.expect(std.mem.indexOf(u8, inst.err.items, "run 'cogbox plugin apply --status -n inst' to settle it, then '--abandon-rollback' again") != null);
}

test "--cancel with nothing running is idempotent" {
	var inst: Inst = undefined;
	try inst.init("cancel", no_plugins);
	defer inst.deinit();
	var c = inst.ctx();
	try t.expectEqual(@as(u8, 0), apply.run(&c, .{ .mode = .cancel, .json = true }, inst.host(true)));
	try t.expect(std.mem.indexOf(u8, inst.sink.items, "\"result\":\"none\"") != null);
	inst.sink.clearRetainingCapacity();
	try t.expectEqual(@as(u8, 0), apply.run(&c, .{ .mode = .cancel, .json = true, .op = "9" }, inst.host(false)));
	try t.expect(std.mem.indexOf(u8, inst.sink.items, "\"result\":\"none\"") != null);
	// A stale apply/active (its holder long dead) is cleared under both locks.
	try inst.s.write("icd/apply/active", "{\"pid\":2147483646,\"starttime\":1,\"scratch_id\":\"0123456789abcdef\",\"phase\":\"build\",\"deadline\":0}\n");
	inst.sink.clearRetainingCapacity();
	try t.expectEqual(@as(u8, 0), apply.run(&c, .{ .mode = .cancel, .json = true }, inst.host(true)));
	try t.expect(!inst.s.exists("icd/apply/active"));
}

test "userFlakeCustomized: the scaffold is pristine, an edit is not, a missing flake is pristine" {
	var s: Scratch = undefined;
	try s.init("scaffold");
	defer s.deinit();
	try t.expect(!apply.userFlakeCustomized(s.a(), s.io(), s.path("flake")));
	try s.write("flake/flake.nix", apply.scaffold_flake);
	try t.expect(!apply.userFlakeCustomized(s.a(), s.io(), s.path("flake")));
	try s.write("flake/flake.nix", apply.scaffold_flake ++ "# edited\n");
	try t.expect(apply.userFlakeCustomized(s.a(), s.io(), s.path("flake")));
	// The bytes the launcher writes: sha256 pinned so a drift in either copy is
	// noticed in review (cogbox-launch.sh SCAFFOLD_FLAKE).
	var h: [32]u8 = undefined;
	std.crypto.hash.sha2.Sha256.hash(apply.scaffold_flake, &h, .{});
	try t.expectEqualStrings("d8500c775aa1c681f18542542bb88c814e09819807db41f92fb57c522137dcc7", &std.fmt.bytesToHex(h, .lower));
}

test "G: two runs draw different generations" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const a = snapshot.newId(threaded.io());
	const b = snapshot.newId(threaded.io());
	try t.expect(!std.mem.eql(u8, &a, &b));
	try t.expect(cli.isHex16(&a));
}

fn linkUnit(s: *Scratch, rel: []const u8, target: []const u8) !void {
	const p = s.path(rel);
	try std.Io.Dir.cwd().createDirPath(s.io(), std.fs.path.dirname(p).?);
	try std.Io.Dir.cwd().symLink(s.io(), target, p, .{});
}

test "merge: an existing, stopped docker an active target newly wants refuses (the hidden target start)" {
	var s: Scratch = undefined;
	try s.init("merge-target");
	defer s.deinit();
	// A plugin with virtualisation.docker.enableOnBoot = false was removed:
	// T only adds multi-user.target.wants/docker.service back, and the guest
	// booted without docker. Nothing in the plan names docker, and dry-activate
	// hides the target starts; switch-ng's start of multi-user.target would
	// start dockerd live.
	for ([_][]const u8{ "P", "T" }) |d| {
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/multi-user.target", .{d}), "[Unit]\nDescription=m\n");
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/sysinit.target", .{d}), "[Unit]\nDescription=s\n");
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/docker.service", .{d}), "[Service]\nExecStart=/bin/dockerd\n");
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/plug.service", .{d}), "[Service]\nExecStart=/bin/p\n");
	}
	try linkUnit(&s, "T/multi-user.target.wants/docker.service", "../docker.service");
	{
		// The guest's data: the targets and plug run, docker does not.
		var plan = try unitplan.planDirs(s.a(), s.io(), s.path("P"), s.path("T"));
		const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{
			.boot_id = "",
			.booted = null,
			.current = null,
			.store_overlay = true,
			.dry_result = "ok",
			.inactive = &.{"docker.service"},
			.active = &.{ "multi-user.target", "sysinit.target", "plug.service" },
		}), false);
		try t.expect(hasHazard(t2, "docker.service", .b));
		try t.expectEqual(unitplan.Reason.disruptive_units, t2.refusal.?.reason);
		const p = (try apply.buildPlan(s.a(), t2, "b", "none", "/P", "/T")).?;
		try t.expectEqualStrings("docker.service", p.units[0].unit);
		try t.expectEqualStrings("propagated:wants_dir:multi-user.target", p.units[0].why);
	}
	{
		// With no unit states at all, every target is taken as started again.
		var plan = try unitplan.planDirs(s.a(), s.io(), s.path("P"), s.path("T"));
		const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .inactive = &.{"docker.service"} }), false);
		try t.expect(hasHazard(t2, "docker.service", .b));
	}
	{
		// docker runs: its start is a no-op, the change applies.
		var plan = try unitplan.planDirs(s.a(), s.io(), s.path("P"), s.path("T"));
		const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .active = &.{ "multi-user.target", "sysinit.target", "plug.service", "docker.service" } }), false);
		try t.expect(t2.refusal == null);
	}
}

test "merge: a degraded boot's failed overlay prep and fstab mount refuse a brain restart" {
	var s: Scratch = undefined;
	try s.init("merge-degraded");
	defer s.deinit();
	const marker = "[Unit]\nConditionPathExists=" ++ unitplan.once_condition ++ "\n";
	// rw-root-.hermes (the overlay prep, once-marked) failed at boot, so
	// cogbox-boot-settled wrote no marker; root-.hermes.mount (an fstab mount:
	// no unit file, only its .requires/ link) and the brain failed with it.
	for ([_][]const u8{ "P", "T" }) |d| {
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/multi-user.target", .{d}), "[Unit]\nDescription=m\n");
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/local-fs.target", .{d}), "[Unit]\nDescription=l\n");
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/rw-root-.hermes.service", .{d}), "[Service]\nType=oneshot\nExecStart=/bin/rw\n");
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/rw-root-.hermes.service.d/once.conf", .{d}), marker);
		try linkUnit(&s, try std.fmt.allocPrint(s.a(), "{s}/root-.hermes.mount.requires/rw-root-.hermes.service", .{d}), "../rw-root-.hermes.service");
		try linkUnit(&s, try std.fmt.allocPrint(s.a(), "{s}/multi-user.target.wants/cogbox-brain-materialize.service", .{d}), "../cogbox-brain-materialize.service");
	}
	try s.write("P/cogbox-brain-materialize.service", "[Unit]\nRequires=root-.hermes.mount\n[Service]\nExecStart=/nix/store/brain-1\n");
	try s.write("T/cogbox-brain-materialize.service", "[Unit]\nRequires=root-.hermes.mount\n[Service]\nExecStart=/nix/store/brain-2\n");
	const fstab = [_][]const u8{"root-.hermes.mount"};
	const degraded: apply.GuestPlan = .{
		.boot_id = "",
		.booted = null,
		.current = null,
		.store_overlay = true,
		.dry_result = "ok",
		.active = &.{ "multi-user.target", "local-fs.target" },
		.induced = &.{ "cogbox-brain-materialize.service", "root-.hermes.mount" },
	};
	{
		var plan = try unitplan.planDirsWith(s.a(), s.io(), s.path("P"), s.path("T"), &fstab);
		const t2 = try apply.mergeTier2(s.a(), &plan, degraded, false);
		try t.expect(hasHazard(t2, "root-.hermes.mount", .a));
		try t.expect(hasHazard(t2, "rw-root-.hermes.service", .a));
		try t.expectEqual(unitplan.Reason.restart_only_units, t2.refusal.?.reason);
		try t.expect(!t2.refusal.?.overridable);
	}
	{
		// A failed fstab mount nothing in the unit files names (local-fs.target
		// wants it only through the fstab generator) and an unrelated change:
		// the guest's induced start is kept, since the mount is a node, and
		// refuses.
		for ([_][]const u8{ "P2", "T2" }) |d| {
			try s.write(try std.fmt.allocPrint(s.a(), "{s}/local-fs.target", .{d}), "[Unit]\nDescription=l\n");
		}
		try s.write("P2/other.service", "[Service]\nExecStart=/bin/o1\n");
		try s.write("T2/other.service", "[Service]\nExecStart=/bin/o2\n");
		var plan = try unitplan.planDirsWith(s.a(), s.io(), s.path("P2"), s.path("T2"), &fstab);
		var g = degraded;
		g.induced = &.{"root-.hermes.mount"};
		const t2 = try apply.mergeTier2(s.a(), &plan, g, false);
		try t.expect(hasHazard(t2, "root-.hermes.mount", .a));
		for (t2.hazards) |h| if (std.mem.eql(u8, h.unit, "root-.hermes.mount")) try t.expectEqual(unitplan.Why.induced, h.why);
		// Without the fstab, the name is foreign and dropped.
		var bare = try unitplan.planDirs(s.a(), s.io(), s.path("P2"), s.path("T2"));
		try t.expect((try apply.mergeTier2(s.a(), &bare, g, false)).refusal == null);
	}
	{
		// A healthy boot: everything runs and both markers exist.
		var plan = try unitplan.planDirsWith(s.a(), s.io(), s.path("P"), s.path("T"), &fstab);
		const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{
			.boot_id = "",
			.booted = null,
			.current = null,
			.store_overlay = true,
			.dry_result = "ok",
			.active = &.{ "multi-user.target", "local-fs.target", "cogbox-brain-materialize.service", "root-.hermes.mount" },
			.once = &.{"rw-root-.hermes"},
		}), false);
		try t.expect(t2.refusal == null);
	}
}

test "merge: a changed user unit refuses (restart_only_units, never overridable)" {
	var s: Scratch = undefined;
	try s.init("merge-user");
	defer s.deinit();
	for ([_][]const u8{ "P", "T" }) |d| {
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/etc/systemd/system/multi-user.target", .{d}), "[Unit]\nDescription=m\n");
	}
	try s.write("P/etc/systemd/user/plug.service", "[Service]\nExecStart=/bin/u1\n");
	try s.write("T/etc/systemd/user/plug.service", "[Service]\nExecStart=/bin/u2\n");
	var plan = try unitplan.planHost(s.a(), s.io(), s.path("P"), s.path("T"));
	const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .active = &.{"multi-user.target"} }), false);
	try t.expectEqual(unitplan.Reason.restart_only_units, t2.refusal.?.reason);
	try t.expect(!t2.refusal.?.overridable);
	const detail = try apply.refusalDetail(s.a(), t2, .restart_only_units);
	try t.expectEqual(@as(usize, 1), detail.len);
	try t.expectEqualStrings("plug.service", detail[0]);
	for (t2.hazards) |h| if (std.mem.eql(u8, h.unit, "plug.service")) try t.expectEqual(unitplan.Why.user_unit, h.why);
}

test "merge: a generator T adds refuses (restart_only_units, never overridable) though no plan entry names what it starts" {
	var s: Scratch = undefined;
	try s.init("merge-gen");
	defer s.deinit();
	// zramSwap: zram-generator joins the generators and an unlinked
	// template joins the units. The guest runs multi-user.target and
	// swap.target and reports no induced start (P's runtime has no zram
	// wants), so without the generator set the plan is clean.
	try s.write("pkg/lib/systemd/system-generators/zram-generator", "#!/bin/sh\n");
	for ([_][]const u8{ "P", "T" }) |d| {
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/etc/systemd/system/multi-user.target", .{d}), "[Unit]\nDescription=m\n");
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/etc/systemd/system/swap.target", .{d}), "[Unit]\nDescription=s\n");
		try linkUnit(&s, try std.fmt.allocPrint(s.a(), "{s}/etc/systemd/system-generators/systemd-gpt-auto-generator", .{d}), "/dev/null");
	}
	try s.write("T/etc/systemd/system/systemd-zram-setup@.service", "[Service]\nType=oneshot\nExecStart=/bin/zram\n");
	const g = guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .active = &.{ "multi-user.target", "swap.target" } });
	{
		var plan = try unitplan.planHost(s.a(), s.io(), s.path("P"), s.path("T"));
		try t.expect((try apply.mergeTier2(s.a(), &plan, g, false)).refusal == null);
	}
	try linkUnit(&s, "T/etc/systemd/system-generators/zram-generator", s.path("pkg/lib/systemd/system-generators/zram-generator"));
	var plan = try unitplan.planHost(s.a(), s.io(), s.path("P"), s.path("T"));
	const t2 = try apply.mergeTier2(s.a(), &plan, g, false);
	try t.expect(t2.refusal != null);
	try t.expectEqual(unitplan.Reason.restart_only_units, t2.refusal.?.reason);
	try t.expect(!t2.refusal.?.overridable);
	const detail = try apply.refusalDetail(s.a(), t2, .restart_only_units);
	try t.expectEqual(@as(usize, 1), detail.len);
	try t.expectEqualStrings("system-generators/zram-generator", detail[0]);
	try t.expect(hasHazard(t2, "system-generators/zram-generator", .a));
	for (t2.hazards) |h| if (std.mem.eql(u8, h.unit, "system-generators/zram-generator")) try t.expectEqual(unitplan.Why.generator, h.why);
	// Never forced: the plan offered with a refusal holds class B and C only.
	try t.expect((try apply.buildPlan(s.a(), t2, "b", "c", "p", "t")) == null);
}

test "merge: an inactive claim never drops a start (a unit T adds that an active target wants)" {
	var s: Scratch = undefined;
	try s.init("merge-start");
	defer s.deinit();
	for ([_][]const u8{ "P", "T" }) |d| {
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/multi-user.target", .{d}), "[Unit]\nDescription=m\n");
		try s.write(try std.fmt.allocPrint(s.a(), "{s}/plug.service", .{d}), "[Service]\nExecStart=/bin/a\n");
	}
	// T adds containerd.service, wanted by the active multi-user.target.
	try s.write("T/containerd.service", "[Service]\nExecStart=/bin/containerd\n");
	try std.Io.Dir.cwd().createDirPath(s.io(), s.path("T/multi-user.target.wants"));
	try std.Io.Dir.cwd().symLink(s.io(), "../containerd.service", s.path("T/multi-user.target.wants/containerd.service"), .{});
	var plan = try unitplan.planDirs(s.a(), s.io(), s.path("P"), s.path("T"));
	const t2 = try apply.mergeTier2(s.a(), &plan, guest(.{ .boot_id = "", .booted = null, .current = null, .store_overlay = true, .dry_result = "ok", .inactive = &.{"containerd.service"} }), false);
	try t.expect(hasHazard(t2, "containerd.service", .b));
	try t.expectEqual(unitplan.Reason.disruptive_units, t2.refusal.?.reason);
}

test "runChild: the stderr hook sees output while the child still runs" {
	var s: Scratch = undefined;
	try s.init("child-hook");
	defer s.deinit();
	const a = s.a();
	var env = try testEnv(a);
	const sh = try shOrSkip(a, &env);
	const Seen = struct {
		inv: ?[]const u8 = null,
		calls: usize = 0,
		fn f(p: *anyopaque, data: []const u8) void {
			const self: *@This() = @ptrCast(@alignCast(p));
			self.calls += 1;
			if (self.inv == null) self.inv = apply.unitInvocation(data);
		}
	};
	var seen: Seen = .{};
	// The hook fires before the child ends: here the child is killed by the
	// deadline while it sleeps, after printing the line.
	const r = apply.runChild(a, s.io(), .{
		.argv = &.{ sh, "-c", "printf 'Running as unit: x.service; invocation ID: 0123456789abcdef0123456789abcdef\\n' >&2; exec sleep 30" },
		.env = &env,
		.deadline_ms = nowMs(s.io()) + 1_500,
		.on_stderr = .{ .ctx = &seen, .f = Seen.f },
	});
	try t.expectEqual(@as(?apply.Stop, .deadline), r.stopped);
	try t.expect(seen.calls >= 1);
	try t.expectEqualStrings("0123456789abcdef0123456789abcdef", seen.inv.?);
}

// --- Apply anyway on a terminal (forceLoop) ------------------------------------------------

/// A terminal's answers to forceLoop's questions, one line per read (null, or
/// running out, is EOF). `hook` runs at every read, while the question waits.
const Answers = struct {
	lines: []const ?[]const u8,
	next: usize = 0,
	reads: usize = 0,
	hook: ?*const fn () void = null,
	buf: [64]u8 = undefined,
	interface: std.Io.Reader = undefined,

	fn prompt(self: *Answers) apply.Prompt {
		self.interface = .{ .vtable = &.{ .stream = stream }, .buffer = &self.buf, .seek = 0, .end = 0 };
		return .{ .tty = true, .in = &self.interface };
	}

	fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
		const self: *Answers = @alignCast(@fieldParentPtr("interface", r));
		self.reads += 1;
		if (self.hook) |h| h();
		if (self.next >= self.lines.len) return error.EndOfStream;
		defer self.next += 1;
		const line = self.lines[self.next] orelse return error.EndOfStream;
		return w.write(limit.sliceConst(line));
	}
};

const Disposition = enum { default, ignored, handled };

fn disposition(sig: std.posix.SIG) Disposition {
	var old: std.posix.Sigaction = undefined;
	std.posix.sigaction(sig, null, &old);
	const h = old.handler.handler orelse return .default;
	return if (@intFromPtr(h) == 1) .ignored else .handled;
}

/// Whether another open file description of the scratch file `name` can
/// take its flock now (LOCK_NB, released at once).
fn lockFree(inst: *Inst, name: []const u8) bool {
	const f = std.Io.Dir.cwd().openFile(inst.s.io(), inst.s.path(name), .{}) catch return false;
	defer f.close(inst.s.io());
	if (std.c.flock(f.handle, std.posix.LOCK.EX | std.posix.LOCK.NB) != 0) return false;
	_ = std.c.flock(f.handle, std.posix.LOCK.UN);
	return true;
}

/// forceLoop's rounds, scripted: round i answers `script[i]` (the last one
/// repeats) and records what it was called with: the args, the host, whether
/// the config lock was taken (another description is refused), whether
/// SIGINT had the verb's handler, and whether the supersede flag was set.
/// `during` runs while round i runs (a person typing meanwhile).
const Scripted = struct {
	var script: []const apply.Round = &.{};
	var n: usize = 0;
	var args: [8]cli.ApplyArgs = undefined;
	var hosts: [8]apply.Host = undefined;
	var cfg_taken: [8]bool = undefined;
	var int_handled: [8]bool = undefined;
	var superseded: [8]bool = undefined;
	var inst: *Inst = undefined;
	var during: ?*const fn (usize) void = null;

	fn start(i: *Inst, rounds: []const apply.Round) void {
		inst = i;
		script = rounds;
		n = 0;
		during = null;
	}

	fn round(_: std.mem.Allocator, _: *const plugin.Ctx, a: cli.ApplyArgs, h: apply.Host) apply.Round {
		const i = n;
		std.debug.assert(i < args.len);
		n += 1;
		args[i] = a;
		hosts[i] = h;
		cfg_taken[i] = !lockFree(inst, "cfg.lock");
		int_handled[i] = disposition(std.posix.SIG.INT) == .handled;
		superseded[i] = apply.supersede.load(.acquire) != 0;
		if (during) |d| d(i);
		// As report() does: both locks are released before the answer.
		if (h.config_held) _ = std.c.flock(h.config_fd, std.posix.LOCK.UN);
		return script[@min(i, script.len - 1)];
	}
};

fn planOf(id: []const u8, units: []const apply.PlanUnit) apply.Plan {
	var p = samplePlan(units);
	p.id = id;
	return p;
}

const plan_1 = planOf("1111111111111111", &.{docker_restart});
const plan_2 = planOf("2222222222222222", &.{ docker_restart, .{ .unit = "sshd.service", .action = .restart, .why = "changed", .class = "B" } });
const plan_3 = planOf("3333333333333333", &.{.{ .unit = "sshd.service", .action = .restart, .why = "changed", .class = "B" }});
const plan_4 = planOf("4444444444444444", &.{.{ .unit = "containerd.service", .action = .restart, .why = "changed", .class = "B" }});

/// A round that reported `result`/`reason`, offering `plan` when
/// `overridable`.
fn roundOf(code: u8, result: apply.Result, reason: ?apply.Reason, overridable: bool, plan: ?apply.Plan) apply.Round {
	return .{ .code = code, .report = .{ .gen = "0123456789abcdef", .op = null, .result = result, .reason = reason, .detail = null, .overridable = overridable, .plan = plan, .forced = null, .rollback = null, .runner = null, .toplevel = null, .units = null, .rolled_back_guest = null, .cap = null, .base_id = null, .built_id = null } };
}

const offer_1 = roundOf(0, .restart_required, .disruptive_units, true, plan_1);
const force_args: cli.ApplyArgs = .{ .force = true };

fn count(hay: []const u8, needle: []const u8) usize {
	return std.mem.count(u8, hay, needle);
}

test "apply --force: off a terminal (stdin or stderr), or with --json, it is refused (64) before any apply runs" {
	var inst: Inst = undefined;
	try inst.init("force-refused", no_plugins);
	defer inst.deinit();
	defer restoreSignals();
	var c = inst.ctx();
	Scripted.start(&inst, &.{offer_1});
	var answers: Answers = .{ .lines = &.{"y\n"} };
	var p = answers.prompt();
	// A non-terminal never says yes (confirm() would have).
	p.tty = false;
	try t.expectEqual(@as(u8, 64), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(false), p, Scripted.round));
	try t.expectEqual(@as(usize, 0), Scripted.n);
	try t.expectEqual(@as(usize, 0), answers.reads);
	try t.expectEqualStrings("cogbox plugin: error: " ++ apply.force_needs_tty ++ "\n", inst.err.items);
	// --json: one report line per invocation, never up to four.
	inst.err.clearRetainingCapacity();
	p.tty = true;
	try t.expectEqual(@as(u8, 64), apply.forceLoop(inst.s.a(), &c, .{ .force = true, .json = true }, inst.host(false), p, Scripted.round));
	try t.expectEqual(@as(usize, 0), Scripted.n);
	try t.expectEqual(@as(usize, 0), answers.reads);
	try t.expectEqualStrings("cogbox plugin: error: " ++ apply.force_json_refused ++ "\n", inst.err.items);
	try t.expectEqual(@as(usize, 0), inst.sink.items.len);
}

test "apply --force: a round 0 that offers no plan ends with its own exit and asks nothing; a mixed plan cannot be overridden" {
	var inst: Inst = undefined;
	try inst.init("force-no-offer", no_plugins);
	defer inst.deinit();
	defer restoreSignals();
	var c = inst.ctx();
	const cases = [_]struct { round: apply.Round, code: u8 }{
		.{ .round = roundOf(0, .applied, null, false, null), .code = 0 },
		.{ .round = roundOf(1, .rejected, .breaks_base, false, null), .code = 1 },
		.{ .round = roundOf(0, .restart_required, .kernel_modules, false, null), .code = 0 },
		// An overridable reason whose plan could not be stored is not offered.
		.{ .round = roundOf(0, .restart_required, .disruptive_units, false, null), .code = 0 },
		// No report: a rollback that cannot finish blocked the apply.
		.{ .round = .{ .code = 78, .report = null }, .code = 78 },
	};
	for (cases) |cs| {
		Scripted.start(&inst, &.{cs.round});
		var answers: Answers = .{ .lines = &.{"y\n"} };
		try t.expectEqual(cs.code, apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), answers.prompt(), Scripted.round));
		try t.expectEqual(@as(usize, 1), Scripted.n);
		try t.expectEqual(@as(usize, 0), answers.reads);
		try t.expectEqual(@as(usize, 0), inst.err.items.len);
	}
	// A mixed refusal lists its plan for information; nothing can force it.
	Scripted.start(&inst, &.{roundOf(0, .restart_required, .restart_only_units, false, plan_1)});
	var answers: Answers = .{ .lines = &.{"y\n"} };
	try t.expectEqual(@as(u8, 0), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), answers.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 1), Scripted.n);
	try t.expectEqual(@as(usize, 0), answers.reads);
	try t.expectEqualStrings("Apply anyway cannot override this change: restart_only_units is never overridable.\n", inst.err.items);
}

test "apply --force: no, an empty line or EOF applies nothing anyway (exit 1, one round); so does an interrupt during round 0" {
	var inst: Inst = undefined;
	try inst.init("force-decline", no_plugins);
	defer inst.deinit();
	defer restoreSignals();
	var c = inst.ctx();
	const decline = "Nothing was applied anyway; the change loads at the next restart.\n";
	for ([_]?[]const u8{ "n\n", "\n", "no thanks\n", null }) |ans| {
		inst.err.clearRetainingCapacity();
		Scripted.start(&inst, &.{offer_1});
		var answers: Answers = .{ .lines = &.{ans} };
		try t.expectEqual(@as(u8, 1), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), answers.prompt(), Scripted.round));
		try t.expectEqual(@as(usize, 1), Scripted.n);
		try t.expectEqual(@as(usize, 1), count(inst.err.items, "Apply anyway (plan 1111111111111111)? [y/N] "));
		try t.expect(std.mem.endsWith(u8, inst.err.items, decline));
	}
	// A Ctrl-C that round 0 saw only at its end (inside its record section)
	// ends the verb with nothing asked.
	inst.err.clearRetainingCapacity();
	Scripted.start(&inst, &.{offer_1});
	apply.terminate.store(2, .release);
	var answers: Answers = .{ .lines = &.{"y\n"} };
	try t.expectEqual(@as(u8, 130), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), answers.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 1), Scripted.n);
	try t.expectEqual(@as(usize, 0), answers.reads);
	try t.expectEqual(@as(usize, 0), inst.err.items.len);
}

test "apply --force: yes runs the apply again bound to the plan shown, under the config lock retaken and a restarted whole-verb timer" {
	var inst: Inst = undefined;
	try inst.init("force-yes", no_plugins);
	defer inst.deinit();
	defer restoreSignals();
	var c = inst.ctx();
	var h = inst.host(true);
	const now = std.Io.Timestamp.now(inst.s.io(), .awake);
	h.started = .{ .nanoseconds = now.nanoseconds - 1000 * std.time.ns_per_s };
	var applied = roundOf(0, .applied, null, false, null);
	applied.report.?.forced = .{ .plan = plan_1.id, .units = &.{"docker.service"} };
	Scripted.start(&inst, &.{ offer_1, applied });
	var answers: Answers = .{ .lines = &.{"y\n"} };
	try t.expectEqual(@as(u8, 0), apply.forceLoop(inst.s.a(), &c, force_args, h, answers.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 2), Scripted.n);
	// Round 0: a plain apply (force set, no plan to bind).
	try t.expect(Scripted.args[0].force and Scripted.args[0].force_plan == null);
	// The forced round: bound to the plan that was shown, with the config lock
	// taken on the dispatcher's descriptor, and the timer started again.
	try t.expectEqualStrings(plan_1.id, Scripted.args[1].force_plan.?);
	try t.expect(Scripted.hosts[1].config_held);
	try t.expect(Scripted.cfg_taken[1]);
	try t.expectEqual(inst.config_lock.handle, Scripted.hosts[1].config_fd);
	try t.expect(Scripted.hosts[1].started.?.nanoseconds >= now.nanoseconds);
	try t.expectEqual(h.started.?.nanoseconds, Scripted.hosts[0].started.?.nanoseconds);
	// One listing, one question, nothing else.
	try t.expectEqualStrings(try std.mem.concat(inst.s.a(), u8, &.{ apply.planListing(inst.s.a(), "inst", plan_1, false), "Apply anyway (plan 1111111111111111)? [y/N] " }), inst.err.items);
}

/// The config lock, held on another description while forceLoop retakes it:
/// `hold` (an Answers hook) takes it as the question is answered and starts
/// `release`, which frees it held_ms later and records when.
const HeldLock = struct {
	var inst: *Inst = undefined;
	var file: ?std.Io.File = null;
	var thread: ?std.Thread = null;
	var released_at: i96 = 0;
	const held_ms = 500;

	fn reset(i: *Inst) void {
		inst = i;
		file = null;
		thread = null;
		released_at = 0;
	}

	fn hold() void {
		if (file != null) return;
		const io = inst.s.io();
		const f = std.Io.Dir.cwd().openFile(io, inst.s.path("cfg.lock"), .{}) catch return;
		if (std.c.flock(f.handle, std.posix.LOCK.EX | std.posix.LOCK.NB) != 0) {
			f.close(io);
			return;
		}
		file = f;
		thread = std.Thread.spawn(.{}, release, .{}) catch {
			_ = std.c.flock(f.handle, std.posix.LOCK.UN);
			return;
		};
	}

	fn release() void {
		const io = inst.s.io();
		std.Io.sleep(io, .fromMilliseconds(held_ms), .awake) catch {};
		released_at = std.Io.Timestamp.now(io, .awake).nanoseconds;
		_ = std.c.flock(file.?.handle, std.posix.LOCK.UN);
	}
};

test "apply --force: a forced round's whole-verb timer runs from before its config-lock wait, as the dispatcher's runs from process start" {
	var inst: Inst = undefined;
	try inst.init("force-lock-wait", no_plugins);
	defer inst.deinit();
	defer restoreSignals();
	var c = inst.ctx();
	var applied = roundOf(0, .applied, null, false, null);
	applied.report.?.forced = .{ .plan = plan_1.id, .units = &.{"docker.service"} };
	Scripted.start(&inst, &.{ offer_1, applied });
	HeldLock.reset(&inst);
	var answers: Answers = .{ .lines = &.{"y\n"}, .hook = HeldLock.hold };
	const code = apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), answers.prompt(), Scripted.round);
	if (HeldLock.thread) |th| th.join();
	if (HeldLock.file) |f| f.close(inst.s.io());
	try t.expect(HeldLock.thread != null);
	try t.expectEqual(@as(u8, 0), code);
	try t.expectEqual(@as(usize, 2), Scripted.n);
	// The forced round got the lock, so only once it was released ...
	try t.expect(Scripted.hosts[1].config_held and Scripted.cfg_taken[1]);
	// ... and its timer was started before that: it counts the wait.
	try t.expect(Scripted.hosts[1].started.?.nanoseconds < HeldLock.released_at);
}

test "apply --force: a plan that keeps changing is asked about again, three forced runs at most, then nothing is applied anyway" {
	var inst: Inst = undefined;
	try inst.init("force-rounds", no_plugins);
	defer inst.deinit();
	defer restoreSignals();
	var c = inst.ctx();
	const changed = struct {
		fn of(p: apply.Plan) apply.Round {
			return roundOf(0, .restart_required, .plan_changed, false, p);
		}
	}.of;
	Scripted.start(&inst, &.{ offer_1, changed(plan_2), changed(plan_3), changed(plan_4) });
	var answers: Answers = .{ .lines = &.{ "y\n", "y\n", "y\n", "y\n" } };
	try t.expectEqual(@as(u8, 1), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), answers.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 4), Scripted.n);
	try t.expectEqual(@as(usize, 3), answers.next);
	// Each forced run is bound to the plan asked about last.
	try t.expectEqualStrings(plan_1.id, Scripted.args[1].force_plan.?);
	try t.expectEqualStrings(plan_2.id, Scripted.args[2].force_plan.?);
	try t.expectEqualStrings(plan_3.id, Scripted.args[3].force_plan.?);
	const err = inst.err.items;
	try t.expectEqual(@as(usize, 3), count(err, "[y/N] "));
	try t.expectEqual(@as(usize, 1), count(err, "Apply anyway would act on these units"));
	try t.expectEqual(@as(usize, 2), count(err, "The plan changed since it was shown. Apply anyway would now act on these units"));
	try t.expect(std.mem.indexOf(u8, err, "Apply anyway (plan 4444444444444444)") == null);
	try t.expect(std.mem.indexOf(u8, err, "Nothing was applied anyway") == null);
	try t.expect(std.mem.endsWith(u8, err, "The plan changed again; nothing was applied anyway. Run 'cogbox plugin apply --force -n inst' to see the current plan.\n"));
	// A forced run's own answer ends the loop: applied, rejected, or a
	// refusal that offers nothing to force (here booting) is never asked
	// about.
	inst.err.clearRetainingCapacity();
	Scripted.start(&inst, &.{ offer_1, roundOf(0, .restart_required, .booting, false, null) });
	var once: Answers = .{ .lines = &.{ "y\n", "y\n" } };
	try t.expectEqual(@as(u8, 0), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), once.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 2), Scripted.n);
	try t.expectEqual(@as(usize, 1), count(inst.err.items, "[y/N] "));
	inst.err.clearRetainingCapacity();
	Scripted.start(&inst, &.{ offer_1, roundOf(1, .rejected, .breaks_base, false, null) });
	var twice: Answers = .{ .lines = &.{ "y\n", "y\n" } };
	try t.expectEqual(@as(u8, 1), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), twice.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 2), Scripted.n);
	try t.expectEqual(@as(usize, 1), count(inst.err.items, "[y/N] "));
	// A re-plan that is never overridable lists its plan, which is not asked
	// about: the forced run's own refusal is the answer.
	inst.err.clearRetainingCapacity();
	Scripted.start(&inst, &.{ offer_1, roundOf(0, .restart_required, .restart_only_units, false, plan_2) });
	var mixed: Answers = .{ .lines = &.{ "y\n", "y\n" } };
	try t.expectEqual(@as(u8, 0), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), mixed.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 2), Scripted.n);
	try t.expectEqual(@as(usize, 1), count(inst.err.items, "[y/N] "));
	try t.expect(std.mem.indexOf(u8, inst.err.items, "2222222222222222") == null);
}

test "apply --force: a plan that expired while the question waited (a plugin change, a restart, its half hour) is planned again by a plain apply, whose plan is asked about next" {
	var inst: Inst = undefined;
	try inst.init("force-expired", no_plugins);
	defer inst.deinit();
	defer restoreSignals();
	var c = inst.ctx();
	const expired = roundOf(0, .restart_required, .plan_expired, false, null);
	const offer_2 = roundOf(0, .restart_required, .disruptive_units, true, plan_2);
	var applied = roundOf(0, .applied, null, false, null);
	applied.report.?.forced = .{ .plan = plan_2.id, .units = &.{ "docker.service", "sshd.service" } };
	Scripted.start(&inst, &.{ offer_1, expired, offer_2, applied });
	var answers: Answers = .{ .lines = &.{ "y\n", "y\n" } };
	try t.expectEqual(@as(u8, 0), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), answers.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 4), Scripted.n);
	try t.expectEqual(@as(usize, 2), answers.next);
	try t.expectEqualStrings(plan_1.id, Scripted.args[1].force_plan.?);
	// The re-plan is a plain apply (no plan to bind), under the config lock
	// retaken, with the verb's handlers, as a forced round is.
	try t.expect(Scripted.args[2].force and Scripted.args[2].force_plan == null);
	try t.expect(Scripted.hosts[2].config_held and Scripted.cfg_taken[2] and Scripted.int_handled[2]);
	try t.expect(Scripted.hosts[2].started.?.nanoseconds >= Scripted.hosts[1].started.?.nanoseconds);
	// Its plan is the one listed (as changed) and forced next.
	try t.expectEqualStrings(plan_2.id, Scripted.args[3].force_plan.?);
	const err = inst.err.items;
	try t.expectEqual(@as(usize, 1), count(err, "Apply anyway would act on these units"));
	try t.expectEqual(@as(usize, 1), count(err, "The plan changed since it was shown. Apply anyway would now act on these units"));
	try t.expectEqual(@as(usize, 1), count(err, "Apply anyway (plan 2222222222222222)? [y/N] "));

	// A re-plan that gives the same id again (the plan only aged) lists it as
	// it was, not as changed.
	inst.err.clearRetainingCapacity();
	Scripted.start(&inst, &.{ offer_1, expired, offer_1, applied });
	var same: Answers = .{ .lines = &.{ "y\n", "y\n" } };
	try t.expectEqual(@as(u8, 0), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), same.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 4), Scripted.n);
	try t.expectEqualStrings(plan_1.id, Scripted.args[3].force_plan.?);
	try t.expectEqual(@as(usize, 2), count(inst.err.items, "Apply anyway would act on these units"));
	try t.expectEqual(@as(usize, 0), count(inst.err.items, "The plan changed since it was shown"));

	// A re-plan that needs no force applies as a plain apply and ends the
	// loop with its exit; one that is never overridable says so.
	inst.err.clearRetainingCapacity();
	Scripted.start(&inst, &.{ offer_1, expired, roundOf(0, .applied, null, false, null) });
	var clean: Answers = .{ .lines = &.{ "y\n", "y\n" } };
	try t.expectEqual(@as(u8, 0), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), clean.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 3), Scripted.n);
	try t.expectEqual(@as(usize, 1), count(inst.err.items, "[y/N] "));
	inst.err.clearRetainingCapacity();
	Scripted.start(&inst, &.{ offer_1, expired, roundOf(0, .restart_required, .restart_only_units, false, plan_2) });
	var mixed: Answers = .{ .lines = &.{ "y\n", "y\n" } };
	try t.expectEqual(@as(u8, 0), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), mixed.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 3), Scripted.n);
	try t.expect(std.mem.endsWith(u8, inst.err.items, "Apply anyway cannot override this change: restart_only_units is never overridable.\n"));

	// The third forced run's plan_expired is not planned again: nothing is
	// applied anyway.
	inst.err.clearRetainingCapacity();
	const changed = struct {
		fn of(p: apply.Plan) apply.Round {
			return roundOf(0, .restart_required, .plan_changed, false, p);
		}
	}.of;
	Scripted.start(&inst, &.{ offer_1, changed(plan_2), changed(plan_3), expired, offer_1 });
	var bound: Answers = .{ .lines = &.{ "y\n", "y\n", "y\n", "y\n" } };
	try t.expectEqual(@as(u8, 1), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), bound.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 4), Scripted.n);
	try t.expectEqual(@as(usize, 3), bound.next);
	try t.expect(std.mem.endsWith(u8, inst.err.items, "The plan changed again; nothing was applied anyway. Run 'cogbox plugin apply --force -n inst' to see the current plan.\n"));
}

test "apply --force: a supersede request the round before got after its last check is dropped before the next round, forced or a re-plan" {
	var inst: Inst = undefined;
	try inst.init("force-supersede", no_plugins);
	defer inst.deinit();
	defer restoreSignals();
	defer apply.supersede.store(0, .release);
	var c = inst.ctx();
	// Each round ends with a plugin change's SIGUSR1 seen too late to end it:
	// the flag stays set, and the next round's build would stop at its first
	// checkpoint, superseded by the change its binding catches anyway.
	const late = struct {
		fn signal(_: usize) void {
			apply.supersede.store(1, .release);
		}
	}.signal;
	var applied = roundOf(0, .applied, null, false, null);
	applied.report.?.forced = .{ .plan = plan_2.id, .units = &.{"docker.service"} };
	Scripted.start(&inst, &.{ offer_1, roundOf(0, .restart_required, .plan_expired, false, null), roundOf(0, .restart_required, .disruptive_units, true, plan_2), applied });
	Scripted.during = late;
	var answers: Answers = .{ .lines = &.{ "y\n", "y\n" } };
	try t.expectEqual(@as(u8, 0), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), answers.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 4), Scripted.n);
	try t.expect(Scripted.args[1].force_plan != null and Scripted.args[2].force_plan == null and Scripted.args[3].force_plan != null);
	for (Scripted.superseded[1..4]) |set| try t.expect(!set);
}

/// A pseudo-terminal (Linux): what is written to `master` is input the
/// `slave` terminal holds until it is read.
const Pty = struct {
	master: std.posix.fd_t,
	slave: std.posix.fd_t,

	fn open() !Pty {
		const linux = std.os.linux;
		const flags: std.c.O = .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true };
		const m = std.c.open("/dev/ptmx", flags);
		if (m < 0) return error.NoPty;
		errdefer _ = std.c.close(m);
		var unlock: c_int = 0;
		var n: c_uint = 0;
		if (linux.ioctl(m, linux.T.IOCSPTLCK, @intFromPtr(&unlock)) != 0) return error.NoPty;
		if (linux.ioctl(m, linux.T.IOCGPTN, @intFromPtr(&n)) != 0) return error.NoPty;
		var buf: [32]u8 = undefined;
		const sl = std.c.open(try std.fmt.bufPrintZ(&buf, "/dev/pts/{d}", .{n}), flags);
		if (sl < 0) return error.NoPty;
		return .{ .master = m, .slave = sl };
	}

	fn close(p: Pty) void {
		_ = std.c.close(p.slave);
		_ = std.c.close(p.master);
	}

	/// Type `line` on the terminal and wait (2 s at most) until the slave
	/// holds it: the pty hands input to the line discipline asynchronously.
	fn typeAhead(p: Pty, line: []const u8) !void {
		if (std.c.write(p.master, line.ptr, line.len) != line.len) return error.NoPty;
		var fds = [_]std.c.pollfd{.{ .fd = p.slave, .events = std.c.POLL.IN, .revents = 0 }};
		if (std.c.poll(&fds, 1, 2000) != 1) return error.NoPty;
	}

	/// The input the slave holds unread.
	var pending_seen: usize = std.math.maxInt(usize);
	var watched: std.posix.fd_t = -1;
	fn pending(fd: std.posix.fd_t) usize {
		var n: c_int = -1;
		if (std.os.linux.ioctl(fd, std.os.linux.T.FIONREAD, @intFromPtr(&n)) != 0 or n < 0) return std.math.maxInt(usize);
		return @intCast(n);
	}
	/// An Answers hook: what the terminal held when the answer was read.
	fn atRead() void {
		pending_seen = pending(watched);
	}
};

test "apply --force: only a line typed after the question answers it; what was typed ahead is discarded" {
	if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
	var inst: Inst = undefined;
	try inst.init("force-typeahead", no_plugins);
	defer inst.deinit();
	const pty = try Pty.open();
	defer pty.close();
	// "y" typed while round 0 ran (before the plan was listed) is on the
	// terminal, unread, when the question is asked.
	try pty.typeAhead("y\n");
	try t.expectEqual(@as(usize, 2), Pty.pending(pty.slave));
	Pty.watched = pty.slave;
	Pty.pending_seen = std.math.maxInt(usize);
	var answers: Answers = .{ .lines = &.{"n\n"}, .hook = Pty.atRead };
	var p = answers.prompt();
	p.fd = pty.slave;
	try t.expect(!apply.askYes(inst.s.io(), p, "Apply anyway (plan 1111111111111111)? [y/N] "));
	// Discarded before the answer was read, not after.
	try t.expectEqual(@as(usize, 0), Pty.pending_seen);
	try t.expectEqual(@as(usize, 0), Pty.pending(pty.slave));
	try t.expectEqual(@as(usize, 1), answers.next);
	try t.expectEqualStrings("Apply anyway (plan 1111111111111111)? [y/N] ", inst.err.items);
}

/// A terminal as forceLoop reads it (the `slave` of a Pty, one line per read in
/// its canonical mode, oldest first; a read that finds nothing there is EOF,
/// never a wait), with a person at it: `typing` (Scripted's `during`) types
/// `ahead[i]` while round i runs, and `onStderr` (the stderr sink's hook)
/// types `replies[k]` once the k-th question is shown, as a terminal driver
/// that waits for `[y/N] ` does.
const Tty = struct {
	var pty: Pty = undefined;
	var ahead: []const []const u8 = &.{};
	var replies: []const []const u8 = &.{};
	var asked: usize = 0;
	var buf: [64]u8 = undefined;
	var reader: std.Io.Reader = undefined;

	fn prompt(p: Pty, typed_ahead: []const []const u8, answers: []const []const u8) apply.Prompt {
		pty = p;
		ahead = typed_ahead;
		replies = answers;
		asked = 0;
		reader = .{ .vtable = &.{ .stream = stream }, .buffer = &buf, .seek = 0, .end = 0 };
		return .{ .tty = true, .in = &reader, .fd = p.slave };
	}

	fn stream(_: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
		const held = Pty.pending(pty.slave);
		if (held == 0 or held == std.math.maxInt(usize)) return error.EndOfStream;
		var line: [64]u8 = undefined;
		const got = std.c.read(pty.slave, &line, limit.minInt(line.len));
		if (got <= 0) return error.EndOfStream;
		return w.write(line[0..@intCast(got)]);
	}

	fn onStderr(bytes: []const u8) void {
		if (!std.mem.endsWith(u8, bytes, "[y/N] ") or asked >= replies.len) return;
		pty.typeAhead(replies[asked]) catch {};
		asked += 1;
	}

	fn typing(i: usize) void {
		if (i < ahead.len) pty.typeAhead(ahead[i]) catch {};
	}
};

test "apply --force: a line typed before a question is shown never answers it, one typed on seeing it does, and a changed plan is agreed to only once it is listed" {
	if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
	var inst: Inst = undefined;
	try inst.init("force-tty", no_plugins);
	defer inst.deinit();
	defer restoreSignals();
	var c = inst.ctx();
	const pty = try Pty.open();
	defer pty.close();
	// Round 0 offers plan 1; the forced round finds the plan changed (plan 2,
	// which restarts sshd too). The person typed "n" while round 0 ran, and
	// answers "y" once asked about plan 1; then, expecting the forced run to
	// go on, types "y" while it runs, and answers "n" once plan 2 is listed
	// and asked about.
	Scripted.start(&inst, &.{ offer_1, roundOf(0, .restart_required, .plan_changed, false, plan_2), roundOf(0, .applied, null, false, null) });
	Scripted.during = Tty.typing;
	apply.stderr_sink_hook = Tty.onStderr;
	defer apply.stderr_sink_hook = null;
	const p = Tty.prompt(pty, &.{ "n\n", "y\n" }, &.{ "y\n", "n\n" });
	try t.expectEqual(@as(u8, 1), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), p, Scripted.round));
	// Plan 1 was forced on the "y" typed once it was asked about (the "n"
	// typed ahead was not the answer); plan 2 was never forced (the "y" typed
	// before it was listed was not the answer either).
	try t.expectEqual(@as(usize, 2), Scripted.n);
	try t.expectEqualStrings(plan_1.id, Scripted.args[1].force_plan.?);
	try t.expectEqual(@as(usize, 2), Tty.asked);
	try t.expectEqual(@as(usize, 0), Pty.pending(pty.slave));
	try t.expectEqual(@as(usize, 1), count(inst.err.items, "Apply anyway (plan 2222222222222222)? [y/N] "));
	try t.expect(std.mem.endsWith(u8, inst.err.items, "Nothing was applied anyway; the change loads at the next restart.\n"));
}

test "apply --force: what the reader took past an answer never answers the next question" {
	var inst: Inst = undefined;
	try inst.init("force-buffered", no_plugins);
	defer inst.deinit();
	defer restoreSignals();
	var c = inst.ctx();
	// One read hands the reader two lines (a paste, a terminal that is not
	// line-buffered): the second was typed before plan 2 was listed.
	Scripted.start(&inst, &.{ offer_1, roundOf(0, .restart_required, .plan_changed, false, plan_2), roundOf(0, .applied, null, false, null) });
	var answers: Answers = .{ .lines = &.{ "y\ny\n", "n\n" } };
	try t.expectEqual(@as(u8, 1), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), answers.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 2), Scripted.n);
	try t.expectEqual(@as(usize, 2), answers.next);
	try t.expectEqual(@as(usize, 2), count(inst.err.items, "[y/N] "));
}

/// An allocator that refuses every block larger than `cap` bytes: as the
/// stderr sink's, a stderr that takes the short question but not the plan
/// listing.
const CapAllocator = struct {
	backing: std.mem.Allocator,
	cap: usize,

	fn allocator(self: *CapAllocator) std.mem.Allocator {
		return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
	}
	fn alloc(ctx: *anyopaque, len: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
		const self: *CapAllocator = @ptrCast(@alignCast(ctx));
		return if (len > self.cap) null else self.backing.rawAlloc(len, al, ra);
	}
	fn resize(ctx: *anyopaque, memory: []u8, al: std.mem.Alignment, new_len: usize, ra: usize) bool {
		const self: *CapAllocator = @ptrCast(@alignCast(ctx));
		return new_len <= self.cap and self.backing.rawResize(memory, al, new_len, ra);
	}
	fn remap(ctx: *anyopaque, memory: []u8, al: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
		const self: *CapAllocator = @ptrCast(@alignCast(ctx));
		return if (new_len > self.cap) null else self.backing.rawRemap(memory, al, new_len, ra);
	}
	fn free(ctx: *anyopaque, memory: []u8, al: std.mem.Alignment, ra: usize) void {
		const self: *CapAllocator = @ptrCast(@alignCast(ctx));
		self.backing.rawFree(memory, al, ra);
	}
};

test "apply --force: a plan whose listing cannot be shown is not asked about, and nothing is applied anyway" {
	var inst: Inst = undefined;
	try inst.init("force-unlisted", no_plugins);
	defer inst.deinit();
	defer restoreSignals();
	var c = inst.ctx();
	// stderr takes the question but not the listing (the sink refuses any
	// block over 400 bytes): a "y" waiting on stdin would agree to a plan
	// never shown, so it is not asked for.
	try t.expect(apply.planListing(inst.s.a(), "inst", plan_1, false).len > 400);
	var capped: CapAllocator = .{ .backing = inst.s.a(), .cap = 400 };
	apply.stderr_sink_allocator = capped.allocator();
	defer apply.stderr_sink_allocator = inst.s.a();
	Scripted.start(&inst, &.{ offer_1, roundOf(0, .applied, null, false, null) });
	var answers: Answers = .{ .lines = &.{"y\n"} };
	try t.expectEqual(@as(u8, 1), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), answers.prompt(), Scripted.round));
	try t.expectEqual(@as(usize, 1), Scripted.n);
	try t.expectEqual(@as(usize, 0), answers.reads);
	try t.expectEqualStrings("Nothing was applied anyway; the change loads at the next restart.\n", inst.err.items);
	// The question itself not shown (stderr takes nothing): no.
	inst.err.clearRetainingCapacity();
	inst.err.shrinkAndFree(inst.s.a(), 0);
	var failing = std.testing.FailingAllocator.init(inst.s.a(), .{ .fail_index = 0 });
	apply.stderr_sink_allocator = failing.allocator();
	answers = .{ .lines = &.{"y\n"} };
	try t.expect(!apply.askYes(inst.s.io(), answers.prompt(), "Apply anyway (plan 1111111111111111)? [y/N] "));
	try t.expectEqual(@as(usize, 0), answers.reads);
}

/// U22's checks, made while the question waits for an answer.
const WhileAsked = struct {
	var inst: *Inst = undefined;
	var cfg_free = false;
	var apply_free = false;
	var term: Disposition = .handled;
	var int: Disposition = .handled;
	var hup: Disposition = .handled;
	var usr1: Disposition = .default;

	fn check() void {
		cfg_free = lockFree(inst, "cfg.lock");
		apply_free = lockFree(inst, "apply.lock");
		term = disposition(std.posix.SIG.TERM);
		int = disposition(std.posix.SIG.INT);
		hup = disposition(std.posix.SIG.HUP);
		usr1 = disposition(std.posix.SIG.USR1);
	}
};

test "apply --force: nothing is held while the question waits, and Ctrl-C there just ends the process; the verb's handlers are back for the forced run" {
	var inst: Inst = undefined;
	try inst.init("force-idle", no_plugins);
	defer inst.deinit();
	defer restoreSignals();
	var c = inst.ctx();
	// The dispatcher installed the verb's handlers before its lock wait.
	apply.installSignals();
	WhileAsked.inst = &inst;
	Scripted.start(&inst, &.{ offer_1, roundOf(0, .applied, null, false, null) });
	var answers: Answers = .{ .lines = &.{"y\n"}, .hook = WhileAsked.check };
	try t.expectEqual(@as(u8, 0), apply.forceLoop(inst.s.a(), &c, force_args, inst.host(true), answers.prompt(), Scripted.round));
	try t.expect(answers.reads > 0);
	try t.expect(WhileAsked.cfg_free);
	try t.expect(WhileAsked.apply_free);
	try t.expectEqual(Disposition.default, WhileAsked.term);
	try t.expectEqual(Disposition.default, WhileAsked.int);
	try t.expectEqual(Disposition.default, WhileAsked.hup);
	// A supersede request has nothing to end there: its handler only stores.
	try t.expectEqual(Disposition.handled, WhileAsked.usr1);
	try t.expect(Scripted.int_handled[0]);
	try t.expect(Scripted.int_handled[1]);
	try t.expectEqual(Disposition.handled, disposition(std.posix.SIG.TERM));
	try t.expectEqual(Disposition.handled, disposition(std.posix.SIG.HUP));
}

test "apply --force: the plan listing names every unit, what the actions whose effect has a name end, the re-exec, the repair and what force relaxes, for the instance asked about" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	// The consent covers what force relaxes (forceUnits): a stopped, started
	// or restarted unit is held to nothing but not failing; a reloaded one to
	// its InvocationID and its running state.
	const tail = "They end or interrupt the sessions, containers and connections they serve, for everyone who uses the sandbox, " ++
		"and they restart again if the change is undone. The units it stops, starts or restarts may end up restarted, stopped or started " ++
		"without that undoing the change (one that fails undoes it); a unit it only reloads must keep running as it was. " ++
		"The checks of logins, sshd and the network still run, and a change they prove broken is rolled back.\n";
	var p = planOf("0123456789abcdef", &.{
		.{ .unit = "docker.service", .action = .stop, .why = "changed", .class = "B" },
		.{ .unit = "docker.service", .action = .start, .why = "induced", .class = "B" },
		.{ .unit = "docker.socket", .action = .restart, .why = "changed", .class = "B" },
		.{ .unit = "sshd.service", .action = .restart, .why = "changed", .class = "B" },
		.{ .unit = "systemd-networkd.service", .action = .reload, .why = "propagated:wants:x.service", .class = "C" },
		.{ .unit = "systemd-resolved.service", .action = .restart, .why = "changed", .class = "B" },
	});
	p.repair = &.{apply.repair_unit};
	p.reexec = true;
	// Spec 4.2's effects, in the control plane's words, only for the action
	// that has them (a start of docker ends no container).
	try t.expectEqualStrings("Apply anyway would act on these units in the running instance 'la':\n" ++
		"  stop docker.service (changed; class B): stops every running container\n" ++
		"  start docker.service (induced; class B)\n" ++
		"  restart docker.socket (changed; class B)\n" ++
		"  restart sshd.service (changed; class B): existing sessions survive, new logins pause briefly\n" ++
		"  reload systemd-networkd.service (propagated:wants:x.service; class C)\n" ++
		"  restart systemd-resolved.service (changed; class B): name lookups fail briefly\n" ++
		"  re-execute systemd\n" ++
		"  then restart cogbox-reply-route.service (repairs the uplink's reply routing)\n" ++ tail, apply.planListing(a, "la", p, false));
	// The default instance, a changed plan, no re-exec and no repair.
	p.repair = &.{};
	p.reexec = false;
	p.units = p.units[0..1];
	try t.expectEqualStrings("The plan changed since it was shown. Apply anyway would now act on these units in the running instance:\n" ++
		"  stop docker.service (changed; class B): stops every running container\n" ++ tail, apply.planListing(a, null, p, true));
	// A re-exec-only plan.
	p.units = &.{};
	p.reexec = true;
	try t.expectEqualStrings("Apply anyway would act on these units in the running instance:\n  re-execute systemd\n" ++ tail, apply.planListing(a, null, p, false));
	// Spec 4.2's docker example is a restart; its reload ends nothing.
	p.reexec = false;
	p.units = &.{
		docker_restart,
		.{ .unit = "docker.service", .action = .reload, .why = "changed", .class = "B" },
	};
	try t.expectEqualStrings("Apply anyway would act on these units in the running instance:\n" ++
		"  restart docker.service (changed; class B): stops every running container\n" ++
		"  reload docker.service (changed; class B)\n" ++ tail, apply.planListing(a, null, p, false));
}

/// A plan as the inline apply reads it back from its report.
fn planJsonOf(a: std.mem.Allocator, p: apply.Plan) !std.json.Value {
	var aw: std.Io.Writer.Allocating = .init(a);
	try std.json.Stringify.value(p, .{}, &aw.writer);
	return std.json.parseFromSliceLeaky(std.json.Value, a, aw.written(), .{});
}

test "apply --force: the inline hint says how to apply it anyway and what it would do: on a terminal --force with at most 8 units, the re-exec and the repair; off one the whole plan, then its id" {
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	var p = planOf("0123456789abcdef", &.{
		.{ .unit = "docker.service", .action = .stop, .why = "changed", .class = "B" },
		.{ .unit = "docker.socket", .action = .restart, .why = "changed", .class = "B" },
		.{ .unit = "systemd-networkd.service", .action = .reload, .why = "changed", .class = "C" },
	});
	p.repair = &.{apply.repair_unit};
	const id_line = "To apply it anyway, after reading the plan above: cogbox plugin apply --force-plan 0123456789abcdef";
	try t.expectEqualStrings("Or run 'cogbox plugin apply --force -n la' to apply it now anyway; it would: stop docker.service, restart docker.socket, reload systemd-networkd.service, then restart cogbox-reply-route.service.", apply.forceHint(a, "la", try planJsonOf(a, p), true).?);
	// Off a terminal, where --force refuses: the whole plan, as the verb's own
	// human line lists it, and only after it the id that forces it.
	try t.expectEqualStrings("Or apply it now anyway, which would:\n" ++
		"  stop docker.service (changed; class B): stops every running container\n" ++
		"  restart docker.socket (changed; class B)\n" ++
		"  reload systemd-networkd.service (changed; class C)\n" ++
		"  then restart cogbox-reply-route.service (repairs the uplink's reply routing)\n" ++ id_line ++ " -n la", apply.forceHint(a, "la", try planJsonOf(a, p), false).?);
	// The default instance takes no -n; the re-exec comes after the units,
	// the repair last.
	p.reexec = true;
	try t.expectEqualStrings("Or run 'cogbox plugin apply --force' to apply it now anyway; it would: stop docker.service, restart docker.socket, reload systemd-networkd.service, re-execute systemd, then restart cogbox-reply-route.service.", apply.forceHint(a, null, try planJsonOf(a, p), true).?);
	try t.expect(std.mem.endsWith(u8, apply.forceHint(a, null, try planJsonOf(a, p), false).?, "  re-execute systemd\n  then restart cogbox-reply-route.service (repairs the uplink's reply routing)\n" ++ id_line));
	p.units = &.{};
	p.repair = &.{};
	try t.expectEqualStrings("Or run 'cogbox plugin apply --force' to apply it now anyway; it would: re-execute systemd.", apply.forceHint(a, null, try planJsonOf(a, p), true).?);
	try t.expectEqualStrings("Or apply it now anyway, which would:\n  re-execute systemd\n" ++ id_line, apply.forceHint(a, null, try planJsonOf(a, p), false).?);
	// Nine units: on a terminal eight named, then the count; off one, all
	// nine before the id.
	p.reexec = false;
	p.units = try unitsOf(a, 1, 9);
	try t.expectEqualStrings("Or run 'cogbox plugin apply --force -n la' to apply it now anyway; it would: restart u001.service, restart u002.service, " ++
		"restart u003.service, restart u004.service, restart u005.service, restart u006.service, restart u007.service, restart u008.service, and 1 more.", apply.forceHint(a, "la", try planJsonOf(a, p), true).?);
	const off = apply.forceHint(a, "la", try planJsonOf(a, p), false).?;
	try t.expect(std.mem.indexOf(u8, off, "more") == null);
	try t.expect(std.mem.indexOf(u8, off, "  restart u009.service (changed; class B)\n" ++ id_line ++ " -n la") != null);
	try t.expectEqual(@as(usize, 1), count(off, "0123456789abcdef"));
	// Not a plan: nothing, on a terminal or off one; nor off one for a plan
	// whose id, or a `why` it would list, is not what a plan carries.
	const bad = [_][]const u8{
		"null",
		"{\"units\":[],\"reexec\":false,\"repair\":[]}",
		"{\"units\":[{\"unit\":\"docker.service\",\"action\":\"stop\"}],\"repair\":[]}",
		"{\"units\":[{\"unit\":\"docker.service\",\"action\":\"stop\"}],\"reexec\":false}",
		"{\"units\":[{\"unit\":\"docker.service\",\"action\":\"explode\"}],\"reexec\":false,\"repair\":[]}",
		"{\"units\":[{\"unit\":\"bad unit;rm\",\"action\":\"stop\"}],\"reexec\":false,\"repair\":[]}",
		"{\"units\":[{\"unit\":7,\"action\":\"stop\"}],\"reexec\":false,\"repair\":[]}",
		"{\"units\":{},\"reexec\":false,\"repair\":[]}",
		"{\"units\":[],\"reexec\":true,\"repair\":[\"bad unit;rm\"]}",
		"{\"units\":[],\"reexec\":true,\"repair\":{}}",
	};
	for (bad) |b| for ([_]bool{ true, false }) |tty| {
		try t.expect(apply.forceHint(a, "la", try std.json.parseFromSliceLeaky(std.json.Value, a, b, .{}), tty) == null);
	};
	p.units = &.{.{ .unit = "docker.service", .action = .restart, .why = "changed", .class = "B" }};
	var odd = p;
	odd.id = "not-a-plan-id";
	try t.expect(apply.forceHint(a, "la", try planJsonOf(a, odd), false) == null);
	odd = p;
	odd.units = &.{.{ .unit = "docker.service", .action = .restart, .why = "propagated:x:\x1b[2J", .class = "B" }};
	try t.expect(apply.forceHint(a, "la", try planJsonOf(a, odd), false) == null);
	try t.expect(apply.forceHint(a, "la", try planJsonOf(a, p), false) != null);
}

test "apply --force: the production round hands back the Report its apply built" {
	var inst: Inst = undefined;
	try inst.init("force-round", no_plugins);
	defer inst.deinit();
	try inst.env.put("COGBOX_LIVE_APPLY", "0");
	var c = inst.ctx();
	const r = apply.applyRound(inst.s.a(), &c, force_args, inst.host(true));
	try t.expectEqual(@as(u8, 0), r.code);
	try t.expectEqual(apply.Result.restart_required, r.report.?.result);
	try t.expectEqual(@as(?apply.Reason, .disabled), r.report.?.reason);
	try t.expectEqualStrings(r.report.?.gen.?, (try std.json.parseFromSliceLeaky(std.json.Value, inst.s.a(), try inst.s.read("icd/apply/last.json"), .{})).object.get("apply").?.object.get("gen").?.string);
	// The human line, printed as for any run.
	try t.expectEqualStrings("plugin apply: restart_required/disabled: saved; it loads at the next restart\n", inst.sink.items);
}
