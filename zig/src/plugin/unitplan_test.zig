const std = @import("std");
const up = @import("unitplan.zig");
const t = std.testing;

// --- helpers -----------------------------------------------------------------

/// A UnitInfo from a comptime literal: .{ .{ "Section", .{ .{ "Key", .{ "v1", "v2" } } } } }.
fn mk(a: std.mem.Allocator, comptime sections: anytype) !up.UnitInfo {
	var u: up.UnitInfo = .empty;
	inline for (sections) |sec| {
		var s: up.Section = .empty;
		inline for (sec[1]) |kv| {
			var vs: up.Values = .empty;
			inline for (kv[1]) |v| try vs.append(a, v);
			try s.put(a, kv[0], vs);
		}
		try u.put(a, sec[0], s);
	}
	return u;
}

fn cmp(a: std.mem.Allocator, comptime cur: anytype, comptime new: anytype) !up.Comparison {
	var c = try mk(a, cur);
	var n = try mk(a, new);
	return up.compareUnits(&c, &n);
}

fn parse(a: std.mem.Allocator, files: []const []const u8) !up.UnitInfo {
	var info: up.UnitInfo = .empty;
	for (files) |f| try up.parseSystemdIni(a, &info, f);
	return info;
}

fn vals(info: *const up.UnitInfo, section: []const u8, key: []const u8) []const []const u8 {
	const s = info.getPtr(section) orelse return &.{};
	const v = s.getPtr(key) orelse return &.{};
	return v.items;
}

fn expectVals(expected: []const []const u8, got: []const []const u8) !void {
	try t.expectEqual(expected.len, got.len);
	for (expected, got) |e, g| try t.expectEqualStrings(e, g);
}

/// A scratch tree under cwd with an arena for everything the test allocates.
const Fx = struct {
	arena_state: std.heap.ArenaAllocator,
	threaded: std.Io.Threaded,
	root: []const u8 = "",

	fn init(fx: *Fx, tag: []const u8) !void {
		fx.arena_state = .init(t.allocator);
		fx.threaded = .init(t.allocator, .{});
		const ar = fx.arena_state.allocator();
		const tio = fx.threaded.io();
		var rnd: [8]u8 = undefined;
		tio.random(&rnd);
		const rel = try std.fmt.allocPrint(ar, "zig-unitplan-test-{s}-{x}", .{ tag, &rnd });
		try std.Io.Dir.cwd().createDirPath(tio, rel);
		fx.root = try std.Io.Dir.cwd().realPathFileAlloc(tio, rel, ar);
	}

	fn deinit(fx: *Fx) void {
		std.Io.Dir.cwd().deleteTree(fx.threaded.io(), fx.root) catch {};
		fx.threaded.deinit();
		fx.arena_state.deinit();
	}

	fn a(fx: *Fx) std.mem.Allocator {
		return fx.arena_state.allocator();
	}

	fn io(fx: *Fx) std.Io {
		return fx.threaded.io();
	}

	fn path(fx: *Fx, rel: []const u8) []const u8 {
		return std.fmt.allocPrint(fx.a(), "{s}/{s}", .{ fx.root, rel }) catch @panic("oom");
	}

	fn put(fx: *Fx, rel: []const u8, data: []const u8) !void {
		const p = fx.path(rel);
		try std.Io.Dir.cwd().createDirPath(fx.io(), std.fs.path.dirname(p).?);
		try std.Io.Dir.cwd().writeFile(fx.io(), .{ .sub_path = p, .data = data });
	}

	fn link(fx: *Fx, rel: []const u8, target: []const u8) !void {
		const p = fx.path(rel);
		try std.Io.Dir.cwd().createDirPath(fx.io(), std.fs.path.dirname(p).?);
		try std.Io.Dir.cwd().symLink(fx.io(), target, p, .{});
	}

	fn mkdir(fx: *Fx, rel: []const u8) !void {
		try std.Io.Dir.cwd().createDirPath(fx.io(), fx.path(rel));
	}
};

fn findUnit(units: []const up.PlannedUnit, name: []const u8) ?up.PlannedUnit {
	for (units) |u| {
		if (std.mem.eql(u8, u.unit, name)) return u;
	}
	return null;
}

fn expectPlanned(units: []const up.PlannedUnit, name: []const u8, action: up.Action, why: up.Why) !void {
	const u = findUnit(units, name) orelse {
		std.debug.print("missing planned unit {s}\n", .{name});
		return error.TestExpectedEqual;
	};
	try t.expectEqual(action, u.action);
	try t.expectEqual(why, u.why);
}

fn findHazard(hz: []const up.Hazard, unit: []const u8) ?up.Hazard {
	for (hz) |h| {
		if (std.mem.eql(u8, h.unit, unit)) return h;
	}
	return null;
}

/// No guest data: nothing runs, no once-marker, every target P has is active.
const no_rt: up.Runtime = .{};

/// A guest that runs `active` and holds the once-markers `once` (unit names
/// without their type).
fn guestRt(a: std.mem.Allocator, active: []const []const u8, once: []const []const u8) !up.Runtime {
	var rt: up.Runtime = .{ .known = true };
	for (active) |u| try rt.active.put(a, u, {});
	for (once) |m| try rt.once.put(a, m, {});
	return rt;
}

// --- main.rs test vectors: compare_units (main.rs:2794-2997) -----------------

test "compareUnits: every switch-ng compare_units vector gives the same verdict" {
	var arena: std.heap.ArenaAllocator = .init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();

	// Equal.
	try t.expectEqual(up.Comparison.equal, try cmp(a, .{}, .{}));
	try t.expectEqual(up.Comparison.equal, try cmp(a, .{.{ "Unit", .{} }}, .{}));
	try t.expectEqual(up.Comparison.equal, try cmp(a, .{.{ "Unit", .{.{ "X-Reload-Triggers", .{"foobar"} }} }}, .{}));

	// Restart, and the [Mount] Options reload.
	try t.expectEqual(up.Comparison.needs_restart, try cmp(a, .{.{ "foobar", .{} }}, .{}));
	try t.expectEqual(up.Comparison.needs_reload, try cmp(a, .{.{ "Mount", .{.{ "Options", .{} }} }}, .{.{ "Mount", .{.{ "Options", .{"ro"} }} }}));

	// Reload triggers and ExecReload.
	try t.expectEqual(up.Comparison.needs_reload, try cmp(a, .{}, .{.{ "Unit", .{.{ "X-Reload-Triggers", .{"foobar"} }} }}));
	try t.expectEqual(up.Comparison.needs_reload, try cmp(a, .{.{ "Unit", .{.{ "X-Reload-Triggers", .{"foobar"} }} }}, .{.{ "Unit", .{.{ "X-Reload-Triggers", .{"barfoo"} }} }}));
	try t.expectEqual(up.Comparison.needs_reload, try cmp(a, .{}, .{.{ "Service", .{.{ "ExecReload", .{"foobar"} }} }}));
	try t.expectEqual(up.Comparison.needs_reload, try cmp(a, .{.{ "Service", .{.{ "ExecReload", .{"foobar"} }} }}, .{.{ "Service", .{.{ "ExecReload", .{"barfoo"} }} }}));

	// A new [Service] section while [Unit] already existed inspects [Service].
	try t.expectEqual(up.Comparison.needs_restart, try cmp(
		a,
		.{.{ "Unit", .{.{ "Description", .{"x"} }} }},
		.{ .{ "Unit", .{.{ "Description", .{"x"} }} }, .{ "Service", .{.{ "ExecStart", .{"y"} }} } },
	));
	try t.expectEqual(up.Comparison.needs_reload, try cmp(
		a,
		.{.{ "Unit", .{.{ "Description", .{"x"} }} }},
		.{ .{ "Unit", .{.{ "Description", .{"x"} }} }, .{ "Service", .{.{ "ExecReload", .{"y"} }} } },
	));

	// ExecReload removed: nothing to do.
	try t.expectEqual(up.Comparison.equal, try cmp(
		a,
		.{.{ "Service", .{ .{ "ExecStart", .{"x"} }, .{ "ExecReload", .{"y"} } } }},
		.{.{ "Service", .{.{ "ExecStart", .{"x"} }} }},
	));
	try t.expectEqual(up.Comparison.equal, try cmp(a, .{.{ "Service", .{.{ "ExecReload", .{"y"} }} }}, .{}));

	// ExecReload added to an existing [Service] section.
	try t.expectEqual(up.Comparison.needs_reload, try cmp(
		a,
		.{.{ "Service", .{.{ "ExecStart", .{"x"} }} }},
		.{.{ "Service", .{ .{ "ExecStart", .{"x"} }, .{ "ExecReload", .{"y"} } } }},
	));

	try t.expectEqual(up.Comparison.needs_restart, try cmp(a, .{.{ "Mount", .{.{ "Type", .{"ext4"} }} }}, .{.{ "Mount", .{.{ "Type", .{"btrfs"} }} }}));
}

test "compareUnits: ignored [Unit] keys never restart, any other change does" {
	var arena: std.heap.ArenaAllocator = .init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	// Changed, added and removed ignored keys are equal.
	try t.expectEqual(up.Comparison.equal, try cmp(a, .{.{ "Unit", .{.{ "Description", .{"a"} }} }}, .{.{ "Unit", .{.{ "Description", .{"b"} }} }}));
	try t.expectEqual(up.Comparison.equal, try cmp(a, .{.{ "Unit", .{.{ "OnFailure", .{"a"} }} }}, .{.{ "Unit", .{} }}));
	try t.expectEqual(up.Comparison.equal, try cmp(a, .{.{ "Unit", .{} }}, .{.{ "Unit", .{.{ "Documentation", .{"d"} }} }}));
	// A non-ignored [Unit] key in any of those positions restarts.
	try t.expectEqual(up.Comparison.needs_restart, try cmp(a, .{.{ "Unit", .{.{ "After", .{"a"} }} }}, .{.{ "Unit", .{.{ "After", .{"b"} }} }}));
	try t.expectEqual(up.Comparison.needs_restart, try cmp(a, .{.{ "Unit", .{.{ "Requires", .{"a"} }} }}, .{}));
	try t.expectEqual(up.Comparison.needs_restart, try cmp(a, .{.{ "Unit", .{} }}, .{.{ "Unit", .{.{ "Wants", .{"x"} }} }}));
	// A restart anywhere beats a reload elsewhere.
	try t.expectEqual(up.Comparison.needs_restart, try cmp(
		a,
		.{ .{ "Unit", .{.{ "X-Reload-Triggers", .{"a"} }} }, .{ "Service", .{.{ "ExecStart", .{"x"} }} } },
		.{ .{ "Unit", .{.{ "X-Reload-Triggers", .{"b"} }} }, .{ "Service", .{.{ "ExecStart", .{"y"} }} } },
	));
	// Two new sections restart even when each alone would only reload.
	try t.expectEqual(up.Comparison.needs_restart, try cmp(
		a,
		.{},
		.{ .{ "Unit", .{.{ "X-Reload-Triggers", .{"a"} }} }, .{ "Service", .{.{ "ExecReload", .{"y"} }} } },
	));
}

// --- main.rs test vectors: parse_systemd_ini (main.rs:2999-3023) -------------

test "parseSystemdIni: escapes are not unescaped (nixpkgs#315602)" {
	var arena: std.heap.ArenaAllocator = .init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	const info = try parse(a, &.{"[Unit]\nAfter=dev-disk-by\\x2dlabel-root.device\n"});
	try expectVals(&.{"dev-disk-by\\x2dlabel-root.device"}, vals(&info, "Unit", "After"));
}

test "parseSystemdIni: rust-ini and switch-ng merge semantics" {
	var arena: std.heap.ArenaAllocator = .init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();

	// A key set n times in one section is applied n times (the per-entry loop):
	// the same two lines in one file differ from one line in a drop-in.
	const one_file = try parse(a, &.{"[Service]\nK=a\nK=b\n"});
	try expectVals(&.{ "a", "b", "a", "b" }, vals(&one_file, "Service", "K"));
	const split = try parse(a, &.{ "[Service]\nK=a\n", "[Service]\nK=b\n" });
	try expectVals(&.{ "a", "b" }, vals(&split, "Service", "K"));
	try t.expectEqual(up.Comparison.needs_restart, up.compareUnits(&one_file, &split));

	// An empty value clears what came before it, in the file and in earlier files.
	const cleared = try parse(a, &.{ "[Service]\nExecStart=/bin/a\n", "[Service]\nExecStart=\nExecStart=/bin/b\n" });
	try expectVals(&.{"/bin/b"}, vals(&cleared, "Service", "ExecStart"));
	const cleared_empty = try parse(a, &.{ "[Service]\nExecStart=/bin/a\n", "[Service]\nExecStart=\n" });
	try expectVals(&.{}, vals(&cleared_empty, "Service", "ExecStart"));
	// A cleared-to-nothing key falls back to the default.
	try t.expect(up.parseSystemdBool(&cleared_empty, "Service", "ExecStart", true));

	// Keys and values are trimmed; ':' separates too; comments and [Install]
	// are dropped; keys before any section are ignored.
	const misc = try parse(a, &.{"Stray=1\n# comment\n; also\n[Unit]\n  Description : hello  \n  After =  x.service \r\n[Install]\nWantedBy=multi-user.target\n"});
	try expectVals(&.{"hello"}, vals(&misc, "Unit", "Description"));
	try expectVals(&.{"x.service"}, vals(&misc, "Unit", "After"));
	try t.expect(misc.getPtr("Install") == null);
	try t.expectEqual(@as(usize, 1), misc.count());

	// A value that starts with a quote loses the quotes; text after the closing
	// quote stays (end-trimmed); quotes later in a value are kept.
	const q = try parse(a, &.{"[Service]\nEnvironment=\"A=1\" \"B=2\"  \nExecStart=/bin/x \"a b\"\nX-RestartIfChanged='false'\n"});
	try expectVals(&.{"A=1 \"B=2\""}, vals(&q, "Service", "Environment"));
	try expectVals(&.{"/bin/x \"a b\""}, vals(&q, "Service", "ExecStart"));
	try t.expect(!up.parseSystemdBool(&q, "Service", "X-RestartIfChanged", true));

	// A repeated section header is a second occurrence: its keys are applied in
	// their own pass.
	const rep = try parse(a, &.{"[Service]\nK=a\n[Unit]\nX=1\n[Service]\nK=b\n"});
	try expectVals(&.{ "a", "b" }, vals(&rep, "Service", "K"));

	// Errors where rust-ini errors.
	var e: up.UnitInfo = .empty;
	try t.expectError(error.UnitParse, up.parseSystemdIni(a, &e, "[Unit\nA=1\n"));
	try t.expectError(error.UnitParse, up.parseSystemdIni(a, &e, "[Unit]\nNoValueHere\n"));
	try t.expectError(error.UnitParse, up.parseSystemdIni(a, &e, "[Unit]\n=x\n"));
	try t.expectError(error.UnitParse, up.parseSystemdIni(a, &e, "[Unit]\nA=\"unclosed\n"));
}

test "parseSystemdIni: a key applied past the value cap is refused" {
	var arena: std.heap.ArenaAllocator = .init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	var buf: std.ArrayList(u8) = .empty;
	try buf.appendSlice(a, "[Service]\n");
	var i: usize = 0;
	while (i < 300) : (i += 1) try buf.appendSlice(a, "Environment=X=1\n");
	var info: up.UnitInfo = .empty;
	// 300 entries applied 300 times each is 90000 values, past the cap.
	try t.expectError(error.UnitTooComplex, up.parseSystemdIni(a, &info, buf.items));
}

test "parseSystemdBool: the last value decides; 1/yes/true/on are true" {
	var arena: std.heap.ArenaAllocator = .init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	const info = try mk(a, .{.{ "Unit", .{
		.{ "A", .{ "no", "yes" } },
		.{ "B", .{ "yes", "0" } },
		.{ "C", .{"on"} },
		.{ "D", .{"1"} },
		.{ "E", .{"TRUE"} },
	} }});
	try t.expect(up.parseSystemdBool(&info, "Unit", "A", false));
	try t.expect(!up.parseSystemdBool(&info, "Unit", "B", true));
	try t.expect(up.parseSystemdBool(&info, "Unit", "C", false));
	try t.expect(up.parseSystemdBool(&info, "Unit", "D", false));
	try t.expect(!up.parseSystemdBool(&info, "Unit", "E", true)); // case-sensitive, as switch-ng
	try t.expect(up.parseSystemdBool(&info, "Unit", "missing", true));
	try t.expect(up.parseSystemdBool(&info, "Nope", "A", true));
	try t.expect(!up.parseSystemdBool(null, "Unit", "A", false));
}

// --- main.rs test vectors: migration_action_* (main.rs:3042-3125) ------------
//
// MigrationAction::for_active_unit honours the same X-* directives as
// handle_modified_unit; its vectors are checked against the port's
// handleModifiedUnit on an active unit (Restart = stopped and started,
// Reload, Skip, and the units that cannot be restarted directly get nothing).
// for_stopped_unit's RefuseManualStart / X-OnlyManualStart are the same
// conditions collect_unit_changes applies to an active target's start, checked
// in the plan test below.

fn handleFor(fx: *Fx, unit: []const u8, comptime info_lit: anytype) !up.Sets {
	const a = fx.a();
	var info = try mk(a, info_lit);
	var active: up.StrSet = .empty;
	try active.put(a, unit, {});
	var sets: up.Sets = .{};
	const s: up.Scope = .{ .arena = a, .io = fx.io(), .old_dir = fx.path("P"), .new_dir = fx.path("T"), .active = &active };
	try up.handleModifiedUnit(s, &sets, unit, up.baseName(unit), "/nonexistent", "/nonexistent", &info);
	return sets;
}

test "handleModifiedUnit: the migration_action_for_active_unit vectors" {
	var fx: Fx = undefined;
	try fx.init("migration");
	defer fx.deinit();
	try fx.mkdir("P");
	try fx.mkdir("T");

	// Plain service: restart (a stop and a start).
	const plain = try handleFor(&fx, "foo.service", .{});
	try t.expect(plain.stop.contains("foo.service") and plain.start.contains("foo.service"));
	try t.expectEqual(@as(usize, 0), plain.skip.count() + plain.reload.count());

	const reload = try handleFor(&fx, "foo.service", .{.{ "Service", .{.{ "X-ReloadIfChanged", .{"true"} }} }});
	try t.expect(reload.reload.contains("foo.service"));
	try t.expectEqual(@as(usize, 0), reload.stop.count() + reload.start.count() + reload.restart.count());

	inline for (.{
		.{ "Service", "X-RestartIfChanged", "false" },
		.{ "Unit", "RefuseManualStop", "yes" },
		.{ "Unit", "X-OnlyManualStart", "yes" },
	}) |v| {
		const skip = try handleFor(&fx, "foo.service", .{.{ v[0], .{.{ v[1], .{v[2]} }} }});
		try t.expect(skip.skip.contains("foo.service"));
		try t.expectEqual(@as(usize, 0), skip.stop.count() + skip.start.count() + skip.restart.count() + skip.reload.count());
	}

	inline for (.{ "sysinit.target", "basic.target", "multi-user.target", "graphical.target", "foo.path", "bar.slice" }) |unit| {
		const none = try handleFor(&fx, unit, .{});
		try t.expectEqual(@as(usize, 0), none.stop.count() + none.start.count() + none.restart.count() + none.reload.count() + none.skip.count());
	}

	// The rest of handle_modified_unit: X-StopIfChanged=false and non-services
	// restart in place; mounts restart except / and /nix, which reload; sockets
	// get nothing.
	const in_place = try handleFor(&fx, "foo.service", .{.{ "Service", .{.{ "X-StopIfChanged", .{"false"} }} }});
	try t.expect(in_place.restart.contains("foo.service") and !in_place.stop.contains("foo.service"));
	try t.expect((try handleFor(&fx, "foo.timer", .{})).restart.contains("foo.timer"));
	try t.expect((try handleFor(&fx, "data.mount", .{})).restart.contains("data.mount"));
	try t.expect((try handleFor(&fx, "-.mount", .{})).reload.contains("-.mount"));
	try t.expect((try handleFor(&fx, "nix.mount", .{})).reload.contains("nix.mount"));
	const sock = try handleFor(&fx, "foo.socket", .{});
	try t.expectEqual(@as(usize, 0), sock.stop.count() + sock.start.count() + sock.restart.count() + sock.reload.count() + sock.skip.count());
}

// --- the host plan over unit directories ---------------------------------------

test "planDirs: changed, reload-only, removed, masked, kept-on-removal, new and wanted, targets" {
	var fx: Fx = undefined;
	try fx.init("plan");
	defer fx.deinit();
	const a = fx.a();

	// P
	try fx.put("P/a.service", "[Unit]\nDescription=a\n[Service]\nExecStart=/bin/a\n");
	try fx.put("P/b.service", "[Service]\nExecStart=/bin/b\n");
	try fx.put("P/c.service", "[Service]\nExecStart=/bin/c\nExecReload=/bin/r1\n");
	try fx.put("P/d.service", "[Unit]\nX-Reload-Triggers=/nix/store/one\n[Service]\nExecStart=/bin/d\n");
	try fx.put("P/gone.service", "[Service]\nExecStart=/bin/g\n");
	try fx.put("P/kept.service", "[Unit]\nX-StopOnRemoval=false\n[Service]\nExecStart=/bin/k\n");
	try fx.put("P/masked-later.service", "[Service]\nExecStart=/bin/m\n");
	try fx.put("P/multi-user.target", "[Unit]\nDescription=Multi-User\n");
	try fx.put("P/manual.target", "[Unit]\nRefuseManualStart=true\n");
	try fx.put("P/only-manual.target", "[Unit]\nX-OnlyManualStart=true\n");
	try fx.put("P/local-fs.target", "[Unit]\nDescription=Local File Systems\n");
	try fx.put("P/local-fs.target.d/overrides.conf", "[Unit]\nX-StopOnReconfiguration=true\n");
	try fx.put("P/sleepy.service", "[Service]\nExecStart=/bin/s\n");
	try fx.link("P/never.service", "/dev/null");
	try fx.put("P/restart-false.service", "[Service]\nExecStart=/bin/x\nX-RestartIfChanged=false\n");

	// T
	try fx.put("T/a.service", "[Unit]\nDescription=a, reworded\n[Service]\nExecStart=/bin/a\n");
	try fx.put("T/b.service", "[Service]\nExecStart=/bin/b2\n");
	try fx.put("T/c.service", "[Service]\nExecStart=/bin/c\nExecReload=/bin/r2\n");
	try fx.put("T/d.service", "[Unit]\nX-Reload-Triggers=/nix/store/two\n[Service]\nExecStart=/bin/d\n");
	try fx.link("T/masked-later.service", "/dev/null");
	try fx.put("T/multi-user.target", "[Unit]\nDescription=Multi-User\n");
	try fx.put("T/manual.target", "[Unit]\nRefuseManualStart=true\n");
	try fx.put("T/only-manual.target", "[Unit]\nX-OnlyManualStart=true\n");
	try fx.put("T/local-fs.target", "[Unit]\nDescription=Local File Systems\n");
	try fx.put("T/local-fs.target.d/overrides.conf", "[Unit]\nX-StopOnReconfiguration=true\n");
	try fx.put("T/sleepy.service", "[Service]\nExecStart=/bin/s\n");
	try fx.put("T/new.service", "[Service]\nExecStart=/bin/n\n");
	try fx.link("T/multi-user.target.wants/new.service", "../new.service");
	try fx.put("T/new-dep.service", "[Service]\nExecStart=/bin/nd\n");
	try fx.put("T/new.service.d/deps.conf", "[Unit]\nWants=new-dep.service\n");
	try fx.put("T/orphan.service", "[Service]\nExecStart=/bin/o\n");
	try fx.put("T/never.service", "[Service]\nExecStart=/bin/v\n");
	try fx.put("T/restart-false.service", "[Service]\nExecStart=/bin/y\nX-RestartIfChanged=false\n");

	const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
	const units = try plan.units(a);

	// a.service: only Description changed (ignored): absent.
	try t.expect(findUnit(units, "a.service") == null);
	try expectPlanned(units, "b.service", .restart, .changed);
	try expectPlanned(units, "c.service", .reload, .changed);
	try expectPlanned(units, "d.service", .reload, .changed);
	try expectPlanned(units, "gone.service", .stop, .removed);
	try expectPlanned(units, "masked-later.service", .stop, .removed);
	try t.expect(findUnit(units, "kept.service") == null);
	try t.expect(findUnit(units, "sleepy.service") == null);
	// New and wanted (directly by an active target, and through a new unit's
	// drop-in Wants=) start; a new unit nothing wants does not.
	try expectPlanned(units, "new.service", .start, .new);
	try expectPlanned(units, "new-dep.service", .start, .new);
	try t.expect(findUnit(units, "orphan.service") == null);
	// A unit masked in P and real in T is new; nothing wants it, so it is not started.
	try t.expect(plan.new_units.contains("never.service"));
	try t.expect(findUnit(units, "never.service") == null);
	// restartIfChanged = false: skipped.
	try t.expect(plan.sets.skip.contains("restart-false.service"));
	try t.expect(findUnit(units, "restart-false.service") == null);

	// Targets: every active target is started (hidden), except a
	// RefuseManualStart / X-OnlyManualStart one (switch-ng's for_stopped_unit
	// conditions); the X-StopOnReconfiguration one is stopped (hidden too).
	try t.expect(plan.sets.start.contains("multi-user.target") and plan.sets.filter.contains("multi-user.target"));
	try t.expect(!plan.sets.start.contains("manual.target"));
	try t.expect(!plan.sets.start.contains("only-manual.target"));
	try t.expect(plan.sets.stop.contains("local-fs.target"));
	try t.expect(findUnit(units, "multi-user.target") == null);
	try t.expect(findUnit(units, "local-fs.target") == null);

	// The seeds add the hidden reconfiguration stop and the hidden target
	// starts: with no guest data, of every target P has (multi-user and
	// local-fs here; sysinit-reactivation.target is restarted only when a
	// system has it).
	const seeds = try plan.seeds(a, &no_rt);
	var saw_lfs_stop = false;
	var target_starts: usize = 0;
	for (seeds) |s| {
		if (s.why == .reconfigured) {
			try t.expectEqualStrings("local-fs.target", s.unit);
			try t.expectEqual(up.Action.stop, s.action);
			saw_lfs_stop = true;
		}
		if (s.why == .target) {
			try t.expectEqual(up.Action.start, s.action);
			try t.expect(std.mem.eql(u8, s.unit, "multi-user.target") or std.mem.eql(u8, s.unit, "local-fs.target"));
			target_starts += 1;
		}
	}
	try t.expect(saw_lfs_stop);
	try t.expectEqual(@as(usize, 2), target_starts);
	try t.expectEqual(units.len + 3, seeds.len);
	// With guest data, only the targets the guest runs are started again.
	const rt = try guestRt(a, &.{"multi-user.target"}, &.{});
	var only_mu = true;
	for (try plan.seeds(a, &rt)) |s| {
		if (s.why == .target and !std.mem.eql(u8, s.unit, "multi-user.target")) only_mu = false;
	}
	try t.expect(only_mu);
	try t.expectEqual(units.len + 2, (try plan.seeds(a, &rt)).len);

	// Deterministic: a second plan of the same trees is identical.
	const again = try (try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"))).units(a);
	try t.expectEqual(units.len, again.len);
	for (units, again) |x, y| {
		try t.expectEqualStrings(x.unit, y.unit);
		try t.expectEqual(x.action, y.action);
		try t.expectEqual(x.why, y.why);
	}
}

test "planDirs: template instances defined by drop-ins, and socket activation" {
	var fx: Fx = undefined;
	try fx.init("tmpl");
	defer fx.deinit();
	const a = fx.a();

	// foo@bar is defined only by drop-ins in P and loses them in T: stopped.
	// foo@baz keeps a drop-in that changed: restarted. The template itself is
	// unchanged.
	try fx.put("P/foo@.service", "[Service]\nExecStart=/bin/foo %i\n");
	try fx.put("P/foo@bar.service.d/overrides.conf", "[Service]\nEnvironment=X=1\n");
	try fx.put("P/foo@baz.service.d/overrides.conf", "[Service]\nEnvironment=X=1\n");
	try fx.put("T/foo@.service", "[Service]\nExecStart=/bin/foo %i\n");
	try fx.put("T/foo@baz.service.d/overrides.conf", "[Service]\nEnvironment=X=2\n");

	// s.service is socket-activated by s.socket (active): its restart stops
	// and starts the socket and only stops the service.
	try fx.put("P/s.socket", "[Socket]\nListenStream=1234\n");
	try fx.put("P/s.service", "[Service]\nExecStart=/bin/s1\n");
	try fx.put("T/s.socket", "[Socket]\nListenStream=1234\n");
	try fx.put("T/s.service", "[Service]\nExecStart=/bin/s2\n");
	// n.service opts out with X-NotSocketActivated: socket restarted, and the
	// service started again too.
	try fx.put("P/n.socket", "[Socket]\nListenStream=1235\n");
	try fx.put("P/n.service", "[Service]\nExecStart=/bin/n1\n");
	try fx.put("T/n.socket", "[Socket]\nListenStream=1235\n");
	try fx.put("T/n.service", "[Service]\nExecStart=/bin/n2\nX-NotSocketActivated=true\n");

	const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
	const units = try plan.units(a);
	try expectPlanned(units, "foo@bar.service", .stop, .removed);
	try expectPlanned(units, "foo@baz.service", .restart, .changed);
	try t.expect(findUnit(units, "foo@.service") == null);
	try expectPlanned(units, "s.socket", .restart, .changed);
	try expectPlanned(units, "s.service", .stop, .changed);
	try expectPlanned(units, "n.socket", .restart, .changed);
	try expectPlanned(units, "n.service", .restart, .changed);
}

test "planDirs: aliases are never planned and share the node of the unit they name" {
	var fx: Fx = undefined;
	try fx.init("alias");
	defer fx.deinit();
	const a = fx.a();

	// The real guest's shape: networkd restarts in place (a drop-in sets
	// X-StopIfChanged=false), its D-Bus alias links to it, dbus.service is an
	// alias of dbus-broker.service, and a top-level instance link to its own
	// template is an instance, not an alias.
	inline for (.{ "P", "T" }) |side| {
		try fx.put(side ++ "/systemd-networkd.service.d/overrides.conf", "[Service]\nX-StopIfChanged=false\n");
		try fx.link(side ++ "/dbus-org.freedesktop.network1.service", "systemd-networkd.service");
		try fx.put(side ++ "/dbus-broker.service", "[Service]\nExecStart=/bin/dbus-broker\n");
		try fx.link(side ++ "/dbus.service", "dbus-broker.service");
		try fx.put(side ++ "/watcher.service", "[Unit]\nRequires=dbus-org.freedesktop.network1.service\n[Service]\nExecStart=/bin/w\n");
		try fx.put(side ++ "/foo@.service", "[Service]\nExecStart=/bin/foo %i\n");
		try fx.link(side ++ "/foo@bar.service", "foo@.service");
	}
	try fx.put("P/systemd-networkd.service", "[Unit]\nSockets=systemd-networkd.socket\n[Service]\nExecStart=/bin/networkd-1\n");
	try fx.put("T/systemd-networkd.service", "[Unit]\nSockets=systemd-networkd.socket\n[Service]\nExecStart=/bin/networkd-2\n");

	const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
	try t.expectEqualStrings("systemd-networkd.service", plan.old.aliases.get("dbus-org.freedesktop.network1.service").?);
	try t.expectEqualStrings("dbus-broker.service", plan.old.aliases.get("dbus.service").?);
	try t.expect(!plan.old.aliases.contains("foo@bar.service"));
	try t.expect(!plan.active.contains("dbus.service") and plan.active.contains("foo@bar.service"));

	const units = try plan.units(a);
	try t.expectEqual(@as(usize, 1), units.len);
	try expectPlanned(units, "systemd-networkd.service", .restart, .changed);

	// The alias is the unit's node, so an edge declared through it propagates:
	// watcher Requires= the alias and restarts with networkd.
	try t.expectEqualStrings("systemd-networkd.service", try plan.graph.nodeOf(a, "dbus-org.freedesktop.network1.service"));
	const hz = try up.closure(a, &plan.graph, try plan.seeds(a, &no_rt), &plan.new_units, &no_rt);
	try t.expect(findHazard(hz, "systemd-networkd.service") != null);
	for (hz) |h| try t.expect(!std.mem.startsWith(u8, h.unit, "dbus"));
	var watcher_restarts = false;
	for (plan.graph.links(.rev, "systemd-networkd.service")) |l| {
		if (std.mem.eql(u8, l.to, "watcher.service")) watcher_restarts = true;
	}
	try t.expect(watcher_restarts);
	// A class C refusal, not a class A one from the dbus- prefix of the alias.
	const v = up.verdict(hz, plan.sets.skip.count(), false).?;
	try t.expectEqual(up.Reason.network_config, v.reason);
	try t.expect(v.overridable);
}

test "planDirs: a missing unit directory is an error, not an empty plan" {
	var fx: Fx = undefined;
	try fx.init("nodir");
	defer fx.deinit();
	try fx.mkdir("P");
	try t.expectError(error.FileNotFound, up.planDirs(fx.a(), fx.io(), fx.path("P"), fx.path("T")));
}

// --- the re-exec predicate (main.rs restart_systemd) ---------------------------

test "reexecNeeded: a different PID 1 binary or system.conf re-executes" {
	var fx: Fx = undefined;
	try fx.init("reexec");
	defer fx.deinit();
	const a = fx.a();
	try fx.put("sysA/lib/systemd/systemd", "pid1 A");
	try fx.put("sysB/lib/systemd/systemd", "pid1 A"); // same bytes, another path
	try fx.put("confA", "[Manager]\n");
	try fx.put("confA2", "[Manager]\n");
	inline for (.{ "cur", "same", "newsys", "newconf", "nosys" }) |tl| try fx.mkdir(tl ++ "/etc/systemd");
	try fx.link("cur/systemd", fx.path("sysA"));
	try fx.link("cur/etc/systemd/system.conf", fx.path("confA"));
	try fx.link("same/systemd", fx.path("sysA"));
	try fx.link("same/etc/systemd/system.conf", fx.path("confA"));
	try fx.link("newsys/systemd", fx.path("sysB"));
	try fx.link("newsys/etc/systemd/system.conf", fx.path("confA"));
	try fx.link("newconf/systemd", fx.path("sysA"));
	try fx.link("newconf/etc/systemd/system.conf", fx.path("confA2"));
	try fx.link("nosys/etc/systemd/system.conf", fx.path("confA"));

	try t.expect(!try up.reexecNeeded(a, fx.io(), fx.path("cur"), fx.path("same")));
	// Paths are compared, not bytes (switch-ng canonicalizes and compares).
	try t.expect(try up.reexecNeeded(a, fx.io(), fx.path("cur"), fx.path("newsys")));
	try t.expect(try up.reexecNeeded(a, fx.io(), fx.path("cur"), fx.path("newconf")));
	// No new PID 1: switch-ng dies.
	try t.expectError(error.NoNewSystemd, up.reexecNeeded(a, fx.io(), fx.path("cur"), fx.path("nosys")));
	// An unresolvable current side is "/unknown", which differs.
	try t.expect(try up.reexecNeeded(a, fx.io(), fx.path("nosys"), fx.path("cur")));
}

// --- names ---------------------------------------------------------------------

test "unit names: template parts, base name, node name, path escape" {
	var arena: std.heap.ArenaAllocator = .init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();

	const tp = up.templateParts("getty@tty1.service").?;
	try t.expectEqualStrings("getty", tp.template);
	try t.expectEqualStrings("tty1", tp.instance);
	try t.expectEqualStrings("service", tp.suffix);
	try t.expectEqualStrings("", up.templateParts("user@.service").?.instance);
	try t.expect(up.templateParts("plain.service") == null);
	try t.expect(up.templateParts("trailing@") == null);
	// The last '@' followed by a '.'.
	const tp2 = up.templateParts("a@b.c@d").?;
	try t.expectEqualStrings("a", tp2.template);
	try t.expectEqualStrings("c@d", tp2.suffix);

	try t.expectEqualStrings("foo@", up.baseName("foo@.service"));
	try t.expectEqualStrings("dev-disk-by\\x2dlabel", up.baseName("dev-disk-by\\x2dlabel.device"));
	try t.expectEqualStrings("Mixed.Case", up.baseName("Mixed.Case"));

	try t.expectEqualStrings("getty@.service", try up.nodeName(a, "getty@tty1.service"));
	try t.expectEqualStrings("user-runtime-dir@.service", try up.nodeName(a, "user-runtime-dir@%i.service"));
	try t.expectEqualStrings("user@.service", try up.nodeName(a, "user@.service"));
	try t.expectEqualStrings("sshd.service", try up.nodeName(a, "sshd.service"));

	try t.expectEqualStrings("-", try up.escapePath(a, "/"));
	try t.expectEqualStrings("var-lib-foo\\x2dbar", try up.escapePath(a, "/var/lib/foo-bar"));
	try t.expectEqualStrings("root-.claude", try up.escapePath(a, "/root/.claude"));
	try t.expectEqualStrings("\\x2edot", try up.escapePath(a, "/.dot"));
	try t.expectEqualStrings("a-b", try up.escapePath(a, "//a//b/"));

	try t.expect(up.isUnitName("x.service") and up.isUnitName("-.mount") and !up.isUnitName(".service") and !up.isUnitName("x.conf") and !up.isUnitName("a/b.service"));
}

// --- classes ---------------------------------------------------------------------

test "classify: the deny-list class table" {
	const Row = struct {
		unit: []const u8,
		action: up.Action,
		direct: bool = true,
		new: bool = false,
		marked: bool = false,
		active: bool = false,
		marker: bool = false,
		unloadable: bool = false,
		want: ?up.Class,
	};
	const rows = [_]Row{
		// A: mounts and swaps, any action of the plan's own.
		.{ .unit = "data.mount", .action = .restart, .want = .a },
		.{ .unit = "data.mount", .action = .reload, .want = .a },
		.{ .unit = "-.mount", .action = .stop, .want = .a },
		.{ .unit = "dev-vdb.swap", .action = .start, .want = .a },
		.{ .unit = "home.automount", .action = .stop, .want = .a },
		// A propagated start of a mount the guest has mounted is a no-op...
		.{ .unit = "var-lib-cogbox.mount", .action = .start, .direct = false, .active = true, .want = null },
		// ...of one it has not (failed, or nothing wanted it at boot) mounts it.
		.{ .unit = "var-lib-cogbox.mount", .action = .start, .direct = false, .want = .a },
		// A start of a mount no file defines and the guest cannot load fails
		// to load; the plan's own start of one is never relaxed.
		.{ .unit = "tmp.mount", .action = .start, .direct = false, .unloadable = true, .want = null },
		.{ .unit = "tmp.mount", .action = .start, .unloadable = true, .want = .a },
		// A mount T adds (whatever the guest claims); a propagated stop or
		// restart, always.
		.{ .unit = "new.mount", .action = .start, .direct = false, .new = true, .active = true, .want = .a },
		.{ .unit = "data.mount", .action = .stop, .direct = false, .active = true, .want = .a },
		.{ .unit = "data.mount", .action = .restart, .direct = false, .active = true, .want = .a },
		// A: the boot-only units (spec section 3; cogbox-additional-dirs' stop unmounts user dirs).
		.{ .unit = "cogbox-additional-dirs.service", .action = .restart, .want = .a },
		.{ .unit = "cogbox-additional-dirs.service", .action = .start, .direct = false, .want = .a },
		.{ .unit = "rw-root-.claude.service", .action = .restart, .want = .a },
		// onceUnits names the preparation of every overlay path rw-<path>,
		// one outside /root too.
		.{ .unit = "rw-var-lib-tool.service", .action = .restart, .want = .a },
		.{ .unit = "rw-var-lib-tool.service", .action = .start, .direct = false, .want = .a },
		.{ .unit = "rw-var-lib-tool.service", .action = .start, .direct = false, .marked = true, .marker = true, .want = null },
		.{ .unit = "harness-setup-dirs.service", .action = .stop, .want = .a },
		.{ .unit = "harness-overlay-img.service", .action = .restart, .want = .a },
		.{ .unit = "resize-store-overlay.service", .action = .restart, .want = .a },
		.{ .unit = "cogbox-guest-dirs.service", .action = .restart, .want = .a },
		.{ .unit = "cogbox-guest-work-migrate.service", .action = .start, .want = .a },
		.{ .unit = "cogbox-runtime-restore.service", .action = .restart, .want = .a },
		.{ .unit = "cogbox-vm-sshd-prep.service", .action = .restart, .want = .a },
		// A propagated start of an existing boot-only unit is skipped only when
		// T carries the once-marker condition AND the guest holds the marker.
		.{ .unit = "rw-root-.hermes.service", .action = .start, .direct = false, .marked = true, .marker = true, .want = null },
		.{ .unit = "harness-setup-dirs.service", .action = .start, .direct = false, .marked = true, .marker = true, .want = null },
		.{ .unit = "cogbox-vm-sshd-prep.service", .action = .start, .direct = false, .marked = true, .marker = true, .want = null },
		// A boot unit that failed (or never ran) has no marker: its start re-runs it.
		.{ .unit = "rw-root-.hermes.service", .action = .start, .direct = false, .marked = true, .want = .a },
		.{ .unit = "harness-setup-dirs.service", .action = .start, .direct = false, .marker = true, .want = .a },
		.{ .unit = "rw-root-.hermes.service", .action = .start, .direct = false, .want = .a },
		.{ .unit = "harness-setup-dirs.service", .action = .start, .direct = false, .new = true, .marked = true, .marker = true, .want = .a },
		.{ .unit = "harness-setup-dirs.service", .action = .stop, .direct = false, .marked = true, .marker = true, .want = .a },
		.{ .unit = "rw-root-.hermes.service", .action = .restart, .direct = false, .marked = true, .marker = true, .want = .a },
		.{ .unit = "cogbox-guest-dirs.service", .action = .start, .marked = true, .marker = true, .want = .a },
		// A boot unit the guest still runs (RemainAfterExit) starts as a no-op.
		.{ .unit = "cogbox-additional-dirs.service", .action = .start, .direct = false, .active = true, .want = null },
		// A: a change to cogbox-reply-route itself, and a stop or restart of
		// it reached over an edge (its stop deletes the reply table); a
		// propagated start or reload leaves the table loaded.
		.{ .unit = "cogbox-reply-route.service", .action = .restart, .want = .a },
		.{ .unit = "cogbox-reply-route.service", .action = .restart, .direct = false, .active = true, .want = .a },
		.{ .unit = "cogbox-reply-route.service", .action = .stop, .direct = false, .active = true, .want = .a },
		.{ .unit = "cogbox-reply-route.service", .action = .start, .direct = false, .want = null },
		.{ .unit = "cogbox-reply-route.service", .action = .reload, .direct = false, .active = true, .want = null },
		// A: a dbus restart or stop; its reload and a (no-op) start are allowed.
		.{ .unit = "dbus.service", .action = .restart, .want = .a },
		.{ .unit = "dbus.socket", .action = .stop, .direct = false, .want = .a },
		.{ .unit = "dbus-broker.service", .action = .restart, .want = .a },
		.{ .unit = "dbus.service", .action = .reload, .want = null },
		.{ .unit = "dbus.socket", .action = .start, .direct = false, .want = null },
		// B: sessions and containers.
		.{ .unit = "sshd.service", .action = .restart, .want = .b },
		.{ .unit = "sshd.socket", .action = .stop, .want = .b },
		.{ .unit = "sshd@0-1.2.3.4:22.service", .action = .stop, .want = .b },
		.{ .unit = "docker.service", .action = .restart, .want = .b },
		.{ .unit = "docker.service", .action = .start, .direct = false, .want = .b },
		// Starting the running docker (a plugin unit Requires= it) is a no-op;
		// its restart is not.
		.{ .unit = "docker.service", .action = .start, .direct = false, .active = true, .want = null },
		.{ .unit = "docker.service", .action = .restart, .direct = false, .active = true, .want = .b },
		.{ .unit = "docker.socket", .action = .restart, .want = .b },
		.{ .unit = "containerd.service", .action = .start, .want = .b },
		.{ .unit = "podman.service", .action = .restart, .want = .b },
		// The socket-activated API service idles out after 5 s: a start of
		// it propagated from a plugin unit is no hazard, running or not. A
		// change to its own unit, a start of it T adds, and its stop or
		// restart over an edge still are; so is any start of its socket.
		.{ .unit = "podman.service", .action = .start, .direct = false, .want = null },
		.{ .unit = "podman.service", .action = .start, .want = .b },
		.{ .unit = "podman.service", .action = .start, .direct = false, .new = true, .want = .b },
		.{ .unit = "podman.service", .action = .stop, .direct = false, .active = true, .want = .b },
		.{ .unit = "podman.service", .action = .restart, .direct = false, .active = true, .want = .b },
		.{ .unit = "podman.socket", .action = .start, .direct = false, .want = .b },
		.{ .unit = "podman.socket", .action = .start, .want = .b },
		.{ .unit = "podman-restart.service", .action = .restart, .want = .b },
		// A plugin's own oci-containers unit, and other podman-* helpers, are not.
		.{ .unit = "podman-obs.service", .action = .restart, .want = null },
		.{ .unit = "podman-auto-update.service", .action = .start, .want = null },
		.{ .unit = "systemd-resolved.service", .action = .restart, .want = .b },
		.{ .unit = "systemd-logind.service", .action = .restart, .want = .b },
		.{ .unit = "systemd-logind.service", .action = .stop, .direct = false, .want = .b },
		.{ .unit = "systemd-logind.service", .action = .reload, .want = null },
		// A start of logind (linger-users Requires= it) only brings logins up.
		.{ .unit = "systemd-logind.service", .action = .start, .direct = false, .want = null },
		.{ .unit = "systemd-logind.service", .action = .start, .want = null },
		.{ .unit = "firewall.service", .action = .restart, .want = .b },
		.{ .unit = "firewall.service", .action = .start, .direct = false, .want = .b },
		.{ .unit = "firewall.service", .action = .reload, .want = null },
		// C: network, any action, a reload included.
		.{ .unit = "systemd-networkd.service", .action = .reload, .want = .c },
		.{ .unit = "systemd-networkd.service", .action = .start, .direct = false, .want = .c },
		.{ .unit = "systemd-networkd.service", .action = .start, .direct = false, .active = true, .want = null },
		.{ .unit = "systemd-networkd.socket", .action = .restart, .want = .c },
		.{ .unit = "nftables.service", .action = .reload, .want = .c },
		.{ .unit = "nftables.service", .action = .restart, .want = .c },
		// Skipped: the login-session units, any change and any propagation.
		.{ .unit = "user@.service", .action = .reload, .want = .skip },
		.{ .unit = "user@1000.service", .action = .restart, .direct = false, .want = .skip },
		// ...except a propagated start of a running one (a rootless container
		// unit Requires= user@<uid>): a no-op.
		.{ .unit = "user@1000.service", .action = .start, .direct = false, .active = true, .want = null },
		.{ .unit = "user@1000.service", .action = .start, .direct = false, .want = .skip },
		.{ .unit = "user@1000.service", .action = .start, .active = true, .want = .skip },
		.{ .unit = "getty@.service", .action = .stop, .want = .skip },
		.{ .unit = "serial-getty@ttyS0.service", .action = .restart, .want = .skip },
		.{ .unit = "autovt@.service", .action = .restart, .want = .skip },
		.{ .unit = "container-getty@.service", .action = .restart, .want = .skip },
		.{ .unit = "console-getty.service", .action = .restart, .want = .skip },
		.{ .unit = "systemd-user-sessions.service", .action = .restart, .want = .skip },
		// Allowed (spec 4.1): plugin units, the brain, the idempotent oneshots,
		// nix-daemon, the sysinit reactivation units, the wait-online unit.
		.{ .unit = "obs-plugin.service", .action = .restart, .want = null },
		.{ .unit = "cogbox-brain-materialize.service", .action = .restart, .want = null },
		.{ .unit = "cogbox-environment.service", .action = .restart, .want = null },
		.{ .unit = "sshd-keygen.service", .action = .restart, .want = null },
		.{ .unit = "linger-users.service", .action = .restart, .want = null },
		.{ .unit = "suid-sgid-wrappers.service", .action = .restart, .want = null },
		.{ .unit = "systemd-sysctl.service", .action = .restart, .want = null },
		.{ .unit = "systemd-tmpfiles-resetup.service", .action = .restart, .want = null },
		.{ .unit = "systemd-modules-load.service", .action = .restart, .want = null },
		.{ .unit = "nix-daemon.service", .action = .restart, .want = null },
		.{ .unit = "systemd-networkd-wait-online.service", .action = .restart, .want = null },
		.{ .unit = "dockerish.service", .action = .restart, .want = null },
	};
	for (rows) |r| {
		const got = up.classify(r.unit, r.action, .{ .direct = r.direct, .is_new = r.new, .once_marked = r.marked, .active = r.active, .marker = r.marker, .unloadable = r.unloadable });
		if (got != r.want) {
			std.debug.print("classify({s}, {s}, direct={any}, new={any}, marked={any}, active={any}, marker={any}, unloadable={any}) = {any}, want {any}\n", .{ r.unit, r.action.name(), r.direct, r.new, r.marked, r.active, r.marker, r.unloadable, got, r.want });
			return error.TestExpectedEqual;
		}
	}

	// Reasons and overridability: only B, C and D can be forced.
	try t.expectEqual(up.Reason.restart_only_units, up.Class.a.reason());
	try t.expectEqual(up.Reason.disruptive_units, up.Class.b.reason());
	try t.expectEqual(up.Reason.network_config, up.Class.c.reason());
	try t.expectEqual(up.Reason.systemd_reexec, up.Class.d.reason());
	try t.expectEqual(up.Reason.skipped_units, up.Class.skip.reason());
	try t.expect(!up.Reason.restart_only_units.overridable());
	try t.expect(!up.Reason.skipped_units.overridable());
	try t.expect(up.Reason.disruptive_units.overridable());
	try t.expect(up.Reason.network_config.overridable());
	try t.expect(up.Reason.systemd_reexec.overridable());
}

test "verdict: the first never-overridable reason wins and a mix is not overridable" {
	const h = struct {
		fn of(c: up.Class) up.Hazard {
			return .{ .class = c, .unit = "x.service", .action = .restart, .path = &.{}, .why = .changed };
		}
	};
	try t.expect(up.verdict(&.{}, 0, false) == null);
	const only_b = up.verdict(&.{h.of(.b)}, 0, false).?;
	try t.expectEqual(up.Reason.disruptive_units, only_b.reason);
	try t.expect(only_b.overridable);
	const c_and_d = up.verdict(&.{h.of(.c)}, 0, true).?;
	try t.expectEqual(up.Reason.network_config, c_and_d.reason);
	try t.expect(c_and_d.overridable);
	const d = up.verdict(&.{}, 0, true).?;
	try t.expectEqual(up.Reason.systemd_reexec, d.reason);
	try t.expect(d.overridable);
	const mixed = up.verdict(&.{ h.of(.b), h.of(.a), h.of(.c) }, 0, true).?;
	try t.expectEqual(up.Reason.restart_only_units, mixed.reason);
	try t.expect(!mixed.overridable);
	const skipped = up.verdict(&.{h.of(.b)}, 1, false).?;
	try t.expectEqual(up.Reason.skipped_units, skipped.reason);
	try t.expect(!skipped.overridable);
	const skip_hazard = up.verdict(&.{ h.of(.c), h.of(.skip) }, 0, false).?;
	try t.expectEqual(up.Reason.skipped_units, skip_hazard.reason);
	try t.expect(!skip_hazard.overridable);
	const a_and_skip = up.verdict(&.{h.of(.skip)}, 2, false).?;
	try t.expectEqual(up.Reason.skipped_units, a_and_skip.reason);
	const a_first = up.verdict(&.{ h.of(.skip), h.of(.a) }, 2, false).?;
	try t.expectEqual(up.Reason.restart_only_units, a_first.reason);
}

// --- the propagation closure -------------------------------------------------------

test "closure: every edge kind propagates the action the spec names, with its path" {
	var arena: std.heap.ArenaAllocator = .init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	var g: up.Graph = .{};
	var none: up.StrSet = .empty;

	// Reverse stop/restart: X Requires=/BindsTo=/PartOf= U, X.requires/U,
	// StopPropagatedFrom=, U's PropagatesStopTo=.
	try g.addDecl(a, "docker.service", .requires, "plug.service");
	try g.addDecl(a, "sshd.service", .binds_to, "plug2.service");
	try g.addDecl(a, "systemd-resolved.service", .part_of, "plug3.service");
	try g.addDecl(a, "containerd.service", .requires_dir, "plug4.service");
	try g.addDecl(a, "podman.service", .stop_propagated_from, "plug5.service");
	try g.addDecl(a, "plug6.service", .propagates_stop_to, "firewall.service");
	inline for (.{
		.{ "plug.service", "docker.service", up.Edge.requires },
		.{ "plug2.service", "sshd.service", up.Edge.binds_to },
		.{ "plug3.service", "systemd-resolved.service", up.Edge.part_of },
		.{ "plug4.service", "containerd.service", up.Edge.requires_dir },
		.{ "plug5.service", "podman.service", up.Edge.stop_propagated_from },
		.{ "plug6.service", "firewall.service", up.Edge.propagates_stop_to },
	}) |v| {
		const hz = try up.closure(a, &g, &.{.{ .unit = v[0], .action = .restart, .why = .changed }}, &none, &no_rt);
		const hit = findHazard(hz, v[1]) orelse return error.TestExpectedEqual;
		try t.expectEqual(up.Class.b, hit.class);
		try t.expectEqual(up.Action.restart, hit.action);
		try t.expectEqual(@as(usize, 2), hit.path.len);
		try t.expectEqualStrings(v[0], hit.path[0].unit);
		try t.expect(hit.path[0].edge == null);
		try t.expectEqual(v[2], hit.path[1].edge.?);
		// A stop propagates as a stop.
		const st = try up.closure(a, &g, &.{.{ .unit = v[0], .action = .stop, .why = .removed }}, &none, &no_rt);
		try t.expectEqual(up.Action.stop, (findHazard(st, v[1]) orelse return error.TestExpectedEqual).action);
		// A start does not travel a reverse edge.
		const sa = try up.closure(a, &g, &.{.{ .unit = v[0], .action = .start, .why = .new }}, &none, &no_rt);
		try t.expect(findHazard(sa, v[1]) == null);
	}

	// Forward start, transitively: the new plugin unit wants network-online,
	// which wants wait-online, which requires networkd.
	try g.addDecl(a, "obs-plugin.service", .wants, "network-online.target");
	try g.addDecl(a, "network-online.target", .wants_dir, "systemd-networkd-wait-online.service");
	try g.addDecl(a, "systemd-networkd-wait-online.service", .requires, "systemd-networkd.service");
	const fw = try up.closure(a, &g, &.{.{ .unit = "obs-plugin.service", .action = .start, .why = .new }}, &none, &no_rt);
	const nd = findHazard(fw, "systemd-networkd.service") orelse return error.TestExpectedEqual;
	try t.expectEqual(up.Class.c, nd.class);
	try t.expectEqual(up.Action.start, nd.action);
	try t.expectEqual(@as(usize, 4), nd.path.len);
	try t.expectEqual(up.Edge.wants, nd.path[1].edge.?);
	try t.expectEqual(up.Edge.wants_dir, nd.path[2].edge.?);
	try t.expectEqual(up.Edge.requires, nd.path[3].edge.?);
	try t.expectEqual(up.Why.new, nd.why);
	// A reload does not travel a forward edge.
	try t.expectEqual(@as(usize, 0), (try up.closure(a, &g, &.{.{ .unit = "obs-plugin.service", .action = .reload, .why = .changed }}, &none, &no_rt)).len);

	// Conflicts, in both directions: starting either one stops the other.
	try g.addDecl(a, "rogue.service", .conflicts, "sshd.service");
	try g.addDecl(a, "docker.service", .conflicts, "rogue2.service");
	const c1 = findHazard(try up.closure(a, &g, &.{.{ .unit = "rogue.service", .action = .start, .why = .new }}, &none, &no_rt), "sshd.service") orelse return error.TestExpectedEqual;
	try t.expectEqual(up.Action.stop, c1.action);
	const c2 = findHazard(try up.closure(a, &g, &.{.{ .unit = "rogue2.service", .action = .restart, .why = .changed }}, &none, &no_rt), "docker.service") orelse return error.TestExpectedEqual;
	try t.expectEqual(up.Action.stop, c2.action);

	// Reload: PropagatesReloadTo= and ReloadPropagatedFrom=.
	try g.addDecl(a, "r.service", .propagates_reload_to, "nftables.service");
	try g.addDecl(a, "systemd-networkd.service", .reload_propagated_from, "r2.service");
	const r1 = findHazard(try up.closure(a, &g, &.{.{ .unit = "r.service", .action = .reload, .why = .changed }}, &none, &no_rt), "nftables.service") orelse return error.TestExpectedEqual;
	try t.expectEqual(up.Action.reload, r1.action);
	try t.expect(findHazard(try up.closure(a, &g, &.{.{ .unit = "r2.service", .action = .reload, .why = .changed }}, &none, &no_rt), "systemd-networkd.service") != null);

	// Runtime reverse edges from the guest add reachability (RequiredBy=).
	try g.addRuntimeEdge(a, "plug7.service", .rt_required_by, "docker.service");
	try t.expect(findHazard(try up.closure(a, &g, &.{.{ .unit = "plug7.service", .action = .restart, .why = .changed }}, &none, &no_rt), "docker.service") != null);

	// Template instances fold into their template: a restart of
	// user-runtime-dir@1000 reaches user@.service, which BindsTo= it by specifier.
	try g.addDecl(a, "user@.service", .binds_to, "user-runtime-dir@%i.service");
	const sess = findHazard(try up.closure(a, &g, &.{.{ .unit = "user-runtime-dir@1000.service", .action = .restart, .why = .changed }}, &none, &no_rt), "user@.service") orelse return error.TestExpectedEqual;
	try t.expectEqual(up.Class.skip, sess.class);
}

test "closure: a seed is its own hazard; mounts the guest runs are not; cycles terminate" {
	var arena: std.heap.ArenaAllocator = .init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	var g: up.Graph = .{};
	var new_units: up.StrSet = .empty;
	try new_units.put(a, "fresh.mount", {});
	const mounted = try guestRt(a, &.{"var-lib-cogbox.mount"}, &.{});

	// The brain Requires= the state mount: its restart must not refuse while
	// the mount is up...
	try g.addDecl(a, "cogbox-brain-materialize.service", .requires, "var-lib-cogbox.mount");
	try t.expectEqual(@as(usize, 0), (try up.closure(a, &g, &.{.{ .unit = "cogbox-brain-materialize.service", .action = .restart, .why = .changed }}, &new_units, &mounted)).len);
	// ...and must when it is not (it failed at boot): the restart mounts it.
	const down = try up.closure(a, &g, &.{.{ .unit = "cogbox-brain-materialize.service", .action = .restart, .why = .changed }}, &new_units, &no_rt);
	try t.expectEqual(@as(usize, 1), down.len);
	try t.expectEqualStrings("var-lib-cogbox.mount", down[0].unit);
	try t.expectEqual(up.Class.a, down[0].class);
	try t.expectEqual(up.Action.start, down[0].action);
	// The mount restarting is a hazard (the seed itself); the brain, which
	// Requires= it, restarts with it (allowed) and starts it again (a no-op).
	const mr = try up.closure(a, &g, &.{.{ .unit = "var-lib-cogbox.mount", .action = .restart, .why = .changed }}, &new_units, &mounted);
	try t.expectEqual(@as(usize, 1), mr.len);
	try t.expectEqual(up.Class.a, mr[0].class);
	try t.expectEqual(@as(usize, 1), mr[0].path.len);
	// A new mount the brain pulls in is a hazard.
	try g.addDecl(a, "cogbox-brain-materialize.service", .wants, "fresh.mount");
	const fm = findHazard(try up.closure(a, &g, &.{.{ .unit = "cogbox-brain-materialize.service", .action = .restart, .why = .changed }}, &new_units, &mounted), "fresh.mount") orelse return error.TestExpectedEqual;
	try t.expectEqual(up.Action.start, fm.action);

	// linger-users Requires= logind, and every switch re-runs it (an induced
	// start): starting the running logind is no hazard, so a plain plugin
	// change is not refused as disruptive_units (seen in checks.cogbox-vm
	// phase LA). Its restart still is.
	try g.addDecl(a, "linger-users.service", .requires, "systemd-logind.service");
	try t.expectEqual(@as(usize, 0), (try up.closure(a, &g, &.{.{ .unit = "linger-users.service", .action = .start, .why = .induced }}, &new_units, &no_rt)).len);
	try t.expectEqual(@as(usize, 0), (try up.closure(a, &g, &.{.{ .unit = "linger-users.service", .action = .restart, .why = .changed }}, &new_units, &no_rt)).len);
	const lr = try up.closure(a, &g, &.{.{ .unit = "systemd-logind.service", .action = .restart, .why = .changed }}, &new_units, &no_rt);
	try t.expect(findHazard(lr, "systemd-logind.service") != null);

	// A cycle (A Requires= B, B Requires= A) terminates, each state once.
	try g.addDecl(a, "cyc-a.service", .requires, "cyc-b.service");
	try g.addDecl(a, "cyc-b.service", .requires, "cyc-a.service");
	try g.addDecl(a, "cyc-b.service", .requires, "docker.service");
	const cy = try up.closure(a, &g, &.{.{ .unit = "cyc-a.service", .action = .restart, .why = .changed }}, &new_units, &no_rt);
	try t.expectEqual(@as(usize, 1), cy.len);
	try t.expectEqualStrings("docker.service", cy[0].unit);

	// Deterministic order: by unit, then action.
	const multi = try up.closure(a, &g, &.{
		.{ .unit = "sshd.service", .action = .restart, .why = .changed },
		.{ .unit = "docker.service", .action = .stop, .why = .removed },
		.{ .unit = "docker.service", .action = .start, .why = .new },
	}, &new_units, &no_rt);
	try t.expectEqual(@as(usize, 3), multi.len);
	try t.expectEqualStrings("docker.service", multi[0].unit);
	try t.expectEqual(up.Action.stop, multi[0].action);
	try t.expectEqual(up.Action.start, multi[1].action);
	try t.expectEqualStrings("sshd.service", multi[2].unit);
}

test "plan to verdict over unit directories: edges come from files, links and drop-ins of P and T" {
	var fx: Fx = undefined;
	try fx.init("e2e");
	defer fx.deinit();
	const a = fx.a();

	// Base units common to P and T.
	inline for (.{ "P", "T" }) |side| {
		try fx.put(side ++ "/multi-user.target", "[Unit]\nDescription=Multi-User\n");
		try fx.put(side ++ "/docker.service", "[Service]\nExecStart=/bin/dockerd\n");
		try fx.put(side ++ "/sshd.service", "[Unit]\nRequires=cogbox-vm-sshd-prep.service\n[Service]\nExecStart=/bin/sshd\n");
		try fx.put(side ++ "/cogbox-vm-sshd-prep.service", "[Service]\nType=oneshot\nExecStart=/bin/prep\n");
		try fx.put(side ++ "/data.mount", "[Mount]\nWhat=/dev/vdc\nWhere=/data\n");
		try fx.put(side ++ "/local-fs.target", "[Unit]\nX-StopOnReconfiguration=true\n");
	}
	try fx.put("P/cogbox-brain-materialize.service", "[Unit]\nRequires=var-lib-cogbox.mount\n[Service]\nExecStart=/nix/store/brain-1\n");
	try fx.put("T/cogbox-brain-materialize.service", "[Unit]\nRequires=var-lib-cogbox.mount\n[Service]\nExecStart=/nix/store/brain-2\n");

	// The guest: the targets, sshd and both mounts run; docker is stopped.
	const rt = try guestRt(a, &.{ "multi-user.target", "local-fs.target", "sshd.service", "var-lib-cogbox.mount", "data.mount" }, &.{});

	// A clean plan: only the brain restarts. Allowed.
	{
		const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
		const hz = try up.closure(a, &plan.graph, try plan.seeds(a, &rt), &plan.new_units, &rt);
		try t.expectEqual(@as(usize, 0), hz.len);
		try t.expect(up.verdict(hz, plan.sets.skip.count(), false) == null);
	}

	// A new plugin unit wanted by multi-user.target that Requires= docker and
	// RequiresMountsFor=/data: the stopped docker is a class B hazard
	// (overridable), the mounted data.mount's start is not.
	try fx.put("T/obs-plugin.service", "[Unit]\nRequires=docker.service\nRequiresMountsFor=/data/obs\n[Service]\nExecStart=/bin/obs\n");
	try fx.link("T/multi-user.target.wants/obs-plugin.service", "../obs-plugin.service");
	{
		const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
		try expectPlanned(try plan.units(a), "obs-plugin.service", .start, .new);
		// With docker running, starting it is a no-op: no hazard at all.
		const running = try guestRt(a, &.{ "multi-user.target", "local-fs.target", "sshd.service", "var-lib-cogbox.mount", "data.mount", "docker.service" }, &.{});
		try t.expectEqual(@as(usize, 0), (try up.closure(a, &plan.graph, try plan.seeds(a, &running), &plan.new_units, &running)).len);
		const hz = try up.closure(a, &plan.graph, try plan.seeds(a, &rt), &plan.new_units, &rt);
		try t.expectEqual(@as(usize, 1), hz.len);
		try t.expectEqualStrings("docker.service", hz[0].unit);
		try t.expectEqual(up.Class.b, hz[0].class);
		try t.expectEqualStrings("obs-plugin.service", hz[0].path[0].unit);
		const v = up.verdict(hz, plan.sets.skip.count(), false).?;
		try t.expectEqual(up.Reason.disruptive_units, v.reason);
		try t.expect(v.overridable);
		// The mount edge was resolved from the path against P/T's unit files.
		var saw = false;
		for (plan.graph.links(.fwd, "obs-plugin.service")) |l| {
			if (std.mem.eql(u8, l.to, "data.mount") and l.edge == .requires_mounts_for) saw = true;
		}
		try t.expect(saw);
	}

	// The plugin also changes the prep unit sshd Requires= (through a drop-in):
	// prep is class A and sshd, restarted with it, class B: not overridable.
	try fx.put("T/cogbox-vm-sshd-prep.service.d/obs.conf", "[Service]\nEnvironment=OBS=1\n");
	{
		const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
		const hz = try up.closure(a, &plan.graph, try plan.seeds(a, &rt), &plan.new_units, &rt);
		const prep = findHazard(hz, "cogbox-vm-sshd-prep.service") orelse return error.TestExpectedEqual;
		try t.expectEqual(up.Class.a, prep.class);
		const sshd = findHazard(hz, "sshd.service") orelse return error.TestExpectedEqual;
		try t.expectEqual(up.Class.b, sshd.class);
		try t.expectEqual(up.Edge.requires, sshd.path[sshd.path.len - 1].edge.?);
		const v = up.verdict(hz, plan.sets.skip.count(), false).?;
		try t.expectEqual(up.Reason.restart_only_units, v.reason);
		try t.expect(!v.overridable);
	}

	// A unit that Requires= local-fs.target is stopped by the reconfiguration
	// stop switch-ng performs on every switch.
	try fx.put("P/needs-lfs.service", "[Unit]\nRequires=local-fs.target\n[Service]\nExecStart=/bin/x\n");
	try fx.put("T/needs-lfs.service", "[Unit]\nRequires=local-fs.target\n[Service]\nExecStart=/bin/x\n");
	try fx.put("P/harness-setup-dirs.service", "[Unit]\nRequires=needs-lfs.service\n[Service]\nExecStart=/bin/h\n");
	try fx.put("T/harness-setup-dirs.service", "[Unit]\nRequires=needs-lfs.service\n[Service]\nExecStart=/bin/h\n");
	{
		const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
		const hz = try up.closure(a, &plan.graph, try plan.seeds(a, &rt), &plan.new_units, &rt);
		const h = findHazard(hz, "harness-setup-dirs.service") orelse return error.TestExpectedEqual;
		try t.expectEqual(up.Action.stop, h.action);
		try t.expectEqual(up.Why.reconfigured, h.why);
		try t.expectEqualStrings("local-fs.target", h.path[0].unit);
	}
}

test "plan to verdict: the brain's restart reaches once-marked boot units through its mounts, which refuse unless the guest holds their markers" {
	var fx: Fx = undefined;
	try fx.init("brain");
	defer fx.deinit();
	const a = fx.a();
	const marker = "[Unit]\nConditionPathExists=" ++ up.once_condition ++ "\n";

	// The shape of a real VM guest: the brain Requires= the harness mount,
	// whose .requires/ holds its rw- preparation unit and whose .wants/ holds
	// harness-setup-dirs, both once-marked (the marker arrives as a drop-in).
	inline for (.{ "P", "T" }) |side| {
		try fx.put(side ++ "/root-.hermes.mount", "[Mount]\nWhat=overlay\nWhere=/root/.hermes\n");
		try fx.put(side ++ "/rw-root-.hermes.service", "[Service]\nType=oneshot\nExecStart=/bin/rw\n");
		try fx.put(side ++ "/rw-root-.hermes.service.d/once.conf", marker);
		try fx.link(side ++ "/root-.hermes.mount.requires/rw-root-.hermes.service", "../rw-root-.hermes.service");
		try fx.put(side ++ "/harness-setup-dirs.service", "[Service]\nType=oneshot\nRemainAfterExit=true\nExecStart=/bin/h\n");
		try fx.link(side ++ "/root-.hermes.mount.wants/harness-setup-dirs.service", "../harness-setup-dirs.service");
	}
	try fx.put("T/harness-setup-dirs.service.d/once.conf", marker);
	try fx.put("P/harness-setup-dirs.service.d/once.conf", marker);
	try fx.put("P/cogbox-brain-materialize.service", "[Unit]\nRequires=var-lib-cogbox.mount root-.hermes.mount\n[Service]\nExecStart=/nix/store/brain-1\n");
	try fx.put("T/cogbox-brain-materialize.service", "[Unit]\nRequires=var-lib-cogbox.mount root-.hermes.mount\n[Service]\nExecStart=/nix/store/brain-2\n");

	// A healthy boot: both mounts are up and cogbox-boot-settled wrote both
	// markers.
	const healthy = try guestRt(a, &.{ "root-.hermes.mount", "var-lib-cogbox.mount" }, &.{ "rw-root-.hermes", "harness-setup-dirs" });
	{
		const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
		try t.expect(plan.graph.once_marked.contains("rw-root-.hermes.service"));
		try t.expect(plan.graph.once_marked.contains("harness-setup-dirs.service"));
		const hz = try up.closure(a, &plan.graph, try plan.seeds(a, &healthy), &plan.new_units, &healthy);
		try t.expectEqual(@as(usize, 0), hz.len);
		try t.expect(up.verdict(hz, plan.sets.skip.count(), false) == null);
	}

	// A degraded boot where harness-setup-dirs failed: the mount (which only
	// Wants= it) came up, but no marker was written, so the brain's restart
	// would run it again over the harness directories in use.
	{
		const rt = try guestRt(a, &.{ "root-.hermes.mount", "var-lib-cogbox.mount" }, &.{"rw-root-.hermes"});
		const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
		const hz = try up.closure(a, &plan.graph, try plan.seeds(a, &rt), &plan.new_units, &rt);
		try t.expectEqual(@as(usize, 1), hz.len);
		try t.expectEqualStrings("harness-setup-dirs.service", hz[0].unit);
		try t.expectEqual(up.Class.a, hz[0].class);
		try t.expectEqual(up.Reason.restart_only_units, up.verdict(hz, 0, false).?.reason);
	}

	// A degraded boot where the overlay prep rw-root-.hermes failed: no marker,
	// and the mount it prepares failed with it. The brain's restart would
	// mount the overlay over /root/.hermes live.
	{
		const rt = try guestRt(a, &.{"var-lib-cogbox.mount"}, &.{"harness-setup-dirs"});
		const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
		const hz = try up.closure(a, &plan.graph, try plan.seeds(a, &rt), &plan.new_units, &rt);
		const m = findHazard(hz, "root-.hermes.mount") orelse return error.TestExpectedEqual;
		try t.expectEqual(up.Action.start, m.action);
		try t.expectEqual(up.Class.a, m.class);
		try t.expect(findHazard(hz, "rw-root-.hermes.service") != null);
		try t.expectEqual(up.Reason.restart_only_units, up.verdict(hz, 0, false).?.reason);
	}

	// T drops harness-setup-dirs' marker condition: its start would re-run boot
	// work although the guest holds the marker.
	try std.Io.Dir.cwd().deleteFile(fx.io(), fx.path("T/harness-setup-dirs.service.d/once.conf"));
	{
		const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
		const hz = try up.closure(a, &plan.graph, try plan.seeds(a, &healthy), &plan.new_units, &healthy);
		const h = findHazard(hz, "harness-setup-dirs.service") orelse return error.TestExpectedEqual;
		try t.expectEqual(up.Class.a, h.class);
		try t.expectEqual(up.Action.start, h.action);
		try t.expectEqual(@as(usize, 3), h.path.len);
		try t.expectEqual(up.Edge.requires, h.path[1].edge.?);
		try t.expectEqual(up.Edge.wants_dir, h.path[2].edge.?);
		try t.expectEqual(up.Reason.restart_only_units, up.verdict(hz, 0, false).?.reason);
	}
}

test "closure: the hidden target starts pull in what the guest does not run" {
	var fx: Fx = undefined;
	try fx.init("targets");
	defer fx.deinit();
	const a = fx.a();

	// docker.service has a file in P (plugin X turned enableOnBoot off, so
	// nothing wanted it at boot and it is stopped); removing X adds only the
	// wants link back. docker is neither new nor changed: only the restart of
	// multi-user.target, which switch-ng starts after the daemon-reload,
	// reaches it.
	inline for (.{ "P", "T" }) |side| {
		try fx.put(side ++ "/multi-user.target", "[Unit]\nDescription=m\n");
		try fx.put(side ++ "/docker.service", "[Service]\nExecStart=/bin/dockerd\n");
	}
	try fx.link("T/multi-user.target.wants/docker.service", "../docker.service");
	{
		const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
		try t.expectEqual(@as(usize, 0), (try plan.units(a)).len);
		const rt = try guestRt(a, &.{"multi-user.target"}, &.{});
		const hz = try up.closure(a, &plan.graph, try plan.seeds(a, &rt), &plan.new_units, &rt);
		const d = findHazard(hz, "docker.service") orelse return error.TestExpectedEqual;
		try t.expectEqual(up.Class.b, d.class);
		try t.expectEqual(up.Action.start, d.action);
		try t.expectEqual(up.Why.target, d.why);
		try t.expectEqualStrings("multi-user.target", d.path[0].unit);
		try t.expectEqual(up.Reason.disruptive_units, up.verdict(hz, 0, false).?.reason);
		// Running docker: the start is a no-op.
		const up_rt = try guestRt(a, &.{ "multi-user.target", "docker.service" }, &.{});
		try t.expectEqual(@as(usize, 0), (try up.closure(a, &plan.graph, try plan.seeds(a, &up_rt), &plan.new_units, &up_rt)).len);
		// A target the guest does not run is not started again.
		const no_target = try guestRt(a, &.{"sshd.service"}, &.{});
		try t.expectEqual(@as(usize, 0), (try up.closure(a, &plan.graph, try plan.seeds(a, &no_target), &plan.new_units, &no_target)).len);
	}

	// Transitively: an unchanged, running plugin unit the target wants
	// Wants= the stopped docker, which every switch would start again.
	inline for (.{ "P", "T" }) |side| {
		try fx.put(side ++ "/obs-plugin.service", "[Unit]\nWants=docker.service\n[Service]\nExecStart=/bin/obs\n");
		try fx.link(side ++ "/multi-user.target.wants/obs-plugin.service", "../obs-plugin.service");
	}
	try fx.put("P/other.service", "[Service]\nExecStart=/bin/o1\n");
	try fx.put("T/other.service", "[Service]\nExecStart=/bin/o2\n");
	{
		const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
		const rt = try guestRt(a, &.{ "multi-user.target", "obs-plugin.service" }, &.{});
		const hz = try up.closure(a, &plan.graph, try plan.seeds(a, &rt), &plan.new_units, &rt);
		const d = findHazard(hz, "docker.service") orelse return error.TestExpectedEqual;
		try t.expectEqual(up.Class.b, d.class);
	}
}

test "closure: a no-op start walks on but never fires OnFailure=, and instances stay apart" {
	var arena: std.heap.ArenaAllocator = .init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	var g: up.Graph = .{};
	var none: up.StrSet = .empty;

	// local-fs.target OnFailure=emergency.target, which Conflicts= with
	// sysinit.target, which every service Requires= at runtime: following the
	// edge from the running target's no-op start would stop everything.
	try g.addDecl(a, "local-fs.target", .on_failure, "emergency.target");
	try g.addDecl(a, "emergency.target", .conflicts, "sysinit.target");
	try g.addRuntimeEdge(a, "sysinit.target", .rt_required_by, "sshd.service");
	const lfs: []const up.Seed = &.{.{ .unit = "local-fs.target", .action = .start, .why = .target }};
	const running = try guestRt(a, &.{ "local-fs.target", "sysinit.target", "sshd.service" }, &.{});
	try t.expectEqual(@as(usize, 0), (try up.closure(a, &g, lfs, &none, &running)).len);
	// A real start can fail, so there the edge is followed.
	const stopped = try guestRt(a, &.{ "sysinit.target", "sshd.service" }, &.{});
	try t.expect(findHazard(try up.closure(a, &g, lfs, &none, &stopped), "sshd.service") != null);
	// The walk goes on through a running unit: its own dependencies start.
	try g.addDecl(a, "local-fs.target", .wants, "data.mount");
	const d = findHazard(try up.closure(a, &g, lfs, &none, &running), "data.mount") orelse return error.TestExpectedEqual;
	try t.expectEqual(up.Action.start, d.action);

	// A rootless container unit Requires= its user's manager: the running
	// user@1000 starts as a no-op, the stopped user@1001 is a session change.
	try g.addDecl(a, "podman-obs.service", .requires, "user@1000.service");
	try g.addDecl(a, "podman-obs2.service", .requires, "user@1001.service");
	const users = try guestRt(a, &.{"user@1000.service"}, &.{});
	try t.expectEqual(@as(usize, 0), (try up.closure(a, &g, &.{.{ .unit = "podman-obs.service", .action = .restart, .why = .changed }}, &none, &users)).len);
	const other = findHazard(try up.closure(a, &g, &.{.{ .unit = "podman-obs2.service", .action = .restart, .why = .changed }}, &none, &users), "user@1001.service") orelse return error.TestExpectedEqual;
	try t.expectEqual(up.Class.skip, other.class);

	// A Wants= of a unit no file defines that the guest cannot load (basic.target
	// Wants=tmp.mount with no tmp.mount anywhere) starts nothing; one the
	// guest does not report as not-found might come from a generator: A.
	try g.addDecl(a, "basic.target", .wants, "tmp.mount");
	const bt: []const up.Seed = &.{.{ .unit = "basic.target", .action = .start, .why = .target }};
	var nf = try guestRt(a, &.{"basic.target"}, &.{});
	try t.expect(findHazard(try up.closure(a, &g, bt, &none, &nf), "tmp.mount") != null);
	try nf.not_found.put(a, "tmp.mount", {});
	try t.expectEqual(@as(usize, 0), (try up.closure(a, &g, bt, &none, &nf)).len);
	// A not-found claim never covers a unit a file defines.
	try g.files.put(a, "tmp.mount", {});
	try t.expect(findHazard(try up.closure(a, &g, bt, &none, &nf), "tmp.mount") != null);

	// An induced start (a runtime want of an active target the guest does not
	// run) is a propagated start: a once-marked unit with its marker is
	// skipped, a mount the guest has not mounted is A.
	try g.once_marked.put(a, "rw-root-.hermes.service", {});
	const marked = try guestRt(a, &.{"multi-user.target"}, &.{"rw-root-.hermes"});
	try t.expectEqual(@as(usize, 0), (try up.closure(a, &g, &.{.{ .unit = "rw-root-.hermes.service", .action = .start, .why = .induced }}, &none, &marked)).len);
	try t.expect(findHazard(try up.closure(a, &g, &.{.{ .unit = "root-.hermes.mount", .action = .start, .why = .induced }}, &none, &marked), "root-.hermes.mount") != null);
}

test "seeds: sysinit-reactivation.target is restarted on every switch" {
	var fx: Fx = undefined;
	try fx.init("reactivation");
	defer fx.deinit();
	const a = fx.a();
	// A unit PartOf= the reactivation target restarts with it: a deny-listed
	// one refuses although nothing about it changed.
	inline for (.{ "P", "T" }) |side| {
		try fx.put(side ++ "/sysinit-reactivation.target", "[Unit]\nDescription=r\n");
		try fx.put(side ++ "/systemd-tmpfiles-resetup.service", "[Unit]\nPartOf=sysinit-reactivation.target\n[Service]\nExecStart=/bin/t\n");
		try fx.put(side ++ "/nftables.service", "[Unit]\nPartOf=sysinit-reactivation.target\n[Service]\nExecStart=/bin/n\n");
	}
	const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
	const rt = try guestRt(a, &.{ "systemd-tmpfiles-resetup.service", "nftables.service" }, &.{});
	const seeds = try plan.seeds(a, &rt);
	var saw = false;
	for (seeds) |s| {
		if (std.mem.eql(u8, s.unit, up.reactivation_target)) {
			try t.expectEqual(up.Action.restart, s.action);
			try t.expectEqual(up.Why.target, s.why);
			saw = true;
		}
	}
	try t.expect(saw);
	const hz = try up.closure(a, &plan.graph, seeds, &plan.new_units, &rt);
	try t.expectEqual(@as(usize, 1), hz.len);
	try t.expectEqualStrings("nftables.service", hz[0].unit);
	try t.expectEqual(up.Action.restart, hz[0].action);
	try t.expectEqual(up.Class.c, hz[0].class);
}

test "fstab: the generator's mount units are graph nodes" {
	var arena: std.heap.ArenaAllocator = .init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	const ms = try up.fstabMountsOf(a,
		\\# a comment
		\\
		\\/dev/vda / ext4 defaults 0 1
		\\overlay /root/.hermes overlay lowerdir=/x,nofail 0 0
		\\/dev/vdb none swap sw 0 0
		\\tmpfs  /var/lib/with\040space  tmpfs  defaults  0  0
		\\store /nix/.ro-store/ virtiofs defaults 0 0
		\\
	);
	try t.expectEqual(@as(usize, 4), ms.len);
	try t.expectEqualStrings("-.mount", ms[0]);
	try t.expectEqualStrings("root-.hermes.mount", ms[1]);
	try t.expectEqualStrings("var-lib-with\\x20space.mount", ms[2]);
	try t.expectEqualStrings("nix-.ro\\x2dstore.mount", ms[3]);

	// planHost reads both systems' etc/fstab: the mount, which has no unit
	// file (only its .requires/ link), is a node the guest may report on, and
	// RequiresMountsFor= resolves to it.
	var fx: Fx = undefined;
	try fx.init("fstab");
	defer fx.deinit();
	const b = fx.a();
	inline for (.{ "P", "T" }) |side| {
		try fx.put(side ++ "/etc/fstab", "overlay /root/.hermes overlay nofail 0 0\n");
		try fx.put(side ++ "/etc/systemd/system/rw-root-.hermes.service", "[Service]\nType=oneshot\nExecStart=/bin/rw\n");
		try fx.link(side ++ "/etc/systemd/system/root-.hermes.mount.requires/rw-root-.hermes.service", "../rw-root-.hermes.service");
		try fx.put(side ++ "/etc/systemd/system/hermes-user.service", "[Unit]\nRequiresMountsFor=/root/.hermes/data\n[Service]\nExecStart=/bin/h\n");
	}
	const plan = try up.planHost(b, fx.io(), fx.path("P"), fx.path("T"));
	try t.expect(plan.graph.files.contains("root-.hermes.mount"));
	try t.expect(plan.graph.fstab.contains("root-.hermes.mount"));
	var saw = false;
	for (plan.graph.links(.fwd, "hermes-user.service")) |l| {
		if (std.mem.eql(u8, l.to, "root-.hermes.mount") and l.edge == .requires_mounts_for) saw = true;
	}
	try t.expect(saw);
	// The mount is not planned (tier 1 pins the fstab; it is no unit file).
	try t.expectEqual(@as(usize, 0), (try plan.units(b)).len);
}

test "userChanges: a changed, removed, reload-only or skipped user unit refuses; an added or identical one does not" {
	var fx: Fx = undefined;
	try fx.init("user");
	defer fx.deinit();
	const a = fx.a();
	inline for (.{ "P", "T" }) |side| {
		try fx.put(side ++ "/etc/systemd/system/multi-user.target", "[Unit]\nDescription=m\n");
		try fx.put(side ++ "/etc/systemd/user/default.target", "[Unit]\nDescription=d\n");
		try fx.put(side ++ "/etc/systemd/user/same.service", "[Service]\nExecStart=/bin/s\n");
	}
	// switch-ng restarts nixos-activation in every user manager on every
	// switch: never a change of the plugin's.
	try fx.put("P/etc/systemd/user/nixos-activation.service", "[Service]\nExecStart=/bin/a1\n");
	try fx.put("T/etc/systemd/user/nixos-activation.service", "[Service]\nExecStart=/bin/a2\n");
	try fx.put("T/etc/systemd/user/added.service", "[Service]\nExecStart=/bin/n\n");
	try fx.link("T/etc/systemd/user/default.target.wants/added.service", "../added.service");
	// The user bus reloads on the configDir trigger the system bus shares (a
	// plugin adding a package moves it): allowed, as the system bus's reload is.
	try fx.put("P/etc/systemd/user/dbus-broker.service", "[Unit]\nX-Restart-Triggers=/nix/store/conf-1\n[Service]\nExecStart=/bin/dbus-broker-launch\nX-ReloadIfChanged=true\n");
	try fx.put("T/etc/systemd/user/dbus-broker.service", "[Unit]\nX-Restart-Triggers=/nix/store/conf-2\n[Service]\nExecStart=/bin/dbus-broker-launch\nX-ReloadIfChanged=true\n");
	{
		const plan = try up.planHost(a, fx.io(), fx.path("P"), fx.path("T"));
		try t.expectEqual(@as(usize, 0), plan.user.len);
	}
	// Its restart is not.
	try fx.put("T/etc/systemd/user/dbus-broker.service", "[Unit]\nX-Restart-Triggers=/nix/store/conf-2\n[Service]\nExecStart=/bin/dbus-broker-launch-2\n");
	{
		const plan = try up.planHost(a, fx.io(), fx.path("P"), fx.path("T"));
		try t.expectEqual(@as(usize, 1), plan.user.len);
		try expectPlanned(plan.user, "dbus-broker.service", .restart, .user_unit);
	}
	try fx.put("T/etc/systemd/user/dbus-broker.service", "[Unit]\nX-Restart-Triggers=/nix/store/conf-2\n[Service]\nExecStart=/bin/dbus-broker-launch\nX-ReloadIfChanged=true\n");
	try fx.put("P/etc/systemd/user/changed.service", "[Service]\nExecStart=/bin/c1\n");
	try fx.put("T/etc/systemd/user/changed.service", "[Service]\nExecStart=/bin/c2\n");
	try fx.put("P/etc/systemd/user/gone.service", "[Service]\nExecStart=/bin/g\n");
	try fx.put("P/etc/systemd/user/reload.service", "[Service]\nExecStart=/bin/r\nExecReload=/bin/r1\n");
	try fx.put("T/etc/systemd/user/reload.service", "[Service]\nExecStart=/bin/r\nExecReload=/bin/r2\n");
	try fx.put("P/etc/systemd/user/stale.service", "[Service]\nExecStart=/bin/k1\nX-RestartIfChanged=false\n");
	try fx.put("T/etc/systemd/user/stale.service", "[Service]\nExecStart=/bin/k2\nX-RestartIfChanged=false\n");
	const plan = try up.planHost(a, fx.io(), fx.path("P"), fx.path("T"));
	try t.expectEqual(@as(usize, 4), plan.user.len);
	try expectPlanned(plan.user, "changed.service", .restart, .user_unit);
	try expectPlanned(plan.user, "gone.service", .stop, .user_unit);
	try expectPlanned(plan.user, "reload.service", .reload, .user_unit);
	try expectPlanned(plan.user, "stale.service", .restart, .user_unit);
	// The system plan is untouched by them.
	try t.expectEqual(@as(usize, 0), (try plan.units(a)).len);
	// A system without etc/systemd/user has no user units.
	try fx.mkdir("Q/etc/systemd/system");
	try t.expectEqual(@as(usize, 0), (try up.planHost(a, fx.io(), fx.path("Q"), fx.path("Q"))).user.len);
}

test "generatorChanges: a generator T adds, removes or retargets refuses; the same set in a rebuilt directory does not" {
	var fx: Fx = undefined;
	try fx.init("gen");
	defer fx.deinit();
	const a = fx.a();
	// The zramSwap shape: the plugin adds zram-generator to systemd.packages.
	// Its only unit is an unlinked template, so the unit plan is empty; the
	// generator writes dev-zram0.swap and swap.target.wants/ at the
	// daemon-reload, and the switch's start of swap.target swaps it on.
	try fx.put("pkg-zram/lib/systemd/system-generators/zram-generator", "#!/bin/sh\n");
	try fx.put("pkg-zram-2/lib/systemd/system-generators/zram-generator", "#!/bin/sh\n# 2\n");
	try fx.put("pkg-quadlet/lib/systemd/user-generators/podman-user-generator", "#!/bin/sh\n");
	inline for (.{ "P", "T" }) |side| {
		try fx.put(side ++ "/etc/systemd/system/multi-user.target", "[Unit]\nDescription=m\n");
		try fx.put(side ++ "/etc/systemd/system/swap.target", "[Unit]\nDescription=s\n");
		// Each side's hooks directory is its own store path (a rebuilt
		// directory); the base disables gpt-auto in both.
		try fx.link(side ++ "-gens/systemd-gpt-auto-generator", "/dev/null");
		try fx.link(side ++ "/etc/systemd/system-generators", fx.path(side ++ "-gens"));
	}
	try fx.put("T/etc/systemd/system/systemd-zram-setup@.service", "[Service]\nType=oneshot\nExecStart=/bin/zram\n");
	{
		const plan = try up.planHost(a, fx.io(), fx.path("P"), fx.path("P"));
		try t.expectEqual(@as(usize, 0), plan.generators.len);
		// The same entries in two different directories: no change.
		try t.expectEqual(@as(usize, 0), (try up.generatorChanges(a, fx.io(), fx.path("P"), fx.path("T"))).len);
	}
	try fx.link("T-gens/zram-generator", fx.path("pkg-zram/lib/systemd/system-generators/zram-generator"));
	{
		const plan = try up.planHost(a, fx.io(), fx.path("P"), fx.path("T"));
		// Nothing in the unit plan names it...
		try t.expectEqual(@as(usize, 0), (try plan.units(a)).len);
		try t.expectEqual(@as(usize, 0), plan.user.len);
		// ...but the generator set does.
		try t.expectEqual(@as(usize, 1), plan.generators.len);
		try expectPlanned(plan.generators, "system-generators/zram-generator", .start, .generator);
		// Removing it is a change too.
		const back = try up.planHost(a, fx.io(), fx.path("T"), fx.path("P"));
		try t.expectEqual(@as(usize, 1), back.generators.len);
		try expectPlanned(back.generators, "system-generators/zram-generator", .stop, .generator);
	}
	// A retarget (a new version of the package) and a dangling link that
	// changes its text are changes; a user generator counts as well.
	try fx.link("P-gens/zram-generator", fx.path("pkg-zram-2/lib/systemd/system-generators/zram-generator"));
	try fx.link("P-gens/gone-generator", "/nonexistent/a");
	try fx.link("T-gens/gone-generator", "/nonexistent/b");
	try fx.link("T-gens/same-dangling", "/nonexistent/c");
	try fx.link("P-gens/same-dangling", "/nonexistent/c");
	try fx.link("T/etc/systemd/user-generators/podman-user-generator", fx.path("pkg-quadlet/lib/systemd/user-generators/podman-user-generator"));
	const plan = try up.planHost(a, fx.io(), fx.path("P"), fx.path("T"));
	try t.expectEqual(@as(usize, 3), plan.generators.len);
	try expectPlanned(plan.generators, "system-generators/gone-generator", .restart, .generator);
	try expectPlanned(plan.generators, "system-generators/zram-generator", .restart, .generator);
	try expectPlanned(plan.generators, "user-generators/podman-user-generator", .start, .generator);
	// The same target, reached through links of its own on each side, is the same generator.
	try fx.link("P-gens/via", fx.path("pkg-zram/lib/systemd/system-generators/zram-generator"));
	try fx.link("hop", fx.path("pkg-zram/lib/systemd/system-generators/zram-generator"));
	try fx.link("T-gens/via", fx.path("hop"));
	try t.expectEqual(@as(usize, 3), (try up.generatorChanges(a, fx.io(), fx.path("P"), fx.path("T"))).len);
}

// --- tier 1: the boot shape ---------------------------------------------------------

const run_b = "#!/bin/sh\nexec qemu -kernel /nix/store/k/bzImage -initrd /nix/store/i/initrd -append 'console=ttyS0 reboot=t init=/nix/store/aaa-nixos-system/init regInfo=/nix/store/rrr-closure-info/registration rdinit=/x'\n";
const run_r = "#!/bin/sh\nexec qemu -kernel /nix/store/k/bzImage -initrd /nix/store/i/initrd -append 'console=ttyS0 reboot=t init=/nix/store/bbb-nixos-system/init regInfo=/nix/store/sss-closure-info/registration rdinit=/x'\n";

/// A runner at `name`: bin/microvm-run, and share/microvm/system -> a system
/// dir with kernel, kernel-modules, initrd links, init-interface-version and
/// etc/fstab.
fn runner(fx: *Fx, name: []const u8, script: ?[]const u8, kernel: []const u8, fstab: []const u8, iv: []const u8) !void {
	const a = fx.a();
	if (script) |s| try fx.put(try std.fmt.allocPrint(a, "{s}/bin/microvm-run", .{name}), s);
	const sys = try std.fmt.allocPrint(a, "{s}-system", .{name});
	try fx.put(try std.fmt.allocPrint(a, "{s}/etc/fstab", .{sys}), fstab);
	try fx.put(try std.fmt.allocPrint(a, "{s}/init-interface-version", .{sys}), iv);
	try fx.link(try std.fmt.allocPrint(a, "{s}/kernel", .{sys}), fx.path(kernel));
	try fx.link(try std.fmt.allocPrint(a, "{s}/kernel-modules", .{sys}), fx.path("modules"));
	try fx.link(try std.fmt.allocPrint(a, "{s}/initrd", .{sys}), fx.path("initrd"));
	try fx.link(try std.fmt.allocPrint(a, "{s}/share/microvm/system", .{name}), fx.path(sys));
}

test "maskRunner: init= and regInfo= values are masked at word starts only" {
	var arena: std.heap.ArenaAllocator = .init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	try t.expectEqualStrings(try up.maskRunner(a, run_b), try up.maskRunner(a, run_r));
	try t.expectEqualStrings(
		"x 'init=@COGBOX-MASKED@ regInfo=@COGBOX-MASKED@ rdinit=/a' \"init=@COGBOX-MASKED@\"",
		try up.maskRunner(a, "x 'init=/nix/store/a/init regInfo=/r rdinit=/a' \"init=/b\""),
	);
	try t.expectEqualStrings("init=@COGBOX-MASKED@", try up.maskRunner(a, "init=/s/init"));
	// rdinit= is not init=, so a change to it is a different boot.
	try t.expect(!std.mem.eql(u8, try up.maskRunner(a, "a rdinit=/x"), try up.maskRunner(a, "a rdinit=/y")));
}

test "bootShape: tier 1 (b) and (c) in the spec's order" {
	var fx: Fx = undefined;
	try fx.init("boot");
	defer fx.deinit();
	const a = fx.a();
	inline for (.{ "k1", "k2", "modules", "initrd" }) |d| try fx.mkdir(d);
	const fstab = "/dev/vda / ext4 defaults 0 1\n";
	const iv = "systemd 2";

	try runner(&fx, "B", run_b, "k1", fstab, iv);
	try runner(&fx, "same", run_r, "k1", fstab, iv);
	try runner(&fx, "args", "#!/bin/sh\nexec qemu -smp 4 -append 'init=/nix/store/x/init'\n", "k1", fstab, iv);
	try runner(&fx, "kern", run_r, "k2", fstab, iv);
	try runner(&fx, "fstab", run_r, "k1", "/dev/vda / ext4 defaults,noatime 0 1\n", iv);
	try runner(&fx, "iface", run_r, "k1", fstab, "systemd 3");
	try runner(&fx, "norun", null, "k1", fstab, iv);
	try fx.put("nosys/bin/microvm-run", run_r);

	const io = fx.io();
	try t.expect(try up.bootShape(a, io, fx.path("B"), fx.path("same")) == null);
	try t.expectEqual(up.BootShapeReason.boot_shape, (try up.bootShape(a, io, fx.path("B"), fx.path("args"))).?);
	try t.expectEqual(up.BootShapeReason.kernel_modules, (try up.bootShape(a, io, fx.path("B"), fx.path("kern"))).?);
	try t.expectEqual(up.BootShapeReason.fstab, (try up.bootShape(a, io, fx.path("B"), fx.path("fstab"))).?);
	try t.expectEqual(up.BootShapeReason.init_interface, (try up.bootShape(a, io, fx.path("B"), fx.path("iface"))).?);
	// Fail closed when a side cannot be read.
	try t.expectEqual(up.BootShapeReason.boot_shape, (try up.bootShape(a, io, fx.path("B"), fx.path("norun"))).?);
	try t.expectEqual(up.BootShapeReason.boot_shape, (try up.bootShape(a, io, fx.path("norun"), fx.path("B"))).?);
	try t.expectEqual(up.BootShapeReason.kernel_modules, (try up.bootShape(a, io, fx.path("B"), fx.path("nosys"))).?);
}

// --- the host plan as text (`cogbox __unitplan`) -------------------------------------

test "renderPlan: one line per planned unit, the skipped units, then reexec" {
	var fx: Fx = undefined;
	try fx.init("render");
	defer fx.deinit();
	const a = fx.a();

	try fx.put("P/multi-user.target", "[Unit]\nDescription=Multi-User\n");
	try fx.put("P/b.service", "[Service]\nExecStart=/bin/b\n");
	try fx.put("P/gone.service", "[Service]\nExecStart=/bin/g\n");
	try fx.put("P/keep.service", "[Service]\nExecStart=/bin/k\nX-RestartIfChanged=false\n");
	try fx.put("T/multi-user.target", "[Unit]\nDescription=Multi-User\n");
	try fx.put("T/b.service", "[Service]\nExecStart=/bin/b2\n");
	try fx.put("T/keep.service", "[Service]\nExecStart=/bin/k2\nX-RestartIfChanged=false\n");
	try fx.put("T/new.service", "[Service]\nExecStart=/bin/n\n");
	try fx.link("T/multi-user.target.wants/new.service", "../new.service");

	const plan = try up.planDirs(a, fx.io(), fx.path("P"), fx.path("T"));
	try t.expectEqualStrings(
		"restart b.service changed\n" ++
			"stop gone.service removed\n" ++
			"start new.service new\n" ++
			"skip keep.service\n" ++
			"reexec no\n",
		try up.renderPlan(a, &plan, false),
	);
	const yes = try up.renderPlan(a, &plan, true);
	try t.expect(std.mem.endsWith(u8, yes, "reexec yes\n"));
}
