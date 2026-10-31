// Live plugin apply: the host-side unit plan (tier 2) and the boot-shape
// comparisons (tier 1). Pure functions over directory trees: nothing here
// spawns, writes or talks to a guest; the only I/O is reading unit files,
// symlinks and a few toplevel files under the roots it is handed.
//
// TIER 2, THE UNIT PLAN. `switch-to-configuration test` decides what to stop,
// restart, reload and start by comparing the unit files of the running system
// (P) with those of the new one (T). This file is a port of that decision from
// nixpkgs' switch-to-configuration-ng (pkgs/by-name/sw/switch-to-configuration-ng
// /src/main.rs): parse_systemd_ini, parse_unit, compare_units,
// handle_modified_unit and the system half of collect_unit_changes, plus the
// re-exec predicate. Two things differ, both on purpose:
//   - switch-ng walks the units systemd reports ACTIVE; the host cannot know
//     them, so it treats every unit P holds a file for as active. That makes
//     the host plan a superset (an inactive unit gets a restart switch-ng would
//     not do), which is the safe direction: guest data may only narrow a plan
//     for units the guest owns (spec 4.11), and it is merged later (apply.zig).
//     Masks and aliases are left out of that set, as systemd leaves them out
//     of its list (an alias is listed under the unit it names, and its edges
//     are that unit's: see Listing.aliases and Graph.nodeOf).
//   - switch-ng's units_to_start of active targets is hidden bookkeeping (it
//     pulls in new units); here the new units it would pull in are named
//     explicitly (`new_starts`), because they are what the plan shows. The
//     hidden target starts are still seeds of the closure (HostPlan.seeds):
//     after the daemon-reload systemd's start transaction pulls in every
//     inactive or failed unit the targets reach in T's graph, which neither the
//     plan's units nor dry-activate name.
// The comparison is verbatim, including the INI parser's quirks (rust-ini with
// quotes on, escapes off; a key with n entries in one section is applied n
// times), because a parser that is merely "reasonable" can call two units equal
// that switch-ng restarts, and an under-counted plan is the unsafe direction.
//
// The plan then gets a propagation closure (spec section 3, tier 2 item 5):
// every unit a planned action reaches over systemd's dependency edges, so a
// plugin unit that Requires= docker.service names docker as a hazard even
// though only the plugin unit changed. Hazards are classified into the deny-list
// classes A-D and the skipped units, and `verdict` turns them into the one
// refusal the apply reports. A start reached over an edge is judged against
// what the guest reports (Runtime): it is a no-op only for a unit the guest
// runs, a boot-only unit whose once-marker the guest holds, or a unit no file
// defines that the guest cannot load. What generators write at the
// daemon-reload is in no directory read here, so any change to T's set of
// generators refuses on its own (generatorChanges).
//
// TIER 1, THE BOOT SHAPE. `test` does not reject a new kernel or initrd
// (main.rs, the init-interface check is all it does), so the host compares the
// booted runner B with the new runner R: the microvm-run script with the
// toplevel and regInfo masked, then the kernel, modules, initrd, fstab and init
// interface of the two systems. Any difference refuses, never overridably.
//
// Memory: every function takes an arena-style allocator and frees nothing
// itself. Callers run a plan in an ArenaAllocator and drop it whole.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

// --- unit names ----------------------------------------------------------------

/// The unit types switch-ng and systemd know. A directory entry is a unit only
/// when its name ends in one of these.
pub const unit_suffixes = [_][]const u8{
	".service", ".socket", ".target", ".mount", ".automount", ".swap",
	".timer",   ".path",   ".slice",  ".scope", ".device",
};

pub fn isUnitName(name: []const u8) bool {
	if (name.len == 0 or std.mem.indexOfScalar(u8, name, '/') != null) return false;
	for (unit_suffixes) |s| {
		if (name.len > s.len and std.mem.endsWith(u8, name, s)) return true;
	}
	return false;
}

pub const TemplateParts = struct {
	template: []const u8,
	instance: []const u8,
	suffix: []const u8,
};

/// main.rs TEMPLATE_UNIT_RE, `^(.*)@[^\.]*\.(.*)$`: the greedy `(.*)@` takes the
/// LAST '@' that is followed by a '.', the instance runs to the first '.' after
/// it, the suffix is everything after that. `foo@.service` matches with an
/// empty instance, exactly as the regex does.
pub fn templateParts(name: []const u8) ?TemplateParts {
	var i = name.len;
	while (i > 0) {
		i -= 1;
		if (name[i] != '@') continue;
		const dot = std.mem.indexOfScalarPos(u8, name, i + 1, '.') orelse continue;
		return .{ .template = name[0..i], .instance = name[i + 1 .. dot], .suffix = name[dot + 1 ..] };
	}
	return null;
}

/// main.rs UNIT_NAME_RE, `^(.*)\.[[:lower:]]*$`: the name without its type
/// suffix when the part after the last '.' is all lowercase; otherwise the name
/// unchanged (the regex does not match, and switch-ng keeps the name).
pub fn baseName(name: []const u8) []const u8 {
	const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return name;
	for (name[dot + 1 ..]) |c| {
		if (c < 'a' or c > 'z') return name;
	}
	return name[0..dot];
}

/// The graph's node name: a template instance (`getty@tty1.service`,
/// `user-runtime-dir@%i.service`) folds into its template (`getty@.service`),
/// so an edge a template file declares with a specifier meets the instances
/// the plan and the wants links name. Folding merges the instances of one
/// template, which only ever adds reachability (the safe direction).
pub fn nodeName(arena: Allocator, name: []const u8) Allocator.Error![]const u8 {
	const tp = templateParts(name) orelse return name;
	if (tp.instance.len == 0) return name;
	return std.mem.concat(arena, u8, &.{ tp.template, "@.", tp.suffix });
}

pub const StrSet = std.array_hash_map.String(void);

fn lessThanStr(_: void, a: []const u8, b: []const u8) bool {
	return std.mem.order(u8, a, b) == .lt;
}

/// The set's members, sorted bytewise (a fresh slice; the set is untouched).
pub fn sortedKeys(arena: Allocator, set: *const StrSet) Allocator.Error![]const []const u8 {
	const out = try arena.dupe([]const u8, set.keys());
	std.mem.sort([]const u8, out, {}, lessThanStr);
	return out;
}

fn setPut(arena: Allocator, set: *StrSet, name: []const u8) Allocator.Error!void {
	try set.put(arena, name, {});
}

// --- the INI parser (parse_systemd_ini) ----------------------------------------

pub const Values = std.ArrayList([]const u8);
/// key -> every value it was set to, in order (an empty assignment clears).
pub const Section = std.array_hash_map.String(Values);
/// section name -> its keys. [Install] is never stored.
pub const UnitInfo = std.array_hash_map.String(Section);

/// A unit file or drop-in larger than this is refused (error.UnitTooLarge):
/// the host reads files a plugin's evaluation produced, so every read is
/// capped. Real unit files are a few KiB.
pub const max_unit_file_bytes: usize = 1 << 20;
/// The values one key may accumulate in one unit. The verbatim port applies a
/// key with n entries n times (see parseSystemdIni), which is quadratic; past
/// this the unit is refused (error.UnitTooComplex) rather than letting a
/// crafted file exhaust host memory.
pub const max_values_per_key: usize = 1 << 16;

/// Rust's `char::is_whitespace` over the bytes unit files actually contain.
const ws = " \t\n\r\x0b\x0c";
const ws_inline = " \t\x0b\x0c";

const IniEntry = struct { key: []const u8, val: []const u8 };
const IniOccurrence = struct { name: []const u8, entries: std.ArrayList(IniEntry) };

/// rust-ini's parser with switch-ng's ParseOption (quotes on, escapes off, no
/// indented multi-line values, key whitespace not preserved). Each `[Section]`
/// header opens a new occurrence (a repeated header is a second occurrence of
/// the same name); keys before any header land in the general section, which
/// switch-ng ignores, so they are parsed and dropped. A key runs to the first
/// '=' or ':' (across lines, as rust-ini reads it) and is trimmed. A value
/// skips leading blanks; a value that starts with a quote takes the quoted
/// text without its quotes (and any text after the closing quote, trimmed at
/// the end); any other value runs to the end of the line, trimmed. A
/// '#'/';' where a key could start is a comment to the end of the line (rust-ini
/// refuses an indented one; this port accepts it, which only matters for a
/// file switch-ng could not parse at all). Errors where rust-ini errors: an
/// unclosed '[' or quote, a key with no '=' or ':' before EOF, and a value
/// with no key.
fn parseIni(arena: Allocator, content: []const u8) error{ OutOfMemory, UnitParse }![]IniOccurrence {
	var occs: std.ArrayList(IniOccurrence) = .empty;
	var cur: ?usize = null;
	var curkey: ?[]const u8 = null;
	var p: usize = skipWs(content, 0);
	while (p < content.len) {
		switch (content[p]) {
			';', '#' => p = std.mem.indexOfAnyPos(u8, content, p, "\n\r") orelse content.len,
			'[' => {
				const close = std.mem.indexOfScalarPos(u8, content, p + 1, ']') orelse return error.UnitParse;
				try occs.append(arena, .{ .name = std.mem.trim(u8, content[p + 1 .. close], ws), .entries = .empty });
				cur = occs.items.len - 1;
				p = close + 1;
			},
			'=', ':' => {
				const key = curkey orelse return error.UnitParse;
				if (key.len == 0) return error.UnitParse;
				const v = try parseIniValue(arena, content, p + 1);
				p = v.next;
				if (cur) |ci| try occs.items[ci].entries.append(arena, .{ .key = key, .val = v.val });
				curkey = null;
			},
			else => {
				const end = std.mem.indexOfAnyPos(u8, content, p, "=:") orelse return error.UnitParse;
				curkey = std.mem.trim(u8, content[p..end], ws);
				p = end;
			},
		}
		p = skipWs(content, p);
	}
	return occs.items;
}

fn skipWs(content: []const u8, from: usize) usize {
	var p = from;
	while (p < content.len and std.mem.indexOfScalar(u8, ws, content[p]) != null) p += 1;
	return p;
}

fn parseIniValue(arena: Allocator, content: []const u8, from: usize) error{ OutOfMemory, UnitParse }!struct { val: []const u8, next: usize } {
	var p = from;
	while (p < content.len and std.mem.indexOfScalar(u8, ws_inline, content[p]) != null) p += 1;
	var out: std.ArrayList(u8) = .empty;
	var first = true;
	while (p < content.len) {
		const c = content[p];
		if (c == '"' or c == '\'') {
			const close = std.mem.indexOfScalarPos(u8, content, p + 1, c) orelse return error.UnitParse;
			try out.appendSlice(arena, content[p + 1 .. close]);
			p = close + 1;
			first = false;
			continue;
		}
		const end = std.mem.indexOfAnyPos(u8, content, p, "\n\r") orelse content.len;
		const part = content[p..end];
		try out.appendSlice(arena, if (first) std.mem.trim(u8, part, ws) else std.mem.trimEnd(u8, part, ws));
		p = end;
		break;
	}
	return .{ .val = out.items, .next = p };
}

/// main.rs parse_systemd_ini: merge one file into `info`. For every section
/// occurrence except [Install], and for every ENTRY in it (so a key set n times
/// is processed n times, as `for (ini_key, _) in properties` does): take all of
/// that key's values in the occurrence; an empty value clears the ones before
/// it and marks the key cleared; a cleared key replaces what earlier files set,
/// an uncleared one extends it. The n-fold application is kept because it is
/// observable: `K=a` in a unit plus `K=b` in a drop-in parses differently from
/// both lines in the unit, and switch-ng restarts on that difference.
pub fn parseSystemdIni(arena: Allocator, info: *UnitInfo, content: []const u8) error{ OutOfMemory, UnitParse, UnitTooComplex }!void {
	const occs = try parseIni(arena, content);
	for (occs) |*occ| {
		if (std.mem.eql(u8, occ.name, "Install")) continue;
		const gop = try info.getOrPut(arena, occ.name);
		if (!gop.found_existing) gop.value_ptr.* = .empty;
		const section = gop.value_ptr;

		// Each distinct key with its entry count, in first-appearance order.
		// Different keys commute, so applying key by key equals entry order.
		var counts: std.array_hash_map.String(usize) = .empty;
		for (occ.entries.items) |e| {
			const c = try counts.getOrPut(arena, e.key);
			if (!c.found_existing) c.value_ptr.* = 0;
			c.value_ptr.* += 1;
		}
		for (counts.keys(), counts.values()) |key, n| {
			var new_vals: Values = .empty;
			var clear = false;
			for (occ.entries.items) |e| {
				if (!std.mem.eql(u8, e.key, key)) continue;
				if (e.val.len == 0) {
					new_vals.clearRetainingCapacity();
					clear = true;
				} else try new_vals.append(arena, e.val);
			}
			if (clear) {
				// Every application replaces with the same list: once is enough.
				try section.put(arena, key, new_vals);
				continue;
			}
			const existing_len = if (section.getPtr(key)) |ex| ex.items.len else 0;
			if (existing_len + n * new_vals.items.len > max_values_per_key) return error.UnitTooComplex;
			if (section.getPtr(key) == null) try section.put(arena, key, .empty);
			const vals = section.getPtr(key).?;
			var i: usize = 0;
			while (i < n) : (i += 1) try vals.appendSlice(arena, new_vals.items);
		}
	}
}

/// main.rs parse_systemd_bool: the LAST value of `section.key`, true for
/// 1/yes/true/on and false for anything else; `default` when the unit, the
/// section or the key is absent, or the key was cleared to no values.
pub fn parseSystemdBool(info: ?*const UnitInfo, section: []const u8, key: []const u8, default: bool) bool {
	const i = info orelse return default;
	const sec = i.getPtr(section) orelse return default;
	const vals = sec.getPtr(key) orelse return default;
	if (vals.items.len == 0) return default;
	const last = vals.items[vals.items.len - 1];
	inline for (.{ "1", "yes", "true", "on" }) |tv| {
		if (std.mem.eql(u8, last, tv)) return true;
	}
	return false;
}

// --- unit files on disk (parse_unit, unit_file_state) ---------------------------

pub const FileState = enum {
	/// Resolves to a real file.
	present,
	/// Resolves to /dev/null.
	masked,
	/// Does not exist, or is a dangling link.
	missing,

	/// UnitFileState::is_gone.
	pub fn isGone(s: FileState) bool {
		return s != .present;
	}
};

/// main.rs unit_file_state: canonicalize, /dev/null means masked, NotFound
/// means missing; any other error propagates.
pub fn fileState(arena: Allocator, io: Io, path: []const u8) !FileState {
	const real = std.Io.Dir.cwd().realPathFileAlloc(io, path, arena) catch |err| switch (err) {
		error.FileNotFound => return .missing,
		else => return err,
	};
	return if (std.mem.eql(u8, real, "/dev/null")) .masked else .present;
}

/// Rust's Path::exists: a stat that follows links succeeds (any error is false).
pub fn pathExists(io: Io, path: []const u8) bool {
	_ = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
	return true;
}

fn readUnitFile(arena: Allocator, io: Io, path: []const u8) ![]u8 {
	return std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_unit_file_bytes + 1)) catch |err| switch (err) {
		error.StreamTooLong => error.UnitTooLarge,
		else => err,
	};
}

/// main.rs unit_dropin_glob: `<unit_path>.d/*.conf`, in the glob crate's
/// (bytewise) order. A missing or non-directory `.d` yields nothing; entries
/// are not filtered by type, as the glob's are not.
pub fn dropins(arena: Allocator, io: Io, unit_path: []const u8) ![]const []const u8 {
	const ddir = try std.fmt.allocPrint(arena, "{s}.d", .{unit_path});
	var d = std.Io.Dir.cwd().openDir(io, ddir, .{ .iterate = true }) catch |err| switch (err) {
		error.FileNotFound, error.NotDir => return &.{},
		else => return err,
	};
	defer d.close(io);
	var names: std.ArrayList([]const u8) = .empty;
	var it = d.iterate();
	while (try it.next(io)) |e| {
		if (!std.mem.endsWith(u8, e.name, ".conf")) continue;
		try names.append(arena, try arena.dupe(u8, e.name));
	}
	std.mem.sort([]const u8, names.items, {}, lessThanStr);
	const out = try arena.alloc([]const u8, names.items.len);
	for (names.items, 0..) |n, i| out[i] = try std.fmt.allocPrint(arena, "{s}/{s}", .{ ddir, n });
	return out;
}

/// main.rs parse_unit: the base file (a masked one reads as empty), its
/// drop-ins, and, for a template instance, the instance's own drop-ins. A
/// missing base file is an error, as in switch-ng.
pub fn parseUnit(arena: Allocator, io: Io, unit_file: []const u8, base_unit_file: []const u8) !UnitInfo {
	var info: UnitInfo = .empty;
	try parseSystemdIni(arena, &info, try readUnitFile(arena, io, base_unit_file));
	for (try dropins(arena, io, base_unit_file)) |d| try parseSystemdIni(arena, &info, try readUnitFile(arena, io, d));
	if (!std.mem.eql(u8, unit_file, base_unit_file)) {
		for (try dropins(arena, io, unit_file)) |d| try parseSystemdIni(arena, &info, try readUnitFile(arena, io, d));
	}
	return info;
}

// --- compare_units ------------------------------------------------------------

pub const Comparison = enum { equal, needs_restart, needs_reload };

/// [Unit] keys whose change never restarts (main.rs unit_section_ignores).
const unit_section_ignores = [_][]const u8{
	"X-Reload-Triggers", "Description",      "Documentation",    "OnFailure",
	"OnSuccess",         "OnFailureJobMode", "IgnoreOnIsolate",  "StopWhenUnneeded",
	"RefuseManualStart", "RefuseManualStop", "AllowIsolate",     "CollectMode",
	"SourcePath",
};

fn isUnitIgnore(key: []const u8) bool {
	for (unit_section_ignores) |k| {
		if (std.mem.eql(u8, k, key)) return true;
	}
	return false;
}

fn valuesEql(a: []const []const u8, b: []const []const u8) bool {
	if (a.len != b.len) return false;
	for (a, b) |x, y| {
		if (!std.mem.eql(u8, x, y)) return false;
	}
	return true;
}

/// main.rs compare_units, verbatim: restart unless the only differences are
/// [Unit] keys in unit_section_ignores (X-Reload-Triggers reloads), [Service]
/// ExecReload (reloads; removing it is a no-op) or [Mount] Options (reloads).
pub fn compareUnits(cur: *const UnitInfo, new: *const UnitInfo) Comparison {
	var ret: Comparison = .equal;
	for (cur.keys(), cur.values()) |sname, *sec| {
		const new_sec = new.getPtr(sname) orelse {
			// A section the new unit dropped.
			if (std.mem.eql(u8, sname, "Unit")) {
				for (sec.keys()) |k| {
					if (!isUnitIgnore(k)) return .needs_restart;
				}
				continue;
			}
			if (std.mem.eql(u8, sname, "Service") and sec.count() == 1 and sec.contains("ExecReload")) continue;
			return .needs_restart;
		};
		for (sec.keys(), sec.values()) |key, *cur_val| {
			const new_val = new_sec.getPtr(key) orelse {
				if (std.mem.eql(u8, sname, "Unit") and isUnitIgnore(key)) continue;
				if (std.mem.eql(u8, sname, "Service") and std.mem.eql(u8, key, "ExecReload")) continue;
				return .needs_restart;
			};
			if (valuesEql(cur_val.items, new_val.items)) continue;
			if (std.mem.eql(u8, sname, "Unit")) {
				if (std.mem.eql(u8, key, "X-Reload-Triggers")) {
					ret = .needs_reload;
					continue;
				} else if (isUnitIgnore(key)) continue;
			}
			if (std.mem.eql(u8, sname, "Service") and std.mem.eql(u8, key, "ExecReload")) {
				ret = .needs_reload;
				continue;
			}
			if (std.mem.eql(u8, sname, "Mount") and std.mem.eql(u8, key, "Options")) {
				ret = .needs_reload;
				continue;
			}
			return .needs_restart;
		}
		// Keys the new unit introduced in this section.
		var added: usize = 0;
		var added_exec_reload = false;
		for (new_sec.keys()) |k| {
			if (sec.contains(k)) continue;
			added += 1;
			if (std.mem.eql(u8, k, "ExecReload")) added_exec_reload = true;
			if (std.mem.eql(u8, sname, "Unit")) {
				if (std.mem.eql(u8, k, "X-Reload-Triggers")) {
					ret = .needs_reload;
				} else if (!isUnitIgnore(k)) return .needs_restart;
			}
		}
		if (added == 0 or std.mem.eql(u8, sname, "Unit")) continue;
		if (std.mem.eql(u8, sname, "Service") and added == 1 and added_exec_reload) {
			ret = .needs_reload;
			continue;
		}
		return .needs_restart;
	}
	// Sections the new unit introduced.
	var introduced: usize = 0;
	var only: []const u8 = "";
	for (new.keys()) |sname| {
		if (cur.contains(sname)) continue;
		introduced += 1;
		only = sname;
	}
	if (introduced > 1) return .needs_restart;
	if (introduced == 1) {
		const sec = new.getPtr(only).?;
		if (std.mem.eql(u8, only, "Unit")) {
			for (sec.keys()) |k| {
				if (!isUnitIgnore(k)) return .needs_restart;
				if (std.mem.eql(u8, k, "X-Reload-Triggers")) ret = .needs_reload;
			}
		} else if (std.mem.eql(u8, only, "Service")) {
			if (sec.count() == 1 and sec.contains("ExecReload")) {
				ret = .needs_reload;
			} else return .needs_restart;
		} else return .needs_restart;
	}
	return ret;
}

// --- the action sets (handle_modified_unit, collect_unit_changes) ---------------

pub const Action = enum {
	stop,
	start,
	restart,
	reload,

	pub fn name(a: Action) []const u8 {
		return @tagName(a);
	}
};

/// main.rs's units_to_{stop,start,reload,restart,skip,filter}, as switch-ng
/// fills them (filter: the active targets started only to pull in new units,
/// which dry-activate does not print).
pub const Sets = struct {
	stop: StrSet = .empty,
	start: StrSet = .empty,
	reload: StrSet = .empty,
	restart: StrSet = .empty,
	skip: StrSet = .empty,
	filter: StrSet = .empty,
};

/// What switch-ng is comparing: the unit directories of the two systems and
/// the units it treats as active.
pub const Scope = struct {
	arena: Allocator,
	io: Io,
	/// <P>/etc/systemd/system
	old_dir: []const u8,
	/// <T>/etc/systemd/system
	new_dir: []const u8,
	/// The units switch-ng would see as active (current_active_units).
	active: *const StrSet,
};

/// main.rs cannot_be_restarted_directly.
pub fn cannotBeRestartedDirectly(unit: []const u8) bool {
	inline for (.{ "sysinit.target", "basic.target", "multi-user.target", "graphical.target" }) |n| {
		if (std.mem.eql(u8, unit, n)) return true;
	}
	return std.mem.endsWith(u8, unit, ".path") or std.mem.endsWith(u8, unit, ".slice");
}

/// main.rs handle_modified_unit, verbatim. `new_info` null is switch-ng's
/// activation-script path (restart instead of stop + start); the host plan
/// always passes the parsed new unit.
pub fn handleModifiedUnit(
	s: Scope,
	sets: *Sets,
	unit: []const u8,
	base_name: []const u8,
	new_unit_file: []const u8,
	new_base_unit_file: []const u8,
	new_info_arg: ?*const UnitInfo,
) !void {
	const a = s.arena;
	const restart_as_stop_start = new_info_arg == null;
	if (cannotBeRestartedDirectly(unit)) {
		// Slices and paths pick their properties up on daemon-reload.
		return;
	}
	if (std.mem.endsWith(u8, unit, ".mount")) {
		// Only / and /nix are reloaded (remounted) rather than restarted.
		if (std.mem.eql(u8, unit, "-.mount") or std.mem.eql(u8, unit, "nix.mount")) {
			try setPut(a, &sets.reload, unit);
		} else try setPut(a, &sets.restart, unit);
		return;
	}
	if (std.mem.endsWith(u8, unit, ".socket")) return; // switch-ng: FIXME, nothing

	var fallback: UnitInfo = undefined;
	const new_info: *const UnitInfo = new_info_arg orelse blk: {
		fallback = try parseUnit(a, s.io, new_unit_file, new_base_unit_file);
		break :blk &fallback;
	};

	if (parseSystemdBool(new_info, "Service", "X-ReloadIfChanged", false) and
		!sets.restart.contains(unit) and
		!(if (restart_as_stop_start) sets.restart.contains(unit) else sets.stop.contains(unit)))
	{
		try setPut(a, &sets.reload, unit);
		return;
	}
	if (!parseSystemdBool(new_info, "Service", "X-RestartIfChanged", true) or
		parseSystemdBool(new_info, "Unit", "RefuseManualStop", false) or
		parseSystemdBool(new_info, "Unit", "X-OnlyManualStart", false))
	{
		try setPut(a, &sets.skip, unit);
		return;
	}
	if (!parseSystemdBool(new_info, "Service", "X-StopIfChanged", true) or !std.mem.endsWith(u8, unit, ".service")) {
		// Restarted in place rather than stopped and started.
		try setPut(a, &sets.restart, unit);
	} else {
		// A socket-activated service: stop its socket(s) too and restart the
		// socket instead of the service. Sockets= when set, else <base>.socket
		// (a template instance's base name keeps its '@', which is stripped).
		var socket_activated = false;
		var sockets: std.ArrayList([]const u8) = .empty;
		if (new_info.getPtr("Service")) |svc| {
			if (svc.getPtr("Sockets")) |vals| {
				for (vals.items) |v| {
					var tok = std.mem.tokenizeAny(u8, v, ws);
					while (tok.next()) |sock| try sockets.append(a, sock);
				}
			}
		}
		if (sockets.items.len == 0) {
			const sb = if (std.mem.endsWith(u8, base_name, "@")) base_name[0 .. base_name.len - 1] else base_name;
			try sockets.append(a, try std.fmt.allocPrint(a, "{s}.socket", .{sb}));
		}
		for (sockets.items) |sock| {
			const in_new = pathExists(s.io, try std.fmt.allocPrint(a, "{s}/{s}", .{ s.new_dir, sock }));
			if (s.active.contains(sock)) {
				if (restart_as_stop_start) try setPut(a, &sets.restart, sock) else try setPut(a, &sets.stop, sock);
				// Only a socket the new configuration still has is started again.
				if (in_new) {
					if (restart_as_stop_start) try setPut(a, &sets.restart, sock) else try setPut(a, &sets.start, sock);
					socket_activated = true;
				}
			} else if (in_new) {
				// Transitioning to socket activation; the socket starts it.
				socket_activated = true;
			}
		}
		if (parseSystemdBool(new_info, "Service", "X-NotSocketActivated", false)) socket_activated = false;
		if (!socket_activated) {
			if (restart_as_stop_start) try setPut(a, &sets.restart, unit) else try setPut(a, &sets.start, unit);
		}
		if (restart_as_stop_start) try setPut(a, &sets.restart, unit) else try setPut(a, &sets.stop, unit);
	}
	// Never both restart and reload.
	_ = sets.reload.orderedRemove(unit);
}

/// The system half of main.rs collect_unit_changes, over the units in
/// `s.active` (bytewise order, for a deterministic result; switch-ng's
/// HashMap order does not change the sets). Every unit is treated as loaded
/// from the NixOS unit directory and as active, which is the host's
/// assumption (see the file comment). `removed` records the units stopped
/// because their file is gone from T.
pub fn collectUnitChanges(s: Scope, sets: *Sets, removed: *StrSet) !void {
	const a = s.arena;
	for (try sortedKeys(a, s.active)) |unit| {
		const cur_unit_file = try std.fmt.allocPrint(a, "{s}/{s}", .{ s.old_dir, unit });
		const new_unit_file = try std.fmt.allocPrint(a, "{s}/{s}", .{ s.new_dir, unit });
		var base_unit = unit;
		var cur_base_file = cur_unit_file;
		var new_base_file = new_unit_file;
		var dropins_removed = false;

		if (templateParts(unit)) |tp| {
			if (!pathExists(s.io, cur_unit_file) and !pathExists(s.io, new_unit_file)) {
				base_unit = try std.fmt.allocPrint(a, "{s}@.{s}", .{ tp.template, tp.suffix });
				cur_base_file = try std.fmt.allocPrint(a, "{s}/{s}", .{ s.old_dir, base_unit });
				new_base_file = try std.fmt.allocPrint(a, "{s}/{s}", .{ s.new_dir, base_unit });
				// An instance defined by drop-ins (overrideStrategy "asDropin")
				// was NixOS-managed iff one of its current drop-ins is a real
				// file, and is gone iff none of its new ones is.
				var currently_managed = false;
				for (try dropins(a, s.io, cur_unit_file)) |d| {
					if (try fileState(a, s.io, d) == .present) {
						currently_managed = true;
						break;
					}
				}
				if (currently_managed) {
					dropins_removed = true;
					for (try dropins(a, s.io, new_unit_file)) |d| {
						if (try fileState(a, s.io, d) == .present) {
							dropins_removed = false;
							break;
						}
					}
				}
			}
		}
		const base_name = baseName(base_unit);

		if (!pathExists(s.io, cur_base_file)) continue;
		if (dropins_removed or (try fileState(a, s.io, new_base_file)).isGone()) {
			const cur_info = try parseUnit(a, s.io, cur_unit_file, cur_base_file);
			if (parseSystemdBool(&cur_info, "Unit", "X-StopOnRemoval", true)) {
				try setPut(a, &sets.stop, unit);
				try setPut(a, removed, unit);
			}
		} else if (std.mem.endsWith(u8, unit, ".target")) {
			const new_info = try parseUnit(a, s.io, new_unit_file, new_base_file);
			// Every active target is started, which pulls in new units; switch-ng
			// hides these starts (filter). The sleep targets are left alone.
			const sleep = std.mem.eql(u8, unit, "suspend.target") or
				std.mem.eql(u8, unit, "hibernate.target") or
				std.mem.eql(u8, unit, "hybrid-sleep.target");
			if (!(sleep or
				parseSystemdBool(&new_info, "Unit", "RefuseManualStart", false) or
				parseSystemdBool(&new_info, "Unit", "X-OnlyManualStart", false)))
			{
				try setPut(a, &sets.start, unit);
				try setPut(a, &sets.filter, unit);
			}
			// X-StopOnReconfiguration targets (local-fs, remote-fs, keys) are
			// stopped first, so ordering through them holds on the restart.
			if (parseSystemdBool(&new_info, "Unit", "X-StopOnReconfiguration", false)) try setPut(a, &sets.stop, unit);
		} else {
			const cur_info = try parseUnit(a, s.io, cur_unit_file, cur_base_file);
			const new_info = try parseUnit(a, s.io, new_unit_file, new_base_file);
			switch (compareUnits(&cur_info, &new_info)) {
				.needs_restart => try handleModifiedUnit(s, sets, unit, base_name, new_unit_file, new_base_file, &new_info),
				.needs_reload => if (!sets.restart.contains(unit)) try setPut(a, &sets.reload, unit),
				.equal => {},
			}
		}
	}
}

// --- the re-exec predicate -------------------------------------------------------

/// main.rs's restart_systemd: systemd re-executes when the running PID 1
/// binary or the resolved /etc/systemd/system.conf differs from the new
/// system's. `cur_toplevel` stands in for both the running PID 1 (switch-ng
/// reads /proc/1/exe, which is the booted system's `systemd/lib/systemd/
/// systemd`) and the current /etc; the caller checks the booted runner's
/// system B and, when a live apply already moved it on, P too (either one
/// differing re-executes: the superset). An unresolvable current path counts
/// as "/unknown" (so it differs), as in switch-ng; an unresolvable new PID 1
/// is error.NoNewSystemd, where switch-ng dies.
pub fn reexecNeeded(arena: Allocator, io: Io, cur_toplevel: []const u8, new_toplevel: []const u8) !bool {
	const cwd = std.Io.Dir.cwd();
	const pid1 = "systemd/lib/systemd/systemd";
	const conf = "etc/systemd/system.conf";
	const cur_pid1 = realOr(arena, io, cur_toplevel, pid1);
	const cur_conf = realOr(arena, io, cur_toplevel, conf);
	const new_pid1 = cwd.realPathFileAlloc(io, try std.fmt.allocPrint(arena, "{s}/{s}", .{ new_toplevel, pid1 }), arena) catch return error.NoNewSystemd;
	const new_conf = realOr(arena, io, new_toplevel, conf);
	return !std.mem.eql(u8, cur_pid1, new_pid1) or !std.mem.eql(u8, cur_conf, new_conf);
}

fn realOr(arena: Allocator, io: Io, root: []const u8, rel: []const u8) []const u8 {
	const p = std.fmt.allocPrint(arena, "{s}/{s}", .{ root, rel }) catch return "/unknown";
	return std.Io.Dir.cwd().realPathFileAlloc(io, p, arena) catch "/unknown";
}

// --- the unit directory and its dependency graph ---------------------------------

/// The dependency edges the closure follows (spec section 3, tier 2 item 5).
/// Each names the declaration it came from; `*_dir` are the `.wants/`,
/// `.requires/` and `.upholds/` links, and the `rt_*` kinds are the guest's
/// runtime reverse edges (`systemctl show -p RequiredBy,BoundBy,...`), which
/// apply.zig adds and which only ever add reachability.
pub const Edge = enum {
	requires,
	requisite,
	wants,
	binds_to,
	upholds,
	part_of,
	on_failure,
	on_success,
	requires_mounts_for,
	wants_mounts_for,
	stop_propagated_from,
	propagates_stop_to,
	propagates_reload_to,
	reload_propagated_from,
	conflicts,
	wants_dir,
	requires_dir,
	upholds_dir,
	rt_required_by,
	rt_bound_by,
	rt_consists_of,
	rt_propagates_stop_to,
	rt_propagates_reload_to,
	rt_conflicted_by,

	pub fn name(e: Edge) []const u8 {
		return @tagName(e);
	}
};

/// One edge out of a node: the node it reaches (`to`, see Graph.nodeOf) and the
/// name it reaches (`name`, see Graph.nameOf), which keeps a concrete template
/// instance (`user@1000.service`) apart from the template's other instances.
pub const Link = struct { to: []const u8, edge: Edge, name: []const u8 };
const Adj = std.array_hash_map.String(std.ArrayList(Link));

/// A unit directory's entries: the unit names it defines (a file, a mask, a
/// dangling link, or only a `<name>.d/` drop-in directory) and its
/// `.wants/`/`.requires/`/`.upholds/` links.
pub const Listing = struct {
	names: StrSet = .empty,
	/// Names that have a `<name>.d/` directory.
	with_dropins: StrSet = .empty,
	links: std.ArrayList(DirLink) = .empty,
	/// Alias name -> the unit it names (see aliasTarget). systemd lists an
	/// aliased unit under its own name only, so switch-ng never acts on an
	/// alias, and every edge through one is an edge of the unit it names.
	aliases: std.array_hash_map.String([]const u8) = .empty,
};

/// The unit an entry is an alias of, or null: the entry resolves to a real
/// file whose name is a different unit name (NixOS writes `aliases` as links
/// to the unit, and systemd's own alias links, like
/// dbus-org.freedesktop.network1.service, resolve to the unit file). A link
/// from a template instance to its own template (`foo@bar.service` ->
/// `foo@.service`) instantiates it and is not an alias, as in systemd.
fn aliasTarget(arena: Allocator, io: Io, dir: []const u8, name: []const u8) !?[]const u8 {
	const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, name });
	const real = std.Io.Dir.cwd().realPathFileAlloc(io, path, arena) catch |err| switch (err) {
		error.FileNotFound => return null,
		else => return err,
	};
	const base = std.fs.path.basename(real);
	if (std.mem.eql(u8, base, name) or std.mem.eql(u8, real, "/dev/null") or !isUnitName(base)) return null;
	if (templateParts(name)) |tp| {
		if (tp.instance.len > 0) {
			const tmpl = try std.fmt.allocPrint(arena, "{s}@.{s}", .{ tp.template, tp.suffix });
			if (std.mem.eql(u8, base, tmpl)) return null;
		}
	}
	return try arena.dupe(u8, base);
}

pub const DirLink = struct { from: []const u8, to: []const u8, edge: Edge };

/// Add the exact unit names `l` shows to `set`: every name (a file, a mask, a
/// dangling link, a drop-in directory), every link's name, and the unit whose
/// directory holds the link. Only these vouch for a template instance in a
/// report (Graph.reportName; apply.zig's outcome units): any instance of a
/// template the system defines is a valid unit name, so an instance only the
/// guest named carries the guest's own text.
pub fn addListed(arena: Allocator, set: *StrSet, l: *const Listing) Allocator.Error!void {
	for (l.names.keys()) |n| try setPut(arena, set, n);
	for (l.links.items) |dl| {
		try setPut(arena, set, dl.from);
		try setPut(arena, set, dl.to);
	}
}

/// List `dir` (a toplevel's etc/systemd/system). A missing directory is an
/// error: a system without one is not something to plan against.
pub fn listUnitDir(arena: Allocator, io: Io, dir: []const u8) !Listing {
	var out: Listing = .{};
	var d = try std.Io.Dir.cwd().openDir(io, dir, .{ .iterate = true });
	defer d.close(io);
	var it = d.iterate();
	while (try it.next(io)) |e| {
		const nm = try arena.dupe(u8, e.name);
		const is_dir = switch (e.kind) {
			.directory => true,
			.sym_link, .unknown => blk: {
				const st = d.statFile(io, nm, .{}) catch break :blk false;
				break :blk st.kind == .directory;
			},
			else => false,
		};
		if (!is_dir) {
			if (isUnitName(nm)) {
				try setPut(arena, &out.names, nm);
				if (try aliasTarget(arena, io, dir, nm)) |target| try out.aliases.put(arena, nm, target);
			}
			continue;
		}
		if (std.mem.endsWith(u8, nm, ".d")) {
			const unit = nm[0 .. nm.len - 2];
			if (isUnitName(unit)) {
				try setPut(arena, &out.names, unit);
				try setPut(arena, &out.with_dropins, unit);
			}
			continue;
		}
		inline for (.{ .{ ".wants", Edge.wants_dir }, .{ ".requires", Edge.requires_dir }, .{ ".upholds", Edge.upholds_dir } }) |kind| {
			if (std.mem.endsWith(u8, nm, kind[0])) {
				const from = nm[0 .. nm.len - kind[0].len];
				if (isUnitName(from)) {
					var sub = try d.openDir(io, nm, .{ .iterate = true });
					defer sub.close(io);
					var sit = sub.iterate();
					while (try sit.next(io)) |se| {
						if (!isUnitName(se.name)) continue;
						try out.links.append(arena, .{ .from = from, .to = try arena.dupe(u8, se.name), .edge = kind[1] });
					}
				}
			}
		}
	}
	return out;
}

/// The union of P's and T's dependency edges, by node name (see nodeName),
/// in the four propagation directions:
///   fwd      U started (or restarted)  -> X started
///   rev      U stopped (or restarted)  -> X stopped (restarted)
///   reload   U reloaded                -> X reloaded
///   conflict U started (or restarted)  -> X stopped
pub const Graph = struct {
	fwd: Adj = .empty,
	rev: Adj = .empty,
	reload: Adj = .empty,
	conflict: Adj = .empty,
	/// Node names with a unit file (or drop-in directory) in P or T, plus the
	/// mounts systemd-fstab-generator makes of P's and T's etc/fstab (`fstab`).
	files: StrSet = .empty,
	/// The fstab-generated mount units (also in `files`): they have no unit
	/// file, only edges (`Requires=`, `.requires/` links), but the guest's data
	/// about them (a failed or inactive mount) must not be dropped as foreign.
	fstab: StrSet = .empty,
	/// Node names whose T unit carries the once-marker condition
	/// (`once_condition`): a start after the boot settled is skipped, IF the
	/// guest holds the marker (Runtime.once).
	once_marked: StrSet = .empty,
	/// Alias -> aliased unit, T's mapping over P's (Listing.aliases).
	aliases: std.array_hash_map.String([]const u8) = .empty,
	/// The exact unit names P's and T's listings show (addListed) and their
	/// unit files name as dependencies, and the names the closure tracks those
	/// under (nameOf): the host's own names, what a report may show a template
	/// instance by (reportName).
	listed: StrSet = .empty,

	/// The name a report shows for a name the closure tracks (nameOf): the
	/// name itself, except a template instance P and T never name (`listed`),
	/// which is shown as its node (the template). The guest's data reaches the
	/// closure by name (an induced start, a runtime edge's target), and checking
	/// an instance against its template's file lets any instance text through
	/// (`serial-getty@<anything>.service`); the guest's free text never reaches
	/// a report (spec 4.11).
	pub fn reportName(g: *const Graph, arena: Allocator, name: []const u8) Allocator.Error![]const u8 {
		const tp = templateParts(name) orelse return name;
		if (tp.instance.len == 0 or g.listed.contains(name)) return name;
		return g.nodeOf(arena, name);
	}

	/// The node a unit name lives at: template instances folded into their
	/// template (nodeName), aliases resolved to the unit they name.
	pub fn nodeOf(g: *const Graph, arena: Allocator, name: []const u8) Allocator.Error![]const u8 {
		const folded = try nodeName(arena, name);
		return nodeName(arena, g.aliases.get(folded) orelse folded);
	}

	/// The name the closure tracks a unit under: aliases resolved, but a
	/// concrete template instance kept (unlike nodeOf), so what the guest
	/// reports about one instance never stands for another. A name with a
	/// specifier (`user-runtime-dir@%i.service`) names every instance: its node.
	pub fn nameOf(g: *const Graph, arena: Allocator, name: []const u8) Allocator.Error![]const u8 {
		if (std.mem.indexOfScalar(u8, name, '%') != null) return g.nodeOf(arena, name);
		if (g.aliases.get(name)) |target| return target;
		// An instance of an aliased template (autovt@tty1 -> getty@tty1) is
		// that instance of the template the alias names.
		if (templateParts(name)) |tp| {
			if (tp.instance.len > 0) {
				const tmpl = try std.fmt.allocPrint(arena, "{s}@.{s}", .{ tp.template, tp.suffix });
				if (g.aliases.get(tmpl)) |target| {
					if (templateParts(target)) |tt| {
						if (tt.instance.len == 0) return std.fmt.allocPrint(arena, "{s}@{s}.{s}", .{ tt.template, tp.instance, tt.suffix });
					}
				}
			}
		}
		return name;
	}

	fn add(g: *const Graph, arena: Allocator, which: *Adj, from: []const u8, to: []const u8, edge: Edge) !void {
		const f = try g.nodeOf(arena, from);
		const t = try g.nodeOf(arena, to);
		const n = try g.nameOf(arena, to);
		const gop = try which.getOrPut(arena, f);
		if (!gop.found_existing) gop.value_ptr.* = .empty;
		for (gop.value_ptr.items) |l| {
			if (l.edge == edge and std.mem.eql(u8, l.name, n)) return;
		}
		try gop.value_ptr.append(arena, .{ .to = t, .edge = edge, .name = n });
	}

	/// Record one declared dependency, in every direction it propagates.
	/// `x` declares `edge` naming `u` (for a `*_dir` link, `x` is the
	/// directory's unit and `u` the link).
	pub fn addDecl(g: *Graph, arena: Allocator, x: []const u8, edge: Edge, u: []const u8) !void {
		switch (edge) {
			// Requires/BindsTo/Requisite and .requires/ links: X pulls U in,
			// and U stopping (restarting) stops (restarts) X. Requisite pulls
			// nothing in systemd but is listed as a forward edge by the spec;
			// its stop propagation (RequisiteOf) is real, so it is in both.
			.requires, .binds_to, .requisite, .requires_dir, .requires_mounts_for => {
				try g.add(arena, &g.fwd, x, u, edge);
				try g.add(arena, &g.rev, u, x, edge);
			},
			.wants, .upholds, .on_failure, .on_success, .wants_mounts_for, .wants_dir, .upholds_dir => try g.add(arena, &g.fwd, x, u, edge),
			.part_of, .stop_propagated_from => try g.add(arena, &g.rev, u, x, edge),
			.propagates_stop_to => try g.add(arena, &g.rev, x, u, edge),
			.propagates_reload_to => try g.add(arena, &g.reload, x, u, edge),
			.reload_propagated_from => try g.add(arena, &g.reload, u, x, edge),
			.conflicts => {
				try g.add(arena, &g.conflict, x, u, edge);
				try g.add(arena, &g.conflict, u, x, edge);
			},
			// Runtime edges arrive already reversed: `x` is the unit whose
			// property lists `u` (RequiredBy=u: u requires x).
			.rt_required_by, .rt_bound_by, .rt_consists_of, .rt_propagates_stop_to => try g.add(arena, &g.rev, x, u, edge),
			.rt_propagates_reload_to => try g.add(arena, &g.reload, x, u, edge),
			.rt_conflicted_by => {
				try g.add(arena, &g.conflict, x, u, edge);
				try g.add(arena, &g.conflict, u, x, edge);
			},
		}
	}

	/// A guest-reported runtime edge (apply.zig, after it intersected both
	/// names with the T/P unit files). Only ever adds reachability.
	pub fn addRuntimeEdge(g: *Graph, arena: Allocator, x: []const u8, edge: Edge, u: []const u8) !void {
		return g.addDecl(arena, x, edge, u);
	}

	pub fn links(g: *const Graph, which: enum { fwd, rev, reload, conflict }, node: []const u8) []const Link {
		const m = switch (which) {
			.fwd => &g.fwd,
			.rev => &g.rev,
			.reload => &g.reload,
			.conflict => &g.conflict,
		};
		const l = m.getPtr(node) orelse return &.{};
		return l.items;
	}
};

const decl_keys = [_]struct { key: []const u8, edge: Edge }{
	.{ .key = "Requires", .edge = .requires },
	.{ .key = "Requisite", .edge = .requisite },
	.{ .key = "Wants", .edge = .wants },
	.{ .key = "BindsTo", .edge = .binds_to },
	.{ .key = "Upholds", .edge = .upholds },
	.{ .key = "PartOf", .edge = .part_of },
	.{ .key = "OnFailure", .edge = .on_failure },
	.{ .key = "OnSuccess", .edge = .on_success },
	.{ .key = "StopPropagatedFrom", .edge = .stop_propagated_from },
	.{ .key = "PropagatesStopTo", .edge = .propagates_stop_to },
	.{ .key = "PropagatesReloadTo", .edge = .propagates_reload_to },
	.{ .key = "ReloadPropagatedFrom", .edge = .reload_propagated_from },
	.{ .key = "Conflicts", .edge = .conflicts },
};

/// systemd's unit_name_path_escape for an absolute path: simplified ("//" and
/// trailing "/" dropped), "/" itself is "-", '/' becomes '-', a leading '.'
/// and every byte outside [A-Za-z0-9:_.] becomes \xNN.
pub fn escapePath(arena: Allocator, path: []const u8) Allocator.Error![]const u8 {
	var out: std.ArrayList(u8) = .empty;
	var it = std.mem.tokenizeScalar(u8, path, '/');
	var first = true;
	while (it.next()) |comp| {
		if (std.mem.eql(u8, comp, ".")) continue;
		if (!first) try out.append(arena, '-');
		for (comp, 0..) |c, i| {
			const plain = std.ascii.isAlphanumeric(c) or c == ':' or c == '_' or (c == '.' and !(first and i == 0));
			if (plain) {
				try out.append(arena, c);
			} else {
				var buf: [4]u8 = undefined;
				try out.appendSlice(arena, std.fmt.bufPrint(&buf, "\\x{x:0>2}", .{c}) catch unreachable);
			}
		}
		first = false;
	}
	if (out.items.len == 0) return "-";
	return out.items;
}

/// The mount units RequiresMountsFor=/WantsMountsFor= `path` implies: one per
/// prefix of the path ("/", "/a", "/a/b", ...), kept only when P or T has a
/// unit file for it or etc/fstab defines it (Graph.files holds both). A mount
/// systemd makes of a mount point nothing declares is not tracked.
fn mountsFor(arena: Allocator, files: *const StrSet, path: []const u8) ![]const []const u8 {
	if (path.len == 0 or path[0] != '/') return &.{};
	var out: std.ArrayList([]const u8) = .empty;
	var end: usize = 0;
	while (true) {
		const prefix = if (end == 0) "/" else path[0..end];
		const unit = try std.fmt.allocPrint(arena, "{s}.mount", .{try escapePath(arena, prefix)});
		if (files.contains(unit)) try out.append(arena, unit);
		if (end == path.len) break;
		end = std.mem.indexOfScalarPos(u8, path, end + 1, '/') orelse path.len;
	}
	return out.items;
}

/// The largest etc/fstab read (tier 1 pins its bytes to the booted system's).
pub const max_fstab_bytes: usize = 1 << 20;

/// The mount units systemd-fstab-generator makes of the fstab at `path`
/// (fstabMountsOf); a missing file has none.
pub fn fstabMounts(arena: Allocator, io: Io, path: []const u8) ![]const []const u8 {
	const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_fstab_bytes + 1)) catch |err| switch (err) {
		error.FileNotFound => return &.{},
		error.StreamTooLong => return error.FileTooLarge,
		else => return err,
	};
	return fstabMountsOf(arena, bytes);
}

/// One `<escaped mount point>.mount` per fstab entry whose mount point (the
/// second field, its octal escapes such as \040 decoded as the generator does)
/// is an absolute path; a swap entry's "none" is not one. Blank lines and
/// comments are skipped.
pub fn fstabMountsOf(arena: Allocator, text: []const u8) Allocator.Error![]const []const u8 {
	var out: std.ArrayList([]const u8) = .empty;
	var lines = std.mem.splitScalar(u8, text, '\n');
	while (lines.next()) |line| {
		var f = std.mem.tokenizeAny(u8, line, " \t\r");
		const spec = f.next() orelse continue;
		if (spec[0] == '#') continue;
		const raw = f.next() orelse continue;
		var where: std.ArrayList(u8) = .empty;
		var i: usize = 0;
		while (i < raw.len) : (i += 1) {
			if (raw[i] == '\\' and i + 4 <= raw.len) {
				if (std.fmt.parseInt(u8, raw[i + 1 .. i + 4], 8)) |c| {
					try where.append(arena, c);
					i += 3;
					continue;
				} else |_| {}
			}
			try where.append(arena, raw[i]);
		}
		if (where.items.len == 0 or where.items[0] != '/') continue;
		try out.append(arena, try std.fmt.allocPrint(arena, "{s}.mount", .{try escapePath(arena, where.items)}));
	}
	return out.items;
}

/// Parse `name` from `dir` for its edges: the unit file (a masked or missing
/// one reads as empty), or for a template instance with no file of its own
/// the template's, plus the drop-ins switch-ng would read. Unlike parseUnit a
/// missing base is not an error: an instance named only by drop-ins or links
/// still has edges to record.
fn parseForGraph(arena: Allocator, io: Io, dir: []const u8, name: []const u8) !UnitInfo {
	const unit_file = try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, name });
	var base_file = unit_file;
	if (!pathExists(io, unit_file)) {
		if (templateParts(name)) |tp| {
			base_file = try std.fmt.allocPrint(arena, "{s}/{s}@.{s}", .{ dir, tp.template, tp.suffix });
		}
	}
	var info: UnitInfo = .empty;
	if (pathExists(io, base_file)) try parseSystemdIni(arena, &info, try readUnitFile(arena, io, base_file));
	for (try dropins(arena, io, base_file)) |d| try parseSystemdIni(arena, &info, try readUnitFile(arena, io, d));
	if (!std.mem.eql(u8, unit_file, base_file)) {
		for (try dropins(arena, io, unit_file)) |d| try parseSystemdIni(arena, &info, try readUnitFile(arena, io, d));
	}
	return info;
}

/// The boot-only units' once-marker (flake.nix "Boot-only units"): each
/// carries ConditionPathExists=!/run/cogbox/once/%N, and cogbox-boot-settled
/// writes the marker once the boot settled, so any later start of the unit is
/// skipped (inactive, condition failed) instead of re-running boot work.
pub const once_condition = "!/run/cogbox/once/%N";

/// Build the union graph of P's (`old_*`) and T's (`new_*`) unit directories,
/// with `fstab_mounts` (fstabMounts of P's and T's etc/fstab) known as units
/// too. The once-markers are read from T: the start jobs of a switch run T's
/// units.
pub fn buildGraph(arena: Allocator, io: Io, old_dir: []const u8, old_l: *const Listing, new_dir: []const u8, new_l: *const Listing, fstab_mounts: []const []const u8) !Graph {
	var g: Graph = .{};
	const dirs = [_][]const u8{ old_dir, new_dir };
	const listings = [_]*const Listing{ old_l, new_l };
	for (listings) |l| {
		for (l.aliases.keys(), l.aliases.values()) |al, target| try g.aliases.put(arena, al, target);
	}
	for (listings) |l| for (l.names.keys()) |n| try setPut(arena, &g.files, try g.nodeOf(arena, n));
	for (listings) |l| try addListed(arena, &g.listed, l);
	for (fstab_mounts) |m| {
		try setPut(arena, &g.files, m);
		try setPut(arena, &g.fstab, m);
	}
	for (dirs, listings, 0..) |dir, l, side| {
		for (try sortedKeys(arena, &l.names)) |x| {
			const info = try parseForGraph(arena, io, dir, x);
			const sec = info.getPtr("Unit") orelse continue;
			if (side == 1) {
				if (sec.getPtr("ConditionPathExists")) |conds| {
					for (conds.items) |c| {
						if (std.mem.eql(u8, c, once_condition)) try setPut(arena, &g.once_marked, try g.nodeOf(arena, x));
					}
				}
			}
			for (decl_keys) |dk| {
				const vals = sec.getPtr(dk.key) orelse continue;
				for (vals.items) |v| {
					var tok = std.mem.tokenizeAny(u8, v, ws);
					while (tok.next()) |u| {
						try g.addDecl(arena, x, dk.edge, u);
						try setPut(arena, &g.listed, u);
					}
				}
			}
			inline for (.{ .{ "RequiresMountsFor", Edge.requires_mounts_for }, .{ "WantsMountsFor", Edge.wants_mounts_for } }) |mk| {
				if (sec.getPtr(mk[0])) |vals| {
					for (vals.items) |v| {
						var tok = std.mem.tokenizeAny(u8, v, ws);
						while (tok.next()) |path| {
							for (try mountsFor(arena, &g.files, path)) |m| try g.addDecl(arena, x, mk[1], m);
						}
					}
				}
			}
		}
		for (l.links.items) |dl| try g.addDecl(arena, dl.from, dl.edge, dl.to);
	}
	for (try sortedKeys(arena, &g.listed)) |n| try setPut(arena, &g.listed, try g.nameOf(arena, n));
	return g;
}

// --- the host plan ---------------------------------------------------------------

pub const Why = enum {
	/// The unit's file changed (or a socket of a changed service).
	changed,
	/// The unit's file is gone from T (stop on removal).
	removed,
	/// A unit new in T that a started target, start or restart pulls in.
	new,
	/// An X-StopOnReconfiguration target switch-ng stops on every switch.
	/// Not shown in the plan's units (switch-ng hides it), but a seed of the
	/// closure: stopping it stops whatever Requires= it.
	reconfigured,
	/// An active target switch-ng starts on every switch (and
	/// sysinit-reactivation.target, which it restarts). Hidden like the
	/// reconfigured stops, but a seed of the closure: after the daemon-reload
	/// the start pulls in every inactive or failed unit the target reaches.
	target,
	/// Merged in by apply.zig from the guest's data. An induced start (a unit
	/// an active target wants at runtime that is not active) is a start the
	/// hidden target starts propagate, classified as one.
	induced,
	guest_reported,
	/// A user unit (etc/systemd/user) switch-ng's user pass would stop,
	/// restart, reload or leave stale (userChanges): never applied live.
	user_unit,
	/// A generator T adds, removes or retargets (generatorChanges): what it
	/// makes at the daemon-reload is in no unit directory the plan reads.
	generator,

	pub fn name(w: Why) []const u8 {
		return @tagName(w);
	}
};

pub const PlannedUnit = struct { unit: []const u8, action: Action, why: Why };

pub const HostPlan = struct {
	old_dir: []const u8,
	new_dir: []const u8,
	old: Listing,
	new: Listing,
	/// The units treated as active in P: every name P lists, except masks
	/// and aliases.
	active: StrSet,
	sets: Sets,
	removed: StrSet,
	/// Node names present in T whose P file is gone (or absent): new units.
	new_units: StrSet,
	/// New units the started targets, starts and restarts pull in.
	new_starts: StrSet,
	graph: Graph,
	/// The user units switch-ng's user pass would change (userChanges);
	/// planHost fills it, planDirs leaves it empty.
	user: []const PlannedUnit = &.{},
	/// The generators T adds, removes or retargets (generatorChanges);
	/// planHost fills it, planDirs leaves it empty.
	generators: []const PlannedUnit = &.{},

	/// The plan's units as dry-activate would print them (the filtered starts
	/// and stops hidden), a stop plus a start of one unit shown as a restart,
	/// with the new starts added; sorted by unit.
	pub fn units(p: *const HostPlan, arena: Allocator) Allocator.Error![]PlannedUnit {
		var names: StrSet = .empty;
		for (p.sets.stop.keys()) |u| if (!p.sets.filter.contains(u)) try setPut(arena, &names, u);
		for (p.sets.start.keys()) |u| if (!p.sets.filter.contains(u)) try setPut(arena, &names, u);
		for (p.sets.restart.keys()) |u| try setPut(arena, &names, u);
		for (p.sets.reload.keys()) |u| try setPut(arena, &names, u);
		for (p.new_starts.keys()) |u| try setPut(arena, &names, u);
		const sorted = try sortedKeys(arena, &names);
		const out = try arena.alloc(PlannedUnit, sorted.len);
		for (sorted, 0..) |u, i| {
			const stop = p.sets.stop.contains(u) and !p.sets.filter.contains(u);
			const start = (p.sets.start.contains(u) and !p.sets.filter.contains(u)) or p.new_starts.contains(u);
			const action: Action = if (p.sets.restart.contains(u) or (stop and start)) .restart else if (stop) .stop else if (start) .start else .reload;
			const why: Why = if (p.removed.contains(u)) .removed else if (p.new_starts.contains(u)) .new else .changed;
			out[i] = .{ .unit = u, .action = action, .why = why };
		}
		return out;
	}

	/// The closure's seeds: the plan's units, the hidden stops of the
	/// X-StopOnReconfiguration targets, the hidden starts of the active
	/// targets, and the restart of sysinit-reactivation.target switch-ng runs
	/// on every switch (main.rs, "Restart sysinit-reactivation.target"). The
	/// target starts are what pulls in an existing unit nothing restarts: a
	/// docker.service T newly wants, a failed mount. switch-ng starts every
	/// target it sees active; the host plan takes every target P has as
	/// active, so the starts are kept to those the guest reports active
	/// (`rt.active`), or, with no guest data (`rt.known` false), all of them.
	pub fn seeds(p: *const HostPlan, arena: Allocator, rt: *const Runtime) Allocator.Error![]Seed {
		const planned = try p.units(arena);
		var out: std.ArrayList(Seed) = .empty;
		for (planned) |u| try out.append(arena, .{ .unit = u.unit, .action = u.action, .why = u.why });
		for (try sortedKeys(arena, &p.sets.stop)) |u| {
			if (p.sets.filter.contains(u)) try out.append(arena, .{ .unit = u, .action = .stop, .why = .reconfigured });
		}
		for (try sortedKeys(arena, &p.sets.start)) |u| {
			if (!p.sets.filter.contains(u)) continue;
			if (rt.known and !rt.active.contains(try p.graph.nameOf(arena, u))) continue;
			try out.append(arena, .{ .unit = u, .action = .start, .why = .target });
		}
		if (p.graph.files.contains(reactivation_target)) try out.append(arena, .{ .unit = reactivation_target, .action = .restart, .why = .target });
		return out.items;
	}
};

/// The target switch-ng restarts on every switch, after the daemon-reload.
pub const reactivation_target = "sysinit-reactivation.target";

/// `<toplevel>/etc/systemd/system`.
pub fn unitDirOf(arena: Allocator, toplevel: []const u8) Allocator.Error![]const u8 {
	return std.fmt.allocPrint(arena, "{s}/etc/systemd/system", .{toplevel});
}

/// The host plan for switching from the system at `old_toplevel` (P) to the
/// one at `new_toplevel` (T): switch-ng's action sets with every P unit
/// treated as active, the new units, the union dependency graph (the mounts of
/// both systems' etc/fstab included), the user units the user pass would
/// change, and the generators T adds, removes or retargets.
pub fn planHost(arena: Allocator, io: Io, old_toplevel: []const u8, new_toplevel: []const u8) !HostPlan {
	const old_dir = try unitDirOf(arena, old_toplevel);
	const new_dir = try unitDirOf(arena, new_toplevel);
	var mounts: std.ArrayList([]const u8) = .empty;
	for ([_][]const u8{ old_toplevel, new_toplevel }) |tl| {
		try mounts.appendSlice(arena, try fstabMounts(arena, io, try std.fmt.allocPrint(arena, "{s}/etc/fstab", .{tl})));
	}
	var p = try planDirsWith(arena, io, old_dir, new_dir, mounts.items);
	p.user = try userChanges(
		arena,
		io,
		try std.fmt.allocPrint(arena, "{s}/etc/systemd/user", .{old_toplevel}),
		try std.fmt.allocPrint(arena, "{s}/etc/systemd/user", .{new_toplevel}),
	);
	p.generators = try generatorChanges(arena, io, old_toplevel, new_toplevel);
	return p;
}

/// planHost over two unit directories (the toplevel-free core; tests use it):
/// no fstab mounts, no user units.
pub fn planDirs(arena: Allocator, io: Io, old_dir: []const u8, new_dir: []const u8) !HostPlan {
	return planDirsWith(arena, io, old_dir, new_dir, &.{});
}

/// switch-ng's user unit, restarted in every user manager on every switch
/// (and skipped for root and the system users: ConditionUser=!@system).
pub const user_activation_unit = "nixos-activation.service";

/// The user units switch-ng's user pass (do_user_switch, run for every user
/// whose manager is up) would stop, restart, reload, or leave stale (skip),
/// switching from the user unit directory `old_dir` (P's etc/systemd/user) to
/// `new_dir` (T's): collect_unit_changes with every P user unit taken as
/// active (any user may run it), nixos-activation.service left out (restarted
/// unconditionally) and the hidden target bookkeeping left out. A unit T adds
/// is not listed: starting it is what a new user unit is for. Nor is a reload
/// of the user bus (dbus*), allowed as the system bus's is (spec 4.1): NixOS's
/// user dbus-broker.service reloads on the same configDir trigger as the
/// system one, which most plugin changes move. Neither the host plan nor
/// dry-activate (which exits before the user pass) sees these otherwise, so
/// any of them refuses the apply (restart_only_units) rather than porting the
/// user scope. A missing directory has no units. Residual: the user pass's
/// second (migration) pass restarts or starts a unit T adds that a user's
/// manager already runs from another unit directory ($XDG_DATA_HOME/systemd/
/// user and the like, or ~/.config/systemd/user once its copy is gone); a unit
/// T adds is allowed here, so that restart is not refused.
pub fn userChanges(arena: Allocator, io: Io, old_dir: []const u8, new_dir: []const u8) ![]const PlannedUnit {
	const old = listUnitDir(arena, io, old_dir) catch |err| switch (err) {
		error.FileNotFound, error.NotDir => return &.{},
		else => return err,
	};
	var active: StrSet = .empty;
	for (old.names.keys()) |n| {
		if (old.aliases.contains(n) or std.mem.eql(u8, n, user_activation_unit)) continue;
		const st = try fileState(arena, io, try std.fmt.allocPrint(arena, "{s}/{s}", .{ old_dir, n }));
		if (st != .masked) try setPut(arena, &active, n);
	}
	var sets: Sets = .{};
	var removed: StrSet = .empty;
	try collectUnitChanges(.{ .arena = arena, .io = io, .old_dir = old_dir, .new_dir = new_dir, .active = &active }, &sets, &removed);
	var names: StrSet = .empty;
	for (sets.stop.keys()) |u| if (!sets.filter.contains(u)) try setPut(arena, &names, u);
	for (sets.start.keys()) |u| if (!sets.filter.contains(u)) try setPut(arena, &names, u);
	for (sets.restart.keys()) |u| try setPut(arena, &names, u);
	for (sets.reload.keys()) |u| try setPut(arena, &names, u);
	for (sets.skip.keys()) |u| try setPut(arena, &names, u);
	var out: std.ArrayList(PlannedUnit) = .empty;
	for (try sortedKeys(arena, &names)) |u| {
		const stop = sets.stop.contains(u) and !sets.filter.contains(u);
		const start = sets.start.contains(u) and !sets.filter.contains(u);
		// A skipped unit is one switch-ng would restart but will not.
		const action: Action = if (sets.restart.contains(u) or sets.skip.contains(u) or (stop and start)) .restart else if (stop) .stop else if (start) .start else .reload;
		if (action == .reload and std.mem.startsWith(u8, u, "dbus")) continue;
		try out.append(arena, .{ .unit = u, .action = action, .why = .user_unit });
	}
	return out.items;
}

/// The generator directories under a toplevel's etc/systemd. NixOS links
/// `systemd.generators` (`systemd.user.generators`) and every
/// `systemd.packages` entry's lib/systemd/system-generators (user-generators)
/// into them (nixpkgs nixos/modules/system/boot/systemd.nix, `hooks`).
pub const generator_dirs = [_][]const u8{ "system-generators", "user-generators" };

/// The generators T adds (start), removes (stop) or retargets (restart),
/// named `<dir>/<entry>` (dir from generator_dirs). switch-ng's daemon-reload
/// runs T's system generators (the user pass's re-exec, T's user generators),
/// and its start of the active targets starts what they generated: a plugin's
/// zramSwap adds zram-generator, whose dev-zram0.swap and its
/// swap.target.wants link appear under /run/systemd/generator, which is
/// nowhere the plan reads (etc/systemd/system, etc/fstab, etc/systemd/user);
/// dry-activate runs no generator, and the guest sees no wants until the
/// reload. etc/fstab is pinned by tier 1, so the fstab generator's output is
/// the boot's; the set of generators is not, so any change to it refuses the
/// apply (restart_only_units) rather than modelling what a generator writes.
/// An entry is identified by what it resolves to (a file in a package, or
/// /dev/null, which disables a built-in generator), a dangling one by its link
/// text; the directories are compared entry by entry, so a rebuilt directory
/// with the same entries is no change (NixOS writes only links: a plain file
/// resolves to its own directory's path, and counts as retargeted, the safe
/// direction). A missing directory has no entries.
pub fn generatorChanges(arena: Allocator, io: Io, old_toplevel: []const u8, new_toplevel: []const u8) ![]const PlannedUnit {
	var out: std.ArrayList(PlannedUnit) = .empty;
	for (generator_dirs) |dir| {
		const old = try generatorEntries(arena, io, try std.fmt.allocPrint(arena, "{s}/etc/systemd/{s}", .{ old_toplevel, dir }));
		const new = try generatorEntries(arena, io, try std.fmt.allocPrint(arena, "{s}/etc/systemd/{s}", .{ new_toplevel, dir }));
		var names: StrSet = .empty;
		for (old.keys()) |n| try setPut(arena, &names, n);
		for (new.keys()) |n| try setPut(arena, &names, n);
		for (try sortedKeys(arena, &names)) |n| {
			const o = old.get(n);
			const w = new.get(n);
			const action: Action = if (o == null) .start else if (w == null) .stop else if (!std.mem.eql(u8, o.?, w.?)) .restart else continue;
			// The name is reported (refusal detail): bytes outside printable
			// ASCII read '?'.
			const shown = try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, n });
			for (shown) |*c| {
				if (c.* < 0x21 or c.* > 0x7e) c.* = '?';
			}
			try out.append(arena, .{ .unit = shown, .action = action, .why = .generator });
		}
	}
	return out.items;
}

/// A generator directory's entries: name -> what it resolves to, or
/// `dangling:<link text>`.
fn generatorEntries(arena: Allocator, io: Io, dir: []const u8) !std.array_hash_map.String([]const u8) {
	var out: std.array_hash_map.String([]const u8) = .empty;
	var d = std.Io.Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch |err| switch (err) {
		error.FileNotFound, error.NotDir => return out,
		else => return err,
	};
	defer d.close(io);
	var it = d.iterate();
	while (try it.next(io)) |e| {
		const name = try arena.dupe(u8, e.name);
		const id = try realOptional(arena, io, try std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, name })) orelse blk: {
			var buf: [std.fs.max_path_bytes]u8 = undefined;
			const n = try d.readLink(io, name, &buf);
			break :blk try std.fmt.allocPrint(arena, "dangling:{s}", .{buf[0..n]});
		};
		try out.put(arena, name, id);
	}
	return out;
}

/// planDirs with the mount units of P's and T's etc/fstab (fstabMounts).
pub fn planDirsWith(arena: Allocator, io: Io, old_dir: []const u8, new_dir: []const u8, fstab_mounts: []const []const u8) !HostPlan {
	var p: HostPlan = .{
		.old_dir = old_dir,
		.new_dir = new_dir,
		.old = try listUnitDir(arena, io, old_dir),
		.new = try listUnitDir(arena, io, new_dir),
		.active = .empty,
		.sets = .{},
		.removed = .empty,
		.new_units = .empty,
		.new_starts = .empty,
		.graph = undefined,
	};
	// Masks are never active; aliases are listed by systemd under the unit
	// they name, so switch-ng never sees them.
	for (p.old.names.keys()) |n| {
		if (p.old.aliases.contains(n)) continue;
		const st = try fileState(arena, io, try std.fmt.allocPrint(arena, "{s}/{s}", .{ old_dir, n }));
		if (st != .masked) try setPut(arena, &p.active, n);
	}
	try collectUnitChanges(.{ .arena = arena, .io = io, .old_dir = old_dir, .new_dir = new_dir, .active = &p.active }, &p.sets, &p.removed);

	p.graph = try buildGraph(arena, io, old_dir, &p.old, new_dir, &p.new, fstab_mounts);

	for (try sortedKeys(arena, &p.new.names)) |n| {
		if (p.new.aliases.contains(n)) continue;
		const st = try fileState(arena, io, try std.fmt.allocPrint(arena, "{s}/{s}", .{ new_dir, n }));
		if (st == .masked) continue;
		if (st == .missing and !p.new.with_dropins.contains(n)) continue; // a dangling link
		const in_old = p.old.names.contains(n);
		const old_st: FileState = if (in_old) try fileState(arena, io, try std.fmt.allocPrint(arena, "{s}/{s}", .{ old_dir, n })) else .missing;
		if (!in_old or (old_st != .present and st == .present)) try setPut(arena, &p.new_units, try p.graph.nodeOf(arena, n));
	}

	// The units the started targets, starts and restarts pull in, over the
	// edges systemd's start transaction follows; the new ones among them are
	// started by the switch.
	var frontier: std.ArrayList([]const u8) = .empty;
	var seen: StrSet = .empty;
	for ([_]*const StrSet{ &p.sets.start, &p.sets.restart }) |set| {
		for (try sortedKeys(arena, set)) |u| {
			const node = try p.graph.nodeOf(arena, u);
			if (seen.contains(node)) continue;
			try setPut(arena, &seen, node);
			try frontier.append(arena, node);
		}
	}
	var i: usize = 0;
	while (i < frontier.items.len) : (i += 1) {
		for (p.graph.links(.fwd, frontier.items[i])) |l| {
			if (!pullsStart(l.edge) or seen.contains(l.to)) continue;
			try setPut(arena, &seen, l.to);
			try frontier.append(arena, l.to);
			if (p.new_units.contains(l.to)) try setPut(arena, &p.new_starts, l.to);
		}
	}
	return p;
}

/// The forward edges a start job pulls its dependencies in by (Requisite,
/// OnFailure and OnSuccess start nothing at start time).
fn pullsStart(e: Edge) bool {
	return switch (e) {
		.requires, .wants, .binds_to, .upholds, .requires_mounts_for, .wants_mounts_for, .requires_dir, .wants_dir, .upholds_dir => true,
		else => false,
	};
}

// --- the deny-list classes --------------------------------------------------------

/// The deny-list classes (spec section 3, tier 2 item 6) and the skipped units.
pub const Class = enum {
	/// Restart-only: mounts, swaps, the boot-only preparation units, a change
	/// to cogbox-reply-route itself or a stop or restart of it, a dbus restart.
	a,
	/// Sessions and containers: sshd, logind (not its reload), resolved, the
	/// container engines, firewall.service (not its reload).
	b,
	/// Network: systemd-networkd and nftables, any action.
	c,
	/// PID 1: systemd would re-execute. Never a unit; see reexecNeeded.
	d,
	/// Units switch-ng will not restart, and the login-session units.
	skip,

	pub fn reason(c: Class) Reason {
		return switch (c) {
			.a => .restart_only_units,
			.b => .disruptive_units,
			.c => .network_config,
			.d => .systemd_reexec,
			.skip => .skipped_units,
		};
	}
};

/// The plan's refusal reasons, in the order the spec's table lists them.
pub const Reason = enum {
	restart_only_units,
	skipped_units,
	disruptive_units,
	network_config,
	systemd_reexec,

	/// Only the class B, C and D reasons can be forced with Apply anyway.
	pub fn overridable(r: Reason) bool {
		return switch (r) {
			.disruptive_units, .network_config, .systemd_reexec => true,
			.restart_only_units, .skipped_units => false,
		};
	}

	pub fn name(r: Reason) []const u8 {
		return @tagName(r);
	}
};

fn stemIs(unit: []const u8, stem: []const u8) bool {
	return std.mem.eql(u8, baseName(unit), stem);
}

/// The login-session units: user@ (every user's manager), getty and its
/// relatives, and systemd-user-sessions (restarting it ends every session).
/// nixpkgs marks all of them restartIfChanged = false, so switch-ng skips
/// them; they are matched by name as well, so ANY change to one (a reload,
/// a stop on removal) and any propagation reaching one is `skipped_units`,
/// never overridable: the live state would differ from the next boot, or a
/// session would end. The one exception is a propagated start of one the guest
/// runs (classify): a no-op.
fn isSessionUnit(unit: []const u8) bool {
	inline for (.{ "user@", "getty@", "serial-getty@", "container-getty@", "autovt@" }) |p| {
		if (std.mem.startsWith(u8, unit, p)) return true;
	}
	return stemIs(unit, "console-getty") or stemIs(unit, "systemd-user-sessions");
}

/// What the guest reports about its units (apply.zig fills it from `plan`,
/// every name intersected with the T/P unit files and the fstab mounts). The
/// host never knows this on its own; it decides only whether a start the
/// closure propagates changes anything (classify). A lie only exposes the
/// guest's own unit.
pub const Runtime = struct {
	/// The guest reported its unit states. Without them every target P has is
	/// taken as active (HostPlan.seeds) and nothing as running.
	known: bool = false,
	/// Names (Graph.nameOf) the guest runs: ActiveState active, reloading or
	/// refreshing. Anything else (inactive, failed, activating, deactivating,
	/// not listed) is not running.
	active: StrSet = .empty,
	/// The once-markers present in /run/cogbox/once: unit names without their
	/// type (`%N`), as cogbox-boot-settled writes them.
	once: StrSet = .empty,
	/// Names the guest cannot load (load state not-found).
	not_found: StrSet = .empty,
};

/// How an action reached the unit being classified.
pub const Reach = struct {
	/// The plan's own action (a seed), not one propagated over an edge.
	direct: bool,
	/// T adds the unit (P has no file for it, or masks it).
	is_new: bool = false,
	/// T's unit carries the once-marker condition (Graph.once_marked).
	once_marked: bool = false,
	/// The guest runs the unit (Runtime.active).
	active: bool = false,
	/// The guest holds the unit's once-marker (Runtime.once).
	marker: bool = false,
	/// No unit file in P or T defines the unit, it is no fstab mount, and the
	/// guest cannot load it (Runtime.not_found): a start of it fails to load.
	unloadable: bool = false,
};

/// Classify `action` on `unit`. Units are matched by their stem (the name
/// without its type), so "sshd" covers sshd.service and sshd.socket. Null: not
/// a hazard.
///
/// Refinements over the spec's literal "any deny-listed unit, *.mount or
/// *.swap reachable", all for a PROPAGATED START of a unit P already has
/// (stops, restarts, reloads, the plan's own actions, and starts of units T
/// adds are never relaxed), and all decided by what the guest reports:
///   - a unit the guest runs, whatever its class (a mounted filesystem, the
///     running docker, user@0): starting an active unit is a no-op;
///   - a once-marked boot-only unit whose marker the guest holds: its start is
///     skipped by the marker condition (flake.nix "Boot-only units"), which
///     exists for exactly this. A boot unit that failed or never ran has no
///     marker, so its start re-runs boot work: class A;
///   - a unit nothing defines that the guest cannot load (a Wants= of an
///     absent tmp.mount): systemd cannot start it.
/// Without them every apply would refuse: every switch starts the active
/// targets again, and every plugin change restarts cogbox-brain-materialize
/// (spec section 2 step 9), whose Requires= reaches the state and harness
/// mounts, and through their .requires/ and .wants/ links the rw-root-* and
/// harness-* preparation units. A start of a unit the guest does not run (a
/// failed mount, a docker.service nothing wanted at boot) is classed like any
/// other action.
pub fn classify(unit: []const u8, action: Action, r: Reach) ?Class {
	const propagated_start = !r.direct and action == .start and !r.is_new;
	if (propagated_start and (r.active or r.unloadable)) return null;
	if (isSessionUnit(unit)) return .skip;

	inline for (.{ ".mount", ".swap", ".automount" }) |sfx| {
		if (std.mem.endsWith(u8, unit, sfx)) return .a;
	}
	const boot_only = blk: {
		inline for (.{ "cogbox-additional-dirs", "resize-store-overlay", "cogbox-runtime-restore", "cogbox-vm-sshd-prep" }) |s| {
			if (stemIs(unit, s)) break :blk true;
		}
		// rw-<escaped overlay path>: the overlay preparation of every
		// harness overlay path (flake.nix onceUnits), not only those under
		// /root.
		inline for (.{ "rw-", "harness-", "cogbox-guest-" }) |p| {
			if (std.mem.startsWith(u8, unit, p)) break :blk true;
		}
		break :blk false;
	};
	if (boot_only) return if (propagated_start and r.once_marked and r.marker) null else .a;
	// cogbox-reply-route: a change to it, or a stop or restart reached over
	// an edge (its ExecStop deletes the reply table); a propagated start or
	// reload leaves the table loaded.
	if (stemIs(unit, "cogbox-reply-route") and (r.direct or action == .stop or action == .restart)) return .a;
	if (std.mem.startsWith(u8, unit, "dbus") and (action == .restart or action == .stop)) return .a;

	inline for (.{ "sshd", "systemd-resolved", "docker", "containerd" }) |s| {
		if (stemIs(unit, s)) return .b;
	}
	// podman's own daemon, socket and restart unit; a plugin's
	// oci-containers unit (podman-<name>.service) is the plugin's own. A
	// propagated start of the API service (a plugin unit Requires= it) is
	// no hazard: it is socket-activated, exits after 5 s idle (so whether
	// the guest runs it is chance) and owns no container, which run under
	// conmon. A change to its own unit, its stop and its restart still are.
	if (propagated_start and std.mem.eql(u8, unit, "podman.service")) return null;
	inline for (.{ "podman.service", "podman.socket", "podman-restart.service" }) |n| {
		if (std.mem.eql(u8, unit, n)) return .b;
	}
	if (std.mem.startsWith(u8, unit, "sshd@")) return .b;
	// logind is disruptive only when it goes down (spec section 3 class B:
	// "systemd-logind (restart)"); its reload is allowed (spec 4.1), and a
	// start is a no-op on the running logind. The propagated start matters:
	// linger-users, one of the idempotent oneshots a switch re-runs (an
	// induced start of every apply), Requires= it.
	if (stemIs(unit, "systemd-logind") and (action == .restart or action == .stop)) return .b;
	if (std.mem.eql(u8, unit, "firewall.service") and action != .reload) return .b;

	if (stemIs(unit, "systemd-networkd") or stemIs(unit, "nftables")) return .c;
	return null;
}

// --- the propagation closure --------------------------------------------------

pub const Seed = struct { unit: []const u8, action: Action, why: Why };

/// One step of a hazard's path: the unit and action it reached, and the edge
/// it was reached over (null for the seed itself).
pub const Hop = struct { unit: []const u8, action: Action, edge: ?Edge };

pub const Hazard = struct {
	class: Class,
	/// The unit's name (Graph.nameOf): a template instance reached by its
	/// own name keeps it, one reached through a specifier is the template.
	unit: []const u8,
	action: Action,
	/// Seed first, the hazard last.
	path: []const Hop,
	/// The seed's why.
	why: Why,
};

/// The closure caps the states it visits (unit x action); a graph past it is
/// refused with error.ClosureTooLarge rather than walked unbounded. NixOS
/// systems hold a few hundred units, so four actions each stay far below.
pub const max_closure_states: usize = 1 << 16;

/// Every hazard reachable from `seeds`, transitively: a stop propagates over
/// the reverse edges (Requires=, BindsTo=, PartOf=, .requires/ links,
/// StopPropagatedFrom=, PropagatesStopTo=, and RequiresMountsFor=/Requisite=,
/// whose stop propagation systemd also performs), a restart over the same as a
/// restart and onward as a start, a start over the forward edges (Requires=,
/// Requisite=, Wants=, BindsTo=, Upholds=, OnFailure=/OnSuccess=,
/// RequiresMountsFor=/WantsMountsFor=, and .wants/ .requires/ .upholds/ links)
/// and stops everything it Conflicts= with in either direction, a reload over
/// PropagatesReloadTo=/ReloadPropagatedFrom=. A seed is classified as the
/// plan's own action, except an induced start (Why.induced), which the hidden
/// target starts propagate; everything reached, as a propagated one, judged
/// against `rt` (classify). The walk goes on through a hazard (so every hazard
/// is listed) and through a unit the guest runs, since systemd adds the
/// dependencies of a no-op start too; only OnFailure=/OnSuccess= are not
/// followed from it, as a no-op start neither fails nor finishes. Units are
/// tracked by name (Graph.nameOf, so one instance of a template is not
/// another) and their edges read at their node; each hazard keeps the first
/// (shortest) path that reached it. Sorted by unit, then action.
pub fn closure(arena: Allocator, g: *const Graph, seeds: []const Seed, new_units: *const StrSet, rt: *const Runtime) ![]Hazard {
	const State = struct { name: []const u8, action: Action, prev: ?usize, edge: ?Edge, seed: usize };
	var states: std.ArrayList(State) = .empty;
	var seen: std.array_hash_map.String([4]bool) = .empty;

	const Visit = struct {
		fn add(a: Allocator, st: *std.ArrayList(State), sn: *std.array_hash_map.String([4]bool), name: []const u8, action: Action, prev: ?usize, edge: ?Edge, seed: usize) !void {
			const gop = try sn.getOrPut(a, name);
			if (!gop.found_existing) gop.value_ptr.* = .{ false, false, false, false };
			const idx = @intFromEnum(action);
			if (gop.value_ptr[idx]) return;
			if (st.items.len >= max_closure_states) return error.ClosureTooLarge;
			gop.value_ptr[idx] = true;
			try st.append(a, .{ .name = name, .action = action, .prev = prev, .edge = edge, .seed = seed });
		}
	};

	for (seeds, 0..) |s, si| try Visit.add(arena, &states, &seen, try g.nameOf(arena, s.unit), s.action, null, null, si);

	var hazards: std.ArrayList(Hazard) = .empty;
	var i: usize = 0;
	while (i < states.items.len) : (i += 1) {
		const st = states.items[i];
		const node = try g.nodeOf(arena, st.name);
		const reach: Reach = .{
			.direct = st.prev == null and seeds[st.seed].why != .induced,
			.is_new = new_units.contains(node),
			.once_marked = g.once_marked.contains(node),
			.active = rt.active.contains(st.name),
			.marker = rt.once.contains(baseName(st.name)),
			.unloadable = !g.files.contains(node) and rt.not_found.contains(st.name),
		};
		if (classify(st.name, st.action, reach)) |cls| {
			var hops: std.ArrayList(Hop) = .empty;
			var cur: ?usize = i;
			while (cur) |c| : (cur = states.items[c].prev) {
				const s = states.items[c];
				try hops.append(arena, .{ .unit = s.name, .action = s.action, .edge = s.edge });
			}
			std.mem.reverse(Hop, hops.items);
			try hazards.append(arena, .{ .class = cls, .unit = st.name, .action = st.action, .path = hops.items, .why = seeds[st.seed].why });
		}
		const noop = st.action == .start and reach.active;
		switch (st.action) {
			.stop => for (g.links(.rev, node)) |l| try Visit.add(arena, &states, &seen, l.name, .stop, i, l.edge, st.seed),
			.restart => {
				for (g.links(.rev, node)) |l| try Visit.add(arena, &states, &seen, l.name, .restart, i, l.edge, st.seed);
				for (g.links(.fwd, node)) |l| try Visit.add(arena, &states, &seen, l.name, .start, i, l.edge, st.seed);
				for (g.links(.conflict, node)) |l| try Visit.add(arena, &states, &seen, l.name, .stop, i, l.edge, st.seed);
			},
			.start => {
				for (g.links(.fwd, node)) |l| {
					if (noop and (l.edge == .on_failure or l.edge == .on_success)) continue;
					try Visit.add(arena, &states, &seen, l.name, .start, i, l.edge, st.seed);
				}
				for (g.links(.conflict, node)) |l| try Visit.add(arena, &states, &seen, l.name, .stop, i, l.edge, st.seed);
			},
			.reload => for (g.links(.reload, node)) |l| try Visit.add(arena, &states, &seen, l.name, .reload, i, l.edge, st.seed),
		}
	}
	std.mem.sort(Hazard, hazards.items, {}, struct {
		fn lt(_: void, x: Hazard, y: Hazard) bool {
			return switch (std.mem.order(u8, x.unit, y.unit)) {
				.lt => true,
				.gt => false,
				.eq => @intFromEnum(x.action) < @intFromEnum(y.action),
			};
		}
	}.lt);
	return hazards.items;
}

pub const Refusal = struct { reason: Reason, overridable: bool };

/// The plan's refusal, if any: the first never-overridable reason when there
/// is one (class A, then the skipped units: a non-empty `skipped` set or a
/// skip-class hazard), with overridable false even when B, C or D are present
/// too; otherwise the first of B, C, D (D when `reexec`), overridable.
pub fn verdict(hazards: []const Hazard, skipped: usize, reexec: bool) ?Refusal {
	var has = [_]bool{false} ** @typeInfo(Class).@"enum".fields.len;
	for (hazards) |h| has[@intFromEnum(h.class)] = true;
	if (skipped > 0) has[@intFromEnum(Class.skip)] = true;
	if (reexec) has[@intFromEnum(Class.d)] = true;
	inline for (.{ Class.a, Class.skip, Class.b, Class.c, Class.d }) |c| {
		// A and skip are checked first, so a B/C/D answer means neither is present.
		if (has[@intFromEnum(c)]) return .{ .reason = c.reason(), .overridable = c.reason().overridable() };
	}
	return null;
}

// --- tier 1: the boot shape ------------------------------------------------------

/// Tier 1 (b) and (c) mismatches (spec section 3), all never overridable.
pub const BootShapeReason = enum {
	/// microvm-run differs beyond the toplevel (init=) and regInfo=.
	boot_shape,
	/// The kernel, its modules or the initrd differ.
	kernel_modules,
	/// etc/fstab differs.
	fstab,
	/// init-interface-version differs.
	init_interface,

	pub fn name(r: BootShapeReason) []const u8 {
		return @tagName(r);
	}
};

pub const max_runner_script_bytes: usize = 4 << 20;
pub const runner_mask = "@COGBOX-MASKED@";

/// microvm-run with the value of every `init=` and `regInfo=` replaced by a
/// fixed token. A key matches only at a word start (the start, after
/// whitespace or a quote), so `rdinit=` is not `init=`; the value runs to the
/// next whitespace or quote. Everything else, the kernel and initrd paths
/// included, stays as it is, so any other difference is a different boot.
pub fn maskRunner(arena: Allocator, script: []const u8) Allocator.Error![]const u8 {
	var out: std.ArrayList(u8) = .empty;
	var p: usize = 0;
	while (p < script.len) {
		const at_word = p == 0 or std.mem.indexOfScalar(u8, " \t\n\r'\"", script[p - 1]) != null;
		var key_len: usize = 0;
		if (at_word) {
			inline for (.{ "init=", "regInfo=" }) |k| {
				if (std.mem.startsWith(u8, script[p..], k)) key_len = k.len;
			}
		}
		if (key_len == 0) {
			try out.append(arena, script[p]);
			p += 1;
			continue;
		}
		try out.appendSlice(arena, script[p .. p + key_len]);
		try out.appendSlice(arena, runner_mask);
		p += key_len;
		while (p < script.len and std.mem.indexOfScalar(u8, " \t\n\r'\"", script[p]) == null) p += 1;
	}
	return out.items;
}

const Read = union(enum) { absent, bytes: []const u8 };

fn readOptional(arena: Allocator, io: Io, path: []const u8, limit: usize) !Read {
	const b = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(limit + 1)) catch |err| switch (err) {
		error.FileNotFound => return .absent,
		error.StreamTooLong => return error.FileTooLarge,
		else => return err,
	};
	return .{ .bytes = b };
}

fn readsEql(x: Read, y: Read) bool {
	return switch (x) {
		.absent => y == .absent,
		.bytes => |b| switch (y) {
			.absent => false,
			.bytes => |c| std.mem.eql(u8, b, c),
		},
	};
}

fn realOptional(arena: Allocator, io: Io, path: []const u8) !?[]const u8 {
	return std.Io.Dir.cwd().realPathFileAlloc(io, path, arena) catch |err| switch (err) {
		error.FileNotFound => return null,
		else => return err,
	};
}

/// Tier 1 (b) and (c): compare the booted runner `booted` (B) with the new
/// runner `new` (R), both runner store paths, and name the first mismatch in
/// the spec's order (boot_shape, kernel_modules, fstab, init_interface), or
/// null when the boot shape is the same. A runner without bin/microvm-run, or
/// one whose share/microvm/system does not resolve, cannot be shown to match:
/// boot_shape and kernel_modules respectively (fail closed). The kernel,
/// kernel-modules and initrd links are compared by resolved target (absent on
/// both sides is equal); init-interface-version and etc/fstab by bytes
/// (absent on both sides is equal, absent on one is a mismatch). Unexpected
/// I/O errors propagate; the caller fails the apply.
pub fn bootShape(arena: Allocator, io: Io, booted: []const u8, new: []const u8) !?BootShapeReason {
	const b_run = try readOptional(arena, io, try std.fmt.allocPrint(arena, "{s}/bin/microvm-run", .{booted}), max_runner_script_bytes);
	const r_run = try readOptional(arena, io, try std.fmt.allocPrint(arena, "{s}/bin/microvm-run", .{new}), max_runner_script_bytes);
	if (b_run == .absent or r_run == .absent) return .boot_shape;
	if (!std.mem.eql(u8, try maskRunner(arena, b_run.bytes), try maskRunner(arena, r_run.bytes))) return .boot_shape;

	const b_sys = try realOptional(arena, io, try std.fmt.allocPrint(arena, "{s}/share/microvm/system", .{booted})) orelse return .kernel_modules;
	const r_sys = try realOptional(arena, io, try std.fmt.allocPrint(arena, "{s}/share/microvm/system", .{new})) orelse return .kernel_modules;
	inline for (.{ "kernel", "kernel-modules", "initrd" }) |link| {
		const x = try realOptional(arena, io, try std.fmt.allocPrint(arena, "{s}/" ++ link, .{b_sys}));
		const y = try realOptional(arena, io, try std.fmt.allocPrint(arena, "{s}/" ++ link, .{r_sys}));
		const same = if (x) |xv| (if (y) |yv| std.mem.eql(u8, xv, yv) else false) else y == null;
		if (!same) return .kernel_modules;
	}
	const small: usize = 1 << 20;
	const b_fstab = try readOptional(arena, io, try std.fmt.allocPrint(arena, "{s}/etc/fstab", .{b_sys}), small);
	const r_fstab = try readOptional(arena, io, try std.fmt.allocPrint(arena, "{s}/etc/fstab", .{r_sys}), small);
	if (!readsEql(b_fstab, r_fstab)) return .fstab;
	const b_iv = try readOptional(arena, io, try std.fmt.allocPrint(arena, "{s}/init-interface-version", .{b_sys}), small);
	const r_iv = try readOptional(arena, io, try std.fmt.allocPrint(arena, "{s}/init-interface-version", .{r_sys}), small);
	if (!readsEql(b_iv, r_iv)) return .init_interface;
	return null;
}

// --- the host plan as text (`cogbox __unitplan`) -----------------------------------

/// The host plan as lines: `<action> <unit> <why>` per planned unit, in units()
/// order, `skip <unit>` per unit switch-ng would not restart, and `reexec
/// yes|no` last. What `cogbox __unitplan` prints; checks.cogbox-vm phase LA
/// compares it with a real guest's `switch-to-configuration dry-activate`.
pub fn renderPlan(arena: Allocator, plan: *const HostPlan, reexec: bool) Allocator.Error![]u8 {
	var out: std.ArrayList(u8) = .empty;
	for (try plan.units(arena)) |u| try out.print(arena, "{s} {s} {s}\n", .{ @tagName(u.action), u.unit, u.why.name() });
	for (try sortedKeys(arena, &plan.sets.skip)) |u| try out.print(arena, "skip {s}\n", .{u});
	try out.print(arena, "reexec {s}\n", .{if (reexec) "yes" else "no"});
	return out.items;
}

/// `cogbox __unitplan P T` (hidden): the host plan for switching from toplevel
/// P to toplevel T (renderPlan) on stdout. Exit 0, 64 on a usage error, 70
/// when a side cannot be planned (with the error on stderr).
pub fn cliMain(gpa: Allocator, io: Io, argv: []const []const u8) u8 {
	if (argv.len != 2) {
		writeTo(io, Io.File.stderr(), "usage: cogbox __unitplan <old-toplevel> <new-toplevel>\n");
		return 64;
	}
	var arena_state = std.heap.ArenaAllocator.init(gpa);
	defer arena_state.deinit();
	const arena = arena_state.allocator();
	const plan = planHost(arena, io, argv[0], argv[1]) catch |err| {
		writeTo(io, Io.File.stderr(), std.fmt.allocPrint(arena, "cogbox __unitplan: cannot plan: {s}\n", .{@errorName(err)}) catch "cogbox __unitplan: cannot plan\n");
		return 70;
	};
	const reexec = reexecNeeded(arena, io, argv[0], argv[1]) catch |err| {
		writeTo(io, Io.File.stderr(), std.fmt.allocPrint(arena, "cogbox __unitplan: cannot compare systemd: {s}\n", .{@errorName(err)}) catch "cogbox __unitplan: cannot compare systemd\n");
		return 70;
	};
	const text = renderPlan(arena, &plan, reexec) catch return 70;
	writeTo(io, Io.File.stdout(), text);
	return 0;
}

fn writeTo(io: Io, file: Io.File, bytes: []const u8) void {
	var buf: [4096]u8 = undefined;
	var w = file.writer(io, &buf);
	w.interface.writeAll(bytes) catch return;
	w.flush() catch {};
}
