// Host-only named secret store for cogbox.
//
// An operator binds a credential by NAME, host-side, with `cogbox secret add`.
// The value lives at <dir>/<name> (the raw secret, 0600) and metadata at
// <dir>/<name>.meta (JSON: audience, kind, tier, bound-at). The global store is
// <config>/secrets/; sidecar-produced per-instance secrets use the same layout
// under <config>/instances/<inst>/secrets/.
//
// SECURITY: the store NEVER holds a path or value chosen by a plugin -- a plugin
// only NAMES a secret it wants injected and the AUDIENCE host it targets; the
// operator binds the real value here. The `audience` in the meta is the host(s)
// the secret may be injected to; the inject-conf renderer refuses to emit a spec
// whose host is not the bound secret's audience, so a hostile plugin cannot
// redirect a bound secret to an attacker host. Nothing here is shared into the
// guest.
//
// This file is split into a PURE layer (validName / buildMeta / parseMeta --
// unit-tested) and an IO layer (add / lookup / remove -- covered by the
// launcher + NixOS VM integration tests, mirroring how rules/config.zig leaves
// its load/save IO to integration coverage).

const std = @import("std");
const proxygid = @import("proxygid.zig");

pub const Gid = proxygid.Gid;

// --- pure layer ------------------------------------------------------------

/// A secret name: 1..64 chars, charset [A-Za-z0-9_-]. Excludes '.' and '/', so
/// neither `<name>` nor the derived `<name>.meta` can traverse out of the store
/// directory. This is the same shape a plugin manifest's `secret` field must
/// satisfy (validated again plugin-side before it reaches config.json).
pub fn validName(name: []const u8) bool {
	if (name.len == 0 or name.len > 64) return false;
	for (name) |c| switch (c) {
		'a'...'z', 'A'...'Z', '0'...'9', '-', '_' => {},
		else => return false,
	};
	return true;
}

pub const Meta = struct {
	/// Exact host(s) the secret may be injected to. null = unset = not
	/// injectable (the renderer skips it and `secret ls` flags it).
	audience: ?[]const u8 = null,
	/// Injection style hint: "bearer" | "cookie" (others are harness-internal).
	kind: []const u8 = "bearer",
	/// "durable" (a long-lived operator secret) | "derived" (a short-lived
	/// session minted by a sidecar). A derived secret may not be bound as a
	/// sidecar loginSecret.
	tier: []const u8 = "durable",
	bound_at: ?i64 = null,
};

pub fn appendJsonString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
	try out.append(allocator, '"');
	for (s) |c| switch (c) {
		'"' => try out.appendSlice(allocator, "\\\""),
		'\\' => try out.appendSlice(allocator, "\\\\"),
		'\n' => try out.appendSlice(allocator, "\\n"),
		'\r' => try out.appendSlice(allocator, "\\r"),
		'\t' => try out.appendSlice(allocator, "\\t"),
		0...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
			var b: [8]u8 = undefined;
			try out.appendSlice(allocator, std.fmt.bufPrint(&b, "\\u{x:0>4}", .{c}) catch unreachable);
		},
		else => try out.append(allocator, c),
	};
	try out.append(allocator, '"');
}

/// Serialize `meta` to its on-disk JSON form (jq --tab shape). Pure.
pub fn buildMeta(allocator: std.mem.Allocator, meta: Meta) ![]u8 {
	var out: std.ArrayList(u8) = .empty;
	errdefer out.deinit(allocator);
	try out.appendSlice(allocator, "{\n\t\"audience\": ");
	if (meta.audience) |a| try appendJsonString(allocator, &out, a) else try out.appendSlice(allocator, "null");
	try out.appendSlice(allocator, ",\n\t\"kind\": ");
	try appendJsonString(allocator, &out, meta.kind);
	try out.appendSlice(allocator, ",\n\t\"tier\": ");
	try appendJsonString(allocator, &out, meta.tier);
	try out.appendSlice(allocator, ",\n\t\"bound_at\": ");
	if (meta.bound_at) |b| {
		var nb: [32]u8 = undefined;
		try out.appendSlice(allocator, std.fmt.bufPrint(&nb, "{d}", .{b}) catch unreachable);
	} else try out.appendSlice(allocator, "null");
	try out.appendSlice(allocator, "\n}\n");
	return out.toOwnedSlice(allocator);
}

/// Parse the meta JSON `text`. Missing/invalid fields fall back to defaults
/// (audience null, kind "bearer"). String fields are dup'd into `allocator`.
/// Pure (no IO).
pub fn parseMeta(allocator: std.mem.Allocator, text: []const u8) !Meta {
	var meta: Meta = .{};
	var parsed = std.json.parseFromSlice(std.json.Value, allocator, text, .{}) catch return meta;
	defer parsed.deinit();
	const root = parsed.value;
	if (root != .object) return meta;
	if (root.object.get("audience")) |v| {
		if (v == .string) meta.audience = try allocator.dupe(u8, v.string);
	}
	if (root.object.get("kind")) |v| {
		if (v == .string) meta.kind = try allocator.dupe(u8, v.string);
	}
	if (root.object.get("tier")) |v| {
		if (v == .string) meta.tier = try allocator.dupe(u8, v.string);
	}
	if (root.object.get("bound_at")) |v| {
		if (v == .integer) meta.bound_at = v.integer;
	}
	return meta;
}

// --- IO layer --------------------------------------------------------------

fn metaPath(allocator: std.mem.Allocator, dir: []const u8, name: []const u8) ![]u8 {
	const base = try std.fmt.allocPrint(allocator, "{s}.meta", .{name});
	defer allocator.free(base);
	return std.fs.path.join(allocator, &.{ dir, base });
}

/// Atomically write `bytes` to `path` with mode 0600 (unique temp + rename).
/// Exclusive creation never reuses a stale inode or follows a planted symlink.
/// Each write owns its temp; errors remove it without touching other writers.
///
/// `group`, when set, is the L7 proxy's gid (see proxygid.zig): the temp file is
/// chowned to it and widened to 0640 BEFORE the rename, so the file is
/// group-readable from the very first instant it is observable at `path`.
/// Returns whether that grant is in place -- false both when no group was asked
/// for and when applying it failed (in which case the file keeps its 0600 and
/// the caller warns; the next inject render's credgrant pass still grants it, so
/// this degrades to the pre-existing behavior rather than to a broken bind).
///
/// The widening happens on the TEMP path, never on the live one: at no point is
/// a file both reachable at `path` and readable by a group it should not be.
/// Ordering inside mirrors credgrant.grantFile -- chown first, then chmod, so a
/// chmod that outlived a failed chown cannot publish group-read to whatever
/// group the file happened to carry.
fn writeFile0600(allocator: std.mem.Allocator, io: std.Io, path: []const u8, bytes: []const u8, group: ?Gid) !bool {
	const cwd = std.Io.Dir.cwd();
	for (0..8) |_| {
		var rnd: [16]u8 = undefined;
		io.random(&rnd);
		var hexb: [32]u8 = undefined;
		_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
		const tmp = try std.fmt.allocPrint(allocator, "{s}.tmp-{s}", .{ path, hexb });
		defer allocator.free(tmp);
		const f = cwd.createFile(io, tmp, .{ .exclusive = true, .permissions = std.Io.File.Permissions.fromMode(0o600) }) catch |err| switch (err) {
			error.PathAlreadyExists => continue,
			else => return err,
		};
		errdefer cwd.deleteFile(io, tmp) catch {};
		defer f.close(io);
		var wbuf: [4096]u8 = undefined;
		var w = f.writer(io, &wbuf);
		try w.interface.writeAll(bytes);
		try w.flush();
		try f.sync(io);
		var granted = false;
		if (group) |gid| granted = stageGroupRead(io, f, gid);
		try cwd.rename(tmp, cwd, path, io);
		return granted;
	}
	return error.PathAlreadyExists;
}

/// chown+chmod the still-unpublished temp file so `gid` may read it: 0600 ->
/// 0640, exactly the transition credgrant.grantedMode makes. Best effort by
/// design (see writeFile0600); returns false if either half did not land.
fn stageGroupRead(io: std.Io, f: std.Io.File, gid: Gid) bool {
	f.setOwner(io, null, gid) catch return false;
	f.setPermissions(io, .fromMode(0o640)) catch return false;
	return true;
}

fn readAll(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ?[]u8 {
	const cwd = std.Io.Dir.cwd();
	const f = cwd.openFile(io, path, .{}) catch return null;
	defer f.close(io);
	var rbuf: [4096]u8 = undefined;
	var r = f.reader(io, &rbuf);
	return r.interface.allocRemaining(allocator, .limited(1 << 20)) catch null;
}

/// Bind `name` to `value` (0600) plus its `meta` sidecar, under `dir`
/// (created 0700-ish if absent). Overwrites atomically (rotation-safe).
pub fn add(allocator: std.mem.Allocator, io: std.Io, dir: []const u8, name: []const u8, value: []const u8, meta: Meta) !void {
	_ = try addForProxy(allocator, io, dir, name, value, meta, null);
}

/// What a bind did about the L7 proxy's read access, so the caller can say so.
pub const AddOutcome = struct {
	/// A proxy gid was configured AND the value file landed group-readable by
	/// it. False both when no gid was configured (container/k8s/local: nothing
	/// to do) and when the chown/chmod failed (the render's credgrant pass is
	/// then the only thing that can grant it -- worth a warning).
	proxy_readable: bool = false,
};

/// `add`, but staging the L7 proxy's read access as part of the same atomic
/// write when `proxy_gid` is set.
///
/// WHY. On a deployment with a uid split (COGBOX_PROXY_RUNAS, i.e. the GCE host
/// image) the store is written by the control uid at 0600 and read by the
/// proxy's uid, which gets its read access from a group grant made by the inject
/// RENDER (rules/credgrant.zig). A bind and its render are two separate control
/// execs, so between them the credential existed but was unreadable: the addon
/// fail-closed with 403 "credential unavailable" for roughly an SSH round-trip.
/// Staging the group on the temp file closes that window -- the file is readable
/// the instant it is nameable -- and makes the render's chmod a no-op (its
/// `want == mode` short-circuit) rather than the moment of readability. That
/// no-op is pinned end to end by rules/main.zig's "a GCE-shaped render over a
/// STAGED bind is a permission no-op": the render leaves both the mode AND the
/// mtime where the bind put them, which matters because the addon caches the
/// credential's value keyed on that mtime.
///
/// Only a credential with an AUDIENCE is staged: a secret with no audience is
/// not injectable at all (the renderer skips it), so there is no window to close
/// and no reason to widen it. The `.meta` sidecar is never widened -- the proxy
/// reads values, not metadata.
///
/// SCOPE, precisely: this gate is WIDER than the set credgrant grants, which is
/// "exactly the value files the conf being written names". It has to be -- the
/// bind cogworx actually issues is a GLOBAL `cogbox secret add` with no `-n`, so
/// at this point there is no instance and no conf to check the audience against.
/// The render remains the authority in the sense that its revoke pass takes
/// group-read back off any value file the conf it writes does not name -- but it
/// is NOT prompt: `secret add` re-renders only when given `-n`, that re-render
/// returns early for an instance with no live runtime dir, and the GCE control
/// plane's follow-up `secret reload` is skipped for a non-live instance and only
/// logged when it fails. So an audience-bearing value that no current conf names
/// can stay 0640 (proxy-group read; still owner-write, never world-readable)
/// until that instance's next render -- at boot, at the latest -- rather than for
/// "roughly an SSH round-trip". That is the price of closing the 403 window; the
/// narrowing, if it is ever wanted, is to stage only for audiences the instance's
/// own conf names, which is computable on the `-n` path and not on this one.
/// Documented in docs/network-filtering.md's "At bind time, too" bullet.
pub fn addForProxy(
	allocator: std.mem.Allocator,
	io: std.Io,
	dir: []const u8,
	name: []const u8,
	value: []const u8,
	meta: Meta,
	proxy_gid: ?Gid,
) !AddOutcome {
	if (!validName(name)) return error.InvalidName;
	const cwd = std.Io.Dir.cwd();
	try cwd.createDirPath(io, dir);

	const stage_gid: ?Gid = if (meta.audience == null) null else proxy_gid;

	const vpath = try std.fs.path.join(allocator, &.{ dir, name });
	defer allocator.free(vpath);
	const granted = try writeFile0600(allocator, io, vpath, value, stage_gid);

	const mpath = try metaPath(allocator, dir, name);
	defer allocator.free(mpath);
	const mjson = try buildMeta(allocator, meta);
	defer allocator.free(mjson);
	_ = try writeFile0600(allocator, io, mpath, mjson, null);

	return .{ .proxy_readable = granted };
}

/// Remove a bound secret + its meta. Returns true if the value file existed.
pub fn remove(allocator: std.mem.Allocator, io: std.Io, dir: []const u8, name: []const u8) !bool {
	if (!validName(name)) return error.InvalidName;
	const cwd = std.Io.Dir.cwd();
	const vpath = try std.fs.path.join(allocator, &.{ dir, name });
	defer allocator.free(vpath);
	const mpath = try metaPath(allocator, dir, name);
	defer allocator.free(mpath);
	var existed = true;
	cwd.access(io, vpath, .{}) catch {
		existed = false;
	};
	cwd.deleteFile(io, vpath) catch {};
	cwd.deleteFile(io, mpath) catch {};
	return existed;
}

/// Enumerate the BOUND secret names under `dir` (value files present; the
/// `.meta` sidecars and `.tmp` write-temps are skipped, invalid names ignored).
/// Names are dup'd into `allocator` -- pass an arena. A never-bound store (no
/// dir yet) yields an empty list, not an error. Used by the container enforcer
/// render to seed an inject spec per bound git secret (it can't know provider
/// names a priori, unlike the single reserved claude-oauth secret).
pub fn listBound(allocator: std.mem.Allocator, io: std.Io, dir: []const u8) ![][]const u8 {
	var out: std.ArrayList([]const u8) = .empty;
	errdefer out.deinit(allocator);
	const cwd = std.Io.Dir.cwd();
	var d = cwd.openDir(io, dir, .{ .iterate = true }) catch |err| switch (err) {
		error.FileNotFound => return out.toOwnedSlice(allocator),
		else => return err,
	};
	defer d.close(io);
	var iter = d.iterate();
	while (try iter.next(io)) |entry| {
		if (entry.kind != .file) continue;
		if (std.mem.endsWith(u8, entry.name, ".meta")) continue;
		if (std.mem.endsWith(u8, entry.name, ".tmp")) continue;
		if (!validName(entry.name)) continue;
		try out.append(allocator, try allocator.dupe(u8, entry.name));
	}
	return out.toOwnedSlice(allocator);
}

pub const Resolved = struct {
	/// Absolute path of the value file (the addon reads this as cred_file).
	/// Allocated in the `allocator` passed to lookup.
	value_path: []const u8,
	/// True iff the value file exists (an unbound spec is skipped by the
	/// renderer -- fail closed).
	bound: bool,
	meta: Meta,
};

/// Resolve a secret by (dir, name). Returns null only for an invalid name.
/// Strings are allocated in `allocator` -- pass an arena you own (the renderer
/// passes the loaded config's tree allocator).
pub fn lookup(allocator: std.mem.Allocator, io: std.Io, dir: []const u8, name: []const u8) !?Resolved {
	if (!validName(name)) return null;
	const value_path = try std.fs.path.join(allocator, &.{ dir, name });
	const cwd = std.Io.Dir.cwd();
	var bound = true;
	cwd.access(io, value_path, .{}) catch {
		bound = false;
	};
	var meta: Meta = .{};
	const mpath = try metaPath(allocator, dir, name);
	defer allocator.free(mpath);
	if (readAll(allocator, io, mpath)) |txt| {
		defer allocator.free(txt);
		meta = try parseMeta(allocator, txt);
	}
	return Resolved{ .value_path = value_path, .bound = bound, .meta = meta };
}
