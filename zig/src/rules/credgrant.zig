// Give the L7 proxy uid read access to EXACTLY the credential files the inject
// conf names -- and to nothing else in the secret store.
//
// WHY THIS EXISTS. The mitmproxy terminate tier is what stamps a bound
// credential onto a request, and on a deployment that sets COGBOX_PROXY_RUNAS
// (the GCE host image) it does NOT run as the uid that owns the store: the
// launcher drops it to a dedicated uid with `setpriv --reuid --regid
// --clear-groups`, because the nftables floor expresses "guest-originated" as a
// `meta skuid` match and therefore needs the proxy on its own uid. The store,
// meanwhile, is written by the control uid (root) at 0600. So the addon opened
// the cred file, got EACCES, and fail-closed every request on the injected host
// with `cogbox-l7: credential unavailable` -- per-user Claude auth and per-user
// git injection were dead on that backend even though the bind, the seed, the
// spec, the terminate-allow and the funnel were all correct.
//
// The CONTAINER backend never had the bug and must not be touched: there the
// proxy runs inside the enforcer pod, which also owns the enforcer-private store
// (COGBOX_GLOBAL_SECRETS_DIR / COGBOX_INSTANCE_SECRETS_DIR), so reader and owner
// are the same uid by construction and no deployment sets COGBOX_PROXY_RUNAS.
// `Grants.gid == null` is exactly that case and makes every entry point below a
// no-op -- see `apply`.
//
// WHY A GROUP AND NOT AN OWNER CHANGE. `--regid` sets the proxy's PRIMARY gid,
// and `--clear-groups` drops only SUPPLEMENTARY groups, so a grant made through
// the primary group survives the drop (measured against real setpriv, not
// reasoned about: with the store file at 0640 root:<gid> the dropped uid reads
// it, with the file at 0600 root:root it gets EACCES). Group-read also keeps the
// grant strictly READ-ONLY and leaves the file owned by the control uid, which
// still has to WRITE it -- cogworx re-binds a rotated token over the same name
// (`secret add` is atomic-rename, rotation-safe), and the addon never writes a
// store-backed cred file (renderL7Inject emits no `refresh` block for one, so
// CredStore.ensure_fresh returns immediately).
//
// WHY IT IS DRIVEN FROM THE RENDER AND NOT FROM BOOT. Binds happen at RUNTIME
// (`cogbox secret add -n <inst>` over the control channel, then `secret
// reload`), so a one-shot chown in the host image's boot script would miss every
// connect-later bind -- and an atomic-rename rebind resets the file's group
// anyway. The grant is therefore recomputed on every inject render, from the
// same pass that emits the conf: `renderL7Inject` calls `Grants.note` at the exact
// statement that puts `cred_file` into a spec, so the readable set and the named
// set cannot drift apart. Nothing here ever takes a path from config.json, a
// plugin manifest or an operator override -- `Grants.note` only ever receives a
// `secret_store.Resolved.value_path`, i.e. `<store dir>/<validName>`, so this is
// not a "chmod whatever a conf file names" primitive.
//
// REVOCATION. `apply` walks the whole store first and CLEARS the group bits off
// every bound value file, then re-grants only the noted ones. So unbinding a
// secret (the value file is deleted), removing a spec, an audience mismatch, or a
// git bind losing its grant rules all take the read access away again on the
// next render -- there is no state to keep in sync and no accumulation of stale
// grants. The invariant is: after any inject render, the proxy gid can read a
// store value file IFF that file is named in the conf the same render wrote.

const std = @import("std");
const secret_mod = @import("secret_module");
const secret_store = secret_mod.store;

const proxygid = secret_mod.proxygid;

pub const Gid = proxygid.Gid;
const Mode = std.posix.mode_t;

/// Owner bits kept, group set to read-only, other bits cleared: 0600 -> 0640.
fn grantedMode(mode: Mode) Mode {
	return (mode & ~@as(Mode, 0o077)) | 0o040;
}

/// Clear the group triad, which is the ONLY thing a grant here can have added.
/// Deliberately not "force 0600": this leaves owner/other bits exactly as found,
/// so the revoke pass can never stomp a mode somebody set for another reason.
fn revokedMode(mode: Mode) Mode {
	return mode & ~@as(Mode, 0o070);
}

/// Add the SEARCH bit for the group, never read: the proxy must be able to
/// traverse the store directory to open a granted file by name, but must not be
/// able to ENUMERATE the store (`+x` without `+r` is exactly that distinction).
fn searchableMode(mode: Mode) Mode {
	return mode | 0o010;
}

// The COGBOX_PROXY_RUNAS parse + /etc/group lookup live in the SECRET module
// (secret/proxygid.zig), because `secret add` needs the same answer to stage the
// grant onto the value file it writes and the module graph only allows
// rules -> secret. Re-exported here so this file stays the one place a reader
// looks for "who may read a bound credential", and so the two ends are provably
// one implementation rather than two that agree today.
pub const runasGroup = proxygid.runasGroup;
pub const lookupGidIn = proxygid.lookupGidIn;

/// The gid the L7 proxy runs under, from `COGBOX_PROXY_RUNAS`, or null when the
/// deployment runs no uid split (container, k8s, local -- none of them set it, so
/// none of them is affected by any of this). Resolved from the SAME variable the
/// launcher hands `setpriv`, so the identity that must read the credential and
/// the identity the proxy actually becomes are one value, not two that can drift.
pub fn proxyGidFromEnv(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map) !?Gid {
	const runas = try proxygid.fromEnv(allocator, io, env);
	if (runas.unresolved_group) |group| {
		// LOUD, not fatal. Fatal here would abort the render that also writes
		// netfilter-rules and l7-rules (the floor), which is a far worse failure
		// than an un-stamped credential -- and the credential path still fails
		// CLOSED on its own (the addon denies with "credential unavailable").
		warn(io, "COGBOX_PROXY_RUNAS names group '{s}', which /etc/group does not define; the L7 proxy will not be able to read bound credentials", .{group});
	}
	return runas.gid;
}

/// The set of store credential files this render's inject conf names, plus the
/// gid they must become readable by. Collected during the render and applied in
/// one pass just before the conf is written (see `apply`).
pub const Grants = struct {
	/// Null => no uid split configured => every method here is a no-op.
	gid: ?Gid,
	arena: std.heap.ArenaAllocator,
	paths: std.ArrayList([]const u8),

	pub fn init(gpa: std.mem.Allocator, gid: ?Gid) Grants {
		return .{ .gid = gid, .arena = std.heap.ArenaAllocator.init(gpa), .paths = .empty };
	}

	pub fn deinit(self: *Grants) void {
		self.arena.deinit();
	}

	/// Record a credential file the conf now names. Called from the statement
	/// that emits `cred_file`, so the two cannot disagree. The path is copied
	/// into this struct's arena because the renderer's own arena dies with the
	/// render.
	pub fn note(self: *Grants, path: []const u8) !void {
		if (self.gid == null) return;
		const a = self.arena.allocator();
		try self.paths.append(a, try a.dupe(u8, path));
	}

	fn noted(self: *const Grants, path: []const u8) bool {
		for (self.paths.items) |p| {
			if (std.mem.eql(u8, p, path)) return true;
		}
		return false;
	}

	/// Bring the store's permissions in line with what this render named:
	/// re-tighten every bound value file in `stores`, then grant group-read on
	/// the noted ones and group-search on the directories holding them.
	///
	/// Best-effort PER FILE and never silent: a file that cannot be adjusted is
	/// warned about and skipped, because failing the whole render would take the
	/// netfilter floor down with it. Ordering is load-bearing in two places --
	/// the caller applies this BEFORE writing the conf (the addon hot-reloads on
	/// the conf's mtime, so a file it is about to be told about must already be
	/// readable), and the chown here happens BEFORE the chmod (a chmod that
	/// landed on a file whose chown had failed would publish group-read to
	/// whatever group the file already had).
	pub fn apply(self: *Grants, io: std.Io, stores: []const []const u8) !void {
		const gid = self.gid orelse return;
		const a = self.arena.allocator();

		for (stores, 0..) |dir, i| {
			// The two store dirs are the same string on a layout that has no
			// separate per-instance store; walking it twice would be harmless but
			// pointless.
			var dup = false;
			for (stores[0..i]) |earlier| {
				if (std.mem.eql(u8, earlier, dir)) dup = true;
			}
			if (dup) continue;

			const names = secret_store.listBound(a, io, dir) catch |err| {
				warn(io, "could not enumerate the secret store {s} to reconcile L7 credential access: {s}", .{ dir, @errorName(err) });
				continue;
			};
			for (names) |name| {
				const path = try std.fs.path.join(a, &.{ dir, name });
				if (self.noted(path)) grantFile(io, path, gid) else revokeFile(io, path);
			}
		}

		// Traverse rights come from the noted paths themselves rather than from
		// `stores`, so the directory that is opened is always the one a granted
		// file actually lives in. Today's store dirs are already world-searchable
		// (createDirPath's 0755), which makes this a no-op in authority -- it is
		// here so that TIGHTENING the store later (the obvious next hardening)
		// cannot silently re-break credential access with the same symptom.
		for (self.paths.items) |path| {
			const dir = std.fs.path.dirname(path) orelse continue;
			grantSearch(io, dir, gid);
		}
	}
};

fn grantFile(io: std.Io, path: []const u8, gid: Gid) void {
	const cwd = std.Io.Dir.cwd();
	// NOFOLLOW on every credential-file operation here. `secret add` only ever
	// writes regular files and only the store's owner can create entries in it, so
	// a symlink in the store is not a reachable state -- but the consequence if it
	// ever became one is that this code would publish group-read on the symlink's
	// TARGET, so it refuses rather than follows. (The store's own directory is
	// opened normally: a store path legitimately may be reached through one.)
	const f = cwd.openFile(io, path, .{ .follow_symlinks = false }) catch |err| {
		warn(io, "could not open the bound credential {s} to grant the L7 proxy read access: {s}", .{ path, @errorName(err) });
		return;
	};
	defer f.close(io);
	const st = f.stat(io) catch |err| {
		warn(io, "could not stat the bound credential {s}: {s}", .{ path, @errorName(err) });
		return;
	};
	f.setOwner(io, null, gid) catch |err| {
		warn(io, "could not set group {d} on the bound credential {s}, so the L7 proxy cannot read it and injection for it will fail closed: {s}", .{ gid, path, @errorName(err) });
		return;
	};
	const mode = st.permissions.toMode();
	const want = grantedMode(mode);
	// Already granted (every render after the first): nothing to change, and
	// nothing to say. So the line below is a TRANSITION log, not per-render noise.
	if (want == mode) return;
	f.setPermissions(io, .fromMode(want)) catch |err| {
		warn(io, "could not set mode {o} on the bound credential {s}, so the L7 proxy cannot read it and injection for it will fail closed: {s}", .{ want, path, @errorName(err) });
		return;
	};
	// AFTER the chmod, and only on a real transition (the want==mode short-circuit
	// above): move the file's MTIME, because that is the addon's cache key for the
	// credential's VALUE (_read_json / _read_raw cache `(mtime, value)`) and chmod
	// moves ctime only. A rebind is atomic-rename + a SEPARATE `secret reload`
	// exec, so between the two the value file is back at 0600 while the previous
	// conf still names it; a guest request landing in that window makes the addon
	// stat the mtime, get EACCES, and cache (mtime, None). Without this bump the
	// re-grant leaves that mtime untouched, the negative entry stays cache-valid
	// forever, and the host silently 403s "credential unavailable" with no
	// self-heal. Ordered after the chmod so no reader can observe the new key while
	// the file is still unreadable. (The conf write that follows this render also
	// flushes those caches -- see reload.writeL7Inject and CredStore._load_conf --
	// so the two fixes cover each other; this one is the leg that does not depend
	// on the addon having reloaded the conf yet.)
	f.setTimestampsNow(io) catch |err| {
		warn(io, "granted the L7 proxy read on {s} but could not bump its mtime, so a credential read the addon cached before the grant may not be reconsidered: {s}", .{ path, @errorName(err) });
	};
	// Say so. The failure this replaces was entirely SILENT host-side -- the only
	// symptom was a 403 inside the guest -- so the one state change that makes a
	// bound credential injectable is worth a journal line.
	info(io, "granted the L7 proxy (gid {d}) read on the bound credential {s}", .{ gid, path });
}

fn revokeFile(io: std.Io, path: []const u8) void {
	const cwd = std.Io.Dir.cwd();
	const st = cwd.statFile(io, path, .{ .follow_symlinks = false }) catch |err| {
		warn(io, "could not stat {s} to revoke L7 proxy access: {s}", .{ path, @errorName(err) });
		return;
	};
	const mode = st.permissions.toMode();
	const want = revokedMode(mode);
	// Nothing to take away: the overwhelmingly common case (a store of 0600
	// files), so no render touches a file's ctime for no reason.
	if (want == mode) return;
	const f = cwd.openFile(io, path, .{ .follow_symlinks = false }) catch |err| {
		warn(io, "could not open {s} to revoke L7 proxy access: {s}", .{ path, @errorName(err) });
		return;
	};
	defer f.close(io);
	f.setPermissions(io, .fromMode(want)) catch |err| {
		warn(io, "could not revoke L7 proxy access to {s} (it stays group-readable): {s}", .{ path, @errorName(err) });
		return;
	};
	info(io, "revoked L7 proxy access to {s} (this render's inject conf does not name it)", .{path});
}

fn grantSearch(io: std.Io, dir_path: []const u8, gid: Gid) void {
	const cwd = std.Io.Dir.cwd();
	const st = cwd.statFile(io, dir_path, .{}) catch |err| {
		warn(io, "could not stat the secret store {s}: {s}", .{ dir_path, @errorName(err) });
		return;
	};
	// `.iterate` is not for iterating: without it the Dir is opened O_PATH, and
	// fchown/fchmod on an O_PATH descriptor is EBADF.
	var d = cwd.openDir(io, dir_path, .{ .iterate = true }) catch |err| {
		warn(io, "could not open the secret store {s} to grant the L7 proxy traverse access: {s}", .{ dir_path, @errorName(err) });
		return;
	};
	defer d.close(io);
	d.setOwner(io, null, gid) catch |err| {
		warn(io, "could not set group {d} on the secret store {s}: {s}", .{ gid, dir_path, @errorName(err) });
		return;
	};
	const mode = st.permissions.toMode();
	const want = searchableMode(mode);
	if (want == mode) return;
	d.setPermissions(io, .fromMode(want)) catch |err| {
		warn(io, "could not make the secret store {s} traversable by the L7 proxy: {s}", .{ dir_path, @errorName(err) });
	};
}

/// pub because the render's other half (reload.zig's foreign-spec carry-over)
/// warns the same way, for the same reasons -- one warner, one stream, one
/// under-test rule.
pub fn warn(io: std.Io, comptime fmt: []const u8, args: anytype) void {
	emit(io, "cogbox: warning: " ++ fmt ++ "\n", args);
}

fn info(io: std.Io, comptime fmt: []const u8, args: anytype) void {
	emit(io, "cogbox: " ++ fmt ++ "\n", args);
}

/// stderr, never stdout: `__render-rules` runs inside the launcher (whose stdout
/// is a user-facing stream) and inside a control-channel exec whose stdout some
/// callers parse. On the GCE image both descriptors land in the journal.
///
/// Silent under `zig build test`: the build runner reports ANY stderr from a test
/// binary as a failed command even when every test passed, which would turn a
/// green gate into output that reads red. The tests here assert on the resulting
/// file modes, not on these lines.
fn emit(io: std.Io, comptime fmt: []const u8, args: anytype) void {
	if (@import("builtin").is_test) return;
	var msg_buf: [1024]u8 = undefined;
	const msg = std.fmt.bufPrint(&msg_buf, fmt, args) catch return;
	var w_buf: [1024]u8 = undefined;
	var w = std.Io.File.stderr().writer(io, &w_buf);
	w.interface.writeAll(msg) catch return;
	w.flush() catch {};
}

// --- tests ------------------------------------------------------------------

test "runasGroup mirrors the shell's ${COGBOX_PROXY_RUNAS#*:}" {
	const t = std.testing;
	// The GCE image's spelling, and the documented short form (group of the same
	// name as the user).
	try t.expectEqualStrings("cogbox-proxy", runasGroup("cogbox-proxy:cogbox-proxy").?);
	try t.expectEqualStrings("cogbox-proxy", runasGroup("cogbox-proxy").?);
	// First colon wins, exactly as `#*:` does.
	try t.expectEqualStrings("g:extra", runasGroup("u:g:extra").?);
	// Numeric spellings pass straight through to lookupGidIn.
	try t.expectEqualStrings("998", runasGroup("998:998").?);
	// No group to resolve.
	try t.expect(runasGroup("") == null);
	try t.expect(runasGroup("cogbox-proxy:") == null);
}

test "lookupGidIn resolves a name from the group file, takes a numeric spelling as-is" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const path = "zig-credgrant-group-fixture";
	{
		const f = try cwd.createFile(io, path, .{ .truncate = true });
		defer f.close(io);
		var wbuf: [512]u8 = undefined;
		var w = f.writer(io, &wbuf);
		try w.interface.writeAll(
			\\root:x:0:
			\\cogbox-passt:x:997:
			\\cogbox-proxy:x:998:
			\\
		);
		try w.flush();
	}
	defer cwd.deleteFile(io, path) catch {};

	try std.testing.expectEqual(@as(?Gid, 998), try lookupGidIn(gpa, io, path, "cogbox-proxy"));
	try std.testing.expectEqual(@as(?Gid, 997), try lookupGidIn(gpa, io, path, "cogbox-passt"));
	// Numeric: answered without consulting the file at all (hence the bogus path).
	try std.testing.expectEqual(@as(?Gid, 1234), try lookupGidIn(gpa, io, "zig-credgrant-no-such-file", "1234"));
	// Unknown name -> null, so the caller can warn instead of granting to gid 0.
	try std.testing.expectEqual(@as(?Gid, null), try lookupGidIn(gpa, io, path, "nope"));
}

/// A throwaway store with `bound` bound at the store's canonical 0600, plus one
/// file pre-set to `stale_mode` to stand in for a grant a previous render made.
fn tmpStore(gpa: std.mem.Allocator, io: std.Io, stale_mode: Mode) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	const dir = try std.fmt.allocPrint(gpa, "zig-credgrant-store-{s}", .{hexb});
	errdefer gpa.free(dir);
	// The reserved per-user Claude bind, an unrelated operator secret, and a
	// secret that WAS named by an earlier render and no longer is.
	try secret_store.add(gpa, io, dir, "claude-oauth", "sk-ant-oat01-FAKEFAKEFAKE", .{ .audience = "api.anthropic.com", .kind = "anthropic-oauth" });
	try secret_store.add(gpa, io, dir, "api-token", "unrelated-operator-secret", .{ .audience = "api.example.com", .kind = "bearer" });
	try secret_store.add(gpa, io, dir, "app-session", "was-granted-last-render", .{ .audience = "app.example.com", .kind = "cookie" });

	const stale = try std.fs.path.join(gpa, &.{ dir, "app-session" });
	defer gpa.free(stale);
	const f = try std.Io.Dir.cwd().openFile(io, stale, .{});
	defer f.close(io);
	try f.setPermissions(io, .fromMode(stale_mode));
	return dir;
}

fn modeOf(io: std.Io, path: []const u8) !Mode {
	const st = try std.Io.Dir.cwd().statFile(io, path, .{});
	return st.permissions.toMode() & 0o7777;
}

/// The credential's modification time in nanoseconds -- the addon's cache key for
/// the credential VALUE, which is why the grant has to move it.
fn mtimeOf(io: std.Io, path: []const u8) !i96 {
	const st = try std.Io.Dir.cwd().statFile(io, path, .{});
	return st.mtime.nanoseconds;
}

/// Pin an mtime to a fixed past instant, so an assertion about "did the grant
/// move it" cannot turn on the filesystem's timestamp granularity.
fn setMtime(io: std.Io, path: []const u8, nanoseconds: i96) !void {
	const f = try std.Io.Dir.cwd().openFile(io, path, .{});
	defer f.close(io);
	try f.setTimestamps(io, .{ .modify_timestamp = .{ .new = .{ .nanoseconds = nanoseconds } } });
}

/// The group owner, which `Io.File.Stat` does not carry.
fn gidOf(path: []const u8) !Gid {
	var buf: [std.fs.max_path_bytes]u8 = undefined;
	const path_z = try std.fmt.bufPrintZ(&buf, "{s}", .{path});
	return (try @import("platform").statPath(path_z)).gid;
}

test "apply grants group-read on exactly the noted cred file, revokes a stale grant, and leaves the meta sidecar alone" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	// `app-session` starts out as a leftover grant from an earlier render.
	const dir = try tmpStore(gpa, io, 0o640);
	defer gpa.free(dir);
	defer cwd.deleteTree(io, dir) catch {};

	// The test process's own primary gid: the one group it may chown a file it
	// owns to without privileges. It stands in for the proxy's gid.
	const gid: Gid = @intCast(@import("platform").getgid());

	var grants = Grants.init(gpa, gid);
	defer grants.deinit();
	const named = try std.fs.path.join(gpa, &.{ dir, "claude-oauth" });
	defer gpa.free(named);
	try grants.note(named);
	try grants.apply(io, &.{dir});

	// 1. The named credential is group-readable BY THAT GID -- the condition the
	//    dropped proxy uid needs.
	try std.testing.expectEqual(@as(Mode, 0o640), try modeOf(io, named));
	try std.testing.expectEqual(gid, try gidOf(named));
	// ...and still owner-writable, because the control uid re-binds rotated
	// tokens over the same file.
	try std.testing.expect(try modeOf(io, named) & 0o200 != 0);

	// 2. An unrelated bound secret in the SAME store stays unreadable. This is
	//    the hard constraint: the proxy gets the files its specs name, not the
	//    store.
	const other = try std.fs.path.join(gpa, &.{ dir, "api-token" });
	defer gpa.free(other);
	try std.testing.expectEqual(@as(Mode, 0o600), try modeOf(io, other));

	// 3. Revocation: a file granted by an earlier render but not named by this one
	//    loses the group bits again.
	const stale = try std.fs.path.join(gpa, &.{ dir, "app-session" });
	defer gpa.free(stale);
	try std.testing.expectEqual(@as(Mode, 0o600), try modeOf(io, stale));

	// 4. The metadata sidecar is never part of the grant -- the addon reads only
	//    cred_file.
	const meta = try std.fs.path.join(gpa, &.{ dir, "claude-oauth.meta" });
	defer gpa.free(meta);
	try std.testing.expectEqual(@as(Mode, 0o600), try modeOf(io, meta));

	// 5. The store directory is traversable by the gid but NOT newly listable:
	//    the group search bit is set, and no group READ bit was added.
	try std.testing.expectEqual(gid, try gidOf(dir));
	try std.testing.expect(try modeOf(io, dir) & 0o010 != 0);
}

test "apply is a total no-op without a proxy gid (the container/k8s/local shape)" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const dir = try tmpStore(gpa, io, 0o640);
	defer gpa.free(dir);
	defer cwd.deleteTree(io, dir) catch {};
	const before_dir_gid = try gidOf(dir);
	const before_dir_mode = try modeOf(io, dir);

	// No COGBOX_PROXY_RUNAS => no uid split => nothing to grant and nothing to
	// revoke. Note the stale 0640 file is deliberately NOT tightened either: on
	// those backends this code has no business touching store permissions at all.
	var grants = Grants.init(gpa, null);
	defer grants.deinit();
	const named = try std.fs.path.join(gpa, &.{ dir, "claude-oauth" });
	defer gpa.free(named);
	try grants.note(named);
	try grants.apply(io, &.{dir});

	try std.testing.expectEqual(@as(Mode, 0o600), try modeOf(io, named));
	const stale = try std.fs.path.join(gpa, &.{ dir, "app-session" });
	defer gpa.free(stale);
	try std.testing.expectEqual(@as(Mode, 0o640), try modeOf(io, stale));
	try std.testing.expectEqual(before_dir_mode, try modeOf(io, dir));
	try std.testing.expectEqual(before_dir_gid, try gidOf(dir));
}

test "a grant TRANSITION moves the cred file's mtime; a steady-state render does not" {
	// The addon caches each cred file's value keyed on the file's MTIME, and chmod
	// moves ctime only -- so a `None` it cached while the file was still 0600 (the
	// window an atomic-rename rebind opens before the separate `secret reload`
	// re-renders) would outlive the re-grant and 403 that host forever. Asserting on
	// the mtime here is asserting on the addon's cache key.
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const dir = try tmpStore(gpa, io, 0o600);
	defer gpa.free(dir);
	defer cwd.deleteTree(io, dir) catch {};
	const gid: Gid = @intCast(@import("platform").getgid());

	const named = try std.fs.path.join(gpa, &.{ dir, "claude-oauth" });
	defer gpa.free(named);
	const pinned: i96 = 1_000_000_000_000_000_000; // 2001-09-09, in ns since the epoch
	try setMtime(io, named, pinned);
	try std.testing.expectEqual(pinned, try mtimeOf(io, named));

	{
		var grants = Grants.init(gpa, gid);
		defer grants.deinit();
		try grants.note(named);
		try grants.apply(io, &.{dir});
	}
	// The 0600 -> 0640 transition happened, and it moved the cache key with it.
	try std.testing.expectEqual(@as(Mode, 0o640), try modeOf(io, named));
	try std.testing.expect(try mtimeOf(io, named) != pinned);

	// A render that changes nothing must NOT move it. The mtime is the cache key
	// for the credential's value, so bumping it on every render would throw a good
	// entry away on every unrelated `l7 add` -- and would look like a concurrent
	// rotation to the addon's post-refresh clobber guard (l7-mitm-addon.py's
	// `rotated concurrently during POST`), which would skip a legitimate refresh.
	try setMtime(io, named, pinned);
	{
		var grants = Grants.init(gpa, gid);
		defer grants.deinit();
		try grants.note(named);
		try grants.apply(io, &.{dir});
	}
	try std.testing.expectEqual(@as(Mode, 0o640), try modeOf(io, named));
	try std.testing.expectEqual(pinned, try mtimeOf(io, named));
}
