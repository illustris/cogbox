// Resolve the cogbox path triple (config, data, runtime) per instance.
// Mirrors the bash logic at cogbox.sh:201-340.
//
// Precedence:
//   - config: $XDG_CONFIG_HOME or $HOME/.config, then `/cogbox`
//   - data:   $COGBOX_DATA, else $XDG_DATA_HOME or $HOME/.local/share, then `/cogbox`
//   - runtime: $XDG_RUNTIME_DIR/cogbox; falls back to /run/user/$UID/cogbox
//              under sudo, and /tmp/cogbox-runtime-$UID with no logind.
//
// Sudo handling: if SUDO_USER is set, resolve $HOME and $UID from
// /etc/passwd of the original (non-root) user. The launch script needs
// the real user's home for ~/.claude etc. and the real UID for the
// XDG_RUNTIME_DIR fallback.

const std = @import("std");

pub const Paths = struct {
	real_user: []const u8,
	real_home: []const u8,
	real_uid: u32,
	config_dir: []const u8, // $config/cogbox
	base_data: []const u8, // $data/cogbox
	base_runtime: []const u8, // $runtime/cogbox  (no instance suffix)
	allocator: std.mem.Allocator,

	pub fn deinit(self: *Paths) void {
		self.allocator.free(self.real_user);
		self.allocator.free(self.real_home);
		self.allocator.free(self.config_dir);
		self.allocator.free(self.base_data);
		self.allocator.free(self.base_runtime);
	}
};

/// Compute the per-instance config dir. If `name` is null, returns the
/// default instance (`<config>/instances/default`).
pub fn instanceConfigDir(allocator: std.mem.Allocator, paths: *const Paths, name: ?[]const u8) ![]const u8 {
	const eff = name orelse "default";
	return try std.fs.path.join(allocator, &.{ paths.config_dir, "instances", eff });
}

pub fn instanceFlakeDir(allocator: std.mem.Allocator, paths: *const Paths, name: ?[]const u8) ![]const u8 {
	const eff = name orelse "default";
	return try std.fs.path.join(allocator, &.{ paths.config_dir, "instances", eff, "flake" });
}

/// The generated plugin-composition flake's directory. A sibling of `flake/`
/// (not a file next to config.json) for the same reason `flake/` is its own
/// subdir: it becomes a `path:` flake input, and unrelated edits in the
/// instance config dir must not bust its source hash.
pub fn instancePluginsFlakeDir(allocator: std.mem.Allocator, paths: *const Paths, name: ?[]const u8) ![]const u8 {
	const eff = name orelse "default";
	return try std.fs.path.join(allocator, &.{ paths.config_dir, "instances", eff, "plugins-flake" });
}

/// The global (operator-bound) secret store dir: `<config>/secrets`. Holds
/// credentials a plugin requests by name and the operator binds with
/// `cogbox secret add`. Shared across an account's instances (not per-instance),
/// since these are operator secrets, not per-VM state.
pub fn globalSecretsDir(allocator: std.mem.Allocator, paths: *const Paths) ![]const u8 {
	return try std.fs.path.join(allocator, &.{ paths.config_dir, "secrets" });
}

/// Per-instance secret dir for sidecar-PRODUCED secrets (e.g. a minted session
/// cookie): `<config>/instances/<name>/secrets`. The resolver checks this before
/// the global store, so a produced session shadows a global secret of the same
/// name (honoring per-instance isolation).
pub fn instanceSecretsDir(allocator: std.mem.Allocator, paths: *const Paths, name: ?[]const u8) ![]const u8 {
	const eff = name orelse "default";
	return try std.fs.path.join(allocator, &.{ paths.config_dir, "instances", eff, "secrets" });
}

pub fn instanceDataDir(allocator: std.mem.Allocator, paths: *const Paths, name: ?[]const u8) ![]const u8 {
	const eff = name orelse "default";
	return try std.fs.path.join(allocator, &.{ paths.base_data, "instances", eff });
}

/// Per-instance runtime: `<base>` for the default, `<base>-<name>` otherwise.
/// Matches cogbox.sh:336-340.
pub fn instanceRuntime(allocator: std.mem.Allocator, paths: *const Paths, name: ?[]const u8) ![]const u8 {
	if (name) |n| {
		return try std.fmt.allocPrint(allocator, "{s}-{s}", .{ paths.base_runtime, n });
	}
	return try allocator.dupe(u8, paths.base_runtime);
}

pub fn resolve(allocator: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map) !Paths {
	const sudo_user_z = env.get("SUDO_USER");

	const user_buf: []const u8 = if (sudo_user_z) |su|
		try allocator.dupe(u8, su)
	else blk: {
		const me = env.get("USER") orelse "user";
		break :blk try allocator.dupe(u8, me);
	};

	// Resolve real user's home and uid. Under sudo, lookup via /etc/passwd
	// rather than $HOME (which is root's). Without sudo, just trust $HOME.
	const home: []const u8 = blk: {
		if (sudo_user_z != null) {
			if (try lookupHome(allocator, io, user_buf)) |h| break :blk h;
		}
		const h = env.get("HOME") orelse "/";
		break :blk try allocator.dupe(u8, h);
	};

	const uid: u32 = blk: {
		if (sudo_user_z != null) {
			if (try lookupUid(allocator, io, user_buf)) |u| break :blk u;
		}
		break :blk @intCast(@import("platform").getuid());
	};

	// Config dir
	const config_root = env.get("XDG_CONFIG_HOME");
	const config_dir = if (config_root) |c|
		try std.fs.path.join(allocator, &.{ c, "cogbox" })
	else
		try std.fs.path.join(allocator, &.{ home, ".config", "cogbox" });

	// Data dir
	const base_data: []const u8 = if (env.get("COGBOX_DATA")) |d|
		try allocator.dupe(u8, d)
	else if (env.get("XDG_DATA_HOME")) |d|
		try std.fs.path.join(allocator, &.{ d, "cogbox" })
	else
		try std.fs.path.join(allocator, &.{ home, ".local", "share", "cogbox" });

	// Runtime base. Under sudo or with no XDG_RUNTIME_DIR, prefer
	// /run/user/$UID; else fall back to /tmp/cogbox-runtime-$UID.
	const runtime_base = try resolveRuntimeBase(allocator, io, env, sudo_user_z != null, uid);
	const base_runtime = try std.fs.path.join(allocator, &.{ runtime_base, "cogbox" });
	allocator.free(runtime_base);

	return .{
		.real_user = user_buf,
		.real_home = home,
		.real_uid = uid,
		.config_dir = config_dir,
		.base_data = base_data,
		.base_runtime = base_runtime,
		.allocator = allocator,
	};
}

fn resolveRuntimeBase(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	is_sudo: bool,
	uid: u32,
) ![]const u8 {
	const xdg = env.get("XDG_RUNTIME_DIR");
	if (!is_sudo and xdg != null and xdg.?.len > 0) {
		return try allocator.dupe(u8, xdg.?);
	}
	// /run/user/$UID
	const candidate = try std.fmt.allocPrint(allocator, "/run/user/{d}", .{uid});
	const cwd = std.Io.Dir.cwd();
	cwd.access(io, candidate, .{}) catch {
		allocator.free(candidate);
		return try std.fmt.allocPrint(allocator, "/tmp/cogbox-runtime-{d}", .{uid});
	};
	return candidate;
}

fn lookupHome(allocator: std.mem.Allocator, io: std.Io, user: []const u8) !?[]const u8 {
	return try lookupPasswdField(allocator, io, user, 5);
}

fn lookupUid(allocator: std.mem.Allocator, io: std.Io, user: []const u8) !?u32 {
	const s = (try lookupPasswdField(allocator, io, user, 2)) orelse return null;
	defer allocator.free(s);
	return std.fmt.parseInt(u32, s, 10) catch null;
}

/// Parse /etc/passwd for `user` and return the requested 0-based field.
fn lookupPasswdField(allocator: std.mem.Allocator, io: std.Io, user: []const u8, field: usize) !?[]const u8 {
	if (@import("platform").darwin) {
		const c = @cImport({ @cInclude("pwd.h"); });
		const name = try allocator.dupeZ(u8, user);
		defer allocator.free(name);
		var entry: c.struct_passwd = undefined;
		var result: ?*c.struct_passwd = null;
		var buffer: [16384]u8 = undefined;
		if (c.getpwnam_r(name.ptr, &entry, &buffer, buffer.len, &result) != 0 or result == null) return null;
		return switch (field) {
			2 => try std.fmt.allocPrint(allocator, "{d}", .{entry.pw_uid}),
			5 => try allocator.dupe(u8, std.mem.span(entry.pw_dir)),
			else => null,
		};
	}
	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(io, "/etc/passwd", .{}) catch return null;
	defer file.close(io);

	var read_buf: [16384]u8 = undefined;
	var reader = file.reader(io, &read_buf);
	const data = reader.interface.allocRemaining(allocator, .limited(1 << 20)) catch return null;
	defer allocator.free(data);

	var line_iter = std.mem.splitScalar(u8, data, '\n');
	while (line_iter.next()) |line| {
		var col_iter = std.mem.splitScalar(u8, line, ':');
		const name = col_iter.next() orelse continue;
		if (!std.mem.eql(u8, name, user)) continue;
		var idx: usize = 1;
		while (idx <= field) : (idx += 1) {
			const v = col_iter.next() orelse return null;
			if (idx == field) return try allocator.dupe(u8, v);
		}
	}
	return null;
}
