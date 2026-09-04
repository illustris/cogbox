// Who the L7 proxy runs as, resolved from `COGBOX_PROXY_RUNAS`.
//
// This lives in the SECRET module rather than next to its consumer in
// rules/credgrant.zig because BOTH ends of the credential's life need the same
// answer and the module graph only allows one direction: `rules` imports
// `secret`, never the reverse. The render end (credgrant.Grants) reconciles the
// store's permissions to whatever the conf it is writing names; the WRITE end
// (`secret add`, store.addForProxy) stages the same group onto the temp file
// before the rename, so a freshly bound credential is proxy-readable from the
// first instant it exists at its final path instead of only after the separate
// render that follows (~1 SSH round-trip later, a window in which the addon
// fail-closed with 403 "credential unavailable").
//
// Everything here is the SAME parse and the SAME lookup credgrant used before
// this file existed -- credgrant re-exports these names -- so the identity the
// launcher hands `setpriv --regid`, the identity the render grants to and the
// identity a bind stages for cannot drift into three different answers.

const std = @import("std");

pub const Gid = std.Io.File.Gid;

/// The group half of a `COGBOX_PROXY_RUNAS` value, byte-for-byte as
/// cogbox-launch.sh's `${COGBOX_PROXY_RUNAS#*:}` reads it when it builds the
/// `setpriv --regid` argument: everything after the FIRST colon, or the whole
/// string when there is no colon (the documented `user` spelling, where the
/// group has the same name as the user). Null for an unset/empty spec, and for a
/// trailing-colon spec (`user:`) -- setpriv would reject that too, and guessing a
/// group for it could only guess wrong. Pure.
pub fn runasGroup(spec: []const u8) ?[]const u8 {
	if (spec.len == 0) return null;
	const colon = std.mem.indexOfScalar(u8, spec, ':') orelse return spec;
	const group = spec[colon + 1 ..];
	return if (group.len == 0) null else group;
}

/// Resolve a group NAME or a numeric gid against `group_file` (/etc/group's
/// format: `name:passwd:gid:members`). A numeric spelling is taken as the gid
/// itself, so a deployment can name the group either way -- and so a caller that
/// has no name service still works. Null when the name is not in the file.
pub fn lookupGidIn(allocator: std.mem.Allocator, io: std.Io, group_file: []const u8, group: []const u8) !?Gid {
	if (std.fmt.parseInt(Gid, group, 10)) |gid| return gid else |_| {}

	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(io, group_file, .{}) catch return null;
	defer file.close(io);
	var read_buf: [16384]u8 = undefined;
	var reader = file.reader(io, &read_buf);
	const data = reader.interface.allocRemaining(allocator, .limited(1 << 20)) catch return null;
	defer allocator.free(data);

	var lines = std.mem.splitScalar(u8, data, '\n');
	while (lines.next()) |line| {
		var cols = std.mem.splitScalar(u8, line, ':');
		const name = cols.next() orelse continue;
		if (!std.mem.eql(u8, name, group)) continue;
		_ = cols.next() orelse continue; // password field
		const gid_str = cols.next() orelse continue;
		return std.fmt.parseInt(Gid, gid_str, 10) catch null;
	}
	return null;
}

/// What `COGBOX_PROXY_RUNAS` resolved to. `gid` is null on every deployment that
/// runs no uid split (container, k8s, local -- none of them set the variable), in
/// which case every caller here is an exact no-op. `unresolved_group` is set
/// ONLY when the spec did name a group and /etc/group does not define it: the
/// answer is still "no gid", but the caller can say so out loud rather than
/// silently behaving like an unsplit deployment.
pub const Resolution = struct {
	gid: ?Gid = null,
	unresolved_group: ?[]const u8 = null,
};

/// Resolve the gid the L7 proxy runs under from `env`, using the SAME variable
/// the launcher hands `setpriv`. Never warns itself -- the two callers log at
/// different volumes (the render is a journal line, a bind is a user-facing
/// stderr note), so the reporting is theirs.
pub fn fromEnv(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map) !Resolution {
	const e = env orelse return .{};
	const spec = e.get("COGBOX_PROXY_RUNAS") orelse return .{};
	const group = runasGroup(spec) orelse return .{};
	const gid = try lookupGidIn(allocator, io, "/etc/group", group);
	if (gid == null) return .{ .gid = null, .unresolved_group = group };
	return .{ .gid = gid };
}
