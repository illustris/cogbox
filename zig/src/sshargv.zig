// Shared `ssh` argv plumbing: the guest endpoint a running instance publishes
// in <runtime>/ssh-endpoint, and the `ssh` argv that reaches it. Used by the
// `cogbox ssh` verb (and `cogbox start`'s auto-ssh) for interactive sessions,
// and by the live plugin apply for its guest hops, which add the options of
// `Hop` below. Pure std (no libc, no other cogbox module), so both the CLI and
// the plugin module import it.
//
// Host key checking is disabled for every hop because the guest's root disk is
// ephemeral and its host keys regenerate on every boot.

const std = @import("std");

/// SSH host:port for a running instance, read from <runtime>/ssh-endpoint.
/// Both fields are owned by the caller; free via `deinit`.
pub const Endpoint = struct {
	port: []const u8,
	host: []const u8,

	pub fn deinit(self: Endpoint, allocator: std.mem.Allocator) void {
		allocator.free(self.port);
		allocator.free(self.host);
	}
};

pub const EndpointError = error{ Missing, Malformed, OutOfMemory };

/// Parse <inst_runtime>/ssh-endpoint ("PORT HOST", written by the launch
/// script when the VM comes up). Returns duped fields. `error.Missing` if the
/// file is absent/unreadable; `error.Malformed` if it lacks a port or host.
pub fn readEndpoint(allocator: std.mem.Allocator, io: std.Io, inst_runtime: []const u8) EndpointError!Endpoint {
	const endpoint_path = std.fs.path.join(allocator, &.{ inst_runtime, "ssh-endpoint" }) catch return error.OutOfMemory;
	defer allocator.free(endpoint_path);
	const text = readSmall(allocator, io, endpoint_path) catch return error.Missing;
	defer allocator.free(text);

	var iter = std.mem.tokenizeAny(u8, text, " \t\r\n");
	const port = iter.next() orelse return error.Malformed;
	const host = iter.next() orelse return error.Malformed;

	const port_d = allocator.dupe(u8, port) catch return error.OutOfMemory;
	errdefer allocator.free(port_d);
	const host_d = allocator.dupe(u8, host) catch return error.OutOfMemory;
	return .{ .port = port_d, .host = host_d };
}

fn readSmall(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
	const cwd = std.Io.Dir.cwd();
	const file = try cwd.openFile(io, path, .{});
	defer file.close(io);
	var buf: [256]u8 = undefined;
	var reader = file.reader(io, &buf);
	return try reader.interface.allocRemaining(allocator, .limited(4096));
}

/// Append the full `ssh ...` argv for `endpoint` into `argv`. When `force_pty`
/// is set a single `-t` is inserted just before the `root@host` target (an ssh
/// option must precede the host) so ssh allocates a remote PTY; see the ssh
/// verb's `wantPty` for when `force_pty` is set. The remote command follows the
/// target, quoted by `appendRemoteCommand` so ssh's space-join cannot let the
/// guest shell re-parse it. The target string, the quoted arguments and the
/// list's backing are owned by `allocator`; on the ssh verb's path its `exec`
/// hands `argv` straight to execvp, so they live until this process is
/// replaced. Split out from `exec` so the `-t` placement and the quoting are
/// unit-testable without a real exec or a local tty.
pub fn buildArgv(
	allocator: std.mem.Allocator,
	argv: *std.ArrayList([]const u8),
	endpoint: Endpoint,
	identity: ?[]const u8,
	extra: []const []const u8,
	force_pty: bool,
) !void {
	return buildArgvOpts(allocator, argv, endpoint, identity, extra, .{ .force_pty = force_pty });
}

/// Which kind of connection an argv is for.
pub const Hop = enum {
	/// `cogbox ssh` and `cogbox start`'s auto-ssh: exactly today's argv, so the
	/// user's ssh config (multiplexing included) applies as it always has.
	interactive,
	/// A live-apply guest hop: non-interactive, bounded, and its own TCP
	/// connection. BatchMode never prompts; ConnectTimeout and the ServerAlive
	/// pair bound a dead peer (a hop has its own wall-clock kill on top); and
	/// ControlMaster=no + ControlPath=none + ControlPersist=no override a user's
	/// `ControlMaster auto`, which would otherwise multiplex the hop over (or
	/// leave behind) a shared master connection. ControlMaster=no alone still
	/// joins an existing master through ControlPath, hence ControlPath=none.
	apply,
	/// The live apply's confirm hop: an `apply` hop that, when the cogbox key is
	/// in use, also reads no ssh config file at all (`-F /dev/null`), so the
	/// confirmation is a new connection with a new authentication that nothing
	/// in a config file can redirect or share. Without the cogbox key (the
	/// --no-auto-keys opt-out) the user's config may be what names their key, so
	/// it is kept and the hop is a plain `apply` hop.
	confirm,
};

/// The options `Hop.apply` (and `Hop.confirm`) add, in order.
pub const apply_hop_options = [_][]const u8{
	"-o", "BatchMode=yes",
	"-o", "ConnectTimeout=10",
	"-o", "ServerAliveInterval=15",
	"-o", "ServerAliveCountMax=4",
	"-o", "ControlMaster=no",
	"-o", "ControlPath=none",
	"-o", "ControlPersist=no",
};

pub const Options = struct {
	hop: Hop = .interactive,
	force_pty: bool = false,
};

/// `buildArgv` with a hop kind. `.interactive` (the default) is byte-identical
/// to `buildArgv`. `-F /dev/null` (confirm with the cogbox key) comes first,
/// as ssh reads the config file before any `-o`; the apply options follow the
/// host-key options and precede the identity pinning.
pub fn buildArgvOpts(
	allocator: std.mem.Allocator,
	argv: *std.ArrayList([]const u8),
	endpoint: Endpoint,
	identity: ?[]const u8,
	extra: []const []const u8,
	opts: Options,
) !void {
	const target = try std.fmt.allocPrint(allocator, "root@{s}", .{endpoint.host});
	try argv.append(allocator, "ssh");
	if (opts.hop == .confirm and identity != null) {
		try argv.append(allocator, "-F");
		try argv.append(allocator, "/dev/null");
	}
	try argv.append(allocator, "-o");
	try argv.append(allocator, "StrictHostKeyChecking=no");
	try argv.append(allocator, "-o");
	try argv.append(allocator, "UserKnownHostsFile=/dev/null");
	try argv.append(allocator, "-o");
	try argv.append(allocator, "LogLevel=ERROR");
	if (opts.hop != .interactive) try argv.appendSlice(allocator, &apply_hop_options);
	if (identity) |id| {
		// Pin ssh to *only* the cogbox key and never touch an authentication
		// agent: IdentitiesOnly stops ssh offering the user's agent / ~/.ssh
		// keys, and IdentityAgent=none keeps ssh from contacting any agent at
		// all. The user's agent may be a gpg-agent (ssh support) that prompts
		// or hangs; the cogbox key is unioned into the guest's authorized_keys
		// by default, so offering it alone is sufficient and is a single,
		// deterministic auth attempt. The opt-out path (no cogbox key ->
		// identity null) skips this and keeps ssh's agent/default-key fallback.
		try argv.append(allocator, "-o");
		try argv.append(allocator, "IdentitiesOnly=yes");
		try argv.append(allocator, "-o");
		try argv.append(allocator, "IdentityAgent=none");
		try argv.append(allocator, "-i");
		try argv.append(allocator, id);
	}
	try argv.append(allocator, "-p");
	try argv.append(allocator, endpoint.port);
	if (opts.force_pty) try argv.append(allocator, "-t");
	try argv.append(allocator, target);
	try appendRemoteCommand(allocator, argv, extra);
}

/// Append the caller's remote command to an `ssh` argv, quoted for the shell on
/// the far side.
///
/// ssh does NOT execute the words after the target as an argv vector: it joins
/// them with single spaces into ONE string, and the remote sshd hands that
/// string to `sh -c`. Forwarded bare, every shell metacharacter in an argument
/// is reinterpreted remotely and the word boundaries are gone. For example:
///
///   cogbox ssh -n <inst> tmux list-sessions -F '#{session_name}\t#{session_attached}'
///
/// arrived in the guest as `... -F #{session_name}<TAB>#{session_attached}`,
/// where `#` opens a comment and tmux receives a bare `-F`.
///
/// So a command of TWO OR MORE arguments is an argv vector the caller built,
/// and every element is single-quoted: each byte reaches the remote command
/// literally, which is both the correctness fix and the injection fix (an
/// element may be a plugin URL, an instance name, or anything else the caller
/// did not vet). This is the same treatment the control plane already gives
/// its own outer hop.
///
/// A LONE argument is passed through VERBATIM, because one argument is ssh's
/// own remote-command-STRING form and cogbox has always had it -- the guest
/// test suite is full of `cogbox ssh 'readlink -f $(command -v hello)'`, where
/// the guest shell is meant to interpret the string. Quoting it would make the
/// whole line a single command NAME. The two forms do not overlap: a caller who
/// wants shell syntax with several words either passes it as one string or
/// spells it `sh -c '<script>'` (which, quoted, still reaches the guest intact).
///
/// Empty `extra` appends nothing, so the interactive login is untouched.
pub fn appendRemoteCommand(
	allocator: std.mem.Allocator,
	argv: *std.ArrayList([]const u8),
	extra: []const []const u8,
) !void {
	if (extra.len < 2) {
		for (extra) |t| try argv.append(allocator, t);
		return;
	}
	for (extra) |t| try argv.append(allocator, try quoteArg(allocator, t));
}

/// Single-quote one argument for POSIX sh: inside single quotes every byte is
/// literal except the quote itself, which is closed, escaped and reopened
/// (`'\''`). An empty argument becomes `''`, so it survives as a word instead of
/// vanishing in the join. The returned slice is owned by `allocator`; like
/// `buildArgv`'s target it lives until execvp replaces the process (tests use an
/// arena).
pub fn quoteArg(allocator: std.mem.Allocator, s: []const u8) ![]const u8 {
	var out: std.ArrayList(u8) = .empty;
	errdefer out.deinit(allocator);
	try out.append(allocator, '\'');
	for (s) |c| {
		if (c == '\'') {
			try out.appendSlice(allocator, "'\\''");
		} else {
			try out.append(allocator, c);
		}
	}
	try out.append(allocator, '\'');
	return out.toOwnedSlice(allocator);
}

// --- tests ---------------------------------------------------------------------

const testing = std.testing;

fn argvIndex(argv: []const []const u8, needle: []const u8) ?usize {
	for (argv, 0..) |a, i| {
		if (std.mem.eql(u8, a, needle)) return i;
	}
	return null;
}

fn argvHasOption(argv: []const []const u8, opt: []const u8) bool {
	for (argv, 0..) |a, i| {
		if (i > 0 and std.mem.eql(u8, argv[i - 1], "-o") and std.mem.eql(u8, a, opt)) return true;
	}
	return false;
}

const ep: Endpoint = .{ .port = "2222", .host = "10.0.2.15" };
const no_mux = [_][]const u8{ "ControlMaster=no", "ControlPath=none", "ControlPersist=no" };
const bounded = [_][]const u8{ "BatchMode=yes", "ConnectTimeout=10", "ServerAliveInterval=15", "ServerAliveCountMax=4" };

test "buildArgvOpts: .interactive is buildArgv byte for byte, with no apply-hop option" {
	var arena = std.heap.ArenaAllocator.init(testing.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	const cases = [_]struct { id: ?[]const u8, extra: []const []const u8, pty: bool }{
		.{ .id = null, .extra = &.{}, .pty = false },
		.{ .id = "/data/cogbox_ed25519", .extra = &.{}, .pty = false },
		.{ .id = "/data/cogbox_ed25519", .extra = &.{"htop"}, .pty = true },
		.{ .id = null, .extra = &.{ "printf", "%s", "a b" }, .pty = false },
	};
	for (cases) |c| {
		var old: std.ArrayList([]const u8) = .empty;
		try buildArgv(a, &old, ep, c.id, c.extra, c.pty);
		var new: std.ArrayList([]const u8) = .empty;
		try buildArgvOpts(a, &new, ep, c.id, c.extra, .{ .force_pty = c.pty });
		try testing.expectEqual(old.items.len, new.items.len);
		for (old.items, new.items) |o, n| try testing.expectEqualStrings(o, n);
		for (no_mux ++ bounded) |opt| try testing.expect(!argvHasOption(new.items, opt));
		try testing.expect(argvIndex(new.items, "-F") == null);
	}
	// Today's exact argv for the no-key login, pinned.
	var login: std.ArrayList([]const u8) = .empty;
	try buildArgv(a, &login, ep, null, &.{}, false);
	const want = [_][]const u8{ "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-p", "2222", "root@10.0.2.15" };
	try testing.expectEqual(want.len, login.items.len);
	for (want, login.items) |w, g| try testing.expectEqualStrings(w, g);
}

test "buildArgvOpts: every apply hop is bounded and never multiplexes" {
	var arena = std.heap.ArenaAllocator.init(testing.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	const cmd = [_][]const u8{ "/run/booted-system/cogbox-live-switch", "status", "7", "--boot-id", "b" };
	for ([_]Hop{ .apply, .confirm }) |hop| {
		for ([_]?[]const u8{ null, "/data/cogbox_ed25519" }) |id| {
			var argv: std.ArrayList([]const u8) = .empty;
			try buildArgvOpts(a, &argv, ep, id, &cmd, .{ .hop = hop });
			for (no_mux ++ bounded) |opt| try testing.expect(argvHasOption(argv.items, opt));
			// Every option precedes the target; the command follows it, quoted.
			const host_i = argvIndex(argv.items, "root@10.0.2.15").?;
			try testing.expect(argvIndex(argv.items, "ControlPath=none").? < host_i);
			try testing.expectEqual(cmd.len, argv.items.len - (host_i + 1));
			try testing.expectEqualStrings("'/run/booted-system/cogbox-live-switch'", argv.items[host_i + 1]);
			try testing.expect(argvIndex(argv.items, "-t") == null);
			// The cogbox key pinning is unchanged by the hop kind.
			if (id) |key| {
				try testing.expect(argvHasOption(argv.items, "IdentitiesOnly=yes"));
				try testing.expect(argvHasOption(argv.items, "IdentityAgent=none"));
				try testing.expectEqualStrings(key, argv.items[argvIndex(argv.items, "-i").? + 1]);
			} else {
				try testing.expect(argvIndex(argv.items, "-i") == null);
			}
		}
	}
}

test "buildArgvOpts: only the confirm hop with the cogbox key reads no ssh config (-F /dev/null)" {
	var arena = std.heap.ArenaAllocator.init(testing.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgvOpts(a, &argv, ep, "/data/cogbox_ed25519", &.{ "confirm", "7" }, .{ .hop = .confirm });
		// First, so ssh reads no config file before any -o applies.
		try testing.expectEqualStrings("-F", argv.items[1]);
		try testing.expectEqualStrings("/dev/null", argv.items[2]);
		try testing.expectEqual(@as(usize, 1), countOf(argv.items, "-F"));
	}
	// Without the cogbox key the user's config may name their key: kept.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgvOpts(a, &argv, ep, null, &.{ "confirm", "7" }, .{ .hop = .confirm });
		try testing.expect(argvIndex(argv.items, "-F") == null);
	}
	// A plain apply hop keeps the config file (the -o options already override
	// its multiplexing).
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgvOpts(a, &argv, ep, "/data/cogbox_ed25519", &.{ "status", "7" }, .{ .hop = .apply });
		try testing.expect(argvIndex(argv.items, "-F") == null);
	}
}

fn countOf(argv: []const []const u8, needle: []const u8) usize {
	var n: usize = 0;
	for (argv) |x| {
		if (std.mem.eql(u8, x, needle)) n += 1;
	}
	return n;
}

fn tmpRuntime(io: std.Io) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	const dir = try std.fmt.allocPrint(testing.allocator, "zig-sshargv-test-{x}", .{&rnd});
	try std.Io.Dir.cwd().createDirPath(io, dir);
	return dir;
}

test "readEndpoint: PORT HOST, a missing file, and a malformed one" {
	var threaded: std.Io.Threaded = .init(testing.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const rt = try tmpRuntime(io);
	defer testing.allocator.free(rt);
	defer std.Io.Dir.cwd().deleteTree(io, rt) catch {};

	try testing.expectError(error.Missing, readEndpoint(testing.allocator, io, rt));
	const path = try std.fs.path.join(testing.allocator, &.{ rt, "ssh-endpoint" });
	defer testing.allocator.free(path);
	{
		const f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
		defer f.close(io);
		var buf: [64]u8 = undefined;
		var w = f.writer(io, &buf);
		try w.interface.writeAll("2222 10.0.2.15\n");
		try w.flush();
	}
	const e = try readEndpoint(testing.allocator, io, rt);
	defer e.deinit(testing.allocator);
	try testing.expectEqualStrings("2222", e.port);
	try testing.expectEqualStrings("10.0.2.15", e.host);
	{
		const f = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
		defer f.close(io);
		var buf: [64]u8 = undefined;
		var w = f.writer(io, &buf);
		try w.interface.writeAll("2222\n");
		try w.flush();
	}
	try testing.expectError(error.Malformed, readEndpoint(testing.allocator, io, rt));
}
