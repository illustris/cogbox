// `cogbox ssh` - connect to a running instance via SSH.
//
// Reads the live host:port from <runtime>/ssh-endpoint (written by the
// launch script when the VM comes up). Disables host-key checking
// because the guest's root disk is ephemeral and host keys regenerate
// on every boot.

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const exit_codes = @import("../exit.zig");
const paths = @import("../paths.zig");
const sshargv = @import("sshargv");

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	p: *const paths.Paths,
	argv: []const []const u8,
) !void {
	const flags = [_]parse.Flag{
		.{ .long = "name", .short = 'n', .kind = .value },
		.{ .long = "wait-for-ssh", .kind = .bool },
		.{ .long = "wait-timeout", .kind = .value },
		.{ .long = "help", .short = 'h', .kind = .bool },
	};
	var parsed = parse.parse(allocator, io, .{
		.verb = "ssh",
		.flags = &flags,
		.allow_trailing = true,
		.terminate_on_positional = true,
	}, argv);
	defer parsed.deinit();

	if (parsed.isSet("help")) {
		try help.print(io, help.SSH);
		return;
	}

	// --wait-timeout only means anything alongside --wait-for-ssh; reject it on
	// its own rather than silently ignoring a misremembered/typo'd value.
	if (parsed.isSet("wait-timeout") and !parsed.isSet("wait-for-ssh")) {
		util.die(allocator, io, "ssh", exit_codes.usage, "--wait-timeout requires --wait-for-ssh.", .{});
	}

	const name = nameFlag(&parsed, allocator, io);

	const inst_runtime = try paths.instanceRuntime(allocator, p, name);
	defer allocator.free(inst_runtime);

	const pid_path = try std.fs.path.join(allocator, &.{ inst_runtime, "pid" });
	defer allocator.free(pid_path);
	if (!util.instanceRunningConservative(allocator, io, inst_runtime)) {
		const eff = name orelse "default";
		const hint_name: []const u8 = if (name) |n|
			try std.fmt.allocPrint(allocator, " --name {s}", .{n})
		else
			try allocator.dupe(u8, "");
		defer allocator.free(hint_name);
		try util.writeStderr(io,
			try std.fmt.allocPrint(allocator,
				"cogbox ssh: error: instance \"{s}\" is not running.\nStart it with: cogbox start{s}\n",
				.{ eff, hint_name },
			),
		);
		std.process.exit(exit_codes.software);
	}
	// The lifetime lock proves a live launch, but the launcher publishes pid
	// (and, just before it, ssh-endpoint) only after its port probe. A launch
	// caught in that window is starting, not broken -- say so instead of the
	// misleading "older cogbox" endpoint error below.
	const pid = readPid(allocator, io, pid_path) orelse {
		const eff = name orelse "default";
		util.die(allocator, io, "ssh", exit_codes.tempfail, "instance \"{s}\" is still starting; retry shortly.", .{eff});
	};

	const endpoint = readEndpoint(allocator, io, inst_runtime) catch |err| switch (err) {
		error.Missing => util.die(allocator, io, "ssh", exit_codes.software, "missing {s}/ssh-endpoint (instance launched by an older cogbox?). Restart the instance to repopulate it.", .{inst_runtime}),
		error.Malformed => util.die(allocator, io, "ssh", exit_codes.software, "ssh-endpoint is malformed in {s}. Restart the instance to repopulate it.", .{inst_runtime}),
		error.OutOfMemory => return error.OutOfMemory,
	};
	defer endpoint.deinit(allocator);

	// --wait-for-ssh: poll the guest's sshd until it answers (or the VM dies, or
	// the timeout elapses) before exec'ing ssh. Closes the cold-boot race in
	// `cogbox start --no-ssh ... && cogbox ssh --wait-for-ssh ... cmd`; a no-op
	// once sshd is up (the first probe connects and we proceed immediately).
	if (parsed.isSet("wait-for-ssh")) {
		const wait_ms: i64 = if (parsed.get("wait-timeout")) |s|
			@as(i64, parse.parseIntRange(s, 1, 86_400) catch
				util.die(allocator, io, "ssh", exit_codes.dataerr, "--wait-timeout must be an integer number of seconds (1-86400)", .{})) * 1000
		else
			180_000;

		if (!waitForSshOrDeath(io, pid, endpoint.host, endpoint.port, wait_ms)) {
			if (pidAlive(pid)) {
				util.die(allocator, io, "ssh", exit_codes.tempfail, "sshd did not become ready within {d}s; the VM may still be booting (check 'cogbox logs' / 'cogbox console').", .{@divTrunc(wait_ms, 1000)});
			}
			util.die(allocator, io, "ssh", exit_codes.software, "the VM exited while waiting for sshd (check 'cogbox logs').", .{});
		}
	}

	// Forward everything after the verb (and any `--`) to the remote as the
	// command/args. With terminate_on_positional both land in `trailing`, but
	// fold `positional` in too for parity.
	var extra: std.ArrayList([]const u8) = .empty;
	defer extra.deinit(allocator);
	for (parsed.trailing.items) |t| try extra.append(allocator, t);
	for (parsed.positional.items) |t| try extra.append(allocator, t);

	const identity = defaultIdentity(allocator, io, p);
	defer if (identity) |id| allocator.free(id);

	try exec(allocator, endpoint, identity, extra.items);
}

// The endpoint read and the argv builder are shared with the live plugin
// apply's guest hops (sshargv); re-exported so `cogbox start` and the tests
// below keep their names.
pub const Endpoint = sshargv.Endpoint;
pub const EndpointError = sshargv.EndpointError;
pub const readEndpoint = sshargv.readEndpoint;
const buildArgv = sshargv.buildArgv;

/// Replace this process with `ssh` pointed at `endpoint`. `extra` is the remote
/// command, appended after the `root@host` target and quoted for the guest shell
/// (see `sshargv.appendRemoteCommand`). Host key checking is disabled because the guest's
/// root disk is ephemeral and its host keys regenerate on every boot.
///
/// When `identity` is non-null (cogbox's own managed key; see `defaultIdentity`)
/// ssh is pinned to *only* that key -- `-i <identity>` plus IdentitiesOnly=yes
/// and IdentityAgent=none -- so it never offers the user's agent / ~/.ssh keys
/// and never contacts an agent. That keeps a gpg-agent (ssh support) from
/// prompting or stalling the connection, and is sufficient because the cogbox
/// key is unioned into the guest's authorized_keys by default. When `identity`
/// is null (the --no-auto-keys opt-out, where no cogbox key exists) none of this
/// is added and ssh keeps its normal fallback to the user's agent and default
/// keys, so a user who authorized only their own key still connects.
///
/// A `-t` is inserted before the target for a fully interactive remote command
/// (a command is present and both local stdin and stdout are ttys) so remote
/// TUIs get a PTY; see `wantPty` for the gating rationale.
///
/// ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
///     [-o IdentitiesOnly=yes -o IdentityAgent=none -i <identity>]
///     -p <port> [-t] root@<host> [extra...]
pub fn exec(allocator: std.mem.Allocator, endpoint: Endpoint, identity: ?[]const u8, extra: []const []const u8) !void {
	// The two isatty() calls are this function's only impurity; evaluate them
	// here and delegate the decision to the pure, unit-tested `wantPty`.
	const force_pty = wantPty(
		extra,
		std.c.isatty(std.posix.STDIN_FILENO) != 0,
		std.c.isatty(std.posix.STDOUT_FILENO) != 0,
	);

	var ssh_argv: std.ArrayList([]const u8) = .empty;
	defer ssh_argv.deinit(allocator);
	try buildArgv(allocator, &ssh_argv, endpoint, identity, extra, force_pty);

	try execvpAlloc(allocator, ssh_argv.items);
}

/// Whether to request a remote PTY (a single `ssh -t`) for this invocation.
/// True only for a *fully interactive* remote command: a command is present
/// (`extra.len > 0`) AND both local stdin and stdout are terminals.
///
/// Without `-t`, `ssh host cmd` runs cmd over pipes (no tty) and screen apps
/// like htop / claude-code refuse to start. The command gate keeps the
/// no-command interactive login -- which ssh already gives a PTY -- on its
/// existing path (so `cogbox start` auto-ssh, which passes empty `extra`, is
/// untouched). Requiring BOTH ends be ttys is what protects
/// `cogbox ssh host cat f | downstream` and `... > file`: a shell pipeline
/// redirects only stdout while stdin stays a tty, so gating on stdin alone
/// would still force a PTY and let its line discipline mangle the bytes
/// (LF->CRLF, control cooking). A single `-t` (never `-tt`) is deliberate --
/// `-tt` would force a PTY even with no local tty at all.
fn wantPty(extra: []const []const u8, stdin_is_tty: bool, stdout_is_tty: bool) bool {
	return extra.len > 0 and stdin_is_tty and stdout_is_tty;
}

/// Path to cogbox's managed SSH identity (`<data>/cogbox_ed25519`), or null if
/// it does not exist. The launch script generates it host-side and unions its
/// pubkey into each VM's authorized_keys; `exec` then pins ssh to it exclusively
/// (no agent), so `cogbox ssh` works without -- and without touching -- the
/// user's personal keys or agent. Best-effort: any error (alloc, missing file)
/// yields null, so ssh falls back to its defaults (the --no-auto-keys opt-out
/// path). The returned slice is owned by the caller.
pub fn defaultIdentity(allocator: std.mem.Allocator, io: std.Io, p: *const paths.Paths) ?[]const u8 {
	const key_path = std.fs.path.join(allocator, &.{ p.base_data, "cogbox_ed25519" }) catch return null;
	const cwd = std.Io.Dir.cwd();
	cwd.access(io, key_path, .{}) catch {
		allocator.free(key_path);
		return null;
	};
	return key_path;
}

fn nameFlag(parsed: *const parse.Parsed, allocator: std.mem.Allocator, io: std.Io) ?[]const u8 {
	if (parsed.get("name")) |n| {
		if (std.mem.eql(u8, n, "default")) {
			util.die(allocator, io, "ssh", exit_codes.dataerr, "'default' is reserved. Omit --name to use the default instance.", .{});
		}
		if (!parse.isValidName(n)) {
			util.die(allocator, io, "ssh", exit_codes.dataerr, "instance name must start with a letter and contain only [a-zA-Z0-9-] (max 64 chars)", .{});
		}
		return n;
	}
	return null;
}

/// Parse <runtime>/pid into a pid. Null if the file is absent/unreadable/empty
/// or doesn't hold an integer. Does NOT check liveness -- see `pidAlive`.
fn readPid(allocator: std.mem.Allocator, io: std.Io, pid_path: []const u8) ?c_int {
	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(io, pid_path, .{}) catch return null;
	defer file.close(io);
	var buf: [64]u8 = undefined;
	var reader = file.reader(io, &buf);
	const data = reader.interface.allocRemaining(allocator, .limited(64)) catch return null;
	defer allocator.free(data);
	const trimmed = std.mem.trim(u8, data, " \t\r\n");
	return std.fmt.parseInt(c_int, trimmed, 10) catch null;
}

/// Whether `pid` names a live process, via a signal-0 probe.
fn pidAlive(pid: c_int) bool {
	const sig_zero: std.posix.SIG = @enumFromInt(0);
	std.posix.kill(@intCast(pid), sig_zero) catch return false;
	return true;
}

// --- sshd readiness probe -------------------------------------------------
// Shared by `cogbox start` (default path) and `cogbox ssh --wait-for-ssh`.
// Socket calls aren't in std.posix on this Zig; use libc (we link it).
extern "c" fn connect(fd: c_int, addr: *const anyopaque, len: c_uint) c_int;
extern "c" fn inet_pton(af: c_int, src: [*:0]const u8, dst: *anyopaque) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn waitpid(pid: c_int, status: *c_int, options: c_int) c_int;
const WNOHANG: c_int = 1;

/// Poll the guest's sshd until it answers with an SSH identification banner,
/// returning true when ready. Returns false if the VM daemon `pid` exits first
/// or the timeout elapses. `host`/`port` come from <runtime>/ssh-endpoint.
///
/// Used by `cogbox start` (default path, where `pid` is its own forked daemon)
/// and `cogbox ssh --wait-for-ssh` (where `pid` is a daemon from an earlier
/// process); `daemonExited` copes with both.
pub fn waitForSshOrDeath(io: std.Io, pid: c_int, host: []const u8, port: []const u8, max_wait_ms: i64) bool {
	const port_num = std.fmt.parseInt(u16, std.mem.trim(u8, port, " \t\r\n"), 10) catch return false;

	// Build the target sockaddr once. The host is an IP literal; if it somehow
	// isn't parseable as IPv4 we can't probe, so report ready and let ssh do its
	// own resolution + connect rather than blocking until the timeout.
	var sin: std.posix.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port_num), .addr = 0 };
	var host_z: [64]u8 = undefined;
	if (host.len >= host_z.len) return true;
	@memcpy(host_z[0..host.len], host);
	host_z[host.len] = 0;
	if (inet_pton(std.posix.AF.INET, @ptrCast(&host_z), @ptrCast(&sin.addr)) != 1) return true;

	// Probe before sleeping so an sshd that is already up returns on the first
	// pass with no delay -- the common warm-VM case for `--wait-for-ssh`, which
	// callers are told is a cheap no-op once sshd is listening.
	const step_ms: i64 = 250;
	var waited: i64 = 0;
	while (true) {
		if (daemonExited(pid)) return false;
		if (probeSsh(&sin)) return true;
		if (waited >= max_wait_ms) return false;
		_ = std.Io.sleep(io, std.Io.Duration.fromMilliseconds(step_ms), .awake) catch {};
		waited += step_ms;
	}
}

/// Whether the VM daemon `pid` has exited -- works whether or not it is our
/// child. `waitpid(WNOHANG)` is authoritative for a child: it returns the pid
/// (exited, and reaps it so it can't linger as a zombie that kill(pid,0) would
/// misreport as alive), 0 (still running), or <0 with ECHILD when `pid` is not
/// our child (the `cogbox ssh` case). In that last case fall back to a signal-0
/// liveness probe -- the daemon's real parent reaps it, so no zombie confuses us.
fn daemonExited(pid: c_int) bool {
	var status: c_int = 0;
	const r = waitpid(pid, &status, WNOHANG);
	if (r == pid) return true; // our child, exited (now reaped)
	if (r == 0) return false; // our child, still running
	return !pidAlive(pid); // not our child (ECHILD) -- probe with kill(pid, 0)
}

/// One readiness probe: open a TCP connection to the forwarded SSH port and
/// wait briefly for sshd's "SSH-..." banner. A bare connect() is not proof of
/// readiness -- passt/SLIRP accept the host side before the guest is listening,
/// then reset -- so the banner is the authoritative signal.
fn probeSsh(sin: *const std.posix.sockaddr.in) bool {
	const fd = @import("platform").streamSocket(std.posix.AF.INET) catch return false;
	defer _ = close(fd);

	if (connect(fd, @ptrCast(sin), @intCast(@sizeOf(std.posix.sockaddr.in))) != 0) return false;

	var pfd = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
	const r = std.posix.poll(&pfd, 1500) catch return false;
	if (r == 0) return false; // no banner within the read window
	if (pfd[0].revents & std.posix.POLL.IN == 0) return false;

	var buf: [16]u8 = undefined;
	const n = std.posix.read(fd, &buf) catch return false;
	return n >= 4 and std.mem.startsWith(u8, buf[0..n], "SSH-");
}

extern "c" fn execvp(file: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;

/// execvp via libc: replaces the current process. Allocates null-terminated
/// strings for the argv array.
pub fn execvpAlloc(allocator: std.mem.Allocator, argv: []const []const u8) !void {
	const argv_z = try allocator.alloc(?[*:0]const u8, argv.len + 1);
	defer allocator.free(argv_z);
	for (argv, 0..) |a, i| {
		const z = try allocator.dupeZ(u8, a);
		argv_z[i] = z.ptr;
	}
	argv_z[argv.len] = null;

	const prog = try allocator.dupeZ(u8, argv[0]);
	const argv_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(argv_z.ptr);
	_ = execvp(prog.ptr, argv_ptr);
	// If execvp returns, it failed.
	return error.ExecvpFailed;
}

const testing = std.testing;

fn argvCount(argv: []const []const u8, needle: []const u8) usize {
	var n: usize = 0;
	for (argv) |a| {
		if (std.mem.eql(u8, a, needle)) n += 1;
	}
	return n;
}

fn argvIndex(argv: []const []const u8, needle: []const u8) ?usize {
	for (argv, 0..) |a, i| {
		if (std.mem.eql(u8, a, needle)) return i;
	}
	return null;
}

/// The ONE string ssh actually sends: every argv element after `root@host`
/// joined with single spaces, which is exactly what the remote sshd hands to
/// `sh -c`. Asserting on this asserts on what the guest shell parses, not on
/// an argv the guest never sees.
fn remoteCommandLine(allocator: std.mem.Allocator, argv: []const []const u8, ep: Endpoint) ![]u8 {
	const target = try std.fmt.allocPrint(allocator, "root@{s}", .{ep.host});
	const host_i = argvIndex(argv, target).?;
	return std.mem.join(allocator, " ", argv[host_i + 1 ..]);
}

test "buildArgv adds a single -t before the target only when force_pty" {
	var arena = std.heap.ArenaAllocator.init(testing.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	const ep: Endpoint = .{ .port = "2222", .host = "10.0.2.15" };

	// Interactive remote command -> exactly one `-t`, placed before root@host,
	// with the remote command still trailing the target.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgv(a, &argv, ep, null, &.{"tty"}, true);
		try testing.expectEqual(@as(usize, 1), argvCount(argv.items, "-t"));
		const t_i = argvIndex(argv.items, "-t").?;
		const host_i = argvIndex(argv.items, "root@10.0.2.15").?;
		try testing.expect(t_i < host_i);
		try testing.expect(argvIndex(argv.items, "tty").? > host_i);
	}

	// Piped / non-interactive (force_pty=false) -> no `-t`, command still sent.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgv(a, &argv, ep, null, &.{"tty"}, false);
		try testing.expectEqual(@as(usize, 0), argvCount(argv.items, "-t"));
		try testing.expect(argvIndex(argv.items, "tty") != null);
	}

	// Interactive login (no remote command) -> caller passes empty extra and
	// force_pty=false; no `-t` (ssh allocates the login PTY itself) and the
	// target is the last argv element.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgv(a, &argv, ep, null, &.{}, false);
		try testing.expectEqual(@as(usize, 0), argvCount(argv.items, "-t"));
		try testing.expectEqualStrings("root@10.0.2.15", argv.items[argv.items.len - 1]);
	}

	// Identity is forwarded as `-i <path>`.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgv(a, &argv, ep, "/data/cogbox_ed25519", &.{}, false);
		const i_i = argvIndex(argv.items, "-i").?;
		try testing.expectEqualStrings("/data/cogbox_ed25519", argv.items[i_i + 1]);
	}

	// A multi-element command is appended in order as the argv tail, immediately
	// after the target (and after `-t` when a PTY is forced), one shell-quoted
	// element each -- see `appendRemoteCommand`.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		const cmd = [_][]const u8{ "uname", "-a" };
		const want = [_][]const u8{ "'uname'", "'-a'" };
		try buildArgv(a, &argv, ep, null, &cmd, true);
		const host_i = argvIndex(argv.items, "root@10.0.2.15").?;
		try testing.expectEqual(cmd.len, argv.items.len - (host_i + 1));
		for (want, 0..) |w, j| {
			try testing.expectEqualStrings(w, argv.items[host_i + 1 + j]);
		}
	}
}

test "buildArgv pins to the cogbox key and disables the agent only with an identity" {
	var arena = std.heap.ArenaAllocator.init(testing.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	const ep: Endpoint = .{ .port = "2222", .host = "10.0.2.15" };

	// With an identity: ssh offers ONLY that key (IdentitiesOnly=yes) and never
	// contacts an agent (IdentityAgent=none), so a gpg-agent can't be reached.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgv(a, &argv, ep, "/data/cogbox_ed25519", &.{}, false);
		try testing.expect(argvIndex(argv.items, "IdentitiesOnly=yes") != null);
		try testing.expect(argvIndex(argv.items, "IdentityAgent=none") != null);
		const i_i = argvIndex(argv.items, "-i").?;
		try testing.expectEqualStrings("/data/cogbox_ed25519", argv.items[i_i + 1]);
	}

	// Without an identity (the --no-auto-keys opt-out, where no cogbox key
	// exists): no pinning, so ssh keeps its default fallback to the user's agent
	// and ~/.ssh keys -- a user who authorized only their own key still connects.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgv(a, &argv, ep, null, &.{}, false);
		try testing.expect(argvIndex(argv.items, "IdentitiesOnly=yes") == null);
		try testing.expect(argvIndex(argv.items, "IdentityAgent=none") == null);
		try testing.expect(argvIndex(argv.items, "-i") == null);
	}
}

test "buildArgv quotes a multi-word remote command so the guest shell sees the caller's words" {
	var arena = std.heap.ArenaAllocator.init(testing.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	const ep: Endpoint = .{ .port = "2222", .host = "10.0.2.15" };

	// A control plane may enumerate the guest's tmux sessions with
	//   cogbox ssh -n <inst> tmux list-sessions -F '#{session_name}\t#{session_attached}'
	// Forwarded bare, ssh's space-join handed the guest shell an unquoted
	// `#{session_name}` -- which opens a COMMENT -- so tmux saw a bare `-F` and
	// exits 1 ("command list-sessions: -F expects an argument").
	{
		var argv: std.ArrayList([]const u8) = .empty;
		const cmd = [_][]const u8{ "tmux", "list-sessions", "-F", "#{session_name}\t#{session_attached}" };
		try buildArgv(a, &argv, ep, null, &cmd, false);
		try testing.expectEqualStrings(
			"'tmux' 'list-sessions' '-F' '#{session_name}\t#{session_attached}'",
			try remoteCommandLine(a, argv.items, ep),
		);
	}

	// Every metacharacter class the join would otherwise hand to the guest
	// shell, as the third word of an argv command. The tab and the newline are
	// word separators for the remote `sh -c`; the rest are expansions,
	// comments, or a command separator (an injection, when any element is
	// user-controlled).
	{
		const cases = [_]struct { arg: []const u8, want: []const u8 }{
			.{ .arg = "#{session_name}", .want = "'#{session_name}'" },
			.{ .arg = "two words", .want = "'two words'" },
			.{ .arg = "it's", .want = "'it'\\''s'" },
			.{ .arg = "'", .want = "''\\'''" },
			.{ .arg = "$HOME", .want = "'$HOME'" },
			.{ .arg = "`id`", .want = "'`id`'" },
			.{ .arg = "a\tb", .want = "'a\tb'" },
			.{ .arg = "a\nb", .want = "'a\nb'" },
			.{ .arg = "a;id", .want = "'a;id'" },
			.{ .arg = "*", .want = "'*'" },
			.{ .arg = "", .want = "''" },
		};
		for (cases) |c| {
			var argv: std.ArrayList([]const u8) = .empty;
			const cmd = [_][]const u8{ "printf", "%s", c.arg };
			try buildArgv(a, &argv, ep, null, &cmd, false);
			try testing.expectEqualStrings(
				try std.fmt.allocPrint(a, "'printf' '%s' {s}", .{c.want}),
				try remoteCommandLine(a, argv.items, ep),
			);
		}
	}
}

test "buildArgv keeps the lone remote-command string and the no-command login untouched" {
	var arena = std.heap.ArenaAllocator.init(testing.allocator);
	defer arena.deinit();
	const a = arena.allocator();
	const ep: Endpoint = .{ .port = "2222", .host = "10.0.2.15" };

	// One argument is ssh's own remote-command-STRING form, which cogbox has
	// always had and the guest test suite uses throughout; quoting it would turn
	// the whole string into a single command NAME. It goes through verbatim.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgv(a, &argv, ep, null, &.{"readlink -f $(command -v hello)"}, false);
		try testing.expectEqualStrings(
			"readlink -f $(command -v hello)",
			try remoteCommandLine(a, argv.items, ep),
		);
	}

	// No command at all (interactive login, and `cogbox start`'s auto-ssh) sends
	// nothing after the target -- a real login PTY, exactly as before.
	{
		var argv: std.ArrayList([]const u8) = .empty;
		try buildArgv(a, &argv, ep, null, &.{}, false);
		try testing.expectEqualStrings("", try remoteCommandLine(a, argv.items, ep));
	}
}

test "wantPty: only a remote command with both stdin+stdout ttys forces a PTY" {
	// No remote command -> never (even with both ttys); ssh gives the
	// no-command login its own PTY, and `cogbox start` auto-ssh passes empty.
	try testing.expect(!wantPty(&.{}, true, true));
	// Fully interactive remote command (terminal on both ends) -> yes.
	try testing.expect(wantPty(&.{"htop"}, true, true));
	// Output piped/redirected (`cmd | downstream`, `cmd > file`) -> no, so the
	// remote PTY's line discipline cannot mangle the bytes.
	try testing.expect(!wantPty(&.{"cat"}, true, false));
	// Input piped (`printf '' | cogbox ssh host cmd`) -> no.
	try testing.expect(!wantPty(&.{"cat"}, false, true));
	// Fully non-interactive (scripted) -> no.
	try testing.expect(!wantPty(&.{"cat"}, false, false));
}
