// Common helpers for verbs that exec the bash launch script.
//
// The launch script lives in $out/libexec/cogbox-launch.sh, alongside
// the binary at $out/bin/cogbox. We resolve the path at runtime via
// the executable path so the binary is relocatable (no compile-time bake).
//
// Launch modes (passed to the script):
//   --init-only   seed host state + (for custom flakes) warm the runner
//                 build via re-exec, then stop before runtime setup. Used
//                 by `cogbox init` and by the foreground init step of the
//                 default launch.
//   (no flag)     full launch: runtime setup + passt + QEMU. The script
//                 daemonization itself is driven by the Zig `start` verb,
//                 which forks before exec'ing the script in this mode.

const std = @import("std");
extern "c" fn _NSGetExecutablePath([*]u8, *u32) c_int;


pub const AdditionalDir = struct {
	path: []const u8,
	read_only: bool,
};
pub const LaunchOpts = struct {
	name: ?[]const u8,
	vcpu: ?u32,
	mem: ?u32,
	network: ?[]const u8,
	auto_keys: bool,
	yes: bool,
	/// Address the guest's port forwards are advertised at (`.bindAddr`).
	/// Seeded into config.json on first init; null keeps the 127.0.0.1 default.
	bind_addr: ?[]const u8 = null,
	/// Drop the filter's implicit port-53 allow for this instance
	/// (`.network.implicitDns = false`). Off by default: on a host whose
	/// resolver is a loopback address, the implicit allow is what makes guest
	/// DNS work at all.
	no_implicit_dns: bool = false,
	/// Addresses of the ENCLOSING host, added to the L7 proxy's non-overridable
	/// floor (`.network.selfAddrs`). Empty by default. Borrowed from argv or
	/// caller-owned; `buildLaunchArgs` only reads it.
	self_addrs: []const []const u8 = &.{},
	/// The loopback address the ENCLOSING host runs its own DNS forwarder on
	/// (`.network.dnsHost`). null by default. Paired with `no_implicit_dns`:
	/// that flag puts loopback DNS back under the shim's loopback deny, and this
	/// one re-admits the ONE socket passt re-emits the guest's queries on
	/// (`--dns-forward` -> `--dns-host`), so the guest resolves what the host
	/// resolves without any other loopback listener becoming reachable.
	dns_host: ?[]const u8 = null,
	/// Host directories granted to this launch only. The paths remain individual
	/// argv elements; the bash launcher canonicalizes and stages them.
	additional_dirs: []const AdditionalDir = &.{},
	/// Zig-side only (never forwarded to the bash script): attach the serial
	/// console after the VM comes up instead of returning immediately.
	foreground: bool,
	/// Zig-side only: suppress the default auto-ssh. With neither this nor
	/// `foreground`, `start` waits for the guest's sshd and then execs `ssh`;
	/// with this set it just prints how to connect and returns.
	no_ssh: bool,
};

/// Build the argv that the bash launch script expects. `init_only` selects
/// the script mode; `opts.foreground` is intentionally NOT forwarded (it is
/// handled entirely on the Zig side).
/// Caller owns the returned slice and each element.
pub fn buildLaunchArgs(
	allocator: std.mem.Allocator,
	opts: LaunchOpts,
	script_path: []const u8,
	init_only: bool,
) ![]const []const u8 {
	var args: std.ArrayList([]const u8) = .empty;
	errdefer args.deinit(allocator);

	try args.append(allocator, try allocator.dupe(u8, script_path));

	if (opts.name) |n| {
		try args.append(allocator, try allocator.dupe(u8, "--name"));
		try args.append(allocator, try allocator.dupe(u8, n));
	}
	if (opts.vcpu) |v| {
		try args.append(allocator, try allocator.dupe(u8, "--vcpu"));
		try args.append(allocator, try std.fmt.allocPrint(allocator, "{d}", .{v}));
	}
	if (opts.mem) |m| {
		try args.append(allocator, try allocator.dupe(u8, "--mem"));
		try args.append(allocator, try std.fmt.allocPrint(allocator, "{d}", .{m}));
	}
	if (opts.network) |n| {
		try args.append(allocator, try allocator.dupe(u8, "--network"));
		try args.append(allocator, try allocator.dupe(u8, n));
	}
	if (opts.bind_addr) |b| {
		try args.append(allocator, try allocator.dupe(u8, "--bind-addr"));
		try args.append(allocator, try allocator.dupe(u8, b));
	}
	if (opts.no_implicit_dns) try args.append(allocator, try allocator.dupe(u8, "--no-implicit-dns"));
	if (opts.dns_host) |h| {
		try args.append(allocator, try allocator.dupe(u8, "--dns-host"));
		try args.append(allocator, try allocator.dupe(u8, h));
	}
	for (opts.self_addrs) |s| {
		try args.append(allocator, try allocator.dupe(u8, "--self-addr"));
		try args.append(allocator, try allocator.dupe(u8, s));
	}
	if (!init_only) {
		for (opts.additional_dirs) |dir| {
			try args.append(allocator, try allocator.dupe(u8, if (dir.read_only) "--add-dir-ro" else "--add-dir"));
			try args.append(allocator, try allocator.dupe(u8, dir.path));
		}
	}
	if (!opts.auto_keys) try args.append(allocator, try allocator.dupe(u8, "--no-auto-keys"));
	if (opts.yes) try args.append(allocator, try allocator.dupe(u8, "--yes"));
	if (init_only) try args.append(allocator, try allocator.dupe(u8, "--init-only"));

	return try args.toOwnedSlice(allocator);
}

// The bash script rejects an argument it does not know (exit 70), so a flag
// that exists on one side only is a broken boot, not a warning. These pin the
// forwarding for the four host-integration seeds, including the empty case
// that every local and k8s launch takes.

test "buildLaunchArgs forwards the host-integration seeds" {
	const gpa = std.testing.allocator;
	const self_addrs = [_][]const u8{ "10.0.0.1/32", "10.0.0.2/32" };
	const argv = try buildLaunchArgs(gpa, .{
		.name = "demo",
		.vcpu = null,
		.mem = null,
		.network = "rules",
		.auto_keys = true,
		.yes = true,
		.bind_addr = "10.0.0.1",
		.no_implicit_dns = true,
		.self_addrs = &self_addrs,
		.dns_host = "127.0.0.53",
		.foreground = false,
		.no_ssh = false,
	}, "/libexec/cogbox-launch.sh", true);
	defer {
		for (argv) |a| gpa.free(a);
		gpa.free(argv);
	}

	var joined: std.ArrayList(u8) = .empty;
	defer joined.deinit(gpa);
	for (argv) |a| {
		try joined.appendSlice(gpa, a);
		try joined.append(gpa, ' ');
	}
	const s = joined.items;
	try std.testing.expect(std.mem.indexOf(u8, s, "--bind-addr 10.0.0.1 ") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "--no-implicit-dns ") != null);
	// One flag per address: collapsing them would shrink a security floor.
	try std.testing.expect(std.mem.indexOf(u8, s, "--self-addr 10.0.0.1/32 ") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "--self-addr 10.0.0.2/32 ") != null);
	try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, s, "--self-addr "));
	// The guest-DNS seed travels with --no-implicit-dns or the rules-mode guest
	// loses DNS entirely: the flag above is what puts loopback DNS back under
	// the shim's loopback deny, and this is the one socket re-admitted to it.
	try std.testing.expect(std.mem.indexOf(u8, s, "--dns-host 127.0.0.53 ") != null);
}

test "buildLaunchArgs omits the seeds entirely when unset" {
	// The default-preserving guarantee at the argv layer: a launch that asks
	// for none of this must produce the argv it produced before the flags
	// existed.
	const gpa = std.testing.allocator;
	const argv = try buildLaunchArgs(gpa, .{
		.name = null,
		.vcpu = 4,
		.mem = 2048,
		.network = null,
		.auto_keys = true,
		.yes = false,
		.foreground = false,
		.no_ssh = false,
	}, "/libexec/cogbox-launch.sh", false);
	defer {
		for (argv) |a| gpa.free(a);
		gpa.free(argv);
	}

	try std.testing.expectEqual(@as(usize, 5), argv.len);
	try std.testing.expectEqualStrings("/libexec/cogbox-launch.sh", argv[0]);
	try std.testing.expectEqualStrings("--vcpu", argv[1]);
	try std.testing.expectEqualStrings("4", argv[2]);
	try std.testing.expectEqualStrings("--mem", argv[3]);
	try std.testing.expectEqualStrings("2048", argv[4]);
}

test "buildLaunchArgs forwards every additional host directory in argv order" {
	const gpa = std.testing.allocator;
	const additional_dirs = [_]AdditionalDir{
		.{ .path = "./read write", .read_only = false },
		.{ .path = "/tmp/read,only", .read_only = true },
		.{ .path = "../again", .read_only = false },
	};
	const opts: LaunchOpts = .{
		.name = null,
		.vcpu = null,
		.mem = null,
		.network = null,
		.auto_keys = true,
		.yes = false,
		.additional_dirs = &additional_dirs,
		.foreground = false,
		.no_ssh = false,
	};

	const argv = try buildLaunchArgs(gpa, opts, "/libexec/cogbox-launch.sh", false);
	defer {
		for (argv) |a| gpa.free(a);
		gpa.free(argv);
	}
	const expected = [_][]const u8{
		"/libexec/cogbox-launch.sh",
		"--add-dir",    "./read write",
		"--add-dir-ro", "/tmp/read,only",
		"--add-dir",    "../again",
	};
	try std.testing.expectEqual(expected.len, argv.len);
	for (expected, argv) |want, got| try std.testing.expectEqualStrings(want, got);

	const init_argv = try buildLaunchArgs(gpa, opts, "/libexec/cogbox-launch.sh", true);
	defer {
		for (init_argv) |a| gpa.free(a);
		gpa.free(init_argv);
	}
	try std.testing.expectEqual(@as(usize, 2), init_argv.len);
	try std.testing.expectEqualStrings("/libexec/cogbox-launch.sh", init_argv[0]);
	try std.testing.expectEqualStrings("--init-only", init_argv[1]);
}

/// Resolve a sibling libexec script via the platform's executable path
/// (/proc/self/exe or _NSGetExecutablePath) and walk up (exe = .../bin/cogbox -> .../libexec/<name>),
/// so the binary stays relocatable. An explicit `override` env var wins (used by
/// the wrapper's --set and by tests).
fn resolveLibexec(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	override: []const u8,
	name: []const u8,
) ![]const u8 {
	if (env.get(override)) |p| {
		return try allocator.dupe(u8, p);
	}

	var buf: [std.fs.max_path_bytes]u8 = undefined;
	const n = if (@import("platform").darwin) blk: {
		var size: u32 = buf.len;
		if (_NSGetExecutablePath(&buf, &size) != 0) return error.NameTooLong;
		break :blk std.mem.indexOfScalar(u8, &buf, 0) orelse return error.NameTooLong;
	} else try std.Io.Dir.readLinkAbsolute(io, "/proc/self/exe", &buf);
	const exe = buf[0..n];
	const bin_dir = std.fs.path.dirname(exe) orelse return error.NoBinDir;
	const prefix = std.fs.path.dirname(bin_dir) orelse return error.NoPrefix;
	return try std.fs.path.join(allocator, &.{ prefix, "libexec", name });
}

/// Resolve the absolute path to libexec/cogbox-launch.sh. Falls back to the
/// COGBOX_LAUNCH_SCRIPT env var for testing.
pub fn resolveScriptPath(allocator: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map) ![]const u8 {
	return resolveLibexec(allocator, io, env, "COGBOX_LAUNCH_SCRIPT", "cogbox-launch.sh");
}

/// Resolve the absolute path to libexec/cogbox-enforce.sh (the container
/// enforcer supervisor). Falls back to the COGBOX_ENFORCE_SCRIPT env var.
pub fn resolveEnforceScriptPath(allocator: std.mem.Allocator, io: std.Io, env: *std.process.Environ.Map) ![]const u8 {
	return resolveLibexec(allocator, io, env, "COGBOX_ENFORCE_SCRIPT", "cogbox-enforce.sh");
}

extern "c" fn execv(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;

/// Replace the current process with `argv[0]` invoked with `argv`.
pub fn execvAlloc(allocator: std.mem.Allocator, argv: []const []const u8) !void {
	const argv_z = try allocator.alloc(?[*:0]const u8, argv.len + 1);
	defer allocator.free(argv_z);
	for (argv, 0..) |a, i| {
		const z = try allocator.dupeZ(u8, a);
		argv_z[i] = z.ptr;
	}
	argv_z[argv.len] = null;

	const prog = try allocator.dupeZ(u8, argv[0]);
	const argv_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(argv_z.ptr);
	_ = execv(prog.ptr, argv_ptr);
	return error.ExecvFailed;
}

/// Resolve the script path, build args for `init_only`, and exec it in place
/// (replacing this process). Used by `cogbox init` (init_only=true,
/// foreground) and the hidden `__launch` re-exec target (init_only=false).
pub fn execLaunchScript(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	opts: LaunchOpts,
	init_only: bool,
) !void {
	const script_path = try resolveScriptPath(allocator, io, env);
	const argv = try buildLaunchArgs(allocator, opts, script_path, init_only);
	try execvAlloc(allocator, argv);
}
