// Shelling out to nix for the plugin verb. Everything network-touching or
// store-touching goes through here: resolving a flake URL to a locked rev
// (metadata), checking the module contract (eval), reading the optional
// cogboxPlugins.<attr> host-side policy output (eval), and pre-fetching the plugin's
// transitive inputs for offline restarts (archive).
//
// Experimental features are passed explicitly (the launcher does the same at
// cogbox-launch.sh's re-exec) so the verb works regardless of user nix.conf.

const std = @import("std");

pub const RunOut = struct {
	stdout: []u8,
	stderr: []u8,
	ok: bool,
	/// runNixTimed only: the `timeout` wrapper killed nix (exit 124).
	timed_out: bool = false,

	pub fn deinit(self: *RunOut, allocator: std.mem.Allocator) void {
		allocator.free(self.stdout);
		allocator.free(self.stderr);
	}
};

/// Run a `nix` subcommand. `env`, when non-null, REPLACES the child
/// environment for this one invocation -- the plugin fetch passes a per-fetch
/// map (a clone of the parent env with HOME / GIT_CONFIG_* / GIT_TERMINAL_PROMPT
/// overridden) so a private-repo clone authenticates from a temp netrc scoped to
/// exactly this exec. Null inherits the parent env
/// unchanged -- the default for every non-authenticated nix call.
pub fn runNix(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, args: []const []const u8) !RunOut {
	var argv: std.ArrayList([]const u8) = .empty;
	defer argv.deinit(allocator);
	try argv.appendSlice(allocator, &.{ "nix", "--extra-experimental-features", "nix-command flakes" });
	try argv.appendSlice(allocator, args);

	const res = try std.process.run(allocator, io, .{ .argv = argv.items, .environ_map = env });
	const ok = res.term == .exited and res.term.exited == 0;
	return .{ .stdout = res.stdout, .stderr = res.stderr, .ok = ok };
}

/// runNix under coreutils `timeout -k 10 <timeout_s>`: nix is sent SIGTERM
/// after `timeout_s` seconds (SIGKILL 10s later), and the result carries
/// `timed_out` so a caller can tell "the network hung" from "this input
/// failed". For the calls that run inside the control plane's fixed install
/// budget and must never eat it whole. `timeout_s` 0 is clamped to 1.
pub fn runNixTimed(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, timeout_s: u32, args: []const []const u8) !RunOut {
	var secs_buf: [16]u8 = undefined;
	const secs = try std.fmt.bufPrint(&secs_buf, "{d}", .{@max(timeout_s, 1)});
	var argv: std.ArrayList([]const u8) = .empty;
	defer argv.deinit(allocator);
	try argv.appendSlice(allocator, &.{ "timeout", "-k", "10", secs, "nix", "--extra-experimental-features", "nix-command flakes" });
	try argv.appendSlice(allocator, args);

	const res = try std.process.run(allocator, io, .{ .argv = argv.items, .environ_map = env });
	const ok = res.term == .exited and res.term.exited == 0;
	const timed_out = res.term == .exited and res.term.exited == 124;
	return .{ .stdout = res.stdout, .stderr = res.stderr, .ok = ok, .timed_out = timed_out };
}

/// `refresh` adds `--refresh`, which bypasses nix's flake/tarball eval cache so
/// a mutable ref (e.g. `github:owner/repo` with no rev) re-resolves to the
/// current tip instead of a stale cached rev. add/update/resolve ALL set it
/// (resolveFlake / cmdUpdate) so an install always pins the latest rev -- the
/// tarball-ttl cache is shared across instances, so even a first resolve on THIS
/// instance can hit a rev another op cached and gone stale.
pub fn flakeMetadata(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, url: []const u8, refresh: bool) !RunOut {
	if (refresh) return runNix(allocator, io, env, &.{ "flake", "metadata", "--refresh", "--json", url });
	return runNix(allocator, io, env, &.{ "flake", "metadata", "--json", url });
}

pub fn flakeArchive(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, url: []const u8) !RunOut {
	return runNix(allocator, io, env, &.{ "flake", "archive", "--json", url });
}

/// `nix flake archive --to <dest> --json <url>`: copy the flake AND its
/// transitive inputs into the `dest` binary cache (a `file://<dir>` URI). The
/// launcher points `--extra-substituters` at that cache so a fresh-store
/// launch substitutes the plugin's tarball/narHash inputs offline (only git+
/// inputs can't substitute -- those are handled by the path: rewrite). Best-
/// effort: a launch with network still rebuilds from the inputs.
pub fn flakeArchiveTo(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, dest: []const u8, url: []const u8) !RunOut {
	return runNix(allocator, io, env, &.{ "flake", "archive", "--to", dest, "--json", url });
}

/// `nix flake lock <url>`: reconcile the composition flake's lock against its
/// current inputs, writing/updating flake.lock in place. Run after every regen.
/// Plain `nix flake lock` only ADDS missing inputs and DROPS removed ones: it
/// does NOT re-hash an existing path: input whose on-disk content changed. The
/// old narHash is kept, so a warm store silently serves the OLD content and a
/// cold store fails with a narHash mismatch. Callers must follow it with
/// flakeUpdateInputs for the STALE path: inputs. Authenticated (the rewritten inputs
/// are local path: refs, but a migration-fallback git+ input still needs the
/// acting user's token).
pub fn flakeLock(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, url: []const u8) !RunOut {
	return runNix(allocator, io, env, &.{ "flake", "lock", url });
}

/// Network bounds for the re-pin: a fetch that cannot connect, or stalls, fails
/// fast instead of eating the caller's whole timeout (a path: re-pin is offline
/// unless the input has no flake.lock of its own and nix re-resolves its
/// transitive inputs).
const repin_net_opts = [_][]const u8{ "--option", "connect-timeout", "5", "--option", "stalled-download-timeout", "20" };

/// The argv (after `nix --extra-experimental-features ...`) for
/// `nix flake update <net opts> <inputs...> --flake <url>`. Pure; the returned
/// slice is owned by the caller (the strings are borrowed). Zero inputs is
/// refused with error.NoInputs: nix treats an empty name list as update-ALL,
/// which would re-resolve git+/tarball fallback inputs against the network.
pub fn flakeUpdateArgv(allocator: std.mem.Allocator, url: []const u8, inputs: []const []const u8) ![]const []const u8 {
	if (inputs.len == 0) return error.NoInputs;
	const n_opts = repin_net_opts.len;
	const argv = try allocator.alloc([]const u8, 2 + n_opts + inputs.len + 2);
	argv[0] = "flake";
	argv[1] = "update";
	@memcpy(argv[2 .. 2 + n_opts], &repin_net_opts);
	@memcpy(argv[2 + n_opts .. 2 + n_opts + inputs.len], inputs);
	argv[2 + n_opts + inputs.len] = "--flake";
	argv[3 + n_opts + inputs.len] = url;
	return argv;
}

/// `nix flake update <inputs...> --flake <url>`: re-pin ONLY the named inputs
/// (re-hashing a path: input's current on-disk content into the lock). Works
/// offline for path: inputs whose own flake.lock pins their transitive inputs;
/// an input WITHOUT its own flake.lock has its transitive inputs re-resolved
/// (floated to upstream), which is why callers name only inputs that are
/// actually stale (compose.repinVerdict), never every path: input. No inputs => refused (error.NoInputs), never an update-all.
/// Bounded by `timeout_s` (runNixTimed): it runs inside the control plane's
/// install budget.
pub fn flakeUpdateInputs(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, url: []const u8, inputs: []const []const u8, timeout_s: u32) !RunOut {
	const argv = try flakeUpdateArgv(allocator, url, inputs);
	defer allocator.free(argv);
	return runNixTimed(allocator, io, env, timeout_s, argv);
}

/// `nix hash path <path>`: the SRI NAR hash of an on-disk tree -- the same
/// value a `path:` input of that tree locks as its narHash. Pure and offline
/// (reads the tree; no store write, no fetch), so the re-pin can tell a stale
/// lock entry from a current one without touching the network.
pub fn hashPath(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, path: []const u8) !RunOut {
	return runNix(allocator, io, env, &.{ "hash", "path", path });
}

/// Inputs for buildRunner. `flake_source`/`nixpkgs_source` are the cogbox
/// flake + nixpkgs store paths (COGBOX_FLAKE_SOURCE / COGBOX_NIXPKGS_SOURCE,
/// baked by mkCogbox); `plugins_flake_dir` is the composition; `arch` is the
/// config-name suffix (x86_64 / aarch64). The substituter knobs combine the
/// per-instance file:// cache with cogworx's remote runner cache so transitive
/// deps substitute rather than build. Empty optional knobs are simply omitted.
pub const RunnerBuild = struct {
	flake_source: []const u8,
	nixpkgs_source: []const u8,
	plugins_flake_dir: []const u8,
	arch: []const u8,
	// "file://<cache_dir> <COGBOX_EXTRA_SUBSTITUTERS>", already joined by the
	// caller (either piece may be empty; the whole string is omitted if empty).
	substituters: []const u8,
	trusted_public_keys: []const u8, // COGBOX_EXTRA_TRUSTED_PUBLIC_KEYS ("" => skip)
	netrc_file: []const u8, // COGBOX_NETRC_FILE ("" => skip)
	// base_store_root: the node-shared CoW base store the caller prepended to
	// `substituters` as `local?root=<base_store_root>&read-only=true` (the base-store substitution). Non-empty => append
	// `--extra-experimental-features read-only-local-store` so nix accepts the FROZEN
	// (chmod a-w, as the CoW-seed step leaves it) chroot store as a substituter. "" => skip
	// (no seeded lower found; `substituters` is the shared-cache-only string).
	base_store_root: []const u8 = "",
	// build_jobs: nix --max-jobs for the TOPLEVEL build only (toplevelBuildArgv). A
	// decimal string from COGBOX_WORKER_BUILD_JOBS, set by cogworx ONLY on the transient
	// worker pod's reconcile exec (never the live agent, whose memory is the instance's).
	// "" => keep the hardcoded -j1 OOM guard below. Default "" so runner/brain callers,
	// which never set it, stay byte-identical.
	build_jobs: []const u8 = "",
};

/// Build the `nix build` argv for the runner (everything after `nix
/// --extra-experimental-features ...`, which runNix prepends). Separated from
/// buildRunner so the load-bearing invariant -- that the installable + the
/// --override-input set EXACTLY match cogbox-launch.sh's re-exec, which is what
/// makes the worker-built out-path byte-identical to the one boot looks for --
/// is unit-testable. The returned slice and every interpolated string it owns
/// are freed by argvDeinit. Optional substituter/key/netrc knobs are appended
/// only when non-empty (so an unconfigured worker emits no extra options); a
/// non-empty base_store_root additionally appends `--extra-experimental-features
/// read-only-local-store` so nix accepts the frozen CoW lower as a store.
fn runnerBuildArgv(allocator: std.mem.Allocator, b: RunnerBuild) !std.ArrayList([]const u8) {
	return buildArgvFor(allocator, b, "", "config.microvm.declaredRunner");
}

/// The container backend's counterpart: build `config.system.build.cogboxBrain`
/// from the `-container` config -- the SAME eval target AND --override-input set
/// the container boot uses (flake.nix brainResolveContainer) -- so the pre-built
/// out-path is byte-identical to the one boot evaluates. cogboxBrain itself is
/// target-independent (same drv from the VM and -container configs), but the VM
/// config's eval forces the `microvm` flake input's SOURCE tree, unfetchable on a
/// cold fail-closed pod, so targeting the VM config here silently failed the seed
/// and left the plugin-cache empty (the boot rebuild then had nothing to
/// substitute from). Pre-copying that closure into the per-instance file:// cache
/// (copyClosureTo) turns the container's egress-less boot rebuild into a local
/// substitution. Same RunnerBuild fields; only the installable differs.
fn brainBuildArgv(allocator: std.mem.Allocator, b: RunnerBuild) !std.ArrayList([]const u8) {
	return buildArgvFor(allocator, b, "-container", "config.system.build.cogboxBrain");
}

/// Full-NixOS-module counterpart: build the per-instance CONTAINER `config.system.build.toplevel`
/// (base container system + the plugin's WHOLE module: environment.systemPackages, services,
/// environment.etc, ...) with the SAME --override-input set the boot uses, so the pre-built
/// out-path is byte-identical to the one agentInit realises + boots directly. Unlike the runner
/// (VM) and the target-INDEPENDENT brain, `system.build.toplevel` is target-DEPENDENT: it MUST
/// target the `-container` config (boot.isContainer, the agentInit shim) -- the plain
/// `cogbox-<arch>` config is a QEMU-guest toplevel that cannot boot as an unprivileged container.
fn toplevelBuildArgv(allocator: std.mem.Allocator, b: RunnerBuild) !std.ArrayList([]const u8) {
	var argv = try buildArgvFor(allocator, b, "-container", "config.system.build.toplevel");
	errdefer argvDeinit(allocator, &argv);
	// Serialize LOCAL builds. The container toplevel has many novel (per-plugin-set,
	// not cache-hittable) NixOS derivations -- unit-*.service generators, system-path,
	// /etc, perl envs -- and `max-jobs=auto` builds them in parallel, OOM-killing the
	// ~4GB sandbox (E2E: -j1 progresses; parallel dies "unexpected EOF reading a line",
	// a different drv each run). Also bound substitution concurrency: base-package NAR
	// downloads/decompression run in parallel regardless of --max-jobs, and on the boot
	// RECONCILE (which runs on the LIVE agent, competing with the running harness for the
	// 4GB) that spike OOM-killed a concurrent local build once. 4 keeps downloads
	// reasonably parallel without the memory blow-up.
	//
	// The -j1 default is overridable via b.build_jobs (COGBOX_WORKER_BUILD_JOBS), which
	// cogworx sets ONLY on a transient worker pod sized with extra cores/memory — never
	// on the live agent, so the OOM guard still holds for the live reconcile. `jobs` is
	// either the static "1" or the caller-owned build_jobs slice; both are non-freed by
	// argvDeinit (which frees only indices 1/4/7), so no argvDeinit change is needed.
	const jobs = if (b.build_jobs.len > 0) b.build_jobs else "1";
	try argv.appendSlice(allocator, &.{ "--max-jobs", jobs, "--max-substitution-jobs", "4" });
	return argv;
}

/// Shared `nix build` argv builder. `config_suffix` is appended after `cogbox-<arch>` to
/// select the nixosConfiguration (`""` = the VM config for the runner; `"-container"` = the
/// container config for the brain and toplevel). `installable_attr` is the leaf attribute. The
/// interpolated installable/inputs land at argv indices 1/4/7, which argvDeinit frees; the
/// literal flags are static.
fn buildArgvFor(allocator: std.mem.Allocator, b: RunnerBuild, config_suffix: []const u8, installable_attr: []const u8) !std.ArrayList([]const u8) {
	const installable = try std.fmt.allocPrint(allocator, "path:{s}#nixosConfigurations.cogbox-{s}{s}.{s}", .{ b.flake_source, b.arch, config_suffix, installable_attr });
	errdefer allocator.free(installable);
	const plugins_input = try std.fmt.allocPrint(allocator, "path:{s}", .{b.plugins_flake_dir});
	errdefer allocator.free(plugins_input);
	const nixpkgs_input = try std.fmt.allocPrint(allocator, "path:{s}", .{b.nixpkgs_source});
	errdefer allocator.free(nixpkgs_input);

	var argv: std.ArrayList([]const u8) = .empty;
	errdefer argv.deinit(allocator);
	try argv.appendSlice(allocator, &.{
		"build",
		installable,
		"--override-input",
		"userExtensions",
		plugins_input,
		"--override-input",
		"userExtensions/user/nixpkgs",
		nixpkgs_input,
		"--no-link",
		"--print-out-paths",
	});
	if (b.substituters.len > 0) {
		try argv.appendSlice(allocator, &.{ "--option", "extra-substituters", b.substituters, "--option", "require-sigs", "false" });
	}
	if (b.trusted_public_keys.len > 0) {
		try argv.appendSlice(allocator, &.{ "--option", "extra-trusted-public-keys", b.trusted_public_keys });
	}
	if (b.netrc_file.len > 0) {
		try argv.appendSlice(allocator, &.{ "--option", "netrc-file", b.netrc_file });
	}
	if (b.base_store_root.len > 0) {
		// the base-store substitution: the base substituter in b.substituters
		// is a FROZEN (chmod a-w) chroot store; nix only reads it as a store under this
		// feature. Additive on top of runNix's "nix-command flakes".
		try argv.appendSlice(allocator, &.{ "--extra-experimental-features", "read-only-local-store" });
	}
	return argv;
}

/// Free the three interpolated installable/input strings runnerBuildArgv owns
/// (the path:... installable at index 1 and the two path: inputs at 4 and 7),
/// then the list itself. The literal flags are static and must not be freed.
fn argvDeinit(allocator: std.mem.Allocator, argv: *std.ArrayList([]const u8)) void {
	allocator.free(argv.items[1]);
	allocator.free(argv.items[4]);
	allocator.free(argv.items[7]);
	argv.deinit(allocator);
}

/// Build the microvm runner the boot path would build -- the SAME flake ref +
/// the SAME --override-input set as cogbox-launch.sh's re-exec -- so the
/// resulting out-path is byte-identical to the one boot looks for, then return
/// it (`--print-out-paths`, `--no-link`). The worker pod pushes this closure to
/// a binary cache so boot substitutes it instead of rebuilding from source.
/// Determinism: nothing instance-specific is baked into the closure (hostname,
/// ports, keys are launch-time sed rewrites on the OUTPUT), so every worker for
/// the same (cogbox-rev, plugin-set) builds the identical path.
pub fn buildRunner(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, b: RunnerBuild) !RunOut {
	var argv = try runnerBuildArgv(allocator, b);
	defer argvDeinit(allocator, &argv);
	return runNix(allocator, io, env, argv.items);
}

/// Build the container's per-instance cogbox-brain (the same out-path boot
/// evaluates). Realizes cfg.packages' closure via the passed substituters so a
/// later copyClosureTo can seed the offline plugin-cache. Container backend only.
pub fn buildBrain(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, b: RunnerBuild) !RunOut {
	var argv = try brainBuildArgv(allocator, b);
	defer argvDeinit(allocator, &argv);
	return runNix(allocator, io, env, argv.items);
}

/// Build the container's per-instance FULL toplevel (the same out-path agentInit realises
/// and boots as PID1). Realizes the plugin's whole-module closure via the passed
/// substituters so a later copyClosureTo can seed the offline plugin-cache. Container only.
pub fn buildToplevel(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, b: RunnerBuild) !RunOut {
	var argv = try toplevelBuildArgv(allocator, b);
	defer argvDeinit(allocator, &argv);
	return runNix(allocator, io, env, argv.items);
}

/// `nix copy --to <dest> <store_path>`: copy a realized store path AND its
/// runtime closure into the `dest` binary cache (a `file://<dir>` URI). Used to
/// seed the per-instance plugin-cache with the pre-built cogbox-brain closure so
/// the container's egress-less boot substitutes it (require-sigs false on the
/// read side) instead of rebuilding. Unlike flakeArchiveTo (which archives a
/// flake + its source inputs), this copies a BUILT output, unreachable from the
/// composition flake.
pub fn copyClosureTo(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, dest: []const u8, store_path: []const u8) !RunOut {
	return runNix(allocator, io, env, &.{ "copy", "--to", dest, store_path });
}

/// `nix path-info --json --all` against the node CoW base store (the delta-only copy): enumerate every base store path in the lower
/// (`local?root=<root>`, frozen -> read-only-local-store) with its narHash/narSize/
/// references, so the caller can write narinfo STUBS into the per-instance plugin-cache
/// and make the subsequent `nix copy <toplevel>` skip the ~2.3 GB base (the boot reads
/// the base from its own CoW lower, never from the cache -- so the stubs' dangling NAR
/// URLs are harmless). NO NARs are read here (metadata comes from the lower's nix DB
/// that the base-closure seed load-db'd), so it costs a DB query, not GBs of I/O.
pub fn basePathInfoJson(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, root: []const u8) !RunOut {
	const store = try std.fmt.allocPrint(allocator, "local?root={s}&read-only=true", .{root});
	defer allocator.free(store);
	// read-only-local-store accumulates on top of runNix's "nix-command flakes".
	return runNix(allocator, io, env, &.{ "path-info", "--json", "--all", "--store", store, "--extra-experimental-features", "read-only-local-store" });
}

/// Outcome of the cogboxPlugins.<attr> contract check. `missing` is the
/// contract violation ("this flake is not a cogbox plugin"); `failed` is
/// everything else that can go wrong with the eval (fetch error, eval error
/// inside the flake) and carries nix's stderr (caller owns it). Conflating
/// the two would misreport any broken URL as a missing plugin.
pub const ModuleCheck = union(enum) {
	present,
	missing,
	failed: []u8,
};

/// `nix eval URL#cogboxPlugins --apply 'm: m ? "<attr>"' --json`. The plugin
/// contract is the cogboxPlugins.<attr> REGISTRATION (which carries the
/// optional `module` reference plus host-side networkRules/l7Rules/inject); a
/// flake without it is not a cogbox plugin. `attr` must satisfy
/// name.isValidAttr (it is interpolated into a nix expression).
pub fn evalHasCogboxPlugin(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, url: []const u8, attr: []const u8) !ModuleCheck {
	const installable = try std.fmt.allocPrint(allocator, "{s}#cogboxPlugins", .{url});
	defer allocator.free(installable);
	const apply = try std.fmt.allocPrint(allocator, "m: m ? \"{s}\"", .{attr});
	defer allocator.free(apply);
	var out = try runNix(allocator, io, env, &.{ "eval", installable, "--apply", apply, "--json" });
	defer out.deinit(allocator);
	return switch (classifyModuleCheck(out.ok, out.stdout, out.stderr)) {
		.present => .present,
		.missing => .missing,
		.failed => .{ .failed = try allocator.dupe(u8, out.stderr) },
	};
}

/// Pure classification of the eval result: a clean "true" is present, a clean
/// "false" or a "flake does not provide attribute ... 'cogboxPlugins'" error is
/// missing, any other failure is real and must be surfaced. The missing-attr
/// match is deliberately narrower than stderrSaysMissingAttribute: it requires
/// nix's flake-output phrase naming 'cogboxPlugins', so a plugin flake whose
/// own eval error happens to contain "has no attribute" cannot smuggle a real
/// failure back into the misleading contract message.
pub fn classifyModuleCheck(ok: bool, stdout: []const u8, stderr: []const u8) std.meta.Tag(ModuleCheck) {
	if (ok) {
		const is_true = std.mem.eql(u8, std.mem.trim(u8, stdout, " \t\r\n"), "true");
		return if (is_true) .present else .missing;
	}
	const no_output = std.mem.indexOf(u8, stderr, "does not provide attribute") != null and
		std.mem.indexOf(u8, stderr, "'cogboxPlugins'") != null;
	return if (no_output) .missing else .failed;
}

/// `nix eval URL#cogboxPlugins."<attr>".<leaf> --json` (or the flat path
/// `cogboxPlugins.<leaf>` when `attr` is null). `leaf` is `networkRules`
/// (L4 CIDR rules), `l7Rules` (vhost rules), or `inject` (cred specs). IFD is
/// blocked: reading the host-side policy must never trigger a build of
/// untrusted code at add time. `attr` must satisfy name.isValidAttr; `leaf` is
/// always caller-controlled. (The kit -- cogbox.* in the module -- is NOT read
/// here; it rides the module import at build, not the cheap add-time eval.)
pub fn evalPluginRules(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, url: []const u8, attr: ?[]const u8, leaf: []const u8) !RunOut {
	const installable = if (attr) |a|
		try std.fmt.allocPrint(allocator, "{s}#cogboxPlugins.\"{s}\".{s}", .{ url, a, leaf })
	else
		try std.fmt.allocPrint(allocator, "{s}#cogboxPlugins.{s}", .{ url, leaf });
	defer allocator.free(installable);
	return runNix(allocator, io, env, &.{ "eval", installable, "--json", "--no-allow-import-from-derivation" });
}

/// Whether a failed eval's stderr means "that attribute just isn't there"
/// (fine: the output is optional) as opposed to a real evaluation error.
pub fn stderrSaysMissingAttribute(stderr: []const u8) bool {
	return std.mem.indexOf(u8, stderr, "does not provide attribute") != null or
		std.mem.indexOf(u8, stderr, "has no attribute") != null or
		std.mem.indexOf(u8, stderr, "missing attribute") != null;
}

pub const Meta = struct {
	locked_url: []const u8,
	rev: ?[]const u8,
	nar_hash: []const u8,
	// The locked flake's source store path (`.path` of `nix flake metadata
	// --json`): the read-only /nix/store/... directory holding the plugin's
	// source. Empty ("") when the metadata didn't carry it (older nix) or when
	// the Meta was built WITHOUT a metadata call (the sibling-reuse path in
	// cmdAdd) -- callers that need it fall back to `flakeSourcePath`. It backs
	// the path: rewrite that makes launch resolve offline.
	source_path: []const u8,

	pub fn deinit(self: *Meta, allocator: std.mem.Allocator) void {
		allocator.free(self.locked_url);
		if (self.rev) |r| allocator.free(r);
		allocator.free(self.nar_hash);
		allocator.free(self.source_path);
	}
};

pub const MetaError = error{
	BadMetadata,
	OutOfMemory,
};

/// Whether nix's git or hg fetcher serves this locked URL. Covers the
/// `git+`/`hg+` transport spellings and the bare legacy `git://` protocol
/// (which nix accepts and locks WITHOUT a `git+` prefix). These fetchers
/// pass unrecognized query params through to the remote.
pub fn isGitOrHgUrl(url: []const u8) bool {
	return std.mem.startsWith(u8, url, "git+") or
		std.mem.startsWith(u8, url, "hg+") or
		std.mem.startsWith(u8, url, "git://");
}

/// Extract the `dir` query-param value from a flake URL (the subdir the flake
/// lives in, e.g. `?dir=flake`), or null if absent/empty. Only the `?...`
/// query is scanned, so a literal `dir=` in the path can't false-match.
/// Returns a slice into `url`. `nix flake metadata`'s `.path` is the repo ROOT
/// for a `?dir=` flake (the flake.nix is at <path>/<dir>), so a path: rewrite
/// of the materialized source must carry the same `?dir=` to find the flake.
pub fn dirParam(url: []const u8) ?[]const u8 {
	const q = std.mem.indexOfScalar(u8, url, '?') orelse return null;
	var it = std.mem.splitScalar(u8, url[q + 1 ..], '&');
	while (it.next()) |param| {
		if (std.mem.startsWith(u8, param, "dir=")) {
			const v = param["dir=".len..];
			return if (v.len == 0) null else v;
		}
	}
	return null;
}

/// Parse `nix flake metadata --json` output. `.url` is nix's locked URL.
/// For github:/path:/tarball refs that don't already carry a narHash query
/// param, `.locked.narHash` is appended (percent-encoded) so the URL alone
/// pins the content and resolves from the local store offline. git/hg refs
/// never get the param (their fetchers would hand it to the remote); they
/// are pinned by rev alone and resolve offline via the fetcher cache.
pub fn parseMetadata(allocator: std.mem.Allocator, json_text: []const u8) MetaError!Meta {
	const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch {
		return error.BadMetadata;
	};
	defer parsed.deinit();

	const root = parsed.value;
	if (root != .object) return error.BadMetadata;
	const url_v = root.object.get("url") orelse return error.BadMetadata;
	if (url_v != .string) return error.BadMetadata;
	const locked_v = root.object.get("locked") orelse return error.BadMetadata;
	if (locked_v != .object) return error.BadMetadata;
	const nar_v = locked_v.object.get("narHash") orelse return error.BadMetadata;
	if (nar_v != .string) return error.BadMetadata;

	var rev: ?[]const u8 = null;
	errdefer if (rev) |r| allocator.free(r);
	if (locked_v.object.get("rev")) |rv| {
		if (rv == .string) rev = try allocator.dupe(u8, rv.string);
	}

	const nar_hash = try allocator.dupe(u8, nar_v.string);
	errdefer allocator.free(nar_hash);

	// `.path` is the locked flake's source store path; absent on older nix,
	// so default to "" (callers fall back to flakeSourcePath).
	const source_path = blk: {
		if (root.object.get("path")) |pv| {
			if (pv == .string) break :blk try allocator.dupe(u8, pv.string);
		}
		break :blk try allocator.dupe(u8, "");
	};
	errdefer allocator.free(source_path);

	const locked_url = blk: {
		if (std.mem.indexOf(u8, url_v.string, "narHash=") != null) {
			break :blk try allocator.dupe(u8, url_v.string);
		}
		// git/hg locked URLs must NOT grow a narHash param: nix's git and hg
		// fetchers consume only their own query params (ref, rev, shallow,
		// ...) and pass everything else through to the remote, so the forge
		// would be asked for a repo literally named "...?narHash=..." and
		// refuse. The rev pins those URLs (clean trees; the caller warns on
		// rev-less dirty-tree locks); offline starts come from the fetcher
		// cache that `nix flake archive` populates.
		if (isGitOrHgUrl(url_v.string)) {
			break :blk try allocator.dupe(u8, url_v.string);
		}
		const sep: u8 = if (std.mem.indexOfScalar(u8, url_v.string, '?') != null) '&' else '?';
		var buf: std.ArrayList(u8) = .empty;
		defer buf.deinit(allocator);
		try buf.appendSlice(allocator, url_v.string);
		try buf.append(allocator, sep);
		try buf.appendSlice(allocator, "narHash=");
		try appendPercentEncoded(allocator, &buf, nar_v.string);
		break :blk try buf.toOwnedSlice(allocator);
	};

	return .{ .locked_url = locked_url, .rev = rev, .nar_hash = nar_hash, .source_path = source_path };
}

/// Resolve a flake URL to its source store path (`.path` of `nix flake
/// metadata --json`), for callers that hold a URL whose Meta lacked a
/// source_path (the sibling-reuse path in cmdAdd builds Meta WITHOUT a
/// metadata call). Returns an allocated path the caller frees, or "" when nix
/// fails or the field is absent (best-effort; the composition then falls back
/// to the git URL). Authenticated via `env` like every other fetch.
pub fn flakeSourcePath(allocator: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, url: []const u8) ![]u8 {
	var out = try flakeMetadata(allocator, io, env, url, false);
	defer out.deinit(allocator);
	if (!out.ok) return try allocator.dupe(u8, "");

	const parsed = std.json.parseFromSlice(std.json.Value, allocator, out.stdout, .{}) catch {
		return try allocator.dupe(u8, "");
	};
	defer parsed.deinit();
	if (parsed.value != .object) return try allocator.dupe(u8, "");
	if (parsed.value.object.get("path")) |pv| {
		if (pv == .string) return try allocator.dupe(u8, pv.string);
	}
	return try allocator.dupe(u8, "");
}

/// Percent-encode a query param value (narHash carries `+`, `/`, `=`).
fn appendPercentEncoded(allocator: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
	for (s) |c| {
		const safe = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
		if (safe) {
			try out.append(allocator, c);
		} else {
			var hex: [3]u8 = undefined;
			_ = std.fmt.bufPrint(&hex, "%{X:0>2}", .{c}) catch unreachable;
			try out.appendSlice(allocator, &hex);
		}
	}
}

/// The trailing lines of nix's stderr, for error messages. Drops the
/// progress noise but keeps the actual failure.
pub fn stderrTail(stderr: []const u8) []const u8 {
	const trimmed = std.mem.trim(u8, stderr, " \t\r\n");
	const max = 600;
	if (trimmed.len <= max) return trimmed;
	const cut = trimmed[trimmed.len - max ..];
	// Start at the next line boundary so we don't emit half a line.
	if (std.mem.indexOfScalar(u8, cut, '\n')) |i| return cut[i + 1 ..];
	return cut;
}

// --- Tests (private runnerBuildArgv is in scope here) ---

const t = std.testing;

/// Per-element string comparison: expectEqualSlices compares pointers for a
/// []const u8 element, so it can't check argv content. This checks length then
/// each string's bytes.
fn expectArgv(expected: []const []const u8, actual: []const []const u8) !void {
	try t.expectEqual(expected.len, actual.len);
	for (expected, actual) |e, a| try t.expectEqualStrings(e, a);
}

// The load-bearing invariant: the runner build invocation must use the SAME
// installable + the SAME --override-input set as cogbox-launch.sh's re-exec, so
// the worker-built out-path is byte-identical to the one boot substitutes. With
// no substituter/key/netrc knobs set, NO extra --option args are emitted.
test "runnerBuildArgv: matches the boot-path flake ref + override-inputs, no knobs" {
	var argv = try runnerBuildArgv(t.allocator, .{
		.flake_source = "/nix/store/abc-cogbox-source",
		.nixpkgs_source = "/nix/store/def-nixpkgs",
		.plugins_flake_dir = "/var/lib/cogbox/inst/plugins-flake",
		.arch = "x86_64",
		.substituters = "",
		.trusted_public_keys = "",
		.netrc_file = "",
	});
	defer argvDeinit(t.allocator, &argv);

	try expectArgv(&.{
		"build",
		"path:/nix/store/abc-cogbox-source#nixosConfigurations.cogbox-x86_64.config.microvm.declaredRunner",
		"--override-input",
		"userExtensions",
		"path:/var/lib/cogbox/inst/plugins-flake",
		"--override-input",
		"userExtensions/user/nixpkgs",
		"path:/nix/store/def-nixpkgs",
		"--no-link",
		"--print-out-paths",
	}, argv.items);
}

// The arch suffix flows straight into the config name (cogbox-aarch64), and
// every configured knob appends its --option in order: extra-substituters (with
// require-sigs false), extra-trusted-public-keys, then netrc-file.
test "runnerBuildArgv: aarch64 config name + all substituter knobs appended" {
	var argv = try runnerBuildArgv(t.allocator, .{
		.flake_source = "/src",
		.nixpkgs_source = "/np",
		.plugins_flake_dir = "/pf",
		.arch = "aarch64",
		.substituters = "file:///cache https://cache.example.com",
		.trusted_public_keys = "cache.example.com-1:KEY=",
		.netrc_file = "/run/secrets/netrc",
	});
	defer argvDeinit(t.allocator, &argv);

	try t.expectEqualStrings("path:/src#nixosConfigurations.cogbox-aarch64.config.microvm.declaredRunner", argv.items[1]);
	try expectArgv(&.{
		"--option", "extra-substituters",       "file:///cache https://cache.example.com",
		"--option", "require-sigs",              "false",
		"--option", "extra-trusted-public-keys", "cache.example.com-1:KEY=",
		"--option", "netrc-file",                "/run/secrets/netrc",
	}, argv.items[10..]);
}

// A configured substituter but no keys/netrc emits exactly the substituter
// option pair -- no stray trusted-keys or netrc options.
test "runnerBuildArgv: substituters only, no keys/netrc" {
	var argv = try runnerBuildArgv(t.allocator, .{
		.flake_source = "/src",
		.nixpkgs_source = "/np",
		.plugins_flake_dir = "/pf",
		.arch = "x86_64",
		.substituters = "file:///cache",
		.trusted_public_keys = "",
		.netrc_file = "",
	});
	defer argvDeinit(t.allocator, &argv);

	try expectArgv(&.{
		"--option", "extra-substituters", "file:///cache", "--option", "require-sigs", "false",
	}, argv.items[10..]);
}

// The container brain build must target the `-container` config (never the VM
// config, whose eval force-fetches the microvm input source -- the cold-node
// seed failure) with the SAME --override-input set as flake.nix's
// brainResolveContainer: the pre-built out-path only substitutes at boot if
// installable + override set exactly match what boot evaluates. Lock both.
test "brainBuildArgv: cogboxBrain installable + boot-path override-inputs" {
	var argv = try brainBuildArgv(t.allocator, .{
		.flake_source = "/nix/store/abc-cogbox-source",
		.nixpkgs_source = "/nix/store/def-nixpkgs",
		.plugins_flake_dir = "/var/lib/cogbox/inst/plugins-flake",
		.arch = "x86_64",
		.substituters = "",
		.trusted_public_keys = "",
		.netrc_file = "",
	});
	defer argvDeinit(t.allocator, &argv);

	try expectArgv(&.{
		"build",
		"path:/nix/store/abc-cogbox-source#nixosConfigurations.cogbox-x86_64-container.config.system.build.cogboxBrain",
		"--override-input",
		"userExtensions",
		"path:/var/lib/cogbox/inst/plugins-flake",
		"--override-input",
		"userExtensions/user/nixpkgs",
		"path:/nix/store/def-nixpkgs",
		"--no-link",
		"--print-out-paths",
	}, argv.items);
}

// The brain build takes the same substituter/key/netrc knobs as the runner (the
// container seeds file://<cache> so the plugin-tool closure substitutes rather
// than builds from source at add time).
test "brainBuildArgv: aarch64 config name + substituter knobs appended" {
	var argv = try brainBuildArgv(t.allocator, .{
		.flake_source = "/src",
		.nixpkgs_source = "/np",
		.plugins_flake_dir = "/pf",
		.arch = "aarch64",
		.substituters = "file:///cache https://cache.example.com",
		.trusted_public_keys = "",
		.netrc_file = "",
	});
	defer argvDeinit(t.allocator, &argv);

	try t.expectEqualStrings("path:/src#nixosConfigurations.cogbox-aarch64-container.config.system.build.cogboxBrain", argv.items[1]);
	try expectArgv(&.{
		"--option", "extra-substituters", "file:///cache https://cache.example.com", "--option", "require-sigs", "false",
	}, argv.items[10..]);
}

// The full-toplevel build must be byte-identical to the brain/runner builds EXCEPT the
// installable leaf (config.system.build.toplevel): the pre-built out-path only realises +
// boots (agentInit) if the installable + --override-input set exactly match what boot would
// derive. Lock both.
test "toplevelBuildArgv: toplevel installable + boot-path override-inputs" {
	var argv = try toplevelBuildArgv(t.allocator, .{
		.flake_source = "/nix/store/abc-cogbox-source",
		.nixpkgs_source = "/nix/store/def-nixpkgs",
		.plugins_flake_dir = "/var/lib/cogbox/inst/plugins-flake",
		.arch = "x86_64",
		.substituters = "",
		.trusted_public_keys = "",
		.netrc_file = "",
	});
	defer argvDeinit(t.allocator, &argv);

	try expectArgv(&.{
		"build",
		"path:/nix/store/abc-cogbox-source#nixosConfigurations.cogbox-x86_64-container.config.system.build.toplevel",
		"--override-input",
		"userExtensions",
		"path:/var/lib/cogbox/inst/plugins-flake",
		"--override-input",
		"userExtensions/user/nixpkgs",
		"path:/nix/store/def-nixpkgs",
		"--no-link",
		"--print-out-paths",
		"--max-jobs",
		"1",
		"--max-substitution-jobs",
		"4",
	}, argv.items);
}

// build_jobs (COGBOX_WORKER_BUILD_JOBS, set by cogworx only on a beefed-up worker pod)
// overrides the hardcoded -j1 for the toplevel build; --max-substitution-jobs stays 4.
// The rest of the argv is unchanged from the default case above.
test "toplevelBuildArgv: build_jobs overrides the hardcoded max-jobs" {
	var argv = try toplevelBuildArgv(t.allocator, .{
		.flake_source = "/nix/store/abc-cogbox-source",
		.nixpkgs_source = "/nix/store/def-nixpkgs",
		.plugins_flake_dir = "/var/lib/cogbox/inst/plugins-flake",
		.arch = "x86_64",
		.substituters = "",
		.trusted_public_keys = "",
		.netrc_file = "",
		.build_jobs = "6",
	});
	defer argvDeinit(t.allocator, &argv);

	try expectArgv(&.{
		"build",
		"path:/nix/store/abc-cogbox-source#nixosConfigurations.cogbox-x86_64-container.config.system.build.toplevel",
		"--override-input",
		"userExtensions",
		"path:/var/lib/cogbox/inst/plugins-flake",
		"--override-input",
		"userExtensions/user/nixpkgs",
		"path:/nix/store/def-nixpkgs",
		"--no-link",
		"--print-out-paths",
		"--max-jobs",
		"6",
		"--max-substitution-jobs",
		"4",
	}, argv.items);
}

// the base-store substitution: when a node-shared CoW base store is
// prepended to the substituters, base_store_root is set, and buildArgvFor appends
// `--extra-experimental-features read-only-local-store` (additive on top of runNix's
// "nix-command flakes") so nix accepts the FROZEN (chmod a-w) chroot store as a
// substituter. It lands AFTER the substituter option pair.
test "buildArgvFor: base_store_root appends read-only-local-store" {
	var argv = try brainBuildArgv(t.allocator, .{
		.flake_source = "/src",
		.nixpkgs_source = "/np",
		.plugins_flake_dir = "/pf",
		.arch = "x86_64",
		.substituters = "local?root=/cogbox-basestore&read-only=true file:///cache",
		.trusted_public_keys = "",
		.netrc_file = "",
		.base_store_root = "/cogbox-basestore",
	});
	defer argvDeinit(t.allocator, &argv);

	try expectArgv(&.{
		"--option",
		"extra-substituters",
		"local?root=/cogbox-basestore&read-only=true file:///cache",
		"--option",
		"require-sigs",
		"false",
		"--extra-experimental-features",
		"read-only-local-store",
	}, argv.items[10..]);
}

// The default (unset) base_store_root emits NO read-only-local-store flag, so a
// build without a mounted lower is byte-for-byte today's argv.
test "buildArgvFor: no base_store_root emits no read-only-local-store" {
	var argv = try brainBuildArgv(t.allocator, .{
		.flake_source = "/src",
		.nixpkgs_source = "/np",
		.plugins_flake_dir = "/pf",
		.arch = "x86_64",
		.substituters = "file:///cache",
		.trusted_public_keys = "",
		.netrc_file = "",
	});
	defer argvDeinit(t.allocator, &argv);

	for (argv.items) |a| try t.expect(!std.mem.eql(u8, a, "read-only-local-store"));
}
