const std = @import("std");

pub fn build(b: *std.Build) void {
	const target = b.standardTargetOptions(.{});
	const optimize = b.standardOptimizeOption(.{});

	const filter_mod = b.createModule(.{
		.root_source_file = b.path("src/filter.zig"),
		.target = target,
		.optimize = optimize,
	});

	const socks5_mod = b.createModule(.{
		.root_source_file = b.path("src/socks5/main.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	socks5_mod.addImport("filter", filter_mod);

	const lib_mod = b.createModule(.{
		.root_source_file = b.path("src/netfilter/main.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	lib_mod.addImport("filter", filter_mod);
	lib_mod.addImport("socks5", socks5_mod);

	// Host-side L7 proxy (cogbox __l7proxy). Reuses the filter rule engine;
	// links libc for getaddrinfo + the socket layer.
	const l7proxy_mod = b.createModule(.{
		.root_source_file = b.path("src/l7proxy/main.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	l7proxy_mod.addImport("filter", filter_mod);

	// Per-sandbox auth proxy (cogbox __authproxy). Reuses filter for the port
	// band; links libc for the socket layer (same reason as l7proxy_mod).
	const authproxy_mod = b.createModule(.{
		.root_source_file = b.path("src/authproxy/main.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	authproxy_mod.addImport("filter", filter_mod);

	// Divert shim (cogbox __divertshim). The separate-pod enforcer's in-pod
	// REDIRECT shim: recovers SO_ORIGINAL_DST, then SOCKS5-CONNECTs the dst to the
	// enforcer. Reuses the filter types + the socks5 client; links libc.
	const divertshim_mod = b.createModule(.{
		.root_source_file = b.path("src/divertshim/main.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	divertshim_mod.addImport("filter", filter_mod);
	divertshim_mod.addImport("socks5", socks5_mod);

	const lib = b.addLibrary(.{
		.name = "netfilter",
		.linkage = .dynamic,
		.root_module = lib_mod,
	});
	b.installArtifact(lib);

	// Rules module: previously the standalone cogbox-rules binary; now
	// imported by the unified cogbox CLI as the `rules` verb.
	const rules_mod = b.createModule(.{
		.root_source_file = b.path("src/rules/main.zig"),
		.target = target,
		.optimize = optimize,
	});
	rules_mod.addImport("filter", filter_mod);

	// Remap verb. Shares config/save/reload with the rules module so
	// edits to either table re-render the full runtime rules file.
	const remap_mod = b.createModule(.{
		.root_source_file = b.path("src/remap/main.zig"),
		.target = target,
		.optimize = optimize,
	});
	remap_mod.addImport("filter", filter_mod);
	remap_mod.addImport("rules_module", rules_mod);

	// L7 verb. Like remap, shares config/save/reload with the rules module
	// so an edit re-renders the funnel rules + the proxy's l7-rules file.
	const l7_mod = b.createModule(.{
		.root_source_file = b.path("src/l7/main.zig"),
		.target = target,
		.optimize = optimize,
	});
	l7_mod.addImport("filter", filter_mod);
	l7_mod.addImport("rules_module", rules_mod);

	// Secret verb + store. Host-only named credential store the operator binds
	// with `cogbox secret`; the rules renderer resolves a plugin's requested
	// secret through it. Pure std (no libc, no other cogbox modules), so it can
	// be imported by both the CLI and the rules module without a cycle.
	const secret_mod = b.createModule(.{
		.root_source_file = b.path("src/secret/main.zig"),
		.target = target,
		.optimize = optimize,
	});
	// The rules renderer (renderL7Inject) resolves bound secrets host-side.
	rules_mod.addImport("secret_module", secret_mod);

	// Plugin verb. Shares config/save/reload with the rules module (plugin
	// rule merges hot-reload like any other rules edit) and shells out to
	// nix for flake resolution; links libc for the process plumbing.
	const plugin_mod = b.createModule(.{
		.root_source_file = b.path("src/plugin/main.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	plugin_mod.addImport("rules_module", rules_mod);
	plugin_mod.addImport("l7_module", l7_mod);
	plugin_mod.addImport("secret_module", secret_mod);

	// Top-level cogbox CLI.
	const cli_mod = b.createModule(.{
		.root_source_file = b.path("src/cli/main.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	cli_mod.addImport("rules_module", rules_mod);
	cli_mod.addImport("remap_module", remap_mod);
	cli_mod.addImport("l7_module", l7_mod);
	cli_mod.addImport("plugin_module", plugin_mod);
	cli_mod.addImport("secret_module", secret_mod);
	cli_mod.addImport("l7proxy_module", l7proxy_mod);
	cli_mod.addImport("authproxy_module", authproxy_mod);
	cli_mod.addImport("divertshim_module", divertshim_mod);
	cli_mod.addImport("filter", filter_mod);

	const cogbox_exe = b.addExecutable(.{
		.name = "cogbox",
		.root_module = cli_mod,
	});
	b.installArtifact(cogbox_exe);

	const filter_tests = b.addTest(.{
		.root_module = filter_mod,
	});
	const run_filter_tests = b.addRunArtifact(filter_tests);

	const socks5_tests = b.addTest(.{
		.root_module = socks5_mod,
	});
	const run_socks5_tests = b.addRunArtifact(socks5_tests);

	const l7proxy_test_mod = b.createModule(.{
		.root_source_file = b.path("src/l7proxy/tests.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	l7proxy_test_mod.addImport("filter", filter_mod);
	// reload_test.zig hammers the RENDERER's truncate-in-place writer against this
	// proxy's polled reader -- the torn-read contract on netfilter-rules only
	// exists between the two, so the test needs both halves. Test module only.
	l7proxy_test_mod.addImport("rules_module", rules_mod);
	const l7proxy_tests = b.addTest(.{
		.root_module = l7proxy_test_mod,
	});
	const run_l7proxy_tests = b.addRunArtifact(l7proxy_tests);

	const divertshim_test_mod = b.createModule(.{
		.root_source_file = b.path("src/divertshim/tests.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	divertshim_test_mod.addImport("filter", filter_mod);
	divertshim_test_mod.addImport("socks5", socks5_mod);
	const divertshim_tests = b.addTest(.{
		.root_module = divertshim_test_mod,
	});
	const run_divertshim_tests = b.addRunArtifact(divertshim_tests);

	const authproxy_test_mod = b.createModule(.{
		.root_source_file = b.path("src/authproxy/tests.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	authproxy_test_mod.addImport("filter", filter_mod);
	const authproxy_tests = b.addTest(.{
		.root_module = authproxy_test_mod,
	});
	const run_authproxy_tests = b.addRunArtifact(authproxy_tests);

	const rules_test_mod = b.createModule(.{
		.root_source_file = b.path("src/rules/tests.zig"),
		.target = target,
		.optimize = optimize,
	});
	rules_test_mod.addImport("filter", filter_mod);
	rules_test_mod.addImport("secret_module", secret_mod);
	const rules_tests = b.addTest(.{
		.root_module = rules_test_mod,
	});
	const run_rules_tests = b.addRunArtifact(rules_tests);

	const remap_test_mod = b.createModule(.{
		.root_source_file = b.path("src/remap/tests.zig"),
		.target = target,
		.optimize = optimize,
	});
	remap_test_mod.addImport("filter", filter_mod);
	const remap_tests = b.addTest(.{
		.root_module = remap_test_mod,
	});
	const run_remap_tests = b.addRunArtifact(remap_tests);

	const l7_test_mod = b.createModule(.{
		.root_source_file = b.path("src/l7/tests.zig"),
		.target = target,
		.optimize = optimize,
	});
	l7_test_mod.addImport("filter", filter_mod);
	// Mirrors l7_mod: cli.zig reaches the rules module for reload.injectUnionCount
	// (the rendered-line delta the replace cap budgets for).
	l7_test_mod.addImport("rules_module", rules_mod);
	const l7_tests = b.addTest(.{
		.root_module = l7_test_mod,
	});
	const run_l7_tests = b.addRunArtifact(l7_tests);

	const plugin_test_mod = b.createModule(.{
		.root_source_file = b.path("src/plugin/tests.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	plugin_test_mod.addImport("rules_module", rules_mod);
	plugin_test_mod.addImport("l7_module", l7_mod);
	plugin_test_mod.addImport("secret_module", secret_mod);
	const plugin_tests = b.addTest(.{
		.root_module = plugin_test_mod,
	});
	const run_plugin_tests = b.addRunArtifact(plugin_tests);

	const secret_test_mod = b.createModule(.{
		.root_source_file = b.path("src/secret/tests.zig"),
		.target = target,
		.optimize = optimize,
	});
	const secret_tests = b.addTest(.{
		.root_module = secret_test_mod,
	});
	const run_secret_tests = b.addRunArtifact(secret_tests);

	const cli_test_mod = b.createModule(.{
		.root_source_file = b.path("src/cli/parse.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	const cli_tests = b.addTest(.{
		.root_module = cli_test_mod,
	});
	const run_cli_tests = b.addRunArtifact(cli_tests);

	// Verb tests. Rooted at src/cli/tests.zig (the cli module root) so verb
	// files that import ../util.zig etc. resolve; links libc for the libc
	// externs (execvp, isatty) the ssh verb uses.
	const cli_verbs_test_mod = b.createModule(.{
		.root_source_file = b.path("src/cli/tests.zig"),
		.target = target,
		.optimize = optimize,
		.link_libc = true,
	});
	// The __claude-stub verb stages the shared stub credential, single-sourced from
	// the secret module's claude_stub_token, so its tests need that import too.
	cli_verbs_test_mod.addImport("secret_module", secret_mod);
	// The `secret` verb re-renders + signals through the rules module (its live
	// hot-reload path), so its tests need that import as well.
	cli_verbs_test_mod.addImport("rules_module", rules_mod);
	const cli_verbs_tests = b.addTest(.{
		.root_module = cli_verbs_test_mod,
	});
	const run_cli_verbs_tests = b.addRunArtifact(cli_verbs_tests);

	const test_step = b.step("test", "Run unit tests");
	test_step.dependOn(&run_filter_tests.step);
	test_step.dependOn(&run_socks5_tests.step);
	test_step.dependOn(&run_l7proxy_tests.step);
	test_step.dependOn(&run_divertshim_tests.step);
	test_step.dependOn(&run_authproxy_tests.step);
	test_step.dependOn(&run_rules_tests.step);
	test_step.dependOn(&run_remap_tests.step);
	test_step.dependOn(&run_l7_tests.step);
	test_step.dependOn(&run_plugin_tests.step);
	test_step.dependOn(&run_secret_tests.step);
	test_step.dependOn(&run_cli_tests.step);
	test_step.dependOn(&run_cli_verbs_tests.step);
}
