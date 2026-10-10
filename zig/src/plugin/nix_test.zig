const std = @import("std");
const nix = @import("nix.zig");
const t = std.testing;

// Captured (abridged) `nix flake metadata --json` outputs.

test "parseMetadata: github ref appends percent-encoded narHash" {
	const json =
		\\{"description":"x","lastModified":1700000000,
		\\ "locked":{"lastModified":1700000000,"narHash":"sha256-AB+cd/ef=","owner":"o","repo":"r","rev":"0123abcd0123abcd0123abcd0123abcd0123abcd","type":"github"},
		\\ "original":{"owner":"o","repo":"r","type":"github"},
		\\ "url":"github:o/r/0123abcd0123abcd0123abcd0123abcd0123abcd"}
	;
	var m = try nix.parseMetadata(t.allocator, json);
	defer m.deinit(t.allocator);
	try t.expectEqualStrings("github:o/r/0123abcd0123abcd0123abcd0123abcd0123abcd?narHash=sha256-AB%2Bcd%2Fef%3D", m.locked_url);
	try t.expectEqualStrings("0123abcd0123abcd0123abcd0123abcd0123abcd", m.rev.?);
	try t.expectEqualStrings("sha256-AB+cd/ef=", m.nar_hash);
}

test "parseMetadata: path flake already carries narHash, no rev" {
	const json =
		\\{"locked":{"lastModified":1700000001,"narHash":"sha256-zzz=","path":"/home/u/plug","type":"path"},
		\\ "original":{"path":"/home/u/plug","type":"path"},
		\\ "url":"path:/home/u/plug?lastModified=1700000001&narHash=sha256-zzz%3D"}
	;
	var m = try nix.parseMetadata(t.allocator, json);
	defer m.deinit(t.allocator);
	try t.expectEqualStrings("path:/home/u/plug?lastModified=1700000001&narHash=sha256-zzz%3D", m.locked_url);
	try t.expect(m.rev == null);
	try t.expectEqualStrings("sha256-zzz=", m.nar_hash);
}

test "parseMetadata: source store path parsed from .path" {
	// nix flake metadata's top-level .path is the locked source store path; it
	// backs the path: rewrite (the materialized source is copied from here).
	const json =
		\\{"locked":{"narHash":"sha256-q=","rev":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef","type":"git","url":"https://git.example.com/o/r"},
		\\ "path":"/nix/store/aaaa-source",
		\\ "url":"git+https://git.example.com/o/r?ref=main&rev=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	;
	var m = try nix.parseMetadata(t.allocator, json);
	defer m.deinit(t.allocator);
	try t.expectEqualStrings("/nix/store/aaaa-source", m.source_path);
}

test "parseMetadata: missing .path defaults source_path to empty" {
	const json =
		\\{"locked":{"narHash":"sha256-q=","rev":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef","type":"git","url":"https://git.example.com/o/r"},
		\\ "url":"git+https://git.example.com/o/r?ref=main&rev=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	;
	var m = try nix.parseMetadata(t.allocator, json);
	defer m.deinit(t.allocator);
	try t.expectEqualStrings("", m.source_path);
}

test "parseMetadata: git scheme never grows a narHash param" {
	// nix's git fetcher passes unknown query params through to the remote
	// URL, so an appended narHash corrupts the repo path the forge sees
	// (observed as a bogus "namespace not found" on git+ssh). The locked
	// URL must come through verbatim; the narHash still lands in .nar_hash.
	const json =
		\\{"locked":{"narHash":"sha256-q=","rev":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef","type":"git","url":"https://e.com/g/r"},
		\\ "url":"git+https://e.com/g/r?dir=flake&rev=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	;
	var m = try nix.parseMetadata(t.allocator, json);
	defer m.deinit(t.allocator);
	try t.expectEqualStrings("git+https://e.com/g/r?dir=flake&rev=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", m.locked_url);
	try t.expectEqualStrings("sha256-q=", m.nar_hash);
}

test "parseMetadata: git+ssh locked URL stays verbatim" {
	const json =
		\\{"locked":{"lastModified":1700000000,"narHash":"sha256-Zz0=","ref":"refs/heads/master","rev":"0123456789abcdef0123456789abcdef01234567","type":"git","url":"ssh://git@forge.example/org/repo"},
		\\ "url":"git+ssh://git@forge.example/org/repo?ref=refs/heads/master&rev=0123456789abcdef0123456789abcdef01234567"}
	;
	var m = try nix.parseMetadata(t.allocator, json);
	defer m.deinit(t.allocator);
	try t.expectEqualStrings("git+ssh://git@forge.example/org/repo?ref=refs/heads/master&rev=0123456789abcdef0123456789abcdef01234567", m.locked_url);
	try t.expectEqualStrings("0123456789abcdef0123456789abcdef01234567", m.rev.?);
	try t.expectEqualStrings("sha256-Zz0=", m.nar_hash);
}

test "parseMetadata: bare git:// scheme never grows a narHash param" {
	// The legacy git protocol locks WITHOUT a git+ prefix; it is served by
	// the same fetcher that hands unknown query params to the remote.
	const json =
		\\{"locked":{"narHash":"sha256-g=","rev":"0123abcd0123abcd0123abcd0123abcd0123abcd","type":"git","url":"git://e.com/g/r"},
		\\ "url":"git://e.com/g/r?ref=refs/heads/master&rev=0123abcd0123abcd0123abcd0123abcd0123abcd"}
	;
	var m = try nix.parseMetadata(t.allocator, json);
	defer m.deinit(t.allocator);
	try t.expectEqualStrings("git://e.com/g/r?ref=refs/heads/master&rev=0123abcd0123abcd0123abcd0123abcd0123abcd", m.locked_url);
}

test "parseMetadata: hg scheme never grows a narHash param" {
	const json =
		\\{"locked":{"narHash":"sha256-h=","rev":"0123abcd0123abcd0123abcd0123abcd0123abcd","type":"hg","url":"https://e.com/h/r"},
		\\ "url":"hg+https://e.com/h/r?rev=0123abcd0123abcd0123abcd0123abcd0123abcd"}
	;
	var m = try nix.parseMetadata(t.allocator, json);
	defer m.deinit(t.allocator);
	try t.expectEqualStrings("hg+https://e.com/h/r?rev=0123abcd0123abcd0123abcd0123abcd0123abcd", m.locked_url);
}

test "parseMetadata: malformed input" {
	try t.expectError(error.BadMetadata, nix.parseMetadata(t.allocator, "not json"));
	try t.expectError(error.BadMetadata, nix.parseMetadata(t.allocator, "{\"url\":\"x\"}"));
	try t.expectError(error.BadMetadata, nix.parseMetadata(t.allocator, "{\"url\":\"x\",\"locked\":{}}"));
}

test "classifyModuleCheck: present / missing / failed" {
	// Clean evals: --apply 'm: m ? "attr"' prints true or false.
	try t.expectEqual(.present, nix.classifyModuleCheck(true, "true\n", ""));
	try t.expectEqual(.missing, nix.classifyModuleCheck(true, "false\n", ""));
	// No cogboxPlugins output at all: still a contract violation, not a failure.
	try t.expectEqual(.missing, nix.classifyModuleCheck(
		false,
		"",
		"error: flake 'git+file:///x' does not provide attribute 'packages.x86_64-linux.cogboxPlugins', 'legacyPackages.x86_64-linux.cogboxPlugins' or 'cogboxPlugins'",
	));
	// A fetch error must NOT be misread as a missing plugin (the bug that
	// reported every broken locked URL as "does not expose cogboxPlugins").
	try t.expectEqual(.failed, nix.classifyModuleCheck(
		false,
		"",
		"fatal: Could not read from remote repository.\nerror: Cannot find Git revision '0123456' in ref 'refs/heads/master'",
	));
	// So must an eval error inside the plugin flake.
	try t.expectEqual(.failed, nix.classifyModuleCheck(false, "", "error: boom: deliberately broken"));
	// A plugin's own eval error containing a missing-attribute phrase must
	// not smuggle the failure back into the contract message: only nix's
	// flake-output error naming 'cogboxPlugins' counts as missing.
	try t.expectEqual(.failed, nix.classifyModuleCheck(
		false,
		"",
		"error: attribute 'foo' missing\n       at /nix/store/x-source/flake.nix:4:7\nerror: input set has no attribute 'bar'",
	));
}

test "stderr helpers" {
	try t.expect(nix.stderrSaysMissingAttribute("error: flake 'path:/x' does not provide attribute 'cogboxPlugins.networkRules'"));
	try t.expect(nix.stderrSaysMissingAttribute("error: attribute 'networkRules' ... has no attribute"));
	try t.expect(!nix.stderrSaysMissingAttribute("error: infinite recursion encountered"));
	try t.expectEqualStrings("short", nix.stderrTail("  short \n"));
}

test "dirParam: extracts ?dir= value, ignores absent/empty and path dir=" {
	try t.expectEqualStrings("flake", nix.dirParam("github:o/r/abc?dir=flake&narHash=sha256-A").?);
	try t.expectEqualStrings("flake", nix.dirParam("git+https://e.com/g/r?ref=main&rev=deadbeef&dir=flake").?);
	// No query / no dir param -> null.
	try t.expect(nix.dirParam("git+https://e.com/g/r?ref=main&rev=deadbeef") == null);
	try t.expect(nix.dirParam("github:o/r") == null);
	// A literal dir= in the PATH (before ?) must not false-match.
	try t.expect(nix.dirParam("git+https://e.com/my/dir=weird/r?ref=main") == null);
	// Empty value -> null.
	try t.expect(nix.dirParam("path:/p?dir=") == null);
}

test "flakeUpdateArgv: bounded fetches, only the given inputs, then --flake <url>" {
	const argv = try nix.flakeUpdateArgv(t.allocator, "path:/x", &.{ "p-a", "user" });
	defer t.allocator.free(argv);
	const want = [_][]const u8{ "flake", "update", "--option", "connect-timeout", "5", "--option", "stalled-download-timeout", "20", "p-a", "user", "--flake", "path:/x" };
	try t.expectEqual(want.len, argv.len);
	for (want, argv) |w, g| try t.expectEqualStrings(w, g);
}

test "flakeUpdateArgv: zero inputs is refused (never an update-all)" {
	try t.expectError(error.NoInputs, nix.flakeUpdateArgv(t.allocator, "path:/x", &.{}));
}
