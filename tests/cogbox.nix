{ self, pkgs, system, liveApply ? { runners = { }; systems = { }; hosted = null; } }:

let
	# Recursively collect every transitive flake input source path. Phase E
	# triggers cogbox's wrapper to re-eval its own flake on the test
	# machine; nix resolves locked inputs by checking /nix/store for a path
	# whose narHash matches the lock entry, so pinning every input (direct
	# and transitive) into the system closure is enough to make the eval
	# work offline. Direct inputs alone are not sufficient: e.g. nix-mcp
	# pulls in numtide/flake-utils, which would otherwise be refetched.
	collectFlakeInputs = let
		walk = input: [ input ] ++ (
			if (builtins.isAttrs input && input ? inputs)
			then builtins.concatMap walk (builtins.attrValues input.inputs)
			else []
		);
	in inputs: builtins.concatMap walk (builtins.attrValues inputs);
in {
	name = "cogbox-vm";

	# Phase LA (live plugin apply) adds about 60 minutes to a run that already
	# takes about 30, past the driver's one-hour default; a loaded builder can
	# stretch both.
	globalTimeout = 3 * 3600;

	nodes.machine = { config, lib, ... }: {
		virtualisation = {
			cores = 4;
			memorySize = 8192;
			diskSize = 8192;
			qemu.options = [ "-cpu" "host" ];
		};

		boot.kernelModules = [ "kvm-intel" "kvm-amd" ];

		environment.systemPackages = with pkgs; [
			self.packages.${system}.cogbox
			openssh
			jq
			netcat-openbsd
			# Phase E rebuilds the inner microvm runner with pkgs.hello in
			# the closure. Pre-realize it on the outer machine so the inner
			# nix build resolves it from the local store with no fetch.
			hello
			# Phase H runs a small SOCKS5 stub server to verify the shim's
			# TCP remap path. The stub is plain Python; no extras needed.
			python3
			# Phase K's L7 origin uses a throwaway self-signed cert.
			openssl
			# Phase Q7 adds a plugin from a git+file:// flake; git is only
			# needed to create the fixture repo (nix fetches via libgit2).
			git
			# Phase LA formats the hosted guest's two volumes (the GCE host
			# carves and labels them on its disk).
			e2fsprogs
		];

		# Phase K (L7 vhost filtering): the host-side L7 proxy re-resolves the
		# allowed vhost NAME via the node's resolver, so the node's /etc/hosts
		# must map the test vhosts to the TEST-NET origin IP. 203.0.113.0/24
		# (TEST-NET-3) is deliberately NOT in the proxy's SSRF blocklist, so a
		# legit allow can reach it; the SSRF canary points a name at the cloud
		# metadata IP, which the proxy MUST refuse.
		# Phase S (cred-inject) points the REAL harness host api.anthropic.com at
		# the same origin so the seeded terminate rule -- which must override the
		# built-in harness auto-passthrough -- re-resolves to the local origin.
		networking.hosts = {
			"203.0.113.5" = [ "vhost-a.test" "vhost-b.test" "api.anthropic.com" ];
			"169.254.169.254" = [ "evil-meta.test" ];
		};

		# Pin all transitive flake-input sources into the test machine's
		# /nix/store so the wrapper's `nix run` re-eval (Phase E) can
		# resolve every locked input via narHash lookup, with no network.
		# Also pin the pre-built runner *and the wrapper script* whose
		# .drv hashes match what Phase E produces at runtime; without
		# either, nix would attempt to (re)build the transitive .drv
		# graph -- ~thousands of derivations including the stage0-posix
		# bootstrap chain -- and time out fetching tarballs offline.
		system.extraDependencies =
			(collectFlakeInputs self.inputs)
			++ [
				self.nixosConfigurations.cogbox-x86_64-test-hello.config.microvm.declaredRunner
				self.packages.x86_64-linux.cogbox-test-hello
				# Phase Q: the plugin composition flake produces an
				# imports-nested module whose systemPackages ORDER differs
				# from the flat test-hello shape, hence a distinct runner
				# drv that needs its own pre-built pin.
				self.nixosConfigurations.cogbox-x86_64-test-plugin.config.microvm.declaredRunner
				self.packages.x86_64-linux.cogbox-test-plugin
			]
			# Phase LA: the runner of every plugin composition it applies live,
			# and the toplevels it only plans against (flake.nix, checks.cogbox-vm);
			# for the hosted guest profile also its cogbox package (whose base
			# runner it boots). Not on PATH: both packages are `cogbox`.
			++ lib.attrValues liveApply.runners
			++ lib.attrValues liveApply.systems
			++ lib.optionals ((liveApply.hosted or null) != null) ([ liveApply.hosted.cogbox ]
				++ lib.attrValues liveApply.hosted.runners
				++ lib.attrValues liveApply.hosted.systems);

		# Phase LA's test plugins (flake + module per plugin and version); the
		# script copies them to the test user's home and adds them from there.
		# The store paths above, by name, for its assertions.
		environment.etc."cogbox-live-apply".source = ./fixtures/live-apply;
		environment.etc."cogbox-live-apply.json".text = builtins.toJSON liveApply;

		users.users.testuser = {
			isNormalUser = true;
			uid = 1000;
			home = "/home/testuser";
			password = "";
			extraGroups = [ "kvm" ];
		};

		# `systemd-run --uid=testuser` in the test script runs without a
		# logind session, so /run/user/1000 is never created. Pre-create
		# it so cogbox's XDG runtime path resolves to /run/user/1000
		# (matching a real interactive setup) instead of the /tmp fallback.
		systemd.tmpfiles.rules = [
			"d /run/user/1000 0700 testuser users -"
		];

		security.sudo.wheelNeedsPassword = false;

		programs.ssh.extraConfig = ''
			Host 127.0.0.1
				StrictHostKeyChecking no
				UserKnownHostsFile /dev/null
				LogLevel ERROR
		'';
	};

	testScript = builtins.readFile ./test_script.py;
}
