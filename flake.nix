{
	description = "cogbox MicroVM";

	# A flake's nixConfig is only honored when it is the *top-level*
	# flake; an input's nixConfig is deliberately never propagated to the
	# consumer. So even though llm-agents.nix declares cache.numtide.com,
	# building cogbox would ignore it and rebuild every harness (codex,
	# etc.) from source. nixConfig also cannot reference `inputs` (it is a
	# static attr, evaluated before outputs), so these values are mirrored
	# by hand from numtide/llm-agents.nix's own flake.nix nixConfig.
	# Re-sync if upstream rotates the cache URL or signing key.
	nixConfig = {
		extra-substituters = [ "https://cache.numtide.com" ];
		extra-trusted-public-keys = [ "niks3.numtide.com-1:DTx8wZduET09hRmMtKdQDxNNthLQETkc/yaX7M4qK0g=" ];
	};

	inputs = {
		nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
		illustris-lib = {
			url = "github:illustris/flake";
			flake = false;
		};
		microvm = {
			url = "github:microvm-nix/microvm.nix";
			inputs.nixpkgs.follows = "nixpkgs";
		};
		nix-mcp = {
			url = "github:illustris/nix-mcp";
			inputs.nixpkgs.follows = "nixpkgs";
			inputs.illustris-lib.follows = "illustris-lib";
		};
		# Intentionally not setting inputs.nixpkgs.follows: llm-agents.nix
		# publishes its builds to cache.numtide.com against its own pinned
		# nixpkgs, and overriding it would force local rebuilds of every
		# harness against our nixpkgs revision instead of cache hits.
		llm-agents.url = "github:numtide/llm-agents.nix";
		userExtensions.url = "path:./userExtensions";
	};

	outputs = { self, nixpkgs, microvm, nix-mcp, ... }@inputs: let
		lib = nixpkgs.lib;
		illustris-lib = import "${inputs.illustris-lib}/lib" { inherit lib; };
		supportedSystems = [ "x86_64-linux" "aarch64-linux" "riscv64-linux" ];
		forAllSystems = f: lib.genAttrs supportedSystems f;
		mkHermesHomeHelper = pkgs: pkgs.writeShellApplication {
			name = "cogbox-hermes-home";
			runtimeInputs = [ pkgs.coreutils pkgs.findutils ];
			text = builtins.readFile ./cogbox-hermes-home.sh;
		};

		archSuffix = system: builtins.head (lib.splitString "-" system);
		configName = system: "cogbox-${archSuffix system}";

		# Sentinel placeholder baked into the microvm runner's QEMU args
		# (9p share sources, fw_cfg file paths). At launch the wrapper
		# sed-rewrites this prefix to the resolved per-user XDG runtime
		# dir ($XDG_RUNTIME_DIR/cogbox), then populates it with
		# symlinks to the user's data/config locations. The literal
		# value here is irrelevant beyond being a unique, stable string
		# for the substitution to find.
		runtimeDir = "/tmp/cogbox";
		dataDir = "${runtimeDir}/data";

		# --- Harness configuration --------------------------------------
		# Single source of truth for how each coding-agent harness is
		# wired into the VM. Iterated below to emit systemPackages,
		# microvm.shares, qemu.extraArgs, systemd services, and
		# fileSystems. The cogbox.sh wrapper iterates the same shape
		# (re-declared in bash) to seed host state and create the runtime
		# symlinks the QEMU runner expects.
		#
		# Path kinds:
		#   overlay   - 9p RO lowerdir from host + persistent upperdir
		#               in the shared harness overlay image
		#   fw_cfg    - single host file copied into the guest at boot
		#               via QEMU's fw_cfg device
		#   ephemeral - sandbox-only; bind-mounted from the harness
		#               overlay image (no host source)
		#
		# Codex is OPT-IN. Its Rust toolchain build is slow and frequently a
		# cache miss against our nixpkgs, so it is disabled by default to keep
		# cogbox builds fast. Flip this to `true` to build it in. Everything
		# downstream is derived from the resulting harness set -- the VM's
		# packages/mounts/services AND the launcher's HARNESSES list (baked in
		# via the @harnesses@ sentinel) -- so this single switch covers both.
		enableCodex = false;
		# pi is OPT-IN. The per-instance full system toplevel is built inside a
		# FAIL-CLOSED worker pod with no registry.npmjs.org egress. pi is the only
		# harness cogbox patches via `.overrideAttrs` (the Bun->Node entrypoint fix
		# below), which changes pi's derivation hash so numtide's published pi is a
		# cache MISS -- forcing a source build that fetches the pi npm tarball from
		# npmjs, which the worker cannot reach, hanging/timing out the toplevel build.
		# Disabling by default keeps pi out of the
		# per-instance toplevel so the worker never builds it. Flip to `true` to build
		# it in. (Hermes stays enabled: used unmodified, so it's a cache hit and never
		# builds in the worker.)
		enablePi = false;
		mkHarnesses = system: pkgs: let
			llmPkgs = inputs.llm-agents.inputs.nixpkgs.legacyPackages.${system};
		in lib.filterAttrs (_: h: h.enable) {
			claude-code = {
				enable = builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
				package = inputs.llm-agents.packages.${system}.claude-code;
				launcher = {
					name = "c";
					flags = [ "--dangerously-skip-permissions" ];
					env = { IS_SANDBOX = "1"; };
					# No injected auth-token env var: the guest ALWAYS gets a present,
					# redacted-scoped .credentials.json (stage_overlay_source stages a
					# placeholder identity even on a staging failure), so claude-code
					# reads the file -- the host proxy injects the real token over the
					# stub, /remote-control's local-cred gate is satisfied, and an
					# in-guest /login can write its OWN token over the placeholder
					# (which then persists per-instance and stops host inheritance).
					# An auth-token env var would shadow the file, breaking all three.
				};
				paths = {
					config = {
						guest = "/root/.claude";
						kind = "overlay";
					};
					auth = {
						guest = "/root/.claude.json";
						kind = "fw_cfg";
						mode = "0600";
					};
				};
			};

			opencode = {
				enable = builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
				package = inputs.llm-agents.packages.${system}.opencode;
				launcher = {
					name = "oc";
					# `--dangerously-skip-permissions` exists only on the
					# `run` subcommand (one-shot mode); the default TUI
					# command parses with yargs `.strict()` and would
					# reject it. `OPENCODE_PERMISSION` is the universal
					# bypass: opencode JSON.parses it and merges it into
					# `config.permission`. opencode 1.16.2 requires the
					# object form keyed by category; a bare `"allow"` string
					# is rejected -- the schema indexes it char by char
					# (got "a" from "allow"[0]). Set every category to `allow`
					# so opencode never prompts (`bash` also takes a {pattern:
					# action} map; plain `"allow"` covers all patterns).
					flags = [];
					env = {
						IS_SANDBOX = "1";
						OPENCODE_PERMISSION = ''{"edit":"allow","bash":"allow","webfetch":"allow","doom_loop":"allow","external_directory":"allow"}'';
					};
				};
				paths = {
					config = {
						guest = "/root/.config/opencode";
						kind = "overlay";
					};
					# Includes auth.json, mcp-auth.json, log/, project/.
					# Single mount covers auth + state because opencode
					# keeps them together under XDG_DATA_HOME.
					data = {
						guest = "/root/.local/share/opencode";
						kind = "overlay";
					};
					cache = {
						guest = "/root/.cache/opencode";
						kind = "ephemeral";
					};
					state = {
						guest = "/root/.local/state/opencode";
						kind = "ephemeral";
					};
				};
			};

			codex = {
				# Opt-in (slow Rust build): gated on `enableCodex` above.
				enable = enableCodex && builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
				package = inputs.llm-agents.packages.${system}.codex;
				launcher = {
					name = "cx";
					# `--dangerously-bypass-approvals-and-sandbox` is codex's
					# documented escape hatch: skips all confirmation prompts
					# and runs commands without codex's own sandbox. Cogbox
					# already provides the outer microvm sandbox, so this is
					# the equivalent of claude-code's `--dangerously-skip-permissions`.
					flags = [ "--dangerously-bypass-approvals-and-sandbox" ];
					env = { IS_SANDBOX = "1"; };
				};
				paths = {
					# Codex stores config, auth, sessions, helper binaries
					# (tmp/), and rollouts together under $CODEX_HOME
					# (default ~/.codex). A single overlay covers everything,
					# matching opencode's auth-inside-data pattern.
					home = {
						guest = "/root/.codex";
						kind = "overlay";
					};
				};
			};

			hermes-agent = {
				enable = builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
				package = inputs.llm-agents.packages.${system}.hermes-agent;
				launcher = {
					name = "h";
					# `HERMES_YOLO_MODE=1` bypasses hermes's dangerous-command
					# approval prompts (equivalent to `--yolo`, but the env var
					# covers every subcommand -- chat, gateway, cron -- not just
					# the ones that grow the flag). Hermes's hardline blocklist
					# (rm -rf /, fork bombs, ...) stays active regardless; that
					# is a code-level constant, not a prompt.
					flags = [];
					env = { HERMES_YOLO_MODE = "1"; };
				};
				paths = {
					# Hermes keeps everything under $HERMES_HOME (default
					# ~/.hermes): config.yaml, the .env credential file
					# (provider API keys), skills, and session state. A single
					# overlay covers it all, matching codex's pattern.
					home = {
						guest = "/root/.hermes";
						kind = "overlay";
					};
				};
			};

			omp = {
				enable = builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
				package = inputs.llm-agents.packages.${system}.omp;
				launcher = {
					name = "om";
					# OMP defaults to yolo today, but pass it explicitly so a
					# persisted user setting cannot reintroduce approval prompts.
					# mkLauncher also supplies NODE_EXTRA_CA_CERTS from l7CaEnv;
					# the compiled Bun executable needs that explicit bundle for
					# OAuth on minimal Nix systems.
					flags = [ "--approval-mode" "yolo" ];
					# OMP's auth management parser rejects launch-only flags.
					# Login still needs the same CA environment, but no approval mode.
					unflaggedCommands = [ "auth-broker" ];
					env = {};
				};
				paths = {
					# OMP keeps config, its SQLite credential store, sessions,
					# profiles, skills, and caches below ~/.omp.
					home = {
						guest = "/root/.omp";
						kind = "overlay";
					};
				};
			};

			pi = {
				# Opt-in (fail-closed worker can't fetch the overridden pi from npmjs): gated on `enablePi` above.
				enable = enablePi && builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
				package = inputs.llm-agents.packages.${system}.pi.overrideAttrs (_: {
					# Retain npm's Node entrypoint for runtime compatibility.
					preInstall = "";
					postInstall = ''
						wrapProgram $out/bin/pi \
							--prefix PATH : ${llmPkgs.lib.makeBinPath [ llmPkgs.fd llmPkgs.ripgrep ]} \
							--set PI_SKIP_VERSION_CHECK 1 \
							--set PI_TELEMETRY 0
					'';
				});
				launcher = {
					name = "p";
					# pi has no permission system at all (documented upstream:
					# no built-in restriction of filesystem/process/network
					# access), so full-auto needs no flag or env -- the outer
					# microvm sandbox is the only containment, same as the
					# other harnesses.
					flags = [];
					env = {};
				};
				paths = {
					# pi keeps config, auth (auth.json: per-provider API keys
					# and OAuth tokens), models.json, settings.json, and
					# sessions/ together under ~/.pi/agent. Mount the whole
					# ~/.pi so sibling pi-mono tools' state is covered too.
					home = {
						guest = "/root/.pi";
						kind = "overlay";
					};
				};
			};
			dsh = {
				enable = builtins.elem system [ "x86_64-linux" "aarch64-linux" ];
				package = inputs.llm-agents.packages.${system}.dsh;
				launcher = {
					name = "ds";
					# DSH_PERMISSION_MODE=danger-full-access is dsh's own
					# full-auto seam: the base bundle derives sandbox-policy
					# mode from it and sets approval to 'never' for that mode,
					# so tools never prompt and dsh's bwrap/Landlock runner is
					# bypassed -- the outer microvm is the containment, same
					# deal as --dangerously-skip-permissions / HERMES_YOLO_MODE.
					# Sessions can still switch presets at runtime in the UI.
					flags = [];
					env = {
						DSH_PERMISSION_MODE = "danger-full-access";
						# Session telemetry ships disabled; hard-opt-out so
						# neither the model nor a discovered .env can stream
						# unredacted session content out of the sandbox.
						DSH_TELEMETRY_DISABLED = "1";
					};
				};
				paths = {
					# dsh keeps settings.yaml, .credentials.yaml (API keys),
					# profiles/, sessions/, and storages/ together under
					# $DSH_HOME (default ~/.dsh). One overlay covers it all,
					# matching codex/hermes/omp/pi. Credentials stay
					# guest-carries-token (no harness_inject_specs arm).
					home = {
						guest = "/root/.dsh";
						kind = "overlay";
					};
				};
			};
		};

		macFromName = name: let
			hash = builtins.hashString "sha256" name;
			b = i: builtins.substring (i * 2) 2 hash;
		in "02:${b 0}:${b 1}:${b 2}:${b 3}:${b 4}";

		mkMicrovm = system: name: {
			vcpu ? 2,
			mem ? 2048,
			extraModules ? []
		}: nixpkgs.lib.nixosSystem {
			inherit system;
			modules = [
				microvm.nixosModules.microvm
				({ pkgs, ... }: {
					# `@cogbox-instance@` is a sentinel rewritten by
					# cogbox-launch.sh to the active instance name, so
					# systemd applies `cogbox-<instance>` as the hostname
					# during early boot. Anchored on `systemd.hostname=`
					# rather than the raw token to avoid collisions if
					# the placeholder ever appears verbatim elsewhere.
					# `nokaslr` is VM-only: it lives here in mkMicrovm (the QEMU
					# guest builder), never in the container's mkContainer, so the
					# container toplevel closure stays byte-identical. The guest
					# kernel otherwise hangs at early-boot KASLR relocation on an
					# RDRAND entropy draw that stalls under nested KVM (when the
					# host nodes are themselves VMs); disabling KASLR skips that draw.
					boot.kernelParams = [ "systemd.hostname=cogbox-@cogbox-instance@" "nokaslr" ];
					users.users.root.password = "";
					services.getty.autologinUser = "root";
					# Land interactive login shells in the persisted data
					# dir so the autologin session starts where the user's
					# state lives, rather than in root's home.
					# Land interactive login shells in the standardized workdir
					# ~/work (= /root/work, a base-created symlink into the persisted
					# share). mkForce so no plugin can append a competing `cd` -- the
					# cogbox.* contract has no loginShellInit surface. Falls back to
					# /root (NOT the data dir, which holds cogbox_ed25519 + instances/)
					# if the brain oneshot has not run yet.
					programs.bash.loginShellInit = lib.mkForce ''
						cd /root/work 2>/dev/null || cd /root
						# Prepend the plugin tools (cogbox.packages) the brain materialized.
						# Redundant on the VM (they are in systemPackages already) but keeps
						# parity with the container, where this is the only PATH surface.
						[ -d /root/work/.cogbox/brain/bin ] && export PATH="/root/work/.cogbox/brain/bin:$PATH"
					'';
					microvm = {
						hypervisor = "qemu";
						inherit vcpu mem;
						socket = "${name}.socket";
						interfaces = [{
							type = "user";
							id = "usernet";
							mac = macFromName name;
						}];
						shares = [
							{
								proto = "9p";
								tag = "ro-store";
								source = "/nix/store";
								mountPoint = "/nix/.ro-store";
							}
							{
								proto = "9p";
								tag = "${name}-data";
								source = dataDir;
								mountPoint = "/var/lib/${name}";
							}
						];
					};
					nix = {
						nixPath = [ "nixpkgs=${pkgs.path}" ];
						settings.experimental-features = [ "nix-command" "flakes" ];
					};
					system.stateVersion = "25.11";
				})
			] ++ extraModules;
		};

		# Container-native backend: boot the
		# SAME guest userland as an unprivileged OCI container -- no QEMU, passt,
		# 9p, or fw_cfg. Reuses cogboxModules with target = "container" (the
		# VM-only plumbing is gated off there). The result's
		# config.system.build.toplevel is streamed into the agent-image below;
		# its /init is systemd PID1, which runs the reused brain/trust/l7-trust
		# oneshots to multi-user.target.
		mkContainer = system: name: { extraModules ? [] }: nixpkgs.lib.nixosSystem {
			inherit system;
			modules = [
				({ pkgs, lib, ... }: {
					# microvm.nixosModules.microvm is intentionally NOT imported for
					# the container. The shared guest module still carries a
					# `microvm = lib.mkIf isVm {...}` definition, so declare an inert,
					# invisible sink option to give it a home (isVm is false here, so
					# the definition is dropped and this stays {}).
					options.microvm = lib.mkOption {
						type = lib.types.attrs;
						default = {};
						visible = false;
						description = "Inert sink for the container target (no microvm).";
					};
					config = {
						boot.isContainer = true;
						system.stateVersion = "25.11";
						# No empty (or any) root password on the container: console
						# access is `kubectl exec` (a fresh process, no auth), and the
						# certificate-authenticated sshd must never fall through to a
						# password. Lock the account (`!`) instead of the VM's empty
						# password. mkForce guards against a plugin's full NixOS module.
						users.users.root.hashedPassword = lib.mkForce "!";
						# Land login + non-login shells in ~/work, same as the VM
						# (mkForce: no plugin appends a competing cd). Falls back to
						# /root (NOT COGBOX_DATA, which holds cogbox_ed25519 +
						# instances/) before the brain oneshot has run.
						programs.bash.loginShellInit = lib.mkForce ''
							cd /root/work 2>/dev/null || cd /root
							# Prepend the plugin tools (cogbox.packages) the brain
							# materialized into $out/bin. This is the container's ONLY PATH
							# surface for plugin tools (the base image is plugin-less), so it
							# is what makes `example-plugin-cli` et al. resolve in the
							# interactive terminal (tmux spawns a login shell).
							[ -d /root/work/.cogbox/brain/bin ] && export PATH="/root/work/.cogbox/brain/bin:$PATH"
						'';
						nix = {
							nixPath = [ "nixpkgs=${pkgs.path}" ];
							# NixOS owns /etc/nix/nix.conf, so express the cogbox-pod-image
							# nix.conf (single-user builds, no sandbox, public caches) as
							# options rather than a baked file.
							settings = {
								experimental-features = [ "nix-command" "flakes" ];
								build-users-group = "";
								sandbox = false;
								# CoW /nix (cogworx's CoW store mode) mounts a
								# node-shared READ-ONLY lower under a thin per-instance
								# overlay upper. Store auto-optimisation hardlinks identical
								# files together, which across the RO lower boundary either
								# EROFSes or forces needless copy-ups that defeat the CoW
								# savings. It buys nothing here anyway (the image store is
								# already optimised at build). mkForce so a plugin's full
								# NixOS module cannot re-enable it and break a cow instance.
								auto-optimise-store = lib.mkForce false;
								substituters = [ "https://cache.nixos.org" "https://cache.numtide.com" ];
								trusted-public-keys = [
									"cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
									"niks3.numtide.com-1:DTx8wZduET09hRmMtKdQDxNNthLQETkc/yaX7M4qK0g="
								];
							};
						};
					};
				})
			] ++ extraModules;
		};

		# GCE backend host: the cogbox HOST half as a full NixOS system that
		# boots on Google Compute Engine under nested virtualization, running
		# the same microVM guest it runs locally and in a k8s pod. Unlike
		# mkMicrovm/mkContainer this is not another shape of the GUEST -- it is
		# the machine the guest runs inside, so it imports nixpkgs' GCE image
		# format and then spends most of ./gce/cogbox-host.nix undoing that
		# profile's metadata-driven defaults.
		#
		# x86_64 only, and the nixosConfigurations entry below is guarded to
		# match: GCE nested virtualization is Intel-series only (S1).
		#
		# `self` and `inputs` reach the modules through specialArgs because the
		# host module needs BOTH the built cogbox package and the flake INPUT
		# SOURCE TREES -- the second is what keeps the launcher's re-exec
		# evaluable with no egress (see system.extraDependencies there).
		mkGceHost = system: { extraModules ? [ ] }: nixpkgs.lib.nixosSystem {
			inherit system;
			specialArgs = { inherit self inputs system; };
			modules = [
				"${nixpkgs}/nixos/modules/virtualisation/google-compute-image.nix"
				./gce/cogbox-host.nix
			] ++ extraModules;
		};

		# `userExt` defaults to the no-op userExtensions input but can be
		# overridden by tests to inject a known module in the same list
		# position the runtime override-input would, so the resulting
		# microvm runner has a deterministic .drvPath that matches what
		# `nix run --override-input userExtensions ...` produces.
		cogboxModules = system: { userExt ? inputs.userExtensions.nixosModules.default, target ? "vm" }: let
			hasNixMcp = builtins.hasAttr system (nix-mcp.packages or {});
		in [
			# Declare the cogbox.* plugin-contribution option tree (the "brain"
			# contract). Every plugin module fills in its slice; the base module
			# below reads the merged config.cogbox and materializes it into each
			# enabled harness's native tree under ~/work. Host-side hot-reloadable
			# policy (networkRules/l7Rules/inject) is NOT here -- it lives in the
			# cogboxPlugins.<name> flake output, read cheaply at `plugin add`.
			({ lib, ... }: {
				options.cogbox = {
					# Convention root(s): each scanned (readDir, pure eval) for
					# skills/, agents/, commands/, rules/. A bare path coerces to a
					# one-element list so multiple plugins' roots concatenate.
					contents = lib.mkOption {
						type = lib.types.coercedTo lib.types.path (p: [ p ]) (lib.types.listOf lib.types.path);
						default = [];
						description = "Convention root(s) scanned for skills/, agents/, commands/, rules/.";
					};
					# Explicit units compose on top of discovery and override a
					# discovered name. Each value is a path: a skill is a dir
					# (containing SKILL.md), an agent/command/rule is a .md file.
					skills   = lib.mkOption { type = lib.types.attrsOf lib.types.path; default = {}; description = "Explicit skill dirs (each containing SKILL.md), keyed by name."; };
					agents   = lib.mkOption { type = lib.types.attrsOf lib.types.path; default = {}; description = "Explicit agent .md files, keyed by name."; };
					commands = lib.mkOption { type = lib.types.attrsOf lib.types.path; default = {}; description = "Explicit command .md files, keyed by name."; };
					rules    = lib.mkOption { type = lib.types.attrsOf lib.types.path; default = {}; description = "Explicit rule .md files (paths: frontmatter; empty => always-on), keyed by name."; };
					# Neutral MCP spec, materialized per-harness. serverName ->
					# { command/args/env } (stdio) or { url/headers } (remote).
					mcp      = lib.mkOption { type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything); default = {}; description = "Neutral MCP servers: name -> { command/args/env } | { url/headers }."; };
					# Lifecycle hooks: event -> command.
					hooks    = lib.mkOption { type = lib.types.attrsOf lib.types.str; default = {}; description = "Lifecycle hooks: event -> command."; };
					# Plugin-scoped env, re-emitted into the harness launchers only
					# (never a hard global environment.variables set).
					env      = lib.mkOption { type = lib.types.attrsOf lib.types.str; default = {}; description = "Plugin-scoped env, merged into the harness launcher env."; };
					# Plugin-contributed CLI tools that must be on the sandbox PATH.
					# The base folds these into BOTH environment.systemPackages (so the
					# VM bakes them into /run/current-system/sw/bin via the per-instance
					# runner rebuild) AND a $out/bin buildEnv inside cogbox-brain, which
					# the container backend prepends to the guest PATH -- its base image
					# is plugin-less, so systemPackages there never carry a plugin's
					# tools. Use this instead of environment.systemPackages so a plugin's
					# tools reach BOTH backends. (listOf package: plugins concatenate.)
					packages = lib.mkOption { type = lib.types.listOf lib.types.package; default = []; description = "Plugin-contributed packages placed on the sandbox PATH (systemPackages on the VM; brain/bin on the container)."; };
					# Per-harness settings -- NOT harness-agnostic (model strings
					# differ). ALLOWLIST per harness: model, reasoningEffort. Never
					# permissions/auth/providers. Keyed by harness name.
					settings = lib.mkOption {
						type = lib.types.attrsOf (lib.types.submodule {
							options = {
								model           = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
								reasoningEffort = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
							};
						});
						default = {};
						description = "Per-harness settings (allowlist: model, reasoningEffort). Keyed by claude-code/opencode/codex.";
					};
				};
			})
			# Storage profile: WHERE durable guest data lives. This sits under
			# cogbox.* because that is the name the storage design agreed on, but it
			# is a genuinely different KIND of option from every sibling above: those
			# are filled in by third-party PLUGIN modules (the brain contract), and
			# storage layout is platform-set. Hence internal + visible = false (the
			# precedent is gce/cogbox-host.nix's own internal options), and hence the
			# two dangerous values are deliberately NOT options at all -- the hosted
			# block-DEVICE path and the machine-state mount-point LIST are plain
			# let-bindings below. A plugin-settable device path would hand a
			# third-party flake module a raw host block device inside the guest, and a
			# plugin-settable mount-point list is mount-point injection into root's
			# home; both are strictly worse than the guest-side power plugins already
			# have.
			({ lib, ... }: {
				options.cogbox.storage = {
					profile = lib.mkOption {
						type = lib.types.enum [ "workstation" "hosted" ];
						default = "workstation";
						internal = true;
						visible = false;
						description = ''
							"workstation" is today's layout, now stated rather than
							inherited: machine-state on the RAM-backed root, work/ on the
							host-visible 9p share, a read-only 9p lower for harness
							config. "hosted" puts work/ + machine/ + harness-rw/ on one
							dedicated block volume the host never mounts, and moves the
							writable /nix/store overlay off RAM. The read-only 9p harness
							lower is unchanged in BOTH profiles -- that is the local
							security property and the hosted case loses nothing by
							keeping it.
						'';
					};
					machineState = lib.mkOption {
						type = lib.types.enum [ "ephemeral" "persist" ];
						default = "ephemeral";
						internal = true;
						visible = false;
						description = ''
							Workstation opt-in: back machine-state with an auto-created
							image file in the instance's data dir instead of the tmpfs
							root. Ignored under profile = "hosted", which always persists.
						'';
					};
					sizeMiB = lib.mkOption {
						type = lib.types.int;
						default = 20480;
						internal = true;
						visible = false;
						description = ''
							Size of the AUTO-CREATED workstation machine-state image, in
							MiB (microvm.nix's `size` unit). Unused under profile =
							"hosted": that disk is sized control-plane side.
						'';
					};
					# There is deliberately NO store-overlay size option here. Under
					# `hosted` BOTH volumes are logical volumes the host carves out of
					# the one dedicated disk and both set autoCreate = false, so the
					# guest sizes neither of them -- microvm.nix reads `size` only
					# inside the autoCreate branch of createVolumesScript. The knob
					# lives where the carving happens: cogworx.gce.storeOverlaySizeMiB
					# in gce/cogbox-host.nix.
				};
			})
			userExt
			# `options` is taken here (not just `config`) for ONE reason: the plugin
			# brain below has to know WHICH plugin defined each cogbox.contents root,
			# and the merged config value has already thrown that away. Only
			# options.cogbox.contents.definitionsWithLocations still carries it.
			({ config, options, pkgs, lib, utils, ... }: let
				harnesses = mkHarnesses system pkgs;
				hermesHomeHelper = mkHermesHomeHelper pkgs;
				cfg = config.cogbox;

				# Build target: "vm" (the QEMU microvm, default) or "container"
				# (the unprivileged OCI agent image). The same guest module tree -- packages, harness
				# launchers, brain/trust/l7-trust oneshots -- serves both; the
				# VM-only plumbing below (microvm runner, 9p shares, fw_cfg
				# copies, harness overlay/loop filesystems, docker, sshd) is
				# gated to "vm" so the container drops it.
				isVm = target == "vm";
				isContainer = target == "container";
				# Container backend: the state volume mounts here, mirroring the
				# cogworx k8s pod env (XDG_CONFIG_HOME/COGBOX_DATA).
				stateRoot = "/var/lib/cogbox-state";
				cogboxData = "${stateRoot}/data/cogbox";
				# Container backend MACHINE-STATE: the tool/editor/cache state that
				# lives on the ephemeral container writable layer today, and is
				# therefore destroyed by every pod restart while the per-instance PVC
				# sits nearly idle. That PVC is already this instance's dedicated disk
				# -- it holds the work tree, the brain, the claude home and the hermes
				# home -- so persisting these three needs no volume, no mkfs and no
				# resize: only that the paths RESOLVE under ${stateRoot}/machine.
				#
				# A plain let-binding, deliberately NOT a cogbox.* option: cogbox.* is
				# the plugin-contribution namespace (see options.cogbox above), so a
				# plugin-settable list of guest paths to redirect would be
				# symlink-point injection into root's home. Adding a path later is a
				# one-line edit here.
				#
				# NEVER /root ITSELF, and never a path another mount or link owns.
				# /root carries the four harness OVERLAY mounts (/root/.claude,
				# /root/.hermes, /root/.config/opencode, /root/.local/share/opencode),
				# two ephemeral binds (/root/.cache/opencode,
				# /root/.local/state/opencode), the runtime /root/work symlink, the
				# fw_cfg-written /root/.claude.json and the tmpfiles-managed
				# /root/.nix-channels; a link over /root shadows every one of them at
				# once.
				#
				# The three roots below are the PARENTS of four of those mounts, which
				# is exactly why this list is CONTAINER-ONLY. On this target
				# `fileSystems` is `lib.mkIf isVm` and evaluates to {} -- there is no
				# mount at or under these paths to orphan, and no mount ordering to get
				# wrong, which is what makes a validated symlink the right mechanism
				# here and the wrong one on the VM. The container-state-unit check
				# asserts both halves: zero container mounts, and the VM's still
				# present. /var/lib/docker is absent on purpose (docker is VM-only).
				containerMachineState = [
					{ guest = "/root/.cache"; sub = "cache"; }
					{ guest = "/root/.local"; sub = "local"; }
					{ guest = "/root/.config"; sub = "config"; }
				];

				# ===== VM storage profile (cogbox.storage) =====================
				storageCfg = config.cogbox.storage;
				hosted = storageCfg.profile == "hosted";
				# The data pool exists when hosted, or when a workstation user opts
				# into persistent machine-state. Everything pool-shaped below keys on
				# this, so `workstation` + `ephemeral` -- the default, and every local
				# user today -- declares no volume and no bind at all.
				poolEnabled = isVm && (hosted || storageCfg.machineState == "persist");

				poolMount = "/var/lib/cogbox-guest";
				# == cogworx's guestDiskDevice. microvm.nix turns a volume's `label`
				# into device = /dev/disk/by-label/<label> instead of an
				# ORDER-DEPENDENT /dev/vd<letter>, which matters here because a second
				# volume exists and drive letters follow list position.
				poolLabel = "cogworx-guest";
				poolUnit = "${utils.escapeSystemdPath poolMount}.mount";
				cogboxUnit = "${utils.escapeSystemdPath "/var/lib/cogbox"}.mount";

				# The two jobs SYSTEMD ITSELF puts on the pool's boot path. Nothing here
				# writes either unit; systemd-fstab-generator synthesises them from the
				# realized fstab, which is exactly why they escaped the round-2 audit of
				# "every oneshot this change adds".
				#
				#   systemd-fsck@<escaped pool device>.service
				#       the pool line is fs_passno 2, so the generator emits
				#       Requires= + After= this instance on the pool .mount.
				#   systemd-growfs@<escaped pool mount>.service
				#       autoResize renders as nothing but x-systemd.growfs, and the
				#       generator turns that into a .wants symlink on the pool .mount
				#       PLUS a local-fs.target.d drop-in ordering local-fs.target After=
				#       it -- so it gates sysinit.target, hence basic.target, hence sshd.
				#
				# Both names are DERIVED, never spelled: they are what systemd-escape
				# produces for the pool's device and mount point, so renaming the label
				# or the mount point moves the drop-ins with it instead of silently
				# orphaning them. cogbox-guest-pool-boot-bounded re-derives the same two
				# names from the GENERATOR'S output and fails if a rendered drop-in does
				# not match, which is the only way to catch an escaping mistake.
				poolDevice = "/dev/disk/by-label/${poolLabel}";
				poolFsckUnit = "systemd-fsck@${utils.escapeSystemdPath poolDevice}.service";
				poolGrowfsUnit = "systemd-growfs@${utils.escapeSystemdPath poolMount}.service";
				# A finite bound for a unit whose upstream text has none, as a DROP-IN
				# body. Both halves are set, and the stop half is the load-bearing one:
				# upstream systemd-fsck@.service and systemd-growfs@.service say
				# `TimeoutSec=infinity`, which sets the START *and the STOP* timeout to
				# infinity. Bounding only the start would fire SIGTERM at the bound and
				# then wait forever for a process that is in uninterruptible D-state on
				# the very device that stalled -- the unit parks in `deactivating`, the
				# job still never completes, and the guest is wedged exactly as before,
				# just one state further along. With both set systemd escalates
				# SIGTERM -> SIGKILL -> "processes still around after final SIGKILL,
				# ignoring" and the unit reaches `failed`, which is what makes the
				# failure both survivable and VISIBLE in `systemctl --failed`.
				poolJobTimeout = start: lib.concatStringsSep "\n" [
					"[Service]"
					"TimeoutStartSec=${toString start}"
					"TimeoutStopSec=60"
					""
				];

				# HOST paths of the two hosted volumes. NOT options -- see the
				# cogbox.storage module comment.
				#
				# BOTH live on the ONE dedicated per-instance disk, as logical volumes
				# in a volume group the GCE host half creates on it
				# (gce/guest-disk.nix). LVM rather than two fixed partitions, and that
				# is the whole reason it is here: with partitions, growing the provider
				# disk only ever yields free space AFTER the last one, so whichever
				# partition sits first can never be extended and one concern blocks the
				# other's growth forever. A volume group shares its free extents, so
				# EITHER logical volume can take new space -- which is what makes
				# decision 5 (grow the disk, restart, the guest grows into it) true for
				# both surfaces rather than for one of them.
				#
				# The GUEST is never told about any of this. It sees two ordinary
				# virtio-blk devices and mounts them BY LABEL: nothing in the guest
				# configuration names the volume group, a logical volume or a
				# device-mapper path, so there is no volume-group activation anywhere on
				# the guest's boot path and no guest-side failure mode to get wrong.
				# (nixpkgs puts lvm2's udev rules in every NixOS initrd by its own
				# default, here as before this change; the point is that nothing in this
				# layout DEPENDS on them.) cogbox-guest-volume-hosted asserts the
				# by-label resolution and the absence of any dm path in both profiles.
				#
				# /dev/<vg>/<lv> rather than the /dev/mapper/ spelling: both are created
				# by lvm2 -- through its udev rules where udev runs (services.lvm.enable
				# defaults true, and the GCE host evaluates it true) and through its own
				# node management where it does not -- so neither is less stable than
				# the other, and /dev/mapper/ mangles a dash in the VG name into a
				# double dash (cogworx--guest-pool), an error-prone literal to keep in
				# step across two repositories. These strings are one half of a wire
				# contract with gce/guest-disk.nix, which spells the same names.
				hostedVG = "cogworx-guest";
				hostedPoolLV = "/dev/${hostedVG}/pool";

				# The writable /nix/store overlay, hosted profile. Its OWN volume, not a
				# subdirectory of the pool, and that is forced rather than preferred:
				# microvm.nix marks a volume neededForBoot only when its mountPoint IS
				# microvm.writableStoreOverlay, and the overlay upper genuinely is
				# needed in stage 1 -- /nix/store is an overlay whose upperdir lives
				# under it, and the overlay's own pre-mount unit carries
				# RequiresMountsFor on that path. Putting the POOL on the initrd path
				# instead would cost two things this design may not lose:
				# `x-systemd.growfs`, which IS restart-to-grow (systemd-growfs@.service
				# is absent from the initrd's upstream unit list, and in stage 2 the
				# mount is already active so its Wants= never fires), and the fail-safe
				# below -- a pool that failed to mount would take /nix/store with it and
				# wedge the guest with no sshd.
				#
				# Being a real block device is what this is actually for: today a large
				# `nix build` fills a 16G tmpfs on an ~11.7 GiB-RAM guest and OOMs the
				# guest instead of failing cleanly.
				#
				# STILL EPHEMERAL, and now the host is what makes it so: the format leg
				# re-creates this logical volume's filesystem on every HOST boot, before
				# the guest is launched. Three things ride on that one line. It keeps
				# today's tmpfs semantics exactly -- nothing in a /nix/store overlay is
				# user data, and making installed packages suddenly survive a reboot is
				# a behaviour change nothing asked for. It is the self-heal for an
				# interrupted first mkfs, which matters more here than anywhere else
				# because this mount is neededForBoot and no in-guest unit could repair
				# it. And it is how this volume GROWS: `x-systemd.growfs` cannot run for
				# an initrd mount (systemd-growfs@.service is a stage-2 upstream unit
				# and this nixpkgs has no stage-1 resize at all), so a filesystem laid
				# down fresh at the logical volume's current size is the only honest way
				# to make restart-to-grow true for this half.
				hostedStoreLV = "/dev/${hostedVG}/store";
				storeOverlayLabel = "cogworx-store-rw";

				# Tmpfs sizing, explicit in BOTH profiles. 50% for / is the value
				# microvm.nix already defaults to, now stated rather than inherited.
				# /nix/.rw-store drops from a fixed size=16G -- larger than the guest's
				# entire RAM -- to the same fraction, so a runaway build fails with
				# ENOSPC instead of OOM-killing the guest.
				rootTmpfsSize = "50%";
				storeOverlayTmpfs = "50%";

				# machine-state binds: guest path -> { sub; before }. NEVER /root
				# ITSELF: it carries four harness OVERLAY mounts (.claude, .hermes, and
				# .config/opencode + .local/share/opencode via their parents), two
				# ephemeral binds, the runtime /root/work symlink, the fw_cfg-written
				# /root/.claude.json and a tmpfiles-managed /root/.nix-channels. A /root
				# bind shadows all of them at once.
				#
				# The three home roots below are PARENTS of harness mounts, which is not
				# the same hazard: systemd orders a mount unit after its path-prefix
				# parents, so the bind lands FIRST and the harness overlay mounts on top
				# of it. Nothing is shadowed, because no overlay lower/upper/work dir
				# lives under these paths -- the lowers are the read-only 9p mounts
				# under /var/lib/harness-lower and the uppers live under
				# /var/lib/harness-rw. The read-only 9p lower is untouched in both
				# profiles, and cogbox-guest-binds-ordered asserts both halves of that:
				# no /root mount, harness overlays still present.
				# `before` on an entry is NOT decoration, and the journal bind is the
				# reason the field exists rather than the only user of it. Every bind
				# here is `nofail` (see mkPoolBind), and nofail is what MOVES the
				# generated unit from local-fs.target.requires to .wants -- which also
				# strips the Before=local-fs.target the generator would otherwise emit
				# (systemd.mount(5): "the mount unit is not ordered before these target
				# units"). MEASURED on the realized hosted fstab: every one of the 14
				# pool-dependent units lands in local-fs.target.wants and NOT ONE
				# carries Before=local-fs.target, while the non-nofail
				# nix-.rw\x2dstore.mount does.
				#
				# So local-fs.target -> sysinit -> basic -> multi-user is reachable
				# while these binds are still queued, and NOTHING is ordered after them
				# except what says so explicitly. Any unit that WRITES THROUGH a
				# pool-bound path therefore needs an entry here, or it writes to the
				# directory the bind is about to cover and its work vanishes under the
				# mount with no error anywhere. That is not hypothetical: it is the
				# recorded "plugins deliver nothing" shape.
				machineStateBinds = {
					"/root/.cache" = { sub = "machine/root/.cache"; };
					"/root/.local" = { sub = "machine/root/.local"; };
					"/root/.config" = { sub = "machine/root/.config"; };
					# dockerd creates its data root itself and nixpkgs' docker module
					# declares no ordering on /var/lib/docker (no RequiresMountsFor, no
					# After= on any mount). Unordered, a boot where this bind is slow --
					# its own x-systemd.device-timeout=30s on the pool, or an fsck --
					# lets dockerd initialise /var/lib/docker on the TMPFS ROOT and keep
					# writing to the shadowed inodes for the whole session, which is
					# precisely the RAM-eating failure this profile exists to remove.
					"/var/lib/docker" = {
						sub = "machine/var/lib/docker";
						before = [ "docker.service" ];
					};
					# A guest journal that survives reboot -- the reason repeated
					# "the sandbox is full" reports went undiagnosed, since the journal
					# lived on the tmpfs root and every restart destroyed the evidence.
					# This is a MOUNT and nothing else: journald already runs
					# Storage=persistent (the nixpkgs default; cogbox configures
					# journald nowhere). systemd-journal-flush.service carries
					# RequiresMountsFor=/var/log/journal of its own; the explicit
					# before= is the gce/state-disk.nix house idiom and costs nothing.
					"/var/log/journal" = {
						sub = "machine/log/journal";
						before = [ "systemd-journal-flush.service" ];
					};
				};
				# work/ and harness-rw/ join the pool only when HOSTED. work/ is bound
				# ONTO the 9p path rather than repointing WORK: brainMaterializeScript
				# hardcodes WORK=/var/lib/cogbox/work and brain-trust seeds claude's
				# trust under the LITERAL project key .projects["/var/lib/cogbox/work"],
				# so a bind keeps both literally true -- and it RETAINS the old 9p copy
				# by SHADOWING it rather than deleting it, which is the design's "retain
				# for at least one release" with zero extra code. harness-rw/ becomes a
				# plain directory on the pool, retiring the 128 MiB ext4-in-a-file-on-
				# ext4 loop image.
				#
				# BOTH of those replace a surface that already held persistent user data
				# on an existing instance, so BOTH need a migration, not just work/.
				# harness-rw's old home is the loop IMAGE on the 9p state dir, and it
				# holds the four harness overlay UPPERS -- claude's settings.json,
				# history, todos and a hand-placed .credentials.json, the hermes home,
				# and opencode's config + data. Repointing it at a freshly-mkdir'd pool
				# directory with no migration would present every one of those as gone on
				# the first hosted boot (the read-only 9p lower supplies only the baked
				# defaults), with the old image still on the state disk but nothing
				# mounting it and nothing saying so.
				poolBinds = machineStateBinds // lib.optionalAttrs hosted {
					"/var/lib/cogbox/work" = {
						sub = "work";
						requires = [ cogboxUnit "cogbox-guest-work-migrate.service" ];
						# cogbox-brain-materialize writes THROUGH this path -- WORK is
						# the literal /var/lib/cogbox/work (brainMaterializeScript) and
						# it creates $WORK/.cogbox/brain, the four .claude/ link trees,
						# .opencode/, .agents/skills and AGENTS.md -- and it is ordered
						# after NOTHING on this chain of its own accord (its after= is
						# the state mount plus the hermes/codex overlay mounts). With
						# nofail stripping Before=local-fs.target, the first hosted boot
						# of an existing instance ran it while the multi-GB
						# cogbox-guest-work-migrate cp was still going: the brain landed
						# in the legacy 9p directory, the migration's own verify could
						# not see it (measure() counts regular files and this leg writes
						# only directories and symlinks), stash() then renamed that
						# directory to work.pre-pool, and the bind covered a work tree
						# with no brain, no skills/agents/commands and no AGENTS.md --
						# silently, once per instance, self-healing only on the NEXT
						# boot. Type=oneshot RemainAfterExit means it does not retry
						# within the boot.
						#
						# Before=, not Requires=: ordering is satisfied by the mount
						# job COMPLETING, success or failure, so a pool-absent boot
						# still degrades instead of holding the brain hostage. The cost
						# is honest and worth naming -- brain-materialize is itself
						# Before=sshd.service, so on the ONE boot that migrates, sshd
						# now waits for the copy instead of racing it.
						before = [ "cogbox-brain-materialize.service" ];
					};
					"/var/lib/harness-rw" = {
						sub = "harness-rw";
						requires = [ cogboxUnit "cogbox-guest-harness-migrate.service" ];
					};
				};
				poolBindUnits = map (guest: "${utils.escapeSystemdPath guest}.mount")
					(lib.attrNames poolBinds);

				# Every pool-backed bind Requires= the pool mount AND the subdir
				# creator. That is what makes the fail-SAFE work: pool absent -> the
				# binds do not run -> the guest still reaches multi-user with sshd,
				# reading and writing the legacy 9p paths, so somebody can log in and
				# read the failed mount out of `systemctl --failed`. Fail-CLOSED here
				# would wedge the guest with no sshd for a fault the HOST cannot see
				# either (see the `nofail` note on the pool mount below), and a bind
				# over an EMPTY pool directory would show the user an empty work tree
				# with no failed unit at all. Both alternatives are worse.
				#
				# This is a DIAGNOSTIC boot, not a second storage mode: the pool is the
				# only place a hosted instance's data lives, and nothing here is a
				# supported way to run. Today's layout, NOT today's contents, and the
				# difference is worth a line because it reads as data loss when it is
				# not. On an instance
				# that has already migrated, stash() has renamed the legacy work
				# directory to work.pre-pool and recreated it EMPTY (that emptiness is
				# the loud signal a pre-pool boot is meant to give), so a degraded boot
				# after the migration shows an empty ~/work. The live copy is on the
				# pool volume and the pre-migration copy is next to it; the degraded
				# boot is for diagnosing, not for working in.
				poolRequires = [
					"x-systemd.requires=${poolUnit}"
					"x-systemd.after=${poolUnit}"
					"x-systemd.requires=cogbox-guest-dirs.service"
					"x-systemd.after=cogbox-guest-dirs.service"
				];
				mkPoolBind = guest: b: {
					device = "${poolMount}/${b.sub}";
					fsType = "none";
					# `nofail` on EVERY bind, not just on the pool mount, and this is the
					# whole difference between "degrades" and "wedges". A non-nofail
					# fstab entry is emitted by systemd-fstab-generator into
					# local-fs.target.REQUIRES (nofail moves it to .wants), and
					# local-fs.target ships OnFailure=emergency.target with
					# OnFailureJobMode=replace-irreversibly -- so ONE failed bind
					# replaces the whole queued multi-user.target transaction and the
					# guest comes up with no sshd. `nofail` on the pool alone only
					# unhooks the POOL; the binds still fail with a dependency error and
					# still take local-fs.target down with them, which is byte-for-byte
					# the field failure recorded on harness-overlay-img below
					# (/var/lib/harness-rw never mounts -> no sshd -> recreate loop, no
					# self-heal). VERIFIED by running systemd-fstab-generator over the
					# realized fstab both ways; cogbox-guest-pool-degradable asserts it.
					#
					# It costs nothing that R3 needs: nofail changes only how the mount
					# is hooked into local-fs.target. The Requires= that
					# x-systemd.requires= generates is untouched, so a work migration
					# that refuses still means the bind does not happen and the 9p copy
					# stays authoritative -- it just no longer takes the boot with it.
					options = [ "bind" "nofail" ] ++ poolRequires
						++ lib.concatMap (u: [ "x-systemd.requires=${u}" "x-systemd.after=${u}" ]) (b.requires or [])
						++ map (u: "x-systemd.before=${u}") (b.before or []);
				};

				# ...and `nofail` on the pool-backed binds is STILL not enough, because
				# the cascade does not stop at the units this flake spells out. systemd
				# MANUFACTURES hard Requires= on a covering mount unit, in places no
				# fstab line names:
				#
				#   src/core/mount.c:270-281  every mount unit implicitly requires the
				#                             mount covering its own parent directory,
				#   src/core/mount.c:284-294  ...and the one covering an absolute bind
				#                             or loop SOURCE,
				#   src/core/unit.c:1522-1542 and RequiresMountsFor= (which nixpkgs
				#                             generates from fileSystems.*.overlay's
				#                             lower/upper/work dirs, overlayfs.nix:116
				#                             + tasks/filesystems.nix:239-243) becomes
				#                             UNIT_REQUIRES for EVERY path prefix whose
				#                             mount unit has a fragment path -- and
				#                             fstab-generated units always do.
				#
				# In the hosted profile that drags in six mounts, none of them pool-backed
				# in its own right: the four harness OVERLAY mounts, whose
				# upper/work dirs live under the pool-bound /var/lib/harness-rw, and the
				# two opencode EPHEMERAL binds, which sit under the pool-bound
				# /root/.cache and /root/.local AND take their source from
				# /var/lib/harness-rw. Left as plain entries they land in
				# local-fs.target.REQUIRES, so an absent pool fails them by dependency
				# and takes local-fs.target -- and with it sshd -- down anyway. That is
				# the stuck-in-Booting failure mode arriving through a path `nofail` on
				# the pool never touched.
				#
				# So the flag is DERIVED from the paths each mount actually depends on
				# rather than pinned per profile: exactly the mounts that can be made to
				# fail by an absent pool are unhooked from local-fs.target, and nothing
				# else is. That matters in both directions. Under `workstation` +
				# `persist` the pool covers only the three home roots, so
				# /root/.config/opencode (nested under one) becomes nofail while
				# /root/.claude and /root/.hermes -- which still depend on the loop image,
				# a genuine precondition whose absence is a bug to surface -- do not. And
				# under the default profile poolBackedPaths is empty, so every entry is
				# byte-identical to today.
				#
				# cogbox-guest-pool-degradable re-derives this from the realized fstab
				# using the same three rules, so a mount added later that depends on the
				# pool fails the build instead of the boot.
				poolBackedPaths = lib.optionals poolEnabled ([ poolMount ] ++ lib.attrNames poolBinds);
				underPool = path: lib.any
					(base: path == base || lib.hasPrefix "${base}/" path)
					poolBackedPaths;
				# `paths` is what this mount depends on: its own mount point (whose
				# PARENT is what the prefix rule keys on -- passing the mount point
				# itself is the same test one level down and costs nothing), its source,
				# and any overlay lower/upper/work dir.
				poolNofail = paths: lib.optionals (lib.any underPool paths) [ "nofail" ];
				# The same test as an attrset, for a mount whose `options` this flake
				# does not otherwise define. fileSystems.*.options is nonEmptyListOf and
				# the check runs PER DEFINITION, so contributing a literal [] is a type
				# error even though overlayfs.nix supplies the rest of the list.
				poolNofailOpt = paths: lib.optionalAttrs (poolNofail paths != [])
					{ options = poolNofail paths; };

				# ...and `nofail` on every affected mount is STILL not the whole
				# fail-safe, because the third way an absent pool reaches
				# emergency.target does not run through a mount unit at all. A SERVICE
				# that hard-Requires= one of those mounts fails with it, and whatever
				# that service was preparing fails too -- the cascade harness-setup-dirs
				# records below, where the four harness overlay UPPERDIRS are never
				# created and the four overlay mounts then fail on a directory that does
				# not exist. `nofail` cannot reach any of that: it changes only how the
				# MOUNT is hooked into local-fs.target.
				#
				# The rule is therefore a CLASS rule and not two special cases: a service
				# keeps a hard Requires= on a mount that is a genuine precondition in
				# EVERY profile, and demotes to Wants= exactly the mounts the hosted
				# profile moves onto the pool. Wants= still pulls the mount in and After=
				# still orders against it, so a healthy boot is unchanged; a pool-absent
				# boot runs the service anyway and degrades it to the pre-pool behaviour
				# (harness config on the tmpfs root, the brain and the claude stub
				# materialised into the directory the bind would have covered), which is
				# a sandbox the user can log into rather than one they cannot.
				#
				# Membership is the same three rules poolNofail applies, read off the
				# same let-bindings, so a mount that becomes pool-backed later moves
				# every service that requires it without anyone remembering to.
				# cogbox-guest-pool-degradable re-derives the class from the realized
				# fstab and scans every realized service unit against it, so a service
				# added later with a hard Requires= is a build failure rather than a
				# boot failure.
				poolDependentMounts = poolBackedPaths
					++ map (p: p.guest) (lib.filter (p: poolNofail [
						p.guest
						(lowerMount p.harness p.pathkey)
						(upperDir p.harness p.pathkey)
						(workDir p.harness p.pathkey)
					] != []) overlayPaths)
					++ map (p: p.guest) (lib.filter (p: poolNofail [
						p.guest
						(ephemeralSrc p.harness p.pathkey)
					] != []) ephemeralPaths);
				mountUnitOf = p: "${utils.escapeSystemdPath p}.mount";
				# The two halves of a service's mount preconditions. Feed BOTH the same
				# path list: `after` takes all of them (ordering is wanted either way),
				# `requires` takes hardMounts and `wants` takes softMounts.
				hardMounts = paths: map mountUnitOf
					(lib.filter (p: !(lib.elem p poolDependentMounts)) paths);
				softMounts = paths: map mountUnitOf
					(lib.filter (p: lib.elem p poolDependentMounts) paths);

				# One-time migrations for an instance that predates the pool, one per
				# surface the hosted profile REPOINTS: work/ (from the 9p share) and
				# harness-rw/ (from the loop image on that same share). Both are
				# guest-side, because on first boot the real data sits at the legacy
				# source while the pool subdir is EMPTY, and the only place both copies
				# are simultaneously visible AND the bind can still be prevented is
				# inside the guest, before the mount. Both are no-ops on a fresh
				# instance.
				#
				# ONE builder rather than two scripts: the copy/verify/switch core is
				# the riskiest code in the change and it must not be able to drift
				# between the two callers. `prepare` is the only difference -- it sets
				# $src, and may decide there is nothing to migrate at all.
				#
				# `legacy` is the path ON THE 9P SHARE that the pool copy replaces, and it is
				# a separate argument from $src because the two differ for harness-rw (there
				# $src is a loop MOUNTPOINT and `legacy` is the image file behind it). It is
				# what gets RETIRED -- renamed to <path>.pre-pool -- once the pool copy is
				# authoritative. Retention by shadowing alone was not enough: a bind hides
				# the legacy copy only while it is mounted, so any boot on the pre-pool
				# layout (a rolled-back image, or an accepted degraded boot) presented a
				# stale-but-complete-looking tree as if it were current, the user worked in
				# it, and the next healthy boot hid that session again with nothing but an
				# informational line. Renaming aside makes the legacy path EMPTY on such a
				# boot instead of subtly stale -- alarming rather than plausible, which is
				# the whole difference -- and keeps the data for the release the design asks
				# for, under a name that says what it is.
				mkPoolMigrate = { name, sub, what, legacy, occupied, prepare }: pkgs.writeShellApplication {
					inherit name;
					runtimeInputs = [ pkgs.coreutils pkgs.findutils pkgs.gawk pkgs.util-linux pkgs.e2fsprogs ];
					text = ''
						pool=${poolMount}
						dst="$pool/${sub}"
						marker="$pool/machine/.${sub}-migrated"
						incoming="$pool/${sub}.incoming"
						legacy=${legacy}

						# Count of regular files + their total apparent bytes, in one
						# walk. Regular files ONLY, deliberately: `du -s --apparent-size`
						# also sums DIRECTORY st_size, which differs between the source
						# filesystem (9p, or ext4 through a loop) and the destination, so
						# it would compare two numbers that are allowed to disagree.
						measure() {
							find "$1" -type f -printf '%s\n' \
								| awk '{ n += 1; s += $1 } END { print (n + 0) " " (s + 0) }'
						}

						# "Holds somebody's data", supplied per leg because the two legacy
						# copies are different SHAPES and only one of them can be judged by
						# looking at the inode: work/ is a directory on the 9p share, the
						# harness copy is an ext4 image whose apparent size is a constant.
						# It gates the fork WARNING and the stash() that follows it, so a
						# false positive here is not cosmetic -- it fires the loudest alarm
						# in this design on a non-event and renames a file the operator then
						# has to reason about.
						${occupied}

						# Retire the legacy copy: one rename, same filesystem, data kept. Called
						# only once the pool copy is provably authoritative. A failure here is
						# LOUD but not fatal -- the migration itself already succeeded, and
						# refusing the bind at that point would hide the copy the user just
						# gained in order to protect the one they are done with.
						stash() {
							stash_to="$1.pre-pool"
							stash_n=1
							# Never overwrite an earlier .pre-pool: it is somebody's data too.
							while [ -e "$stash_to" ]; do
								stash_to="$1.pre-pool.$stash_n"
								stash_n=$((stash_n + 1))
							done
							if [ -d "$1" ]; then stash_dir=1; else stash_dir=0; fi
							if ! mv "$1" "$stash_to"; then
								echo "${name}: WARNING could not move $1 aside; it stays where it is, and a boot on the pre-pool layout would present it as current" >&2
								return 0
							fi
							echo "${name}: retired the legacy ${what}: $1 -> $stash_to (kept, not deleted)"
							# The bind mounts OVER a directory, so one has to remain there.
							# Recreated EMPTY on purpose: that is the loud signal on a pre-pool
							# boot, and the bind covers it on every hosted boot anyway.
							if [ "$stash_dir" = 1 ]; then
								mkdir -p "$1"
							fi
						}

						# The pool copy is authoritative whenever it has ANY content: a
						# previous migration finished, or the instance was created on the
						# pool and has always lived there. `find -print -quit` rather
						# than parsing ls -- it stops at the first entry and copes with
						# names ls would mangle.
						#
						# This comparison comes FIRST, before the marker is consulted at
						# all, and that ordering is the point. The marker is written on
						# boot 1 of every hosted instance, so a marker-first
						# short-circuit would skip the comparison forever -- and then an
						# accepted degraded boot (pool absent, the user works in the 9p
						# tree for a session) would be silently shadowed by the bind on
						# the next healthy boot, with no log line. The marker can no
						# longer suppress the check; it only records that a migration
						# already happened, which is what makes a REpeat one loud.
						if [ -n "$(find "$dst" -mindepth 1 -print -quit 2>/dev/null)" ]; then
							echo "${name}: $dst is already populated; claiming it"
							# ...but never SILENTLY. A populated pool copy AND an occupied legacy
							# copy is a fork: the likeliest cause is a boot on the pre-pool layout
							# after the migration, whose session is about to be hidden by the bind.
							# The pool copy still wins -- it is what the last hosted boot wrote, and
							# refusing here would hide weeks of work to protect days of it -- but
							# the operator gets both trees and both sizes, and the legacy copy is
							# retired so the same fork cannot form twice. Measuring both trees is
							# affordable precisely because the stash makes THAT a once-per-instance
							# path rather than a per-boot one -- note that the occupancy TEST is not
							# once-per-instance and must stay cheap on its own: the harness leg's
							# blank-image case deliberately never stashes, so its test repeats on
							# every hosted boot until a workstation boot reuses the image. One
							# superblock read plus one loop mount and a single readdir is that
							# budget; walking the image is not.
							if occupied "$legacy"; then
								echo "${name}: WARNING $dst (pool copy, files/bytes $(measure "$dst")) is about to be bound over $legacy (legacy copy, files/bytes $(measure "$legacy")), which is NOT empty -- most likely a boot without the pool wrote there after ${what} was migrated. The pool copy wins; the legacy one is kept but moved aside." >&2
								stash "$legacy"
							fi
							: > "$marker"
							exit 0
						fi

						${prepare}

						if [ -z "$(find "$src" -mindepth 1 -print -quit 2>/dev/null)" ]; then
							echo "${name}: $src is empty or absent; nothing to move"
							: > "$marker"
							exit 0
						fi
						if [ -e "$marker" ]; then
							echo "${name}: WARNING $dst is EMPTY but $marker says ${what} was already migrated, and $src is not empty -- a boot without the pool most likely wrote there. Re-migrating rather than binding an empty directory over live data." >&2
						fi

						# Copy to a SIDE directory and switch with one rename. The mv is
						# the atomic step and it is the LAST one before the marker, so a
						# crash anywhere above leaves the legacy copy authoritative --
						# and the bind, which Requires= this unit, simply does not
						# happen. That refusal is now survivable rather than fatal: the
						# bind is `nofail`, so a refused migration degrades this one path
						# instead of failing local-fs.target and taking sshd with it.
						rm -rf "$incoming"
						mkdir -p "$incoming"
						# ENOSPC on the pool, or a path cp cannot read, lands here as a
						# refusal and not a half-copy -- EXERCISED, not assumed: a
						# 128 KiB pool and a 512 KiB source gives exit 1, the incoming
						# directory removed and NO marker. No marker means the next boot
						# retries from scratch, so a persistent cause costs boot time
						# every time; loud in the journal, which now survives the reboot,
						# and never silent. (`cp -a` does recreate unix sockets and
						# fifos, so those are not a refusal cause.)
						if ! cp -a "$src/." "$incoming/"; then
							echo "${name}: copy failed; keeping ${what} where it is" >&2
							rm -rf "$incoming"
							exit 1
						fi

						# VERIFY by file count and bytes. The failure being defended
						# against is a PARTIAL copy (ENOSPC, an interrupted boot), which
						# those two catch exactly. Content hashing is deliberately NOT
						# done: hashing a 20 GiB tree at boot is itself the hazard --
						# harness-overlay-img below records a first-boot format that
						# outran the startup-probe deadline and wedged the guest.
						if ! src_m=$(measure "$src") || ! dst_m=$(measure "$incoming"); then
							echo "${name}: could not measure the trees (a file vanished mid-walk?); keeping ${what} where it is" >&2
							rm -rf "$incoming"
							exit 1
						fi
						if [ "$src_m" != "$dst_m" ]; then
							echo "${name}: verification FAILED (files/bytes $src_m -> $dst_m); keeping ${what} where it is" >&2
							rm -rf "$incoming"
							exit 1
						fi

						# $dst is provably empty at this point (checked above), so the rm
						# cannot destroy anything and the mv is a single rename.
						rm -rf "$dst"
						mv "$incoming" "$dst"
						: > "$marker"
						echo "${name}: migrated ${what} onto the pool (files/bytes $src_m)"
						# LAST, and after the marker: the migration is complete either way, and
						# this is the step that stops the copy we just replaced from ever looking
						# current again on a pre-pool boot.
						stash "$legacy"
					'';
				};
				guestWorkMigrate = mkPoolMigrate {
					name = "cogbox-guest-work-migrate";
					sub = "work";
					what = "the 9p work tree";
					# Same path as $src here: work/ is migrated in place off the share.
					legacy = "/var/lib/cogbox/work";
					# REGULAR FILES, the same definition of content measure() uses two
					# screens up -- not "any entry at all", which is what this said and
					# which is FALSE in the field. The reasoning it replaces was that an
					# empty directory is what stash() leaves behind, so a directory with
					# anything in it must be somebody's data. It is not:
					# cogbox-brain-materialize is wantedBy multi-user.target in EVERY VM
					# profile and writes THROUGH $WORK=/var/lib/cogbox/work, so any boot
					# on which the work bind does not happen repopulates that
					# stashed-empty directory with .cogbox/brain, the .claude/,
					# .opencode/ and .agents/ link trees and AGENTS.md before anybody
					# touches it. Every one of those is a directory or a SYMLINK.
					#
					# STILL REACHABLE, on two paths, which is why this test stays. One is
					# a hosted boot whose `nofail` pool mount fails or times out, so the
					# bind never happens -- deliberately survivable, see the pool mount's
					# nofail note. The other is an IMAGE ROLLBACK to a rev whose guest is
					# the workstation profile, which has no work bind at all. (The third
					# path, a launch-time chooser falling back to the workstation runner
					# because the carve was refused, is GONE: the GCE image bakes one
					# profile. It is named here only because it is what this case was
					# originally written against.)
					#
					# Read as occupancy they made the loudest alarm in this design fire
					# on a non-event -- the fork WARNING naming a legacy tree whose own
					# `files/bytes` reads 0 0 -- and stash() then renamed it, leaking one
					# .pre-pool copy onto the STATE disk (which also carries the L7 CA
					# private key, the secret store and the sshd host key) per such boot,
					# reclaimed by nothing.
					#
					# -type f is also still one cheap walk: it quits at the first regular
					# file on a populated tree, and on a scaffolded one it walks only the
					# handful of link directories brain-materialize made.
					occupied = ''
						occupied() {
							[ -n "$(find "$1" -type f -print -quit 2>/dev/null)" ]
						}
					'';
					prepare = ''src=/var/lib/cogbox/work'';
				};
				# harness-rw's legacy home is an ext4 loop IMAGE on the 9p share, so
				# this one has to mount before it can read. The image is never deleted,
				# only renamed aside once the pool copy is authoritative -- the same
				# retention work/ gets, and for the same reason.
				guestHarnessMigrate = mkPoolMigrate {
					name = "cogbox-guest-harness-migrate";
					sub = "harness-rw";
					what = "the harness overlay uppers";
					# The IMAGE, not the loop mountpoint $src: retiring it is what keeps a
					# rolled-back pre-pool boot from presenting a stale claude home as
					# current. That boot then finds no image, and harness-overlay-img.service
					# recreates a blank one (its `[ ! -f ]` arm), so it still comes up.
					legacy = "/var/lib/cogbox/harness-overlay.img";
					# CONTENT, not apparent size. `[ -s ]` on this file is always true and
					# says nothing: a hosted instance that has already migrated can take
					# one boot on the WORKSTATION runner, and harness-overlay-img.service's
					# `[ ! -f "$img" ]` arm then lays a fresh EMPTY 128 MiB ext4 back at
					# this exact path. The next hosted boot would read st_size=134217728 as
					# user data: it would fire the fork WARNING (the alarm this design
					# built to be un-mistakable) on a non-event an operator then chases,
					# and stash() would rename the blank image to .pre-pool.N -- leaking
					# 128 MiB of the STATE disk, which also carries the L7 CA private key,
					# the secret store and the sshd host key, per such boot, and eroding
					# what a .pre-pool file means.
					#
					# HOW a migrated instance takes a workstation boot, now that the GCE
					# image bakes one profile and there is no launch-time chooser to fall
					# back: an IMAGE ROLLBACK. Rolling the VM back to a rev that predates
					# the hosted profile (or forward to one that drops it) boots the
					# workstation guest against the SAME state disk, and that is the one
					# mode flip this design cannot remove -- an operator must always be
					# able to roll an image back. So this test stays exactly as strict as
					# it is; only its trigger got rarer. cogbox-guest-migrate-behaviour
					# case 7 is the fixture, and it is seeded through the units that
					# produce the state rather than by hand, so it does not depend on
					# which boot produced it.
					#
					# So look inside. The two cheap steps prepare already uses, in the same
					# order and for the same reasons.
					occupied = ''
						occupied() {
							[ -f "$1" ] || return 1
							# Superblock only. A never-formatted or truncated image holds
							# nothing to fork over and must not reach the mount below.
							dumpe2fs -h "$1" >/dev/null 2>&1 || return 1
							occ_at=/run/cogbox-harness-occupied
							mkdir -p "$occ_at"
							# READ-WRITE, for the reason spelled out in prepare: an unclean
							# power-off leaves a dirty ext4 journal and `-o ro,loop` sets
							# the LOOP DEVICE read-only, so the kernel cannot replay it and
							# the mount fails outright. Read-only here would report a
							# genuinely populated image as empty and LOSE the alarm on
							# exactly the boxes most likely to have forked. Nothing below
							# writes to it.
							#
							# A mount that fails anyway reads as unoccupied: conservative
							# toward silence rather than toward a false alarm, and it costs
							# nothing durable -- no stash means the image stays exactly
							# where it is, still migratable, and the next boot re-tries.
							mount -o loop "$1" "$occ_at" || return 1
							# REGULAR FILES, the same definition of content measure() uses --
							# not "any top-level entry that is not lost+found", which is what
							# this said and which never reads a recreated image as blank.
							# harness-overlay-img.service's `[ ! -f "$img" ]` arm lays the
							# fresh ext4 down, and then harness-setup-dirs.service
							# unconditionally mkdirs claude-code/, hermes-agent/ and
							# opencode/ upper+work trees into it on every workstation boot,
							# before anything else can look. So the top level of a blank
							# image is never empty, and the alarm this test gates fired on
							# the recreate rather than on a fork -- naming a legacy image
							# whose own `files/bytes` reads 0 0 -- and stash() then leaked
							# another .pre-pool image onto the state disk per flap.
							#
							# lost+found stays PRUNED rather than merely untyped-out: fsck
							# can recover orphan regular FILES into it, and today's test
							# never descends there, so pruning keeps that judgement
							# unchanged instead of quietly widening it.
							#
							# Dropping -maxdepth 1 is required, not incidental: real harness
							# content is nested (claude-code/config/upper/settings.json), so
							# a depth-limited -type f would read a genuinely populated image
							# as blank and LOSE the alarm -- the opposite error, and the
							# worse one. The budget survives: -quit stops at the first
							# regular file on a populated image, and a blank one only walks
							# the handful of scaffolded directories.
							if [ -n "$(find "$occ_at" -path "$occ_at/lost+found" -prune -o -type f -print -quit 2>/dev/null)" ]; then
								occ_rc=0
							else
								occ_rc=1
							fi
							umount "$occ_at" || true
							rmdir "$occ_at" 2>/dev/null || true
							return "$occ_rc"
						}
					'';
					prepare = ''
						img=/var/lib/cogbox/harness-overlay.img
						src=/run/cogbox-harness-migrate
						if [ ! -f "$img" ]; then
							echo "cogbox-guest-harness-migrate: no legacy overlay image at $img; nothing to migrate"
							: > "$marker"
							exit 0
						fi
						# dumpe2fs -h reads ONLY the superblock, so this is the same cheap
						# validity test harness-overlay-img uses -- and it keeps a
						# never-formatted or truncated image out of the mount below,
						# where it would only produce a confusing failure.
						if ! dumpe2fs -h "$img" >/dev/null 2>&1; then
							echo "cogbox-guest-harness-migrate: $img holds no valid ext4 superblock; nothing to migrate" >&2
							: > "$marker"
							exit 0
						fi
						mkdir -p "$src"
						trap 'umount "$src" 2>/dev/null || true' EXIT
						# READ-WRITE on purpose, and this is not laxity: a guest that was
						# powered off uncleanly leaves a dirty ext4 journal, and `mount
						# -o ro,loop` sets up the loop device read-only, so the kernel
						# cannot replay it and the mount fails outright. Recovery is also
						# what makes the user's LAST session visible. Nothing below
						# writes to it.
						if ! mount -o loop "$img" "$src"; then
							echo "cogbox-guest-harness-migrate: could not loop-mount $img; refusing the bind so the image stays migratable on the next boot" >&2
							exit 1
						fi
					'';
				};
				# The VM's guest oneshots order after the 9p data mount; the
				# container has no such mount, so they order after the state-prep
				# oneshot that symlinks /var/lib/cogbox into the mounted state
				# (so ~/work resolves identically to the VM).
				stateUnit = if isVm then "var-lib-cogbox.mount" else "cogbox-container-state.service";
				# L7 trust CA source: fw_cfg in the VM, a mounted file in the
				# container (the enforcer publishes it; absent -> the unit yields the system
				# bundle, which is the no-enforcement default).
				l7CaSource = if isVm
					then "/sys/firmware/qemu_fw_cfg/by_name/opt/system-l7ca/raw"
					else "/var/run/cogbox-ca/ca.crt"; # enforcer publishes the CA cert here (agent ro mount)

				# Flatten harnesses into a list of paths annotated with
				# their owning harness name and path key.
				allPaths = lib.concatLists (lib.mapAttrsToList (hname: h:
					lib.mapAttrsToList (pkey: p: p // { harness = hname; pathkey = pkey; }) h.paths
				) harnesses);
				pathsByKind = kind: lib.filter (p: p.kind == kind) allPaths;
				overlayPaths = pathsByKind "overlay";
				fwCfgPaths = pathsByKind "fw_cfg";
				ephemeralPaths = pathsByKind "ephemeral";

				# Naming conventions, used in both this flake and the
				# wrapper. Keep them in sync.
				sentinel = h: k: "${runtimeDir}/${h}-${k}";
				tag = h: k: "${h}-${k}";
				lowerMount = h: k: "/var/lib/harness-lower/${h}/${k}";
				upperDir = h: k: "/var/lib/harness-rw/${h}/${k}/upper";
				workDir = h: k: "/var/lib/harness-rw/${h}/${k}/work";
				ephemeralSrc = h: k: "/var/lib/harness-rw/${h}/${k}";

				# CA bundle the L7 terminate tier injects. cogbox-l7-trust.service
				# assembles it at boot from the system trust store plus the
				# per-instance MITM CA (if terminate is active); when terminate is
				# off it is just the system bundle, so pointing tools at it
				# unconditionally is safe.
				l7CaBundle = "/run/cogbox/ca-bundle.crt";
				l7CaEnv = {
					SSL_CERT_FILE = l7CaBundle;
					NIX_SSL_CERT_FILE = l7CaBundle;
					CURL_CA_BUNDLE = l7CaBundle;
					GIT_SSL_CAINFO = l7CaBundle;
					REQUESTS_CA_BUNDLE = l7CaBundle;
					NODE_EXTRA_CA_CERTS = l7CaBundle;
				};

				mkLauncher = h: pkgs.writeScriptBin h.launcher.name (
					let
						# opencode reads its merged plugin config from OPENCODE_CONFIG
						# (deep-merged UNDER any user ./opencode.json), not the project
						# root, so a plugin's mcp/instructions/settings never clobber
						# the user's file. cogbox-set, so plugin env can't shadow it.
						ocConfig = lib.optionalAttrs (h.launcher.name == "oc") {
							OPENCODE_CONFIG = "/root/work/.cogbox/brain/opencode.json";
						};
						# Layer order: CA env first (a harness may override it), then
						# plugin-scoped cogbox.env, then the cogbox OPENCODE_CONFIG, then
						# the harness's own launcher env (wins). Plugin env is launcher-
						# scoped on purpose -- never a hard global environment.variables.
						envParts = lib.mapAttrsToList (k: v: "${k}=${lib.escapeShellArg v}")
							(l7CaEnv // pluginEnv // ocConfig // h.launcher.env);
						envStr = lib.concatStringsSep " " envParts;
						flagsStr = lib.concatStringsSep " " (map lib.escapeShellArg h.launcher.flags);
						unflaggedCommands = h.launcher.unflaggedCommands or [];
						unflaggedPattern = lib.concatStringsSep "|" (map lib.escapeShellArg unflaggedCommands);
						command = ''exec env PATH="/root/work/.cogbox/brain/bin:$PATH" ${envStr} ${lib.getExe h.package}'';
						unflaggedDispatch = lib.optionalString (unflaggedCommands != []) ''
							case "''${1-}" in
								${unflaggedPattern}) ${command} "$@" ;;
							esac
						'';
					# Land non-login `cogbox ssh -- c/oc/om/cx/h/p/ds` in the standardized
					# workdir too (loginShellInit covers the interactive login path).
					# Prepend the brain's plugin-tool bin to PATH so the harness AND its
					# tool subprocesses (e.g. claude-code's Bash) resolve cogbox.packages
					# tools -- this is what lets the AGENT invoke them, not just a human at
					# the terminal. Harness itself is found via the absolute getExe, so
					# PATH order never affects launching it. Bash expands $PATH at runtime
					# (literal in the '' string); redundant-but-harmless on the VM.
					in "#!${pkgs.runtimeShell}\n"
						+ "cd /root/work 2>/dev/null || true\n"
						+ unflaggedDispatch
						+ ''${command} ${flagsStr} "$@"''
						+ "\n"
				);

				# All harness mount units (overlay + ephemeral). Used to
				# wire harness-setup-dirs.service in front of every per-
				# path mount.
				harnessMountUnits = map (p: "${utils.escapeSystemdPath p.guest}.mount")
					(overlayPaths ++ ephemeralPaths);

				# ===== Plugin brain: materialize config.cogbox into per-harness =====
				# native trees under ~/work. Pure eval (readDir/readFile over the
				# in-closure plugin sources); built once into the cogbox-brain
				# derivation and symlinked in by the cogbox-brain oneshot. See
				# docs/plugins.md (the cogbox.* contract).

				# --- readDir discovery (skill = dir with SKILL.md; agent/command/
				#     rule = <name>.md file) over each cogbox.contents root ---
				readDirSafe = dir: if builtins.pathExists dir then builtins.readDir dir else {};
				discoverSkills = root: let
					dir = root + "/skills";
				in lib.mapAttrs (n: _: dir + "/${n}")
					(lib.filterAttrs (n: t: t == "directory" && builtins.pathExists (dir + "/${n}/SKILL.md"))
						(readDirSafe dir));
				discoverMd = sub: root: let
					dir = root + "/${sub}";
				in lib.mapAttrs' (n: _: lib.nameValuePair (lib.removeSuffix ".md" n) (dir + "/${n}"))
					(lib.filterAttrs (n: t: t == "regular" && lib.hasSuffix ".md" n && n != "README.md")
						(readDirSafe dir));

				# --- provenance: WHICH plugin contributed each cogbox.contents root ---
				# `cogbox plugin add` renders the composition flake so every generated
				# import is wrapped in a module stamping `_file` with the plugin's
				# install name ("p-<name>"), and the instance's own flake with
				# "cogbox-user" (zig/src/plugin/compose.zig). nixpkgs propagates a
				# module's `_file` down as the fallback file of every INLINE module it
				# imports (lib/modules.nix: loadModule passes the parent's _file to
				# unifyModuleSyntax, which takes `_file = toString m._file or file`),
				# and a plugin's module is a bare function out of a flake output with no
				# _file of its own -- so the stamp reaches the option definition intact.
				# definitionsWithLocations then hands us one { file, value } per DEFINING
				# module: exactly the provenance the merged cfg.contents has discarded,
				# and the reason the old collision message could name no plugin.
				#
				# Untagged (user = false, plugin = null) is not an error by itself; it
				# only means that root cannot be QUALIFIED. Two ways to land there: a
				# composition flake generated before provenance stamping existed, and a
				# plugin that declares cogbox.contents from an imported PATH
				# (imports = [ ./sub.nix ]), which nixpkgs files under the path itself.
				#
				# `user` is a separate flag rather than a reserved tag string so a
				# plugin installed under the name "cogbox-user" cannot impersonate the
				# instance's own flake and steal the unqualified name.
				rootTag = file: let
					f = toString file;
				in if f == "cogbox-user" then { user = true; plugin = null; }
					else if lib.hasPrefix "p-" f then { user = false; plugin = lib.removePrefix "p-" f; }
					else { user = false; plugin = null; };
				tagLabel = t: if t.user then "the instance's own flake"
					else if t.plugin != null then "plugin '${t.plugin}'"
					else "an unattributed cogbox.contents root";
				# Identity of a tag for "this same source defined it twice" detection.
				# null = untagged, which every caller screens out before comparing.
				tagKey = t: if t.user then "cogbox-user"
					else if t.plugin != null then "p-${t.plugin}" else null;

				# The contents roots in merge order, each carrying its tag. Rebuilt from
				# the definitions rather than read off cfg.contents because only the
				# definitions know the provenance; this flattening reproduces
				# cfg.contents exactly. `coercedTo path (p: [p])` runs at MERGE time, so
				# a definition's `value` is whatever the author wrote -- a bare path or
				# a list -- and both must be coerced here. mkIf/mkMerge are already
				# discharged by the time definitionsWithLocations is built, so no
				# property wrapper arrives; any other unexpected shape degrades to a
				# one-element untagged root rather than throwing.
				taggedRoots = lib.concatMap (d: let
					vs = if builtins.isList d.value then d.value else [ d.value ];
					tag = rootTag d.file;
				in map (r: { root = r; inherit tag; }) vs)
					options.cogbox.contents.definitionsWithLocations;
				# [ { tag; units = { name -> path }; } ], one entry per root.
				perRootTagged = discover: map (r: { inherit (r) tag; units = discover r.root; }) taggedRoots;

				# The generated capability index is linked in under this skill name
				# (indexSkill below, `ln -s ... $out/claude/skills/cogbox-plugins`), so
				# a plugin shipping a skill by that name used to fail as a bare
				# "ln: File exists" naming nobody. Skills only: no other unit kind gets
				# an index leaf.
				reservedSkillName = "cogbox-plugins";

				# Resolve one unit kind's DISCOVERED names across all contents roots.
				# Plugins live in independently-owned repos and are installed in
				# arbitrary combinations, so "pick globally unique names" is not an
				# invariant any author can uphold -- two plugins each shipping a skill
				# called `overview` is normal, not a bug. cogbox therefore disambiguates
				# instead of refusing to build: every colliding PLUGIN copy is renamed
				# to "<plugin>-<unit>" and both stay installed. The instance's own flake
				# is the one root cogbox will not rename behind the user's back, so it
				# keeps the bare name when it is one of the colliders.
				#
				# Returns { units; owners; sources; collisions; }: the name -> path map
				# the brain materializes, per-final-name plugin attribution and the
				# ORIGINAL source path (both for the index), and the list of messages
				# for what could NOT be resolved. `units` throws that list; `collisions`
				# does not, so a check can assert on the text a user will see.
				resolveKind = kind: perRootList: let
					# name -> [ { tag; path; } ], in root order.
					byName = lib.zipAttrs (map (r: lib.mapAttrs (_: path: { inherit (r) tag; inherit path; }) r.units) perRootList);

					step = name: providers: let
						labels = map (x: tagLabel x.tag) providers;
						keys = map (x: tagKey x.tag) providers;
						# Tags that appear more than once: one source defining the same
						# name from two of its own roots. Nothing distinguishes the two
						# copies, so this is the genuine residue.
						dupKeys = lib.unique (lib.filter (k: k != null && lib.count (x: x == k) keys > 1) keys);
						dupLabels = lib.unique (map (x: tagLabel x.tag)
							(lib.filter (x: lib.elem (tagKey x.tag) dupKeys) providers));
						qualify = x: if x.tag.user
							# The user's own content is never renamed behind their back.
							then { final = name; orig = name; qualified = false; src = x.path; path = x.path; inherit (x) tag; }
							else let q = "${x.tag.plugin}-${name}"; in
								{ final = q; orig = name; qualified = true; src = x.path;
									path = qualifiedUnit "${kind} '${name}' from ${tagLabel x.tag}" q x.path; inherit (x) tag; };
					in
						if kind == "skill" && name == reservedSkillName then {
							entries = [];
							collisions = [ "cogbox: ${kind} '${name}' (from ${lib.concatStringsSep ", " labels}) uses the name cogbox reserves for its own generated capability index. Rename that ${kind} in the plugin, or place it under a different name with cogbox.${kind}s." ];
						}
						else if builtins.length providers == 1 then {
							# The overwhelmingly common case. Pass the discovered store
							# path straight through: bare name, bare symlink, no copy
							# derivation -- so the brain out-path stays byte-identical to
							# what it was before this pass existed. The container
							# prebuild and the container boot rebuild must agree on it.
							entries = [ (let x = builtins.head providers; in
								{ final = name; orig = name; qualified = false; src = x.path; path = x.path; inherit (x) tag; }) ];
							collisions = [];
						}
						else if lib.any (k: k == null) keys then {
							entries = [];
							collisions = [ "cogbox: ${kind} '${name}' is provided by ${toString (builtins.length providers)} cogbox.contents roots (${lib.concatStringsSep ", " labels}), at least one of which cogbox cannot attribute to a plugin -- so it cannot tell the copies apart to qualify them. Rename the ${kind} in one of those roots, or set cogbox.${kind}s explicitly. (A root is unattributed when it comes from the instance's own flake outside a plugin composition; when the composition flake predates provenance stamping, which any 'cogbox plugin add/del/update' regenerates; or when the plugin declares cogbox.contents from an imported file, imports = [ ./sub.nix ].)" ];
						}
						else if dupKeys != [] then {
							entries = [];
							collisions = [ "cogbox: ${lib.concatStringsSep " and " dupLabels} provides ${kind} '${name}' from more than one of its own cogbox.contents roots. cogbox can only disambiguate ACROSS plugins, never inside one: rename one of the two copies, or set cogbox.${kind}s.\"<new-name>\" explicitly to place it." ];
						}
						else { entries = map qualify providers; collisions = []; };

					steps = lib.mapAttrsToList step byName;
					entries = lib.concatMap (s: s.entries) steps;
					# A qualified "<plugin>-<unit>" can land on a name that is already
					# taken -- plugin 'a' shipping a skill literally called
					# `b-overview` while plugins 'b' and 'c' both ship `overview`.
					# Group by FINAL name and refuse any group with more than one
					# member: silently last-wins here would reintroduce exactly the
					# failure mode this pass exists to remove.
					byFinal = lib.zipAttrs (map (e: { ${e.final} = e; }) entries);
					takenErrors = lib.concatLists (lib.mapAttrsToList (n: es:
						lib.optional (builtins.length es > 1)
							"cogbox: ${kind} name '${n}' is claimed twice: ${lib.concatStringsSep "; " (map (e:
								"${tagLabel e.tag} provides ${if e.qualified then "'${e.orig}', which cogbox qualified to '${n}' because '${e.orig}' collides across plugins" else "'${n}'"}") es)}. The qualified name is unavailable, so rename the ${kind} in one of them or set cogbox.${kind}s explicitly."
					) byFinal);
					# The reserved index name is reachable by QUALIFICATION too, and the
					# discovered-name test in `step` cannot see that: a plugin installed
					# as `cogbox` shipping `skills/plugins` becomes `cogbox-plugins` the
					# moment any second plugin also ships `plugins`. Both finals are then
					# unique, so `takenErrors` stays empty, and the brain build dies on a
					# bare `ln`/`cp` error under $out/claude/skills/cogbox-plugins naming
					# neither plugin nor unit -- `cogbox init` non-zero on the VM path,
					# which is precisely the wedge this pass exists to remove.
					reservedErrors = lib.optionals (kind == "skill") (lib.concatLists (lib.mapAttrsToList (n: es:
						lib.optional (n == reservedSkillName)
							"cogbox: ${kind} '${(builtins.head es).orig}' (from ${lib.concatStringsSep ", " (map (e: tagLabel e.tag) es)}) qualifies to '${n}', which is the name cogbox reserves for its own generated capability index. Rename that ${kind} in the plugin, or place it under a different name with cogbox.${kind}s."
					) byFinal));
					collisions = lib.concatMap (s: s.collisions) steps ++ takenErrors ++ reservedErrors;
				in {
					inherit collisions;
					units = lib.throwIf (collisions != []) (lib.concatStringsSep "\n" collisions)
						(lib.listToAttrs (map (e: lib.nameValuePair e.final e.path) entries));
					owners = lib.listToAttrs (map (e: lib.nameValuePair e.final (if e.tag.plugin != null then e.tag.plugin else "-")) entries);
					sources = lib.listToAttrs (map (e: lib.nameValuePair e.final e.src) entries);
				};

				resolvedSkills   = resolveKind "skill"   (perRootTagged discoverSkills);
				resolvedAgents   = resolveKind "agent"   (perRootTagged (discoverMd "agents"));
				resolvedCommands = resolveKind "command" (perRootTagged (discoverMd "commands"));
				resolvedRules    = resolveKind "rule"    (perRootTagged (discoverMd "rules"));

				# Explicit cogbox.{skills,...} compose on top of (and override) a
				# discovered unit of the same name -- explicit is the more
				# intentional declaration. Applied AFTER qualification, so an author can
				# target either the bare name or a qualified "<plugin>-<unit>".
				skills   = resolvedSkills.units   // cfg.skills;
				agents   = resolvedAgents.units   // cfg.agents;
				commands = resolvedCommands.units // cfg.commands;
				rules    = resolvedRules.units    // cfg.rules;

				# Every unresolvable-collision message, exposed (below) as a build
				# attribute. Forcing any of the four bindings above throws these; this
				# list is the same text WITHOUT the throw, which is the only way a
				# check can assert on the message a user actually gets.
				brainCollisions = resolvedSkills.collisions ++ resolvedAgents.collisions
					++ resolvedCommands.collisions ++ resolvedRules.collisions;

				# cogbox.env deliberately gets NO cross-plugin resolution: an env var's
				# name IS its meaning, so qualifying it would only break the consumer.
				# Two plugins setting one key to DIFFERENT values already fails loudly
				# (attrsOf str merges with mergeEqualOption -- and the _file stamps
				# above now make that nixpkgs error name the plugins instead of two
				# anonymous store paths). What stays silent is a PRIORITY-resolved
				# override: one plugin's lib.mkDefault quietly losing to another's plain
				# definition. Warn whenever a key comes from more than one source.
				envDupKeys = let
					perKeyFiles = lib.zipAttrs (lib.concatMap (d:
						map (k: { ${k} = toString d.file; }) (lib.attrNames d.value))
						options.cogbox.env.definitionsWithLocations);
				in lib.attrNames (lib.filterAttrs (_: files: lib.length (lib.unique files) > 1) perKeyFiles);
				pluginEnv = lib.warnIf (envDupKeys != [])
					"cogbox: env var(s) ${lib.concatStringsSep ", " envDupKeys} are defined by more than one cogbox.env source; the highest-priority definition wins silently (cogbox never qualifies env var names)."
					cfg.env;

				# --- minimal YAML-frontmatter reader (for the index + codex). Pure
				#     readFile over store paths; only flat `key: value` lines. ---
				trimWs = s: let m = builtins.match "[[:space:]]*(.*[^[:space:]]|)[[:space:]]*" s; in if m == null then s else builtins.head m;
				stripQuotes = s: let
					unq = q: x: if lib.hasPrefix q x && lib.hasSuffix q x && builtins.stringLength x >= 2
						then builtins.substring 1 (builtins.stringLength x - 2) x else x;
				in unq "'" (unq "\"" s);
				fmLinesOf = file: let
					content = if builtins.pathExists file then builtins.readFile file else "";
					lines = lib.splitString "\n" content;
					hasFm = lines != [] && lib.head lines == "---";
					afterFirst = if hasFm then lib.tail lines else [];
					closes = lib.filter (x: x.v == "---") (lib.imap0 (i: l: { i = i; v = l; }) afterFirst);
				in if !hasFm || closes == [] then [] else lib.take (lib.head closes).i afterFirst;
				fmOf = file: lib.listToAttrs (lib.filter (x: x != null) (map (l: let
					parts = lib.splitString ":" l;
				in if lib.length parts < 2 || lib.hasPrefix "#" (trimWs l) then null
					else lib.nameValuePair (trimWs (lib.head parts))
						(stripQuotes (trimWs (lib.concatStringsSep ":" (lib.tail parts))))) (fmLinesOf file)));
				# Collapse to a single line, neutralize the most obvious override
				# patterns, and length-cap a plugin-authored description before it
				# reaches the always-on index (defense-in-depth; see plan section 8).
				sanitize = s: let
					oneLine = lib.concatStringsSep " " (lib.splitString "\n" (lib.concatStringsSep " " (lib.splitString "\t" s)));
					neutralized = builtins.replaceStrings
						[ "ignore previous" "ignore all previous" "disregard previous" "system prompt" ]
						[ "(redacted)" "(redacted)" "(redacted)" "(redacted)" ]
						oneLine;
					capped = if builtins.stringLength neutralized > 200 then (builtins.substring 0 197 neutralized) + "..." else neutralized;
				in capped;

				# MCP secret-rejection: a neutral mcp server may name only
				# command/args/env/url/headers. A plugin can never inline a
				# token/cred_file/refresh/secret -- MCP auth goes through host-side
				# inject/sidecar (the same stance as the inject spec validator).
				mcpAllowedKeys = [ "command" "args" "env" "url" "headers" ];
				mcpViolations = lib.concatLists (lib.mapAttrsToList (srv: m:
					map (k: "${srv}.${k}") (lib.filter (k: !(lib.elem k mcpAllowedKeys)) (lib.attrNames m))) cfg.mcp);

				# --- per-harness config files (pkgs.formats; no hand-rolled JSON/TOML) ---
				jsonFmt = pkgs.formats.json {};
				tomlFmt = pkgs.formats.toml {};
				opencodeMcp = lib.mapAttrs (n: m:
					(if m ? command
						then { type = "local"; command = [ m.command ] ++ (m.args or []); enabled = true; }
							// lib.optionalAttrs (m ? env) { environment = m.env; }
						else { type = "remote"; url = m.url; enabled = true; }
							// lib.optionalAttrs (m ? headers) { headers = m.headers; })) cfg.mcp;
				claudeMcp = lib.mapAttrs (n: m:
					(if m ? command
						then { command = m.command; args = m.args or []; } // lib.optionalAttrs (m ? env) { env = m.env; }
						else { type = "http"; url = m.url; } // lib.optionalAttrs (m ? headers) { headers = m.headers; })) cfg.mcp;
				codexMcp = lib.mapAttrs (n: m:
					(if m ? command
						then { command = m.command; args = m.args or []; } // lib.optionalAttrs (m ? env) { env = m.env; }
						else { url = m.url; } // lib.optionalAttrs (m ? headers) { headers = m.headers; })) cfg.mcp;
				ompMcp = lib.mapAttrs (_: m:
					(if m ? command
						then { type = "stdio"; command = m.command; args = m.args or []; }
							// lib.optionalAttrs (m ? env) { env = m.env; }
						else { type = "http"; url = m.url; }
							// lib.optionalAttrs (m ? headers) { headers = m.headers; })) cfg.mcp;
				settingsModel = h: let s = cfg.settings.${h} or null; in
					lib.optionalAttrs (s != null && s.model != null) { model = s.model; };
				claudeHooks = lib.mapAttrs (_: cmd: [ { hooks = [ { type = "command"; command = cmd; } ]; } ]) cfg.hooks;

				opencodeConfigAttrs = {
					"$schema" = "https://opencode.ai/config.json";
					instructions = [ ".cogbox/brain/rules/*.md" ];
				} // lib.optionalAttrs (cfg.mcp != {}) { mcp = opencodeMcp; }
					// settingsModel "opencode";
				opencodeConfig = jsonFmt.generate "opencode.json" opencodeConfigAttrs;

				claudeSettingsAttrs = settingsModel "claude-code"
					// lib.optionalAttrs (cfg.hooks != {}) { hooks = claudeHooks; };
				claudeSettings = jsonFmt.generate "settings.json" claudeSettingsAttrs;
				claudeMcpJson = jsonFmt.generate "mcp.json" { mcpServers = claudeMcp; };

				codexConfigAttrs = lib.optionalAttrs (cfg.mcp != {}) { mcp_servers = codexMcp; }
					// settingsModel "codex";
				codexConfig = tomlFmt.generate "config.toml" codexConfigAttrs;
				ompMcpJson = jsonFmt.generate "mcp.json" { mcpServers = ompMcp; };

				# --- the cogbox-authored capability index (the only always-on text) ---
				# Descriptions are read from the ORIGINAL discovered path, never from a
				# qualified copy: the copy is a derivation, and readFile-ing one would
				# turn this eval into import-from-derivation -- which the offline
				# container boot rebuild cannot do. An explicit cogbox.skills entry
				# overrides discovery, so it supplies its own path and a blank plugin
				# column (cogbox knows no plugin for it).
				indexSkillSrc = resolvedSkills.sources // cfg.skills;
				indexSkillOwner = n: if cfg.skills ? ${n} then "-" else (resolvedSkills.owners.${n} or "-");
				indexRows = lib.mapAttrsToList (n: _:
					"| `${n}` | ${indexSkillOwner n} | ${sanitize ((fmOf (indexSkillSrc.${n} + "/SKILL.md")).description or "")} |") skills;
				# Built as an explicit line list (NOT a '' here-string): a SKILL.md
				# whose `---` frontmatter is not at column 0 is not recognized by the
				# harness, and '' dedent leaves stray leading tabs.
				indexSkill = pkgs.writeTextDir "SKILL.md" (lib.concatStringsSep "\n" ([
					"---"
					"name: cogbox-plugins"
					"description: Index of capabilities installed in this sandbox; consult before answering domain questions."
					"---"
					""
					"# Installed capabilities"
					""
					"Plugin-provided skills available in this sandbox. Load a skill by relevance before answering domain questions in its area."
					""
					"| skill | plugin | description |"
					"|---|---|---|"
				] ++ indexRows) + "\n");

				# --- the materialized brain derivation (RO store leaves) ---
				linkInto = dir: ext: attrs: lib.concatStringsSep "\n"
					(lib.mapAttrsToList (n: p: ''ln -s ${p} "${dir}/${n}${ext}"'') attrs);
				# Copy a unit under a QUALIFIED name, rewriting its frontmatter `name:`
				# to match. A copy, not a symlink, because the leaf's own content has to
				# change: docs/plugins.md requires a skill's frontmatter name to equal
				# its directory name (opencode enforces it), and claude-code keys its
				# agents on the frontmatter name too -- a qualified unit still carrying
				# the bare name in its frontmatter would collide again inside the
				# harness, one layer down from where cogbox just fixed it.
				#
				# Only the LEADING `---` block is touched (a `name:` line further down
				# is prose, not metadata) and only when that block already has one, so
				# this never invents frontmatter a plugin chose not to ship.
				#
				# A pure function of (newName, src) with a fixed derivation name, so the
				# container prebuild and the container boot rebuild produce the same
				# out-path -- the byte-identical-brain rule below. runCommandLocal (not
				# runCommand) keeps it buildable in the egress-less sandbox.
				#
				# `what` names the unit and its plugin ("skill 'overview' from plugin
				# 'a'"). It is only used when the rewrite CANNOT be carried out, which
				# has to fail loudly rather than ship a copy still declaring the bare
				# name: that would reintroduce the collision one layer down, inside the
				# harness, with nothing said anywhere.
				qualifiedUnit = what: newName: src: pkgs.runCommandLocal "cogbox-unit-${newName}" {} ''
					what=${lib.escapeShellArg what}
					# The delimiter and the key are matched with exactly the whitespace
					# tolerance cogbox's own frontmatter reader has (fmOf trims around
					# both halves of `key: value`). Byte-exact matching silently skipped
					# a plugin authored on Windows -- line 1 is `---\r`, never `---`, so
					# `fm` was never set and the `name:` line was never reached -- and
					# the qualified copy shipped with the ORIGINAL name in it.
					fm_name() {  # $1 = markdown file -> the leading block's `name:`, or ""
						awk '
							NR == 1 && !/^---[[:space:]]*$/ { exit }
							NR == 1                         { next }
							/^---[[:space:]]*$/             { exit }
							/^[[:space:]]*name[[:space:]]*:/ {
								sub(/^[[:space:]]*name[[:space:]]*:[[:space:]]*/, "")
								sub(/[[:space:]]+$/, "")
								print; exit
							}
						' "$1"
					}
					rewrite_fm() {  # $1 = markdown file (rewritten in place), $2 = new name
						awk -v n="$2" '
							NR == 1 && /^---[[:space:]]*$/   { fm = 1; print; next }
							fm && /^---[[:space:]]*$/        { fm = 0; print; next }
							fm && !done && /^[[:space:]]*name[[:space:]]*:/ { print "name: " n; done = 1; next }
							{ print }
						' "$1" > "$1.new"
						mv "$1.new" "$1"
						# Belt and braces, and the reason the recognizers above are not
						# left to speak for themselves: if a leading block still declares
						# some other name, this rewriter has met a shape it does not
						# understand. Refuse the build -- with the plugin and the unit in
						# the message, the same contract every other residue keeps --
						# rather than ship a copy whose frontmatter contradicts its name.
						got=$(fm_name "$1")
						if [ -n "$got" ] && [ "$got" != "$2" ]; then
							echo "cogbox: $what could not be qualified to '$2': its frontmatter still declares 'name: $got'. Rename it in the plugin, or place it under a different name with cogbox.skills/agents/commands/rules." >&2
							exit 1
						fi
					}
					if [ -d ${src} ]; then
						# A skill is a DIRECTORY; its new directory name comes from the
						# symlink linkInto creates, so only SKILL.md needs rewriting.
						#
						# Copied STRUCTURE-PRESERVING (no -L). A skill tree may carry a
						# symlink that does not resolve inside the build sandbox -- a
						# relative link pointing out of the tree, an absolute link to a
						# host path -- and dereferencing aborts the whole derivation with
						# a `cp: cannot stat` naming neither plugin nor unit, i.e. turns
						# a plugin PAIR into a failed boot. Those links were already
						# dangling before qualification (linkInto symlinked the directory
						# and never followed them), so copying them through leaves them
						# exactly as broken as they were and no worse.
						#
						# What the flat copy DOES cost, stated honestly: a link that stays
						# inside the skill tree keeps working, but one that ESCAPES the
						# skill directory (`../shared/SKILL.md`, a repo sharing one text
						# between skill variants) does not. `$out` sits at the top of the
						# store, not under <contents>/skills/, so an escaping link points
						# somewhere else entirely here. That is a REGRESSION against the
						# un-qualified path for payload files, which linked the discovered
						# directory in place and left such a link resolving; qualification
						# has to copy, so it is the price of resolving the collision at
						# all. SKILL.md does not pay it -- it is re-materialized below.
						cp -r ${src} $out
						chmod -R u+w $out
						# The one file whose CONTENT this derivation changes, taken from
						# the SOURCE rather than read back out of the copy above.
						# --remove-destination because the copied leaf may itself be a
						# now-dangling symlink, which cp would otherwise follow.
						#
						# Whether that source read succeeds depends on how the contents
						# root reached the build, and BOTH outcomes are correct:
						#   - a store TREE (what a flake input or a `path:` plugin source
						#     produces -- one store path holding the whole repo): the link
						#     still resolves at its original depth, so the qualified copy
						#     gets a real file and the rewrite below;
						#   - a bare path LITERAL: nix copies each discovered leaf
						#     DIRECTORY to the store on its own, so the link points
						#     outside its store path and cannot be read at all.
						#
						# Then rewrite UNCONDITIONALLY, and refuse when the read failed.
						# Testing `[ -f $out/SKILL.md ]` first is what made both cases
						# silent: the test was false, so neither the rewrite nor its
						# fm_name assertion ran, and cogbox shipped a `<plugin>-<unit>/`
						# whose SKILL.md dangled -- a skill the harness cannot read at all,
						# still advertised by description in the generated index.
						# discoverSkills only accepts a directory whose SKILL.md
						# pathExists (resolved in the plugin's own tree), so a leaf that
						# cannot be read HERE is genuinely unreadable, and that is a
						# legitimate hard failure -- named, like every other residue,
						# rather than skipped.
						cp -L --remove-destination ${src}/SKILL.md $out/SKILL.md || {
							echo "cogbox: $what could not be qualified to '${newName}': its SKILL.md cannot be read (a link resolving nowhere inside the build, or not a file). Fix it in the plugin, or place that skill under a different name with cogbox.skills." >&2
							exit 1
						}
						chmod u+w $out/SKILL.md
						rewrite_fm $out/SKILL.md "${newName}"
					else
						# agent/command/rule: a single .md file IS the unit. discoverMd
						# only accepts a `regular` readDir entry, so this side is never
						# handed a symlink and -L is safe here.
						cp -L ${src} $out
						chmod u+w $out
						rewrite_fm $out "${newName}"
					fi
				'';
				# Plugin-contributed tools, merged into one bin/ tree. Fixed name so the
				# out-path is a pure function of cfg.packages -- the container prebuild
				# and boot rebuild must produce a byte-identical cogbox-brain out-path
				# (the boot substitutes it offline from the per-instance plugin-cache).
				# ignoreCollisions: a plugin listing tools whose closures share a bin
				# name must not FAIL the brain build (which would drop ALL its tools);
				# first-wins matches how environment.systemPackages already tolerates the
				# same set on the VM. Only /bin is linked (tools, not docs/man/lib).
				pluginBin = pkgs.buildEnv { name = "cogbox-plugin-bin"; paths = cfg.packages; pathsToLink = [ "/bin" ]; ignoreCollisions = true; };
				cogbox-brain = pkgs.runCommandLocal "cogbox-brain" {} (''
					set -e
					mkdir -p $out/rules
					${linkInto "$out/rules" ".md" rules}
				'' + lib.optionalString (harnesses ? "claude-code") ''
					mkdir -p $out/claude/skills $out/claude/agents $out/claude/commands
					${linkInto "$out/claude/skills" "" skills}
					ln -s ${indexSkill} $out/claude/skills/cogbox-plugins
					${linkInto "$out/claude/agents" ".md" agents}
					${linkInto "$out/claude/commands" ".md" commands}
					${lib.optionalString (claudeSettingsAttrs != {}) "cp ${claudeSettings} $out/claude/settings.json"}
					${lib.optionalString (cfg.mcp != {}) "cp ${claudeMcpJson} $out/claude/.mcp.json"}
				'' + lib.optionalString (harnesses ? "opencode") ''
					mkdir -p $out/opencode/skills $out/opencode/agents $out/opencode/commands
					${linkInto "$out/opencode/skills" "" skills}
					ln -s ${indexSkill} $out/opencode/skills/cogbox-plugins
					${linkInto "$out/opencode/agents" ".md" agents}
					${linkInto "$out/opencode/commands" ".md" commands}
					cp ${opencodeConfig} $out/opencode.json
				'' + lib.optionalString (harnesses ? "omp") ''
					# OMP discovers all four unit types natively from the project
					# .omp tree. Keep MCP project-scoped as well so the host's
					# ~/.omp credential/state overlay remains untouched.
					mkdir -p $out/omp/skills $out/omp/agents $out/omp/commands $out/omp/rules
					${linkInto "$out/omp/skills" "" skills}
					ln -s ${indexSkill} $out/omp/skills/cogbox-plugins
					${linkInto "$out/omp/agents" ".md" agents}
					${linkInto "$out/omp/commands" ".md" commands}
					${linkInto "$out/omp/rules" ".md" rules}
					${lib.optionalString (cfg.mcp != {}) "cp ${ompMcpJson} $out/omp/mcp.json"}
				'' + lib.optionalString (harnesses ? "codex" || harnesses ? "pi") ''
					# The agentskills.io project layout, read natively by BOTH codex
					# (~/.agents/skills) and pi (.agents/skills in cwd/ancestors) --
					# one tree serves whichever of the two is enabled.
					mkdir -p $out/agents/skills
					${linkInto "$out/agents/skills" "" skills}
					ln -s ${indexSkill} $out/agents/skills/cogbox-plugins
				'' + lib.optionalString (harnesses ? "codex") ''
					${lib.optionalString (codexConfigAttrs != {}) "mkdir -p $out/codex && cp ${codexConfig} $out/codex/config.toml"}
				'' + lib.optionalString (harnesses ? "hermes-agent") ''
					# Hermes has no project-level skill discovery -- it only loads
					# $HERMES_HOME/skills (same agentskills.io SKILL.md format). The
					# materialize oneshot links these into /root/.hermes/skills; the
					# writes land in the VM overlay upper or container state PVC,
					# never the host.
					mkdir -p $out/hermes/skills
					${linkInto "$out/hermes/skills" "" skills}
					ln -s ${indexSkill} $out/hermes/skills/cogbox-plugins
				'' + lib.optionalString (rules != {}) ''
					# Harness-neutral rules digest: pi and hermes auto-inject an
					# AGENTS.md found in the cwd, and codex reads it natively -- none
					# of them has a native per-file rules dir like claude-code's
					# .claude/rules. Concatenate the merged rules into one AGENTS.md,
					# linked into ~/work only-if-absent by the materialize oneshot.
					# Path-scoped rules (paths: frontmatter) become always-on here,
					# same trade-off as opencode's instructions glob; the frontmatter
					# block itself is stripped (it is routing metadata, not prompt).
					{
						for f in $out/rules/*.md; do
							echo "<!-- cogbox rule: $(basename "$f" .md) -->"
							awk 'NR==1 && $0=="---" {fm=1; next} fm && $0=="---" {fm=0; next} !fm' "$f"
							echo
						done
					} > $out/AGENTS.md
				'' + lib.optionalString (cfg.packages != []) ''
					# Plugin tools on PATH: the container's brain-materialize prepends
					# $out/bin (via /root/work/.cogbox/brain/bin) to the guest PATH. On
					# the VM these are already baked into systemPackages, so this bin/ is
					# harmless-redundant there. Guarded so a plugin-less brain (the baked
					# base image's) keeps an out-path with no bin dir.
					ln -s ${pluginBin}/bin $out/bin
				'');

				# Materialize the brain into ~/work: create the ~/work symlink into
				# the persisted share, the .cogbox/brain RO store link, and per-leaf
				# child symlinks into each harness's native dirs (parents stay real
				# writable dirs so the harness can scaffold session state alongside).
				# Harness-agnostic: each layout is attempted, skipped if the brain
				# didn't build it. Offline-safe -- reads only closure-resident paths.
				# Container backend: the baked ${cogbox-brain} is BASE-only (the agent
				# image is built once, plugin-less). Resolve $brain by rebuilding it
				# from THIS instance's composition flake -- the SAME
				# `--override-input userExtensions <composition>` path the VM runner
				# rebuild takes (cogbox-launch.sh) -- and fall back to the baked base
				# brain when the instance has no plugins or the rebuild fails
				# (offline / eval error), so the sandbox always boots. Best-effort
				# throughout; nix's stderr flows to the unit journal. COGBOX_INSTANCE
				# is forwarded into the unit (PassEnvironment); ${self}/${nixpkgs} are
				# the image's baked flake + nixpkgs sources.
				brainResolveContainer = ''
					brain=${cogbox-brain}
					inst="''${COGBOX_INSTANCE:-default}"
					icd="''${XDG_CONFIG_HOME:-${stateRoot}/config}/cogbox/instances/$inst"
					pcount=0
					if [ -f "$icd/config.json" ]; then
						pcount=$(${pkgs.jq}/bin/jq -r '(.plugins // []) | length' "$icd/config.json" 2>/dev/null || echo 0)
					fi
					if [ "$pcount" -gt 0 ] && [ -f "$icd/plugins-flake/flake.nix" ]; then
						# Resolve the composition's transitive tarball/narHash inputs from
						# the per-instance file:// cache `cogbox plugin add` populated
						# (require-sigs false: a local content-addressed cache is unsigned).
						subst=()
						[ -d "$icd/plugin-cache" ] && subst=(--option extra-substituters "file://$icd/plugin-cache" --option require-sigs false)
						# Narinfo count is the seed-health signal on fallback: 0 means the
						# worker-side prebuild never populated the plugin-cache, so the
						# egress-less rebuild below had nothing to substitute from.
						nnar=$(ls "$icd/plugin-cache"/*.narinfo 2>/dev/null | wc -l || echo 0)
						echo "cogbox-brain: rebuilding per-instance brain ($pcount plugin(s)) for instance '$inst'" >&2
						# Evaluate the `-container` config, NOT the VM `${configName system}`.
						# cogboxBrain is target-INDEPENDENT (same runCommandLocal in both), but
						# the VM config imports microvm.nixosModules.microvm, which forces the
						# `microvm` flake input's SOURCE tree -- unfetchable offline in a
						# fail-closed sandbox, aborting the eval and silently dropping the whole
						# guest half. The `-container` (mkContainer) config omits microvm.
						# OFFLINE-CLEAN: the `-container`
						# brain eval now force-reads ZERO github flake input SOURCE trees.
						# microvm/nix-mcp/llm-agents are not forced here, and the last
						# holdout -- nixfs, previously imported unconditionally in
						# cogboxModules -- has been fully dropped. Only nixpkgs and
						# illustris-lib (both seeded in the baked agent image) are touched,
						# so a cold fail-closed pod can rebuild the brain without network.
						if out=$(${pkgs.nix}/bin/nix build --no-link --print-out-paths \
								--extra-experimental-features "nix-command flakes" \
								"''${subst[@]}" \
								--override-input userExtensions "path:$icd/plugins-flake" \
								--override-input userExtensions/user/nixpkgs "path:${nixpkgs}" \
								"path:${self}#nixosConfigurations.${configName system}-container.config.system.build.cogboxBrain"); then
							first=$(printf '%s\n' "$out" | grep -m1 '^/nix/store/' || true)
							if [ -n "$first" ] && [ -e "$first" ]; then
								brain="$first"
								echo "cogbox-brain: using per-instance brain $brain" >&2
								rm -f "$icd/brain.fallback" || true
							else
								echo "cogbox-brain: rebuild produced no out-path; using baked base brain (plugin-cache narinfos: $nnar)" >&2
								printf 'time=%s reason=%s narinfos=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" no-out-path "$nnar" > "$icd/brain.fallback" || true
							fi
						else
							# WHY A SECOND EVAL ON THE FAILURE PATH. An unresolvable
							# unit-name collision makes cogboxBrain THROW, so the build
							# above fails and this branch keeps the image's plugin-less
							# BASE brain: the sandbox boots green with no plugin skills,
							# agents, commands, rules or $out/bin tools at all. On the VM
							# path the same composition refuses to boot and says why; a
							# container must not degrade that far in silence.
							# cogboxBrainCollisions is the same message list WITHOUT the
							# throw, so it still evaluates here -- and it is the only
							# thing that names the plugins and the unit. Same overrides,
							# same offline constraint, and empty for every other cause
							# (offline, cold plugin-cache, a plugin's own eval error),
							# which keeps those on the generic line below.
							cmsg=$(${pkgs.nix}/bin/nix eval --raw \
									--extra-experimental-features "nix-command flakes" \
									"''${subst[@]}" \
									--override-input userExtensions "path:$icd/plugins-flake" \
									--override-input userExtensions/user/nixpkgs "path:${nixpkgs}" \
									--apply 'c: builtins.concatStringsSep "\n" c' \
									"path:${self}#nixosConfigurations.${configName system}-container.config.system.build.cogboxBrainCollisions" 2>/dev/null || true)
							if [ -n "$cmsg" ]; then
								echo "cogbox-brain: this instance's plugin set cannot be composed, so the sandbox is starting WITHOUT any plugin content:" >&2
								printf '%s\n' "$cmsg" >&2
								{ printf 'time=%s reason=%s narinfos=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" unit-name-collision "$nnar"
									printf '%s\n' "$cmsg"; } > "$icd/brain.fallback" || true
							else
								echo "cogbox-brain: rebuild failed; using baked base brain (see prior nix log; plugin-cache narinfos: $nnar, 0 = worker seed never populated the cache)" >&2
								printf 'time=%s reason=%s narinfos=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" rebuild-failed "$nnar" > "$icd/brain.fallback" || true
							fi
						fi
					else
						# No plugin composition -> the baked base brain IS the correct
						# brain; clear any stale fallback marker left by a prior
						# plugin-era boot so it can't false-positive later.
						rm -f "$icd/brain.fallback" 2>/dev/null || true
					fi'';
				brainMaterializeScript = pkgs.writeShellScript "cogbox-brain-materialize" ''
					set -e
					${if isContainer then brainResolveContainer else "brain=${cogbox-brain}"}
					WORK=/var/lib/cogbox/work
					mkdir -p "$WORK/.cogbox"
					ln -sfn "$WORK" /root/work
					ln -sfn "$brain" "$WORK/.cogbox/brain"

					linkleaves() {  # $1 = brain subdir, $2 = dest dir
						[ -d "$1" ] || return 0
						mkdir -p "$2"
						for leaf in "$1"/*; do
							[ -e "$leaf" ] || continue
							ln -sfn "$leaf" "$2/$(basename "$leaf")"
						done
					}

					# claude-code: native skills/agents/commands/rules
					linkleaves "$brain/claude/skills"   "$WORK/.claude/skills"
					linkleaves "$brain/claude/agents"   "$WORK/.claude/agents"
					linkleaves "$brain/claude/commands" "$WORK/.claude/commands"
					linkleaves "$brain/rules"           "$WORK/.claude/rules"
					if [ -e "$brain/claude/settings.json" ]; then
						mkdir -p "$WORK/.claude"
						ln -sfn "$brain/claude/settings.json" "$WORK/.claude/settings.json"
					fi
					# project .mcp.json only when the user has none (never clobber)
					if [ -e "$brain/claude/.mcp.json" ] && [ ! -e "$WORK/.mcp.json" ]; then
						ln -sfn "$brain/claude/.mcp.json" "$WORK/.mcp.json"
					fi

					# opencode: config via OPENCODE_CONFIG; native skills/agents/commands
					linkleaves "$brain/opencode/skills"   "$WORK/.opencode/skills"
					linkleaves "$brain/opencode/agents"   "$WORK/.opencode/agents"
					linkleaves "$brain/opencode/commands" "$WORK/.opencode/commands"


					# omp: native project skills/agents/commands/rules and MCP.
					linkleaves "$brain/omp/skills"   "$WORK/.omp/skills"
					linkleaves "$brain/omp/agents"   "$WORK/.omp/agents"
					linkleaves "$brain/omp/commands" "$WORK/.omp/commands"
					linkleaves "$brain/omp/rules"    "$WORK/.omp/rules"
					if [ -e "$brain/omp/mcp.json" ] && [ ! -e "$WORK/.omp/mcp.json" ]; then
						mkdir -p "$WORK/.omp"
						ln -sfn "$brain/omp/mcp.json" "$WORK/.omp/mcp.json"
					fi
					# codex + pi: skills under .agents/skills (codex resolves it from
					# ~, pi from cwd/ancestors -- the launchers cd to ~/work, and
					# /root/work -> $WORK, so both see this same tree). codex global
					# config.toml only if absent.
					linkleaves "$brain/agents/skills" "$WORK/.agents/skills"
					if [ -e "$brain/codex/config.toml" ] && [ ! -e /root/.codex/config.toml ]; then
						mkdir -p /root/.codex
						install -m600 "$brain/codex/config.toml" /root/.codex/config.toml || true
					fi

					${lib.optionalString (harnesses ? "hermes-agent") ''
						mkdir -p /root/.hermes/{cron,sessions,logs,memories}
					''}
					# hermes-agent: after its managed runtime skeleton exists, link skills
					# into $HERMES_HOME/skills. These writes land in the VM overlay upper
					# or container's per-instance state PVC, never the host home.
					linkleaves "$brain/hermes/skills" /root/.hermes/skills

					# Harness-neutral AGENTS.md (pi + hermes inject it from the cwd,
					# codex reads it natively): linked THROUGH the stable brain path
					# so it tracks brain rebuilds, and only-if-absent so a user's own
					# AGENTS.md is never clobbered. A dangling link that is ours
					# (rules removed by a plugin change) is dropped, not left broken.
					if [ -L "$WORK/AGENTS.md" ] && [ ! -e "$WORK/AGENTS.md" ] \
						&& [ "$(readlink "$WORK/AGENTS.md")" = ".cogbox/brain/AGENTS.md" ]; then
						rm -f "$WORK/AGENTS.md"
					fi
					if [ -e "$brain/AGENTS.md" ] && [ ! -e "$WORK/AGENTS.md" ]; then
						ln -sfn .cogbox/brain/AGENTS.md "$WORK/AGENTS.md"
					fi
				'';

				# Pre-accept Claude Code workspace trust for ~/work (both /root/work
				# and the /var/lib/cogbox/work it resolves to, since Node's cwd
				# resolves the symlink) and reconcile stale pre-migration project
				# keys. Replaces the per-plugin cogbox-claude-trust units. Also seeds
				# bypassPermissionsModeAccepted -- see the block above claudeStubScript,
				# which carries the full rationale for both backends.
				brainTrustScript = pkgs.writeShellScript "cogbox-brain-trust" ''
					set -eu
					f=/root/.claude.json
					[ -s "$f" ] || echo '{}' > "$f"
					${pkgs.jq}/bin/jq '
						.projects["/var/lib/cogbox/work"].hasTrustDialogAccepted = true
						| .projects["/root/work"].hasTrustDialogAccepted = true
						| del(.projects["/var/lib/cogbox"])
						| del(.projects["/var/lib/cogbox/home"])${lib.optionalString isVm ''

						| .hasCompletedOnboarding = true
						| .bypassPermissionsModeAccepted = true''}
					' "$f" > "$f.tmp"
					# Write THROUGH $f rather than `mv` onto it: on the container backend
					# the claude-stub oneshot symlinks /root/.claude.json at the state PVC
					# (so config survives a restart), and a rename would replace that
					# symlink with an ephemeral regular file. `cat >` follows the symlink
					# to the PVC target; for the VM (a regular file) it is equivalent.
					cat "$f.tmp" > "$f" && rm -f "$f.tmp"
					chmod 600 "$f"
				'';

				# Container backend: seed instances/<COGBOX_INSTANCE>/config.json
				# (with the default network-rule seed) once at boot, so the
				# kubectl-exec'd control-plane verbs (rules/l7/plugin) have a config
				# to edit. `cogbox init`'s --init-only path is pure host-state
				# seeding -- on a fresh instance PLUGIN_COUNT is 0, so it never
				# rebuilds a runner or touches a VM. 'default' is reserved by
				# `cogbox init -n`, so the default instance omits -n (which writes
				# the same instances/default/config.json).
				cogboxInitScript = pkgs.writeShellScript "cogbox-init" ''
					set -eu
					inst="''${COGBOX_INSTANCE:-default}"
					cfg="''${XDG_CONFIG_HOME:-${stateRoot}/config}/cogbox/instances/$inst/config.json"
					if [ -f "$cfg" ]; then
						echo "cogbox-init: $cfg already present; skipping seed." >&2
						exit 0
					fi
					echo "cogbox-init: seeding config for instance '$inst'" >&2
					if [ "$inst" = "default" ]; then
						exec ${self.packages.${system}.cogbox-container}/bin/cogbox init -y
					else
						exec ${self.packages.${system}.cogbox-container}/bin/cogbox init -y -n "$inst"
					fi
				'';

				# Container backend: per-user Claude auth stub-staging
				# cogworx's reconcile sets the
				# marker file on the state PVC when it binds the owner's `claude-oauth`
				# setup-token into the enforcer (and clears it on disconnect); this
				# oneshot makes the guest's ~/.claude/.credentials.json match, so
				# claude-code boots "logged-in but tokenless" exactly when -- and only
				# when -- the owner has connected Claude. The enforcer stamps the real
				# Bearer over the inert stub; the real token never reaches the agent.
				#
				# ~/.claude{,.json} are backed by the state PVC (symlinks below) so both
				# the staged stub AND the harness's own config/history survive a
				# container restart (closes Phase 0). The marker + the stub also live
				# on the PVC, so a restart re-stages from the persisted marker. The
				# marker path + unit name are matched by convention with cogworx
				# (control-plane convention).
				claudeStubScript = pkgs.writeShellScript "cogbox-claude-stub" ''
					set -eu
					persist=${stateRoot}/claude-home
					cdir="$persist/.claude"
					cjson="$persist/.claude.json"
					marker=${stateRoot}/claude-oauth.bound

					mkdir -p "$cdir"
					chmod 700 "$persist" "$cdir"
					# claude-code gates INTERACTIVE startup on hasCompletedOnboarding in
					# ~/.claude.json (observed on 2.1.191): without it the first-run
					# wizard runs, and its "Select login method" step reads as an auth
					# prompt -- a dead end in the sandbox, where the wizard's OAuth hosts
					# are never in the l7 allow-list. The credential file alone is NOT
					# enough for an interactive boot (`claude -p` works either way, which
					# is how this gap survived the launch e2e). So seed (absent) or merge
					# (present) the onboarding state: hasCompletedOnboarding is forced
					# true (claude-code clears it on /logout; the next oneshot run
					# re-forces it), theme is only defaulted (never clobbers a user's
					# choice). The merge is a SINGLE slurped jq read (no guard-then-merge
					# TOCTOU, and a multi-document file is rejected, not concatenated)
					# and NON-FATAL: cogworx restarts this unit mid-session while
					# claude-code may be rewriting the file through the symlink, and a
					# torn read must neither kill the oneshot before the stub verb below
					# runs nor seed-reset away the user's config -- on any parse/shape
					# failure the file is left untouched (claude-code's own
					# corrupt-config handling deals with real rot). brain-trust later
					# enriches the same file (workspace trust).
					#
					# bypassPermissionsModeAccepted rides along for the same reason, and is
					# forced the same way. It records that the harness's first-run consent
					# dialog has been answered; unseeded, the `c` launcher stops on a fresh
					# sandbox at an interactive "1. No, exit / 2. Yes, I accept" prompt and
					# never reaches the REPL (bare `claude` is unaffected, which is how it
					# stayed hidden). Note it is a TOP-LEVEL key read off the global config
					# getter -- NOT a .projects[...] key like the trust dialog brain-trust
					# seeds -- so it belongs here and not under a project path. It must be
					# set on BOTH branches below: an existing config that only gets the
					# merge would keep gating. The dialog is long-standing, not new to
					# 2.1.220 (same occurrence counts in the 2.1.214 bundle).
					#
					# Posture note, since this pre-answers a warning dialog: it changes
					# nothing about what the agent may do. The launcher already requests
					# that mode unconditionally, and cogbox's containment is the sandbox
					# boundary (nftables floor, l4/l7 enforcer, guest isolation), never the
					# harness's own in-process prompts -- the sibling harnesses are set up
					# the same way on purpose (see the codex launcher flags and opencode's
					# OPENCODE_PERMISSION). The key also VANISHES after first run: the
					# harness migrates the acceptance into
					# userSettings.skipDangerousModePermissionPrompt and strips it, and
					# either source satisfies the check, so re-forcing it each boot is a
					# no-op and an absent key in a USED config is not a failed seed.
					seed='{"hasCompletedOnboarding":true,"bypassPermissionsModeAccepted":true,"theme":"dark"}'
					if [ -e "$cjson" ]; then
						if merged=$(${pkgs.jq}/bin/jq -es 'if length == 1 and (.[0] | type == "object") then .[0] | .hasCompletedOnboarding = true | .bypassPermissionsModeAccepted = true | .theme //= "dark" else error("not a single object") end' "$cjson" 2>/dev/null); then
							printf '%s\n' "$merged" > "$cjson.tmp" && mv "$cjson.tmp" "$cjson" || rm -f "$cjson.tmp"
						fi
					else
						printf '%s\n' "$seed" > "$cjson"
					fi
					chmod 600 "$cjson"
					# /root/.claude{,.json} may pre-exist as REAL files/dirs (the image
					# home skel / claude-code's own init runs before this oneshot). `ln
					# -sfn` against an existing DIR NESTS the link inside it
					# (/root/.claude/.claude -> ...) instead of replacing it, so the staged
					# stub lands at the wrong path and claude-code reports "Not logged in".
					# Drop any non-symlink first; on later boots the link already exists
					# (-L true) so ln -f just refreshes it.
					[ -L /root/.claude ] || rm -rf /root/.claude
					ln -sfn "$cdir" /root/.claude
					[ -L /root/.claude.json ] || rm -rf /root/.claude.json
					ln -sfn "$cjson" /root/.claude.json

					# Stage (marker present) or remove (absent) the redacted stub. The
					# verb single-sources the stub sentinel from the secret module,
					# never writes a real token, and TOUCHES ONLY a file carrying that
					# sentinel -- it neither removes NOR overwrites anything else (a
					# credential an in-guest /login wrote is the user's, and that
					# session supersedes the host-managed identity).
					${self.packages.${system}.cogbox-container}/bin/cogbox __claude-stub "$cdir" "$marker"
				'';

				# VM backend variant of the claude-stub reconcile. The container
				# claudeStubScript above is NOT reusable verbatim on the VM: its
				# ${stateRoot} marker/home paths are ephemeral on the VM (only
				# /var/lib/cogbox, the 9p mount, persists) and ~/.claude is an OVERLAY
				# mount the harness owns (the symlink dance would fight it). So this
				# variant only reconciles the cred file, against the marker on the
				# persistent mount, and -- crucially -- differs from the container in
				# how it reads an ABSENT marker:
				#
				#   marker ABSENT  -> UNMANAGED: a standalone single-host-user VM whose
				#     launcher staged its own redacted placeholder identity. Leave it
				#     untouched -- exit BEFORE calling the verb, because that placeholder
				#     carries the same sentinel the verb removes, and deleting it would
				#     break that model's on-the-wire injection.
				#   marker == "0"  -> cogworx MANAGED, owner DISCONNECTED (or never
				#     connected -- the control plane cannot tell those apart and writes
				#     "0" for both): hand it to the verb, which removes the stub (an
				#     overlay whiteout over the launcher placeholder) so claude-code falls
				#     back to in-guest /login. It removes ONLY a file carrying cogbox's
				#     own sentinel: a credential the user obtained with an in-guest
				#     /login lands at the same path, is theirs, and stays. Fail-closed
				#     does not depend on that file anyway -- cogworx unbinds the enforcer
				#     secret and the render gate then emits no inject spec at all.
				#   marker present, not "0" -> cogworx MANAGED, owner CONNECTED: stage the
				#     redacted sentinel (the pod-side proxy stamps the real Bearer over
				#     it), but ONLY over an absent file or cogbox's own sentinel -- a
				#     credential an in-guest /login wrote is the user's and supersedes
				#     the host-managed identity, so it is left alone (the verb warns to
				#     the journal when it skips). The real token never enters the guest.
				#
				# Both the sentinel AND the write/remove rule are single-sourced through
				# the verb (never hardcoded in this shell), so container and VM now share
				# one rule: "touch only what cogbox wrote" -- write AND remove. cogworx
				# writes the marker host-side on the 9p SOURCE and restarts this oneshot
				# (and it re-runs at every boot, so the persisted marker survives a
				# restart).
				claudeStubScriptVm = pkgs.writeShellScript "cogbox-claude-stub-vm" ''
					set -eu
					marker=/var/lib/cogbox/claude-oauth.bound
					[ -e "$marker" ] || exit 0
					${self.packages.${system}.cogbox-container}/bin/cogbox __claude-stub /root/.claude "$marker"
				'';
			in {
				nixpkgs.config.allowUnfree = true;

				# Discovered-unit name collisions are NOT asserted here: resolveKind
				# throws them from inside the skills/agents/commands/rules bindings
				# instead. config.assertions only fire through system.build.toplevel,
				# which the VM path forces but the container's boot-time brain rebuild
				# does not (it builds system.build.cogboxBrain) -- so the same collision
				# used to hard-fail a microVM and silently last-wins on a container.
				# One mechanism, both backends, and the error arrives earlier.
				assertions = lib.optional (mcpViolations != []) {
					assertion = false;
					message = "cogbox.mcp servers may only set command/args/env/url/headers; rejected: ${lib.concatStringsSep ", " mcpViolations}. MCP auth goes through host-side inject, never inline.";
				};

				# Point login-shell TLS tools at the L7 CA bundle too (the
				# harness launchers also bake these in for non-login `cogbox
				# ssh -- c` invocations).
				environment.variables = l7CaEnv;
				# environment.variables reaches login shells only. The gateway's
				# sshd runs `UsePAM yes`, so a non-interactive `ssh host cmd`
				# exec (VS Code Remote-SSH's transport) sources pam_env but NOT a
				# login shell -- it would otherwise get no CA env. Mirror the CA
				# trust into sessionVariables (delivered via pam_env) so TLS tools
				# work over exec sessions too. NixOS merges sessionVariables
				# across modules, so this coexists with nix-ld's own NIX_LD*
				# entries below (disjoint keys).
				environment.sessionVariables = l7CaEnv;

				# nix-ld lets dynamically-linked, non-Nix ELF binaries run in the
				# sandbox: VS Code Remote-SSH downloads a prebuilt glibc `node`
				# (vscode-server) and extension host that expect a standard
				# /lib64/ld-linux loader, which a pure-Nix guest lacks. The module
				# sets environment.ldso (the /lib64 stub), NIX_LD, and
				# NIX_LD_LIBRARY_PATH via environment.sessionVariables -- again
				# pam_env-delivered, so it reaches the exec sessions the server
				# runs under. The stock default library set (zlib, openssl, curl,
				# systemd, stdenv.cc.cc, ...) covers vscode-server's node; these
				# extras cover common VS Code extension native binaries.
				programs.nix-ld.enable = true;
				programs.nix-ld.libraries = with pkgs; [ stdenv.cc.cc.lib icu libsecret ];

				# Container target DNS: the kubelet writes /etc/resolv.conf (cluster
				# DNS, e.g. `nameserver 10.96.0.10`) into the pod and manages it at
				# runtime -- it is NOT an environment.etc entry. NixOS's resolvconf
				# default-enables resolvconf.service, which runs `openresolv -u` at
				# boot and regenerates /etc/resolv.conf from the (empty)
				# networking.nameservers, leaving it nameserver-less -> DNS broken.
				# Disable resolvconf for the container so the kubelet-provided file is
				# preserved (nothing else here touches /etc/resolv.conf). mkForce
				# guards against any other module flipping it back on; gated to the
				# container so the VM runner is byte-identical.
				networking.resolvconf.enable = lib.mkIf isContainer (lib.mkForce false);

				# VM target DNS: NO PUBLIC FALLBACK RESOLVER, EVER.
				#
				# The guest's own resolver is always link-scope and always comes
				# from the host: passt/SLIRP puts a nameserver in its DHCP offer
				# (the host's resolver on a local/k8s launch, the intercepted
				# `--dns-forward` handle where COGBOX_GUEST_RESOLVER is set), and
				# what that answers is by construction what the HOST resolves --
				# internal names included. The microvm target enables networkd,
				# which default-enables systemd-resolved, which arrives carrying
				# systemd's compiled-in FallbackDNS list (1.1.1.1, 8.8.8.8,
				# 9.9.9.9, ...) at GLOBAL scope. That list is not a safety net
				# here, it is a LEAK: any window where the link scope has no DNS
				# yet or its server is marked bad sends the query NAME -- an
				# internal name -- to a third-party resolver, and turns an
				# internal-DNS outage into an ordinary-looking NXDOMAIN instead
				# of a visible failure. An empty list means such a lookup fails,
				# loudly, which is the correct answer for a sandbox whose entire
				# egress story is mediated by the host.
				#
				# `""` (not `[]`): settings.Resolve is the freeform systemd-ini
				# surface, and an empty LIST renders no line at all, which is
				# indistinguishable from unset -- the defect itself. The empty
				# STRING renders `FallbackDNS=`, which is what overrides the
				# compiled-in list. Same reasoning, same spelling as the GCE
				# host half in gce/cogbox-host.nix.
				#
				# Ungated by target although only the VM has resolved enabled
				# (the container's /etc/resolv.conf is kubelet-managed and this
				# module turns resolvconf off for it above): the resolved module
				# emits nothing when disabled, so the container toplevel stays
				# byte-identical, and if resolved were ever enabled there it
				# would want this pin too.
				services.resolved.settings.Resolve.FallbackDNS = "";

				# Container web-terminal locale. The web terminal attaches via
				# `kubectl exec -- env ... tmux ...` (cogworx's terminal attach),
				# which sources NO login shell and inherits NO /etc/locale.conf, so
				# without a UTF-8 LANG in the container env LC_CTYPE stays C (ASCII)
				# and tmux/claude-code render as degraded boxes. The cogworx pod env +
				# baked OCI Env set LANG=C.UTF-8; this makes that locale resolvable.
				# C.UTF-8 is a glibc builtin, so restricting supportedLocales to it
				# keeps the multi-hundred-MB glibcLocales archive out of the closure
				# instead of building "all". Gated to the container; the VM is untouched.
				i18n.defaultLocale = lib.mkIf isContainer "C.UTF-8";
				i18n.supportedLocales = lib.mkIf isContainer [ "C.UTF-8/UTF-8" ];

				# Container web-terminal TUI colors. The outer `kubectl exec` forces
				# TERM=xterm-256color, but tmux's default default-terminal is the
				# 8-color "screen", so a TUI INSIDE a pane (claude-code) would still
				# see TERM=screen and render in 8 colors. Advertise a 256-color,
				# truecolor-capable terminal to pane processes. The tmux-256color
				# terminfo entry ships with ncurses (a tmux dependency, already in the
				# image closure). cogworx launches tmux with `-f /etc/tmux.conf` so
				# this is loaded regardless of tmux's compiled sysconfdir. Gated to the
				# container; the VM's host-side tmux is unaffected.
				environment.etc."tmux.conf" = lib.mkIf isContainer {
					text = ''
						set -g default-terminal "tmux-256color"
						set -ga terminal-overrides ",*256col*:Tc"
					'';
				};

				# nscd is the lone unit that goes "degraded" in the unprivileged
				# container: NixOS default-enables it, but it cannot write its cache
				# (EROFS) here, so `systemctl is-system-running` reports degraded on an
				# otherwise healthy boot. The sandbox resolves users from a static
				# passwd/group (glibc builtin `files` NSS) and DNS via the
				# kubelet-managed /etc/resolv.conf (glibc builtin `dns` NSS), so the
				# NSS cache buys nothing. mkForce overrides the NixOS default-on; gated
				# to the container so the VM keeps its default nscd.
				services.nscd.enable = lib.mkIf isContainer (lib.mkForce false);
				# NixOS routes EXTERNAL NSS modules (here only nss-systemd, for the
				# `systemd` userdb / DynamicUser) through nscd, so it asserts nscd-on
				# whenever system.nssModules is non-empty. The sandbox needs neither
				# DynamicUser nor the systemd userdb -- root and DNS resolve via the
				# glibc builtin `files`/`dns` sources, which need no module -- so drop
				# the external modules in lockstep with disabling nscd. mkForce []
				# clears the systemd contribution; gated to the container (the VM keeps
				# nss-systemd + nscd untouched).
				system.nssModules = lib.mkIf isContainer (lib.mkForce []);

				# Container under a userns (hostUsers:false): NixOS stage-2 activation
				# re-applies its hardened mount options to the special filesystems the
				# OCI runtime/kubelet already mounted (/proc, /dev, /dev/pts, /dev/shm)
				# with `mount -o remount`. A SYS_ADMIN confined to a non-initial userns
				# cannot change flags on a superblock owned by the init userns, so the
				# remount EPERMs; the specialfs snippet has no `|| true`, so its ERR
				# trap makes `activate` exit non-zero and wedges the boot
				# (CrashLoopBackOff). Override specialfs to make ONLY the already-mounted
				# (remount) branch non-fatal: in a NON-userns container (today's live
				# deploy) the remount still SUCCEEDS and applies nosuid/noexec/nodev
				# exactly as upstream -- zero behavior change; only under a userns does
				# it fall through to "keep the runtime's mount as-is". The fresh-mount
				# branch (/run tmpfs, /run/keys ramfs -- userns-mountable and NOT
				# runtime-provided) stays FATAL so a genuinely missing mount errors
				# loudly (same "no silent || true" stance as the cgroup fix in a87dc47).
				# Sources the upstream earlyMountScript so the special-fs set can never
				# drift. Gated to the container; the VM/microvm path is byte-identical.
				system.activationScripts.specialfs = lib.mkIf isContainer (lib.mkForce ''
					specialMount() {
						local device="$1"
						local mountPoint="$2"
						local options="$3"
						local fsType="$4"

						if mountpoint -q "$mountPoint"; then
							mount -t "$fsType" -o "remount,$options" "$device" "$mountPoint" || true
						else
							mkdir -p "$mountPoint"
							chmod 0755 "$mountPoint"
							mount -t "$fsType" -o "$options" "$device" "$mountPoint"
						fi
					}
					source ${config.system.build.earlyMountScript}
				'');

				# Enabled on BOTH targets. The VM keeps its historical loopback
				# key-auth path (see below); the container adds a
				# certificate-authenticated sshd the cogworx SSH gateway dials with
				# a short-lived user cert (cogbox-sshd-ca staging the CA + principals).
				services.openssh.enable = true;
				# Auth hardening forced on BOTH targets. root has an EMPTY password on
				# the guest (VM serial-console UX), so password/empty-password/keyboard-
				# interactive auth MUST be unusable over the wire; root logs in by key
				# (VM) or user cert (container) only. mkForce so a NixOS default or a
				# plugin's full NixOS module can never re-enable them.
				services.openssh.settings = {
					PasswordAuthentication = lib.mkForce false;
					KbdInteractiveAuthentication = lib.mkForce false;
					PermitEmptyPasswords = lib.mkForce false;
					PermitRootLogin = lib.mkForce "prohibit-password";
					# `cogbox ssh` pins to a single key with IdentitiesOnly +
					# IdentityAgent=none (see zig/src/cli/verbs/ssh.zig), so its
					# default path makes exactly one auth attempt and can't exhaust
					# the limit. The generous cap is kept for the --no-auto-keys
					# opt-out path, where ssh falls back to the user's agent and
					# ~/.ssh keys and a busy agent could otherwise burn through the
					# default 6 attempts before a working key is reached. This guest
					# is a local, ephemeral, single-user sandbox (sshd bound to
					# 127.0.0.1), so a generous cap is safe. The k8s gateway path gets
					# a tight cap below (MaxAuthTries keyed per target in the shared
					# block), the local VM keeps 50.
				} // lib.optionalAttrs (isContainer || isVm) {
					# The gateway authenticates with a user certificate signed by a
					# cogworx-held CA; trust that CA and require the cert's principal
					# to match this instance (AuthorizedPrincipalsFile lists exactly
					# the instance ID). BOTH cluster-launched targets get this: the
					# container reads the CA/principal from pod env (cogbox-sshd-ca),
					# the VM reads them from the 9p-persistent state that cogworx
					# stages before boot (/var/lib/cogbox/.config, seeded by the k8s
					# pod entrypoint). The paths differ per target; everything else is
					# shared. (A purely-local `cogbox` VM leaves these files absent ->
					# no trusted CA -> cert auth simply never succeeds, fail-closed,
					# and plain authorized_keys still works via load-ssh-keys.)
					TrustedUserCAKeys = if isContainer then "/etc/ssh/trusted_user_ca.pub" else "/var/lib/cogbox/.config/ssh-ca.pub";
					AuthorizedPrincipalsFile = if isContainer then "/etc/ssh/principals/%u" else "/var/lib/cogbox/.config/ssh-principals/%u";
					# The gateway only needs local (client-initiated) port forwards to
					# reach in-sandbox services; deny everything else.
					AllowTcpForwarding = "local";
					AllowStreamLocalForwarding = "no";
					GatewayPorts = "no";
					X11Forwarding = false;
					# Permit ssh-agent forwarding so in-sandbox tools can reuse the
					# user's keys (e.g. git push). sshd only sets the ceiling here; the
					# gateway's short-lived cert (permit-agent-forwarding) is the actual
					# per-connection gate, driven by cogworx's COGWORX_SSH_AGENT_FORWARDING
					# (default on) -- with that off the sshd allowance is simply unused.
					AllowAgentForwarding = true;
					PermitTunnel = "no";
					# The cluster gateway/`cogbox ssh` hop makes exactly one
					# cert/key attempt, so a tight cap is correct there; a purely-
					# local VM keeps the generous cap for the --no-auto-keys agent
					# fallback (see the base comment above).
					MaxAuthTries = if isContainer then 3 else 50;
					LoginGraceTime = 20;
					ClientAliveInterval = 30;
					ClientAliveCountMax = 4;
					AllowUsers = [ "root" ];
				};
				# Container sshd binds all interfaces so the gateway pod can reach it;
				# the VM keeps the module default (reached only via the QEMU loopback
				# forward on 127.0.0.1:2222).
				services.openssh.listenAddresses = lib.mkIf isContainer [
					{ addr = "0.0.0.0"; port = 22; }
				];
				# Persist the sandbox host key so the gateway's TOFU host-key pin
				# survives restarts (a rotating key would break the pin on every
				# boot). The container persists on the state PVC (cogbox-container-
				# state creates the 0700 dir); the VM persists on the 9p-backed
				# /var/lib/cogbox mount (cogbox-vm-sshd-prep creates the 0700 dir and
				# pre-generates the key BEFORE sshd, ordered after var-lib-cogbox.mount,
				# so sshd never races the late 9p mount). A purely-local `cogbox` VM
				# gets the same persistent key under its host data dir.
				services.openssh.hostKeys = lib.mkIf (isContainer || isVm) [
					{ type = "ed25519"; path = if isContainer then "${stateRoot}/ssh/ssh_host_ed25519_key" else "/var/lib/cogbox/ssh/ssh_host_ed25519_key"; }
				];

				environment.systemPackages = with pkgs; [
					git
					curl
					jq
					vim
					ncdu
					tmux
					htop
					# certutil: cogbox-l7-trust.service imports the per-instance MITM
					# CA into root's NSS db with it (so Chromium/Playwright trust the
					# terminate tier); also handy for inspecting that trust.
					nss.tools

					# Generic CLI toolkit, broadly useful to any in-guest agent or
					# task. Grouped by purpose; jq/curl/git are above.
					# search / files
					ripgrep fd bat sd
					# data wrangling
					yq-go duckdb miller dasel gron datamash jo
					# http / dns / web
					xh websocat dnsutils htmlq pup
					# shell glue (moreutils brings sponge/ts/chronic/ifne/vipe; for
					# parallelism `xargs -P` is already present, so no GNU parallel)
					moreutils
				]
				++ lib.concatMap (h: [ h.package (mkLauncher h) ]) (lib.attrValues harnesses)
				++ lib.optionals (harnesses ? "dsh") [
					# `dsh plugin --profile <name> <pnpm args>` forwards to
					# pnpm; without it the only broken surface is plugin
					# management (web/headless profiles self-initialize).
					pkgs.pnpm
				]
				++ lib.optionals hasNixMcp [
					nix-mcp.packages.${system}.default
				]
				++ lib.optionals (system != "riscv64-linux") [
					bpftrace
				]
				# Container backend: the cogbox CLI itself, so cogworx can
				# `kubectl exec <pod> -c agent -- cogbox <verb> -n <name>` to drive
				# the control-plane verbs (init/rules/l7/remap/plugin) on the running
				# sandbox. Lands `cogbox`/`cbx` in /run/current-system/sw/bin (on the
				# agent-image PATH). The VM never carries the CLI in-guest (it is the
				# host-side launcher there), so gate it to the container.
				++ lib.optional isContainer self.packages.${system}.cogbox-container
				# Plugin-contributed tools (cogbox.packages). On the VM the runner
				# rebuild bakes these into the guest closure here; on the container
				# they reach PATH via cogbox-brain's $out/bin instead (the baked base
				# image is plugin-less), so this line is an inert no-op there.
				++ cfg.packages;

				# Expose the materialized plugin "brain" as a build product so the
				# container can rebuild it per-instance at boot. config.cogbox (hence
				# this derivation) is target-independent, so it is the SAME drv on the
				# VM and container configs; adding it here does not touch the microvm
				# runner closure (which references neither system.build.cogboxBrain nor
				# the toplevel's full system.build). The container's
				# cogbox-brain-materialize builds
				# `nixosConfigurations.${configName}.config.system.build.cogboxBrain`
				# with `--override-input userExtensions <instance composition>` -- the
				# exact mechanism cogbox-launch.sh uses to fold per-instance plugins
				# into the VM runner.
				system.build.cogboxBrain = cogbox-brain;
				# The unresolvable-collision messages, WITHOUT the throw that
				# cogboxBrain carries. Forcing the brain is the user-facing failure;
				# forcing this list is how a check reads the exact text that failure
				# prints (builtins.tryEval reports that an eval threw, never why).
				system.build.cogboxBrainCollisions = brainCollisions;
				# The resolved unit -> path maps, keyed by FINAL (possibly qualified)
				# name. The brain swallows them whole, so this is the only handle a
				# check has on ONE qualified copy -- specifically on a copy that must
				# REFUSE to build, which is a builder failure rather than an eval
				# throw and therefore invisible to cogboxBrainCollisions.
				system.build.cogboxBrainUnits = { inherit skills agents commands rules; };

				microvm = lib.mkIf isVm {
					writableStoreOverlay = "/nix/.rw-store";
					# Cogbox owns the singular runtime hook. A user extension that
					# defines a different extraArgsScript gets a normal Nix conflicting-
					# definitions error instead of silently disabling dynamic shares;
					# extension-owned static arguments belong in qemu.extraArgs.
					extraArgsScript = "${runtimeDir}/additional-dir-args";
					forwardPorts = [
						{ from = "host"; host.port = 2222; host.address = "127.0.0.1"; guest.port = 22; }
						{ from = "host"; host.port = 8080; host.address = "127.0.0.1"; guest.port = 8080; }
					];
					shares = map (p: {
						proto = "9p";
						tag = tag p.harness p.pathkey;
						source = sentinel p.harness p.pathkey;
						mountPoint = lowerMount p.harness p.pathkey;
						# THE security property of the harness layout, in one word, in
						# both profiles: QEMU exports the host's harness config
						# read-only, so a compromised agent cannot write back into it.
						# Every guest write lands in the per-instance overlay upper
						# instead. Nothing in the storage profiles touches this.
						readOnly = true;
					}) overlayPaths;
					# The user's data pool, plus (hosted only) the writable /nix/store
					# overlay. microvm.nix wires each volume as virtio-blk with
					# discard=unmap already set, and generates a fileSystems entry for
					# each mountPoint carrying only `device` and `fsType` -- never
					# `options` -- so the pool's mount options and autoResize below
					# merge onto it with no mkForce.
					volumes = lib.optionals poolEnabled ([ ({
						mountPoint = poolMount;
						fsType = "ext4";
						label = poolLabel;
					} // (if hosted then {
						image = hostedPoolLV;
						# MUST be explicit, on BOTH hosted volumes. microvm.nix defaults
						# autoCreate to TRUE and its guard is `[ ! -e "$image" ]` -- an
						# EXISTENCE check that follows symlinks, not a filesystem check.
						# Left true, a logical volume that did not get activated (an
						# unattached disk, a volume group the host refused to touch)
						# would be touch'ed into a regular FILE under /dev, truncated
						# and mkfs'd, handing the user a blank pool while their real
						# disk sat there intact. This disk holds the only copy of their
						# work tree, so that failure is worse than an over-eager mkfs,
						# and it is reachable through the dependency rather than through
						# any cogbox code.
						#
						# The cost of false is that microvm.nix applies NO label (it
						# warns exactly that at eval time), which is why the GCE host
						# half formats AND labels both logical volumes before the VM is
						# launched.
						autoCreate = false;
						# `size` is deliberately omitted: the submodule gives it no
						# default, but it is only forced inside the autoCreate branch of
						# createVolumesScript. VERIFIED BY EVALUATION, not by reading.
						# The host sizes both volumes -- see cogworx.gce.
					} else {
						# ${dataDir} is the /tmp/cogbox/data sentinel cogbox-launch.sh
						# sed-rewrites to $RUNTIME/data, itself a symlink to the
						# instance's persistent data dir -- so the image survives
						# restarts with no launcher change. The rewrite happens inside
						# bin/microvm-run, which is where createVolumesScript runs.
						image = "${dataDir}/machine-state.img";
						autoCreate = true;   # truncate + mkfs.ext4 -L <label>
						size = storageCfg.sizeMiB;
					})) ] ++ lib.optional hosted {
						# See hostedStoreLV above for why this is a second volume and
						# not a subdirectory of the pool. mountPoint == writableStoreOverlay
						# is what makes microvm.nix mark it neededForBoot, which is
						# exactly what the /nix/store overlay needs -- and it is the
						# whole reason this is a separate logical volume rather than a
						# directory in the pool, so do not fold it back in.
						mountPoint = "/nix/.rw-store";
						fsType = "ext4";
						label = storeOverlayLabel;
						image = hostedStoreLV;
						# Same reasoning as the pool: the host carves and formats this
						# logical volume, so microvm.nix must neither create nor size it.
						autoCreate = false;
					});
					# A human (HMP) QEMU monitor on a per-instance socket, for
					# `cogbox monitor`. The microvm module already wires a QMP
					# control socket (qemu.socket -> -qmp); this is the separate
					# readline monitor humans actually want to type at. The
					# ${runtimeDir} sentinel is sed-rewritten to the live $RUNTIME
					# by cogbox-launch.sh, same as the fw_cfg paths below.
					qemu.extraArgs = [
						# Re-emit `-cpu` to mask RDRAND/RDSEED off the guest CPU while
						# KEEPING KVM accel. microvm.nix's own runner emits
						# `-enable-kvm -cpu host,+x2apic,-sgx`; setting the microvm.cpu
						# option would override that string BUT the module then also
						# drops `-enable-kvm` (qemu.nix gates it on `cpu == null`), so we
						# cannot use it. Instead we append a second `-cpu` here: qemu
						# honors the LAST `-cpu` (verified: no warning, last wins) and
						# `-enable-kvm` stays. Without this the guest kernel wedges at
						# early boot ("Poking KASLR using RDRAND RDTSC...") because
						# executing RDRAND can stall the vcpu under nested KVM;
						# masking it forces the RDTSC entropy
						# fallback. Mirrors microvm's own base string so only rdrand/rdseed
						# differ. VM-only (isVm); the container has no qemu args.
						"-cpu"
						"host,+x2apic,-sgx,-rdrand,-rdseed"
						"-monitor"
						"unix:${runtimeDir}/monitor.sock,server,nowait"
					] ++ lib.concatMap (p: [
						"-fw_cfg"
						"name=opt/${tag p.harness p.pathkey},file=${sentinel p.harness p.pathkey}"
					]) fwCfgPaths ++ [
						# System (instance-level, not per-harness) fw_cfg payloads.
						# Both are always emitted and staged, including empty forms, so
						# the guest closure is independent of per-launch state.
						"-fw_cfg"
						"name=opt/system-l7ca,file=${runtimeDir}/system-l7ca"
						"-fw_cfg"
						"name=opt/system-additional-dirs,file=${runtimeDir}/system-additional-dirs"
					];
				};
				# re-run the L7 trust assembly whenever the enforcer (re)publishes
				# its CA, so a CA that arrives after cogbox-l7-trust's boot window still
				# gets trusted (else allowed HTTPS silently fails until the next reboot).
				systemd.paths.cogbox-l7-trust = lib.mkIf isContainer {
					description = "Watch the enforcer-published L7 CA and rebuild the trust bundle";
					wantedBy = [ "multi-user.target" ];
					pathConfig = {
						PathChanged = l7CaSource;
						Unit = "cogbox-l7-trust-refresh.service";
					};
				};


				# Per-fw_cfg copy services. Each one materializes a single
				# host file (auth token, etc.) into its guest path at boot.
				# fw_cfg copy units are a VM-only mechanism (the container has no
				# /sys/firmware/qemu_fw_cfg); gate the whole generated set off so
				# the container drops them. optionalAttrs (not mkIf) so the keys
				# vanish entirely rather than evaluate to dropped definitions.
				systemd.services = lib.optionalAttrs isVm (lib.listToAttrs (map (p:
					lib.nameValuePair "${p.harness}-${p.pathkey}" {
						description = "Copy ${p.harness}/${p.pathkey} from fw_cfg";
						wantedBy = [ "multi-user.target" ];
						# Order BEFORE sshd: otherwise a client that connects the moment
						# sshd is up (ttyd -> cogbox ssh ... c) can read this file while
						# the cp below is still writing it, which surfaces as
						# "<file> contains invalid JSON" on the first harness launch
						# (later launches see the finished file). Mirrors cogbox-l7-trust.
						before = [ "multi-user.target" "sshd.service" ];
						serviceConfig = {
							Type = "oneshot";
							# Write to a temp then rename so the target appears atomically
							# (whole file or nothing), never a half-written partial.
							ExecStart = "/bin/sh -c 'cp /sys/firmware/qemu_fw_cfg/by_name/opt/${tag p.harness p.pathkey}/raw ${p.guest}.tmp && chmod ${p.mode} ${p.guest}.tmp && mv ${p.guest}.tmp ${p.guest}'";
							RemainAfterExit = true;
						};
					}
				) fwCfgPaths)) // {
					cogbox-additional-dirs = {
						description = "Validate and mount launch-only host directories";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "sshd.service" ];
						after = [ "systemd-modules-load.service" ];
						path = [ pkgs.jq pkgs.coreutils pkgs.util-linux ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							TimeoutStartSec = 120;
							ExecStart = pkgs.writeShellScript "cogbox-additional-dirs-start" ''
								set -euo pipefail

								manifest=/sys/firmware/qemu_fw_cfg/by_name/opt/system-additional-dirs/raw
								mounted=()

								fail() {
									echo "cogbox-additional-dirs: $*" >&2
									exit 1
								}
								path_at_or_below() {
									[ "$1" = "$2" ] || [[ "$1" == "$2/"* ]]
								}
								paths_overlap() {
									[ "$1" = "$2" ] || [[ "$1" == "$2/"* ]] || [[ "$2" == "$1/"* ]]
								}
								rollback() {
									local rc=$?
									if [ "$rc" -ne 0 ]; then
										for ((i = ''${#mounted[@]} - 1; i >= 0; i--)); do
											if mountpoint -q -- "''${mounted[i]}"; then
												umount -- "''${mounted[i]}" || true
											fi
										done
									fi
								}
								trap rollback EXIT

								jq -e '
									type == "array"
									and all(.[];
										type == "object"
										and (keys == ["readOnly", "tag", "target"])
										and (.tag | type == "string")
										and (.target | type == "string")
										and (.readOnly | type == "boolean")
									)
								' "$manifest" >/dev/null \
									|| fail "firmware payload must be an array of exact tag/target/readOnly objects"

								mapfile -t entries < <(jq -c '.[]' "$manifest")
								protected_targets=( ${lib.escapeShellArgs ([
									"/var/lib/cogbox"
									poolMount
									"/var/lib/harness-lower"
									"/var/lib/harness-rw"
									"/root/work"
								] ++ map (p: p.guest) allPaths)} )

								# Validate the complete manifest before creating a target or
								# mounting anything. The rollback trap still protects the
								# mount loop against a later runtime failure.
								for i in "''${!entries[@]}"; do
									entry="''${entries[i]}"
									tag=$(jq -r '.tag' <<<"$entry")
									target=$(jq -r '.target' <<<"$entry")
									read_only=$(jq -r '.readOnly' <<<"$entry")
									[ "$tag" = "cogbox-add-dir-$i" ] \
										|| fail "non-contiguous or invalid mount tag at index $i"
									[ "$target" != / ] \
										|| fail "target / is not permitted"
									for special_root in /dev /proc /sys /run /nix; do
										if path_at_or_below "$target" "$special_root"; then
											fail "target $target is at or below protected path $special_root"
										fi
									done
									for protected in "''${protected_targets[@]}"; do
										if paths_overlap "$target" "$protected"; then
											fail "target $target overlaps protected guest path $protected"
										fi
									done
									canonical=$(realpath -m -- "$target") \
										|| fail "cannot resolve target $target"
									[ "$canonical" = "$target" ] \
										|| fail "target is not canonical or crosses an existing symlink: $target"
									case "$read_only" in
										true|false) ;;
										*) fail "readOnly is not boolean at index $i" ;;
									esac
								done

								for i in "''${!entries[@]}"; do
									entry="''${entries[i]}"
									tag=$(jq -r '.tag' <<<"$entry")
									target=$(jq -r '.target' <<<"$entry")
									read_only=$(jq -r '.readOnly' <<<"$entry")
									mkdir -p -- "$target"
									[ "$(realpath -m -- "$target")" = "$target" ] \
										|| fail "target changed through a symlink before mount: $target"
									mode=rw
									[ "$read_only" = true ] && mode=ro
									mount -t 9p \
										-o "trans=virtio,version=9p2000.L,msize=65536,$mode" \
										"$tag" "$target"
									mounted+=("$target")
								done
							'';
							ExecStop = pkgs.writeShellScript "cogbox-additional-dirs-stop" ''
								set -uo pipefail

								manifest=/sys/firmware/qemu_fw_cfg/by_name/opt/system-additional-dirs/raw
								[ -r "$manifest" ] || exit 0
								mapfile -t targets < <(jq -r 'reverse[].target' "$manifest")
								rc=0
								for target in "''${targets[@]}"; do
									if mountpoint -q -- "$target"; then
										umount -- "$target" || rc=1
									fi
								done
								exit "$rc"
							'';
						};
					};
					cogbox-brain-materialize = let
						# The mount this unit writes THROUGH: hermes skills are linked into
						# the overlay UPPER, so linking before the mount writes to the
						# covered rootfs. Named once and fed to all three of after/requires/
						# wants, because the ordering is wanted in every profile and only
						# the strength of the dependency differs.
						hermesMount = lib.optional (isVm && harnesses ? "hermes-agent") "/root/.hermes";
					in {
						description = "Materialize the cogbox plugin brain into ~/work";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "sshd.service" ];
						after = [ stateUnit ]
							++ lib.optional isContainer "cogbox-init.service"
							++ lib.optional (isVm && harnesses ? "codex") "${utils.escapeSystemdPath "/root/.codex"}.mount"
							++ map mountUnitOf hermesMount;
						# hardMounts/softMounts, not a flat Requires=: under `hosted` that
						# overlay's upper and work dirs live under the pool-bound
						# /var/lib/harness-rw, so a hard Requires= means a pool-absent boot
						# does not materialise the brain AT ALL -- no .cogbox/brain, no
						# skills/agents/commands, no AGENTS.md -- when the degradation is
						# only supposed to cost that boot its harness CONFIG. Wants= keeps
						# the mount pulled in and the After= above keeps the ordering, so
						# nothing changes on a healthy boot. In the workstation profile the
						# same call keeps the Requires=: there the overlay rests on the loop
						# image, which is a genuine precondition in every case.
						requires = [ stateUnit ] ++ hardMounts hermesMount;
						wants = softMounts hermesMount;
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							ExecStart = brainMaterializeScript;
							# The container arm rebuilds the brain with `nix build`, whose
							# duration is set by the plugin closure the USER installed, so
							# there is no honest bound: a cap here would turn a slow
							# first-boot plugin build into a sandbox with no brain. Stated
							# rather than left to the Type=oneshot default so the unit file
							# says which of the two it is (systemd.service(5): oneshot
							# DISABLES the start timeout unless it is set).
							#
							# The VM arm is bounded, because there this script only mkdirs
							# and symlinks under $WORK -- a wedged 9p share or a wedged pool
							# bind is the only way it can take minutes, and this unit is
							# Before=sshd.service, so unbounded that is a guest with no sshd
							# and nothing in `systemctl --failed`. At the bound the unit
							# fails loudly, sshd proceeds, and the sandbox comes up with the
							# pre-plugin work tree.
							TimeoutStartSec = if isContainer then "infinity" else 600;
						} // lib.optionalAttrs isContainer {
							# COGBOX_INSTANCE picks which instance's composition flake the
							# brain rebuilds from; XDG_CONFIG_HOME locates it. systemd does
							# not forward PID1's env, so set/pass them explicitly.
							Environment = [ "XDG_CONFIG_HOME=${stateRoot}/config" ];
							PassEnvironment = [ "COGBOX_INSTANCE" ];
						};
					};
					cogbox-brain-trust = {
						description = "Pre-accept Claude Code workspace trust for ~/work";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "sshd.service" ];
						after = [ stateUnit "cogbox-brain-materialize.service" ]
							++ lib.optional isContainer "cogbox-claude-stub.service"
							++ lib.optional (isVm && harnesses ? "claude-code") "claude-code-auth.service";
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							ExecStart = brainTrustScript;
						};
					};
					# Crash-loop guard for the per-instance full toplevel. agentInit writes
					# a toplevel.attempt marker (the out-path) BEFORE exec'ing a per-instance
					# toplevel; this oneshot clears it once THIS booted system is confirmed to
					# be that recorded toplevel. If the toplevel fails to boot, systemd never
					# reaches here, the marker persists, and the next boot falls back to the
					# baked base (quarantining the unbootable toplevel until a re-add produces a
					# new out-path). Only clears when the running system IS the recorded
					# toplevel, so a crash that fell back to base keeps the quarantine.
					cogbox-toplevel-confirm = lib.mkIf isContainer {
						description = "Clear the per-instance toplevel crash-loop marker on a good boot";
						wantedBy = [ "multi-user.target" ];
						after = [ stateUnit "cogbox-brain-materialize.service" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							Environment = [ "XDG_CONFIG_HOME=${stateRoot}/config" ];
							PassEnvironment = [ "COGBOX_INSTANCE" ];
						};
						script = ''
							inst="''${COGBOX_INSTANCE:-default}"
							icd="${stateRoot}/config/cogbox/instances/$inst"
							rec="$icd/toplevel.path"
							[ -f "$rec" ] || exit 0
							recorded="$(${pkgs.coreutils}/bin/head -n2 "$rec" | ${pkgs.coreutils}/bin/tail -n1)"
							cur="$(${pkgs.coreutils}/bin/readlink -f /run/current-system)"
							if [ -n "$recorded" ] && [ "$cur" = "$recorded" ]; then
								${pkgs.coreutils}/bin/rm -f "$icd/toplevel.attempt"
							fi
						'';
					};
					# Boot reconcile for the per-instance full toplevel. The add-time toplevel
					# prebuild only runs on the LIVE agent pod (running-instance adds); a
					# stopped/fresh add (worker pod) writes no toplevel record, so its
					# non-package module surface wouldn't take effect. This oneshot -- run AFTER
					# boot completes (multi-user.target => egress up, and the base is already in
					# the image store) -- builds + records the toplevel from the already-
					# materialized composition, so the NEXT Start boots the per-instance
					# toplevel. It also self-heals across image bumps. `after multi-user.target`
					# makes it truly background: the sandbox is Ready (the readiness probe gates
					# on brain-materialize, well before this) while the reconcile builds. The
					# `reconcile` verb no-ops fast when nothing changed (composition-hash guard)
					# and removes the record when no plugins remain (revert to base). Best-effort.
					cogbox-toplevel-reconcile = lib.mkIf isContainer {
						description = "Reconcile + record the per-instance full toplevel for the next boot";
						wantedBy = [ "multi-user.target" ];
						after = [ "multi-user.target" ];
						serviceConfig = {
							Type = "oneshot";
							# cogbox resolves the instance config from $XDG_CONFIG_HOME/cogbox/...
							# (else $HOME/.config, which is /.config with HOME unset -> "no config
							# found" -> the || true swallows it -> silent no-op). systemd does not
							# forward PID1's env, so set it explicitly (same as brain-materialize).
							Environment = [ "XDG_CONFIG_HOME=${stateRoot}/config" ];
							PassEnvironment = [ "COGBOX_INSTANCE" ];
						};
						script = ''
							inst="''${COGBOX_INSTANCE:-}"
							cbx=${self.packages.${system}.cogbox-container}/bin/cogbox
							# The plugin verb resolves the instance from -n only (not the env), and
							# rejects the reserved name "default"; omit -n for the default instance.
							# Best-effort: never fail the unit -- a miss just leaves the last record.
							if [ -n "$inst" ] && [ "$inst" != "default" ]; then
								"$cbx" plugin reconcile -n "$inst" || true
							else
								"$cbx" plugin reconcile || true
							fi
						'';
					};
					# Assemble the L7 CA trust bundle: system store + the injected
					# per-instance MITM CA (when terminate is active). Always
					# produces ${l7CaBundle} so the CA env vars resolve even when
					# terminate is off (then it is just the system bundle).
					cogbox-l7-trust = {
						description = "Assemble the L7 terminate-tier CA trust bundle";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "sshd.service" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# cogbox-l7-trust.path/refresh restarts this unit when the enforcer
							# CA lands; if that happens while the boot run is still in its bounded
							# CA wait, the restart SIGTERMs it. For Type=oneshot systemd does NOT
							# treat SIGTERM as success, so the superseded (idempotent) initial run
							# would otherwise surface as a failed unit -- mark SIGTERM successful.
							SuccessExitStatus = "SIGTERM";
							ExecStart = pkgs.writeShellScript "cogbox-l7-trust" ''
								set -e
								mkdir -p /run/cogbox
								raw=${l7CaSource}${lib.optionalString isContainer ''
								  # The enforcer sidecar mints the CA then publishes the cert to the
								  # ca-pub mount asynchronously. BLOCK (bounded, ~60s) so the bundle + NSS
								  # import below actually include it and harness egress never opens before
								  # the CA is trusted. The nft divert is fail-closed meanwhile, so a timeout
								  # here degrades to the system bundle, never opens an untrusted hole.
								  for _ in $(seq 1 300); do
								  	[ -s "$raw" ] && break
								  	sleep 0.2
								  done''}
								ca=/run/cogbox/l7-ca.crt
								bundle=${l7CaBundle}
								sys=/etc/ssl/certs/ca-certificates.crt
								[ -r "$sys" ] || sys=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
								: > "$ca"
								[ -r "$raw" ] && cp "$raw" "$ca" || true
								if [ -s "$ca" ] && grep -q "BEGIN CERTIFICATE" "$ca"; then
									cat "$sys" "$ca" > "$bundle"
								else
									cp "$sys" "$bundle"
								fi
								chmod 0644 "$bundle"

								# NSS-based clients -- notably Chromium / Playwright, which
								# ignore the CA env vars AND the bundle file above -- read
								# trusted roots from the per-user NSS db. Mirror the CA into
								# root's db so browser-driven plugins trust terminate-tier
								# leaves too. Idempotent across boots and terminate on/off:
								# (re)create the db (the cert9.db guard avoids a certutil -N
								# re-init prompt), drop any prior copy, re-add only when a real
								# CA is present. Best-effort (set +e): the env-var bundle still
								# covers non-NSS clients, so a certutil hiccup must degrade
								# browser trust, never fail this boot-ordered unit.
								set +e
								db=/root/.pki/nssdb
								mkdir -p "$db"
								[ -e "$db/cert9.db" ] || ${pkgs.nss.tools}/bin/certutil -N --empty-password -d "sql:$db"
								${pkgs.nss.tools}/bin/certutil -D -n cogbox-l7-ca -d "sql:$db" 2>/dev/null
								if [ -s "$ca" ] && grep -q "BEGIN CERTIFICATE" "$ca"; then
									${pkgs.nss.tools}/bin/certutil -A -n cogbox-l7-ca -t "C,," -i "$ca" -d "sql:$db"
								fi
								set -e
							'';
						};
					};
					# self-heal: the enforcer publishes its CA to l7CaSource
					# asynchronously; a slow (cold image pull) enforcer pod can land it
					# AFTER cogbox-l7-trust's ~60s boot window, leaving the agent on the
					# bare system bundle so every allowed HTTPS fails until reboot
					# (fail-closed, no leak). The .path above runs this on the CA's
					# (re)appearance; restarting the trust unit re-runs its idempotent
					# bundle+NSS assembly, now with the CA present. Container-only
					# (the VM delivers the CA via fw_cfg before boot).
					cogbox-l7-trust-refresh = lib.mkIf isContainer {
						description = "Rebuild the L7 CA trust bundle when the enforcer CA (re)appears";
						serviceConfig = {
							Type = "oneshot";
							ExecStart = "${pkgs.systemd}/bin/systemctl restart cogbox-l7-trust.service";
						};
					};
					load-ssh-keys = lib.mkIf isVm {
						description = "Load SSH authorized keys from shared config";
						wantedBy = [ "multi-user.target" ];
						before = [ "sshd.service" ];
						after = [ "var-lib-cogbox.mount" ];
						requires = [ "var-lib-cogbox.mount" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							ExecStart = pkgs.writeShellScript "load-ssh-keys" ''
								keyfile=/var/lib/cogbox/.config/authorized_keys
								if [ -f "$keyfile" ] && [ -s "$keyfile" ]; then
									mkdir -p /root/.ssh
									chmod 700 /root/.ssh
									cp "$keyfile" /root/.ssh/authorized_keys
									chmod 600 /root/.ssh/authorized_keys
								fi
							'';
						};
					};
					# VM backend: prepare the persistent sshd host key + the gateway
					# CA/principal files on the 9p-backed /var/lib/cogbox BEFORE sshd
					# starts. The container backend does the equivalent from pod env
					# (cogbox-sshd-ca); the VM cannot read pod env, so cogworx's k8s
					# pod entrypoint stages the real CA/principal into this same 9p
					# source before boot and sshd reads them directly (TrustedUserCAKeys
					# /AuthorizedPrincipalsFile point here). Ordered after the 9p mount
					# so the (late) mount is up, and before sshd so the key + dirs exist.
					cogbox-vm-sshd-prep = lib.mkIf isVm {
						description = "Prepare the VM's persistent sshd host key + gateway CA/principal dirs";
						wantedBy = [ "multi-user.target" ];
						before = [ "sshd.service" ];
						after = [ "var-lib-cogbox.mount" ];
						requires = [ "var-lib-cogbox.mount" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							ExecStart = pkgs.writeShellScript "cogbox-vm-sshd-prep" ''
								set -eu
								# Persistent host-key dir (0700 so the private key is not
								# group/world readable) + the gateway CA/principal dir.
								mkdir -p /var/lib/cogbox/ssh /var/lib/cogbox/.config/ssh-principals
								chmod 700 /var/lib/cogbox/ssh
								# Pre-generate the persistent host key here rather than leaving
								# it to sshd's own keygen, so it exists on the (late) 9p mount
								# before sshd regardless of the module's keygen timing. A
								# stable key is what keeps the gateway's TOFU pin valid across
								# restarts.
								key=/var/lib/cogbox/ssh/ssh_host_ed25519_key
								[ -s "$key" ] || ${pkgs.openssh}/bin/ssh-keygen -t ed25519 -N "" -C cogbox-vm -f "$key"
								# Fail-closed CA/principal: cogworx stages the REAL files into
								# this dir (host-side, before boot) when the gateway is enabled.
								# When it is not (a purely-local VM, or the gateway is off),
								# seed EMPTY files so sshd never reads a missing
								# TrustedUserCAKeys/AuthorizedPrincipalsFile -- empty CA -> no
								# cert validates; empty principals -> no principal matches. A
								# real file already staged by cogworx is left untouched.
								[ -e /var/lib/cogbox/.config/ssh-ca.pub ] || : > /var/lib/cogbox/.config/ssh-ca.pub
								[ -e /var/lib/cogbox/.config/ssh-principals/root ] || : > /var/lib/cogbox/.config/ssh-principals/root
							'';
						};
					};
					# The VM host key lives on the late 9p mount; order sshd after
					# it (and after the prep unit that creates the dir + key) so sshd
					# never starts before the key it must read is present.
					sshd = lib.mkIf isVm {
						after = [ "var-lib-cogbox.mount" "cogbox-vm-sshd-prep.service" ];
						requires = [ "cogbox-vm-sshd-prep.service" ];
					};
					# The module's separate host-key generator must also wait for
					# the 9p mount + prep, or it races the late mount; with the key
					# already generated it finds it present and does nothing.
					sshd-keygen = lib.mkIf isVm {
						after = [ "var-lib-cogbox.mount" "cogbox-vm-sshd-prep.service" ];
					};
					# Gated off in the hosted profile: /var/lib/harness-rw is a plain
					# directory on the pool there, so there is no image to build and
					# running this would create a 128 MiB file nothing ever mounts.
					harness-overlay-img = lib.mkIf (isVm && !hosted) {
						description = "Create ext4 image for harness overlay";
						wantedBy = [ "var-lib-harness\\x2drw.mount" ];
						before = [ "var-lib-harness\\x2drw.mount" ];
						after = [ "var-lib-cogbox.mount" ];
						requires = [ "var-lib-cogbox.mount" ];
						unitConfig.DefaultDependencies = false;
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# Bounded. This unit is the recorded precedent for the failure
							# shape -- its own comment below records a first-boot format
							# that outran an EXTERNAL deadline -- and the two are not the
							# same thing: a 10-minute INTERNAL bound is orders of magnitude
							# above any healthy truncate + mkfs of a 128 MiB file, so it
							# never fires on the slow-but-progressing case, and it converts
							# a genuinely wedged 9p share (where the mkfs never returns)
							# from a silent hang into a failure. It is deliberately the
							# only unit here whose timeout does NOT degrade: this profile's
							# harness-rw mount is a hard local-fs.target requirement, so a
							# failure ends in emergency.target either way. Loud and
							# diagnosable beats a boot that hangs with nothing in
							# `systemctl --failed`.
							TimeoutStartSec = 600;
							ExecStart = pkgs.writeShellScript "harness-overlay-img" ''
								img=/var/lib/cogbox/harness-overlay.img
								old_img=/var/lib/cogbox/claude-overlay.img
								# Migration: pre-multi-harness installs had
								# the image named after the only harness.
								# The wrapper renames host-side at launch,
								# but cover the case where the guest is
								# booted by something else.
								if [ ! -f "$img" ] && [ -f "$old_img" ]; then
									mv "$old_img" "$img"
								fi
								# (Re)format when the image is MISSING or does not hold a
								# valid ext4 filesystem. A first-boot mkfs interrupted by a
								# pod recreate (the ~4min boot can outrun the ~5.2min k8s
								# startup-probe deadline) leaves the file present but with a
								# zeroed/garbage superblock; the old `[ ! -f ]`-only guard
								# then skipped reformatting on every later boot, wedging the
								# guest in emergency mode (VFS: Can't find ext4 filesystem ->
								# /var/lib/harness-rw never mounts -> no sshd -> recreate
								# loop, no self-heal). `dumpe2fs -h` reads ONLY the
								# superblock, so a valid (even fully populated) overlay is
								# preserved -- no data loss -- while a missing or corrupt one
								# is rebuilt.
								if [ ! -f "$img" ] || ! ${pkgs.e2fsprogs}/bin/dumpe2fs -h "$img" >/dev/null 2>&1; then
									size="128M"
									sizefile=/var/lib/cogbox/.config/overlay-size
									if [ -f "$sizefile" ]; then
										size=$(cat "$sizefile")
									fi
									${pkgs.coreutils}/bin/truncate -s "$size" "$img"
									${pkgs.e2fsprogs}/bin/mkfs.ext4 -q -F "$img"
								else
									# Valid superblock, but a host crash with the VM running
									# can still leave corrupt INTERNAL metadata (bitmaps,
									# extent/dir checksums) that journal replay does not fix;
									# the harness-rw mount then fails and the guest drops to
									# emergency.target with no sshd (observed 3x). The
									# reformat arm above correctly skips this, so fsck before
									# the mount. Preen (-fp) no-ops a clean image and fixes
									# mild drift (exit 0/1/2); it exits >=4 on anything
									# needing a real decision -- which the observed
									# corruptions hit -- so then repair with -fy twice (the
									# second pass settles the journal replay) and gate on a
									# read-only -fn. The exit 1 is diagnostic only: the mount
									# merely Wants= this unit, so the kernel mount attempt
									# still decides the boot either way. -fy can drop mangled
									# files into lost+found, and the overlay holds real
									# in-guest harness state (transcripts, credentials) --
									# accepted, since the reformat arm already takes a full
									# wipe of the same image as the harsher fallback.
									rc=0
									${pkgs.e2fsprogs}/bin/e2fsck -fp "$img" || rc=$?
									if [ "$rc" -ge 4 ]; then
										echo "harness-overlay: preen declined $img (exit $rc); escalating to full repair" >&2
										${pkgs.e2fsprogs}/bin/e2fsck -fy "$img" || true
										${pkgs.e2fsprogs}/bin/e2fsck -fy "$img" || true
										if ! ${pkgs.e2fsprogs}/bin/e2fsck -fn "$img" >/dev/null 2>&1; then
											echo "harness-overlay: $img still inconsistent after auto-repair; manual e2fsck required" >&2
											exit 1
										fi
										echo "harness-overlay: auto-repaired $img" >&2
									fi
								fi
							'';
						};
					};

					harness-setup-dirs = lib.mkIf isVm {
						description = "Create per-harness subdirs in harness overlay";
						wantedBy = harnessMountUnits;
						before = harnessMountUnits;
						after = [ "var-lib-harness\\x2drw.mount" ];
						# Requires= the mount in the WORKSTATION profile only, and that
						# split is what completes the hosted fail-safe. In hosted the
						# harness-rw mount is a pool bind, so an absent pool makes it
						# fail; with a hard Requires= this unit would fail too, the four
						# harness overlay UPPERDIRS would never be created, and the four
						# overlay mounts -- which are ordinary local-fs.target.requires
						# entries with no nofail of their own -- would fail and take the
						# boot to emergency.target. `nofail` on the pool binds cannot
						# reach that: the cascade runs through a SERVICE, not through the
						# generated mount units. Ordered `after` regardless, so the dirs
						# are never created on the underlying directory and then shadowed
						# by a mount that arrives late; After= orders on job COMPLETION,
						# success or failure. Degraded result: the uppers land on the
						# tmpfs root and harness config is ephemeral for that boot, which
						# is the pre-pool behaviour and not a wedge.
						#
						# Through hardMounts/softMounts rather than a local `hosted`
						# test, because this is one member of a CLASS -- see their
						# definition above and the scan in cogbox-guest-pool-degradable.
						# It resolves to exactly the split spelled out here: harness-rw is
						# pool-backed under hosted and the loop image otherwise.
						requires = hardMounts [ "/var/lib/harness-rw" ];
						wants = softMounts [ "/var/lib/harness-rw" ];
						unitConfig.DefaultDependencies = false;
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# Bounded, and the bound is what makes the degradation above
							# reachable rather than theoretical: every path this unit
							# mkdirs is on the harness-rw mount, so a mount that hangs
							# instead of failing -- a wedged pool bind, a wedged loop image
							# -- leaves it in `activating` forever. The four harness
							# overlay mounts are ordered after it and
							# cogbox-brain-materialize is ordered after those, and that
							# unit is Before=sshd.service: unbounded, a hung mkdir is a
							# guest with no sshd and nothing in `systemctl --failed`. At
							# the bound the unit fails, the overlays fail with it, and the
							# guest comes up with ephemeral harness config -- the same
							# degraded shape the Wants= split produces.
							TimeoutStartSec = 120;
							ExecStart = pkgs.writeShellScript "harness-setup-dirs" ''
								base=/var/lib/harness-rw

								# Migration: pre-multi-harness images had
								# upper/ and work/ at the root (single
								# Claude overlay). Move into the new
								# claude-code/config/ subdir layout.
								if [ -d "$base/upper" ] && [ ! -d "$base/claude-code/config/upper" ]; then
									mkdir -p "$base/claude-code/config"
									mv "$base/upper" "$base/claude-code/config/upper"
									[ -d "$base/work" ] && mv "$base/work" "$base/claude-code/config/work"
								fi

								${lib.concatMapStringsSep "\n" (p: ''
									mkdir -p ${upperDir p.harness p.pathkey} ${workDir p.harness p.pathkey}
								'') overlayPaths}
								${lib.concatMapStringsSep "\n" (p: ''
									mkdir -p ${ephemeralSrc p.harness p.pathkey}
								'') ephemeralPaths}
							'';
						};
					};

					# Gated off in the hosted profile, and that gate is load-bearing
					# rather than tidy-up. This unit remounts /nix/.rw-store to whatever
					# /var/lib/cogbox/.config/store-overlay-size holds, and
					# cogbox-launch.sh has always written "16G" there (and baked
					# storeOverlaySize: "16G" into every instance's config.json). Every
					# hosted instance in the field therefore carries that file already,
					# so without this gate the boot would try `mount -o remount,size=16G`
					# against an EXT4 filesystem -- and on the workstation side the
					# explicit tmpfs fraction above would be remounted straight back to
					# 16G, making the sizing fix inert. The launcher's matching half
					# stops writing a default for NEW instances.
					resize-store-overlay = lib.mkIf (isVm && !hosted) {
						description = "Resize writable nix store overlay from config";
						wantedBy = [ "multi-user.target" ];
						after = [ "var-lib-cogbox.mount" ];
						requires = [ "var-lib-cogbox.mount" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# Bounded. Nothing is ordered after this unit, so a hang here
							# cannot hold sshd -- but it reads a file off the 9p share,
							# which CAN block indefinitely, and multi-user.target's job
							# does not complete while a unit it wants is still activating.
							# 60s is far above a stat + a remount; at the bound the unit
							# fails, the store overlay keeps the size the Nix-declared
							# tmpfs fraction gave it, and the failure is visible.
							TimeoutStartSec = 60;
							ExecStart = pkgs.writeShellScript "resize-store-overlay" ''
								sizefile=/var/lib/cogbox/.config/store-overlay-size
								if [ -f "$sizefile" ]; then
									size=$(cat "$sizefile")
									${pkgs.util-linux}/bin/mount -o "remount,size=$size" /nix/.rw-store
								fi
							'';
						};
					};

					# Create the pool's per-class subdirectories. Clone of
					# harness-setup-dirs above: DefaultDependencies = false, oneshot +
					# RemainAfterExit, wantedBy/before the module-generated bind mount
					# units, after/requires the pool mount. This is ORDERING, not
					# housekeeping: a bind whose SOURCE does not exist either fails or --
					# worse, for work/ -- mounts an empty directory over live data. Every
					# bind also carries x-systemd.requires= on this unit, so a failure
					# here stops the binds rather than letting them run half-prepared.
					cogbox-guest-dirs = lib.mkIf poolEnabled {
						description = "Create per-class subdirs in the guest storage pool";
						wantedBy = poolBindUnits;
						before = poolBindUnits;
						after = [ poolUnit ];
						requires = [ poolUnit ];
						unitConfig.DefaultDependencies = false;
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# Bounded. Every path here is ON the pool, so a filesystem that
							# hangs rather than fails -- a stalled virtio-blk, an ext4 that
							# never finishes recovery -- makes these mkdirs block in
							# D-state. Every pool bind carries x-systemd.requires= on this
							# unit and the work bind is ordered before
							# cogbox-brain-materialize, which is Before=sshd.service: with
							# no bound that is a guest with no login and nothing in
							# `systemctl --failed`. Seven mkdirs and a chmod finish in
							# milliseconds on any pool that works at all, so 120s is
							# entirely fault, not slow progress. At the bound the unit
							# fails, the binds it gates do not happen, and `nofail` on
							# every one of them means the guest degrades to the pre-pool
							# layout instead of failing local-fs.target.
							TimeoutStartSec = 120;
							ExecStart = pkgs.writeShellScript "cogbox-guest-dirs" ''
								set -eu
								${lib.concatMapStringsSep "\n"
									(sub: "mkdir -p ${poolMount}/${sub}")
									(lib.mapAttrsToList (_: b: b.sub) poolBinds)}
								# root's home lives at 0700; the pool-backed replacements
								# must not be laxer than what they cover. Wrapped in an
								# optionalString so dropping every /root bind cannot leave a
								# bare `chmod 0700` behind -- that would fail under set -eu
								# and take the whole pool-prep unit down.
								${let rootDirs = map (b: "${poolMount}/${b.sub}")
									(lib.attrValues (lib.filterAttrs
										(guest: _: lib.hasPrefix "/root/" guest) poolBinds));
								in lib.optionalString (rootDirs != [])
									"chmod 0700 ${lib.concatStringsSep " " rootDirs}"}
							'';
						};
					};

					# ONE-TIME work migration for an instance that predates the pool.
					# Deliberately NOT wantedBy anything: the /var/lib/cogbox/work bind
					# pulls it in via x-systemd.requires, which is the gce/state-disk.nix
					# idiom -- it runs exactly when the bind is about to happen and not
					# at all on an instance that has no such bind. Because the bind
					# Requires= it, a nonzero exit means the bind does not happen and the
					# guest keeps using the 9p copy: fail-safe on the one leg of this
					# change that touches irreplaceable user data.
					cogbox-guest-work-migrate = lib.mkIf (isVm && hosted) {
						description = "One-time copy of work/ from the 9p state dir onto the guest pool";
						after = [ poolUnit cogboxUnit "cogbox-guest-dirs.service" ];
						requires = [ poolUnit cogboxUnit "cogbox-guest-dirs.service" ];
						unitConfig.DefaultDependencies = false;
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# EXPLICIT, because the default for Type=oneshot is NO TIMEOUT
							# AT ALL (systemd.service(5): "except when Type=oneshot is
							# used, in which case the timeout is DISABLED by default").
							# This unit is an UNBOUNDED DATA COPY that now sits in front of
							# sshd: the /var/lib/cogbox/work bind Requires= it, and that
							# bind is ordered Before=cogbox-brain-materialize.service,
							# which is itself Before=sshd.service. A copy that wedges --
							# a 9p share that stops answering mid-walk is the realistic
							# way -- therefore holds the guest's login forever, with the
							# unit stuck in `activating` and NOTHING in `systemctl
							# --failed`. That is the exact shape this design is written
							# against, and only this line rules it out.
							#
							# 15 minutes, and the number is chosen from the RETRY cost
							# rather than from the copy cost. At the bound systemd SIGTERMs
							# the script: it leaves no marker, so the next boot re-runs the
							# whole migration from scratch (`rm -rf "$incoming"` at the top
							# of the copy path clears the partial), and the bind -- which
							# Requires= this unit -- does not happen, so the 9p copy stays
							# authoritative and visible. `nofail` on that bind is what
							# makes the failure degrade the one path instead of failing
							# local-fs.target. The cost of a bound that is too TIGHT is
							# therefore not a lost migration but a permanent one: a tree
							# that cannot be copied in the budget charges the full budget
							# in front of sshd on EVERY boot and never completes. 15
							# minutes clears a many-GiB tree over 9p with room to spare
							# while still being a bound; a tree that needs longer needs an
							# operator, not a bigger number.
							TimeoutStartSec = 900;
							ExecStart = "${guestWorkMigrate}/bin/cogbox-guest-work-migrate";
						};
					};

					# The same one-time migration for the OTHER surface the hosted
					# profile repoints: /var/lib/harness-rw, whose legacy home is the
					# ext4 loop image on the 9p share. Without this, switching an
					# existing instance to hosted would present all four harness overlay
					# uppers -- claude's settings/history/credentials, the hermes home,
					# opencode's config and data -- as empty on the first hosted boot,
					# because the bind would land on a freshly-created pool directory
					# and the read-only 9p lower supplies only the baked defaults. Same
					# shape as the work leg: pulled in by the bind via
					# x-systemd.requires, refuses rather than half-copies, and the
					# refusal now degrades one path instead of the boot.
					cogbox-guest-harness-migrate = lib.mkIf (isVm && hosted) {
						description = "One-time copy of the harness overlay image onto the guest pool";
						after = [ poolUnit cogboxUnit "cogbox-guest-dirs.service" ];
						requires = [ poolUnit cogboxUnit "cogbox-guest-dirs.service" ];
						unitConfig.DefaultDependencies = false;
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# Same reasoning as the work leg above -- an unbounded oneshot
							# in front of sshd, with the Type=oneshot default being no
							# timeout at all -- but a fifth of the budget, because the
							# input is bounded in a way work/ is not: the legacy source is
							# a single 128 MiB ext4 image on the 9p share (the size
							# harness-overlay-img has always created), not a tree the user
							# grows. 5 minutes is two orders of magnitude above a healthy
							# loop-mount plus copy of that image.
							#
							# At the bound: no marker, so the next boot retries; the bind
							# Requires= this unit, so it does not happen and the harness
							# overlays keep resolving through the legacy loop image. One
							# leak worth naming -- bash does NOT run an EXIT trap on an
							# untrapped SIGTERM, so the `umount` this script arms for
							# /run/cogbox-harness-migrate does not run and the loop mount
							# survives until the guest reboots. Harmless: nothing else
							# reads that path, and a same-boot retry would stack a second
							# mount of the same image over it and read identical content.
							TimeoutStartSec = 300;
							ExecStart = "${guestHarnessMigrate}/bin/cogbox-guest-harness-migrate";
						};
					};

					# Container backend: prepare the mounted state volume and make
					# ~/work and enabled harness state resolve into it before brain
					# materialization. The brain/trust oneshots hardcode /var/lib/cogbox
					# as the data dir, so symlink it into the mounted state too.
					cogbox-container-state = lib.mkIf isContainer {
						description = "Prepare mounted state + ~/work resolution (container backend)";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "cogbox-brain-materialize.service" ];
						unitConfig.DefaultDependencies = false;
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# Bounded, now that this unit reaches further into the PVC than
							# it used to: the three machine-state legs below mkdir and
							# symlink under ${stateRoot}/machine, so a PVC that hangs
							# rather than fails blocks here. Everything downstream is
							# ordered after it -- cogbox-init Requires= it, and
							# cogbox-brain-materialize Requires= it through stateUnit --
							# and the readiness probe gates on brain-materialize, so an
							# unbounded hang is a pod that never becomes Ready with nothing
							# in `systemctl --failed`. This does not degrade and is not
							# meant to: the unit owns the /var/lib/cogbox symlink and
							# sshd's persisted host key, so its failure is fail-CLOSED by
							# design. The bound only changes an invisible hang into a
							# failure an operator can see. 180s against a script whose slow
							# path is a handful of mkdirs.
							TimeoutStartSec = 180;
							ExecStart = pkgs.writeShellScript "cogbox-container-state" ''
								set -e
								# ${stateRoot}/machine is the machine-state parent. It has to
								# exist BEFORE the legs below: the helper creates its
								# persistent home with a bare `mkdir` (no -p), so a missing
								# parent turns every leg into a failure. hermes-home needs no
								# such line -- it sits directly under the mount point.
								mkdir -p ${cogboxData} ${stateRoot}/config ${stateRoot}/ssh ${stateRoot}/machine /run/cogbox
								# sshd writes the persisted host key here (0700 so the
								# private key is not group/world readable).
								chmod 700 ${stateRoot}/ssh
								ln -sfn ${cogboxData} /var/lib/cogbox
								${lib.optionalString (harnesses ? "hermes-agent") ''
									${hermesHomeHelper}/bin/cogbox-hermes-home ${stateRoot}/hermes-home /root/.hermes
								''}
								# Machine-state on the PVC, through the SAME validated-symlink
								# helper the hermes home uses: it refuses a symlinked or
								# non-directory persistent target, refuses a link path that is
								# a NONEMPTY directory (so a real directory with content is
								# never blindly replaced), adopts an already-populated
								# persistent directory as-is, and no-ops when the link is
								# already correct -- which is what makes this unit idempotent
								# across the every-boot re-run.
								#
								# Nothing pre-creates these three on this target (the image
								# bakes /root empty at 0700, the only tmpfiles rule under /root
								# is the .nix-channels FILE, and the pre-systemd
								# `nix-store --realise` in agent-init writes no ~/.cache), so
								# the normal boot takes the create-or-adopt path. There is
								# deliberately no content MIGRATION leg: the container's /root
								# lives on the ephemeral writable layer, so by the time this
								# unit runs on a restart the previous boot's content is already
								# gone -- there is never anything to migrate, only a persistent
								# copy to adopt.
								#
								# Each leg is INDIVIDUALLY tolerant, and that is load-bearing
								# rather than lax: this script runs under `set -e`, so an
								# untolerated failure would take the whole unit down -- and with
								# it the /var/lib/cogbox symlink, the seeded instance config and
								# sshd's persisted host key -- wedging the sandbox over a cache
								# directory. A failed leg degrades that ONE path to today's
								# ephemeral behaviour and says so in the journal. The hermes leg
								# above keeps its fail-closed semantics: it carries credentials.
								${lib.concatMapStringsSep "\n" (p: ''
									${hermesHomeHelper}/bin/cogbox-hermes-home ${stateRoot}/machine/${p.sub} ${p.guest} \
										|| echo "cogbox-container-state: ${p.guest} is not persisted (see above); continuing on the ephemeral container layer" >&2
								'') containerMachineState}
							'';
						};
					};

					# Container backend: seed the per-instance config.json before the
					# brain materializes (and before any kubectl-exec'd verb edits it).
					# Ordered after the state symlink and before brain-materialize.
					cogbox-init = lib.mkIf isContainer {
						description = "Seed the per-instance cogbox config (container backend)";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "cogbox-brain-materialize.service" ];
						after = [ "cogbox-container-state.service" ];
						requires = [ "cogbox-container-state.service" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# systemd does not forward PID1's env to services. XDG_CONFIG_HOME
							# /COGBOX_DATA/HOME are baked constants; COGBOX_INSTANCE is the
							# runtime per-sandbox name the pod sets (unset -> "default").
							Environment = [
								"HOME=/root"
								"XDG_CONFIG_HOME=${stateRoot}/config"
								"COGBOX_DATA=${cogboxData}"
							];
							PassEnvironment = [ "COGBOX_INSTANCE" ];
							ExecStart = cogboxInitScript;
						};
					};

					# Container backend: reconcile the redacted Claude stub credential
					# from the per-instance marker cogworx sets/clears (step 5b). Ordered
					# after the state symlink and BEFORE brain-materialize/brain-trust/login
					# so the ~/.claude{,.json} PVC symlinks + the stub are in place before
					# brain-trust writes ~/.claude.json and before a terminal opens.
					# Re-run on connect/disconnect by cogworx (systemctl restart) and at
					# every boot (restart persistence from the PVC marker).
					cogbox-claude-stub = lib.mkIf (isContainer || isVm) (let
						claudeMount = lib.optional (isVm && harnesses ? "claude-code") "/root/.claude";
					in {
						description = "Stage/remove the redacted Claude stub credential"
							+ lib.optionalString isContainer " (container backend)";
						wantedBy = [ "multi-user.target" ];
						before = [ "multi-user.target" "sshd.service" "cogbox-brain-materialize.service" "cogbox-brain-trust.service" ];
						# stateUnit resolves per target (cogbox-container-state.service /
						# var-lib-cogbox.mount). On the VM the verb writes
						# .credentials.json into the /root/.claude OVERLAY, so that mount
						# must be up first (a write before it lands on the covered rootfs).
						after = [ stateUnit ] ++ map mountUnitOf claudeMount;
						# Same split as cogbox-brain-materialize, and for the same reason:
						# under `hosted` that overlay's upper lives under the pool-bound
						# /var/lib/harness-rw, so a hard Requires= means a pool-absent boot
						# never reconciles the stub -- which is how a user ends up looking
						# at a stale credential the control plane believes it removed. The
						# After= above still keeps the write off the covered rootfs when
						# the mount DOES arrive, and the workstation profile keeps its
						# Requires= (there the overlay rests on the loop image).
						requires = [ stateUnit ] ++ hardMounts claudeMount;
						wants = softMounts claudeMount;
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# Bounded: both variants are a marker test plus one short
							# `cogbox __claude-stub` run against files on the state mount,
							# and this unit is Before=sshd.service, so a wedged state mount
							# would otherwise hold the login prompt forever with nothing in
							# `systemctl --failed`. At the bound the unit fails loudly and
							# the boot continues with the stub unreconciled -- exactly what
							# a pool-absent boot already degrades to.
							TimeoutStartSec = 120;
							# The container verb resolves XDG/HOME/COGBOX_DATA to locate
							# the state root; the VM variant takes explicit path args and
							# needs only HOME.
							Environment = if isContainer then [
								"HOME=/root"
								"XDG_CONFIG_HOME=${stateRoot}/config"
								"COGBOX_DATA=${cogboxData}"
							] else [
								"HOME=/root"
							];
							ExecStart = if isContainer then claudeStubScript else claudeStubScriptVm;
						};
					});

					# Container backend: install the SSH user-CA trust anchor and this
					# instance's authorized-principals file BEFORE sshd starts. The
					# gateway presents a short-lived user certificate signed by the
					# cogworx-held CA; sshd (TrustedUserCAKeys) verifies the signature
					# and (AuthorizedPrincipalsFile) that the cert carries this
					# instance's name as a principal. Fail closed: if the CA is not
					# supplied no anchor is written (no cert can validate); if the
					# instance name is empty the principals file is empty (no principal
					# matches). sshd reads both files at connection time, so ordering
					# this unit before sshd is sufficient.
					cogbox-sshd-ca = lib.mkIf isContainer {
						description = "Install the SSH user-CA trust anchor + per-instance principals (container backend)";
						wantedBy = [ "multi-user.target" ];
						before = [ "sshd.service" ];
						after = [ "cogbox-container-state.service" ];
						serviceConfig = {
							Type = "oneshot";
							RemainAfterExit = true;
							# systemd does not forward PID1's env; the pod sets these and
							# they are passed through explicitly (mirrors COGBOX_INSTANCE
							# elsewhere).
							PassEnvironment = [ "COGBOX_SSH_CA_PUB" "COGBOX_SSH_PRINCIPAL" "COGBOX_INSTANCE" ];
							ExecStart = pkgs.writeShellScript "cogbox-sshd-ca" ''
								set -eu
								mkdir -p /etc/ssh/principals ${stateRoot}/ssh
								chmod 700 ${stateRoot}/ssh
								ca="''${COGBOX_SSH_CA_PUB:-}"
								if [ -n "$ca" ]; then
									printf '%s\n' "$ca" > /etc/ssh/trusted_user_ca.pub
									chmod 644 /etc/ssh/trusted_user_ca.pub
								fi
								# Exactly one principal, keyed on a GLOBALLY-UNIQUE id
								# (cogworx sets COGBOX_SSH_PRINCIPAL to the full instance ID,
								# accountID-name). Falls back to the bare COGBOX_INSTANCE name
								# only if the manifest has not set it yet -- but note the bare
								# name is unique only per-account, so a shared CA + bare-name
								# principal would let a captured cert replay across tenants;
								# the dedicated principal env closes that. Empty when neither
								# is set -> no cert principal can match -> sshd denies.
								principal="''${COGBOX_SSH_PRINCIPAL:-''${COGBOX_INSTANCE:-}}"
								printf '%s\n' "$principal" > /etc/ssh/principals/root
								chmod 644 /etc/ssh/principals/root
							'';
						};
					};
				} // lib.optionalAttrs poolEnabled (lib.listToAttrs (map (p: lib.nameValuePair
					# nixpkgs' OWN overlay pre-mount units (tasks/filesystems/overlayfs.nix
					# names them rw-<escaped mountPoint>), bounded here for the same reason
					# harness-setup-dirs is: each runs `mkdir -p <upper> <work>` under
					# /var/lib/harness-rw -- a pool bind in this profile -- and each is
					# Before= its overlay mount. cogbox-brain-materialize is After= the
					# hermes overlay and Before=sshd.service, so an unbounded mkdir sitting
					# in D-state on a pool that stalled AFTER mounting is once again a guest
					# with no login and an EMPTY `systemctl --failed`. That 120s bound on
					# harness-setup-dirs does not rescue this: nothing orders these two
					# against each other, and they mkdir the same directories independently.
					#
					# cogbox-guest-pool-degradable exempts rw-* from its hard-dependency
					# scan; that exemption is about FAILURE (theirs fails only the matching
					# `nofail` overlay mount) and is untouched here. This is about a HANG,
					# which `nofail` does not bound.
					#
					# Merged into nixpkgs' definition rather than added as a drop-in,
					# because systemd.services already renders these into systemd.units and
					# a second systemd.units definition of the same name is a `text`
					# conflict, not an override. The cost of merging is that a nixpkgs
					# rename would leave a stray timeout-only unit behind instead of an
					# error -- so cogbox-guest-pool-boot-bounded asserts each of these
					# still carries an ExecStart alongside the bound.
					"rw-${utils.escapeSystemdPath p.guest}"
					{ serviceConfig.TimeoutStartSec = 120; }) overlayPaths));

				virtualisation.docker.enable = lib.mkIf isVm true;

				# Cap the journal now that it can outlive a reboot. journald's
				# SystemMaxUse defaults to 10% of the containing filesystem and
				# SystemKeepFree to 15%; with /var/log/journal on the pool, and docker's
				# log driver in this guest being journald, container stdout could
				# otherwise claim a tenth of the user's single data pool. One line, or
				# the observability half eats the storage half.
				#
				# Gated on poolEnabled -- i.e. applied only where the journal actually
				# HAS a mount of its own -- because these are ABSOLUTE sizes and
				# journald's own defaults are FRACTIONS of the containing filesystem.
				# On the default profile the journal lives on the root tmpfs, sized at
				# half of guest RAM, and `mem` is a per-instance knob: on a 2048 MiB
				# guest that filesystem is 1 GiB, where SystemKeepFree=1G would demand
				# the whole of it and journald would vacuum the journal to nothing --
				# breaking `journalctl -b -1` on precisely the profile with no journal
				# mount to fall back on -- while SystemMaxUse=512M would RAISE the cap
				# from the 100 MiB the 10% default gives. The percentage defaults
				# self-scale with `mem` and are already the right answer there.
				#
				# Joined from a list rather than written as an indented '' block: Nix
				# strips only SPACE indentation and this file is tab-indented, so a ''
				# block emits tab-prefixed directives into journald.conf and leans on
				# systemd's parser stripping them.
				services.journald.extraConfig = lib.mkIf poolEnabled (lib.concatStringsSep "\n" [
					"SystemMaxUse=512M"
					"SystemKeepFree=1G"
				]);

				# Bounds for the jobs on the pool's boot path that this change does not
				# author. `nofail` on the pool line bounds FAILURE; only a timeout bounds
				# a HANG, and the fault this design is written against -- a provider disk
				# that ANSWERS the device probe and then stalls on reads -- produces a
				# hang, not a failure. The 30s x-systemd.device-timeout covers "the
				# device never appears"; everything below covers "the device appeared and
				# then stopped answering", which is the stuck-in-Booting shape.
				#
				# Rendered as DROP-INS (overrideStrategy = "asDropin") and via
				# systemd.units rather than systemd.services, and both choices are
				# load-bearing:
				#
				#   asDropinIfExists -- the DEFAULT -- would look for
				#   systemd-fsck@dev-...-guest.service in the unit tree, not find it
				#   (only the TEMPLATE systemd-fsck@.service is there) and install this
				#   as a FULL unit shadowing the template: no ExecStart, so the instance
				#   would "succeed" instantly and the pool would never be checked at all.
				#   Silently. cogbox-guest-pool-boot-bounded asserts the drop-in shape.
				#
				#   systemd.services would render the NixOS service scaffolding into the
				#   drop-in too -- in particular Environment=PATH=, built from this
				#   unit's own (empty) `path`. Drop-ins are applied after the template's,
				#   and a later Environment= for the same variable WINS, so that PATH
				#   would replace the one nixpkgs' filesystems module gives
				#   systemd-fsck@.service and take e2fsprogs off fsck's PATH. A raw
				#   `text` emits the two settings and nothing else.
				systemd.units = lib.mkIf poolEnabled {
					# 10 minutes. `fsck -a` on a journalled ext4 replays and returns in
					# well under a second in the ordinary case, including after an
					# unclean guest shutdown; only a filesystem systemd decides to check
					# in full runs long, and that scales with the pool's size, which is
					# operator-set and unbounded. So the number is chosen the same way
					# the migration budgets were: far above any healthy run, and a
					# filesystem that genuinely needs longer needs an operator rather
					# than a bigger constant.
					#
					# Hitting it DEGRADES, in the direction S3 already chose: the pool
					# .mount Requires= this unit, so the mount does not happen, and the
					# mount is `nofail`, so local-fs.target still activates and every
					# pool bind simply does not run. The guest comes up on the pre-pool
					# layout with sshd, and the failure is named in `systemctl --failed`
					# instead of being an invisible `activating` job.
					${poolFsckUnit} = {
						overrideStrategy = "asDropin";
						text = poolJobTimeout 600;
					};
					# Same bound, different degradation: the pool .mount only Wants= this
					# one, so a timeout leaves the pool MOUNTED AT ITS OLD SIZE and the
					# guest otherwise intact -- the correct outcome for a grow that could
					# not finish, and it retries on the next boot because x-systemd.growfs
					# runs every boot. Unbounded it is worse than the fsck: an online
					# resize2fs that D-states holds local-fs.target through the
					# generator's own ordering drop-in, and local-fs.target gates
					# systemd-tmpfiles-setup, hence sysinit.target, hence sshd.
					${poolGrowfsUnit} = {
						overrideStrategy = "asDropin";
						text = poolJobTimeout 600;
					};
					# NOT generated and not upstream-unbounded by accident:
					# systemd-tmpfiles-setup.service is Type=oneshot with no TimeoutSec at
					# all, and systemd.service(5) DISABLES the start timeout for oneshot,
					# so it is unbounded. It is After=local-fs.target and
					# Before=sysinit.target, and this change is what first puts a
					# provider-disk-backed path under it: systemd's own tmpfiles.d chowns
					# and chmods /var/log/journal, which is a pool bind here and was a
					# directory on the RAM-backed root before. A pool that stalls AFTER
					# mounting therefore parks tmpfiles in D-state and wedges sysinit with
					# nothing in `systemctl --failed` -- finding 1's shape, reached
					# through a unit nobody in this repo writes.
					#
					# 5 minutes rather than 10: unlike fsck this work does not scale with
					# the pool, it is a fixed set of rules that finishes in seconds on any
					# guest that works. sysinit.target only Wants= it, so the bound
					# degrades (some tmpfiles rules unapplied, loudly) rather than wedging.
					"systemd-tmpfiles-setup.service" = {
						overrideStrategy = "asDropin";
						text = poolJobTimeout 300;
					};
				};

				fileSystems = lib.mkIf isVm ({
					# microvm.nix declares the WHOLE "/" attrset under ONE
					# lib.mkDefault, so a partial override DISCARDS device, fsType and
					# neededForBoot: `fileSystems."/".options = [...]` alone fails eval
					# with `fileSystems."/".fsType was accessed but has no value
					# defined`. Restate the whole attrset. 50% is the value microvm.nix
					# already defaults to -- this states the rootfs size deliberately
					# rather than inheriting it, which is the point of the change.
					"/" = {
						device = "rootfs";
						fsType = "tmpfs";
						options = [ "size=${rootTmpfsSize}" "mode=0755" ];
						neededForBoot = true;
					};
				} // lib.optionalAttrs (!hosted) {
					# Workstation: the writable /nix/store overlay stays a tmpfs, but
					# sized as a FRACTION OF RAM instead of a fixed size=16G that is
					# larger than the guest's entire memory -- a runaway `nix build`
					# then fails with ENOSPC instead of OOM-killing the guest. NOTE the
					# runtime half: resize-store-overlay.service remounts this from
					# /var/lib/cogbox/.config/store-overlay-size, so cogbox-launch.sh
					# must stop defaulting that file to "16G" or the size here is inert.
					#
					# Hosted has NO entry here on purpose: the volume above generates
					# device + fsType + neededForBoot for /nix/.rw-store, and declaring
					# fsType = "tmpfs" alongside an ext4 volume is a definition
					# conflict, not an override.
					"/nix/.rw-store" = {
						fsType = "tmpfs";
						options = [ "size=${storeOverlayTmpfs}" "mode=0755" ];
						neededForBoot = true;
					};
				} // lib.optionalAttrs hosted {
					"/nix/.rw-store" = {
						options = [
							# ext4 mounts nodiscard by DEFAULT. discard=unmap on the QEMU
							# drive is necessary but not sufficient; without this the
							# freed blocks never return through device-mapper to the
							# provider disk and the sparse ratchet the design is fixing
							# just moves one layer down.
							"discard"
						];
						# Skip fsck. The host lays this filesystem down fresh on every
						# host boot before the guest launches, so there is never a dirty
						# filesystem to repair -- and this mount is neededForBoot, so a
						# failing fsck would wedge stage 1 over a disposable cache. The
						# pool deliberately keeps its fsck: that one holds real data.
						# Keeps it BOUNDED, too -- see the systemd.units drop-ins above,
						# which give that fsck the finite TimeoutSec upstream denies it.
						#
						# NO autoResize here, and the absence is a finding rather than an
						# omission: NixOS renders autoResize as nothing but the
						# x-systemd.growfs mount option, and systemd-growfs@.service is a
						# STAGE-2 upstream unit (nixpkgs system/boot/systemd.nix) with no
						# stage-1 counterpart in this nixpkgs at all. Setting it on a
						# neededForBoot mount would assert a growth path that cannot run.
						# This volume grows because the host re-creates its filesystem at
						# the logical volume's current size on every host boot.
						noCheck = true;
					};
				} // lib.optionalAttrs poolEnabled {
					# The pool itself. microvm.nix generates only device + fsType for a
					# volume's mountPoint and NEVER sets `options` or `autoResize`, so
					# both merge with no mkForce -- verified by evaluation.
					${poolMount} = {
						# Restart-to-grow: NixOS turns autoResize into x-systemd.growfs
						# and ext4 is resizable, so growing an instance is `resize the
						# disk, restart the guest` and nothing more. This works ONLY
						# because the pool is stage 2 (neededForBoot false) --
						# systemd-growfs@.service does not exist in the initrd, and a
						# filesystem already mounted by stage 1 never runs its Wants= in
						# stage 2 either. That is the whole reason the store overlay got
						# its own volume instead of a subdirectory here.
						autoResize = true;
						options = [
							# `nofail` STAYS, and NOT because it was already here.
							# The reason it was written with is dead: "the guest
							# degrades to today's LAYOUT, reading and writing the
							# legacy 9p paths", extended on GCE by a launch-time
							# chooser that fell back to the workstation runner
							# whenever the host would not carve. The chooser is gone
							# -- one baked profile, because state persisting across
							# that flip was the root of four blocker rounds -- and
							# the old comment's own parenthetical already conceded
							# that after the migration those legacy paths hold the
							# EMPTY directory stash() left behind. "Today's layout"
							# was never "today's data".
							#
							# What earns it now is VISIBILITY, and this is the one
							# fault on the whole path that the HOST cannot see.
							# Everything the host refuses lands in its own `systemctl
							# --failed` and is named on serial by supervise.sh leg
							# (e2). But a pool the host carved, formatted and labelled
							# SUCCESSFULLY, which the guest then cannot mount --
							# corruption, an fsck that fails, a label that stopped
							# resolving, a first mkfs interrupted between the two --
							# gives the host nothing to report. Fail-closed here makes
							# that local-fs.target -> emergency.target -> a guest with
							# no sshd: a sandbox that is down for a reason neither
							# side can read. With `nofail` the guest reaches
							# multi-user, sshd answers, and the failed mount sits in
							# the guest's own `systemctl --failed` where a person can
							# actually find it.
							#
							# The two objections, both CLOSED rather than accepted:
							#
							#   "the user works in the empty tree and the next healthy
							#   boot hides it." No: cogbox-guest-{work,harness}-migrate
							#   test the POPULATED-POOL case first, before the
							#   migration marker is consulted at all, precisely so a
							#   marker cannot suppress the check. Such a boot fires
							#   the fork WARNING naming both trees with both sizes and
							#   retires the legacy copy to a numbered .pre-pool.
							#
							#   "nofail bounds FAILURE, not a HANG." Correct, which is
							#   why the hang is bounded separately and explicitly:
							#   x-systemd.device-timeout below, plus the finite
							#   TimeoutStartSec/TimeoutStopSec drop-ins this module
							#   renders onto the GENERATED systemd-fsck@ and
							#   systemd-growfs@ instances for this mount (poolJobTimeout
							#   above). cogbox-guest-pool-boot-bounded asserts every
							#   one of them.
							"nofail"
							"x-systemd.device-timeout=30s"
							# See the hosted /nix/.rw-store note above; the weekly
							# fstrim timer is the belt to this brace.
							"discard"
						];
					};
				} // lib.optionalAttrs poolEnabled (lib.mapAttrs mkPoolBind poolBinds)
				// lib.optionalAttrs (!hosted) {
					# Workstation keeps the loop image. Hosted gets /var/lib/harness-rw
					# as a plain pool directory instead (it is in poolBinds), retiring
					# the 128 MiB ext4-in-a-file-on-ext4 image -- and with it the
					# overlay-size knob's effect, since the launcher keeps writing the
					# size file but harness-overlay-img, the only unit that read it, is
					# gated off below. Existing workstation instances are unaffected.
					"/var/lib/harness-rw" = {
						device = "/var/lib/cogbox/harness-overlay.img";
						fsType = "ext4";
						options = [ "loop" ];
					};
				} // lib.listToAttrs (
					# poolNofail on both kinds: see its definition above for WHY a
					# harness mount that names no pool path anywhere still fails when the
					# pool is absent. `options` on an overlay entry MERGES with the
					# lowerdir=/upperdir=/workdir= list overlayfs.nix generates (they are
					# separate definitions of one list option), so this adds a flag rather
					# than replacing anything.
					(map (p: lib.nameValuePair p.guest ({
						overlay = {
							lowerdir = [ (lowerMount p.harness p.pathkey) ];
							upperdir = upperDir p.harness p.pathkey;
							workdir = workDir p.harness p.pathkey;
						};
					} // poolNofailOpt [
						p.guest
						(lowerMount p.harness p.pathkey)
						(upperDir p.harness p.pathkey)
						(workDir p.harness p.pathkey)
					])) overlayPaths)
					++ (map (p: lib.nameValuePair p.guest {
						device = ephemeralSrc p.harness p.pathkey;
						fsType = "none";
						options = [ "bind" ]
							++ poolNofail [ p.guest (ephemeralSrc p.harness p.pathkey) ];
					}) ephemeralPaths)
				));
			})
		];
	in {
		# The GCE bake seam. `packages.gce-image` builds the DEFAULT host config,
		# whose cogworx.gce.controlCAPublicKey is empty -- fail-closed, and
		# therefore NOT publishable: sshd would trust no control CA and every
		# certificate cogworxd mints would be refused, so every instance created
		# from it wedges in Booting. Baking a real image means overriding that
		# option, and these two outputs are the supported ways to do it (there is
		# no other: the default config is constructed inside this flake and takes
		# no arguments).
		#
		#   nix build --impure --expr '((builtins.getFlake "/path/to/cc-sandbox").lib.mkGceHost
		#     "x86_64-linux" { extraModules = [ { cogworx.gce.controlCAPublicKey = "ssh-ed25519 AAAA... control-ca"; } ]; }
		#   ).config.system.build.googleComputeImage'
		lib.mkGceHost = mkGceHost;
		nixosModules.gce-host = ./gce/cogbox-host.nix;

		packages = forAllSystems (system: let
			pkgs = nixpkgs.legacyPackages.${system};
			runner = self.nixosConfigurations.${configName system}.config.microvm.declaredRunner;
			# The HOSTED-storage-profile guest runner. Same module tree, same
			# vcpu/mem, cogbox.storage.profile = "hosted"; consumed only by
			# packages.cogbox-hosted below, which only the GCE host image consumes.
			runnerHosted = self.nixosConfigurations."${configName system}-hosted".config.microvm.declaredRunner;
			# Container-native agent system (see mkContainer): the SAME guest
			# module tree with target = "container". Its toplevel/init boots
			# systemd PID1 in the agent-image below.
			containerSystem = mkContainer system "cogbox" {
				extraModules = cogboxModules system { target = "container"; };
			};
			containerToplevel = containerSystem.config.system.build.toplevel;
			# Registration (nix-store --dump-db format) for the WHOLE agent-image /nix
			# closure, baked into the image at /etc/cogbox/base-reginfo. The CoW seed
			# (cogworx's CoW-seed) `nix-store --load-db`s it into the frozen node lower
			# so the stopped-add worker can SUBSTITUTE the base closure from the lower over
			# local disk. Without a DB the lower
			# is store-paths-only and unusable as a substituter. rootPaths = the image
			# content root (containerToplevel; bashInteractive is already in its closure),
			# so the registration covers every path `cp -a /nix/.` puts in the lower. The
			# baked file is plain text (store-path strings already in the image closure), so
			# it adds no new closure.
			baseReginfo = pkgs.closureInfo { rootPaths = [ containerToplevel ]; };
			# Pre-systemd boot shim for the unprivileged agent pod
			# systemd PID1 cannot bring
			# itself up under a stock Kubernetes pod for two container-specific
			# reasons that must be fixed BEFORE exec'ing the NixOS init:
			#
			#  1. cgroup-v2 delegation. The kubelet mounts the pod's delegated
			#     /sys/fs/cgroup subtree READ-ONLY for a non-privileged container,
			#     so systemd cannot create its cgroup hierarchy and exits. Remount
			#     it read-write -- or, under a userns (hostUsers:false) where that
			#     remount EPERMs because the superblock is owned by the INIT userns,
			#     mount a FRESH pod-owned cgroup2 instead (a confined SYS_ADMIN may
			#     mount cgroup2 but may not change the init-userns mount's flags).
			#     This is namespaced to the pod's OWN delegated subtree (private
			#     cgroup namespace, cgroup root "0::/"), NOT the host root, and uses
			#     the single CAP_SYS_ADMIN the pod is granted for exactly this — no
			#     privileged, no /dev/kvm, no NET_ADMIN/RAW. systemd in container
			#     mode does NOT self-remount a ro cgroup (verified), so this is required.
			#  2. Writable /etc. dockerTools lays the NixOS toplevel's own /etc as
			#     a symlink into the immutable Nix store, so activation's setup-etc
			#     cannot populate it. Drop the symlink; NixOS then builds a fresh
			#     writable /etc on the overlay rootfs.
			#
			# Both are no-ops/best-effort if a future runtime delegates a writable
			# cgroup or the image stops baking /etc, so the shim degrades cleanly.
			# NB: at boot time PATH points only at /run/current-system/sw/bin (not
			# yet populated), so every command here MUST be an absolute store path.
			agentInit = pkgs.writeShellScript "cogbox-agent-init" ''
				# cgroup-v2: make the kubelet's read-only delegated /sys/fs/cgroup
				# writable so systemd PID1 can build its hierarchy. NON-userns: a
				# remount,rw works (the pod's host-level CAP_SYS_ADMIN owns the
				# superblock). Under a USERNS (hostUsers:false) that remount EPERMs --
				# a SYS_ADMIN confined to a non-initial userns cannot change mount
				# flags on the cgroup2 superblock, which is owned by the INIT userns --
				# so fall back to mounting a FRESH pod-owned cgroup2 over it: cgroup2
				# is userns-mountable, the new superblock is owned by THIS userns
				# (hence writable), and the pod's private cgroup namespace scopes it to
				# the pod's own subtree. No silent "|| true": if neither works the boot
				# log says so loudly instead of dying as an opaque systemd exit 255.
				if ! ${pkgs.util-linux}/bin/mount -o remount,rw /sys/fs/cgroup 2>/dev/null; then
					${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null \
						|| echo "cogbox-agent-init: WARNING: /sys/fs/cgroup stayed read-only (remount,rw and a fresh cgroup2 mount both failed); systemd will likely fail to boot" >&2
				fi
				[ -L /etc ] && ${pkgs.coreutils}/bin/rm -f /etc || true

				# Boot the per-instance toplevel (the plugin's FULL NixOS module folded in)
				# when a valid record exists, else the baked plugin-less base. The record +
				# closure are seeded WITH egress at plugin-add (prebuildToplevelLocal); boot
				# has none, so realise the recorded out-path OFFLINE from the per-instance
				# file:// plugin-cache on the state PVC (the base is already in the image
				# store, so only the plugin's delta is fetched). Any miss -- no record, rev
				# mismatch (image bump), or an unrealisable path -- falls back to the baked
				# base, so the sandbox always boots. Pre-systemd: /etc/nix/nix.conf does not
				# exist yet, so pass nix options explicitly and RESTRICT substituters to the
				# local cache (no network attempt on the egress-less boot); read the RAW PVC
				# path (the /var/lib/cogbox symlink oneshot has not run yet).
				top=${containerToplevel}
				inst="''${COGBOX_INSTANCE:-default}"
				icd="/var/lib/cogbox-state/config/cogbox/instances/$inst"
				rec="$icd/toplevel.path"
				attempt="$icd/toplevel.attempt"
				if [ -f "$rec" ]; then
					rev="$(${pkgs.coreutils}/bin/head -n1 "$rec")"
					out="$(${pkgs.coreutils}/bin/head -n2 "$rec" | ${pkgs.coreutils}/bin/tail -n1)"
					if [ "$rev" = "${self}" ] && [ -n "$out" ]; then
						# Crash-loop guard: an attempt marker for THIS out-path means a
						# previous boot exec'd it but it never reached the confirm oneshot
						# (systemd failed to boot) -- do NOT re-boot the unbootable toplevel;
						# fall back to the baked base so the sandbox stays usable (tools still
						# land via the brain). A re-add yields a new out-path (marker mismatch),
						# so a fixed plugin IS retried; the confirm oneshot clears the marker
						# once the recorded toplevel boots successfully.
						if [ -f "$attempt" ] && [ "$(${pkgs.coreutils}/bin/cat "$attempt" 2>/dev/null)" = "$out" ]; then
							echo "cogbox-agent-init: per-instance toplevel $out failed a prior boot; booting baked base" >&2
						elif ${pkgs.nix}/bin/nix-store --realise "$out" --option substituters "file://$icd/plugin-cache" --option require-sigs false --option build-users-group "" >/dev/null 2>&1 && [ -x "$out/init" ]; then
							${pkgs.coreutils}/bin/mkdir -p "$icd" 2>/dev/null || true
							echo "$out" > "$attempt" 2>/dev/null || true
							top="$out"
							echo "cogbox-agent-init: booting per-instance toplevel $out" >&2
						else
							echo "cogbox-agent-init: per-instance toplevel not realisable offline; booting baked base" >&2
						fi
					else
						echo "cogbox-agent-init: toplevel record stale/invalid (image bump?); booting baked base" >&2
					fi
				fi
				exec "$top/init"
			'';
			# Space-separated enabled-harness names, baked into cogbox-launch.sh's
			# `HARNESSES=(@harnesses@)` so the launcher's set can never drift from
			# what the VM was built with (single source of truth: mkHarnesses +
			# enableCodex).
			harnessNames = lib.concatStringsSep " " (lib.attrNames (mkHarnesses system pkgs));
			# Build a cogbox package: the Zig CLI binary at $out/bin/cogbox,
			# the LD_PRELOAD filter at $out/lib/libnetfilter.so, and the
			# substituted bash launch script at $out/libexec/cogbox-launch.sh.
			# bin/cogbox is wrapped to expose runtime deps on PATH and to
			# point COGBOX_LAUNCH_SCRIPT at its sibling libexec script.
			#
			# `reexecAttr` is the flake PACKAGE ATTRIBUTE this cogbox re-execs
			# itself through when an instance has plugins or a customized
			# per-instance flake (`nix run path:@flakeSource@#@reexecPackage@`),
			# and it has to be baked because that re-exec is what rebuilds the
			# guest. The re-exec used to be attribute-LESS -- `nix run
			# path:<flake>` -- which resolves packages.default, i.e. plain
			# `cogbox`, i.e. the WORKSTATION guest. Byte-identical behaviour for
			# `cogbox` itself, since default IS cogbox; load-bearing for
			# cogbox-hosted below, where an attribute-less re-exec would have
			# silently swapped the hosted guest for the workstation one on the
			# first plugin add -- unmounting the user's data pool and showing them
			# the stale retained 9p work tree, with no error anywhere.
			#
			# It is ALSO exported as COGBOX_REEXEC_PACKAGE, because the launcher's
			# runner.path record is keyed on "<flakeSource>#<reexecPackage>" (see
			# cogbox-launch.sh) and the Zig plugin verb pre-writes that same record
			# from the worker pod. Both writers have to spell the key identically
			# or the pre-write is silently rejected on every boot and a fresh
			# instance pays a full eval it had already been spared. The Zig side
			# defaults to "cogbox" when the variable is absent, which is what an
			# unwrapped binary and every pre-existing image mean.
			mkCogboxAttr = reexecAttr: runner': pkgs.runCommand "cogbox" {
				nativeBuildInputs = [ pkgs.makeWrapper ];
				meta = { mainProgram = "cogbox"; };
			} ''
				mkdir -p $out/bin $out/lib $out/libexec
				cp ${self.packages.${system}.cogbox-tools}/bin/cogbox $out/bin/cogbox
				chmod +w $out/bin/cogbox
				cp ${self.packages.${system}.cogbox-tools}/lib/libnetfilter.so $out/lib/libnetfilter.so

				# L7 terminate-tier enforcement addon for mitmproxy.
				cp ${./l7-mitm-addon.py} $out/libexec/l7-mitm-addon.py
				cp ${./cogbox-launch.sh} $out/libexec/cogbox-launch.sh
				chmod +w $out/libexec/cogbox-launch.sh
				substituteInPlace $out/libexec/cogbox-launch.sh \
					--replace-fail "@runtimeDir@" "${runtimeDir}" \
					--replace-fail "@runner@" "${runner'}" \
					--replace-fail "@netfilter@" "$out/lib/libnetfilter.so" \
					--replace-fail "@cogbox@" "$out/bin/cogbox" \
					--replace-fail "@harnesses@" "${harnessNames}" \
					--replace-fail "@mitmdump@" "${pkgs.mitmproxy}/bin/mitmdump" \
					--replace-fail "@l7addon@" "$out/libexec/l7-mitm-addon.py" \
					--replace-fail "@flock@" "${pkgs.util-linux}/bin/flock" \
					--replace-fail "@dumpe2fs@" "${pkgs.e2fsprogs}/bin/dumpe2fs" \
					--replace-fail "@flakeSource@" "${self}" \
					--replace-fail "@reexecPackage@" "${reexecAttr}" \
					--replace-fail "@nixpkgsSource@" "${nixpkgs}"
				chmod +x $out/libexec/cogbox-launch.sh
				
				# Container enforcer supervisor (sidecar PID1). Reuses the same cogbox
				# binary + mitmdump + L7 addon as the launch script; NO VM tokens.
				cp ${./cogbox-enforce.sh} $out/libexec/cogbox-enforce.sh
				chmod +w $out/libexec/cogbox-enforce.sh
				substituteInPlace $out/libexec/cogbox-enforce.sh \
					--replace-fail "@cogbox@" "$out/bin/cogbox" \
					--replace-fail "@mitmdump@" "${pkgs.mitmproxy}/bin/mitmdump" \
					--replace-fail "@l7addon@" "$out/libexec/l7-mitm-addon.py"
				chmod +x $out/libexec/cogbox-enforce.sh
				
				# nft REDIRECT divert init -- the nft-init sidecar's entrypoint. Standalone
				# POSIX sh (bare nft/awk resolved from the nft-init image PATH), so it
				# carries no @-substitutions; co-located here for provenance/debugging.
				cp ${./cogbox-nft-divert.sh} $out/libexec/cogbox-nft-divert.sh
				chmod +x $out/libexec/cogbox-nft-divert.sh

				wrapProgram $out/bin/cogbox \
					--set COGBOX_LAUNCH_SCRIPT $out/libexec/cogbox-launch.sh \
					--set COGBOX_ENFORCE_SCRIPT $out/libexec/cogbox-enforce.sh \
					--set-default COGBOX_FLAKE_SOURCE "${self}" \
					--set-default COGBOX_NIXPKGS_SOURCE "${nixpkgs}" \
					--set-default COGBOX_REEXEC_PACKAGE "${reexecAttr}" \
					--prefix PATH : "${lib.makeBinPath (with pkgs; [
						coreutils gnused gnugrep jq diffutils nix bashInteractive openssh
					] ++ [ self.packages.${system}.passt-cc ])}"

				# `cbx` is a short alias for `cogbox`. The wrapper execs an
				# absolute path to .cogbox-wrapped (not $0) and the Zig CLI
				# ignores argv[0], so the symlink behaves identically.
				ln -s cogbox $out/bin/cbx
			'';
			# Partial application, so every existing `mkCogbox <runner>` call site
			# stays exactly as it was and keeps re-execing through `cogbox`.
			mkCogbox = mkCogboxAttr "cogbox";
		in rec {
			cogbox-tools = pkgs.stdenv.mkDerivation {
				pname = "cogbox-tools";
				version = "0.1.0";
				src = lib.cleanSourceWith {
					filter = name: type: !(
						lib.hasSuffix ".nix" (toString name)
						|| lib.hasSuffix ".lock" (toString name)
					);
					src = lib.cleanSource ./zig;
				};
				nativeBuildInputs = [ pkgs.zig ];
				dontConfigure = true;
				dontInstall = true;
				buildPhase = ''
					export HOME=$TMPDIR
					zig build --prefix $out -Doptimize=ReleaseSafe \
						--global-cache-dir $TMPDIR/.zig-global-cache
				'';
			};
			# Backwards-compatible alias
			netfilter = cogbox-tools;
			passt-cc = pkgs.passt.overrideAttrs (old: {
				# Allow rt_sigreturn so LD_PRELOAD signal handlers work
				# under passt's seccomp filter (needed for SIGUSR1 rule reload)
				makeFlags = (old.makeFlags or []) ++ [ "EXTRA_SYSCALLS=rt_sigreturn" ];
			});
			cogbox = mkCogbox runner;
			default = cogbox;

			# cogbox baked against the HOSTED-storage-profile guest, for the GCE
			# backend image (gce/cogbox-host.nix's cogboxHosted wrapper is the sole
			# consumer). Identical Zig binary and launch script; the only
			# differences are which runner's store path is substituted for
			# @runner@ and which package the launcher re-execs through.
			#
			# It has to be a separate PACKAGE, not a host module option or a
			# launch-time flag, because the guest closure is baked at this point:
			# mkCogbox substitutes a runner store path into cogbox-launch.sh, and
			# `nixosConfigurations.cogbox-<arch>-hosted` is where the storage
			# profile is set. mkGceHost's extraModules configure the HOST system
			# and cannot reach the guest config at all.
			#
			# LOCAL USERS ARE UNTOUCHED: `cogbox`, `default` and every existing
			# consumer above still resolve the workstation runner, and the
			# workstation nixosConfiguration is unchanged.
			cogbox-hosted = mkCogboxAttr "cogbox-hosted" runnerHosted;

			# cogbox CLI for the container-native agent image: identical Zig
			# binary + launch script, but baked against a NON-store placeholder
			# runner so the heavy microvm runner closure (QEMU, guest kernel) is
			# NOT pulled into the agent image. The container IS the sandbox -- it
			# never launches a VM, so the only `cogbox` paths it exercises are the
			# control-plane verbs (init/rules/l7/remap/plugin) and `cogbox init`'s
			# --init-only host-state seeding, none of which dereference @runner@.
			# COGBOX_FLAKE_SOURCE/COGBOX_NIXPKGS_SOURCE stay baked (the in-container
			# per-instance brain rebuild below needs them).
			cogbox-container = mkCogbox "/var/empty/cogbox-container-has-no-vm-runner";

			# Container image for a single cogbox sandbox pod: bundles the cogbox
			# CLI so a Kubernetes control plane (e.g. cogworx) runs `cogbox start`
			# against /dev/kvm inside the pod. streamLayeredImage (not
			# buildLayeredImage) makes the image a build script that streams the
			# tarball on demand -- nothing multi-hundred-MB is realized into the
			# Nix store; pipe it to skopeo / `docker load` (see push-pod-image).
			cogbox-pod-image = pkgs.dockerTools.streamLayeredImage {
				name = "cogbox-pod";
				tag = "latest";
				# passt self-sandboxes by mounting a tmpfs at /tmp and pivot_root-ing
				# into it; streamLayeredImage creates no /tmp, so passt failed with
				# ENOENT and the guest VM booted with no networking. Provide /tmp.
				extraCommands = "mkdir -m 1777 -p tmp var/tmp";
				contents = [
					cogbox
					# nix's git+http(s)/ssh flake fetcher execs the `git` CLI; without it
					# `cogbox plugin add <git+...>` fails "executing git: No such file".
					# cacert + SSL_CERT_FILE (below) let the https variant verify TLS.
					pkgs.git
					# The worker pod pre-builds the microvm runner at plugin-add time and
					# pushes the closure to a binary cache so boot substitutes it instead
					# of rebuilding from source (cogbox plugin's COGBOX_RUNNER_PUSH path).
					pkgs.attic-client
					pkgs.cacert
					pkgs.bashInteractive
					pkgs.coreutils
					# `kubectl cp <local> <worker>:<dst>` (cogworx, the
					# STOPPED-instance archive-upload path) untars INTO this container, so it
					# needs `tar` on the exec PATH -- coreutils does NOT ship it, and without it
					# the cp fails "exec: tar: not found" before the plugin add runs. The agent
					# image gets tar from /run/current-system/sw/bin; the worker is a plain
					# userland, so add it explicitly.
					pkgs.gnutar
					# cogbox-launch.sh is `#!/usr/bin/env bash`; without /usr/bin/env
					# the kernel can't find the interpreter and `cogbox init` ExecvFails.
					pkgs.dockerTools.usrBinEnv
					# passt drops privileges to `nobody` and cogbox calls `id`; both
					# need /etc/passwd + /etc/group. fakeNss seeds root + nobody.
					pkgs.dockerTools.fakeNss
					# In-pod nix must BUILD the microvm runner when an instance has a
					# plugin: a no-plugin runner is the baked-in cache hit, but a
					# plugin's custom NixOS module makes a fresh closure. The pod has
					# no `nixbld` group, so nix's default `build-users-group = nixbld`
					# aborts every build -- empty it so nix builds single-user as root
					# (the pod is itself the isolation boundary). `sandbox = false`:
					# the build sandbox needs namespace/mount setup the pod doesn't
					# grant, and plugin builds are trusted-on-add. `substituters` makes
					# the standard leaf deps (nodejs, ...) substitute from the public
					# caches the pod is given egress to, so only the small
					# plugin-specific top is built from source. cogbox-launch.sh still
					# adds the per-instance PVC plugin-cache via `--extra-substituters`
					# (require-sigs false) on top of this.
					(pkgs.writeTextDir "etc/nix/nix.conf" (lib.concatStringsSep "\n" [
						"experimental-features = nix-command flakes"
						"build-users-group ="
						"sandbox = false"
						"substituters = https://cache.nixos.org https://cache.numtide.com"
						"trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY= niks3.numtide.com-1:DTx8wZduET09hRmMtKdQDxNNthLQETkc/yaX7M4qK0g="
					] + "\n"))
				];
				config = {
					Entrypoint = [ "/bin/sh" ];
					Env = [ "PATH=/bin" "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" ];
				};
			};

			# Container-native agent image:
			# the cogbox guest's NixOS userland booted as an UNPRIVILEGED
			# container -- no QEMU, no /dev/kvm, no privileged. Reuses the
			# streamLayeredImage builder from cogbox-pod-image, but the contents
			# are a full NixOS toplevel: /etc, users, /etc/nix/nix.conf, and CA
			# trust are generated by NixOS activation at boot, so -- unlike the
			# plain-userland cogbox-pod-image -- this image needs no fakeNss /
			# usrBinEnv / baked nix.conf / cacert layers (their equivalents are
			# mkContainer options). Entrypoint is systemd PID1 via the toplevel's
			# /init; it runs the reused brain/trust/l7-trust oneshots to
			# multi-user.target. cogbox-pod-image is deliberately left untouched
			# (the VM backend coexists).
			agent-image = pkgs.dockerTools.streamLayeredImage {
				name = "cogbox-agent";
				tag = "latest";
				# systemd PID1 + early units need a writable /tmp; streamLayeredImage
				# seeds none (same reason as cogbox-pod-image). Also bake root's home
				# /root: NixOS does not create it for a container, and creating a new
				# entry directly under / can be blocked by the runtime's rootfs
				# ownership -- so the reused brain-materialize/trust oneshots (which
				# write ~/work + dotfiles under /root) get a real, writable home.
				# Also drop the NixOS toplevel's baked /etc symlink (it points into
				# the read-only Nix store, so activation's setup-etc cannot populate
				# it); with it gone NixOS builds a fresh writable /etc on the overlay
				# rootfs at boot. The agent-init shim repeats this defensively at
				# runtime in case the whiteout does not survive the layering.
				# Bake a /bin/sh -> bash symlink: NixOS creates /bin/sh only during
					# activation (setupBinSh), but cogworx's CoW-store seed init container
					# runs `sh -c <script>` against THIS image BEFORE systemd/activation (to
					# seed the node-shared /nix lower + mount the per-instance overlay), so it
					# needs a shell at the raw-image /bin/sh. bashInteractive is root's login
					# shell, already in the toplevel closure. The seed script is otherwise
					# self-contained (globs coreutils/util-linux/grep out of the store), so
					# /bin/sh is the ONLY userland entry it needs baked here.
					extraCommands = "mkdir -m 1777 -p tmp var/tmp && mkdir -m 0700 -p root && rm -f etc && mkdir -p bin && ln -sf ${pkgs.bashInteractive}/bin/bash bin/sh && mkdir -p etc/cogbox && cp ${baseReginfo}/registration etc/cogbox/base-reginfo";
				# The store closure arrives via the toplevel (also referenced by
				# Entrypoint); no extra userland layers are needed.
				contents = [ containerToplevel ];
				config = {
					# Entrypoint is the pre-systemd shim (above), which fixes the
					# cgroup/-etc container quirks then exec's the NixOS systemd PID1.
					Entrypoint = [ "${agentInit}" ];
					# Mirror the cogworx k8s pod env so a
					# kubectl-exec'd `c`/`tmux`/`git` resolves identically whether or
					# not the pod also sets these. /run/current-system/sw/bin is
					# populated by NixOS activation (the harness launchers c/oc, tmux,
					# git all live there).
					Env = [
						"PATH=/run/current-system/sw/bin:/usr/bin:/bin"
						"XDG_CONFIG_HOME=/var/lib/cogbox-state/config"
						"COGBOX_DATA=/var/lib/cogbox-state/data/cogbox"
						"XDG_RUNTIME_DIR=/run/cogbox"
						"SSL_CERT_FILE=/run/cogbox/ca-bundle.crt"
						# UTF-8 locale for a `kubectl exec` (which sources no login
						# shell, so it does not pick up /etc/locale.conf): without this
						# LC_CTYPE stays C (ASCII) and tmux/claude-code render in
						# degraded boxes. C.UTF-8 is the glibc builtin the container
						# system sets as i18n.defaultLocale. Mirrors the cogworx pod env
						# so a direct/worker-pod exec inherits it even without the pod.
						"LANG=C.UTF-8"
						"LC_CTYPE=C.UTF-8"
						# NixOS stage-2 + systemd run in container mode only when the
						# `container` env var is set (nspawn sets it; containerd/k8s do
						# not). Without it stage-2 tries to remount / and mount host
						# special filesystems, all of which fail unprivileged. Set it
						# so the guest boots as a container, not a host.
						"container=oci"
					];
				};
			};
				# Container enforcer sidecar image (the L7 proxy/mitm control plane). Uses
				# the placeholder-runner cogbox (cogbox-container) so NO QEMU/microvm-runner
				# closure is pulled in; mitmdump + the L7 addon + cogbox-enforce.sh arrive via
				# that cogbox's closure (the @mitmdump@/@l7addon@ substitutions). The pod
				# overrides Entrypoint with `cogbox enforce -n <name>`. (passt-cc/libnetfilter
				# remain incidentally in the cogbox closure but are unused here.)
				enforcer-image = pkgs.dockerTools.streamLayeredImage {
					name = "cogbox-enforcer";
					tag = "latest";
					# mitmproxy/python + the supervisor write under /tmp; streamLayeredImage
					# seeds none (same as cogbox-pod-image). Provide it.
					extraCommands = "mkdir -m 1777 -p tmp var/tmp";
					contents = [
						cogbox-container          # cogbox CLI + cogbox-enforce.sh + mitmdump + L7 addon (closure)
						pkgs.cacert
						pkgs.bashInteractive
						pkgs.coreutils
						pkgs.gnugrep              # cogbox-enforce.sh greps the CA for a stray private key
						# cogbox-enforce.sh is `#!/usr/bin/env bash`; without /usr/bin/env the
						# kernel cannot find the interpreter.
						pkgs.dockerTools.usrBinEnv
						# mitmproxy drops privileges / calls id(); both need /etc/passwd + group.
						pkgs.dockerTools.fakeNss
					];
					config = {
					  # Pod sets command: ["cogbox","enforce","-n",<name>]; this is a sane default.
					  Entrypoint = [ "/bin/cogbox" ];
					  Env = [ "PATH=/bin" "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" ];
					};
				};

				# nft REDIRECT divert init image -- the privileged native sidecar (NET_ADMIN/
				# NET_RAW). MINIMAL: just nftables + iproute2 + coreutils + /bin/sh + the
				# standalone divert script (entrypoint). NO cogbox/qemu/mitmproxy. The
				# separate-pod divert script uses nft alone -- the old cgroup-handshake
				# (find -inum + awk) is gone -- so gawk + findutils are dropped. The pod
				# sets no command, so the image Entrypoint runs the script directly; the
				# enforcer ClusterIP carve-out arrives via COGBOX_ENFORCER_IP/PORT env.
				nft-init-image = pkgs.dockerTools.streamLayeredImage {
					name = "cogbox-nft-init";
					tag = "latest";
					contents = [
						pkgs.nftables             # nft (loads the divert + fail-closed floor)
						pkgs.iproute2             # ip (the native-sidecar netns toolkit / debugging)
						pkgs.coreutils            # sleep/cat/printf for the script + entrypoint
						pkgs.dockerTools.binSh    # /bin/sh for the script's #!/bin/sh
						(pkgs.runCommand "cogbox-nft-divert" {} ''
							mkdir -p $out/bin
							cp ${./cogbox-nft-divert.sh} $out/bin/cogbox-nft-divert
							chmod +x $out/bin/cogbox-nft-divert
						'')
					];
					config = {
					  Entrypoint = [ "/bin/cogbox-nft-divert" ];
					  Env = [ "PATH=/bin" "COGBOX_DIVERT_PORT=18443" ];
					};
				};

		} // lib.optionalAttrs (system == "x86_64-linux") {
			# Test fixture: a cogbox wrapper baked against the
			# pre-built test-hello runner. Used by tests/cogbox.nix
			# Phase E to make the offline NixOS test machine's
			# `nix run --override-input userExtensions ...` resolve as a
			# cache hit instead of building the transitive .drv graph
			# (which would fail with no network).
			cogbox-test-hello = mkCogbox
				self.nixosConfigurations.cogbox-x86_64-test-hello.config.microvm.declaredRunner;
			# Phase Q analog: wrapper baked against the composition-shaped
			# runner (see cogbox-x86_64-test-plugin).
			cogbox-test-plugin = mkCogbox
				self.nixosConfigurations.cogbox-x86_64-test-plugin.config.microvm.declaredRunner;

			# The GCE backend image: a raw disk.raw wrapped in the sparse
			# gzipped tar `gcloud compute images create` imports. Building it
			# is an OPERATOR step (it boots a builder VM and produces a
			# multi-GB artifact), which is why nothing in `checks` depends on
			# it -- the checks assert the CLOSURE and the UNIT GRAPH of the
			# system this image contains, which is where the image invariants live.
			#
			# PHASE-0: nixpkgs' postVM tars with the default GNU format. Confirm `gcloud compute
			# images create` accepts it before the bake is called done.
			gce-image = self.nixosConfigurations.cogbox-x86_64-gce.config.system.build.googleComputeImage;
		});

		# `nix run .#push-pod-image [-- <registry-ref>]` streams the sandbox-pod
		# image straight into the destination registry. Supply the ref as the arg
		# or via $COGBOX_POD_REF (default is a placeholder); registry auth comes
		# from $REGISTRY_AUTH_FILE, else ~/.docker/config.json.
		apps = forAllSystems (system: let
			pkgs = nixpkgs.legacyPackages.${system};
			image = self.packages.${system}.cogbox-pod-image;
			agentImage = self.packages.${system}.agent-image;
			enforcerImage = self.packages.${system}.enforcer-image;
			nftInitImage = self.packages.${system}.nft-init-image;
		in {
			push-pod-image = {
				type = "app";
				program = "${pkgs.writeShellApplication {
					name = "push-pod-image";
					runtimeInputs = [ pkgs.skopeo ];
					text = ''
						ref="''${1:-''${COGBOX_POD_REF:-registry.example.com/team/cogbox-pod:latest}}"
						authfile="''${REGISTRY_AUTH_FILE:-$HOME/.docker/config.json}"
						echo "Pushing cogbox-pod -> docker://$ref (auth: $authfile)" >&2
						${image} | skopeo copy --insecure-policy --authfile "$authfile" docker-archive:/dev/stdin "docker://$ref"
						echo "Pushed $ref" >&2
					'';
				}}/bin/push-pod-image";
			};
			# `nix run .#push-agent-image [-- <registry-ref>]` streams the
			# container-native agent image into the destination registry. Supply
			# the ref as the arg or via $COGBOX_AGENT_REF (default is a
			# placeholder); auth from $REGISTRY_AUTH_FILE, else ~/.docker/config.json.
			push-agent-image = {
				type = "app";
				program = "${pkgs.writeShellApplication {
					name = "push-agent-image";
					runtimeInputs = [ pkgs.skopeo ];
					text = ''
						ref="''${1:-''${COGBOX_AGENT_REF:-registry.example.com/team/cogbox-agent:latest}}"
						authfile="''${REGISTRY_AUTH_FILE:-$HOME/.docker/config.json}"
						echo "Pushing cogbox-agent -> docker://$ref (auth: $authfile)" >&2
						${agentImage} | skopeo copy --insecure-policy --authfile "$authfile" docker-archive:/dev/stdin "docker://$ref"
						echo "Pushed $ref" >&2
					'';
				}}/bin/push-agent-image";
			};
			# `nix run .#push-enforcer-image [-- <ref>]` streams the enforcer sidecar
			# image into the destination registry. Ref via the arg or $COGBOX_ENFORCER_REF
			# (default a placeholder on registry.example.com); auth from
			# $REGISTRY_AUTH_FILE, else ~/.docker/config.json.
			push-enforcer-image = {
				type = "app";
				program = "${pkgs.writeShellApplication {
					name = "push-enforcer-image";
					runtimeInputs = [ pkgs.skopeo ];
					text = ''
						ref="''${1:-''${COGBOX_ENFORCER_REF:-registry.example.com/team/cogbox-enforcer:latest}}"
						authfile="''${REGISTRY_AUTH_FILE:-$HOME/.docker/config.json}"
						echo "Pushing cogbox-enforcer -> docker://$ref (auth: $authfile)" >&2
						${enforcerImage} | skopeo copy --insecure-policy --authfile "$authfile" docker-archive:/dev/stdin "docker://$ref"
						echo "Pushed $ref" >&2
					'';
				}}/bin/push-enforcer-image";
			};
			# `nix run .#push-nft-init-image [-- <ref>]` streams the nft-init sidecar
			# image. Ref via the arg or $COGBOX_NFT_INIT_REF (default a placeholder on
			# registry.example.com); auth as above.
			push-nft-init-image = {
				type = "app";
				program = "${pkgs.writeShellApplication {
					name = "push-nft-init-image";
					runtimeInputs = [ pkgs.skopeo ];
					text = ''
						ref="''${1:-''${COGBOX_NFT_INIT_REF:-registry.example.com/team/cogbox-nft-init:latest}}"
						authfile="''${REGISTRY_AUTH_FILE:-$HOME/.docker/config.json}"
						echo "Pushing cogbox-nft-init -> docker://$ref (auth: $authfile)" >&2
						${nftInitImage} | skopeo copy --insecure-policy --authfile "$authfile" docker-archive:/dev/stdin "docker://$ref"
						echo "Pushed $ref" >&2
					'';
				}}/bin/push-nft-init-image";
			};
		} // lib.optionalAttrs (system == "x86_64-linux") {
			# `nix run .#push-gce-image [-- <gs://bucket/prefix>]` stages the
			# GCE image tarball in GCS and registers it as a Compute image in a
			# family.
			#
			# This is the OPERATOR image-pipeline identity's job, never the
			# lifecycle credential's: the least-privilege model excludes
			# `images.create` plus GCS staging from the role cogworxd holds, so
			# a compromised lifecycle credential cannot substitute the trusted
			# half's own code. Run it with the pipeline identity's gcloud
			# credentials, not cogworxd's service-account key.
			#
			# IT TAKES THE IMAGE PATH AS INPUT and refuses to default to
			# `packages.gce-image`. That default was the whole hazard: the
			# packaged image is built from the flake's DEFAULT host config,
			# whose cogworx.gce.controlCAPublicKey is empty. Publishing is the one
			# step where that mistake becomes expensive, so this is where it
			# fails closed. See README ("Two things the image cannot supply").
			push-gce-image = {
				type = "app";
				program = "${pkgs.writeShellApplication {
					name = "push-gce-image";
					runtimeInputs = [ pkgs.google-cloud-sdk pkgs.coreutils ];
					text = ''
						bucket="''${1:-''${COGWORX_GCE_IMAGE_BUCKET:-gs://example-bucket/cogbox-gce}}"
						family="''${COGWORX_GCE_IMAGE_FAMILY:-cogbox-gce}"
						name="''${COGWORX_GCE_IMAGE_NAME:-$family-$(date -u +%Y%m%d%H%M%S)}"
						src="''${COGWORX_GCE_IMAGE_SRC:-}"
						if [ -z "$src" ]; then
							echo "push-gce-image: set COGWORX_GCE_IMAGE_SRC to the build output of a CA-BAKED image." >&2
							echo "  nix build --impure --expr '((builtins.getFlake \"/path/to/cogbox\").lib.mkGceHost \"x86_64-linux\" { extraModules = [ { cogworx.gce.controlCAPublicKey = \"ssh-ed25519 AAAA... cogworx-control-ca\"; } ]; }).config.system.build.googleComputeImage'" >&2
							echo "  COGWORX_GCE_IMAGE_SRC=./result nix run .#push-gce-image" >&2
							echo "This does NOT default to packages.gce-image: that one bakes no control CA, so sshd would trust nothing and every instance would wedge in Booting." >&2
							exit 1
						fi
						if [ -d "$src" ]; then
							src=$(echo "$src"/*.raw.tar.gz)
						fi
						[ -f "$src" ] || { echo "push-gce-image: no image tarball at $src" >&2; exit 1; }
						obj="$bucket/$(basename "$src")"
						echo "Staging $src -> $obj" >&2
						gcloud storage cp "$src" "$obj"
						echo "Creating image $name (family $family) from $obj" >&2
						gcloud compute images create "$name" \
							--source-uri="$obj" \
							--family="$family"
						# The control plane pins the IMMUTABLE NUMERIC ID, never
						# the name: deleting an image frees its name, so a
						# name pin would let the whole trusted half be replaced
						# while the recorded pin still matched. Print the id so
						# the operator records the right thing.
						gcloud compute images describe "$name" --format='value(id,name,selfLink)'
					'';
				}}/bin/push-gce-image";
			};
		});

		checks = forAllSystems (system: let
			pkgs = nixpkgs.legacyPackages.${system};
			hermesHomeHelper = mkHermesHomeHelper pkgs;
			containerStateScript = self.nixosConfigurations."${configName system}-container".config.systemd.services.cogbox-container-state.serviceConfig.ExecStart;
			# Machine-state anti-shadow evidence for container-state-unit below. The
			# three PVC-backed symlinks replace DIRECTORIES in root's home, and four
			# harness mounts are nested under those same directories on the VM target
			# -- so the whole safety argument for using a symlink here is "the
			# container target declares no fileSystems at all". Read that off the
			# realized configs instead of trusting the prose: if the container ever
			# grows a mount, or the VM ever loses one of the nested harness mounts,
			# this fails at eval rather than at runtime in a user's sandbox.
			containerMountPoints = lib.attrNames self.nixosConfigurations."${configName system}-container".config.fileSystems;
			vmMountPoints = lib.attrNames self.nixosConfigurations.${configName system}.config.fileSystems;
			# Derived from the harness definition, not restated, so a harness that
			# adds or moves a path is covered without editing the check.
			opencodeGuestPaths = lib.optionals (enabledHarnesses ? "opencode")
				(lib.mapAttrsToList (_: p: p.guest) enabledHarnesses.opencode.paths);
			# Guest storage-profile evidence for cogbox-guest-volume-hosted and
			# cogbox-guest-binds-ordered below. The realized /etc/fstab is the whole
			# assertion surface: it is what stage 1 and systemd-fstab-generator actually
			# read, so it captures the volume-generated device, the merged options and the
			# x-initrd.mount / neededForBoot split in one artifact. environment.etc.fstab
			# rather than `${toplevel}/etc/fstab` (the gce-image-* idiom) on purpose:
			# byte-identical content for a few kilobytes of build instead of a whole guest
			# system, and these two checks are meant to be cheap enough to always run.
			hostedFstab = self.nixosConfigurations."${configName system}-hosted".config.environment.etc.fstab.source;
			workstationFstab = self.nixosConfigurations.${configName system}.config.environment.etc.fstab.source;
			hostedCfg = self.nixosConfigurations."${configName system}-hosted".config;
			hostedGuestDirsScript = hostedCfg.systemd.services.cogbox-guest-dirs.serviceConfig.ExecStart;
			hostedWorkMigrateScript = hostedCfg.systemd.services.cogbox-guest-work-migrate.serviceConfig.ExecStart;
			hostedHarnessMigrateScript = hostedCfg.systemd.services.cogbox-guest-harness-migrate.serviceConfig.ExecStart;
			# The two units that SCAFFOLD, for cogbox-guest-migrate-behaviour. Both
			# write into a legacy surface unconditionally, on every boot, before any
			# migration can look at it -- which is exactly the sequence the occupancy
			# cases have to reproduce and used not to. The REALIZED ExecStarts rather
			# than a hand-copy of their mkdirs and symlinks: a harness added or renamed,
			# or a brain layout change, then moves the scaffolding in the fixture too,
			# instead of leaving it asserting a shape the system has stopped producing.
			# Cheap -- both closures are bash plus the brain, ~38 MiB total.
			hostedHarnessDirsScript = hostedCfg.systemd.services.harness-setup-dirs.serviceConfig.ExecStart;
			hostedBrainMaterializeScript = hostedCfg.systemd.services.cogbox-brain-materialize.serviceConfig.ExecStart;
			# The harness lowers that MUST stay read-only 9p shares in the hosted
			# profile. Derived from the realized microvm config, so a share that loses
			# readOnly shows up here as a false and not as a silently weakened sandbox.
			hostedHarnessLowers = lib.filter (s: lib.hasPrefix "/var/lib/harness-lower/" s.mountPoint)
				hostedCfg.microvm.shares;
			# The REALIZED harness-setup-dirs unit files, both profiles, for
			# cogbox-guest-pool-degradable. Read as files rather than as the
			# systemd.services.*.requires option, because it is the [Unit] section
			# systemd actually acts on and the option is only one of several inputs to
			# it.
			hostedHarnessDirsUnit = "${hostedCfg.systemd.units."harness-setup-dirs.service".unit}/harness-setup-dirs.service";
			workstationUnit = n: "${self.nixosConfigurations.${configName system}.config.systemd.units.${n}.unit}/${n}";
			workstationHarnessDirsUnit = workstationUnit "harness-setup-dirs.service";
			# EVERY profile in which the data pool sits on the guest's boot path, for
			# cogbox-guest-pool-boot-bounded. The pool is NOT hosted-only: `workstation`
			# + machineState = "persist" declares the same volume with the same label,
			# and its realized fstab carries the same pass-2 pool line -- so the same
			# generated fsck gates the same sshd there. That combination has no
			# nixosConfigurations entry of its own (it is an opt-in on the default
			# guest), so it is extended here rather than added to the flake's output
			# set: this check is its only consumer, and an fstab plus a handful of unit
			# files is all it costs.
			poolBootProfiles = {
				hosted = hostedCfg;
				workstation-persist = (self.nixosConfigurations.${configName system}.extendModules {
					modules = [ { cogbox.storage.machineState = "persist"; } ];
				}).config;
			};
			# The pool's mount point, DERIVED from the realized fileSystems instead of
			# spelled: it is the sole autoResize entry in either profile. The check
			# asserts that there is exactly one, so a second growable filesystem --
			# which would come with a second unbounded systemd-growfs@ instance -- forces
			# a look here rather than quietly going unbounded.
			poolAutoResized = cfg: lib.attrNames (lib.filterAttrs (_: f: f.autoResize) cfg.fileSystems);
			# The bounds this change renders, in one directory keyed by unit name, so the
			# check can look one up by the name the GENERATOR produced. Selected by
			# override strategy rather than by a list: a bound added later is covered
			# without editing this, and -- the point -- a bound rendered as a FULL unit
			# instead of a drop-in is NOT here. That distinction is not pedantic: the
			# default strategy (asDropinIfExists) finds no
			# systemd-fsck@<instance>.service to extend, installs the bound as a whole
			# unit shadowing systemd-fsck@.service, and the pool then never gets checked
			# at all -- a unit with no ExecStart succeeds instantly.
			poolBoundDropins = name: cfg: pkgs.runCommand name { } (''
				mkdir -p $out
			'' + lib.concatMapStringsSep "\n"
				(n: ''cp -L '${cfg.systemd.units.${n}.unit}/${n}' "$out/${n}"'')
				(lib.attrNames (lib.filterAttrs
					(_: u: (u.overrideStrategy or "") == "asDropin") cfg.systemd.units)));
			# EVERY realized service unit of the hosted guest, in one directory, so
			# cogbox-guest-pool-degradable can scan the whole set instead of the units
			# somebody remembered to name. Built out of systemd.units rather than out of
			# ${toplevel}/etc/systemd/system to keep that check cheap: 76 tiny
			# derivations instead of a whole guest system.
			#
			# The honest limit of that surface, stated because the check reads stronger
			# than it is otherwise: systemd.units holds only what NixOS RENDERS. Units
			# shipped by upstream systemd itself never appear, and one of them is a
			# member of exactly the class scanned there --
			# systemd-journal-flush.service carries RequiresMountsFor=/var/log/journal
			# upstream, so an absent pool fails it. That one is the accepted
			# volatile-journal degradation: the journal stays in /run/log/journal
			# exactly as it did before this change, and sysinit.target only WANTS the
			# unit. The scan exists for cogbox-authored units, and every one of those
			# lands here.
			serviceUnitsOf = name: cfg: pkgs.runCommand name { } (''
				mkdir -p $out
			'' + lib.concatMapStringsSep "\n"
				(n: ''cp -L '${cfg.systemd.units.${n}.unit}/${n}' "$out/${n}"'')
				(lib.attrNames (lib.filterAttrs (n: _: lib.hasSuffix ".service" n)
					cfg.systemd.units)));
			hostedServiceUnits = serviceUnitsOf "hosted-service-units" hostedCfg;
			# The STAGE-2 overlay mounts, per profile: nixpkgs' overlayfs module gives
			# each one a `rw-<escaped mountPoint>.service` that mkdirs its upper and work
			# dirs before the mount, and under `hosted` those dirs are on the pool.
			# x-initrd.mount is the same split the module makes (fsNeededForBoot ->
			# boot.initrd.systemd.services), so this excludes the /nix/store overlay,
			# whose pre-mount unit is in the initrd and never sees the pool.
			stage2Overlays = cfg: lib.attrNames (lib.filterAttrs
				(_: f: (f.overlay.lowerdir or null) != null && !(lib.elem "x-initrd.mount" f.options))
				cfg.fileSystems);
			# The two realized harness-config reconcile scripts, one per backend, for
			# harness-firstrun-flags below. Forcing the two small scripts rather than
			# a toplevel keeps that check cheap.
			containerHarnessConfScript = self.nixosConfigurations."${configName system}-container".config.systemd.services.cogbox-claude-stub.serviceConfig.ExecStart;
			vmHarnessConfScript = self.nixosConfigurations.${configName system}.config.systemd.services.cogbox-brain-trust.serviceConfig.ExecStart;
			# Every cogbox GUEST config that renders a resolved.conf, paired with
			# its name, for guest-dns-no-public-fallback below. Forcing the small
			# ini file rather than a toplevel keeps that check cheap. Today only
			# the microVM guest contributes: the container has resolved disabled
			# (kubelet owns its /etc/resolv.conf), so it renders no file.
			guestResolvedConfs = lib.concatMap (name: let
				etc = self.nixosConfigurations.${name}.config.environment.etc;
			in lib.optional (etc ? "systemd/resolved.conf") {
				inherit name;
				path = etc."systemd/resolved.conf".source;
			}) [ (configName system) "${configName system}-container" ];
			enabledHarnesses = mkHarnesses system pkgs;
			releaseHarnesses = {
				claude-code = enabledHarnesses.claude-code.package;
				opencode = enabledHarnesses.opencode.package;
				codex = inputs.llm-agents.packages.${system}.codex;
				hermes-agent = enabledHarnesses.hermes-agent.package;
				omp = enabledHarnesses.omp.package;
				dsh = enabledHarnesses.dsh.package;
				# pi is opt-out of the default image (enablePi above), so it is no longer
				# in enabledHarnesses. Reference the BASE numtide pi (not the overridden
				# one we've stopped shipping) so the release version gate stays a cache
				# hit and needs no npmjs egress -- mirrors how codex is handled above.
				pi = inputs.llm-agents.packages.${system}.pi;
			};
			# GCE backend image assertions (x86_64 only; nested virt is Intel
			# only). These are lazy let-bindings, forced only by the
			# x86_64-guarded checks at the bottom of this block.
			gceCfg = self.nixosConfigurations.cogbox-x86_64-gce.config;
			gceToplevel = gceCfg.system.build.toplevel;
			gceUnits = "${gceToplevel}/etc/systemd/system";
			# closureInfo over the toplevel is exactly what make-disk-image.nix
			# loads into the image's store DB, so asserting against it asserts
			# against what the booted VM can actually resolve offline.
			gceClosure = pkgs.closureInfo { rootPaths = [ gceToplevel ]; };
			gceFloorVerify = gceCfg.systemd.services.cogworx-floor.serviceConfig.ExecStartPost;
			gceFloorInstall = gceCfg.systemd.services.cogworx-floor.serviceConfig.ExecStart;
			gceSuperviseScript = gceCfg.systemd.services.cogworx-supervisor.serviceConfig.ExecStart;
			gceStateDiskScript = gceCfg.systemd.services.cogworx-state-disk.serviceConfig.ExecStart;
			gceGuestDiskScript = gceCfg.systemd.services.cogworx-guest-disk.serviceConfig.ExecStart;
			# The HOST half of the boot-boundedness evidence, for
			# gce-image-host-boot-bounded. Same three artifacts the guest check uses,
			# fed the GCE host configuration instead of a guest profile: its realized
			# fstab (what systemd-fstab-generator actually reads), the drop-ins this
			# configuration renders with overrideStrategy = "asDropin" (where a bound on
			# a GENERATED unit has to live), and every service unit it renders in full
			# (where a bound on an AUTHORED unit lives instead).
			gceFstab = gceCfg.environment.etc.fstab.source;
			gceBoundDropins = poolBoundDropins "gce-host-bound-dropins" gceCfg;
			gceHostServiceUnits = serviceUnitsOf "gce-host-service-units" gceCfg;
			# The SAME module realized with a small store-overlay size, for
			# gce-image-guest-disk-behaviour. That check runs the script against real
			# block devices, and the shipped one carves a 16 GiB logical volume --
			# which in a vmTools VM means a multi-gigabyte tmpfs and a minutes-long
			# mkfs for a property that has nothing to do with the number.
			#
			# It is a re-REALIZATION, not a copy: same file, same code path, one
			# option value different. gce-image-guest-disk-format proves that claim
			# rather than asserting it in prose -- it diffs the two realized scripts
			# with the two size lines normalised out and fails if anything else
			# differs, so a behaviour test that drifted away from what ships is a
			# build failure.
			gceGuestDiskScriptSmall = (mkGceHost "x86_64-linux" {
				extraModules = [ { cogworx.gce.storeOverlaySizeMiB = 32; } ];
			}).config.systemd.services.cogworx-guest-disk.serviceConfig.ExecStart;
			gceResolverDeadlineScript = gceCfg.systemd.services.cogworx-resolver-deadline.serviceConfig.ExecStart;
			gceCogboxWrapper = gceCfg.cogworx.gce.cogboxPackage;
			# The delivery seam of the hosted guest, in the pieces
			# gce-image-hosted-guest-profile walks: the package the image bakes, the
			# workstation package it must NOT be able to reach, both runners (the
			# workstation one is still needed -- for the vacuity guard and for the
			# not-in-closure assertion), and the volume device paths -- re-derived HERE
			# from the hosted guest configuration so the check compares the supervisor's
			# env against the volumes the runner actually declares rather than against a
			# copy of the same literals.
			gceHostedCogbox = self.packages.x86_64-linux.cogbox-hosted;
			gceWorkstationCogbox = self.packages.x86_64-linux.cogbox;
			gceHostedRunner = self.nixosConfigurations."cogbox-x86_64-hosted".config.microvm.declaredRunner;
			gceWorkstationRunner = self.nixosConfigurations.cogbox-x86_64.config.microvm.declaredRunner;
			gceHostedVolumeDevices = map (v: v.image)
				(lib.filter (v: !v.autoCreate)
					self.nixosConfigurations."cogbox-x86_64-hosted".config.microvm.volumes);
			# Stands in for the real cogbox binary so gce-cogbox-wrapper-env can
			# observe what the wrapper actually exported, without running a verb.
			gceWrapperEnvStub = pkgs.writeShellScript "cogbox-env-stub" ''
				printf 'XDG_CONFIG_HOME=%s\n' "''${XDG_CONFIG_HOME-<unset>}"
				printf 'COGBOX_DATA=%s\n' "''${COGBOX_DATA-<unset>}"
				printf 'XDG_RUNTIME_DIR=%s\n' "''${XDG_RUNTIME_DIR-<unset>}"
				printf 'COGBOX_PROXY_RUNAS=%s\n' "''${COGBOX_PROXY_RUNAS-<unset>}"
			'';
			# The bake seam of `lib.mkGceHost`, evaluated (not built) so the
			# runbook's one supported way to inject a control CA is asserted
			# rather than asserted-in-prose. A fictional key line: nothing parses
			# it, the check only proves it reaches sshd's TrustedUserCAKeys file.
			gceBakeCAKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEcontrolCAkeyFORtheFLAKEcheck control-ca";
			gceBakedCAText = (mkGceHost "x86_64-linux" {
				extraModules = [ { cogworx.gce.controlCAPublicKey = gceBakeCAKey; } ];
			}).config.environment.etc."ssh/cogworx-control-ca.pub".text;
			gceDefaultCAText = gceCfg.environment.etc."ssh/cogworx-control-ca.pub".text;
			# The MERGE-ABLE seam, exercised through the same bake path: a composed
			# profile's own user CA has to have somewhere to land, because
			# TrustedUserCAKeys itself is forced and a definition there loses
			# silently. Fictional key lines; nothing parses them.
			gceBakeExtraCAKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEfleetCAkeyFORtheFLAKEcheck fleet-ca";
			gceBakedExtraCAText = (mkGceHost "x86_64-linux" {
				extraModules = [ {
					cogworx.gce.controlCAPublicKey = gceBakeCAKey;
					cogworx.gce.extraTrustedUserCAKeys = [ gceBakeExtraCAKey ];
				} ];
			}).config.environment.etc."ssh/cogworx-control-ca.pub".text;
			# The realized sshd PAM stack, read as a string so gce-image-control-pam
			# can assert the ORDER of the account rules rather than their presence.
			gcePamSshd = gceCfg.security.pam.services.sshd.text;
			# The DNS-upstream publishability guard (cogworx.gce's second
			# assertion), exercised through the same bake seam an operator uses:
			# does a CA-baked host still EVALUATE?
			#
			# Forced through `system.build.toplevel.drvPath` because that is the
			# attribute NixOS makes THROW on a failed assertion. `config.assertions`
			# is only a list -- a tryEval over it succeeds in every leg, so the
			# negative leg below would pass no matter what the module asserted.
			gceResolverBakeEvals = extraModules: (builtins.tryEval (mkGceHost "x86_64-linux" {
				extraModules = [ { cogworx.gce.controlCAPublicKey = gceBakeCAKey; } ] ++ extraModules;
			}).config.system.build.toplevel.drvPath).success;
			# Default upstream, unaffirmed: must NOT evaluate.
			gceResolverDefaultBakeEvals = gceResolverBakeEvals [ ];
			# Pointed at another resolver: must evaluate. 192.0.2.1 is
			# documentation-range (RFC 5737) -- nothing dials it, the leg only reads
			# whether the assertion fired.
			gceResolverPointedBakeEvals = gceResolverBakeEvals [ { cogworx.gce.vpcResolver = "192.0.2.1"; } ];
			# Default upstream, affirmed: must evaluate.
			gceResolverAffirmedBakeEvals = gceResolverBakeEvals [ { cogworx.gce.allowMetadataResolver = true; } ];
			# And the CA-less default host, which the guard must leave alone:
			# `packages.gce-image` builds this one. Memoized -- the other gce-image-*
			# checks force this same toplevel.
			gceResolverDefaultHostEvals = (builtins.tryEval gceToplevel.drvPath).success;
		in lib.optionalAttrs ((mkHarnesses system pkgs) ? "hermes-agent") {
			# Exercise the same helper used by the container state unit. There is no
			# container boot harness in this repository, so retain one invocation check.
			container-state-unit = pkgs.runCommand "cogbox-container-state-unit" {} ''
				helper=${hermesHomeHelper}/bin/cogbox-hermes-home
				assert_fails() {
					if "$@"; then
						echo "expected failure: $*" >&2
						exit 1
					fi
				}

				mkdir fresh
				"$helper" "$PWD/fresh/persistent" "$PWD/fresh/home"
				test -d "$PWD/fresh/persistent"
				test "$(stat -c %a "$PWD/fresh/persistent")" = 700
				test -L "$PWD/fresh/home"
				test "$(readlink "$PWD/fresh/home")" = "$PWD/fresh/persistent"
				touch "$PWD/fresh/persistent/marker"
				"$helper" "$PWD/fresh/persistent" "$PWD/fresh/home"
				test -f "$PWD/fresh/persistent/marker"

				mkdir -p empty/persistent empty/home
				chmod 755 empty/persistent
				"$helper" "$PWD/empty/persistent" "$PWD/empty/home"
				test "$(stat -c %a "$PWD/empty/persistent")" = 700
				test "$(readlink "$PWD/empty/home")" = "$PWD/empty/persistent"

				mkdir -p nonempty/persistent nonempty/home
				touch nonempty/persistent/target-marker nonempty/home/source-marker
				assert_fails "$helper" "$PWD/nonempty/persistent" "$PWD/nonempty/home"
				test -f nonempty/persistent/target-marker
				test -f nonempty/home/source-marker
				test ! -L nonempty/home

				mkdir -p wrong-link/persistent wrong-link/elsewhere
				touch wrong-link/persistent/target-marker wrong-link/elsewhere/source-marker
				ln -s "$PWD/wrong-link/elsewhere" wrong-link/home
				assert_fails "$helper" "$PWD/wrong-link/persistent" "$PWD/wrong-link/home"
				test "$(readlink wrong-link/home)" = "$PWD/wrong-link/elsewhere"
				test -f wrong-link/persistent/target-marker
				test -f wrong-link/elsewhere/source-marker

				mkdir bad-target
				printf 'persistent marker\n' > bad-target/persistent
				assert_fails "$helper" "$PWD/bad-target/persistent" "$PWD/bad-target/home"
				grep -qFx 'persistent marker' bad-target/persistent
				test ! -e bad-target/home

				mkdir -p target-symlink/source
				touch target-symlink/source/marker
				ln -s "$PWD/target-symlink/source" target-symlink/persistent
				assert_fails "$helper" "$PWD/target-symlink/persistent" "$PWD/target-symlink/home"
				test "$(readlink target-symlink/persistent)" = "$PWD/target-symlink/source"
				test -f target-symlink/source/marker
				test ! -e target-symlink/home

				mkdir -p link-file/persistent
				touch link-file/persistent/target-marker
				printf 'link marker\n' > link-file/home
				assert_fails "$helper" "$PWD/link-file/persistent" "$PWD/link-file/home"
				test -f link-file/persistent/target-marker
				grep -qFx 'link marker' link-file/home

				mkdir identical
				assert_fails "$helper" "$PWD/identical/home" "$PWD/identical/home"
				test ! -e identical/home

				mkdir correct-missing
				ln -s "$PWD/correct-missing/persistent" correct-missing/home
				"$helper" "$PWD/correct-missing/persistent" "$PWD/correct-missing/home"
				test -d correct-missing/persistent
				test "$(readlink correct-missing/home)" = "$PWD/correct-missing/persistent"

				mkdir -p wrong-missing/source
				touch wrong-missing/source/marker
				ln -s "$PWD/wrong-missing/source" wrong-missing/home
				assert_fails "$helper" "$PWD/wrong-missing/persistent" "$PWD/wrong-missing/home"
				test ! -e wrong-missing/persistent
				test "$(readlink wrong-missing/home)" = "$PWD/wrong-missing/source"
				test -f wrong-missing/source/marker

				mkdir -p nonempty-missing/home
				printf 'source marker\n' > nonempty-missing/home/marker
				assert_fails "$helper" "$PWD/nonempty-missing/persistent" "$PWD/nonempty-missing/home"
				test ! -e nonempty-missing/persistent
				test -d nonempty-missing/home
				grep -qFx 'source marker' nonempty-missing/home/marker

				# Deterministically reproduce the post-validation race outcome: GNU ln
				# -T must reject the destination directory without creating a child link.
				mkdir -p raced/persistent raced/home
				touch raced/home/directory-marker
				assert_fails ln -sT -- "$PWD/raced/persistent" "$PWD/raced/home"
				test -d raced/home
				test -f raced/home/directory-marker
				test ! -e raced/home/persistent
				test "$(grep -c 'ln -sT --' "$helper")" = 2

				grep -qF '${hermesHomeHelper}/bin/cogbox-hermes-home /var/lib/cogbox-state/hermes-home /root/.hermes' ${containerStateScript}

				# The machine-state legs (PVC-backed ~/.cache, ~/.local, ~/.config).
				# Restated literally here rather than shared with the module's
				# let-binding on purpose: an independent restatement catches a drift,
				# a shared binding would co-vary with it and assert nothing.
				for leg in \
					'/var/lib/cogbox-state/machine/cache /root/.cache' \
					'/var/lib/cogbox-state/machine/local /root/.local' \
					'/var/lib/cogbox-state/machine/config /root/.config'
				do
					grep -qF "$helper $leg" ${containerStateScript} || {
						echo "FAIL: the container state unit no longer persists: $leg" >&2
						exit 1
					}
				done

				# EVERY machine-state leg must stay individually tolerant. The unit runs
				# under `set -e`, so an untolerated failure takes the whole unit down --
				# and with it the /var/lib/cogbox symlink, the seeded instance config and
				# sshd's persisted host key -- wedging the sandbox over a cache
				# directory. Counted RELATIVE to the number of legs rather than pinned at
				# three, so adding a fourth machine-state path stays the one-line edit the
				# module claims it is, while dropping a fallback still goes red.
				# `|| true` on both counts: grep exits 1 on ZERO matches, which under the
				# builder's set -e aborts before the diagnostics below can say why.
				legs=$(grep -c "$helper /var/lib/cogbox-state/machine/" ${containerStateScript} || true)
				tolerated=$(grep -c 'continuing on the ephemeral container layer' ${containerStateScript} || true)
				test "$legs" -ge 3 || {
					echo "FAIL: only $legs machine-state legs in the container state unit; expected at least the three PVC-backed home directories" >&2
					exit 1
				}
				test "$legs" = "$tolerated" || {
					echo "FAIL: $legs machine-state legs but $tolerated '|| echo ...' fallbacks; under set -e an untolerated leg takes the whole state unit -- and with it /var/lib/cogbox, the seeded config and sshd's host key -- down" >&2
					exit 1
				}

				# The persistent parent must be pre-created: the helper's own mkdir has
				# no -p, so /var/lib/cogbox-state/machine/<sub> is uncreatable -- and
				# every leg fails -- unless the parent already exists.
				grep -qE 'mkdir -p .*/var/lib/cogbox-state/machine([[:space:]]|$)' ${containerStateScript} || {
					echo "FAIL: the container state unit no longer pre-creates /var/lib/cogbox-state/machine; the helper's mkdir has no -p, so every machine-state leg would fail" >&2
					exit 1
				}

				# ANTI-SHADOW, part 1: /root itself must NEVER be a link path. It
				# carries the harness overlay/bind mounts, the runtime /root/work
				# symlink, the fw_cfg-written /root/.claude.json and the
				# tmpfiles-managed /root/.nix-channels; a symlink over /root shadows
				# all of them at once.
				if grep -qE 'cogbox-hermes-home [^ ]+ /root([[:space:]]|$)' ${containerStateScript}; then
					echo "FAIL: the container state unit links /root itself; that shadows the harness mounts, /root/work, .claude.json and .nix-channels" >&2
					exit 1
				fi

				# ANTI-SHADOW, part 2: the container target must keep declaring NO
				# filesystems. That is the entire reason a symlink over the ~/.cache,
				# ~/.local and ~/.config DIRECTORIES is safe here -- a mount at or under
				# any of them would be silently orphaned by the link, and only at
				# runtime.
				container_mounts='${lib.concatStringsSep " " containerMountPoints}'
				if [ -n "$container_mounts" ]; then
					echo "FAIL: the container target now declares mounts ($container_mounts); a machine-state symlink can orphan them -- re-check the strategy before adding one" >&2
					exit 1
				fi

				# ANTI-SHADOW, part 3: the VM target is deliberately NOT changed by
				# this, and still owns the harness mounts nested under those same three
				# directories. These are precisely what a future edit would orphan if
				# the machine-state links were ever extended to the VM, so pin them --
				# and pin that none of the three link roots (nor /root) is itself a VM
				# mount point.
				vm_mounts=' ${lib.concatStringsSep " " vmMountPoints} '
				for m in ${lib.concatStringsSep " " opencodeGuestPaths}; do
					case "$vm_mounts" in
					*" $m "*) ;;
					*)
						echo "FAIL: the VM target no longer mounts $m; the container machine-state links assume the VM keeps owning the nested harness paths" >&2
						exit 1
						;;
					esac
				done
				for m in /root /root/.cache /root/.local /root/.config; do
					case "$vm_mounts" in
					*" $m "*)
						echo "FAIL: the VM target mounts $m; that shadows the nested harness mounts" >&2
						exit 1
						;;
					esac
				done
				touch $out
			'';
		} // lib.optionalAttrs (builtins.hasAttr system inputs.llm-agents.packages) {
			# The harness's first-run dialog state is reconciled in TWO places -- the
			# container's claude-stub oneshot and the VM's brain-trust oneshot -- and,
			# inside the container one, on TWO branches (fresh write vs merge onto an
			# existing config). Nothing at eval time couples the three, so an edit can
			# fix one and leave a fresh sandbox parked on an interactive first-run
			# prompt instead of reaching the REPL. No unit or VM test in this repo
			# reaches that: it needs an interactive terminal, and `claude -p` passes
			# either way. Assert the realized scripts by grep: cheap,
			# and it fails on the drift rather than on the symptom.
			harness-firstrun-flags = pkgs.runCommand "cogbox-harness-firstrun-flags" { } ''
				fails=0
				container=${containerHarnessConfScript}
				vm=${vmHarnessConfScript}

				for flag in hasCompletedOnboarding bypassPermissionsModeAccepted; do
					# Container, fresh-write branch: the literal used when no config exists.
					if ! grep -qF "\"$flag\":true" "$container"; then
						echo "FAIL: container fresh write does not set $flag" >&2
						fails=$((fails + 1))
					fi
					# Container, merge branch: FORCED (=), not defaulted (//=), so a config
					# the harness has already rewritten still ends up with it.
					if ! grep -qF ".$flag = true" "$container"; then
						echo "FAIL: container merge branch does not force $flag" >&2
						fails=$((fails + 1))
					fi
					# VM: the same two, via brain-trust's isVm-guarded jq program.
					if ! grep -qF ".$flag = true" "$vm"; then
						echo "FAIL: VM brain-trust does not force $flag" >&2
						fails=$((fails + 1))
					fi
				done

				# bypassPermissionsModeAccepted is read off the GLOBAL config getter, so
				# it has to be top-level. Written under .projects[...] -- where the
				# neighbouring trust dialog legitimately lives -- it is never read, and
				# the dialog still fires with the config looking correct to a grep.
				if grep -qE 'projects\[[^]]*\]\.bypassPermissionsModeAccepted' "$container" "$vm"; then
					echo "FAIL: bypassPermissionsModeAccepted written under .projects[...]; the global getter would never see it" >&2
					fails=$((fails + 1))
				fi

				test "$fails" = 0
				touch $out
			'';

			harness-versions = pkgs.runCommand "cogbox-harness-versions" {} ''
				export HOME=$TMPDIR/home
				export HERMES_HOME=$HOME/.hermes
				mkdir -p "$HERMES_HOME"/{cron,sessions,logs,memories}
				assert_version() {
					expected=$1
					shift
					if ! output=$("$@" 2>&1); then
						printf 'version command failed: %s\n%s\n' "$*" "$output" >&2
						exit 1
					fi
					case "$output" in
					*"$expected"*) ;;
					*)
						printf 'expected version %s from %s, got: %s\n' "$expected" "$*" "$output" >&2
						exit 1
						;;
					esac
				}

				test '${releaseHarnesses.claude-code.version}' = '2.1.238'
				test '${releaseHarnesses.opencode.version}' = '1.18.19'
				test '${releaseHarnesses.codex.version}' = '0.149.0'
				test '${releaseHarnesses.hermes-agent.version}' = '2026.8.18'
				test '${releaseHarnesses.omp.version}' = '17.4.0'
				test '${releaseHarnesses.pi.version}' = '0.84.2'
				test '${releaseHarnesses.dsh.version}' = '0.1.0-rc.7'

				assert_version '2.1.238' ${releaseHarnesses.claude-code}/bin/claude --version
				assert_version '1.18.19' ${releaseHarnesses.opencode}/bin/opencode --version
				assert_version '0.149.0' ${releaseHarnesses.codex}/bin/codex --version
				assert_version '17.4.0' ${releaseHarnesses.omp}/bin/omp --version
				assert_version '0.84.2' ${releaseHarnesses.pi}/bin/pi --version
				assert_version '0.1.0-rc.7' ${releaseHarnesses.dsh}/bin/dsh --version

				if ! hermes_output=$(${releaseHarnesses.hermes-agent}/bin/hermes --version 2>&1); then
					printf 'version command failed: hermes --version\n%s\n' "$hermes_output" >&2
					exit 1
				fi
				for expected in 'v0.20.4' '(2026.8.18)'; do
					case "$hermes_output" in
					*"$expected"*) ;;
					*)
						printf 'expected Hermes version %s, got: %s\n' "$expected" "$hermes_output" >&2
						exit 1
						;;
					esac
				done
				touch $out
			'';
		} // {
			# Pure-helper parity + credential-injection unit tests for the
			# mitmproxy L7 addon. Fast (no VM); keeps the addon's host
			# pattern / path / cred-injection logic honest on every build.
			addon-tests = pkgs.runCommand "cogbox-addon-tests" {
				nativeBuildInputs = [ pkgs.python3 ];
			} ''
				cp ${./l7-mitm-addon.py} l7-mitm-addon.py
				# The single-source stub-token / no-env-stub assertions read these
				# from ../ relative to tests/; stage them so the check can grep them.
				cp ${./cogbox-launch.sh} cogbox-launch.sh
				cp ${./flake.nix} flake.nix
				# The SHARED path-matcher vector table. The Zig suite embeds this
				# very file; staging it here is what makes the two matchers assert
				# against ONE oracle rather than two copies that can drift.
				mkdir -p zig/src/l7proxy
				cp ${./zig/src/l7proxy/path_vectors.tsv} zig/src/l7proxy/path_vectors.tsv
				# The stub-token no-drift assertion compares the launcher's literal
				# against the Zig one, so stage that source too.
				mkdir -p zig/src/secret
				cp ${./zig/src/secret/main.zig} zig/src/secret/main.zig
				mkdir tests
				cp ${./tests/test_l7_addon.py} tests/test_l7_addon.py
				python3 tests/test_l7_addon.py
				touch $out
			'';

			# The launcher's `init` seeding and its failure-path hygiene, exercised
			# by RUNNING the script (no VM: every case stops at --init-only or fails
			# before the launch). Two invariants no unit test can reach: that
			# --no-implicit-dns / --self-addr actually reach config.json -- without a
			# producer the filter's parameterized port-53 allow and the l7proxy
			# self-address floor are dead code -- and that an init WITHOUT them
			# writes the pre-feature blob unchanged, which is what keeps the local
			# and k8s backends untouched. Plus: no failure path echoes credential
			# context, which matters wherever the launcher's stderr lands somewhere
			# retained outside the machine.
			launch-flag-tests = pkgs.runCommand "cogbox-launch-flag-tests" {
				nativeBuildInputs = with pkgs; [ bash jq coreutils gnugrep ];
			} ''
				export HOME=$TMPDIR
				bash ${./tests/test_launch_flags.sh} ${./cogbox-launch.sh}
				touch $out
			'';

			# cogbox-enforce.sh's FIRST-EVER test. Everything in that supervisor
			# is an ordering or a refusal invisible in the unit file or the pod
			# spec, so a flake check over the manifest cannot reach any of it. By
			# RUNNING the script against stub children it asserts: all three
			# children start in order (mitm -> publish_ca -> auth -> l7proxy),
			# each is restarted INDEPENDENTLY by the wait -n loop -- the auth-proxy
			# arm is the correctness obligation of the whole auth-proxy change --
			# terminate() kills all three, and the two COGBOX_L7_AUTH_* vars reach
			# mitmdump even when l7-auth-hosts does not exist.
			enforce-tests = pkgs.runCommand "cogbox-enforce-tests" {
				nativeBuildInputs = with pkgs; [ bash coreutils gawk gnugrep ];
			} ''
				export HOME=$TMPDIR
				bash ${./tests/test_enforce.sh} ${./cogbox-enforce.sh}
				touch $out
			'';

			zig-tests = pkgs.stdenv.mkDerivation {
				pname = "cogbox-zig-tests";
				version = "0.1.0";
				src = lib.cleanSourceWith {
					filter = name: type: !(
						lib.hasSuffix ".nix" (toString name)
						|| lib.hasSuffix ".lock" (toString name)
					);
					src = lib.cleanSource ./zig;
				};
				nativeBuildInputs = [ pkgs.zig ];
				dontConfigure = true;
				dontInstall = true;
				buildPhase = ''
					export HOME=$TMPDIR
					zig build test --global-cache-dir $TMPDIR/.zig-global-cache \
						&& touch $out
				'';
			};
		} // lib.optionalAttrs (system == "x86_64-linux") {
			# On the container backend the guest half
			# (plugin commands/skills/agents + cogbox.packages) is
			# delivered by the cogbox-brain-materialize oneshot rebuilding the brain
			# at boot. That rebuild MUST evaluate the `-container` config: the VM
			# config imports microvm.nixosModules.microvm, whose input source cannot
			# be fetched in the fail-closed offline sandbox, so evaluating it aborts
			# and silently drops the whole guest half. This check (a) builds the
			# container brain from a fixture that ships a plugin command + package
			# and asserts both land in the brain, and (b) guards that the baked
			# boot rebuild targets the `-container` config, not the VM one.
			container-brain-command = pkgs.runCommand "cogbox-container-brain-command" { } ''
				brain=${self.nixosConfigurations.cogbox-x86_64-brain-fixture-container.config.system.build.cogboxBrain}
				# (a) a plugin-shipped command reaches the container brain's claude tree
				if [ ! -f "$brain/claude/commands/demo-rca.md" ]; then
					echo "FAIL: plugin command not in container brain: $brain/claude/commands/demo-rca.md" >&2
					ls -R "$brain/claude" >&2 || true
					exit 1
				fi
				# cogbox.packages reach the brain's $out/bin (the container PATH surface)
				if [ ! -e "$brain/bin/hello" ]; then
					echo "FAIL: cogbox.packages tool not in container brain: $brain/bin/hello" >&2
					exit 1
				fi
				# (b) the boot rebuild must target the `-container` config (no microvm)
				mat=${self.nixosConfigurations.cogbox-x86_64-container.config.systemd.services.cogbox-brain-materialize.serviceConfig.ExecStart}
				if ! grep -q 'cogbox-x86_64-container.config.system.build.cogboxBrain' "$mat"; then
					echo "FAIL: brain-materialize does not rebuild via the -container config" >&2
					exit 1
				fi
				if grep -qF 'cogbox-x86_64.config.system.build.cogboxBrain' "$mat"; then
					echo "FAIL: brain-materialize rebuilds via the VM config (microvm force-fetch regression)" >&2
					exit 1
				fi
				touch $out
			'';

			# CROSS-PLUGIN UNIT-NAME COLLISIONS RESOLVE, they do not brick the box.
			#
			# WHY THIS NEEDS A CHECK. Plugins live in independently-owned repos and are
			# installed in arbitrary combinations, so no author can see what their
			# skill names will be paired with -- two plugins each shipping
			# skills/overview is normal. Under the old hard assertion that composition
			# did not EVALUATE, so the guest system could not be built at all: `cogbox
				# init` exited non-zero, the supervisor restart-looped, and the real Nix
			# error stayed inside the VM's journal where nobody could see it. The
			# failure surface was a sandbox stuck "Booting" forever.
			#
			# Asserted on a real brain BUILD (the leaf layout and the rewritten
			# frontmatter are the actual guest-visible artifacts), and, for the residue
			# cogbox still cannot resolve, on the MESSAGE rather than merely on the
			# fact that something threw -- "fail to boot, but say why" is the whole
			# point of the residue path.
			brain-unit-name-collisions = let
				# The fixtures live HERE rather than in nixosConfigurations for one
				# reason: two of them must not evaluate, and `nix flake check`
				# evaluates every nixosConfigurations entry's toplevel -- an
				# intentionally-throwing config published there would fail the whole
				# flake check. Each wraps its contents root in exactly the
				# `_file`-stamped module `cogbox plugin add` renders into the
				# per-instance composition flake (zig/src/plugin/compose.zig), so these
				# exercise the real provenance path rather than a stand-in for it.
				# CONTAINER configs: cogboxBrain is target-independent, and the
				# container is the cheaper of the two targets to evaluate.
				collideFixture = imports: (mkContainer system "cogbox" {
					extraModules = cogboxModules system { target = "container"; userExt.imports = imports; };
				}).config.system.build;
				# Three independently-owned plugins, each shipping skills/overview (a
				# and b also ship agents/triage): every copy is qualified, all stay
				# usable. Root `c` is the awkward-but-legal shape a real plugin repo
				# reaches sooner or later -- a SKILL.md with CRLF line endings, and a
				# symlink inside the skill directory that does not resolve in the
				# store -- because both of those used to be silent wrong answers:
				# a copy that kept the bare name in its frontmatter, and a `cp -L`
				# that aborted the whole brain build naming neither plugin nor unit.
				resolved = (collideFixture [
					{ _file = "p-a"; imports = [ ({ ... }: { cogbox.contents = ./tests/fixtures/brain-collide/a; }) ]; }
					{ _file = "p-b"; imports = [ ({ ... }: { cogbox.contents = ./tests/fixtures/brain-collide/b; }) ]; }
					{ _file = "p-c"; imports = [ ({ ... }: { cogbox.contents = ./tests/fixtures/brain-collide/c; }) ]; }
				]).cogboxBrain;
				# Root `d` ships a SKILL.md that is itself a relative symlink ESCAPING
				# its skill directory -- how a repo shares one text between several
				# skill variants. Discovery accepts it either way (pathExists resolves
				# it in the plugin's own tree), and what the qualified copy can then do
				# with it depends on how that tree reaches the build, so BOTH shapes
				# are pinned. `contents` as a store TREE (what a flake input or a
				# `path:` plugin source actually produces: one store path holding the
				# whole repo) keeps the link resolvable at the source, so the leaf is
				# re-materialized from there and gets its rewrite:
				escapingTree = (collideFixture [
					{ _file = "p-a"; imports = [ ({ ... }: { cogbox.contents = ./tests/fixtures/brain-collide/a; }) ]; }
					{ _file = "p-d"; imports = [ ({ ... }: { cogbox.contents = "${./tests/fixtures/brain-collide/d}"; }) ]; }
				]).cogboxBrain;
				# ...whereas a bare path literal makes nix copy each discovered leaf
				# DIRECTORY to the store on its own, so the same link points outside
				# its store path and the leaf cannot be read at all. That is the
				# genuinely-unreadable case, and it must be refused by name instead of
				# shipping a qualified skill whose SKILL.md dangles while the generated
				# index still advertises its description. A BUILDER refusal, not an
				# eval throw, so cogboxBrainCollisions/mustThrow cannot see it: it is
				# asserted with testers.testBuildFailure against the one unit
				# derivation, reached through system.build.cogboxBrainUnits.
				escapingAlone = pkgs.testers.testBuildFailure (collideFixture [
					{ _file = "p-a"; imports = [ ({ ... }: { cogbox.contents = ./tests/fixtures/brain-collide/a; }) ]; }
					{ _file = "p-d"; imports = [ ({ ... }: { cogbox.contents = ./tests/fixtures/brain-collide/d; }) ]; }
				]).cogboxBrainUnits.skills."d-overview";
				# Same collision, but one side is the instance's OWN flake.
				userWins = (collideFixture [
					{ _file = "cogbox-user"; imports = [ ({ ... }: { cogbox.contents = ./tests/fixtures/brain-collide/a; }) ]; }
					{ _file = "p-b"; imports = [ ({ ... }: { cogbox.contents = ./tests/fixtures/brain-collide/b; }) ]; }
				]).cogboxBrain;
				# Residue: ONE plugin providing the same unit from two of its own
				# roots. Nothing distinguishes the copies, so this must still fail.
				sameTag = collideFixture [
					{ _file = "p-a"; imports = [ ({ ... }: { cogbox.contents = [
						./tests/fixtures/brain-collide/a
						./tests/fixtures/brain-collide/b
					]; }) ]; }
				];
				# Residue: a plugin squatting on the reserved index name.
				reserved = collideFixture [
					{ _file = "p-a"; imports = [ ({ ... }: { cogbox.contents = ./tests/fixtures/brain-collide/reserved; }) ]; }
				];
				# Residue: the reserved name reached by QUALIFICATION rather than by
				# discovery. Neither plugin ships `cogbox-plugins`; both ship
				# `plugins`, and the one installed as `cogbox` qualifies onto the
				# index's own leaf. Nothing in the discovered-name pass can see this.
				reservedQual = collideFixture [
					{ _file = "p-cogbox"; imports = [ ({ ... }: { cogbox.contents = ./tests/fixtures/brain-collide/reserved-qual-a; }) ]; }
					{ _file = "p-other"; imports = [ ({ ... }: { cogbox.contents = ./tests/fixtures/brain-collide/reserved-qual-b; }) ]; }
				];
				# builtins.tryEval reports THAT an eval threw and never why, so the
				# text is read off system.build.cogboxBrainCollisions -- the same
				# strings the throw carries, without the throw.
				evalFails = b: !(builtins.tryEval (builtins.seq b.cogboxBrain.drvPath null)).success;
				mustThrow = what: b: lib.optionalString (!(evalFails b)) ''
					echo "FAIL: ${what} must refuse to evaluate, but the brain built" >&2
					exit 1
				'';
			in pkgs.runCommand "cogbox-brain-unit-name-collisions" {
				sameTagMsg = lib.concatStringsSep "\n" sameTag.cogboxBrainCollisions;
				reservedMsg = lib.concatStringsSep "\n" reserved.cogboxBrainCollisions;
				reservedQualMsg = lib.concatStringsSep "\n" reservedQual.cogboxBrainCollisions;
			} ''
				fail() { echo "FAIL: $1" >&2; exit 1; }

				# (1) two PLUGIN roots ship the same names -> every copy is qualified,
				#     both stay usable, and NEITHER keeps the bare name.
				s=${resolved}/claude/skills
				[ -e "$s/a-overview/SKILL.md" ] || fail "a-overview missing from the brain"
				[ -e "$s/b-overview/SKILL.md" ] || fail "b-overview missing from the brain"
				[ -e "$s/overview" ] && fail "bare 'overview' survived a cross-plugin collision"
				grep -qx 'name: a-overview' "$s/a-overview/SKILL.md" || fail "a-overview frontmatter name not rewritten"
				grep -qx 'name: b-overview' "$s/b-overview/SKILL.md" || fail "b-overview frontmatter name not rewritten"
				# The single-file unit kind (agent) takes the other qualifiedUnit branch.
				g=${resolved}/claude/agents
				[ -e "$g/a-triage.md" ] || fail "a-triage.md missing from the brain"
				[ -e "$g/b-triage.md" ] || fail "b-triage.md missing from the brain"
				[ -e "$g/triage.md" ] && fail "bare 'triage.md' survived a cross-plugin collision"
				grep -qx 'name: a-triage' "$g/a-triage.md" || fail "a-triage frontmatter name not rewritten"
				# Only the LEADING '---' block is metadata: a 'name:' line in the body
				# must come through untouched.
				grep -qx 'name: not-metadata' "$g/a-triage.md" || fail "body 'name:' line was rewritten"
				# The index gained a plugin column and attributes each qualified skill.
				i=$s/cogbox-plugins/SKILL.md
				grep -q '^| skill | plugin | description |$' "$i" || fail "index header has no plugin column"
				grep -q '^| `a-overview` | a |' "$i" || fail "index does not attribute a-overview to plugin a"
				grep -q '^| `b-overview` | b |' "$i" || fail "index does not attribute b-overview to plugin b"

				# (1b) the awkward-but-legal plugin tree. A CRLF SKILL.md must still
				# get its frontmatter name rewritten (matching only the byte-exact
				# '---' delimiter silently shipped the bare name), and a symlink that
				# does not resolve must be copied THROUGH rather than dereferenced
				# (which aborted the whole brain build with a `cp: cannot stat`).
				[ -e "$s/c-overview/SKILL.md" ] || fail "c-overview missing from the brain"
				grep -qx 'name: c-overview' "$s/c-overview/SKILL.md" || fail "CRLF skill frontmatter name not rewritten"
				[ -L "$s/c-overview/data.json" ] || fail "unresolvable symlink was not copied through as a symlink"

				# (1c) a SKILL.md that IS a relative symlink escaping its skill
				# directory. The tree is still copied flat, so that link dangles in
				# the copy; the leaf is re-materialized from the source instead. It
				# must arrive as a REAL FILE carrying the QUALIFIED name -- reading it
				# back out of the flat copy left a `d-overview/` whose SKILL.md
				# dangled, with the rewrite and its frontmatter assertion both skipped
				# and nothing said anywhere.
				l=${escapingTree}/claude/skills
				[ -f "$l/d-overview/SKILL.md" ] || fail "d-overview/SKILL.md is not a readable file"
				grep -qx 'name: d-overview' "$l/d-overview/SKILL.md" || fail "symlinked SKILL.md frontmatter name not rewritten"
				# ...and when the same link cannot be read at all, the unit refuses to
				# build, naming the plugin and the unit like every other residue.
				grep -q "cogbox: skill 'overview' from plugin 'd' could not be qualified to 'd-overview'" \
					${escapingAlone}/testBuildFailure.log \
					|| fail "an unreadable SKILL.md was not refused by name"
				[ "$(cat ${escapingAlone}/testBuildFailure.exit)" != 0 ] || fail "an unreadable SKILL.md built anyway"

				# (2) the instance's own flake is never renamed behind the user's back.
				u=${userWins}/claude/skills
				[ -e "$u/overview/SKILL.md" ] || fail "user root lost the bare 'overview'"
				[ -e "$u/b-overview/SKILL.md" ] || fail "plugin copy b-overview missing"
				[ -e "$u/a-overview" ] && fail "user root was qualified"
				grep -qx 'name: overview' "$u/overview/SKILL.md" || fail "user skill frontmatter was rewritten"

				# (3) residue: one plugin, two of its own roots -> throws, and the
				#     message names the plugin and the unit.
				${mustThrow "a same-plugin duplicate" sameTag}
				printf '%s\n' "$sameTagMsg" > same.txt
				grep -q "plugin 'a'" same.txt || fail "same-plugin message does not name the plugin"
				grep -q "skill 'overview'" same.txt || fail "same-plugin message does not name the unit"
				grep -q 'ACROSS plugins' same.txt || fail "same-plugin message does not say what cogbox can/cannot do"

				# (4) residue: the reserved index name -> a real message, not the bare
				#     'ln: File exists' this used to produce.
				${mustThrow "a plugin squatting on the reserved index name" reserved}
				printf '%s\n' "$reservedMsg" > reserved.txt
				grep -q "plugin 'a'" reserved.txt || fail "reserved-name message does not name the plugin"
				grep -q 'cogbox-plugins' reserved.txt || fail "reserved-name message does not name the unit"

				# (5) residue: the reserved index name reached by QUALIFICATION.
				#     Neither plugin ships 'cogbox-plugins'; both ship 'plugins', and
				#     the one installed as 'cogbox' qualifies straight onto the index's
				#     own leaf. Testing only the DISCOVERED name let this through, and
				#     the brain build then died on a bare `ln`/`cp` error naming nobody.
				${mustThrow "a qualified name landing on the reserved index name" reservedQual}
				printf '%s\n' "$reservedQualMsg" > reserved-qual.txt
				grep -q "plugin 'cogbox'" reserved-qual.txt || fail "reserved-qual message does not name the plugin"
				grep -q "skill 'plugins'" reserved-qual.txt || fail "reserved-qual message does not name the discovered unit"
				grep -q "qualifies to 'cogbox-plugins'" reserved-qual.txt || fail "reserved-qual message does not name the qualified unit"

				touch $out
			'';
			# GUEST-HALF DNS: no public fallback resolver, asserted against the
			# rendered resolved.conf rather than against prose.
			#
			# WHY THIS NEEDS A CHECK. The leak is invisible from inside the
			# guest's normal behaviour: resolution keeps working through the
			# link-scope server passt advertises, and only the GLOBAL scope
			# carries systemd's compiled-in 1.1.1.1/8.8.8.8/9.9.9.9 list -- so it
			# reads as `resolvectl status` trivia right up until a link-scope
			# failure ships an INTERNAL query name to a third-party resolver and
			# an internal-DNS outage comes back as an ordinary NXDOMAIN. It also
			# has a near-miss spelling: an empty LIST renders no line at all,
			# which is byte-identical to the defect, and only the empty STRING
			# renders the `FallbackDNS=` that overrides the compiled-in list.
			#
			# Written over "every guest config that renders the file" rather than
			# over the VM by name so that enabling resolved in the container later
			# is covered automatically instead of silently unasserted.
			guest-dns-no-public-fallback = pkgs.runCommand "cogbox-guest-dns-no-public-fallback" { } ''
				fails=0
				${lib.concatMapStrings ({ name, path }: ''
					conf=${path}
					if [ "$(grep -c '^FallbackDNS=' "$conf")" != 1 ]; then
						echo "FAIL: ${name}: resolved.conf carries $(grep -c '^FallbackDNS=' "$conf") FallbackDNS lines, expected exactly 1; with none, systemd's compiled-in PUBLIC resolver list stands at global scope and an internal query name leaks the moment link-scope DNS is unset or fails" >&2
						fails=$((fails + 1))
					elif ! grep -qx 'FallbackDNS=' "$conf"; then
						echo "FAIL: ${name}: FallbackDNS names a resolver ($(grep '^FallbackDNS=' "$conf")); the guest must resolve exactly what the host resolves, or fail visibly" >&2
						fails=$((fails + 1))
					fi
				'') guestResolvedConfs}
				# Non-vacuity. The microVM guest enables networkd, which
				# default-enables resolved, so that config MUST have contributed a
				# file to the loop above; if the attribute path ever moves, this
				# check would otherwise pass by asserting nothing.
				${lib.optionalString (!(lib.any (c: c.name == configName system) guestResolvedConfs)) ''
					echo "FAIL: ${configName system} renders no /etc/systemd/resolved.conf, so this check asserted nothing about the guest's resolver" >&2
					fails=$((fails + 1))
				''}
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';
			cogbox-vm = pkgs.testers.runNixOSTest (import ./tests/cogbox.nix {
				inherit self pkgs system;
			});
			# Standing bypass-test suite for the container-mode nft egress floor
			# (TODO): loads the real cogbox-nft-divert.sh and probes every
			# egress path to PROVE the DNS-tunnel / ICMP / non-tcp-udp-L4 leaks are
			# closed. Needs nested KVM -- runs in CI / on a KVM host, not the dev box.
			nft-floor-bypass = pkgs.testers.runNixOSTest (import ./tests/nft-floor-bypass.nix {
				inherit self pkgs;
			});
		} // lib.optionalAttrs (system == "x86_64-linux") {
			# --- GCE backend image checks -------------------------------------
			#
			# The image itself is an operator bake. What the gce-image-* checks
			# assert is the thing the bake cannot change: the CLOSURE and the UNIT
			# GRAPH of the system inside it. Every one of them stands in for a
			# failure that is invisible until a real instance is already broken in
			# the field.

			# THE offline-boot regression, caught at build time. cogbox-launch.sh's
			# custom-flake re-exec EVALUATES the VM config, which forces every
			# flake input SOURCE TREE. A non-resident input aborts the eval and
			# silently drops the whole guest half.
			# google-compute-image.nix does not thread `additionalPaths` through to
			# make-disk-image.nix, so system.extraDependencies is the only route
			# into the registered store, and this check is what proves it took.
			gce-image-offline-closure = pkgs.runCommand "gce-image-offline-closure" { } ''
				fails=0
				for src in \
					'${inputs.microvm}' \
					'${inputs.llm-agents}' \
					'${inputs.nix-mcp}' \
					'${inputs.illustris-lib}'; do
					if ! grep -qxF "$src" ${gceClosure}/store-paths; then
						echo "FAIL: flake input source $src is NOT in the GCE image's registered closure;" >&2
						echo "      the launcher's re-exec will abort offline and drop the guest half" >&2
						fails=$((fails + 1))
					fi
				done
				# The cogbox package itself, and with it the microvm runner and the
				# guest kernel/initrd/toplevel, must be resident too.
				if ! grep -q 'cogbox' ${gceClosure}/store-paths; then
					echo "FAIL: no cogbox path in the GCE image closure" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# What a flake FETCH needs from the image's userland, which is not the
			# same question as what its closure contains. nix's git+http(s)/ssh
			# fetcher execs the `git` CLI off PATH. Without git, every curated
			# catalog entry fails at resolve time, including entries handled by
			# an ephemeral resolver VM.
			#
			# Neither half is REFERENCED by anything in the image -- the caller is
			# nix, at runtime, by name -- so nothing but this check stands between
			# a boot-disk closure trim and a backend that cannot install a plugin.
			gce-image-flake-fetch = pkgs.runCommand "gce-image-flake-fetch" { } ''
				fails=0
				# On the system path, not merely in the closure: nix resolves the
				# fetcher off PATH, and /run/current-system/sw/bin (= sw/bin of the
				# toplevel) is what a control-channel exec, the supervisor unit and
				# a serial break-glass session all share. Do NOT weaken this to a
				# closureInfo store-paths grep the way the offline-closure check
				# above does -- git was ALREADY in the broken image's closure (the
				# guest half pulls it in), so a closure grep passed while the whole
				# catalog was uninstallable. Adding it here costs ~68 KiB of
				# system-path symlinks, not a git closure.
				if [ ! -x ${gceToplevel}/sw/bin/git ]; then
					echo "FAIL: no git on /run/current-system/sw/bin; nix's git+http(s)/ssh flake fetcher execs the git CLI, so every git+ plugin URL dies with 'executing git: No such file or directory' -- and every curated catalog entry is a git+ URL" >&2
					fails=$((fails + 1))
				fi
				# TLS trust for the https variant. The pod image needs pkgs.cacert +
				# SSL_CERT_FILE for this because it is a bare userland; on NixOS it
				# comes from security.pki instead, i.e. from a file that can vanish
				# by REMOVAL (an environment.etc mkForce, a stripped security.pki)
				# with no missing package to notice. The failure mode is then a
				# certificate error on git+https rather than a missing binary.
				if [ ! -e ${gceToplevel}/etc/ssl/certs/ca-certificates.crt ]; then
					echo "FAIL: the realized system has no /etc/ssl/certs/ca-certificates.crt; git's curl would have no CA bundle, so a git+https plugin fetch cannot verify TLS" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The lifecycle credential's setMetadata capability is inert rather
			# than pretending the permission is narrow. Two of the three doors are
			# closed here: startup/shutdown script execution and OS Login key
			# management. A nixpkgs bump that re-enables either would silently hand
			# `instances.setMetadata` root on the trusted half again.
			gce-image-guest-agent-disabled = pkgs.runCommand "gce-image-guest-agent-disabled" { } ''
				fails=0
				for u in google-guest-agent google-startup-scripts google-shutdown-scripts; do
					hits=$(find ${gceUnits} -name "$u.service" -path '*.wants/*' 2>/dev/null || true)
					if [ -n "$hits" ]; then
						echo "FAIL: $u is still wanted by a target:" >&2
						echo "$hits" >&2
						fails=$((fails + 1))
					fi
					# A .wants symlink is only one of the two routes in. A
					# Wants=/Requires= inside some other unit would start it
					# just as effectively and leaves no symlink to find.
					pulls=$(grep -rlE "^(Wants|Requires|Requisite|BindsTo)=.*$u" ${gceUnits} 2>/dev/null || true)
					if [ -n "$pulls" ]; then
						echo "FAIL: a unit pulls in $u by dependency:" >&2
						echo "$pulls" >&2
						fails=$((fails + 1))
					fi
				done
				if [ '${lib.boolToString gceCfg.security.googleOsLogin.enable}' != false ]; then
					echo "FAIL: security.googleOsLogin.enable is on; metadata ssh-keys would grant login" >&2
					fails=$((fails + 1))
				fi
				# The OS Login PAM/NSS half leaves its own traces even when the
				# service is not wanted, so assert the realized sshd config too.
				if grep -qi 'oslogin' ${gceToplevel}/etc/ssh/sshd_config; then
					echo "FAIL: sshd_config still references OS Login" >&2
					fails=$((fails + 1))
				fi
				# Certificate-only control auth: a bare public key must be
				# refused, so there is no authorized_keys path at all.
				if ! grep -qx 'AuthorizedKeysFile none' ${gceToplevel}/etc/ssh/sshd_config; then
					echo "FAIL: sshd still has an AuthorizedKeysFile path; a bare public key would be accepted" >&2
					fails=$((fails + 1))
				fi
				if ! grep -q '^TrustedUserCAKeys ' ${gceToplevel}/etc/ssh/sshd_config; then
					echo "FAIL: sshd has no TrustedUserCAKeys; the control CA is not baked in" >&2
					fails=$((fails + 1))
				fi
				# The VM host key must live on the STATE disk, or Stop and a
				# boot-disk swap regenerate it and force a silent re-TOFU.
				if ! grep -q '^HostKey /var/lib/cogbox-state/' ${gceToplevel}/etc/ssh/sshd_config; then
					echo "FAIL: sshd's HostKey is not on the state disk" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# Floor-before-sandbox and scrub-independence are both load-bearing
			# orderings. Both are the kind of thing a later "tidy the
			# dependency graph" commit breaks without any test noticing.
			gce-image-unit-ordering = pkgs.runCommand "gce-image-unit-ordering" { } ''
				fails=0
				sup=${gceUnits}/cogworx-supervisor.service
				scrub=${gceUnits}/cogworx-attr-scrub.service
				floor=${gceUnits}/cogworx-floor.service

				# Requires=, not merely After=. With After= alone a floor-failed boot
				# still starts the sandbox, and a full-mode guest on a floorless VM
				# can forge the very guest attributes the boot path trusts.
				req=$(grep '^Requires=' "$sup" || true)
				case "$req" in
					*cogworx-attr-scrub.service*) ;;
					*) echo "FAIL: supervisor does not Requires= the scrub unit ($req)" >&2; fails=$((fails + 1)) ;;
				esac
				case "$req" in
					*cogworx-floor.service*) ;;
					*) echo "FAIL: supervisor does not Requires= the floor unit ($req)" >&2; fails=$((fails + 1)) ;;
				esac
				aft=$(grep '^After=' "$sup" || true)
				case "$aft" in
					*'var-lib-cogbox\x2dstate.mount'*) ;;
					*) echo "FAIL: supervisor is not After= the state-disk mount ($aft)" >&2; fails=$((fails + 1)) ;;
				esac
				if ! grep -q '^ExecStopPost=.' "$sup"; then
					echo "FAIL: supervisor has no ExecStopPost; readiness would latch across the crash paths the poll loop cannot see" >&2
					fails=$((fails + 1))
				fi

				# The scrub retries forever and is INDEPENDENT of the floor. A scrub
				# sequenced after the floor check would never run on a floor-failed
				# same-epoch reboot -- exactly the boot whose stale attribute still
				# carries the current nonce.
				if ! grep -qx 'StartLimitIntervalSec=0' "$scrub"; then
					echo "FAIL: the scrub unit has a start limit; a failed scrub would become terminal" >&2
					fails=$((fails + 1))
				fi
				if grep -E '^(After|Requires|Wants|BindsTo|PartOf)=' "$scrub" | grep -q 'cogworx-floor'; then
					echo "FAIL: the scrub unit is ordered on the floor unit; the same-epoch stale attribute would survive" >&2
					fails=$((fails + 1))
				fi

				# RestartMode=direct, not a nicety. Under the default the unit
				# transits through failed on its way into auto-restart, which
				# CANCELS the supervisor's start job for the rest of the boot --
				# so one transient scrub failure permanently strands the instance
				# in Booting while the scrub itself succeeds on retry #2.
				if ! grep -qx 'RestartMode=direct' "$scrub"; then
					echo "FAIL: the scrub unit is not RestartMode=direct; its first transient failure would cancel the supervisor's start job for the whole boot" >&2
					fails=$((fails + 1))
				fi

				# The floor's live probes, and the empty-set fail-closed that
				# stops a VACUOUS rule 2 from passing a shape-only check.
				if ! grep -q '^ExecStartPost=.' "$floor"; then
					echo "FAIL: the floor unit has no ExecStartPost; the ruleset would be installed but never verified" >&2
					fails=$((fails + 1))
				fi

				# THE FIRST-BOOT SOURCE. cogworx-self-addrs is stamped EMPTY into
				# every insert body (no address exists yet), so a floor unit with
				# only that source refuses the boot of every freshly created
				# sandbox and of every resolver VM -- neither of which gets a
				# second chance to be repaired by a later Start. The install leg
				# must therefore fall back to the metadata server's own interface
				# addresses, and only an empty set from BOTH may fail the boot.
				install=${gceFloorInstall}
				if ! grep -qF 'network-interfaces' "$install"; then
					echo "FAIL: the floor installer has no metadata-server fallback for cogworx-self-addrs; a first boot (empty attribute) would fail closed forever" >&2
					fails=$((fails + 1))
				fi
				# RULE 2 IS A skuid RANGE OVER EVERY UID, SCOPED TO THE ORIGINAL
				# DIRECTION OF A FLOW, and all three of those are load-bearing.
				#
				# It must carry a skuid EXPRESSION: a drop written as a bare `ip
				# daddr <self> drop` also matches the KERNEL-GENERATED return
				# packets of a same-host flow (the RST when nothing is listening),
				# which carry the VM's own address as their destination and no
				# owning socket at all -- so they can never match the skuid-scoped
				# control-uid accept above and get swallowed by the drop below it.
				#
				# It must NOT be narrowed to named uids to get that property. An
				# enumeration (`skuid cogbox-passt`, `skuid cogbox-proxy`) has a
				# skuid expression and would pass the first half while leaving
				# root-run and `nixbld*` in-VM plugin builds -- and passt's own
				# pre-drop, root-owned listening sockets -- outside rule 2. A range
				# is a skuid expression AND covers every uid, so it satisfies both;
				# 4294967295 is (uid_t)-1 and never a real account.
				#
				# And it must be scoped to `ct direction original`, because the
				# skuid range does NOT cover the return path once something is
				# actually LISTENING. passt creates its port-forward listener
				# BEFORE its privilege drop, so a real SYN-ACK has a real owning
				# socket (fsuid 0), no NFT_BREAK happens, and its destination port
				# is the CLIENT's ephemeral port -- unmatchable by any dport accept.
				# The range deny would take cogbox ssh, Terminal,
				# Console-over-ssh and the user SSH gateway down. Direction rather
				# than `ct state new`: a
				# state-scoped deny would additionally let a flow that survived a
				# floor reload keep running, which the stateless rule did not.
				#
				# tests/test_floor.sh proves all of it on the RENDERED ruleset and,
				# in its live section, against a REAL listener in a throwaway netns;
				# these lines stop the format string itself from regressing.
				if ! grep -qF 'meta skuid 0-4294967294 ct direction original ip daddr %s counter drop comment "cogworx-floor-rule2-self"' "$install"; then
					echo "FAIL: the floor installer's rule-2 deny is not the every-uid, original-direction range; it has either lost its skuid match, been narrowed to named uids, or lost the direction scoping that keeps a real listener's reply out of the drop" >&2
					fails=$((fails + 1))
				fi
				if grep -F 'cogworx-floor-rule2-self' "$install" | grep -qF 'meta skuid "'; then
					echo "FAIL: the floor installer renders a named-uid rule-2 deny; root-run and nixbld* plugin builds and passt's pre-drop sockets would be outside rule 2" >&2
					fails=$((fails + 1))
				fi
				# RULE 3 IS THE LOOPBACK LEG, AND IT IS THE OPPOSITE SHAPE TO RULE
				# 2 ON PURPOSE.
				#
				# Rule 2 covers the VM's own non-loopback addresses from every uid.
				# It cannot cover loopback: the L7 remap funnel is a shim-side
				# connect() rewrite to 127.0.0.1:<l7base> made by passt itself, and
				# the trusted half's own components talk to each other there
				# (l7proxy -> the mitm hop, mitmproxy -> its upstreams, the nix
				# daemon, sshd). So loopback was left out of the floor entirely,
				# and the property "a guest cannot address the enclosing VM's
				# services" rested on passt alone: it drops tap frames carrying a
				# loopback address (tap.c), and --no-map-gw removes the
				# gateway->127.0.0.1 mapping. Both are upstream behaviors, so an
				# independent floor remains necessary.
				#
				# Rule 3 supplies the missing layer: the passt uid, and only the
				# passt uid, may not OPEN a flow to loopback except to the funnel's
				# own targets. A skuid RANGE here would cut the trusted half's own
				# loopback traffic, so this is the one rule that must stay
				# uid-scoped -- the exact opposite of rule 2, and worth stating so
				# a later reader does not "fix" the asymmetry.
				if ! grep -qF 'ip daddr 127.0.0.0/8 counter drop comment "cogworx-floor-rule3-loopback"' "$install"; then
					echo "FAIL: the floor installer renders no rule-3 loopback deny; the guest-to-loopback path would rest on passt's tap filter alone, with nothing in the floor behind it" >&2
					fails=$((fails + 1))
				fi
				if ! grep -F 'cogworx-floor-rule3-loopback' "$install" | grep -qF 'ct direction original'; then
					echo "FAIL: the floor installer's rule-3 deny is not scoped to the original direction; it would swallow the L7 funnel's own SYN-ACK (daddr 127.0.0.1, client ephemeral port) and take L7 down the way the stateless rule-2 deny took cogbox ssh down" >&2
					fails=$((fails + 1))
				fi
				if grep -F 'cogworx-floor-rule3-loopback' "$install" | grep -qF 'meta skuid 0-4294967294'; then
					echo "FAIL: the floor installer's rule-3 deny covers every uid; l7proxy, mitmproxy, the nix daemon and sshd all talk over this machine's loopback" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'cogworx-floor-rule3-l7-funnel' "$install"; then
					echo "FAIL: the floor installer renders no rule-3 funnel exception; the L7 remap funnel connects to 127.0.0.1:<l7base> under the passt uid and would be dropped by the rule above" >&2
					fails=$((fails + 1))
				fi
				# RULE 3'S SECOND AND LAST EXCEPTION: the VM's own DNS forwarder.
				# It is there because guest/host resolution parity has no shape
				# that leaves rule 1 alone -- passt re-emits the guest's
				# intercepted DNS queries under the PASST uid, so a forwarding
				# target of 169.254.169.254 is indistinguishable at nftables from
				# the guest dialling the metadata API and rule 1 drops it
				# (measured). Sending them to a root-run loopback forwarder moves
				# that hop to a uid rule 1 does not name.
				#
				# THE CAP is the assertion that matters, not the presence: rule 3's
				# accept set must be the funnel ports plus THIS ONE SOCKET, and the
				# widening that would pass every other check here is a second
				# accept line. Two accepts (udp + tcp) and two denies (v4 + v6) on
				# top of the funnel accept is five rule-3 lines, exactly.
				if ! grep -qF 'cogworx-floor-rule3-dns-forwarder' "$install"; then
					echo "FAIL: the floor installer renders no rule-3 DNS-forwarder exception; passt's re-emitted guest DNS query is a loopback connect under the passt uid, so every sandbox on the VM would resolve nothing" >&2
					fails=$((fails + 1))
				fi
				if [ "$(grep -cF 'cogworx-floor-rule3' "$install")" != 5 ]; then
					echo "FAIL: the floor installer renders $(grep -cF 'cogworx-floor-rule3' "$install") rule-3 lines, expected 5 (funnel accept, DNS-forwarder udp+tcp accepts, v4 and v6 loopback denies); an added accept widens the passt uid's loopback reach" >&2
					fails=$((fails + 1))
				fi
				if grep -F 'cogworx-floor-rule3-dns-forwarder' "$install" | grep -qE 'dport [^ ]*[-{]'; then
					echo "FAIL: the rule-3 DNS-forwarder exception carries a port range or set; it must name exactly one port, or it re-admits neighbouring loopback listeners" >&2
					fails=$((fails + 1))
				fi
				verify=${gceFloorVerify}
				for token in cogbox-passt cogbox-proxy 169.254.169.254 \
					'rule 1, metadata API' 'rule 2, passt leg' 'rule 2, proxy leg' \
					'rule 2 control-uid exception' 'Refusing the boot' \
					'expected blocked' 'expected connected or refused' \
					'rule 2 exempt-port return path' 'systemd-socket-activate' \
					'rule 3, loopback leg' 'rule 3 L7 funnel exception' \
					'rule 3 host DNS forwarder exception'; do
					if ! grep -qF "$token" "$verify"; then
						echo "FAIL: the floor verifier does not mention '$token'" >&2
						fails=$((fails + 1))
					fi
				done

				# PROBE POLARITY, and the one probe that is exempt from it. The
				# control-uid EXCEPTION probe is proven healthy by "connected OR
				# refused" and broken only by a DROP, because this unit runs before
				# the supervisor that starts passt, so nothing can be listening on
				# the guest SSH forward when the probe runs and a correct VM answers
				# RST. Demanding a completed connection there would fail every boot
				# of a correct image -- and the obvious remedy for that is to widen
				# rule 2, which is the pressure the probe exists to resist.
				#
				# The RETURN-PATH probe demands "open" and is allowed to, because it
				# binds its own root-owned listener on an exempt port first. That
				# distinction matters: an
				# empty port answers with a socket-less RST that breaks past the
				# deny, so the exception probe reads healthy under a deny that eats
				# every real reply. Deleting the return-path probe puts the image
				# back in the state where nothing on the VM can see that bug.
				if grep -qF 'expected reachable' "$verify"; then
					echo "FAIL: the floor verifier still demands a reachable control-uid connect; nothing can listen on the guest SSH forward before the supervisor starts passt" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'expected open' "$verify"; then
					echo "FAIL: the floor verifier no longer asserts a COMPLETED connection against its own listener on an exempt port; the same-host return path would be unverifiable before a sandbox starts" >&2
					fails=$((fails + 1))
				fi

				# The in-VM store GC. "NixGCReconciler is unsupported" is a
				# statement about the control plane; the boot disk still fills.
				for u in cogworx-nix-gc.service cogworx-nix-gc.timer; do
					if [ ! -e ${gceUnits}/$u ]; then
						echo "FAIL: $u is missing" >&2
						fails=$((fails + 1))
					fi
				done

				# The resolver VM's in-VM self-destruct belt.
				if [ ! -e ${gceUnits}/cogworx-resolver-deadline.service ]; then
					echo "FAIL: cogworx-resolver-deadline.service is missing" >&2
					fails=$((fails + 1))
				fi
				# ... and the belt's own FAIL-OPEN, which presence cannot see. The
				# arm script decides "not a resolver boot" from a failed metadata
				# read, and that verdict is `exit 0` under RemainAfterExit=true --
				# a LATCH: Restart=on-failure never fires and the deadline never
				# arms for the rest of the boot. So an unreachable endpoint must be
				# a RETRY, never a verdict, and the only way to tell the two apart
				# is to probe reachability first (the shape cogworx-attr-scrub
				# already uses) before reading the flag. This is a static shape
				# assertion because the unit has no executable test home: it takes
				# no COGWORX_MD_BASE override, so unlike the floor and supervisor
				# scripts it cannot be run against a file:// metadata tree.
				arm=${gceResolverDeadlineScript}
				if ! grep -qF 'instance/id' "$arm"; then
					echo "FAIL: the resolver-deadline arm script does not probe metadata reachability before reading the cogworx-resolver flag; an unreachable endpoint would read as 'not a resolver boot' and latch an UNARMED self-destruct on a VM that evaluates attacker-controlled flakes" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'will retry' "$arm"; then
					echo "FAIL: the resolver-deadline arm script has no retry path; every metadata failure would exit 0 and latch an unarmed deadline" >&2
					fails=$((fails + 1))
				fi
				# The retry path must come BEFORE the flag read, or it is not the
				# thing standing between an unreachable endpoint and the latch.
				if [ "$(grep -n 'instance/id' "$arm" | head -n1 | cut -d: -f1)" -ge "$(grep -n 'attributes/cogworx-resolver' "$arm" | head -n1 | cut -d: -f1)" ]; then
					echo "FAIL: the resolver-deadline arm script reads the cogworx-resolver flag before probing reachability; the unreachable case would still latch" >&2
					fails=$((fails + 1))
				fi

				# A non-interactive `ssh <vm> cogbox <verb>` sources no profile, so
				# without these three baked into the program itself every control
				# verb exits 66. NAME-presence only: it says nothing about whether the
				# wrapper can win against a value PAM already set, which is a separate
				# and equally fatal failure -- see gce-cogbox-wrapper-env.
				for v in XDG_CONFIG_HOME COGBOX_DATA XDG_RUNTIME_DIR; do
					if ! grep -qF "$v" ${gceCogboxWrapper}/bin/cogbox; then
						echo "FAIL: the cogbox wrapper does not set $v; control-channel verbs would exit 66" >&2
						fails=$((fails + 1))
					fi
				done

				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The filesystem every other path assumed and nothing created. The mkfs
			# guard is the load-bearing half: an unconditional mkfs on a resumed
			# instance destroys the L7 CA private key, the secret store and the VM
			# host key on every Start.
			# The hosted guest's storage layout, read off the realized fstab. Two
			# properties carry the whole design and the rest of the change hangs off
			# them:
			#
			#   1. The POOL is stage 2 (no x-initrd.mount) and carries
			#      x-systemd.growfs. That IS restart-to-grow -- resize the disk,
			#      restart the guest -- and it only works in stage 2, because
			#      systemd-growfs@.service does not exist in the initrd's unit set and
			#      a filesystem already mounted by stage 1 never runs its Wants= in
			#      stage 2 either. `nofail` is the other half: a pool that fails to
			#      mount must let the guest reach multi-user with sshd -- not as a
			#      supported second layout, but because that mount is the ONE fault
			#      on this path the host cannot see, so the guest has to come up far
			#      enough to report it (see the pool mount's own nofail note).
			#
			#   2. The /nix/store overlay upper IS stage 1, on its own volume. That is
			#      not a preference: microvm.nix marks a volume neededForBoot only
			#      when its mountPoint is microvm.writableStoreOverlay, and the
			#      overlay's pre-mount unit RequiresMountsFor= that path. Making it a
			#      subdirectory of the pool would have dragged the pool onto the
			#      initrd path and cost property 1 outright.
			cogbox-guest-volume-hosted = pkgs.runCommand "cogbox-guest-volume-hosted" { } ''
				fails=0
				fstab=${hostedFstab}

				pool=$(grep ' /var/lib/cogbox-guest ' "$fstab" || true)
				if [ -z "$pool" ]; then
					echo "FAIL: the hosted guest declares no /var/lib/cogbox-guest pool" >&2
					fails=$((fails + 1))
				fi
				case "$pool" in
					'/dev/disk/by-label/cogworx-guest '*) ;;
					*)
						echo "FAIL: the pool is not resolved by LABEL: $pool" >&2
						echo "  a /dev/vd<letter> device is assigned by volume list position, so a second volume silently renames the user's data pool" >&2
						fails=$((fails + 1))
						;;
				esac
				for opt in x-systemd.growfs nofail discard; do
					case "$pool" in
						*"$opt"*) ;;
						*) echo "FAIL: the pool mount has no $opt: $pool" >&2; fails=$((fails + 1)) ;;
					esac
				done
				# The non-vacuous half of the growfs assertion. x-systemd.growfs above is
				# satisfiable only outside the initrd, so asserting it without also
				# asserting the pool is NOT an initrd mount would pass on a
				# configuration where restart-to-grow silently never happens.
				case "$pool" in
					*x-initrd.mount*)
						echo "FAIL: the pool is an INITRD mount; x-systemd.growfs cannot run there (systemd-growfs@.service is absent from the initrd) and stage 2 will not grow an already-mounted filesystem, so restart-to-grow is dead" >&2
						fails=$((fails + 1))
						;;
				esac

				rw=$(grep ' /nix/.rw-store ' "$fstab" || true)
				case "$rw" in
					'/dev/disk/by-label/cogworx-store-rw '*ext4*) ;;
					*)
						echo "FAIL: the hosted /nix/.rw-store is not an ext4 volume resolved by label: $rw" >&2
						echo "  a tmpfs here is what OOM-kills the guest on a large in-guest nix build" >&2
						fails=$((fails + 1))
						;;
				esac
				# Must be in the initrd: /nix/store is an overlay whose upperdir lives
				# under this mount and is itself neededForBoot.
				case "$rw" in
					*x-initrd.mount*) ;;
					*)
						echo "FAIL: the hosted /nix/.rw-store is not an initrd mount; the /nix/store overlay upper lives under it and stage 1 needs it" >&2
						fails=$((fails + 1))
						;;
				esac
				case "$rw" in
					*discard*) ;;
					*) echo "FAIL: the hosted /nix/.rw-store has no discard; ext4 mounts nodiscard by default so freed store paths never shrink the provider disk" >&2; fails=$((fails + 1)) ;;
				esac
				# ...and NOT autoResize, which would be a lie rather than a nicety. NixOS
				# renders autoResize as nothing but the x-systemd.growfs mount option,
				# and systemd-growfs@.service is a STAGE-2 upstream unit with no stage-1
				# counterpart in this nixpkgs -- so on an initrd mount the option asserts
				# a growth path that cannot run. This volume grows because the host lays
				# its filesystem down fresh at the logical volume's current size on every
				# host boot (gce-image-guest-disk-behaviour case 3 measures exactly that).
				case "$rw" in
					*x-systemd.growfs*)
						echo "FAIL: the hosted /nix/.rw-store carries x-systemd.growfs; it is an INITRD mount, where systemd-growfs@.service does not exist, so that option can only mislead" >&2
						fails=$((fails + 1))
						;;
				esac

				# THE GUEST IS NOT TOLD ABOUT LVM, and this is what that claim reduces
				# to in the artifact systemd actually reads. Both volumes are logical
				# volumes the HOST carves out of one dedicated disk, and the guest
				# resolves them by filesystem LABEL -- so no fstab line may name a
				# volume group, a logical volume or a device-mapper node. A guest that
				# addressed /dev/cogworx-guest/pool or /dev/mapper/... would need lvm2
				# and a volume-group activation on its own boot path, which is the
				# complexity this layout exists to keep out of the guest.
				for f in "$fstab" ${workstationFstab}; do
					if grep -qE '^(/dev/mapper/|/dev/cogworx-guest/)' "$f"; then
						echo "FAIL: $f addresses a device-mapper/LVM path; the guest must resolve its volumes by label and know nothing about the host's volume group" >&2
						grep -E '^(/dev/mapper/|/dev/cogworx-guest/)' "$f" >&2
						fails=$((fails + 1))
					fi
				done

				# THE local security property, unchanged by either profile: the host's
				# harness config is exported read-only, so a compromised agent cannot
				# write back into it. Enforced host-side by QEMU, which is why it is
				# asserted against the share list and not the guest's mount options.
				${lib.concatMapStringsSep "\n\t" (s: ''
					${lib.optionalString (!s.readOnly) ''
						echo "FAIL: harness lower ${s.mountPoint} is no longer a read-only 9p share; that is the load-bearing local security property" >&2
						fails=$((fails + 1))
					''}
				'') hostedHarnessLowers}
				${lib.optionalString (hostedHarnessLowers == []) ''
					echo "FAIL: the hosted guest declares no /var/lib/harness-lower/* shares at all; the read-only assertion above would be vacuous" >&2
					fails=$((fails + 1))
				''}

				# The WORKSTATION default must be untouched apart from the two tmpfs
				# sizes: no pool, no volume, and the harness overlay still on its loop
				# image. This is what makes the change safe to ship to local users.
				wfstab=${workstationFstab}
				if grep -q ' /var/lib/cogbox-guest ' "$wfstab"; then
					echo "FAIL: the default (workstation) profile declares a guest pool; it must stay opt-in" >&2
					fails=$((fails + 1))
				fi
				if ! grep -q '^/var/lib/cogbox/harness-overlay.img /var/lib/harness-rw ext4 loop ' "$wfstab"; then
					echo "FAIL: the workstation profile no longer mounts the harness overlay loop image" >&2
					fails=$((fails + 1))
				fi
				# The fixed size=16G is the bug: it exceeds the guest's entire RAM, so a
				# large nix build OOMs the guest instead of failing with ENOSPC.
				wrw=$(grep ' /nix/.rw-store ' "$wfstab" || true)
				case "$wrw" in
					*size=16G*)
						echo "FAIL: the workstation /nix/.rw-store is still a fixed 16G tmpfs: $wrw" >&2
						fails=$((fails + 1))
						;;
				esac
				case "$wrw" in
					'tmpfs /nix/.rw-store tmpfs '*size=50%*) ;;
					*) echo "FAIL: the workstation /nix/.rw-store is not a RAM-fraction tmpfs: $wrw" >&2; fails=$((fails + 1)) ;;
				esac
				# Inert-fix guard: resize-store-overlay.service remounts /nix/.rw-store
				# from a launcher-written size file on every boot, so the declared size
				# above means nothing unless the launcher stops defaulting it to 16G.
				if grep -qF 'storeOverlaySize: "16G"' ${./cogbox-launch.sh}; then
					echo "FAIL: cogbox-launch.sh still seeds storeOverlaySize: \"16G\" into new instance configs; resize-store-overlay would remount the tmpfs straight back to 16G and the sizing fix would be inert" >&2
					fails=$((fails + 1))
				fi
				if grep -qF ".storeOverlaySize // \"16G\"" ${./cogbox-launch.sh}; then
					echo "FAIL: cogbox-launch.sh still falls back to a 16G store-overlay size for instances whose config omits the key" >&2
					fails=$((fails + 1))
				fi

				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The machine-state binds: ordering, and the anti-shadow invariant.
			#
			# Binding root's home DIRECTORIES is safe only because nothing that
			# matters lives under them: the harness overlays' lowerdirs are the
			# read-only 9p mounts under /var/lib/harness-lower and their uppers live
			# under /var/lib/harness-rw, so a bind at /root/.config lands first (systemd
			# orders a mount after its path-prefix parents) and the overlay mounts on
			# top of it. Binding /root ITSELF would break all of that at once -- it
			# carries four harness mounts, the runtime /root/work symlink, the
			# fw_cfg-written /root/.claude.json and a tmpfiles-managed
			# /root/.nix-channels -- so that is asserted as an explicit prohibition
			# rather than left to review.
			cogbox-guest-binds-ordered = pkgs.runCommand "cogbox-guest-binds-ordered" { } ''
				fails=0
				fstab=${hostedFstab}

				# Every pool-backed bind must Require= BOTH the pool mount and the
				# subdir creator. Without the pool requirement a bind over an unmounted
				# pool directory shows the user an EMPTY work tree; without the dirs
				# requirement the bind source may not exist yet.
				while read -r src mnt _type opts _rest; do
					case "$src" in
						/var/lib/cogbox-guest/*) ;;
						*) continue ;;
					esac
					for dep in 'x-systemd.requires=var-lib-cogbox\x2dguest.mount' \
						'x-systemd.requires=cogbox-guest-dirs.service'; do
						case "$opts" in
							*"$dep"*) ;;
							*)
								echo "FAIL: pool bind $mnt does not carry $dep: $opts" >&2
								fails=$((fails + 1))
								;;
						esac
					done
				done < "$fstab"

				# Count the pool binds so the loop above cannot pass by matching nothing.
				binds=$(grep -c '^/var/lib/cogbox-guest/' "$fstab" || true)
				if [ "$binds" -lt 7 ]; then
					echo "FAIL: only $binds pool-backed binds in the hosted fstab; expected at least the three home roots, /var/lib/docker, /var/log/journal, work/ and harness-rw/" >&2
					fails=$((fails + 1))
				fi

				# work/ is the one leg that touches irreplaceable data. The migration
				# unit exits nonzero on any verification failure, and this Requires= is
				# what converts that into "the bind does not happen and the 9p copy
				# stays authoritative" instead of "the user's work tree looks empty".
				work=$(grep ' /var/lib/cogbox/work ' "$fstab" || true)
				for dep in 'x-systemd.requires=cogbox-guest-work-migrate.service' \
					'x-systemd.requires=var-lib-cogbox.mount'; do
					case "$work" in
						*"$dep"*) ;;
						*) echo "FAIL: the work bind does not carry $dep: $work" >&2; fails=$((fails + 1)) ;;
					esac
				done
				# Bound ONTO the 9p path, not a repointed WORK: brainMaterializeScript
				# hardcodes WORK=/var/lib/cogbox/work and claude's trust key is that
				# literal string, and shadowing rather than moving is what retains the
				# old copy for a release.
				case "$work" in
					'/var/lib/cogbox-guest/work /var/lib/cogbox/work none bind,'*) ;;
					*) echo "FAIL: work/ is not bound from the pool onto /var/lib/cogbox/work: $work" >&2; fails=$((fails + 1)) ;;
				esac

				# The journal must be ordered before the flush, or the first boot's
				# ring buffer lands on the tmpfs root and the evidence is lost again.
				journal=$(grep ' /var/log/journal ' "$fstab" || true)
				case "$journal" in
					*x-systemd.before=systemd-journal-flush.service*) ;;
					*) echo "FAIL: the journal bind is not ordered before systemd-journal-flush.service: $journal" >&2; fails=$((fails + 1)) ;;
				esac

				# ANTI-SHADOW. /root must never itself be a mount point, and the four
				# harness mounts nested under the bound home roots must still be there --
				# otherwise the "binding the parents is harmless" argument is untested.
				if awk '{ print $2 }' "$fstab" | grep -qx '/root'; then
					echo "FAIL: the hosted guest mounts /root itself; that shadows the harness overlays, /root/work, .claude.json and .nix-channels at once" >&2
					fails=$((fails + 1))
				fi
				for m in ${lib.concatStringsSep " " opencodeGuestPaths} /root/.claude; do
					if ! awk '{ print $2 }' "$fstab" | grep -qx "$m"; then
						echo "FAIL: the hosted guest no longer mounts $m; the machine-state binds are only safe while the nested harness mounts still own these paths" >&2
						fails=$((fails + 1))
					fi
				done
				# The overlays' lowers and uppers must stay OUTSIDE the bound home roots.
				# A lower or upper under /root/.config would be shadowed by the bind, and
				# it would be shadowed silently, at runtime, in a user's sandbox.
				if grep -E '^overlay ' "$fstab" | grep -E '(lowerdir|upperdir|workdir)=/root/' >/dev/null; then
					echo "FAIL: a harness overlay has a lower/upper/work dir under /root; the machine-state bind over its parent would shadow it" >&2
					grep -E '^overlay ' "$fstab" | grep -E '(lowerdir|upperdir|workdir)=/root/' >&2
					fails=$((fails + 1))
				fi

				# The subdir creator must create EVERY bind source, and the migration
				# must be able to refuse. Both are read off the realized scripts.
				dirs=${hostedGuestDirsScript}
				for sub in machine/root/.cache machine/root/.local machine/root/.config \
					machine/var/lib/docker machine/log/journal work harness-rw; do
					if ! grep -qF "mkdir -p /var/lib/cogbox-guest/$sub" "$dirs"; then
						echo "FAIL: cogbox-guest-dirs does not create /var/lib/cogbox-guest/$sub; the bind over it would fail, or worse mount an empty directory over live data" >&2
						fails=$((fails + 1))
					fi
				done
				migrate=${hostedWorkMigrateScript}
				for token in '.work-migrated' 'work.incoming' 'exit 1'; do
					if ! grep -qF "$token" "$migrate"; then
						echo "FAIL: the work migration has no '$token'; it must be idempotent, stage into a side directory and FAIL rather than switch a partial copy" >&2
						fails=$((fails + 1))
					fi
				done
				# The marker must NOT be able to short-circuit the "pool copy empty?"
				# comparison: the marker is written on boot 1 of every hosted instance,
				# so a marker-first exit would let an accepted degraded boot's work be
				# silently shadowed on the next healthy one. Assert the ORDER in the
				# realized script -- the $dst emptiness test has to appear before the
				# first read of $marker.
				for m in "$migrate" ${hostedHarnessMigrateScript}; do
					dst_line=$(grep -n 'find "$dst" -mindepth 1 -print -quit' "$m" | head -1 | cut -d: -f1)
					marker_line=$(grep -n '\[ -e "\$marker" \]' "$m" | head -1 | cut -d: -f1)
					if [ -z "$dst_line" ]; then
						echo "FAIL: $m never tests whether the pool copy is already populated; that test is what stops a bind from hiding live data" >&2
						fails=$((fails + 1))
					elif [ -n "$marker_line" ] && [ "$marker_line" -lt "$dst_line" ]; then
						echo "FAIL: $m reads \$marker (line $marker_line) BEFORE testing whether the pool copy is empty (line $dst_line); the marker exists from boot 1, so that ordering skips the comparison forever" >&2
						fails=$((fails + 1))
					fi
				done

				# harness-rw is the OTHER repointed surface, and it carries the four
				# harness overlay uppers -- claude's settings/history/credentials, the
				# hermes home, opencode's config and data. Without a migration the first
				# hosted boot binds an empty pool directory over all of them and the old
				# loop image is orphaned on the state disk with nothing saying so.
				hrw=$(grep ' /var/lib/harness-rw ' "$fstab" || true)
				for dep in 'x-systemd.requires=cogbox-guest-harness-migrate.service' \
					'x-systemd.requires=var-lib-cogbox.mount'; do
					case "$hrw" in
						*"$dep"*) ;;
						*) echo "FAIL: the harness-rw bind does not carry $dep: $hrw" >&2; fails=$((fails + 1)) ;;
					esac
				done
				hmigrate=${hostedHarnessMigrateScript}
				for token in '.harness-rw-migrated' 'harness-rw.incoming' \
					'/var/lib/cogbox/harness-overlay.img' 'dumpe2fs -h' 'mount -o loop' 'exit 1'; do
					if ! grep -qF "$token" "$hmigrate"; then
						echo "FAIL: the harness-rw migration has no '$token'; it must read the LEGACY loop image, stage into a side directory and FAIL rather than orphan the uppers" >&2
						fails=$((fails + 1))
					fi
				done

				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# POOL-ABSENT DEGRADATION, proved with the real generator rather than
			# argued. This is the property S3/R4 and the README rest on -- "a pool that
			# fails to appear degrades the guest to the pre-pool layout" -- and it is
			# NOT implied by `nofail` on the pool mount alone. Concrete triggers: a
			# legacy instance whose third disk was never attached, a failed
			# create/attach leg, or a disk the host-side format never labelled, so
			# /dev/disk/by-label/... times out.
			#
			# Two mechanisms can each turn that into emergency.target, and neither is
			# visible by reading the fstab:
			#
			#   1. systemd-fstab-generator emits a non-`nofail` entry into
			#      local-fs.target.REQUIRES; local-fs.target ships
			#      OnFailure=emergency.target with
			#      OnFailureJobMode=replace-irreversibly, so one failed bind replaces
			#      the whole queued multi-user.target transaction -> no sshd.
			#   2. harness-setup-dirs Requires= the harness-rw mount. If that fails the
			#      four overlay UPPERDIRS are never created and the four overlay mounts
			#      fail too. That cascade runs through a SERVICE, so no amount of nofail
			#      on the binds reaches it.
			#   3. systemd MANUFACTURES a hard Requires= on the mount unit covering a
			#      mount's parent directory (src/core/mount.c:270-281), the one covering
			#      an absolute bind or loop SOURCE (:284-294), and the one covering every
			#      path prefix named in RequiresMountsFor= (src/core/unit.c:1522-1542:
			#      UNIT_MOUNT_REQUIRES becomes UNIT_REQUIRES for any covering unit that
			#      has a fragment path, which fstab-generated units always have). In
			#      hosted that reaches SIX mounts whose own fstab lines name no pool path
			#      at all: the four harness overlays, through the upper/work dirs nixpkgs
			#      renders as RequiresMountsFor=, and the two opencode ephemeral binds,
			#      through both their parent and their source. A first version of this
			#      check enumerated only lines whose SOURCE was on the pool, so it passed
			#      while all six sat in local-fs.target.requires -- VACUOUS with respect
			#      to the one property it exists to prove. Hence the three rules are
			#      re-implemented below instead of the affected mounts being listed.
			#
			# Running the generator is what makes this non-vacuous: dropping `nofail` from
			# mkPoolBind moves all seven binds from .wants to .requires, and dropping
			# poolNofail moves the six dependents; this check goes red on either.
			cogbox-guest-pool-degradable = pkgs.runCommand "cogbox-guest-pool-degradable" {
				nativeBuildInputs = [ pkgs.systemd ];
			} ''
				fails=0
				mkdir -p gen
				# SYSTEMD_FSTAB is the generator's own test hook; SYSTEMD_IN_INITRD=0
				# keeps it out of the initrd code path, which mounts under /sysroot.
				SYSTEMD_FSTAB=${hostedFstab} SYSTEMD_IN_INITRD=0 \
					${pkgs.systemd}/lib/systemd/system-generators/systemd-fstab-generator gen gen gen

				# Every mount an absent pool can fail -- the pool, every bind ON it, and
				# every mount that DEPENDS on one of those -- must be WANTED by
				# local-fs.target, never REQUIRED by it. All three sets are DERIVED from the
				# realized fstab by re-implementing systemd's own three rules, so a mount
				# added later that happens to depend on the pool is covered without an edit,
				# while one that does NOT depend on it keeps its fail-closed requirement (the
				# /nix/store overlay, the read-only 9p shares).
				pool_points=$(awk '$1 == "/dev/disk/by-label/cogworx-guest" || $1 ~ "^/var/lib/cogbox-guest/" { print $2 }' ${hostedFstab})
				dependents=$(awk -v pools="$pool_points" '
					BEGIN { np = split(pools, P, " ") }
					# At or under any pool-backed mount point.
					function under(p) {
						for (i = 1; i <= np; i++)
							if (p == P[i] || index(p, P[i] "/") == 1) return 1
						return 0
					}
					function opt(o, pfx) {
						if (index(o, pfx) != 1) return 0
						return under(substr(o, length(pfx) + 1))
					}
					/^[ \t]*(#|$)/ { next }
					{
						dep = 0
						# mount.c:270-281, the parent-prefix rule. Testing the mount point
						# itself is the same test one level down and costs nothing.
						if (under($2)) dep = 1
						# mount.c:284-294, an absolute bind or loop source.
						if (!dep && $1 ~ /^\// && under($1)) dep = 1
						# unit.c:1522-1542, via the options overlayfs.nix and
						# tasks/filesystems.nix render from overlay.* and depends.
						if (!dep) {
							no = split($4, O, ",")
							for (j = 1; j <= no && !dep; j++) {
								if (index(O[j], "lowerdir=") == 1) {
									nl = split(substr(O[j], 10), L, ":")
									for (k = 1; k <= nl && !dep; k++) if (under(L[k])) dep = 1
								}
								else if (opt(O[j], "upperdir=")) dep = 1
								else if (opt(O[j], "workdir=")) dep = 1
								else if (opt(O[j], "x-systemd.requires-mounts-for=")) dep = 1
							}
						}
						if (dep) print $2
					}
				' ${hostedFstab})
				# The pool is not "under" itself by those rules, so union it in; sort -u
				# because one bind can qualify under several rules at once.
				pool_units=$(printf '%s\n%s\n' "$pool_points" "$dependents" | sort -u \
					| while read -r mnt; do
						[ -n "$mnt" ] || continue
						systemd-escape -p --suffix=mount "$mnt"
					done)
				n=0
				for unit in $pool_units; do
					n=$((n + 1))
					if [ -e "gen/local-fs.target.requires/$unit" ]; then
						echo "FAIL: $unit is in local-fs.target.requires; a pool that fails to mount then fails local-fs.target, whose OnFailure=emergency.target replaces the multi-user job -- the guest comes up with NO sshd instead of degrading to the pre-pool layout" >&2
						fails=$((fails + 1))
					fi
					# The other half, so the loop cannot pass by asserting nothing: the
					# unit must still exist and still be pulled in when the pool IS there.
					if [ ! -e "gen/local-fs.target.wants/$unit" ]; then
						echo "FAIL: $unit is not wanted by local-fs.target at all; it would never be mounted" >&2
						fails=$((fails + 1))
					fi
				done
				# ...and the derivation must have found something to assert on. Two floors,
				# because the second set is the one a naive rewrite loses: 8 covers the pool
				# plus its seven binds, and the INDIRECT count covers the four harness
				# overlays and the two opencode binds that only rule 3 finds.
				if [ "$n" -lt 14 ]; then
					echo "FAIL: only $n pool-dependent mounts derived from the fstab; expected the pool, its seven binds, the four harness overlays and the two opencode binds" >&2
					fails=$((fails + 1))
				fi
				indirect=$(comm -13 <(printf '%s\n' "$pool_points" | sort -u) \
					<(printf '%s\n' "$dependents" | sort -u) | grep -c . || true)
				if [ "$indirect" -lt 6 ]; then
					echo "FAIL: only $indirect mounts were found to depend on the pool INDIRECTLY; the harness overlays and the opencode binds are the ones an absent pool fails through systemd's implicit rules, and finding none of them is how this check was vacuous before" >&2
					fails=$((fails + 1))
				fi

				# nofail must not have cost R3 its refusal: the generated work mount
				# still has to REQUIRE the migration, so a migration that declines still
				# means the bind does not happen and the legacy copy stays authoritative.
				for pair in 'var-lib-cogbox-work.mount:cogbox-guest-work-migrate.service' \
					'var-lib-harness\x2drw.mount:cogbox-guest-harness-migrate.service'
				do
					unit=''${pair%%:*}
					dep=''${pair#*:}
					if ! grep -q "^Requires=.*$dep" "gen/$unit"; then
						echo "FAIL: gen/$unit does not Requires= $dep; a refused migration would let the bind hide the legacy copy" >&2
						fails=$((fails + 1))
					fi
				done

				# THE COMPENSATING HALF, and without it everything above CERTIFIES a
				# regression. The loop that opens this check asserts that no
				# pool-dependent mount is in local-fs.target.requires -- but the very
				# thing that achieves that, `nofail`, is also what strips
				# Before=local-fs.target from these units (systemd.mount(5)). So having
				# passed, this file has PROVED that nothing outside the explicitly
				# ordered set waits for these binds. Any unit that writes THROUGH a
				# pool-bound path must therefore say so itself, and the two below are
				# the ones that do it silently when they do not:
				#
				#   brain-materialize writes $WORK=/var/lib/cogbox/work directly, and
				#   unordered it materialises the brain into the legacy 9p directory
				#   that stash() is about to rename aside -- a work tree with no
				#   .cogbox/brain, no skills/agents/commands, no AGENTS.md, no error.
				#
				#   docker.service creates its data root itself and nixpkgs' module
				#   declares no ordering on /var/lib/docker, so unordered dockerd
				#   initialises on the tmpfs root and writes to shadowed inodes for the
				#   whole session -- the RAM exhaustion this profile removes.
				#
				# Asserted on the GENERATED unit, not on the fstab line, so it covers
				# the option actually reaching systemd.
				for pair in 'var-lib-cogbox-work.mount:cogbox-brain-materialize.service' \
					'var-lib-docker.mount:docker.service' \
					'var-log-journal.mount:systemd-journal-flush.service'
				do
					unit=''${pair%%:*}
					dep=''${pair#*:}
					if ! grep -q "^Before=.*$dep" "gen/$unit"; then
						echo "FAIL: gen/$unit is not ordered Before= $dep. nofail removed this unit's Before=local-fs.target, so nothing waits for the bind unless it says so here: $dep would write to the directory the bind is about to cover and lose it under the mount, silently" >&2
						fails=$((fails + 1))
					fi
				done

				# Mechanism 2. In hosted, harness-setup-dirs must only WANT the
				# pool-backed harness-rw mount; in workstation it must keep REQUIRING the
				# loop mount, because there the mount really is a precondition and a
				# missing overlay image is a bug to surface, not to work around.
				if grep -qE '^Requires=.*var-lib-harness' ${hostedHarnessDirsUnit}; then
					echo "FAIL: the hosted harness-setup-dirs Requires= the harness-rw mount; an absent pool then fails it, the overlay upperdirs are never created, and the four harness overlay mounts take local-fs.target -- and sshd -- down with them" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qE '^After=.*var-lib-harness' ${hostedHarnessDirsUnit}; then
					echo "FAIL: the hosted harness-setup-dirs is not ordered After= the harness-rw mount; it would create the upperdirs on the underlying directory and a late mount would shadow them" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qE '^Requires=.*var-lib-harness' ${workstationHarnessDirsUnit}; then
					echo "FAIL: the workstation harness-setup-dirs no longer Requires= the harness-rw loop mount; that profile has no pool to degrade to and the requirement is what surfaces a corrupt overlay image" >&2
					fails=$((fails + 1))
				fi

				# Mechanism 2 AS A CLASS, which is what the three assertions above are
				# only one member of. harness-setup-dirs was fixed on its own once and the
				# same defect was still sitting in cogbox-brain-materialize (Requires= the
				# hermes overlay mount) and cogbox-claude-stub (Requires= the claude
				# overlay mount) -- both of them mounts that are perfectly ordinary
				# preconditions under `workstation` and pool-backed only under `hosted`,
				# which is exactly why naming units one at a time does not close it.
				#
				# So every REALIZED service unit of the hosted guest is scanned against
				# the pool-dependent mount set derived at the top of this check. Two
				# spellings of the same hard dependency, because they reach systemd
				# differently and only one of them is visible in the flake:
				#   Requires=<unit>          what a service writes itself.
				#   RequiresMountsFor=<path> which unit.c:1522-1542 turns into UNIT_REQUIRES
				#                            on whichever mount unit COVERS that path.
				#
				# Two exemptions, both deliberate and both narrow:
				#   the pool-prep units       cogbox-guest-dirs and the two migrations
				#                             exist only to prepare the pool. Requiring it
				#                             is their whole point: with no pool there is
				#                             nothing for them to do and running them
				#                             anyway is what a bind over an empty
				#                             directory looks like.
				#   rw-*.service              nixpkgs' own overlay pre-mount units
				#                             (overlayfs.nix), which RequiresMountsFor=
				#                             their upper/work dirs on /var/lib/harness-rw.
				#                             They are not ours to write, and their failure
				#                             fails only the matching overlay mount -- which
				#                             is `nofail` here, so it degrades that one
				#                             harness to ephemeral config rather than
				#                             reaching local-fs.target.
				pool_prep_units='cogbox-guest-dirs.service cogbox-guest-work-migrate.service cogbox-guest-harness-migrate.service'
				scanned=0
				for f in ${hostedServiceUnits}/*.service; do
					svc=$(basename "$f")
					scanned=$((scanned + 1))
					case " $pool_prep_units " in *" $svc "*) continue ;; esac
					case "$svc" in rw-*) continue ;; esac
					for req in $(sed -n 's/^Requires=//p' "$f"); do
						for unit in $pool_units; do
							if [ "$req" = "$unit" ]; then
								echo "FAIL: $svc has a hard Requires=$unit. That mount is pool-backed in this profile, so an absent pool does not merely skip the mount -- it stops this service from running at all, and whatever it was preparing fails with it. Demote it with softMounts (Wants=) and keep the After=" >&2
								fails=$((fails + 1))
							fi
						done
					done
					for p in $(sed -n 's/^RequiresMountsFor=//p' "$f"); do
						for base in $pool_points; do
							case "$p" in
								"$base"|"$base"/*)
									echo "FAIL: $svc has RequiresMountsFor=$p, which systemd turns into a hard Requires= on the mount covering $base -- a pool-backed mount in this profile. Same failure as a literal Requires=, arriving through a path nothing in the flake spells" >&2
									fails=$((fails + 1))
									;;
							esac
						done
					done
				done
				# Floors, because a glob that matched nothing would pass every loop above.
				if [ "$scanned" -lt 40 ]; then
					echo "FAIL: only $scanned service units were scanned; the hosted guest renders far more than that, so the class scan above asserted nothing" >&2
					fails=$((fails + 1))
				fi
				for svc in cogbox-brain-materialize.service cogbox-claude-stub.service harness-setup-dirs.service; do
					if [ ! -e "${hostedServiceUnits}/$svc" ]; then
						echo "FAIL: $svc is not in the scanned set at all; the three units this class rule was written for must be covered by it" >&2
						fails=$((fails + 1))
					fi
				done

				# ...and the OTHER direction, which no scan for a forbidden token can
				# reach: a demotion must not become a DELETION. Dropping the Requires= AND
				# the Wants= AND the After= passes every assertion above while letting
				# these units run before the overlay they write through is mounted -- the
				# shadowed-write failure this whole file exists to prevent, arriving from
				# the opposite side. Pinned by name for the two known pairs (hosted keeps
				# Wants= + After=, workstation keeps its Requires=)...
				for pair in 'cogbox-brain-materialize.service:root-.hermes.mount' \
					'cogbox-claude-stub.service:root-.claude.mount'
				do
					svc=''${pair%%:*}
					mnt=''${pair#*:}
					if ! grep -qE "^Wants=.*$mnt" "${hostedServiceUnits}/$svc"; then
						echo "FAIL: the hosted $svc does not Wants= $mnt; demoting a hard dependency must keep pulling the mount in, not delete it" >&2
						fails=$((fails + 1))
					fi
					if ! grep -qE "^After=.*$mnt" "${hostedServiceUnits}/$svc"; then
						echo "FAIL: the hosted $svc is not ordered After= $mnt; it writes THROUGH that overlay, so unordered it writes to the covered rootfs and the user's harness state vanishes under the mount" >&2
						fails=$((fails + 1))
					fi
				done
				for pair in "${workstationUnit "cogbox-brain-materialize.service"}:root-.hermes.mount" \
					"${workstationUnit "cogbox-claude-stub.service"}:root-.claude.mount"
				do
					unit=''${pair%%:*}
					mnt=''${pair#*:}
					if ! grep -qE "^Requires=.*$mnt" "$unit"; then
						echo "FAIL: the workstation $(basename "$unit") no longer Requires= $mnt; that profile has no pool to degrade to, and there the overlay rests on the loop image, whose absence is a bug to surface rather than to work around" >&2
						fails=$((fails + 1))
					fi
				done
				# ...and derived for everything else, so a unit demoted later inherits the
				# same rule without being added here.
				for f in ${hostedServiceUnits}/*.service; do
					svc=$(basename "$f")
					for w in $(sed -n 's/^Wants=//p' "$f"); do
						for unit in $pool_units; do
							if [ "$w" = "$unit" ]; then
								ordered=0
								for a in $(sed -n 's/^After=//p' "$f"); do
									if [ "$a" = "$unit" ]; then ordered=1; fi
								done
								if [ "$ordered" = 0 ]; then
									echo "FAIL: $svc Wants= $unit but is not ordered After= it; a demoted dependency keeps the degradation only while the ordering survives, or the service runs before the mount and writes under it" >&2
									fails=$((fails + 1))
								fi
							fi
						done
					done
				done

				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The sibling of cogbox-guest-pool-degradable, and the distinction between
			# them is the whole reason this file exists: that one proves a pool that
			# FAILS degrades instead of wedging; this one proves a pool that HANGS is
			# eventually let go of. `nofail` bounds failure and nothing else -- a job
			# whose process sits in uninterruptible D-state on a stalled device is not
			# failed, it is `activating` forever, which is why the shape it
			# produces is an unbounded "Booting" with an EMPTY `systemctl --failed`.
			#
			# The scope that matters, and the one a previous audit got wrong: the jobs
			# on this path are mostly not written here. systemd-fstab-generator
			# SYNTHESISES them from the realized fstab -- a pass-2 pool line becomes a
			# hard Requires= on systemd-fsck@<device>.service, x-systemd.growfs (which
			# is all autoResize renders) becomes systemd-growfs@<mount>.service plus a
			# local-fs.target drop-in ordering the target after it -- and BOTH of those
			# upstream units ship TimeoutSec=infinity. An audit of "every unit this
			# change adds" cannot see either of them. So the unit names here are read
			# out of the GENERATOR'S OUTPUT and matched against the rendered
			# configuration, which also makes this the only thing that can catch a
			# systemd-escape mistake or a label rename orphaning a drop-in.
			cogbox-guest-pool-boot-bounded = pkgs.runCommand "cogbox-guest-pool-boot-bounded" {
				# util-linux and e2fsprogs are NOT decoration, and leaving them out made
				# the first draft of this check silently vacuous about the very unit it
				# was written for. systemd-fstab-generator emits the fsck dependency for
				# a pass-2 line only when BOTH `fsck` (util-linux's driver) and
				# `fsck.<fstype>` are findable on PATH -- generator.c's
				# generator_write_fsck_deps calls fsck_exists_for_fstype, which probes
				# for both and treats "nothing to run" as nothing to order against. With
				# a bare builder PATH the generator produced no fsck unit at all and the
				# loop below asserted nothing about it; only the floor caught that, which
				# is why the floor is there. Both of these are on the GUEST's PATH too
				# (systemd.settings.Manager.ManagerEnvironment carries util-linux-minimal
				# and e2fsprogs), so the fsck really is generated where it boots -- that
				# is what makes the bound necessary rather than theoretical.
				nativeBuildInputs = [ pkgs.systemd pkgs.util-linux pkgs.e2fsprogs ];
			} (''
				fails=0
				bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
			'' + lib.concatStrings (lib.mapAttrsToList (pname: cfg: ''

				echo "== profile ${pname} =="
				# The pool, derived: exactly one growable filesystem, and its mount point
				# is what every escaped unit name below is built from.
				autoresized="${lib.concatStringsSep " " (poolAutoResized cfg)}"
				n_ar=$(printf '%s\n' $autoresized | grep -c . || true)
				if [ "$n_ar" != 1 ]; then
					bad "${pname}: expected exactly one autoResize filesystem (the pool); found $n_ar: $autoresized. Each one gets its own unbounded systemd-growfs@ instance, so a new one needs a new bound"
				fi
				pool_point=$(printf '%s\n' $autoresized | head -1)

				rm -rf gen-${pname}
				mkdir -p gen-${pname}
				# SYSTEMD_FSTAB is the generator's own test hook; SYSTEMD_IN_INITRD=0
				# keeps it out of the initrd code path, which mounts under /sysroot.
				SYSTEMD_FSTAB=${cfg.environment.etc.fstab.source} SYSTEMD_IN_INITRD=0 \
					${pkgs.systemd}/lib/systemd/system-generators/systemd-fstab-generator \
					gen-${pname} gen-${pname} gen-${pname}
				mount_unit=$(systemd-escape -p --suffix=mount "$pool_point")
				if [ ! -e "gen-${pname}/$mount_unit" ]; then
					bad "${pname}: the generator produced no $mount_unit; the pool is not on this profile's boot path at all and everything below asserts nothing"
				fi

				# Every .service job systemd interposes between the pool's device and
				# local-fs.target, by the three edges that put one there:
				#   the pool .mount's own hard/soft/ordering dependencies   -> the fsck
				#   the .wants directory the generator writes beside it     -> the growfs
				#   an After= in a local-fs.target drop-in                  -> the growfs
				#       again, by the edge that is the REASON it blocks: without this
				#       one a hung growfs would only delay the mount it grows.
				jobs=$( {
					sed -nE 's/^(Requires|Wants|After|BindsTo)=//p' "gen-${pname}/$mount_unit"
					ls "gen-${pname}/$mount_unit.wants" 2>/dev/null || true
					cat gen-${pname}/local-fs.target.d/*.conf 2>/dev/null | sed -nE 's/^After=//p' || true
				} | tr ' ' '\n' | grep '\.service$' | sort -u )

				n_jobs=0
				for svc in $jobs; do
					n_jobs=$((n_jobs + 1))
					dropin="${poolBoundDropins "pool-bound-dropins-${pname}" cfg}/$svc"
					if [ ! -e "$dropin" ]; then
						# No bound of ours. Acceptable only if the unit systemd would
						# actually load is already bounded -- read the TEMPLATE out of the
						# guest's OWN systemd, not this builder's, because the version
						# that boots is the one whose default applies.
						tmpl=$(printf '%s' "$svc" | sed -E 's/@.*\.service$/@.service/')
						up="${cfg.systemd.package}/example/systemd/system/$tmpl"
						if [ -e "$up" ] && grep -qE '^Timeout(Start)?Sec=[0-9]' "$up"; then
							echo "  $svc: upstream bound, no drop-in needed"
							continue
						fi
						bad "${pname}: $svc is a job on the pool's boot path with NO finite start timeout -- $tmpl ships $(grep -E '^Timeout(Start)?Sec=' "$up" 2>/dev/null || echo 'no TimeoutSec at all, which for Type=oneshot means the timeout is DISABLED') and nothing here overrides it. A device that answers its probe and then stalls leaves this in D-state, the pool mount job never completes, and the guest sits in Booting with no sshd and an EMPTY systemctl --failed"
						continue
					fi
					# The bound exists. Now the three ways it can be present and still
					# not work.
					if ! grep -qE '^Timeout(Start)?Sec=[0-9]' "$dropin"; then
						bad "${pname}: $dropin sets no finite start timeout (TimeoutSec=infinity is not a bound)"
					fi
					# The stop half, which is the one that is easy to leave out and fatal
					# to leave out: upstream says TimeoutSec=infinity, which sets START
					# AND STOP. Bounding only the start fires SIGTERM at a process wedged
					# in D-state on the device that stalled and then waits forever for it
					# to die -- the unit parks in `deactivating`, the job still never
					# completes, and the guest is wedged one state further along.
					if ! grep -qE '^TimeoutStopSec=[0-9]' "$dropin"; then
						bad "${pname}: $dropin bounds the start but not the stop; upstream's TimeoutSec=infinity still applies to the stop, so the unit hangs in deactivating instead of reaching failed"
					fi
					# ...and it has to be a DROP-IN. overrideStrategy defaults to
					# asDropinIfExists, which for a template INSTANCE finds nothing to
					# extend and installs this as a whole unit shadowing the template. A
					# systemd-fsck@<instance>.service with no ExecStart succeeds
					# instantly and the pool is never checked again -- silently, and in
					# the direction of data loss rather than of a wedge.
					if grep -q '^ExecStart=' "$dropin"; then
						bad "${pname}: $dropin carries an ExecStart=, so it is a full unit and not a drop-in; it SHADOWS the upstream template instead of extending it, and the job it replaces stops happening"
					fi
					echo "  $svc: bounded by a drop-in"
				done
				if [ "$n_jobs" -lt 2 ]; then
					bad "${pname}: only $n_jobs services derived from the pool mount unit; expected at least the generated fsck and growfs, so the loop above asserted nothing"
				fi

				# systemd-tmpfiles-setup.service, asserted BY NAME because it is the one
				# member of this class that cannot be derived: its edge to the pool is a
				# runtime path walk, not a declared dependency, so no unit file anywhere
				# states it. systemd's own tmpfiles.d chowns and chmods /var/log/journal,
				# which this change turns from a directory on the RAM-backed root into a
				# pool bind; the unit is Type=oneshot with no TimeoutSec (so unbounded by
				# systemd.service(5)'s oneshot rule), After=local-fs.target and
				# Before=sysinit.target. A pool that stalls AFTER mounting therefore
				# wedges sysinit, hence basic.target, hence sshd -- finding 1's shape
				# reached through a unit nobody in this repo writes.
				tmpfiles="${poolBoundDropins "pool-bound-dropins-${pname}" cfg}/systemd-tmpfiles-setup.service"
				if ! grep -qE '^TimeoutStartSec=[0-9]' "$tmpfiles" 2>/dev/null; then
					bad "${pname}: systemd-tmpfiles-setup.service has no finite start bound. It walks /var/log/journal, which is pool-backed in this profile, and it gates sysinit.target"
				fi

				# ...and nixpkgs' overlay pre-mount units, the other class whose edge to
				# the pool no unit file states: each runs `mkdir -p <upper> <work>` under
				# /var/lib/harness-rw and is Before= its overlay mount, and
				# cogbox-brain-materialize is After= the hermes overlay and
				# Before=sshd.service. The COUNT is derived from the realized fileSystems
				# so that a nixpkgs rename of the rw- prefix shows up here as a mismatch
				# rather than as a bound that silently stopped applying, and the ExecStart
				# assertion is the other half of that: the bound is merged into nixpkgs'
				# own definition, so a rename would leave a timeout-only unit behind.
				n_rw=0
				for f in ${serviceUnitsOf "service-units-${pname}" cfg}/rw-*.service; do
					[ -e "$f" ] || continue
					n_rw=$((n_rw + 1))
					rw=$(basename "$f")
					if ! grep -qE '^TimeoutStartSec=[0-9]' "$f"; then
						bad "${pname}: $rw has no finite start bound; its mkdir on a stalled pool sits in D-state, its overlay mount job never completes, and cogbox-brain-materialize -- Before=sshd.service -- never starts"
					fi
					if ! grep -q '^ExecStart=' "$f"; then
						bad "${pname}: $rw has a bound but no ExecStart, so it is a stray unit this flake invented: nixpkgs' overlayfs naming moved and the bound is no longer reaching the real pre-mount unit"
					fi
				done
				if [ "$n_rw" != ${toString (builtins.length (stage2Overlays cfg))} ]; then
					bad "${pname}: found $n_rw rw-*.service units for ${toString (builtins.length (stage2Overlays cfg))} stage-2 overlay mounts; the pre-mount units this profile actually renders are not the ones being bounded"
				fi
			'') poolBootProfiles) + ''

				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'');

			# The two pool migrations, RUN rather than read. Everything else about this
			# change can be asserted off a realized fstab or unit file; these two
			# scripts are the only code in it that moves data the user cannot get back,
			# and their whole contract is behavioural -- what they do when the pool copy
			# is empty but the marker says otherwise, and whether a failed copy leaves
			# the original authoritative. The eval checks above can only see that the
			# tokens are present.
			#
			# It needs a VM because it needs real root: the scripts address /var/lib/...
			# absolutely (correctly -- an overridable path in a data-moving unit is a
			# hazard, not a feature), a mkfs'd loop image is the harness migration's
			# actual input, and a small tmpfs is the only honest way to produce the
			# ENOSPC that the refusal path exists for. `loop` is added to the VM's root
			# modules for that image; the stock vmTools list has no loop support.
			cogbox-guest-migrate-behaviour = (pkgs.vmTools.override {
				# vmTools' own default list plus `loop`. Restated because the default is
				# an argument default and nixpkgs does not expose it, so a bump that
				# renames a module here is a build error rather than a silent loss.
				rootModules = [
					"virtio_pci" "virtio_mmio" "virtio_blk" "virtio_balloon" "virtio_rng"
					"ext4" "virtiofs" "crc32c" "loop"
				];
			}).runInLinuxVM (pkgs.runCommand "cogbox-guest-migrate-behaviour" {
				nativeBuildInputs = [ pkgs.util-linux pkgs.e2fsprogs pkgs.coreutils ];
			} ''
				fails=0
				work=${hostedWorkMigrateScript}
				harness=${hostedHarnessMigrateScript}
				bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

				# A fresh pool + a fresh 9p-equivalent state dir per case. The size
				# argument is what case 4 uses to force ENOSPC on the pool.
				reset() {
					umount /var/lib/cogbox-guest 2>/dev/null || true
					rm -rf /var/lib/cogbox /var/lib/cogbox-guest
					mkdir -p /var/lib/cogbox-guest /var/lib/cogbox
					if [ -n "''${1:-}" ]; then
						mount -t tmpfs -o "size=$1" tmpfs /var/lib/cogbox-guest
					fi
					mkdir -p /var/lib/cogbox-guest/machine /var/lib/cogbox-guest/work \
						/var/lib/cogbox-guest/harness-rw
				}

				# THE WORKSTATION BOOT, which the occupancy cases below are about and
				# which they used to skip entirely. harness-overlay-img.service's
				# `[ ! -f "$img" ]` arm lays a fresh 128 MiB ext4 at the legacy path, and
				# then harness-setup-dirs.service unconditionally mkdirs every harness's
				# overlay upper+work tree into it -- on EVERY workstation boot, before
				# anything else can look. mkfs'ing an image and running the migration
				# immediately, which is what these cases did, reproduces a state the
				# system is never in for more than the few milliseconds between those two
				# units.
				#
				# The REALIZED harness-setup-dirs ExecStart, not a copy of its mkdirs: a
				# harness added or renamed moves the scaffolding here too, rather than
				# leaving the fixture asserting a shape that has stopped being produced.
				# It writes to the absolute /var/lib/harness-rw, so that is where the
				# image has to be mounted.
				scaffold_image() {
					mkdir -p /var/lib/harness-rw
					mount -o loop "$1" /var/lib/harness-rw
					${hostedHarnessDirsScript} \
						|| bad "harness-setup-dirs failed against $1; the workstation boot was not reproduced"
					# The fixture has to PROVE it reached the state it names. Without
					# these two, a scaffolding step that silently stopped writing would
					# leave every case below asserting what it asserted before -- that a
					# blank image is quiet -- which is the unreachable state the whole
					# reseed is here to remove.
					[ -n "$(find /var/lib/harness-rw -mindepth 1 -not -name lost+found -print -quit)" ] \
						|| bad "harness-setup-dirs scaffolded NOTHING into $1; the cases below are back to testing an empty image"
					# ...and that what it wrote is scaffolding and not content. The
					# occupancy test keys on REGULAR FILES, so a fixture whose scaffolding
					# included one would stop distinguishing the two.
					[ -z "$(find /var/lib/harness-rw -type f -print -quit)" ] \
						|| bad "harness-setup-dirs wrote a REGULAR FILE into $1; this fixture no longer separates scaffolding from user data"
					umount /var/lib/harness-rw
				}

				echo "== case 1: fresh instance, nothing to move =="
				reset
				mkdir -p /var/lib/cogbox/work
				"$work" || bad "the migration failed on a fresh instance with an empty work tree"
				[ -e /var/lib/cogbox-guest/machine/.work-migrated ] \
					|| bad "case 1 did not record the marker; every later boot would re-walk both trees"

				echo "== case 2: marker present, pool copy EMPTY, legacy copy NOT (the degraded-boot case) =="
				# This is the one the marker must not be able to short-circuit: the
				# marker is written on boot 1 of every hosted instance, so a boot that
				# came up WITHOUT the pool leaves the user's session in the legacy tree
				# with the marker already set. Binding an empty directory over it is the
				# data-loss outcome; re-migrating is the correct one.
				mkdir -p /var/lib/cogbox/work/repo
				echo hello > /var/lib/cogbox/work/repo/a.txt
				ln -s a.txt /var/lib/cogbox/work/repo/link
				"$work" 2> case2.err || bad "the migration failed on the degraded-boot case"
				grep -q 'WARNING' case2.err \
					|| bad "case 2 re-migrated silently; a marker that disagrees with the trees must be loud"
				[ "$(cat /var/lib/cogbox-guest/work/repo/a.txt)" = hello ] \
					|| bad "case 2 did not copy the legacy work tree onto the pool"
				[ -L /var/lib/cogbox-guest/work/repo/link ] \
					|| bad "case 2 did not preserve a symlink; cp -a must copy the tree as-is"
				# Retention, and its SHAPE. The legacy tree is moved aside rather than
				# left in place: shadowing alone let a boot on the pre-pool layout
				# present the stale copy as current, the user work in it, and the next
				# hosted boot hide that session again. Renamed, the same boot finds an
				# EMPTY work tree -- wrong in a way nobody mistakes for right -- and the
				# data is still on the share.
				[ -e /var/lib/cogbox/work.pre-pool/repo/a.txt ] \
					|| bad "case 2 did not RETAIN the legacy copy at work.pre-pool; that rename is the whole retention policy"
				[ -d /var/lib/cogbox/work ] \
					|| bad "case 2 left no /var/lib/cogbox/work directory behind; the bind would have no mount point"
				[ -z "$(find /var/lib/cogbox/work -mindepth 1 -print -quit)" ] \
					|| bad "case 2 left content at the legacy path; a pre-pool boot would present it as current"

				echo "== case 3: idempotent -- a populated pool copy is claimed, not re-copied =="
				echo changed > /var/lib/cogbox-guest/work/repo/a.txt
				"$work" 2> case3.err || bad "the migration failed on an already-populated pool"
				[ "$(cat /var/lib/cogbox-guest/work/repo/a.txt)" = changed ] \
					|| bad "case 3 overwrote the pool copy from the stale legacy tree"
				# Case 2 retired the legacy tree, so there is no fork to report. This is
				# the steady state of every hosted boot after the first, and it has to
				# stay quiet AND cheap -- the tree-measuring warning in case 3b is only
				# affordable because the stash stops it recurring.
				grep -q WARNING case3.err \
					&& bad "case 3 warned on the steady-state path, which every hosted boot after the first takes"

				echo "== case 3b: NEGATIVE -- a fork must be LOUD and must be broken, not just claimed =="
				# The review finding this exists for. After the migration, a boot on the
				# pre-pool layout -- a rolled-back image, or an accepted degraded boot --
				# writes into the legacy path. The next hosted boot binds the pool copy
				# over it. The pool copy is right to win (it is what the last hosted boot
				# wrote), but the hidden session must not vanish silently, and the same
				# fork must not be able to form a second time.
				mkdir -p /var/lib/cogbox/work/repo
				echo written-while-degraded > /var/lib/cogbox/work/repo/degraded.txt
				"$work" 2> case3b.err || bad "the migration failed on the fork case"
				grep -q WARNING case3b.err \
					|| bad "case 3b shadowed a NON-EMPTY legacy tree silently; that is the silent-fork finding itself"
				grep -q /var/lib/cogbox/work case3b.err \
					|| bad "case 3b did not name the legacy path in the warning; an operator cannot find the hidden copy"
				[ "$(cat /var/lib/cogbox-guest/work/repo/a.txt)" = changed ] \
					|| bad "case 3b let the stale legacy tree overwrite the pool copy"
				[ -e /var/lib/cogbox/work.pre-pool.1/repo/degraded.txt ] \
					|| bad "case 3b did not retain the degraded-boot session; it is kept, only moved out of the way"
				[ -z "$(find /var/lib/cogbox/work -mindepth 1 -print -quit)" ] \
					|| bad "case 3b left the fork at the legacy path, so the next pre-pool boot forks again"
				[ -e /var/lib/cogbox/work.pre-pool/repo/a.txt ] \
					|| bad "case 3b overwrote the EARLIER .pre-pool copy; every retained copy is somebody data"

				echo "== case 3c: NEGATIVE -- brain-materialize's SCAFFOLDING is not a fork =="
				# The work leg's twin of case 7, and the reason its occupancy test could
				# not stay "any entry at all". stash() leaves the legacy path an EMPTY
				# directory, and the old comment reasoned from that: anything in it
				# afterwards must be somebody's data. It is not.
				# cogbox-brain-materialize is wantedBy multi-user.target in every VM
				# profile and writes THROUGH $WORK=/var/lib/cogbox/work, so ANY boot on
				# which the work bind does not happen -- a hosted boot whose `nofail`
				# pool mount fails or times out, or an image rollback to a rev whose
				# guest is the workstation profile -- repopulates that directory with
				# .cogbox/brain, the .claude/ and .opencode/ link trees and AGENTS.md
				# before the user or anything else touches it. Every one is a directory
				# or a symlink; the tree's own files/bytes reads 0 0. (Both triggers are
				# live; a third, a launch-time chooser falling back to the workstation
				# runner, is gone with the chooser -- the GCE image bakes one profile.)
				#
				# Seeded by RUNNING the realized unit, for the same reason case 7 is: the
				# state has to be produced by the thing that produces it in the field.
				mkdir -p /root
				${hostedBrainMaterializeScript} \
					|| bad "case 3c could not reproduce the degraded boot: brain-materialize failed"
				[ -L /var/lib/cogbox/work/.cogbox/brain ] \
					|| bad "case 3c reproduced nothing: brain-materialize left no .cogbox/brain link at the legacy path"
				# ...and the premise, asserted rather than assumed: if this leg ever
				# writes a regular file, case 3c stops being the scaffolding case and
				# silently becomes a second copy of case 3b.
				[ -z "$(find /var/lib/cogbox/work -type f -print -quit)" ] \
					|| bad "case 3c seeded a REGULAR FILE at the legacy path, so it is testing a genuine fork and not scaffolding"
				"$work" 2> case3c.err || bad "the migration failed on the scaffolded-legacy case"
				grep -q WARNING case3c.err \
					&& bad "case 3c fired the fork WARNING for a tree holding nothing but brain-materialize's own directories and symlinks; that alarm has to stay un-mistakable, so it must key on content and not on a readdir"
				[ -e /var/lib/cogbox/work.pre-pool.2 ] \
					&& bad "case 3c stashed the scaffolding; every hosted<->workstation flap would leak another copy onto the STATE disk, which also carries the L7 CA key, the secret store and the sshd host key, and nothing ever reclaims one"
				[ -L /var/lib/cogbox/work/.cogbox/brain ] \
					|| bad "case 3c moved the scaffolded tree aside anyway"
				[ "$(cat /var/lib/cogbox-guest/work/repo/a.txt)" = changed ] \
					|| bad "case 3c touched the pool copy"

				echo "== case 4: a copy that cannot finish must REFUSE, not half-switch =="
				reset 128k
				mkdir -p /var/lib/cogbox/work
				dd if=/dev/zero of=/var/lib/cogbox/work/big.bin bs=1024 count=512 status=none
				if "$work" 2>/dev/null; then
					bad "the migration SUCCEEDED with a pool too small to hold the tree; a partial copy would then be bound over the real one"
				fi
				[ -e /var/lib/cogbox-guest/machine/.work-migrated ] \
					&& bad "case 4 wrote the marker after failing; the next boot would treat the partial state as migrated"
				[ -e /var/lib/cogbox-guest/work.incoming ] \
					&& bad "case 4 left the partial copy behind, wasting the pool it just ran out of"
				[ -z "$(find /var/lib/cogbox-guest/work -mindepth 1 -print -quit)" ] \
					|| bad "case 4 put something in the pool work tree; the bind would then hide the real one"
				[ -e /var/lib/cogbox/work/big.bin ] \
					|| bad "case 4 damaged the source tree"

				echo "== case 5: harness-rw comes off the LEGACY LOOP IMAGE =="
				# Without this leg, switching an existing instance to hosted presents
				# claude's settings/history/credentials, the hermes home and opencode's
				# config+data as gone, because the bind lands on an empty pool directory
				# and the read-only 9p lower has only the baked defaults.
				reset
				truncate -s 8M /var/lib/cogbox/harness-overlay.img
				mkfs.ext4 -q -F /var/lib/cogbox/harness-overlay.img
				# A real legacy image ALWAYS carries the scaffolding: nothing ever
				# reaches one that harness-setup-dirs has not already written into. So
				# the positive case is seeded that way too -- which is also what proves
				# a tree measure() does not count (directories) does not break the
				# copy-and-verify.
				scaffold_image /var/lib/cogbox/harness-overlay.img
				mkdir -p seed
				mount -o loop /var/lib/cogbox/harness-overlay.img seed
				mkdir -p seed/claude-code/config/upper seed/hermes-agent/home/upper
				echo '{"theme":"dark"}' > seed/claude-code/config/upper/settings.json
				echo present > seed/hermes-agent/home/upper/state
				umount seed
				"$harness" || bad "the harness migration failed on a valid legacy overlay image"
				[ "$(cat /var/lib/cogbox-guest/harness-rw/claude-code/config/upper/settings.json)" = '{"theme":"dark"}' ] \
					|| bad "case 5 did not carry the claude overlay upper onto the pool"
				[ -e /var/lib/cogbox-guest/harness-rw/hermes-agent/home/upper/state ] \
					|| bad "case 5 did not carry the hermes overlay upper onto the pool"
				# Same retention shape as work/, and it matters more here: left in
				# place, a rolled-back pre-pool boot would loop-mount this image and
				# present a stale claude home -- settings, history, a hand-placed
				# credential -- as current. Renamed, that boot finds no image and
				# harness-overlay-img recreates a blank one, so it still comes up.
				[ -e /var/lib/cogbox/harness-overlay.img.pre-pool ] \
					|| bad "case 5 did not retain the legacy overlay image at .pre-pool"
				[ -e /var/lib/cogbox/harness-overlay.img ] \
					&& bad "case 5 left the legacy overlay image where a pre-pool boot would mount it as current"
				if mountpoint -q /run/cogbox-harness-migrate; then
					bad "case 5 left the legacy image loop-mounted; the EXIT trap must unmount it"
				fi

				echo "== case 6: an image with no valid superblock is skipped, never mounted =="
				# The interrupted-first-mkfs image. Reading it as a filesystem would only
				# produce a confusing failure, and there is nothing in it to migrate.
				reset
				head -c 4096 /dev/urandom > /var/lib/cogbox/harness-overlay.img
				"$harness" 2>/dev/null || bad "the harness migration failed instead of skipping an unformatted image"
				[ -z "$(find /var/lib/cogbox-guest/harness-rw -mindepth 1 -print -quit)" ] \
					|| bad "case 6 put something in the pool from an image with no filesystem"

				echo "== case 7: a RECREATED legacy image is NOT user data (size lies, and so does a readdir) =="
				# The hosted<->workstation flap. An instance that already migrated takes
				# one boot on the workstation runner -- now reachable only by an IMAGE
				# ROLLBACK, since the GCE image bakes one profile and there is no
				# launch-time chooser to fall back, but rollback is a mode flip no design
				# gets to remove -- and harness-overlay-img.service's
				# `[ ! -f ]` arm lays a fresh ext4 back at the legacy path, which
				# harness-setup-dirs then scaffolds. Judging that by st_size fired the
				# fork WARNING on a non-event an operator then chases, and stashed the
				# image, leaking it onto the STATE disk on every flap. Judging it by "any
				# top-level entry that is not lost+found" did exactly the same thing, for
				# the same reason, one round later -- because the image is NEVER empty by
				# the time anything looks at it. This is the case that must stay QUIET,
				# and it only says so if it is seeded through the units that make the
				# state.
				reset
				truncate -s 8M /var/lib/cogbox/harness-overlay.img
				mkfs.ext4 -q -F /var/lib/cogbox/harness-overlay.img
				scaffold_image /var/lib/cogbox/harness-overlay.img
				mkdir -p /var/lib/cogbox-guest/harness-rw/claude-code/config/upper
				echo pooled > /var/lib/cogbox-guest/harness-rw/claude-code/config/upper/settings.json
				"$harness" 2> case7.err \
					|| bad "the harness migration failed with a populated pool and a blank legacy image"
				grep -q WARNING case7.err \
					&& bad "case 7 fired the fork WARNING for a RECREATED image holding nothing but harness-setup-dirs' own overlay directories; that alarm has to stay un-mistakable, so it must key on regular files -- neither apparent size nor a top-level readdir can tell this image from a used one"
				[ -e /var/lib/cogbox/harness-overlay.img.pre-pool ] \
					&& bad "case 7 stashed a recreated image; every flap would leak another one onto the STATE disk, which also carries the L7 CA key, the secret store and the sshd host key, and .pre-pool would stop meaning somebody data"
				[ -e /var/lib/cogbox/harness-overlay.img ] \
					|| bad "case 7 moved the recreated image aside anyway"
				[ "$(cat /var/lib/cogbox-guest/harness-rw/claude-code/config/upper/settings.json)" = pooled ] \
					|| bad "case 7 touched the pool copy"

				echo "== case 8: a POPULATED legacy image still forks LOUDLY and is retired =="
				# The other half, and the half a naive "never stash an image" fix loses
				# silently: a pre-pool boot that actually WROTE to the legacy overlay --
				# a claude login, a settings change -- is a real fork and must still be
				# named and moved aside. Same image as case 7, now with content in it.
				mkdir -p seed8
				mount -o loop /var/lib/cogbox/harness-overlay.img seed8
				mkdir -p seed8/claude-code/config/upper
				echo '{"theme":"light"}' > seed8/claude-code/config/upper/settings.json
				umount seed8
				"$harness" 2> case8.err || bad "the harness migration failed on the fork case"
				grep -q WARNING case8.err \
					|| bad "case 8 shadowed a POPULATED legacy image silently; that is the silent-fork finding, arriving through the occupancy test instead of through the branch"
				grep -q /var/lib/cogbox/harness-overlay.img case8.err \
					|| bad "case 8 did not name the legacy image in the warning; an operator cannot find the hidden copy"
				[ -e /var/lib/cogbox/harness-overlay.img.pre-pool ] \
					|| bad "case 8 did not retire the populated legacy image"
				[ -e /var/lib/cogbox/harness-overlay.img ] \
					&& bad "case 8 left the populated image where a pre-pool boot would mount it as current"
				[ "$(cat /var/lib/cogbox-guest/harness-rw/claude-code/config/upper/settings.json)" = pooled ] \
					|| bad "case 8 let the legacy image overwrite the pool copy"
				if mountpoint -q /run/cogbox-harness-occupied; then
					bad "case 8 left the occupancy probe loop-mounted; it runs on every hosted boot until the image is reused, so a leak here stacks"
				fi

				[ "$fails" -eq 0 ] || exit 1
				mkdir -p $out
				touch $out/ok
			'');
			gce-image-state-disk-ordering = pkgs.runCommand "gce-image-state-disk-ordering" { } ''
				fails=0
				fstab=${gceToplevel}/etc/fstab
				line=$(grep ' /var/lib/cogbox-state ' "$fstab" || true)
				if [ -z "$line" ]; then
					echo "FAIL: no /var/lib/cogbox-state entry in the realized fstab" >&2
					fails=$((fails + 1))
				fi
				case "$line" in
					'/dev/disk/by-id/google-cogworx-state '*) ;;
					*) echo "FAIL: the state disk is not resolved through its fixed by-id deviceName: $line" >&2; fails=$((fails + 1)) ;;
				esac
				# sshd-keygen is what actually writes the host key, so ordering only
				# sshd would still lose the race that regenerates it on the boot disk.
				for dep in sshd-keygen.service sshd.service cogworx-supervisor.service cogworx-attr-scrub.service; do
					case "$line" in
						*"x-systemd.before=$dep"*) ;;
						*) echo "FAIL: the state mount is not ordered before $dep: $line" >&2; fails=$((fails + 1)) ;;
					esac
				done
				mkfs=${gceStateDiskScript}
				if ! grep -qF 'blkid' "$mkfs"; then
					echo "FAIL: the mkfs leg has no blkid guard; a resume would reformat the state disk" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'mkfs.ext4' "$mkfs"; then
					echo "FAIL: the state-disk unit never formats anything" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The HOST half of cogbox-guest-pool-boot-bounded, and it exists because
			# three rounds of "audit every unit this change adds" kept missing the same
			# class -- units nobody in either repository WRITES. The guest check was
			# scoped to the guest; the GCE host runs the same shape and had it worse.
			#
			# The state mount's fstab line carries x-systemd.before=sshd.service AND
			# x-systemd.before=cogworx-supervisor.service, so every job systemd
			# interposes on that mount's start path holds BOTH the host's sshd and the
			# VM launcher. Two of them were unbounded: cogworx-state-disk.service is
			# Type=oneshot, for which systemd DISABLES the start timeout by default,
			# and systemd-fstab-generator synthesises a
			# systemd-fsck@<escaped device>.service from the pass-2 line whose upstream
			# template says TimeoutSec=infinity. A state PD that answers its 30s device
			# probe and then stalls on reads parks blkid or e2fsck in D-state, neither
			# start job ever completes, the VM sits in Booting forever with an EMPTY
			# `systemctl --failed` (the units are `activating`, not failed), and with
			# the supervisor gone there is no `ssh <vm> cogbox <verb>` control channel
			# left to recover through. `nofail` does not touch any of that: it unhooks
			# the mount from local-fs.target and leaves the explicit x-systemd.before=
			# edges exactly where they are. nofail bounds FAILURE; only a timeout
			# bounds a HANG.
			#
			# So the unit names are read out of the GENERATOR'S OUTPUT, exactly as on
			# the guest side, rather than out of anything this repository declares --
			# which is also what makes an escaping mistake or a stateDevice override
			# orphaning its drop-in a build failure instead of a wedged host.
			gce-image-host-boot-bounded = pkgs.runCommand "gce-image-host-boot-bounded" {
				# Not decoration: systemd-fstab-generator emits the fsck dependency for
				# a pass-2 line only when BOTH `fsck` and `fsck.<fstype>` are findable
				# on PATH (generator.c's generator_write_fsck_deps ->
				# fsck_exists_for_fstype), so with a bare builder PATH it emits no fsck
				# unit at all and this check would assert nothing about the very unit it
				# was written for. Both are on the HOST's PATH too, which is what makes
				# the bound necessary rather than theoretical.
				nativeBuildInputs = [ pkgs.systemd pkgs.util-linux pkgs.e2fsprogs ];
			} ''
				fails=0
				bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

				rm -rf gen
				mkdir -p gen
				# SYSTEMD_FSTAB is the generator's own test hook; SYSTEMD_IN_INITRD=0
				# keeps it out of the initrd code path, which mounts under /sysroot.
				SYSTEMD_FSTAB=${gceFstab} SYSTEMD_IN_INITRD=0 \
					${pkgs.systemd}/lib/systemd/system-generators/systemd-fstab-generator \
					gen gen gen

				n_mounts=0
				n_jobs=0
				for m in gen/*.mount; do
					[ -e "$m" ] || continue
					unit=$(basename "$m")
					# The ROOT filesystem is EXEMPT, by name and with the reason stated
					# rather than by scoping the loop until it happens to pass. Its
					# x-systemd.growfs renders an unbounded systemd-growfs-root.service
					# that local-fs.target is ordered after, so the class is genuinely
					# present there too -- but a bound buys nothing: every ExecStart on
					# this host reads the boot disk, so a root PD that stalls has no
					# recoverable state to time out INTO. That is a different problem
					# from a data disk whose failure the host is written to survive, and
					# it is deliberately not fixed here. Reported as a residual instead.
					if [ "$unit" = "-.mount" ]; then
						echo "  $unit: root filesystem, exempt (see comment)"
						continue
					fi
					n_mounts=$((n_mounts + 1))
					echo "== $unit =="
					# Every .service job systemd interposes between this mount's device
					# and the mount itself: its own hard/soft/ordering dependencies, plus
					# the .wants directory the generator writes beside it (where a
					# per-mount growfs would land).
					jobs=$( {
						sed -nE 's/^(Requires|Wants|After|BindsTo)=//p' "$m"
						ls "$m.wants" 2>/dev/null || true
					} | tr ' ' '\n' | grep '\.service$' | sort -u )

					for svc in $jobs; do
						n_jobs=$((n_jobs + 1))
						dropin="${gceBoundDropins}/$svc"
						rendered="${gceHostServiceUnits}/$svc"
						if [ -e "$dropin" ]; then
							# A bound on a unit this configuration does not render in full
							# -- i.e. on a generated or upstream one. Three ways it can be
							# present and still not work.
							if ! grep -qE '^Timeout(Start)?Sec=[0-9]' "$dropin"; then
								bad "$dropin sets no finite start timeout (TimeoutSec=infinity is not a bound)"
							fi
							# The stop half, easy to leave out and fatal to leave out:
							# upstream's TimeoutSec=infinity sets START AND STOP. Bounding
							# only the start fires SIGTERM at a process wedged in D-state on
							# the device that stalled and then waits forever for it to die --
							# the unit parks in `deactivating`, the job still never
							# completes, and the host is wedged one state further along.
							if ! grep -qE '^TimeoutStopSec=[0-9]' "$dropin"; then
								bad "$dropin bounds the start but not the stop; upstream's TimeoutSec=infinity still applies to the stop, so the unit hangs in deactivating instead of reaching failed"
							fi
							# ...and it has to be a DROP-IN. overrideStrategy defaults to
							# asDropinIfExists, which for a template INSTANCE finds nothing
							# to extend and installs this as a whole unit SHADOWING the
							# template. A systemd-fsck@<instance>.service with no ExecStart
							# succeeds instantly and the state disk is never checked again --
							# silently, and in the direction of data loss rather than of a
							# wedge.
							if grep -q '^ExecStart=' "$dropin"; then
								bad "$dropin carries an ExecStart=, so it is a full unit and not a drop-in; it SHADOWS the upstream template instead of extending it, and the fsck it replaces stops happening"
							fi
							echo "  $svc: bounded by a drop-in"
						elif [ -e "$rendered" ]; then
							# An AUTHORED unit: the bound lives in the unit body.
							#
							# ...but first, the way this arm gets reached BY MISTAKE, which
							# is not hypothetical -- it was measured while proving this
							# check can fail. A bound intended as a drop-in whose
							# overrideStrategy is left at the default (asDropinIfExists)
							# finds no systemd-fsck@<instance>.service to extend and is
							# installed as a WHOLE unit instead, carrying nothing but a
							# [Service] section of timeouts. It shadows the upstream
							# template, has no ExecStart, succeeds instantly -- and every
							# timeout assertion in this arm passes it. The state disk would
							# then silently never be fsck'd again, a failure in the
							# direction of data loss rather than of a wedge. So an
							# ExecStart is REQUIRED here: a unit on a mount's start path
							# that runs nothing is not an authored job, it is a shadow.
							if ! grep -q '^ExecStart=' "$rendered"; then
								bad "$svc is on $unit's start path and this configuration renders it as a FULL unit with no ExecStart. That is a drop-in that lost overrideStrategy = \"asDropin\": it shadows the upstream template instead of extending it, succeeds instantly, and the job it replaced -- an fsck, here -- stops happening silently"
							fi
							# Only the start half is asserted for an authored unit, and that
							# asymmetry is correct rather than lax: a NixOS-rendered service
							# inherits the manager's finite DefaultTimeoutStopSec (nothing on
							# this host overrides it), so SIGKILL escalation still gets it to
							# `failed`. It is only the units whose own text says
							# TimeoutSec=infinity that lose the stop half too.
							if ! grep -qE '^TimeoutStartSec=[0-9]' "$rendered"; then
								bad "$svc is a job on $unit's start path and the unit this configuration renders sets no finite TimeoutStartSec. For Type=oneshot systemd DISABLES the start timeout by default, so a probe that parks in D-state on a stalled device holds this mount's job forever -- and $unit is ordered before sshd and the VM launcher, so the host comes up with neither and an EMPTY systemctl --failed"
							fi
							echo "  $svc: bounded in the unit it renders"
						else
							# Neither: acceptable only if the unit systemd would actually
							# load is already bounded upstream. Read the TEMPLATE out of the
							# HOST's own systemd, not this builder's, because the version
							# that boots is the one whose default applies.
							tmpl=$(printf '%s' "$svc" | sed -E 's/@.*\.service$/@.service/')
							up="${gceCfg.systemd.package}/example/systemd/system/$tmpl"
							if [ -e "$up" ] && grep -qE '^Timeout(Start)?Sec=[0-9]' "$up"; then
								echo "  $svc: upstream bound, no drop-in needed"
								continue
							fi
							bad "$svc is a job on $unit's start path with NO finite start timeout -- $tmpl ships $(grep -E '^Timeout(Start)?Sec=' "$up" 2>/dev/null || echo 'no TimeoutSec at all, which for Type=oneshot means the timeout is DISABLED') and nothing here overrides it. A device that answers its probe and then stalls leaves this in D-state, $unit's job never completes, and the host sits in Booting with no sshd, no VM launcher and an EMPTY systemctl --failed"
						fi
					done
				done

				# Floors, because every assertion above is inside two loops and an empty
				# loop asserts nothing. The host has exactly one non-root fstab mount
				# today (the state disk) and it carries exactly two jobs -- the authored
				# format oneshot and the generated fsck -- so anything less means the
				# generator produced nothing to look at and this check is vacuous.
				if [ "$n_mounts" -lt 1 ]; then
					bad "the generator produced no non-root .mount units from the host fstab; nothing above asserted anything"
				fi
				if [ "$n_jobs" -lt 2 ]; then
					bad "only $n_jobs service jobs derived across $n_mounts non-root host mounts; expected at least the state disk's format oneshot and its generated fsck, so the loop above asserted nothing"
				fi

				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The guest disk's first-boot carve. Sibling of the state-disk check
			# above, and the assertions diverge in exactly the two places the
			# modules do: this disk is NEVER MOUNTED BY THE HOST, and its guard
			# chain is deliberately stricter, because it holds the user's only copy
			# of their work tree rather than a re-mintable host key.
			gce-image-guest-disk-format = pkgs.runCommand "gce-image-guest-disk-format" { } ''
				fails=0

				# 1. The host must not mount the guest's pool -- that is the trust
				#    boundary the whole hosted design rests on. Assert it three ways:
				#    no entry for the raw device, none for either logical volume, and
				#    none for the guest's mount point (a fileSystems block added under
				#    any of those names would show up in one of them). The host DOES
				#    open these block devices and write filesystem metadata; what it
				#    must never do is mount a guest filesystem and read the user's
				#    files, and an fstab entry is exactly that.
				fstab=${gceToplevel}/etc/fstab
				if grep -q 'google-cogworx-guest' "$fstab"; then
					echo "FAIL: the HOST fstab has an entry for the guest disk; this host must carve it and never mount it" >&2
					grep 'google-cogworx-guest' "$fstab" >&2
					fails=$((fails + 1))
				fi
				if grep -q '/dev/cogworx-guest/' "$fstab"; then
					echo "FAIL: the HOST fstab mounts a logical volume off the guest disk; those two volumes belong to the GUEST" >&2
					grep '/dev/cogworx-guest/' "$fstab" >&2
					fails=$((fails + 1))
				fi
				if grep -q ' /var/lib/cogbox-guest ' "$fstab"; then
					echo "FAIL: the HOST fstab mounts /var/lib/cogbox-guest; that path belongs to the GUEST" >&2
					fails=$((fails + 1))
				fi

				mkfs=${gceGuestDiskScript}

				# 2. The guards, in the order the safety argument needs them. A
				#    "simplification" that drops any one of these is unrecoverable user
				#    data loss on a resumed instance, so each is named individually
				#    rather than being covered by one grep. These are TOKEN assertions
				#    and they cannot see control flow -- gce-image-guest-disk-behaviour
				#    below is what actually runs the script.
				if ! grep -qF '[ ! -b "$dev" ]' "$mkfs"; then
					echo "FAIL: the carve leg does not assert a real BLOCK DEVICE; a missing or renamed device node would be treated as a disk" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'blkid -p -o value -s TYPE' "$mkfs"; then
					echo "FAIL: the carve leg has no blkid filesystem guard; every Start would reformat the user's work tree" >&2
					fails=$((fails + 1))
				fi
				# The fail-SAFE polarity, not merely the presence of blkid. Only
				# blkid exit 2 (nothing found) may reach a write: exit 0 means a
				# signature was identified and exit 8 is its ambivalent
				# two-signatures result. state-disk.nix tests the exit status alone
				# and so formats on ANY nonzero, which is the wrong direction for
				# this disk -- this assertion is what stops that shape being copied
				# back in.
				if ! grep -qF '[ "$rc" -ne 2 ]' "$mkfs"; then
					echo "FAIL: the carve leg does not treat 'blkid could not tell' as already-initialised; only exit 2 may be read as provably blank" >&2
					fails=$((fails + 1))
				fi
				# ...and no signature probe can supply the POSITIVE half, which is the
				# other half of the same finding. blkid returns exit 2 with empty stdout
				# both for a blank device and for one it failed to READ, and wipefs
				# returns exit 0 with no signatures for the same unreadable device (both
				# measured against a dm `error` target). Only a read that had to succeed
				# proves the device answered at all, so assert that read is there too.
				if ! grep -qF 'dd if="$d"' "$mkfs"; then
					echo "FAIL: the carve leg never READS the device; blkid exit 2 and wipefs exit 0 both also mean \"could not read this disk\", so a device that errors on read would be written to" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'wipefs --no-act' "$mkfs"; then
					echo "FAIL: the carve leg has no second, positively-proving probe; blkid exit 2 alone also means \"could not read this device\", so a disk that errors on read would be written to" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF '[ "$wrc" -ne 0 ]' "$mkfs"; then
					echo "FAIL: the carve leg does not require the second probe to SUCCEED; running it and ignoring its exit status proves nothing" >&2
					fails=$((fails + 1))
				fi
				# The three-probe test must be applied TWICE -- to the raw disk before
				# the volume group, and to the POOL VOLUME before its mkfs. The second
				# application is what makes an interrupted first mkfs self-heal without
				# ever putting a populated pool at risk, and it is the one a refactor
				# that "already checked the disk" would drop.
				for target in '"$dev"' '"$pooldev"'; do
					if ! grep -qF "probe_blank $target" "$mkfs"; then
						echo "FAIL: the carve leg does not run the three-probe blankness test against $target" >&2
						fails=$((fails + 1))
					fi
				done
				# The LVM case table. "already carries LVM metadata" must be a
				# RECOGNISED state that creates nothing, not an unhandled one that
				# falls through to a create.
				if ! grep -qF 'LVM2_member' "$mkfs"; then
					echo "FAIL: the carve leg does not recognise an existing LVM physical volume; a resumed instance would not be identified as already-initialised" >&2
					fails=$((fails + 1))
				fi
				# Every lvm call scoped to this one disk, so a same-named volume group
				# on another device cannot be activated, renamed or resized from here.
				if ! grep -qF 'lvm "$sub" --devices "$dev"' "$mkfs"; then
					echo "FAIL: the carve leg's lvm calls are not scoped with --devices to the guest disk; a name-scoped command could reach a volume group on another disk" >&2
					fails=$((fails + 1))
				fi
				for verb in pvcreate vgcreate lvcreate; do
					if ! grep -qF "lvmc $verb" "$mkfs"; then
						echo "FAIL: the carve leg never calls $verb; the guest disk would carry no volume group and QEMU would have no volume to open" >&2
						fails=$((fails + 1))
					fi
				done
				# Restart-to-grow, host half. pvresize teaches the physical volume
				# about a disk the operator grew; the two lvextends are what let EITHER
				# volume take the new extents -- the whole reason this is LVM and not
				# two fixed partitions.
				if ! grep -qF 'lvmc pvresize "$dev"' "$mkfs"; then
					echo "FAIL: the carve leg never calls pvresize; growing the provider disk would never reach the volume group and restart-to-grow would be dead" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'lvmc lvextend -L "$storesize" "$vg/$storelv"' "$mkfs"; then
					echo "FAIL: the carve leg never extends the store overlay volume to its configured size" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'lvmc lvextend -l +100%FREE "$vg/$poollv"' "$mkfs"; then
					echo "FAIL: the carve leg never extends the data pool volume into the free extents; the pool is the half that takes the remainder" >&2
					fails=$((fails + 1))
				fi
				# The SIZING POLICY is an ORDER, not just two commands: the store takes
				# its configured size and the pool takes what is left, so every store
				# sizing call has to come before the pool's 100%FREE. Reversed, the pool
				# would swallow the group and the store could never grow.
				store_line=$(grep -nF 'lvmc lvextend -L "$storesize"' "$mkfs" | tail -1 | cut -d: -f1)
				pool_line=$(grep -nF 'lvcreate --yes -l 100%FREE' "$mkfs" | head -1 | cut -d: -f1)
				if [ -n "$store_line" ] && [ -n "$pool_line" ] && [ "$store_line" -gt "$pool_line" ]; then
					echo "FAIL: the carve leg sizes the data pool (line $pool_line) BEFORE the store overlay (line $store_line); 100%FREE would leave the store nothing to grow into" >&2
					fails=$((fails + 1))
				fi
				# The two mkfs calls, and the asymmetry between them IS the design.
				# The pool is formatted only behind the guard above; the store volume
				# is formatted unconditionally on every host boot, which is what keeps
				# the writable /nix/store overlay as ephemeral as the tmpfs it replaced
				# AND what grows it (x-systemd.growfs cannot run for a neededForBoot
				# mount, so nothing in the guest can).
				if ! grep -qF 'mkfs.ext4 -q -L cogworx-guest "$pooldev"' "$mkfs"; then
					echo "FAIL: the carve leg does not create an ext4 labelled cogworx-guest on the pool volume; the guest resolves it BY LABEL and would never find it" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'mkfs.ext4 -q -F -L cogworx-store-rw "$storedev"' "$mkfs"; then
					echo "FAIL: the carve leg does not (re)create an ext4 labelled cogworx-store-rw on the store volume; that mkfs is how the overlay stays ephemeral and how it grows" >&2
					fails=$((fails + 1))
				fi
				# ...and that unconditional mkfs is bounded to ONCE PER HOST BOOT by a
				# /run marker. RemainAfterExit below suppresses a re-run only while the
				# unit is `active`, and the pool probe is allowed to leave it `failed`
				# with both volumes carved and a guest already launched on them (Wants=,
				# not Requires=), so the obvious operator retry of a failed unit would
				# otherwise remake the filesystem under a live guest. The marker has to
				# live on a tmpfs the HOST clears at boot, and it has to be set on the
				# script's FIRST lines -- above the device check, above every probe and
				# above the vgchange.
				#
				# That last part is the one an operator-plausible "tidy-up" undoes, and it
				# is asserted by LINE NUMBER for exactly that reason. Setting the latch
				# next to the mkfs it guards reads better and is WRONG: lvm2's own udev
				# rule activates the volume group independently of this unit (see the
				# blind-spot note on the behaviour check), so both volume device nodes --
				# the entire test supervise.sh leg (e2) applies before launching a guest
				# -- can exist before this script runs a line. Any exit before the latch
				# then leaves the marker absent with a guest live on the store volume.
				# Asserted as tokens and by position here, and exercised for real by cases
				# 11, 12, 13 and 14 of the behaviour check.
				if ! grep -qF 'storeflag=/run/' "$mkfs"; then
					echo "FAIL: the carve leg's store-format latch is not under /run; anywhere persistent would survive a host boot and stop the overlay from ever being recreated, and anywhere the unit owns (RuntimeDirectory=) is removed when the unit fails -- which is exactly the state the latch exists for" >&2
					fails=$((fails + 1))
				fi
				# `|| true` on both, because the ABSENCE of either line is a case this
				# has to REPORT and not die on: the buildCommand runs under
				# `set -e -o pipefail`, so a grep that matches nothing aborts the whole
				# check with nothing but a builder exit code. MEASURED -- removing the
				# latch-set line failed this derivation without ever printing the
				# message below, which is a check that catches the regression and then
				# refuses to say what it was.
				flag_set=$(grep -nF ': > "$storeflag"' "$mkfs" | head -1 | cut -d: -f1 || true)
				store_mkfs=$(grep -nF 'mkfs.ext4 -q -F -L cogworx-store-rw' "$mkfs" | head -1 | cut -d: -f1 || true)
				# The FIRST line at which this script can exit, and therefore the line the
				# latch has to precede for "marker absent" to mean "no start job of this
				# unit completed this host boot". Everything before it is literal
				# assignments and function definitions, which cannot fail.
				first_exit=$(grep -nF '[ ! -b "$dev" ]' "$mkfs" | head -1 | cut -d: -f1 || true)
				if [ -z "$flag_set" ]; then
					echo "FAIL: the carve leg never SETS the store-format latch, so it can be re-entered in the same host boot and mkfs the store volume under a live guest" >&2
					fails=$((fails + 1))
				elif [ "$flag_set" -gt "$store_mkfs" ]; then
					echo "FAIL: the carve leg sets the store-format latch (line $flag_set) AFTER the mkfs (line $store_mkfs); a run killed at TimeoutStartSec mid-format then leaves no marker while the supervisor has already launched a guest, and the retry mkfs's underneath it" >&2
					fails=$((fails + 1))
				elif [ -n "$first_exit" ] && [ "$flag_set" -gt "$first_exit" ]; then
					echo "FAIL: the carve leg sets the store-format latch (line $flag_set) BELOW its first exit path, the device check at line $first_exit; lvm2's udev rule activates the volume group independently of this unit, so both volume nodes -- all supervise.sh leg (e2) tests before launching a guest -- can already exist, and every refusal above the latch then leaves the marker absent with a guest live on the store volume" >&2
					fails=$((fails + 1))
				fi
				# The shipped size. gce-image-guest-disk-behaviour runs a re-realization
				# of this module with a small store volume, so the number that actually
				# ships is asserted here instead.
				if ! grep -qF 'storesize=16384m' "$mkfs"; then
					echo "FAIL: the shipped carve leg does not bake a 16384 MiB store overlay volume" >&2
					fails=$((fails + 1))
				fi
				# ...and that the behaviour check's fixture really is the same code.
				# Normalise only the two baked size lines; anything else that differs
				# means the tested script and the shipped script have diverged.
				sed -e 's/^\(\t*storesize=\).*/\1SIZE/' -e 's/^\(\t*storebytes=\).*/\1SIZE/' "$mkfs" > shipped.norm
				sed -e 's/^\(\t*storesize=\).*/\1SIZE/' -e 's/^\(\t*storebytes=\).*/\1SIZE/' ${gceGuestDiskScriptSmall} > tested.norm
				if ! diff -u shipped.norm tested.norm; then
					echo "FAIL: the script gce-image-guest-disk-behaviour runs differs from the shipped one by more than the store-overlay size; the behaviour evidence does not describe what ships" >&2
					fails=$((fails + 1))
				fi

				# 3. Ordering. With no host mount unit there is no
				#    x-systemd.before= seam, so the only thing keeping mkfs off a
				#    disk QEMU already has open is the supervisor's own After=.
				sup=${gceUnits}/cogworx-supervisor.service
				if ! grep -Eq '^After=.*cogworx-guest-disk\.service' "$sup"; then
					echo "FAIL: cogworx-supervisor is not ordered After= cogworx-guest-disk.service; the carve could race the VM launch -- mkfs on a volume the guest has open, or a grow that lands after QEMU already sized the drive" >&2
					fails=$((fails + 1))
				fi
				# Wants= is also what PULLS the unit in: it is wantedBy nothing, so
				# without this the carve never runs at all.
				if ! grep -Eq '^Wants=.*cogworx-guest-disk\.service' "$sup"; then
					echo "FAIL: cogworx-supervisor does not Want= cogworx-guest-disk.service; nothing else pulls that unit in, so the disk would never be carved" >&2
					fails=$((fails + 1))
				fi
				# ...but NOT Requires=: a carve that fails must not also make the unit
				# that launches the sandbox fail, and the bounded case matters too --
				# with Wants the launch proceeds when a probe times out.
				if grep -Eq '^Requires=.*cogworx-guest-disk\.service' "$sup"; then
					echo "FAIL: cogworx-supervisor Requires= cogworx-guest-disk.service; a failed carve would then prevent the sandbox from starting at all" >&2
					fails=$((fails + 1))
				fi
				# RemainAfterExit keeps the unit active for the rest of the boot, so the
				# supervisor's own Restart=always does not re-enqueue the carve and the
				# grow on every restart cycle: both stay once-per-HOST-boot, which is
				# exactly the Stop -> resize -> Start shape restart-to-grow needs.
				#
				# It is NOT what protects the store volume's mkfs, and reading it that
				# way is how F2 got in: RemainAfterExit suppresses a re-run only in the
				# `active` state, and the refusals above deliberately leave this unit
				# `failed`. The /run latch asserted higher up is the protection; this
				# assertion is about restart-cycle churn and about the grow's
				# granularity.
				if ! grep -Eq '^RemainAfterExit=(yes|true|1|on)$' ${gceUnits}/cogworx-guest-disk.service; then
					echo "FAIL: cogworx-guest-disk is not RemainAfterExit; every supervisor restart cycle would re-enqueue the carve and the grow mid-boot" >&2
					fails=$((fails + 1))
				fi
				# Not wantedBy anything, the state-disk.nix idiom: the supervisor is
				# the single puller, so the unit cannot run on a boot class that has
				# no business touching a guest disk.
				if [ -e ${gceUnits}/multi-user.target.wants/cogworx-guest-disk.service ]; then
					echo "FAIL: cogworx-guest-disk is wantedBy multi-user.target; it must be pulled in only by the unit that launches the guest" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The carve script, RUN rather than read. The eval check above can only
			# see that certain tokens are present in it, and every one of those greps
			# passes on a script whose control flow is wrong -- an inverted test, an
			# `exit 0` moved below the mkfs, a blkid guard that reads "could not read
			# the disk" as "blank", or a grow leg that sizes the pool before the store
			# would all satisfy them while destroying the user's work tree or silently
			# never growing. This is the one piece of code in the change that can
			# destroy data that has no other copy, so its contract is exercised against
			# real block devices, a real volume group and a real mkfs.
			#
			# The fixture is a SYMLINK at the script's baked by-id path, which is
			# exactly what udev creates on the real host -- so the script runs
			# unmodified and un-parameterised, addressing the device, the volume group
			# and the two logical volumes by the names it ships with. `[ -b ]` follows
			# symlinks, so pointing it at a loop device, a regular file, a
			# device-mapper error target or nothing at all selects the branches.
			#
			# The one thing that IS parameterised is the store overlay's size: the
			# shipped 16 GiB would mean a multi-gigabyte tmpfs and a minutes-long mkfs
			# in a vmTools VM for a property that has nothing to do with the number.
			# gce-image-guest-disk-format asserts the shipped size AND diffs the two
			# realized scripts with the size lines normalised out, so this cannot drift
			# into testing different code.
			#
			# DM_DISABLE_UDEV is set for the FIXTURE, never in the shipped script:
			# there is no udevd in this VM, so lvm has to create the device nodes
			# itself instead of waiting on a udev cookie that will never be answered.
			#
			# THE BLIND SPOT THAT SETTING CREATES, named here because three rounds of
			# review derived a false premise from a fixture that cannot express the
			# question. On the SHIPPED image this script is NOT the only thing that
			# activates the volume group. `services.lvm.enable` is true, which puts
			# lvm2 in `services.udev.packages` (MEASURED on the realized host), and
			# /etc/lvm/lvm.conf leaves `event_activation` at its default 1 -- so
			# lvm2's own 69-dm-lvm.rules fires off the disk's uevent and runs
			# `systemd-run --no-block ... lvm vgchange -aay cogworx-guest`,
			# INDEPENDENTLY of this unit and before it (which keeps
			# DefaultDependencies and so starts after basic.target) has run a line.
			# Both /dev/cogworx-guest/{pool,store} therefore exist on boots where
			# this script exited early -- and supervise.sh leg (e2), which tests only
			# that those two nodes are block devices, launches a guest on them.
			#
			# THIS FIXTURE CANNOT REPRODUCE THAT ACTIVATOR, and the reason is
			# structural rather than a missing line: the rule's RUN+= is
			# `/run/current-system/systemd/bin/systemd-run --no-block`, which needs a
			# systemd MANAGER on D-Bus. vmTools' stage 2 is a shell script as PID 1,
			# with no systemd and no dbus, so running udevd with lvm2's rules here
			# would fire a rule whose activation command cannot work. Case 14 below
			# therefore SIMULATES the state instead: it activates the volume group
			# from the fixture before invoking the script, exactly as udev would have,
			# and then makes the script exit early. What that reproduces is
			# "both nodes exist without this unit having created them in this host
			# boot", which is the premise every store-mkfs guard rests on. What it
			# does NOT reproduce is udev's activation racing this unit in TIME; only
			# a real GCE boot can show that, so the image pipeline's fresh-instance
			# validation is where that half is evidenced.
			gce-image-guest-disk-behaviour = (pkgs.vmTools.override {
				# vmTools' own default list plus `loop`; see cogbox-guest-migrate-behaviour.
				rootModules = [
					"virtio_pci" "virtio_mmio" "virtio_blk" "virtio_balloon" "virtio_rng"
					# dm_mod is both the LVM substrate and, for the unreadable-device
					# case, the only honest way to build a device whose reads FAIL
					# rather than a device that is merely empty.
					"ext4" "virtiofs" "crc32c" "loop" "dm_mod"
				];
			}).runInLinuxVM (pkgs.runCommand "gce-image-guest-disk-behaviour" {
				nativeBuildInputs = [ pkgs.util-linux pkgs.e2fsprogs pkgs.coreutils pkgs.lvm2 ];
				# The default 512 MiB leaves the root tmpfs too small for two ext4
				# filesystems plus the loop backing file.
				memSize = 2048;
			} ''
				fails=0
				fmt=${gceGuestDiskScriptSmall}
				bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
				dev=/dev/disk/by-id/google-cogworx-guest
				pooldev=/dev/cogworx-guest/pool
				storedev=/dev/cogworx-guest/store
				storeflag=/run/cogworx-guest-disk.store-formatted
				mkdir -p /dev/disk/by-id /etc/lvm /run
				export DM_DISABLE_UDEV=1

				# EVERY case below is a fresh HOST BOOT unless it says otherwise, and
				# `boot` is what makes that true. The script latches its unconditional
				# store-volume mkfs on a /run marker, because /run is a tmpfs the host
				# clears at boot and cogworx-supervisor is After= this unit -- so an
				# absent marker proves no guest can be holding the store volume. This VM
				# has ONE /run for all the cases, so without clearing it here every case
				# after the first would silently exercise the SAME-BOOT path and the
				# store assertions would be testing the opposite of what they say.
				# Cases 11, 12 and 14 deliberately re-invoke "$fmt" WITHOUT clearing it,
				# and case 13 arms it by hand: all four are about a RETRY within one
				# host boot.
				boot() { rm -f "$storeflag"; "$fmt"; }

				# A fresh backing file on a loop device per case, reachable at the baked
				# by-id path through the same kind of symlink udev would create. 256 MiB
				# against the fixture's 32 MiB store volume, so the pool gets the clear
				# majority of the group and a grow has somewhere to go.
				loop=""
				fresh_loop() {
					if [ -n "$loop" ]; then
						vgchange -an cogworx-guest 2>/dev/null || true
						losetup -d "$loop" || true
						loop=""
					fi
					rm -f /disk.img
					truncate -s 256M /disk.img
					loop=$(losetup --find --show /disk.img)
					ln -sfn "$loop" "$dev"
				}
				lv_bytes() { lvs --noheadings --units b --nosuffix -o lv_size "$1" | tr -d '[:space:]'; }
				vg_free() { vgs --noheadings --units b --nosuffix -o vg_free cogworx-guest | tr -d '[:space:]'; }
				# ext4's own idea of how big it is, in bytes, read from the superblock
				# rather than by mounting -- this check must never mount a pool.
				fs_bytes() {
					dumpe2fs -h "$1" 2>/dev/null | awk -F: '
						/^Block count/ { n = $2 } /^Block size/ { s = $2 }
						END { gsub(/ /, "", n); gsub(/ /, "", s); print n * s }'
				}
				fs_uuid() { blkid -p -o value -s UUID "$1"; }

				echo "== case 1: a blank disk gets the whole LVM stack, and both labels =="
				fresh_loop
				boot || bad "the carve leg failed on a blank disk"
				[ "$(blkid -p -o value -s TYPE "$loop")" = LVM2_member ] \
					|| bad "case 1 did not make the disk a physical volume"
				[ "$(vgs --noheadings -o vg_name cogworx-guest | tr -d '[:space:]')" = cogworx-guest ] \
					|| bad "case 1 did not create the cogworx-guest volume group"
				[ -b "$pooldev" ] || bad "case 1 left no $pooldev device node; QEMU would have nothing to open"
				[ -b "$storedev" ] || bad "case 1 left no $storedev device node; the guest cannot boot without its store overlay"
				# SIZING POLICY, measured: the store takes its configured size and the
				# pool takes everything else, so there is nothing left over.
				[ "$(lv_bytes "$pooldev")" -gt "$(lv_bytes "$storedev")" ] \
					|| bad "case 1 gave the data pool no more space than the store overlay; the pool is supposed to take the remainder"
				[ "$(vg_free)" = 0 ] \
					|| bad "case 1 left $(vg_free) bytes unallocated; the pool must take the whole remainder or the disk is being wasted"
				[ "$(blkid -p -o value -s TYPE "$pooldev")" = ext4 ] || bad "case 1 left the pool volume unformatted"
				[ "$(blkid -p -o value -s LABEL "$pooldev")" = cogworx-guest ] \
					|| bad "case 1 did not LABEL the pool; the guest resolves it by label and would never find it"
				[ "$(blkid -p -o value -s LABEL "$storedev")" = cogworx-store-rw ] \
					|| bad "case 1 did not LABEL the store overlay; the guest's stage-1 mount resolves it by label"
				store_size_1=$(lv_bytes "$storedev")
				[ "$store_size_1" = 33554432 ] \
					|| bad "case 1 sized the store overlay at $store_size_1 bytes, not the configured 32 MiB"

				echo "== discard: freed blocks must reach the provider disk THROUGH device-mapper =="
				# The mechanism that stops the sparse ratchet the design is about. QEMU
				# opens each logical volume with discard=unmap, so a guest ext4 mounted
				# `discard` issues BLKDISCARD down to the dm device; if dm-linear did not
				# pass that through, the trim would stop one layer above the disk and
				# nothing would ever be returned.
				loop_disc=$(cat /sys/class/block/"$(basename "$loop")"/queue/discard_max_bytes)
				if [ "$loop_disc" = 0 ]; then
					# Not a failure of dm -- a fixture that cannot express the question.
					# Say so rather than passing quietly, exactly as the unreadable-device
					# case does.
					bad "the fixture loop device advertises no discard support, so the passthrough assertions below would be vacuous"
				fi
				for lv in "$pooldev" "$storedev"; do
					dm=$(basename "$(readlink -f "$lv")")
					dm_disc=$(cat /sys/class/block/"$dm"/queue/discard_max_bytes)
					[ "$dm_disc" -gt 0 ] \
						|| bad "$lv ($dm) advertises discard_max_bytes=0; device-mapper is not passing discards down to the disk, so freed guest blocks would never be returned"
				done
				echo "discard evidence: loop=$loop_disc pool=$(cat /sys/class/block/"$(basename "$(readlink -f "$pooldev")")"/queue/discard_max_bytes) store=$(cat /sys/class/block/"$(basename "$(readlink -f "$storedev")")"/queue/discard_max_bytes)"

				echo "== case 2: NEGATIVE -- a re-run never touches the POOL, and always remakes the STORE =="
				# The single most important assertion in the change on the pool side:
				# this is the step between a resumed instance and the total,
				# unrecoverable loss of the user's work tree, on every boot. The store
				# half is the deliberate opposite, and testing both in one case is what
				# makes the asymmetry impossible to lose by accident.
				mkdir -p /mnt/pool
				mount "$pooldev" /mnt/pool
				echo the-users-only-copy > /mnt/pool/sentinel
				umount /mnt/pool
				pool_uuid_1=$(fs_uuid "$pooldev")
				store_uuid_1=$(fs_uuid "$storedev")
				vg_uuid_1=$(vgs --noheadings -o vg_uuid cogworx-guest | tr -d '[:space:]')
				boot || bad "the carve leg failed on an already-initialised disk"
				[ "$(fs_uuid "$pooldev")" = "$pool_uuid_1" ] \
					|| bad "case 2 REFORMATTED the populated pool: its UUID changed, so the user's work tree is gone"
				mount "$pooldev" /mnt/pool
				[ "$(cat /mnt/pool/sentinel)" = the-users-only-copy ] \
					|| bad "case 2 lost the sentinel from a volume it must not have written to"
				umount /mnt/pool
				[ "$(fs_uuid "$storedev")" != "$store_uuid_1" ] \
					|| bad "case 2 did NOT remake the store overlay's filesystem; that mkfs is what keeps the /nix/store upper as ephemeral as the tmpfs it replaced and is the only way it can grow"
				[ "$(vgs --noheadings -o vg_uuid cogworx-guest | tr -d '[:space:]')" = "$vg_uuid_1" ] \
					|| bad "case 2 re-created the volume group; an already-LVM disk must be recognised, not re-initialised"
				[ "$(vg_free)" = 0 ] || bad "case 2 changed the allocation on a disk nobody grew"

				echo "== case 3: GROW -- pvresize, then the pool takes the new extents =="
				# Decision 5, host half. The operator grows the provider disk and
				# restarts; this unit runs BEFORE the guest launches, so the volumes are
				# already bigger by the time QEMU opens them.
				pool_size_2=$(lv_bytes "$pooldev")
				pool_fs_2=$(fs_bytes "$pooldev")
				truncate -s 512M /disk.img
				losetup -c "$loop"
				boot || bad "the carve leg failed after the disk grew"
				[ "$(lv_bytes "$pooldev")" -gt "$pool_size_2" ] \
					|| bad "case 3 did not grow the data pool volume after the disk grew; restart-to-grow is dead for the pool"
				[ "$(vg_free)" = 0 ] \
					|| bad "case 3 left $(vg_free) bytes unallocated after the grow; the pool takes the remainder"
				[ "$(lv_bytes "$storedev")" = "$store_size_1" ] \
					|| bad "case 3 changed the store overlay's size; it takes its CONFIGURED size and the pool takes what is left"
				# The DIVISION OF LABOUR, asserted rather than assumed: the host grows
				# the VOLUME and stops there, and the guest's x-systemd.growfs grows the
				# pool's FILESYSTEM on the same boot (cogbox-guest-volume-hosted asserts
				# the mount option and that the pool is a stage-2 mount, which is what
				# makes that unit able to run at all).
				[ "$(fs_bytes "$pooldev")" = "$pool_fs_2" ] \
					|| bad "case 3 resized the pool's FILESYSTEM from the host; that belongs to the guest, which is the only side that knows whether the filesystem is in use"
				[ "$(fs_bytes "$pooldev")" -lt "$(lv_bytes "$pooldev")" ] \
					|| bad "case 3 left the pool filesystem no smaller than its volume, so there is nothing for the guest to grow into and the assertion above proved nothing"
				# ...and the space really is usable, which a size comparison alone does
				# not show. resize2fs here stands in for the guest's growfs; it is the
				# FIXTURE doing it, not the shipped script.
				e2fsck -fp "$pooldev" >/dev/null 2>&1 || true
				resize2fs "$pooldev" >/dev/null 2>&1 \
					|| bad "case 3's new extents could not actually be used: resize2fs failed on the grown pool volume"
				[ "$(fs_bytes "$pooldev")" -gt "$pool_fs_2" ] \
					|| bad "case 3's pool filesystem did not grow into the new extents even when told to"
				mount "$pooldev" /mnt/pool
				[ "$(cat /mnt/pool/sentinel)" = the-users-only-copy ] || bad "case 3 lost data while growing"
				umount /mnt/pool
				# The store's filesystem, by contrast, is ALWAYS the size of its volume,
				# because the host lays it down fresh. That is what makes restart-to-grow
				# true for the half x-systemd.growfs cannot reach.
				[ "$(fs_bytes "$storedev")" -gt $(( $(lv_bytes "$storedev") - 4194304 )) ] \
					|| bad "case 3's store filesystem is materially smaller than its volume; the unconditional mkfs is what keeps the two in step"

				echo "== case 4: the STORE volume grows to a RAISED configured size, and the pool absorbs the rest =="
				# The other direction of the sizing policy, and the only path that
				# exercises lvextend on the store. Seeded by hand at half the configured
				# size, which is also what an instance carved by an older image with a
				# smaller store looks like.
				fresh_loop
				pvcreate -qq --yes "$loop"
				vgcreate -qq --yes cogworx-guest "$loop"
				lvcreate -qq --yes -L 16m -n store cogworx-guest
				boot || bad "the carve leg failed on a disk whose store volume was smaller than configured"
				[ "$(lv_bytes "$storedev")" = 33554432 ] \
					|| bad "case 4 did not grow the store overlay volume to its configured size"
				[ -b "$pooldev" ] || bad "case 4 did not create the missing data pool volume"
				[ "$(vg_free)" = 0 ] || bad "case 4 left free extents instead of giving them to the pool"

				echo "== case 5: NEGATIVE -- an interrupted first mkfs on the POOL self-heals =="
				# lvcreate succeeded, mkfs did not. The volume exists and is blank, so
				# the three-probe test applied to the POOL VOLUME (not just the disk) is
				# what makes the next boot finish the job instead of leaving a volume the
				# guest cannot mount.
				wipefs -a -q "$pooldev"
				dd if=/dev/zero of="$pooldev" bs=1M count=2 status=none
				boot || bad "the carve leg failed on a pool volume with no filesystem"
				[ "$(blkid -p -o value -s LABEL "$pooldev")" = cogworx-guest ] \
					|| bad "case 5 did not format a blank pool volume; an interrupted first mkfs would never heal"

				echo "== case 5b: an UNREADABLE POOL volume still gets the store remade =="
				# The refusal that costs nothing and used to cost the store overlay. A
				# pool volume the host cannot read makes this unit exit 1 -- correctly --
				# but by then BOTH logical volumes exist, so QEMU opens two drives and
				# the guest boots anyway. With the store's unconditional mkfs sitting
				# behind the pool probe, that boot handed the guest last boot's store
				# filesystem: no longer ephemeral, not sized to the volume, and possibly
				# the half-written result of an interrupted format on the one mount the
				# guest's stage 1 cannot boot without.
				#
				# It is also the state F2 is about: this unit ends `failed` with both
				# volumes carved and a guest live on them, which is exactly when a
				# `systemctl start cogworx-guest-disk` retry must NOT remake the store
				# filesystem. Case 11 below is that half.
				# dmsetup wipe_table swaps the pool's live table for an error target,
				# which is the honest shape: a real volume of the right size whose every
				# read fails, with the EXTENTS untouched underneath -- so the table can
				# be put back afterwards and the volume read to prove nothing was
				# written to it. Addressed by dm NAME, which is not the /dev/dm-N node
				# basename `readlink -f` resolves to.
				pool_dm=$(dmsetup info -c --noheadings -o name "$pooldev" | tr -d '[:space:]')
				store_uuid_5=$(fs_uuid "$storedev")
				pool_uuid_5=$(fs_uuid "$pooldev")
				dmsetup wipe_table --noudevsync "$pool_dm" \
					|| bad "case 5b could not swap the pool volume's table for an error target"
				if dd if="$pooldev" of=/dev/null bs=1M count=1 status=none 2>/dev/null; then
					bad "case 5b's pool volume still READS, so the refusal it is about is unexercised and the assertions below prove nothing"
				fi
				boot > case5b.out 2>&1 \
					&& bad "case 5b exited 0 on a pool volume it could not examine; that refusal must be visible in systemctl --failed"
				grep -q 'cannot be READ' case5b.out \
					|| bad "case 5b did not report an unreadable pool volume, so it refused for some other reason"
				# Restore the real table before reading anything back off the volume.
				vgchange -an cogworx-guest >/dev/null 2>&1 || true
				vgchange -ay cogworx-guest >/dev/null
				[ "$(fs_uuid "$storedev")" != "$store_uuid_5" ] \
					|| bad "case 5b did NOT remake the store overlay's filesystem before refusing the pool; the guest is then started on last boot's store, which is neither ephemeral nor grown"
				[ "$(blkid -p -o value -s LABEL "$storedev")" = cogworx-store-rw ] \
					|| bad "case 5b left the store overlay without its label; the guest's stage-1 mount resolves it by label"
				# ...and the refusal is still a refusal: nothing was written to the volume
				# this host could not read.
				[ "$(fs_uuid "$pooldev")" = "$pool_uuid_5" ] \
					|| bad "case 5b WROTE to the pool volume it had just declared unreadable"

				echo "== case 6: NEGATIVE -- a disk carrying a NON-LVM filesystem is left alone, LOUDLY =="
				# Not ours. The likeliest cause is the wrong disk attached, and writing
				# a volume group over somebody else's filesystem is the failure this
				# whole guard chain exists to prevent.
				#
				# The refusal is unchanged; its EXIT STATUS is what this case now
				# asserts, 1 rather than 0. This used to be a boot that still produced a
				# guest, because a launch-time chooser fell back to the workstation
				# runner, so `active` was honest. With one baked profile it produces no
				# guest at all -- and exit 0 left NOTHING in `systemctl --failed` while
				# cogworx-supervisor flapped under Restart=always, which is the
				# undiagnosable stuck-in-Booting shape this design exists to prevent.
				fresh_loop
				mkfs.ext4 -q -L someone-elses "$loop"
				boot 2> case6.err \
					&& bad "case 6 exited 0 on a disk it refused to carve; with one baked storage profile that boot has no guest at all, so the refusal must be visible in systemctl --failed"
				[ "$(blkid -p -o value -s TYPE "$loop")" = ext4 ] \
					|| bad "case 6 overwrote a disk carrying a non-LVM filesystem"
				[ "$(blkid -p -o value -s LABEL "$loop")" = someone-elses ] \
					|| bad "case 6 relabelled a filesystem that is most likely not ours"
				grep -q 'leaving it alone' case6.err \
					|| bad "case 6 refused silently; a disk the guest cannot use must say why"

				echo "== case 7: NEGATIVE -- a foreign VOLUME GROUP is reported, never renamed, and FAILS =="
				# Same visibility argument as case 6: somebody else's group is left
				# exactly as it is, and the unit fails so that the refusal lands
				# somewhere an operator and the control plane can both see it.
				fresh_loop
				pvcreate -qq --yes "$loop"
				vgcreate -qq --yes somebody-elses-vg "$loop"
				boot 2> case7.err \
					&& bad "case 7 exited 0 on somebody else's volume group; that boot has no guest, so the refusal must land in systemctl --failed"
				[ "$(pvs --noheadings -o vg_name "$loop" | tr -d '[:space:]')" = somebody-elses-vg ] \
					|| bad "case 7 renamed or replaced somebody else's volume group"
				grep -q WARNING case7.err \
					|| bad "case 7 did not warn; a disk the guest cannot use must not be silent"
				vgchange -an somebody-elses-vg >/dev/null 2>&1 || true
				vgremove -qq -f somebody-elses-vg >/dev/null 2>&1 || true

				echo "== case 8: NEGATIVE -- a REGULAR FILE at the device path is not touched =="
				# microvm.nix's own autoCreate guard is `[ ! -e ]`, which would touch a
				# missing device node into a regular file and mkfs THAT, handing the user
				# a blank pool while their real disk sat unattached. `[ ! -b ]` here is
				# what makes that unreachable from this side.
				rm -f /notadisk
				truncate -s 256M /notadisk
				ln -sfn /notadisk "$dev"
				boot || bad "the carve leg failed instead of skipping a regular file"
				[ -z "$(blkid -p -o value -s TYPE /notadisk)" ] \
					|| bad "case 8 wrote to a REGULAR FILE at the device path"
				[ "$(stat -c %s /notadisk)" = 268435456 ] \
					|| bad "case 8 changed the size of a regular file it must not have touched"

				echo "== case 9: no device at all -- exit 0, and create nothing =="
				# A resolver VM and every instance created before the guest disk existed
				# boot this same image with no such device. Both must still boot.
				rm -f "$dev"
				boot || bad "the carve leg failed on a boot class with no guest disk; that boot now has no sandbox at all"
				[ ! -e "$dev" ] || bad "case 9 CREATED something at the device path"
				# ...and it STILL arms the once-per-host-boot latch on the way out, which
				# is the late-attach half of case 14. A disk that attaches after this run
				# exited 0 is activated by lvm2's udev rule (see the blind-spot note above),
				# leg (e2) then finds both nodes and launches a guest, and the operator
				# retries this unit in the same host boot -- so the exit-0 path is a
				# pre-mkfs exit like any other and may not leave the latch unarmed.
				[ -e "$storeflag" ] \
					|| bad "case 9's absent-device exit left the once-per-host-boot marker unarmed; a disk attached later in this host boot is activated by udev, leg (e2) launches a guest on it, and a retry of this unit is then free to mkfs the store volume underneath that guest"

				echo "== case 10: NEGATIVE -- a device that cannot be READ is not written to =="
				# The finding this case exists for. blkid returns exit 2 with empty
				# stdout for a device it could not probe, identically to a blank one, so
				# a guard resting on blkid alone reads "I could not read this disk" as
				# "this disk is blank" -- and carves the disk most likely to hold data.
				# device-mapper's `error` target is the honest way to produce it: a real
				# block device of a real size whose every read returns EIO.
				dmsetup create cogbox-eio --table "0 131072 error" --noudevsync
				eio=/dev/mapper/cogbox-eio
				dmsetup mknodes cogbox-eio || true
				if [ ! -b "$eio" ]; then
					# Two calls rather than one lookup plus a shell suffix-strip: a bare
					# dollar-brace is Nix interpolation inside this string, and escaping
					# one here to save a subprocess buys nothing.
					eio_major=$(dmsetup info -c --noheadings -o major cogbox-eio)
					eio_minor=$(dmsetup info -c --noheadings -o minor cogbox-eio)
					mknod "$eio" b "$eio_major" "$eio_minor"
				fi
				[ -b "$eio" ] \
					|| bad "case 10 has no block device to test with, so the unreadable-device guard is unexercised and the assertions below prove nothing"
				ln -sfn "$eio" "$dev"
				# Prove the fixture has the shape this case is about before asserting
				# anything about the script, or a pass here means nothing. BOTH signature
				# probes must be indistinguishable from blank -- blkid exit 2 with no
				# TYPE, wipefs exit 0 with no signatures -- while the READ fails. That
				# combination is the finding: two blind probes agreeing.
				brc=0
				btype=$(blkid -p -o value -s TYPE "$eio" 2>/dev/null) || brc=$?
				wrc=0
				wsigs=$(wipefs --no-act -i -O TYPE "$eio" 2>/dev/null) || wrc=$?
				if [ "$brc" -ne 2 ] || [ -n "$btype" ]; then
					bad "case 10 did not reproduce the unreadable-device shape (blkid exit $brc, type '$btype'); the guard it exists to test is then unexercised"
				fi
				if [ "$wrc" -ne 0 ] || [ -n "$wsigs" ]; then
					bad "case 10 gave the signature probes something to refuse on (wipefs exit $wrc, signatures '$wsigs'); the read proof is then not what is being tested"
				fi
				if dd if="$eio" of=/dev/null bs=1M count=1 status=none 2>/dev/null; then
					bad "case 10 device READS fine, so it is not the unreadable-device shape at all"
				fi
				# A fault, not a boot class, so the unit is expected to FAIL loudly -- it
				# costs nothing (the supervisor only Wants= it) and a later supervisor
				# start retries it, so a transient error self-heals.
				boot > case10.out 2>&1 \
					&& bad "case 10 exited 0 on a disk it could not examine; that refusal must be visible in systemctl --failed"
				# THE assertion, and it is on the ATTEMPT rather than on the outcome
				# because the outcome cannot discriminate: pvcreate fails on an error
				# target of its own accord, so a script with no read proof at all still
				# leaves the device uncarved and still exits nonzero. What separates the
				# two is whether it TRIED. On a real disk that reads intermittently --
				# the shape this guards against -- that attempt succeeds.
				grep -q 'provably blank' case10.out \
					&& bad "case 10 went on to CARVE a device it could not read; the attempt IS the defect, whatever pvcreate then did with it"
				grep -q 'cannot be READ' case10.out \
					|| bad "case 10 did not report an unreadable disk at all, so it refused for some other reason and the read proof is unexercised"
				[ -z "$(blkid -p -o value -s TYPE "$eio" 2>/dev/null)" ] \
					|| bad "case 10 WROTE to a device it could not read; a blank-looking signature probe was taken as proof of blankness"
				dmsetup remove cogbox-eio

				echo "== case 11: NEGATIVE -- a SAME-BOOT re-run must not remake the store filesystem =="
				# F2, reproduced through the state that actually produces it rather than
				# by calling the script twice.
				#
				# RemainAfterExit stops a re-run only while the unit is `active`. The
				# pool probe is ALLOWED to refuse (case 5b), and a refusal leaves this
				# unit `failed` with BOTH logical volumes carved and active -- and
				# cogworx-supervisor only Wants= it, so the guest was launched anyway and
				# QEMU is holding /dev/cogworx-guest/store open as its /nix/store overlay
				# upper. From there a plain `systemctl start cogworx-guest-disk` -- the
				# obvious operator retry of a failed unit, and what any future Wants=
				# edge would also do -- re-entered the store leg and ran `mkfs.ext4 -F`
				# on that live volume. `-F` refuses a MOUNTED device and this host mounts
				# neither, so nothing stopped it.
				#
				# The fixture cannot run a guest, so it asserts the mechanism instead:
				# after a run that got as far as the store leg, a re-run WITHOUT a fresh
				# /run must leave the store filesystem's UUID untouched.
				fresh_loop
				boot || bad "case 11 could not carve a fresh disk to start from"
				pool_dm_11=$(dmsetup info -c --noheadings -o name "$pooldev" | tr -d '[:space:]')
				# Produce the failed-with-volumes-carved state: an unreadable pool makes
				# the run exit 1 AFTER the store leg has already re-formatted.
				dmsetup wipe_table --noudevsync "$pool_dm_11" \
					|| bad "case 11 could not swap the pool volume's table for an error target"
				boot > case11a.out 2>&1 \
					&& bad "case 11's setup run exited 0 on an unreadable pool; it is supposed to reproduce the FAILED unit state"
				store_uuid_11=$(fs_uuid "$storedev")
				[ -n "$store_uuid_11" ] \
					|| bad "case 11's setup run left the store volume with no filesystem, so the assertion below cannot distinguish anything"
				[ -e "$storeflag" ] \
					|| bad "case 11's setup run did not leave the once-per-host-boot marker; the latch is not armed and the re-run below proves nothing"
				# THE RETRY, deliberately WITHOUT clearing /run -- the same host boot.
				"$fmt" > case11b.out 2>&1 \
					&& bad "case 11's retry exited 0 on a pool it still cannot read; the refusal must be unchanged"
				grep -q 'NOT (re)formatting' case11b.out \
					|| bad "case 11's retry did not report skipping the store mkfs, so it either ran it or skipped it for some other reason"
				[ "$(fs_uuid "$storedev")" = "$store_uuid_11" ] \
					|| bad "case 11's retry REMADE the store overlay's filesystem in the same host boot; a live guest holds that volume open as its /nix/store overlay upper, and mkfs -F only refuses a MOUNTED device"
				# ...and the latch is a per-BOOT bound, not a permanent off switch: the
				# next host boot must still remake it, or the overlay stops being
				# ephemeral and stops growing. Without this half the assertion above
				# would also pass on a script that simply never formats the store again.
				boot > case11c.out 2>&1 \
					&& bad "case 11's next-boot run exited 0 on an unreadable pool"
				[ "$(fs_uuid "$storedev")" != "$store_uuid_11" ] \
					|| bad "case 11's NEXT host boot did not remake the store overlay's filesystem; the marker has become a permanent latch rather than a once-per-boot bound"
				vgchange -an cogworx-guest >/dev/null 2>&1 || true
				vgchange -ay cogworx-guest >/dev/null 2>&1 || true

				echo "== case 12: NEGATIVE -- a run that DIED BEFORE the store leg must not let a same-boot retry remake the store filesystem =="
				# Case 11's twin, and the half case 11 cannot reach. Case 11's setup run
				# gets all the way THROUGH the store leg before the pool probe refuses, so
				# it only ever exercises a latch the store leg itself armed. The window
				# this case is about is the one BEFORE that: both volume device nodes are
				# up (`lvmc vgchange -ay` here, lvm2's own udev rule on the shipped image --
				# case 14), supervise.sh leg (e2) gates the guest launch on exactly those two
				# nodes existing, and `After=` is satisfied by a FAILED start job -- so every
				# leg between the top of the script and the store leg can fail with a guest
				# already live on the store volume.
				#
				# The fault injected is the one the unit's TimeoutStartSec exists for, in
				# its fast-failing form: a disk that still answers its probe and its reads
				# -- so the three-probe test types it LVM2_member and the volume group
				# activates -- and refuses WRITES, so `pvresize` dies. MEASURED with
				# blockdev --setro: vgchange exit 0 with both nodes present, dd and blkid
				# unaffected, pvresize exit 5 ("Error writing device").
				fresh_loop
				boot || bad "case 12 could not carve a fresh disk to start from"
				store_uuid_12=$(fs_uuid "$storedev")
				# A FRESH host boot -- hence the marker is cleared -- whose run dies after
				# the activation and before the store leg.
				rm -f "$storeflag"
				blockdev --setro "$loop"
				"$fmt" > case12a.out 2>&1 \
					&& bad "case 12's setup run exited 0 on a disk whose writes fail; it is supposed to reproduce the run that DIES between the activation and the store leg"
				# The fixture really is that window, asserted with the script's own words
				# rather than with lvm's error text, which is version-coupled.
				grep -q '(re)creating ext4' case12a.out \
					&& bad "case 12's setup run reached the store leg after all, so it does not reproduce the state this case is about"
				[ -b "$storedev" ] \
					|| bad "case 12's setup run left no store volume node, so no guest could have been launched and the retry below has nothing to protect"
				[ -b "$pooldev" ] \
					|| bad "case 12's setup run left no pool volume node; both nodes present is precisely when supervise.sh leg (e2) lets the guest start, and that is the state this case is about"
				# THE discriminating assertion on the setup run: a run that ACTIVATED the
				# volume group must leave the marker behind however it then died. Without
				# it the retry below reformats the store volume under a guest leg (e2)
				# already let start.
				[ -e "$storeflag" ] \
					|| bad "case 12's setup run left no once-per-host-boot marker although both volume nodes were present; a guest can exist from before this script's first line (case 14), so the retry below is free to mkfs the store volume underneath it"
				# The transient fault clears and the operator does what the failed unit's
				# own message invites -- in the SAME host boot, so no fresh marker.
				blockdev --setrw "$loop"
				"$fmt" > case12b.out 2>&1 \
					|| bad "case 12's retry failed on a disk that is healthy again; unlike case 11 the pool here is fine, so the retry is expected to SUCCEED"
				grep -q 'NOT (re)formatting' case12b.out \
					|| bad "case 12's retry did not report skipping the store mkfs, so it either ran it or skipped it for some other reason"
				[ "$(fs_uuid "$storedev")" = "$store_uuid_12" ] \
					|| bad "case 12's retry REMADE the store overlay's filesystem in the same host boot; a guest launched by leg (e2) after the failed run holds that volume open as its /nix/store overlay upper, and mkfs -F only refuses a MOUNTED device"
				# ...and the latch is still a per-BOOT bound. Without this half the
				# assertion above would also pass on a script that armed the marker and
				# never formatted the store again.
				boot > case12c.out 2>&1 \
					|| bad "case 12's next host boot failed on a healthy disk"
				[ "$(fs_uuid "$storedev")" != "$store_uuid_12" ] \
					|| bad "case 12's NEXT host boot did not remake the store overlay's filesystem; arming the marker earlier has turned it into a permanent latch rather than a once-per-boot bound"

				echo "== case 13: NEGATIVE -- a same-boot retry of an INTERRUPTED FIRST carve FAILS by name instead of exiting 0 with no store filesystem =="
				# Case 12's other half, and the one path arming the latch at the
				# activation opened. Case 12's setup run had LAST boot's store filesystem
				# to fall back on, so its retry skipping the mkfs cost only freshness. A
				# FIRST-EVER carve has nothing to fall back to, and the window is the
				# same one: the marker is armed on the script's first lines, both device
				# nodes are up (from `lvmc vgchange -ay`, or from lvm2's udev rule on the
				# shipped image -- case 14), supervise.sh leg (e2) launches a guest on
				# exactly those two nodes, and every leg between there and the store mkfs
				# can still fail -- the [ -b ] node checks losing a race with udev, a
				# transient lvm error, a TimeoutStartSec kill, a host crash.
				#
				# On the retry the marker still says a guest may hold the store volume
				# open, so the mkfs must NOT run. MEASURED before the refusal below
				# existed: the script skipped it, ran off its own end and exited 0 --
				# leaving the unit `active`, nothing in `systemctl --failed`, and the
				# store volume with no filesystem at all. The guest's /nix/.rw-store is
				# neededForBoot, x-initrd.mount, resolved BY LABEL and carries no nofail,
				# so stage 1 cannot mount a label that does not exist: the sandbox never
				# starts for the rest of the host boot and no unit anywhere says why.
				# That is the stuck-in-Booting shape this whole file is written against,
				# so the skip has to be loud when there is nothing there to skip.
				fresh_loop
				# Carved by hand rather than through an injected fault: the script has no
				# leg that both creates the volumes and then fails before the store mkfs
				# on demand, and this is precisely the state such a run leaves behind --
				# both logical volumes present, neither filesystem written, marker armed.
				pvcreate -qq --yes "$loop"
				vgcreate -qq --yes cogworx-guest "$loop"
				lvcreate -qq --yes -L 32m -n store cogworx-guest
				lvcreate -qq --yes -l 100%FREE -n pool cogworx-guest
				: > "$storeflag"
				# Prove the fixture is that state before asserting anything about the
				# script, or a pass below means nothing.
				[ -b "$storedev" ] \
					|| bad "case 13 has no store volume node, so this is not the interrupted-first-carve state and the assertions below prove nothing"
				[ -b "$pooldev" ] \
					|| bad "case 13 has no pool volume node; both nodes present is precisely when supervise.sh leg (e2) lets the guest start, and that is the state this case is about"
				[ -z "$(blkid -p -o value -s TYPE "$storedev" 2>/dev/null)" ] \
					|| bad "case 13's store volume already carries a filesystem, so the never-formatted path this case exists for is unexercised"
				"$fmt" > case13a.out 2>&1 \
					&& bad "case 13's same-boot retry exited 0 with the store volume unformatted; the unit stays active, nothing lands in systemctl --failed, and the guest's stage-1 mount by label fails for the rest of the host boot with no unit saying why"
				grep -q 'has no cogworx-store-rw filesystem' case13a.out \
					|| bad "case 13's retry did not NAME the missing store filesystem; a refusal that costs the user their sandbox has to say which volume and why, or the operator is back to guessing from serial output"
				[ -z "$(blkid -p -o value -s TYPE "$storedev" 2>/dev/null)" ] \
					|| bad "case 13's retry FORMATTED the store volume in a host boot whose marker says a guest may already hold it open; the refusal must only get LOUDER, never turn into a write"
				# ...and the next host boot still heals it, the same closing half cases 11
				# and 12 carry. Without it the assertion above also passes on a script
				# that has simply stopped formatting the store volume at all.
				boot > case13b.out 2>&1 \
					|| bad "case 13's next host boot failed on a healthy disk"
				[ "$(blkid -p -o value -s LABEL "$storedev" 2>/dev/null)" = cogworx-store-rw ] \
					|| bad "case 13's NEXT host boot did not lay down the store filesystem the retry refused to; the refusal has turned a recoverable interrupted carve into a permanently unbootable instance"

				echo "== case 14: NEGATIVE -- volumes activated by UDEV, not by this unit, must still bound the store mkfs to once per host boot =="
				# The case DM_DISABLE_UDEV blinds this fixture to, simulated by hand --
				# see the blind-spot note at the fixture's `export DM_DISABLE_UDEV=1`
				# for why udevd with lvm2's rules cannot be run in this harness and for
				# exactly what this case does and does not reproduce.
				#
				# It is also the ROOT of cases 11, 12 and 13 rather than a fourth
				# sibling of them. Every one of those reasons about a marker that some
				# earlier run of THIS SCRIPT armed, because in this fixture the script
				# is the only thing that can create the volume device nodes. On the
				# shipped image it is not: lvm2's 69-dm-lvm.rules activates the volume
				# group off the disk's own uevent, so BOTH nodes -- which is the entire
				# test supervise.sh leg (e2) applies before launching a guest -- exist
				# on a boot where this script exited at its very first refusal. "Marker
				# absent" then did not mean "no guest can exist"; it only meant "no run
				# of this script reached the vgchange", and those two stopped being the
				# same statement the moment something else could activate.
				#
				# The chain, end to end: existing carved sandbox, host boot, udev
				# activates. Run A hits a transient read error on the disk and exits at
				# the 'cannot be READ' branch -- before the line the latch used to be
				# armed on. Unit failed, marker absent, both nodes present, so leg (e2)
				# starts a guest that mounts /dev/disk/by-label/cogworx-store-rw
				# READ-WRITE as its neededForBoot /nix/.rw-store overlay upper. The disk
				# reads fine again and the operator does what this unit's own message
				# invites -- `systemctl start cogworx-guest-disk`. With the latch armed
				# at the activation, run B saw no marker and ran `mkfs.ext4 -F` on the
				# live guest's store volume (`-F` refuses only a MOUNTED device, and
				# this host mounts neither), destroying the running sandbox's /nix/store
				# overlay upper mid-session -- and then exited 0, so nothing landed in
				# `systemctl --failed` either.
				fresh_loop
				boot || bad "case 14 could not carve a fresh disk to start from"
				mount "$pooldev" /mnt/pool
				echo the-users-only-copy-14 > /mnt/pool/sentinel
				umount /mnt/pool
				store_uuid_14=$(fs_uuid "$storedev")
				pool_uuid_14=$(fs_uuid "$pooldev")
				# A NEW host boot of an ALREADY-CARVED instance: /run is cleared, and the
				# volume group is activated by something OTHER than this script. The
				# vgchange here stands in for the `vgchange -aay --autoactivation event`
				# that 69-dm-lvm.rules runs; the deactivate first is what makes it a real
				# activation rather than a no-op on a group left active by the run above.
				rm -f "$storeflag"
				vgchange -an cogworx-guest >/dev/null
				vgchange -ay cogworx-guest >/dev/null
				# Prove the fixture is that state before asserting anything about the
				# script, or a pass below means nothing.
				[ -b "$storedev" ] \
					|| bad "case 14 has no store volume node before the script runs, so it is not the udev-activated state and the assertions below prove nothing"
				[ -b "$pooldev" ] \
					|| bad "case 14 has no pool volume node before the script runs; both nodes present is precisely when supervise.sh leg (e2) lets a guest start, and that is the state this case is about"
				[ ! -e "$storeflag" ] \
					|| bad "case 14 starts with the marker already armed, so it is not a fresh host boot and the run-A assertion below is vacuous"
				# RUN A: a transient read error on the DISK. The same dm `error` target
				# case 10 uses, at the same baked by-id path, so probe_blank's `dd` fails
				# and the script exits at 'cannot be READ' -- the earliest refusal it has,
				# and one that is reachable on a disk whose volume group is already up.
				# (`lvmc pvs` failing, `vgchange -ay` failing and a TimeoutStartSec kill
				# on a wedged probe all land in the same window; this is the one the
				# fixture can inject deterministically.)
				dmsetup create cogbox-eio14 --table "0 131072 error" --noudevsync
				eio14=/dev/mapper/cogbox-eio14
				dmsetup mknodes cogbox-eio14 || true
				if [ ! -b "$eio14" ]; then
					eio14_major=$(dmsetup info -c --noheadings -o major cogbox-eio14)
					eio14_minor=$(dmsetup info -c --noheadings -o minor cogbox-eio14)
					mknod "$eio14" b "$eio14_major" "$eio14_minor"
				fi
				[ -b "$eio14" ] \
					|| bad "case 14 has no unreadable device to fault the disk with, so run A would not exit early and the assertions below prove nothing"
				ln -sfn "$eio14" "$dev"
				"$fmt" > case14a.out 2>&1 \
					&& bad "case 14's run A exited 0 on a disk it could not read; it is supposed to reproduce the run that dies at the FIRST refusal"
				grep -q 'cannot be READ' case14a.out \
					|| bad "case 14's run A did not refuse on an unreadable disk, so it did not exit in the window this case is about"
				# Both nodes are STILL there -- udev put them there and this unit failing
				# did not take them away -- so leg (e2) is satisfied and a guest is live
				# on the store volume from here on.
				[ -b "$storedev" ] \
					|| bad "case 14's run A left no store volume node, so no guest could have been launched and the retry below has nothing to protect"
				[ -b "$pooldev" ] \
					|| bad "case 14's run A left no pool volume node; leg (e2) would not have launched a guest and this case proves nothing"
				# THE discriminating assertion, and the one that fails on a script whose
				# latch is armed at its own vgchange: the volume group was ALREADY active
				# when this run started, so a guest can exist from before the first line
				# of it, and every exit path -- including the very first refusal -- has to
				# leave the marker behind.
				[ -e "$storeflag" ] \
					|| bad "case 14's run A exited before arming the once-per-host-boot marker although the volume group was ALREADY ACTIVE and both nodes were present; supervise.sh leg (e2) launches a guest on exactly those two nodes, so the retry below is free to mkfs the store volume underneath it"
				# The transient error clears and the operator retries the failed unit, in
				# the SAME host boot -- which is what this unit's own failure message and
				# the supervisor's Wants= edge both invite.
				ln -sfn "$loop" "$dev"
				dmsetup remove cogbox-eio14
				"$fmt" > case14b.out 2>&1 \
					|| bad "case 14's retry failed on a disk that is healthy again; the fault was transient, so the retry is expected to SUCCEED"
				grep -q 'NOT (re)formatting' case14b.out \
					|| bad "case 14's retry did not report skipping the store mkfs, so it either ran it or skipped it for some other reason"
				# The evidence line, in the style of the discard one above: the store
				# filesystem's identity across the retry is the single measurement this
				# whole case turns on, and a reader of the log should not have to infer
				# it from whether an assertion fired.
				echo "case 14 store filesystem UUID: before the retry $store_uuid_14, after it $(fs_uuid "$storedev")"
				[ "$(fs_uuid "$storedev")" = "$store_uuid_14" ] \
					|| bad "case 14's retry REMADE the store overlay's filesystem in a host boot where UDEV had already activated the volume group; a guest launched by leg (e2) holds that volume open as its /nix/store overlay upper and mkfs -F only refuses a MOUNTED device, so this is the running sandbox's entire /nix/store upper destroyed mid-session"
				[ "$(fs_uuid "$pooldev")" = "$pool_uuid_14" ] \
					|| bad "case 14's retry REFORMATTED the populated pool; the user's work tree has no other copy"
				mount "$pooldev" /mnt/pool
				[ "$(cat /mnt/pool/sentinel)" = the-users-only-copy-14 ] \
					|| bad "case 14's retry lost the sentinel from a volume it must not have written to"
				umount /mnt/pool
				# ...and the latch is still a per-BOOT bound, not a permanent off switch.
				# Without this half the assertion above also passes on a script that has
				# simply stopped remaking the store filesystem at all.
				boot > case14c.out 2>&1 \
					|| bad "case 14's next host boot failed on a healthy disk"
				[ "$(fs_uuid "$storedev")" != "$store_uuid_14" ] \
					|| bad "case 14's NEXT host boot did not remake the store overlay's filesystem; arming the marker at the top of the script has turned it into a permanent latch rather than a once-per-boot bound"

				echo "== all cases ran =="
				# Leave nothing holding the VM's root filesystem open. vmTools' stage 2
				# ends with `mount -o remount,ro dummy /` to flush the build output, and
				# a loop device whose backing file lives on that root -- or a live
				# device-mapper table over one -- makes that remount fail with EBUSY,
				# which surfaces as an init panic rather than as a readable test result.
				vgchange -an cogworx-guest >/dev/null 2>&1 || true
				if [ -n "$loop" ]; then losetup -d "$loop" >/dev/null 2>&1 || true; fi
				losetup -D >/dev/null 2>&1 || true
				rm -f /disk.img /notadisk "$dev"

				[ "$fails" -eq 0 ] || exit 1
				mkdir -p $out
				touch $out/ok
			'');

			# The hosted-guest DELIVERY seam, and -- since the launch-time chooser was
			# removed -- the SAFETY PROPERTY that makes one baked profile acceptable.
			#
			# Delivery: everything the guest half declares is inert unless the image
			# actually bakes the hosted runner, and the ways it silently would not are
			# (a) the wrapper pointing somewhere else, (b) the launcher's plugin
			# re-exec resolving packages.default, and (c) the fast-path runner record
			# validating against a runner composed for a different package. All three
			# are invisible at eval and all three look exactly like "the storage
			# feature did not work".
			#
			# Safety: with no fallback runner, a refused carve means no guest. That is
			# accepted ONLY while the host half stays up and reachable and the failure
			# is visible and named -- otherwise this is the stuck-in-Booting mode with a
			# tidier cause. The second half of this check asserts those legs against
			# the realized units.
			gce-image-hosted-guest-profile = pkgs.runCommand "gce-image-hosted-guest-profile" { } ''
				fails=0

				# Guard against a VACUOUS run first. Every absence assertion below
				# is meaningless if the two runners are the same derivation -- which
				# is what would happen if the hosted nixosConfiguration stopped
				# setting the profile, the exact regression worth catching.
				if [ '${gceHostedRunner}' = '${gceWorkstationRunner}' ]; then
					echo "FAIL: the hosted and workstation runners are the SAME derivation, so the hosted profile is not being applied and every assertion below is vacuous" >&2
					exit 1
				fi

				# ONE MODE. The host's cogbox wrapper must exec packages.cogbox-hosted
				# DIRECTLY, with nothing between them that could select a second guest
				# at runtime.
				#
				# An earlier revision put a storage-profile chooser there, testing the
				# two volume device nodes and falling back to the WORKSTATION runner
				# when either was missing. It was removed because the image could then
				# run in two modes while all per-instance state -- the state disk, the
				# instance config dir, the recorded runner path, the retained 9p work
				# tree, the harness overlay image -- persisted across the flip, which
				# was the single root of four separate blocker rounds. So the assertion
				# is now the opposite of what it was: no chooser, and no workstation
				# package reachable from the wrapper at all.
				wrapper=${gceCogboxWrapper}/bin/cogbox
				if grep -q 'cogbox-choose-storage-profile' "$wrapper"; then
					echo "FAIL: the GCE cogbox wrapper still fronts a storage-profile chooser; this image is hosted-only, and a runtime choice between two guest profiles is the state-across-a-flip class four rounds of blockers came from" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF '${gceHostedCogbox}/bin/cogbox' "$wrapper"; then
					echo "FAIL: the GCE cogbox wrapper does not exec packages.cogbox-hosted; the image would never launch the hosted guest" >&2
					fails=$((fails + 1))
				fi
				if grep -qF '${gceWorkstationCogbox}/bin/cogbox' "$wrapper"; then
					echo "FAIL: the GCE cogbox wrapper can still reach packages.cogbox; that is the second mode this change removed" >&2
					fails=$((fails + 1))
				fi

				# ...whose launch script must bake the hosted runner, and must
				# re-exec through the hosted ATTRIBUTE. Without the second, the
				# first plugin add rebuilds packages.default = the workstation guest
				# and the user's pool quietly stops being mounted.
				launch=${gceHostedCogbox}/libexec/cogbox-launch.sh
				if ! grep -qF '${gceHostedRunner}' "$launch"; then
					echo "FAIL: the hosted launch script does not bake the hosted runner" >&2
					fails=$((fails + 1))
				fi
				if grep -qF '${gceWorkstationRunner}' "$launch"; then
					echo "FAIL: the hosted launch script still references the workstation runner" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'run "path:${self}#cogbox-hosted"' "$launch"; then
					echo "FAIL: the hosted launcher's re-exec does not name the cogbox-hosted attribute; a plugin add would rebuild the workstation guest and unmount the user's data pool" >&2
					fails=$((fails + 1))
				fi
				# The runner.path fast-path record must be keyed on the PACKAGE too,
				# not on the flake source alone: @flakeSource@ is byte-identical for
				# cogbox and cogbox-hosted, so a rev-only key let a record written by
				# one validate for the other -- and FAST_PATH=1 is exactly the path
				# that does not rewrite it, so a wrong record is sticky until the image
				# rev moves. Read off the SUBSTITUTED script, so this also proves both
				# @-substitutions landed. Compare AND write are both checked: fixing
				# one alone leaves the two spellings disagreeing, which silently
				# disables the fast path on every boot forever.
				if ! grep -qF 'RUNNER_KEY="${self}#cogbox-hosted"' "$launch"; then
					echo "FAIL: the hosted launcher does not key its runner record on <flakeSource>#cogbox-hosted; a record composed against a different package would be accepted and the re-exec that would rebuild the right runner skipped" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF '[ "$FP_REV" = "$RUNNER_KEY" ]' "$launch"; then
					echo "FAIL: the hosted launcher's fast path does not compare the record against RUNNER_KEY" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF '"$RUNNER_KEY" "${gceHostedRunner}" > "$RUNNER_PATH_FILE"' "$launch"; then
					echo "FAIL: the hosted launcher does not RECORD RUNNER_KEY plus the hosted runner; a record whose key differs from the one the fast path compares never matches, so every boot pays a full eval" >&2
					fails=$((fails + 1))
				fi

				# ...and the image's REGISTERED store must contain the hosted runner
				# and NOT the workstation one. The launch is offline, so a runner that
				# is not registered here cannot be started at all -- which is what
				# makes the second half a real assertion and not bookkeeping: with no
				# chooser there is nothing that could start the workstation guest, so
				# its presence would mean something still references it.
				paths=${gceClosure}/store-paths
				if ! grep -qxF '${gceHostedRunner}' "$paths"; then
					echo "FAIL: ${gceHostedRunner} is not in the GCE image closure; the launch is offline, so the guest could not be started at all" >&2
					fails=$((fails + 1))
				fi
				if grep -qxF '${gceWorkstationRunner}' "$paths"; then
					echo "FAIL: the WORKSTATION runner is still in the GCE image closure; this image is hosted-only, so something is still pulling in a guest it can never launch" >&2
					fails=$((fails + 1))
				fi

				# --- THE SAFETY PROPERTY --------------------------------------------
				#
				# Hosted-only is only acceptable because a refused carve or an
				# unmountable pool leaves the HOST HALF fully up and reachable. The
				# stuck-in-Booting mode was bad for one reason: there was no recovery
				# path -- the instance sat in Booting with no sshd and no control
				# channel, so nobody could look. A guest that will not launch is
				# survivable; an unreachable VM is not. Three legs, each asserted
				# against the realized host units rather than argued in prose.
				#
				# 1. No host mount unit for the guest disk, so nothing on the host's
				#    boot path can be held by it. (gce-image-guest-disk-format asserts
				#    the fstab side; this is the unit side, which is what a
				#    RequiresMountsFor= or an x-systemd.before= would show up in.)
				gdisk=${gceUnits}/cogworx-guest-disk.service
				if grep -Eq '^(Before|RequiredBy|WantedBy)=.*(sshd|local-fs|sysinit|basic|multi-user)' "$gdisk"; then
					echo "FAIL: cogworx-guest-disk orders itself before a host boot target or sshd; a refused or slow carve would then hold the host's own login path, which is the one thing hosted-only may not do:" >&2
					grep -E '^(Before|RequiredBy|WantedBy)=' "$gdisk" >&2
					fails=$((fails + 1))
				fi
				if grep -q 'RequiresMountsFor=' "$gdisk"; then
					echo "FAIL: cogworx-guest-disk declares RequiresMountsFor=; systemd turns that into a hard Requires= on the covering mount unit, so a guest-disk path would become a host boot dependency" >&2
					fails=$((fails + 1))
				fi
				# 2. The failure is a FAILED unit, not a job parked in `activating`.
				#    A Type=oneshot has NO start timeout by default, and this unit is
				#    the one that probes a provider disk that can block in D-state.
				if ! grep -Eq '^TimeoutStartSec=[0-9]' "$gdisk"; then
					echo "FAIL: cogworx-guest-disk has no finite TimeoutStartSec; a Type=oneshot gets no start timeout by default, so a wedged probe leaves the unit ACTIVATING forever -- invisible in systemctl --failed, which is precisely the shape hosted-only is not allowed to have" >&2
					fails=$((fails + 1))
				fi
				# 3. sshd and the control channel do not depend on any of it. sshd is
				#    ordered BEFORE the supervisor (supervisor.nix), never after it,
				#    and nothing here may invert that.
				if grep -Eq '^(After|Requires|Wants)=.*cogworx-(guest-disk|supervisor)' ${gceUnits}/sshd.service; then
					echo "FAIL: sshd depends on the guest-disk or supervisor units; the host's login path must be reachable on exactly the boots where the guest is not" >&2
					grep -E '^(After|Requires|Wants)=' ${gceUnits}/sshd.service >&2
					fails=$((fails + 1))
				fi
				# ...and the refusal is NAMED, not merely visible. supervise.sh tests
				# the guest volume device nodes before the launch and fatals by name
				# onto serial, which is the only channel the control plane has on a VM
				# whose guest never came up. The env it reads is derived from the
				# hosted guest's own autoCreate = false volumes, so renaming a volume
				# group or moving a volume fails the build instead of silently making
				# the message name a path nothing uses.
				sup=${gceUnits}/cogworx-supervisor.service
				if ! grep -qF 'COGWORX_GUEST_VOLUMES' "$sup"; then
					echo "FAIL: cogworx-supervisor is not given COGWORX_GUEST_VOLUMES; an uncarved guest disk would reach serial only as the generic \"sandbox start failed\", and with no fallback runner that message is the whole of an operator's recovery path" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'COGWORX_GUEST_VOLUMES' ${gceSuperviseScript}; then
					echo "FAIL: the realized supervise script never reads COGWORX_GUEST_VOLUMES, so the env above is inert" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'is not a block device; cogworx-guest-disk.service did not carve' ${gceSuperviseScript}; then
					echo "FAIL: the realized supervise script does not fatal by NAME on a missing guest volume; reading the env without acting on it leaves the generic \"sandbox start failed\" as the only symptom" >&2
					fails=$((fails + 1))
				fi
				nvol=0
				for d in ${lib.concatStringsSep " " gceHostedVolumeDevices}; do
					nvol=$((nvol + 1))
					if ! grep -qF "$d" "$sup"; then
						echo "FAIL: cogworx-supervisor's COGWORX_GUEST_VOLUMES does not name $d, one of the hosted guest's autoCreate=false volumes; a boot where that volume is missing would fail without saying which one" >&2
						fails=$((fails + 1))
					fi
				done
				if [ "$nvol" -lt 2 ]; then
					echo "FAIL: only $nvol autoCreate=false volumes were derived from the hosted guest config; expected the data pool and the store overlay, and finding fewer makes the loop above vacuous" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# Serial classification. On GCE `console` is ttyS0, the port
			# Backend.Log reads: provider-retained state outside the VM boundary,
			# readable under a coarser grant than the control channel. cogbox.log
			# carries l7proxy's per-request decisions and the mitmproxy
			# credential-injection addon's output, so it must never land there.
			#
			# Scoped to the cogworx-* units this repository ships. The upstream
			# getty/emergency/rescue units legitimately own a tty and carry no
			# cogbox state; asserting over them would pin unrelated nixpkgs
			# internals and say nothing about this invariant.
			gce-image-serial-classes = pkgs.runCommand "gce-image-serial-classes" { } ''
				fails=0
				for u in ${gceUnits}/cogworx-*.service ${gceUnits}/cogworx-*.timer; do
					[ -f "$u" ] || continue
					if grep -E '^Standard(Output|Error)=' "$u" | grep -Eq 'console|tty'; then
						echo "FAIL: $(basename "$u") sends a standard stream to console/tty:" >&2
						grep -E '^Standard(Output|Error)=' "$u" >&2
						fails=$((fails + 1))
					fi
				done
				sup=${gceUnits}/cogworx-supervisor.service
				if ! grep -qx 'StandardOutput=journal' "$sup"; then
					echo "FAIL: the supervisor is not StandardOutput=journal (journal+console would export the whole runtime log to serial)" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qx 'StandardError=journal' "$sup"; then
					echo "FAIL: the supervisor is not StandardError=journal" >&2
					fails=$((fails + 1))
				fi
				# The tail leg exists, but in its own journal-only unit.
				script=${gceSuperviseScript}
				if grep -v '^[[:space:]]*#' "$script" | grep -q 'cogbox\.log'; then
					echo "FAIL: the supervisor script touches cogbox.log; that leg belongs in cogworx-cogbox-log.service" >&2
					fails=$((fails + 1))
				fi
				logunit=${gceUnits}/cogworx-cogbox-log.service
				if [ ! -e "$logunit" ]; then
					echo "FAIL: cogworx-cogbox-log.service is missing; the runtime log has nowhere to go" >&2
					fails=$((fails + 1))
				elif ! grep -qx 'StandardOutput=journal' "$logunit"; then
					echo "FAIL: cogworx-cogbox-log.service is not journal-only" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The substituter posture, as an assertion rather than prose. In-VM
			# plugin builds process attacker-controlled flakes, so an unsigned
			# substituter here is a cross-instance code-injection path.
			# GUEST/HOST RESOLUTION PARITY, asserted against the realized image.
			#
			# THE PROPERTY. A cogbox guest must resolve names the way the host
			# does, so an internal name resolves to its internal address -- what
			# the local, k8s and container backends get for free because the guest
			# inherits the host's resolver. Here it cannot: at the default
			# `vpcResolver` the host's upstream IS the metadata address, and floor
			# rule 1 denies the passt uid the whole of 169.254.0.0/16 in every
			# mode. The first shape of this backend therefore advertised a PUBLIC
			# resolver to the guest, which answers internal names publicly or not
			# at all.
			#
			# THE MECHANISM, and why every leg below is load-bearing. passt is told
			# to INTERCEPT the guest's queries (`--dns-forward`) and re-emit them
			# to a loopback forwarder on the host (`--dns-host`), which is
			# systemd-resolved's stub. But passt substitutes the --dns-forward
			# address into its DHCP offer only when the nameserver it reads from
			# /etc/resolv.conf is a LOOPBACK one (conf.c add_dns_resolv4). So:
			# resolved must be enabled, resolv.conf must point at its stub,
			# resolved's upstream must be the one `vpcResolver` names, and the units
			# that depend on it must be ordered after it. Miss any one and the guest is
			# handed the host's real resolver, rule 1 drops every query, and the
			# sandbox comes up healthy resolving NOTHING -- precisely the failure
			# mode nothing else in this flake can see.
			gce-image-guest-dns = pkgs.runCommand "gce-image-guest-dns" { } ''
				fails=0
				# 1. The forwarder exists and /etc/resolv.conf names it. This is
				#    the leg that makes passt advertise the forward address at all.
				rc=${gceToplevel}/etc/resolv.conf
				if [ ! -L "$rc" ]; then
					echo "FAIL: /etc/resolv.conf is not the systemd-resolved stub symlink; passt would read the host's real resolver and advertise IT to the guest" >&2
					fails=$((fails + 1))
				elif [ "$(readlink "$rc")" != /run/systemd/resolve/stub-resolv.conf ]; then
					echo "FAIL: /etc/resolv.conf points at $(readlink "$rc"), not resolved's stub" >&2
					fails=$((fails + 1))
				fi
				if [ ! -e ${gceUnits}/systemd-resolved.service ] && [ ! -e ${gceUnits}/sysinit.target.wants/systemd-resolved.service ]; then
					echo "FAIL: systemd-resolved is not enabled; nothing binds the loopback socket passt forwards guest DNS to" >&2
					fails=$((fails + 1))
				fi
				# 2. Its upstream is the one `vpcResolver` names -- the VPC resolver
				#    by default, or another full recursive resolver -- and it is
				#    authoritative for every name. A resolved
				#    that fell back to a public resolver would reproduce the exact
				#    defect this replaced, quietly.
				conf=${gceToplevel}/etc/systemd/resolved.conf
				if ! grep -qx 'DNS=${gceCfg.cogworx.gce.vpcResolver}' "$conf"; then
					echo "FAIL: resolved's upstream is not cogworx.gce.vpcResolver (${gceCfg.cogworx.gce.vpcResolver}); the guest and host would not resolve the same names, and internal names would not resolve internally" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qx 'Domains=~.' "$conf"; then
					echo "FAIL: resolved's pinned upstream is not authoritative for all names (no 'Domains=~.'); some lookups would take another route" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qx 'FallbackDNS=' "$conf"; then
					echo "FAIL: FallbackDNS is not explicitly empty; systemd's compiled-in PUBLIC resolver list would stand behind the configured upstream" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qx 'DNSStubListener=true' "$conf"; then
					echo "FAIL: resolved's stub listener is off; the address passt forwards to would bind nothing" >&2
					fails=$((fails + 1))
				fi
				# 3. The supervisor hands cogbox BOTH halves and the dependent
				#    units are ordered after the forwarder. Ordering is not
				#    cosmetic: before resolved is up /etc/resolv.conf is a DANGLING
				#    symlink and passt advertises no resolver at all, and the
				#    floor's probe 8 connects to the stub.
				sup=${gceUnits}/cogworx-supervisor.service
				if ! grep -q 'COGBOX_HOST_RESOLVER=${gceCfg.cogworx.gce.hostResolver}' "$sup"; then
					echo "FAIL: the supervisor unit does not carry COGBOX_HOST_RESOLVER=${gceCfg.cogworx.gce.hostResolver}; passt would have no pinned forwarding target and cogbox init no --dns-host seed" >&2
					fails=$((fails + 1))
				fi
				for u in ${gceUnits}/cogworx-supervisor.service ${gceUnits}/cogworx-floor.service; do
					if ! grep -q '^After=.*systemd-resolved.service' "$u"; then
						echo "FAIL: $u is not ordered after systemd-resolved.service" >&2
						fails=$((fails + 1))
					fi
				done
				# 4. The supervisor script's own two legs: the --dns-host seed that
				#    keeps the L4 shim from dropping passt's re-emitted query, and
				#    the refusal when resolv.conf does not name the forwarder.
				sh=${gceSuperviseScript}
				if ! grep -qF -- '--dns-host' "$sh"; then
					echo "FAIL: the supervisor does not pass --dns-host to cogbox init; the L4 shim's loopback deny would eat passt's re-emitted guest DNS query and every rules-mode sandbox would resolve nothing" >&2
					fails=$((fails + 1))
				fi
				if ! grep -qF 'RESOLV_CONF' "$sh"; then
					echo "FAIL: the supervisor never checks that resolv.conf names the forwarder; passt would silently advertise the host's real resolver to the guest" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# THE BOOT PATH MUST NOT DEPEND ON DNS, asserted because nothing else
			# can see it. Every leg of the boot/control path names the metadata
			# server by NAME -- the supervisor's readiness write and
			# cogworx-instance read, the control-cert principal fetch, the floor's
			# first-boot self-address fallback, the scrub, the resolver
			# self-destruct belt, supervise.sh's MD base, and
			# google-compute-config.nix's networking.timeServers -- while the only
			# resolver any of them can reach is the SINGLE upstream `vpcResolver`
			# names, which `Domains=~.` makes authoritative for every name with an
			# empty FallbackDNS behind it.
			#
			# The /etc/hosts pin keeps metadata access independent of the
			# configured resolver. This check asserts the realized file because
			# several boot units depend on that property.
			gce-image-metadata-pin = pkgs.runCommand "gce-image-metadata-pin" { } ''
				fails=0
				hosts=${gceToplevel}/etc/hosts
				# The pin itself, asserted on the REALIZED file rather than on the
				# option that wrote it: this image sets networking.hosts and
				# google-compute-config.nix independently ships the same mapping
				# through networking.extraHosts, so what matters is that at least
				# one of them still lands in /etc/hosts.
				if ! grep -E '^[[:space:]]*169\.254\.169\.254[[:space:]]' "$hosts" | grep -qE '(^|[[:space:]])metadata\.google\.internal([[:space:]]|$)'; then
					echo "FAIL: /etc/hosts does not pin metadata.google.internal to 169.254.169.254; metadata access would depend on the configured resolver" >&2
					fails=$((fails + 1))
				fi
				# `metadata` is the short alias google-compute-config.nix also
				# ships; nothing here uses it, but a pin that names only one of the
				# two would be a surprise for an operator debugging by hand.
				if ! grep -E '^[[:space:]]*169\.254\.169\.254[[:space:]]' "$hosts" | grep -qE '(^|[[:space:]])metadata([[:space:]]|$)'; then
					echo "FAIL: /etc/hosts pins metadata.google.internal but not the short 'metadata' alias" >&2
					fails=$((fails + 1))
				fi
				# OUR OWN CONTRIBUTION, asserted separately, and the realized-file
				# legs above are exactly why it has to be: they pass on either
				# source, so deleting this module's `networking.hosts` line stays
				# green on google-compute-config.nix's extraHosts alone. That is the
				# invariant the duplication exists for -- inheriting a boot-critical
				# mapping from another module's default is how it vanishes in a
				# nixpkgs bump -- and it is invisible to a check that only reads the
				# merged output. Same asymmetry gce-image-control-pam closes with an
				# order comparison: the property that matters is not fully
				# observable in the artifact, so assert the source too. Both legs
				# stay: this one alone would pass an image whose /etc/hosts was
				# emptied downstream.
				pinned='${lib.concatStringsSep " " (gceCfg.networking.hosts."169.254.169.254" or [ ])}'
				for name in metadata.google.internal metadata; do
					case " $pinned " in
						*" $name "*) ;;
						*) echo "FAIL: this module's own networking.hosts no longer pins '$name' to 169.254.169.254 (it carries: $pinned); the realized /etc/hosts would then rest entirely on google-compute-config.nix's extraHosts default, which is not ours to rely on" >&2
							fails=$((fails + 1)) ;;
					esac
				done
				# THE OTHER HALF, and the one a reader of /etc/hosts alone would
				# miss: nss reaches `files` only when resolved is UNAVAIL (this
				# image's order is
				# `hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns`),
				# so on a HEALTHY VM the component that has to honour the pin is
				# systemd-resolved, which does so by reading /etc/hosts itself
				# (ReadEtcHosts, default yes). Turning that off would undo the pin
				# while leaving /etc/hosts looking correct. systemd's
				# parse_boolean() also takes `n` and `f`, so the spellings are
				# matched, not just the words. NOT covered: a drop-in under
				# resolved.conf.d/, which this image does not use.
				rconf=${gceToplevel}/etc/systemd/resolved.conf
				if grep -qiE '^[[:space:]]*ReadEtcHosts[[:space:]]*=[[:space:]]*(n|no|f|false|off|0)[[:space:]]*$' "$rconf"; then
					echo "FAIL: resolved is configured with ReadEtcHosts off; the /etc/hosts metadata pin would be bypassed on every healthy boot, since nss consults 'files' only when resolved is unavailable" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			gce-image-nix-conf = pkgs.runCommand "gce-image-nix-conf" { } ''
				fails=0
				conf=${gceToplevel}/etc/nix/nix.conf
				if grep -Eq '^require-sigs[[:space:]]*=[[:space:]]*false' "$conf"; then
					echo "FAIL: require-sigs is disabled in the image's nix.conf" >&2
					fails=$((fails + 1))
				fi
				subs=$(grep -E '^substituters[[:space:]]*=' "$conf" | cut -d= -f2- || true)
				for s in $subs; do
					case "$s" in
						https://cache.nixos.org|https://cache.nixos.org/|https://cache.numtide.com|https://cache.numtide.com/) ;;
						*) echo "FAIL: unexpected substituter '$s' in the image's nix.conf" >&2; fails=$((fails + 1)) ;;
					esac
				done
				# A trusted-substituters entry lets an unprivileged caller opt into a
				# cache the operator never vetted.
				extra=$(grep -E '^trusted-substituters[[:space:]]*=' "$conf" | cut -d= -f2- || true)
				if [ -n "$(echo "$extra" | tr -d '[:space:]')" ]; then
					echo "FAIL: trusted-substituters is non-empty: $extra" >&2
					fails=$((fails + 1))
				fi
				for key in 'cache.nixos.org-1:' 'niks3.numtide.com-1:'; do
					if ! grep -E '^trusted-public-keys[[:space:]]*=' "$conf" | grep -qF "$key"; then
						echo "FAIL: no trusted-public-key for $key; its substituter would fail closed or be unsigned" >&2
						fails=$((fails + 1))
					fi
				done
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The control CA is a BAKE-TIME input with no usable default, and the
			# runbook has to have a supported way to supply it. Without one an
			# operator builds `.#gce-image` literally, publishes an image whose
			# sshd trusts no CA, and every certificate cogworxd mints is refused
			# -- every instance wedges in Booting with a build-time warning as the
			# only diagnostic. The existing sshd check cannot see this: it greps
			# for `TrustedUserCAKeys`, which is set unconditionally regardless of
			# whether the file it points at has any content.
			gce-image-control-ca = pkgs.runCommand "gce-image-control-ca" {
				bakedCA = gceBakedCAText;
				defaultCA = gceDefaultCAText;
				bakedExtraCA = gceBakedExtraCAText;
			} ''
				fails=0
				# The DEFAULT config is fail-closed, deliberately: an empty file
				# admits nothing. This is asserted so that "the bake step is
				# optional" can never become true by accident.
				if [ -n "$(printf '%s' "$defaultCA" | tr -d '[:space:]')" ]; then
					echo "FAIL: the default gce host bakes a control CA; the fail-closed default is the only thing making the bake step mandatory" >&2
					fails=$((fails + 1))
				fi
				# The documented seam actually reaches sshd's TrustedUserCAKeys.
				case "$bakedCA" in
					*"${gceBakeCAKey}"*) ;;
					*) echo "FAIL: lib.mkGceHost's controlCAPublicKey override does not reach /etc/ssh/cogworx-control-ca.pub; the runbook's bake step would silently produce a CA-less image" >&2
						fails=$((fails + 1)) ;;
				esac
				# AND THE MERGE-ABLE SEAM, which exists because the alternative
				# regressed once: TrustedUserCAKeys is forced, so a composed
				# profile's own definition there loses with no error and no log
				# line. extraTrustedUserCAKeys is where such a CA is meant to land,
				# and it is only useful if BOTH keys survive into the one file sshd
				# reads -- the control CA it must never lose, plus the contributed
				# one, on separate lines (`sshkey_in_file` reads line by line).
				case "$bakedExtraCA" in
					*"${gceBakeCAKey}"*) ;;
					*) echo "FAIL: extraTrustedUserCAKeys displaced the baked control CA; the control channel would trust the wrong CA and every certificate cogworxd mints would be refused" >&2
						fails=$((fails + 1)) ;;
				esac
				case "$bakedExtraCA" in
					*"${gceBakeExtraCAKey}"*) ;;
					*) echo "FAIL: cogworx.gce.extraTrustedUserCAKeys does not reach /etc/ssh/cogworx-control-ca.pub; a composed profile's user CA has nowhere to land and would be dropped silently by the mkForce on TrustedUserCAKeys" >&2
						fails=$((fails + 1)) ;;
				esac
				if [ "$(printf '%s' "$bakedExtraCA" | grep -c .)" != 2 ]; then
					echo "FAIL: the baked CA file holds $(printf '%s' "$bakedExtraCA" | grep -c .) key lines, expected 2 (control CA + one contributed); a joined or blank-padded file is not what sshd parses" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The DNS upstream has to be a DELIBERATE bake-time choice, and this
			# check exists because one bake proved it was not. An image published
			# WITHOUT the operator-side module that supplies a full recursive
			# resolver's address left `cogworx.gce.vpcResolver` at its default: every
			# sandbox created from it came up healthy resolving neither internal
			# names nor public ones a peering zone shadowed, and nothing surfaced it.
			# Every existing gce-image-* check passed on that image --
			# gce-image-guest-dns compares resolved's upstream against the option, so
			# a fallen-back option agrees with itself.
			#
			# The guard is an assertion in the host module rather than a check here,
			# and it has to be: an assertion in the operator module would vanish
			# together with the module whose absence IS the bug. What this check adds
			# is the part an assertion cannot demonstrate about itself -- that it
			# fires, that both documented ways out satisfy it, and that it leaves the
			# CA-less default host alone.
			gce-image-resolver-bake = pkgs.runCommand "gce-image-resolver-bake" {
				defaultBakeEvals = lib.boolToString gceResolverDefaultBakeEvals;
				pointedBakeEvals = lib.boolToString gceResolverPointedBakeEvals;
				affirmedBakeEvals = lib.boolToString gceResolverAffirmedBakeEvals;
				defaultHostEvals = lib.boolToString gceResolverDefaultHostEvals;
			} ''
				fails=0
				# 1. THE FIRING LEG, and the one that keeps the other three from
				#    being decoration: a publishable bake (control CA set) that
				#    left the upstream at its default and did not affirm it must
				#    not evaluate at all.
				if [ "$defaultBakeEvals" != false ]; then
					echo "FAIL: a CA-baked host with cogworx.gce.vpcResolver left at its default still evaluates; the publishability assertion is gone or unreachable, so a bake composed without the module that supplies a full recursive resolver publishes silently, resolving neither internal names nor peering-shadowed public ones" >&2
					fails=$((fails + 1))
				fi
				# 2. Pointing the upstream elsewhere is the fix the assertion's
				#    message names, so it must evaluate -- otherwise the guard is
				#    a ban on baking at all.
				if [ "$pointedBakeEvals" != true ]; then
					echo "FAIL: a CA-baked host with cogworx.gce.vpcResolver pointed at another resolver does not evaluate; the assertion is comparing the wrong thing and no image could be baked" >&2
					fails=$((fails + 1))
				fi
				# 3. And so must the acknowledgement, because the link-local
				#    default is a supported configuration, not a defect.
				if [ "$affirmedBakeEvals" != true ]; then
					echo "FAIL: a CA-baked host with cogworx.gce.allowMetadataResolver = true does not evaluate; the affirmation the assertion's own message tells an operator to set does not work" >&2
					fails=$((fails + 1))
				fi
				# 4. The CA-less default host is NOT publishable and must stay
				#    evaluable regardless of its upstream: `packages.gce-image`
				#    builds it, and so does every other check here.
				if [ "$defaultHostEvals" != true ]; then
					echo "FAIL: the default (CA-less) gce host no longer evaluates; the publishability gate has widened past a bake meant for publication and packages.gce-image is dead" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The control account's local PAM rule must precede any remote
			# directory-backed account module added through extraModules.
			#
			# THE ORDER IS NOT ASSERTED HERE, on purpose. It is derived in the
			# module from the minimum order of every other account rule, and the
			# comparison lives in that module's `assertions` -- which is where it
			# has to be, because the config that ships is an operator bake with a
			# profile composed in and a flake check can only ever see the default
			# host. An assertion travels into that build; this derivation cannot.
			# What is left here is everything the assertion does NOT cover: the
			# rendered SHAPE of the rule, which no option comparison can see.
			gce-image-control-pam = pkgs.runCommand "gce-image-control-pam" {
				pamSshd = gcePamSshd;
			} ''
				fails=0
				printf '%s' "$pamSshd" > pam.sshd
				acct=$(grep '^account ' pam.sshd || true)
				first=$(printf '%s\n' "$acct" | head -n1)
				# FIRST, or it is not an exemption: a `default=bad`/`die` module
				# above it decides the phase before it is reached.
				case "$first" in
					*'pam_succeed_if.so quiet user = ${gceCfg.cogworx.gce.controlUser}'*) ;;
					*) echo "FAIL: the first sshd account rule is not the control user's local short-circuit, it is: $first" >&2
						echo "      a directory-backed account module above it refuses the control certificate whenever its daemon is down" >&2
						fails=$((fails + 1)) ;;
				esac
				# `sufficient` is what ENDS the phase. `optional`/`required` here
				# would let the stack carry on into the directory module and lose.
				case "$first" in
					'account sufficient '*) ;;
					*) echo "FAIL: the control user's account rule is not 'sufficient', so the account phase does not end at it: $first" >&2
						fails=$((fails + 1)) ;;
				esac
				# Matching on the PAM user NAME, not on uid: a uid comparison makes
				# pam_succeed_if resolve the account through NSS, which is the same
				# directory this rule exists to stay independent of.
				case "$first" in
					*' uid '*) echo "FAIL: the control user's account rule matches on uid, which sends pam_succeed_if through an NSS lookup -- the exemption must not depend on the directory it exempts" >&2
						fails=$((fails + 1)) ;;
				esac
				# And pam_unix must still stand behind it, so a NON-control user is
				# decided by a real module rather than by an empty stack.
				if ! printf '%s\n' "$acct" | grep -q '^account required .*pam_unix.so'; then
					echo "FAIL: the sshd account stack has no 'required pam_unix' behind the exemption" >&2
					fails=$((fails + 1))
				fi
				# The ACCOUNT stack is the only one this rule may appear in. A copy
				# that also landed in auth or session would be a second, unreviewed
				# exemption on a phase whose semantics are not the one reasoned
				# about here -- and it is the kind of thing a "make it symmetric"
				# edit adds. The order relationship is asserted in the module (see
				# above); this is the shape half.
				if [ "$(grep -c 'pam_succeed_if.so quiet user = ${gceCfg.cogworx.gce.controlUser}' pam.sshd)" != 1 ]; then
					echo "FAIL: the control user's pam_succeed_if rule appears $(grep -c 'pam_succeed_if.so quiet user = ${gceCfg.cogworx.gce.controlUser}' pam.sshd) times in the sshd PAM stack, expected exactly 1 (account only)" >&2
					fails=$((fails + 1))
				fi
				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The wrapper's --set / --set-default split, exercised rather than
			# grepped. gce-image-unit-ordering above only proves the three NAMES
			# appear in the wrapper, and that is exactly the check that passed while
			# the entire control-verb surface would fail because NixOS sets
			# `security.pam.services.sshd.startSession = true` whenever sshd uses PAM,
			# so pam_systemd exports XDG_RUNTIME_DIR=/run/user/0 into every
			# `ssh <vm> cogbox <verb>` BEFORE the wrapper runs, and --set-default
			# cannot override an already-set variable. cogbox then looked for
			# /run/user/0/cogbox-<name>/pid while the supervisor's runtime lives under
			# /run/cogbox, so `cogbox status` answered 3 (stopped) on a HEALTHY
			# sandbox and Terminal, Console, the liveness probe and every
			# rule/secret/plugin mutation went down behind it.
			#
			# So this runs the REAL wrapper with the PAM value already in the
			# environment, against a stub standing in for the cogbox binary, and pins
			# BOTH directions: XDG_RUNTIME_DIR must be forced, and the other two must
			# stay overridable (they are not set by anything in an ssh session, and a
			# break-glass operator pointing cogbox at another state tree is the reason
			# they are defaults). Flipping either is a decision, not a reflex -- if you
			# mean it, update the per-variable reasoning in gce/cogbox-host.nix too.
			gce-cogbox-wrapper-env = pkgs.runCommand "gce-cogbox-wrapper-env" {
				nativeBuildInputs = with pkgs; [ bash coreutils gnused gnugrep ];
			} ''
				fails=0
				sed 's|^exec .*|exec ${gceWrapperEnvStub} "$@"|' \
					${gceCogboxWrapper}/bin/cogbox > wrapper
				chmod +x wrapper
				if ! grep -q '${gceWrapperEnvStub}' wrapper; then
					echo "FAIL: could not retarget the wrapper's exec line at the stub; this check is vacuous" >&2
					exit 1
				fi
				val() { grep "^$1=" | cut -d= -f2-; }

				# 1. The PAM value must lose.
				got=$(XDG_RUNTIME_DIR=/run/user/0 ./wrapper | val XDG_RUNTIME_DIR)
				if [ "$got" != /run/cogbox ]; then
					echo "FAIL: the wrapper did not force XDG_RUNTIME_DIR: with pam_systemd's /run/user/0 already set, cogbox saw '$got'" >&2
					echo "      every control verb would address /run/user/0/cogbox-<name> while the supervisor runs under /run/cogbox" >&2
					fails=$((fails + 1))
				fi

				# 2. With nothing set, all three still carry the baked paths -- the
				#    original reason the wrapper exists (a bare `ssh host cmd` sources
				#    no profile, and cogbox with no config/data path exits 66).
				baked=$(env -u XDG_CONFIG_HOME -u COGBOX_DATA -u XDG_RUNTIME_DIR ./wrapper)
				for pair in \
					'XDG_CONFIG_HOME=${gceCfg.cogworx.gce.stateDir}/config' \
					'COGBOX_DATA=${gceCfg.cogworx.gce.stateDir}/data/cogbox' \
					'XDG_RUNTIME_DIR=/run/cogbox'; do
					if ! printf '%s\n' "$baked" | grep -qxF "$pair"; then
						echo "FAIL: an empty environment did not yield $pair; got: $(printf '%s' "$baked" | tr '\n' ' ')" >&2
						fails=$((fails + 1))
					fi
				done

				# 3. The two that PAM does not own stay overridable.
				got=$(XDG_CONFIG_HOME=/var/empty/alt-config ./wrapper | val XDG_CONFIG_HOME)
				if [ "$got" != /var/empty/alt-config ]; then
					echo "FAIL: XDG_CONFIG_HOME is now forced ('$got'); nothing in an ssh session sets it, and forcing it removes the break-glass override" >&2
					fails=$((fails + 1))
				fi
				got=$(COGBOX_DATA=/var/empty/alt-data ./wrapper | val COGBOX_DATA)
				if [ "$got" != /var/empty/alt-data ]; then
					echo "FAIL: COGBOX_DATA is now forced ('$got'); the name is cogbox-private, so no PAM module or unit can be setting it" >&2
					fails=$((fails + 1))
				fi

				# 4. The forced value must be the SAME runtime dir the supervisor uses.
				#    Neither side can detect a mismatch alone.
				rt=$(env -u XDG_RUNTIME_DIR ./wrapper | val XDG_RUNTIME_DIR)
				if ! grep -qF "XDG_RUNTIME_DIR=$rt" ${gceUnits}/cogworx-supervisor.service; then
					echo "FAIL: the wrapper forces XDG_RUNTIME_DIR=$rt but the supervisor unit does not use it; the control channel and the supervisor would address different sandboxes" >&2
					fails=$((fails + 1))
				fi

				# 5. A control-channel exec must learn the proxy uid split, and learn
				#    the SAME one the supervisor exports. This image runs the L7 proxy
				#    on its own uid, so the inject render has to grant that identity
				#    read on the cred files it names (rules/credgrant.zig) -- and binds
				#    arrive on THIS path (`cogbox secret add -n` + `secret reload`),
				#    which carries no unit Environment=. Unset here means the boot
				#    render grants and every later bind does not: a Claude connect on a
				#    running sandbox stays dead until a restart. A DIFFERENT value here
				#    means the two renders grant to two different groups, which is the
				#    same failure with an extra step.
				runas=$(env -u COGBOX_PROXY_RUNAS ./wrapper | val COGBOX_PROXY_RUNAS)
				if [ "$runas" = "<unset>" ] || [ -z "$runas" ]; then
					echo "FAIL: the wrapper exports no COGBOX_PROXY_RUNAS, so a control-channel bind cannot grant the dropped L7 proxy read access to the credential it just bound" >&2
					fails=$((fails + 1))
				elif ! grep -qF "COGBOX_PROXY_RUNAS=$runas" ${gceUnits}/cogworx-supervisor.service; then
					echo "FAIL: the wrapper exports COGBOX_PROXY_RUNAS=$runas but the supervisor unit exports something else; the boot render and the bind render would grant to different groups" >&2
					fails=$((fails + 1))
				fi

				[ "$fails" -eq 0 ] || exit 1
				touch $out
			'';

			# The supervisor's orderings and refusals, none of which are visible in
			# the unit file. See tests/test_supervise.sh for what each case guards.
			gce-supervise-tests = pkgs.runCommand "gce-supervise-tests" {
				nativeBuildInputs = with pkgs; [ bash coreutils gawk gnugrep ];
			} ''
				export HOME=$TMPDIR
				bash ${./tests/test_supervise.sh} ${./gce/supervise.sh}
				touch $out
			'';

			# The floor's RENDERED ruleset, its probe POLARITIES, and its live
			# PACKET behaviour. None of the three is visible in the unit file, and
			# none is something a grep over a printf format string can really
			# prove, so this runs the real install leg against a file:// metadata
			# tree and asserts on the nft file it writes, runs the real verify leg
			# on a machine with no floor loaded at all, and finally loads the
			# rendered ruleset into a throwaway user+network namespace and probes
			# it with a REAL LISTENER bound on an exempt port. The cases cover a
			# rule-2 deny with no skuid match, an exception probe that needs a
			# listener before the supervisor starts passt, narrowing to named
			# uids, and a deny that eats a real listener's SYN-ACK.
			# util-linux/nftables/iproute2
			# are for that last section, which SKIPS where the kernel cannot host
			# it. See tests/test_floor.sh.
			# systemd is here for the same reason the verifier reaches for it:
			# section 5's rule-3 cases need a REAL listener on loopback, and
			# systemd-socket-activate is already in this image's closure, so
			# testing the floor adds no network utility to it.
			gce-floor-tests = pkgs.runCommand "gce-floor-tests" {
				nativeBuildInputs = with pkgs; [ bash coreutils gnugrep util-linux nftables iproute2 systemd ];
			} ''
				export HOME=$TMPDIR
				bash ${./tests/test_floor.sh} ${gceFloorInstall} ${gceFloorVerify}
				touch $out
			'';
		});

		nixosConfigurations = lib.listToAttrs (map (system: {
			name = configName system;
			value = mkMicrovm system "cogbox" {
				vcpu = 16;
				mem = 32768;
				extraModules = cogboxModules system {};
			};
		}) supportedSystems)
		# The HOSTED-profile guest: identical modules, cogbox.storage.profile =
		# "hosted". It has to be a separate nixosConfiguration rather than a
		# host-side or launch-time switch, because packages.cogbox bakes the guest
		# runner and the GCE image bakes packages.cogbox -- mkGceHost's extraModules
		# configure the HOST system and cannot reach the guest config at all. The
		# GCE host half selects this runner; the cogbox-guest-* checks assert its
		# realized fstab.
		// lib.listToAttrs (map (system: {
			name = "${configName system}-hosted";
			value = mkMicrovm system "cogbox" {
				vcpu = 16;
				mem = 32768;
				extraModules = cogboxModules system {} ++ [ { cogbox.storage.profile = "hosted"; } ];
			};
		}) supportedSystems)
		# The CONTAINER config exposed as a buildable nixosConfiguration so the
		# per-instance FULL toplevel builds via `--override-input userExtensions`
		# (prebuildToplevelLocal / agentInit's realise target). SAME args as the
		# let-bound containerSystem the agent-image bakes, so the base (no-plugin)
		# toplevel here is the SAME derivation agentInit falls back to. This MUST be
		# a separate attr from the VM `cogbox-<arch>`: `system.build.toplevel` is
		# target-DEPENDENT -- the VM config's toplevel is a QEMU-guest system that
		# cannot boot as an unprivileged container (unlike the target-independent brain).
		// lib.listToAttrs (map (system: {
			name = "${configName system}-container";
			value = mkContainer system "cogbox" {
				extraModules = cogboxModules system { target = "container"; };
			};
		}) supportedSystems) // {
			# The GCE backend HOST system (see mkGceHost). x86_64 only: GCE
			# nested virtualization is offered on Intel machine series only
			# so there is no aarch64/riscv64 twin to generate.
			# `packages.gce-image` builds this config's googleComputeImage; the
			# gce-image-* checks assert its closure, userland and unit graph
			# without needing the image itself.
			cogbox-x86_64-gce = mkGceHost "x86_64-linux" { };

			# Test fixture used by tests/cogbox.nix Phase E. Pre-builds
			# a runner whose closure includes pkgs.hello, so the offline
			# NixOS test machine has the cached output of the
			# user-customised runner that Phase E reconstructs at runtime
			# via `nix run --override-input userExtensions ...`. The
			# `userExt` parameter inserts the hello-adding module in the
			# same list position userExtensions normally occupies, so the
			# resulting .drvPath is byte-identical to the runtime path.
			cogbox-x86_64-test-hello = mkMicrovm "x86_64-linux" "cogbox" {
				vcpu = 16;
				mem = 32768;
				extraModules = cogboxModules "x86_64-linux" {
					userExt = { pkgs, ... }: {
						environment.systemPackages = [ pkgs.hello ];
						system.extraDependencies = [ pkgs.hello ];
					};
				};
			};
			# Same idea for Phase Q (`cogbox plugin`): the generated
			# composition flake wraps the plugin modules and the (no-op
			# scaffold) user module in an `imports` list. That nesting
			# changes module flattening order, which changes
			# environment.systemPackages ORDER, which changes the
			# system-path drv -- so the flat test-hello fixture above does
			# NOT cache-hit for the plugin path. Pre-build the runner with
			# the exact same nested shape the composition produces: two
			# plugins from one flake (default = hello, extra = etc marker)
			# plus the scaffold's no-op module, in add order, user last -- each
			# behind the `_file` provenance wrapper compose.zig now emits. The
			# wrapper carries no config of its own, so it does not perturb
			# definition order, but keeping the two shapes identical is what
			# makes this prebuild a real cache hit.
			cogbox-x86_64-test-plugin = mkMicrovm "x86_64-linux" "cogbox" {
				vcpu = 16;
				mem = 32768;
				extraModules = cogboxModules "x86_64-linux" {
					userExt = {
						imports = [
							{ _file = "p-testhello"; imports = [ ({ pkgs, ... }: {
								environment.systemPackages = [ pkgs.hello ];
								system.extraDependencies = [ pkgs.hello ];
							}) ]; }
							{ _file = "p-testextra"; imports = [ ({ ... }: {
								environment.etc."cogbox-test-extra".text = "extra\n";
							}) ]; }
							{ _file = "cogbox-user"; imports = [ ({ pkgs, lib, ... }: { }) ]; }
						];
					};
				};
			};
			# Fixture: a populated cogbox.* config, for the brain-materialization
			# VM test (Phase brain) and local brain builds.
			cogbox-x86_64-brain-fixture = mkMicrovm "x86_64-linux" "cogbox" {
				vcpu = 4;
				mem = 4096;
				extraModules = cogboxModules "x86_64-linux" {
					userExt = { pkgs, lib, ... }: {
						cogbox = {
							contents = ./tests/fixtures/brain-plugin/contents;
							mcp.demo-mcp = { command = "demo-mcp-server"; args = [ "--stdio" ]; env = { DEMO_MODE = "ro"; }; };
							env = { DEMO_URL = "http://demo.example.com"; };
							# Plugin tools -> cogbox-brain's $out/bin (prepended to the
							# container PATH). hello is the smallest real package; the brain
							# build below asserts $out/bin/hello resolves.
							packages = [ pkgs.hello ];
							settings.claude-code = { model = "claude-opus-4-8"; };
							settings.opencode = { model = "anthropic/claude-opus-4-8"; };
							hooks.SessionStart = "true";
						};
					};
				};
			};
			# CONTAINER analogue of the brain fixture above. The brain output is
			# target-INDEPENDENT (identical runCommandLocal drv in both configs),
			# but the container brain-materialize oneshot rebuilds it by evaluating
			# THIS `-container` config -- so the container-brain-command check builds
			# it here to exercise exactly the guest-half delivery path (commands /
			# packages) when the boot rebuild evaluates the container config.
			cogbox-x86_64-brain-fixture-container = mkContainer "x86_64-linux" "cogbox" {
				extraModules = cogboxModules "x86_64-linux" {
					target = "container";
					userExt = { pkgs, lib, ... }: {
						cogbox = {
							contents = ./tests/fixtures/brain-plugin/contents;
							mcp.demo-mcp = { command = "demo-mcp-server"; args = [ "--stdio" ]; env = { DEMO_MODE = "ro"; }; };
							env = { DEMO_URL = "http://demo.example.com"; };
							packages = [ pkgs.hello ];
							settings.claude-code = { model = "claude-opus-4-8"; };
							settings.opencode = { model = "anthropic/claude-opus-4-8"; };
							hooks.SessionStart = "true";
						};
					};
				};
			};

		};
	};
}
