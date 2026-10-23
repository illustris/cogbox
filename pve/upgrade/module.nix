# In-place system upgrades of a PVE host VM: what every system generation of
# the image carries so cogworxd can move a sandbox VM from one generation to
# the next, try it once, and commit or fall back (docs/pve-system-upgrade.md).
#
#   - the tool, cogworx-pve-upgrade, in environment.systemPackages: cogworxd
#     runs it by store path, <system>/sw/bin/cogworx-pve-upgrade, over the
#     control channel. Nothing on the VM runs it;
#   - the compat doc, <toplevel>/cogworx-pve-compat.json, built from this
#     evaluated configuration (compat_doc.py normalizes it);
#   - the GRUB guard (grub-guard.cfg) as boot.loader.grub.extraConfig, which
#     decides at boot time whether the pending one-shot entry may run;
#   - panic=10 boot.panic_on_fail, so a candidate whose stage 1 fails reboots
#     onto entry 0 instead of hanging;
#   - the gce nix-gc unit wrapped in the upgrade lock, so a collection never
#     runs while the tool holds it, and the lock file created root-owned 0600
#     at boot.
#
# GENERIC AND STANDALONE: no cogbox package, no `self`, no `inputs`. pve-host.nix
# imports it and supplies the host contract from cogbox's options; the VM test
# imports it with image.nix alone and supplies its own.
{
	config,
	lib,
	pkgs,
	...
}:
let
	cfg = config.cogworx.pve;
	up = cfg.upgrade;
	# bootProof and stateFormat have one source; the compat doc never restates
	# them.
	proto = import ../../gce/protocol.nix;

	# The gce collector's program, taken from the module itself so this file
	# never edits gce/nix-gc.nix. The function never reads `config`.
	gceGc = (import ../../gce/nix-gc.nix { inherit config lib pkgs; }).config.systemd.services.cogworx-nix-gc.serviceConfig.ExecStart;

	package = pkgs.callPackage ./package.nix {
		nix = config.nix.package;
		systemd = config.systemd.package;
		inherit (up) minFreeBytes reserveBytes;
	};

	nixSettings = config.nix.settings;
	raw = {
		schema = 1;
		kind = "cogworx-pve-system";
		toolProto = 1;
		txnSchema = 1;
		inherit (proto) bootProof stateFormat;
		bootConfigVersions = [ 1 ];
		# What this generation's metadata emulator tolerates in the SMBIOS
		# blob, not a GRUB capability: the guard belongs to the pinned base.
		smbiosSelector = "S";
		guestAttrsVersion = 1;
		release = cfg.release;
		inherit (up.hostContract) controlCAKeys controlPlaneCIDRs controlUser hostKeyPath stateDevice guestDevice interface;
		substituters = nixSettings.substituters ++ (nixSettings.extra-substituters or [ ]);
		trustedPublicKeys = nixSettings.trusted-public-keys ++ (nixSettings.extra-trusted-public-keys or [ ]);
		specialisations = lib.attrNames config.specialisation;
		bootloader = {
			installer = "${config.system.build.installBootLoader}";
			grub = "${config.system.build.grub}";
			devices = config.boot.loader.grub.devices;
			distroName = config.system.nixos.distroName;
			guard = if lib.hasInfix "# cwx-guard-v1" config.boot.loader.grub.extraConfig then "cwx-guard-v1" else null;
		};
	};
	compatDoc = pkgs.runCommand "cogworx-pve-compat.json" {
		nativeBuildInputs = [ pkgs.python3 ];
		passAsFile = [ "doc" ];
		doc = builtins.toJSON raw;
	} "python3 -I ${./compat_doc.py} \"$docPath\" > $out";

	toplevelName = "${config.system.name}-${config.system.nixos.label}";
	# The tool's distro grammar (distro_ok): it pins this name and parses
	# grub.cfg with it.
	distroName = config.system.nixos.distroName;
	distroOk = builtins.match "[ -~]{1,64}" distroName != null
		&& !(lib.any (c: lib.elem c [ ">" "\"" "\\" "$" "'" ]) (lib.stringToCharacters distroName));
	guardText = builtins.readFile ./grub-guard.cfg;
in
{
	imports = [
		# Deduplicated by path when gce/cogbox-host.nix imports it too.
		../../gce/nix-gc.nix
	];

	options.cogworx.pve = {
		release = lib.mkOption {
			type = lib.types.nullOr (lib.types.submodule {
				options = {
					id = lib.mkOption {
						type = lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9._-]{0,63}";
						description = "The release identifier cogworxd shows and records for this system generation.";
					};
					builtAt = lib.mkOption {
						type = lib.types.strMatching "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z";
						description = "When the release was built, UTC, as YYYY-MM-DDTHH:MM:SSZ.";
					};
				};
			});
			default = null;
			example = {
				id = "2026.10.1";
				builtAt = "2026-10-18T00:00:00Z";
			};
			description = ''
				This system generation as an in-place upgrade target. It is
				written into the compat doc (<toplevel>/cogworx-pve-compat.json),
				and the upgrade tool refuses a target whose release is null, so
				null (the default) means "not an upgrade target": a dev build
				never reaches a sandbox VM by upgrade.
			'';
		};

		upgrade = {
			hostContract = lib.mkOption {
				internal = true;
				description = ''
					The host values written into the compat doc, which the
					upgrade tool (rule vi) and cogworxd compare across system
					generations. No defaults: a composition that imports this
					module must supply every field, or evaluation fails.
				'';
				type = lib.types.submodule {
					options = {
						controlCAKeys = lib.mkOption {
							type = lib.types.listOf lib.types.str;
							description = "The control CA public keys sshd trusts, one `<type> <blob> [comment]` per entry.";
						};
						controlPlaneCIDRs = lib.mkOption {
							type = lib.types.listOf lib.types.str;
							description = "Where cogworxd's control channel comes from.";
						};
						controlUser = lib.mkOption {
							type = lib.types.str;
							description = "The user cogworxd's control connections log in as.";
						};
						hostKeyPath = lib.mkOption {
							type = lib.types.str;
							description = "The sshd ed25519 host key file.";
						};
						stateDevice = lib.mkOption {
							type = lib.types.str;
							description = "The state disk's device path.";
						};
						guestDevice = lib.mkOption {
							type = lib.types.str;
							description = "The guest disk's device path.";
						};
						interface = lib.mkOption {
							type = lib.types.str;
							description = "The VM's one network interface.";
						};
					};
				};
			};

			minFreeBytes = lib.mkOption {
				type = lib.types.ints.positive;
				internal = true;
				default = 12 * 1024 * 1024 * 1024;
				description = "The fetch headroom floor in bytes: free space on /nix/store that must remain after a fetch. checks.nix pins it to gce/nix-gc.nix's floor.";
			};

			reserveBytes = lib.mkOption {
				type = lib.types.ints.unsigned;
				internal = true;
				default = 4 * 1024 * 1024 * 1024;
				description = "The fixed reserve in the fetch headroom formula, in bytes.";
			};

			package = lib.mkOption {
				type = lib.types.package;
				internal = true;
				readOnly = true;
				description = "The upgrade tool package (set by this module; read by checks and the VM test).";
			};

			compatDoc = lib.mkOption {
				type = lib.types.package;
				internal = true;
				readOnly = true;
				description = "The compat doc derivation (set by this module; read by the compat-doc check).";
			};
		};
	};

	config = {
		cogworx.pve.upgrade.package = package;
		cogworx.pve.upgrade.compatDoc = compatDoc;

		environment.systemPackages = [ package ];

		# A regular file in the toplevel, not a symlink: the tool reads
		# <target>/cogworx-pve-compat.json from a fetched target before any
		# profile points at it.
		system.systemBuilderCommands = "cp ${compatDoc} $out/cogworx-pve-compat.json\n";

		boot.loader.grub.extraConfig = guardText;

		# Per system generation, because only kernel, initrd and kernel-params
		# come from a generation (the boot loader belongs to the base). Under
		# the systemd stage 1, boot.panic_on_fail turns a failed initrd into a
		# kernel crash, and only panic=10 on the command line turns that crash
		# into a reboot (the kernel.panic sysctl applies in stage 2 only).
		boot.kernelParams = [ "panic=10" "boot.panic_on_fail" ];

		# A collection never runs while the tool holds its lock (a fetch's
		# substituted paths are unrooted until it finishes). A skipped run exits
		# 75 and is a success; the next timer run collects.
		systemd.services.cogworx-nix-gc.serviceConfig = {
			ExecStart = lib.mkForce "${pkgs.util-linux}/bin/flock --nonblock --conflict-exit-code 75 /run/cogworx-pve-upgrade.lock ${gceGc}";
			SuccessExitStatus = "75";
		};

		# The lock file exists root-owned 0600 from early boot (tmpfiles runs
		# in sysinit, before any timer or control connection). Otherwise its
		# first opener creates it, flock(1) above with 0644, and flock(2)
		# works on a read-only descriptor, so any local uid could hold the
		# lock forever: every verb busy, every collection skipped.
		systemd.tmpfiles.rules = [ "f /run/cogworx-pve-upgrade.lock 0600 root root -" ];

		assertions = [
			{
				# Checked on the name's parts, not on the toplevel itself (that
				# would recurse through the assertions).
				assertion = builtins.match "[A-Za-z0-9._+-]{1,200}" toplevelName != null;
				message = "cogworx.pve.upgrade: the toplevel name nixos-system-${toplevelName} does not match the upgrade tool's system path grammar (nixos-system-[A-Za-z0-9._+-]{1,200}). An impure NIXOS_LABEL with characters such as ':' (the label type allows them) mints a system the tool refuses to fetch, arm or commit.";
			}
			{
				# grub.nix substitutes this name into install-grub.pl (every
				# title: entry 0, the "<name> - Profile '...'" submenus and
				# their entries) and the compat doc records it, so the pinned
				# installer and the tool's parse agree on any name; but the
				# tool refuses to pin a name outside its grammar, which would
				# make the first fetch or abort of every clone exit 69.
				assertion = distroOk;
				message = "cogworx.pve.upgrade: system.nixos.distroName (${distroName}) is not a name the upgrade tool can pin: 1-64 printable ASCII characters, none of > \" \\ $ '. install-grub.pl puts it in every GRUB title, and the tool would refuse to pin the bootloader on every clone.";
			}
			{
				# A composition that replaces environment.systemPackages
				# (mkForce) drops the tool. Committed, such a generation is
				# the only system whose tool may abort, release or move on
				# (the argv[0] rule), so the guest would be stranded there; the
				# tool's own compat rule xiii refuses such a target too. The
				# names are compared first so no other package's outPath is
				# forced.
				assertion = lib.any (p: (p.name or null) == package.name && p == package) config.environment.systemPackages;
				message = "cogworx.pve.upgrade: environment.systemPackages does not contain the upgrade tool (cogworx.pve.upgrade.package). Something replaced the list (for example with lib.mkForce); add packages without lib.mkForce instead. cogworxd runs <system>/sw/bin/cogworx-pve-upgrade from every system generation.";
			}
			{
				# A composition that REPLACES extraConfig (mkForce) drops the
				# guard silently: the pin then records no guard, and the
				# unconditional `set fallback=0` is gone too, so a candidate
				# whose kernel does not load stops at GRUB's menu instead of
				# booting entry 0.
				assertion = lib.hasInfix guardText config.boot.loader.grub.extraConfig;
				message = "cogworx.pve.upgrade: boot.loader.grub.extraConfig does not contain the GRUB guard (pve/upgrade/grub-guard.cfg) verbatim. Something replaced it (for example with lib.mkForce); add GRUB lines around it with lib.mkBefore or lib.mkAfter instead. Lines after the guard must not set default, fallback, next_entry or any cwx_* variable: they would silently override the guard's decision. lib.mkBefore is the safe place for lines unrelated to boot selection.";
			}
		];
	};
}
