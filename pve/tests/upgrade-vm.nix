# pve-upgrade-vm-<suite>: the in-guest upgrade path on a real boot loader.
#
# One VM boots like a PVE template: legacy MBR, SeaBIOS, GRUB on /dev/vda,
# configurationLimit 1, timeout 0 (image.nix), plus everything upgrade/
# module.nix gives every system generation: the tool, the compat doc, the GRUB
# guard, the panic parameters and the locked nix-gc. pve-host.nix is NOT
# imported (it needs the cogbox package, the state and guest disks and the
# metadata emulator); the host contract is set here instead.
#
# The system generations under test are this node re-evaluated with
# extendModules (same backdoor, disk layout and kernel; a distinct toplevel),
# plus three hand-made "systems". They reach the VM the way a real target
# does: through `fetch` from a substituter, here a file:// binary cache that a
# second node (cachehost) fills and signs at run time. The VM trusts that key
# through an optional nix.conf include the test writes after the first boot.
# QEMU gets `-smbios type=1,serial=<blob>` per boot (QEMU_OPTS), the raw blob
# PVE hands QEMU after its base64 decode.
#
#   main      the guard on every boot path (S=c, no S, no serial, a serial
#             that is not a raw v1 blob, S=r, a hard stop mid-trial, a missing
#             initrd, a stage-1 panic, a kernel that does not load, the SMBIOS
#             3.0 entry point), the fetch verdicts, the headroom gate, the lock
#             against nix-gc (held by a stand-in, then by the real worker), the
#             argv[0] rule, commit, abort and revert-commit, with the MBR and
#             the first MiB byte-identical throughout.
#   powercut  a power cut after every commit step and every abort step, after
#             --no-rollback commit steps 3 and 8, after abort step 4 of a
#             committing txn and after arm step 6, repaired from txn.json.
#
# Both suites share the node configuration and so the disk image derivation.
# The script is upgrade_vm.py; Nix only prepends the values below.
{ suite }:
{ lib, ... }:
let
	# The SMBIOS budget's worst case, as the control plane encodes it today
	# (the raw serial, 329 bytes). The script swaps its `M=` for `S=c`/`S=r`
	# and gives every boot its own start nonce.
	bootcfg = builtins.fromJSON (builtins.readFile ../testdata/bootcfg-v1.json);
	worstCase = (lib.findFirst (c: c.name == "worst-case-498")
		(throw "pve-upgrade-vm: bootcfg-v1.json has no worst-case-498 case") bootcfg.cases).serial_blob;

	# The same fictional control CA key as checks.nix's fixture.
	fixtureCAKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJMmGv60w43igyko8BEEnvP2PPu01MPlwi9Zamq2j/LC control-ca";
	builtAt = "2026-10-18T00:00:00Z";
	rel = id: { cogworx.pve.release = lib.mkForce { inherit id builtAt; }; };
	gib = 1024 * 1024 * 1024;
in
{
	name = "pve-upgrade-vm-${suite}";
	# The scripts take about 6 (main) and 9 (powercut) minutes. nixpkgs'
	# run-*-vm backgrounds its virtiofsd daemons and execs QEMU without
	# waiting for their sockets; under host load QEMU can lose that race and
	# exit, and the driver then waits on the monitor silently until this
	# timeout. 30 minutes bounds that stall instead of the default hour.
	globalTimeout = 30 * 60;

	nodes.machine =
		{
			config,
			lib,
			pkgs,
			extendModules,
			...
		}:
		let
			# This node re-evaluated with more modules. additionalPaths is cut
			# so a variant never tries to carry the others.
			mkGen = mods:
				(extendModules {
					modules = [ { virtualisation.additionalPaths = lib.mkForce [ ]; } ] ++ mods;
				}).config.system.build.toplevel;
			gen = g: extra: mkGen ([
				(rel "test-${lib.toLower g}")
				{ environment.etc."cwx-gen".text = lib.mkForce "${g}\n"; }
			] ++ extra);

			B = gen "B" [ { boot.kernelParams = [ "cwx.gen=B" ]; } ];
			C = gen "C" [ { boot.kernelParams = [ "cwx.gen=C" ]; } ];
			# A unique initrd, so deleting it breaks I alone.
			I = gen "I" [ { boot.initrd.systemd.contents."/etc/cwx-gen-i".text = "I\n"; } ];
			# Stage 1 fails: emergency.target, then nixpkgs' panic-on-fail
			# (boot.panic_on_fail), sysrq c, a panic, and panic=N reboots.
			P = gen "P" [
				{
					boot.initrd.systemd.services.cwx-fail = {
						wantedBy = [ "initrd.target" ];
						before = [ "initrd.target" ];
						unitConfig = {
							DefaultDependencies = false;
							OnFailure = [ "emergency.target" ];
							OnFailureJobMode = "replace-irreversibly";
						};
						serviceConfig = {
							Type = "oneshot";
							ExecStart = "${pkgs.coreutils}/bin/false";
						};
					};
				}
			];
			# Guest compat rule vi: another host key path.
			X = gen "X" [ { cogworx.pve.upgrade.hostContract.hostKeyPath = lib.mkForce "/var/lib/other/ssh_host_ed25519_key"; } ];
			# A "system" whose kernel is not a kernel but which passes every
			# guest compat rule: install-grub.pl renders its entry and GRUB's
			# `linux` fails on it. Rule xiii wants the tool at sw/bin, so it
			# carries this node's (a link to the package's file, as a real
			# system path has it).
			K = pkgs.runCommand "nixos-system-cwx-badkernel" { nativeBuildInputs = [ pkgs.python3 ]; } ''
				mkdir -p $out/sw/bin
				ln -s ${config.cogworx.pve.upgrade.package}/bin/cogworx-pve-upgrade $out/sw/bin/cogworx-pve-upgrade
				echo "this is not a bzImage" > $out/kernel
				echo "this is not an initrd" > $out/initrd
				printf '#!/bin/sh\nexit 1\n' > $out/init
				chmod +x $out/init
				cp ${B}/kernel-params $out/kernel-params
				printf 'cwx-badkernel' > $out/nixos-version
				python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); d["release"]["id"] = "test-k"; sys.stdout.write(json.dumps(d, sort_keys=True, separators=(",", ":")))' \
					${B}/cogworx-pve-compat.json > $out/cogworx-pve-compat.json
			'';
			# Never realised successfully: U is in the cache unsigned, E is not
			# in it at all.
			U = pkgs.runCommand "nixos-system-cwx-unsigned" { } "mkdir -p $out; echo U > $out/marker";
			E = pkgs.runCommand "nixos-system-cwx-notfound" { } "mkdir -p $out; echo E > $out/marker";
		in
		{
			imports = [
				../image.nix
				../upgrade/module.nix
			];

			virtualisation = {
				useBootLoader = true;
				# As on PVE (image.nix), so the pin and the compat doc see the
				# production device.
				bootLoaderDevice = "/dev/vda";
				memorySize = 1536;
				diskSize = 8192;
				# The VM's own root mount replaces image.nix's; keep its growth.
				fileSystems."/".autoResize = true;
			};
			boot.loader.grub.enable = true;
			boot.initrd.systemd.enable = true;
			# TEST ONLY: GRUB's messages on the serial console, before the
			# shipped guard text (which is otherwise exactly the file).
			boot.loader.grub.extraConfig = lib.mkBefore ''
				serial --unit=0 --speed=115200
				terminal_output serial
			'';

			# A, too, is a release: the powercut suite cycles A -> B -> C -> A.
			cogworx.pve.release = { id = "test-a"; inherit builtAt; };
			cogworx.pve.upgrade = {
				hostContract = {
					controlCAKeys = [ fixtureCAKey ];
					controlPlaneCIDRs = [ "198.51.100.0/24" ];
					controlUser = "root";
					hostKeyPath = "/var/lib/cogworx/sshd/ssh_host_ed25519_key";
					stateDevice = "/dev/disk/by-id/virtio-cogworx-state";
					guestDevice = "/dev/disk/by-id/virtio-cogworx-guest";
					interface = "eth0";
				};
				# The test seam: an 8 GiB disk. Production values are pinned
				# by checks.nix config-values.
				minFreeBytes = 2 * gib;
				reserveBytes = 256 * 1024 * 1024;
			};

			# The one substituter is the run-time file:// cache; its key is
			# generated at run time, so it is trusted through an optional
			# include the script writes.
			nix.settings.substituters = lib.mkForce [ "file:///tmp/shared/cache" ];
			nix.settings.trusted-public-keys = lib.mkForce [ ];
			nix.extraOptions = ''
				!include /var/lib/cwx-test/nix-trust.conf
			'';

			environment.etc."cwx-gen".text = "A\n";
			environment.etc."cwx-test/crashat.py".source = ./upgrade_crashat.py;
			environment.systemPackages = [ pkgs.python3 ];

			system.build.cwxGens = {
				A = config.system.build.toplevel;
				inherit
					B
					C
					I
					P
					X
					K
					U
					E
					;
			};
		};

	# Signs and serves the targets: the host store is mounted here, and these
	# paths are registered valid.
	nodes.cachehost =
		{ nodes, ... }:
		{
			virtualisation.memorySize = 1024;
			virtualisation.additionalPaths = with nodes.machine.system.build.cwxGens; [
				A
				B
				C
				I
				P
				X
				K
				U
			];
			nix.settings.experimental-features = [ "nix-command" ];
			environment.systemPackages = [ nodes.machine.cogworx.pve.upgrade.package ];
		};

	testScript =
		{ nodes, ... }:
		let
			up = nodes.machine.cogworx.pve.upgrade;
			gens = lib.mapAttrs (_: p: "${p}") nodes.machine.system.build.cwxGens;
		in
		"SUITE = '${suite}'\n"
		+ "G_JSON = r'''${builtins.toJSON gens}'''\n"
		+ "WC_BLOB = '${worstCase}'\n"
		+ "MIN_FREE = ${toString up.minFreeBytes}\n"
		+ "RESERVE = ${toString up.reserveBytes}\n"
		+ builtins.readFile ./upgrade_vm.py;
}
