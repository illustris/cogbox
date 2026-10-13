# Boot restore of runtime tool generations (runtime/module.nix), on a guest
# with the storage SHAPE of the hosted (GCE) one, which is the only profile
# that enables the feature:
#
#   - the root is a tmpfs, so the Nix database resets on every boot;
#   - the writable store overlay upper lives on its own persisted ext4 disk,
#     so a plain reboot keeps the bundle's files while forgetting them: the
#     guest-only reboot, where the import rewrites present-but-invalid paths
#     in place. Deleting that disk between boots is the host re-creating the
#     store volume (a CP stop/start);
#   - ~/work lives on its own `nofail` mount at /var/lib/cogbox/work, so the
#     module renders the hosted Wants=/After=/ConditionPathIsMountPoint shape.
#     Deleting that disk is a pool-absent boot.
#
# systemd stage 1, as in the real hosted guest: scripted stage 1 ignores
# autoFormat (it only renders x-systemd.makefs), and the store disk must be
# formatted in the initrd whenever it comes back blank. The driver recreates a
# deleted emptyDiskImages qcow2 blank on the next start (qemu-vm.nix cds into
# the machine's state dir and creates empty<N>.qcow2 only if it is missing).
#
# Needs KVM: `nix build .#checks.x86_64-linux.runtime-boot-restore`.
{ self, pkgs }:
{
	name = "cogbox-runtime-boot-restore";

	nodes.machine = { config, lib, pkgs, ... }: {
		imports = [ ../runtime/module.nix ];
		cogbox.runtimeEnvironment.enable = true;
		# prepare --import-store-path asks `nix eval` for the system.
		nix.settings.experimental-features = [ "nix-command" ];

		boot.initrd.systemd.enable = true;
		virtualisation = {
			cores = 2;
			memorySize = 2048;
			diskImage = null;
			writableStoreUseTmpfs = false;
			# empty0 = the writable store, empty1 = the work tree. Sizes matter:
			# cogbox-env keeps max(2 GiB, 10%) of the work filesystem free.
			emptyDiskImages = [
				{ size = 2048; driveConfig.deviceExtraOpts.serial = "rt-store"; }
				{ size = 4096; driveConfig.deviceExtraOpts.serial = "rt-work"; }
			];
			fileSystems = {
				"/nix/.rw-store" = {
					device = "/dev/disk/by-id/virtio-rt-store";
					fsType = "ext4";
					autoFormat = true;
					neededForBoot = true;
				};
				# Never formatted at boot: a blank disk fails this mount, which is
				# exactly the pool-absent case. The test formats it once.
				"/var/lib/cogbox/work" = {
					device = "/dev/disk/by-id/virtio-rt-work";
					fsType = "ext4";
					options = [ "nofail" "x-systemd.device-timeout=10s" ];
				};
			};
		};

		# Stand-in for the real brain-materialize: ordered after the work mount
		# and before multi-user.target, it creates <work>/.cogbox (which
		# cogbox-env requires and never creates) and the /root/work link.
		systemd.services.cogbox-brain-materialize = {
			description = "Test stub for cogbox brain materialization";
			wantedBy = [ "multi-user.target" ];
			before = [ "multi-user.target" ];
			after = [ "var-lib-cogbox-work.mount" ];
			serviceConfig = {
				Type = "oneshot";
				RemainAfterExit = true;
			};
			script = ''
				mkdir -p /var/lib/cogbox/work/.cogbox
				ln -sfn /var/lib/cogbox/work /root/work
			'';
		};

		# Test-only hook in front of the real ExecStart. It records what the boot
		# restore is about to face (is the bundle path on disk, and does the
		# freshly reset database know it?), and on request stretches the start so
		# the ordering step can show that the boot never waits for it.
		systemd.services.cogbox-runtime-restore.serviceConfig.ExecStartPre = pkgs.writeShellScript "runtime-restore-probe" ''
			probe=/var/lib/cogbox/work/.test-probe
			if [ -e "$probe" ]; then
				path=$(cat "$probe")
				if [ -e "$path" ]; then echo present; else echo missing; fi > /run/runtime-test-pre
				if ${config.nix.package}/bin/nix-store --check-validity "$path" 2>/dev/null; then echo valid; else echo invalid; fi >> /run/runtime-test-pre
			fi
			if [ -e /var/lib/cogbox/work/.test-slow-restore ]; then sleep 20; fi
		'';
	};

	# A column-0 .py file, like tests/cogbox.nix: Nix strips only space
	# indentation from '' strings, and this file is indented with tabs.
	testScript = builtins.readFile ./runtime_boot_restore_driver.py;
}
