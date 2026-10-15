# The PVE template disk: a qcow2 with a legacy (MBR) partition table and GRUB
# on /dev/vda, booted by SeaBIOS from virtio0.
#
# Built as config.system.build.pveImage. The bake converts it with
# `qemu-img convert -c` before upload, so the image is produced uncompressed
# here (a compressed qcow2 would be re-compressed anyway).
#
# The disk is grown at clone time (cogworxd resizes virtio0 once, at
# Provision), so the root partition and filesystem grow on first boot:
# boot.growPartition plus autoResize. On this backend the boot disk IS the nix
# store (cogbox-host.nix), so that growth is where in-VM plugin builds land.
{
	config,
	lib,
	pkgs,
	modulesPath,
	...
}:
{
	config = {
		fileSystems."/" = {
			device = "/dev/disk/by-label/nixos";
			fsType = "ext4";
			autoResize = true;
		};
		boot.growPartition = true;

		boot.loader.grub.device = "/dev/vda";
		boot.loader.timeout = 0;
		# A template boots exactly one configuration; there is no console user
		# to pick an older one. 1, NEVER 0: install-grub.pl always opens the
		# "All configurations" submenu and only then applies the limit, so 0
		# renders an empty `submenu { }`, which GRUB's parser rejects (a syntax
		# error on every boot, in every clone). checks.nix pins >= 1.
		boot.loader.grub.configurationLimit = 1;

		# The root disk is virtio-blk, so the initrd must be able to see it
		# before udev's modalias pass could load the driver.
		boot.initrd.kernelModules = [ "virtio_pci" "virtio_blk" ];

		# ttyS0 is PVE's serial0 socket: the kernel console and the break-glass
		# getty. It is NOT the cogworx log channel -- that is the file named by
		# cogworx.gce.serialDevice (platform.nix).
		boot.kernelParams = [ "console=ttyS0" ];

		system.build.pveImage = import "${modulesPath}/../lib/make-disk-image.nix" {
			inherit lib config pkgs;
			name = "cogworx-pve-image";
			baseName = "cogworx-pve";
			format = "qcow2";
			partitionTableType = "legacy";
			diskSize = "auto";
			additionalSpace = "1024M";
			# No channel: the image never runs nixos-rebuild, and a channel is
			# a second, unpinned nixpkgs on the store disk.
			copyChannel = false;
		};
	};
}
