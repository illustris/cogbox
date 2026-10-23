# mke2fs without its whole-device discard, for the two host units that format
# a disk: cogworx-state-disk (gce/state-disk.nix) and cogworx-guest-disk
# (gce/guest-disk.nix). Both run `mkfs.ext4` with no -E, so mke2fs takes its
# default, discard = 1, and walks the whole device in 2 GiB BLKDISCARDs
# before it writes a byte.
#
# WHY THAT BREAKS PVE. Every drive of a PVE sandbox VM carries QEMU IO limits,
# and QEMU charges discarded bytes against the drive's write-bandwidth
# throttle. At 20 MB/s the state disk's discard (32 GiB) takes about 27
# minutes, the guest disk's 16 GiB store volume about 14 and its pool about 40,
# against the units' TimeoutStartSec=600. Measured live: both units were killed
# at 600 s having used ~26 ms of CPU, after ~12 GiB of discards each. The kill
# lands after mke2fs's first discard has already hit block 0, so it leaves no
# superblock behind, and the guest-disk unit's once-per-boot latch then
# refuses to re-make the store filesystem in the same host boot. The store leg
# re-formats on EVERY host boot, not only the first, so without this file no
# PVE boot ever gets a bootable guest.
#
# WHY SKIPPING IT IS FREE. A freshly allocated RBD volume (the state and guest
# disks are never linked clones) is thin and already reads as zeros, so the
# first format's discard reclaims nothing. mke2fs never relied on it here either: a block device reports that
# discard does not zero (BLKDISCARDZEROES is 0), so the inode tables stay lazy
# and the journal is still zeroed explicitly, exactly as before. The drives
# keep discard=on, so later frees (the guest's online discard and fstrim) still
# reach the storage. The one cost is the store volume: re-made every boot over
# the previous boot's blocks, it leaves them allocated in the storage until the
# guest's fstrim trims them (online discard returns only blocks the new
# filesystem itself frees), at most the store volume's size.
#
# HOW. mke2fs reads $MKE2FS_CONFIG in place of its compiled-in profile, and
# looks `discard` up in [defaults] before the fs_types stanzas, none of which
# sets it. The profile below is that compiled-in file plus one line,
# `discard = false` under [defaults], derived at build time from the SAME
# e2fsprogs the two units put on PATH. The variable is set on those two units
# only. Not `-E nodiscard`, because gce/ is imported unchanged; not a PATH
# wrapper, because writeShellApplication puts its runtimeInputs first.
#
# A MISSING FILE IS SILENT. mke2fs given an MKE2FS_CONFIG that does not exist
# falls back to its built-in defaults, discard on. That cannot happen with a
# store path in the units' closure, and checks.nix pins the exact value on both
# units (config-values, unit-graph) and runs the realized mkfs lines with and
# without it (mkfs-nodiscard).
#
# The nested guest needs nothing: it formats no device (its hosted volumes
# have autoCreate = false), and both filesystems it mounts from the guest disk
# are made by cogworx-guest-disk on the host.
{
	config,
	lib,
	pkgs,
	...
}:
let
	# The attribute both gce/ units list in runtimeInputs. Its mke2fs (the
	# `bin` output) compiles in the profile path of the `out` output, which is
	# where the file lives.
	e2fsprogs = pkgs.e2fsprogs;

	profile = pkgs.runCommand "mke2fs-nodiscard.conf" {
		upstream = "${e2fsprogs.out}/etc/mke2fs.conf";
	} ''
		# Loud on an e2fsprogs whose default profile this edit no longer fits.
		[ "$(grep -c '^\[defaults\]$' "$upstream")" = 1 ] \
			|| { echo "mke2fs-nodiscard: expected exactly one [defaults] stanza in $upstream" >&2; exit 1; }
		if grep -Eq '^[[:space:]]*discard[[:space:]]*=' "$upstream"; then
			echo "mke2fs-nodiscard: $upstream already sets discard; review this profile" >&2
			exit 1
		fi
		awk '{ print } /^\[defaults\]$/ { print "\tdiscard = false" }' "$upstream" > "$out"
	'';

	# The gce/ units that run mkfs.ext4. checks.nix spells the same list and
	# fails when any other unit carries the variable or a format leg appears
	# elsewhere under gce/.
	formatUnits = [ "cogworx-state-disk" "cogworx-guest-disk" ];
in
{
	config = {
		systemd.services = lib.genAttrs formatUnits (_: {
			environment.MKE2FS_CONFIG = "${profile}";
		});

		# genAttrs DEFINES the unit, so a gce/ unit that is later renamed would
		# survive here as an environment-only stub and its replacement would
		# format with discard. Every listed unit must still run something.
		assertions = map (n: {
			assertion = lib.any (s: s != "") (lib.toList (config.systemd.services.${n}.serviceConfig.ExecStart or [ ]));
			message = "pve/mkfs-nodiscard.nix: ${n} has no ExecStart, so MKE2FS_CONFIG no longer reaches a format leg. Point the list at the unit that now runs mkfs.ext4.";
		}) formatUnits;

		system.build.pveMke2fsConfig = profile;
	};
}
