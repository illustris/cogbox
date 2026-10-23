# cogworx-pve-hostname.service -- set the kernel hostname from the SMBIOS boot
# config before anything can read or publish it.
#
# Two consumers make the hostname more than cosmetic on PVE, and both read it
# early and once:
#   - dhcpcd sends it to the site's DHCP server (NixOS hard-codes a `hostname`
#     line in dhcpcd.conf for DDNS, and extraConfig cannot remove it);
#   - a composed fleet profile's consul agent registers under it as its node
#     name.
# So it must be set BEFORE both, and it must never be a user-chosen string:
# instance names are unique only per account, and are user input. The value is
# blob code `h` (cogworx-hostname): the PVE VM name, `<prefix><vmid>`, which the
# control plane mints and the emulator validates. NEVER cogworx-instance.
#
# Read with `--print-attr`, which decodes DMI directly: this unit runs before
# the network and before the metadata socket, so it cannot depend on HTTP.
#
# Fallback when the blob has no (valid) `h`: `cwx-` plus the first 12 hex
# digits of the SMBIOS uuid (dashes removed), which cogworxd stamps with the
# instance's owner uuid at Provision. Still control-plane-chosen and unique per
# instance, and still never a user string.
{
	config,
	lib,
	pkgs,
	...
}:
let
	cfg = config.cogworx.pve;

	setHostname = pkgs.writeShellApplication {
		name = "cogworx-pve-hostname";
		runtimeInputs = [ cfg.metadataPackage pkgs.coreutils ];
		text = ''
			# Test seams only, like COGWORX_MD_BASE in gce/supervise.sh: a
			# systemd unit starts from a clean environment.
			uuid_path="''${COGWORX_DMI_UUID_PATH:-/sys/class/dmi/id/product_uuid}"
			serial_path="''${COGWORX_DMI_SERIAL_PATH:-/sys/class/dmi/id/product_serial}"
			hostname_path="''${COGWORX_HOSTNAME_PATH:-/proc/sys/kernel/hostname}"

			# One DNS label, lowercase, no trailing dash. The emulator already
			# holds `h` to a stricter grammar; this re-check is what keeps the
			# fallback and any future blob version honest too.
			valid() { [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; }

			name=""
			if out=$(cogworx-pve-metadata --dmi-serial-path "$serial_path" --print-attr cogworx-hostname); then
				name="$out"
			fi
			src="the SMBIOS boot config (cogworx-hostname)"
			if ! valid "$name"; then
				[ -z "$name" ] || echo "cogworx-pve-hostname: refusing cogworx-hostname '$name': not a DNS label" >&2
				uuid=""
				if [ -r "$uuid_path" ]; then
					uuid=$(tr -d '[:space:]' < "$uuid_path" | tr 'A-F' 'a-f')
				fi
				hex="''${uuid//-/}"
				if ! [[ "$hex" =~ ^[0-9a-f]{32}$ ]]; then
					echo "cogworx-pve-hostname: no cogworx-hostname and no readable SMBIOS uuid; leaving the hostname unset" >&2
					exit 1
				fi
				name="cwx-''${hex:0:12}"
				src="the SMBIOS uuid (fallback)"
			fi
			printf '%s' "$name" > "$hostname_path"
			echo "cogworx-pve-hostname: hostname set to $name from $src"
		'';
	};
in
{
	config = {
		systemd.services.cogworx-pve-hostname = {
			description = "Set the hostname from the SMBIOS boot config";
			wantedBy = [ "sysinit.target" ];
			# network-pre.target is the documented hook for "before any network
			# configuration": Before= plus Wants= (systemd.special(7)).
			wants = [ "network-pre.target" ];
			before = [
				"network-pre.target"
				"dhcpcd.service"
				# Ordering on a unit that is not part of this image is inert;
				# it binds as soon as a fleet profile adds consul.
				"consul.service"
				"shutdown.target"
			];
			conflicts = [ "shutdown.target" ];
			unitConfig.DefaultDependencies = false;
			serviceConfig = {
				Type = "oneshot";
				RemainAfterExit = true;
				ExecStart = "${setHostname}/bin/cogworx-pve-hostname";
			};
		};
	};
}
