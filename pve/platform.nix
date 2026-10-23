# The Proxmox platform layer: everything nixpkgs' google-compute-config.nix
# supplied to the GCE image that a PVE VM needs in a different shape, plus the
# PVE-only pieces (the qemu-ga allow-list, nested KVM, virtio disk serials and
# the serial-log file).
#
# Not imported here, on purpose: google-compute-image.nix and everything under
# it. Its guest agent, OS Login and metadata-driven defaults are the surface
# cogbox-host.nix spends most of its length undoing, and on PVE there is no
# provider behind any of them.
{
	config,
	lib,
	pkgs,
	modulesPath,
	...
}:
let
	cfg = config.cogworx.pve;
	iface = cfg.interface;

	# The serial-log FILE cogworxd reads through QGA file-read (README.md,
	# "Files"). supervise.sh's emit() appends classified lines to whatever
	# cogworx.gce.serialDevice names; on GCE that is ttyS0, read back through the
	# provider's serial-port API, which PVE does not have.
	serialLog = "/run/cogworx/serial.log";
	# Cap and keep sizes are a contract with the control plane's Log reader,
	# which resumes after the last line it retained and tolerates truncation.
	serialCapBytes = 256 * 1024;
	serialKeepBytes = 128 * 1024;

	# THE QGA ALLOW-LIST. qemu-ga's default surface includes guest-exec and
	# guest-file-write, i.e. root code execution and arbitrary file writes for
	# anyone who can reach the PVE agent API. cogworxd needs three reads (ping,
	# file-read of two files, network-get-interfaces) and PVE's own shutdown
	# path; the rest are the read-only probes PVE's UI issues. Allow-listing
	# (not block-listing) means an RPC a future qemu-ga adds is OFF until named
	# here.
	#
	# Residual, stated rather than discovered: the allow-list removes exec and
	# write, NOT path scope. qemu-ga runs as root and guest-file-open takes any
	# path, so:
	#   - any PVE principal with VM.GuestAgent.FileRead on this VM -- cogworxd's
	#     own scoped token included -- can read ANY guest file as root;
	#   - any principal with VM.GuestAgent.FileWrite or
	#     VM.GuestAgent.Unrestricted (or root on a PVE node, which reaches the
	#     agent socket directly) can create or truncate ANY file through
	#     guest-file-open with mode "w". Observed live: a file-write that the
	#     allow-list refused still left a 0-byte file behind, because the open
	#     that created it is allowed.
	# guest-file-open stays allowed because guest-file-read needs it.
	qgaAllowedRpcs = [
		"guest-sync"
		"guest-sync-delimited"
		"guest-ping"
		"guest-info"
		"guest-network-get-interfaces"
		"guest-file-open"
		"guest-file-read"
		"guest-file-close"
		"guest-shutdown"
		"guest-get-osinfo"
		"guest-get-host-name"
		"guest-get-time"
		"guest-fsfreeze-status"
	];

	serialCap = pkgs.writeShellApplication {
		name = "cogworx-pve-serial-cap";
		runtimeInputs = [ pkgs.coreutils ];
		text = ''
			log="''${COGWORX_SERIAL:-${serialLog}}"
			[ -f "$log" ] || exit 0
			size=$(stat -c %s "$log")
			if [ "$size" -le ${toString serialCapBytes} ]; then
				exit 0
			fi
			# Keep the tail, starting on a line boundary: the first line of a
			# byte-cut tail is (almost always) a fragment, and a reader must
			# never see half a classified line. Renamed into place, so a reader
			# sees the old file or the new one and never a half-written one.
			# An emit() racing the rename lands in the old inode and is lost;
			# that is a one-line window every few minutes on a channel whose
			# reader already tolerates truncation.
			tmp=$(mktemp "$log.XXXXXX")
			tail -c ${toString serialKeepBytes} "$log" | tail -n +2 > "$tmp"
			chmod 0600 "$tmp"
			mv -f "$tmp" "$log"
			echo "cogworx-pve-serial-cap: $log was $size bytes; kept the last $(stat -c %s "$log")"
		'';
	};

	kvmCheck = pkgs.writeShellApplication {
		name = "cogworx-pve-kvm";
		runtimeInputs = [ pkgs.coreutils pkgs.gnugrep ];
		text = ''
			if [ -c /dev/kvm ]; then
				echo "cogworx-pve-kvm: /dev/kvm is present; nested virtualization is available"
				exit 0
			fi
			vmx=$(grep -c -w vmx /proc/cpuinfo || true)
			msg="nested KVM unavailable: /dev/kvm is absent (CPUs advertising vmx: $vmx); the sandbox guest cannot start on this VM"
			echo "cogworx-pve-kvm: $msg" >&2
			# A classified serial line, in emit()'s format, because this is the
			# root cause the supervisor's own later "sandbox start failed"
			# would otherwise hide.
			printf 'cogworx: FAILED: %s\n' "$msg" >> ${lib.escapeShellArg config.cogworx.gce.serialDevice} 2>/dev/null || true
			exit 1
		'';
	};
in
{
	imports = [
		# virtio_pci, virtio_blk, virtio_net, virtio_console (the qemu-ga port)
		# and friends in the initrd.
		"${modulesPath}/profiles/qemu-guest.nix"
	];

	config = {
		# --- Networking -------------------------------------------------------
		#
		# No host firewall. This image's packet policy is two dedicated nft
		# tables -- gce/floor.nix's cogworx_floor and floor-site.nix's
		# cogworx_pve_floor -- and a NixOS firewall a composed fleet profile
		# switches on (and opens ports in) would be a third policy nobody
		# reviewed against them. Forced, and asserted below so a later mkForce
		# elsewhere cannot silently win.
		networking.firewall.enable = lib.mkForce false;

		# net.ifnames=0 (rendered by nixpkgs' udev module from this option): the
		# one virtio NIC is eth0 on every clone, which every consumer of
		# cogworx.pve.interface relies on.
		networking.usePredictableInterfaceNames = false;

		# DHCP on eth0 alone. The hostname is set by hostname.nix before dhcpcd
		# starts; an empty static name keeps nothing else claiming one.
		networking.useDHCP = false;
		networking.interfaces.${iface}.useDHCP = true;
		networking.hostName = lib.mkDefault "";

		# No cloud-init. It would take the hostname, the network and SSH keys
		# from a datasource this image does not have; here the metadata
		# emulator, hostname.nix and dhcpcd own those. Forced, because a base
		# profile for Proxmox guests (nixpkgs' proxmox-image.nix) turns it on,
		# and with it systemd-networkd; asserted below.
		services.cloud-init.enable = lib.mkForce false;
		networking.dhcpcd = {
			# network-online.target means "eth0 has its IPv4 lease", which
			# self-refresh and the gce floor's first-boot fallback depend on.
			wait = "ipv4";
			# dhcpcd must never rename this VM: the hostname is the consul
			# node name and the DHCP client name, so it comes from the control
			# plane (hostname.nix) and nowhere else.
			setHostname = false;
			# - nohook hostname: the same, at the hook level.
			# - nohook resolv.conf: DNS is pinned to cogworx.gce.vpcResolver
			#   (cogbox-host.nix); a DHCP-supplied server must not reach
			#   resolved through the resolvconf hook.
			# - noipv4ll: never fall back to a 169.254/16 address -- that range
			#   is the metadata emulator's and rule 4a's.
			# - noipv6: IPv4 only (eth0's IPv6 is disabled below).
			# - clientid: identify by hardware address. cogworxd derives the
			#   MAC from the instance's owner uuid, so the lease follows the
			#   instance across stop/start and template rebuilds.
			#
			# NixOS still renders a bare `hostname` line (send our hostname for
			# DDNS); it cannot be removed from extraConfig. What gets sent is
			# therefore the control plane's VM name, never a user string.
			#
			# Joined rather than written as an indented literal: Nix strips
			# leading SPACES from '' strings but not tabs, so a literal here
			# would render every directive tab-indented (state-disk.nix's
			# drop-in hit the same trap). checks.nix greps the realized file
			# for exact lines.
			extraConfig = lib.concatStringsSep "\n" [
				"nohook hostname"
				"nohook resolv.conf"
				"noipv4ll"
				"noipv6"
				"clientid"
				""
			];
		};

		boot.kernel.sysctl = {
			# The GCE network-security set (google-guest-configs'
			# 60-gce-network-security.conf), inlined so it is asserted rather
			# than inherited from a package this image does not otherwise need.
			"net.ipv4.tcp_syncookies" = 1;
			"net.ipv4.conf.all.accept_source_route" = 0;
			"net.ipv4.conf.default.accept_source_route" = 0;
			"net.ipv4.conf.all.accept_redirects" = 0;
			"net.ipv4.conf.default.accept_redirects" = 0;
			"net.ipv4.conf.all.secure_redirects" = 1;
			"net.ipv4.conf.default.secure_redirects" = 1;
			"net.ipv4.ip_forward" = 0;
			"net.ipv4.conf.all.send_redirects" = 0;
			"net.ipv4.conf.default.send_redirects" = 0;
			"net.ipv4.conf.all.rp_filter" = 1;
			"net.ipv4.conf.default.rp_filter" = 1;
			"net.ipv4.icmp_echo_ignore_broadcasts" = 1;
			"net.ipv4.icmp_ignore_bogus_error_responses" = 1;
			"net.ipv4.conf.all.log_martians" = 1;
			"net.ipv4.conf.default.log_martians" = 1;
			"kernel.randomize_va_space" = 2;
			"kernel.panic" = 10;
			# The metadata address lives on lo. arp_ignore=1 answers ARP only
			# for addresses configured on the RECEIVING interface, so eth0
			# never answers who-has 169.254.169.254 for a neighbour on the
			# shared L2; arp_announce=2 never sources ARP from an address that
			# is not on the sending interface.
			"net.ipv4.conf.all.arp_ignore" = 1;
			"net.ipv4.conf.default.arp_ignore" = 1;
			"net.ipv4.conf.all.arp_announce" = 2;
			"net.ipv4.conf.default.arp_announce" = 2;
			# IPv4 only on the shared segment: no SLAAC address, no router
			# advertisements from a neighbour. Loopback keeps ::1.
			"net.ipv6.conf.${iface}.disable_ipv6" = 1;
		};

		# --- No GCE agents ------------------------------------------------------
		#
		# cogbox-host.nix only un-wants these (on GCE the units come from
		# google-compute-config.nix). Here nothing else defines them, so its
		# wantedBy-only definitions would render three ExecStart-less units;
		# disabling them renders none.
		systemd.services.google-guest-agent.enable = false;
		systemd.services.google-startup-scripts.enable = false;
		systemd.services.google-shutdown-scripts.enable = false;

		# --- QEMU guest agent ----------------------------------------------------
		#
		# The module's ExecStart is fixed and it has no argument option, so the
		# allow-list goes in by mkForce. checks.nix asserts the realized line.
		services.qemuGuest.enable = true;
		systemd.services.qemu-guest-agent.serviceConfig.ExecStart = lib.mkForce
			"${config.services.qemuGuest.package}/bin/qemu-ga --statedir /run/qemu-ga --allow-rpcs=${lib.concatStringsSep "," qgaAllowedRpcs}";

		# --- Nested KVM -----------------------------------------------------------
		boot.kernelModules = [ "kvm-intel" ];
		systemd.services.cogworx-pve-kvm = {
			description = "Check that nested KVM is available to the sandbox guest";
			wantedBy = [ "multi-user.target" ];
			after = [ "systemd-modules-load.service" ];
			# Ahead of the supervisor so its classified line lands first.
			before = [ "cogworx-supervisor.service" ];
			serviceConfig = {
				Type = "oneshot";
				RemainAfterExit = true;
				ExecStart = "${kvmCheck}/bin/cogworx-pve-kvm";
			};
		};

		# --- Disks ------------------------------------------------------------------
		#
		# cogworxd attaches the state and guest disks as virtio-blk with
		# serial=cogworx-state / serial=cogworx-guest, which udev publishes
		# under /dev/disk/by-id/virtio-<serial>. Same wire contract as the GCE
		# deviceNames (cogbox-host.nix), different provider prefix.
		cogworx.gce.stateDevice = "/dev/disk/by-id/virtio-cogworx-state";
		cogworx.gce.guestDevice = "/dev/disk/by-id/virtio-cogworx-guest";

		# --- Serial log ----------------------------------------------------------------
		cogworx.gce.serialDevice = serialLog;
		systemd.tmpfiles.rules = [
			# Pre-created 0600 so emit()'s first append does not create it with
			# the default umask. /run/cogworx itself is metadata.nix's.
			"f ${serialLog} 0600 root root -"
		];
		systemd.services.cogworx-pve-serial-cap = {
			description = "Cap the cogworx serial log file";
			serviceConfig = {
				Type = "oneshot";
				ExecStart = "${serialCap}/bin/cogworx-pve-serial-cap";
			};
		};
		systemd.timers.cogworx-pve-serial-cap = {
			description = "Periodically cap the cogworx serial log file";
			wantedBy = [ "timers.target" ];
			timerConfig = {
				OnBootSec = "1min";
				OnUnitActiveSec = "1min";
				AccuracySec = "10s";
				Unit = "cogworx-pve-serial-cap.service";
			};
		};

		assertions = [
			{
				assertion = !config.networking.firewall.enable;
				message = "cogworx.pve: networking.firewall.enable is true. This image's packet policy is gce/floor.nix's and floor-site.nix's nft tables; a NixOS firewall from a composed profile would be a third, unreviewed policy (and opens ports of its own). Leave it off.";
			}
			{
				assertion = !config.services.cloud-init.enable;
				message = "cogworx.pve: services.cloud-init.enable is true. cloud-init would take the hostname, the network and SSH keys from a datasource this image does not have; the metadata emulator, hostname.nix and dhcpcd own those here. Leave it off (platform.nix forces it off; something overrode that).";
			}
			{
				assertion = !config.systemd.network.enable;
				message = "cogworx.pve: systemd.network.enable is true. dhcpcd on ${iface} is this image's network stack: it holds the lease network-online.target waits for, with its hostname and resolv.conf hooks off. systemd-networkd from a composed profile would replace it. Leave it off.";
			}
			{
				assertion = config.networking.hostName == "";
				message = "cogworx.pve: networking.hostName is set (\"${config.networking.hostName}\"). hostname.nix sets the hostname from the boot config before dhcpcd and consul read it, so a static name would make every clone claim the same one. Leave it empty.";
			}
		];
	};
}
