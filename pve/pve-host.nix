# The cogworx Proxmox (PVE) backend image, nested v0: the cogbox HOST half as a
# NixOS system that boots as a PVE/QEMU VM and runs the same nested microVM
# guest the GCE backend runs. It is the gcp backend's shape on Proxmox.
#
# THE ONE IDEA. ../gce/cogbox-host.nix is imported UNCHANGED. The GCE host half
# talks to the outside world through exactly one interface, the GCE metadata
# server at 169.254.169.254, and five of its units hard-code that URL. A PVE VM
# has no metadata server, so this tree supplies one: a local emulator bound on
# 169.254.169.254/32 scope host dev lo, fed INBOUND by an SMBIOS type-1 serial
# blob that cogworxd writes into the stopped VM's `smbios1`, and OUTBOUND by a
# guest-attributes file cogworxd reads through the QEMU guest agent. Everything
# else in this directory is PVE platform glue:
#
#   metadata.nix      the emulator, its loopback address and socket, and the
#                     ordering edge every gce/ metadata consumer needs
#   platform.nix      networking (dhcpcd on eth0), sysctls, the qemu-ga RPC
#                     allow-list, nested KVM, virtio disk serials, and the
#                     serial-log FILE that replaces GCE's serial port
#   hostname.nix      the guest hostname from the SMBIOS blob, before dhcpcd and
#                     consul can read it
#   self-refresh.nix  per-boot refresh of cogbox's write-once bindAddr, which a
#                     DHCP address change would otherwise leave stale
#   floor-site.nix    the SITE floor (nft table inet cogworx_pve_floor): rules
#                     4a and 4 (the nix build users only), beside
#                     gce/floor.nix's own table
#   image.nix         the qcow2 disk image (legacy BIOS, grub on /dev/vda)
#   mkfs-nodiscard.nix  the format units' mke2fs profile: no whole-device
#                     discard, which the drives' IO limits throttle past the
#                     units' timeout
#   upgrade/module.nix  in-place system upgrades: the cogworx-pve-upgrade tool,
#                     the compat doc, the GRUB guard, the panic parameters and
#                     the nix-gc lock wrapper (docs/pve-system-upgrade.md)
#
# The cross-repo contract (SMBIOS blob, served routes, files, disk serials,
# units) is written down in README.md next to this file.
#
# The flake builds this module with lib.mkPveHost (the same specialArgs as
# mkGceHost: `self`, `inputs`, `system`) and exports it as
# nixosModules.pve-host, nixosConfigurations.cogbox-x86_64-pve (CA-less, so
# fail-closed) and packages.x86_64-linux.pve-image. Operators pass their base
# and site modules as mkPveHost's extraModules; eval.nix remains as a shim over
# it.
{
	config,
	lib,
	...
}:
let
	cfg = config.cogworx.pve;
	gce = config.cogworx.gce;

	# The publishability gate: a CA-less image is fail-closed (no control
	# connection can authenticate), so it is a test or dev image and the gates
	# below do not apply to it.
	#
	# Wider than cogbox-host.nix's own `controlCAPublicKey != ""`, because that
	# option is not the only way a CA reaches sshd: extraTrustedUserCAKeys is
	# written to the same TrustedUserCAKeys file, and the file's `text` is a
	# `lines` option that any composed module can append to. A bake that
	# trusts its control CA through either would otherwise build a working,
	# CA-trusting image with every gate below skipped. So any of the three
	# counts: either option non-empty, or the rendered file non-empty. Erring
	# wide only fails closed (a bake with `extraTrustedUserCAKeys = [ "" ]` is
	# held to the gates it does not strictly need).
	caBaked =
		gce.controlCAPublicKey != ""
		|| gce.extraTrustedUserCAKeys != [ ]
		|| (config.environment.etc."ssh/cogworx-control-ca.pub".text or "") != "";

	linkLocal = s: builtins.match "169\\.254\\..*" s != null;

	# --- the shape of a controlPlaneCIDRs entry ---------------------------------
	#
	# An address or CIDR as { addr; len; } (addr an integer), or null for
	# anything that is not one. No leading zeros, so lib.toInt never sees an
	# octal-looking octet.
	octet = "(0|[1-9][0-9]{0,2})";
	parseCidr = s:
		let
			m = builtins.match "${octet}\\.${octet}\\.${octet}\\.${octet}(/(0|[1-9][0-9]?))?" s;
			octets = map lib.toInt (lib.take 4 m);
			len = if builtins.elemAt m 5 == null then 32 else lib.toInt (builtins.elemAt m 5);
		in
		if m == null || lib.any (o: o > 255) octets || len > 32 then null
		else { addr = lib.foldl' (a: o: a * 256 + o) 0 octets; inherit len; };
	pow2 = n: lib.foldl' (a: _: a * 2) 1 (lib.range 1 n);
	# The entries that are not an IPv4 address or a canonical IPv4 CIDR (a
	# CIDR with host bits set included). floor_render.py refused those at
	# build time while it rendered the list (rule 4's passt mosh-reply
	# accept); the floor no longer reads it, so the module refuses them
	# instead, on every image.
	cpBad = lib.filter (s: let p = parseCidr s; in p == null || lib.mod p.addr (pow2 (32 - p.len)) != 0) cfg.floor.controlPlaneCIDRs;

	# A [lo, hi] port range, refused at evaluation when it is not one (so
	# the renderer never sees a reversed or out-of-range pair).
	portRange = lib.types.addCheck (lib.types.listOf (lib.types.ints.between 1 65535))
		(r: builtins.length r == 2 && builtins.all builtins.isInt r && builtins.head r <= lib.last r)
		// { description = "[lo, hi] port range (1 <= lo <= hi <= 65535)"; };
in
{
	imports = [
		../gce/cogbox-host.nix
		./platform.nix
		./image.nix
		./metadata.nix
		./hostname.nix
		./self-refresh.nix
		./floor-site.nix
		./mkfs-nodiscard.nix
		./upgrade/module.nix
	];

	options.cogworx.pve = {
		allowConsoleAutologin = lib.mkOption {
			type = lib.types.bool;
			default = false;
			description = ''
				Allow console root autologin (services.getty.autologinUser) on a
				published, CA-baked image. Console autologin on ttyS0 gives a
				root shell, i.e. the trusted half, to every PVE principal with
				VM.Console on the VM and to root on its node. Set true only
				where that is the site's break-glass policy; a CA-baked image
				with autologin and without this opt-in does not evaluate.
			'';
		};

		interface = lib.mkOption {
			type = lib.types.strMatching "[A-Za-z0-9_.-]{1,15}";
			default = "eth0";
			description = ''
				The VM's one network interface. net.ifnames=0 (platform.nix)
				makes the single virtio NIC eth0, and four things have to agree
				on it: dhcpcd's allowinterfaces, the emulator's
				network-interfaces/0/ip source, rule 4a's egress spoof guard and
				eth0's IPv6 disable. One option rather than four literals.
			'';
		};

		metadataPackage = lib.mkOption {
			type = lib.types.package;
			internal = true;
			description = "The metadata emulator (metadata/cogworx_pve_metadata.py) as a runnable package. Set by metadata.nix; read by hostname.nix for --print-attr.";
		};

		metadataClients = lib.mkOption {
			type = lib.types.listOf lib.types.str;
			internal = true;
			description = ''
				Every service that talks to the metadata emulator over HTTP. The
				emulator answers only peer uid 0, and floor rule 4a drops every
				non-root socket to 169.254.0.0/16, so each of these must run as
				root: floor-site.nix asserts that none sets User= or
				DynamicUser=. Set by metadata.nix, which also orders them.
			'';
		};

		floor = {
			controlPlaneCIDRs = lib.mkOption {
				type = lib.types.listOf lib.types.str;
				default = [ ];
				example = [ "198.51.100.0/24" ];
				description = ''
					Optional (default [ ]). Not a floor input: the floor has no
					@cp and no ingress filter. It is the upgrade compat doc's
					controlPlaneCIDRs, where cogworxd's control connections come
					from as the VM sees them (docs/pve-system-upgrade.md upgrade
					compat rule ii: cogworxd checks that every control-plane
					egress address is covered by these CIDRs). Each entry is an
					IPv4 address or a canonical IPv4 CIDR (asserted).
				'';
			};
			infraDenyCIDRs = lib.mkOption {
				type = lib.types.listOf lib.types.str;
				default = [ ];
				example = [ "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" "100.64.0.0/10" ];
				description = ''
					The site's internal ranges, closed to the nix build users
					(decision 2026-10-22). Rule 4 drops NEW flows to them from
					the build group (nixbld by default, under which the daemon
					runs the builders of in-VM plugin derivations; only
					fixed-output builds share the VM's network namespace), in
					the original direction only, so replies still pass. The
					exact infraAllow sockets are accepted ahead of the drop.
					Nothing else is restricted by it: the guest (passt) and the
					L7 proxy follow each sandbox's own network rules, as on GCE,
					and root is outside rule 4, so root-run plugin evaluation and
					its eval-time fetches are not covered (README.md,
					residuals).

					REQUIRED on a published (CA-baked) image, with no escape.
					Each entry is an IPv4 address or CIDR, canonical (no host
					bits), at most /8 wide, overlapping neither 127/8,
					169.254/16 nor 0/8 (floor_render.py refuses the build
					otherwise).
				'';
			};
			infraAllow = lib.mkOption {
				type = lib.types.listOf (lib.types.submodule {
					options = {
						address = lib.mkOption {
							type = lib.types.str;
							description = "One IPv4 address (a bare address or a /32) inside infraDenyCIDRs that the nix build users may nevertheless reach on this port. Not a range: list each host separately.";
						};
						protocol = lib.mkOption {
							type = lib.types.enum [ "tcp" "udp" ];
							default = "tcp";
							description = "Transport protocol of the exception.";
						};
						port = lib.mkOption {
							type = lib.types.port;
							description = "Destination port of the exception.";
						};
					};
				});
				default = [ ];
				example = [ { address = "198.18.0.80"; protocol = "tcp"; port = 443; } ];
				description = ''
					Exact (address, protocol, port) exceptions to rule 4's
					internal-range drop for the nix build users, rendered as
					accepts ahead of it: for example an internal git host a
					plugin's fixed-output fetch must reach. One entry per
					socket, never a range of ports. The guest and the L7 proxy
					do not need one: each sandbox's own network rules decide
					what they reach.
				'';
			};
			buildDenyLoopbackTCP = lib.mkOption {
				type = lib.types.listOf portRange;
				default = [ ];
				example = [ [ 8500 8500 ] ];
				description = ''
					Loopback TCP port ranges, each [lo, hi], closed to the nix
					build users beside the L7 relays' ports rule 4 derives
					itself: the build users may neither connect to them on
					127.0.0.1 or ::1 nor answer from them. They are for a
					bake's own agents that act for unauthenticated local
					clients and can be made to send requests to an address the
					client picks, for example a service-discovery agent's local
					HTTP API with no ACLs (an HTTP health check it is asked to
					register is a request it sends). The agent's uid is not
					rule 4's, so without an entry here it carries a build user
					around the internal-range drop. A bake that composes such
					an agent MUST list its ports. Ranges may overlap each other
					or the L7 window: floor-site.nix sorts and merges them.
					TCP only: list a UDP agent in buildDenyLoopbackUDP.
				'';
			};
			buildDenyLoopbackUDP = lib.mkOption {
				type = lib.types.listOf portRange;
				default = [ ];
				example = [ [ 7301 7301 ] ];
				description = ''
					Loopback UDP port ranges, each [lo, hi], the nix build users
					may not send to on 127.0.0.1 or ::1: the UDP counterpart of
					buildDenyLoopbackTCP, for a bake's agents that take
					unauthenticated datagrams on loopback and can be made to
					probe or send to addresses a datagram names (a gossip
					agent's UDP port, for example). The broadcast and multicast
					drop rule 4 always renders keeps the same datagrams from
					reaching a wildcard listener by way of a broadcast address
					(the limited one or the VM segment's). A bake that
					composes such an agent MUST list its UDP ports. Ranges may
					overlap: floor-site.nix sorts and merges them.
				'';
			};
			ruleset = lib.mkOption {
				type = lib.types.package;
				internal = true;
				readOnly = true;
				description = "The rendered nft ruleset (floor_render.py's output for cogworx.pve.interface, the options above, the nix build group and the L7 port window). Set by floor-site.nix; read by checks.nix.";
			};
		};
	};

	config = {
		# The host values the upgrade compat doc carries (upgrade/module.nix),
		# read from the options that already define them so the doc cannot
		# drift from the system it describes.
		cogworx.pve.upgrade.hostContract = {
			controlCAKeys = lib.filter (l: l != "" && !(lib.hasPrefix "#" l))
				(map lib.trim (lib.splitString "\n" (config.environment.etc."ssh/cogworx-control-ca.pub".text or "")));
			controlPlaneCIDRs = cfg.floor.controlPlaneCIDRs;
			controlUser = gce.controlUser;
			hostKeyPath = (lib.findFirst (k: (k.type or "") == "ed25519")
				(throw "cogworx.pve: no ed25519 sshd host key") config.services.openssh.hostKeys).path;
			stateDevice = gce.stateDevice;
			guestDevice = gce.guestDevice;
			interface = cfg.interface;
		};

		# ASSERTED IN THE MODULE, for the reason cogbox-host.nix gives for its
		# own resolver gate: the values these guard come from an operator-side
		# bake module, and an assertion living THERE disappears together with
		# the value it guards -- which is exactly the bake that ships open.
		assertions = [
			{
				# THE BUILD-USER EGRESS GATE (no escape). Without the site's
				# internal ranges rule 4 renders no internal-range drop, and a
				# nix build user running a plugin derivation's fixed-output
				# fetch can open flows to every internal service the VM can
				# route to. (The guest and the L7 proxy are not rule 4's: each
				# sandbox's own network rules decide what they reach.)
				assertion = !caBaked || cfg.floor.infraDenyCIDRs != [ ];
				message = lib.concatStringsSep "\n\n" [
					"cogworx.pve: this image bakes a control CA -- it is meant to be PUBLISHED -- but cogworx.pve.floor.infraDenyCIDRs is empty."
					"Floor rule 4 would then drop nothing towards internal ranges: the nix build users running in-VM plugin builds (fixed-output fetches) could open flows to every internal address this VM can route to. The guest and the L7 proxy are not affected either way; each sandbox's own network rules decide what they reach."
					"Set cogworx.pve.floor.infraDenyCIDRs to the site's internal ranges, and add exact cogworx.pve.floor.infraAllow entries for the internal services the nix build users genuinely need."
				];
			}
			{
				# Every image, CA-baked or not, as floor_render.py refused a
				# malformed entry on every image while the floor rendered the
				# list.
				assertion = cpBad == [ ];
				message = "cogworx.pve: cogworx.pve.floor.controlPlaneCIDRs ${if builtins.length cpBad == 1 then "entry" else "entries"} ${lib.concatMapStringsSep ", " (e: "\"${e}\"") cpBad} ${if builtins.length cpBad == 1 then "is" else "are"} not an IPv4 address or a canonical IPv4 CIDR (no host bits). The list is not a floor input; the upgrade compat doc carries it for upgrade compat rule ii, where cogworxd checks that every control-plane egress address is covered by these CIDRs.";
			}
			{
				# On GCE the link-local default resolver is real (the VPC
				# resolver answers there) and cogbox-host.nix lets a bake affirm
				# it. Here 169.254.169.254 is a loopback-scoped HTTP emulator
				# with no DNS server behind it, and rule 4a drops the resolver's
				# non-root uid towards the whole range anyway, so
				# allowMetadataResolver does not apply on PVE.
				assertion = !caBaked || !(linkLocal gce.vpcResolver);
				message = lib.concatStringsSep "\n\n" [
					"cogworx.pve: this image bakes a control CA while cogworx.gce.vpcResolver = \"${gce.vpcResolver}\" is link-local."
					"On Proxmox nothing serves DNS there: 169.254.169.254 is the local metadata emulator, an HTTP-only listener on loopback. Every name lookup on the VM, and through the host forwarder every guest lookup, would fail. cogworx.gce.allowMetadataResolver does not apply on PVE."
					"Set cogworx.gce.vpcResolver to the site's recursive resolver."
				];
			}
			{
				# Certificate-only control auth is cogbox-host.nix's posture,
				# but that file cannot stop a composed fleet profile from adding
				# an AuthorizedKeysCommand, which sshd consults when the
				# certificate is refused. On a shared L2 that command's key
				# fetch and its answer are reachable by neighbours, so a
				# published PVE image refuses one outright.
				assertion = !caBaked || config.services.openssh.authorizedKeysCommand == "none";
				message = lib.concatStringsSep "\n\n" [
					"cogworx.pve: this image bakes a control CA while services.openssh.authorizedKeysCommand = \"${config.services.openssh.authorizedKeysCommand}\"."
					"sshd consults that command whenever a control certificate is refused, which adds a second way into the trusted half that does not go through the control CA."
					"Force it off in the bake: services.openssh.authorizedKeysCommand = lib.mkOverride 40 \"none\" (a fleet profile may already set it with mkForce, so a second mkForce would conflict)."
				];
			}
			{
				# Console autologin is the one gate with an escape, and it is an
				# explicit operator opt-in: a site may keep a root console as its
				# break-glass path, but never by accident. No warning either way
				# (a composed image's verification pins warnings == [ ]).
				assertion = !caBaked || config.services.getty.autologinUser == null || cfg.allowConsoleAutologin;
				message = lib.concatStringsSep "\n\n" [
					"cogworx.pve: this image bakes a control CA while services.getty.autologinUser = \"${toString config.services.getty.autologinUser}\"."
					"Console autologin on ttyS0 gives a root shell -- the trusted half -- to every PVE principal with VM.Console on this VM and to root on its node."
					"Either set services.getty.autologinUser = null, or, where a root console is the site's break-glass policy, opt in explicitly with cogworx.pve.allowConsoleAutologin = true."
				];
			}
		];

		warnings = lib.optional (linkLocal gce.vpcResolver)
			"cogworx.pve: cogworx.gce.vpcResolver (${gce.vpcResolver}) is link-local, and on Proxmox nothing serves DNS there; this image will resolve no names. Set it to the site's recursive resolver.";
	};
}
