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
#                     4a and 4, beside gce/floor.nix's own table
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

	# --- how wide @cp is, for the warnings below --------------------------------
	#
	# An address or CIDR as { addr; len; } (addr an integer), or null for
	# anything floor_render.py refuses: the build then fails with the
	# renderer's own message, so an evaluation-time warning must not throw
	# first. No leading zeros, so lib.toInt never sees an octal-looking octet.
	octet = "(0|[1-9][0-9]{0,2})";
	parseCidr = s:
		let
			m = builtins.match "${octet}\\.${octet}\\.${octet}\\.${octet}(/(0|[1-9][0-9]?))?" s;
			octets = map lib.toInt (lib.take 4 m);
			len = if builtins.elemAt m 5 == null then 32 else lib.toInt (builtins.elemAt m 5);
		in
		if m == null || lib.any (o: o > 255) octets || len > 32 then null
		else { addr = lib.foldl' (a: o: a * 256 + o) 0 octets; inherit len; };
	block = len: addr: addr / (lib.foldl' (a: _: a * 2) 1 (lib.range 1 (32 - len)));
	# `outer` equals or contains `inner`.
	covers = outer: inner: outer.len <= inner.len && block outer.len outer.addr == block outer.len inner.addr;
	parsed = l: lib.filter (p: p.net != null) (map (s: { str = s; net = parseCidr s; }) l);

	# THE @cp / RULE 4 COUPLING, what is left of it. Rule 4 accepts passt's
	# mosh reply sockets (the passt uid, UDP from the mosh range) towards @cp
	# ahead of its drops, because once conntrack forgets the inbound flow
	# those replies to the cogworxd relay are original-direction flows. The
	# floor cannot tell such a reply from a guest datagram whose source port
	# passt preserved inside that range, so whatever part of infraDenyCIDRs
	# controlPlaneCIDRs also covers is open to that one shape of guest UDP
	# (in rules mode the L4 shim denies it via the seeded private-range rules
	# unless an owner/admin L4 allow covers that @cp address). A narrow @cp
	# (the control plane's own source addresses) makes that a few hosts; a
	# wide one -- e.g. whole internal ranges admitted because the control
	# source is NATed or unstable -- extends it to all of them, and an empty
	# one removes it. Warned rather than asserted: admitting
	# internal ranges as @cp is an accepted fallback, so this is the
	# operator's call, but it must not be a silent one.
	cpCoversInfra = lib.concatMap (c:
		map (i: { cp = c.str; infra = i.str; })
			(lib.filter (i: covers c.net i.net) (parsed cfg.floor.infraDenyCIDRs)))
		(parsed cfg.floor.controlPlaneCIDRs);
	cpWide = lib.filter (c: c.net.len < 16) (parsed cfg.floor.controlPlaneCIDRs);
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
					Optional (default [ ]). The destination set (@cp) of floor
					rule 4's passt mosh-reply accept, and that is its only
					effect: the source address(es) of cogworxd's mosh relay, as
					the VM sees them. passt answers a datagram on its mosh `-u`
					forward from a per-flow socket connected to the relay, and
					for a mosh flow conntrack has forgotten that answer is an
					original-direction flow, which rule 4 drops when the relay
					sits inside infraDenyCIDRs. Listed here, those replies (the
					passt uid, UDP from the mosh range) are accepted ahead of
					rule 4's drops; every other flow rule 4 names is dropped
					towards these addresses like towards any internal address.

					[ ] leaves mosh replies to conntrack's reply direction, which
					passes them on every flow the relay opened while conntrack
					still tracks it. There is no ingress filter: the internal
					network is trusted, and nothing on the VM's input side reads
					this option.

					Keep it to the control plane's own source addresses: whatever
					part of infraDenyCIDRs it also covers is open to passt-uid UDP
					from the mosh port range. Evaluation warns when an entry
					covers a whole infraDenyCIDRs entry or is wider than /16. IPv4
					only; each entry is an address or a CIDR, at most /8 wide,
					overlapping neither 127/8, 169.254/16 nor 0/8 (floor_render.py
					refuses the build otherwise).
				'';
			};
			infraDenyCIDRs = lib.mkOption {
				type = lib.types.listOf lib.types.str;
				default = [ ];
				example = [ "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" "100.64.0.0/10" ];
				description = ''
					The site's internal ranges. Rule 4 drops NEW flows to them
					from the passt and L7-proxy uids (guest-originated traffic)
					and from the nix build users (the nixbld group, under which
					the daemon runs the builders of in-VM plugin derivations), in
					the original direction only, so replies on flows the control
					plane opened still pass. Root is outside rule 4, so root-run
					plugin evaluation and its eval-time fetches are not covered
					(README.md, residuals). The exact infraAllow sockets, and
					passt's mosh replies to controlPlaneCIDRs, are accepted ahead
					of the drops.

					REQUIRED on a published (CA-baked) image, with no escape. Same
					per-entry validation as controlPlaneCIDRs.
				'';
			};
			infraAllow = lib.mkOption {
				type = lib.types.listOf (lib.types.submodule {
					options = {
						address = lib.mkOption {
							type = lib.types.str;
							description = "One IPv4 address (a bare address or a /32) inside infraDenyCIDRs that is nevertheless reachable on this port. Not a range: list each host separately.";
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
					Exact (address, protocol, port) exceptions to rule 4, rendered
					as accepts ahead of its drops: for example an internal git
					host the guest's git grants must reach through the L7 proxy.
					One entry per socket, never a range of ports.
				'';
			};
			ruleset = lib.mkOption {
				type = lib.types.package;
				internal = true;
				readOnly = true;
				description = "The rendered nft ruleset (floor_render.py's output for the options above). Set by floor-site.nix; read by checks.nix.";
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
				# THE EGRESS GATE (no escape). Without the site's internal
				# ranges rule 4 renders no drop at all, and a guest -- or a
				# nix build user running a plugin derivation's builder -- can
				# open flows to every internal service the VM can route to.
				assertion = !caBaked || cfg.floor.infraDenyCIDRs != [ ];
				message = lib.concatStringsSep "\n\n" [
					"cogworx.pve: this image bakes a control CA -- it is meant to be PUBLISHED -- but cogworx.pve.floor.infraDenyCIDRs is empty."
					"Floor rule 4 would then drop nothing: guest traffic (the passt and L7-proxy uids) and the nix build users running in-VM plugin builds could open flows to every internal address this VM can route to."
					"Set cogworx.pve.floor.infraDenyCIDRs to the site's internal ranges, and add exact cogworx.pve.floor.infraAllow entries for the internal services the sandbox genuinely needs."
				];
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
			"cogworx.pve: cogworx.gce.vpcResolver (${gce.vpcResolver}) is link-local, and on Proxmox nothing serves DNS there; this image will resolve no names. Set it to the site's recursive resolver."
			++ map (w:
				"cogworx.pve: floor rule 4 only partly applies to infraDenyCIDRs entry ${w.infra}: controlPlaneCIDRs entry ${w.cp} covers all of it, and rule 4 accepts passt-uid UDP from the mosh port range to @cp ahead of its drops (passt's mosh replies to the cogworxd relay). A guest datagram whose source port passt preserved in that range may then reach every address in ${w.infra}. Unless that is intended, narrow controlPlaneCIDRs to the source address(es) cogworxd's control connections actually arrive from.")
				cpCoversInfra
			++ map (c:
				"cogworx.pve: controlPlaneCIDRs entry ${c.str} is wider than /16. Floor rule 4 accepts passt-uid UDP from the mosh port range to all of it, including any part that lies inside infraDenyCIDRs.")
				cpWide;
	};
}
