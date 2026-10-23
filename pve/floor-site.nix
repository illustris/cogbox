# cogworx-pve-floor.service -- the SITE floor: nft table inet cogworx_pve_floor,
# rules 4a and 4 (rule 4 names the nix build users only), loaded beside
# gce/floor.nix's own table and verified before any sandbox starts.
#
# WHY A SECOND TABLE. gce/floor.nix is the guest-isolation floor and is
# provider-neutral (rules 1-3: link-local for passt, the VM's own addresses,
# loopback). This table carries rule 4a, the non-root link-local block the
# metadata emulator needs (on PVE 169.254.169.254 is a local emulator that
# answers only root, where GCE has a real metadata server), and rule 4, which
# keeps the nix build users off the site's internal ranges, off the local
# hops that would dial them on a build user's behalf, and off broadcast and
# multicast, which would solicit a flow from them. Which internal networks
# a GUEST may reach is the sandbox's own network rules' business, as on GCE
# (decision 2026-10-22; floor_render.py's "No internal-range egress filter"),
# and who may reach the VM is deliberately not filtered: the internal network
# is trusted (decision 2026-10-21; "No ingress filter"). A drop in either
# table is final, so this one can only narrow what gce/floor.nix admits, and
# gce/ stays unchanged. The rules, and why each is shaped as it is, are
# written down in floor_render.py, which renders them from the
# cogworx.pve.floor options at BUILD time and refuses (fails the build on) a
# CIDR that is not IPv4, is wider than /8, or overlaps 127/8, 169.254/16 or
# 0/8, and a spec key it does not know.
#
# The publish gate -- infraDenyCIDRs non-empty on a CA-baked image, with no
# escape -- is a pve-host.nix assertion, evaluated before anything is built.
# The assertions below also hold cogworx.gce.l7PortBase to the launcher's
# built-in L7 base and the l7PortTriples window inside the port range, on
# every image: rule 4's hop block is placed from the launcher's base.
#
# Rule 4a drops every NON-ROOT socket towards 169.254.0.0/16, and the emulator
# answers only peer uid 0, so every metadata client must run as root: asserted
# below over cogworx.pve.metadataClients. Rule 4a also drops, on input,
# anything for 169.254.0.0/16 that did not arrive on lo: the emulator's address
# is scope host on lo, but Linux's weak host model would otherwise deliver a
# frame for it that a neighbour sends to eth0 (metadata.nix).
{
	config,
	lib,
	pkgs,
	...
}:
let
	cfg = config.cogworx.pve;
	floor = cfg.floor;
	gce = config.cogworx.gce;
	buildGroup = config.nix.settings.build-users-group or "nixbld";

	# Rule 4's local hops (floor_render.py says why). First the loopback TCP
	# ports of the trusted half's L7 relays, over the same l7PortTriples
	# window gce/floor.nix rule 3 admits the funnel over (cogbox-launch.sh
	# slides the base by 3 when a triple is taken). Each triple is l7proxy's
	# two front doors and the mitmproxy SOCKS5 hop (base, +1, +2), and each
	# auth proxy listens 400 below its triple's base: two contiguous bands.
	#
	# The base is the LAUNCHER's, and no option moves it: cogbox-launch.sh
	# seeds an instance at 18443 (INIT_L7, and `.l7PortBase // 18443` for an
	# older config.json) and puts the auth proxy at base - 400, mirroring
	# zig/src/filter.zig's l7_default_base and l7_auth_port_offset. Nothing
	# passes cogworx.gce.l7PortBase to the launcher; that option only mirrors
	# the base, for gce/floor.nix's funnel window and probes. So the two
	# literals below mirror the launcher, checks.nix reads both facts back
	# from its sources and compares the realized ruleset against them, and
	# an assertion below holds the option to the same base.
	launcherL7Base = 18443;
	launcherAuthOffset = 400;
	span = 3 * gce.l7PortTriples;
	authBase = launcherL7Base - launcherAuthOffset;
	l7Bands = [
		[ authBase (authBase + span - 1) ]
		[ launcherL7Base (launcherL7Base + span - 1) ]
	];
	# Then the bake's own loopback agents that act for unauthenticated local
	# clients (buildDenyLoopbackTCP). Sorted, and merged where two ranges
	# overlap or touch, so the renderer's ascending-and-disjoint check holds
	# whatever a bake lists, and however many triples the window spans (past
	# 133 the auth band runs into the triple band).
	mergeRanges = rs: lib.foldl' (acc: r:
		let last = lib.last acc; in
		if acc != [ ] && builtins.head r <= lib.last last + 1
		then lib.init acc ++ [ [ (builtins.head last) (lib.max (lib.last last) (lib.last r)) ] ]
		else acc ++ [ r ]) [ ] (lib.sort (a: b: builtins.head a < builtins.head b) rs);
	hopTCP = mergeRanges (l7Bands ++ floor.buildDenyLoopbackTCP);
	# And the bake's UDP agents of that kind (buildDenyLoopbackUDP), on their
	# own: the L7 relays are TCP only. May be empty.
	hopUDP = mergeRanges floor.buildDenyLoopbackUDP;

	# The renderer's input. Nothing names the passt or the L7-proxy uid: the
	# guest and the L7 proxy follow each sandbox's own network rules.
	spec = {
		version = 1;
		iface = cfg.interface;
		infraDenyCIDRs = floor.infraDenyCIDRs;
		infraAllow = map (a: { inherit (a) address protocol port; }) floor.infraAllow;
		inherit buildGroup hopTCP hopUDP;
	};

	ruleset = pkgs.runCommand "cogworx-pve-floor.nft" {
		nativeBuildInputs = [ pkgs.python3 ];
		spec = builtins.toJSON spec;
		passAsFile = [ "spec" ];
	} ''
		python3 -I ${./floor_render.py} "$specPath" > $out
	'';

	install = pkgs.writeShellApplication {
		name = "cogworx-pve-floor-install";
		runtimeInputs = [ pkgs.nftables ];
		text = ''
			nft -f ${ruleset}
			echo "cogworx-pve-floor: ruleset loaded (rule 4a: link-local for local root only; rule 4: ${toString (builtins.length floor.infraDenyCIDRs)} internal range(s), the local L7 hops, ${toString (builtins.length floor.buildDenyLoopbackTCP)} other loopback TCP and ${toString (builtins.length floor.buildDenyLoopbackUDP)} loopback UDP listener range(s), and broadcast and multicast closed to the nix build users, ${toString (builtins.length floor.infraAllow)} exception(s); the guest and the L7 proxy follow each sandbox's own network rules; no ingress filter)"
		'';
	};

	# Positive verification, in gce/floor.nix's discipline: the probe that can
	# show the rule is MISSING runs against a real listener, the metadata
	# emulator's own socket (metadata.nix orders this unit After= and
	# Requires= it), so "blocked" can only mean the drop and never "nothing is
	# listening".
	verify = pkgs.writeShellApplication {
		name = "cogworx-pve-floor-verify";
		runtimeInputs = [ pkgs.util-linux pkgs.coreutils pkgs.bash ];
		text = ''
			# gce/floor.nix's classifier: a DROP times out (124), a reachable
			# port without a listener answers RST at once.
			probe() {
				local user="$1" group="$2" addr="$3" port="$4" rc=0
				if [ "$user" = root ]; then
					timeout 3 bash -c "exec 3<>/dev/tcp/$addr/$port" >/dev/null 2>&1 || rc=$?
				else
					setpriv --reuid "$user" --regid "$group" --clear-groups -- \
						timeout 3 bash -c "exec 3<>/dev/tcp/$addr/$port" >/dev/null 2>&1 || rc=$?
				fi
				case "$rc" in
					0) echo open ;;
					124) echo blocked ;;
					*) echo refused ;;
				esac
			}
			fails=0
			expect() {
				local want="$1" what="$2" got
				got=$(probe "$3" "$4" "$5" "$6")
				if [ "$got" != "$want" ]; then
					echo "cogworx-pve-floor: PROBE FAILED: $what ($3 -> $5:$6) was $got, expected $want" >&2
					fails=$((fails + 1))
				fi
			}

			# The listener is up and root reaches it: without this, the two
			# denies below could pass on an emulator that is simply absent.
			expect open "rule 4a, root reaches the metadata emulator" root root 169.254.169.254 80
			# Every other uid is dropped -- the generic account, and the nix
			# build users (the daemon's builders for plugin derivations).
			expect blocked "rule 4a, nobody" nobody nogroup 169.254.169.254 80
			build_group=${lib.escapeShellArg buildGroup}
			# Rule 4's local hop block, on the mitmproxy hop of the first
			# triple. Nothing listens there yet (the relays start with the
			# supervisor, ordered after this unit), so without the drop the
			# connect is refused at once and with it the SYN times out: no
			# listener is needed to tell the two apart. Root's probe of the
			# same port is the control: anything but "blocked" (refused, or
			# open should something listen) shows the drop is the build
			# group's alone. Rule 4's other drops (internal ranges, the UDP
			# hops, broadcast and multicast) are not probed at boot; the
			# floor-site check runs them live, and this leg itself.
			mitm=${toString (launcherL7Base + 2)}
			got=$(probe root root 127.0.0.1 "$mitm")
			if [ "$got" = blocked ]; then
				echo "cogworx-pve-floor: PROBE FAILED: rule 4 hop control (root -> 127.0.0.1:$mitm) was blocked; root must reach the local hops" >&2
				fails=$((fails + 1))
			fi
			if id -u "''${build_group}1" >/dev/null 2>&1; then
				expect blocked "rule 4a, nix build user" "''${build_group}1" "$build_group" 169.254.169.254 80
				expect blocked "rule 4, nix build user to the mitmproxy hop" "''${build_group}1" "$build_group" 127.0.0.1 "$mitm"
			else
				echo "cogworx-pve-floor: no ''${build_group}1 account on this image; the build-user probes are skipped (nobody's probe covers rule 4a; rule 4's hop block is unverified)"
			fi

			if [ "$fails" -gt 0 ]; then
				echo "cogworx-pve-floor: $fails probe(s) failed; the sandbox must not start" >&2
				exit 1
			fi
			echo "cogworx-pve-floor: rules 4a and 4 verified (root reaches the metadata emulator and the local hop port; nobody and the build users are dropped towards link-local, and the build users towards the mitmproxy hop)"
		'';
	};
in
{
	config = {
		cogworx.pve.floor.ruleset = ruleset;

		# nft_fib_inet for rule 4's broadcast drop (`fib daddr type`), named
		# for the reason gce/floor.nix names nft_ct.
		boot.kernelModules = [ "nf_tables" "nf_conntrack" "nft_ct" "nft_fib_inet" ];

		systemd.services.cogworx-pve-floor = {
			description = "Install and verify the cogworx PVE site floor (nftables)";
			wantedBy = [ "multi-user.target" ];
			# Ahead of sshd and the supervisor (passt's forwards, the guest,
			# the L7 proxy). The metadata socket edges come from metadata.nix:
			# the verify leg probes the emulator.
			before = [ "sshd.service" "cogworx-supervisor.service" ];
			# And sshd REQUIRES it: fail closed by policy, as cogbox-host.nix
			# does for the control principal. A VM whose floor failed to load
			# or verify is unusable anyway -- the supervisor Requires= it --
			# so it is left without sshd too, and the serial console stays as
			# break-glass.
			requiredBy = [ "sshd.service" ];
			serviceConfig = {
				Type = "oneshot";
				RemainAfterExit = true;
				ExecStart = "${install}/bin/cogworx-pve-floor-install";
				ExecStartPost = "${verify}/bin/cogworx-pve-floor-verify";
			};
		};

		# Requires=, not merely After=, for gce/floor.nix's reason: a sandbox
		# must not start on a VM whose floor did not load and verify.
		systemd.services.cogworx-supervisor = {
			requires = [ "cogworx-pve-floor.service" ];
			after = [ "cogworx-pve-floor.service" ];
		};

		assertions = map (unit:
			let
				sc = config.systemd.services.${unit}.serviceConfig or { };
			in
			{
				assertion = !(sc ? User) && !(sc ? DynamicUser && sc.DynamicUser != false);
				message = "cogworx.pve: ${unit} talks to the metadata emulator but sets ${if sc ? User then "User=${toString sc.User}" else "DynamicUser="}. The emulator answers only peer uid 0, and floor rule 4a drops every non-root socket towards 169.254.0.0/16, so it would fail closed at runtime. Metadata clients run as root.";
			}) cfg.metadataClients
		++ [
			{
				# Every image: the option is a mirror, and a moved mirror would
				# put gce/floor.nix's funnel window where no relay listens.
				assertion = gce.l7PortBase == launcherL7Base;
				message = "cogworx.pve: cogworx.gce.l7PortBase is ${toString gce.l7PortBase}, not ${toString launcherL7Base}. The option only mirrors cogbox's built-in L7 base: cogbox-launch.sh seeds every instance at ${toString launcherL7Base} (zig/src/filter.zig l7_default_base) and nothing passes the option to it. Floor rule 4's hop block is placed from the launcher's base, and with the option moved gce/floor.nix's L7 funnel window and its probes would sit on ports no relay uses. Leave it at its default.";
			}
			{
				assertion = launcherL7Base + span - 1 <= 65535;
				message = "cogworx.pve: cogworx.gce.l7PortTriples is ${toString gce.l7PortTriples}: that many triples from the L7 base ${toString launcherL7Base} end at port ${toString (launcherL7Base + span - 1)}, past 65535, so floor rule 4 cannot cover the window. Lower it.";
			}
		];
	};
}
