# cogworx-pve-floor.service -- the SITE floor: nft table inet cogworx_pve_floor,
# rules 4a and 4, loaded beside gce/floor.nix's own table and verified before
# any sandbox starts.
#
# WHY A SECOND TABLE. gce/floor.nix is the guest-isolation floor and is
# provider-neutral (rules 1-3: link-local for passt, the VM's own addresses,
# loopback). What GCE's VPC firewall supplied around it -- which internal
# networks a guest may reach -- has no provider equivalent on a shared PVE L2
# segment, so the image carries it. (Who may reach the VM is deliberately not
# filtered: the internal network is trusted, decision 2026-10-21; see
# floor_render.py's "No ingress filter".) A drop in either table is
# final, so this one can only narrow what gce/floor.nix admits, and gce/ stays
# unchanged. The rules, and why each is shaped as it is, are written down in
# floor_render.py, which renders them from the cogworx.pve.floor options at
# BUILD time and refuses (fails the build on) a CIDR that is not IPv4, is wider
# than /8, or overlaps 127/8, 169.254/16 or 0/8.
#
# The publish gate -- infraDenyCIDRs non-empty on a CA-baked image, with no
# escape -- is a pve-host.nix assertion, evaluated before anything is built.
# So is the warning for a controlPlaneCIDRs entry wide enough to take part of
# infraDenyCIDRs out of rule 4.
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

	range = lo: width: [ lo (lo + width - 1) ];
	# passt's `-u` forward (gce/supervisor.nix COGBOX_MOSH_UDP_FORWARD, from
	# gce/cogbox-host.nix moshUDPPort/moshUDPPortRange): rule 4 accepts
	# passt's reply sockets bound to it towards @cp.
	moshRange = range gce.moshUDPPort gce.moshUDPPortRange;

	# The renderer's input. The mosh range is READ from the options that
	# decide it, so rule 4's mosh accept cannot drift from what passt binds.
	spec = {
		version = 1;
		iface = cfg.interface;
		controlPlaneCIDRs = floor.controlPlaneCIDRs;
		infraDenyCIDRs = floor.infraDenyCIDRs;
		infraAllow = map (a: { inherit (a) address protocol port; }) floor.infraAllow;
		passtUser = gce.passtUser;
		proxyUser = gce.proxyUser;
		buildGroup = config.nix.settings.build-users-group or "nixbld";
		moshUDP = [ moshRange ];
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
			echo "cogworx-pve-floor: ruleset loaded (rule 4a: link-local for local root only; rule 4: ${toString (builtins.length floor.infraDenyCIDRs)} internal range(s) closed to guest, proxy and nix-build-user traffic, ${toString (builtins.length floor.infraAllow)} exception(s), and its @cp accept limited to passt's mosh replies; no ingress filter)"
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
			build_group=${lib.escapeShellArg spec.buildGroup}
			if id -u "''${build_group}1" >/dev/null 2>&1; then
				expect blocked "rule 4a, nix build user" "''${build_group}1" "$build_group" 169.254.169.254 80
			else
				echo "cogworx-pve-floor: no ''${build_group}1 account on this image; the build-user probe is skipped (nobody's probe covers the same rule)"
			fi

			if [ "$fails" -gt 0 ]; then
				echo "cogworx-pve-floor: $fails probe(s) failed; the sandbox must not start" >&2
				exit 1
			fi
			echo "cogworx-pve-floor: rule 4a verified (root reaches the metadata emulator; nobody and the build users are dropped)"
		'';
	};
in
{
	config = {
		cogworx.pve.floor.ruleset = ruleset;

		boot.kernelModules = [ "nf_tables" "nf_conntrack" "nft_ct" ];

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
			}) cfg.metadataClients;
	};
}
