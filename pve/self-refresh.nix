# cogworx-pve-self-refresh.service -- refresh cogbox's write-once bindAddr and
# selfAddrs to this boot's DHCP address, ordered BEFORE the supervisor. The
# reasoning lives in self-refresh.sh; this file is the unit and its edges.
#
#   After= network-online.target   the lease is what is being recorded
#   RequiresMountsFor= the state   config.json lives on the state disk; on the
#                     disk mount   boot disk it would be the wrong file
#   After=/Requires= the metadata  the address and instance name come from the
#                     socket       emulator (metadata.nix adds both edges)
#   Before= cogworx-supervisor     `cogbox start` reads .bindAddr at launch
#
# The supervisor Wants= it rather than Requires= it: a failed refresh is loud
# (journal + a classified serial line) but must not stop a sandbox whose
# address did not change from starting at all.
{
	config,
	lib,
	pkgs,
	...
}:
let
	gce = config.cogworx.gce;

	refresh = pkgs.writeShellApplication {
		name = "cogworx-pve-self-refresh";
		runtimeInputs = [ pkgs.curl pkgs.jq pkgs.coreutils pkgs.util-linux ];
		text = builtins.readFile ./self-refresh.sh;
	};
in
{
	config = {
		systemd.services.cogworx-pve-self-refresh = {
			description = "Refresh cogbox's recorded bindAddr to this boot's DHCP address";
			wantedBy = [ "multi-user.target" ];
			after = [ "network-online.target" ];
			wants = [ "network-online.target" ];
			before = [ "cogworx-supervisor.service" ];
			unitConfig.RequiresMountsFor = gce.stateDir;
			environment = {
				# The same three paths the supervisor runs with, so this edits
				# the config.json `cogbox start` is about to read.
				XDG_CONFIG_HOME = "${gce.stateDir}/config";
				COGWORX_STATE_DIR = gce.stateDir;
				COGWORX_SERIAL = gce.serialDevice;
			};
			serviceConfig = {
				Type = "oneshot";
				RemainAfterExit = true;
				ExecStart = "${refresh}/bin/cogworx-pve-self-refresh";
			};
		};

		systemd.services.cogworx-supervisor = {
			after = [ "cogworx-pve-self-refresh.service" ];
			wants = [ "cogworx-pve-self-refresh.service" ];
		};
	};
}
