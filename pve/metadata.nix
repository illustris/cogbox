# The local GCE-metadata emulator: what lets ../gce/ run unchanged on PVE.
#
# Five gce/ units, and supervise.sh, address the metadata server by name
# (metadata.google.internal, pinned to 169.254.169.254 in /etc/hosts by
# cogbox-host.nix). This module puts that address on LOOPBACK and serves the
# subset they use from metadata/cogworx_pve_metadata.py, socket-activated:
#
#   cogworx-pve-md-addr.service      ip addr replace 169.254.169.254/32 scope
#                                    host dev lo; before the socket
#   cogworx-pve-metadata.socket      ListenStream=169.254.169.254:80
#   cogworx-pve-metadata.service     the emulator, handed the socket as fd 3
#
# THE ORDERING IS THE CONTRACT. cogworx-control-principal fetches the sshd
# principal ONCE (Type=oneshot, no Restart, --max-time 10) and stages an EMPTY
# principals file on failure: a principal fetch that races the emulator's
# address leaves the VM unreachable by the control plane for the whole boot.
# So every client is After= AND Requires= the socket, and the socket is
# After=/Requires= the address. checks.nix asserts each edge on the realized
# units.
#
# scope host, on lo, does NOT by itself keep the address off the shared L2.
# arp_ignore=1 (platform.nix) only stops eth0 from answering ARP for it; Linux
# uses the weak host model, so a frame a neighbour sends to this VM's MAC
# addressed to 169.254.169.254 arrives on eth0 and is accepted for local
# delivery (measured in tests/test_floor_site.sh). What keeps the emulator
# local is floor rule 4a (floor-site.nix): its input drop refuses anything
# for 169.254.0.0/16 that did not arrive on lo, its egress drop keeps a
# 169.254/16-sourced reply from leaving eth0, and its uid drop keeps every
# non-root uid on this VM away from the whole range. The emulator's peer-uid
# check is the last layer: it resolves the client socket in /proc/net/tcp,
# which has no row for a client on another machine, so a non-local client is
# refused even with the floor gone.
{
	config,
	lib,
	pkgs,
	...
}:
let
	cfg = config.cogworx.pve;
	mdAddr = "169.254.169.254";
	socketUnit = "cogworx-pve-metadata.socket";

	# -I: isolated mode -- no PYTHON* environment, no user site-packages, no
	# script directory on sys.path. The emulator is stdlib only.
	emulator = pkgs.writeShellScriptBin "cogworx-pve-metadata" ''
		exec ${pkgs.python3.interpreter} -I ${./metadata/cogworx_pve_metadata.py} "$@"
	'';

	# The gce/ units that read or write metadata over HTTP, plus this tree's
	# own. Each gets After= + Requires= the SOCKET below, never the service:
	# the emulator is socket-activated and Restart=on-failure, so a crashed
	# emulator is re-activated by the next connection and its restart never
	# propagates to the clients. The supervisor is not in this list because it
	# already depends on the socket through the floor and scrub it Requires=;
	# it gets the After= edges below for shutdown ordering.
	socketClients = [
		"cogworx-control-principal"
		"cogworx-attr-scrub"
		"cogworx-floor"
		"cogworx-resolver-deadline"
		"cogworx-cogbox-log"
		"cogworx-pve-self-refresh"
		"cogworx-pve-floor"
	];
in
{
	config = {
		cogworx.pve.metadataPackage = emulator;
		cogworx.pve.metadataClients = socketClients ++ [ "cogworx-supervisor" ];

		# The emulator's state dir: guest-attributes.json (read by cogworxd
		# through QGA file-read) and the serial log. Root-only.
		systemd.tmpfiles.rules = [ "d /run/cogworx 0700 root root -" ];

		systemd.sockets.cogworx-pve-metadata = {
			description = "PVE metadata emulator socket (${mdAddr}:80)";
			wantedBy = [ "sockets.target" ];
			requires = [ "cogworx-pve-md-addr.service" ];
			after = [ "cogworx-pve-md-addr.service" ];
			listenStreams = [ "${mdAddr}:80" ];
			# Belt for the ordering above: bind even if the address is not
			# (yet) configured, rather than fail the socket.
			socketConfig.FreeBind = true;
		};

		systemd.services = lib.mkMerge [
			(lib.genAttrs socketClients (_: {
				after = [ socketUnit ];
				requires = [ socketUnit ];
			}))
			{
				cogworx-pve-md-addr = {
					description = "Put the metadata address on loopback for the PVE metadata emulator";
					wantedBy = [ "sockets.target" ];
					before = [ socketUnit "sockets.target" "shutdown.target" ];
					conflicts = [ "shutdown.target" ];
					# Early: the socket it precedes is up before sockets.target, and PID
					# 1 has brought lo up long before any unit runs.
					unitConfig.DefaultDependencies = false;
					serviceConfig = {
						Type = "oneshot";
						RemainAfterExit = true;
						# `replace`, so a re-run is idempotent. No ExecStop: the
						# supervisor's ExecStopPost unpublishes readiness through this
						# address during shutdown, so it stays until poweroff.
						ExecStart = "${pkgs.iproute2}/bin/ip addr replace ${mdAddr}/32 scope host dev lo";
					};
				};

				cogworx-pve-metadata = {
					description = "PVE metadata emulator (GCE metadata subset on ${mdAddr})";
					requires = [ socketUnit ];
					after = [ socketUnit ];
					serviceConfig = {
						# Root, and that is required rather than tolerated: the SMBIOS
						# serial is mode 0400, and the peer-uid check reads every
						# socket's owner from /proc/net/tcp.
						ExecStart = "${emulator}/bin/cogworx-pve-metadata serve --iface ${cfg.interface} --state-dir /run/cogworx";
						Restart = "on-failure";
						RestartSec = 1;
						NoNewPrivileges = true;
						PrivateTmp = true;
						ProtectHome = true;
						ProtectSystem = "strict";
						# tmpfiles creates it (sysinit, before any socket activation).
						ReadWritePaths = [ "/run/cogworx" ];
					};
				};

				cogworx-supervisor.after = [
					socketUnit
					# Stop ordering: at shutdown the supervisor's ExecStopPost
					# DELETEs cogworx/ready, so the emulator must outlive it.
					"cogworx-pve-metadata.service"
				];
			}
		];
	};
}
