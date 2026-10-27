# Reply-via-uplink policy routing (modules/guest-reply-route.nix) in a real
# cogbox VM guest behind passt, which keeps a client's source address on the
# forwarded ports. The outer machine owns a client address (198.51.100.7) and
# the guest gets a Docker network on 198.51.100.0/24, with a netns peer at that
# same address: without the fix the guest's replies to the client go into the
# bridge. Proves that, with the fix:
#
#   - ssh (TCP 22), the app relay (TCP 8080) and a mosh-range UDP responder
#     bound to the uplink address all answer the colliding client, and passt
#     really did keep the source (SSH_CONNECTION, the UDP echo);
#   - guest egress to the colliding subnet still reaches the Docker side, the
#     netns peer still reaches the guest, and uplink egress is unchanged;
#   - each half is load-bearing: stopping the unit (the nft table) and deleting
#     the networkd rule each bring the failure back, and both recover;
#   - restarting systemd-networkd, docker and the firewall keeps it working.
#
# Needs KVM: `nix build .#checks.x86_64-linux.guest-reply-route`.
{ self, pkgs, ids }:
let
	moshRange = import ../mosh-udp-range.nix;
in
{
	name = "cogbox-guest-reply-route";

	nodes.machine = { config, lib, ... }: {
		virtualisation = {
			cores = 4;
			memorySize = 8192;
			diskSize = 8192;
			qemu.options = [ "-cpu" "host" ];
		};

		boot.kernelModules = [ "kvm-intel" "kvm-amd" ];

		# socat is also run INSIDE the guest by its store path, which the guest
		# sees through the read-only 9p store share.
		environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.cogbox ]
			++ (with pkgs; [ openssh jq socat curl iproute2 ]);

		users.users.testuser = {
			isNormalUser = true;
			uid = 1000;
			home = "/home/testuser";
			password = "";
			extraGroups = [ "kvm" ];
		};

		# `systemd-run --uid=testuser`-style runs have no logind session, so
		# /run/user/1000 is never created; cogbox's XDG runtime path needs it.
		systemd.tmpfiles.rules = [
			"d /run/user/1000 0700 testuser users -"
		];

		programs.ssh.extraConfig = ''
			Host 127.0.0.1
				StrictHostKeyChecking no
				UserKnownHostsFile /dev/null
				LogLevel ERROR
		'';
	};

	# The driver is a column-0 .py file: Nix strips only space indentation from
	# '' strings, and this file is indented with tabs.
	testScript = "MARK = '${ids.mark}'\nTABLE = ${toString ids.table}\nPRIO = ${toString ids.priority}\nGROUP = ${toString ids.group}\nSOCAT = '${pkgs.socat}/bin/socat'\nMOSH_RANGE = '${toString moshRange.port}-${toString (moshRange.port + moshRange.count - 1)}'\nUDP_PORT = ${toString (moshRange.port + 1)}\n" + builtins.readFile ./guest_reply_route_driver.py;
}
