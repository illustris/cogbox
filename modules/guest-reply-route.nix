# Reply-via-uplink policy routing for VM guests. Imported by cogboxModules for
# target = "vm" only; the container never imports it. `ids` is flake.nix
# guestReplyRoute (mark, table, priority, link group), shared with
# checks.guest-reply-route{,-vm-only}.
#
# Why: passt keeps a remote peer's real source address on the forwarded guest
# ports (sshd 22, the app relay 8080, the mosh UDP range), and the guest routes
# its replies by the main table. Any more-specific guest route covering the
# peer's address captures them: a Docker bridge auto-assigned from its default
# pools, a VPN, kind/k3s, podman or a static route. A peer at 198.51.100.7 and
# a Docker network on 198.51.100.0/24 means the SYN-ACK goes into the bridge
# and the connecting side never sees the SSH banner.
#
# How: connections that ARRIVE on the uplink (`ct state new`) get one connmark
# bit; a `type route` output chain copies it to the packet mark, so setting it
# reroutes, and rule priority 50 sends the packet to table 1000, which holds
# the default via the DHCP gateway on the uplink (networkd also adds the lease
# prefix route and a host route to the gateway there). Guest egress,
# container egress and guest<->container traffic never carry the bit and keep
# the main table.
#
# The uplink is the networkd link group set in its own .network, matched with
# `meta iifgroup`, never an interface name: the virtio NIC's PCI-slot name
# differs between profiles (enp0s10, enp0s11, enp0s12). `Kind=!*` in that
# match already limits it to the one physical NIC (no bridges, veths, tuns).
# GatewayOnLink lets one route form serve the GCE /32 + option-121 lease, the
# PVE subnet lease and local passt/SLIRP; passt accepts anything sent out the
# uplink.
#
# Why networkd and not a script: networkd deletes routing rules and routes it
# did not configure, so a script-added rule would be wiped on any reconfigure.
# The settings merge into the nixpkgs unit under the same useNetworkd &&
# useDHCP condition that creates it, so this never renders a [Match]-less unit
# that would match every link.
#
# Fail semantics: the nft half fails open. `nft -f` is one transaction, so a
# failed unit leaves no table, the rule then matches nothing and the old
# behaviour returns; `systemctl stop cogbox-reply-route` is the kill switch (it
# deletes the table). The networkd half uses constants only; a kernel refusal
# would leave the uplink failed, which is why the VM test asserts it routable.
#
# Not covered: UDP servers bound to 0.0.0.0 (their source address is chosen
# from the main table before netfilter runs; mosh-server's default `-s` binds
# the SSH_CONNECTION address and IS covered), and IPv6 (passt runs `-4`).
#
# Leave alone: no src_valid_mark, tcp_fwmark_accept, fwmark_reflect or other
# sysctl; no networking.firewall.extraCommands or networking.nftables. No
# Requires=/RequiredBy= from networkd or sshd to this unit, Wants= only.
# Chain priorities: prerouting at mangle - 10 (after conntrack at -200),
# output at mangle + 10. Both forms were verified on the guest kernel.
ids: { config, lib, pkgs, ... }: let
	nft = "${pkgs.nftables}/bin/nft";
	ruleset = pkgs.writeText "cogbox-reply-route.nft" ''
		table ip cogbox_reply {}
		delete table ip cogbox_reply
		table ip cogbox_reply {
			chain prerouting {
				type filter hook prerouting priority mangle - 10; policy accept;
				meta iifgroup ${toString ids.group} ct state new ct mark set ct mark or ${ids.mark} counter
			}
			chain output {
				type route hook output priority mangle + 10; policy accept;
				ct mark and ${ids.mark} != 0 meta mark set meta mark or ${ids.mark} counter
			}
		}
	'';
in {
	config = lib.mkIf (config.networking.useNetworkd && config.networking.useDHCP) {
		systemd.network.networks."99-ethernet-default-dhcp" = {
			linkConfig.Group = ids.group;
			routes = [ { Gateway = "_dhcp4"; GatewayOnLink = true; Table = ids.table; } ];
			routingPolicyRules = [ {
				FirewallMark = "${ids.mark}/${ids.mark}";
				Table = ids.table;
				Priority = ids.priority;
				Family = "ipv4";
			} ];
		};
		systemd.services.cogbox-reply-route = {
			description = "Route replies to uplink-initiated connections back out the uplink";
			wantedBy = [ "sysinit.target" ];
			wants = [ "network-pre.target" ];
			after = [ "systemd-modules-load.service" "nftables.service" ];
			before = [ "network-pre.target" "shutdown.target" ];
			conflicts = [ "shutdown.target" ];
			unitConfig.DefaultDependencies = false;
			serviceConfig = {
				Type = "oneshot";
				RemainAfterExit = true;
				ExecStart = "${nft} -f ${ruleset}";
				ExecStop = "-${nft} delete table ip cogbox_reply";
			};
		};
	};
}
