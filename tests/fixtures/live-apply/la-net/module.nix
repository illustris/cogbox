# checks.cogbox-vm phase LA, plan only: a change to the uplink's .network
# file, which systemd-networkd reloads (network_config). Only planned, never
# applied.
{ ... }: {
	systemd.network.networks."99-ethernet-default-dhcp".dhcpV4Config.RouteMetric = 512;
}
