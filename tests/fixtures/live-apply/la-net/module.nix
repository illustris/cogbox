# checks.cogbox-vm phase LA: a change to the uplink's .network file, which
# systemd-networkd reloads (network_config); applied only with Apply anyway,
# which then also restarts cogbox-reply-route (the repair).
{ ... }: {
	systemd.network.networks."99-ethernet-default-dhcp".dhcpV4Config.RouteMetric = 512;
}
