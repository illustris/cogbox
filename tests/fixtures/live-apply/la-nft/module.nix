# checks.cogbox-vm phase LA, plan only: the firewall moved to nftables
# (network_config). Only planned, never applied.
{ ... }: {
	networking.nftables.enable = true;
}
