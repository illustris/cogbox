# checks.cogbox-vm phase LA: la-deny version 2 drops version 1's deny. The
# phase plants a login trap in the guest that fails while /etc/la-deny says v2,
# so the switch fails the guest's login probe (breaks_base) and the update is
# rolled back: version 1, and its deny, return.
{ ... }: {
	environment.etc."la-deny".text = "v2\n";
}
