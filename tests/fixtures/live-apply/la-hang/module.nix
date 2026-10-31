# checks.cogbox-vm phase LA: an activation snippet that never returns. A live
# apply hangs in activation until the apply unit's bound kills it: the guest
# reports activation_hang and the host rolls the add back. Never booted.
{ pkgs, ... }: {
	system.activationScripts.la-hang = "${pkgs.coreutils}/bin/sleep infinity";
}
