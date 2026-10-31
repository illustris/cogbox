# checks.cogbox-vm phase LA: an activation snippet that hangs once la-x's
# /etc file is gone, so removing la-x live is rejected (activation_hang) and
# rolled back: la-x is reinserted.
{ pkgs, ... }: {
	system.activationScripts.la-guard = {
		deps = [ "etc" ];
		text = "[ -e /etc/la-x ] || ${pkgs.coreutils}/bin/sleep infinity";
	};
}
