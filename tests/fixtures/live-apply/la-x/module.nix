# checks.cogbox-vm phase LA: the plugin la-guard depends on (its /etc file).
{ ... }: {
	environment.etc."la-x".text = "x\n";
}
