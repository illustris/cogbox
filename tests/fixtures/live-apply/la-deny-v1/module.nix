# checks.cogbox-vm phase LA: la-deny version 1 denies a host that a broader
# user allow covers. Its /etc file names the version.
{ ... }: {
	environment.etc."la-deny".text = "v1\n";
}
