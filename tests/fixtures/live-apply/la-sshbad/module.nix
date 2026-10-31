# checks.cogbox-vm phase LA: an option sshd does not know, in a file that
# sshd_config includes. The build's sshd config check runs without that file
# (an Include that matches nothing is skipped), so the system builds; in the
# guest sshd's restart fails and so does `sshd -t`. Applied anyway (sshd is
# forced), the base checks still answer breaks_base and the change is rolled
# back.
{ ... }: {
	services.openssh.extraConfig = "Include /etc/ssh/la-sshbad.conf\n";
	environment.etc."ssh/la-sshbad.conf".text = "LaSshBadOption yes\n";
}
