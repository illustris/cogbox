# checks.cogbox-vm phase LA: refuses every ssh login at PAM's account stage.
# The switch changes no unit sshd restarts for (only /etc/pam.d/sshd), and the
# guest's own login probe (runuser) does not use the sshd stack, so the guest
# reports the switch good; only the host's confirm, on a fresh ssh connection,
# finds it cannot get in, and the dead-man reverts the guest.
{ pkgs, ... }: {
	security.pam.services.sshd.rules.account.la-lock = {
		order = 0;
		control = "requisite";
		modulePath = "${pkgs.pam}/lib/security/pam_deny.so";
	};
}
