# checks.cogbox-vm phase LA: la-kit version 5, version 2 with sshd refusing
# every root login (DenyUsers). sshd restarts (disruptive_units); applied
# anyway, `sshd -t` and the guest's login probe (runuser, which does not use
# sshd) still pass, while every new ssh connection is refused, the host's
# confirm included. Connections already open survive (KillMode=process), so
# only a fresh connection sees it, and the dead-man reverts the guest.
{ pkgs, ... }: {
	environment.systemPackages = [ pkgs.hello ];
	environment.etc."la-kit".text = "v5\n";
	systemd.services.la-kit = {
		wantedBy = [ "multi-user.target" ];
		serviceConfig = {
			Type = "oneshot";
			RemainAfterExit = true;
			ExecStart = pkgs.writeShellScript "la-kit-v5" "echo v5 > /run/la-kit-version";
		};
	};
	services.openssh.settings.DenyUsers = [ "root" ];
	cogbox.skills.la-kit-skill = pkgs.writeTextDir "SKILL.md"
		"---\nname: la-kit-skill\ndescription: live-apply test skill\n---\n\nla-kit v5\n";
}
