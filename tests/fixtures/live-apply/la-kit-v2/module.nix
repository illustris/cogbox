# checks.cogbox-vm phase LA: la-kit version 2, an update of every part of
# version 1 (the service's unit changes, so the switch restarts it).
{ pkgs, ... }: {
	environment.systemPackages = [ pkgs.hello ];
	environment.etc."la-kit".text = "v2\n";
	systemd.services.la-kit = {
		wantedBy = [ "multi-user.target" ];
		serviceConfig = {
			Type = "oneshot";
			RemainAfterExit = true;
			ExecStart = pkgs.writeShellScript "la-kit-v2" "echo v2 > /run/la-kit-version";
		};
	};
	cogbox.skills.la-kit-skill = pkgs.writeTextDir "SKILL.md"
		"---\nname: la-kit-skill\ndescription: live-apply test skill\n---\n\nla-kit v2\n";
}
