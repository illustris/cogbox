# checks.cogbox-vm phase LA: la-kit version 4, a working update of version 2
# that a plugin change makes while version 3's live apply (unit_hang) is in its
# guest phase: it waits for that apply, version 3 is rolled back to version 2,
# and version 4 then commits from version 2 and applies live.
{ pkgs, ... }: {
	environment.systemPackages = [ pkgs.hello ];
	environment.etc."la-kit".text = "v4\n";
	systemd.services.la-kit = {
		wantedBy = [ "multi-user.target" ];
		serviceConfig = {
			Type = "oneshot";
			RemainAfterExit = true;
			ExecStart = pkgs.writeShellScript "la-kit-v4" "echo v4 > /run/la-kit-version";
		};
	};
	cogbox.skills.la-kit-skill = pkgs.writeTextDir "SKILL.md"
		"---\nname: la-kit-skill\ndescription: live-apply test skill\n---\n\nla-kit v4\n";
}
