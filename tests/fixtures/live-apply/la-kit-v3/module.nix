# checks.cogbox-vm phase LA: la-kit version 3, a broken update of version 2. It
# adds a oneshot that never finishes starting (a oneshot has no start timeout),
# so the switch waits on its start job until the apply unit's bound kills it:
# the guest reports unit_hang and the host rolls the update back to version 2.
{ pkgs, ... }: {
	environment.systemPackages = [ pkgs.hello ];
	environment.etc."la-kit".text = "v3\n";
	systemd.services.la-kit = {
		wantedBy = [ "multi-user.target" ];
		serviceConfig = {
			Type = "oneshot";
			RemainAfterExit = true;
			ExecStart = pkgs.writeShellScript "la-kit-v3" "echo v3 > /run/la-kit-version";
		};
	};
	systemd.services.la-kit-wait = {
		wantedBy = [ "multi-user.target" ];
		serviceConfig = {
			Type = "oneshot";
			ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
		};
	};
	cogbox.skills.la-kit-skill = pkgs.writeTextDir "SKILL.md"
		"---\nname: la-kit-skill\ndescription: live-apply test skill\n---\n\nla-kit v3\n";
}
