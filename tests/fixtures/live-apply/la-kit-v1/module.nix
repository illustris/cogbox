# checks.cogbox-vm phase LA: la-kit version 1. A package, an /etc file, a
# service and a skill, each of which a live apply must bring into the running
# guest. Every path is a store derivation, never a path relative to this file,
# so the plugin installed from its own flake and the flake.nix fixture that
# pre-builds its runner evaluate to the same derivations.
{ pkgs, ... }: {
	environment.systemPackages = [ pkgs.hello ];
	environment.etc."la-kit".text = "v1\n";
	systemd.services.la-kit = {
		wantedBy = [ "multi-user.target" ];
		serviceConfig = {
			Type = "oneshot";
			RemainAfterExit = true;
			ExecStart = pkgs.writeShellScript "la-kit-v1" "echo v1 > /run/la-kit-version";
		};
	};
	cogbox.skills.la-kit-skill = pkgs.writeTextDir "SKILL.md"
		"---\nname: la-kit-skill\ndescription: live-apply test skill\n---\n\nla-kit v1\n";
}
