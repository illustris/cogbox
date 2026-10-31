# checks.cogbox-vm phase LA: a user unit (etc/systemd/user). Adding it applies
# live; removing it would make switch-to-configuration's user pass stop it in
# every running user manager, which neither the host plan nor dry-activate
# shows: restart_required/restart_only_units, never overridable.
{ pkgs, ... }: {
	systemd.user.services.la-uunit = {
		wantedBy = [ "default.target" ];
		serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
	};
}
