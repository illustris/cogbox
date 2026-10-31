# checks.cogbox-vm phase LA: a new mount unit. Mounts are restart-only
# (restart_only_units, never overridable).
{ ... }: {
	systemd.mounts = [ {
		what = "tmpfs";
		where = "/mnt/la-mount";
		type = "tmpfs";
		wantedBy = [ "multi-user.target" ];
	} ];
}
