# checks.cogbox-vm phase LA: docker is no longer started at boot. Only the
# multi-user.target.wants/docker.service link goes, so the add applies live
# (the running docker is left alone). Removing the plugin once docker is down
# brings the link back, and the switch's start of multi-user.target would
# start dockerd: an existing, unchanged unit nothing in the plan names, which
# is restart_required/disruptive_units.
{ ... }: {
	virtualisation.docker.enableOnBoot = false;
}
