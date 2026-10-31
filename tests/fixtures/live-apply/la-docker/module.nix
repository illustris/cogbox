# checks.cogbox-vm phase LA, plan only: a docker daemon setting, which
# restarts docker.service (disruptive_units). Only planned, never applied.
{ ... }: {
	virtualisation.docker.daemon.settings.log-level = "warn";
}
