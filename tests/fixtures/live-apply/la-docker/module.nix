# checks.cogbox-vm phase LA: a docker daemon setting. docker.service is
# socket-activated, so the switch stops it and restarts docker.socket
# (disruptive_units); applied only with Apply anyway.
{ ... }: {
	virtualisation.docker.daemon.settings.log-level = "warn";
}
