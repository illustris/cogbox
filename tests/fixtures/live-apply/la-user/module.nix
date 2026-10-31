# checks.cogbox-vm phase LA: a change to user@.service, which a switch never
# restarts (restartIfChanged = false): skipped_units, never overridable.
{ ... }: {
	systemd.services."user@".environment.LA_USER = "1";
}
