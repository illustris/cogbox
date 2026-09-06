#!/usr/bin/env bash
# Synchronous ExecStop. The executable argument is fixed by the Nix unit, not
# metadata. No network or credentials are needed to stop the captured guest.
set -euo pipefail
runtime=${XDG_RUNTIME_DIR:?}
record="$runtime/cogworx-supervisor-instance"
stopping="$runtime/cogworx-supervisor-stopping"
umask 077
: > "$stopping"
# Serialize against start admission. An in-flight slow start gets an explicit
# bounded failure, then the unit's cgroup backstop, never a false graceful pass.
exec 9> "$runtime/cogworx-supervisor-start.lock"
if ! flock -w 1 9; then
	echo 'cogworx-supervisor: start still in progress; guest shutdown unconfirmed' >&2
	exit 1
fi
if [ ! -e "$record" ]; then
	echo 'cogworx-supervisor: no guest admitted for this run'
	exit 0
fi
instance=$(< "$record")
if [[ ! "$instance" =~ ^[a-zA-Z][a-zA-Z0-9-]{0,63}$ ]] || [ "$instance" = default ]; then
	echo 'cogworx-supervisor: invalid stop identity; guest shutdown unconfirmed' >&2
	exit 1
fi
# The CLI's classified result goes to the journal, even if the log-tail unit
# has already stopped. Do not emit raw runtime/QMP data or write to serial.
exec "${1:?trusted cogbox executable required}" stop --name "$instance" 9>&-
