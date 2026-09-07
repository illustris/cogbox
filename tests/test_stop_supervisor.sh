#!/usr/bin/env bash
# Execute the actual synchronous ExecStop without a host service or VM.
set -euo pipefail
stop_script=${1:?stop-supervisor.sh required}
supervise_script=${2:?supervise.sh required}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export XDG_RUNTIME_DIR="$work/run"
mkdir -p "$XDG_RUNTIME_DIR"
export STOP_EVENTS="$work/events"
stub="$work/cogbox"
printf '#!%s\n' "$(command -v bash)" > "$stub"
cat >> "$stub" <<'STUB'
printf '%s\n' "$*" >> "$STOP_EVENTS"
sleep 0.1
echo 'instance stopped; clean guest shutdown could not be verified, recent writes might have been lost'
exit "${STOP_EXIT:-0}"
STUB
chmod +x "$stub"
record="$XDG_RUNTIME_DIR/cogworx-supervisor-instance"

bash "$stop_script" "$stub" > "$work/no-guest"
[ ! -e "$STOP_EVENTS" ]
grep -q 'no guest admitted' "$work/no-guest"
[ -f "$XDG_RUNTIME_DIR/cogworx-supervisor-stopping" ]
echo 'ok - no guest is an explicit safe no-op'

printf 'demo\n' > "$record"
bash "$stop_script" "$stub" > "$work/normal"
[ "$(< "$STOP_EVENTS")" = 'stop --name demo' ]
grep -q 'clean guest shutdown could not be verified' "$work/normal"
echo 'ok - exact captured instance and synchronous classified output'

for invalid in default '../demo' '-n other' 'demo; echo injected'; do
	printf '%s\n' "$invalid" > "$record"
	if bash "$stop_script" "$stub" > "$work/invalid" 2>&1; then
		echo 'FAIL - invalid instance admitted' >&2; exit 1
	fi
done
[ "$(wc -l < "$STOP_EVENTS")" -eq 1 ]
echo 'ok - malformed identity never selects a guest or default'

printf 'demo\n' > "$record"
if STOP_EXIT=70 bash "$stop_script" "$stub" > "$work/failed" 2>&1; then
	echo 'FAIL - CLI failure swallowed' >&2; exit 1
fi
echo 'ok - CLI failure propagates to systemd'

# The actual start-admission lock cannot block host shutdown indefinitely.
exec 8> "$XDG_RUNTIME_DIR/cogworx-supervisor-start.lock"
flock -x 8
started=$SECONDS
if bash "$stop_script" "$stub" 8>&- > "$work/in-flight" 2>&1; then
	echo 'FAIL - in-flight startup reported stopped' >&2; exit 1
fi
[ "$((SECONDS - started))" -le 3 ]
grep -q 'start still in progress' "$work/in-flight"
echo 'ok - in-flight startup fails explicitly within bounded admission wait'
exec 8>&-

# Execute the actual start-admission function after ExecStop wins the race.
# The stop marker, checked INSIDE its lock, must prevent a late guest spawn.
eval "$(sed -n '/^start_sandbox() {/,/^}/p' "$supervise_script")"
INSTANCE=demo
STOP_INSTANCE="$record"
STOPPING="$XDG_RUNTIME_DIR/cogworx-supervisor-stopping"
start_args=(start --no-ssh -y -n demo)
cogbox() { "$stub" "$@"; }
before=$(wc -l < "$STOP_EVENTS")
if start_sandbox 9> "$XDG_RUNTIME_DIR/cogworx-supervisor-start.lock"; then
	echo 'FAIL - late start admitted after synchronous stop' >&2; exit 1
fi
[ "$(wc -l < "$STOP_EVENTS")" -eq "$before" ]
echo 'ok - stop-before-start admission prevents a late guest launch'
