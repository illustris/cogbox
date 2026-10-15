#!/usr/bin/env bash
# Behavioural test for cogworx-pve-self-refresh (pve/self-refresh.sh): the
# per-boot refresh of cogbox's write-once .bindAddr and .network.selfAddrs.
#
# The metadata emulator is a file:// tree (real curl, no network), the same seam
# tests/test_floor.sh uses for gce/floor.nix; the state disk is a temp dir.
#
#   1. a changed lease rewrites bindAddr, UNIONS selfAddrs, keeps every other
#      key and the file's mode, writes cogbox's own format (jq --tab), and emits
#      one classified serial line;
#   2. an unchanged lease does not rewrite the file at all;
#   3. first boot (no config.json) is a no-op that creates nothing;
#   4. full/none mode (.network is a string) refreshes bindAddr only;
#   5. the read-modify-write happens UNDER cogbox's config lock: a concurrent
#      holder's edit survives (and, as the negative control, a copy of the
#      script with the flock removed loses it);
#   6. a held lock past the wait fails loudly and leaves the file untouched;
#   7. every failure (no instance, no address, a bad address, a bad name,
#      invalid JSON) fails loudly, leaves the file untouched and emits a
#      FAILED serial line.
#
# Usage: test_self_refresh.sh [SCRIPT]
#   SCRIPT is the realized cogworx-pve-self-refresh (checks.nix passes it), or
#   by default ../self-refresh.sh run with bash. Needs bash, curl, jq, flock and
#   coreutils on PATH (the realized script brings its own).

set -uo pipefail

fails=0
ok()  { echo "ok   - $*"; }
bad() { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCRIPT="${1:-$HERE/../self-refresh.sh}"
[ -r "$SCRIPT" ] || { echo "FAIL: not readable: $SCRIPT" >&2; exit 1; }

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

MD="$ROOT/md"
CONF="$ROOT/config"
SERIAL="$ROOT/serial.log"
CFG="$CONF/cogbox/instances/demo/config.json"
LOCK="$CONF/cogbox/.locks/demo.lock"

# Metadata: $1 instance name (ABSENT for none), $2 address (ABSENT for none).
metadata() {
	rm -rf "$MD"
	mkdir -p "$MD/instance/attributes" "$MD/instance/network-interfaces/0"
	[ "$1" = ABSENT ] || printf '%s' "$1" > "$MD/instance/attributes/cogworx-instance"
	[ "$2" = ABSENT ] || printf '%s' "$2" > "$MD/instance/network-interfaces/0/ip"
}
# A config.json the way `cogbox init` writes one (jq --tab), rules mode.
seed() {
	rm -rf "$CONF"
	mkdir -p "$(dirname "$CFG")"
	jq -n --tab '{
		vcpu: 2, mem: 8192, sshPort: 2223, httpPort: 8081, l7PortBase: 18446,
		overlaySize: "128M", bindAddr: "192.0.2.10",
		network: { rules: [ { deny: "10.0.0.0/8", comment: "RFC1918 private" } ],
			implicitDns: false, dnsHost: "127.0.0.53", selfAddrs: [ "192.0.2.10/32" ] }
	}' > "$CFG"
	chmod 0640 "$CFG"
}
run() {
	local script="${RUN_SCRIPT:-$SCRIPT}"
	: > "$SERIAL"
	COGWORX_MD_BASE="file://$MD" XDG_CONFIG_HOME="$CONF" COGWORX_SERIAL="$SERIAL" \
		COGWORX_REFRESH_ATTEMPTS=2 COGWORX_REFRESH_RETRY_SLEEP=0 \
		COGWORX_REFRESH_LOCK_WAIT="${LOCK_WAIT:-10}" \
		bash "$script" > "$ROOT/out" 2>&1
}
others() { jq -S 'del(.bindAddr) | if (.network | type) == "object" then del(.network.selfAddrs) else . end' "$1"; }

# --- 1. a changed lease --------------------------------------------------------
metadata demo 192.0.2.20
seed
cp "$CFG" "$ROOT/before.json"
if run; then ok "a changed lease refreshes (rc 0)"; else bad "a changed lease failed: $(cat "$ROOT/out")"; fi
if [ "$(jq -r .bindAddr "$CFG")" = 192.0.2.20 ]; then
	ok "bindAddr is the new address"
else
	bad "bindAddr is $(jq -r .bindAddr "$CFG")"
fi
if [ "$(jq -c .network.selfAddrs "$CFG")" = '["192.0.2.10/32","192.0.2.20/32"]' ]; then
	ok "selfAddrs is the UNION, old entry first"
else
	bad "selfAddrs is $(jq -c .network.selfAddrs "$CFG")"
fi
if [ "$(others "$CFG")" = "$(others "$ROOT/before.json")" ]; then
	ok "every other key is untouched"
else
	bad "other keys changed: $(diff <(others "$ROOT/before.json") <(others "$CFG"))"
fi
if [ "$(jq --tab . "$CFG")" = "$(cat "$CFG")" ]; then
	ok "the file is in cogbox's own format (jq --tab)"
else
	bad "the file is not jq --tab formatted"
fi
if [ "$(stat -c %a "$CFG")" = 640 ]; then
	ok "the file's mode is preserved"
else
	bad "mode is $(stat -c %a "$CFG")"
fi
if grep -qx 'cogworx: bindAddr refreshed to 192.0.2.20 (was 192.0.2.10)' "$SERIAL"; then
	ok "one classified serial line names the change"
else
	bad "serial: $(cat "$SERIAL")"
fi
left=$(find "$(dirname "$CFG")" -name 'config.json.*')
if [ -z "$left" ]; then
	ok "no temp file left behind"
else
	bad "a temp file was left behind: $left"
fi
if [ -f "$LOCK" ] && [ "$(stat -c %a "$LOCK")" = 600 ]; then
	ok "the config lock file is cogbox's (0600)"
else
	bad "lock file: $(ls -l "$LOCK" 2>&1)"
fi

# --- 2. an unchanged lease -----------------------------------------------------
ino=$(stat -c %i "$CFG")
if run; then ok "an unchanged lease succeeds"; else bad "an unchanged lease failed: $(cat "$ROOT/out")"; fi
if [ "$(stat -c %i "$CFG")" = "$ino" ]; then
	ok "...without rewriting the file"
else
	bad "the file was rewritten for a no-op"
fi
if [ "$(jq -c .network.selfAddrs "$CFG")" = '["192.0.2.10/32","192.0.2.20/32"]' ]; then
	ok "...and selfAddrs gains no duplicate"
else
	bad "selfAddrs is $(jq -c .network.selfAddrs "$CFG")"
fi
if [ ! -s "$SERIAL" ]; then
	ok "...and writes nothing to serial"
else
	bad "a no-op wrote to serial: $(cat "$SERIAL")"
fi

# --- 3. first boot -------------------------------------------------------------
rm -rf "$CONF"
metadata demo 192.0.2.20
if run; then ok "first boot (no config.json) is a no-op (rc 0)"; else bad "first boot failed: $(cat "$ROOT/out")"; fi
if [ ! -e "$CONF" ]; then
	ok "...and creates nothing (cogbox init records the address)"
else
	bad "first boot created state: $(find "$CONF")"
fi

# --- 4. full/none mode ---------------------------------------------------------
seed
jq --tab '.network = "none"' "$CFG" > "$CFG.x" && mv "$CFG.x" "$CFG"
if run; then ok "none mode refreshes"; else bad "none mode failed: $(cat "$ROOT/out")"; fi
if [ "$(jq -r .bindAddr "$CFG")" = 192.0.2.20 ] && [ "$(jq -c .network "$CFG")" = '"none"' ]; then
	ok "...bindAddr only; the bare-string .network is left alone"
else
	bad "none mode result: $(cat "$CFG")"
fi

# --- 5. under the config lock --------------------------------------------------
# A concurrent cogbox mutation: takes the lock, reads config.json, takes a
# second, writes its edit back. The refresh starts while it holds the lock.
holder() {
	flock "$LOCK" bash -c '
		c=$(cat "$1"); touch "$2"; sleep 1
		printf "%s\n" "$c" | jq --tab ".holder = 1" > "$1.h" && mv "$1.h" "$1"
	' _ "$CFG" "$ROOT/held" &
	HPID=$!
	for _ in $(seq 50); do [ -e "$ROOT/held" ] && return 0; sleep 0.1; done
	bad "the lock holder never took the lock"
}
locked_case() {
	seed
	mkdir -p "$(dirname "$LOCK")"
	rm -f "$ROOT/held"
	holder
	run || true
	wait "$HPID"
}
locked_case
if [ "$(jq -r .holder "$CFG")" = 1 ] && [ "$(jq -r .bindAddr "$CFG")" = 192.0.2.20 ]; then
	ok "the refresh waits for cogbox's config lock: the concurrent edit AND the refresh both survive"
else
	bad "a concurrent edit was lost: $(jq -c '{holder, bindAddr}' "$CFG")"
fi
# NEGATIVE CONTROL: the same script with its flock removed loses the update.
sed 's/flock -w "\$LOCK_WAIT" "\$lockfd"/true/' "$SCRIPT" > "$ROOT/unlocked.sh"
if cmp -s "$SCRIPT" "$ROOT/unlocked.sh"; then
	bad "the negative control's sed did not apply; the flock line changed shape"
else
	RUN_SCRIPT="$ROOT/unlocked.sh" locked_case
	if [ "$(jq -r .holder "$CFG")" = 1 ] && [ "$(jq -r .bindAddr "$CFG")" = 192.0.2.10 ]; then
		ok "NEGATIVE CONTROL: without the flock the refresh is silently overwritten (the case above is not vacuous)"
	else
		bad "the unlocked variant did not lose the update; the lock case proves nothing: $(jq -c '{holder, bindAddr}' "$CFG")"
	fi
fi

# --- 6. a held lock past the wait ---------------------------------------------
seed
mkdir -p "$(dirname "$LOCK")"
cp "$CFG" "$ROOT/before.json"
flock "$LOCK" sleep 4 &
HPID=$!
sleep 0.3
if LOCK_WAIT=1 run; then bad "a held lock did not fail the refresh"; else ok "a lock held past the wait fails the refresh"; fi
wait "$HPID"
if cmp -s "$CFG" "$ROOT/before.json"; then
	ok "...and leaves config.json untouched"
else
	bad "config.json changed without the lock"
fi
if grep -q '^cogworx: FAILED: bindAddr refresh: could not take the cogbox config lock' "$SERIAL"; then
	ok "...with a FAILED serial line"
else
	bad "serial: $(cat "$SERIAL")"
fi

# --- 7. loud failures ---------------------------------------------------------
fails_untouched() {
	local what="$1" want="$2"
	if run; then
		bad "$what: succeeded"
	elif ! cmp -s "$CFG" "$ROOT/before.json"; then
		bad "$what: config.json changed"
	elif ! grep -q "^cogworx: FAILED: bindAddr refresh: $want" "$SERIAL"; then
		bad "$what: no matching FAILED serial line: $(cat "$SERIAL")"
	else
		ok "$what fails loudly and leaves config.json untouched"
	fi
}
seed; cp "$CFG" "$ROOT/before.json"
metadata ABSENT 192.0.2.20;   fails_untouched "no cogworx-instance" "could not read cogworx-instance"
metadata demo ABSENT;         fails_untouched "no address" "the metadata emulator named no IPv4 address"
metadata demo 192.0.2.300;    fails_untouched "an out-of-range address" "the metadata emulator's address"
metadata demo 'not-an-ip';    fails_untouched "a non-address" "the metadata emulator's address"
metadata '../etc' 192.0.2.20; fails_untouched "a traversal instance name" "invalid instance name"
metadata default 192.0.2.20;  fails_untouched "the reserved instance name" "invalid instance name"
metadata demo 192.0.2.20
printf '{ not json' > "$CFG"; cp "$CFG" "$ROOT/before.json"
fails_untouched "an invalid config.json" "config.json for demo is not valid JSON"

if [ "$fails" -gt 0 ]; then
	echo "test_self_refresh: $fails failure(s)" >&2
	exit 1
fi
echo "test_self_refresh: all passed"
