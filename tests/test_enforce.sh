#!/usr/bin/env bash
# Behavioural test for cogbox-enforce.sh, the SEPARATE enforcer pod's PID1
# supervisor. Its first-ever test: everything that matters in this file is an
# ORDERING or a REFUSAL that no static artifact (the unit file, the pod spec)
# can show, which is exactly why the auth-proxy third `wait -n` arm shipped
# invisible in review until this existed. What is covered:
#
#   - all THREE children (mitmdump, the auth proxy, l7proxy) are started, in the
#     order start_l7mitm -> publish_ca -> start_l7auth -> start_l7proxy;
#   - each of the three is restarted INDEPENDENTLY by the wait -n loop -- kill
#     one, and exactly that one respawns (a new pid) while the other two keep
#     theirs. The auth-proxy arm is the correctness obligation of the whole
#     change: omit it and the enforcer runs without the auth proxy after one
#     crash, so every migrated git provider fails closed with no self-heal;
#   - terminate() kills all THREE;
#   - COGBOX_L7_AUTH_PORT and COGBOX_L7_AUTH_HOSTS are passed to mitmdump EVEN
#     WHEN the l7-auth-hosts file does not exist -- the :93-102 bug re-asserted
#     for the new vars (blanking a runtime path wedges the addon reader);
#   - the supervisor never writes a PID into $RUNTIME/authproxy.pid, but does
#     PRE-CREATE it EMPTY on every (re)start, mirroring the VM launcher. That
#     file is the auth proxy's v1 health signal, whose contents the Zig side
#     writes only after its listener bound and its first conf parse succeeded;
#     a pid the script wrote from $! would name a process that may already have
#     died on a bind failure. The cogbox stub here never writes it, so a
#     non-empty file at any point would prove the script did -- and a restart
#     must truncate a stale pid away rather than leave it to be read as live;
#   - 6. a PRESENT-but-unrenderable config (here 0 bytes) does NOT kill PID1:
#     the old `|| die` exited 70 -> CrashLoopBackOff -> no kubectl exec, so the
#     control plane could never re-courier. The supervisor must move it aside to
#     config.json.bad, keep the wire files already in $RUNTIME (last-known-good;
#     the emptyDir survives an in-pod restart) and still start all three
#     children;
#   - 7. a GOOD config is rendered and left in place (never moved aside).
#
# Usage: test_enforce.sh <path-to-cogbox-enforce.sh>
# Needs: bash, coreutils, gawk, gnugrep. NOT cogbox/mitmproxy -- both are stubs.

set -uo pipefail

SRC="${1:?usage: test_enforce.sh <cogbox-enforce.sh>}"
[ -f "$SRC" ] || { echo "FAIL: no such script: $SRC" >&2; exit 1; }

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"; [ -n "${SUP_PID:-}" ] && kill "$SUP_PID" 2>/dev/null' EXIT

fails=0
ok()  { echo "ok   - $*"; }
bad() { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

BIN="$ROOT/bin"
EVENTS="$ROOT/events"
RT="$ROOT/rt"
CAPUB="$ROOT/capub"
CACONF="$ROOT/caconf"
mkdir -p "$BIN" "$RT" "$CAPUB" "$CACONF"
: > "$EVENTS"

BASH_BIN=$(command -v bash)
shebang() { printf '#!%s\n' "$BASH_BIN"; }

# The cogbox stub: __render-rules records the call and then, like the real
# renderer on unparseable JSON, fails unless the config ($2) starts with '{';
# __l7proxy / __authproxy record a start line (with role + pid) and then become a
# long-lived, killable process so `wait -n` has something to wait on and a kill
# triggers exactly one restart.
{ shebang; cat <<'STUB'
verb="${1:-}"
case "$verb" in
	__render-rules)
		echo "render $*" >> "$EVENTS"
		grep -q '^{' "$2" 2>/dev/null || { echo "error: InvalidJson" >&2; exit 1; }
		exit 0 ;;
	__l7proxy)   role=l7proxy ;;
	__authproxy) role=authproxy ;;
	*) echo "cogbox-unknown $*" >> "$EVENTS"; exit 0 ;;
esac
echo "start $role pid=$$" >> "$EVENTS"
exec sleep 300
STUB
} > "$BIN/cogbox-stub"

# The mitmdump stub: records the env vars the supervisor passed (assertion 4),
# mints the CA cert publish_ca waits on, then stays alive + killable.
{ shebang; cat <<'STUB'
confdir=""
for a in "$@"; do
	case "$a" in confdir=*) confdir="${a#confdir=}" ;; esac
done
{
	echo "start mitm pid=$$"
	echo "mitm-env AUTH_PORT=${COGBOX_L7_AUTH_PORT-<unset>}"
	echo "mitm-env AUTH_HOSTS=${COGBOX_L7_AUTH_HOSTS-<unset>}"
	echo "mitm-env INJECT_CONF=${COGBOX_L7_INJECT_CONF-<unset>}"
} >> "$EVENTS"
# Mint the CA cert publish_ca blocks on (cert only, no private key).
[ -n "$confdir" ] && printf 'FAKE CA CERT\n' > "$confdir/mitmproxy-ca-cert.pem"
exec sleep 300
STUB
} > "$BIN/mitmdump-stub"

chmod 0755 "$BIN"/*

# A copy of the supervisor with the substitution points and the hardcoded
# contract mount paths pointed at the test tree. sed only the path CONSTANTS and
# the @...@ slots -- never the logic under test.
SUP="$ROOT/enforce.sh"
sed \
	-e "s#@cogbox@#$BIN/cogbox-stub#g" \
	-e "s#@mitmdump@#$BIN/mitmdump-stub#g" \
	-e "s#@l7addon@#/dev/null#g" \
	-e "s#^RUNTIME=/run/cogbox-rt#RUNTIME=$RT#" \
	-e "s#^CAPUB_DIR=/run/cogbox-capub#CAPUB_DIR=$CAPUB#" \
	-e "s#^CA_CONF=/run/cogbox-ca-conf#CA_CONF=$CACONF#" \
	"$SRC" > "$SUP"

# Run the supervisor. XDG_CONFIG_HOME points at a tree with NO config.json for
# this instance, so the render is skipped (default-deny) -- and, deliberately,
# NO l7-auth-hosts file exists in $RT, so assertion 4 exercises the absent-file
# path. The instance name is passed as $1.
# EVENTS is exported so the backgrounded stub children (separate processes the
# supervisor spawns) append to the same ordered log.
export EVENTS
PATH="$BIN:$PATH" \
XDG_CONFIG_HOME="$ROOT/config" \
COGBOX_DIVERT_PORT=18443 \
	bash "$SUP" demo > "$ROOT/out.log" 2>&1 &
SUP_PID=$!

# --- wait for all three children --------------------------------------------
wait_for() {
	local pat="$1" i
	for i in $(seq 1 100); do
		grep -q -- "$pat" "$EVENTS" && return 0
		kill -0 "$SUP_PID" 2>/dev/null || return 1
		sleep 0.1
	done
	return 1
}

if wait_for "start mitm " && wait_for "start authproxy " && wait_for "start l7proxy "; then
	ok "all three children (mitmdump, auth proxy, l7proxy) are started"
else
	bad "not all three children started; events: $(cat "$EVENTS")"
fi

# --- 1. bring-up ORDER: mitm -> publish_ca -> auth -> l7proxy ----------------
mitm_ln=$(grep -n 'start mitm ' "$EVENTS" | head -1 | cut -d: -f1)
auth_ln=$(grep -n 'start authproxy ' "$EVENTS" | head -1 | cut -d: -f1)
l7_ln=$(grep -n 'start l7proxy ' "$EVENTS" | head -1 | cut -d: -f1)
if [ -n "$mitm_ln" ] && [ -n "$auth_ln" ] && [ -n "$l7_ln" ] \
	&& [ "$mitm_ln" -lt "$auth_ln" ] && [ "$auth_ln" -lt "$l7_ln" ]; then
	ok "bring-up order is mitmdump -> auth proxy -> l7proxy"
else
	bad "bring-up order wrong (mitm=$mitm_ln auth=$auth_ln l7proxy=$l7_ln)"
fi

# publish_ca ran between mitm and l7proxy (the CA cert reached the pub dir).
if [ -s "$CAPUB/ca.crt" ]; then
	ok "publish_ca ran (the CA cert reached the publish dir)"
else
	bad "no published CA cert at $CAPUB/ca.crt"
fi

# --- 4. the two auth env vars are passed to mitmdump, file absent ------------
if [ ! -e "$RT/l7-auth-hosts" ]; then
	ok "the l7-auth-hosts file does not exist (the absent-file path is exercised)"
else
	bad "l7-auth-hosts unexpectedly exists; assertion 4 would be vacuous"
fi
ap=$(grep 'mitm-env AUTH_PORT=' "$EVENTS" | head -1)
ah=$(grep 'mitm-env AUTH_HOSTS=' "$EVENTS" | head -1)
case "$ap" in
	*"AUTH_PORT=18043"*) ok "COGBOX_L7_AUTH_PORT (base-400) is passed to mitmdump" ;;
	*) bad "COGBOX_L7_AUTH_PORT not passed / wrong (base 18443 -> 18043): $ap" ;;
esac
case "$ah" in
	*"AUTH_HOSTS=$RT/l7-auth-hosts"*) ok "COGBOX_L7_AUTH_HOSTS is passed even though the file is absent" ;;
	*) bad "COGBOX_L7_AUTH_HOSTS not passed unconditionally: $ah" ;;
esac

# --- helpers to read the live child pids ------------------------------------
pidof_child() { cat "$RT/$1" 2>/dev/null; }
# The auth proxy's pid comes from the EVENTS log (its stub's start line), never
# from the pid file: the supervisor pre-creates that EMPTY and never fills it
# (assertion 5 below).
auth_pid() { grep 'start authproxy pid=' "$EVENTS" | tail -1 | sed 's/.*pid=//'; }

MITM0=$(pidof_child l7mitm.pid)
AUTH0=$(auth_pid)
L70=$(pidof_child l7proxy.pid)

# Wait until $1's pidfile holds a value different from $2 (a restart landed).
wait_restart() {
	local file="$1" old="$2" i cur
	for i in $(seq 1 100); do
		cur=$(pidof_child "$file")
		[ -n "$cur" ] && [ "$cur" != "$old" ] && kill -0 "$cur" 2>/dev/null && { echo "$cur"; return 0; }
		sleep 0.1
	done
	echo ""
	return 1
}
# Same, for the auth proxy, off the events log.
wait_restart_auth() {
	local old="$1" i cur
	for i in $(seq 1 100); do
		cur=$(auth_pid)
		[ -n "$cur" ] && [ "$cur" != "$old" ] && kill -0 "$cur" 2>/dev/null && { echo "$cur"; return 0; }
		sleep 0.1
	done
	echo ""
	return 1
}

# --- 5. authproxy.pid is pre-created EMPTY, never given a pid by the script ---
# Checked now (after bring-up) and again after the restart below: the stub never
# writes it, so a non-empty file at any point means the script did; an absent
# file means the pre-create (the mirror of the launcher's
# precreate_authproxy_pidfile) is missing.
if [ -f "$RT/authproxy.pid" ] && [ ! -s "$RT/authproxy.pid" ]; then
	ok "the supervisor pre-creates authproxy.pid EMPTY and never writes a pid into it (the auth proxy owns its own health signal)"
elif [ ! -e "$RT/authproxy.pid" ]; then
	bad "the supervisor did not pre-create $RT/authproxy.pid (the enforcer path must mirror the launcher's precreate_authproxy_pidfile)"
else
	bad "the supervisor wrote a pid into $RT/authproxy.pid; its contents must be written only by the auth proxy after bind + first parse"
fi

# --- 2. independent restart: the AUTH PROXY arm (the correctness obligation) --
# Simulate the auth proxy having written its pid (as the Zig side does after
# bind + first parse): the restart arm must truncate it away, so a dead child's
# pid is never read as live.
echo "$AUTH0" > "$RT/authproxy.pid"
if [ -n "$AUTH0" ] && kill "$AUTH0" 2>/dev/null; then
	AUTH1=$(wait_restart_auth "$AUTH0")
	if [ -n "$AUTH1" ]; then
		ok "the auth proxy is restarted independently after a crash (its own wait -n arm)"
	else
		bad "the auth proxy did NOT respawn after a crash; the third wait -n arm is missing"
	fi
	# The other two kept their pids (only the killed child restarted).
	if [ "$(pidof_child l7mitm.pid)" = "$MITM0" ] && [ "$(pidof_child l7proxy.pid)" = "$L70" ]; then
		ok "killing the auth proxy left mitmdump and l7proxy untouched"
	else
		bad "an auth-proxy crash disturbed the other children (mitm/l7proxy pid changed)"
	fi
else
	bad "could not kill the auth proxy child (pid '$AUTH0')"
fi

# ...and the mitmdump arm restarts independently too (with a re-publish).
MITM_NOW=$(pidof_child l7mitm.pid)
if [ -n "$MITM_NOW" ] && kill "$MITM_NOW" 2>/dev/null; then
	MITM1=$(wait_restart l7mitm.pid "$MITM_NOW")
	if [ -n "$MITM1" ]; then
		ok "mitmdump is restarted independently after a crash"
	else
		bad "mitmdump did NOT respawn after a crash"
	fi
else
	bad "could not kill the mitmdump child"
fi

# ...and the l7proxy arm.
L7_NOW=$(pidof_child l7proxy.pid)
if [ -n "$L7_NOW" ] && kill "$L7_NOW" 2>/dev/null; then
	L71=$(wait_restart l7proxy.pid "$L7_NOW")
	if [ -n "$L71" ]; then
		ok "l7proxy is restarted independently after a crash"
	else
		bad "l7proxy did NOT respawn after a crash"
	fi
else
	bad "could not kill the l7proxy child"
fi

# The restart path pre-created the file again, EMPTY: the pid "the Zig side"
# wrote before the crash is gone, and the script wrote none of its own.
if [ -f "$RT/authproxy.pid" ] && [ ! -s "$RT/authproxy.pid" ]; then
	ok "a restarted auth proxy gets a freshly truncated, empty pid file (a stale pid is never read as live)"
elif [ ! -e "$RT/authproxy.pid" ]; then
	bad "the restart arm did not pre-create $RT/authproxy.pid"
else
	bad "after the restart $RT/authproxy.pid still holds '$(cat "$RT/authproxy.pid")'; expected truncated (empty)"
fi

# --- 3. terminate() kills ALL THREE -----------------------------------------
MITM_F=$(pidof_child l7mitm.pid)
AUTH_F=$(auth_pid)
L7_F=$(pidof_child l7proxy.pid)
kill -TERM "$SUP_PID" 2>/dev/null
for _ in $(seq 1 50); do
	kill -0 "$SUP_PID" 2>/dev/null || break
	sleep 0.1
done
SUP_PID=""
alive=0
for pid in "$MITM_F" "$AUTH_F" "$L7_F"; do
	[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && alive=$((alive + 1))
done
if [ "$alive" -eq 0 ]; then
	ok "terminate() kills all three children (mitmdump, auth proxy, l7proxy)"
else
	bad "terminate() left $alive child(ren) alive"
fi

# --- helpers for the config-present runs (6, 7) -------------------------------
# prepare_run <tag>: a fresh tree under $ROOT/<tag> with its own RT/CAPUB/CACONF,
# EVENTS log and XDG config dir, plus a supervisor copy sed-ed exactly like the
# first run's (path CONSTANTS and @...@ slots only). Re-points the globals the
# helpers above read (RT, EVENTS) at the new tree.
prepare_run() {
	local tag="$1"
	RUN="$ROOT/$tag"
	RT="$RUN/rt"
	CAPUB="$RUN/capub"
	CACONF="$RUN/caconf"
	EVENTS="$RUN/events"
	XDG="$RUN/config"
	CFG="$XDG/cogbox/instances/demo/config.json"
	mkdir -p "$RT" "$CAPUB" "$CACONF" "$(dirname "$CFG")"
	: > "$EVENTS"
	export EVENTS
	sed \
		-e "s#@cogbox@#$BIN/cogbox-stub#g" \
		-e "s#@mitmdump@#$BIN/mitmdump-stub#g" \
		-e "s#@l7addon@#/dev/null#g" \
		-e "s#^RUNTIME=/run/cogbox-rt#RUNTIME=$RT#" \
		-e "s#^CAPUB_DIR=/run/cogbox-capub#CAPUB_DIR=$CAPUB#" \
		-e "s#^CA_CONF=/run/cogbox-ca-conf#CA_CONF=$CACONF#" \
		"$SRC" > "$RUN/enforce.sh"
}
# start_run: launch the prepared copy; SUP_PID is reused so the EXIT trap still
# kills it.
start_run() {
	PATH="$BIN:$PATH" \
	XDG_CONFIG_HOME="$XDG" \
	COGBOX_DIVERT_PORT=18443 \
		bash "$RUN/enforce.sh" demo > "$RUN/out.log" 2>&1 &
	SUP_PID=$!
}
# stop_run <label>: TERM the supervisor and assert none of its children outlive it.
stop_run() {
	local mitm auth l7 pid alive=0
	mitm=$(pidof_child l7mitm.pid)
	auth=$(auth_pid)
	l7=$(pidof_child l7proxy.pid)
	kill -TERM "$SUP_PID" 2>/dev/null
	for _ in $(seq 1 50); do
		kill -0 "$SUP_PID" 2>/dev/null || break
		sleep 0.1
	done
	SUP_PID=""
	for pid in "$mitm" "$auth" "$l7"; do
		[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && alive=$((alive + 1))
	done
	if [ "$alive" -eq 0 ]; then
		ok "$1: terminate() kills all three children"
	else
		bad "$1: terminate() left $alive child(ren) alive"
	fi
}

# --- 6. an unrenderable PRESENT config is moved aside, PID1 survives ---------
# A 0-byte config.json (a torn courier / truncated PVC file) and a runtime dir
# that already holds the last successful render, as after an in-pod restart.
prepare_run bad
: > "$CFG"
echo "allow last-good.example" > "$RT/l7-rules"
start_run
if wait_for "start mitm " && wait_for "start authproxy " && wait_for "start l7proxy "; then
	ok "6: an unrenderable config does not kill the supervisor; all three children start"
else
	bad "6: the supervisor died on an unrenderable config (CrashLoopBackOff, no exec path for the control plane); out: $(cat "$RUN/out.log")"
fi
if grep -q "^render __render-rules $CFG " "$EVENTS"; then
	ok "6: the boot render was attempted on the present config"
else
	bad "6: no boot render of $CFG; events: $(cat "$EVENTS")"
fi
if kill -0 "$SUP_PID" 2>/dev/null; then
	ok "6: the supervisor (PID1) is still alive"
else
	bad "6: the supervisor exited"
fi
if [ ! -e "$CFG" ] && [ -f "$CFG.bad" ] && [ ! -s "$CFG.bad" ]; then
	ok "6: the unrenderable config was moved aside to config.json.bad (0 bytes, kept for forensics)"
else
	bad "6: expected $CFG gone and an empty $CFG.bad (config present=$([ -e "$CFG" ] && echo y || echo n), .bad present=$([ -e "$CFG.bad" ] && echo y || echo n))"
fi
if grep -q "render of" "$RUN/out.log" && grep -q "\.bad" "$RUN/out.log"; then
	ok "6: the fallthrough is logged (render of ... moved aside to ....bad)"
else
	bad "6: the fallthrough was not logged; out: $(cat "$RUN/out.log")"
fi
if grep -qx "allow last-good.example" "$RT/l7-rules" 2>/dev/null; then
	ok "6: the wire files already in the runtime dir were kept (last-known-good, not wiped)"
else
	bad "6: the runtime dir's last-good l7-rules was cleared or replaced"
fi
stop_run "6"

# --- 7. a GOOD config is rendered and left in place --------------------------
prepare_run good
echo '{}' > "$CFG"
start_run
if wait_for "start l7proxy "; then
	ok "7: a good config boots the supervisor through to l7proxy"
else
	bad "7: the supervisor did not come up on a good config; out: $(cat "$RUN/out.log")"
fi
if grep -q "^render __render-rules $CFG " "$EVENTS"; then
	ok "7: the boot render was attempted on the good config"
else
	bad "7: no boot render of $CFG; events: $(cat "$EVENTS")"
fi
if [ -f "$CFG" ] && [ ! -e "$CFG.bad" ]; then
	ok "7: a good config stays in place (never moved aside)"
else
	bad "7: a good config was moved aside"
fi
if kill -0 "$SUP_PID" 2>/dev/null; then
	ok "7: the supervisor (PID1) is alive"
else
	bad "7: the supervisor exited on a good config"
fi
stop_run "7"

if [ "$fails" -gt 0 ]; then
	echo "$fails check(s) failed" >&2
	exit 1
fi
echo "all enforce checks passed"
