#!/usr/bin/env bash
# checks.live-switch-helper: the guest live switch helper (cogbox-live-switch)
# driven verb by verb against stand-ins for systemctl, systemd-run, ip, nft,
# sshd, runuser, logger, sleep and the store setup script, under a scratch
# root (the helper's COGBOX_LS_TEST_* seams). The fake toplevels' own
# switch-to-configuration is a fixture-driven script, so a test decides what
# a switch prints, exits with and changes. No unit is ever started: the tests
# run the verbs the units would run (run, settle, revert, settle-revert).
#
# usage: test_live_switch.sh HELPER
set -u
helper=$1
fails=0
bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

P_TOP=/nix/store/pppppppppppppppppppppppppppppppp-nixos-system-p
T_TOP=/nix/store/tttttttttttttttttttttttttttttttt-nixos-system-t
X_TOP=/nix/store/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-nixos-system-x
CI=/nix/store/cccccccccccccccccccccccccccccccc-closure-info
REG=$CI/registration
BOOT_REG=/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-closure-info/registration
G1=0123456789abcdef
G2=fedcba9876543210
G3=00000000000000a3
BOOT=11111111-2222-3333-4444-555555555555
OTHER_BOOT=99999999-2222-3333-4444-555555555555

# ----- stand-ins --------------------------------------------------------------
BIN=$work/bin
mkdir -p "$BIN"
stub() { { echo "#!$BASH"; cat; } > "$BIN/$1"; chmod +x "$BIN/$1"; }

stub systemctl <<'EOF'
echo "systemctl $*" >> "$FIX/calls"
args=()
for a in "$@"; do
	case $a in --no-block|--quiet|--no-legend|--plain|--full|--no-pager|--all) ;; *) args+=("$a") ;; esac
done
set -- "${args[@]}"
case $1 in
	is-system-running) cat "$FIX/system_state" 2>/dev/null || echo running ;;
	list-jobs) cat "$FIX/jobs" 2>/dev/null ;;
	list-units) cat "$FIX/units" ;;
	is-active) if grep -qxF -- "${!#}" "$FIX/down" 2>/dev/null; then exit 3; fi ;;
	show)
		[ -f "$FIX/fail.show" ] && exit 1
		while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
		shift
		for u in "$@"; do
			echo "Id=$u"
			[ -f "$FIX/inv/$u" ] && echo "InvocationID=$(< "$FIX/inv/$u")"
			[ -f "$FIX/show/$u" ] && cat "$FIX/show/$u"
			echo
		done
		;;
	restart|start|stop|kill) [ -f "$FIX/fail.systemctl.$1" ] && exit 1 ;;
esac
exit 0
EOF

stub systemd-run <<'EOF'
echo "systemd-run $*" >> "$FIX/calls"
unit="" wait=0 out=""
while [ "$#" -gt 0 ]; do
	case $1 in
		-p) case $2 in StandardOutput=truncate:*) out=${2#StandardOutput=truncate:} ;; esac; shift 2 ;;
		--unit=*) unit=${1#--unit=}; shift ;;
		--wait) wait=1; shift ;;
		-*) shift ;;
		*) break ;;
	esac
done
case $unit in
	cogbox-live-revert-*) [ -f "$FIX/fail.deadman" ] && exit 1 ;;
	cogbox-live-apply-*) [ -f "$FIX/fail.apply" ] && exit 1 ;;
esac
if [ "$wait" = 1 ]; then
	if [ -n "$out" ]; then "$@" > "$out" 2>&1; else "$@"; fi
fi
exit 0
EOF

stub ip <<'EOF'
case "$*" in
	*"addr show group"*) [ "$(cat "$FIX/net.uplink" 2>/dev/null || echo yes)" = yes ] && echo "2: eth0    inet 10.0.2.15/24 scope global eth0" ;;
	*"link show group"*) echo "2: eth0: <BROADCAST,UP> mtu 1500 group 1000" ;;
	*"route show default"*) echo "default via 10.0.2.2 dev eth0" ;;
	*"rule show pref"*) [ "$(cat "$FIX/net.rule" 2>/dev/null || echo yes)" = yes ] && echo "50: from all fwmark 0x10000000/0x10000000 lookup 1000" ;;
esac
exit 0
EOF

stub nft <<'EOF'
[ "$(cat "$FIX/net.table" 2>/dev/null || echo yes)" = yes ]
EOF

stub sshd <<'EOF'
echo "sshd $*" >> "$FIX/calls"
exit "$(cat "$FIX/sshd_rc" 2>/dev/null || echo 0)"
EOF

stub runuser <<'EOF'
echo "runuser $*" >> "$FIX/calls"
exit "$(cat "$FIX/runuser_rc" 2>/dev/null || echo 0)"
EOF

stub logger <<'EOF'
echo "$*" >> "$FIX/journal"
EOF

# The real timeout, its bound recorded ("timeout SECONDS COMMAND"); the
# command still runs with the stand-ins on PATH.
stub timeout <<'EOF'
echo "timeout $1 ${2##*/}" >> "$FIX/calls"
real=$(PATH=${PATH#"$COGBOX_LS_TEST_BIN:"} type -P timeout)
exec "$real" "$@"
EOF

stub sleep <<'EOF'
echo "sleep $*" >> "$FIX/calls"
[ -f "$FIX/on_sleep" ] && . "$FIX/on_sleep"
exit 0
EOF

# The store setup: builds the generation directory and, like the real
# script, repoints nix-store.conf at it only on success.
stub cogbox-overlay-store <<'EOF'
echo "overlay $*" >> "$FIX/calls"
[ -f "$FIX/on_overlay" ] && . "$FIX/on_overlay"
mkdir -p "$R$2"
[ -f "$FIX/fail.overlay" ] && exit 1
printf 'store = local-overlay://?lower-store=local%%3Freal%%3D/nix/.ro-store%%26state%%3D%s%%26read-only%%3Dtrue&upper-layer=/nix/.rw-store/store\n' "$2" \
	> "$R/run/cogbox/nix-store.conf"
EOF

# A fake toplevel's switch-to-configuration: each call of ACTION sources
# $FIX/<name>.<action>.<n> (the n-th call) or $FIX/<name>.<action>, which
# set out (printed to stderr), rc and activate (point the current system at
# this toplevel) and may change other fixtures.
switch_template='#!@BASH@
name=@NAME@ top=@TOP@ R=@R@ FIX=@FIX@
action=$1
echo "switch $name $action" >> "$FIX/calls"
n=$(cat "$FIX/$name.$action.count" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$FIX/$name.$action.count"
spec=$FIX/$name.$action.$n
[ -f "$spec" ] || spec=$FIX/$name.$action
out="" rc=0 activate=0
[ -f "$spec" ] && . "$spec"
[ -z "$out" ] || printf "%s\n" "$out" >&2
[ "$activate" = 1 ] && ln -sfn "$top" "$R/run/current-system"
exit "$rc"
'

mktop() { # NAME TOP
	local d=$R$2
	mkdir -p "$d/bin" "$d/etc/systemd/system"
	printf '%s' "$switch_template" | sed -e "s|@BASH@|$BASH|" -e "s|@NAME@|$1|" -e "s|@TOP@|$2|" \
		-e "s|@R@|$R|" -e "s|@FIX@|$FIX|" > "$d/bin/switch-to-configuration"
	chmod +x "$d/bin/switch-to-configuration"
}

n=0
setup() {
	n=$((n + 1))
	R=$work/root$n FIX=$work/fix$n
	export R FIX
	mkdir -p "$R/run/cogbox/once" "$R/nix/var/nix/gcroots" "$R/nix/.rw-store/store" "$R/nix/.rw-store/lower-state" \
		"$R/proc/sys/kernel/random" "$R/proc/sys/vm" "$R/etc/ssh" "$FIX/show" "$FIX/inv"
	echo "$BOOT" > "$R/proc/sys/kernel/random/boot_id"
	echo "console=ttyS0 init=$P_TOP/init regInfo=$BOOT_REG quiet" > "$R/proc/cmdline"
	: > "$R/proc/sys/vm/drop_caches"
	printf 'store = local-overlay://?lower-store=local%%3Freal%%3D/nix/.ro-store%%26state%%3D/nix/.rw-store/lower-state%%26read-only%%3Dtrue&upper-layer=/nix/.rw-store/store\n' \
	> "$R/run/cogbox/nix-store.conf"
	: > "$R/etc/ssh/sshd_config"
	ln -s "$P_TOP" "$R/run/current-system"
	ln -s "$P_TOP" "$R/run/booted-system"
	mktop p "$P_TOP"
	mktop t "$T_TOP"
	mkdir -p "$R$CI"
	printf '%s\n' "$T_TOP" "$CI" > "$R$CI/store-paths"
	: > "$R$REG"
	# The guest's units: name load active sub description.
	cat > "$FIX/units" <<-'EOF'
	sshd.service loaded active running OpenSSH Daemon
	cogbox-brain-materialize.service loaded active exited brain
	docker.service loaded active running Docker
	containerd.service loaded active running containerd
	cogbox-reply-route.service loaded active exited reply route
	nix-store.mount loaded active mounted /nix/store
	run-user-0.mount loaded active mounted /run/user/0
	multi-user.target loaded active active Multi-User
	foo.service loaded inactive dead foo
	oncey.service loaded inactive dead once
	failedy.service loaded failed failed failing
	ghost.service not-found inactive dead ghost
	EOF
	# `systemctl show` reads InvocationIDs from inv/ (a switch fixture can
	# change one with a builtin: the helper's PATH has no sed).
	printf 'FragmentPath=/etc/systemd/system/sshd.service\n' > "$FIX/show/sshd.service"
	printf 'FragmentPath=/etc/systemd/system/docker.service\nRequiredBy=foo.service\n' > "$FIX/show/docker.service"
	printf 'FragmentPath=/etc/systemd/system/containerd.service\n' > "$FIX/show/containerd.service"
	printf 'FragmentPath=/etc/systemd/system/cogbox-reply-route.service\n' > "$FIX/show/cogbox-reply-route.service"
	printf 'FragmentPath=\nSourcePath=/etc/fstab\n' > "$FIX/show/nix-store.mount"
	printf 'FragmentPath=\nSourcePath=\n' > "$FIX/show/run-user-0.mount"
	for u in sshd.service:s1 docker.service:d1 containerd.service:c1 cogbox-reply-route.service:r1 nix-store.mount:m1 run-user-0.mount:u1; do
		echo "${u#*:}" > "$FIX/inv/${u%%:*}"
	done
	printf 'Wants=foo.service oncey.service failedy.service sshd.service ghost.service\nRequires=\n' > "$FIX/show/multi-user.target"
	: > "$R/run/cogbox/once/oncey"
	# A plain successful switch to T, and back to P.
	printf 'out="activating the configuration...\nrestarting sysinit-reactivation.target"\nactivate=1\n' > "$FIX/t.test"
	printf 'out="activating the configuration..."\nactivate=1\n' > "$FIX/p.test"
	: > "$FIX/calls"
}

h() {
	COGBOX_LS_TEST_BIN=$BIN COGBOX_LS_TEST_ROOT=$R COGBOX_LS_TEST_GC_WAIT=1 "$helper" "$@" 2>> "$FIX/stderr"
}
start() { h start "$1" "$T_TOP" "$REG" --prev "$P_TOP" --boot-id "$BOOT" --bound 840 --window 960 "${@:2}"; }
status() { h status "$1" --boot-id "$BOOT" "${@:2}"; }
gd() { printf '%s' "$R/run/cogbox/live-apply/gen/$1"; }
# has OUT LINE...: every LINE is a whole line of OUT.
has() {
	local o=$1 l
	shift
	for l in "$@"; do grep -qxF -- "$l" <<< "$o" || { bad "$T: expected '$l' in: $(tr '\n' ' ' <<< "$o")"; }; done
}
hasnt() {
	local o=$1 l
	shift
	for l in "$@"; do grep -qxF -- "$l" <<< "$o" && bad "$T: unexpected '$l' in: $(tr '\n' ' ' <<< "$o")"; done
	return 0
}
framed() { # the reply contract: first line proto=2, last end=1
	[ "$(head -n 1 <<< "$1")" = proto=2 ] && [ "$(tail -n 1 <<< "$1")" = end=1 ] || bad "$T: reply not framed: $(tr '\n' ' ' <<< "$1")"
}
calls() { grep -cF -- "$1" "$FIX/calls"; }
# Put generation $1 into state $2 as if the run had got there.
force_state() {
	echo "$2" > "$(gd "$1")/state"
	[ -n "${3-}" ] && echo "$3" > "$(gd "$1")/reached"
	return 0
}

# ----- start --------------------------------------------------------------------
T="start arms the dead-man before the apply unit"
setup
o=$(start "$G1")
framed "$o"
has "$o" result=started gen=$G1 state=starting tainted=no
mapfile -t runs < <(grep '^systemd-run ' "$FIX/calls")
[ "${#runs[@]}" = 2 ] || bad "$T: expected 2 systemd-run calls, got ${#runs[@]}"
[[ ${runs[0]-} == *"--unit=cogbox-live-revert-$G1 "* && ${runs[0]-} == *"--on-active=960s"* && ${runs[0]-} == *"RuntimeMaxSec=360"* && ${runs[0]-} == *" revert $G1 --cause dead-man" ]] \
	|| bad "$T: the first unit is not the dead-man: ${runs[0]-}"
[[ ${runs[0]-} == *"ExecStopPost="*" settle-revert $G1"* ]] || bad "$T: the dead-man has no settle-revert: ${runs[0]-}"
[[ ${runs[1]-} == *"--no-block"*"--unit=cogbox-live-apply-$G1 "* && ${runs[1]-} == *"RuntimeMaxSec=840"* && ${runs[1]-} == *" run $G1 $T_TOP $REG" ]] \
	|| bad "$T: the second unit is not the apply unit: ${runs[1]-}"
[[ ${runs[1]-} == *"ExecStopPost="*" settle $G1 "* ]] || bad "$T: the apply unit has no settle: ${runs[1]-}"

T="start is idempotent for a recorded generation"
o=$(start "$G1")
has "$o" result=recorded gen=$G1 state=starting
[ "$(calls systemd-run)" = 2 ] || bad "$T: a repeated start armed units again"

T="start refuses a second generation while one is active"
o=$(start "$G2")
framed "$o"
has "$o" result=busy busy_gen=$G1
[ -e "$(gd "$G2")" ] && bad "$T: the busy start recorded $G2"
o=$(h plan "$T_TOP")
has "$o" result=busy busy_gen=$G1

T="start refuses a superseded P, a stale boot and bad arguments"
setup
ln -sfn "$X_TOP" "$R/run/current-system"
o=$(start "$G1")
has "$o" result=superseded
[ -e "$(gd "$G1")" ] && bad "$T: a superseded start recorded the generation"
[ "$(calls systemd-run)" = 0 ] || bad "$T: a superseded start armed units"
ln -sfn "$P_TOP" "$R/run/current-system"
o=$(h start "$G1" "$T_TOP" "$REG" --prev "$P_TOP" --boot-id "$OTHER_BOOT" --bound 840 --window 960)
has "$o" result=stale_boot
for argv in \
	"start nothex $T_TOP $REG --prev $P_TOP --boot-id $BOOT --bound 840 --window 960" \
	"start $G1 /tmp/evil $REG --prev $P_TOP --boot-id $BOOT --bound 840 --window 960" \
	"start $G1 $T_TOP $REG --prev $P_TOP --boot-id $BOOT --bound 840 --window 860" \
	"start $G1 $T_TOP $REG --prev $P_TOP --boot-id $BOOT --bound 840 --window 960 --repair sshd.service" \
	"status $G1" \
	"bogus"; do
	# shellcheck disable=SC2086
	o=$(h $argv); rc=$?
	[ "$rc" = 64 ] || bad "$T: '$argv' exited $rc, not 64"
	has "$o" error=usage
done
printf 'docker.service\nbad name.service\n' > "$work/force.bad"
o=$(start "$G1" --force-units "$work/force.bad"); rc=$?
[ "$rc" = 64 ] || bad "$T: a force file with a bad unit name exited $rc, not 64"
[ "$(calls systemd-run)" = 0 ] || bad "$T: a refused start armed units"

T="start refuses on a tainted guest"
setup
mkdir -p "$R/run/cogbox/live-apply"
: > "$R/run/cogbox/live-apply/tainted"
o=$(start "$G1")
has "$o" result=guest_tainted
o=$(h plan "$T_TOP")
has "$o" result=guest_tainted

T="a failed dead-man arms nothing else"
setup
: > "$FIX/fail.deadman"
o=$(start "$G1")
has "$o" result=started state=refused refusal=deadman_failed
[ "$(calls 'unit=cogbox-live-apply-')" = 0 ] || bad "$T: the apply unit started without a dead-man"

T="a failed apply unit start is refused and disarms the dead-man"
setup
: > "$FIX/fail.apply"
o=$(start "$G1")
has "$o" result=started state=refused refusal=start_failed
[ "$(calls "stop --no-block cogbox-live-revert-$G1.timer")" = 1 ] || bad "$T: the dead-man timer was not stopped"

# ----- abort tombstones -----------------------------------------------------------
T="abort of an unknown generation tombstones it"
setup
o=$(h abort "$G1" --boot-id "$BOOT")
framed "$o"
has "$o" result=tombstoned gen=$G1 state=stale
o=$(start "$G1")
has "$o" result=recorded state=stale
[ "$(calls systemd-run)" = 0 ] || bad "$T: a start after the tombstone armed units"
o=$(status "$G1")
has "$o" result=ok state=stale
o=$(start "$G2")
has "$o" result=started state=starting
o=$(status "$G3")
has "$o" result=unknown
o=$(h status "$G1" --boot-id "$OTHER_BOOT")
has "$o" result=stale_boot

# ----- run ------------------------------------------------------------------------
T="run registers, switches and waits for the confirm"
setup
start "$G1" > /dev/null
h run "$G1" "$T_TOP" "$REG"
has "$(grep '^overlay ' "$FIX/calls")" "overlay --live /nix/.rw-store/lower-state.1 $BOOT_REG $REG"
[ "$(calls 'systemctl restart nix-daemon.service')" = 1 ] || bad "$T: nix-daemon was not restarted"
[ "$(readlink "$R/nix/var/nix/gcroots/cogbox-live/$G1")" = "$T_TOP" ] || bad "$T: no guest root to T"
grep -qxF "$REG" "$R/run/cogbox/live-apply/reginfos" || bad "$T: the applied regInfo was not recorded"
grep -qF 'state%3D/nix/.rw-store/lower-state.1%26' "$R/run/cogbox/nix-store.conf" || bad "$T: the conf does not name generation 1"
[ -d "$R/nix/.rw-store/lower-state" ] || bad "$T: the boot generation (the previous one) was pruned"
o=$(status "$G1")
has "$o" result=ok state=switched reached=switched exit=0
hasnt "$o" verdict=breaks_base
o=$(status "$G1" --wait 30)
has "$o" state=switched
[ "$(calls 'sleep')" = 0 ] || bad "$T: status --wait slept on a switched generation"
o=$(h confirm "$G1" --boot-id "$BOOT")
framed "$o"
has "$o" result=confirmed state=confirmed
[ -e "$R/nix/var/nix/gcroots/cogbox-live/$G1" ] && bad "$T: the guest root outlived the confirm"
[ "$(calls "stop --no-block cogbox-live-revert-$G1.timer")" = 1 ] || bad "$T: the confirm did not disarm the dead-man"
o=$(h confirm "$G1" --boot-id "$BOOT")
has "$o" result=confirmed
# A dead-man that fires anyway, and an abort, change nothing.
h revert "$G1" --cause dead-man
h abort "$G1" --boot-id "$BOOT" > /dev/null
o=$(status "$G1")
has "$o" state=confirmed
hasnt "$o" cause=dead-man cause=aborted
[ "$(calls 'switch p test')" = 0 ] || bad "$T: a confirmed generation was reverted"

T="status --wait long-polls a starting generation"
setup
start "$G1" > /dev/null
o=$(status "$G1" --wait 3)
has "$o" state=starting
[ "$(calls 'sleep 1')" = 3 ] || bad "$T: expected 3 one-second polls, got $(calls 'sleep 1')"

T="lower DB generations: boot + applied regInfos, current and previous kept"
setup
for g in "$G1" "$G2" "$G3"; do
	start "$g" > /dev/null
	h run "$g" "$T_TOP" "$REG"
	h confirm "$g" --boot-id "$BOOT" > /dev/null
	ln -sfn "$P_TOP" "$R/run/current-system"
	echo 'activate=1' > "$FIX/t.test"
done
has "$(grep '^overlay ' "$FIX/calls")" "overlay --live /nix/.rw-store/lower-state.3 $BOOT_REG $REG"
[ -e "$R/nix/.rw-store/lower-state" ] && bad "$T: the boot generation outlived two later ones"
[ -e "$R/nix/.rw-store/lower-state.1" ] && bad "$T: generation 1 outlived generation 3"
[ -d "$R/nix/.rw-store/lower-state.2" ] && [ -d "$R/nix/.rw-store/lower-state.3" ] || bad "$T: the current or previous generation is gone"
[ "$(grep -c . "$R/run/cogbox/live-apply/reginfos")" = 1 ] || bad "$T: the applied regInfo list is not deduplicated"

T="a failed registration never costs the generation in use"
setup
for g in "$G1" "$G2" "$G3"; do
	if [ "$g" = "$G2" ]; then : > "$FIX/fail.overlay"; else rm -f "$FIX/fail.overlay"; fi
	start "$g" > /dev/null
	h run "$g" "$T_TOP" "$REG"
	h confirm "$g" --boot-id "$BOOT" > /dev/null
	ln -sfn "$P_TOP" "$R/run/current-system"
done
has "$(status "$G2")" state=refused refusal=register_failed
has "$(grep '^overlay ' "$FIX/calls")" "overlay --live /nix/.rw-store/lower-state.3 $BOOT_REG $REG"
[ -d "$R/nix/.rw-store/lower-state.1" ] || bad "$T: generation 1, current before generation 3, was pruned"
[ -e "$R/nix/.rw-store/lower-state.2" ] && bad "$T: the failed generation 2 was left behind"
[ -e "$R/nix/.rw-store/lower-state" ] && bad "$T: the boot generation outlived two later ones"
grep -qF 'state%3D/nix/.rw-store/lower-state.3%26' "$R/run/cogbox/nix-store.conf" || bad "$T: the conf does not name generation 3"

T="run refuses a busy gc.lock"
setup
start "$G1" > /dev/null
flock -x -o "$R/nix/var/nix/gc.lock" sleep 10 &
holder=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
	flock -n "$R/nix/var/nix/gc.lock" true 2>/dev/null || break
	sleep 0.1 2>/dev/null || true
done
h run "$G1" "$T_TOP" "$REG"
kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null
o=$(status "$G1")
has "$o" state=refused refusal=busy_gc
[ "$(calls 'switch t test')" = 0 ] || bad "$T: the switch ran without the registration"

T="run refuses the fallback store and hidden closure paths"
setup
start "$G1" > /dev/null
: > "$R/run/cogbox/nix-store.err"
h run "$G1" "$T_TOP" "$REG"
has "$(status "$G1")" state=refused refusal=store_fallback
setup
start "$G1" > /dev/null
echo /nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-hidden >> "$R$CI/store-paths"
h run "$G1" "$T_TOP" "$REG"
has "$(status "$G1")" state=refused refusal=store_path_hidden
[ "$(cat "$R/proc/sys/vm/drop_caches")" = 3 ] || bad "$T: no drop_caches retry"
[ "$(calls 'overlay ')" = 0 ] || bad "$T: a hidden closure was registered"
setup
start "$G1" > /dev/null
: > "$FIX/fail.overlay"
h run "$G1" "$T_TOP" "$REG"
has "$(status "$G1")" state=refused refusal=register_failed
[ -e "$R/nix/.rw-store/lower-state.1" ] && bad "$T: a failed generation was left behind"
[ -e "$R/nix/var/nix/gcroots/cogbox-live/$G1" ] && bad "$T: a refused generation kept its guest root"

T="the no-op refusals, and a failure after activation"
for case in \
	'out="Pre-switch checks failed"; rc=1|pre_switch_check' \
	'out="Warning: the new NixOS configuration has an init that is incompatible"; rc=100|init_interface' \
	'out="Could not acquire lock"; rc=11|switch_locked'; do
	setup
	start "$G1" > /dev/null
	echo "${case%|*}" > "$FIX/t.test"
	h run "$G1" "$T_TOP" "$REG"
	has "$(status "$G1")" state=refused "refusal=${case#*|}"
done
setup
start "$G1" > /dev/null
printf 'out="activating the configuration..."\nrc=1\nactivate=1\n' > "$FIX/t.test"
h run "$G1" "$T_TOP" "$REG"
o=$(status "$G1")
has "$o" state=failed verdict=exit_1 exit=1
hasnt "$o" state=refused
grep -q '^runuser ' "$FIX/calls" || bad "$T: the base was not checked after a failed switch"

T="a failure after activation that broke the base is breaks_base"
# switch-ng exits 1 when a job fails it (block_on_jobs): if the base broke
# on the way (here sshd stopped), the change must roll back, not stay for the
# next boot as exit_1 would.
setup
start "$G1" > /dev/null
printf 'out="activating the configuration..."\nrc=1\nactivate=1\necho sshd.service >> "$FIX/down"\n' > "$FIX/t.test"
h run "$G1" "$T_TOP" "$REG"
o=$(status "$G1")
has "$o" state=failed verdict=breaks_base exit=1
setup
start "$G1" > /dev/null
printf 'out="stopping the following units: a.service"\nrc=3\necho 255 > "$FIX/sshd_rc"\n' > "$FIX/t.test"
h run "$G1" "$T_TOP" "$REG"
has "$(status "$G1")" state=failed verdict=breaks_base exit=3
# Before the activation began nothing changed: the exit is reported as it is
# and the base is not probed.
setup
start "$G1" > /dev/null
printf 'out="error: something odd"\nrc=1\necho sshd.service >> "$FIX/down"\n' > "$FIX/t.test"
h run "$G1" "$T_TOP" "$REG"
has "$(status "$G1")" state=failed verdict=exit_1 exit=1
grep -q '^runuser ' "$FIX/calls" && bad "$T: the base was probed although nothing was activated"

# ----- post-checks ------------------------------------------------------------------
postcase() { # NAME SPEC EXPECTED-LINES... ($pre runs after the setup)
	T="post-check: $1"
	setup
	eval "${pre:-}"
	start "$G1" "${extra[@]}" > /dev/null < "${stdin:-/dev/null}"
	printf '%s\n' "$2" > "$FIX/t.test"
	h run "$G1" "$T_TOP" "$REG"
	o=$(status "$G1")
	shift 2
	has "$o" "$@"
}
extra=()
postcase "sshd inactive" 'activate=1; echo sshd.service >> "$FIX/down"' state=failed verdict=breaks_base
postcase "brain inactive" 'activate=1; echo cogbox-brain-materialize.service >> "$FIX/down"' state=failed verdict=breaks_base
postcase "sshd -t fails" 'activate=1; echo 255 > "$FIX/sshd_rc"' state=failed verdict=breaks_base
# `sshd -t` runs the binary of the running sshd (it serves every new login),
# not the booted system's.
T="post-check: sshd -t uses the running sshd"
setup
mkdir -p "$R/proc/4242"
printf '#!%s\necho "running-sshd $*" >> "$FIX/calls"\nexit 0\n' "$BASH" > "$R/proc/4242/exe"
chmod +x "$R/proc/4242/exe"
printf 'MainPID=4242\n' >> "$FIX/show/sshd.service"
echo 255 > "$FIX/sshd_rc"
start "$G1" > /dev/null
echo 'activate=1' > "$FIX/t.test"
h run "$G1" "$T_TOP" "$REG"
has "$(status "$G1")" state=switched
grep -q "^running-sshd -t -f $R/etc/ssh/sshd_config" "$FIX/calls" || bad "$T: the running sshd did not check the config"
grep -q '^sshd ' "$FIX/calls" && bad "$T: the booted sshd checked the config"
postcase "the login probe fails on exit 2" 'activate=1; rc=2; echo 1 > "$FIX/runuser_rc"' state=failed verdict=activation_failed
postcase "exit 2 with every check passing" 'activate=1; rc=2' state=switched exit=2
postcase "exit 4 with non-protected failures" \
	'activate=1; rc=4; out="activating the configuration...
warning: the following units failed: foo.service, bad\$(x).service, ../../etc.service"' \
	state=switched exit=4 failed_unit=foo.service
hasnt "$o" 'failed_unit=bad$(x).service' failed_unit=../../etc.service
postcase "a protected unit restarted outside the plan" \
	'activate=1; echo d2 > "$FIX/inv/docker.service"' state=failed verdict=unplanned_disruption detail=docker.service
# A plugin's own oci-containers unit is not protected; podman's daemon is.
pre='for u in podman-obs.service:o1 podman.service:p1; do
	echo "${u%%:*} loaded active running x" >> "$FIX/units"
	echo "${u#*:}" > "$FIX/inv/${u%%:*}"
	echo "FragmentPath=/etc/systemd/system/${u%%:*}" > "$FIX/show/${u%%:*}"
done'
postcase "a plugin's podman container restarted" \
	'activate=1; echo o2 > "$FIX/inv/podman-obs.service"' state=switched
postcase "podman itself restarted" \
	'activate=1; echo p2 > "$FIX/inv/podman.service"' state=failed verdict=unplanned_disruption detail=podman.service
# With no podman.socket listening, nothing activates it again: its stop counts.
postcase "podman.service stopped with no socket listening" \
	'activate=1; u=$(< "$FIX/units"); printf "%s\n" "${u//podman.service loaded active running/podman.service loaded inactive dead}" > "$FIX/units"' \
	state=failed verdict=unplanned_disruption detail=podman.service
# podman.service is socket-activated and `podman system service` exits after
# 5 s idle, so a docker-API client polling during a switch stops it (an idle
# exit), starts it (a call to the idle service) or gives it a new
# InvocationID (both). None of it is the switch's while podman.socket listens
# throughout, with the InvocationID it had before.
pre='echo "podman.socket loaded active running x" >> "$FIX/units"; echo s1 > "$FIX/inv/podman.socket"
printf "FragmentPath=/etc/systemd/system/podman.socket\n" > "$FIX/show/podman.socket"
echo "podman.service loaded active running x" >> "$FIX/units"; echo p1 > "$FIX/inv/podman.service"
printf "FragmentPath=/etc/systemd/system/podman.service\n" > "$FIX/show/podman.service"'
postcase "podman.service exited on idle during the switch" \
	'activate=1; u=$(< "$FIX/units"); u=${u//podman.service loaded active running/podman.service loaded inactive dead}
printf "%s\n" "${u//podman.socket loaded active running/podman.socket loaded active listening}" > "$FIX/units"' \
	state=switched
postcase "podman itself restarted while its socket listens" \
	'activate=1; echo p2 > "$FIX/inv/podman.service"' state=switched
# A restart of the socket itself (a new InvocationID) is no idle churn: the
# service it took down counts as well as the socket.
postcase "podman.socket restarted, and podman.service with it" \
	'activate=1; echo s2 > "$FIX/inv/podman.socket"; echo p2 > "$FIX/inv/podman.service"' \
	state=failed verdict=unplanned_disruption detail=podman.service detail=podman.socket
pre='echo "podman.socket loaded active listening x" >> "$FIX/units"; echo s1 > "$FIX/inv/podman.socket"
printf "FragmentPath=/etc/systemd/system/podman.socket\n" > "$FIX/show/podman.socket"
echo "podman.service loaded inactive dead x" >> "$FIX/units"; echo p1 > "$FIX/inv/podman.service"
printf "FragmentPath=/etc/systemd/system/podman.service\n" > "$FIX/show/podman.service"'
postcase "podman.service started while its socket listens" \
	'activate=1; u=$(< "$FIX/units"); printf "%s\n" "${u//podman.service loaded inactive dead/podman.service loaded active running}" > "$FIX/units"; echo p2 > "$FIX/inv/podman.service"' \
	state=switched
# A stopped socket keeps its last InvocationID: with nothing listening, nothing
# activates podman.service, so its restart is not idle churn.
pre='echo "podman.socket loaded inactive dead x" >> "$FIX/units"; echo s1 > "$FIX/inv/podman.socket"
printf "FragmentPath=/etc/systemd/system/podman.socket\n" > "$FIX/show/podman.socket"
echo "podman.service loaded active running x" >> "$FIX/units"; echo p1 > "$FIX/inv/podman.service"
printf "FragmentPath=/etc/systemd/system/podman.service\n" > "$FIX/show/podman.service"'
postcase "podman.service restarted while its socket is inactive" \
	'activate=1; echo p2 > "$FIX/inv/podman.service"' state=failed verdict=unplanned_disruption detail=podman.service
pre=""
postcase "a kernel-table mount came and went" \
	'activate=1; echo u2 > "$FIX/inv/run-user-0.mount"' state=switched
# The overlay preparation of every harness overlay path (onceUnits), not only
# those under /root.
pre='echo "rw-var-lib-tool.service loaded active exited rw" >> "$FIX/units"; echo w1 > "$FIX/inv/rw-var-lib-tool.service"
printf "FragmentPath=/etc/systemd/system/rw-var-lib-tool.service\n" > "$FIX/show/rw-var-lib-tool.service"'
postcase "an overlay preparation outside /root restarted" \
	'activate=1; echo w2 > "$FIX/inv/rw-var-lib-tool.service"' state=failed verdict=unplanned_disruption detail=rw-var-lib-tool.service
pre=""
# switch-to-configuration exits 4 listing every unit failed at its end.
postcase "exit 4 with a failed protected unit" \
	'activate=1; rc=4; out="activating the configuration...
warning: the following units failed: docker.service"; u=$(< "$FIX/units"); printf "%s\n" "${u//docker.service loaded active running/docker.service loaded failed failed}" > "$FIX/units"' \
	state=failed verdict=unplanned_disruption detail=docker.service
# One that failed at boot, with the InvocationID it still has, is not the switch's
# (its escaped name reaches awk unexpanded).
pre='echo "data\x2dpool.mount loaded failed failed /data" >> "$FIX/units"; echo m9 > "$FIX/inv/data\x2dpool.mount"
printf "FragmentPath=\nSourcePath=/etc/fstab\n" > "$FIX/show/data\x2dpool.mount"'
postcase "exit 4 with a protected unit that was failed before the switch" \
	'activate=1; rc=4; out="activating the configuration...
warning: the following units failed: data\x2dpool.mount, foo.service"' \
	state=switched exit=4 'failed_unit=data\x2dpool.mount'
postcase "a protected unit failed before the switch that it ran again" \
	'activate=1; rc=4; out="activating the configuration...
warning: the following units failed: data\x2dpool.mount"; echo m10 > "$FIX/inv/data\x2dpool.mount"' \
	state=failed verdict=unplanned_disruption 'detail=data\x2dpool.mount'
# zramSwap: the generator a plugin added writes dev-zram0.swap at the
# daemon-reload, and the switch's start of swap.target swaps it on. Nothing
# listed it before the switch.
pre='printf "FragmentPath=/run/systemd/generator/dev-zram0.swap\n" > "$FIX/show/dev-zram0.swap"'
postcase "a protected unit started outside the plan" \
	'activate=1; echo "dev-zram0.swap loaded active active /dev/zram0" >> "$FIX/units"; echo z1 > "$FIX/inv/dev-zram0.swap"' \
	state=failed verdict=unplanned_disruption detail=dev-zram0.swap
# An activation snippet starting the docker the user had stopped, which then fails.
pre='u=$(< "$FIX/units"); printf "%s\n" "${u//docker.service loaded active running/docker.service loaded inactive dead}" > "$FIX/units"'
postcase "a stopped protected unit an activation snippet started" \
	'activate=1; rc=4; out="activating the configuration...
warning: the following units failed: docker.service"; u=$(< "$FIX/units"); printf "%s\n" "${u//docker.service loaded inactive dead/docker.service loaded failed failed}" > "$FIX/units"; echo d2 > "$FIX/inv/docker.service"' \
	state=failed verdict=unplanned_disruption detail=docker.service
# Forced, it is the plan's.
printf 'docker.service\n' > "$work/force.docker"
extra=(--force-units "$work/force.docker")
postcase "a stopped protected unit the forced plan started" \
	'activate=1; u=$(< "$FIX/units"); printf "%s\n" "${u//docker.service loaded inactive dead/docker.service loaded active running}" > "$FIX/units"; echo d2 > "$FIX/inv/docker.service"' \
	state=switched
extra=()
# A boot oneshot that ran and exited, run again: a new InvocationID, inactive after as before.
pre='echo "cogbox-guest-dirs.service loaded inactive dead dirs" >> "$FIX/units"; echo g1 > "$FIX/inv/cogbox-guest-dirs.service"
printf "FragmentPath=/etc/systemd/system/cogbox-guest-dirs.service\n" > "$FIX/show/cogbox-guest-dirs.service"'
postcase "a protected oneshot run again outside the plan" \
	'activate=1; echo g2 > "$FIX/inv/cogbox-guest-dirs.service"' \
	state=failed verdict=unplanned_disruption detail=cogbox-guest-dirs.service
# A mount the initrd made has no InvocationID to compare; getting one is a restart.
pre='echo "-.mount loaded active mounted /" >> "$FIX/units"; printf "FragmentPath=\nSourcePath=/etc/fstab\n" > "$FIX/show/-.mount"'
postcase "a running protected unit without an InvocationID restarted" \
	'activate=1; echo r1 > "$FIX/inv/-.mount"' \
	state=failed verdict=unplanned_disruption detail=-.mount
postcase "a running protected unit without an InvocationID left alone" 'activate=1' state=switched
pre=""
# A stop: systemd keeps the last InvocationID of a unit that stays loaded, so
# only the state shows it (a plugin unit's ExecStartPre stopping a daemon, an
# activation snippet's `systemctl stop`). A startable unit's stop counts too,
# and so does a unit that is gone from the list after.
postcase "a running protected unit stopped, its InvocationID kept" \
	'activate=1; u=$(< "$FIX/units"); printf "%s\n" "${u//docker.service loaded active running/docker.service loaded inactive dead}" > "$FIX/units"' \
	state=failed verdict=unplanned_disruption detail=docker.service
postcase "a running fstab mount unmounted, its InvocationID kept" \
	'activate=1; u=$(< "$FIX/units"); printf "%s\n" "${u//nix-store.mount loaded active mounted/nix-store.mount loaded inactive dead}" > "$FIX/units"' \
	state=failed verdict=unplanned_disruption detail=nix-store.mount
postcase "a running startable protected unit stopped" \
	'activate=1; u=$(< "$FIX/units"); printf "%s\n" "${u//cogbox-reply-route.service loaded active exited/cogbox-reply-route.service loaded inactive dead}" > "$FIX/units"' \
	state=failed verdict=unplanned_disruption detail=cogbox-reply-route.service
postcase "a running protected unit gone from the list" \
	'activate=1; u=$(< "$FIX/units"); printf "%s\n" "${u//containerd.service loaded active running containerd/}" > "$FIX/units"' \
	state=failed verdict=unplanned_disruption detail=containerd.service
# The plan's classes by stem: a protected service's socket, an automount.
pre='echo "docker.socket loaded active listening sock" >> "$FIX/units"; echo k1 > "$FIX/inv/docker.socket"
printf "FragmentPath=/etc/systemd/system/docker.socket\n" > "$FIX/show/docker.socket"
echo "proc-sys-fs-binfmt_misc.automount loaded active waiting binfmt" >> "$FIX/units"; echo a1 > "$FIX/inv/proc-sys-fs-binfmt_misc.automount"
printf "FragmentPath=/etc/systemd/system/proc-sys-fs-binfmt_misc.automount\n" > "$FIX/show/proc-sys-fs-binfmt_misc.automount"'
postcase "a protected service's socket restarted" \
	'activate=1; echo k2 > "$FIX/inv/docker.socket"' state=failed verdict=unplanned_disruption detail=docker.socket
postcase "an automount stopped" \
	'activate=1; u=$(< "$FIX/units"); printf "%s\n" "${u//proc-sys-fs-binfmt_misc.automount loaded active waiting/proc-sys-fs-binfmt_misc.automount loaded inactive dead}" > "$FIX/units"' \
	state=failed verdict=unplanned_disruption detail=proc-sys-fs-binfmt_misc.automount
# A mount its running automount unmounted when idle is not the switch's.
pre='echo "proc-sys-fs-binfmt_misc.automount loaded active waiting binfmt" >> "$FIX/units"
echo "proc-sys-fs-binfmt_misc.mount loaded active mounted binfmt" >> "$FIX/units"; echo b1 > "$FIX/inv/proc-sys-fs-binfmt_misc.mount"
printf "FragmentPath=/etc/systemd/system/proc-sys-fs-binfmt_misc.mount\n" > "$FIX/show/proc-sys-fs-binfmt_misc.mount"'
postcase "a mount its running automount unmounted" \
	'activate=1; u=$(< "$FIX/units"); printf "%s\n" "${u//proc-sys-fs-binfmt_misc.mount loaded active mounted/proc-sys-fs-binfmt_misc.mount loaded inactive dead}" > "$FIX/units"' \
	state=switched
# Not the switch's: a kernel-table mount appearing, a mount its running
# automount triggered, a dbus activation.
pre='printf "FragmentPath=\nSourcePath=\n" > "$FIX/show/var-lib-docker-overlay2-x-merged.mount"
echo "proc-sys-fs-binfmt_misc.automount loaded active waiting binfmt" >> "$FIX/units"
echo "proc-sys-fs-binfmt_misc.mount loaded inactive dead binfmt" >> "$FIX/units"
printf "FragmentPath=/etc/systemd/system/proc-sys-fs-binfmt_misc.mount\n" > "$FIX/show/proc-sys-fs-binfmt_misc.mount"
printf "FragmentPath=/run/systemd/transient/dbus-:1.2-org.example.Thing@0.service\n" > "$FIX/show/dbus-:1.2-org.example.Thing@0.service"'
postcase "units the switch did not start" \
	'activate=1; u=$(< "$FIX/units"); u=${u//proc-sys-fs-binfmt_misc.mount loaded inactive dead/proc-sys-fs-binfmt_misc.mount loaded active mounted}
printf "%s\n" "$u" "var-lib-docker-overlay2-x-merged.mount loaded active mounted x" "dbus-:1.2-org.example.Thing@0.service loaded active running thing" > "$FIX/units"
echo b1 > "$FIX/inv/proc-sys-fs-binfmt_misc.mount"; echo x1 > "$FIX/inv/var-lib-docker-overlay2-x-merged.mount"; echo t1 > "$FIX/inv/dbus-:1.2-org.example.Thing@0.service"' \
	state=switched
# Without its automount running, that mount is a start outside the plan.
pre='echo "proc-sys-fs-binfmt_misc.mount loaded inactive dead binfmt" >> "$FIX/units"
printf "FragmentPath=/etc/systemd/system/proc-sys-fs-binfmt_misc.mount\n" > "$FIX/show/proc-sys-fs-binfmt_misc.mount"'
# A unit state systemd cannot report after the switch is no proof that nothing changed.
postcase "the units cannot be read after the switch" \
	'activate=1; : > "$FIX/fail.show"' state=failed verdict=unplanned_disruption detail=docker.service
postcase "a mount started with no automount running" \
	'activate=1; u=$(< "$FIX/units"); printf "%s\n" "${u//proc-sys-fs-binfmt_misc.mount loaded inactive dead/proc-sys-fs-binfmt_misc.mount loaded active mounted}" > "$FIX/units"; echo b1 > "$FIX/inv/proc-sys-fs-binfmt_misc.mount"' \
	state=failed verdict=unplanned_disruption detail=proc-sys-fs-binfmt_misc.mount
pre=""
postcase "the network got worse and stayed worse" 'activate=1; echo no > "$FIX/net.table"' state=failed verdict=breaks_base
[ "$(calls 'sleep 5')" = 1 ] || bad "$T: the network was not sampled again after 5 s"
printf 'echo yes > "$FIX/net.table"\n' > "$work/on_sleep"
postcase "the network recovered on the second sample" \
	'activate=1; echo no > "$FIX/net.table"; cp "'"$work"'/on_sleep" "$FIX/on_sleep"' state=switched

# ----- force and repair -------------------------------------------------------------
T="--force-units exempts only the listed units from the InvocationID check"
setup
echo docker.service > "$work/force"
start "$G1" --force-units - < "$work/force" > /dev/null
grep -qF "forced units: docker.service" "$FIX/journal" || bad "$T: the forced units were not journaled"
echo 'activate=1; echo d2 > "$FIX/inv/docker.service"; echo c2 > "$FIX/inv/containerd.service"' > "$FIX/t.test"
h run "$G1" "$T_TOP" "$REG"
o=$(status "$G1")
has "$o" state=failed verdict=unplanned_disruption detail=containerd.service
hasnt "$o" detail=docker.service
setup
start "$G1" --force-units "$work/force" > /dev/null
echo 'activate=1; echo d2 > "$FIX/inv/docker.service"' > "$FIX/t.test"
h run "$G1" "$T_TOP" "$REG"
has "$(status "$G1")" state=switched

T="a forced unit that failed with a healthy base"
setup
start "$G1" --force-units "$work/force" > /dev/null
printf 'activate=1; rc=4; out="activating the configuration...\nwarning: the following units failed: docker.service"\n' > "$FIX/t.test"
h run "$G1" "$T_TOP" "$REG"
has "$(status "$G1")" state=failed verdict=forced_unit_failed detail=docker.service

T="--repair restarts cogbox-reply-route after the switch and after a forced revert"
setup
start "$G1" --force-units "$work/force" --repair cogbox-reply-route.service > /dev/null
echo 'activate=1; echo r2 > "$FIX/inv/cogbox-reply-route.service"' > "$FIX/t.test"
h run "$G1" "$T_TOP" "$REG"
has "$(status "$G1")" state=switched
[ "$(calls 'systemctl restart cogbox-reply-route.service')" = 1 ] || bad "$T: no repair after the switch"
grep -n -e 'switch t test' -e 'restart cogbox-reply-route' "$FIX/calls" | head -n 1 | grep -q 'switch t test' \
	|| bad "$T: the repair ran before the switch"
o=$(h abort "$G1" --boot-id "$BOOT")
has "$o" state=reverting cause=aborted during_activation=no
h revert "$G1" --cause dead-man
has "$(status "$G1")" state=reverted cause=aborted
[ "$(calls 'systemctl restart cogbox-reply-route.service')" = 2 ] || bad "$T: no repair after the forced revert"
last_p=$(grep -n 'switch p test' "$FIX/calls" | tail -n 1 | cut -d: -f1)
last_r=$(grep -n 'restart cogbox-reply-route' "$FIX/calls" | tail -n 1 | cut -d: -f1)
[ -n "$last_p" ] && [ -n "$last_r" ] && [ "$last_p" -lt "$last_r" ] || bad "$T: the revert did not switch to P and then repair"
setup
start "$G1" --force-units "$work/force" > /dev/null
echo 'activate=1; echo r2 > "$FIX/inv/cogbox-reply-route.service"' > "$FIX/t.test"
h run "$G1" "$T_TOP" "$REG"
has "$(status "$G1")" state=failed verdict=unplanned_disruption detail=cogbox-reply-route.service
[ "$(calls 'restart cogbox-reply-route.service')" = 0 ] || bad "$T: a run without --repair restarted the reply route"

# Force relaxes only the listed units' comparisons, never a base check: a
# forced sshd may restart, but it must still run and pass `sshd -t`, and one
# whose restart failed is breaks_base, not forced_unit_failed. The list comes
# on stdin, as the host sends it.
printf 'sshd.service\n' > "$work/force.sshd"
extra=(--force-units -)
stdin=$work/force.sshd
postcase "a forced sshd with a new InvocationID" 'activate=1; echo s2 > "$FIX/inv/sshd.service"' state=switched
postcase "a forced sshd whose sshd -t fails" \
	'activate=1; echo s2 > "$FIX/inv/sshd.service"; echo 255 > "$FIX/sshd_rc"' state=failed verdict=breaks_base
postcase "a forced sshd that is down after the switch" 'activate=1; echo sshd.service >> "$FIX/down"' state=failed verdict=breaks_base
postcase "a forced sshd whose restart failed" \
	'activate=1; rc=4; out="activating the configuration...
warning: the following units failed: sshd.service"; echo sshd.service >> "$FIX/down"; echo 255 > "$FIX/sshd_rc"' \
	state=failed verdict=breaks_base exit=4
# A forced docker plan stops the socket-activated service and restarts its
# socket; unforced, each is unplanned_disruption (above).
printf 'docker.service\ndocker.socket\n' > "$work/force.docker2"
stdin=$work/force.docker2
pre='echo "docker.socket loaded active listening sock" >> "$FIX/units"; echo k1 > "$FIX/inv/docker.socket"
printf "FragmentPath=/etc/systemd/system/docker.socket\n" > "$FIX/show/docker.socket"'
postcase "a forced docker stop and socket restart" \
	'activate=1; u=$(< "$FIX/units"); printf "%s\n" "${u//docker.service loaded active running/docker.service loaded inactive dead}" > "$FIX/units"; echo k2 > "$FIX/inv/docker.socket"' \
	state=switched
grep -qF "generation $G1: forced units: docker.service docker.socket; repair: none" "$FIX/journal" || bad "$T: the forced units read from stdin were not journaled"
pre=""
extra=()
stdin=""

# ----- settle -----------------------------------------------------------------------
settlecase() { # NAME SWITCH-OUT JOBS EXPECTED-LINES...
	T="settle: $1"
	setup
	start "$G1" > /dev/null
	force_state "$G1" switching switching
	printf '%b' "$2" > "$(gd "$G1")/switch.out"
	printf '%b' "$3" > "$FIX/jobs"
	h settle "$G1"
	o=$(status "$G1")
	shift 3
	has "$o" state=reverting "$@"
	[ "$(calls "start --no-block cogbox-live-revert-$G1.service")" = 1 ] || bad "$T: the revert unit was not started"
}
settlecase "a hung activation" 'activating the configuration...\n' '' cause=activation_hang
settlecase "a hung stop" 'stopping the following units: x.service\n' '' cause=stop_hang
T="settle: a hung plugin unit"
setup
start "$G1" > /dev/null
force_state "$G1" switching switching
printf 'activating the configuration...\nrestarting sysinit-reactivation.target\n' > "$(gd "$G1")/switch.out"
# plug.service is new in T; base.service is the same in T and P; the apply
# unit's own stop job is in the list too.
printf '12 plug.service start running\n13 base.service start waiting\n14 cogbox-live-apply-%s.service stop running\n' "$G1" > "$FIX/jobs"
echo '[Service]' > "$R$T_TOP/etc/systemd/system/plug.service"
echo '[Service]' > "$R$T_TOP/etc/systemd/system/base.service"
echo '[Service]' > "$R$P_TOP/etc/systemd/system/base.service"
h settle "$G1"
o=$(status "$G1")
has "$o" state=reverting cause=unit_hang detail=plug.service
hasnt "$o" detail=base.service
T="settle: only base units pending"
setup
start "$G1" > /dev/null
force_state "$G1" switching switching
printf 'activating the configuration...\nreloading user units for root...\n' > "$(gd "$G1")/switch.out"
printf '13 base.service start waiting\n' > "$FIX/jobs"
echo '[Service]' > "$R$T_TOP/etc/systemd/system/base.service"
echo '[Service]' > "$R$P_TOP/etc/systemd/system/base.service"
h settle "$G1"
has "$(status "$G1")" state=reverting cause=switch_timeout
settlecase "no progress line" '' '' cause=switch_timeout

T="settle: an apply unit that ended before the switch"
setup
start "$G1" > /dev/null
h settle "$G1"
has "$(status "$G1")" state=refused refusal=run_failed
T="settle: a failed generation reverts with its verdict"
setup
start "$G1" > /dev/null
echo 'activate=1; echo sshd.service >> "$FIX/down"' > "$FIX/t.test"
h run "$G1" "$T_TOP" "$REG"
h settle "$G1"
o=$(status "$G1")
has "$o" state=reverting verdict=breaks_base
hasnt "$o" cause=dead-man
T="settle: a switched generation waits for the confirm"
setup
start "$G1" > /dev/null
h run "$G1" "$T_TOP" "$REG"
h settle "$G1"
has "$(status "$G1")" state=switched

# ----- abort and revert ---------------------------------------------------------------
T="abort during registration reverts without a switch"
setup
start "$G1" > /dev/null
o=$(h abort "$G1" --boot-id "$BOOT")
framed "$o"
has "$o" result=ok state=reverting cause=aborted during_activation=no
[ "$(calls "start --no-block cogbox-live-revert-$G1.service")" = 1 ] || bad "$T: the abort did not start the revert"
# A run that starts after it does nothing.
h run "$G1" "$T_TOP" "$REG"
[ "$(calls 'switch t test')" = 0 ] || bad "$T: the run switched after the abort"
[ "$(calls 'overlay ')" = 0 ] || bad "$T: the run registered after the abort"
h revert "$G1" --cause dead-man
o=$(status "$G1")
has "$o" state=reverted cause=aborted
[ "$(calls 'switch p test')" = 0 ] || bad "$T: a generation that never switched ran P's switch"
[ "$(calls "systemctl stop cogbox-live-apply-$G1.service")" = 1 ] || bad "$T: the revert did not stop the apply unit"

T="an abort that lands during the registration stops the run before the switch"
setup
start "$G1" > /dev/null
printf '"%s" abort %s --boot-id %s > /dev/null\n' "$helper" "$G1" "$BOOT" > "$FIX/on_overlay"
h run "$G1" "$T_TOP" "$REG"
[ "$(calls 'overlay ')" = 1 ] || bad "$T: the registration did not run"
[ "$(calls 'switch t test')" = 0 ] || bad "$T: the run switched after the abort"
has "$(status "$G1")" state=reverting cause=aborted during_activation=no

T="a revert unit that cannot be started is replaced by a transient one"
setup
start "$G1" > /dev/null
: > "$FIX/fail.systemctl.start"
o=$(h abort "$G1" --boot-id "$BOOT")
has "$o" state=reverting cause=aborted
grep -q "^systemd-run .*--unit=cogbox-live-revert-$G1-now .*RuntimeMaxSec=360.* revert $G1\$" "$FIX/calls" \
	|| bad "$T: no transient revert after the dead-man's unit failed to start"

T="abort during the switch notes the running activation"
setup
start "$G1" > /dev/null
force_state "$G1" switching switching
o=$(h abort "$G1" --boot-id "$BOOT")
has "$o" state=reverting cause=aborted during_activation=yes
h revert "$G1" --cause dead-man
has "$(status "$G1")" state=reverted
[ "$(calls 'switch p test')" = 1 ] || bad "$T: P's switch did not run"

T="abort never replaces a recorded verdict or cause"
setup
start "$G1" > /dev/null
echo 'activate=1; echo sshd.service >> "$FIX/down"' > "$FIX/t.test"
h run "$G1" "$T_TOP" "$REG"
o=$(h abort "$G1" --boot-id "$BOOT")
has "$o" result=ok state=failed verdict=breaks_base
hasnt "$o" cause=aborted
[ "$(calls "cogbox-live-revert-$G1.service")" = 0 ] || bad "$T: the abort started a revert"
setup
start "$G1" > /dev/null
force_state "$G1" switching switching
printf 'activating the configuration...\n' > "$(gd "$G1")/switch.out"
h settle "$G1"
o=$(h abort "$G1" --boot-id "$BOOT")
has "$o" cause=activation_hang
hasnt "$o" cause=aborted

T="the dead-man reverts an unconfirmed switch"
setup
start "$G1" > /dev/null
h run "$G1" "$T_TOP" "$REG"
h revert "$G1" --cause dead-man
o=$(status "$G1")
has "$o" state=reverted cause=dead-man revert_exit=0
[ "$(readlink "$R/run/current-system")" = "$P_TOP" ] || bad "$T: P is not current after the revert"
o=$(h confirm "$G1" --boot-id "$BOOT")
has "$o" result=not_switched state=reverted

T="revert retries a busy switch lock"
setup
start "$G1" > /dev/null
h run "$G1" "$T_TOP" "$REG"
printf 'out="Could not acquire lock"\nrc=11\n' > "$FIX/p.test.1"
h revert "$G1" --cause dead-man
has "$(status "$G1")" state=reverted
[ "$(calls 'switch p test')" = 2 ] || bad "$T: expected two attempts of P's switch, got $(calls 'switch p test')"
[ "$(calls 'sleep 2')" = 1 ] || bad "$T: no back-off between the attempts"

T="revert waits for a busy generation lock again (the dead-man fires once)"
setup
start "$G1" > /dev/null
h run "$G1" "$T_TOP" "$REG"
has "$(status "$G1")" state=switched
lk=$(gd "$G1")/lock
flock -x "$lk" sleep 1.5 &
holder=$!
for _ in $(seq 100); do flock -n "$lk" true || break; sleep 0.05; done
export COGBOX_LS_TEST_REVERT_LOCK_WAIT=1
h revert "$G1"
unset COGBOX_LS_TEST_REVERT_LOCK_WAIT
wait "$holder"
has "$(status "$G1")" state=reverted cause=dead-man
[ "$(readlink "$R/run/current-system")" = "$P_TOP" ] || bad "$T: P is not current after the revert"

T="a failed revert taints the guest"
setup
start "$G1" > /dev/null
h run "$G1" "$T_TOP" "$REG"
printf 'rc=1\n' > "$FIX/p.test"
h revert "$G1" --cause dead-man
o=$(status "$G1")
has "$o" state=revert_failed tainted=yes revert_exit=1
has "$(h plan "$T_TOP")" result=guest_tainted
has "$(start "$G2")" result=guest_tainted

T="a revert cut short by its bound taints the guest"
setup
start "$G1" > /dev/null
h run "$G1" "$T_TOP" "$REG"
force_state "$G1" reverting
h settle-revert "$G1"
has "$(status "$G1")" state=revert_failed tainted=yes

# The revert's legs fit inside its unit's bound: the switch gets what the
# bound leaves after the checks (and a forced run's repair), the repair what
# is left after the switch, and a revert out of time ends revert_failed
# itself, never cut by the bound in a leg.
T="the revert budgets its legs inside its own bound"
setup
start "$G1" > /dev/null
h run "$G1" "$T_TOP" "$REG"
COGBOX_LS_TEST_REVERT_BOUND=100 h revert "$G1" --cause dead-man
has "$(status "$G1")" state=reverted revert_exit=0
b=$(grep '^timeout [0-9]* switch-to-configuration$' "$FIX/calls" | tail -n 1 | cut -d' ' -f2)
[ -n "$b" ] && [ "$b" -le 60 ] && [ "$b" -ge 55 ] || bad "$T: P's switch ran under timeout '${b-}', not 100 - 30 - 10 s"
setup
start "$G1" --force-units "$work/force" --repair cogbox-reply-route.service > /dev/null
h run "$G1" "$T_TOP" "$REG"
COGBOX_LS_TEST_REVERT_BOUND=100 h revert "$G1" --cause dead-man
has "$(status "$G1")" state=reverted revert_exit=0
b=$(grep '^timeout [0-9]* switch-to-configuration$' "$FIX/calls" | tail -n 1 | cut -d' ' -f2)
[ -n "$b" ] && [ "$b" -le 40 ] && [ "$b" -ge 35 ] || bad "$T: a forced run's switch ran under timeout '${b-}', not 100 - 30 - 30 s"
b=$(grep '^timeout [0-9]* systemctl$' "$FIX/calls" | tail -n 1 | cut -d' ' -f2)
[ "${b-}" = 60 ] || bad "$T: the repair ran under timeout '${b-}', not 60 s"
setup
start "$G1" --force-units "$work/force" --repair cogbox-reply-route.service > /dev/null
h run "$G1" "$T_TOP" "$REG"
: > "$FIX/calls"
COGBOX_LS_TEST_REVERT_BOUND=60 h revert "$G1" --cause dead-man
has "$(status "$G1")" state=revert_failed revert_exit=124 tainted=yes
[ "$(calls 'switch p test')" = 0 ] || bad "$T: a revert with no time left ran P's switch"
b=$(grep '^timeout [0-9]* systemctl$' "$FIX/calls" | tail -n 1 | cut -d' ' -f2)
[ -n "$b" ] && [ "$b" -le 30 ] && [ "$b" -ge 25 ] || bad "$T: the repair ran under timeout '${b-}', not what is left of 60 - 30 s"

T="revert leaves a foreign system alone"
setup
start "$G1" > /dev/null
h run "$G1" "$T_TOP" "$REG"
ln -sfn "$X_TOP" "$R/run/current-system"
h revert "$G1" --cause dead-man
has "$(status "$G1")" state=stale
[ "$(calls 'switch p test')" = 0 ] || bad "$T: the revert switched a foreign system"

# ----- output is enum-only ---------------------------------------------------------------
T="status passes only tokens and checked unit names"
setup
start "$G1" > /dev/null
d=$(gd "$G1")
echo 'rm -rf / please' > "$d/state"
echo 'free text' > "$d/verdict"
echo 'dead man' > "$d/cause"
printf 'ok.service\n$(id).service\nnot a unit\n' > "$d/detail"
o=$(status "$G1")
framed "$o"
has "$o" state=invalid verdict=invalid cause=invalid detail=ok.service
grep -qvE '^(proto|result|gen|state|reached|refusal|verdict|cause|during_activation|exit|revert_exit|detail|failed_unit|tainted|end)=[-A-Za-z0-9_.:@\\]*$' <<< "$o" \
	&& bad "$T: a line outside the contract: $(grep -vE '^[a-z_]+=[-A-Za-z0-9_.:@\\]*$' <<< "$o" | head -n 1)"

T="log strips control characters"
setup
start "$G1" > /dev/null
printf 'plain \033[31mred\033[0m line\n' > "$(gd "$G1")/switch.out"
o=$(h log "$G1")
grep -q $'\033' <<< "$o" && bad "$T: an escape sequence crossed"
grep -q 'plain \[31mred\[0m line' <<< "$o" || bad "$T: the log text is missing"

# ----- plan and settled ------------------------------------------------------------------
T="plan reports the guest data for tier 2"
setup
printf '%s\n' 'reloady.service loaded reloading reload reloading' 'stopping.service loaded deactivating stop-sigterm stopping' \
	'starting.service loaded activating start starting' >> "$FIX/units"
: > "$R/run/cogbox/once/bad marker"
cat > "$FIX/t.dry-activate" <<'EOF'
out="would stop the following units: a.service, b.service
would NOT stop the following changed units: getty@tty1.service
would activate the configuration...
would restart systemd
would reload the following units: dbus.service
would restart the following units: c.service, evil\$(x).service
would start the following units: d.service"
EOF
o=$(h plan "$T_TOP")
framed "$o"
has "$o" result=ok dry_result=ok store=overlay "boot_id=$BOOT" "booted=$P_TOP" "current=$P_TOP" \
	'dry=stop a.service' 'dry=stop b.service' 'dry=skip getty@tty1.service' 'dry=reload dbus.service' \
	'dry=restart c.service' 'dry=start d.service' reexec=yes \
	inactive=foo.service inactive=oncey.service \
	active=sshd.service active=cogbox-brain-materialize.service active=nix-store.mount active=multi-user.target active=reloady.service \
	notfound=ghost.service once=oncey \
	induced=foo.service induced=failedy.service induced=oncey.service \
	'edge=required_by docker.service foo.service'
hasnt "$o" 'dry=restart evil$(x).service' inactive=failedy.service induced=sshd.service induced=ghost.service \
	active=foo.service active=failedy.service active=ghost.service active=stopping.service active=starting.service 'once=bad marker'
# Only enumerated keys and checked tokens cross.
grep -qvE '^(proto|result|boot_id|booted|current|store|dry_result|reexec|end)=[-A-Za-z0-9_./]*$|^(dry=(stop|skip|reload|restart|start) |(inactive|active|notfound|once|induced)=|edge=[a-z_]+ [-A-Za-z0-9_.:@\\]+ )[-A-Za-z0-9_.:@\\]+$' <<< "$o" \
	&& bad "$T: a line outside the contract: $(grep -vE '^[a-z_]+=' <<< "$o" | head -n 1)"
grep -q 'unit=cogbox-live-plan-.*RuntimeMaxSec=60' "$FIX/calls" || bad "$T: dry-activate did not run in a bounded unit"
[ -z "$(ls "$R/run/cogbox/live-apply/plan" 2>/dev/null)" ] || bad "$T: the dry-activate output was left behind"
printf 'out="Pre-switch checks failed"\nrc=1\n' > "$FIX/t.dry-activate"
o=$(h plan "$T_TOP")
has "$o" dry_result=pre_switch_check
hasnt "$o" reexec=yes reexec=no
printf 'rc=100\n' > "$FIX/t.dry-activate"
has "$(h plan "$T_TOP")" dry_result=init_interface
: > "$R/run/cogbox/nix-store.err"
has "$(h plan "$T_TOP")" store=fallback

T="settled waits for a running system with no jobs"
setup
o=$(h settled --wait 25)
framed "$o"
has "$o" settled=yes system=running jobs=0 "boot_id=$BOOT"
[ "$(calls sleep)" = 0 ] || bad "$T: a settled system was polled"
echo starting > "$FIX/system_state"
o=$(h settled --wait 2)
has "$o" settled=no system=starting
[ "$(calls 'sleep 1')" = 2 ] || bad "$T: expected two polls"
echo degraded > "$FIX/system_state"
printf '7 foo.service start waiting\n' > "$FIX/jobs"
has "$(h settled)" settled=no system=degraded jobs=1

[ "$fails" -eq 0 ] || { echo "$fails failure(s)" >&2; exit 1; }
echo "live switch helper: all checks passed"
