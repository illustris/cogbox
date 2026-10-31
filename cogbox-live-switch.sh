#!@bash@
# cogbox-live-switch: the guest half of a live plugin apply (VM guests only).
#
# The host runs it over ssh as /run/booted-system/cogbox-live-switch, so every
# hop of one boot runs the same helper whatever system is current. It drives
# one generation G at a time: T (the toplevel of the runner the host built) is
# registered in the guest's local-overlay store, `T/bin/switch-to-configuration
# test` runs in a detached, time-bounded unit, and a dead-man revert, armed
# BEFORE any mutation, switches back to the previous system P unless the host
# confirms G on a fresh connection. Nothing in the guest depends on the ssh
# session that started it.
#
# Host-facing verbs:
#   settled --wait N
#   plan T
#   start G T REGINFO --prev P --boot-id ID --bound S --window W
#         [--force-units FILE|-] [--repair UNITS]
#   status G --boot-id ID [--wait N]
#   abort G --boot-id ID
#   confirm G --boot-id ID
#   log G
# Unit-facing verbs: run G T REGINFO (the apply unit cogbox-live-apply-G),
# settle G (its ExecStopPost), revert G [--cause C] (cogbox-live-revert-G, the
# dead-man), settle-revert G (its ExecStopPost). Internal: __register, __dry.
#
# Output contract of every host-facing verb but `log`: `key=value` lines, the
# first `proto=2` and the last `end=1` (a reply without it was cut off). Every
# value is an enumerated token, an integer, the 16-hex generation, the boot
# id, a store path of the booted or current system, or a unit name that
# passed a charset check (the host intersects unit names with T's and P's
# unit files). No guest free text crosses: the helper's own diagnostics go to
# the generation's log or to $ST/helper.log, and the guest log leaves only
# through `log`, whose output the host keeps in <G>.guest.log and never
# exports. Exit 0 for every answered request, 64 for a usage error.
#
# State machine, per generation, every transition under that generation's
# lock (gen/G/lock):
#   starting  -> switching | refused | reverting
#   switching -> switched | refused | failed | reverting
#   switched  -> confirmed | reverting
#   failed    -> reverting
#   reverting -> reverted | revert_failed
#   any non-terminal state -> stale (only from revert)
# refused, confirmed, reverted, revert_failed and stale are terminal and
# sticky. Entering one removes the guest root and disarms the dead-man;
# revert_failed also writes `tainted`, which refuses every later plan and
# start of this boot. The active generation is the one in a non-terminal
# state; `start` creates one only while there is none, under the global lock
# ($ST/lock, always taken before a generation lock), so there is at most one.
#
# Recorded per generation, and reported by `status` in every state: the
# refusal of a no-op `refused` (refusal=), the post-check verdict of `failed`
# (verdict=), and the revert cause (cause=: settle's phase activation_hang,
# unit_hang, stop_hang or switch_timeout; dead-man; aborted, with
# during_activation=yes when the abort landed while the switch was running).
# A verdict or cause, once recorded, is never replaced.
#
# Bounds: the apply unit runs under RuntimeMaxSec=S (gc.lock wait 30 s,
# registration 150 s, the switch and its checks the rest); the dead-man fires
# W s after `start` armed it; the revert unit runs under RuntimeMaxSec=360 with
# its generation lock waited for at most three times 20 s and its switch
# retried on a busy switch lock for at most 240 s inside 300 s, every leg
# budgeted to end 30 s before that bound, so the revert records its own end
# (a revert its bound cuts short anyway ends revert_failed, never silently on
# T); the plan's dry-activate runs in a unit under RuntimeMaxSec=60;
# `settled --wait` and `status --wait` long-poll at most 30 s; lock waits are
# bounded.

set -u
umask 022
PATH=@path@
# Test seams (checks.live-switch-helper only; the guest sets none of them): a
# directory of stand-in commands searched first, a root prefix for every
# filesystem path the helper reads or writes (store paths it is given are
# compared as strings and reached under the prefix), shorter gc.lock and
# revert lock waits, and a shorter revert bound.
if [ -n "${COGBOX_LS_TEST_BIN-}" ]; then PATH=$COGBOX_LS_TEST_BIN:$PATH; fi
R=${COGBOX_LS_TEST_ROOT-}
GC_WAIT=${COGBOX_LS_TEST_GC_WAIT:-30}
REVERT_LOCK_WAIT=${COGBOX_LS_TEST_REVERT_LOCK_WAIT:-20}
# The revert unit's RuntimeMaxSec (cmd_revert budgets its legs inside it).
REVERT_BOUND=${COGBOX_LS_TEST_REVERT_BOUND:-360}

ST=$R/run/cogbox/live-apply
GENS=$ST/gen
ONCE=$R/run/cogbox/once
STORE_CONF=$R/run/cogbox/nix-store.conf
STORE_ERR=$R/run/cogbox/nix-store.err
GC_LOCK=$R/nix/var/nix/gc.lock
GC_ROOTS=$R/nix/var/nix/gcroots/cogbox-live
RW=$R/nix/.rw-store
SSHD_CONFIG=$R/etc/ssh/sshd_config
# modules/guest-reply-route.nix: the uplink's networkd link group and the
# reply rule's priority (flake.nix guestReplyRoute).
REPLY_GROUP=@replyGroup@
REPLY_PRIORITY=@replyPriority@
REPAIR_UNIT=cogbox-reply-route.service
BRAIN_UNIT=cogbox-brain-materialize.service
self=$(readlink -f -- "$0") || self=$0

re_gen='^[0-9a-f]{16}$'
re_boot='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
re_store='^/nix/store/[0-9a-z]{32}-[A-Za-z0-9+_?=-][A-Za-z0-9+_.?=-]*$'
re_reginfo='^/nix/store/[0-9a-z]{32}-[A-Za-z0-9+_?=-][A-Za-z0-9+_.?=-]*/registration$'
# systemd unit names: its escaping (\x2d) keeps them to this set.
re_unit='^[-A-Za-z0-9:_.@\]{1,250}\.[a-z]{3,9}$'
re_int='^[0-9]{1,5}$'

GFD="" KFD="" gd="" G=""

kv() { printf '%s=%s\n' "$1" "$2"; }
finish() { kv end 1; exit 0; }
usage() { kv proto 2; kv error usage; kv end 1; exit 64; }
log() { printf 'cogbox-live-switch: %s\n' "$*" >&2; }

# Small state files: written to a temp name and renamed, so a reader never
# sees a torn value.
put() { printf '%s\n' "$3" > "$1/.$2.tmp" && mv -f "$1/.$2.tmp" "$1/$2"; }
get() { local v=""; [ -f "$1/$2" ] && IFS= read -r v < "$1/$2"; printf '%s' "$v"; }
putlist() {
	local d=$1 n=$2
	shift 2
	if [ "$#" -gt 0 ]; then printf '%s\n' "$@"; fi > "$d/.$n.tmp" && mv -f "$d/.$n.tmp" "$d/$n"
}

# Locks. The global lock is always taken before a generation lock. No long
# child runs while either is held (systemd-run, systemctl --no-block and
# logger return at once), because a child inherits the open descriptor.
glock() {
	exec {GFD}>>"$ST/lock" || { GFD=""; return 1; }
	flock -w "$1" "$GFD" && return 0
	exec {GFD}>&-
	GFD=""
	return 1
}
gunlock() { if [ -n "$GFD" ]; then exec {GFD}>&-; GFD=""; fi; }
klock() {
	exec {KFD}>>"$gd/lock" || { KFD=""; return 1; }
	flock -w "$1" "$KFD" && return 0
	exec {KFD}>&-
	KFD=""
	return 1
}
kunlock() { if [ -n "$KFD" ]; then exec {KFD}>&-; KFD=""; fi; }

is_terminal() { case $1 in refused|confirmed|reverted|revert_failed|stale) return 0 ;; esac; return 1; }
is_live() { case $1 in starting|switching|switched|failed|reverting) return 0 ;; esac; return 1; }

boot_id_raw() { local b=""; IFS= read -r b 2>/dev/null < "$R/proc/sys/kernel/random/boot_id"; printf '%s' "$b"; }
boot_id_tok() { local b; b=$(boot_id_raw); if [[ $b =~ $re_boot ]]; then printf '%s' "$b"; else printf invalid; fi; }
store_tok() { if [[ $1 =~ $re_store ]]; then printf '%s' "$1"; else printf invalid; fi; }
uptime_s() { local u=0; read -r u _ < /proc/uptime; printf '%s' "${u%%.*}"; }
rand_hex() { od -An -N8 -tx1 /dev/urandom | tr -d ' \n'; }

# The generation in a non-terminal state, if any.
active_gen() {
	local d s
	for d in "$GENS"/*/; do
		[ -d "$d" ] || continue
		s=$(get "${d%/}" state)
		if is_live "$s"; then
			d=${d%/}
			printf '%s' "${d##*/}"
			return 0
		fi
	done
	return 1
}

# ----- output tokens ---------------------------------------------------------
tok_state() {
	case $1 in
		starting|switching|switched|failed|reverting|refused|confirmed|reverted|revert_failed|stale) printf '%s' "$1" ;;
		*) printf invalid ;;
	esac
}
tok_verdict() {
	case $1 in
		breaks_base|activation_failed|unplanned_disruption|forced_unit_failed) printf '%s' "$1" ;;
		*) if [[ $1 =~ ^exit_[0-9]{1,3}$ ]]; then printf '%s' "$1"; else printf invalid; fi ;;
	esac
}
tok_cause() {
	case $1 in
		activation_hang|unit_hang|stop_hang|switch_timeout|dead-man|aborted) printf '%s' "$1" ;;
		*) printf invalid ;;
	esac
}
tok_refusal() {
	case $1 in
		busy_gc|store_path_hidden|store_whiteout|store_fallback|register_failed|pre_switch_check|init_interface|switch_locked|run_failed|start_failed|deadman_failed) printf '%s' "$1" ;;
		*) printf invalid ;;
	esac
}
# Unit names from a list file, charset-checked, at most 64.
units_of() {
	local u n=0
	[ -f "$1" ] || return 0
	while IFS= read -r u; do
		[[ $u =~ $re_unit ]] || continue
		kv "$2" "$u"
		n=$((n + 1))
		[ "$n" -lt 64 ] || break
	done < "$1"
}

# The status block of generation $1.
block() {
	local d=$GENS/$1 v
	kv gen "$1"
	kv state "$(tok_state "$(get "$d" state)")"
	v=$(get "$d" reached); [ -z "$v" ] || kv reached "$(tok_state "$v")"
	v=$(get "$d" refusal); [ -z "$v" ] || kv refusal "$(tok_refusal "$v")"
	v=$(get "$d" verdict); [ -z "$v" ] || kv verdict "$(tok_verdict "$v")"
	v=$(get "$d" cause)
	if [ -n "$v" ]; then
		kv cause "$(tok_cause "$v")"
		if [ "$v" = aborted ]; then
			if [ "$(get "$d" cause_during)" = yes ]; then kv during_activation yes; else kv during_activation no; fi
		fi
	fi
	v=$(get "$d" exit); if [[ $v =~ $re_int ]]; then kv exit "$v"; fi
	v=$(get "$d" revert_exit); if [[ $v =~ $re_int ]]; then kv revert_exit "$v"; fi
	units_of "$d/detail" detail
	units_of "$d/failed_units" failed_unit
	if [ -e "$ST/tainted" ]; then kv tainted yes; else kv tainted no; fi
}

# ----- transitions (callers hold the generation lock) ------------------------
terminal() {
	if [ "$1" = revert_failed ]; then : > "$ST/tainted"; fi
	put "$gd" state "$1"
	rm -f "$GC_ROOTS/$G"
	systemctl stop --no-block "cogbox-live-revert-$G.timer" >/dev/null 2>&1
	logger -t cogbox-live-switch "generation $G: $1" >/dev/null 2>&1
	return 0
}
# refuse FROM REASON: a no-op refusal, only from state FROM.
refuse() {
	klock 30 || { log "refuse $2: cannot take the generation lock"; return 1; }
	if [ "$(get "$gd" state)" = "$1" ]; then
		put "$gd" refusal "$2"
		terminal refused
		log "generation $G refused: $2"
	fi
	kunlock
}
# Start the revert now: the dead-man's own service, or, when that unit is
# gone, a transient one like it, so a generation never stays in reverting
# with nothing to finish it. The revert is idempotent.
start_revert() {
	systemctl start --no-block "cogbox-live-revert-$G.service" >/dev/null 2>&1 && return 0
	log "could not start cogbox-live-revert-$G.service; starting a transient revert"
	systemd-run --no-block --collect --unit="cogbox-live-revert-$G-now" --service-type=exec \
		-p "RuntimeMaxSec=$REVERT_BOUND" -p TimeoutStopSec=30 \
		-p "StandardOutput=append:$gd/log" -p "StandardError=append:$gd/log" \
		-p "ExecStopPost=$self settle-revert $G" \
		"$self" revert "$G" >/dev/null 2>&1 \
		|| log "could not start a revert of generation $G"
}

# ----- guest data -----------------------------------------------------------
drop_caches() { echo 3 > "$R/proc/sys/vm/drop_caches" 2>/dev/null || log "drop_caches failed"; }

# Every path of T's closure (the closure info's store-paths, beside REGINFO)
# must be visible through the overlay, after one drop_caches retry for 9p
# dentries cached before the host built them. Prints the refusal on failure.
visible() {
	local sp=$R${1%/registration}/store-paths p miss=() still=()
	[ -r "$sp" ] || drop_caches
	[ -r "$sp" ] || { echo store_path_hidden; return 1; }
	while IFS= read -r p; do
		[[ $p =~ $re_store ]] || continue
		[ -e "$R$p" ] || miss+=("$p")
	done < "$sp"
	[ "${#miss[@]}" -eq 0 ] && return 0
	drop_caches
	for p in "${miss[@]}"; do [ -e "$R$p" ] || still+=("$p"); done
	[ "${#still[@]}" -eq 0 ] && return 0
	for p in "${still[@]}"; do
		if [ -c "$RW/store/${p#/nix/store/}" ]; then
			log "a whiteout in the upper hides $p"
			echo store_whiteout
			return 1
		fi
	done
	log "${#still[@]} closure path(s) not visible, the first $(store_tok "${still[0]}")"
	echo store_path_hidden
	return 1
}

# Units a live switch must not disrupt (the plan's classes A-C, matched as the
# plan matches them: by stem, so sshd.* is sshd.service and sshd.socket):
# snapshotted before the switch and compared after it. rw-<overlay path> is
# the overlay preparation of every harness overlay path (flake.nix onceUnits).
# Left out: sshd@ and the login-session units (user@, getty@ and the like),
# which every login starts and every logout stops, the login probe's
# included; the plan refuses any change to them.
protected() {
	case $1 in
		*.mount|*.swap|*.automount|rw-*|harness-*|cogbox-guest-*|dbus*) return 0 ;;
		cogbox-additional-dirs.*|resize-store-overlay.*|cogbox-runtime-restore.*|cogbox-vm-sshd-prep.*|cogbox-reply-route.*) return 0 ;;
		sshd.*|systemd-logind.*|systemd-resolved.*|docker.*|containerd.*|firewall.service) return 0 ;;
		# podman's own units; a plugin's oci-containers unit
		# (podman-<name>.service) is the plugin's.
		podman.service|podman.socket|podman-restart.service) return 0 ;;
		systemd-networkd.*|nftables.*) return 0 ;;
	esac
	return 1
}
# Protected units the plan may start: a dbus activation, logind (a start of
# the running logind is a no-op) and the reply route (its start is the
# repair). Their restart or stop still counts.
startable() {
	case $1 in
		dbus*|systemd-logind.service|cogbox-reply-route.service) return 0 ;;
	esac
	return 1
}
# The forced units and the repair unit are exempt from the post-check's unit
# comparisons.
exempt() {
	grep -qxF -- "$1" "$gd/force" 2>/dev/null && return 0
	grep -qxF -- "$1" "$gd/repair" 2>/dev/null && return 0
	return 1
}
list_units() { systemctl list-units --all --plain --no-legend --full --no-pager 2>/dev/null; }
# `systemctl show` blocks to "Id value" lines for one property.
show_pairs() {
	local prop=$1
	shift
	[ "$#" -gt 0 ] || return 0
	systemctl show -p "Id,$prop" -- "$@" 2>/dev/null | awk -v prop="$prop" '
		BEGIN { RS = ""; FS = "\n" }
		{
			id = ""; val = ""
			for (i = 1; i <= NF; i++) {
				if ($i ~ /^Id=/) id = substr($i, 4)
				else if (index($i, prop "=") == 1) val = substr($i, length(prop) + 2)
			}
			if (id != "") print id, (val == "" ? "-" : val)
		}'
}
# "unit state invocation source" for every protected unit systemd lists, the
# forced and repair units aside: list-units' active state, the InvocationID
# ("-" for none), and y when a unit file or generator source backs the unit, n
# for a mount that only mirrors the kernel's mount table (a container's
# overlay, a user's /run/user), which comes and goes on its own. The states
# go to awk in a file: a guest running many containers lists more mounts than
# one argument or environment string holds.
protected_states() {
	local n ld act names=()
	while read -r n ld act _; do
		[[ $n =~ $re_unit ]] || continue
		protected "$n" || continue
		exempt "$n" && continue
		names+=("$n")
		printf '%s %s\n' "$n" "$act"
	done < <(list_units) > "$gd/.states.list"
	[ "${#names[@]}" -gt 0 ] || return 0
	systemctl show -p Id,InvocationID,FragmentPath,SourcePath -- "${names[@]}" 2>/dev/null | SF=$gd/.states.list awk '
		BEGIN {
			while ((getline line < ENVIRON["SF"]) > 0) if (split(line, f, " ") == 2) st[f[1]] = f[2]
			RS = ""; FS = "\n"
		}
		{
			id = ""; inv = "-"; src = "n"
			for (i = 1; i <= NF; i++) {
				if ($i ~ /^Id=/) id = substr($i, 4)
				else if ($i ~ /^InvocationID=./) inv = substr($i, 14)
				else if ($i ~ /^(FragmentPath|SourcePath)=./) src = "y"
			}
			if (id in st) print id, st[id], inv, src
		}'
}
# "unit InvocationID" for every running unit of a protected_states snapshot
# that has an InvocationID and a source: what invocation_changes compares.
running_invocations() {
	awk '($2 == "active" || $2 == "reloading") && $3 != "-" && $4 == "y" { print $1, $3 }' "$1"
}
# podman.service is podman's socket-activated API service: `podman system
# service` exits after 5 s idle and the next client of podman.socket starts it
# again, so a docker-API client polling during a switch stops it, starts it or
# gives it a new InvocationID, none of it the switch's. It owns no container
# (they run under conmon, in their own scopes). So while podman.socket ran
# through the whole switch (active after it, with the InvocationID it had
# before), invocation_changes and start_changes leave podman.service out:
# its stop, its start and its new InvocationID; failed_changes still counts
# it. The plan refuses a switch-driven change to its own unit (class B), and
# a socket restart or stop still counts podman.service as well as the socket.
# Gap: an activation snippet's `systemctl restart podman` while the socket
# stays up is not caught. A snapshot systemctl could not take (empty) never
# matches.
podman_churn() {
	awk 'FILENAME == ARGV[1] { if ($1 == "podman.socket") b = $3; next }
		$1 == "podman.socket" && $2 == "active" { a = $3 }
		END { exit !(b != "" && b != "-" && a == b) }' "$gd/states" "$gd/states.after" 2>/dev/null
}
# Snapshotted units whose InvocationID changed: restarted, or unloaded (show
# then has none). A stopped unit that stays loaded keeps its last
# InvocationID; start_changes counts it. podman.service is left out while its
# socket listens (podman_churn).
invocation_changes() {
	[ -s "$gd/inv" ] || return 0
	local names=() u
	mapfile -t names < <(awk '{ print $1 }' "$gd/inv")
	show_pairs InvocationID "${names[@]}" > "$gd/.inv.after"
	while read -r u; do
		[ "$u" = podman.service ] && podman_churn && continue
		printf '%s\n' "$u"
	done < <(awk 'FILENAME == ARGV[1] { after[$1] = $2; next } { if (!($1 in after) || after[$1] != $2) print $1 }' "$gd/.inv.after" "$gd/inv")
}
# Protected units with a source that the switch started or stopped outside
# the plan, from the snapshots before ($gd/states) and after
# ($gd/states.after). Started: one that did not run before (inactive, failed,
# or not loaded at all, as a unit a new generator wrote) and runs, is starting
# or stopping, or failed after, or that got a new InvocationID (a oneshot that
# ran and exited); a running one without an InvocationID (a mount the initrd
# made), which invocation_changes cannot compare, that got one. Stopped: one
# that ran before and does not run after, or is gone from the list. systemd
# keeps a stopped unit's last InvocationID, so invocation_changes sees no
# change for it. The plan sees no generator output, activation snippet or
# generator-only edge, and stops a protected unit only when forced; this sees
# both. A start of a unit the plan may start (startable) is left out, and so
# is a mount its running automount triggered or unmounted when idle (an
# access, not the switch), and podman.service while its socket listens
# (podman_churn).
# Unit names reach awk through the environment: -v would expand their \x2d
# escapes. Every comparison tells its files apart by FILENAME, so an empty
# snapshot (one systemctl could not take) counts its units as changed, never
# as unchanged.
start_changes() {
	local how u
	[ -f "$gd/states.after" ] || return 0
	while read -r how u; do
		[ "$how" = started ] && startable "$u" && continue
		if [[ $u == *.mount ]] && list_units | A=${u%.mount}.automount awk '$1 == ENVIRON["A"] && $3 == "active" { f = 1 } END { exit !f }'; then
			continue
		fi
		[ "$u" = podman.service ] && podman_churn && continue
		printf '%s\n' "$u"
	done < <(awk '
		function running(s) { return s == "active" || s == "reloading" }
		FILENAME == ARGV[1] { bst[$1] = $2; binv[$1] = $3; bsrc[$1] = $4; next }
		{ seen[$1] = 1 }
		$4 != "y" { next }
		$1 in bst {
			b = bst[$1]
			if (running(b)) {
				if (!running($2)) print "stopped", $1
				else if (binv[$1] == "-" && $3 != "-") print "started", $1
				next
			}
			if (b != "inactive" && b != "failed") next
			if (($2 != "inactive" && $2 != b) || ($3 != "-" && $3 != binv[$1])) print "started", $1
			next
		}
		$2 != "inactive" || $3 != "-" { print "started", $1 }
		END { for (u in bst) if (!(u in seen) && running(bst[u]) && bsrc[u] == "y") print "stopped", u }' "$gd/states" "$gd/states.after")
}
# The failed units switch-to-configuration reported ($@) that are protected
# and not exempt. It lists every unit failed at its end, so one that was failed
# before the switch with the InvocationID it still has (it failed at boot) is
# not the switch's.
failed_changes() {
	local u
	for u in "$@"; do
		protected "$u" || continue
		exempt "$u" && continue
		U=$u awk '
			FILENAME == ARGV[1] { if ($1 == ENVIRON["U"]) { bst = $2; binv = $3 }; next }
			$1 == ENVIRON["U"] { ainv = $3 }
			END { exit !(bst == "failed" && ainv != "" && ainv == binv) }' "$gd/states" "$gd/states.after" && continue
		printf '%s\n' "$u"
	done
}

# Network health: the uplink has an IPv4 address, the reply rule is
# installed, the reply table is loaded (modules/guest-reply-route.nix).
net_sample() {
	local up=no rule=no table=no
	if ip -4 -o addr show group "$REPLY_GROUP" scope global 2>/dev/null | grep -q ' inet '; then
		up=yes
	elif [ -z "$(ip -o link show group "$REPLY_GROUP" 2>/dev/null)" ] && [ -n "$(ip -4 route show default 2>/dev/null)" ]; then
		# No link carries the uplink group (the reply route is not
		# configured): the default route stands in for the uplink.
		up=yes
	fi
	[ -z "$(ip -4 rule show pref "$REPLY_PRIORITY" 2>/dev/null)" ] || rule=yes
	if nft list table ip cogbox_reply >/dev/null 2>&1; then table=yes; fi
	printf 'uplink=%s rule=%s table=%s\n' "$up" "$rule" "$table"
}
# net_worse BEFORE AFTER: a check that held before fails after.
net_worse() {
	local k
	for k in uplink rule table; do
		if [[ " $1 " == *" $k=yes "* && " $2 " != *" $k=yes "* ]]; then return 0; fi
	done
	return 1
}

# The units a unit name resolves to in a unit directory, with a checksum of
# each file: the unit (or its template) and its drop-ins.
unit_sig() {
	local d=$1 u=$2 base=$2 f
	if [ ! -e "$d/$u" ] && [[ $u == *@?*.* ]]; then base=${u%%@*}@.${u##*.}; fi
	for f in "$d/$base" "$d/$base.d"/*.conf "$d/$u.d"/*.conf; do
		[ -f "$f" ] || continue
		printf '%s %s\n' "${f#"$d"/}" "$(cksum < "$f")"
	done
}
# A unit this apply brought: new in T, or its files differ from P's.
plugin_owned() {
	local t
	t=$(unit_sig "$R$(get "$gd" T)/etc/systemd/system" "$1")
	[ -n "$t" ] || return 1
	[ "$t" != "$(unit_sig "$R$(get "$gd" P)/etc/systemd/system" "$1")" ]
}

# What a switch killed by its bound was doing, from switch-to-configuration's
# own progress lines (main.rs prints "stopping the following units", then
# "activating the configuration...", then, once the activation script has
# returned, one of the lines below before it starts and restarts units).
switch_phase() {
	local out=$gd/switch.out id u hung=()
	if grep -qE '^(Failed to run activate script|restarting systemd\.\.\.|reloading user units for |restarting sysinit-reactivation\.target)' "$out" 2>/dev/null; then
		while read -r id u _; do
			[[ $id =~ ^[0-9]+$ && $u =~ $re_unit ]] || continue
			if plugin_owned "$u"; then hung+=("$u"); fi
		done < <(systemctl list-jobs --no-legend --plain --no-pager 2>/dev/null)
		if [ "${#hung[@]}" -gt 0 ]; then
			putlist "$gd" detail "${hung[@]}"
			echo unit_hang
		else
			echo switch_timeout
		fi
	elif grep -q '^activating the configuration\.\.\.' "$out" 2>/dev/null; then
		echo activation_hang
	elif grep -q '^stopping the following units: ' "$out" 2>/dev/null; then
		echo stop_hang
	else
		echo switch_timeout
	fi
}

# ----- settled --------------------------------------------------------------
count_jobs() { systemctl list-jobs --no-legend --plain --no-pager 2>/dev/null | awk '$1 ~ /^[0-9]+$/ { n++ } END { print n + 0 }'; }

cmd_settled() {
	local wait=0 i=0 state jobs settled=no
	if [ "$#" -gt 0 ]; then
		[ "$#" -eq 2 ] && [ "$1" = --wait ] && [[ $2 =~ $re_int ]] || usage
		wait=$2
	fi
	[ "$wait" -le 30 ] || wait=30
	kv proto 2
	while :; do
		state=$(systemctl is-system-running 2>/dev/null)
		jobs=$(count_jobs)
		case $state in running|degraded) [ "$jobs" -eq 0 ] && settled=yes ;; esac
		[ "$settled" = yes ] || [ "$i" -ge "$wait" ] && break
		sleep 1
		i=$((i + 1))
	done
	case $state in initializing|starting|running|degraded|maintenance|stopping|offline) ;; *) state=unknown ;; esac
	kv settled "$settled"
	kv system "$state"
	kv jobs "$jobs"
	kv boot_id "$(boot_id_tok)"
	finish
}

# ----- plan -----------------------------------------------------------------
emit_dry() {
	local action=$1 u items=()
	IFS=, read -ra items <<< "$2"
	for u in "${items[@]}"; do
		u=${u# }
		[[ $u =~ $re_unit ]] && kv dry "$action $u"
	done
}

# dry-activate in a transient unit bounded at 60 s (it runs T's dry
# activation snippets), never under the ssh session.
plan_dry() {
	local T=$1 tag out rcf rc res reexec=no line
	[ -x "$R$T/bin/switch-to-configuration" ] || drop_caches
	if [ ! -x "$R$T/bin/switch-to-configuration" ]; then kv dry_result not_visible; return; fi
	mkdir -p "$ST/plan" || { kv dry_result failed; return; }
	tag=$(rand_hex)
	out=$ST/plan/$tag.out rcf=$ST/plan/$tag.rc
	timeout 80 systemd-run --quiet --wait --collect --unit="cogbox-live-plan-$tag" --service-type=exec \
		-p RuntimeMaxSec=60 -p "StandardOutput=truncate:$out" \
		"$self" __dry "$T" "$rcf" >/dev/null 2>&1
	rc=$(get "$ST/plan" "$tag.rc")
	if [[ ! $rc =~ $re_int ]]; then
		if [ -e "$out" ]; then res=timeout; else res=failed; fi
	elif grep -q '^Could not acquire lock' "$out"; then res=switch_locked
	elif [ "$rc" = 100 ]; then res=init_interface
	elif [ "$rc" = 1 ] && grep -q '^Pre-switch checks failed' "$out"; then res=pre_switch_check
	elif [ "$rc" = 0 ]; then res=ok
	else res=failed
	fi
	kv dry_result "$res"
	if [ "$res" = ok ]; then
		while IFS= read -r line; do
			case $line in
				"would stop the following units: "*) emit_dry stop "${line#would stop the following units: }" ;;
				"would NOT stop the following changed units: "*) emit_dry skip "${line#would NOT stop the following changed units: }" ;;
				"would reload the following units: "*) emit_dry reload "${line#would reload the following units: }" ;;
				"would restart the following units: "*) emit_dry restart "${line#would restart the following units: }" ;;
				"would start the following units: "*) emit_dry start "${line#would start the following units: }" ;;
				"would restart systemd") reexec=yes ;;
			esac
		done < "$out"
		kv reexec "$reexec"
	fi
	rm -f "$out" "$rcf"
}

# The unit states, the once-markers, the induced starts and the runtime
# reverse edges. Per loaded unit: `inactive` for exactly "inactive" (a stop,
# restart or reload of it is a no-op), `active` for one that runs (active,
# reloading, refreshing: starting it is a no-op; anything else, failed,
# activating or deactivating included, is not running, and so is a unit not
# listed at all), `notfound` for one systemd cannot load. `once` names every
# marker in /run/cogbox/once; the host decides what it skips (with T's units).
plan_units() {
	local n ld act names=() targets=() u k x v items=() p m
	local -A load=() active=() induced=()
	while read -r n ld act _; do
		[[ $n =~ $re_unit ]] || continue
		load[$n]=$ld
		active[$n]=$act
		names+=("$n")
		case $act in
			inactive) kv inactive "$n" ;;
			active|reloading|refreshing) kv active "$n" ;;
		esac
		[ "$ld" = not-found ] && kv notfound "$n"
		[[ $n == *.target && $act == active ]] && targets+=("$n")
	done < <(list_units)
	for m in "$ONCE"/*; do
		m=${m##*/}
		[[ $m.service =~ $re_unit ]] && kv once "$m"
	done
	# Induced starts: every active target is started again, which starts
	# the units it wants that are inactive or failed (generator wants
	# included, which the host's unit files do not show). Once-marked ones
	# are listed too: the host skips them only when T keeps the marker
	# condition and the marker is here.
	if [ "${#targets[@]}" -gt 0 ]; then
		while read -r k x v; do
			read -ra items <<< "$v"
			for u in "${items[@]}"; do
				[[ $u =~ $re_unit ]] || continue
				case ${load[$u]-} in loaded) ;; *) continue ;; esac
				case ${active[$u]-} in inactive|failed) ;; *) continue ;; esac
				induced[$u]=1
			done
		done < <(systemctl show -p Id,Wants,Requires -- "${targets[@]}" 2>/dev/null | awk '
			BEGIN { RS = ""; FS = "\n" }
			{
				id = ""; w = ""
				for (i = 1; i <= NF; i++) {
					if ($i ~ /^Id=/) id = substr($i, 4)
					else if ($i ~ /^(Wants|Requires)=./) w = w " " substr($i, index($i, "=") + 1)
				}
				if (id != "" && w != "") print "W", id, w
			}')
	fi
	for u in "${!induced[@]}"; do printf '%s\n' "$u"; done | sort | while IFS= read -r u; do kv induced "$u"; done
	# Runtime reverse edges, as `systemctl show` lists them: x's property
	# names u. Used by the host only to refuse.
	[ "${#names[@]}" -gt 0 ] || return 0
	systemctl show -p Id,RequiredBy,BoundBy,ConsistsOf,PropagatesStopTo,PropagatesReloadTo,ConflictedBy -- "${names[@]}" 2>/dev/null | awk '
		BEGIN { RS = ""; FS = "\n" }
		{
			id = ""
			for (i = 1; i <= NF; i++) if ($i ~ /^Id=/) id = substr($i, 4)
			if (id == "") next
			for (i = 1; i <= NF; i++) {
				k = $i; sub(/=.*/, "", k)
				if (k == "Id") continue
				v = substr($i, length(k) + 2)
				if (v != "") print k, id, v
			}
		}' | while read -r p x v; do
			case $p in
				RequiredBy) k=required_by ;;
				BoundBy) k=bound_by ;;
				ConsistsOf) k=consists_of ;;
				PropagatesStopTo) k=propagates_stop_to ;;
				PropagatesReloadTo) k=propagates_reload_to ;;
				ConflictedBy) k=conflicted_by ;;
				*) continue ;;
			esac
			[[ $x =~ $re_unit ]] || continue
			read -ra items <<< "$v"
			for u in "${items[@]}"; do
				[[ $u =~ $re_unit ]] && kv edge "$k $x $u"
			done
		done
}

cmd_plan() {
	[ "$#" -eq 1 ] && [[ $1 =~ $re_store ]] || usage
	local T=$1 a
	kv proto 2
	if [ -e "$ST/tainted" ]; then kv result guest_tainted; finish; fi
	if a=$(active_gen); then kv result busy; kv busy_gen "$a"; finish; fi
	kv result ok
	kv boot_id "$(boot_id_tok)"
	kv booted "$(store_tok "$(readlink "$R/run/booted-system")")"
	kv current "$(store_tok "$(readlink "$R/run/current-system")")"
	if [ -e "$STORE_CONF" ] && [ ! -e "$STORE_ERR" ]; then kv store overlay; else kv store fallback; fi
	plan_dry "$T"
	plan_units
	finish
}

# ----- start ----------------------------------------------------------------
cmd_start() {
	[ "$#" -ge 3 ] || usage
	G=$1
	local T=$2 REG=$3 P="" ID="" S="" W="" force_src="" have_force=0 repair="" a u
	local force=() repairs=() items=()
	shift 3
	while [ "$#" -gt 0 ]; do
		case $1 in
			--prev) [ "$#" -ge 2 ] || usage; P=$2; shift 2 ;;
			--boot-id) [ "$#" -ge 2 ] || usage; ID=$2; shift 2 ;;
			--bound) [ "$#" -ge 2 ] || usage; S=$2; shift 2 ;;
			--window) [ "$#" -ge 2 ] || usage; W=$2; shift 2 ;;
			--force-units) [ "$#" -ge 2 ] || usage; force_src=$2; have_force=1; shift 2 ;;
			--repair) [ "$#" -ge 2 ] || usage; repair=$2; shift 2 ;;
			*) usage ;;
		esac
	done
	[[ $G =~ $re_gen && $T =~ $re_store && $REG =~ $re_reginfo && $P =~ $re_store && $ID =~ $re_boot ]] || usage
	[[ $S =~ $re_int && $W =~ $re_int ]] || usage
	[ "$S" -ge 60 ] && [ "$S" -le 3600 ] && [ "$W" -ge $((S + 60)) ] && [ "$W" -le 7200 ] || usage
	# The forced units: host-validated, checked again here. Read from a
	# guest file, or from stdin with "-".
	if [ "$have_force" = 1 ]; then
		if [ "$force_src" = - ]; then
			mapfile -t items < <(head -c 65536)
		else
			[ -r "$force_src" ] || usage
			mapfile -t items < <(head -c 65536 -- "$force_src")
		fi
		for u in "${items[@]}"; do
			[ -n "$u" ] || continue
			[[ $u =~ $re_unit ]] || usage
			force+=("$u")
		done
		[ "${#force[@]}" -gt 0 ] && [ "${#force[@]}" -le 256 ] || usage
	fi
	# The only repair unit there is.
	if [ -n "$repair" ]; then
		IFS=, read -ra items <<< "$repair"
		for u in "${items[@]}"; do
			[ "$u" = "$REPAIR_UNIT" ] || usage
		done
		repairs=("$REPAIR_UNIT")
	fi
	mkdir -p "$GENS" || usage
	kv proto 2
	if [ "$ID" != "$(boot_id_raw)" ]; then kv result stale_boot; finish; fi
	if ! glock 20; then kv result lock_timeout; finish; fi
	gd=$GENS/$G
	# A generation recorded this boot, a tombstone included, answers its
	# recorded state and arms nothing.
	if [ -d "$gd" ]; then gunlock; kv result recorded; block "$G"; finish; fi
	if [ -e "$ST/tainted" ]; then gunlock; kv result guest_tainted; finish; fi
	if a=$(active_gen); then gunlock; kv result busy; kv busy_gen "$a"; finish; fi
	if [ "$(readlink "$R/run/current-system")" != "$P" ]; then gunlock; kv result superseded; finish; fi
	if ! mkdir "$gd"; then gunlock; kv result error; finish; fi
	put "$gd" T "$T"; put "$gd" P "$P"; put "$gd" reginfo "$REG"; put "$gd" boot "$ID"
	put "$gd" bound "$S"; put "$gd" window "$W"
	putlist "$gd" force "${force[@]}"
	putlist "$gd" repair "${repairs[@]}"
	put "$gd" reached starting
	put "$gd" state starting
	if [ "${#force[@]}" -gt 0 ] || [ "${#repairs[@]}" -gt 0 ]; then
		logger -t cogbox-live-switch "generation $G: forced units: ${force[*]:-none}; repair: ${repairs[*]:-none}" >/dev/null 2>&1
	fi
	# The dead-man first: nothing has changed yet, and from here on the
	# guest returns to P unless the host confirms G within W seconds.
	if ! systemd-run --unit="cogbox-live-revert-$G" --on-active="${W}s" --timer-property=AccuracySec=1s \
		--service-type=exec -p "RuntimeMaxSec=$REVERT_BOUND" -p TimeoutStopSec=30 \
		-p "StandardOutput=append:$gd/log" -p "StandardError=append:$gd/log" \
		-p "ExecStopPost=$self settle-revert $G" \
		"$self" revert "$G" --cause dead-man >/dev/null 2>>"$gd/log"; then
		# G is new and the global lock is held: nothing else can hold its lock.
		klock 10
		put "$gd" refusal deadman_failed
		terminal refused
		kunlock
		gunlock
		kv result started
		block "$G"
		finish
	fi
	# The apply unit, detached: it outlives the ssh session.
	if ! systemd-run --no-block --collect --unit="cogbox-live-apply-$G" --service-type=exec \
		-p "RuntimeMaxSec=$S" -p TimeoutStopSec=30 \
		-p "StandardOutput=append:$gd/log" -p "StandardError=append:$gd/log" \
		-p "ExecStopPost=$self settle $G" \
		"$self" run "$G" "$T" "$REG" >/dev/null 2>>"$gd/log"; then
		# The run, had it started after all, finds G refused and does nothing.
		klock 10
		if [ "$(get "$gd" state)" = starting ]; then put "$gd" refusal start_failed; terminal refused; fi
		kunlock
	fi
	gunlock
	kv result started
	block "$G"
	finish
}

# ----- run (the apply unit) -------------------------------------------------
add_reginfo() { grep -qxF -- "$1" "$ST/reginfos" 2>/dev/null || printf '%s\n' "$1" >> "$ST/reginfos"; }

# The running sshd's own binary, which serves every new login (sshd re-execs
# itself per connection), else the booted system's: `sshd -t` must judge the
# new sshd_config with the sshd that will read it.
running_sshd() {
	local pid="" k v
	while IFS='=' read -r k v; do
		[ "$k" = MainPID ] && pid=$v
	done < <(systemctl show -p MainPID -- sshd.service 2>/dev/null)
	if [[ $pid =~ ^[1-9][0-9]*$ ]] && [ -x "$R/proc/$pid/exe" ]; then
		printf '%s' "$R/proc/$pid/exe"
	else
		printf sshd
	fi
}

# The base checks: sshd and the brain are active, `sshd -t` passes, the login
# probe passes, and network health is no worse (re-sampled once after 5 s).
# Exit 0 when all pass; each failure is logged.
base_ok() {
	local ok=0 after
	systemctl is-active --quiet sshd.service || { log "post-check: sshd.service is not active"; ok=1; }
	systemctl is-active --quiet "$BRAIN_UNIT" || { log "post-check: $BRAIN_UNIT is not active"; ok=1; }
	"$(running_sshd)" -t -f "$SSHD_CONFIG" >/dev/null 2>&1 || { log "post-check: sshd -t fails"; ok=1; }
	timeout 20 runuser -l root -c true </dev/null >/dev/null 2>&1 || { log "post-check: the login probe fails"; ok=1; }
	after=$(net_sample)
	if net_worse "$(cat "$gd/net" 2>/dev/null)" "$after"; then
		log "post-check: network health $after, was $(cat "$gd/net" 2>/dev/null); sampling again in 5 s"
		sleep 5
		after=$(net_sample)
		net_worse "$(cat "$gd/net" 2>/dev/null)" "$after" && { log "post-check: network health is worse: $after"; ok=1; }
	fi
	return "$ok"
}

# Post-checks after an exit of 0, 2 or 4: prints the verdict, or ok.
postcheck() {
	local rc=$1 base=ok line failed=() changed=() ff=() u items=()
	line=$(grep '^warning: the following units failed: ' "$gd/switch.out" | tail -n 1)
	if [ -n "$line" ]; then
		IFS=, read -ra items <<< "${line#warning: the following units failed: }"
		for u in "${items[@]}"; do
			u=${u# }
			[[ $u =~ $re_unit ]] && failed+=("$u")
		done
	fi
	putlist "$gd" failed_units "${failed[@]}"
	base_ok || base=bad
	if [ "$base" = bad ]; then
		if [ "$rc" = 2 ]; then echo activation_failed; else echo breaks_base; fi
		return
	fi
	protected_states > "$gd/states.after"
	mapfile -t changed < <({ invocation_changes; start_changes; failed_changes "${failed[@]}"; } | sort -u)
	if [ "${#changed[@]}" -gt 0 ]; then
		log "post-check: protected units outside the plan changed: ${changed[*]}"
		putlist "$gd" detail "${changed[@]}"
		echo unplanned_disruption
		return
	fi
	if [ "$rc" = 4 ] && [ "${#failed[@]}" -gt 0 ]; then
		for u in "${failed[@]}"; do
			grep -qxF -- "$u" "$gd/force" 2>/dev/null && ff+=("$u")
		done
		if [ "${#ff[@]}" -gt 0 ]; then
			putlist "$gd" detail "${ff[@]}"
			echo forced_unit_failed
			return
		fi
	fi
	echo ok
}

cmd_run() {
	[ "$#" -eq 3 ] && [[ $1 =~ $re_gen && $2 =~ $re_store && $3 =~ $re_reginfo ]] || usage
	G=$1
	local T=$2 REG=$3 why rc verdict r
	gd=$GENS/$G
	[ -d "$gd" ] || { log "generation $G is unknown"; exit 0; }
	if [ "$(get "$gd" T)" != "$T" ] || [ "$(get "$gd" reginfo)" != "$REG" ]; then
		log "generation $G: arguments differ from the recorded ones"
		exit 0
	fi
	r=$(get "$gd" state)
	[ "$r" = starting ] || { log "generation $G is $r, not starting; nothing to do"; exit 0; }
	log "generation $G: registering $T"
	if [ ! -e "$STORE_CONF" ] || [ -e "$STORE_ERR" ]; then refuse starting store_fallback; exit 0; fi
	# Checked before registering too, so a hidden closure is never
	# registered as valid in the lower DB.
	if ! why=$(visible "$REG"); then refuse starting "$why"; exit 0; fi
	# 1. Register, under gc.lock so no guest GC runs meanwhile.
	flock -x -w "$GC_WAIT" -E 75 -o "$GC_LOCK" timeout 150 "$self" __register "$G" "$T" "$REG"
	rc=$?
	case $rc in
		0) ;;
		75) refuse starting busy_gc; exit 0 ;;
		*) log "registration failed ($rc)"; refuse starting register_failed; exit 0 ;;
	esac
	# 2. Visibility.
	if ! why=$(visible "$REG"); then refuse starting "$why"; exit 0; fi
	add_reginfo "$REG"
	# 3. Snapshot the protected units and the network.
	protected_states > "$gd/states"
	running_invocations "$gd/states" > "$gd/inv"
	net_sample > "$gd/net"
	# 4. Switch.
	klock 30 || { log "cannot take the generation lock before the switch"; exit 0; }
	if [ "$(get "$gd" state)" != starting ]; then kunlock; log "generation $G left starting before the switch"; exit 0; fi
	put "$gd" reached switching
	put "$gd" state switching
	kunlock
	log "generation $G: switch-to-configuration test"
	"$R$T/bin/switch-to-configuration" test > "$gd/switch.out" 2>&1 < /dev/null
	rc=$?
	put "$gd" exit "$rc"
	log "generation $G: switch-to-configuration test exited $rc"
	# 6. The no-op refusals: nothing was stopped and nothing activated.
	if ! grep -qE '^(stopping the following units: |activating the configuration\.\.\.)' "$gd/switch.out"; then
		r=""
		if grep -q '^Could not acquire lock' "$gd/switch.out"; then r=switch_locked
		elif [ "$rc" = 100 ]; then r=init_interface
		elif [ "$rc" = 1 ] && grep -q '^Pre-switch checks failed' "$gd/switch.out"; then r=pre_switch_check
		fi
		if [ -n "$r" ]; then refuse switching "$r"; exit 0; fi
	fi
	# 5. Repair (forced runs): live, an nftables start flushes the reply
	# table, which at boot is loaded after it.
	if [ -s "$gd/repair" ]; then
		log "repair: restarting $REPAIR_UNIT"
		timeout 60 systemctl restart "$REPAIR_UNIT" || log "repair: restarting $REPAIR_UNIT failed"
	fi
	# 7. Post-checks. Any other exit after the activation began (it stopped
	# units or ran the activation script) gets the base checks too: a switch
	# that broke the base and then failed is breaks_base, which rolls the
	# change back, not exit_<n>, which keeps it for the next boot.
	case $rc in
		0|2|4) verdict=$(postcheck "$rc") ;;
		*)
			verdict=exit_$rc
			if grep -qE '^(stopping the following units: |activating the configuration\.\.\.)' "$gd/switch.out" && ! base_ok; then
				verdict=breaks_base
			fi
			;;
	esac
	klock 30 || { log "cannot take the generation lock to record $verdict"; exit 0; }
	if [ "$(get "$gd" state)" = switching ]; then
		if [ "$verdict" = ok ]; then
			put "$gd" reached switched
			put "$gd" state switched
			log "generation $G switched; waiting for the host's confirm"
		else
			put "$gd" verdict "$verdict"
			put "$gd" state failed
			log "generation $G failed: $verdict"
		fi
	fi
	kunlock
	exit 0
}

# The lower DB generation nix-store.conf names: lower-state (the boot's) or
# lower-state.<n>; empty when the conf does not parse.
conf_gen() {
	local c=""
	[ -f "$STORE_CONF" ] && c=$(< "$STORE_CONF")
	if [[ $c =~ state%3D/nix/\.rw-store/(lower-state(\.[0-9]+)?)%26 ]]; then printf '%s' "${BASH_REMATCH[1]}"; fi
}

# Under gc.lock, bounded by the caller: the guest root, a fresh lower DB
# generation (the boot regInfo, every regInfo applied this boot, and T's),
# nix-daemon restarted onto it, and every generation removed but the new one
# and the one the conf named before (a daemon worker forked before this
# restart still reads it). New generations are named from a sequence that is
# never reused, and the current one is read from the conf itself, so a
# registration that failed partway never makes a later one prune the
# generation in use.
cmd_register() {
	[ "$#" -eq 3 ] && [[ $1 =~ $re_gen && $2 =~ $re_store && $3 =~ $re_reginfo ]] || usage
	G=$1
	local T=$2 REG=$3 boot="" prev now k n r d list=() applied=()
	local -A seen=()
	mkdir -p "$GC_ROOTS" && ln -sfn "$T" "$GC_ROOTS/.$G.tmp" && mv -fT "$GC_ROOTS/.$G.tmp" "$GC_ROOTS/$G" || exit 1
	if [[ "$(cat "$R/proc/cmdline")" =~ regInfo=([^ ]*) ]]; then boot=${BASH_REMATCH[1]}; fi
	[[ $boot =~ $re_reginfo ]] || { log "no boot regInfo on the kernel command line"; exit 1; }
	[ -f "$ST/reginfos" ] && mapfile -t applied < "$ST/reginfos"
	for r in "$boot" "${applied[@]}" "$REG"; do
		[[ $r =~ $re_reginfo ]] || continue
		[ -n "${seen[$r]-}" ] && continue
		seen[$r]=1
		list+=("$r")
	done
	prev=$(conf_gen)
	k=$(get "$ST" lower-seq)
	[[ $k =~ ^[0-9]+$ ]] || k=0
	n=$((k + 1))
	put "$ST" lower-seq "$n" || exit 1
	if ! cogbox-overlay-store --live "/nix/.rw-store/lower-state.$n" "${list[@]}"; then
		log "the lower DB generation $n did not build; the store stays on ${prev:-its current generation}"
		rm -rf --one-file-system "$RW/lower-state.$n"
		exit 1
	fi
	timeout 60 systemctl restart nix-daemon.service || { log "nix-daemon did not restart"; exit 1; }
	now=$(conf_gen)
	if [ "$now" != "lower-state.$n" ] || [ -z "$prev" ]; then
		log "nix-store.conf names ${now:-no generation} (previously ${prev:-none}); not pruning"
		exit 0
	fi
	for d in "$RW/lower-state" "$RW"/lower-state.*; do
		[ -e "$d" ] || continue
		case ${d##*/} in "$now"|"$prev") continue ;; esac
		[[ ${d##*/} =~ ^lower-state(\.[0-9]+)?$ ]] && rm -rf --one-file-system "$d"
	done
	exit 0
}

# Inside the plan's transient unit.
cmd_dry() {
	[ "$#" -eq 2 ] && [[ $1 =~ $re_store ]] || usage
	case $2 in "$ST"/plan/[0-9a-f]*.rc) ;; *) usage ;; esac
	"$R$1/bin/switch-to-configuration" dry-activate < /dev/null
	echo "$?" > "$2.tmp" && mv -f "$2.tmp" "$2"
}

# ----- settle (the apply unit's ExecStopPost) -------------------------------
cmd_settle() {
	[ "$#" -eq 1 ] && [[ $1 =~ $re_gen ]] || usage
	G=$1
	gd=$GENS/$G
	local s phase go=0
	[ -d "$gd" ] || exit 0
	klock 20 || { log "settle: cannot take the generation lock"; exit 0; }
	s=$(get "$gd" state)
	case $s in
		starting)
			# The unit ended before the switch began: nothing changed.
			put "$gd" refusal run_failed
			terminal refused
			log "generation $G: the apply unit ended before the switch"
			;;
		switching)
			# Killed by its bound (or it died) mid-switch.
			phase=$(switch_phase)
			if [ -z "$(get "$gd" cause)" ] && [ -z "$(get "$gd" verdict)" ]; then put "$gd" cause "$phase"; fi
			put "$gd" state reverting
			log "generation $G: the switch did not finish ($phase); reverting"
			go=1
			;;
		failed)
			put "$gd" state reverting
			go=1
			;;
		reverting) go=1 ;;
	esac
	kunlock
	if [ "$go" = 1 ]; then start_revert; fi
	exit 0
}

# ----- revert (the dead-man unit) -------------------------------------------
# revert_switch P END: P's switch, retried on a busy switch lock for at most
# 240 s inside 300 s, and never running past END (uptime seconds); 124 when
# no time is left.
revert_switch() {
	local P=$1 end=$2 t0 left rc attempt=$gd/.revert.attempt
	t0=$(uptime_s)
	[ "$end" -le $((t0 + 300)) ] || end=$((t0 + 300))
	while :; do
		left=$((end - $(uptime_s)))
		if [ "$left" -le 0 ]; then rc=124; break; fi
		timeout "$left" "$R$P/bin/switch-to-configuration" test > "$attempt" 2>&1 < /dev/null
		rc=$?
		cat "$attempt" >> "$gd/revert.out"
		if [ "$rc" != 0 ] && grep -q '^Could not acquire lock' "$attempt" && [ $(($(uptime_s) - t0)) -lt 240 ]; then
			sleep 2
			continue
		fi
		break
	done
	rm -f "$attempt"
	return "$rc"
}

cmd_revert() {
	[ "$#" -ge 1 ] && [[ $1 =~ $re_gen ]] || usage
	G=$1
	shift
	local cause=dead-man s T P cur reached ok=yes rc r rdl post left
	# Every leg ends by rdl, inside the unit's RuntimeMaxSec: 20 s are left for
	# the record's lock wait and 10 s for the unit's own start, so the bound
	# never cuts a leg and the revert records its own end. The switch leaves
	# 10 s for the checks after it, and 20 s more for a forced run's repair.
	rdl=$(($(uptime_s) + REVERT_BOUND - 30))
	if [ "$#" -gt 0 ]; then
		[ "$#" -eq 2 ] && [ "$1" = --cause ] || usage
		cause=$2
	fi
	case $cause in dead-man|aborted|activation_hang|unit_hang|stop_hang|switch_timeout) ;; *) usage ;; esac
	gd=$GENS/$G
	[ -d "$gd" ] || exit 0
	# The dead-man fires once: a busy lock is waited for again (three waits)
	# rather than leaving a switched generation on T with nothing armed.
	for r in 1 2 3; do
		klock "$REVERT_LOCK_WAIT" && break
		log "revert: the generation lock is busy (wait $r of 3)"
	done
	[ -n "$KFD" ] || { log "revert: cannot take the generation lock"; exit 1; }
	s=$(get "$gd" state)
	if is_terminal "$s"; then kunlock; exit 0; fi
	T=$(get "$gd" T) P=$(get "$gd" P)
	if [ -z "$(get "$gd" cause)" ] && [ -z "$(get "$gd" verdict)" ]; then put "$gd" cause "$cause"; fi
	cur=$(readlink "$R/run/current-system")
	# The stale guard: something other than this generation switched the
	# system; reverting would undo it.
	if [ "$cur" != "$P" ] && [ "$cur" != "$T" ]; then
		log "generation $G: the current system is neither its previous nor its new one; not reverting"
		terminal stale
		kunlock
		exit 0
	fi
	[ "$s" = reverting ] || put "$gd" state reverting
	reached=$(get "$gd" reached)
	kunlock
	log "generation $G: reverting to $P"
	timeout 30 systemctl stop "cogbox-live-apply-$G.service" >/dev/null 2>&1 \
		|| systemctl kill --signal=SIGKILL "cogbox-live-apply-$G.service" >/dev/null 2>&1
	case $reached in
		switching|switched)
			post=10
			[ -s "$gd/repair" ] && post=30
			revert_switch "$P" "$((rdl - post))"
			rc=$?
			put "$gd" revert_exit "$rc"
			case $rc in 0|4) ;; *) ok=no; log "revert: switch-to-configuration test of $P exited $rc" ;; esac
			if [ -s "$gd/repair" ]; then
				left=$((rdl - $(uptime_s)))
				[ "$left" -le 60 ] || left=60
				if [ "$left" -gt 0 ]; then
					log "repair: restarting $REPAIR_UNIT"
					timeout "$left" systemctl restart "$REPAIR_UNIT" || log "repair: restarting $REPAIR_UNIT failed"
				else
					log "repair: no time left to restart $REPAIR_UNIT"
				fi
			fi
			systemctl is-active --quiet sshd.service || { ok=no; log "revert: sshd.service is not active"; }
			systemctl is-active --quiet "$BRAIN_UNIT" || { ok=no; log "revert: $BRAIN_UNIT is not active"; }
			;;
		*) log "generation $G: nothing was switched" ;;
	esac
	[ "$(readlink "$R/run/current-system")" = "$P" ] || { ok=no; log "revert: the current system is not $P"; }
	klock 20 || { log "revert: cannot take the generation lock to record the outcome"; exit 1; }
	if [ "$(get "$gd" state)" = reverting ]; then
		if [ "$ok" = yes ]; then terminal reverted; else terminal revert_failed; fi
	fi
	kunlock
	exit 0
}

# The revert unit's ExecStopPost: a revert that did not finish (its bound, a
# crash) leaves the guest tainted.
cmd_settle_revert() {
	[ "$#" -eq 1 ] && [[ $1 =~ $re_gen ]] || usage
	G=$1
	gd=$GENS/$G
	[ -d "$gd" ] || exit 0
	klock 20 || exit 0
	if [ "$(get "$gd" state)" = reverting ]; then
		log "generation $G: the revert did not finish"
		terminal revert_failed
	fi
	kunlock
	exit 0
}

# ----- status, abort, confirm, log ------------------------------------------
# Parses "G --boot-id ID [--wait N]" into G, ID and WAIT.
gen_args() {
	local allow_wait=$1
	shift
	[ "$#" -ge 3 ] || usage
	G=$1 ID="" WAIT=0
	shift
	while [ "$#" -gt 0 ]; do
		case $1 in
			--boot-id) [ "$#" -ge 2 ] || usage; ID=$2; shift 2 ;;
			--wait) [ "$allow_wait" = 1 ] && [ "$#" -ge 2 ] || usage; WAIT=$2; shift 2 ;;
			*) usage ;;
		esac
	done
	[[ $G =~ $re_gen && $ID =~ $re_boot && $WAIT =~ $re_int ]] || usage
	[ "$WAIT" -le 30 ] || WAIT=30
	gd=$GENS/$G
}

snap() { printf '%s|%s|%s' "$(get "$gd" state)" "$(get "$gd" verdict)" "$(get "$gd" cause)"; }

cmd_status() {
	local ID WAIT s0 i=0
	gen_args 1 "$@"
	kv proto 2
	if [ "$ID" != "$(boot_id_raw)" ]; then kv result stale_boot; finish; fi
	if [ ! -d "$gd" ]; then kv result unknown; finish; fi
	# Long-poll: return at once on switched or a terminal state, else as
	# soon as the state, verdict or cause changes.
	s0=$(snap)
	while [ "$i" -lt "$WAIT" ]; do
		case $(get "$gd" state) in switched|refused|confirmed|reverted|revert_failed|stale) break ;; esac
		[ "$(snap)" = "$s0" ] || break
		sleep 1
		i=$((i + 1))
	done
	kv result ok
	block "$G"
	finish
}

cmd_abort() {
	local ID WAIT s go=0
	gen_args 0 "$@"
	kv proto 2
	if [ "$ID" != "$(boot_id_raw)" ]; then kv result stale_boot; finish; fi
	mkdir -p "$GENS" || usage
	glock 10 || { kv result lock_timeout; finish; }
	if [ ! -d "$gd" ]; then
		# Never seen this boot: a tombstone, under the lock `start` takes,
		# so a `start` of G still in flight answers stale and arms nothing.
		# Nothing else changes.
		if mkdir "$gd" && put "$gd" state stale; then
			logger -t cogbox-live-switch "generation $G: tombstoned" >/dev/null 2>&1
			gunlock
			kv result tombstoned
			block "$G"
			finish
		fi
		gunlock
		kv result error
		finish
	fi
	if ! klock 10; then gunlock; kv result lock_timeout; finish; fi
	gunlock
	s=$(get "$gd" state)
	# A no-op once a verdict or cause is recorded; it never replaces one.
	case $s in
		starting|switching|switched)
			if [ -z "$(get "$gd" verdict)" ] && [ -z "$(get "$gd" cause)" ]; then
				put "$gd" cause aborted
				if [ "$s" = switching ]; then put "$gd" cause_during yes; else put "$gd" cause_during no; fi
				put "$gd" state reverting
				go=1
			fi
			;;
	esac
	kunlock
	if [ "$go" = 1 ]; then start_revert; fi
	kv result ok
	block "$G"
	finish
}

cmd_confirm() {
	local ID WAIT s res
	gen_args 0 "$@"
	kv proto 2
	if [ "$ID" != "$(boot_id_raw)" ]; then kv result stale_boot; finish; fi
	if [ ! -d "$gd" ]; then kv result unknown; finish; fi
	klock 10 || { kv result lock_timeout; finish; }
	s=$(get "$gd" state)
	case $s in
		switched) terminal confirmed; res=confirmed ;;
		confirmed) res=confirmed ;;
		*) res=not_switched ;;
	esac
	kunlock
	kv result "$res"
	block "$G"
	finish
}

# The guest log of G (its units' output and both switches'), control
# characters removed, at most 64 KiB. The host keeps it in <G>.guest.log.
cmd_log() {
	[ "$#" -eq 1 ] && [[ $1 =~ $re_gen ]] || usage
	local d=$GENS/$1 f
	[ -d "$d" ] || exit 0
	for f in log switch.out revert.out; do
		[ -f "$d/$f" ] || continue
		printf '== %s\n' "$f"
		tail -c 32768 "$d/$f"
	done | tr -d '\000-\010\013-\037\177' | tail -c 65536
	exit 0
}

verb=${1-}
[ "$#" -gt 0 ] && shift
case $verb in
	settled|plan|start|status|abort|confirm)
		# Host-facing: diagnostics stay in the guest.
		mkdir -p "$ST" 2>/dev/null
		exec 2>>"$ST/helper.log" || exec 2>/dev/null
		;;
esac
case $verb in
	settled) cmd_settled "$@" ;;
	plan) cmd_plan "$@" ;;
	start) cmd_start "$@" ;;
	status) cmd_status "$@" ;;
	abort) cmd_abort "$@" ;;
	confirm) cmd_confirm "$@" ;;
	log) cmd_log "$@" ;;
	run) cmd_run "$@" ;;
	settle) cmd_settle "$@" ;;
	revert) cmd_revert "$@" ;;
	settle-revert) cmd_settle_revert "$@" ;;
	__register) cmd_register "$@" ;;
	__dry) cmd_dry "$@" ;;
	*) usage ;;
esac
