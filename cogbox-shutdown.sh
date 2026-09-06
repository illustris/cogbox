# Sourced by the launcher. Constants are fixed in the packaged source, not
# environment knobs. Tests source these functions and shorten the tick counts.
SHUTDOWN_GRACE_TICKS=450
SHUTDOWN_HELPER_TAIL_TICKS=10
SHUTDOWN_TERM_TICKS=50
SHUTDOWN_KILL_TICKS=50
SHUTDOWN_AUX_TICKS=30
SHUTDOWN_AUX_KILL_TICKS=10
SHUTDOWN_TICK=0.1
SHUTDOWN_TICK_CS=10
STOP_REQUESTED=0
STOP_FORCE=0
STOP_OUTCOME=failed
SHUTDOWN_HELPER_PID=""
QEMU_START=""

# Monotonic host uptime, in centiseconds. Poll-loop work must count against
# the budget too; counting sleeps alone can silently extend a host shutdown.
cogbox_shutdown_now() {
	local uptime rest
	read -r uptime rest < /proc/uptime || return 1
	COGBOX_SHUTDOWN_NOW=$(( ${uptime%.*} * 100 + 10#${uptime#*.} ))
}

# Linux starttime fences a PID against reuse. Parse after the LAST ')' because
# a process comm may contain spaces and parentheses. Never signal a guessed VM.
cogbox_process_start() {
	local line rest
	IFS= read -r line 2>/dev/null < "/proc/$1/stat" || return 1
	rest=${line##*) }
	local fields=()
	read -r -a fields <<< "$rest"
	[ "${#fields[@]}" -ge 20 ] || return 1
	printf '%s\n' "${fields[19]}"
}

cogbox_child_live() {
	local line rest
	[ -n "$1" ] || return 1
	IFS= read -r line 2>/dev/null < "/proc/$1/stat" || return 1
	rest=${line##*) }
	local fields=()
	read -r -a fields <<< "$rest"
	[ "${#fields[@]}" -ge 20 ] || return 1
	[ "${fields[1]}" = "$$" ] || return 1
	[ "${fields[0]}" != Z ] && [ "${fields[0]}" != X ] || return 1
	[ -z "${2:-}" ] || [ "${fields[19]}" = "$2" ]
}

cogbox_child_gone() {
	local line rest
	[ -n "$1" ] || return 0
	if ! IFS= read -r line 2>/dev/null < "/proc/$1/stat"; then
		# Missing process, not a procfs/I/O/permission failure. An unreadable
		# surviving process must never lead to an unbounded wait or cleanup.
		[ -r "/proc/$$/stat" ] && [ ! -d "/proc/$1" ]
		return
	fi
	rest=${line##*) }
	case "$rest" in Z\ *|X\ *) return 0 ;; esac
	return 1
}

cogbox_wait_child() {
	local pid=$1 ticks=$2 deadline
	cogbox_shutdown_now || return 1
	deadline=$((COGBOX_SHUTDOWN_NOW + ticks * SHUTDOWN_TICK_CS))
	while [ "$COGBOX_SHUTDOWN_NOW" -lt "$deadline" ]; do
		cogbox_child_gone "$pid" && return 0
		sleep "$SHUTDOWN_TICK"
		cogbox_shutdown_now || return 1
	done
	cogbox_child_gone "$pid"
}

cogbox_reap_child() {
	local repeated
	cogbox_child_gone "$1" || return 1
	wait "$1" 2>/dev/null; COGBOX_REAP_STATUS=$?
	if [ "$COGBOX_REAP_STATUS" -ge 128 ]; then
		# Bash can return the signal interrupting the outer wait even inside
		# EXIT cleanup. Reap this SAME already-ended child again to obtain its
		# cached actual status. A truly signaled child retains its nonzero
		# status; an unknown child (127) never manufactures success.
		wait "$1" 2>/dev/null; repeated=$?
		[ "$repeated" -eq 127 ] || COGBOX_REAP_STATUS=$repeated
	fi
}

cogbox_stop_init() {
	local nonce start
	IFS= read -r nonce < /proc/sys/kernel/random/uuid || return 1
	start=$(cogbox_process_start "$$") || return 1
	STOP_ID="v1 $nonce $$ $start"
	(umask 077; printf '%s\n' "$STOP_ID" > "$RUNTIME/launch") || return 1
}

cogbox_stop_result() {
	# Called only after cleanup, before the launcher exits. Retain this small
	# per-run record until the next start replaces runtime under the flock.
	(umask 077; printf '%s %s\n' "$STOP_ID" "$STOP_OUTCOME" > "$RUNTIME/stop-result.tmp") &&
		mv -f "$RUNTIME/stop-result.tmp" "$RUNTIME/stop-result"
}

cogbox_request_stop() {
	# Coalesce immediately, including the short interval BEFORE EXIT cleanup
	# begins. A second TERM must not terminate the shell inside its first trap.
	trap '' TERM INT
	STOP_REQUESTED=1
	if [ "${1:-}" = force ]; then
		STOP_FORCE=1
		trap '' USR1
	fi
	# A signal during an EXIT trap must not interrupt child-first cleanup.
	[ "$CLEANED" -eq 1 ] || exit 143
}

cogbox_stop_traps() {
	# Mask on the FIRST trap command, before entering a shell function. The
	# normal lane retains exactly one force upgrade; force masks all repeats.
	trap 'trap "" TERM INT; cogbox_request_stop' TERM INT
	trap 'trap "" TERM INT USR1; cogbox_request_stop force' USR1
}

cogbox_cancel_helper() {
	[ -n "$SHUTDOWN_HELPER_PID" ] || return 0
	# GNU timeout owns a private process group (without --foreground). Kill
	# that group too: the upstream helper contains a pipeline and sleep loop.
	if cogbox_child_live "$SHUTDOWN_HELPER_PID"; then
		kill -KILL -- "-$SHUTDOWN_HELPER_PID" 2>/dev/null || true
		kill -KILL "$SHUTDOWN_HELPER_PID" 2>/dev/null || true
	fi
	cogbox_wait_child "$SHUTDOWN_HELPER_PID" 10 || return 1
	wait "$SHUTDOWN_HELPER_PID" 2>/dev/null || true
	SHUTDOWN_HELPER_PID=""
}

cogbox_stop_child() {
	local helper="$RUNNER_DIR/bin/microvm-shutdown" deadline helper_rc=0 qemu_rc helper_done=0
	STOP_OUTCOME=already-stopped
	[ -n "$QEMU_PID" ] || return 0
	if [ -z "$QEMU_START" ] && ! cogbox_child_gone "$QEMU_PID"; then
		STOP_OUTCOME=failed
		return 1
	fi
	if ! cogbox_child_live "$QEMU_PID" "$QEMU_START"; then
		cogbox_child_gone "$QEMU_PID" || { STOP_OUTCOME=failed; return 1; }
		wait "$QEMU_PID" 2>/dev/null || true
		return 0
	fi
	STOP_OUTCOME=forced
	if [ "$STOP_REQUESTED" -eq 1 ] && [ "$STOP_FORCE" -eq 0 ] &&
		[ -x "$helper" ] && [ -S "$RUNTIME/cogbox.socket" ]; then
		# The selected pinned helper sends Ctrl-Alt-Delete. QEMU's no-reboot
		# exits after guest shutdown. No SSH/network and no raw QMP in logs.
		cogbox_shutdown_now || { STOP_OUTCOME=failed; return 1; }
		# Reserve the final second INSIDE the 45s budget for helper-group
		# termination/reap, including a helper that ignores TERM.
		deadline=$((COGBOX_SHUTDOWN_NOW + (SHUTDOWN_GRACE_TICKS - SHUTDOWN_HELPER_TAIL_TICKS) * SHUTDOWN_TICK_CS))
		# Kill the helper GROUP at its deadline. TERM could let its leader
		# exit while a resistant pipeline descendant survives the timeout.
		(cd "$RUNTIME" && exec timeout --signal=KILL 44s "$helper") >/dev/null 2>&1 &
		SHUTDOWN_HELPER_PID=$!
		while [ "$COGBOX_SHUTDOWN_NOW" -lt "$deadline" ]; do
			[ "$STOP_FORCE" -eq 0 ] || break
			if [ "$helper_done" -eq 0 ] && ! cogbox_child_live "$SHUTDOWN_HELPER_PID"; then
				cogbox_child_gone "$SHUTDOWN_HELPER_PID" || break
				cogbox_reap_child "$SHUTDOWN_HELPER_PID" || break
				helper_rc=$COGBOX_REAP_STATUS
				SHUTDOWN_HELPER_PID=""
				helper_done=1
				if [ "$helper_rc" -ne 0 ]; then
					echo "cogbox-launch: shutdown helper failed (status $helper_rc)" >&2
					break
				fi
			fi
			if [ "$helper_done" -eq 1 ]; then
				# Socket teardown can precede final QEMU exit. Give the child
				# the REMAINING grace budget, never a second full window.
				if ! cogbox_child_live "$QEMU_PID" "$QEMU_START"; then
					cogbox_child_gone "$QEMU_PID" || { STOP_OUTCOME=failed; return 1; }
					cogbox_reap_child "$QEMU_PID" || { STOP_OUTCOME=failed; return 1; }
					qemu_rc=$COGBOX_REAP_STATUS
					if [ "$qemu_rc" -eq 0 ]; then
						STOP_OUTCOME=graceful
						return 0
					fi
					echo "cogbox-launch: guest exited unsuccessfully during shutdown (status $qemu_rc)" >&2
					break
				fi
			fi
			sleep "$SHUTDOWN_TICK"
			cogbox_shutdown_now || break
		done
		if [ "$COGBOX_SHUTDOWN_NOW" -ge "$deadline" ]; then
			echo 'cogbox-launch: graceful shutdown deadline expired' >&2
		fi
		cogbox_cancel_helper || { STOP_OUTCOME=failed; return 1; }
	fi
	# Only the child from this launch, still owned and starttime-matched, may
	# receive fallback signals. A helper error is never hidden as graceful.
	if cogbox_child_live "$QEMU_PID" "$QEMU_START"; then
		kill -TERM "$QEMU_PID" 2>/dev/null || true
		if ! cogbox_wait_child "$QEMU_PID" "$SHUTDOWN_TERM_TICKS" "$QEMU_START"; then
			cogbox_child_live "$QEMU_PID" "$QEMU_START" || { STOP_OUTCOME=failed; return 1; }
			kill -KILL "$QEMU_PID" 2>/dev/null || true
			if ! cogbox_wait_child "$QEMU_PID" "$SHUTDOWN_KILL_TICKS" "$QEMU_START"; then
				STOP_OUTCOME=failed
				return 1
			fi
		fi
	fi
	cogbox_child_gone "$QEMU_PID" || { STOP_OUTCOME=failed; return 1; }
	wait "$QEMU_PID" 2>/dev/null || true
	return 0
}

cogbox_stop_aux() {
	local pid live deadline
	for pid in "$@"; do
		cogbox_child_live "$pid" && kill -TERM "$pid" 2>/dev/null || true
	done
	# One shared budget, not a separate delay for each supporting process.
	cogbox_shutdown_now || return 1
	deadline=$((COGBOX_SHUTDOWN_NOW + SHUTDOWN_AUX_TICKS * SHUTDOWN_TICK_CS))
	while [ "$COGBOX_SHUTDOWN_NOW" -lt "$deadline" ]; do
		live=0
		for pid in "$@"; do cogbox_child_live "$pid" && live=1; done
		[ "$live" -eq 1 ] || break
		sleep "$SHUTDOWN_TICK"
		cogbox_shutdown_now || return 1
	done
	for pid in "$@"; do
		cogbox_child_live "$pid" && kill -KILL "$pid" 2>/dev/null || true
	done
	cogbox_shutdown_now || return 1
	deadline=$((COGBOX_SHUTDOWN_NOW + SHUTDOWN_AUX_KILL_TICKS * SHUTDOWN_TICK_CS))
	while [ "$COGBOX_SHUTDOWN_NOW" -lt "$deadline" ]; do
		live=0
		for pid in "$@"; do cogbox_child_live "$pid" && live=1; done
		[ "$live" -eq 1 ] || break
		sleep "$SHUTDOWN_TICK"
		cogbox_shutdown_now || return 1
	done
	for pid in "$@"; do
		[ -n "$pid" ] || continue
		# No blocking wait on a survivor: retain diagnostics on D-state I/O.
		cogbox_child_gone "$pid" || return 1
		wait "$pid" 2>/dev/null || true
	done
}
