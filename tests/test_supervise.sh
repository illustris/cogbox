#!/usr/bin/env bash
# Behavioural test for gce/supervise.sh, the GCE sandbox supervisor.
#
# Everything this script does that matters is an ORDERING or a REFUSAL, and
# neither is visible in the unit file, so a flake check over the systemd graph
# cannot reach any of it. What is covered here:
#
#   - leg (a2) publishes the VM host key on a MAINTENANCE and a RESOLVER boot,
#     with zero `cogbox start`. Publishing it only on boots that start a sandbox
#     kills two paths outright: an instance whose first-ever boot is a
#     maintenance boot could never be pinned (so every stopped mutation returns
#     ErrSandboxNotReady forever), and the resolver flow blocks on an attribute
#     that never appears -- whose cheapest "fix" is a TOFU dial on the one
#     connection carrying a live git OAuth token.
#   - on a normal boot the host-key publish PRECEDES `cogbox start`.
#   - a MAINTENANCE boot on an instance that has never booted RUNS `cogbox init`
#     -- and still runs `cogbox start` zero times. A maintenance boot exists so
#     a mutation can run against a stopped instance, every one of those
#     mutations reads config.json, and nothing but init creates it. With the
#     short-circuit ahead of init, the one path that mutates an instance that
#     has NEVER booted -- create-with-plugins / template-instantiate, which hold
#     the instance Stopped through the PluginAdd, NetworkRuleAdd and SecretBind
#     loops and only Start at the tail -- lost every create-time plugin, rule
#     and secret to "No such file or directory" and reported "partial".
#   - a maintenance boot on an ALREADY-initialized instance does NOT re-run
#     init. Re-running is safe (cogbox-launch.sh seeds config.json, the scaffold
#     flake, authorized_keys and every harness path only when absent) but not
#     free: once config.json lists a plugin, init's tail re-execs a full nix
#     eval of the composed runner, which is exactly the per-mutation cost
#     cogworxd's maintenance path declines to pay.
#   - a RESOLVER boot runs NEITHER init nor start. It is this image with no
#     state disk attached and it seeds its own placeholder config over the
#     control channel, so supervisor-side init would either trip the
#     state-disk assertion or write cogbox state onto the boot disk of a machine
#     that evaluates attacker-controlled flakes.
#   - the per-start nonce is read exactly once. Re-reading it would let a later
#     leg stamp a different epoch's value onto readiness.
#   - readiness is published only after the GUEST's host key file appears, and
#     the readiness DELETE precedes the non-zero exit, so a dead sandbox cannot
#     coast on a stamped attribute.
#   - `cogbox init` carries --bind-addr, --no-implicit-dns and one --self-addr
#     per metadata entry. Without a producer, cogbox's parameterized port-53
#     allow and l7proxy's self-address floor are both dead code and the image
#     ships the permissive defaults.
#   - an absent OR EMPTY cogworx-self-addrs with no provider fallback exits
#     non-zero with zero `cogbox start` -- the same fail-closed the floor unit
#     applies to its own vacuous-rule case.
#   - but an empty cogworx-self-addrs whose provider DOES name an interface
#     address boots normally, seeding --bind-addr and --self-addr from it. That
#     is the realized FIRST-BOOT shape: every insert body stamps the attribute
#     empty, so treating empty as fatal killed every fresh sandbox and every
#     resolver VM on its first (and, for a resolver, only) boot.
#   - an absent cogworx-guest-resolver does the same. COGBOX_GUEST_RESOLVER
#     carries passt's --dns-forward and --no-map-gw as ONE knob, so a missing
#     attribute would silently drop --no-map-gw from both passt invocations and
#     leave passt's gateway mapping to the host's loopback in place --
#     unfiltered in `full` mode.
#   - `cogbox init` carries --dns-host, and the two other halves of guest DNS
#     are fail-closed: an unset COGBOX_HOST_RESOLVER, and an /etc/resolv.conf
#     that does not name that forwarder. Both failures are SILENT otherwise --
#     the sandbox comes up healthy and resolves nothing -- which is why they
#     refuse the boot rather than warn.
#   - a canary in the cogbox runtime log never reaches the serial sink.
#   - leg (j) records an UNREQUESTED inner exit: a 0700 ring of 0600 records on
#     the STATE DISK (leg, stop-result, meminfo, the kernel's kill lines, the
#     guest console tail), bounded to 20, plus a nonce-stamped per-epoch count
#     in cogworx/inner-exit. Serial gets a one-line pointer and never the
#     console text; a stop requested through ExecStop is not recorded; and a
#     record that cannot be written never blocks the restart.
#   - an OOM kill of any process in the unit -- a helper while QEMU keeps
#     running, or QEMU itself -- ends the sandbox through leg (j) as `oom-kill`.
#     Under OOMPolicy=continue nothing else restarts a dead passt or L7 proxy.
#     A helper's kill first drains the still-live guest with `cogbox stop`
#     (readiness deleted before it, the record and the exit after it), since
#     leg (j)'s exit skips ExecStop; a drain that fails is only noted.
#   - the boot proof (leg h2). cogworx/boot-proof is deleted at run start
#     before anything is published, and wherever readiness is (leg (j), the
#     OOM drain, a failed start, both short-circuits). The guest's boot stamp
#     is cleared before `cogbox start` -- a directory with rm -rf -- and a path
#     that survives both removals (a file, a dangling symlink, a directory)
#     publishes exactly the err=stamp-path proof instead of any success proof.
#     A stamp this launch's guest wrote publishes exactly
#     `<nonce> bp= hb= gb= pool= sf=`, each value from its own baked
#     variable, once and after readiness; a stale,
#     malformed, host-boot-id, symlinked or FIFO stamp publishes nothing,
#     never reaches the read at all when it is already a symlink or a FIFO,
#     and never costs the guest its life -- nor does one the guest swaps for a
#     symlink or a FIFO after the host's check, which the read's O_NOFOLLOW
#     and 2 s bound (exactly 2 s) refuse without stalling the loop; the read
#     stops at 256 bytes; and READY_TIMEOUT still counts readiness alone.
#     Readiness gains a
#     `bp=` tail only from a valid baked protocol version; without one there
#     is no proof of either kind. A PUT that fails -- readiness, the proof,
#     the refusal -- is retried until one lands, in the same order; the
#     refusal is retried whether or not the guest is ready, and while it is
#     still owed no success proof lands and the ready guest is not killed for
#     it. Nothing
#     from the stamp reaches serial, and the boot-error contract the control
#     plane classifies by (a classified summary, the generic literal, cleared
#     by a later successful init) is unchanged -- except that a
#     cogbox-stamped WARNING no longer stands in for an unstamped failure.
#
# Usage: test_supervise.sh <path-to-supervise.sh>
# Needs: bash, coreutils, gawk, gnugrep. NOT curl/cogbox/GCE -- both are stubs.

set -uo pipefail

SUP="${1:?usage: test_supervise.sh <supervise.sh>}"
[ -f "$SUP" ] || { echo "FAIL: no such script: $SUP" >&2; exit 1; }

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

fails=0
ok()  { echo "ok   - $*"; }
bad() { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

# --- stubs ------------------------------------------------------------------
#
# Both stubs append to ONE ordered event log, which is what makes "publish
# precedes start" assertable at all.

BIN="$ROOT/bin"
mkdir -p "$BIN"

# Resolved, not `#!/usr/bin/env bash`: this test runs inside a nix build
# sandbox, which has no /usr/bin/env.
BASH_BIN=$(command -v bash)
shebang() { printf '#!%s\n' "$BASH_BIN"; }

{ shebang; cat <<'STUB'
method=GET; data=""; url=""
while [ $# -gt 0 ]; do
	case "$1" in
		-X) method="$2"; shift 2 ;;
		--data-binary|--data) data="$2"; shift 2 ;;
		-o) shift 2 ;;
		-H|--max-time) shift 2 ;;
		http*) url="$1"; shift ;;
		*) shift ;;
	esac
done
path="${url#*/computeMetadata/v1/}"
# STUB_PUT_FAIL_ONCE=<attr>: the FIRST PUT of that guest attribute fails, as a
# transient metadata-server error would. It is logged as FAILED-PUT, so a count
# of `^PUT ` events still counts only the publishes that landed.
if [ "$method" = PUT ] && [ -n "${STUB_PUT_FAIL_ONCE:-}" ] \
	&& [ "$path" = "instance/guest-attributes/$STUB_PUT_FAIL_ONCE" ] \
	&& [ ! -e "$FAKEMD/put-failed-once" ]; then
	: > "$FAKEMD/put-failed-once"
	printf 'FAILED-PUT %s %s\n' "$path" "$data" >> "$FAKEMD/events"
	exit 22
fi
# STUB_PUT_FAIL_DATA=<text>: EVERY PUT whose value contains that text fails,
# logged the same way -- a metadata-server error that outlasts the run.
if [ "$method" = PUT ] && [ -n "${STUB_PUT_FAIL_DATA:-}" ] && [[ "$data" == *"$STUB_PUT_FAIL_DATA"* ]]; then
	printf 'FAILED-PUT %s %s\n' "$path" "$data" >> "$FAKEMD/events"
	exit 22
fi
printf '%s %s %s\n' "$method" "$path" "$data" >> "$FAKEMD/events"
gakey() { printf '%s' "${path#instance/guest-attributes/}" | tr / _; }
case "$method" in
	GET)
		case "$path" in
			instance/id) echo 123456; exit 0 ;;
			# The PROVIDER's own statement of this VM's interface addresses:
			# the source both the floor unit and the supervisor fall back to
			# when cogworx-self-addrs is empty, which it always is on the
			# first boot after an insert.
			instance/network-interfaces/)
				[ -f "$FAKEMD/nics/index" ] || exit 22
				cat "$FAKEMD/nics/index"; exit 0 ;;
			instance/network-interfaces/*/ip)
				n="${path#instance/network-interfaces/}"; n="${n%/ip}"
				[ -f "$FAKEMD/nics/$n" ] || exit 22
				cat "$FAKEMD/nics/$n"; exit 0 ;;
			instance/attributes/*)
				f="$FAKEMD/attrs/${path#instance/attributes/}"
				[ -f "$f" ] || exit 22
				cat "$f"; exit 0 ;;
			instance/guest-attributes/*)
				f="$FAKEMD/ga/$(gakey)"
				[ -f "$f" ] || exit 22
				cat "$f"; exit 0 ;;
		esac
		exit 22 ;;
	PUT)
		case "$path" in
			instance/guest-attributes/*) printf '%s' "$data" > "$FAKEMD/ga/$(gakey)"; exit 0 ;;
		esac
		exit 22 ;;
	DELETE)
		case "$path" in
			instance/guest-attributes/*) rm -f "$FAKEMD/ga/$(gakey)"; exit 0 ;;
		esac
		exit 22 ;;
esac
exit 22
STUB
} > "$BIN/curl"

{ shebang; cat <<'STUB'
printf 'cogbox %s\n' "$*" >> "$FAKEMD/events"
case "${1:-}" in
	init)
		# A FAILING init, which is the shape the classification leg exists for:
		# write the requested output on BOTH streams (the supervisor captures the
		# combined one) and exit non-zero. The real failure is a guest system
		# that will not evaluate, whose entire diagnostic value is in these lines.
		if [ -n "${STUB_INIT_OUT:-}" ]; then
			printf '%s\n' "$STUB_INIT_OUT"
			printf '%s\n' "$STUB_INIT_OUT" >&2
		fi
		[ "${STUB_INIT_RC:-0}" = 0 ] || exit "${STUB_INIT_RC}"
		# The real init seeds $XDG_CONFIG_HOME/cogbox/instances/<name>/config.json
		# and writes it ONLY when the file is absent (cogbox-launch.sh), which is
		# both what a mutation reads and what makes re-running init safe. Mirror
		# both here, so "a maintenance boot produces a config" is asserted against
		# the file rather than against an argv line.
		name=""; prev=""
		for a in "$@"; do
			case "$prev" in -n|--name) name="$a" ;; esac
			prev="$a"
		done
		d="$XDG_CONFIG_HOME/cogbox/instances/${name:-default}"
		mkdir -p "$d"
		[ -f "$d/config.json" ] || printf '{"vcpu":4}\n' > "$d/config.json"
		exit 0 ;;
	start)
		# Leg (h2): whatever sits at the guest's boot-stamp path when the launch
		# begins. The supervisor must have cleared it, or a stamp it reads after
		# this line could be a previous boot's.
		stamp="$COGBOX_DATA/instances/demo/.cogbox-boot-stamp"
		if [ -e "$stamp" ] || [ -L "$stamp" ]; then
			echo "stamp at start: present" >> "$FAKEMD/events"
		else
			echo "stamp at start: absent" >> "$FAKEMD/events"
		fi
		# The guest writes its persisted host key only after it boots, so a
		# stub that creates it up front would make the readiness ordering
		# assertion vacuous.
		if [ -n "${STUB_GUEST_KEY:-}" ]; then
			mkdir -p "$(dirname "$STUB_GUEST_KEY")"
			printf 'ssh-ed25519 AAAAguestkey guest\n' > "$STUB_GUEST_KEY"
		fi
		# What the real launcher leaves in its runtime dir for leg (j) to read:
		# the guest's serial console and the launcher's own stop-result. Written
		# here, i.e. after the supervisor's leg (e) cleared the runtime.
		if [ -n "${STUB_CONSOLE:-}" ]; then
			mkdir -p "$XDG_RUNTIME_DIR/cogbox-demo"
			printf '%s\n' "$STUB_CONSOLE" > "$XDG_RUNTIME_DIR/cogbox-demo/console.log"
			printf 'run-1 exited\n' > "$XDG_RUNTIME_DIR/cogbox-demo/stop-result"
		fi
		# What this launch's guest leaves at the stamp path: its
		# cogbox-boot-stamp.service, which writes once its sshd is up. `stale`
		# and `none` write nothing (stale is a PREVIOUS boot's stamp, seeded by
		# run_boot); `undeletable` and `dir` write a good one over whatever the
		# supervisor could or could not clear; `undeletable-link` and
		# `dir-undeletable` leave what run_boot seeded and neither removal
		# clears.
		mkdir -p "$(dirname "$stamp")"
		case "${STUB_STAMP:-none}" in
			match|dir|undeletable) printf '%s pool=%s\n' "$STUB_GB" "$STUB_POOL" > "$stamp" ;;
			bad) printf '%b' "$STUB_STAMP_TEXT" > "$stamp" ;;
			symlink)
				printf '%s pool=ok\n' "$STUB_GB" > "$stamp.target"
				ln -s "$stamp.target" "$stamp" ;;
			fifo) mkfifo "$stamp" ;;
		esac
		exit "${STUB_START_RC:-0}" ;;
	stop)
		# The supervisor's own guest drain (leg (i), after a helper's OOM kill).
		# The event line above orders it against the metadata calls; the stdout
		# line orders it against the supervisor's journal. Like the real
		# launcher, a finished requested stop leaves its outcome in stop-result.
		echo "cogbox-stub: $*"
		mkdir -p "$XDG_RUNTIME_DIR/cogbox-demo"
		printf 'run-1 graceful\n' > "$XDG_RUNTIME_DIR/cogbox-demo/stop-result"
		exit "${STUB_STOP_RC:-0}" ;;
	status)
		n=0
		[ -f "$FAKEMD/statusn" ] && n=$(cat "$FAKEMD/statusn")
		n=$((n + 1)); echo "$n" > "$FAKEMD/statusn"
		# The kernel OOM-killing a process of the unit, as the supervisor sees
		# it: its cgroup's memory.events `oom_kill` count goes up. Whether
		# QEMU was the victim is what the status answer below says.
		if [ -n "${STUB_OOM_AT:-}" ] && [ "$n" = "$STUB_OOM_AT" ]; then
			printf 'oom 1\noom_kill 1\noom_group_kill 0\n' > "$COGWORX_UNIT_MEMORY_EVENTS"
		fi
		[ "$n" -le "${STUB_STATUS_OK:-2}" ] && exit 0
		# A REQUESTED stop: ExecStop (gce/stop-supervisor.sh) drops this marker
		# before it stops the guest the supervisor is polling.
		if [ -n "${STUB_STOPPING:-}" ]; then
			: > "$XDG_RUNTIME_DIR/cogworx-supervisor-stopping"
		fi
		exit 1 ;;
esac
exit 0
STUB
} > "$BIN/cogbox"

# Real sleeps would make a 300 s readiness budget a 300 s test. The loop bound
# is an iteration count for exactly this reason.
{ shebang; printf 'exit 0\n'; } > "$BIN/sleep"
{ shebang; printf 'exit 0\n'; } > "$BIN/mountpoint"
# The kernel ring, as leg (j) reads it: one OOM kill it must keep and one
# unrelated line its filter must drop. Stubbed so the case is deterministic and
# does not depend on the build sandbox being allowed to read the real one.
{ shebang; cat <<'STUB'
echo '[  797.1] Out of memory: Killed process 988 (qemu-system-x86) shmem-rss:1kB'
echo '[  797.2] unrelated-dmesg-line'
STUB
} > "$BIN/dmesg"
# Every removal is the real one, but one naming the guest's boot stamp is also
# logged, so leg (h2)'s clear can be ordered against `cogbox start` -- and under
# STUB_STAMP=undeletable (a file), undeletable-link (a dangling symlink) or
# dir-undeletable (a directory, so `rm -rf` fails too) it fails, standing in for
# a path neither of the supervisor's removals can clear (an immutable attribute,
# a mount squatting there or below it).
REAL_RM=$(command -v rm)
{ shebang; printf 'REAL_RM=%q\n' "$REAL_RM"; cat <<'STUB'
for a in "$@"; do
	case "$a" in
		*/.cogbox-boot-stamp)
			printf 'rm %s\n' "$*" >> "$FAKEMD/events"
			case "${STUB_STAMP:-}" in undeletable|undeletable-link|dir-undeletable) exit 1 ;; esac ;;
	esac
done
exec "$REAL_RM" "$@"
STUB
} > "$BIN/rm"
# Every stamp read is the real dd too, logged as `dd-read <path>`, but under
# STUB_STAMP_SWAP it first renames a symlink or a FIFO over the stamp: the guest
# winning the race between the supervisor's `[ -f ] && [ ! -L ]` check and dd's
# open, which is the only window the read's O_NOFOLLOW and its time bound exist
# for. A stamp that is ALREADY a symlink or FIFO must never reach dd -- the log
# is what asserts that -- so without this seam neither defence is load-bearing
# in any case.
REAL_DD=$(command -v dd)
{ shebang; printf 'REAL_DD=%q\n' "$REAL_DD"; cat <<'STUB'
for a in "$@"; do
	case "$a" in
		if=*/.cogbox-boot-stamp)
			p="${a#if=}"
			printf 'dd-read %s\n' "$p" >> "$FAKEMD/events"
			case "${STUB_STAMP_SWAP:-}" in
				symlink)
					printf '%s pool=ok\n' "$STUB_GB" > "$p.target"
					ln -sfn "$p.target" "$p.swap" && mv -fT "$p.swap" "$p" ;;
				fifo) mkfifo "$p.swap" && mv -fT "$p.swap" "$p" ;;
			esac ;;
	esac
done
exec "$REAL_DD" "$@"
STUB
} > "$BIN/dd"
# ...and every stamp read's time bound is the real timeout's, logged as
# `timeout-read <duration>`. The FIFO-swap run's wall time shows the bound
# works; this pins it at the 2 s the protocol names, which no wall-clock
# threshold a loaded build machine can keep could tell from 5 s.
REAL_TIMEOUT=$(command -v timeout)
{ shebang; printf 'REAL_TIMEOUT=%q\n' "$REAL_TIMEOUT"; cat <<'STUB'
for a in "$@"; do
	case "$a" in
		if=*/.cogbox-boot-stamp) printf 'timeout-read %s\n' "$1" >> "$FAKEMD/events" ;;
	esac
done
exec "$REAL_TIMEOUT" "$@"
STUB
} > "$BIN/timeout"
chmod 0755 "$BIN"/*

# Leg (h2)'s boot ids: the HOST's (the supervisor's COGWORX_BOOT_ID_FILE seam),
# the guest's for this launch, and a previous guest boot's.
HOST_BOOT_ID=11111111-2222-4333-8444-555555555555
GUEST_BOOT_ID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
PREV_BOOT_ID=99999999-8888-4777-8666-555555555555

# --- harness ----------------------------------------------------------------

# run_boot <tag> [attr=value ...] -- seeds a metadata blob and runs one boot.
# Echoes the exit status; the caller reads $FAKEMD/events.
run_boot() {
	local tag="$1"; shift
	local home="$ROOT/$tag"
	FAKEMD="$home/md"
	mkdir -p "$FAKEMD/attrs" "$FAKEMD/ga" "$FAKEMD/nics" "$home/state/sshd" "$home/run"
	: > "$FAKEMD/events"
	# Off unless a case opts in, so every other case still proves the
	# both-sources-empty fail-closed rather than silently taking the fallback.
	if [ -n "${SEED_NIC_IP:-}" ]; then
		printf '0/\n' > "$FAKEMD/nics/index"
		printf '%s' "$SEED_NIC_IP" > "$FAKEMD/nics/0"
	fi
	# The VM's own sshd host key already exists on the state disk: sshd-keygen
	# wrote it, and the mount unit is ordered before both.
	printf 'ssh-ed25519 AAAAvmhostkey root@vm\n' > "$home/state/sshd/ssh_host_ed25519_key.pub"
	# A case opts into "this instance has booted before" by naming the instance
	# whose config the state disk already carries. Off by default, so every other
	# case runs against the never-booted shape -- the one the maintenance-boot
	# regression lived on.
	if [ -n "${SEED_INIT_CONFIG:-}" ]; then
		mkdir -p "$home/state/config/cogbox/instances/$SEED_INIT_CONFIG"
		printf '{"vcpu":4,"plugins":["obs-plugin"]}\n' \
			> "$home/state/config/cogbox/instances/$SEED_INIT_CONFIG/config.json"
	fi
	# The host's resolv.conf, standing in for the one systemd-resolved writes.
	# A case can override the nameserver it names (SEED_RESOLV_NS) to exercise
	# the refusal; the default is the healthy shape.
	printf 'nameserver %s\n' "${SEED_RESOLV_NS:-127.0.0.53}" > "$home/resolv.conf"
	# The unit cgroup's memory.events, with no OOM kill yet. Seeded on every
	# case so none depends on the build sandbox's own cgroup; a case opts out
	# (SEED_NO_MEM_EVENTS) to exercise the unreadable-counter warning.
	rm -f "$home/memory.events"
	[ -n "${SEED_NO_MEM_EVENTS:-}" ] \
		|| printf 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n' > "$home/memory.events"
	# The host boot id leg (h2) binds a proof to, and the guest's boot stamp as
	# a PREVIOUS boot left it on the 9p share: a complete, well-formed stamp
	# (`stale`, and the one that cannot be cleared), a directory (and one that
	# cannot be cleared), or a dangling symlink that cannot be cleared (which
	# `-e` alone does not see).
	printf '%s\n' "$HOST_BOOT_ID" > "$home/boot_id"
	local stamp="$home/state/data/cogbox/instances/demo/.cogbox-boot-stamp"
	case "${STUB_STAMP:-none}" in
		stale|undeletable)
			mkdir -p "$(dirname "$stamp")"
			printf '%s pool=ok\n' "$PREV_BOOT_ID" > "$stamp" ;;
		dir|dir-undeletable)
			mkdir -p "$stamp/sub"
			printf '%s pool=ok\n' "$PREV_BOOT_ID" > "$stamp/sub/f" ;;
		undeletable-link)
			mkdir -p "$(dirname "$stamp")"
			ln -s "$stamp.gone" "$stamp" ;;
	esac
	local kv
	for kv in "$@"; do
		printf '%s' "${kv#*=}" > "$FAKEMD/attrs/${kv%%=*}"
	done
	PATH="$BIN:$PATH" \
	FAKEMD="$FAKEMD" \
	COGBOX_HOST_RESOLVER="${SEED_HOST_RESOLVER-127.0.0.53}" \
	COGWORX_RESOLV_CONF="$home/resolv.conf" \
	STUB_GUEST_KEY="${SEED_GUEST_KEY-$home/state/data/cogbox/instances/demo/ssh/ssh_host_ed25519_key.pub}" \
	COGWORX_MD_BASE="http://metadata.invalid/computeMetadata/v1" \
	COGWORX_SERIAL="$home/serial.log" \
	COGWORX_STATE_DIR="$home/state" \
	COGWORX_POLL_INTERVAL=1 \
	COGWORX_READY_TIMEOUT=4 \
	COGWORX_HOSTKEY_TIMEOUT=2 \
	COGWORX_GUEST_VOLUMES="${SEED_GUEST_VOLUMES-}" \
	STUB_INIT_RC="${STUB_INIT_RC:-0}" \
	STUB_INIT_OUT="${STUB_INIT_OUT:-}" \
	STUB_CONSOLE="${STUB_CONSOLE:-}" \
	STUB_STOPPING="${STUB_STOPPING:-}" \
	STUB_STATUS_OK="${STUB_STATUS_OK:-2}" \
	STUB_OOM_AT="${STUB_OOM_AT:-}" \
	STUB_STOP_RC="${STUB_STOP_RC:-0}" \
	STUB_START_RC="${STUB_START_RC:-0}" \
	STUB_STAMP="${STUB_STAMP:-none}" \
	STUB_STAMP_TEXT="${STUB_STAMP_TEXT:-}" \
	STUB_STAMP_SWAP="${STUB_STAMP_SWAP:-}" \
	STUB_PUT_FAIL_ONCE="${STUB_PUT_FAIL_ONCE:-}" \
	STUB_PUT_FAIL_DATA="${STUB_PUT_FAIL_DATA:-}" \
	STUB_GB="$GUEST_BOOT_ID" \
	STUB_POOL="${STUB_POOL:-ok}" \
	COGWORX_BOOT_ID_FILE="${SEED_BOOT_ID_FILE-$home/boot_id}" \
	COGWORX_IMAGE_BOOT_PROOF="${SEED_BP-1}" \
	COGWORX_IMAGE_STATE_FORMAT="${SEED_SF-1}" \
	COGWORX_UNIT_MEMORY_EVENTS="$home/memory.events" \
	XDG_CONFIG_HOME="${SEED_XDG_CONFIG_HOME-$home/state/config}" \
	COGBOX_DATA="$home/state/data/cogbox" \
	XDG_RUNTIME_DIR="$home/run" \
		timeout 60 bash "$SUP" > "$home/out.log" 2>&1
	local rc=$?
	# Every case finishes in well under a second (sleep is a stub), so a run
	# that hits the bound is a supervisor that wedged -- a stamp read that
	# blocks, say. Recorded here and failed at the end: this function runs in a
	# command substitution, where `bad` would not count.
	[ "$rc" != 124 ] || echo "$tag" >> "$ROOT/wedged"
	echo "$rc"
}

evline() { grep -n -- "$2" "$1/events" 2>/dev/null | head -1 | cut -d: -f1; }
evcount() { grep -c -- "$2" "$1/events" 2>/dev/null || true; }

BASE_ATTRS=(
	"cogworx-start-nonce=n0nce-aaaa"
	"cogworx-instance=demo"
	"cogworx-vcpu=4"
	"cogworx-mem-mb=8192"
	"cogworx-network=rules"
	"cogworx-guest-resolver=192.0.2.53"
	"cogworx-self-addrs=10.0.0.5 10.0.0.6"
)

# --- 1. normal boot ---------------------------------------------------------

rc=$(run_boot normal "${BASE_ATTRS[@]}")
md="$ROOT/normal/md"
[ "$(cat "$ROOT/normal/run/cogworx-supervisor-instance" 2>/dev/null)" = demo ] \
	|| bad "normal start did not capture the exact shutdown identity"
[ "$(stat -c %a "$ROOT/normal/run/cogworx-supervisor-instance" 2>/dev/null)" = 600 ] \
	|| bad "shutdown identity was not private"

# A surviving previous QEMU holds the lifetime flock. Neither its runtime nor
# the inode protecting it may be removed by a supervisor restart.
mkdir -p "$ROOT/locked/run/cogbox-demo"
printf 'preserved\n' > "$ROOT/locked/run/cogbox-demo/sentinel"
exec 8> "$ROOT/locked/run/cogbox-demo.lock"
flock -x 8
lock_inode=$(stat -c %i "$ROOT/locked/run/cogbox-demo.lock")
locked_rc=$(run_boot locked "${BASE_ATTRS[@]}" 8>&-)
[ "$locked_rc" != 0 ] || bad "supervisor accepted an owned runtime"
[ "$(evcount "$ROOT/locked/md" 'cogbox start')" = 0 ] || bad "supervisor launched over an owned runtime"
[ "$(cat "$ROOT/locked/run/cogbox-demo/sentinel")" = preserved ] || bad "supervisor deleted live runtime contents"
[ "$(stat -c %i "$ROOT/locked/run/cogbox-demo.lock")" = "$lock_inode" ] || bad "supervisor replaced the lifetime lock inode"
exec 8>&-
ok "owned runtime contents and lifetime lock survive supervisor restart"

# The supervisor exits non-zero once the sandbox is gone, so Restart=always
# re-runs the whole sequence rather than leaving a half-torn-down instance.
[ "$rc" != 0 ] || bad "normal boot exited 0; Restart=always would never re-run the sequence"

pub=$(evline "$md" 'PUT instance/guest-attributes/cogworx/vm-host-key')
start=$(evline "$md" 'cogbox start')
if [ -n "$pub" ] && [ -n "$start" ] && [ "$pub" -lt "$start" ]; then
	ok "the VM host-key publish precedes cogbox start"
else
	bad "host-key publish ($pub) did not precede cogbox start ($start); events: $(cat "$md/events")"
fi

n=$(evcount "$md" 'GET instance/attributes/cogworx-start-nonce')
if [ "$n" = 1 ]; then
	ok "the per-start nonce is read exactly once"
else
	bad "the nonce was read $n times, expected 1"
fi

# The published attribute must be STAMPED, or Status has nothing to bind it to.
if grep -q '^n0nce-aaaa ssh-ed25519 AAAAvmhostkey$' "$md/ga/cogworx_vm-host-key" 2>/dev/null; then
	ok "the host-key attribute is nonce-stamped and carries no host-local comment"
else
	bad "host-key attribute is not '<nonce> <type> <key>': $(cat "$md/ga/cogworx_vm-host-key" 2>/dev/null)"
fi

init=$(grep -- 'cogbox init' "$md/events" | head -1)
case "$init" in
	*"--bind-addr 10.0.0.5"*) ok "cogbox init carries --bind-addr with the VM address" ;;
	*) bad "cogbox init has no --bind-addr <vm-addr>: $init" ;;
esac
case "$init" in
	*"--no-implicit-dns"*) ok "cogbox init carries --no-implicit-dns" ;;
	*) bad "cogbox init has no --no-implicit-dns: $init" ;;
esac
# THE GUEST-DNS REGRESSION, producer half. --no-implicit-dns puts loopback DNS
# back under the shim's loopback deny, and passt's --dns-forward re-emits every
# guest query as exactly such a loopback connect. Without this seed the shim
# drops it and every rules-mode guest on the VM resolves nothing, silently --
# and the tempting "fix" for that is a public resolver, which is the state this
# whole change replaced.
case "$init" in
	*"--dns-host 127.0.0.53"*) ok "cogbox init carries --dns-host with the VM's own forwarder" ;;
	*) bad "cogbox init has no --dns-host <host-forwarder>; the guest's DNS would be dropped by the L4 shim: $init" ;;
esac
nself=$(printf '%s' "$init" | grep -o -- '--self-addr' | wc -l)
if [ "$nself" = 2 ] && [ "${init#*--self-addr 10.0.0.5/32}" != "$init" ] \
	&& [ "${init#*--self-addr 10.0.0.6/32}" != "$init" ]; then
	ok "cogbox init carries one --self-addr per cogworx-self-addrs entry"
else
	bad "expected two --self-addr flags carrying 10.0.0.5/32 and 10.0.0.6/32, got: $init"
fi

ready=$(evline "$md" 'PUT instance/guest-attributes/cogworx/ready')
if [ -n "$ready" ] && [ -n "$start" ] && [ "$ready" -gt "$start" ]; then
	ok "readiness is published only after the guest host key appears"
else
	bad "readiness publish ($ready) did not follow cogbox start ($start)"
fi

# Level-held, not latched: leg (j) unpublishes BEFORE the exit so Status drops
# out of Running the way the kubelet makes a pod not-ready. And FIRST: the
# inner-exit record that follows is best-effort and must never stand between a
# dead sandbox and its readiness delete.
last_ready=$(grep -n -- 'guest-attributes/cogworx/ready' "$md/events" | tail -1)
last_ready_n=${last_ready%%:*}
inner_put=$(evline "$md" 'PUT instance/guest-attributes/cogworx/inner-exit')
case "${last_ready#*:}" in
	"DELETE instance/guest-attributes/cogworx/ready"*)
		if [ -n "$ready" ] && [ -n "$inner_put" ] && [ "$last_ready_n" -gt "$ready" ] && [ "$last_ready_n" -lt "$inner_put" ]; then
			ok "the readiness delete follows the publish and precedes the inner-exit record"
		else
			bad "readiness delete ($last_ready_n) is not between the readiness PUT ($ready) and the inner-exit PUT ($inner_put); events: $(cat "$md/events")"
		fi ;;
	*) bad "expected the last readiness event to be the DELETE, got: $last_ready" ;;
esac

# --- 2. the cogbox runtime log never reaches serial -------------------------
#
# The supervisor's stdout is the journal and the cogbox.log tail lives in its
# own unit. A canary in the runtime log must therefore be invisible on serial,
# which on GCE is provider-retained state readable under a coarser grant than
# the control channel.
CANARY="cogbox-l7-canary-do-not-serialize"
mkdir -p "$ROOT/normal/run/cogbox-demo"
printf 'l7proxy: allow example.com %s\n' "$CANARY" > "$ROOT/normal/run/cogbox-demo/cogbox.log"
if grep -q "$CANARY" "$ROOT/normal/serial.log" 2>/dev/null; then
	bad "the cogbox runtime log canary reached the serial sink"
else
	ok "a canary in cogbox.log never reaches the serial sink"
fi
# Comments about the leg are fine and wanted; CODE touching the runtime log is
# what re-opens the channel, so strip comment lines before looking.
if grep -v '^[[:space:]]*#' "$SUP" | grep -q 'cogbox\.log'; then
	bad "supervise.sh has code touching cogbox.log; the tail belongs in cogworx-cogbox-log.service"
else
	ok "no code path in supervise.sh touches cogbox.log"
fi

# --- 3. maintenance boot, instance never booted -----------------------------
#
# A maintenance boot exists so a mutation can run over SSH against a stopped
# instance, and every one of those mutations
# reads config.json -- which lives on the state disk and is created by nothing
# but `cogbox init`. Any instance that has booted once already has one, so the
# short-circuit sitting ahead of init only bit the single path that mutates an
# instance that has never booted. Initializing is host-half work; it is not
# starting the guest, which is the only thing this leg is asked never to do.

rc=$(run_boot maint "${BASE_ATTRS[@]}" "cogworx-maintenance=true")
md="$ROOT/maint/md"
if [ -n "$(evline "$md" 'PUT instance/guest-attributes/cogworx/vm-host-key')" ]; then
	ok "a maintenance boot still publishes the VM host key"
else
	bad "maintenance boot did not publish the host key; a stopped instance could never be pinned"
fi
n=$(evcount "$md" 'cogbox start')
if [ "$n" = 0 ]; then
	ok "a maintenance boot invokes cogbox start zero times"
else
	bad "maintenance boot invoked cogbox start $n times"
fi
n=$(evcount "$md" 'cogbox init')
if [ "$n" = 1 ]; then
	ok "a maintenance boot on a never-booted instance initializes cogbox"
else
	bad "maintenance boot invoked cogbox init $n times, expected 1; a mutation would have no config.json to read; events: $(cat "$md/events")"
fi
if [ -s "$ROOT/maint/state/config/cogbox/instances/demo/config.json" ]; then
	ok "the maintenance boot left a config.json where the mutation reads it"
else
	bad "no config.json under $ROOT/maint/state/config/cogbox/instances/demo/ after a maintenance boot"
fi
# The ORDERING, not just the fact. The short-circuit's own `ga_del cogworx/ready`
# is its first observable act, so init landing before that line is what proves
# init runs BEFORE the hold rather than after some later leg.
init=$(evline "$md" 'cogbox init')
hold=$(evline "$md" 'DELETE instance/guest-attributes/cogworx/ready')
if [ -n "$init" ] && [ -n "$hold" ] && [ "$init" -lt "$hold" ]; then
	ok "cogbox init precedes the maintenance short-circuit"
else
	bad "cogbox init ($init) did not precede the maintenance short-circuit ($hold); events: $(cat "$md/events")"
fi
# config.json is written on FIRST init only, so a maintenance boot that is an
# instance's first-ever boot is what permanently seeds bindAddr and the l7proxy
# self-address floor. An init here that dropped the host-integration flags would
# pin loopback into the config for the life of the instance.
init=$(grep -- 'cogbox init' "$md/events" | head -1)
case "$init" in
	*"--bind-addr 10.0.0.5"*) ok "the maintenance-boot init carries --bind-addr, which config.json keeps for good" ;;
	*) bad "the maintenance-boot init has no --bind-addr <vm-addr>: $init" ;;
esac

# --- 3a. maintenance boot, instance already initialized ---------------------
#
# Re-running init is SAFE -- cogbox-launch.sh writes config.json, the scaffold
# flake, authorized_keys and every harness path only when absent, so plugins,
# L4/L7 rules, secret bindings and the harness overlay all survive -- but it is
# not free: once config.json lists a plugin, init's tail re-execs a full nix
# eval of the composed runner, minutes on a cold store, and cogworxd's
# maintenance path declines that cost per mutation on purpose. So the seed is for the
# never-booted case only.

SEED_INIT_CONFIG=demo
rc=$(run_boot maintinit "${BASE_ATTRS[@]}" "cogworx-maintenance=true")
unset SEED_INIT_CONFIG
md="$ROOT/maintinit/md"
n=$(evcount "$md" 'cogbox init')
if [ "$n" = 0 ]; then
	ok "a maintenance boot on an already-initialized instance does not re-run init"
else
	bad "maintenance boot re-ran cogbox init $n times on an initialized instance"
fi
n=$(evcount "$md" 'cogbox start')
if [ "$n" = 0 ]; then
	ok "a maintenance boot on an already-initialized instance still starts nothing"
else
	bad "maintenance boot invoked cogbox start $n times on an initialized instance"
fi
if grep -q '"plugins"' "$ROOT/maintinit/state/config/cogbox/instances/demo/config.json" 2>/dev/null; then
	ok "the pre-existing config.json is left exactly as it was"
else
	bad "the maintenance boot clobbered the pre-existing config.json: $(cat "$ROOT/maintinit/state/config/cogbox/instances/demo/config.json" 2>/dev/null)"
fi

# --- 4. resolver boot -------------------------------------------------------
#
# Neither init nor start, and that asymmetry with (d2) is deliberate: a resolver
# VM is this image with NO state disk attached, and it seeds its own placeholder
# config over the control channel (`cogbox init -y -n template`) once
# cogworxd has pinned its host key. A supervisor-side init here would either
# trip the state-disk assertion and turn a throwaway VM into a restart loop, or
# write cogbox state onto the boot disk of a machine whose whole job is to
# evaluate an attacker-controlled flake.

rc=$(run_boot resolver "${BASE_ATTRS[@]}" "cogworx-resolver=true")
md="$ROOT/resolver/md"
if [ -n "$(evline "$md" 'PUT instance/guest-attributes/cogworx/vm-host-key')" ]; then
	ok "a resolver boot still publishes the VM host key"
else
	bad "resolver boot did not publish the host key; ResolvePinEphemeral would have nothing to pin against"
fi
n=$(evcount "$md" 'cogbox start')
if [ "$n" = 0 ]; then
	ok "a resolver boot invokes cogbox start zero times"
else
	bad "resolver boot invoked cogbox start $n times"
fi
n=$(evcount "$md" 'cogbox init')
if [ "$n" = 0 ]; then
	ok "a resolver boot invokes cogbox init zero times; it seeds its own config over SSH"
else
	bad "resolver boot invoked cogbox init $n times; it has no state disk to write to"
fi

# --- 5. the flag is read by PRESENCE, not value -----------------------------
#
# The control plane clears a flag by REMOVING the metadata item, never by
# setting it to "false"; a value test here would read a cleared flag as set and
# leave the instance permanently sandbox-less.
rc=$(run_boot maintempty "${BASE_ATTRS[@]}" "cogworx-maintenance=")
md="$ROOT/maintempty/md"
n=$(evcount "$md" 'cogbox start')
if [ "$n" = 0 ]; then
	ok "an EMPTY cogworx-maintenance value still short-circuits (presence, not value)"
else
	bad "an empty cogworx-maintenance value started the sandbox anyway"
fi

# --- 6. cogworx-self-addrs with no provider fallback is fail-closed ---------
#
# Neither source named an address, so rule 2 and the l7proxy self-address floor
# would both be seeded from nothing.

rc=$(run_boot noself \
	"cogworx-start-nonce=n0nce-bbbb" \
	"cogworx-instance=demo" \
	"cogworx-vcpu=4" \
	"cogworx-mem-mb=8192" \
	"cogworx-network=rules")
md="$ROOT/noself/md"
[ "$rc" != 0 ] || bad "a boot with no cogworx-self-addrs exited 0"
n=$(evcount "$md" 'cogbox start')
if [ "$n" = 0 ] && [ "$rc" != 0 ]; then
	ok "an absent cogworx-self-addrs with no provider address exits non-zero with zero cogbox start"
else
	bad "absent cogworx-self-addrs: rc=$rc, cogbox start invoked $n times"
fi

# An EMPTY value must fail the same way an absent one does. The control plane
# stamps the key with an empty VALUE (not an absent key) into every insert body,
# so a check that only handled "absent" would leave the realized first-boot shape
# untested -- which is exactly how the first-boot hole survived review.
rc=$(run_boot emptyself \
	"cogworx-start-nonce=n0nce-eeee" \
	"cogworx-instance=demo" \
	"cogworx-vcpu=4" \
	"cogworx-mem-mb=8192" \
	"cogworx-network=rules" \
	"cogworx-guest-resolver=192.0.2.53" \
	"cogworx-self-addrs=")
md="$ROOT/emptyself/md"
n=$(evcount "$md" 'cogbox start')
if [ "$n" = 0 ] && [ "$rc" != 0 ]; then
	ok "an EMPTY cogworx-self-addrs with no provider address exits non-zero with zero cogbox start"
else
	bad "empty cogworx-self-addrs: rc=$rc, cogbox start invoked $n times"
fi

# --- 6a. the FIRST-BOOT path: empty attribute, provider answers -------------
#
# An insert can carry an empty self-address attribute because the address is not
# allocated yet. The supervisor falls back to the metadata server's statement
# of the VM's interface addresses, matching the floor unit.

SEED_NIC_IP=192.0.2.7
rc=$(run_boot firstboot \
	"cogworx-start-nonce=n0nce-ffff" \
	"cogworx-instance=demo" \
	"cogworx-vcpu=4" \
	"cogworx-mem-mb=8192" \
	"cogworx-network=rules" \
	"cogworx-guest-resolver=192.0.2.53" \
	"cogworx-self-addrs=")
unset SEED_NIC_IP
md="$ROOT/firstboot/md"
init=$(grep -- 'cogbox init' "$md/events" | head -1)
case "$init" in
	*"--bind-addr 192.0.2.7"*) ok "an empty cogworx-self-addrs falls back to the provider's interface address for --bind-addr" ;;
	*) bad "first boot did not take the provider fallback for --bind-addr: $init" ;;
esac
case "$init" in
	*"--self-addr 192.0.2.7/32"*) ok "the provider fallback also seeds l7proxy's --self-addr floor" ;;
	*) bad "first boot did not seed --self-addr from the provider fallback: $init" ;;
esac
n=$(evcount "$md" 'cogbox start')
if [ "$n" != 0 ]; then
	ok "a first boot with an empty cogworx-self-addrs still starts the sandbox"
else
	bad "a first boot with an empty cogworx-self-addrs never started the sandbox; events: $(cat "$md/events")"
fi

# --- 6b. absent cogworx-guest-resolver is fail-closed ------------------------
#
# COGBOX_GUEST_RESOLVER carries passt's -D AND --no-map-gw as one knob, so an
# absent attribute does not merely leave the guest without a resolver: it drops
# --no-map-gw from both passt invocations, and passt's default gateway mapping
# translates guest traffic to the gateway address into the host's loopback (plus
# a port-53 hop to the host's own resolver). In `full` mode there is no L4 filter
# to catch that, so the guest reaches the trusted half's own listeners -- the
# thing the policy promises is denied in every mode. Every other missing-metadata
# case in this script fails the boot; this one must too.

rc=$(run_boot noresolver \
	"cogworx-start-nonce=n0nce-cccc" \
	"cogworx-instance=demo" \
	"cogworx-vcpu=4" \
	"cogworx-mem-mb=8192" \
	"cogworx-network=rules" \
	"cogworx-self-addrs=10.0.0.5")
md="$ROOT/noresolver/md"
n=$(evcount "$md" 'cogbox start')
if [ "$n" = 0 ] && [ "$rc" != 0 ]; then
	ok "an absent cogworx-guest-resolver exits non-zero with zero cogbox start"
else
	bad "absent cogworx-guest-resolver: rc=$rc, cogbox start invoked $n times"
fi

# --- 6c. an absent COGBOX_HOST_RESOLVER is fail-closed -----------------------
#
# The image's own unit sets it, so an empty value means a broken image rather
# than a broken provision -- and its failure mode is the silent one this file
# exists to catch. passt would forward the guest's queries to whatever
# /etc/resolv.conf named, which on GCE is the VPC resolver at the metadata
# address: floor rule 1 drops that socket (it is owned by the passt uid and
# aimed at link-local), so the sandbox comes up healthy with no DNS at all.

SEED_HOST_RESOLVER=""
rc=$(run_boot nohostresolver "${BASE_ATTRS[@]}")
unset SEED_HOST_RESOLVER
md="$ROOT/nohostresolver/md"
n=$(evcount "$md" 'cogbox start')
if [ "$n" = 0 ] && [ "$rc" != 0 ]; then
	ok "an absent COGBOX_HOST_RESOLVER exits non-zero with zero cogbox start"
else
	bad "absent COGBOX_HOST_RESOLVER: rc=$rc, cogbox start invoked $n times"
fi

# --- 6d. a resolv.conf that does not name the forwarder is fail-closed -------
#
# THE PRECONDITION NOTHING ELSE CHECKS. passt does not advertise its
# --dns-forward address unconditionally: it substitutes that address into the
# DHCP offer only when the nameserver it reads from /etc/resolv.conf is a
# LOOPBACK one (conf.c add_dns_resolv4, the "--dns-forward and --no-map-gw"
# case). With the host's real resolver still in resolv.conf -- resolved not up
# yet, or an image built without it -- passt hands the guest 169.254.169.254
# instead, rule 1 drops every query, and NOTHING anywhere reports it. The whole
# mechanism is that one substitution, so the boot must refuse rather than start
# a sandbox that silently resolves nothing.

SEED_RESOLV_NS=169.254.169.254
rc=$(run_boot badresolv "${BASE_ATTRS[@]}")
unset SEED_RESOLV_NS
md="$ROOT/badresolv/md"
n=$(evcount "$md" 'cogbox start')
if [ "$n" = 0 ] && [ "$rc" != 0 ]; then
	ok "a resolv.conf naming the host's real resolver exits non-zero with zero cogbox start"
else
	bad "resolv.conf without the loopback forwarder: rc=$rc, cogbox start invoked $n times"
fi
if grep -q "$ROOT/badresolv/resolv.conf" "$ROOT/badresolv/out.log" 2>/dev/null; then
	ok "the refusal names the file it read, so the cause is diagnosable from the journal"
else
	bad "the resolv.conf refusal does not name the file: $(cat "$ROOT/badresolv/out.log" 2>/dev/null)"
fi

# --- 6e. an empty/unset XDG_CONFIG_HOME fails with a SERIAL line --------------
#
# The config root is dereferenced on the path of EVERY boot class now that (b)
# runs before (d2), and the two ways it can go missing fail differently without
# the guard. UNSET kills the shell under `set -u` with "unbound variable" on
# stderr, which goes to the JOURNAL: the boot then emits NOTHING to serial and is
# undiagnosable from getSerialPortOutput, the only channel the control plane can
# read on a box that never came up. EMPTY is worse than a crash: init succeeds
# against /cogbox/instances/... on the boot disk, and the mutation the maintenance
# boot exists to serve then reads a config that is not the instance's. A shell
# prefix can only express the empty half, so that is the half that runs here; the
# guard covers both, and what is asserted is the SHAPE of the failure.

SEED_XDG_CONFIG_HOME=""
rc=$(run_boot noxdg "${BASE_ATTRS[@]}")
unset SEED_XDG_CONFIG_HOME
md="$ROOT/noxdg/md"
n=$(evcount "$md" 'cogbox init')
if [ "$rc" != 0 ] && [ "$n" = 0 ]; then
	ok "an empty XDG_CONFIG_HOME exits non-zero with zero cogbox init"
else
	bad "empty XDG_CONFIG_HOME: rc=$rc, cogbox init invoked $n times"
fi
if grep -q '^cogworx: FAILED: XDG_CONFIG_HOME is unset or empty' "$ROOT/noxdg/serial.log" 2>/dev/null; then
	ok "the refusal reaches serial, so the boot is diagnosable from getSerialPortOutput"
else
	bad "empty XDG_CONFIG_HOME emitted no classified serial line: $(cat "$ROOT/noxdg/serial.log" 2>/dev/null)"
fi

# --- 6f. a MISSING guest volume is fail-closed, and says WHICH ---------------
#
# Leg (e2), and it exists because the GCE image is now hosted-only. There is one
# baked guest storage profile and no launch-time fallback, so when
# cogworx-guest-disk refuses to carve -- absent disk, unreadable disk, foreign
# filesystem, foreign volume group -- QEMU is handed two paths that do not exist
# and no guest starts. That outcome is accepted; being unable to DIAGNOSE it is
# not, and that was the whole of the stuck-in-Booting failure mode. Without
# this leg the only symptom is `cogbox start` failing to open a drive, which
# reaches serial as the generic "sandbox start failed" -- true, and
# indistinguishable from a kernel that would not boot or a port collision. On a
# VM whose guest never came up, getSerialPortOutput is the only channel the
# control plane has.
#
# The NEGATIVE CONTROL for both cases below is every other case in this file:
# they run with COGWORX_GUEST_VOLUMES unset, the loop is then a no-op, and they
# all reach `cogbox start`. So a leg that simply always fataled would fail them,
# not pass here.

SEED_GUEST_VOLUMES="$ROOT/absent-vol/pool $ROOT/absent-vol/store"
rc=$(run_boot novolume "${BASE_ATTRS[@]}")
unset SEED_GUEST_VOLUMES
md="$ROOT/novolume/md"
n=$(evcount "$md" 'cogbox start')
if [ "$rc" != 0 ] && [ "$n" = 0 ]; then
	ok "a missing guest volume exits non-zero with zero cogbox start"
else
	bad "missing guest volume: rc=$rc, cogbox start invoked $n times"
fi
# NAMED, not merely non-zero. An operator reading serial has to learn which
# volume is missing and which unit to go look at; "sandbox start failed" is what
# this replaces.
if grep -q "^cogworx: FAILED: guest volume $ROOT/absent-vol/pool is not a block device" "$ROOT/novolume/serial.log" 2>/dev/null; then
	ok "the refusal names the missing volume on serial"
else
	bad "missing guest volume emitted no named serial line: $(cat "$ROOT/novolume/serial.log" 2>/dev/null)"
fi
if grep -q 'cogworx-guest-disk' "$ROOT/novolume/serial.log" 2>/dev/null; then
	ok "the serial line points at the unit that refused to carve"
else
	bad "the refusal does not name cogworx-guest-disk, so an operator has no next step"
fi

# ...and the test is `-b`, not `-e`. microvm.nix's own autoCreate guard is
# `[ ! -e ]`, which would touch a missing device node into a REGULAR FILE and
# mkfs that -- handing the user a blank pool while their real disk sat
# unattached. Both volumes are autoCreate = false precisely to make that
# unreachable, and a regular file at the device path must fail here for the same
# reason: QEMU can open it, and the guest would then boot on a file instead of
# its disk. (This is also the only shape a build sandbox can express -- it has
# character devices but no block devices -- so it is the case that actually
# proves the predicate rather than the path.)
mkdir -p "$ROOT/filevol"
: > "$ROOT/filevol/pool"
SEED_GUEST_VOLUMES="$ROOT/filevol/pool"
rc=$(run_boot filevolume "${BASE_ATTRS[@]}")
unset SEED_GUEST_VOLUMES
md="$ROOT/filevolume/md"
n=$(evcount "$md" 'cogbox start')
if [ "$rc" != 0 ] && [ "$n" = 0 ]; then
	ok "a REGULAR FILE at a guest volume path is refused, so the test is -b and not -e"
else
	bad "regular file at a guest volume path: rc=$rc, cogbox start invoked $n times"
fi

# --- 7. absent nonce is fail-closed -----------------------------------------
#
# Without a nonce nothing this boot published could ever be bound to the start
# epoch, so a stale attribute from a previous boot would be indistinguishable.
rc=$(run_boot nononce "cogworx-instance=demo" "cogworx-self-addrs=10.0.0.5")
md="$ROOT/nononce/md"
n=$(evcount "$md" 'PUT instance/guest-attributes')
if [ "$rc" != 0 ] && [ "$n" = 0 ]; then
	ok "an absent start nonce exits non-zero and publishes no attribute at all"
else
	bad "absent nonce: rc=$rc, $n guest attributes published"
fi

# --- 8. a failed init is CLASSIFIED, not swallowed --------------------------
#
# THE FAILURE MODE THIS REPLACES. A sandbox created with two plugins that
# both shipped a skill called `overview`; the composed guest system would not
# EVALUATE, `cogbox init` exited non-zero, and the supervisor restart-looped
# without bound. Serial filled with identical "FAILED: cogbox init
# failed" lines -- enough to overwrite the 1 MB ring buffer and destroy the
# earlier maintenance-boot output -- while the ONE line of Nix error that
# explained everything was reachable only over SSH, on a box whose guest never
# came up. Three properties fix that, and all three are asserted here: the full
# output survives on the STATE DISK, an allowlisted summary reaches serial and
# the guest attribute, and the serial line is deduplicated so the ring buffer
# keeps the boot history.

# The real shape: one cogbox-stamped line worth reading, and other output that
# must NOT leave the VM boundary. Serial on GCE is provider-retained state
# readable under a coarser grant than the control channel, so the summary is an
# ALLOWLIST ('cogbox: ' only) rather than a filter -- a filter only removes the
# leaks somebody already thought of.
INIT_CANARY="l7proxy: allow api.example.com init-canary-do-not-serialize"
INIT_ERR="error: cogbox: skill 'overview' is provided by 2 cogbox.contents roots (plugin 'obs-plugin', plugin 'demo-plugin')"

STUB_INIT_RC=70
STUB_INIT_OUT="$INIT_CANARY
$INIT_ERR
- cogbox: rename that skill or set cogbox.skills"
rc=$(run_boot initfail "${BASE_ATTRS[@]}")
md="$ROOT/initfail/md"
n=$(evcount "$md" 'cogbox start')
if [ "$rc" != 0 ] && [ "$n" = 0 ]; then
	ok "a failed cogbox init exits non-zero with zero cogbox start"
else
	bad "failed init: rc=$rc, cogbox start invoked $n times"
fi

# On the STATE DISK, not in /run: the first thing a user does with a box stuck
# "Booting" is reboot it, and a tmpfs copy would not survive that.
if grep -qF "$INIT_ERR" "$ROOT/initfail/state/last-init-error.log" 2>/dev/null; then
	ok "init's combined output is kept on the state disk, where a reboot cannot destroy it"
else
	bad "no last-init-error.log on the state disk: $(ls "$ROOT/initfail/state" 2>/dev/null)"
fi

if grep -q "^cogworx: FAILED: init: .*skill 'overview'" "$ROOT/initfail/serial.log" 2>/dev/null; then
	ok "the classified summary reaches serial, so the cause is diagnosable from getSerialPortOutput"
else
	bad "no classified init line on serial: $(cat "$ROOT/initfail/serial.log" 2>/dev/null)"
fi
# The allowlist half. The canary is a line init really can print (the cogbox
# runtime log's l7 allow/deny decisions have the same shape) and it carries no
# 'cogbox: ' stamp, so it must not be on serial or in the guest attribute.
if grep -q 'init-canary-do-not-serialize' "$ROOT/initfail/serial.log" 2>/dev/null; then
	bad "an unstamped init line reached the serial sink; the summary is filtering, not allowlisting"
else
	ok "an unstamped init line never reaches the serial sink"
fi

ga="$ROOT/initfail/md/ga/cogworx_boot-error"
if grep -q "^n0nce-aaaa .*skill 'overview'" "$ga" 2>/dev/null \
	&& ! grep -q 'init-canary-do-not-serialize' "$ga" 2>/dev/null; then
	ok "the same summary is published nonce-stamped as cogworx/boot-error"
else
	bad "cogworx/boot-error is missing, unstamped or carries unstamped output: $(cat "$ga" 2>/dev/null)"
fi

# DEDUP. Same tag, so the same $XDG_RUNTIME_DIR and the same serial log: this is
# the restart the unit would perform 1456 more times. An identical failure adds
# no line; a DIFFERENT one does, because that is a state change an operator
# needs to see.
rc=$(run_boot initfail "${BASE_ATTRS[@]}")
n=$(grep -c '^cogworx: FAILED: init' "$ROOT/initfail/serial.log" 2>/dev/null || true)
if [ "$n" = 1 ]; then
	ok "an identical repeat failure emits no second serial line"
else
	bad "expected 1 classified init line after a repeat, got $n"
fi

STUB_INIT_OUT="error: cogbox: config.json is empty"
rc=$(run_boot initfail "${BASE_ATTRS[@]}")
n=$(grep -c '^cogworx: FAILED: init' "$ROOT/initfail/serial.log" 2>/dev/null || true)
if [ "$n" = 2 ] && grep -q 'config.json is empty' "$ROOT/initfail/serial.log"; then
	ok "a CHANGED failure emits a fresh serial line"
else
	bad "expected 2 classified init lines after the summary changed, got $n"
fi

# HEARTBEAT. Dedup must not make a permanently-wedged box go silent: an
# operator arriving later has to be able to tell "stuck since boot" from
# "stopped failing an hour ago". Every 20th restart says so, with the count.
for _ in $(seq 19); do rc=$(run_boot initfail "${BASE_ATTRS[@]}"); done
if grep -q '^cogworx: FAILED: init still failing after 20 attempts: .*config.json is empty' \
	"$ROOT/initfail/serial.log" 2>/dev/null; then
	ok "a permanently-failing init re-announces itself every 20th restart, with the count"
else
	bad "no heartbeat line after 20 identical failures: $(grep -c '^cogworx: FAILED: init' "$ROOT/initfail/serial.log")"
fi

# NOTHING MATCHED. An init that fails without printing a cogbox-stamped line
# must still say something, and it must still say only that -- falling back to
# the generic string rather than to whatever the last line happened to be.
STUB_INIT_OUT="$INIT_CANARY"
rc=$(run_boot initopaque "${BASE_ATTRS[@]}")
if grep -q '^cogworx: FAILED: init: cogbox init failed$' "$ROOT/initopaque/serial.log" 2>/dev/null \
	&& ! grep -q 'init-canary-do-not-serialize' "$ROOT/initopaque/serial.log" 2>/dev/null; then
	ok "an init failure with no cogbox-stamped line falls back to the generic string"
else
	bad "opaque init failure did not fall back cleanly: $(cat "$ROOT/initopaque/serial.log" 2>/dev/null)"
fi

# A WARNING IS NOT THE FAILURE. The control plane reads every summary but the
# generic string as CLASSIFIED -- a fault of the image, which fails an upgrade
# and is remembered against it -- so a non-fatal cogbox-stamped warning must
# never stand in for an unstamped failure. A box whose config draws a warning on
# every evaluation (two cogbox.env sources setting one key) would otherwise turn
# a transient fetch failure on its first boot of a new image into a classified
# one. Each shape on its own: nix's, older nix's (whose lib.warn carries its own
# colour escape), and the cogbox CLI's.
n=0
for warnline in \
	"evaluation warning: cogbox: env var(s) EDITOR are defined by more than one cogbox.env source; the highest-priority definition wins silently" \
	$'trace: \033[1;31mwarning: cogbox: env var(s) EDITOR are defined by more than one cogbox.env source\033[0m' \
	"cogbox: warning: COGBOX_OLD_NAME is set but no longer honored. Rename to COGBOX_NEW_NAME."; do
	n=$((n + 1))
	STUB_INIT_OUT="$warnline
error: unable to download 'https://cache.example.com/nar/0abc.nar.xz': HTTP error 503"
	rc=$(run_boot "initwarn$n" "${BASE_ATTRS[@]}")
	ga="$ROOT/initwarn$n/md/ga/cogworx_boot-error"
	if [ "$(cat "$ga" 2>/dev/null)" = 'n0nce-aaaa cogbox init failed' ] \
		&& grep -qx 'cogworx: FAILED: init: cogbox init failed' "$ROOT/initwarn$n/serial.log" 2>/dev/null; then
		ok "a stamped warning ($(printf '%s' "$warnline" | tr -c ' -~' '?' | head -c 40)) beside an unstamped failure publishes the generic literal"
	else
		bad "a stamped warning was published as the failure ($n): boot-error '$(tr -c ' -~' '?' < "$ga" 2>/dev/null)'"
	fi
done
# ...while a REAL stamped error beside the same warning is still classified, and
# its summary carries the error, not the warning.
STUB_INIT_OUT="evaluation warning: cogbox: env var(s) EDITOR are defined by more than one cogbox.env source
error: cogbox: config.json is empty"
rc=$(run_boot initwarnerr "${BASE_ATTRS[@]}")
ga="$ROOT/initwarnerr/md/ga/cogworx_boot-error"
if grep -q '^n0nce-aaaa error: cogbox: config.json is empty' "$ga" 2>/dev/null && ! grep -q 'warning' "$ga"; then
	ok "a stamped error beside a stamped warning publishes the error alone, still classified"
else
	bad "a stamped error beside a warning: boot-error '$(cat "$ga" 2>/dev/null)'"
fi
unset STUB_INIT_RC STUB_INIT_OUT

# CLEARED ON SUCCESS. A boot-error that outlives its failure is worse than
# none: it would be read as the reason for the next problem.
rc=$(run_boot initclear "${BASE_ATTRS[@]}")
md="$ROOT/initclear/md"
if [ -n "$(evline "$md" 'DELETE instance/guest-attributes/cogworx/boot-error')" ]; then
	ok "a boot that gets past init clears cogworx/boot-error"
else
	bad "a successful init left cogworx/boot-error in place; events: $(cat "$md/events")"
fi
if [ ! -e "$ROOT/initclear/state/last-init-error.log" ]; then
	ok "a successful init leaves no stale error log on the state disk"
else
	bad "last-init-error.log survived a successful init"
fi

# PRESERVED BY A MAINTENANCE BOOT. Clearing the diagnostic is the job of an
# init that RAN and SUCCEEDED, not of "any boot that got past leg (b)" -- a
# maintenance boot deliberately skips init, and it is the boot class an operator
# reaches for to investigate a box wedged on a failing init. Deleting the
# state-disk log and the guest attribute there would destroy the evidence this
# leg exists to preserve, and then hold at `sleep infinity` with nothing
# recorded anywhere.
rc=$(run_boot maintkeep "${BASE_ATTRS[@]}")
printf "error: cogbox: skill 'overview' is provided by 2 cogbox.contents roots\n" \
	> "$ROOT/maintkeep/state/last-init-error.log"
printf "n0nce-aaaa cogbox: skill 'overview' collides\n" \
	> "$ROOT/maintkeep/md/ga/cogworx_boot-error"
rc=$(run_boot maintkeep "${BASE_ATTRS[@]}" "cogworx-maintenance=true")
md="$ROOT/maintkeep/md"
if [ "$(evcount "$md" 'cogbox init')" = 0 ]; then
	ok "the maintenance boot skipped init, as this case requires"
else
	bad "maintenance boot re-ran init; the preservation assertions below prove nothing"
fi
if [ -s "$ROOT/maintkeep/state/last-init-error.log" ]; then
	ok "a maintenance boot preserves the state-disk init error log"
else
	bad "a maintenance boot deleted last-init-error.log, the evidence it exists to let an operator read"
fi
if [ -z "$(evline "$md" 'DELETE instance/guest-attributes/cogworx/boot-error')" ]; then
	ok "a maintenance boot preserves cogworx/boot-error"
else
	bad "a maintenance boot cleared cogworx/boot-error without having run init"
fi

# --- 9. restart backoff lives HERE, and only on the failure path ------------
#
# The unit's RestartSec is flat on purpose: systemd never resets its restart
# counter after a successful run, and leg (j) exits non-zero on every ordinary
# sandbox exit -- an in-guest `reboot` included -- so RestartSteps= there would
# throttle the NORMAL restart path and leave a healthy box waiting minutes with
# nothing to explain it. This script can tell a failed boot from a finished one,
# so the doubling delay is here. (`sleep` is stubbed at the top of this file, so
# these assertions read the ANNOUNCED delay rather than wall-clock time.)
delay_of() { sed -n 's/.*delaying \([0-9]*\)s before this exit.*/\1/p' "$1" | tail -1; }

STUB_INIT_RC=70
STUB_INIT_OUT="error: cogbox: skill 'overview' collides"
rc=$(run_boot backoff "${BASE_ATTRS[@]}"); d1=$(delay_of "$ROOT/backoff/out.log")
rc=$(run_boot backoff "${BASE_ATTRS[@]}"); d2=$(delay_of "$ROOT/backoff/out.log")
rc=$(run_boot backoff "${BASE_ATTRS[@]}"); d3=$(delay_of "$ROOT/backoff/out.log")
if [ "$d1" = 5 ] && [ "$d2" = 10 ] && [ "$d3" = 20 ]; then
	ok "consecutive failed boots back off 5s -> 10s -> 20s"
else
	bad "expected a 5/10/20 backoff across three failed boots, got $d1/$d2/$d3"
fi
unset STUB_INIT_RC STUB_INIT_OUT

# A boot that actually STARTED the sandbox is the proof this box got somewhere,
# so it resets the counter -- and its own leg (j) exit announces no delay at all.
rc=$(run_boot backoff "${BASE_ATTRS[@]}")
if [ -z "$(delay_of "$ROOT/backoff/out.log")" ]; then
	ok "an ordinary sandbox exit (leg j) is never delayed"
else
	bad "leg (j) delayed a normal restart by $(delay_of "$ROOT/backoff/out.log")s"
fi
STUB_INIT_RC=70
STUB_INIT_OUT="error: cogbox: skill 'overview' collides"
rc=$(run_boot backoff "${BASE_ATTRS[@]}")
if [ "$(delay_of "$ROOT/backoff/out.log")" = 5 ]; then
	ok "a successful start resets the backoff, so the next failure starts over at 5s"
else
	bad "the backoff was not reset by a successful start: $(delay_of "$ROOT/backoff/out.log")s"
fi
unset STUB_INIT_RC STUB_INIT_OUT

# --- 10. inner-exit forensics -----------------------------------------------
#
# THE FAILURE MODE THIS REPLACES. Inner VMs died on real boxes and left nothing:
# leg (j) said "sandbox exited" and restarted, the next start's leg (e) deleted
# the runtime dir holding the guest console and the launcher's stop-result,
# and an image Upgrade recreates the boot disk and its journal. So the cause of
# three deaths stayed unproven. Leg (j) now keeps a bounded record on the STATE
# DISK and publishes a per-epoch count, and serial -- provider-retained, see
# case 2 -- carries only a pointer.

# 10a. capture + pointer.
CONSOLE_CANARY="console-canary-do-not-serialize"
STUB_CONSOLE="$CONSOLE_CANARY"
rc=$(run_boot innerexit "${BASE_ATTRS[@]}")
unset STUB_CONSOLE
ie="$ROOT/innerexit/state/inner-exit"
recs=( "$ie"/*.log )
[ "$rc" != 0 ] || bad "an inner exit exited 0; Restart=always would never re-run the sequence"
if [ -e "${recs[0]}" ] && [ "${#recs[@]}" = 1 ]; then
	ok "an inner exit leaves exactly one record on the state disk"
else
	bad "expected exactly one inner-exit record: $(ls -la "$ie" 2>&1)"
fi
rec="${recs[0]}"
for want in 'leg: exited' 'stop-result: run-1 exited' 'MemTotal' "$CONSOLE_CANARY" 'Killed process 988 (qemu-system-x86)'; do
	if grep -qF -- "$want" "$rec" 2>/dev/null; then
		ok "the inner-exit record carries '$want'"
	else
		bad "the inner-exit record lacks '$want': $(cat "$rec" 2>/dev/null)"
	fi
done
if grep -q 'unrelated-dmesg-line' "$rec" 2>/dev/null; then
	bad "the inner-exit record kept an unrelated kernel line; the dmesg filter is not filtering"
else
	ok "the record keeps only the kernel's oom/kill/segfault/qemu lines"
fi
if grep -Eq '^n0nce-aaaa 1 [0-9]+ exited$' "$ROOT/innerexit/md/ga/cogworx_inner-exit" 2>/dev/null; then
	ok "cogworx/inner-exit is '<nonce> 1 <epoch> exited'"
else
	bad "cogworx/inner-exit is not '<nonce> 1 <epoch> exited': $(cat "$ROOT/innerexit/md/ga/cogworx_inner-exit" 2>/dev/null)"
fi
if grep -q '^cogworx: inner exit 1 under this start (exited); evidence on the state disk at inner-exit/' "$ROOT/innerexit/serial.log" 2>/dev/null; then
	ok "serial gets a one-line pointer to the record"
else
	bad "no inner-exit pointer on serial: $(cat "$ROOT/innerexit/serial.log" 2>/dev/null)"
fi
# The console tail is guest/tenant output: it may sit on the state disk, never
# on the provider-retained serial port.
if grep -q "$CONSOLE_CANARY" "$ROOT/innerexit/serial.log" 2>/dev/null; then
	bad "the guest console tail reached the serial sink"
else
	ok "the guest console tail never reaches the serial sink"
fi
if [ "$(stat -c %a "$ie" 2>/dev/null)" = 700 ] && [ "$(stat -c %a "$rec" 2>/dev/null)" = 600 ]; then
	ok "the inner-exit ring is 0700 and its record 0600"
else
	bad "inner-exit modes: dir $(stat -c %a "$ie" 2>/dev/null), record $(stat -c %a "$rec" 2>/dev/null); expected 700/600"
fi

# 10b. the count is per start nonce, and survives a rerun. Same tag, so the
# same state disk -- the restart the unit performs, or a whole VM reboot.
rm -f "$ROOT/innerexit/md/statusn"
rc=$(run_boot innerexit "${BASE_ATTRS[@]}")
if grep -Eq '^n0nce-aaaa 2 [0-9]+ exited$' "$ROOT/innerexit/md/ga/cogworx_inner-exit" 2>/dev/null; then
	ok "a second inner exit under the same start nonce counts 2"
else
	bad "the inner-exit count did not survive a rerun: $(cat "$ROOT/innerexit/md/ga/cogworx_inner-exit" 2>/dev/null)"
fi
rm -f "$ROOT/innerexit/md/statusn"
rc=$(run_boot innerexit "${BASE_ATTRS[@]}" "cogworx-start-nonce=n0nce-bbbb")
if grep -Eq '^n0nce-bbbb 1 [0-9]+ exited$' "$ROOT/innerexit/md/ga/cogworx_inner-exit" 2>/dev/null; then
	ok "a new start nonce resets the inner-exit count to 1"
else
	bad "a new start nonce did not reset the count: $(cat "$ROOT/innerexit/md/ga/cogworx_inner-exit" 2>/dev/null)"
fi

# 10c. the ring is bounded. A crash-looping guest must not fill the state disk.
mkdir -p "$ROOT/innering/state/inner-exit"
for i in $(seq -w 1 25); do
	printf 'old\n' > "$ROOT/innering/state/inner-exit/20000101T0000${i}Z-1.log"
done
rc=$(run_boot innering "${BASE_ATTRS[@]}")
ie="$ROOT/innering/state/inner-exit"
recs=( "$ie"/*.log )
# The new record is the one whose timestamp is not the seeded year-2000 one.
newrec=$(ls "$ie" 2>/dev/null | grep '\.log$' | grep -vc '^20000101' || true)
if [ "${#recs[@]}" = 20 ] && [ ! -e "$ie/20000101T000001Z-1.log" ] && [ ! -e "$ie/20000101T000006Z-1.log" ] \
	&& [ -e "$ie/20000101T000007Z-1.log" ] && [ -e "$ie/20000101T000025Z-1.log" ] && [ "$newrec" = 1 ]; then
	ok "the inner-exit ring keeps the newest 20 records and drops the oldest"
else
	bad "inner-exit ring not bounded to the newest 20: $(ls "$ie" 2>&1 | tr '\n' ' ')"
fi
if [ -s "$ie/count" ]; then
	ok "pruning the ring never deletes the count"
else
	bad "the inner-exit count file is gone after pruning"
fi

# 10d. the readiness-timeout leg is recorded as such. The guest never writes its
# host key, but cogbox status keeps answering, so the loop times out.
SEED_GUEST_KEY="" STUB_STATUS_OK=100
rc=$(run_boot innertimeout "${BASE_ATTRS[@]}")
unset SEED_GUEST_KEY STUB_STATUS_OK
recs=( "$ROOT/innertimeout/state/inner-exit"/*.log )
if grep -q '^leg: ready-timeout$' "${recs[0]}" 2>/dev/null \
	&& grep -Eq ' ready-timeout$' "$ROOT/innertimeout/md/ga/cogworx_inner-exit" 2>/dev/null \
	&& grep -q 'did not become ready' "$ROOT/innertimeout/serial.log" 2>/dev/null; then
	ok "a readiness timeout is recorded with leg ready-timeout"
else
	bad "readiness timeout not recorded as such: record=$(cat "${recs[0]}" 2>/dev/null | head -3) ga=$(cat "$ROOT/innertimeout/md/ga/cogworx_inner-exit" 2>/dev/null)"
fi

# 10e. a REQUESTED stop is not an inner exit. The control plane's Stop and
# Restart go through ExecStop, which drops the stopping marker first; counting
# those would make the count meaningless.
STUB_STOPPING=1
rc=$(run_boot innerstop "${BASE_ATTRS[@]}")
unset STUB_STOPPING
md="$ROOT/innerstop/md"
recs=( "$ROOT/innerstop/state/inner-exit"/*.log )
if [ "$rc" != 0 ] && [ ! -e "${recs[0]}" ] && [ "$(evcount "$md" 'PUT instance/guest-attributes/cogworx/inner-exit')" = 0 ] \
	&& [ -n "$(evline "$md" 'DELETE instance/guest-attributes/cogworx/ready')" ]; then
	ok "a requested stop deletes readiness and records no inner exit"
else
	bad "requested stop: rc=$rc, records: $(ls "$ROOT/innerstop/state/inner-exit" 2>&1), events: $(cat "$md/events")"
fi

# 10f. best-effort. A state disk that cannot take the record must not change
# what leg (j) does: readiness is still deleted and the unit still restarts.
mkdir -p "$ROOT/innerbroken/state"
: > "$ROOT/innerbroken/state/inner-exit"
rc=$(run_boot innerbroken "${BASE_ATTRS[@]}")
md="$ROOT/innerbroken/md"
if [ "$rc" != 0 ] && [ -n "$(evline "$md" 'DELETE instance/guest-attributes/cogworx/ready')" ] \
	&& grep -q 'sandbox is no longer running' "$ROOT/innerbroken/out.log" 2>/dev/null \
	&& [ "$(evcount "$md" 'PUT instance/guest-attributes/cogworx/inner-exit')" = 0 ]; then
	ok "an unwritable inner-exit ring never blocks leg (j)"
else
	bad "unwritable inner-exit ring: rc=$rc, out: $(cat "$ROOT/innerbroken/out.log" 2>/dev/null); events: $(cat "$md/events")"
fi

# 10g. an OOM kill of a HELPER while QEMU keeps running. The unit is
# OOMPolicy=continue, so systemd no longer stops it for this, and `cogbox
# status` only checks QEMU: before the unit OOM-kill watch the sandbox stayed
# Running with its network or L7 tier dead until the status poll happened to
# fail. Status here keeps answering for 100 polls; the counter rises at poll 3.
STUB_STATUS_OK=100 STUB_OOM_AT=3
rc=$(run_boot inneroom "${BASE_ATTRS[@]}")
unset STUB_STATUS_OK STUB_OOM_AT
md="$ROOT/inneroom/md"
recs=( "$ROOT/inneroom/state/inner-exit"/*.log )
put=$(evline "$md" 'PUT instance/guest-attributes/cogworx/ready')
del=$(evline "$md" 'DELETE instance/guest-attributes/cogworx/ready')
if [ "$rc" != 0 ] && [ "$(cat "$md/statusn" 2>/dev/null)" = 3 ] \
	&& [ -n "$put" ] && [ -n "$del" ] && [ "$put" -lt "$del" ] \
	&& grep -q '^leg: oom-kill$' "${recs[0]}" 2>/dev/null \
	&& grep -Eq '^n0nce-aaaa 1 [0-9]+ oom-kill$' "$md/ga/cogworx_inner-exit" 2>/dev/null \
	&& grep -q '^cogworx: a process of the sandbox unit was OOM-killed; restarting the sandbox$' "$ROOT/inneroom/serial.log" 2>/dev/null; then
	ok "an OOM kill of a helper ends a running sandbox at the next poll, recorded as oom-kill"
else
	bad "helper OOM kill: rc=$rc polls=$(cat "$md/statusn" 2>/dev/null) record=$(head -1 "${recs[0]}" 2>/dev/null) ga=$(cat "$md/ga/cogworx_inner-exit" 2>/dev/null) serial: $(cat "$ROOT/inneroom/serial.log" 2>/dev/null)"
fi
# ...and QEMU is still alive at that poll, while leg (j)'s non-zero exit makes
# systemd skip ExecStop and TERM the whole cgroup. So the guest must be drained
# with `cogbox stop` (the CLI ExecStop runs) BEFORE the exit: after the
# readiness delete, before the record and the exit, and exactly once.
stop=$(evline "$md" 'cogbox stop --name demo')
ieput=$(evline "$md" 'PUT instance/guest-attributes/cogworx/inner-exit')
out="$ROOT/inneroom/out.log"
stopj=$(grep -n '^cogbox-stub: stop --name demo$' "$out" 2>/dev/null | head -1 | cut -d: -f1)
exitj=$(grep -n 'sandbox is no longer running; exiting so the unit restarts' "$out" 2>/dev/null | head -1 | cut -d: -f1)
if [ -n "$stop" ] && [ -n "$del" ] && [ -n "$ieput" ] && [ "$del" -lt "$stop" ] && [ "$stop" -lt "$ieput" ] \
	&& [ "$(evcount "$md" '^cogbox stop ')" = 1 ] \
	&& [ -n "$stopj" ] && [ -n "$exitj" ] && [ "$stopj" -lt "$exitj" ] \
	&& grep -q '^stop-result: run-1 graceful$' "${recs[0]}" 2>/dev/null \
	&& ! grep -q 'warning: the guest drain' "$out" 2>/dev/null; then
	ok "a helper's OOM kill drains the live guest with cogbox stop before leg (j) records it and exits"
else
	bad "helper OOM kill drain: del=$del stop=$stop inner-exit-put=$ieput journal stop=$stopj exit=$exitj; events: $(cat "$md/events"); out: $(cat "$out" 2>/dev/null)"
fi

# 10h. QEMU itself OOM-killed: status fails at the same poll the counter rises,
# and the record names the cause rather than the generic `exited`.
STUB_OOM_AT=3
rc=$(run_boot inneroomqemu "${BASE_ATTRS[@]}")
unset STUB_OOM_AT
recs=( "$ROOT/inneroomqemu/state/inner-exit"/*.log )
if [ "$rc" != 0 ] && grep -q '^leg: oom-kill$' "${recs[0]}" 2>/dev/null \
	&& grep -q '^cogworx: sandbox exited$' "$ROOT/inneroomqemu/serial.log" 2>/dev/null \
	&& grep -Eq ' oom-kill$' "$ROOT/inneroomqemu/md/ga/cogworx_inner-exit" 2>/dev/null; then
	ok "an OOM kill of QEMU is recorded as oom-kill"
else
	bad "QEMU OOM kill not recorded as oom-kill: record=$(head -1 "${recs[0]}" 2>/dev/null) ga=$(cat "$ROOT/inneroomqemu/md/ga/cogworx_inner-exit" 2>/dev/null)"
fi
# With QEMU already gone there is no guest left to drain.
if [ "$(evcount "$ROOT/inneroomqemu/md" '^cogbox stop ')" = 0 ]; then
	ok "an OOM kill of QEMU itself runs no guest drain"
else
	bad "an OOM kill of QEMU itself ran cogbox stop; events: $(cat "$ROOT/inneroomqemu/md/events")"
fi

# 10i. a counter that cannot be read is said so in the journal, and changes
# nothing else: the sandbox runs and exits exactly as before.
SEED_NO_MEM_EVENTS=1
rc=$(run_boot inneroomnone "${BASE_ATTRS[@]}")
unset SEED_NO_MEM_EVENTS
recs=( "$ROOT/inneroomnone/state/inner-exit"/*.log )
if [ "$rc" != 0 ] && grep -q "warning: cannot read this unit's OOM-kill count" "$ROOT/inneroomnone/out.log" 2>/dev/null \
	&& grep -q '^leg: exited$' "${recs[0]}" 2>/dev/null; then
	ok "an unreadable OOM-kill count warns and leaves leg (i) as it was"
else
	bad "unreadable OOM-kill count: rc=$rc record=$(head -1 "${recs[0]}" 2>/dev/null) out: $(cat "$ROOT/inneroomnone/out.log" 2>/dev/null)"
fi

# 10j. a guest drain that fails after a helper's OOM kill is only noted: leg (j)
# still records the death as oom-kill and exits non-zero, so the unit restarts
# and its cgroup TERM is the backstop.
STUB_STATUS_OK=100 STUB_OOM_AT=3 STUB_STOP_RC=1
rc=$(run_boot inneroomdrainfail "${BASE_ATTRS[@]}")
unset STUB_STATUS_OK STUB_OOM_AT STUB_STOP_RC
md="$ROOT/inneroomdrainfail/md"
recs=( "$ROOT/inneroomdrainfail/state/inner-exit"/*.log )
if [ "$rc" != 0 ] && [ "$(evcount "$md" '^cogbox stop ')" = 1 ] \
	&& grep -q 'warning: the guest drain after the OOM kill did not complete (exit 1)' "$ROOT/inneroomdrainfail/out.log" 2>/dev/null \
	&& grep -q '^leg: oom-kill$' "${recs[0]}" 2>/dev/null \
	&& grep -Eq ' oom-kill$' "$md/ga/cogworx_inner-exit" 2>/dev/null \
	&& grep -q 'sandbox is no longer running' "$ROOT/inneroomdrainfail/out.log" 2>/dev/null; then
	ok "a failed guest drain is noted and leg (j) still records oom-kill and restarts"
else
	bad "failed guest drain: rc=$rc record=$(head -1 "${recs[0]}" 2>/dev/null) out: $(cat "$ROOT/inneroomdrainfail/out.log" 2>/dev/null)"
fi

# --- 11. the boot proof (leg h2) ---------------------------------------------
#
# The control plane's image upgrade commits only on cogworx/boot-proof: proof
# that THIS launch's guest booted, on THIS host boot, from an image whose baked
# protocol values it can check the image's labels against. So the proof must be
# fresh (a previous run's proof and a previous boot's stamp both die before the
# launch), exact (the control plane parses it), refused rather than guessed (a
# stamp the host cannot trust publishes nothing), and level-held like readiness.
# None of it may change what an old control plane sees: readiness keeps its
# nonce half and its timing, and READY_TIMEOUT still counts readiness alone.
# proof_events <md>: every boot-proof PUT/DELETE, in order.
proof_events() { grep -E '^(PUT|DELETE) instance/guest-attributes/cogworx/boot-proof' "$1/events" 2>/dev/null; }
proof_puts() { grep -c '^PUT instance/guest-attributes/cogworx/boot-proof ' "$1/events" 2>/dev/null || true; }

# 11a. A stamp this launch's guest wrote: the proof, exactly, once, after
# readiness, and only after a run-start delete that precedes every publish.
STUB_STAMP=match
rc=$(run_boot proofmatch "${BASE_ATTRS[@]}")
unset STUB_STAMP
md="$ROOT/proofmatch/md"
first_ga=$(grep -n 'instance/guest-attributes/' "$md/events" | head -1)
case "${first_ga#*:}" in
	"DELETE instance/guest-attributes/cogworx/boot-proof "*)
		ok "a previous run's boot proof is deleted at run start, before anything is published" ;;
	*) bad "the first guest-attribute event is not the boot-proof DELETE: $first_ga" ;;
esac
want="PUT instance/guest-attributes/cogworx/ready n0nce-aaaa ok bp=1"
if [ "$(grep -c '^PUT instance/guest-attributes/cogworx/ready ' "$md/events")" = 1 ] \
	&& grep -qxF "$want" "$md/events"; then
	ok "readiness carries the image's protocol version as a bp= tail after the nonce half"
else
	bad "readiness is not exactly '$want': $(grep 'cogworx/ready' "$md/events")"
fi
want="PUT instance/guest-attributes/cogworx/boot-proof n0nce-aaaa bp=1 hb=$HOST_BOOT_ID gb=$GUEST_BOOT_ID pool=ok sf=1"
ready=$(evline "$md" 'PUT instance/guest-attributes/cogworx/ready')
put=$(evline "$md" 'PUT instance/guest-attributes/cogworx/boot-proof')
if [ "$(proof_puts "$md")" = 1 ] && grep -qxF "$want" "$md/events" \
	&& [ -n "$ready" ] && [ -n "$put" ] && [ "$put" -gt "$ready" ]; then
	ok "a stamp this launch's guest wrote publishes exactly the proof, once, after readiness"
else
	bad "expected one '$want' after readiness ($ready); proof events: $(proof_events "$md")"
fi
# Level-held: leg (j) deletes it after the readiness delete, so a dead
# sandbox's proof does not outlive it.
last=$(grep -n 'guest-attributes/cogworx/boot-proof' "$md/events" | tail -1)
rdel=$(grep -n 'DELETE instance/guest-attributes/cogworx/ready' "$md/events" | tail -1 | cut -d: -f1)
case "${last#*:}" in
	"DELETE instance/guest-attributes/cogworx/boot-proof "*)
		if [ -n "$rdel" ] && [ "${last%%:*}" -gt "$rdel" ] && [ ! -e "$md/ga/cogworx_boot-proof" ]; then
			ok "leg (j) deletes the boot proof, after readiness"
		else
			bad "leg (j)'s boot-proof delete (${last%%:*}) does not follow the readiness delete ($rdel), or the proof survived"
		fi ;;
	*) bad "the last boot-proof event is not leg (j)'s DELETE: $last" ;;
esac
if grep -q '^cogworx: boot proof published$' "$ROOT/proofmatch/serial.log" 2>/dev/null \
	&& ! grep -qF -e "$GUEST_BOOT_ID" -e "$HOST_BOOT_ID" -e 'pool=' "$ROOT/proofmatch/serial.log"; then
	ok "serial says a proof was published and carries none of its values"
else
	bad "serial lacks the proof line or carries the stamp's values: $(cat "$ROOT/proofmatch/serial.log" 2>/dev/null)"
fi
# Each baked value travels under its own key. Every other case bakes bp=1 and
# sf=1, which cannot tell the two apart, and a swapped sf is exactly what the
# control plane decides a fallback to an older image by.
STUB_STAMP=match SEED_BP=2 SEED_SF=7
rc=$(run_boot proofdistinct "${BASE_ATTRS[@]}")
unset STUB_STAMP SEED_BP SEED_SF
md="$ROOT/proofdistinct/md"
if grep -qxF "PUT instance/guest-attributes/cogworx/ready n0nce-aaaa ok bp=2" "$md/events" \
	&& grep -qxF "PUT instance/guest-attributes/cogworx/boot-proof n0nce-aaaa bp=2 hb=$HOST_BOOT_ID gb=$GUEST_BOOT_ID pool=ok sf=7" "$md/events"; then
	ok "readiness and the proof carry bp and sf each from its own baked value"
else
	bad "bp=2 sf=7 baked: readiness $(grep 'cogworx/ready' "$md/events" | head -1); proof events: $(proof_events "$md")"
fi
STUB_STAMP=undeletable SEED_BP=2 SEED_SF=7
rc=$(run_boot proofdistinctstuck "${BASE_ATTRS[@]}")
unset STUB_STAMP SEED_BP SEED_SF
if grep -qxF "PUT instance/guest-attributes/cogworx/boot-proof n0nce-aaaa bp=2 err=stamp-path" "$ROOT/proofdistinctstuck/md/events"; then
	ok "the err=stamp-path refusal carries bp from its own baked value"
else
	bad "bp=2 sf=7 baked, uncleanable stamp path: proof events: $(proof_events "$ROOT/proofdistinctstuck/md")"
fi

# 11b. A PREVIOUS boot's stamp, still on the share: cleared before the launch,
# so this guest -- which writes none -- gets no proof from it.
STUB_STAMP=stale
rc=$(run_boot proofstale "${BASE_ATTRS[@]}")
unset STUB_STAMP
md="$ROOT/proofstale/md"
clr=$(evline "$md" '^rm -f -- .*/instances/demo/\.cogbox-boot-stamp$')
start=$(evline "$md" '^cogbox start')
if [ -n "$clr" ] && [ -n "$start" ] && [ "$clr" -lt "$start" ] && grep -qx 'stamp at start: absent' "$md/events" \
	&& [ "$(proof_puts "$md")" = 0 ] && [ -n "$(evline "$md" 'PUT instance/guest-attributes/cogworx/ready')" ]; then
	ok "a previous boot's stamp is removed before cogbox start and proves nothing"
else
	bad "stale stamp: clear=$clr start=$start; events: $(cat "$md/events")"
fi

# 11c. A DIRECTORY squatting at the path (the guest can make one): removed
# recursively, which is safe because no guest runs at leg (f), and the proof
# then publishes normally.
STUB_STAMP=dir
rc=$(run_boot proofdir "${BASE_ATTRS[@]}")
unset STUB_STAMP
md="$ROOT/proofdir/md"
want="PUT instance/guest-attributes/cogworx/boot-proof n0nce-aaaa bp=1 hb=$HOST_BOOT_ID gb=$GUEST_BOOT_ID pool=ok sf=1"
if [ -n "$(evline "$md" '^rm -rf --one-file-system -- .*/\.cogbox-boot-stamp$')" ] \
	&& grep -qx 'stamp at start: absent' "$md/events" && grep -qxF "$want" "$md/events"; then
	ok "a directory at the stamp path is removed with rm -rf and the proof then publishes"
else
	bad "directory stamp: events: $(cat "$md/events")"
fi

# 11d. A path that survives both removals: exactly the err=stamp-path proof,
# before the launch, and no success proof even though this guest then writes a
# perfectly good stamp over it -- the host cannot tell whose it is.
STUB_STAMP=undeletable
rc=$(run_boot proofstuck "${BASE_ATTRS[@]}")
unset STUB_STAMP
md="$ROOT/proofstuck/md"
want="PUT instance/guest-attributes/cogworx/boot-proof n0nce-aaaa bp=1 err=stamp-path"
put=$(evline "$md" 'PUT instance/guest-attributes/cogworx/boot-proof')
start=$(evline "$md" '^cogbox start')
if [ "$(proof_puts "$md")" = 1 ] && grep -qxF "$want" "$md/events" \
	&& [ -n "$put" ] && [ -n "$start" ] && [ "$put" -lt "$start" ] \
	&& grep -qx 'stamp at start: present' "$md/events" \
	&& [ -n "$(evline "$md" 'PUT instance/guest-attributes/cogworx/ready')" ]; then
	ok "an uncleanable stamp path publishes exactly '<nonce> bp=1 err=stamp-path' before start, and no success proof"
else
	bad "uncleanable stamp: expected one '$want' before start ($start); proof events: $(proof_events "$md")"
fi
# A DANGLING symlink that survives both removals is the same refusal: `-e`
# follows it and sees nothing, so only the `-L` half of the check catches it.
STUB_STAMP=undeletable-link
rc=$(run_boot proofstucklink "${BASE_ATTRS[@]}")
unset STUB_STAMP
md="$ROOT/proofstucklink/md"
put=$(evline "$md" 'PUT instance/guest-attributes/cogworx/boot-proof')
start=$(evline "$md" '^cogbox start')
if [ "$(proof_puts "$md")" = 1 ] && grep -qxF "$want" "$md/events" \
	&& [ -n "$put" ] && [ -n "$start" ] && [ "$put" -lt "$start" ]; then
	ok "an uncleanable dangling symlink at the stamp path publishes exactly the err=stamp-path proof before start"
else
	bad "uncleanable dangling symlink: expected one '$want' before start ($start); proof events: $(proof_events "$md")"
fi
# stuck <tag> <what>: exactly the err=stamp-path refusal, once, before start.
stuck() {
	local md="$ROOT/$1/md" put start
	put=$(evline "$md" 'PUT instance/guest-attributes/cogworx/boot-proof')
	start=$(evline "$md" '^cogbox start')
	if [ "$(proof_puts "$md")" = 1 ] && grep -qxF "$want" "$md/events" \
		&& [ -n "$put" ] && [ -n "$start" ] && [ "$put" -lt "$start" ]; then
		ok "$2 publishes exactly the err=stamp-path proof before start"
	else
		bad "$2: expected one '$want' before start ($start); proof events: $(proof_events "$md")"
	fi
}
# A DIRECTORY that outlives `rm -rf --one-file-system` (something mounted below
# it, the realistic undeletable shape) is the same refusal.
STUB_STAMP=dir-undeletable
rc=$(run_boot proofdirstuck "${BASE_ATTRS[@]}")
unset STUB_STAMP
[ -n "$(evline "$ROOT/proofdirstuck/md" '^rm -rf --one-file-system -- .*/\.cogbox-boot-stamp$')" ] \
	|| bad "the uncleanable directory case never reached rm -rf; the next check proves nothing"
stuck proofdirstuck "a directory at the stamp path that rm -rf cannot clear"
# The refusal is gated on a valid version and host boot id only, never on the
# state format: an image whose sf is broken still says why it proves nothing.
SEED_SF=x STUB_STAMP=undeletable
rc=$(run_boot proofsfstuck "${BASE_ATTRS[@]}")
unset SEED_SF STUB_STAMP
stuck proofsfstuck "an invalid state format with an uncleanable stamp path"

# 11e. Stamps the host must refuse: each publishes nothing, the sandbox runs and
# ends exactly as it would without a stamp (never stopped for it), and nothing
# of the stamp reaches serial. `bad` covers a stamp that is not a boot id, one
# equal to the HOST's boot id (no evidence of a guest boot at all), leading and
# trailing junk, an unknown pool state and an uppercase id; a symlink is
# refused even though its target is good, and so is a FIFO. Both are refused
# again when the guest renames one over a good stamp AFTER the host's check:
# the symlink by O_NOFOLLOW (its target is good), the FIFO by the read's 2 s
# bound -- without it the open blocks forever, the loop stops polling, and the
# run hits the test's 60 s bound instead of ending on its own leg.
refused() {
	local tag="$1" what="$2" md="$ROOT/$1/md" recs
	recs=( "$ROOT/$tag/state/inner-exit"/*.log )
	if [ "$rc" != 0 ] && [ "$(proof_puts "$md")" = 0 ] \
		&& [ -n "$(evline "$md" 'PUT instance/guest-attributes/cogworx/ready')" ] \
		&& [ "$(evcount "$md" '^cogbox stop ')" = 0 ] \
		&& grep -q '^leg: exited$' "${recs[0]}" 2>/dev/null \
		&& ! grep -qF -e 'stamp-canary' -e "$GUEST_BOOT_ID" -e 'pool=' "$ROOT/$tag/serial.log"; then
		ok "$what publishes no proof and leaves the sandbox alone"
	else
		bad "$what: rc=$rc proof events: $(proof_events "$md"); stops: $(evcount "$md" '^cogbox stop '); record: $(head -1 "${recs[0]}" 2>/dev/null); serial: $(cat "$ROOT/$tag/serial.log" 2>/dev/null)"
	fi
}
n=0
for text in 'stamp-canary pool=ok\n' "$HOST_BOOT_ID pool=ok\n" "$GUEST_BOOT_ID pool=ok\nstamp-canary\n" \
	"$GUEST_BOOT_ID pool=stamp-canary\n" "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE pool=ok\n" "$GUEST_BOOT_ID  pool=ok\n" \
	"x$GUEST_BOOT_ID pool=ok\n"; do
	n=$((n + 1))
	STUB_STAMP=bad STUB_STAMP_TEXT="$text"
	rc=$(run_boot "proofbad$n" "${BASE_ATTRS[@]}")
	unset STUB_STAMP STUB_STAMP_TEXT
	refused "proofbad$n" "a malformed stamp ($(printf '%s' "$text" | head -c 50))"
done
STUB_STAMP=symlink
rc=$(run_boot proofsymlink "${BASE_ATTRS[@]}")
unset STUB_STAMP
refused proofsymlink "a symlinked stamp"
STUB_STAMP=fifo
rc=$(run_boot prooffifo "${BASE_ATTRS[@]}")
unset STUB_STAMP
refused prooffifo "a FIFO at the stamp path"
STUB_STAMP=match STUB_STAMP_SWAP=symlink
rc=$(run_boot proofswapsym "${BASE_ATTRS[@]}")
unset STUB_STAMP STUB_STAMP_SWAP
refused proofswapsym "a stamp swapped for a symlink after the check (O_NOFOLLOW)"
STUB_STAMP=match STUB_STAMP_SWAP=fifo
t0=$SECONDS
rc=$(run_boot proofswapfifo "${BASE_ATTRS[@]}")
swapfifo_secs=$((SECONDS - t0))
unset STUB_STAMP STUB_STAMP_SWAP
refused proofswapfifo "a stamp swapped for a FIFO after the check (the read's time bound)"
# ...and both swaps really reached the read: a passing pair above that never
# opened the stamp would prove neither defence.
stamp_at() { printf '%s' "$ROOT/$1/state/data/cogbox/instances/demo/.cogbox-boot-stamp"; }
if [ -L "$(stamp_at proofswapsym)" ] && [ -p "$(stamp_at proofswapfifo)" ] \
	&& [ "$(evcount "$ROOT/proofswapsym/md" '^dd-read ')" -ge 1 ] \
	&& [ "$(evcount "$ROOT/proofswapfifo/md" '^dd-read ')" -ge 1 ]; then
	ok "the swap seam fired on the supervisor's stamp read in both swap cases"
else
	bad "a swap case never reached the stamp read: $(ls -l "$(stamp_at proofswapsym)" "$(stamp_at proofswapfifo)" 2>&1)"
fi
# The check ahead of the read is the PRIMARY defence and the only one against a
# device node already at the path (O_NOFOLLOW and the time bound do nothing for
# it): a stamp that is already a symlink or a FIFO is refused before dd opens
# anything.
if [ "$(evcount "$ROOT/proofsymlink/md" '^dd-read ')" = 0 ] && [ "$(evcount "$ROOT/prooffifo/md" '^dd-read ')" = 0 ]; then
	ok "a stamp that is already a symlink or a FIFO never reaches the read"
else
	bad "the stamp read opened a non-regular stamp: symlink case $(evcount "$ROOT/proofsymlink/md" '^dd-read ') read(s), FIFO case $(evcount "$ROOT/prooffifo/md" '^dd-read ') read(s)"
fi
# The time bound is 2 s, and a swapped-in FIFO blocks exactly one read (every
# later poll's check refuses it before dd), so that run takes a couple of
# seconds. A bound loosened to tens of seconds would stall the hold loop -- and
# the QEMU and OOM-kill watch with it -- that long per swap, well short of the
# 60 s wedge bound.
if [ "$swapfifo_secs" -lt 10 ]; then
	ok "a FIFO swapped over the stamp costs the hold loop one short bounded read (${swapfifo_secs}s)"
else
	bad "the FIFO swap run took ${swapfifo_secs}s; the read's time bound is not the 2 s it should be"
fi
# ...and it is exactly the protocol's 2 s, on every read, the blocked one and an
# ordinary one alike.
for tag in proofswapfifo proofmatch; do
	if [ "$(evcount "$ROOT/$tag/md" '^timeout-read ')" -ge 1 ] \
		&& ! grep '^timeout-read ' "$ROOT/$tag/md/events" | grep -qvx 'timeout-read 2'; then
		ok "every stamp read in $tag runs under a 2 s bound"
	else
		bad "a stamp read in $tag is not bounded at 2 s: $(grep '^timeout-read ' "$ROOT/$tag/md/events" | sort | uniq -c | tr '\n' ' ')"
	fi
done
# The size bound: only the first 256 bytes are read. A good stamp padded with
# newlines to exactly 256 bytes, with junk past them, reads as that good stamp
# (the shell trims the trailing newlines), while an unbounded read sees the junk
# and refuses it. This pins the bound, not a shape the guest writes.
stampline="$GUEST_BOOT_ID pool=ok"
STUB_STAMP=bad STUB_STAMP_TEXT="$stampline$(printf '\\n%.0s' $(seq $((256 - ${#stampline}))))stamp-canary-past-the-bound\n"
rc=$(run_boot proofpad "${BASE_ATTRS[@]}")
unset STUB_STAMP STUB_STAMP_TEXT
want="PUT instance/guest-attributes/cogworx/boot-proof n0nce-aaaa bp=1 hb=$HOST_BOOT_ID gb=$GUEST_BOOT_ID pool=ok sf=1"
if [ "$(head -c 256 "$(stamp_at proofpad)" | wc -l)" = $((256 - ${#stampline})) ] \
	&& [ "$(stat -c %s "$(stamp_at proofpad)")" -gt 256 ] \
	&& [ "$(proof_puts "$ROOT/proofpad/md")" = 1 ] && grep -qxF "$want" "$ROOT/proofpad/md/events"; then
	ok "the stamp read stops at 256 bytes"
else
	bad "the stamp read is not bounded at 256 bytes: proof events: $(proof_events "$ROOT/proofpad/md")"
fi

# 11f. pool=missing is still a well-formed proof: the control plane, not the
# host, decides that a guest whose data pool did not mount fails the upgrade.
STUB_STAMP=match STUB_POOL=missing
rc=$(run_boot proofpool "${BASE_ATTRS[@]}")
unset STUB_STAMP STUB_POOL
want="PUT instance/guest-attributes/cogworx/boot-proof n0nce-aaaa bp=1 hb=$HOST_BOOT_ID gb=$GUEST_BOOT_ID pool=missing sf=1"
if grep -qxF "$want" "$ROOT/proofpool/md/events"; then
	ok "a stamp saying the pool did not mount publishes a proof with pool=missing"
else
	bad "pool=missing: proof events: $(proof_events "$ROOT/proofpool/md")"
fi

# 11g. No valid baked protocol version is the LEGACY shape: readiness with no
# tail and no proof of either kind, even for a good stamp or an uncleanable
# path. A valid version with no valid state format or host boot id keeps the
# tail but publishes no success proof; the err=stamp-path refusal needs only a
# valid version and host boot id.
legacy() {
	local tag="$1" what="$2" want="$3" md="$ROOT/$1/md"
	if [ "$(grep -c '^PUT instance/guest-attributes/cogworx/ready ' "$md/events")" = 1 ] \
		&& grep -qxF "PUT instance/guest-attributes/cogworx/ready $want" "$md/events" \
		&& [ "$(proof_puts "$md")" = 0 ]; then
		ok "$what: readiness is '$want' and no proof is published"
	else
		bad "$what: readiness $(grep 'cogworx/ready' "$md/events" | head -2 | tr '\n' ' '); proof events: $(proof_events "$md")"
	fi
}
for bp in "" 0 abc 1x; do
	SEED_BP="$bp" STUB_STAMP=match
	rc=$(run_boot "proofbp${bp:-empty}" "${BASE_ATTRS[@]}")
	unset SEED_BP STUB_STAMP
	legacy "proofbp${bp:-empty}" "COGWORX_IMAGE_BOOT_PROOF='$bp'" "n0nce-aaaa ok"
done
SEED_BP="" STUB_STAMP=undeletable
rc=$(run_boot proofbpstuck "${BASE_ATTRS[@]}")
unset SEED_BP STUB_STAMP
legacy proofbpstuck "no protocol version and an uncleanable stamp path" "n0nce-aaaa ok"
for sf in "" x -1; do
	SEED_SF="$sf" STUB_STAMP=match
	rc=$(run_boot "proofsf${sf:-empty}" "${BASE_ATTRS[@]}")
	unset SEED_SF STUB_STAMP
	legacy "proofsf${sf:-empty}" "COGWORX_IMAGE_STATE_FORMAT='$sf'" "n0nce-aaaa ok bp=1"
done
printf 'not-a-boot-id\n' > "$ROOT/badhostid"
SEED_BOOT_ID_FILE="$ROOT/badhostid" STUB_STAMP=match
rc=$(run_boot proofhb "${BASE_ATTRS[@]}")
unset SEED_BOOT_ID_FILE STUB_STAMP
legacy proofhb "a host boot id that is not a UUID" "n0nce-aaaa ok bp=1"
# The refusal needs a valid host boot id too: without one an uncleanable path
# publishes nothing at all.
SEED_BOOT_ID_FILE="$ROOT/badhostid" STUB_STAMP=undeletable
rc=$(run_boot proofhbstuck "${BASE_ATTRS[@]}")
unset SEED_BOOT_ID_FILE STUB_STAMP
legacy proofhbstuck "a host boot id that is not a UUID and an uncleanable stamp path" "n0nce-aaaa ok bp=1"

# 11h. No stamp at all: readiness alone decides the boot. A ready guest whose
# stamp never appears stays up until it exits on its own -- never a
# ready-timeout, which still means only "the guest never became ready".
STUB_STAMP=none STUB_STATUS_OK=100
rc=$(run_boot proofnone "${BASE_ATTRS[@]}")
unset STUB_STAMP STUB_STATUS_OK
md="$ROOT/proofnone/md"
recs=( "$ROOT/proofnone/state/inner-exit"/*.log )
if [ "$(cat "$md/statusn" 2>/dev/null)" = 101 ] && grep -q '^leg: exited$' "${recs[0]}" 2>/dev/null \
	&& ! grep -q 'did not become ready' "$ROOT/proofnone/serial.log" 2>/dev/null \
	&& [ "$(proof_puts "$md")" = 0 ] && [ "$(evcount "$md" '^cogbox stop ')" = 0 ]; then
	ok "a ready guest with no stamp is held to readiness alone, never a ready-timeout"
else
	bad "no stamp: polls=$(cat "$md/statusn" 2>/dev/null) record=$(head -1 "${recs[0]}" 2>/dev/null) serial: $(cat "$ROOT/proofnone/serial.log" 2>/dev/null)"
fi
# ...and the converse: a good stamp from a guest that never becomes ready
# proves nothing, and the boot still times out on readiness exactly as before.
SEED_GUEST_KEY="" STUB_STAMP=match STUB_STATUS_OK=100
rc=$(run_boot proofnoready "${BASE_ATTRS[@]}")
unset SEED_GUEST_KEY STUB_STAMP STUB_STATUS_OK
md="$ROOT/proofnoready/md"
recs=( "$ROOT/proofnoready/state/inner-exit"/*.log )
if grep -q '^leg: ready-timeout$' "${recs[0]}" 2>/dev/null && [ "$(proof_puts "$md")" = 0 ] \
	&& [ -z "$(evline "$md" 'PUT instance/guest-attributes/cogworx/ready')" ]; then
	ok "a stamp from a guest that never becomes ready publishes nothing, and readiness still times out"
else
	bad "stamp without readiness: record=$(head -1 "${recs[0]}" 2>/dev/null) proof events: $(proof_events "$md")"
fi

# 11i. Level-held at every other site readiness is deleted.
# The OOM drain: after the readiness delete and before the guest is stopped.
STUB_STAMP=match STUB_STATUS_OK=100 STUB_OOM_AT=3
rc=$(run_boot proofoom "${BASE_ATTRS[@]}")
unset STUB_STAMP STUB_STATUS_OK STUB_OOM_AT
md="$ROOT/proofoom/md"
put=$(evline "$md" 'PUT instance/guest-attributes/cogworx/boot-proof')
rdel=$(evline "$md" 'DELETE instance/guest-attributes/cogworx/ready')
stop=$(evline "$md" '^cogbox stop ')
pdel=$(grep -n '^DELETE instance/guest-attributes/cogworx/boot-proof' "$md/events" | awk -F: -v r="${rdel:-0}" '$1 > r { print $1; exit }')
if [ -n "$put" ] && [ -n "$rdel" ] && [ -n "$stop" ] && [ -n "$pdel" ] && [ "$put" -lt "$rdel" ] && [ "$pdel" -lt "$stop" ]; then
	ok "the OOM drain deletes the boot proof before it stops the guest"
else
	bad "OOM drain: proof put=$put ready delete=$rdel proof delete=$pdel stop=$stop; events: $(cat "$md/events")"
fi
# A failed start, which may follow an err=stamp-path proof.
STUB_STAMP=undeletable STUB_START_RC=1
rc=$(run_boot proofstartfail "${BASE_ATTRS[@]}")
unset STUB_STAMP STUB_START_RC
md="$ROOT/proofstartfail/md"
start=$(evline "$md" '^cogbox start')
last=$(grep -n 'guest-attributes/cogworx/boot-proof' "$md/events" | tail -1)
if [ "$rc" != 0 ] && grep -q '^cogworx: sandbox start failed$' "$ROOT/proofstartfail/serial.log" 2>/dev/null \
	&& [ -n "$start" ] && [ "${last%%:*}" -gt "$start" ] \
	&& [ "${last#*:}" = "DELETE instance/guest-attributes/cogworx/boot-proof " ]; then
	ok "a failed start deletes the boot proof"
else
	bad "failed start: rc=$rc start=$start last proof event: $last"
fi
# Both short-circuits: the run-start delete, and their own after readiness's.
for tag in resolver maint; do
	md="$ROOT/$tag/md"
	rdel=$(evline "$md" 'DELETE instance/guest-attributes/cogworx/ready')
	pdel=$(grep -n '^DELETE instance/guest-attributes/cogworx/boot-proof' "$md/events" | tail -1 | cut -d: -f1)
	if [ "$(evcount "$md" '^DELETE instance/guest-attributes/cogworx/boot-proof')" = 2 ] \
		&& [ -n "$rdel" ] && [ -n "$pdel" ] && [ "$pdel" -gt "$rdel" ]; then
		ok "the $tag short-circuit deletes the boot proof after readiness"
	else
		bad "$tag short-circuit: proof events: $(proof_events "$md"); ready delete at $rdel"
	fi
done

# 11j. The boot-error contract the control plane classifies by is unchanged: a
# classified failure publishes its cogbox-stamped summary, an unmatched one the
# frozen generic literal, and a later successful init clears it.
ga="$ROOT/initfail/md/ga/cogworx_boot-error"
if grep -q '^n0nce-aaaa error: cogbox: config.json is empty' "$ga" 2>/dev/null \
	&& [ "$(cat "$ga")" != 'n0nce-aaaa cogbox init failed' ]; then
	ok "a classified init failure publishes '<nonce> <cogbox-stamped summary>'"
else
	bad "classified boot-error is not '<nonce> error: cogbox: ...': $(cat "$ga" 2>/dev/null)"
fi
if [ "$(cat "$ROOT/initopaque/md/ga/cogworx_boot-error" 2>/dev/null)" = 'n0nce-aaaa cogbox init failed' ]; then
	ok "an unmatched init failure publishes exactly '<nonce> cogbox init failed'"
else
	bad "unclassified boot-error is not the generic literal: $(cat "$ROOT/initopaque/md/ga/cogworx_boot-error" 2>/dev/null)"
fi
rc=$(run_boot initfail "${BASE_ATTRS[@]}")
if [ ! -e "$ga" ] && [ -n "$(evline "$ROOT/initfail/md" 'DELETE instance/guest-attributes/cogworx/boot-error')" ]; then
	ok "a later successful init clears the published boot-error"
else
	bad "a successful init left boot-error in place: $(cat "$ga" 2>/dev/null)"
fi

# 11k. A transient PUT failure never costs a run its publish: each publish is
# retried on the next poll until one lands, and the order holds across the
# retry. Without the retry one metadata-server blip leaves the control plane
# waiting out its whole window on a running target and reading the silence as a
# fault of the image.
evlinex() { grep -nxF -- "$2" "$1/events" 2>/dev/null | head -1 | cut -d: -f1; }
proof="n0nce-aaaa bp=1 hb=$HOST_BOOT_ID gb=$GUEST_BOOT_ID pool=ok sf=1"
# The success proof.
STUB_STAMP=match STUB_PUT_FAIL_ONCE=cogworx/boot-proof STUB_STATUS_OK=4
rc=$(run_boot proofputretry "${BASE_ATTRS[@]}")
unset STUB_STAMP STUB_PUT_FAIL_ONCE STUB_STATUS_OK
md="$ROOT/proofputretry/md"
failed=$(evlinex "$md" "FAILED-PUT instance/guest-attributes/cogworx/boot-proof $proof")
put=$(evlinex "$md" "PUT instance/guest-attributes/cogworx/boot-proof $proof")
if [ -n "$failed" ] && [ -n "$put" ] && [ "$failed" -lt "$put" ] && [ "$(proof_puts "$md")" = 1 ]; then
	ok "a boot-proof PUT that fails is retried, and lands exactly once"
else
	bad "boot-proof PUT retry: failed at $failed, landed at $put, $(proof_puts "$md") landed; events: $(cat "$md/events")"
fi
# Readiness: the proof still waits for the readiness PUT that LANDED, not for
# the guest's host key that made the failed attempt.
STUB_STAMP=match STUB_PUT_FAIL_ONCE=cogworx/ready STUB_STATUS_OK=4
rc=$(run_boot readyputretry "${BASE_ATTRS[@]}")
unset STUB_STAMP STUB_PUT_FAIL_ONCE STUB_STATUS_OK
md="$ROOT/readyputretry/md"
failed=$(evlinex "$md" "FAILED-PUT instance/guest-attributes/cogworx/ready n0nce-aaaa ok bp=1")
ready=$(evlinex "$md" "PUT instance/guest-attributes/cogworx/ready n0nce-aaaa ok bp=1")
put=$(evlinex "$md" "PUT instance/guest-attributes/cogworx/boot-proof $proof")
if [ -n "$failed" ] && [ -n "$ready" ] && [ -n "$put" ] && [ "$failed" -lt "$ready" ] && [ "$ready" -lt "$put" ] \
	&& [ "$(grep -c '^PUT instance/guest-attributes/cogworx/ready ' "$md/events")" = 1 ] && [ "$(proof_puts "$md")" = 1 ]; then
	ok "a readiness PUT that fails is retried, and the proof lands only after the retry"
else
	bad "readiness PUT retry: failed at $failed, readiness landed at $ready, proof at $put; events: $(cat "$md/events")"
fi
# The err=stamp-path refusal: its leg (f) PUT fails, and the hold loop lands it.
STUB_STAMP=undeletable STUB_PUT_FAIL_ONCE=cogworx/boot-proof
rc=$(run_boot proofstuckretry "${BASE_ATTRS[@]}")
unset STUB_STAMP STUB_PUT_FAIL_ONCE
md="$ROOT/proofstuckretry/md"
failed=$(evlinex "$md" "FAILED-PUT instance/guest-attributes/cogworx/boot-proof n0nce-aaaa bp=1 err=stamp-path")
start=$(evline "$md" '^cogbox start')
put=$(evlinex "$md" "PUT instance/guest-attributes/cogworx/boot-proof n0nce-aaaa bp=1 err=stamp-path")
if [ -n "$failed" ] && [ -n "$start" ] && [ -n "$put" ] && [ "$failed" -lt "$start" ] && [ "$start" -lt "$put" ] \
	&& [ "$(proof_puts "$md")" = 1 ]; then
	ok "an err=stamp-path refusal whose PUT fails before start is retried from the hold loop, once"
else
	bad "refusal PUT retry: failed at $failed, start at $start, landed at $put; proof events: $(proof_events "$md")"
fi
# A refusal whose PUT keeps failing leaves the hold loop ready, owing the
# refusal and with nothing published -- the window in which only the refusal's
# own "no success proof this run" stands between the host and a proof built from
# a stamp it could not clear, possibly a previous boot's (on network=none the
# control plane has no guest hop to catch that). So no proof of either kind may
# land, the refusal is still retried after readiness, and the ready guest is
# never killed for it: READY_TIMEOUT counts readiness alone, refusal pending or
# not.
STUB_STAMP=undeletable STUB_PUT_FAIL_DATA='err=stamp-path' STUB_STATUS_OK=6
rc=$(run_boot proofstuckfailing "${BASE_ATTRS[@]}")
unset STUB_STAMP STUB_PUT_FAIL_DATA STUB_STATUS_OK
md="$ROOT/proofstuckfailing/md"
recs=( "$ROOT/proofstuckfailing/state/inner-exit"/*.log )
ready=$(evlinex "$md" "PUT instance/guest-attributes/cogworx/ready n0nce-aaaa ok bp=1")
failed=$(grep -nxF "FAILED-PUT instance/guest-attributes/cogworx/boot-proof n0nce-aaaa bp=1 err=stamp-path" "$md/events" | tail -1 | cut -d: -f1)
if [ "$(proof_puts "$md")" = 0 ] \
	&& [ "$(evcount "$md" '^FAILED-PUT instance/guest-attributes/cogworx/boot-proof ')" -ge 2 ] \
	&& [ -n "$ready" ] && [ -n "$failed" ] && [ "$failed" -gt "$ready" ] \
	&& grep -q '^leg: exited$' "${recs[0]}" 2>/dev/null \
	&& ! grep -q 'did not become ready' "$ROOT/proofstuckfailing/serial.log" 2>/dev/null; then
	ok "a refusal that never lands lets no success proof through, is retried after readiness, and never kills the ready guest"
else
	bad "refusal PUT failing throughout: ready at $ready, last failed refusal at $failed; proof events: $(proof_events "$md"); failed: $(grep -c '^FAILED-PUT' "$md/events"); record: $(head -1 "${recs[0]}" 2>/dev/null)"
fi
# ...and its retry does not wait for readiness: a guest that never becomes
# ready still gets the refusal it owes from the hold loop, so the control plane
# reads "the host could not prove this boot" rather than silence.
STUB_STAMP=undeletable STUB_PUT_FAIL_ONCE=cogworx/boot-proof SEED_GUEST_KEY="" STUB_STATUS_OK=100
rc=$(run_boot proofstucknoready "${BASE_ATTRS[@]}")
unset STUB_STAMP STUB_PUT_FAIL_ONCE SEED_GUEST_KEY STUB_STATUS_OK
md="$ROOT/proofstucknoready/md"
recs=( "$ROOT/proofstucknoready/state/inner-exit"/*.log )
start=$(evline "$md" '^cogbox start')
put=$(evlinex "$md" "PUT instance/guest-attributes/cogworx/boot-proof n0nce-aaaa bp=1 err=stamp-path")
if [ -n "$start" ] && [ -n "$put" ] && [ "$put" -gt "$start" ] && [ "$(proof_puts "$md")" = 1 ] \
	&& [ -z "$(evline "$md" 'PUT instance/guest-attributes/cogworx/ready')" ] \
	&& grep -q '^leg: ready-timeout$' "${recs[0]}" 2>/dev/null; then
	ok "a refusal whose first PUT fails lands from the hold loop even when the guest never becomes ready"
else
	bad "refusal retry without readiness: start at $start, landed at $put; proof events: $(proof_events "$md"); record: $(head -1 "${recs[0]}" 2>/dev/null)"
fi

if [ -s "$ROOT/wedged" ]; then
	bad "the supervisor hit the test's 60 s bound in: $(tr '\n' ' ' < "$ROOT/wedged")"
fi

if [ "$fails" -gt 0 ]; then
	echo "$fails check(s) failed" >&2
	exit 1
fi
echo "all supervise checks passed"
