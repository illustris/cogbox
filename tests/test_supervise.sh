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
		# The guest writes its persisted host key only after it boots, so a
		# stub that creates it up front would make the readiness ordering
		# assertion vacuous.
		if [ -n "${STUB_GUEST_KEY:-}" ]; then
			mkdir -p "$(dirname "$STUB_GUEST_KEY")"
			printf 'ssh-ed25519 AAAAguestkey guest\n' > "$STUB_GUEST_KEY"
		fi
		exit "${STUB_START_RC:-0}" ;;
	status)
		n=0
		[ -f "$FAKEMD/statusn" ] && n=$(cat "$FAKEMD/statusn")
		n=$((n + 1)); echo "$n" > "$FAKEMD/statusn"
		[ "$n" -le "${STUB_STATUS_OK:-2}" ] && exit 0
		exit 1 ;;
esac
exit 0
STUB
} > "$BIN/cogbox"

# Real sleeps would make a 300 s readiness budget a 300 s test. The loop bound
# is an iteration count for exactly this reason.
{ shebang; printf 'exit 0\n'; } > "$BIN/sleep"
{ shebang; printf 'exit 0\n'; } > "$BIN/mountpoint"
chmod 0755 "$BIN"/*

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
	local kv
	for kv in "$@"; do
		printf '%s' "${kv#*=}" > "$FAKEMD/attrs/${kv%%=*}"
	done
	PATH="$BIN:$PATH" \
	FAKEMD="$FAKEMD" \
	COGBOX_HOST_RESOLVER="${SEED_HOST_RESOLVER-127.0.0.53}" \
	COGWORX_RESOLV_CONF="$home/resolv.conf" \
	STUB_GUEST_KEY="$home/state/data/cogbox/instances/demo/ssh/ssh_host_ed25519_key.pub" \
	COGWORX_MD_BASE="http://metadata.invalid/computeMetadata/v1" \
	COGWORX_SERIAL="$home/serial.log" \
	COGWORX_STATE_DIR="$home/state" \
	COGWORX_POLL_INTERVAL=1 \
	COGWORX_READY_TIMEOUT=4 \
	COGWORX_HOSTKEY_TIMEOUT=2 \
	COGWORX_GUEST_VOLUMES="${SEED_GUEST_VOLUMES-}" \
	STUB_INIT_RC="${STUB_INIT_RC:-0}" \
	STUB_INIT_OUT="${STUB_INIT_OUT:-}" \
	XDG_CONFIG_HOME="${SEED_XDG_CONFIG_HOME-$home/state/config}" \
	COGBOX_DATA="$home/state/data/cogbox" \
	XDG_RUNTIME_DIR="$home/run" \
		bash "$SUP" > "$home/out.log" 2>&1
	echo $?
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
# out of Running the way the kubelet makes a pod not-ready.
last=$(tail -1 "$md/events")
case "$last" in
	"DELETE instance/guest-attributes/cogworx/ready"*) ok "the readiness delete is the last act before the non-zero exit" ;;
	*) bad "expected the readiness DELETE last, got: $last" ;;
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

if [ "$fails" -gt 0 ]; then
	echo "$fails check(s) failed" >&2
	exit 1
fi
echo "all supervise checks passed"
