#!/usr/bin/env bash
# Behavioural test for cogbox-launch.sh's `init` seeding, run without a VM.
#
# Covers two things unit tests cannot:
#
#   1. The PRODUCER half of the host-integration seeds. --no-implicit-dns and
#      --self-addr are what turn the filter's parameterized port-53 allow and
#      the L7 proxy's per-instance floor ON; without a producer both sides are
#      dead code and an image ships the permissive defaults. It also pins the
#      inverse: an init WITHOUT the flags writes exactly the blob it wrote
#      before they existed, which is what keeps the local and k8s backends
#      untouched.
#
#   2. That a launch failure does not echo credential context. Error paths run
#      with secrets in the environment; a diagnostic that interpolates one is a
#      leak into whatever collects the launcher's stderr (on a cloud VM that is
#      a provider-retained serial console).
#
# Usage: test_launch_flags.sh <path-to-cogbox-launch.sh> <path-to-cogbox-shutdown.sh> <path-to-zig/src/plugin/apply.zig>
# Needs: bash, jq, coreutils, util-linux (flock). NOT passt/qemu/nix: every case
# stops at --init-only or fails before the launch, except section 10's daemon
# passes, which boot a fake runner (`--network none`, stub nix/nix-store/cogbox)
# through the real shutdown module.

set -uo pipefail

LAUNCH="${1:?usage: test_launch_flags.sh <cogbox-launch.sh> <cogbox-shutdown.sh>}"
[ -f "$LAUNCH" ] || { echo "FAIL: no such script: $LAUNCH" >&2; exit 1; }
SHUTDOWN="${2:?usage: test_launch_flags.sh <cogbox-launch.sh> <cogbox-shutdown.sh> <apply.zig>}"
[ -f "$SHUTDOWN" ] || { echo "FAIL: no such script: $SHUTDOWN" >&2; exit 1; }
APPLY_ZIG="${3:?usage: test_launch_flags.sh <cogbox-launch.sh> <cogbox-shutdown.sh> <apply.zig>}"
[ -f "$APPLY_ZIG" ] || { echo "FAIL: no such file: $APPLY_ZIG" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

fails=0
ok()   { echo "ok   - $*"; }
bad()  { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

# Run `cogbox-launch.sh` against a private HOME. Echoes nothing; the caller
# reads $out_dir/config.json and $WORK/<tag>.log.
run_init() {
	local tag="$1"; shift
	local home="$WORK/$tag"
	mkdir -p "$home"
	HOME="$home" \
	COGBOX_DATA="$home/data" \
	XDG_CONFIG_HOME="$home/config" \
		bash "$LAUNCH" --init-only --yes "$@" >"$WORK/$tag.log" 2>&1
	echo $?
}

cfg_of() { echo "$WORK/$1/config/cogbox/instances/demo/config.json"; }

# --- 1. no flags: today's blob, unchanged -----------------------------------

rc=$(run_init plain --name demo --network rules)
[ "$rc" = 0 ] || bad "plain init exited $rc (log: $(cat "$WORK/plain.log"))"
plain=$(cfg_of plain)
if [ -f "$plain" ]; then
	[ "$(jq -r '.bindAddr' "$plain")" = "127.0.0.1" ] \
		|| bad "plain init did not keep bindAddr 127.0.0.1"
	[ "$(jq -r '.network | has("implicitDns")' "$plain")" = "false" ] \
		|| bad "plain init wrote an implicitDns key"
	[ "$(jq -r '.network | has("selfAddrs")' "$plain")" = "false" ] \
		|| bad "plain init wrote a selfAddrs key"
	[ "$(jq -r '.network | has("dnsHost")' "$plain")" = "false" ] \
		|| bad "plain init wrote a dnsHost key"
	ok "init without the seeds writes the pre-feature config"
else
	bad "plain init wrote no config.json"
fi

# --- 2. all four flags land in config.json ----------------------------------

rc=$(run_init seeded --name demo --network rules \
	--bind-addr 10.0.0.5 --no-implicit-dns --dns-host 127.0.0.53 \
	--self-addr 10.0.0.5/32 --self-addr 10.0.0.6/32)
[ "$rc" = 0 ] || bad "seeded init exited $rc (log: $(cat "$WORK/seeded.log"))"
seeded=$(cfg_of seeded)
if [ -f "$seeded" ]; then
	[ "$(jq -r '.bindAddr' "$seeded")" = "10.0.0.5" ] \
		|| bad "--bind-addr did not reach .bindAddr"
	[ "$(jq -r '.network.implicitDns' "$seeded")" = "false" ] \
		|| bad "--no-implicit-dns did not reach .network.implicitDns"
	[ "$(jq -c '.network.selfAddrs' "$seeded")" = '["10.0.0.5/32","10.0.0.6/32"]' ] \
		|| bad "--self-addr did not reach .network.selfAddrs in order (got $(jq -c '.network.selfAddrs' "$seeded"))"
	[ "$(jq -r '.network.dnsHost' "$seeded")" = "127.0.0.53" ] \
		|| bad "--dns-host did not reach .network.dnsHost"
	ok "the four seeds land in config.json"

	# ...and they add NOTHING else: strip exactly what they contribute and the
	# blob must equal the flagless one, key for key.
	if [ -f "$plain" ]; then
		stripped=$(jq -S 'del(.network.implicitDns, .network.selfAddrs, .network.dnsHost) | .bindAddr = "127.0.0.1"' "$seeded")
		base=$(jq -S '.' "$plain")
		[ "$stripped" = "$base" ] \
			|| bad "the seeded config differs from the plain one beyond the four seeds"
		ok "the seeds contribute exactly four keys and no other drift"
	fi
else
	bad "seeded init wrote no config.json"
fi

# --- 3. each seed is independent -------------------------------------------

rc=$(run_init dnsonly --name demo --network rules --no-implicit-dns)
[ "$rc" = 0 ] || bad "dns-only init exited $rc (log: $(cat "$WORK/dnsonly.log"))"
dnsonly=$(cfg_of dnsonly)
if [ -f "$dnsonly" ]; then
	[ "$(jq -r '.network.implicitDns' "$dnsonly")" = "false" ] \
		|| bad "--no-implicit-dns alone did not reach .network.implicitDns"
	[ "$(jq -r '.network | has("selfAddrs")' "$dnsonly")" = "false" ] \
		|| bad "--no-implicit-dns alone invented a selfAddrs key"
	[ "$(jq -r '.network | has("dnsHost")' "$dnsonly")" = "false" ] \
		|| bad "--no-implicit-dns alone invented a dnsHost key"
	ok "--no-implicit-dns alone writes only implicitDns"
else
	bad "dns-only init wrote no config.json"
fi

rc=$(run_init selfonly --name demo --network rules --self-addr 10.0.0.5/32)
[ "$rc" = 0 ] || bad "self-addr-only init exited $rc (log: $(cat "$WORK/selfonly.log"))"
selfonly=$(cfg_of selfonly)
if [ -f "$selfonly" ]; then
	[ "$(jq -c '.network.selfAddrs' "$selfonly")" = '["10.0.0.5/32"]' ] \
		|| bad "--self-addr alone did not reach .network.selfAddrs"
	[ "$(jq -r '.network | has("implicitDns")' "$selfonly")" = "false" ] \
		|| bad "--self-addr alone invented an implicitDns key"
	ok "--self-addr alone writes only selfAddrs"
else
	bad "self-addr-only init wrote no config.json"
fi

rc=$(run_init dnshostonly --name demo --network rules --dns-host 127.0.0.53)
[ "$rc" = 0 ] || bad "dns-host-only init exited $rc (log: $(cat "$WORK/dnshostonly.log"))"
dnshostonly=$(cfg_of dnshostonly)
if [ -f "$dnshostonly" ]; then
	[ "$(jq -r '.network.dnsHost' "$dnshostonly")" = "127.0.0.53" ] \
		|| bad "--dns-host alone did not reach .network.dnsHost"
	[ "$(jq -r '.network | has("implicitDns")' "$dnshostonly")" = "false" ] \
		|| bad "--dns-host alone invented an implicitDns key"
	ok "--dns-host alone writes only dnsHost"
else
	bad "dns-host-only init wrote no config.json"
fi

# --- 4. full mode: the rules-only seeds are refused loudly ------------------

rc=$(run_init fullmode --name demo --network full --no-implicit-dns --dns-host 127.0.0.53 --self-addr 10.0.0.5/32)
[ "$rc" = 0 ] || bad "full-mode init exited $rc (log: $(cat "$WORK/fullmode.log"))"
fullcfg=$(cfg_of fullmode)
if [ -f "$fullcfg" ]; then
	[ "$(jq -r '.network' "$fullcfg")" = "full" ] \
		|| bad "full-mode init did not keep .network == \"full\""
	grep -qi "rules.*mode only\|apply to \"rules\" mode only" "$WORK/fullmode.log" \
		|| bad "full-mode init dropped the seeds silently (no warning in the log)"
	ok "the rules-only seeds are refused with a warning in full mode"
else
	bad "full-mode init wrote no config.json"
fi

# --- 5. the passt knobs reach BOTH modes ------------------------------------
#
# Static, because starting passt needs a VM. Worth pinning anyway: `full` mode
# is the one with no L4 filter at all, so wiring the uid and guest-DNS knobs
# into `rules` only would leave the hole open exactly where nothing else covers
# it. Asserting the invocation count too, so a third one cannot slip by
# unchecked.

n_passt=$(grep -c ' --foreground --socket' "$LAUNCH")
if [ "$n_passt" -ne 2 ]; then
	bad "expected 2 passt invocations in the launcher, found $n_passt"
else
	missing=0
	while IFS= read -r ln; do
		window=$(sed -n "${ln},$((ln + 2))p" "$LAUNCH")
		for tok in PASST_RUNAS_ARGS PASST_DNS_ARGS PASST_FWD_PREFIX PASST_MOSH_ARGS; do
			case "$window" in
				*"$tok"*) ;;
				*) bad "passt invocation at line $ln does not carry $tok"; missing=1 ;;
			esac
		done
	done < <(grep -n ' --foreground --socket' "$LAUNCH" | cut -d: -f1)
	[ "$missing" -eq 0 ] && ok "both passt invocations carry the uid / guest-DNS / bind / mosh knobs"
	# Both must run passt IPv4-only. No host has IPv6 egress, and passt (since
	# 2026_07) with no host IPv6 interface to template still sends router
	# advertisements: the guest gets `default via fe80::1`, dials dual-stack
	# names over IPv6 first and fast-fails each before falling back to IPv4.
	# `-4` is the one flag that disables RA/NDP/DHCPv6 together.
	v4=0
	while IFS= read -r ln; do
		window=$(sed -n "${ln},$((ln + 2))p" "$LAUNCH")
		case "$window" in
			*' -4 '*|*'--ipv4-only'*) ;;
			*) bad "passt invocation at line $ln is not IPv4-only (-4); the guest would pick up a router advertisement and dial IPv6 first"; v4=1 ;;
		esac
	done < <(grep -n ' --foreground --socket' "$LAUNCH" | cut -d: -f1)
	[ "$v4" -eq 0 ] && ok "both passt invocations run IPv4-only (-4)"
	# Neither invocation may pin passt's outbound source address: the netfilter
	# shim's mosh reply exemption (zig/src/netfilter) tells passt's inbound
	# reply sockets apart from guest-originated UDP by the latter binding the
	# WILDCARD address, and `--outbound-addr`/`-o` would make every outbound
	# socket bind a specific one -- widening the exemption to all guest UDP.
	oa=0
	while IFS= read -r ln; do
		window=$(sed -n "${ln},$((ln + 2))p" "$LAUNCH")
		case "$window" in
			*'--outbound-addr'*|*' -o '*) bad "passt invocation at line $ln pins an outbound address; the shim's mosh reply exemption would then match guest-originated UDP too"; oa=1 ;;
		esac
	done < <(grep -n ' --foreground --socket' "$LAUNCH" | cut -d: -f1)
	[ "$oa" -eq 0 ] && ok "no passt invocation passes --outbound-addr / -o"
fi

# --- 5a. the mosh UDP forward: composed like -t, refused unless <lo>-<hi> ---
#
# The `-u` must take the SAME bind prefix as the two -t forwards, or with
# COGBOX_PASST_BIND_FORWARDS the SSH/HTTP forwards would bind the VM address
# while the mosh range bound every address. Static for the composition (the
# spelling is the mechanism); BEHAVIOURAL for the validation, by extracting
# the PASST_MOSH_ARGS block and running it with a stub `die` -- --init-only
# returns before the knob block, so run_init cannot reach it.
grep -qF -- '-u "${PASST_FWD_PREFIX}${COGBOX_MOSH_UDP_FORWARD}"' "$LAUNCH" \
	&& ok "the mosh -u forward composes the same bind prefix as the -t forwards" \
	|| bad "the mosh -u forward does not use \${PASST_FWD_PREFIX}; with COGBOX_PASST_BIND_FORWARDS it would bind every address"
mosh_src=$(sed -n '/^PASST_MOSH_ARGS=()$/,/^fi$/p' "$LAUNCH")
if [ -z "$mosh_src" ]; then
	bad "could not find the PASST_MOSH_ARGS construction in the launcher"
else
	# $1 = COGBOX_MOSH_UDP_FORWARD ("" = unset), $2 = PASST_FWD_PREFIX; prints
	# the resulting args one per line, exits with die's code on refusal
	run_mosh_block() {
		local fwd="$1" prefix="$2"
		( die() { echo "cogbox-launch: error: $*" >&2; exit "${2:-70}"; }
		  PASST_FWD_PREFIX="$prefix"
		  if [ -n "$fwd" ]; then export COGBOX_MOSH_UDP_FORWARD="$fwd"; else unset COGBOX_MOSH_UDP_FORWARD; fi
		  eval "$mosh_src"
		  printf '%s\n' "${PASST_MOSH_ARGS[@]+"${PASST_MOSH_ARGS[@]}"}" )
	}
	# unset: expands to NOTHING (the byte-identity guarantee for every
	# launch that does not set the knob)
	out=$(run_mosh_block "" "" 2>&1); rc=$?
	[ "$rc" = 0 ] && [ -z "$out" ] \
		&& ok "unset COGBOX_MOSH_UDP_FORWARD adds no passt argv" \
		|| bad "unset COGBOX_MOSH_UDP_FORWARD changed the argv (rc=$rc out='$out')"
	# set, no bind prefix: bare -u lo-hi
	out=$(run_mosh_block "60000-60031" "" 2>&1); rc=$?
	[ "$rc" = 0 ] && [ "$out" = "$(printf -- '-u\n60000-60031')" ] \
		&& ok "COGBOX_MOSH_UDP_FORWARD=60000-60031 renders -u 60000-60031" \
		|| bad "COGBOX_MOSH_UDP_FORWARD=60000-60031 rendered rc=$rc '$out'"
	# the bounds are inclusive: 1-65535 and a single port lo-lo render
	for goodv in 1-65535 60000-60000; do
		out=$(run_mosh_block "$goodv" "" 2>&1); rc=$?
		[ "$rc" = 0 ] && [ "$out" = "$(printf -- '-u\n%s' "$goodv")" ] \
			&& ok "COGBOX_MOSH_UDP_FORWARD=$goodv renders -u $goodv" \
			|| bad "COGBOX_MOSH_UDP_FORWARD=$goodv rendered rc=$rc '$out'"
	done
	# set, with the bind prefix: -u <bind>/lo-hi, the address-scoped passt form
	out=$(run_mosh_block "60000-60031" "10.0.0.5/" 2>&1); rc=$?
	[ "$rc" = 0 ] && [ "$out" = "$(printf -- '-u\n10.0.0.5/60000-60031')" ] \
		&& ok "the -u forward takes the bind prefix (-u 10.0.0.5/60000-60031)" \
		|| bad "the -u forward with a bind prefix rendered rc=$rc '$out'"
	# malformed spellings are refused with exit 64 and the usage text, never
	# handed to passt: the mosh-server colon form, a bare port, a stray letter,
	# a dangling or doubled dash; and well-formed ranges the shim's
	# parsePortRange would refuse (lo > hi, port 0, > 65535, > 5 digits), which
	# passt might otherwise accept while the reply exemption stayed OFF
	for badv in 60000:60031 60000 6000a-60031 -60031 60000- 1-2-3 60031-60000 0-5 1-70000 60000-000060031; do
		out=$(run_mosh_block "$badv" "" 2>&1); rc=$?
		if [ "$rc" = 64 ] && grep -qF 'must be <lo>-<hi>' <<<"$out"; then
			ok "COGBOX_MOSH_UDP_FORWARD='$badv' is refused with exit 64"
		else
			bad "COGBOX_MOSH_UDP_FORWARD='$badv' was not refused (rc=$rc out='$out')"
		fi
	done
fi

# --- 5b. guest DNS is FORWARDED to the host, never handed over raw ----------
#
# THE REGRESSION THIS SECTION EXISTS FOR. The guest must resolve what the HOST
# resolves, so an internal name resolves to its internal address -- parity with
# the local and k8s backends. That holds only if passt INTERCEPTS the guest's
# queries and re-emits them to a resolver on the host:
#
#   --dns-forward <addr>   the address the guest is told to use, which passt
#                          consumes at the tap. A handle, not a route.
#   --dns-host <addr>      where passt re-emits them: the host's own forwarder.
#
# `-D <addr>` is the shape that FAILS the property, and it fails it silently:
# passt applies -D before reading /etc/resolv.conf and then skips the read
# (conf.c get_dns()'s `dns4_set` short-circuit), so dns_host is left unspecified
# and no forwarding happens at all -- the guest is handed a raw address it must
# reach on its own, which on a host whose real resolver is fenced off means a
# PUBLIC resolver and no internal names. Static, because proving it at runtime
# needs a VM; here the spelling IS the mechanism, so checking the spelling is
# not a proxy for the behaviour.

dnsblock=$(sed -n '/^PASST_DNS_ARGS=()/,/^fi$/p' "$LAUNCH")
if [ -z "$dnsblock" ]; then
	bad "could not find the PASST_DNS_ARGS construction in the launcher"
else
	case "$dnsblock" in
		*'--dns-forward'*) ok "the guest resolver is advertised via --dns-forward, so passt intercepts the guest's queries" ;;
		*) bad "the guest resolver is not passed as --dns-forward; the guest would have to reach it itself: $dnsblock" ;;
	esac
	case "$dnsblock" in
		*'--dns-host'*) ok "the intercepted queries are re-emitted to the host's own forwarder (--dns-host)" ;;
		*) bad "no --dns-host: passt would have no pinned forwarding target and guest DNS would follow whatever resolv.conf named: $dnsblock" ;;
	esac
	case "$dnsblock" in
		*'--no-map-gw'*) ok "the gateway mapping stays closed (--no-map-gw travels with the resolver knob)" ;;
		*) bad "--no-map-gw is no longer applied with the guest resolver; passt's gateway->loopback mapping would reopen in both modes: $dnsblock" ;;
	esac
	# The refusal, stated as its own case: -D is the pre-fix spelling, and
	# re-adding it disarms passt's forwarding while changing nothing else that
	# any other assertion here can see.
	case "$dnsblock" in
		*' -D '*) bad "the launcher passes passt -D, which skips /etc/resolv.conf and leaves dns_host unspecified: guest DNS stops being forwarded to the host and reverts to a raw (public) resolver: $dnsblock" ;;
		*) ok "passt -D is not used, so get_dns() still runs and passt's own forwarding stays armed" ;;
	esac
	# And the whole thing stays behind the knob: an unset COGBOX_GUEST_RESOLVER
	# must add nothing, which is what keeps the local, k8s and container argv
	# byte-identical to what they ran before any of this existed.
	case "$dnsblock" in
		*'if [ -n "${COGBOX_GUEST_RESOLVER:-}" ]; then'*) ok "the whole DNS block is gated on COGBOX_GUEST_RESOLVER, so an unset knob adds no argv" ;;
		*) bad "the DNS args are not gated on COGBOX_GUEST_RESOLVER; a local or k8s launch would change argv: $dnsblock" ;;
	esac
fi

# --- 6. failure paths must not echo credential context ----------------------

CANARY="cogbox-canary-do-not-log"

# A canary check over a path that did not actually fail proves nothing, so
# each case also asserts the failure it is supposed to be exercising.
canary_free() {
	local tag="$1" log="$2" rc="$3" marker="$4"
	[ "$rc" != 0 ] || bad "$tag did not fail (exit 0) -- the canary check would be vacuous"
	grep -q "$marker" "$log" || bad "$tag did not take the expected error path ($marker)"
	if grep -q "$CANARY" "$log"; then
		bad "$tag leaked the canary: $(grep -n "$CANARY" "$log" | head -3)"
	else
		ok "$tag emits no line carrying the canary"
	fi
}

# (a) unexpected argument (exit 70)
home="$WORK/canary-a"; mkdir -p "$home"
HOME="$home" COGBOX_DATA="$home/data" XDG_CONFIG_HOME="$home/config" \
	COGBOX_NETRC_FILE="/nonexistent/$CANARY" \
	COGBOX_L7_INJECT_CONF="/nonexistent/$CANARY.json" \
	AUTH_TOKEN="$CANARY" \
	bash "$LAUNCH" --init-only --yes --bogus-flag x >"$WORK/canary-a.log" 2>&1
canary_free "unexpected-argument failure" "$WORK/canary-a.log" "$?" "unexpected argument"

# (b) launch against a corrupt config (exit 70 from the JSON gate)
home="$WORK/canary-b"; mkdir -p "$home/config/cogbox/instances/demo"
printf 'not json' > "$home/config/cogbox/instances/demo/config.json"
HOME="$home" COGBOX_DATA="$home/data" XDG_CONFIG_HOME="$home/config" \
	COGBOX_NETRC_FILE="/nonexistent/$CANARY" \
	AUTH_TOKEN="$CANARY" \
	bash "$LAUNCH" --yes --name demo >"$WORK/canary-b.log" 2>&1
canary_free "corrupt-config launch failure" "$WORK/canary-b.log" "$?" "invalid JSON"

# (c) unwritable home (the identity guard, exit 78)
HOME="/nonexistent-home-for-cogbox-test" \
	COGBOX_DATA="$WORK/canary-c/data" XDG_CONFIG_HOME="$WORK/canary-c/config" \
	COGBOX_NETRC_FILE="/nonexistent/$CANARY" \
	AUTH_TOKEN="$CANARY" \
	bash "$LAUNCH" --init-only --yes >"$WORK/canary-c.log" 2>&1
canary_free "unwritable-home failure" "$WORK/canary-c.log" "$?" "is not writable"

# --- 7. launch-only directory grants fail before runner/QEMU setup ----------

rc=$(run_init add-dir-reject --name demo --network rules)
[ "$rc" = 0 ] || bad "add-dir rejection fixture init exited $rc (log: $(cat "$WORK/add-dir-reject.log"))"
home="$WORK/add-dir-reject"
runner_probe="$WORK/runner-must-not-be-read"

check_add_dir_rejection() {
	local tag=$1 expected_rc=$2 marker=$3 rejected_path=$4 payload_canary=$5
	local log="$WORK/$tag.log"
	shift 5
	HOME="$home" COGBOX_DATA="$home/data" XDG_CONFIG_HOME="$home/config" \
		RUNNER_DIR="$runner_probe" \
		bash "$LAUNCH" --yes --name demo "$@" >"$log" 2>&1
	local rc=$?
	[ "$rc" = "$expected_rc" ] \
		|| bad "$tag exited $rc, expected $expected_rc (log: $(cat "$log"))"
	grep -Fq "$marker" "$log" \
		|| bad "$tag did not reach the intended diagnostic '$marker' (log: $(cat "$log"))"
	grep -Fq "$rejected_path" "$log" \
		|| bad "$tag diagnostic did not name the rejected path $rejected_path"
	if [ -n "$payload_canary" ] && grep -Fq "$payload_canary" "$log"; then
		bad "$tag echoed file contents instead of naming only $rejected_path"
	fi
	if grep -Fq "$runner_probe" "$log"; then
		bad "$tag reached the substituted runner path instead of rejecting before QEMU setup"
	fi
	ok "$tag rejects before runner/QEMU setup with exit $expected_rc"
}

missing="$home/does-not-exist-add-dir"
check_add_dir_rejection "missing additional directory" 66 \
	"missing or inaccessible" "$missing" "" \
	--add-dir "$missing"

regular="$home/not-a-directory-add-dir"
regular_canary="regular-file-payload-must-not-be-logged"
printf '%s' "$regular_canary" > "$regular"
check_add_dir_rejection "regular-file additional directory" 65 \
	"requires a directory" "$regular" "$regular_canary" \
	--add-dir-ro "$regular"

overlap="$home/data"
overlap_canary="overlap-payload-must-not-be-logged"
printf '%s' "$overlap_canary" > "$overlap/secret-payload"
check_add_dir_rejection "Cogbox-data overlap" 65 \
	"overlaps protected host path" "$overlap" "$overlap_canary" \
	--add-dir "$overlap"

# --- 5. the auth proxy's pid file is pre-created for the proxy uid -----------
#
# Under COGBOX_PROXY_RUNAS the auth proxy runs as a uid that cannot create
# files in $RUNTIME (root-owned 0755 on GCE), so the launcher pre-creates
# $RUNTIME/authproxy.pid EMPTY and chowns it to that uid; the Zig side then
# truncate-writes its pid into the existing inode. The function is extracted
# from the launcher and run here with a recording `chown` on PATH (the test is
# not root), so the contract is exercised rather than grepped for.
precreate_src=$(sed -n '/^precreate_authproxy_pidfile() {$/,/^}$/p' "$LAUNCH")
if [ -z "$precreate_src" ]; then
	bad "precreate_authproxy_pidfile() not found in the launcher (the extraction anchor moved?)"
else
	pc_bin="$WORK/pc-bin"
	mkdir -p "$pc_bin"
	# an absolute bash shebang: the nix build sandbox has no /usr/bin/env
	# (test_enforce.sh's shebang() idiom)
	{ printf '#!%s\n' "$(command -v bash)"; cat <<'STUB'
echo "chown $*" >> "$CHOWN_LOG"
STUB
	} > "$pc_bin/chown"
	chmod +x "$pc_bin/chown"
	run_precreate() {
		# $1 = COGBOX_PROXY_RUNAS value ("" = unset), $2 = runtime dir
		local runas="$1" rt="$2"
		( eval "$precreate_src"
		  RUNTIME="$rt"
		  if [ -n "$runas" ]; then export COGBOX_PROXY_RUNAS="$runas"; else unset COGBOX_PROXY_RUNAS; fi
		  PATH="$pc_bin:$PATH" CHOWN_LOG="$WORK/chown.log" precreate_authproxy_pidfile )
	}
	pc_rt="$WORK/pc-rt"
	mkdir -p "$pc_rt"
	: > "$WORK/chown.log"
	# under a runas uid: the file exists, is EMPTY, mode 0644, and was chowned
	# to exactly the uid:gid the proxy will run as
	run_precreate "1234:1234" "$pc_rt"
	if [ -f "$pc_rt/authproxy.pid" ] && [ ! -s "$pc_rt/authproxy.pid" ]; then
		ok "precreate under COGBOX_PROXY_RUNAS leaves an EMPTY pid file (health is non-empty, not existence)"
	else
		bad "precreate under COGBOX_PROXY_RUNAS did not leave an empty pid file"
	fi
	[ "$(stat -c %a "$pc_rt/authproxy.pid")" = 644 ] \
		|| bad "pre-created pid file mode is $(stat -c %a "$pc_rt/authproxy.pid"), expected 644"
	grep -Fqx "chown 1234:1234 $pc_rt/authproxy.pid" "$WORK/chown.log" \
		|| bad "pre-created pid file was not chowned to the proxy uid:gid (log: $(cat "$WORK/chown.log"))"
	# a stale pid from a previous launch is truncated away, never inherited
	echo 99999 > "$pc_rt/authproxy.pid"
	run_precreate "1234:1234" "$pc_rt"
	[ ! -s "$pc_rt/authproxy.pid" ] \
		|| bad "precreate did not truncate a stale pid file"
	# no runas: the launching user owns the file already; no chown at all
	: > "$WORK/chown.log"
	run_precreate "" "$pc_rt"
	[ ! -s "$WORK/chown.log" ] || bad "precreate chowned without COGBOX_PROXY_RUNAS (log: $(cat "$WORK/chown.log"))"
	[ -f "$pc_rt/authproxy.pid" ] && [ ! -s "$pc_rt/authproxy.pid" ] \
		|| bad "precreate without COGBOX_PROXY_RUNAS did not leave an empty pid file"
	ok "precreate without COGBOX_PROXY_RUNAS pre-creates without chown"
	# an unwritable runtime dir warns and returns 0: warn-not-die, like the
	# rest of start_l7auth
	pc_out=$(run_precreate "1234:1234" "$WORK/no-such-runtime-dir" 2>&1); pc_rc=$?
	[ "$pc_rc" = 0 ] || bad "precreate exited $pc_rc on an unwritable runtime dir (must warn, never fail the launch)"
	grep -Fq "cannot pre-create" <<<"$pc_out" \
		|| bad "precreate did not warn on an unwritable runtime dir (out: $pc_out)"
	ok "precreate on an unwritable runtime dir warns and continues"
fi

# --- 8. harness hosts are withheld from l7-inject-hosts after the merge ------
#
# The L7 proxy routes a host's PLAIN-HTTP egress to the injecting addon when
# the host is listed in l7-inject-hosts, and the addon resolves a host to the
# LAST conf element naming it -- after the launcher's merge, the HARNESS spec
# (the real host-side OAuth token). A rendered spec that names a harness host
# (a plugin's, the claude seed's, an operator `secret add --inject` bind's)
# lists it, so the launcher must strip it back out or a guest-forced
# http://api.anthropic.com/... gets the harness token stamped on a cleartext
# leg. Extracted and driven like the mosh block: the merge runs after
# __render-rules, which --init-only never reaches.
withhold_src=$(sed -n '/^withhold_harness_inject_hosts() {$/,/^}$/p' "$LAUNCH")
if [ -z "$withhold_src" ]; then
	bad "withhold_harness_inject_hosts() not found in the launcher (the extraction anchor moved?)"
else
	# $1 = the harness conf JSON, $2 = the l7-inject-hosts body to start from
	# ("-" = no file at all). Leaves the result in $wh_rt/l7-inject-hosts and
	# the function's stderr in $WORK/withhold.log.
	wh_rt="$WORK/withhold-rt"
	run_withhold() {
		local conf="$1" body="$2"
		rm -rf "$wh_rt"; mkdir -p "$wh_rt"
		[ "$body" = "-" ] || printf '%s' "$body" > "$wh_rt/l7-inject-hosts"
		( eval "$withhold_src"
		  RUNTIME="$wh_rt"
		  withhold_harness_inject_hosts "$conf" ) 2>"$WORK/withhold.log"
	}
	same_bytes() { [ "$(cksum < "$1")" = "$(printf '%s' "$2" | cksum)" ]; }
	HARNESS_CANARY="sk-ant-oat01-cogbox-test-canary-never-logged"
	harness_conf='[{"host":"api.anthropic.com","style":"anthropic-oauth","cred_file":"/home/testuser/.claude/.credentials.json","token_path":"claudeAiOauth.accessToken","stub_token":"'"$HARNESS_CANARY"'"},{"host":"chatgpt.com","style":"openai-chatgpt","cred_file":"/home/testuser/.codex/auth.json","token_path":"tokens.access_token"}]'

	# (a) rendered specs listed both harness hosts (one in another case, as an
	# operator's --audience may spell it): both leave, the ordinary host stays,
	# and the warning names the withheld hosts and nothing else from the conf
	run_withhold "$harness_conf" $'API.Anthropic.com\napi.example.com\nchatgpt.com\n'
	same_bytes "$wh_rt/l7-inject-hosts" $'api.example.com\n' \
		&& ok "harness hosts are stripped from l7-inject-hosts (case-insensitively); the ordinary host stays" \
		|| bad "l7-inject-hosts after the strip: '$(cat "$wh_rt/l7-inject-hosts")' (expected api.example.com only)"
	if grep -q "withholding plain-HTTP inject-routing" "$WORK/withhold.log" \
		&& grep -q "API.Anthropic.com" "$WORK/withhold.log" && grep -q "chatgpt.com" "$WORK/withhold.log"; then
		ok "the strip warns, naming the withheld hosts"
	else
		bad "the strip did not warn with the withheld hosts (log: $(cat "$WORK/withhold.log"))"
	fi
	if grep -q "$HARNESS_CANARY\|credentials.json\|auth.json" "$WORK/withhold.log"; then
		bad "the strip's warning echoed conf content beyond the hosts: $(cat "$WORK/withhold.log")"
	else
		ok "the strip's warning carries hosts only (no cred_file path, no stub)"
	fi

	# (b) every listed host is a harness host: an EMPTY list is published (a
	# valid file the proxy parses to "route nothing"), not a missing one
	run_withhold "$harness_conf" $'api.anthropic.com\n'
	[ -f "$wh_rt/l7-inject-hosts" ] && [ ! -s "$wh_rt/l7-inject-hosts" ] \
		&& ok "a list of only harness hosts becomes an empty file" \
		|| bad "a list of only harness hosts did not become an empty file: '$(cat "$wh_rt/l7-inject-hosts" 2>&1)'"

	# (c) no harness host listed -- the steady state under a control plane,
	# where the render names none: byte-identical, nothing logged
	run_withhold "$harness_conf" $'api.example.com\napp.example.com\n'
	same_bytes "$wh_rt/l7-inject-hosts" $'api.example.com\napp.example.com\n' && [ ! -s "$WORK/withhold.log" ] \
		&& ok "a list with no harness host is untouched and nothing is logged" \
		|| bad "a harness-free list was rewritten or warned about (file: '$(cat "$wh_rt/l7-inject-hosts")', log: $(cat "$WORK/withhold.log"))"

	# (d) no harness half at all (`[]`: nobody logged in host-side, which is
	# every cogworx VM): untouched, so a rendered api.anthropic.com -- then the
	# ONLY spec for the host -- keeps routing exactly as before
	run_withhold '[]' $'api.anthropic.com\n'
	same_bytes "$wh_rt/l7-inject-hosts" $'api.anthropic.com\n' && [ ! -s "$WORK/withhold.log" ] \
		&& ok "an empty harness conf leaves the list alone" \
		|| bad "an empty harness conf rewrote the list (file: '$(cat "$wh_rt/l7-inject-hosts")', log: $(cat "$WORK/withhold.log"))"

	# (e) a harness conf jq cannot read: the merge failed the same way, so no
	# harness spec landed and there is nothing to strip
	run_withhold 'not json' $'api.anthropic.com\n'
	same_bytes "$wh_rt/l7-inject-hosts" $'api.anthropic.com\n' && [ ! -s "$WORK/withhold.log" ] \
		&& ok "an unparseable harness conf strips nothing (no merge happened either)" \
		|| bad "an unparseable harness conf rewrote the list (file: '$(cat "$wh_rt/l7-inject-hosts")', log: $(cat "$WORK/withhold.log"))"

	# (f) the list itself cannot be read: fail CLOSED to an empty one, loudly
	run_withhold "$harness_conf" -
	if [ -f "$wh_rt/l7-inject-hosts" ] && [ ! -s "$wh_rt/l7-inject-hosts" ] && grep -q "cannot read" "$WORK/withhold.log"; then
		ok "an unreadable l7-inject-hosts is replaced by an empty one, with a warning"
	else
		bad "an unreadable l7-inject-hosts was not failed closed (file: $(cat "$wh_rt/l7-inject-hosts" 2>&1), log: $(cat "$WORK/withhold.log"))"
	fi

	# (g) the call site: exactly one, inside the merge's SUCCESS branch (only a
	# merge that landed put a harness spec in the conf) and right after the
	# conf is published
	call_ln=$(grep -n 'withhold_harness_inject_hosts "\$_harness_conf"' "$LAUNCH" | cut -d: -f1)
	mv_ln=$(grep -n 'mv "\$RUNTIME/l7-inject-conf.json.tmp" "\$RUNTIME/l7-inject-conf.json"$' "$LAUNCH" | cut -d: -f1)
	if [ "$(printf '%s\n' "$call_ln" | grep -c .)" = 1 ] && [ "$(printf '%s\n' "$mv_ln" | grep -c .)" = 1 ] \
		&& [ "$call_ln" -gt "$mv_ln" ] && [ $((call_ln - mv_ln)) -le 20 ] \
		&& ! grep -q '^\s*else$\|^\s*fi$' <(sed -n "${mv_ln},${call_ln}p" "$LAUNCH"); then
		ok "the strip runs once, in the merge's success branch, after the conf is published"
	else
		bad "the strip's call site moved (mv at '$mv_ln', call at '$call_ln')"
	fi
fi

# --- 9. the plugin composition re-pin is gated, per-input, and confirmed ----
# The launcher re-pins a STALE path: input of the plugin composition before its
# fast path (plain `nix flake lock` keeps a changed path: input's old narHash).
# Driven through the real --init-only flow with a stub `nix` on PATH: `hash
# path` answers from a fixture file in the tree, `flake update` re-pins from
# the same file (all-or-nothing per call, like nix), `build` is the pre-exec
# confirmation, `run` is the re-exec. Pins: only stale inputs are named (a
# current one never floats), a tree that disagrees with config.json keeps its
# pin, one failing input does not block the others, and a re-pinned
# composition that fails to build is rolled back to the last lock that booted.
rp_stub="$WORK/rp-stub"
mkdir -p "$rp_stub"
# (No /usr/bin/env in the nix build sandbox: the shebang names this bash.)
{ echo "#!$(command -v bash)"; cat <<'STUB_EOF'
cmd=()
while [ $# -gt 0 ]; do
	case "$1" in
		--extra-experimental-features) shift 2 ;;
		--option) shift 3 ;;
		*) cmd+=("$1"); shift ;;
	esac
done
echo "${cmd[*]}" >> "$RP_LOG"
case "${cmd[0]}" in
	hash) cat "${cmd[2]}/.stubhash" 2>/dev/null || exit 1 ;;
	flake)
		lock="${cmd[${#cmd[@]}-1]#path:}/flake.lock"
		names=()
		for n in "${cmd[@]:2}"; do [ "$n" = --flake ] && break; names+=("$n"); done
		# A fetch that stalls (blackholed egress) before it fails.
		[ -z "${RP_UPDATE_SLEEP:-}" ] || sleep "$RP_UPDATE_SLEEP"
		[ -z "${RP_UPDATE_RC:-}" ] || exit "$RP_UPDATE_RC"
		for n in "${names[@]}"; do [ "$n" = "${RP_UPDATE_FAIL:-}" ] && exit 1; done
		for n in "${names[@]}"; do
			src=$(jq -r --arg k "$n" '.nodes[.nodes.root.inputs[$k]].locked.path' "$lock")
			h=$(cat "$src/.stubhash")
			jq --arg k "$n" --arg h "$h" '.nodes[.nodes.root.inputs[$k]].locked.narHash = $h' "$lock" > "$lock.t" && mv "$lock.t" "$lock"
		done ;;
	build)
		# Is the instance config lock free while the confirmation builds?
		[ -z "${RP_LOCKFILE:-}" ] || { flock -n "$RP_LOCKFILE" true && echo "config-lock-free" >> "$RP_LOG"; }
		# A `cogbox plugin` op moving the lock while the build runs.
		[ -z "${RP_BUILD_OP:-}" ] || echo '{"op":"moved"}' > "$RP_BUILD_OP"
		# The launcher killed mid-confirmation (Stop while Booting, preemption).
		[ -z "${RP_BUILD_KILL:-}" ] || kill -KILL "$PPID"
		exit "${RP_BUILD_RC:-0}" ;;
	*) exit 0 ;;
esac
STUB_EOF
} > "$rp_stub/nix"
chmod +x "$rp_stub/nix"

# rp_setup TAG LOCK_A LOCK_B: a fresh instance with plugins a and b recorded at
# sha256-A2 / sha256-B1, their trees hashing to sha256-A2 / sha256-B1, and the
# composition lock pinning a at LOCK_A and b at LOCK_B (user current).
rp_setup() {
	local tag="$1" la="$2" lb="$3"
	rc=$(run_init "$tag" --name demo)
	[ "$rc" = 0 ] || { bad "re-pin fixture init ($tag) exited $rc"; return 1; }
	icd="$WORK/$tag/config/cogbox/instances/demo"
	mkdir -p "$icd/plugin-sources/a" "$icd/plugin-sources/b" "$icd/plugins-flake"
	printf 'sha256-A2' > "$icd/plugin-sources/a/.stubhash"
	printf 'sha256-B1' > "$icd/plugin-sources/b/.stubhash"
	printf 'sha256-U1' > "$icd/flake/.stubhash"
	jq '.plugins = [{"name":"a","narHash":"sha256-A2"},{"name":"b","narHash":"sha256-B1"}]' "$icd/config.json" > "$icd/c.t" && mv "$icd/c.t" "$icd/config.json"
	echo '{}' > "$icd/plugins-flake/flake.nix"
	jq -n --arg d "$icd" --arg la "$la" --arg lb "$lb" '{nodes:{
		"p-a":{locked:{narHash:$la,path:"\($d)/plugin-sources/a",type:"path"},original:{path:"\($d)/plugin-sources/a",type:"path"}},
		"p-b":{locked:{narHash:$lb,path:"\($d)/plugin-sources/b",type:"path"},original:{path:"\($d)/plugin-sources/b",type:"path"}},
		user:{locked:{narHash:"sha256-U1",path:"\($d)/flake",type:"path"},original:{path:"\($d)/flake",type:"path"}},
		root:{inputs:{"p-a":"p-a","p-b":"p-b",user:"user"}}},root:"root",version:7}' > "$icd/plugins-flake/flake.lock"
	cp "$icd/plugins-flake/flake.lock" "$WORK/$tag.lock0"
	printf 'stale-key\n/nix/store/x-runner\n' > "$icd/runner.path"
	: > "$WORK/$tag.nix.log"
}
rp_run() {
	local tag="$1"
	HOME="$WORK/$tag" COGBOX_DATA="$WORK/$tag/data" XDG_CONFIG_HOME="$WORK/$tag/config" \
	PATH="$rp_stub:$PATH" RP_LOG="$WORK/$tag.nix.log" \
		bash "$LAUNCH" --init-only --yes --name demo >"$WORK/$tag.log" 2>&1
}
rp_pin() { jq -r --arg k "$2" '.nodes[.nodes.root.inputs[$k]].locked.narHash' "$WORK/$1/config/cogbox/instances/demo/plugins-flake/flake.lock"; }

# (a) one stale plugin whose tree is the recorded pin: ONLY it is updated, the
# composition is built before exec, and the stale runner record is dropped
if rp_setup rp-stale sha256-A1 sha256-B1; then
	rp_run rp-stale
	upd=$(grep '^flake update' "$WORK/rp-stale.nix.log")
	if [ "$upd" = "flake update p-a --flake path:$icd/plugins-flake" ] \
		&& [ "$(rp_pin rp-stale p-a)" = sha256-A2 ] && [ "$(rp_pin rp-stale p-b)" = sha256-B1 ] \
		&& grep -q '^build --no-link' "$WORK/rp-stale.nix.log" && [ ! -e "$icd/runner.path" ] \
		&& grep -q 're-pinned plugin composition lock' "$WORK/rp-stale.log"; then
		ok "a stale plugin input alone is re-pinned, confirmed by a build, and the runner record dropped"
	else
		bad "stale re-pin (updates: '$upd', p-a=$(rp_pin rp-stale p-a), log: $(cat "$WORK/rp-stale.log"))"
	fi
fi

# (b) nothing stale: no update, no build, the lock and runner record untouched
if rp_setup rp-current sha256-A2 sha256-B1; then
	rp_run rp-current
	if ! grep -q '^flake update\|^build' "$WORK/rp-current.nix.log" \
		&& cmp -s "$WORK/rp-current.lock0" "$icd/plugins-flake/flake.lock" && [ -e "$icd/runner.path" ]; then
		ok "a current composition is not re-pinned or rebuilt (no transitive float, no fetch)"
	else
		bad "current composition was touched (nix calls: $(cat "$WORK/rp-current.nix.log"))"
	fi
fi

# (c) a stale plugin whose tree is NOT the recorded pin keeps its old pin
if rp_setup rp-diverge sha256-A1 sha256-B1; then
	printf 'sha256-PARTIAL' > "$icd/plugin-sources/a/.stubhash"
	rp_run rp-diverge
	if ! grep -q '^flake update' "$WORK/rp-diverge.nix.log" \
		&& cmp -s "$WORK/rp-diverge.lock0" "$icd/plugins-flake/flake.lock" \
		&& grep -q 'p-a: on-disk source does not match the pin config.json records' "$WORK/rp-diverge.log"; then
		ok "a plugin tree that disagrees with config.json keeps its locked pin, with a warning"
	else
		bad "diverged tree was re-pinned (nix calls: $(cat "$WORK/rp-diverge.nix.log"), log: $(cat "$WORK/rp-diverge.log"))"
	fi
fi

# (d) the batched update fails on one input: the others still re-pin
if rp_setup rp-onefail sha256-A1 sha256-B0; then
	RP_UPDATE_FAIL=p-b rp_run rp-onefail
	if [ "$(rp_pin rp-onefail p-a)" = sha256-A2 ] && [ "$(rp_pin rp-onefail p-b)" = sha256-B0 ] \
		&& grep -q 'could not re-pin plugin composition input(s) p-b' "$WORK/rp-onefail.log"; then
		ok "one input failing its re-pin does not block the others (per-input retry)"
	else
		bad "per-input retry (p-a=$(rp_pin rp-onefail p-a) p-b=$(rp_pin rp-onefail p-b), log: $(cat "$WORK/rp-onefail.log"))"
	fi
fi

# (e) the re-pinned composition fails to build: roll back to the booted lock.
# The boot's own snapshot is restored, so runner.path -- which names the runner
# that booted under exactly that lock -- is KEPT: it is the one fast path that
# still boots if GC has since collected the old sources.
if rp_setup rp-buildfail sha256-A1 sha256-B1; then
	RP_BUILD_RC=1 rp_run rp-buildfail
	if cmp -s "$WORK/rp-buildfail.lock0" "$icd/plugins-flake/flake.lock" \
		&& grep -q 'failed to build; restored the previous lock' "$WORK/rp-buildfail.log" \
		&& [ -e "$icd/runner.path" ] && [ ! -e "$icd/composition.lock.prev" ] \
		&& [ ! -e "$icd/composition.lock.prev.boot" ]; then
		ok "a re-pinned composition that fails to build is rolled back, keeping the booted runner record"
	else
		bad "build-failure rollback (p-a=$(rp_pin rp-buildfail p-a), runner.path: $(ls "$icd"), log: $(cat "$WORK/rp-buildfail.log"))"
	fi
fi

# (e2) a launcher killed between the re-pin and its confirmation leaves the
# snapshot behind, so the NEXT boot still confirms (and drops the runner record
# of the old lock) instead of fast-pathing the old runner forever
if rp_setup rp-killed sha256-A1 sha256-B1; then
	RP_BUILD_KILL=1 rp_run rp-killed
	if [ "$(rp_pin rp-killed p-a)" = sha256-A2 ] && cmp -s "$WORK/rp-killed.lock0" "$icd/composition.lock.prev" \
		&& [ -e "$icd/composition.lock.prev.boot" ] && [ -e "$icd/runner.path" ] \
		&& [ -z "$(ls "$icd" | grep 'flake.lock.repin\|flake.lock.restore')" ]; then
		: > "$WORK/rp-killed.nix.log"
		rp_run rp-killed
		if ! grep -q '^flake update' "$WORK/rp-killed.nix.log" && grep -q '^build --no-link' "$WORK/rp-killed.nix.log" \
			&& [ ! -e "$icd/runner.path" ] && [ ! -e "$icd/composition.lock.prev" ] \
			&& [ "$(rp_pin rp-killed p-a)" = sha256-A2 ]; then
			ok "a boot killed mid-confirmation leaves the snapshot, and the next boot confirms and drops runner.path"
		else
			bad "post-kill boot (nix calls: $(cat "$WORK/rp-killed.nix.log"), files: $(ls "$icd"))"
		fi
	else
		bad "killed confirmation state (p-a=$(rp_pin rp-killed p-a), files: $(ls "$icd"))"
	fi
fi

# (e3) the confirmation build runs WITHOUT the config lock (a long build must
# not block `cogbox plugin` verbs into the control plane's install budget), and
# a lock an op moved during it is left to that op: no restore, no cleanup
if rp_setup rp-unlocked sha256-A1 sha256-B1; then
	RP_BUILD_RC=1 RP_LOCKFILE="$WORK/rp-unlocked/config/cogbox/.locks/demo.lock" \
		RP_BUILD_OP="$icd/plugins-flake/flake.lock" rp_run rp-unlocked
	if grep -q '^config-lock-free' "$WORK/rp-unlocked.nix.log" \
		&& [ "$(cat "$icd/plugins-flake/flake.lock")" = '{"op":"moved"}' ] \
		&& [ -e "$icd/composition.lock.prev" ] \
		&& grep -q 'changed during its confirmation build' "$WORK/rp-unlocked.log"; then
		ok "the confirmation build runs unlocked and never clobbers a lock an op moved meanwhile"
	else
		bad "unlocked confirmation (nix calls: $(cat "$WORK/rp-unlocked.nix.log"), lock: $(cat "$icd/plugins-flake/flake.lock"), log: $(cat "$WORK/rp-unlocked.log"))"
	fi
fi

# (e4) a batched re-pin that TIMED OUT skips the per-input retries (the network
# is the problem, not one input), and the boot's unused snapshot is dropped
if rp_setup rp-timeout sha256-A1 sha256-B0; then
	printf 'sha256-B0x' > "$icd/plugin-sources/b/.stubhash"
	jq '.plugins[1].narHash = "sha256-B0x"' "$icd/config.json" > "$icd/c.t" && mv "$icd/c.t" "$icd/config.json"
	RP_UPDATE_RC=124 rp_run rp-timeout
	if [ "$(grep -c '^flake update' "$WORK/rp-timeout.nix.log")" = 1 ] \
		&& grep -q 'could not re-pin plugin composition input(s) p-a p-b (timed out' "$WORK/rp-timeout.log" \
		&& cmp -s "$WORK/rp-timeout.lock0" "$icd/plugins-flake/flake.lock" \
		&& [ ! -e "$icd/composition.lock.prev" ] && ! grep -q '^build' "$WORK/rp-timeout.nix.log"; then
		ok "a timed-out batched re-pin skips the per-input retries"
	else
		bad "timed-out re-pin (nix calls: $(cat "$WORK/rp-timeout.nix.log"), log: $(cat "$WORK/rp-timeout.log"))"
	fi
fi

# (e5) a failed confirmation is STICKY: `cogbox start` runs the launcher twice
# (--init-only, then the daemon, which must reach QEMU within 60s) and every
# boot runs it again, so the next pass must NOT re-pin the same content and
# repeat the failing full eval -- it boots the restored lock's runner on the
# fast path. An image change (RUNNER_KEY), new content, or the record's removal
# (every `cogbox plugin` op) retries.
rp_rkey=$(sed -n 's/^RUNNER_KEY="\(.*\)"$/\1/p' "$LAUNCH")
# The comp the launcher hashes (cogbox-launch.sh comp_of_dir; Zig
# snapshot.compOfBytes): sha256(flake.nix || NUL || flake.lock), lowercase hex.
# A missing flake.lock hashes as empty.
comp_of() { { cat "$1/flake.nix"; printf '\0'; [ ! -e "$1/flake.lock" ] || cat "$1/flake.lock"; } | sha256sum | cut -d' ' -f1; }
# A fast-path record is three lines, the third the comp of the composition the
# runner was built from: a record for the bytes on disk now.
rp_fastpath() {
	mkdir -p "$WORK/$1/fake-runner/bin" && : > "$WORK/$1/fake-runner/bin/microvm-run"
	printf '%s\n%s\n%s\n' "$rp_rkey" "$WORK/$1/fake-runner" "$(comp_of "$icd/plugins-flake")" > "$icd/runner.path"
}
if rp_setup rp-sticky sha256-A1 sha256-B1; then
	rp_fastpath rp-sticky
	RP_BUILD_RC=1 rp_run rp-sticky
	if cmp -s "$WORK/rp-sticky.lock0" "$icd/plugins-flake/flake.lock" && [ -e "$icd/runner.path" ] \
		&& [ "$(cat "$icd/composition.repin.failed")" = "$rp_rkey"$'\n'"p-a"$'\t'"sha256-A2" ]; then
		: > "$WORK/rp-sticky.nix.log"
		RP_BUILD_RC=1 rp_run rp-sticky
		if ! grep -q '^flake update\|^build\|^run' "$WORK/rp-sticky.nix.log" \
			&& cmp -s "$WORK/rp-sticky.lock0" "$icd/plugins-flake/flake.lock" \
			&& [ ! -e "$icd/composition.lock.prev" ] && [ -e "$icd/composition.repin.failed" ] \
			&& grep -q 'p-a: its current content failed the plugin composition.s confirmation build' "$WORK/rp-sticky.log"; then
			ok "a failed confirmation is not repeated by the next launcher pass, which fast-paths the restored lock"
		else
			bad "second pass after a failed confirmation (nix calls: $(cat "$WORK/rp-sticky.nix.log"), files: $(ls "$icd"), log: $(cat "$WORK/rp-sticky.log"))"
		fi
		# Another image: the verdict is dropped and the re-pin retried.
		printf 'other-image-key\np-a\tsha256-A2\n' > "$icd/composition.repin.failed"
		: > "$WORK/rp-sticky.nix.log"
		rp_run rp-sticky
		if grep -q '^flake update p-a' "$WORK/rp-sticky.nix.log" && grep -q '^build --no-link' "$WORK/rp-sticky.nix.log" \
			&& [ "$(rp_pin rp-sticky p-a)" = sha256-A2 ] && [ ! -e "$icd/composition.repin.failed" ]; then
			ok "a failure recorded under another image is retried, and a successful confirmation drops the record"
		else
			bad "image-change retry (nix calls: $(cat "$WORK/rp-sticky.nix.log"), files: $(ls "$icd"))"
		fi
	else
		bad "failed confirmation record (lock p-a=$(rp_pin rp-sticky p-a), record: $(cat "$icd/composition.repin.failed" 2>&1), log: $(cat "$WORK/rp-sticky.log"))"
	fi
fi
# ... new content for the same plugin (an op re-copied it) is retried, while a
# still-failed sibling stays skipped and keeps the record alive
if rp_setup rp-sticky-new sha256-A1 sha256-B0; then
	printf '%s\np-a\tsha256-A2\np-b\tsha256-B1\n' "$rp_rkey" > "$icd/composition.repin.failed"
	printf 'sha256-A3' > "$icd/plugin-sources/a/.stubhash"
	jq '.plugins[0].narHash = "sha256-A3"' "$icd/config.json" > "$icd/c.t" && mv "$icd/c.t" "$icd/config.json"
	rp_run rp-sticky-new
	if [ "$(grep '^flake update' "$WORK/rp-sticky-new.nix.log")" = "flake update p-a --flake path:$icd/plugins-flake" ] \
		&& [ "$(rp_pin rp-sticky-new p-a)" = sha256-A3 ] && [ "$(rp_pin rp-sticky-new p-b)" = sha256-B0 ] \
		&& [ -e "$icd/composition.repin.failed" ] && grep -q 'p-b: its current content failed' "$WORK/rp-sticky-new.log"; then
		ok "new content is re-pinned despite an old failure record; a still-failed sibling stays skipped"
	else
		bad "new-content retry (nix calls: $(cat "$WORK/rp-sticky-new.nix.log"), log: $(cat "$WORK/rp-sticky-new.log"))"
	fi
fi
# ... and an op's snapshot that fails to confirm is sticky too: the restored
# lock's stale input is not re-pinned straight back to the content that failed
if rp_setup rp-sticky-op sha256-A2 sha256-B1; then
	jq '.nodes["p-a"].locked.narHash = "sha256-A1"' "$icd/plugins-flake/flake.lock" > "$icd/composition.lock.prev"
	RP_BUILD_RC=1 rp_run rp-sticky-op
	: > "$WORK/rp-sticky-op.nix.log"
	rp_run rp-sticky-op
	if [ "$(rp_pin rp-sticky-op p-a)" = sha256-A1 ] && ! grep -q '^flake update\|^build' "$WORK/rp-sticky-op.nix.log" \
		&& grep -q 'p-a: its current content failed' "$WORK/rp-sticky-op.log"; then
		ok "an op's re-pin that failed to confirm is not re-pinned again by the next launch"
	else
		bad "op snapshot stickiness (p-a=$(rp_pin rp-sticky-op p-a), nix calls: $(cat "$WORK/rp-sticky-op.nix.log"), log: $(cat "$WORK/rp-sticky-op.log"))"
	fi
fi

# (e6) `cogbox start`'s daemon pass (COGBOX_SKIP_REPIN=1) never re-pins or
# confirms: it must own a live QEMU within start's 60s, so it fast-paths the
# lock the init pass left. Init pass: the re-pin fetch fails and leaves the lock
# alone; daemon pass, with a `flake update` that would now stall for 200s:
# no hash, no update, no build, no re-exec, done in seconds. The failure is not
# recorded, so the NEXT start's init pass retries it.
if rp_setup rp-skip sha256-A1 sha256-B1; then
	rp_fastpath rp-skip
	RP_UPDATE_RC=1 rp_run rp-skip
	if grep -q '^flake update p-a' "$WORK/rp-skip.nix.log" && cmp -s "$WORK/rp-skip.lock0" "$icd/plugins-flake/flake.lock" \
		&& [ ! -e "$icd/composition.lock.prev" ] && [ ! -e "$icd/composition.repin.failed" ]; then
		: > "$WORK/rp-skip.nix.log"
		rp_t0=$SECONDS
		COGBOX_SKIP_REPIN=1 RP_UPDATE_SLEEP=200 rp_run rp-skip
		rp_dt=$((SECONDS - rp_t0))
		if [ "$rp_dt" -lt 30 ] && ! grep -q '^hash\|^flake update\|^build\|^run' "$WORK/rp-skip.nix.log" \
			&& cmp -s "$WORK/rp-skip.lock0" "$icd/plugins-flake/flake.lock" && [ -e "$icd/runner.path" ] \
			&& grep -q 'daemon pass: leaving the plugin composition re-pin to the init pass' "$WORK/rp-skip.log"; then
			ok "the daemon pass makes no re-pin (no flake update, no stall) and fast-paths the lock the init pass left"
		else
			bad "daemon pass after a failed re-pin (${rp_dt}s, nix calls: $(cat "$WORK/rp-skip.nix.log"), log: $(cat "$WORK/rp-skip.log"))"
		fi
		: > "$WORK/rp-skip.nix.log"
		rp_run rp-skip
		if grep -q '^flake update p-a' "$WORK/rp-skip.nix.log" && [ "$(rp_pin rp-skip p-a)" = sha256-A2 ]; then
			ok "a failed re-pin fetch is retried by the next start's init pass (not recorded as sticky)"
		else
			bad "re-pin retry on the next start (nix calls: $(cat "$WORK/rp-skip.nix.log"))"
		fi
	else
		bad "init pass with a failing re-pin fetch (nix calls: $(cat "$WORK/rp-skip.nix.log"), files: $(ls "$icd"))"
	fi
fi
# ... and an op's unconfirmed snapshot (or one an init pass left when an op
# moved the lock mid-confirmation) costs the daemon no confirmation eval: the
# snapshot is left for the next init pass.
if rp_setup rp-skip-prev sha256-A2 sha256-B1; then
	rp_fastpath rp-skip-prev
	echo '{"stale":"snapshot"}' > "$icd/composition.lock.prev"
	COGBOX_SKIP_REPIN=1 rp_run rp-skip-prev
	if ! grep -q '^build\|^run' "$WORK/rp-skip-prev.nix.log" && [ -e "$icd/composition.lock.prev" ] \
		&& cmp -s "$WORK/rp-skip-prev.lock0" "$icd/plugins-flake/flake.lock"; then
		ok "the daemon pass leaves an unconfirmed snapshot unbuilt and fast-paths"
	else
		bad "daemon pass with a snapshot (nix calls: $(cat "$WORK/rp-skip-prev.nix.log"))"
	fi
fi
# A `nix hash path` that times out is "could not hash": the locked narHash is
# kept and nothing is re-pinned. (A `timeout` shim stands in for the 60s cap.)
if rp_setup rp-hash-timeout sha256-A1 sha256-B1; then
	mkdir -p "$WORK/rp-hash-timeout/bin"
	{ echo "#!$(command -v bash)"; cat <<'SHIM_EOF'
for a in "$@"; do [ "$a" = hash ] && { echo "hash-capped $*" >> "$RP_LOG"; exit 124; }; done
exec REALTIMEOUT "$@"
SHIM_EOF
	} | sed "s|REALTIMEOUT|$(command -v timeout)|" > "$WORK/rp-hash-timeout/bin/timeout"
	chmod +x "$WORK/rp-hash-timeout/bin/timeout"
	PATH="$WORK/rp-hash-timeout/bin:$PATH" rp_run rp-hash-timeout
	if grep -q '^hash-capped -k 5 60 nix .* hash path' "$WORK/rp-hash-timeout.nix.log" \
		&& ! grep -q '^flake update\|^build' "$WORK/rp-hash-timeout.nix.log" \
		&& cmp -s "$WORK/rp-hash-timeout.lock0" "$icd/plugins-flake/flake.lock" \
		&& grep -q 'p-a: could not hash its source (timed out); keeping its locked narHash' "$WORK/rp-hash-timeout.log"; then
		ok "a timed-out nix hash path keeps the locked narHash (no re-pin)"
	else
		bad "hash timeout (nix calls: $(cat "$WORK/rp-hash-timeout.nix.log"), log: $(cat "$WORK/rp-hash-timeout.log"))"
	fi
fi

# (f) an op left composition.lock.prev (unconfirmed re-pin): confirmed by a
# successful build, rolled back to the snapshot by a failed one
if rp_setup rp-prev-ok sha256-A2 sha256-B1; then
	echo '{"stale":"snapshot"}' > "$icd/composition.lock.prev"
	rp_run rp-prev-ok
	if grep -q '^build --no-link' "$WORK/rp-prev-ok.nix.log" && [ ! -e "$icd/composition.lock.prev" ] \
		&& cmp -s "$WORK/rp-prev-ok.lock0" "$icd/plugins-flake/flake.lock"; then
		ok "an op's unconfirmed re-pin is confirmed by a successful pre-exec build"
	else
		bad "prev confirm (nix calls: $(cat "$WORK/rp-prev-ok.nix.log"))"
	fi
fi
if rp_setup rp-prev-fail sha256-A2 sha256-B1; then
	echo '{"stale":"snapshot"}' > "$icd/composition.lock.prev"
	RP_BUILD_RC=1 rp_run rp-prev-fail
	if [ "$(cat "$icd/plugins-flake/flake.lock")" = '{"stale":"snapshot"}' ] && [ ! -e "$icd/composition.lock.prev" ] \
		&& [ ! -e "$icd/runner.path" ]; then
		ok "an op's unconfirmed re-pin that fails to build is rolled back to its snapshot"
	else
		bad "prev rollback (lock: $(cat "$icd/plugins-flake/flake.lock"), log: $(cat "$WORK/rp-prev-fail.log"))"
	fi
fi

# (g) the input-name filter cannot be bypassed: a key `p-a<LF>` (Oniguruma's
# `$` matches before a trailing newline) whose narHash carries newline-split
# "names", and the reserved `p-user` / `p-git-grants`, never reach nix argv --
# not even `hash path` -- while the real stale input still re-pins
if rp_setup rp-inject sha256-A1 sha256-B1; then
	jq '.nodes.evil = {locked:{narHash:"--option\npost-build-hook\n/tmp/x",type:"path"},original:{type:"path"}}
		| .nodes.root.inputs += {"p-a\n":"evil","p-user":"evil","p-git-grants":"evil"}' \
		"$icd/plugins-flake/flake.lock" > "$icd/l.t" && mv "$icd/l.t" "$icd/plugins-flake/flake.lock"
	rp_run rp-inject
	upd=$(grep '^flake update' "$WORK/rp-inject.nix.log")
	if [ "$(grep -c '^hash path' "$WORK/rp-inject.nix.log")" = 3 ] \
		&& ! grep -q 'post-build-hook\|/tmp/x\|plugin-sources/user\|plugin-sources/git-grants\|plugin-sources/--option' "$WORK/rp-inject.nix.log" \
		&& [ "$upd" = "flake update p-a --flake path:$icd/plugins-flake" ] \
		&& [ "$(rp_pin rp-inject p-a)" = sha256-A2 ]; then
		ok "newline-bearing and reserved composition input names are filtered before nix argv"
	else
		bad "input-name filter bypass (nix calls: $(cat "$WORK/rp-inject.nix.log"))"
	fi
fi

# --- 10. live-apply boot state: snapshot, pin, line 3, GC (never fails a boot)
# The daemon pass snapshots exactly what it boots (byte-copied composition,
# `cp -al` sources, meta.json written last), promotes it to apply/base after the
# lifetime lock, records and roots the booted runner; every pass that re-execs
# evaluates a COPY of the composition and records its comp as runner.path line
# 3, which the fast path requires; the GC only renames into apply/trash. None of
# it may fail a boot that boots today.
#
# Daemon passes really boot, against fake runners (a script that keeps the
# runtime's booted-runner and exits like a guest poweroff) with
# `--network none`, through the real shutdown module, so "still boots" is
# asserted, not inferred. Stubs on PATH: `nix` (records the re-exec's pinned
# composition and hand-off env, then runs the second hop as `nix run` would:
# this launcher again, under COGBOX_REEXECED=1), `nix-store` (the gcroot),
# `cogbox` (__plugin-apply-preboot, which can fail or be killed on demand), and
# `cp`/`sha256sum`/`mv` shims that fail (or, for `cp -al`, stall) on demand, a
# `stat` shim whose `stat -f` reports the free space LA_STATFS names, a `find`
# shim that logs the take's sizing walk (and can inflate what it measures),
# an `rm` shim that can stall the removal of a failed take's partial tree, and
# an `mkdir` shim that can refuse new directories under apply/ once a take has
# filled the disk.
BASH_BIN=$(command -v bash)
la_bin="$WORK/la-bin"
mkdir -p "$la_bin"

# A fake runner at $1 whose "QEMU" records which runner booted and the
# booted-runner the launcher wrote, then exits.
la_runner() {
	mkdir -p "$1/bin"
	{ printf '#!%s\n' "$BASH_BIN"
	  printf 'echo %q > "$LA_MARK"\n' "$1"
	  printf 'cat booted-runner > "$LA_MARK.booted-runner" 2>/dev/null\n'
	  printf '[ ! -e live-runner ] || cat live-runner > "$LA_MARK.live-runner"\n'
	  printf 'exit 0\n'; } > "$1/bin/microvm-run"
	chmod +x "$1/bin/microvm-run"
}
la_base_runner="$WORK/la-base-runner"
la_runner "$la_base_runner"

# The launcher with the build-time substitutions a package makes (the runner a
# re-exec builds is played by the base runner).
LA_LAUNCH="$WORK/la-launch.sh"
sed -e "1s|^#!/usr/bin/env bash\$|#!$BASH_BIN|" \
	-e "s|@flock@|$(command -v flock)|g" \
	-e "s|@shutdown@|$SHUTDOWN|g" \
	-e "s|@harnesses@||g" \
	-e "s|@cogbox@|$la_bin/cogbox|g" \
	-e "s|@runner@|$la_base_runner|g" \
	"$LAUNCH" > "$LA_LAUNCH"
chmod +x "$LA_LAUNCH"
la_rkey=$(sed -n 's/^RUNNER_KEY="\(.*\)"$/\1/p' "$LA_LAUNCH")

{ echo "#!$BASH_BIN"; cat <<'STUB_EOF'
cmd=()
while [ $# -gt 0 ]; do
	case "$1" in
		--extra-experimental-features) shift 2 ;;
		--option) shift 3 ;;
		*) cmd+=("$1"); shift ;;
	esac
done
case "${cmd[0]}" in
	hash) cat "${cmd[2]}/.stubhash" 2>/dev/null || exit 1 ;;
	run)
		pin="" prev="" rest=() after=0
		for a in "${cmd[@]}"; do
			if [ "$after" = 1 ]; then rest+=("$a"); continue; fi
			[ "$a" = -- ] && { after=1; continue; }
			[ "$prev" = userExtensions ] && pin="${a#path:}"
			prev="$a"
		done
		{ echo "run pin=$pin"
		  echo "run comp=${COGBOX_BOOT_COMP-<unset>}"
		  echo "run snap=${COGBOX_BOOT_SNAPSHOT-<unset>}"; } >> "$LA_LOG"
		# The bytes the eval reads (the pin must still exist).
		cat "$pin/flake.nix" "$pin/flake.lock" > "$LA_LOG.evaluated" 2>/dev/null \
			|| echo "run pin-unreadable" >> "$LA_LOG"
		# A `cogbox plugin` op committing while the eval runs.
		[ -z "${LA_RUN_MUTATE:-}" ] || printf '%s' "$LA_RUN_MUTATE" > "$LA_ICD/plugins-flake/flake.lock"
		# The disk filling up while the eval runs (the second hop's statfs).
		[ -z "${LA_STATFS_HOP2:-}" ] || export LA_STATFS="$LA_STATFS_HOP2"
		echo "run low-space=${COGBOX_BOOT_LOW_SPACE-<unset>}" >> "$LA_LOG"
		# The second hop: `nix run` execs the cogbox it built with ORIG_ARGS,
		# which execs this launcher (`init` = --init-only, `__launch` = daemon).
		case "${rest[0]}" in
			init) rest[0]=--init-only ;;
			__launch) rest=("${rest[@]:1}") ;;
		esac
		exec "$LA_LAUNCH" "${rest[@]}" ;;
	*) echo "nix ${cmd[*]}" >> "$LA_LOG" ;;
esac
STUB_EOF
} > "$la_bin/nix"
{ echo "#!$BASH_BIN"; cat <<'STUB_EOF'
echo "nix-store $*" >> "$LA_LOG"
if [ -n "${LA_NIXSTORE_RC:-}" ]; then echo "error: simulated nix-store failure" >&2; exit "$LA_NIXSTORE_RC"; fi
link="" path=""
while [ $# -gt 0 ]; do
	case "$1" in
		--add-root) link=$2; shift 2 ;;
		--realise|-r) shift ;;
		*) path=$1; shift ;;
	esac
done
[ -e "$path" ] || exit 1
[ -z "$link" ] || ln -sfn "$path" "$link"
STUB_EOF
} > "$la_bin/nix-store"
# __plugin-apply-preboot: exits LA_PREBOOT_RC, or SIGKILLs itself mid-run when
# LA_PREBOOT_KILL is set (the launcher must only warn either way); with
# LA_PREBOOT_FINISH it removes the rollback intents first, as the real verb's
# finish does once it has rolled them back.
{ echo "#!$BASH_BIN"; cat <<'STUB_EOF'
echo "cogbox $*" >> "$LA_LOG"
[ -z "${LA_PREBOOT_FINISH:-}" ] || rm -f "$LA_ICD"/apply/rollback/*.intent
[ -z "${LA_PREBOOT_KILL:-}" ] || kill -KILL $$
exit "${LA_PREBOOT_RC:-0}"
STUB_EOF
} > "$la_bin/cogbox"
# `cp -al` cut short (ENOSPC, EMLINK) after it created its destination and a
# first entry, exactly when LA_CP_FAIL names the error (and it then leaves
# $LA_LOG.cpfailed for the stat shim); or, with LA_CP_SLOW, one that has made
# that much progress and then stalls for LA_CP_SLOW seconds (a large tree on a
# cold or network-backed disk).
{ echo "#!$BASH_BIN"; cat <<'SHIM_EOF'
if [ -n "${LA_CP_FAIL:-}${LA_CP_SLOW:-}" ]; then
	for a in "$@"; do
		if [ "$a" = -al ]; then
			dst="${*: -1}"
			mkdir -p "$dst" && : > "$dst/partial-entry"
			[ -z "${LA_CP_SLOW:-}" ] || { echo "cp-al-stalled" >> "$LA_LOG"; sleep "$LA_CP_SLOW"; echo "cp-al-finished" >> "$LA_LOG"; exit 0; }
			: > "$LA_LOG.cpfailed"
			echo "cp: cannot create hard link '$dst/x': $LA_CP_FAIL" >&2
			exit 1
		fi
	done
fi
exec REALCP "$@"
SHIM_EOF
} | sed "s|REALCP|$(command -v cp)|" > "$la_bin/cp"
# The take's sizing walk (`find <plugin-sources> -type d -printf '%k\n'`):
# logged, and with LA_FIND_KIB every directory reports that many KiB (a tree
# of large directories, whatever this build's filesystem allocates).
{ echo "#!$BASH_BIN"; cat <<'SHIM_EOF'
echo "find $1" >> "$LA_LOG"
if [ -n "${LA_FIND_KIB:-}" ]; then
	REALFIND "$@" | sed "s/.*/$LA_FIND_KIB/"
	exit "${PIPESTATUS[0]}"
fi
exec REALFIND "$@"
SHIM_EOF
} | sed "s|REALFIND|$(command -v find)|" > "$la_bin/find"
# A failed take's removal (`rm -rf --one-file-system -- <snap>`) that stalls
# for LA_RM_SLOW seconds; every other rm is the real one.
{ echo "#!$BASH_BIN"; cat <<'SHIM_EOF'
if [ -n "${LA_RM_SLOW:-}" ] && [[ " $* " == *" --one-file-system "*/apply/snap/* ]]; then
	echo "rm-stalled" >> "$LA_LOG"
	sleep "$LA_RM_SLOW"
fi
exec REALRM "$@"
SHIM_EOF
} | sed "s|REALRM|$(command -v rm)|" > "$la_bin/rm"
# With LA_MKDIR_FULL, once the cp shim has failed (the take filled the disk),
# no new directory can be made under <icd>/apply; every other mkdir is real.
{ echo "#!$BASH_BIN"; cat <<'SHIM_EOF'
if [ -n "${LA_MKDIR_FULL:-}" ] && [ -e "$LA_LOG.cpfailed" ] && [[ ${*: -1} == "$LA_ICD/apply"* ]]; then
	echo "mkdir-refused ${*: -1}" >> "$LA_LOG"
	echo "mkdir: cannot create directory '${*: -1}': No space left on device" >&2
	exit 1
fi
exec REALMKDIR "$@"
SHIM_EOF
} | sed "s|REALMKDIR|$(command -v mkdir)|" > "$la_bin/mkdir"
{ echo "#!$BASH_BIN"; echo '[ -z "${LA_SHA_FAIL:-}" ] || exit 1'; echo "exec $(command -v sha256sum) \"\$@\""; } > "$la_bin/sha256sum"
# An `mv` whose destination's basename is LA_MV_FAIL fails (after the first
# LA_MV_FAIL_SKIP such moves succeed): a booted-runner, base, meta.json or GC
# rename that the disk refuses.
{ echo "#!$BASH_BIN"; cat <<'SHIM_EOF'
dst="${*: -1}"
if [ -n "${LA_MV_FAIL:-}" ] && [ "${dst##*/}" = "$LA_MV_FAIL" ]; then
	n=$(( $(cat "$LA_LOG.mvseen" 2>/dev/null || echo 0) + 1 ))
	echo "$n" > "$LA_LOG.mvseen"
	if [ "$n" -gt "${LA_MV_FAIL_SKIP:-0}" ]; then
		echo "mv-refused $dst" >> "$LA_LOG"
		echo "mv: cannot move to '$dst': Input/output error" >&2
		exit 1
	fi
fi
exec REALMV "$@"
SHIM_EOF
} | sed "s|REALMV|$(command -v mv)|" > "$la_bin/mv"
# A `sync` (the fsync of a new snapshot file) that stalls for LA_SYNC_SLOW
# seconds: a journal commit stuck behind a big host build.
{ echo "#!$BASH_BIN"; cat <<'SHIM_EOF'
[ -z "${LA_SYNC_SLOW:-}" ] || { echo "sync-stalled" >> "$LA_LOG"; sleep "$LA_SYNC_SLOW"; }
exec REALSYNC "$@"
SHIM_EOF
} | sed "s|REALSYNC|$(command -v sync)|" > "$la_bin/sync"
# `stat -f` answers LA_STATFS ("<avail blocks> <block size> <inodes> <free
# inodes> <blocks> <free blocks>", the launcher's %a %S %c %d %b %f), so a pass
# sees the free space a case plants rather than the build machine's, or
# LA_STATFS_AFTER_CP once the cp shim has failed (a take that filled the disk);
# every other stat is the real one.
{ echo "#!$BASH_BIN"; cat <<'SHIM_EOF'
if [ -n "${LA_STATFS:-}" ]; then
	for a in "$@"; do
		[ "$a" = -f ] || continue
		echo "statfs $*" >> "$LA_LOG"
		if [ -n "${LA_STATFS_AFTER_CP:-}" ] && [ -e "$LA_LOG.cpfailed" ]; then echo "$LA_STATFS_AFTER_CP"; else echo "$LA_STATFS"; fi
		exit 0
	done
fi
exec REALSTAT "$@"
SHIM_EOF
} | sed "s|REALSTAT|$(command -v stat)|" > "$la_bin/stat"
chmod +x "$la_bin"/*
# Plenty of space and inodes, unless a case plants less (la_run's default): the
# room above the floor exceeds what the filesystem uses, so no take is sized.
LA_STATFS_PLENTY="268435456 4096 67108864 67108000 268500000 268440000"

# The comp format both sides must agree on (the k8s pre-build records Zig's
# comp and this launcher compares it with its own): the launcher's own
# comp_of_dir, extracted, against the vectors zig/src/plugin/snapshot.zig pins,
# with a lock and without one. And the statfs format it parses is what this
# coreutils prints.
eval "$(sed -n '/^comp_of_dir() {$/,/^}$/p' "$LAUNCH")"
mkdir -p "$WORK/comp-vec"
printf 'A' > "$WORK/comp-vec/flake.nix"
rm -f "$WORK/comp-vec/flake.lock"
v_nolock=$(comp_of_dir "$WORK/comp-vec")
printf 'B' > "$WORK/comp-vec/flake.lock"
v_lock=$(comp_of_dir "$WORK/comp-vec")
if [ "$v_lock" = 76fe3925c7167317f2df68454339f5ec3650e4062178b4f2be219b105a507907 ] \
	&& [ "$v_nolock" = e61c21ca716b3b1aefb7d1198f83679c4ca4d596e5792275dd6203b49216237d ]; then
	ok "the launcher's comp_of_dir matches the Zig side's vectors, with a flake.lock and without one"
else
	bad "comp_of_dir vectors (with lock: '$v_lock', without: '$v_nolock')"
fi
if grep -qF "stat -f -c '%a %S %c %d %b %f' --" "$LAUNCH" \
	&& [[ $(stat -f -c '%a %S %c %d %b %f' -- "$WORK") =~ ^[0-9]+\ [1-9][0-9]*\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]]; then
	ok "the launcher's free-space probe reads six integers from this coreutils' stat -f"
else
	bad "statfs format (launcher: $(grep -o "stat -f -c '[^']*'" "$LAUNCH"), here: $(stat -f -c '%a %S %c %d %b %f' -- "$WORK" 2>&1))"
fi
# ...and the sizing walk's output is what this findutils prints: one line of
# whole KiB per directory, the tree's root included.
mkdir -p "$WORK/find-vec/a/b"
if [[ $(find "$WORK/find-vec" -type d -printf '%k\n' | jq -rs '"\(length) \(add // 0)"') =~ ^3\ [0-9]+$ ]]; then
	ok "the take's sizing walk reads one KiB count per directory from this find"
else
	bad "find -printf %k format (here: $(find "$WORK/find-vec" -type d -printf '%k\n' 2>&1 | tr '\n' ' '))"
fi

# la_setup TAG: an initialized instance with plugins a and b (entries, tagged
# L4/L7/inject policy, materialized sources), a composition whose lock pins each
# tree at what the stub `nix hash path` answers (so no re-pin), no record.
la_setup() {
	local tag="$1"
	rc=$(run_init "$tag" --name demo)
	[ "$rc" = 0 ] || { bad "live-apply fixture init ($tag) exited $rc (log: $(cat "$WORK/$tag.log"))"; return 1; }
	icd="$WORK/$tag/config/cogbox/instances/demo"
	mkdir -p "$icd/plugin-sources/a/sub" "$icd/plugin-sources/b" "$icd/plugins-flake" "$WORK/$tag/run"
	printf 'sha256-A1' > "$icd/plugin-sources/a/.stubhash"
	printf 'sha256-B1' > "$icd/plugin-sources/b/.stubhash"
	printf 'sha256-U1' > "$icd/flake/.stubhash"
	echo 'plugin a module' > "$icd/plugin-sources/a/sub/module.nix"
	jq '.plugins = [{"name":"a","narHash":"sha256-A1"},{"name":"b","narHash":"sha256-B1"}]
		| .network.rules = [{"allow":"10.1.0.0/16","plugin":"a"},{"deny":"10.2.0.0/16","plugin":"b"}] + .network.rules
		| .network.l7 = {rules: [{"allow":"git.example.com","plugin":"a"}],
			inject: {enabled: true, specs: [{"host":"api.example.com","style":"bearer","secret":"api-token","plugin":"b"}]}}' \
		"$icd/config.json" > "$icd/c.t" && mv "$icd/c.t" "$icd/config.json"
	echo '{ outputs = _: { }; }' > "$icd/plugins-flake/flake.nix"
	jq -n --arg d "$icd" '{nodes:{
		"p-a":{locked:{narHash:"sha256-A1",path:"\($d)/plugin-sources/a",type:"path"},original:{path:"\($d)/plugin-sources/a",type:"path"}},
		"p-b":{locked:{narHash:"sha256-B1",path:"\($d)/plugin-sources/b",type:"path"},original:{path:"\($d)/plugin-sources/b",type:"path"}},
		user:{locked:{narHash:"sha256-U1",path:"\($d)/flake",type:"path"},original:{path:"\($d)/flake",type:"path"}},
		root:{inputs:{"p-a":"p-a","p-b":"p-b",user:"user"}}},root:"root",version:7}' > "$icd/plugins-flake/flake.lock"
	: > "$WORK/$tag.la.log"
	rm -f "$WORK/$tag.mark" "$WORK/$tag.mark.booted-runner" "$WORK/$tag.la.log.evaluated"
}
# la_run TAG [--init-only] [VAR=value...]: one launcher pass. The daemon pass is
# what `cogbox start` forks (COGBOX_SKIP_REPIN=1), booting with --network none.
la_run() {
	local tag="$1" mode=() envs=()
	shift
	if [ "${1:-}" = --init-only ]; then mode=(--init-only); shift; else mode=(--network none); envs=(COGBOX_SKIP_REPIN=1); fi
	rm -f "$WORK/$tag.mark" "$WORK/$tag.mark.booted-runner"
	rm -f "$WORK/$tag.la.log.mvseen" "$WORK/$tag.la.log.cpfailed"
	env HOME="$WORK/$tag" COGBOX_DATA="$WORK/$tag/data" XDG_CONFIG_HOME="$WORK/$tag/config" \
		XDG_RUNTIME_DIR="$WORK/$tag/run" PATH="$la_bin:$PATH" \
		LA_LOG="$WORK/$tag.la.log" LA_MARK="$WORK/$tag.mark" LA_LAUNCH="$LA_LAUNCH" LA_ICD="$icd" \
		LA_STATFS="$LA_STATFS_PLENTY" "${envs[@]}" "$@" \
		"$LA_LAUNCH" "${mode[@]}" --yes --name demo >"$WORK/$tag.log" 2>&1
}
# Everything the launcher said in a pass: its stdout/stderr and, once it won the
# lifetime lock, the runtime's cogbox.log it reopened onto. Always status 0:
# under pipefail, `la_said T | grep -q X` must be grep's verdict, not cat's (a
# grep -q that matches in the first file exits before cat writes the second,
# and cat dies of SIGPIPE; a pass that never reopened onto cogbox.log has
# none, and cat exits 1).
la_said() { cat "$WORK/$1.log" "$WORK/$1/run/cogbox-demo/cogbox.log" 2>/dev/null; return 0; }
la_booted() { [ "$(cat "$WORK/$1.mark" 2>/dev/null)" = "$2" ]; }
la_base_id() { local l; l=$(readlink "$icd/apply/base" 2>/dev/null) && echo "${l##*/}"; }
la_record() { printf '%s\n%s\n%s\n' "$la_rkey" "$1" "$2" > "$icd/runner.path"; }
la_snaps() { ls "$icd/apply/snap" 2>/dev/null | tr '\n' ' '; }

# (a) snapshot success on the fast path: a three-line record for these bytes
# boots its runner with no re-exec, the boot snapshot holds exactly the booted
# composition (byte copies, own inodes), the plugin state and its tagged
# policy, a hard-linked src/, and meta.json naming the runner; it becomes base,
# the previous base goes to the trash, booted-runner and gcroots/booted record
# and root the runner, gcroots/applied is released, and the preboot runs
# without --init-only.
if la_setup la-snap; then
	la_runner "$WORK/la-snap/fp-runner"
	comp=$(comp_of "$icd/plugins-flake")
	la_record "$WORK/la-snap/fp-runner" "$comp"
	# An earlier boot's base and a runner rooted during it.
	mkdir -p "$icd/apply/snap/00000000000000aa/src" "$icd/gcroots/applied"
	echo '{"id":"00000000000000aa","comp":"none","runner":null,"key":null}' > "$icd/apply/snap/00000000000000aa/meta.json"
	ln -s snap/00000000000000aa "$icd/apply/base"
	ln -s "$la_base_runner" "$icd/gcroots/applied/0123456789abcdef"
	la_run la-snap
	id=$(la_base_id)
	s="$icd/apply/snap/$id"
	m="$s/meta.json"
	if la_booted la-snap "$WORK/la-snap/fp-runner" && ! grep -q '^run ' "$WORK/la-snap.la.log" \
		&& [ -n "$id" ] && [ "$id" != 00000000000000aa ] && [[ $id =~ ^[0-9a-f]{16}$ ]] \
		&& cmp -s "$s/composition/flake.nix" "$icd/plugins-flake/flake.nix" \
		&& cmp -s "$s/composition/flake.lock" "$icd/plugins-flake/flake.lock" \
		&& [ "$(stat -c %i "$s/composition/flake.lock")" != "$(stat -c %i "$icd/plugins-flake/flake.lock")" ] \
		&& [ "$(stat -c %i "$s/src/a/sub/module.nix")" = "$(stat -c %i "$icd/plugin-sources/a/sub/module.nix")" ] \
		&& [ "$(jq -c '[.plugins[].name]' "$s/state.json")" = '["a","b"]' ] \
		&& [ "$(jq -c '.tagged.a' "$s/state.json")" = '{"l4":[{"allow":"10.1.0.0/16","plugin":"a"}],"l7":[{"allow":"git.example.com","plugin":"a"}],"inject":[]}' ] \
		&& [ "$(jq -c '.tagged.b' "$s/state.json")" = '{"l4":[{"deny":"10.2.0.0/16","plugin":"b"}],"l7":[],"inject":[{"host":"api.example.com","style":"bearer","secret":"api-token","plugin":"b"}]}' ] \
		&& [ "$(jq -r '[.id, .comp, .runner, .key] | join(" ")' "$m")" = "$id $comp $WORK/la-snap/fp-runner $la_rkey" ] \
		&& [ ! -e "$icd/apply/booting" ] && [ ! -e "$icd/apply/snap/00000000000000aa" ] \
		&& [ -f "$icd/apply/trash/00000000000000aa/meta.json" ] \
		&& [ "$(cat "$WORK/la-snap.mark.booted-runner")" = "$la_rkey"$'\n'"$WORK/la-snap/fp-runner"$'\n'"$comp" ] \
		&& [ "$(readlink "$icd/gcroots/booted")" = "$WORK/la-snap/fp-runner" ] \
		&& [ -d "$icd/gcroots/applied" ] && [ -z "$(ls -A "$icd/gcroots/applied")" ] \
		&& grep -qx "cogbox __plugin-apply-preboot $icd --runtime $WORK/la-snap/run/cogbox-demo --name demo" "$WORK/la-snap.la.log"; then
		ok "a fast-path daemon pass snapshots exactly what it boots, promotes it to base, and records and roots the booted runner"
	else
		bad "fast-path boot snapshot (base=$id snaps=$(la_snaps) trash=$(ls "$icd/apply/trash" 2>&1) meta=$(cat "$m" 2>&1) booted-runner=$(cat "$WORK/la-snap.mark.booted-runner" 2>&1) calls=$(cat "$WORK/la-snap.la.log") said: $(la_said la-snap))"
	fi
	# The snapshot's lock is a byte copy: rewriting the live lock in place (as
	# `nix flake lock` and the re-pin restore do) leaves it and its comp alone.
	cp "$s/composition/flake.lock" "$WORK/la-snap.snaplock"
	printf '{"rewritten":"in place"}' > "$icd/plugins-flake/flake.lock"
	if cmp -s "$WORK/la-snap.snaplock" "$s/composition/flake.lock" && [ "$(comp_of "$s/composition")" = "$comp" ]; then
		ok "an in-place rewrite of plugins-flake/flake.lock leaves the snapshot's lock and comp unchanged"
	else
		bad "the snapshot's lock followed an in-place rewrite of the live lock"
	fi
fi

# (b) a two-line record (an older cogbox's) misses the fast path once: the init
# pass re-execs from a PIN copy (never plugins-flake, never a snapshot: an init
# pass takes none) with the pin's comp, and the second hop writes a three-line
# record whose line 3 is that comp. The next init pass and the daemon pass both
# fast-path it. The preboot gets --init-only exactly in the init pass.
if la_setup la-line3; then
	la_runner "$WORK/la-line3/fp-runner"
	comp=$(comp_of "$icd/plugins-flake")
	printf '%s\n%s\n' "$la_rkey" "$WORK/la-line3/fp-runner" > "$icd/runner.path"
	la_run la-line3 --init-only
	pin=$(sed -n 's/^run pin=//p' "$WORK/la-line3.la.log")
	if [ "$(grep -c '^run pin=' "$WORK/la-line3.la.log")" = 1 ] \
		&& [[ $pin == "$icd/apply/pin/"* ]] && [ -f "$pin/flake.lock" ] \
		&& grep -qx "run comp=$comp" "$WORK/la-line3.la.log" && grep -qx 'run snap=<unset>' "$WORK/la-line3.la.log" \
		&& [ "$(cat "$WORK/la-line3.la.log.evaluated")" = "$(cat "$icd/plugins-flake/flake.nix" "$icd/plugins-flake/flake.lock")" ] \
		&& [ "$(cat "$icd/runner.path")" = "$la_rkey"$'\n'"$la_base_runner"$'\n'"$comp" ] \
		&& [ -z "$(la_snaps)" ] && [ ! -e "$icd/apply/base" ] \
		&& [ "$(grep -c "^cogbox __plugin-apply-preboot $icd --runtime $WORK/la-line3/run/cogbox-demo --name demo --init-only\$" "$WORK/la-line3.la.log")" = 1 ]; then
		ok "a two-line record misses the fast path; the init pass re-execs from a pinned copy and records three lines"
	else
		bad "two-line record (calls: $(cat "$WORK/la-line3.la.log"), record: $(cat "$icd/runner.path" 2>&1), snaps: $(la_snaps), said: $(la_said la-line3))"
	fi
	# Point the (now three-line) record at a real runner: the next passes hit.
	la_record "$WORK/la-line3/fp-runner" "$comp"
	: > "$WORK/la-line3.la.log"
	la_run la-line3 --init-only
	la_run la-line3
	if ! grep -q '^run ' "$WORK/la-line3.la.log" && la_booted la-line3 "$WORK/la-line3/fp-runner" \
		&& [ "$(grep -c '^cogbox __plugin-apply-preboot' "$WORK/la-line3.la.log")" = 2 ] \
		&& [ "$(grep -c -- '--init-only$' "$WORK/la-line3.la.log")" = 1 ]; then
		ok "a three-line record whose comp matches fast-paths the init pass and the daemon pass"
	else
		bad "three-line record (calls: $(cat "$WORK/la-line3.la.log"), said: $(la_said la-line3))"
	fi
	# An empty or different line 3 never fast-paths.
	for line3 in "" "$(printf '%064d' 0)"; do
		la_record "$WORK/la-line3/fp-runner" "$line3"
		: > "$WORK/la-line3.la.log"
		la_run la-line3 --init-only
		if grep -q '^run pin=' "$WORK/la-line3.la.log"; then
			ok "a record whose line 3 is '${line3:0:8}' (not this composition's comp) never fast-paths"
		else
			bad "line 3 '$line3' fast-pathed (calls: $(cat "$WORK/la-line3.la.log"))"
		fi
	done
	# A plugin op that commits while the init pass's eval runs: the record names
	# the runner of the PINNED bytes, so the daemon pass re-execs instead of
	# fast-pathing the pre-op runner.
	rm -f "$icd/runner.path"
	: > "$WORK/la-line3.la.log"
	la_run la-line3 --init-only LA_RUN_MUTATE='{"op":"committed during the eval"}'
	recorded=$(sed -n 3p "$icd/runner.path")
	: > "$WORK/la-line3.la.log"
	la_run la-line3
	if [ "$recorded" = "$comp" ] && [ "$recorded" != "$(comp_of "$icd/plugins-flake")" ] \
		&& [ "$(grep -c '^run pin=' "$WORK/la-line3.la.log")" = 1 ] && la_booted la-line3 "$la_base_runner"; then
		ok "a plugin op committed during the init pass's eval makes the daemon pass re-exec, not fast-path the pre-op runner"
	else
		bad "op during eval (record: $(cat "$icd/runner.path"), calls: $(cat "$WORK/la-line3.la.log"))"
	fi
fi

# (c) a re-exec'd daemon pass evaluates its complete boot snapshot's own
# composition/, hands the snapshot to the second hop, which promotes it.
if la_setup la-reexec; then
	la_run la-reexec
	id=$(la_base_id)
	if la_booted la-reexec "$la_base_runner" && [ -n "$id" ] \
		&& grep -qx "run pin=$icd/apply/snap/$id/composition" "$WORK/la-reexec.la.log" \
		&& grep -qx "run snap=$icd/apply/snap/$id" "$WORK/la-reexec.la.log" \
		&& grep -qx "run comp=$(comp_of "$icd/plugins-flake")" "$WORK/la-reexec.la.log" \
		&& [ "$(jq -r .runner "$icd/apply/snap/$id/meta.json")" = "$la_base_runner" ] \
		&& [ "$(sed -n 3p "$icd/runner.path")" = "$(comp_of "$icd/plugins-flake")" ] \
		&& [ "$(la_snaps)" = "$id " ] && [ ! -e "$icd/apply/booting" ]; then
		ok "a re-exec'd daemon pass evaluates its boot snapshot's composition and the second hop promotes it"
	else
		bad "re-exec'd daemon pass (base=$id, snaps=$(la_snaps), calls: $(cat "$WORK/la-reexec.la.log"), said: $(la_said la-reexec))"
	fi
fi

# (d) a planted `cp -al` failure (ENOSPC, EMLINK), after the composition copies
# succeeded, still boots, on the fast path and on the re-exec: booting is
# cleared, the re-exec names a pin (never the partial tree) with that pin's
# comp, and base is unlinked. The partial tree (no meta.json) of a take that
# ran out of room (ENOSPC) is removed at once, since a rename would free
# nothing for the rest of the pass; any other failure's goes to the trash.
for errno in "No space left on device" "Too many links"; do
	tag=la-cpfail-${errno%% *}
	if la_setup "$tag"; then
		la_runner "$WORK/$tag/fp-runner"
		comp=$(comp_of "$icd/plugins-flake")
		la_record "$WORK/$tag/fp-runner" "$comp"
		mkdir -p "$icd/apply/snap/00000000000000aa"
		echo '{"id":"00000000000000aa","comp":"none","runner":null,"key":null}' > "$icd/apply/snap/00000000000000aa/meta.json"
		ln -s snap/00000000000000aa "$icd/apply/base"
		la_run "$tag" LA_CP_FAIL="$errno"
		partial=$(ls "$icd/apply/trash" 2>/dev/null | grep -v '^00000000000000aa$')
		if [ "$errno" = "Too many links" ]; then
			[ -n "$partial" ] && [ -e "$icd/apply/trash/$partial/src/partial-entry" ] \
				&& [ -f "$icd/apply/trash/$partial/composition/flake.lock" ] && [ ! -e "$icd/apply/trash/$partial/meta.json" ] \
				&& ! la_said "$tag" | grep -q 'partial tree was removed'
		else
			[ -z "$partial" ] && [ -d "$icd/apply/trash/00000000000000aa" ] \
				&& la_said "$tag" | grep -q 'could not take the live-apply boot snapshot .*(the disk ran out of room for it, so its partial tree was removed)'
		fi
		partial_ok=$?
		if la_booted "$tag" "$WORK/$tag/fp-runner" && [ ! -e "$icd/apply/base" ] && [ ! -L "$icd/apply/base" ] \
			&& [ ! -e "$icd/apply/booting" ] && [ -z "$(la_snaps)" ] && [ "$partial_ok" = 0 ] \
			&& [ "$(sed -n 3p "$WORK/$tag.mark.booted-runner")" = "$comp" ] \
			&& [ "$(la_said "$tag" | grep -c "cannot create hard link")" = 1 ] \
			&& la_said "$tag" | grep -q 'could not take the live-apply boot snapshot'; then
			ok "a failed boot-snapshot cp -al ($errno) on the fast path still boots, without a base, the partial tree $([ -z "$partial" ] && echo removed || echo 'in the trash')"
		else
			bad "cp -al failure ($errno) on the fast path (base: $(readlink "$icd/apply/base" 2>&1), snaps=$(la_snaps) trash=$(ls "$icd/apply/trash" 2>&1), said: $(la_said "$tag"))"
		fi
		# ...and on the re-exec (no record for these bytes).
		rm -f "$icd/runner.path"
		: > "$WORK/$tag.la.log"
		la_run "$tag" LA_CP_FAIL="$errno"
		pin=$(sed -n 's/^run pin=//p' "$WORK/$tag.la.log")
		if la_booted "$tag" "$la_base_runner" && [[ $pin == "$icd/apply/pin/"* ]] \
			&& grep -qx "run comp=$(comp_of "$pin")" "$WORK/$tag.la.log" && grep -qx "run comp=$comp" "$WORK/$tag.la.log" \
			&& grep -qx 'run snap=<unset>' "$WORK/$tag.la.log" \
			&& [ ! -e "$icd/apply/base" ] && [ -z "$(la_snaps)" ] \
			&& [ "$(sed -n 3p "$icd/runner.path")" = "$comp" ]; then
			ok "a failed boot-snapshot cp -al ($errno) on the re-exec boots from a pinned copy, never the partial tree"
		else
			bad "cp -al failure ($errno) on the re-exec (pin=$pin, calls: $(cat "$WORK/$tag.la.log"), said: $(la_said "$tag"))"
		fi
	fi
done
# ...and when the pin cannot be written either, the pass re-execs from
# plugins-flake exactly as before, with the comp of those bytes, and boots.
if la_setup la-pinfail; then
	mkdir -p "$icd/apply"
	: > "$icd/apply/pin"
	la_run la-pinfail LA_CP_FAIL="No space left on device"
	if la_booted la-pinfail "$la_base_runner" \
		&& grep -qx "run pin=$icd/plugins-flake" "$WORK/la-pinfail.la.log" \
		&& grep -qx "run comp=$(comp_of "$icd/plugins-flake")" "$WORK/la-pinfail.la.log" \
		&& [ ! -e "$icd/apply/base" ] && la_said la-pinfail | grep -q 'could not pin the plugin composition'; then
		ok "with the pin unwritable too, the pass re-execs from plugins-flake as before and still boots"
	else
		bad "pin failure fallback (calls: $(cat "$WORK/la-pinfail.la.log"), said: $(la_said la-pinfail))"
	fi
fi
# ...a `cp -al` that stalls (a large tree on a cold or network-backed disk) is
# cut off at the take's bound (COGBOX_BOOT_SNAPSHOT_TIMEOUT, here 3s: bash's
# SECONDS ticks whole seconds, so a 1s bound may be spent before cp starts), not left
# to eat `cogbox start`'s 60s: it fails like any other take, its partial tree
# goes to the trash, and the box boots without a base, on the fast path and on
# the re-exec (from a pin).
if la_setup la-cpslow; then
	la_runner "$WORK/la-cpslow/fp-runner"
	comp=$(comp_of "$icd/plugins-flake")
	la_record "$WORK/la-cpslow/fp-runner" "$comp"
	t0=$SECONDS
	la_run la-cpslow LA_CP_SLOW=30 COGBOX_BOOT_SNAPSHOT_TIMEOUT=3
	took=$((SECONDS - t0))
	partial=$(ls "$icd/apply/trash" 2>/dev/null)
	if la_booted la-cpslow "$WORK/la-cpslow/fp-runner" && [ "$took" -lt 15 ] \
		&& grep -qx cp-al-stalled "$WORK/la-cpslow.la.log" && ! grep -q cp-al-finished "$WORK/la-cpslow.la.log" \
		&& [ ! -e "$icd/apply/base" ] && [ ! -e "$icd/apply/booting" ] && [ -z "$(la_snaps)" ] \
		&& [ -n "$partial" ] && [ -e "$icd/apply/trash/$partial/src/partial-entry" ] && [ ! -e "$icd/apply/trash/$partial/meta.json" ] \
		&& la_said la-cpslow | grep -q 'could not take the live-apply boot snapshot .*(its cp -al of plugin-sources took over 3s)'; then
		ok "a boot-snapshot cp -al that stalls past its bound is cut off: the box boots in ${took}s without a base, the partial tree in the trash"
	else
		bad "stalled cp -al (took ${took}s, snaps=$(la_snaps), trash=$(ls "$icd/apply/trash" 2>&1), calls: $(cat "$WORK/la-cpslow.la.log"), said: $(la_said la-cpslow))"
	fi
	rm -f "$icd/runner.path"
	: > "$WORK/la-cpslow.la.log"
	la_run la-cpslow LA_CP_SLOW=30 COGBOX_BOOT_SNAPSHOT_TIMEOUT=3
	pin=$(sed -n 's/^run pin=//p' "$WORK/la-cpslow.la.log")
	if la_booted la-cpslow "$la_base_runner" && [[ $pin == "$icd/apply/pin/"* ]] \
		&& grep -qx "run comp=$comp" "$WORK/la-cpslow.la.log" && [ ! -e "$icd/apply/base" ] && [ -z "$(la_snaps)" ]; then
		ok "a boot-snapshot cp -al cut off at its bound on the re-exec boots from a pinned copy"
	else
		bad "stalled cp -al on the re-exec (pin=$pin, calls: $(cat "$WORK/la-cpslow.la.log"), said: $(la_said la-cpslow))"
	fi
fi
# ...an fsync that stalls is bounded the same way (each at most 5s, and never
# past what the take's bound has left): the take fails, and the box boots.
if la_setup la-syncslow; then
	la_runner "$WORK/la-syncslow/fp-runner"
	la_record "$WORK/la-syncslow/fp-runner" "$(comp_of "$icd/plugins-flake")"
	t0=$SECONDS
	la_run la-syncslow LA_SYNC_SLOW=30 COGBOX_BOOT_SNAPSHOT_TIMEOUT=2
	took=$((SECONDS - t0))
	if la_booted la-syncslow "$WORK/la-syncslow/fp-runner" && [ "$took" -lt 20 ] \
		&& grep -qx sync-stalled "$WORK/la-syncslow.la.log" \
		&& [ ! -e "$icd/apply/base" ] && [ ! -e "$icd/apply/booting" ] && [ -z "$(la_snaps)" ] \
		&& la_said la-syncslow | grep -q 'could not take the live-apply boot snapshot'; then
		ok "a stalled fsync fails the boot snapshot within its bound: the box boots in ${took}s without a base"
	else
		bad "stalled fsync (took ${took}s, snaps=$(la_snaps), calls: $(cat "$WORK/la-syncslow.la.log"), said: $(la_said la-syncslow))"
	fi
fi
# ...and a failed take CLEARS apply/booting, so the GC retires the snapshot an
# earlier pass recorded there (it never booted). Observed in a pass that then
# loses the lifetime lock, so no promotion clears it instead.
if la_setup la-cpfail-booting; then
	mkdir -p "$icd/apply/snap/00000000000000b0/src" "$WORK/la-cpfail-booting/run"
	echo '{"id":"00000000000000b0","comp":"none","runner":null,"key":null}' > "$icd/apply/snap/00000000000000b0/meta.json"
	echo 00000000000000b0 > "$icd/apply/booting"
	exec {la_lock}>"$WORK/la-cpfail-booting/run/cogbox-demo.lock"
	flock -n "$la_lock"
	la_run la-cpfail-booting LA_CP_FAIL="No space left on device"; rc=$?
	exec {la_lock}>&-
	if [ "$rc" = 75 ] && [ ! -e "$icd/apply/booting" ] && [ -z "$(la_snaps)" ] \
		&& [ -f "$icd/apply/trash/00000000000000b0/meta.json" ]; then
		ok "a failed boot-snapshot take clears apply/booting, so the GC retires the earlier pass's unbooted snapshot"
	else
		bad "failed take vs booting (rc=$rc, booting=$(cat "$icd/apply/booting" 2>&1), snaps=$(la_snaps), trash=$(ls "$icd/apply/trash" 2>&1), said: $(la_said la-cpfail-booting))"
	fi
fi

# (e) the other Phase 0 steps fail soft: a hash that fails (empty line 3: the
# boot re-execs and its record never fast-paths), a gcroot that fails (applied/
# is kept), a GC that cannot rename (trash is a file) -- the box boots each time.
if la_setup la-soft; then
	la_run la-soft LA_SHA_FAIL=1
	if la_booted la-soft "$la_base_runner" && [ -z "$(sed -n 3p "$icd/runner.path")" ] \
		&& [ "$(wc -l < "$icd/runner.path")" = 3 ] && [ ! -e "$icd/apply/base" ] \
		&& la_said la-soft | grep -q 'could not hash the plugin composition'; then
		ok "a failing comp hash only costs the fast path: the box boots and records an empty line 3"
	else
		bad "hash failure (record: $(cat "$icd/runner.path" 2>&1), said: $(la_said la-soft))"
	fi
	la_runner "$WORK/la-soft/fp-runner"
	la_record "$WORK/la-soft/fp-runner" "$(comp_of "$icd/plugins-flake")"
	mkdir -p "$icd/gcroots/applied"
	ln -sfn "$la_base_runner" "$icd/gcroots/applied/0123456789abcdef"
	mkdir -p "$icd/apply/snap/00000000000000bb"
	rm -rf "$icd/apply/trash"
	: > "$icd/apply/trash"
	la_run la-soft LA_NIXSTORE_RC=1
	if la_booted la-soft "$WORK/la-soft/fp-runner" && [ -L "$icd/gcroots/applied/0123456789abcdef" ] \
		&& [ -d "$icd/apply/snap/00000000000000bb" ] && [ -n "$(la_base_id)" ] \
		&& la_said la-soft | grep -q 'could not root the booted runner' \
		&& la_said la-soft | grep -q 'cannot create .*apply/trash'; then
		ok "a failing gcroot and an impossible GC rename only warn: the box boots, applied/ and the snapshot stay"
	else
		bad "soft failures (applied: $(ls "$icd/gcroots/applied" 2>&1), snaps=$(la_snaps), said: $(la_said la-soft))"
	fi
fi
# ...and so do the rest, each on a fast-path daemon pass that must still boot:
# a refused booted-runner write (no record, no tmp left), a refused base flip
# (base unlinked, its tmp link gone, the snapshot retired), a refused base
# meta.json rewrite (base still promoted, its runner unrecorded), a refused GC
# rename (the snapshot stays), and a housekeeping verb that exits 1 or is
# SIGKILLed.
if la_setup la-soft2; then
	la_runner "$WORK/la-soft2/fp-runner"
	la_record "$WORK/la-soft2/fp-runner" "$(comp_of "$icd/plugins-flake")"
	la_run la-soft2 LA_MV_FAIL=booted-runner
	if la_booted la-soft2 "$WORK/la-soft2/fp-runner" && [ ! -s "$WORK/la-soft2.mark.booted-runner" ] \
		&& grep -q '^mv-refused .*/booted-runner$' "$WORK/la-soft2.la.log" \
		&& [ -z "$(ls "$WORK/la-soft2/run/cogbox-demo" | grep 'booted-runner')" ] \
		&& [ -n "$(la_base_id)" ] && la_said la-soft2 | grep -q 'could not record the booted runner in .*/booted-runner'; then
		ok "a refused booted-runner write only warns: the box boots, nothing half-written is left"
	else
		bad "booted-runner write failure (runtime: $(ls "$WORK/la-soft2/run/cogbox-demo" 2>&1), calls: $(cat "$WORK/la-soft2.la.log"), said: $(la_said la-soft2))"
	fi
	: > "$WORK/la-soft2.la.log"
	# What a launcher killed mid-write leaves: the GC sweeps it.
	: > "$icd/apply/.booting.tmp.4242"
	ln -s snap/00000000000000ff "$icd/apply/.base.tmp.4242"
	la_run la-soft2 LA_MV_FAIL=base
	if la_booted la-soft2 "$WORK/la-soft2/fp-runner" && grep -q '^mv-refused .*/apply/base$' "$WORK/la-soft2.la.log" \
		&& [ ! -e "$icd/apply/base" ] && [ ! -L "$icd/apply/base" ] && [ ! -e "$icd/apply/booting" ] \
		&& [ -z "$(ls -A "$icd/apply" | grep '^\.base\.tmp\|^\.booting\.tmp')" ] && [ -z "$(la_snaps)" ] \
		&& la_said la-soft2 | grep -q "could not point .*/apply/base at this boot's snapshot"; then
		ok "a refused base flip only warns: the box boots without a base, its snapshot is retired, stale tmp names are swept"
	else
		bad "base flip failure (apply: $(ls -A "$icd/apply" 2>&1), snaps=$(la_snaps), calls: $(cat "$WORK/la-soft2.la.log"), said: $(la_said la-soft2))"
	fi
	: > "$WORK/la-soft2.la.log"
	la_run la-soft2 LA_MV_FAIL=meta.json LA_MV_FAIL_SKIP=1
	id=$(la_base_id)
	if la_booted la-soft2 "$WORK/la-soft2/fp-runner" && [ -n "$id" ] \
		&& [ "$(grep -c '^mv-refused .*/meta.json$' "$WORK/la-soft2.la.log")" = 1 ] \
		&& [ "$(jq -r '.runner' "$icd/apply/snap/$id/meta.json")" = null ] \
		&& la_said la-soft2 | grep -q "could not record the booted runner in live-apply snapshot $id"; then
		ok "a refused base meta.json rewrite only warns: the box boots and base is still promoted"
	else
		bad "base meta.json failure (base=$id, meta: $(cat "$icd/apply/snap/$id/meta.json" 2>&1), calls: $(cat "$WORK/la-soft2.la.log"), said: $(la_said la-soft2))"
	fi
	mkdir -p "$icd/apply/snap/00000000000000cc/src"
	echo '{"id":"00000000000000cc","comp":"none","runner":null,"key":null}' > "$icd/apply/snap/00000000000000cc/meta.json"
	: > "$WORK/la-soft2.la.log"
	la_run la-soft2 LA_MV_FAIL=00000000000000cc
	if la_booted la-soft2 "$WORK/la-soft2/fp-runner" && [ -f "$icd/apply/snap/00000000000000cc/meta.json" ] \
		&& [ -n "$(la_base_id)" ] && grep -q '^mv-refused .*/trash/00000000000000cc$' "$WORK/la-soft2.la.log" \
		&& la_said la-soft2 | grep -q 'could not move live-apply snapshot 00000000000000cc into'; then
		ok "a refused GC rename only warns: the box boots and the snapshot stays for the next GC"
	else
		bad "GC rename failure (snaps=$(la_snaps), calls: $(cat "$WORK/la-soft2.la.log"), said: $(la_said la-soft2))"
	fi
	for how in LA_PREBOOT_RC=1 LA_PREBOOT_KILL=1; do
		: > "$WORK/la-soft2.la.log"
		la_run la-soft2 "$how"
		want=1 what="exits 1"
		[ "$how" = LA_PREBOOT_RC=1 ] || { want=137 what="is SIGKILLed"; }
		if la_booted la-soft2 "$WORK/la-soft2/fp-runner" && grep -q '^cogbox __plugin-apply-preboot' "$WORK/la-soft2.la.log" \
			&& [ -n "$(la_base_id)" ] \
			&& la_said la-soft2 | grep -q "live-apply housekeeping (__plugin-apply-preboot) exited $want; continuing"; then
			ok "a housekeeping verb that $what only warns (exit $want): the box boots"
		else
			bad "preboot $how (calls: $(cat "$WORK/la-soft2.la.log"), said: $(la_said la-soft2))"
		fi
	done
fi

# (e2) a symlinked apply/ is never written through, even when the pass would
# only remove: no snapshot, no booting cleared, no base flip, no GC there. The
# box still boots (without a base).
if la_setup la-applylink; then
	la_runner "$WORK/la-applylink/fp-runner"
	la_record "$WORK/la-applylink/fp-runner" "$(comp_of "$icd/plugins-flake")"
	elsewhere="$WORK/la-applylink/elsewhere"
	mkdir -p "$elsewhere/snap/00000000000000e1"
	echo 00000000000000e1 > "$elsewhere/booting"
	ln -s snap/00000000000000e1 "$elsewhere/base"
	ln -s snap/00000000000000e1 "$elsewhere/built"
	: > "$elsewhere/.base.tmp.4242"
	ln -s "$elsewhere" "$icd/apply"
	before=$(cd "$elsewhere" && find . | sort | tr '\n' ' ')
	la_run la-applylink
	if la_booted la-applylink "$WORK/la-applylink/fp-runner" \
		&& [ "$(cd "$elsewhere" && find . | sort | tr '\n' ' ')" = "$before" ] \
		&& [ "$(cat "$elsewhere/booting")" = 00000000000000e1 ] && [ -L "$icd/apply" ]; then
		ok "a symlinked apply/ is never written or cleared through, and the box boots"
	else
		bad "symlinked apply/ (before: $before, after: $(cd "$elsewhere" && find . | sort | tr '\n' ' '), said: $(la_said la-applylink))"
	fi
fi

# (f) the GC renames into the trash every snapshot nothing names and every
# incomplete one, and keeps complete snapshots named by base, built, booting
# and a live apply's files; pins go once an hour old. Observed after the take's
# GC by a pass that then loses the lifetime lock (an instance already running),
# which must not move base; then a booting pass retires the rest.
if la_setup la-gc; then
	snapd="$icd/apply/snap"
	mk_snap() {
		mkdir -p "$snapd/$1/src"
		[ "$2" = complete ] && echo "{\"id\":\"$1\",\"comp\":\"none\",\"runner\":null,\"key\":null}" > "$snapd/$1/meta.json"
		return 0
	}
	mk_snap 00000000000000a1 complete    # base
	mk_snap 00000000000000a2 complete    # built
	mk_snap 00000000000000a3 complete    # an intent's target
	mk_snap 00000000000000a4 complete    # nothing names it
	mk_snap 00000000000000a5 incomplete  # nothing names it
	mk_snap 00000000000000a6 incomplete  # named by inflight.json, but incomplete
	mk_snap 00000000000000a7 complete    # an earlier pass's boot snapshot (booting)
	mk_snap 00000000000000a8 complete    # a live apply's S (apply/active) only
	mk_snap 00000000000000a9 complete    # named by inflight.json only
	ln -s snap/00000000000000a1 "$icd/apply/base"
	ln -s snap/00000000000000a2 "$icd/apply/built"
	echo 00000000000000a7 > "$icd/apply/booting"
	mkdir -p "$icd/apply/rollback" "$icd/apply/pin/old" "$icd/apply/pin/fresh"
	echo '{"G":"1111111111111111","target":"base","target_id":"00000000000000a3"}' > "$icd/apply/rollback/1111111111111111.intent"
	echo '{"G":"2222222222222222","scratch_id":"00000000000000a6","target_id":"00000000000000a9"}' > "$icd/apply/inflight.json"
	echo '{"pid":4242,"phase":"build","scratch_id":"00000000000000a8"}' > "$icd/apply/active"
	touch -d '2 hours ago' "$icd/apply/pin/old"
	# Another launcher holds the lifetime lock: this pass takes its snapshot and
	# GCs, then exits 75 before it could promote anything.
	mkdir -p "$WORK/la-gc/run"
	exec {la_lock}>"$WORK/la-gc/run/cogbox-demo.lock"
	flock -n "$la_lock"
	la_run la-gc; rc=$?
	exec {la_lock}>&-
	new=$(head -n 1 "$icd/apply/booting" 2>/dev/null)
	trash=$(ls "$icd/apply/trash" 2>/dev/null | tr '\n' ' ')
	if [ "$rc" = 75 ] && [ -n "$new" ] && [ -f "$snapd/$new/meta.json" ] \
		&& [ "$(la_base_id)" = 00000000000000a1 ] && [ -L "$icd/apply/built" ] \
		&& [ "$(la_snaps)" = "$(printf '%s ' 00000000000000a1 00000000000000a2 00000000000000a3 00000000000000a8 00000000000000a9 "$new" | tr ' ' '\n' | sort | grep . | tr '\n' ' ')" ] \
		&& [ "$trash" = "00000000000000a4 00000000000000a5 00000000000000a6 00000000000000a7 pin-old " ] \
		&& [ -d "$icd/apply/pin/fresh" ]; then
		ok "the GC renames unnamed and incomplete snapshots and old pins into the trash, and keeps named ones"
	else
		bad "GC (rc=$rc, booting=$new, base=$(la_base_id), snaps=$(la_snaps), trash=$trash, said: $(la_said la-gc))"
	fi
	# Nothing in a daemon pass deleted a tree: the trash still holds them all
	# (the stub preboot never empties it; the real one does so only with
	# --init-only, which this pass never passed).
	if ! grep -q -- '--init-only' "$WORK/la-gc.la.log" && [ -f "$icd/apply/trash/00000000000000a4/meta.json" ]; then
		ok "a daemon pass never empties the trash"
	else
		bad "the daemon pass emptied the trash or passed --init-only (calls: $(cat "$WORK/la-gc.la.log"))"
	fi
	# The pass that boots (its housekeeping finished the rollback, so the
	# intent is gone and its target is no longer named) promotes its own
	# snapshot and retires the old base, built, the losing pass's snapshot and
	# the finished intent's target; the live apply's S and the inflight target
	# stay.
	la_run la-gc LA_PREBOOT_FINISH=1
	id=$(la_base_id)
	if la_booted la-gc "$la_base_runner" && [ -n "$id" ] && [ "$id" != "$new" ] && [ ! -e "$icd/apply/built" ] \
		&& [ "$(la_snaps)" = "$(printf '%s\n' 00000000000000a8 00000000000000a9 "$id" | sort | tr '\n' ' ')" ] \
		&& [ -d "$icd/apply/trash/00000000000000a1" ] && [ -d "$icd/apply/trash/00000000000000a2" ] \
		&& [ -d "$icd/apply/trash/00000000000000a3" ] && [ -d "$icd/apply/trash/$new" ]; then
		ok "a booting pass promotes its snapshot and retires the old base, built, an unbooted pass's snapshot and a finished intent's target"
	else
		bad "promotion GC (base=$id, snaps=$(la_snaps), trash=$(ls "$icd/apply/trash" | tr '\n' ' '), said: $(la_said la-gc))"
	fi
fi
# ...and when a live apply's file does not parse, the GC cannot know what it
# names, so it keeps EVERY snapshot, the incomplete ones included, and says so;
# the pass still boots and promotes its own. (An unparseable rollback intent is
# an unfinished rollback: section 11 below.)
for f in active inflight.json; do
	tag=la-gc-garbage-${f%%[./]*}
	if la_setup "$tag"; then
		snapd="$icd/apply/snap"
		mkdir -p "$snapd/00000000000000d1/src" "$snapd/00000000000000d2/src" "$icd/apply/rollback"
		echo '{"id":"00000000000000d1","comp":"none","runner":null,"key":null}' > "$snapd/00000000000000d1/meta.json"
		printf '{"scratch_id":"00000000000000d1",' > "$icd/apply/$f"
		la_run "$tag"
		id=$(la_base_id)
		if la_booted "$tag" "$la_base_runner" && [ -n "$id" ] \
			&& [ "$(la_snaps)" = "$(printf '%s\n' 00000000000000d1 00000000000000d2 "$id" | sort | tr '\n' ' ')" ] \
			&& [ -z "$(ls "$icd/apply/trash" 2>/dev/null)" ] \
			&& la_said "$tag" | grep -q "cannot read $icd/apply/$f; keeping every live-apply snapshot"; then
			ok "an unparseable apply/$f keeps every snapshot, incomplete ones included, and the box boots"
		else
			bad "unparseable apply/$f (base=$id, snaps=$(la_snaps), trash=$(ls "$icd/apply/trash" 2>&1), said: $(la_said "$tag"))"
		fi
	fi
done

# (g) a composition without a flake.lock (a first add whose `nix flake lock`
# failed only warned) still has a comp, the hash of an empty lock: the init
# pass records it as line 3, and the daemon pass then fast-paths, snapshots the
# lockless composition and promotes it -- as before line 3, when its two-line
# record fast-pathed every later pass. Without that, every pass would evaluate,
# the daemon pass inside start's 60s.
if la_setup la-nolock; then
	rm -f "$icd/plugins-flake/flake.lock"
	comp=$(comp_of "$icd/plugins-flake")
	la_run la-nolock --init-only
	pin=$(sed -n 's/^run pin=//p' "$WORK/la-nolock.la.log")
	rec3=$(sed -n 3p "$icd/runner.path")
	if [[ $rec3 =~ ^[0-9a-f]{64}$ ]] && [ "$rec3" = "$comp" ] \
		&& [ "$comp" = "$(printf '%s\n\0' '{ outputs = _: { }; }' | sha256sum | cut -d' ' -f1)" ] \
		&& [[ $pin == "$icd/apply/pin/"* ]] && [ -f "$pin/flake.nix" ] && [ ! -e "$pin/flake.lock" ] \
		&& grep -qx "run comp=$comp" "$WORK/la-nolock.la.log" \
		&& ! la_said la-nolock | grep -q 'could not hash'; then
		ok "a lockless composition's init pass records line 3 = the comp of an empty lock"
	else
		bad "lockless init pass (record line 3: '$rec3', want '$comp', calls: $(cat "$WORK/la-nolock.la.log"), said: $(la_said la-nolock))"
	fi
	: > "$WORK/la-nolock.la.log"
	la_run la-nolock
	id=$(la_base_id)
	if la_booted la-nolock "$la_base_runner" && ! grep -q '^run ' "$WORK/la-nolock.la.log" && [ -n "$id" ] \
		&& [ -f "$icd/apply/snap/$id/composition/flake.nix" ] && [ ! -e "$icd/apply/snap/$id/composition/flake.lock" ] \
		&& [ "$(jq -r .comp "$icd/apply/snap/$id/meta.json")" = "$comp" ] \
		&& [ "$(sed -n 3p "$WORK/la-nolock.mark.booted-runner")" = "$comp" ] \
		&& ! la_said la-nolock | grep -q 'could not take\|could not hash'; then
		ok "a lockless composition's daemon pass fast-paths, snapshots it without a lock and promotes it"
	else
		bad "lockless daemon pass (base=$id, snaps=$(la_snaps), calls: $(cat "$WORK/la-nolock.la.log"), said: $(la_said la-nolock))"
	fi
fi

# (h) a nearly full state disk: below the free-space floor (64 MiB, or 16384
# free inodes where the filesystem counts them) a pass writes NO snapshot, pin
# or gcroot -- each would use blocks and inodes the rest of the boot (the
# .app-launch record on the same disk) may need -- and boots exactly as before,
# with one warning: on the fast path, on the re-exec (straight from
# plugins-flake, with the comp of those bytes), and in an init pass.
# A filesystem that reports no inode count (btrfs) is judged on blocks alone.
for statfs in "100 4096 1000000 500000 1000000 200" "268435456 4096 1000000 100 268500000 268440000"; do
	tag=la-lowspace-${statfs%% *}
	if la_setup "$tag"; then
		la_runner "$WORK/$tag/fp-runner"
		comp=$(comp_of "$icd/plugins-flake")
		la_record "$WORK/$tag/fp-runner" "$comp"
		la_run "$tag" LA_STATFS="$statfs"
		if la_booted "$tag" "$WORK/$tag/fp-runner" && ! grep -q '^run ' "$WORK/$tag.la.log" \
			&& [ ! -e "$icd/apply" ] && [ ! -e "$icd/gcroots/booted" ] \
			&& [ "$(sed -n 3p "$WORK/$tag.mark.booted-runner")" = "$comp" ] \
			&& [ "$(la_said "$tag" | grep -c 'skipping the live-apply boot snapshot')" = 1 ]; then
			ok "under the free-space floor ($statfs) the fast-path pass writes no snapshot or gcroot, warns once, and boots"
		else
			bad "low space on the fast path ($statfs; apply: $(ls -A "$icd/apply" 2>&1), calls: $(cat "$WORK/$tag.la.log"), said: $(la_said "$tag"))"
		fi
		rm -f "$icd/runner.path"
		: > "$WORK/$tag.la.log"
		la_run "$tag" LA_STATFS="$statfs"
		if la_booted "$tag" "$la_base_runner" && grep -qx "run pin=$icd/plugins-flake" "$WORK/$tag.la.log" \
			&& grep -qx "run comp=$comp" "$WORK/$tag.la.log" && grep -qx 'run snap=<unset>' "$WORK/$tag.la.log" \
			&& grep -qx 'run low-space=1' "$WORK/$tag.la.log" && [ "$(grep -c '^statfs ' "$WORK/$tag.la.log")" = 1 ] \
			&& [ ! -e "$icd/apply" ] && [ ! -e "$icd/gcroots/booted" ] && [ "$(sed -n 3p "$icd/runner.path")" = "$comp" ] \
			&& [ "$(la_said "$tag" | grep -c 'skipping the live-apply boot snapshot')" = 1 ] \
			&& ! la_said "$tag" | grep -q 'could not pin'; then
			ok "under the free-space floor ($statfs) the re-exec evaluates plugins-flake as before, warns once, and boots"
		else
			bad "low space on the re-exec ($statfs; apply: $(ls -A "$icd/apply" 2>&1), calls: $(cat "$WORK/$tag.la.log"), said: $(la_said "$tag"))"
		fi
		rm -f "$icd/runner.path"
		: > "$WORK/$tag.la.log"
		la_run "$tag" --init-only LA_STATFS="$statfs"
		if grep -qx "run pin=$icd/plugins-flake" "$WORK/$tag.la.log" && [ ! -e "$icd/apply" ] \
			&& [ "$(sed -n 3p "$icd/runner.path")" = "$comp" ] \
			&& [ "$(la_said "$tag" | grep -c 'skipping the live-apply boot snapshot')" = 1 ]; then
			ok "under the free-space floor ($statfs) an init pass writes no pin and evaluates plugins-flake as before"
		else
			bad "low space in an init pass ($statfs; calls: $(cat "$WORK/$tag.la.log"), said: $(la_said "$tag"))"
		fi
	fi
done
# ...the verdict crosses the re-exec: a first hop that found the disk low tells
# its second hop (which then neither re-checks nor warns); one that found it
# fine does not, and a second hop that finds it low by then skips its gcroot
# and says so, after the first hop's snapshot was taken and is promoted.
if la_setup la-lowspace-hop2; then
	la_run la-lowspace-hop2 LA_STATFS_HOP2="100 4096 1000000 500000 1000000 200"
	if la_booted la-lowspace-hop2 "$la_base_runner" && grep -qx 'run low-space=<unset>' "$WORK/la-lowspace-hop2.la.log" \
		&& [ -n "$(la_base_id)" ] && [ ! -e "$icd/gcroots/booted" ] \
		&& [ "$(la_said la-lowspace-hop2 | grep -c 'skipping the live-apply boot snapshot')" = 1 ]; then
		ok "a disk that fills during the eval: the second hop finds it low itself, skips its gcroot and warns"
	else
		bad "low space in the second hop only (calls: $(cat "$WORK/la-lowspace-hop2.la.log"), said: $(la_said la-lowspace-hop2))"
	fi
fi
if la_setup la-btrfs; then
	la_run la-btrfs LA_STATFS="268435456 4096 0 0 268500000 268440000"
	if la_booted la-btrfs "$la_base_runner" && [ -n "$(la_base_id)" ] \
		&& ! la_said la-btrfs | grep -q 'skipping the live-apply boot snapshot'; then
		ok "a filesystem that reports no inode count (btrfs) with blocks to spare still gets its boot snapshot"
	else
		bad "no inode count (snaps=$(la_snaps), said: $(la_said la-btrfs))"
	fi
fi

# (i) a take is sized against the room ABOVE the floor, not the floor alone: a
# `cp -al` costs one inode and the blocks of each directory it copies, and a
# ?dir= plugin brings its whole repo, so a disk that passes the floor can still
# have fewer inodes (or blocks) above it than plugin-sources has directories.
# That take is skipped before cp can use them up -- what the rest of the pass
# (.app-launch, on the same disk on GCE/PVE) needs -- and the box boots as
# before with one warning: on the fast path with no snapshot and nothing left
# behind (apply/trash is ready for a later GC), on the re-exec from a pin. The
# walk stops once the tree exceeds the room (553 directories for a room of
# 17000 - 16384 - 64 inodes). A tree that fits is taken; with more room than
# the filesystem uses (the common case) nothing is walked; and with no room
# at all above the floor the take is skipped without a walk.
la_tight_inodes="268435456 4096 1000000 17000 268500000 268440000"
if la_setup la-room; then
	mkdir -p "$icd/plugin-sources/a/big"
	( cd "$icd/plugin-sources/a/big" && mkdir d{1..700} )
	la_runner "$WORK/la-room/fp-runner"
	comp=$(comp_of "$icd/plugins-flake")
	la_record "$WORK/la-room/fp-runner" "$comp"
	la_run la-room LA_STATFS="$la_tight_inodes"
	if la_booted la-room "$WORK/la-room/fp-runner" && grep -qx "find $icd/plugin-sources" "$WORK/la-room.la.log" \
		&& [ -z "$(la_snaps)" ] && [ -d "$icd/apply/trash" ] && [ -z "$(ls -A "$icd/apply/trash")" ] \
		&& [ ! -e "$icd/apply/pin" ] && [ ! -e "$icd/apply/base" ] && [ ! -e "$icd/apply/booting" ] && [ -L "$icd/gcroots/booted" ] \
		&& [ "$(la_said la-room | grep -c 'warning: .*live-apply')" = 1 ] \
		&& la_said la-room | grep -q 'could not take the live-apply boot snapshot .*(at least 553, [0-9]* KiB) does not fit above the free-space floor (64 MiB, 16384 inodes)'; then
		ok "a take whose directories exceed the inodes above the floor is skipped before cp: the fast path boots, nothing left behind, one warning"
	else
		bad "oversized take on the fast path (snaps=$(la_snaps), trash=$(ls -A "$icd/apply/trash" 2>&1), calls: $(cat "$WORK/la-room.la.log"), said: $(la_said la-room))"
	fi
	rm -f "$icd/runner.path"
	: > "$WORK/la-room.la.log"
	la_run la-room LA_STATFS="$la_tight_inodes"
	pin=$(sed -n 's/^run pin=//p' "$WORK/la-room.la.log")
	if la_booted la-room "$la_base_runner" && [[ $pin == "$icd/apply/pin/"* ]] \
		&& grep -qx "run comp=$comp" "$WORK/la-room.la.log" && grep -qx 'run snap=<unset>' "$WORK/la-room.la.log" \
		&& [ -z "$(la_snaps)" ] && [ ! -e "$icd/apply/base" ] \
		&& la_said la-room | grep -q 'does not fit above the free-space floor'; then
		ok "a take whose directories exceed the inodes above the floor is skipped on the re-exec too, which boots from a pin"
	else
		bad "oversized take on the re-exec (pin=$pin, calls: $(cat "$WORK/la-room.la.log"), said: $(la_said la-room))"
	fi
fi
if la_setup la-room-fits; then
	la_run la-room-fits LA_STATFS="$la_tight_inodes"
	if la_booted la-room-fits "$la_base_runner" && grep -qx "find $icd/plugin-sources" "$WORK/la-room-fits.la.log" \
		&& [ -n "$(la_base_id)" ] && [ -f "$icd/apply/snap/$(la_base_id)/src/a/sub/module.nix" ] \
		&& ! la_said la-room-fits | grep -q 'could not take'; then
		ok "a tree that fits above the floor is sized and taken"
	else
		bad "fitting take (base=$(la_base_id), calls: $(cat "$WORK/la-room-fits.la.log"), said: $(la_said la-room-fits))"
	fi
	: > "$WORK/la-room-fits.la.log"
	la_run la-room-fits
	if la_booted la-room-fits "$la_base_runner" && [ -n "$(la_base_id)" ] && ! grep -q '^find ' "$WORK/la-room-fits.la.log"; then
		ok "with more room above the floor than the filesystem uses, the take is not sized (O(1))"
	else
		bad "O(1) sizing (base=$(la_base_id), calls: $(cat "$WORK/la-room-fits.la.log"))"
	fi
	# Blocks: 1000 blocks above the floor, less the snapshot's 1 MiB margin,
	# hold 2976 KiB; four directories of 1024 KiB each do not fit.
	: > "$WORK/la-room-fits.la.log"
	la_run la-room-fits LA_STATFS="17384 4096 0 0 1000000 17384" LA_FIND_KIB=1024
	if la_booted la-room-fits "$la_base_runner" && [ ! -e "$icd/apply/base" ] && [ -z "$(la_snaps)" ] \
		&& grep -qx "find $icd/plugin-sources" "$WORK/la-room-fits.la.log" \
		&& la_said la-room-fits | grep -q '(at least 4, 4096 KiB) does not fit above the free-space floor'; then
		ok "a take whose directories exceed the blocks above the floor is skipped, and the box boots"
	else
		bad "oversized take by blocks (snaps=$(la_snaps), calls: $(cat "$WORK/la-room-fits.la.log"), said: $(la_said la-room-fits))"
	fi
	: > "$WORK/la-room-fits.la.log"
	la_run la-room-fits LA_STATFS="268435456 4096 1000000 16400 268500000 268440000"
	if la_booted la-room-fits "$la_base_runner" && [ ! -e "$icd/apply/base" ] && [ -z "$(la_snaps)" ] \
		&& ! grep -q '^find ' "$WORK/la-room-fits.la.log" \
		&& la_said la-room-fits | grep -q '(no room above the free-space floor (64 MiB, 16384 inodes) for a copy'; then
		ok "with no inodes above the floor (but not under it) the take is skipped without a walk, and the box boots"
	else
		bad "no room above the floor (snaps=$(la_snaps), calls: $(cat "$WORK/la-room-fits.la.log"), said: $(la_said la-room-fits))"
	fi
fi

# (j) a take that runs the disk out of room anyway (the walk's estimate was off,
# or something else filled the disk meanwhile) gives the space back at once:
# its partial tree is REMOVED, not renamed (a rename frees nothing, and the
# init pass that empties the trash runs only at the next start), when cp says
# ENOSPC (case d) or a statfs after the failure reads under the floor. A
# removal that outlasts its bound (half the take's) leaves the rest to the GC's
# rename, and the pass then writes nothing more (no pin, no gcroot), as under
# the floor; the box boots either way. apply/trash exists before the take, so
# that rename works even on a disk too full for a new directory.
if la_setup la-undo; then
	la_runner "$WORK/la-undo/fp-runner"
	comp=$(comp_of "$icd/plugins-flake")
	la_record "$WORK/la-undo/fp-runner" "$comp"
	la_run la-undo LA_CP_FAIL="Too many links" LA_STATFS_AFTER_CP="100 4096 1000000 500000 1000000 200"
	if la_booted la-undo "$WORK/la-undo/fp-runner" && [ -z "$(la_snaps)" ] \
		&& [ -d "$icd/apply/trash" ] && [ -z "$(ls -A "$icd/apply/trash")" ] && [ ! -e "$icd/apply/base" ] \
		&& la_said la-undo | grep -q 'could not take the live-apply boot snapshot .*(the disk ran out of room for it, so its partial tree was removed)'; then
		ok "a take that leaves the disk under the floor removes its partial tree at once, and the box boots"
	else
		bad "undo of a take under the floor (snaps=$(la_snaps), trash=$(ls -A "$icd/apply/trash" 2>&1), calls: $(cat "$WORK/la-undo.la.log"), said: $(la_said la-undo))"
	fi
fi
if la_setup la-undo-slow; then
	la_runner "$WORK/la-undo-slow/fp-runner"
	comp=$(comp_of "$icd/plugins-flake")
	la_record "$WORK/la-undo-slow/fp-runner" "$comp"
	t0=$SECONDS
	la_run la-undo-slow LA_CP_FAIL="No space left on device" LA_RM_SLOW=30 LA_MKDIR_FULL=1 COGBOX_BOOT_SNAPSHOT_TIMEOUT=3
	took=$((SECONDS - t0))
	partial=$(ls "$icd/apply/trash" 2>/dev/null)
	if la_booted la-undo-slow "$WORK/la-undo-slow/fp-runner" && [ "$took" -lt 15 ] \
		&& grep -qx rm-stalled "$WORK/la-undo-slow.la.log" && [ -z "$(la_snaps)" ] \
		&& [ -n "$partial" ] && [ -e "$icd/apply/trash/$partial/src/partial-entry" ] \
		&& [ ! -e "$icd/gcroots/booted" ] && [ ! -e "$icd/apply/base" ] \
		&& la_said la-undo-slow | grep -q 'could not remove the partial live-apply boot snapshot .* within 2s'; then
		ok "a removal that outlasts its bound leaves the partial tree to the trash and skips the gcroot: the box boots in ${took}s"
	else
		bad "stalled undo on the fast path (took ${took}s, snaps=$(la_snaps), trash=$(ls -A "$icd/apply/trash" 2>&1), calls: $(cat "$WORK/la-undo-slow.la.log"), said: $(la_said la-undo-slow))"
	fi
	rm -f "$icd/runner.path"
	: > "$WORK/la-undo-slow.la.log"
	la_run la-undo-slow LA_CP_FAIL="No space left on device" LA_RM_SLOW=30 COGBOX_BOOT_SNAPSHOT_TIMEOUT=3
	if la_booted la-undo-slow "$la_base_runner" && grep -qx "run pin=$icd/plugins-flake" "$WORK/la-undo-slow.la.log" \
		&& grep -qx "run comp=$comp" "$WORK/la-undo-slow.la.log" && grep -qx 'run low-space=1' "$WORK/la-undo-slow.la.log" \
		&& [ ! -e "$icd/apply/pin" ] && [ ! -e "$icd/gcroots/booted" ] && ! la_said la-undo-slow | grep -q 'could not pin'; then
		ok "a removal that outlasts its bound on the re-exec evaluates plugins-flake as under the floor, and the box boots"
	else
		bad "stalled undo on the re-exec (calls: $(cat "$WORK/la-undo-slow.la.log"), said: $(la_said la-undo-slow))"
	fi
fi

# (z) live-runner (what a live apply confirmed during the previous boot) never
# outlives that boot: the daemon pass recreates the runtime dir under the
# lifetime lock before QEMU starts, so the runtime dir names only what this
# boot runs (booted-runner); an init pass, which boots nothing, leaves a
# running instance's copy alone.
if la_setup la-liverun; then
	la_runner "$WORK/la-liverun/fp-runner"
	comp=$(comp_of "$icd/plugins-flake")
	la_record "$WORK/la-liverun/fp-runner" "$comp"
	lr="$WORK/la-liverun/run/cogbox-demo/live-runner"
	mkdir -p "${lr%/*}"
	printf '%s\n%s\n%s\n%s\n' "$la_rkey" /nix/store/rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr-microvm-run "$comp" 4242 > "$lr"
	la_run la-liverun --init-only
	init_kept=0
	[ -s "$lr" ] && init_kept=1
	rm -f "$WORK/la-liverun.mark.live-runner"
	la_run la-liverun
	if [ "$init_kept" = 1 ] && la_booted la-liverun "$WORK/la-liverun/fp-runner" \
		&& [ ! -e "$WORK/la-liverun.mark.live-runner" ] && [ ! -e "$lr" ] \
		&& [ -s "$WORK/la-liverun.mark.booted-runner" ]; then
		ok "a daemon pass never boots with the previous boot's live-runner; an init pass leaves it"
	else
		bad "stale live-runner (init kept: $init_kept, at QEMU start: $(cat "$WORK/la-liverun.mark.live-runner" 2>&1), after: $(cat "$lr" 2>&1), said: $(la_said la-liverun))"
	fi
fi

# --- 11. an automatic plugin rollback that could not be finished blocks the boot
# The launcher never relies on __plugin-apply-preboot's exit status for this:
# after the verb returns (or crashes, or is killed), it looks for a rollback
# intent itself. On a stopped instance one left behind exits 78 with the
# `cogbox: `-stamped line the GCE/PVE supervisor publishes, before any boot
# snapshot or promotion; on a running instance (an init pass, which boots
# nothing) a live apply may have just written it, so it only warns.
la_intent_json='{"G":"0123456789abcdef","reason":"activation_hang","target":"base","target_id":"00000000000000aa","scope":[]}'
la_intent() {
	mkdir -p "$icd/apply/rollback"
	if [ $# -gt 0 ]; then printf '%s' "$1"; else printf '%s' "$la_intent_json"; fi \
		> "$icd/apply/rollback/0123456789abcdef.intent"
}
la_stamped() { la_said "$1" | grep -c "^cogbox: an automatic plugin rollback could not be finished ($2); free disk space, or run 'cogbox plugin apply --abandon-rollback -n demo'\$"; }
if la_setup la-78; then
	la_runner "$WORK/la-78/fp-runner"
	la_record "$WORK/la-78/fp-runner" "$(comp_of "$icd/plugins-flake")"
	mkdir -p "$icd/apply"
	for how in "" LA_PREBOOT_KILL=1 LA_PREBOOT_RC=1; do
		la_intent
		: > "$WORK/la-78.la.log"
		before=$(la_snaps)
		# shellcheck disable=SC2086 # an empty $how adds nothing
		la_run la-78 $how; rc=$?
		case "$how" in
			"") why="the live-apply housekeeping exited 0" ;;
			LA_PREBOOT_KILL=1) why="the live-apply housekeeping exited 137" ;;
			*) why="the live-apply housekeeping exited 1" ;;
		esac
		if [ "$rc" = 78 ] && [ ! -e "$WORK/la-78.mark" ] && grep -q '^cogbox __plugin-apply-preboot' "$WORK/la-78.la.log" \
			&& [ "$(la_stamped la-78 "$why")" = 1 ] && [ "$(la_snaps)" = "$before" ] \
			&& [ ! -e "$icd/apply/base" ] && [ ! -e "$icd/apply/booting" ] && ! grep -q '^run ' "$WORK/la-78.la.log" \
			&& [ -e "$icd/apply/rollback/0123456789abcdef.intent" ]; then
			ok "a rollback intent left on a stopped instance (preboot ${how:-exits 0}) exits 78 with the stamped line, before any snapshot"
		else
			bad "pending intent, preboot '${how:-exit 0}' (rc=$rc, snaps: $(la_snaps), calls: $(cat "$WORK/la-78.la.log"), said: $(la_said la-78))"
		fi
	done
	# The verb's own 78 carries its own stamped line; the launcher adds none.
	: > "$WORK/la-78.la.log"
	la_run la-78 LA_PREBOOT_RC=78; rc=$?
	if [ "$rc" = 78 ] && [ ! -e "$WORK/la-78.mark" ] && [ "$(la_said la-78 | grep -c '^cogbox: an automatic plugin rollback')" = 0 ] \
		&& ! la_said la-78 | grep -q 'housekeeping (__plugin-apply-preboot) exited'; then
		ok "a preboot that exits 78 itself (its message printed) is not repeated or warned about, and the pass exits 78"
	else
		bad "preboot exit 78 (rc=$rc, said: $(la_said la-78))"
	fi
	# An unparseable (here zero-length) intent is an unfinished rollback too.
	la_intent ""
	: > "$WORK/la-78.la.log"
	la_run la-78; rc=$?
	if [ "$rc" = 78 ] && [ ! -e "$WORK/la-78.mark" ] && [ "$(la_stamped la-78 "the live-apply housekeeping exited 0")" = 1 ]; then
		ok "a zero-length intent blocks the boot the same way"
	else
		bad "zero-length intent (rc=$rc, said: $(la_said la-78))"
	fi
	# An init pass of a stopped instance refuses too (cogbox start never gets
	# to its daemon pass).
	: > "$WORK/la-78.la.log"
	la_run la-78 --init-only; rc=$?
	if [ "$rc" = 78 ] && grep -q -- '--init-only$' "$WORK/la-78.la.log" && [ "$(la_stamped la-78 "the live-apply housekeeping exited 0")" = 1 ]; then
		ok "an init pass of a stopped instance with a pending rollback exits 78"
	else
		bad "init pass with an intent (rc=$rc, said: $(la_said la-78))"
	fi
	# On a running instance (the lifetime lock held) an init pass only warns,
	# and a daemon pass loses the lifetime lock as before (75, not 78).
	mkdir -p "$WORK/la-78/run"
	exec {la_lock}>"$WORK/la-78/run/cogbox-demo.lock"
	flock -n "$la_lock"
	: > "$WORK/la-78.la.log"
	la_run la-78 --init-only; rc_init=$?
	said_init=$(la_said la-78)
	la_run la-78; rc_daemon=$?
	said_daemon=$(la_said la-78)
	exec {la_lock}>&-
	if [ "$rc_init" = 0 ] && [ "$rc_daemon" = 75 ] \
		&& [ "$(printf '%s\n%s\n' "$said_init" "$said_daemon" | grep -c '^cogbox: an automatic plugin rollback')" = 0 ] \
		&& grep -q 'warning: an automatic plugin rollback is pending' <<<"$said_init" \
		&& grep -q 'warning: an automatic plugin rollback is pending' <<<"$said_daemon"; then
		ok "with the instance running, a pending rollback only warns (init 0, daemon 75)"
	else
		bad "intent on a running instance (init rc=$rc_init, said: $said_init; daemon rc=$rc_daemon, said: $said_daemon; calls: $(cat "$WORK/la-78.la.log"); rollback: $(ls -la "$icd/apply/rollback" 2>&1))"
	fi
	# Once the intent is gone (finished, or moved aside by --abandon-rollback)
	# the box boots.
	: > "$WORK/la-78.la.log"
	la_run la-78 LA_PREBOOT_FINISH=1; rc=$?
	if [ "$rc" = 0 ] && la_booted la-78 "$WORK/la-78/fp-runner" && [ -n "$(la_base_id)" ]; then
		ok "a pass whose housekeeping finished the rollback boots"
	else
		bad "finished rollback boot (rc=$rc, said: $(la_said la-78))"
	fi
	# A tmp name an intent writer left is not an intent.
	mkdir -p "$icd/apply/rollback"
	: > "$icd/apply/rollback/.0123456789abcdef.intent.4242.tmp"
	la_run la-78; rc=$?
	if [ "$rc" = 0 ] && la_booted la-78 "$WORK/la-78/fp-runner"; then
		ok "a leftover intent tmp name does not block the boot"
	else
		bad "intent tmp name (rc=$rc, said: $(la_said la-78))"
	fi
fi

# --- 12. the per-instance flake scaffold: one text in two places ------------
# The live apply decides `customized_flake` by comparing flake/flake.nix with
# its own copy of SCAFFOLD_FLAKE (zig/src/plugin/apply.zig scaffold_flake).
# The launcher boots its base runner only while flake.nix is its scaffold, so
# the two copies must be the same bytes: an edit to one alone makes every
# instance created afterwards answer restart_required/customized_flake once its
# last plugin is gone, or lets an apply build against the base runner while the
# next boot re-execs from the user flake. The launcher's text is the value its
# own assignment gives (shell-evaluated, quoting included); the Zig text is the
# concatenated literal, its escapes decoded.
launcher_scaffold="$WORK/scaffold.launcher"
zig_scaffold="$WORK/scaffold.zig"
assign=$(sed -n "/^SCAFFOLD_FLAKE='/,/^'\$/p" "$LAUNCH")
if [ -z "$assign" ]; then
	bad "no SCAFFOLD_FLAKE='...' assignment found in the launcher"
else
	( eval "$assign" && printf '%s' "$SCAFFOLD_FLAKE" ) > "$launcher_scaffold"
	python3 - "$APPLY_ZIG" "$zig_scaffold" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r'pub const scaffold_flake =\n(.*?);\n', src, re.S)
if not m:
    sys.exit("no `pub const scaffold_flake = ...;` in " + sys.argv[1])
parts = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
esc = {"n": "\n", "t": "\t", '"': '"', "\\": "\\", "'": "'"}
out = re.sub(r'\\(.)', lambda e: esc[e.group(1)], "".join(parts))
open(sys.argv[2], "w").write(out)
PY
	if [ ! -s "$zig_scaffold" ] || [ ! -s "$launcher_scaffold" ]; then
		bad "could not extract the scaffold (launcher: $(wc -c < "$launcher_scaffold") bytes, apply.zig: $(wc -c < "$zig_scaffold" 2>/dev/null || echo 0) bytes)"
	elif cmp -s "$launcher_scaffold" "$zig_scaffold"; then
		ok "the launcher's SCAFFOLD_FLAKE and apply.zig's scaffold_flake are the same bytes ($(sha256sum < "$zig_scaffold" | cut -c1-16))"
	else
		bad "SCAFFOLD_FLAKE (cogbox-launch.sh) and scaffold_flake (apply.zig) differ: $(diff "$launcher_scaffold" "$zig_scaffold" | head -5 | tr '\n' ' ')"
	fi
fi

if [ "$fails" -gt 0 ]; then
	echo "$fails check(s) failed" >&2
	exit 1
fi
echo "all launch-flag checks passed"
