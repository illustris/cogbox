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
# Usage: test_launch_flags.sh <path-to-cogbox-launch.sh>
# Needs: bash, jq, coreutils. NOT passt/qemu/nix -- every case stops at
# --init-only or fails before the launch.

set -uo pipefail

LAUNCH="${1:?usage: test_launch_flags.sh <cogbox-launch.sh>}"
[ -f "$LAUNCH" ] || { echo "FAIL: no such script: $LAUNCH" >&2; exit 1; }

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
		&& ! sed -n "${mv_ln},${call_ln}p" "$LAUNCH" | grep -q '^\s*else$\|^\s*fi$'; then
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
rp_fastpath() {
	mkdir -p "$WORK/$1/fake-runner/bin" && : > "$WORK/$1/fake-runner/bin/microvm-run"
	printf '%s\n%s\n' "$rp_rkey" "$WORK/$1/fake-runner" > "$icd/runner.path"
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

if [ "$fails" -gt 0 ]; then
	echo "$fails check(s) failed" >&2
	exit 1
fi
echo "all launch-flag checks passed"
