#!/usr/bin/env bash
# Behavioural test for the PVE site floor (pve/floor-site.nix, rendered by
# pve/floor_render.py): nft table inet cogworx_pve_floor, rules 4a and 4. The
# floor filters no ingress (decision 2026-10-21; floor_render.py's "No ingress
# filter"), and section 3 shows that too.
#
#   1. the validator refuses what it must (IPv4-only, canonical, at most /8,
#      no overlap with 127/8, 169.254/16 or 0/8, exact infraAllow entries,
#      plain names, the removed ingress keys) and accepts the boundaries;
#   2. the rendered ruleset, pinned byte for byte, plus the properties that
#      matter stated one by one (every uid/gid deny is `ct direction
#      original`; the mosh-reply and infraAllow accepts come first; the only
#      @cp accept is passt's mosh replies; the input chain is rule 4a's input
#      drop alone);
#   3. LIVE, in a throwaway user+network namespace with real listeners: rule
#      4a (root reaches link-local, a non-root uid does not; a link-local source
#      never leaves eth0; a neighbour's datagram for the metadata address,
#      arriving over a veth from a second namespace, is dropped on input
#      whatever its source, @cp included), rule 4 ("a passt-uid NEW flow to
#      @infra4 drops", "a passt NEW tcp flow to @cp drops when @cp sits inside
#      @infra4", "a passt mosh reply -- udp from the mosh range -- to @cp
#      passes", "a passt-uid REPLY to a @cp address passes", the same reply to
#      a non-@cp internal address passes because of the direction scoping, and
#      so does passt's mosh reply on a flow a non-@cp relay opened -- what an
#      empty @cp relies on --, infraAllow is reachable, the build group is
#      dropped, @cp included), and open ingress (over the same veth, a
#      neighbour outside @infra4, one inside @infra4 but outside @cp, and one
#      inside both all reach sshd, a guest SSH forward, a guest HTTP forward
#      and the mosh range), each with a negative control that removes the
#      property and shows the probe catching it;
#   4. with the realized gce floor scripts given, the gce floor and this one
#      loaded TOGETHER: gce/floor.nix's own verifier passes the probes that run
#      as the control uid (4 and 5); probes 1, 3, 6, 7 and 8, which name the
#      passt uid, are modelled with passt re-pointed at uid 0 in both tables;
#      and root still reaches the metadata address. Probe 2 is the one of the
#      eight that cannot be modelled in a one-uid namespace (see section 4).
#
# Usage: test_floor_site.sh [RENDERER [REALIZED_RULESET|- [GCE_INSTALL GCE_VERIFY]]]
#   RENDERER          floor_render.py (default: ../floor_render.py)
#   REALIZED_RULESET  the ruleset floor-site.nix built for checks.nix's fixture
#                     system; asserted equal to section 2's golden file. `-` skips.
#   GCE_INSTALL/VERIFY the realized cogworx-floor ExecStart/ExecStartPost, for
#                     section 4.
# Needs python3 and grep for sections 1-2. Sections 3-4 additionally need
# unshare, ip and nft and a kernel with nftables + conntrack + dummy links, and
# SKIP loudly when the namespace cannot host them; the rule 4a input probe and
# the open-ingress cases also need veth links and nsenter, and skip loudly on
# their own without them (checks.nix asserts on the realized ruleset that the
# input chain is rule 4a's input drop alone regardless).
# Nothing touches the host's own ruleset, addresses or routes.
#
# SKUID IN A USER NAMESPACE. nft resolves `meta skuid` against the network
# namespace's OWNER user namespace, so inside `unshare -Urn` our own sockets
# read as uid 0 and match exactly as root's would on the VM. Only ONE uid is
# mapped, so "this probe runs as the passt uid" is modelled the way
# tests/test_floor.sh models it: the rule naming the account is rewritten to
# uid 0. The users the ruleset names do not exist here (nft refuses unknown
# names), so the base load rewrites them to unused numeric ids first; every
# rewrite is a sed whose hit count is asserted, so a renderer change cannot
# silently turn a case vacuous.

set -uo pipefail

fails=0
ok()  { echo "ok   - $*"; }
bad() { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROBE="$HERE/netprobe.py"
# A missing helper is a broken test, not an environment that cannot host it.
[ -r "$PROBE" ] || { echo "FAIL: $PROBE is missing; run this script from its directory's copy" >&2; exit 1; }

# --- sections 3 and 4: the child, re-exec'd inside `unshare -Urn` ------------
if [ "${1:-}" = --live-child ]; then
	RUN="$2"
	GCE_VERIFY="${3:-}"
	echo "LIVE-BEGIN"
	SELF=192.0.2.10        # eth0's DHCP address
	CP=198.18.7.5          # control plane, INSIDE @infra4 (198.18.0.0/15)
	INFRA=198.18.9.9       # internal, not control plane
	ALLOW=203.0.113.80     # internal, with a tcp/443 infraAllow exception
	OUTSIDE=192.0.2.99     # a neighbour on the shared segment
	MD=169.254.169.254
	PIDS=()
	cleanup() {
		local p
		for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
		wait 2>/dev/null || true
	}
	trap cleanup EXIT

	ip link set lo up 2>/dev/null || { echo "LIVE-SKIP: cannot bring up lo"; exit 77; }
	ip link add eth0 type dummy 2>/dev/null || { echo "LIVE-SKIP: cannot create a dummy eth0"; exit 77; }
	ip link set eth0 up
	ip addr add "$SELF/24" dev eth0
	ip addr add "$MD/32" scope host dev lo
	for a in "$CP" "$INFRA" "$ALLOW" "$OUTSIDE" 169.254.10.10; do
		ip addr add "$a/32" dev lo || { echo "LIVE-SKIP: cannot assign $a"; exit 77; }
	done

	# The base load: the account names this sandbox does not have, parked on
	# unused numeric ids. Exactly one line each, or the case below that
	# re-points one of them would test something else.
	# SRC overrides the ruleset (default: the fixture's).
	load() {
		local -a extra=()
		[ $# -gt 0 ] && extra=(-e "$1")
		sed -e 's/meta skuid { "cogbox-passt", "cogbox-proxy" }/meta skuid { 65532, 65533 }/' \
			-e 's/meta skuid "cogbox-passt" ip daddr @cp/meta skuid 65532 ip daddr @cp/' \
			-e 's/meta skgid "nixbld"/meta skgid 65533/' \
			${extra[@]+"${extra[@]}"} "${SRC:-$RUN/base.nft}" > "$RUN/live.nft"
		nft -f "$RUN/live.nft" 2>&1
	}
	# passt modelled as uid 0, in BOTH rules that name it: rule 4's drop and
	# its mosh-reply accept.
	PASST0='s/meta skuid { 65532, 65533 }/meta skuid { 0, 65533 }/; s/meta skuid 65532 ip daddr @cp/meta skuid 0 ip daddr @cp/'
	listen() {
		local kind="$1" addr="$2" port="$3" ready="$RUN/ready.$1.$2.$3"
		rm -f "$ready"
		python3 "$PROBE" listen "$kind" "$addr" "$port" "$ready" ${4:+"$4"} >/dev/null 2>&1 &
		PIDS+=($!)
		for _ in $(seq 50); do [ -e "$ready" ] && return 0; sleep 0.1; done
		echo "LIVE-SKIP: listener $kind $addr:$port never bound"
		exit 77
	}
	conn() { python3 "$PROBE" connect "$@"; }
	udp() { python3 "$PROBE" udp "$@"; }
	expect() {
		local want="$1" what="$2" got
		shift 2
		got=$("$@")
		if [ "$got" = "$want" ]; then ok "live: $what"; else bad "live: $what -- got $got, expected $want"; fi
	}
	counter() {
		nft list chain inet cogworx_pve_floor "${2:-output}" | grep -F "$1" | grep -o 'packets [0-9]*' | cut -d' ' -f2
	}

	if ! out=$(load); then
		echo "LIVE-SKIP: nft could not load the rendered ruleset here: $out"
		exit 77
	fi
	for pat in 'meta skuid { 65532, 65533 }' 'meta skuid 65532 ip daddr @cp' 'meta skgid 65533'; do
		if [ "$(grep -cF "$pat" "$RUN/live.nft")" != 1 ]; then
			bad "live: the base rewrite '$pat' did not land on exactly one rule: $(cat "$RUN/live.nft")"
		fi
	done
	ok "live: the rendered ruleset loads"
	if out=$(SRC="$RUN/empty.nft" load); then
		ok "live: a ruleset rendered from EMPTY lists (dev image) loads too"
	else
		bad "live: a ruleset rendered from empty lists does not load: $out"
	fi
	load >/dev/null

	listen tcp "$MD" 80
	listen tcp "$INFRA" 443
	listen tcp "$CP" 443
	listen tcp "$ALLOW" 443
	listen tcp "$ALLOW" 8443
	listen tcp "$SELF" 9000
	# passt's mosh forward: an echo on a mosh-range port, for the replies on
	# relay-opened flows in rule 4.
	listen udp-echo "$SELF" 60001

	# --- rule 4a -------------------------------------------------------------
	expect open "rule 4a: root reaches the metadata address" conn "$MD" 80
	load 's/meta skuid != 0 /meta skuid != 4242 /' >/dev/null
	expect blocked "rule 4a: a NON-root uid is dropped opening a flow to the metadata address (uid 0 standing in for one)" conn "$MD" 80
	load >/dev/null
	# The egress guard. A datagram dropped on OUTPUT fails the send (EPERM);
	# the counter shows it was THIS rule. A scope-global link-local address,
	# because the kernel will not route a scope-host source off the box at all.
	before=$(counter rule4a-egress)
	expect eperm "rule 4a: a 169.254/16 source is dropped leaving eth0" udp --src 169.254.10.10 192.0.2.50 9
	after=$(counter rule4a-egress)
	if [ "$after" -gt "$before" ]; then ok "live: ...and it was the rule4a-egress rule ($before -> $after)"; else bad "live: the rule4a-egress counter did not move ($before -> $after)"; fi
	expect sent "rule 4a: an ordinary source leaves eth0 (negative control)" udp --src "$SELF" 192.0.2.50 9
	if [ "$(counter rule4a-egress)" = "$after" ]; then ok "live: ...without touching the egress rule"; else bad "live: the egress rule counted an ordinary source"; fi

	# The input leg. A neighbour on the shared segment is a second network
	# namespace behind a veth pair. The metadata address is scope host on lo,
	# yet Linux's weak host model delivers a datagram for it that arrives on
	# the NIC -- the negative control shows exactly that -- so the input drop
	# is what refuses it. The @cp-sourced copy shows no source is exempt. UDP
	# to a logging listener, because a TCP probe could not tell the input drop
	# from rule 4a's egress drop of the SYN-ACK.
	nb_skip=""
	unshare -n sleep 600 2>/dev/null &
	nb=$!
	PIDS+=("$nb")
	for _ in $(seq 50); do
		[ "$(readlink "/proc/$nb/ns/net" 2>/dev/null)" != "$(readlink /proc/self/ns/net)" ] && [ -e "/proc/$nb/ns/net" ] && break
		sleep 0.1
	done
	if [ "$(readlink "/proc/$nb/ns/net" 2>/dev/null)" = "$(readlink /proc/self/ns/net)" ] || ! [ -e "/proc/$nb/ns/net" ]; then
		nb_skip="no second network namespace"
	elif ! ip link add ext0 type veth peer name ext1 netns "$nb" 2>/dev/null; then
		nb_skip="no veth links"
	elif ! { ip link set ext0 up && ip addr add 198.51.100.1/24 dev ext0 && ip route add 198.18.7.9/32 dev ext0; } 2>/dev/null \
		|| ! nsenter -t "$nb" -n -- bash -c 'ip link set lo up && ip link set ext1 up && ip addr add 198.51.100.2/24 dev ext1 && ip addr add 198.18.7.9/32 dev ext1 && ip route add 169.254.0.0/16 via 198.51.100.1 dev ext1' 2>/dev/null; then
		nb_skip="cannot configure the veth pair or enter the neighbour namespace"
	fi
	if [ -n "$nb_skip" ]; then
		echo "SKIP - live: rule 4a input leg ($nb_skip); its place in the ruleset is still pinned by the golden file and by checks.nix"
	else
		listen udp-log "$MD" 7009 "$RUN/md.log"
		nbsend() { nsenter -t "$nb" -n -- python3 "$PROBE" udp ${1:+--src "$1"} "$MD" 7009 >/dev/null; sleep 0.3; }
		: > "$RUN/md.log"
		before=$(counter rule4a-input input)
		nbsend
		nbsend 198.18.7.9
		after=$(counter rule4a-input input)
		if [ -s "$RUN/md.log" ]; then bad "live: rule 4a: a neighbour's datagram for the metadata address arrived over the NIC: $(tr '\n' ' ' < "$RUN/md.log")"; else ok "live: rule 4a: a neighbour's datagram for the metadata address, arriving on the NIC, is dropped on input"; fi
		if [ "$after" -ge $((before + 2)) ]; then ok "live: ...both, the @cp-sourced one included, by the rule4a-input rule ($before -> $after)"; else bad "live: the rule4a-input counter did not count both datagrams ($before -> $after)"; fi
		load '/rule4a-input/d' >/dev/null
		: > "$RUN/md.log"
		nbsend
		nbsend 198.18.7.9
		if grep -qx 198.51.100.2 "$RUN/md.log" && grep -qx 198.18.7.9 "$RUN/md.log"; then
			ok "live: rule 4a NEGATIVE CONTROL: without the input drop both datagrams reach the scope-host listener (the weak host model is real)"
		else
			bad "live: rule 4a NEGATIVE CONTROL: without the input drop the datagrams still did not arrive ($(tr '\n' ' ' < "$RUN/md.log")); the probe above proves nothing"
		fi
		load >/dev/null
	fi

	# --- rule 4 --------------------------------------------------------------
	# Under the base load our uid is none of the named ones: the listener is
	# reachable, so a "blocked" below can only be the rule.
	expect open "rule 4: the internal listener is reachable from an uninvolved uid (negative control)" conn "$INFRA" 443
	expect open "rule 4: an uninvolved uid (root: the trusted half, nix-daemon) reaches @cp; rule 4 never names it" conn "$CP" 443
	load "$PASST0" >/dev/null
	expect blocked "rule 4: a passt-uid NEW flow to @infra4 drops" conn "$INFRA" 443
	expect blocked "rule 4: a passt NEW tcp flow to @cp drops when @cp sits inside @infra4 (no blanket @cp accept)" conn "$CP" 443
	# passt's mosh reply sockets: bound to the forward's port, connected to
	# the relay in @cp, and ORIGINAL direction once conntrack has forgotten the
	# inbound flow -- a fresh datagram is exactly that case. A datagram dropped
	# on OUTPUT fails the send (eperm).
	before=$(counter rule4-cp-mosh)
	expect sent "rule 4: a passt mosh reply (udp from the mosh range) to @cp passes" udp --src "$SELF" --sport 60010 "$CP" 9
	after=$(counter rule4-cp-mosh)
	if [ "$after" -gt "$before" ]; then ok "live: ...and it was the rule4-cp-mosh accept ($before -> $after)"; else bad "live: the rule4-cp-mosh counter did not move ($before -> $after)"; fi
	expect eperm "rule 4: the same passt datagram from outside the mosh range to @cp drops" udp --src "$SELF" --sport 50010 "$CP" 9
	expect eperm "rule 4: a passt datagram from the mosh range to a non-@cp internal address drops (the accept is @cp only)" udp --src "$SELF" --sport 60011 "$INFRA" 9
	expect open "rule 4: the infraAllow socket is reachable" conn "$ALLOW" 443
	expect blocked "rule 4: the same host on another port is not (infraAllow is exact)" conn "$ALLOW" 8443
	# Replies. The listener belongs to "passt" (uid 0 here), and its SYN-ACK is
	# owned by that listener, so skuid resolves on it. No accept names @cp for
	# TCP any more, so the @cp case passes on the direction scoping alone.
	expect open "rule 4: a passt-uid REPLY to a @cp address passes" conn --src "$CP" "$SELF" 9000
	expect open "rule 4: a passt-uid REPLY to a non-@cp internal address passes (original-direction scoping)" conn --src "$INFRA" "$SELF" 9000
	# The same for passt's mosh forward: the relay sends first, so passt's
	# answer from the forward's port is a REPLY and passes rule 4 whatever the
	# relay's address. That is all an empty @cp leaves mosh. (The @cp copy is
	# also admitted by the mosh accept; the non-@cp one is direction alone.)
	expect reply "rule 4: a passt mosh REPLY on a relay-opened flow passes from a non-@cp internal address (direction scoping; what an empty @cp relies on)" udp --src "$INFRA" --expect-reply "$SELF" 60001
	expect reply "rule 4: a passt mosh REPLY on a relay-opened flow passes from a @cp address" udp --src "$CP" --expect-reply "$SELF" 60001
	load "$PASST0; /rule4-uid/s/ ct direction original//" >/dev/null
	expect blocked "rule 4 NEGATIVE CONTROL: without the direction scoping the same reply is dropped" conn --src "$INFRA" "$SELF" 9000
	expect blocked "rule 4 NEGATIVE CONTROL: without the direction scoping the reply to @cp is dropped too" conn --src "$CP" "$SELF" 9000
	# The echo's dropped send (EPERM) ends that listener: its last use.
	expect noreply "rule 4 NEGATIVE CONTROL: without the direction scoping the passt mosh reply to a non-@cp internal address is dropped" udp --src "$INFRA" --expect-reply "$SELF" 60001
	# The mosh accept's own negative control: passt at uid 0 in the drop, the
	# accept left on the parked uid. The datagram it admitted above now drops,
	# so it was that accept, scoped to the passt uid, that admitted it.
	load 's/meta skuid { 65532, 65533 }/meta skuid { 0, 65533 }/' >/dev/null
	expect eperm "rule 4 NEGATIVE CONTROL: with the mosh accept naming another uid, the same passt mosh reply to @cp is dropped" udp --src "$SELF" --sport 60012 "$CP" 9
	load 's/meta skgid 65533/meta skgid 0/' >/dev/null
	expect blocked "rule 4: a build-group NEW flow to @infra4 drops" conn "$INFRA" 443
	expect blocked "rule 4: a build-group NEW flow to @cp drops when @cp sits inside @infra4" conn "$CP" 443
	expect eperm "rule 4: a build-group datagram from the mosh range to @cp drops (the accept names the passt uid only)" udp --src "$SELF" --sport 60013 "$CP" 9

	# --- ingress is open ------------------------------------------------------
	# No ingress filter (decision 2026-10-21): sshd, the guest SSH and HTTP
	# forwards and the mosh range are reachable from any neighbour, and rely on
	# their own authentication. Shown over the rule 4a neighbour's real (non-lo)
	# veth link -- every packet sent inside this namespace arrives on lo --
	# from three sources: one outside @infra4, one inside @infra4 but outside
	# @cp (every internal host when @cp is empty), and one inside both
	# (the rule 4a neighbour's @cp source), under the base load and with passt
	# as uid 0 (passt answers its own forwards). The middle one alone catches
	# an ingress filter that admits @cp but drops the rest of @infra4. The
	# negative control inserts a test-only input drop on the same ports, which
	# the same probes must catch.
	if [ -n "$nb_skip" ]; then
		echo "SKIP - live: ingress is open ($nb_skip); the input chain is still pinned to rule 4a's drop alone by the golden file and by checks.nix"
	elif ! { ip route add 198.18.9.20/32 dev ext0 && nsenter -t "$nb" -n -- bash -c 'ip addr add 198.18.9.20/32 dev ext1 && ip route add 192.0.2.0/24 via 198.51.100.1 dev ext1'; } 2>/dev/null; then
		bad "live: ingress: cannot route the neighbour namespace to $SELF"
	else
		listen tcp "$SELF" 22
		listen tcp "$SELF" 2223
		listen tcp "$SELF" 8081
		listen udp-log "$SELF" 60002 "$RUN/udp.log"
		surface() { case "$1" in 22) echo "sshd" ;; 2223) echo "a guest SSH forward" ;; 8081) echo "a guest HTTP forward" ;; esac; }
		srcs="198.51.100.2 198.18.9.20 198.18.7.9"
		where() { case "$1" in 198.51.100.2) echo "outside @infra4" ;; 198.18.9.20) echo "inside @infra4, outside @cp" ;; 198.18.7.9) echo "inside @infra4 and @cp" ;; esac; }
		nbconn() { nsenter -t "$nb" -n -- python3 "$PROBE" connect --src "$1" "$SELF" "$2"; }
		nbudp() {
			: > "$RUN/udp.log"
			for src in $srcs; do
				nsenter -t "$nb" -n -- python3 "$PROBE" udp --src "$src" "$SELF" 60002 >/dev/null
			done
			sleep 0.3
		}
		for ld in "" "$PASST0"; do
			if [ -n "$ld" ]; then load "$ld" >/dev/null; tag="passt as uid 0"; else load >/dev/null; tag="base load"; fi
			for src in $srcs; do
				for p in 22 2223 8081; do
					expect open "ingress is open ($tag): a neighbour at $src ($(where "$src")) reaches $(surface "$p") ($SELF:$p) over the NIC" nbconn "$src" "$p"
				done
			done
			nbudp
			missing=""
			for src in $srcs; do grep -qx "$src" "$RUN/udp.log" || missing="$missing $src"; done
			if [ -z "$missing" ]; then
				ok "live: ingress is open ($tag): datagrams from all three neighbour sources reach the mosh range ($SELF:60002) over the NIC"
			else
				bad "live: ingress is open ($tag): the datagram to the mosh range from$missing never arrived (logged: $(tr '\n' ' ' < "$RUN/udp.log"))"
			fi
		done
		load 's/\(counter drop comment "cogworx-pve-floor-rule4a-input"\)/\1\n\t\ttcp dport { 22, 2223, 8081 } counter drop comment "test-only"\n\t\tudp dport 60002 counter drop comment "test-only"/' >/dev/null
		for p in 22 2223 8081; do
			expect blocked "ingress NEGATIVE CONTROL: a test-only input drop on $(surface "$p") is caught by the same probe" nbconn 198.18.9.20 "$p"
		done
		nbudp
		if [ -s "$RUN/udp.log" ]; then
			bad "live: ingress NEGATIVE CONTROL: a test-only input drop on the mosh port did not stop the datagrams ($(tr '\n' ' ' < "$RUN/udp.log")); the probe above proves nothing"
		else
			ok "live: ingress NEGATIVE CONTROL: a test-only input drop on the mosh port is caught by the same probe"
		fi
		load >/dev/null
	fi

	# --- section 4: beside gce/floor.nix's own table --------------------------
	if [ -n "$GCE_VERIFY" ] && [ -s "$RUN/gce/cogworx-floor.nft" ]; then
		load >/dev/null
		# test_floor.sh's rewrites: the passt account parked on an unused uid,
		# and setpriv's setgroups(2) (denied in a user namespace) swapped.
		sed -e 's/meta skuid "cogbox-passt"/meta skuid 65533/' "$RUN/gce/cogworx-floor.nft" > "$RUN/gce/live.nft"
		if ! out=$(nft -f "$RUN/gce/live.nft" 2>&1); then
			bad "live: the gce floor ruleset did not load beside this one: $out"
		else
			sed 's/--clear-groups/--keep-groups/' "$GCE_VERIFY" > "$RUN/gce/verify"
			chmod +x "$RUN/gce/verify"
			# rc dropped on purpose, as in test_floor.sh: probes 1-3 and 6-8 run
			# as cogbox-passt/cogbox-proxy, which do not exist here. Probes 4
			# and 5 run as the control uid and are the ones that apply.
			out=$(COGWORX_RUN_DIR="$RUN/gce" "$RUN/gce/verify" 2>&1)
			case "$out" in
				*'exempt-port return path verified'*) ok "live: with both tables loaded, gce probe 5 (control uid to a real listener on an exempt port) passes" ;;
				*) bad "live: gce probe 5 failed with both tables loaded: $out" ;;
			esac
			case "$out" in
				*'PROBE FAILED: rule 2 control-uid exception'*) bad "live: gce probe 4 failed with both tables loaded: $out" ;;
				*) ok "live: with both tables loaded, gce probe 4 (control-uid exception) passes" ;;
			esac
			expect open "rule 4a beside the gce floor: root still reaches the metadata address" conn "$MD" 80

			# gce probes 1, 3, 6, 7 and 8 name the passt or proxy uid, which
			# cannot be impersonated here, so they are modelled the way
			# test_floor.sh models them: the passt account re-pointed at uid 0 --
			# in BOTH tables, so the site floor's rule 4 also treats this uid as
			# passt. Probe 2 is the one that cannot be modelled: with passt and
			# the control uid collapsed onto uid 0, the control-uid exception
			# admits it. The property shown is that the site table neither
			# re-opens what the gce floor closes nor closes what it keeps open
			# (the L7 funnel and the host DNS forwarder).
			listen tcp 127.0.0.1 18443
			listen tcp 127.0.0.1 18445
			listen tcp "$SELF" 18443
			sed -e 's/meta skuid "cogbox-passt"/meta skuid 0/' "$RUN/gce/cogworx-floor.nft" > "$RUN/gce/live0.nft"
			load "$PASST0" >/dev/null
			if ! out=$(nft -f "$RUN/gce/live0.nft" 2>&1); then
				bad "live: the passt-as-uid-0 gce ruleset did not load beside this one: $out"
			else
				expect blocked "beside the site floor, gce probe 1 holds: passt cannot reach the metadata API" conn "$MD" 80
				expect blocked "beside the site floor, gce probe 3 holds: the VM's own address stays closed outside the SSH exception" conn "$SELF" 18443
				expect blocked "beside the site floor, gce probe 6 holds: passt cannot reach the mitm hop on loopback" conn 127.0.0.1 18445
				expect open "beside the site floor, gce probe 7 holds: passt still reaches the L7 funnel target" conn 127.0.0.1 18443
				listen tcp 127.0.0.53 53
				expect open "beside the site floor, gce probe 8 holds: passt still reaches the host DNS forwarder" conn 127.0.0.53 53
			fi
		fi
	elif [ -n "$GCE_VERIFY" ]; then
		bad "live: the gce install leg rendered no ruleset to load (see the parent's output)"
	fi

	[ "$fails" -eq 0 ] || exit 1
	exit 0
fi

RENDER="${1:-$HERE/../floor_render.py}"
REALIZED="${2:--}"
GCE_INSTALL="${3:-}"
GCE_VERIFY="${4:-}"
[ -r "$RENDER" ] || { echo "FAIL: renderer not readable: $RENDER" >&2; exit 1; }

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

# The fixture: fictional, and the same values pve/checks.nix's fixture system
# sets, so the realized ruleset can be compared to the golden one below.
cat > "$ROOT/base.json" <<'EOF'
{
	"version": 1,
	"iface": "eth0",
	"controlPlaneCIDRs": ["198.18.7.0/24"],
	"infraDenyCIDRs": ["198.18.0.0/15", "203.0.113.0/24"],
	"infraAllow": [{"address": "203.0.113.80", "protocol": "tcp", "port": 443}],
	"passtUser": "cogbox-passt",
	"proxyUser": "cogbox-proxy",
	"buildGroup": "nixbld",
	"moshUDP": [[60000, 60031]]
}
EOF

# A variant of the fixture: $2 is Python run against the parsed spec `d`.
mkspec() {
	python3 - "$ROOT/base.json" "$ROOT/$1.json" "$2" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
exec(sys.argv[3])
json.dump(d, open(sys.argv[2], "w"))
EOF
}
render() { python3 -I "$RENDER" "$ROOT/$1.json" >"$ROOT/$1.nft" 2>"$ROOT/$1.err"; }

# --- 1. the validator ----------------------------------------------------------
refuses() {
	local name="$1" patch="$2" want="$3" rc=0
	mkspec "$name" "$patch"
	render "$name" || rc=$?
	if [ "$rc" != 2 ]; then
		bad "validator accepted $name (rc $rc): $(cat "$ROOT/$name.nft")"
	elif [ -s "$ROOT/$name.nft" ]; then
		bad "validator refused $name but still wrote a ruleset"
	elif ! grep -qF 'cogworx-pve-floor: REFUSED:' "$ROOT/$name.err" || ! grep -qF -- "$want" "$ROOT/$name.err"; then
		bad "validator refused $name without naming '$want': $(cat "$ROOT/$name.err")"
	else
		ok "validator refuses $name ($(sed 's/^cogworx-pve-floor: REFUSED: //' "$ROOT/$name.err"))"
	fi
}
accepts() {
	local name="$1" patch="$2" rc=0
	mkspec "$name" "$patch"
	render "$name" || rc=$?
	if [ "$rc" = 0 ] && [ -s "$ROOT/$name.nft" ]; then ok "validator accepts $name"; else bad "validator refused $name: $(cat "$ROOT/$name.err")"; fi
}

refuses cp-slash0          'd["controlPlaneCIDRs"] = ["0.0.0.0/0"]'              'controlPlaneCIDRs[0]'
refuses cp-wider-than-8    'd["controlPlaneCIDRs"] = ["198.0.0.0/7"]'            'wider than /8'
refuses infra-loopback     'd["infraDenyCIDRs"] = ["127.0.0.0/8"]'               'overlaps 127.0.0.0/8'
refuses infra-in-loopback  'd["infraDenyCIDRs"] = ["127.1.2.0/24"]'              'overlaps 127.0.0.0/8'
refuses infra-metadata     'd["infraDenyCIDRs"] = ["169.254.169.254"]'           'overlaps 169.254.0.0/16'
refuses infra-around-ll    'd["infraDenyCIDRs"] = ["169.0.0.0/8"]'               'overlaps 169.254.0.0/16'
refuses infra-this-net     'd["infraDenyCIDRs"] = ["0.1.0.0/16"]'                'overlaps 0.0.0.0/8'
refuses cp-link-local      'd["controlPlaneCIDRs"] = ["169.254.0.0/16"]'         'overlaps 169.254.0.0/16'
refuses allow-link-local   'd["infraAllow"][0]["address"] = "169.254.169.254"'  'infraAllow[0].address'
refuses allow-cidr         'd["infraAllow"][0]["address"] = "203.0.113.0/24"'   'is not a single address'
refuses allow-wide-cidr    'd["infraAllow"][0]["address"] = "10.0.0.0/8"'       'is not a single address'
refuses cp-host-bits       'd["controlPlaneCIDRs"] = ["198.18.7.1/24"]'          'not a canonical'
refuses cp-leading-zero    'd["controlPlaneCIDRs"] = ["198.018.7.0/24"]'         'controlPlaneCIDRs[0]'
refuses cp-ipv6            'd["controlPlaneCIDRs"] = ["2001:db8::/32"]'          'not an IPv4'
refuses cp-hostname        'd["controlPlaneCIDRs"] = ["git.example.com"]'        'not an IPv4'
refuses infra-not-list     'd["infraDenyCIDRs"] = "198.18.0.0/15"'               'expected a list'
refuses allow-protocol     'd["infraAllow"][0]["protocol"] = "icmp"'             'infraAllow[0].protocol'
refuses allow-port-zero    'd["infraAllow"][0]["port"] = 0'                      'infraAllow[0].port'
refuses allow-port-high    'd["infraAllow"][0]["port"] = 70000'                  'infraAllow[0].port'
refuses allow-port-string  'd["infraAllow"][0]["port"] = "443"'                  'infraAllow[0].port'
refuses allow-extra-key    'd["infraAllow"][0]["comment"] = "x"'                 'infraAllow[0]'
refuses passt-quote        'd["passtUser"] = "cogbox\"passt"'                    'passtUser'
refuses iface-injection    'd["iface"] = "eth0\" accept"'                        'iface'
refuses open-ingress-knob  'd["allowOpenIngress"] = True'                        'unknown key'
# A spec that still carries rule 5's ports (a stale composer) fails the build.
refuses stale-ingressTCP   'd["ingressTCP"] = [[22, 22]]'                        'unknown key'
refuses stale-ingressUDP   'd["ingressUDP"] = [[60000, 60031]]'                  'unknown key'
refuses mosh-reversed      'd["moshUDP"] = [[60031, 60000]]'                     'moshUDP[0]: [60031, 60000] has lo > hi'
refuses mosh-not-list      'd["moshUDP"] = 60000'                                'moshUDP'
refuses mosh-missing       'del d["moshUDP"]'                                    'missing key(s) moshUDP'
refuses spec-version       'd["version"] = 2'                                    'version'

accepts exactly-slash-8    'd["infraDenyCIDRs"] = ["10.0.0.0/8"]'
accepts beside-loopback    'd["infraDenyCIDRs"] = ["126.0.0.0/8", "128.0.0.0/8"]'
accepts beside-link-local  'd["infraDenyCIDRs"] = ["169.253.0.0/16", "169.255.0.0/16"]'
accepts overlapping-infra  'd["infraDenyCIDRs"] = ["198.18.0.0/15", "198.18.4.0/24"]'
accepts allow-slash-32     'd["infraAllow"][0]["address"] = "203.0.113.80/32"'
accepts empty              'd["controlPlaneCIDRs"] = []; d["infraDenyCIDRs"] = []; d["infraAllow"] = []'
accepts no-mosh            'd["moshUDP"] = []'

# --- 2. the rendered ruleset ---------------------------------------------------
render base || bad "the fixture spec was refused: $(cat "$ROOT/base.err")"
nft="$ROOT/base.nft"
# Golden. A deliberate change to the renderer updates this in the same commit;
# an accidental one fails here with the diff.
cat > "$ROOT/golden.nft" <<'EOF'
table inet cogworx_pve_floor
delete table inet cogworx_pve_floor
table inet cogworx_pve_floor {
	set cp {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { 198.18.7.0/24 }
	}
	set infra4 {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { 198.18.0.0/15, 203.0.113.0/24 }
	}
	chain output {
		type filter hook output priority 0; policy accept;
		meta skuid != 0 ct direction original ip daddr 169.254.0.0/16 counter drop comment "cogworx-pve-floor-rule4a-linklocal"
		oifname "eth0" ip saddr 169.254.0.0/16 counter drop comment "cogworx-pve-floor-rule4a-egress"
		meta skuid "cogbox-passt" ip daddr @cp udp sport 60000-60031 counter accept comment "cogworx-pve-floor-rule4-cp-mosh"
		ip daddr 203.0.113.80 tcp dport 443 counter accept comment "cogworx-pve-floor-rule4-infra-allow"
		meta skuid { "cogbox-passt", "cogbox-proxy" } ct direction original ip daddr @infra4 counter drop comment "cogworx-pve-floor-rule4-uid"
		meta skgid "nixbld" ct direction original ip daddr @infra4 counter drop comment "cogworx-pve-floor-rule4-build"
	}
	chain input {
		type filter hook input priority 0; policy accept;
		iifname != "lo" ip daddr 169.254.0.0/16 counter drop comment "cogworx-pve-floor-rule4a-input"
	}
}
EOF
if diff -u "$ROOT/golden.nft" "$nft" >"$ROOT/golden.diff"; then
	ok "the rendered ruleset matches the golden file"
else
	bad "the rendered ruleset differs from the golden file: $(cat "$ROOT/golden.diff")"
fi
if [ "$REALIZED" != - ]; then
	if diff -u "$ROOT/golden.nft" "$REALIZED" >"$ROOT/realized.diff"; then
		ok "the ruleset floor-site.nix realized for the fixture system is the golden one (mosh range read from the right options)"
	else
		bad "the realized ruleset differs from the golden file: $(cat "$ROOT/realized.diff")"
	fi
fi

# Properties, one by one, so a golden update that breaks one still says which.
while IFS= read -r line; do
	case "$line" in
		*'ct direction original'*) ;;
		*) bad "a uid/gid deny is not scoped to the original direction (replies on control-plane flows would be dropped): $line" ;;
	esac
done < <(grep -E 'meta sk(uid|gid) .* drop' "$nft")
n=$(grep -cE 'meta sk(uid|gid) .* drop' "$nft")
if [ "$n" = 3 ]; then ok "every uid/gid deny (4a, 4-uid, 4-build) is original-direction scoped"; else bad "expected 3 uid/gid denies, found $n"; fi
if grep -E '^[[:space:]]*ip daddr @infra4' "$nft"; then
	bad "rule 4 renders an @infra4 drop with no uid/gid selector: it would drop the trusted half's own traffic"
else
	ok "no rule-4 drop without a uid/gid selector"
fi
line_of() { grep -nF "$1" "$nft" | head -1 | cut -d: -f1; }
for acc in rule4-cp-mosh rule4-infra-allow; do
	for den in rule4-uid rule4-build; do
		a=$(line_of "cogworx-pve-floor-$acc\""); d=$(line_of "cogworx-pve-floor-$den\"")
		if [ -n "$a" ] && [ -n "$d" ] && [ "$a" -lt "$d" ]; then ok "$acc is rendered above $den"; else bad "$acc ($a) is not above $den ($d)"; fi
	done
done
# The @cp accept is passt's mosh replies and nothing wider: one output-chain
# rule names @cp, and it carries the passt uid, udp and the mosh source range.
cp_out=$(sed -n '/chain output {/,/^\t}/p' "$nft" | grep -F '@cp')
if [ "$(printf '%s\n' "$cp_out" | grep -c .)" = 1 ] && printf '%s\n' "$cp_out" | grep -qF 'meta skuid "cogbox-passt" ip daddr @cp udp sport 60000-60031 counter accept'; then
	ok "rule 4's only @cp accept is passt's mosh replies (passt uid, udp, mosh source range)"
else
	bad "rule 4 accepts @cp more widely than passt's mosh replies: $cp_out"
fi
mkspec no-mosh 'd["moshUDP"] = []'
render no-mosh
if grep -q 'rule4-cp-mosh' "$ROOT/no-mosh.nft" || sed -n '/chain output {/,/^\t}/p' "$ROOT/no-mosh.nft" | grep -qF '@cp'; then
	bad "with no mosh range the output chain still names @cp: $(cat "$ROOT/no-mosh.nft")"
else
	ok "with no mosh range there is no @cp accept at all"
fi
# The input chain is exactly one rule, rule 4a's input drop: the floor filters
# no ingress (floor_render.py's "No ingress filter").
in_rules=$(sed -n '/chain input {/,/^\t}/{/chain input {/d;/type filter hook input/d;/^\t}/d;p}' "$nft")
if [ "$(printf '%s\n' "$in_rules" | grep -c .)" = 1 ] && printf '%s\n' "$in_rules" | grep -qF 'iifname != "lo" ip daddr 169.254.0.0/16 counter drop comment "cogworx-pve-floor-rule4a-input"'; then
	ok "the input chain is exactly one rule, rule4a-input (no ingress filter)"
else
	bad "the input chain is not exactly rule 4a's input drop: $in_rules"
fi
mkspec empty 'd["controlPlaneCIDRs"] = []; d["infraDenyCIDRs"] = []; d["infraAllow"] = []'
render empty
if grep -q 'elements' "$ROOT/empty.nft"; then bad "an empty list rendered an elements line (nft refuses 'elements = { }')"; else ok "empty lists render sets without an elements line"; fi

# --- 3 and 4: live --------------------------------------------------------------
mkdir -p "$ROOT/gce"
if [ -n "$GCE_INSTALL" ]; then
	# The real gce install leg, against a file:// metadata tree: it writes the
	# ruleset before attempting the load, which fails here (no CAP_NET_ADMIN in
	# the parent) and is attempted again inside the namespace.
	mkdir -p "$ROOT/md/instance/attributes"
	printf '192.0.2.10' > "$ROOT/md/instance/attributes/cogworx-self-addrs"
	COGWORX_MD_BASE="file://$ROOT/md" COGWORX_RUN_DIR="$ROOT/gce" "$GCE_INSTALL" >"$ROOT/gce/install.out" 2>&1 || true
	[ -s "$ROOT/gce/cogworx-floor.nft" ] || bad "the gce install leg rendered no ruleset: $(cat "$ROOT/gce/install.out")"
fi
if ! command -v unshare >/dev/null || ! command -v nft >/dev/null || ! command -v ip >/dev/null; then
	echo "SKIP - live sections: unshare, nft or ip is not available"
else
	rc=0
	out=$(unshare -Urn bash "${BASH_SOURCE[0]}" --live-child "$ROOT" "$GCE_VERIFY" 2>&1) || rc=$?
	echo "$out" | grep -v '^LIVE-BEGIN$'
	if [ "$rc" = 77 ] || { [ "$rc" != 0 ] && ! printf '%s' "$out" | grep -q '^LIVE-BEGIN$'; }; then
		echo "SKIP - live sections: this kernel/sandbox cannot host a user+network namespace with nftables (rc $rc)"
	elif [ "$rc" != 0 ]; then
		fails=$((fails + 1))
	fi
fi

if [ "$fails" -gt 0 ]; then
	echo "test_floor_site: $fails failure(s)" >&2
	exit 1
fi
echo "test_floor_site: all passed"
