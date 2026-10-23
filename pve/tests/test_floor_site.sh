#!/usr/bin/env bash
# Behavioural test for the PVE site floor (pve/floor-site.nix, rendered by
# pve/floor_render.py): nft table inet cogworx_pve_floor, rules 4a and 4. Rule
# 4 names the nix build users only: the guest (passt) and the L7 proxy follow
# each sandbox's own network rules (decision 2026-10-22, GCE parity), and the
# build users stay blocked from the internal ranges, from the local hops that
# would dial them on their behalf, and from broadcast and multicast, which
# would solicit a flow from them. The floor filters no ingress
# (decision 2026-10-21; floor_render.py's "No ingress filter"), and section 3
# shows that too.
#
#   1. the validator refuses what it must (IPv4-only, canonical, at most /8,
#      no overlap with 127/8, 169.254/16 or 0/8, exact infraAllow entries,
#      plain names, a non-empty, ascending and disjoint TCP hop port list, an
#      ascending and disjoint UDP one that may be empty, and the removed
#      passt, proxy, mosh and ingress keys) and accepts the boundaries;
#   2. the rendered ruleset, pinned byte for byte, plus the properties that
#      matter stated one by one (every uid/gid deny is `ct direction
#      original` except the hop source-port pair, which drops a reply; the
#      hop and broadcast drops come first and the infraAllow accepts before
#      the internal-range drop; no UDP hop drop without UDP hops, the
#      broadcast drop always; the only uid selector is rule 4a's root test and
#      every gid selector the build group's; no passt or proxy account and no
#      @cp; the input chain is rule 4a's input drop alone);
#   3. LIVE, in a throwaway user+network namespace with real listeners: rule
#      4a (root reaches link-local, a non-root uid does not; a link-local source
#      never leaves eth0; a neighbour's datagram for the metadata address,
#      arriving over a veth from a second namespace, is dropped on input
#      whatever its source, an internal one included); the guest and the L7
#      proxy (a non-root uid outside the build group opens NEW flows to an
#      internal address and reaches every local hop, while rule 4a still drops
#      it towards link-local); root (the internal address and every hop);
#      the build users (a NEW flow to an internal address drops except the
#      exact infraAllow socket, every hop port of the first and the last
#      triple and the bake's extra loopback port drops on 127.0.0.1 and,
#      where the namespace has it, ::1, the ports just outside the hop bands
#      and the DNS forwarder stay open, a build-group listener on a hop port
#      never answers a probe, a datagram to the bake's UDP agent port on
#      loopback, to the limited broadcast address and to eth0's segment
#      broadcast, which is outside the internal ranges (a wildcard agent
#      would otherwise receive either), and to a multicast group drops, and
#      a reply to an internal address passes); the site floor's own boot
#      verify leg, as realized, passes, and fails on each probe's own
#      breakage; and open ingress (over the same
#      veth, a neighbour outside the internal ranges and one inside them both
#      reach sshd, a guest SSH forward, a guest HTTP forward and the mosh
#      range). Each with a negative control that adds or removes the property
#      and shows the probe catching it;
#   4. with the realized gce floor scripts given, the gce floor and this one
#      loaded TOGETHER: gce/floor.nix's own verifier passes the probes that run
#      as the control uid (4 and 5); probes 1, 3, 6, 7 and 8, which name the
#      passt uid, are modelled with passt re-pointed at uid 0 in the gce
#      table; and root still reaches the metadata address. Probe 2 is the one
#      of the eight that cannot be modelled in a one-uid namespace (see
#      section 4).
#
# Usage: test_floor_site.sh [RENDERER [REALIZED_RULESET|- [GCE_INSTALL GCE_VERIFY [PVE_VERIFY]]]]
#   RENDERER          floor_render.py (default: ../floor_render.py)
#   REALIZED_RULESET  the ruleset floor-site.nix built for checks.nix's fixture
#                     system; asserted equal to section 2's golden file. `-` skips.
#   GCE_INSTALL/VERIFY the realized cogworx-floor ExecStart/ExecStartPost, for
#                     section 4.
#   PVE_VERIFY        the realized cogworx-pve-floor ExecStartPost (this floor's
#                     boot verify leg), run in section 3.
# Needs python3 and grep for sections 1-2. Sections 3-4 additionally need
# unshare, ip and nft and a kernel with nftables + conntrack + dummy links, and
# SKIP loudly when the namespace cannot host them; the rule 4a input probe and
# the open-ingress cases also need veth links and nsenter, and the ::1 hop
# case needs ::1 on lo, and each skips loudly on its own without them
# (checks.nix asserts on the realized ruleset that the input chain is rule
# 4a's input drop alone and that the hop and broadcast drops are there,
# regardless).
# Nothing touches the host's own ruleset, addresses or routes.
#
# SKUID AND SKGID IN A USER NAMESPACE. nft resolves `meta skuid`/`skgid`
# against the network namespace's OWNER user namespace, so inside `unshare
# -Urn` our own sockets read as uid 0 and gid 0 and match exactly as root's
# would on the VM. Only ONE uid and gid are mapped, so "this probe runs as a
# build user" is modelled the way tests/test_floor.sh models its uid cases:
# the build group's rules are re-pointed at gid 0, and "a non-root uid" by
# re-pointing rule 4a's root test at an unused uid. The boot verify leg, which
# probes as three accounts in one run, gets a network namespace per account
# instead, each with the floor loaded as that account would meet it. The base
# load parks the build group on an unused numeric gid (the name may not
# resolve here), with its hit count asserted, so a renderer change cannot
# silently turn a case vacuous. Nothing else is rewritten: nft refuses a name it cannot resolve,
# so a ruleset that named the passt or the proxy account would fail to load
# here, and that is a failure, not a skip (a fixed probe table with the same
# match kinds tells the two apart).

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
	PVE_VERIFY="${4:-}"
	echo "LIVE-BEGIN"
	SELF=192.0.2.10        # eth0's DHCP address
	INFRA=198.18.9.9       # internal: inside the fixture's infraDenyCIDRs
	ALLOW=203.0.113.80     # internal, with a tcp/443 infraAllow exception
	OUTSIDE=192.0.2.99     # a neighbour on the shared segment
	MD=169.254.169.254
	# Rule 4's local hops for the fixture (the launcher's base 18443, 16
	# triples): l7proxy's two front doors and the mitmproxy hop of the first
	# and of the last triple, both triples' auth proxy ports (base - 400),
	# and the bake's extra loopback port (buildDenyLoopbackTCP).
	HOPS="18443 18444 18445 18043 18488 18489 18490 18088 8500"
	# One port past each end of every hop band: never a hop.
	NOT_HOPS="8499 8501 18042 18091 18442 18491"
	# The bake's UDP agent (buildDenyLoopbackUDP), listening on the wildcard
	# address as such an agent would, so a broadcast reaches it too.
	UDP_HOP=7301
	MCAST=224.0.0.251
	# eth0's segment broadcast (DHCP's, on the VM): outside infraDenyCIDRs,
	# so only the drop by address type covers it.
	SEG_BCAST=192.0.2.255
	hopname() {
		case "$1" in
			18443|18488) echo "l7proxy's TLS front door" ;;
			18444|18489) echo "l7proxy's HTTP front door" ;;
			18445|18490) echo "the mitmproxy SOCKS5 hop" ;;
			18043|18088) echo "the auth proxy" ;;
			8500) echo "a bake agent's local API" ;;
		esac
	}
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
	for a in "$INFRA" "$ALLOW" "$OUTSIDE" 169.254.10.10; do
		ip addr add "$a/32" dev lo || { echo "LIVE-SKIP: cannot assign $a"; exit 77; }
	done

	# The base load: the build group parked on an unused numeric gid. $1,
	# when given, is a sed expression applied after that rewrite; SRC
	# overrides the ruleset (default: the fixture's).
	load() {
		local -a extra=()
		[ $# -gt 0 ] && extra=(-e "$1")
		sed -e 's/meta skgid "nixbld"/meta skgid 65533/' \
			${extra[@]+"${extra[@]}"} "${SRC:-$RUN/base.nft}" > "$RUN/live.nft"
		nft -f "$RUN/live.nft" 2>&1
	}
	# Our gid 0 as the build group, in every rule that names it.
	BUILD0='s/meta skgid 65533/meta skgid 0/'
	# Our uid 0 as a non-root uid, for rule 4a.
	NONROOT='s/meta skuid != 0 /meta skuid != 4242 /'
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
	# A rule's packet counter, by the end of its comment (the closing quote
	# keeps rule4-build from matching rule4-build-hop).
	counter() {
		nft list chain inet cogworx_pve_floor "${2:-output}" | grep -F "cogworx-pve-floor-$1\"" | grep -o 'packets [0-9]*' | cut -d' ' -f2
	}

	# Can this namespace host the floor's match kinds at all? A fixed probe
	# table with the same expressions and no account name: when it loads, a
	# failure to load the rendered ruleset below is the ruleset's own (an
	# account name nft cannot resolve, say), not the environment's.
	probe_nft=$(printf '%s\n' \
		'table inet cogworx_pve_probe {' \
		'	set s {' \
		'		type ipv4_addr' \
		'		flags interval' \
		'		auto-merge' \
		'		elements = { 198.18.0.0/15, 203.0.113.0/24 }' \
		'	}' \
		'	chain output {' \
		'		type filter hook output priority 0; policy accept;' \
		'		meta skuid != 0 ct direction original ip daddr 169.254.0.0/16 counter drop comment "probe"' \
		'		oifname "eth0" ip saddr 169.254.0.0/16 counter drop comment "probe"' \
		'		meta skgid 65533 ct direction original ip daddr 127.0.0.0/8 tcp dport { 1-2, 4-5 } counter drop comment "probe"' \
		'		meta skgid 65533 ct direction original ip6 daddr ::1 tcp dport { 1-2, 4-5 } counter drop comment "probe"' \
		'		meta skgid 65533 ip saddr 127.0.0.0/8 tcp sport { 1-2, 4-5 } counter drop comment "probe"' \
		'		meta skgid 65533 ip6 saddr ::1 tcp sport { 1-2, 4-5 } counter drop comment "probe"' \
		'		meta skgid 65533 ct direction original ip daddr 127.0.0.0/8 udp dport 7 counter drop comment "probe"' \
		'		meta skgid 65533 ct direction original ip6 daddr ::1 udp dport 7 counter drop comment "probe"' \
		'		meta skgid 65533 ct direction original meta nfproto ipv4 fib daddr type { broadcast, multicast } counter drop comment "probe"' \
		'		ip daddr 203.0.113.80 tcp dport 443 counter accept comment "probe"' \
		'		meta skgid 65533 ct direction original ip daddr @s counter drop comment "probe"' \
		'	}' \
		'	chain input {' \
		'		type filter hook input priority 0; policy accept;' \
		'		iifname != "lo" ip daddr 169.254.0.0/16 counter drop comment "probe"' \
		'	}' \
		'}' \
		'delete table inet cogworx_pve_probe')
	if ! out=$(printf '%s\n' "$probe_nft" | nft -f - 2>&1); then
		echo "LIVE-SKIP: nft cannot load the floor's match kinds here: $out"
		exit 77
	fi
	if ! out=$(load); then
		bad "live: the rendered ruleset does not load with only the build group re-pointed (it must name no other account): $out"
		exit 1
	fi
	n=$(grep -cF 'meta skgid 65533' "$RUN/live.nft")
	if [ "$n" = 8 ] && ! grep -qF '"nixbld"' "$RUN/live.nft"; then
		ok "live: the rendered ruleset loads with only the build group re-pointed (its eight rules; no other account is named)"
	else
		bad "live: the build-group rewrite landed on $n rule(s), not rule 4's eight: $(cat "$RUN/live.nft")"
	fi
	if out=$(SRC="$RUN/empty.nft" load); then
		ok "live: a ruleset rendered from EMPTY lists (dev image) loads too"
	else
		bad "live: a ruleset rendered from empty lists does not load: $out"
	fi
	load >/dev/null

	listen tcp "$MD" 80
	listen tcp "$INFRA" 443
	listen tcp "$ALLOW" 443
	listen tcp "$ALLOW" 8443
	listen tcp "$SELF" 9000
	for p in $HOPS $NOT_HOPS; do listen tcp 127.0.0.1 "$p"; done
	listen tcp 127.0.0.53 53
	listen udp-log 0.0.0.0 "$UDP_HOP" "$RUN/agent.log"
	# expect, for a datagram the UDP agent may receive: its log is emptied
	# first and given time to fill, so the caller can say whether (and from
	# which source) it arrived.
	agent() {
		local want="$1" what="$2" got
		shift 2
		: > "$RUN/agent.log"
		got=$("$@")
		sleep 0.3
		if [ "$got" = "$want" ]; then ok "live: $what"; else bad "live: $what -- got $got, expected $want"; fi
	}
	arrived() { [ -s "$RUN/agent.log" ] && echo "arrived from $(tr '\n' ' ' < "$RUN/agent.log")" || echo "never arrived"; }
	have6=""
	if ip -6 addr show dev lo 2>/dev/null | grep -q 'inet6 ::1/128'; then
		listen tcp ::1 18445
		have6=1
	fi

	# --- rule 4a -------------------------------------------------------------
	expect open "rule 4a: root reaches the metadata address" conn "$MD" 80
	load "$NONROOT" >/dev/null
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
	# is what refuses it. The copy from an internal source shows no source is
	# exempt. UDP to a logging listener, because a TCP probe could not tell
	# the input drop from rule 4a's egress drop of the SYN-ACK.
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
		if [ "$after" -ge $((before + 2)) ]; then ok "live: ...both, the one from an internal source included, by the rule4a-input rule ($before -> $after)"; else bad "live: the rule4a-input counter did not count both datagrams ($before -> $after)"; fi
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

	# --- the guest and the L7 proxy: no internal-range egress filter -----------
	# Decision 2026-10-22 (GCE parity): the table names neither the passt nor
	# the L7-proxy uid, so their egress is the sandbox's own network rules'
	# business. A non-root uid outside the build group stands for both: rule
	# 4a's root test re-pointed at an unused uid makes our uid 0 non-root,
	# and the build group stays parked on an unused gid. The hop ports are
	# the L7 proxy's own dials (l7proxy to the mitmproxy hop, mitmproxy to the
	# auth proxy); passt's loopback reach is gce/floor.nix rule 3's business
	# (section 4). A datagram dropped on OUTPUT fails the send (eperm).
	load "$NONROOT" >/dev/null
	expect open "guest and L7 proxy: a NEW tcp flow from a non-root uid outside the build group to an internal address passes the floor" conn "$INFRA" 443
	expect sent "guest and L7 proxy: ...and so does its datagram to the internal address" udp "$INFRA" 9
	expect blocked "guest and L7 proxy: ...while rule 4a still drops the same uid towards link-local" conn "$MD" 80
	for p in $HOPS; do
		expect open "guest and L7 proxy: the same uid reaches the local hop 127.0.0.1:$p ($(hopname "$p"))" conn 127.0.0.1 "$p"
	done
	expect sent "guest and L7 proxy: ...and the bake's UDP agent port 127.0.0.1:$UDP_HOP" udp 127.0.0.1 "$UDP_HOP"
	expect sent "guest and L7 proxy: ...and broadcast (rule 4's broadcast drop is the build users' alone)" udp --src "$SELF" 255.255.255.255 "$UDP_HOP"
	# The negative control: a test-only uid drop towards the internal ranges
	# after rule 4a's egress line -- the shape of the removed passt/proxy leg
	# -- which the same probes must catch.
	load "$NONROOT; "'s/\(counter drop comment "cogworx-pve-floor-rule4a-egress"\)/\1\n\t\tmeta skuid 0 ct direction original ip daddr 198.18.0.0\/15 counter drop comment "test-only"/' >/dev/null
	expect blocked "guest and L7 proxy NEGATIVE CONTROL: a test-only uid drop towards the internal ranges is caught by the same tcp probe" conn "$INFRA" 443
	expect eperm "guest and L7 proxy NEGATIVE CONTROL: ...and by the same udp probe" udp "$INFRA" 9

	# --- root ------------------------------------------------------------------
	# The trusted half: rule 4 never names it.
	load >/dev/null
	expect open "root: reaches the internal address" conn "$INFRA" 443
	for p in $HOPS; do
		expect open "root: reaches the local hop 127.0.0.1:$p ($(hopname "$p"))" conn 127.0.0.1 "$p"
	done
	agent sent "root: reaches the bake's UDP agent port 127.0.0.1:$UDP_HOP" udp 127.0.0.1 "$UDP_HOP"
	if [ -s "$RUN/agent.log" ]; then ok "live: ...and the datagram arrived"; else bad "live: root's datagram to the UDP agent never arrived; the build-user drops below prove nothing"; fi

	# --- the nix build users -----------------------------------------------------
	# Our gid 0 re-pointed into the build group, in all eight of its rules.
	load "$BUILD0" >/dev/null
	before=$(counter rule4-build)
	expect blocked "build users: a NEW tcp flow to an internal address drops" conn "$INFRA" 443
	expect eperm "build users: a datagram to an internal address drops" udp "$INFRA" 9
	after=$(counter rule4-build)
	if [ "$after" -gt "$before" ]; then ok "live: ...and it was the rule4-build rule ($before -> $after)"; else bad "live: the rule4-build counter did not move ($before -> $after)"; fi
	expect open "build users: the infraAllow socket is reachable" conn "$ALLOW" 443
	expect blocked "build users: the same host on another port is not (infraAllow is exact)" conn "$ALLOW" 8443
	before=$(counter rule4-build-hop)
	for p in $HOPS; do
		expect blocked "build users: the local hop 127.0.0.1:$p ($(hopname "$p")) drops" conn 127.0.0.1 "$p"
	done
	after=$(counter rule4-build-hop)
	if [ "$after" -ge $((before + 9)) ]; then ok "live: ...all nine by the rule4-build-hop rule ($before -> $after)"; else bad "live: the rule4-build-hop counter did not count all nine hop probes ($before -> $after)"; fi
	for p in $NOT_HOPS; do
		expect open "build users: 127.0.0.1:$p, one port past a hop band, stays reachable" conn 127.0.0.1 "$p"
	done
	expect open "build users: the host DNS forwarder (127.0.0.53:53) stays reachable" conn 127.0.0.53 53
	if [ -n "$have6" ]; then
		expect blocked "build users: the mitmproxy hop port on ::1 drops (the v6 mirror)" conn ::1 18445
	else
		echo "SKIP - live: the ::1 hop leg (no ::1 on lo in this namespace); it is still pinned by the golden file and by checks.nix"
	fi
	# The bake's UDP agent: on loopback, and by way of the limited and the
	# segment broadcast address, each of which loops back to a wildcard
	# listener without using 127/8.
	# A multicast group, which, like broadcast, would let a neighbour answer
	# with a flow it opens (its reply direction passes rule4-build).
	before=$(counter rule4-build-hop-udp)
	agent eperm "build users: a datagram to the bake's UDP agent port 127.0.0.1:$UDP_HOP drops" udp 127.0.0.1 "$UDP_HOP"
	after=$(counter rule4-build-hop-udp)
	if [ "$after" -gt "$before" ] && ! [ -s "$RUN/agent.log" ]; then ok "live: ...by the rule4-build-hop-udp rule ($before -> $after), and nothing arrived"; else bad "live: the rule4-build-hop-udp counter did not move ($before -> $after), or the agent got it: $(arrived)"; fi
	if [ -n "$have6" ]; then
		expect eperm "build users: ...and the same port on ::1 (the UDP v6 mirror)" udp ::1 "$UDP_HOP"
	fi
	expect sent "build users: a datagram to 127.0.0.1:$((UDP_HOP + 1)), one port past the UDP agent's, is sent" udp 127.0.0.1 "$((UDP_HOP + 1))"
	before=$(counter rule4-build-bcast)
	agent eperm "build users: a limited broadcast (255.255.255.255:$UDP_HOP) drops" udp --src "$SELF" 255.255.255.255 "$UDP_HOP"
	expect eperm "build users: a broadcast to eth0's segment ($SEG_BCAST:$UDP_HOP), outside the internal ranges, drops" udp --src "$SELF" "$SEG_BCAST" "$UDP_HOP"
	expect eperm "build users: a multicast datagram ($MCAST:5353) drops" udp --src "$SELF" "$MCAST" 5353
	after=$(counter rule4-build-bcast)
	if [ "$after" -ge $((before + 3)) ] && ! [ -s "$RUN/agent.log" ]; then ok "live: ...all three by the rule4-build-bcast rule ($before -> $after), and the wildcard agent got nothing"; else bad "live: the rule4-build-bcast counter did not count all three ($before -> $after), or the agent got a broadcast: $(arrived)"; fi
	# A build-group listener on a hop port never answers. The launcher's
	# port probe connects as root and slides the base past a triple that
	# answers; a build user holding a hop port would steer the relays out of
	# the window. Here the listeners are ours (gid 0, the build group), and
	# the connecting side stands for root by losing the two destination-port
	# drops, so what is left between them is the source-port pair, on the
	# listener's SYN-ACK (a reply: it carries no direction scoping).
	load "$BUILD0; /rule4-build-hop\"/d; /rule4-build-hop6\"/d" >/dev/null
	before=$(counter rule4-build-hop-src)
	expect blocked "build users: a build-group listener on the mitmproxy hop 127.0.0.1:18445 never answers a probe (its SYN-ACK drops)" conn 127.0.0.1 18445
	expect blocked "build users: ...nor one on the bake agent's port 127.0.0.1:8500" conn 127.0.0.1 8500
	after=$(counter rule4-build-hop-src)
	if [ "$after" -gt "$before" ]; then ok "live: ...and it was the rule4-build-hop-src rule ($before -> $after)"; else bad "live: the rule4-build-hop-src counter did not move ($before -> $after)"; fi
	expect open "build users: a build-group listener one port past a hop band still answers" conn 127.0.0.1 18491
	if [ -n "$have6" ]; then
		expect blocked "build users: ...and on ::1 (the v6 mirror)" conn ::1 18445
	fi
	load "$BUILD0; /rule4-build-hop\"/d; /rule4-build-hop6\"/d; /rule4-build-hop-src\"/d" >/dev/null
	expect open "build users NEGATIVE CONTROL: with rule4-build-hop-src deleted too, the build-group listener on 127.0.0.1:18445 answers" conn 127.0.0.1 18445
	if [ -n "$have6" ]; then
		load "$BUILD0; /rule4-build-hop\"/d; /rule4-build-hop6\"/d; /rule4-build-hop-src6\"/d" >/dev/null
		expect open "build users NEGATIVE CONTROL: with rule4-build-hop-src6 deleted too, the build-group listener on ::1 answers" conn ::1 18445
	fi
	load "$BUILD0" >/dev/null
	# A reply. The listener belongs to the build group (gid 0 here), and its
	# SYN-ACK to the internal source is owned by that listener, so the gid
	# selector resolves on it: it passes on the direction scoping alone.
	expect open "build users: a REPLY to an internal address passes (original-direction scoping)" conn --src "$INFRA" "$SELF" 9000
	# The negative controls: each drop removed in turn, and the direction
	# scoping stripped, shown by the same probes. The hop listeners here are
	# the build group's too, so the source-port drop is taken out first: the
	# destination-port drop alone still blocks the hop, and only with both
	# gone is it reachable.
	load "$BUILD0; /rule4-build-hop-src\"/d" >/dev/null
	expect blocked "build users: with the source-port drop deleted, rule4-build-hop alone still drops the mitmproxy hop" conn 127.0.0.1 18445
	load "$BUILD0; /rule4-build-hop-src\"/d; /rule4-build-hop\"/d" >/dev/null
	expect open "build users NEGATIVE CONTROL: with rule4-build-hop deleted too the mitmproxy hop is reachable (the drop above was that rule)" conn 127.0.0.1 18445
	if [ -n "$have6" ]; then
		load "$BUILD0; /rule4-build-hop-src6\"/d" >/dev/null
		expect blocked "build users: with the v6 source-port drop deleted, rule4-build-hop6 alone still drops the ::1 hop" conn ::1 18445
		load "$BUILD0; /rule4-build-hop-src6\"/d; /rule4-build-hop6\"/d" >/dev/null
		expect open "build users NEGATIVE CONTROL: with rule4-build-hop6 deleted too the ::1 hop is reachable" conn ::1 18445
	fi
	load "$BUILD0; /rule4-build-hop-udp\"/d" >/dev/null
	agent sent "build users NEGATIVE CONTROL: with rule4-build-hop-udp deleted the datagram to 127.0.0.1:$UDP_HOP is sent" udp 127.0.0.1 "$UDP_HOP"
	if [ -s "$RUN/agent.log" ]; then ok "live: ...and the agent got it ($(arrived))"; else bad "live: with rule4-build-hop-udp deleted the agent still got nothing; the drop above proves nothing"; fi
	if [ -n "$have6" ]; then
		load "$BUILD0; /rule4-build-hop-udp6\"/d" >/dev/null
		expect sent "build users NEGATIVE CONTROL: with rule4-build-hop-udp6 deleted the datagram to ::1 is sent" udp ::1 "$UDP_HOP"
	fi
	load "$BUILD0; /rule4-build-bcast\"/d" >/dev/null
	agent sent "build users NEGATIVE CONTROL: with rule4-build-bcast deleted the limited broadcast is sent" udp --src "$SELF" 255.255.255.255 "$UDP_HOP"
	if grep -qx "$SELF" "$RUN/agent.log"; then ok "live: ...and loops back to the wildcard agent past the loopback UDP drop ($(arrived)): why the broadcast drop is needed beside it"; else bad "live: with rule4-build-bcast deleted the broadcast did not reach the wildcard agent ($(arrived))"; fi
	agent sent "build users NEGATIVE CONTROL: ...and so is the broadcast to eth0's segment, which @infra4 does not cover" udp --src "$SELF" "$SEG_BCAST" "$UDP_HOP"
	if grep -qx "$SELF" "$RUN/agent.log"; then ok "live: ...and it loops back to the wildcard agent too ($(arrived)): why the drop keys on the address type, not on a fixed set"; else bad "live: with rule4-build-bcast deleted the segment broadcast did not reach the wildcard agent ($(arrived)); the drop above proves nothing"; fi
	expect sent "build users NEGATIVE CONTROL: ...and so is the multicast datagram" udp --src "$SELF" "$MCAST" 5353
	load "$BUILD0; /rule4-build\"/d" >/dev/null
	expect open "build users NEGATIVE CONTROL: with rule4-build deleted the internal address is reachable" conn "$INFRA" 443
	load "$BUILD0; /rule4-build\"/s/ ct direction original//" >/dev/null
	expect blocked "build users NEGATIVE CONTROL: without the direction scoping the same reply is dropped" conn --src "$INFRA" "$SELF" 9000
	load >/dev/null

	# --- the site floor's boot verify leg -----------------------------------
	# cogworx-pve-floor-verify as realized (the unit's ExecStartPost), run so
	# its probes and its classifier are exercised, not only shellchecked: a
	# mistake there fails closed at boot, and sshd requires the unit. It
	# probes as root, nobody and the first build user in one run, and setpriv
	# cannot switch uid in a one-uid namespace, so the copy enters a network
	# namespace per account instead, each with this floor loaded as that
	# account would meet it (nobody: rule 4a's root test re-pointed; the
	# build user: the build group re-pointed too) and the metadata address
	# listening on its lo. Root's probes run here, against section 3's
	# listeners. Then one run with a breakage per probe, which must name each,
	# and one on an image without a build account.
	if [ -z "$PVE_VERIFY" ]; then
		echo "SKIP - live: the site floor's boot verify leg (no realized verify script given)"
	else
		vf_skip=""
		mkdir -p "$RUN/ns"
		vf_load() {
			local acct="$1" rw="$2"
			sed -e 's/meta skgid "nixbld"/meta skgid 65533/' -e "$rw" "$RUN/base.nft" > "$RUN/ns/$acct.nft"
			nsenter --net="$RUN/ns/$acct" -- nft -f "$RUN/ns/$acct.nft"
		}
		for acct in nobody nixbld1; do
			unshare -n sleep 600 2>/dev/null &
			vp=$!
			PIDS+=("$vp")
			for _ in $(seq 50); do
				[ -e "/proc/$vp/ns/net" ] && [ "$(readlink "/proc/$vp/ns/net")" != "$(readlink /proc/self/ns/net)" ] && break
				sleep 0.1
			done
			ln -sfn "/proc/$vp/ns/net" "$RUN/ns/$acct"
			if [ "$(readlink "/proc/$vp/ns/net" 2>/dev/null)" = "$(readlink /proc/self/ns/net)" ] \
				|| ! nsenter --net="$RUN/ns/$acct" -- bash -c "ip link set lo up && ip addr add $MD/32 scope host dev lo" 2>/dev/null; then
				vf_skip="no network namespace for $acct"
				break
			fi
			rm -f "$RUN/ns/$acct.ready"
			nsenter --net="$RUN/ns/$acct" -- python3 "$PROBE" listen tcp "$MD" 80 "$RUN/ns/$acct.ready" >/dev/null 2>&1 &
			PIDS+=($!)
			for _ in $(seq 50); do [ -e "$RUN/ns/$acct.ready" ] && break; sleep 0.1; done
			[ -e "$RUN/ns/$acct.ready" ] || { vf_skip="no metadata listener for $acct"; break; }
		done
		if [ -n "$vf_skip" ]; then
			echo "SKIP - live: the site floor's boot verify leg ($vf_skip)"
		else
			# The copy: setpriv swapped for the account's namespace, and the
			# build account's existence check pinned. Each swap must land
			# exactly once, or the run below would test something else.
			# $1 replaces the existence check (true: the account exists).
			vf_copy() {
				# shellcheck disable=SC2016 # the script's own ${build_group}, matched literally
				sed -e "s|setpriv --reuid \"\$user\" --regid \"\$group\" --clear-groups --|nsenter --net=\"$RUN/ns/\$user\" --|" \
					-e 's|if id -u "${build_group}1" |if '"$1"' |' "$PVE_VERIFY" > "$RUN/pve-verify"
				chmod +x "$RUN/pve-verify"
				if [ "$(grep -cF 'nsenter --net=' "$RUN/pve-verify")" != 1 ] || grep -qF 'setpriv --reuid' "$RUN/pve-verify" \
					|| [ "$(grep -cF "if $1 " "$RUN/pve-verify")" != 1 ]; then
					bad "live: the verify leg no longer has the one setpriv call and the one build-account check this test swaps: $(grep -nE 'setpriv|nsenter|id -u' "$RUN/pve-verify")"
					return 1
				fi
			}
			vf_run() { vf_rc=0; vf_out=$("$RUN/pve-verify" 2>&1) || vf_rc=$?; }
			if vf_copy true; then
				load >/dev/null
				vf_load nobody "$NONROOT"
				vf_load nixbld1 "$NONROOT; $BUILD0"
				vf_run
				if [ "$vf_rc" = 0 ] && printf '%s' "$vf_out" | grep -qF 'cogworx-pve-floor: rules 4a and 4 verified'; then
					ok "live: the boot verify leg passes on this floor (root reaches the metadata address and the mitmproxy hop port; nobody and the build user are dropped towards link-local, the build user towards the hop)"
				else
					bad "live: the boot verify leg failed on an intact floor (rc $vf_rc): $vf_out"
				fi
				# One breakage per probe: nobody's rule 4a test left at root (so
				# it reaches the metadata address), the build user's hop drop
				# deleted, and a test-only drop of root's hop port.
				vf_load nobody ""
				vf_load nixbld1 "$NONROOT; $BUILD0; /rule4-build-hop\"/d"
				load 's/\(counter drop comment "cogworx-pve-floor-rule4a-egress"\)/\1\n\t\tmeta skuid 0 ip daddr 127.0.0.1 tcp dport 18445 counter drop comment "test-only"/' >/dev/null
				vf_run
				missing=""
				for want in 'PROBE FAILED: rule 4a, nobody (nobody -> 169.254.169.254:80) was open, expected blocked' \
					'PROBE FAILED: rule 4 hop control (root -> 127.0.0.1:18445) was blocked' \
					'PROBE FAILED: rule 4, nix build user to the mitmproxy hop (nixbld1 -> 127.0.0.1:18445) was refused, expected blocked' \
					'3 probe(s) failed; the sandbox must not start'; do
					printf '%s' "$vf_out" | grep -qF -- "$want" || missing="$missing [$want]"
				done
				if [ "$vf_rc" = 1 ] && [ -z "$missing" ]; then
					ok "live: the boot verify leg NEGATIVE CONTROL: with one breakage per probe it exits 1 and names each (nobody reaching link-local, root's hop control blocked, the build user's hop drop missing)"
				else
					bad "live: the boot verify leg did not fail as it must (rc $vf_rc; missing:$missing): $vf_out"
				fi
				load >/dev/null
			fi
			if vf_copy false; then
				vf_load nobody "$NONROOT"
				vf_run
				if [ "$vf_rc" = 0 ] && printf '%s' "$vf_out" | grep -qF 'the build-user probes are skipped'; then
					ok "live: the boot verify leg on an image without a build account passes and says the build-user probes are skipped"
				else
					bad "live: the boot verify leg without a build account (rc $vf_rc): $vf_out"
				fi
			fi
		fi
	fi
	load >/dev/null

	# --- ingress is open ------------------------------------------------------
	# No ingress filter (decision 2026-10-21): sshd, the guest SSH and HTTP
	# forwards and the mosh range are reachable from any neighbour, and rely on
	# their own authentication. Shown over the rule 4a neighbour's real (non-lo)
	# veth link -- every packet sent inside this namespace arrives on lo --
	# from two sources: one outside the internal ranges and one inside them.
	# The negative control inserts a test-only input drop on the same ports,
	# which the same probes must catch.
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
		srcs="198.51.100.2 198.18.9.20"
		where() { case "$1" in 198.51.100.2) echo "outside the internal ranges" ;; 198.18.9.20) echo "an internal address" ;; esac; }
		nbconn() { nsenter -t "$nb" -n -- python3 "$PROBE" connect --src "$1" "$SELF" "$2"; }
		nbudp() {
			: > "$RUN/udp.log"
			for src in $srcs; do
				nsenter -t "$nb" -n -- python3 "$PROBE" udp --src "$src" "$SELF" 60002 >/dev/null
			done
			sleep 0.3
		}
		load >/dev/null
		for src in $srcs; do
			for p in 22 2223 8081; do
				expect open "ingress is open: a neighbour at $src ($(where "$src")) reaches $(surface "$p") ($SELF:$p) over the NIC" nbconn "$src" "$p"
			done
		done
		nbudp
		missing=""
		for src in $srcs; do grep -qx "$src" "$RUN/udp.log" || missing="$missing $src"; done
		if [ -z "$missing" ]; then
			ok "live: ingress is open: datagrams from both neighbour sources reach the mosh range ($SELF:60002) over the NIC"
		else
			bad "live: ingress is open: the datagram to the mosh range from$missing never arrived (logged: $(tr '\n' ' ' < "$RUN/udp.log"))"
		fi
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
			# test_floor.sh models them: the passt account re-pointed at uid 0,
			# in the gce table only (the site table names neither passt nor
			# the proxy). Probe 2 is the one that cannot be modelled: with
			# passt and the control uid collapsed onto uid 0, the control-uid
			# exception admits it. The property shown is that the site table
			# neither re-opens what the gce floor closes nor closes what it
			# keeps open (the L7 funnel and the host DNS forwarder, whose
			# listeners section 3 started).
			listen tcp "$SELF" 18443
			sed -e 's/meta skuid "cogbox-passt"/meta skuid 0/' "$RUN/gce/cogworx-floor.nft" > "$RUN/gce/live0.nft"
			load >/dev/null
			if ! out=$(nft -f "$RUN/gce/live0.nft" 2>&1); then
				bad "live: the passt-as-uid-0 gce ruleset did not load beside this one: $out"
			else
				expect blocked "beside the site floor, gce probe 1 holds: passt cannot reach the metadata API" conn "$MD" 80
				expect blocked "beside the site floor, gce probe 3 holds: the VM's own address stays closed outside the SSH exception" conn "$SELF" 18443
				expect blocked "beside the site floor, gce probe 6 holds: passt cannot reach the mitm hop on loopback" conn 127.0.0.1 18445
				expect open "beside the site floor, gce probe 7 holds: passt still reaches the L7 funnel target" conn 127.0.0.1 18443
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
PVE_VERIFY="${5:-}"
[ -r "$RENDER" ] || { echo "FAIL: renderer not readable: $RENDER" >&2; exit 1; }

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

# The fixture: fictional, and the same values pve/checks.nix's fixture system
# sets (hopTCP is what floor-site.nix derives from the launcher's base 18443,
# l7PortTriples 16 and the fixture's buildDenyLoopbackTCP port 8500, hopUDP
# its buildDenyLoopbackUDP port 7301), so the realized ruleset can be compared
# to the golden one below.
cat > "$ROOT/base.json" <<'EOF'
{
	"version": 1,
	"iface": "eth0",
	"infraDenyCIDRs": ["198.18.0.0/15", "203.0.113.0/24"],
	"infraAllow": [{"address": "203.0.113.80", "protocol": "tcp", "port": 443}],
	"buildGroup": "nixbld",
	"hopTCP": [[8500, 8500], [18043, 18090], [18443, 18490]],
	"hopUDP": [[7301, 7301]]
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

refuses infra-slash0       'd["infraDenyCIDRs"] = ["0.0.0.0/0"]'                 'infraDenyCIDRs[0]'
refuses infra-wider-than-8 'd["infraDenyCIDRs"] = ["198.0.0.0/7"]'               'wider than /8'
refuses infra-loopback     'd["infraDenyCIDRs"] = ["127.0.0.0/8"]'               'overlaps 127.0.0.0/8'
refuses infra-in-loopback  'd["infraDenyCIDRs"] = ["127.1.2.0/24"]'              'overlaps 127.0.0.0/8'
refuses infra-metadata     'd["infraDenyCIDRs"] = ["169.254.169.254"]'           'overlaps 169.254.0.0/16'
refuses infra-around-ll    'd["infraDenyCIDRs"] = ["169.0.0.0/8"]'               'overlaps 169.254.0.0/16'
refuses infra-this-net     'd["infraDenyCIDRs"] = ["0.1.0.0/16"]'                'overlaps 0.0.0.0/8'
refuses allow-link-local   'd["infraAllow"][0]["address"] = "169.254.169.254"'  'infraAllow[0].address'
refuses allow-loopback     'd["infraAllow"][0]["address"] = "127.0.0.1"'        'overlaps 127.0.0.0/8'
refuses allow-cidr         'd["infraAllow"][0]["address"] = "203.0.113.0/24"'   'is not a single address'
refuses allow-wide-cidr    'd["infraAllow"][0]["address"] = "10.0.0.0/8"'       'is not a single address'
refuses infra-host-bits    'd["infraDenyCIDRs"] = ["198.18.7.1/24"]'             'not a canonical'
refuses infra-leading-zero 'd["infraDenyCIDRs"] = ["198.018.7.0/24"]'            'infraDenyCIDRs[0]'
refuses infra-ipv6         'd["infraDenyCIDRs"] = ["2001:db8::/32"]'             'not an IPv4'
refuses infra-hostname     'd["infraDenyCIDRs"] = ["git.example.com"]'           'not an IPv4'
refuses infra-not-list     'd["infraDenyCIDRs"] = "198.18.0.0/15"'               'expected a list'
refuses allow-protocol     'd["infraAllow"][0]["protocol"] = "icmp"'             'infraAllow[0].protocol'
refuses allow-port-zero    'd["infraAllow"][0]["port"] = 0'                      'infraAllow[0].port'
refuses allow-port-high    'd["infraAllow"][0]["port"] = 70000'                  'infraAllow[0].port'
refuses allow-port-string  'd["infraAllow"][0]["port"] = "443"'                  'infraAllow[0].port'
refuses allow-extra-key    'd["infraAllow"][0]["comment"] = "x"'                 'infraAllow[0]'
refuses build-quote        'd["buildGroup"] = "nix\"bld"'                        'buildGroup'
refuses iface-injection    'd["iface"] = "eth0\" accept"'                        'iface'
refuses hop-missing        'del d["hopTCP"]'                                     'missing key(s) hopTCP'
refuses hop-empty          'd["hopTCP"] = []'                                    'hopTCP: expected at least one'
refuses hop-not-list       'd["hopTCP"] = 18445'                                 'hopTCP'
refuses hop-reversed       'd["hopTCP"] = [[18490, 18443]]'                      'hopTCP[0]: [18490, 18443] has lo > hi'
refuses hop-port-zero      'd["hopTCP"] = [[0, 18490]]'                          'hopTCP[0]'
refuses hop-overlap        'd["hopTCP"] = [[18043, 18443], [18443, 18490]]'      'ascending and disjoint'
refuses hop-out-of-order   'd["hopTCP"] = [[18443, 18490], [18043, 18090]]'      'ascending and disjoint'
refuses udp-hop-missing    'del d["hopUDP"]'                                     'missing key(s) hopUDP'
refuses udp-hop-not-list   'd["hopUDP"] = 7301'                                  'hopUDP'
refuses udp-hop-reversed   'd["hopUDP"] = [[7310, 7301]]'                        'hopUDP[0]: [7310, 7301] has lo > hi'
refuses udp-hop-port-high  'd["hopUDP"] = [[7301, 70000]]'                       'hopUDP[0]'
refuses udp-hop-overlap    'd["hopUDP"] = [[7301, 7305], [7305, 7310]]'          'hopUDP[1]: [7305, 7310] does not start above'
refuses udp-hop-unordered  'd["hopUDP"] = [[7305, 7310], [7301, 7302]]'          'ascending and disjoint'
refuses open-ingress-knob  'd["allowOpenIngress"] = True'                        'unknown key'
# A spec that still carries rule 5's ports (a stale composer) fails the build.
refuses stale-ingressTCP   'd["ingressTCP"] = [[22, 22]]'                        'unknown key'
refuses stale-ingressUDP   'd["ingressUDP"] = [[60000, 60031]]'                  'unknown key'
# So does one that still carries the inputs of rule 4's passt and proxy legs
# (decision 2026-10-22).
refuses stale-controlPlaneCIDRs 'd["controlPlaneCIDRs"] = ["198.18.7.0/24"]'     'unknown key(s) controlPlaneCIDRs'
refuses stale-passtUser         'd["passtUser"] = "cogbox-passt"'                'unknown key(s) passtUser'
refuses stale-proxyUser         'd["proxyUser"] = "cogbox-proxy"'                'unknown key(s) proxyUser'
refuses stale-moshUDP           'd["moshUDP"] = [[60000, 60031]]'                'unknown key(s) moshUDP'
refuses spec-version       'd["version"] = 2'                                    'version'

accepts exactly-slash-8    'd["infraDenyCIDRs"] = ["10.0.0.0/8"]'
accepts beside-loopback    'd["infraDenyCIDRs"] = ["126.0.0.0/8", "128.0.0.0/8"]'
accepts beside-link-local  'd["infraDenyCIDRs"] = ["169.253.0.0/16", "169.255.0.0/16"]'
accepts overlapping-infra  'd["infraDenyCIDRs"] = ["198.18.0.0/15", "198.18.4.0/24"]'
accepts allow-slash-32     'd["infraAllow"][0]["address"] = "203.0.113.80/32"'
accepts empty              'd["infraDenyCIDRs"] = []; d["infraAllow"] = []'
accepts hop-adjacent       'd["hopTCP"] = [[18043, 18442], [18443, 18490]]'
accepts hop-single         'd["hopTCP"] = [[18443, 18490]]'
accepts udp-hop-empty      'd["hopUDP"] = []'
accepts udp-hop-two        'd["hopUDP"] = [[7301, 7301], [7400, 7410]]'

# --- 2. the rendered ruleset ---------------------------------------------------
render base || bad "the fixture spec was refused: $(cat "$ROOT/base.err")"
nft="$ROOT/base.nft"
# Golden. A deliberate change to the renderer updates this in the same commit;
# an accidental one fails here with the diff.
cat > "$ROOT/golden.nft" <<'EOF'
table inet cogworx_pve_floor
delete table inet cogworx_pve_floor
table inet cogworx_pve_floor {
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
		meta skgid "nixbld" ct direction original ip daddr 127.0.0.0/8 tcp dport { 8500, 18043-18090, 18443-18490 } counter drop comment "cogworx-pve-floor-rule4-build-hop"
		meta skgid "nixbld" ct direction original ip6 daddr ::1 tcp dport { 8500, 18043-18090, 18443-18490 } counter drop comment "cogworx-pve-floor-rule4-build-hop6"
		meta skgid "nixbld" ip saddr 127.0.0.0/8 tcp sport { 8500, 18043-18090, 18443-18490 } counter drop comment "cogworx-pve-floor-rule4-build-hop-src"
		meta skgid "nixbld" ip6 saddr ::1 tcp sport { 8500, 18043-18090, 18443-18490 } counter drop comment "cogworx-pve-floor-rule4-build-hop-src6"
		meta skgid "nixbld" ct direction original ip daddr 127.0.0.0/8 udp dport 7301 counter drop comment "cogworx-pve-floor-rule4-build-hop-udp"
		meta skgid "nixbld" ct direction original ip6 daddr ::1 udp dport 7301 counter drop comment "cogworx-pve-floor-rule4-build-hop-udp6"
		meta skgid "nixbld" ct direction original meta nfproto ipv4 fib daddr type { broadcast, multicast } counter drop comment "cogworx-pve-floor-rule4-build-bcast"
		ip daddr 203.0.113.80 tcp dport 443 counter accept comment "cogworx-pve-floor-rule4-infra-allow"
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
		ok "the ruleset floor-site.nix realized for the fixture system is the golden one (hop ports from the launcher's base, l7PortTriples, buildDenyLoopbackTCP and buildDenyLoopbackUDP)"
	else
		bad "the realized ruleset differs from the golden file: $(cat "$ROOT/realized.diff")"
	fi
fi

# Properties, one by one, so a golden update that breaks one still says which.
# Every uid/gid deny is original-direction scoped but the hop source-port
# pair, which exists to drop a reply (the SYN-ACK to the launcher's probe).
while IFS= read -r line; do
	case "$line" in
		*'rule4-build-hop-src'*) ;;
		*'ct direction original'*) ;;
		*) bad "a uid/gid deny is not scoped to the original direction (replies would be dropped): $line" ;;
	esac
done < <(grep -E 'meta sk(uid|gid) .* drop' "$nft")
n=$(grep -E 'meta sk(uid|gid) .* drop' "$nft" | grep -cvF 'rule4-build-hop-src')
if [ "$n" = 7 ]; then ok "every uid/gid deny but the hop source-port pair (4a, 4-build-hop, 4-build-hop6, 4-build-hop-udp, 4-build-hop-udp6, 4-build-bcast, 4-build) is original-direction scoped"; else bad "expected 7 original-direction uid/gid denies, found $n"; fi
src=$(grep -F 'rule4-build-hop-src' "$nft")
if [ "$(printf '%s\n' "$src" | grep -c .)" = 2 ] && ! printf '%s\n' "$src" | grep -qF 'ct direction'; then
	ok "the hop source-port pair (v4 and v6) carries no direction scoping, so it matches the SYN-ACK of a flow root opened"
else
	bad "the hop source-port drops are not exactly two unscoped rules: $src"
fi
if grep -E '^[[:space:]]*ip daddr @infra4' "$nft"; then
	bad "rule 4 renders an @infra4 drop with no uid/gid selector: it would drop the trusted half's own traffic"
else
	ok "no rule-4 drop without a uid/gid selector"
fi
line_of() { grep -nF "$1" "$nft" | head -1 | cut -d: -f1; }
above() {
	local a b
	a=$(line_of "cogworx-pve-floor-$1\""); b=$(line_of "cogworx-pve-floor-$2\"")
	if [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; then ok "$1 is rendered above $2"; else bad "$1 ($a) is not above $2 ($b)"; fi
}
above rule4-infra-allow rule4-build
above rule4-build-hop rule4-infra-allow
above rule4-build-hop6 rule4-infra-allow
above rule4-build-hop-src rule4-infra-allow
above rule4-build-hop-src6 rule4-infra-allow
above rule4-build-hop-udp rule4-infra-allow
above rule4-build-hop-udp6 rule4-infra-allow
above rule4-build-bcast rule4-infra-allow
# Rule 4 names the nix build users and nobody else: rule 4a's root test is
# the only uid selector, every gid selector names the build group, and
# neither the passt nor the proxy account, nor any @cp, is left.
sel=$(grep -F 'meta skuid' "$nft")
if [ "$(printf '%s\n' "$sel" | grep -c .)" = 1 ] && printf '%s\n' "$sel" | grep -qF 'meta skuid != 0 ct direction original ip daddr 169.254.0.0/16'; then
	ok "the only uid selector is rule 4a's root test (the guest and the L7 proxy are not rule 4's)"
else
	bad "the ruleset selects on a uid other than in rule 4a's root test: $sel"
fi
gids=$(grep -F 'meta skgid' "$nft")
if [ "$(printf '%s\n' "$gids" | grep -c .)" = 8 ] && ! printf '%s\n' "$gids" | grep -vqF 'meta skgid "nixbld" '; then
	ok "every gid selector (eight) names the build group"
else
	bad "the gid selectors are not exactly rule 4's eight build-group rules: $gids"
fi
named=""
for pat in 'cogbox-passt' 'cogbox-proxy' '@cp' 'set cp ' 'rule4-uid' 'rule4-cp-mosh'; do
	grep -qF -- "$pat" "$nft" && named="$named '$pat'"
done
if [ -z "$named" ]; then
	ok "the ruleset names neither the passt nor the proxy account, and no @cp"
else
	bad "the ruleset names$named (rule 4 names the nix build users only): $(cat "$nft")"
fi
# The hop drops carry the spec's three bands, in both families and both
# directions.
for m in 'ct direction original ip daddr 127.0.0.0/8 tcp dport' 'ct direction original ip6 daddr ::1 tcp dport' 'ip saddr 127.0.0.0/8 tcp sport' 'ip6 saddr ::1 tcp sport'; do
	if grep -qF "meta skgid \"nixbld\" $m { 8500, 18043-18090, 18443-18490 } counter drop" "$nft"; then
		ok "the hop drop ($m) carries every hop band"
	else
		bad "no hop drop ($m) with every hop band: $(grep -F rule4-build-hop "$nft")"
	fi
done
# The UDP hop drops carry the spec's UDP band, in both families; several
# bands render as a set.
for m in 'ip daddr 127.0.0.0/8 udp dport' 'ip6 daddr ::1 udp dport'; do
	if grep -qF "meta skgid \"nixbld\" ct direction original $m 7301 counter drop" "$nft"; then
		ok "the UDP hop drop ($m) carries the UDP band"
	else
		bad "no UDP hop drop ($m) with the UDP band: $(grep -F rule4-build-hop-udp "$nft")"
	fi
done
mkspec udp-two 'd["hopUDP"] = [[7301, 7301], [7400, 7410]]'
render udp-two
if [ "$(grep -cF 'udp dport { 7301, 7400-7410 } counter drop' "$ROOT/udp-two.nft")" = 2 ]; then
	ok "two UDP hop bands render as one set in both UDP hop drops"
else
	bad "two UDP hop bands did not render as a set: $(grep -F rule4-build-hop-udp "$ROOT/udp-two.nft")"
fi
# No UDP hops, no UDP hop drop (nft refuses an empty set); the broadcast
# drop and the rest of rule 4 stay.
mkspec udp-none 'd["hopUDP"] = []'
render udp-none
if ! grep -qF 'rule4-build-hop-udp' "$ROOT/udp-none.nft" && grep -qF 'rule4-build-bcast"' "$ROOT/udp-none.nft" \
	&& [ "$(grep -cF 'meta skgid' "$ROOT/udp-none.nft")" = 6 ]; then
	ok "an empty hopUDP renders no UDP hop drop and keeps the broadcast drop and the rest of rule 4"
else
	bad "an empty hopUDP did not render rule 4 without its UDP hop drops: $(grep -F 'meta skgid' "$ROOT/udp-none.nft")"
fi
if grep -qF 'meta skgid "nixbld" ct direction original meta nfproto ipv4 fib daddr type { broadcast, multicast } counter drop comment "cogworx-pve-floor-rule4-build-bcast"' "$nft"; then
	ok "the broadcast drop keys on the IPv4 address type: every broadcast address (the limited one and each local segment's) and every multicast group"
else
	bad "no IPv4 broadcast and multicast drop by address type: $(grep -F rule4-build-bcast "$nft")"
fi
mkspec hop-one 'd["hopTCP"] = [[18443, 18490]]'
render hop-one
if grep -qF 'ip daddr 127.0.0.0/8 tcp dport 18443-18490 counter drop' "$ROOT/hop-one.nft"; then
	ok "a single hop band renders as a plain range"
else
	bad "a single hop band did not render as a plain range: $(grep -F rule4-build-hop "$ROOT/hop-one.nft")"
fi
# The input chain is exactly one rule, rule 4a's input drop: the floor filters
# no ingress (floor_render.py's "No ingress filter").
in_rules=$(sed -n '/chain input {/,/^\t}/{/chain input {/d;/type filter hook input/d;/^\t}/d;p}' "$nft")
if [ "$(printf '%s\n' "$in_rules" | grep -c .)" = 1 ] && printf '%s\n' "$in_rules" | grep -qF 'iifname != "lo" ip daddr 169.254.0.0/16 counter drop comment "cogworx-pve-floor-rule4a-input"'; then
	ok "the input chain is exactly one rule, rule4a-input (no ingress filter)"
else
	bad "the input chain is not exactly rule 4a's input drop: $in_rules"
fi
mkspec empty 'd["infraDenyCIDRs"] = []; d["infraAllow"] = []; d["hopUDP"] = []'
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
	out=$(unshare -Urn bash "${BASH_SOURCE[0]}" --live-child "$ROOT" "$GCE_VERIFY" "$PVE_VERIFY" 2>&1) || rc=$?
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
