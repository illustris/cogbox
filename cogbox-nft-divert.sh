#!/bin/sh
# cogbox separate-pod enforcer nft divert + fail-closed floor (nft-init sidecar PID1).
#
# Uses REDIRECT (DNAT), NOT TPROXY -- so NOTHING downstream needs CAP_NET_ADMIN
# beyond this one sidecar (IP_TRANSPARENT/fwmark would force it). nft-init (the
# ONLY privileged container; NET_ADMIN/NET_RAW) DNATs the agent's locally-
# originated TCP egress to the in-pod divert shim (`cogbox __divertshim`, a
# no-caps sidecar on the SAME pod netns). The shim recovers the original dst via
# SO_ORIGINAL_DST (conntrack) and carries it over a SOCKS5 hop to the SEPARATE
# enforcer pod for L7 enforcement.
#
# The enforcer carve-out (validated): the shim's own SOCKS5
# connection to the enforcer must NOT be redirected back into the shim, else it
# loops. Exempt it by destination = the enforcer's STABLE ClusterIP:port. The CNI's
# socket-LB does NOT rewrite the in-pod OUTPUT netfilter hook's view (the
# ClusterIP -> backend DNAT is downstream in eBPF tc), so the in-pod nft hook sees
# the ClusterIP and the exemption matches across enforcer-pod restarts -- no
# pod-IP refresh. This replaces the old cgroup-keyed handshake entirely.
#
# nft-init image PATH carries nft + ip + coreutils + /bin/sh ONLY (no grep/awk/
# find): this script uses nft for the ruleset and POSIX shell built-ins alone to
# parse /etc/resolv.conf (no external text tools), with absolute paths nowhere
# required (PATH is set by the image). The fail-closed floor + divert load
# ATOMICALLY (one nft -f transaction, `flush ruleset`-first so it is idempotent
# across restarts with no open window); guard with set -e so nft-init fails loudly
# if nft rejects them.
set -e
PORT="${COGBOX_DIVERT_PORT:-18443}"       # == the in-pod shim's loopback listener (REDIRECT target)
ENFORCER_IP="${COGBOX_ENFORCER_IP:-}"     # the enforcer Service ClusterIP (stable VIP)
ENFORCER_PORT="${COGBOX_ENFORCER_PORT:-}" # the enforcer l7proxy SOCKS5 port (== its base)

# --- resolver-restricted DNS allow rules -------------------------------------
# The floor is a DEFAULT-DROP allowlist (see the FILTER-table comment below). DNS
# is the single UDP exception, and it is NOT open to the world: allow udp/53 ONLY
# to the cluster resolver(s). Discover them from the kubelet-managed
# /etc/resolv.conf, whose `nameserver` lines hold the kube-dns ClusterIP. Emit one
# allow rule per VALID IPv4 nameserver. An IPv6 nameserver is skipped (the floor
# rejects all v6 egress, so it could never carry DNS anyway). If resolv.conf yields
# NO usable nameserver we allow NONE -- DNS then fails loudly rather than silently
# re-opening udp/53-to-anywhere as the exfil channel the old floor permitted.
# Parsing uses shell built-ins only and validates each candidate as a dotted-quad
# BEFORE it is interpolated into the nft program, so a malformed or attacker-shaped
# resolv.conf line can inject neither shell nor nft.
valid_ipv4() {
	# 0 iff $1 is exactly four 0-255 octets separated by dots, nothing else.
	# Reject empties, a leading/trailing/doubled dot, and any non-digit/dot char
	# up front -- a leading/trailing dot would otherwise survive field-splitting as
	# a 4-octet false positive that nft then rejects (crashing the atomic load).
	case "$1" in
		'' | .* | *. | *..* | *[!0-9.]*) return 1 ;;
	esac
	_oifs=$IFS
	IFS=.
	# shellcheck disable=SC2086  # deliberate word-split on '.' into octets
	set -- $1
	IFS=$_oifs
	[ "$#" -eq 4 ] || return 1
	for _o in "$@"; do
		case "$_o" in
			'' | *[!0-9]*) return 1 ;;
		esac
		[ "${#_o}" -le 3 ] && [ "$_o" -le 255 ] || return 1
	done
	return 0
}

DNS_ALLOW=""
NS_OK=0
if [ -r /etc/resolv.conf ]; then
	while read -r _kw _ns _rest; do
		[ "$_kw" = nameserver ] || continue
		if valid_ipv4 "$_ns"; then
			DNS_ALLOW="${DNS_ALLOW}
    ip daddr ${_ns} udp dport 53 accept"
			NS_OK=$((NS_OK + 1))
		else
			echo "cogbox-nft-divert: WARN: ignoring non-IPv4/malformed nameserver '${_ns}' from /etc/resolv.conf" >&2
		fi
	done < /etc/resolv.conf
fi
if [ "$NS_OK" -eq 0 ]; then
	echo "cogbox-nft-divert: WARN: no usable IPv4 nameserver in /etc/resolv.conf; udp/53 will be DENIED (fail-loud; no exfil fallback to udp/53-anywhere)" >&2
fi

# Fail-closed if the enforcer carve-out coordinates are missing: without them the
# exemption rule is malformed and the atomic load would leave the netns with NO
# rules at all (open egress). Load a deny-all floor (default drop; only lo + the
# resolver-restricted DNS allow pass -- the leak-closing allowlist applies on this
# path too) first, then refuse to start, so a misconfig blocks egress rather than
# leaking it.
if [ -z "$ENFORCER_IP" ] || [ -z "$ENFORCER_PORT" ]; then
	nft -f - <<EOF
flush ruleset
table inet cogbox_floor {
  chain output {
    type filter hook output priority mangle; policy drop;
    oif "lo" accept$DNS_ALLOW
  }
  chain forward { type filter hook forward priority filter; policy drop; }
}
EOF
	echo "cogbox-nft-divert: FATAL: COGBOX_ENFORCER_IP/PORT unset; loaded deny-all floor and refusing to start" >&2
	exit 64
fi

nft -f - <<EOF
flush ruleset

# NAT table: DNAT the agent's LOCALLY-ORIGINATED TCP egress to the in-pod shim.
# REDIRECT in OUTPUT maps locally-originated packets to 127.0.0.1, matching the
# shim's 127.0.0.1:$PORT listener (the pod shares ONE netns across containers).
# The forwarded leg is NOT redirected -- it is DROPPED by the FORWARD chain below.
table inet cogbox_divert {
  chain output {
    type nat hook output priority -100; policy accept;
    # Enforcer carve-out FIRST: the shim's own SOCKS5 connect to the enforcer
    # ClusterIP must pass through un-redirected (anti-loop). Stable VIP -- see header.
    ip daddr $ENFORCER_IP tcp dport $ENFORCER_PORT counter return
    oif "lo" return
    udp dport 53 return
    meta l4proto tcp redirect to :$PORT
  }
}
# FILTER table = the egress FLOOR, a DEFAULT-DROP ALLOWLIST. It runs at priority
# mangle (-150), BEFORE the nat divert (-100), so every packet here still carries
# its ORIGINAL destination and ALL TCP is *destined* to be REDIRECT'd downstream --
# therefore the floor ACCEPTs all TCP (enforcement happens at the enforcer, not
# here) and must NOT try to drop it; that accept also covers the shim's own
# outbound TCP to the enforcer ClusterIP. The floor's job is to close the
# non-TCP leaks a policy-accept floor would permit:
#   - udp/53 to ANY ip  -> a DNS-tunnel/exfil channel (now: allow ONLY the resolver);
#   - ICMP              -> direct egress via unprivileged ping sockets (now: dropped);
#   - SCTP/DCCP/other   -> direct egress on a non-tcp/udp L4 (now: dropped).
# Allowlist = lo + all TCP + udp/53-to-resolver + the mosh REPLY leg (below). IPv6
# has no legitimate egress, so reject it explicitly (faster app feedback than a
# silent policy drop). Everything else (other UDP, ICMP, SCTP, udp/53 to a
# non-resolver) falls to policy drop. ALL forwarded traffic is dropped too
# (belt-and-suspenders -- the agent holds no NET_ADMIN to make a tap, but keep the
# FORWARD drop regardless).
table inet cogbox_floor {
  # mosh seed-marking, PREROUTING. The reply-leg accept below fires ONLY for a
  # flow whose seeding datagram we saw ARRIVE on a real interface (iif != lo) at
  # udp/60000-60031. That is the whole basis of the reply rule's soundness: it
  # must NOT depend on the pod being unable to forge such a seed itself. Without
  # this mark, a pod that ever held CAP_NET_RAW could open IP_HDRINCL, send one
  # spoofed datagram src A:P -> podIP:60005 which routes via lo (accepted by
  # `oif "lo"`), seed a conntrack entry, and then egress freely from sport 60005
  # to A:P as `ct direction reply` -- the exact sport-keyed hole the reply rule
  # is meant not to be. A lo-injected seed traverses prerouting with iif="lo"
  # and so never gets the mark, so its "reply" leg fails the `ct mark` test
  # below and falls to policy drop. Range mirrors mosh-udp-range.nix. (ct state
  # is settled by the conntrack hook at priority -200, before this -150 mangle
  # hook, so `ct state new` is available here.)
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iif != "lo" udp dport 60000-60031 ct state new ct mark set 0x6d
  }
  chain output {
    type filter hook output priority mangle; policy drop;
    meta nfproto ipv6 reject
    oif "lo" accept
    meta l4proto tcp accept$DNS_ALLOW
    # mosh reply leg ONLY. mosh-server binds udp 60000-60031 in the pod (range
    # mirrors mosh-udp-range.nix; the cogworx gateway injects it into the exec)
    # and answers the client datagrams the gateway relays in. The pod never
    # ORIGINATES these flows: a datagram is admitted only when it belongs to a
    # conntrack entry (a) in the reply direction AND (b) that was seeded from a
    # real interface (ct mark 0x6d, set by the prerouting chain above). Both
    # halves matter: (a) keeps a pod-originated sport-60000-60031 datagram (ct
    # direction original) on the drop path, and (b) makes the rule hold even if
    # the pod could spoof a lo-injected seed with a raw socket (it never gets
    # the mark). Who may LEGITIMATELY seed one is bounded outside the pod by the
    # per-instance NetworkPolicy (the cogworxd gateway pod). This is not a UDP
    # egress hole keyed on a source port.
    udp sport 60000-60031 ct state established ct direction reply ct mark 0x6d counter accept
  }
  chain forward { type filter hook forward priority filter; policy drop; }
}
EOF
echo "cogbox-nft-divert: default-drop floor + REDIRECT(:$PORT) loaded; enforcer carve-out $ENFORCER_IP:$ENFORCER_PORT; resolver DNS rules=$NS_OK" >&2

# nft rules persist in the shared pod netns for the pod's lifetime; this sidecar
# just needs to stay up (k8s native sidecar = a never-exiting initContainer).
exec sleep infinity
