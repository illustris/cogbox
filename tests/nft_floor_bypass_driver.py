# NixOS test driver script for the container-mode nft egress-floor bypass suite
# (TODO). `machine`, `start_all`, etc. are injected by the test driver.
#
# The probe destinations live OFF-box in a SEPARATE peer netns reached over a veth
# pair, and are routed via the veth next-hop. That is the whole point: a locally
# assigned dst routes via `lo`, and BOTH the nat divert (`oif "lo" return`) and the
# filter floor (`oif "lo" accept`) special-case lo, so on-box dsts would bypass the
# very redirect/policy-drop rules under test. With the dsts off-box every probe packet
# leaves the main netns with oif=veth0, so the divert's REDIRECT and the floor's
# default-drop actually fire. The peer netns runs a listener server (the probe script's
# `--serve` mode) that records each off-box delivery as a marker file in a shared dir.
start_all()
machine.wait_for_unit("multi-user.target")

PEER = "cbxpeer"
PEER_NS = f"/run/netns/{PEER}"
HITDIR = "/run/cbxprobe"

# Off-box destinations assigned in the peer netns (so an unfloored packet WOULD land,
# making each drop probe's "not delivered" a real signal, and the allowed/carve-out
# probes observably reachable). Documentation/test ranges only -- no internal IDs.
PEER_V4 = [
    "10.96.0.10", "10.96.12.34", "192.0.2.10", "192.0.2.20", "192.0.2.30",
    "198.51.100.10", "198.51.100.20", "198.51.100.30", "198.51.100.40",
    "198.51.100.50",
]
PEER_V6 = ["fd00:dead:beef::10"]
# Routes that send each probe dst off-box (oif=veth0) via the peer next-hop.
ROUTES_V4 = ["192.0.2.0/24", "198.51.100.0/24", "10.96.0.0/16"]
ROUTES_V6 = ["fd00:dead:beef::/64"]

# 1. Build the topology: a veth pair main<->peer, addresses + off-box routes, rp_filter
#    relaxed (single symmetric path, but the dsts sit on the peer's lo). Assign BEFORE
#    loading the floor so this setup egress is unhindered.
machine.succeed(f"ip netns add {PEER}")
machine.succeed("ip link add veth0 type veth peer name veth1")
machine.succeed(f"ip link set veth1 netns {PEER}")
machine.succeed("ip addr add 10.0.0.1/24 dev veth0")
machine.succeed("ip -6 addr add fd00:c0::1/64 dev veth0 nodad")
machine.succeed("ip link set veth0 up")
machine.succeed("sysctl -wq net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.veth0.rp_filter=0")
for net in ROUTES_V4:
    machine.succeed(f"ip route add {net} via 10.0.0.2")
for net in ROUTES_V6:
    machine.succeed(f"ip -6 route add {net} via fd00:c0::2")

machine.succeed(f"ip -n {PEER} link set lo up")
machine.succeed(f"ip -n {PEER} addr add 10.0.0.2/24 dev veth1")
machine.succeed(f"ip -n {PEER} -6 addr add fd00:c0::2/64 dev veth1 nodad")
machine.succeed(f"ip -n {PEER} link set veth1 up")
machine.succeed(f"ip netns exec {PEER} sysctl -wq net.ipv4.conf.all.rp_filter=0")
for ip in PEER_V4:
    machine.succeed(f"ip -n {PEER} addr add {ip}/32 dev lo")
for ip in PEER_V6:
    machine.succeed(f"ip -n {PEER} -6 addr add {ip}/128 dev lo nodad")

# 2. Point the script's resolver discovery (it parses the MAIN netns /etc/resolv.conf)
#    at our stub kube-dns ClusterIP, which lives off-box in the peer netns.
machine.succeed("rm -f /etc/resolv.conf; printf 'nameserver 10.96.0.10\\n' > /etc/resolv.conf")

# 3. Start the peer-netns listener server. Use `nsenter --net=` (NET ns only, NO mount
#    ns) so the server's sockets land in the peer netns while the marker dir stays
#    shared with the main-netns client.
machine.succeed(f"mkdir -p {HITDIR}")
machine.succeed(
    f"COGBOX_PROBE_HITDIR={HITDIR} setsid nsenter --net={PEER_NS} "
    "python3 /etc/nft_bypass_probe.py --serve >/tmp/serve.log 2>&1 </dev/null & "
    "sleep 0.2; true"
)

# 4. Load the REAL divert+floor ruleset in the MAIN netns. The script execs
#    `sleep infinity` after an atomic nft load, so background it, then confirm both
#    tables are present.
machine.succeed(
    "COGBOX_ENFORCER_IP=10.96.12.34 COGBOX_ENFORCER_PORT=18443 "
    "setsid sh /etc/cogbox-nft-divert.sh >/tmp/divert.log 2>&1 </dev/null & "
    "sleep 1; "
    "nft list table inet cogbox_floor >/dev/null && "
    "nft list table inet cogbox_divert >/dev/null"
)

# 4a. The floor must be a DEFAULT-DROP allowlist whose ONLY udp/53 accept is pinned
#     to the discovered resolver (no allow-all DNS reopening the exfil channel).
machine.succeed("nft list chain inet cogbox_floor output | grep -F 'policy drop'")
machine.succeed(
    "nft list chain inet cogbox_floor output "
    "| grep -F 'ip daddr 10.96.0.10 udp dport 53 accept'"
)
# An unqualified `udp dport 53 accept` (allow-all) must NOT exist in the floor.
machine.fail(
    "nft list chain inet cogbox_floor output "
    "| grep -E '^[[:space:]]*udp dport 53 accept$'"
)
# 4b. The mosh REPLY-leg exception is present and is exactly the reply-only,
#     seed-marked shape: established + ct direction reply + ct mark 0x6d, so only a
#     flow whose seed we saw arrive on a real interface (marked by the prerouting
#     chain, NOT a lo-injected raw-socket spoof) gets its answers out. The
#     60000-60031 literal is pinned to mosh-udp-range.nix (port + count - 1); a
#     drift in either breaks every mosh session, so keep the spellings in step.
machine.succeed(
    "nft list chain inet cogbox_floor output "
    "| grep -F 'udp sport 60000-60031 ct state established ct direction reply ct mark 0x0000006d counter'"
)
# 4c. ...and its seed-marking half exists in prerouting and is iif-guarded: a seed
#     that arrives on lo (the raw-socket spoof path) must NOT be marked, so the
#     rule's soundness does not silently depend on the pod lacking CAP_NET_RAW.
machine.succeed(
    "nft list chain inet cogbox_floor prerouting "
    "| grep -F 'iif != \"lo\" udp dport 60000-60031 ct state new ct mark set 0x0000006d'"
)

# 5. Run the in-guest probe harness: it asserts every egress path against the off-box
#    dsts and exits non-zero (with a PASS/FAIL report) on any leak.
print(machine.succeed(f"COGBOX_PROBE_HITDIR={HITDIR} python3 /etc/nft_bypass_probe.py"))

# 6. FAIL-CLOSED: unset enforcer coords -> deny-all floor + exit 64, and the nat
#    divert table is NOT (re)loaded, so TCP egress is dropped.
rc, _ = machine.execute(
    "COGBOX_ENFORCER_IP= COGBOX_ENFORCER_PORT= "
    "sh /etc/cogbox-nft-divert.sh >/tmp/failclosed.log 2>&1"
)
assert rc == 64, f"fail-closed must exit 64, got {rc}"
machine.fail("nft list table inet cogbox_divert")
# The deny-all floor still default-drops TCP egress (no redirect, no tcp accept). The
# dst is off-box (oif=veth0), so this exercises the policy drop, not the lo bypass.
machine.fail(
    "timeout 5 python3 -c "
    "'import socket; socket.create_connection((\"192.0.2.10\", 443), timeout=2)'"
)
# ...but it KEEPS the resolver-only DNS allow (leaks stay closed on this path too).
machine.succeed(
    "nft list chain inet cogbox_floor output "
    "| grep -F 'ip daddr 10.96.0.10 udp dport 53 accept'"
)
# ...and carries NO mosh exception, on EITHER half: the fallback floor is
# deny-all-but-DNS, so a misconfigured nft-init must not leave the mosh reply leg
# open nor even the seed-marking prerouting chain that arms it.
machine.fail("nft list chain inet cogbox_floor output | grep -F 'udp sport 60000-60031'")
machine.fail("nft list chain inet cogbox_floor prerouting")
