#!/usr/bin/env python3
"""Check a guest's rendered Docker daemon.json for checks.guest-docker-pools.

usage: check_guest_docker_pools.py <daemon.json> <want JSON> <config name>

Fails unless default-address-pools is a non-empty list equal to <want> and no
pool base overlaps 10.0.0.0/8 or 172.16.0.0/12: Docker's stock pools sit in
172.17-172.31, ranges control planes and site networks commonly use, and a
bridge on a remote peer's range captures what the guest sends that peer.
"""
import ipaddress
import json
import sys

AVOID = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12")]

conf, want, name = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3]
fails = []
with open(conf) as f:
    pools = json.load(f).get("default-address-pools")
if not isinstance(pools, list) or not pools:
    fails.append(f"{conf} has no default-address-pools list (got {pools!r}); docker0 and new networks take Docker's stock 172.17-172.31 pools")
else:
    if pools != want:
        fails.append(f"{conf} default-address-pools is {json.dumps(pools)}, not {json.dumps(want)}")
    for p in pools:
        try:
            net = ipaddress.ip_network(p["base"], strict=False)
        except (KeyError, TypeError, ValueError) as e:
            fails.append(f"{conf} has an unparsable pool {p!r}: {e}")
            continue
        for avoid in AVOID:
            if net.version == avoid.version and net.overlaps(avoid):
                fails.append(f"pool {p['base']} overlaps {avoid}, a range control planes and site networks commonly use")
for msg in fails:
    print(f"FAIL: {name}: {msg}", file=sys.stderr)
sys.exit(1 if fails else 0)
