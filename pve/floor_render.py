#!/usr/bin/env python3
"""Validate a cogworx PVE site-floor spec and render it as an nft ruleset.

    floor_render.py SPEC.json      -> the ruleset on stdout, exit 0
                                   -> "cogworx-pve-floor: REFUSED: ..." on
                                      stderr, exit 2, nothing on stdout

floor-site.nix runs this at image BUILD time, so a spec it refuses fails the
build; tests/test_floor_site.sh runs it directly. Stdlib only.

The ruleset is table `inet cogworx_pve_floor`, a SECOND table beside
gce/floor.nix's `cogworx_floor`. A drop in either table is final, so this
table can only ever narrow what the gce floor admits; its accepts end
evaluation of ITS chain only.

Rule 4a (always on):
    output: meta skuid != 0 ct direction original ip daddr 169.254.0.0/16 drop
    output: oifname <iface> ip saddr 169.254.0.0/16 drop
    input:  iifname != "lo" ip daddr 169.254.0.0/16 drop
  Only root may open a flow to link-local. The metadata emulator lives there
  (and answers only peer uid 0); this is the packet-level half of the same
  rule, for every non-root uid on the VM rather than only the passt uid
  gce/floor.nix rule 1 names. The second line keeps a 169.254/16 source from
  ever leaving the NIC onto the shared segment. The third is defence in depth
  for the other direction: the emulator's address is scope host on lo, but
  Linux's weak host model still delivers a frame for it that arrives on the
  NIC, so anything for link-local that did not come in on lo is dropped
  before the emulator sees it, whatever its source. It is the input chain's
  only rule (see "No ingress filter" below).

Rule 4 (output), the nix build users only:
    meta skgid <build group> ct direction original ip daddr 127.0.0.0/8 tcp dport { <hops> } drop
    meta skgid <build group> ct direction original ip6 daddr ::1 tcp dport { <hops> } drop
    meta skgid <build group> ip saddr 127.0.0.0/8 tcp sport { <hops> } drop
    meta skgid <build group> ip6 saddr ::1 tcp sport { <hops> } drop
    meta skgid <build group> ct direction original ip daddr 127.0.0.0/8 udp dport { <udp hops> } drop
    meta skgid <build group> ct direction original ip6 daddr ::1 udp dport { <udp hops> } drop
    meta skgid <build group> ct direction original meta nfproto ipv4 fib daddr type { broadcast, multicast } drop
    ip daddr <allow> <proto> dport <port> accept          (one per infraAllow)
    meta skgid <build group> ct direction original ip daddr @infra4 drop
  The nix build users (the daemon's builders, group <build group>) may not
  OPEN a flow to the site's internal ranges, except the exact infraAllow
  sockets (decision 2026-10-22: GCE leaves them unrestricted; this site keeps
  them blocked). Only fixed-output builds share the VM's network namespace,
  so in practice this is their fetches. Root is outside the rule by design:
  the trusted half, nix-daemon substitution from the site cache and root-run
  plugin evaluation all run as root (README.md states the residual). `ct
  direction original` for the reason gce/floor.nix gives for its rules 2 and
  3: a REPLY on a flow a peer opened is in the reply direction and passes,
  and the scoping is a per-packet property that a floor reload cannot turn
  into a standing exemption. So the drop is a no-new-flows rule, not a peer
  filter: an address that sends to the VM first can be answered from the
  port it sent to (README.md states the residual).
  The infraAllow accepts name no uid. The only drops after them are the
  build users', so for any other uid they change nothing in this table.

  The local hops, first. Every other uid may reach internal addresses (see
  "No internal-range egress filter" below), and the L7 proxy uid in
  particular dials them for its clients, so a loopback listener that dials
  upstream on behalf of a client it does not authenticate would carry a
  build user around the @infra4 drop. Of cogbox's own, those are the
  trusted half's L7 relays, all on 127.0.0.1 and all under the proxy uid:
    - l7proxy's two front doors, <base> and <base+1> (the guest's 443 and 80
      funnel targets): SOCKS5 carrying the original address and port, then
      the L7 policy's upstream;
    - mitmproxy's SOCKS5 terminate hop, <base+2>: any upstream, with the
      owner's credentials injected host-side;
    - the auth proxy, <base-400>: stamps the owner's git credential itself.
  The launcher seeds the base at its built-in 18443 and slides it upward by
  3 when a triple is taken, so these bands are the window gce/floor.nix
  rule 3 admits the funnel over: the l7PortTriples triples from that base,
  plus the auth band 400 below them. floor-site.nix adds the bake's own
  loopback agents of the same kind (cogworx.pve.floor.buildDenyLoopbackTCP,
  a service-discovery agent's local HTTP API for example: it sends requests
  to any address it is told to) and hands over the union, sorted and merged,
  as <hops>. The host DNS forwarder is not a hop and stays reachable
  (fixed-output fetches resolve through it); passt's guest forwards are
  bound at the VM's own address, which gce/floor.nix rule 2 closes to every
  uid. The ::1 mirror is free today (every hop binds 127.0.0.1) and closes
  the v6 half should a hop ever bind both families. Loopback as a whole is
  NOT closed to the build users: a fixed-output build may talk to itself
  over loopback (a build tool's own client and server), and those ports are
  ephemeral.

  The source-port drops keep a build user from steering the base. The
  launcher probes base, +1, +2 and base-400 with a loopback connect as root
  before it starts the relays, slides past a triple where any of them
  answers, whoever listens there, and persists the new base in the
  instance's config.json, so a slide outlasts the launch that made it. A
  build user's listener inside <hops> would answer that probe and push the
  relays to a base outside the window, and so outside the drops above. With
  these drops its SYN-ACK never leaves: the probe times out, which the
  launcher reads as free, and the relay's own bind then fails, closed. They
  carry no `ct direction`, because the SYN-ACK of a flow root opened is in
  the reply direction; a build user has no other reason to send from a hop
  port. A listener of any other uid in the window still moves the base
  (README.md states the residual). The pair is load-bearing a second way:
  only l7proxy's bind failure aborts the start. When mitmproxy (+2) or the
  auth proxy (base-400) cannot bind, the launcher only warns and the
  sandbox runs, while l7proxy still hands terminate hosts to 127.0.0.1:<+2>
  and mitmproxy still sends its git retarget to 127.0.0.1:<base-400>. A
  build user's listener holding either port would then answer the relays'
  own connections; the pair drops its SYN-ACK to them as it does to the
  probe's. So the pair may be neither direction-scoped nor dropped.

  The bake's UDP agents of the same kind (buildDenyLoopbackUDP: a gossip
  agent that takes unauthenticated datagrams on loopback and probes or
  sends to whatever addresses they name, for example) are <udp hops>: the
  same destination drops on 127.0.0.0/8 and ::1, rendered only when the
  bake lists any (nft refuses an empty set). They have no source-port
  pair: nothing probes a UDP port to place a relay. The L7 relays are TCP
  only, so the list has no derived part.

  Nor may a build user send to a broadcast or multicast address. Such a
  datagram reaches every neighbour on the segment, and an answer is a flow
  the NEIGHBOUR opens: a neighbour inside the internal ranges that answers
  a broadcast or a multicast query (a discovery protocol, a gossip agent)
  opens a flow to the build user's port, and the build user's next
  datagram to it is that flow's reply, which `ct direction original` lets
  past the @infra4 drop. A broadcast also loops back to every local
  wildcard listener without using 127/8, so the UDP hop drops alone would
  not hold either. The drop keys on the type the routing table gives the
  destination, not on a fixed set: besides the limited broadcast and every
  multicast group (both decided by the address alone), that is each local
  segment's directed broadcast, the eth0 one DHCP hands out included, which
  the floor could not name at build time and which @infra4 covers only when
  the segment is listed there. IPv4 only: eth0 carries no IPv6 (README.md).

No internal-range egress filter for the guest and the L7 proxy (decision
2026-10-22, GCE parity):
  This table drops nothing towards internal ranges for passt or the L7
  proxy. Guest (passt) and L7-proxy egress is decided by the sandbox's own
  network rules, as on GCE: the seeded RFC1918/CGNAT/link-local/bogon
  denies, enforced by the passt shim (the L4 LD_PRELOAD filter) and by
  l7proxy. An approved L4 allow, or an L7 name allow, opens a destination;
  an L7 allow supersedes the L4 denies, and l7proxy's hard floor (loopback,
  0/8, link-local, the VM's own addresses) stays. What still keeps the guest
  off link-local, the VM's own addresses and loopback is gce/floor.nix's
  rules 1-3, plus rule 4a above for every non-root uid.

No ingress filter (decision 2026-10-21):
  The internal network is trusted, so input is filtered only by rule 4a's
  link-local drop: sshd, the guest SSH and HTTP forwards and the mosh range
  are reachable from every host that can route to the VM, and rely on their
  own authentication.

Validation (every refusal names the field and the value):
  - every CIDR or address is IPv4, in canonical form (no host bits), at most
    /8 wide, and overlaps none of 127.0.0.0/8, 169.254.0.0/16, 0.0.0.0/8;
  - infraAllow entries are {address, protocol in tcp|udp, port 1-65535}, and
    the address is ONE host (bare or /32): an exception is an exact socket,
    never a range;
  - hopTCP is a non-empty list of [lo, hi] port ranges with
    1 <= lo <= hi <= 65535, ascending and disjoint (an nft interval set
    refuses overlapping elements; floor-site.nix merges before it hands
    them over, so a refusal here is a composer bug, not an operator's);
    hopUDP is the same, except that it may be empty;
  - the group name and the interface name are plain identifiers, because
    they are rendered into the ruleset;
  - every other key is refused as unknown, the removed inputs of rule 4's
    passt and proxy legs and of rule 5 included (controlPlaneCIDRs,
    passtUser, proxyUser, moshUDP, ingressTCP, ingressUDP), so a stale
    composer fails the build instead of rendering a floor it no longer
    describes.
Emptiness of the CIDR lists is NOT refused here: on a CA-baked image the
publish gate in pve-host.nix requires infraDenyCIDRs, and a dev image is
allowed to render a rule 4 with nothing to drop.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys

TABLE = "cogworx_pve_floor"
SPEC_VERSION = 1
MIN_PREFIX = 8
# Ranges no floor CIDR may touch: loopback (rule 3 and the trusted half's own
# traffic), link-local (rule 4a and the metadata emulator), and "this network".
FORBIDDEN = tuple(
    ipaddress.IPv4Network(n) for n in ("127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8")
)
_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_IFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}")
_CIDR_SHAPE = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2})?")
SPEC_KEYS = frozenset({
    "version", "iface", "infraDenyCIDRs", "infraAllow", "buildGroup", "hopTCP",
    "hopUDP",
})
# Rule 4's broadcast and multicast drop, by address type: the kernel's
# answer for 255.255.255.255 and 224.0.0.0/4 needs no lookup, and a local
# segment's directed broadcast is a `broadcast` route in its local table.
BCAST = "meta nfproto ipv4 fib daddr type { broadcast, multicast }"


class FloorError(ValueError):
    pass


def parse_cidr(value, what):
    """An IPv4Network for an address or CIDR, or FloorError naming `what`."""
    if not isinstance(value, str) or not _CIDR_SHAPE.fullmatch(value):
        raise FloorError("%s: %r is not an IPv4 address or CIDR" % (what, value))
    try:
        net = ipaddress.IPv4Network(value, strict=True)
    except ValueError as e:
        raise FloorError("%s: %r is not a canonical IPv4 address or CIDR (%s)" % (what, value, e)) from None
    if net.prefixlen < MIN_PREFIX:
        raise FloorError("%s: %r is wider than /%d" % (what, value, MIN_PREFIX))
    for bad in FORBIDDEN:
        if net.overlaps(bad):
            raise FloorError("%s: %r overlaps %s, which no floor CIDR may touch" % (what, value, bad))
    return net


def parse_port(value, what):
    if type(value) is not int or not 1 <= value <= 65535:
        raise FloorError("%s: %r is not a port (1-65535)" % (what, value))
    return value


def parse_ranges(value, what):
    if not isinstance(value, list):
        raise FloorError("%s: expected a list of [lo, hi] port ranges" % what)
    out = []
    for i, r in enumerate(value):
        if not (isinstance(r, list) and len(r) == 2):
            raise FloorError("%s[%d]: %r is not a [lo, hi] port range" % (what, i, r))
        lo = parse_port(r[0], "%s[%d]" % (what, i))
        hi = parse_port(r[1], "%s[%d]" % (what, i))
        if lo > hi:
            raise FloorError("%s[%d]: %r has lo > hi" % (what, i, r))
        out.append((lo, hi))
    return out


def parse_name(value, what, pattern=_NAME):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise FloorError("%s: %r is not a plain name" % (what, value))
    return value


def validate(spec):
    """The normalized spec, or FloorError."""
    if not isinstance(spec, dict):
        raise FloorError("spec: expected a JSON object")
    unknown = sorted(set(spec) - SPEC_KEYS)
    if unknown:
        raise FloorError("spec: unknown key(s) %s" % ", ".join(unknown))
    missing = sorted(SPEC_KEYS - set(spec))
    if missing:
        raise FloorError("spec: missing key(s) %s" % ", ".join(missing))
    if spec["version"] != SPEC_VERSION:
        raise FloorError("spec: version %r is not %d" % (spec["version"], SPEC_VERSION))

    def cidrs(key):
        if not isinstance(spec[key], list):
            raise FloorError("%s: expected a list" % key)
        return [parse_cidr(v, "%s[%d]" % (key, i)) for i, v in enumerate(spec[key])]

    allow = []
    if not isinstance(spec["infraAllow"], list):
        raise FloorError("infraAllow: expected a list")
    for i, a in enumerate(spec["infraAllow"]):
        what = "infraAllow[%d]" % i
        if not isinstance(a, dict) or set(a) != {"address", "protocol", "port"}:
            raise FloorError("%s: expected exactly {address, protocol, port}, got %r" % (what, a))
        if a["protocol"] not in ("tcp", "udp"):
            raise FloorError("%s.protocol: %r is not tcp or udp" % (what, a["protocol"]))
        net = parse_cidr(a["address"], what + ".address")
        if net.prefixlen != 32:
            raise FloorError("%s.address: %r is not a single address; an infraAllow entry is one exact socket, so list each host separately" % (what, a["address"]))
        allow.append((net, a["protocol"], parse_port(a["port"], what + ".port")))

    def disjoint(key):
        ranges = parse_ranges(spec[key], key)
        for i in range(1, len(ranges)):
            if ranges[i][0] <= ranges[i - 1][1]:
                raise FloorError("%s[%d]: %r does not start above %s[%d]'s end; the ranges must be ascending and disjoint" % (key, i, list(ranges[i]), key, i - 1))
        return ranges

    hops = disjoint("hopTCP")
    if not hops:
        raise FloorError("hopTCP: expected at least one [lo, hi] port range; without one rule 4 would leave the local hops open to the build users")
    # Empty is a bake without a UDP agent of that kind.
    udp_hops = disjoint("hopUDP")

    return {
        "iface": parse_name(spec["iface"], "iface", _IFACE),
        "infra": cidrs("infraDenyCIDRs"),
        "allow": allow,
        "build": parse_name(spec["buildGroup"], "buildGroup"),
        "hops": hops,
        "udp_hops": udp_hops,
    }


def _addr(net):
    return str(net.network_address) if net.prefixlen == 32 else str(net)


def _ports(ranges):
    items = ["%d" % lo if lo == hi else "%d-%d" % (lo, hi) for lo, hi in ranges]
    return items[0] if len(items) == 1 else "{ " + ", ".join(items) + " }"


def _set(name, nets):
    lines = [
        "\tset %s {" % name,
        "\t\ttype ipv4_addr",
        "\t\tflags interval",
        # Overlapping entries (a /16 inside a listed /8) are an operator
        # convenience, not an error; without auto-merge nft refuses them.
        "\t\tauto-merge",
    ]
    if nets:
        lines.append("\t\telements = { %s }" % ", ".join(_addr(n) for n in nets))
    lines.append("\t}")
    return lines


def render(spec):
    v = validate(spec)
    c = lambda name: 'comment "cogworx-pve-floor-%s"' % name  # noqa: E731
    out = [
        # create/delete/create: idempotent reload without a conditional, the
        # same prelude gce/floor.nix renders.
        "table inet %s" % TABLE,
        "delete table inet %s" % TABLE,
        "table inet %s {" % TABLE,
    ]
    out += _set("infra4", v["infra"])
    hops = _ports(v["hops"])
    out += [
        "\tchain output {",
        "\t\ttype filter hook output priority 0; policy accept;",
        "\t\tmeta skuid != 0 ct direction original ip daddr 169.254.0.0/16 counter drop %s" % c("rule4a-linklocal"),
        '\t\toifname "%s" ip saddr 169.254.0.0/16 counter drop %s' % (v["iface"], c("rule4a-egress")),
        # Rule 4 names the build users and nobody else (see the docstring).
        # The local hops come first, so no accept below can ever precede
        # them.
        '\t\tmeta skgid "%s" ct direction original ip daddr 127.0.0.0/8 tcp dport %s counter drop %s' % (v["build"], hops, c("rule4-build-hop")),
        '\t\tmeta skgid "%s" ct direction original ip6 daddr ::1 tcp dport %s counter drop %s' % (v["build"], hops, c("rule4-build-hop6")),
        # Nor answer from a hop port: no direction scoping, because the
        # SYN-ACK to the launcher's port probe is a reply.
        '\t\tmeta skgid "%s" ip saddr 127.0.0.0/8 tcp sport %s counter drop %s' % (v["build"], hops, c("rule4-build-hop-src")),
        '\t\tmeta skgid "%s" ip6 saddr ::1 tcp sport %s counter drop %s' % (v["build"], hops, c("rule4-build-hop-src6")),
    ]
    if v["udp_hops"]:
        udp_hops = _ports(v["udp_hops"])
        out += [
            '\t\tmeta skgid "%s" ct direction original ip daddr 127.0.0.0/8 udp dport %s counter drop %s' % (v["build"], udp_hops, c("rule4-build-hop-udp")),
            '\t\tmeta skgid "%s" ct direction original ip6 daddr ::1 udp dport %s counter drop %s' % (v["build"], udp_hops, c("rule4-build-hop-udp6")),
        ]
    # No soliciting an answer from the segment (see the docstring).
    out.append('\t\tmeta skgid "%s" ct direction original %s counter drop %s' % (v["build"], BCAST, c("rule4-build-bcast")))
    for net, proto, port in v["allow"]:
        out.append("\t\tip daddr %s %s dport %d counter accept %s" % (_addr(net), proto, port, c("rule4-infra-allow")))
    out += [
        '\t\tmeta skgid "%s" ct direction original ip daddr @infra4 counter drop %s' % (v["build"], c("rule4-build")),
        "\t}",
        "\tchain input {",
        "\t\ttype filter hook input priority 0; policy accept;",
        # Rule 4a's input leg, and the input chain's only rule: the floor
        # filters no ingress (the docstring's "No ingress filter").
        '\t\tiifname != "lo" ip daddr 169.254.0.0/16 counter drop %s' % c("rule4a-input"),
        "\t}",
        "}",
    ]
    return "\n".join(out) + "\n"


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: floor_render.py SPEC.json\n")
        return 64
    try:
        with open(argv[1], "rb") as f:
            spec = json.loads(f.read())
    except (OSError, ValueError) as e:
        sys.stderr.write("cogworx-pve-floor: REFUSED: cannot read the spec: %s\n" % e)
        return 2
    try:
        text = render(spec)
    except FloorError as e:
        sys.stderr.write("cogworx-pve-floor: REFUSED: %s\n" % e)
        return 2
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
