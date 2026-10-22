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

Rule 4 (output):
    meta skuid <passt> ip daddr @cp udp sport <mosh range> accept
    ip daddr <allow> <proto> dport <port> accept          (one per infraAllow)
    meta skuid { <passt>, <proxy> } ct direction original ip daddr @infra4 drop
    meta skgid <build group>       ct direction original ip daddr @infra4 drop
  Guest traffic (passt), the L7 proxy's upstream sockets and the nix build
  users (the daemon's builders, group <build group>) may not OPEN a flow to
  the site's internal ranges. Root is outside the rule by design: the trusted
  half, nix-daemon substitution from the site cache and root-run plugin
  evaluation all run as root (README.md states the residual). `ct direction
  original` for the reason gce/floor.nix gives for its rules 2 and 3: a REPLY
  on a flow the control plane opened (SSH and HTTP forwards, which passt
  answers from its own sockets) is in the reply direction and passes, and the
  scoping is a per-packet property that a floor reload cannot turn into a
  standing exemption. So rule 4 is a no-new-flows rule keyed on conntrack
  direction, not a peer filter: ANY address that sends to the VM first can be
  answered from the port it sent to, by passt (which keeps the guest's UDP
  source port) or by a build user. The guest cannot open such a flow alone,
  but an internal host or L2 neighbour that sends on its behalf can (README.md
  states the residual).
  Two accepts come first, because their targets can sit inside @infra4. The
  exact infraAllow sockets. And passt's mosh reply sockets: passt answers a
  datagram that arrived on its `-u` forward from a per-flow socket bound to
  the forward's own port and connected to the sender (the cogworxd relay, in
  @cp), and once conntrack has forgotten the inbound flow such a reply is an
  ORIGINAL-direction flow to @cp. The accept names exactly that: the passt
  uid, UDP, a source port in the mosh range, a @cp destination. Nothing else
  that rule 4 names reaches @cp in the original direction, so a @cp inside
  @infra4 is otherwise covered by the drops like any internal address.
  Residual: the floor cannot tell a reply socket from a guest-originated
  datagram whose source port passt preserved inside the mosh range; in
  `rules` mode the L4 shim's reply-socket exemption never covers the latter
  (it requires a specific bound address), so it falls to the instance's L4
  rule walk: denied by the seeded private-range rules unless an owner/admin
  allow covers that @cp address. The PVE boot config has no `full` mode (the
  emulator rejects a blob that asks for it).

No ingress filter (decision 2026-10-21):
  The internal network is trusted, so input is filtered only by rule 4a's
  link-local drop: sshd, the guest SSH and HTTP forwards and the mosh range
  are reachable from every host that can route to the VM, and rely on their
  own authentication. Replies on flows the cogworxd relay opened pass rule 4
  by direction, whatever the relay's address; so do replies on flows any
  other peer opened, which with no ingress filter now includes every forward
  and the mosh range (rule 4's direction residual above).

Validation (every refusal names the field and the value):
  - every CIDR or address is IPv4, in canonical form (no host bits), at most
    /8 wide, and overlaps none of 127.0.0.0/8, 169.254.0.0/16, 0.0.0.0/8;
  - infraAllow entries are {address, protocol in tcp|udp, port 1-65535}, and
    the address is ONE host (bare or /32): an exception is an exact socket,
    never a range;
  - port ranges (moshUDP) are [lo, hi] with 1 <= lo <= hi <= 65535;
  - user/group names and the interface name are plain identifiers, because
    they are rendered into the ruleset.
Emptiness is NOT refused here: on a CA-baked image the publish gate in
pve-host.nix requires infraDenyCIDRs, and a dev image is allowed to render a
rule 4 with nothing to drop. An empty controlPlaneCIDRs only leaves the mosh
accept without a target: passt's mosh replies then pass on conntrack's reply
direction alone. An empty moshUDP renders no mosh accept (no `-u` forward, no
reply sockets).
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
    "version", "iface", "controlPlaneCIDRs", "infraDenyCIDRs", "infraAllow",
    "passtUser", "proxyUser", "buildGroup", "moshUDP",
})


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

    return {
        "iface": parse_name(spec["iface"], "iface", _IFACE),
        "cp": cidrs("controlPlaneCIDRs"),
        "infra": cidrs("infraDenyCIDRs"),
        "allow": allow,
        "passt": parse_name(spec["passtUser"], "passtUser"),
        "proxy": parse_name(spec["proxyUser"], "proxyUser"),
        "build": parse_name(spec["buildGroup"], "buildGroup"),
        "mosh": parse_ranges(spec["moshUDP"], "moshUDP"),
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
    out += _set("cp", v["cp"])
    out += _set("infra4", v["infra"])
    out += [
        "\tchain output {",
        "\t\ttype filter hook output priority 0; policy accept;",
        "\t\tmeta skuid != 0 ct direction original ip daddr 169.254.0.0/16 counter drop %s" % c("rule4a-linklocal"),
        '\t\toifname "%s" ip saddr 169.254.0.0/16 counter drop %s' % (v["iface"], c("rule4a-egress")),
    ]
    # Rule 4's @cp accept is passt's mosh reply sockets ONLY (see the
    # docstring): every other uid rule 4 names is dropped towards a @cp that
    # sits inside @infra4, and every uid it does not name is never dropped.
    if v["mosh"]:
        out.append('\t\tmeta skuid "%s" ip daddr @cp udp sport %s counter accept %s' % (v["passt"], _ports(v["mosh"]), c("rule4-cp-mosh")))
    for net, proto, port in v["allow"]:
        out.append("\t\tip daddr %s %s dport %d counter accept %s" % (_addr(net), proto, port, c("rule4-infra-allow")))
    uids = ", ".join('"%s"' % u for u in sorted({v["passt"], v["proxy"]}))
    out += [
        "\t\tmeta skuid { %s } ct direction original ip daddr @infra4 counter drop %s" % (uids, c("rule4-uid")),
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
