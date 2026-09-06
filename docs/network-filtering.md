# Network filtering

cogbox restricts what the sandboxed agent can reach on the network. Filtering is layered: a network *mode* selects the overall posture, L4 CIDR rules filter by destination IP, a remap table can redirect TCP flows into a proxy, and L7 rules filter individual virtual hosts behind shared IPs. This document covers all of it, including the threat model and the enforcement internals.

- [Network modes](#network-modes)
- [L4 CIDR rules](#l4-cidr-rules)
- [TCP destination remap](#tcp-destination-remap)
- [L7 host filtering](#l7-host-filtering)
- [Host-side credential injection](#host-side-credential-injection)

## Network modes

Three modes are available. `full` and `rules` use [passt](https://passt.top/) for networking, which supports all IP protocols including ICMP. `none` uses QEMU's built-in SLIRP with `restrict=on`. None of them need extra privileges.

| Mode | Posture |
|---|---|
| `full` | Unrestricted networking via passt. All IP protocols (TCP, UDP, ICMP, etc.) work. |
| `none` | SLIRP `restrict=on` blocks all outbound traffic. SSH and HTTP port forwards from the host still work. |
| `rules` (default) | Ordered CIDR allow/deny rules enforced via an LD_PRELOAD filter on passt. First match wins; default policy is deny. All IP protocols are subject to the rules, with exactly one host-provisioned exemption: passt's reply sockets for a UDP range the host forwards into the guest for mosh ([below](#the-mosh-reply-socket-exemption)). |

The mode is chosen at init (`--network MODE`) and stored in `config.json` as `.network`: the string `"full"` or `"none"`, or an object `{"rules": [...]}` for rules mode.

Note for `none` mode: every supported harness needs access to a model provider's API. In `none` mode they won't function unless API access is provided through another channel (e.g. SSH port forwarding).

## L4 CIDR rules

### The seeded ruleset

A new rules-mode instance is seeded with deny rules for private (RFC1918), link-local (including cloud metadata `169.254.169.254`), and bogon ranges, followed by `allow 0.0.0.0/0` for the public internet. Net effect: working internet out of the box, with LAN and metadata services blocked. Rule objects may optionally carry a `comment` field; it's preserved through edits and shown by `rules list` but ignored by the filter.

```json
{
    "network": {
        "rules": [
            {"deny":  "0.0.0.0/8",       "comment": "this network (RFC 1122)"},
            {"deny":  "10.0.0.0/8",      "comment": "RFC1918 private"},
            {"deny":  "100.64.0.0/10",   "comment": "carrier-grade NAT (RFC 6598)"},
            {"deny":  "169.254.0.0/16",  "comment": "link-local incl. cloud metadata 169.254.169.254"},
            {"deny":  "172.16.0.0/12",   "comment": "RFC1918 private"},
            {"deny":  "192.0.0.0/24",    "comment": "IETF protocol assignments (RFC 6890)"},
            {"deny":  "192.0.2.0/24",    "comment": "TEST-NET-1 documentation (RFC 5737)"},
            {"deny":  "192.168.0.0/16",  "comment": "RFC1918 private"},
            {"deny":  "198.18.0.0/15",   "comment": "benchmark testing (RFC 2544)"},
            {"deny":  "198.51.100.0/24", "comment": "TEST-NET-2 documentation (RFC 5737)"},
            {"deny":  "203.0.113.0/24",  "comment": "TEST-NET-3 documentation (RFC 5737)"},
            {"deny":  "224.0.0.0/4",     "comment": "multicast (RFC 5771)"},
            {"deny":  "240.0.0.0/4",     "comment": "reserved/broadcast incl. 255.255.255.255"},
            {"allow": "0.0.0.0/0",       "comment": "public internet"}
        ]
    }
}
```

### Host-topology keys (`implicitDns`, `selfAddrs`)

Two optional `.network` keys describe the machine cogbox itself runs on, rather than a user policy. Both are absent by default and are seeded at `cogbox init` time by whoever provisions the instance -- never by the `rules` verbs:

| Key | init flag | Effect |
|---|---|---|
| `"implicitDns": false` | `--no-implicit-dns` | Removes the implicit port-53 allow (see [Enforcement internals](#enforcement-internals)), so DNS walks the ordered rules like any other port. |
| `"selfAddrs": ["10.0.0.5/32"]` | `--self-addr` (repeatable) | Adds each address to the L7 proxy's [non-overridable hard floor](#how-l7-composes-with-l4). |
| `"dnsHost": "127.0.0.53"` | `--dns-host` | Re-admits **exactly one address on port 53** to the rule walk: the loopback DNS forwarder the enclosing host runs. One bare address -- a prefix, a port or a proto qualifier is refused, because any of them would turn a one-socket exception into a loopback carve-out. |

All three are rules-mode only: `full` and `none` store `.network` as a bare string, have no L4 filter to parameterize and no proxy to give a floor to, so `cogbox init` warns and ignores them there. They render into the runtime rules file as the directives `no-implicit-dns`, `hard-deny <cidr>` and `dns-host <addr>`, ahead of every rule, and hot-reload with everything else.

Set them where the host's own resolver or addresses are things the sandbox must not reach -- a cloud VM whose DHCP resolver is also its metadata server is the motivating case. `--no-implicit-dns` and `--dns-host` are two halves of one arrangement: the first puts loopback DNS back under the filter's loopback deny, and the second re-opens the single socket passt re-emits the guest's forwarded queries on (`COGBOX_GUEST_RESOLVER` + `COGBOX_HOST_RESOLVER`, see [Host-integration knobs](#host-integration-knobs)). Use `--no-implicit-dns` **without** either and the guest's DNS has to reach a resolver the rules allow on its own -- one inside a denied range leaves it with **silently** broken DNS, because its queries are dropped like any other denied packet.

### How rules are evaluated and edited

Rules are evaluated top-to-bottom on every outbound packet; the first matching rule wins, and a packet that matches no rule is denied. **Position matters**: a rule only fires if no earlier rule matches the same address first.

The `rules add` command **appends by default** -- the new rule lands at the bottom of the list, after the seeded `allow 0.0.0.0/0` catch-all. That position is almost always wrong: the catch-all matches everything public, so an appended `deny` or `allow` for a public address is unreachable. Pass `--at N` to insert at 1-based position `N`, shifting existing rules down. To see current positions, run `rules list`.

Two practical patterns:

**Allow a specific LAN host** -- insert the allow ahead of the matching deny. Use `rules list` to find the right index for the deny:

```sh
cogbox rules list
# ...
# 8: deny 192.168.0.0/16  # RFC1918 private
# ...
cogbox rules add allow 192.168.1.50/32 --at 8
```

**Block a specific public address** -- insert the deny ahead of the trailing `allow 0.0.0.0/0`. Easiest is `--at 1` so it runs before all existing rules:

```sh
cogbox rules add deny 8.8.8.8/32 --at 1
```

**Allow only one port on a host** -- scope the allow with a proto and `:PORT`, then deny the rest of the host. The narrower rule must come first:

```sh
cogbox rules add allow tcp 1.2.3.4/32:443 --at 1   # HTTPS to that host
cogbox rules add deny 1.2.3.4/32 --at 2            # nothing else to it
```

Implicit rules (applied before user rules, not configurable):

- **DNS (port 53)** is always allowed so hostname resolution works
- **Loopback (127.0.0.0/8, ::1)** is always denied to prevent the VM from accessing host services via passt's gateway-to-loopback mapping

### Rule format

CIDR rules accept optional `tcp`/`udp` and `:PORT` qualifiers, both via `cogbox rules add` (e.g. `cogbox rules add allow tcp 1.2.3.4/32:443`) and when hand-edited in `config.json`. The runtime file format is:

```
allow 10.0.0.0/8                 # any proto, any port
allow tcp 10.0.0.0/8             # tcp, any port
deny  0.0.0.0/0:25               # any proto, port 25
allow tcp 0.0.0.0/0:443          # tcp, port 443
```

IPv6 CIDRs are matched port-less only (e.g. `deny tcp ::/0`); the `:PORT` qualifier is IPv4-only in v1, so a rule like `allow tcp ::1/128:443` is rejected.

### Rules verb reference

| Form | Description |
|---|---|
| `cogbox rules list [-n NAME]` | List current rules with 1-based indices |
| `cogbox rules add allow\|deny [tcp\|udp] CIDR[:PORT] [--at N] [-n NAME]` | Add a rule. An optional `tcp`/`udp` proto and `:PORT` narrow the match (both default to any). Appends by default; `--at N` inserts at 1-based position N. |
| `cogbox rules del INDEX [-n NAME]` | Delete a rule by index |
| `cogbox rules set [-n NAME]` | Replace all rules from stdin |

If the instance is running, rule changes take effect immediately: the runtime rules file is regenerated and passt receives `SIGUSR1` to reload.

### Enforcement internals

The filter works by intercepting passt's outbound `connect()`, `sendto()`, `sendmsg()`, and `sendmmsg()` syscalls. Since passt is the VM's only network path, this is a complete enforcement point. The filter is a Zig shared library (`libnetfilter.so`) loaded via `LD_PRELOAD`; it initializes via `.init_array` (before `main()`) so that all file I/O for rule loading completes before passt activates its seccomp-bpf sandbox. Denied connections receive `ENETUNREACH`.

The `cogbox rules` subcommands edit `config.json`, regenerate the runtime rules file, and signal the running passt, so rule changes take effect without restarting the VM. The CLI shares the on-disk rule format parser with the LD_PRELOAD filter, so the formats stay in sync.

Two implicit rules sit above the user rules, in this order:

1. **Port 53 is allowed**, to any destination, before the walk. It exists so a loopback resolver (`127.0.0.53`/systemd-resolved) keeps working, and it is checked first, so DNS also escapes the L7 mode's IPv6 fail-close, the seeded link-local deny and every private-range deny. `--no-implicit-dns` (`.network.implicitDns = false`) turns it off for an instance; the loopback deny below then applies to DNS as well.
2. **Loopback is denied.** passt translates traffic aimed at the guest's default *gateway* into `127.0.0.1` on the host (`--map-host-loopback`, whose default is the gateway address; `--no-map-gw` turns it off), so allowing loopback would expose every host service to the sandbox. The remap path bypasses this deliberately (it never evaluates the rewritten destination). Note that this is the gateway address, **not** the host's own address: the guest is assigned the host interface's address by passt's DHCP, so it cannot name the host that way at all.

One known boundary: traffic handled internally by passt (ARP, DHCP, gateway ping responses) never reaches the intercepted syscalls and is not subject to user rules. The launcher also runs passt `-4` (IPv4-only) in both modes: no cogbox host has IPv6 egress, and without a host IPv6 interface to template passt (2026_07+) would still send router advertisements, giving the guest a `fe80::1` default route and an IPv6-first fast-fail on every dual-stack name; with `-4` the guest has no IPv6 address or route, so the filter's IPv6 fail-close is a backstop rather than the first thing a connect hits.

### Host-integration knobs

Environment variables read by the launcher, all empty/off by default -- set by whatever provisions the host, never by a user. With none of them set, cogbox runs the exact command line it ran before they existed.

| Variable | Effect |
|---|---|
| `COGBOX_PASST_RUNAS` | Run passt under a dedicated uid (`--runas`) instead of the ambient `nobody` it self-drops to, so a host packet filter can express "guest-originated" as a uid match. Needs the launcher to start as root (or hold `CAP_SETUID`). Applied in `rules` **and** `full` mode -- `full` is the one with no L4 filter at all, so the host's rule is its only floor. |
| `COGBOX_PROXY_RUNAS` | Run the L7 proxy and the mitmproxy terminate backend under `user[:group]` (`setpriv`). The proxy re-resolves an allowed vhost and opens the upstream socket under **its own** uid, so a passt-only uid rule leaves it as an unscoped relay. Its runtime dir, per-instance CA dir and mitmproxy confdir must be writable by that uid, and whatever sends the hot-reload signals (`SIGHUP`/`SIGUSR1`) must be allowed to signal it. |
| `COGBOX_GUEST_RESOLVER` | Advertise this address to the guest as its resolver **and intercept its queries to it** (`passt --dns-forward`), plus stop mapping the gateway to the host (`--no-map-gw`). The address is a handle, not a destination: passt consumes the guest's DNS at the tap and re-emits it host-side, so nothing ever routes to it. The two flags go together: `--no-map-gw` is what closes passt's DNS carve-out (traffic to the mapped gateway on port 53 is forwarded to the *host's* resolver rather than translated to loopback, so it never looks like loopback to the filter), but it also disables the remap of loopback resolvers from `/etc/resolv.conf` -- which is how a dev box running systemd-resolved gives its guests DNS at all. Dropping that mapping is therefore only safe when an explicit guest resolver replaces it. **Not `-D`:** passt applies `-D` before reading `/etc/resolv.conf` and then skips the read, leaving `dns_host` unspecified and its own forwarding silently disarmed. |
| `COGBOX_HOST_RESOLVER` | Where those intercepted queries go (`passt --dns-host`): the loopback DNS forwarder on the enclosing host. Only applied together with `COGBOX_GUEST_RESOLVER`. A bare address -- passt parses it with `inet_pton`, so `host:port` is rejected -- and unlike `--dns-forward` it accepts a loopback one. The guest then resolves exactly what the host resolves, which is the point on a host whose real resolver the sandbox must not reach. Pair it with `cogbox init --dns-host <same address>` so the L4 filter admits that socket in `rules` mode, and with a rule in the host's own packet filter if it has one. |
| `COGBOX_PASST_BIND_FORWARDS` | Bind the guest's SSH/HTTP forwards to `.bindAddr` instead of every address. Opt-in: the default `.bindAddr` is `127.0.0.1`, and deployments that reach the forwards at a pod or host address depend on the wildcard bind. |
| `COGBOX_MOSH_UDP_FORWARD` | `lo-hi` (digits, `1 <= lo <= hi <= 65535`). Forward that UDP port range into the guest (`passt -u`, bound like the TCP forwards) **and** arm the L4 shim's reply-socket exemption below so the guest's answers can leave. This is how a mosh session reaches a sandbox: the control plane's gateway relays each client's datagrams to `<VM_IP>:<port>` in this range. Unset, both passt command lines and every shim decision are byte-identical to today; a malformed value (a bare port, the mosh-server `lo:hi` colon spelling, `lo > hi`, a port outside 1-65535) is refused by the launcher (exit 64) and, should it ever reach the shim, leaves the exemption off. `none` mode ignores it: SLIRP forwards no UDP and mosh is unsupported there. Nothing sets it on a workstation or in the Kubernetes pod; the GCE host renders it from `cogworx.gce.moshUDPPort`/`moshUDPPortRange` (`gce/supervisor.nix`), whose defaults come from `mosh-udp-range.nix` -- the repo's one source for the sandbox-side range (60000-60031), which also feeds the guest firewall's `allowedUDPPortRanges` and must agree with the range the cogworx gateway injects into every `mosh-server` exec (`internal/agent/mosh.go` there). The `gce-image-mosh-forward` flake check pins the rendered value to the range file. |

Whichever way the guest is handed its resolver, that resolver is the **only** one
it has: the guest image pins systemd-resolved's `FallbackDNS` to empty, so the
compiled-in public list (1.1.1.1, 8.8.8.8, 9.9.9.9, ...) never stands behind the
link-scope server. Without that pin, a guest whose link-scope DNS is unset or
failing falls through to a third-party resolver -- which does not merely answer
with public data, it *sends the internal query name off-site* and turns an
internal-DNS outage into an ordinary-looking NXDOMAIN. Empty means such a lookup
fails visibly instead. The `guest-dns-no-public-fallback` flake check asserts it
against the rendered `resolved.conf`.

Both `RUNAS` uids exist so a host filter can name them, and the GCE image's
`cogworx-floor.service` (`gce/floor.nix`) is the deployment that does: link-local
is dropped for the passt uid, and OPENING a flow to the VM's own non-loopback
addresses is dropped for **every** uid --
`meta skuid 0-4294967294 ct direction original ip daddr <self> drop` -- with the
control uid admitted to the guest SSH forward range above it so `cogbox ssh`
still works. Every part of that spelling is deliberate.

It cannot be narrowed to `skuid cogbox-passt` / `skuid cogbox-proxy`, because
in-VM nix builds run as `nixbld*` under the daemon and passt creates its
port-forward listeners *before* its privilege drop (`meta skuid` matches the
fsuid frozen in at socket creation, so those are root-owned).

It cannot be a blanket `daddr` drop with no `skuid` match either: on a same-host
connection the return packets carry the machine's own address as their
destination too, and the kernel's RST -- the reply when nothing is listening --
has no owning socket, so a `meta skuid` rule cannot match it and it survives. A
matchless drop swallows it.

And `skuid` alone does not save a reply that *does* have a socket. Once passt is
listening, the reply is a SYN-ACK from a real (pre-drop, root-owned) socket whose
destination port is the client's ephemeral port, so it matches no `dport` accept
and lands in the deny: an unscoped range would break `cogbox ssh`, Terminal,
Console-over-ssh and the user SSH gateway while still passing shape checks and
empty-port probes. `ct direction original`
scopes the deny to the direction that OPENS a flow, which is the rule's actual
intent. It is not `ct state new`: state-scoping would additionally exempt a flow
that survived a floor reload for that flow's whole lifetime, whereas direction is
a property of the packet and keeps the strength of the unscoped drop. It does
mean the VM's network namespace now runs conntrack, whose table is a finite
resource a busy guest can push on.

A guest gains nothing from the direction scoping: its first packet is the one
that opens the flow, the deny takes it, and a dropped OUTPUT packet is never
confirmed into conntrack, so no reply direction ever exists for it to ride.
Loopback is outside *that* rule so the L7 remap funnel is untouched; the proxy's
own `--self-addr` hard floor covers the relay path a second time.
`tests/test_floor.sh` loads the rendered ruleset into a throwaway netns and probes
it with a real listener bound, because that is the only setup in which the broken
and the correct rule behave differently.

Loopback gets its own rule, and deliberately the **opposite** shape:
`meta skuid cogbox-passt ct direction original ip daddr 127.0.0.0/8 drop` (plus
the `::1` mirror), with the funnel's own targets accepted above it as an explicit
port set -- `127.0.0.1:<l7base>` and `+1` for each triple `cogbox start` may slide
onto. It stays scoped to the passt uid rather than covering every uid because
loopback is where the trusted half talks to *itself*: l7proxy dials the mitm hop,
mitmproxy dials its upstreams, sshd and the nix daemon live there. passt is the
only process that turns guest bytes into host sockets, and its per-flow outbound
sockets are created after the privilege drop, so that one uid is both necessary
and sufficient. The third port of each triple -- the mitmproxy SOCKS5 hop, dialed
by l7proxy under the *proxy* uid -- is deliberately not in the set, which is why
it is a set and not a port range. `ct direction original` matters here for the
same reason it does on rule 2: the funnel's SYN-ACK carries `daddr 127.0.0.1` and
the client's ephemeral port, so a stateless deny would eat every funnel reply and
take L7 down.

The rule is defence in depth, and what it is defending is worth naming so nobody
removes it as redundant. A guest cannot address the enclosing machine over
loopback today for two reasons that are both upstream C: passt drops tap frames
carrying a loopback source or destination, and `--no-map-gw` removes the
gateway-to-loopback mapping that would otherwise turn an address the guest *can*
name into `127.0.0.1` on the host. In `full` mode there is no L4 shim, so this
rule independently enforces the loopback half of "a guest cannot reach the
host's services." The funnel's remap table is also rendered from
`.network.remap`, which accepts an arbitrary single loopback target, so anything
that can write an instance's config can aim passt's own `connect()` at
`127.0.0.1:22`.

> **Testing note.** An in-guest probe of the *host's own address* proves nothing.
> passt assigns the guest the host interface's own address over DHCP ("its own
> address shadows that of the host", `passt(1) --map-guest-addr`), so a connect to
> that address from inside the guest is delivered inside the guest -- to the
> guest's own sshd, whose banner matches the host's when both run the same
> nixpkgs. The floor's counters correctly stay still, because nothing was sent.
> Compare SSH **host keys**, or probe a port only the host binds.

#### The mosh reply-socket exemption

With `COGBOX_MOSH_UDP_FORWARD` set, the `rules`-mode L4 shim admits exactly one class of socket that its default deny would otherwise refuse: the per-flow reply socket passt opens for a datagram that arrived at one of those `-u` listeners. passt's shape for an inbound UDP flow is fixed (`udp_flow_from_sock` -> `flow_initiate_sa` -> `udp_flow_sock`): it creates a socket, `bind()`s it to the datagram's *destination* -- the listener's own address and port, taken from `IP_PKTINFO` -- and `connect()`s it to the sender; the guest's replies then leave through `sendmmsg()` on that socket with the sender as the explicit `msg_name` of every entry. Under the default deny that `connect()` fails and passt logs `Couldn't connect flow socket`, so an inbound UDP forward is dead without an exemption.

The shim keys the exemption on the socket's **local** address, read with `getsockname()` inside its `connect()` wrapper before the real connect runs (an implicit bind after connect would report the route's source address instead): the port must lie inside the configured range **and** the address must be a specific, non-loopback unicast address (a v4-mapped v6 address is unwrapped and judged as v4; `0.0.0.0`, `::`, `127/8`, `::1`, multicast and broadcast all fail). A socket that passes has its peer recorded and is marked exempt; the connect proceeds without a rule walk. A fd beyond the shim's tracked-fd table is never exempted, whatever its local address: the mark could not be stored, so such a connect falls through to the ordinary deny and fails once, cleanly, instead of being admitted and then having every reply datagram denied one by one in `sendmmsg`. The three passt facts the exemption rests on -- the outbound `oaddr` stays unspecified without `-o`, the inbound reply socket is bound to the `IP_PKTINFO` destination, and `getsockname` is in passt's seccomp profile (`udp_flow.c` declares it unprofiled, so it lands in every profile) -- were re-verified against the passt release nixpkgs pins (2026_07_16); re-check them on a passt bump.

Guest-originated UDP cannot satisfy that test, and this is why the address half is load-bearing rather than the port alone. For a flow the guest opens, passt sets the host-side source to its `--outbound-addr`, which the launcher never passes, so it stays unspecified -- and it preserves the guest's source port (`fwd_nat_from_tap`: `oaddr = addr_out`, `oport = ini->eport`), then `bind()`s exactly that (`sock_l4`). At connect time such a socket is bound to `0.0.0.0:<guest sport>` (or `[::]`), which fails the address half even when the guest chooses a source port inside the range. The `ENETUNREACH` the shim returns is what passt's own `connect()` sees on the host side, not what the guest observes: passt logs `Couldn't connect flow socket` at debug level and then silently drops the tap-originated datagram (`udp_tap_handler`: `Dropping datagram with no flow`) without sending any ICMP, so a guest-side `nc -u -p 60005 <off-range host>` succeeds at `sendto` and simply hears nothing back. `tests/test_launch_flags.sh` pins that `--outbound-addr`/`-o` never appears on the passt command line, because adding it would hand every guest flow a specific source address and turn the exemption into a port-only check.

On the send side, an exempt fd is exempt **only toward the recorded peer**: a NULL destination (connected send) or an explicit `msg_name`/`dest_addr` equal to the peer goes straight to libc; any other destination -- and `sendmmsg` inspects `vec[0]` as it always has -- runs the ordinary allow/deny walk, so the socket cannot be steered at a third party even by a passt that misbehaved. A loopback peer is never exempted (the loopback deny stays whole). `socket()` re-tracking and `close()` untracking reset the mark; a later UDP `connect()` on the same fd that does not re-qualify clears it before the rule walk runs, so the mark is gone whether that connect is then allowed or denied (a denied one leaves the kernel's old association in place, but no longer an exemption for it). `bind()`, TCP, remap and the DNS gates are untouched, and with the knob unset no `getsockname()` is ever issued.

The residual is the same class as the guest SSH forward under the VPC 10/8 rule: any host that can route to `<VM_IP>:<lo>-<hi>` can seed such a flow and receive the guest's replies to it. The exemption extends to whatever source address seeded the flow, so it relies on the network's anti-spoofing (the VPC on GCE) to keep "any host that can route to the VM" from becoming "any address". Who can seed a flow is decided outside the shim (the VPC rule on GCE), and mosh's own payloads are AES-OCB authenticated end to end, so what such a host receives without the session key is noise.

What covers the exemption: the pure halves live in `zig/src/filter.zig` (`parsePortRange`, `isForwardReplyLocal`, `replySendAllowed`) with `test` blocks run by the `zig-tests` flake check; the table-lookup half in `zig/src/netfilter/main.zig` (`isForwardReplySocket`, `replyExemptTo`, the `connect()` ordering) has no unit target, so `zig/test-reload.sh` carries the manual recipe -- passt under the shim with the knob and a matching `-u` forward must show no `Couldn't connect flow socket` for a peer-seeded datagram, while a guest-side send from an in-range source port to an off-range host still gets nothing back. `tests/test_launch_flags.sh` pins the launcher side: the `-u` render, the exit-64 refusals, the unset-knob byte-identity and the absence of `--outbound-addr`.

#### The container floor's mosh reply leg

The container backend runs no passt and no shim; its egress floor is the nftables ruleset `cogbox-nft-divert.sh` installs from the `nft-init` container (`table inet cogbox_floor`, a default-drop allowlist: `lo`, all TCP -- which the divert table redirects into the enforcer -- and `udp/53` to the resolver only). mosh adds one accept to that allowlist, and it is deliberately not a source-port hole. `mosh-server` binds a port in 60000-60031 inside the pod (the literal mirrors `mosh-udp-range.nix`; the nft-init image carries no nix at runtime, so the script spells it out and `tests/nft_floor_bypass_driver.py` grep-pins the spelling), and its datagrams are admitted only when they belong to a conntrack entry that is (a) in the reply direction and (b) carries `ct mark 0x6d`, which a `prerouting` chain sets on a `ct state new` datagram to `udp dport 60000-60031` arriving on a real interface (`iif != "lo"`). Half (a) keeps a pod-originated datagram from a source port in the range -- `ct direction original` -- on the drop path; half (b) makes the rule hold even against a pod that could forge a seed with a raw socket, because a datagram injected over loopback traverses prerouting with `iif lo`, never gets the mark, and so its "reply" leg fails the mark test. Who may legitimately seed a flow is bounded outside the pod by the per-instance NetworkPolicy the control plane renders (the gateway pod, on that UDP range). The fail-closed fallback floor -- loaded when the enforcer coordinates are missing -- carries no mosh rule at all, and the driver asserts that too. `tests/nft_bypass_probe.py` exercises both edges in the `nft-floor-bypass` VM test: a pod-originated datagram from source port 60006 is dropped, and a reply from `:60005` to a peer-initiated flow is delivered. One more thing about that script is worth knowing before editing its comments: the nft program is an unquoted heredoc, because the shell has to expand the divert port, the enforcer carve-out and the resolver allow rules into it, so a backtick or `$(` inside an nft comment there is command-substituted by the shell -- the ruleset still loads (nft ignores the comment) but the sidecar's stderr fills with `oif: command not found` noise. `tests/test_nft_divert.sh` (the `nft-divert-tests` flake check) pins the heredoc bodies shell-inert, runs the script against a stub `nft` on both the normal and the fail-closed path, and re-parses the captured programs with a real `nft -c` where the sandbox allows it.

Where the launcher's stderr is collected somewhere retained outside the machine (a cloud serial console, say), what it prints on a failure matters. Its error paths name **files, instances and harness keys, never credential values** -- the redaction failures say "token withheld" rather than echoing the token -- and it never dumps its environment or its own argv. One deliberate exception: an argument the Zig wrapper did not recognize is echoed back verbatim in `cogbox-launch: error: unexpected argument <arg>`, since the whole point of that branch is to name the offending token. It is unreachable through the CLI (the wrapper validates first) and only matters to something invoking the script directly with a secret in an argument position -- which is already the wrong shape: credentials reach cogbox on stdin or through a file, never argv.

## TCP destination remap

A second, independent table redirects outbound TCP connects from specific `(cidr, port)` destinations to a loopback target on the host. When a match fires, the shim drives a SOCKS5 v5 CONNECT handshake on the connecting fd, carrying the original `(ip, port)` to the target proxy -- so the downstream proxy sees the guest's real intended destination. v1 supports TCP only; the target must be a single host.

| Form | Description |
|---|---|
| `cogbox remap list [-n NAME]` | List current remap rules with 1-based indices |
| `cogbox remap add FROM TO [--at N] [-n NAME]` | Add a rule. `FROM` and `TO` are single quoted args, e.g. `"tcp 0.0.0.0/0:443"` and `"tcp 127.0.0.1:18080"`. |
| `cogbox remap del INDEX [-n NAME]` | Delete a rule by index |
| `cogbox remap set [-n NAME]` | Replace all rules from stdin (one `FROM -> TO` per line) |

Example: send every outbound TCP/443 connection through a SOCKS5 proxy running on `127.0.0.1:18080`:

```sh
cogbox remap add "tcp 0.0.0.0/0:443" "tcp 127.0.0.1:18080"
```

The CIDR + remap tables share one runtime rules file; edits to either verb rewrite both sections cleanly without dropping the other layer. Like L4 rules, remap edits hot-reload into a running instance.

The remap table is also the substrate for [L7 host filtering](#l7-host-filtering): enabling L7 auto-injects remaps that funnel guest web traffic into the host-side proxy.

**The handshake is invisible to passt's byte accounting.** The shim writes the SOCKS5 prefix (13 bytes for an IPv4 target) on passt's own flow socket, inside `connect()`, before passt writes the first guest byte, so the peer's `tcpi_bytes_acked` on that socket counts 13 bytes that never came from the tap. passt 2026_07_16 (the version the pinned nixpkgs ships; 2025_09_19 did not take this path with the default sndbuf) derives the ACK it sends the guest from that counter on flows with a large sndbuf and a non-low RTT, and so acks 13 bytes past the guest's `snd_nxt`; the guest discards an ACK for unsent data, passt never moves its ACK backwards, and the flow stalls until the guest's retransmit timer gives up. It showed up on the terminate tier as roughly one in four HTTPS connections hanging whenever the ClientHello spans more than one MSS (a stock TLS 1.3 hello). The `passt-cc` package therefore carries `patches/passt-ack-never-exceeds-seq-from-tap.patch`, which clamps the derived ACK to what the guest has sent; the `passt-cc-patched` flake check asserts the clamp is in the source passt-cc compiles, so a nixpkgs bump that drops the override is loud rather than a 25% stall. The container backend is unaffected: it runs no passt and its enforcer receives flows by netfilter redirect, with no in-band prefix at all.

## L7 host filtering

L4 rules whitelist a destination *IP*. That is not enough when several virtual hosts share one load-balancer IP: allowing the LB lets the sandbox reach **every** backend on it by guessing the `Host`/SNI. The `l7` layer whitelists individual vhosts instead.

### The model

When `.network.l7` has any rule, cogbox starts a small host-side proxy and funnels **all** guest 80/443 traffic to it (via an auto-injected `remap`). For each connection the proxy reads the vhost from the TLS **SNI** (HTTPS) or **Host** header (HTTP), checks it against your `allow`/`deny` list (first match, default deny; patterns are exact / `*.suffix` / `*`), and on allow **re-resolves that name itself, host-side**, then splices the bytes through. Re-resolution is the point: the guest's chosen IP is discarded, so

- allowing one vhost does **not** expose siblings on the same IP, and
- DNS-based load balancing (rotating/shared IPs) keeps working, because the proxy always resolves the allowed name fresh.

The exception is a ClientHello with **no SNI** -- which is what HTTPS to a bare IP literal looks like, since RFC 6066 forbids IP literals in `server_name`. It carries no vhost to evaluate, so the proxy neither allows nor denies it by name (an L7 `deny *` does not cover it); it is spliced to its original `ip:port` only when the **L4** policy and the hard floor admit that address, exactly as on a non-funneled port. So an L4 allow for an appliance's IP covers `https://<ip>/` too, while a host reachable only through an L7 *name* allow must be addressed by that name -- and an IP that must stay off-limits over HTTPS has to be restricted at L4. A no-SNI hello that also carries an ECH extension is never L4-gated as no-SNI (its encrypted inner name could be any vhost on the IP): it stays on the unclassifiable path (dropped on the plain socks5 front door; raw-L4-gated like any unclassifiable flow where the front door funnels every port).

```sh
cogbox l7 add allow api.example.com        # only this vhost on its LB
```

L7 rules live under `.network.l7` and require the instance's network mode to be `rules`. Edits hot-reload the proxy (`SIGHUP`) and passt (`SIGUSR1`).

### How L7 composes with L4

The proxy re-resolves the allowed name **host-side** (it never trusts the guest's IP or a guest-supplied Host/SNI as a destination), so an L7 rule refines the L4 IP policy by name. For each re-resolved IP, on funneled web traffic:

| vhost vs. L7 rules | decision |
|---|---|
| explicitly **allowed** | **dial** -- supersedes an L4 IP *block* |
| explicitly **denied** | **drop** -- supersedes an L4 IP *allow* |
| **not in any rule** | defer to L4 (dial if the IP is allowed, drop if blocked) |
| **no SNI** (HTTPS to an IP literal) | defer to L4 only (dial if the IP:port is L4-allowed; neither a name allow nor a name deny -- including `deny *` -- can apply: there is no name) |

...and a **non-overridable hard floor** (loopback, this-network `0.0.0.0/8`, and link-local incl. cloud metadata `169.254.169.254`) is *always* dropped, even for an allowed vhost.

That built-in set is topology-independent, so it cannot include the address of the machine cogbox is running on -- and since an explicit L7 allow supersedes the L4 IP check, a sandbox owner who controls a DNS zone could otherwise point a name at that machine, allow the name, and obtain a guest-triggered connection back into the host half (under the *proxy's* uid, not passt's). Per-instance `--self-addr` entries (`.network.selfAddrs`, rendered as `hard-deny <cidr>`) extend the floor with exactly those addresses. They apply to every proxy dial path -- named splice, terminate handoff, and the raw-L4 splice -- and, being a floor, are never superseded by an allow. Loopback is untouched, so the L7 funnel itself keeps working.

**Path constraints fail closed.** When an `allow` rule names a host but adds a path prefix (`allow api.example.com /v1/`), a request to that host on an *uncovered* path (e.g. `/v2/`) is **dropped**, not deferred to L4 -- otherwise the constraint would be silently bypassed whenever the IP is independently L4-allowed (the usual "allow the internet at L4, restrict vhosts at L7" setup). A `deny` rule with a path (`deny api.example.com /admin/`) only blocks that prefix and leaves other paths to L4, since you're carving out a hole, not whitelisting. On HTTPS this is enforced by the terminate tier; on cleartext HTTP the proxy enforces it inline from the request line.

So to reach an internal vhost on a private LB, you just allow the **name** -- no L4 IP rule, and you never open that IP for anything else:

```sh
# 10.10.10.10 hosts a.internal and b.internal; reach ONLY a.internal:
cogbox l7 add allow a.internal          # leave 10.10.10.10 blocked (default deny 10/8)
# a.internal -> allowed -> dialed;  b.internal -> unlisted -> IP blocked -> dropped
```

Conversely, sibling isolation only applies where the LB's **IP is blocked**. On a public LB reachable via `allow 0.0.0.0/0`, an unlisted sibling falls back to L4 and is allowed; block the IP (or `l7 add deny sibling`) to restrict it.

**HTTPS to a bare IP** (an appliance with no DNS name -- a BMC, a switch, a printer) goes the other way: a browser or `curl` sends no SNI for an IP literal, so there is no name to allow. Allow the **IP** at L4 and the no-SNI HTTPS flow follows that decision:

```sh
# 198.51.100.10 is a management controller on the LAN with no DNS name; open only its HTTPS port
cogbox rules add allow tcp 198.51.100.10/32:443 --at 1
# in the guest: curl -k https://198.51.100.10/   -> TLS completes to the device's own cert
```

No L7 rule takes part (`cogbox l7 add allow 198.51.100.10` is not needed). Forcing the IP into SNI to get past the funnel -- `openssl s_client -connect <ip>:443 -servername <ip>` -- was the workaround while the VM/GCE front door still dropped a no-SNI hello as unclassifiable; it is no longer needed. A client that does put the IP into SNI is treated as the named vhost `<ip>` and walks the L7 rules like any other name (so an L7 `deny *` catches *that* form, but not the plain no-SNI one -- restrict the IP at L4 if it must stay unreachable).

> **Wildcard caveat.** A `*.suffix` allow trusts that whole domain's DNS -- if an attacker can create `evil.suffix` pointing at an internal IP, it would be dialed (metadata/loopback/link-local still blocked by the hard floor). Exact-name allows have no such exposure (you control that name's DNS); only wildcard a suffix whose DNS you trust.

### Tiers: terminate and passthrough

There are two tiers, chosen per host. **Terminate is the default**:

- **Terminate (default)** -- the proxy MITMs the host's TLS via a per-instance CA so it can enforce `Host == SNI` and URL paths -- see [the terminate tier](#the-terminate-tier). This breaks cert-pinned clients, so opt those out with `--passthrough`.
- **Passthrough** (`--passthrough` per host, or `l7 mode passthrough` for the whole instance) -- TLS is *not* intercepted, so cert pinning is preserved, but the proxy trusts the SNI it sees: a shared ingress that routes by the inner `Host:`/HTTP-2 `:authority` could still be steered to a sibling on a single connection, and URL paths can't be inspected on HTTPS. Because that cleartext SNI is the *only* routing signal, an [ECH-bearing](#l7-caveats) ClientHello is refused on this tier.

**Harness API endpoints auto-passthrough.** Because terminate is the default, the in-guest agents' own control-plane endpoints (`api.anthropic.com`, `api.openai.com`, `chatgpt.com`, `api.deepseek.com`, etc.) are automatically kept in passthrough, so the harnesses keep working out of the box (notably rustls clients that may not honor the injected CA) and their API tokens stay end-to-end. An explicit `--terminate` on such a host overrides it; provider-agnostic harnesses (opencode, omp, pi, hermes-agent) should `--passthrough` their configured provider hosts when termination is inappropriate.

### The terminate tier

By default every allowed host is routed through a TLS-terminating proxy ([mitmproxy](https://mitmproxy.org/)) so cogbox can see inside HTTPS (use `--passthrough` to opt a host out, or a `--path` prefix to add path enforcement). This closes the passthrough gaps:

- enforces `Host == SNI` (a connection whose decrypted `Host:`/`:authority` disagrees with the negotiated SNI is rejected with `403`), and
- enforces **URL path prefixes** (`--path /v1/`), boundary-aware and applied to the normalized, percent-decoded path, and
- **strips HTTP method-override headers** (`X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`) from every request it sees. Rules are matched on the *wire* method, while frameworks such as Rack rewrite the request to the method one of those headers names -- so leaving one in place would let a method the rules allow (`POST`) be executed by the origin as one they exclude (`DELETE`), with the host-side credential already injected. Stripping is unconditional, so the origin always acts on the same method the decision was made on. Residual, stated rather than assumed away: Rack also honours a `_method` field in a form-encoded **body**, and this proxy is header-only by construction (pack-endpoint bodies are streamed, never buffered).

**A request whose path carries a `.` or `..` segment is refused with `403`** -- at both tiers, before any rule is consulted and before any credential is injected. Dot segments are *rejected, never collapsed*, because the enforcer decides on the normalized path but forwards the **original raw path** upstream: percent-decoding can only ever *add* segments (a `%2F` becomes a real separator), which narrows a left-anchored rule, whereas popping `..` *removes* them -- so `/a/denied/..%2Fallowed` would be authorized as `/a/allowed` while the origin stays free to route the raw form. Only a whole `.`/`..` segment is refused; dots inside a segment (`/a/..b`, `/v1.2/x`) are ordinary data, and `//` still collapses. No normal HTTP client emits a dot segment.

```sh
cogbox l7 add allow git.example.com --path /myorg/   # only this path prefix
cogbox l7 mode terminate                             # terminate every L7 host
```

**Single-segment path wildcards.** A `--path` segment that is exactly `*` matches **exactly one** request segment and never spans a `/`: `--path /api/v4/projects/*/issues` matches `/api/v4/projects/1234/issues` and everything under it, but not `/api/v4/projects/1234/access_tokens` and not `/api/v4/projects/a/b/issues`. A segment that is exactly `#` is the same thing **narrowed to ASCII digits** (`[0-9]+`), for a segment that is a numeric identifier by construction: `--path /api/v4/projects/#/issues` matches `/api/v4/projects/1234/issues` but not `/api/v4/projects/mygroup/issues`. Either character outside a whole segment (`/a*`, `/b#c`) is a literal, and either one in the *request* is always literal -- the request side is data and is never interpreted. `--exact` compares the path literally and does **not** honour either wildcard.

Three properties matter when writing rules with them:

- **The rule is still a prefix.** `--path /a/*` also matches `/a/b/c`. Only a path ending in a *literal* segment is bounded.
- **Matching happens on the percent-DECODED path,** so an encoded slash (`%2F`) is a real separator and inflates one addressed segment into several. A wildcard **deny** in front of a broader allow therefore fails *open* -- a left-anchored matcher cannot suffix-anchor a deny. Put the boundary in the allow, never in a deny.
- **Terminating an allow at a literal segment is necessary but not sufficient -- prefer `#` for an id.** If the caller chooses the wildcard segment's value (an "ID or URL-encoded path" style parameter), it can pick one whose *own last component is the rule's literal tail*: with `--path /a/*/tail`, the request `/a/x%2Ftail/anything` decodes to `/a/x/tail/anything`, `*` absorbs `x`, the tail is satisfied by the id's second component, and `/anything` rides through as ordinary prefix continuation. `#` closes that whenever the segment is numeric, because the absorbed component would then have to be all digits. The `tail absorption` block in the vector table pins both directions.

> **Upgrade note -- this changes the meaning of existing rules.** Before this release `*` and `#` in a `--path` were literal bytes, so a rule written as `--path /v1/*/chat` in the hope of globbing matched essentially nothing (fail closed). It now matches one segment. On upgrade, **audit every persisted rule set for a `*` or `#` path segment** -- each instance's `config.json` (`.l7.rules[].path`) and any rule set a control plane pushes -- because for an `allow` this is a silent widening applied by a rolling image roll. There is no escape for a *literal* `*`/`#` as a whole segment; if you need one, express the rule with `--exact`, which compares literally and does not honour the wildcards.

The Zig proxy (cleartext + passthrough) and the mitmproxy addon (terminate) implement this identically, asserted from one shared vector table -- `zig/src/l7proxy/path_vectors.tsv`, read by both `zig build test` and `tests/test_l7_addon.py`. Change one matcher and its own suite fails; realign the table for one matcher and the other suite fails.

How it works: every rules-mode instance runs mitmproxy with a **per-instance CA** (auto-generated under `~/.config/cogbox/instances/<name>/l7-ca/`, key stays host-side at mode `0600`) -- started at every boot, even with no L7 rules yet, so that hot-added rules terminate immediately and the CA is in the guest trust store from the start (it can only be injected at launch). The CA **certificate** (never the key) is injected into the guest at boot via `fw_cfg` and assembled into `/run/cogbox/ca-bundle.crt`; the harness launchers and login shells point `SSL_CERT_FILE`/`CURL_CA_BUNDLE`/`GIT_SSL_CAINFO`/`REQUESTS_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS` at it. Those env vars only reach OpenSSL/Node/git-style clients, so `cogbox-l7-trust.service` *also* imports the CA into root's **NSS database** (`/root/.pki/nssdb`) -- the trust store Chromium reads on Linux -- so browser-driven plugins (e.g. headless Chromium under Playwright, which ignores the env vars and the bundle file entirely) trust the terminate tier too. The Zig proxy still does all SSRF/CIDR vetting and hands mitmproxy only a pre-vetted IP; mitmproxy mints a per-SNI leaf, applies the rules, and re-originates upstream TLS validated against the *real* system trust.

**Upstream cert verification (`--insecure-upstream`).** Because the proxy re-originates TLS, it -- not the guest -- validates the upstream certificate (against the real system trust, by SNI). The guest's `curl -k` can't relax this: `-k` only covers the guest<->proxy leg, which is the always-valid minted leaf. So a terminate host whose upstream has a self-signed or name-mismatched cert fails with mitmproxy's `502 Bad Gateway -- Certificate verify failed` (common for internal services). Mark such a host `--insecure-upstream` to skip verification on **its** proxy<->upstream leg only -- the operator's per-host equivalent of `curl -k`:

```sh
cogbox l7 add allow internal.svc --insecure-upstream    # MITM, don't verify its upstream cert
cogbox l7 add allow internal.svc --path /v1/ --insecure-upstream
```

Verification stays **on** for every other host (fail closed); the flag is a deliberate per-target exception. If you only need to *whitelist* a bad-cert host (no path/`Host` enforcement), prefer passthrough instead -- there the guest keeps end-to-end TLS and its own `curl -k`.

Terminate caveats:

- This is an **intentional MITM**: for terminate hosts the proxy sees plaintext (host-process-only, never persisted). Cert pinning is **broken** for those hosts -- clients that pin a specific cert/CA (some Go and mobile apps) will fail; leave them on passthrough.
- The CA reaches OpenSSL/Node/git clients (via the env vars), curl/python, and NSS clients including Chromium (via root's NSS db, imported by `cogbox-l7-trust.service`). What's still **not** covered: a client that ships its **own** embedded trust store and consults neither the env vars nor any system/NSS store -- e.g. Rust `rustls` pinned to the bundled `webpki-roots` crate. The `codex` harness is Rust and uses `rustls`, but it links `rustls-native-certs`/`native-tls` and references `SSL_CERT_FILE` with **no** bundled `webpki-roots` (per binary inspection of 0.139.0), so it loads system roots and should honor the injected CA -- worth a quick runtime check. Passthrough is unaffected regardless. (The NSS import targets root's db, so a plugin running a browser as a non-root user with a different `$HOME` would need its own import.)
- HTTP/2 to the client is disabled (http/1.1 only) so every request's authority is checked against the SNI.

### Per-instance ports

The proxy and its mitmproxy terminate backend bind **per-instance** loopback ports (a contiguous triple from each instance's `l7PortBase` in config.json, default 18443: TLS funnel / HTTP funnel / terminate hop), so several L7-enabled instances run on one host without one instance's guest traffic funnelling into another's proxy. Named instances auto-assign disjoint triples at init -- but only disjoint among *one user's* instances. Because the triple binds the host's shared loopback, a different user's instance (or any process) can hold it on a multi-user host, so at launch `cogbox start` probes the triple and, if it is taken, slides to the next free triple and persists it back to config.json (`cogbox-launch: L7 port base ... in use; using ... instead.` in the log). Only if the proxy still can't bind -- e.g. a port grabbed in the race between probe and bind -- does `cogbox start` **abort** rather than boot a VM whose funnel can't reach its proxy.

### L7 verb reference

| Form | Description |
|---|---|
| `cogbox l7 list [-n NAME]` | List current L7 rules and the instance mode |
| `cogbox l7 add allow\|deny HOST [--passthrough \| --path P \| --terminate [--insecure-upstream]] [--at N] [-n NAME]` | Add a rule. `HOST` is an exact name, a `*.suffix` wildcard, or a bare `*`. Hosts **terminate by default**; `--passthrough` opts a host out (SNI-only, for cert-pinned clients). `--path`/`--terminate` force terminate; `--insecure-upstream` skips upstream cert verification (implies terminate). A `--path` segment that is exactly `*` (any one segment) or `#` (one all-digit segment) is a single-segment wildcard (see [the terminate tier](#the-terminate-tier)); `--exact` honours neither. This verb's grammar is a deliberate back-compat pin — it is what an old control plane falls back to — so it applies no whitespace or control-character restriction to its values: a padded `HOST` parses and is stored padded (the DNS-pattern validator trims before validating), and a whitespace-bearing `--path`/`--service` is accepted and then silently drops the whole rule at the enforcer, which is whitespace-tokenized. That restriction is a property of the line format, so it lives in `replace`. |
| `cogbox l7 del INDEX [-n NAME]` | Delete a rule by index |
| `cogbox l7 clear --plugin TAG [-n NAME]` | Drop every rule tagged `TAG` (the `"plugin"` field an `add --plugin` stamps) |
| `cogbox l7 replace --plugin TAG --from-stdin [-n NAME]` | Drop every rule tagged `TAG` and append the rule set read from stdin in its place, stamped with the same `TAG` — ONE config edit and ONE reload. Each line is the argv tail of `add` (`allow\|deny HOST [flags...]`), tokenized on space/tab, with blank and `#` lines skipped. `--at`, `--plugin` and a `tag=` token are rejected per line: the tag is argv-level exactly once, which is what stops one tagged batch from writing rules owned by another tag. A token carrying whitespace or a control character is rejected too — the format is whitespace-tokenized and newline-delimited, and a newline would split one rule into two with the second half inheriting the invocation's `TAG`. Rules append in stdin order, after every other rule. If the **resulting rendered rule-line count** would exceed the enforcer's rule cap **and the batch is larger than the tagged set it replaces**, the whole replace is refused with exit 65 and the config is left untouched — never truncated, because the proxy compiles only the first cap lines while the terminate-tier addon reading the same file has no cap, so a dropped tail makes the two layers disagree. Rendered *lines*, not `.l7.rules[]` entries: the renderer also emits one `allow HOST terminate` per inject-spec host that no rule names, so a result whose array fits can still render a document that does not. Only a replace that *grows* the rule set is refused: `l7 add` is **uncapped**, so the clear-then-add sequence this verb replaces can leave an already-over-cap array behind, and on such an instance a revoke (an empty batch) or a narrowing edit must still succeed or the withdrawn rules would stay in force with no way to remove them. |
| `cogbox l7 policy --from-stdin [-n NAME]` | Replace the instance's **auth-proxy policy document** (`.network.l7.authpolicy`) with the JSON document read from stdin — the delivery verb for a [migrated provider](#the-per-sandbox-auth-proxy). The document is validated *before* anything is written: a malformed document or an unknown `version` is refused with exit 65, and an over-cap (>64 KiB) document is refused too. The empty document `{"version":1,"providers":[]}` is accepted (it is how a share teardown withdraws a policy). On success the render runs inside the same credential transaction as `secret reload`, so the auth conf and the store grants stay consistent. An **old** binary that predates the auth proxy answers this subcommand with exit 64 and stderr exactly `cogbox l7: error: UnknownSubcommand` — the byte-exact signal the control plane classifies to fall back to the legacy per-grant rules. |
| `cogbox l7 set [-n NAME]` | Replace all rules from stdin (one `allow\|deny HOST` per line) |
| `cogbox l7 mode passthrough\|terminate [-n NAME]` | Set the instance default tier (terminate if unset) |

```sh
cogbox l7 add allow api.example.com                       # terminate (default)
cogbox l7 add allow pinned.example.com --passthrough      # SNI-only (cert pinned)
cogbox l7 add allow api.example.com --path /v1/           # terminate + path
cogbox l7 add deny '*' --at 1                             # explicit default-deny for vhosts
```

A rendered rule line may also carry a trailing `tag=<name>` token (e.g. `tag=git-grants`, stamped on compiled git-grant rules). Both wire parsers handle it: the Zig proxy **accepts and ignores** it (it plays no part in allow/deny or tiering), and the mitmproxy addon **uses** it for credential-injection gating (an inject spec's `rules_tag` must match a rule's `tag` for the token to be injected -- see [Host-side credential injection](#host-side-credential-injection)). A line carrying any genuinely-unknown token is still dropped fail-closed by both.

### L7 caveats

Documented, not silently assumed safe:

- **QUIC / UDP-443 and all guest IPv6** are denied while L7 is active (the funnel is IPv4/TCP-only), so clients fall back to inspectable IPv4 TCP. DNS (port 53) still works -- unless the instance was initialized with `--no-implicit-dns`, in which case DNS obeys the rules like everything else and the IPv6 fail-close covers it too.
- Loopback, this-network, and link-local/metadata vhosts are never reachable through the proxy (the hard floor) -- consistent with the sandbox's LAN posture for those specific ranges. Add the host's own addresses with `--self-addr` if the deployment needs them covered too; the built-in floor cannot know them.
- **Unclassifiable flows** carry no name to evaluate: a first byte that is neither TLS nor HTTP/1.x, a malformed ClientHello, a server-speaks-first protocol, or a client that sends nothing before the peek deadline. What happens next depends on the proxy's *front door*. On the VM/GCE path (`cogbox-launch.sh`: SOCKS5 accept, only the funneled web/inject ports reach the proxy) they are dropped fail-closed, logged `unclassifiable-or-no-sni`. On the container enforcer (`cogbox-enforce.sh`, which sets `COGBOX_L7_FUNNEL_ALL=1` because its in-pod shim funnels *every* diverted port over the one SOCKS5 hop) and in redirect accept mode (`COGBOX_L7_ACCEPT=redirect`), they are instead spliced raw to the original `ip:port` iff the L4 policy and the hard floor admit it -- logged `rawl4-deny` when they do not, `rawl4-no-upstream` when the dial fails. A well-formed no-SNI ClientHello is the one flow that is L4-gated this way on **every** front door (next bullets).
- **Encrypted ClientHello (ECH)** is refused on **passthrough** hosts (logged `ech-on-splice`): the cleartext SNI that passthrough routes on could be a decoy for an encrypted inner name, so it can't be trusted to identify the real host. **Terminate** hosts accept ECH -- mitmproxy is the TLS endpoint and re-checks `Host == SNI` on the *decrypted* request, so an inner name can't be smuggled past it. Chrome/Chromium send a GREASE ECH extension on every handshake by default, so a browser client reaching a vhost must be on the terminate tier (the default); only an explicitly `--passthrough` vhost would drop it. A GREASE ECH hello sent to a **bare IP literal** (no outer SNI) is not classified as no-SNI -- there is no name to terminate on, and the L4-only no-SNI splice cannot see what the encrypted inner hello names -- so on the VM/GCE (plain socks5) front door it is dropped, and on the redirect / `FUNNEL_ALL` front doors it is raw-L4-gated like any unclassifiable flow; a browser must reach such a host by name (the same trade-off the passthrough tier makes).
- **HTTPS to a bare IP (no SNI)** is gated by L4, never L7 (logged `no-sni-not-l4-allowed` when the IP:port is not L4-allowed; a successful splice is silent, like every raw-L4 splice). An L7 `deny *` does not cover it -- there is no name for it to match -- so restrict the IP at L4 instead. The VM/GCE front door used to drop such a hello as `unclassifiable-or-no-sni`, which made HTTPS-by-IP devices unreachable despite a correct L4 allow unless the client forced the IP into SNI (`openssl s_client -servername <ip>`); that workaround is no longer needed -- see [L7 host filtering](#l7-host-filtering). A malformed hello is never L4-gated as no-SNI: it stays on the unclassifiable path (dropped as `unclassifiable-or-no-sni` on the plain socks5 front door; raw-L4-gated as `rawl4-deny` where the front door funnels every port).

## Host-side credential injection

By default, cogbox inherits the harness's auth from the host by mounting the host's credential files into the guest (see [harnesses](harnesses.md)). Those files carry the agent's long-lived secrets -- for the OAuth harnesses, an `accessToken` and a `refreshToken` (in `~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.local/share/opencode/auth.json`, `~/.pi/agent/auth.json`, or OMP's `~/.omp/agent/agent.db` SQLite store); for hermes-agent, the provider API keys in `~/.hermes/.env`. A compromised or prompt-injected agent inside the sandbox can read them.

Host-side credential injection removes the secret from the sandbox. Because the terminate tier already MITMs a host's TLS host-side, the proxy can **rewrite the request's auth header** with the real token read from the host's own credential file -- so the guest only ever carries a stub, and the real token (especially the refresh token) never crosses the 9p / fw_cfg boundary into the VM.

### How it works

When an **inject-conf** is present (path in `COGBOX_L7_INJECT_CONF`, passed to the mitmproxy backend by `cogbox-launch.sh`), the terminate-tier addon (`l7-mitm-addon.py`), on every decrypted request whose host matches a configured spec, **after** the allow + `Host == SNI` checks pass, replaces the auth header from a host-side credential file:

- the conf is a JSON list of specs `{host, style, cred_file, token_path?, cred_format?, cookie_name?, account_id_path?, refresh?, stub_token?, rules_tag?}`;
- the addon reads `token_path` (a dotted path, e.g. `claudeAiOauth.accessToken`) out of `cred_file` and hot-reloads it on mtime change, so a rotated access token is picked up on the next request with no restart;
- injection is **scoped to the stub identity**: when the spec carries a `stub_token` (the placeholder redacted into the guest's cred file), the addon replaces the credential **only** when the request presents that exact stub -- or no credential at all. The guest's stub is thus overwritten with the real token, but a **secondary credential the guest legitimately obtained through an already-injected call** -- e.g. claude-code Remote Control's per-session `worker_jwt` -- is forwarded **untouched** instead of being clobbered (which would 401). A spec with no `stub_token` (harnesses that still mount their real token in-guest) always replaces, as before;
- if injection should fire for this request but the host-side token can't be read, the request **fails closed** (`403`) rather than forwarding the stub.
- when a spec carries `rules_tag`, the addon injects the credential **only if** the request is allowed by a rule bearing that tag (a second, tag-restricted evaluation over the same rule set). The full rule set still decides overall allow/deny, so a broad `allow <host>` grants **reachability** to the host but **not the token** -- the token rides only on a request a tagged rule matches. Emitted for the per-user `gitlab-oauth` bind as `rules_tag: git-grants`, matching the `tag=git-grants` wire token stamped on the compiled git-grant rules; a spec without `rules_tag` (the harness OAuth binds) is unaffected and injects on every allowed request as before.

`style` shapes the wire format: `bearer` (`Authorization: Bearer <token>`), `anthropic-oauth` (Bearer + `anthropic-beta: …,oauth-2025-04-20`, drops `x-api-key`), `anthropic-apikey` (`x-api-key`, drops `Authorization`), `openai-chatgpt` (Bearer + `ChatGPT-Account-Id`), and `cookie` (replaces **only** the named cookie -- the spec's `cookie_name` -- in the request `Cookie` header, leaving every other cookie verbatim). The conf and the credential files live **host-side only** -- they are never on a 9p share or fw_cfg slot, and `mitmdump` reads them as the launching user. For an **HTTPS** host this applies only on the **terminate** tier (so the addon sees the decrypted request); an explicit `cogbox l7 add allow <host> --passthrough` opts an HTTPS host out of both terminate and injection (the legacy "guest carries its own token end-to-end" behavior).

**Plain HTTP hosts.** Injection also works for cleartext `http://` vhosts -- the common case being an internal service with no TLS (e.g. an intranet app whose only credential is a session cookie). A plain-HTTP request carries no TLS to terminate and no SNI, so the proxy can't route it by the terminate tier; instead it routes a host's HTTP egress to the addon whenever that host appears in the inject-conf (the proxy reads the host list from a runtime `l7-inject-hosts` file derived from the same conf). The addon then skips the `Host == SNI` check (there is no SNI) but still enforces `allow`/`deny` + paths and stamps the credential exactly as for HTTPS. Two consequences worth understanding: (1) because the credential is stamped on the **cleartext** proxy<->upstream leg, only declare injection for a host you trust to receive that secret over the protocol it actually serves -- a host you reach over HTTPS but that *also* answers on `:80` could have its secret sent in the clear if the guest is steered to the HTTP port; (2) the **harness** provider hosts (`api.anthropic.com`, ...) are deliberately **excluded** from HTTP inject-routing -- they are HTTPS-only, so a guest cannot force a cleartext send of the real OAuth token by downgrading to `http://`. Only plugin/operator-declared inject hosts (and a hand-rolled `COGBOX_L7_INJECT_CONF`) are HTTP-routed.

### Default-on for new instances

A new rules-mode instance is **seeded for injection at init** for the harnesses the user is already **logged into** (a host-side cred file is present): `cogbox init` writes, under `.network.l7`, a `terminate` allow rule for each such harness's provider host(s) (`api.anthropic.com`, `chatgpt.com`, `api.openai.com`, ...) plus `"inject": true`. Nothing is seeded for a harness with no token yet (the `--yes` init activates all harnesses, but only logged-in ones are seeded) -- log in on the host first, or add the rule later. At launch, when `.network.l7.inject` is true, cogbox generates the inject-conf from the active harnesses' host cred files (`~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.local/share/opencode/auth.json`) into the runtime dir and points the terminate backend at it -- so injection works out of the box with no manual conf. The mapping is keyed on the **host**; if two harnesses provide the same host (e.g. claude-code and opencode both for `api.anthropic.com`), the first active one whose token file exists wins. Only specs whose host-side cred file exists are emitted; the rest fall back to the legacy path.

Opt a seeded host out by replacing its rule with passthrough -- `cogbox l7 add allow api.anthropic.com --passthrough` -- which drops both terminate and injection so the token goes end-to-end again (the legacy behavior); deleting the rule has the same effect. Setting `.network.l7.inject` to `false` stops the token rewriting but leaves the host on the terminate tier (still MITM'd, just not injected). Note that `cogbox l7 mode passthrough` does **not** opt a seeded host out: the seeded rule carries an explicit `terminate` that wins over the instance-default tier (`needsTerminate` precedence). An explicit `COGBOX_L7_INJECT_CONF=<path>` overrides the generated conf (used for testing or a hand-rolled mapping): it replaces both what the addon injects and the plain-HTTP inject-routing list (`l7-inject-hosts`). It does **not**, however, drive the netfilter funnel -- the per-port `remap` rules are rendered from `.network.l7.inject.specs[]` in `config.json` only (the funnel runs before any inject-conf is read). So an override-conf host on `:80`/`:443` is HTTP-routed and injected as usual, but one on a [non-standard port](#non-standard-ports) also needs a matching config spec carrying that `port`, or its egress never reaches the proxy to be injected.

### Keeping the token out of the guest

Injection rewrites the request host-side, but on its own the harness's credential file is still mounted into the guest (via the config/data overlay), so a compromised agent could read it directly. When injection is active, cogbox therefore **scrubs the secret from the guest**: the 9p source for that overlay becomes a per-instance hardlink-mirror of the host dir in which the credential file is **redacted** -- rewritten with its token fields replaced by inert placeholders, but its non-secret fields (the OAuth `scopes`, `subscriptionType`) kept -- so the real access/refresh tokens never enter the VM while the harness still sees a logged-in identity. (If the cred file has an unexpected shape and can't be redacted safely, staging writes a minimal placeholder-scoped credential instead -- a present, logged-in stub identity -- rather than risk writing a real token; only if even that write fails is the file dropped entirely.) The mirror is otherwise a hardlink copy (no bulk data copy -- the dir can be large), and the cred file's hardlink is broken before it is rewritten so the user's real file is never touched. The mirror lives host-only under the cogbox data root (`~/.local/share/cogbox/mirrors/<instance>/`), deliberately **not** under the instance's `instances/<name>/` data dir, which is shared read-write into the guest -- since the mirror is hardlinked to the real host dir, a guest write there would corrupt it. Hardlinking needs the mirror and source on the same filesystem (true when both live under `$HOME`); it falls back to a copy otherwise, and fail-closed to an empty dir, never the real dir. The rest of the config dir (settings, history, `CLAUDE.md`, ...) is preserved.

Because the redacted file keeps the OAuth `scopes`, claude-code starts up as a normally logged-in subscriber and the placeholder token is harmless: it sends the placeholder accessToken as a Bearer, the host proxy overwrites it on the wire (only over the stub) with the real token, and the far-future `expiresAt` stops the guest from ever trying (and failing) to refresh the placeholder itself. Keeping a real (logged-in) identity in the guest -- rather than the older "drop the file, run on an `ANTHROPIC_AUTH_TOKEN` env stub" approach -- is what lets features that gate on a **local full-scope credential** work under injection. `/remote-control` (`/rc`) is the motivating case: it checks the on-disk OAuth `scopes` before connecting (so the redacted-but-scoped file is essential), then mints an **ephemeral per-session `worker_jwt`** via an OAuth-authed call to `api.anthropic.com` (the stub is injected on that call), and runs its live transport (an SSE event stream + POSTs to `/v1/code/sessions/<id>/worker`) authenticated with that `worker_jwt`. Those transport requests also hit `api.anthropic.com`, but they carry the `worker_jwt` -- not the stub -- so the stub-scoped injection forwards them untouched; the earlier always-replace behavior clobbered the `worker_jwt` with the OAuth token, which the worker endpoint rejected (`401` -> `worker_register_failed` -> `Transport closed (code 403)`). A second terminate-tier subtlety surfaces in the same transport: its **inbound** leg (controller -> guest) is a long-lived **SSE event stream** (`GET .../worker/events/stream`), and mitmproxy **buffers response bodies by default** -- which stalls an open-ended stream, so the session connects and the **outbound** POSTs work but inbound events never flush (a one-way session). The addon's `responseheaders` hook sets `flow.response.stream = True` for `text/event-stream` responses so they pass through chunk-by-chunk (this also makes ordinary streaming inference truly stream rather than arrive all-at-once on close). The guest's `.credentials.json` is therefore **always present** -- a real redacted-scoped file on the happy path, or a minimal placeholder-scoped stub if staging fails -- so claude-code reads it, `/rc`'s on-disk scope gate is satisfied, and (crucially) an in-guest `/login` can write its OWN token over the placeholder. There is deliberately **no `ANTHROPIC_AUTH_TOKEN` env stub**: an injected auth-token env var would shadow the file, break `/rc`, and silently defeat in-guest login. Net: the **host's** access and refresh tokens never enter the sandbox; if a user logs in inside the VM with their own account, that token stays in that instance (see [In-VM login](#in-vm-login-per-instance-isolated) below).

**Keeping the injected token fresh (host-side refresh).** Scrubbing the token has a consequence: since the guest holds only a static placeholder and no refresh token, it can **never refresh on its own** -- so a long-running session would start getting `401`s the moment the host's short-lived access token lapsed. With nothing refreshing the host file -- the host's own CLI only keeps it warm while *it* is running -- the injected token eventually goes stale. To close this, an inject-conf spec may carry a `refresh` block (`{refresh_token_path, expires_at_path, token_url, client_id, expires_at_unit}`); cogbox emits one for the scrubbed **claude-code** host. When present, the addon does the OAuth refresh-token grant **host-side** as the access token nears expiry (default window 10 min; `COGBOX_L7_REFRESH_WINDOW_SEC`) and writes the rotated tokens back to the **same canonical credential file** the host's own CLI uses -- a single refresh-token lineage (a separate copy would fork the lineage and the provider's rotation would invalidate one side). It is serialized with `flock` in a host-only lock dir (never beside the cred file -- the mirror redacts the cred file but copies the rest of the dir, so a sibling token copy beside it would leak into the guest; no backup file is written for the same reason) and re-checks expiry under the lock, so it coexists with the host CLI refreshing the same file. The write is atomic (temp + `rename`, mode `0600`), and the whole path is **fail-safe**: any error -- unreadable file, network failure, malformed response, missing refresh token -- leaves the file untouched and the request proceeds with the current (still-valid, since the refresh fires before expiry) token. The refresh runs over the host's own egress and trust store, never through this proxy, and no token is ever logged. (Harnesses that still carry their token in-guest refresh there and carry no `refresh` block.)

This redaction currently covers **claude-code**. `codex` and `opencode` keep mounting their token for now (codex's non-secret account id lives in the same file; opencode is multi-provider with API-key providers that aren't injected) -- they still benefit from host-side injection but their cred files are not yet redacted.

### In-VM login (per-instance, isolated)

A user can run `/login` **inside** a guest; it works, **persists per-instance**, and never touches the host's credential. This falls out of the model rather than needing any capture machinery:

- **Default (placeholder present):** the guest carries the redacted stub, so its requests present `Bearer <stub>` and the addon injects the host token -- the instance **inherits** the host login.
- **After an in-guest `/login`:** the guest reaches the OAuth endpoint (`platform.claude.com`) over the default **passthrough** splice -- it is deliberately *not* terminated or injected, so the exchange is end-to-end and the guest receives and stores its **own** real tokens. That write copies up into the instance's persistent overlay upperdir (`instances/<name>/harness-overlay.img`), shadowing the redacted stub in the read-only lower. It survives reboots, and it takes **both** stub writers to keep it that way: the *launcher's* stub lives in the read-only **lower** layer (the host-only mirror `stage_overlay_source` builds), so it is simply shadowed by the upperdir copy; but the cogworx-managed reconcile (`cogbox __claude-stub`, driven by a per-instance marker) writes through the **merged** view at `/root/.claude`, i.e. into the *same* upperdir the in-guest login lives in, so shadowing cannot protect anything from it. That leg therefore refuses both to overwrite and to remove any credential at that path which does not carry cogbox's own sentinel -- so an in-guest login survives every boot and every cogworx re-drive on both legs. From then on the guest presents its **own** (non-stub) token, so `should_inject` passes it through untouched -- **host inheritance stops for that instance automatically, with no host write**. The guest holds its own refresh token too, so it self-refreshes against `platform.claude.com` directly.
- **Logout (back to the stub):** if the guest clears its credential, the merged overlay view falls back to the lower stub, so it presents the placeholder again and host inheritance resumes (placeholder present ⇒ inherit).

The boundary holds in the only direction that matters: a guest login is confined to that instance's own ext4 upperdir (the 9p lower is read-only, so overlay copy-up cannot write through to the host source), and the sole host-side write -- the addon's host-token refresh -- runs only while injecting (i.e. while the guest is still on the stub) and writes only the launching user's own canonical file, on a path the guest cannot influence. **No guest action mutates the host credential or any other instance.** (The host user can of course offline-read their own instance's image -- host-reads-own-guest, the safe direction.)

This per-instance login model currently applies to **claude-code** (the only harness with a redactor + stub identity). `codex`/`opencode` stay on the guest-carries-token path until they get redactors.

### Plugin-declared and operator-bound injection

The same terminate-tier mechanism is not limited to the built-in harnesses: a **plugin** can request injection for any host its agent talks to, and an **operator** binds the actual credential host-side. This generalizes the harness path to arbitrary bearer tokens and session cookies while preserving the credless boundary.

A plugin declares `cogboxPlugins.<attr>.inject` (see [plugins](plugins.md#credential-injection)). Crucially, a plugin can only **name** a secret and the exact host it targets -- it can never carry a value or a host-side path (the manifest is rejected at `add` time if it tries: `path`, `cred_file`, `token`, `refresh`, ... are all forbidden). Each spec names an exact `host` (no wildcard), a `style` (`bearer`, `cookie`, or `basic`; the `cookie` style also needs a `cookieName`), the secret `name`, an optional `stub` sentinel, and an optional `port` (see [non-standard ports](#non-standard-ports) -- declare it when the host is served somewhere other than 80/443, e.g. `9200` for Elasticsearch). The named specs merge into `.network.l7.inject.specs[]`:

```json
"network": { "l7": {
    "inject": { "enabled": true, "specs": [
        { "host": "api.example.com", "style": "bearer", "secret": "api-bearer", "plugin": "myplugin" },
        { "host": "es.internal", "style": "basic", "secret": "es-creds", "port": 9200, "plugin": "myplugin" },
        { "host": "app.example.com", "style": "cookie", "secret": "app-session",
          "cookieName": "app.sid", "stub": "cogbox-app-stub", "plugin": "myplugin" }
    ] },
    "rules": [ ... ]
} }
```

(`.network.l7.inject` is an object `{enabled, specs}`; the legacy bool `inject: true` -- harness injection on -- still works and is coerced to the object form the first time a verb writes inject specs.)

#### The secret store

Operators bind the real credential with `cogbox secret`, host-side, never on the command line:

```sh
cogbox secret add api-bearer --from-file ~/.secrets/api.token --audience api.example.com
cogbox secret ls
cogbox secret ls --json   # machine-readable inventory for a control plane
cogbox secret rm api-bearer
```

`cogbox secret ls --json` emits a JSON array of `{name, kind, audience, tier, bound, bound_at}` (the **value is never included**). A control plane (e.g. cogworx) reads it to show each plugin-declared inject request as bound vs unbound -- correctly reflecting the host-side store even when an operator bound the secret directly with `cogbox secret add` rather than through the UI. `audience` is `null` when unset (not injectable), `bound` is `false` when the named secret has no value file. A store that was never created prints `[]`.

The value is read from a file or stdin (never argv, which leaks to the process table) and stored at `~/.config/cogbox/secrets/<name>` (mode `0600`) alongside a `<name>.meta` sidecar recording `audience`, `kind`, `tier`, and `bound_at`. Where the deployment runs the proxy on a dedicated uid (`COGBOX_PROXY_RUNAS`), a bind with an `--audience` lands `0640` with the proxy's group instead, staged before the file is nameable so it is injectable from the first instant rather than from the render that follows -- see [Credential access under a dropped proxy uid](#credential-access-under-a-dropped-proxy-uid). The stored value is a single line -- a bare bearer token, a `user:password` pair, or a cookie value -- interpreted according to `--kind`.

**Supported `--kind` values and their wire format:**

| Kind | `Authorization` header | Stored value |
|---|---|---|
| `bearer` (default) | `Authorization: Bearer <value>` | raw token |
| `basic` | `Authorization: Basic base64(<value>)` | `user:password` |
| `cookie` | replaces named cookie only | cookie value |

**Example -- HTTP Basic auth for an internal Elasticsearch cluster on `:9200`:**

Injection needs two things: an inject **spec** (which host + style + secret name, and -- on a non-standard port -- the `port`) and the **bound secret**. A plugin's `cogboxPlugins.inject` writes the spec for you; there is no `cogbox inject add` verb, so an operator without a plugin hand-edits `.network.l7.inject.specs[]` in the instance `config.json`:

```sh
# 1. Declare the inject spec. (A plugin does this via cogboxPlugins.inject; by hand:)
cfg=~/.config/cogbox/instances/<name>/config.json
jq '.network.l7.inject = {enabled: true,
      specs: ((.network.l7.inject.specs // []) +
        [{host: "es.internal.example.com", style: "basic", secret: "es-creds", port: 9200}])}' \
   "$cfg" > "$cfg.tmp" && mv "$cfg.tmp" "$cfg"

# 2. Bind the credential host-side (raw user:password; base64 is done at injection time).
#    The --audience is the BARE host -- no :9200 -- and must equal the spec host.
echo -n "elastic:mypassword" | cogbox secret add es-creds \
    --from-stdin --audience es.internal.example.com --kind basic

# 3. cogbox restart  (the inject spec auto-adds an `allow <host> terminate` rule and,
#    via port:9200, a funnel remap so the guest's :9200 egress reaches the proxy).
```

The guest then sends requests unauthenticated or with a placeholder, and the host proxy rewrites the `Authorization` header before the request leaves the host. The spec host, the `--audience`, and any explicit `cogbox l7 add allow` all use the **bare** host (the proxy matches the request `Host` with its port stripped); the `:9200` lives only in the spec's `port` -- see [non-standard ports](#non-standard-ports). Omit the `port` and the spec still injects on `:80`/`:443` but a `:9200` request never reaches the proxy and stays unauthenticated.

Sidecar-produced per-instance secrets use the same layout under `instances/<name>/secrets/` and shadow a global secret of the same name. Names are restricted to `[A-Za-z0-9_-]` so neither `<name>` nor `<name>.meta` can traverse out of the store.

#### Non-standard ports

The guest's web egress is funnelled into the L7 proxy by a netfilter remap that captures only TCP **:80** and **:443** -- the ports the proxy splits into its plain-HTTP and TLS entries. A host served anywhere else (Elasticsearch on **:9200**, an internal API on **:8080**, ...) would bypass the proxy entirely: the connection clears only the L4 CIDR layer and egresses untouched, so its credential is never stamped and the upstream answers `401`.

To inject on such a host, the inject spec declares a `port`:

```json
{ "host": "data-es.internal", "style": "basic", "secret": "es-creds", "port": 9200 }
```

The renderer then emits an extra funnel remap (`0.0.0.0/0:9200 -> the proxy`) so the host's `:9200` egress reaches the addon and gets injected exactly like an `:80`/`:443` host. Two consequences:

1. The funnel is **per-port and instance-wide** -- declaring `:9200` routes *all* guest TCP to `:9200` (any host) through the L7 proxy, and the proxy classifies each connection by its first bytes: a valid TLS ClientHello or an HTTP/1.x request is evaluated against the L7 rules and forwarded (injected only for the exact inject host; a non-inject HTTP/TLS host on the port is just spliced). **Anything else is dropped, fail-closed** on the VM/GCE front door -- a non-HTTP/non-TLS (raw binary, server-speaks-first, malformed) connection on the port never reaches an upstream dial (the container enforcer raw-L4-gates it instead; see [L7 caveats](#l7-caveats)). The one exception is a well-formed TLS ClientHello with no SNI (HTTPS to an IP literal): it is spliced only if the L4 policy admits that `ip:port` -- the same gate the native L4 path applied before the funnel. So this is also a *behavior change* for the port: a non-HTTP service on `:9200` that the guest could previously reach over the native L4 path is now denied. Only declare a port that genuinely serves HTTP/TLS (Elasticsearch's REST is HTTP on `:9200`; its binary transport is the separate `:9300`, unaffected).
2. The `port` is a property of the **spec**, not the secret -- the secret's `--audience` and the `cogbox l7 add allow` rule both stay the bare host.

At boot (and on the hot-reload path), the renderer resolves each spec's named secret to the store's value path and emits it with `cred_format: "raw"` -- the addon reads that file's **first non-empty line** as the credential (no dotted `token_path`, unlike the JSON-cred harness specs). It writes the inject-conf with **two fail-closed gates**:

- **unbound** -- no value bound for the named secret ⇒ no conf element. Injection stays inert (the request's stub goes upstream and fails auth) until you bind it; nothing is ever forwarded *as if* it were real auth.
- **audience mismatch** -- a spec is emitted only when the bound secret's `audience` equals the spec host. This is the gate that stops a hostile plugin from later requesting that your bound `api-bearer` be injected to `attacker.example`: you bound it for `api.example.com`, so it is injectable **only** there. A secret with no audience set is treated as not-injectable.

Inject hosts are automatically unioned into the **terminate-allow** set (a header or cookie can only be added on a MITM-terminated flow), so an inject-only plugin still activates the funnel and terminates its host -- whether injection actually fires is decided separately by the bound/audience gates above. The plugin/operator specs and the harness specs are merged into the single conf the addon reads (harness specs win a host collision). The trust an operator grants by binding a secret is surfaced at `cogbox plugin add` (the injection requests render in their own section, and a bind-checklist prints the exact `cogbox secret add` commands); the secret value itself, like the harness credentials, is host-only and never crosses into the guest.

**Reserved control-plane binds are auto-seeded.** Two secret shapes are bound by a control plane rather than declared by a plugin, so the renderer seeds their spec itself -- no `config.json` entry is needed, and none is written (the seed is a render-time overlay, so revoking is just unbinding):

- `claude-oauth` with `--kind anthropic-oauth` -- seeds `{host: api.anthropic.com, style: anthropic-oauth, secret: claude-oauth}`. The seed's ONLY gate is that **a value file exists** for the secret, so a sandbox whose owner never connected gets no spec, hence no terminate-allow for the provider host and no funnel. That gate is *presence*, not validity: a zero-byte value with no `.meta` also seeds the terminate-allow. It is safe because the injection itself is gated a layer down by the two fail-closed checks above -- such a secret has no audience, so the inject conf stays empty and nothing is ever stamped; the host is merely funnelled and terminated.
- any secret with a value file and `--kind gitlab-oauth` -- seeds a spec for its `--audience` host, but only when an l7 rule already names that host (a grant-scoped bind must never render as a whole-host allow).

The seed runs on **every** render path -- the boot render, `cogbox secret reload -n <inst>`, and the rule/plugin-mutation reload -- because both the terminate-allow and the funnel are derived from the specs, so a path that re-rendered without seeding would strip them off a running instance. (It was originally gated on a "am I an enforcing container" env signal, which made the bind inert on the VM path: the credential was bound host-side and the guest stub staged, but nothing named the secret, so the placeholder was never replaced and the harness reported *not logged in*.)

Because the funnel remaps live in `netfilter-rules` -- the file the in-`passt` LD_PRELOAD shim owns -- every one of those paths must signal **both** consumers after re-rendering: `SIGHUP` the L7 proxy (`l7-rules` + the inject conf) *and* `SIGUSR1` passt (the shim reloads its ruleset only on that signal). Signalling only the proxy leaves a connect-later bind inert on a running instance: the funnel is on disk, but the guest's `:443` keeps egressing directly, so the placeholder credential reaches the upstream and the harness stays logged out until a restart.

### Credential access under a dropped proxy uid

The store's value files are written `0600` by the uid that runs `cogbox secret add` (the control uid). Where the proxy runs as that same uid -- the container enforcer, which also owns the enforcer-private store -- reader and owner coincide and there is nothing to arrange. Where `COGBOX_PROXY_RUNAS` puts the proxy on a **dedicated uid** (so a host packet filter can select guest-originated traffic by `meta skuid`), they do not: the addon's `open()` on `cred_file` gets `EACCES`, `token_for` returns `None`, and every request on the injected host is denied with `cogbox-l7: credential unavailable` -- with the bind, the seed, the spec, the terminate-allow and the funnel all correct.

So the inject render also reconciles the store's permissions (`rules/credgrant.zig`):

- **Scope.** Exactly the value files the conf being written *names*, and nothing else in the store (with one deviation at bind time, described two bullets down) -- the store holds credentials for unrelated audiences the proxy has no business reading. The grant is recorded at the same statement that emits `cred_file`, so the readable set is derived from the spec set and cannot drift from it. Only a resolved store path (`<store>/<secret name>`) can ever be granted; a `cred_file` supplied by a config, a plugin manifest or an operator override never is.
- **Mechanism.** `chgrp` to the proxy's **group** plus mode `0640`. `--regid` sets the proxy's *primary* gid and `--clear-groups` drops only *supplementary* groups, so a primary-group grant survives the drop (a supplementary-group scheme would not). Group-read also keeps the grant read-only and leaves the file owned by the control uid, which still has to rewrite it when a rotated token is re-bound. The store directory gains group **search** (`+x`, never `+r`) so a granted path can be opened by name without the store becoming enumerable. The `.meta` sidecar is never granted.
- **When.** On every inject render, because binds are runtime events (`cogbox secret add -n <inst>` then `secret reload`), not boot events -- and because a re-bind is an atomic rename that resets the file's group anyway. A boot-time `chown` would cover only the sandboxes whose owner had already connected. `COGBOX_PROXY_RUNAS` therefore has to be in the environment of **control-channel execs**, not just the launcher's.
- **At bind time, too.** A bind and its render are two separate control execs (`cogbox secret add -n <inst>`, then the re-render), so between them the credential existed at `0600` while the *previous* conf still named it -- roughly an SSH round-trip in which the addon answered 403 `credential unavailable` on that host. `secret add` therefore stages the same grant itself: it `chgrp`s the proxy's group and widens to `0640` on the **temp file, before the rename**, so the value is group-readable the first instant it is observable at its final path and the render's `chmod` is a steady-state no-op rather than the moment of readability. The widening never touches a live path, the `.meta` sidecar stays `0600`, and the render remains the authority -- its revoke pass takes the access straight back off any value file the conf it writes does not name. A `COGBOX_PROXY_RUNAS` group that `/etc/group` does not define, or a `chown` that fails, warns on stderr and leaves the file at `0600`: the bind still succeeded and the next render is still free to grant it.

  **The stage gate is deliberately wider than the Scope bullet above, and its reconciliation is not instant.** A bind stages the group on *any* value carrying an `--audience` (one without an audience is not injectable at all, so nothing is staged for it) — it cannot do better, because a global `cogbox secret add` with no `-n` does not know which instance's conf will name the secret. The compensating render is best-effort: `secret add` re-renders only when it was given `-n`, that re-render returns early for an instance with no live runtime dir, and the GCE control plane's follow-up `secret reload` is skipped outright for a non-live instance and only logged when it fails. So a value bound with an audience no current conf names can sit `0640` — readable by the proxy's group, still owner-write, never world-readable — until that instance's next render, at boot at the latest. That is the price of closing the 403 window; if it ever matters for a store holding many unrelated audiences, the narrowing is to stage only for audiences the instance's own conf names, which is computable on the `-n` path and not on the global one.
- **Revocation.** The pass first clears the group bits off every bound value file in the store, then re-grants only the named ones. Unbinding a secret, dropping a spec, an audience mismatch, or a git bind losing its grant rules all withdraw the access on the next render; there is no separate state to keep in sync.
- **Cache invalidation.** The addon caches each credential's value keyed on the value file's `(mtime_ns, size)`, and `chmod` moves neither -- so a grant is, by itself, invisible to it. Three things keep that from stranding a host on a stale answer. A **failed** read is never cached (it is not an answer): a transient `EACCES` in the render's revoke-then-regrant window, or an `EMFILE`, used to be stored under a key a later successful read would not move, which turned one unlucky request into a permanent 403 `credential unavailable` for that host with no self-heal. A **grant transition** bumps the value file's mtime, but only on a real `0600 -> 0640` change (a steady-state render must not, because the mtime is also the *rotation* signal the host-side refresh path reads) -- which is what retires a positive entry read before a re-bind, since a re-bind is an atomic rename followed by a *separate* `secret reload` exec that re-renders. And the addon **drops its credential caches whenever the inject conf reloads**, which happens in the same render pass, so it also covers a grant that failed once and succeeded on a later render.

Unset `COGBOX_PROXY_RUNAS` (container, k8s, local) means no uid split, and both halves are skipped -- `secret add` writes `0600` as it always did, and store permissions come out of a render byte-for-byte as it left them.

### What it does and does not protect

**Eliminated:** theft of the long-lived **refresh token** (it never enters the guest), account takeover via a stolen credential file reused off-box, and any persistence beyond the instance lifetime -- only short-lived access tokens are ever injected, host-side, into headers the guest cannot read.

**Not changed:** the guest still holds a **live, authenticated channel** to the provider while the instance runs. A compromised agent can still burn quota / cost and exfiltrate data through the model itself. Credential injection is a credential-*confidentiality* control, not a capability-*confinement* control; pair it with the L4/L7 egress rules, plus rate/cost limits and output monitoring. Note also that terminating a provider host means the **host process sees the plaintext** of that harness's model traffic (your box, never persisted) and that HTTP/2 is downgraded to HTTP/1.1 for that host.

## The per-sandbox auth proxy

Addon injection (above) replaces a request's auth header with a bound token, gated by generic L7 path rules. For a git provider that is too coarse: a per-user grant model ("this sandbox may clone `grp/repo` and read its issues, nothing else") has to be compiled down into path-prefix rules, and a decoded-then-forwarded path prefix is [escapable](#the-terminate-tier). The **per-sandbox auth proxy** replaces that whole scheme for a *migrated* provider with a fourth trusted-half process that classifies and authorizes each request against a typed route table and stamps the owner's credential itself — so the guest holds no token at all and no path-prefix rule is load-bearing. It is pluggable per service (gitlab is plugin #1). The full design, the route table, the three retarget traps and the hardening catalog live in **[docs/authproxy.md](authproxy.md)**; this section is the network-filtering-side summary.

**The fourth process.** Alongside `passt`/`l7proxy`/`mitmdump`, a rules-mode sandbox now runs `cogbox __authproxy` (started by `cogbox-launch.sh` on the VM path and `cogbox-enforce.sh` on the container path). It listens on loopback at a port derived **downward** from the instance's L7 base: `auth = base − 400` (`filter.l7AuthPortForBase`; `18443 → 18043`). Downward is collision-free forever — the auth band and the stride-3 triple band both grow upward at stride 3 and cannot meet. The port is **topology, never policy**: it lives only in the `COGBOX_L7_AUTH_PORT` env var, never in `config.json` and never in a wire file, and `next_free_l7_base` treats it as a fourth term so a base is only chosen when its auth slot is free too. On the VM path its start is **warn-not-die** (its absence breaks only migrated hosts, fail-closed — never the whole boot); on the container path it gets its own `wait -n` restart arm and its own `terminate()` kill, exactly like the other two children.

**The retarget seam.** For a host in `l7-auth-hosts`, the mitmproxy addon does **not** inject. After the allow decision it retargets the flow to `127.0.0.1:<auth-port>`: it writes `flow.request.data.host/.data.port` directly (never the `.host`/`.port` properties, which would rewrite `Host`), forces `flow.request.scheme = "http"` on the loopback hop, and hands the auth proxy three proxy-authored reserved headers after stripping every `X-Cogbox-*` request header unconditionally on every flow:

| header | value | role |
|---|---|---|
| `X-Cogbox-Host` | the request's `pretty_host`, captured before the retarget | the auth proxy's route key (must equal `Host`) |
| `X-Cogbox-Vetted` | l7proxy's already-vetted, pinned `ip:port` (the SOCKS5 CONNECT address), captured before the retarget | the auth proxy's **only** upstream target — it never re-resolves |
| `X-Cogbox-Proto` | the guest's original scheme (`https`/`http`) | audit only; the upstream scheme comes from the conf |

The loopback hop is connection-pooled across upstream hosts, so the auth proxy routes **per request** off `X-Cogbox-Host` and refuses a request whose host is not a configured entry. If the retarget cannot be completed (the auth proxy is dead, or the auth port is unusable), the request **fails closed** — a proxy error to the guest, no credential upstream.

**The new secret kind.** A migrated provider's token is bound under kind **`gitlab-authproxy`** instead of `gitlab-oauth`. This does double duty: it is the version gate (an old binary's `secret add` refuses the kind with exit 65, so no credential can exist on an un-rolled image), and it is the inject suppressor (the addon's inject-spec seeding keys on `gitlab-oauth`, so a token bound under the new kind is never seeded as an inject spec and the addon can never double-stamp a host the auth proxy already authenticates).

**The wire files, and the write order.** The credential render (`writeL7Inject`) now emits four files in **one** pass, inside one credential-grant transaction, so the store's read grants can never drift from what any reader is told to read:

1. `l7-inject-conf.json` — the addon's inject specs (unchanged).
2. `l7-auth-conf.json` — the auth proxy's conf: one element per migrated host with its plugin, scheme, `insecure` flag, `cred_file` and the policy doc's semantic grants. An element is emitted only when three gates hold together — the secret is bound under the new kind with an audience, the policy document names that host, and an L7 rule (the funnel) names it too. `insecure` is single-sourced from the same rule scan the addon's upstream-verification toggle uses, so a rule marked `--insecure-upstream` keeps applying after the upstream leg moves to the auth proxy.
3. `l7-inject-hosts` — the plain-HTTP routing list. Every migrated host is appended here too (deduped), so an `http://` request to it takes the terminate backend rather than a raw-L4 splice with no path enforcement.
4. `l7-auth-hosts` — the addon's retarget set, **written last**.

The order is load-bearing, and it sits inside a larger one. A render publishes **six** files in one fixed sequence (`reload.writeWireFiles`, shared by the boot render and the hot-reload render so the two cannot drift): `netfilter-rules` (the funnel) first, then the four above, then `l7-rules` — the **widening** file, carrying the terminate-allow — **last**. Each of the **five renamed** files — the four above plus `l7-rules` — is written **atomically**: a sibling `<name>.tmp-<pid>-<random>` is filled, `fsync`ed and renamed over the path, so no reader can ever see a half-written one (before that, a poll landing inside a truncate-then-rewrite could cache an *empty* spec set and un-inject a host until the next render moved the mtime). `netfilter-rules`, the sixth, is the documented **exception** and stays truncate-in-place — see the paragraph below. What survives is the **multi-file** window — a reader that catches file *N* updated and *N+1* not — and the order keeps that window on the fail-closed side: a host retargeted before its conf exists only 403s, and "rules widened while the inject conf is still the old one" (the proxy funnels and allows a host the addon has no spec for, so the guest's placeholder goes upstream and the provider 401s) cannot happen at all. What a failed read falls back to is per-reader, and the two failure kinds fall different ways: a failed **stat** (the file gone or unreadable) empties every reader and drops its cache key — `l7-rules` to deny-all, `l7-auth-hosts` to no retargeting, `l7-inject-conf.json` to no specs, with the inject seam denying the requests it would have injected into, for the hosts the last good conf named — while a failed or **torn read** is fail-**static**: `l7-rules` and `l7-inject-conf.json` keep the **previous** contents (never a partial list, never `{}`) for one poll and retry on settled bytes, `l7-auth-hosts` alone still emptying. See [docs/authproxy.md](authproxy.md).

The order is chosen for the **widening** direction and it is not symmetric. The mitm addon re-reads `l7-rules` on every request, so a render that *removes* an allow (a git-grant revocation) reaches it only after the inject pass has enumerated both secret stores, reconciled the credential grants and `fsync`ed four files — the old, wider rule stays enforceable at the addon for that span. The trade is deliberate: a widening interleave forwards a real placeholder credential upstream and costs a user their login, a narrowing one keeps a stale allow for the tail of one render, bounded by the L7 proxy reloading only on the `SIGHUP` the render sends after all six writes. If the narrowing side ever matters, the shape is to write `l7-rules` twice — the intersection of old and new first, the full new set last.

`l7-inject-conf.json` has **two writers**, and that is a content contract, not a tearing one (the second writer publishes with `mv`). After the boot render, `cogbox-launch.sh` reads the file back, appends the **harness** inject specs (`gen_inject_conf`: the host-side cred file, its `token_path`, the OAuth refresh block and the redaction stub, gated on `INJECT_ACTIVE`) and republishes the union with `jq -s add`, harness **last** so it wins a host collision at the addon. Those specs are projected from the launcher's shell state — nothing in `config.json` or the secret store names them — so the renderer cannot reproduce them. A live render that replaced the file would therefore strip them while leaving `l7-rules`' terminate-allow and the `:443` funnel standing, which is the exact fail-open above: the guest's redacted placeholder goes upstream and `claude-code` reports an expired login. So the renderer distinguishes the two cases (`reload.ForeignSpecs`): the **boot** render (`__render-rules`) *replaces* the file — it is the authoritative reset, and the launcher merges the current harness half back on top immediately after, whereas a carried-over spec from the previous boot would outlive the credential it names — while **every live render** (`rules`/`remap`/`l7`/`plugin` hot reload, `secret reload -n`, `l7 authpolicy replace`) *preserves* every element it did not author, appended last. Provenance is a stamp: each rendered spec carries `"origin": "render"`, so the render still owns and replaces its own elements (dropping a plugin spec or unbinding a secret withdraws the injection as before) and everything unstamped is carried over verbatim (with one exception, an upgrade belt: an unstamped spec whose `cred_file` points *into* the secret store is ours too — only the renderer emits one — so a conf written by a cogbox older than the stamp does not pin a stale spec on its host) — never added to `l7-inject-hosts`, never a terminate-allow, and never granted a credential (only a store path the render itself resolved can be granted). One **known behaviour change** comes with this, under the operator override `COGBOX_L7_INJECT_CONF` (`rules/main.zig`): the launcher computes `l7-inject-hosts` from the override conf, and because a live render now rewrites that file from its own rendered spec set, the next render resets it to the config-rendered set. Kept deliberately, because the direction is **fail-closed** — plain-HTTP egress to an override-only host stops being routed through the injector, so the guest's placeholder goes upstream and the provider 401s rather than a real credential being stamped onto a host the render does not know about. The override conf itself, at its own path, is never touched, so TLS injection for those hosts is unaffected; an operator who wants the plain-HTTP route back names the host in the instance config as well.

`netfilter-rules` is the one deliberate **exception** to the atomic write. passt's LD_PRELOAD shim opens it once, before seccomp is applied, and every `SIGUSR1` reload afterwards is `lseek`+`read` on that held fd — it cannot `open()` again — so renaming a new file over the path would leave the shim reading the unlinked old inode forever and a rule **narrowing** would silently never reach the guest. It stays truncate-in-place. Its second reader, the L7 proxy, *does* open by path and so can read it mid-truncate (its reload flag is set by a signal it may consume while a later, overlapping render is writing). That reader therefore carries the fix the writer cannot: `l7proxy`'s `readPolledInto` uses the same polled shape as every other reader of these files — stat → read → re-stat over `(mtime_ns, size)` on the open fd — and **discards** the read when the key moved, keeping the CIDR set it already installed and re-raising its own reload flag so the next accept-loop iteration retries on settled bytes. It discards a **zero-length** read the same way when the set it holds came from a file that had content, because a reader landing wholly inside the truncate sees a stable `(t, 0)` and would otherwise install deny-all. That refusal is deliberately not permanent: an instance whose rules legitimately narrow to nothing renders an empty `netfilter-rules`, so the second consecutive empty read carrying the **same** key is taken as settled and installed — a render cannot hold one `mtime_ns` across two reads. Both refusals are fail-**static** for a bounded window, not a stall: the accept loop's `poll(…, 1000)` bounds one retry at ~1s, so a discarded read costs up to a second of the previous CIDR set standing and a settled narrowing-to-empty (refuse, then install) up to ~1–2s. What the reader does **not** defend is a *settled* file larger than its 16 KiB read buffer — that is a pre-existing cap, not a tear, and the key cannot tell the two apart; it is refused once with a warning and then installs **truncated**, because refusing it forever would pin the previous, wider set with nothing left to clear it. Render **serialisation** is no longer what bounds this window.

### Where the two-writer contract actually applies

The `ForeignSpecs` split above is exercised on the **VM path only** (`gcp`/`k8s`, the backends that run `cogbox-launch.sh`). On the **container** backend the enforcer is the **single writer** of `l7-inject-conf.json`: `cogbox-enforce.sh` renders through `cogbox __render-rules` — pinned to `reload.boot_foreign_specs` = `.replace` — at start and again on every courier reconcile, and it has no `gen_inject_conf` half, so it never merges a harness spec. `cogbox secret reload` cannot address that file either: it renders into `paths.instanceRuntime` (`<base_runtime>[-<name>]`, `zig/src/cli/paths.zig`), while the enforcer's runtime is the enforcer pod's own `/run/cogbox-rt` emptyDir. There is therefore no second writer for the preserve leg to preserve from on the container path today, which is exactly why the `.replace` there is correct rather than merely tolerated.

**The rule if that ever changes.** If a container-side harness merge — or any other second writer of `l7-inject-conf.json` — is added, its live re-render call site must render with `.preserve` (`rules.renderFiles(…, .preserve)`, the shape `zig/src/rules/main.zig:137` already uses for hot reload), **never** `__render-rules`/`.replace`. A live `.replace` alongside a second writer strips that writer's specs while leaving `l7-rules`' terminate-allow and the `:443` funnel standing — the precise fail-open the `writeL7Inject` docstring exists to describe, and the one shape unit tests on the VM path will not catch for you.

### A cogworx-managed box grows no foreign spec

A foreign spec survives a live re-render only when its `cred_file` lives **outside** the secret store: `readForeignInjectSpecs` deliberately drops an unstamped spec whose `cred_file` points *into* the store as "ours, unstamped" (the image-skew belt above). Under cogworx, nothing produces such a spec on the `gcp` path in the first place. `cogbox-launch.sh`'s `inject_specs_deduped` emits a harness spec only when the **host-side** cred file exists (`[ -f "$cred" ] || continue`), and cogworx's stub staging writes the credential into the **guest** overlay rather than onto the VM host, so `gen_inject_conf` returns `[]` and the merged union is the rendered set alone. The spec carrying `api.anthropic.com` on such a box is the **render-origin** one resolved from the secret store, and the absence of a harness entry in `l7-inject-conf.json` is the designed steady state, not a missing merge — the launcher's two-writer merge is a bare-cogbox (host-login) behaviour.
