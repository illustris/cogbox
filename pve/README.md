# cogbox on Proxmox VE (nested v0)

This directory builds the cogbox **host half** as a NixOS image that boots as a Proxmox VE (QEMU/KVM) virtual machine and runs the same nested microVM guest the GCE backend runs. It is the gcp backend's shape on Proxmox: one VM per cogworx instance, linked-cloned from a template baked from this image.

The central design choice: `../gce/cogbox-host.nix` is imported **unchanged**. The GCE host half talks to the outside only through the GCE metadata server at `169.254.169.254`, so this tree provides a local emulator of the subset it uses. Control-plane input arrives in an SMBIOS blob; guest output leaves through a file that cogworxd reads with the QEMU guest agent. Everything else here is platform glue.

All addresses, names and keys in this directory are fictional (RFC 5737 / RFC 2544 ranges, example keys). Site values (resolver, control-plane CIDRs, internal ranges, control CA) belong in an operator's bake module, never in this tree.

## Files

| File | What it is |
|---|---|
| `pve-host.nix` | Entry module. Imports `../gce/cogbox-host.nix` and the modules below; declares `cogworx.pve.*`; holds the publish gates. |
| `platform.nix` | Networking (dhcpcd on `eth0`), sysctls, the qemu-ga RPC allow-list, nested KVM check, virtio disk serials, the serial-log file and its cap timer. |
| `metadata.nix` | The emulator package, its loopback address, socket and service, and the ordering edges every metadata client needs. |
| `metadata/cogworx_pve_metadata.py` | The emulator (stdlib Python). Its module docstring is the normative description of the blob decoder and the HTTP subset. |
| `hostname.nix` | Sets the hostname from the blob before dhcpcd and consul start. |
| `self-refresh.nix`, `self-refresh.sh` | Refreshes cogbox's write-once `bindAddr` / `selfAddrs` to the current DHCP address before the supervisor launches. |
| `floor-site.nix`, `floor_render.py` | The site floor: nft table `inet cogworx_pve_floor`, rules 4a and 4 (rule 4 names the nix build users only), rendered and validated at build time. |
| `image.nix` | The qcow2 template disk (`config.system.build.pveImage`). |
| `mkfs-nodiscard.nix` | The mke2fs profile for the two host units that format a disk: the package default without the whole-device discard (see [Disks: no discard at format time](#disks-no-discard-at-format-time)). |
| `upgrade/` | In-place system upgrades (see [System upgrades](#system-upgrades)): `cogworx_pve_upgrade.py` (the tool), `package.nix` (it as one executable file), `module.nix` (what every system generation carries), `grub-guard.cfg` (the GRUB guard) and `compat_doc.py` (the compat doc builder). |
| `eval.nix` | Compatibility shim over the flake's `lib.mkPveHost`, with its old signature. |
| `checks.nix` | The checks (see below). |
| `testdata/bootcfg-v1.json` | Canonical boot-config vectors, shared byte for byte with the cogworx Go encoder. |
| `testdata/grubcfg-v1/`, `testdata/grubenv-v1/`, `testdata/closure-digest-v1.json` | grub.cfg parse vectors (each `*.cfg` with its expected parse as `*.json`; `vm-*` are install-grub.pl's real output captured in `upgrade-vm`), real 1024-byte grubenv blocks from the same runs plus hand-made invalid ones (`*.env` with their parse as `*.json`, `null` when invalid), and the closure digest vector, shared with cogworxd's parsers. |
| `tests/` | Emulator and upgrade-tool unit tests, the floor, self-refresh, hostname, serial-cap, qemu-ga, route-coverage and mke2fs-discard tests, and the upgrade VM test (`upgrade-vm.nix`, its script `upgrade_vm.py` and the power-cut driver `upgrade_crashat.py`). |

The flake exports:

| Output | What it is |
|---|---|
| `nixosConfigurations.cogbox-x86_64-pve` | The host system, CA-less and therefore fail-closed: no control certificate is ever accepted, so it is a dev image. `cogworx.pve.release` is null, so it is never an upgrade target. |
| `packages.x86_64-linux.pve-image` | That system's template disk (`config.system.build.pveImage`). |
| `lib.mkPveHost` | `system: { extraModules ? [ ] }:` the host system with the operator's base and site modules (resolver, control CA, floor CIDRs, release) on top. Those modules must evaluate on this flake's nixpkgs. |
| `nixosModules.pve-host` | `pve-host.nix` itself. It needs the specialArgs `self`, `inputs` and `system`, as `mkGceHost`'s module does; `lib.mkPveHost` is the supported way to build it. |
| `checks.x86_64-linux.pve-<name>` | Every check in `checks.nix`, the heavy ones included. |

```sh
# evaluate the system (builds nothing)
nix eval --raw .#nixosConfigurations.cogbox-x86_64-pve.config.system.build.toplevel.drvPath

# build the CA-less template disk
nix build .#pve-image

# build a template disk with an operator site module on top
nix build --impure --expr '((builtins.getFlake "/path/to/cogbox").lib.mkPveHost "x86_64-linux" {
  extraModules = [ ./site.nix ];
}).config.system.build.pveImage'

# run one check, or every cheap one
nix build -L .#checks.x86_64-linux.pve-unit-graph
nix build --impure -f pve/checks.nix all
```

`eval.nix` (`import ./pve/eval.nix { extraModules = [ ... ]; }`) and the standalone `nix build --impure -f pve/checks.nix <name>` remain for compatibility; both go through `lib.mkPveHost`.

## Inbound: the SMBIOS boot config (control plane to VM)

cogworxd writes the VM's `smbios1` while the VM is **stopped**, in one digest-carrying config update. There are two shapes:

| When | `smbios1` |
|---|---|
| Provision (identity only) | `uuid=<owner-uuid>` |
| Every start | `uuid=<owner-uuid>,base64=1,serial=<base64(blob)>` |

- `uuid` is the instance's owner UUID, minted by cogworxd. A clone regenerates it, so it is stamped at Provision. It is served lowercased as `instance/id`, and systemd seeds the machine id from it.
- The blob is ASCII `application/x-www-form-urlencoded`, keys in byte order, version `v=1`. Go encodes it with `url.Values.Encode()`; the emulator decodes it with `parse_qsl(strict_parsing=True, keep_blank_values=True, max_num_fields=32)`.
- The guest reads it from `/sys/class/dmi/id/product_serial`, either raw or base64 (both forms are accepted; see the emulator docstring for why the classification is unambiguous).
- A duplicate key, `v` other than `1`, or any parse or grammar failure rejects the **whole** blob. A rejected blob is served exactly like no blob: attributes return 404 and `instance/id` returns 200. Unknown keys are ignored and logged by name.

| Code | Served as `instance/attributes/...` | Value |
|---|---|---|
| `v` | (none) | `1`, required |
| `n` | `cogworx-start-nonce` | lowercase UUID |
| `i` | `cogworx-instance` | `[a-zA-Z][a-zA-Z0-9-]{0,63}` |
| `p` | `cogworx-ssh-principal` | `[A-Za-z0-9._-]{1,81}` |
| `K` | `cogworx-ssh-ca-pub` | base64url (unpadded, 68 chars) of the ed25519 SSH wire key; served as `ssh-ed25519 <std-base64>` |
| `h` | `cogworx-hostname` | `[a-z][a-z0-9-]{0,7}[0-9]{1,9}` (the VM name, `<prefix><vmid>`) |
| `c` / `m` | `cogworx-vcpu` / `cogworx-mem-mb` | digits |
| `w` | `cogworx-network` | `rules` or `none` (`full` is refused) |
| `g` | `cogworx-guest-resolver` | dotted-quad IPv4 |
| `M` | `cogworx-maintenance` | flag (empty value, served as an empty 200) |

`R`, `D` and `s` are reserved and never emitted in v1. `cogworx-self-addrs` is never served, so the gce floor and supervisor fall back to `network-interfaces/0/ip`. The worst-case `smbios1` is 498 of PVE's 512 characters. `testdata/bootcfg-v1.json` pins it, along with every rejection.

## The emulator's HTTP subset

`http://169.254.169.254/computeMetadata/v1/...`, bound on `169.254.169.254/32 scope host dev lo` by socket activation.

| Method | Path | Response |
|---|---|---|
| GET | `instance/id` | 200 owner UUID |
| GET | `instance/attributes/{k}` | 200 value, or exactly 404 when absent |
| GET | `instance/network-interfaces/` | `0/\n` once `eth0` has a usable IPv4 (waits up to 8 s), else 503 |
| GET | `instance/network-interfaces/0/ip` | `eth0`'s IPv4 (never link-local), else 503; other indexes 404 |
| GET / PUT / DELETE | `instance/guest-attributes/{ns}/{key}` | GET 200/404; PUT at most 1024 bytes and at most 64 keys (413 beyond); DELETE is idempotent |

Every request needs exactly one `Metadata-Flavor: Google` header and must come from a socket that is still open and owned by uid 0. A client that sends its request and then closes its socket is refused: the kernel reports that orphaned socket as uid 0 with inode 0, so it identifies nobody. A request with `X-Forwarded-For` gets 403. A query string, `%` or `..` gets 400. Other methods get 405. Every response carries `Metadata-Flavor: Google`. `tests/test_route_coverage.py` extracts every access that the realized unit scripts make, `gce/supervise.sh` included, and replays each one against the emulator with the script's own curl flags.

## Outbound: files cogworxd reads (VM to control plane)

cogworxd reads both files with the QEMU guest agent (`agent/file-read`), and reads the address with `agent/network-get-interfaces`.

| Path | Content |
|---|---|
| `/run/cogworx/guest-attributes.json` | `{"v":1,"boot_id":"...","gen":N,"sys":"<booted toplevel>","attrs":{"cogworx/vm-host-key":"<nonce> ssh-ed25519 ...","cogworx/ready":"<nonce> ok bp=1","cogworx/boot-proof":"<nonce> bp=1 hb=... gb=... pool=ok sf=1","cogworx/boot-error":"<nonce> <text>"}}`. Mode 0600, rewritten atomically on every guest-attribute mutation, and reset on reboot. `cogworx/ready` appears only once the hosted guest's sshd has started in this launch: `gce/supervise.sh` waits for the guest's boot stamp (written by `cogbox-boot-stamp.service`, after its sshd) as well as its host key. The `bp=` tail and `cogworx/boot-proof` carry the image's protocol values from `gce/protocol.nix`; the proof is `<nonce> bp=1 err=stamp-path` when the supervisor could not clear the stamp path, and readiness then rests on the host key alone. cogworxd compares only the nonce half of `cogworx/ready` and does not read `cogworx/boot-proof`. `sys` is the booted system (`realpath /run/booted-system`), read once when the emulator starts and absent when unknown; cogworxd ignores it today, and the upgrade resolver will read it. |
| `/run/cogworx/serial.log` | The classified `cogworx: ...` lifecycle lines that the supervisor writes (on GCE they go to serial port 1). Pre-created 0600. When it passes 256 KiB, a timer trims it to the last 128 KiB, starting on a line boundary. |

`/run/cogworx` is created 0700 by tmpfiles.

## VM shape the image expects

| Item | Contract |
|---|---|
| Boot disk | `virtio0`, SeaBIOS, GRUB on `/dev/vda`, root by label `nixos`. The partition and filesystem grow on boot. The boot disk is also the nix store. |
| State disk | `virtio1`, `serial=cogworx-state`, found at `/dev/disk/by-id/virtio-cogworx-state` |
| Guest disk | `virtio2`, `serial=cogworx-guest`, found at `/dev/disk/by-id/virtio-cogworx-guest` |
| NIC | one virtio NIC, `eth0` (`net.ifnames=0`), DHCP with a hardware-address client id |
| CPU | nested VMX (`cpu=host`). `cogworx-pve-kvm` fails loudly, with a serial line, when `/dev/kvm` is absent. |
| Console | `serial0`, `console=ttyS0` (kernel console and break-glass getty, not the cogworx log) |
| Agent | `agent=1`. qemu-ga runs with `--allow-rpcs=` set to exactly `guest-sync`, `guest-sync-delimited`, `guest-ping`, `guest-info`, `guest-network-get-interfaces`, `guest-file-open`, `guest-file-read`, `guest-file-close`, `guest-shutdown`, `guest-get-osinfo`, `guest-get-host-name`, `guest-get-time` and `guest-fsfreeze-status`. There is no exec and no file-write. |

Residual: the allow-list removes exec and write, not path scope. qemu-ga runs as root, and `guest-file-open` (which file-read needs) takes any path:

- Any PVE principal with `VM.GuestAgent.FileRead` on the VM, cogworxd's own scoped token included, can read any guest file as root.
- Any principal with `VM.GuestAgent.FileWrite` or `VM.GuestAgent.Unrestricted` (or root on a PVE node, which reaches the agent socket directly) can create or truncate any file through `guest-file-open` with mode `w`. Observed live: a file-write that the allow-list refused still left a 0-byte file behind, because the open that created it is allowed.

## Disks: no discard at format time

PVE gives every drive of a sandbox VM QEMU IO limits, and QEMU charges discarded bytes against the drive's write-bandwidth limit. By default mke2fs discards the whole device before it formats it. At a 20 MB/s write limit that takes about 27 minutes for the 32 GiB state disk, about 14 for the 16 GiB store volume on the guest disk and about 40 for the pool, while the format units time out after 600 s. Measured on a live first boot: `cogworx-state-disk` and `cogworx-guest-disk` were both killed at 600 s after about 26 ms of CPU, each having discarded about 12 GiB. The state disk was then not mounted, so self-refresh and the supervisor refused to start, and the guest-disk unit refused to re-make the store filesystem in the same host boot. `cogworx-guest-disk` re-formats the store volume on every host boot, so this is not a first-boot failure only: without the fix, no PVE boot gets a bootable guest.

`mkfs-nodiscard.nix` sets `MKE2FS_CONFIG` on those two units, and on no other, to a profile built from the e2fsprogs they run: its compiled-in `mke2fs.conf` plus `discard = false` under `[defaults]`. Nothing in `gce/` changes, so GCE is unaffected. The nested guest formats no device, so it needs nothing.

Skipping the discard costs nothing at first format, because a freshly allocated volume on thin storage such as Ceph RBD already reads as zeros (the state and guest disks are never linked clones). A block device reports that discard does not zero data, so mke2fs handles the inode tables and the journal exactly as before. The drives keep `discard=on`, so later frees from the guest still reach the storage.

Residuals (asynchronous and throttled, but not boot failures; nothing here changes them):

- The store volume is re-made over the previous boot's blocks without a discard, so those blocks stay allocated in the storage until the guest's fstrim trims them (online discard returns only blocks the new filesystem itself frees). That is bounded by the store volume's size.
- Periodic discards hit the same limits. The host's NixOS `fstrim.timer` (on by default, weekly, and `Persistent=`, so it catches up after a stop that spans the weekly point) trims the free space of the state filesystem (about 27 minutes at 20 MB/s) and of the boot disk. The guest mounts both of its filesystems with `discard` and runs its own weekly fstrim, all against the guest disk's single limit. Turning the host timer off would also give up the boot disk's reclaim, so that is left as a decision. The guest side lives in `flake.nix`.

## Units and ordering

| Unit | Role and edges |
|---|---|
| `cogworx-pve-hostname` | `DefaultDependencies=no`. Sets the hostname from `--print-attr cogworx-hostname` (read directly from DMI, no HTTP), falling back to `cwx-` plus the first 12 hex digits of the SMBIOS UUID with its dashes removed (`cwx-<12 hex>`, for example `cwx-0a1b2c3d4e5f`: the dashes are removed so all 12 characters are hex digits). It never uses the instance name. `Before=` `dhcpcd`, `consul` and `network-pre.target`. |
| `cogworx-pve-md-addr` | `DefaultDependencies=no`. Runs `ip addr replace 169.254.169.254/32 scope host dev lo`, `Before=` the socket and `sockets.target`. |
| `cogworx-pve-metadata.socket` | `ListenStream=169.254.169.254:80`, `FreeBind=yes`. `Requires=` and `After=` md-addr. |
| `cogworx-pve-metadata.service` | The emulator, socket-activated, as root. |
| `cogworx-control-principal`, `cogworx-attr-scrub`, `cogworx-floor`, `cogworx-resolver-deadline`, `cogworx-cogbox-log` (gce/) | Also `After=` and `Requires=` the socket. The principal fetch is one-shot, so the address must already be on lo. |
| `cogworx-pve-self-refresh` | `After=` network-online and the socket; `RequiresMountsFor=` the state disk; `Before=` the supervisor. |
| `cogworx-pve-floor` | Loads the site floor, then verifies rule 4a against the live emulator socket (root connects, while `nobody` and a nix build user are dropped) and rule 4's hop block on the first triple's mitmproxy port (a nix build user's connect is dropped, root's is not). `Before=` sshd and the supervisor, and `RequiredBy=` sshd: fail closed by policy. A VM whose floor fails to load or verify is unusable anyway, because the supervisor requires the floor, so it is left without sshd too (the serial console stays as break-glass). |
| `cogworx-supervisor` (gce/) | Also `After=` the emulator (its `ExecStopPost` unpublishes readiness and the boot proof at shutdown), `After=` and `Requires=` `cogworx-pve-floor`, and `After=` and `Wants=` `cogworx-pve-self-refresh`. |

Clients depend on the socket, never on the emulator service: the emulator is socket-activated and restarts on failure, so a crashed emulator is re-activated by the next request and its restart does not propagate to any client.

Every metadata client runs as root. The emulator answers only uid 0, and floor rule 4a drops other uids. `floor-site.nix` asserts that none of them sets `User=` or `DynamicUser=`.

## Network

- No NixOS firewall. This is forced, and asserted.
- DHCP on `eth0` only, with `wait ipv4`, `nohook hostname`, `nohook resolv.conf`, `noipv4ll`, `noipv6` and `clientid`.
- NixOS still sends the hostname to the DHCP server. Because `cogworx-pve-hostname` runs first, that hostname is the control plane's VM name.
- DNS is pinned to `cogworx.gce.vpcResolver` (see cogbox-host.nix). On PVE that must be the site's resolver: nothing answers DNS on `169.254.169.254` here.
- IPv4 only on the shared segment: `eth0` IPv6 is disabled, and loopback keeps `::1`.
- The GCE network-security sysctls apply, plus `arp_ignore=1` and `arp_announce=2`, so `eth0` never answers ARP for the loopback-scoped metadata address.
- ARP silence is not isolation. Linux uses the weak host model: a frame a neighbour sends to this VM's MAC, addressed to `169.254.169.254`, arrives on `eth0` and is accepted for local delivery even though the address is `scope host` on lo. Floor rule 4a's input drop refuses it, its egress drop keeps a `169.254/16`-sourced reply from leaving `eth0`, and the emulator's peer-uid check refuses any client whose socket is not on this VM.

## The site floor (`inet cogworx_pve_floor`)

This is a second nft table beside gce/floor.nix's `cogworx_floor`. A drop in either table is final, so this table can only narrow what the gce floor admits. `floor_render.py`'s docstring has the full reasoning.

- **Rule 4a**:
  - output: `meta skuid != 0 ct direction original ip daddr 169.254.0.0/16 drop`
  - output: `oifname "eth0" ip saddr 169.254.0.0/16 drop`
  - input, first in the chain: `iifname != "lo" ip daddr 169.254.0.0/16 drop`
- **Rule 4** (output), the nix build users only:
  1. `meta skgid nixbld ct direction original ip daddr 127.0.0.0/8 tcp dport { 18043-18090, 18443-18490 } drop`, and the same for `ip6 daddr ::1` (the local hops: the L7 relays' ports, from the launcher's built-in base 18443 and `cogworx.gce.l7PortTriples`, plus any `buildDenyLoopbackTCP` ranges)
  2. `meta skgid nixbld ip saddr 127.0.0.0/8 tcp sport { <the same ports> } drop`, and the same for `ip6 saddr ::1` (a build user may not answer from a hop port either)
  3. `meta skgid nixbld ct direction original ip daddr 127.0.0.0/8 udp dport { <buildDenyLoopbackUDP ports> } drop`, and the same for `ip6 daddr ::1` (rendered only when the bake lists UDP ports)
  4. `meta skgid nixbld ct direction original meta nfproto ipv4 fib daddr type { broadcast, multicast } drop` (no broadcast or multicast)
  5. the exact `infraAllow` accepts
  6. `meta skgid nixbld ct direction original ip daddr @infra4 drop`

  Rule 4 keeps the nix build users (`nixbld`, the daemon's builders; only fixed-output builds share the VM's network namespace) off the site's internal ranges, except the exact `infraAllow` sockets. Root is outside it by design (see the residual below). Replies still pass through the direction scoping (see the conntrack-direction residual below).

  The local hops are loopback listeners that act for any local client, authenticate none, and send requests to an address the client picks. cogbox's own are the trusted half's L7 relays, all on 127.0.0.1 under the L7 proxy uid: l7proxy's two front doors (the guest's 443 and 80 funnel targets, the base and `+1`; SOCKS5 carrying the original address), the mitmproxy SOCKS5 terminate hop (`+2`; injects the owner's credentials host-side) and the auth proxy (base `- 400`; stamps the owner's git credential). The L7 proxy uid now reaches internal addresses, so without this block a build user could reach them through it. The ports cover the same window gce/floor.nix rule 3 admits the funnel over: `l7PortTriples` triples from the base (cogbox slides the base by 3 when a triple is taken) and the auth band 400 below them.

  The base is the launcher's built-in 18443 (`cogbox-launch.sh`, mirrored by `zig/src/filter.zig`'s `l7_default_base`); no option moves where the relays listen. `cogworx.gce.l7PortBase` only mirrors it, for gce/floor.nix's funnel window and probes, so `floor-site.nix` asserts on every image that the option equals 18443, and that the `l7PortTriples` window ends inside the port range. `checks.nix` reads the base and the 400 offset back from the launcher's sources and compares the realized ruleset against them.

  A bake's own agents of the same kind go in `cogworx.pve.floor.buildDenyLoopbackTCP`. One example is a service-discovery agent whose local HTTP API has no ACLs: an HTTP health check registered through it is a request the agent sends, to any URL, and the response comes back in the check's output. A bake that composes such an agent must list its ports there. `floor-site.nix` sorts the L7 bands and these ranges together and merges any that overlap or touch. An agent that takes unauthenticated datagrams on loopback, such as a gossip agent's UDP port that can be made to probe or send to the addresses a datagram names, goes in `cogworx.pve.floor.buildDenyLoopbackUDP` (sorted and merged the same way). Its drops cover `127.0.0.0/8` and `::1` and have no source-port pair, because nothing probes a UDP port to place a relay.

  The source-port pair keeps a build user from steering the base. Before it starts the relays, the launcher probes the base, `+1`, `+2` and base `- 400` with a loopback connect as root. It slides past any triple where one of them answers, whoever is listening, and writes the new base into the instance's `config.json`, so the slide outlasts that launch. A build user listening in the window could otherwise push the relays to a base outside the hop drops. With the pair, that listener's SYN-ACK never leaves. The probe times out, which the launcher reads as a free port, and the relay's own bind then fails. The pair carries no direction scoping, because that SYN-ACK is a reply.

  The pair matters a second way. Only l7proxy's bind failure (base, `+1`) aborts the start. When mitmproxy (`+2`) or the auth proxy (base `- 400`) cannot bind, the launcher only warns and the sandbox runs, while l7proxy still hands terminate-tier hosts to `127.0.0.1:<+2>` and mitmproxy still sends its git retarget to `127.0.0.1:<base - 400>`. A build user's listener holding either port would then answer the relays' own connections, and the pair drops its SYN-ACK to them just as it does to the probe's. So the pair must stay, without direction scoping.

  Nor may a build user send to a broadcast or multicast address. Such a datagram reaches every neighbour on the segment, and an answer is a flow the neighbour opens: a neighbour inside the internal ranges that answers a broadcast or a multicast query opens a flow to the build user's port, and the build user's next datagram to it is that flow's reply, which the direction scoping lets past the `@infra4` drop. A broadcast also loops back to every local wildcard listener without using `127/8`, so the loopback UDP drops alone would not stop a datagram to a wildcard UDP agent. The drop keys on the type the routing table gives the destination (`fib daddr type`), not on a fixed address set: besides the limited broadcast `255.255.255.255` and every multicast group, it covers each local segment's directed broadcast, including the one for the `eth0` segment DHCP hands out, which the floor cannot name at build time and which `@infra4` covers only when the segment is listed there. `floor-site.nix` loads `nft_fib_inet` at boot for it. IPv4 only, because `eth0` carries no IPv6.

  The host DNS forwarder (127.0.0.53:53) is not a hop and stays reachable; passt's guest forwards are bound at the VM's own address, which gce/floor.nix rule 2 already closes to every uid. Loopback as a whole is not closed to the build users, because a fixed-output build may talk to itself over loopback on ephemeral ports.

**No internal-range egress filter for the guest and the L7 proxy** (decision 2026-10-22, GCE parity). The table names neither the passt nor the L7-proxy uid. What the guest and the L7 proxy may reach is decided by the sandbox's own network rules, as on GCE: the seeded RFC1918, CGNAT, link-local and bogon denies, enforced by the passt shim and by l7proxy. Allows are admin-gated in cogworx. An approved L4 allow or L7 name allow opens a destination, and an L7 allow supersedes the L4 denies while l7proxy's hard floor (loopback, `0/8`, link-local and the VM's own addresses) stays. The nix build users stay blocked (rule 4), which is stricter than GCE, where nothing restricts them. Rule 4a is stricter than GCE too, for every non-root uid: gce/floor.nix rule 1 drops only the passt uid towards link-local. gce/floor.nix's rules 1-3 are unchanged, and full network mode is refused on PVE (the metadata emulator rejects a boot config that asks for it).

| Option | Meaning |
|---|---|
| `cogworx.pve.floor.infraDenyCIDRs` | The site's internal ranges (`@infra4`), closed to the nix build users |
| `cogworx.pve.floor.infraAllow` | `[{ address, protocol, port }]` exact exceptions for the nix build users, one host each |
| `cogworx.pve.floor.buildDenyLoopbackTCP` | `[[lo, hi] ...]` loopback TCP port ranges closed to the nix build users beside the L7 relays' own (default `[]`): the ports of a bake's agents that act for unauthenticated local clients, such as a service-discovery agent's local HTTP API. Each entry is a `[lo, hi]` pair with `1 <= lo <= hi <= 65535` (refused at evaluation otherwise). |
| `cogworx.pve.floor.buildDenyLoopbackUDP` | `[[lo, hi] ...]` loopback UDP port ranges the nix build users may not send to (default `[]`): the ports of a bake's agents that take unauthenticated datagrams, such as a gossip agent's UDP port. Same entry shape and refusal as `buildDenyLoopbackTCP`. |
| `cogworx.pve.floor.controlPlaneCIDRs` | Optional (default `[]`). Not a floor input: the upgrade compat doc's `controlPlaneCIDRs`, where cogworxd's control connections come from as the VM sees them (upgrade compat rule ii in [docs/pve-system-upgrade.md](../docs/pve-system-upgrade.md): cogworxd checks that every control-plane egress address is covered by these CIDRs). Each entry must be an IPv4 address or a canonical IPv4 CIDR, asserted on every image. |

The build refuses a CIDR that is not IPv4, is not canonical, is wider than `/8`, or overlaps `127/8`, `169.254/16` or `0/8`. It also refuses an `infraAllow` address that is a range rather than one host (a bare address or a `/32`), a renderer spec key it does not know (the removed `controlPlaneCIDRs`, `passtUser`, `proxyUser` and `moshUDP` keys included), an empty, unordered or overlapping list of TCP hop port ranges, and an unordered or overlapping list of UDP ones (`floor-site.nix` merges before it renders, so those are composer bugs). Evaluation refuses a `cogworx.gce.l7PortBase` other than the launcher's 18443 and an `l7PortTriples` window that ends past port 65535, both naming the option, on every image.

**No ingress filter** (decision 2026-10-21). The internal network is trusted, so the floor filters inbound traffic only with rule 4a's link-local drop. Host sshd on 22, the guest SSH forwards on 2222-2237, the in-guest app relay on 8080-8095 and mosh on 60000-60031, all on `eth0`, are reachable from every internal host, and each relies on its own authentication: key-only sshd, the relay key, and the mosh session key.

Residuals, all accepted under the trusted-internal-network decision:

- The guest's internal-range denial rests on the passt shim and l7proxy, with no kernel backstop, as on GCE. The seed is written once, at first init: an instance's rules are whatever its config has held since, so a later change to the seed does not reach existing sandboxes. On a shared site network, an approved internal allow, or an L7 wildcard whose DNS others control, reaches whatever sits there, hypervisor and storage hosts included.
- Root is outside rule 4: the trusted half, nix-daemon substitution from the site cache and the control channel all run as root. So root-run plugin evaluation, and eval-time fetches of attacker-chosen URLs (fetchers that run in the evaluator rather than in a `nixbld` builder), can reach `@infra4` (on GCE nothing restricts root either).
- Rule 4 keys on conntrack direction: it is a no-new-flows rule, not a peer filter. Any address that sends to the VM first can be answered by a nix build user from the port it sent to. The broadcast and multicast drop keeps a build user from soliciting that first packet from the segment.
- The hop block covers the `l7PortTriples` window. The launcher slides the base by 3, up to port 65000, past every triple where the base, `+1`, `+2` or base `- 400` answers its root loopback probe at launch. Any listener counts: root's, another service's, or another uid's. Only the build users' are hidden from the probe (the source-port pair). The slid base is persisted in the instance's `config.json`, so it holds for later launches too. A base slid past the window leaves that triple's hops open to the build users, and it also leaves that triple outside gce/floor.nix rule 3's funnel accept, which already breaks the guest's L7 egress. A build user holding a hop port cannot cause a slide. If it holds l7proxy's base or `+1`, l7proxy cannot bind and the start aborts (fail closed). If it holds the mitmproxy hop (`+2`) or the auth port (base `- 400`), that relay's bind fails with only a warning: the sandbox runs with terminate-tier hosts and migrated git providers refused, and the source-port pair keeps the build user's listener from answering the relays' connections to that port. Either way it would need a build running during the launch, because the nix daemon kills a build user's leftover processes when its build ends.
- A loopback agent a bake adds that acts for unauthenticated local clients is covered only when the bake lists its ports in `buildDenyLoopbackTCP` (TCP) or `buildDenyLoopbackUDP` (UDP). Nothing detects one the bake did not list. The broadcast drop keeps a listed UDP agent from being reached by way of a broadcast address (the limited one or a local segment's); an agent bound to the VM's own address is closed to every uid by gce/floor.nix rule 2.
- Rule 4 keys on the build group. Builders the daemon runs outside it (`auto-allocate-uids`, which these images do not enable) escape all of its drops.

**Publish gates** (asserted in `pve-host.nix` whenever the image trusts a user CA: `cogworx.gce.controlCAPublicKey` or `cogworx.gce.extraTrustedUserCAKeys` is set, or anything else makes sshd's `TrustedUserCAKeys` file non-empty). No gate has an escape hatch except console autologin, which is an explicit operator opt-in:

- `infraDenyCIDRs` must be non-empty (rule 4's build-user block).
- `cogworx.gce.vpcResolver` must not be link-local. `allowMetadataResolver` does not apply on PVE.
- `services.openssh.authorizedKeysCommand` must be `none`.
- `services.getty.autologinUser` must be null, unless the bake sets `cogworx.pve.allowConsoleAutologin = true`. The opt-in produces no warning.

Residual, with that opt-in: console autologin on `ttyS0` gives a root shell, the trusted half, to every PVE principal with `VM.Console` on the VM and to root on its node.

Asserted on every image, CA-baked or not (`platform.nix`): `services.cloud-init.enable` is false (it is forced off, because a Proxmox base profile turns it and systemd-networkd on), `systemd.network.enable` is false (dhcpcd on `eth0` is the network stack), and `networking.hostName` is empty (`hostname.nix` owns it).

## System upgrades

cogworxd can move a sandbox VM to a newer system generation in place: it fetches the target into the VM's store, arms GRUB's one-shot entry for one trial boot, and then commits or falls back. [docs/pve-system-upgrade.md](../docs/pve-system-upgrade.md) is the full contract; in short:

- **The tool.** Every system generation ships `cogworx-pve-upgrade` at `<toplevel>/sw/bin/cogworx-pve-upgrade` (stdlib Python, one file run as `python3 -I`). cogworxd runs it by store path as root over the control channel, always the committed system's copy (the previous system's copy for `revert-commit`). Nothing on the VM runs it. Verbs: `proto`, `status`, `closure-digest`, `fetch`, `arm`, `commit`, `abort`, `revert-commit`, `release`.
- **State.** `/var/lib/cogworx-pve-upgrade/txn.json` (the committed system, the rollback, the staged target, the bootloader pin and the newest transaction). Profiles `system`, `system-profiles/cogworx_candidate` (the armed target) and `system-profiles/cogworx_rollback` (the previous system). GC roots under `/nix/var/nix/gcroots/cogworx-pve-upgrade/`: `bootloader`, `staged`, `committed`.
- **GRUB.** The tool only ever runs the BASE image's installer, pinned at its first use and vetted so it never runs `grub-install`; a later system generation contributes only its kernel, initrd and kernel parameters. grubenv variables it owns: `next_entry` (GRUB's one-shot), `cwx_rollback_entry` and `cwx_once`.
- **The guard.** `upgrade/grub-guard.cfg` (`boot.loader.grub.extraConfig`; the module asserts the text is there verbatim, so a composition adds GRUB lines with `lib.mkBefore`/`lib.mkAfter` and never replaces `extraConfig`; lines after the guard must not set `default`, `fallback`, `next_entry` or any `cwx_*` variable, which would silently override the guard's decision, and `lib.mkBefore` is the safe place for lines unrelated to boot selection) reads the SMBIOS serial: under a pending one-shot it lets the candidate boot only when the serial carries `S=c`, falls back to entry 0 when it is a v1 blob without it, and stays inert (fail open) when the serial is unreadable. `S=r` boots the rollback. It records its decision and the boot's start nonce as `cwx_once`. `panic=10 boot.panic_on_fail` make a candidate whose stage 1 fails reboot onto entry 0.
- **The compat doc.** `<toplevel>/cogworx-pve-compat.json`, built from the evaluated configuration: protocol values, the host contract (control CA keys and fingerprints, control-plane CIDRs, control user, host key path, disk devices, interface), substituters and keys, the release (`cogworx.pve.release`; null means not an upgrade target) and the boot loader. The guest and cogworxd check a target's doc against the committed one before a switch.
- **The lock.** `/run/cogworx-pve-upgrade.lock` (flock), created root-owned 0600 at boot by a tmpfiles rule so no other user can open it and hold it; `cogworx-nix-gc` skips a run (exit 75, a success) while the tool holds it.
- **What cogworxd reads.** `status` over the control channel, and over the guest agent `/boot/grub/grub.cfg` and `/boot/grub/grubenv`, which the control plane's file-read allow-list must add, plus the emulator's `sys`.

Only images built from a tree with `upgrade/` are upgradeable in place. A VM cloned from an older template lacks the tool, the guard, the pin source and the panic parameters, and is never upgraded in place.

## Checks

Run with `nix build -L .#checks.x86_64-linux.pve-<name>`, or standalone with `nix build --impure -f pve/checks.nix <name>` (or `all`). The fixture system is a publishable-shaped bake made of fictional values.

| Check | What it proves |
|---|---|
| `unit-graph` | Every ordering edge above, root-only clients, the qemu-ga allow-list line, journal-only streams, `MKE2FS_CONFIG` on exactly the two format units, the nix-gc lock wrapper's exact `ExecStart` and `SuccessExitStatus=75`, and no unit naming the upgrade tool, all on the rendered unit files |
| `config-values` | cogbox's built-in L7 base is one value in all four places it is spelled (`cogbox-launch.sh`'s `INIT_L7`, its `.l7PortBase` fallback, `next_available_ports`' seed plus 3, and `zig/src/filter.zig`'s `l7_default_base`), and the auth proxy offset is one value in its four places (the two `L7_AUTH_PORT` assignments, `next_free_l7_base`'s probe of the auth slot, and `filter.zig`'s `l7_auth_port_offset`). Device paths, serial path, tmpfiles, kernel parameters, GRUB device, sysctls, the hosts pin, DHCP shape, no google or firewall units, and sshd requiring the site floor. It also requires every `cogworx-*` unit to be classified as a metadata client or not, and every metadata client to still run something (an edge-only stub left behind by a removed gce/ unit fails). The two format units carry the no-discard mke2fs profile and no other unit does, `gce/` has no format line beyond the three known ones, and a format unit reduced to a stub trips `mkfs-nodiscard.nix`'s assertion. For upgrades: `panic=10` and `boot.panic_on_fail`, the GRUB guard as `extraConfig`, cloud-init and networkd off, the tool in the system path and the compat doc in the toplevel, the headroom floor equal to `gce/nix-gc.nix`'s (12 GiB) and the 4 GiB reserve, the upgrade lock file pre-created root-owned 0600, no `cogworx.pve.release` on the fixture, and `mkPveHost`'s `system.configurationRevision` (a `lib.mkDefault` of the flake's revision). |
| `publish-gates` | The fixture and the CA-less default both evaluate, and the exported `nixosConfigurations.cogbox-x86_64-pve` IS that default (same toplevel drvPath, no control CA). Each gate trips on exactly its own assertion (a `cogworx.gce.l7PortBase` off the launcher's base, also on the CA-less default, an `l7PortTriples` window past port 65535, console autologin, cloud-init forced on, networkd, a static hostname, a system label outside the upgrade tool's path grammar, an `extraConfig` that replaced the GRUB guard, an `environment.systemPackages` that dropped the upgrade tool and a `system.nixos.distroName` the upgrade tool cannot pin included), and a CA-baked image with no `infraDenyCIDRs` does not evaluate (also with the CA reaching sshd only through `extraTrustedUserCAKeys` or only through the trusted-CA file), nor does a `buildDenyLoopbackTCP` or `buildDenyLoopbackUDP` entry that is reversed or not a pair, and neither does a `controlPlaneCIDRs` entry with host bits or that is not an address (on the CA-less default too). A CA-baked image with an empty `controlPlaneCIDRs` evaluates, fails no assertion and warns about nothing, and one listing a bare address and a `/32` fails no assertion and adds no warning. Autologin with `cogworx.pve.allowConsoleAutologin` fails no assertion and adds no warning, autologin on the CA-less default needs no opt-in, the cloud-init, networkd and hostname gates trip on the CA-less default too, and a default-priority `services.cloud-init.enable = true` (what a Proxmox base profile sets) is forced off and fails nothing, and neither does a distro name other than `NixOS` in the tool's grammar. |
| `floor-warnings` | The floor warns about nothing: the fixture has no warning, and no `controlPlaneCIDRs` shape adds one (the old `@cp` coupling warnings went with rule 4's passt leg), the entries that used to warn and malformed ones included, without throwing. |
| `dhcpcd-conf` | The realized `dhcpcd.conf` |
| `hosts-pin` | The realized `/etc/hosts` pins `metadata.google.internal` |
| `qga-allowlist` | The real qemu-ga, run with the realized flags, enables exactly the allow-list and refuses `guest-exec` and `guest-file-write` |
| `route-coverage` | Every metadata access in the realized scripts is served, with a negative control |
| `floor-site` | On the realized ruleset: rule 4a's input drop is the input chain's only rule (no ingress filter); the only uid selector is rule 4a's root test, the ruleset names neither the passt nor the proxy account and has no `@cp`, and every gid selector is the build group's, original-direction except the hop source-port pair; all four TCP hop drops carry exactly the ports implied by the launcher's base and offset (read from its sources), `l7PortTriples` and the fixture's `buildDenyLoopbackTCP` port, both UDP hop drops carry the fixture's `buildDenyLoopbackUDP` port, and the broadcast and multicast drop, by address type, is there once; and on a variant with out-of-order, overlapping and touching ranges and a 200-triple window, the TCP and UDP ranges reach the renderer merged. Then validator refusals (the removed passt, proxy, mosh and ingress keys and bad TCP and UDP hop port lists included), a golden ruleset and its properties one by one (an empty UDP hop list renders no UDP hop drop), and live probes in a user and network namespace, each with a negative control: rule 4a (root reaches the metadata address and a non-root uid does not, a `169.254/16` source never leaves `eth0`, and a neighbour's datagram for the metadata address arriving over a veth is dropped on input, an internal source included); the guest and the L7 proxy (a non-root uid outside the build group: its TCP flow and datagram to an internal address pass, it still cannot reach link-local, and it reaches every hop port, the UDP agent port and broadcast; a test-only uid drop is caught by the same probes); the nix build users (a TCP flow and a datagram to an internal address are dropped, the `infraAllow` socket is open and the same host on another port is not, both front doors, the mitmproxy hop and the auth proxy port of the first and the last triple, and the fixture's extra port, are dropped on `127.0.0.1`, and on `::1` where the namespace has it, while the ports just outside every band and the DNS forwarder stay open; a build-group listener on a hop port never answers a probe, while one just outside a band does; a datagram to the fixture's UDP agent port on `127.0.0.1` and `::1`, a limited broadcast and a broadcast to `eth0`'s segment, which is outside the internal ranges (each of which, with the drop deleted, loops back to the wildcard agent), and a multicast datagram are dropped; and a reply to an internal address passes; deleting each drop, or its direction scoping, shows the probe catching it); root reaching the internal address, every hop port and the UDP agent; the site floor's own boot verify leg as realized, with a network namespace per account standing in for `setpriv`: it passes on the intact floor, exits 1 naming each probe when nobody reaches link-local, root's hop control is blocked and the build user's hop drop is gone, and skips the build-user probes on an image without a build account; and open ingress (neighbours outside and inside the internal ranges reach sshd, a guest SSH forward, a guest HTTP forward and the mosh range over the veth). With both tables loaded it also runs seven of the gce floor's eight probes: 4 and 5 through gce's own verifier, and 1, 3, 6, 7 and 8 modelled. Probe 2 cannot be modelled with a single mapped uid. |
| `self-refresh` | The union rewrite, no-op cases, failures that are loud and leave the file untouched, and the config lock (with a negative control) |
| `hostname` | VM name from the blob, the dashless `cwx-<12 hex>` UUID fallback, and never the instance name |
| `serial-cap` | The serial log is trimmed to its last 128 KiB on a line boundary, keeps its newest line and mode 0600, and is left alone below the cap |
| `unit-scripts` | Every `cogworx-pve-*` unit program builds (writeShellApplication shellchecks at build time) |
| `metadata-unittests` | The emulator's unit tests and the shared vectors, `sys` included |
| `upgrade-unittests` | The upgrade tool: the argv grammar, the envelope, the grub.cfg and grubenv parsers on the shared vectors (grubenv blocks from the real `grub-editenv`), the closure digest vector, the bootloader pin on the image's real `install-grub.sh`, the guest compat rules, fetch classification on nix 2.34's strings, the state machine on a fake guest with a power cut after every numbered step, a wrong menu after the installer runs of commit, abort, release and the headroom release (a fake installer renders a wrong entry 0, a wrong entry init or an extra cogworx submenu), abort stopping a live fetch worker, a stop outside the realise classified `interrupted`, the fetch launcher waiting (bounded) for its worker to register, abort of a switch txn after the fetch worker's headroom release (before arm and from the trial), abort with the rollback booted over an armed candidate, a second tool process holding the lock making a verb busy, a target without its own tool or with an `append-initrd-secrets` refused before any profile points at it, a rollback a GC collected or invalidated dropped as `rollback_lost`, closed txn ids never reused (the newest and every id `history` still holds), `arm` and `release` refused off the committed system, an unknown `txn.state` or `txn.kind` treated as an unreadable file and never overwritten, a failed closing write of commit, `revert-commit` re-asserting the `committed` root a lost commit flip left behind, `commit` refusing before any step a committed (base) system whose `nixos-version` the rollback entry's title cannot carry, `commit`, `abort`, `revert-commit` and `release` refusing a drifted pin before any step, and the built package. Plus the compat doc builder (every schema key required). |
| `grub-guard-syntax` | `grub-script-check` accepts the guard and rejects a truncated copy (the negative control), and the guard carries the `# cwx-guard-v1` marker |
| `compat-doc` | The fixture's compat doc, built and pinned whole (its key set and every value): the host contract equals the fixture's values, the control CA is decoded and fingerprinted, the protocol values are `gce/protocol.nix`'s, the substituter lists are `nix.settings`' normalized, the boot loader fields name the system's own installer and the guard, and the doc is ASCII and at most 16 KiB |
| `mkfs-nodiscard` | The profile is the package default plus `discard = false` under `[defaults]` and nothing else, derived from the file the units' mke2fs compiles in, and the units' `PATH` resolves `mkfs.ext4` to that mke2fs. Each realized `mkfs.ext4` line of the two units is run on a sparse file under strace: under the default profile it discards (the control, which must), and under the unit's `MKE2FS_CONFIG` it discards nothing. Apart from the discard, `dumpe2fs` shows the same filesystem either way. |
| `eval` | The default and fixture toplevels and the image evaluate |
| `offline-closure` | **Not in `all`**, because it builds the whole system. The fixture toplevel's closure (the store the image registers) holds the flake input sources and the cogbox package that the launcher's offline re-exec needs. The toplevel carries the compat doc as a regular file and the tool in `sw/bin`. |
| `upgrade-vm` | **Not in `all`**; KVM, about 6 minutes. One VM booted like a template (legacy MBR, SeaBIOS, GRUB on `/dev/vda`, `image.nix` plus `upgrade/module.nix`) runs the REAL tool against system generations it fetches from a signed file:// cache, with `-smbios type=1,serial=<blob>` per boot. The guard on every boot path: `S=c` on the 330-byte worst case boots the candidate once (`c:`), a v1 serial without `S` (`d:`), and, failing open (`u:`, the candidate boots), no serial at all and a readable serial that is not a raw v1 blob (still base64-encoded); `S=r` boots the rollback over an armed candidate, a hard stop mid-trial, a missing initrd (panic, reboot), a stage-1 failure (sysrq crash, reboot) and a kernel that does not load (GRUB fallback) all land on entry 0, and the SMBIOS 3.0 entry point. The fetch verdicts `not-found`, `signature`, `compat` and `integrity` on nix's real stderr, the headroom gate, nix-gc skipping (exit 75, a success) while a stand-in and then the REAL fetch worker (parked by the crash driver in its own transient unit) hold the lock, and collecting a planted path but not the staged target afterwards, `busy`, the argv[0] rule, commit, a no-op re-issued commit, abort and `revert-commit`. Every fetch launcher's own status already shows its worker registered (never `interrupted`), and at the first boot (in both VM checks) the lock file is already there, root-owned 0600. The first sector and the first MiB stay byte-identical throughout, and `/boot/grub/state` never changes. Both VM checks fail after 30 minutes (`globalTimeout`) instead of stalling on a QEMU start race in the test harness (docs/pve-system-upgrade.md). |
| `upgrade-vm-powercut` | **Not in `all`**; KVM, about 9 minutes. The same VM with a power cut (QEMU quits, the guest page cache is lost) right after every numbered step of `commit` (steps 1-7, including the "head = target, entry 0 = old" state after step 2) and of `abort` (steps 1-9); a `--no-rollback` commit after step 3 and then its repairing abort after step 4 (the rollback restored from `pre`); a `--no-rollback` commit after step 8 (the closing write landed, the root flip did not: the old system stays rooted and the next `fetch` re-asserts the root); and `arm` after step 6 (the one-shot survives, `S=c` boots the candidate, `abort` runs from it). Each cut is repaired from `txn.json` by the step table's repair verb, after which the head, entry 0 and the committed system agree, the rollback is the recorded one (a commit's `pre` restored; no collection runs between a cut and its repair here, so the rollback is never lost, which docs/pve-system-upgrade.md's `rollback_lost` covers), no candidate or one-shot is left (after abort steps 2-9 no `cwx_once` either), grub.cfg parses clean and the boot area is unchanged. |

The live floor section needs unprivileged user namespaces with nftables. Where those are unavailable it skips loudly instead of passing silently. The rule 4a input probe and the open-ingress cases also need veth links and `nsenter`, and skip loudly on their own without them; the realized-ruleset assertion that the input chain is rule 4a's drop alone holds either way.

## Validation still owed

Not yet covered here: a booted-image test (a nixosTest with a fixture SMBIOS serial), and a live smoke clone on a cluster. Both need a baked image. For upgrades, `upgrade-vm` covers the boot loader mechanics on a VM built from `image.nix` and `upgrade/module.nix`, but no check boots a full `pve-host.nix` image, and the guard's inputs on a real PVE VM are unchecked: PVE's `base64=1` decode as GRUB sees it, the machine type and the SMBIOS entry point (a negative result is non-blocking, because the guard fails open, and shows as `cwx_once == "u:"`). The smoke clone must also confirm what no check here can show:

- `sshd` comes up on a fresh clone. `sshd.service` `Requires=` `cogworx-pve-floor` (via `RequiredBy=`), so a floor that does not load and verify on first boot keeps sshd down.
- A deliberately broken floor keeps `sshd` down while the serial console (`serial0`, the break-glass getty) still works.
- On a real NIC, a neighbour's frame to 169.254.169.254 arriving on eth0 is dropped and counted by `rule4a-input` (`nft list chain inet cogworx_pve_floor input`).
- With default rules, a guest TCP connect to an internal address is refused by the sandbox's own rules; after an admin L4 allow it connects; after deleting the allow it is refused again. The passt and L7-proxy uids reach an internal listener from the VM.
- A nix build user (`setpriv` as `nixbld1`) times out connecting to an internal address except the `infraAllow` sockets, to `127.0.0.1:18445` (the mitmproxy hop) while the sandbox runs, and to each `buildDenyLoopbackTCP` port the bake lists, while root and the L7 proxy uid reach the hop; its datagrams to each `buildDenyLoopbackUDP` port on `127.0.0.1`, to `255.255.255.255`, to the `eth0` segment's broadcast address and to a multicast group fail with EPERM; the `rule4-build`, `rule4-build-hop`, `rule4-build-hop-udp` and `rule4-build-bcast` counters move. On the first boot of a fresh clone, `cogworx-pve-floor`'s verify leg reports both build-user probes run (not the "no nixbld1 account" skip).
- On a fresh clone, `systemctl show -p Environment` lists `MKE2FS_CONFIG` for `cogworx-state-disk` and `cogworx-guest-disk`, both finish within about a minute, and the discard columns of `/proc/diskstats` for the state and guest disks do not move while they run. After a Stop and Start, the second boot's store re-format also finishes in seconds.
