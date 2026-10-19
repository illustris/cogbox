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
| `floor-site.nix`, `floor_render.py` | The site floor: nft table `inet cogworx_pve_floor`, rules 4a, 4 and 5, rendered and validated at build time. |
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
| `cogworx-pve-floor` | Loads the site floor, then verifies rule 4a against the live emulator socket: root connects, while `nobody` and a nix build user are dropped. `Before=` sshd and the supervisor, and `RequiredBy=` sshd: a floor that fails to load or verify leaves the VM without sshd rather than with an sshd open to the shared L2 (the serial console stays as break-glass). |
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
- **Rule 4** (output):
  1. `meta skuid cogbox-passt ip daddr @cp udp sport 60000-60031 accept` (the mosh range, read from `cogworx.gce.moshUDPPort` and `moshUDPPortRange`)
  2. the exact `infraAllow` accepts
  3. `meta skuid { cogbox-passt, cogbox-proxy } ct direction original ip daddr @infra4 drop`
  4. `meta skgid nixbld ct direction original ip daddr @infra4 drop`

  Rule 4 names guest traffic (passt), the L7 proxy's upstream sockets and the nix build users (`nixbld`, the daemon's builders). Root is outside it by design (see the residual below). Replies on flows the control plane opened still pass, `@cp` included, through the direction scoping. The only `@cp` accept is for passt's mosh reply sockets: passt answers a datagram that arrived on its `-u` forward from a per-flow socket bound to the forward's port and connected to the sender (the cogworxd relay), and once conntrack has forgotten the inbound flow that reply is an original-direction flow to `@cp`. Any other new flow from a uid rule 4 names to a `@cp` address inside `@infra4` is dropped.
- **Rule 5** (input, after rule 4a's input drop):
  1. `iifname "lo" accept`
  2. `ip saddr @cp accept`
  3. `ct direction original` drops of TCP to sshd, the guest SSH forward range and the HTTP forward range, and of UDP to the mosh range

| Option | Meaning |
|---|---|
| `cogworx.pve.floor.controlPlaneCIDRs` | Where cogworxd's control traffic comes from (`@cp`) |
| `cogworx.pve.floor.infraDenyCIDRs` | The site's internal ranges (`@infra4`) |
| `cogworx.pve.floor.infraAllow` | `[{ address, protocol, port }]` exact exceptions to rule 4, one host each |

The build refuses a CIDR that is not IPv4, is not canonical, is wider than `/8`, or overlaps `127/8`, `169.254/16` or `0/8`. It also refuses an `infraAllow` address that is a range rather than one host (a bare address or a `/32`).

Residual, the `@cp` / rule 4 coupling: the floor cannot tell passt's mosh reply socket from a guest-originated datagram whose source port passt preserved inside the mosh range. So passt-uid UDP from that port range reaches every `@cp` address, including any part of `infraDenyCIDRs` that `controlPlaneCIDRs` also covers. In `rules` mode the L4 shim's reply-socket exemption never covers a guest-originated datagram (that exemption requires a specific bound address, which a guest socket never has), so such a datagram falls to the instance's ordinary L4 rule walk: the seeded RFC1918/bogon denies refuse it by default, but an owner or admin L4 allow that covers a `@cp` address admits it. The PVE boot config has no `full` mode. With `@cp` limited to the control plane's own source addresses this is a few hosts. With `@cp` set to whole internal ranges (the fallback when the control source is NATed or unstable), it is those whole ranges, and rule 5 admits control ingress from all of them too. Nothing refuses this. Evaluation warns when a `controlPlaneCIDRs` entry covers an entire `infraDenyCIDRs` entry, or is wider than `/16`.

Residual, root is outside rule 4: rule 4 drops new flows to `@infra4` from passt, the L7 proxy and the nix build users (`nixbld`) only. Root is deliberately not in the set, because the trusted half, nix-daemon substitution from the site cache and the control channel all run as root. So root-run plugin evaluation, and eval-time fetches of attacker-chosen URLs (fetchers that run in the evaluator rather than in a `nixbld` builder), can reach `@infra4`. This is accepted under the operator trust model: the internal network is trusted, and breakout from the inner sandbox is out of scope.

Residual: rule 5's forward windows are fixed at build time (`guestSSHPort` and `guestHTTPPort`, each `guestSSHPortRange` wide), but `cogbox-launch.sh` slides a taken forward port upward with no upper bound and persists the result. A forward that slides past its window is bound on `eth0`'s address with no rule 5 drop, so any L2 neighbour can reach it. A slide needs every port in the window to be taken on the VM's address, which a single-instance VM does not do on its own. Closing this properly means bounding the slide in the launcher, which this tree does not change.

**Publish gates** (asserted in `pve-host.nix` whenever the image trusts a user CA: `cogworx.gce.controlCAPublicKey` or `cogworx.gce.extraTrustedUserCAKeys` is set, or anything else makes sshd's `TrustedUserCAKeys` file non-empty). No gate has an escape hatch except console autologin, which is an explicit operator opt-in:

- `controlPlaneCIDRs` must be non-empty. There is no open-ingress option. Keeping it narrow is not a gate; see the `@cp` / rule 4 residual above.
- `infraDenyCIDRs` must be non-empty.
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
| `config-values` | Device paths, serial path, tmpfiles, kernel parameters, GRUB device, sysctls, the hosts pin, DHCP shape, no google or firewall units, and sshd requiring the site floor. It also requires every `cogworx-*` unit to be classified as a metadata client or not, and every metadata client to still run something (an edge-only stub left behind by a removed gce/ unit fails). The two format units carry the no-discard mke2fs profile and no other unit does, `gce/` has no format line beyond the three known ones, and a format unit reduced to a stub trips `mkfs-nodiscard.nix`'s assertion. For upgrades: `panic=10` and `boot.panic_on_fail`, the GRUB guard as `extraConfig`, cloud-init and networkd off, the tool in the system path and the compat doc in the toplevel, the headroom floor equal to `gce/nix-gc.nix`'s (12 GiB) and the 4 GiB reserve, the upgrade lock file pre-created root-owned 0600, no `cogworx.pve.release` on the fixture, and `mkPveHost`'s `system.configurationRevision` (a `lib.mkDefault` of the flake's revision). |
| `publish-gates` | The fixture and the CA-less default both evaluate, and the exported `nixosConfigurations.cogbox-x86_64-pve` IS that default (same toplevel drvPath, no control CA). Each gate trips on exactly its own assertion (console autologin, cloud-init forced on, networkd, a static hostname, a system label outside the upgrade tool's path grammar, an `extraConfig` that replaced the GRUB guard, an `environment.systemPackages` that dropped the upgrade tool and a `system.nixos.distroName` the upgrade tool cannot pin included), and a CA-baked image with no `controlPlaneCIDRs` does not evaluate. Autologin with `cogworx.pve.allowConsoleAutologin` fails no assertion and adds no warning, autologin on the CA-less default needs no opt-in, the cloud-init, networkd and hostname gates trip on the CA-less default too, and a default-priority `services.cloud-init.enable = true` (what a Proxmox base profile sets) is forced off and fails nothing, and neither does a distro name other than `NixOS` in the tool's grammar. |
| `floor-warnings` | A `controlPlaneCIDRs` entry that covers an `infraDenyCIDRs` entry (opening it to passt's mosh-range UDP), or is wider than `/16`, warns, and the fixture's narrow one does not. Malformed entries are left to the build-time refusal. |
| `dhcpcd-conf` | The realized `dhcpcd.conf` |
| `hosts-pin` | The realized `/etc/hosts` pins `metadata.google.internal` |
| `qga-allowlist` | The real qemu-ga, run with the realized flags, enables exactly the allow-list and refuses `guest-exec` and `guest-file-write` |
| `route-coverage` | Every metadata access in the realized scripts is served, with a negative control |
| `floor-site` | On the realized ruleset: rule 4a's input drop opens the input chain, and the only `@cp` accept is passt's mosh replies. Then validator refusals, a golden ruleset, and live probes of rules 4a, 4 and 5 in a user and network namespace, each with a negative control: among them a neighbour's datagram for the metadata address arriving over a veth (dropped on input, `@cp` source included), a passt mosh reply to `@cp` (passes), and a passt or build-user TCP flow to a `@cp` inside `@infra4` (dropped). With both tables loaded it also runs seven of the gce floor's eight probes: 4 and 5 through gce's own verifier, and 1, 3, 6, 7 and 8 modelled. Probe 2 cannot be modelled with a single mapped uid. |
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

The live floor section needs unprivileged user namespaces with nftables. Where those are unavailable it skips loudly instead of passing silently. The rule 4a input probe also needs veth links and `nsenter`, and skips loudly on its own without them; the realized-ruleset assertion covers the rule's place either way.

## Validation still owed

Not yet covered here: a booted-image test (a nixosTest with a fixture SMBIOS serial), and a live smoke clone on a cluster. Both need a baked image. For upgrades, `upgrade-vm` covers the boot loader mechanics on a VM built from `image.nix` and `upgrade/module.nix`, but no check boots a full `pve-host.nix` image, and the guard's inputs on a real PVE VM are unchecked: PVE's `base64=1` decode as GRUB sees it, the machine type and the SMBIOS entry point (a negative result is non-blocking, because the guard fails open, and shows as `cwx_once == "u:"`). The smoke clone must also confirm two things no check here can show:

- `sshd` comes up on a fresh clone. `sshd.service` `Requires=` `cogworx-pve-floor` (via `RequiredBy=`), so a floor that does not load and verify on first boot keeps sshd down.
- A deliberately broken floor keeps `sshd` down while the serial console (`serial0`, the break-glass getty) still works.
- On a real NIC, a neighbour's frame to 169.254.169.254 arriving on eth0 is dropped and counted by `rule4a-input` (`nft list chain inet cogworx_pve_floor input`).
- A mosh session through the cogworxd relay survives an idle gap longer than the conntrack UDP timeout, with the `rule4-cp-mosh` counter advancing.
- On a fresh clone, `systemctl show -p Environment` lists `MKE2FS_CONFIG` for `cogworx-state-disk` and `cogworx-guest-disk`, both finish within about a minute, and the discard columns of `/proc/diskstats` for the state and guest disks do not move while they run. After a Stop and Start, the second boot's store re-format also finishes in seconds.
