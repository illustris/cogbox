<h1 align="center">
  <img src="cogbox-icon.svg" width="120" alt=""><br>
  cogbox
</h1>

<p align="center">
  A NixOS <a href="https://github.com/microvm-nix/microvm.nix">microvm</a> sandbox for running coding-agent harnesses with permission prompts disabled.
</p>

Each harness's host config and auth tokens are mounted into an isolated
QEMU guest where the agent can read, write, and run commands without
prompting -- without that blast radius reaching the host.

Currently supported harnesses: `claude-code` ([Claude Code](https://docs.anthropic.com/en/docs/claude-code)), `opencode` ([opencode](https://github.com/sst/opencode)), `omp` ([Oh My Pi](https://github.com/can1357/oh-my-pi)), `codex` ([OpenAI Codex CLI](https://github.com/openai/codex)), `hermes-agent` ([Hermes Agent](https://github.com/NousResearch/hermes-agent)), `dsh` ([DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)), and `pi` ([pi coding agent](https://github.com/earendil-works/pi)). Codex and pi are opt-in and **disabled by default**; enable them by setting `enableCodex = true` or `enablePi = true` in `flake.nix`. The architecture is harness-agnostic; see [Harnesses](docs/harnesses.md) for the model and how to add more.

## Quick start

```
nix run github:illustris/cogbox
```

On first run, the wrapper asks which harnesses to set up (only the ones
you pick get host-side config dirs created) and then prompts before
touching anything (the list reflects which harnesses were built in, so
`codex` appears only when `enableCodex` is on):

```
No harness state detected. Set up which?
  [1] claude-code     (creates ~/.claude/, ~/.claude.json)
  [2] dsh     (creates ~/.dsh/)
  [3] hermes-agent     (creates ~/.hermes/)
  [4] omp     (creates ~/.omp/)
  [5] opencode     (creates ~/.config/opencode/, ~/.local/share/opencode/)
  [6] all
Choice [1-6, comma-separated for multiple]:

The following paths will be created:
  ~/.config/cogbox/instances/default/config.json  (default settings)
  ~/.config/cogbox/authorized_keys  (SSH public keys; seeded from ~/.ssh/*.pub + ssh-add -L)
  ~/.local/share/cogbox/cogbox_ed25519  (cogbox's own SSH key, the default identity for `cogbox ssh`)
  ~/.local/share/cogbox/instances/default/  (VM data)
  ...

Continue? [y/N]
```

The VM then starts in the background and, by default, `cogbox` waits for
the guest's SSH server to come up and drops you straight into an SSH
session. When you exit the session the VM keeps running (stop it with
`cogbox stop`). Pass `--no-ssh` to just start it and return, or `-f` to
watch it boot on the serial console instead (`Ctrl-]` detaches without
stopping the VM).

The package installs the CLI as both `cogbox` and `cbx` (a short alias
symlink); once it's on your `PATH`, the two names are interchangeable
(`cbx stop`, `cbx list`, ...).

Each enabled harness ships a full-auto launcher inside the VM: `c` for `claude-code`, `oc` for `opencode`, `om` for `omp`, `cx` for `codex`, `h` for `hermes-agent`, `ds` for `dsh`, and `p` for `pi`. Every enabled harness binary is installed regardless of which host-state directories you select, so once the VM boots its launcher is on `$PATH`.

## Documentation

| Doc | Contents |
|---|---|
| [Network filtering](docs/network-filtering.md) | Network modes; L4 CIDR rules; TCP destination remap (SOCKS5); L7 vhost filtering with terminate/passthrough tiers and path constraints; threat model and enforcement internals |
| [Per-instance extensions](docs/extensions.md) | Extending one instance's NixOS config through its `flake/flake.nix` |
| [Plugins](docs/plugins.md) | Installable, versioned extensions: the flake contract, pinning, plugin-supplied firewall rules, the generated composition flake |
| [Harnesses](docs/harnesses.md) | The harness model, per-harness full-auto wiring, adding a harness |
| [Internals](docs/internals.md) | Directory layout, runtime dir + 9p shares, fw_cfg injection, launch-time patching, re-exec mechanism, host path overrides |

## Named instances

Run multiple isolated VMs simultaneously, like Wine prefixes. Each named
instance gets its own data directory, overlay image, and network ports.

```sh
# Default instance (starts in the background, then SSHes in)
nix run github:illustris/cogbox

# Create and start a named instance
nix run github:illustris/cogbox -- --name work
nix run github:illustris/cogbox -- --name personal --vcpu 8 --mem 16384

# List all instances and their ports
nix run github:illustris/cogbox -- list
```

Ports are auto-assigned when an instance is first created (default starts
at SSH 2222 / HTTP 8080; each new instance increments by one), including a
per-instance L7 port triple (`l7PortBase`). Override by editing the
instance config. Those values are only kept disjoint among *your own*
instances; on a shared multi-user host another user's instance may already
hold them (passt and the L7 proxy bind the host's shared loopback). When that
happens, `cogbox start` slides each conflicting port/triple to the next free
one at launch and persists the new value back to the instance config.

Harness authentication and base config are shared across all instances;
each instance overlays its own changes on top, so per-instance harness
settings persist independently (see [Harnesses](docs/harnesses.md)).

The guest's hostname is `cogbox-<instance>` (e.g. `cogbox-work`), and
interactive shells start in `~/work` (a symlink into the persisted host-shared
data dir), the standardized project workdir where plugin kits are materialized.

## CLI

cogbox uses a verb-based CLI. Bare `cogbox` (no verb) is sugar for
`cogbox start`. The VM always runs as a background daemon; its serial
console and QEMU monitor live on per-instance Unix sockets, so you can
attach and detach (`Ctrl-]`) freely without stopping the VM.

| Verb | Description |
|---|---|
| `start` | Init if needed, launch in the background, then SSH in (default verb). `--no-ssh` just returns; `-f` attaches the serial console. |
| `console` | Attach the serial console of a running instance (`Ctrl-]` detaches) |
| `monitor` | Attach the QEMU (HMP) monitor of a running instance |
| `stop` | Stop a running instance (SIGTERM, then SIGKILL with `--force`) |
| `restart` | `stop` then `start` |
| `status` | Print whether an instance is running, plus ports/net mode |
| `list` | List all instances. `--json` for machine-readable output |
| `init` | Create config + host directories without launching |
| `delete` | Delete an instance's config + persistent files (refuses if running; `-y` skips the prompt) |
| `ssh` | Connect to a running instance via SSH. A trailing command of two or more words is an argv vector: each word is quoted, so `#`, spaces, quotes, `$`, backticks and newlines reach the remote command literally. A command passed as ONE argument stays a shell string the guest shell interprets |
| `rules` | Manage CIDR (L4) allow/deny rules -- [docs](docs/network-filtering.md#l4-cidr-rules) |
| `remap` | Manage TCP destination-remap rules -- [docs](docs/network-filtering.md#tcp-destination-remap) |
| `l7` | Manage L7 (vhost) allow/deny rules -- [docs](docs/network-filtering.md#l7-host-filtering) |
| `plugin` | Manage guest plugins -- [docs](docs/plugins.md) |
| `help` | `cogbox help VERB` ≡ `cogbox VERB --help` |

Run `cogbox VERB --help` for verb-specific options.

### Common options

| Flag | Verbs | Description |
|---|---|---|
| `-n, --name NAME` | every verb that takes an instance | Instance name (default: `default`) |
| `-h, --help` | every verb | Show help and exit |
| `--no-ssh` | `start` | Don't auto-SSH after launch; start in the background and return |
| `-f, --foreground` | `start` | Attach the serial console after launch instead of SSHing |
| `-y, --yes` | `start`, `init`, `plugin`, `delete` | Skip the harness-selection prompt on first init / plugin and delete confirmation prompts |
| `--vcpu N` | `start`, `init` | vCPU count (default: config.json or 16) |
| `--mem N` | `start`, `init` | RAM in MB (default: config.json or 32768) |
| `--network MODE` | `start`, `init` | `full`, `none`, or `rules` (default: rules) |
| `--no-auto-keys` | `start`, `init` | Leave `authorized_keys` empty instead of seeding, and skip generating cogbox's own SSH key |
| `--add-dir DIR` | `start`, `restart` | Mount an existing host directory read-write at the same canonical absolute path in the guest. Repeatable. |
| `--add-dir-ro DIR` | `start`, `restart` | Mount an existing host directory read-only at the same canonical absolute path in the guest. Repeatable. |
| `--bind-addr ADDR` | `init` | Seed `bindAddr` (default `127.0.0.1`) |
| `--no-implicit-dns` | `init` | Seed `network.implicitDns = false`, so port 53 stops escaping the L4 rule walk. Rules mode only -- see [network filtering](docs/network-filtering.md) |
| `--self-addr CIDR` | `init` | Seed one `network.selfAddrs` entry (repeatable): an address of the enclosing host, added to the L7 proxy's non-overridable floor. Rules mode only |
| `--force` | `stop` | Send SIGKILL after 10s if SIGTERM doesn't exit the process |
| `--json` | `list` | Emit one JSON object per instance |

When an instance is first created, `--vcpu`, `--mem`, and `--network` are saved to its `config.json`. On subsequent runs they override the config for that run only.

Additional-directory grants are launch-only and do not change the `config.json` schema. Repeat `--add-dir` and `--add-dir-ro` on every later `start` or `restart`; a flagless launch inherits none. `--add-dir` lets guest root modify the selected host tree with the permissions of the launcher user. Use `--add-dir-ro` unless host writes are required.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 3 | `status`: instance is stopped |
| 64 | EX_USAGE: bad CLI args, unknown verb, unknown flag |
| 65 | EX_DATAERR: invalid value or wrong-type directory input |
| 66 | EX_NOINPUT: missing or inaccessible config, file, or directory |
| 70 | EX_SOFTWARE: internal/system error |
| 75 | EX_TEMPFAIL: already running, port collision |

### Examples

```sh
# Lifecycle
cogbox init --name work             # create without starting
cogbox --name work                  # start + SSH in
cogbox ssh --name work htop         # one-off remote command
cogbox ssh -- tmux ls -F '#{session_name}'   # words stay literal (argv form)
cogbox ssh -- sh -c 'ls /root/*'    # shell syntax: one string, or sh -c
cogbox status --name work
cogbox stop --name work

# Launch-only host directories, preserving mixed access modes
cd /home/me
cogbox start --name work --add-dir ./src --add-dir-ro '/opt/shared docs'
cogbox delete --name work            # remove its config + persistent files

# Console access
cogbox -f                           # start and watch it boot
cogbox console                      # attach the console later
cogbox monitor                      # QEMU monitor ((qemu) prompt)
```

## Network filtering

The default `rules` mode gives the sandbox working public internet while
blocking LAN, link-local, and cloud-metadata ranges. On top of that, L7
rules whitelist individual vhosts behind shared IPs, with TLS termination
for `Host`/path enforcement. Rule edits hot-reload into a running VM.

```sh
cogbox rules add allow 192.168.1.50/32 --at 8    # open one LAN host (position matters)
cogbox l7 add allow api.example.com              # one vhost, not its LB siblings
cogbox l7 add allow git.example.com --path /myorg/
nix run github:illustris/cogbox -- --network none   # or: no network at all
```

First match wins and position matters; L7 has two tiers (terminate
default, passthrough for cert-pinned clients) and several deliberate
caveats. For the OAuth harnesses, the terminate tier also injects the real
token host-side by default, so the long-lived credential stays out of the
sandbox and the guest carries only a stub. **Read
[network filtering](docs/network-filtering.md)** for rule semantics, the
L4/L7 composition table, [host-side credential
injection](docs/network-filtering.md#host-side-credential-injection), the
threat model, and the enforcement internals.

## Configuration

All settings are in `~/.config/cogbox/` (or `$XDG_CONFIG_HOME/cogbox/`),
one subdir per instance under `instances/<name>/`. Edit and restart the
VM -- no rebuild needed.

### config.json

```json
{
    "vcpu": 16,
    "mem": 32768,
    "sshPort": 2222,
    "httpPort": 8080,
    "overlaySize": "128M",
    "storeOverlaySize": "16G",
    "bindAddr": "127.0.0.1",
    "network": {"rules": [...]}
}
```

| Key | Type | Default | Description |
|---|---|---|---|
| `vcpu` | int | 16 | Virtual CPUs |
| `mem` | int | 32768 | RAM in megabytes |
| `sshPort` | int | 2222 | Host port forwarded to guest SSH (22) |
| `httpPort` | int | 8080 | Host port forwarded to guest 8080. Guest **8080 is reserved for the app relay** (the `app-relay` plugin listens there); bind sandbox services to another port. |
| `overlaySize` | string | `128M` | Persistent harness overlay image |
| `storeOverlaySize` | string | absent | Optional override for the writable nix store tmpfs. Absent means "whatever the guest declares" (half of RAM). It used to be seeded as `16G`, which is more than the guest's entire RAM, so a large in-guest `nix build` OOM-killed the guest instead of failing with `ENOSPC`. |
| `bindAddr` | string | `127.0.0.1` | Host bind address for port forwards |
| `network` | string/object | seeded `rules` | `"full"`, `"none"`, or `{"rules":[...]}` |
| `network.implicitDns` | bool | absent (`true`) | `false` drops the implicit port-53 allow for this instance |
| `network.selfAddrs` | array | absent | Enclosing-host addresses added to the L7 proxy's hard floor |
| `l7PortBase` | int | 18443 | Base of the instance's L7 loopback port triple |
| `plugins` | array | absent | Managed by `cogbox plugin` -- see [Plugins](docs/plugins.md) |

Only include the keys you want to change -- missing keys use the defaults.

### authorized_keys

SSH public keys, one per line. On first init the shared file
(`~/.config/cogbox/authorized_keys`) is seeded from `~/.ssh/*.pub` plus
any keys in the running ssh-agent; pass `--no-auto-keys` to keep it
empty. A per-instance `instances/<name>/authorized_keys` overrides the
shared file. Without SSH keys, the VM console is accessible directly
(root autologin is enabled).

In addition, cogbox manages its own keypair at
`~/.local/share/cogbox/cogbox_ed25519` and unions its public key into
every guest's `authorized_keys` at launch, so `cogbox ssh` connects out
of the box without relying on your personal keys. It pins ssh to this key
alone (`-i` plus `IdentitiesOnly=yes` and `IdentityAgent=none`), so your
agent and `~/.ssh` keys are not offered and no agent is contacted -- a
gpg-agent with ssh support can't stall or prompt on connect. The private
key stays on the host -- it lives beside, not inside, the per-instance
data mounted into a VM, and is reused across all instances. (Under
`--no-auto-keys`, where no cogbox key exists, `cogbox ssh` instead falls
back to your agent and `~/.ssh` keys.)

`--no-auto-keys` at first init skips generating this key and records the
opt-out (at `~/.config/cogbox/no-cogbox-key`), so a later plain `cogbox
start` won't silently re-create it -- the guest stays reachable only via
the console. To opt back in, remove that marker. To rotate the key,
delete `~/.local/share/cogbox/cogbox_ed25519*`; the next launch (without
`--no-auto-keys`) regenerates it.

### Extending the guest

Two mechanisms, both folding NixOS modules into the instance's VM:

- **[Per-instance flake](docs/extensions.md)** -- edit
  `instances/<name>/flake/flake.nix` to add packages, services, mounts;
  applied on the next start.
- **[Plugins](docs/plugins.md)** -- install versioned extensions from any
  flake URL, optionally with the firewall rules they need:

  ```sh
  cogbox plugin add github:myorg/myplugin?dir=flake
  cogbox plugin add 'github:org/observability#loki' -n work
  cogbox plugin update
  ```

Host-side data locations can be overridden with `COGBOX_*` environment
variables -- see [Internals](docs/internals.md#host-side-path-overrides).

## Defaults

| Resource | Value |
|---|---|
| vCPUs | 16 |
| RAM | 32 GB |
| Guest root (`/`) | tmpfs, half of RAM |
| Writable nix store | tmpfs overlay, half of RAM |
| Harness overlay (shared) | 128 MB ext4 image, per-harness subdirs |
| SSH | 127.0.0.1:2222 -> 22 |
| HTTP | 127.0.0.1:8080 -> 8080 (guest 8080 is reserved for the `app-relay` plugin) |
| Network | rules (private/bogon denied, public allowed) |
| Docker | enabled |
| Storage profile | `workstation` (see below) |

### Storage profiles

Where durable guest data lives is a single internal option,
`cogbox.storage.profile`, because the right answer differs by deployment:

| Class | `workstation` (default) | `hosted` |
|---|---|---|
| Host harness config | read-only 9p lower | read-only 9p lower |
| `work` tree | 9p share of the instance data dir | data-pool volume on the dedicated disk |
| harness-config diffs | 128 MB ext4 loop image | data-pool volume on the dedicated disk |
| machine-state (`~/.cache`, `~/.local`, `~/.config`, `/var/lib/docker`, journal) | tmpfs root (opt in with `machineState = "persist"`) | data-pool volume on the dedicated disk |
| writable `/nix/store` upper | tmpfs, half of RAM | its own volume on the same disk, remade each host boot |
| `/tmp` | tmpfs | tmpfs |

`workstation` is the historical layout and is what a developer running
`cogbox` on their own machine wants: the host filesystem is precious and
shared, the sandbox is meant to be re-creatable, and a RAM-backed root is a
feature. `hosted` is for a platform that runs one sandbox per disposable
single-tenant VM, where the guest *is* the user's only machine and nothing
should be lost on reboot. Set it with an extra module:

```nix
extraModules = [ { cogbox.storage.profile = "hosted"; } ];
```

`hosted` needs TWO block volumes -- the data pool and the writable
`/nix/store` upper, which has to be its own volume because `microvm.nix` marks
a volume `neededForBoot` exactly when its mount point is the writable store
overlay. They come from ONE dedicated disk, carved into a volume group with a
logical volume each. That is LVM rather than two partitions for one reason:
growing a disk only ever yields free space after the *last* partition, so with
fixed partitions whichever one sits first could never be extended and one
concern would permanently block the other's growth. A volume group shares its
free extents, so either volume can take new space.

The carving is entirely host-side (`cogworx-guest-disk.service` on the GCE
backend). The guest is never told about it: it sees two ordinary virtio-blk
devices and mounts them by filesystem *label*, so there is no volume-group
activation anywhere on the guest's boot path.

Under `hosted` a pool that fails to appear must still yield a guest you can
log into, and that takes three mechanisms rather than one. Every bind carries
`x-systemd.requires=` on the pool, which is what stops a bind from showing an
empty directory where the user's data should be; and every mount an absent pool
can fail is `nofail`, which is what keeps that failure from failing
`local-fs.target`, whose `OnFailure=emergency.target` would leave the guest with
no sshd at all. The second set is larger than it looks: besides the pool and its
binds it includes the four harness overlay mounts and the two opencode ephemeral
binds, none of which name a pool path in their own fstab line -- systemd derives
a hard `Requires=` on the pool for them from their parent directory, their bind
source and their overlay upper/work dirs. `cogbox-guest-pool-degradable` derives
that set from the realized fstab and fails the build if any member of it is
`local-fs.target`-required.

The third is about SERVICES, and `nofail` cannot reach it: a service that
hard-`Requires=` one of those mounts fails when the mount does, taking whatever
it was preparing with it. That is a class, not a list -- the same mounts are
perfectly ordinary preconditions under `workstation` -- so a service names the
mount *paths* it depends on and the profile decides the strength: `Requires=`
where the mount is a genuine precondition in every profile, `Wants=` (plus the
same `After=`) where `hosted` moves it onto the pool. Three units are in it
today: `harness-setup-dirs`, whose failure would leave the harness overlay
upperdirs uncreated; `cogbox-brain-materialize`, whose failure is a work tree
with no brain; and `cogbox-claude-stub`, whose failure leaves a credential the
control plane believes it reconciled. `cogbox-guest-pool-degradable` scans every
realized service unit for both spellings of the hard dependency (`Requires=` and
`RequiresMountsFor=`), so a service added later joins the rule or fails the
build.

Every one of those units is a `Type=oneshot`, for which systemd *disables* the
start timeout by default, and several of them sit in front of sshd. Each
therefore carries an explicit `TimeoutStartSec` with the reason in a comment
beside it -- an unbounded oneshot on the boot path is a guest that hangs with
nothing in `systemctl --failed`, which is indistinguishable from the wedge this
whole profile is written against. The bounds are chosen to degrade rather than
wedge: at the deadline the unit fails, its dependent binds do not happen, and
`nofail` turns that into the pre-pool layout instead of `emergency.target`.

**`nofail` bounds a FAILURE; only a timeout bounds a HANG -- and the jobs that
can hang are mostly not written here.** A pass-2 pool line makes
systemd-fstab-generator emit a hard `Requires=` on `systemd-fsck@<device>`, and
`autoResize` (which renders as nothing but `x-systemd.growfs`) makes it emit
`systemd-growfs@<mount>` plus an ordering drop-in that puts `local-fs.target`
*after* it. Both of those upstream units ship `TimeoutSec=infinity`. A provider
disk that answers its device probe and then stalls on reads -- the same fault
class this profile is written against, and one the 30s
`x-systemd.device-timeout` does not cover, because that bounds the device
appearing and not the reads afterwards -- leaves either job in uninterruptible
D-state, so the mount job never completes and the guest sits in "Booting" with
an *empty* `systemctl --failed`. Two units nixpkgs contributes are in the same
class: `systemd-tmpfiles-setup`, which chowns `/var/log/journal` (a pool bind
here) and gates `sysinit.target`, and the `rw-<mount>` overlay pre-mount units,
which mkdir their upper/work dirs on the pool ahead of
`cogbox-brain-materialize`. All of them get a finite bound under `poolEnabled`,
and each bound sets `TimeoutStopSec` as well: bounding only the start fires
SIGTERM at a process wedged in D-state on the device that stalled and then waits
forever for it to die, which parks the unit in `deactivating` and wedges the
boot one state further along. `cogbox-guest-pool-boot-bounded` re-derives those
unit names from the generator's own output and fails the build if a rendered
bound does not match one -- the only way an escaping mistake or a label rename
shows up, since a drop-in naming an instance systemd never creates is silent.
None of this is `hosted`-only: `workstation` with `machineState = "persist"`
declares the same volume with the same label and gets the same generated jobs,
so the check runs over both profiles.

Nor is it guest-only. The GCE **host** has the identical shape and had it worse:
its `/var/lib/cogbox-state` fstab line carries `x-systemd.before=sshd.service`
*and* `x-systemd.before=cogworx-supervisor.service`, so the two jobs systemd
interposes on that mount -- `cogworx-state-disk.service` (a `Type=oneshot`, for
which systemd DISABLES the start timeout by default) and the
`systemd-fsck@<device>.service` the generator synthesises from the pass-2 line
(upstream `TimeoutSec=infinity`) -- could each hold *both* the host's sshd and
the VM launcher indefinitely. With the supervisor gone there is no
`ssh <vm> cogbox <verb>` control channel left, so that state has no recovery
path at all. Both are bounded now, and `gce-image-host-boot-bounded` derives the
unit names from the generator's output over the host fstab exactly as the guest
check does. `nofail` does not substitute for either bound: it unhooks the mount
from `local-fs.target` and leaves the explicit `x-systemd.before=` edges in
place. **`nofail` bounds FAILURE; only a timeout bounds a HANG.**

What a pool-less boot gives you, stated precisely and **not** as "it degrades to
`workstation`": sshd comes up, and `~/work` is whatever is at the legacy 9p
path. **Read that literally, because it depends on whether the instance has
already migrated.** Before the migration it is the user's full work tree,
untouched. *After* it, the migration has renamed that directory to
`work.pre-pool` and left an empty one in its place -- deliberately, so that a
boot on the pre-pool layout cannot present a stale copy as current -- so `~/work`
is **EMPTY** on such a boot. Harness *state* is not available either --
`/root/.claude` and friends are pool-backed under this profile, so their overlays
do not mount and the harnesses start from their baked defaults.

**This is a boot to diagnose from, not a supported way to run**, and that is the
whole reason `nofail` is still on the pool mount. It is not a second storage
mode and it is not a fallback: a pool the host carved, formatted and labelled
successfully which the guest then cannot mount is the *one* fault on this path
that the host cannot see, so the guest has to come up far enough to put the
failed mount in its own `systemctl --failed` where a person can read it.
Fail-closed there would give you `emergency.target`, no sshd, and no explanation
on either side. Nothing is silently lost in the meantime: anything a user writes
into that empty tree is found by the next healthy boot, which fires the fork
warning naming both trees and both sizes and retires the legacy copy under a
numbered `.pre-pool.1`, `.2`, ... rather than hiding it under the bind.

The GCE image is **hosted-only**. There is one baked guest storage profile and
nothing selects between two at runtime. An earlier revision put a chooser in
front of `cogbox` that fell back to the workstation runner whenever the host
would not carve; it was removed, and the reason was not the ~23 MB of extra
closure it cost. It was that the image could then run in two modes while every
piece of per-instance state -- the state disk, the instance config dir, the
recorded runner path, the retained 9p work tree, the harness overlay image --
persisted **across the flip**. Four separate blocker rounds each turned up one
instance of that; they were one structural fact, and removing the flip removes
the class.

So when `cogworx-guest-disk` refuses -- absent disk, unreadable disk, foreign
filesystem, foreign volume group -- there are no logical volumes for QEMU to
open and **the guest does not start**. That outcome is accepted. What is not
accepted is the shape it used to have, an instance stuck in "Booting" that
nobody could diagnose, so three things make it legible and all three are
asserted by `gce-image-hosted-guest-profile`:

- the **host half stays up and reachable** -- `cogworx-guest-disk` declares no
  host mount, orders itself before nothing on the host's boot path, and the
  supervisor only `Wants=` it, so sshd and `ssh <vm> cogbox <verb>` answer on
  exactly the boots where the guest does not;
- the failure is a **failed unit**, not a job parked in `activating`: three of
  the four refusals exit non-zero and the unit carries an explicit finite
  `TimeoutStartSec` (a `Type=oneshot` has none by default);
- and it is **named**. `cogworx-supervisor` is handed the hosted guest's own
  volume paths as `COGWORX_GUEST_VOLUMES`, and supervise.sh leg (e2) tests them
  before the launch and fatals with the missing device on serial -- the one
  channel the control plane has on a VM whose guest never came up. The fourth
  refusal, an absent device, is exit 0 on purpose: a resolver VM legitimately
  boots this image with no guest disk, and that unit cannot tell the two apart.
  Leg (e2) can, because it only runs on a boot that is about to start a guest.

Growing an instance is "grow the disk, restart", and the two volumes get there
by different routes. The host runs `pvresize` and then extends the volumes --
the store overlay to its configured size, the pool into whatever is left -- and
it does that *before* the guest launches, so the guest never sees the old size.
The pool's filesystem is then grown by the guest, because the pool mounts
`autoResize`, which works only there: `x-systemd.growfs` needs
`systemd-growfs@.service`, a stage-2 unit with no counterpart in the initrd.
The store overlay *is* an initrd mount, so nothing in the guest could grow it;
instead the host lays its filesystem down fresh at the volume's current size on
every host boot. That also keeps the `/nix/store` upper exactly as ephemeral as
the tmpfs it replaces, and self-heals a `mkfs` that was interrupted on a volume
the guest's stage 1 cannot boot without.

The read-only harness lower is identical in both profiles -- that is the
security property, and the hosted case loses nothing by keeping it.

Pre-installed tools: core — `git`, `curl`, `jq`, `vim`, `ncdu`, `tmux`, `htop`, `nixfs`; search/files — `ripgrep`, `fd`, `bat`, `sd`; data wrangling — `yq-go`, `duckdb`, `miller`, `dasel`, `gron`, `datamash`, `jo`; HTTP/DNS/web — `xh`, `websocat`, `dnsutils`, `htmlq`, `pup`; shell glue — `moreutils` (plus `xargs -P` for parallelism).
Harness binaries (with launchers): `claude-code` (`c`), `hermes-agent`
(`h`), `opencode` (`oc`), and `pi` (`p`) on `x86_64-linux` and
`aarch64-linux` (sourced from `numtide/llm-agents.nix`). `codex` (`cx`)
is opt-in (see above) and built in only when `enableCodex` is set.
Architecture-conditional extras: `bpftrace` (x86_64, aarch64), `nix-mcp`
(where the `nix-mcp` flake publishes a build).

## GCE backend image

`gce/` builds cogbox's HOST half as a NixOS system that boots on Google Compute
Engine under nested virtualization, running the same microVM guest it runs
locally. It exists for a control plane that gives each sandbox its own VM
instead of its own pod; nothing in it changes the local or Kubernetes paths.

| Output | What it is |
|---|---|
| `nixosConfigurations.cogbox-x86_64-gce` | The host system. x86_64 only -- GCE nested virtualization is Intel-series only |
| `packages.x86_64-linux.gce-image` | `disk.raw` in the sparse gzipped tar `gcloud compute images create` imports |
| `apps.x86_64-linux.push-gce-image` | Stage in GCS + register the image in a family. Run it with the image-pipeline identity, never the control plane's credential |
| `nixosConfigurations.cogbox-<arch>-hosted` | The guest with `cogbox.storage.profile = "hosted"`. A separate configuration because the guest closure is baked into a package, and a host module cannot reach a guest option |
| `packages.<system>.cogbox-hosted` | `cogbox` baked against that guest. The GCE image ships this and ONLY this -- it is hosted-only, `packages.cogbox` and its runner are not in the image closure, and nothing chooses between them at launch; nothing else uses it |

Units, all root-owned:

| Unit | Job |
|---|---|
| `cogworx-state-disk.service` | Format `/dev/disk/by-id/google-cogworx-state` on first boot ONLY (`blkid` guard); an unconditional mkfs would destroy the L7 CA, the secret store and the VM host key on every resume |
| `cogworx-guest-disk.service` | Carve `/dev/disk/by-id/google-cogworx-guest` into a volume group with two logical volumes -- the guest's data pool and its writable `/nix/store` overlay -- keep them grown to the disk, and put a labelled ext4 on each. It NEVER MOUNTS a guest filesystem; the volumes are handed straight to QEMU. Five cases: absent (exit 0, a resolver VM has no such disk), unreadable (exit 1, a fault), already-LVM (recognised, nothing re-created), a foreign filesystem or volume group (left alone), and provably blank (carved). The pool's `mkfs` is guarded by the same three probes as the disk, because it holds the user's only copy of their work tree: blankness must be PROVED by a successful read, then left unrefuted by `blkid -p` (exit 2, no TYPE) and by `wipefs --no-act` (exit 0, no signature) -- a read proof is required because a device that errors on read looks identical to a blank one through either signature probe. The store overlay's `mkfs` is deliberately unconditional: it holds no user data, and remaking it is both how it stays ephemeral and how it grows. Pulled in and ordered by the supervisor (`Wants=`/`After=`, deliberately not `Requires=`), since with no host mount unit there is no `x-systemd.before=` seam and neither `mkfs` nor a grow may race the VM launch |
| `cogworx-attr-scrub.service` | Delete the previous boot's readiness/host-key guest attributes. Retries forever, and is deliberately independent of the floor unit |
| `cogworx-floor.service` | Install the nftables floor, then verify it with seven live connect probes -- three of them against a listener the probe binds itself -- and refuse the boot if the self-address set is empty |
| `cogworx-supervisor.service` | The sandbox lifecycle. `Requires=` both of the above, so a failed floor or scrub can never yield a running sandbox. Restarts forever and at a FLAT `RestartSec=5` (`StartLimitIntervalSec=0`); the exponential backoff a permanently-failing boot needs -- so it cannot restart without bound -- lives in `gce/supervise.sh` (`backoff_sleep`, 5s doubling to 300s) and NOT in the unit, because systemd never resets its restart counter after a successful run while leg (j) exits non-zero on every ordinary sandbox exit, an in-guest `reboot` included. Script-side, the backoff applies only to boots that FAILED and resets once one gets past init, so a user rebooting inside their sandbox is never throttled. See the comment at `gce/supervisor.nix` |
| `cogworx-cogbox-log.service` | Tail the cogbox runtime log into the JOURNAL. It is a separate unit so that log can never reach serial, which on GCE is provider-retained |
| `cogworx-nix-gc.service`/`.timer` | Collect the in-VM store when the boot disk runs low |
| `cogworx-resolver-deadline.service` | Power a resolver VM off after its deadline, independently of the provider-side field |

The floor itself is three rules, all matching on `skuid`, and what each one
matches is load-bearing rather than incidental:

| Rule | Realized form |
|---|---|
| 1 | `meta skuid cogbox-passt ip daddr 169.254.0.0/16 drop` -- the whole link-local range, not an enumeration of the metadata API and the resolver that shares its address by default. The host half keeps that address: every metadata read on the boot path goes there, and so does its own DNS while `vpcResolver` is left at the default |
| 2 | `meta skuid 0-4294967294 ct direction original ip daddr <self> drop`, one rule per address: **opening** a flow to the VM's own non-loopback addresses is dropped from **every** uid -- with `meta skuid root ip daddr <self> tcp dport 2222-2237 accept` rendered ahead of it, because `cogbox ssh` (and Terminal) dial the passt forward bound at `bindAddr` |
| 3 | `meta skuid cogbox-passt ct direction original ip daddr 127.0.0.0/8 drop` (and its `::1` mirror) -- with `... ip daddr 127.0.0.1 tcp dport { <funnel targets> } accept` above it. The passt uid, and only it, may not open a flow to this machine's loopback except to the L7 remap funnel's own targets |

Rule 2's shape carries three requirements. It must not be *narrowed* to named uids: an
enumeration of the passt and proxy uids leaves the hostile code out of the rule
-- in-VM plugin builds run as `nixbld*` under the daemon, and passt creates its
forward listeners *before* it drops privileges, so those sockets are root-owned
no matter how the drop is spelled. The proxy uid matters for the relay path
specifically: it re-resolves an allowed vhost and opens the upstream socket
under its own uid, so a passt-only drop would leave a guest-triggered relay into
the enclosing VM.

It must carry a `skuid` expression, because a same-host connection holds the
VM's own address on *both* ends, so the return packets also match `daddr <self>`
-- and when nothing is listening that reply is a kernel RST with no owning
socket, for which `meta skuid` cannot be fetched, so nftables skips the rule and
the RST survives. A drop with no `skuid` match swallows it and breaks the very
connection the exception above just allowed.

And it must be scoped to `ct direction original`, because the `skuid` expression
covers only that socket-less case. Once passt is actually *listening*, the reply
is a SYN-ACK from a real socket, and its destination port is the client's
ephemeral port, which no `dport` accept can match -- so an unscoped range ate it
and would take `cogbox ssh`, Terminal, Console-over-ssh and the user SSH gateway
down. Direction rather than `ct state new`: scoping by state
would also let a flow that survived a floor reload keep running, which the
unscoped drop did not. The cost is that the VM's netns now runs conntrack.

Loopback is deliberately outside rule 2 so the L7 remap funnel keeps working,
and nothing on the trusted half needs the VM's own address -- passt *binds*
there, which an output drop does not affect, and the one dial that needs it is
the `cogbox ssh` exception. A guest is unaffected by the direction scoping: its
first packet is the one that opens the flow, the deny takes it, and a dropped
OUTPUT packet is never confirmed into conntrack, so no reply direction ever
exists for it to ride.

Rule 3 is loopback's own rule, and it is the **opposite shape** to rule 2 on
purpose. It stays scoped to the passt uid instead of covering every uid, because
loopback is where the trusted half talks to itself -- l7proxy dials the mitm hop,
mitmproxy dials its upstreams, sshd and the nix daemon are there -- so a range
would cut the enforcement stack rather than protect it. passt is the only process
on the VM that turns guest bytes into host sockets, and its per-flow outbound
sockets are created *after* the privilege drop, so it is both the necessary and
the sufficient selector. The exception admits the funnel's own targets, which the
shim rewrites guest 443/80 to (`127.0.0.1:<l7base>` and `+1`, for each of the
triples cogbox may slide onto), as an explicit port **set**: the third port of
every triple is the mitmproxy SOCKS5 hop, which l7proxy dials under the *proxy*
uid, and a `dport <lo>-<hi>` range would hand it to the guest. `ct direction
original` is needed here for rule 2's reason -- the funnel's SYN-ACK carries
`daddr 127.0.0.1` and the client's ephemeral port, so a stateless deny would eat
every funnel reply.

What rule 3 backs up is worth stating, because the property does not rest on it
alone and never did. passt gives the guest the host interface's **own** address
over DHCP ("its own address shadows that of the host", `passt(1)`), so ordinary
guest traffic to the VM's address is delivered inside the guest and never reaches
the wire; a guest that *crafts* a frame to that address reaches passt, which
opens a real socket, and rule 2 takes it; a crafted frame carrying a loopback
address is dropped by passt on tap ingress; and `--no-map-gw` removes the
gateway-to-loopback mapping that would otherwise turn an address the guest can
name into `127.0.0.1` on the host. Rule 3 exists because the loopback half of
that list otherwise depends on upstream behavior. Rule 3 adds an independent
enforcement layer behind it.

One consequence for anyone testing this: **an in-guest probe of the VM's own
address proves nothing either way.** A connect to `<self>:22` from inside the
guest reaches the *guest's* sshd, and since both halves run the same nixpkgs
OpenSSH the banner is byte-identical to the host's, while rule 2's counter
correctly stays still because nothing was ever sent. Probe the SSH host key, or a
port only the host binds.

The control plane drives a booted image entirely through instance metadata; the
guest agent's metadata handling is disabled, so none of these keys can execute
code or install a login key.

| Metadata key | Read by |
|---|---|
| `cogworx-start-nonce` | supervisor, once per boot; stamped onto every guest attribute it publishes |
| `cogworx-instance` | supervisor (`cogbox init -n`), cogbox-log |
| `cogworx-vcpu`, `cogworx-mem-mb`, `cogworx-network` | supervisor sizing/mode |
| `cogworx-guest-resolver` | supervisor -> `COGBOX_GUEST_RESOLVER` (passt `--dns-forward` + `--no-map-gw`). A handle, not a destination: passt intercepts the guest's queries to it and re-emits them to the VM's own loopback forwarder (`COGBOX_HOST_RESOLVER`), so the guest resolves what the host resolves |
| `cogworx-self-addrs` | floor unit (rule 2) and supervisor (`--bind-addr`/`--self-addr`). Absent or empty falls back to the metadata server's own `instance/network-interfaces/*/ip`, because every insert body stamps this key empty (no address exists yet) and only a later Start refreshes it; an empty set from BOTH sources FAILS the boot in both |
| `cogworx-maintenance`, `cogworx-resolver` | supervisor short-circuit; read by key PRESENCE, never value |
| `cogworx-resolver-deadline` | resolver self-destruct timer |
| `cogworx-ssh-ca-pub`, `cogworx-ssh-principal` | supervisor: the gateway user CA staged for the guest, and the control certificate principal sshd accepts |

Guest attributes published back, each stamped `<nonce> <payload>`:
`cogworx/vm-host-key` (every boot class, before any sandbox start),
`cogworx/ready` (level-held; deleted when the sandbox stops), and
`cogworx/boot-error` (an allowlisted one-line summary of why `cogbox init`
failed -- only `cogbox: `-stamped lines, capped, never the guest's own output --
deleted again by any boot that gets past init). The last one is what turns a
sandbox stuck "Booting" into a reason without reading a console dump; the full
init output is kept on the state disk at `last-init-error.log`, and the same
summary reaches serial once per DISTINCT failure so a restart loop cannot
overwrite the ring buffer with 1300 copies of one line.

Three things the image cannot supply and the operator must:
`cogworx.gce.controlCAPublicKey` (empty means sshd trusts no control CA and
nothing can log in), a state disk attached with the fixed `deviceName`
`cogworx-state`, and -- for the hosted storage profile below -- a second data
disk attached with the fixed `deviceName` `cogworx-guest`. Both device names are
cross-repo wire contracts with the control plane, not provider-assigned values:
the host resolves them as `/dev/disk/by-id/google-<deviceName>` and can only
find a disk whose name both halves spell the same way. The guest disk is
**required for a sandbox boot**: a VM without one still reaches
`multi-user.target`, and its sshd and control channel answer normally, but with
no volume group there is nothing for QEMU to open, so no sandbox starts and
`cogworx-supervisor` fatals on serial naming the missing volume. (That is why
`cogworx-guest-disk` itself treats an absent disk as exit 0 -- a resolver VM
boots this same image with no guest disk by design, and that unit runs on every
boot class.) Size the guest disk for both halves of what it carries -- the store
overlay's logical volume is thick, taking `cogworx.gce.storeOverlaySizeMiB`
(16 GiB by default) outright, and the data pool gets the rest.

This image is **hosted-only**: it bakes the `hosted` storage profile and nothing
selects a second one at runtime. It does NOT need `cogbox.storage.profile`
passed to `mkGceHost`, and passing it there would do nothing. `mkGceHost`'s
`extraModules` configure the HOST system, whereas the storage profile is a GUEST
option, and the guest closure is baked inside `packages.cogbox-hosted` (the
runner's store path is substituted into `cogbox-launch.sh`). That is why the
hosted guest is a second `nixosConfiguration` and a second package -- exactly one
of which ships here: `cogbox` on this host is a thin environment wrapper around
`cogbox-hosted`, and the workstation runner is not in the image closure at all.

`packages.gce-image` builds the DEFAULT host config, whose
`controlCAPublicKey` is empty -- fail-closed, and therefore not publishable.
Bake a real image through the `lib.mkGceHost` seam instead:

```
nix build --impure --expr '((builtins.getFlake "/path/to/cc-sandbox").lib.mkGceHost
  "x86_64-linux" { extraModules = [ { cogworx.gce.controlCAPublicKey = "ssh-ed25519 AAAA... control-ca"; } ]; }
).config.system.build.googleComputeImage'
```

`nixosModules.gce-host` exports the host module itself for anyone composing
their own `nixosSystem`. The `gce-image-control-ca` flake check asserts both
halves: that the default bakes no CA, and that the override reaches sshd's
`TrustedUserCAKeys` file.

### The DNS upstream, and why the metadata server is not resolved

`cogworx.gce.vpcResolver` is the single upstream systemd-resolved forwards to,
authoritative for every name with an empty `FallbackDNS` behind it -- so it must
be a full recursive resolver, not a split-horizon forwarder for internal zones.
It defaults to GCE's VPC resolver (which *is* the metadata address), but another
full recursive resolver is also supported. Only the *default* is link-local:
with another resolver, floor rule 1
no longer covers a guest that dials the resolver itself, and that traffic is
ordinary private-range egress governed by the L4 shim and the instance's network
rules like any other. Rule 1's own invariant does not move either way -- the
metadata address stays link-local and stays denied to the guest wholesale.

Because of that, `/etc/hosts` pins `metadata.google.internal` to
`169.254.169.254` unconditionally. Every unit on the boot path (host-key
publish, readiness, the control-certificate principal, the floor's first-boot
address fallback, the attribute scrub) reaches the metadata server by name, so
without the pin a resolver that does not serve that GCE-internal name would
block metadata access. With it, the boot and control path
touches no resolver at all. `gce-image-metadata-pin` asserts the realized
`/etc/hosts` and refuses a resolved configured not to read it.

Leaving the default in place and *choosing* it are indistinguishable in the built
image, so a **publishable** bake has to say which it means: a config that sets
`cogworx.gce.controlCAPublicKey` -- the publishability gate, since a CA-less image
can authenticate no control connection -- while `vpcResolver` still names the VPC
resolver fails to evaluate unless it also sets
`cogworx.gce.allowMetadataResolver = true`. That is not a ban on the default; it
is an acknowledgement, and it exists because the address of a full recursive
resolver comes from an operator-side module: a bake composed without that module
falls back to the default silently, and every sandbox from the published image
then resolves neither internal names nor peering-shadowed public ones, with
nothing failing loudly. The guard is an assertion in the host module rather than a
flake check, for the same reason the control-PAM one is: it has to travel into an
operator's composed build, and an assertion in the operator module would disappear
together with the module whose absence is the bug. `gce-image-resolver-bake`
asserts that it fires, that both documented ways out satisfy it, and that the
CA-less default host still evaluates.

### Composing additional modules

`lib.mkGceHost` accepts `extraModules`. Security-sensitive SSH options are
intentionally constrained by the host module; use
`cogworx.gce.extraTrustedUserCAKeys` to add trusted user CAs. A composed module
that also defines `nix.registry.nixpkgs` must resolve that option conflict
explicitly.

## Limitations

- Linux host with KVM. Build targets: `x86_64-linux`, `aarch64-linux`,
  `riscv64-linux`.
- Per-harness platform availability varies. `claude-code`, `opencode`, `omp`, `codex`, `hermes-agent`, and `pi` all come from `numtide/llm-agents.nix`, which builds them for `x86_64-linux` and `aarch64-linux` only.
- One instance per name at a time (PID lock per runtime directory).
  Multiple differently-named instances can run simultaneously.
- Installed packages do not persist across VM reboots: the writable nix
  store overlay is wiped in both storage profiles -- a tmpfs under
  `workstation`, so on every guest boot; a block volume the host reformats
  under `hosted`, so on every *host* boot (a guest relaunch inside one host
  boot keeps it, which is harmless -- store paths are content-addressed). See
  [pre-populating the store](docs/extensions.md#example-pre-populate-the-nix-store-with-build-deps).
- Changing `overlaySize` only affects newly created overlay images; delete
  the overlay image to recreate with a new size. The `hosted` profile has no
  overlay image at all, so the knob does nothing there.
- Under `hosted`, the two surfaces that already held persistent data are
  migrated once, on the first hosted boot: the `work` tree (from the 9p
  share) and the harness overlay uppers (from the `overlaySize` loop image).
  Either migration refuses rather than half-copies, and a refusal leaves that
  one path on its old home instead of failing the boot. Machine-state that
  lived on the tmpfs root is *not* migrated -- it never survived a reboot to
  begin with. Both are bounded (15 minutes for `work`, 5 for the overlay
  image), because the `work` bind is ordered in front of sshd: a copy that
  wedges would otherwise hold the login prompt for the rest of the boot. A
  migration killed at its deadline writes no marker, so the next boot retries
  it from scratch and the legacy copy stays authoritative meanwhile.
- A completed migration RETAINS the copy it replaced, renamed to
  `work.pre-pool` / `harness-overlay.img.pre-pool` on the same share.
  Renamed, not merely shadowed by the bind: a boot on the pre-pool layout --
  a rolled-back image, or a boot where the pool did not appear -- would
  otherwise present a stale-but-complete-looking tree as if it were current,
  and the next healthy boot would hide whatever was written into it. If a
  fork does form anyway, the pool copy wins and the migration says so loudly,
  naming both paths and both sizes, and retires the other side so the same
  fork cannot form twice. Nothing is ever deleted; reclaiming the
  `.pre-pool` copies is a deliberate later step.
- "The legacy copy is occupied" means it holds a REGULAR FILE -- the same
  definition of content the migration's own `measure()` uses -- and not "it has
  an entry in it". That distinction is the whole point, because on both legs the
  system SCAFFOLDS the legacy surface before anything can look at it, so neither
  copy is ever empty by the time it is judged. `harness-overlay-img` lays a fresh
  ext4 back at the legacy path whenever a hosted instance takes one boot on the
  `workstation` runner, and `harness-setup-dirs` then mkdirs every harness's
  overlay upper/work tree into it; `cogbox-brain-materialize` is wantedBy
  `multi-user.target` in every VM profile and writes `.cogbox/brain`, the
  `.claude/` and `.opencode/` link trees and `AGENTS.md` into `~/work` on any
  boot where the pool bind did not happen. Every one of those writes is a
  directory or a symlink, so the tree's own `files/bytes` reads `0 0` -- and
  judging occupancy by apparent size, or by a readdir, fired the fork warning on
  that non-event and stashed the copy, leaking one `.pre-pool` onto the state
  disk per hosted<->workstation flap with nothing to reclaim it. The harness leg
  still reads the superblock and loop-mounts the image to look inside (it cannot
  be judged from the outside at all), and still prunes `lost+found`; what it
  counts inside is regular files, at any depth, because real harness content is
  nested. Both directions are covered by `cogbox-guest-migrate-behaviour`, which
  seeds those cases by RUNNING the realized scaffolding units rather than
  imitating them: a recreated-and-scaffolded image and a scaffolded `~/work`
  must stay silent and stay where they are, a populated one must still be named
  and retired.
- Under `hosted`, the writable `/nix/store` overlay is a real block volume on
  the guest disk rather than a tmpfs, which is what makes a runaway in-guest
  `nix build` fail with `ENOSPC` instead of OOM-killing the guest. It lives on
  the SAME dedicated disk as the data pool, as a second logical volume, so the
  instance's state disk carries none of it and does not need to be sized for
  it. The **sizing requirement is on the guest disk**: that volume is thick,
  taking `cogworx.gce.storeOverlaySizeMiB` (16 GiB by default) outright, and
  the pool gets only what is left. The two never compete after the fact, since
  the store volume is remade at exactly its own size on every host boot and the
  pool takes the whole remainder; raising the number moves free space from the
  pool to the overlay on the next boot, and lowering it does nothing until the
  instance is recreated (the host never shrinks a volume).
- Network `rules` mode filters at the passt syscall level; traffic
  handled internally by passt (ARP, DHCP, gateway ping responses) is not
  subject to user rules. See
  [enforcement internals](docs/network-filtering.md#enforcement-internals).
