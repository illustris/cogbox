# Internals

How cogbox wires a per-user, per-instance sandbox out of a single prebuilt VM image. Useful when debugging, or when extending cogbox itself.

## Directory layout

Each instance has its own config dir under `~/.config/cogbox/instances/<name>/`. The default instance uses the reserved name `default`, so the config layout mirrors the data layout:

```
~/.config/cogbox/
  authorized_keys              # shared SSH keys (fallback for all instances)
  instances/
    default/
      config.json              # default instance settings (sshPort 2222)
      flake/
        flake.nix              # per-instance NixOS extensions (no-op default)
      plugins-flake/
        flake.nix              # GENERATED plugin composition (only with plugins)
      l7-ca/                   # per-instance L7 terminate CA (key never leaves host)
    work/
      config.json              # auto-generated with unique ports
      flake/
        flake.nix
      authorized_keys          # optional per-instance SSH keys
```

SSH keys fall back to the shared top-level `authorized_keys` unless a per-instance file exists. At launch, cogbox's own public key (`~/.local/share/cogbox/cogbox_ed25519.pub`, see below) is unioned into whichever file is used, so `cogbox ssh` always has an authorized identity.

Data (VM state, overlays) is stored per-instance under `~/.local/share/cogbox/instances/<name>/`. All instances are siblings, so a default-instance boot does not 9p-share named-instance state into the default guest:

```
~/.local/share/cogbox/
  cogbox_ed25519             # cogbox's own SSH key; default identity for `cogbox ssh`
  cogbox_ed25519.pub         # its pubkey, unioned into each guest's authorized_keys
  instances/
    default/
      harness-overlay.img      # shared ext4 overlay for all harnesses
      .config/active-harnesses # newline-separated list of active harnesses
    work/
      harness-overlay.img
```

The keypair sits in the data-dir root, a sibling of `instances/`. Only `instances/<name>/` is 9p-mounted into a guest, so the private key never enters the sandbox. It is generated automatically and reused across all instances; generation is idempotent and re-runs on every launch, so an existing setup gains the key on upgrade and a deleted key is regenerated. `--no-auto-keys` at first init skips generation and writes a durable opt-out marker (`~/.config/cogbox/no-cogbox-key`) so a later plain launch does not re-create the key. The Zig `ssh` and `start` verbs pin ssh to it -- `ssh -i <data>/cogbox_ed25519 -o IdentitiesOnly=yes -o IdentityAgent=none` -- so the user's agent and `~/.ssh` keys are not offered and no agent is contacted (a gpg-agent can't stall or prompt on connect). Under `--no-auto-keys`, where the key is absent, ssh falls back to the user's agent and `~/.ssh` keys.

## Runtime directory and 9p shares

Static QEMU 9p share sources use build-time sentinel paths that the wrapper rewrites into a per-instance symlink directory, so the built VM image works for any user. Launch-only `--add-dir` and `--add-dir-ro` grants use the MicroVM runner's runtime argument hook instead: the wrapper canonicalizes each selected source, stages it behind a numeric alias, and passes only fixed alias-based QEMU tokens. Runtime state lives under `$XDG_RUNTIME_DIR/cogbox` (typically `/run/user/$UID/cogbox`); named instances append a `-<name>` suffix. Each has its own symlinks and PID lock:

```
$XDG_RUNTIME_DIR/cogbox[-<name>]/
  data/                  -> $COGBOX_DATA/instances/<name>
  claude-code-config     -> $COGBOX_CLAUDE_CONFIG
  claude-code-auth       -> $COGBOX_CLAUDE_AUTH
  opencode-config        -> $COGBOX_OPENCODE_CONFIG
  opencode-data          -> $COGBOX_OPENCODE_DATA
  codex-home             -> $COGBOX_CODEX_HOME
  hermes-agent-home      -> $COGBOX_HERMES_HOME
  omp-home               -> $COGBOX_OMP_HOME
  pi-home                -> $COGBOX_PI_HOME
  additional-dirs/
    0                   -> first canonical --add-dir/--add-dir-ro source
    1                   -> second canonical source
  additional-dir-args   # executable producing fixed alias-based -fsdev/-device tokens
  system-additional-dirs # fw_cfg JSON: tag, same-path guest target, read-only mode
  .harness-stubs/        # empty stubs for inactive harnesses (so QEMU
                         # 9p sources resolve even when the host has no
                         # state for a given harness)
  console.sock           # guest serial console (Unix socket)
  monitor.sock           # QEMU HMP monitor (Unix socket)
  netfilter-rules        # rendered L4 + remap runtime rules
  l7-rules               # rendered L7 runtime rules
  console.log            # captured guest serial output
  cogbox.log             # daemon stdout/stderr (passt, QEMU warnings); kept on a failed start for post-mortem
```

If `$XDG_RUNTIME_DIR` is unset and `/run/user/$UID` doesn't exist (no active logind session), the wrapper falls back to `/tmp/cogbox-runtime-$UID/` per the XDG spec.

The numeric aliases and their manifest exist for one VM lifetime. Cleanup waits for QEMU to exit before deleting `additional-dirs/`, `additional-dir-args`, and `system-additional-dirs`, even when a crashed launch retains the rest of the runtime directory for logs. A later flagless launch stages an empty manifest and exposes none of the prior paths.

`cogbox delete [-n <name>]` removes all three of these per-instance trees -- the config dir, the data dir, and the runtime dir -- for one instance. It refuses while the instance is running (stop it first) and prompts before removing anything unless `-y` is given.

## Guest Nix store

On a VM guest (local and hosted) `/nix/store` is an overlay: the lower is the host's whole `/nix/store`, read-only over 9p at `/nix/.ro-store`, and the upper is `/nix/.rw-store/store`. The guest DB registers only the guest closure, so under a plain local store every other host path looked like an invalid path to `nix store gc` (and `nix-collect-garbage`, `nix-store --gc`), which walked it over 9p and left a whiteout for it in the upper, freeing nothing. The guest therefore runs Nix's experimental `local-overlay://` store, which deletes only what is in the upper layer: GC reclaims guest-built and guest-fetched paths, and host paths outside the guest closure stay visible but unregistered.

The lower store's metadata DB is built at boot by a `boot.postBootCommands` fragment (ordered before microvm.nix's own `--load-db`) from the same `regInfo` closure registration, into `/nix/.rw-store/lower-state`, so it is exactly as ephemeral as the upper. It cannot be a build-time derivation: it would close over the toplevel that carries `nix.conf`. The `store =` line reaches `nix.conf` through `!include /run/cogbox/nix-store.conf`, which the fragment writes only after it has checked that the `/nix/store` mount's lowerdir and upperdir are `/nix/.ro-store` and `/nix/.rw-store/store` (allowing the `/sysroot` or `/mnt-root` prefix stage 1 leaves in `/proc/mounts`, which is why Nix's own verbatim `check-mount` is off) and `nix store info` has opened the overlay store. Any failure leaves the guest on the plain local store with a boot-log warning, and the failing step's stderr in `/run/cogbox/nix-store.err` (absent on success). The container target does not use this (its `/nix` is cogworx's CoW overlay). `checks.cogbox-vm` Phase B covers it.

## Launch-time patching

Runtime settings (vcpu, memory, ports) are applied by patching the microvm runner script's QEMU arguments at launch time. Settings that affect the guest (overlay sizes, SSH keys) are written to the instance's data directory where systemd services inside the VM pick them up at boot. The wrapper patches the static QEMU runner's 9p share source paths to point at the instance-specific runtime directory, so the same VM image serves all instances.

Additional host directories avoid runner text injection. Cogbox owns `microvm.extraArgsScript`, which executes `additional-dir-args` after the sentinel rewrite; every generated `-fsdev` references only `additional-dirs/N`. The paired `system-additional-dirs` fw_cfg manifest carries the canonical target and access mode. `cogbox-additional-dirs.service` validates the complete manifest, rejects guest-state and special-filesystem collisions, and mounts each 9p tag at the same canonical absolute path before sshd. Read-only grants are enforced both by QEMU's `readonly=true` export and the guest's `ro` mount option.

Single-file injections (harness auth tokens, the L7 CA certificate, and the additional-directory manifest) go through QEMU's `fw_cfg` instead of a static 9p share: the wrapper passes `-fw_cfg name=opt/<tag>,file=<source>` and a guest systemd service consumes the blob from `/sys/firmware/qemu_fw_cfg` at boot.

Dynamic host-directory grants apply to both workstation and hosted QEMU runners because this plumbing lives in the shared VM module. The container target deliberately has no equivalent: OCI and Kubernetes deployments must select host-directory mounts in their orchestrator, and `cogbox-container` has no VM runner. It declares no `cogbox-additional-dirs.service` either: the unit reads the fw_cfg manifest, which cannot exist in a container, so it would fail at every boot and leave the system degraded (pinned by `checks.guest-additional-dirs-vm-only`).

## Guest extension re-exec

Two sources of guest extension share one mechanism, `--override-input userExtensions`:

1. With [plugins](plugins.md) installed (`.plugins` non-empty in config.json), the wrapper re-execs `nix run` with `userExtensions` pointing at the generated `plugins-flake/`, which composes every plugin module plus the user flake.
2. Otherwise, if the [per-instance flake](extensions.md) differs from the scaffold, `userExtensions` points at `flake/` directly. A pristine scaffold skips the re-exec entirely (the closure would be identical to the baked-in one, and re-evaluating the cogbox flake needs its inputs fetchable).

`COGBOX_REEXECED` breaks the loop after one hop. Non-launch verbs never re-exec.

The re-exec rebuilds cogbox on the host that runs the launcher (for a hosted image, the guest host VM), so `cogbox-tools` (the zig-built `bin/cogbox` and `lib/libnetfilter.so`) is built there or substituted from a binary cache. A store path does not record the CPU its machine code was compiled for, and zig targets the build host's CPU by default: a cache entry built on a host with AVX-512 would die with SIGILL at startup on a host without it. The zig builds are therefore pinned to a fixed level (`zigCpuFlag` in `flake.nix`: `x86_64_v2+avx+aes+pclmul` on x86_64, which keeps zig std's hardware AES-GCM/GHASH paths, and `baseline` on the other Linux systems, which gives up hardware AES there so that the tools also run on aarch64 cores without the crypto extension), and `zig-tests` runs at the same level. The pin is also the x86_64 host floor: on a CPU without AVX, AES-NI or PCLMULQDQ (or a VM whose CPU model hides them, such as `qemu64`/`kvm64`) the tools die the same way, with SIGILL (exit status 132) at startup. `checks.x86_64-linux.cogbox-tools-isa` fails on instructions from the extensions beyond that level (`tests/check_tools_isa.sh`, a static objdump scan against a list of instruction classes, so it also catches paths a startup smoke never reaches, such as SHA extensions in std.crypto), on a lost hardware AES or carry-less-multiply path, and when `cogbox help` does not start under qemu-user on a Sandy Bridge CPU model.

## Plugin brain materialization

The base module declares the `cogbox.*` option tree and folds the merged `config.cogbox` of every plugin into one `cogbox-brain` derivation at build (per-harness native trees + merged opencode/codex/OMP MCP settings + a generated capability index skill). Two base-owned `Type=oneshot` services (modeled on `load-ssh-keys`, ordered `before=sshd.service`) materialize it at boot:

1. `cogbox-brain-materialize` runs after backend state is available and creates the `~/work` (`/root/work` -> `/var/lib/cogbox/work`) symlink, the `~/work/.cogbox/brain` link to the RO store derivation, and per-leaf child symlinks into each harness's real writable dirs (`.claude/skills/<s>`, `.opencode/agents/<a>.md`, `.omp/rules/<r>.md`, `.agents/skills/<s>`, etc.). Before linking it prunes stale links: every symlink in those harness dirs, plus `~/work/.claude/settings.json`, `~/work/.mcp.json` and `~/work/.omp/mcp.json`, whose target is inside an earlier `/nix/store/*-cogbox-brain` path is removed, so a removed plugin's skills, commands, hooks and MCP servers stop applying at the next boot (and an old-brain `.mcp.json` no longer blocks the only-if-absent relink). A link counts only when the store entry itself is a `*-cogbox-brain` (a `-cogbox-brain` deeper in some other store path does not). Regular files, directories, links into the current brain and links anywhere else are never touched (`checks.brain-linkleaves-prune`). A container boot that cannot build the brain falls back to the plugin-less base brain (see `brain.fallback`): no plugin skills, agents, commands, rules or tools, and the prune also removes the links earlier boots left into the previous brain, so nothing from it lingers; the plugin links come back at the next boot whose rebuild succeeds. When Hermes is enabled, it creates the managed runtime skeleton (`~/.hermes/{cron,sessions,logs,memories}`) after the persistent Hermes home is ready and before materializing Hermes skills. In the VM these writes land in the Hermes overlay upper. In the container `/root/.hermes` is linked to the per-instance state PVC at `/var/lib/cogbox-state/hermes-home`; setup replaces only an empty image-scaffold directory and fails closed on a nonempty directory, wrong symlink, or invalid persistent target.
2. `cogbox-brain-trust` pre-accepts Claude Code workspace trust for `~/work` (both `/root/work` and the `/var/lib/cogbox/work` it resolves to) and reconciles stale pre-migration project keys.

The workdir/cwd is base-owned: `programs.bash.loginShellInit` and the harness launchers (`c`/`oc`/`om`/`cx`/`h`/`p`) `cd ~/work` (the launcher also exports `OPENCODE_CONFIG` and merges `cogbox.env`). The contract has no `loginShellInit`/`cwd` surface, so a plugin cannot fight over cwd. See [plugins](plugins.md) for the full contract.

On the container target, `cogbox-toplevel-reconcile` runs `cogbox plugin reconcile` after `multi-user.target` to build and record the per-instance full toplevel the next boot uses. It is best-effort but loud. The verb exits 0 even when the build fails (every failure path only warns), so a failure is a nonzero exit or a `(boot uses baked base)` warning in its output. A failure prints a `cogbox-toplevel-reconcile: FAILED rc=N attempts=M` journal line and writes `instances/<name>/toplevel.reconcile-failed` beside `toplevel.path` (line 1 `time=... rc=... attempts=...`, then the last 40 lines of the verb's output, which carry nix's error lines or the verb's own error message); a clean run removes it. Only this boot unit writes or clears the marker, so it describes the last BOOT reconcile: a later successful build outside it (a live plugin add on the running pod, or the control plane's stopped-instance reconcile) rewrites `toplevel.path` but leaves the marker, so compare its `time=` with `toplevel.path`'s mtime. The pod's nix builds without a sandbox, so a derivation that writes `$HOME` (a Go build) can leave nix's sentinel `/homeless-shelter` behind, and every later derivation then aborts on it. The unit removes it before each attempt and after the last, and retries, up to 3 attempts, while a failed attempt leaves it behind (keyed on the sentinel itself, since nix's own message about it rarely survives the verb's 600-byte stderr tail). The unit always exits 0 (`checks.container-toplevel-reconcile`).

## Runtime tool environments

Where `cogbox.runtimeEnvironment.enable` is on (by default only the hosted guest the GCE image runs), [`cogbox-env`](runtime-environment.md) selects a tool bundle at runtime. Two pieces of the guest wiring live outside `runtime/module.nix`, because `programs.bash.loginShellInit` is `mkForce`d and the launchers are generated in `flake.nix`: both guests' login init prepend `/root/work/.cogbox/runtime/current/bin` after the plugin tool bin (so it ends up first) and print a one-line warning in interactive shells when the selected bin no longer resolves, and every harness launcher puts the runtime bin first in its `PATH`.

`cogbox-runtime-restore.service` restores the selected bundle offline after a restart. It is a background unit: wanted by `multi-user.target`, ordered `After=` it and `cogbox-brain-materialize`, and never `Before=` anything, so sshd, brain materialization and readiness never wait for it. On the hosted guest it also `Wants=` and is `After=` the `nofail` work bind `var-lib-cogbox-work.mount` with `ConditionPathIsMountPoint=/var/lib/cogbox/work`, so a pool-absent boot skips it instead of letting it write under the unmounted path. `checks.runtime-environment` and `cogbox-guest-pool-degradable` assert that graph on the realized units, and `checks.runtime-boot-restore` boots it.

## Guest environment and non-Nix binaries

The L7 CA-trust env (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, …, all pointing at the assembled `/run/cogbox/ca-bundle.crt`) is set both as `environment.variables` (login shells) and `environment.sessionVariables`. The latter matters because the container sshd runs `UsePAM yes`, so `pam_env` delivers `sessionVariables` to *non-interactive* `ssh host cmd` execs — which source no login shell. That is the path VS Code Remote-SSH uses, so its server and tools see the CA bundle.

`programs.nix-ld` is enabled so downloaded, dynamically-linked non-Nix ELF binaries run in the otherwise pure-Nix guest. VS Code Remote-SSH ships a prebuilt glibc `node` (vscode-server) that expects a standard `/lib64/ld-linux` loader; nix-ld provides the `/lib64` stub loader and delivers `NIX_LD`/`NIX_LD_LIBRARY_PATH` via the same `sessionVariables`/`pam_env` mechanism. The stock library set is extended with `stdenv.cc.cc.lib`, `icu`, and `libsecret` for common VS Code extension native binaries.

## Network enforcement

In `rules` network mode, the wrapper loads a Zig shared library (`libnetfilter.so`) into passt via `LD_PRELOAD`. The library intercepts outbound socket calls (`connect`, `sendto`, `sendmsg`, `sendmmsg`) and checks destination addresses against the configured CIDR rules; denied connections receive `ENETUNREACH`. It initializes via `.init_array` (before `main()`) so all file I/O for rule loading completes before passt activates its seccomp-bpf sandbox. Rules hot-reload via `SIGUSR1`; the L7 proxy reloads via `SIGHUP`. The filter's default deny has exactly one exemption, armed only when the launcher is handed `COGBOX_MOSH_UDP_FORWARD`: passt's per-flow reply socket for an inbound datagram on that forwarded UDP range, recognised by its bound local address (see [the mosh reply-socket exemption](network-filtering.md#the-mosh-reply-socket-exemption)). Details, including the remap/SOCKS5 layer and the L7 proxy architecture, are in [network filtering](network-filtering.md).

The `cogbox rules`/`remap`/`l7`/`plugin` verbs all edit `config.json`, regenerate the runtime rules files, and signal the running processes, so policy changes take effect without restarting the VM. The CLI shares the on-disk rule format parser with the LD_PRELOAD filter, so the formats stay in sync.

## Guest reply routing

passt keeps a remote peer's real source address on the forwarded guest ports (sshd 22, the app relay 8080 and the mosh UDP range), so the guest answers a client at, say, 198.51.100.7 by routing to 198.51.100.7. Any more-specific guest route covering that address captures the replies: a Docker bridge auto-assigned from Docker's default pools, a VPN, kind/k3s, podman or a static route. The symptom is that the connecting side never gets the SSH banner (or the HTTP response, or the mosh datagram), while the guest itself looks healthy and other clients work. Every VM guest (local, GCE-hosted, Proxmox-hosted) therefore routes replies to connections that arrived on its uplink back out the uplink, even when a more-specific route in its main table covers the client's address. The container target does not carry it.

The mechanism is `modules/guest-reply-route.nix`, with its ids in flake.nix `guestReplyRoute`. `cogbox-reply-route.service` loads `table ip cogbox_reply`: a prerouting rule sets connmark bit 0x10000000 on new connections whose input interface is in link group 1000, and a `type route` output chain copies that bit to the packet mark, which reroutes the packet. The uplink gets link group 1000 from the `99-ethernet-default-dhcp` match (`Type=ether`, `Kind=!*`), so no interface name is involved; the same .network declares routing rule priority 50 (`fwmark 0x10000000/0x10000000 lookup 1000`) and table 1000 with a default route via the DHCP gateway (`onlink`; networkd also adds the lease prefix route and a host route to the gateway in that table). Guest egress, container egress and guest<->container traffic never carry the bit and keep using the main table. Diagnose with `ip -4 rule` (the priority-50 rule), `ip -4 route show table 1000` (the default via the uplink), `nft list table ip cogbox_reply` (the counters show whether anything matched) and `ip route get <peer> mark 0x10000000` (where a marked reply would go). `systemctl stop cogbox-reply-route` is the kill switch (it deletes the table) and `systemctl start cogbox-reply-route` restores it. The nft half fails open: `nft -f` is one transaction, so a failed unit leaves no table, the rule then matches nothing and routing falls back to the old behaviour. The networkd half is constants only, and networkd owns it because it deletes rules and routes it did not configure.

Residuals, all of which fall back to the old behaviour: UDP servers bound to the wildcard address (their source is chosen from the main table before netfilter runs; mosh-server's default `-s` binds the SSH_CONNECTION address and is covered); IPv6 (passt runs `-4`); a container on the colliding network still cannot reach peers in its own subnet through the guest; a peer whose address equals a guest-local address; strict reverse-path filtering set by a plugin (first packets are dropped before the mark applies); forwarded/DNAT flows, such as a container publishing a port reached through the uplink; a blackhole, unreachable or prohibit route (or rule) covering the peer, because the first route lookup fails before the output chain sees a packet; a flow whose conntrack entry is lost mid-session; and a plugin that claims the uplink with an earlier .network, disables networkd, or enables `networking.nftables` (whose flushRuleset drops the table). `checks.guest-reply-route-vm-only` pins the VM-only wiring at eval time and `checks.guest-reply-route` proves the behaviour in a nested VM against a real Docker network, including both negative controls.

## Host-side path overrides

Override where data lives on the host with environment variables:

| Variable | Default | Description |
|---|---|---|
| `COGBOX_DATA` | `$XDG_DATA_HOME/cogbox` (i.e. `~/.local/share/cogbox`) | Persistent data root. Each instance lives at `$COGBOX_DATA/instances/<name>/`. |
| `COGBOX_CLAUDE_CONFIG` | `$HOME/.claude` | Host claude-code config (overlay lower in VM) |
| `COGBOX_CLAUDE_AUTH` | `$HOME/.claude.json` | claude-code account/telemetry config (incl. the org UUID `/rc` needs), copied in via `fw_cfg`. Holds **no** secret token -- the OAuth tokens live in `COGBOX_CLAUDE_CONFIG`'s `.credentials.json` (overlay, redacted under injection) |
| `COGBOX_OPENCODE_CONFIG` | `$XDG_CONFIG_HOME/opencode` | Host opencode config (overlay lower in VM) |
| `COGBOX_OPENCODE_DATA` | `$XDG_DATA_HOME/opencode` | Host opencode data (auth lives here as `auth.json`) |
| `COGBOX_CODEX_HOME` | `$HOME/.codex` | Host codex home (config, auth, sessions; overlay lower in VM) |
| `COGBOX_HERMES_HOME` | `$HOME/.hermes` | Host hermes-agent home (config.yaml, `.env` credentials, skills; overlay lower in VM) |
| `COGBOX_PI_HOME` | `$HOME/.pi` | Host pi home (`agent/` holds auth.json, settings, sessions; overlay lower in VM) |
| `COGBOX_DSH_HOME` | `$HOME/.dsh` | Host dsh home (settings.yaml, .credentials.yaml, sessions/, profiles/; overlay lower in VM) |

```sh
COGBOX_DATA=/mnt/fast/cogbox nix run .
```

## Running as another user (sudo context)

cogbox resolves the *real* (non-root) user -- whose `$HOME` holds the config, data, and harness credential files -- from `SUDO_USER`, but **only when actually running as root** (euid 0). That is the genuine `sudo cogbox` case, where cogbox acts on the invoking user's behalf and `chown`s the files it creates back to them. When not root, cogbox uses its own identity (`id` / `$HOME`).

This guard matters because `sudo` exports `SUDO_USER` for *every* invocation (including `sudo -u other`), and a non-login `su other` preserves it. So `sudo su <user>` **without** `-` leaves the invoker's `SUDO_USER`/`HOME` in the environment; without the euid guard cogbox would resolve paths to the *invoker*, not the user it now runs as, and write into a directory it can't touch. A fail-fast preflight catches this -- if the resolved home isn't writable by the current uid, cogbox aborts with actionable guidance instead of cascading permission errors.

**To run cogbox as a different user, use a login shell** -- `sudo su - <user>` (or `sudo -u <user> env -u SUDO_USER HOME=/home/<user> cogbox`) -- not `sudo su <user>`. This is the invocation a multi-user control plane must use to launch cogbox per-user.
