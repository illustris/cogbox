# PVE in-place system upgrades

A Proxmox (PVE) sandbox VM is linked-cloned once from a template baked from `pve/`, and its boot disk is also its nix store. To move such a VM to a newer image without re-creating it, cogworxd switches it from one NixOS **system generation** (a toplevel) to another: it fetches the target into the VM's store, arms GRUB's one-shot entry for a single trial boot, and then commits or falls back. This page is the contract between the guest half (`pve/upgrade/`, the tool `cogworx-pve-upgrade` and the GRUB guard) and the control plane that drives it. Example addresses are RFC 5737, `cache.example` stands for a site's binary cache, and every name is generic.

"Generation" alone is ambiguous in this tree (the guest also has runtime tool generations, see [runtime-environment.md](runtime-environment.md)), so this page always says **system generation**.

Only images built from a tree that ships `pve/upgrade/` are upgradeable in place. A VM cloned from an older template has no tool, no guard, no pin source and no panic parameters, and it is never upgraded in place.

## What every system generation carries

`pve/upgrade/module.nix`, imported by `pve/pve-host.nix`, adds to every system generation:

| Item | Where | Why |
|---|---|---|
| The tool | `<toplevel>/sw/bin/cogworx-pve-upgrade` | cogworxd runs it by store path. Nothing on the VM runs it; the `pve-unit-graph` check pins that no rendered unit names it. |
| The compat doc | `<toplevel>/cogworx-pve-compat.json`, a regular file | What the guest and cogworxd compare before a switch (below). |
| The GRUB guard | `boot.loader.grub.extraConfig` = `pve/upgrade/grub-guard.cfg` | Decides at boot time whether the pending one-shot may run. Only the BASE image's copy is ever rendered (see the pin). |
| `panic=10 boot.panic_on_fail` | `boot.kernelParams` | A candidate whose stage 1 fails crashes and reboots onto entry 0 instead of hanging. The kernel-params of each generation are used, so every generation needs them. |
| The nix-gc lock wrapper | `cogworx-nix-gc.service` | `flock --nonblock --conflict-exit-code 75 /run/cogworx-pve-upgrade.lock <gce collector>`, with `SuccessExitStatus=75`: a collection skips while the tool holds its lock. A tmpfiles rule creates the lock file root-owned 0600 at boot (see the lock). |
| `cogworx.pve.release` | option, default `null` | `{ id; builtAt; }` for a release bake. The tool refuses a target whose release is null, so a dev build is never an upgrade target. |

The flake's `lib.mkPveHost` also sets `system.configurationRevision = lib.mkDefault (self.rev or self.dirtyRev or null)`, so `nixos-version --configuration-revision` names the source of each system generation.

## Roles and trust

Only cogworxd calls the tool, over the existing control channel, as root on the VM's trusted half. Each verb has a required copy of the tool, addressed by the UNRESOLVED path `sys.argv[0]`:

| Verb | argv[0] must be `<S>/sw/bin/cogworx-pve-upgrade` with S = | Booted system must be | Lock |
|---|---|---|---|
| `proto`, `status`, `closure-digest` | any path (also an operator workstation build) | any | none |
| `fetch`, `_fetch` (worker), `arm`, `release` | committed | committed | exclusive |
| `commit` | committed | `txn.target` | exclusive |
| `abort` | committed | committed, `txn.target` or `rollback.path` | exclusive |
| `revert-commit` | `rollback.path` | `rollback.path` | exclusive |

"Committed" is always `txn.json`'s `committed.path` (or the bootstrap value), never the system profile head. Two system generations whose tool package is identical share one realpath, so only the invoked path tells them apart: the package is one file whose first line is `#!<python3> -I`, and nothing may wrap it. A violation exits 65 `not-committed-tool`.

The guarantee is narrow: the target's copy of the tool never writes profiles, `txn.json` or GRUB state before the target is committed. That protects against a bug in a new tool, not against a hostile target, whose kernel, initrd and daemons run as root during the trial. Against a hostile target the defenses are the closure digest and the release process.

The tool never runs `switch-to-configuration`, `nixos-rebuild` or `grub-install`, and never runs any generation's own `installBootLoader`: each one calls `grub-install` whenever its GRUB differs from `/boot/grub/state`, which would rewrite the MBR.

## Transport

The control channel single-quotes every argv element.

| Verb | cogworxd call | Timeout |
|---|---|---|
| `proto`, `status`, `closure-digest` | a bounded read (stdout at most 64 KiB, may be killed at the deadline) | 30 s |
| `fetch` (the launcher) | an exec under the instance lock | 60 s |
| `arm` | exec | 75 s |
| `commit` | exec | 90 s |
| `abort` | exec | 75 s |
| `revert-commit` | exec | 90 s |
| `release` | exec | 75 s |

The timeouts are cogworxd's; the tool does not enforce them. Measured in `pve-upgrade-vm` (KVM, 8 GiB disk): every installer run took at most 0.21 s, `arm` at most 0.30 s, `commit` 0.49 s, `abort` 0.62 s, `revert-commit` 0.25 s and the `fetch` launcher 0.36 s (including its wait for the worker to register), so the budgets above are dominated by the transport, not the tool. A trial boot to multi-user took 11-16 s; a candidate that fails adds a second boot inside the trial window (a missing initrd or a kernel GRUB cannot load about 12 s more, a stage-1 panic about 4 s more with the test's `panic=1`; production's `panic=10` adds 9 s). The tool ignores SIGHUP and SIGPIPE, makes every mutation before it prints anything and swallows EPIPE on its final write, so a verb whose caller has gone still finishes and records its outcome. After a transport error or a deadline on a mutating verb, cogworxd never re-issues blindly: it polls `status` until `lock.held` is false and then decides from `txn.state`.

## Argument grammar

Every pattern is a full match (Python `re.fullmatch`, Go `^...$` without `(?m)`; Python's `re.match('^...$')` accepts a trailing newline).

| Name | Pattern |
|---|---|
| SYS | `/nix/store/[0-9a-df-np-sv-z]{32}-nixos-system-[A-Za-z0-9._+-]{1,200}` |
| TXN | `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` |
| CLOSURE | `[0-9a-f]{64}` |
| TIME | `[0-9]{4}-(0[1-9]\|1[0-2])-(0[1-9]\|[12][0-9]\|3[01])T([01][0-9]\|2[0-3]):[0-5][0-9]:[0-5][0-9]Z` |
| BYTES | `[1-9][0-9]{0,15}` |

argv[1] is the verb. Options are `--name value` pairs or bare `--flag`s, each at most once, in any order; no `--name=value`, no positionals; at most 12 elements, each printable ASCII and at most 320 bytes. A violation exits 64 before any file is read.

| Verb | Grammar |
|---|---|
| `proto` | (none) |
| `status` | (none) |
| `closure-digest` | `--target SYS` |
| `fetch` | `--txn TXN --target SYS --closure CLOSURE [--closure-bytes BYTES] [--release-rollback]` |
| `_fetch` | `--txn TXN` (the worker; refused with 64 outside its transient unit) |
| `arm` | `--txn TXN` |
| `commit` | `--txn TXN (--retain-until TIME \| --no-rollback)` |
| `abort` | `--txn TXN [--release-staged]` |
| `revert-commit` | `--txn TXN` |
| `release` | `--txn TXN` |

- `--closure-bytes` is the release's total closure size; it caps the headroom estimate when the guest cannot measure the missing set.
- `--release-rollback` lets the fetch worker drop the rollback under headroom pressure. cogworxd sends it only when its own clock is past the rollback's retention, so the guest clock never decides a release.
- `--no-rollback` commits without keeping the previous system.

Order of checks for every invocation: (1) the grammar (64); (2) for a mutating verb, the idempotent re-report; (3) the argv[0] rule (65); (4) the lock (75); (5) the verb's preconditions.

**Idempotent re-report.** If `--txn` names the newest txn and that txn is already closed with this verb's outcome (`commit` -> committed, `abort` -> aborted or repaired, `revert-commit` -> reverted, `release` -> released), or is open in the state this verb would leave (`arm` in armed while grubenv's `next_entry` is still set; `fetch` with the same `--target` and `--closure` in fetching with the worker active, or fetched), the tool answers exit 0, `mutated: false`, before the argv[0] rule. So the old tool can re-ask after a commit moved `committed` to the target. An `arm` exit 0 therefore always means the one-shot is pending: once a boot consumed it (`d:`, `u:`, or a trial followed by another reboot) the txn is still `armed` but nothing is armed in GRUB, and a re-issued `arm` is 65 `state` ("one-shot consumed: abort"). An id that only `history` still holds re-reports nothing: every verb refuses it (see the state machine notes).

## Output

stdout carries exactly one JSON object (ASCII, sorted keys, compact) and one newline, at most 64 KiB; stderr is diagnostics only.

```json
{"cogworx_pve_upgrade":1,"exit":0,"mutated":true,"ok":true,"reason":null,"reason_class":null,"status":{"...":"..."},"txn_id":"3c4d5e6f-7081-4293-a4b5-c6d7e8f90a1b","verb":"arm"}
```

- `cogworx_pve_upgrade` is the tool protocol; v0 cogworxd requires exactly 1.
- `exit` repeats the process exit code and `ok` is `exit == 0`.
- `reason` is ASCII, at most 512 bytes, with no newline and no `"`; cogworxd still sanitizes it as guest text.
- `mutated` says whether THIS invocation changed guest state. A 65 from a step that failed halfway can have `mutated: true`; `status.txn.state` then shows where it stopped.
- `status` (the object below, taken after the verb's last step) is absent for `proto`, `closure-digest` and exit 64. If the whole object would exceed 64 KiB, `status.compat` is dropped and the exit is 70 `output-too-large`. `status` can also be absent when the tool could not build it (only a diagnostic on stderr says why) or when it is still over 64 KiB without `compat`; cogworxd then re-reads `status`, and the envelope's exit and `reason_class` still stand.

`proto` adds `"proto": {"proto": 1, "txn_schema": [1], "compat_schema": [1], "verbs": [...the nine public verbs...], "tool": "<realpath of the script>", "guard": "<txn.json's pin.guard if pinned, else the marker in the committed compat doc's installer XML, else null>"}`.

`closure-digest` adds `"closure_digest": {"target", "closure", "paths", "nar_bytes"}` (`nar_bytes` is the sum of `nix-store -q --size`).

### The status object

```json
{
  "booted": "SYS|null", "current": "path|null", "system_head": "path|null",
  "committed": "SYS|null", "committed_source": "txn|bootstrap", "entry0_init": "SYS|null",
  "candidate": "SYS|null",
  "rollback": {"path": "SYS|null", "recorded": "SYS|null", "retain_until": "TIME|null"},
  "next_entry": "string|null", "cwx_rollback_entry": "string|null", "cwx_once": "string|null", "grubenv_ok": true,
  "grubcfg": {"ok": true, "sha256": "<64 hex>|null", "errors": [], "entry0_title": "NixOS|null",
              "candidate_entry": {"path": "<title path>", "init": "SYS"},
              "rollback_entry": {"path": "<title path>", "init": "SYS"}},
  "bootloader_pin": {"state": "pinned|unpinned|mismatch", "installer": "...", "perl": "...", "script": "...", "xml": "...",
                     "grub": "...", "devices": ["/dev/vda"], "distro": "NixOS", "guard": "cwx-guard-v1|null",
                     "boot_area_sha256": {"/dev/vda": "<64 hex>"}},
  "txn": {"schema": 1, "id": "TXN", "kind": "switch|revert|release|repair", "state": "...",
          "committed": "SYS", "target": "SYS|null", "closure": "CLOSURE|null",
          "reason_class": null, "reason": null, "progress": {"...": "fetch worker progress, or null"},
          "opened_at": "TIME", "updated_at": "TIME", "closed_at": "TIME|null"},
  "compat": {"committed": {"...": "compat doc"}, "target": null},
  "free_bytes": "int|null",
  "lock": {"held": false, "holder": "verb|fetch-worker|gc|unknown|null", "pid": null},
  "worker": {"active": false, "txn": null},
  "trial": false,
  "crash_state": []
}
```

- `booted` = `realpath(/run/booted-system)`, `current` = `realpath(/run/current-system)`, `system_head` = the resolved system profile (reported only; nothing decides on it except the bootstrap check). `booted` is null when `/run/booted-system` is missing or not a system toplevel (`status` then exits 69 `unavailable`, with this object); `current` and `system_head` are null when they do not resolve.
- `committed` is null when `txn.json` is unreadable (`crash_state: ["txn_unreadable", ...]`) and, before the first `txn.json`, when the bootstrap check fails (`bootstrap_inconsistent`); otherwise it is `txn.json`'s value (`committed_source: "txn"`) or the booted system (`"bootstrap"`).
- `entry0_init`, `candidate_entry` and `rollback_entry` come from parsing `/boot/grub/grub.cfg`; `next_entry`, `cwx_rollback_entry` and `cwx_once` from parsing `/boot/grub/grubenv` directly. `next_entry` and `cwx_rollback_entry` are null when absent OR empty: GRUB itself writes `next_entry=` (an empty value) when it consumes the one-shot, so a Go reader of the raw grubenv sees `""` where `status` says null. `cwx_once` is null only when absent. When grub.cfg cannot be read, `grubcfg.sha256` and `entry0_title` are null and `grubcfg.errors` is `["unreadable"]`.
- `rollback.path` is the resolved `system-profiles/cogworx_rollback`, `rollback.recorded` the `txn.json` value.
- `txn` is the NEWEST txn, open or closed, so cogworxd learns the outcome of a txn whose answer it lost; null before the first.
- `trial` is derived: `txn.state == "armed" && booted == txn.target`. No stored state is called "trial".
- `free_bytes` is statvfs(`/nix/store`) `f_bavail * f_frsize`, null when statvfs fails.
- `progress` (from the volatile `/run/cogworx-pve-upgrade/progress.json`): `{pid, txn, phase: lock-wait|dry-run|headroom|realise|digest|compat|done, attempt, missing_at_start, started_at, updated_at}`, plus `result` at phase `done`: the worker's verdict as `<state>` or `<state>:<reason_class>` (for example `fetched` or `fetch_failed:signature`), or `not-fetching` when the worker found its txn no longer `fetching` and did nothing.
- `status` is lock-free and nix-free: it reads files, symlinks, `/proc` and statvfs only, so it works while the fetch worker holds the lock. The worker counts as active when the holder note names `fetch-worker`, or progress.json is not `done`, AND that pid is alive with `/proc/<pid>/cgroup` ending in `cogworx-pve-upgrade-fetch.service`: a SIGKILLed worker leaves both files behind, and its pid can be reused within the boot.
- `crash_state` tokens are a snapshot; while another process holds the lock, decide on them only once `lock.held` is false.

## Exit codes

| Code | Meaning | Mutated | cogworxd action |
|---|---|---|---|
| 0 | done (`fetch`: the worker started, or already ran or runs for this txn) | per `mutated` | proceed |
| 64 | usage: a grammar violation | no | caller bug |
| 65 | refused: `reason_class` says why | per `mutated` | map the class (below) |
| 69 | unavailable: a required facility is missing (`/run/booted-system`, the committed compat doc, a child command, a pinnable installer) | no | refuse with an admin note |
| 70 | internal: an unexpected error; mutation unknown | unknown | re-read `status`; if still unprovable, hold Unsafe |
| 75 | busy: the lock is held | no | poll `status` until `lock.held` is false, then retry |
| anything else, a signal, 127, unparseable stdout | unknown (127: no tool at that path, for example a VM cloned from an older template) | unknown | treat as 70 |

`main` turns every uncaught exception into 70; the tool never exits 1 or 255 on purpose (255 is the control channel's transport verdict).

## Reason classes

Synchronous (a verb exits 65, 69, 70 or 75), a closed set:

| Class | Exit | Meaning |
|---|---|---|
| `state` | 65 | the txn state does not allow this verb |
| `txn-mismatch` | 65 | `--txn` is not the guest's open txn (its id is in `status.txn.id`) |
| `booted-mismatch` | 65 | the booted system is not what this verb requires |
| `not-committed-tool` | 65 | the argv[0] rule failed |
| `bootstrap-inconsistent` | 65 | no `txn.json`, and booted, head and entry 0 disagree, or a `system-profiles/cogworx_*` profile exists |
| `crash-state` | 65 | `arm` or `fetch` refused: `crash_state` holds more than `current_differs` (a `fetch` that resumes its own txn also tolerates `interrupted`) |
| `bootloader` | 65 | pin missing or mismatched, `/boot/grub/state` or the boot area changed, or the installer failed |
| `grub-parse` | 65 | grub.cfg after an installer run lacks entry 0 or the expected submenu entry; or, before commit's first step (`mutated: false`), the committed system's `nixos-version` could not title the rollback entry |
| `grubenv` | 65 | grubenv not creatable, an overflowing write, or a read-back mismatch |
| `compat` | 65 | a guest compat rule failed; `reason` names it (`compat:<rule>[:<field>]`, `compat:xiii:unreadable` or `compat:doc`, see the compat rules) |
| `schema` | 65 | `txn.json` has a newer schema than this tool reads |
| `busy` | 75 | the lock is held |
| `unavailable` | 69 | see exit 69 |
| `internal` | 70 | see exit 70 |
| `usage` | 64 | grammar |

Fetch worker verdicts, in `status.txn.reason_class` when `state == "fetch_failed"`. nix-store's stderr is matched with `LC_ALL=C`, first match wins. The strings are nix 2.34's:

| Class | Matched when |
|---|---|
| `enospc` | `No space left on device` |
| `headroom` | the headroom gate failed (no realise ran) |
| `integrity` | the closure digest differs from `--closure`, or stderr has `hash mismatch importing path` or `hash mismatch for` |
| `signature` | stderr has `as it's not signed by any of the keys in 'trusted-public-keys'` and the realise or dry run failed |
| `not-found` | stderr has `is required, but there is no substituter that can build it` or `don't know how to build these paths` (and no signature line) |
| `unreachable` | stderr has `unable to download`, `HTTP error`, `Couldn't resolve`, `Could not resolve`, `Connection refused`, `Connection timed out` or `timed out`, and nothing above matched |
| `compat` | a guest compat rule failed on the target |
| `interrupted` | SIGTERM, or a boot found `fetching` with no live worker |
| `internal` | anything else |

`pve-upgrade-vm` pins `not-found` and `signature` on nix 2.34.8's real output. A path no substituter has: the dry run prints `don't know how to build these paths:` and the path, so no realise runs. An unsigned path: the dry run still reports `this path will be fetched (...)` (it does not check signatures), and the realise prints `warning: ignoring substitute for '<path>' from '<cache>', as it's not signed by any of the keys in 'trusted-public-keys'` followed by `error: path '<path>' is required, but there is no substituter that can build it`; the signature line wins.

"Incomplete" (the fetch slice ran out) is cogworxd's own classification: the worker reports `interrupted` plus `progress`, and cogworxd compares `missing_at_start` across attempts.

## txn.json (schema 1)

`/var/lib/cogworx-pve-upgrade/txn.json`, mode 0600 in a 0700 directory, on the boot disk.

```json
{
  "schema": 1, "seq": 17,
  "committed": {"path": "SYS", "closure": "CLOSURE|null", "since": "TIME"},
  "rollback": {"path": "SYS", "closure": "CLOSURE|null", "retain_until": "TIME|null"},
  "staged": "SYS|null",
  "pin": {"installer": "...-install-grub.sh", "perl": ".../bin/perl", "script": "...-install-grub.pl", "xml": "...-grub-config.xml",
          "grub": "...", "devices": ["/dev/vda"], "distro": "NixOS", "guard": "cwx-guard-v1|null", "boot_area_sha256": {"/dev/vda": "<64 hex>"}},
  "txn": {"id": "TXN", "kind": "switch|revert|release|repair", "state": "...", "target": "SYS|null", "closure": "CLOSURE|null",
          "pre": {"rollback": {"...": "..."}, "cwx_rollback_entry": "string|null"},
          "fetch": {"attempts": 1, "missing_at_start": {"paths": 412, "bytes": 0}, "release_rollback": false, "closure_bytes": "int|null"},
          "arm_boot_id": "BOOT_ID", "commit": {"retain_until": "TIME|null", "no_rollback": false},
          "aborted_from": "STATE|null", "reverted_from": "SYS",
          "reason_class": null, "reason": null, "opened_at": "TIME", "updated_at": "TIME", "closed_at": "TIME|null"},
  "history": [{"id": "TXN", "kind": "switch", "outcome": "committed", "target": "SYS", "closed_at": "TIME", "previous": "SYS"}],
  "writer": {"tool": "<realpath>", "argv0_system": "SYS"}
}
```

- `rollback` is null when there is none; `txn` is null before the first txn; `history` holds at most 16 entries (one per closed txn, plus a `released-for-headroom` one), newest first; `seq` grows by one per write.
- A history entry may carry `rollback_lost: SYS`: the abort that closed it found the rollback it had to restore gone from the store, and closed with `rollback: null` (see abort step 4).
- Keys a verb writes and a later run of the same or another verb reads, so every schema-1 writer must keep writing them with this meaning (each is present only once its verb ran):
  - `fetch.closure_bytes`: `--closure-bytes`, or null; a resumed attempt caps the dry run's missing-bytes estimate with it.
  - `arm_boot_id`: the kernel boot id `arm` step 1 recorded; an `arm` redo from `arming` runs only in that same boot (else 65 `state`, abort first).
  - `aborted_from`: the state `abort` found (null for a `repair`); from `committing` or `reverting` abort step 4 restores `pre.rollback`, from any other state the recorded rollback.
  - `reverted_from`: the committed system a `revert-commit` replaces; copied into its history entry.
  - `commit`: the commit's arguments (`--retain-until`, `--no-rollback`); informational, a re-run takes its own.
- History entries carry `id`, `kind`, `outcome`, `target` and `closed_at`, plus per outcome: `previous` (committed: the system committed before), `reverted_from` (reverted), `rollback` (released and `released-for-headroom`: the system released, or null) and `rollback_lost` (aborted or repaired). A `released-for-headroom` entry (kind `release`, `target` null) is written by the fetch worker's inline release under the id of the switch txn it ran for, which stays open; that txn's own close adds a second entry with the same id.
- `pre` holds the pre-images of the rollback, written in the same write that enters `committing`, `aborting`, `reverting` or `releasing`.
- **Write discipline:** `txn.json.tmp` in the same directory, fsync, rename, fsync the directory; one write per transition. Additive only within schema 1: readers ignore unknown keys and a key never changes meaning. A tool never overwrites a file it cannot parse (70, `crash_state: txn_unreadable`) or whose schema is newer (65 `schema`).
- **New values need a schema bump.** "Additive" covers keys, not values: a reader accepts only the `txn.state` and `txn.kind` values it knows and treats any other as an unreadable file (70 `txn_unreadable`). Since `revert-commit` runs the older tool on the newer tool's file, adding a state or a kind requires a `txnSchema` bump, which rule ix then keeps away from a guest that still has a rollback to the older tool.
- **Forward compatibility:** `revert-commit` runs the OLDER tool against a file the newer tool wrote, so compat rule ix requires equal `txnSchema` between a target and the committed system.
- **Bootstrap** (no file yet, the state of every fresh clone): `committed = booted` only if `booted == system_head == entry0_init`; otherwise 65 `bootstrap-inconsistent`. Any existing `system-profiles/cogworx_*` profile is `untracked_profile`, refuses bootstrap and is never deleted. The first mutating verb writes the file, the pin and the `committed` GC root.

GC roots, under `/nix/var/nix/gcroots/cogworx-pve-upgrade/`: `bootloader` (the pinned `install-grub.sh`), `staged` (the fetched target, made by `nix-store --realise --add-root`) and `committed` (the committed toplevel). `committed` keeps the system `txn.json` names as committed in the store for as long as it does: across a `--no-rollback` commit nothing else roots it once step 3 removed the rollback, and its tool is the only one that may repair. So commit and revert-commit move the roots only AFTER their closing write (step 9); a cut between the two leaks a root and loses nothing, and `fetch`, `arm`, `abort`, `revert-commit` and `release` re-assert `committed` at their step 1 (the next realise or commit replaces `staged`). Profiles: `system` (the head), `system-profiles/cogworx_candidate` (the armed target) and `system-profiles/cogworx_rollback` (the previous system). Removing a profile unlinks `<name>` and every `<name>-<N>-link`: generation links are GC roots that never show in the menu.

## State machine

| State | Open | Meaning |
|---|---|---|
| `fetching` | yes | the worker runs for `txn.target` |
| `fetch_failed` | yes (pre-arm) | the worker ended with `reason_class` |
| `fetched` | yes (pre-arm) | the target is realised, digest-verified, rooted as `staged`, and passed the guest compat rules |
| `arming` / `armed` | yes | arm in progress / candidate profile set, grub.cfg verified, `next_entry` set and read back |
| `committing` / `committed` | yes / closed | `committed.path := target`; rollback per the commit arguments |
| `aborting` / `aborted` | yes / closed | the invariants restored for `committed` |
| `reverting` / `reverted` | yes / closed | (kind `revert`) `committed.path := the rollback`; rollback null |
| `releasing` / `released` | yes / closed | (kind `release`) the rollback dropped |
| `repaired` | closed | (kind `repair`) `abort` with no open txn restored the invariants |

| From | Verb (condition) | To |
|---|---|---|
| none or closed | `fetch` (new id) | `fetching` |
| `fetching` with a live worker, same id | `fetch` | no-op (0, `mutated: false`) |
| `fetching` with a dead worker, or `fetch_failed`, same id, same target and closure | `fetch` | `fetching` (resume; valid paths are kept) |
| any open txn, different id or arguments | `fetch` | 65 `txn-mismatch` |
| `fetched` (or `arming`, same id) | `arm`, booted committed | `arming`, then `armed` |
| `armed` or `committing` | `commit`, booted target | `committing`, then `committed` |
| any open state | `abort` (same id) | `aborting`, then `aborted` |
| none or closed | `abort` (new id) | kind `repair`, then `repaired` |
| closed, rollback present (or `reverting`) | `revert-commit` (rollback tool, booted rollback) | `reverting`, then `reverted` |
| closed, rollback present (or `releasing`) | `release` (new id) | `releasing`, then `released` |

- `fetch` requires booted == committed (65 `booted-mismatch`) and target != committed (65 `state`); a target equal to `rollback.path` is allowed. Like `arm`, it refuses (65 `crash-state`) while `crash_state` holds more than `current_differs`, except that a resume of its own txn also tolerates `interrupted`.
- `release` refuses with `state` while a txn is between `arming` and `committing`.
- Every mutating verb acts on the GUEST's open txn id (`status.txn.id`). To start over, cogworxd aborts the old pre-arm txn, with `--release-staged` only when the next target differs, and then fetches under its own id.
- `--txn` is a lowercase RFC 4122 UUID (the TXN grammar) that cogworxd mints fresh for each switch, stale cleanup or release and records with the switch fence. It is NOT cogworxd's operation id, whose format does not match TXN (exit 64). An id is never reused: `fetch`, `abort`, `revert-commit` and `release` refuse to open a new txn under the id of a closed one that `txn.json` still records, the newest txn or any id among the last 16 `history` entries (65 `state`, `mutated: false`); `arm` and `commit` never open one. Only the verb whose outcome closed the NEWEST txn re-reports. So a stale retry of an older leg (crash adoption re-issues a leg under its recorded id) is refused instead of acting on a newer commit, for example a `release` that would drop the rollback a later commit made. The guard reaches as far as `history` does; cogworxd does not rely on it beyond those 16 entries.

## Step tables

Every numbered step sets an ABSOLUTE value, ends with `os.sync()`, and re-running a verb from step 1 is always safe. Every installer run is followed by a fresh grub.cfg parse and the post-run checks (state file and boot area unchanged). Menu entries are addressed by TITLE paths copied from that parse.

**Pre-checks of fetch-end and arm** (no mutation): the guest compat rules, including the bootable shape, run before any profile points at the target. install-grub.pl silently skips a toplevel without kernel, initrd or nixos-version and leaves an EMPTY submenu, which GRUB rejects for the whole file.

**fetch (the launcher)**. Pre: booted == committed (65 `booted-mismatch`); target != committed (65 `state`); no open txn and an id never used (65 `state`), or the same open id in `fetching` or `fetch_failed` with the same target and closure (65 `txn-mismatch`); `crash_state` holds nothing but `current_differs`, plus `interrupted` on a resume (65 `crash-state`). (1) lock, bootstrap if needed, write `fetching` (`fetch.attempts += 1`), re-assert the `committed` root; (2) `systemd-run --unit=cogworx-pve-upgrade-fetch --collect --quiet -p Nice=19 -p IOSchedulingClass=idle -p TimeoutStopSec=20s -p KillMode=control-group -- <argv0> _fetch --txn <id>`. If that fails and no worker of this txn runs, a previous worker that has just released the lock may still own the unit name: the launcher polls `systemctl is-active` (at most 5 s) until the unit is neither running nor stopping and tries once more; a second failure records `fetch_failed` / `internal` and exits 69. (3) wait up to 5 s for the worker to register, then unlock and return. systemd-run returns at fork, and the worker writes progress.json (phase `lock-wait`, its pid inside the worker unit) before it waits for the launcher's lock, so the launcher's own `status` normally shows `worker: {active: true, txn: <id>}`. If the worker has not registered within 5 s the exit is still 0 with reason `the fetch worker started; it has not registered yet`, and that `status` shows the `fetching` txn as `interrupted` with an inactive worker: cogworxd re-polls `status` for a few seconds before it acts on that `interrupted` (an abort would end a healthy fetch). A power cut leaves `fetching` with no worker: `interrupted`; resume with `fetch` or `abort`.

**_fetch (the worker)**, inside the transient unit only:

1. Lock with a bounded wait (60 s, phase `lock-wait`); write the holder note and progress.
2. Dry run `nix-store --realise --dry-run <target>` with the options of step 4. Parse `these N paths will be fetched (X download, Y unpacked):` or `this path will be fetched (X download, Y unpacked):`; no such line means nothing is missing. `missing_bytes = Y`, capped by `--closure-bytes`; unparseable and no `--closure-bytes`: `internal`.
3. Headroom: `free_bytes - 1.5 * missing_bytes - reserve >= floor` (floor 12 GiB, the gce collector's own floor; reserve 4 GiB). On failure with `--release-rollback` and a rollback present: release it inline (the pin is re-verified BEFORE the rollback profile goes; then release steps 2-4 with the same parse check; history `released-for-headroom`), run `nix-store --gc --max-freed <deficit>`, re-measure. Still short: `headroom`. A refusal inside the inline release (pin, installer or parse) ends the worker with `fetch_failed` / `internal` and that reason (`interrupted` when a stop caused it, below).
4. `nix-store --realise <target> --add-root .../staged --option require-sigs true --option narinfo-cache-negative-ttl 0 --option max-jobs 0 --option builders "" --option fallback false --option fsync-store-paths true`, in its own session. `fsync-store-paths` makes every path durable before it is registered valid, so no post-crash verify pass is needed.
5. `os.sync()`.
6. Closure digest == `--closure`, else `integrity`.
7. Guest compat rules, else `compat`.
8. `staged = target`, state `fetched`.

On SIGTERM the worker kills the nix-store session (TERM, then KILL after 10 s), records `fetch_failed` / `interrupted` and exits within 20 s. `systemctl stop` signals every process in the unit (`KillMode=control-group`), so a stop during the digest or the inline release also kills that step's child; a step that fails after a stop was received is recorded as `interrupted` too, never `internal`, and the worker checks for a stop after the realise and after the digest. `abort` of the worker's own txn first stops the unit (bounded 30 s).

**arm** (argv0 committed, booted committed, state `fetched`, or `arming` with the same id). Pre: the pin matches `/boot/grub/state`; grubenv valid or absent; no candidate profile; compat and bootable shape; `crash_state` clean apart from `current_differs`.

| # | Step | Power cut after it: next boot | Repair |
|---|---|---|---|
| 1 | write `arming`; create grubenv with the pinned `grub-editenv` if absent; re-assert the `committed` root | committed | `abort` |
| 2 | `nix-env -p .../system-profiles/cogworx_candidate --set <target>` | committed | `abort` |
| 3 | installer with `<committed>` | committed | `abort` |
| 4 | parse: no errors; entry 0 == committed; the candidate submenu holds one entry == target; the rollback submenu (if recorded) one entry == rollback. On failure: remove the candidate, re-run the installer, and parse again: when that render is the expected menu without a candidate, write `fetched` with `grub-parse` and exit 65 `mutated: true`; when it is not either (the cause is outside the candidate, for example a damaged rollback toplevel), exit 65 `grub-parse` leaving the txn in `arming`, so `crash_state` shows `interrupted` (plus `grubcfg_invalid` or `entry0_mismatch`) and cogworxd never reboots onto that grub.cfg | committed | (self-repaired), or `abort` |
| 5 | `grub-editenv unset cwx_once boot_once`; `set cwx_rollback_entry=<rollback title path>` or unset | committed | `abort` |
| 6 | `grub-editenv set next_entry=<candidate title path>` | the guard decides (one-shot pending) | `abort` |
| 7 | read grubenv back (`next_entry` and `cwx_rollback_entry` as written, no `cwx_once`, no `boot_once`); write `armed` | (trial) | n/a |

**commit** (argv0 committed X, booted target T, state `armed` or `committing`). Pre: the pin matches; with `--retain-until`, X's `nixos-version` passes rule xiii's clause, else 65 `grub-parse` with nothing changed (`mutated: false`; cogworxd commits `--no-rollback` or aborts). Step 5 renders X as the rollback entry, whose title carries that version, and a render that fails there cannot be undone; every committed system but the base passed rule xiii as a target, and the base (bootstrap) system never did. Every power cut is followed by a boot with no `S`, the one-shot having been consumed by the trial boot:

| # | Step | Next boot | Repair |
|---|---|---|---|
| 1 | write `committing`; from `armed`, record `pre = {rollback, cwx_rollback_entry}` | X | `abort` (X's tool; restores `pre` while it is in the store, see below) |
| 2 | `nix-env -p .../system --set T` ("head = target, entry 0 = old") | X | `abort` |
| 3 | `--retain-until`: rollback profile `--set X`, `--delete-generations old`; `--no-rollback`: remove the rollback profile | X | `abort` |
| 4 | remove the candidate profile | X | `abort` |
| 5 | installer with T; parse: entry 0 == T, no candidate submenu, rollback submenu == X (absent with `--no-rollback`) | T | `commit` (X's tool) |
| 6 | `set cwx_rollback_entry=<rollback title path>` (or unset); `unset next_entry` | T | `commit` |
| 7 | `nix-env -p .../system --delete-generations old` | T | `commit` |
| 8 | write `committed := T`, `rollback := X or null`, `staged := null`, state `committed`, history (the closing write, BEFORE any root moves) | T | (re-report) |
| 9 | remove `staged`; flip the `committed` root to T | T | (re-report; a lost flip is re-asserted by the next `fetch`, `arm`, `abort`, `revert-commit` or `release`) |

**abort** (argv0 committed X, booted X, target or rollback; any open state with the same id, or a new id as kind `repair`):

| # | Step | Note |
|---|---|---|
| 0 | `fetching` with a live worker: `systemctl stop cogworx-pve-upgrade-fetch.service` (30 s), then take the lock | |
| 1 | write `aborting` with `pre` (unless `committing`/`reverting` recorded it); re-assert the `committed` root | |
| 2 | `grub-editenv unset next_entry` | FIRST: a pending one-shot must never outlive the candidate |
| 3 | `nix-env -p .../system --set X` | |
| 4 | only when aborting `committing` or `reverting`: rollback := `pre.rollback` (from any other state: the recorded rollback). When that system is absent from the store or not valid in nix's database, the rollback profile is removed instead and the txn closes with `rollback: null` and history `rollback_lost` | undoes commit step 3 |
| 5 | remove the candidate profile | |
| 6 | installer with X; parse: entry 0 == X, no candidate submenu, the rollback submenu matches | |
| 7 | `cwx_rollback_entry` := the rollback title path from step 6, or unset | indices may have moved |
| 8 | `nix-env -p .../system --delete-generations old` | the abandoned target is not rooted for days |
| 9 | with `--release-staged`: remove `staged` | |
| 10 | write `aborted` (or `repaired`) | |

A power cut after any abort step boots X (after step 1 from `armed`, the still-pending one-shot is decided by the guard); repair with `abort`.

**The rollback can be lost in a repair window.** The old rollback loses its last GC root at commit step 3 (with `--retain-until` the profile is re-pointed at X; with `--no-rollback` it is removed), at release step 2 and in the fetch worker's inline release. If a power cut lands after such a step and a collection (`cogworx-nix-gc`, which runs when the disk is low) deletes that system before the repairing `abort`, the abort cannot restore it: it closes with `rollback: null` and history `rollback_lost`. A GC cut between invalidating a path and deleting its directory counts as lost too: validity, not presence, decides, and an error from that check is exit 70 (retry), never a reason to drop the rollback. So "abort restores `pre`" holds only while the system is still in the store; after any repair cogworxd must read `rollback.recorded` (or `txn.json`'s `rollback`) before it offers an `S=r` boot or `revert-commit`.

**revert-commit** (argv0 = `rollback.path` R, booted R, latest txn closed, rollback present): (1) write `reverting` (kind `revert`) with `pre`, re-assert the `committed` root (after a commit whose root flip was lost it still names the old system, and step 7 deletes the committed system's last generation link while `txn.json` names it until step 8); (2) unset `next_entry`; (3) `nix-env -p system --set R`; (4) remove the rollback profile; (5) installer with R, parse (entry 0 == R, no rollback or candidate submenu); (6) unset `cwx_rollback_entry`; (7) `--delete-generations old`; (8) write `committed := R`, `rollback := null`, `reverted`, history `reverted_from` (the closing write); (9) flip the `committed` root to R. A power cut after 1-4 boots committed with no `S` (repair: `abort` with the committed tool) or R with `S=r` (repair: `revert-commit`); after 5-7 it boots R (`revert-commit`); after 8 or 9, a re-issued `revert-commit` re-reports.

**release** (argv0 committed, booted committed, latest txn closed, rollback present, new id): (1) write `releasing` with `pre`, re-assert the `committed` root; (2) remove the rollback profile; (3) installer with committed, parse; (4) unset `cwx_rollback_entry`; (5) write `released`, `rollback := null`.

## crash_state

Tokens computed by `status` (C = committed, S = `txn.state`):

| Token | Condition | Repair |
|---|---|---|
| `head_mismatch` | `system_head != C` and S not in {committing, reverting, aborting} | `abort` |
| `entry0_mismatch` | `entry0_init != C` and S not in {committing, reverting, aborting, releasing} | `abort` |
| `orphan_candidate` | the candidate profile exists and S not in {arming, armed, committing, aborting} | `abort` |
| `candidate_mismatch` | the candidate != `txn.target` | `abort` |
| `orphan_next_entry` | `next_entry` set and S not in {arming, armed} | `abort` |
| `rollback_mismatch` | the rollback profile disagrees with `txn.json` | `abort` |
| `untracked_profile` | a `system-profiles/cogworx_*` profile `txn.json` does not name | admin; never deleted |
| `interrupted` | S in progress and the lock not held (`fetching`: no live worker) | the step tables |
| `grubenv_invalid` | grubenv present but not a valid 1024-byte block | `abort` |
| `grubcfg_invalid` | the grub.cfg parse has errors | Unsafe unless a repair verb's installer run clears it |
| `bootloader_pin_mismatch` | the pin's six fields differ from `/boot/grub/state` | Unsafe |
| `bootstrap_inconsistent` | no `txn.json` and booted, head, entry 0 disagree | Unsafe |
| `txn_unreadable` | `txn.json` unreadable | Unsafe |
| `booted_unknown` | booted not in {C, `txn.target`, `rollback.path`} | cogworxd quarantines |
| `current_differs` | `current != booted` (someone activated a configuration by hand) | informational |

`arm` and `fetch` refuse (65 `crash-state`) unless only `current_differs` is present (a `fetch` resuming its own txn also tolerates `interrupted`). If `crash_state` holds anything repairable, cogworxd runs `abort` before `fetch`.

## The lock

`/run/cogworx-pve-upgrade.lock`, opened `O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC`, `flock(2)` `LOCK_EX`. Verbs use `LOCK_NB` (75 on conflict); the worker waits up to 60 s. A holder writes `/run/cogworx-pve-upgrade.holder` (`{"pid", "what": "verb:<verb>"|"fetch-worker", "txn"}`). `status` decides `lock.held` from `/proc/locks`, never by probing the lock; `holder` comes from the note when its pid matches, `gc` when the holder's `/proc/<pid>/comm` is `flock`, else `unknown`. `cogworx-nix-gc` takes the same lock non-blocking and exits 75 (a success) when it is held. `/run` is tmpfs, so a crashed holder's lock vanishes on reboot. The file itself exists root-owned 0600 from early boot (`systemd.tmpfiles.rules`, `f /run/cogworx-pve-upgrade.lock 0600 root root -`, in sysinit, before any timer or control connection): otherwise its first opener would create it, `flock(1)` in the gc wrapper with 0644, and since `flock(2)` works on a read-only descriptor any local user could then hold the lock forever. The tool opens the existing file as root and checks neither its owner nor its mode.

## Bootloader pin and installer runs

The pin is established once, at bootstrap, from the committed (base) system's compat doc `bootloader.installer` (its `install-grub.sh`), and only if ALL hold, else 69 `unavailable` naming the failed condition:

- The script, minus its `#!` line and `set -e`, is exactly one line `<perl> <install-grub.pl> <grub-config.xml> $@` (no cryptodisk export, no `extraInstallCommands` tail).
- The XML has `useOSProber` false, empty `extraPrepareConfig` and `extraEntries`, `copyKernels` false, `default` `"0"`, `configurationLimit >= 1` and no EFI.
- All six inputs of install-grub.pl's `requireNewInstall` equal `/boot/grub/state`: devices and extra install args (as sets), EFI target `no`, the EFI mount point, `grub` and `grubEfi`.

At pin time the tool also records `distro` (the compat doc's `distroName`: `config.system.nixos.distroName`, which grub.nix also substitutes into install-grub.pl's titles, so the pinned installer and the parse agree on any name; `pve/upgrade/module.nix` asserts it fits the tool's grammar, 1-64 printable ASCII characters without `>`, `"`, `\`, `$` or `'`, without which bootstrap refuses 69 on every clone), `guard` (`cwx-guard-v1` when the XML `extraConfig` has the line `# cwx-guard-v1`, else null) and `boot_area_sha256` per device: sha256 over sector 0 bytes 0-445 and 510-511 plus bytes 512-1048575 (the boot code and GRUB's embedding gap, excluding the partition table, which growpart rewrites when a disk grows).

Every installer run: (1) re-verify the six fields, else 65 `bootloader` without a run; (2) execute `[perl, install-grub.pl, xml, <toplevel>]` directly, no shell, with exactly `PATH`, `LC_ALL=C` and `HOME=/root` (so `NIXOS_INSTALL_BOOTLOADER` and `NIXOS_INSTALL_GRUB` can never reach it), 120 s; (3) sync; (4) `/boot/grub/state` byte-identical and the boot area unchanged, else 65 `bootloader`; (5) parse grub.cfg. `grub-editenv` is always the pinned GRUB's; the tool refuses (65 `grubenv`) a write whose encoded block would overflow 1024 bytes, and values must be printable ASCII without `\` or newline.

**What the pin fixes forever.** The pinned XML carries the BASE image's GRUB settings, the guard included. A later system generation's GRUB settings never reach grub.cfg; only its kernel, initrd and kernel-params do. So GRUB fixes and guard changes reach existing sandboxes only through a new base.

## grub.cfg and grubenv parsing (shared with cogworxd)

`parse_grub_cfg(text, distro)` returns:

```json
{"entry0": {"title": "NixOS", "init": "SYS|null"},
 "submenus": [{"title": "...", "entries": [{"title": "...", "init": "SYS|null"}]}],
 "profiles": {"cogworx_candidate": {"path": "<submenu title>><entry title>", "init": "SYS"}},
 "errors": []}
```

- Lines are stripped. Openers: `^(menuentry|submenu) "([^"]*)"(\s.*)?\{$` and `^function \S+ \{$`; closer: a line `}`. An unmatched closer or an unclosed opener at EOF: `unbalanced`.
- Inside a menuentry, the first `linux ` line's `init=(\S+)` must end with `/init` and the rest fullmatch SYS, else `init:<title>`. `init` is a copied file in the toplevel, so the toplevel prefix is reliable.
- `entry0` is the first top-level menuentry and must be titled exactly the distro name (`entry0-title`; missing: `no-entry0`).
- The complete error set (`errors` holds each token once, in the order the parser finds them; the vectors pin it):

  | Token | When |
  |---|---|
  | `unbalanced` | a `}` with nothing open, or an opener still open at EOF |
  | `nested-submenu:<title>` | a submenu inside another opener |
  | `nested-entry:<title>` | a menuentry inside a menuentry or a function |
  | `title-chars:<title>` | a title with `>`, `"`, `\`, `$` or a byte outside 0x20-0x7e |
  | `init:<title>` | a menuentry whose first `linux ` line has no `init=<SYS>/init` |
  | `no-entry0` | no top-level menuentry |
  | `entry0-title` | the first top-level menuentry is not titled exactly the distro name |
  | `empty-submenu:<title>` | any submenu without an entry |
  | `profile-entries:<name>:<n>` | a `<distro> - Profile '<name>'` submenu of a `cogworx_*` profile holds n != 1 entries |
  | `entry-title:<title>` | the one entry of such a submenu does not fullmatch `<distro> - Configuration [0-9]+ \([0-9]{4}-[0-9]{2}-[0-9]{2} - [ -~]{1,128}\)` |

  `status.grubcfg.errors` is `["unreadable"]` when grub.cfg cannot be read at all; that token never comes from the parser.
- **Title paths, never numeric ones.** Profile submenus are globbed in sorted order, so `cogworx_candidate` sorts before `cogworx_rollback` and a numeric rollback path saved at commit would name the candidate after the next arm. Title paths (for example `NixOS - Profile 'cogworx_rollback'>NixOS - Configuration 1 (2026-10-18 - 26.11.20261008.e7439b6)`) embed the generation number and the link's mtime date; they are copied verbatim from the file, never computed.

grubenv, as GRUB's envblk.c reads it:

- Exactly 1024 bytes, starting with the line `# GRUB Environment Block`.
- Then lines of two kinds, anywhere and in any order: a line starting with `#` is a comment and is skipped wherever it appears, and every other line is `name=value`. grub-editenv's `create` writes the comment `# WARNING: Do not edit this file by tools other than grub-editenv!!!` right after the header, before any variable (every captured vector has it), and the trailing `#` padding that fills the block is one more such line.
- In a value, a backslash escapes the next byte, newline included; a `name=value` line ends at an unescaped newline. An empty name, a line without `=`, or a value running off the end of the block is invalid.
- A name that appears twice makes the block invalid.
- Anything else is invalid too (`grubenv_ok: false`, `grubenv_invalid`).

An empty value is a value: GRUB writes `next_entry=` when it consumes the one-shot. `status` reports an empty `next_entry` or `cwx_rollback_entry` as null (see the status object). The tool owns `next_entry`, `cwx_rollback_entry` and `cwx_once`, and `arm` also unsets a saved `boot_once` (see the guard). GRUB's `save_env` cannot create a missing block, so `arm` creates it.

Shared vectors: `pve/testdata/grubcfg-v1/*.cfg`, each with its expected parse as `*.json` (hand-rendered in install-grub.pl's exact shape, including one per error class the real renderer can be pushed into: `empty-candidate-submenu`, `bad-title`, `entry-title`, `nested-entry`, `unbalanced`; plus `vm-*`, install-grub.pl's real output captured in `pve-upgrade-vm`), `pve/testdata/grubenv-v1/*.env` (real 1024-byte blocks from the same runs: grub-install's, the tool's `grub-editenv` writes, and one GRUB wrote itself at a trial boot, plus hand-made invalid ones such as `duplicate-name`) with their parse as `*.json` (`null` for an invalid block), and `pve/testdata/closure-digest-v1.json`. The tool's unit tests consume them, and so must cogworxd's Go parsers. The real grub.cfg header quotes `grub-reboot` with U+2018/U+2019; the vectors keep ASCII quotes there and a unit test re-inserts the real bytes, so a parser must not depend on that comment's encoding.

## The compat doc

`<toplevel>/cogworx-pve-compat.json`, built from the evaluated configuration and normalized by `pve/upgrade/compat_doc.py` (ASCII, sorted keys, at most 16384 bytes; both readers cap at 16 KiB).

```json
{
  "schema": 1, "kind": "cogworx-pve-system", "toolProto": 1, "txnSchema": 1,
  "bootProof": 1, "stateFormat": 1, "bootConfigVersions": [1], "smbiosSelector": "S", "guestAttrsVersion": 1,
  "release": {"id": "2026.10.1", "builtAt": "2026-10-18T00:00:00Z"},
  "controlCAKeys": ["ssh-ed25519 AAAA..."], "controlCAFingerprints": ["SHA256:..."],
  "controlPlaneCIDRs": ["198.51.100.0/24"], "controlUser": "root",
  "hostKeyPath": "/var/lib/cogbox-state/sshd/ssh_host_ed25519_key",
  "stateDevice": "/dev/disk/by-id/virtio-cogworx-state", "guestDevice": "/dev/disk/by-id/virtio-cogworx-guest", "interface": "eth0",
  "substituters": ["https://cache.example"], "trustedPublicKeys": ["cache.example-1:AAAA..."],
  "specialisations": [],
  "bootloader": {"installer": "/nix/store/...-install-grub.sh", "grub": "/nix/store/...-grub-2.14", "devices": ["/dev/vda"], "distroName": "NixOS", "guard": "cwx-guard-v1"}
}
```

- Every key above is required: `compat_doc.py` fails the build when the module did not write one (it never defaults a list to `[]`, which would fail cogworxd's rule (v) on every target), and the `compat-doc` check pins the fixture's document whole, its key set included.
- `bootProof` and `stateFormat` come from `gce/protocol.nix`, never restated.
- `release` is `cogworx.pve.release`: null means "not an upgrade target".
- `controlCAKeys` are reduced to `<type> <blob>` (comment dropped), sorted and unique; `controlCAFingerprints` are `SHA256:<unpadded base64>` in the same order (what `ssh-keygen -lf -E sha256` prints). A blob that does not decode fails the build.
- `controlPlaneCIDRs`, `substituters`, `trustedPublicKeys` and `specialisations` are sorted and unique; the substituters and keys are the union of `nix.settings` including `extra-*`. An `http://` or `https://` substituter loses its trailing slashes before that (nix's HTTP binary cache store ignores them too, and nixpkgs' default `https://cache.nixos.org/` would otherwise sit beside a configured `https://cache.nixos.org`); any other URL is kept as configured. cogworxd's rule (v) must compare the release's cache URLs normalized the same way.
- `smbiosSelector` is what this system generation's emulator tolerates, NOT a GRUB capability: the guard is a property of the pin.
- `bootloader` is authoritative only when the tool pins at bootstrap; for a target it is informational.

| Rule | Check | Checked by |
|---|---|---|
| i | cogworxd's control CA is in the target's keys / fingerprints | cogworxd |
| ii | every control-plane egress address is covered by the target's `controlPlaneCIDRs` | cogworxd |
| iii | the boot config version is supported; `S` only when `status.bootloader_pin.guard` is known | cogworxd |
| iv | `toolProto` supported (v0: 1) | cogworxd |
| v | the target's substituters and keys include every cache the release was verified against | cogworxd |
| vi | `hostKeyPath`, `stateDevice`, `guestDevice`, `interface`, `controlUser` equal the committed doc's | guest |
| vii | `builtAt`, `bootProof`, `stateFormat` equal the release record's | cogworxd |
| viii | `stateFormat` equal (v0) | guest |
| ix | `txnSchema` equal | guest |
| x | `release` non-null; `kind == "cogworx-pve-system"`; `schema == 1` | guest |
| xi | `specialisations == []` and `<target>/specialisation` absent or empty | guest |
| xii | `<target>/kernel-params` has `boot.panic_on_fail` and its last `panic=N` has N >= 1 | guest |
| xiii | bootable shape: `kernel`, `initrd`, `init`, `kernel-params`, `nixos-version` exist; `nixos-version` is 1-128 printable ASCII bytes without `>`, `"`, `\`, `$`; `sw/bin/cogworx-pve-upgrade` resolves to an executable regular file (`compat:xiii:sw/bin/cogworx-pve-upgrade`); no `append-initrd-secrets` (`compat:xiii:append-initrd-secrets`) | guest |

A guest rule fails `fetch` (`fetch_failed` / `compat`) or `arm` (65 `compat`) with `reason` `compat:<rule>[:<field>]`, for example `compat:vi:hostKeyPath`. Two more tokens are part of the same closed set: `compat:doc`, the target's compat doc is absent, malformed or over 16 KiB (`status.compat.target` is then null too; the likeliest cause is a target built from a tree without `pve/upgrade/`), and `compat:xiii:unreadable`, `nixos-version` or `kernel-params` exists but cannot be read. A failed rule of either side is a permanent memo for that target.

Rule xiii's tool clause exists because of the argv[0] rule: once a target is committed, `<target>/sw/bin/cogworx-pve-upgrade` is the only tool allowed to abort, release or switch away from it. A target without it (a composition that replaced `environment.systemPackages` with `lib.mkForce`, or a hand-built system that copied a compat doc) would strand the guest after a `--no-rollback` commit. `pve/upgrade/module.nix` asserts the tool is in `environment.systemPackages`, and the rule catches what the assertion cannot see.

Rule xiii's `append-initrd-secrets` clause exists because install-grub.pl runs `<toplevel>/append-initrd-secrets` as root for every system it renders. For the candidate at `arm` that would run the target's code before any trial; for entry 0 at commit step 5 a failure is fatal, so `commit` would answer 65 `bootloader` on every redo while `abort` refuses a `committing` txn with the target booted. nixpkgs links that file into a toplevel only when `boot.initrd.secrets` is set, so a system generation meant as an upgrade target must not set it.

## Closure digest

`closure = sha256_hex(concat over sorted(nix-store -qR <target>) of "<path> sha256:<nix32>\n")`, sorted by byte order, the target included. Hashes come from `nix-store -q --hash` (batched, at most 500 paths per call) and are normalized from nix32, base16 or SRI to `sha256:<nix32>`, so a workstation and a guest on different nix versions agree. `closure-digest` takes no lock, reads no `txn.json` and works unprivileged on any local store, so the operator computes the release's digest with the same code the guest uses. It uses the database's recorded hashes only, which is why fetch uses `fsync-store-paths`.

## The GRUB guard and the S code

`pve/upgrade/grub-guard.cfg`, rendered after install-grub.pl's one-shot block (which sets `boot_once` when it consumed `next_entry`):

```
# cwx-guard-v1
insmod smbios
insmod regexp
set cwx_si=""
set cwx_s=""
set cwx_n=""
set cwx_hasn=""
set cwx_v1=""
set cwx_trial=""
set cwx_rb=""
if smbios --type 1 --get-byte 7 --set cwx_si; then
	if [ "${cwx_si}" != "0" ]; then
		if smbios --type 1 --get-string 7 --set cwx_s; then
			if [ -n "${cwx_s}" ]; then
				if regexp '(^|&)v=1(&|$)' "${cwx_s}"; then set cwx_v1=1; fi
				if regexp '(^|&)S=c(&|$)' "${cwx_s}"; then set cwx_trial=1; fi
				if regexp '(^|&)S=r(&|$)' "${cwx_s}"; then set cwx_rb=1; fi
				if regexp --set 2:cwx_n '(^|&)n=([0-9a-f-]+)(&|$)' "${cwx_s}"; then set cwx_hasn=1; fi
			fi
		fi
	fi
fi
if [ -n "${boot_once}" ]; then
	set fallback=0
	if [ -n "${cwx_trial}" ]; then
		set cwx_once="c:${cwx_n}"
	else
		if [ -n "${cwx_v1}" ]; then
			set default=0
			set cwx_once="d:${cwx_n}"
		else
			set cwx_once="u:"
		fi
	fi
	save_env cwx_once
fi
if [ -n "${cwx_rb}" ]; then
	if [ -n "${cwx_rollback_entry}" ]; then
		set default="${cwx_rollback_entry}"
		set fallback=0
	fi
fi
```

- The string at type-1 offset 7 is the SMBIOS serial, the raw boot-config blob. `--get-byte 7` probes it first, so a boot with no serial prints no GRUB error.
- Every `cwx_*` flag is reset first, because `load_env` imports every grubenv variable and a stale one must never act as a flag. `cwx_once` is not reset: it is a record that must survive later boots.
- `boot_once` is the one input the guard takes from install-grub.pl's header, which sets it (in memory, never saved) only when it consumed `next_entry`, and never clears it otherwise. A `boot_once` SAVED in grubenv would therefore make every boot look like a consumed one-shot and overwrite `cwx_once` with a false record. Nothing writes one, and `arm` step 5 unsets it anyway (the guard text cannot change on existing sandboxes; see the pin).
- **Fail open.** With a one-shot pending, `default` is forced back to entry 0 ONLY when the serial was read, is a v1 blob (`v=1`) and lacks `S=c` (`d:`). An unreadable, absent or non-v1 serial (for example one still base64-encoded) leaves the guard inert (`u:`), and the one-shot boots the candidate exactly as without a guard. An SMBIOS problem on some platform therefore never blocks every upgrade, and `u:` tells cogworxd the guard is not effective on that VM.
- `set fallback=0` under any one-shot: a candidate whose kernel fails to load boots entry 0 instead of stopping at GRUB's menu. A candidate whose initrd is missing or whose stage 1 fails panics, and `panic=10` reboots onto entry 0 (the one-shot is already consumed).
- `S=r` runs last, so it wins over an armed one-shot, and boots the rollback by its title path.
- GRUB's `regexp` returns the same failure for a bad pattern as for no match, so a pattern typo fails closed silently. The `pve-grub-guard-syntax` check runs `grub-script-check`, and the VM test boots the positive cases.

`cwx_once`, which `arm` unsets:

| Value | Meaning |
|---|---|
| `c:<nonce>` | GRUB took the one-shot to the candidate on the boot whose serial carried that start nonce. Trial nonce and booted committed: the candidate failed (GRUB fallback or a panic reboot), which is target evidence. |
| `d:<nonce>` | GRUB refused the one-shot (a v1 serial without `S=c`): an environment or control-plane fault, no memo. |
| `u:` | the guard was inert on the boot that consumed the one-shot. Booted target: an unguarded trial. Booted committed: the candidate failed, but which boot consumed the one-shot is unprovable: no memo. |
| absent | GRUB has not consumed the one-shot since `arm`. |

**The S code** is a GRUB-only boot-config key, value `c` (the candidate may boot) or `r` (boot the rollback). The emulator and cogworxd's decoder ignore unknown keys, so old images are unaffected; the emulator logs it as unknown. In the raw blob `&` and `=` appear only as separators, keys are in byte order, and `S` can be the first field, hence `(^|&)`. cogworxd's encoder validates `S` and refuses it together with `M`: `S=c` and `S=r` replace `M=` in the worst case, so the worst-case `smbios1` stays at 498 of PVE's 512 characters (base64 encodes 329 and 330 bytes to the same 440 characters); `S` with `M` would be 502, and is refused by the encoder rather than by the guest (a guest-side reject would refuse the whole blob).

## The emulator's `sys` field

`/run/cogworx/guest-attributes.json` carries `"sys": "<booted toplevel>"` beside `v`, `boot_id` and `gen`, read once from `realpath(/run/booted-system)` when the emulator starts. It is ABSENT, never null, when unknown; a restarted emulator never takes it from the file. `v` stays 1. cogworxd ignores it today; the upgrade resolver uses it to learn which system generation booted. The emulator writes the file on the first attribute write of a boot (its directory is under `/run`), so `sys` appears with the guest's first attribute and the file is absent before it.

## What the control plane codes against

| Phase | Tool and guest calls | What cogworxd reads |
|---|---|---|
| host half ready | `proto`, `status` | `cogworx_pve_upgrade == 1`; `booted` equals the recorded system (else Unsafe); `crash_state` |
| (every call) | `--txn` is a fresh lowercase RFC 4122 UUID cogworxd mints per switch, cleanup or release and records with the fence; never the operation id (it does not match TXN) | |
| stale cleanup | `abort --txn <status.txn.id or new> [--release-staged]` | `txn.state` in {aborted, repaired}; after a repair, `rollback.recorded` (it may have been lost, history `rollback_lost`) |
| fetch slice | `fetch ...`, then poll `status` | `txn.state`, `progress`, `reason_class`, `compat.target`; at the slice end its own `incomplete`, then a stop (the worker records `interrupted`) |
| compat + arm + read-back | rules i-v and vii; `arm`; guest-agent reads of `/boot/grub/grub.cfg` and `/boot/grub/grubenv` | `armed`; its own parse: entry 0 == committed, candidate == target, `next_entry` == the candidate's title path. An `arm` exit 0, re-reported or not, means the one-shot is pending; a 65 `state` "one-shot consumed" means abort |
| trial | stop; boot config with `S=c` (only when `status.bootloader_pin.guard` is known); start; the emulator's `sys`; `status` with the COMMITTED tool path | `booted == candidate == txn.target`, `next_entry` null, `entry0_init == txn.committed`; booted committed: classify by `cwx_once` |
| commit | `commit --txn --retain-until T` (or `--no-rollback`); verify over the guest agent | `committed`, `committed == target`; a 65 `grub-parse` with `mutated: false` (the committed system's `nixos-version` cannot title the rollback entry) changed nothing: commit `--no-rollback` or abort |
| abort | `abort --txn` (with the trial still reachable); verify | `aborted` |
| revert | fence (kind revert); stop; `S=r` boot, bounded by a timeout; `sys` == the previous system; `revert-commit` with the PREVIOUS tool path; verify; stop, clear `S` from the boot config and start | `reverted` |
| resolver | a boot with a fresh boot config; `status` | the table below |

Prerequisites on the control-plane side: the guest-agent file-read allow-list must add `/boot/grub/grub.cfg` and `/boot/grub/grubenv`; the Go grub.cfg and grubenv parsers consume the shared vectors; the encoder's `S` code, its refusal of `S` with `M`, the worst case over {`M`, `S=c`, `S=r`} and the shared boot-config vectors are one joint change; the `S=r` boot is fenced (`switch_target` = the previous system) so the booted-system cross-check does not quarantine it.

Resolver decisions, keyed on `status` after a boot:

| `txn.state` | booted | Action |
|---|---|---|
| `committed`, target == the fence target | target | prove readiness, then record the commit (status only: the old tool is no longer committed) |
| `committing` | target | `commit` (old tool), verify, record |
| `committing` | committed | `abort` |
| `armed` | target | this boot is the trial: commit if proven and eligible, else abort |
| `armed` or `arming` | committed | `abort`; memo per `cwx_once` |
| `arming` | target | `abort` (never commit from `arming`) |
| `reverting` | rollback | `revert-commit` (previous tool) |
| `reverting` | committed | `abort` |
| `aborting` | committed, target or rollback | `abort` (same id) |
| any other open state except `reverting` (pre-arm, `arming`, `armed`, `committing`, `releasing`) | rollback (for example an `S=r` boot over an armed candidate, or after a cut inside a commit) | `abort` with the committed tool (same id), then `revert-commit` with the rollback's tool if a revert was intended (still booted on it) |
| `releasing` | committed | `release` (same id) or `abort` |
| pre-arm states | committed | `abort` (`--release-staged` when the target changes) |
| an unrepairable `crash_state` token, or an unreadable txn | any | hold Unsafe |

**Choosing S.** The VM is stopped when the boot config is written, so `txn.json` cannot be read then. cogworxd sends `S=c` whenever the fence is set, the switch is eligible and `status.bootloader_pin.guard` (or `proto.guard`) is known. That is safe because GRUB honours `S=c` only under a pending one-shot, which only an armed guest has.

**`S=r` applies to every boot of that start.** The SMBIOS serial is fixed for the life of the QEMU process, and a guest-initiated reset keeps it: a `panic=10` reboot and an in-guest `reboot` both boot `cwx_rollback_entry` again while that is set, because the guard's `S=r` branch, unlike `S=c`, does not depend on a one-shot. So a rollback whose stage 1 now fails boot-loops until cogworxd stops the VM, and after an `S=r` start that ends in an `abort` instead of a revert (abort step 7 sets `cwx_rollback_entry` again), an in-guest reboot lands on the rollback once more. After an `S=r` start cogworxd therefore never reboots from inside the guest: it bounds the `S=r` boot with a timeout, then stops the VM and starts it with a boot config without `S`, and it clears `S` from the PVE config once the revert is done or abandoned. `S=c` has no such issue: after the trial boot consumed the one-shot, later resets of the same start boot entry 0.

## The VM test

`pve-upgrade-vm` and `pve-upgrade-vm-powercut` (`pve/tests/upgrade-vm.nix`; what each proves is in pve/README.md's checks table) boot one VM the way a template boots: legacy MBR, SeaBIOS, GRUB 2.14 on `/dev/vda`, `configurationLimit` 1 and timeout 0, from `pve/image.nix` plus `pve/upgrade/module.nix`. The REAL tool runs every verb as cogworxd would, by store path; system generations arrive through `fetch` from a signed file:// binary cache; each boot gets its own `-smbios type=1,serial=<blob>` with a distinct start nonce, so every `cwx_once` value is checked exactly. The test script runs in about 6 minutes (`main`) and 9 minutes (`powercut`), and each check's `globalTimeout` is 30 minutes: nixpkgs' `run-*-vm` script starts its virtiofsd daemons in the background and execs QEMU without waiting for their sockets, so under host load QEMU can lose that race and exit (seen after a `crash()` restart and after a clean shutdown), and the driver then waits on the monitor with no output until the timeout. Such a failure is the harness, not the tool; re-run the check.

Where the test differs from production, and why:

- `pve-host.nix` is not imported (it needs the cogbox package, the state and guest disks and the emulator); the test supplies the host contract.
- Two GRUB lines (`serial`, `terminal_output serial`) are prepended to `extraConfig` so GRUB's messages reach the log. The guard after them is the shipped file.
- The test framework's kernel parameters put `panic=1` after the module's `panic=10`, and the last one wins, so a panicking candidate reboots after 1 s instead of 10.
- The headroom seam is 2 GiB floor and 256 MiB reserve on an 8 GiB disk; production's values are pinned by `config-values`.
- QEMU's machine is Q35 with SMBIOS 2.8 (one boot uses the 3.0 entry point). PVE defaults to i440fx; that, and PVE's `base64=1` decode, stay a live check.
- The cache holds the targets' whole closures. nix refuses to add a path to a binary cache whose references the cache lacks (`cannot add '%s' to the binary cache because the reference '%s' is not valid`), so a cache of only the paths the VM is missing cannot be written. The VM still substitutes only what it is missing.
- The base system is a release too, because the power-cut suite cycles A, B, C and back to A.

A power cut is the tool imported with a `STEP_HOOK` (`pve/tests/upgrade_crashat.py`) that parks the process right after a step's `os.sync()`, periodic writeback disabled, and then QEMU quitting: what reached the virtual disk survives and the guest's page cache does not. The filesystem is never unmounted, and GRUB does not replay the ext4 journal. Every boot after a cut still landed on the entry the step table predicts and read the grubenv the step wrote, so a step's `sync(2)` is enough for GRUB, not only for Linux.

Beyond every commit step (with `--retain-until`) and every abort step (from `armed`), `pve-upgrade-vm-powercut` cuts a `--no-rollback` commit after step 3 (the rollback profile removed) and then the repairing abort after its step 4 (the rollback put back from `pre`), a `--no-rollback` commit after step 8 (closing write done, root flip lost: the old system stays rooted, a re-issued commit re-reports, and the next `fetch` re-asserts the root), and `arm` after step 6 (the one-shot is durable: an `S=c` boot takes the candidate, `abort` runs from it). `pve-upgrade-vm` also boots an armed candidate with a serial that is readable but not a raw v1 blob (the blob still base64-encoded, as if PVE had not decoded it): the guard stays inert (`u:`) and the candidate boots. And it holds the lock with the REAL worker, not a stand-in: the crash driver parks `_fetch`, run in the worker's own transient unit, after its dry run, `cogworx-nix-gc` skips (75) and collects nothing, and the released worker finishes the fetch.

## Deferred

- A live check on a real PVE VM of the guard's inputs: PVE's `base64=1` decode, the machine type (PVE defaults to i440fx) and the SMBIOS entry point. The fail-open guard makes a negative result non-blocking, and `cwx_once == "u:"` reveals it.
- The control-plane side listed above, and `cwx_once` consumption.
- In the VM test, power cuts inside fetch, revert-commit and release, inside arm except after step 6, inside abort of a `committing` txn except after step 4, and after commit step 9 (the roots), the `--release-rollback` headroom release and the `unreachable` class are covered by the unit tests only. GC during a fetch runs while the worker is parked between its dry run and its realise, not inside the realise itself (the lock is the same either way).
- Schema 2 and downgrade-safe writers (rule ix forbids a `txnSchema` change while a rollback exists). A `nixDbSchema` compat field if a nix bump ever migrates the store database. GRUB fixes and guard changes reach existing sandboxes only through a new base.
- A collection between fetch attempts deletes the paths an interrupted attempt substituted; that costs time only.
- An evaluation-time assertion that `boot.initrd.secrets` is empty; until then rule xiii refuses such a target at fetch end and in `arm`, before anything renders it.
