# Runtime tool environments

`cogbox-env` lets the sandbox owner, or an agent working for them, select one Nix-built bundle of executables at runtime, without rebuilding the guest and without a restart. The bundle's `bin` directory goes first on PATH, every selection is a compare-and-swap with one level of rollback, and the bundle's full closure is archived in the persistent work tree so it is restored offline after a restart. It changes executables on PATH and nothing else: no NixOS activation, services, environment variables, libraries for other programs, network policy, kernel or running binaries.

## Enablement

The NixOS module is `runtime/module.nix`. Every guest configuration imports it (it is the first entry of `cogboxModules`), and it is also exported as `nixosModules.runtime-environment`. The option is `cogbox.runtimeEnvironment.enable`.

It is enabled by default in the **hosted** guest only, the configuration the GCE image runs. `hostedGuestModule` in `flake.nix` sets `cogbox.runtimeEnvironment.enable = lib.mkDefault hostedRuntimeDefault`, and `hostedRuntimeDefault = true` is the one line a dark launch changes to `false` (the checks follow it). Plugin-composed GCE guests re-execute through the `cogbox-hosted` package, which re-evaluates the same hosted configuration with the plugin modules merged in, so they get the feature too. Because it is `mkDefault`, a plugin module may set `cogbox.runtimeEnvironment.enable = false` to turn it off for that sandbox; against a plain `true` the same setting would be a conflicting definition and fail the whole plugin composition. `checks.runtime-environment` evaluates a plugin-composed hosted guest in both directions.

Only images that ship `runtime/module.nix` declare the option, so a plugin that sets it unguarded fails composition on an older image ("The option `cogbox.runtimeEnvironment' does not exist"). A plugin meant for both should guard on the option existing; `lib.mkIf` cannot do that, because the module system checks a definition's path even when its condition is false:

```nix
{ options, lib, ... }: {
  config = lib.optionalAttrs (options ? cogbox && options.cogbox ? runtimeEnvironment) {
    cogbox.runtimeEnvironment.enable = false;
  };
}
```

The workstation profile (local, darwin, the k8s VM-in-pod backend) and the container guest keep it off. Enabling it there, including from a plugin, is **unsupported** and is not prevented, because an assertion would turn a plugin's setting into a failed compose:

- On the workstation profile the writable store is a 50%-of-RAM tmpfs, so every boot would restore the bundle into memory.
- On the container cow store, an existing upper keeps its own store database across an image bump, so it can call paths valid whose files are gone. `nix-store --import` never repairs a valid path, so a restore could never bring them back. The container also has no `/var/lib/cogbox/work` mount, so the boot unit renders without its mount gate.

Enabling the option installs:

- the helper, `/run/current-system/sw/bin/cogbox-env`, on `python3Minimal` with the guest's own `config.nix.package` on its PATH (the read-only internal option `cogbox.runtimeEnvironment.package`);
- `/root/work/.cogbox/runtime/current/bin` at the front of PATH in login shells (so also new tmux panes) and in every harness launcher, plus a one-line login warning;
- `cogbox-runtime-restore.service`, the boot restore;
- the baked agent skill `cogbox-runtime`, through `cogbox.skills`.

On a box with nothing selected all of this is inert: the PATH entry names a missing directory, the boot unit is skipped by its condition, and the helper does nothing unprompted.

The cogworx control-plane flag `COGWORX_RUNTIME_ENV` gates only its read-only status endpoint. The guest feature follows the image: a GCE image pin is resolved once at provision, so a box keeps whatever its image shipped. For a box that already has it, the per-box levers are the kill switch and `cogbox-env clear` (see the recovery runbook); new boxes are controlled by the image pin, or by an image built with `hostedRuntimeDefault = false`.

## Using it

A bundle is an ordinary flake package whose output has a `bin` directory, for example a `pkgs.buildEnv` of the wanted tools. In the guest, lock it against the image's own nixpkgs, which is already in the store:

```nix
{
  inputs.nixpkgs.url = "nixpkgs";
  outputs = { self, nixpkgs }: let
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
  in {
    packages.x86_64-linux.default = pkgs.buildEnv {
      name = "project-tools";
      paths = [ pkgs.hello pkgs.jq ];
      pathsToLink = [ "/bin" ];
    };
  };
}
```

```sh
nix flake lock --flake-registry /etc/nix/registry.json "path:$(realpath ~/work/tools)"
cogbox-env prepare --flake "path:$(realpath ~/work/tools)" --attribute packages.x86_64-linux.default
cogbox-env status
cogbox-env apply --generation GENERATION --expected-selection none
cogbox-env exec -- hello
cogbox-env rollback --expected-selection TOKEN
cogbox-env clear --expected-selection TOKEN
cogbox-env restore [--generation GENERATION]
cogbox-env prune [--generation GENERATION]
cogbox-env capabilities
```

- **Locking.** Nix (checked on 2.34.8) resolves an indirect flake *input* such as `inputs.nixpkgs.url = "nixpkgs"` through the global registry and `--override-flake` only, never through the user or system registry; a command-line reference like `nix flake metadata nixpkgs` does consult the system registry, but loading the registries downloads the global one first. On the guest the global registry is `https://channels.nixos.org/flake-registry.json`, so a plain `nix flake lock` needs the network (it fails in `none` network mode) and locks the latest nixpkgs-unstable tarball rather than the image's nixpkgs. `--flake-registry /etc/nix/registry.json` makes the guest's system registry file, which NixOS writes with `nixpkgs` pointing at the image's nixpkgs source path, the global registry for that one command: the input locks offline to that `path:/nix/store/...-source` with its `narHash`, and the lock's `original` stays `indirect nixpkgs`, so prepare accepts it. `nix flake lock --override-input nixpkgs nixpkgs` also lands on the image's path, but only with network access. The file names only `nixpkgs`, and the flag makes it the only global registry, so every other input needs a direct reference (`github:numtide/flake-utils`, not `flake-utils`, which fails with `cannot find flake 'flake:flake-utils' in the flake registries`). A `flake.lock` whose `nixpkgs` is locked to anything but a `path` under `/nix/store` was locked without the flag or elsewhere, and `nix flake lock` keeps it: such a bundle builds from another nixpkgs and its prepare needs the network after every stop and start, until `nix flake update nixpkgs` with the flag (below) re-resolves it.
- `prepare` snapshots the flake source into the store and records each locked input's store path with `nix flake archive --dry-run --json` (it copies the flake's own source and fetches no input it keeps from `flake.lock`, except a root input whose own `flake.nix` makes one of its inputs follow another without the bundle's `flake.nix` declaring that follows: Nix 2.34 fetches such an input again to re-read its `flake.nix`, even when the attribute never uses it, and a failed fetch then fails at the archive. Nix also fetches any input it locks in memory, because `flake.lock` lacks it or its URL in `flake.nix` changed), with `--no-update-lock-file --no-write-lock-file --no-use-registries`, then builds the immutable snapshot with the same flags, verifies and roots the complete closure, and exports it to a streamed archive before publishing the generation. It reads the bundle's system from `nix derivation show`, which works for `__structuredAttrs` derivations (`pkgs.buildEnv`, and in current nixpkgs even `pkgs.hello`) whose environment carries no `system` binding. It never selects anything. It never writes `flake.lock`, but the flags do not make a missing or stale entry fail: Nix raises the `--no-update-lock-file` error only when it would write the lock, which `--no-write-lock-file` rules out, and `allowUnlocked` stays on (checked on 2.34.8). An input that needs a registry to lock, such as `nixpkgs` with no lock entry, fails (`'flake:nixpkgs' is an indirect flake reference, but registry lookups are not allowed`). An input with a direct URL that `flake.lock` lacks, or whose URL in `flake.nix` changed, is locked in memory for that one prepare and fetched, with only the warning `not writing modified lock file`, so the generation is built from inputs `flake.lock` does not record, and an unpinned reference such as `github:owner/repo` can lock to a newer commit at each such prepare. So lock first and run `nix flake lock` again after changing inputs. `nix flake lock` locks new inputs and inputs whose URL changed but never re-resolves an unchanged one, so when an image upgrade removed the locked nixpkgs source, or the `flake.lock` came from another sandbox, re-resolve it with `nix flake update nixpkgs --flake-registry /etc/nix/registry.json --flake "path:$(realpath ~/work/tools)"`; without `--flake-registry`, that command fetches the global nixpkgs-unstable instead. Use the `path:` and `realpath` forms throughout: `~/work` is a symlink, Nix refuses a `path:` source that goes through one, and inside a git checkout a bare `nix flake lock` refuses a `flake.nix` that git does not track. Re-running prepare for an existing generation reuses it, and repairs a missing or corrupt archive or manifest from the local closure. Apart from that follows case, a locked input the attribute never uses is not fetched at prepare, and a lock entry the build needs but cannot fetch fails in `nix build --json`. The dry run computes each locked input's store path from its `narHash`, so an entry without one fails at the archive with `cannot compute store path for unlocked input` where a full archive would fetch it; Nix always writes the hash, so only a hand-edited lock (a `git` entry locked by `rev` alone, say) or one from another tool meets this.
- **Locked store paths are not re-read.** Nix 2.34.8 (unchanged in 2.35.2 and in master as of 2026-10-14) marks lock-file entries final and gives a final `path` input no fetcher-cache fingerprint, so every Nix command that evaluates such an input NAR-hashes its whole tree again: 2 to 4 minutes per command for the image's nixpkgs on a 1-vCPU GCE guest, over its uncached 9p lower store (120 to 157 seconds in one run, 234 to 257 in another, with the same lock and machine shape). For each root input locked as a `path` to a valid `/nix/store/HASH-source` path, prepare passes `nix build` an `--override-input NAME path:PATH?ATTRS` that repeats the lock entry, and Nix then uses the path in place. The archive JSON, the derivation and the output are byte-identical, so `inputs_digest` and generation ids do not change. Trust: Nix takes the narHash from the store database and still rejects a lock narHash that differs. An entry the override would not reproduce exactly keeps the slow path: one with inputs of its own (an override resolves them again from that input's own `flake.lock`), one without `lastModified` or with attributes beyond `narHash`, `lastModified`, `rev` and `revCount`, and one whose URL or `flake` flag in `flake.nix` changed without a new lock. An override takes both from `flake.nix`, while Nix keeps a lock entry whose URL is unchanged, with the entry's own `flake` flag, and re-locks one whose URL changed in memory; such a re-lock can keep the narHash, and so the store path the archive records, while changing `lastModified` or `rev`, which the bundle may read. So prepare first passes the overrides to `nix flake metadata --json` for the snapshot (with the same flags; it fetches nothing the build would not) and keeps one only where the lock Nix computes with them holds that input's `flake.lock` entry unchanged, which is then also the entry Nix evaluates without it. When Nix cannot compute that lock, every input keeps the slow path: a `path` entry whose `path` names another valid source than its `narHash` fails the override's hash check, and prepare then builds what plain Nix builds, from the source the `narHash` names. Whenever an entry locked to a valid store path keeps the slow path, prepare says so on stderr (`no store-path override for NAME`), after any Nix error that caused it. Not covered: nested inputs, and users' own `nix build`, `nix eval` or `nix flake check` of the bundle, which is why the skill leaves the building to prepare. The regression guards are the acceptance test's read sentinel, its comparison of each recorded derivation with a plain `nix eval` of the recorded source, and the `_NIX_TEST_BARF_ON_UNCACHEABLE` runs in the acceptance and VM tests.
- In a `none`-network sandbox, a prepare can use only what is already in the store. Measured on a 1-vCPU GCE guest at the default `--timeout`, with the skill's two-tool `buildEnv` (which needed downloads) and two single-script `builtins.derivation` bundles on the image's bash and coreutils (which did not): the first failed with `prepare_failed` (`nix build --json`) in 11 to 16 seconds and published nothing, the others succeeded in 20 to 28 seconds, and a no-op repeat took about 10 seconds. A bundle that has to compile something locally takes as long as that build. A failure for a missing download needs no short `--timeout` to fail fast, and its stderr shows the failed download under an `error:` line (in the log lines of a fixed-output derivation's `Cannot build` error, or in a failed input fetch). Nix's `warning: unable to download` lines for the binary cache's `nix-cache-info` do not identify it: they can also appear in a prepare that succeeds (seen on the guest) or fails for another reason (checked on 2.34.8 with a builder that exits 1).
- `prepare --import-store-path /nix/store/HASH-NAME` publishes an output that is already in the store; its provenance is labelled `import`.
- A bundle must contain `bin` and must not provide `bin/cogbox-env`, which would shadow the helper.
- `--flake` references with URL userinfo (`://[^/@]*@`) are refused before Nix runs, so the documented workflow never puts a credential on a command line. That includes `git+ssh://git@host/...`. Private inputs belong in `git+https://` URLs fetched through the sandbox's own git access; never put tokens in flake references, `flake.lock` or `nix.conf`.
- `apply` and `rollback` take the current selection token (`none` when nothing is selected). A stale token fails, including after A, B, A. Applying the selected generation with its token keeps that token and its previous generation; it reports `changed: true` only when it had to import the generation's closure again. Rollback is one level: it selects the generation selected before the current one, so rolling back twice returns to the start. Both import the target's closure from its archive, offline, when it is missing.
- `clear` takes the token too and removes the selection; generations stay.
- `restore` imports the selected generation (or `--generation`) offline when its closure is unavailable; `changed` is true only when an import happened.
- `exec -- CMD` runs one command with the runtime bin first on PATH. Everything else prints one JSON envelope and exits 0 only when it is `ok`, except the boot unit's `restore --boot`, whose exit status follows the restore outcome instead: 0 when nothing is selected or the outcome is `active` or `restored`, 1 when it `failed`.

A replacement bundle is the complete desired bin set: tools it omits leave the runtime directory, though the base image or a plugin may still provide the name. Long-lived processes keep running; newly executed tools follow the pointer, and a program holding an old executable or an absolute store path keeps that version.

### PATH precedence

The runtime bin comes first, ahead of the plugin tools (`~/work/.cogbox/brain/bin`) and the base system, in login shells, tmux panes and the harness launchers (see [Harnesses](harnesses.md)). A non-login `ssh box cmd` through the SSH gateway sees it too: the bash that sshd starts reads `/etc/bashrc`, which sources `/etc/profile` when no parent shell did. Run any command that does not see the bundle's tools as `cogbox-env exec -- CMD`. A shell that already resolved a name needs `hash -r`.

The login warning is printed only by interactive login shells, and only when `current` is a symlink whose `bin/` no longer resolves to a directory: the boot restore is still running, has failed, or was skipped by the kill switch. It names `cogbox-env status` and `systemctl status cogbox-runtime-restore`.

## Protocol v2

GCE image pins are write-once, so the wire protocol and the on-disk state format in a shipped image are permanent on the boxes that run it, and the helper and its consumers roll independently. The helper reports `PROTOCOL_VERSION = 2`, `STATE_FORMAT = 1` (the generation identity version, unchanged from the POC so its generation ids stay valid) and `HELPER_VERSION = "0.2.0"`.

Transport: `cogbox-env rpc --state-dir ABS --timeout N`. One JSON request on stdin (at most 64 KiB, strict: no duplicate keys, unknown fields or trailing data), one envelope on stdout (at most 4 MiB), diagnostics on stderr. Exit 0 if and only if `ok`.

| `action` | Fields besides `version` | Accepted `version` |
| --- | --- | --- |
| `capabilities` | none | any integer >= 1 |
| `status` | none | 2 |
| `prepare` | `flake` and `attribute`, or `import_store_path` | 2 |
| `apply` | `generation`, `expected_selection` (`none` or a token) | 2 |
| `rollback` | `expected_selection` | 2 |
| `clear` | `expected_selection` | 2 |
| `restore` | optional `generation` | 2 |
| `prune` | optional `generation` | 2 |

Any other version is `unsupported_version`. Generation ids are 64 lowercase hex characters and selection tokens 32.

The envelope has exactly `version`, `ok`, `action`, `changed`, `generation`, `status`, `error` (`{code, message}`) and `capabilities`. `generation` is set only on an ok prepare and `capabilities` only on an ok capabilities response; every other ok response carries `status`. Error envelopes have `changed: false`, with one exception: `status_unavailable` is `ok: false, changed: true, status: null`, meaning the selection change committed but observing it afterwards failed. Error envelopes of actions other than `status` carry a best-effort `status`. `action` is null only on an error envelope, when the helper could not read a known action from the request: it was unparsable, oversized, not received before the deadline, or named no known action.

The capabilities payload is `helper_version`, `protocol_versions` (`[2]`), `state_formats` (`[1]`) and `actions` (the sorted eight names). Answering it opens, creates and locks nothing.

The status object:

- `selection`, `selected_generation`, `active_generation`, `previous_generation` (set only when retained and valid), `output` (null when the selected manifest is invalid);
- `generations[]`, each `id`, `output`, `derivation`, `system`, `provenance {kind, source, attribute, inputs_digest}`, `closure_available`, `archive_present`, `archive_valid` (always null: status does not hash archives), `archive_bytes`, `created_at` (manifest mtime, which an archive repair keeps, so a repaired generation keeps its place in the oldest-first retention order);
- `corrupt_generations[]` (sorted, disjoint from `generations`) and `ignored_entries` (stray names under `generations/`);
- `boot_restore`: null, or `{boot_id, outcome: active|restored|failed, code, generation, finished_at, duration_ms}`;
- `limits`: `{max_generations, archive_budget_bytes, archive_bytes_total, free_bytes, reserve_bytes, max_path_nar_bytes}`;
- `guest_system`, `boot_id`.

When the selected generation is not in `generations`, `output` and `active_generation` are null. When it is, `output` is that generation's output and `active_generation` is set exactly when its closure is available.

Error codes: `invalid_request`, `unsupported_version`, `stale_selection`, `invalid_generation`, `unavailable_closure`, `invalid_archive`, `prepare_failed`, `restore_failed`, `corrupt_state`, `internal_error`, `no_previous`, and, new in v2, `insufficient_space`, `not_ready`, `store_inconsistent`, `timed_out`, `status_unavailable`.

**Compatibility contract.** The producer never removes or retypes a v2 field. Consumers ignore unknown object keys at every level, still require the known required keys, and treat an unknown error code as `internal_error`; unknown subtrees still pass the consumers' structural checks, so no object at any level, new fields included, may hold two keys equal under Unicode simple case folding or nest deeper than 32, and a collection keyed by data (tool names, say) is emitted as an array. On an ok `apply` or `rollback`, a moved selection token always comes with `changed: true`, while `changed: true` beside an unmoved token is legal for `apply` only (re-applying the selected generation re-imported its closure). A breaking change bumps `version`, and a helper keeps answering every version it lists in `protocol_versions`; it refuses any other with an `unsupported_version` error envelope in its own version (integer `version`, `ok: false`, `error.code`, no status), which is the one envelope a v2 consumer reads at a version other than 2. A consumer keeps speaking v2 for as long as boxes carrying a v2 helper exist. Value domains are part of the contract: `error.code`, `boot_restore.outcome` and `boot_restore.code` are open (a consumer reads an unknown value as unknown, an unknown code as `internal_error`; the two `boot_restore` fields stay lowercase words of at most 64 characters), while `version`, `action`, `provenance.kind`, `changed: true` on an error (only `status_unavailable`) and the identifier and store-path patterns are closed, so a producer adding a value to any of those makes a breaking change that needs a `version` bump.

`tests/fixtures/runtime-env/protocol-v2/` pins the exact wire bytes of every envelope shape (`apply-reimport-ok` is a `{"request", "response"}` pair, because an unmoved token beside `changed: true` cannot be read off the envelope alone); the unit tests compare against them byte for byte (`COGBOX_ENV_REGENERATE=1` rewrites them), and consumers copy those files verbatim. `tests/fixtures/runtime-env/state-format-1/` is a state tree the POC helper wrote, which every future helper must keep parsing, because an image upgrade keeps the work pool and with it the state.

## State and persistence

The state directory is `/var/lib/cogbox/work/.cogbox/runtime`, the same directory as `~/work/.cogbox/runtime`; `--state-dir` is resolved once. On a hosted guest it lives on the data pool.

```
current -> selections/<token>             atomically replaced pointer
selections/<token>/selection.json         {generation, previous}
selections/<token>/bin -> <output>/bin
generations/<id>/manifest.json            identity, closure, archive size and sha256
generations/<id>/closure.nar              nix-store --export of the full closure
generations/<id>/root -> <output>
roots/<id>                                indirect GC root
boot-restore.json                         last boot restore record
lock                                      one flock for every action
disable-boot-restore                      optional kill switch
```

The parent, `<work>/.cogbox`, belongs to brain-materialize, and the helper never creates it. Until it exists every action except `capabilities` fails `not_ready`, and the boot restore treats it as nothing to restore. Only `prepare` creates state, and only the state directory and its three subdirectories, with durable syncs; every other action on a missing state directory reports an empty state and creates nothing, not even the lock file. So nothing lands on the root tmpfs before brain-materialize, or under an unmounted pool.

One damaged or stray entry never fails a verb: dot entries are skipped, stray names counted in `ignored_entries`, unreadable generations listed in `corrupt_generations`, and a missing or corrupt previous generation reads as no previous. A corrupt `current` pointer, selection record or bin link is still `corrupt_state`, since those are written atomically and only tampering breaks them.

`status` waits at most 15 seconds for the lock and then fails `timed_out`; mutations wait up to their whole `--timeout` (600 seconds by default). A selection commit blocks the timeout signal from before the new pointer is created until the end of the request, and any failure after the pointer moved reports `status_unavailable`, so an envelope never claims an unchanged selection that actually changed.

What each event does on a GCE sandbox:

| Event | Writable store | Store database | Work pool | Boot restore |
| --- | --- | --- | --- | --- |
| Reboot inside the guest | kept | reset | kept | imports present-but-unregistered paths, rewriting them in place |
| Control-plane stop and start | re-created by the host | reset | kept | imports the missing paths |
| Upgrade-image swap | reset | reset | kept | imports the missing paths |
| Recreate | new | new | new | nothing to restore |

The guest store database is on the RAM root and is never persisted, so every GCE boot takes the import path. Restore always targets the selected generation only.

## The boot restore

`cogbox-runtime-restore.service` runs `cogbox-env restore --boot --state-dir /var/lib/cogbox/work/.cogbox/runtime --timeout 900`:

- `Type=oneshot`, `RemainAfterExit=true`, `TimeoutStartSec=960`, `TimeoutStopSec=30`, `Nice=10`, best-effort I/O priority 7, and `OOMScoreAdjust=500` so a pathological import is killed before user processes.
- Wanted by, and ordered after, `multi-user.target` (the house pattern for background units), and after `cogbox-brain-materialize.service`. It is never before sshd, brain-materialize, `systemd-user-sessions` or `multi-user.target`, so it never delays login, and GCE readiness (the guest host key and its post-sshd boot stamp) does not depend on it.
- When the guest declares a `/var/lib/cogbox/work` filesystem (the hosted profile), it also `Wants=` and is `After=` `var-lib-cogbox-work.mount` and has `ConditionPathIsMountPoint=/var/lib/cogbox/work`. That bind is `nofail`, which strips its `Before=local-fs.target`, so the unit orders on the mount itself. A soft dependency rather than `Requires=` or `RequiresMountsFor=`: `After=` waits for the mount job to finish either way, and over an absent pool the mount-point condition skips the unit (inactive, not failed) without touching the shadowed directory underneath. `cogbox-guest-pool-degradable` pins the Wants=+After= pair and rejects any `RequiresMountsFor=` on a pool path.
- `ConditionPathIsSymbolicLink=.../current` skips it when nothing is selected, and `ConditionPathExists=!.../disable-boot-restore` is the per-box kill switch.
- On a VM guest it is also a boot-only unit: `ConditionPathExists=!/run/cogbox/once/%N`, a marker `cogbox-boot-settled` writes once the boot has settled when this boot started the restore and it did not fail (skipped by its conditions counts as started). A later start in the same boot, such as a configuration switch starting `multi-user.target` again, is then skipped instead of restoring a second time; select a generation after boot with `cogbox-env apply`. See [boot-only units](internals.md#boot-only-units-once-markers).
- No `Restart=`.

In boot mode the helper takes the lock, restores the selected generation, atomically writes `boot-restore.json` (exposed as `status.boot_restore`), prints one line to the journal, `cogbox-runtime-restore: outcome=<active|restored|failed> code=<code|-> generation=<id> duration_ms=<n>`, and exits 0 for `active` or `restored` and 1 for `failed`. That line is on stderr; the unit sets `StandardOutput=null` (and `StandardError=journal`, since the default `inherit` would follow stdout) so the JSON envelope a manual `restore --boot` prints stays out of the journal. A failed restore adds a second line, `cogbox-runtime-restore: error: <code>: <message>` (whitespace collapsed, at most 1024 characters of message), and an error that escapes the restore before it has an outcome prints only that line: neither `boot-restore.json` nor `status.boot_restore` keeps the message, so the journal is the only place to read it. The journal is pool-backed on hosted guests, so the line survives the next restart. A failure shows in `systemctl --failed` and in `status.boot_restore`, and in the login warning only when the bundle's files are gone (after a stop and start). After a reboot inside the guest the files survive, unregistered, so no warning prints. A later manual `cogbox-env restore` makes the selection active again but writes no boot record, so `status.boot_restore` and the failed unit keep reporting that boot's failure until the next boot.

Restoring a generation: when every closure path is present and registered, it only re-roots (`active`, no hashing). A path the database registers but whose files are gone is `store_inconsistent`, because an import cannot repair a registered path; it cannot arise on GCE, where the database never outlives the store. Otherwise the store needs `512 MiB` free, plus the archive size if any path is missing (a present path is rewritten in place and costs about nothing), else `insufficient_space`. The archive's size and sha256 are verified (`invalid_archive`), it is imported with substitution disabled, the closure is re-checked (`restore_failed`) and re-rooted. A non-boot restore additionally runs `nix-store --verify-path`.

Every GCE boot resets the database, so the boot restore always hashes and imports; its cost is bounded by the archive budget.

**Torn window after a reboot inside the guest (accepted).** That reboot keeps the writable store and resets the database, so the selected bundle's files are present but unregistered, and the tools work from login until the restore reaches them. The import then deletes and rewrites each path in place. While it runs, a bundle tool can fail with a missing or half-written file, and `cogbox-env status` answers `timed_out` because the restore holds the lock. The exposure grows with the bundle's closure bytes outside the base image, not with its archive size. Measured on a GCE guest: a bundle adding about 800 KB to the base showed no failure in 122 probes; one adding a 250 MB Go toolchain took 18 s to restore (21 s unit wall time), during which `go` was missing for about 1.1 s, once half-written (`cannot find GOROOT directory`), and missing together with the other tools for another 1.2 s, while a concurrent `status` answered `timed_out` after 18.9 s. Wait until `systemctl list-jobs cogbox-runtime-restore.service` shows no job, then read `status.boot_restore`. It describes this boot only when its `boot_id` equals `status.boot_id`; otherwise this boot's restore was skipped (nothing selected, the kill switch, or no work mount) or killed before it recorded an outcome, or it could not write its record, and `systemctl status cogbox-runtime-restore` says which. A control-plane stop and start has no such window: the paths are simply missing until restored. Removing the window needs a register-only fast path with trusted per-path hashes, which state format 1 does not record.

## Retention

Archives share the work pool with the user's only copy of their work, so they are bounded. Limits are frozen per image and reported in `status.limits`:

- at most 4 generations;
- archives within `min(8 GiB, 25%)` of the work filesystem;
- `max(2 GiB, 10%)` of it kept free;
- 1 GiB per store path (`nix-store --import` buffers each path in memory).

`prepare` checks all of this after querying the closure and before exporting anything: an oversized path, a bundle over the budget, or a bundle that cannot fit after dropping every unprotected generation is `insufficient_space` with nothing dropped. Otherwise it drops corrupt generations first and then the oldest unprotected ones until the new one fits. The selected generation, the valid previous one and the one being prepared are protected. A dropped generation is renamed into a trash entry and unrooted; its closure stays in the store until a garbage collection.

`prune` with no generation removes exactly three things:

- generations whose manifest is missing or corrupt, except the selected one;
- the oldest valid generations other than the selected and previous one, until at most 4 remain;
- leftovers of interrupted operations: `generations/.prepare-*` and `generations/.trash-*`, `.current-*` and `.boot-restore-*` in the state directory, `roots/.preparing-*`, roots whose generation is gone, selections other than the current one, and the `closure.nar.new` and `manifest.json.new` an interrupted archive repair leaves inside a generation.

Nothing else. It leaves entries it does not recognise alone (under `generations/`, `status.ignored_entries` counts the ones without a leading dot), and it does not read archives: it never drops a generation with a valid manifest because its archive is missing or damaged (the same `prepare` repairs that archive, and `prune --generation ID` drops the generation), though such a generation still counts toward the generation limit like any other. `prune --generation ID` drops one generation, the previous one included, but never the selected one (`invalid_request`). An automatic prune runs after every committed `apply`, `rollback` or `clear`; its failures go to stderr only.

## Recovery runbook

- **Boot restore failed with `invalid_archive`**: run the same `prepare` again, which repairs the archive from the closure, then `cogbox-env restore`. A flake prepare rebuilds the closure itself. An import-provenance generation needs its output registered in the store first: after any restart the database no longer registers it (after a stop and start its files are gone too, after a reboot inside the guest they remain), and the repeat answers `unavailable_closure` until the output is rebuilt or re-delivered. The boot record keeps the failure until the next boot.
- **`prepare` cannot find the locked nixpkgs** (after an image upgrade, or a `flake.lock` from another sandbox): `nix flake update nixpkgs --flake-registry /etc/nix/registry.json --flake "path:$(realpath ~/work/tools)"`, then prepare again. `nix flake lock` leaves an existing entry alone, and without `--flake-registry` the update locks the global nixpkgs-unstable over the network.
- **`insufficient_space`**: `cogbox-env prune --generation ID` for a generation no longer needed, or `clear` and then prune; or a smaller bundle. For a restore, free space in the Nix store.
- **`corrupt_state` from `current` or a selection**: `rm ~/work/.cogbox/runtime/current`, then `cogbox-env apply --generation ID --expected-selection none`.
- **A bad bundle with nothing to roll back to**: `cogbox-env clear --expected-selection TOKEN`.
- **`timed_out` from status**: another operation holds the lock, usually prepare or the boot restore. Wait and retry.
- **`status_unavailable`**, or any lost response: run `cogbox-env status` before retrying.
- **Stop restoring at boot on one box**: `touch ~/work/.cogbox/runtime/disable-boot-restore`; remove it to resume.

Never delete or recreate the sandbox to fix a runtime problem: on GCE that deletes the work disk, and `~/work` with it.

## Security

- **Guest-only execution.** prepare, import and restore run only inside the guest, never on the GCE host half, a worker or a seed container. GCE hosts never mount the guest's pool or store volumes, and a host-side import could let a guest-forged archive into a binary cache other machines trust.
- The state belongs to guest root, the sandbox owner. It is not a security boundary against them: the integrity checks catch damage, not a malicious owner.
- The helper never contacts the control plane, and the control plane stores nothing about generations, tokens or archives. RPC request content travels only on stdin.

## Limitations

Deferred: container, workstation, k8s VM-in-pod, local and darwin enablement; control-plane mutation endpoints and UI; a binary-cache archive format; compression and deduplication; store-side reclaim of pruned closures; a narrower lock scope; the register-only fast path that would remove the torn window; user-tunable limits; full NixOS activation, plugin brain reconciliation and policy changes. Durability depends on the filesystem honouring fsync, and selecting a bundle is not a transaction over application data.

## Reproducible validation

```sh
nix build .#cogbox-env .#checks.x86_64-linux.runtime-environment
nix build .#checks.x86_64-linux.runtime-boot-restore        # needs KVM
nix build .#checks.x86_64-linux.cogbox-guest-pool-degradable
python3 tests/test_runtime_env.py runtime/cogbox-env.py -v
```

- `checks.runtime-environment` asserts the enablement matrix (on by default only when hosted, off in the workstation and container guests), the realized hosted unit and its graph, that the hosted `/etc/nix/registry.json` maps `nixpkgs` to a `path` entry for the image's nixpkgs and carries that source into the closure, the login PATH and warning (run against a scratch tree), a plugin-composed hosted guest with the feature on and with a plugin turning it off, and runs the unit tests under both `python3Minimal` and `python3`.
- The unit tests drive the real argv shapes against a mocked store. `COGBOX_ENV_FIXTURES` points them at `tests/fixtures/runtime-env` when the test file is copied alone, and `COGBOX_ENV_REGENERATE=1` rewrites the protocol-v2 goldens.
- `checks.runtime-boot-restore` boots a NixOS VM with the hosted storage shape (tmpfs root, a persisted writable-store disk formatted in stage 1 only when blank, a `nofail` work disk) through a guest-only reboot, a store-loss boot, a slow restore the boot does not wait for, a damaged archive (whose message must reach the journal), the kill switch and a pool-absent boot. On the guest's own Nix and with no network, it also runs the skill's lock recipe on `tests/fixtures/runtime-env/indirect` (an indirect `nixpkgs` input; the registry file is rendered by `nixpkgs.flake.source`, as on the hosted guest, pointing at a stand-in) and a `--flake` prepare of that `__structuredAttrs` bundle under `_NIX_TEST_BARF_ON_UNCACHEABLE=1`, with which Nix throws instead of hashing the locked stand-in again. It then swaps in a `flake.lock` written against another nixpkgs and checks that `nix flake lock` keeps that entry and that the skill's `nix flake update nixpkgs --flake-registry /etc/nix/registry.json --flake ...` restores the first one, which prepare accepts.
- The real-Nix acceptance test needs a materialized fixture (whose flake also has a `reserved` package that ships `bin/cogbox-env`, and a `structured` package built as a raw `__structuredAttrs = true` derivation, the shape `pkgs.buildEnv` produces, whose environment has no `system` binding), plus an unlocked copy of `indirect`, which the test locks with `--flake-registry` against a registry file mapping `nixpkgs` to the archived `tools` flake, then prepares. It runs the stale-lock update recipe the same way, against a second archived copy standing in for another image's nixpkgs. The stand-in carries a directory no evaluation reads, and each recipe prepare must leave it unopened and unread (inotify), must not re-lock (no `lock file` or `Updated input` line on stderr), and must record the identity a full `nix flake archive` gives and the derivation a plain `nix eval` of the recorded source gives. A probe bundle that writes out the `lastModified`, `narHash`, `rev` and `revCount` its evaluation sees then covers three more locks: a registry entry with `rev`, `revCount` and a non-zero `lastModified`, each of which must reach the evaluation unchanged, again without a re-read or a re-lock; a `flake.nix` whose nixpkgs URL changed to the same content without a new lock, where prepare must build what Nix re-locks in memory rather than the stale entry; and a lock that names another valid source path with the stand-in's `narHash`, which must print Nix's `NAR hash mismatch` and still prepare the derivation plain Nix evaluates. A second probe, which writes out whether its evaluation sees nixpkgs as a flake or as a source tree, covers a current `flake = false` entry, which must be overridden without a re-read, and a `flake = false` added or removed in `flake.nix` without a new lock, where prepare must evaluate nixpkgs as the same kind plain Nix does (the lock's). Every helper call runs under `_NIX_TEST_BARF_ON_UNCACHEABLE=1`, except the prepares that must keep plain Nix's evaluation of the stand-in, which hashes it again. Every helper call and every Nix command of the test's own gets a fresh Nix cache directory, since an evaluation an earlier run cached would hide a re-read. It also fails on any Nix deprecation warning in the helper's stderr (as `--no-registries` once printed), and needs `nix` on PATH:

```sh
python3 tests/fixtures/runtime-env/materialize.py /tmp/runtime-fixture \
  --bash /nix/store/HASH-bash --coreutils /nix/store/HASH-coreutils
python3 tests/test_runtime_env_nix.py ./result/bin/cogbox-env /tmp/runtime-fixture
```

It never deletes shared store paths, so it covers the restore fast path but not an import; the VM test covers imports.
