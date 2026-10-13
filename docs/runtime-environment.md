# Runtime tool environments

`cogbox-env` lets the sandbox owner, or an agent working for them, select one Nix-built bundle of executables at runtime, without rebuilding the guest and without a restart. The bundle's `bin` directory goes first on PATH, every selection is a compare-and-swap with one level of rollback, and the bundle's full closure is archived in the persistent work tree so it is restored offline after a restart. It changes executables on PATH and nothing else: no NixOS activation, services, environment variables, libraries for other programs, network policy, kernel or running binaries.

## Enablement

The NixOS module is `runtime/module.nix`. Every guest configuration imports it (it is the first entry of `cogboxModules`), and it is also exported as `nixosModules.runtime-environment`. The option is `cogbox.runtimeEnvironment.enable`.

It is enabled by default in the **hosted** guest only, the configuration the GCE image runs. `hostedGuestModule` in `flake.nix` sets `cogbox.runtimeEnvironment.enable = lib.mkDefault hostedRuntimeDefault`, and `hostedRuntimeDefault = true` is the one line a dark launch changes to `false` (the checks follow it). Plugin-composed GCE guests re-execute through the `cogbox-hosted` package, which re-evaluates the same hosted configuration with the plugin modules merged in, so they get the feature too. Because it is `mkDefault`, a plugin module may set `cogbox.runtimeEnvironment.enable = false` to turn it off for that sandbox; against a plain `true` the same setting would be a conflicting definition and fail the whole plugin composition. `checks.runtime-environment` evaluates a plugin-composed hosted guest in both directions.

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

A bundle is an ordinary flake package whose output has a `bin` directory. In the guest, lock it against the image's own nixpkgs through the flake registry (`nixpkgs` resolves to the image's nixpkgs source path):

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
nix flake lock "path:$(realpath ~/work/tools)"
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

- `prepare` archives the flake source and its locked inputs with `--no-update-lock-file --no-write-lock-file --no-registries`, builds the immutable snapshot, verifies and roots the complete closure, and exports it to a streamed archive before publishing the generation. It never selects anything. An unlocked or stale flake fails, so lock first and run `nix flake lock` again after changing inputs. It locks new inputs and inputs whose URL changed but never re-resolves an unchanged one, so when an image upgrade removed the locked nixpkgs source, or the `flake.lock` came from another sandbox, re-resolve it with `nix flake update nixpkgs --flake "path:$(realpath ~/work/tools)"`. Use the `path:` and `realpath` forms throughout: `~/work` is a symlink, Nix refuses a `path:` source that goes through one, and inside a git checkout a bare `nix flake lock` refuses a `flake.nix` that git does not track. Re-running prepare for an existing generation reuses it, and repairs a missing or corrupt archive or manifest from the local closure.
- `prepare --import-store-path /nix/store/HASH-NAME` publishes an output that is already in the store; its provenance is labelled `import`.
- A bundle must contain `bin` and must not provide `bin/cogbox-env`, which would shadow the helper.
- `--flake` references with URL userinfo (`://[^/@]*@`) are refused before Nix runs, so the documented workflow never puts a credential on a command line. That includes `git+ssh://git@host/...`. Private inputs belong in `git+https://` URLs fetched through the sandbox's own git access; never put tokens in flake references, `flake.lock` or `nix.conf`.
- `apply` and `rollback` take the current selection token (`none` when nothing is selected). A stale token fails, including after A, B, A. Applying the selected generation with its token keeps that token and its previous generation; it reports `changed: true` only when it had to import the generation's closure again. Rollback is one level: it selects the generation selected before the current one, so rolling back twice returns to the start. Both import the target's closure from its archive, offline, when it is missing.
- `clear` takes the token too and removes the selection; generations stay.
- `restore` imports the selected generation (or `--generation`) offline when its closure is unavailable; `changed` is true only when an import happened.
- `exec -- CMD` runs one command with the runtime bin first on PATH. Everything else prints one JSON envelope and exits 0 only when it is `ok`, except the boot unit's `restore --boot`, whose exit status follows the restore outcome instead: 0 when nothing is selected or the outcome is `active` or `restored`, 1 when it `failed`.

A replacement bundle is the complete desired bin set: tools it omits leave the runtime directory, though the base image or a plugin may still provide the name. Long-lived processes keep running; newly executed tools follow the pointer, and a program holding an old executable or an absolute store path keeps that version.

### PATH precedence

The runtime bin comes first, ahead of the plugin tools (`~/work/.cogbox/brain/bin`) and the base system, in login shells, tmux panes and the harness launchers (see [Harnesses](harnesses.md)). Commands that start no login shell, such as `ssh box cmd`, VS Code Remote-SSH and commands the control plane runs, do not see it; use `cogbox-env exec -- CMD`. A shell that already resolved a name needs `hash -r`.

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
- `generations[]`, each `id`, `output`, `derivation`, `system`, `provenance {kind, source, attribute, inputs_digest}`, `closure_available`, `archive_present`, `archive_valid` (always null: status does not hash archives), `archive_bytes`, `created_at` (manifest mtime);
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
- Wanted by, and ordered after, `multi-user.target` (the house pattern for background units), and after `cogbox-brain-materialize.service`. It is never before sshd, brain-materialize, `systemd-user-sessions` or `multi-user.target`, so it never delays login, and GCE readiness (the guest host key appearing) does not depend on it.
- When the guest declares a `/var/lib/cogbox/work` filesystem (the hosted profile), it also `Wants=` and is `After=` `var-lib-cogbox-work.mount` and has `ConditionPathIsMountPoint=/var/lib/cogbox/work`. That bind is `nofail`, which strips its `Before=local-fs.target`, so the unit orders on the mount itself. A soft dependency rather than `Requires=` or `RequiresMountsFor=`: `After=` waits for the mount job to finish either way, and over an absent pool the mount-point condition skips the unit (inactive, not failed) without touching the shadowed directory underneath. `cogbox-guest-pool-degradable` pins the Wants=+After= pair and rejects any `RequiresMountsFor=` on a pool path.
- `ConditionPathIsSymbolicLink=.../current` skips it when nothing is selected, and `ConditionPathExists=!.../disable-boot-restore` is the per-box kill switch.
- No `Restart=`.

In boot mode the helper takes the lock, restores the selected generation, atomically writes `boot-restore.json` (exposed as `status.boot_restore`), prints one line to the journal, `cogbox-runtime-restore: outcome=<active|restored|failed> code=<code|-> generation=<id> duration_ms=<n>`, and exits 0 for `active` or `restored` and 1 for `failed`. The journal is pool-backed on hosted guests, so the line survives the next restart. A failure shows in `systemctl --failed` and in `status.boot_restore`, and in the login warning only when the bundle's files are gone (after a stop and start). After a reboot inside the guest the files survive, unregistered, so no warning prints.

Restoring a generation: when every closure path is present and registered, it only re-roots (`active`, no hashing). A path the database registers but whose files are gone is `store_inconsistent`, because an import cannot repair a registered path; it cannot arise on GCE, where the database never outlives the store. Otherwise the store needs `512 MiB` free, plus the archive size if any path is missing (a present path is rewritten in place and costs about nothing), else `insufficient_space`. The archive's size and sha256 are verified (`invalid_archive`), it is imported with substitution disabled, the closure is re-checked (`restore_failed`) and re-rooted. A non-boot restore additionally runs `nix-store --verify-path`.

Every GCE boot resets the database, so the boot restore always hashes and imports; its cost is bounded by the archive budget.

**Torn window after a reboot inside the guest (accepted).** That reboot keeps the writable store and resets the database, so the selected bundle's files are present but unregistered, and the tools work from login until the restore reaches them. The import then deletes and rewrites each path in place. While it runs, a bundle tool can fail with a missing or half-written file, and `cogbox-env status` answers `timed_out` because the restore holds the lock. Wait until `systemctl list-jobs cogbox-runtime-restore.service` shows no job, then read `status.boot_restore`. It describes this boot only when its `boot_id` equals `status.boot_id`; otherwise this boot's restore was skipped (nothing selected, the kill switch, or no work mount) or killed before it recorded an outcome, or it could not write its record, and `systemctl status cogbox-runtime-restore` says which. A control-plane stop and start has no such window: the paths are simply missing until restored. Removing the window needs a register-only fast path with trusted per-path hashes, which state format 1 does not record.

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

- **Boot restore failed with `invalid_archive`**: run the same `prepare` again, which builds the closure again and repairs the archive, then `cogbox-env restore`.
- **`prepare` cannot find the locked nixpkgs** (after an image upgrade, or a `flake.lock` from another sandbox): `nix flake update nixpkgs --flake "path:$(realpath ~/work/tools)"`, then prepare again. `nix flake lock` leaves an existing entry alone.
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

- `checks.runtime-environment` asserts the enablement matrix (on by default only when hosted, off in the workstation and container guests), the realized hosted unit and its graph, the login PATH and warning (run against a scratch tree), a plugin-composed hosted guest with the feature on and with a plugin turning it off, and runs the unit tests under both `python3Minimal` and `python3`.
- The unit tests drive the real argv shapes against a mocked store. `COGBOX_ENV_FIXTURES` points them at `tests/fixtures/runtime-env` when the test file is copied alone, and `COGBOX_ENV_REGENERATE=1` rewrites the protocol-v2 goldens.
- `checks.runtime-boot-restore` boots a NixOS VM with the hosted storage shape (tmpfs root, a persisted writable-store disk formatted in stage 1 only when blank, a `nofail` work disk) through a guest-only reboot, a store-loss boot, a slow restore the boot does not wait for, a damaged archive, the kill switch and a pool-absent boot.
- The real-Nix acceptance test needs a materialized fixture (whose flake also has a `reserved` package that ships `bin/cogbox-env`):

```sh
python3 tests/fixtures/runtime-env/materialize.py /tmp/runtime-fixture \
  --bash /nix/store/HASH-bash --coreutils /nix/store/HASH-coreutils
python3 tests/test_runtime_env_nix.py ./result/bin/cogbox-env /tmp/runtime-fixture
```

It never deletes shared store paths, so it covers the restore fast path but not an import; the VM test covers imports.
