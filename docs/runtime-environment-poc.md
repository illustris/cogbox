# Runtime tool environments (experimental)

`cogbox-env` prepares an ordinary Nix package bundle independently of the NixOS
configuration, selects it for new child processes, rolls back, and retains an
exact closure archive in the guest's durable work directory. It is opt-in. It
does not activate NixOS services, change network policy, replace the kernel or
upgrade a running binary.

Build the helper with `nix build .#cogbox-env`. A future guest can enable
`cogbox.runtimeEnvironment.enable = true`. Both Cogbox guest configurations
already import the module; it is also exported as
`nixosModules.runtime-environment`. The option installs the helper. Cogbox's VM
login, container login and harness launchers then prepend
`/root/work/.cogbox/runtime/current/bin`, including before a generation exists.
The harness itself still runs from its configured absolute executable path.
Existing sessions can use `cogbox-env exec -- bash` or export that stable PATH
entry before starting an agent. Some shells cache command locations; use
`hash -r` when checking whether a removed executable still resolves.

## Prepare and select

Use a normal locked package flake. For example, after choosing and locking the
project's nixpkgs input, its output can contain:

```nix
packages.x86_64-linux.default = pkgs.buildEnv {
  name = "project-tools";
  paths = [ pkgs.hello pkgs.jq ];
  pathsToLink = [ "/bin" ];
  ignoreCollisions = false;
};
```

```sh
cogbox-env prepare --flake "path:$(realpath /root/work/tools)" \
  --attribute packages.x86_64-linux.default
cogbox-env status
cogbox-env apply --generation GENERATION_FROM_PREPARE --expected-selection none
cogbox-env exec -- hello
```

Use a canonical source path: hosted guests make `/root/work` a symlink, and Nix
can reject a `path:` source containing symlink components. `--state-dir` resolves
the durable work symlink itself; source flake references follow Nix's rules.

All commands emit the JSON response envelope. The first apply uses the literal
`none`; subsequent apply and rollback commands require the current selection
token from status. A stale token fails, including after A → B → A. Applying the
already selected generation with its current token preserves both that token
and the previous generation. Prepare never selects a bundle. A replacement
bundle describes the complete desired bin directory, so omitted tools disappear
from the runtime profile. Other inherited PATH entries may still provide them.

```sh
cogbox-env rollback --expected-selection CURRENT_SELECTION_TOKEN
cogbox-env restore                 # selected and previous generations
cogbox-env restore --generation GENERATION
```

Prepare archives the source and its locked inputs, builds the immutable source
snapshot, verifies and roots the complete output closure, and exports it to a
streamed NAR archive before publishing the generation. Missing locks that need
resolution fail. Repeating prepare can reuse the generation, but still resolves
the source and invokes Nix build; this is not an evaluation-free fast path.
`prepare --import-store-path /nix/store/HASH-bundle` is an explicit alternative
for an already delivered output. Its provenance is labeled `import`, never
presented as a locked source build.

Apply and rollback validate existing local closures and update one atomic
selection pointer. They do not evaluate, build or fetch. Long-lived processes
keep running; newly executed tools follow the pointer. A program that keeps an
old executable open or uses an absolute store path keeps that version.

## Persistence and recovery

The default state directory is `/root/work/.cogbox/runtime`; `--state-dir` accepts
an absolute override for isolated tests. The work path may be a symlink to the
persisted volume and is resolved once. State is guest-owner writable with a
private root directory. It is not a security boundary against that owner.

Each generation retains `manifest.json`, `closure.nar` and an output symlink.
The manifest records immutable provenance, exact closure members, archive bytes
and checksums. Stable GC roots live under `roots/`; temporary preparation roots
protect outputs before publication. Each immutable `selections/TOKEN` directory
contains one record with current/previous identities and a bin symlink. Atomically
replacing `current` commits both identities together. Files and parent
directories are fsynced. An interrupted preparation can leave an unselected root
or directory; it cannot select a partially prepared bundle.

Status observes the current pointer and the local Nix database/files for every
recorded closure member. It reports selected and active identities separately.
A selected generation whose closure is absent remains selected and is not active.
Archive presence/bytes are observed separately; `archive_valid: null` means the
checksum was not checked by that observation. Apply and restore additionally
verify store content hashes. Corrupt manifests or pointers fail explicitly.

After writable-store loss, explicitly restore from the retained archives. Restore
verifies the archive checksum, imports its exact contents with substituters
disabled, validates the complete closure and re-registers roots in the current
store. It needs neither source evaluation nor rebuilding. It preserves the
selection. Missing/corrupt archives fail without selecting a replacement.
There is no automatic boot restore in this POC. A manually delivered helper may
itself disappear with the store and must first be redelivered byte-identically;
that bootstrap is separate from restoring the retained bundle.

All prepared generations and old selections are retained. Archives contain full
closures and may be large; there is no quota, deduplication or pruning yet.
Durability depends on the underlying persisted filesystem honoring fsync.
Nix selection is not a transaction over application data.

## Protocol v1

The fixed entrypoint is `cogbox-env rpc --state-dir ABS`. It reads one JSON object
from stdin and emits one JSON envelope to stdout; diagnostics go to stderr.
The operator can set a finite `--timeout` (600 seconds by default). Request input
is limited to 64 KiB, response output to 4 MiB, and subprocess diagnostic capture
to a 64 KiB tail. Archives stream to disk. Failed requests exit nonzero.

Requests always contain `version: 1` and `action`. The only additional fields are:

| Action | Fields |
| --- | --- |
| `status` | none |
| `prepare` | `flake` and `attribute`, or `import_store_path` |
| `apply` | `generation`, `expected_selection` |
| `rollback` | `expected_selection` |
| `restore` | optional `generation` |

Generation IDs are 64 lowercase hex characters; selection tokens are 32 lowercase
hex characters. Extra fields, duplicate keys, trailing JSON and unsupported
versions are rejected. Exec is a human CLI operation, not an RPC action.
Every envelope contains `version`, `ok`, `action`, `changed`, `generation`,
`status`, and `error`; unused nullable fields are explicitly null. Error is
`{code,message}`. Status includes selection/current/previous/active identities,
selected output, retained generation provenance/availability/archive facts,
and independently observed guest system and kernel boot ID. It never labels
the full machine upgraded. After a transport interruption inspect status before
retrying: the pointer may already have committed even if its response was lost.

## Reproducible validation

```sh
nix build .#cogbox-env .#checks.x86_64-linux.runtime-environment
python3 tests/test_runtime_env.py runtime/cogbox-env.py -v
python3 tests/fixtures/runtime-env/materialize.py /tmp/runtime-fixture \
  --bash /nix/store/HASH-bash --coreutils /nix/store/HASH-coreutils
python3 tests/test_runtime_env_nix.py ./result/bin/cogbox-env /tmp/runtime-fixture
```

Supply actual installed Bash/coreutils output paths to the fixture generator.
Its locked local input records exact store contexts, preserving builder closure
references without importing a NixOS configuration. The real-Nix test covers
preparation, live replacement/removal, a continuously running shell/heartbeat,
rollback, no-op, stale ABA rejection, executable collisions, generation reuse,
archive corruption and re-rooting an existing closure. It records timings and
archive sizes; warm build timings are not cold evaluation benchmarks. It never
deletes shared host store paths. Actual store-loss recovery belongs in a fresh,
disposable guest with a durable work volume and a deliberately reset store.

Full NixOS activation/boot coordination, plugin brain and skill reconciliation,
fleet caching, control-plane persistence/UI, quotas and automatic boot restore
remain outside this POC.

A local x86_64 run on 2026-10-12, with the fixture's outputs already cached,
prepared and exported each generation in 2.06–2.28 seconds, selected in
1.03–1.21 seconds and rolled back in 1.18 seconds. Repeating preparation took
1.67 seconds; verifying/re-rooting the already present selected and previous
closures took 3.27 seconds. The two full archives occupied 99,022,016 bytes.
These measurements include integrity/status work and show a small warm fixture,
not fleet throughput or recovery after actual store loss.

The runtime checks passed on one fresh hosted test guest on 2026-10-12, using the
Cogworx POC owner-SSH driver. Guest-side preparation took 6.1–6.8 seconds and
selection/rollback 4.4–4.7 seconds including gateway overhead. An existing shell
kept its PID and boot identity while observing replacement, removal and rollback;
199 heartbeat samples had a maximum gap of 0.305 seconds.

An outer stop/start then erased the helper, both bundle outputs and their unique
executable dependencies. After identical helper-only reinstallation, status kept
the selection token but reported no active generation, and apply refused the
missing closure. With the source snapshot absent, workspace sources removed and
substituters disabled, explicit restore recovered both exact closures in 6.8
seconds and the tools ran again. This validates manual archive recovery on that
guest; it does not establish automatic boot restoration or general performance.
