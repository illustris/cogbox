---
name: cogbox-runtime
description: Keep a set of command-line tools in this sandbox across restarts with cogbox-env, switch between tool sets, roll back, and recover the tools after a restart.
---

`cogbox-env` puts one Nix-built bundle of executables first on PATH and keeps an archive of its full closure in `~/work`, so the same tools come back after a restart without network access. Choose the route that fits:

- One-off use: `nix shell nixpkgs#<pkg> -c <cmd>`, as `cogbox-packages` describes. Nothing to clean up, but it is fetched again after a restart.
- Tools this sandbox should keep across restarts: a `cogbox-env` bundle, below. Takes effect without a restart.
- A shared, reviewed extension that also carries services, skills or network policy: a plugin, as `cogbox-packages` describes. A plugin needs a sandbox restart to load.

A bundle only provides executables. It sets no environment variables, starts no services, supplies no libraries to other programs and changes no network policy.

## Build a bundle

Give the bundle its own directory, for example `~/work/tools/flake.nix`:

```nix
{
  inputs.nixpkgs.url = "nixpkgs";
  outputs = { self, nixpkgs }: let
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
  in {
    packages.x86_64-linux.default = pkgs.buildEnv {
      name = "project-tools";
      paths = [ pkgs.jq pkgs.ripgrep ];
      pathsToLink = [ "/bin" ];
    };
  };
}
```

`"nixpkgs"` resolves through this sandbox's flake registry to the nixpkgs its image was built from. Lock the flake, then prepare it:

```sh
nix flake lock "path:$(realpath ~/work/tools)"
cogbox-env prepare --flake "path:$(realpath ~/work/tools)" --attribute packages.x86_64-linux.default
```

`prepare` never creates or updates `flake.lock` and does not consult registries, so an unlocked or stale flake fails. `nix flake lock` locks new inputs and inputs whose URL you edited and leaves every other entry as it is, so run it again after changing inputs. When a prepare cannot find the locked nixpkgs (after an image upgrade, or with a `flake.lock` written in another sandbox), `nix flake lock` changes nothing: re-resolve it with `nix flake update nixpkgs --flake "path:$(realpath ~/work/tools)"`. Always pass the `path:` and `realpath` form: `~/work` is a symlink, a `path:` source must not go through one, and inside a git checkout a bare `nix flake lock` refuses a `flake.nix` that git does not track. The bundle must contain a `bin` directory and must not ship its own `cogbox-env`.

`prepare` builds the bundle and archives it but changes nothing on PATH. Every command except `exec` prints one JSON envelope (`ok`, `error.code`, `error.message`, `status`) and exits 0 only when `ok` is true; a successful prepare reports the new id in `generation`.

## Select, roll back, clear

Every change to the selection is a compare-and-swap against the current selection token, which `cogbox-env status` reports as `selection` (`null` when nothing is selected):

```sh
cogbox-env status
cogbox-env apply --generation GENERATION --expected-selection none    # first selection
cogbox-env apply --generation GENERATION --expected-selection TOKEN   # later ones
cogbox-env rollback --expected-selection TOKEN
cogbox-env clear --expected-selection TOKEN
```

- `stale_selection` means the selection changed since you read it. Run `status` again and decide again.
- The selected bundle is the complete set of bundle tools. A tool left out of the new bundle disappears from it (the base image or a plugin may still provide that name).
- `rollback` switches to the generation that was selected before the current one. It is one level: a second rollback returns to where you started.
- `clear` removes the selection, so only base and plugin tools remain. Prepared generations stay, and `apply` can select one again.
- `apply` and `rollback` restore a generation from its archive by themselves, offline, when its closure is missing.

## Where the tools resolve

`/root/work/.cogbox/runtime/current/bin` comes first on PATH, ahead of plugin and base tools, in login shells, new tmux panes and the harness launchers. In a shell that already looked a name up, run `hash -r`. Commands that start no login shell, such as `ssh <sandbox> cmd`, VS Code Remote-SSH and commands run by the control plane, do not get that entry: wrap them as `cogbox-env exec -- CMD ARGS`. A program that is already running keeps the version it started with.

## After a restart

`cogbox-runtime-restore.service` restores the selected bundle offline, in the background, after the sandbox has booted. It never delays login. Until it finishes, bundle tools can be missing, and after a stop and start a login shell warns that the selected tools are not active. Check:

- `cogbox-env status`: the tools are usable when `active_generation` equals `selected_generation`. `boot_restore` records the last boot restore: `outcome` is `active`, `restored` or `failed`, with an error `code` when it failed. It describes this boot only when its `boot_id` equals `status.boot_id`; otherwise this boot's restore was skipped, killed, or could not write its record (see `systemctl status cogbox-runtime-restore`).
- `systemctl status cogbox-runtime-restore` and `journalctl -u cogbox-runtime-restore`.

Just after a reboot from inside the sandbox, the bundle files are still on disk but are rewritten in place while the restore runs. For that time a bundle tool can briefly fail with a missing file, and `status` can answer `timed_out` because the restore holds the state lock. Wait until `systemctl list-jobs cogbox-runtime-restore.service` shows no job (the restore has finished, failed or been skipped), then read `status.boot_restore`. Do not run `prepare` or `apply` in the meantime.

If the boot restore failed with `invalid_archive`, run the same `prepare` command again (it builds the closure again and repairs the archive), then `cogbox-env restore`. For any other code, report the code and message to the user. Only if the user asks to stop automatic restores, `touch ~/work/.cogbox/runtime/disable-boot-restore`; removing that file turns them back on.

## Disk limits

Archives share `~/work`, the filesystem that holds the user's work, so they are bounded. `status.limits` reports the values for this sandbox:

- At most 4 generations are kept. The oldest ones beyond that, never the selected or the previous one, are dropped automatically after `apply`, `rollback` or `clear`, and `prepare` drops them too when it needs room.
- All archives together stay within 8 GiB or a quarter of that filesystem, whichever is smaller.
- `prepare` leaves at least 2 GiB or a tenth of that filesystem free, whichever is larger.
- A single store path larger than 1 GiB is refused.

`insufficient_space` from `prepare` means nothing was dropped. Free room with `cogbox-env prune --generation GENERATION` for a generation that is no longer needed (never the selected one; `clear` first if it is), or make the bundle smaller. `cogbox-env prune` with no generation drops generations whose manifest is damaged (never the selected one), enforces the limit and removes leftovers of interrupted operations. It removes nothing else, and never drops a generation because its archive alone is damaged: run that generation's `prepare` again, which repairs it.

## Network and credentials

`prepare` is the only step that may fetch from the network: in `none` network mode it fails unless everything the bundle needs is already in the store. `apply`, `rollback`, `restore`, `clear` and `prune` work offline. For a private input, use a `git+https://` URL the sandbox's git access can already fetch. Never put a token in a flake reference, `flake.nix`, `flake.lock` or `nix.conf`. `cogbox-env` refuses a `--flake` reference that carries credentials, meaning anything with `user@` after `://`, including `git+ssh://git@...`.

## Rules

- Never edit, move or delete anything under `~/work/.cogbox/runtime` by hand. The only file you may create there is the kill switch above, and only when the user asks.
- After any error, a timeout or `status_unavailable` (the selection change happened but could not be confirmed), run `cogbox-env status` before retrying anything.
- On `corrupt_state`, stop and report it to the user. Do not delete state to make the error go away.
- Never delete, recreate or re-provision the sandbox to fix a tool problem.
