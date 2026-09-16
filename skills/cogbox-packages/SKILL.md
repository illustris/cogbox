---
name: cogbox-packages
description: Obtain a tool that is not installed, and make it permanent when it will be needed again after a restart.
---

Check first with `command -v <tool>`, using the command name and not the package
name. The base image already gives you `git`, `curl`, `jq`, `rg` (ripgrep),
`fd`, `bat`, `sd`, `yq` (yq-go), `duckdb`, `mlr` (miller), `dasel`, `gron`,
`datamash`, `jo`, `xh`, `websocat`, `dig` (dnsutils), `htmlq`, `pup`, the
moreutils commands (`sponge`, `ts`, `chronic`, `ifne`, `vipe`), `tmux`, `vim`,
`htop` and `ncdu`, plus the harness launchers and `herdr`. Installed plugins add
tools of their own, which on the container backend reach PATH only through the
login shell, so `command -v` in the shell you are actually using is the check,
not this list.

For one-off use, run it straight from nixpkgs. Flakes and `nix-command` are
enabled in the guest, with the public caches configured as substituters:

- `nix run nixpkgs#<pkg> -- <args>` for a single invocation.
- `nix shell nixpkgs#<pkg> -c <cmd>` to run one command with it on PATH.
- `nix shell nixpkgs#a nixpkgs#b` for an interactive subshell.

Say what that costs, and do not overstate it. The writable nix store layer is
not storage, but how long it lasts depends on the backend: a VM-backed sandbox
re-creates that filesystem before each launch, so anything fetched this way is
downloaded again after a restart, while on the container backend the
per-instance overlay upper is node-local and usually survives a restart until a
reschedule onto another node loses it. `nix profile install` writes to that same
layer and changes none of it. Egress applies either way: in `none` network mode
the fetch fails outright, and in `rules` mode it depends on the host's policy.
Read the actual error instead of guessing which applies. If the tool has to be
there reliably, extend the sandbox rather than re-running `nix shell`.

To make a tool permanent and reproducible, extend the sandbox. Read
`/run/cogbox/environment.json` first, as `cogbox-environment` describes, and
choose the route for the reported mode:

- `cogworx`: install a plugin from the sandbox's Plugins tab, then restart the
  sandbox. The restart is required for the new closure to load.
- `local`: tell the user to run `cogbox plugin add <flake-url>` on their host,
  or to edit the per-instance flake at
  `~/.config/cogbox/instances/<name>/flake/flake.nix` there. Never run a
  host-side `cogbox` command inside this guest.

A plugin is a flake exposing two outputs: `nixosModules.<attr>`, the guest NixOS
module, and `cogboxPlugins.<attr>`, a thin `{ module; networkRules; l7Rules;
inject; }` registration. `cogbox plugin add URL#attr` resolves the
`cogboxPlugins` attr and imports its `.module`, so a flake carrying only
`nixosModules.default` does not install; `module` itself is optional for a
pure-policy plugin that ships only network or credential policy.

Ship a plugin's CLI tools through `cogbox.packages`, not
`environment.systemPackages`. The base folds `cogbox.packages` into the system
closure on the VM and onto PATH through the brain's `$out/bin` on the container,
so they reach both backends; `environment.systemPackages` reaches only the VM,
because the container image is built plugin-less, and tools shipped that way go
silently missing on a container sandbox even though the plugin's skills
materialize.

`environment.systemPackages` is the right option in the other place: a
per-instance extension flake in `local` mode, paired with
`system.extraDependencies` when build-time dependencies must be realized locally
too.
