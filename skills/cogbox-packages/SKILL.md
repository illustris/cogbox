---
name: cogbox-packages
description: Get a missing tool or language library, keep tools across restarts, or change services, environment variables or other NixOS configuration through a plugin module, and find out who installs it.
---

Check first with `command -v <tool>`, using the command name and not the package name. The base image already gives you `git`, `curl`, `jq`, `rg` (ripgrep), `fd`, `bat`, `sd`, `yq` (yq-go), `duckdb`, `mlr` (miller), `dasel`, `gron`, `datamash`, `jo`, `xh`, `websocat`, `dig` (dnsutils), `htmlq`, `pup`, the moreutils commands (`sponge`, `ts`, `chronic`, `ifne`, `vipe`), `tmux`, `vim`, `htop` and `ncdu`, plus the harness launchers and `herdr`. Installed plugins add tools of their own, and on the container backend a shell that is neither a login shell nor started by a harness launcher can miss them, so `command -v` in the shell you are actually using is the check, not this list.

For one-off use, run it straight from nixpkgs. Flakes and `nix-command` are enabled in the guest, and `cache.nixos.org` is configured as a binary cache:

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

If `command -v cogbox-env` finds the helper, this sandbox can also keep tools across restarts without a plugin or a restart, as the `cogbox-runtime` skill describes.

To make a tool permanent and reproducible, extend the sandbox. Read
`/run/cogbox/environment.json` first, as `cogbox-environment` describes, and
choose the route for the reported mode:

- `cogworx`: a plugin is installed by the sandbox's owner or an admin. Ask the user to arrange it; do not try it from inside the sandbox, and never run `cogbox` here even where it is on PATH.
  - The installer uses the sandbox's Plugins tab (a flake or archive URL, or an uploaded archive) or, where enabled, the cogworx API or the Ask Cogworx chat. When the installer is not an admin, the plugin's network rules can wait for an admin's approval.
  - Its module loads only at the sandbox's next restart (or next start, if it is stopped), and a restart ends every session in the sandbox, this one included, so leave the timing to the user.
  - A plugin you wrote must be fetchable by whoever installs it: push it, with every file it uses committed, to a git repository the user chooses and the installer can fetch, or give them an archive of its directory (`.tar.gz` or `.zip`) to upload. Give the user the exact URL to install, with `?dir=<subdir>` when the flake is not at the repository root.
- `local`: tell the user to run `cogbox plugin add <flake-url>` on their host (with `-n <name>` unless the instance is `default`), or to edit the per-instance flake at `~/.config/cogbox/instances/<name>/flake/flake.nix` there. A plugin's module, like an edit to that flake, loads at the instance's next start, or after `cogbox restart` (add `-n <name>` unless the instance is `default`) if it is running, which ends every session in it, this one included. Never run a host-side `cogbox` command inside this guest.

## Writing a plugin

A plugin is a flake exposing two outputs: `nixosModules.<attr>`, the guest NixOS
module, and `cogboxPlugins.<attr>`, a thin `{ module; networkRules; l7Rules;
inject; }` registration. `cogbox plugin add URL#attr` resolves the
`cogboxPlugins` attr and imports its `.module`, so a flake carrying only
`nixosModules.default` does not install; `module` itself is optional for a
pure-policy plugin that ships only network or credential policy.

A plugin module is an ordinary NixOS module and gets this sandbox's own `pkgs`, so it needs no nixpkgs input. For example, `flake.nix` at the root of the plugin's directory:

```nix
{
  outputs = { self }: {
    nixosModules.default = { pkgs, ... }: {
      cogbox.packages = [ pkgs.hyperfine ];    # CLI tools
      cogbox.contents = ./contents;            # skills in contents/skills/<name>/SKILL.md
      environment.variables.NOTES_DIR = "/root/work/notes";
      systemd.services.notes-server = {
        wantedBy = [ "multi-user.target" ];
        after = [ "cogbox-brain-materialize.service" ];  # ~/work is in place
        script = ''
          mkdir -p /root/work/notes
          exec ${pkgs.python3}/bin/python3 -m http.server 3090 --bind 127.0.0.1 --directory /root/work/notes
        '';
      };
    };
    cogboxPlugins.default = {
      module = self.nixosModules.default;
      l7Rules = [ { allow = "api.example.com"; } ];   # egress it needs (optional)
    };
  };
}
```

Ship a plugin's CLI tools through `cogbox.packages`: they reach PATH on every backend, and on the container they arrive with the plugin's skills, so they can be there on a boot that lacks the rest of the module. An interpreter with the libraries a project imports ships the same way, for example `cogbox.packages = [ (pkgs.python3.withPackages (ps: [ ps.requests ])) ];`. Everything else the module sets (`environment.systemPackages`, `systemd.services`, `environment.variables`, any other NixOS option) is built into a VM-backed sandbox at its next start. A container sandbox has it only while it boots its own per-instance system, which cogworx normally builds when the plugin is installed, so it can be missing for a boot after an image change or a failed build; a rebuild in the background then normally restores it at the following restart (`journalctl -u cogbox-toplevel-reconcile` shows that rebuild).

- Keep the module small, with packages you know build: on a VM-backed sandbox a newly added module that fails to evaluate or build keeps the sandbox from starting until the plugin is removed or fixed. A container sandbox still starts, without that module, and when the module does not evaluate or a `cogbox.packages` entry does not build, also without any plugin's skills and without some or all of their `cogbox.packages` tools (`journalctl -u cogbox-brain-materialize` says why).
- Leave sshd and the sandbox's own `cogbox-*` units as they are; ordering your own service after one of them, as below, is fine. On a VM-backed sandbox, a module that starts sshd only on demand (`services.openssh.startWhenNeeded`) or disables `cogbox-boot-stamp.service` can keep the sandbox from ever becoming ready, and a restart does not help until the plugin is removed or fixed.
- On a VM-backed sandbox, a download that one of the module's derivations makes while it builds (`pkgs.fetchurl`, `pkgs.fetchgit` and the like) runs outside the sandbox, on the machine that builds its system. This sandbox's network allows, the plugin's own `networkRules` and `l7Rules`, and the credentials the host adds to this sandbox's requests do not apply to it, and that machine may be barred from internal addresses. So a source this sandbox can reach, such as a private repository or an internal server, can still fail to download there, and a failed download is a failed build (above). Use public sources, or commit the file into the plugin itself.
- Keep anything a service has to keep under `/root/work`, and order the service after `cogbox-brain-materialize.service`, which puts `~/work` in place. `/root` is private (mode 0700), so that works for a service that runs as root, like the example; one that runs as its own user, as most NixOS `services.*` modules do (PostgreSQL among them), cannot reach it, so tell the user that such a service's state will not survive a restart and let them decide; never loosen `/root`. Do not keep service state elsewhere, such as `/var/lib/<name>`: most of the guest does not survive a restart (`cogbox-filesystem`).
- `environment.variables` sets a variable for login shells and for commands run as `ssh <sandbox> cmd`, VS Code Remote-SSH included; a systemd service needs its own `systemd.services.<name>.environment`. `cogbox.env` sets one only for a harness started through its launcher and the commands that harness runs.
- `cogbox.contents` installs each `contents/skills/<name>/SKILL.md` as the skill `<name>`, whose `name:` frontmatter must match, or as `<plugin>-<name>` when another plugin ships the same name. Give it a name of its own: `cogbox-plugins` is reserved, and a skill named like one this sandbox already ships is replaced by that one.
- `networkRules` (CIDR ranges) and `l7Rules` (hostnames) declare the egress the plugin needs, and `inject` a host-side credential; all three are optional. Never put a token or password in the module (`cogbox.env` and `environment.variables` included) or in the plugin's URL: the module ends up in the world-readable Nix store and in the plugin's source. A credential goes through `inject`, which only names a secret. Nothing is added until the user binds that secret's value outside the sandbox (in `cogworx` mode on the sandbox's Plugins tab, which marks the unbound ones; in `local` mode with `cogbox secret add` on the host), and the host side then adds it to matching requests, so never ask for the value inside the sandbox.
- `docs/plugins.md` in the cogbox source documents the rest, including `cogbox.mcp`, `cogbox.hooks` and the rule formats; if you need it, ask the user for it rather than guessing where it is.

`environment.systemPackages` also works in a per-instance extension flake in `local` mode, paired with `system.extraDependencies` when build-time dependencies must be realized locally too.
