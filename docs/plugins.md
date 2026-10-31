# Plugins

Plugins package the [per-instance extension pattern](extensions.md) into something installable: a git repo (or any flake source) that carries a NixOS module **and** the agent-facing kit it contributes (skills, agents, commands, rules), plus the host-side firewall/credential policy it needs. `cogbox plugin add` is the CLI workflow for what previously required hand-editing the instance flake and hand-merging rules.

```sh
cogbox plugin add github:myorg/myplugin?dir=flake            # install into the default instance
cogbox plugin add 'github:org/observability#loki' -n work    # one module of a multi-plugin flake
cogbox plugin resolve github:org/observability#loki          # preview (JSON) -- installs nothing
cogbox plugin update                                          # re-resolve and re-pin everything
cogbox plugin del myplugin                                    # remove module + its firewall rules
```

## The contract

A plugin is a flake that exposes two outputs:

- **`nixosModules.<attr>`** — a standard, reusable NixOS module. It carries ordinary guest config (packages, services, mounts) **and** the plugin's agent-facing contributions under the `cogbox.*` option tree the base declares (see [The kit](#the-kit-cogbox)). Selected by the URL fragment (`URL#attr`); a bare URL means the `default` module. `pkgs` resolves to cogbox's nixpkgs (same caveat as the [extension scaffold](extensions.md#which-nixpkgs-pkgs-is)).
- **`cogboxPlugins.<attr>`** — a thin registration: `{ module = self.nixosModules.<attr>; networkRules; l7Rules; inject; }`. This is the host-side, **hot-reloadable** network/auth policy, read at `cogbox plugin add` with a cheap isolated `nix eval` (no cogbox-system context, IFD-blocked) and merged into `config.json` — applied to the running firewall/proxy **without a rebuild**.

`cogbox plugin add URL` installs `cogboxPlugins.default`; `add URL#loki` installs `cogboxPlugins.loki` (and imports its `.module`). `module` is optional — a **pure-policy** plugin (only firewall/inject, no guest content) omits it and cogbox treats it as the empty module.

### The organizing principle — hot-reload decides where a thing lives

- **Host-side, hot-reloadable policy** (`networkRules`/`l7Rules`/`inject`) lives in the `cogboxPlugins.<attr>` flake output. It is read at `add` by a cheap `nix eval`, stored in `config.json`, and applied to the running firewall/proxy **without a rebuild**. It is never rendered inside the guest.
- **Build-time guest content** (the kit, and any packages/services) lives in the **NixOS module** as `cogbox.*`. A change there already requires a rebuild (on a running VM sandbox it is then [loaded live](#live-apply-vm-sandboxes) when it can be, else at the next restart), so it belongs in the build, where it is evaluated with cogbox's `pkgs` and folded into the guest by the base. Ship a plugin's CLI tools via **`cogbox.packages`** (not raw `environment.systemPackages`) so they land on PATH on *both* the VM and the container backends — see [The kit](#the-kit-cogbox).

A complete mid-complexity plugin:

```nix
{
  description = "cogbox druid-es: Druid performance-analysis agent over an Elasticsearch cluster";

  outputs = { self }: {

    # Everything built into the guest -- the kit AND ordinary NixOS config.
    nixosModules.default = { pkgs, ... }: {
      cogbox = {
        contents = ./contents;                  # scan contents/{skills,agents,commands,rules}
        env.ES_URL = "http://es-1.example.internal:9200";
        settings.claude-code.model = "claude-opus-4-8";
        packages = [ /* es-*, druid-* helper bins */ ];   # tools on the sandbox PATH (both backends)
      };
    };

    # Thin registration: which module is the plugin, plus host-side policy.
    cogboxPlugins.default = {
      module  = self.nixosModules.default;
      l7Rules = [ { allow = "es-1.example.internal"; terminate = true; comment = "ES data node 1"; } ];
      inject  = [ { host = "es-1.example.internal"; style = "basic"; secret = "es-creds"; port = 9200; } ];
    };
  };
}
```

The directory **is** the manifest:

```
data-druid-es/
├── flake.nix
├── bin/                       es-cat, es-search, druid-metric, ...
└── contents/
    ├── skills/{overview,es-query,druid-metrics}/SKILL.md
    ├── agents/druid-investigator.md      # standard agent file (name/description/model frontmatter + body)
    ├── commands/druid-rca.md
    └── rules/read-only.md                # optional; empty `paths` frontmatter => always-on
```

`FLAKE_URL` can be anything nix accepts: `github:owner/repo`, `git+https://...`, `path:/abs/dir`, with `?dir=` for flakes in a subdirectory. The `#attr` fragment is restricted to `[a-zA-Z0-9_-]`. Plugin names follow the instance-name grammar; `user` is reserved.

A `git+http(s)://` or `git+ssh://` URL is fetched by nix EXEC'ING THE `git` CLI, so whatever host half runs `cogbox plugin` must have `git` on PATH (and, for the https form, a CA bundle) or every such URL fails at resolve time with `executing "git": No such file or directory` — a missing-binary error that reads like a network problem. Every backend image is responsible for carrying it: the pod image via its `contents`, the GCE host image via `environment.systemPackages` (both in `flake.nix` / `gce/cogbox-host.nix`, each with a build-time check).

## The kit: `cogbox.*`

The base declares one option tree; each plugin module fills in its slice, and the module system merges across all imported plugins:

| Option | Type | Meaning |
|---|---|---|
| `cogbox.contents` | path \| list of paths | Convention root(s) scanned (`readDir`, pure eval) for `skills/`, `agents/`, `commands/`, `rules/`. Roots concatenate across plugins. |
| `cogbox.skills` / `.agents` / `.commands` / `.rules` | attrset name→path | Explicit units that compose on top of (and override) discovery — e.g. a *generated* skill dir. |
| `cogbox.mcp` | attrset name→`{command/args/env}` \| `{url/headers}` | Neutral MCP servers, materialized per harness. |
| `cogbox.hooks` | attrset event→command | Lifecycle hooks. |
| `cogbox.env` | attrset string→string | Plugin endpoints, merged into the harness launcher env (never a hard global `environment.variables`). |
| `cogbox.packages` | list of packages | Tools placed on the sandbox PATH. **Use this for a plugin's CLIs.** The base folds them into `environment.systemPackages` (baked into the VM runner and into a container's per-instance toplevel) **and** into the brain's `$out/bin`, which login shells and the harness launchers prepend to PATH. The container resolves the brain at every boot, separately from its toplevel, so these tools can still be there when it boots the plugin-less base toplevel instead: no toplevel record yet, a record from another image rev (the post-boot `cogbox-toplevel-reconcile` records a new one for the next boot), an unrealisable record, or the crash-loop guard. That fallback drops everything else the module sets, `environment.systemPackages` included. |
| `cogbox.settings.<harness>` | `{ model; reasoningEffort }` | Per-harness settings. **Allowlist: `model`, `reasoningEffort` only** (enforced by the option type) — never permissions/auth/providers. Keyed `claude-code` / `opencode` / `codex`. |

**Discovery.** A skill is a directory containing `SKILL.md`; an agent/command/rule is a `<name>.md` file. A unit's name is its **basename**, never its frontmatter. The skill's `name:` frontmatter must still equal its directory name (opencode requirement) — but where that used to be an unchecked assertion in this document, it is now **repaired**: when cogbox qualifies a colliding unit it rewrites the `name:` line of its copy to the new name, so the frontmatter and the directory cannot drift apart. Only the *leading* `---` block is touched, and only when the unit already has one; a `name:` line further down is prose. Non-conforming entries (`README.md`, a dir without `SKILL.md`) are skipped.

**Names are natural — cogbox resolves collisions.** A skill is `/druid-rca`, not `/druid-es-druid-rca`. Prefixing is not the author's job: plugins live in independently-owned repos and get installed in arbitrary combinations, so no author can see what their names will be paired with. Two plugins each shipping `skills/overview` is normal, and cogbox disambiguates it instead of refusing to build:

- a discovered name provided by exactly **one** root is installed unchanged;
- a name provided by **two or more plugin** roots is installed once per plugin as `<plugin>-<unit>` — both stay usable, neither keeps the bare name — with each copy's frontmatter `name:` rewritten to match;
- if one of the colliding roots is the **instance's own flake**, that one keeps the bare name and only the plugin copies are qualified: cogbox never renames a user's own content behind their back;
- an explicit `cogbox.<kind>.<name>` still overrides discovery, applied *after* qualification, so it can target either the bare or the qualified name.

Attribution comes from the generated composition flake, which stamps every import with the plugin's install name (`_file = "p-<name>"`; `"cogbox-user"` for the instance's own flake). What cogbox genuinely cannot resolve still **fails the build**, with a message naming the plugins, the unit and what to do: one plugin providing the same name from two of its *own* `contents` roots; a qualified name that is itself already taken; a collision involving a root with no provenance (any `cogbox plugin add/del/update` regenerates the composition and fixes that); and a unit named `cogbox-plugins`, which is reserved for the generated index. Failing the build is the accepted outcome for those four — *"fail to boot, but show a useful error message"* — because there is no correct rename cogbox could pick on the author's behalf.

A fifth refusal differs in kind, and is called out separately because it surfaces differently. Qualification COPIES a unit in order to rewrite its frontmatter, and re-takes a skill's `SKILL.md` from the source so that an intra-tree symlink is not flattened into a dangling one. When that leaf cannot be read at all — a link resolving nowhere even at the source — the copy is refused with the same `cogbox: ` wording. But this one is a **builder** failure rather than an eval throw, so unlike the four above it never reaches `system.build.cogboxBrainCollisions`: on the container backend it lands in the generic `reason=rebuild-failed` fallback, and only the nix build log names the plugin. Such a skill is already broken *without* a collision — the unqualified path symlinks a store copy whose leaf dangles — it merely fails silently there and loudly once qualified.

**Add-time lint.** `cogbox plugin add` does not wait for the next start to tell you any of this. Once the new plugin's source is materialized it enumerates that source's `contents/` the same way the build does, compares it against the already-materialized `contents/` of every installed plugin, and prints what will be qualified:

```
Name collisions with installed plugins (cogbox qualifies both sides):
  ~ skill 'overview' also provided by 'obs-plugin'
      -> obs-plugin-overview, demo-plugin-overview
```

That is **advisory** — the build resolves it and both plugins install. For the NAME-level shapes the build *refuses*, the add itself fails with exit 65 and the build's own wording, so the CLI and the build agree about what installs. Three caveats, all deliberate: the lint reads the conventional `contents/` root because the CLI never evaluates the plugin module (a plugin that points `cogbox.contents` elsewhere is invisible to it); it reports only what **this** add is responsible for, so an instance already carrying an unresolvable pair is not blocked from installing something unrelated; and it compares NAMES only, never the readability of a unit's leaf — so the fifth refusal above is the one shape that passes `plugin add` and can still fail the build later, once a collision makes that plugin's copy qualify. Nothing is written host-side: qualification is derived in Nix from the installed set, so `del`/`update` recompute it for free.

**Migration.** Qualification needs the `_file` stamps, and those come from the composition flake. An instance whose `plugins-flake/flake.nix` was generated by an older CLI has *untagged* roots, so a collision there is unresolvable and lands in the refusal set above. That is intended, and there is no migration code — the next `cogbox plugin add`, `del` or `update` on that instance regenerates the composition and the stamps arrive with it.

**What "fails the build" means on each backend**, because the two differ and the difference is what you are looking at when a sandbox misbehaves:

- **microVM**: the guest system *is* the build, so the refusal is the boot failure. `cogbox init` exits non-zero carrying the message; on GCE the supervisor additionally puts a one-line summary on the serial console and in the `cogworx/boot-error` guest attribute, so the control plane can say why instead of showing "Booting" forever.
- **container**: the per-instance brain is rebuilt at boot and that rebuild is best-effort by design (it has to survive an offline pod), so a refusal does **not** stop the sandbox. It starts on the image's plugin-less *base* brain — no plugin skills, agents, commands, rules or `cogbox.packages` tools — and says so in two places: the `cogbox-brain-materialize` unit's journal, and `~/.config/cogbox/instances/<name>/brain.fallback` (`reason=unit-name-collision`, followed by the messages themselves). A container sandbox that has suddenly lost all of its plugin content is this case; read that file.

**Two deliberate non-features**, enforced by the contract shape:

- **Plugins set no cwd and no `loginShellInit`.** The workdir (`~/work`) and cwd are 100% base-owned, so the cwd fight between plugins is structurally impossible.
- **Plugins ship no always-on `CLAUDE.md`/`AGENTS.md`.** Orientation is relevance-loaded skills (listed in the cogbox-authored index) plus an optional path-scoped `rules/` channel (a rule with empty `paths` ⇒ always-on). There is no channel for a third party to inject always-on, user-outranking prose.

**The image bakes its own skills.** `app-relay`, `cogbox-environment`, `cogbox-filesystem`, `cogbox-packages`, `cogbox-git`, `cogbox-network`, `cogbox-remote-access` and `cogbox-vault`, plus `cogbox-runtime` where runtime tool environments are enabled, are registered through `cogbox.skills`, so each, as an explicit unit, replaces a discovered plugin skill of the same name; give a plugin's skills names of their own.

## The workdir: `~/work`

`~/work` is a base-created symlink into the persisted 9p share (`/var/lib/cogbox/work`); HOME stays `/root`. It is the standardized project dir: agents and users land there (`loginShellInit` and the `c`/`oc`/`om`/`cx`/`h`/`p` launchers `cd ~/work`), it survives restarts, and it is host-visible under `~/.local/share/cogbox/instances/<name>/data/work/`.

At build, the base folds every plugin's merged `config.cogbox` into **one derivation** (`cogbox-brain`) laying out each enabled harness's native tree + merged config + a cogbox-authored capability **index** skill. At boot, one base-owned oneshot (modeled on `load-ssh-keys`) materializes it:

```
~/work/.cogbox/brain      -> the cogbox-brain store derivation (RO leaves)
~/work/.claude/skills/<s>  -> child symlinks into the RO leaves (parents stay real writable dirs)
~/work/.claude/agents/<a>.md, .claude/commands/<c>.md, .claude/rules/<r>.md
~/work/.opencode/{skills,agents,commands}/...   (opencode.json read via OPENCODE_CONFIG)
~/work/.agents/skills/...                        (codex skills)
```

The base drops only **child** symlinks into real writable dirs (never a whole-dir or whole-file link), so the harness can scaffold session state alongside and peers coexist. At boot the materializer first removes every link whose store entry is an earlier `*-cogbox-brain` (in the harness leaf dirs, plus `.claude/settings.json`, `.mcp.json` and `.omp/mcp.json`), so a removed plugin's skills, agents, commands, rules and MCP config stop loading; user files, dirs and other links are never touched. A single base oneshot pre-accepts Claude Code workspace trust for `~/work`.

## Plugins and runtime tool environments

On the hosted guest, [runtime tool environments](runtime-environment.md) offer a second way to get tools: `cogbox-env` selects a Nix-built bundle of executables at runtime, with no restart and one level of rollback, and restores it offline after a restart. It is per sandbox and only touches `PATH`. A plugin is the route for anything shared or reviewed, and for anything beyond executables (services, skills, MCP, network or credential policy), and it loads at the next restart, or [live](#live-apply-vm-sandboxes) on a running VM sandbox when that is safe.

Precedence: a selected bundle's `bin` comes first in login shells and harness launchers, ahead of plugin tools (the brain's `bin`) and the base system. That order is base-owned: the contract gives a plugin no `loginShellInit` surface.

The hosted guest enables the feature with `lib.mkDefault`, so a plugin module may set `cogbox.runtimeEnvironment.enable = false` to turn it off for the sandboxes that install it; the composition still evaluates. Only images that ship `runtime/module.nix` declare the option, so an unguarded setting fails the whole composition on an older image ("The option `cogbox.runtimeEnvironment' does not exist"). Guard it on the option's existence; `lib.mkIf` cannot guard an undeclared option, because the module system still checks the definition's path:

```nix
{ options, lib, ... }: {
  config = lib.optionalAttrs (options ? cogbox && options.cogbox ? runtimeEnvironment) {
    cogbox.runtimeEnvironment.enable = false;
  };
}
```

Setting it to `true` from a plugin on any other profile (workstation, container) is unsupported: there every boot would restore into a RAM-backed store (workstation), or into a copy-on-write store whose stale database an import cannot repair (container).

## Harness-agnostic → native mapping

One neutral unit → each enabled harness's native layout (gated on which harnesses the instance uses):

| Neutral | claude-code | opencode | omp | codex | pi | hermes-agent |
|---|---|---|---|---|---|---|
| **skill** `<s>` | `.claude/skills/<s>/SKILL.md` | `.opencode/skills/<s>/SKILL.md` | `.omp/skills/<s>/SKILL.md` | `.agents/skills/<s>/SKILL.md` | `.agents/skills/<s>/SKILL.md` (native project discovery) | `~/.hermes/skills/<s>/SKILL.md` (VM overlay upper or container state PVC; no project discovery) |
| **rule** `<r>` | `.claude/rules/<r>.md` (`paths:`; empty means always-on) | `instructions` glob in `opencode.json` | `.omp/rules/<r>.md` | `AGENTS.md` digest (always-on) | `AGENTS.md` digest (always-on) | `AGENTS.md` digest (always-on) |
| **agent** `<a>` | `.claude/agents/<a>.md` | `.opencode/agents/<a>.md` | `.omp/agents/<a>.md` | (best-effort) | -- | -- |
| **command** `<c>` | `.claude/commands/<c>.md` | `.opencode/commands/<c>.md` | `.omp/commands/<c>.md` | skill `.agents/skills/<c>` | -- | -- |
| **mcp** `<srv>` | `.mcp.json` `mcpServers` | `opencode.json` `mcp` | `.omp/mcp.json` `mcpServers` | `config.toml` `[mcp_servers]` | -- | -- |
| **settings** | `.claude/settings.json` | `opencode.json` | -- | `config.toml` | -- | -- |
| **env** | launcher env | launcher env | launcher env | launcher env | launcher env | launcher env |
| **index** | `.claude/skills/cogbox-plugins/` | `.opencode/skills/cogbox-plugins/` | `.omp/skills/cogbox-plugins/` | `.agents/skills/cogbox-plugins/` | `.agents/skills/cogbox-plugins/` | `~/.hermes/skills/cogbox-plugins/` |

The same store copy is symlinked into each layout (no duplication). OMP consumes skills, rules, agents, commands, and MCP through its native project `.omp` tree. codex agent/command fidelity is best-effort (claude-only frontmatter is dropped; read-only relies on prompt + egress lockdown). codex, pi, and Hermes have no native per-file rules dir, so the merged rules are concatenated into one `AGENTS.md` digest linked at `~/work/AGENTS.md` (only-if-absent, never clobbering a user file); `paths:`-scoped rules become always-on there. pi and codex share the same `.agents/skills/` tree (agentskills.io layout); Hermes only loads `$HERMES_HOME/skills`, so its links go into the VM's per-instance overlay upper or the container's per-instance PVC-backed home (the host dir is untouched). pi/Hermes have no plugin MCP, settings, agent, or command mapping yet; OMP has no neutral settings mapping yet.

## Network rules and credential injection

`cogboxPlugins.<attr>.networkRules` (L4 CIDR), `.l7Rules` ([L7 vhost rules](network-filtering.md#l7-host-filtering)), and `.inject` ([credential injection](network-filtering.md#host-side-credential-injection)) are the host-side, hot-reloadable policy. If the plugin declares any and the instance is in `rules` mode, `add` shows them all and asks once before merging (auto-confirmed with `-y` or when stdin is not a tty). Injection gets its own louder confirmation section (granting a host-side credential is a different trust than a firewall rule) and prints a `cogbox secret add` bind checklist — the secret is named symbolically and **never** enters the guest.

An `l7Rules` entry's host, `path`, `methods` and `service` must each be a single printable-ASCII token (no whitespace, control or non-ASCII bytes), because the rendered policy file is whitespace-tokenized and its two readers split lines differently. A rule `path` is compared literally against the percent-DECODED request path, so a path that needs whitespace or non-ASCII cannot be expressed; percent-encoding it does not help, since the result only matches a double-encoded request. `methods` must be upper-case HTTP methods joined by commas (`"GET,POST"`), as `l7 add --method` requires. A manifest that violates this fails `plugin add`, `update` and `resolve` with exit 65 and `invalid cogboxPlugins.l7Rules[<i>]: ...` naming the field.

Each merged rule/spec carries a `"plugin": "<name>"` field, so `del`/`update` remove or replace exactly what that plugin brought in. A rule added with `cogbox rules add ... --plugin NAME` or `cogbox l7 add ... --plugin NAME` (how the control plane applies an admin-approved rule request) also carries `"approved": true`; a plugin cannot set that field on its own rules (the merge drops it). It marks a rule an approval granted, which the automatic rollback of a live plugin apply keeps. **Rule/inject changes hot-reload** into a running instance; **kit/module changes need a rebuild**, loaded [live](#live-apply-vm-sandboxes) on a running VM sandbox when that is safe and otherwise at the next `cogbox restart` — that asymmetry is the §"organizing principle" above. An `mcp` server may name only `command`/`args`/`env`/`url`/`headers` — a token/cred_file/secret path is rejected (MCP auth goes through host-side inject, never inline).

A spec's `style` is what the wire gets: it wins over the bound secret's `--kind` (the render keys the element's style off the spec; only the platform kinds `anthropic-oauth` / `gitlab-oauth` force a style of their own). What a plugin cannot choose is the **precedence over a credential the sandbox already sends**: that is the operator's choice at bind time (`cogbox secret add --on-guest-credential replace|keep`), stored in the secret's meta, and it rides through the plugin's spec unchanged -- a manifest `on_guest_credential` key is ignored (neither merged nor a validation error). A plugin spec is also authoritative for its host: an operator `cogbox secret add --inject` bind targeting the same host is skipped at render (one spec per host), so bind the plugin's named secret rather than a second one.

See [Credential injection](network-filtering.md#host-side-credential-injection) for the full security model and the [`cogbox secret`](network-filtering.md#the-secret-store) reference.

## Pinning and updates

Versioning is per flake, not per plugin. `add` resolves the URL with `nix flake metadata`, records the locked URL, rev, and narHash in `config.json` (`.plugins`), and runs `nix flake archive` so the plugin and its transitive inputs land in the local store — subsequent starts resolve the pins offline.

Enabling another module of an already-installed flake **reuses the existing pin**, so all plugins from one flake stay at one rev; `update` resolves each distinct URL once (with `nix flake metadata --refresh`, bypassing nix's eval cache so a mutable ref like `github:owner/repo` actually re-resolves to the current tip) and moves all of its plugins together. To hold a flake at a specific rev, pin it in the URL (`...?rev=<sha>` or `github:owner/repo/<sha>`). A **dirty git worktree** is the worst-pinned shape (no rev, no narHash in the URL); `add` warns — commit, then `cogbox plugin update` to pin properly.

A `.plugins` entry:

```json
{
    "name": "loki",
    "url": "github:org/observability",
    "attr": "loki",
    "lockedUrl": "github:org/observability/<rev>?narHash=sha256-...",
    "rev": "<rev>",
    "narHash": "sha256-..."
}
```

`url` is what you typed (minus the fragment) and is what `update` re-resolves; `lockedUrl` is what the composition flake's inputs consume. `attr` is omitted for the default module.

## The composition flake

Plugin state is materialized as a generated flake at `~/.config/cogbox/instances/<name>/plugins-flake/flake.nix` (marked DO NOT EDIT; regenerated from `config.json` by every `plugin` command). It declares one pinned input per plugin plus the instance's own `flake/` as input `user`, and exposes a single `nixosModules.default` importing each plugin's module via its registration, user module last:

```nix
# GENERATED by 'cogbox plugin' -- DO NOT EDIT.
{
    inputs = {
        user.url = "path:/home/me/.config/cogbox/instances/default/flake";
        "p-mimir".url = "github:org/observability/<rev>?narHash=sha256-...";
        "p-loki".url  = "github:org/observability/<rev>?narHash=sha256-...";
    };
    outputs = { self, user, ... }@inputs: {
        nixosModules.default = {
            imports = [
                { _file = "p-mimir"; imports = [ (inputs."p-mimir".cogboxPlugins."default".module or {}) ]; }
                { _file = "p-loki"; imports = [ (inputs."p-loki".cogboxPlugins."loki".module or {}) ]; }
                { _file = "cogbox-user"; imports = [ user.nixosModules.default ]; }
            ];
        };
    };
}
```

`(... .module or {})` makes the module optional (a pure-policy plugin omits it). The `_file` wrapper carries provenance: nixpkgs passes a module's `_file` down as the fallback file of every inline module it imports, and a plugin's module is a bare function out of a flake output with no `_file` of its own, so it inherits `p-<name>`. That is what lets the guest brain read `options.cogbox.contents.definitionsWithLocations` and attribute a colliding unit to a plugin instead of to an anonymous `/nix/store/...-source` path. At launch, when `.plugins` is non-empty, the wrapper points `--override-input userExtensions` at this flake (at a byte copy of it taken under the instance config lock, so a plugin op that commits during the eval cannot change what is built; only when that copy cannot be written, or the disk is under its free-space floor, does the eval read this flake itself, as before; see [internals](internals.md#guest-extension-re-exec)), so plugins and manual flake.nix edits compose. Because the inputs are pinned and pre-fetched by `nix flake archive`, restarts of a plugin-bearing instance work offline once the runner is built.

The composition's `flake.lock` is kept across regens. Plain `nix flake lock` keeps the old narHash of a `path:` input whose content changed, so after every regen cogbox runs `nix flake lock` and then re-pins the STALE `path:` inputs (the materialized plugin sources and `user`) with `nix flake update <inputs>`; a content-changing `update` therefore actually reaches the lock instead of the guest silently serving the old plugin. The re-pin is never blind: an input is stale only when its locked narHash differs from `nix hash path` of its tree (pure, offline), so a current input is never touched and its transitive inputs never float; and a stale plugin is re-pinned only when its `plugin-sources/<name>` tree is the narHash `config.json` records for it (a half-finished copy or an update interrupted before `config.json` was saved keeps its old pin, with a warning naming the plugin). Plugin sources are materialized with their file modes kept (only ownership is dropped): the NAR records the executable bit, so a copy that stripped it, as cogbox did before, never hashes to the recorded narHash. The copy unlinks each existing file before writing it (`cp --remove-destination`), so a file that survives the best-effort delete of the old tree gets a new inode instead of being rewritten in place: a hard-linked copy of the tree (a live-apply snapshot) never changes underneath. That copy is also why removing or updating a plugin frees no disk space at once: the booted version's files stay allocated until two later `cogbox start`s have retired and emptied the boot snapshot that holds them (see [internals](internals.md#boot-snapshot-live-apply-state)). `cogbox plugin update` heals such a tree: when an up-to-date plugin's `plugin-sources/<name>` does not hash to its recorded pin, update re-copies it from the store path it just resolved, then re-pins it (this also makes the plugin's scripts executable again, as shipped). The re-pin is bounded: each `nix hash path` is capped at 60s (a timeout counts as could-not-hash and keeps the locked narHash), one 120s deadline covers the batched `nix flake update` and its per-input retries, a batch that timed out skips the retries, and fetches carry connect/stall timeouts. The VM runner push (`COGBOX_RUNNER_PUSH=1`, the k8s worker pod) builds the runner of the package the launcher re-execs through (`cogbox` builds `nixosConfigurations.cogbox-<arch>`, `cogbox-hosted` builds `cogbox-<arch>-hosted`), so the `runner.path` record it pre-writes under that package's key names a runner of the same guest layout; its record carries a third line, the composition's `comp` (the sha256 of `flake.nix`, a NUL byte and `flake.lock`, in lowercase hex; a missing `flake.lock` hashes as empty) taken right before the build, and no record is written when those bytes changed during the build. A re-pin that moved the lock saves the pre-re-pin lock as `composition.lock.prev` (next to `plugins-flake/`) until the new pin is confirmed: by a prebuild built from the new lock (the VM runner push, the container brain/toplevel prebuild) or the post-boot reconcile, or on the VM/GCE by the launcher. Until then a container boot whose brain cannot be built offline from the re-pinned lock retries with the snapshot before falling back to the plugin-less base brain. The VM/GCE launcher runs the same gated, bounded re-pin at each boot, before its skip-eval fast path, so a plain relaunch heals a stale lock whose tree is still the recorded pin (a tree an older cogbox materialized with stripped exec bits is not: it never hashes to the recorded pin, keeps its old pin with a warning, and needs a `cogbox plugin update`). `cogbox start` runs the re-pin and its confirmation (below) only in its foreground init pass: its daemon pass, which must reach QEMU within 60s, is launched with `COGBOX_SKIP_REPIN=1` and fast-paths whatever lock the init pass left, so a re-pin that keeps failing (host egress down) is tried once per start and retried by the next start instead of pushing the daemon past its deadline. The launcher saves its own snapshot as `composition.lock.prev` before it touches the lock (marked by `composition.lock.prev.boot`, so a boot killed mid-way leaves it for the next boot to confirm). Whenever a snapshot exists it builds the re-exec package BEFORE the `exec`, without holding the instance config lock (so `cogbox plugin` verbs are not blocked behind a long build) and against a scratch copy of the composition; the outcome is applied only if `flake.lock` did not change meanwhile. On success it drops the snapshot and `runner.path`; on failure it restores the last lock that booted (so a box whose stale lock hid content that does not build keeps serving the old content instead of restart-looping), keeping `runner.path` when the snapshot was the launcher's own (that record names the runner that booted under it). A failed confirmation is sticky: the launcher records the content that failed (`composition.repin.failed`, keyed on the image's runner key) and later launches do not re-pin exactly that content again, so later launcher passes (a GCE boot runs supervise.sh's `cogbox init`, then `cogbox start`'s init pass) and every later boot go straight to the restored lock instead of repeating the same failing full eval. Any `cogbox plugin` op removes the record, and an image change or new plugin content retries. A boot that confirms evaluates twice (the confirmation, then the re-exec). A no-op `update` (nothing re-resolved, nothing re-pinned, composition byte-identical) skips the container brain/toplevel prebuild when the recorded toplevel is current for this image rev and composition and its narinfo is seeded in the plugin-cache.

## Preview before install: `cogbox plugin resolve`

`cogbox plugin resolve URL[#attr] [--git-credential-stdin]` is a read-only preview: it runs flake metadata + the `cogboxPlugins.<attr>` contract check + the host-side `networkRules`/`l7Rules`/`inject` readout and prints **one JSON line** on stdout (`{name, attr, url, lockedUrl, rev, narHash, dirty, present, networkRules, l7Rules, inject}`). It mutates nothing — no config, no source materialization, no composition. It is the foundation for the cogworx plugin store's truthful pre-install posture preview.

## Trust

Adding a plugin evaluates third-party nix code at add time (pure eval, IFD disabled) and *builds* it into the guest at the next start. Treat `cogbox plugin add` like installing software: only add flakes you trust. The contract removes the always-on prompt-injection channel and the cwd fight by construction, sanitizes plugin-authored descriptions before they reach the cogbox-authored index, and surfaces the egress/credential ask for confirmation — but a skill body is still arbitrary plugin prose loaded on relevance. The boundary remains "only add plugins you trust."

## Live apply (VM sandboxes)

On a running VM sandbox, a plugin change made with the cogbox CLI does not have to wait for a restart. `cogbox plugin apply` builds, on the host, exactly the runner the next boot would boot from the committed plugin state, and loads it into the running guest when that is safe: the kernel, initrd, kernel modules, `fstab` and QEMU arguments must be unchanged, and no unit the switch would stop, restart or reload may end sessions, containers or the network. The guest arms a revert before it changes anything, runs `switch-to-configuration test` in a detached, time-bounded unit, checks itself (sshd and the kit unit active, `sshd -t`, a login, the network, no protected unit restarted), and keeps the new system only once the host confirms over a fresh ssh connection. Terminal, tmux and ssh sessions survive; running harness processes keep their environment and settings until they are restarted. After a live apply the next boot boots exactly the live state, on the fast path. The container and k8s backends stay restart-only. The control plane never has its plugin changes applied inline, and until its operator turns live apply on they load at the next restart. It drives live apply itself on its local, gcp and proxmox backends once its operator turns it on: after a plugin change it commits on a running sandbox it runs `cogbox plugin apply --json --op RUN`. When enabled by the operator, it can also offer [Apply anyway](#apply-anyway) through `--force-plan`.

On a running instance, `add`, `del` and `update` apply the committed change inline (the same apply, in the same process) when stderr is a terminal outside the control plane, or anywhere with `--apply`. `--no-apply`, a non-terminal stderr, or `COGBOX_LIVE_APPLY=0` in the environment (the kill switch; `apply` then answers `restart_required/disabled`) leaves the change for `cogbox plugin apply` or the next restart, and says so. A stopped instance simply takes the change at its next start.

### Outcomes

An apply reports one outcome (`--json`: one `{"apply":{...}}` line, also kept in `<icd>/apply/last.json`; an inline apply prints a sentence):

| Result | Meaning | The committed change |
|---|---|---|
| `applied`, `already_live` | the guest runs the new system (`already_live`: it already did) | kept; the next boot boots it |
| `applied_with_failures` | live, but a plugin unit failed while the sandbox's base stayed healthy (`units` names them) | kept |
| `restart_required/<reason>` | not loaded live; it loads at the next restart. The reason says why (below) | kept |
| `rejected/<reason>` | the sandbox proved the change broken: `breaks_base` (it broke logins, sshd, the kit unit or the network), `activation_failed`, `activation_hang` (its activation did not return), `unit_hang` (a unit it starts never finished starting), `unreachable` (the host lost the guest after the switch, and the guest reverted itself), or `eval_error` (its NixOS configuration does not evaluate; the guest is never touched) | **rolled back automatically** (below); the inline form prints `'X' was not applied and has been rolled back: <reason>. Build log: cogbox plugin apply --log G` and exits 1. A rollback that did not simply finish prints `'X' was not applied: <reason>.` and then what happened instead: `Its previous plugin state could not be restored, so the plugins it added or updated were removed.` (the fail-closed tier, after a failed restore such as a full disk; after a `del`, `so the plugins it removed stay removed`), `Its rollback is pending; the next plugin command or start of the instance finishes it.`, or, when the rollback could not be finished at all, `Its rollback could not be finished (see the message above).` after the stamped `cogbox: an automatic plugin rollback could not be finished (...)` line, exiting 78 (below). `cogbox plugin apply` without `--json` prints `plugin apply: rejected/<reason>: the change was not applied` with the same sentences (or `and has been rolled back`) and exits 1, or 78. Both build-log hints carry `-n NAME` for a named instance |
| `undone/<reason>` | the guest was reverted for a cause that does not prove the change broken: `aborted` (Ctrl-C, `apply --cancel`, a stop), `stop_hang`, `switch_timeout`, `unplanned_disruption` (a protected unit, such as sshd, docker or a mount, was restarted, stopped or started outside the plan during the switch), `forced_unit_failed` (a unit [Apply anyway](#apply-anyway) forced failed while the base stayed healthy; `detail` names it), `host_lost` (the host stopped polling), `switch_failed` (the switch failed with the base still healthy; one that broke the base is `breaks_base`) | kept; loads at the next restart |
| `failed/<reason>` | the apply itself failed: `busy`, `build`, `build_timeout`, `build_inputs_uncached`, `inputs_changed` (a plugin source changed during the build; run `apply` again), `snapshot`, `plan`, `switch_locked`, `timeout`, `guest_refused` | kept |
| `superseded` | a plugin change, a stop or a relaunch overtook the apply before the guest was touched | kept |
| `unknown` | the instance stopped or relaunched before the outcome reached the host; the next boot may include the change | kept |

`restart_required` reasons: `disabled` (the kill switch); `not_running` is its own result. Never overridable: `boot_shape`, `kernel_modules`, `fstab`, `init_interface` (the running QEMU fixes the kernel, initrd, modules, mounts and init interface); `base_changed` (cogbox itself changed since the boot), `no_boot_record` (this boot has no usable record of what it booted, e.g. its boot snapshot failed, or the record of a live apply could not be written; restart once), `foreign_system` (something else switched the guest), `customized_flake` (an edited per-instance flake with no plugins), `unsupported_platform` (macOS); `booting`, `air_gapped` (hosted, network `none`), `insufficient_memory`, `insufficient_disk`, `no_containment`, `user_flake_changed`, `composition_stale` (a plugin's locked content differs from its recorded pin, after a failed re-pin), `store_fallback`, `guest_tainted` (an earlier revert failed: restart), `no_helper` (the sandbox predates live apply); and from the unit plan `restart_only_units` (a mount, swap, boot-only unit or `dbus` restart, a mount or boot-only unit a failed or partial boot left down that the switch would start, a change to a user unit in `etc/systemd/user`, or a generator the change adds, removes or retargets, named `system-generators/<name>` or `user-generators/<name>`, such as the `zram-generator` that `zramSwap` brings), `skipped_units` (units a switch never restarts, such as `user@`, `systemd-user-sessions` and getty), `pre_switch_check`; and Apply anyway's own `plan_expired` and `plan_changed` (below). Overridable with [Apply anyway](#apply-anyway): `disruptive_units` (sshd, logind, resolved, docker, containerd, podman's own units or the firewall), `network_config` (systemd-networkd, or the ruleset of an nftables the boot already enabled) and `systemd_reexec`; `detail` names the units, and `plan` lists what applying it anyway would do. A unit the switch only starts counts only when it is not already running: a plugin unit that requires the running docker applies live, while a change that would start a stopped docker (say, removing a plugin that kept it off at boot) does not.

### Apply anyway

A change refused only because going live would stop, restart or reload units that end sessions, containers or the network (`disruptive_units`, `network_config`, `systemd_reexec`) can still be applied live once the owner has seen exactly what that does and accepts it. Such a refusal reports `overridable: true` and a `plan`: `{id, boot_id, comp, P, T, units: [{unit, action, why, class}], repair, reexec}`, every unit with its action (`stop`, `restart`, `reload`, `start`), why it is in the plan (`changed`, `removed`, `new`, `induced`, `guest_reported`, or `propagated:<edge>:<from>`) and its class (`B`, or `C` for the network); `repair` names `cogbox-reply-route.service` when a network unit (class `C`) or `firewall.service` is in it, and `reexec` says systemd re-executes itself. Its human line ends with `to apply it now anyway: cogbox plugin apply --force -n NAME`, then `applying it anyway would:` and the whole plan (each unit with its action, why and class and, for a stop or restart of docker or a restart of sshd or resolved, what that ends; the systemd re-exec; the repair), and only after it `without a terminal, after reading the plan above: cogbox plugin apply --force-plan PLAN -n NAME` (PLAN is the plan's id, which the line shows nowhere else). The units right after the reason are only that reason's, so a plan that also reloads the network, re-executes systemd or repairs the reply route says so only in the listing. A `plan_changed` ends the same way for its new plan (`applying the new plan anyway would:`), and a plan that cannot be listed gets neither hint. The inline output of `add`, `update` and `del` (which never ask) ends, when stdin and stderr are terminals, with `Or run 'cogbox plugin apply --force -n NAME' to apply it now anyway; it would: stop docker.service, restart docker.socket, reload systemd-networkd.service, then restart cogbox-reply-route.service.` (at most eight units named, then the re-exec and the repair). Off a terminal, where `--force` refuses, it ends with `Or apply it now anyway, which would:`, the whole plan listed as above, and only after it `To apply it anyway, after reading the plan above: cogbox plugin apply --force-plan PLAN -n NAME`. A refusal that also has a never-overridable reason lists its plan for information only, with `overridable: false`; force never applies it.

- `cogbox plugin apply --force [-n NAME]` runs the apply and, when it ends overridable, lists the plan on stderr (each unit with its action, why and class, and for a stop or restart of docker, a restart of sshd or of resolved what that ends; the systemd re-exec, the repair, what that does to everyone using the sandbox, and which checks it relaxes) and asks `Apply anyway (plan ID)? [y/N]`. It needs stdin and stderr on a terminal, and takes no `--json`: both are refused at once (exit 64, before any lock is waited for). Only a line typed after the question is shown answers it (what was typed before, during the apply or before a changed plan was listed, is discarded), and a plan whose listing could not be written is not asked about. Nothing is held while it waits for the answer: any answer but yes, EOF, or Ctrl-C applies nothing anyway (exit 1, or the signal's). After a yes it runs the apply again, bound to that plan; when the plan changed meanwhile it lists the new one and asks again, at most three forced runs, then stops with nothing applied anyway (exit 1). A plan that expired while it waited (another plugin change, a restart, or 30 minutes) is planned again by a plain apply, and its new plan is asked about the same way.
- `cogbox plugin apply --force-plan PLAN [--json] [--op RUN] [-n NAME]` is the form for scripts and the control plane: one run bound to the plan id an earlier apply reported, with the exit codes of a plain apply.

**The binding.** Every offered plan is stored as `<icd>/apply/plans/<id>.json` when it is reported (one that cannot be stored, whose unit list the guest would refuse, or that names a unit outside the unit-name charset in a unit or a `why`, is not offered: `overridable: false`, `plan: null`). A forced run is admitted only for a stored plan less than 30 minutes old, made in this boot of the instance and of the host, for the same plugin state; anything else ends `restart_required/plan_expired` before anything is built. It then builds and plans again from scratch, and only the same plan id is forced: a plan that changed (the guest stopped or started a unit, another plugin change landed) ends `restart_required/plan_changed`, with the new plan stored and reported and nothing applied; a re-plan that is now never overridable stays refused; one that needs no force any more applies as a plain apply. The report of a forced run carries `forced: {plan, units}` (the units the guest was told to relax: those the plan stops, starts or restarts, `[]` when it only reloads units or re-executes systemd), else `forced: null`.

**What force relaxes, and what it never does.** It relaxes only the post-check comparisons of the units the plan stops, starts or restarts: any of them may end up restarted, stopped or started during the switch, not only as the plan says. A unit the plan only reloads (networkd for a `.network` change, an nftables ruleset) is not relaxed: a reload keeps its InvocationID and its running state, so a restart or stop of it during the switch is still `undone/unplanned_disruption`. A plan with a network unit (systemd-networkd, nftables) or `firewall.service` in it gets its repair (`cogbox-reply-route.service` restarted after the switch, and again after a revert). A relaxed unit that fails while the base stays healthy is `undone/forced_unit_failed`: the guest goes back, and the change is kept for the next boot. It never touches tier 1 or any other never-overridable reason, the base checks (sshd and the kit unit active, `sshd -t`, a login, the network after the repair), the guest's own revert timer, the host's confirm over a fresh ssh connection, or the automatic rollback of a change those prove broken: a forced sshd change that breaks `sshd -t`, or locks new logins out, is rejected and rolled back like any other, and the rollback never re-grants a rule or an injection. If the change is undone, the listed units restart again. Every admission and every end is a `"event":"force"` line in `<icd>/apply/audit.log` (the invoking uid and euid, the plan and the units it relaxes, the result), and the guest journals the units it was told to relax and the repair.

### Automatic rollback

A rejected change is rolled back on the host so the next boot does not include it: the guest is already back on its previous system, and the plugin entries, `plugin-sources/`, the composition and `runner.path` return to what the guest runs (for `eval_error`, to the last state that evaluated, which keeps an earlier change that was only `restart_required`). Network policy only ever narrows on a rollback:

- a rolled-back **add** takes every rule and injection the plugin brought with it, denies included;
- a rolled-back **update** or **del** keeps or re-adds the plugin's denies, but never re-grants an allow or a credential injection the change removed. An allow an admin approved (`rules add --plugin` / `l7 add --plugin`, which mark it `"approved": true`) stays.

The records are in `<icd>/apply/rollbacks.jsonl` (`cogbox plugin apply --status --json` shows them). A rejected change can only be installed without a live test by making it on a stopped sandbox. A rollback that cannot finish (a full or read-only disk) stays pending: the instance does not start and the plugin changes refuse, with exit 78 and `cogbox: an automatic plugin rollback could not be finished (...)`, until space is freed (a read-only disk: until it is writable again) or, on a full disk, `cogbox plugin apply --abandon-rollback` moves it aside (the config then boots as it is). Nothing can be moved on a read-only disk. When a live apply was interrupted and its record of the guest's answer remains, a later plugin command can read the rejection again and leave a new pending rollback; `--abandon-rollback` says so, and running `cogbox plugin apply --status` and then `--abandon-rollback` again settles it.

### Plugin changes during an apply

A plugin change and a live apply never overlap: a change made while an apply is still building stops that apply (it ends `superseded`; the guest is untouched) and goes ahead, while a change made during the apply's guest phase waits for it, printing `waiting for the live apply of generation G to finish (at most N s)` every minute, at most `COGBOX_APPLY_WAIT_MAX` seconds (from the environment, 1200 by default), and then exits 69 having changed nothing.

Exit codes specific to plugins: 69 means a plugin change gave up waiting for a live apply that is finishing, and nothing changed; 78 means an automatic plugin rollback could not be finished (usually a full or read-only disk): `add`, `del`, `update`, `reconcile` and `apply` refuse, and the instance does not start, until disk space is freed (a read-only disk: until it is writable again) or, on a full disk, `cogbox plugin apply --abandon-rollback` is run. Every plugin subcommand first finishes a pending rollback; `list` and `resolve` report one that cannot finish and carry on.

Tunables (environment, seconds or MiB): `COGBOX_APPLY_TIMEOUT` (the whole apply, 5340), `COGBOX_APPLY_BUILD_TIMEOUT` (1800), `COGBOX_APPLY_SWITCH_TIMEOUT` (the bound of the guest's switch, 60 to 3600, default 840; the guest reverts on its own once this plus 120 s has passed since the apply started it, unless the host has confirmed), `COGBOX_APPLY_MIN_AVAILABLE_MB` (2048), `COGBOX_APPLY_MIN_FREE_MB` (64) and `COGBOX_APPLY_WAIT_MAX` (1200). The mechanism, its bounds and its on-disk state are in [internals](internals.md#live-plugin-apply).

### Writing plugins that apply live

- **Never block in activation.** A `system.activationScripts` snippet that waits (on the network, on a lock, on a prompt) hangs the switch, is rejected as `activation_hang` and rolled back; at boot it would hang the boot.
- **Give every oneshot a timeout** (`serviceConfig.TimeoutStartSec`), especially one that waits for egress that may still be awaiting approval: a oneshot has no start timeout by default, and one that never finishes starting is rejected as `unit_hang`.
- **Mind what restarts.** A changed unit restarts on a switch; set `restartIfChanged = false` for a unit that must not, or `reloadIfChanged` where a reload suffices. Do not hang units off base units with `requiredBy`/`partOf`/`bindsTo`: a stop or restart propagates, and the apply refuses a plan that reaches sshd, the network or a mount.
- **tmpfiles:** a `D` or `R` line empties its directory whenever the rules are re-applied with `--remove`, which a switch that changes the tmpfiles configuration does (`systemd-tmpfiles-resetup`), live as at boot.
- **What needs a restart:** a new or changed mount or swap, a change that restarts a boot-only unit, and changes to `user@`, `systemd-user-sessions` or getty units, always; `.network` files, a ruleset change of an nftables the boot already enabled, and a change that restarts (rather than reloads) the firewall service, sshd, logind, resolved, docker, containerd or podman, unless forced ([Apply anyway](#apply-anyway)). Enabling nftables always needs a restart, forced or not: it blacklists the `ip_tables` module, which changes the initrd (`kernel_modules`), as does any change to `boot.blacklistedKernelModules` or `boot.extraModprobeConfig`. An iptables firewall reload, which `networking.firewall.extraCommands` changes cause, is applied live, so a rule that cuts off ssh is caught only by the host's confirm and rolled back as `unreachable`.

## Plugin verb reference

| Form | Description |
|---|---|
| `cogbox plugin list [-n NAME]` | List installed plugins with their pinned revision and rule count |
| `cogbox plugin add FLAKE_URL[#ATTR] [--as PLUGIN] [-y] [--apply \| --no-apply] [-n NAME]` | Resolve, pin, and install. `#ATTR` selects `cogboxPlugins.<attr>` (default: `default`). `--as` overrides the derived name; `-y` skips the confirmation. Reports unit-name collisions with the installed plugins, and refuses (65) the ones the build cannot resolve. |
| `cogbox plugin resolve FLAKE_URL[#ATTR] [--git-credential-stdin]` | Preview (JSON) the contract + host-side rules/inject without installing |
| `cogbox plugin del PLUGIN [-y] [--apply \| --no-apply] [-n NAME]` | Remove a plugin and exactly the network rules it brought in |
| `cogbox plugin update [PLUGIN] [--git-credential-stdin] [--defer-rules] [--apply \| --no-apply] [-n NAME]` | Re-resolve the original URL(s), re-pin, and replace the plugins' tagged rules. `--defer-rules` (control-plane use; needs `PLUGIN`) leaves the plugin's applied tagged L4/L7 rules untouched, still replaces its inject specs, and prints the incoming rules not already tagged for the plugin (compared ignoring the tag and the comment) as one `{"deferred":{"plugin","l4","l7"}}` stdout line after the config is saved; nothing for an up-to-date plugin or outside rules mode |
| `cogbox plugin apply [--json] [--op RUN] [--force-plan PLAN] [-n NAME]` | Build the committed plugin state on the host and, when nothing it would stop, restart or reload ends sessions, containers or the network, load it into the running VM without a restart: the guest arms a revert before it changes anything, switches, and keeps the new system only when the host confirms over a fresh ssh connection. One outcome line (`--json`: the `{"apply":{...}}` report, also kept in `apply/last.json`); otherwise the change loads at the next restart, with the reason. A change the sandbox proves broken (it breaks logins or the network, its activation or a plugin unit hangs, or the host loses the guest after the switch) or whose composition does not evaluate is rolled back automatically: the guest returns to its previous system and the plugin state on the host to the last one the guest ran, without re-granting any network rule or credential injection the change removed. Ctrl-C asks the guest to undo the switch and exits. `--force-plan PLAN` applies a reported plan anyway ([Apply anyway](#apply-anyway)). See [internals](internals.md#the-apply-verb-host) |
| `cogbox plugin apply --force [-n NAME]` | On a terminal: apply, and when the change can go live only by disrupting units, list them and ask whether to [apply it anyway](#apply-anyway) |
| `cogbox plugin apply --status [--json] [--since N] [-n NAME]` | Whether an apply is running, the last outcome, the `base`/`built` snapshot ids and the rollback records past seq N. Settles an apply whose process died first, from what the guest still reports |
| `cogbox plugin apply --cancel [--json] [--op RUN] [-n NAME]` | Stop a running apply (idempotent; with `--op`, only the run with that token: another run's apply is left alone and the answer is `none`), then settle it from what the guest reports. Without the config lock (an apply recording its outcome holds it) it never sends SIGKILL: an apply still running after the SIGTERM answers `pending`, and exits once its record is made |
| `cogbox plugin apply --log GENERATION [-n NAME]` | Print the last 32 KiB of a generation's build output |
| `cogbox plugin apply --abandon-rollback [-y] [-n NAME]` | Move aside an automatic rollback that cannot finish (exit 78 below), so the instance starts with its config as it is. Asks on a terminal; `-y` otherwise. Refused while an apply or plugin change runs |

`add` and `update` take two control-plane flags. `--git-credential-stdin` reads one `host<TAB>user<TAB>token` line from stdin and authenticates that run's nix fetches with it through a temporary 0600 netrc, so the token is never in argv or the environment. `add --defer-rules` installs the module and merges inject specs as usual but does not merge the plugin's L4/L7 network rules: it prints them as the same one-line `{"deferred":...}` JSON on stdout (its own messages go to stderr, and the confirmation prompt is skipped) for the control plane to route through admin approval; with `--apply` it prints nothing when the inline apply rolled the add back, since the plugin is gone. `update --defer-rules` is described in the table above; with `--apply` it prints its line as soon as the update is saved, before the inline apply runs, so unlike `add` the line is not withheld when that apply rolls the update back, and it can then name rules of a version that is no longer installed. Neither flag reviews inject specs: `secret bind` gates the credential, but every inject-spec host renders as an L7 `allow <host> terminate` whether or not its secret is bound, so a plugin's inject host is reachable as soon as the add or update lands.
