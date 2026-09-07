// Per-verb help text and the top-level `cogbox --help` output.
//
// Each verb's own file holds the body it wants to print when invoked
// with --help; this module just enumerates them for the top-level lister.

const std = @import("std");
const util = @import("util.zig");

pub const TOP_LEVEL =
    \\cogbox - run coding-agent harnesses (claude-code, opencode, omp, hermes-agent, dsh; codex/pi opt-in) in an isolated QEMU microvm
    \\
    \\Usage:
    \\  cogbox [VERB] [OPTIONS]            (cbx is a short alias for cogbox)
    \\
    \\Verbs:
    \\  start     Launch the VM in the background, then SSH into it (default).
    \\            --no-ssh just returns; -f/--foreground attaches the console.
    \\  console   Attach the serial console of a running instance (Ctrl-] detaches)
    \\  monitor   Attach the QEMU monitor of a running instance (Ctrl-] detaches)
    \\  stop      Stop a running instance
    \\  restart   Stop then start
    \\  delete    Delete an instance's config and persistent files
    \\  status    Print whether an instance is running, its ports, and net mode
    \\  list      List all instances
    \\  init      Create instance config and host directories without launching
    \\  ssh       Connect to a running instance via SSH
    \\  rules     Manage CIDR allow/deny rules for an instance
    \\  remap     Manage TCP destination-remap rules
    \\  l7        Manage L7 (vhost) allow/deny rules for an instance
    \\  plugin    Manage guest plugins (flakes folded into the VM)
    \\  secret    Bind host-side credentials plugins/harnesses can inject
    \\  help      Show help for a verb (cogbox help VERB)
    \\
    \\Common options:
    \\  -n, --name NAME    Instance name (default: "default")
    \\  -f, --foreground   (start) attach the serial console after launch
    \\      --no-ssh       (start) don't auto-ssh; just launch and return
    \\  -h, --help         Show help and exit
    \\
    \\Run 'cogbox VERB --help' for verb-specific options. Bare 'cogbox' is
    \\equivalent to 'cogbox start' -- it launches the VM in the background and
    \\then opens an SSH session into it (pass --no-ssh to just return). The VM's
    \\serial console and QEMU monitor live on per-instance sockets, so you can
    \\attach and detach (Ctrl-]) freely without stopping the VM.
    \\
    \\Network modes:
    \\  full              Unrestricted networking
    \\  none              Block all outbound traffic (QEMU restrict=on)
    \\  rules             Ordered CIDR allow/deny rules. Default. Seeded with
    \\                    denies for private (RFC1918), link-local (incl. cloud
    \\                    metadata 169.254.169.254), and bogon ranges, followed
    \\                    by allow 0.0.0.0/0 for the public internet.
    \\
    \\Paths (XDG basedir spec):
    \\  Config:  $XDG_CONFIG_HOME/cogbox        (default: ~/.config/cogbox)
    \\  Data:    $XDG_DATA_HOME/cogbox          (default: ~/.local/share/cogbox)
    \\  Runtime: $XDG_RUNTIME_DIR/cogbox        (default: /run/user/$UID/cogbox)
    \\
    \\Environment variables:
    \\  COGBOX_DATA              Override the data root.
    \\  COGBOX_CLAUDE_CONFIG     Host claude-code config dir (default: ~/.claude)
    \\  COGBOX_CLAUDE_AUTH       claude-code auth token file (default: ~/.claude.json)
    \\  COGBOX_OPENCODE_CONFIG   Host opencode config dir
    \\  COGBOX_OPENCODE_DATA     Host opencode data dir, includes auth.json
    \\  COGBOX_CODEX_HOME        Host codex home dir (default: ~/.codex), includes auth.json
    \\  COGBOX_DSH_HOME          Host dsh home dir (default: ~/.dsh)
    \\  COGBOX_L7_INJECT_CONF    Override the generated host-side credential-injection
    \\                           conf (advanced/testing; see docs/network-filtering.md)
    \\
    \\Exit codes:
    \\  0   success
    \\  3   status: instance is stopped
    \\  64  bad CLI args, unknown verb or flag (EX_USAGE)
    \\  65  bad data: invalid value or wrong-type directory input (EX_DATAERR)
    \\  66  missing/unreadable input: config, file, or directory (EX_NOINPUT)
    \\  70  internal/system error (EX_SOFTWARE)
    \\  73  cannot write file: secret store write failed (EX_CANTCREAT)
    \\  75  already running, port collision (EX_TEMPFAIL)
    \\
;

pub const START =
    \\cogbox start - launch the VM in the background, then SSH in (the default verb)
    \\
    \\Usage:
    \\  cogbox start [OPTIONS]
    \\  cogbox       [OPTIONS]            (bare cogbox is equivalent)
    \\
    \\Options:
    \\  -n, --name NAME       Instance name (default: "default")
    \\      --no-ssh          Don't open an SSH session after launch; just start
    \\                        the VM in the background and return.
    \\  -f, --foreground      Attach the serial console after launch instead of
    \\                        sshing. Detaching (Ctrl-]) leaves the VM running.
    \\  --vcpu N              vCPU count (default: 16; or value from config.json)
    \\  --mem N               RAM in megabytes (default: 32768; or from config.json)
    \\  --network MODE        Network mode: full, none, or rules (default: rules)
    \\  --add-dir DIR         Mount an existing host directory read-write at its
    \\                        canonical absolute path in the guest. Repeatable.
    \\  --add-dir-ro DIR      Mount an existing host directory read-only at its
    \\                        canonical absolute path in the guest. Repeatable.
    \\  --no-auto-keys        On first init, leave authorized_keys empty instead of
    \\                        seeding from ~/.ssh/*.pub and ssh-add -L, and skip
    \\                        generating cogbox's own SSH key
    \\  -y, --yes             Skip the harness-selection prompt on first init
    \\  -h, --help            Show this help and exit
    \\
    \\The VM always runs as a background daemon. By default, once QEMU is up
    \\cogbox waits for the guest's sshd to start accepting connections and then
    \\execs `ssh` into the guest; when that session ends the VM keeps running
    \\(stop it with `cogbox stop`). Press Ctrl-C during the wait to leave the VM
    \\running and drop back to your shell.
    \\
    \\First-run setup prompts are shown in the foreground; the daemon's own
    \\output goes to <runtime>/cogbox.log, and the guest serial console is
    \\captured to <runtime>/console.log. Exits 75 if an instance with the same
    \\name is already running.
    \\Additional directory grants apply only to this launch and are not written
    \\to config.json. Repeat them on every later `start` or `restart`.
    \\
    \\Examples:
    \\  cogbox                           Start the default instance and SSH in
    \\  cogbox --no-ssh                  Start in the background and return
    \\  cogbox -f                        Start and attach the serial console
    \\  cogbox --name work               Start the "work" instance and SSH in
    \\  cogbox --vcpu 8 --mem 16384      Start with custom resources, then SSH in
    \\  cogbox --network none --no-ssh   Start fully isolated, don't connect
    \\  cogbox --add-dir ./src --add-dir-ro '/opt/shared docs'
    \\                                    Mount two host trees with mixed access
    \\
    \\See also: cogbox ssh, cogbox console, cogbox monitor, cogbox status, cogbox stop
    \\
;

pub const CONSOLE =
    \\cogbox console - attach the serial console of a running instance
    \\
    \\Usage:
    \\  cogbox console [OPTIONS]
    \\
    \\Options:
    \\  -n, --name NAME       Instance name (default: "default")
    \\  -h, --help            Show this help and exit
    \\
    \\Connects to the guest's serial console (<runtime>/console.sock) and relays
    \\your terminal to it in raw mode. Recent console history is replayed first,
    \\then the session goes live. Press Ctrl-] to detach; the VM keeps running.
    \\Only one console attachment is possible at a time.
    \\
    \\See also: cogbox monitor, cogbox start -f
    \\
;

pub const MONITOR =
    \\cogbox monitor - attach the QEMU (HMP) monitor of a running instance
    \\
    \\Usage:
    \\  cogbox monitor [OPTIONS]
    \\
    \\Options:
    \\  -n, --name NAME       Instance name (default: "default")
    \\  -h, --help            Show this help and exit
    \\
    \\Connects to the human QEMU monitor (<runtime>/monitor.sock) where you can
    \\type commands like 'info status', 'info block', or 'system_powerdown'.
    \\Press Ctrl-] to detach; the VM keeps running. Only one monitor attachment
    \\is possible at a time.
    \\
    \\See also: cogbox console, cogbox stop
    \\
;

pub const STOP =
    \\cogbox stop - stop a running instance
    \\
    \\Usage:
    \\  cogbox stop [OPTIONS]
    \\
    \\Options:
    \\  -n, --name NAME       Instance name (default: "default")
    \\  --force               Skip guest grace; ask the launcher to terminate QEMU
    \\  -h, --help            Show this help and exit
    \\
    \\Idempotent when no launch is recorded. A retained launch consumes its
    \\matching stop result; failed, missing or changed outcomes remain errors.
    \\Normal stop allows up to 45s for orderly guest shutdown, then uses bounded
    \\forced termination with a data-loss warning. Total wait is at most 65s.
    \\Even without fallback, clean guest shutdown cannot be verified; a warning
    \\is reported. Confirmed termination still permits an ordinary restart.
    \\An older launcher receives TERM only; its shutdown cannot be verified.
    \\
;

pub const DELETE =
    \\cogbox delete - delete an instance's config and persistent files
    \\
    \\Usage:
    \\  cogbox delete [OPTIONS]
    \\
    \\Options:
    \\  -n, --name NAME       Instance name (default: "default")
    \\  -y, --yes             Skip the confirmation prompt
    \\  -h, --help            Show this help and exit
    \\
    \\Permanently removes the instance's config dir (config.json, flake/,
    \\plugins-flake/, authorized_keys, ...), its persistent data dir (disk
    \\overlays and guest state), and any leftover runtime dir (sockets, logs,
    \\pid). Refuses to delete a running instance -- stop it first with
    \\'cogbox stop'.
    \\
    \\Prompts for confirmation, listing the directories to be removed, unless
    \\-y/--yes is given (or stdin is not a terminal, as for the CLI's other
    \\prompts). Idempotent: deleting a nonexistent instance prints a notice
    \\and exits 0.
    \\
;

pub const RESTART =
    \\cogbox restart - stop then start
    \\
    \\Usage:
    \\  cogbox restart [OPTIONS]
    \\
    \\Accepts the same options as `cogbox start`, including its default behavior:
    \\once the VM is back up it waits for sshd and opens an SSH session. Pass
    \\--no-ssh to just restart the daemon and return, or -f to attach the console.
    \\
;

pub const STATUS =
    \\cogbox status - print whether an instance is running
    \\
    \\Usage:
    \\  cogbox status [OPTIONS]
    \\
    \\Options:
    \\  -n, --name NAME       Instance name (default: "default")
    \\  -h, --help            Show this help and exit
    \\
    \\Prints one of:
    \\  running pid=N ssh=HOST:PORT http=HOST:PORT net=MODE
    \\  stopped
    \\
    \\Exit codes:
    \\  0  running
    \\  3  stopped
    \\  64 unknown instance (no config.json)
    \\
;

pub const LIST =
    \\cogbox list - list all instances
    \\
    \\Usage:
    \\  cogbox list [--json]
    \\
    \\Options:
    \\  --json                Emit one JSON object per instance instead of text
    \\  -h, --help            Show this help and exit
    \\
;

pub const INIT =
    \\cogbox init - create instance config and host directories without launching
    \\
    \\Usage:
    \\  cogbox init [OPTIONS]
    \\
    \\Options:
    \\  -n, --name NAME       Instance name (default: "default")
    \\  --vcpu N              vCPU count to bake into the new config
    \\  --mem N               RAM in megabytes to bake into the new config
    \\  --network MODE        Network mode: full, none, or rules
    \\  --bind-addr ADDR      Address the guest's port forwards are advertised
    \\                        at (default: 127.0.0.1)
    \\  --no-implicit-dns     Stop port 53 escaping the L4 rule walk, so the
    \\                        seeded link-local/private denies apply to DNS as
    \\                        well. Needs a resolver those rules allow: one
    \\                        inside a denied range breaks DNS silently, unless
    \\                        --dns-host names a forwarder the host provides.
    \\                        Rules mode only.
    \\  --dns-host ADDR       The loopback address the ENCLOSING host runs its
    \\                        own DNS forwarder on. Re-admits exactly that one
    \\                        address on port 53, so a guest whose resolver
    \\                        passt forwards there keeps resolving what the host
    \\                        resolves under --no-implicit-dns. One bare
    \\                        address: no prefix, no port. Rules mode only.
    \\  --self-addr CIDR      An address of the ENCLOSING host, added to the L7
    \\                        proxy's non-overridable floor so an allowed vhost
    \\                        that resolves to it is refused. Repeatable.
    \\                        Rules mode only.
    \\  --no-auto-keys        Leave authorized_keys empty instead of seeding it
    \\  -y, --yes             Skip the harness-selection prompt
    \\  -h, --help            Show this help and exit
    \\
    \\For a rules-mode instance, init also seeds L7 terminate + host-side
    \\credential injection for the provider hosts of any harness you're logged
    \\into, keeping that token out of the sandbox (see `cogbox l7 --help`).
    \\
    \\Idempotent. Re-running on an existing instance only seeds anything that's
    \\missing; existing config is preserved.
    \\
;

pub const SSH =
    \\cogbox ssh - connect to a running instance via SSH
    \\
    \\Usage:
    \\  cogbox ssh [OPTIONS] [-- REMOTE_COMMAND...]
    \\
    \\Options:
    \\  -n, --name NAME       Instance name (default: "default")
    \\      --wait-for-ssh    Wait for the guest's sshd to accept connections
    \\                        before connecting (no-op once it is up)
    \\      --wait-timeout N  Seconds to wait with --wait-for-ssh (default: 180)
    \\  -h, --help            Show this help and exit
    \\
    \\Reads the live SSH host:port from <runtime>/ssh-endpoint, so it works
    \\even with auto-assigned ports. Disables host-key checking since the
    \\guest's root disk is ephemeral and host keys regenerate every boot.
    \\
    \\--wait-for-ssh polls the guest's sshd until it is ready (or the VM dies, or
    \\the timeout elapses) before connecting, closing the cold-boot race in
    \\`cogbox start --no-ssh ... && cogbox ssh --wait-for-ssh ... cmd`. Put it
    \\before any remote command (it is a flag, not part of the command).
    \\
    \\Connects with cogbox's own key (<data>/cogbox_ed25519), generated and
    \\authorized in the guest automatically, so it works out of the box. ssh is
    \\pinned to that key alone (IdentitiesOnly + IdentityAgent=none): your agent
    \\and ~/.ssh keys are not offered and no agent is contacted, so a gpg-agent
    \\can't prompt or stall the connection. With --no-auto-keys (no cogbox key)
    \\ssh instead falls back to your agent and ~/.ssh keys.
    \\
    \\A remote command run from an interactive terminal (stdin and stdout both a
    \\tty) gets a PTY (ssh -t), so TUIs like htop or claude-code render and accept
    \\input. When output is piped or redirected, no PTY is forced and bytes stream
    \\through untouched (e.g. `cogbox ssh -- cat f | sha256sum`).
    \\
    \\ssh joins the words after the target into ONE string and the guest runs it
    \\through `sh -c`, so a command of TWO OR MORE words is quoted word by word:
    \\`#`, spaces, quotes, `$`, backticks and newlines reach the remote command
    \\literally instead of being re-parsed by the guest shell. A command passed as
    \\ONE argument is left alone -- that is the shell-string form -- so pass one
    \\string, or `-- sh -c '<script>'`, when you want guest-side shell syntax.
    \\
    \\Examples:
    \\  cogbox ssh                          Open an interactive shell
    \\  cogbox ssh -- htop                  Run htop on the default instance
    \\  cogbox ssh --name work -- uname -a  Run on the "work" instance
    \\  cogbox ssh --wait-for-ssh -- c      Wait for sshd, then run c (cold boot)
    \\  cogbox ssh -- tmux ls -F '#{session_name}'
    \\                                      Words stay literal (argv form)
    \\  cogbox ssh -- sh -c 'ls /root/*'    Guest-side shell syntax
    \\
;

pub const RULES =
    \\cogbox rules - manage netfilter rules for an instance
    \\
    \\Usage:
    \\  cogbox rules [-n NAME] list
    \\  cogbox rules [-n NAME] add allow|deny [tcp|udp] CIDR[:PORT] [--at N]
    \\  cogbox rules [-n NAME] del INDEX
    \\  cogbox rules [-n NAME] set            (reads rules from stdin)
    \\
    \\Options:
    \\  -n, --name NAME       Instance name (default: "default")
    \\  -h, --help            Show this help and exit
    \\
    \\Spec syntax: an optional proto (tcp|udp) and :PORT narrow the rule;
    \\both default to "any" when omitted.
    \\
    \\Examples:
    \\  cogbox rules add allow 10.0.0.0/8              any proto, any port
    \\  cogbox rules add deny  0.0.0.0/0:25            any proto, port 25
    \\  cogbox rules add allow tcp 1.2.3.4/32:443      TCP port 443 to one host
    \\
    \\Rules apply only when the instance's network mode is "rules". The
    \\evaluator walks the list top-down and stops at the first match; an
    \\unmatched destination is DENIED. (`cogbox init` seeds a trailing
    \\`allow 0.0.0.0/0`, so out of the box only explicit denies bite;
    \\remove that catch-all for a default-deny allowlist.)
    \\
    \\If the instance is running, edits hot-reload via SIGUSR1 to passt
    \\(no VM restart needed).
    \\
;

pub const REMAP =
    \\cogbox remap - manage TCP destination-remap rules
    \\
    \\Usage:
    \\  cogbox remap [-n NAME] list
    \\  cogbox remap [-n NAME] add FROM TO [--at N]
    \\  cogbox remap [-n NAME] del INDEX
    \\  cogbox remap [-n NAME] set            (reads rules from stdin)
    \\
    \\Spec syntax (v1: tcp only, single-host target):
    \\  FROM:  tcp CIDR:PORT       e.g. "tcp 0.0.0.0/0:443"
    \\  TO:    tcp IP[:PORT]       e.g. "tcp 127.0.0.1:18080"
    \\
    \\When a TCP connect() inside the LD_PRELOAD'd network process
    \\matches FROM, the shim rewrites the destination to TO and drives
    \\a SOCKS5 v5 CONNECT handshake on the same fd carrying the
    \\original (IP, port). The downstream proxy thus sees the guest's
    \\real intended destination.
    \\
    \\Examples:
    \\  cogbox remap add "tcp 0.0.0.0/0:443" "tcp 127.0.0.1:18080"
    \\  cogbox remap add "tcp 1.2.3.0/24:80" "tcp 10.0.0.1:8080" --at 1
    \\
    \\If the instance is running, edits hot-reload via SIGUSR1 to passt
    \\(no VM restart needed).
    \\
;

pub const L7 =
    \\cogbox l7 - manage L7 (vhost) allow/deny rules for an instance
    \\
    \\Usage:
    \\  cogbox l7 [-n NAME] list
    \\  cogbox l7 [-n NAME] add allow|deny HOST [--passthrough | --path P
    \\                              | --terminate [--insecure-upstream]] [--at N]
    \\  cogbox l7 [-n NAME] del INDEX
    \\  cogbox l7 [-n NAME] clear --plugin TAG   (drop every TAG-tagged rule)
    \\  cogbox l7 [-n NAME] replace --plugin TAG --from-stdin
    \\  cogbox l7 [-n NAME] policy --from-stdin  (replace the auth-proxy policy
    \\                                            document from JSON on stdin)
    \\  cogbox l7 [-n NAME] set                  (reads HOST rules from stdin)
    \\  cogbox l7 [-n NAME] mode passthrough|terminate
    \\
    \\Options:
    \\  -n, --name NAME        Instance name (default: "default")
    \\      --passthrough      Opt this host OUT of the terminate default: SNI-only
    \\                         passthrough, TLS not intercepted (cert pinning kept).
    \\                         For cert-pinned clients. (Excludes the flags below.)
    \\      --path P           Restrict the host to URL paths under prefix P
    \\                         (boundary-aware, e.g. /v1/; implies --terminate)
    \\      --terminate        Force MITM for this host (already the default)
    \\      --insecure-upstream  Skip upstream cert verification for this host
    \\                         (implies --terminate; the proxy-side equivalent of
    \\                         curl -k, for internal self-signed/mismatched certs)
    \\      --at N             Insert at 1-based position N (default: append)
    \\      --plugin TAG       Tag a rule (add), or select the tagged set to drop
    \\                         (clear) / drop and re-append (replace)
    \\      --from-stdin       replace only: read the new rule set from stdin, one
    \\                         `allow|deny HOST [flags...]` line per rule (the argv
    \\                         tail of `add`; blank and # lines skipped, --at and
    \\                         --plugin not accepted per line). Appended in stdin
    \\                         order, in ONE config edit and ONE reload.
    \\  -h, --help             Show this help and exit
    \\
    \\HOST is an SNI/Host pattern: an exact name (api.example.com), a left
    \\wildcard (*.example.com), or a bare * catch-all. Rules are first-match;
    \\an allowed vhost SUPERSEDES an L4 IP block, a denied one supersedes an L4
    \\allow, and an unmatched host defers to the L4 policy.
    \\
    \\While L4 rules whitelist a destination IP, L7 rules whitelist individual
    \\vhosts behind a shared load-balancer IP. When any L7 rule exists, all
    \\guest 80/443 traffic is funneled through a host-side proxy that allows
    \\only the listed vhosts (matched by TLS SNI / HTTP Host) and re-resolves
    \\the name host-side -- so allowing one vhost does NOT expose siblings on
    \\the same IP, and DNS-based load balancing keeps working. Requires the
    \\instance's network mode to be "rules".
    \\
    \\Two tiers. TERMINATE is the DEFAULT (per host, or `mode passthrough` to
    \\flip an instance):
    \\  terminate (default)  MITM via a per-instance CA injected into the guest
    \\                       trust store; enforces Host==SNI and URL path prefixes.
    \\                       Breaks cert-pinned clients -- use --passthrough there.
    \\  passthrough (--passthrough)  TLS not intercepted (cert pinning preserved);
    \\                       the proxy trusts the SNI and cannot see URL paths.
    \\
    \\Harness API endpoints (api.anthropic.com, api.openai.com, chatgpt.com, api.deepseek.com, ...):
    \\for a harness you're logged into on the host, `cogbox init` seeds a
    \\terminate rule + credential injection (.network.l7.inject) so the real
    \\token is swapped in host-side and the guest carries only a stub -- the
    \\long-lived token never enters the sandbox. Opt a host out with
    \\--passthrough (token end-to-end, cert pinning preserved). A harness with
    \\no host-side token, or any such host with no explicit rule, stays
    \\auto-passthrough. Beyond the harnesses, a plugin can REQUEST injection for
    \\a host (cogboxPlugins.<attr>.inject) and you bind the credential host-side
    \\with `cogbox secret add` (see `cogbox secret --help`); those specs live
    \\under .network.l7.inject.specs[] -- the `inject` field is an object
    \\{enabled, specs}, though the legacy bool is still accepted. See
    \\docs/network-filtering.md (host-side credential injection).
    \\
    \\QUIC/UDP-443 and all guest IPv6 are denied while L7 is active (clients
    \\fall back to inspectable IPv4 TCP).
    \\
    \\Examples:
    \\  cogbox l7 add allow api.example.com                  terminate (default)
    \\  cogbox l7 add allow pinned.example.com --passthrough SNI-only (pinned)
    \\  cogbox l7 add allow api.example.com --path /v1/      terminate + path
    \\  cogbox l7 add allow internal.svc --insecure-upstream skip upstream verify
    \\  cogbox l7 add deny '*' --at 1
    \\
    \\If the instance is running, edits hot-reload the proxy via SIGHUP and
    \\passt via SIGUSR1 (no VM restart needed).
    \\
;

pub const PLUGIN =
    \\cogbox plugin - manage guest plugins for an instance
    \\
    \\Usage:
    \\  cogbox plugin [-n NAME] add FLAKE_URL [--as PLUGIN] [-y]
    \\  cogbox plugin [-n NAME] del PLUGIN [-y]
    \\  cogbox plugin [-n NAME] update [PLUGIN]
    \\  cogbox plugin [-n NAME] list
    \\
    \\Options:
    \\  -n, --name NAME       Instance name (default: "default")
    \\      --as PLUGIN       (add) plugin name override (default: derived from
    \\                        the #attr, the ?dir= basename, or the repo name)
    \\  -y, --yes             Skip confirmation prompts
    \\  -h, --help            Show this help and exit
    \\
    \\A plugin is a flake output `cogboxPlugins.<attr>` (its `module` reference
    \\plus host-side networkRules/l7Rules/inject): `URL#attr` selects it, bare URL
    \\means `default`. One flake can carry many plugins; enable any subset with
    \\repeated adds. FLAKE_URL is any nix flake reference: github:owner/repo,
    \\git+https://..., path:/abs/dir, with ?dir= supported. The module (which
    \\carries the kit via cogbox.*) is folded into the guest at the next start.
    \\
    \\Versioning is per FLAKE, not per plugin: the source is resolved and
    \\pinned at add time (rev + narHash recorded in config.json, inputs
    \\pre-fetched into the nix store); adding another module of an installed
    \\flake reuses its pin, and `update` re-resolves each URL once and moves
    \\all of its plugins together. Pin a specific rev nix-style in the URL
    \\itself (e.g. ?rev=...) to hold a flake back.
    \\
    \\A plugin may also declare firewall rules, tagged with the plugin's name
    \\so del/update remove or replace exactly those rules:
    \\  cogboxPlugins.<attr>.networkRules  L4 CIDR rules (.network.rules schema)
    \\  cogboxPlugins.<attr>.l7Rules       L7 vhost rules (.network.l7.rules
    \\                                    schema, incl. terminate/passthrough/
    \\                                    path/insecure_upstream)
    \\(flat cogboxPlugins.networkRules / .l7Rules for the default module), e.g.
    \\  cogboxPlugins.l7Rules = [ { allow = "api.internal"; terminate = true; } ];
    \\On add/update these are shown for confirmation and inserted AT THE TOP of
    \\their rule lists (first match wins, so plugin allows must precede the
    \\seeded RFC1918 denies). Rule changes hot-reload; module changes need
    \\'cogbox restart'.
    \\
    \\Adding a plugin evaluates and later builds third-party nix code -- only
    \\add flakes you trust.
    \\
    \\Examples:
    \\  cogbox plugin add github:myorg/myplugin?dir=flake
    \\  cogbox plugin add 'github:org/observability#loki' -n work
    \\  cogbox plugin add path:/home/me/myplugin --as dev -n work
    \\  cogbox plugin update
    \\  cogbox plugin del myplugin
    \\  cogbox plugin resolve github:org/observability#loki   # preview (JSON), installs nothing
    \\
;

pub const SECRET =
    \\cogbox secret - bind host-side credentials that plugins/harnesses inject
    \\
    \\Usage:
    \\  cogbox secret add NAME --from-file F | --from-stdin
    \\                        [--audience HOST] [--kind bearer|cookie] [-n INSTANCE]
    \\  cogbox secret ls [--json]
    \\  cogbox secret rm NAME [-n INSTANCE]
    \\  cogbox secret reload -n INSTANCE
    \\
    \\Options:
    \\  --from-file F     Read the secret value from file F (mode preserved 0600)
    \\  --from-stdin      Read the secret value from stdin
    \\  --audience HOST   The exact host this secret may be injected to. A secret
    \\                    is NOT injectable until its audience is set; the
    \\                    inject-conf renderer refuses to stamp a secret onto any
    \\                    host other than its bound audience, so a plugin cannot
    \\                    redirect a bound credential to an attacker host.
    \\  --kind K          Injection style hint: bearer (default) or cookie
    \\  -n INSTANCE       After the bind/remove, re-render that instance's inject
    \\                    conf and SIGHUP its proxy, so the change takes effect on a
    \\                    RUNNING VM without a restart. Omit to only write the store
    \\                    (the binding then applies at the instance's next start).
    \\  -h, --help        Show this help and exit
    \\
    \\A plugin REQUESTS a credential by symbolic name (cogboxPlugins.<attr>.inject =
    \\[{ host, style, secret }]); it can never name a file path or a value. You
    \\bind the real value here, host-side, and it stays out of the guest -- the
    \\guest carries only a stub (or no real credential) and the addon overwrites
    \\it with the real secret on the L7 terminate tier. Values are read from a
    \\file or stdin, never from argv (which would leak into the process table and
    \\shell history).
    \\
    \\The store lives at <config>/secrets/ (value 0600 + a <name>.meta sidecar with
    \\audience/kind/tier). `cogbox plugin add` prints a checklist of the secrets a
    \\plugin needs so you know what to bind.
    \\
    \\Examples:
    \\  cogbox secret add api-bearer --from-file ~/.secrets/api.token \
    \\        --audience api.example.com
    \\  printf '%s' "$TOKEN" | cogbox secret add api-token --from-stdin --audience api.internal
    \\  cogbox secret ls
    \\  cogbox secret ls --json   # name/kind/audience/bound, for a control plane
    \\  cogbox secret add api-bearer --from-stdin --audience api.example.com -n web
    \\                            # bind AND apply to running instance 'web'
    \\  cogbox secret reload -n web   # re-apply an already-bound secret to 'web'
    \\  cogbox secret rm api-bearer
    \\
;

pub fn forVerb(verb: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, verb, "start")) return START;
    if (std.mem.eql(u8, verb, "console")) return CONSOLE;
    if (std.mem.eql(u8, verb, "monitor")) return MONITOR;
    if (std.mem.eql(u8, verb, "stop")) return STOP;
    if (std.mem.eql(u8, verb, "delete")) return DELETE;
    if (std.mem.eql(u8, verb, "restart")) return RESTART;
    if (std.mem.eql(u8, verb, "status")) return STATUS;
    if (std.mem.eql(u8, verb, "list")) return LIST;
    if (std.mem.eql(u8, verb, "init")) return INIT;
    if (std.mem.eql(u8, verb, "ssh")) return SSH;
    if (std.mem.eql(u8, verb, "rules")) return RULES;
    if (std.mem.eql(u8, verb, "remap")) return REMAP;
    if (std.mem.eql(u8, verb, "l7")) return L7;
    if (std.mem.eql(u8, verb, "plugin")) return PLUGIN;
    if (std.mem.eql(u8, verb, "secret")) return SECRET;
    return null;
}

pub fn print(io: std.Io, body: []const u8) !void {
    try util.writeStdout(io, body);
}
