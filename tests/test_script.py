import shlex

SSH_OPTS = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=2"


def as_user(cmd):
    return "su - testuser -c " + shlex.quote(cmd)


def probe(name, ip):
    remote = f"timeout 3 bash -c 'exec 3<>/dev/tcp/{ip}/9000'"
    name_arg = f"--name {name} " if name else ""
    return as_user(f"cogbox ssh {name_arg}{shlex.quote(remote)}")


def boot_and_wait(unit, args, ssh_port):
    # `cogbox start --no-ssh` daemonizes the VM (passt + QEMU) itself and
    # returns once QEMU has come up, WITHOUT opening an interactive SSH session
    # (which would block this command forever). The auto-ssh default is covered
    # separately in Phase J. The daemon is setsid'd into its own session, so it
    # survives this command and is torn down later by `cogbox stop`. The `unit`
    # arg is kept for call-site compatibility but is now unused.
    _ = unit
    machine.succeed(as_user(f"cogbox start --no-ssh {args}".strip()))
    machine.wait_until_succeeds(
        as_user(f"ssh {SSH_OPTS} -p {ssh_port} root@127.0.0.1 true"),
        timeout=600,
    )


def stop_instance(unit, name=None):
    # `cogbox stop` SIGTERMs the daemon; its trap forwards to QEMU + passt
    # and the EXIT trap removes the runtime dir. This exercises the
    # stop-reliability path that the background-by-default model depends on.
    _ = unit
    name_arg = f"--name {name}" if name else ""
    machine.succeed(as_user(f"cogbox stop {name_arg}".strip()))
    runtime = "/run/user/1000/cogbox" + (("-" + name) if name else "")
    machine.wait_until_fails(f"test -e {runtime}/pid", timeout=30)


machine.wait_for_unit("multi-user.target")

# Pre-create testuser ssh keypair
machine.succeed(as_user('ssh-keygen -t ed25519 -N "" -f /home/testuser/.ssh/id_ed25519'))

# Set up fake outbound targets and a single TCP listener.
# Inner VM connects to 10.99.0.{1,2}:9000; passt issues the same connect
# on the outer VM, which routes locally to the listener bound on 0.0.0.0.
machine.succeed("ip addr add 10.99.0.1/32 dev lo")
machine.succeed("ip addr add 10.99.0.2/32 dev lo")
machine.succeed("systemd-run --unit=test-listener --collect nc -l -k -p 9000")
machine.wait_for_open_port(9000)

# Node-side helper for the L7 ECH regression tests (Phases K/L). Crafts a TLS
# ClientHello carrying a cleartext SNI plus, optionally, an ECH extension
# (0xfe0d) -- the GREASE ECH that Chrome/Chromium send on every handshake --
# and pushes it through the proxy's SOCKS5 front door exactly like the guest
# shim does. Usage: ech-hello.py <proxy_port> <dest_ip> <sni> <ech:0|1>.
# Prints "socks-ok" once the proxy accepts the SOCKS connection. We don't
# complete a real TLS handshake; the assertions read the proxy's decision off
# its log. (curl/openssl never send ECH, so this is the only way to exercise
# the ECH path in the VM.)
ech_hello_script = r'''
import socket, struct, sys
port = int(sys.argv[1]); dst = sys.argv[2]; sni = sys.argv[3].encode(); ech = sys.argv[4] == "1"
def u16(x): return struct.pack(">H", x)
sni_entry = b"\x00" + u16(len(sni)) + sni          # name_type host_name + name
sni_list = u16(len(sni_entry)) + sni_entry
exts = u16(0x0000) + u16(len(sni_list)) + sni_list  # server_name extension
if ech:
    exts += u16(0xfe0d) + u16(1) + b"\x00"          # stub ECH extension
body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"         # version + random + empty session_id
        + b"\x00\x02\x13\x01" + b"\x01\x00"          # one cipher suite + null compression
        + u16(len(exts)) + exts)
hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
rec = b"\x16\x03\x01" + u16(len(hs)) + hs
s = socket.create_connection(("127.0.0.1", port), timeout=8)
s.sendall(b"\x05\x01\x00")
assert s.recv(2) == b"\x05\x00", "socks greeting"
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(dst) + u16(443))
assert s.recv(16)[:2] == b"\x05\x00", "socks connect"
s.sendall(rec)
print("socks-ok")
s.close()
'''
machine.succeed("cat > /tmp/ech-hello.py << 'PY_EOF'\n" + ech_hello_script + "\nPY_EOF")

with subtest("Phase A: CLI / state without booting"):
    # A1: first-run init for the default instance, network=none.
    # A non-interactive stdin auto-selects all built-in harnesses, so
    # claude-code and opencode host paths are seeded. Codex is opt-in
    # (disabled by default via enableCodex in flake.nix), so it is not
    # built into the VM and its host path is not seeded.
    machine.succeed(as_user("cogbox init -y --network none"))
    machine.succeed("test -f /home/testuser/.config/cogbox/instances/default/config.json")
    machine.succeed("test -f /home/testuser/.config/cogbox/authorized_keys")
    machine.succeed("test -d /home/testuser/.local/share/cogbox/instances/default")
    # cogbox generates its own SSH identity (the default key for `cogbox ssh`),
    # owned by the user with 0600 perms, in the data-dir root (never mounted
    # into a VM). The ownership/mode checks must observe the file as the user,
    # not as root: `test -O` compares against the *effective* uid, so a bare
    # machine.succeed (root) would never confirm testuser ownership.
    machine.succeed("test -f /home/testuser/.local/share/cogbox/cogbox_ed25519")
    machine.succeed("test -f /home/testuser/.local/share/cogbox/cogbox_ed25519.pub")
    owner = machine.succeed(
        "stat -c %U /home/testuser/.local/share/cogbox/cogbox_ed25519"
    ).strip()
    assert owner == "testuser", f"cogbox key owned by {owner!r}, expected testuser"
    mode = machine.succeed(
        "stat -c %a /home/testuser/.local/share/cogbox/cogbox_ed25519"
    ).strip()
    assert mode == "600", f"cogbox key mode {mode!r}, expected 600"
    machine.succeed("test -f /home/testuser/.claude.json")
    machine.succeed("test -d /home/testuser/.claude")
    machine.succeed("test -d /home/testuser/.config/opencode")
    machine.succeed("test -d /home/testuser/.local/share/opencode")
    machine.succeed("test -d /home/testuser/.hermes")
    machine.succeed("test -d /home/testuser/.omp")
    machine.succeed("test -d /home/testuser/.dsh")
    # Codex and pi are opt-in and not built by default, so their host dirs
    # are not seeded.
    machine.fail("test -d /home/testuser/.codex")
    machine.fail("test -d /home/testuser/.pi")
    machine.succeed(
        "test -f /home/testuser/.local/share/cogbox/instances/default/.config/active-harnesses"
    )
    active = machine.succeed(
        "cat /home/testuser/.local/share/cogbox/instances/default/.config/active-harnesses"
    ).strip().splitlines()
    assert "claude-code" in active and "opencode" in active, active
    assert "hermes-agent" in active and "omp" in active, active
    assert "dsh" in active, active
    assert "codex" not in active, active
    assert "pi" not in active, active
    # Old top-level default config must NOT be created any more.
    machine.fail("test -e /home/testuser/.config/cogbox/config.json")
    net = machine.succeed(
        "jq -r .network /home/testuser/.config/cogbox/instances/default/config.json"
    ).strip()
    assert net == "none", f"expected network=none, got {net!r}"

    # A2: list shows the default instance
    out = machine.succeed(as_user("cogbox list"))
    assert "(default)" in out, out
    assert "ssh:2222" in out, out
    assert "net:none" in out, out

    # A3: named instance with rules mode -> auto-assigned ports
    machine.succeed(as_user("cogbox init -y --name work --network rules"))
    # Named instance data must be a sibling of the default's data dir, not
    # nested inside it. A default-instance boot 9p-shares its data dir into
    # the guest; if named instances live under it, they leak across.
    machine.succeed("test -d /home/testuser/.local/share/cogbox/instances/work")
    machine.fail("test -e /home/testuser/.local/share/cogbox/instances/default/instances")
    ssh_port = machine.succeed(
        "jq -r .sshPort /home/testuser/.config/cogbox/instances/work/config.json"
    ).strip()
    assert ssh_port == "2223", f"expected auto-assigned 2223, got {ssh_port!r}"
    net_kind = machine.succeed(
        "jq -r '.network | type' /home/testuser/.config/cogbox/instances/work/config.json"
    ).strip()
    assert net_kind == "object", f"expected rules object, got {net_kind!r}"

    # A4: list shows both
    out = machine.succeed(as_user("cogbox list"))
    assert "(default)" in out and "work" in out, out

    # A5: rules add / list / del on the work instance.
    # Use --at to land the new rules at known positions; otherwise they
    # append after the seeded bogon-deny ruleset and del 1 would remove
    # a seeded rule instead of the test rule. Use 8.8.8.8/32 instead of
    # 0.0.0.0/0 for the second rule so its substring check doesn't
    # collide with the seeded `allow 0.0.0.0/0`.
    machine.succeed(as_user("cogbox rules add allow 10.99.0.1/32 --at 1 --name work"))
    machine.succeed(as_user("cogbox rules add deny 8.8.8.8/32 --at 2 --name work"))
    out = machine.succeed(as_user("cogbox rules list --name work"))
    assert "10.99.0.1/32" in out and "8.8.8.8/32" in out, out
    machine.succeed(as_user("cogbox rules del 1 --name work"))
    out = machine.succeed(as_user("cogbox rules list --name work"))
    assert "10.99.0.1/32" not in out and "8.8.8.8/32" in out, out

    # A6: rules add fails on a non-rules instance (default is network=none)
    machine.fail(as_user("cogbox rules add allow 1.1.1.1/32"))

# Install host pubkey for inner-VM SSH (shared by the default and work instances)
machine.succeed(
    "cp /home/testuser/.ssh/id_ed25519.pub "
    "/home/testuser/.config/cogbox/authorized_keys"
)

with subtest("Phase B: --network none blocks all outbound"):
    boot_and_wait("cc-default", "", ssh_port=2222)
    out = machine.succeed(as_user("cogbox list"))
    assert "(running)" in out, out
    hostname = machine.succeed(as_user("cogbox ssh hostname")).strip()
    assert hostname == "cogbox-default", f"unexpected inner hostname {hostname!r}"
    # The cogbox key alone must authenticate: this proves its pubkey was unioned
    # into the guest authorized_keys (and that `cogbox ssh` would use it as the
    # default identity). IdentitiesOnly=yes offers ONLY the cogbox key, so this
    # does not piggyback on the testuser key copied in above.
    machine.succeed(as_user(
        f"ssh {SSH_OPTS} -o IdentitiesOnly=yes "
        "-i /home/testuser/.local/share/cogbox/cogbox_ed25519 "
        "-p 2222 root@127.0.0.1 true"
    ))
    machine.fail(probe(None, "10.99.0.1"))
    machine.fail(probe(None, "10.99.0.2"))

    # B2: the guest store is local-overlay, so GC reclaims only guest-built
    # paths. hello is realized on this (outer) machine and is NOT in the
    # default guest closure: it sits in the 9p lower unregistered, which a
    # plain local store would walk and white out.
    def guest(cmd):
        return as_user("cogbox ssh " + shlex.quote(cmd))
    print(machine.succeed(guest(
        "grep ' /nix/store ' /proc/self/mounts; cat /run/cogbox/nix-store.conf; "
        "cat /run/cogbox/nix-store.err 2>/dev/null; true"
    )))
    machine.succeed(guest("nix store info 2>&1 | grep -qx 'Store URL: local-overlay://'"))
    hello_dir = machine.succeed("dirname $(dirname $(readlink -f $(command -v hello)))").strip()
    machine.succeed(guest(f"test -d {hello_dir}/bin && ! nix-store --check-validity {hello_dir}"))
    garbage = machine.succeed(guest("echo gc-me > /tmp/gc-me && nix-store --add /tmp/gc-me")).strip()
    machine.succeed(guest(f"nix-store --check-validity {garbage}"))
    machine.succeed(guest("nix store gc"))
    machine.succeed(guest(f"test ! -e {garbage}"))
    machine.succeed(guest(f"test -x {hello_dir}/bin/hello"))
    machine.succeed(guest("test -z \"$(find /nix/.rw-store/store -maxdepth 1 -type c)\""))
    machine.succeed(guest("nix-store --check-validity $(readlink -f /run/current-system)"))

    # B3: once-markers. Once the boot settles, cogbox-boot-settled marks the
    # boot-only units this boot started without failing, and a later start of
    # a marked unit in the same boot is skipped by its condition. A unit that
    # is restarted on a running guest carries no marker.
    machine.wait_until_succeeds(
        guest("systemctl show -P SubState cogbox-boot-settled.service | grep -qx exited"),
        timeout=300,
    )
    print(machine.succeed(guest("journalctl -b -u cogbox-boot-settled.service --no-pager | tail -n 3; ls -A /run/cogbox/once")))
    for unit in ["cogbox-vm-sshd-prep", "harness-setup-dirs", "rw-root-.claude"]:
        machine.succeed(guest(f"test -f /run/cogbox/once/{unit}"))
    machine.succeed(guest("test ! -e /run/cogbox/once/cogbox-claude-stub"))
    machine.succeed(guest("systemctl start rw-root-.claude.service"))
    cond = machine.succeed(guest("systemctl show -P ConditionResult rw-root-.claude.service")).strip()
    assert cond == "no", f"a marked boot-only unit ran again after the boot settled (ConditionResult={cond!r})"
    stop_instance("cc-default")

with subtest("Phase C: --network full allows outbound"):
    # Reinit the default instance in full mode
    machine.succeed("rm -f /home/testuser/.config/cogbox/instances/default/config.json")
    machine.succeed(as_user("cogbox init -y --network full"))
    machine.succeed(
        "cp /home/testuser/.ssh/id_ed25519.pub "
        "/home/testuser/.config/cogbox/authorized_keys"
    )
    boot_and_wait("cc-default", "", ssh_port=2222)
    machine.succeed(probe(None, "10.99.0.1"))
    machine.succeed(probe(None, "10.99.0.2"))
    stop_instance("cc-default")

with subtest("Phase D: --network rules with dynamic reload"):
    # work instance carries the seeded bogon-deny ruleset; 10.99.0.0/8
    # falls inside `deny 10.0.0.0/8`, so we need an explicit allow at the
    # front for 10.99.0.1/32 to be reachable.
    rw_host_dir = "/home/testuser/cogbox-pass-rw"
    ro_host_dir = "/home/testuser/cogbox pass,ro"
    rw_payload = rw_host_dir + "/nested/payload"
    ro_payload = ro_host_dir + "/nested/payload"
    machine.succeed(as_user(
        f"mkdir -p {shlex.quote(rw_host_dir + '/nested')} "
        f"{shlex.quote(ro_host_dir + '/nested')} && "
        f"printf %s {shlex.quote('rw-payload-exact-v1')} > {shlex.quote(rw_payload)} && "
        f"printf %s {shlex.quote('ro-payload-exact-v1')} > {shlex.quote(ro_payload)}"
    ))
    rw_host_hash = machine.succeed(
        f"sha256sum -- {shlex.quote(rw_payload)}"
    ).split()[0]
    ro_host_hash = machine.succeed(
        f"sha256sum -- {shlex.quote(ro_payload)}"
    ).split()[0]
    machine.succeed(as_user("cogbox rules add allow 10.99.0.1/32 --at 1 --name work"))
    boot_and_wait(
        "cc-work",
        f"--name work --add-dir ./cogbox-pass-rw --add-dir-ro {shlex.quote(ro_host_dir)}",
        ssh_port=2223,
    )

    # Both launch-only grants are mounted at their canonical host paths. The
    # source containing a comma and space proves caller bytes never enter the
    # QEMU argument grammar.
    for guest_path in (rw_host_dir, ro_host_dir):
        quoted = shlex.quote(guest_path)
        machine.succeed(as_user(
            "cogbox ssh --name work " + shlex.quote(
                f"mountpoint -q {quoted} && "
                f'test "$(findmnt -n -o FSTYPE --target {quoted})" = 9p'
            )
        ))
    rw_guest_hash = machine.succeed(as_user(
        "cogbox ssh --name work " + shlex.quote(
            f"sha256sum -- {shlex.quote(rw_payload)}"
        )
    )).split()[0]
    ro_guest_hash = machine.succeed(as_user(
        "cogbox ssh --name work " + shlex.quote(
            f"sha256sum -- {shlex.quote(ro_payload)}"
        )
    )).split()[0]
    assert rw_guest_hash == rw_host_hash, (rw_guest_hash, rw_host_hash)
    assert ro_guest_hash == ro_host_hash, (ro_guest_hash, ro_host_hash)

    # Initial policy: .1 allowed, .2 denied
    machine.succeed(probe("work", "10.99.0.1"))
    machine.fail(probe("work", "10.99.0.2"))

    # Dynamic add: insert allow 10.99.0.2/32 BEFORE the catch-all deny
    out = machine.succeed(as_user("cogbox rules add allow 10.99.0.2/32 --at 2 --name work"))
    assert "Rules reloaded" in out, out
    machine.succeed(probe("work", "10.99.0.2"))

    # Dynamic delete: drop the .1 allow at position 1
    out = machine.succeed(as_user("cogbox rules del 1 --name work"))
    assert "Rules reloaded" in out, out
    machine.fail(probe("work", "10.99.0.1"))
    machine.succeed(probe("work", "10.99.0.2"))

    guest_write = "guest-write-through-exact-v1"
    guest_write_path = rw_host_dir + "/nested/from-guest"
    machine.succeed(as_user(
        "cogbox ssh --name work " + shlex.quote(
            f"printf %s {shlex.quote(guest_write)} > {shlex.quote(guest_write_path)}"
        )
    ))
    expected_write_hash = machine.succeed(
        f"printf %s {shlex.quote(guest_write)} | sha256sum"
    ).split()[0]
    actual_write_hash = machine.succeed(
        f"sha256sum -- {shlex.quote(guest_write_path)}"
    ).split()[0]
    assert actual_write_hash == expected_write_hash, (actual_write_hash, expected_write_hash)

    # Guest `ro` is not the security boundary: even after guest root attempts a
    # rw remount, QEMU's readonly=true export must still reject the write.
    machine.execute(as_user(
        "cogbox ssh --name work " + shlex.quote(
            f"mount -o remount,rw {shlex.quote(ro_host_dir)}"
        )
    ))
    machine.fail(as_user(
        "cogbox ssh --name work " + shlex.quote(
            f"printf blocked > {shlex.quote(ro_host_dir + '/nested/from-guest')}"
        )
    ))
    ro_host_hash_after = machine.succeed(
        f"sha256sum -- {shlex.quote(ro_payload)}"
    ).split()[0]
    assert ro_host_hash_after == ro_host_hash, (ro_host_hash_after, ro_host_hash)

    stop_instance("cc-work", name="work")
    machine.fail("test -e /run/user/1000/cogbox-work/additional-dirs")
    machine.fail("test -e /run/user/1000/cogbox-work/additional-dir-args")
    machine.fail("test -e /run/user/1000/cogbox-work/system-additional-dirs")

with subtest("Phase E: per-instance flake adds package + nix DB registers it"):
    flake_path = "/home/testuser/.config/cogbox/instances/default/flake/flake.nix"

    # Earlier phases left a scaffolded no-op flake.nix; confirm and rewrite
    # to a flake that adds pkgs.hello via both systemPackages and
    # extraDependencies. No `inputs.nixpkgs` so `pkgs` flows in from the
    # surrounding NixOS evaluation (cogbox's nixpkgs).
    machine.succeed(f"test -f {flake_path}")
    machine.succeed(as_user("""cat > """ + flake_path + """ <<'NIX_EOF'
{
    description = "test-ext-hello";
    outputs = { self }: {
        nixosModules.default = { pkgs, ... }: {
            environment.systemPackages = [ pkgs.hello ];
            system.extraDependencies = [ pkgs.hello ];
        };
    };
}
NIX_EOF"""))

    # Boot default (still in --network full from Phase C). The wrapper
    # detects the edited flake.nix, re-execs via nix run with the override,
    # rebuilds the microvm runner with hello in the closure.
    boot_and_wait(
        "cc-default",
        f"--add-dir-ro {shlex.quote(ro_host_dir)}",
        ssh_port=2222,
    )
    # This start crosses the edited-flake nix re-exec and hidden `__launch`
    # parser. The grant must retain its mode and payload through both hops.
    machine.succeed(as_user(
        "cogbox ssh " + shlex.quote(
            f"mountpoint -q {shlex.quote(ro_host_dir)} && "
            f"test \"$(sha256sum -- {shlex.quote(ro_payload)} | cut -d' ' -f1)\" "
            f"= {shlex.quote(ro_host_hash)}"
        )
    ))
    hello_path = machine.succeed(
        as_user("cogbox ssh 'readlink -f $(command -v hello)'")
    ).strip()
    assert hello_path.startswith("/nix/store/") and "hello-" in hello_path, hello_path
    # nix-store --check-validity succeeds only if the path is in the guest's
    # /nix/var/nix/db -- proving it's a registered store object, not just
    # a file dropped in via the 9p ro-store share.
    machine.succeed(
        as_user(f"cogbox ssh 'nix-store --check-validity {hello_path}'")
    )

    # --- Brain materialization: the base oneshots run for EVERY instance, even
    # one with no plugins. ~/work (the standardized workdir) is a symlink into
    # the persisted share, .cogbox/brain is the RO store tree, and the
    # cogbox-authored capability index is always present as a skill.
    work_link = machine.succeed(
        as_user("cogbox ssh 'readlink /root/work'")
    ).strip()
    assert work_link == "/var/lib/cogbox/work", work_link
    machine.succeed(as_user("cogbox ssh 'test -L /var/lib/cogbox/work/.cogbox/brain'"))
    machine.succeed(as_user(
        "cogbox ssh 'test -f /var/lib/cogbox/work/.claude/skills/cogbox-plugins/SKILL.md'"
    ))
    # Frontmatter must start at column 0 or the harness ignores the skill.
    machine.succeed(as_user(
        "cogbox ssh 'sed -n 1p /var/lib/cogbox/work/.claude/skills/cogbox-plugins/SKILL.md | grep -qx -- ---'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'test -f /var/lib/cogbox/work/.omp/skills/cogbox-plugins/SKILL.md'"
    ))
    # Hermes's skills land inside its home overlay upper. With both codex
    # and pi disabled, their shared .agents/skills tree is omitted. A
    # plugin-less brain has no rules, so no AGENTS.md digest is linked.
    machine.succeed(as_user(
        "cogbox ssh 'test ! -e /var/lib/cogbox/work/.agents/skills/cogbox-plugins/SKILL.md'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'test -f /root/.hermes/skills/cogbox-plugins/SKILL.md'"
    ))
    machine.succeed(as_user("cogbox ssh 'test ! -e /root/work/AGENTS.md'"))
    # Claude workspace trust is pre-accepted for the new workdir.
    machine.succeed(as_user(
        "cogbox ssh 'grep -q /var/lib/cogbox/work /root/.claude.json'"
    ))
    stop_instance("cc-default")

    # Revert to the byte-exact scaffold so the next boot skips re-exec
    # again (the wrapper compares the on-disk flake.nix to its built-in
    # scaffold and skips the re-eval when they match).
    machine.succeed(f"rm {flake_path}")
    # Re-running init repopulates the scaffold without prompting
    # since everything else exists.
    machine.succeed(as_user("cogbox init -y --network full"))
    boot_and_wait("cc-default", "", ssh_port=2222)
    machine.fail(
        as_user("cogbox ssh 'command -v hello'")
    )
    stop_instance("cc-default")

with subtest("Phase Q: plugin verb folds a flake into the guest + tagged rules"):
    # Fixture: ONE flake exposing TWO plugins under the cogboxPlugins.<attr>
    # contract (registration = module ref + host-side rules). The composed
    # runner drv must equal the pre-built cogbox-x86_64-test-plugin fixture
    # (offline cache hit), whose userExt mirrors exactly the imported modules:
    # hello module + etc marker module + scaffold no-op, in add order (the
    # `.module or {}` composition wrapper imports the same module values).
    plug_flake = "/home/testuser/cogbox-test-plugin/flake.nix"
    machine.succeed(as_user("mkdir -p /home/testuser/cogbox-test-plugin"))
    # An executable file: the NAR records the exec bit, so a materialized copy
    # that dropped it never hashed to the recorded narHash and the composition
    # re-pin refused the plugin forever (asserted in Q5).
    machine.succeed(as_user(
        "mkdir -p /home/testuser/cogbox-test-plugin/bin && "
        "printf '#!/bin/sh\\necho hook\\n' > /home/testuser/cogbox-test-plugin/bin/hook && "
        "chmod 0755 /home/testuser/cogbox-test-plugin/bin/hook"
    ))
    machine.succeed(as_user("""cat > """ + plug_flake + """ <<'NIX_EOF'
{
    description = "cogbox test plugin";
    outputs = { self }: {
        nixosModules.default = { pkgs, ... }: {
            environment.systemPackages = [ pkgs.hello ];
            system.extraDependencies = [ pkgs.hello ];
        };
        nixosModules.extra = { ... }: {
            environment.etc."cogbox-test-extra".text = "extra\n";
        };
        cogboxPlugins.default = {
            module = self.nixosModules.default;
            networkRules = [
                { allow = "10.99.0.1/32"; comment = "test plugin allow"; }
            ];
            l7Rules = [
                { allow = "plugin-l7.test"; terminate = true; comment = "l7 vhost allow"; }
            ];
        };
        cogboxPlugins.extra = {
            module = self.nixosModules.extra;
            networkRules = [
                { allow = "10.99.0.2/32"; comment = "extra allow"; }
            ];
        };
    };
}
NIX_EOF"""))

    # Q1: dedicated rules-mode instance; ports auto-assign past work's 2223.
    machine.succeed(as_user("cogbox init -y --name plug --network rules"))
    plug_cfg = "/home/testuser/.config/cogbox/instances/plug/config.json"
    plug_ssh = machine.succeed(f"jq -r .sshPort {plug_cfg}").strip()

    # Q2: add. The backdoor shell's stdin IS a tty (serial console), so the
    # rule-merge prompt would block; -y skips it (and exercises the flag).
    # The derived name is the path basename: cogbox-test-plugin.
    out = machine.succeed(as_user(
        "cogbox plugin add path:/home/testuser/cogbox-test-plugin -y --name plug"
    ))
    assert "10.99.0.1/32" in out and "added" in out, out
    assert "l7 allow plugin-l7.test [terminate]" in out, out
    n = machine.succeed(f"jq -r '.plugins | length' {plug_cfg}").strip()
    assert n == "1", f"expected 1 plugin, got {n!r}"
    nar = machine.succeed(f"jq -r '.plugins[0].narHash' {plug_cfg}").strip()
    assert nar.startswith("sha256-"), nar
    tag = machine.succeed(f"jq -r '.network.rules[0].plugin' {plug_cfg}").strip()
    assert tag == "cogbox-test-plugin", f"rule not tagged at head: {tag!r}"
    # The plugin's L7 vhost rule lands tagged in .network.l7.rules too.
    tag = machine.succeed(f"jq -r '.network.l7.rules[0].plugin' {plug_cfg}").strip()
    assert tag == "cogbox-test-plugin", f"l7 rule not tagged at head: {tag!r}"
    term = machine.succeed(f"jq -r '.network.l7.rules[0].terminate' {plug_cfg}").strip()
    assert term == "true", f"l7 terminate flag lost: {term!r}"
    rules_out = machine.succeed(as_user("cogbox rules list --name plug"))
    assert rules_out.splitlines()[0].startswith("1: allow 10.99.0.1/32"), rules_out
    comp = "/home/testuser/.config/cogbox/instances/plug/plugins-flake/flake.nix"
    comp_text = machine.succeed(f"cat {comp}")
    assert "DO NOT EDIT" in comp_text, comp_text
    # The materialized source is referenced as a path: input (offline at launch);
    # narHash lives in config.json (.plugins[].narHash, asserted above), not here.
    assert '"p-cogbox-test-plugin".url' in comp_text, comp_text
    assert "plugin-sources/cogbox-test-plugin" in comp_text, comp_text
    assert 'cogboxPlugins."default".module' in comp_text, comp_text

    # Q2b: enable a SECOND module of the same flake via #fragment. The pin
    # must be reused (flake-level versioning), the name derives from the
    # attr, and its per-attr rules land at the head tagged with ITS name.
    out = machine.succeed(as_user(
        "cogbox plugin add 'path:/home/testuser/cogbox-test-plugin#extra' -y --name plug"
    ))
    assert "Reusing pin" in out and "10.99.0.2/32" in out, out
    n = machine.succeed(f"jq -r '.plugins | length' {plug_cfg}").strip()
    assert n == "2", f"expected 2 plugins, got {n!r}"
    attr = machine.succeed(f"jq -r '.plugins[1].attr' {plug_cfg}").strip()
    assert attr == "extra", f"attr not recorded: {attr!r}"
    nar_extra = machine.succeed(f"jq -r '.plugins[1].narHash' {plug_cfg}").strip()
    assert nar_extra == nar, f"siblings diverged: {nar!r} vs {nar_extra!r}"
    tag = machine.succeed(f"jq -r '.network.rules[0].plugin' {plug_cfg}").strip()
    assert tag == "extra", f"extra's rule not tagged at head: {tag!r}"
    comp_text = machine.succeed(f"cat {comp}")
    assert 'cogboxPlugins."default".module' in comp_text, comp_text
    assert 'inputs."p-extra".cogboxPlugins."extra".module' in comp_text, comp_text

    # Q3: list shows both; duplicate add, unknown del, and a fragment that
    # names no module all fail with exit 65.
    out = machine.succeed(as_user("cogbox plugin list --name plug"))
    assert "cogbox-test-plugin" in out and "#extra" in out, out
    machine.fail(as_user(
        "cogbox plugin add path:/home/testuser/cogbox-test-plugin -y --name plug"
    ))
    machine.fail(as_user("cogbox plugin del nosuch --name plug"))
    machine.fail(as_user(
        "cogbox plugin add 'path:/home/testuser/cogbox-test-plugin#nonexistent' -y --name plug"
    ))

    # Q3b: the add-time unit-name lint.
    #
    # Plugins live in independently-owned repos and get installed in arbitrary
    # combinations, so two of them shipping skills/overview is normal. Until
    # the build resolved that itself, the composed guest would not EVALUATE:
    # `cogbox init` exited non-zero, the supervisor restart-looped, and the one
    # line of Nix error that explained it never left the VM. `plugin add` and
    # `plugin update` now report it at install time -- advisorily for what the
    # build qualifies, fatally for what it still refuses, so a refused shape
    # never reaches a boot through either mutation. (The lint reads the
    # conventional contents/ root and never evaluates the module, so a plugin
    # that points cogbox.contents elsewhere is still the build's problem alone.)
    #
    # A DEDICATED instance, never booted: adding these to `plug` would change
    # its composition and cost Q4 its cache hit against the pre-built fixture.
    def mk_lint_plugin(pname, units):
        """A minimal plugin flake at /home/testuser/<pname> whose contents/
        ships `units` -- (kind_dir, unit_name) pairs. The module is empty on
        purpose: the lint reads contents/ off the MATERIALIZED SOURCE and never
        evaluates the module, which is the property under test."""
        d = f"/home/testuser/{pname}"
        machine.succeed(as_user(f"mkdir -p {d}"))
        machine.succeed(as_user("cat > " + d + """/flake.nix <<'NIX_EOF'
{
    description = "cogbox lint fixture";
    outputs = { self }: {
        nixosModules.default = { ... }: { };
        cogboxPlugins.default = { module = self.nixosModules.default; };
    };
}
NIX_EOF"""))
        for kind, unit in units:
            if kind == "skills":
                leaf = f"{d}/contents/skills/{unit}/SKILL.md"
                machine.succeed(as_user(f"mkdir -p {d}/contents/skills/{unit}"))
            else:
                leaf = f"{d}/contents/{kind}/{unit}.md"
                machine.succeed(as_user(f"mkdir -p {d}/contents/{kind}"))
            machine.succeed(as_user(
                f"printf -- '---\\nname: {unit}\\n---\\n' > {leaf}"
            ))
        return d

    machine.succeed(as_user("cogbox init -y --name collide --network rules"))
    collide_cfg = "/home/testuser/.config/cogbox/instances/collide/config.json"
    mk_lint_plugin("collide-a", [("skills", "overview"), ("agents", "triage")])
    mk_lint_plugin("collide-b", [("skills", "overview"), ("agents", "triage")])
    # Reserved: cogbox links its own generated capability index in at
    # claude/skills/cogbox-plugins, so a plugin shipping that name has nowhere
    # to go. It used to surface as a bare `ln: File exists` naming nobody.
    mk_lint_plugin("collide-reserved", [("skills", "cogbox-plugins")])
    # Taken: once collide-b's `overview` is qualified to `collide-b-overview`,
    # a plugin shipping that literal name claims it twice. Last-wins there
    # would reintroduce exactly the failure mode qualification removes.
    mk_lint_plugin("collide-taken", [("skills", "collide-b-overview")])

    machine.succeed(as_user("cogbox plugin add path:/home/testuser/collide-a -y --name collide"))
    out = machine.succeed(as_user("cogbox plugin add path:/home/testuser/collide-b -y --name collide"))
    assert "Name collisions with installed plugins" in out, out
    assert "~ skill 'overview' also provided by 'collide-a'" in out, out
    assert "-> collide-a-overview, collide-b-overview" in out, out
    assert "~ agent 'triage' also provided by 'collide-a'" in out, out
    assert "-> collide-a-triage, collide-b-triage" in out, out
    # ADVISORY, not a refusal: the build resolves this, so both install.
    n = machine.succeed(f"jq -r '.plugins | length' {collide_cfg}").strip()
    assert n == "2", f"the advisory blocked the add: {n!r}"

    # The residue, refused with the build's own wording so the CLI and the
    # build can never disagree about what installs.
    out = machine.fail(as_user(
        "cogbox plugin add path:/home/testuser/collide-reserved -y --name collide 2>&1"
    ))
    assert "cogbox plugin: error:" in out and "cogbox-plugins" in out, out
    assert "reserves for its own generated capability index" in out, out
    out = machine.fail(as_user(
        "cogbox plugin add path:/home/testuser/collide-taken -y --name collide 2>&1"
    ))
    assert "skill name 'collide-b-overview' is claimed twice" in out, out
    # Refused AND clean: neither is in config.json, and neither left an orphan
    # source tree behind for the next reader to puzzle over.
    n = machine.succeed(f"jq -r '.plugins | length' {collide_cfg}").strip()
    assert n == "2", f"a refused add still mutated config.json: {n!r}"
    machine.fail(as_user(
        "test -e /home/testuser/.config/cogbox/instances/collide"
        "/plugin-sources/collide-reserved"
    ))

    # THE UPDATE PATH runs the same lint, and that is not symmetry for its own
    # sake: an update installs a version nobody has reviewed, so it is the one
    # mutation that can introduce an unresolvable name into a set that was fine
    # yesterday. It is linted from the STORE before anything on the instance is
    # replaced, so a refusal leaves the old pin, the old source and the old
    # composition exactly as they were -- the box keeps booting.
    def pin_of(pname):
        return machine.succeed(
            "jq -r '.plugins[] | select(.name==\"" + pname + "\") | .narHash' " + collide_cfg
        ).strip()

    old_pin = pin_of("collide-a")
    machine.succeed(as_user(
        "mkdir -p /home/testuser/collide-a/contents/skills/cogbox-plugins"
    ))
    machine.succeed(as_user(
        "printf -- '---\\nname: cogbox-plugins\\n---\\n' > "
        "/home/testuser/collide-a/contents/skills/cogbox-plugins/SKILL.md"
    ))
    out = machine.fail(as_user("cogbox plugin update collide-a --name collide 2>&1"))
    assert "reserves for its own generated capability index" in out, out
    assert pin_of("collide-a") == old_pin, (
        f"a refused update still re-pinned collide-a: {old_pin!r} -> {pin_of('collide-a')!r}"
    )
    # ...and the installed source is still the OLD version, so the composition's
    # path: input keeps resolving to something that builds.
    machine.fail(as_user(
        "test -e /home/testuser/.config/cogbox/instances/collide"
        "/plugin-sources/collide-a/contents/skills/cogbox-plugins"
    ))

    # THE MULTI-PLUGIN SHAPE, where the refusal lands MID-LOOP. `update` with no
    # argument walks every installed plugin: collide-a resolves and has its
    # source replaced, then collide-b's new version trips the lint. Exiting
    # there would strand collide-a -- its new tree on disk, but config.json (and
    # the composition lock, both written after the loop) still naming the old
    # rev. nix honours a stale lock rather than erroring, so the guest would go
    # on building the old plugin until some later add/del/update silently jumped
    # it to a version `plugin list` never recorded, all while the operator was
    # told the update was refused. The loop has to finish instead: what updated
    # is saved, what refused is left exactly as it was, and the run still exits
    # non-zero.
    machine.succeed(as_user(
        "rm -rf /home/testuser/collide-a/contents/skills/cogbox-plugins"
    ))
    machine.succeed(as_user(
        "mkdir -p /home/testuser/collide-a/contents/skills/alpha"
    ))
    machine.succeed(as_user(
        "printf -- '---\\nname: alpha\\n---\\n' > "
        "/home/testuser/collide-a/contents/skills/alpha/SKILL.md"
    ))
    machine.succeed(as_user(
        "mkdir -p /home/testuser/collide-b/contents/skills/cogbox-plugins"
    ))
    machine.succeed(as_user(
        "printf -- '---\\nname: cogbox-plugins\\n---\\n' > "
        "/home/testuser/collide-b/contents/skills/cogbox-plugins/SKILL.md"
    ))
    a_pin, b_pin = pin_of("collide-a"), pin_of("collide-b")
    out = machine.fail(as_user("cogbox plugin update --name collide 2>&1"))
    assert "reserves for its own generated capability index" in out, out
    assert "collide-b: not updated" in out, out
    assert "collide-a: updated to" in out, out
    assert pin_of("collide-a") != a_pin, (
        f"collide-a's new source is installed but config.json still pins {a_pin!r}"
    )
    assert pin_of("collide-b") == b_pin, f"a refused update re-pinned collide-b: {out}"
    # The saved pin and the tree on disk agree, on both sides.
    machine.succeed(as_user(
        "test -e /home/testuser/.config/cogbox/instances/collide"
        "/plugin-sources/collide-a/contents/skills/alpha"
    ))
    machine.fail(as_user(
        "test -e /home/testuser/.config/cogbox/instances/collide"
        "/plugin-sources/collide-b/contents/skills/cogbox-plugins"
    ))

    # Q4: boot. The wrapper sees .plugins non-empty, re-execs with the
    # composition flake; the rebuilt runner resolves as a cache hit against
    # the pre-built test-plugin fixture. Both modules AND both merged rules
    # must be live: hello on PATH, the extra module's /etc marker present,
    # 10.99.0.1 and 10.99.0.2 allowed (plugin rules precede the seeded
    # 10.0.0.0/8 deny).
    boot_and_wait("cc-plug", "--name plug", ssh_port=plug_ssh)
    hello_path = machine.succeed(
        as_user("cogbox ssh --name plug 'readlink -f $(command -v hello)'")
    ).strip()
    assert hello_path.startswith("/nix/store/") and "hello-" in hello_path, hello_path
    machine.succeed(
        as_user(f"cogbox ssh --name plug 'nix-store --check-validity {hello_path}'")
    )
    machine.succeed(as_user("cogbox ssh --name plug 'test -f /etc/cogbox-test-extra'"))
    machine.succeed(probe("plug", "10.99.0.1"))
    machine.succeed(probe("plug", "10.99.0.2"))

    # Q4b: disable a subset while RUNNING: del of the extra plugin drops
    # exactly its tagged rule (hot-reloaded -> .2 unreachable now), while
    # its module stays until restart (/etc marker survives).
    machine.succeed(as_user("cogbox plugin del extra -y --name plug"))
    machine.fail(probe("plug", "10.99.0.2"))
    machine.succeed(probe("plug", "10.99.0.1"))
    machine.succeed(as_user("cogbox ssh --name plug 'test -f /etc/cogbox-test-extra'"))

    # Q5: update. No change -> up to date. Then extend the fixture's rules
    # (modules untouched, so the runner drv stays the cached one) and update
    # again: the lock re-pins and the replaced tagged rules hot-reload into
    # the RUNNING instance.
    out = machine.succeed(as_user("cogbox plugin update --name plug"))
    assert "up to date" in out, out
    machine.succeed(as_user("""cat > """ + plug_flake + """ <<'NIX_EOF'
{
    description = "cogbox test plugin";
    outputs = { self }: {
        nixosModules.default = { pkgs, ... }: {
            environment.systemPackages = [ pkgs.hello ];
            system.extraDependencies = [ pkgs.hello ];
        };
        nixosModules.extra = { ... }: {
            environment.etc."cogbox-test-extra".text = "extra\n";
        };
        cogboxPlugins.default = {
            module = self.nixosModules.default;
            networkRules = [
                { allow = "10.99.0.1/32"; comment = "test plugin allow"; }
                { allow = "10.99.0.2/32"; comment = "second allow"; }
            ];
            l7Rules = [
                { allow = "plugin-l7.test"; terminate = true; comment = "l7 vhost allow"; }
            ];
        };
        cogboxPlugins.extra = {
            module = self.nixosModules.extra;
            networkRules = [
                { allow = "10.99.0.2/32"; comment = "extra allow"; }
            ];
        };
    };
}
NIX_EOF"""))
    # Keep the pre-update composition lock: the heal case below restores it.
    plug_icd = "/home/testuser/.config/cogbox/instances/plug"
    plug_lock = f"{plug_icd}/plugins-flake/flake.lock"
    machine.succeed(f"cp {plug_lock} /tmp/plug-stale-flake.lock")
    out = machine.succeed(as_user("cogbox plugin update --name plug"))
    assert "updated to" in out and "10.99.0.2/32" in out, out
    nar2 = machine.succeed(f"jq -r '.plugins[0].narHash' {plug_cfg}").strip()
    assert nar2 != nar and nar2.startswith("sha256-"), (nar, nar2)

    # REGRESSION: the composition lock must pin the NEW materialized source.
    # Plain `nix flake lock` kept a path: input's old narHash after its content
    # changed, so a content-changing update was a silent false success (the
    # guest kept the old plugin content on a warm store; a cold store failed
    # with a narHash mismatch). locked == on-disk == config.json's pin.
    def plug_lock_vs_disk():
        locked = machine.succeed(
            "jq -r '.nodes[.nodes.root.inputs[\"p-cogbox-test-plugin\"]].locked.narHash' "
            + plug_lock
        ).strip()
        disk = machine.succeed(as_user(
            "nix --extra-experimental-features 'nix-command flakes' "
            f"hash path {plug_icd}/plugin-sources/cogbox-test-plugin"
        )).strip()
        return locked, disk

    locked, disk = plug_lock_vs_disk()
    assert locked == disk == nar2, (locked, disk, nar2)
    plug_src = f"{plug_icd}/plugin-sources/cogbox-test-plugin"
    machine.succeed(as_user(f"test -x {plug_src}/bin/hook"))

    # Heal: a lock left stale by an older cogbox is re-pinned by a no-op update.
    machine.succeed(f"cp /tmp/plug-stale-flake.lock {plug_lock} && chown testuser {plug_lock}")
    locked, disk = plug_lock_vs_disk()
    assert locked != disk, ("stale lock fixture did not take", locked, disk)
    out = machine.succeed(as_user("cogbox plugin update --name plug 2>&1"))
    assert "up to date" in out, out
    assert "re-pinned composition lock" in out, out
    locked, disk = plug_lock_vs_disk()
    assert locked == disk == nar2, (locked, disk, nar2)

    # Heal a tree that is not the pin: an older cogbox stripped exec bits while
    # materializing, and a killed op can leave stray files. With the lock stale
    # too, a no-op update re-copies the tree from the recorded store path and
    # then re-pins it.
    machine.succeed(f"cp /tmp/plug-stale-flake.lock {plug_lock} && chown testuser {plug_lock}")
    machine.succeed(as_user(f"chmod a-x {plug_src}/bin/hook && touch {plug_src}/partial-copy"))
    out = machine.succeed(as_user("cogbox plugin update --name plug 2>&1"))
    assert "up to date" in out and "re-materialized its plugin source" in out, out
    assert "re-pinned composition lock" in out, out
    machine.succeed(as_user(f"test -x {plug_src}/bin/hook && test ! -e {plug_src}/partial-copy"))
    locked, disk = plug_lock_vs_disk()
    assert locked == disk == nar2, (locked, disk, nar2)

    # Gate: the re-pin is never blind. A stale lock is NOT re-pinned onto a
    # plugin-sources tree config.json never recorded (a half-finished copy, an
    # update killed between materialize and config.save); the old, coherent pin
    # is kept and the plugin is named, by every op that is not an update of it
    # (here: add + del of a sibling module). Once the tree matches the record
    # again, the next op heals it.
    def plug_locked_pin():
        return machine.succeed(
            "jq -r '.nodes[.nodes.root.inputs[\"p-cogbox-test-plugin\"]].locked.narHash' "
            + plug_lock
        ).strip()

    stale_pin = machine.succeed(
        "jq -r '.nodes[.nodes.root.inputs[\"p-cogbox-test-plugin\"]].locked.narHash' "
        "/tmp/plug-stale-flake.lock"
    ).strip()
    machine.succeed(f"cp /tmp/plug-stale-flake.lock {plug_lock} && chown testuser {plug_lock}")
    machine.succeed(as_user(f"touch {plug_src}/partial-copy"))
    out = machine.succeed(as_user(
        "cogbox plugin add 'path:/home/testuser/cogbox-test-plugin#extra' -y --name plug 2>&1"
    ))
    assert "does not match the pin config.json records" in out, out
    assert "re-pinned composition lock" not in out, out
    assert plug_locked_pin() == stale_pin, (plug_locked_pin(), stale_pin)
    out = machine.succeed(as_user("cogbox plugin del extra -y --name plug 2>&1"))
    assert "does not match the pin config.json records" in out, out
    assert plug_locked_pin() == stale_pin, (plug_locked_pin(), stale_pin)
    machine.succeed(as_user(f"rm {plug_src}/partial-copy"))
    out = machine.succeed(as_user("cogbox plugin update --name plug 2>&1"))
    assert "re-pinned composition lock" in out, out
    locked, disk = plug_lock_vs_disk()
    assert locked == disk == nar2, (locked, disk, nar2)
    n = machine.succeed(
        f"jq -r '[.network.rules[] | select(.plugin == \"cogbox-test-plugin\")] | length' {plug_cfg}"
    ).strip()
    assert n == "2", f"expected 2 tagged rules after update, got {n!r}"
    machine.succeed(probe("plug", "10.99.0.2"))
    stop_instance("cc-plug", name="plug")

    # Q6: del removes the entry, exactly the tagged rules, and the
    # composition flake; the next boot falls back to the baked-in runner
    # (no re-exec), so hello is gone.
    machine.succeed(as_user("cogbox plugin del cogbox-test-plugin -y --name plug"))
    n = machine.succeed(f"jq -r '.plugins | length' {plug_cfg}").strip()
    assert n == "0", f"expected 0 plugins after del, got {n!r}"
    n = machine.succeed(
        f"jq -r '[.network.rules[] | select(.plugin != null)] | length' {plug_cfg}"
    ).strip()
    assert n == "0", f"tagged rules survived del: {n!r}"
    n = machine.succeed(f"jq -r '.network.l7.rules | length' {plug_cfg}").strip()
    assert n == "0", f"tagged l7 rules survived del: {n!r}"
    machine.fail(f"test -e {comp}")
    boot_and_wait("cc-plug", "--name plug", ssh_port=plug_ssh)
    machine.fail(as_user("cogbox ssh --name plug 'command -v hello'"))
    machine.fail(as_user("cogbox ssh --name plug 'test -f /etc/cogbox-test-extra'"))
    stop_instance("cc-plug", name="plug")

    # Q7: git-scheme plugin URLs. REGRESSION: parseMetadata used to append
    # ?narHash=... to the locked URL, but nix's git fetcher passes unknown
    # query params through to the remote, so every later fetch of the pin
    # (the contract check, the composition flake's inputs) asked the forge
    # for a repo literally named "...?narHash=..." and failed -- misreported
    # as "does not expose cogboxPlugins.default". git+file:// exercises the
    # same fetcher without network.
    git_plug = "/home/testuser/cogbox-git-plugin"
    machine.succeed(as_user(f"mkdir -p {git_plug}"))
    machine.succeed(as_user("""cat > """ + git_plug + """/flake.nix <<'NIX_EOF'
{
    description = "cogbox git-scheme test plugin";
    outputs = { self }: {
        nixosModules.default = { ... }: {
            environment.etc."cogbox-git-plugin".text = "git\\n";
        };
        cogboxPlugins.default = { module = self.nixosModules.default; };
    };
}
NIX_EOF"""))
    machine.succeed(as_user(
        f"cd {git_plug} && git init -q && git add flake.nix && "
        "git -c user.email=t@test -c user.name=t commit -qm init"
    ))
    out = machine.succeed(as_user(
        f"cogbox plugin add 'git+file://{git_plug}' -y --name plug"
    ))
    assert "added" in out, out
    locked = machine.succeed(f"jq -r '.plugins[0].lockedUrl' {plug_cfg}").strip()
    assert locked.startswith("git+file://") and "rev=" in locked, locked
    assert "narHash=" not in locked, f"narHash param corrupts git URLs: {locked!r}"
    nar = machine.succeed(f"jq -r '.plugins[0].narHash' {plug_cfg}").strip()
    assert nar.startswith("sha256-"), nar
    rev = machine.succeed(f"jq -r '.plugins[0].rev' {plug_cfg}").strip()
    assert len(rev) == 40, rev
    # The recorded pin must itself be fetchable: this exact eval is what the
    # contract check and the composition flake's input resolution perform.
    out = machine.succeed(as_user(
        "nix --extra-experimental-features 'nix-command flakes' "
        f"eval '{locked}#cogboxPlugins' --apply 'm: m ? \"default\"' --json"
    )).strip()
    assert out == "true", out
    machine.succeed(as_user("cogbox plugin del cogbox-git-plugin -y --name plug"))

    # Q7b: a DIRTY git worktree locks with neither rev nor narHash in the
    # URL -- nothing pins it. The add must still work but warn that the
    # plugin floats with the worktree.
    machine.succeed(as_user(f"echo '# dirty' >> {git_plug}/flake.nix"))
    out = machine.succeed(as_user(
        f"cogbox plugin add 'git+file://{git_plug}' -y --name plug 2>&1"
    ))
    assert "added" in out, out
    assert "source tree is dirty" in out, out
    locked = machine.succeed(f"jq -r '.plugins[0].lockedUrl' {plug_cfg}").strip()
    assert "rev=" not in locked and "narHash=" not in locked, locked
    rev = machine.succeed(f"jq -r '.plugins[0].rev' {plug_cfg}").strip()
    assert rev == "null", rev
    machine.succeed(as_user("cogbox plugin del cogbox-git-plugin -y --name plug"))

    # Q8: error reporting. An eval failure inside the plugin flake must
    # surface nix's error, NOT the "does not expose" contract message
    # (which used to swallow every fetch/eval failure) ...
    bad_plug = "/home/testuser/cogbox-bad-plugin"
    machine.succeed(as_user(f"mkdir -p {bad_plug}"))
    machine.succeed(as_user("""cat > """ + bad_plug + """/flake.nix <<'NIX_EOF'
{
    outputs = { self }: {
        cogboxPlugins = throw "cogbox-test-deliberate-eval-error";
    };
}
NIX_EOF"""))
    rc, out = machine.execute(as_user(
        f"cogbox plugin add path:{bad_plug} -y --name plug 2>&1"
    ))
    assert rc != 0, out
    assert "could not evaluate flake" in out, out
    assert "cogbox-test-deliberate-eval-error" in out, out
    assert "does not expose" not in out, out
    # ... while a flake that evaluates fine but lacks the module still gets
    # the contract message.
    rc, out = machine.execute(as_user(
        "cogbox plugin add 'path:/home/testuser/cogbox-test-plugin#nonexistent' -y --name plug 2>&1"
    ))
    assert rc != 0, out
    assert "does not expose cogboxPlugins.nonexistent" in out, out

with subtest("Phase LA: live plugin apply, automatic rollback and serialization"):
    # `cogbox plugin apply` and the inline apply of add/update/del load a plugin
    # change into the RUNNING guest without relaunching QEMU (the host builds
    # the runner the next boot would boot; the guest arms a dead-man revert,
    # switches in a detached unit and keeps the new system only once the host
    # confirms over a fresh ssh connection), and roll a change the guest proves
    # broken back on the host. The test plugins live in
    # tests/fixtures/live-apply; this offline machine can only realise a runner
    # it already has, so flake.nix (checks.cogbox-vm) pre-builds the runner of
    # every composition this phase applies, in add order.
    #
    # Instance `la` (rules mode) runs the live legs with a tmux session in the
    # guest and an ssh session from the host held open across every apply; a
    # second instance, `lafin`, which only ever boots without plugins, runs the
    # planted-intent legs that boot a rolled-back config.
    import json
    import re

    la_icd = "/home/testuser/.config/cogbox/instances/la"
    la_cfg = f"{la_icd}/config.json"
    la_apply = f"{la_icd}/apply"
    la_rt = "/run/user/1000/cogbox-la"
    fixtures = "/etc/cogbox-live-apply"
    # A 60 s apply-unit bound (so W = 180 s) instead of 840/960 s keeps the
    # hang legs and the dead-man leg to minutes; the memory floor is lowered
    # because this 8 GiB machine also runs the inner VM.
    LA_ENV = "COGBOX_APPLY_SWITCH_TIMEOUT=60 COGBOX_APPLY_MIN_AVAILABLE_MB=512"

    def la(cmd):
        return as_user(f"{LA_ENV} {cmd}")

    def la_guest(cmd, name="la"):
        return as_user(f"cogbox ssh --name {name} " + shlex.quote(cmd))

    def install(src, name):
        # (Re)place ~/<name> with a fixture plugin; `plugin add path:...` derives
        # the plugin name from the directory's basename.
        machine.succeed(as_user(
            f"rm -rf /home/testuser/{name} && "
            f"cp -rL --no-preserve=mode {fixtures}/{src} /home/testuser/{name}"
        ))

    def la_diag(apply_dir=la_apply):
        # Everything a failed leg needs, printed before the assertion fires.
        print(machine.execute(
            f"set -x; ls -la {apply_dir} {apply_dir}/rollback {apply_dir}/snap; "
            f"cat {apply_dir}/last.json {apply_dir}/active {apply_dir}/inflight.json; "
            f"tail -n 5 {apply_dir}/rollbacks.jsonl; "
            f"for f in {apply_dir}/*.build.log {apply_dir}/*.guest.log; do echo \"== $f\"; tail -c 6000 $f; done"
        )[1])

    def check(cond, what, apply_dir=la_apply):
        if not cond:
            la_diag(apply_dir)
            raise AssertionError(what)

    def last(apply_dir=la_apply):
        return json.loads(machine.succeed(f"cat {apply_dir}/last.json"))["apply"]

    def expect(result, reason=None, apply_dir=la_apply):
        a = last(apply_dir)
        check(a["result"] == result and (reason is None or a["reason"] == reason),
              f"expected {result}/{reason}, got {a}", apply_dir)
        return a

    def jq(expr, path=la_cfg):
        return machine.succeed(f"jq -r {shlex.quote(expr)} {path}").strip()

    def tagged(plugin, action, cidr):
        return jq(f'[.network.rules[] | select(.plugin == "{plugin}" and .{action} == "{cidr}")] | length')

    def guest_system(name="la"):
        return machine.succeed(la_guest("readlink /run/current-system", name)).strip()

    def system_of(runner):
        return machine.succeed(f"readlink {runner}/share/microvm/system").strip()

    def runner_record():
        # runner.path's content plus its mtime and inode: a pass that re-execs
        # (an evaluation) rewrites it, so an unchanged stat proves the fast path.
        return machine.succeed(f"stat -c '%y %i' {la_icd}/runner.path; cat {la_icd}/runner.path")

    def booted_runner():
        return machine.succeed(f"sed -n 2p {la_rt}/booted-runner").strip()

    def hold_sessions():
        # A tmux session in the guest and an ssh session from the host; every
        # live apply must leave both running (only a restart ends them).
        machine.succeed(la_guest("tmux new-session -d -s la-hold 'sleep 100000'"))
        machine.succeed(as_user(
            "setsid -f cogbox ssh --name la "
            + shlex.quote("echo $$ > /run/la-ssh-hold.pid; exec sleep 100000")
            + " < /dev/null > /dev/null 2>&1"
        ))
        machine.wait_until_succeeds(la_guest("kill -0 $(cat /run/la-ssh-hold.pid)"), timeout=60)

    def sessions_survive():
        machine.succeed(la_guest("tmux has-session -t la-hold"))
        machine.succeed(la_guest("kill -0 $(cat /run/la-ssh-hold.pid)"))
        machine.succeed("pgrep -u testuser -f la-ssh-hold.pid")

    def restart_la():
        machine.succeed(as_user("cogbox restart --no-ssh --name la"))
        machine.wait_until_succeeds(
            as_user(f"ssh {SSH_OPTS} -p {la_ssh} root@127.0.0.1 true"), timeout=600
        )

    def bg(cmd, tag):
        # Run a plugin command in the background; its output and exit code
        # land in /tmp/<tag>.out and /tmp/<tag>.rc.
        machine.succeed(f"rm -f /tmp/{tag}.out /tmp/{tag}.rc")
        machine.succeed(la(
            "setsid -f sh -c "
            + shlex.quote(f"{cmd} > /tmp/{tag}.out 2>&1; echo $? > /tmp/{tag}.rc")
            + " < /dev/null > /dev/null 2>&1"
        ))

    def bg_wait(tag, timeout):
        machine.wait_until_succeeds(f"test -s /tmp/{tag}.rc", timeout=timeout)
        return int(machine.succeed(f"cat /tmp/{tag}.rc").strip()), machine.succeed(f"cat /tmp/{tag}.out")

    # The runners of the compositions this phase applies, and the toplevels it
    # only plans against, by name (flake.nix, checks.cogbox-vm).
    store = json.loads(machine.succeed("cat /etc/cogbox-live-apply.json"))

    def fixture(name):
        if name in store["systems"]:
            return store["systems"][name]
        return system_of(store["runners"][name])

    def plan_agrees(name, inst="la", target=None):
        # The host's unit plan (zig/src/plugin/unitplan.zig, as the hidden
        # `cogbox __unitplan P T` prints it) next to the guest's own
        # `switch-to-configuration dry-activate` for the same switch, from the
        # system the guest runs to fixture `name`: every unit dry-activate would
        # act on, the plan acts on the same way (a stop plus a start of one unit
        # is a restart, as the plan shows it); the units it would not restart
        # and the systemd re-exec verdict agree. The plan is the superset (it
        # takes every unit of P as active), so a unit only it lists is new in T
        # or not active in the guest. A template's instance stands for its
        # template on the plan's side.
        p_sys, t_sys = guest_system(inst), target or fixture(name)
        host, host_skip, host_reexec = {}, set(), None
        for line in machine.succeed(as_user(f"cogbox __unitplan {p_sys} {t_sys}")).splitlines():
            f = line.split()
            if f[0] == "skip":
                host_skip.add(f[1])
            elif f[0] == "reexec":
                host_reexec = f[1] == "yes"
            else:
                host[f[1]] = (f[0], f[2])
        dry = machine.succeed(la_guest(f"{t_sys}/bin/switch-to-configuration dry-activate 2>&1", inst))
        heads = {
            "would stop the following units: ": "stop",
            "would NOT stop the following changed units: ": "skip",
            "would reload the following units: ": "reload",
            "would restart the following units: ": "restart",
            "would start the following units: ": "start",
        }
        acts = {k: set() for k in heads.values()}
        guest_reexec = False
        for line in dry.splitlines():
            if line.strip() == "would restart systemd":
                guest_reexec = True
            for head, k in heads.items():
                if line.startswith(head):
                    acts[k].update(u.strip() for u in line[len(head):].split(",") if u.strip())
        guest = {}
        for u in acts["stop"] | acts["start"] | acts["restart"] | acts["reload"]:
            if u in acts["restart"] or (u in acts["stop"] and u in acts["start"]):
                guest[u] = "restart"
            elif u in acts["stop"]:
                guest[u] = "stop"
            elif u in acts["start"]:
                guest[u] = "start"
            else:
                guest[u] = "reload"

        def template(u):
            return u.split("@", 1)[0] + "@." + u.rsplit(".", 1)[1] if "@" in u else u

        problems = []
        for u, act in sorted(guest.items()):
            h = host.get(u) or host.get(template(u))
            if h is None or h[0] != act:
                problems.append(f"dry-activate would {act} {u}; the plan has {h}")
        for u in sorted(acts["skip"]):
            if u not in host_skip and template(u) not in host_skip:
                problems.append(f"dry-activate would not restart {u}; the plan does not skip it")
        if guest_reexec != host_reexec:
            problems.append(f"dry-activate re-execs systemd: {guest_reexec}; the plan: {host_reexec}")
        covered = set(guest) | {template(u) for u in guest}
        only = sorted(u for u, (act, why) in host.items() if why != "new" and u not in covered and "@." not in u)
        if only:
            shown = machine.succeed(la_guest("systemctl show -p Id,ActiveState -- " + " ".join(only), inst))
            for block in shown.strip().split("\n\n"):
                kv = dict(x.split("=", 1) for x in block.splitlines() if "=" in x)
                if kv.get("ActiveState") not in (None, "inactive", "failed"):
                    problems.append(f"the plan would {host[kv['Id']][0]} {kv['Id']}, active in the guest, but dry-activate would not")
        print(f"plan {name}: host {sorted(host.items())} skip {sorted(host_skip)}; dry-activate {sorted(guest.items())} skip {sorted(acts['skip'])}")
        if problems:
            print(dry)
            raise AssertionError(f"unit plan for {name} disagrees with dry-activate: " + "; ".join(problems))

    for src, name in [("la-kit-v1", "la-kit"), ("la-hang", "la-hang"), ("la-x", "la-x"),
                      ("la-guard", "la-guard"), ("la-lock", "la-lock"), ("la-mount", "la-mount"),
                      ("la-user", "la-user"), ("la-bad", "la-bad"),
                      ("la-noboot", "la-noboot"), ("la-uunit", "la-uunit"),
                      ("la-deny-v1", "la-deny"), ("la-docker", "la-docker"),
                      ("la-net", "la-net"), ("la-sshbad", "la-sshbad")]:
        install(src, name)

    machine.succeed(as_user("cogbox init -y --name la --network rules"))
    machine.succeed(
        "cp /home/testuser/.ssh/id_ed25519.pub /home/testuser/.config/cogbox/authorized_keys"
    )
    la_ssh = jq(".sshPort")
    boot_and_wait("cc-la", "--name la", ssh_port=la_ssh)
    hold_sessions()
    base_sys = guest_system()
    plan_agrees("kit1")

    # LA1: the first plugin of a fresh instance (no plugin source ever
    # materialized) goes live: a package, an /etc file, a service and a skill.
    out = machine.succeed(la("cogbox plugin add path:/home/testuser/la-kit -y --apply --name la 2>&1"))
    print(out)
    a = expect("applied")
    assert "Loaded into the running instance" in out, out
    assert a["runner"] == store["runners"]["kit1"], (a, store)
    assert guest_system() == a["toplevel"] == system_of(a["runner"]), (a, base_sys)
    machine.succeed(la_guest(
        "command -v hello && grep -qx v1 /etc/la-kit && systemctl is-active la-kit.service "
        "&& grep -qx v1 /run/la-kit-version"
    ))
    machine.wait_until_succeeds(la_guest(
        "grep -q 'la-kit v1' /var/lib/cogbox/work/.claude/skills/la-kit-skill/SKILL.md"
    ), timeout=120)
    sessions_survive()
    # The next boot boots exactly this: runner.path names R under the comp of
    # the base, which is now S.
    rp = machine.succeed(f"cat {la_icd}/runner.path").splitlines()
    assert rp[1] == a["runner"], (rp, a)
    base_id = machine.succeed(f"basename $(readlink {la_apply}/base)").strip()
    assert base_id == a["base_id"], (base_id, a)
    assert rp[2] == machine.succeed(f"jq -r .comp {la_apply}/snap/{base_id}/meta.json").strip(), rp

    # LA2: an update goes live too (the service restarts with the new script).
    plan_agrees("kit2")
    install("la-kit-v2", "la-kit")
    out = machine.succeed(la("cogbox plugin update la-kit --apply --name la 2>&1"))
    print(out)
    a = expect("applied")
    r2 = a["runner"]
    sys2 = guest_system()
    assert sys2 == system_of(r2), (sys2, a)
    machine.succeed(la_guest("grep -qx v2 /etc/la-kit && grep -qx v2 /run/la-kit-version"))
    machine.wait_until_succeeds(la_guest(
        "grep -q 'la-kit v2' /var/lib/cogbox/work/.claude/skills/la-kit-skill/SKILL.md"
    ), timeout=120)
    sessions_survive()
    nar_v2 = jq('.plugins[] | select(.name == "la-kit") | .narHash')

    # LA3: a restart boots the same runner on the fast path (no evaluation:
    # neither pass re-execs, so nothing rewrites runner.path).
    before = runner_record()
    restart_la()
    assert runner_record() == before, (before, runner_record())
    assert booted_runner() == r2, (booted_runner(), r2)
    assert guest_system() == sys2
    hold_sessions()
    # The host plan agrees with dry-activate on what the phase applies next
    # (an activation-only change, a new oneshot, an /etc file) and on the
    # disruptive kinds it applies only when forced (docker and the uplink,
    # LA3c) or never (nftables, which changes the initrd).
    for name in ["hang", "kit3", "xguard", "docker", "nft", "net"]:
        plan_agrees(name)

    # Apply anyway (cogbox plugin apply --force / --force-plan PLAN): a change
    # that can go live only by disrupting units (classes B and C) is planned,
    # its plan stored and offered; the owner forces exactly that plan.
    force_hint = "Or apply it now anyway, which would:\n"

    def hinted(out, plan_id, *names):
        # An inline add, update or del run off a terminal (as here, where
        # --force refuses) lists the whole plan it would force, each of
        # `names` in it, and only after it the --force-plan line with its id.
        if force_hint not in out:
            return False
        listing, sep, _ = out.split(force_hint, 1)[1].partition(
            f"To apply it anyway, after reading the plan above: cogbox plugin apply --force-plan {plan_id} -n la")
        return bool(sep) and all(n in listing for n in names)

    def la_inv(unit, name="la"):
        return machine.succeed(la_guest(f"systemctl show -p InvocationID --value {unit}", name)).strip()

    def la_gens():
        # The generations the guest helper has recorded this boot.
        return machine.succeed(la_guest("ls /run/cogbox/live-apply/gen 2>/dev/null | wc -l")).strip()

    def plan_units(plan):
        return [(u["unit"], u["action"], u["class"]) for u in plan["units"]]

    def relaxed(plan):
        # The units a forced run sends the guest to relax: those the plan
        # stops, starts or restarts. One it only reloads keeps its InvocationID
        # and stays running, so it is held to every post-check comparison.
        return sorted({u for u, act, _ in plan_units(plan) if act != "reload"})

    def forced_journal(gen, name="la"):
        # The guest's journal line naming what generation `gen` was told to
        # relax and repair.
        lines = [line for line in machine.succeed(la_guest("journalctl -t cogbox-live-switch --no-pager", name)).splitlines()
                 if f"generation {gen}: forced units: " in line]
        assert len(lines) == 1, lines
        return lines[0]

    def plan_only(plan, unit, action, cls):
        # The plan acts on `unit` alone (by `action`, maybe more: the guest's
        # dry-activate can add a stop and a start beside a restart), class `cls`.
        units = plan_units(plan)
        return {u for u, _, _ in units} == {unit} and (unit, action, cls) in units and {c for _, _, c in units} == {cls}

    def reply_route(name="la"):
        # The reply-via-uplink routing (modules/guest-reply-route.nix) a forced
        # network change must leave in place: the rule, table 1000's default
        # route (networkd re-adds it once the reloaded uplink has its lease)
        # and the nft table, listed with the nft the unit itself runs (the
        # guest has none on PATH).
        machine.succeed(la_guest("ip -4 rule show pref 50 | grep -q 'lookup 1000'", name))
        machine.wait_until_succeeds(la_guest("ip -4 route show table 1000 | grep -q '^default'", name), timeout=60)
        machine.succeed(la_guest(
            "nft=$(systemctl show -p ExecStart --value cogbox-reply-route.service | grep -o '/nix/store/[^ ;]*/bin/nft' | head -n 1); "
            '[ -n "$nft" ] && "$nft" list table ip cogbox_reply > /dev/null', name
        ))

    def force_audit(plan_id, apply_dir=la_apply):
        # The Apply anyway lines of apply/audit.log for one plan, in order.
        recs = []
        for line in machine.succeed(f"cat {apply_dir}/audit.log 2>/dev/null || true").splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("event") == "force" and rec.get("plan") == plan_id:
                recs.append(rec)
        return recs

    def la_kit_at(nar):
        # la-kit's pin in config.json, its source tree and its lock node.
        assert jq('.plugins[] | select(.name == "la-kit") | .narHash') == nar
        disk = machine.succeed(as_user(
            f"nix --extra-experimental-features 'nix-command flakes' hash path {la_icd}/plugin-sources/la-kit"
        )).strip()
        assert disk == nar, (disk, nar)
        locked = machine.succeed(
            "jq -r '.nodes[.nodes.root.inputs[\"p-la-kit\"]].locked.narHash' "
            f"{la_icd}/plugins-flake/flake.lock"
        ).strip()
        assert locked == nar, (locked, nar)

    # LA3c: a docker daemon setting (docker.service stopped and docker.socket
    # restarted: class B) and a change to the uplink's .network file
    # (systemd-networkd reloaded: class C, so the reply route is repaired
    # after the switch), added together. The inline add only plans: it stores
    # the plan and says how to force it, and the guest is untouched. --force
    # refuses without a terminal; an unknown id is plan_expired; once the
    # guest's state moved, the stored id is plan_changed (the new plan is
    # stored, the guest untouched); with the guest back as it was, the same
    # id applies it, the units it stops, starts or restarts exempt only from
    # the unit comparisons and networkd (only reloaded) held to all of them.
    # Then the interactive form, on a terminal, takes it back out.
    inv0 = la_inv("cogbox-reply-route.service")
    gens0 = la_gens()
    machine.succeed(la("cogbox plugin add path:/home/testuser/la-docker -y --no-apply --name la"))
    out = machine.succeed(la("cogbox plugin add path:/home/testuser/la-net -y --apply --name la 2>&1"))
    print(out)
    a = expect("restart_required", "disruptive_units")
    plan = a["plan"]
    check(a["overridable"] is True and plan is not None and a["forced"] is None, a)
    acts = {(u, act) for u, act, _ in plan_units(plan)}
    check(acts >= {("docker.service", "stop"), ("docker.socket", "restart"), ("systemd-networkd.service", "reload")}
          and all(c in ("B", "C") for _, _, c in plan_units(plan)), plan)
    check(plan["repair"] == ["cogbox-reply-route.service"] and plan["reexec"] is False, plan)
    check(plan["P"] == sys2 and plan["T"] == system_of(store["runners"]["netforce"]), (plan, sys2))
    assert hinted(out, plan["id"], "docker.socket", "then restart cogbox-reply-route.service"), out
    id1 = plan["id"]
    stored = json.loads(machine.succeed(f"cat {la_apply}/plans/{id1}.json"))
    check(stored["plan"] == plan and stored["reason"] == "disruptive_units", stored)
    assert stored["nonce"] == machine.succeed(f"cat {la_rt}/qemu.start").strip(), stored
    assert guest_system() == sys2 and la_gens() == gens0
    # --force asks on a terminal only, and takes no --json; neither touches
    # last.json.
    last_before = machine.succeed(f"sha256sum < {la_apply}/last.json")
    for flags, why in [("--force", "terminal"), ("--force --json", "takes no --json")]:
        rc, out = machine.execute(la(f"cogbox plugin apply {flags} --name la < /dev/null 2>&1"))
        check(rc == 64 and why in out, (flags, rc, out))
        assert machine.succeed(f"sha256sum < {la_apply}/last.json") == last_before
    machine.succeed(la("cogbox plugin apply --force-plan ffffffffffffffff --json --name la"))
    a = expect("restart_required", "plan_expired")
    check(a["overridable"] is False and a["plan"] is None and a["forced"] is None, a)
    # A stopped docker.service is no longer stopped by the switch (it would be
    # started instead): another plan.
    machine.succeed(la_guest("systemctl stop docker.service"))
    machine.succeed(la(f"cogbox plugin apply --force-plan {id1} --json --name la"))
    a = expect("restart_required", "plan_changed")
    check(a["plan"] is not None and a["plan"]["id"] != id1 and a["overridable"] is False and a["forced"] is None, a)
    machine.succeed(f"test -f {la_apply}/plans/{a['plan']['id']}.json")
    assert guest_system() == sys2 and la_gens() == gens0
    machine.succeed(la_guest("systemctl start docker.service"))
    # The same guest state plans the same id, and Apply anyway applies it.
    out = machine.succeed(la(f"cogbox plugin apply --force-plan {id1} --json --name la"))
    print(out)
    a = expect("applied")
    check(a["forced"] == {"plan": id1, "units": relaxed(plan)} and "docker.socket" in relaxed(plan)
          and "systemd-networkd.service" not in relaxed(plan), (a, plan))
    sys_nf = system_of(store["runners"]["netforce"])
    check(a["runner"] == store["runners"]["netforce"] and a["toplevel"] == sys_nf, a)
    assert guest_system() == sys_nf
    assert machine.succeed(f"sed -n 2p {la_icd}/runner.path").strip() == store["runners"]["netforce"]
    # docker.socket brings dockerd back with the new setting.
    machine.succeed(la_guest("timeout 120 docker info > /dev/null"))
    machine.succeed(la_guest(
        "conf=$(systemctl show -p ExecStart --value docker.service | grep -o -- '--config-file=[^ ;]*' | head -n 1); "
        "grep -q '\"warn\"' \"${conf#--config-file=}\""
    ))
    reply_route()
    check(la_inv("cogbox-reply-route.service") != inv0, "the repair did not restart cogbox-reply-route.service")
    journal = forced_journal(a["gen"])
    check("docker.service" in journal and "systemd-networkd.service" not in journal
          and "repair: cogbox-reply-route.service" in journal, journal)
    recs = force_audit(id1)
    check(len(recs) >= 2 and recs[-2]["phase"] == "admitted" and recs[-2]["gen"] == a["gen"]
          and recs[-1]["phase"] == "done" and recs[-1]["gen"] == a["gen"]
          and recs[-1]["result"] == "applied" and recs[-1]["forced"] is True, recs)
    machine.succeed(as_user(
        f"ssh {SSH_OPTS} -o IdentitiesOnly=yes -i /home/testuser/.local/share/cogbox/cogbox_ed25519 "
        f"-p {la_ssh} root@127.0.0.1 true"
    ))
    sessions_survive()
    # Back to la-kit alone, interactively: the plan is listed on the terminal
    # and asked about, with neither lock held while the question waits.
    machine.succeed(la("cogbox plugin del la-net -y --no-apply --name la"))
    machine.succeed(la("cogbox plugin del la-docker -y --no-apply --name la"))
    force_pty = r'''
import os, pty, select, subprocess, sys, time
# Run argv[1] as testuser with stdin, stdout and stderr on one terminal; once
# it asks, check the plan it listed and that neither instance lock is held,
# answer y, and exit with its status after printing what the terminal showed.
locks = ["/home/testuser/.config/cogbox/.locks/la.lock", "/home/testuser/.config/cogbox/.locks/la.apply.lock"]
master, slave = pty.openpty()
proc = subprocess.Popen(["su", "-", "testuser", "-c", sys.argv[1]], stdin=slave, stdout=slave, stderr=slave)
os.close(slave)
seen = b""
def pump(until, secs):
    global seen
    end = time.monotonic() + secs
    while time.monotonic() < end and not until():
        ready, _, _ = select.select([master], [], [], 0.5)
        if ready:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                chunk = b""
            if not chunk:
                return
            seen += chunk
def done(code):
    sys.stdout.write(seen.decode(errors="replace") + "\nla-force-pty: %d\n" % code)
    sys.exit(code)
pump(lambda: b"[y/N] " in seen, 400)
if b"[y/N] " not in seen:
    proc.kill()
    done(90)
for unit in [b"docker.service", b"systemd-networkd.service", b"cogbox-reply-route.service"]:
    if unit not in seen:
        proc.kill()
        done(91)
for lock in locks:
    if subprocess.run(["flock", "-n", lock, "true"]).returncode != 0:
        proc.kill()
        done(92)
os.write(master, b"y\n")
pump(lambda: False, 400)
try:
    rc = proc.wait(timeout=30)
except subprocess.TimeoutExpired:
    proc.kill()
    done(93)
done(rc if rc >= 0 else 128 - rc)
'''
    machine.succeed("cat > /tmp/la-force-pty.py << 'PY_EOF'\n" + force_pty + "\nPY_EOF")
    rc, out = machine.execute(
        "python3 /tmp/la-force-pty.py " + shlex.quote(f"{LA_ENV} cogbox plugin apply --force --name la") + " < /dev/null"
    )
    print(out)
    asked = re.search(r"Apply anyway \(plan ([0-9a-f]{16})\)\? \[y/N\] ", out)
    asked_id = asked.group(1) if asked else None
    check(rc == 0 and asked_id is not None and "Apply anyway would act on these units in the running instance 'la':" in out
          and "forced units: " in out, (rc, out))
    a = expect("applied")
    check(a["forced"] is not None and a["forced"]["plan"] == asked_id, (a, asked_id))
    assert guest_system() == sys2
    assert machine.succeed(f"sed -n 2p {la_icd}/runner.path").strip() == r2
    # The forced stop left only docker.socket; a stopped docker.service that
    # multi-user.target wants would make every later plan start it (LA14b).
    machine.succeed(la_guest("systemctl start docker.service"))
    sessions_survive()

    # LA3b: a rolled-back update keeps the plugin's deny under a broader user
    # allow. A user allow for 10.99.0.0/24 lets the guest reach 10.99.0.2;
    # la-deny version 1 denies that host (its deny is merged ahead of the
    # allow). Version 2 drops the deny, and a login trap planted from guest
    # root (it fails while /etc/la-deny says v2) makes the switch fail the
    # guest's login probe: rejected/breaks_base. The rollback restores version
    # 1, its deny is merged back ahead of the allow, and the host is denied
    # again.
    def la_rule_index(cidr):
        # 1-based position of the untagged user allow `cidr` in .network.rules.
        return jq(f'[.network.rules | to_entries[] | select(.value.allow == "{cidr}" and (.value.plugin == null)) | .key][0] + 1')

    machine.succeed(as_user("cogbox rules add allow 10.99.0.0/24 --at 1 --name la"))
    machine.succeed(probe("la", "10.99.0.2"))
    out = machine.succeed(la("cogbox plugin add path:/home/testuser/la-deny -y --apply --name la 2>&1"))
    print(out)
    a = expect("applied")
    assert a["runner"] == store["runners"]["deny1"], (a, store)
    sys_deny = guest_system()
    assert tagged("la-deny", "deny", "10.99.0.2/32") == "1"
    machine.fail(probe("la", "10.99.0.2"))
    trap = '[ "$(cat /etc/la-deny 2>/dev/null)" = v2 ] && exit 1'
    machine.succeed(la_guest(f"printf '%s\\n' {shlex.quote(trap)} > /etc/profile.local && runuser -l root -c true"))
    install("la-deny-v2", "la-deny")
    rc, out = machine.execute(la("cogbox plugin update la-deny --apply --name la 2>&1"))
    print(out)
    a = expect("rejected", "breaks_base")
    check(rc == 1 and a["rollback"]["status"] == "done" and a["rollback"]["target"] == "base", (rc, a))
    assert guest_system() == sys_deny
    machine.succeed(la_guest("grep -qx v1 /etc/la-deny && runuser -l root -c true"))
    assert tagged("la-deny", "deny", "10.99.0.2/32") == "1"
    assert int(jq('[.network.rules | to_entries[] | select(.value.plugin == "la-deny") | .key][0]')) < int(la_rule_index("10.99.0.0/24")) - 1
    machine.fail(probe("la", "10.99.0.2"))
    rec = json.loads(machine.succeed(f"tail -n 1 {la_apply}/rollbacks.jsonl"))
    assert rec["reason"] == "breaks_base", rec
    assert [(n["name"], n["action"]) for n in rec["names"]] == [("la-deny", "restored")], rec
    sessions_survive()
    # Back to la-kit alone (the runner LA4 and later expect), the user allow
    # dropped: without la-deny's deny that allow alone decides .2.
    machine.succeed(la_guest("rm -f /etc/profile.local"))
    out = machine.succeed(la("cogbox plugin del la-deny -y --apply --name la 2>&1"))
    print(out)
    a = expect("applied")
    assert a["runner"] == r2 and guest_system() == sys2, (a, r2, sys2)
    machine.succeed(probe("la", "10.99.0.2"))
    machine.succeed(as_user(f"cogbox rules del {la_rule_index('10.99.0.0/24')} --name la"))
    machine.fail(probe("la", "10.99.0.2"))
    sessions_survive()

    # LA4: rollback of an add. la-hang's activation never returns: the apply
    # unit's bound kills it, the guest reports activation_hang and reverts, and
    # the host restores the base snapshot. Meanwhile a plugin change with
    # COGBOX_APPLY_WAIT_MAX=5 gives up waiting (exit 69) and changes nothing.
    bg("cogbox plugin add path:/home/testuser/la-hang -y --apply --name la", "la-hang")
    machine.wait_until_succeeds(f"jq -e '.phase == \"guest\"' {la_apply}/active", timeout=900)
    cfg_before = machine.succeed(f"sha256sum < {la_cfg}")
    rc, out = machine.execute(as_user(
        "COGBOX_APPLY_WAIT_MAX=5 cogbox plugin update la-kit --no-apply --name la 2>&1"
    ))
    assert rc == 69 and "busy: a live apply is finishing" in out, (rc, out)
    assert machine.succeed(f"sha256sum < {la_cfg}") == cfg_before
    rc, out = bg_wait("la-hang", 900)
    print(out)
    a = expect("rejected", "activation_hang")
    check(rc == 1 and "'la-hang' was not applied and has been rolled back" in out, (rc, out))
    check(a["rollback"]["status"] == "done" and a["rollback"]["target"] == "base", a)
    check(a["rolled_back_guest"] is True, a)
    # The guest is back on P, /etc included.
    assert guest_system() == sys2
    machine.succeed(la_guest(f'[ "$(readlink -f /etc/static)" = "$(readlink -f {sys2}/etc)" ]'))
    sessions_survive()
    # The host is back on B: no entry, no rule tagged la-hang (its deny went with
    # it), the composition is B's bytes and runner.path is the booted runner.
    assert jq('[.plugins[] | select(.name == "la-hang")] | length') == "0"
    assert jq('[.network.rules[] | select(.plugin == "la-hang")] | length') == "0"
    base_id = machine.succeed(f"basename $(readlink {la_apply}/base)").strip()
    for f in ["flake.nix", "flake.lock"]:
        machine.succeed(f"cmp {la_icd}/plugins-flake/{f} {la_apply}/snap/{base_id}/composition/{f}")
    assert machine.succeed(f"sed -n 2p {la_icd}/runner.path").strip() == booted_runner() == r2
    rec = json.loads(machine.succeed(f"tail -n 1 {la_apply}/rollbacks.jsonl"))
    assert rec["reason"] == "activation_hang" and rec["names"][0]["name"] == "la-hang", rec
    assert rec["names"][0]["action"] == "removed", rec
    # The build log of the generation is available.
    machine.succeed(as_user(f"cogbox plugin apply --log {a['gen']} --name la"))
    # ...and the next boot takes the fast path, with no evaluation.
    before = runner_record()
    restart_la()
    assert runner_record() == before
    assert booted_runner() == r2
    hold_sessions()

    # LA5: a restart right after the guest reports activation_hang, while the
    # inline add is still polling: `cogbox stop` ends the apply (its intent is
    # already on disk) and the next launch finishes the rollback before it
    # boots, so the box boots without la-hang.
    bg("cogbox plugin add path:/home/testuser/la-hang -y --apply --name la", "la-hang2")
    # The intent exists from the verdict until the guest's revert ends and the
    # add finishes it, which can be a second or two, so it is polled tightly;
    # should the add win anyway, the restart still follows a rejection.
    machine.succeed(
        f"timeout 900 sh -c 'until ls {la_apply}/rollback/*.intent >/dev/null 2>&1 "
        "|| test -s /tmp/la-hang2.rc; do sleep 0.1; done'"
    )
    restart_la()
    rc, out = bg_wait("la-hang2", 120)
    # 143: the stop ended the add on its SIGTERM path and the launch finished
    # the rollback; 1: the add finished it first.
    print(f"LA5: the inline add exited {rc}", out)
    assert rc in (1, 143), (rc, out)
    assert jq('[.plugins[] | select(.name == "la-hang")] | length') == "0"
    assert jq('[.network.rules[] | select(.plugin == "la-hang")] | length') == "0"
    machine.fail(f"ls {la_apply}/rollback/*.intent")
    rec = json.loads(machine.succeed(f"tail -n 1 {la_apply}/rollbacks.jsonl"))
    assert rec["reason"] == "activation_hang" and rec["names"][0]["name"] == "la-hang", rec
    assert booted_runner() == r2
    assert guest_system() == sys2
    hold_sessions()

    # LA6: rollback of an update. Version 3 adds a oneshot that never finishes
    # starting: unit_hang. The entry and the tree return to version 2, the rule
    # only version 3 added is gone, and the rule both versions carry stays.
    install("la-kit-v3", "la-kit")
    rc, out = machine.execute(la("cogbox plugin update la-kit --apply --name la 2>&1"))
    print(out)
    a = expect("rejected", "unit_hang")
    check(rc == 1, (rc, out))
    assert jq('.plugins[] | select(.name == "la-kit") | .narHash') == nar_v2
    disk = machine.succeed(as_user(
        f"nix --extra-experimental-features 'nix-command flakes' hash path {la_icd}/plugin-sources/la-kit"
    )).strip()
    assert disk == nar_v2, (disk, nar_v2)
    locked = machine.succeed(
        "jq -r '.nodes[.nodes.root.inputs[\"p-la-kit\"]].locked.narHash' "
        f"{la_icd}/plugins-flake/flake.lock"
    ).strip()
    assert locked == nar_v2, (locked, nar_v2)
    assert tagged("la-kit", "allow", "10.99.0.5/32") == "0"
    assert tagged("la-kit", "allow", "10.99.0.1/32") == "1"
    assert guest_system() == sys2
    machine.succeed(la_guest("grep -qx v2 /etc/la-kit && ! systemctl is-active la-kit-wait.service"))
    sessions_survive()
    install("la-kit-v2", "la-kit")

    # LA6b: a plugin change waits behind a guest-phase apply and commits on top
    # of that apply's rollback. `update la-kit` to version 3 (unit_hang again)
    # runs in the background; once its apply is in the guest phase, a second
    # `update la-kit` to a working version 4 waits for it (printing why), the
    # first is rolled back to version 2, and only then does version 4 commit,
    # from version 2, and apply live. Had it committed on top of version 3,
    # the rollback (which restores version 2 wholesale) would have erased it.
    install("la-kit-v3", "la-kit")
    bg("cogbox plugin update la-kit --apply --name la", "la-v3")
    machine.wait_until_succeeds(f"jq -e '.phase == \"guest\"' {la_apply}/active", timeout=900)
    install("la-kit-v4", "la-kit")
    nar_v4 = machine.succeed(as_user(
        "nix --extra-experimental-features 'nix-command flakes' hash path /home/testuser/la-kit"
    )).strip()
    rc, out = machine.execute(la("cogbox plugin update la-kit --apply --name la 2>&1"))
    print(out)
    rc3, out3 = bg_wait("la-v3", 900)
    print(out3)
    check(rc3 == 1 and "has been rolled back" in out3, (rc3, out3))
    check(rc == 0 and "waiting for the live apply of generation" in out and "Loaded into the running instance" in out, (rc, out))
    a = expect("applied")
    assert a["runner"] == store["runners"]["kit4"], (a, store)
    # Version 3's rollback (to version 2) is the newest record: version 4's
    # commit came after it, not before.
    rec = json.loads(machine.succeed(f"tail -n 1 {la_apply}/rollbacks.jsonl"))
    assert rec["reason"] == "unit_hang", rec
    assert [(n["name"], n["action"]) for n in rec["names"]] == [("la-kit", "restored")], rec
    assert jq('.plugins[] | select(.name == "la-kit") | .narHash') == nar_v4
    disk = machine.succeed(as_user(
        f"nix --extra-experimental-features 'nix-command flakes' hash path {la_icd}/plugin-sources/la-kit"
    )).strip()
    assert disk == nar_v4, (disk, nar_v4)
    locked = machine.succeed(
        "jq -r '.nodes[.nodes.root.inputs[\"p-la-kit\"]].locked.narHash' "
        f"{la_icd}/plugins-flake/flake.lock"
    ).strip()
    assert locked == nar_v4, (locked, nar_v4)
    assert tagged("la-kit", "allow", "10.99.0.5/32") == "0"
    assert tagged("la-kit", "allow", "10.99.0.1/32") == "1"
    machine.succeed(la_guest(
        "grep -qx v4 /etc/la-kit && grep -qx v4 /run/la-kit-version && ! systemctl is-active la-kit-wait.service"
    ))
    sessions_survive()
    # Back to version 2 (the runner the later legs expect).
    install("la-kit-v2", "la-kit")
    out = machine.succeed(la("cogbox plugin update la-kit --apply --name la 2>&1"))
    print(out)
    a = expect("applied")
    assert a["runner"] == r2 and guest_system() == sys2, (a, r2, sys2)
    assert jq('.plugins[] | select(.name == "la-kit") | .narHash') == nar_v2

    # LA7: a plugin change during an apply's build supersedes it: the apply ends
    # `superseded` with the guest untouched, the change commits, and the next
    # apply brings both changes live.
    machine.succeed(la("cogbox plugin add path:/home/testuser/la-x -y --no-apply --name la"))
    bg("cogbox plugin apply --json --name la", "la-sup")
    machine.wait_until_succeeds(f"jq -e '.phase == \"build\"' {la_apply}/active", timeout=300)
    machine.succeed(la("cogbox plugin add path:/home/testuser/la-guard -y --no-apply --name la"))
    rc, out = bg_wait("la-sup", 120)
    print(out)
    sup = json.loads([line for line in out.splitlines() if line.startswith('{"apply"')][-1])["apply"]
    check(rc == 0 and sup["result"] == "superseded", (rc, out))
    assert guest_system() == sys2
    assert jq('[.plugins[].name] | join(",")') == "la-kit,la-x,la-guard"
    out = machine.succeed(la("cogbox plugin apply --json --name la"))
    print(out)
    a = expect("applied")
    sys5 = guest_system()
    assert sys5 == a["toplevel"]
    machine.succeed(la_guest("test -f /etc/la-x"))
    sessions_survive()
    for name in ["guard", "lock", "user", "mount"]:
        plan_agrees(name)

    # LA7b: an orphaned build unit on a host that stays up. A root apply
    # (`cap: unit`; root without sudo, as GCE and PVE run it, with HOME and
    # XDG_RUNTIME_DIR naming testuser's instance) runs each build stage in
    # `cogbox-apply-build-<12 hex of sha256(icd)>`.
    # A `systemd-run` shim first on its PATH forces what systemd 261 often does
    # on its own (the `Running as unit:` line reaches the verb without its
    # InvocationID) and runs a long, recognisable process in stage (a)'s unit
    # instead of the evaluation; the real systemd-run starts the real unit. The
    # verb is SIGKILLed, as cogworx's bound does before its cancel: its
    # systemd-run client dies with it, and the unit runs on, recorded only by
    # apply/active. A non-root apply cannot stop a root apply's unit, so it
    # answers failed/busy and leaves the record as it was; the cancel, as
    # root, stops the unit by its name and only then clears the record.
    import hashlib
    la_unit = "cogbox-apply-build-" + hashlib.sha256(la_icd.encode()).hexdigest()[:12]
    la_sdrun_shim = (
        "#!/run/current-system/sw/bin/bash\n"
        "for a in \"$@\"; do case $a in *declaredRunner.drvPath*) orphan=1 ;; esac; done\n"
        "if [ -n \"${orphan-}\" ]; then\n"
        "  opts=()\n"
        "  for a in \"$@\"; do [ \"$a\" = -- ] && break; opts+=(\"$a\"); done\n"
        "  set -- \"${opts[@]}\" -- /tmp/la-shim/la-orphan-build\n"
        "fi\n"
        "exec 2> >(/run/current-system/sw/bin/sed -u 's/; invocation ID: [0-9a-f]\\{32\\}$//' >&2)\n"
        "exec /run/current-system/sw/bin/systemd-run \"$@\""
    )
    machine.succeed("mkdir -p /tmp/la-shim")
    machine.succeed("cat > /tmp/la-shim/systemd-run << 'SH_EOF'\n" + la_sdrun_shim + "\nSH_EOF")
    # Not `exec -a NAME sleep`: coreutils is one multi-call binary that picks
    # the program from argv[0]. The loop's own cmdline names the script.
    machine.succeed(
        "printf '#!/run/current-system/sw/bin/bash\\nwhile :; do /run/current-system/sw/bin/sleep 5; done\\n'"
        " > /tmp/la-shim/la-orphan-build"
    )
    la_orphan = "pgrep -f '^/run/current-system/sw/bin/bash /tmp/la-shim/la-orphan-buil[d]'"
    machine.succeed("chmod 0755 /tmp/la-shim/systemd-run /tmp/la-shim/la-orphan-build")
    la_root = (
        "env -u NIX_REMOTE -u SUDO_USER -u XDG_CONFIG_HOME -u XDG_DATA_HOME -u COGBOX_DATA "
        f"HOME=/home/testuser XDG_RUNTIME_DIR=/run/user/1000 PATH=/tmp/la-shim:$PATH {LA_ENV}"
    )

    def la7b_diag():
        print(machine.execute(
            "set -x; cat /tmp/la-orphan.out; "
            f"cat {la_apply}/active; ls -la {la_apply}; "
            "ps -eo pid,ppid,etimes,user,args --forest | grep -v ']$' | tail -n 80; "
            f"systemctl status --no-pager {la_unit}; "
            "systemctl list-units --all --no-pager --plain 'cogbox-apply-build*'; "
            "cat /proc/locks; ls -lai /home/testuser/.config/cogbox/.locks; "
            "journalctl --no-pager -n 80"
        )[1])

    def la7b_wait(cmd, timeout):
        try:
            machine.wait_until_succeeds(cmd, timeout=timeout)
        except Exception:
            la7b_diag()
            raise

    print(machine.succeed(f"{la_root} sh -c 'id -u; command -v systemd-run cogbox; echo $PATH'"))
    machine.succeed(
        "setsid -f sh -c "
        + shlex.quote(f"{la_root} cogbox plugin apply --json --op 1 --name la > /tmp/la-orphan.out 2>&1")
        + " < /dev/null > /dev/null 2>&1"
    )
    # The root apply reaches its build, or reports early.
    la_reported = "grep -q '^{\"apply\"' /tmp/la-orphan.out"
    la7b_wait(f"jq -e '.phase == \"build\"' {la_apply}/active || {la_reported}", 120)
    # Then stage (a)'s unit runs the orphan.
    la7b_wait(f"(systemctl is-active --quiet {la_unit} && {la_orphan}) || {la_reported}", 120)
    if machine.execute(f"systemctl is-active --quiet {la_unit} && {la_orphan}")[0] != 0:
        la7b_diag()
        raise AssertionError("the root apply ended before its build unit ran the orphan")
    act = json.loads(machine.succeed(f"cat {la_apply}/active"))
    # The no-ID path was taken, and the record names the unit regardless.
    check(act["unit"] == la_unit and act["phase"] == "build" and act["invocation"] is None, act)
    machine.succeed(f"kill -KILL {act['pid']}")
    machine.wait_until_fails(f"kill -0 {act['pid']}", timeout=30)
    machine.wait_until_fails("pgrep -f 'systemd-run --unit=cogbox-apply-buil[d]'", timeout=30)
    print(machine.succeed("cat /tmp/la-orphan.out"))
    # The orphan: the verb and its systemd-run client are gone, the unit runs.
    machine.succeed(f"systemctl is-active --quiet {la_unit}")
    machine.succeed(la_orphan)
    before = machine.succeed(f"cat {la_apply}/active")
    rc, out = machine.execute(la("cogbox plugin apply --json --name la 2>&1"))
    print(out)
    expect("failed", "busy")
    # busy because its stop of the unit was refused (not a held lock).
    check(f"could not stop {la_unit}" in out and "apply/active keeps it" in out, out)
    check(machine.succeed(f"cat {la_apply}/active") == before, "a non-root apply overwrote the record of a unit it could not stop")
    machine.succeed(f"systemctl is-active --quiet {la_unit}")
    # The cancel recovery, as cogworx runs it on GCE and PVE.
    out = machine.succeed(f"{la_root} cogbox plugin apply --cancel --json --op 1 --name la")
    print(out)
    c = json.loads(out.strip().splitlines()[-1])["cancel"]
    check(c["result"] == "none" and c["signalled"] is False, c)
    machine.wait_until_fails(f"systemctl is-active --quiet {la_unit}", timeout=30)
    machine.wait_until_fails(la_orphan, timeout=30)
    machine.wait_until_succeeds(
        f"test -z \"$(systemctl list-units --all --plain --no-legend '{la_unit}*')\"", timeout=30
    )
    machine.succeed(f"test ! -e {la_apply}/active")
    machine.succeed("rm -rf /tmp/la-shim")
    # Root without sudo chowns nothing back: its scratch snapshot and build
    # log are root's. The instance is testuser's again for the legs below.
    machine.succeed(f"chown -R testuser:users {la_icd}")
    # Nothing stale blocks the next apply.
    out = machine.succeed(la("cogbox plugin apply --json --name la"))
    print(out)
    expect("already_live")

    # LA8: rollback of a removal. la-guard's activation hangs once /etc/la-x is
    # gone, so `del la-x` is rejected: la-x is reinserted with its source, its
    # tagged deny comes back, and its allow (which the del removed) does not.
    assert tagged("la-x", "deny", "10.99.0.9/32") == "1"
    nar_x = jq('.plugins[] | select(.name == "la-x") | .narHash')
    rc, out = machine.execute(la("cogbox plugin del la-x -y --apply --name la 2>&1"))
    print(out)
    a = expect("rejected", "activation_hang")
    check(rc == 1, (rc, out))
    assert jq('[.plugins[].name] | join(",")') == "la-kit,la-x,la-guard"
    disk = machine.succeed(as_user(
        f"nix --extra-experimental-features 'nix-command flakes' hash path {la_icd}/plugin-sources/la-x"
    )).strip()
    assert disk == nar_x, (disk, nar_x)
    assert tagged("la-x", "deny", "10.99.0.9/32") == "1"
    assert tagged("la-x", "allow", "10.99.0.8/32") == "0"
    rec = json.loads(machine.succeed(f"tail -n 1 {la_apply}/rollbacks.jsonl"))
    assert [(n["name"], n["action"]) for n in rec["names"]] == [("la-x", "reinserted")], rec
    assert guest_system() == sys5
    machine.succeed(la_guest("test -f /etc/la-x"))
    sessions_survive()

    # LA9: a lockout only a fresh connection sees. la-lock refuses every ssh
    # login at PAM's account stage without restarting sshd, so the guest's own
    # checks pass; with `ControlMaster auto` in the user's ssh config and a
    # master connection open, an apply hop that reused it would get in. Every
    # hop opens its own connection, so the host loses the guest, the dead-man
    # reverts it at W, and the change is rejected/unreachable and rolled back.
    machine.succeed(as_user(
        "mkdir -p ~/.ssh && printf 'Host 127.0.0.1\\n\\tControlMaster auto\\n"
        "\\tControlPath /tmp/la-cm-%%r@%%h:%%p\\n\\tControlPersist 900\\n' > ~/.ssh/config"
    ))
    machine.succeed(as_user("cogbox ssh --name la true"))
    machine.succeed(f"test -S /tmp/la-cm-root@127.0.0.1:{la_ssh}")

    # LA9a: the same through a forced sshd restart, and K after a live
    # rejection. la-kit version 5 makes sshd deny root: the update plans
    # sshd.service's restart (disruptive_units), so it is kept for the next
    # boot (K := S, its runner recorded). Applied anyway, sshd restarts and
    # passes `sshd -t` and the guest's login probe, and the connections
    # already open (the master included) survive, but no fresh connection
    # gets in: rejected/unreachable, rolled back to B. That live rejection
    # unlinks K, so the eval_error that follows rolls back to B as well,
    # never to version 5.
    install("la-kit-v5", "la-kit")
    out = machine.succeed(la("cogbox plugin update la-kit --apply --name la 2>&1"))
    print(out)
    a = expect("restart_required", "disruptive_units")
    plan = a["plan"]
    check(a["overridable"] is True and plan is not None and plan_only(plan, "sshd.service", "restart", "B")
          and plan["repair"] == [] and a["built_id"], a)
    assert machine.succeed(f"sed -n 2p {la_icd}/runner.path").strip() == store["runners"]["kit5x"]
    assert hinted(out, plan["id"], "restart sshd.service"), out
    out = machine.succeed(la(f"cogbox plugin apply --force-plan {plan['id']} --json --name la"))
    print(out)
    a = expect("rejected", "unreachable")
    check("recovered" in a["detail"] and a["forced"] == {"plan": plan["id"], "units": ["sshd.service"]}, a)
    check(a["rollback"]["status"] == "done" and a["rollback"]["target"] == "base" and a["built_id"] is None, a)
    machine.fail(f"test -e {la_apply}/built || test -L {la_apply}/built")
    la_kit_at(nar_v2)
    assert guest_system() == sys5
    machine.succeed(f"test -S /tmp/la-cm-root@127.0.0.1:{la_ssh}")
    # A fresh login with the cogbox key works again (P's sshd_config is back);
    # -F /dev/null keeps the user's ControlMaster from multiplexing it.
    machine.succeed(as_user(
        f"ssh -F /dev/null {SSH_OPTS} -o IdentitiesOnly=yes -i /home/testuser/.local/share/cogbox/cogbox_ed25519 "
        f"-p {la_ssh} root@127.0.0.1 true"
    ))
    sessions_survive()
    rc, out = machine.execute(la("cogbox plugin add path:/home/testuser/la-bad -y --apply --name la 2>&1"))
    print(out)
    a = expect("rejected", "eval_error")
    base_id = machine.succeed(f"basename $(readlink {la_apply}/base)").strip()
    check(rc == 1 and a["rollback"]["target"] == "base" and a["rollback"]["target_id"] == base_id, (rc, a))
    assert jq('[.plugins[] | select(.name == "la-bad")] | length') == "0"
    la_kit_at(nar_v2)
    rp = machine.succeed(f"sed -n 2p {la_icd}/runner.path").strip()
    check(rp == machine.succeed(f"jq -r .runner {la_apply}/base/meta.json").strip() == store["runners"]["xguard"]
          and rp != store["runners"]["kit5x"], rp)
    install("la-kit-v2", "la-kit")

    rc, out = machine.execute(la("cogbox plugin add path:/home/testuser/la-lock -y --apply --name la 2>&1"))
    print(out)
    a = expect("rejected", "unreachable")
    check(rc == 1 and "recovered" in a["detail"], (rc, a))
    check(a["rollback"]["status"] == "done", a)
    machine.succeed(f"test -S /tmp/la-cm-root@127.0.0.1:{la_ssh}")
    machine.succeed(as_user(
        f"ssh -O exit -o ControlPath=/tmp/la-cm-root@127.0.0.1:{la_ssh} -p {la_ssh} root@127.0.0.1; rm -f ~/.ssh/config"
    ))
    assert jq('[.plugins[] | select(.name == "la-lock")] | length') == "0"
    assert guest_system() == sys5
    machine.succeed(as_user(
        f"ssh {SSH_OPTS} -o IdentitiesOnly=yes -i /home/testuser/.local/share/cogbox/cogbox_ed25519 "
        f"-p {la_ssh} root@127.0.0.1 true"
    ))
    sessions_survive()

    # LA9c: a forced sshd whose new config does not load. la-sshbad includes
    # an option sshd does not know, so sshd's restart fails and so does
    # `sshd -t`. Force exempts sshd only from the unit comparisons, never from
    # the base checks: rejected/breaks_base, rolled back, and the human line
    # names the forced units.
    rc, out = machine.execute(la("cogbox plugin add path:/home/testuser/la-sshbad -y --apply --name la 2>&1"))
    print(out)
    a = expect("restart_required", "disruptive_units")
    plan = a["plan"]
    check(rc == 0 and plan is not None and plan_only(plan, "sshd.service", "restart", "B"), (rc, a))
    rc, out = machine.execute(la(f"cogbox plugin apply --force-plan {plan['id']} --name la 2>&1"))
    print(out)
    a = expect("rejected", "breaks_base")
    check(rc == 1 and "forced units: sshd.service" in out, (rc, out))
    check(a["rollback"]["status"] == "done" and a["rollback"]["target"] == "base"
          and a["rolled_back_guest"] is True and a["forced"] == {"plan": plan["id"], "units": ["sshd.service"]}, a)
    machine.succeed(la_guest("systemctl is-active sshd.service && sshd -t && ! test -e /etc/ssh/la-sshbad.conf"))
    assert guest_system() == sys5
    assert jq('[.plugins[] | select(.name == "la-sshbad")] | length') == "0"
    sessions_survive()

    # LA10: `cogbox init` on the running instance leaves the base alone.
    base_before = machine.succeed(f"readlink {la_apply}/base; cat {la_apply}/base/meta.json")
    machine.succeed(as_user("cogbox init -y --name la"))
    assert machine.succeed(f"readlink {la_apply}/base; cat {la_apply}/base/meta.json") == base_before
    sessions_survive()

    # LA11: never-overridable refusals. A user@ change (skipped_units) and then
    # a new mount unit (restart_only_units, which a mixed plan reports first)
    # are not loaded live; each is kept for the next boot (K := S) with its
    # runner recorded.
    rc, out = machine.execute(la("cogbox plugin add path:/home/testuser/la-user -y --apply --name la 2>&1"))
    print(out)
    a = expect("restart_required", "skipped_units")
    check(rc == 0 and a["overridable"] is False and a["built_id"] and a["plan"] is None, a)
    assert "now anyway" not in out, out
    rc, out = machine.execute(la("cogbox plugin add path:/home/testuser/la-mount -y --apply --name la 2>&1"))
    print(out)
    a = expect("restart_required", "restart_only_units")
    check(rc == 0 and a["overridable"] is False and a["built_id"] and a["plan"] is None, a)
    assert "now anyway" not in out, out
    built = a["built_id"]
    r9 = a["runner"]
    assert r9 == store["runners"]["mount"], (a, store)
    assert machine.succeed(f"sed -n 2p {la_icd}/runner.path").strip() == r9
    assert guest_system() == sys5
    machine.fail(la_guest("mountpoint -q /mnt/la-mount"))

    # LA12: a composition that does not evaluate (an option type error) is
    # rejected/eval_error before the guest is touched, and rolled back to K, so
    # the two restart_required changes above survive.
    rc, out = machine.execute(la("cogbox plugin add path:/home/testuser/la-bad -y --apply --name la 2>&1"))
    print(out)
    a = expect("rejected", "eval_error")
    check(rc == 1 and a["rollback"]["target"] == "built" and a["rollback"]["target_id"] == built, a)
    assert jq('[.plugins[].name] | join(",")') == "la-kit,la-x,la-guard,la-user,la-mount"
    assert machine.succeed(f"sed -n 2p {la_icd}/runner.path").strip() == r9
    assert guest_system() == sys5
    build_log = machine.succeed(as_user(f"cogbox plugin apply --log {a['gen']} --name la"))
    assert "is not of type" in build_log, build_log
    status = json.loads(machine.succeed(as_user("cogbox plugin apply --status --json --name la")))["status"]
    assert status["records_id"] and len(status["rollbacks"]) >= 5, status
    sessions_survive()

    # LA13: the kill switch.
    out = machine.succeed(as_user("COGBOX_LIVE_APPLY=0 cogbox plugin apply --json --name la"))
    assert json.loads(out)["apply"]["reason"] == "disabled", out

    # LA14: a boot whose snapshot fails (here a tmpfs over apply/snap, so the
    # take's hard links cross a filesystem) still boots, on the fast path, with
    # no base: applies answer no_boot_record. The next good boot has a base again.
    machine.succeed(f"mount -t tmpfs -o size=1m,uid=1000,gid=100,mode=0755 la-snap {la_apply}/snap")
    restart_la()
    assert booted_runner() == r9
    machine.fail(f"test -e {la_apply}/base")
    out = machine.succeed(la("cogbox plugin apply --json --name la"))
    a = json.loads(out)["apply"]
    check(a["result"] == "restart_required" and a["reason"] == "no_boot_record", a)
    stop_instance("cc-la", name="la")
    machine.succeed(f"umount {la_apply}/snap")
    boot_and_wait("cc-la", "--name la", ssh_port=la_ssh)
    machine.succeed(f"test -f {la_apply}/base/meta.json")
    out = machine.succeed(la("cogbox plugin apply --json --name la"))
    print(out)
    a = expect("already_live")

    # LA14b: what a switch starts beyond its plan. la-noboot turns docker's
    # enableOnBoot off: only multi-user.target.wants/docker.service goes, so
    # the add applies live and docker keeps running. With docker then down, as
    # after a boot with la-noboot, removing it brings the link back, and the
    # switch's start of multi-user.target would start dockerd although no unit
    # file changed: refused (disruptive_units, overridable), docker untouched.
    out = machine.succeed(la("cogbox plugin add path:/home/testuser/la-noboot -y --apply --name la 2>&1"))
    print(out)
    expect("applied")
    machine.succeed(la_guest("systemctl is-active docker.service"))
    machine.succeed(la_guest("systemctl stop docker.service"))
    rc, out = machine.execute(la("cogbox plugin del la-noboot -y --apply --name la 2>&1"))
    print(out)
    a = expect("restart_required", "disruptive_units")
    check(rc == 0 and a["overridable"] is True and "docker.service" in a["detail"], a)
    check(hinted(out, a["plan"]["id"], "docker.service"), (out, a))
    machine.succeed(f"test -f {la_apply}/plans/{a['plan']['id']}.json")
    assert machine.succeed(f"sed -n 2p {la_icd}/runner.path").strip() == r9
    machine.fail(la_guest("systemctl is-active docker.service"))
    machine.succeed(la_guest("systemctl start docker.service"))

    # LA14c: a user unit (etc/systemd/user). Adding one applies live; removing
    # it would have switch-to-configuration's user pass stop it in every
    # running user manager, which neither the host plan nor dry-activate
    # shows: refused, never overridable.
    out = machine.succeed(la("cogbox plugin add path:/home/testuser/la-uunit -y --apply --name la 2>&1"))
    print(out)
    expect("applied")
    machine.succeed(la_guest("test -f /etc/systemd/user/la-uunit.service"))
    rc, out = machine.execute(la("cogbox plugin del la-uunit -y --apply --name la 2>&1"))
    print(out)
    a = expect("restart_required", "restart_only_units")
    check(rc == 0 and a["overridable"] is False and "la-uunit.service" in a["detail"], a)
    machine.succeed(la_guest("test -f /etc/systemd/user/la-uunit.service"))
    stop_instance("cc-la", name="la")

    # LA15-17 (instance lafin, only ever booted without plugins): a pending
    # rollback intent is finished by the launcher before it boots; a target
    # snapshot that cannot be read takes the fail-closed tier; and a rollback
    # that cannot finish at all makes `cogbox start` and the plugin changes exit
    # 78 until `--abandon-rollback`.
    fin_icd = "/home/testuser/.config/cogbox/instances/lafin"
    fin_cfg = f"{fin_icd}/config.json"
    fin_apply = f"{fin_icd}/apply"
    machine.succeed(as_user("cogbox init -y --name lafin --network rules"))
    fin_ssh = jq(".sshPort", fin_cfg)
    boot_and_wait("cc-lafin", "--name lafin", ssh_port=fin_ssh)
    stop_instance("cc-lafin", name="lafin")

    def plant(gen, scope):
        target = machine.succeed(f"basename $(readlink {fin_apply}/base)").strip()
        intent = json.dumps({"G": gen, "reason": "activation_hang", "target": "base",
                             "target_id": target, "scope": scope})
        machine.succeed(as_user(
            f"mkdir -p {fin_apply}/rollback && printf '%s' {shlex.quote(intent)} > {fin_apply}/rollback/{gen}.intent"
        ))
        return target

    # LA15: planted intent, finished by `cogbox start`.
    machine.succeed(la("cogbox plugin add path:/home/testuser/la-x -y --no-apply --name lafin"))
    plant("1111111111111111", [{"name": "la-x", "action": "removed"}])
    boot_and_wait("cc-lafin", "--name lafin", ssh_port=fin_ssh)
    assert jq(".plugins | length", fin_cfg) == "0"
    assert jq('[.network.rules[] | select(.plugin == "la-x")] | length', fin_cfg) == "0"
    rec = json.loads(machine.succeed(f"tail -n 1 {fin_apply}/rollbacks.jsonl"))
    assert rec["gen"] == "1111111111111111" and rec["status"] == "done", rec
    machine.fail(la_guest("test -e /etc/la-x", "lafin"))
    stop_instance("cc-lafin", name="lafin")

    # LA16: the target snapshot is unreadable (incomplete: no meta.json), so the
    # same finish takes the fail-closed tier: exactly the intent's names go.
    machine.succeed(la("cogbox plugin add path:/home/testuser/la-x -y --no-apply --name lafin"))
    target = plant("2222222222222222", [{"name": "la-x", "action": "removed"}])
    machine.succeed(f"mv {fin_apply}/snap/{target}/meta.json {fin_apply}/snap/{target}/meta.json.off")
    boot_and_wait("cc-lafin", "--name lafin", ssh_port=fin_ssh)
    assert jq(".plugins | length", fin_cfg) == "0"
    rec = json.loads(machine.succeed(f"tail -n 1 {fin_apply}/rollbacks.jsonl"))
    assert rec["gen"] == "2222222222222222" and rec["status"] == "removed", rec
    machine.fail(f"test -e {fin_icd}/plugin-sources/la-x")
    stop_instance("cc-lafin", name="lafin")

    # LA17: a rollback that cannot be saved (a read-only config dir): exit 78
    # with the stamped line, from the launcher and from a plugin change; `list`
    # still runs; --abandon-rollback moves the intent aside and the box boots.
    plant("3333333333333333", [])
    machine.succeed(f"chmod 0555 {fin_icd}")
    rc, out = machine.execute(as_user("cogbox start --no-ssh --name lafin 2>&1"))
    print(out)
    check(rc == 78 and "cogbox: an automatic plugin rollback could not be finished" in out, (rc, out), fin_apply)
    rc, out = machine.execute(la("cogbox plugin add path:/home/testuser/la-x -y --no-apply --name lafin 2>&1"))
    check(rc == 78 and "cogbox: an automatic plugin rollback could not be finished" in out, (rc, out), fin_apply)
    machine.succeed(as_user("cogbox plugin list --name lafin"))
    machine.succeed(as_user("cogbox plugin apply --abandon-rollback -y --name lafin"))
    machine.succeed(f"ls {fin_apply}/abandoned/3333333333333333.intent.*")
    machine.fail(f"ls {fin_apply}/rollback/*.intent")
    machine.succeed(f"chmod 0755 {fin_icd}")
    boot_and_wait("cc-lafin", "--name lafin", ssh_port=fin_ssh)
    stop_instance("cc-lafin", name="lafin")

    # LA18: a rollback on a network=full instance, whose `.network` is a
    # string: there is no rules list to restore and no reload, and the rollback
    # still completes (status done): no pending rollback, and plugin changes
    # still run afterwards.
    full_icd = "/home/testuser/.config/cogbox/instances/lafull"
    full_cfg = f"{full_icd}/config.json"
    full_apply = f"{full_icd}/apply"
    machine.succeed(as_user("cogbox init -y --name lafull --network full"))
    assert jq(".network", full_cfg) == "full"
    full_ssh = jq(".sshPort", full_cfg)
    boot_and_wait("cc-lafull", "--name lafull", ssh_port=full_ssh)
    out = machine.succeed(la("cogbox plugin add path:/home/testuser/la-kit -y --apply --name lafull 2>&1"))
    print(out)
    a = expect("applied", apply_dir=full_apply)
    assert a["runner"] == r2, (a, r2)
    install("la-kit-v3", "la-kit")
    rc, out = machine.execute(la("cogbox plugin update la-kit --apply --name lafull 2>&1"))
    print(out)
    a = expect("rejected", "unit_hang", apply_dir=full_apply)
    check(rc == 1 and a["rollback"]["status"] == "done" and a["rollback"]["target"] == "base", (rc, a), full_apply)
    install("la-kit-v2", "la-kit")
    assert jq(".network", full_cfg) == "full"
    assert jq('.plugins[] | select(.name == "la-kit") | .narHash', full_cfg) == nar_v2
    machine.fail(f"ls {full_apply}/rollback/*.intent")
    status = json.loads(machine.succeed(as_user("cogbox plugin apply --status --json --name lafull")))["status"]
    check(status["rollback_pending"] == 0 and not status["in_flight"], status, full_apply)
    machine.succeed(la_guest("grep -qx v2 /etc/la-kit && ! systemctl is-active la-kit-wait.service", "lafull"))
    machine.succeed(as_user("cogbox plugin list --name lafull"))
    machine.succeed(la("cogbox plugin del la-kit -y --no-apply --name lafull"))
    assert jq(".plugins | length", full_cfg) == "0"
    stop_instance("cc-lafull", name="lafull")

    # LA19: the hosted guest profile (packages.cogbox-hosted, what the GCE and
    # PVE hosts boot), whose unit set differs from the workstation's. Its two
    # volumes, which those hosts carve, format and label on their disk, are
    # sparse files here behind the same device paths. The host plan agrees
    # with the hosted guest's own dry-activate; a clean add applies live; an
    # add whose activation hangs is rejected and rolled back.
    hosted = store["hosted"]
    hcogbox = f"{hosted['cogbox']}/bin/cogbox"
    lah_icd = "/home/testuser/.config/cogbox/instances/lah"
    lah_cfg = f"{lah_icd}/config.json"
    lah_apply = f"{lah_icd}/apply"

    def lah(cmd):
        return as_user(f"{LA_ENV} {hcogbox} {cmd}")

    def hosted_fixture(name):
        if name in hosted["systems"]:
            return hosted["systems"][name]
        return system_of(hosted["runners"][name])

    machine.succeed(
        "mkdir -p /var/lib/la-hosted /dev/cogworx-guest"
        " && truncate -s 4G /var/lib/la-hosted/pool.img /var/lib/la-hosted/store.img"
        " && mkfs.ext4 -q -L cogworx-guest /var/lib/la-hosted/pool.img"
        " && mkfs.ext4 -q -L cogworx-store-rw /var/lib/la-hosted/store.img"
        " && chown testuser /var/lib/la-hosted/pool.img /var/lib/la-hosted/store.img"
        " && ln -sfn /var/lib/la-hosted/pool.img /dev/cogworx-guest/pool"
        " && ln -sfn /var/lib/la-hosted/store.img /dev/cogworx-guest/store"
    )
    machine.succeed(lah("init -y --name lah --network rules"))
    lah_ssh = jq(".sshPort", lah_cfg)
    machine.succeed(lah("start --no-ssh --name lah"))
    machine.wait_until_succeeds(as_user(f"ssh {SSH_OPTS} -p {lah_ssh} root@127.0.0.1 true"), timeout=600)
    lah_base = machine.succeed("sed -n 2p /run/user/1000/cogbox-lah/booted-runner").strip()
    assert guest_system("lah") == system_of(lah_base), (guest_system("lah"), lah_base)
    machine.succeed(la_guest("mountpoint -q /var/lib/cogbox-guest", "lah"))
    for name in ["kit2", "docker", "nft", "net"]:
        plan_agrees(f"hosted {name}", inst="lah", target=hosted_fixture(name))
    out = machine.succeed(lah("plugin add path:/home/testuser/la-kit -y --apply --name lah 2>&1"))
    print(out)
    a = expect("applied", apply_dir=lah_apply)
    check(a["runner"] == hosted["runners"]["kit2"], (a, hosted), lah_apply)
    sys_h = guest_system("lah")
    assert sys_h == system_of(a["runner"]), (sys_h, a)
    machine.succeed(la_guest("grep -qx v2 /etc/la-kit && systemctl is-active la-kit.service && grep -qx v2 /run/la-kit-version", "lah"))
    rc, out = machine.execute(lah("plugin add path:/home/testuser/la-hang -y --apply --name lah 2>&1"))
    print(out)
    a = expect("rejected", "activation_hang", apply_dir=lah_apply)
    check(rc == 1 and a["rollback"]["status"] == "done" and a["rolled_back_guest"] is True, (rc, a), lah_apply)
    assert guest_system("lah") == sys_h
    machine.succeed(la_guest(f'[ "$(readlink -f /etc/static)" = "$(readlink -f {sys_h}/etc)" ]', "lah"))
    assert jq('[.plugins[] | select(.name == "la-hang")] | length', lah_cfg) == "0"
    assert machine.succeed(f"sed -n 2p {lah_icd}/runner.path").strip() == hosted["runners"]["kit2"]
    # LA19b: Apply anyway on the hosted guest. The uplink's .network change
    # alone is network_config (class C, so the repair is on); the stored
    # plan's id applies it with nothing relaxed (networkd is only reloaded,
    # so every post-check still holds it), and the reply route is in place
    # after the repair.
    inv_h = la_inv("cogbox-reply-route.service", "lah")
    rc, out = machine.execute(lah("plugin add path:/home/testuser/la-net -y --apply --name lah 2>&1"))
    print(out)
    a = expect("restart_required", "network_config", apply_dir=lah_apply)
    plan = a["plan"]
    check(rc == 0 and a["overridable"] is True and plan is not None
          and plan_only(plan, "systemd-networkd.service", "reload", "C")
          and plan["repair"] == ["cogbox-reply-route.service"], (rc, a), lah_apply)
    out = machine.succeed(lah(f"plugin apply --force-plan {plan['id']} --json --name lah"))
    print(out)
    a = expect("applied", apply_dir=lah_apply)
    check(a["forced"] == {"plan": plan["id"], "units": []}, a, lah_apply)
    journal = forced_journal(a["gen"], "lah")
    check(f"generation {a['gen']}: forced units: none; repair: cogbox-reply-route.service" in journal, journal, lah_apply)
    assert guest_system("lah") == system_of(hosted["runners"]["net"])
    reply_route("lah")
    check(la_inv("cogbox-reply-route.service", "lah") != inv_h, "the repair did not restart cogbox-reply-route.service", lah_apply)
    machine.succeed(lah("stop --name lah"))
    machine.wait_until_fails("test -e /run/user/1000/cogbox-lah/pid", timeout=30)

with subtest("Phase F: default harnesses wired into the VM (codex/pi opt-in, excluded)"):
    boot_and_wait("cc-default", "", ssh_port=2222)
    # Built-in harness launchers are on $PATH inside the VM unconditionally
    # (D4: binaries always installed regardless of which harness has
    # active host state).
    c_path = machine.succeed(as_user("cogbox ssh 'command -v c'")).strip()
    oc_path = machine.succeed(as_user("cogbox ssh 'command -v oc'")).strip()
    assert c_path and oc_path, (c_path, oc_path)
    h_path = machine.succeed(as_user("cogbox ssh 'command -v h'")).strip()
    assert h_path, h_path
    om_version = machine.succeed(as_user("cogbox ssh 'om --version'")).strip()
    assert om_version == "18.8.4", om_version
    ds_path = machine.succeed(as_user("cogbox ssh 'command -v ds'")).strip()
    assert ds_path, ds_path
    ds_version = machine.succeed(as_user("cogbox ssh 'ds --version'")).strip()
    assert "0.2.0-rc.2" in ds_version, ds_version
    machine.succeed(as_user(
        "cogbox ssh 'om auth-broker --help | grep -q \"Manage the omp auth-broker\"'"
    ))
    # OMP's compiled Bun runtime does not reliably discover Nix's CA store.
    # The full-auto launcher must point it at the assembled system + L7 bundle
    # so every OAuth provider's login/token exchange can validate TLS.
    machine.succeed(as_user(
        "cogbox ssh 'test \"$NODE_EXTRA_CA_CERTS\" = /run/cogbox/ca-bundle.crt'"
    ))
    # Codex and pi are opt-in, so their launchers are absent.
    machine.succeed(as_user("cogbox ssh '! command -v cx'"))
    machine.succeed(as_user("cogbox ssh '! command -v p'"))

    # Per-harness config dirs are mounted at the expected guest paths.
    machine.succeed(as_user(
        "cogbox ssh 'mountpoint -q /root/.config/opencode'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'mountpoint -q /root/.local/share/opencode'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'mountpoint -q /root/.hermes'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'mountpoint -q /root/.omp'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'mountpoint -q /root/.dsh'"
    ))
    # The materializer must fail closed if the Hermes overlay mount fails:
    # ordering alone is insufficient because systemd can continue after a
    # failed unit unless the mount is also required.
    for dependency_property in ("After", "Requires"):
        dependencies = machine.succeed(as_user(
            f"cogbox ssh 'systemctl show -p {dependency_property} --value cogbox-brain-materialize.service'"
        )).split()
        assert "root-.hermes.mount" in dependencies, (
            dependency_property, dependencies
        )
    # Brain materialization seeds Hermes's managed-home runtime skeleton only
    # after the home overlay is mounted, so every directory lands in its upper.
    for hermes_dir in ("cron", "sessions", "logs", "memories"):
        machine.succeed(as_user(
            f"cogbox ssh 'test -d /root/.hermes/{hermes_dir}'"
        ))
        machine.succeed(as_user(
            f"cogbox ssh 'test -d /var/lib/harness-rw/hermes-agent/home/upper/{hermes_dir}'"
        ))
    machine.succeed(as_user(
        "cogbox ssh 'h config show >/dev/null'"
    ))
    # Ephemeral paths (cache + state) bind from the harness overlay.
    machine.succeed(as_user(
        "cogbox ssh 'mountpoint -q /root/.cache/opencode'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'mountpoint -q /root/.local/state/opencode'"
    ))

    # Single-image overlay layout: claude-code/config and opencode/{config,data}
    # live under the shared harness-rw mount. (codex/home would join them here
    # when codex is enabled.)
    machine.succeed(as_user(
        "cogbox ssh 'test -d /var/lib/harness-rw/claude-code/config/upper'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'test -d /var/lib/harness-rw/opencode/config/upper'"
    ))
    machine.succeed(as_user(
        "cogbox ssh 'test -d /var/lib/harness-rw/omp/home/upper'"
    ))

    # Persistence: write files under the opencode and OMP overlays, reboot,
    # and verify both survive. The sync flushes the writes through overlayfs
    # to the ext4 overlay image; without it, SIGTERM-killed QEMU loses
    # uncommitted journal entries.
    machine.succeed(as_user(
        "cogbox ssh 'echo persisted > /root/.config/opencode/marker && echo omp-persisted > /root/.omp/marker && sync'"
    ))
    stop_instance("cc-default")
    boot_and_wait("cc-default", "", ssh_port=2222)
    out = machine.succeed(as_user(
        "cogbox ssh 'cat /root/.config/opencode/marker'"
    )).strip()
    assert out == "persisted", out
    omp_out = machine.succeed(as_user(
        "cogbox ssh 'cat /root/.omp/marker'"
    )).strip()
    assert omp_out == "omp-persisted", omp_out
    stop_instance("cc-default")

with subtest("Phase I: background default, console + monitor sockets, stop teardown"):
    rt = "/run/user/1000/cogbox"

    # console/monitor on a stopped instance fail cleanly.
    rc, _ = machine.execute(as_user("cogbox console 2>&1"))
    assert rc != 0, "console on stopped instance should fail"
    rc, _ = machine.execute(as_user("cogbox monitor 2>&1"))
    assert rc != 0, "monitor on stopped instance should fail"

    # cogbox-boot-stamp.service (the guest half of the GCE boot proof) writes
    # this guest boot's id onto the 9p data share once sshd is up: the GUEST's
    # boot id, never this machine's, and pool=na because a workstation guest
    # has no data pool. Earlier phases booted this instance too, so the path is
    # cleared before each boot (as the GCE supervisor does) and a stamp seen
    # afterwards is that boot's. The stop and start at the end of this phase
    # must change it.
    stamp = "/home/testuser/.local/share/cogbox/instances/default/.cogbox-boot-stamp"
    stamp_re = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} pool=na$"
    machine.succeed(f"rm -f {stamp}")

    # `cogbox start` daemonizes and returns; boot_and_wait asserts SSH is up.
    boot_and_wait("cc-default", "", ssh_port=2222)

    machine.wait_until_succeeds(f"grep -qE '{stamp_re}' {stamp}", timeout=60)
    first_stamp = machine.succeed(f"cat {stamp}").strip()
    outer_boot_id = machine.succeed("cat /proc/sys/kernel/random/boot_id").strip()
    assert first_stamp.split()[0] != outer_boot_id, f"the boot stamp carries the outer machine's boot id: {first_stamp}"

    # The per-instance console + monitor sockets exist, and the serial
    # console was captured to console.log (proves the chardev rewrite took).
    machine.succeed(f"test -S {rt}/console.sock")
    machine.succeed(f"test -S {rt}/monitor.sock")
    machine.succeed(f"test -f {rt}/console.log")

    # Drive the live serial console over its socket: the guest runs an
    # autologin root shell on ttyS0, so a typed command produces output.
    console_drv = r'''
import socket, time, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/user/1000/cogbox/console.sock")
s.settimeout(1.0)
buf = b""
deadline = time.time() + 20
s.sendall(b"\n")
while time.time() < deadline:
    s.sendall(b"uname -n\n")
    try:
        while True:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    if b"cogbox-default" in buf:
        break
sys.stderr.write(repr(buf[-200:]))
sys.exit(0 if b"cogbox-default" in buf else 1)
'''
    machine.succeed("cat > /tmp/console-drv.py << 'PY_EOF'\n" + console_drv + "\nPY_EOF")
    machine.succeed(as_user("python3 /tmp/console-drv.py"))

    # Drive the HMP monitor over its socket: 'info status' reports VM state.
    monitor_drv = r'''
import socket, time, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/user/1000/cogbox/monitor.sock")
s.settimeout(1.0)
buf = b""
deadline = time.time() + 15
while time.time() < deadline:
    s.sendall(b"info status\n")
    try:
        while True:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    if b"running" in buf or b"VM status" in buf:
        break
sys.stderr.write(repr(buf[-200:]))
sys.exit(0 if (b"running" in buf or b"VM status" in buf) else 1)
'''
    machine.succeed("cat > /tmp/monitor-drv.py << 'PY_EOF'\n" + monitor_drv + "\nPY_EOF")
    machine.succeed(as_user("python3 /tmp/monitor-drv.py"))

    # Stop must tear the VM down without --force: SIGTERM to the daemon must
    # propagate to QEMU + passt (the trap), not just orphan them.
    stop_instance("cc-default")
    rc, _ = machine.execute(as_user("cogbox status"))
    assert rc == 3, f"expected stopped (exit 3) after stop, got {rc}"
    # No QEMU process should survive a plain stop. Match on the process name
    # (comm = "qemu-system-x86") NOT the full cmdline: microvm-run launches
    # QEMU via `exec -a microvm@nixos`, so the cmdline contains no "qemu" and
    # `pgrep -f qemu-system` would (a) never match the VM and (b) self-match
    # the test driver's own `bash -c 'pgrep ...'` wrapper.
    machine.wait_until_fails("pgrep qemu-system", timeout=15)

    # A new guest boot writes a stamp with a new boot id.
    machine.succeed(f"rm -f {stamp}")
    boot_and_wait("cc-default", "", ssh_port=2222)
    machine.wait_until_succeeds(f"grep -qE '{stamp_re}' {stamp}", timeout=60)
    second_stamp = machine.succeed(f"cat {stamp}").strip()
    assert second_stamp != first_stamp, f"a stop and start did not change the boot stamp: {second_stamp}"
    stop_instance("cc-default")
    machine.wait_until_fails("pgrep qemu-system", timeout=15)

with subtest("Phase H: TCP remap routes via SOCKS5 to a host stub"):
    # The shim's remap primitive (zig/src/filter.zig::RemapRule) rewrites
    # an outbound TCP connect to a loopback target and drives a SOCKS5 v5
    # CONNECT handshake on it, carrying the original destination. The
    # downstream proxy thus learns where the guest *wanted* to go.
    #
    # This phase validates that path end-to-end:
    #   1. A Python stub on the outer VM (127.0.0.1:18080) speaks SOCKS5,
    #      records the CONNECT target to a log, replies success.
    #   2. The cogbox work instance gets a remap rule for
    #      10.99.0.1/32:9000 -> 127.0.0.1:18080 via direct config.json
    #      edit (no CLI verb for remap yet).
    #   3. The cogbox guest probes 10.99.0.1:9000; passt's connect() is
    #      intercepted by the shim, rewritten to 127.0.0.1:18080, and
    #      hands off via SOCKS5.
    #   4. The stub log must show a CONNECT for the *original* destination.

    # Raw string: backslash escapes inside the bytes literals are
    # preserved verbatim through the heredoc.
    stub_script = r'''
import socket, struct, sys
LOG = "/tmp/socks5-conn.log"
open(LOG, "w").close()
def log(s):
    with open(LOG, "a") as f:
        f.write(s + "\n")
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 18080))
srv.listen(8)
log("ready")
while True:
    c, _ = srv.accept()
    try:
        greet = c.recv(3)
        if greet != b"\x05\x01\x00":
            c.close(); continue
        c.sendall(b"\x05\x00")
        hdr = c.recv(4)
        if len(hdr) < 4 or hdr[:2] != b"\x05\x01" or hdr[3] != 1:
            c.close(); continue
        addr = c.recv(4)
        port_b = c.recv(2)
        ip_str = ".".join(str(b) for b in addr)
        port = struct.unpack(">H", port_b)[0]
        log("CONNECT {0}:{1}".format(ip_str, port))
        c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        # Consume any echo bytes the client sends so probe()'s bash
        # exec doesn't block on a write to a full socket buffer.
        try:
            c.recv(64)
        except Exception:
            pass
    finally:
        c.close()
'''
    machine.succeed(
        "cat > /tmp/socks5-stub.py << 'PY_EOF'\n" + stub_script + "\nPY_EOF"
    )
    machine.succeed("systemd-run --unit=socks5-stub --collect python3 /tmp/socks5-stub.py")
    # Stub writes "ready" to its log on bind+listen.
    machine.wait_until_succeeds("grep -q ready /tmp/socks5-conn.log", timeout=10)

    # Pick a target that has NO direct listener so we can prove the
    # remap is what made the probe succeed -- not a lucky catch-all on
    # the existing nc -l -p 9000 (which binds 0.0.0.0).
    machine.succeed("ip addr add 10.99.0.3/32 dev lo")
    # Port 9100: no listener anywhere on the outer VM. Without remap,
    # a TCP connect should be refused (RST).

    # Restore .1 allow (phase D ended after `del 1` which removed .1)
    # and explicitly allow .3.
    machine.succeed(as_user("cogbox rules add allow 10.99.0.1/32 --at 1 --name work"))
    machine.succeed(as_user("cogbox rules add allow 10.99.0.3/32 --at 2 --name work"))

    # Hand-edit the remap table; no CLI verb yet.
    machine.succeed(
        "jq '.network.remap = [{\"from\":\"tcp 10.99.0.3/32:9100\",\"to\":\"tcp 127.0.0.1:18080\"}]' "
        "/home/testuser/.config/cogbox/instances/work/config.json > /tmp/work-cfg.json "
        "&& mv /tmp/work-cfg.json /home/testuser/.config/cogbox/instances/work/config.json "
        "&& chown testuser:users /home/testuser/.config/cogbox/instances/work/config.json"
    )

    boot_and_wait("cc-work", "--name work", ssh_port=2223)

    # The launch script renders both rules and remap into one file.
    rules_text = machine.succeed("cat /run/user/1000/cogbox-work/netfilter-rules")
    assert "remap tcp 10.99.0.3/32:9100 -> tcp 127.0.0.1:18080" in rules_text, rules_text

    # End-to-end: guest connect to 10.99.0.3:9100 must succeed because
    # the shim rewrote the destination to the SOCKS5 stub. The direct
    # 10.99.0.3:9100 path would otherwise be refused (no listener).
    def probe_port(name, ip, port):
        remote = "timeout 3 bash -c 'exec 3<>/dev/tcp/" + ip + "/" + str(port) + "'"
        return as_user("cogbox ssh --name " + name + " " + shlex.quote(remote))

    machine.succeed(probe_port("work", "10.99.0.3", 9100))

    # The stub recorded a CONNECT for the original (pre-remap) target.
    out = machine.succeed("cat /tmp/socks5-conn.log")
    assert "CONNECT 10.99.0.3:9100" in out, "stub log was: " + repr(out)

    # Sanity: connect to 10.99.0.3 on a different port has no remap rule
    # and no listener -- must fail.
    machine.fail(probe_port("work", "10.99.0.3", 9101))

    # Dynamic add through the `cogbox remap` CLI -- the running passt
    # must pick up the new rule via SIGUSR1 reload without restart.
    # Insert at position 1 so the index of the rule we're about to test
    # is deterministic (the .3:9100 jq-edit rule already occupies a
    # slot, so a plain append would land at position 2).
    machine.succeed("ip addr add 10.99.0.4/32 dev lo")
    machine.succeed(as_user("cogbox rules add allow 10.99.0.4/32 --at 1 --name work"))
    out = machine.succeed(as_user(
        "cogbox remap add 'tcp 10.99.0.4/32:9200' 'tcp 127.0.0.1:18080' --at 1 --name work"
    ))
    assert "Rules reloaded" in out, out

    out = machine.succeed(as_user("cogbox remap list --name work"))
    # The new rule should be at index 1 after --at 1.
    first_line = out.splitlines()[0]
    assert first_line == "1: tcp 10.99.0.4/32:9200 -> tcp 127.0.0.1:18080", out

    # The reloaded rule must take effect without a VM restart.
    machine.succeed(probe_port("work", "10.99.0.4", 9200))
    out = machine.succeed("cat /tmp/socks5-conn.log")
    assert "CONNECT 10.99.0.4:9200" in out, "stub log was: " + repr(out)

    # `cogbox remap del 1` removes the .4:9200 rule we just inserted.
    # After reload, the probe must fail -- no remap, no listener.
    out = machine.succeed(as_user("cogbox remap del 1 --name work"))
    assert "Rules reloaded" in out, out
    machine.fail(probe_port("work", "10.99.0.4", 9200))

    stop_instance("cc-work", name="work")
    machine.succeed("systemctl stop socks5-stub")

with subtest("Phase K: L7 vhost filtering (passthrough tier)"):
    # The L7 layer funnels ALL guest 80/443 through the host-side proxy,
    # which allows only whitelisted vhosts (by TLS SNI / HTTP Host) and
    # re-resolves the name host-side. The decisive property: allowing
    # vhost-a does NOT grant a sibling vhost-b that shares the SAME IP.
    #
    # Guest and node are different machines, so we decouple resolution --
    # which IS the security story:
    #   - guest pins names to the origin IP with curl --resolve;
    #   - the node's /etc/hosts (networking.hosts in cogbox.nix) maps the
    #     vhosts to 203.0.113.5 for the proxy's host-side re-resolution.
    # 203.0.113.0/24 (TEST-NET-3) is NOT in the proxy's SSRF floor, so a
    # legit allow can reach it; evil-meta.test -> 169.254.169.254 must be
    # refused by that floor.

    # Throwaway self-signed cert for the origin (passthrough never validates
    # it; the guest uses curl -k). Combined cert+key in one PEM.
    machine.succeed(
        "openssl req -x509 -newkey rsa:2048 -keyout /tmp/origin.key "
        "-out /tmp/origin.crt -days 1 -nodes -subj '/CN=test-origin' "
        "-addext 'subjectAltName=DNS:vhost-a.test,DNS:vhost-b.test' 2>/dev/null "
        "&& cat /tmp/origin.crt /tmp/origin.key > /tmp/origin.pem"
    )
    machine.succeed("ip addr add 203.0.113.5/32 dev lo")

    # Origin: HTTPS on :443 + HTTP on :80, both bound to 203.0.113.5. Each
    # request's Host is appended to a hit log; the proxy only ever connects
    # here for an ALLOWED vhost, so the log is the ground truth for which
    # vhosts actually reached a backend.
    origin_script = r'''
import socket, ssl, threading
ORIGIN = "203.0.113.5"
HITLOG = "/tmp/origin-hits.log"
open(HITLOG, "w").close()
lock = threading.Lock()
def loghit(s):
    with lock:
        with open(HITLOG, "a") as f:
            f.write(s + "\n")
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tmp/origin.pem")
def respond(conn, scheme):
    data = conn.recv(8192).decode("latin1")
    first = data.split("\r\n")[0]
    parts = first.split(" ")
    path = parts[1] if len(parts) > 1 else "?"
    host = ""
    auth = ""
    for h in data.split("\r\n"):
        if h.lower().startswith("host:"):
            host = h.split(":", 1)[1].strip()
        elif h.lower().startswith("authorization:"):
            auth = h.split(":", 1)[1].strip()
    loghit("%s host=%s path=%s auth=%s" % (scheme, host, path, auth))
    body = ("ok %s host=%s path=%s auth=%s" % (scheme, host, path, auth)).encode()
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                 % (len(body), body))
def handle_tls(raw):
    try:
        c = ctx.wrap_socket(raw, server_side=True)
    except Exception:
        try: raw.close()
        except Exception: pass
        return
    try:
        respond(c, "TLS")
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass
def handle_http(c):
    try:
        respond(c, "HTTP")
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass
def serve(port, handler):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ORIGIN, port))
    s.listen(16)
    loghit("listen %d" % port)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()
threading.Thread(target=serve, args=(443, handle_tls), daemon=True).start()
serve(80, handle_http)
'''
    machine.succeed("cat > /tmp/l7-origin.py << 'PY_EOF'\n" + origin_script + "\nPY_EOF")
    machine.succeed("systemd-run --unit=l7-origin --collect python3 /tmp/l7-origin.py")
    machine.wait_until_succeeds("grep -q 'listen 443' /tmp/origin-hits.log", timeout=10)
    machine.wait_until_succeeds("grep -q 'listen 80' /tmp/origin-hits.log", timeout=10)

    # The origin IP is BLOCKED at L4 (TEST-NET deny + public catch-all). Under
    # the L7-composition model an L7 `allow` supersedes that block, so vhost-a
    # is reachable with NO L4 IP allow, while an unlisted sibling on the same
    # blocked IP is dropped. (Keeping the public catch-all also proves the SSRF
    # canary's metadata IP is stopped by the hard floor, not by an L4 deny.)
    machine.succeed(as_user(
        "printf 'deny 203.0.113.0/24\\nallow 0.0.0.0/0\\n' | cogbox rules set --name work"
    ))
    # Terminate is the DEFAULT tier now, so this phase (which exercises the
    # passthrough tier against a self-signed origin via `curl -k`) opts the
    # instance into passthrough explicitly. Bare allows are then SNI-only.
    machine.succeed(as_user("cogbox l7 mode passthrough --name work"))
    # Seed the L7 allowlist with vhost-a only (vhost-b is the sibling).
    machine.succeed(as_user("cogbox l7 add allow vhost-a.test --name work"))

    boot_and_wait("cc-work", "--name work", ssh_port=2223)

    # `work` is a NAMED instance, so it got an allocated per-instance L7 port
    # base (not the canonical 18443 the default keeps). Derive the expected
    # funnel ports from its config rather than hardcoding the allocation order.
    work_base = int(machine.succeed(
        "jq -r '.l7PortBase' /home/testuser/.config/cogbox/instances/work/config.json"
    ).strip())
    work_tls, work_http = work_base, work_base + 1
    assert work_base >= 18446, f"named instance should allocate above the default's 18443: {work_base}"

    nf = machine.succeed("cat /run/user/1000/cogbox-work/netfilter-rules")
    assert f"remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:{work_tls}" in nf, nf
    assert f"remap tcp 0.0.0.0/0:80 -> tcp 127.0.0.1:{work_http}" in nf, nf
    assert "deny udp 0.0.0.0/0:443" in nf, nf
    assert "deny tcp ::/0" in nf, nf
    l7r = machine.succeed("cat /run/user/1000/cogbox-work/l7-rules")
    assert "allow vhost-a.test" in l7r, l7r
    # The proxy must be running (its pidfile exists and the process is alive).
    machine.succeed("test -f /run/user/1000/cogbox-work/l7proxy.pid")
    machine.succeed("kill -0 $(cat /run/user/1000/cogbox-work/l7proxy.pid)")

    def gcurl(extra):
        cmd = "curl -k -s -o /dev/null -w '%{http_code}' --max-time 10 " + extra
        return machine.execute(as_user("cogbox ssh --name work " + shlex.quote(cmd)))

    # Allowed vhost over HTTPS -> 200, even though its IP is L4-blocked
    # (proves the L7 allow supersedes the L4 deny; re-resolved + spliced E2E).
    rc, out = gcurl("--resolve vhost-a.test:443:203.0.113.5 https://vhost-a.test/p1")
    assert rc == 0 and out.strip().endswith("200"), f"vhost-a https rc={rc} out={out!r}"
    # Same vhost over plaintext HTTP :80 -> 200.
    rc, out = gcurl("--resolve vhost-a.test:80:203.0.113.5 http://vhost-a.test/p1")
    assert rc == 0 and out.strip().endswith("200"), f"vhost-a http rc={rc} out={out!r}"

    # CORE PROPERTY: sibling vhost-b on the SAME IP is blocked. Dual proof:
    #  (1) the guest request fails, and
    #  (2) the origin never logs a hit for vhost-b (it never connected).
    rc, out = gcurl("--resolve vhost-b.test:443:203.0.113.5 https://vhost-b.test/")
    assert rc != 0, f"sibling vhost-b should be blocked, got rc={rc} out={out!r}"
    hits = machine.succeed("cat /tmp/origin-hits.log")
    assert "host=vhost-a.test" in hits, hits
    assert "vhost-b.test" not in hits, f"sibling reached origin! log={hits!r}"

    # Direct-IP / no-SNI HTTPS -> the no-SNI arm defers to L4; 203.0.113.0/24
    # is L4-denied above, so it drops (proxy logs no-sni-not-l4-allowed). The
    # drop comes from rawL4Allowed, NOT from classification: lifting that L4
    # deny would make this request succeed.
    wlog = "/run/user/1000/cogbox-work/cogbox.log"
    before = int(machine.succeed(f"wc -l < {wlog}").strip())
    rc, out = gcurl("https://203.0.113.5/")
    assert rc != 0, f"direct-IP no-SNI should be L4-dropped, got rc={rc}"
    machine.wait_until_succeeds(
        f"tail -n +{before + 1} {wlog} | grep -q no-sni-not-l4-allowed", timeout=10
    )
    new = machine.succeed(f"tail -n +{before + 1} {wlog}")
    assert "no-sni-not-l4-allowed" in new, f"no-SNI drop not attributed to the L4 gate: {new!r}"

    # SSRF canary: an allowed name that resolves (host-side) to the cloud
    # metadata IP MUST be refused by the proxy's non-overridable SSRF floor.
    # Without the post-resolution re-check this would connect.
    machine.succeed(as_user("cogbox l7 add allow evil-meta.test --name work"))
    rc, out = gcurl("--resolve evil-meta.test:443:169.254.169.254 https://evil-meta.test/")
    assert rc != 0, f"SSRF canary should be refused, got rc={rc} out={out!r}"

    # Hot reload + renderer-drift guard: adding vhost-b flips its
    # reachability WITHOUT a VM restart, and the funnel lines survive the
    # hot re-render of netfilter-rules.
    out = machine.succeed(as_user("cogbox l7 add allow vhost-b.test --name work"))
    assert "Rules reloaded" in out, out
    nf2 = machine.succeed("cat /run/user/1000/cogbox-work/netfilter-rules")
    assert f"remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:{work_tls}" in nf2, nf2
    rc, out = gcurl("--resolve vhost-b.test:443:203.0.113.5 https://vhost-b.test/")
    assert rc == 0 and out.strip().endswith("200"), f"vhost-b should now be allowed rc={rc} out={out!r}"

    # And deleting it blocks it again (proxy SIGHUP reload).
    # vhost-b is the last rule added; list to find its index.
    listing = machine.succeed(as_user("cogbox l7 list --name work"))
    idx = None
    for line in listing.splitlines():
        if "vhost-b.test" in line and ":" in line:
            idx = line.split(":", 1)[0].strip()
    assert idx is not None, listing
    out = machine.succeed(as_user(f"cogbox l7 del {idx} --name work"))
    assert "Rules reloaded" in out, out
    rc, out = gcurl("--resolve vhost-b.test:443:203.0.113.5 https://vhost-b.test/")
    assert rc != 0, f"vhost-b should be blocked again after del, rc={rc}"

    # ECH on the passthrough/splice tier is REFUSED: routing trusts the
    # cleartext SNI, so a real ECH could front a denied sibling. vhost-a is
    # still allowed (passthrough), but an ECH-bearing hello for it must be
    # dropped with the dedicated reason.
    wlog = "/run/user/1000/cogbox-work/cogbox.log"
    before = int(machine.succeed(f"wc -l < {wlog}").strip())
    out = machine.succeed(f"python3 /tmp/ech-hello.py {work_tls} 203.0.113.5 vhost-a.test 1")
    assert "socks-ok" in out, out
    machine.wait_until_succeeds(
        f"tail -n +{before + 1} {wlog} | grep -q ech-on-splice", timeout=10
    )
    new = machine.succeed(f"tail -n +{before + 1} {wlog}")
    assert "host=vhost-a.test" in new, new
    # A non-ECH hello for the same vhost is NOT refused for ECH (it proceeds to
    # the splice) -- proves the refusal keys on ECH, not on the host.
    before = int(machine.succeed(f"wc -l < {wlog}").strip())
    machine.succeed(f"python3 /tmp/ech-hello.py {work_tls} 203.0.113.5 vhost-a.test 0")
    machine.succeed("sleep 2")
    new = machine.succeed(f"tail -n +{before + 1} {wlog}")
    assert "ech-on-splice" not in new, new

    stop_instance("cc-work", name="work")
    machine.succeed("systemctl stop l7-origin")

with subtest("Phase L: L7 terminate tier (CA injection + Host/path enforcement)"):
    # Terminate tier: mitmproxy MITMs terminate-marked hosts with a
    # per-instance CA injected into the guest. We prove the in-guest
    # integration -- the guest TRUSTS the minted leaf (curl WITHOUT -k, via the
    # injected bundle) and the addon enforces Host==SNI + path. The addon's
    # deny/anti-fronting 403s short-circuit BEFORE any upstream connection, so
    # this stays hermetic (no trusted upstream needed); the allowed-path 200
    # against a real trusted upstream is covered by local tests. 203.0.113.5
    # has no listener here, so an allowed path yields mitmproxy's 502 -- still
    # over a trusted TLS connection, just not a cogbox 403.
    # Origin IP stays L4-BLOCKED; the terminate-host allow supersedes it just
    # like the passthrough tier (firstVettedAddr is gated only by the hard floor).
    machine.succeed(as_user(
        "printf 'deny 203.0.113.0/24\\nallow 0.0.0.0/0\\n' | cogbox rules set --name work"
    ))
    machine.succeed(as_user("printf '' | cogbox l7 set --name work"))  # clear Phase K rules
    machine.succeed(as_user("cogbox l7 add allow vhost-a.test --path /allowed/ --name work"))

    boot_and_wait("cc-work", "--name work", ssh_port=2223)
    rt = "/run/user/1000/cogbox-work"

    # The mitmproxy terminate backend is running.
    machine.succeed(f"test -f {rt}/l7mitm.pid && kill -0 $(cat {rt}/l7mitm.pid)")
    # netfilter-rules still funnels (terminate is a superset of L7 active).
    nf = machine.succeed(f"cat {rt}/netfilter-rules")
    assert f"remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:{work_tls}" in nf, nf
    # l7-rules carries the terminate marker.
    l7r = machine.succeed(f"cat {rt}/l7-rules")
    assert "allow vhost-a.test /allowed/" in l7r, l7r

    # CA CERT injected into the guest -- certificate present, key absent.
    machine.succeed(as_user("cogbox ssh --name work 'test -s /run/cogbox/l7-ca.crt'"))
    machine.succeed(as_user(
        "cogbox ssh --name work 'grep -q \"BEGIN CERTIFICATE\" /run/cogbox/l7-ca.crt'"
    ))
    machine.fail(as_user(
        "cogbox ssh --name work 'grep -q \"PRIVATE KEY\" /run/cogbox/l7-ca.crt'"
    ))
    # Trust bundle assembled (system store + instance CA).
    machine.succeed(as_user("cogbox ssh --name work 'test -s /run/cogbox/ca-bundle.crt'"))
    # CA also imported into root's NSS db, so NSS clients (Chromium/Playwright,
    # which ignore the CA env vars + bundle file) trust the terminate tier.
    nss = machine.succeed(as_user(
        "cogbox ssh --name work 'certutil -L -d sql:/root/.pki/nssdb'"
    ))
    assert "cogbox-l7-ca" in nss, f"per-instance CA not in root NSS db: {nss!r}"

    def gterm(extra):
        cmd = (
            "curl -sS -o /dev/null -w '%{http_code}' --max-time 12 "
            "--cacert /run/cogbox/ca-bundle.crt "
            "--resolve vhost-a.test:443:203.0.113.5 " + extra
        )
        return machine.execute(as_user("cogbox ssh --name work " + shlex.quote(cmd)))

    def gterm_body(extra):
        cmd = (
            "curl -sS --max-time 12 --cacert /run/cogbox/ca-bundle.crt "
            "--resolve vhost-a.test:443:203.0.113.5 " + extra
        )
        return machine.execute(as_user("cogbox ssh --name work " + shlex.quote(cmd)))

    # Denied path -> addon 403 over a TRUSTED TLS connection (no -k). rc==0
    # proves the guest validated the minted leaf via the injected CA; the body
    # identifies cogbox (not an upstream 403).
    rc, code = gterm("https://vhost-a.test/denied")
    assert rc == 0 and code.strip().endswith("403"), f"path-deny rc={rc} code={code!r}"
    _, body = gterm_body("https://vhost-a.test/denied")
    assert "cogbox-l7" in body, body

    # Allowed path -> addon passes (upstream absent -> 502), NOT a cogbox 403.
    _, body = gterm_body("https://vhost-a.test/allowed/x")
    assert "cogbox-l7" not in body, f"allowed path should pass the addon: {body!r}"

    # Host==SNI anti-fronting: SNI=vhost-a.test, inner Host=vhost-b.test -> 403.
    rc, code = gterm("-H 'Host: vhost-b.test' https://vhost-a.test/allowed/")
    assert rc == 0 and code.strip().endswith("403"), f"anti-fronting rc={rc} code={code!r}"

    # Negative-CA control: the minted leaf must NOT validate against the system
    # store alone -- proving trust came from the injected instance CA, not -k.
    rc, _ = machine.execute(as_user("cogbox ssh --name work " + shlex.quote(
        "curl -sS -o /dev/null --max-time 12 "
        "--cacert /etc/ssl/certs/ca-certificates.crt "
        "--resolve vhost-a.test:443:203.0.113.5 https://vhost-a.test/allowed/"
    )))
    assert rc != 0, "minted leaf must not validate against the system store alone"

    # ECH on the terminate tier is ACCEPTED: mitmproxy is the TLS endpoint and
    # its addon re-checks Host==SNI on the decrypted request, so ECH can't
    # smuggle a different host. The proxy must classify the cleartext SNI and
    # enter the terminate handoff -- NOT reject it as unclassifiable (the bug
    # this fix addresses) nor as ech-on-splice (that's the passthrough tier).
    # This is what unblocks Chrome's default GREASE ECH against a terminate vhost.
    wlog = "/run/user/1000/cogbox-work/cogbox.log"
    before = int(machine.succeed(f"wc -l < {wlog}").strip())
    out = machine.succeed(f"python3 /tmp/ech-hello.py {work_tls} 203.0.113.5 vhost-a.test 1")
    assert "socks-ok" in out, out
    machine.succeed("sleep 2")
    new = machine.succeed(f"tail -n +{before + 1} {wlog}")
    assert "unclassifiable-or-no-sni" not in new, f"ECH hello wrongly rejected at SNI peek: {new!r}"
    assert "ech-on-splice" not in new, f"terminate vhost wrongly refused ECH: {new!r}"

    stop_instance("cc-work", name="work")

with subtest("Phase M: terminate-by-default + --passthrough + --insecure-upstream"):
    # Terminate is the DEFAULT tier. Against ONE self-signed origin we prove the
    # three behaviors: (A) a bare allow is MITM'd -> 502 (upstream verify fails);
    # (B) --passthrough opts back out -> end-to-end TLS, curl -k reaches it (200);
    # (C) --insecure-upstream stays terminate but skips upstream verify -> 200.
    machine.succeed("systemctl reset-failed l7-origin 2>/dev/null || true")
    machine.succeed("systemd-run --unit=l7-origin --collect python3 /tmp/l7-origin.py")
    machine.wait_until_succeeds("grep -q 'listen 443' /tmp/origin-hits.log", timeout=10)

    # Undo Phase K's `mode passthrough` so the DEFAULT tier (terminate) applies.
    machine.succeed(as_user("cogbox l7 mode terminate --name work"))
    rt = "/run/user/1000/cogbox-work"
    code_probe = (
        "curl -sS -o /dev/null -w '%{http_code}' --max-time 12 "
        "--cacert /run/cogbox/ca-bundle.crt "
        "--resolve vhost-a.test:443:203.0.113.5 https://vhost-a.test/"
    )

    # A) terminate by DEFAULT, enabled HOT: boot with ZERO L7 rules, then add
    #    a bare allow on the LIVE instance. The terminate backend + CA staging
    #    must not depend on boot-time rule presence -- the regression was an
    #    instance booted before its first `l7 add` handing TLS to a backend
    #    that was never started (fail-closed EOF mid-handshake). The hot-added
    #    bare allow is then MITM'd, so the self-signed upstream is rejected
    #    (verify on) -> 502 over a TRUSTED client TLS leg.
    machine.succeed(as_user("printf '' | cogbox l7 set --name work"))
    boot_and_wait("cc-work", "--name work", ssh_port=2223)
    # No launch flags here: neither Phase D's work grant nor Phase E's
    # edited-runner grant may survive into this fresh work VM.
    machine.succeed(as_user(
        "cogbox ssh --name work " + shlex.quote(
            f"test ! -e {shlex.quote(rw_host_dir)} && "
            f"test ! -e {shlex.quote(ro_host_dir)}"
        )
    ))
    # Backend up + CA injected even though the instance booted with no rules.
    machine.succeed(f"test -f {rt}/l7mitm.pid && kill -0 $(cat {rt}/l7mitm.pid)")
    machine.succeed(as_user("cogbox ssh --name work 'test -s /run/cogbox/l7-ca.crt'"))
    machine.succeed(as_user("cogbox l7 add allow vhost-a.test --name work"))
    l7r = machine.succeed(f"cat {rt}/l7-rules")
    assert "mode terminate" in l7r and "allow vhost-a.test\n" in l7r, l7r  # bare, no token
    machine.wait_until_succeeds(
        as_user("cogbox ssh --name work " + shlex.quote(code_probe + " | grep -q 502")),
        timeout=20,
    )

    # B) --passthrough opts the host back out: TLS is end-to-end to the
    #    (self-signed) origin, so curl -k reaches it (200) and it's NOT MITM'd.
    machine.succeed(as_user("printf '' | cogbox l7 set --name work"))
    machine.succeed(as_user("cogbox l7 add allow vhost-a.test --passthrough --name work"))
    l7r = machine.succeed(f"cat {rt}/l7-rules")
    assert "allow vhost-a.test passthrough" in l7r, l7r
    pt_probe = (
        "curl -sS -o /dev/null -w '%{http_code}' --max-time 12 -k "
        "--resolve vhost-a.test:443:203.0.113.5 https://vhost-a.test/"
    )
    machine.wait_until_succeeds(
        as_user("cogbox ssh --name work " + shlex.quote(pt_probe + " | grep -q 200")),
        timeout=20,
    )

    # C) --insecure-upstream: still terminate, but skip upstream verify -> 200
    #    over the trusted bundle (no -k), reaching the origin.
    machine.succeed(as_user("printf '' | cogbox l7 set --name work"))
    machine.succeed(as_user("cogbox l7 add allow vhost-a.test --insecure-upstream --name work"))
    l7r = machine.succeed(f"cat {rt}/l7-rules")
    assert "allow vhost-a.test terminate insecure" in l7r, l7r
    machine.wait_until_succeeds(
        as_user("cogbox ssh --name work " + shlex.quote(code_probe + " | grep -q 200")),
        timeout=20,
    )
    machine.succeed("grep -q 'host=vhost-a.test' /tmp/origin-hits.log")

    stop_instance("cc-work", name="work")
    machine.succeed("systemctl stop l7-origin")

with subtest("Phase R: L7 host-side credential injection keeps the token out of the guest"):
    # Inject mode: a harness's request to a terminate host has its auth header
    # REPLACED host-side (in the mitmproxy addon, after decryption) with the real
    # token read off the host FS, so the guest only ever carries a stub. Proven
    # end-to-end: the guest sends a PLACEHOLDER bearer; the origin -- reached only
    # because mitmproxy forwards the decrypted, rewritten request (terminate +
    # --insecure-upstream) -- must observe the REAL token and never the
    # placeholder. The real token lives only in a host-side file the guest VM
    # cannot read (it is not on any 9p share, fw_cfg slot, or env that crosses in).
    machine.succeed("systemctl reset-failed l7-origin 2>/dev/null || true")
    machine.succeed("systemd-run --unit=l7-origin --collect python3 /tmp/l7-origin.py")
    machine.wait_until_succeeds("grep -q 'listen 443' /tmp/origin-hits.log", timeout=10)

    # Host-side secret: a stand-in cred file holding the REAL token, 0600, owned
    # by the launching user. The mitmdump addon reads it host-side; it is NEVER
    # shared into the guest.
    real_token = "REAL-OAT-do-not-leak-7f3a"
    machine.succeed(as_user(
        "printf '%s' '{\"claudeAiOauth\":{\"accessToken\":\"" + real_token + "\"}}' "
        "> /home/testuser/host-creds.json && chmod 600 /home/testuser/host-creds.json"
    ))
    # Inject-conf maps the terminate vhost -> that host cred file + token path.
    # Lives host-side only (never $RUNTIME, never 9p-shared). `bearer` style sets
    # a plain `Authorization: Bearer <token>`.
    inject_conf = "/home/testuser/l7-inject.json"
    machine.succeed(as_user(
        "printf '%s' "
        "'[{\"host\":\"vhost-a.test\",\"style\":\"bearer\","
        "\"cred_file\":\"/home/testuser/host-creds.json\","
        "\"token_path\":\"claudeAiOauth.accessToken\"}]' > " + inject_conf
    ))

    # Terminate + insecure-upstream so the rewritten request actually reaches the
    # self-signed origin (mitmproxy is the TLS endpoint; the addon injects).
    machine.succeed(as_user("printf '' | cogbox l7 set --name work"))
    machine.succeed(as_user(
        "cogbox l7 add allow vhost-a.test --insecure-upstream --name work"
    ))

    # Boot with injection enabled. v0 is env-driven (COGBOX_L7_INJECT_CONF);
    # the daemon is setsid'd but inherits this env. (The config-driven, default-on
    # path lands in a later phase.)
    machine.succeed(as_user(
        f"COGBOX_L7_INJECT_CONF={inject_conf} cogbox start --no-ssh --name work"
    ))
    machine.wait_until_succeeds(
        as_user(f"ssh {SSH_OPTS} -p 2223 root@127.0.0.1 true"), timeout=600,
    )
    # The addon actually loaded the inject-conf (passed through start_l7mitm).
    machine.succeed(
        "grep -qa '/home/testuser/l7-inject.json' /proc/$(cat "
        "/run/user/1000/cogbox-work/l7mitm.pid)/environ"
    )

    # The guest sends a PLACEHOLDER bearer; injection must overwrite it before
    # the request leaves the host. The origin echoes the auth it received.
    placeholder = "PLACEHOLDER-guest-token"
    body_cmd = (
        "curl -sS --max-time 12 --cacert /run/cogbox/ca-bundle.crt "
        "--resolve vhost-a.test:443:203.0.113.5 "
        "-H 'Authorization: Bearer " + placeholder + "' https://vhost-a.test/"
    )
    machine.wait_until_succeeds(
        as_user("cogbox ssh --name work " + shlex.quote(
            body_cmd + " | grep -q 'auth=Bearer " + real_token + "'")),
        timeout=20,
    )
    # Ground truth at the origin: it saw the REAL token, NEVER the placeholder.
    hits = machine.succeed("cat /tmp/origin-hits.log")
    assert ("auth=Bearer " + real_token) in hits, f"injected token missing at origin: {hits!r}"
    assert placeholder not in hits, f"guest placeholder leaked upstream: {hits!r}"

    # Same injection over PLAIN HTTP. A plain http:// inject host used to bypass
    # the addon entirely (the Zig proxy native-spliced it), so its credential was
    # never stamped -- HTTPS-only injection. The proxy now routes an inject host's
    # HTTP egress through the terminate backend too (driven by the l7-inject-hosts
    # list it derives from this same inject-conf), so the cred is injected on the
    # cleartext leg as well. No CA needed (no TLS to the guest).
    http_cmd = (
        "curl -sS --max-time 12 "
        "--resolve vhost-a.test:80:203.0.113.5 "
        "-H 'Authorization: Bearer " + placeholder + "' http://vhost-a.test/"
    )
    machine.wait_until_succeeds(
        as_user("cogbox ssh --name work " + shlex.quote(
            http_cmd + " | grep -q 'auth=Bearer " + real_token + "'")),
        timeout=20,
    )
    # The origin logged a plain-HTTP request carrying the REAL token (the origin
    # tags the cleartext listener "HTTP"), confirming the cleartext leg was
    # injected, not bypassed.
    hits = machine.succeed("cat /tmp/origin-hits.log")
    assert ("HTTP host=vhost-a.test path=/ auth=Bearer " + real_token) in hits, \
        f"http injection missing at origin: {hits!r}"
    assert placeholder not in hits, f"guest placeholder leaked upstream (http): {hits!r}"

    # The real token never crossed into the guest: it is in no guest-readable
    # mount, the inject-conf and cred file are host-only.
    rc_leak, _ = machine.execute(as_user(
        "cogbox ssh --name work " + shlex.quote(
            "grep -rqsI '" + real_token + "' /root /etc /var/lib /run/cogbox")))
    assert rc_leak != 0, "real token must not be present anywhere in the guest"

    stop_instance("cc-work", name="work")
    machine.succeed("systemctl stop l7-origin")

with subtest("Phase S: cred-inject default-on (init seeding + auto conf + token redaction)"):
    # A new rules-mode instance with an active harness seeds .network.l7 with a
    # terminate rule for the harness's provider host AND inject:true, and the
    # launcher auto-generates the inject-conf from the host cred file -- no env
    # var, no hand-written conf. We prove the seeding survives an l7 edit, the
    # generated conf maps host->cred-file, the config-driven path injects
    # end-to-end (anthropic-oauth) against the hermetic origin, AND (v1b) the
    # real token is EVICTED from the guest overlay while the rest of the config
    # dir is preserved, with the launcher presenting a placeholder identity.
    machine.succeed("systemctl reset-failed l7-origin 2>/dev/null || true")
    machine.succeed("systemd-run --unit=l7-origin --collect python3 /tmp/l7-origin.py")
    machine.wait_until_succeeds("grep -q 'listen 443' /tmp/origin-hits.log", timeout=10)

    # Make claude-code an ACTIVE harness for testuser, with a fake on-disk token
    # plus a NON-secret marker file (settings.json) to prove redaction is surgical.
    fake_tok = "FAKE-CRED-TOKEN-s9k2"
    machine.succeed(as_user("mkdir -p /home/testuser/.claude"))
    machine.succeed(as_user(
        "printf '%s' '{\"claudeAiOauth\":{\"accessToken\":\"" + fake_tok + "\"}}' "
        "> /home/testuser/.claude/.credentials.json"
    ))
    machine.succeed(as_user(
        "printf '%s' '{\"marker\":\"keep-me\"}' > /home/testuser/.claude/settings.json"
    ))

    # Fresh rules-mode instance -> default-on seeding kicks in.
    machine.succeed(as_user("cogbox init -y --name injauto --network rules"))
    icfg = "/home/testuser/.config/cogbox/instances/injauto/config.json"
    assert machine.succeed(f"jq -r '.network.l7.inject' {icfg}").strip() == "true", \
        machine.succeed(f"cat {icfg}")
    seeded = machine.succeed(
        f"jq -r '.network.l7.rules[] | select(.allow==\"api.anthropic.com\") | .terminate' {icfg}"
    ).strip()
    assert seeded == "true", f"api.anthropic.com not seeded terminate: {machine.succeed(f'cat {icfg}')}"

    # Point the seeded host at the hermetic self-signed origin: keep terminate +
    # inject, add insecure-upstream so the rewritten request reaches it. l7
    # set/add must PRESERVE the sibling .network.l7.inject flag.
    machine.succeed(as_user("printf '' | cogbox l7 set --name injauto"))
    machine.succeed(as_user("cogbox l7 add allow api.anthropic.com --insecure-upstream --name injauto"))
    assert machine.succeed(f"jq -r '.network.l7.inject' {icfg}").strip() == "true", \
        "l7 edit dropped the .network.l7.inject flag"

    iport = int(machine.succeed(f"jq -r '.sshPort' {icfg}").strip())
    boot_and_wait("cc-injauto", "--name injauto", ssh_port=iport)
    irt = "/run/user/1000/cogbox-injauto"

    # Auto-generated inject-conf (no env var) maps the provider host -> the host
    # cred file with the right style.
    machine.succeed(
        "jq -e '.[] | select(.host==\"api.anthropic.com\") "
        "| select(.style==\"anthropic-oauth\") "
        f"| select(.cred_file==\"/home/testuser/.claude/.credentials.json\")' {irt}/l7-inject-conf.json"
    )

    # token REDACTION: with inject active, the harness's secret file is PRESENT
    # in the guest but rewritten -- the real token replaced by the recognizable
    # stub, non-secret fields kept -- so the guest holds a logged-in placeholder
    # identity (the addon injects the real token over the stub on the wire) while
    # the real token NEVER enters the VM. A present, scoped file is what lets
    # /remote-control work and lets an in-guest /login write its OWN token on top.
    stub = "sk-ant-oat01-cogbox-host-injected-placeholder"
    machine.succeed(as_user(
        "cogbox ssh --name injauto 'test -e /root/.claude/.credentials.json'"))
    machine.succeed(as_user("cogbox ssh --name injauto " + shlex.quote(
        f"jq -e '.claudeAiOauth.accessToken==\"{stub}\"' /root/.claude/.credentials.json")))
    # The real token must NOT be anywhere in the guest cred dir.
    machine.fail(as_user("cogbox ssh --name injauto " + shlex.quote(
        f"grep -rq {fake_tok} /root/.claude/")))
    machine.succeed(as_user(
        "cogbox ssh --name injauto 'test -e /root/.claude/settings.json'"))
    # No ANTHROPIC_AUTH_TOKEN env stub: it would shadow the on-disk file (break
    # /rc and in-guest login). The guest relies on the present redacted file.
    # Match the ASSIGNMENT: the launcher's connect hint only READS the variable
    # (`${ANTHROPIC_AUTH_TOKEN-}`) to stay silent for env-authenticated runs.
    machine.fail(as_user("cogbox ssh --name injauto " + shlex.quote(
        'grep -q ANTHROPIC_AUTH_TOKEN= "$(command -v c)"')))
    # The host-side mirror exists under the cogbox data root (host-only, NOT in
    # the guest-shared instances/<name>/ dir) and holds the REDACTED file (stub,
    # not the real token); the non-secret marker is preserved.
    mirror = "/home/testuser/.local/share/cogbox/mirrors/injauto/claude-code-config"
    machine.succeed(as_user(
        f"jq -e '.claudeAiOauth.accessToken==\"{stub}\"' {mirror}/.credentials.json"))
    machine.fail(as_user(f"grep -q {fake_tok} {mirror}/.credentials.json"))
    machine.succeed(as_user(f"test -e {mirror}/settings.json"))

    # Config-driven injection end-to-end, with the token now redacted in the
    # guest: guest sends the stub Bearer; the addon overwrites it with the real
    # host-side token (anthropic-oauth). Origin echoes the Authorization.
    # The guest MUST present its stubbed primary identity (the placeholder the
    # launcher redacted into its cred file): the auto-generated inject-conf carries
    # a stub_token, so should_inject only re-stamps a request bearing the stub (or
    # no credential) -- any other bearer is treated as a legitimate secondary
    # credential and passed through. An arbitrary Bearer would (correctly) NOT be
    # injected, so this check must send the stub, matching what the harness does.
    machine.wait_until_succeeds(
        as_user("cogbox ssh --name injauto " + shlex.quote(
            "curl -sS --max-time 12 --cacert /run/cogbox/ca-bundle.crt "
            "--resolve api.anthropic.com:443:203.0.113.5 "
            "-H 'Authorization: Bearer " + stub + "' -H 'x-api-key: guest-key' "  # gitleaks:allow
            "https://api.anthropic.com/v1/x | grep -q 'auth=Bearer " + fake_tok + "'")),
        timeout=20,
    )
    hits = machine.succeed("cat /tmp/origin-hits.log")
    assert ("auth=Bearer " + fake_tok) in hits, f"config-driven injection failed: {hits!r}"

    stop_instance("cc-injauto", name="injauto")
    machine.succeed("systemctl stop l7-origin")
    # Clean up so later inits (Phase N) don't treat claude-code as active.
    machine.succeed(as_user(
        "rm -rf /home/testuser/.claude /home/testuser/.claude.json "
        "/home/testuser/.config/cogbox/instances/injauto "
        "/home/testuser/.local/share/cogbox/instances/injauto "
        "/home/testuser/.local/share/cogbox/mirrors/injauto"
    ))

with subtest("Phase AP: per-sandbox auth proxy end-to-end (funnel -> addon retarget -> authproxy -> upstream, and fail-closed)"):
    # The migrated-provider path: a git host bound under the NEW kind
    # (gitlab-authproxy) and delivered a policy DOCUMENT (`cogbox l7 policy`)
    # takes the fourth trusted-half process instead of addon injection. The
    # decisive property proven end to end: the guest holds NO credential, the
    # mitmproxy addon RETARGETS the flow to 127.0.0.1:<auth-port> (never
    # injecting), and the auth proxy authenticates the request itself so the
    # origin observes the REAL owner token -- and if the auth proxy is dead, the
    # request FAILS CLOSED with no credential upstream.
    #
    # Reuses the Phase-K/R hermetic origin on 203.0.113.5 (mapped from
    # vhost-a.test by the node's /etc/hosts, so the proxy re-resolves it
    # host-side). The origin's TLS listener echoes the Authorization it received.
    machine.succeed("systemctl reset-failed l7-origin 2>/dev/null || true")
    machine.succeed("systemd-run --unit=l7-origin --collect python3 /tmp/l7-origin.py")
    machine.wait_until_succeeds("grep -q 'listen 443' /tmp/origin-hits.log", timeout=10)

    apx_host = "vhost-a.test"
    apx_token = "glpat-AUTHPROXY-REAL-do-not-leak-2c9f"  # fictional owner token (OSS-clean)

    # Fresh rules-mode instance for the migrated provider.
    machine.succeed(as_user("cogbox init -y --name apx --network rules"))
    apx_cfg = "/home/testuser/.config/cogbox/instances/apx/config.json"

    # 1) BIND the owner token under the NEW kind. An OLD binary would refuse this
    #    with exit 65 (validKind) -- the rollout's version gate -- so the bind
    #    succeeding is itself proof the image carries the auth-proxy support.
    machine.succeed(as_user(
        "printf '%s' " + shlex.quote(apx_token) +
        " | cogbox secret add git-gitlab --kind gitlab-authproxy "
        "--audience " + apx_host + " --name apx --from-stdin"
    ))

    # 2) The funnel rule: `allow <host> --path /` (the `--path /` is load-bearing
    #    -- it forces terminate so the addon runs on a passthrough-mode instance)
    #    plus --insecure-upstream so the auth proxy's TLS leg reaches the origin's
    #    self-signed cert (propagated into the auth conf's `insecure` per N2).
    machine.succeed(as_user("printf '' | cogbox l7 set --name apx"))
    machine.succeed(as_user(
        "cogbox l7 add allow " + apx_host + " --path / --insecure-upstream "
        "--plugin git-grants --name apx"
    ))

    # 3) DELIVER the policy document. `cogbox l7 policy --from-stdin` validates it
    #    (an unknown version / malformed doc is refused BEFORE any write) and sets
    #    .network.l7.authpolicy. One provider entry: the gitlab plugin, scheme
    #    https, an instance-scope grant carrying `issues` (which authorizes the
    #    ambient /api/v4/user route).
    apx_doc = (
        '{"version":1,"providers":[{'
        '"provider":"GitLab","plugin":"gitlab","hosts":["' + apx_host + '"],'
        '"secret":"git-gitlab","git_user":"oauth2","scheme":"https",'
        '"grants":[{"id":"gg-apx","scope":"instance","caps":["git-read","issues"]}]}]}'
    )
    machine.succeed(as_user(
        "printf '%s' " + shlex.quote(apx_doc) + " | cogbox l7 policy --from-stdin --name apx"
    ))
    # The document landed in config.json under the contract key.
    machine.succeed(f"jq -e '.network.l7.authpolicy.version==1' {apx_cfg}")
    machine.succeed(
        f"jq -e '.network.l7.authpolicy.providers[0].hosts[0]==\"{apx_host}\"' {apx_cfg}")

    aport = int(machine.succeed(f"jq -r '.sshPort' {apx_cfg}").strip())
    boot_and_wait("cc-apx", "--name apx", ssh_port=aport)
    art = "/run/user/1000/cogbox-apx"

    # The render wrote all four wire files. The auth conf names the host + its
    # cred file, and l7-auth-hosts (the retarget set) carries the host.
    machine.succeed(
        f"jq -e '.providers[] | select(.host==\"{apx_host}\") "
        f"| select(.plugin==\"gitlab\") | select(.insecure==true)' {art}/l7-auth-conf.json")
    machine.succeed(f"grep -qx '{apx_host}' {art}/l7-auth-hosts")
    # Finding N1: the host is ALSO in the plain-HTTP routing list, even though no
    # inject SPEC was seeded for it (the new kind seeds none).
    machine.succeed(f"grep -qx '{apx_host}' {art}/l7-inject-hosts")
    # The auth proxy is up and wrote its pid INTO the pid file. `-s`, not `-f`:
    # the launcher pre-creates the file EMPTY (so a runas uid can write into a
    # root-owned runtime dir on GCE); only the Zig side fills it, after bind +
    # first conf parse, so non-empty is the health signal, existence is not.
    machine.succeed(f"test -s {art}/authproxy.pid")
    machine.succeed(f"kill -0 $(cat {art}/authproxy.pid)")
    # NO inject spec for this host: the mitm addon must never double-stamp it.
    machine.fail(
        f"jq -e '.[] | select(.host==\"{apx_host}\")' {art}/l7-inject-conf.json")

    # END TO END: the guest presents NO credential. The request funnels to the
    # proxy, mitmproxy terminates + retargets to the auth proxy, which stamps the
    # owner token; the origin observes it. (The api-user route takes a Bearer.)
    apx_curl = (
        "curl -sS --max-time 12 --cacert /run/cogbox/ca-bundle.crt "
        "--resolve " + apx_host + ":443:203.0.113.5 "
        "https://" + apx_host + "/api/v4/user"
    )
    machine.wait_until_succeeds(
        as_user("cogbox ssh --name apx " + shlex.quote(
            apx_curl + " | grep -q 'auth=Bearer " + apx_token + "'")),
        timeout=30,
    )
    hits = machine.succeed("cat /tmp/origin-hits.log")
    assert ("auth=Bearer " + apx_token) in hits, \
        f"auth proxy did not stamp the owner token at the origin: {hits!r}"

    # The token never crossed into the guest: no cred file, no env, nowhere.
    rc_leak, _ = machine.execute(as_user(
        "cogbox ssh --name apx " + shlex.quote(
            "grep -rqsI '" + apx_token + "' /root /etc /var/lib /run/cogbox")))
    assert rc_leak != 0, "the owner token must not be present anywhere in the guest"

    # FAIL CLOSED: kill the auth proxy, then a request to the migrated host must
    # FAIL (mitmproxy's retarget to the dead loopback port cannot connect) and
    # the origin must observe NO new token. Snapshot the hit count first.
    before = machine.succeed("wc -l < /tmp/origin-hits.log").strip()
    machine.succeed(f"kill $(cat {art}/authproxy.pid)")
    # An unusable auth hop yields a proxy error, not a 200 with a token upstream.
    rc_dead, _ = machine.execute(as_user(
        "cogbox ssh --name apx " + shlex.quote(
            apx_curl + " -o /dev/null -w '%{http_code}' | grep -q '^200$'")))
    assert rc_dead != 0, "a request with the auth proxy dead must not succeed with a 200"
    after = machine.succeed("wc -l < /tmp/origin-hits.log").strip()
    # The origin logs a line only when it is actually reached WITH a request; a
    # fail-closed retarget never reaches it carrying the credential.
    hits2 = machine.succeed("cat /tmp/origin-hits.log")
    assert ("auth=Bearer " + apx_token) not in hits2.split("\n")[int(before):], \
        f"the owner token reached the origin AFTER the auth proxy died: {hits2!r}"
    _ = after

    stop_instance("cc-apx", name="apx")
    machine.succeed("systemctl stop l7-origin")
    machine.succeed(as_user(
        "rm -rf /home/testuser/.config/cogbox/instances/apx "
        "/home/testuser/.local/share/cogbox/instances/apx"
    ))

with subtest("Phase N: per-instance L7 ports (isolation + fail-closed bind)"):
    # The cross-instance bleed bug: with a single shared port, instance B's
    # funnel pointed at instance A's proxy. Per-instance ports fix it. We prove
    # the two mechanisms directly -- no second guest VM needed (the node only
    # has 8G; the funnel->proxy->policy path is already covered by Phase K):
    #   (1) the RENDERER targets each instance's own allocated base, and
    #   (2) the PROXY binds per-instance ports and FAILS CLOSED on a conflict.

    # (1) A second L7 instance renders its funnel to its OWN base, never the
    # default's 18443 nor work's base.
    machine.succeed(as_user("cogbox init -y --name work2 --network rules"))
    machine.succeed(as_user("cogbox l7 add allow vhost-b.test --name work2"))
    w2cfg = "/home/testuser/.config/cogbox/instances/work2/config.json"
    w2_base = int(machine.succeed(f"jq -r '.l7PortBase' {w2cfg}").strip())
    assert w2_base >= 18446 and w2_base != work_base, \
        f"work2 base {w2_base} must be distinct + allocated (work={work_base})"
    # Runtime dir must be owned by testuser -- the renderer runs as_user and
    # writes netfilter-rules into it.
    machine.succeed(as_user("mkdir -p /run/user/1000/cogbox-work2"))
    machine.succeed(as_user(f"cogbox __render-rules {w2cfg} /run/user/1000/cogbox-work2"))
    nf2 = machine.succeed("cat /run/user/1000/cogbox-work2/netfilter-rules")
    assert f"127.0.0.1:{w2_base}" in nf2, nf2
    assert "127.0.0.1:18443" not in nf2 and f"127.0.0.1:{work_base}" not in nf2, \
        f"work2 funnel must not target the default's or work's port: {nf2!r}"

    # (2) The L7 proxy is a host binary that binds base/base+1. Two proxies on
    # DISTINCT bases coexist; a third on a TAKEN base fails closed (the old bug
    # would silently share the port and bleed policy across instances).
    machine.succeed(as_user("mkdir -p /tmp/pna /tmp/pnb /tmp/pnc"))
    a, b = 19443, 19446
    pa = machine.succeed(as_user(
        f"setsid cogbox __l7proxy /tmp/pna {a} >/tmp/pna.log 2>&1 & echo $!")).strip()
    pb = machine.succeed(as_user(
        f"setsid cogbox __l7proxy /tmp/pnb {b} >/tmp/pnb.log 2>&1 & echo $!")).strip()
    machine.wait_until_succeeds(f"ss -tln | grep -q '127.0.0.1:{a} '", timeout=10)
    machine.wait_until_succeeds(f"ss -tln | grep -q '127.0.0.1:{b} '", timeout=10)
    # both HTTP listeners (base+1) up too
    machine.succeed(f"ss -tln | grep -q '127.0.0.1:{a + 1} '")
    machine.succeed(f"ss -tln | grep -q '127.0.0.1:{b + 1} '")
    # A third proxy on a taken base must exit non-zero (fail-closed bind).
    rc, _ = machine.execute(as_user(f"cogbox __l7proxy /tmp/pnc {a}"))
    assert rc != 0, "proxy on a taken port must fail closed, not silently share it"
    machine.succeed(f"kill {pa} {pb} 2>/dev/null || true")

with subtest("Phase G: CLI parser regressions and stub-friendly verbs"):
    # cogbox writes errors to stderr; the test driver's machine.execute()
    # captures only stdout, so we redirect 2>&1 to assert on the message
    # text. Exit codes are still distinct (sysexits values).
    def run_cli(cmd):
        return machine.execute(as_user(cmd + " 2>&1"))

    # G1: status of a not-running default instance -> exit 3, prints "stopped"
    rc, out = run_cli("cogbox status")
    assert rc == 3, f"expected exit 3 (stopped), got {rc}; out={out!r}"
    assert "stopped" in out, out

    # G2: --list and --init-only are removed; both must exit 64 with a
    # redirect-style error message.
    rc, out = run_cli("cogbox --list")
    assert rc == 64, f"expected exit 64, got {rc}; out={out!r}"
    assert "use 'cogbox list'" in out, out
    rc, out = run_cli("cogbox --init-only")
    assert rc == 64, f"expected exit 64, got {rc}; out={out!r}"
    assert "use 'cogbox init'" in out, out

    # G2b: the `run` verb was removed in favor of background-by-default + -f.
    rc, out = run_cli("cogbox run")
    assert rc == 64, f"expected exit 64 for removed 'run', got {rc}; out={out!r}"
    assert "was removed" in out and "-f" in out, out

    # G2c: console/monitor exist as verbs and accept --help (exit 0).
    rc, out = run_cli("cogbox console --help")
    assert rc == 0 and "detach" in out.lower(), out
    rc, out = run_cli("cogbox monitor --help")
    assert rc == 0 and "monitor" in out.lower(), out

    # G3: parser bug -- `--name --vcpu 8` must NOT swallow `--vcpu` as the
    # name. Old bash parser bug; new parser exits 64 with "requires a value".
    rc, out = run_cli("cogbox start --name --vcpu 8")
    assert rc == 64, f"expected exit 64, got {rc}; out={out!r}"
    assert "requires a value" in out, out

    # G4: integer validation on --vcpu; must reject non-numeric with 65.
    rc, out = run_cli("cogbox start --vcpu abc")
    assert rc == 65, f"expected exit 65, got {rc}; out={out!r}"
    assert "positive integer" in out, out

    # G4b: launch-only directory validation runs before foreground init or
    # daemonization while every selected instance is stopped.
    missing_add_dir = "/home/testuser/does-not-exist-add-dir"
    rc, out = run_cli(f"cogbox start --add-dir {missing_add_dir}")
    assert rc == 66, f"expected exit 66 for missing add-dir, got {rc}; out={out!r}"
    assert missing_add_dir in out and "missing or inaccessible" in out, out

    not_a_dir = "/home/testuser/not-a-directory-add-dir"
    machine.succeed(as_user(f"printf fixture > {not_a_dir}"))
    rc, out = run_cli(f"cogbox start --add-dir-ro {not_a_dir}")
    assert rc == 65, f"expected exit 65 for non-directory add-dir, got {rc}; out={out!r}"
    assert not_a_dir in out and "requires a directory" in out, out

    rc, out = run_cli("cogbox init --add-dir /tmp")
    assert rc == 64, f"expected exit 64 for init-only add-dir, got {rc}; out={out!r}"
    assert "unknown flag --add-dir" in out, out

    # G5: unknown flag for a verb -- per-verb scoping, not silent passthrough.
    rc, out = run_cli("cogbox rules list --vcpu 8 --name work")
    assert rc != 0, f"expected nonzero, got {rc}; out={out!r}"

    # G6: list --json emits parseable JSON with one entry per instance
    out = machine.succeed(as_user("cogbox list --json"))
    import json as _json
    parsed = _json.loads(out)
    assert isinstance(parsed, list) and len(parsed) >= 2, parsed
    names = {e["name"] for e in parsed}
    assert "default" in names and "work" in names, names

with subtest("Phase J: bare `cogbox start` waits for sshd then auto-SSHes in"):
    # The new default: daemonize, poll the forwarded SSH port until sshd sends
    # its banner, then exec ssh into the guest. With a non-tty stdin the remote
    # shell reads piped input, so feeding it a command and capturing the output
    # proves the readiness wait + auto-connect work end to end -- in particular
    # that we don't exec ssh before sshd is actually accepting connections.
    # (The foreground init step also prints "Init complete." to stdout, so match
    # on a substring rather than the whole capture.)
    out = machine.succeed(as_user("echo 'uname -n' | cogbox start"), timeout=600)
    assert "cogbox-default" in out, out
    # The VM keeps running after the SSH session ends.
    rc, _ = machine.execute(as_user("cogbox status"))
    assert rc == 0, f"expected running (0) after auto-ssh, got {rc}"
    stop_instance("cc-default")

    # --no-ssh keeps the old behavior: daemonize and return immediately without
    # opening a session. A second start while running reports already-running.
    machine.succeed(as_user("cogbox start --no-ssh"))
    machine.wait_until_succeeds(
        as_user(f"ssh {SSH_OPTS} -p 2222 root@127.0.0.1 true"), timeout=600
    )
    rc, out = machine.execute(as_user("cogbox start --no-ssh 2>&1"))
    assert rc == 75, f"expected already-running (75), got {rc}; out={out!r}"
    stop_instance("cc-default")

with subtest("Phase O: guest UDP egress is filtered (CIDR deny + QUIC/UDP-443 funnel deny)"):
    # The LD_PRELOAD shim gates UDP egress (sendto/sendmsg/sendmmsg + connected
    # UDP) the same way it gates TCP connect(), and the L7 funnel additionally
    # fail-closes UDP/443+UDP/80 (QUIC / HTTP-3) so cert-pinned clients can't
    # tunnel past the inspectable IPv4-TCP funnel. Every other phase only ever
    # sends TCP, so the entire UDP enforcement path was integration-untested --
    # a regression in the UDP hooks would silently fail OPEN. We drive real
    # guest UDP datagrams and assert host-side delivery (or non-delivery).
    #
    # A host UDP sink binds 0.0.0.0 on :9000 (general egress) and :443 (QUIC)
    # and appends every datagram's payload to a hit log. The guest reaches it
    # via the same 10.99.0.{1,2} loopback addresses the TCP phases use; passt
    # re-issues the guest's UDP send host-side, where the shim (LD_PRELOAD'd
    # into passt) enforces the rule before the packet leaves the node.
    udp_sink = r'''
import socket, threading, time
HITLOG = "/tmp/udp-hits.log"
open(HITLOG, "w").close()
lock = threading.Lock()
def loghit(s):
    with lock:
        with open(HITLOG, "a") as f:
            f.write(s + "\n")
def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    loghit("listen %d" % port)
    while True:
        data, _ = s.recvfrom(2048)
        loghit("port=%d payload=%s" % (port, data.decode("latin1").strip()))
for p in (9000, 443):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
while True:
    time.sleep(3600)
'''
    machine.succeed("cat > /tmp/udp-sink.py << 'PY_EOF'\n" + udp_sink + "\nPY_EOF")
    machine.succeed("systemd-run --unit=udp-sink --collect python3 /tmp/udp-sink.py")
    machine.wait_until_succeeds("grep -q 'listen 9000' /tmp/udp-hits.log", timeout=10)
    machine.wait_until_succeeds("grep -q 'listen 443' /tmp/udp-hits.log", timeout=10)

    # Guest-side single-datagram send via bash /dev/udp (same bash feature the
    # TCP probes use). The guest never sees the host-side drop, so this always
    # succeeds in the guest; the host hit log is the ground truth.
    def guest_udp(ip, port, marker):
        cmd = f"bash -c 'echo {marker} >/dev/udp/{ip}/{port}'"
        machine.succeed(as_user("cogbox ssh --name work " + shlex.quote(cmd)))

    def sink_has(marker):
        rc, _ = machine.execute(f"grep -q 'payload={marker}$' /tmp/udp-hits.log")
        return rc == 0

    # Pure-L4 UDP: one IP allowed, the sibling default-denied. No L7 rules, so
    # no funnel is rendered -- this isolates the plain UDP CIDR path.
    machine.succeed(as_user("printf '' | cogbox l7 set --name work"))
    machine.succeed(as_user("printf 'allow 10.99.0.1/32\\n' | cogbox rules set --name work"))
    boot_and_wait("cc-work", "--name work", ssh_port=2223)

    # Allowed IP: the datagram reaches the sink. (Truncate first so the earlier
    # `listen` markers don't interfere with payload greps.)
    machine.succeed("truncate -s 0 /tmp/udp-hits.log")
    guest_udp("10.99.0.1", 9000, "udp-allowed")
    machine.wait_until_succeeds("grep -q 'payload=udp-allowed$' /tmp/udp-hits.log", timeout=15)

    # Denied IP: the shim drops the send. Use a tracer to a DIFFERENT allowed
    # target -- once the tracer (sent AFTER) lands, the pipeline has flushed,
    # so a still-absent denied marker proves a real drop, not a slow packet.
    guest_udp("10.99.0.2", 9000, "udp-denied")
    guest_udp("10.99.0.2", 9000, "udp-denied")
    guest_udp("10.99.0.1", 9000, "udp-tracer1")
    machine.wait_until_succeeds("grep -q 'payload=udp-tracer1$' /tmp/udp-hits.log", timeout=15)
    assert not sink_has("udp-denied"), "UDP to a default-denied IP must be dropped by the shim"

    # QUIC fail-closed: hot-enable L7 (adds the funnel + `deny udp .../443,:80`
    # + `deny udp ::/0`). The origin IP stays L4-allowed, so the ONLY reason a
    # UDP/443 datagram is dropped is the funnel's QUIC deny -- while general UDP
    # egress (port 9000) to the same allowed IP still works.
    machine.succeed(as_user("cogbox l7 add allow vhost-a.test --name work"))
    l7nf = machine.succeed("cat /run/user/1000/cogbox-work/netfilter-rules")
    assert "deny udp 0.0.0.0/0:443" in l7nf and "deny udp ::/0" in l7nf, l7nf
    guest_udp("10.99.0.1", 443, "quic-denied")
    guest_udp("10.99.0.1", 443, "quic-denied")
    guest_udp("10.99.0.1", 9000, "udp-tracer2")
    machine.wait_until_succeeds("grep -q 'payload=udp-tracer2$' /tmp/udp-hits.log", timeout=15)
    assert not sink_has("quic-denied"), "UDP/443 (QUIC) must be denied while L7 is active"
    assert sink_has("udp-tracer2"), "general UDP egress to an allowed IP must still work under L7"

    stop_instance("cc-work", name="work")
    machine.succeed("systemctl stop udp-sink")

with subtest("Phase P: concurrent `cogbox start` boots exactly one VM (single-starter lock)"):
    # The flock single-starter guard exists so two near-simultaneous starts of
    # the same instance can't both wipe+recreate the runtime and boot two QEMUs
    # against one overlay image (corruption). Phase J only covers the SEQUENTIAL
    # already-running case (pid-file detected); this drives the actual race.
    machine.succeed(as_user("cogbox init -y --network none"))  # fast, isolated boot

    # Fire three starts at once; capture each one's exit code independently.
    machine.succeed(
        as_user(
            "rm -f /tmp/cs*.rc; "
            "for i in 1 2 3; do "
            "( cogbox start --no-ssh >/tmp/cs$i.log 2>&1; echo $? >/tmp/cs$i.rc ) & "
            "done; wait"
        ),
        timeout=600,
    )
    rcs = [int(machine.succeed(f"cat /tmp/cs{i}.rc").strip()) for i in (1, 2, 3)]
    # At least one start must win and report success; losers abort with the
    # already-running code (75) or, if their parent observed the winner's
    # daemon, the generic come-up failure (70) -- never a crash or 0-from-both
    # double boot. The decisive invariant is the QEMU count below.
    assert rcs.count(0) >= 1, f"no start succeeded: {rcs}; logs in /tmp/cs*.log"
    assert all(c in (0, 70, 75) for c in rcs), f"unexpected start exit codes: {rcs}"

    # Single-winner: exactly ONE cogbox QEMU is running (the lock blocked the
    # losers before they reached QEMU). A regression in the lock shows up here
    # as 2+. Match on comm (`qemu-system`, truncated to 15 chars by the kernel)
    # the same way Phase I does -- the cmdline is `exec -a microvm@nixos`.
    machine.wait_until_succeeds(as_user("cogbox status"), timeout=120)
    n = int(machine.succeed("pgrep -c qemu-system || true").strip() or "0")
    assert n == 1, f"expected exactly one QEMU after concurrent start, found {n}"

    # The winner's overlay is intact and the VM is usable. `cogbox status` only
    # proves the daemon/QEMU is up, not that sshd is accepting yet, so wait for
    # the guest's sshd before probing it (matches Phase J's readiness wait).
    machine.wait_until_succeeds(
        as_user(f"ssh {SSH_OPTS} -p 2222 root@127.0.0.1 true"), timeout=600
    )
    out = machine.succeed(as_user(f"ssh {SSH_OPTS} -p 2222 root@127.0.0.1 uname -n"))
    assert "cogbox-default" in out, out

    # Steady state: the held lock makes a fresh start report already-running.
    rc, out = machine.execute(as_user("cogbox start --no-ssh 2>&1"))
    assert rc == 75, f"expected already-running (75) once booted, got {rc}; out={out!r}"
    stop_instance("cc-default")

# ---------------------------------------------------------------------------
# Phase SSH-GW: VM SSHTarget parity (Slice 3A). Proves the exact mechanism the
# k8s (microVM) backend relies on: passt guest-:22 port-map reachable on a
# NON-loopback address, gateway user-CA cert auth (fail-closed on a wrong
# principal / unsigned key), and a host key persisted on /var/lib/cogbox so the
# gateway's TOFU pin survives a restart. cogworx stages ssh-ca.pub + the
# principals file into the guest's 9p SOURCE before boot; here the test plays
# cogworx's role by writing those same files into the instance data dir.
# ---------------------------------------------------------------------------
with subtest("Phase SSH-GW: passt port-map + gateway CA cert auth + host-key persistence"):
    DATA = "/home/testuser/.local/share/cogbox/instances/sshgw"
    PRINCIPAL = "acct-sshgw"  # cogworx uses the globally-unique instance id

    machine.succeed(as_user("cogbox init -y --name sshgw --network rules"))
    port = machine.succeed(
        "jq -r .sshPort /home/testuser/.config/cogbox/instances/sshgw/config.json"
    ).strip()

    # Play cogworx: mint a gateway user-CA and stage the CA + this instance's
    # principal into the 9p source BEFORE boot (the guest sshd reads them at
    # /var/lib/cogbox/.config over 9p). certutil-free: plain ssh keys.
    machine.succeed('ssh-keygen -t ed25519 -N "" -C gw-ca -f /tmp/gwca')
    machine.succeed(as_user(f"mkdir -p {DATA}/.config/ssh-principals"))
    machine.succeed(as_user(f"cp /tmp/gwca.pub {DATA}/.config/ssh-ca.pub"))
    machine.succeed(f"echo {PRINCIPAL} > /tmp/gwprincipal")
    machine.succeed(as_user(f"cp /tmp/gwprincipal {DATA}/.config/ssh-principals/root"))

    boot_and_wait("cc-sshgw", "--name sshgw", port)

    # The persistent host key was generated by cogbox-vm-sshd-prep on the 9p
    # mount; cogworx reads its PUBLIC half host-side (no guest hop).
    hostkey1 = machine.succeed(as_user(f"cat {DATA}/ssh/ssh_host_ed25519_key.pub")).strip()
    assert hostkey1, "guest host key was not generated/persisted on /var/lib/cogbox/ssh"

    # A short-lived user cert with the RIGHT principal authenticates (the
    # gateway's trust anchor is now in the guest, keyed to this instance).
    machine.succeed('ssh-keygen -t ed25519 -N "" -C gw-user -f /tmp/gwuser')
    machine.succeed(f"ssh-keygen -s /tmp/gwca -I test -n {PRINCIPAL} -V +5m /tmp/gwuser.pub")
    CERT = "-o CertificateFile=/tmp/gwuser-cert.pub -i /tmp/gwuser -o IdentitiesOnly=yes"
    machine.wait_until_succeeds(
        f"ssh {SSH_OPTS} {CERT} -p {port} root@127.0.0.1 true", timeout=120
    )

    # LOAD-BEARING (design A.2.1): passt rules-mode `-t "$SSH_PORT:22"` (no bind
    # address) must LISTEN on all addresses, not loopback-only -- that is exactly
    # what makes podIP:<port> reachable from the gateway pod in the k8s backend.
    # Assert the bind directly (a self-dial to the node's own address is not a
    # faithful stand-in for genuine cross-pod ingress); a loopback-only bind would
    # show 127.0.0.1:<port> with no wildcard and MUST fail here.
    listeners = machine.succeed(f"ss -H -tln 'sport = :{port}'")
    assert (f"0.0.0.0:{port}" in listeners) or (f"*:{port}" in listeners), (
        f"passt must bind :{port} on all addresses so podIP is reachable; got:\n{listeners}"
    )

    # Fail-closed: a cert with the WRONG principal is rejected.
    machine.succeed("ssh-keygen -s /tmp/gwca -I bad -n wrong-principal -V +5m /tmp/gwuser.pub")
    machine.fail(f"ssh {SSH_OPTS} {CERT} -p {port} root@127.0.0.1 true")

    # Fail-closed: an unsigned key not in authorized_keys is rejected.
    machine.succeed('ssh-keygen -t ed25519 -N "" -f /tmp/gwrogue')
    machine.fail(
        f"ssh {SSH_OPTS} -i /tmp/gwrogue -o IdentitiesOnly=yes -p {port} root@127.0.0.1 true"
    )

    # Host key survives a restart (stable TOFU pin) because it lives on the
    # persistent 9p mount, not ephemeral /etc/ssh.
    stop_instance("cc-sshgw", name="sshgw")
    boot_and_wait("cc-sshgw", "--name sshgw", port)
    hostkey2 = machine.succeed(as_user(f"cat {DATA}/ssh/ssh_host_ed25519_key.pub")).strip()
    assert hostkey1 == hostkey2, "host key rotated across restart -> gateway pin would break"
    stop_instance("cc-sshgw", name="sshgw")


# Phase CLAUDE-STUB: VM per-user Claude auth stub reconcile parity (Slice 3B).
# Proves the exact mechanism the k8s (microVM) backend's StageClaudeStub /
# ClaudeStubPresent rely on: cogworx writes a bound/unbound marker onto the 9p
# SOURCE host-side (== guest /var/lib/cogbox/claude-oauth.bound) and restarts the
# guest cogbox-claude-stub oneshot; the oneshot reconciles ONLY the redacted stub
# credential (never a real token), and -- unlike the container -- treats an ABSENT
# marker as an UNMANAGED standalone VM (leaves the launcher placeholder alone).
# The marker + the resulting logged-in/out state persist across a VM restart
# (they live on /var/lib/cogbox), so the boot oneshot re-stages from the marker
# with no cogworx re-drive.
# ---------------------------------------------------------------------------
with subtest("Phase CLAUDE-STUB: VM marker-gated stub reconcile + restart persistence"):
    DATA = "/home/testuser/.local/share/cogbox/instances/claudestub"
    MARKER = f"{DATA}/claude-oauth.bound"
    STUB = "sk-ant-oat01-cogbox-host-injected-placeholder"
    CRED = "/root/.claude/.credentials.json"

    machine.succeed(as_user("cogbox init -y --name claudestub --network rules"))
    port = machine.succeed(
        "jq -r .sshPort /home/testuser/.config/cogbox/instances/claudestub/config.json"
    ).strip()
    boot_and_wait("cc-claudestub", "--name claudestub", port)

    def restart_stub():
        machine.succeed(as_user(
            "cogbox ssh --name claudestub 'systemctl restart cogbox-claude-stub.service'"))

    # (0) MISROUTE GUARD: there is no host ~/.claude here, so the launcher emits
    # NO harness claude inject spec -- a bound `claude-oauth` OPERATOR spec (which
    # on a real pod cogworx renders pod-side) is therefore never shadowed by a
    # standalone harness spec on the same host. The generated inject-conf carries
    # no api.anthropic.com entry (absent file also satisfies this).
    irt = "/run/user/1000/cogbox-claudestub"
    machine.fail(as_user(
        f"jq -e '.[] | select(.host==\"api.anthropic.com\")' {irt}/l7-inject-conf.json"))

    # (1) BOUND: cogworx writes marker="1" host-side on the 9p SOURCE, then
    # restarts the oneshot -> the redacted SENTINEL is staged into the guest
    # overlay (accessToken == the shared placeholder, never a real token).
    machine.succeed(as_user(f"printf '1\\n' > {MARKER}"))
    restart_stub()
    machine.succeed(as_user(f"cogbox ssh --name claudestub 'test -e {CRED}'"))
    machine.succeed(as_user("cogbox ssh --name claudestub " + shlex.quote(
        f"jq -e '.claudeAiOauth.accessToken==\"{STUB}\"' {CRED}")))

    # (2) UNBOUND: cogworx writes marker="0" (NOT rm -- absence is reserved for
    # "unmanaged standalone"), restarts -> the stub is dropped (overlay whiteout)
    # so claude-code falls back to /login (fail-closed logged-out).
    machine.succeed(as_user(f"printf '0\\n' > {MARKER}"))
    restart_stub()
    machine.fail(as_user(f"cogbox ssh --name claudestub 'test -e {CRED}'"))

    # (3) RE-BOUND + RESTART PERSISTENCE: the marker lives on the 9p mount, so a
    # full VM restart re-stages the sentinel from it at boot (the oneshot is
    # wantedBy multi-user.target) with NO cogworx re-drive.
    machine.succeed(as_user(f"printf '1\\n' > {MARKER}"))
    restart_stub()
    machine.succeed(as_user(f"cogbox ssh --name claudestub 'test -e {CRED}'"))
    stop_instance("cc-claudestub", name="claudestub")
    boot_and_wait("cc-claudestub", "--name claudestub", port)
    machine.succeed(as_user(f"cogbox ssh --name claudestub 'test -e {CRED}'"))
    machine.succeed(as_user("cogbox ssh --name claudestub " + shlex.quote(
        f"jq -e '.claudeAiOauth.accessToken==\"{STUB}\"' {CRED}")))

    # (4) ONBOARDING: brain-trust seeds hasCompletedOnboarding on the VM so a
    # logged-out claude-code lands on /login rather than the first-run wizard's
    # dead-end "Select login method". (Container gets this via claudeStubScript;
    # the VM gets it from the isVm-gated brain-trust jq clause.)
    machine.succeed(as_user("cogbox ssh --name claudestub " + shlex.quote(
        "jq -e '.hasCompletedOnboarding==true' /root/.claude.json")))

    stop_instance("cc-claudestub", name="claudestub")
    machine.succeed(as_user(
        "rm -rf /home/testuser/.config/cogbox/instances/claudestub "
        "/home/testuser/.local/share/cogbox/instances/claudestub"))
