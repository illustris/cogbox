# Driver for tests/guest-reply-route.nix. The Nix side prepends MARK, TABLE,
# PRIO, GROUP (flake.nix guestReplyRoute), SOCAT (an absolute store path the
# guest also runs, via the read-only 9p store share), MOSH_RANGE (the passt
# UDP forward) and UDP_PORT (one port inside it).
import re
import shlex

CLIENT = "198.51.100.7"
UPLINK_PEER = "203.0.113.9"
COLLIDE_NET = "198.51.100.0/24"
COLLIDE_GW = "198.51.100.1"
BRIDGE = "cbxcollide"
CFG = "/home/testuser/.config/cogbox/instances/default/config.json"
KEY = "/home/testuser/.ssh/id_ed25519"
SSH_OPTS = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=2"


def as_user(cmd):
    return "su - testuser -c " + shlex.quote(cmd)


def guest(cmd):
    return as_user("cogbox ssh " + shlex.quote(cmd))


with subtest("outer setup: client and uplink-peer addresses, decoy listeners"):
    machine.wait_for_unit("multi-user.target")
    machine.succeed(as_user(f'ssh-keygen -t ed25519 -N "" -f {KEY}'))
    machine.succeed(f"ip addr add {CLIENT}/32 dev lo")
    machine.succeed(f"ip addr add {UPLINK_PEER}/32 dev lo")
    # The decoy answers on the outer machine at the client address: guest
    # egress to the colliding subnet must reach the Docker side, never this.
    machine.succeed(
        f"systemd-run --unit=rr-decoy socat TCP4-LISTEN:9100,bind={CLIENT},fork,reuseaddr SYSTEM:'echo host'"
    )
    machine.succeed(
        f"systemd-run --unit=rr-uplink socat TCP4-LISTEN:9100,bind={UPLINK_PEER},fork,reuseaddr SYSTEM:'echo uplink'"
    )
    machine.wait_until_succeeds(f"ss -Htln | grep -q '{CLIENT}:9100'", timeout=30)
    machine.wait_until_succeeds(f"ss -Htln | grep -q '{UPLINK_PEER}:9100'", timeout=30)

with subtest("start the guest with the mosh UDP forward"):
    machine.succeed(as_user("cogbox init -y --network full"))
    machine.succeed(f"cp {KEY}.pub /home/testuser/.config/cogbox/authorized_keys")
    machine.succeed(
        as_user(f"COGBOX_MOSH_UDP_FORWARD={MOSH_RANGE} cogbox start --no-ssh"),
        timeout=600,
    )
    ssh_port = int(machine.succeed(f"jq -r .sshPort {CFG}").strip())
    http_port = int(machine.succeed(f"jq -r .httpPort {CFG}").strip())
    machine.wait_until_succeeds(
        as_user(f"ssh {SSH_OPTS} -p {ssh_port} root@127.0.0.1 true"),
        timeout=600,
    )
    udp = machine.succeed("ss -Huln")
    assert re.search(r":%d\b" % UDP_PORT, udp), f"passt is not forwarding UDP {UDP_PORT}:\n{udp}"

with subtest("guest discovery"):
    UP = machine.succeed(guest("ip -4 route show default | awk '{print $5; exit}'")).strip()
    GW = machine.succeed(guest("ip -4 route show default | awk '{print $3; exit}'")).strip()
    UPIP = machine.succeed(
        guest(f"ip -4 -o addr show dev {UP} | awk '{{print $4; exit}}' | cut -d/ -f1")
    ).strip()
    assert UP and GW and UPIP, f"uplink discovery failed: dev={UP!r} gw={GW!r} addr={UPIP!r}"
    print(f"uplink dev={UP} gw={GW} addr={UPIP}")
    machine.wait_until_succeeds(
        guest("systemctl is-active cogbox-reply-route docker cogbox-app-relay"),
        timeout=300,
    )
    # nft is not on the guest's PATH; take the unit's own binary.
    NFT = machine.succeed(
        guest("systemctl cat cogbox-reply-route | grep -o '/nix/store/[^ ]*/bin/nft' | head -n1")
    ).strip()
    assert NFT, "could not find nft in cogbox-reply-route.service"

RULE_RE = r"^%d:\s+from all fwmark %s/%s lookup %d\b" % (PRIO, MARK, MARK, TABLE)
TABLE_RE = r"^default via %s dev %s\b.*\bonlink\b" % (re.escape(GW), re.escape(UP))
ROUTABLE = "State: routable (configured)"
# The same three checks as one guest shell command, for wait_until_succeeds.
MECHANISM = (
    f"ip -4 rule show | grep -qE '^{PRIO}:[[:space:]]+from all fwmark {MARK}/{MARK} lookup {TABLE}( |$)'"
    f" && ip -4 route show table {TABLE} | grep -E '^default via {re.escape(GW)} dev {UP} ' | grep -qw onlink"
    f" && networkctl status {UP} --no-pager | grep -qF '{ROUTABLE}'"
)


def assert_collision():
    out = machine.succeed(guest(f"ip -4 route get {CLIENT}"))
    assert f"dev {BRIDGE}" in out, f"the client address is not routed into the Docker bridge:\n{out}"


with subtest("mechanism present"):
    rules = machine.succeed(guest("ip -4 rule show"))
    assert re.search(RULE_RE, rules, re.M), f"no fwmark rule matching {RULE_RE!r}:\n{rules}"
    t = machine.succeed(guest(f"ip -4 route show table {TABLE}"))
    assert re.search(TABLE_RE, t, re.M), f"table {TABLE} has no onlink default via {GW} dev {UP}:\n{t}"
    link = machine.succeed(guest(f"ip -o link show dev {UP}"))
    assert f"group {GROUP}" in link, f"uplink is not in link group {GROUP}:\n{link}"
    st = machine.succeed(guest(f"networkctl status {UP} --no-pager"))
    assert ROUTABLE in st, f"uplink is not routable/configured (networkd refused the config?):\n{st}"
    print(rules + t + link)


def probe_ssh():
    rc, out = machine.execute(as_user(
        f"timeout 25 ssh -b {CLIENT} -p {ssh_port} -i {KEY} -o BatchMode=yes -o ConnectTimeout=8"
        " -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
        f" root@{CLIENT} 'echo $SSH_CONNECTION'"
    ))
    fields = out.split()
    return rc == 0 and len(fields) > 0 and fields[0] == CLIENT, (rc, out)


def probe_http():
    rc, out = machine.execute(
        f"timeout 15 curl -sS -m 10 --interface {CLIENT} http://{CLIENT}:{http_port}/healthz"
    )
    return rc == 0 and out.strip() == "ok", (rc, out)


def udp_out():
    # -t5: after stdin's EOF, keep reading for 5s (the default 0.5s can lose a
    # reply that a forked responder in a nested guest sends a little later).
    # socat exits 0 on its timeouts, so the reply text is the verdict.
    _, out = machine.execute(
        f"echo x | timeout 10 socat -t5 -T5 - UDP4:{CLIENT}:{UDP_PORT},bind={CLIENT}"
    )
    return out


def probes_pass():
    ok, rs = probe_ssh()
    assert ok, f"ssh from {CLIENT} failed or lost its source: {rs}"
    ok, rh = probe_http()
    assert ok, f"app relay /healthz from {CLIENT} failed: {rh}"
    out = udp_out()
    assert CLIENT in out, f"UDP reply to {CLIENT} missing: {out!r}"
    print(f"probes pass: SSH_CONNECTION={rs[1].strip()!r} healthz={rh[1].strip()!r} udp={out.strip()!r}")


def probes_fail():
    ok, r = probe_ssh()
    assert not ok, f"ssh from {CLIENT} unexpectedly worked: {r}"
    ok, r = probe_http()
    assert not ok, f"app relay /healthz from {CLIENT} unexpectedly worked: {r}"
    out = udp_out()
    assert CLIENT not in out, f"UDP reply to {CLIENT} unexpectedly arrived: {out!r}"


with subtest("baseline before any collision: passt keeps the client source"):
    # Stands in for mosh-server -s, which binds the SSH_CONNECTION address.
    machine.succeed(guest(
        f"systemd-run --unit=rr-udp {SOCAT} UDP4-RECVFROM:{UDP_PORT},bind={UPIP},fork SYSTEM:'echo $SOCAT_PEERADDR'"
    ))
    machine.wait_until_succeeds(guest(f"ss -Huln | grep -q '{UPIP}:{UDP_PORT}'"), timeout=30)
    probes_pass()

with subtest("collide: a Docker network and a netns peer on the client's subnet"):
    machine.succeed(guest(
        f"docker network create --subnet {COLLIDE_NET} --gateway {COLLIDE_GW}"
        f" -o com.docker.network.bridge.name={BRIDGE} cbx-collide"
    ))
    machine.succeed(guest(
        "ip netns add ctr"
        " && ip link add vh0 type veth peer name vc0"
        f" && ip link set vh0 master {BRIDGE}"
        " && ip link set vh0 up"
        " && ip link set vc0 netns ctr"
        f" && ip -n ctr addr add {CLIENT}/24 dev vc0"
        " && ip -n ctr link set vc0 up"
        " && ip -n ctr link set lo up"
        f" && ip -n ctr route add default via {COLLIDE_GW}"
    ))
    machine.succeed(guest(
        f"systemd-run --unit=rr-ctr ip netns exec ctr {SOCAT} TCP4-LISTEN:9100,fork,reuseaddr SYSTEM:'echo ctr'"
    ))
    machine.wait_until_succeeds(guest("ip netns exec ctr ss -Htln | grep -q ':9100'"), timeout=30)
    assert_collision()
    out = machine.succeed(guest(f"ip -4 route get {CLIENT} mark {MARK}"))
    print(out)
    assert f"dev {UP}" in out and f"table {TABLE}" in out, f"the marked route does not take table {TABLE} via {UP}:\n{out}"

with subtest("with the fix: replies to the colliding client leave through the uplink"):
    probes_pass()

with subtest("regressions: guest egress, container traffic and uplink egress are unchanged"):
    # -u: read only, so the reply is never cut short by our own EOF.
    out = machine.succeed(guest(f"timeout 8 {SOCAT} -T5 -u TCP4:{CLIENT}:9100 -")).strip()
    assert out == "ctr", f"guest egress to {CLIENT} must follow the main table into the bridge, got {out!r}"
    out = machine.succeed(guest(
        f"ip netns exec ctr timeout 8 {SOCAT} -T5 -u TCP4:{COLLIDE_GW}:22 - | head -c7"
    ))
    assert out == "SSH-2.0", f"the netns peer can no longer reach the guest's sshd: {out!r}"
    out = machine.succeed(guest(f"timeout 8 {SOCAT} -T5 -u TCP4:{UPLINK_PEER}:9100 -")).strip()
    assert out == "uplink", f"guest egress via the uplink changed, got {out!r}"

with subtest("counters: both rules matched traffic"):
    nft = machine.succeed(guest(f"{NFT} list table ip cogbox_reply"))
    print(nft)
    for needle in ("iifgroup", "meta mark set"):
        line = next((ln for ln in nft.splitlines() if needle in ln), None)
        assert line is not None, f"no {needle!r} rule in:\n{nft}"
        m = re.search(r"counter packets (\d+)", line)
        assert m and int(m.group(1)) > 0, f"the {needle!r} rule never matched: {line!r}"

with subtest("negative control A: stopping the unit drops the table and the fix (fail-open)"):
    machine.succeed(guest("systemctl stop cogbox-reply-route"))
    machine.succeed(guest(f"if {NFT} list table ip cogbox_reply >/dev/null 2>&1; then exit 1; fi"))
    probes_fail()
    # The control channel is unaffected: passt remaps its 127.0.0.1 source, so
    # it never comes from the colliding subnet.
    machine.succeed(guest("true"))
    machine.succeed(guest("systemctl start cogbox-reply-route"))
    probes_pass()

with subtest("negative control B: the networkd rule is load-bearing and networkd restores it"):
    machine.succeed(guest(f"ip -4 rule del priority {PRIO}"))
    probes_fail()
    machine.succeed(guest("true"))
    machine.succeed(guest(f"networkctl reconfigure {UP}"))
    machine.wait_until_succeeds(guest(MECHANISM), timeout=120)
    probes_pass()


def restart(unit):
    # --no-block, then wait for a new invocation: a networkd restart can
    # briefly take the uplink address away under the control session itself.
    before = machine.succeed(guest(f"systemctl show -P InvocationID {unit}")).strip()
    machine.succeed(guest(f"systemctl --no-block restart {unit}"))
    machine.wait_until_succeeds(
        guest(f"test \"$(systemctl show -P InvocationID {unit})\" != '{before}' && systemctl is-active {unit}"),
        timeout=180,
    )


for unit in ("systemd-networkd", "docker", "firewall"):
    with subtest(f"robustness: restart {unit}"):
        restart(unit)
        machine.wait_until_succeeds(guest(MECHANISM), timeout=120)
        assert_collision()
        probes_pass()

with subtest("stop the guest"):
    machine.succeed(as_user("cogbox stop"))
    machine.wait_until_fails("test -e /run/user/1000/cogbox/pid", timeout=30)
