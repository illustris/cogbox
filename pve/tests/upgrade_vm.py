# The pve-upgrade-vm test script. pve/tests/upgrade-vm.nix prepends SUITE,
# G_JSON (system generation name -> toplevel), WC_BLOB (the worst-case raw
# SMBIOS serial), MIN_FREE and RESERVE (the node's headroom seam).
#
# The REAL tool runs everywhere: cogworxd's calls are `<system>/sw/bin/
# cogworx-pve-upgrade ...` over the backdoor shell, and power cuts come from
# crashat.py (the tool imported with a STEP_HOOK that parks the process right
# after a step's sync) followed by a QEMU quit.
#
# CWX-VECTOR-BEGIN/END lines carry grub.cfg and grubenv as hex; they are the
# source of pve/testdata/grubcfg-v1/vm-*.cfg and grubenv-v1/vm-*.env.

import base64
import datetime as dt
import json
import os
import re
import shlex
import time
from typing import Any, Dict, List, Optional, Tuple

G: Dict[str, str] = json.loads(G_JSON)
NAMES: Dict[str, str] = {v: k for k, v in G.items()}
TOOL_REL = "/sw/bin/cogworx-pve-upgrade"
GRUBCFG = "/boot/grub/grub.cfg"
GRUBENV = "/boot/grub/grubenv"
GRUBSTATE = "/boot/grub/state"
TXN_FILE = "/var/lib/cogworx-pve-upgrade/txn.json"
STAGED = "/nix/var/nix/gcroots/cogworx-pve-upgrade/staged"
COMMITTED_ROOT = "/nix/var/nix/gcroots/cogworx-pve-upgrade/committed"
LOCK = "/run/cogworx-pve-upgrade.lock"
RETAIN = "2030-01-01T00:00:00Z"
GIB = 1024 * 1024 * 1024
ROLLBACK_MENU = "NixOS - Profile 'cogworx_rollback'"
CYCLE = ["A", "B", "C"]

# The raw blob as PVE hands it to QEMU after its base64 decode: M= in the
# sorted position, which S=c and S=r replace (K < S < c).
assert len(WC_BLOB) == 329 and "&M=&" in WC_BLOB and "&v=1&" in WC_BLOB, len(WC_BLOB)
NONCE_RE = re.compile(r"&n=[0-9a-f-]{36}&")
assert NONCE_RE.search(WC_BLOB)


class Run:
    def __init__(self) -> None:
        self.committed = "A"
        self.txns = 0
        self.nonces = 0
        self.mib0: Tuple[str, str] = ("", "")
        self.state0 = ""
        self.dig: Dict[str, str] = {}
        self.boots: List[Tuple[str, float]] = []
        self.installs: List[float] = []
        self.verbs: Dict[str, List[float]] = {}


R = Run()


def name_of(path: Optional[str]) -> str:
    if path is None:
        return "-"
    return NAMES.get(path, path)


def tool_path(gen: str) -> str:
    return G[gen] + TOOL_REL


def tool(gen: str, *args: str, want: Optional[int] = 0, path: Optional[str] = None, quiet: bool = False) -> Dict[str, Any]:
    """Run the tool once; exactly one JSON line, exit == envelope exit."""
    exe = path if path is not None else tool_path(gen)
    who = name_of(exe[: -len(TOOL_REL)]) if exe.endswith(TOOL_REL) else exe
    cmd = " ".join(shlex.quote(a) for a in (exe,) + args)
    t0 = time.monotonic()
    rc, out = machine.execute(cmd + " 2>/run/cwx-tool.err", timeout=dt.timedelta(minutes=5))
    took = time.monotonic() - t0
    err = machine.execute("cat /run/cwx-tool.err")[1]
    for m in re.finditer(r"installer run for \S+: exit \d+ in ([0-9.]+)s", err):
        R.installs.append(float(m.group(1)))
    lines = [line for line in out.splitlines() if line.strip()]
    if len(lines) != 1:
        machine.log("CWX tool stderr:\n" + err)
        raise AssertionError(f"{cmd}: want one JSON line on stdout, got {out!r}")
    env: Dict[str, Any] = json.loads(lines[0])
    if args[0] not in ("status", "proto", "closure-digest"):
        R.verbs.setdefault(args[0], []).append(round(took, 2))
    if not quiet:
        machine.log(f"CWX tool[{who}] {' '.join(args)} -> exit {rc} {env.get('reason_class')} {env.get('reason')!r} mutated={env.get('mutated')} {took:.2f}s")
    assert env["exit"] == rc, (env, rc)
    if want is not None and rc != want:
        machine.log("CWX tool stderr:\n" + err)
        raise AssertionError(f"{cmd}: exit {rc} ({env.get('reason_class')}: {env.get('reason')}), want {want}")
    return env


def status() -> Dict[str, Any]:
    st: Dict[str, Any] = tool(R.committed, "status", quiet=True)["status"]
    return st


def new_txn() -> str:
    R.txns += 1
    return "%08x-0000-4000-8000-%012x" % (R.txns, R.txns)


def new_nonce() -> str:
    R.nonces += 1
    return "00000000-0000-4000-8000-%012x" % R.nonces


def blob(sel: str, nonce: str) -> str:
    """The worst-case serial with this boot's nonce; sel c, r or M (no S)."""
    b = NONCE_RE.sub("&n=" + nonce + "&", WC_BLOB)
    if sel == "c":
        b = b.replace("&M=&", "&S=c&")
    elif sel == "r":
        b = b.replace("&M=&", "&S=r&")
    else:
        assert sel == "M", sel
    return b


def boot(serial: Optional[str], label: str, allow_reboot: bool = False, smbios_ep: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
    """Start with this SMBIOS serial (None: no -smbios at all), wait for
    multi-user, return the booted generation's name and `status` from the
    committed tool path."""
    opts: List[str] = []
    if serial is not None:
        # The boot-config charset (plus base64's `/`): no spaces, commas or
        # glob characters, so QEMU_OPTS needs no quoting.
        assert re.fullmatch(r"[A-Za-z0-9._~+=&%/-]+", serial), serial
        opts.append("-smbios type=1,serial=" + serial)
    if smbios_ep is not None:
        opts.append("-machine smbios-entry-point-type=" + smbios_ep)
    if opts:
        os.environ["QEMU_OPTS"] = " ".join(opts)
    else:
        os.environ.pop("QEMU_OPTS", None)
    t0 = time.monotonic()
    machine.start(allow_reboot=allow_reboot)
    machine.wait_for_unit("multi-user.target")
    took = round(time.monotonic() - t0, 1)
    R.boots.append((label, took))
    booted = machine.succeed("readlink -f /run/booted-system").strip()
    st = status()
    machine.log(
        f"CWX boot[{label}] {took}s booted={name_of(booted)} cwx_once={st['cwx_once']!r} "
        f"next_entry={st['next_entry']!r} txn={(st['txn'] or {}).get('state')} crash_state={st['crash_state']}"
    )
    assert st["booted"] == booted, (st["booted"], booted)
    return name_of(booted), st


def off() -> None:
    machine.shutdown()


def fetch(target: str, closure: Optional[str] = None, want_state: str = "fetched", want_class: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
    """`fetch` from the committed tool, then poll `status` until the worker's
    verdict is in."""
    tid = new_txn()
    env = tool(R.committed, "fetch", "--txn", tid, "--target", G[target], "--closure", closure or R.dig[target])
    # The launcher waits for its worker to register before it answers, so its
    # own status never shows the healthy txn as interrupted.
    lst = env["status"]
    assert lst["txn"]["id"] == tid, lst["txn"]
    assert lst["txn"]["state"] != "fetching" or lst["worker"] == {"active": True, "txn": tid}, (env["reason"], lst["worker"])
    assert "interrupted" not in lst["crash_state"], (env["reason"], lst["crash_state"])
    t0 = time.monotonic()
    while True:
        st = status()
        t = st["txn"]
        if t and t["id"] == tid and t["state"] != "fetching":
            break
        if time.monotonic() - t0 > 600:
            raise AssertionError(f"fetch {target}: still {t} after 600 s")
        time.sleep(1)
    machine.log(f"CWX fetch[{target}] {t['state']} {t['reason_class']} {t['reason']!r} {time.monotonic() - t0:.1f}s")
    assert t["state"] == want_state, t
    if want_class is not None:
        assert t["reason_class"] == want_class, t
    return tid, st


def arm(tid: str) -> Dict[str, Any]:
    st: Dict[str, Any] = tool(R.committed, "arm", "--txn", tid)["status"]
    cand = st["grubcfg"]["candidate_entry"]
    assert st["txn"]["state"] == "armed", st["txn"]
    assert cand is not None and cand["init"] == st["txn"]["target"], st["grubcfg"]
    assert st["next_entry"] == cand["path"], (st["next_entry"], cand)
    assert st["cwx_once"] is None, st["cwx_once"]
    return st


def abort(tid: str, *extra: str, want_state: str = "aborted") -> Dict[str, Any]:
    st: Dict[str, Any] = tool(R.committed, "abort", "--txn", tid, *extra)["status"]
    assert st["txn"]["state"] == want_state, st["txn"]
    assert st["candidate"] is None and st["next_entry"] is None, st
    assert st["entry0_init"] == G[R.committed] and st["system_head"] == G[R.committed], st
    assert st["grubcfg"]["ok"], st["grubcfg"]
    return st


def worker_log(label: str) -> None:
    machine.log(f"CWX worker stderr [{label}]:\n" + machine.succeed("journalctl -u cogworx-pve-upgrade-fetch.service -o cat --no-pager | tail -n 40"))


def first_mib() -> Tuple[str, str]:
    out = machine.succeed(
        "dd if=/dev/vda bs=512 count=1 status=none | sha256sum | cut -d' ' -f1; "
        "dd if=/dev/vda bs=1M count=1 status=none | sha256sum | cut -d' ' -f1"
    ).split()
    return out[0], out[1]


def state_hash() -> str:
    return machine.succeed(f"sha256sum {GRUBSTATE} | cut -d' ' -f1").strip()


def boot_area_unchanged(label: str) -> None:
    got = first_mib()
    assert got == R.mib0, f"{label}: first sector / first MiB {got}, at boot0 {R.mib0}"
    assert state_hash() == R.state0, f"{label}: /boot/grub/state changed"


def hexof(path: str) -> str:
    return machine.succeed(f"od -An -v -tx1 {path} | tr -d ' \\n'").strip()


def vector(label: str) -> None:
    listing = machine.succeed(f"grub-editenv {GRUBENV} list")
    machine.log(f"CWX-VECTOR-BEGIN {label} cfg={hexof(GRUBCFG)} env={hexof(GRUBENV)} list={listing.encode().hex()} CWX-VECTOR-END")


def submenu_index(title: str) -> int:
    titles = re.findall(r'^submenu "([^"]*)"', machine.succeed(f"cat {GRUBCFG}"), re.M)
    return titles.index(title)


def txn_seq() -> int:
    return int(machine.succeed(f"python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))[\"seq\"])' {TXN_FILE}").strip())


def lock_held() -> bool:
    held: bool = status()["lock"]["held"]
    return held


def wait_lock(want: bool) -> None:
    t0 = time.monotonic()
    while lock_held() != want:
        if time.monotonic() - t0 > 60:
            raise AssertionError(f"lock.held never became {want}")
        time.sleep(0.5)


def crashat_argv(gen: str, verb: str, k: int, args: List[str]) -> List[str]:
    tp = tool_path(gen)
    real = machine.succeed(f"readlink -f {tp}").strip()
    return ["python3", "-I", "/etc/cwx-test/crashat.py", real, tp, verb, str(k)] + args


def wait_crash_point(log: str) -> str:
    try:
        machine.wait_until_succeeds("test -e /run/cwx-crash-point", timeout=dt.timedelta(seconds=180))
    except Exception:
        machine.log("CWX crashat log:\n" + machine.execute(log)[1])
        raise
    return machine.succeed("cat /run/cwx-crash-point").strip()


def park_at(gen: str, verb: str, k: int, args: List[str]) -> str:
    """Run `verb` with gen's tool through crashat.py, parked right after step k."""
    machine.succeed("rm -f /run/cwx-crash-point /run/cwx-crash-release /run/cwx-crashat.log")
    argv = crashat_argv(gen, verb, k, args)
    machine.succeed("setsid -f " + " ".join(shlex.quote(a) for a in argv) + " >/run/cwx-crashat.log 2>&1 </dev/null")
    return wait_crash_point("cat /run/cwx-crashat.log")


def crash_after(gen: str, verb: str, k: int, args: List[str]) -> None:
    """Run `verb` with gen's tool through crashat.py and pull the plug right
    after step k (the tool has synced; nothing after it has)."""
    machine.succeed("sysctl -q -w vm.dirty_writeback_centisecs=0 vm.dirty_expire_centisecs=360000")
    point = park_at(gen, verb, k, args)
    machine.log(f"CWX power cut after {point}")
    machine.crash()


def invariants(label: str) -> Dict[str, Any]:
    """After a repair: one consistent committed system and an untouched boot area."""
    st = status()
    g = G[R.committed]
    assert st["booted"] == g and st["committed"] == g, (label, st["booted"], st["committed"])
    assert st["system_head"] == g and st["entry0_init"] == g, (label, st["system_head"], st["entry0_init"])
    assert st["candidate"] is None and st["next_entry"] is None, (label, st["candidate"], st["next_entry"])
    assert st["grubcfg"]["ok"] and st["grubenv_ok"], (label, st["grubcfg"])
    assert st["grubcfg"]["candidate_entry"] is None, (label, st["grubcfg"])
    assert st["rollback"]["path"] == st["rollback"]["recorded"], (label, st["rollback"])
    rb = st["grubcfg"]["rollback_entry"]
    if st["rollback"]["recorded"] is None:
        assert rb is None and st["cwx_rollback_entry"] is None, (label, rb, st["cwx_rollback_entry"])
    else:
        assert rb is not None and rb["init"] == st["rollback"]["recorded"], (label, rb)
        assert st["cwx_rollback_entry"] == rb["path"], (label, st["cwx_rollback_entry"], rb)
    assert st["crash_state"] == [], (label, st["crash_state"])
    boot_area_unchanged(label)
    return st


# --- shared setup ---------------------------------------------------------------


def setup() -> None:
    with subtest("cache: cachehost signs and serves the targets"):
        cachehost.start()
        cachehost.wait_for_unit("multi-user.target")
        cachehost.succeed(
            "nix-store --generate-binary-cache-key cwx-test-1 /root/sk /root/pk",
            "mkdir -p /tmp/shared/cache",
            "cp /root/pk /tmp/shared/cache-pk",
        )
        # Whole closures: nix refuses to add a path to a binary cache whose
        # references the cache lacks, so a cache of only what the VM is
        # missing cannot be written. The VM still substitutes only what it
        # is missing.
        t0 = time.monotonic()
        signed = " ".join(G[n] for n in ("B", "C", "I", "P", "X", "K"))
        cachehost.succeed(
            f"nix copy --to 'file:///tmp/shared/cache?compression=zstd&secret-key=/root/sk' {signed}",
            timeout=dt.timedelta(minutes=30),
        )
        # U unsigned: the same cache, no key.
        cachehost.succeed(f"nix copy --to 'file:///tmp/shared/cache?compression=zstd' {G['U']}")
        size = cachehost.succeed("du -sm /tmp/shared/cache | cut -f1").strip()
        cachehost.log(f"CWX cache filled: {size} MiB in {time.monotonic() - t0:.1f}s")
        # The digests cogworxd pins, computed off the VM (the workstation path).
        for n in ("A", "B", "C", "I", "P", "X", "K", "U"):
            env = json.loads(cachehost.succeed(f"cogworx-pve-upgrade closure-digest --target {G[n]}"))
            assert env["exit"] == 0 and env["closure_digest"]["target"] == G[n], env
            R.dig[n] = env["closure_digest"]["closure"]
        R.dig["E"] = "0" * 64
        cachehost.log("CWX digests " + json.dumps(R.dig, sort_keys=True))
        cachehost.shutdown()

    with subtest("S0 boot0: no serial, booted A, bootstrap status, proto guard, baselines"):
        b, st = boot(None, "boot0")
        assert b == "A", b
        assert st["committed_source"] == "bootstrap" and st["committed"] == G["A"], st
        assert st["crash_state"] == [], st["crash_state"]
        assert st["grubenv_ok"] and st["grubcfg"]["ok"], st["grubcfg"]
        assert st["txn"] is None and st["bootloader_pin"]["state"] == "unpinned", st
        # The disk grew (growpart + growfs) and leaves room above the seam.
        assert st["free_bytes"] >= MIN_FREE + RESERVE + GIB, st["free_bytes"]
        machine.succeed(f"test $(stat -c %s {GRUBENV}) -eq 1024")
        machine.succeed("test -f /boot/grub/i386-pc/smbios.mod", "test -f /boot/grub/i386-pc/regexp.mod")
        machine.fail(f"test -e {TXN_FILE}")
        # The lock file is there root-owned 0600 before anything opened it
        # (a tmpfiles rule): flock(1) in the gc wrapper would create it 0644.
        lockmode = machine.succeed(f"stat -c '%a %U %G' {LOCK}").strip()
        assert lockmode == "600 root root", lockmode
        proto = tool("A", "proto")["proto"]
        assert proto["guard"] == "cwx-guard-v1" and proto["proto"] == 1, proto
        machine.succeed(
            "mkdir -p /var/lib/cwx-test",
            'echo "extra-trusted-public-keys = $(cat /tmp/shared/cache-pk)" > /var/lib/cwx-test/nix-trust.conf',
            "systemctl restart nix-daemon.service",
        )
        # Baselines AFTER the first boot: growpart has rewritten the
        # partition table once; nothing may change it again.
        R.mib0 = first_mib()
        R.state0 = state_hash()
        machine.log(f"CWX boot0 first sector / first MiB {R.mib0}")
        machine.log("CWX /boot/grub/state:\n" + machine.succeed(f"cat {GRUBSTATE}"))
        machine.log("CWX grub.cfg one-shot vs guard lines:\n" + machine.succeed(
            f"grep -n 'next_entry\\|boot_once=true\\|cwx-guard-v1\\|insmod smbios\\|save_env cwx_once\\|^menuentry\\|^submenu' {GRUBCFG}"))
        vector("base")


# --- suite main -------------------------------------------------------------------


def suite_main() -> None:
    with subtest("S1 refusals without a boot: grammar, the argv[0] rule"):
        env = tool("A", "arm", "--txn", "not-a-txn", want=64)
        assert env["reason_class"] == "usage" and "status" not in env, env
        cur = "/run/current-system" + TOOL_REL
        env = tool("", "arm", "--txn", new_txn(), want=65, path=cur)
        assert env["reason_class"] == "not-committed-tool" and env["mutated"] is False, env
        machine.fail(f"test -e {TXN_FILE}")
        env = tool("", "status", path=cur)
        assert env["status"]["committed"] == G["A"], env["status"]

    with subtest("S2 fetch verdicts: not-found, signature, compat, integrity"):
        tid, _ = fetch("E", want_state="fetch_failed", want_class="not-found")
        worker_log("E not-found")
        abort(tid)
        tid, _ = fetch("U", want_state="fetch_failed", want_class="signature")
        worker_log("U signature")
        abort(tid)
        tid, st = fetch("X", want_state="fetch_failed", want_class="compat")
        assert st["txn"]["reason"] == "compat:vi:hostKeyPath", st["txn"]
        abort(tid, "--release-staged")
        # C under B's digest, so B itself stays unrealised for S3.
        tid, _ = fetch("C", closure=R.dig["B"], want_state="fetch_failed", want_class="integrity")
        abort(tid)
        machine.fail(f"test -e {STAGED}")
        assert txn_seq() > 0

    with subtest("S3 the headroom gate refuses before anything is realised"):
        free = status()["free_bytes"]
        ballast = free - (MIN_FREE + RESERVE // 2)
        assert ballast > 0, free
        machine.succeed(f"fallocate -l {ballast} /var/lib/cwx-test/ballast")
        machine.log(f"CWX headroom: {status()['free_bytes']} bytes free with the ballast")
        tid, _ = fetch("B", want_state="fetch_failed", want_class="headroom")
        machine.fail(f"nix-store --check-validity {G['B']}")
        abort(tid)
        machine.succeed("rm -f /var/lib/cwx-test/ballast")

    with subtest("S4 the lock against nix-gc, a busy verb, the argv[0] rule after a fetch, GC during a staged fetch"):
        machine.succeed(f"systemd-run --unit=cwx-lockholder --collect $(command -v flock) {LOCK} $(command -v sleep) 600")
        wait_lock(True)
        garbage = machine.succeed("echo cwx-garbage-$RANDOM-$$ > /tmp/cwx-garbage && nix-store --add /tmp/cwx-garbage").strip()
        machine.succeed("systemctl start cogworx-nix-gc.service")
        info = machine.get_unit_info("cogworx-nix-gc.service")
        assert info["Result"] == "success" and info["ExecMainStatus"] == "75", (info["Result"], info["ExecMainStatus"])
        machine.succeed(f"test -e {garbage}")
        env = tool("A", "arm", "--txn", new_txn(), want=75)
        assert env["reason_class"] == "busy", env
        assert env["status"]["lock"]["held"] is True, env["status"]["lock"]
        machine.succeed("systemctl stop cwx-lockholder.service")
        wait_lock(False)
        # Now the REAL worker in the lock, not a stand-in: crashat parks the
        # launcher after step 1 (`fetching` written) and is killed, then runs
        # `_fetch` in the worker's own transient unit (its cgroup and
        # INVOCATION_ID pass the worker gate) parked after the dry run.
        tid_b = new_txn()
        park_at("A", "fetch", 1, ["--txn", tid_b, "--target", G["B"], "--closure", R.dig["B"]])
        machine.succeed("pkill -f 'cwx-test/crashat[.]py'")
        wait_lock(False)
        st = status()
        assert st["txn"]["state"] == "fetching" and "interrupted" in st["crash_state"], st
        machine.succeed("rm -f /run/cwx-crash-point /run/cwx-crash-release")
        worker = crashat_argv("A", "_fetch", 2, ["--txn", tid_b])
        machine.succeed(
            "systemd-run --unit=cogworx-pve-upgrade-fetch --collect --quiet -p KillMode=control-group -- $(command -v python3) "
            + " ".join(shlex.quote(a) for a in worker[1:])
        )
        point = wait_crash_point("journalctl -u cogworx-pve-upgrade-fetch.service -o cat --no-pager | tail -n 40")
        st = status()
        assert st["lock"]["held"] is True and st["lock"]["holder"] == "fetch-worker", (point, st["lock"])
        assert st["worker"] == {"active": True, "txn": tid_b}, st["worker"]
        assert st["txn"]["state"] == "fetching" and "interrupted" not in st["crash_state"], st
        machine.succeed("systemctl start cogworx-nix-gc.service")
        info = machine.get_unit_info("cogworx-nix-gc.service")
        assert info["Result"] == "success" and info["ExecMainStatus"] == "75", (info["Result"], info["ExecMainStatus"])
        machine.succeed(f"test -e {garbage}")
        machine.succeed("touch /run/cwx-crash-release")
        t0 = time.monotonic()
        while True:
            t = status()["txn"]
            if t["state"] != "fetching":
                break
            assert time.monotonic() - t0 < 600, t
            time.sleep(1)
        worker_log("B with GC skipped during the fetch")
        assert t["id"] == tid_b and t["state"] == "fetched", t
        seq = txn_seq()
        env = tool("B", "arm", "--txn", tid_b, want=65)
        assert env["reason_class"] == "not-committed-tool" and env["mutated"] is False, env
        assert txn_seq() == seq
        machine.succeed("systemctl start cogworx-nix-gc.service", timeout=dt.timedelta(minutes=10))
        info = machine.get_unit_info("cogworx-nix-gc.service")
        assert info["Result"] == "success" and info["ExecMainStatus"] == "0", (info["Result"], info["ExecMainStatus"])
        machine.fail(f"test -e {garbage}")
        machine.succeed(f"nix-store --check-validity $(nix-store -qR {G['B']})")

    with subtest("S5 FEASIBILITY: arm B, then a 330-byte S=c serial boots it exactly once"):
        arm(tid_b)
        vector("armed")
        boot_area_unchanged("arm B")
        off()
        n5 = new_nonce()
        s5 = blob("c", n5)
        assert len(s5) == 330, len(s5)
        b, st = boot(s5, "S5 S=c")
        assert b == "B", b
        assert machine.succeed("cat /sys/class/dmi/id/product_serial").strip() == s5
        machine.succeed("grep -q cwx.gen=B /proc/cmdline")
        assert st["trial"] is True and st["next_entry"] is None, st
        assert st["cwx_once"] == "c:" + n5, st["cwx_once"]
        assert st["entry0_init"] == G["A"], st["entry0_init"]
        vector("trial")

    with subtest("S6 commit B with A's tool, A kept as the rollback; a re-issued commit is a no-op"):
        st = tool("A", "commit", "--txn", tid_b, "--retain-until", RETAIN)["status"]
        R.committed = "B"
        assert st["txn"]["state"] == "committed" and st["committed"] == G["B"], st["txn"]
        assert st["rollback"]["path"] == G["A"] and st["rollback"]["recorded"] == G["A"], st["rollback"]
        assert st["rollback"]["retain_until"] == RETAIN, st["rollback"]
        assert st["entry0_init"] == G["B"] and st["system_head"] == G["B"], st
        assert st["grubcfg"]["candidate_entry"] is None, st["grubcfg"]
        rb = st["grubcfg"]["rollback_entry"]
        assert rb is not None and rb["init"] == G["A"], st["grubcfg"]
        assert st["cwx_rollback_entry"] == rb["path"] and st["next_entry"] is None, st
        assert st["crash_state"] == [], st["crash_state"]
        assert machine.succeed("ls -d /nix/var/nix/profiles/system-*-link | wc -l").strip() == "1"
        machine.fail(f"test -e {STAGED}")
        assert machine.succeed("readlink /nix/var/nix/gcroots/cogworx-pve-upgrade/committed").strip() == G["B"]
        boot_area_unchanged("commit B")
        vector("committed-with-rollback")
        idx6 = submenu_index(ROLLBACK_MENU)
        env = tool("A", "commit", "--txn", tid_b, "--retain-until", RETAIN)
        assert env["exit"] == 0 and env["mutated"] is False, env

    with subtest("S7 armed C, a v1 serial without S: GRUB refuses the one-shot (d:) and boots B"):
        tid, _ = fetch("C")
        st = arm(tid)
        rb = st["grubcfg"]["rollback_entry"]
        assert rb is not None and rb["init"] == G["A"] and st["cwx_rollback_entry"] == rb["path"], st
        idx7 = submenu_index(ROLLBACK_MENU)
        assert idx7 != idx6, (idx6, idx7)
        machine.log(f"CWX rollback submenu index {idx6} -> {idx7}; cwx_rollback_entry {st['cwx_rollback_entry']!r}")
        vector("armed-with-rollback")
        off()
        n7 = new_nonce()
        b, st = boot(blob("M", n7), "S7 no S")
        assert b == "B", b
        assert st["cwx_once"] == "d:" + n7 and st["next_entry"] is None, st
        abort(tid)

    with subtest("S8 armed C, no serial at all: the guard is inert (u:) and C boots"):
        tid, _ = fetch("C")
        arm(tid)
        off()
        b, st = boot(None, "S8 no serial")
        assert b == "C", b
        assert st["cwx_once"] == "u:" and st["next_entry"] is None and st["trial"] is True, st
        abort(tid)
        off()

    with subtest("S8b armed C, a serial that is not a raw v1 blob (still base64-encoded): inert (u:), C boots"):
        b, st = boot(None, "S8b plain")
        assert b == "B", b
        tid, _ = fetch("C")
        arm(tid)
        off()
        # What GRUB would read if PVE passed the blob through undecoded: a
        # guard that refused on ANY readable serial would boot B here.
        b64 = base64.b64encode(blob("c", new_nonce()).encode("ascii")).decode("ascii")
        b, st = boot(b64, "S8b base64 serial")
        assert b == "C", b
        assert machine.succeed("cat /sys/class/dmi/id/product_serial").strip() == b64
        assert st["cwx_once"] == "u:" and st["next_entry"] is None and st["trial"] is True, st
        abort(tid)
        off()

    with subtest("S9 S=r with a candidate armed boots the rollback; revert-commit with its tool"):
        b, st = boot(None, "S9 plain")
        assert b == "B", b
        tid, _ = fetch("C")
        arm(tid)
        off()
        n9 = new_nonce()
        b, st = boot(blob("r", n9), "S9 S=r")
        assert b == "A", b
        assert st["cwx_once"] == "d:" + n9, st["cwx_once"]
        abort(tid)
        st = tool("A", "revert-commit", "--txn", new_txn())["status"]
        R.committed = "A"
        assert st["txn"]["state"] == "reverted" and st["committed"] == G["A"], st["txn"]
        assert st["rollback"]["path"] is None and st["rollback"]["recorded"] is None, st["rollback"]
        assert st["entry0_init"] == G["A"] and st["system_head"] == G["A"], st
        assert st["grubcfg"]["rollback_entry"] is None and st["cwx_rollback_entry"] is None, st
        assert st["crash_state"] == [], st["crash_state"]
        boot_area_unchanged("revert-commit")
        off()

    with subtest("S10 a hard stop mid-trial lands on entry 0"):
        b, st = boot(None, "S10 plain")
        assert b == "A", b
        tid, _ = fetch("B")
        arm(tid)
        off()
        na = new_nonce()
        b, st = boot(blob("c", na), "S10 trial")
        assert b == "B", b
        machine.crash()
        b, st = boot(blob("c", new_nonce()), "S10 after the stop")
        assert b == "A", b
        assert st["cwx_once"] == "c:" + na, st["cwx_once"]
        abort(tid)

    with subtest("S11 a missing initrd: the kernel panics, panic=10 reboots, entry 0 boots"):
        tid, _ = fetch("I")
        arm(tid)
        initrd = machine.succeed(f"readlink -f {G['I']}/initrd").strip()
        machine.succeed(
            "mount -o remount,rw /nix/store || mount -o remount,bind,rw /nix/store || true",
            f"rm -f {initrd}",
            "sync",
            f"test ! -e {initrd}",
        )
        off()
        n = new_nonce()
        b, st = boot(blob("c", n), "S11 missing initrd", allow_reboot=True)
        assert b == "A", b
        con = machine.get_console_log()
        assert "Kernel panic" in con and "Rebooting in" in con, "no panic reboot on the console"
        assert st["cwx_once"] == "c:" + n, st["cwx_once"]
        abort(tid, "--release-staged")

    with subtest("S12 a stage-1 failure: sysrq crash, reboot, entry 0"):
        tid, _ = fetch("P")
        arm(tid)
        off()
        n = new_nonce()
        b, st = boot(blob("c", n), "S12 stage-1 panic", allow_reboot=True)
        assert b == "A", b
        assert "sysrq triggered crash" in machine.get_console_log(), "no sysrq crash on the console"
        assert st["cwx_once"] == "c:" + n, st["cwx_once"]
        abort(tid)

    with subtest("S13 a kernel that does not load: GRUB falls back to entry 0"):
        tid, _ = fetch("K")
        arm(tid)
        off()
        n = new_nonce()
        b, st = boot(blob("c", n), "S13 bad kernel")
        assert b == "A", b
        assert "Falling back to" in machine.get_console_log(), "no GRUB fallback on the console"
        assert st["cwx_once"] == "c:" + n, st["cwx_once"]
        abort(tid)

    with subtest("S14 the SMBIOS 3.0 (64-bit) entry point"):
        tid, _ = fetch("B")
        arm(tid)
        off()
        b, st = boot(blob("c", new_nonce()), "S14 SMBIOS 3.0", smbios_ep="64")
        assert b == "B", b
        # grep reads all of dmesg (no -q/-m): an early exit would SIGPIPE
        # dmesg and fail the pipeline.
        machine.log("CWX dmesg SMBIOS: " + machine.succeed("dmesg | grep 'SMBIOS' || true").strip())
        machine.succeed("dmesg | grep 'SMBIOS 3\\.' >/dev/null")
        abort(tid)
        off()

    with subtest("S15 final: a plain boot, the boot area as at boot0"):
        b, st = boot(None, "S15 final")
        assert b == "A", b
        assert st["committed"] == G["A"] and st["crash_state"] == [], st
        boot_area_unchanged("final")


# --- suite powercut ---------------------------------------------------------------


def suite_powercut() -> None:
    stale_root = ""
    # k=5 first, so a rollback exists for k=1..4 and `pre` is restored.
    for k in (5, 1, 2, 3, 4, 6, 7):
        with subtest(f"a power cut after commit step {k}"):
            x = R.committed
            t = CYCLE[(CYCLE.index(x) + 1) % len(CYCLE)]
            tid, _ = fetch(t)
            arm(tid)
            off()
            b, st = boot(blob("c", new_nonce()), f"commit {k} trial")
            assert b == t, b
            pre_rb = st["rollback"]["path"]
            pre_entry = st["cwx_rollback_entry"]
            crash_after(x, "commit", k, ["--txn", tid, "--retain-until", RETAIN])
            b, st = boot(blob("M", new_nonce()), f"commit {k} after the cut")
            assert b == (x if k <= 4 else t), (k, b)
            assert st["txn"]["state"] == "committing" and "interrupted" in st["crash_state"], st
            if k == 2:
                # head = target, entry 0 = old
                assert st["system_head"] == G[t] and st["entry0_init"] == G[x], st
            if k <= 4:
                st = abort(tid)
                assert st["rollback"]["path"] == pre_rb, (st["rollback"], pre_rb)
                rb = st["grubcfg"]["rollback_entry"]
                if pre_rb is None:
                    assert rb is None and st["cwx_rollback_entry"] is None, st
                else:
                    assert rb is not None and rb["init"] == pre_rb and st["cwx_rollback_entry"] == rb["path"], st
                    if k <= 2:
                        # The rollback profile was never touched: the same title.
                        assert st["cwx_rollback_entry"] == pre_entry, (st["cwx_rollback_entry"], pre_entry)
            else:
                st = tool(x, "commit", "--txn", tid, "--retain-until", RETAIN)["status"]
                assert st["txn"]["state"] == "committed", st["txn"]
                R.committed = t
            invariants(f"commit {k}")

    with subtest("--no-rollback: a power cut after commit step 3 (rollback removed), then after abort step 4 (pre restored)"):
        x = R.committed
        t = CYCLE[(CYCLE.index(x) + 1) % len(CYCLE)]
        tid, _ = fetch(t)
        arm(tid)
        off()
        b, st = boot(blob("c", new_nonce()), "no-rollback 3 trial")
        assert b == t, b
        pre_rb = st["rollback"]["path"]
        assert pre_rb is not None, st["rollback"]
        crash_after(x, "commit", 3, ["--txn", tid, "--no-rollback"])
        b, st = boot(blob("M", new_nonce()), "no-rollback 3 after the cut")
        assert b == x, b
        assert st["txn"]["state"] == "committing" and "interrupted" in st["crash_state"], st
        assert st["rollback"]["path"] is None and st["rollback"]["recorded"] == pre_rb, st["rollback"]
        # Abort of a committing txn: step 4 puts the rollback back from `pre`.
        crash_after(x, "abort", 4, ["--txn", tid])
        b, st = boot(blob("M", new_nonce()), "abort 4 of committing after the cut")
        assert b == x, b
        assert st["txn"]["state"] == "aborting" and "interrupted" in st["crash_state"], st
        assert st["rollback"]["path"] == pre_rb, st["rollback"]
        st = abort(tid)
        assert st["rollback"]["path"] == pre_rb and st["rollback"]["recorded"] == pre_rb, st["rollback"]
        invariants("no-rollback 3, abort 4")

    with subtest("--no-rollback: a power cut after commit step 8 (the closing write); the lost root flip only leaks"):
        x = R.committed
        t = CYCLE[(CYCLE.index(x) + 1) % len(CYCLE)]
        tid, _ = fetch(t)
        arm(tid)
        off()
        b, st = boot(blob("c", new_nonce()), "no-rollback 8 trial")
        assert b == t, b
        crash_after(x, "commit", 8, ["--txn", tid, "--no-rollback"])
        b, st = boot(blob("M", new_nonce()), "no-rollback 8 after the cut")
        assert b == t, b
        assert st["txn"]["state"] == "committed" and st["committed"] == G[t], st["txn"]
        assert st["rollback"]["path"] is None and st["rollback"]["recorded"] is None, st["rollback"]
        # Step 9 never ran: the old system is still rooted (a leak), never
        # unrooted while txn.json named it.
        assert machine.succeed(f"readlink {COMMITTED_ROOT}").strip() == G[x]
        env = tool(x, "commit", "--txn", tid, "--no-rollback")
        assert env["mutated"] is False, env
        R.committed = t
        invariants("no-rollback 8")
        stale_root = G[x]

    for k in range(1, 10):
        with subtest(f"a power cut after abort step {k}"):
            x = R.committed
            t = "C" if x == "B" else "B"
            tid, _ = fetch(t)
            if k == 1:
                # fetch re-asserted the root the lost flip left behind.
                root = machine.succeed(f"readlink {COMMITTED_ROOT}").strip()
                assert root == G[x] and root != stale_root, root
            arm(tid)
            crash_after(x, "abort", k, ["--txn", tid])
            n = new_nonce()
            b, st = boot(blob("M", n), f"abort {k} after the cut")
            assert b == x, (k, b)
            if k == 1:
                # The one-shot was still pending: the guard refused it.
                assert st["cwx_once"] == "d:" + n, st["cwx_once"]
            else:
                # Step 2 cleared it: no one-shot was consumed, so the guard
                # wrote nothing (arm unset cwx_once). A one-shot left pending
                # would show here as d:, even though X boots either way.
                assert st["cwx_once"] is None, (k, st["cwx_once"])
            assert st["txn"]["state"] == "aborting" and "interrupted" in st["crash_state"], st
            abort(tid)
            invariants(f"abort {k}")

    with subtest("a power cut after arm step 6: the one-shot is durable, S=c boots the candidate, abort repairs"):
        x = R.committed
        t = "C" if x == "B" else "B"
        tid, _ = fetch(t)
        crash_after(x, "arm", 6, ["--txn", tid])
        n = new_nonce()
        b, st = boot(blob("c", n), "arm 6 after the cut")
        assert b == t, b
        assert st["cwx_once"] == "c:" + n and st["next_entry"] is None, st
        assert st["txn"]["state"] == "arming" and "interrupted" in st["crash_state"], st
        abort(tid)
        off()
        b, st = boot(blob("M", new_nonce()), "after the abort from the candidate")
        assert b == x, b
        invariants("arm 6")


setup()
if SUITE == "main":
    suite_main()
elif SUITE == "powercut":
    suite_powercut()
else:
    raise AssertionError("unknown suite " + SUITE)

machine.log("CWX TIMES " + json.dumps({
    "boots": R.boots,
    "installer_runs": {"n": len(R.installs), "max": max(R.installs or [0.0]), "mean": round(sum(R.installs) / max(1, len(R.installs)), 2)},
    "verbs": {v: {"n": len(ts), "max": max(ts)} for v, ts in sorted(R.verbs.items())},
}))
machine.shutdown()
