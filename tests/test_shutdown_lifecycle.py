#!/usr/bin/env python3
"""Run the actual launcher/CLI lifecycle with only external VM tools replaced.

Unlike test_shutdown.py, no launcher functions or admission wiring are copied.
The production substitution boundary supplies a hermetic runner and helper.
"""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest


if len(sys.argv) > 1 and sys.argv[1] == "--qemu":
    runtime = Path.cwd()
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(runtime / "cogbox.socket"))
    sock.listen()
    (runtime / "fake-qemu-ready").touch()
    while True:
        for marker, code in (("request", 0), ("panic", 0), ("crash", 4)):
            if (runtime / marker).exists():
                sock.close()
                (runtime / "cogbox.socket").unlink()
                sys.exit(code)
        time.sleep(.01)

if len(sys.argv) > 1 and sys.argv[1] in ("--helper", "--panic-helper"):
    runtime = Path.cwd()
    (runtime / ("panic" if sys.argv[1] == "--panic-helper" else "request")).touch()
    while (runtime / "cogbox.socket").exists():
        time.sleep(.01)
    sys.exit(0)

LAUNCH, MODULE, CLI = (Path(p).resolve() for p in sys.argv[1:4])
TEST = str(Path(__file__).resolve())
sys.argv = sys.argv[:1] + sys.argv[4:]
Q = shlex.quote


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cogbox-lifecycle-")
        self.root = Path(self.tmp.name)
        self.runtime = self.root / "run" / "cogbox-demo"
        self.runtime.parent.mkdir()
        self.runner = self.root / "runner"
        (self.runner / "bin").mkdir(parents=True)
        self.bash = shutil.which("bash")
        self.flock = shutil.which("flock")
        self.children = []
        for name, mode in (("microvm-run", "--qemu"), ("microvm-shutdown", "--helper")):
            self.executable(self.runner / "bin" / name,
                            f"#!{self.bash}\nexec {Q(sys.executable)} {Q(TEST)} {mode}\n")
        self.flock_gate = self.root / "flock-gate"
        self.admission_entered = self.root / "admission-entered"
        self.executable(self.flock_gate, f"#!{self.bash}\n"
                        f"if [ -e {Q(str(self.root / 'hold-admission'))} ]; then\n"
                        f"  touch {Q(str(self.admission_entered))}\nfi\n"
                        f"while [ -e {Q(str(self.root / 'hold-admission'))} ]; do sleep .01; done\n"
                        f"exec {Q(self.flock)} \"$@\"\n")
        self.script = self.root / "cogbox-launch.sh"
        source = LAUNCH.read_text()
        substitutions = {"#!/usr/bin/env bash": f"#!{self.bash}",
                         "@harnesses@": "", "@shutdown@": str(MODULE),
                         "@flock@": str(self.flock_gate), "@runner@": str(self.runner),
                         "@runtimeDir@": "/tmp/cogbox", "@cogbox@": str(CLI)}
        for old, new in substitutions.items():
            source = source.replace(old, new)
        self.executable(self.script, source)
        # The launcher's port probe resolves `timeout` through the inherited
        # PATH. This shim marks probe entry and parks the probe while hold-probe
        # exists, then becomes the real timeout -- the only way to hold the
        # launcher inside the (millisecond) loopback probe deterministically.
        # It keys on the probe's own argv (`timeout 1 bash -c ...`): the
        # launcher runs other bounded steps through `timeout` before the probe
        # (the live-apply housekeeping verb, the boot snapshot's fsyncs and
        # `cp -al`), and those must pass straight through.
        self.hold_probe = self.root / "hold-probe"
        self.probe_entered = self.root / "probe-entered"
        (self.root / "bin").mkdir()
        self.executable(self.root / "bin" / "timeout", f"#!{self.bash}\n"
                        f"if [ \"$1 $2 $3\" = '1 bash -c' ]; then\n"
                        f"touch {Q(str(self.probe_entered))}\n"
                        f"while [ -e {Q(str(self.hold_probe))} ]; do sleep .01; done\n"
                        f"fi\n"
                        f"exec {Q(shutil.which('timeout'))} \"$@\"\n")
        self.env = dict(os.environ, HOME=str(self.root), XDG_RUNTIME_DIR=str(self.runtime.parent),
                        XDG_CONFIG_HOME=str(self.root / "config"),
                        COGBOX_DATA=str(self.root / "data"),
                        COGBOX_LAUNCH_SCRIPT=str(self.script),
                        PATH=str(self.root / "bin") + os.pathsep + os.environ["PATH"])
        self.env.pop("SUDO_USER", None)

    @staticmethod
    def executable(path, content):
        path.write_text(content)
        path.chmod(0o700)

    def tearDown(self):
        # Only processes named by this fixture's current launch and its own
        # explicitly created sentinel children are eligible for cleanup.
        launch = self.runtime / "launch"
        if launch.exists():
            fields = launch.read_text().split()
            if len(fields) == 4:
                pid = int(fields[2])
                try:
                    actual = self.proc_identity(pid)
                    if actual[1] == int(fields[3]) and os.getpgid(pid) == pid:
                        os.killpg(pid, signal.SIGKILL)
                except (ProcessLookupError, FileNotFoundError):
                    pass
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.communicate()
        self.tmp.cleanup()

    @staticmethod
    def proc_identity(pid):
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return int(fields[1]), int(fields[19]), fields[0]

    def wait_for(self, condition, timeout=6):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if condition():
                return
            time.sleep(.02)
        log = self.runtime / "cogbox.log"
        self.fail("condition timed out: " + (log.read_text() if log.exists() else "no log"))

    def cli(self, verb, *args, ok=True):
        result = subprocess.run([str(CLI), verb, "-n", "demo", *args], env=self.env,
                                capture_output=True, text=True, timeout=12)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def start(self):
        self.cli("start", "--no-ssh", "--no-auto-keys", "--yes", "--network", "none")
        self.wait_for(lambda: (self.runtime / "fake-qemu-ready").exists())
        identity = (self.runtime / "launch").read_text().split()
        self.assertEqual(int((self.runtime / "pid").read_text()), int(identity[2]))
        self.assertEqual(self.proc_identity(int(identity[2]))[1], int(identity[3]))
        qemu = int((self.runtime / "qemu.pid").read_text())
        self.assertEqual(self.proc_identity(qemu)[0], int(identity[2]))
        return identity

    def ended(self, identity):
        self.wait_for(lambda: (self.runtime / "stop-result").exists())
        self.wait_for(lambda: not (self.runtime / "pid").exists())
        self.assertFalse((self.runtime / "qemu.pid").exists())
        result = (self.runtime / "stop-result").read_text().split()
        self.assertEqual(result[:4], identity)
        self.assertNotEqual(result[-1], "graceful")
        self.assertTrue((self.runtime / "cogbox.log").exists())
        self.wait_for(lambda: self.lock_free())
        return result[-1]

    def lock_free(self):
        with open(str(self.runtime) + ".lock", "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except BlockingIOError:
                return False

    def test_actual_start_stop_start(self):
        before = self.start()
        stopped = self.cli("stop")
        self.assertIn("could not be verified", stopped.stdout)
        self.assertEqual(self.ended(before), "unverified")
        after = self.start()
        self.assertNotEqual(before[1], after[1])
        self.assertNotEqual(before[2:], after[2:])
        self.cli("stop")
        self.ended(after)

    def test_actual_crash_and_panic_exit_allow_restart(self):
        for mode in ("crash", "panic"):
            with self.subTest(mode=mode):
                before = self.start()
                (self.runtime / mode).touch()
                # Unrequested end: distinct from a requested stop's `unverified`.
                self.assertEqual(self.ended(before), "exited")
                stopped = self.cli("stop")
                self.assertIn("exited on its own", stopped.stdout)
                self.cli("restart", "--no-ssh")
                self.wait_for(lambda: (self.runtime / "fake-qemu-ready").exists())
                after = (self.runtime / "launch").read_text().split()
                self.assertNotEqual(before[1], after[1])
                self.cli("stop")
                self.ended(after)

    def test_panic_equivalent_during_stop_is_unverified(self):
        self.executable(self.runner / "bin" / "microvm-shutdown",
                        f"#!{self.bash}\nexec {Q(sys.executable)} {Q(TEST)} --panic-helper\n")
        before = self.start()
        result = self.cli("stop")
        self.assertIn("could not be verified", result.stdout)
        self.assertEqual(self.ended(before), "unverified")
        self.assertTrue((self.runtime / "panic").exists())
        self.assertFalse((self.runtime / "request").exists())

    def test_stale_pid_hints_never_signal_or_block_unrelated_process(self):
        sentinel = subprocess.Popen(["sleep", "30"])
        self.children.append(sentinel)
        self.runtime.mkdir()
        identity = f"v1 01234567-1234-1234-1234-123456789abc {sentinel.pid} 1"
        (self.runtime / "launch").write_text(identity + "\n")
        (self.runtime / "pid").write_text(str(sentinel.pid))
        (self.runtime / "qemu.pid").write_text(str(sentinel.pid))
        for outcome in ("graceful", "unverified"):
            (self.runtime / "stop-result").write_text(identity + " " + outcome + "\n")
            self.assertIn("could not be verified", self.cli("stop").stdout)
            self.assertIsNone(sentinel.poll())
        (self.runtime / "stop-result").write_text(identity + " failed\n")
        self.cli("restart", "--no-ssh", ok=False)
        self.assertIsNone(sentinel.poll())
        (self.runtime / "stop-result").write_text(identity + " unverified\n")
        fresh = self.start()
        self.assertIsNone(sentinel.poll())
        self.assertNotEqual(fresh[1], identity.split()[1])
        self.cli("stop")
        self.ended(fresh)

    def test_start_daemon_pass_skips_repin_and_drops_marker(self):
        # `cogbox start` runs the launcher twice: the foreground --init-only
        # pass owns the boot-time plugin re-pin, the daemon pass (bound to
        # start's 60s QEMU deadline) must skip it via COGBOX_SKIP_REPIN=1, and
        # the launcher must not hand that marker on to QEMU.
        passes = self.root / "passes"
        wrapper = self.root / "launch-wrapper.sh"
        self.executable(wrapper, f"#!{self.bash}\n"
                        f"m=unset; [ -z \"${{COGBOX_SKIP_REPIN+x}}\" ] || m=\"$COGBOX_SKIP_REPIN\"\n"
                        f"init=daemon; for a in \"$@\"; do [ \"$a\" != --init-only ] || init=init; done\n"
                        f"echo \"$init $m\" >> {Q(str(passes))}\n"
                        f"exec {Q(str(self.script))} \"$@\"\n")
        self.env["COGBOX_LAUNCH_SCRIPT"] = str(wrapper)
        identity = self.start()
        self.assertEqual(passes.read_text().split("\n")[:2], ["init unset", "daemon 1"])
        qemu = int((self.runtime / "qemu.pid").read_text())
        environ = Path(f"/proc/{qemu}/environ").read_bytes().split(b"\0")
        self.assertEqual([e for e in environ if e.startswith(b"COGBOX_SKIP_REPIN=")], [])
        self.cli("stop")
        self.ended(identity)

    def test_boot_snapshot_promotion_and_trash_emptied_by_init_pass(self):
        # Live-apply boot state through the real CLI and the real
        # __plugin-apply-preboot: every daemon pass snapshots what it boots and
        # promotes it to apply/base, retiring the previous base into
        # apply/trash by RENAME; only `cogbox start`'s --init-only pass deletes
        # the trash. A box with no plugins records comp `none`.
        icd = self.root / "config" / "cogbox" / "instances" / "demo"
        apply = icd / "apply"
        first = self.start()
        base1 = os.readlink(apply / "base")
        snap1 = apply / base1
        meta = json.loads((snap1 / "meta.json").read_text())
        self.assertEqual((meta["id"], meta["comp"], meta["runner"]),
                         (snap1.name, "none", str(self.runner)))
        self.assertEqual(json.loads((snap1 / "state.json").read_text()), {"plugins": [], "tagged": {}})
        self.assertTrue((snap1 / "src").is_dir())
        self.assertFalse((apply / "booting").exists())
        booted = (self.runtime / "booted-runner").read_text().split("\n")
        self.assertEqual(booted[1:], [str(self.runner), "none", ""])
        self.cli("stop")
        self.ended(first)
        # A tree retired by an earlier boot, as the GC leaves it.
        planted = apply / "trash" / "00000000000000aa"
        (planted / "src" / "p").mkdir(parents=True)
        (planted / "src" / "p" / "f").write_text("x")
        second = self.start()
        base2 = os.readlink(apply / "base")
        self.assertNotEqual(base1, base2)
        self.assertFalse(planted.exists(), "the init pass did not empty the trash")
        self.assertTrue((apply / "trash" / snap1.name / "meta.json").exists(),
                        "the daemon pass did not retire the previous base into the trash")
        self.assertEqual(sorted(p.name for p in (apply / "snap").iterdir()), [Path(base2).name])
        self.cli("stop")
        self.ended(second)

    def test_live_lock_blocks_cli_and_direct_launcher(self):
        before = self.start()
        # PID hints are not the lock, even while the owned child is still live.
        (self.runtime / "pid").unlink()
        (self.runtime / "qemu.pid").unlink()
        self.cli("start", "--no-ssh", ok=False)
        direct = subprocess.run([str(self.script), "--name", "demo"], env=self.env,
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(direct.returncode, 75, direct.stdout + direct.stderr)
        self.assertEqual((self.runtime / "launch").read_text().split(), before)
        self.cli("stop")
        self.ended(before)

    def test_stop_during_port_probe(self):
        # The shutdown handlers and run identity must exist BEFORE the port
        # probe, while the legacy pid marker follows it (cogbox ssh needs the
        # ssh-endpoint written just before pid). A stop that lands inside the
        # probe must be honored, recorded against this launch, and exit 0.
        self.cli("init", "--no-auto-keys", "--yes", "--network", "none")
        self.hold_probe.touch()
        starter = subprocess.Popen([str(CLI), "start", "-n", "demo", "--no-ssh"], env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.children.append(starter)
        try:
            self.wait_for(self.probe_entered.exists)
            # The ordering proof: identity published, pid not yet.
            self.assertTrue((self.runtime / "launch").exists(), "launch identity missing during the port probe")
            self.assertFalse((self.runtime / "pid").exists(), "pid published before the port probe finished")
            identity = (self.runtime / "launch").read_text().split()
            self.assertEqual(len(identity), 4)
            # delete consults the lifetime flock, not the (absent) pid file: it
            # must refuse to remove a launch that is still starting.
            kept = [d for d in (self.root / "config", self.root / "data", self.runtime) if d.exists()]
            self.assertIn(self.runtime, kept)
            self.cli("delete", "-y", ok=False)
            for d in kept:
                self.assertTrue(d.exists(), f"delete removed {d} from under a starting launch")
            self.assertFalse(self.lock_free(), "delete released the lifetime lock")
            stopper = subprocess.Popen([str(CLI), "stop", "-n", "demo"], env=self.env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.children.append(stopper)
            # Let the stop caller fence the launcher and deliver TERM while the
            # probe is still parked; bash defers the trap until the command
            # substitution around the probe returns.
            time.sleep(.3)
        finally:
            self.hold_probe.unlink()
        out, err = stopper.communicate(timeout=8)
        self.assertEqual(stopper.returncode, 0, out + err)
        starter.communicate(timeout=8)
        self.assertNotEqual(starter.returncode, 0)
        self.wait_for(lambda: (self.runtime / "stop-result").exists())
        result = (self.runtime / "stop-result").read_text().split()
        self.assertEqual(result[:4], identity)
        # No QEMU was ever launched, so the launcher records already-stopped;
        # `unverified` is tolerated only if the deferred trap ran after launch.
        self.assertIn(result[-1], ("already-stopped", "unverified"))
        self.assertFalse((self.runtime / "pid").exists())
        self.wait_for(lambda: self.lock_free())

    def test_start_failed_before_qemu_does_not_block_restart(self):
        # A launcher that dies AFTER the run identity exists but BEFORE QEMU
        # (here: an --add-dir that vanishes while the port probe is parked, so
        # the staging realpath check fails) must record `start-failed`, which
        # `stop` reports as not running and `restart` sails past. The generic
        # `failed` would make every pre-QEMU start failure un-restartable.
        self.cli("init", "--no-auto-keys", "--yes", "--network", "none")
        extra = self.root / "extra"
        extra.mkdir()
        self.hold_probe.touch()
        starter = subprocess.Popen([str(CLI), "start", "-n", "demo", "--no-ssh", "--add-dir", str(extra)],
                                   env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.children.append(starter)
        try:
            self.wait_for(self.probe_entered.exists)
            extra.rmdir()
        finally:
            self.hold_probe.unlink()
        out, err = starter.communicate(timeout=8)
        self.assertNotEqual(starter.returncode, 0, out + err)
        self.wait_for(lambda: (self.runtime / "stop-result").exists())
        result = (self.runtime / "stop-result").read_text().split()
        self.assertEqual(result[:4], (self.runtime / "launch").read_text().split())
        self.assertEqual(result[-1], "start-failed")
        self.assertFalse((self.runtime / "qemu.pid").exists())
        self.wait_for(lambda: self.lock_free())
        stopped = self.cli("stop")
        self.assertIn("start failed; see cogbox.log", stopped.stdout)
        # restart = stop + start: the retained record must not block the start.
        restarted = self.cli("restart", "--no-ssh")
        self.assertIn("start failed; see cogbox.log", restarted.stdout)
        self.wait_for(lambda: (self.runtime / "fake-qemu-ready").exists())
        identity = (self.runtime / "launch").read_text().split()
        self.assertNotEqual(identity[1], result[1])
        self.cli("stop")
        self.ended(identity)

    def test_existing_start_rechecks_after_foreground_init(self):
        self.cli("init", "--no-auto-keys", "--yes", "--network", "none")
        original = self.script.with_name("original-launcher")
        self.script.rename(original)
        config_dir = self.root / "config/cogbox/instances/demo"
        self.executable(self.script, f"#!{self.bash}\n"
                        f"case \" $* \" in *' --init-only '*)\n"
                        f"  {Q(str(original))} \"$@\" || exit $?\n"
                        f"  rm -rf {Q(str(config_dir))}\n"
                        f"  exit 0 ;;\nesac\n"
                        f"exec {Q(str(original))} \"$@\"\n")
        self.cli("start", "--existing", "--no-ssh", ok=False)
        self.assertFalse(config_dir.exists(), "daemon phase recreated a deleted instance")

    def test_launcher_port_update_and_waiting_writer_preserve_both_changes(self):
        self.cli("init", "--no-auto-keys", "--yes", "--network", "rules")
        cfg = self.root / "config/cogbox/instances/demo/config.json"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            occupied = listener.getsockname()[1]
            doc = json.loads(cfg.read_text())
            doc["sshPort"] = occupied
            doc["future"] = {"keep": True}
            cfg.write_text(json.dumps(doc))
            self.hold_probe.touch()
            starter = subprocess.Popen([str(CLI), "start", "--existing", "-n", "demo", "--no-ssh", "--network", "none"],
                                       env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.children.append(starter)
            try:
                self.wait_for(self.probe_entered.exists)
                writer = subprocess.Popen([str(CLI), "rules", "add", "allow", "192.0.2.1/32", "-n", "demo"],
                                          env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.children.append(writer)
                with self.assertRaises(subprocess.TimeoutExpired):
                    writer.communicate(timeout=.2)
            finally:
                self.hold_probe.unlink()
            out, err = starter.communicate(timeout=8)
            self.assertEqual(starter.returncode, 0, out + err)
            out, err = writer.communicate(timeout=8)
            self.assertEqual(writer.returncode, 0, out + err)
        actual = json.loads(cfg.read_text())
        self.assertNotEqual(actual["sshPort"], occupied)
        self.assertEqual(actual["future"], doc["future"])
        self.assertTrue(any(r.get("allow") == "192.0.2.1/32" for r in actual["network"]["rules"]))
        # Successful live config mutation also proves the VM did not inherit
        # the config lock for its lifetime.
        self.cli("stop")

    def test_stale_qemu_hint_cannot_report_new_start_ready(self):
        self.cli("init", "--no-auto-keys", "--yes", "--network", "none")
        self.runtime.mkdir()
        (self.runtime / "qemu.pid").write_text(str(os.getpid()))
        hold = self.root / "hold-admission"
        hold.touch()
        caller = subprocess.Popen([str(CLI), "start", "-n", "demo", "--no-ssh"], env=self.env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.children.append(caller)
        try:
            self.wait_for(self.admission_entered.exists)
            # Prove the daemon reached admission before observing the caller:
            # time spent starting the process must not make this test pass.
            with self.assertRaises(subprocess.TimeoutExpired,
                                   msg="stale qemu.pid was accepted as new readiness"):
                caller.communicate(timeout=.5)
        finally:
            hold.unlink()
            self.wait_for(lambda: (self.runtime / "launch").exists())
        out, err = caller.communicate(timeout=8)
        self.assertEqual(caller.returncode, 0, out + err)
        self.wait_for(lambda: (self.runtime / "fake-qemu-ready").exists())
        identity = (self.runtime / "launch").read_text().split()
        self.cli("stop")
        self.ended(identity)


    # --- live plugin apply: the gate, cogbox stop's step, a pending rollback ---

    HOLDER = (
        "import os, signal, sys, time\n"
        "log, sock, ready, mode = sys.argv[1:5]\n"
        "def term(s, f):\n"
        "    with open(log, 'a') as fh:\n"
        "        fh.write('term qemu=%s\\n' % os.path.exists(sock))\n"
        "    if mode == 'exit':\n"
        "        os._exit(0)\n"
        "signal.signal(signal.SIGTERM, term)\n"
        "open(ready, 'w').close()\n"
        "while True:\n"
        "    time.sleep(.05)\n"
    )

    def icd(self):
        return self.root / "config" / "cogbox" / "instances" / "demo"

    def holder(self, mode):
        """A process apply/active can name: it logs each SIGTERM (and whether
        the fake QEMU's socket still existed then) and exits on it, or, with
        mode `ignore`, keeps running (an apply inside its record section)."""
        log, ready = self.root / f"holder-{mode}.log", self.root / f"holder-{mode}.ready"
        proc = subprocess.Popen([sys.executable, "-c", self.HOLDER, str(log),
                                 str(self.runtime / "cogbox.socket"), str(ready), mode])
        self.children.append(proc)
        self.wait_for(ready.exists)
        return proc, log

    def plant_active(self, pid, phase):
        apply = self.icd() / "apply"
        apply.mkdir(parents=True, exist_ok=True)
        (apply / "active").write_text(json.dumps({
            "pid": pid, "starttime": self.proc_identity(pid)[1], "unit": None, "invocation": None,
            "op": None, "gen": "0123456789abcdef", "scratch_id": "00000000000000aa",
            "phase": phase, "deadline": int(time.clock_gettime(time.CLOCK_BOOTTIME)) + 600}) + "\n")

    def plant_inflight(self, scope=()):
        store = "/nix/store/" + "a" * 32
        inflight = self.icd() / "apply" / "inflight.json"
        inflight.write_text(json.dumps({
            "G": "0123456789abcdef", "op": None, "scratch_id": "00000000000000aa",
            "base_id": "00000000000000bb", "nonce": (self.runtime / "qemu.start").read_text().strip(),
            "boot_id": "0123abcd-0000-4000-8000-0123456789ab",
            "host_boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "R": store + "-microvm-run", "key": "k#cogbox", "T": store + "-t", "P": store + "-p",
            "scope": list(scope), "expires_at": int(time.clock_gettime(time.CLOCK_BOOTTIME)) + 3600,
            "hops": {"streak": 0, "confirm_failed": False, "rfails": 0, "seen": None}}) + "\n")
        return inflight

    @staticmethod
    def entry(name):
        return {"name": name, "url": f"path:/nonexistent/{name}", "narHash": "sha256-" + name.upper() * 43 + "="}

    def plugins(self):
        return json.loads((self.icd() / "config.json").read_text())["plugins"]

    def set_plugins(self, entries):
        path = self.icd() / "config.json"
        config = json.loads(path.read_text())
        config["plugins"] = entries
        path.write_text(json.dumps(config) + "\n")

    def plant_base(self, entries):
        """A complete snapshot 00000000000000bb (the base plant_inflight and
        plant_intent name) holding `entries` and no composition."""
        snap = self.icd() / "apply" / "snap" / "00000000000000bb"
        (snap / "src").mkdir(parents=True)
        (snap / "state.json").write_text(json.dumps({"plugins": entries, "tagged": {}}) + "\n")
        (snap / "meta.json").write_text(json.dumps({"id": "00000000000000bb", "comp": "none",
                                                    "runner": None, "key": None}) + "\n")

    @staticmethod
    def added(entry):
        """The scope of a generation that added `entry` (rolled back: removed)."""
        return {"name": entry["name"], "action": "removed", "from_rev": entry["narHash"],
                "from_nar_hash": entry["narHash"]}

    def plant_intent(self, scope):
        rollback = self.icd() / "apply" / "rollback"
        rollback.mkdir(parents=True, exist_ok=True)
        (rollback / "0123456789abcdef.intent").write_text(json.dumps({
            "G": "0123456789abcdef", "reason": "activation_hang", "target": "base",
            "target_id": "00000000000000bb", "scope": list(scope)}) + "\n")

    def records(self):
        path = self.icd() / "apply" / "rollbacks.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def fake_ssh(self, reply=None):
        """An env whose `ssh` answers a `status` hop with `reply` (the guest
        helper's key=value lines), or fails as an unreachable guest does (255)."""
        fake = self.root / "fake-ssh"
        fake.mkdir(exist_ok=True)
        body = "exit 255\n" if reply is None else \
            f"case \" $* \" in *\" status \"*|*\"'status'\"*) printf '%s' {Q(reply)}; exit 0 ;; esac\nexit 255\n"
        self.executable(fake / "ssh", f"#!{self.bash}\n{body}")
        return dict(self.env, PATH=str(fake) + os.pathsep + self.env["PATH"])

    def plugin(self, *args, env=None):
        return subprocess.run([str(CLI), "plugin", "-n", "demo", *args], env=env or self.env,
                              capture_output=True, text=True, timeout=30)

    def test_stop_signals_a_live_apply_first_and_never_sigkills_it(self):
        # cogbox stop's apply step runs before QEMU is signalled: SIGTERM to
        # the holder apply/active names (a 2 s grace, never a SIGKILL), with
        # no config lock (the test holds it throughout), at most 5 s.
        identity = self.start()
        proc, log = self.holder("ignore")
        self.plant_active(proc.pid, "record")
        locks = self.root / "config" / "cogbox" / ".locks"
        with open(locks / "demo.lock", "a") as config_lock:
            fcntl.flock(config_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            began = time.monotonic()
            self.cli("stop")
            took = time.monotonic() - began
        self.ended(identity)
        self.assertEqual(log.read_text(), "term qemu=True\n", "the holder was not signalled once, before QEMU")
        self.assertIsNone(proc.poll(), "the apply holder was killed")
        self.assertLess(took, 9)

    def test_stop_short_hop_leaves_inflight_and_its_evidence_alone(self):
        # With the holder gone, one lock-free `status` hop under a 3 s kill;
        # an unreachable guest settles nothing and never counts toward rfails.
        identity = self.start()
        proc, log = self.holder("exit")
        self.plant_active(proc.pid, "guest")
        inflight = self.plant_inflight()
        before = inflight.read_text()
        began = time.monotonic()
        self.cli("stop")
        took = time.monotonic() - began
        self.ended(identity)
        self.assertEqual(log.read_text(), "term qemu=True\n")
        self.assertEqual(inflight.read_text(), before)
        self.assertFalse((self.icd() / "apply" / "rollback").exists())
        self.assertLess(took, 12)

    def test_plugin_change_behind_a_finishing_live_apply_exits_69_untouched(self):
        # The apply gate: a guest-phase apply (apply/active names a live
        # holder; the test holds the apply flock for it) is waited for with a
        # progress line, at most COGBOX_APPLY_WAIT_MAX, then exit 69 with
        # nothing read or written. Such an apply is never signalled.
        identity = self.start()
        self.cli("stop")
        self.ended(identity)
        proc, log = self.holder("exit")
        self.plant_active(proc.pid, "guest")
        config = (self.icd() / "config.json").read_text()
        locks = self.root / "config" / "cogbox" / ".locks"
        with open(locks / "demo.apply.lock", "a") as apply_lock:
            fcntl.flock(apply_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            began = time.monotonic()
            result = self.plugin("del", "nothing", "-y", env=dict(self.env, COGBOX_APPLY_WAIT_MAX="1"))
            took = time.monotonic() - began
        self.assertEqual(result.returncode, 69, result.stdout + result.stderr)
        self.assertIn("cogbox plugin: waiting for the live apply of generation 0123456789abcdef "
                      "to finish (at most 1 s)", result.stderr)
        self.assertIn("cogbox plugin: error: busy: a live apply is finishing (generation "
                      "0123456789abcdef); try again in a few minutes", result.stderr)
        self.assertLess(took, 6)
        self.assertEqual((self.icd() / "config.json").read_text(), config)
        self.assertFalse(log.exists(), "a guest-phase apply was signalled")
        self.assertIsNone(proc.poll())

    def test_pending_rollback_refuses_start_and_plugin_changes_until_abandoned(self):
        # A rollback intent no finish can complete (one that does not parse)
        # is an unfinished automatic rollback: the real preboot verb and the
        # launcher refuse to boot (78, the `cogbox: ` line), every plugin
        # change refuses with the same line, list reports it and goes on, and
        # `apply --abandon-rollback -y` moves it aside so the box starts.
        identity = self.start()
        self.cli("stop")
        self.ended(identity)
        rollback = self.icd() / "apply" / "rollback"
        rollback.mkdir(parents=True, exist_ok=True)
        (rollback / "0123456789abcdef.intent").write_text("")
        stamped = "cogbox: an automatic plugin rollback could not be finished ("
        abandon = "; free disk space, or run 'cogbox plugin apply --abandon-rollback -n demo'"
        started = self.cli("start", "--no-ssh", "--no-auto-keys", "--yes", "--network", "none", ok=False)
        self.assertEqual(started.returncode, 78, started.stdout + started.stderr)
        self.assertIn(stamped, started.stderr)
        self.assertIn(abandon, started.stderr)
        self.assertEqual((self.runtime / "launch").read_text().split(), identity)
        config = (self.icd() / "config.json").read_text()
        changed = self.plugin("del", "nothing", "-y")
        self.assertEqual(changed.returncode, 78, changed.stdout + changed.stderr)
        self.assertIn(stamped, changed.stderr)
        self.assertEqual((self.icd() / "config.json").read_text(), config)
        listed = self.plugin("list")
        self.assertEqual(listed.returncode, 0, listed.stdout + listed.stderr)
        self.assertIn(stamped, listed.stderr)
        moved = self.plugin("apply", "--abandon-rollback", "-y")
        self.assertEqual(moved.returncode, 0, moved.stdout + moved.stderr)
        self.assertEqual(list(rollback.glob("*.intent")), [])
        self.assertTrue(list((self.icd() / "apply" / "abandoned").iterdir()))
        identity = self.start()
        self.cli("stop")
        self.ended(identity)

    # The dispatcher's steps before a plugin change commits (spec 4.8 and
    # 4.6): an orphaned inflight.json is recovered first, then a pending
    # rollback is finished, then config.json is read. In each case G added
    # x on top of a base B that holds y, and the change is `del y`.

    def test_plugin_change_rolls_back_an_orphaned_rejection_before_it_commits(self):
        # The apply verb died (SIGKILL) after the guest recorded a rejecting
        # verdict: the change recovers inflight.json, rolls G back to B, and
        # then commits on the restored config. Without the recovery, the
        # del would commit on top of G, and G's later rollback to B would
        # bring y back.
        identity = self.start()
        x, y = self.entry("x"), self.entry("y")
        self.plant_base([y])
        self.set_plugins([x, y])
        inflight = self.plant_inflight([self.added(x)])
        env = self.fake_ssh("proto=2\nresult=ok\ngen=0123456789abcdef\nstate=reverted\n"
                            "verdict=breaks_base\nend=1\n")
        result = self.plugin("del", "y", "-y", env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Plugin 'y' removed", result.stdout + result.stderr)
        self.assertEqual(self.plugins(), [])
        self.assertFalse(inflight.exists())
        self.assertEqual([(r["gen"], r["reason"], r["status"], [(n["name"], n["action"]) for n in r["names"]])
                          for r in self.records()],
                         [("0123456789abcdef", "breaks_base", "done", [("x", "removed")])])
        last = json.loads((self.icd() / "apply" / "last.json").read_text())["apply"]
        self.assertEqual((last["gen"], last["result"], last["reason"], last["rollback"]["status"]),
                         ("0123456789abcdef", "rejected", "breaks_base", "done"))
        self.assertEqual(list((self.icd() / "apply" / "rollback").glob("*.intent")), [])
        self.cli("stop")
        self.ended(identity)

    def test_plugin_change_behind_an_unresolvable_orphaned_apply_exits_69_untouched(self):
        # The guest cannot be read (ssh fails) before inflight.json's
        # expiry: the change refuses with the gate's busy line and exit 69,
        # config.json byte-identical; only the recoverer's evidence moved.
        identity = self.start()
        x, y = self.entry("x"), self.entry("y")
        self.plant_base([y])
        self.set_plugins([x, y])
        inflight = self.plant_inflight([self.added(x)])
        config = (self.icd() / "config.json").read_text()
        result = self.plugin("del", "y", "-y", env=self.fake_ssh())
        self.assertEqual(result.returncode, 69, result.stdout + result.stderr)
        self.assertIn("cogbox plugin: error: busy: a live apply is finishing (generation "
                      "0123456789abcdef); try again in a few minutes", result.stderr)
        self.assertEqual((self.icd() / "config.json").read_text(), config)
        self.assertEqual(json.loads(inflight.read_text())["hops"]["rfails"], 1)
        self.assertEqual(self.records(), [])
        inflight.unlink()
        self.cli("stop")
        self.ended(identity)

    def test_plugin_change_finishes_a_pending_rollback_before_it_reads_the_config(self):
        # A finishable intent for G (its target complete): the change
        # finishes it before config.json is read, so x stays removed and y
        # goes. Read before the finish, the del would save the config it
        # loaded, bringing back the x the rollback had just removed.
        identity = self.start()
        self.cli("stop")
        self.ended(identity)
        x, y = self.entry("x"), self.entry("y")
        self.plant_base([y])
        self.set_plugins([x, y])
        self.plant_intent([self.added(x)])
        result = self.plugin("del", "y", "-y")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.plugins(), [])
        self.assertEqual(list((self.icd() / "apply" / "rollback").glob("*.intent")), [])
        self.assertEqual([(r["gen"], r["status"]) for r in self.records()], [("0123456789abcdef", "done")])

    def test_apply_force_is_refused_at_once_not_after_the_config_lock_wait(self):
        # `apply --force` and `--force-plan` (Apply anyway) are not supported
        # yet: the dispatcher refuses them (64) before it opens or waits for
        # any lock, so a long plugin op holding the config lock (the test holds
        # it throughout) does not hold the refusal back for the apply's 300 s
        # lock wait.
        identity = self.start()
        self.cli("stop")
        self.ended(identity)
        locks = self.root / "config" / "cogbox" / ".locks"
        with open(locks / "demo.lock", "a") as config_lock:
            fcntl.flock(config_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for args in (["--force"], ["--force-plan", "0123456789abcdef"]):
                with self.subTest(args=args):
                    began = time.monotonic()
                    result = self.plugin("apply", "--json", *args)
                    took = time.monotonic() - began
                    self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
                    self.assertIn("cogbox plugin: error: apply --force and --force-plan (Apply anyway) "
                                  "are not supported by this cogbox yet", result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertLess(took, 10)
        self.assertFalse((self.icd() / "apply" / "last.json").exists())


    # --- live plugin apply: the verb's children, its stdout, the inline default ---

    def alive(self, pid):
        try:
            return self.proc_identity(pid)[2] not in ("Z", "X")
        except (FileNotFoundError, ProcessLookupError):
            return False

    def test_sigkilled_apply_leaves_no_child_alive(self):
        # Every child of the apply verb is forked with PR_SET_PDEATHSIG=SIGKILL
        # (and stays in its process group): a SIGKILLed verb (an OOM kill, a
        # caller's kill -9) leaves none of its nix, ssh or systemd-run children
        # running. The child here is the first one `cogbox plugin apply` starts
        # on this fixture: the ssh hop that recovers a planted inflight.json,
        # played by an `ssh` that records its pid and sleeps.
        identity = self.start()
        (self.icd() / "apply").mkdir(parents=True, exist_ok=True)
        self.plant_inflight()
        fake = self.root / "fake-bin"
        fake.mkdir()
        pidfile = self.root / "child.pid"
        self.executable(fake / "ssh", f"#!{self.bash}\necho $$ > {Q(str(pidfile))}\nexec sleep 1000\n")
        env = dict(self.env, PATH=str(fake) + os.pathsep + self.env["PATH"])
        verb = subprocess.Popen([str(CLI), "plugin", "-n", "demo", "apply", "--json"], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children.append(verb)
        child = None
        try:
            self.wait_for(lambda: pidfile.exists() and pidfile.read_text().strip() != "")
            child = int(pidfile.read_text())
            # The child is the verb's own (not a shell's), and it exec'd.
            self.wait_for(lambda: Path(f"/proc/{child}/comm").read_text().strip() == "sleep")
            self.assertEqual(self.proc_identity(child)[0], verb.pid)
            os.kill(verb.pid, signal.SIGKILL)
            verb.wait(timeout=10)
            self.wait_for(lambda: not self.alive(child), timeout=5)
        finally:
            if child is not None and self.alive(child):
                os.kill(child, signal.SIGKILL)
        self.cli("stop")
        self.ended(identity)

    def test_apply_with_a_closed_stdout_still_records_and_exits_0(self):
        # A lost reader (the control plane's ssh session dropped) never aborts
        # the verb: SIGPIPE is ignored and a failed stdout write is not fatal,
        # so the classified outcome lands in last.json (written before the
        # report) and the exit is 0, whether the pipe's reader is gone (EPIPE)
        # or there is no stdout at all (EBADF). This fixture has no boot
        # record, so the outcome is restart_required/no_boot_record.
        identity = self.start()
        last = self.icd() / "apply" / "last.json"
        argv = [str(CLI), "plugin", "-n", "demo", "apply", "--json"]
        for how in ("reader-gone", "closed"):
            with self.subTest(stdout=how):
                if last.exists():
                    last.unlink()
                if how == "reader-gone":
                    r, w = os.pipe()
                    os.close(r)
                    try:
                        result = subprocess.run(argv, env=self.env, stdout=w, stderr=subprocess.PIPE,
                                                text=True, timeout=30)
                    finally:
                        os.close(w)
                else:
                    result = subprocess.run([self.bash, "-c", 'exec "$@" >&-', "closed-stdout", *argv],
                                            env=self.env, stderr=subprocess.PIPE, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                rep = json.loads(last.read_text())["apply"]
                self.assertEqual((rep["result"], rep["reason"]), ("restart_required", "no_boot_record"))
        self.cli("stop")
        self.ended(identity)

    def run_on_pty(self, argv, env):
        """Run argv with stderr on a pseudo-terminal (stdout a pipe); returns
        (exit status, stdout, what reached the terminal)."""
        master, slave = pty.openpty()
        try:
            proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=slave)
        finally:
            os.close(slave)
        self.children.append(proc)
        seen = b""
        end = time.monotonic() + 30
        try:
            while time.monotonic() < end:
                ready, _, _ = select.select([master], [], [], 0.2)
                if ready:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    seen += chunk
                elif proc.poll() is not None:
                    break
        finally:
            os.close(master)
        out, _ = proc.communicate(timeout=10)
        return proc.returncode, out.decode(), seen.decode(errors="replace")

    def test_committed_change_applies_inline_only_when_stderr_is_a_terminal(self):
        # The CLI default (spec section 2 step 1): a committed del on a running
        # instance goes live right away only when stderr is a terminal and
        # COGBOX_ENVIRONMENT is not cogworx; otherwise it is deferred with the
        # apply-or-restart hint. Stdout is never the probe (it is a pipe in
        # every run here). The inline apply answers
        # restart_required/no_boot_record on this fixture, which is enough to
        # tell the two paths apart.
        identity = self.start()
        config_path = self.icd() / "config.json"
        argv = [str(CLI), "plugin", "-n", "demo", "del", "x", "-y"]
        inline = "Loading it into the running instance (live apply)"
        deferred = "Run 'cogbox plugin apply -n demo' to load it live"
        for case in ("pipe", "terminal", "terminal-cogworx"):
            with self.subTest(stderr=case):
                config = json.loads(config_path.read_text())
                config["plugins"] = [{"name": "x", "url": "path:/nonexistent/x",
                                      "narHash": "sha256-" + "A" * 43 + "="}]
                config_path.write_text(json.dumps(config) + "\n")
                env = dict(self.env)
                env.pop("COGBOX_ENVIRONMENT", None)
                if case == "terminal-cogworx":
                    env["COGBOX_ENVIRONMENT"] = "cogworx"
                # The verb's messages go to stdout (a pipe in every case);
                # only stderr changes.
                if case == "pipe":
                    result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                            text=True, timeout=30)
                    rc, said = result.returncode, result.stdout + result.stderr
                else:
                    rc, out, err = self.run_on_pty(argv, env)
                    said = out + err
                self.assertEqual(rc, 0, said)
                self.assertIn("Plugin 'x' removed", said)
                self.assertEqual(json.loads(config_path.read_text())["plugins"], [])
                if case == "terminal":
                    self.assertIn(inline, said)
                    self.assertIn("Not loaded live (restart_required/no_boot_record)", said)
                    self.assertNotIn(deferred, said)
                else:
                    self.assertIn(deferred, said)
                    self.assertNotIn(inline, said)
        self.cli("stop")
        self.ended(identity)


unittest.main()
