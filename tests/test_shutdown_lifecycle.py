#!/usr/bin/env python3
"""Run the actual launcher/CLI lifecycle with only external VM tools replaced.

Unlike test_shutdown.py, no launcher functions or admission wiring are copied.
The production substitution boundary supplies a hermetic runner and helper.
"""
import fcntl
import os
from pathlib import Path
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
        self.hold_probe = self.root / "hold-probe"
        self.probe_entered = self.root / "probe-entered"
        (self.root / "bin").mkdir()
        self.executable(self.root / "bin" / "timeout", f"#!{self.bash}\n"
                        f"touch {Q(str(self.probe_entered))}\n"
                        f"while [ -e {Q(str(self.hold_probe))} ]; do sleep .01; done\n"
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


unittest.main()
