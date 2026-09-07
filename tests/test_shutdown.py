"""Real owned processes, the packaged shutdown functions, and launcher cleanup.

No VM, root, network access, or systemd mutations. Optional third argument tests
the actual Zig CLI against the same launch fixtures, not a copied stop routine.
"""
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


def child(mode, runtime):
    runtime = Path(runtime)
    if mode == "aux":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        # The VM child records its termination before auxiliary cleanup may
        # begin. Ignore TERM so the bounded KILL/reap leg is exercised too.
        def aux_term(*_):
            if not (runtime / "qemu-ended").exists():
                (runtime / "aux-before-qemu").touch()
        signal.signal(signal.SIGTERM, aux_term)
        while True:
            time.sleep(.01)
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(runtime / "cogbox.socket"))
    sock.listen()

    def term(*_):
        (runtime / "qemu-term").touch()
        if mode != "resistant":
            (runtime / "qemu-ended").touch()
            sys.exit(7)

    signal.signal(signal.SIGTERM, term)
    (runtime / "child-ready").touch()
    while not (runtime / "request").exists():
        if not (runtime / "additional-dirs").exists():
            (runtime / "sources-removed-early").touch()
        time.sleep(.01)
    sock.close()
    (runtime / "cogbox.socket").unlink()
    # The helper exits on socket closure before QEMU itself finishes.
    time.sleep(.08)
    (runtime / "qemu-ended").touch()
    if mode == "signaled":
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        os.kill(os.getpid(), signal.SIGTERM)
    sys.exit(4 if mode == "crashed" else 0)


def helper(mode, runtime):
    runtime = Path(runtime)
    with (runtime / "requests").open("a") as f:
        f.write("request\n")
    print("raw-QMP-canary-must-not-leak", flush=True)
    if mode == "failure":
        sys.exit(3)
    if mode == "signaled":
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        os.kill(os.getpid(), signal.SIGTERM)
    if mode == "false-success":
        sys.exit(0)
    if mode == "hang":
        # Descendant inherits the timeout process group. Force must reap/kill
        # the whole helper group, not leave this child holding the flock.
        proc = subprocess.Popen([sys.executable, __file__, "--child", "aux", str(runtime)])
        (runtime / "helper-child").write_text(str(proc.pid))
        while True:
            time.sleep(.01)
    (runtime / "request").touch()
    while (runtime / "cogbox.socket").exists():
        time.sleep(.01)


if len(sys.argv) > 1 and sys.argv[1] in ("--child", "--helper"):
    (child if sys.argv[1] == "--child" else helper)(sys.argv[2], sys.argv[3])
    sys.exit(0)

MODULE, LAUNCH = (Path(p).resolve() for p in sys.argv[1:3])
TEST_FILE = str(Path(__file__).resolve())
CLI = sys.argv[3] if len(sys.argv) > 3 else None
sys.argv = sys.argv[:1] + sys.argv[4:]
CLEANUP = LAUNCH.read_text().split("cogbox_cleanup() {", 1)[1].split("\ntrap cogbox_cleanup EXIT", 1)[0]
CLEANUP = "cogbox_cleanup() {" + CLEANUP
Q = shlex.quote


class Shutdown(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cogbox-shutdown-")
        self.root = Path(self.tmp.name)
        self.runtime = self.root / "run" / "cogbox-demo"
        self.runtime.mkdir(parents=True)
        (self.runtime / "additional-dirs").mkdir()
        (self.root / "data" / "mirrors" / "demo").mkdir(parents=True)
        self.runner = self.root / "runner"
        (self.runner / "bin").mkdir(parents=True)
        self.proc = None
        self.log = (self.root / "log").open("w+")

    def tearDown(self):
        if self.proc:
            # Failed/unconfirmed cleanup deliberately retains its children.
            # Kill only the disposable process group this fixture created.
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.proc.wait()
        self.log.close()
        self.tmp.cleanup()

    def wait_for(self, predicate, timeout=5):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(.01)
        self.fail("timed out waiting for fixture condition: " + (self.root / "log").read_text())

    def launch(self, helper_mode="success", child_mode="normal", uncertain=False, production=False):
        helper_path = self.runner / "bin" / "microvm-shutdown"
        if helper_mode != "missing":
            helper_path.write_text("#!" + shutil.which("bash") +
                                   "\nexec " + " ".join(map(Q, [sys.executable, TEST_FILE, "--helper", helper_mode, str(self.runtime)])) + "\n")
            helper_path.chmod(0o700)
        wrapper = self.root / "launcher"
        timers = "" if production else """SHUTDOWN_GRACE_TICKS=200
SHUTDOWN_TERM_TICKS=10
SHUTDOWN_KILL_TICKS=10
SHUTDOWN_AUX_TICKS=10
SHUTDOWN_AUX_KILL_TICKS=10
SHUTDOWN_TICK=0.01
SHUTDOWN_TICK_CS=1"""
        wrapper.write_text(f"""source {Q(str(MODULE))}
{timers}
RUNTIME={Q(str(self.runtime))}
RUNNER_DIR={Q(str(self.runner))}
BASE_DATA={Q(str(self.root / 'data'))}
EFFECTIVE_NAME=demo
CLEANED=0
PASST_PID=""; L7PROXY_PID=""; L7MITM_PID=""; L7AUTH_PID=""; QEMU_PID=""
{CLEANUP}
trap cogbox_cleanup EXIT
cogbox_stop_traps
cogbox_stop_init || exit 1
echo "$$" > "$RUNTIME/pid"
{Q(sys.executable)} {Q(TEST_FILE)} --child aux "$RUNTIME" &
PASST_PID=$!
echo "$PASST_PID" > "$RUNTIME/aux.pid"
{Q(sys.executable)} {Q(TEST_FILE)} --child {Q(child_mode)} "$RUNTIME" &
QEMU_PID=$!
QEMU_START=$(cogbox_process_start "$QEMU_PID")
echo "$QEMU_PID" > "$RUNTIME/qemu.pid"
{'cogbox_child_live() { return 1; }' if uncertain else ''}
wait "$QEMU_PID"
""")
        self.proc = subprocess.Popen(["bash", str(wrapper)], stdout=self.log, stderr=self.log, start_new_session=True)
        self.wait_for(lambda: (self.runtime / "child-ready").exists())
        self.qemu = int((self.runtime / "qemu.pid").read_text())
        self.aux = int((self.runtime / "aux.pid").read_text())

    def stop(self, force=False):
        start = time.monotonic()
        os.kill(self.proc.pid, signal.SIGUSR1 if force else signal.SIGTERM)
        self.proc.wait(timeout=4)
        self.assertLess(time.monotonic() - start, 3)
        self.assertFalse(Path(f"/proc/{self.qemu}").exists())
        self.assertFalse(Path(f"/proc/{self.aux}").exists())
        self.assertFalse((self.runtime / "additional-dirs").exists())
        self.assertFalse((self.root / "data" / "mirrors" / "demo").exists())
        self.assertNotIn("raw-QMP-canary", (self.root / "log").read_text())
        self.assertFalse((self.runtime / "sources-removed-early").exists())
        data = (self.runtime / "stop-result").read_text().split()
        self.assertEqual(data[:4], (self.runtime / "launch").read_text().split())
        return data[-1]

    def test_orderly_socket_closure_precedes_child_exit(self):
        self.launch()
        self.assertEqual(self.stop(), "unverified")
        self.assertFalse((self.runtime / "qemu-term").exists())
        self.assertFalse((self.runtime / "aux-before-qemu").exists())
        self.assertEqual((self.runtime / "requests").read_text(), "request\n")

    def test_helper_missing(self):
        self.launch("missing")
        self.assertEqual(self.stop(), "forced")

    def test_socket_missing_is_not_graceful(self):
        self.launch()
        (self.runtime / "cogbox.socket").unlink()
        self.assertEqual(self.stop(), "forced")
        self.assertFalse((self.runtime / "requests").exists())

    def test_helper_error(self):
        self.launch("failure")
        self.assertEqual(self.stop(), "forced")

    def test_actual_signaled_helper_is_not_hidden_by_reap_retry(self):
        self.launch("signaled")
        self.assertEqual(self.stop(), "forced")
        self.assertIn("helper failed (status 143)", (self.root / "log").read_text())

    def test_actual_signaled_qemu_is_not_hidden_by_reap_retry(self):
        self.launch(child_mode="signaled")
        self.assertEqual(self.stop(), "forced")
        self.assertIn("guest exited unsuccessfully during shutdown (status 143)", (self.root / "log").read_text())

    def test_helper_zero_with_surviving_child(self):
        self.launch("false-success")
        self.assertEqual(self.stop(), "forced")

    def test_child_crash_is_not_graceful(self):
        self.launch(child_mode="crashed")
        self.assertEqual(self.stop(), "forced")

    def test_hung_helper_and_term_resistant_children_are_bounded(self):
        self.launch("hang", "resistant")
        self.assertEqual(self.stop(), "forced")
        helper_pid = (self.runtime / "helper-child").read_text()
        stat = Path(f"/proc/{helper_pid}/stat")
        self.assertTrue(not stat.exists() or stat.read_text().split(") ", 1)[1].startswith("Z "))

    def test_force_skips_helper(self):
        self.launch("hang", "resistant")
        self.assertEqual(self.stop(force=True), "forced")
        self.assertFalse((self.runtime / "requests").exists())

    def test_force_and_duplicate_term_during_helper(self):
        self.launch("hang", "resistant")
        os.kill(self.proc.pid, signal.SIGTERM)
        self.wait_for(lambda: (self.runtime / "helper-child").exists())
        os.kill(self.proc.pid, signal.SIGTERM)
        self.assertEqual(self.stop(force=True), "forced")
        self.assertEqual((self.runtime / "requests").read_text(), "request\n")

    def test_unconfirmed_child_retains_sources_and_supporting_processes(self):
        # Fault-inject only the read-only liveness inspection, not the cleanup
        # routine. Real owned children remain alive; no signal/cleanup is safe.
        self.launch(uncertain=True)
        os.kill(self.proc.pid, signal.SIGTERM)
        self.proc.wait(timeout=3)
        self.assertEqual((self.runtime / "stop-result").read_text().split()[-1], "failed")
        self.assertTrue(Path(f"/proc/{self.qemu}").exists())
        self.assertTrue(Path(f"/proc/{self.aux}").exists())
        self.assertTrue((self.runtime / "additional-dirs").is_dir())
        self.assertTrue((self.root / "data" / "mirrors" / "demo").is_dir())

    def test_no_child_and_already_reaped_child_are_not_graceful_claims(self):
        for prefix in ('QEMU_PID=""', 'sleep 0.01 & QEMU_PID=$!; wait "$QEMU_PID"'):
            command = f"source {Q(str(MODULE))}; RUNNER_DIR={Q(str(self.runner))}; RUNTIME={Q(str(self.runtime))}; {prefix}; STOP_REQUESTED=1; cogbox_stop_child; printf '%s' \"$STOP_OUTCOME\""
            completed = subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=2)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "already-stopped")

    def cli_env(self):
        return dict(os.environ, XDG_RUNTIME_DIR=str(self.root / "run"), XDG_CONFIG_HOME=str(self.root / "config"))

    @unittest.skipUnless(CLI, "actual CLI supplied by Nix check")
    def test_cli_unverified_and_concurrent_callers(self):
        self.launch()
        env = dict(os.environ, XDG_RUNTIME_DIR=str(self.root / "run"), XDG_CONFIG_HOME=str(self.root / "config"))
        callers = [subprocess.Popen([CLI, "stop", "-n", "demo"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        try:
            for caller in callers:
                out, err = caller.communicate(timeout=5)
                self.assertEqual(caller.returncode, 0, err + (self.root / "log").read_text() + repr(list(self.runtime.iterdir())))
                self.assertIn("clean guest shutdown could not be verified", out, (self.root / "log").read_text())
        finally:
            for caller in callers:
                if caller.poll() is None:
                    caller.kill()
                caller.communicate()
        self.proc.wait(timeout=3)

    @unittest.skipUnless(CLI, "actual CLI supplied by Nix check")
    def test_cli_concurrent_force_callers(self):
        self.launch("hang", "resistant")
        callers = [subprocess.Popen([CLI, "stop", "--force", "-n", "demo"], env=self.cli_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(8)]
        try:
            for caller in callers:
                out, err = caller.communicate(timeout=5)
                self.assertEqual(caller.returncode, 0, err + (self.root / "log").read_text())
                self.assertIn("recent writes might have been lost", out)
        finally:
            for caller in callers:
                if caller.poll() is None:
                    caller.kill()
                caller.communicate()
        self.proc.wait(timeout=3)

    @unittest.skipUnless(CLI, "actual CLI supplied by Nix check")
    def test_cli_retained_failed_missing_and_changed_results_refuse_restart(self):
        self.launch()
        self.assertEqual(self.stop(), "unverified")
        result = self.runtime / "stop-result"
        identity = (self.runtime / "launch").read_text().strip()
        for value in (identity + " failed\n", identity.replace("v1 ", "v1 a", 1) + " graceful\n", None):
            if value is None:
                result.unlink()
            else:
                result.write_text(value)
            for verb in ("stop", "restart"):
                completed = subprocess.run([CLI, verb, "-n", "demo"], env=self.cli_env(), capture_output=True, text=True, timeout=3)
                self.assertNotEqual(completed.returncode, 0)
                self.assertNotIn("is not running", completed.stdout)

    @unittest.skipUnless(CLI, "actual CLI supplied by Nix check")
    def test_cli_legacy_force_uses_term_and_does_not_claim_graceful(self):
        self.launch()
        (self.runtime / "launch").unlink()
        completed = subprocess.run([CLI, "stop", "--force", "-n", "demo"], env=self.cli_env(), capture_output=True, text=True, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("cannot verify guest shutdown", completed.stdout)
        self.assertEqual((self.runtime / "requests").read_text(), "request\n")

    @unittest.skipUnless(CLI, "actual CLI supplied by Nix check")
    def test_cli_production_deadlines_bound_hung_helper_and_resistant_children(self):
        # No timer overrides: exercise the full 44+1 helper /5+5 QEMU /3+1
        # auxiliary path and actual CLI65s limit, not just scaled constants.
        self.launch("hang", "resistant", production=True)
        began = time.monotonic()
        completed = subprocess.run([CLI, "stop", "-n", "demo"], env=self.cli_env(), capture_output=True, text=True, timeout=68)
        elapsed = time.monotonic() - began
        self.assertEqual(completed.returncode, 0, completed.stderr + (self.root / "log").read_text())
        self.assertIn("recent writes might have been lost", completed.stdout)
        self.assertGreater(elapsed, 40)
        self.assertLess(elapsed, 65)
        self.proc.wait(timeout=2)
        self.assertFalse(Path(f"/proc/{self.qemu}").exists())
        self.assertFalse(Path(f"/proc/{self.aux}").exists())
        helper_pid = (self.runtime / "helper-child").read_text()
        stat = Path(f"/proc/{helper_pid}/stat")
        self.assertTrue(not stat.exists() or stat.read_text().split(") ", 1)[1].startswith("Z "))
        print(f"production shutdown aggregate: {elapsed:.3f}s", flush=True)

    @unittest.skipUnless(CLI, "actual CLI supplied by Nix check")
    def test_cli_force_and_stale_identity(self):
        self.launch("hang", "resistant")
        env = dict(os.environ, XDG_RUNTIME_DIR=str(self.root / "run"), XDG_CONFIG_HOME=str(self.root / "config"))
        launch = self.runtime / "launch"
        original = launch.read_text()
        fields = original.split()
        fields[3] = str(int(fields[3]) + 1)
        launch.write_text(" ".join(fields))
        denied = subprocess.run([CLI, "stop", "--force", "-n", "demo"], env=env, capture_output=True, text=True, timeout=3)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIsNone(self.proc.poll())
        launch.write_text(original)
        forced = subprocess.run([CLI, "stop", "--force", "-n", "demo"], env=env, capture_output=True, text=True, timeout=5)
        self.assertEqual(forced.returncode, 0, forced.stderr)
        self.assertIn("recent writes might have been lost", forced.stdout)
        self.proc.wait(timeout=3)


unittest.main(verbosity=2)
