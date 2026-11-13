#!/usr/bin/env python3
"""Real CLI/config-writer concurrency with disposable HOME and XDG roots."""
import fcntl
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

LAUNCH, CLI = (Path(p).resolve() for p in sys.argv[1:3])
sys.argv = sys.argv[:1] + sys.argv[3:]


class Contract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cogbox-config-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        self.script = self.root / "launcher"
        source = LAUNCH.read_text().replace("@harnesses@", "")
        source = source.replace("#!/usr/bin/env bash", "#!" + shutil.which("bash"))
        self.script.write_text(source)
        self.script.chmod(0o700)
        self.env = dict(os.environ, HOME=str(self.root), USER="untrusted-env-name",
                        XDG_CONFIG_HOME=str(self.root / "config"),
                        XDG_DATA_HOME=str(self.root / "data"),
                        XDG_RUNTIME_DIR=str(self.runtime),
                        COGBOX_LAUNCH_SCRIPT=str(self.script))
        for key in ("SUDO_USER", "COGBOX_DATA", "COGWORX_STATE_DIR", "COGBOX_REEXECED"):
            self.env.pop(key, None)
        self.config = self.root / "config/cogbox/instances/demo/config.json"

    def spawn(self, argv):
        child = subprocess.Popen(argv, env=self.env, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.communicate()
        self.addCleanup(cleanup)
        return child

    def cli(self, *args, ok=True, input=None):
        result = subprocess.run([str(CLI), *args], env=self.env, capture_output=True,
                                text=True, timeout=12, input=input)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def init(self, name="demo", **options):
        args = ["init", "--yes", "--no-auto-keys", "--network", "rules"]
        if name is not None:
            args += ["-n", name]
        return self.cli(*args, **options)

    def test_context_is_read_only_canonical_and_uses_effective_identity(self):
        target = self.root / "target"
        target.mkdir()
        (self.root / "alias").symlink_to(target)
        self.env["XDG_CONFIG_HOME"] = str(self.root / "alias/missing")
        before = sorted(str(p) for p in self.root.rglob("*"))
        ctx = json.loads(self.cli("config", "context", "--json").stdout)
        self.assertEqual(ctx, dict(version=1, uid=os.geteuid(), user=pwd.getpwuid(os.geteuid()).pw_name,
                                   configDir=str(target / "missing/cogbox"),
                                   dataDir=str(self.root / "data/cogbox"),
                                   runtimeDir=str(self.runtime / "cogbox")))
        self.assertEqual(before, sorted(str(p) for p in self.root.rglob("*")))
        self.assertIn("context --json", self.cli("help", "config").stdout)

    def test_missing_runtime_root_uses_launcher_fallback_without_creation(self):
        self.env["XDG_RUNTIME_DIR"] = str(self.root / "missing-runtime")
        ctx = json.loads(self.cli("config", "context", "--json").stdout)
        self.assertEqual(ctx["runtimeDir"], f"/tmp/cogbox-runtime-{os.geteuid()}/cogbox")
        self.assertFalse((self.root / "missing-runtime").exists())

    def test_resource_set_preserves_unknown_fields_and_rejects_bad_input(self):
        self.init()
        doc = json.loads(self.config.read_text())
        doc["future"] = {"nested": [True, {"message": "keep"}]}
        self.config.write_text(json.dumps(doc))
        self.cli("config", "set", "-n", "demo", "--vcpu", "3", "--mem", "1024")
        actual = json.loads(self.config.read_text())
        self.assertEqual(actual, dict(doc, vcpu=3, mem=1024))
        for args in ((), ("--vcpu", "0"), ("--mem", "255"), ("--vcpu", "257")):
            self.cli("config", "set", "-n", "demo", *args, ok=False)
        self.assertEqual(json.loads(self.config.read_text()), actual)
        self.cli("config", "set", "-n", "missing", "--mem", "512", ok=False)
        self.assertFalse(self.config.parent.with_name("missing").exists())

    def test_set_and_delete_refuse_lifetime_lock(self):
        self.init()
        with open(self.runtime / "cogbox-demo.lock", "w") as lifetime:
            fcntl.flock(lifetime, fcntl.LOCK_EX)
            self.cli("config", "set", "-n", "demo", "--vcpu", "2", ok=False)
            self.cli("delete", "-n", "demo", "-y", ok=False)
        self.assertTrue(self.config.exists())

    @unittest.skipIf(os.geteuid() == 0, "permission failure requires an unprivileged user")
    def test_delete_failure_keeps_config_discoverable_for_retry(self):
        self.init()
        original = self.config.read_bytes()
        data = self.root / "data/cogbox/instances/demo"
        data.mkdir(parents=True, exist_ok=True)
        (data / "fixture").write_text("disposable data")
        runtime = self.runtime / "cogbox-demo"
        runtime.mkdir()
        (runtime / "fixture").write_text("disposable runtime")
        runtime.chmod(0o500)
        try:
            result = self.cli("delete", "-n", "demo", "-y", ok=False)
            self.assertIn("removing runtime dir", result.stderr)
            self.assertFalse(data.exists())
            self.assertEqual(self.config.read_bytes(), original)
        finally:
            runtime.chmod(0o700)
        self.cli("delete", "-n", "demo", "-y")
        self.assertFalse(self.config.parent.exists())
        self.assertFalse(runtime.exists())

    @unittest.skipIf(os.geteuid() == 0, "permission failure requires an unprivileged user")
    def test_config_cleanup_failure_keeps_config_discoverable_for_retry(self):
        self.init()
        original = self.config.read_bytes()
        # Filesystem directory order is not creation order. Choose a child that
        # is actually enumerated after config so this exercises partial removal.
        for n in range(128):
            blocked = self.config.parent / f"blocked-plugin-{n}"
            blocked.mkdir()
            entries = os.listdir(self.config.parent)
            if entries.index("config.json") < entries.index(blocked.name):
                break
            blocked.rmdir()
        else:
            self.fail("could not arrange config before the failing child")
        (blocked / "fixture").write_text("disposable config child")
        blocked.chmod(0o500)
        try:
            result = self.cli("delete", "-n", "demo", "-y", ok=False)
            self.assertIn("removing config dir", result.stderr)
            self.assertEqual(self.config.read_bytes(), original)
        finally:
            blocked.chmod(0o700)
        self.cli("delete", "-n", "demo", "-y")
        self.assertFalse(self.config.parent.exists())

    def test_default_resource_set_and_reload_use_base_runtime(self):
        self.init(name=None)
        self.cli("config", "set", "--vcpu", "2")
        default = self.config.parent.with_name("default") / "config.json"
        self.assertEqual(json.loads(default.read_text())["vcpu"], 2)
        (self.runtime / "cogbox").mkdir()
        self.cli("secret", "reload")
        self.assertTrue((self.runtime / "cogbox/netfilter-rules").exists())
        self.assertFalse((self.runtime / "cogbox-default").exists())

    def test_explicit_reload_reports_bad_helpers_but_allows_absent_or_dead(self):
        self.init()
        runtime = self.runtime / "cogbox-demo"
        runtime.mkdir()
        self.cli("secret", "reload", "-n", "demo")
        for name in ("l7proxy.pid", "passt.pid"):
            pidfile = runtime / name
            pidfile.write_text("not-a-pid")
            self.cli("secret", "reload", "-n", "demo", ok=False)
            # Linux PIDs cannot reach this value; a genuinely dead helper is
            # normal after shutdown and must not make reload fail.
            pidfile.write_text("2147483647")
            self.cli("secret", "reload", "-n", "demo")
            if os.geteuid() != 0:
                pidfile.chmod(0)
                try:
                    self.cli("secret", "reload", "-n", "demo", ok=False)
                finally:
                    pidfile.chmod(0o600)
            pidfile.unlink()

    def test_explicit_reload_attempts_second_helper_after_first_failure(self):
        self.init()
        runtime = self.runtime / "cogbox-demo"
        runtime.mkdir()
        ready, signalled = self.root / "helper-ready", self.root / "helper-signalled"
        helper = self.spawn([sys.executable, "-c", """
import signal, sys
from pathlib import Path
signal.signal(signal.SIGUSR1, lambda *_: Path(sys.argv[2]).write_text('reload'))
Path(sys.argv[1]).write_text('ready')
while True:
    signal.pause()
""", str(ready), str(signalled)])
        deadline = time.monotonic() + 3
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(ready.exists(), "disposable helper did not become ready")
        (runtime / "l7proxy.pid").write_text("not-a-pid")
        (runtime / "passt.pid").write_text(str(helper.pid))
        self.cli("secret", "reload", "-n", "demo", ok=False)
        deadline = time.monotonic() + 3
        while not signalled.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(signalled.exists(), "second helper missed reload after first helper failed")

    def test_existing_refuses_missing_in_both_launcher_phases(self):
        for init_only in (True, False):
            args = [str(self.script), "--existing", "--yes", "--name", "missing"]
            if init_only:
                args.append("--init-only")
            result = subprocess.run(args, env=self.env, capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 66, result.stdout + result.stderr)
            self.assertFalse(self.config.parent.with_name("missing").exists())
        self.cli("start", "--existing", "-n", "missing", "--no-ssh", ok=False)
        self.assertFalse(self.config.parent.with_name("missing").exists())

    def test_exclusive_concurrent_init_has_one_winner(self):
        argv = [str(CLI), "init", "--exclusive", "--yes", "--no-auto-keys", "-n", "demo"]
        children = [self.spawn(argv) for _ in range(2)]
        outputs = [child.communicate(timeout=12) for child in children]
        self.assertEqual(sorted(child.returncode for child in children), [0, 73], outputs)
        self.assertTrue(self.config.exists())
        self.cli("init", "--exclusive", "--yes", "-n", "demo", ok=False)

    def test_all_writers_lock_before_read_and_keep_concurrent_fields(self):
        self.init()
        doc = json.loads(self.config.read_text())
        doc["plugins"] = [{"name": "obs-plugin", "url": "path:/absent", "attr": "default"}]
        self.config.write_text(json.dumps(doc))
        operations = [
            ("config", "set", "--vcpu", "7"),
            ("config", "set", "--mem", "3072"),
            ("rules", "add", "allow", "192.0.2.1/32"),
            ("l7", "add", "allow", "api.example.com"),
            ("remap", "add", "tcp 192.0.2.0/24:443", "tcp 127.0.0.1:9443"),
            ("plugin", "del", "obs-plugin", "-y"),
        ]
        guard_path = self.root / "config/cogbox/.locks/demo.lock"
        with guard_path.open("a") as guard:
            fcntl.flock(guard, fcntl.LOCK_EX)
            children = [self.spawn([str(CLI), *op, "-n", "demo"]) for op in operations]
            try:
                # Each real process must remain parked behind the externally held
                # lock. Changing the document now proves no writer read it early.
                time.sleep(.2)
                self.assertTrue(all(child.poll() is None for child in children))
                doc["future"] = "written while every writer waited"
                self.config.write_text(json.dumps(doc))
            finally:
                fcntl.flock(guard, fcntl.LOCK_UN)
            for child in children:
                out, err = child.communicate(timeout=12)
                self.assertEqual(child.returncode, 0, out + err)
        actual = json.loads(self.config.read_text())
        self.assertEqual(actual["future"], doc["future"])
        self.assertEqual((actual["vcpu"], actual["mem"]), (7, 3072))
        self.assertEqual(actual["plugins"], [])
        self.assertTrue(any(r.get("allow") == "192.0.2.1/32" for r in actual["network"]["rules"]))
        self.assertTrue(actual["network"]["remap"])
        self.assertTrue(actual["network"]["l7"]["rules"])
        self.assertFalse(list(self.config.parent.glob("*.tmp")))

    def test_delete_and_existing_launch_serialize_without_resurrection(self):
        self.init()
        guard_path = self.root / "config/cogbox/.locks/demo.lock"
        with guard_path.open("a") as guard:
            fcntl.flock(guard, fcntl.LOCK_EX)
            starter = self.spawn([str(self.script), "--existing", "--name", "demo", "--yes"])
            time.sleep(.15)
            self.assertIsNone(starter.poll())
            # Model deletion inside the same lock critical section. A start that
            # checked existence before acquiring the lock would recreate it.
            shutil.rmtree(self.config.parent)
            fcntl.flock(guard, fcntl.LOCK_UN)
            out, err = starter.communicate(timeout=8)
            self.assertEqual(starter.returncode, 66, out + err)
        self.assertFalse(self.config.parent.exists())
        self.assertTrue(guard_path.exists())


    # --- git-hosts.json: the guest-readable git host list the l7 verbs publish ---

    FUNNEL = "allow git.example.com --path /\n"
    BANNED = ("project_id", "projects", "secret", "grants", "git_user")

    def git_hosts(self):
        return self.root / "data/cogbox/instances/demo/git-hosts.json"

    def replace_funnel(self, ok=True):
        return self.cli("l7", "replace", "--plugin", "git-grants", "--from-stdin", "-n", "demo",
                        input=self.FUNNEL, ok=ok)

    def assert_no_tmp(self):
        self.assertEqual(list(self.git_hosts().parent.glob(".git-hosts.json.*.tmp")), [])

    def test_l7_verbs_publish_git_hosts(self):
        self.init()
        summary = self.git_hosts()
        self.assertTrue(summary.parent.is_dir())
        self.replace_funnel()
        self.assertEqual(json.loads(summary.read_text()),
                         {"version": 1, "hosts": [{"host": "git.example.com", "discovery": False}]})
        st = summary.lstat()
        self.assertTrue(stat.S_ISREG(st.st_mode))
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o644)

        # No instance runtime dir exists in this harness: policy takes its
        # not-running early return and must still publish.
        doc = {"version": 2, "providers": [{
            "provider": "GitLab", "plugin": "gitlab", "hosts": ["git.example.com"],
            "secret": "git-gitlab", "git_user": "oauth2", "scheme": "https",
            "grants": [{"id": "gg-1", "scope": "namespace", "repo": "grp", "projects": ["11"],
                        "caps": ["git-read"]},
                       {"id": "gg-2", "scope": "project", "repo": "grp/proj", "project_id": "1234",
                        "caps": ["git-read"]}]}]}
        result = self.cli("l7", "policy", "--from-stdin", "-n", "demo", input=json.dumps(doc))
        self.assertIn("Instance is not running", result.stdout)
        raw = summary.read_text()
        self.assertEqual(json.loads(raw), {"version": 1, "hosts": [
            {"host": "git.example.com", "scheme": "https", "discovery": True}]})
        for banned in self.BANNED:
            self.assertNotIn(banned, raw)

        self.cli("l7", "clear", "--plugin", "git-grants", "-n", "demo")
        self.assertEqual(json.loads(summary.read_text()), {"version": 1, "hosts": []})
        self.cli("l7", "mode", "terminate", "-n", "demo")
        self.assertEqual(json.loads(summary.read_text()), {"version": 1, "hosts": []})
        self.assert_no_tmp()

    def test_git_hosts_publish_never_changes_the_verb(self):
        self.init()
        self.replace_funnel()
        control = self.replace_funnel()
        control = (control.returncode, control.stdout, control.stderr)
        summary = self.git_hosts()
        data = summary.parent

        def same():
            r = self.replace_funnel()
            self.assertEqual((r.returncode, r.stdout, r.stderr), control)
            self.assert_no_tmp()

        # (a) a symlink to a file: the target is untouched, the name is replaced.
        victim = self.root / "victim"
        victim.write_text("victim")
        summary.unlink()
        summary.symlink_to(victim)
        same()
        self.assertEqual(victim.read_text(), "victim")
        self.assertTrue(stat.S_ISREG(summary.lstat().st_mode))

        # (b) a symlink to a directory: nothing lands inside it.
        target = self.root / "target-dir"
        target.mkdir()
        summary.unlink()
        summary.symlink_to(target)
        same()
        self.assertEqual(list(target.iterdir()), [])
        self.assertTrue(stat.S_ISREG(summary.lstat().st_mode))

        # (c) a directory at the name: it stays an empty directory.
        summary.unlink()
        summary.mkdir()
        same()
        self.assertTrue(summary.is_dir() and not summary.is_symlink())
        self.assertEqual(list(summary.iterdir()), [])
        summary.rmdir()

        # (d) an unwritable data dir: nothing changes.
        if os.geteuid() != 0:
            self.replace_funnel()
            before = summary.read_bytes()
            data.chmod(0o555)
            try:
                same()
                self.assertEqual(summary.read_bytes(), before)
            finally:
                data.chmod(0o755)

        # (e) the data dir is gone: it is not recreated.
        moved = self.root / "moved-data"
        data.rename(moved)
        r = self.replace_funnel()
        self.assertEqual((r.returncode, r.stdout, r.stderr), control)
        self.assertFalse(data.exists())

    def test_refused_policy_publishes_nothing(self):
        self.init()
        summary = self.git_hosts()
        for prime in (False, True):
            if prime:
                self.replace_funnel()
            before = summary.read_bytes() if summary.exists() else None
            r = self.cli("l7", "policy", "--from-stdin", "-n", "demo",
                         input='{"version":3,"providers":[]}', ok=False)
            self.assertEqual(r.returncode, 65)
            self.assertEqual(r.stderr,
                             "cogbox l7: error: unknown policy document version (expected 1 or 2)\n")
            self.assertEqual(summary.read_bytes() if summary.exists() else None, before)

if __name__ == "__main__":
    unittest.main()
