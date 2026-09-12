"""Exercise the launcher's real context producer without booting a VM."""
import json
import os
import pwd
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(sys.argv.pop(1)).read_text()
CONTEXT = SOURCE.split("# -- Environment context (host authority, guest descriptive mirror) --", 1)[1].split(
    "# -- Re-exec with per-instance extensions overlaid", 1
)[0]
ENDPOINT = SOURCE.split("# An app proxy pins this endpoint", 1)[1].split(
    "# The legacy pid marker", 1
)[0]
# Keep the comment preceding the real shell commands intact.
ENDPOINT = "# An app proxy pins this endpoint" + ENDPOINT


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / "config"
        self.data = self.root / "data"
        self.config.mkdir()
        self.data.mkdir()
        self.env = dict(os.environ, INSTANCE_CONFIG_DIR=str(self.config), REAL_DATA=str(self.data),
                        EFFECTIVE_NAME="sample", NEW_INSTANCE_CONFIG="0", SUDO_INVOCATION="0")
        for name in ("COGBOX_ENVIRONMENT", "COGWORX_STATE_DIR", "COGBOX_REEXEC_PACKAGE"):
            self.env.pop(name, None)

    def run_context(self, **env):
        return subprocess.run(["bash", "-c", 'die() { echo "$1" >&2; exit "$2"; };\n' + CONTEXT],
                              env=dict(self.env, **env), capture_output=True, text=True)

    def mode(self):
        return json.loads((self.config / "environment.json").read_text())["mode"]

    def test_new_local_and_repeated_init(self):
        self.assertEqual(self.run_context(NEW_INSTANCE_CONFIG="1").returncode, 0)
        self.assertEqual(self.mode(), "local")
        self.assertEqual(self.run_context().returncode, 0)
        self.assertEqual(self.mode(), "local")
        self.assertEqual((self.config / "environment.json").stat().st_mode & 0o777, 0o600)

    def test_legacy_is_unknown_including_repeated_init(self):
        for _ in range(2):
            self.assertEqual(self.run_context().returncode, 0)
            self.assertEqual(self.mode(), "unknown")

    def test_hosted_wins_and_survives_env_absence(self):
        self.assertEqual(self.run_context(NEW_INSTANCE_CONFIG="1", COGBOX_ENVIRONMENT="cogworx").returncode, 0)
        self.assertEqual(self.mode(), "cogworx")
        self.assertEqual(self.run_context().returncode, 0)
        self.assertEqual(self.mode(), "cogworx")

    def test_older_gce_wrapper_is_managed(self):
        self.assertEqual(self.run_context(NEW_INSTANCE_CONFIG="1", COGWORX_STATE_DIR="/var/lib/sample-state").returncode, 0)
        self.assertEqual(self.mode(), "cogworx")

    def test_guest_mirror_cannot_adopt_local(self):
        (self.data / "environment.json").write_text('{"version":1,"mode":"local","instance":"sample"}')
        self.assertEqual(self.run_context().returncode, 0)
        self.assertEqual(self.mode(), "unknown")
        self.assertEqual(json.loads((self.data / "environment.json").read_text())["mode"], "unknown")

    def test_host_record_refuses_malformed_or_foreign_instance(self):
        for body in ('broken', '{"version":1,"mode":"local","instance":"other"}'):
            (self.config / "environment.json").write_text(body)
            self.assertNotEqual(self.run_context().returncode, 0)
            self.assertEqual((self.config / "environment.json").read_text(), body)

    def test_host_record_symlink_refused(self):
        target = self.root / "target"
        target.write_text("unchanged")
        (self.config / "environment.json").symlink_to(target)
        self.assertNotEqual(self.run_context(NEW_INSTANCE_CONFIG="1").returncode, 0)
        self.assertEqual(target.read_text(), "unchanged")

    def test_endpoint_carries_actual_port_and_launch(self):
        env = dict(self.env, RUNTIME=str(self.root), HTTP_PORT="8097", BIND_ADDR="127.0.0.1",
                   STOP_ID="v1 11111111-1111-1111-1111-111111111111 456 123")
        result = subprocess.run(["bash", "-c", 'die() { exit "$2"; };\n' + ENDPOINT], env=env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads((self.root / "http-endpoint.json").read_text())
        self.assertEqual(record, dict(version=1, host="127.0.0.1", port=8097, launch=env["STOP_ID"]))
        marker = self.data / ".app-launch"
        self.assertEqual(marker.read_text(), env["STOP_ID"] + "\n")
        self.assertEqual(marker.stat().st_mode & 0o777, 0o644)

    def test_guest_launch_marker_replaces_prior_generation_without_following_symlinks(self):
        foreign = self.root / "foreign"
        foreign.write_text("unchanged")
        marker = self.data / ".app-launch"
        marker.symlink_to(foreign)
        for start in ("123", "456"):
            identity = "v1 11111111-1111-1111-1111-111111111111 456 " + start
            env = dict(self.env, RUNTIME=str(self.root), HTTP_PORT="8097", BIND_ADDR="127.0.0.1", STOP_ID=identity)
            result = subprocess.run(["bash", "-c", 'die() { exit "$2"; };\n' + ENDPOINT], env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.is_symlink())
            self.assertEqual(marker.read_text(), identity + "\n")
            self.assertEqual(marker.stat().st_mode & 0o777, 0o644)
            self.assertEqual(foreign.read_text(), "unchanged")
            self.assertEqual(list(self.data.glob(".app-launch.*")), [])

    def test_sudo_metadata_belongs_to_local_operator_only(self):
        (self.root / "launch").write_text("launch")
        (self.root / "ssh-endpoint").write_text("2222 127.0.0.1\n")
        for mode in ("local", "unknown", "cogworx"):
            record = self.root / ("chown-" + mode)
            env = dict(self.env, RUNTIME=str(self.root), HTTP_PORT="8097", BIND_ADDR="127.0.0.1",
                       STOP_ID="v1 11111111-1111-1111-1111-111111111111 456 123",
                       SUDO_INVOCATION="1", REAL_USER="operator", _mode=mode, CHOWN_RECORD=str(record))
            prefix = 'die() { exit "$2"; }; chown() { printf "%s\\n" "$@" > "$CHOWN_RECORD"; };\n'
            result = subprocess.run(["bash", "-c", prefix + ENDPOINT], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(record.exists(), mode != "cogworx")
            if record.exists():
                self.assertEqual(record.read_text().splitlines(), ["operator", str(self.root / "launch"), str(self.root / "http-endpoint.json"), str(self.root / "ssh-endpoint")])
            self.assertEqual((self.root / "http-endpoint.json").stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(os.environ.get("COGBOX_TEST_SUDO") == "1", "explicit local sudo fixture")
    def test_real_sudo_metadata_readable_by_invoking_user(self):
        uid = os.getuid()
        self.assertNotEqual(uid, 0, "run this fixture as the invoking user")
        env = dict(RUNTIME=str(self.root), REAL_DATA=str(self.data), HTTP_PORT="8097", BIND_ADDR="127.0.0.1",
                   STOP_ID="v1 11111111-1111-1111-1111-111111111111 456 123",
                   SUDO_INVOCATION="1", REAL_USER=pwd.getpwuid(uid).pw_name, _mode="local")
        prefix = 'die() { exit "$2"; }; umask 077; printf "%s\\n" "$STOP_ID" > "$RUNTIME/launch"; printf "2222 127.0.0.1\\n" > "$RUNTIME/ssh-endpoint";\n'
        result = subprocess.run(["sudo", "-n", "env", *[f"{k}={v}" for k, v in env.items()],
                                 "bash", "-c", prefix + ENDPOINT], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for leaf in ("launch", "ssh-endpoint", "http-endpoint.json"):
            path = self.root / leaf
            self.assertEqual(path.stat().st_uid, uid)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(path.read_text())


if __name__ == "__main__":
    unittest.main()
