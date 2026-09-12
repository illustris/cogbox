"""Run the actual rendered guest context scripts in a private filesystem."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

VM = Path(sys.argv.pop(1)).read_text()
CONTAINER = Path(sys.argv.pop(1)).read_text()


class GuestContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.run = self.root / "run"
        self.state.mkdir()

    def materialize(self, source=VM, **env):
        source = source.replace("/var/lib/cogbox-state", str(self.state)).replace("/var/lib/cogbox", str(self.state))
        source = source.replace("/run/cogbox", str(self.run))
        environ = dict(os.environ)
        environ.pop("COGBOX_ENVIRONMENT", None)
        environ.pop("COGBOX_INSTANCE", None)
        result = subprocess.run(["bash", "-eu", "-c", source], env=dict(environ, **env), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads((self.run / "environment.json").read_text())

    def test_missing_and_malformed_context_are_unknown(self):
        self.assertEqual(self.materialize()["mode"], "unknown")
        for value in ("broken", '{"version":99,"mode":"local","instance":"sample"}',
                      '{"version":1,"mode":"local","instance":[]}'):
            (self.state / "environment.json").write_text(value)
            self.assertEqual(self.materialize()["appAccess"], "unknown")

    def test_local_context_normalizes_fields(self):
        (self.state / "environment.json").write_text(json.dumps(dict(version=1, mode="local", instance="sample", untrusted="discard")))
        self.assertEqual(self.materialize(), dict(version=1, mode="local", instance="sample", workspace="/root/work", appAccess="local-cli"))

    def test_container_explicit_managed_replaces_stale_mirror(self):
        (self.state / "environment.json").write_text('{"version":1,"mode":"local","instance":"sample"}')
        result = self.materialize(CONTAINER, COGBOX_ENVIRONMENT="cogworx", COGBOX_INSTANCE="sample")
        self.assertEqual(result["mode"], "cogworx")
        self.assertEqual(result["appAccess"], "cogworx")
        authority = self.state / "config/cogbox/instances/sample/environment.json"
        self.assertEqual(json.loads(authority.read_text())["mode"], "cogworx")
        self.assertEqual(authority.stat().st_mode & 0o777, 0o600)

    def test_container_without_declaration_does_not_invent_local(self):
        self.assertEqual(self.materialize(CONTAINER)["mode"], "unknown")


if __name__ == "__main__":
    unittest.main()
