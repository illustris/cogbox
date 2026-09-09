"""Exercise the launcher's fallback directory admission without root or a VM.

Directory creation, symlinks and modes use real temporary files. Identity and
root/foreign ownership are modeled where needed to run sudo cases unprivileged.
Requires Bash and GNU coreutils on PATH; pass cogbox-launch.sh as the first arg.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


source = Path(sys.argv.pop(1)).read_text()
start = source.index('if [ "$SUDO_INVOCATION" = 1 ] || [ -z "${XDG_RUNTIME_DIR:-}" ]; then')
end = source.index('BASE_RUNTIME="$XDG_RUNTIME_BASE/cogbox"', start)
# Redirect only the two fixed system paths; execute the actual admission block.
block = source[start:end].replace('"/run/user/$REAL_UID"', '"$TEST_LOGIND_BASE"')
block = block.replace('"/tmp/cogbox-runtime-$REAL_UID"', '"$TEST_RUNTIME_BASE"')


class RuntimeBaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cbx-runtime-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = self.root / "runtime"

    def admit(self, sudo=False, owner="", stat_failure=False):
        env = dict(os.environ, TEST_RUNTIME_BASE=str(self.runtime),
                   TEST_LOGIND_BASE=str(self.root / "missing-logind-session"),
                   REAL_UID=str(os.getuid()), SUDO_INVOCATION=str(int(sudo)),
                   TEST_EFFECTIVE_UID="0" if sudo else str(os.getuid()),
                   TEST_OWNER=str(owner), TEST_STAT_FAILURE=str(int(stat_failure)))
        setup = '''
unset XDG_RUNTIME_DIR
id() { printf '%s\\n' "$TEST_EFFECTIVE_UID"; }
stat() {
    [ "$TEST_STAT_FAILURE" = 0 ] || return 1
    if [ -n "$TEST_OWNER" ]; then
        printf '%s\\n' "$TEST_OWNER"
    else
        command stat "$@"
    fi
}
die() { echo "$1" >&2; exit "${2:-70}"; }
'''
        return subprocess.run(["bash", "-c", setup + block], env=env,
                              capture_output=True, text=True, timeout=5)

    def assert_admitted(self, **kwargs):
        result = self.admit(**kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.runtime.stat().st_mode & 0o777, 0o700)

    def test_create(self):
        self.assert_admitted()

    def test_reuse_user_directory(self):
        self.runtime.mkdir(mode=0o755)
        self.assert_admitted()

    def test_sudo_reuses_invoking_users_directory(self):
        self.runtime.mkdir(mode=0o755)
        self.assert_admitted(sudo=True)

    def test_sudo_reuses_root_directory(self):
        self.runtime.mkdir(mode=0o755)
        self.assert_admitted(sudo=True, owner=0)

    def test_refuse_foreign_owner(self):
        self.runtime.mkdir()
        self.runtime.chmod(0o755)
        for sudo in (False, True):
            with self.subTest(sudo=sudo):
                result = self.admit(sudo=sudo, owner=os.getuid() + 1)
                self.assertEqual(result.returncode, 70, result.stderr)
                self.assertEqual(self.runtime.stat().st_mode & 0o777, 0o755)

    def test_refuse_symlink(self):
        target = self.root / "target"
        target.mkdir()
        target.chmod(0o755)
        self.runtime.symlink_to(target)
        result = self.admit(sudo=True)
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)

    def test_refuse_regular_file(self):
        self.runtime.write_text("keep")
        result = self.admit(sudo=True)
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertEqual(self.runtime.read_text(), "keep")

    def test_refuse_failed_owner_lookup(self):
        self.runtime.mkdir()
        result = self.admit(sudo=True, stat_failure=True)
        self.assertEqual(result.returncode, 70, result.stderr)


if __name__ == "__main__":
    unittest.main()
