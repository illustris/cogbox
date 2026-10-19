"""compat_doc.py: key normalization and fingerprints, sorting, release shape,
the size cap.

Usage: python3 -I pve/tests/test_compat_doc.py

Stdlib only (ssh-keygen, when on PATH, cross-checks the fingerprint).
COGWORX_PVE_COMPAT_DOC overrides the script path.
"""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = os.environ.get("COGWORX_PVE_COMPAT_DOC", str(HERE.parent / "upgrade" / "compat_doc.py"))
IN_CHECK = "COGWORX_PVE_COMPAT_DOC" in os.environ

loader = importlib.machinery.SourceFileLoader("compat_doc", SCRIPT)
spec = importlib.util.spec_from_loader("compat_doc", loader)
cd = importlib.util.module_from_spec(spec)
loader.exec_module(cd)

# The fixture CA key of pve/checks.nix: a public key whose private half was
# deleted when it was generated.
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJMmGv60w43igyko8BEEnvP2PPu01MPlwi9Zamq2j/LC control-ca"
FP = "SHA256:4fR1sXmorUlWspPK0W8CKAc2aQmmRM9X/JSYyLPQ9GY"
KEY2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEcontrolCAkeyFORthePVEcheck control-ca"


def raw(**over):
    """A raw doc in module.nix's shape, every schema-1 key present."""
    doc = {"schema": 1, "kind": "cogworx-pve-system", "toolProto": 1, "txnSchema": 1, "bootProof": 1,
           "stateFormat": 1, "bootConfigVersions": [1], "smbiosSelector": "S", "guestAttrsVersion": 1,
           "release": None, "controlCAKeys": [KEY], "controlPlaneCIDRs": ["198.51.100.0/24"], "controlUser": "root",
           "hostKeyPath": "/var/lib/cogworx/sshd/ssh_host_ed25519_key",
           "stateDevice": "/dev/disk/by-id/virtio-cogworx-state",
           "guestDevice": "/dev/disk/by-id/virtio-cogworx-guest", "interface": "eth0",
           "substituters": ["https://cache.example"], "trustedPublicKeys": ["cache.example-1:AAAA"],
           "specialisations": [],
           "bootloader": {"installer": "/nix/store/00000000000000000000000000000000-install-grub.sh",
                          "grub": "/nix/store/00000000000000000000000000000000-grub-2.14", "devices": ["/dev/vda"],
                          "distroName": "NixOS", "guard": "cwx-guard-v1"}}
    doc.update(over)
    return doc


def run_script(doc):
    d = tempfile.mkdtemp()
    try:
        p = os.path.join(d, "raw.json")
        with open(p, "w") as f:
            json.dump(doc, f)
        return subprocess.run([sys.executable, "-I", SCRIPT, p], capture_output=True)
    finally:
        shutil.rmtree(d)


class CompatDocTest(unittest.TestCase):
    def test_fingerprint_matches_ssh_keygen(self):
        self.assertEqual(cd.normalize_key(KEY), (KEY.rsplit(" ", 1)[0], FP))
        keygen = shutil.which("ssh-keygen")
        if keygen is None:
            if IN_CHECK:
                self.fail("ssh-keygen is not on PATH")
            self.skipTest("no ssh-keygen")
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        with open(os.path.join(d, "k.pub"), "w") as f:
            f.write(KEY + "\n")
        out = subprocess.run([keygen, "-lf", os.path.join(d, "k.pub"), "-E", "sha256"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.split()[1], FP)

    def test_normalized_document(self):
        r = run_script(raw(controlCAKeys=[KEY + " extra comment words", "  " + KEY.replace("control-ca", "other"), KEY],
                           controlPlaneCIDRs=["203.0.113.0/24", "198.51.100.0/24", "203.0.113.0/24"],
                           substituters=["https://b.example", "https://a.example"],
                           trustedPublicKeys=["b-1:x", "a-1:y", "a-1:y"], specialisations=[],
                           release={"id": "rel-20261018", "builtAt": "2026-10-18T00:00:00Z"}))
        self.assertEqual(r.returncode, 0, r.stderr)
        text = r.stdout.decode("ascii")
        doc = json.loads(text)
        self.assertEqual(doc["controlCAKeys"], [KEY.rsplit(" ", 1)[0]])
        self.assertEqual(doc["controlCAFingerprints"], [FP])
        self.assertEqual(doc["controlPlaneCIDRs"], ["198.51.100.0/24", "203.0.113.0/24"])
        self.assertEqual(doc["substituters"], ["https://a.example", "https://b.example"])
        self.assertEqual(doc["trustedPublicKeys"], ["a-1:y", "b-1:x"])
        self.assertEqual(text, json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")

    def test_http_substituters_lose_trailing_slashes(self):
        doc = json.loads(cd.normalize(raw(substituters=[
            "https://cache.example/", "https://cache.example", "http://cache.example/sub//",
            "file:///tmp/cache/", "https://"])))
        self.assertEqual(doc["substituters"], ["file:///tmp/cache/", "http://cache.example/sub", "https://",
                                               "https://cache.example"])

    def test_refusals_fail_the_build(self):
        bad = [
            raw(controlCAKeys=[KEY2]),                              # does not base64-decode
            raw(controlCAKeys=["ssh-rsa " + KEY.split()[1]]),       # an ed25519 blob called rsa
            raw(controlCAKeys=["just-one-field"]),
            raw(controlCAKeys=["ssh-ed25519"]),
            raw(controlCAKeys="not a list"),
            raw(substituters=[1]),
            raw(release={"id": "x y", "builtAt": "2026-10-18T00:00:00Z"}),
            raw(release={"id": "x", "builtAt": "2026-10-18 00:00:00"}),
            raw(release={"id": "x", "builtAt": "2026-10-18T00:00:00Z", "extra": 1}),
            raw(pad="x" * 16400),
            [],
        ]
        for doc in bad:
            with self.subTest(doc=str(doc)[:80]):
                r = run_script(doc)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(r.stdout, b"")
                self.assertIn(b"compat_doc.py: ", r.stderr)
        r = run_script(raw(controlCAKeys=[KEY2]))
        self.assertIn(b"EXAMPLEcontrolCAkey", r.stderr)

    def test_size_cap_boundary(self):
        base = cd.normalize(raw(pad=""))
        room = cd.MAX_BYTES - len(base)
        self.assertEqual(len(cd.normalize(raw(pad="x" * room))), cd.MAX_BYTES)
        with self.assertRaises(cd.DocError):
            cd.normalize(raw(pad="x" * (room + 1)))

    def test_every_schema_key_is_required(self):
        # A key the module stopped writing fails the build; it never becomes
        # an empty list (substituters [] would fail cogworxd's rule (v) on
        # every target, and a failed cogworxd compat rule is remembered).
        self.assertEqual(sorted(cd.RAW_KEYS), sorted(raw()))
        for key in cd.RAW_KEYS:
            with self.subTest(key=key):
                doc = raw()
                del doc[key]
                r = run_script(doc)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(r.stdout, b"")
                self.assertIn(("lacks " + key).encode(), r.stderr)
        out = json.loads(cd.normalize(raw()))
        self.assertEqual(sorted(out), sorted(cd.RAW_KEYS + ("controlCAFingerprints",)))

    def test_empty_ca_is_allowed(self):
        doc = json.loads(cd.normalize(raw(controlCAKeys=[])))
        self.assertEqual((doc["controlCAKeys"], doc["controlCAFingerprints"]), ([], []))


if __name__ == "__main__":
    unittest.main(verbosity=1)
