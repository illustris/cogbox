"""The PVE metadata emulator: boot config v1 vectors, HTTP subset, guest attributes.

Usage: python3 -m unittest discover -s pve/tests   (or python3 pve/tests/test_metadata.py)

Stdlib only. No root, no network beyond loopback, nothing outside temporary
directories. COGWORX_PVE_METADATA and COGWORX_PVE_VECTORS override the module
and vector paths, so a packaged check can run this file against the installed
script.
"""
import ast
import base64
import errno
import importlib.util
import json
import logging
import os
from pathlib import Path
import queue
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
MODULE_PATH = Path(os.environ.get("COGWORX_PVE_METADATA", HERE.parent / "metadata" / "cogworx_pve_metadata.py"))
VECTORS_PATH = Path(os.environ.get("COGWORX_PVE_VECTORS", HERE.parent / "testdata" / "bootcfg-v1.json"))


def load_module():
    spec = importlib.util.spec_from_file_location("cogworx_pve_metadata", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


md = load_module()
# Keep expected warnings out of the test output; assertLogs still sees them.
md.LOG.addHandler(logging.NullHandler())
md.LOG.propagate = False

with open(VECTORS_PATH, "rb") as _f:
    VECTORS_BYTES = _f.read()
VECTORS = json.loads(VECTORS_BYTES)
CASES = {c["name"]: c for c in VECTORS["cases"]}

BOOT_ID = "0b0a0908-0706-4504-8302-010000005000"
OWNER = "0a1b2c3d-4e5f-4a6b-8c7d-8e9fa0b15010"
# Booted systems, as /run/booted-system resolves to them (nix32 hash alphabet).
SYS_A = "/nix/store/" + "a" * 32 + "-nixos-system-unnamed-26.11.20261008.0000000"
SYS_B = "/nix/store/" + "b" * 32 + "-nixos-system-unnamed-26.11.20261009.0000000"


def decode_outcome(blob):
    """("ok", attrs) or ("reject", reason): the shape every vector asserts."""
    try:
        return "ok", md.decode_blob(blob)
    except md.BootConfigRejected as e:
        return "reject", e.reason


def expected_outcome(case):
    if "expect_reject" in case:
        return "reject", case["expect_reject"]
    return "ok", case["expect_attrs"]


# --- HTTP helpers ---------------------------------------------------------------


class Response:
    def __init__(self, raw):
        self.raw = raw
        head, _, self.body = raw.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        self.status_line = lines[0]
        self.code = int(self.status_line.split()[1]) if raw else None
        self.headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            self.headers.setdefault(name.strip().lower(), []).append(value.strip())

    def header(self, name):
        values = self.headers.get(name.lower(), [])
        return values[0] if len(values) == 1 else values


def exchange(port, data, timeout=10):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(data)
        chunks = []
        while chunk := s.recv(65536):
            chunks.append(chunk)
    return Response(b"".join(chunks))


def request(method, path, headers=(), body=None, flavor=True):
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: metadata.google.internal"]
    if flavor:
        lines.append("Metadata-Flavor: Google")
    lines.extend("%s: %s" % kv for kv in headers)
    if body is not None:
        lines.append("Content-Length: %d" % len(body))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + (body or b"")


MD = "/computeMetadata/v1/"
GA = MD + "instance/guest-attributes/"


class ServerCase(unittest.TestCase):
    """An in-process emulator on 127.0.0.1 with injected peer uid and address."""

    attrs_case = "typical"

    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="cogworx-pve-md-")
        self.addCleanup(shutil.rmtree, tmp, True)
        self.state_dir = os.path.join(tmp, "run-cogworx")
        self.peer = 0
        self.addr = "198.51.100.7"
        self.store = md.GuestAttributeStore(self.state_dir, BOOT_ID, SYS_A)
        attrs = CASES[self.attrs_case]["expect_attrs"] if self.attrs_case else {}
        self.app = md.Metadata(
            instance_id=OWNER,
            attrs=attrs,
            store=self.store,
            iface="eth0",
            addr_fn=lambda iface: self.addr,
            addr_wait=0.3,
            peer_uid=lambda server, client: self.peer,
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(16)
        self.port = sock.getsockname()[1]
        self.server = md.MetadataServer(sock, self.app)
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()

        def stop():
            self.server.shutdown()
            self.server.server_close()
            thread.join(5)

        self.addCleanup(stop)

    def send(self, method, path, **kw):
        return exchange(self.port, request(method, path, **kw))

    def get(self, path, **kw):
        return self.send("GET", path, **kw)

    def assertMetadataResponse(self, r, code):
        self.assertEqual(r.code, code, r.raw[:300])
        self.assertTrue(r.status_line.startswith("HTTP/1.0 "), r.status_line)
        self.assertEqual(r.header("Metadata-Flavor"), "Google")
        self.assertEqual(r.header("Content-Length"), str(len(r.body)))


# --- boot config vectors ----------------------------------------------------------


class VectorFileTest(unittest.TestCase):
    def test_file_is_canonical_json(self):
        # The Go side copies this file and compares sha256; a hand edit that
        # reformats it must fail here, not there.
        self.assertEqual(VECTORS_BYTES, (json.dumps(VECTORS, indent=2, ensure_ascii=True) + "\n").encode("ascii"))

    def test_header_tables_match_the_module(self):
        self.assertEqual(VECTORS["schema"], "cogworx-pve-bootcfg-v1-vectors")
        self.assertEqual(VECTORS["smbios1_max_len"], md.SMBIOS1_MAX_LEN)
        self.assertEqual(VECTORS["attributes"], md.ATTRIBUTES)
        self.assertEqual(VECTORS["bootconfig_fields"], dict(md.BOOTCONFIG_FIELDS))
        self.assertEqual(VECTORS["reject_reasons"], list(md.REJECT_REASONS))
        self.assertEqual(len(CASES), len(VECTORS["cases"]), "duplicate case names")

    def test_every_smbios1_fits_the_cap(self):
        for case in VECTORS["cases"]:
            with self.subTest(case["name"]):
                self.assertLessEqual(len(case["smbios1"]), VECTORS["smbios1_max_len"])

    def test_worst_case_is_exactly_498(self):
        worst = CASES["worst-case-498"]
        self.assertEqual(len(worst["serial_blob"]), 329)
        self.assertEqual(len(worst["smbios1"]), 498)
        self.assertEqual(max(len(c["smbios1"]) for c in VECTORS["cases"]), 498)
        # Every code is present at its grammar's maximum length.
        self.assertEqual(
            sorted(k for k, _, _ in (f.partition("=") for f in worst["serial_blob"].split("&"))),
            sorted(list(md.ATTRIBUTES) + ["v"]),
        )

    def test_smbios1_wraps_the_serial_blob(self):
        for case in VECTORS["cases"]:
            with self.subTest(case["name"]):
                if case["serial_blob"] == "":
                    self.assertEqual(case["smbios1"], "uuid=" + case["owner_uuid"])
                    continue
                parts = dict(p.split("=", 1) for p in case["smbios1"].split(","))
                self.assertEqual(list(parts), ["uuid", "base64", "serial"])
                self.assertEqual(parts["uuid"], case["owner_uuid"])
                self.assertEqual(parts["base64"], "1")
                self.assertEqual(base64.b64decode(parts["serial"], validate=True).decode("ascii"), case["serial_blob"])

    def test_encode_vectors_are_reproduced(self):
        encoded = [c for c in VECTORS["cases"] if c["bootconfig"] is not None]
        self.assertGreaterEqual(len(encoded), 6)
        for case in encoded:
            with self.subTest(case["name"]):
                blob = md.encode_blob(case["bootconfig"])
                self.assertEqual(blob, case["serial_blob"])
                self.assertEqual(md.encode_smbios1(case["owner_uuid"], blob), case["smbios1"])
                self.assertNotIn("expect_reject", case)

    def test_decode_vectors(self):
        for case in VECTORS["cases"]:
            with self.subTest(case["name"]):
                self.assertEqual(decode_outcome(case["serial_blob"]), expected_outcome(case))

    def test_decode_through_both_dmi_serial_forms(self):
        # The first live smoke test pins which form the guest sees; until
        # then both must agree.
        for case in VECTORS["cases"]:
            blob = case["serial_blob"].encode("ascii")
            for form, raw in (("raw", blob + b"\n"), ("base64", base64.b64encode(blob) + b"\n")):
                with self.subTest(case["name"], form=form):
                    self.assertEqual(decode_outcome(md.unwrap_serial(raw)), expected_outcome(case))

    def test_vectors_cover_every_rejection_and_feature(self):
        rejects = {c["expect_reject"] for c in VECTORS["cases"] if "expect_reject" in c}
        self.assertEqual(rejects, set(md.REJECT_REASONS))
        k = CASES["K-reprefixed-as-standard-base64"]
        blob_k = dict(f.split("=", 1) for f in k["serial_blob"].split("&"))["K"]
        self.assertTrue("-" in blob_k and "_" in blob_k, "the K vector must exercise both base64url-only characters")
        served = k["expect_attrs"]["cogworx-ssh-ca-pub"]
        self.assertTrue(served.startswith("ssh-ed25519 ") and "+" in served and "/" in served)
        self.assertEqual(CASES["maintenance-flag"]["expect_attrs"]["cogworx-maintenance"], "")
        self.assertNotIn("cogworx-maintenance", CASES["typical"]["expect_attrs"])
        self.assertEqual(CASES["typical"]["expect_attrs"]["cogworx-hostname"], "cwx-5010")
        self.assertNotIn("cogworx-ssh-ca-pub", CASES["gateway-off-omits-K"]["expect_attrs"])
        self.assertEqual(CASES["reserved-resolver-keys-ignored"]["expect_attrs"], {"cogworx-network": "none"})
        self.assertEqual(CASES["owner-only-no-blob"]["expect_attrs"], {})


class BootConfigTest(unittest.TestCase):
    def test_unknown_and_reserved_keys_are_logged_by_name(self):
        with self.assertLogs(md.LOG, logging.WARNING) as logs:
            attrs = md.decode_blob("D=600&R=&s=192.0.2.1&v=1&w=none&xyz=1")
        self.assertEqual(attrs, {"cogworx-network": "none"})
        text = "\n".join(logs.output)
        for name in ("'D'", "'R'", "'s'", "'xyz'"):
            self.assertIn(name, text)
        self.assertIn("reserved", text)

    def test_rejected_blob_serves_nothing_and_says_why(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "product_serial")
            with open(path, "w") as f:
                f.write("v=1&w=none&w=rules\n")
            with self.assertLogs(md.LOG, logging.ERROR) as logs:
                self.assertEqual(md.read_boot_attrs(path), {})
        self.assertIn("REJECTED (duplicate-key", "\n".join(logs.output))

    def test_absent_or_empty_serial_is_no_blob(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "product_serial")
            self.assertEqual(md.read_boot_attrs(path), {})
            with open(path, "w") as f:
                f.write("\n")
            self.assertEqual(md.read_boot_attrs(path), {})

    def test_serial_forms(self):
        blob = CASES["typical"]["serial_blob"]
        self.assertEqual(md.unwrap_serial(blob.encode() + b"\n"), blob)
        self.assertEqual(md.unwrap_serial(base64.b64encode(blob.encode()) + b"\n"), blob)
        self.assertEqual(md.unwrap_serial(b"v=1\x00"), "v=1")
        # Valid base64 that does not decode to printable ASCII stays raw.
        self.assertEqual(md.unwrap_serial(b"abcd"), "abcd")
        with self.assertRaises(md.BootConfigRejected) as cm:
            md.unwrap_serial("v=1&i=d\u00e9mo".encode("utf-8"))
        self.assertEqual(cm.exception.reason, "parse-error")

    def test_encoder_refusals(self):
        typical = dict(CASES["typical"]["bootconfig"])
        with self.assertRaises(ValueError):
            md.encode_blob(dict(typical, network="full"))
        with self.assertRaises(ValueError):
            md.encode_blob(dict(typical, colour="blue"))
        with self.assertRaises(md.BootConfigRejected):
            md.encode_blob(dict(typical, hostname="Not-A-Hostname"))
        with self.assertRaises(ValueError):
            md.encode_smbios1(OWNER, "x" * 400)
        with self.assertRaises(ValueError):
            md.encode_smbios1("6F1D2C3B-4A59-4E68-8A77-0B1C2D3E4F50", "v=1")

    def test_instance_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "product_uuid")
            with open(path, "w") as f:
                f.write(OWNER.upper() + "\n")
            self.assertEqual(md.read_instance_id(path), OWNER)
            with open(path, "w") as f:
                f.write("Not Settable\n")
            self.assertIsNone(md.read_instance_id(path))
            self.assertIsNone(md.read_instance_id(os.path.join(tmp, "absent")))

    def test_module_is_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names.add(node.module.split(".")[0])
        self.assertEqual(sorted(n for n in names if n not in sys.stdlib_module_names), [])


# --- HTTP subset ------------------------------------------------------------------


class RoutesTest(ServerCase):
    def test_instance_id_over_http10_with_content_length(self):
        r = self.get(MD + "instance/id")
        self.assertMetadataResponse(r, 200)
        self.assertEqual(r.body, OWNER.encode())

    def test_attributes_are_served_and_absent_ones_are_404(self):
        for name, value in CASES["typical"]["expect_attrs"].items():
            with self.subTest(name):
                r = self.get(MD + "instance/attributes/" + name)
                self.assertMetadataResponse(r, 200)
                self.assertEqual(r.body.decode(), value)
        for name in ("cogworx-self-addrs", "cogworx-resolver", "cogworx-maintenance", "v", "n"):
            with self.subTest(name):
                self.assertMetadataResponse(self.get(MD + "instance/attributes/" + name), 404)

    def test_unknown_paths_are_404(self):
        for path in (
            "/",
            MD,
            MD + "instance/",
            MD + "instance/attributes/",
            MD + "instance/hostname",
            MD + "project/project-id",
            MD + "instance/network-interfaces",
            MD + "instance/network-interfaces/1/ip",
            MD + "instance/network-interfaces/00/ip",
            MD + "instance/network-interfaces/0/mac",
            MD + "instance/attributes/" + "a" * 129,
            MD + "instance/attributes/a/b",
            "/computeMetadata/v2/instance/id",
            GA + "cogworx",
            GA + "cogworx/",
            GA + "cogworx/ready/extra",
            GA + "cog.worx/ready",
            GA + "cogworx/" + "k" * 65,
        ):
            with self.subTest(path):
                self.assertMetadataResponse(self.get(path), 404)

    def test_metadata_flavor_is_required(self):
        path = MD + "instance/id"
        self.assertMetadataResponse(self.get(path, flavor=False), 403)
        self.assertMetadataResponse(self.get(path, flavor=False, headers=[("Metadata-Flavor", "google")]), 403)
        self.assertMetadataResponse(self.get(path, headers=[("Metadata-Flavor", "Google")]), 403)  # twice

    def test_x_forwarded_for_is_403(self):
        r = self.get(MD + "instance/attributes/cogworx-start-nonce", headers=[("X-Forwarded-For", "192.0.2.9")])
        self.assertMetadataResponse(r, 403)
        self.assertNotIn(CASES["typical"]["expect_attrs"]["cogworx-start-nonce"].encode(), r.body)

    def test_non_root_or_unknown_peer_is_403(self):
        for uid in (1000, 65534, None):
            self.peer = uid
            with self.subTest(uid=uid):
                for method, path in (("GET", MD + "instance/attributes/cogworx-start-nonce"),
                                     ("GET", MD + "instance/id"),
                                     ("PUT", GA + "cogworx/ready")):
                    r = self.send(method, path, body=b"x" if method == "PUT" else None)
                    self.assertMetadataResponse(r, 403)
        self.peer = 0
        self.assertMetadataResponse(self.get(GA + "cogworx/ready"), 404)  # the refused PUT stored nothing

    def test_query_escape_and_traversal_are_400(self):
        for path in (
            MD + "instance/id?recursive=true",
            MD + "instance/attributes/?alt=json",
            MD + "instance/attributes/%63ogworx-instance",
            MD + "instance/../instance/id",
            MD + "instance/attributes/..",
            GA + "cogworx/..",
        ):
            with self.subTest(path):
                self.assertMetadataResponse(self.get(path), 400)

    def test_other_methods_are_405(self):
        for method, path in (
            ("POST", MD + "instance/id"),
            ("PATCH", GA + "cogworx/ready"),
            ("OPTIONS", MD + "instance/id"),
            ("PUT", MD + "instance/id"),
            ("DELETE", MD + "instance/attributes/cogworx-instance"),
            ("PUT", MD + "instance/network-interfaces/0/ip"),
        ):
            with self.subTest(method=method, path=path):
                r = self.send(method, path, body=b"" if method in ("PUT", "POST", "PATCH") else None)
                self.assertMetadataResponse(r, 405)
        r = exchange(self.port, request("HEAD", MD + "instance/id"))
        self.assertEqual(r.code, 405)
        self.assertEqual(r.header("Metadata-Flavor"), "Google")
        self.assertEqual(r.body, b"")

    def test_get_with_a_body_is_400(self):
        self.assertMetadataResponse(self.send("GET", MD + "instance/id", body=b"x"), 400)

    def test_protocol_errors_still_carry_the_flavor_header(self):
        for data, code in (
            (b"GET " + MD.encode() + b"instance/id HTTP/9.9\r\n\r\n", 505),
            (b"GET " + MD.encode() + b"instance/id HTTP/x\r\n\r\n", 400),
            (b"NONSENSE\r\n\r\n", 400),
            (request("GET", MD + "instance/id", headers=[("X-Pad-%d" % i, "1") for i in range(101)]), 431),
        ):
            with self.subTest(data=data[:40]):
                r = exchange(self.port, data)
                self.assertMetadataResponse(r, code)
                self.assertNotIn(OWNER.encode(), r.raw)

    def test_http09_gets_no_answer(self):
        with self.assertNoLogs(md.LOG, logging.ERROR):
            self.assertEqual(exchange(self.port, b"GET " + MD.encode() + b"instance/id\r\n").raw, b"")

    def test_refusals_over_an_unread_body_still_deliver_their_response(self):
        # The bodies outgrow the handler's 8 KiB read buffer, so the kernel
        # still holds them at close. The server half-closes (FIN) before it
        # closes, so the client reads the whole refusal and a clean EOF rather
        # than a reset; exchange() would raise on a reset.
        self.assertMetadataResponse(exchange(self.port, request("PUT", MD + "instance/attributes/x", body=b"v" * 30000)), 405)
        self.assertMetadataResponse(exchange(self.port, request("PUT", MD + "project/x", body=b"v" * 30000)), 404)
        self.assertMetadataResponse(exchange(self.port, request("PUT", GA + "cogworx/big", body=b"v" * 60000)), 413)
        self.peer = 1000
        self.assertMetadataResponse(exchange(self.port, request("PUT", GA + "cogworx/ready", body=b"v" * 30000)), 403)


class NoBlobTest(ServerCase):
    attrs_case = None

    def test_attributes_404_but_instance_id_200(self):
        self.assertMetadataResponse(self.get(MD + "instance/attributes/cogworx-start-nonce"), 404)
        self.assertMetadataResponse(self.get(MD + "instance/id"), 200)

    def test_instance_id_503_without_a_uuid(self):
        self.app.instance_id = None
        self.assertMetadataResponse(self.get(MD + "instance/id"), 503)


class MaintenanceFlagTest(ServerCase):
    attrs_case = "maintenance-flag"

    def test_flag_is_an_empty_200(self):
        r = self.get(MD + "instance/attributes/cogworx-maintenance")
        self.assertMetadataResponse(r, 200)
        self.assertEqual(r.body, b"")


class NetworkInterfacesTest(ServerCase):
    def test_index_listing_and_ip(self):
        r = self.get(MD + "instance/network-interfaces/")
        self.assertMetadataResponse(r, 200)
        self.assertEqual(r.body, b"0/\n")
        r = self.get(MD + "instance/network-interfaces/0/ip")
        self.assertMetadataResponse(r, 200)
        self.assertEqual(r.body, b"198.51.100.7")

    def test_503_after_waiting_when_there_is_no_address(self):
        self.addr = None
        for path in ("instance/network-interfaces/", "instance/network-interfaces/0/ip"):
            with self.subTest(path):
                start = time.monotonic()
                self.assertMetadataResponse(self.get(MD + path), 503)
                self.assertGreaterEqual(time.monotonic() - start, 0.3)

    def test_an_address_that_lands_mid_wait_is_served(self):
        self.addr = None
        self.app.addr_wait = 5.0
        timer = threading.Timer(0.3, lambda: setattr(self, "addr", "198.51.100.8"))
        timer.start()
        self.addCleanup(timer.cancel)
        r = self.get(MD + "instance/network-interfaces/0/ip")
        self.assertMetadataResponse(r, 200)
        self.assertEqual(r.body, b"198.51.100.8")

    def test_the_metadata_address_is_never_served(self):
        for addr in ("169.254.169.254", "169.254.10.1", "127.0.0.1", "0.0.0.0"):
            self.addr = addr
            with self.subTest(addr):
                self.assertMetadataResponse(self.get(MD + "instance/network-interfaces/0/ip"), 503)


# --- guest attributes -------------------------------------------------------------


class GuestAttributesHTTPTest(ServerCase):
    def state(self):
        with open(self.store.path) as f:
            return json.load(f)

    def assertNoTempFiles(self):
        self.assertEqual(sorted(os.listdir(self.state_dir)), [md.STATE_FILE] if os.path.exists(self.store.path) else [])

    def test_put_get_delete(self):
        nonce = CASES["typical"]["expect_attrs"]["cogworx-start-nonce"]
        self.assertMetadataResponse(self.get(GA + "cogworx/ready"), 404)
        self.assertMetadataResponse(self.send("PUT", GA + "cogworx/ready", body=(nonce + " ok").encode()), 200)
        r = self.get(GA + "cogworx/ready")
        self.assertMetadataResponse(r, 200)
        self.assertEqual(r.body.decode(), nonce + " ok")
        self.assertMetadataResponse(self.send("DELETE", GA + "cogworx/ready"), 200)
        self.assertMetadataResponse(self.get(GA + "cogworx/ready"), 404)
        self.assertMetadataResponse(self.send("DELETE", GA + "cogworx/ready"), 200)  # idempotent

    def test_each_mutation_rewrites_the_state_file(self):
        self.assertFalse(os.path.exists(self.store.path))
        self.send("PUT", GA + "cogworx/vm-host-key", body=b"n1 ssh-ed25519 AAAA")
        self.assertEqual(self.state(), {"v": 1, "boot_id": BOOT_ID, "gen": 1, "sys": SYS_A, "attrs": {"cogworx/vm-host-key": "n1 ssh-ed25519 AAAA"}})
        self.assertEqual(os.stat(self.store.path).st_mode & 0o777, 0o600)
        self.send("PUT", GA + "cogworx/ready", body=b"n1 ok")
        self.send("PUT", GA + "cogworx/ready", body="n1 \u00e9t\u00e9".encode())
        self.assertEqual(self.state()["gen"], 3)
        self.assertEqual(self.state()["attrs"]["cogworx/ready"], "n1 \u00e9t\u00e9")
        self.send("DELETE", GA + "cogworx/absent")
        self.assertEqual(self.state()["gen"], 3, "deleting an absent key is not a mutation")
        self.send("DELETE", GA + "cogworx/ready")
        self.assertEqual(self.state(), {"v": 1, "boot_id": BOOT_ID, "gen": 4, "sys": SYS_A, "attrs": {"cogworx/vm-host-key": "n1 ssh-ed25519 AAAA"}})
        with open(self.store.path, "rb") as f:
            f.read().decode("ascii")  # ensure_ascii: QGA hands it back as-is
        self.assertNoTempFiles()

    def test_value_limit_is_413(self):
        self.assertMetadataResponse(self.send("PUT", GA + "cogworx/big", body=b"x" * 1024), 200)
        self.assertMetadataResponse(self.send("PUT", GA + "cogworx/big", body=b"y" * 1025), 413)
        self.assertEqual(self.get(GA + "cogworx/big").body, b"x" * 1024)

    def test_key_limit_is_413(self):
        for i in range(64):
            self.assertMetadataResponse(self.send("PUT", GA + "ns/k%02d" % i, body=b"v"), 200)
        self.assertMetadataResponse(self.send("PUT", GA + "ns/k64", body=b"v"), 413)
        self.assertMetadataResponse(self.send("PUT", GA + "ns/k00", body=b"replaced"), 200)
        self.send("DELETE", GA + "ns/k01")
        self.assertMetadataResponse(self.send("PUT", GA + "ns/k64", body=b"v"), 200)
        self.assertEqual(len(self.state()["attrs"]), 64)

    def test_empty_value_is_stored(self):
        self.assertMetadataResponse(self.send("PUT", GA + "cogworx/empty", body=b""), 200)
        r = self.get(GA + "cogworx/empty")
        self.assertMetadataResponse(r, 200)
        self.assertEqual(r.body, b"")

    def test_malformed_puts_are_400(self):
        path = GA + "cogworx/ready"
        cases = {
            "no Content-Length": request("PUT", path),
            "chunked": request("PUT", path, headers=[("Transfer-Encoding", "chunked")]) + b"2\r\nok\r\n0\r\n\r\n",
            "non-numeric length": request("PUT", path, headers=[("Content-Length", "two")]) + b"ok",
            "negative length": request("PUT", path, headers=[("Content-Length", "-1")]),
            "two lengths": request("PUT", path, headers=[("Content-Length", "2"), ("Content-Length", "2")]) + b"ok",
            "not UTF-8": request("PUT", path, body=b"\xff\xfe"),
        }
        for name, data in cases.items():
            with self.subTest(name):
                self.assertMetadataResponse(exchange(self.port, data), 400)
        self.assertFalse(os.path.exists(self.store.path))

    def test_a_failed_write_changes_nothing(self):
        self.send("PUT", GA + "cogworx/ready", body=b"n1 ok")
        before = self.state()
        with mock.patch.object(md.os, "replace", side_effect=OSError(errno.ENOSPC, "No space left on device")):
            self.assertMetadataResponse(self.send("PUT", GA + "cogworx/ready", body=b"n2 ok"), 500)
            self.assertMetadataResponse(self.send("DELETE", GA + "cogworx/ready"), 500)
        self.assertEqual(self.get(GA + "cogworx/ready").body, b"n1 ok")
        self.assertEqual(self.state(), before)
        self.assertNoTempFiles()


class GuestAttributeStoreTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="cogworx-pve-ga-")
        self.addCleanup(shutil.rmtree, tmp, True)
        self.dir = os.path.join(tmp, "run", "cogworx")

    def write(self, doc):
        with open(os.path.join(self.dir, md.STATE_FILE), "w") as f:
            f.write(doc if isinstance(doc, str) else json.dumps(doc))

    def read(self):
        with open(os.path.join(self.dir, md.STATE_FILE)) as f:
            return json.load(f)

    def test_creates_a_private_dir_and_no_file_until_a_mutation(self):
        md.GuestAttributeStore(self.dir, BOOT_ID)
        self.assertEqual(os.stat(self.dir).st_mode & 0o777, 0o700)
        self.assertEqual(os.listdir(self.dir), [])

    def test_a_restart_in_the_same_boot_readopts_the_file(self):
        first = md.GuestAttributeStore(self.dir, BOOT_ID)
        first.put("cogworx/ready", "n1 ok")
        first.put("cogworx/vm-host-key", "n1 ssh-ed25519 AAAA")
        with self.assertLogs(md.LOG, logging.INFO) as logs:
            second = md.GuestAttributeStore(self.dir, BOOT_ID)
        self.assertIn("re-adopted 2 attribute(s) at gen 2", "\n".join(logs.output))
        self.assertEqual(second.get("cogworx/ready"), "n1 ok")
        second.delete("cogworx/ready")
        self.assertEqual(self.read()["gen"], 3)

    def test_the_store_enforces_its_own_bounds(self):
        store = md.GuestAttributeStore(self.dir, BOOT_ID)
        for key in ("no-slash", "a/b/c", "a/", "/b", "a.b/c"):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    store.put(key, "v")
        with self.assertRaises(md.LimitExceeded):
            store.put("a/b", "\u00e9" * 513)  # 1026 UTF-8 bytes
        self.assertEqual(os.listdir(self.dir), [])

    def test_another_boots_file_is_discarded_and_rewritten(self):
        os.makedirs(self.dir)
        self.write({"v": 1, "boot_id": "another-boot", "gen": 7, "sys": SYS_B, "attrs": {"cogworx/ready": "old ok"}})
        store = md.GuestAttributeStore(self.dir, BOOT_ID, SYS_A)
        self.assertIsNone(store.get("cogworx/ready"))
        self.assertEqual(self.read(), {"v": 1, "boot_id": BOOT_ID, "gen": 0, "sys": SYS_A, "attrs": {}})

    def test_malformed_files_are_discarded(self):
        os.makedirs(self.dir)
        for doc in (
            "{not json",
            {"v": 2, "boot_id": BOOT_ID, "gen": 1, "attrs": {}},
            {"v": 1, "boot_id": BOOT_ID, "gen": True, "attrs": {}},
            {"v": 1, "boot_id": BOOT_ID, "gen": 1, "attrs": {"no-slash": "x"}},
            {"v": 1, "boot_id": BOOT_ID, "gen": 1, "attrs": {"a/b": 1}},
            {"v": 1, "boot_id": BOOT_ID, "gen": 1, "attrs": {"a/b": "x" * 1025}},
            {"v": 1, "boot_id": BOOT_ID, "gen": 1, "attrs": {"a/k%d" % i: "v" for i in range(65)}},
        ):
            with self.subTest(doc=str(doc)[:60]):
                self.write(doc)
                store = md.GuestAttributeStore(self.dir, BOOT_ID, SYS_A)
                self.assertEqual(self.read(), {"v": 1, "boot_id": BOOT_ID, "gen": 0, "sys": SYS_A, "attrs": {}})
                self.assertIsNone(store.get("a/b"))

    # --- `sys`: the booted system, read once at start -----------------------

    def link(self, target):
        path = os.path.join(os.path.dirname(self.dir), "booted-system")
        if os.path.lexists(path):
            os.unlink(path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.symlink(target, path)
        return path

    def test_sys_is_absent_when_unknown(self):
        cases = {
            "missing link": os.path.join(os.path.dirname(self.dir), "no-such-link"),
            "link to a store path that is not a system": self.link("/nix/store/" + "c" * 32 + "-hello-2.12"),
        }
        for name, path in cases.items():
            with self.subTest(name):
                with self.assertLogs(md.LOG, logging.WARNING):
                    booted = md.read_booted_system(path)
                self.assertIsNone(booted)
                if os.path.exists(os.path.join(self.dir, md.STATE_FILE)):
                    os.unlink(os.path.join(self.dir, md.STATE_FILE))
                store = md.GuestAttributeStore(self.dir, BOOT_ID, booted)
                store.put("cogworx/ready", "n1 ok")
                self.assertEqual(self.read(), {"v": 1, "boot_id": BOOT_ID, "gen": 1, "attrs": {"cogworx/ready": "n1 ok"}})
        # A link to a directory that merely sits elsewhere.
        other = os.path.join(os.path.dirname(self.dir), "nixos-system-x")
        os.makedirs(other)
        with self.assertLogs(md.LOG, logging.WARNING):
            self.assertIsNone(md.read_booted_system(self.link(other)))

    def test_sys_from_a_valid_link(self):
        path = self.link(SYS_A)
        self.assertEqual(md.read_booted_system(path), SYS_A)
        store = md.GuestAttributeStore(self.dir, BOOT_ID, md.read_booted_system(path))
        store.put("cogworx/ready", "n1 ok")
        with open(os.path.join(self.dir, md.STATE_FILE), "rb") as f:
            raw = f.read()
        self.assertEqual(json.loads(raw), {"v": 1, "boot_id": BOOT_ID, "gen": 1, "sys": SYS_A, "attrs": {"cogworx/ready": "n1 ok"}})
        self.assertTrue(raw.startswith(b'{"v":1,"boot_id":"%s","gen":1,"sys":"%s","attrs":' % (BOOT_ID.encode(), SYS_A.encode())), raw)

    def test_a_restart_never_takes_sys_from_the_file(self):
        os.makedirs(self.dir)
        for booted, want in ((SYS_A, {"sys": SYS_A}), (None, {})):
            with self.subTest(booted=booted):
                self.write({"v": 1, "boot_id": BOOT_ID, "gen": 5, "sys": SYS_B, "attrs": {"cogworx/ready": "n1 ok"}})
                with self.assertLogs(md.LOG, logging.INFO) as logs:
                    store = md.GuestAttributeStore(self.dir, BOOT_ID, booted)
                self.assertIn("re-adopted 1 attribute(s) at gen 5", "\n".join(logs.output))
                self.assertEqual(store.get("cogworx/ready"), "n1 ok")
                store.put("cogworx/vm-host-key", "n1 ssh-ed25519 AAAA")
                self.assertEqual(self.read(), dict({"v": 1, "boot_id": BOOT_ID, "gen": 6,
                                                    "attrs": {"cogworx/ready": "n1 ok", "cogworx/vm-host-key": "n1 ssh-ed25519 AAAA"}}, **want))


# --- peer uid and interface address ---------------------------------------------------

PROC_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def proc_row(sl, local, rem, st, uid, inode=None):
    return "%4d: %s %s %s 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0 20 4 30 10 -1\n" % (
        sl, md._proc_hexaddr(local), md._proc_hexaddr(rem), st, uid, 1000 + sl if inode is None else inode)


SERVER = ("169.254.169.254", 80)
CLIENT = ("169.254.169.254", 41234)


class PeerUidTest(unittest.TestCase):
    def test_the_client_row_is_matched_not_the_server_row(self):
        text = PROC_HEADER + proc_row(0, SERVER, ("0.0.0.0", 0), "0A", 0) \
            + proc_row(1, SERVER, CLIENT, "01", 0) + proc_row(2, CLIENT, SERVER, "01", 1000)
        self.assertEqual(md.match_proc_net_tcp(text, CLIENT, SERVER), 1000)
        text = PROC_HEADER + proc_row(1, SERVER, CLIENT, "01", 0) + proc_row(2, CLIENT, SERVER, "01", 0)
        self.assertEqual(md.match_proc_net_tcp(text, CLIENT, SERVER), 0)

    def test_rows_that_do_not_carry_an_owner_fail_closed(self):
        # TIME_WAIT and SYN_RECV rows print uid 0 whoever owned the socket.
        for st in ("06", "03", "0A", "02"):
            with self.subTest(st=st):
                text = PROC_HEADER + proc_row(2, CLIENT, SERVER, st, 0)
                self.assertIsNone(md.match_proc_net_tcp(text, CLIENT, SERVER))

    def test_an_orphaned_client_socket_fails_closed(self):
        # A client that sends its request and then close()s leaves an orphan
        # in FIN_WAIT1/FIN_WAIT2, printed as uid 0 with inode 0 whoever
        # opened it, while its request is still served from our buffer.
        for st in ("04", "05"):
            with self.subTest(st=st):
                text = PROC_HEADER + proc_row(2, CLIENT, SERVER, st, 0, inode=0)
                self.assertIsNone(md.match_proc_net_tcp(text, CLIENT, SERVER))
        # The same states with an owner (a half-close, shutdown(SHUT_WR))
        # still resolve.
        text = PROC_HEADER + proc_row(2, CLIENT, SERVER, "05", 1000, inode=4242)
        self.assertEqual(md.match_proc_net_tcp(text, CLIENT, SERVER), 1000)
        # A row too short to carry the inode column names nobody.
        text = PROC_HEADER + " ".join(proc_row(2, CLIENT, SERVER, "01", 0).split()[:9]) + "\n"
        self.assertIsNone(md.match_proc_net_tcp(text, CLIENT, SERVER))

    def test_missing_ambiguous_or_ipv6_fails_closed(self):
        self.assertIsNone(md.match_proc_net_tcp(PROC_HEADER, CLIENT, SERVER))
        text = PROC_HEADER + proc_row(2, CLIENT, SERVER, "01", 0) + proc_row(3, CLIENT, SERVER, "05", 1000)
        self.assertIsNone(md.match_proc_net_tcp(text, CLIENT, SERVER))
        self.assertIsNone(md.match_proc_net_tcp(PROC_HEADER, ("::1", 41234, 0, 0), ("::1", 80, 0, 0)))
        self.assertIsNone(md.proc_peer_uid(SERVER, CLIENT, path="/nonexistent/proc/net/tcp"))

    def test_a_live_loopback_connection_resolves_to_this_process(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            with socket.create_connection(listener.getsockname(), timeout=5) as client:
                conn, peer = listener.accept()
                with conn:
                    self.assertEqual(peer, client.getsockname())
                    self.assertEqual(md.proc_peer_uid(conn.getsockname(), peer), os.geteuid())

    def test_a_live_closed_client_is_not_resolved(self):
        # The same orphan on the real kernel: send, close, and the request is
        # still readable here while the client's row reads uid 0, inode 0.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            client = socket.create_connection(listener.getsockname(), timeout=5)
            conn, peer = listener.accept()
            with conn:
                client.sendall(b"GET / HTTP/1.0\r\n\r\n")
                client.close()
                self.assertEqual(conn.recv(64), b"GET / HTTP/1.0\r\n\r\n")
                self.assertIsNone(md.proc_peer_uid(conn.getsockname(), peer))


class InterfaceAddressTest(unittest.TestCase):
    def test_usable_addresses(self):
        for value in ("198.51.100.7", "192.0.2.10", "192.168.0.10", "100.64.0.1"):
            self.assertTrue(md.usable_ipv4(value), value)
        for value in ("169.254.169.254", "169.254.0.1", "127.0.0.1", "0.0.0.0", "224.0.0.1",
                      "255.255.255.255", "240.0.0.1", "not-an-ip", "", None):
            self.assertFalse(md.usable_ipv4(value), value)

    def test_missing_interfaces_have_no_address(self):
        self.assertIsNone(md.iface_ipv4("cwxnoiface0"))
        self.assertIsNone(md.iface_ipv4("x" * 16))
        self.assertIsNone(md.iface_ipv4(""))

    def test_loopback_address_is_read(self):
        addr = md.iface_ipv4("lo")
        if addr is None:
            self.skipTest("lo has no IPv4 address here")
        self.assertEqual(addr, "127.0.0.1")
        self.assertFalse(md.usable_ipv4(addr))


# --- the CLI, as systemd and the hostname unit run it ---------------------------------


class CLITest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="cogworx-pve-cli-")
        self.addCleanup(shutil.rmtree, tmp, True)
        self.tmp = tmp
        self.serial = os.path.join(tmp, "product_serial")
        self.uuid = os.path.join(tmp, "product_uuid")
        with open(self.uuid, "w") as f:
            f.write(OWNER.upper() + "\n")
        self.set_serial(CASES["typical"]["serial_blob"].encode())

    def set_serial(self, data):
        with open(self.serial, "wb") as f:
            f.write(data + b"\n")

    def run_cli(self, *args, **kw):
        return subprocess.run(
            [sys.executable, str(MODULE_PATH), "--dmi-serial-path", self.serial, "--dmi-uuid-path", self.uuid] + list(args),
            capture_output=True, text=True, timeout=30, **kw)

    def test_print_attr_from_either_serial_form(self):
        blob = CASES["typical"]["serial_blob"].encode()
        for form, data in (("raw", blob), ("base64", base64.b64encode(blob))):
            with self.subTest(form):
                self.set_serial(data)
                p = self.run_cli("--print-attr", "cogworx-hostname")
                self.assertEqual((p.returncode, p.stdout), (0, "cwx-5010\n"), p.stderr)

    def test_print_attr_absent_exits_1(self):
        p = self.run_cli("--print-attr", "cogworx-resolver")
        self.assertEqual((p.returncode, p.stdout), (1, ""))
        self.assertIn("not set", p.stderr)

    def test_print_attr_on_a_rejected_blob_exits_1_and_says_why(self):
        self.set_serial(CASES["w-full-refused"]["serial_blob"].encode())
        p = self.run_cli("--print-attr", "cogworx-network")
        self.assertEqual((p.returncode, p.stdout), (1, ""))
        self.assertIn("REJECTED (invalid-value:w", p.stderr)

    def test_print_attr_of_a_flag_prints_an_empty_line(self):
        self.set_serial(CASES["maintenance-flag"]["serial_blob"].encode())
        p = self.run_cli("--print-attr", "cogworx-maintenance")
        self.assertEqual((p.returncode, p.stdout), (0, "\n"), p.stderr)

    def test_print_attr_without_dmi_exits_1(self):
        os.unlink(self.serial)
        self.assertEqual(self.run_cli("--print-attr", "cogworx-hostname").returncode, 1)

    def test_usage_errors_exit_2(self):
        for args in ((), ("serve", "--print-attr", "cogworx-hostname"), ("--listen", "127.0.0.1:0", "--print-attr", "x"), ("start",)):
            with self.subTest(args=args):
                self.assertEqual(self.run_cli(*args).returncode, 2)

    def test_serve_without_a_socket_exits_2(self):
        for env in ({}, {"LISTEN_PID": "1", "LISTEN_FDS": "1"}):
            with self.subTest(env=env):
                p = self.run_cli("serve", "--state-dir", os.path.join(self.tmp, "state"),
                                 env=dict(os.environ, **env))
                self.assertEqual(p.returncode, 2)
                self.assertIn("no socket", p.stderr)

    def test_systemd_socket_wants_exactly_one_fd(self):
        env = {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "2"}
        with mock.patch.dict(os.environ, env):
            with self.assertRaises(SystemExit):
                md.systemd_socket()
            self.assertNotIn("LISTEN_FDS", os.environ)

    def expected_live_code(self):
        # The real /proc/net/tcp resolver runs here: this test's own uid is the
        # peer, so only a root test runner may be served.
        return 200 if os.geteuid() == 0 else 403

    def stop(self, proc, reader=None):
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(10)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if reader is not None:
                reader.join(5)
            proc.stderr.close()
        self.assertEqual(proc.returncode, 0)

    def test_serve_socket_activated(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = listener.getsockname()[1]
        fd = listener.fileno()
        # LISTEN_PID must be the server's own pid, which only exists after
        # exec: the shell moves the socket to fd 3 and exports $$ before
        # exec'ing python in its place, exactly as systemd hands it over.
        proc = subprocess.Popen(
            ["sh", "-c", 'exec 3<&"$1"; shift; LISTEN_PID=$$; LISTEN_FDS=1; export LISTEN_PID LISTEN_FDS; exec "$@"',
             "sh", str(fd), sys.executable, str(MODULE_PATH), "serve",
             "--dmi-serial-path", self.serial, "--dmi-uuid-path", self.uuid,
             "--state-dir", os.path.join(self.tmp, "state")],
            pass_fds=[fd], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        listener.close()
        try:
            r = exchange(port, request("GET", MD + "instance/id"), timeout=20)
            self.assertEqual(r.code, self.expected_live_code(), r.raw[:200])
            self.assertTrue(r.status_line.startswith("HTTP/1.0 "))
            self.assertEqual(r.header("Metadata-Flavor"), "Google")
            if r.code == 200:
                self.assertEqual(r.body, OWNER.encode())
        finally:
            self.stop(proc)

    def test_serve_listen_mode(self):
        booted = os.path.join(self.tmp, "booted-system")
        os.symlink(SYS_A, booted)
        proc = subprocess.Popen(
            [sys.executable, str(MODULE_PATH), "serve", "--listen", "127.0.0.1:0",
             "--dmi-serial-path", self.serial, "--dmi-uuid-path", self.uuid,
             "--state-dir", os.path.join(self.tmp, "state"), "--booted-system-path", booted],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        lines = queue.Queue()
        reader = threading.Thread(target=lambda: [lines.put(line) for line in proc.stderr], daemon=True)
        reader.start()
        try:
            deadline = time.monotonic() + 20
            port = None
            while port is None:
                line = lines.get(timeout=max(0.1, deadline - time.monotonic()))
                if "listening on 127.0.0.1:" in line:
                    port = int(line.rsplit(":", 1)[1])
            r = exchange(port, request("GET", MD + "instance/attributes/cogworx-hostname"))
            self.assertEqual(r.code, self.expected_live_code())
            self.assertEqual(r.header("Metadata-Flavor"), "Google")
        finally:
            self.stop(proc, reader)


if __name__ == "__main__":
    unittest.main()
