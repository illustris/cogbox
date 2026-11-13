"""Run the guest helper cogbox-git-hosts against a stub HTTP server.

Usage: python3 test_git_hosts_helper.py <cogbox-git-hosts.sh> [<cogbox binary>] -v

The raw helper body is run under the same prelude the guest package adds
(errexit, nounset, pipefail, summary_layout), with its guest paths relocated
into temp directories. A curl shim first on PATH logs its argv and routes
every connection to the stub. With the cogbox binary, a round trip pins the
file name, directory layout and schema between the Zig writer and this reader.
"""
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

SCRIPT = Path(sys.argv.pop(1)).read_text()
COGBOX = None
if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
    COGBOX = Path(sys.argv.pop(1)).resolve()

REAL_CURL = shutil.which("curl")
BASH = shutil.which("bash")
HOST = "git.example.com"
# A git host the owner reaches through an injected secret, not a grant.
OTHER = "git.other.example.com"
GRANTS = {"grants": [{"repo": "acme/widgets", "caps": ["git-read"]}]}
# The list holds grant hosts only; every listing and empty list must say that a
# host reached through an injected secret is missing from it by design.
NOT_LISTED = "A git host reached through an injected secret instead of a grant is not listed"
FORBIDDEN_FLAGS = ("-L", "--location", "-u", "--user", "-n", "--netrc", "-H", "--header",
                   "-b", "--cookie", "-K", "--config", "-k", "--insecure")
CRED_HEADERS = ("authorization", "private-token", "cookie", "proxy-authorization")


class Stub(http.server.ThreadingHTTPServer):
    daemon_threads = True
    # Never share the port: with SO_REUSEPORT another listener on it (a
    # concurrent run of a similar stub) could take this test's connections.
    allow_reuse_address = False
    allow_reuse_port = False

    def __init__(self, port):
        self.requests = []
        # Host header -> (status, headers, body bytes)
        self.answers = {}
        super().__init__(("127.0.0.1", port), Handler)


def flat(text):
    """Text with every whitespace run folded to one space (the usage text wraps)."""
    return " ".join(text.split())


def bind_stub():
    """The stub on the first free port in 29100-29199."""
    for port in range(29100, 29200):
        try:
            return Stub(port)
        except OSError:
            continue
    raise RuntimeError("no free port in 29100-29199")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        self.server.requests.append((self.command, self.path, host,
                                     {k.lower(): v for k, v in self.headers.items()}))
        status, headers, body = self.server.answers.get(
            host, (200, {"Content-Type": "application/json"}, json.dumps(GRANTS).encode()))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Helper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stub = bind_stub()
        cls.port = cls.stub.server_address[1]
        cls.thread = threading.Thread(target=cls.stub.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.stub.shutdown()
        cls.stub.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="githosts-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        # None of these names contains the guest paths being relocated.
        self.state = self.root / "state"        # /var/lib/cogbox-state
        self.vmdata = self.root / "vmdata"      # /var/lib/cogbox
        self.run = self.root / "run"            # /run/cogbox
        self.home = self.root / "home"
        self.bin = self.root / "bin"
        for d in (self.state, self.vmdata, self.run, self.home, self.bin):
            d.mkdir()
        self.curl_log = self.root / "curl.log"
        shim = self.bin / "curl"
        shim.write_text(
            "#!" + BASH + "\n"
            'printf "%s\\x1f" "$@" >> "$SHIM_LOG"; printf "\\n" >> "$SHIM_LOG"\n'
            'first=$1; shift\n'
            'exec ' + REAL_CURL + ' "$first" --connect-to "::127.0.0.1:$SHIM_PORT" "$@"\n')
        shim.chmod(0o755)
        # Credentials a curl that read them would send; -q and the absent flags
        # must keep every one of them out of the request.
        (self.home / ".curlrc").write_text(
            'header = "Authorization: Bearer leak"\nuser = "u:p"\nlocation\ncookie = "a=b"\n')
        netrc = self.home / ".netrc"
        netrc.write_text(f"machine {HOST} login u password p\n")
        netrc.chmod(0o600)
        self.stub.requests.clear()
        self.stub.answers.clear()
        self.shim_port = self.port

    def summary_path(self, layout, instance="demo"):
        if layout == "vm":
            return self.vmdata / "git-hosts.json"
        return self.state / "data/cogbox/instances" / instance / "git-hosts.json"

    def environment(self, mode="cogworx", instance="demo", raw=None):
        text = raw if raw is not None else json.dumps(
            {"version": 1, "mode": mode, "instance": instance, "workspace": "/root/work"})
        (self.run / "environment.json").write_text(text)

    def publish(self, layout, doc, instance="demo"):
        path = self.summary_path(layout, instance)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(doc if isinstance(doc, str) else json.dumps(doc))

    def helper(self, layout, *args):
        source = SCRIPT.replace("/var/lib/cogbox-state", str(self.state))
        source = source.replace("/var/lib/cogbox", str(self.vmdata))
        source = source.replace("/run/cogbox", str(self.run))
        prelude = f"set -o errexit\nset -o nounset\nset -o pipefail\nsummary_layout={layout}\n"
        env = {"PATH": f"{self.bin}:{os.environ['PATH']}", "HOME": str(self.home),
               "SHIM_LOG": str(self.curl_log), "SHIM_PORT": str(self.shim_port),
               "TMPDIR": str(self.root)}
        return subprocess.run([BASH, "-c", prelude + source, "cogbox-git-hosts", *args],
                              env=env, capture_output=True, text=True, timeout=60)

    def curl_calls(self):
        if not self.curl_log.exists():
            return []
        return [line.split("\x1f")[:-1] for line in self.curl_log.read_text().splitlines()]

    def assert_no_curl(self):
        self.assertEqual(self.curl_calls(), [])
        self.assertEqual(self.stub.requests, [])

    # --- absent / empty / local ---

    def test_absent_exits_11_without_any_request(self):
        cases = [("vm", None), ("container", None)]
        for layout, _ in cases:
            self.environment()
            r = self.helper(layout)
            self.assertEqual(r.returncode, 11, r.stdout + r.stderr)
            self.assertIn("Ask the user which git host", r.stdout)
            self.assertEqual(r.stderr, "")
        # Container: no environment record, or an instance that is not a name.
        self.publish("container", {"version": 1, "hosts": [{"host": HOST, "scheme": "http", "discovery": True}]})
        (self.run / "environment.json").unlink()
        self.assertEqual(self.helper("container").returncode, 11)
        self.publish("container", {"version": 1, "hosts": [{"host": HOST}]}, instance="x")
        self.environment(instance="../x")
        self.assertEqual(self.helper("container").returncode, 11)
        # Contents that are not a v1 list.
        self.environment()
        forged = [{"host": h, "scheme": "http", "discovery": True}
                  for h in ("x/../y", "a b", "-evil", f"{HOST}:8080", "*.example.com")] + [{"host": 7}, "str", None]
        for doc in ("not json", '{"version":2,"hosts":[]}', '{"version":1,"hosts":{}}',
                    '{"version":1}', "[]", json.dumps({"version": 1, "hosts": forged})):
            for layout in ("vm", "container"):
                self.publish(layout, doc)
                r = self.helper(layout)
                self.assertEqual(r.returncode, 11, (layout, doc, r.stdout, r.stderr))
        # A directory or a FIFO at the name.
        path = self.summary_path("vm")
        path.unlink()
        path.mkdir()
        self.assertEqual(self.helper("vm").returncode, 11)
        path.rmdir()
        os.mkfifo(path)
        self.assertEqual(self.helper("vm").returncode, 11)
        self.assert_no_curl()

    def test_empty_exits_10_and_names_the_git_access_tab(self):
        self.environment()
        for layout in ("vm", "container"):
            self.publish(layout, {"version": 1, "hosts": []})
            r = self.helper(layout)
            self.assertEqual(r.returncode, 10, r.stdout + r.stderr)
            self.assertIn("Git access tab", r.stdout)
            self.assertIn("wait about 15 seconds", r.stdout)
        self.assert_no_curl()

    def test_local_mode_exits_10_even_with_a_populated_list(self):
        self.environment(mode="local")
        for layout in ("vm", "container"):
            self.publish(layout, {"version": 1, "hosts": [{"host": HOST, "scheme": "http", "discovery": True}]})
            r = self.helper(layout)
            self.assertEqual(r.returncode, 10, r.stdout + r.stderr)
            self.assertIn("local cogbox sandbox", r.stdout)
            self.assertIn('"Local mode"', r.stdout)
            self.assertNotIn("Git access tab", r.stdout)
        self.assert_no_curl()

    def test_usage(self):
        r = self.helper("vm", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("Exit codes", r.stdout)
        r = self.helper("vm", "--bogus")
        self.assertEqual(r.returncode, 64)
        self.assertIn("Usage", r.stderr)
        self.assert_no_curl()

    def test_lists_grant_hosts_only_and_says_so(self):
        # The list holds grant hosts only: a host reached through an injected
        # secret is never in it. So every output that describes the list, lists
        # hosts or reports none live says so, and none claims to cover every
        # credential the host side holds -- an agent told "no git host is
        # proxied" asked about a grant instead of using a host its injected
        # secret already covered.
        pointer = 'see "SSH remotes, other hosts, Open repository" in the cogbox-git skill'
        self.environment()
        outputs = []
        for layout in ("vm", "container"):
            self.publish(layout, {"version": 1, "hosts": []})
            outputs.append(self.helper(layout))
            self.publish(layout, {"version": 1, "hosts": [{"host": HOST, "discovery": False}]})
            outputs.append(self.helper(layout))
        self.assertEqual([r.returncode for r in outputs], [10, 0, 10, 0],
                         [r.stdout + r.stderr for r in outputs])
        # Usage runs before the environment record is read, so it must hold in
        # local mode too: no pointer into the skill's cogworx-only section.
        self.environment(mode="local")
        usage = self.helper("vm", "--help")
        self.assertEqual(usage.returncode, 0)
        self.assertNotIn(pointer, flat(usage.stdout))
        for r in outputs + [usage]:
            text = flat(r.stdout)
            self.assertIn(NOT_LISTED, text)
            self.assertIn("Git access tab", text)
            for overclaim in ("host side holds", "host-held", "is proxied"):
                self.assertNotIn(overclaim, text)
        for r in outputs:
            self.assertIn(pointer, flat(r.stdout))
        self.assert_no_curl()

    # --- populated ---

    def assert_clean_curl(self, calls):
        for argv in calls:
            self.assertEqual(argv[0], "-q")
            for flag in FORBIDDEN_FLAGS:
                self.assertNotIn(flag, argv)
        for _, _, _, headers in self.stub.requests:
            for h in CRED_HEADERS:
                self.assertNotIn(h, headers)

    def test_populated_discovery_host_on_both_layouts(self):
        self.environment()
        for layout in ("vm", "container"):
            self.stub.requests.clear()
            self.curl_log.unlink(missing_ok=True)
            self.publish(layout, {"version": 1, "hosts": [{"host": HOST, "scheme": "http", "discovery": True}]})
            r = self.helper(layout)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(r.stderr, "")
            self.assertIn("can overwrite it", r.stdout)
            self.assertIn(f"host={HOST} scheme=http discovery=yes base=http://{HOST}\n", r.stdout)
            self.assertIn("  grants=" + json.dumps(GRANTS, separators=(",", ":")) + "\n", r.stdout)
            self.assertEqual([(m, p, h) for m, p, h, _ in self.stub.requests], [("GET", "/_cogbox/grants", HOST)])
            self.assert_clean_curl(self.curl_calls())

    def test_legacy_host_is_never_probed(self):
        self.environment()
        self.publish("vm", {"version": 1, "hosts": [{"host": HOST, "discovery": False}]})
        r = self.helper("vm")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"host={HOST} scheme=unknown discovery=no\n", r.stdout)
        self.assertNotIn("base=", r.stdout)
        self.assertNotIn("grants=", r.stdout)
        self.assert_no_curl()

    def test_unusable_answers(self):
        self.environment()
        self.publish("vm", {"version": 1, "hosts": [{"host": HOST, "scheme": "http", "discovery": True}]})
        marker = "MARKER-not-for-the-agent"
        cases = [
            ((302, {"Location": "/elsewhere"}, b""), "http=302\n"),
            ((200, {"Content-Type": "text/html"}, f"<html>{marker}</html>".encode()), "http=200\n"),
            ((200, {}, json.dumps({"other": marker}).encode()), "http=200\n"),
            ((403, {"X-Cogbox-Deny": "no_route"}, marker.encode()), "http=403 deny=no_route\n"),
            ((403, {"X-Cogbox-Deny": "bad value!"}, b""), "http=403\n"),
        ]
        for answer, tail in cases:
            self.stub.requests.clear()
            self.stub.answers[HOST] = answer
            r = self.helper("vm")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("  grants=unavailable " + tail, r.stdout)
            self.assertNotIn(marker, r.stdout)
            self.assertEqual(len(self.stub.requests), 1)
            self.assertEqual(self.stub.requests[0][1], "/_cogbox/grants")

    def test_closed_port_reports_000(self):
        self.environment()
        self.publish("vm", {"version": 1, "hosts": [{"host": HOST, "scheme": "http", "discovery": True}]})
        self.shim_port = self.closed_port()
        r = self.helper("vm")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(r.stderr, "")
        self.assertIn("  grants=unavailable http=000\n", r.stdout)

    def test_forged_entries_never_reach_curl(self):
        self.environment()
        forged = ["x/../y", "a b", "-evil", f"{HOST}:8080", "*.example.com", "evil\nhost=" + HOST]
        hosts = [{"host": h, "scheme": "http", "discovery": True} for h in forged]
        hosts += [{"host": 7, "scheme": "http", "discovery": True},
                  {"host": HOST, "scheme": "http", "discovery": True}]
        self.publish("vm", {"version": 1, "hosts": hosts})
        r = self.helper("vm")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("were skipped", r.stdout)
        calls = self.curl_calls()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][-1], f"http://{HOST}/_cogbox/grants")
        log = self.curl_log.read_text()
        for h in forged:
            self.assertNotIn(h, log)
        self.assertEqual(r.stdout.count("host="), 1)
        self.assert_clean_curl(calls)

    def closed_port(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def test_cacert_only_when_the_bundle_exists(self):
        # Only the argv matters here: the https request goes to a closed port.
        self.shim_port = self.closed_port()
        self.environment()
        self.publish("vm", {"version": 1, "hosts": [{"host": HOST, "scheme": "https", "discovery": True}]})
        r = self.helper("vm")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("--cacert", self.curl_calls()[0])
        (self.run / "ca-bundle.crt").write_text("not a certificate\n")
        self.curl_log.unlink()
        r = self.helper("vm")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        argv = self.curl_calls()[0]
        self.assertEqual(argv[argv.index("--cacert") + 1], str(self.run / "ca-bundle.crt"))

    # --- round trip through the real writer ---

    @unittest.skipIf(COGBOX is None, "no cogbox binary given")
    def test_round_trip_with_the_l7_verbs(self):
        data_root = self.state / "data/cogbox"
        inst_data = data_root / "instances/demo"
        inst_data.mkdir(parents=True)
        config_home = self.root / "config"
        config = config_home / "cogbox/instances/demo/config.json"
        config.parent.mkdir(parents=True)
        config.write_text('{"network":{"rules":[]}}')
        runtime = self.root / "xdg-runtime"
        runtime.mkdir()
        env = {"PATH": os.environ["PATH"], "HOME": str(self.home), "XDG_CONFIG_HOME": str(config_home),
               "XDG_DATA_HOME": str(self.root / "xdg-data"), "XDG_STATE_HOME": str(self.root / "xdg-state"),
               "XDG_RUNTIME_DIR": str(runtime), "COGBOX_DATA": str(data_root)}

        def cogbox(*args, stdin=None):
            r = subprocess.run([str(COGBOX), *args], env=env, input=stdin,
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

        self.environment(instance="demo")
        # The VM guest sees the instance data directory as its /var/lib/cogbox.
        shutil.rmtree(self.vmdata)
        self.vmdata.symlink_to(inst_data)

        # A git host the owner reaches through an injected secret (a basic secret
        # bound with --inject, as the Secrets page does, plus the untagged rule an
        # owner adds) is not a grant host: it is never listed, and the empty list
        # says so instead of claiming no git host is reachable.
        cogbox("secret", "add", "api-token", "--from-stdin", "--audience", OTHER, "--kind", "basic",
               "--inject", "-n", "demo", stdin="user:not-a-token\n")
        cogbox("l7", "add", "allow", OTHER, "-n", "demo")
        for layout in ("vm", "container"):
            r = self.helper(layout)
            self.assertEqual(r.returncode, 10, (layout, r.stdout, r.stderr))
            self.assertIn(NOT_LISTED, flat(r.stdout))
            self.assertNotIn(OTHER, r.stdout)
        self.assert_no_curl()

        cogbox("l7", "replace", "--plugin", "git-grants", "--from-stdin", "-n", "demo",
               stdin=f"allow {HOST} --path /\n")
        cogbox("l7", "policy", "--from-stdin", "-n", "demo", stdin=json.dumps({"version": 1, "providers": [{
            "provider": "GitLab", "plugin": "gitlab", "hosts": [HOST], "secret": "git-gitlab",
            "git_user": "oauth2", "scheme": "http", "grants": []}]}))
        for layout in ("vm", "container"):
            self.stub.requests.clear()
            r = self.helper(layout)
            self.assertEqual(r.returncode, 0, (layout, r.stdout, r.stderr))
            self.assertIn(f"host={HOST} scheme=http discovery=yes base=http://{HOST}\n", r.stdout)
            self.assertIn('"acme/widgets"', r.stdout)
            self.assertEqual(len(self.stub.requests), 1)
            # The injected-secret host stays off the list beside a grant host.
            self.assertNotIn(OTHER, r.stdout)
            self.assertIn(NOT_LISTED, flat(r.stdout))


if __name__ == "__main__":
    unittest.main()
