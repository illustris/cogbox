#!/usr/bin/env python3
"""Route coverage: every metadata access the REALIZED unit scripts make is one
the PVE emulator serves, replayed with each script's own curl flags.

    test_route_coverage.py --emulator PATH --vectors PATH SCRIPT...

SCRIPTS are the realized ExecStart/ExecStartPost/ExecStopPost programs of every
metadata client unit (pve/checks.nix passes them from the evaluated system, so
what is checked is what the image runs, gce/supervise.sh included). Stdlib
only, plus curl on PATH.

What it does:
  1. EXTRACT every access: direct curl lines (a literal
     http://metadata.google.internal/computeMetadata/v1/... URL or one built on
     $MD/$GA), and calls of curl helpers (supervise.sh's md_get/md_has/md_path/
     ga_put/ga_del, self-refresh.sh's md_get/md_path) expanded through the
     helper's own body. Loop variables (`for key in a b`) and the NIC index
     (`${nic%/}`) are expanded. Any line that mentions the metadata server but
     cannot be resolved FAILS the check -- a new access shape is a reason to
     look, never something to skip.
  2. CLASSIFY each path: an attribute the emulator serves (200 with the
     fixture's value), an attribute that is ABSENT BY DESIGN on PVE (exactly
     404, which its consumer treats as "unset"), the instance id, the network
     interface listing and address, or a guest attribute (PUT/GET/DELETE).
     Anything else FAILS: gce/ reads something this emulator does not serve.
  3. REPLAY each access with the script's exact curl argv against the real
     emulator (in-process, on 127.0.0.1, curl --connect-to), asserting curl's
     exit status and output, and cross-check the exact HTTP status with a
     direct request.
  4. NEGATIVE CONTROL: the same extraction against an emulator that no longer
     serves one attribute must fail -- the check is not vacuous.

Peer-uid enforcement is stubbed to "root" here (the build user is not uid 0);
tests/test_metadata.py covers it against /proc/net/tcp.
"""

import argparse
import http.client
import importlib.util
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import threading

BASE = "http://metadata.google.internal/computeMetadata/v1"
HOST_PORT = "metadata.google.internal:80"
HEADER = "Metadata-Flavor: Google"
SELF_IP = "192.0.2.10"
PUT_VALUE = "route-coverage-probe"

# Attributes gce/ reads that the PVE boot config never carries, each with the
# reason its consumer is correct to see a 404.
ABSENT_BY_DESIGN = {
    "cogworx-self-addrs": "floor.nix and supervise.sh fall back to network-interfaces/0/ip (README.md, Inbound)",
    "cogworx-resolver": "no resolver boots on PVE in v0; resolver-deadline needs an exact 404 to latch 'not a resolver boot'",
    "cogworx-resolver-deadline": "read only on a resolver boot",
}
# Attributes the emulator serves that no HTTP client reads, with where they go.
SERVED_NOT_READ_OVER_HTTP = {
    "cogworx-hostname": "read from DMI by cogworx-pve-hostname (--print-attr), before the network",
}
_VAR_DEFAULT = re.compile(r"\$\{COGWORX_MD_BASE:-([^}]*)\}")
_NIC = re.compile(r"\$\{_?nic%/\}")
_HELPER_DEF = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{\s*(.*?)\s*;?\s*\}\s*$")
_ASSIGN = re.compile(r"^\s*(?:export\s+)?(MD|GA|hdr|MDHDR)=(.*)$")
_FOR = re.compile(r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^;]+);\s*do\b")

fails = 0


def ok(msg):
    print("ok   - " + msg)


def bad(msg):
    global fails
    fails += 1
    print("FAIL - " + msg, file=sys.stderr)


def logical_lines(text):
    """(line number, line) with backslash continuations joined, comments dropped."""
    out, buf, start = [], "", None
    for n, line in enumerate(text.split("\n"), 1):
        if start is None:
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        if not buf.lstrip().startswith("#"):
            out.append((start, buf))
        buf, start = "", None
    return out


def unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


class Script:
    def __init__(self, path):
        self.path = path
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            self.text = f.read()
        self.lines = logical_lines(self.text)
        self.vars = {"hdr": HEADER, "MDHDR": HEADER}
        self.helpers = {}
        self.loops = {}
        for _, line in self.lines:
            m = _ASSIGN.match(line)
            if m and m.group(1) in ("MD", "GA"):
                self.vars[m.group(1)] = self.subst(unquote(m.group(2)), {})
            m = _HELPER_DEF.match(line)
            if m and "curl " in m.group(2):
                self.helpers[m.group(1)] = m.group(2)
            for m in _FOR.finditer(line):
                self.loops[m.group(1)] = m.group(2).split()

    def subst(self, s, extra):
        s = _VAR_DEFAULT.sub(lambda m: m.group(1), s)
        s = _NIC.sub("0", s)
        names = dict(self.vars)
        names.update(extra)
        for name in sorted(names, key=len, reverse=True):
            s = s.replace("${%s}" % name, names[name]).replace("$" + name, names[name])
        return s

    def curl_argvs(self, cmd, where):
        """[(argv, method, path)] for one curl command string; may expand a loop."""
        cmd = cmd[cmd.index("curl"):]
        cmd = re.sub(r"\s[12]?>\s*/dev/null", " ", cmd)
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=";|&()")
        lex.whitespace_split = True
        tokens = []
        for t in lex:
            if t and all(c in ";|&()" for c in t):
                break
            tokens.append(t)
        loop_vars = [v for v in self.loops if any(("$" + v) in t for t in tokens)]
        expansions = [{}]
        for v in loop_vars:
            expansions = [dict(e, **{v: val}) for e in expansions for val in self.loops[v]]
        out = []
        for extra in expansions:
            argv = [self.subst(t, extra) for t in tokens]
            urls = [a for a in argv if a.startswith("http://")]
            if any("$" in a for a in argv) or len(urls) != 1:
                bad("%s: unresolvable metadata access: %s" % (where, cmd.strip()))
                continue
            url = urls[0]
            if not url.startswith(BASE + "/"):
                bad("%s: curl to something other than the metadata server: %s" % (where, url))
                continue
            method = "GET"
            if "-X" in argv:
                method = argv[argv.index("-X") + 1]
            out.append((argv, method, url[len(BASE) + 1:]))
        return out

    def accesses(self):
        """Every (argv, method, path, where) this script makes."""
        found = []
        for n, line in self.lines:
            where = "%s:%d" % (os.path.basename(self.path), n)
            if _HELPER_DEF.match(line) or _ASSIGN.match(line):
                continue
            hits = []
            for name, body in self.helpers.items():
                for m in re.finditer(r"(?<![\w-])%s\s+(\"[^\"]*\"|'[^']*'|[^\s;|&)]+)" % re.escape(name), line):
                    arg = unquote(m.group(1))
                    expanded = body.replace('"$1"', '"%s"' % arg).replace("$1", arg).replace('"$2"', '"%s"' % PUT_VALUE)
                    hits += self.curl_argvs(expanded, "%s (%s %s)" % (where, name, arg))
            if re.search(r"(?<![\w-])curl\s", line):
                hits += self.curl_argvs(line, where)
            mentions = "computeMetadata" in line or "$MD/" in line or "$GA/" in line or any(
                re.search(r"(?<![\w-])%s\b" % re.escape(h), line) for h in self.helpers)
            if mentions and not hits:
                bad("%s: mentions the metadata server but no access could be resolved: %s" % (where, line.strip()))
            found += [(a, m, p, where) for a, m, p in hits]
        return found


def load_emulator(path):
    spec = importlib.util.spec_from_file_location("cogworx_pve_metadata", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.LOG.disabled = True
    return mod


def fixture(md, vectors_path):
    """(instance id, {attribute: value}) covering every code the blob can carry."""
    with open(vectors_path) as f:
        vectors = json.load(f)
    case = next(c for c in vectors["cases"] if c["name"] == "typical")
    bootconfig = dict(case["bootconfig"], maintenance=True)
    attrs = md.decode_blob(md.encode_blob(bootconfig))
    missing = set(md.ATTRIBUTES.values()) - set(attrs)
    if missing:
        raise SystemExit("fixture does not carry %s" % ", ".join(sorted(missing)))
    return case["owner_uuid"], attrs


class Emulator:
    def __init__(self, md, instance_id, attrs):
        self.tmp = tempfile.TemporaryDirectory()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(16)
        self.port = sock.getsockname()[1]
        app = md.Metadata(
            instance_id=instance_id,
            attrs=attrs,
            store=md.GuestAttributeStore(self.tmp.name, "route-coverage-boot"),
            addr_fn=lambda iface: SELF_IP,
            addr_wait=0.5,
            peer_uid=lambda server, client: 0,
        )
        self.server = md.MetadataServer(sock, app)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def status(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        headers = {"Metadata-Flavor": "Google"}
        if body is not None:
            headers["Content-Length"] = str(len(body))
        c.request(method, "/computeMetadata/v1/" + path, body=body, headers=headers)
        r = c.getresponse()
        data = r.read()
        flavor = r.getheader("Metadata-Flavor")
        c.close()
        return r.status, data.decode("utf-8", "replace"), flavor

    def curl(self, argv):
        cmd = [argv[0], "--connect-to", "%s:127.0.0.1:%d" % (HOST_PORT, self.port)] + argv[1:]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout


def expectation(path, instance_id, attrs):
    """(kind, expected status, expected body or None), or None if unserved."""
    if path == "instance/id":
        return "id", 200, instance_id
    if path == "instance/network-interfaces/":
        return "nics", 200, "0/\n"
    if path == "instance/network-interfaces/0/ip":
        return "ip", 200, SELF_IP
    m = re.fullmatch(r"instance/attributes/([A-Za-z0-9._-]{1,128})", path)
    if m:
        key = m.group(1)
        if key in attrs:
            return "attr", 200, attrs[key]
        if key in ABSENT_BY_DESIGN:
            return "absent", 404, None
        return None
    if re.fullmatch(r"instance/guest-attributes/[A-Za-z0-9_-]{1,64}/[A-Za-z0-9_-]{1,64}", path):
        return "guest", None, None
    return None


def check(md, vectors, scripts, report=True, drop=()):
    """Run the coverage; returns the failure count it added. `drop` names
    attributes the emulator under test does NOT serve (the negative control)."""
    before = fails
    instance_id, attrs = fixture(md, vectors)
    attrs = {k: v for k, v in attrs.items() if k not in drop}
    accesses = []
    for path in scripts:
        s = Script(path)
        found = s.accesses()
        if report:
            ok("%s: %d metadata access(es) extracted" % (os.path.basename(path), len(found)))
        accesses += found
    emu = Emulator(md, instance_id, attrs)
    try:
        read_attrs = set()
        guest = {}
        for argv, method, path, where in accesses:
            exp = expectation(path, instance_id, attrs)
            if exp is None:
                bad("%s: %s %s is not served by the PVE emulator" % (where, method, path))
                continue
            kind, want_status, want_body = exp
            if kind == "guest":
                guest.setdefault(path, []).append((argv, method, where))
                continue
            if kind in ("attr", "absent"):
                read_attrs.add(path.rsplit("/", 1)[1])
            status, body, flavor = emu.status("GET", path)
            if status != want_status or flavor != "Google":
                bad("%s: GET %s answered %s (Metadata-Flavor %r), expected %d" % (where, path, status, flavor, want_status))
                continue
            if want_body is not None and body != want_body:
                bad("%s: GET %s served %r, expected %r" % (where, path, body, want_body))
                continue
            rc, out = emu.curl(argv)
            fail_flag = any(a.startswith("-") and not a.startswith("--") and "f" in a for a in argv[1:])
            if want_status == 200:
                quiet = "-o" in argv
                if rc != 0 or (not quiet and out != want_body):
                    bad("%s: replay of %s exited %d with %r" % (where, " ".join(argv), rc, out))
                    continue
            elif fail_flag:
                if rc != 22:
                    bad("%s: replay of %s exited %d, expected 22 (HTTP 404 under -f)" % (where, " ".join(argv), rc))
                    continue
            elif "%{http_code}" in " ".join(argv):
                if rc != 0 or out != "404":
                    bad("%s: replay of %s printed %r (rc %d), expected the status 404" % (where, " ".join(argv), out, rc))
                    continue
            if report:
                ok("%s: %s %s -> %d, replayed with the script's own flags" % (where, method, path, want_status))
        # Guest attributes: each key's accesses in PUT, GET, DELETE order, so
        # every replay meets the state its method expects.
        order = {"PUT": 0, "GET": 1, "DELETE": 2}
        for path, uses in sorted(guest.items()):
            for argv, method, where in sorted(uses, key=lambda u: order.get(u[1], 9)):
                if method not in order:
                    bad("%s: %s %s is not a guest-attribute method the emulator takes" % (where, method, path))
                    continue
                rc, _ = emu.curl(argv)
                status, body, _ = emu.status("GET", path)
                if method == "PUT":
                    good = rc == 0 and status == 200 and body == PUT_VALUE
                elif method == "DELETE":
                    good = rc == 0 and status == 404
                else:
                    good = rc == 0 or (status == 404 and rc == 22)
                if good:
                    if report:
                        ok("%s: %s %s replayed (now %d)" % (where, method, path, status))
                else:
                    bad("%s: %s %s replay exited %d; the key now answers %d %r" % (where, method, path, rc, status, body))
        unread = set(attrs) - read_attrs - set(SERVED_NOT_READ_OVER_HTTP)
        if unread:
            bad("the emulator serves attribute(s) no client reads over HTTP and none is documented: %s" % ", ".join(sorted(unread)))
        elif report:
            ok("every served attribute is read by a client, or documented as read another way")
        if report and len(accesses) < 20:
            bad("only %d accesses extracted; the extractor is probably not seeing the scripts" % len(accesses))
    finally:
        emu.close()
    return fails - before


def main(argv):
    global fails
    p = argparse.ArgumentParser()
    p.add_argument("--emulator", required=True)
    p.add_argument("--vectors", required=True)
    p.add_argument("scripts", nargs="+")
    a = p.parse_args(argv)
    md = load_emulator(a.emulator)
    check(md, a.vectors, a.scripts)

    # NEGATIVE CONTROL: an emulator that no longer serves cogworx-instance.
    saved = fails
    devnull = open(os.devnull, "w")
    real_stderr, sys.stderr = sys.stderr, devnull
    try:
        caught = check(md, a.vectors, a.scripts, report=False, drop=("cogworx-instance",))
    finally:
        sys.stderr = real_stderr
        devnull.close()
    fails = saved
    if caught:
        ok("NEGATIVE CONTROL: an emulator missing cogworx-instance is caught (%d failure(s))" % caught)
    else:
        bad("NEGATIVE CONTROL: an emulator missing cogworx-instance passed; the check is vacuous")

    if fails:
        print("test_route_coverage: %d failure(s)" % fails, file=sys.stderr)
        return 1
    print("test_route_coverage: all passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
