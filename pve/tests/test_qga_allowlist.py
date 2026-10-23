#!/usr/bin/env python3
"""The qemu-guest-agent RPC allow-list, proven against the REAL agent binary.

    test_qga_allowlist.py 'EXECSTART'

EXECSTART is the realized qemu-guest-agent ExecStart line (pve/checks.nix
passes it). The agent is started with exactly that argv, except that it
listens on a unix socket in a temp dir instead of the virtio port and keeps
its state dir and pidfile there too; then guest-info is asked which RPCs are
ENABLED, and two refused RPCs are called.

A grep of the ExecStart line proves the flag is spelled; this proves the agent
version in the image parses it the way the allow-list means: exactly the listed
RPCs enabled, everything else -- guest-exec and guest-file-write in particular
-- refused as disabled. Stdlib only.
"""

import json
import os
import shlex
import socket
import subprocess
import sys
import tempfile
import time

# README.md, "VM shape the image expects" (Agent). A change here is a change
# to the cluster-facing agent surface.
EXPECTED = {
    "guest-sync", "guest-sync-delimited", "guest-ping", "guest-info",
    "guest-network-get-interfaces", "guest-file-open", "guest-file-read",
    "guest-file-close", "guest-shutdown", "guest-get-osinfo",
    "guest-get-host-name", "guest-get-time", "guest-fsfreeze-status",
}
MUST_REFUSE = ("guest-exec", "guest-file-write", "guest-exec-status",
               "guest-set-user-password", "guest-ssh-add-authorized-keys")

fails = 0


def ok(msg):
    print("ok   - " + msg)


def bad(msg):
    global fails
    fails += 1
    print("FAIL - " + msg, file=sys.stderr)


def rpc(sock, req):
    sock.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("agent closed the connection")
        buf += chunk
    return json.loads(buf.split(b"\n", 1)[0])


def main(argv):
    if len(argv) != 1:
        print("usage: test_qga_allowlist.py 'EXECSTART'", file=sys.stderr)
        return 64
    args = shlex.split(argv[0])
    allow = [a for a in args if a.startswith("--allow-rpcs=")]
    if len(allow) != 1:
        bad("ExecStart carries %d --allow-rpcs= flags, expected exactly 1: %s" % (len(allow), argv[0]))
        return 1
    listed = set(allow[0].split("=", 1)[1].split(","))
    if listed == EXPECTED:
        ok("the ExecStart allow-list is exactly the spec's %d RPCs" % len(EXPECTED))
    else:
        bad("the ExecStart allow-list differs from the spec: extra %s, missing %s"
            % (sorted(listed - EXPECTED), sorted(EXPECTED - listed)))
    if any(a.startswith(("--block-rpcs", "-b")) for a in args[1:]):
        bad("ExecStart also carries a block-list; the allow-list must be the only filter")

    with tempfile.TemporaryDirectory() as tmp:
        sock_path = os.path.join(tmp, "qga.sock")
        state = os.path.join(tmp, "state")
        os.mkdir(state)
        run = []
        skip = False
        for a in args:
            if skip:
                skip = False
                continue
            if a == "--statedir":
                skip = True
                continue
            run.append(a)
        run += ["--statedir", state, "-m", "unix-listen", "-p", sock_path, "-f", os.path.join(tmp, "pid")]
        proc = subprocess.Popen(run, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                if os.path.exists(sock_path):
                    break
                if proc.poll() is not None:
                    break
                time.sleep(0.05)
            if not os.path.exists(sock_path):
                out = proc.stdout.read().decode() if proc.poll() is not None else ""
                bad("qemu-ga did not come up with the realized flags: %s" % out)
                return 1
            s = socket.socket(socket.AF_UNIX)
            s.connect(sock_path)
            s.settimeout(10)
            info = rpc(s, {"execute": "guest-info"})
            enabled = {c["name"] for c in info["return"]["supported_commands"] if c["enabled"]}
            if enabled == EXPECTED:
                ok("the running agent enables exactly the allow-listed RPCs (%s)" % info["return"]["version"])
            else:
                bad("the running agent's enabled set differs: extra %s, missing %s"
                    % (sorted(enabled - EXPECTED), sorted(EXPECTED - enabled)))
            for name in MUST_REFUSE:
                r = rpc(s, {"execute": name, "arguments": {}})
                err = r.get("error", {})
                if err.get("class") == "CommandNotFound" and "disabled" in err.get("desc", ""):
                    ok("%s is refused as disabled" % name)
                else:
                    bad("%s was not refused as disabled: %s" % (name, r))
            r = rpc(s, {"execute": "guest-ping"})
            if r == {"return": {}}:
                ok("an allowed RPC (guest-ping) still answers")
            else:
                bad("guest-ping did not answer: %s" % r)
            s.close()
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    if fails:
        print("test_qga_allowlist: %d failure(s)" % fails, file=sys.stderr)
        return 1
    print("test_qga_allowlist: all passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
