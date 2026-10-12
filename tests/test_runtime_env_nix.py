#!/usr/bin/env python3
"""Real Nix acceptance; uses an explicit helper and a materialized tiny fixture.

No shared store paths are deleted. Actual store loss is a disposable guest test.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("helper", help="packaged cogbox-env executable")
p.add_argument("fixture", type=Path)
p.add_argument("--evidence", type=Path)
a = p.parse_args()
measurements = []
with tempfile.TemporaryDirectory(prefix="cogbox-env-acceptance-") as temporary:
    root = Path(temporary)
    state = root / "state"
    def rpc(action, expected_ok=True, **fields):
        req = {"version": 1, "action": action, **fields}
        started = time.monotonic()
        proc = subprocess.run([a.helper, "rpc", "--state-dir", str(state), "--timeout", "120"],
                              input=json.dumps(req), capture_output=True, text=True, timeout=125)
        result = json.loads(proc.stdout)
        assert result["ok"] == expected_ok and (proc.returncode == 0) == expected_ok, (result, proc.stderr)
        measurements.append({"action": action, "seconds": round(time.monotonic() - started, 4),
                             "ok": result["ok"], "changed": result["changed"], "generation": result["generation"]})
        return result
    def prepare(attr, expected_ok=True):
        return rpc("prepare", expected_ok, flake="path:" + str(a.fixture.resolve()), attribute="packages.x86_64-linux." + attr)

    first = prepare("a")
    assert first["status"]["active_generation"] is None
    ga = first["generation"]
    selected = rpc("apply", generation=ga, expected_selection="none")
    ta = selected["status"]["selection"]
    env = dict(os.environ, PATH=str(state / "current/bin") + ":" + os.environ["PATH"])
    heartbeat = root / "heartbeat"
    shell = subprocess.Popen(["bash", "--noprofile", "--norc", "-c", '''
      while true; do printf '%s\\n' "$EPOCHREALTIME" >> "$1"; sleep .05; done &
      beat=$!
      trap 'kill "$beat" 2>/dev/null || true; wait "$beat" 2>/dev/null || true' EXIT
      echo ready
      while read -r request; do
        hash -r
        case "$request" in
          probe) runtime-probe ;;
          only) if command -v runtime-a-only >/dev/null; then echo present; else echo absent; fi ;;
        esac
      done
    ''', "test-shell", str(heartbeat)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env)
    try:
        assert shell.stdout.readline().strip() == "ready"
        starttime = Path(f"/proc/{shell.pid}/stat").read_text().split()[21]
        def ask(question):
            shell.stdin.write(question + "\n")
            shell.stdin.flush()
            return shell.stdout.readline().strip()
        assert ask("probe") == "v1" and ask("only") == "present"
        before = heartbeat.stat().st_size
        second = prepare("b")
        gb = second["generation"]
        switched = rpc("apply", generation=gb, expected_selection=ta)
        tb = switched["status"]["selection"]
        assert ask("probe") == "v2" and ask("only") == "absent"
        assert shell.poll() is None and Path(f"/proc/{shell.pid}/stat").read_text().split()[21] == starttime
        assert heartbeat.stat().st_size > before
        noop = rpc("apply", generation=gb, expected_selection=tb)
        assert not noop["changed"] and noop["status"]["selection"] == tb and noop["status"]["previous_generation"] == ga
        rolled = rpc("rollback", expected_selection=tb)
        tc = rolled["status"]["selection"]
        assert tc != ta and ask("probe") == "v1" and ask("only") == "present"
        stale = rpc("apply", False, generation=gb, expected_selection=ta)
        assert stale["error"]["code"] == "stale_selection" and stale["status"]["selection"] == tc
        failed = prepare("collision", False)
        assert failed["error"]["code"] == "prepare_failed" and failed["status"]["selection"] == tc
        warm = prepare("a")
        assert warm["generation"] == ga and not warm["changed"]
        # Checksum failure is real; it must not import or change the pointer.
        archive = state / "generations" / ga / "closure.nar"
        with archive.open("r+b") as stream:
            byte = stream.read(1)
            stream.seek(0)
            stream.write(bytes([byte[0] ^ 1]))
        repeated = prepare("a", False)
        assert repeated["error"]["code"] == "invalid_archive" and repeated["status"]["selection"] == tc
        corrupt = rpc("restore", False, generation=ga)
        assert corrupt["error"]["code"] == "invalid_archive" and corrupt["status"]["selection"] == tc
        with archive.open("r+b") as stream:
            stream.write(byte)
        hidden = archive.with_suffix(".saved")
        archive.rename(hidden)
        missing = prepare("a", False)
        assert missing["error"]["code"] == "invalid_archive" and missing["status"]["selection"] == tc
        hidden.rename(archive)
        # This verifies/re-roots an existing closure. It does NOT prove recovery
        # from actual store loss; the stage acceptance separately does that.
        restored = rpc("restore")
        assert restored["status"]["output"] == selected["status"]["output"]
        assert ask("probe") == "v1"
        report = {"tests": "prepare/apply/live replacement/removal/rollback/noop/ABA/collision/reuse/checksum/restore-existing",
                  "measurements": measurements, "archive_bytes": sum(g["archive_bytes"] for g in restored["status"]["generations"]),
                  "shell_pid": shell.pid, "shell_starttime": starttime,
                  "store_loss_tested": False, "store_loss_note": "No shared host store deletion; disposable guest acceptance required."}
        print(json.dumps(report, indent=2))
        if a.evidence:
            a.evidence.write_text(json.dumps(report, indent=2) + "\n")
    finally:
        shell.stdin.close()
        shell.wait(timeout=5)
