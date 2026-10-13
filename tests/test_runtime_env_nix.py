#!/usr/bin/env python3
"""Real Nix acceptance for protocol v2; uses an explicit helper and a materialized tiny fixture.

No shared store paths are deleted, so this never exercises an actual import:
store-loss recovery belongs to the runtime-boot-restore VM test and the stage
matrix. It does cover the restore fast path and the boot-restore record.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("helper", help="packaged cogbox-env executable")
p.add_argument("fixture", type=Path)
p.add_argument("--evidence", type=Path)
a = p.parse_args()
measurements = []


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


with tempfile.TemporaryDirectory(prefix="cogbox-env-acceptance-") as temporary:
    root = Path(temporary)
    work = root / "work"
    state = work / ".cogbox" / "runtime"

    def run(argv, request=None):
        return subprocess.run([a.helper, *argv, "--state-dir", str(state), "--timeout", "120"],
                              input=request, capture_output=True, text=True, timeout=125)

    def rpc(action, expected_ok=True, version=2, **fields):
        started = time.monotonic()
        proc = run(["rpc"], json.dumps({"version": version, "action": action, **fields}))
        result = json.loads(proc.stdout)
        assert result["version"] == 2 and result["ok"] == expected_ok and (proc.returncode == 0) == expected_ok, (result, proc.stderr)
        # Any Nix deprecation warning would print on every call (as --no-registries did).
        assert not [line for line in proc.stderr.splitlines() if "is deprecated" in line], proc.stderr
        measurements.append({"action": action, "seconds": round(time.monotonic() - started, 4),
                             "ok": result["ok"], "changed": result["changed"], "generation": result["generation"],
                             "code": result["error"]["code"] if result["error"] else None})
        return result

    def prepare(attr, expected_ok=True):
        return rpc("prepare", expected_ok, flake="path:" + str(a.fixture.resolve()), attribute="packages.x86_64-linux." + attr)

    caps = rpc("capabilities", version=1)["capabilities"]
    assert caps["protocol_versions"] == [2] and caps["state_formats"] == [1] and caps["helper_version"] == "0.2.0", caps
    # Before brain-materialize: nothing exists, and nothing may be created.
    assert rpc("status", False)["error"]["code"] == "not_ready"
    work.mkdir()
    assert rpc("status", False)["error"]["code"] == "not_ready" and list(work.iterdir()) == []
    (work / ".cogbox").mkdir()
    empty = rpc("status")["status"]
    assert empty["selection"] is None and empty["generations"] == [] and not state.exists(), empty
    assert rpc("prepare", False, flake="git+https://user:secret@git.example.com/acme/tools",
               attribute="default")["error"]["code"] == "invalid_request"
    assert rpc("apply", False, version=1, generation="0" * 64, expected_selection="none")["error"]["code"] == "unsupported_version"

    first = prepare("a")
    assert first["status"]["active_generation"] is None and first["changed"]
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
          probe) if command -v runtime-probe >/dev/null; then runtime-probe; else echo none; fi ;;
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
        reserved = prepare("reserved", False)
        assert reserved["error"] == {"code": "prepare_failed", "message": "bundle must not provide cogbox-env"}, reserved
        assert reserved["status"]["selection"] == tc and len(reserved["status"]["generations"]) == 2
        # A __structuredAttrs bundle, the pkgs.buildEnv shape: its environment has no
        # `system` binding (so the binding query fails), and prepare still reads it.
        structured = prepare("structured")
        gs = structured["generation"]
        listed = next(g for g in structured["status"]["generations"] if g["id"] == gs)
        assert structured["changed"] and listed["system"] == "x86_64-linux" and listed["provenance"]["kind"] == "flake", structured
        shown = json.loads(subprocess.run(["nix", "derivation", "show", listed["derivation"]], capture_output=True, check=True, text=True).stdout)
        entry = next(iter(shown.get("derivations", shown).values()))
        assert "structuredAttrs" in entry and "system" not in entry["env"], entry
        binding = subprocess.run(["nix-store", "--query", "--binding", "system", listed["derivation"]], capture_output=True, text=True)
        assert binding.returncode != 0 and "no environment binding" in binding.stderr, binding
        assert rpc("prune", generation=gs)["changed"]

        def nix(*argv):
            proc = subprocess.run(["nix", *argv], capture_output=True, text=True, timeout=120)
            assert proc.returncode == 0, (argv, proc.stderr)
            return proc.stdout

        def registry_for(name, path):
            registry = root / name
            registry.write_text(json.dumps({"flakes": [{"exact": True, "from": {"id": "nixpkgs", "type": "indirect"},
                                                        "to": {"path": path, "type": "path"}}], "version": 2}))
            return str(registry)

        def nixpkgs_node(directory):
            return json.loads((directory / "flake.lock").read_text())["nodes"]["nixpkgs"]

        def prepare_indirect(directory):
            recipe = rpc("prepare", flake="path:" + str(directory.resolve()), attribute="packages.x86_64-linux.default")
            listed = next(g for g in recipe["status"]["generations"] if g["id"] == recipe["generation"])
            assert recipe["changed"] and listed["system"] == "x86_64-linux" and listed["provenance"]["kind"] == "flake", recipe
            assert rpc("prune", generation=recipe["generation"])["changed"]

        # The skill's lock recipe. Nix resolves an indirect input such as
        # `nixpkgs` through the global registry only; --flake-registry makes a
        # file that maps it to a store path (the image's nixpkgs on a guest, the
        # archived tools flake here) that registry, so the input locks offline
        # to exactly that path with `original` still indirect, and prepare
        # (--no-use-registries) accepts the lock. Without the flag the lock
        # downloads the default global registry and lands on a nixpkgs tarball.
        stand_in = json.loads(nix("flake", "archive", "--json", "path:" + str((a.fixture / "tools").resolve())))["path"]
        registry = registry_for("registry.json", stand_in)
        indirect = root / "indirect"
        shutil.copytree(a.fixture / "indirect", indirect)
        nix("flake", "lock", "--flake-registry", registry, "path:" + str(indirect.resolve()))
        node = nixpkgs_node(indirect)
        assert node["locked"]["type"] == "path" and node["locked"]["path"] == stand_in, node
        assert node["original"] == {"id": "nixpkgs", "type": "indirect"}, node
        prepare_indirect(indirect)
        # The skill's stale-lock recipe. A flake.lock written against another
        # nixpkgs (another sandbox's image, or this image before an upgrade):
        # `nix flake lock` keeps that entry whatever registry it is given, and
        # `nix flake update nixpkgs --flake-registry FILE --flake REF`
        # re-resolves it, offline, to the path FILE maps. Without the flag the
        # update needs the network and locks the global nixpkgs-unstable.
        other_source = root / "other-nixpkgs"
        other_source.mkdir()
        (other_source / "flake.nix").write_text((a.fixture / "tools" / "flake.nix").read_text() + "# another image's nixpkgs\n")
        other = json.loads(nix("flake", "archive", "--json", "path:" + str(other_source.resolve())))["path"]
        assert other != stand_in, other
        elsewhere = root / "elsewhere"
        shutil.copytree(a.fixture / "indirect", elsewhere)
        nix("flake", "lock", "--flake-registry", registry_for("other-registry.json", other), "path:" + str(elsewhere.resolve()))
        shutil.copyfile(elsewhere / "flake.lock", indirect / "flake.lock")
        nix("flake", "lock", "--flake-registry", registry, "path:" + str(indirect.resolve()))
        assert nixpkgs_node(indirect)["locked"]["path"] == other, nixpkgs_node(indirect)
        nix("flake", "update", "nixpkgs", "--flake-registry", registry, "--flake", "path:" + str(indirect.resolve()))
        assert nixpkgs_node(indirect) == node, (nixpkgs_node(indirect), node)
        prepare_indirect(indirect)
        warm = prepare("a")
        assert warm["generation"] == ga and not warm["changed"]
        # A damaged or missing retained archive is repaired from the local closure.
        archive = state / "generations" / ga / "closure.nar"
        manifest = json.loads((state / "generations" / ga / "manifest.json").read_text())
        good = sha256(archive)
        with archive.open("r+b") as stream:
            byte = stream.read(1)
            stream.seek(0)
            stream.write(bytes([byte[0] ^ 1]))
        repaired = prepare("a")
        assert repaired["generation"] == ga and repaired["changed"] and sha256(archive) == good, repaired
        archive.unlink()
        repaired = prepare("a")
        assert repaired["changed"] and sha256(archive) == good and repaired["status"]["selection"] == tc
        assert json.loads((state / "generations" / ga / "manifest.json").read_text())["identity"] == manifest["identity"]
        # Present closure: restore is the fast path, no import and no change.
        restored = rpc("restore")
        assert not restored["changed"] and restored["status"]["active_generation"] == ga
        assert ask("probe") == "v1"
        boot = run(["restore", "--boot"])
        assert boot.returncode == 0, boot.stderr
        assert boot.stderr.startswith("cogbox-runtime-restore: outcome=active code=- generation=" + ga + " duration_ms="), boot.stderr
        record = rpc("status")["status"]["boot_restore"]
        assert record["outcome"] == "active" and record["generation"] == ga and record["code"] is None, record
        cleared = rpc("clear", expected_selection=tc)
        assert cleared["changed"] and cleared["status"]["selection"] is None and ask("probe") == "none"
        assert sorted(g["id"] for g in cleared["status"]["generations"]) == sorted([ga, gb])
        again = rpc("apply", generation=ga, expected_selection="none")
        assert again["status"]["previous_generation"] is None and ask("probe") == "v1"
        pruned = rpc("prune", generation=gb)
        assert pruned["changed"] and [g["id"] for g in pruned["status"]["generations"]] == [ga]
        assert not (state / "roots" / gb).exists()
        refused = rpc("prune", False, generation=ga)
        assert refused["error"]["code"] == "invalid_request"
        final = rpc("prune")["status"]
        limits = final["limits"]
        assert limits["max_generations"] == 4 and limits["max_path_nar_bytes"] == 1 << 30, limits
        leftovers = sorted(str(p.relative_to(state)) for p in state.rglob(".*"))
        assert leftovers == [], leftovers
        report = {"tests": "capabilities/not_ready/no-create/userinfo/v1-reject/prepare/apply/live replacement/removal/"
                           "rollback/noop/ABA/collision/reserved/structured attrs/registry lock recipe/stale lock update recipe/"
                           "reuse/archive repair/"
                           "restore fast path/boot record/clear/prune",
                  "measurements": measurements,
                  "archive_bytes": limits["archive_bytes_total"], "limits": limits,
                  "shell_pid": shell.pid, "shell_starttime": starttime,
                  "store_loss_tested": False,
                  "store_loss_note": "No shared host store deletion; import paths are covered by the VM test and stage matrix."}
        print(json.dumps(report, indent=2))
        if a.evidence:
            a.evidence.write_text(json.dumps(report, indent=2) + "\n")
    finally:
        shell.stdin.close()
        shell.wait(timeout=5)
