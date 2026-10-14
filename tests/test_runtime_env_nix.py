#!/usr/bin/env python3
"""Real Nix acceptance for protocol v2; uses an explicit helper and a materialized tiny fixture.

No shared store paths are deleted, so this never exercises an actual import:
store-loss recovery belongs to the runtime-boot-restore VM test and the stage
matrix. It does cover the restore fast path and the boot-restore record.
"""
import argparse
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("helper", help="packaged cogbox-env executable")
p.add_argument("fixture", type=Path)
p.add_argument("--evidence", type=Path)
a = p.parse_args()
measurements = []
last = {}
LOCK_FLAGS = ("--no-update-lock-file", "--no-write-lock-file", "--no-use-registries")
FULL_ARCHIVE = ("flake", "archive", "--json", *LOCK_FLAGS)
# Records the locked nixpkgs attributes its evaluation sees; nixpkgs is the stand-in.
PROBE = """{
  inputs.nixpkgs.url = "nixpkgs";
  outputs = { self, nixpkgs }: {
    packages.${nixpkgs.system}.default = builtins.derivation {
      name = "runtime-bundle-probe";
      inherit (nixpkgs) system;
      builder = "${nixpkgs.bash}/bin/bash";
      locked = builtins.toJSON {
        inherit (nixpkgs) lastModified narHash;
        rev = nixpkgs.rev or null;
        revCount = nixpkgs.revCount or null;
      };
      args = [ "-euc" ''
        ${nixpkgs.coreutils}/bin/mkdir -p "$out/bin"
        printf '%s' "$locked" > "$out/locked.json"
      '' ];
    };
  };
}
"""
# Records whether its evaluation sees nixpkgs as a flake or as a plain source
# tree. FLAKE is empty or `flake = false;`; either way it builds with the
# stand-in's tools, read through the stand-in's own flake.nix.
TOGGLE = """{
  inputs.nixpkgs = { url = "nixpkgs"; FLAKE };
  outputs = { self, nixpkgs }: let
    tools = (import "${nixpkgs}/flake.nix").outputs { self = tools; };
  in {
    packages.${tools.system}.default = builtins.derivation {
      name = "runtime-bundle-toggle";
      inherit (tools) system;
      builder = "${tools.bash}/bin/bash";
      kind = if nixpkgs ? outputs then "flake" else "source";
      args = [ "-euc" ''
        ${tools.coreutils}/bin/mkdir -p "$out/bin"
        printf '%s' "$kind" > "$out/kind"
      '' ];
    };
  };
}
"""
SLOW = "cogbox-env: prepare: no store-path override for nixpkgs, so Nix hashes the locked source again"
libc = ctypes.CDLL(None, use_errno=True)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


@contextlib.contextmanager
def opened(directory):
    """Collect every inotify open or read (IN_OPEN, IN_ACCESS) of directory and its entries.

    The list fills when the block ends.
    """
    fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    assert fd >= 0, os.strerror(ctypes.get_errno())
    events = []
    try:
        assert libc.inotify_add_watch(fd, os.fsencode(directory), 0x20 | 0x01) >= 0, os.strerror(ctypes.get_errno())
        yield events
        while True:
            try:
                data = os.read(fd, 65536)
            except BlockingIOError:
                break
            offset = 0
            while offset < len(data):
                _, mask, _, length = struct.unpack_from("iIII", data, offset)
                events.append((hex(mask), data[offset + 16:offset + 16 + length].rstrip(b"\0").decode()))
                offset += 16 + length
    finally:
        os.close(fd)


with tempfile.TemporaryDirectory(prefix="cogbox-env-acceptance-") as temporary:
    root = Path(temporary)
    work = root / "work"
    state = work / ".cogbox" / "runtime"

    def fresh_cache():
        return tempfile.mkdtemp(prefix="cache-", dir=root)

    def run(argv, request=None, barf=True):
        # With _NIX_TEST_BARF_ON_UNCACHEABLE, Nix 2.34 throws where it would copy
        # an input it cannot cache into the store again, the re-read prepare must
        # never do; the test's own Nix commands run without it, as does a
        # prepare that must keep Nix's own evaluation of a stale lock entry
        # (barf=False), which re-reads. A fresh cache directory per run: an
        # evaluation an earlier run cached would skip the evaluation, and with
        # it any re-read in `nix build`.
        env = dict(os.environ, XDG_CACHE_HOME=fresh_cache())
        if barf:
            env["_NIX_TEST_BARF_ON_UNCACHEABLE"] = "1"
        return subprocess.run([a.helper, *argv, "--state-dir", str(state), "--timeout", "120"],
                              input=request, capture_output=True, text=True, timeout=125, env=env)

    def rpc(action, expected_ok=True, version=2, barf=True, **fields):
        started = time.monotonic()
        proc = run(["rpc"], json.dumps({"version": version, "action": action, **fields}), barf=barf)
        last["stderr"] = proc.stderr
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
            # A cold cache too, so that no evaluation is shared with a helper run.
            proc = subprocess.run(["nix", *argv], capture_output=True, text=True, timeout=120,
                                  env=dict(os.environ, XDG_CACHE_HOME=fresh_cache()))
            assert proc.returncode == 0, (argv, proc.stderr)
            return proc.stdout

        def registry_for(name, path):
            registry = root / name
            registry.write_text(json.dumps({"flakes": [{"exact": True, "from": {"id": "nixpkgs", "type": "indirect"},
                                                        "to": {"path": path, "type": "path"}}], "version": 2}))
            return str(registry)

        def nixpkgs_node(directory):
            return json.loads((directory / "flake.lock").read_text())["nodes"]["nixpkgs"]

        def prepare_locked(directory, override=True, rereads=False):
            """Prepare a bundle whose nixpkgs is locked to the stand-in; return its output.

            With override the lock is current, and the prepare must override
            nixpkgs: it must neither re-read the stand-in nor re-lock. Without,
            the prepare must keep Nix's own evaluation and say so; with rereads
            that evaluation hashes the stand-in again, as plain Nix does, so it
            runs without the barf hook and unwatched. Either way the identity
            must be the one the full (not dry-run) archive gives, and the
            derivation the one Nix itself evaluates for the recorded snapshot.
            The prepare's stderr stays in last["prepared"].
            """
            with opened(sentinel) as events:
                recipe = rpc("prepare", barf=not rereads, flake="path:" + str(directory.resolve()),
                             attribute="packages.x86_64-linux.default")
            last["prepared"] = last["stderr"]
            relocked = [line for line in last["stderr"].splitlines() if "lock file" in line or "Updated input" in line]
            if not rereads:
                assert events == [], ("prepare re-read a locked store-path input", len(events), events[:4])
            if override:
                # The override repeats the lock entry exactly, so Nix neither re-locks nor warns.
                assert not relocked and SLOW not in last["stderr"], last["stderr"]
            else:
                assert SLOW in last["stderr"].splitlines(), last["stderr"]
            listed = next(g for g in recipe["status"]["generations"] if g["id"] == recipe["generation"])
            assert recipe["changed"] and listed["system"] == "x86_64-linux" and listed["provenance"]["kind"] == "flake", recipe
            full = json.loads(nix(*FULL_ARCHIVE, "path:" + str(directory.resolve())))
            provenance = listed["provenance"]
            assert hashlib.sha256(canonical(full)).hexdigest() == provenance["inputs_digest"], (full, provenance)
            assert full["path"] == provenance["source"], (full, provenance)
            plain = nix("eval", "--raw", *LOCK_FLAGS, "path:" + provenance["source"] + "#packages.x86_64-linux.default.drvPath")
            assert listed["derivation"] == plain, (listed["derivation"], plain)
            assert rpc("prune", generation=recipe["generation"])["changed"]
            return listed["output"]

        # The skill's lock recipe. Nix resolves an indirect input such as
        # `nixpkgs` through the global registry only; --flake-registry makes a
        # file that maps it to a store path (the image's nixpkgs on a guest, the
        # archived tools flake here) that registry, so the input locks offline
        # to exactly that path with `original` still indirect, and prepare
        # (--no-use-registries) accepts the lock. Without the flag the lock
        # downloads the default global registry and lands on a nixpkgs tarball.
        # The stand-in is a content-addressed path named "source", like the
        # image's nixpkgs, and carries a directory no evaluation reads: any open
        # or read in it during a prepare means Nix hashed the whole input again.
        stand_in_source = root / "stand-in"
        shutil.copytree(a.fixture / "tools", stand_in_source)
        (stand_in_source / "sentinel").mkdir()
        for i in range(64):
            (stand_in_source / "sentinel" / ("file-%02d" % i)).write_text("never evaluated %d\n" % i)
        stand_in = json.loads(nix("flake", "archive", "--json", "path:" + str(stand_in_source.resolve())))["path"]
        sentinel = Path(stand_in) / "sentinel"
        registry = registry_for("registry.json", stand_in)
        indirect = root / "indirect"
        shutil.copytree(a.fixture / "indirect", indirect)
        nix("flake", "lock", "--flake-registry", registry, "path:" + str(indirect.resolve()))
        node = nixpkgs_node(indirect)
        assert node["locked"]["type"] == "path" and node["locked"]["path"] == stand_in, node
        assert node["original"] == {"id": "nixpkgs", "type": "indirect"}, node
        prepare_locked(indirect)
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
        prepare_locked(indirect)
        # A bundle that records what its evaluation sees of nixpkgs, so a lock
        # attribute that does not reach the evaluation changes its derivation.
        def probe(name, registry_file):
            directory = root / name
            directory.mkdir()
            (directory / "flake.nix").write_text(PROBE)
            nix("flake", "lock", "--flake-registry", registry_file, "path:" + str(directory.resolve()))
            return directory

        def seen(output):
            return json.loads((Path(output) / "locked.json").read_text())

        # A registry entry with rev, revCount and a non-zero lastModified: Nix
        # takes each back exactly from the percent-encoded override.
        rev = "0123456789abcdef0123456789abcdef01234567"
        full_entry = {"lastModified": 1791456040, "narHash": node["locked"]["narHash"], "path": stand_in,
                      "rev": rev, "revCount": 7, "type": "path"}
        registry_rc = root / "registry-rc.json"
        registry_rc.write_text(json.dumps({"flakes": [{"exact": True, "from": {"id": "nixpkgs", "type": "indirect"},
                                                       "to": {k: v for k, v in full_entry.items() if k != "narHash"}}], "version": 2}))
        carried = probe("probe-rev", str(registry_rc))
        assert nixpkgs_node(carried)["locked"] == full_entry, nixpkgs_node(carried)
        assert seen(prepare_locked(carried)) == {k: full_entry[k] for k in ("lastModified", "narHash", "rev", "revCount")}
        # flake.nix names nixpkgs by another URL that resolves to the same
        # narHash, and the lock was not renewed: Nix re-locks nixpkgs in memory
        # with that URL's lastModified and rev. prepare must build what Nix
        # evaluates, not the lock file's stale entry.
        edited = probe("probe-edited", registry)
        assert nixpkgs_node(edited)["locked"]["lastModified"] == 0, nixpkgs_node(edited)
        (edited / "flake.nix").write_text(PROBE.replace('"nixpkgs";', json.dumps("path:%s?lastModified=1700000000&rev=%s" % (stand_in, rev)) + ";"))
        assert seen(prepare_locked(edited, override=False)) == {"lastModified": 1700000000, "narHash": node["locked"]["narHash"],
                                                                "rev": rev, "revCount": None}
        assert [line for line in last["prepared"].splitlines() if "lock file" in line], last["prepared"]
        # flake.nix adds or drops `flake = false` on nixpkgs without a new lock.
        # Nix keeps the entry, whose reference did not change, with the lock's
        # own flag, where an override would take the flag from flake.nix: prepare
        # must evaluate nixpkgs as the same kind plain Nix does. A non-flake
        # entry that is current keeps its override.
        def toggle(name, locked_flag, flag):
            directory = root / name
            directory.mkdir()
            (directory / "flake.nix").write_text(TOGGLE.replace("FLAKE", locked_flag))
            nix("flake", "lock", "--flake-registry", registry, "path:" + str(directory.resolve()))
            expected = dict(node, flake=False) if locked_flag else node
            assert nixpkgs_node(directory) == expected, (nixpkgs_node(directory), expected)
            (directory / "flake.nix").write_text(TOGGLE.replace("FLAKE", flag))
            return directory

        for name, locked_flag, flag, kind in (("toggle-source", "flake = false;", "flake = false;", "source"),
                                              ("toggle-removed", "flake = false;", "", "source"),
                                              ("toggle-added", "", "flake = false;", "flake")):
            current = locked_flag == flag
            output = prepare_locked(toggle(name, locked_flag, flag), override=current, rereads=not current)
            assert (Path(output) / "kind").read_text() == kind, (name, (Path(output) / "kind").read_text())
        # A self-inconsistent lock: the path of another valid source with the
        # stand-in's narHash. Nix checks the narHash of the path an override
        # gives it, so the check fails, and prepare builds what plain Nix
        # builds: the source the narHash names, the one the archive records.
        mismatched = probe("probe-mismatched", registry)
        lock = json.loads((mismatched / "flake.lock").read_text())
        lock["nodes"]["nixpkgs"]["locked"]["path"] = other
        (mismatched / "flake.lock").write_text(json.dumps(lock))
        assert seen(prepare_locked(mismatched, override=False, rereads=True)) == {
            "lastModified": 0, "narHash": node["locked"]["narHash"], "rev": None, "revCount": None}
        assert "NAR hash mismatch" in last["prepared"], last["prepared"]
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
                           "no re-read of a locked store-path input/identity equals full archive/derivation equals plain Nix/"
                           "locked rev and revCount/in-memory re-lock/flake flag change/non-flake input/narHash mismatch/reuse/archive repair/"
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
