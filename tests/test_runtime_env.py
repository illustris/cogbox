"""State-machine tests for cogbox-env over a mocked Nix store; tests/test_runtime_env_nix.py covers real Nix.

Protocol-v2 envelopes are pinned by golden fixtures in tests/fixtures/runtime-env/protocol-v2,
compared byte for byte. Regenerate them with COGBOX_ENV_REGENERATE=1. COGBOX_ENV_FIXTURES
overrides tests/fixtures/runtime-env (needed when this file is copied into the store alone).
"""
import fcntl
import importlib.util
import io
import itertools
import json
import multiprocessing
from pathlib import Path
import os
import shutil
import signal
import sys
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

helper = sys.argv.pop(1) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else str(Path(__file__).parent.parent / "runtime/cogbox-env.py")
spec = importlib.util.spec_from_file_location("runtime", helper)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)

FIXTURES = Path(os.environ.get("COGBOX_ENV_FIXTURES") or Path(__file__).resolve().parent / "fixtures" / "runtime-env")
REGENERATE = os.environ.get("COGBOX_ENV_REGENERATE") == "1"
GIB, MIB = runtime.GIB, runtime.MIB
S = "/nix/store/"
DEP = S + "j" * 32 + "-tool-dependency"
SOURCE = S + "g" * 32 + "-source"
SYSTEM = S + "s" * 32 + "-nixos-system-cogbox"
BOOT_ID = "0b0b0b0b-0000-4000-8000-000000000001"
ENVELOPE = {"version", "ok", "action", "changed", "generation", "status", "error", "capabilities"}
STATUS = {"selection", "selected_generation", "active_generation", "previous_generation", "output", "generations",
          "corrupt_generations", "ignored_entries", "boot_restore", "limits", "guest_system", "boot_id"}
GENERATION = {"id", "output", "derivation", "system", "provenance", "closure_available", "archive_present",
              "archive_valid", "archive_bytes", "created_at"}
LIMITS = {"max_generations", "archive_budget_bytes", "archive_bytes_total", "free_bytes", "reserve_bytes", "max_path_nar_bytes"}


def out(name):
    # One character from Nix's base32 alphabet (no e, o, t or u).
    return S + name * 32 + "-bundle-" + name


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def flip_byte(path):
    """Same-size damage: only the archive's sha256 catches it, since an import registers whatever bytes it reads."""
    data = bytearray(path.read_bytes())
    data[3] ^= 0x20
    path.write_bytes(bytes(data))


def on_a_small_stack(fn):
    """Run fn on a 512 KiB thread stack and return its result.

    Python 3.14 bounds JSON nesting by the C stack it has left. A 64 KiB state file
    nests too shallowly to exhaust the default 8 MiB main stack, but a smaller one
    (a thread, a lower ulimit -s) raises RecursionError, not ValueError.
    """
    outcome = []
    def run():
        try:
            outcome.append((True, fn()))
        except BaseException as exc:
            outcome.append((False, exc))
    previous = threading.stack_size(512 * 1024)
    try:
        worker = threading.Thread(target=run)
        worker.start()
        worker.join(30)
    finally:
        threading.stack_size(previous)
    expect(outcome, "the small-stack worker did not finish")
    ok, value = outcome[0]
    if not ok:
        raise value
    return value


def check_envelope(r):
    """The frozen v2 producer contract (docs/runtime-environment.md)."""
    expect(set(r) == ENVELOPE and r["version"] == 2, r)
    if r["ok"]:
        expect(r["error"] is None, r)
        if r["action"] == "capabilities":
            expect(r["capabilities"] is not None and r["status"] is None and r["generation"] is None, r)
        else:
            expect(r["status"] is not None and r["capabilities"] is None, r)
            expect((r["generation"] is not None) == (r["action"] == "prepare"), r)
    else:
        expect(set(r["error"]) == {"code", "message"} and r["generation"] is None and r["capabilities"] is None, r)
        if r["error"]["code"] == "status_unavailable":
            expect(r["changed"] is True and r["status"] is None, r)
        else:
            expect(r["changed"] is False, r)
    if r["status"] is not None:
        s = r["status"]
        expect(set(s) == STATUS and set(s["limits"]) == LIMITS, s)
        ids = [g["id"] for g in s["generations"]]
        for g in s["generations"]:
            expect(set(g) == GENERATION and g["archive_valid"] is None and type(g["created_at"]) is int, g)
        expect(s["corrupt_generations"] == sorted(s["corrupt_generations"]) and not set(ids) & set(s["corrupt_generations"]), s)
        current = next((g for g in s["generations"] if g["id"] == s["selected_generation"]), None)
        if current is None:
            expect(s["output"] is None and s["active_generation"] is None, s)
        else:
            expect(s["output"] == current["output"] and (s["active_generation"] is not None) == current["closure_available"], s)
        if s["previous_generation"] is not None:
            expect(s["previous_generation"] in ids and s["previous_generation"] != s["selected_generation"], s)
        if s["boot_restore"] is not None:
            expect(set(s["boot_restore"]) == runtime.BOOT_FIELDS, s)


class Store(runtime.Commands):
    """In-memory Nix store driven through the real Commands argv. `paths` are on disk and registered."""
    def __init__(self):
        super().__init__(30)
        self.paths = set()
        self.unregistered = set()  # on disk, unknown to the DB: a guest-only reboot
        self.ghosts = set()        # registered but absent; import cannot repair these
        self.damaged = set()       # present and registered, failing --verify-path
        self.files = set()         # other store files, e.g. a bundle's bin/cogbox-env
        self.no_bin = set()
        self.closures, self.nar, self.builds = {}, {}, {}
        self.hooks = []            # (argv token, exception)
        self.free = 64 * GIB
        self.import_registers = True
        self.imports = 0
        self.calls = []
        self.roots = {}            # indirect GC roots Nix knows (gcroots/auto): link -> output

    def lexists(self, path):
        return path in self.paths or path in self.unregistered or path in self.files or self.isdir(path)

    def isdir(self, path):
        output = path[:-4]
        return path.endswith("/bin") and (output in self.paths or output in self.unregistered) and output not in self.no_bin

    def store_free(self):
        return self.free

    def wipe(self, *paths):
        """Store loss (CP Stop/Start): gone from disk and from the DB.

        Both this and reset_db are a GCE boot, whose fresh /nix/var also forgets every root registration.
        """
        self.roots.clear()
        for path in paths:
            self.paths.discard(path)
            self.unregistered.discard(path)

    def reset_db(self, *paths):
        """Guest-only reboot: the files survive, the DB forgets them."""
        self.roots.clear()
        for path in paths:
            self.paths.discard(path)
            self.unregistered.add(path)

    def run(self, args, *, stdin=None, stdout=None):
        self.calls.append(tuple(args))
        for token, exc in self.hooks:
            if token in args:
                raise exc
        if args[:3] == ["nix-store", "--check-validity", "--print-invalid"]:
            return "".join(p + "\n" for p in args[3:] if p not in self.paths and p not in self.ghosts).encode()
        if args[:2] == ["nix-store", "--verify-path"]:
            if self.damaged.intersection(args[2:]):
                raise runtime.Failure("internal_error", "Nix command failed (exit 1)")
            return b""
        if args[:2] == ["nix-store", "--import"]:
            self.imports += 1
            data = stdin.read().decode()
            if self.import_registers:
                imported = set(data.split(":", 1)[1].strip().split(","))
                self.unregistered -= imported
                self.paths |= imported
            return b""
        if args[:2] == ["nix-store", "--export"]:
            stdout.write(("archive:" + ",".join(args[2:]) + "\n").encode())
            return b""
        if args[:3] == ["nix-store", "--query", "--size"]:
            return "".join("%d\n" % self.nar.get(p, 1000) for p in args[3:]).encode()
        if args[:3] == ["nix-store", "--query", "--requisites"]:
            return "".join(p + "\n" for p in self.closures.get(args[3], [args[3]])).encode()
        if args[:3] == ["nix-store", "--query", "--deriver"]:
            return b"unknown-deriver\n"
        if args[:3] == ["nix-store", "--query", "--binding"]:
            return b"x86_64-linux\n"
        if args[:2] == ["nix-store", "--realise"]:
            if args[2] not in self.paths:
                raise runtime.Failure("internal_error", "Nix command failed (exit 1)")
            link = Path(args[args.index("--add-root") + 1])
            link.unlink(missing_ok=True)
            link.symlink_to(args[2])
            self.roots[str(link)] = args[2]
            return b""
        if args[:2] == ["nix", "eval"]:
            return b"x86_64-linux"
        if args[:3] == ["nix", "flake", "archive"]:
            return json.dumps({"inputs": {}, "path": SOURCE}).encode()
        if args[:2] == ["nix", "build"]:
            output = self.builds[args[-1].split("#", 1)[1]]
            Path(args[args.index("--out-link") + 1]).symlink_to(output)
            return json.dumps([{"drvPath": S + "h" * 32 + "-bundle.drv", "outputs": {"out": output}}]).encode()
        raise runtime.Failure("internal_error", "unexpected command")


class Harness:
    """One guest work directory. <work>/.cogbox exists (brain-materialize's job); the state dir does not yet."""
    def __init__(self, case, parent=True):
        tmp = tempfile.TemporaryDirectory()
        case.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        if parent:
            (self.root / ".cogbox").mkdir()
        self.state = self.root / ".cogbox" / "runtime"
        self.store = Store()

    def env(self, create=False):
        return runtime.Environment(str(self.state), self.store, create)

    def call(self, action, version=2, **fields):
        result = runtime.dispatch({"version": version, "action": action, **fields}, str(self.state), self.store)
        check_envelope(result)
        return result

    def apply(self, generation, token="none"):
        result = self.call("apply", generation=generation, expected_selection=token)
        expect(result["ok"], result)
        return result["status"]["selection"]

    def closure(self, generation):
        return self.env().manifest(generation)["closure"]

    def offer(self, name, nar=None):
        """An output present and registered in the store, ready for prepare --import-store-path."""
        output = out(name)
        self.store.closures[output] = sorted([output, DEP])
        self.store.paths.update(self.store.closures[output])
        if nar is not None:
            self.store.nar[output] = nar
        return output

    def seed(self, name, created_at=None):
        """Publish a generation exactly as prepare would, with its closure present and registered."""
        self.env(create=True)
        output = self.offer(name)
        closure = self.store.closures[output]
        identity = {"version": runtime.STATE_FORMAT, "output": output, "derivation": None, "system": "x86_64-linux",
                    "provenance": {"kind": "import", "source": None, "attribute": None, "inputs_digest": None}}
        generation = runtime.digest(identity)
        directory = self.state / "generations" / generation
        directory.mkdir()
        archive = directory / "closure.nar"
        archive.write_bytes(("archive:" + ",".join(closure) + "\n").encode())
        manifest = {"identity": identity, "closure": closure, "source_archive": None,
                    "archive_sha256": runtime.file_digest(archive), "archive_bytes": archive.stat().st_size}
        manifest["manifest_sha256"] = runtime.digest(manifest)
        runtime.write_json(directory / "manifest.json", manifest)
        os.symlink(output, directory / "root")
        if created_at is not None:
            os.utime(directory / "manifest.json", (created_at, created_at))
        return generation

    def generations(self):
        return sorted(p.name for p in (self.state / "generations").iterdir())

    def leftovers(self):
        return sorted(str(p.relative_to(self.state)) for d in ("generations", "roots") for p in (self.state / d).iterdir() if p.name.startswith("."))


def overlap(state, generation, output, ready, go, result):
    store = Store()
    store.paths.update([output, DEP])
    ready.put(True)
    go.wait(10)
    result.put(runtime.dispatch({"version": 2, "action": "apply", "generation": generation, "expected_selection": "none"}, state, store))


def slow_boot_restore(state, store, importing, release, result):
    """A boot restore whose import blocks until the parent has probed the lock."""
    real = store.run
    def run(args, **kwargs):
        if args[:2] == ["nix-store", "--import"]:
            importing.set()
            release.wait(10)
        return real(args, **kwargs)
    store.run = run
    result.put(runtime.boot_restore(state, store))


class Base(unittest.TestCase):
    def setUp(self):
        self.fs = (16 * GIB, 10 * GIB)
        for name, value in (("filesystem", lambda path: self.fs), ("guest_identity", lambda: (SYSTEM, BOOT_ID))):
            patcher = patch.object(runtime, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)


class RuntimeTest(Base):
    def setUp(self):
        super().setUp()
        self.h = Harness(self)
        self.store = self.h.store
        self.a = self.h.seed("a", created_at=1000)
        self.b = self.h.seed("b", created_at=2000)

    def call(self, action, **fields):
        return self.h.call(action, **fields)

    def assertRerooted(self, generation):
        """The generation's root is registered again, by a call after the last import.

        A GCE boot forgets every registration while roots/<gen> survives on the pool, so
        without this the next garbage collection deletes a restored closure.
        """
        root = str(self.h.state / "roots" / generation)
        output = self.h.env().manifest(generation)["identity"]["output"]
        self.assertEqual(self.store.roots.get(root), output)
        calls = [c[:5] for c in self.store.calls]
        imported = max(i for i, c in enumerate(calls) if c[:2] == ("nix-store", "--import"))
        self.assertIn(("nix-store", "--realise", output, "--add-root", root), calls[imported:])

    # Protocol

    def test_capabilities_answers_any_version_and_touches_nothing(self):
        missing = Harness(self, parent=False)
        for version in (1, 2, 99):
            result = runtime.dispatch({"version": version, "action": "capabilities"}, str(missing.state), missing.store)
            check_envelope(result)
            self.assertEqual(result["capabilities"], {"helper_version": "0.2.0", "protocol_versions": [2], "state_formats": [1],
                                                      "actions": ["apply", "capabilities", "clear", "prepare", "prune", "restore", "rollback", "status"]})
        for version in (0, True, "2"):
            result = runtime.dispatch({"version": version, "action": "capabilities"}, str(missing.state), missing.store)
            self.assertEqual(result["error"]["code"], "unsupported_version")
        self.assertEqual(list(missing.root.iterdir()), [])
        self.assertEqual(missing.store.calls, [])
        # A ready work directory stays untouched too.
        ready = Harness(self)
        self.assertTrue(ready.call("capabilities")["ok"])
        self.assertEqual(list((ready.root / ".cogbox").iterdir()), [])
        # Even the state lock is untouched: a held lock does not delay it.
        with open(self.h.state / "lock", "a+b") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            proc = subprocess.run([sys.executable, helper, "rpc", "--state-dir", str(self.h.state), "--timeout", "5"],
                                  input='{"version":1,"action":"capabilities"}', capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["capabilities"]["protocol_versions"], [2])

    def test_v1_requests_are_rejected(self):
        for req in ({"version": 1, "action": "status"}, {"version": 1, "action": "apply", "generation": self.a, "expected_selection": "none"}):
            result = runtime.dispatch(req, str(self.h.state), self.store)
            check_envelope(result)
            self.assertEqual(result["error"]["code"], "unsupported_version")
            self.assertIsNone(result["status"])
        self.assertIsNone(self.h.env().selected()[0])

    def test_reject_invalid_protocol(self):
        requests = [None, {}, {"version": True, "action": "status"}, {"version": 3, "action": "status"},
                    {"version": 2, "action": "exec"}, {"version": 2, "action": "status", "generation": self.a},
                    {"version": 2, "action": "apply", "generation": self.a},
                    {"version": 2, "action": "apply", "generation": "../bad", "expected_selection": "none"},
                    {"version": 2, "action": "clear"}, {"version": 2, "action": "clear", "expected_selection": "NONE"},
                    {"version": 2, "action": "prune", "expected_selection": "none"},
                    {"version": 2, "action": "restore", "generation": "x"},
                    {"version": 2, "action": "capabilities", "generation": self.a},
                    {"version": 2, "action": "prepare", "flake": "x", "attribute": "x", "import_store_path": "x"}]
        for req in requests:
            with self.subTest(req=req):
                result = runtime.dispatch(req, str(self.h.state), self.store)
                check_envelope(result)
                self.assertFalse(result["ok"])
                self.assertIn(result["error"]["code"], ("invalid_request", "unsupported_version"))
        for raw in ('{} {}', '{"version":2,"version":2}', '{"a":NaN}'):
            with self.assertRaises(ValueError):
                runtime.strict_json(raw)

    def test_rpc_rejects_oversized_and_trailing_requests(self):
        for request in ('{"version":2,"action":"status"} {}', 'x' * (runtime.INPUT_LIMIT + 1),
                        '{"version":2,"version":2,"action":"status"}'):
            proc = subprocess.run([sys.executable, helper, "rpc", "--state-dir", str(self.h.state)],
                                  input=request, capture_output=True, text=True, timeout=5)
            self.assertEqual(proc.returncode, 1)
            reply = json.loads(proc.stdout)
            check_envelope(reply)
            self.assertEqual(reply["error"]["code"], "invalid_request")

    def test_flake_references_with_userinfo_are_rejected_before_nix(self):
        for flake in ("git+https://user:secret@git.example.com/acme/tools", "git+https://token@git.example.com/acme/tools",
                      "git+ssh://git@git.example.com/acme/tools"):
            with self.subTest(flake=flake):
                result = self.call("prepare", flake=flake, attribute="packages.x86_64-linux.default")
                self.assertEqual(result["error"], {"code": "invalid_request", "message": "flake references must not embed credentials"})
        self.assertEqual(self.store.calls, [])
        for flake in ("git+https://git.example.com/acme/tools?ref=main", "path:/root/work/tools@2", "github:acme/tools"):
            runtime.validate_request({"version": 2, "action": "prepare", "flake": flake, "attribute": "default"})

    # Tolerant state

    def test_stray_entries_are_counted_and_never_fail_a_verb(self):
        generations = self.h.state / "generations"
        (generations / "notes.txt").write_text("not ours")
        (generations / "scratch").mkdir()
        (generations / ".prepare-interrupted").mkdir()
        (generations / ("d" * 64)).write_text("a file where a generation belongs")
        status = self.call("status")["status"]
        self.assertEqual(status["ignored_entries"], 2)
        self.assertEqual(status["corrupt_generations"], ["d" * 64])
        self.assertEqual([g["id"] for g in status["generations"]], sorted([self.a, self.b]))
        self.assertTrue(self.call("apply", generation=self.b, expected_selection="none")["ok"])

    def test_corrupt_selected_manifest_is_reported_not_fatal(self):
        token = self.h.apply(self.a)
        path = self.h.state / "generations" / self.a / "manifest.json"
        original = json.loads(path.read_text())
        missing_provenance = dict(original)
        missing_provenance["identity"] = {k: v for k, v in original["identity"].items() if k != "provenance"}
        for value in (None, 1, "bad", [], {}, {"identity": None}, {**original, "identity": None}, {**original, "closure": []}, missing_provenance):
            path.write_text(json.dumps(value))
            # The real entrypoint, so the exit status and envelope are covered too.
            proc = subprocess.run([sys.executable, helper, "rpc", "--state-dir", str(self.h.state)],
                                  input='{"version":2,"action":"status"}', capture_output=True, text=True, timeout=5)
            with self.subTest(value=value):
                self.assertEqual(proc.returncode, 0, proc.stderr)
                status = json.loads(proc.stdout)["status"]
                self.assertEqual((status["selection"], status["selected_generation"]), (token, self.a))
                self.assertIsNone(status["output"])
                self.assertIsNone(status["active_generation"])
                self.assertEqual(status["corrupt_generations"], [self.a])
        restored = self.call("restore")
        self.assertEqual(restored["error"]["code"], "corrupt_state")
        # Unrelated corruption does not block another generation's commit either.
        self.assertTrue(self.call("apply", generation=self.b, expected_selection=token)["ok"])

    def test_deleted_previous_reads_as_none_and_rollback_has_no_previous(self):
        first = self.h.apply(self.a)
        second = self.h.apply(self.b, first)
        shutil.rmtree(self.h.state / "generations" / self.a)
        status = self.call("status")["status"]
        self.assertEqual((status["selection"], status["previous_generation"]), (second, None))
        self.assertEqual(self.call("rollback", expected_selection=second)["error"]["code"], "no_previous")
        (self.h.state / "generations").joinpath(self.a).mkdir()
        (self.h.state / "generations" / self.a / "manifest.json").write_text("{}")
        self.assertIsNone(self.call("status")["status"]["previous_generation"])
        self.assertEqual(self.call("rollback", expected_selection=second)["error"]["code"], "no_previous")

    def test_corrupt_pointer_or_selection_is_corrupt_state_with_documented_recovery(self):
        token = self.h.apply(self.a)
        current = self.h.state / "current"
        selection = self.h.state / "selections" / token
        damage = [lambda: (current.unlink(), current.symlink_to("selections/" + "f" * 32)),
                  lambda: (current.unlink(), current.write_text("not a link")),
                  lambda: ((selection / "bin").unlink(), (selection / "bin").symlink_to(out("b") + "/bin")),
                  lambda: (selection / "selection.json").write_text("{}")]
        for breaks in damage:
            shutil.rmtree(self.h.state)
            self.h.seed("a", created_at=1000)
            token = self.h.apply(self.a)
            selection = self.h.state / "selections" / token
            breaks()
            result = self.call("status")
            self.assertEqual(result["error"]["code"], "corrupt_state")
            self.assertIsNone(result["status"])
            # Recovery: drop the pointer, then select again from none.
            current.unlink()
            self.assertTrue(self.call("apply", generation=self.a, expected_selection="none")["ok"])

    def test_deeply_nested_state_files_are_corrupt_not_internal_error(self):
        token = self.h.apply(self.a)
        def nested(limit):
            depth = limit // 2 - 1
            return "[" * depth + "]" * depth
        manifest = self.h.state / "generations" / self.b / "manifest.json"
        manifest.write_text(nested(runtime.OUTPUT_LIMIT))
        status = on_a_small_stack(lambda: self.call("status"))
        self.assertTrue(status["ok"], status)
        self.assertEqual(status["status"]["corrupt_generations"], [self.b])
        (self.h.state / "boot-restore.json").write_text(nested(runtime.INPUT_LIMIT))
        status = on_a_small_stack(lambda: self.call("status"))
        self.assertTrue(status["ok"], status)
        self.assertIsNone(status["status"]["boot_restore"])
        (self.h.state / "selections" / token / "selection.json").write_text(nested(runtime.INPUT_LIMIT))
        self.assertEqual(on_a_small_stack(lambda: self.call("status"))["error"]["code"], "corrupt_state")
        envelope, record = on_a_small_stack(lambda: runtime.boot_restore(str(self.h.state), self.store))
        self.assertEqual((envelope["error"]["code"], record["outcome"], record["code"]), ("corrupt_state", "failed", "corrupt_state"))

    def test_uncommitted_selection_is_ignored(self):
        token = self.h.apply(self.a)
        (self.h.state / "selections" / ("f" * 32)).mkdir()
        self.assertEqual(self.call("status")["status"]["selection"], token)

    # Non-creating reads

    def test_reads_on_a_missing_state_dir_create_nothing(self):
        fresh = Harness(self)
        checks = [("status", {}, True, None), ("restore", {}, True, None), ("prune", {}, True, None),
                  ("clear", {"expected_selection": "none"}, True, None),
                  ("clear", {"expected_selection": "f" * 32}, False, "stale_selection"),
                  ("apply", {"generation": self.a, "expected_selection": "none"}, False, "invalid_generation"),
                  ("rollback", {"expected_selection": "none"}, False, "no_previous"),
                  ("restore", {"generation": self.a}, False, "invalid_generation"),
                  ("prune", {"generation": self.a}, False, "invalid_generation")]
        for action, fields, ok, code in checks:
            with self.subTest(action=action, fields=fields):
                result = fresh.call(action, **fields)
                self.assertEqual(result["ok"], ok, result)
                self.assertFalse(result["changed"])
                if code:
                    self.assertEqual(result["error"]["code"], code)
                self.assertEqual(result["status"]["generations"], [])
        envelope, record = runtime.boot_restore(str(fresh.state), fresh.store)
        self.assertTrue(envelope["ok"])
        self.assertIsNone(record)
        self.assertEqual(list((fresh.root / ".cogbox").iterdir()), [])
        self.assertEqual(fresh.store.calls, [])

    def test_missing_parent_is_not_ready_and_never_created(self):
        fresh = Harness(self, parent=False)
        for action, fields in (("status", {}), ("prepare", {"import_store_path": out("a")}),
                               ("apply", {"generation": self.a, "expected_selection": "none"}), ("prune", {})):
            result = fresh.call(action, **fields)
            self.assertEqual(result["error"]["code"], "not_ready")
            self.assertIsNone(result["status"])
        self.assertEqual(list(fresh.root.iterdir()), [])
        envelope, record = runtime.boot_restore(str(fresh.state), fresh.store)
        self.assertTrue(envelope["ok"])
        self.assertIsNone(record)
        self.assertEqual(list(fresh.root.iterdir()), [])

    def test_prepare_creates_only_the_state_dir_and_its_subdirectories_durably(self):
        fresh = Harness(self)
        synced = []
        original = runtime.sync_dir
        with patch.object(runtime, "sync_dir", lambda path: (synced.append(path), original(path))[-1]):
            fresh.env(create=True)
        state = fresh.state
        for path in (state, state / "generations", state / "selections", state / "roots"):
            self.assertIn(path, synced)
            self.assertIn(path.parent, synced)
        self.assertNotIn(state.parent.parent, synced)
        self.assertEqual(os.stat(state).st_mode & 0o777, 0o700)
        self.assertEqual(sorted(p.name for p in state.iterdir()), ["generations", "roots", "selections"])

    def test_interrupted_directory_creation_is_synced_on_retry(self):
        fresh = Harness(self)
        # The creator dies after mkdir but before its first fsync.
        with patch.object(runtime, "sync_dir", side_effect=OSError("interrupted creator")):
            with self.assertRaises(OSError):
                runtime.durable_mkdir(fresh.state)
        self.assertTrue(fresh.state.is_dir())
        synced = []
        original = runtime.sync_dir
        with patch.object(runtime, "sync_dir", lambda path: (synced.append(path), original(path))[-1]):
            runtime.durable_mkdir(fresh.state)
        self.assertEqual(synced, [fresh.state, fresh.state.parent])

    # Locking and deadlines

    def test_status_waits_at_most_the_lock_timeout(self):
        self.assertEqual(runtime.STATUS_LOCK_TIMEOUT, 15)
        with open(self.h.state / "lock", "a+b") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            with patch.object(runtime, "STATUS_LOCK_TIMEOUT", 0.2):
                started = time.monotonic()
                result = self.call("status")
                elapsed = time.monotonic() - started
            self.store.deadline = time.monotonic() + 0.3
            mutation = self.call("apply", generation=self.a, expected_selection="none")
        self.assertEqual(result["error"], {"code": "timed_out", "message": runtime.LOCK_BUSY})
        self.assertIsNone(result["status"])
        self.assertLess(elapsed, 5)
        self.assertEqual(mutation["error"]["code"], "timed_out")
        self.assertIsNone(self.h.env().selected()[0])

    def test_concurrent_cas_writers_only_one_commits(self):
        ctx = multiprocessing.get_context("fork")
        ready, result = ctx.Queue(), ctx.Queue()
        go = ctx.Event()
        workers = [ctx.Process(target=overlap, args=(str(self.h.state), g, self.h.env().manifest(g)["identity"]["output"], ready, go, result)) for g in (self.a, self.b)]
        for worker in workers:
            worker.start()
        for _ in workers:
            ready.get(timeout=10)
        go.set()
        replies = [result.get(timeout=10) for _ in workers]
        for worker in workers:
            worker.join(10)
            self.assertEqual(worker.exitcode, 0)
        self.assertEqual(sum(r["ok"] for r in replies), 1)
        self.assertEqual([r["error"]["code"] for r in replies if not r["ok"]], ["stale_selection"])

    def test_deadline_right_after_the_pointer_moves_reports_status_unavailable(self):
        first = self.h.apply(self.a)
        real = os.replace
        def replace(src, dst):
            real(src, dst)
            if Path(dst).name == "current":
                raise runtime.Deadline("operation timed out; inspect status before retrying")
        with patch.object(runtime.os, "replace", replace):
            result = self.call("apply", generation=self.b, expected_selection=first)
        self.assertEqual(result["error"], {"code": "status_unavailable", "message": "selection committed; run cogbox-env status"})
        self.assertTrue(result["changed"])
        self.assertIsNone(result["status"])
        self.assertEqual(self.h.env().selected()[1]["generation"], self.b)
        # A failing post-commit observation is the same outcome.
        original = runtime.Environment.status
        calls = []
        def status(env):
            calls.append(True)
            raise runtime.Deadline("Nix operation timed out")
        token = self.call("status")["status"]["selection"]
        with patch.object(runtime.Environment, "status", status):
            cleared = self.call("clear", expected_selection=token)
        self.assertEqual((cleared["ok"], cleared["changed"], cleared["error"]["code"]), (False, True, "status_unavailable"))
        self.assertIsNone(original(self.h.env())["selection"])
        # Inside the commit section but before the pointer moves: an ordinary error.
        real_symlink = os.symlink
        def symlink(src, dst):
            if Path(dst).name.startswith(".current-"):
                raise OSError("no space")
            real_symlink(src, dst)
        with patch.object(runtime.os, "symlink", symlink):
            failed = self.call("apply", generation=self.a, expected_selection="none")
        self.assertEqual((failed["changed"], failed["error"]["code"]), (False, "internal_error"))
        self.assertIsNone(failed["status"]["selection"])

    def test_commit_defers_the_alarm_until_the_request_has_its_answer(self):
        fired = []
        def handler(_signum, _frame):
            fired.append(True)
            raise runtime.Deadline("operation timed out; inspect status before retrying")
        previous = signal.signal(signal.SIGALRM, handler)
        self.addCleanup(signal.signal, signal.SIGALRM, previous)
        real = os.replace
        masked = []
        def replace(src, dst):
            if Path(dst).name == "current":
                masked.append(signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK, []))
            real(src, dst)
            if Path(dst).name == "current":
                os.kill(os.getpid(), signal.SIGALRM)  # the request deadline lands here
        with patch.object(runtime.os, "replace", replace):
            result = self.call("apply", generation=self.a, expected_selection="none")
        self.assertEqual(masked, [True])
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["changed"])
        self.assertEqual(fired, [])
        self.assertNotIn(signal.SIGALRM, signal.pthread_sigmask(signal.SIG_BLOCK, []))

    def test_deadline_during_build_is_timed_out_not_prepare_failed(self):
        self.store.builds["default"] = self.h.offer("c")
        self.store.hooks.append(("build", runtime.Deadline("Nix operation timed out")))
        before = self.h.generations()
        result = self.call("prepare", flake="path:/root/work/tools", attribute="default")
        self.assertEqual(result["error"]["code"], "timed_out")
        self.assertEqual(self.h.generations(), before)
        self.assertEqual(self.h.leftovers(), [])

    def test_deadline_during_import_is_timed_out_not_restore_failed(self):
        token = self.h.apply(self.a)
        self.store.wipe(*self.h.closure(self.a))
        self.store.hooks.append(("--import", runtime.Deadline("Nix operation timed out")))
        result = self.call("restore")
        self.assertEqual(result["error"]["code"], "timed_out")
        self.assertEqual((result["status"]["selection"], result["status"]["active_generation"]), (token, None))
        envelope, record = runtime.boot_restore(str(self.h.state), self.store)
        self.assertEqual((envelope["error"]["code"], record["outcome"], record["code"]), ("timed_out", "failed", "timed_out"))

    def test_deadline_during_verification_is_timed_out_not_unavailable_closure(self):
        self.store.hooks.append(("--verify-path", runtime.Deadline("Nix operation timed out")))
        result = self.call("apply", generation=self.a, expected_selection="none")
        self.assertEqual(result["error"]["code"], "timed_out")
        self.assertIsNone(result["status"]["selection"])
        self.assertEqual(self.store.imports, 0)

    def test_a_child_outliving_the_deadline_after_closing_its_pipes_is_timed_out(self):
        commands = runtime.Commands(0.5)
        started = time.monotonic()
        with self.assertRaises(runtime.Deadline):
            commands.run([sys.executable, "-c", "import os, time; os.close(1); os.close(2); time.sleep(30)"])
        self.assertLess(time.monotonic() - started, 10)

    def test_availability_timeout_is_not_missing_closure_success(self):
        commands = runtime.Commands(1)
        with patch.object(commands, "missing", return_value=[]), patch.object(commands, "run", side_effect=runtime.Deadline("timed out")):
            with self.assertRaises(runtime.Deadline):
                commands.available([out("a")])

    # Selection

    def test_cas_aba_and_noop_preserve_previous(self):
        first = self.h.apply(self.a)
        second = self.h.apply(self.b, first)
        r = self.call("rollback", expected_selection=second)
        self.assertTrue(r["ok"])
        third = r["status"]["selection"]
        self.assertNotEqual(third, first)
        stale = self.call("apply", generation=self.a, expected_selection=first)
        self.assertEqual(stale["error"]["code"], "stale_selection")
        same = self.call("apply", generation=self.a, expected_selection=third)
        self.assertFalse(same["changed"])
        self.assertEqual(same["status"]["selection"], third)
        self.assertEqual(same["status"]["previous_generation"], self.b)

    def test_clear_is_compare_and_swap_and_keeps_generations(self):
        none = self.call("clear", expected_selection="none")
        self.assertEqual((none["ok"], none["changed"]), (True, False))
        token = self.h.apply(self.a)
        self.assertEqual(self.call("clear", expected_selection="none")["error"]["code"], "stale_selection")
        self.assertEqual(self.call("clear", expected_selection="f" * 32)["error"]["code"], "stale_selection")
        cleared = self.call("clear", expected_selection=token)
        self.assertEqual((cleared["ok"], cleared["changed"]), (True, True))
        self.assertIsNone(cleared["status"]["selection"])
        self.assertFalse(os.path.lexists(self.h.state / "current"))
        self.assertEqual(self.h.generations(), sorted([self.a, self.b]))
        self.assertTrue(self.call("apply", generation=self.b, expected_selection="none")["ok"])

    def test_apply_and_rollback_import_a_lost_closure_offline(self):
        first = self.h.apply(self.a)
        second = self.h.apply(self.b, first)
        self.store.wipe(*self.h.closure(self.a), *self.h.closure(self.b))
        status = self.call("status")["status"]
        self.assertEqual((status["selected_generation"], status["active_generation"]), (self.b, None))
        rolled = self.call("rollback", expected_selection=second)
        self.assertTrue(rolled["ok"], rolled)
        self.assertEqual((rolled["changed"], rolled["status"]["active_generation"]), (True, self.a))
        self.assertEqual(self.store.imports, 1)
        applied = self.call("apply", generation=self.b, expected_selection=rolled["status"]["selection"])
        self.assertEqual(applied["status"]["active_generation"], self.b)
        self.assertEqual(self.store.imports, 2)
        for call in self.store.calls:
            self.assertNotIn("build", call)
            self.assertNotIn("eval", call)

    def test_reapplying_the_selected_generation_reimports_and_keeps_the_token(self):
        token = self.h.apply(self.a)
        self.store.wipe(*self.h.closure(self.a))
        again = self.call("apply", generation=self.a, expected_selection=token)
        self.assertTrue(again["ok"], again)
        # changed reports the import; the selection token does not move (fixture apply-reimport-ok).
        self.assertEqual((again["changed"], again["status"]["selection"], again["status"]["active_generation"]), (True, token, self.a))
        self.assertEqual(self.store.imports, 1)
        same = self.call("apply", generation=self.a, expected_selection=token)
        self.assertEqual((same["changed"], same["status"]["selection"]), (False, token))
        self.assertEqual(self.store.imports, 1)

    def test_apply_refuses_a_damaged_closure_that_import_cannot_fix(self):
        self.store.damaged.add(out("a"))
        result = self.call("apply", generation=self.a, expected_selection="none")
        self.assertEqual(result["error"]["code"], "unavailable_closure")
        self.assertEqual(self.store.imports, 0)
        self.assertIsNone(result["status"]["selection"])

    # Prepare

    def test_prepare_flake_publishes_and_reuses(self):
        self.store.builds["packages.x86_64-linux.default"] = self.h.offer("c")
        first = self.call("prepare", flake="path:/root/work/tools", attribute="packages.x86_64-linux.default")
        self.assertTrue(first["ok"], first)
        self.assertTrue(first["changed"])
        generation = first["generation"]
        listed = next(g for g in first["status"]["generations"] if g["id"] == generation)
        self.assertEqual(listed["provenance"]["kind"], "flake")
        self.assertEqual(listed["provenance"]["source"], SOURCE)
        self.assertIsNone(first["status"]["selection"])
        self.assertTrue((self.h.state / "roots" / generation).is_symlink())
        again = self.call("prepare", flake="path:/root/work/tools", attribute="packages.x86_64-linux.default")
        self.assertEqual((again["generation"], again["changed"]), (generation, False))
        self.assertEqual(self.h.leftovers(), [])

    def test_failed_prepare_never_selects_publishes_or_leaks_a_root(self):
        token = self.h.apply(self.a)
        before = self.h.generations()
        output = self.h.offer("c")
        generation = runtime.digest({"version": 1, "output": output, "derivation": None, "system": "x86_64-linux",
                                     "provenance": {"kind": "import", "source": None, "attribute": None, "inputs_digest": None}})
        self.store.hooks.append(("--export", runtime.Failure("internal_error", "injected export failure")))
        failed = self.call("prepare", import_store_path=output)
        self.assertEqual(failed["error"]["code"], "prepare_failed")
        self.assertEqual(failed["status"]["selection"], token)
        self.assertEqual(self.h.generations(), before)
        # The generation root was created for the export, then must go with it.
        self.assertIn(("nix-store", "--realise", output, "--add-root", str(self.h.state / "roots" / generation)),
                      [c[:5] for c in self.store.calls])
        self.assertFalse(os.path.lexists(self.h.state / "roots" / generation))
        self.assertEqual(self.h.leftovers(), [])
        self.store.hooks.clear()
        self.assertTrue(self.call("prepare", import_store_path=output)["ok"])

    def test_bundle_providing_cogbox_env_is_refused(self):
        output = self.h.offer("c")
        self.store.files.add(output + "/bin/cogbox-env")
        result = self.call("prepare", import_store_path=output)
        self.assertEqual(result["error"], {"code": "prepare_failed", "message": "bundle must not provide cogbox-env"})
        self.assertEqual(self.h.generations(), sorted([self.a, self.b]))

    def test_reprepare_repairs_a_missing_or_corrupt_archive(self):
        token = self.h.apply(self.a)
        archive = self.h.state / "generations" / self.a / "closure.nar"
        manifest = self.h.env().manifest(self.a)
        for damage in (flip_byte, lambda path: path.write_bytes(b"truncat"), Path.unlink):
            damage(archive)
            result = self.call("prepare", import_store_path=out("a"))
            self.assertTrue(result["ok"], result)
            self.assertEqual((result["generation"], result["changed"]), (self.a, True))
            self.assertEqual(runtime.file_digest(archive), self.h.env().manifest(self.a)["archive_sha256"])
            self.assertEqual(self.h.env().manifest(self.a)["identity"], manifest["identity"])
            self.assertEqual(self.h.env().selected()[0], token)
            self.assertEqual(sorted(p.name for p in archive.parent.iterdir()), ["closure.nar", "manifest.json", "root"])
        intact = self.call("prepare", import_store_path=out("a"))
        self.assertEqual((intact["ok"], intact["changed"]), (True, False))
        # The repaired archive restores.
        self.store.wipe(*self.h.closure(self.a))
        self.assertTrue(self.call("restore")["changed"])

    def test_reprepare_repairs_a_corrupt_manifest(self):
        (self.h.state / "generations" / self.a / "manifest.json").write_text("{")
        self.assertEqual(self.call("status")["status"]["corrupt_generations"], [self.a])
        result = self.call("prepare", import_store_path=out("a"))
        self.assertEqual((result["ok"], result["generation"], result["changed"]), (True, self.a, True))
        self.assertEqual(result["status"]["corrupt_generations"], [])

    def test_an_interrupted_archive_repair_leaves_no_partial_files(self):
        token = self.h.apply(self.a)
        directory = self.h.state / "generations" / self.a
        published = ["closure.nar", "manifest.json", "root"]
        # The deadline lands in the export, after closure.nar.new was created.
        flip_byte(directory / "closure.nar")
        self.store.hooks.append(("--export", runtime.Deadline("Nix operation timed out")))
        result = self.call("prepare", import_store_path=out("a"))
        self.assertEqual(result["error"]["code"], "timed_out")
        self.assertEqual(sorted(p.name for p in directory.iterdir()), published)
        self.store.hooks.clear()
        # It lands between the renames: the new archive is in place, manifest.json.new is not.
        (directory / "manifest.json").write_text("{")
        real = os.rename
        def rename(src, dst):
            if Path(dst).name == "manifest.json":
                raise runtime.Deadline("operation timed out; inspect status before retrying")
            real(src, dst)
        with patch.object(runtime.os, "rename", rename):
            result = self.call("prepare", import_store_path=out("a"))
        self.assertEqual(result["error"]["code"], "timed_out")
        self.assertEqual(result["status"]["corrupt_generations"], [self.a])
        self.assertEqual(sorted(p.name for p in directory.iterdir()), published)
        repaired = self.call("prepare", import_store_path=out("a"))
        self.assertEqual((repaired["ok"], repaired["generation"], repaired["changed"]), (True, self.a, True), repaired)
        self.assertEqual(runtime.file_digest(directory / "closure.nar"), self.h.env().manifest(self.a)["archive_sha256"])
        self.assertEqual(sorted(p.name for p in directory.iterdir()), published)
        self.assertEqual(self.h.env().selected()[0], token)

    # Retention

    def test_per_path_cap_refuses_without_dropping(self):
        output = self.h.offer("c", nar=runtime.MAX_PATH_NAR + 1)
        result = self.call("prepare", import_store_path=output)
        self.assertEqual(result["error"]["code"], "insufficient_space")
        self.assertIn(output, result["error"]["message"])
        self.assertEqual(self.h.generations(), sorted([self.a, self.b]))

    def test_over_budget_bundle_is_refused(self):
        self.fs = (2 * GIB, 2 * GIB)  # budget 512 MiB
        output = self.h.offer("c", nar=600 * MIB)
        result = self.call("prepare", import_store_path=output)
        self.assertEqual(result["error"]["code"], "insufficient_space")
        self.assertIn("archive budget", result["error"]["message"])

    def test_preflight_drops_corrupt_then_oldest_unprotected(self):
        first = self.h.apply(self.a)
        self.h.apply(self.b, first)
        c = self.h.seed("c", created_at=3000)
        d = self.h.seed("d", created_at=4000)
        x = self.h.seed("x", created_at=500)
        (self.h.state / "generations" / x / "manifest.json").write_text("null")
        (self.h.state / "roots" / c).symlink_to(out("c"))
        output = self.h.offer("f")
        result = self.call("prepare", import_store_path=output)
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.h.generations(), sorted([self.a, self.b, d, result["generation"]]))
        self.assertEqual(result["status"]["previous_generation"], self.a)
        self.assertFalse(os.path.lexists(self.h.state / "roots" / c))
        self.assertEqual(self.h.leftovers(), [])

    def test_preflight_refuses_when_only_protected_generations_remain(self):
        first = self.h.apply(self.a)
        self.h.apply(self.b, first)
        c = self.h.seed("c", created_at=3000)
        self.fs = (4 * GIB, 3 * GIB)  # budget 1 GiB, reserve 2 GiB
        budget = runtime.archive_budget(self.fs[0])
        output = self.h.offer("f", nar=budget - 2 * runtime.PATH_OVERHEAD - 1000 - 10)
        result = self.call("prepare", import_store_path=output)
        self.assertEqual(result["error"]["code"], "insufficient_space")
        for text in (self.a, self.b, "prune --generation", "clear"):
            self.assertIn(text, result["error"]["message"])
        self.assertEqual(self.h.generations(), sorted([self.a, self.b, c]))

    def test_reserve_refuses_without_dropping(self):
        c = self.h.seed("c", created_at=3000)
        d = self.h.seed("d", created_at=4000)
        self.fs = (16 * GIB, 2 * GIB + 10 * MIB)
        output = self.h.offer("f", nar=20 * MIB)
        result = self.call("prepare", import_store_path=output)
        self.assertEqual(result["error"]["code"], "insufficient_space")
        self.assertIn("must stay free", result["error"]["message"])
        self.assertEqual(self.h.generations(), sorted([self.a, self.b, c, d]))

    def test_reserve_counts_the_archives_the_drops_free(self):
        c, d, f = (self.h.seed(n, created_at=t) for n, t in (("c", 3000), ("d", 4000), ("f", 5000)))
        output = self.h.offer("g")
        projected = 2 * 1000 + 2 * runtime.PATH_OVERHEAD
        # One byte short of the reserve until the two oldest archives go.
        self.fs = (16 * GIB, runtime.reserve_bytes(16 * GIB) + projected - 1)
        result = self.call("prepare", import_store_path=output)
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.h.generations(), sorted([c, d, f, result["generation"]]))

    def test_preflight_never_drops_the_generation_it_repairs(self):
        # Repair reaches the preflight with its target listed as corrupt (bad manifest) or as
        # the oldest valid one (bad archive): the first drop candidate either way, unless protected.
        for damage in ("manifest.json", "closure.nar"):
            with self.subTest(damage=damage):
                h = Harness(self)
                a, b, c = (h.seed(n, created_at=t) for n, t in (("a", 1000), ("b", 2000), ("c", 3000)))
                token = h.apply(c)
                d, f = (h.seed(n, created_at=t) for n, t in (("d", 4000), ("f", 5000)))
                (h.state / "generations" / a / damage).write_text("{")
                result = h.call("prepare", import_store_path=out("a"))
                self.assertTrue(result["ok"], result)
                self.assertEqual((result["generation"], result["changed"]), (a, True))
                # One over the limit: the oldest unprotected generation goes instead.
                self.assertEqual(h.generations(), sorted([a, c, d, f]))
                self.assertEqual(runtime.file_digest(h.state / "generations" / a / "closure.nar"), h.env().manifest(a)["archive_sha256"])
                self.assertEqual(result["status"]["selection"], token)

    def test_prune_drops_corrupt_enforces_the_limit_and_sweeps(self):
        first = self.h.apply(self.a)
        second = self.h.apply(self.b, first)
        c, d, f = (self.h.seed(n, created_at=t) for n, t in (("c", 3000), ("d", 4000), ("f", 5000)))
        x = self.h.seed("x", created_at=100)
        (self.h.state / "generations" / x / "manifest.json").write_text("[]")
        state = self.h.state
        (state / "generations" / ".prepare-killed").mkdir()
        (state / "generations" / ".trash-killed").mkdir()
        (state / ".current-killed").symlink_to("selections/" + first)
        (state / ".boot-restore-killed").write_text("{}")
        (state / "roots" / ".preparing-killed").symlink_to(out("c"))
        (state / "roots" / ("9" * 64)).symlink_to(out("c"))
        (state / "selections" / ("1" * 32)).mkdir()
        (state / "generations" / "notes.txt").write_text("not ours")
        result = self.call("prune")
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["changed"])
        self.assertEqual(self.h.generations(), sorted([self.a, self.b, d, f, "notes.txt"]))
        self.assertEqual(sorted(p.name for p in (state / "selections").iterdir()), [second])
        self.assertEqual(sorted(p.name for p in (state / "roots").iterdir()), sorted([self.a, self.b]))
        self.assertEqual(sorted(p.name for p in state.iterdir() if p.name.startswith(".")), [])
        self.assertEqual((result["status"]["selection"], result["status"]["previous_generation"]), (second, self.a))
        again = self.call("prune")
        self.assertEqual((again["ok"], again["changed"]), (True, False))

    def test_prune_removes_an_interrupted_repair_and_nothing_it_does_not_own(self):
        self.h.apply(self.a)
        c = self.h.seed("c", created_at=3000)
        directory = self.h.state / "generations" / self.b
        archive = (directory / "closure.nar").read_bytes()
        # A repair killed before (closure.nar.new) or between (manifest.json.new) its renames.
        (directory / "manifest.json.new").write_text("{}")
        (directory / "closure.nar.new").write_bytes(b"partial")
        # Prune does not read archives: a valid generation with a damaged one stays for prepare to repair.
        flip_byte(self.h.state / "generations" / c / "closure.nar")
        result = self.call("prune")
        self.assertEqual((result["ok"], result["changed"]), (True, True), result)
        self.assertEqual(sorted(p.name for p in directory.iterdir()), ["closure.nar", "manifest.json", "root"])
        self.assertEqual((directory / "closure.nar").read_bytes(), archive)
        self.assertEqual(self.h.generations(), sorted([self.a, self.b, c]))
        self.assertEqual([g["id"] for g in result["status"]["generations"]], sorted([self.a, self.b, c]))
        again = self.call("prune")
        self.assertEqual((again["ok"], again["changed"]), (True, False))

    def test_prune_counts_a_corrupt_selected_generation_toward_the_limit(self):
        first = self.h.apply(self.a)
        x = self.h.seed("x", created_at=3000)
        self.h.apply(x, first)
        c, d, f = (self.h.seed(n, created_at=t) for n, t in (("c", 4000), ("d", 5000), ("f", 6000)))
        (self.h.state / "generations" / x / "manifest.json").write_text("{")
        result = self.call("prune")
        self.assertTrue(result["ok"], result)
        # Six generations, one of them the corrupt selected one: two unprotected ones go.
        self.assertEqual(self.h.generations(), sorted([self.a, x, d, f]))

    def test_prune_generation(self):
        first = self.h.apply(self.a)
        second = self.h.apply(self.b, first)
        refused = self.call("prune", generation=self.b)
        self.assertEqual(refused["error"]["code"], "invalid_request")
        self.assertEqual(self.call("prune", generation="c" * 64)["error"]["code"], "invalid_generation")
        dropped = self.call("prune", generation=self.a)
        self.assertEqual((dropped["ok"], dropped["changed"]), (True, True))
        self.assertIsNone(dropped["status"]["previous_generation"])
        self.assertEqual(self.call("rollback", expected_selection=second)["error"]["code"], "no_previous")

    def test_auto_prune_after_commit_and_its_failure_is_stderr_only(self):
        c, d, f = (self.h.seed(n, created_at=t) for n, t in (("c", 3000), ("d", 4000), ("f", 5000)))
        result = self.call("apply", generation=f, expected_selection="none")
        self.assertTrue(result["ok"])
        self.assertEqual(self.h.generations(), sorted([self.b, c, d, f]))
        g = self.h.seed("g", created_at=6000)
        stderr = io.StringIO()
        with patch.object(runtime.Environment, "prune", side_effect=OSError("disk went away")), patch.object(sys, "stderr", stderr):
            applied = self.call("apply", generation=g, expected_selection=result["status"]["selection"])
        self.assertEqual((applied["ok"], applied["changed"]), (True, True))
        self.assertIn("automatic prune failed: disk went away", stderr.getvalue())
        self.assertEqual(len(self.h.generations()), 5)

    # Restore

    def test_restore_fast_path_neither_hashes_nor_verifies(self):
        token = self.h.apply(self.a)
        self.store.calls.clear()
        self.store.roots.clear()
        with patch.object(runtime, "file_digest", side_effect=AssertionError("archive hashed")):
            result = self.call("restore")
        self.assertEqual((result["ok"], result["changed"], result["status"]["selection"]), (True, False, token))
        self.assertFalse([c for c in self.store.calls if "--verify-path" in c or "--import" in c])
        # It still re-roots.
        self.assertEqual(self.store.roots, {str(self.h.state / "roots" / self.a): out("a")})

    def test_restore_targets_the_selected_generation_only(self):
        first = self.h.apply(self.a)
        self.h.apply(self.b, first)
        self.store.wipe(out("a"), out("b"))
        result = self.call("restore")
        self.assertEqual((result["changed"], result["status"]["active_generation"]), (True, self.b))
        self.assertNotIn(out("a"), self.store.paths)
        self.assertEqual(self.store.imports, 1)
        targeted = self.call("restore", generation=self.a)
        self.assertEqual((targeted["changed"], targeted["status"]["selected_generation"]), (True, self.b))
        self.assertIn(out("a"), self.store.paths)

    def test_registered_but_missing_paths_are_store_inconsistent(self):
        self.h.apply(self.a)
        self.store.wipe(out("a"))
        self.store.ghosts.add(out("a"))
        result = self.call("restore")
        self.assertEqual(result["error"]["code"], "store_inconsistent")
        self.assertIn("1 closure paths", result["error"]["message"])
        self.assertEqual(self.store.imports, 0)

    def test_free_space_precheck_counts_only_missing_paths(self):
        self.h.apply(self.a)
        archive_bytes = self.h.env().manifest(self.a)["archive_bytes"]
        self.store.free = runtime.RESTORE_HEADROOM + archive_bytes - 1
        # Guest-only reboot: every path present but unregistered, rewritten in place.
        self.store.reset_db(*self.h.closure(self.a))
        result = self.call("restore")
        self.assertEqual((result["ok"], result["changed"]), (True, True), result)
        self.assertEqual(self.store.imports, 1)
        # One path really missing: the whole archive counts. The refusal comes before the archive is hashed.
        self.store.reset_db(*self.h.closure(self.a))
        self.store.wipe(out("a"))
        with patch.object(runtime, "file_digest", side_effect=AssertionError("archive hashed")):
            refused = self.call("restore")
        self.assertEqual(refused["error"]["code"], "insufficient_space")
        self.assertEqual(self.store.imports, 1)
        # Even the all-present shape needs the headroom.
        self.store.free = runtime.RESTORE_HEADROOM - 1
        self.store.unregistered.update(self.h.closure(self.a))
        with patch.object(runtime, "file_digest", side_effect=AssertionError("archive hashed")):
            self.assertEqual(self.call("restore")["error"]["code"], "insufficient_space")
        self.assertEqual(self.store.imports, 1)

    def test_corrupt_and_missing_archive_leave_pointer_unchanged(self):
        token = self.h.apply(self.a)
        self.store.wipe(*self.h.closure(self.a))
        archive = self.h.state / "generations" / self.a / "closure.nar"
        for damage in (flip_byte, lambda path: path.write_bytes(b"invalid archive"), Path.unlink):
            damage(archive)
            result = self.call("restore")
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["error"]["code"], "invalid_archive")
            self.assertEqual(result["status"]["selection"], token)
            self.assertIsNone(result["status"]["active_generation"])
            self.assertEqual(self.store.imports, 0)
            envelope, record = runtime.boot_restore(str(self.h.state), self.store)
            self.assertEqual((envelope["error"]["code"], record["outcome"], record["code"]), ("invalid_archive", "failed", "invalid_archive"))
            self.assertEqual(self.store.imports, 0)

    def test_import_that_does_not_register_the_closure_is_restore_failed(self):
        self.h.apply(self.a)
        self.store.wipe(*self.h.closure(self.a))
        self.store.import_registers = False
        result = self.call("restore")
        self.assertEqual(result["error"]["code"], "restore_failed")
        self.assertEqual(self.store.imports, 1)

    # Boot restore

    def test_boot_restore_without_a_selection_writes_nothing(self):
        envelope, record = runtime.boot_restore(str(self.h.state), self.store)
        self.assertTrue(envelope["ok"])
        self.assertIsNone(record)
        self.assertFalse((self.h.state / "boot-restore.json").exists())
        fresh = Harness(self)
        proc = subprocess.run([sys.executable, helper, "restore", "--boot", "--state-dir", str(fresh.state)],
                              capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(json.loads(proc.stdout)["ok"])
        self.assertEqual(proc.stderr, "")
        self.assertEqual(list((fresh.root / ".cogbox").iterdir()), [])
        # A non-symlink current is not a selection either: still a no-op that writes nothing.
        (self.h.state / "current").write_text("not a link")
        proc = subprocess.run([sys.executable, helper, "restore", "--boot", "--state-dir", str(self.h.state)],
                              capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["error"]["code"], "corrupt_state")
        self.assertFalse((self.h.state / "boot-restore.json").exists())
        for argv in (["status", "--boot"], ["restore", "--boot", "--generation", self.a]):
            proc = subprocess.run([sys.executable, helper, *argv, "--state-dir", str(fresh.state)], capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("--boot", proc.stderr)

    def test_boot_restore_restores_the_selection_and_records_the_outcome(self):
        first = self.h.apply(self.a)
        self.h.apply(self.b, first)
        self.store.wipe(out("a"), out("b"))
        self.store.calls.clear()
        envelope, record = runtime.boot_restore(str(self.h.state), self.store)
        self.assertTrue(envelope["ok"], envelope)
        self.assertTrue(envelope["changed"])
        self.assertEqual({k: record[k] for k in ("boot_id", "outcome", "code", "generation")},
                         {"boot_id": BOOT_ID, "outcome": "restored", "code": None, "generation": self.b})
        self.assertEqual(runtime.read_json_file(self.h.state / "boot-restore.json"), record)
        self.assertEqual(self.call("status")["status"]["boot_restore"], record)
        self.assertNotIn(out("a"), self.store.paths)
        self.assertFalse([c for c in self.store.calls if "--verify-path" in c])
        self.assertRerooted(self.b)
        self.assertRegex(runtime.summary_line(record), r"\Acogbox-runtime-restore: outcome=restored code=- generation=%s duration_ms=\d+\Z" % self.b)
        active, record = runtime.boot_restore(str(self.h.state), self.store)
        self.assertEqual((active["changed"], record["outcome"]), (False, "active"))
        self.store.wipe(out("b"))
        (self.h.state / "generations" / self.b / "closure.nar").write_bytes(b"truncated")
        failed, record = runtime.boot_restore(str(self.h.state), self.store)
        self.assertEqual((failed["ok"], failed["error"]["code"]), (False, "invalid_archive"))
        self.assertEqual((record["outcome"], record["code"], record["generation"]), ("failed", "invalid_archive", self.b))
        status = self.call("status")["status"]
        self.assertEqual((status["selected_generation"], status["active_generation"], status["boot_restore"]), (self.b, None, record))
        self.assertEqual(runtime.summary_line(record).split()[1:4], ["outcome=failed", "code=invalid_archive", "generation=" + self.b])
        self.assertEqual([p.name for p in self.h.state.iterdir() if p.name.startswith(".")], [])
        # The real entrypoint: one summary line on stderr and an exit status that follows the outcome.
        selection = self.h.state / "selections" / status["selection"]
        proc = subprocess.run([sys.executable, helper, "restore", "--boot", "--state-dir", str(self.h.state)],
                              capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 1)
        self.assertRegex(proc.stderr, r"\Acogbox-runtime-restore: outcome=failed code=(restore_failed|invalid_archive|internal_error) generation=%s duration_ms=\d+\n\Z" % self.b)
        self.assertTrue(selection.is_dir())

    def test_boot_restore_after_a_guest_reboot_registers_the_root_again(self):
        # The files survived and roots/<gen> still points at them, but the fresh database
        # knows neither the paths nor the root.
        self.h.apply(self.a)
        self.store.reset_db(*self.h.closure(self.a))
        self.store.calls.clear()
        envelope, record = runtime.boot_restore(str(self.h.state), self.store)
        self.assertEqual((envelope["ok"], envelope["changed"], record["outcome"]), (True, True, "restored"), envelope)
        self.assertRerooted(self.a)

    def test_boot_restore_outcome_survives_a_failed_record_write(self):
        self.h.apply(self.a)
        self.store.wipe(out("a"))
        stderr = io.StringIO()
        with patch.object(runtime.Environment, "write_boot_record", side_effect=OSError("read-only filesystem")), patch.object(sys, "stderr", stderr):
            envelope, record = runtime.boot_restore(str(self.h.state), self.store)
        self.assertEqual((envelope["ok"], record["outcome"]), (True, "restored"))
        self.assertIn("could not record the boot restore: read-only filesystem", stderr.getvalue())

    def test_boot_restore_holds_the_state_lock_while_it_imports(self):
        # The skill and the doc promise that status answers timed_out while the restore runs.
        self.h.apply(self.a)
        self.store.wipe(*self.h.closure(self.a))
        ctx = multiprocessing.get_context("fork")
        importing, release, result = ctx.Event(), ctx.Event(), ctx.Queue()
        child = ctx.Process(target=slow_boot_restore, args=(str(self.h.state), self.store, importing, release, result))
        child.start()
        try:
            self.assertTrue(importing.wait(10))
            with patch.object(runtime, "STATUS_LOCK_TIMEOUT", 0.2):
                busy = self.call("status")
        finally:
            release.set()
        envelope, record = result.get(timeout=10)
        child.join(10)
        self.assertEqual(child.exitcode, 0)
        self.assertEqual(busy["error"], {"code": "timed_out", "message": runtime.LOCK_BUSY})
        self.assertEqual((envelope["ok"], record["outcome"]), (True, "restored"))
        self.assertEqual(self.call("status")["status"]["boot_restore"], record)

    def test_boot_record_garbage_reads_as_none(self):
        for value in ("{", "[]", json.dumps({"outcome": "restored"}),
                      json.dumps({"boot_id": None, "outcome": "maybe", "code": None, "generation": None, "finished_at": 1, "duration_ms": 1})):
            (self.h.state / "boot-restore.json").write_text(value)
            self.assertIsNone(self.call("status")["status"]["boot_restore"])


class StateFormatOneTest(Base):
    """The POC wrote state format 1; helpers must keep reading it (fixtures/runtime-env/state-format-1)."""
    FLAKE = "0f640f43622cd52a76cea70ddd4f3c3cd932932c1bbc2a21f106578e983c5c20"
    IMPORT = "dbb63f980c7da61782a535b43221dfeb8442364a756fa8d30d09438ae1be33df"
    SELECTION = "0436a8af34df43fb982f5bc64d08af9f"
    PATHS = [S + "f" * 32 + "-tools-a", S + "k" * 32 + "-tools-b", S + "j" * 32 + "-tool-dependency"]

    def setUp(self):
        super().setUp()
        source = FIXTURES / "state-format-1" / "runtime"
        self.assertTrue(source.is_dir(), "missing %s; set COGBOX_ENV_FIXTURES" % source)
        self.h = Harness(self)
        shutil.copytree(source, self.h.state, symlinks=True)
        # A store copy of the fixture is read-only.
        for directory, _, files in os.walk(self.h.state):
            os.chmod(directory, 0o700)
            for name in files:
                if not os.path.islink(os.path.join(directory, name)):
                    os.chmod(os.path.join(directory, name), 0o600)
        self.h.store.paths.update(self.PATHS)

    def test_poc_state_parses_and_operates(self):
        status = self.h.call("status")["status"]
        self.assertEqual((status["selection"], status["selected_generation"], status["previous_generation"]),
                         (self.SELECTION, self.IMPORT, self.FLAKE))
        self.assertEqual(status["active_generation"], self.IMPORT)
        self.assertEqual((status["corrupt_generations"], status["ignored_entries"], status["boot_restore"]), ([], 0, None))
        kinds = {g["id"]: g["provenance"]["kind"] for g in status["generations"]}
        self.assertEqual(kinds, {self.FLAKE: "flake", self.IMPORT: "import"})
        self.assertEqual(runtime.digest(self.h.env().manifest(self.FLAKE)["identity"]), self.FLAKE)
        # Store loss, then the POC archives restore and the POC token still commits.
        self.h.store.wipe(*self.PATHS)
        self.assertTrue(self.h.call("restore")["changed"])
        rolled = self.h.call("rollback", expected_selection=self.SELECTION)
        self.assertTrue(rolled["ok"], rolled)
        self.assertEqual((rolled["status"]["selected_generation"], rolled["status"]["previous_generation"]), (self.FLAKE, self.IMPORT))
        self.assertEqual(self.h.store.imports, 2)


class GoldenTest(Base):
    """Protocol-v2 envelopes, byte for byte. The control plane decodes copies of these files."""
    CREATED_AT = 1760000000

    def test_protocol_v2_fixtures(self):
        cases = self.cases()
        directory = FIXTURES / "protocol-v2"
        if REGENERATE:
            directory.mkdir(parents=True, exist_ok=True)
            for stale in directory.glob("*.json"):
                stale.unlink()
            for name, data in cases.items():
                (directory / (name + ".json")).write_bytes(data)
        self.assertTrue(directory.is_dir(), "missing %s; set COGBOX_ENV_FIXTURES or regenerate with COGBOX_ENV_REGENERATE=1" % directory)
        self.assertEqual(sorted(p.stem for p in directory.glob("*.json")), sorted(cases))
        for name, data in cases.items():
            with self.subTest(fixture=name):
                self.assertEqual((directory / (name + ".json")).read_bytes().decode(), data.decode())
        envelopes = [json.loads(data) for data in cases.values()]
        envelopes = [e["response"] if "request" in e else e for e in envelopes]
        codes = {e["error"]["code"] for e in envelopes if e["error"]}
        self.assertEqual(codes, {"invalid_request", "unsupported_version", "stale_selection", "invalid_generation",
                                 "unavailable_closure", "invalid_archive", "prepare_failed", "restore_failed",
                                 "corrupt_state", "internal_error", "no_previous", "insufficient_space", "not_ready",
                                 "store_inconsistent", "timed_out", "status_unavailable"})

    def cases(self):
        cases = {}
        tokens = [None]
        created = patch.object(runtime.Environment, "created_at", lambda env, generation: self.CREATED_AT)
        token_patch = patch.object(runtime, "new_token", lambda: "%032x" % next(tokens[0]))
        created.start()
        token_patch.start()
        self.addCleanup(created.stop)
        self.addCleanup(token_patch.stop)

        def case(parent=True):
            tokens[0] = itertools.count(1)
            return Harness(self, parent)

        def record(name, h, action, **fields):
            cases[name] = runtime.encode(h.call(action, **fields))

        def selected(h, *names):
            generations = [h.seed(n) for n in names]
            token = "none"
            for generation in generations:
                token = h.apply(generation, token)
            return generations, token

        h = case()
        cases["capabilities"] = runtime.encode(runtime.dispatch({"version": 2, "action": "capabilities"}, str(h.state), h.store))
        # action:null: the request named no action the helper knows. main() also answers an unreadable,
        # oversized or timed-out request with action:null. Consumers must accept it on an error envelope.
        cases["error-invalid_request-null_action"] = runtime.encode(runtime.dispatch({"version": 2, "action": "exec"}, str(h.state), h.store))
        record("status-empty", case(), "status")

        h = case()
        (a, b), _ = selected(h, "a", "b")
        c = h.seed("c")
        (h.state / "generations" / c / "manifest.json").write_text("{}")
        (h.state / "generations" / "notes.txt").write_text("not ours")
        h.store.wipe(out("a"))
        runtime.write_json(h.state / "boot-restore.json", {"boot_id": BOOT_ID, "outcome": "restored", "code": None,
                                                           "generation": b, "finished_at": self.CREATED_AT + 300, "duration_ms": 4210})
        record("status-full", h, "status")

        h = case()
        h.env(create=True)
        record("prepare-ok", h, "prepare", import_store_path=h.offer("p"))
        h = case()
        record("apply-ok", h, "apply", generation=h.seed("a"), expected_selection="none")
        # Re-applying the selected generation after its closure was lost imports it and keeps the token:
        # changed:true beside an unmoved selection. A {"request","response"} pair, because a consumer
        # deriving the request from a bare envelope would read changed:true as a moved token.
        h = case()
        (a,), token = selected(h, "a")
        h.store.wipe(out("a"), DEP)
        request = {"version": 2, "action": "apply", "generation": a, "expected_selection": token}
        cases["apply-reimport-ok"] = runtime.encode({"request": request, "response": h.call(**request)})
        h = case()
        _, token = selected(h, "a", "b")
        record("rollback-ok", h, "rollback", expected_selection=token)
        h = case()
        _, token = selected(h, "a")
        record("clear-ok", h, "clear", expected_selection=token)
        h = case()
        selected(h, "a")
        h.store.wipe(out("a"), DEP)
        record("restore-ok", h, "restore")
        h = case()
        _, token = selected(h, "a")
        record("prune-ok", h, "prune", generation=h.seed("b"))

        record("error-invalid_request", case(), "status", generation="0" * 64)
        record("error-unsupported_version", case(), "status", version=1)
        h = case()
        record("error-stale_selection", h, "apply", generation=h.seed("a"), expected_selection="f" * 32)
        h = case()
        h.seed("a")
        record("error-invalid_generation", h, "apply", generation="c" * 64, expected_selection="none")
        h = case()
        h.env(create=True)
        record("error-unavailable_closure", h, "prepare", import_store_path=out("q"))
        h = case()
        (a,), _ = selected(h, "a")
        h.store.wipe(out("a"), DEP)
        (h.state / "generations" / a / "closure.nar").write_bytes(b"truncated")
        record("error-invalid_archive", h, "restore")
        h = case()
        h.env(create=True)
        output = h.offer("r")
        h.store.no_bin.add(output)
        record("error-prepare_failed", h, "prepare", import_store_path=output)
        h = case()
        selected(h, "a")
        h.store.wipe(out("a"), DEP)
        h.store.import_registers = False
        record("error-restore_failed", h, "restore")
        h = case()
        selected(h, "a")
        (h.state / "current").unlink()
        (h.state / "current").symlink_to("selections/" + "f" * 32)
        record("error-corrupt_state", h, "status")
        h = case()
        selected(h, "a")
        h.store.wipe(out("a"))
        h.store.hooks.append(("--check-validity", runtime.Failure("internal_error", "Nix command failed (exit 1)")))
        record("error-internal_error", h, "restore")
        h = case()
        h.seed("a")
        record("error-no_previous", h, "rollback", expected_selection="none")
        h = case()
        h.env(create=True)
        record("error-insufficient_space", h, "prepare", import_store_path=h.offer("v", nar=runtime.MAX_PATH_NAR + 1))
        record("error-not_ready", case(parent=False), "status")
        h = case()
        selected(h, "a")
        h.store.wipe(out("a"))
        h.store.ghosts.add(out("a"))
        record("error-store_inconsistent", h, "restore")
        h = case()
        h.env(create=True)
        with open(h.state / "lock", "a+b") as held, patch.object(runtime, "STATUS_LOCK_TIMEOUT", 0.05):
            fcntl.flock(held, fcntl.LOCK_EX)
            record("error-timed_out", h, "status")
        h = case()
        real = os.replace
        def replace(src, dst):
            real(src, dst)
            if Path(dst).name == "current":
                raise runtime.Deadline("operation timed out; inspect status before retrying")
        a = h.seed("a")
        with patch.object(runtime.os, "replace", replace):
            record("error-status_unavailable", h, "apply", generation=a, expected_selection="none")
        return cases


if __name__ == "__main__":
    unittest.main()
