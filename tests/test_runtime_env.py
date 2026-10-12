"""State-machine failure tests; the separate real-Nix test covers building and execution."""
import importlib.util
import json
import multiprocessing
from pathlib import Path
import os
import sys
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

helper = sys.argv.pop(1) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else str(Path(__file__).parent.parent / "runtime/cogbox-env.py")
spec = importlib.util.spec_from_file_location("runtime", helper)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class Store:
    def json(self, args):
        return runtime.strict_json(self.run(args))

    def __init__(self):
        self.deadline = time.monotonic() + 30
        self.paths = set()
        self.imports = 0
        self.import_paths = []
        self.calls = []

    def available(self, paths, verify=False):
        self.calls.append(("available", tuple(paths)))
        return set(paths) <= self.paths

    def root(self, output, link):
        self.calls.append(("root", output))
        link.unlink(missing_ok=True)
        link.symlink_to(output)

    def run(self, args, **kwargs):
        self.calls.append(tuple(args))
        if "--import" in args:
            self.imports += 1
            self.paths.update(self.import_paths)
            return b""
        raise runtime.Failure("internal_error", "injected export/build failure")


def overlap(directory, generation, output, ready, go, result):
    store = Store()
    store.paths.add(output)
    ready.put(True)
    go.wait(10)
    result.put(runtime.dispatch({"version": 1, "action": "apply", "generation": generation, "expected_selection": "none"}, directory, store))


class RuntimeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store()
        self.env = runtime.Environment(self.tmp.name, self.store)
        self.a = self.seed("a")
        self.b = self.seed("b")

    def tearDown(self):
        self.tmp.cleanup()

    def seed(self, name):
        output = "/nix/store/" + name * 32 + "-bundle"
        identity = {"version": 1, "output": output, "derivation": None, "system": "x86_64-linux",
                    "provenance": {"kind": "import", "source": None, "attribute": None, "inputs_digest": None}}
        generation = runtime.digest(identity)
        directory = self.env.path / "generations" / generation
        directory.mkdir()
        archive = directory / "closure.nar"
        archive.write_bytes(b"retained exact archive")
        manifest = {"identity": identity, "closure": [output], "source_archive": None,
                    "archive_sha256": runtime.file_digest(archive), "archive_bytes": archive.stat().st_size}
        manifest["manifest_sha256"] = runtime.digest(manifest)
        runtime.write_json(directory / "manifest.json", manifest)
        self.store.paths.add(output)
        return generation

    def call(self, action, **fields):
        return runtime.dispatch({"version": 1, "action": action, **fields}, self.tmp.name, self.store)

    def select(self, generation, token="none"):
        result = self.call("apply", generation=generation, expected_selection=token)
        self.assertTrue(result["ok"], result)
        return result["status"]["selection"]

    def test_cas_aba_and_noop_preserve_previous(self):
        first = self.select(self.a)
        second = self.select(self.b, first)
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

    def test_missing_closure_is_selected_but_not_active_and_explicit_restore(self):
        token = self.select(self.a)
        output = self.env.manifest(self.a)["identity"]["output"]
        self.store.paths.remove(output)
        status = self.call("status")["status"]
        self.assertEqual(status["selected_generation"], self.a)
        self.assertIsNone(status["active_generation"])
        failed = self.call("apply", generation=self.a, expected_selection=token)
        self.assertEqual(failed["error"]["code"], "unavailable_closure")
        self.store.import_paths = [output]
        restored = self.call("restore")
        self.assertTrue(restored["ok"], restored)
        self.assertEqual(restored["status"]["selection"], token)
        self.assertEqual(restored["status"]["active_generation"], self.a)
        self.assertEqual(self.store.imports, 1)
        for call in self.store.calls:
            self.assertNotIn("build", call)
            self.assertNotIn("eval", call)

    def test_targeted_restore_does_not_make_another_selection_active(self):
        self.select(self.a)
        self.store.paths.clear()
        self.store.import_paths = [self.env.manifest(self.b)["identity"]["output"]]
        result = self.call("restore", generation=self.b)
        self.assertTrue(result["ok"])
        self.assertIsNone(result["status"]["active_generation"])
        self.assertEqual(result["status"]["selected_generation"], self.a)

    def test_corrupt_and_missing_archive_leave_pointer_unchanged(self):
        token = self.select(self.a)
        self.store.paths.clear()
        archive = self.env.path / "generations" / self.a / "closure.nar"
        for missing in (False, True):
            if missing:
                archive.unlink()
            else:
                archive.write_bytes(b"invalid archive")
            result = self.call("restore")
            self.assertEqual(result["error"]["code"], "invalid_archive")
            self.assertEqual(result["status"]["selection"], token)
            self.assertIsNone(result["status"]["active_generation"])
            self.assertEqual(self.store.imports, 0)

    def test_manifest_corruption_fails_closed(self):
        self.select(self.a)
        path = self.env.path / "generations" / self.a / "manifest.json"
        m = json.loads(path.read_text())
        m["closure"] = []
        path.write_text(json.dumps(m))
        result = self.call("status")
        self.assertFalse(result["ok"])
        self.assertIsNone(result["status"])
        self.assertEqual(result["error"]["code"], "corrupt_state")

    def test_rpc_rejects_malformed_state_objects_with_error_envelopes(self):
        path = self.env.path / "generations" / self.a / "manifest.json"
        original = json.loads(path.read_text())
        candidates = [None, 1, "bad", [], {}, {"identity": None}, {**original, "identity": None}]
        missing_provenance = dict(original)
        missing_provenance["identity"] = {k: v for k, v in original["identity"].items() if k != "provenance"}
        candidates.append(missing_provenance)
        for value in candidates:
            path.write_text(json.dumps(value))
            proc = subprocess.run([sys.executable, helper, "rpc", "--state-dir", self.tmp.name],
                                  input='{"version":1,"action":"status"}', capture_output=True, text=True, timeout=5)
            with self.subTest(value=value):
                self.assertEqual(proc.returncode, 1, proc.stderr)
                reply = json.loads(proc.stdout)
                self.assertEqual(reply["error"]["code"], "corrupt_state")
                self.assertIsNone(reply["status"])

    def test_uncommitted_selection_is_ignored_and_broken_pointer_errors(self):
        token = self.select(self.a)
        (self.env.path / "selections" / ("f" * 32)).mkdir()
        self.assertEqual(self.call("status")["status"]["selection"], token)
        (self.env.path / "current").unlink()
        (self.env.path / "current").symlink_to("selections/" + "f" * 32)
        self.assertEqual(self.call("status")["error"]["code"], "corrupt_state")

    def test_concurrent_cas_writers_only_one_commits(self):
        ctx = multiprocessing.get_context("fork")
        ready, result = ctx.Queue(), ctx.Queue()
        go = ctx.Event()
        workers = [ctx.Process(target=overlap, args=(self.tmp.name, g, self.env.manifest(g)["identity"]["output"], ready, go, result)) for g in (self.a, self.b)]
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

    def test_prepare_build_and_export_failure_never_select_or_publish(self):
        token = self.select(self.a)
        before = set((self.env.path / "generations").iterdir())
        failed = self.call("prepare", flake="path:/tmp/fixture", attribute="packages.x86_64-linux.default")
        self.assertFalse(failed["ok"])
        self.assertEqual(self.call("status")["status"]["selection"], token)
        self.assertEqual(set((self.env.path / "generations").iterdir()), before)
        output = "/nix/store/" + "c" * 32 + "-bundle"
        self.store.paths.add(output)
        old_run = self.store.run
        def run(args, **kwargs):
            if "--deriver" in args:
                return b"unknown-deriver\n"
            if "eval" in args:
                return b"x86_64-linux"
            if "--requisites" in args:
                return (output + "\n").encode()
            return old_run(args, **kwargs)
        old_is_dir = Path.is_dir
        with patch.object(self.store, "run", run), patch.object(Path, "is_dir", lambda p: True if str(p) == output + "/bin" else old_is_dir(p)):
            failed = self.call("prepare", import_store_path=output)
        self.assertEqual(failed["error"]["code"], "prepare_failed")
        self.assertEqual(self.call("status")["status"]["selection"], token)
        self.assertEqual(set((self.env.path / "generations").iterdir()), before)

    def test_reprepare_rejects_missing_or_corrupt_retained_archive(self):
        output = self.env.manifest(self.a)["identity"]["output"]
        token = self.select(self.a)
        old_run = self.store.run
        def run(args, **kwargs):
            if "--deriver" in args:
                return b"unknown-deriver\n"
            if "eval" in args:
                return b"x86_64-linux"
            if "--requisites" in args:
                return (output + "\n").encode()
            return old_run(args, **kwargs)
        archive = self.env.path / "generations" / self.a / "closure.nar"
        old_is_dir = Path.is_dir
        with patch.object(self.store, "run", run), patch.object(Path, "is_dir", lambda p: True if str(p) == output + "/bin" else old_is_dir(p)):
            for missing in (False, True):
                if missing:
                    archive.unlink()
                else:
                    archive.write_bytes(b"invalid")
                result = self.call("prepare", import_store_path=output)
                self.assertEqual(result["error"]["code"], "invalid_archive")
                self.assertEqual(self.env.selected()[0], token)

    def test_unrelated_corruption_fails_before_selection_commit(self):
        token = self.select(self.a)
        extra = self.seed("c")
        (self.env.path / "generations" / extra / "manifest.json").write_text("null")
        result = self.call("apply", generation=self.b, expected_selection=token)
        self.assertEqual(result["error"]["code"], "corrupt_state")
        self.assertEqual(self.env.selected()[0], token)
        self.assertEqual(self.env.selected()[1]["generation"], self.a)

    def test_durable_creation_syncs_each_new_parent_entry(self):
        directory = self.env.path / "new-work" / ".cogbox" / "runtime"
        synced = []
        original = runtime.sync_dir
        with patch.object(runtime, "sync_dir", lambda path: (synced.append(path), original(path))[-1]):
            runtime.Environment(str(directory), self.store)
        for path in (directory, directory.parent, directory.parent.parent,
                     directory / "generations", directory / "selections", directory / "roots"):
            self.assertIn(path, synced)
            self.assertIn(path.parent, synced)

    def test_interrupted_directory_creation_is_synced_on_retry(self):
        directory = self.env.path / "new-work" / ".cogbox" / "runtime"
        # Simulate the creator dying after mkdir but before its first fsync.
        with patch.object(runtime, "sync_dir", side_effect=OSError("interrupted creator")):
            with self.assertRaises(OSError):
                runtime.durable_mkdir(directory)
        self.assertTrue((self.env.path / "new-work").exists())
        synced = []
        original = runtime.sync_dir
        with patch.object(runtime, "sync_dir", lambda path: (synced.append(path), original(path))[-1]):
            runtime.Environment(str(directory), self.store)
        cursor = directory
        while True:
            self.assertIn(cursor, synced)
            if cursor.parent == cursor:
                break
            cursor = cursor.parent

    def test_rpc_rejects_oversized_and_trailing_requests(self):
        for request in ('{"version":1,"action":"status"} {}', 'x' * (runtime.INPUT_LIMIT + 1),
                        '{"version":1,"version":1,"action":"status"}'):
            proc = subprocess.run([sys.executable, helper, "rpc", "--state-dir", self.tmp.name],
                                  input=request, capture_output=True, text=True, timeout=5)
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(json.loads(proc.stdout)["error"]["code"], "invalid_request")

    def test_availability_timeout_is_not_missing_closure_success(self):
        commands = runtime.Commands(1)
        with patch.object(Path, "exists", return_value=True), patch.object(commands, "run", side_effect=runtime.Deadline("timed out")):
            with self.assertRaises(runtime.Deadline):
                commands.available(["/nix/store/" + "a" * 32 + "-bundle"])

    def test_reject_invalid_protocol(self):
        requests = [None, {}, {"version": True, "action": "status"}, {"version": 2, "action": "status"},
                    {"version": 1, "action": "exec"}, {"version": 1, "action": "status", "generation": self.a},
                    {"version": 1, "action": "apply", "generation": self.a},
                    {"version": 1, "action": "apply", "generation": "../bad", "expected_selection": "none"},
                    {"version": 1, "action": "prepare", "flake": "x", "attribute": "x", "import_store_path": "x"}]
        for req in requests:
            with self.subTest(req=req):
                self.assertFalse(runtime.dispatch(req, self.tmp.name, self.store)["ok"])
        for raw in ('{} {}', '{"version":1,"version":1}', '{"a":NaN}'):
            with self.assertRaises(ValueError):
                runtime.strict_json(raw)


if __name__ == "__main__":
    unittest.main()
