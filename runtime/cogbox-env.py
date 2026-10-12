#!/usr/bin/env python3
"""Guest-owned immutable tool generations. Protocol and durability: docs/runtime-environment-poc.md."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

VERSION = 1
INPUT_LIMIT = 65536
OUTPUT_LIMIT = 4 * 1024 * 1024
GEN = re.compile(r"[0-9a-f]{64}\Z")
TOKEN = re.compile(r"[0-9a-f]{32}\Z")
STORE = re.compile(r"/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+\Z")
LOCK_FLAGS = ["--no-update-lock-file", "--no-write-lock-file", "--no-registries"]


class Failure(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Deadline(Failure):
    def __init__(self, message):
        super().__init__("internal_error", message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def validate_request(req):
    if not isinstance(req, dict):
        raise Failure("invalid_request", "request must be an object")
    if type(req.get("version")) is not int or req["version"] != VERSION:
        raise Failure("unsupported_version", "version must be 1")
    action = req.get("action")
    fields = {"status": set(), "prepare": {"flake", "attribute", "import_store_path"},
              "apply": {"generation", "expected_selection"}, "rollback": {"expected_selection"},
              "restore": {"generation"}}
    if not isinstance(action, str) or action not in fields or set(req) - fields[action] - {"version", "action"}:
        raise Failure("invalid_request", "unknown action or unexpected field")
    if any(not isinstance(v, str) or not v or len(v) > 8192 or "\0" in v for k, v in req.items() if k != "version"):
        raise Failure("invalid_request", "fields must be nonempty bounded strings")
    if action == "prepare":
        supplied = set(req) - {"version", "action"}
        if supplied not in ({"flake", "attribute"}, {"import_store_path"}):
            raise Failure("invalid_request", "prepare requires flake and attribute, or import_store_path")
        if "import_store_path" in req and (not STORE.fullmatch(req["import_store_path"]) or req["import_store_path"].endswith(".drv")):
            raise Failure("invalid_request", "import requires a canonical store output")
        if "flake" in req and (req["flake"].startswith("-") or "#" in req["flake"] or not re.fullmatch(r"[A-Za-z0-9_.-]+", req["attribute"])):
            raise Failure("invalid_request", "invalid flake reference or package attribute")
    if action == "apply" and "generation" not in req:
        raise Failure("invalid_request", "apply requires generation")
    if "generation" in req and not GEN.fullmatch(req["generation"]):
        raise Failure("invalid_request", "invalid generation")
    if action in ("apply", "rollback"):
        token = req.get("expected_selection", "")
        if token != "none" and not TOKEN.fullmatch(token):
            raise Failure("invalid_request", "expected_selection must be none or a selection token")
    return req


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable_mkdir(path):
    """Commit each newly created directory entry, including a new work subtree."""
    missing = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            if not directory.is_dir():
                raise
    # A concurrent/interrupted creator may have made an existing ancestor
    # visible without syncing its entry. Commit that boundary as well.
    cursor = path
    while True:
        sync_dir(cursor)
        if cursor.parent == cursor:
            break
        cursor = cursor.parent


def write_json(path, value):
    with open(path, "xb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def read_json_file(path, limit=OUTPUT_LIMIT):
    with open(path, "rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("oversized state file")
    return strict_json(raw)


def file_digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class Commands:
    """Bound stdout, retain only a bounded diagnostic tail, and kill the process group on timeout."""
    def __init__(self, timeout):
        self.deadline = time.monotonic() + timeout

    def run(self, args, *, stdin=None, stdout=None):
        proc = subprocess.Popen(args, stdin=stdin or subprocess.DEVNULL, stdout=stdout or subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        out, err = bytearray(), bytearray()
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(proc.stderr, selectors.EVENT_READ, "err")
                if stdout is None:
                    sel.register(proc.stdout, selectors.EVENT_READ, "out")
                while sel.get_map():
                    remaining = self.deadline - time.monotonic()
                    if remaining <= 0:
                        raise Deadline("Nix operation timed out")
                    for key, _ in sel.select(min(remaining, 0.2)):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            sel.unregister(key.fileobj)
                        elif key.data == "err":
                            err.extend(chunk)
                            del err[:-65536]
                        else:
                            out.extend(chunk)
                            if len(out) > OUTPUT_LIMIT:
                                raise Failure("internal_error", "Nix output exceeds limit")
            proc.wait(timeout=max(0.01, self.deadline - time.monotonic()))
            if err:
                sys.stderr.buffer.write(err)
                sys.stderr.buffer.flush()
            if proc.returncode:
                raise Failure("internal_error", "Nix command failed (exit %s)" % proc.returncode)
            return bytes(out)
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            proc.stderr.close()
            if proc.stdout:
                proc.stdout.close()

    def json(self, args):
        return strict_json(self.run(args))

    def available(self, paths, verify=False):
        if not paths or any(not Path(p).exists() for p in paths):
            return False
        try:
            self.run(["nix-store", "--check-validity", *paths])
            if verify:
                self.run(["nix-store", "--verify-path", *paths])
            return True
        except Deadline:
            raise
        except Failure:
            return False

    def root(self, output, link):
        # Only a verified existing output, never a derivation; substitution is disabled.
        self.run(["nix-store", "--realise", output, "--add-root", str(link), "--indirect",
                  "--option", "substitute", "false", "--option", "substituters", ""])
        sync_dir(link.parent)


class Environment:
    def __init__(self, directory, commands):
        if not os.path.isabs(directory):
            raise Failure("invalid_request", "state-dir must be absolute")
        # /root/work is intentionally a durable symlink in guests. Resolve it once;
        # records use relative pointers, so moving a retained work volume is supported.
        self.path = Path(directory).resolve()
        durable_mkdir(self.path)
        os.chmod(self.path, 0o700)
        for name in ("generations", "selections", "roots"):
            durable_mkdir(self.path / name)
        self.commands = commands

    @contextlib.contextmanager
    def locked(self):
        with open(self.path / "lock", "a+b") as lock:
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= self.commands.deadline:
                        raise Deadline("state lock timed out")
                    time.sleep(0.05)
            yield

    def manifest(self, generation):
        if not GEN.fullmatch(generation):
            raise Failure("corrupt_state", "invalid generation in state")
        try:
            m = read_json_file(self.path / "generations" / generation / "manifest.json")
            if not isinstance(m, dict) or set(m) != {"manifest_sha256", "identity", "closure", "source_archive", "archive_sha256", "archive_bytes"}:
                raise ValueError("invalid manifest object")
            checksum = m.pop("manifest_sha256")
            if digest(m) != checksum:
                raise ValueError("manifest checksum mismatch")
            identity = m["identity"]
            if not isinstance(identity, dict) or set(identity) != {"version", "output", "derivation", "system", "provenance"}:
                raise ValueError("invalid identity object")
            if digest(identity) != generation or type(identity["version"]) is not int or identity["version"] != VERSION:
                raise ValueError("identity mismatch")
            if not isinstance(identity["output"], str) or not STORE.fullmatch(identity["output"]) or identity["output"].endswith(".drv"):
                raise ValueError("invalid output")
            drv = identity["derivation"]
            if drv is not None and (not isinstance(drv, str) or not STORE.fullmatch(drv) or not drv.endswith(".drv")):
                raise ValueError("invalid derivation")
            if not isinstance(identity["system"], str) or not re.fullmatch(r"[a-z0-9_]+-[a-z0-9_]+", identity["system"]):
                raise ValueError("invalid system")
            provenance = identity["provenance"]
            if not isinstance(provenance, dict) or set(provenance) != {"kind", "source", "attribute", "inputs_digest"}:
                raise ValueError("invalid provenance object")
            if provenance["kind"] == "import":
                if any(provenance[k] is not None for k in ("source", "attribute", "inputs_digest")) or m["source_archive"] is not None:
                    raise ValueError("invalid import provenance")
            elif provenance["kind"] == "flake":
                if not STORE.fullmatch(provenance["source"]) or not re.fullmatch(r"[A-Za-z0-9_.-]+", provenance["attribute"]) or not GEN.fullmatch(provenance["inputs_digest"]):
                    raise ValueError("invalid flake provenance")
                if not isinstance(m["source_archive"], dict) or digest(m["source_archive"]) != provenance["inputs_digest"] or m["source_archive"].get("path") != provenance["source"]:
                    raise ValueError("source archive identity mismatch")
            else:
                raise ValueError("invalid provenance kind")
            closure = m["closure"]
            if not isinstance(closure, list) or not closure or identity["output"] not in closure or any(not isinstance(p, str) or not STORE.fullmatch(p) for p in closure):
                raise ValueError("invalid closure")
            if not GEN.fullmatch(m["archive_sha256"]) or type(m["archive_bytes"]) is not int or m["archive_bytes"] < 1:
                raise ValueError("invalid archive metadata")
            return m
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise Failure("corrupt_state", "missing or corrupt generation manifest") from exc

    def selected(self):
        pointer = self.path / "current"
        if not pointer.is_symlink():
            if pointer.exists():
                raise Failure("corrupt_state", "current is not a symlink")
            return None, None
        target = os.readlink(pointer)
        if not re.fullmatch(r"selections/[0-9a-f]{32}", target):
            raise Failure("corrupt_state", "invalid current pointer")
        try:
            record = read_json_file(self.path / target / "selection.json", INPUT_LIMIT)
            if not isinstance(record, dict) or set(record) != {"generation", "previous"} or not GEN.fullmatch(record["generation"]) or (record["previous"] is not None and not GEN.fullmatch(record["previous"])):
                raise ValueError("invalid selection record")
            m = self.manifest(record["generation"])
            if os.readlink(self.path / target / "bin") != m["identity"]["output"] + "/bin":
                raise ValueError("selection bin mismatch")
            if record["previous"]:
                self.manifest(record["previous"])
            return target.split("/")[1], record
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise Failure("corrupt_state", "missing or corrupt selection") from exc

    def status(self):
        token, record = self.selected()
        generations = []
        for directory in sorted((self.path / "generations").iterdir()):
            if directory.name.startswith("."):
                continue
            m = self.manifest(directory.name)
            ident = m["identity"]
            archive = directory / "closure.nar"
            generations.append({"id": directory.name, **{k: ident[k] for k in ("output", "derivation", "system", "provenance")},
                                "closure_available": self.commands.available(m["closure"]),
                                "archive_present": archive.is_file(), "archive_valid": None,
                                "archive_bytes": archive.stat().st_size if archive.is_file() else 0})
        selected = record["generation"] if record else None
        current = next((g for g in generations if g["id"] == selected), None)
        system = os.path.realpath("/run/current-system") if os.path.exists("/run/current-system") else None
        try:
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError:
            boot_id = None
        return {"selection": token, "selected_generation": selected,
                "active_generation": selected if current and current["closure_available"] else None,
                "previous_generation": record["previous"] if record else None,
                "output": current["output"] if current else None, "generations": generations,
                "guest_system": system, "boot_id": boot_id}

    def prepare(self, req):
        staging = Path(tempfile.mkdtemp(prefix=".prepare-", dir=self.path / "generations"))
        protection = self.path / "roots" / (".preparing-" + uuid.uuid4().hex)
        try:
            metadata = None
            if "import_store_path" in req:
                output = req["import_store_path"]
                if not self.commands.available([output]):
                    raise Failure("unavailable_closure", "imported output is not locally available")
                self.commands.root(output, protection)
                drv = self.commands.run(["nix-store", "--query", "--deriver", output]).decode().strip()
                drv = drv if STORE.fullmatch(drv) and drv.endswith(".drv") else None
                system = self.commands.run(["nix", "eval", "--impure", "--raw", "--expr", "builtins.currentSystem"]).decode()
                provenance = {"kind": "import", "source": None, "attribute": None, "inputs_digest": None}
            else:
                metadata = self.commands.json(["nix", "flake", "archive", "--json", *LOCK_FLAGS, req["flake"]])
                source = metadata["path"]
                if not STORE.fullmatch(source):
                    raise Failure("prepare_failed", "flake archive did not produce an immutable snapshot")
                # Evaluate/build the archived source, never the original mutable checkout.
                result = self.commands.json(["nix", "build", "--json", *LOCK_FLAGS, "--out-link", str(protection),
                                             "path:" + source + "#" + req["attribute"]])
                if len(result) != 1 or set(result[0]["outputs"]) != {"out"}:
                    raise Failure("prepare_failed", "bundle must produce exactly one out output")
                output, drv = result[0]["outputs"]["out"], result[0]["drvPath"]
                system = self.commands.run(["nix-store", "--query", "--binding", "system", drv]).decode().strip()
                provenance = {"kind": "flake", "source": source, "attribute": req["attribute"], "inputs_digest": digest(metadata)}
            if not (Path(output) / "bin").is_dir():
                raise Failure("prepare_failed", "bundle must contain a bin directory")
            closure = sorted(set(self.commands.run(["nix-store", "--query", "--requisites", output]).decode().splitlines()))
            if not self.commands.available(closure, verify=True):
                raise Failure("unavailable_closure", "complete bundle closure is unavailable")
            identity = {"version": VERSION, "output": output, "derivation": drv, "system": system, "provenance": provenance}
            generation = digest(identity)
            destination = self.path / "generations" / generation
            if destination.exists():
                old = self.manifest(generation)
                if old["identity"] != identity:
                    raise Failure("corrupt_state", "generation identity mismatch")
                retained = destination / "closure.nar"
                if not retained.is_file() or retained.stat().st_size != old["archive_bytes"] or file_digest(retained) != old["archive_sha256"]:
                    raise Failure("invalid_archive", "existing generation has a missing or corrupt retained archive")
                self.commands.root(output, self.path / "roots" / generation)
                return generation, False
            self.commands.root(output, self.path / "roots" / generation)
            os.symlink(output, staging / "root")
            archive = staging / "closure.nar"
            with open(archive, "xb") as stream:
                self.commands.run(["nix-store", "--export", *closure], stdout=stream)
                stream.flush()
                os.fsync(stream.fileno())
            manifest = {"identity": identity, "closure": closure, "source_archive": metadata,
                        "archive_sha256": file_digest(archive), "archive_bytes": archive.stat().st_size}
            manifest["manifest_sha256"] = digest(manifest)
            write_json(staging / "manifest.json", manifest)
            sync_dir(staging)
            os.rename(staging, destination)
            sync_dir(destination.parent)
            return generation, True
        except Failure as exc:
            if exc.code in ("unavailable_closure", "corrupt_state", "invalid_archive"):
                raise
            raise Failure("prepare_failed", str(exc)) from exc
        finally:
            protection.unlink(missing_ok=True)
            if staging.exists():
                shutil.rmtree(staging)

    def select(self, req, rollback=False):
        token, record = self.selected()
        if (token or "none") != req["expected_selection"]:
            raise Failure("stale_selection", "selection changed; inspect status before retrying")
        generation = req.get("generation")
        if rollback:
            if not record or not record["previous"]:
                raise Failure("no_previous", "no previous generation")
            generation = record["previous"]
        if not (self.path / "generations" / generation).is_dir():
            raise Failure("invalid_generation", "generation is not prepared")
        m = self.manifest(generation)
        if not self.commands.available(m["closure"], verify=True):
            raise Failure("unavailable_closure", "restore the exact closure before selecting")
        self.commands.root(m["identity"]["output"], self.path / "roots" / generation)
        if record and record["generation"] == generation:
            return False
        selection = uuid.uuid4().hex
        directory = self.path / "selections" / selection
        directory.mkdir(mode=0o700)
        write_json(directory / "selection.json", {"generation": generation, "previous": record["generation"] if record else None})
        os.symlink(m["identity"]["output"] + "/bin", directory / "bin")
        sync_dir(directory)
        sync_dir(directory.parent)
        temporary = self.path / (".current-" + selection)
        os.symlink("selections/" + selection, temporary)
        os.replace(temporary, self.path / "current")
        sync_dir(self.path)
        return True

    def restore(self, req):
        _, record = self.selected()
        wanted = [req["generation"]] if "generation" in req else ([record["generation"], record["previous"]] if record else [])
        changed = False
        for generation in dict.fromkeys(g for g in wanted if g):
            if not (self.path / "generations" / generation).is_dir():
                raise Failure("invalid_generation", "generation is not prepared")
            m = self.manifest(generation)
            archive = self.path / "generations" / generation / "closure.nar"
            if not archive.is_file() or archive.stat().st_size != m["archive_bytes"] or file_digest(archive) != m["archive_sha256"]:
                raise Failure("invalid_archive", "missing or corrupt retained closure archive")
            try:
                if not self.commands.available(m["closure"], verify=True):
                    with open(archive, "rb") as stream:
                        self.commands.run(["nix-store", "--import", "--option", "substitute", "false", "--option", "substituters", ""], stdin=stream)
                    changed = True
                if not self.commands.available(m["closure"], verify=True):
                    raise Failure("restore_failed", "import did not restore the exact complete closure")
                root = self.path / "roots" / generation
                # Re-register even if a stale symlink survived a store DB reset.
                self.commands.root(m["identity"]["output"], root)
                changed = True
            except Failure as exc:
                raise Failure("restore_failed", str(exc)) from exc
        return changed

    def perform(self, req):
        action = req["action"]
        changed, generation = False, None
        if action == "prepare":
            generation, changed = self.prepare(req)
        elif action in ("apply", "rollback"):
            changed = self.select(req, action == "rollback")
        elif action == "restore":
            changed = self.restore(req)
        return changed, generation


def envelope(action=None, *, ok=False, changed=False, generation=None, status=None, error=None):
    return {"version": VERSION, "ok": ok, "action": action, "changed": changed,
            "generation": generation, "status": status, "error": error}


def dispatch(req, directory, commands):
    action = req.get("action") if isinstance(req, dict) and req.get("action") in ("status", "prepare", "apply", "rollback", "restore") else None
    env = None
    try:
        validate_request(req)
        env = Environment(directory, commands)
        with env.locked():
            try:
                # Validate every retained record before any selection commit, so
                # unrelated pre-existing corruption cannot first surface afterward.
                before = env.status()
                if len(canonical(envelope(action, ok=True, status=before))) + 128 > OUTPUT_LIMIT:
                    raise Failure("internal_error", "retained state exceeds response limit")
                changed, generation = env.perform(req)
                return envelope(action, ok=True, changed=changed, generation=generation,
                                status=before if action == "status" else env.status())
            except Failure as exc:
                try:
                    status = env.status()
                except (Failure, OSError, ValueError, TypeError):
                    status = None
                return envelope(action, status=status, error={"code": exc.code, "message": str(exc)})
    except (Failure, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        return envelope(action, error={"code": exc.code if isinstance(exc, Failure) else "internal_error", "message": str(exc)})


def read_request(timeout):
    data = bytearray()
    deadline = time.monotonic() + timeout
    with selectors.SelectSelector() as sel:
        sel.register(sys.stdin.buffer, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not sel.select(remaining):
                raise Failure("invalid_request", "request read timed out")
            chunk = os.read(sys.stdin.fileno(), min(65536, INPUT_LIMIT + 1 - len(data)))
            if not chunk:
                return strict_json(data)
            data.extend(chunk)
            if len(data) > INPUT_LIMIT:
                raise Failure("invalid_request", "request exceeds 64 KiB")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["rpc", "status", "prepare", "apply", "rollback", "restore", "exec"])
    parser.add_argument("--state-dir", default="/root/work/.cogbox/runtime")
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--json", action="store_true", help="emit the protocol envelope (also the default)")
    parser.add_argument("--flake")
    parser.add_argument("--attribute")
    parser.add_argument("--import-store-path")
    parser.add_argument("--generation")
    parser.add_argument("--expected-selection")
    # A separator keeps exec arguments out of this parser.
    argv = sys.argv[1:]
    command = []
    if "--" in argv:
        i = argv.index("--")
        argv, command = argv[:i], argv[i + 1:]
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 86400:
        parser.error("timeout must be finite and between 0 and 86400 seconds")
    if args.action == "exec":
        if not command or not os.path.isabs(args.state_dir):
            parser.error("exec requires an absolute state-dir and -- COMMAND")
        os.environ["PATH"] = str(Path(args.state_dir).resolve() / "current" / "bin") + os.pathsep + os.environ.get("PATH", "")
        os.execvp(command[0], command)
    def timed_out(_signum, _frame):
        raise Deadline("operation timed out; inspect status before retrying")
    signal.signal(signal.SIGALRM, timed_out)
    signal.setitimer(signal.ITIMER_REAL, args.timeout)
    try:
        if command:
            raise Failure("invalid_request", "unexpected command arguments")
        if args.action == "rpc":
            req = read_request(args.timeout)
        else:
            req = {"version": VERSION, "action": args.action}
            req.update({k: getattr(args, k) for k in ("flake", "attribute", "import_store_path", "generation", "expected_selection") if getattr(args, k) is not None})
        result = dispatch(req, args.state_dir, Commands(args.timeout))
    except (ValueError, UnicodeError, Failure) as exc:
        result = envelope(error={"code": exc.code if isinstance(exc, Failure) else "invalid_request", "message": str(exc)})
    signal.setitimer(signal.ITIMER_REAL, 0)
    encoded = canonical(result) + b"\n"
    if len(encoded) > OUTPUT_LIMIT:
        result = envelope(result["action"], error={"code": "internal_error", "message": "response exceeds 4 MiB; selection outcome requires inspection"})
        encoded = canonical(result) + b"\n"
    sys.stdout.buffer.write(encoded)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
