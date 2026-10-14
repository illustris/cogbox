#!/usr/bin/env python3
"""Guest-owned immutable tool generations. Protocol and durability: docs/runtime-environment.md."""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid

# Guest image pins are write-once, so the wire protocol and the on-disk state
# format are frozen per image and versioned separately. STATE_FORMAT is the
# generation identity version; keeping it at 1 keeps POC generation ids valid.
PROTOCOL_VERSION = 2
STATE_FORMAT = 1
HELPER_VERSION = "0.2.0"
ACTIONS = ("apply", "capabilities", "clear", "prepare", "prune", "restore", "rollback", "status")
INPUT_LIMIT = 65536
OUTPUT_LIMIT = 4 * 1024 * 1024
MIB = 1024 * 1024
GIB = 1024 * MIB
# Retention limits, also frozen per image. nix-store --import buffers each NAR
# in memory, hence the per-path cap.
MAX_GENERATIONS = 4
MAX_PATH_NAR = GIB
PATH_OVERHEAD = 4096
RESTORE_HEADROOM = 512 * MIB
STATUS_LOCK_TIMEOUT = 15
GEN = re.compile(r"[0-9a-f]{64}\Z")
TOKEN = re.compile(r"[0-9a-f]{32}\Z")
STORE = re.compile(r"/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]+\Z")
USERINFO = re.compile(r"://[^/@]*@")
SYSTEM = re.compile(r"[a-z0-9_]+-[a-z0-9_]+\Z")
# --no-use-registries is the setting's own flag; --no-registries is its
# deprecated alias and warns on every call (both since at least Nix 2.13).
LOCK_FLAGS = ["--no-update-lock-file", "--no-write-lock-file", "--no-use-registries"]
# The root lock entries prepare repeats to `nix build` as overrides (see
# Environment.store_overrides): `path` entries naming a "source" store path.
LOCKED_PATH_ATTRS = frozenset({"type", "path", "narHash", "lastModified", "rev", "revCount"})
SOURCE_PATH = re.compile(r"/nix/store/[0-9a-df-np-sv-z]{32}-source\Z")
SRI_SHA256 = re.compile(r"sha256-[A-Za-z0-9+/]{43}=\Z")
INPUT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")
NIX_BASE32 = "0123456789abcdfghijklmnpqrsvwxyz"
SUBDIRS = ("generations", "selections", "roots")
# What an archive repair writes beside a published generation before renaming.
REPAIR_FILES = ("closure.nar.new", "manifest.json.new")
BOOT_FIELDS = {"boot_id", "outcome", "code", "generation", "finished_at", "duration_ms"}
LOCK_BUSY = "another cogbox-env operation holds the state lock (prepare or boot restore in progress)"
NOT_READY = "the work directory is not ready yet; retry once the sandbox has finished starting"
UNCOMMITTED = object()
FIELDS = {"capabilities": (set(), set()), "status": (set(), set()),
          "prepare": (set(), {"flake", "attribute", "import_store_path"}),
          "apply": ({"generation", "expected_selection"}, set()),
          "rollback": ({"expected_selection"}, set()), "clear": ({"expected_selection"}, set()),
          "restore": (set(), {"generation"}), "prune": (set(), {"generation"})}


class Failure(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Deadline(Failure):
    def __init__(self, message):
        super().__init__("timed_out", message)


def archive_budget(fs_bytes):
    return min(8 * GIB, fs_bytes // 4)


def reserve_bytes(fs_bytes):
    return max(2 * GIB, fs_bytes // 10)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def encode(result):
    return canonical(result) + b"\n"


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def new_token():
    return uuid.uuid4().hex


def source_store_path(nar_hash):
    """The store path Nix gives a flake source with this SRI sha256 NAR hash.

    It is what `nix flake archive --dry-run` reports for a locked input: a
    content-addressed path named "source" without references.
    """
    fingerprint = "source:sha256:%s:/nix/store:source" % base64.b64decode(nar_hash[len("sha256-"):]).hex()
    folded = bytearray(20)
    for i, byte in enumerate(hashlib.sha256(fingerprint.encode()).digest()):
        folded[i % 20] ^= byte
    number = int.from_bytes(folded, "little")
    return "/nix/store/" + "".join(NIX_BASE32[(number >> 5 * k) & 31] for k in range(31, -1, -1)) + "-source"


def root_input_nodes(lock):
    """Each root input of a parsed flake.lock with the node it names (None for a follows); {} when malformed."""
    try:
        nodes = lock["nodes"]
        return {name: nodes[key] if isinstance(key, str) else None for name, key in nodes[lock["root"]].get("inputs", {}).items()}
    except (TypeError, KeyError, IndexError, AttributeError):
        return {}


def overridable(name, node, archived):
    """Whether `--override-input NAME path:PATH?ATTRS` reproduces this root lock entry exactly.

    Three kinds keep the plain evaluation, because an override would change
    what Nix evaluates: an entry with inputs of its own (an override resolves
    them again from that input's own flake.lock), one without lastModified (Nix
    would add it), and one whose reference or `flake` flag in flake.nix no
    longer matches the lock (an override takes both from flake.nix). This
    checks the first two and the archive's record. A changed reference can keep
    the narHash, and so that record, and a changed flag keeps the whole entry,
    so store_overrides checks the third against the lock Nix computes with the
    override.
    """
    locked = node.get("locked") if isinstance(node, dict) else None
    if not (INPUT_NAME.fullmatch(name) and isinstance(locked, dict) and node.get("inputs", {}) == {}
            and locked.get("type") == "path" and locked.keys() <= LOCKED_PATH_ATTRS and "lastModified" in locked):
        return False
    path, nar_hash = locked.get("path"), locked.get("narHash")
    if not (isinstance(path, str) and SOURCE_PATH.fullmatch(path) and isinstance(nar_hash, str) and SRI_SHA256.fullmatch(nar_hash)):
        return False
    if any(type(locked[k]) is not int or locked[k] < 0 for k in ("lastModified", "revCount") if k in locked):
        return False
    if "rev" in locked and not isinstance(locked["rev"], str):
        return False
    # What the archive (the provenance) recorded: the same narHash, nothing nested.
    return archived == {"inputs": {}, "path": source_store_path(nar_hash)}


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
    version, action = req.get("version"), req.get("action")
    # capabilities is the skew probe, so it answers any client version.
    if type(version) is not int or not (version >= 1 if action == "capabilities" else version == PROTOCOL_VERSION):
        raise Failure("unsupported_version", "version must be 2")
    if not isinstance(action, str) or action not in FIELDS:
        raise Failure("invalid_request", "unknown action")
    required, optional = FIELDS[action]
    supplied = set(req) - {"version", "action"}
    if supplied - required - optional or required - supplied:
        raise Failure("invalid_request", "missing or unexpected field")
    if any(not isinstance(v, str) or not v or len(v) > 8192 or "\0" in v for k, v in req.items() if k != "version"):
        raise Failure("invalid_request", "fields must be nonempty bounded strings")
    if action == "prepare":
        if supplied not in ({"flake", "attribute"}, {"import_store_path"}):
            raise Failure("invalid_request", "prepare requires flake and attribute, or import_store_path")
        if "import_store_path" in req and (not STORE.fullmatch(req["import_store_path"]) or req["import_store_path"].endswith(".drv")):
            raise Failure("invalid_request", "import requires a canonical store output")
        if "flake" in req and (req["flake"].startswith("-") or "#" in req["flake"] or not re.fullmatch(r"[A-Za-z0-9_.-]+", req["attribute"])):
            raise Failure("invalid_request", "invalid flake reference or package attribute")
        if "flake" in req and USERINFO.search(req["flake"]):
            raise Failure("invalid_request", "flake references must not embed credentials")
    if "generation" in req and not GEN.fullmatch(req["generation"]):
        raise Failure("invalid_request", "invalid generation")
    if "expected_selection" in req and req["expected_selection"] != "none" and not TOKEN.fullmatch(req["expected_selection"]):
        raise Failure("invalid_request", "expected_selection must be none or a selection token")
    return req


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable_mkdir(path):
    """Create one directory under an existing parent and commit both entries.

    Syncing even when it already exists also commits an entry an interrupted
    creator made visible without syncing.
    """
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        if not path.is_dir():
            raise
    sync_dir(path)
    sync_dir(path.parent)


def remove_tree(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def write_json(path, value, times=None):
    """Write a new file durably; times=(atime_ns, mtime_ns) sets its timestamps before the sync."""
    with open(path, "xb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        if times is not None:
            os.utime(stream.fileno(), ns=times)
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


def filesystem(path):
    """Size and free bytes of the filesystem holding the state (the pool on hosted guests)."""
    while not path.is_dir():
        path = path.parent
    st = os.statvfs(path)
    return st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize


def guest_identity():
    system = os.path.realpath("/run/current-system") if os.path.exists("/run/current-system") else None
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        boot_id = None
    return system, boot_id


def capabilities():
    return {"helper_version": HELPER_VERSION, "protocol_versions": [PROTOCOL_VERSION],
            "state_formats": [STATE_FORMAT], "actions": sorted(ACTIONS)}


class Commands:
    """Bound stdout, retain only a bounded diagnostic tail, and kill the process group on timeout.

    Every observation of /nix/store goes through this class, so tests can model
    a damaged store without one.
    """
    def __init__(self, timeout):
        self.deadline = time.monotonic() + timeout

    def run(self, args, *, stdin=None, stdout=None):
        if time.monotonic() >= self.deadline:
            raise Deadline("Nix operation timed out")
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
            try:
                proc.wait(timeout=max(0.01, self.deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                # Its pipes closed but it outlived the deadline; finally kills the group.
                raise Deadline("Nix operation timed out") from None
            if err:
                sys.stderr.buffer.write(err)
                sys.stderr.buffer.flush()
            if proc.returncode:
                # Name the step by its leading words, never a path or reference;
                # Nix's own error is already on stderr. `--option NAME VALUE` only
                # sets a Nix setting, and without its values reads as a truncated command.
                step = " ".join(itertools.takewhile(lambda t: t != "--option" and re.fullmatch(r"(--)?[a-z][a-z-]*", t), args[:3]))
                raise Failure("internal_error", "Nix command failed (exit %s)%s" % (proc.returncode, ": " + step if step else ""))
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

    def derivation_system(self, drv):
        """The system a store derivation builds for.

        `nix-store --query --binding system` reads the environment only, which a
        __structuredAttrs derivation (pkgs.buildEnv, even pkgs.hello in current
        nixpkgs) leaves holding just its outputs. `nix derivation show` reports
        the derivation's own system for both kinds. Nix 2.34 wraps the map as
        {"derivations": {"HASH-NAME.drv": ...}, "version": N}; older releases
        (2.31 checked) print the bare map keyed by the full path.
        """
        shown = self.json(["nix", "derivation", "show", drv])
        if isinstance(shown, dict) and isinstance(shown.get("derivations"), dict):
            shown = shown["derivations"]
        if not isinstance(shown, dict) or len(shown) != 1:
            raise Failure("internal_error", "unexpected nix derivation show output")
        (name, value), = shown.items()
        if name not in (drv, os.path.basename(drv)) or not isinstance(value, dict) or not isinstance(value.get("system"), str):
            raise Failure("internal_error", "unexpected nix derivation show output")
        return value["system"]

    def lexists(self, path):
        return os.path.lexists(path)

    def isdir(self, path):
        return os.path.isdir(path)

    def missing(self, paths):
        return [p for p in paths if not self.lexists(p)]

    def invalid(self, paths):
        """Paths the Nix database does not register, whether or not they exist on disk."""
        return set(self.run(["nix-store", "--check-validity", "--print-invalid", *paths]).decode().split())

    def verify(self, paths):
        try:
            self.run(["nix-store", "--verify-path", *paths])
            return True
        except Deadline:
            raise
        except Failure:
            return False

    def available(self, paths, verify=False):
        if not paths or self.missing(paths):
            return False
        try:
            if self.invalid(paths):
                return False
        except Deadline:
            raise
        except Failure:
            return False
        return not verify or self.verify(paths)

    def sizes(self, paths):
        values = self.run(["nix-store", "--query", "--size", *paths]).split()
        if len(values) != len(paths) or not all(v.isdigit() for v in values):
            raise Failure("internal_error", "unexpected nix-store size output")
        return [int(v) for v in values]

    def read_lock(self, source):
        """The archived source's flake.lock, or None when it has none or it does not parse."""
        try:
            return read_json_file(Path(source) / "flake.lock")
        except (OSError, ValueError, RecursionError):
            return None

    def store_free(self):
        st = os.statvfs("/nix/store")
        return st.f_bavail * st.f_frsize

    def root(self, output, link):
        # Only a verified existing output, never a derivation; substitution is disabled.
        self.run(["nix-store", "--realise", output, "--add-root", str(link), "--indirect",
                  "--option", "substitute", "false", "--option", "substituters", ""])
        sync_dir(link.parent)


class Environment:
    def __init__(self, directory, commands, create=False):
        if not os.path.isabs(directory):
            raise Failure("invalid_request", "state-dir must be absolute")
        # /root/work is intentionally a durable symlink in guests. Resolve it once;
        # records use relative pointers, so moving a retained work volume is supported.
        self.path = Path(directory).resolve()
        self.commands = commands
        self.commit_target = UNCOMMITTED
        self.alarm_mask = None
        # The parent (<work>/.cogbox) belongs to brain-materialize and is never
        # created here: before materialization, or over an unmounted nofail pool,
        # it would land on the wrong filesystem. Callers fail not_ready instead.
        self.ready = self.path.parent.is_dir()
        if create and self.ready:
            durable_mkdir(self.path)
            os.chmod(self.path, 0o700)
            for name in SUBDIRS:
                durable_mkdir(self.path / name)
        if os.path.lexists(self.path) and not self.path.is_dir():
            raise Failure("corrupt_state", "state-dir is not a directory")
        # Only prepare creates state. A missing state dir is an empty state.
        self.present = self.path.is_dir()

    @contextlib.contextmanager
    def locked(self, timeout=None):
        self.present = self.path.is_dir()
        if not self.present:
            # Nothing to protect, and nothing (not even the lock file) is created.
            yield
            return
        limit = self.commands.deadline if timeout is None else min(self.commands.deadline, time.monotonic() + timeout)
        with open(self.path / "lock", "a+b") as lock:
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= limit:
                        raise Deadline(LOCK_BUSY)
                    time.sleep(0.05)
            yield

    @contextlib.contextmanager
    def commit(self, target):
        """Defer the async deadline from the selection change through its sync.

        SIGALRM stays blocked for the rest of the request; later work relies on
        the cooperative Commands deadline. committed() then reports truthfully
        whether the pointer moved, whatever fails afterwards.
        """
        if self.alarm_mask is None:
            self.alarm_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
        self.commit_target = target
        yield

    def committed(self):
        if self.commit_target is UNCOMMITTED:
            return False
        try:
            target = os.readlink(self.path / "current")
        except FileNotFoundError:
            target = None
        except OSError:
            return True
        return target == self.commit_target

    def release(self):
        """Discard an alarm deferred by a commit: the request already has its answer."""
        if self.alarm_mask is None:
            return
        signal.setitimer(signal.ITIMER_REAL, 0)
        handler = signal.signal(signal.SIGALRM, signal.SIG_IGN)
        signal.pthread_sigmask(signal.SIG_SETMASK, self.alarm_mask)
        if handler is not None:
            signal.signal(signal.SIGALRM, handler)
        self.alarm_mask = None

    def entries(self, name):
        directory = self.path / name
        if not self.present or not directory.is_dir():
            return []
        return sorted(directory.iterdir())

    def has_generation(self, generation):
        return self.present and (self.path / "generations" / generation).is_dir()

    def archive_size(self, generation):
        archive = self.path / "generations" / generation / "closure.nar"
        return archive.stat().st_size if archive.is_file() else 0

    def created_at(self, generation):
        return int((self.path / "generations" / generation / "manifest.json").stat().st_mtime)

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
            if digest(identity) != generation or type(identity["version"]) is not int or identity["version"] != STATE_FORMAT:
                raise ValueError("identity mismatch")
            if not isinstance(identity["output"], str) or not STORE.fullmatch(identity["output"]) or identity["output"].endswith(".drv"):
                raise ValueError("invalid output")
            drv = identity["derivation"]
            if drv is not None and (not isinstance(drv, str) or not STORE.fullmatch(drv) or not drv.endswith(".drv")):
                raise ValueError("invalid derivation")
            if not isinstance(identity["system"], str) or not SYSTEM.fullmatch(identity["system"]):
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
        # RecursionError: JSON nested deeper than the decoder's stack allows.
        except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
            raise Failure("corrupt_state", "missing or corrupt generation manifest") from exc

    def valid_manifest(self, generation):
        try:
            return self.manifest(generation)
        except Failure:
            return None

    def scan(self):
        """Valid manifests by id, corrupt generation ids, and the count of foreign entries.

        One damaged or stray entry never fails a verb; it is reported instead.
        """
        valid, corrupt, ignored = {}, [], 0
        for entry in self.entries("generations"):
            if entry.name.startswith("."):
                continue
            if not GEN.fullmatch(entry.name):
                ignored += 1
                continue
            m = self.valid_manifest(entry.name)
            if m is None:
                corrupt.append(entry.name)
            else:
                valid[entry.name] = m
        return valid, corrupt, ignored

    def selected(self, manifests=None):
        if not self.present:
            return None, None
        pointer = self.path / "current"
        if not pointer.is_symlink():
            if os.path.lexists(pointer):
                raise Failure("corrupt_state", "current is not a symlink")
            return None, None
        target = os.readlink(pointer)
        if not re.fullmatch(r"selections/[0-9a-f]{32}", target):
            raise Failure("corrupt_state", "invalid current pointer")
        try:
            record = read_json_file(self.path / target / "selection.json", INPUT_LIMIT)
            if not isinstance(record, dict) or set(record) != {"generation", "previous"} or not GEN.fullmatch(record["generation"]) or (record["previous"] is not None and not GEN.fullmatch(record["previous"])):
                raise ValueError("invalid selection record")
            link = os.readlink(self.path / target / "bin")
            if not link.endswith("/bin") or not STORE.fullmatch(link[:-4]):
                raise ValueError("invalid selection bin")
            # A corrupt selected manifest is reported by status, not fatal here;
            # the previous generation is not validated at all.
            m = manifests.get(record["generation"]) if manifests is not None else self.valid_manifest(record["generation"])
            if m is not None and link != m["identity"]["output"] + "/bin":
                raise ValueError("selection bin mismatch")
            return target.split("/")[1], record
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
            raise Failure("corrupt_state", "missing or corrupt selection") from exc

    def previous(self, record, valid):
        previous = record["previous"] if record else None
        return previous if previous in valid and previous != record["generation"] else None

    def boot_record(self):
        if not self.present:
            return None
        try:
            record = read_json_file(self.path / "boot-restore.json", INPUT_LIMIT)
        except (OSError, ValueError, RecursionError):
            return None
        if not isinstance(record, dict) or set(record) != BOOT_FIELDS or record["outcome"] not in ("active", "restored", "failed"):
            return None
        if any(record[k] is not None and not isinstance(record[k], str) for k in ("boot_id", "code")):
            return None
        if record["generation"] is not None and not (isinstance(record["generation"], str) and GEN.fullmatch(record["generation"])):
            return None
        if any(type(record[k]) is not int for k in ("finished_at", "duration_ms")):
            return None
        return record

    def write_boot_record(self, record):
        temporary = self.path / (".boot-restore-" + uuid.uuid4().hex)
        write_json(temporary, record)
        os.replace(temporary, self.path / "boot-restore.json")
        sync_dir(self.path)

    def status(self):
        valid, corrupt, ignored = self.scan()
        token, record = self.selected(valid)
        generations = []
        for generation, m in valid.items():
            ident = m["identity"]
            archive = self.path / "generations" / generation / "closure.nar"
            present = archive.is_file()
            generations.append({"id": generation, **{k: ident[k] for k in ("output", "derivation", "system", "provenance")},
                                "closure_available": self.commands.available(m["closure"]),
                                "archive_present": present, "archive_valid": None,
                                "archive_bytes": archive.stat().st_size if present else 0,
                                "created_at": self.created_at(generation)})
        selected = record["generation"] if record else None
        current = next((g for g in generations if g["id"] == selected), None)
        fs_bytes, free = filesystem(self.path)
        system, boot_id = guest_identity()
        return {"selection": token, "selected_generation": selected,
                "active_generation": selected if current and current["closure_available"] else None,
                "previous_generation": self.previous(record, valid),
                "output": current["output"] if current else None, "generations": generations,
                "corrupt_generations": corrupt, "ignored_entries": ignored,
                "boot_restore": self.boot_record(),
                "limits": {"max_generations": MAX_GENERATIONS, "archive_budget_bytes": archive_budget(fs_bytes),
                           "archive_bytes_total": sum(self.archive_size(g) for g in [*valid, *corrupt]),
                           "free_bytes": free, "reserve_bytes": reserve_bytes(fs_bytes),
                           "max_path_nar_bytes": MAX_PATH_NAR},
                "guest_system": system, "boot_id": boot_id}

    def make_room(self, closure, generation):
        """Prepare preflight: refuse before writing anything, then drop the oldest unprotected generations."""
        sizes = self.commands.sizes(closure)
        for path, size in zip(closure, sizes):
            if size > MAX_PATH_NAR:
                raise Failure("insufficient_space", "%s is %d bytes; a single store path may not exceed %d bytes" % (path, size, MAX_PATH_NAR))
        projected = sum(sizes) + PATH_OVERHEAD * len(closure)
        fs_bytes, free = filesystem(self.path)
        budget, reserve = archive_budget(fs_bytes), reserve_bytes(fs_bytes)
        if projected > budget:
            raise Failure("insufficient_space", "the bundle archive needs about %d bytes; the archive budget is %d bytes" % (projected, budget))
        valid, corrupt, _ = self.scan()
        _, record = self.selected(valid)
        selected = record["generation"] if record else None
        protected = {selected, self.previous(record, valid), generation}
        retained = {g: self.archive_size(g) for g in [*valid, *corrupt] if g != generation}
        candidates = [g for g in corrupt if g not in protected]
        candidates += sorted((g for g in valid if g not in protected), key=lambda g: (self.created_at(g), g))
        drops = []
        def fits():
            kept = [g for g in retained if g not in drops]
            return sum(retained[g] for g in kept) + projected <= budget and len(kept) + 1 <= MAX_GENERATIONS
        for candidate in candidates:
            if fits():
                break
            drops.append(candidate)
        if not fits():
            raise Failure("insufficient_space", "no room within %d generations and %d archive bytes; the selected (%s) and previous (%s) generations are never dropped automatically: run cogbox-env prune --generation ID, or cogbox-env clear" % (MAX_GENERATIONS, budget, selected or "none", self.previous(record, valid) or "none"))
        if free + sum(retained[g] for g in drops) - projected < reserve:
            raise Failure("insufficient_space", "the bundle archive needs about %d bytes and %d bytes must stay free; %d bytes are free" % (projected, reserve, free))
        for candidate in drops:
            self.drop_generation(candidate, selected)

    def drop_generation(self, generation, selected):
        # The closure itself stays in the store; the guest's GC reclaims it once unrooted.
        if generation == selected:
            raise Failure("invalid_request", "the selected generation cannot be pruned; apply another generation or clear first")
        generations = self.path / "generations"
        trash = generations / (".trash-%s-%s" % (generation, uuid.uuid4().hex))
        os.rename(generations / generation, trash)
        sync_dir(generations)
        (self.path / "roots" / generation).unlink(missing_ok=True)
        sync_dir(self.path / "roots")
        remove_tree(trash)

    def write_generation(self, directory, identity, closure, metadata, suffix="", times=None):
        archive = directory / ("closure.nar" + suffix)
        with open(archive, "xb") as stream:
            self.commands.run(["nix-store", "--export", *closure], stdout=stream)
            stream.flush()
            os.fsync(stream.fileno())
        manifest = {"identity": identity, "closure": closure, "source_archive": metadata,
                    "archive_sha256": file_digest(archive), "archive_bytes": archive.stat().st_size}
        manifest["manifest_sha256"] = digest(manifest)
        write_json(directory / ("manifest.json" + suffix), manifest, times)

    def reuse(self, generation, identity, closure, metadata, output):
        """Reuse a published generation; repair a missing or corrupt archive or manifest from the local closure."""
        directory = self.path / "generations" / generation
        if not directory.is_dir():
            raise Failure("corrupt_state", "generation entry is not a directory; run cogbox-env prune --generation " + generation)
        old = self.valid_manifest(generation)
        if old is not None:
            # The directory name is the identity digest, so a valid manifest already matches.
            archive = directory / "closure.nar"
            if archive.is_file() and archive.stat().st_size == old["archive_bytes"] and file_digest(archive) == old["archive_sha256"]:
                return False
        self.make_room(closure, generation)
        for stale in REPAIR_FILES:
            (directory / stale).unlink(missing_ok=True)
        # created_at is the manifest's mtime and orders retention, so a repair
        # keeps the original one instead of making the generation the newest.
        # Only a regular file has one to keep: never follow a link, and never
        # let a damaged entry (a symlink loop, say) stop the repair that
        # replaces it.
        try:
            st = os.lstat(directory / "manifest.json")
            times = (st.st_atime_ns, st.st_mtime_ns) if stat.S_ISREG(st.st_mode) else None
        except OSError:
            times = None
        try:
            self.write_generation(directory, identity, closure, metadata, ".new", times)
            # A crash between the renames leaves manifest.json.new beside the new
            # archive and the old manifest, a pair restore refuses unless they
            # already match; the next repair or prune removes the leftover.
            os.rename(directory / "closure.nar.new", directory / "closure.nar")
            os.rename(directory / "manifest.json.new", directory / "manifest.json")
        except BaseException:
            # Best effort, so the caller still sees the original error.
            for stale in REPAIR_FILES:
                with contextlib.suppress(OSError):
                    (directory / stale).unlink(missing_ok=True)
            raise
        if not os.path.lexists(directory / "root"):
            os.symlink(output, directory / "root")
        sync_dir(directory)
        return True

    def store_overrides(self, metadata):
        """`--override-input` arguments repeating each root input locked to a valid "source" store path.

        Nix 2.34 gives a lock-file `path` input no fetcher-cache fingerprint, so
        every evaluation NAR-hashes the whole tree again: minutes for the
        image's nixpkgs over the guest's 9p store. The same locked reference
        passed as an override is used in place and cached, and Nix checks its
        narHash. An override takes the input's reference and `flake` flag from
        flake.nix, where plain Nix keeps the lock entry's flag while the
        reference is unchanged and re-locks the input in memory when it
        changed. So an input keeps its override only when the lock Nix computes
        with the overrides holds its flake.lock entry unchanged: that entry is
        then also the one Nix evaluates without them, and the evaluation,
        derivation and output do not change. Every other input, and every input
        when Nix cannot compute that lock, keeps the plain evaluation.
        """
        try:
            archived = metadata["inputs"]
            wanted = {name: node for name, node in sorted(root_input_nodes(self.commands.read_lock(metadata["path"])).items())
                      if overridable(name, node, archived.get(name))}
        except (TypeError, KeyError, AttributeError):
            return []
        overrides, evaluated, invalid = {}, {}, set()
        try:
            if wanted:
                invalid = self.commands.invalid(sorted({node["locked"]["path"] for node in wanted.values()}))
            for name, node in wanted.items():
                locked = node["locked"]
                if locked["path"] not in invalid:
                    query = urllib.parse.urlencode(sorted((k, v) for k, v in locked.items() if k not in ("type", "path")))
                    overrides[name] = ["--override-input", name, "path:" + locked["path"] + "?" + query]
            if overrides:
                # The lock Nix evaluates the snapshot with under these overrides;
                # computing it fetches nothing the build would not.
                # Nix locks each root input on its own, so dropping one override
                # changes no other entry.
                shown = self.commands.json(["nix", "flake", "metadata", "--json", *LOCK_FLAGS,
                                            *itertools.chain.from_iterable(overrides.values()), "path:" + metadata["path"]])
                evaluated = root_input_nodes(shown.get("locks") if isinstance(shown, dict) else None)
        except Deadline:
            raise
        except (Failure, ValueError, RecursionError):
            pass
        kept = [name for name in overrides if evaluated.get(name) == wanted[name]]
        # A store path the database does not register is not N1: Nix fetches or refuses it.
        slow = [name for name in wanted if name not in kept and wanted[name]["locked"]["path"] not in invalid]
        if slow:
            sys.stderr.write("cogbox-env: prepare: no store-path override for %s, so Nix hashes the locked source again\n"
                             % ", ".join(slow))
        return [arg for name in kept for arg in overrides[name]]

    def prepare(self, req):
        staging = Path(tempfile.mkdtemp(prefix=".prepare-", dir=self.path / "generations"))
        protection = self.path / "roots" / (".preparing-" + uuid.uuid4().hex)
        root, root_created, destination = None, False, None
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
                # --dry-run records each locked input's store path from its narHash
                # and copies the source itself; Nix fetches only an input it
                # re-locks in memory or must re-read for a follows (see the doc).
                metadata = self.commands.json(["nix", "flake", "archive", "--dry-run", "--json", *LOCK_FLAGS, req["flake"]])
                source = metadata["path"]
                if not STORE.fullmatch(source):
                    raise Failure("prepare_failed", "flake archive did not produce an immutable snapshot")
                # Evaluate/build the archived source, never the original mutable checkout.
                result = self.commands.json(["nix", "build", "--json", *LOCK_FLAGS, *self.store_overrides(metadata),
                                             "--out-link", str(protection), "path:" + source + "#" + req["attribute"]])
                if len(result) != 1 or set(result[0]["outputs"]) != {"out"}:
                    raise Failure("prepare_failed", "bundle must produce exactly one out output")
                output, drv = result[0]["outputs"]["out"], result[0]["drvPath"]
                system = self.commands.derivation_system(drv)
                provenance = {"kind": "flake", "source": source, "attribute": req["attribute"], "inputs_digest": digest(metadata)}
            # Checked before publishing: manifest() would read it back as corrupt.
            if not SYSTEM.fullmatch(system):
                raise Failure("prepare_failed", "the bundle names an invalid system")
            if not self.commands.isdir(output + "/bin"):
                raise Failure("prepare_failed", "bundle must contain a bin directory")
            # The bundle's bin leads PATH; a bundled helper would shadow this one.
            if self.commands.lexists(output + "/bin/cogbox-env"):
                raise Failure("prepare_failed", "bundle must not provide cogbox-env")
            closure = sorted(set(self.commands.run(["nix-store", "--query", "--requisites", output]).decode().splitlines()))
            if not self.commands.available(closure, verify=True):
                raise Failure("unavailable_closure", "complete bundle closure is unavailable")
            identity = {"version": STATE_FORMAT, "output": output, "derivation": drv, "system": system, "provenance": provenance}
            generation = digest(identity)
            destination = self.path / "generations" / generation
            root = self.path / "roots" / generation
            if os.path.lexists(destination):
                changed = self.reuse(generation, identity, closure, metadata, output)
                self.commands.root(output, root)
                return generation, changed
            self.make_room(closure, generation)
            root_created = not os.path.lexists(root)
            self.commands.root(output, root)
            os.symlink(output, staging / "root")
            self.write_generation(staging, identity, closure, metadata)
            sync_dir(staging)
            os.rename(staging, destination)
            sync_dir(destination.parent)
            return generation, True
        except Failure as exc:
            if exc.code in ("unavailable_closure", "corrupt_state", "invalid_archive", "timed_out", "not_ready", "insufficient_space"):
                raise
            raise Failure("prepare_failed", str(exc)) from exc
        finally:
            protection.unlink(missing_ok=True)
            # A root for a generation this call never published would pin its closure forever.
            if root_created and not os.path.lexists(destination):
                root.unlink(missing_ok=True)
            if staging.exists():
                shutil.rmtree(staging)

    def restore_generation(self, generation, boot=False):
        """Make a generation's closure usable offline: 'active' if it already was, else 'restored'."""
        if not self.has_generation(generation):
            raise Failure("invalid_generation", "generation is not prepared")
        m = self.manifest(generation)
        closure, output = m["closure"], m["identity"]["output"]
        root = self.path / "roots" / generation
        missing = self.commands.missing(closure)
        invalid = self.commands.invalid(closure)
        if not missing and not invalid:
            self.commands.root(output, root)
            return "active"
        # The import adds only unregistered paths (NoRepair), so a registered but
        # absent path would never come back.
        registered = [p for p in missing if p not in invalid]
        if registered:
            raise Failure("store_inconsistent", "%d closure paths are registered but missing from the store (first: %s); importing cannot repair them" % (len(registered), registered[0]))
        # A present but unregistered path is deleted and rewritten in place, so
        # it costs about nothing. Per-path sizes are not recorded, so any missing
        # path counts the whole archive.
        needed = RESTORE_HEADROOM + (m["archive_bytes"] if missing else 0)
        free = self.commands.store_free()
        if free < needed:
            raise Failure("insufficient_space", "restoring needs %d free bytes in the Nix store; %d are free" % (needed, free))
        archive = self.path / "generations" / generation / "closure.nar"
        if not archive.is_file() or archive.stat().st_size != m["archive_bytes"] or file_digest(archive) != m["archive_sha256"]:
            raise Failure("invalid_archive", "missing or corrupt retained closure archive; run prepare again to repair it")
        try:
            with open(archive, "rb") as stream:
                self.commands.run(["nix-store", "--import", "--option", "substitute", "false", "--option", "substituters", ""], stdin=stream)
            if self.commands.missing(closure) or self.commands.invalid(closure):
                raise Failure("restore_failed", "import did not restore the exact complete closure")
            if not boot and not self.commands.verify(closure):
                raise Failure("restore_failed", "restored closure failed content verification")
            # Re-register even if a stale symlink survived a store DB reset.
            self.commands.root(output, root)
        except Deadline:
            raise
        except Failure as exc:
            raise Failure("restore_failed", str(exc)) from exc
        return "restored"

    def ensure_closure(self, generation, m):
        """apply/rollback: import the target offline when its closure is gone (after a restart)."""
        if self.commands.available(m["closure"], verify=True):
            return False
        if self.restore_generation(generation) == "active":
            # Present and registered but failing verification: an import cannot fix that.
            raise Failure("unavailable_closure", "closure content failed verification")
        return True

    def select(self, req, rollback=False):
        token, record = self.selected()
        if (token or "none") != req["expected_selection"]:
            raise Failure("stale_selection", "selection changed; inspect status before retrying")
        if rollback:
            generation = record["previous"] if record else None
            if not generation or not self.has_generation(generation) or self.valid_manifest(generation) is None:
                raise Failure("no_previous", "no previous generation")
        else:
            generation = req["generation"]
        if not self.has_generation(generation):
            raise Failure("invalid_generation", "generation is not prepared")
        m = self.manifest(generation)
        imported = self.ensure_closure(generation, m)
        self.commands.root(m["identity"]["output"], self.path / "roots" / generation)
        if record and record["generation"] == generation:
            return imported
        selection = new_token()
        directory = self.path / "selections" / selection
        directory.mkdir(mode=0o700)
        write_json(directory / "selection.json", {"generation": generation, "previous": record["generation"] if record else None})
        os.symlink(m["identity"]["output"] + "/bin", directory / "bin")
        sync_dir(directory)
        sync_dir(directory.parent)
        with self.commit("selections/" + selection):
            temporary = self.path / (".current-" + selection)
            os.symlink("selections/" + selection, temporary)
            os.replace(temporary, self.path / "current")
            sync_dir(self.path)
        return True

    def clear(self, req):
        token, _ = self.selected()
        if (token or "none") != req["expected_selection"]:
            raise Failure("stale_selection", "selection changed; inspect status before retrying")
        if token is None:
            return False
        # Selections and generations stay; only the pointer goes.
        with self.commit(None):
            os.unlink(self.path / "current")
            sync_dir(self.path)
        return True

    def restore(self, req):
        _, record = self.selected()
        generation = req.get("generation") or (record["generation"] if record else None)
        if generation is None:
            return False
        return self.restore_generation(generation) == "restored"

    def sweep(self, token):
        """Remove leftovers of interrupted operations. Callers hold the lock, so none are in flight."""
        removed = False
        generations = self.path / "generations"
        for entry in self.entries("generations"):
            if entry.name.startswith((".prepare-", ".trash-")):
                remove_tree(entry)
                removed = True
            elif GEN.fullmatch(entry.name) and entry.is_dir() and not entry.is_symlink():
                # An archive repair interrupted before or between its renames.
                stale = [entry / name for name in REPAIR_FILES if os.path.lexists(entry / name)]
                for path in stale:
                    remove_tree(path)
                if stale:
                    sync_dir(entry)
                    removed = True
        for entry in self.entries("."):
            if entry.name.startswith((".current-", ".boot-restore-")):
                entry.unlink()
                removed = True
        for entry in self.entries("roots"):
            if entry.name.startswith(".preparing-") or (GEN.fullmatch(entry.name) and not os.path.lexists(generations / entry.name)):
                entry.unlink()
                removed = True
        for entry in self.entries("selections"):
            if TOKEN.fullmatch(entry.name) and entry.name != token:
                remove_tree(entry)
                removed = True
        if removed:
            for directory in (self.path, generations, self.path / "roots", self.path / "selections"):
                if directory.is_dir():
                    sync_dir(directory)
        return removed

    def prune(self, req):
        valid, corrupt, _ = self.scan()
        token, record = self.selected(valid)
        selected = record["generation"] if record else None
        if "generation" in req:
            generation = req["generation"]
            if generation == selected:
                raise Failure("invalid_request", "the selected generation cannot be pruned; apply another generation or clear first")
            if not self.present or not os.path.lexists(self.path / "generations" / generation):
                raise Failure("invalid_generation", "generation is not prepared")
            self.drop_generation(generation, selected)
            return True
        protected = {selected, self.previous(record, valid)}
        changed = False
        for generation in corrupt:
            if generation not in protected:
                self.drop_generation(generation, selected)
                changed = True
        count = len(valid) + sum(1 for g in corrupt if g in protected)
        for generation in sorted((g for g in valid if g not in protected), key=lambda g: (self.created_at(g), g)):
            if count <= MAX_GENERATIONS:
                break
            self.drop_generation(generation, selected)
            count -= 1
            changed = True
        return self.sweep(token) or changed

    def auto_prune(self):
        try:
            self.prune({})
        except Exception as exc:  # best effort: the commit already happened
            sys.stderr.write("cogbox-env: automatic prune failed: %s\n" % exc)

    def perform(self, req):
        action = req["action"]
        changed, generation = False, None
        if action == "prepare":
            generation, changed = self.prepare(req)
        elif action in ("apply", "rollback"):
            changed = self.select(req, action == "rollback")
        elif action == "clear":
            changed = self.clear(req)
        elif action == "restore":
            changed = self.restore(req)
        elif action == "prune":
            changed = self.prune(req)
        if self.commit_target is not UNCOMMITTED:
            self.auto_prune()
        return changed, generation


def envelope(action=None, *, ok=False, changed=False, generation=None, status=None, error=None, capabilities=None):
    return {"version": PROTOCOL_VERSION, "ok": ok, "action": action, "changed": changed,
            "generation": generation, "status": status, "error": error, "capabilities": capabilities}


def unavailable(action, message="selection committed; run cogbox-env status"):
    # The one error envelope with changed:true: the change happened, observing it failed.
    return envelope(action, changed=True, error={"code": "status_unavailable", "message": message})


def failure_of(exc):
    if isinstance(exc, Failure):
        return {"code": exc.code, "message": str(exc)}
    return {"code": "internal_error", "message": str(exc)}


def dispatch(req, directory, commands):
    action = req.get("action") if isinstance(req, dict) and req.get("action") in ACTIONS else None
    env = None
    try:
        validate_request(req)
        if action == "capabilities":
            # Answered before any state is opened, created or locked.
            return envelope(action, ok=True, capabilities=capabilities())
        env = Environment(directory, commands, create=action == "prepare")
        if not env.ready:
            raise Failure("not_ready", NOT_READY)
        with env.locked(STATUS_LOCK_TIMEOUT if action == "status" else None):
            try:
                changed, generation = env.perform(req)
                result = envelope(action, ok=True, changed=changed, generation=generation, status=env.status())
            except Exception as exc:
                if env.committed():
                    return unavailable(action)
                status = None
                if action != "status":
                    try:
                        status = env.status()
                    except Exception:
                        status = None
                result = envelope(action, status=status, error=failure_of(exc))
            if len(encode(result)) > OUTPUT_LIMIT:
                if env.committed():
                    return unavailable(action)
                if result["ok"]:
                    return envelope(action, error={"code": "internal_error", "message": "retained state exceeds the response limit"})
                result["status"] = None
            return result
    except Exception as exc:
        if env is not None and env.committed():
            return unavailable(action)
        return envelope(action, error=failure_of(exc))
    finally:
        if env is not None:
            env.release()


def summary_line(record):
    return "cogbox-runtime-restore: outcome=%s code=%s generation=%s duration_ms=%d" % (
        record["outcome"], record["code"] or "-", record["generation"] or "-", record["duration_ms"])


def error_line(error):
    """A failed boot restore's message, which neither its record nor status carries, as one bounded line."""
    message = " ".join(str(error.get("message") or "").split())[:1024]
    return "cogbox-runtime-restore: error: %s: %s" % (error.get("code") or "-", message)


def boot_restore(directory, commands):
    """`restore --boot`: restore the selected generation offline and record the outcome.

    Returns (envelope, record); record is None when there was nothing to restore.
    """
    started = time.monotonic()
    env = Environment(directory, commands)
    if not (env.ready and env.present and (env.path / "current").is_symlink()):
        # Nothing selected, nothing to restore: a no-op that succeeds and writes
        # nothing, whatever the status read says (the unit's condition skips it).
        try:
            with env.locked(STATUS_LOCK_TIMEOUT):
                return envelope("restore", ok=True, status=env.status()), None
        except Exception as exc:
            return envelope("restore", error=failure_of(exc)), None
    outcome, code, message, generation, status = "failed", None, None, None, None
    with contextlib.ExitStack() as stack:
        try:
            stack.enter_context(env.locked())
            _, selection = env.selected()
            if selection is None:
                return envelope("restore", ok=True, status=env.status()), None
            generation = selection["generation"]
            outcome = env.restore_generation(generation, boot=True)
        except Failure as exc:
            code, message = exc.code, str(exc)
        except (OSError, ValueError, TypeError) as exc:
            code, message = "internal_error", str(exc)
        record = {"boot_id": guest_identity()[1], "outcome": outcome, "code": code, "generation": generation,
                  "finished_at": int(time.time()), "duration_ms": int((time.monotonic() - started) * 1000)}
        try:
            env.write_boot_record(record)
        except OSError as exc:
            # The outcome still reaches the journal and the exit status.
            sys.stderr.write("cogbox-env: could not record the boot restore: %s\n" % exc)
        try:
            status = env.status()
        except Exception:
            status = None
    if outcome == "failed":
        return envelope("restore", status=status, error={"code": code, "message": message}), record
    if status is None:
        if outcome == "restored":
            return unavailable("restore", "restore finished; run cogbox-env status"), record
        return envelope("restore", error={"code": "internal_error", "message": "status unavailable after boot restore"}), record
    return envelope("restore", ok=True, changed=outcome == "restored", status=status), record


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
    parser.add_argument("action", choices=["rpc", *ACTIONS, "exec"])
    parser.add_argument("--state-dir", default="/root/work/.cogbox/runtime")
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--json", action="store_true", help="emit the protocol envelope (also the default)")
    parser.add_argument("--boot", action="store_true", help="restore only: the boot unit's offline restore of the selected generation")
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
    if args.boot and (args.action != "restore" or args.generation is not None):
        parser.error("--boot is only valid for restore, which then restores the selected generation")
    if args.action == "exec":
        if not command or not os.path.isabs(args.state_dir):
            parser.error("exec requires an absolute state-dir and -- COMMAND")
        os.environ["PATH"] = str(Path(args.state_dir).resolve() / "current" / "bin") + os.pathsep + os.environ.get("PATH", "")
        os.execvp(command[0], command)
    def timed_out(_signum, _frame):
        raise Deadline("operation timed out; inspect status before retrying")
    signal.signal(signal.SIGALRM, timed_out)
    signal.setitimer(signal.ITIMER_REAL, args.timeout)
    record, booted = None, False
    try:
        if command:
            raise Failure("invalid_request", "unexpected command arguments")
        if args.boot:
            result, record = boot_restore(args.state_dir, Commands(args.timeout))
            booted = True
        else:
            if args.action == "rpc":
                req = read_request(args.timeout)
            else:
                req = {"version": PROTOCOL_VERSION, "action": args.action}
                req.update({k: getattr(args, k) for k in ("flake", "attribute", "import_store_path", "generation", "expected_selection") if getattr(args, k) is not None})
            result = dispatch(req, args.state_dir, Commands(args.timeout))
    except (ValueError, UnicodeError) as exc:
        result = envelope(error={"code": "invalid_request", "message": str(exc)})
    except Exception as exc:
        result = envelope(error=failure_of(exc))
    signal.setitimer(signal.ITIMER_REAL, 0)
    # Kept before any size fallback below replaces the envelope.
    error = result["error"]
    encoded = encode(result)
    if len(encoded) > OUTPUT_LIMIT:
        result = unavailable(result["action"]) if result["changed"] else envelope(result["action"], error={"code": "internal_error", "message": "response exceeds 4 MiB"})
        encoded = encode(result)
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    # The boot unit discards stdout, so its journal gets only stderr: the
    # summary line and, on failure, the message, which is on no other
    # persisted surface.
    if booted:
        # The boot unit's status follows the restore outcome; no selection is success.
        if record is None:
            return 0
        sys.stderr.write(summary_line(record) + "\n")
        if record["outcome"] == "failed":
            sys.stderr.write(error_line(error) + "\n")
            return 1
        return 0
    if args.boot and error is not None:
        # An exception escaped the boot restore before it had an outcome.
        sys.stderr.write(error_line(error) + "\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
