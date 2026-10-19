"""cogworx-pve-upgrade: the in-guest system upgrade tool of a cogbox PVE host.

cogworxd moves a PVE sandbox from one NixOS system generation (a toplevel) to
another without re-creating the VM. This tool is the guest half: it fetches the
target, arms GRUB's one-shot for a trial boot, and commits, aborts, reverts or
releases afterwards. Every system generation ships it at
<toplevel>/sw/bin/cogworx-pve-upgrade, and cogworxd always invokes it by that
store path over the control channel, as root. docs/pve-system-upgrade.md is the
full contract; this docstring is the summary the code is held to.

WHICH COPY RUNS. Read verbs (proto, status, closure-digest) run from any path,
including an operator workstation build. A mutating verb checks the UNRESOLVED
sys.argv[0]: it must be <S>/sw/bin/cogworx-pve-upgrade where S is

  fetch, _fetch, arm, release, abort   the committed system
  commit                               the committed system (booted: target)
  revert-commit                        the recorded rollback (booted: it)

"committed" is txn.json's committed.path, never the profile head. Two system
generations whose tool package is identical share one realpath, so only the
invoked path tells them apart: the package shebang is `python3 -I` on the
script's own first line and nothing may wrap it. A re-issued verb whose txn
already reached that verb's outcome is answered (exit 0, mutated false) before
the argv[0] rule, so the old tool can re-ask after a commit.

OUTPUT. stdout carries exactly one JSON object (ASCII, sorted keys) and one
newline, at most 64 KiB; stderr is diagnostics. Every mutation happens before
anything is printed, SIGHUP and SIGPIPE are ignored, and a vanished reader is
not an error: a verb whose caller has gone still finishes and records its
outcome in txn.json.

  {"cogworx_pve_upgrade":1,"verb":..,"ok":..,"exit":..,"reason_class":..,
   "reason":..,"txn_id":..,"mutated":..,"status":{..}}

Exit codes: 0 done; 64 usage (argv grammar, nothing read or written); 65
refused (reason_class says why; `mutated` says whether this run changed
anything); 69 unavailable (a required facility is missing); 70 internal
(mutation unknown); 75 busy (the lock is held). `status` is absent for proto,
closure-digest and exit 64.

STATE. /var/lib/cogworx-pve-upgrade/txn.json (0600, written tmp + fsync +
rename + directory fsync, one write per transition) holds the committed
system, the rollback, the staged target, the bootloader pin and the newest
txn. Profiles: system (the head), system-profiles/cogworx_candidate (armed
target), system-profiles/cogworx_rollback (the previous system). GC roots under
/nix/var/nix/gcroots/cogworx-pve-upgrade/: bootloader, staged, committed.
grubenv variables owned here: next_entry (GRUB's one-shot), cwx_rollback_entry,
cwx_once (written by the GRUB guard, unset by arm). Lock:
/run/cogworx-pve-upgrade.lock, flock(2), shared with cogworx-nix-gc.

STEPS. Every numbered step of every verb sets an ABSOLUTE value and ends with
os.sync(), so re-running a verb from step 1 is always safe and a power cut
between two steps leaves a state txn.json names. Menu entries are addressed by
TITLE paths copied from a fresh grub.cfg parse after every installer run;
numeric paths shift when the candidate submenu appears.

THE INSTALLER. Only the bootloader pinned at the first mutating verb (the base
image's install-grub.sh, vetted to be exactly one perl line) ever writes
grub.cfg, run as its perl argv with a scrubbed environment, and only while
/boot/grub/state matches all six of install-grub.pl's requireNewInstall inputs.
So grub-install never runs, and the base owns GRUB's global section forever;
each system generation contributes only its kernel, initrd and kernel-params.

THE FETCH WORKER. `fetch` starts a transient unit (cogworx-pve-upgrade-fetch)
running `_fetch` and waits up to 5 s for it to register; the worker records
its verdict in txn.json and exits 0 whether the verdict is fetched or
fetch_failed; cogworxd polls `status`.

TEST SEAMS. ROOT prefixes every filesystem path the tool touches or hands to a
child (P()), STEP_HOOK(verb, n, name) runs after each step's sync, and
statvfs_free(), now() and sync() are module functions. None of them is reachable
from the command line or the environment.
"""

import base64
import errno
import fcntl
import hashlib
import json
import math
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

TOOL_PROTO = 1
TXN_SCHEMA = 1
COMPAT_SCHEMA = 1
COMPAT_KIND = "cogworx-pve-system"
GUARD_MARKER = "# cwx-guard-v1"
GUARD_ID = "cwx-guard-v1"

# --- seams (see the docstring) -----------------------------------------------

ROOT = ""
CHILD_PATH = "@childPath@"
MIN_FREE_BYTES = "@minFreeBytes@"
RESERVE_BYTES = "@reserveBytes@"
STEP_HOOK = None
WORKER_LOCK_WAIT = 60.0
WORKER_REGISTER_WAIT = 5.0


def P(path):
    return ROOT + path


def statvfs_free(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sync():
    os.sync()


# --- paths ---------------------------------------------------------------------

STATE_DIR = "/var/lib/cogworx-pve-upgrade"
TXN_FILE = STATE_DIR + "/txn.json"
LOCK_FILE = "/run/cogworx-pve-upgrade.lock"
HOLDER_FILE = "/run/cogworx-pve-upgrade.holder"
PROGRESS_DIR = "/run/cogworx-pve-upgrade"
PROGRESS_FILE = PROGRESS_DIR + "/progress.json"
GCROOTS = "/nix/var/nix/gcroots/cogworx-pve-upgrade"
PROFILES = "/nix/var/nix/profiles"
SYSTEM_PROFILE = PROFILES + "/system"
SYSTEM_PROFILES_DIR = PROFILES + "/system-profiles"
CANDIDATE = SYSTEM_PROFILES_DIR + "/cogworx_candidate"
ROLLBACK = SYSTEM_PROFILES_DIR + "/cogworx_rollback"
BOOTED = "/run/booted-system"
CURRENT = "/run/current-system"
GRUB_CFG = "/boot/grub/grub.cfg"
GRUBENV = "/boot/grub/grubenv"
GRUB_STATE = "/boot/grub/state"
BOOT_ID = "/proc/sys/kernel/random/boot_id"
COMPAT_NAME = "cogworx-pve-compat.json"
TOOL_REL = "/sw/bin/cogworx-pve-upgrade"
FETCH_UNIT = "cogworx-pve-upgrade-fetch"

COMPAT_MAX = 16384
MAX_OUT = 65536
MAX_HOPS = 16
HISTORY_MAX = 16
INSTALLER_TIMEOUT = 120
CHILD_TIMEOUT = 120
STDERR_KEEP = 262144

# --- argument grammar --------------------------------------------------------

NIX32 = "0123456789abcdfghijklmnpqrsvwxyz"
SYS_RE = re.compile(r"/nix/store/[0-9a-df-np-sv-z]{32}-nixos-system-[A-Za-z0-9._+-]{1,200}")
STORE_PATH_RE = re.compile(r"/nix/store/[0-9a-df-np-sv-z]{32}-[A-Za-z0-9+._?=-]{1,211}")
TXN_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
CLOSURE_RE = re.compile(r"[0-9a-f]{64}")
TIME_RE = re.compile(r"[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z")
BYTES_RE = re.compile(r"[1-9][0-9]{0,15}")

VALUE_RE = {
    "--txn": TXN_RE,
    "--target": SYS_RE,
    "--closure": CLOSURE_RE,
    "--closure-bytes": BYTES_RE,
    "--retain-until": TIME_RE,
}

# verb -> ({option: "v" (takes a value) | "f" (bare flag)}, required options)
GRAMMAR = {
    "proto": ({}, ()),
    "status": ({}, ()),
    "closure-digest": ({"--target": "v"}, ("--target",)),
    "fetch": ({"--txn": "v", "--target": "v", "--closure": "v", "--closure-bytes": "v",
               "--release-rollback": "f"}, ("--txn", "--target", "--closure")),
    "_fetch": ({"--txn": "v"}, ("--txn",)),
    "arm": ({"--txn": "v"}, ("--txn",)),
    "commit": ({"--txn": "v", "--retain-until": "v", "--no-rollback": "f"}, ("--txn",)),
    "abort": ({"--txn": "v", "--release-staged": "f"}, ("--txn",)),
    "revert-commit": ({"--txn": "v"}, ("--txn",)),
    "release": ({"--txn": "v"}, ("--txn",)),
}
PUBLIC_VERBS = ["proto", "status", "closure-digest", "fetch", "arm", "commit", "abort",
                "revert-commit", "release"]

OPEN_STATES = ("fetching", "fetch_failed", "fetched", "arming", "armed", "committing",
               "aborting", "reverting", "releasing")
CLOSED_STATES = ("committed", "aborted", "reverted", "released", "repaired")
IN_PROGRESS = ("fetching", "arming", "committing", "aborting", "reverting", "releasing")
KINDS = ("switch", "revert", "release", "repair")


class Usage(Exception):
    pass


class Fail(Exception):
    """A refusal or failure that becomes the envelope: exit code, class, reason."""

    def __init__(self, code, cls, reason):
        super().__init__(reason)
        self.code = code
        self.cls = cls
        self.reason = reason


class Terminated(BaseException):
    """The fetch worker got SIGTERM; raised only at a safe point."""


def parse_argv(argv):
    """(verb, {option: value or True}) or Usage. Reads nothing. argv[0] is not
    part of the grammar: the argv[0] rule checks it, for mutating verbs only."""
    args = list(argv[1:])
    if not args:
        raise Usage("no verb")
    if len(args) > 12:
        raise Usage("more than 12 arguments")
    for a in args:
        if not isinstance(a, str) or any(not (0x20 <= ord(c) <= 0x7E) for c in a):
            raise Usage("an argument is not printable ASCII")
        if len(a) > 320:
            raise Usage("an argument is longer than 320 bytes")
    verb = args[0]
    if verb not in GRAMMAR:
        raise Usage("unknown verb")
    allowed, required = GRAMMAR[verb]
    opts = {}
    i = 1
    while i < len(args):
        a = args[i]
        if not a.startswith("--"):
            raise Usage("positional argument " + a)
        if "=" in a:
            raise Usage("--name=value is not accepted")
        if a not in allowed:
            raise Usage("unknown option " + a)
        if a in opts:
            raise Usage("duplicate option " + a)
        if allowed[a] == "f":
            opts[a] = True
            i += 1
            continue
        if i + 1 >= len(args):
            raise Usage("missing value for " + a)
        if not VALUE_RE[a].fullmatch(args[i + 1]):
            raise Usage("malformed value for " + a)
        opts[a] = args[i + 1]
        i += 2
    for r in required:
        if r not in opts:
            raise Usage("missing " + r)
    if verb == "commit" and (("--retain-until" in opts) == ("--no-rollback" in opts)):
        raise Usage("commit takes exactly one of --retain-until and --no-rollback")
    return verb, opts


# --- small helpers -------------------------------------------------------------


def diag(msg):
    try:
        sys.stderr.write("cogworx-pve-upgrade: %s\n" % msg)
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


def clean(text, limit=512):
    """Envelope-safe reason text: printable ASCII, no quote or backslash."""
    out = "".join(c if (0x20 <= ord(c) <= 0x7E and c not in '"\\') else "?" for c in str(text))
    return out[:limit]


def resolve(path, hops=MAX_HOPS):
    """The logical realpath of an absolute path under ROOT, or None when a
    component is missing or more than `hops` symlinks are followed. Symlink
    targets are logical (absolute targets restart at ROOT)."""
    if not isinstance(path, str) or not path.startswith("/"):
        return None
    parts = [p for p in path.split("/") if p not in ("", ".")]
    done = ""
    budget = hops
    while parts:
        name = parts.pop(0)
        if name == "..":
            done = done.rsplit("/", 1)[0]
            continue
        cand = done + "/" + name
        try:
            st = os.lstat(P(cand))
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            budget -= 1
            if budget < 0:
                return None
            try:
                target = os.readlink(P(cand))
            except OSError:
                return None
            parts = [p for p in target.split("/") if p not in ("", ".")] + parts
            if target.startswith("/"):
                done = ""
            continue
        done = cand
    return done or "/"


def lexists(path):
    return os.path.lexists(P(path))


def sys_or_none(path):
    return path if isinstance(path, str) and SYS_RE.fullmatch(path) else None


def read_file(path, limit):
    """Bytes of a logical path (symlinks resolved under ROOT), at most `limit`."""
    real = resolve(path)
    if real is None:
        raise FileNotFoundError(errno.ENOENT, "no such file", path)
    with open(P(real), "rb") as f:
        return f.read(limit)


def read_json_file(path, limit=65536):
    try:
        with open(P(path), "rb") as f:
            d = json.loads(f.read(limit))
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write(real_path, data, mode=0o600):
    tmp = real_path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, real_path)
    fsync_dir(os.path.dirname(real_path))


def pid_alive(pid):
    return isinstance(pid, int) and not isinstance(pid, bool) and pid > 0 and os.path.isdir(P("/proc/%d" % pid))


def boot_id():
    try:
        return read_file(BOOT_ID, 128).decode("ascii", "replace").strip()
    except OSError:
        return ""


def tool_realpath():
    return os.path.realpath(__file__)


def argv0_system(argv0):
    if isinstance(argv0, str) and argv0.endswith(TOOL_REL):
        return sys_or_none(argv0[: -len(TOOL_REL)])
    return None


def int_seam(value, name):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise Fail(69, "unavailable", "the tool was built without %s" % name)


def history_add(doc, entry):
    doc["history"] = ([entry] + list(doc.get("history") or []))[:HISTORY_MAX]


def close_txn(doc, t, outcome, **extra):
    t["state"] = outcome
    t["closed_at"] = now()
    entry = {"id": t["id"], "kind": t["kind"], "outcome": outcome, "target": t.get("target"),
             "closed_at": t["closed_at"]}
    entry.update(extra)
    history_add(doc, entry)


def new_txn(tid, kind, state, target=None, closure=None):
    ts = now()
    return {"id": tid, "kind": kind, "state": state, "target": target, "closure": closure,
            "pre": None, "fetch": None, "reason_class": None, "reason": None,
            "opened_at": ts, "updated_at": ts, "closed_at": None}


# --- nix32 and hashes ------------------------------------------------------------


def nix32_encode(raw):
    n = (len(raw) * 8 - 1) // 5 + 1
    out = []
    for k in range(n - 1, -1, -1):
        b = k * 5
        i, j = b // 8, b % 8
        c = raw[i] >> j
        if i + 1 < len(raw):
            c |= raw[i + 1] << (8 - j)
        out.append(NIX32[c & 0x1F])
    return "".join(out)


def nix32_decode(text, size):
    if len(text) != (size * 8 - 1) // 5 + 1:
        raise ValueError("wrong nix32 length")
    raw = bytearray(size)
    for k in range(len(text)):
        digit = NIX32.find(text[len(text) - k - 1])
        if digit < 0:
            raise ValueError("not a nix32 digit")
        b = k * 5
        i, j = b // 8, b % 8
        raw[i] |= (digit << j) & 0xFF
        carry = digit >> (8 - j)
        if i + 1 < size:
            raw[i + 1] |= carry
        elif carry:
            raise ValueError("non-canonical nix32")
    return bytes(raw)


def normalize_hash(text):
    """`sha256:<nix32>` from a nix32, base16 or SRI sha256 (with or without the
    `sha256:` prefix), whatever form the local nix prints."""
    s = text.strip()
    try:
        if s.startswith("sha256-"):
            raw = base64.b64decode(s[7:], validate=True)
        else:
            body = s[7:] if s.startswith("sha256:") else s
            if len(body) == 64 and re.fullmatch(r"[0-9a-f]{64}", body):
                raw = bytes.fromhex(body)
            else:
                raw = nix32_decode(body, 32)
    except ValueError:
        raw = b""
    if len(raw) != 32:
        raise Fail(70, "internal", "unrecognized hash form from nix-store: " + clean(s, 80))
    return "sha256:" + nix32_encode(raw)


# --- children --------------------------------------------------------------------


def child_path():
    if CHILD_PATH.startswith("@"):
        raise Fail(69, "unavailable", "the tool was built without a child PATH")
    return CHILD_PATH


def child_env():
    # Exactly these: NIXOS_INSTALL_BOOTLOADER and NIXOS_INSTALL_GRUB (either turns
    # an installer run into a grub-install) can never reach a child.
    return {"PATH": child_path(), "LC_ALL": "C", "HOME": "/root"}


def which(name):
    found = shutil.which(name, path=child_path())
    if not found:
        raise Fail(69, "unavailable", "%s is not on the tool's child PATH" % name)
    return os.path.abspath(found)


def run_cmd(argv, timeout=CHILD_TIMEOUT):
    try:
        r = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, env=child_env(), timeout=timeout, close_fds=True)
    except subprocess.TimeoutExpired:
        raise Fail(70, "internal", "%s timed out" % os.path.basename(argv[0]))
    except OSError as e:
        raise Fail(69, "unavailable", "cannot run %s: %s" % (os.path.basename(argv[0]), e.strerror))
    err = r.stderr.decode("utf-8", "replace").strip()
    if err:
        diag("%s: %s" % (os.path.basename(argv[0]), err[-4000:]))
    return r


def last_line(data):
    lines = [l for l in data.decode("utf-8", "replace").splitlines() if l.strip()]
    return clean(lines[-1], 300) if lines else ""


# --- grub.cfg and grubenv parsing (shared with cogworxd's Go parser) --------------

_OPEN = re.compile(r'(menuentry|submenu) "([^"]*)"(\s.*)?\{')
_FUNC = re.compile(r"function \S+ \{")
_INIT = re.compile(r"(?:^|\s)init=(\S+)")
_PROFILE_NAME = re.compile(r"\w+", re.ASCII)


def _title_ok(title):
    return all(0x20 <= ord(c) <= 0x7E and c not in '>"\\$' for c in title)


def entry_title_re(distro):
    return re.compile(re.escape(distro) + r" - Configuration [0-9]+ \([0-9]{4}-[0-9]{2}-[0-9]{2} - [ -~]{1,128}\)")


def parse_grub_cfg(text, distro):
    """install-grub.pl's grub.cfg -> {entry0, submenus, profiles, errors}.

    Lines are stripped. Openers are `menuentry "T" ... {`, `submenu "T" ... {`
    and `function NAME {`; a closer is a line `}`. The first `linux ` line of a
    menuentry gives init=<SYS>/init. Errors (deduplicated, in order):
    unbalanced, nested-submenu:<t>, nested-entry:<t>, title-chars:<t>,
    init:<t>, no-entry0, entry0-title, empty-submenu:<t>,
    profile-entries:<name>:<n>, entry-title:<t>. `profiles` maps each
    `<distro> - Profile 'cogworx_*'` submenu holding exactly one entry to that
    entry's title path (`<submenu title>><entry title>`, verbatim) and init.
    """
    errors = []

    def err(e):
        if e not in errors:
            errors.append(e)

    stack = []
    entry0 = None
    submenus = []
    entries = []
    for raw in text.split("\n"):
        line = raw.strip()
        m = _OPEN.fullmatch(line)
        if m:
            kind, title = m.group(1), m.group(2)
            if not _title_ok(title):
                err("title-chars:" + title)
            parent = stack[-1] if stack else None
            if kind == "submenu":
                node = {"title": title, "entries": []}
                if parent is None:
                    submenus.append(node)
                else:
                    err("nested-submenu:" + title)
                stack.append(("submenu", node))
            else:
                node = {"title": title, "init": None, "linux": False}
                entries.append(node)
                if parent is None:
                    if entry0 is None:
                        entry0 = node
                elif parent[0] == "submenu":
                    parent[1]["entries"].append(node)
                else:
                    err("nested-entry:" + title)
                stack.append(("menuentry", node))
            continue
        if _FUNC.fullmatch(line):
            stack.append(("function", None))
            continue
        if line == "}":
            if stack:
                stack.pop()
            else:
                err("unbalanced")
            continue
        if stack and stack[-1][0] == "menuentry" and re.match(r"linux\s", line):
            node = stack[-1][1]
            if not node["linux"]:
                node["linux"] = True
                mi = _INIT.search(line)
                if mi and mi.group(1).endswith("/init") and SYS_RE.fullmatch(mi.group(1)[:-5]):
                    node["init"] = mi.group(1)[:-5]
    if stack:
        err("unbalanced")
    for e in entries:
        if e["init"] is None:
            err("init:" + e["title"])
    if entry0 is None:
        err("no-entry0")
    elif entry0["title"] != distro:
        err("entry0-title")
    for s in submenus:
        if not s["entries"]:
            err("empty-submenu:" + s["title"])
    profiles = {}
    prefix = distro + " - Profile '"
    title_re = entry_title_re(distro)
    for s in submenus:
        t = s["title"]
        if not (t.startswith(prefix) and t.endswith("'")):
            continue
        name = t[len(prefix):-1]
        if not (_PROFILE_NAME.fullmatch(name) and name.startswith("cogworx_")):
            continue
        if len(s["entries"]) != 1:
            err("profile-entries:%s:%d" % (name, len(s["entries"])))
            continue
        e = s["entries"][0]
        if not _title_ok(e["title"]):
            continue
        if not title_re.fullmatch(e["title"]):
            err("entry-title:" + e["title"])
            continue
        profiles[name] = {"path": t + ">" + e["title"], "init": e["init"]}

    def pub(e):
        return {"title": e["title"], "init": e["init"]}

    return {
        "entry0": pub(entry0) if entry0 else None,
        "submenus": [{"title": s["title"], "entries": [pub(e) for e in s["entries"]]} for s in submenus],
        "profiles": profiles,
        "errors": errors,
    }


ENV_HEADER = b"# GRUB Environment Block\n"
ENV_SIZE = 1024


def parse_grubenv(data):
    """A grubenv block -> {name: value}, or None when it is not a valid block.

    Exactly 1024 bytes starting with the GRUB header; then, per
    grub-core/lib/envblk.c, `name=value\\n` entries and `#` comment lines (the
    trailing `#` padding is one), where a backslash escapes the next byte of a
    value, newline included. grub-editenv's own `create` writes a comment line.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) != ENV_SIZE or not data.startswith(ENV_HEADER):
        return None
    out = {}
    i = len(ENV_HEADER)
    n = len(data)
    while i < n:
        if data[i] == 0x23:
            nl = data.find(b"\n", i)
            i = n if nl < 0 else nl + 1
            continue
        eq = data.find(b"=", i)
        nl = data.find(b"\n", i)
        if eq < 0 or (0 <= nl < eq) or eq == i:
            return None
        name = data[i:eq].decode("latin-1")
        i = eq + 1
        val = bytearray()
        while True:
            if i >= n:
                return None
            b = data[i]
            if b == 0x5C:
                if i + 1 >= n:
                    return None
                val.append(data[i + 1])
                i += 2
                continue
            i += 1
            if b == 0x0A:
                break
            val.append(b)
        if name in out:
            return None
        out[name] = bytes(val).decode("latin-1")
    return out


def env_line_len(name, value):
    return len(name) + 1 + len(value) + value.count("\\") + value.count("\n") + 1


def env_used(data):
    """Bytes in use: everything up to the trailing `#` padding."""
    end = len(data)
    while end > 0 and data[end - 1:end] == b"#":
        end -= 1
    return end


# --- the bootloader pin --------------------------------------------------------------

_PERL_LINE = re.compile(r"\s*(/nix/store/\S+/bin/perl) (/nix/store/\S+-install-grub\.pl) (/nix/store/\S+-grub-config\.xml) \$@\s*")


class PinError(Exception):
    pass


def parse_installer_script(text):
    """install-grub.sh -> (perl, install-grub.pl, grub-config.xml). The script,
    minus its #! line, `set -e` and blank lines, must be exactly one perl line:
    no cryptodisk export, no second mirrored boot, no extraInstallCommands."""
    lines = text.split("\n")
    if not lines or not lines[0].startswith("#!"):
        raise PinError("install-grub.sh has no #! line")
    rest = [l for l in lines[1:] if l.strip() not in ("", "set -e")]
    if len(rest) != 1:
        raise PinError("install-grub.sh is not exactly one perl line (%d lines)" % len(rest))
    m = _PERL_LINE.fullmatch(rest[0])
    if not m:
        raise PinError("install-grub.sh's line is not perl install-grub.pl grub-config.xml $@")
    return m.group(1), m.group(2), m.group(3)


def parse_grub_xml(data):
    """grub-config.xml (builtins.toXML) -> {name: str | bool | int | [str] | None}."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise PinError("grub-config.xml does not parse: %s" % e)
    attrs = root.find("attrs") if root.tag == "expr" else None
    if attrs is None:
        raise PinError("grub-config.xml is not an <expr><attrs> document")
    out = {}
    for attr in attrs.findall("attr"):
        name = attr.get("name")
        kids = list(attr)
        if name is None or len(kids) != 1:
            continue
        v = kids[0]
        if v.tag == "string":
            out[name] = v.get("value", "")
        elif v.tag == "bool":
            out[name] = v.get("value") == "true"
        elif v.tag == "int":
            try:
                out[name] = int(v.get("value"))
            except (TypeError, ValueError):
                out[name] = None
        elif v.tag == "list":
            items = list(v)
            out[name] = [c.get("value", "") for c in items] if all(c.tag == "string" for c in items) else None
        else:
            out[name] = None
    return out


def check_xml(x):
    """The installer settings the pin requires (None when they hold)."""
    want = [
        ("useOSProber", False),
        ("extraPrepareConfig", ""),
        ("extraEntries", ""),
        ("copyKernels", False),
        ("default", "0"),
        ("grubEfi", ""),
    ]
    for name, value in want:
        if name not in x or x[name] != value or type(x[name]) is not type(value):
            return "grub-config.xml %s is %r, the pin needs %r" % (name, x.get(name), value)
    if not isinstance(x.get("configurationLimit"), int) or isinstance(x.get("configurationLimit"), bool) or x["configurationLimit"] < 1:
        return "grub-config.xml configurationLimit is below 1"
    if not isinstance(x.get("grub"), str) or not STORE_PATH_RE.fullmatch(x["grub"]):
        return "grub-config.xml has no grub store path"
    devs = x.get("devices")
    if not isinstance(devs, list) or not devs or any((not d.startswith("/dev/")) for d in devs):
        return "grub-config.xml devices are not /dev paths"
    if not isinstance(x.get("extraGrubInstallArgs"), list):
        return "grub-config.xml extraGrubInstallArgs is not a list"
    if not isinstance(x.get("efiSysMountPoint"), str):
        return "grub-config.xml has no efiSysMountPoint"
    return None


def compare_state(x, state_text):
    """install-grub.pl's six requireNewInstall inputs against /boot/grub/state
    (None when they all match, so the installer never runs grub-install)."""
    lines = state_text.split("\n")
    if len(lines) < 6:
        return "/boot/grub/state has fewer than 6 lines"
    _name, _version, efi, devices, efi_mount, js = lines[:6]
    try:
        j = json.loads(js) if js.strip() else {}
    except ValueError:
        return "/boot/grub/state line 6 is not JSON"
    if not isinstance(j, dict):
        return "/boot/grub/state line 6 is not an object"
    if set(d for d in devices.split(",") if d) != set(x["devices"]):
        return "devices differ from /boot/grub/state"
    args = j.get("extraGrubInstallArgs", [])
    if not isinstance(args, list) or set(map(str, args)) != set(x["extraGrubInstallArgs"]):
        return "extraGrubInstallArgs differ from /boot/grub/state"
    if efi != "no":
        return "/boot/grub/state efi target is not no"
    if efi_mount != x["efiSysMountPoint"]:
        return "efiSysMountPoint differs from /boot/grub/state"
    if j.get("grub", "") != x["grub"]:
        return "grub differs from /boot/grub/state"
    if j.get("grubEfi", "") != x["grubEfi"]:
        return "grubEfi differs from /boot/grub/state"
    return None


def guard_of(x):
    lines = str(x.get("extraConfig") or "").split("\n")
    return GUARD_ID if any(l.strip() == GUARD_MARKER for l in lines) else None


def boot_area_hash(dev):
    """sha256 over the MBR boot code (bytes 0-445), its signature (510-511) and
    the rest of the first MiB (GRUB's embedding gap); the partition table is
    left out, because growpart rewrites it when the disk grows."""
    real = resolve(dev) or dev
    with open(P(real), "rb") as f:
        data = f.read(1048576)
    if len(data) < 512:
        raise OSError(errno.EIO, "short read", dev)
    h = hashlib.sha256()
    h.update(data[0:446])
    h.update(data[510:512])
    h.update(data[512:])
    return h.hexdigest()


def read_state_text():
    with open(P(GRUB_STATE), "rb") as f:
        return f.read(65536).decode("utf-8", "replace")


def distro_ok(d):
    return isinstance(d, str) and 0 < len(d) <= 64 and all(0x20 <= ord(c) <= 0x7E and c not in '>"\\$\'' for c in d)


def derive_pin(committed, boot_area=True):
    """The pin from the committed system's compat doc, or PinError."""
    cd = read_compat(committed)
    if cd is None:
        raise PinError("the committed system's compat doc is missing or malformed")
    bl = cd.get("bootloader")
    if not isinstance(bl, dict):
        raise PinError("the compat doc has no bootloader")
    installer = bl.get("installer")
    distro = bl.get("distroName")
    if not isinstance(installer, str) or not STORE_PATH_RE.fullmatch(installer):
        raise PinError("the compat doc's bootloader.installer is not a store path")
    if not distro_ok(distro):
        raise PinError("the compat doc's bootloader.distroName is unusable")
    try:
        text = read_file(installer, 65536).decode("utf-8")
    except (OSError, UnicodeDecodeError):
        raise PinError("cannot read install-grub.sh")
    perl, script, xml = parse_installer_script(text)
    try:
        x = parse_grub_xml(read_file(xml, 1048576))
    except OSError:
        raise PinError("cannot read grub-config.xml")
    why = check_xml(x)
    if why:
        raise PinError(why)
    try:
        why = compare_state(x, read_state_text())
    except OSError:
        raise PinError("cannot read /boot/grub/state")
    if why:
        raise PinError(why)
    pin = {"installer": installer, "perl": perl, "script": script, "xml": xml, "grub": x["grub"],
           "devices": list(x["devices"]), "distro": distro, "guard": guard_of(x), "boot_area_sha256": {}}
    if boot_area:
        for dev in pin["devices"]:
            try:
                pin["boot_area_sha256"][dev] = boot_area_hash(dev)
            except OSError:
                raise PinError("cannot read the boot area of %s" % dev)
    return pin


def verify_pin(pin):
    """Re-check the pinned installer against /boot/grub/state (65 bootloader)."""
    if not isinstance(pin, dict):
        raise Fail(65, "bootloader", "no bootloader pin recorded")
    try:
        x = parse_grub_xml(read_file(pin["xml"], 1048576))
        why = check_xml(x) or compare_state(x, read_state_text())
    except (OSError, PinError) as e:
        why = "cannot re-read the pinned installer: %s" % e
    if why is None and (x["grub"] != pin["grub"] or set(x["devices"]) != set(pin["devices"])):
        why = "the pinned installer's grub or devices changed"
    if why:
        raise Fail(65, "bootloader", why)


# --- txn.json --------------------------------------------------------------------------


def _valid_rollback(r):
    return r is None or (isinstance(r, dict) and sys_or_none(r.get("path")) is not None)


def _valid_doc(doc):
    c = doc.get("committed")
    if not isinstance(c, dict) or sys_or_none(c.get("path")) is None:
        return False
    if not _valid_rollback(doc.get("rollback")):
        return False
    pin = doc.get("pin")
    if not isinstance(pin, dict):
        return False
    for k in ("installer", "perl", "script", "xml", "grub", "distro"):
        if not isinstance(pin.get(k), str):
            return False
    if not isinstance(pin.get("devices"), list) or not isinstance(pin.get("boot_area_sha256"), dict):
        return False
    t = doc.get("txn")
    if t is not None:
        if not isinstance(t, dict) or not isinstance(t.get("id"), str) or not TXN_RE.fullmatch(t["id"]):
            return False
        if t.get("state") not in OPEN_STATES + CLOSED_STATES or t.get("kind") not in KINDS:
            return False
        if t.get("target") is not None and sys_or_none(t["target"]) is None:
            return False
        if t.get("pre") is not None and (not isinstance(t["pre"], dict) or not _valid_rollback(t["pre"].get("rollback"))):
            return False
    if not isinstance(doc.get("history", []), list):
        return False
    return True


def read_doc():
    """txn.json, or None when absent. A file this tool cannot parse is never
    overwritten: 70 (txn_unreadable); a newer schema is 65 `schema`."""
    try:
        fd = os.open(P(TXN_FILE), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise Fail(70, "internal", "txn.json is unreadable: %s" % e.strerror)
    try:
        with os.fdopen(fd, "rb") as f:
            data = f.read(4 * 1048576)
    except OSError as e:
        raise Fail(70, "internal", "txn.json is unreadable: %s" % e.strerror)
    try:
        doc = json.loads(data)
    except ValueError:
        raise Fail(70, "internal", "txn.json does not parse")
    if not isinstance(doc, dict) or not isinstance(doc.get("schema"), int) or isinstance(doc.get("schema"), bool):
        raise Fail(70, "internal", "txn.json has no schema")
    if doc["schema"] > TXN_SCHEMA:
        raise Fail(65, "schema", "txn.json schema %d is newer than this tool's %d" % (doc["schema"], TXN_SCHEMA))
    if doc["schema"] < 1 or not _valid_doc(doc):
        raise Fail(70, "internal", "txn.json is malformed")
    return doc


def write_doc(ctx, doc):
    doc["seq"] = int(doc.get("seq") or 0) + 1
    doc["writer"] = {"tool": tool_realpath(), "argv0_system": argv0_system(ctx.argv0)}
    if doc.get("txn"):
        doc["txn"]["updated_at"] = now()
    data = (json.dumps(doc, ensure_ascii=True, sort_keys=True, indent=1) + "\n").encode("ascii")
    os.makedirs(P(STATE_DIR), mode=0o700, exist_ok=True)
    os.chmod(P(STATE_DIR), 0o700)
    ctx.mutated = True
    atomic_write(P(TXN_FILE), data, 0o600)


def new_doc(committed, pin):
    return {"schema": TXN_SCHEMA, "seq": 0,
            "committed": {"path": committed, "closure": None, "since": now()},
            "rollback": None, "staged": None, "pin": pin, "txn": None, "history": [],
            "writer": None}


# --- the compat doc and the guest compat rules ----------------------------------------


def read_compat(system):
    if not system:
        return None
    try:
        data = read_file(system + "/" + COMPAT_NAME, COMPAT_MAX + 1)
    except OSError:
        return None
    if len(data) > COMPAT_MAX:
        return None
    try:
        d = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def title_version_ok(version):
    """Rule xiii's nixos-version clause, on the file's bytes (one trailing
    newline dropped, as install-grub.pl's readFile chomps it): what a profile
    entry's title carries, `[ -~]{1,128}` and title-safe."""
    if version.endswith(b"\n"):
        version = version[:-1]
    return 1 <= len(version) <= 128 and all(0x20 <= b <= 0x7E and b not in b'>"\\$' for b in version)


def compat_problem(target, committed):
    """The first guest compat rule the target fails (`compat:<rule>[:<field>]`),
    or None. These run before any profile points at the target: install-grub.pl
    silently skips an unbootable toplevel and leaves an empty submenu, which
    GRUB rejects for the whole file."""
    cd = read_compat(committed)
    if cd is None:
        raise Fail(69, "unavailable", "the committed system's compat doc is missing or malformed")
    td = read_compat(target)
    if td is None:
        return "compat:doc"
    if td.get("schema") != COMPAT_SCHEMA or isinstance(td.get("schema"), bool):
        return "compat:x:schema"
    if td.get("kind") != COMPAT_KIND:
        return "compat:x:kind"
    if not isinstance(td.get("release"), dict):
        return "compat:x:release"
    for f in ("hostKeyPath", "stateDevice", "guestDevice", "interface", "controlUser"):
        if td.get(f) != cd.get(f):
            return "compat:vi:" + f
    if td.get("stateFormat") != cd.get("stateFormat"):
        return "compat:viii:stateFormat"
    if td.get("txnSchema") != cd.get("txnSchema"):
        return "compat:ix:txnSchema"
    if td.get("specialisations") != []:
        return "compat:xi:specialisations"
    spec = resolve(target + "/specialisation")
    if spec is not None:
        try:
            if os.listdir(P(spec)):
                return "compat:xi:specialisation"
        except OSError:
            return "compat:xi:specialisation"
    for f in ("kernel", "initrd", "init", "kernel-params", "nixos-version"):
        if resolve(target + "/" + f) is None:
            return "compat:xiii:" + f
    # The target's own tool, an executable regular file: once the target is
    # committed, the argv[0] rule lets only <target>/sw/bin/cogworx-pve-upgrade
    # abort, release or move it on. A composition that replaced
    # environment.systemPackages (mkForce) would otherwise strand the guest.
    tool = resolve(target + TOOL_REL)
    try:
        st = os.stat(P(tool)) if tool else None
    except OSError:
        st = None
    if st is None or not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
        return "compat:xiii:" + TOOL_REL[1:]
    # install-grub.pl runs <toplevel>/append-initrd-secrets as root for every
    # system it renders: the target's own code would run at arm, before any
    # trial, and its failure is fatal for entry 0 (commit step 5). nixpkgs
    # links it into a toplevel only when boot.initrd.secrets is set.
    if lexists(target + "/append-initrd-secrets"):
        return "compat:xiii:append-initrd-secrets"
    try:
        version = read_file(target + "/nixos-version", 4096)
        params = read_file(target + "/kernel-params", 65536).decode("utf-8", "replace")
    except OSError:
        return "compat:xiii:unreadable"
    if not title_version_ok(version):
        return "compat:xiii:nixos-version"
    tokens = params.split()
    if "boot.panic_on_fail" not in tokens:
        return "compat:xii:boot.panic_on_fail"
    panics = [t[6:] for t in tokens if t.startswith("panic=")]
    if not panics or not re.fullmatch(r"[0-9]{1,9}", panics[-1]) or int(panics[-1]) < 1:
        return "compat:xii:panic"
    return None


# --- closure digest --------------------------------------------------------------------


def closure_digest(target):
    """sha256 over `<path> sha256:<nix32>\\n` for every path of the target's
    closure, sorted by byte order: (digest, paths, nar bytes). DB-recorded
    hashes only; no lock, no txn.json, unprivileged."""
    ns = which("nix-store")
    r = run_cmd([ns, "-qR", target], 300)
    if r.returncode != 0:
        raise Fail(69, "unavailable", "nix-store -qR failed: " + last_line(r.stderr))
    paths = [l for l in r.stdout.decode("utf-8", "replace").split("\n") if l]
    if target not in paths or any(not STORE_PATH_RE.fullmatch(p) for p in paths):
        raise Fail(70, "internal", "unexpected nix-store -qR output")
    paths = sorted(set(paths), key=lambda s: s.encode())
    hashes, sizes = [], []
    for i in range(0, len(paths), 500):
        batch = paths[i:i + 500]
        for flag, sink in (("--hash", hashes), ("--size", sizes)):
            r = run_cmd([ns, "-q", flag] + batch, 300)
            out = [l for l in r.stdout.decode("utf-8", "replace").split("\n") if l]
            if r.returncode != 0 or len(out) != len(batch):
                raise Fail(70, "internal", "nix-store -q %s failed: %s" % (flag, last_line(r.stderr)))
            sink.extend(out)
    h = hashlib.sha256()
    for p, x in zip(paths, hashes):
        h.update(("%s %s\n" % (p, normalize_hash(x))).encode("ascii"))
    try:
        nar = sum(int(s) for s in sizes)
    except ValueError:
        raise Fail(70, "internal", "nix-store -q --size printed a non-number")
    return h.hexdigest(), len(paths), nar


# --- the lock ----------------------------------------------------------------------------


class Lock:
    def __init__(self):
        self.fd = None

    def acquire(self, what, txn, wait=0.0):
        try:
            fd = os.open(P(LOCK_FILE), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except OSError as e:
            raise Fail(69, "unavailable", "cannot open the lock: %s" % e.strerror)
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if e.errno not in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                    os.close(fd)
                    raise
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise Fail(75, "busy", "the upgrade lock is held")
                time.sleep(0.2)
        self.fd = fd
        try:
            atomic_write(P(HOLDER_FILE), json.dumps({"pid": os.getpid(), "what": what, "txn": txn}).encode(), 0o600)
        except OSError as e:
            diag("cannot write the holder note: %s" % e)

    def release(self):
        if self.fd is None:
            return
        note = read_json_file(HOLDER_FILE)
        if note and note.get("pid") == os.getpid():
            try:
                os.unlink(P(HOLDER_FILE))
            except OSError:
                pass
        os.close(self.fd)
        self.fd = None


def lock_info():
    """Who holds the lock, from /proc/locks: never by probing the lock."""
    out = {"held": False, "holder": None, "pid": None}
    try:
        st = os.stat(P(LOCK_FILE))
        with open(P("/proc/locks"), "r", encoding="ascii", errors="replace") as f:
            text = f.read(1048576)
    except OSError:
        return out
    for line in text.splitlines():
        fl = line.split()
        if len(fl) < 6 or fl[1] == "->" or fl[1] != "FLOCK" or fl[3] != "WRITE":
            continue
        dev = fl[5].split(":")
        if len(dev) != 3:
            continue
        try:
            maj, mn, ino, pid = int(dev[0], 16), int(dev[1], 16), int(dev[2]), int(fl[4])
        except ValueError:
            continue
        if ino == st.st_ino and maj == os.major(st.st_dev) and mn == os.minor(st.st_dev):
            out["held"], out["pid"] = True, pid
            break
    if out["held"]:
        note = read_json_file(HOLDER_FILE)
        if note and note.get("pid") == out["pid"]:
            what = str(note.get("what") or "")
            out["holder"] = "fetch-worker" if what == "fetch-worker" else "verb" if what.startswith("verb:") else "unknown"
        else:
            try:
                with open(P("/proc/%d/comm" % out["pid"]), "rb") as f:
                    comm = f.read(64).strip()
            except OSError:
                comm = b""
            out["holder"] = "gc" if comm == b"flock" else "unknown"
    return out


def cgroup_leaf(path):
    """The last component of a /proc/<pid>/cgroup's unified (0::) line, or of
    its last line on a v1 hierarchy; None when unreadable."""
    try:
        with open(P(path), "r", encoding="ascii", errors="replace") as f:
            lines = [l for l in f.read(65536).splitlines() if l]
    except OSError:
        return None
    v2 = [l for l in lines if l.startswith("0::")]
    line = v2[0] if v2 else (lines[-1] if lines else "")
    return line.rsplit("/", 1)[-1]


def is_worker_pid(pid):
    """A pid from the holder note or progress.json counts as the fetch worker
    only while it is alive AND inside the worker's unit: a SIGKILLed worker
    leaves both files behind, and its pid may be reused in the same boot."""
    return pid_alive(pid) and cgroup_leaf("/proc/%d/cgroup" % pid) == FETCH_UNIT + ".service"


def worker_info():
    note = read_json_file(HOLDER_FILE)
    if note and note.get("what") == "fetch-worker" and is_worker_pid(note.get("pid")):
        return {"active": True, "txn": note.get("txn")}
    pr = read_json_file(PROGRESS_FILE)
    if pr and pr.get("phase") != "done" and is_worker_pid(pr.get("pid")):
        return {"active": True, "txn": pr.get("txn")}
    return {"active": False, "txn": None}


def write_progress(tid, phase, **extra):
    try:
        os.makedirs(P(PROGRESS_DIR), mode=0o700, exist_ok=True)
        cur = read_json_file(PROGRESS_FILE) or {}
        if cur.get("txn") != tid or cur.get("pid") != os.getpid():
            cur = {}
        doc = {"pid": os.getpid(), "txn": tid, "phase": phase,
               "attempt": cur.get("attempt"), "missing_at_start": cur.get("missing_at_start"),
               "started_at": cur.get("started_at") or now(), "updated_at": now()}
        doc.update(extra)
        atomic_write(P(PROGRESS_FILE), json.dumps(doc, sort_keys=True).encode(), 0o600)
    except OSError as e:
        diag("cannot write progress: %s" % e)


# --- observing the guest -----------------------------------------------------------------


class Snap:
    """Everything `status` and the verbs read: files and symlinks only."""


def cogworx_profile_names():
    try:
        names = os.listdir(P(SYSTEM_PROFILES_DIR))
    except OSError:
        return []
    out = set()
    for e in names:
        m = re.fullmatch(r"(\w+)(?:-[0-9]+-link)?", e, re.ASCII)
        if m and m.group(1).startswith("cogworx_"):
            out.add(m.group(1))
    return sorted(out)


def observe(doc):
    s = Snap()
    s.booted = sys_or_none(resolve(BOOTED))
    s.current = resolve(CURRENT)
    s.head = resolve(SYSTEM_PROFILE)
    s.candidate_present = lexists(CANDIDATE)
    s.candidate = resolve(CANDIDATE) if s.candidate_present else None
    s.rollback_present = lexists(ROLLBACK)
    s.rollback = resolve(ROLLBACK) if s.rollback_present else None
    s.cogworx_profiles = cogworx_profile_names()
    if doc is not None:
        s.distro = doc["pin"]["distro"]
    else:
        bl = (read_compat(s.booted) or {}).get("bootloader")
        d = bl.get("distroName") if isinstance(bl, dict) else None
        s.distro = d if distro_ok(d) else "NixOS"
    try:
        with open(P(GRUB_CFG), "rb") as f:
            s.cfg_bytes = f.read(4 * 1048576)
        s.parse = parse_grub_cfg(s.cfg_bytes.decode("latin-1"), s.distro)
    except OSError:
        s.cfg_bytes, s.parse = None, None
    s.entry0_init = s.parse["entry0"]["init"] if s.parse and s.parse["entry0"] else None
    try:
        with open(P(GRUBENV), "rb") as f:
            s.env_bytes = f.read(ENV_SIZE + 1)
        s.env_present = True
    except FileNotFoundError:
        s.env_bytes, s.env_present = None, False
    except OSError:
        s.env_bytes, s.env_present = b"", True
    s.env = parse_grubenv(s.env_bytes) if s.env_present else None
    env = s.env or {}
    s.next_entry = env.get("next_entry") or None
    s.cwx_rollback_entry = env.get("cwx_rollback_entry") or None
    s.cwx_once = env.get("cwx_once") if "cwx_once" in env else None
    return s


def bootstrap_problem(s):
    """Why the guest cannot be bootstrapped (no txn.json yet), or None."""
    if s.booted is None:
        return "no /run/booted-system"
    if s.cogworx_profiles:
        return "untracked system profile(s): %s" % " ".join(s.cogworx_profiles)
    if s.head != s.booted:
        return "the system profile head is not the booted system"
    if s.entry0_init != s.booted:
        return "grub.cfg entry 0 is not the booted system"
    return None


def committed_of(doc, s):
    if doc is not None:
        return doc["committed"]["path"]
    why = bootstrap_problem(s)
    if why:
        raise Fail(65, "bootstrap-inconsistent", "cannot bootstrap: " + why)
    return s.booted


def pin_state(doc):
    if doc is None:
        return "unpinned"
    try:
        verify_pin(doc["pin"])
        return "pinned"
    except Fail:
        return "mismatch"


def crash_tokens(doc, s, committed, held, worker_active, pin_st=None):
    """crash_state: the inconsistencies a repair verb (or an admin) must clear.
    `held` says another process holds the lock; a verb computes this under its
    own lock, so it passes False. While another holder runs, the tokens are a
    snapshot taken inside one of its steps: decide on them only once
    `lock.held` is false. A missing grubenv is not a token (arm creates it;
    `grubenv_ok` is false); a present but invalid one is."""
    toks = []

    def add(t):
        if t not in toks:
            toks.append(t)

    t = doc.get("txn") if doc else None
    st = t["state"] if t else None
    if doc is None:
        if s.cogworx_profiles:
            add("untracked_profile")
        if s.booted is not None and (s.head != s.booted or s.entry0_init != s.booted):
            add("bootstrap_inconsistent")
    if committed is not None:
        if s.head != committed and st not in ("committing", "reverting", "aborting"):
            add("head_mismatch")
        if s.entry0_init != committed and st not in ("committing", "reverting", "aborting", "releasing"):
            add("entry0_mismatch")
    if doc is not None:
        if s.candidate_present:
            if st not in ("arming", "armed", "committing", "aborting"):
                add("orphan_candidate")
            elif s.candidate != t.get("target"):
                add("candidate_mismatch")
        if s.next_entry and st not in ("arming", "armed"):
            add("orphan_next_entry")
        recorded = doc["rollback"]["path"] if doc.get("rollback") else None
        if st not in ("committing", "reverting", "releasing", "aborting"):
            if (s.rollback_present or recorded) and s.rollback != recorded:
                add("rollback_mismatch")
        if [n for n in s.cogworx_profiles if n not in ("cogworx_candidate", "cogworx_rollback")]:
            add("untracked_profile")
        if st in IN_PROGRESS and not held and (st != "fetching" or not worker_active):
            add("interrupted")
        if (pin_st or pin_state(doc)) == "mismatch":
            add("bootloader_pin_mismatch")
        known = {committed, recorded, t.get("target") if t else None}
        if s.booted is not None and s.booted not in known:
            add("booted_unknown")
    if s.env_present and s.env is None:
        add("grubenv_invalid")
    if s.parse is None or s.parse["errors"]:
        add("grubcfg_invalid")
    if s.booted is not None and s.current != s.booted:
        add("current_differs")
    return toks


# --- status -------------------------------------------------------------------------------


def current_guard(doc, s):
    if doc is not None:
        return doc["pin"]["guard"]
    try:
        return derive_pin(s.booted, boot_area=False)["guard"] if s.booted else None
    except (PinError, Fail, OSError):
        return None


def build_status(ctx):
    doc, doc_err = None, None
    try:
        doc = read_doc()
    except Fail as f:
        doc_err = f
    s = observe(doc)
    if doc is not None:
        committed, source = doc["committed"]["path"], "txn"
    else:
        committed, source = None, "bootstrap"
        if doc_err is None and bootstrap_problem(s) is None:
            committed = s.booted
    li = lock_info()
    wk = worker_info()
    t = doc.get("txn") if doc else None
    pst = pin_state(doc) if doc_err is None else "mismatch"
    if doc_err is not None:
        toks = ["txn_unreadable"]
        if s.booted is not None and s.current != s.booted:
            toks.append("current_differs")
    else:
        toks = crash_tokens(doc, s, committed, li["held"],
                            wk["active"] and t is not None and wk["txn"] == t["id"], pst)

    pin = {"state": pst, "installer": None, "perl": None, "script": None, "xml": None, "grub": None,
           "devices": [], "distro": None, "guard": None, "boot_area_sha256": {}}
    src_pin = doc["pin"] if doc else None
    if src_pin is None and doc_err is None and s.booted:
        try:
            src_pin = derive_pin(s.booted, boot_area=False)
        except (PinError, Fail, OSError):
            src_pin = None
    if src_pin:
        for k in ("installer", "perl", "script", "xml", "grub", "devices", "distro", "guard", "boot_area_sha256"):
            pin[k] = src_pin.get(k)

    def entry(name):
        p = (s.parse or {}).get("profiles", {}).get(name)
        return {"path": p["path"], "init": p["init"]} if p else None

    txn = None
    if t:
        prog = read_json_file(PROGRESS_FILE)
        txn = {"schema": doc["schema"], "id": t["id"], "kind": t["kind"], "state": t["state"],
               "committed": committed, "target": t.get("target"), "closure": t.get("closure"),
               "reason_class": t.get("reason_class"), "reason": t.get("reason"),
               "progress": prog if prog and prog.get("txn") == t["id"] else None,
               "opened_at": t.get("opened_at"), "updated_at": t.get("updated_at"),
               "closed_at": t.get("closed_at")}
    rb = doc.get("rollback") if doc else None
    try:
        free = int(statvfs_free(P("/nix/store")))
    except OSError:
        free = None
    return {
        "booted": s.booted,
        "current": s.current,
        "system_head": s.head,
        "committed": committed,
        "committed_source": source,
        "entry0_init": s.entry0_init,
        "candidate": s.candidate,
        "rollback": {"path": s.rollback, "recorded": rb["path"] if rb else None,
                     "retain_until": rb.get("retain_until") if rb else None},
        "next_entry": s.next_entry,
        "cwx_rollback_entry": s.cwx_rollback_entry,
        "cwx_once": s.cwx_once,
        "grubenv_ok": s.env is not None,
        "grubcfg": {"ok": bool(s.parse) and not s.parse["errors"],
                    "sha256": hashlib.sha256(s.cfg_bytes).hexdigest() if s.cfg_bytes is not None else None,
                    "errors": list(s.parse["errors"]) if s.parse else ["unreadable"],
                    "entry0_title": s.parse["entry0"]["title"] if s.parse and s.parse["entry0"] else None,
                    "candidate_entry": entry("cogworx_candidate"),
                    "rollback_entry": entry("cogworx_rollback")},
        "bootloader_pin": pin,
        "txn": txn,
        "compat": {"committed": read_compat(committed),
                   "target": read_compat(t.get("target")) if t else None},
        "free_bytes": free,
        "lock": li,
        "worker": wk,
        "trial": bool(t and t["state"] == "armed" and s.booted == t.get("target")),
        "crash_state": toks,
    }


# --- the mutating machinery ----------------------------------------------------------------


def require_booted(s):
    if s.booted is None:
        raise Fail(69, "unavailable", "no /run/booted-system (or it is not a system toplevel)")


def check_argv0(ctx, doc, s):
    if ctx.verb == "revert-commit":
        if doc is None or not doc.get("rollback"):
            raise Fail(65, "state", "no rollback is recorded")
        required = doc["rollback"]["path"]
    else:
        required = committed_of(doc, s)
    if argv0_system(ctx.argv0) != required:
        raise Fail(65, "not-committed-tool", "argv[0] is not %s%s" % (required, TOOL_REL))


def one_shot_pending():
    try:
        with open(P(GRUBENV), "rb") as f:
            env = parse_grubenv(f.read(ENV_SIZE + 1))
    except OSError:
        env = None
    return bool(env and env.get("next_entry"))


def rereport(ctx, doc):
    """True when --txn already reached this verb's outcome (exit 0, mutated
    false): checked before the argv[0] rule, so an old tool may re-ask."""
    t = doc.get("txn") if doc else None
    if not t or t["id"] != ctx.opts.get("--txn"):
        return False
    st, v = t["state"], ctx.verb
    if v == "commit":
        return st == "committed"
    if v == "abort":
        return st in ("aborted", "repaired")
    if v == "revert-commit":
        return st == "reverted"
    if v == "release":
        return st == "released"
    if v == "arm":
        # "armed" is the outcome only while the one-shot is still pending: a
        # boot that consumed it (d:, u:, or a trial followed by a reboot)
        # leaves the txn armed but nothing armed in GRUB.
        return st == "armed" and one_shot_pending()
    if v == "fetch":
        same = t.get("target") == ctx.opts["--target"] and t.get("closure") == ctx.opts["--closure"]
        wk = worker_info()
        return same and (st == "fetched" or (st == "fetching" and wk["active"] and wk["txn"] == t["id"]))
    return False


def ensure_bootstrapped(ctx, doc, s, committed):
    """The first mutating verb pins the bootloader and roots the committed
    system; the caller's first write then persists the document."""
    if doc is not None:
        return doc
    try:
        pin = derive_pin(committed)
    except PinError as e:
        raise Fail(69, "unavailable", "cannot pin the bootloader: %s" % e)
    set_gcroot(ctx, "bootloader", pin["installer"])
    set_gcroot(ctx, "committed", committed)
    return new_doc(committed, pin)


def set_gcroot(ctx, name, target):
    os.makedirs(P(GCROOTS), mode=0o755, exist_ok=True)
    link = GCROOTS + "/" + name
    try:
        if os.readlink(P(link)) == target:
            return
    except OSError:
        pass
    ctx.mutated = True
    tmp = P(link + ".tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    os.symlink(target, tmp)
    os.rename(tmp, P(link))
    fsync_dir(P(GCROOTS))


def remove_gcroot(ctx, name):
    try:
        os.unlink(P(GCROOTS + "/" + name))
        ctx.mutated = True
        fsync_dir(P(GCROOTS))
    except FileNotFoundError:
        pass


def profile_set(ctx, profile, path):
    ctx.mutated = True
    r = run_cmd([which("nix-env"), "-p", P(profile), "--set", path])
    if r.returncode != 0 or resolve(profile) != path:
        raise Fail(70, "internal", "nix-env -p %s --set failed: %s" % (profile, last_line(r.stderr)))


def profile_delete_old(ctx, profile):
    ctx.mutated = True
    r = run_cmd([which("nix-env"), "-p", P(profile), "--delete-generations", "old"])
    if r.returncode != 0:
        raise Fail(70, "internal", "nix-env --delete-generations old failed: " + last_line(r.stderr))


def remove_profile(ctx, profile):
    """Unlink the profile and every generation link of it (they are GC roots,
    and install-grub.pl never shows them, so a leftover leaks a closure)."""
    d, name = os.path.split(profile)
    try:
        names = os.listdir(P(d))
    except FileNotFoundError:
        return
    pat = re.compile(re.escape(name) + r"-[0-9]+-link")
    for e in names:
        if e == name or pat.fullmatch(e):
            ctx.mutated = True
            os.unlink(P(d + "/" + e))
    fsync_dir(P(d))


def ensure_profiles_dir():
    os.makedirs(P(SYSTEM_PROFILES_DIR), mode=0o755, exist_ok=True)


def installer(ctx, doc, toplevel):
    """One run of the pinned installer for `toplevel` as entry 0; returns the
    fresh grub.cfg parse. 65 bootloader if anything but grub.cfg changed."""
    pin = doc["pin"]
    verify_pin(pin)
    try:
        before = read_file(GRUB_STATE, 65536)
    except OSError:
        raise Fail(65, "bootloader", "cannot read /boot/grub/state")
    argv = [P(pin["perl"]), pin["script"], pin["xml"], toplevel]
    ctx.mutated = True
    t0 = time.monotonic()
    try:
        r = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=child_env(), timeout=INSTALLER_TIMEOUT, close_fds=True)
    except subprocess.TimeoutExpired:
        sync()
        raise Fail(65, "bootloader", "the installer timed out")
    except OSError as e:
        raise Fail(65, "bootloader", "cannot run the pinned installer: %s" % e.strerror)
    sync()
    diag("installer run for %s: exit %d in %.2fs" % (toplevel, r.returncode, time.monotonic() - t0))
    if r.stderr.strip():
        diag("installer: " + r.stderr.decode("utf-8", "replace").strip()[-4000:])
    if r.returncode != 0:
        raise Fail(65, "bootloader", "the installer exited %d: %s" % (r.returncode, last_line(r.stderr)))
    try:
        after = read_file(GRUB_STATE, 65536)
    except OSError:
        after = None
    if after != before:
        raise Fail(65, "bootloader", "/boot/grub/state changed during an installer run (grub-install ran)")
    for dev, want in (pin.get("boot_area_sha256") or {}).items():
        try:
            got = boot_area_hash(dev)
        except OSError:
            got = None
        if got != want:
            raise Fail(65, "bootloader", "the boot area of %s changed during an installer run" % dev)
    try:
        with open(P(GRUB_CFG), "rb") as f:
            return parse_grub_cfg(f.read(4 * 1048576).decode("latin-1"), pin["distro"])
    except OSError:
        return {"entry0": None, "submenus": [], "profiles": {}, "errors": ["unreadable"]}


def cfg_problem(parse, entry0, candidate, rollback):
    """Why a fresh parse is not the expected menu, or None."""
    if parse["errors"]:
        return "grub.cfg has errors: " + ",".join(parse["errors"])
    e0 = parse["entry0"]
    if not e0 or e0["init"] != entry0:
        return "grub.cfg entry 0 is not %s" % entry0
    want = {}
    if candidate:
        want["cogworx_candidate"] = candidate
    if rollback:
        want["cogworx_rollback"] = rollback
    have = parse["profiles"]
    if set(have) != set(want):
        return "grub.cfg cogworx submenus are [%s], expected [%s]" % (" ".join(sorted(have)), " ".join(sorted(want)))
    for name, path in want.items():
        if have[name]["init"] != path:
            return "grub.cfg %s entry is not %s" % (name, path)
    return None


def env_value_ok(v):
    return isinstance(v, str) and all(0x20 <= ord(c) <= 0x7E and c != "\\" for c in v)


def env_write(ctx, doc, sets=None, unsets=(), create=False):
    """Edit grubenv with the PINNED grub's grub-editenv. Creates the block when
    asked, when it is invalid, or when it is absent and something is set."""
    sets = dict(sets or {})
    exe = P(doc["pin"]["grub"] + "/bin/grub-editenv")
    path = P(GRUBENV)
    try:
        with open(path, "rb") as f:
            data = f.read(ENV_SIZE + 1)
    except FileNotFoundError:
        data = None
    except OSError:
        data = b""
    cur = parse_grubenv(data) if data is not None else None
    if cur is None and (create or sets or data is not None):
        ctx.mutated = True
        r = run_cmd([exe, path, "create"], 30)
        if r.returncode != 0:
            raise Fail(65, "grubenv", "grub-editenv create failed: " + last_line(r.stderr))
        with open(path, "rb") as f:
            data = f.read(ENV_SIZE + 1)
        cur = parse_grubenv(data)
        if cur is None:
            raise Fail(65, "grubenv", "grub-editenv created an invalid block")
    if cur is None:
        return {}
    for k, v in sets.items():
        if not env_value_ok(v):
            raise Fail(65, "grubenv", "refusing to write an unprintable grubenv value for " + k)
    drop = [k for k in unsets if k in cur and k not in sets]
    used = env_used(data)
    for k in drop + [k for k in sets if k in cur]:
        used -= env_line_len(k, cur[k])
    used += sum(env_line_len(k, v) for k, v in sets.items())
    if used > ENV_SIZE:
        raise Fail(65, "grubenv", "the grubenv block would overflow %d bytes" % ENV_SIZE)
    if drop:
        ctx.mutated = True
        r = run_cmd([exe, path, "unset"] + drop, 30)
        if r.returncode != 0:
            raise Fail(65, "grubenv", "grub-editenv unset failed: " + last_line(r.stderr))
    if sets:
        ctx.mutated = True
        r = run_cmd([exe, path, "set"] + ["%s=%s" % kv for kv in sorted(sets.items())], 30)
        if r.returncode != 0:
            raise Fail(65, "grubenv", "grub-editenv set failed: " + last_line(r.stderr))
    with open(path, "rb") as f:
        got = parse_grubenv(f.read(ENV_SIZE + 1))
    if got is None or any(got.get(k) != v for k, v in sets.items()) or any(k in got for k in drop):
        raise Fail(65, "grubenv", "grubenv read-back mismatch")
    return got


def store_path_valid(path):
    """Whether nix's database holds `path` as valid. A GC invalidates a path
    before it deletes the directory, so a cut inside a GC can leave the
    directory present and invalid; presence alone is not validity. An error
    (rather than an answer) is 70: never a reason to drop a rollback."""
    r = run_cmd([which("nix-store"), "--check-validity", "--print-invalid", path], 30)
    if r.returncode != 0:
        raise Fail(70, "internal", "nix-store --check-validity failed: " + last_line(r.stderr))
    return path not in r.stdout.decode("utf-8", "replace").split()


def restore_rollback(ctx, want):
    """Point the rollback profile at `want` (a rollback record or None).
    Returns the record that holds afterwards: None when the recorded system is
    no longer in the store (a GC ran after it lost its last root, or was cut
    after invalidating it but before deleting it)."""
    if want is None:
        remove_profile(ctx, ROLLBACK)
        return None
    if resolve(ROLLBACK) == want["path"]:
        return want
    if resolve(want["path"]) is None or not store_path_valid(want["path"]):
        diag("rollback %s is gone from the store; dropping the rollback" % want["path"])
        remove_profile(ctx, ROLLBACK)
        return None
    ensure_profiles_dir()
    profile_set(ctx, ROLLBACK, want["path"])
    profile_delete_old(ctx, ROLLBACK)
    return want


def pre_image(doc, s):
    rb = doc.get("rollback")
    return {"rollback": dict(rb) if rb else None, "cwx_rollback_entry": s.cwx_rollback_entry}


class Ctx:
    def __init__(self, argv):
        self.argv = list(argv)
        self.argv0 = self.argv[0] if self.argv else ""
        self.verb = None
        self.opts = {}
        self.mutated = False
        self.lock = Lock()
        self.lock_wait = 0.0

    def step(self, n, name):
        sync()
        if STEP_HOOK is not None:
            STEP_HOOK(self.verb, n, name)

    def envelope(self, code, cls, reason, extra=None, with_status=True):
        env = {"cogworx_pve_upgrade": TOOL_PROTO, "verb": self.verb, "ok": code == 0, "exit": code,
               "reason_class": cls, "reason": clean(reason) if reason is not None else None,
               "txn_id": self.opts.get("--txn"), "mutated": self.mutated}
        if extra:
            env.update(extra)
        if with_status:
            try:
                env["status"] = build_status(self)
            except Exception as e:
                diag("cannot build status: %s: %s" % (type(e).__name__, e))
        return env

    def run(self):
        try:
            self.verb, self.opts = parse_argv(self.argv)
        except Usage as u:
            self.verb = self.argv[1] if len(self.argv) > 1 and self.argv[1] in GRAMMAR else None
            return self.envelope(64, "usage", "usage: %s" % u, with_status=False)
        if self.verb == "_fetch":
            why = worker_context_problem()
            if why:
                return self.envelope(64, "usage", "usage: " + why, with_status=False)
        try:
            code, cls, reason, extra, with_status = HANDLERS[self.verb](self)
        except Fail as f:
            # proto and closure-digest never carry status, failing or not
            # (closure-digest runs on workstations, whose /run is not a guest).
            code, cls, reason, extra = f.code, f.cls, f.reason, None
            with_status = self.verb not in ("proto", "closure-digest")
        finally:
            self.lock.release()
        return self.envelope(code, cls, reason, extra=extra, with_status=with_status)


def mutating(ctx, body, pre_lock=None):
    """Order of checks: re-report, booted, argv[0], lock, then again under the
    lock (another verb may have finished in between), then the verb."""
    doc = read_doc()
    if rereport(ctx, doc):
        return 0, None, "already done", None, True
    s = observe(doc)
    require_booted(s)
    check_argv0(ctx, doc, s)
    if pre_lock:
        pre_lock(ctx, doc)
    ctx.lock.acquire("verb:" + ctx.verb, ctx.opts.get("--txn"), wait=ctx.lock_wait)
    doc = read_doc()
    if rereport(ctx, doc):
        return 0, None, "already done", None, True
    s = observe(doc)
    require_booted(s)
    check_argv0(ctx, doc, s)
    return body(ctx, doc, s)


def ok(reason=None):
    return 0, None, reason, None, True


def refuse_crash(doc, s, committed, allowed):
    toks = crash_tokens(doc, s, committed, False, worker_info()["active"])
    bad = [t for t in toks if t not in allowed]
    if bad:
        raise Fail(65, "crash-state", "crash_state is not clean: " + " ".join(bad))


def open_txn(doc):
    t = doc.get("txn") if doc else None
    return t if t and t["state"] in OPEN_STATES else None


def closed_id(doc, tid):
    """True when `tid` names a closed txn txn.json still records: the newest
    txn, or any `history` entry (the last HISTORY_MAX). Consulted only when no
    txn is open: fetch, abort, revert-commit and release refuse to open a new
    txn under such an id, so a stale retry of an older leg (cogworxd adopting
    a crashed operation by its recorded id) never acts on a newer state."""
    t = doc.get("txn") if doc else None
    if t and t["id"] == tid and t["state"] in CLOSED_STATES:
        return True
    return any(isinstance(h, dict) and h.get("id") == tid for h in (doc or {}).get("history") or [])


# --- verbs: read-only --------------------------------------------------------------------


def h_proto(ctx):
    guard = None
    try:
        try:
            doc = read_doc()
        except Fail:
            doc = None
        guard = current_guard(doc, observe(doc))
    except Exception as e:
        diag("proto: guard unknown: %s" % e)
    payload = {"proto": TOOL_PROTO, "txn_schema": [TXN_SCHEMA], "compat_schema": [COMPAT_SCHEMA],
               "verbs": list(PUBLIC_VERBS), "tool": tool_realpath(), "guard": guard}
    return 0, None, None, {"proto": payload}, False


def h_status(ctx):
    if sys_or_none(resolve(BOOTED)) is None:
        return 69, "unavailable", "no /run/booted-system (or it is not a system toplevel)", None, True
    return ok()


def h_closure_digest(ctx):
    target = ctx.opts["--target"]
    digest, n, nar = closure_digest(target)
    return 0, None, None, {"closure_digest": {"target": target, "closure": digest, "paths": n,
                                              "nar_bytes": nar}}, False


# --- verbs: fetch and the worker --------------------------------------------------------


def h_fetch(ctx):
    return mutating(ctx, fetch_body)


def fetch_body(ctx, doc, s):
    tid, target, closure = ctx.opts["--txn"], ctx.opts["--target"], ctx.opts["--closure"]
    committed = committed_of(doc, s)
    if s.booted != committed:
        raise Fail(65, "booted-mismatch", "fetch needs the committed system booted")
    if target == committed:
        raise Fail(65, "state", "the target is the committed system")
    t = open_txn(doc)
    resume = False
    if t:
        if t["id"] != tid:
            raise Fail(65, "txn-mismatch", "the open txn is %s" % t["id"])
        if t.get("target") != target or t.get("closure") != closure:
            raise Fail(65, "txn-mismatch", "the target or closure differs from the open txn")
        if t["state"] not in ("fetching", "fetch_failed"):
            raise Fail(65, "state", "the txn is %s" % t["state"])
        if t["state"] == "fetching":
            wk = worker_info()
            if wk["active"] and wk["txn"] == tid:
                return ok("the fetch worker is running")
        resume = True
    elif closed_id(doc, tid):
        raise Fail(65, "state", "txn %s is closed" % tid)
    refuse_crash(doc, s, committed, ("current_differs",) + (("interrupted",) if resume else ()))
    doc = ensure_bootstrapped(ctx, doc, s, committed)

    # 1: write fetching.
    prev = (t.get("fetch") or {}) if resume else {}
    nt = dict(t) if resume else new_txn(tid, "switch", "fetching", target, closure)
    nt.update(state="fetching", reason_class=None, reason=None)
    nt["fetch"] = {"attempts": int(prev.get("attempts") or 0) + 1,
                   "missing_at_start": prev.get("missing_at_start"),
                   "release_rollback": "--release-rollback" in ctx.opts,
                   "closure_bytes": int(ctx.opts["--closure-bytes"]) if "--closure-bytes" in ctx.opts else None}
    doc["txn"] = nt
    write_doc(ctx, doc)
    set_gcroot(ctx, "committed", committed)
    ctx.step(1, "write-fetching")

    # 2: start the worker in its own transient unit.
    run = [which("systemd-run"), "--unit=" + FETCH_UNIT, "--collect", "--quiet",
           "-p", "Nice=19", "-p", "IOSchedulingClass=idle", "-p", "TimeoutStopSec=20s",
           "-p", "KillMode=control-group", "--", ctx.argv0, "_fetch", "--txn", tid]
    r = run_cmd(run, 30)
    if r.returncode != 0:
        wk = worker_info()
        if wk["active"] and wk["txn"] == tid:
            return ok("the fetch worker is running")
        # A previous worker that just released the lock may still be
        # stopping, and its unit name is taken until systemd collects it.
        if wait_fetch_unit_gone():
            r = run_cmd(run, 30)
    if r.returncode != 0:
        nt.update(state="fetch_failed", reason_class="internal", reason=clean("systemd-run failed: " + last_line(r.stderr)))
        write_doc(ctx, doc)
        raise Fail(69, "unavailable", "systemd-run failed: " + last_line(r.stderr))
    ctx.step(2, "systemd-run")

    # 3: systemd-run returns at fork. The worker registers (progress.json,
    # phase lock-wait) before it waits for this verb's lock, so wait for that
    # here: otherwise this envelope's status, taken after the unlock, and the
    # first poll show a healthy `fetching` txn as interrupted.
    if wait_worker_registered(tid, WORKER_REGISTER_WAIT):
        return ok("the fetch worker started")
    return ok("the fetch worker started; it has not registered yet")


def wait_worker_registered(tid, timeout):
    """True once worker_info() shows this txn's worker (at most `timeout` s)."""
    deadline = time.monotonic() + timeout
    while True:
        wk = worker_info()
        if wk["active"] and wk["txn"] == tid:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)


def wait_fetch_unit_gone(timeout=5.0):
    """Poll `systemctl is-active` until the worker unit is neither running nor
    stopping (at most `timeout` s), then give systemd a moment to collect it.
    True when it went away, so one more systemd-run is worth trying."""
    ctl = which("systemctl")
    deadline = time.monotonic() + timeout
    while True:
        r = run_cmd([ctl, "is-active", FETCH_UNIT + ".service"], 10)
        state = r.stdout.decode("ascii", "replace").strip()
        if state not in ("active", "activating", "deactivating", "reloading", "refreshing"):
            time.sleep(0.5)
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.5)


def worker_context_problem():
    if not os.environ.get("INVOCATION_ID"):
        return "_fetch runs only inside its transient unit (no INVOCATION_ID)"
    leaf = cgroup_leaf("/proc/self/cgroup")
    if leaf is None:
        return "_fetch cannot read /proc/self/cgroup"
    if leaf != FETCH_UNIT + ".service":
        return "_fetch runs only inside %s.service" % FETCH_UNIT
    return None


# Signal plumbing for the worker: the handler only flags and forwards SIGTERM
# to the nix-store session; the worker raises Terminated at its next safe point.
_TERM = {"flag": False, "child": None}


def _on_term(signum, frame):
    _TERM["flag"] = True
    child = _TERM["child"]
    if child is not None:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except OSError:
            pass


def check_term():
    if _TERM["flag"]:
        raise Terminated()


NIX_OPTIONS = ["--option", "require-sigs", "true", "--option", "narinfo-cache-negative-ttl", "0",
               "--option", "max-jobs", "0", "--option", "builders", "", "--option", "fallback", "false",
               "--option", "fsync-store-paths", "true"]

# nix 2.34 stderr, matched with LC_ALL=C, first class wins.
CLASSES = [
    ("enospc", ("No space left on device",)),
    ("integrity", ("hash mismatch importing path", "hash mismatch for")),
    ("signature", ("as it's not signed by any of the keys in 'trusted-public-keys'",)),
    ("not-found", ("is required, but there is no substituter that can build it",
                   "don't know how to build these paths")),
    ("unreachable", ("unable to download", "HTTP error", "Couldn't resolve", "Could not resolve",
                     "Connection refused", "Connection timed out", "timed out")),
]
_NOTABLE = tuple(n for _, ns in CLASSES for n in ns) + ("will be fetched",)


def classify(text):
    for cls, needles in CLASSES:
        if any(n in text for n in needles):
            return cls
    return "internal"


_SIZE = r"([0-9]+(?:\.[0-9]+)?) (B|KiB|MiB|GiB|TiB|PiB|EiB)"
_DRY = re.compile(r"(?:these ([0-9]+) paths|this path) will be fetched \(" + _SIZE + " download, " + _SIZE + r" unpacked\):")
_UNITS = {"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40, "PiB": 1 << 50, "EiB": 1 << 60}


def parse_dry_run(text):
    """(missing paths, unpacked bytes, parsed?) from `nix-store --realise --dry-run`.
    No fetch line means nothing is missing."""
    m = _DRY.search(text)
    if m:
        n = int(m.group(1)) if m.group(1) else 1
        return n, int(math.ceil(float(m.group(4)) * _UNITS[m.group(5)])), True
    if "will be fetched" in text:
        return 0, 0, False
    return 0, 0, True


def headroom_ok(free, missing, min_free, reserve):
    # free - 1.5 * missing - reserve >= min_free, in integers.
    return 2 * free - 3 * missing - 2 * reserve >= 2 * min_free


def run_nix(argv):
    """Run a long nix-store command in its own session, keeping a bounded copy
    of stderr: every line a classifier looks for, plus a 256 KiB tail.
    SIGTERM (via _on_term) kills the session; KILL follows after 10 s."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            env=child_env(), start_new_session=True, close_fds=True)
    _TERM["child"] = proc
    notable, tail, tail_len, partial = [], [], 0, b""
    term_at = None

    def keep(line):
        nonlocal tail_len
        text = line.decode("utf-8", "replace")
        if any(n in text for n in _NOTABLE) and len(notable) < 64:
            notable.append(text)
        tail.append(text)
        tail_len += len(text) + 1
        while tail_len > STDERR_KEEP and len(tail) > 1:
            tail_len -= len(tail.pop(0)) + 1

    try:
        fd = proc.stderr.fileno()
        while True:
            if _TERM["flag"] and term_at is None:
                term_at = time.monotonic()
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except OSError:
                    pass
            if term_at is not None and time.monotonic() - term_at > 10:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
            ready, _, _ = select.select([fd], [], [], 0.5)
            if not ready:
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data = partial + chunk
            lines = data.split(b"\n")
            partial = lines.pop()
            for line in lines:
                keep(line)
        if partial:
            keep(partial)
        proc.wait()
    finally:
        _TERM["child"] = None
        proc.stderr.close()
    text = "\n".join(notable + tail)
    if text.strip():
        diag("%s %s: %s" % (os.path.basename(argv[0]), argv[1], text[-4000:]))
    return proc.returncode, text


class Worker:
    def __init__(self, ctx, doc, t):
        self.ctx, self.doc, self.t = ctx, doc, t
        self.rooted = False

    def progress(self, phase, **extra):
        f = self.t.get("fetch") or {}
        write_progress(self.t["id"], phase, attempt=f.get("attempts"), missing_at_start=f.get("missing_at_start"), **extra)

    def finish(self, state, cls, reason):
        t = self.t
        if self.rooted and state != "fetched":
            # The realise rooted the target as `staged`; a target that failed its
            # digest or compat check must not stay pinned in the store.
            remove_gcroot(self.ctx, "staged")
            self.doc["staged"] = None
        t.update(state=state, reason_class=cls, reason=clean(reason) if reason else None)
        write_doc(self.ctx, self.doc)
        self.progress("done", result=state if cls is None else "%s:%s" % (state, cls))
        return 0, None, state if cls is None else "%s:%s" % (state, cls), None, True

    def run(self):
        ctx, doc, t = self.ctx, self.doc, self.t
        target, closure, committed = t["target"], t["closure"], doc["committed"]["path"]
        f = t.setdefault("fetch", {}) or {}
        t["fetch"] = f
        ns = which("nix-store")
        min_free = int_seam(MIN_FREE_BYTES, "a headroom floor")
        reserve = int_seam(RESERVE_BYTES, "a headroom reserve")
        cb = f.get("closure_bytes")
        self.progress("dry-run")
        ctx.step(1, "lock")

        # 2: what is missing, and how big.
        check_term()
        rc, err = run_nix([ns, "--realise", "--dry-run", target] + NIX_OPTIONS)
        check_term()
        if rc != 0 or "don't know how to build these paths" in err:
            return self.finish("fetch_failed", classify(err), "dry run: " + (err.strip().splitlines() or ["exit %d" % rc])[-1])
        paths, missing, parsed = parse_dry_run(err)
        if not parsed:
            if cb is None:
                return self.finish("fetch_failed", "internal", "cannot parse the dry run's sizes")
            missing = cb
        if cb is not None:
            missing = min(missing, cb)
        if f.get("missing_at_start") is None:
            f["missing_at_start"] = {"paths": paths, "bytes": missing}
        ctx.step(2, "dry-run")

        # 3: headroom, releasing the rollback first when cogworxd allowed it.
        self.progress("headroom")
        free = int(statvfs_free(P("/nix/store")))
        if not headroom_ok(free, missing, min_free, reserve) and f.get("release_rollback") and doc.get("rollback"):
            self.release_for_headroom(committed)
            check_term()
            deficit = max(1, (2 * min_free + 3 * missing + 2 * reserve - 2 * free + 1) // 2)
            check_term()
            rc, _ = run_nix([ns, "--gc", "--max-freed", str(deficit)])
            check_term()
            free = int(statvfs_free(P("/nix/store")))
        if not headroom_ok(free, missing, min_free, reserve):
            return self.finish("fetch_failed", "headroom",
                               "%d bytes free, %d missing, floor %d, reserve %d" % (free, missing, min_free, reserve))
        ctx.step(3, "headroom")

        # 4: realise, rooted as `staged`.
        self.progress("realise")
        os.makedirs(P(GCROOTS), mode=0o755, exist_ok=True)
        check_term()
        rc, err = run_nix([ns, "--realise", target, "--add-root", P(GCROOTS + "/staged")] + NIX_OPTIONS)
        check_term()
        if rc != 0:
            return self.finish("fetch_failed", classify(err), "realise: " + (err.strip().splitlines() or ["exit %d" % rc])[-1])
        self.rooted = True
        ctx.mutated = True
        ctx.step(4, "realise")
        ctx.step(5, "sync")

        # 6: the digest cogworxd pinned.
        self.progress("digest")
        digest, _, _ = closure_digest(target)
        check_term()
        if digest != closure:
            return self.finish("fetch_failed", "integrity", "closure digest %s is not %s" % (digest, closure))
        ctx.step(6, "digest")

        # 7: guest compat rules.
        self.progress("compat")
        why = compat_problem(target, committed)
        if why:
            return self.finish("fetch_failed", "compat", why)
        ctx.step(7, "compat")

        # 8: fetched.
        doc["staged"] = target
        result = self.finish("fetched", None, None)
        ctx.step(8, "fetched")
        return result

    def release_for_headroom(self, committed):
        """Release steps 2-4 inline, then record rollback := null."""
        ctx, doc = self.ctx, self.doc
        released = doc["rollback"]["path"]
        # Before the profile goes: a drifted pin must refuse with nothing
        # changed, not after the rollback lost its root.
        verify_pin(doc["pin"])
        remove_profile(ctx, ROLLBACK)
        parse = installer(ctx, doc, committed)
        why = cfg_problem(parse, committed, None, None)
        if why:
            raise Fail(65, "grub-parse", why)
        env_write(ctx, doc, unsets=["cwx_rollback_entry"])
        doc["rollback"] = None
        history_add(doc, {"id": self.t["id"], "kind": "release", "outcome": "released-for-headroom",
                          "target": None, "rollback": released, "closed_at": now()})
        write_doc(ctx, doc)


def h_fetch_worker(ctx):
    tid = ctx.opts["--txn"]
    doc = read_doc()
    s = observe(doc)
    require_booted(s)
    if doc is None:
        raise Fail(65, "state", "no txn.json: nothing to fetch")
    check_argv0(ctx, doc, s)
    write_progress(tid, "lock-wait")
    ctx.lock.acquire("fetch-worker", tid, wait=WORKER_LOCK_WAIT)
    _TERM["flag"] = False
    old = signal.signal(signal.SIGTERM, _on_term)
    try:
        doc = read_doc()
        t = doc.get("txn") if doc else None
        if not t or t["id"] != tid or t["state"] != "fetching":
            write_progress(tid, "done", result="not-fetching")
            raise Fail(65, "state", "txn %s is not fetching" % tid)
        s = observe(doc)
        check_argv0(ctx, doc, s)
        w = Worker(ctx, doc, t)
        if s.booted != doc["committed"]["path"]:
            return w.finish("fetch_failed", "internal", "the committed system is not booted")
        try:
            return w.run()
        except Terminated:
            return w.finish("fetch_failed", "interrupted", "the fetch worker was stopped")
        except Fail as f:
            # systemctl stop signals the whole unit (KillMode=control-group):
            # a child killed under the digest or the headroom release fails
            # its step, and that failure is the stop, not an internal error.
            if _TERM["flag"]:
                return w.finish("fetch_failed", "interrupted", "the fetch worker was stopped: " + f.reason)
            return w.finish("fetch_failed", "internal", f.reason)
    finally:
        signal.signal(signal.SIGTERM, old)
        _TERM["flag"] = False


# --- verbs: arm, commit, abort, revert-commit, release ------------------------------------


def h_arm(ctx):
    return mutating(ctx, arm_body)


def arm_body(ctx, doc, s):
    tid = ctx.opts["--txn"]
    if doc is None:
        raise Fail(65, "state", "no fetched txn to arm")
    committed = doc["committed"]["path"]
    if s.booted != committed:
        raise Fail(65, "booted-mismatch", "arm needs the committed system booted")
    t = open_txn(doc)
    if not t:
        raise Fail(65, "state", "no open txn")
    if t["id"] != tid:
        raise Fail(65, "txn-mismatch", "the open txn is %s" % t["id"])
    if t["state"] == "armed":
        # Not re-reported: the one-shot is gone (rereport checks it).
        raise Fail(65, "state", "the txn is armed but its one-shot was consumed: abort")
    if t["state"] not in ("fetched", "arming"):
        raise Fail(65, "state", "the txn is %s" % t["state"])
    redo = t["state"] == "arming"
    if redo and (not t.get("arm_boot_id") or t.get("arm_boot_id") != boot_id()):
        raise Fail(65, "state", "arming began in an earlier boot: abort first")
    target = t["target"]
    verify_pin(doc["pin"])
    refuse_crash(doc, s, committed, ("current_differs",) + (("interrupted",) if redo else ()))
    why = compat_problem(target, committed)
    if why:
        raise Fail(65, "compat", why)
    rb = doc["rollback"]["path"] if doc.get("rollback") else None

    # 1
    t.update(state="arming", arm_boot_id=boot_id(), reason_class=None, reason=None)
    write_doc(ctx, doc)
    if not s.env_present:
        env_write(ctx, doc, create=True)
    set_gcroot(ctx, "committed", committed)
    ctx.step(1, "write-arming")
    # 2
    ensure_profiles_dir()
    profile_set(ctx, CANDIDATE, target)
    ctx.step(2, "candidate-profile")
    # 3
    parse = installer(ctx, doc, committed)
    ctx.step(3, "installer")
    # 4: on a wrong menu, take the candidate back out and return to fetched,
    # but only once a fresh render without it is the expected menu. A cause
    # outside the candidate (a damaged rollback toplevel) leaves the txn in
    # `arming`: grub.cfg is then broken for GRUB, and crash_state says so.
    why = cfg_problem(parse, committed, target, rb)
    if why:
        remove_profile(ctx, CANDIDATE)
        why2 = cfg_problem(installer(ctx, doc, committed), committed, None, rb)
        if why2:
            raise Fail(65, "grub-parse", "%s; without the candidate: %s" % (why, why2))
        t.update(state="fetched", reason_class="grub-parse", reason=clean(why))
        write_doc(ctx, doc)
        raise Fail(65, "grub-parse", why)
    ctx.step(4, "parse")
    cand_path = parse["profiles"]["cogworx_candidate"]["path"]
    rb_path = parse["profiles"]["cogworx_rollback"]["path"] if rb else None
    # 5: also a stale saved `boot_once`: load_env would import it, and the
    # guard (which trusts boot_once as "a one-shot was consumed") would then
    # write a false cwx_once on a boot with no one-shot.
    env_write(ctx, doc, sets={"cwx_rollback_entry": rb_path} if rb_path else None,
              unsets=["cwx_once", "boot_once"] + ([] if rb_path else ["cwx_rollback_entry"]))
    ctx.step(5, "grubenv-rollback")
    # 6
    env_write(ctx, doc, sets={"next_entry": cand_path})
    ctx.step(6, "next-entry")
    # 7
    try:
        with open(P(GRUBENV), "rb") as f:
            env = parse_grubenv(f.read(ENV_SIZE + 1))
    except OSError:
        env = None
    if (env is None or env.get("next_entry") != cand_path or env.get("cwx_rollback_entry") != rb_path
            or "cwx_once" in env or "boot_once" in env):
        raise Fail(65, "grubenv", "grubenv read-back mismatch after arm")
    t["state"] = "armed"
    write_doc(ctx, doc)
    ctx.step(7, "armed")
    return ok()


def h_commit(ctx):
    return mutating(ctx, commit_body)


def commit_body(ctx, doc, s):
    tid = ctx.opts["--txn"]
    t = open_txn(doc)
    if doc is None or not t:
        raise Fail(65, "state", "no open txn")
    if t["id"] != tid:
        raise Fail(65, "txn-mismatch", "the open txn is %s" % t["id"])
    if t["state"] not in ("armed", "committing"):
        raise Fail(65, "state", "the txn is %s" % t["state"])
    X, T = doc["committed"]["path"], t["target"]
    if s.booted != T:
        raise Fail(65, "booted-mismatch", "commit needs the target booted")
    verify_pin(doc["pin"])
    retain = ctx.opts.get("--retain-until")
    norb = "--no-rollback" in ctx.opts
    # Step 5 renders X as the rollback entry, whose title carries X's
    # nixos-version, and a failed render there cannot be undone (abort
    # refuses the target booted mid-commit). Every committed system but the
    # base passed rule xiii as a target; the base (bootstrap) system never
    # did. So check X's here, before any step: the txn stays as it is, and
    # cogworxd can commit --no-rollback or abort.
    if not norb:
        try:
            version_ok = title_version_ok(read_file(X + "/nixos-version", 4096))
        except OSError:
            version_ok = False
        if not version_ok:
            raise Fail(65, "grub-parse", "the committed system's nixos-version cannot title the rollback entry: "
                       "commit --no-rollback or abort")

    # 1
    if t["state"] == "armed":
        t["pre"] = pre_image(doc, s)
    t.update(state="committing", commit={"retain_until": retain, "no_rollback": norb})
    write_doc(ctx, doc)
    ctx.step(1, "write-committing")
    # 2: the "head = target, entry 0 = old" state.
    profile_set(ctx, SYSTEM_PROFILE, T)
    ctx.step(2, "system-profile")
    # 3
    if norb:
        remove_profile(ctx, ROLLBACK)
    else:
        ensure_profiles_dir()
        profile_set(ctx, ROLLBACK, X)
        profile_delete_old(ctx, ROLLBACK)
    ctx.step(3, "rollback-profile")
    # 4
    remove_profile(ctx, CANDIDATE)
    ctx.step(4, "remove-candidate")
    # 5
    parse = installer(ctx, doc, T)
    why = cfg_problem(parse, T, None, None if norb else X)
    if why:
        raise Fail(65, "grub-parse", why)
    ctx.step(5, "installer")
    # 6
    rb_path = parse["profiles"]["cogworx_rollback"]["path"] if not norb else None
    env_write(ctx, doc, sets={"cwx_rollback_entry": rb_path} if rb_path else None,
              unsets=["next_entry"] + ([] if rb_path else ["cwx_rollback_entry"]))
    ctx.step(6, "grubenv")
    # 7
    profile_delete_old(ctx, SYSTEM_PROFILE)
    ctx.step(7, "delete-old")
    # 8: the closing write comes BEFORE the roots move. Until it lands,
    # txn.json names X as committed and X's tool is the only repair, so the
    # `committed` root must keep X alive (with --no-rollback nothing else
    # does, and a collection runs exactly when the disk is low).
    old = doc["committed"]
    doc["committed"] = {"path": T, "closure": t.get("closure"), "since": now()}
    doc["rollback"] = None if norb else {"path": X, "closure": old.get("closure"), "retain_until": retain}
    doc["staged"] = None
    close_txn(doc, t, "committed", previous=X)
    write_doc(ctx, doc)
    ctx.step(8, "committed")
    # 9: a cut before this only leaks roots: fetch, arm, abort, revert-commit
    # and release re-assert `committed`, and the next realise or commit
    # replaces `staged`.
    remove_gcroot(ctx, "staged")
    set_gcroot(ctx, "committed", T)
    ctx.step(9, "roots")
    return ok()


def h_abort(ctx):
    return mutating(ctx, abort_body, pre_lock=abort_stop_worker)


def abort_stop_worker(ctx, doc):
    """A running fetch worker holds the lock: stop its unit first (its SIGTERM
    handler records fetch_failed/interrupted), then wait up to 5 s for the lock."""
    t = open_txn(doc)
    if t and t["id"] == ctx.opts["--txn"] and t["state"] == "fetching":
        wk = worker_info()
        if wk["active"] and wk["txn"] == t["id"]:
            run_cmd([which("systemctl"), "stop", FETCH_UNIT + ".service"], 30)
            ctx.lock_wait = 5.0


def abort_body(ctx, doc, s):
    tid = ctx.opts["--txn"]
    X = committed_of(doc, s)
    t = open_txn(doc)
    if t and t["id"] != tid:
        raise Fail(65, "txn-mismatch", "the open txn is %s" % t["id"])
    if not t and closed_id(doc, tid):
        raise Fail(65, "state", "txn %s is closed" % tid)
    allowed = {X}
    if t and t.get("target"):
        allowed.add(t["target"])
    if doc and doc.get("rollback"):
        allowed.add(doc["rollback"]["path"])
    if s.booted not in allowed:
        raise Fail(65, "booted-mismatch", "abort needs the committed system, the target or the rollback booted")
    if t and t["state"] == "committing" and s.booted == t["target"] and s.booted != X:
        raise Fail(65, "booted-mismatch", "the target booted mid-commit: re-run commit")
    if doc is not None:
        verify_pin(doc["pin"])
    doc = ensure_bootstrapped(ctx, doc, s, X)

    # 1
    if t:
        if t["state"] not in ("committing", "reverting", "releasing", "aborting") or not t.get("pre"):
            t["pre"] = pre_image(doc, s)
        if t["state"] != "aborting":
            t["aborted_from"] = t["state"]
        t["state"] = "aborting"
    else:
        t = new_txn(tid, "repair", "aborting")
        t["pre"] = pre_image(doc, s)
        t["aborted_from"] = None
        doc["txn"] = t
    write_doc(ctx, doc)
    set_gcroot(ctx, "committed", X)
    ctx.step(1, "write-aborting")
    # 2: FIRST, so a pending one-shot never outlives the candidate.
    env_write(ctx, doc, unsets=["next_entry"])
    ctx.step(2, "next-entry")
    # 3
    profile_set(ctx, SYSTEM_PROFILE, X)
    ctx.step(3, "system-profile")
    # 4: the rollback the aborted txn found (commit and revert recorded it as
    # `pre`; every other state still has it as the recorded rollback).
    want = t["pre"]["rollback"] if t.get("aborted_from") in ("committing", "reverting") else doc.get("rollback")
    have = restore_rollback(ctx, want)
    ctx.step(4, "rollback-profile")
    # 5
    remove_profile(ctx, CANDIDATE)
    ctx.step(5, "remove-candidate")
    # 6
    parse = installer(ctx, doc, X)
    why = cfg_problem(parse, X, None, have["path"] if have else None)
    if why:
        raise Fail(65, "grub-parse", why)
    ctx.step(6, "installer")
    # 7
    rb_path = parse["profiles"]["cogworx_rollback"]["path"] if have else None
    env_write(ctx, doc, sets={"cwx_rollback_entry": rb_path} if rb_path else None,
              unsets=[] if rb_path else ["cwx_rollback_entry"])
    ctx.step(7, "grubenv")
    # 8
    profile_delete_old(ctx, SYSTEM_PROFILE)
    ctx.step(8, "delete-old")
    # 9
    if "--release-staged" in ctx.opts:
        remove_gcroot(ctx, "staged")
        doc["staged"] = None
    ctx.step(9, "staged")
    # 10
    extra = {}
    if want is not None and have is None:
        extra["rollback_lost"] = want["path"]
    doc["rollback"] = have
    close_txn(doc, t, "repaired" if t["kind"] == "repair" else "aborted", **extra)
    write_doc(ctx, doc)
    ctx.step(10, "aborted")
    return ok()


def h_revert(ctx):
    return mutating(ctx, revert_body)


def revert_body(ctx, doc, s):
    tid = ctx.opts["--txn"]
    X = doc["committed"]["path"]
    R = doc["rollback"]["path"]
    if s.booted != R:
        raise Fail(65, "booted-mismatch", "revert-commit needs the rollback booted")
    t = open_txn(doc)
    if t:
        if t["id"] != tid:
            raise Fail(65, "txn-mismatch", "the open txn is %s" % t["id"])
        if t["state"] != "reverting":
            raise Fail(65, "state", "the txn is %s" % t["state"])
    elif closed_id(doc, tid):
        raise Fail(65, "state", "txn %s is closed" % tid)
    verify_pin(doc["pin"])

    # 1
    if not t:
        t = new_txn(tid, "revert", "reverting", R, doc["rollback"].get("closure"))
        t["pre"] = pre_image(doc, s)
        t["reverted_from"] = X
        doc["txn"] = t
    write_doc(ctx, doc)
    # Re-asserted like fetch, arm, abort and release do: after a commit whose
    # root flip was lost, `committed` still names the old system, and step 7
    # deletes X's last generation link while txn.json names X until step 8.
    set_gcroot(ctx, "committed", X)
    ctx.step(1, "write-reverting")
    # 2
    env_write(ctx, doc, unsets=["next_entry"])
    ctx.step(2, "next-entry")
    # 3
    profile_set(ctx, SYSTEM_PROFILE, R)
    ctx.step(3, "system-profile")
    # 4
    remove_profile(ctx, ROLLBACK)
    ctx.step(4, "remove-rollback")
    # 5
    parse = installer(ctx, doc, R)
    why = cfg_problem(parse, R, None, None)
    if why:
        raise Fail(65, "grub-parse", why)
    ctx.step(5, "installer")
    # 6
    env_write(ctx, doc, unsets=["cwx_rollback_entry"])
    ctx.step(6, "grubenv")
    # 7
    profile_delete_old(ctx, SYSTEM_PROFILE)
    ctx.step(7, "delete-old")
    # 8: the closing write, then the root (as commit steps 8 and 9).
    doc["committed"] = {"path": R, "closure": doc["rollback"].get("closure"), "since": now()}
    doc["rollback"] = None
    close_txn(doc, t, "reverted", reverted_from=t.get("reverted_from", X))
    write_doc(ctx, doc)
    ctx.step(8, "reverted")
    # 9
    set_gcroot(ctx, "committed", R)
    ctx.step(9, "roots")
    return ok()


def h_release(ctx):
    return mutating(ctx, release_body)


def release_body(ctx, doc, s):
    tid = ctx.opts["--txn"]
    if doc is None:
        raise Fail(65, "state", "no rollback to release")
    X = doc["committed"]["path"]
    if s.booted != X:
        raise Fail(65, "booted-mismatch", "release needs the committed system booted")
    t = open_txn(doc)
    if t:
        if t["id"] != tid or t["state"] != "releasing":
            raise Fail(65, "state", "a txn is open (%s, %s)" % (t["id"], t["state"]))
    else:
        if closed_id(doc, tid):
            raise Fail(65, "state", "txn %s is closed" % tid)
        if not doc.get("rollback"):
            raise Fail(65, "state", "no rollback to release")
    verify_pin(doc["pin"])

    # 1
    if not t:
        t = new_txn(tid, "release", "releasing")
        t["pre"] = pre_image(doc, s)
        doc["txn"] = t
    write_doc(ctx, doc)
    set_gcroot(ctx, "committed", X)
    ctx.step(1, "write-releasing")
    # 2
    remove_profile(ctx, ROLLBACK)
    ctx.step(2, "remove-rollback")
    # 3
    parse = installer(ctx, doc, X)
    why = cfg_problem(parse, X, None, None)
    if why:
        raise Fail(65, "grub-parse", why)
    ctx.step(3, "installer")
    # 4
    env_write(ctx, doc, unsets=["cwx_rollback_entry"])
    ctx.step(4, "grubenv")
    # 5
    released = doc["rollback"]["path"] if doc.get("rollback") else None
    doc["rollback"] = None
    close_txn(doc, t, "released", rollback=released)
    write_doc(ctx, doc)
    ctx.step(5, "released")
    return ok()


HANDLERS = {
    "proto": h_proto,
    "status": h_status,
    "closure-digest": h_closure_digest,
    "fetch": h_fetch,
    "_fetch": h_fetch_worker,
    "arm": h_arm,
    "commit": h_commit,
    "abort": h_abort,
    "revert-commit": h_revert,
    "release": h_release,
}


# --- output ---------------------------------------------------------------------------------


def render(env):
    """(exit code, the one stdout line), within 64 KiB."""
    text = json.dumps(env, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    if len(text) > MAX_OUT:
        if isinstance(env.get("status"), dict):
            env["status"].pop("compat", None)
        env.update(exit=70, ok=False, reason_class="internal", reason="output-too-large")
        text = json.dumps(env, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
        if len(text) > MAX_OUT:
            env.pop("status", None)
            text = json.dumps(env, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    return env["exit"], text


def write_out(text):
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except (BrokenPipeError, OSError, ValueError):
        # The caller has gone. Point stdout at /dev/null so the interpreter's
        # final flush cannot fail and change the exit status.
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except (OSError, ValueError, AttributeError):
            pass


def main(argv):
    """Run one verb; return its exit code. Never raises, never calls sys.exit."""
    ctx = None
    try:
        ctx = Ctx(argv)
        env = ctx.run()
    except BaseException as e:
        try:
            diag("internal error: %s: %s" % (type(e).__name__, e))
            if ctx is not None:
                ctx.lock.release()
                env = ctx.envelope(70, "internal", "%s: %s" % (type(e).__name__, e),
                                   with_status=ctx.verb not in ("proto", "closure-digest"))
            else:
                env = None
        except BaseException:
            env = None
        if env is None:
            env = {"cogworx_pve_upgrade": TOOL_PROTO, "verb": None, "ok": False, "exit": 70,
                   "reason_class": "internal", "reason": "internal error", "txn_id": None, "mutated": False}
    try:
        code, text = render(env)
    except BaseException:
        code = 70
        text = '{"cogworx_pve_upgrade":1,"exit":70,"mutated":false,"ok":false,"reason":"internal error",' \
               '"reason_class":"internal","txn_id":null,"verb":null}\n'
    write_out(text)
    return code


if __name__ == "__main__":
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    sys.exit(main(sys.argv))
