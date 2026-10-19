"""cogworx-pve-upgrade: grammar, envelope, parsers, the bootloader pin, compat
rules, fetch classification, the state machine on a fake guest, and a power
cut after every numbered step of every verb.

Usage: python3 -I pve/tests/test_upgrade.py

Stdlib only; no root, no network, nothing outside temporary directories. The
fake guest is a directory tree the tool sees through its ROOT seam: a store
with fake system toplevels, profiles, /boot/grub (grub.cfg rendered by a fake
installer in install-grub.pl's shape, grubenv edited by the REAL grub-editenv),
/run and a fake /proc. nix-env, nix-store, systemd-run and systemctl are fakes
on the tool's child PATH. pve/checks.nix (upgrade-unittests) sets:

  COGWORX_PVE_UPGRADE      the tool source
  COGWORX_PVE_UPGRADE_BIN  the built package's bin/cogworx-pve-upgrade
  GRUB_EDITENV             a real grub-editenv (required here too)
  PVE_INSTALLER            the PVE image's real install-grub.sh
  PVE_GRUB_STATE_GRUB      that system's system.build.grub
  UPGRADE_VECTORS          pve/testdata
"""
import ast
import base64
import contextlib
import errno
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = Path(__file__).resolve().parent
TOOL_SRC = os.environ.get("COGWORX_PVE_UPGRADE", str(HERE.parent / "upgrade" / "cogworx_pve_upgrade.py"))
TOOL_BIN = os.environ.get("COGWORX_PVE_UPGRADE_BIN")
VECTORS = Path(os.environ.get("UPGRADE_VECTORS", str(HERE.parent / "testdata")))
GRUB_EDITENV = os.environ.get("GRUB_EDITENV") or shutil.which("grub-editenv")
PVE_INSTALLER = os.environ.get("PVE_INSTALLER")
PVE_GRUB = os.environ.get("PVE_GRUB_STATE_GRUB")
# Under the flake check every input is required; a local run may skip the
# real-installer and built-package cases.
IN_CHECK = "COGWORX_PVE_UPGRADE" in os.environ


def load_tool(path=TOOL_SRC, name="cwx_pve_upgrade"):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


T = load_tool()

GiB = 1 << 30
MIN_FREE = 12 * GiB
RESERVE = 4 * GiB
DISTRO = "NixOS"
RETAIN = "2026-11-01T00:00:00Z"


def txid(n):
    return "00000000-0000-4000-8000-%012d" % n


def h32(label):
    return T.nix32_encode(hashlib.sha256(label.encode()).digest()[:20])


def sha_forms(raw):
    return {"nix32": "sha256:" + T.nix32_encode(raw), "base16": raw.hex(),
            "sri": "sha256-" + base64.b64encode(raw).decode(), "bare32": T.nix32_encode(raw)}


# --- the fakes on the tool's child PATH (one multi-call script) -----------------

FAKE_SRC = r'''
import json, os, re, shutil, sys, time
import xml.etree.ElementTree as ET
HERE = os.path.dirname(os.path.abspath(sys.argv[0]))
with open(os.path.join(HERE, "fake.json")) as _f:
    CFG = json.load(_f)
ROOT, SW, LOGS = CFG["root"], CFG["switch"], CFG["logs"]


def P(p):
    return ROOT + p


def sw(name):
    try:
        with open(os.path.join(SW, name)) as f:
            return f.read()
    except FileNotFoundError:
        return None


def log(name, **kw):
    with open(os.path.join(LOGS, name + ".jsonl"), "a") as f:
        f.write(json.dumps(kw) + "\n")


def resolve(path, hops=16):
    parts = [p for p in path.split("/") if p not in ("", ".")]
    done = ""
    while parts:
        name = parts.pop(0)
        if name == "..":
            done = done.rsplit("/", 1)[0]
            continue
        cand = done + "/" + name
        if not os.path.lexists(P(cand)):
            return None
        if os.path.islink(P(cand)):
            hops -= 1
            if hops < 0:
                return None
            t = os.readlink(P(cand))
            parts = [p for p in t.split("/") if p not in ("", ".")] + parts
            if t.startswith("/"):
                done = ""
            continue
        done = cand
    return done or "/"


def db():
    with open(CFG["db"]) as f:
        return json.load(f)


def closure(p):
    d = db()
    seen, todo = [], [p]
    while todo:
        q = todo.pop()
        if q in seen:
            continue
        if q not in d:
            return None
        seen.append(q)
        todo.extend(d[q]["refs"])
    return seen


def present(p):
    return os.path.lexists(P(p))


def nix_env(a):
    log("nix-env", argv=a)
    prof = a[a.index("-p") + 1]
    d, name = os.path.split(prof)
    if not os.path.isdir(d):
        sys.stderr.write('error: cannot read directory "%s"\n' % d)
        return 1
    gens = {}
    for e in os.listdir(d):
        m = re.fullmatch(re.escape(name) + r"-([0-9]+)-link", e)
        if m:
            gens[int(m.group(1))] = e
    cur = os.readlink(prof) if os.path.islink(prof) else None
    if "--set" in a:
        path = a[a.index("--set") + 1]
        if path not in db() or not present(path):
            sys.stderr.write("error: path '%s' is not valid\n" % path)
            return 1
        if gens and os.readlink(os.path.join(d, gens[max(gens)])) == path:
            link = gens[max(gens)]
        else:
            link = "%s-%d-link" % (name, max(gens, default=0) + 1)
            os.symlink(path, os.path.join(d, link))
        if cur != link:
            os.symlink(link, prof + ".tmp")
            os.rename(prof + ".tmp", prof)
        return 0
    if "--delete-generations" in a:
        for n, e in gens.items():
            if e != cur:
                os.unlink(os.path.join(d, e))
        return 0
    return 2


def nix_store(a):
    log("nix-store", argv=a)
    d = db()
    if a[:1] == ["-qR"]:
        c = closure(a[1])
        if c is None or not all(present(q) for q in c):
            sys.stderr.write("error: path '%s' is not valid\n" % a[1])
            return 1
        for q in reversed(c):
            print(q)
        return 0
    if a[:1] == ["-q"] and a[1] in ("--hash", "--size"):
        if a[1] == "--hash" and sw("hash-fail") is not None:
            sys.stderr.write(sw("hash-fail") or "error: interrupted by the user\n")
            return 1
        form = (sw("hash-form") or "nix32").strip()
        for q in a[2:]:
            if q not in d or not present(q):
                sys.stderr.write("error: path '%s' is not valid\n" % q)
                return 1
            print(d[q]["hash"][form] if a[1] == "--hash" else d[q]["size"])
        return 0
    if a[:2] == ["--check-validity", "--print-invalid"]:
        # From the database, not the directory (World.invalidate).
        if sw("check-validity-fail") is not None:
            sys.stderr.write("error: cannot open the Nix database\n")
            return 1
        for q in a[2:]:
            if q not in d:
                print(q)
        return 0
    if a[:1] == ["--gc"]:
        with open(os.path.join(SW, "gc-ran"), "w") as f:
            f.write(" ".join(a))
        return 0
    if a[:1] == ["--realise"]:
        rest = a[1:]
        target = [x for x in rest if x.startswith("/nix/store/")][0]
        if "--dry-run" in rest:
            out = sw("dryrun-out")
            if out is not None:
                sys.stderr.write(out)
                return int(sw("dryrun-exit") or 0)
            c = closure(target)
            if c is None:
                sys.stderr.write("don't know how to build these paths:\n  %s\n" % target)
                return 0
            missing = [q for q in c if not present(q)]
            if missing:
                # nix's renderSize: one decimal, KiB at the least
                n = sum(d[q]["size"] for q in missing)
                unit = next(u for u in ((1 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB")) if n >= u[0] or u[1] == "KiB")
                size = "%.1f %s" % (n / float(unit[0]), unit[1])
                head = "this path" if len(missing) == 1 else "these %d paths" % len(missing)
                sys.stderr.write("%s will be fetched (%s download, %s unpacked):\n" % (head, size, size))
                for q in missing:
                    sys.stderr.write("  %s\n" % q)
            return 0
        if sw("realise-hang") is not None:
            with open(os.path.join(SW, "realise-pid"), "w") as f:
                f.write(str(os.getpid()))
            time.sleep(120)
            return 0
        err = sw("realise-err")
        if err is not None:
            sys.stderr.write(err)
            return int(sw("realise-exit") or 1)
        c = closure(target)
        if c is None:
            sys.stderr.write("error: path '%s' is required, but there is no substituter that can build it\n" % target)
            return 1
        for q in c:
            if not present(q):
                src = os.path.join(CFG["cache"], q[len("/nix/store/"):])
                shutil.copytree(src, P(q), symlinks=True)
        if "--add-root" in rest:
            link = rest[rest.index("--add-root") + 1]
            os.symlink(target, link + ".tmp")
            os.rename(link + ".tmp", link)
        return 0
    return 2


def systemd_run(a):
    log("systemd-run", argv=a)
    once = os.path.join(SW, "systemd-run-fail-once")
    if sw("systemd-run-fail") is not None or os.path.exists(once):
        if os.path.exists(once):
            os.unlink(once)
        sys.stderr.write("Failed to start transient service unit: Unit cogworx-pve-upgrade-fetch.service was already loaded or has a fragment file.\n")
        return 1
    return 0


def systemctl(a):
    """is-active prints the `unit-state` switch (default inactive); stop sends
    SIGTERM to the `worker-pid` switch's process and waits until it is gone,
    as systemctl stop waits for the unit."""
    log("systemctl", argv=a)
    if a[:1] == ["is-active"]:
        state = (sw("unit-state") or "inactive").strip()
        print(state)
        return 0 if state == "active" else 3
    if a[:1] == ["stop"] and sw("worker-pid"):
        pid = int(sw("worker-pid"))
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            pass
        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                with open("/proc/%d/stat" % pid) as f:
                    state = f.read().rsplit(")", 1)[1].split()[0]
            except OSError:
                break
            if state in ("Z", "X"):
                break
            time.sleep(0.05)
        shutil.rmtree(P("/proc/%d" % pid), ignore_errors=True)
    return 0


S1 = "search --set=drive1 --fs-uuid 6f1d2c3b-4a59-4e68-8d7c-0a1b2c3d4e5f"
S2 = "search --set=drive2 --fs-uuid 6f1d2c3b-4a59-4e68-8d7c-0a1b2c3d4e5f"
HEADER = ("# Automatically generated.  DO NOT EDIT THIS FILE!\n\n        " + S2 + "\n    " + S1 + "\n"
          "    if [ -s $prefix/grubenv ]; then\n      load_env\n    fi\n\n"
          "    if [ \"${next_entry}\" ]; then\n      set default=\"${next_entry}\"\n      set next_entry=\n"
          "      save_env next_entry\n      set timeout=1\n      set boot_once=true\n    else\n"
          "      set default=0\n      set timeout=0\n    fi\n    set timeout_style=menu\n\n"
          "    function savedefault {\n        if [ -z \"${boot_once}\"]; then\n        saved_entry=\"${chosen}\"\n"
          "        save_env saved_entry\n        fi\n    }\n\n"
          "    if [ \"${grub_platform}\" = \"efi\" ]; then\n      insmod efi_gop\n      insmod efi_uga\n"
          "    else\n      insmod vbe\n    fi\n")


def readfile(p):
    with open(P(p)) as f:
        s = f.read()
    return s[:-1] if s.endswith("\n") else s


def perl(a):
    """install-grub.pl, as far as grub.cfg's menu goes. Switches render a
    wrong menu: installer-entry0-as <system> (entry 0 boots that system),
    installer-profile-as "<profile> <system>" (that profile's entry boots it),
    installer-extra-profile <name> (one more profile submenu)."""
    log("installer", argv=a, env=dict(os.environ))
    if sw("installer-fail") is not None:
        sys.stderr.write("fake installer: failing as told\n")
        return 1
    _pl, xml, top = a[0], a[1], a[2]
    vals = {}
    for at in ET.parse(P(xml)).getroot().find("attrs").findall("attr"):
        vals[at.get("name")] = at[0].get("value")
    limit = int(vals["configurationLimit"])
    skip = (sw("installer-skip") or "").split()
    entry0_as = (sw("installer-entry0-as") or "").strip() or None
    profile_as = dict([(sw("installer-profile-as") or "").split()] if sw("installer-profile-as") else [])
    conf = [HEADER, (vals.get("extraConfig") or "") + "\n", "\n"]

    def add_entry(name, path, options, as_path=None):
        real = resolve(path)
        if real is None or real in skip:
            return
        src = as_path or path
        k, i, init = resolve(src + "/kernel"), resolve(src + "/initrd"), resolve(src + "/init")
        if k is None or i is None:
            return
        conf.append('menuentry "%s" %s {\n%s\n%s\n  linux ($drive2)%s init=%s %s\n  initrd ($drive2)%s\n}\n\n'
                    % (name, options, S1, S2, k, init, readfile((as_path or real) + "/kernel-params"), i))

    def add_profile(profile, desc):
        as_path = profile_as.get(os.path.basename(profile))
        conf.append('submenu "%s" --class submenu {\n' % desc)
        d, name = os.path.split(P(profile))
        links = []
        for e in (os.listdir(d) if os.path.isdir(d) else []):
            m = re.fullmatch(re.escape(name) + r"-([0-9]+)-link", e)
            if m:
                links.append((int(m.group(1)), "%s-%s-link" % (profile, m.group(1))))
        cur = 0
        for n, link in sorted(links, reverse=True):
            if cur >= limit:
                break
            cur += 1
            v = resolve(link + "/nixos-version")
            if v is None:
                continue
            date = time.strftime("%Y-%m-%d", time.localtime(os.lstat(P(link)).st_mtime))
            add_entry("%s - Configuration %d (%s - %s)" % (CFG["distro"], n, date, readfile(v)), link, "--class nixos", as_path)
        conf.append("}\n")

    add_entry(CFG["distro"], top, "--class nixos --unrestricted", entry0_as)
    conf.append("\n")
    add_profile("/nix/var/nix/profiles/system", CFG["distro"] + " - All configurations")
    sp = P("/nix/var/nix/profiles/system-profiles")
    for e in sorted(os.listdir(sp)) if os.path.isdir(sp) else []:
        if re.fullmatch(r"\w+", e, re.ASCII):
            add_profile("/nix/var/nix/profiles/system-profiles/" + e, "%s - Profile '%s'" % (CFG["distro"], e))
    if sw("installer-extra-profile"):
        add_profile("/nix/var/nix/profiles/system", "%s - Profile '%s'" % (CFG["distro"], sw("installer-extra-profile").strip()))
    with open(P("/boot/grub/grub.cfg.tmp"), "w") as f:
        f.write("".join(conf))
    os.rename(P("/boot/grub/grub.cfg.tmp"), P("/boot/grub/grub.cfg"))
    if sw("installer-rewrite-state") is not None:
        with open(P("/boot/grub/state"), "a") as f:
            f.write("rewritten by a grub-install\n")
    if sw("installer-touch-boot-area") is not None:
        with open(P("/dev/vda"), "r+b") as f:
            f.seek(600)
            f.write(b"\xff\xfe")
    return 0


NAME = os.path.basename(sys.argv[0])
sys.exit({"nix-env": nix_env, "nix-store": nix_store, "systemd-run": systemd_run,
          "systemctl": systemctl, "perl": perl}[NAME](sys.argv[1:]))
'''

# A power cut: the verb runs in its own process, which dies (os._exit) right
# after step k's sync. The tree persists; nothing of the process does.
DRIVER_SRC = r'''
import importlib.machinery, importlib.util, json, os, sys
with open(sys.argv[1]) as f:
    cfg = json.load(f)
loader = importlib.machinery.SourceFileLoader("cwx", cfg["tool"])
spec = importlib.util.spec_from_loader("cwx", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)
mod.ROOT, mod.CHILD_PATH = cfg["root"], cfg["bin"]
mod.MIN_FREE_BYTES, mod.RESERVE_BYTES = str(cfg["min_free"]), str(cfg["reserve"])
mod.statvfs_free = lambda p: cfg["free"]
mod.WORKER_LOCK_WAIT = 2.0
mod.WORKER_REGISTER_WAIT = 0.0
os.environ.update(cfg.get("env", {}))


def hook(verb, n, name):
    if verb == cfg["verb"] and n == cfg["k"]:
        os._exit(99)


mod.STEP_HOOK = hook
sys.exit(mod.main(cfg["argv"]))
'''


def xml_escape(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            .replace("\n", "&#xA;"))


def make_xml(grub, **over):
    """grub-config.xml in builtins.toXML's shape; `over` replaces values
    (python bool/int/str/list map to <bool>/<int>/<string>/<list>)."""
    vals = {"bootPath": "/boot", "configurationLimit": 1, "copyKernels": False, "default": "0",
            "devices": ["/dev/vda"], "efiSysMountPoint": "/boot", "efiSupport": False,
            "entryOptions": "--class nixos --unrestricted", "extraConfig": "", "extraEntries": "",
            "extraEntriesBeforeNixOS": False, "extraGrubInstallArgs": [], "extraPerEntryConfig": "",
            "extraPrepareConfig": "", "fullName": "grub", "fullVersion": "2.14", "grub": grub, "grubEfi": "",
            "grubTarget": "i386-pc", "grubTargetEfi": "", "subEntryOptions": "--class nixos", "timeout": 0,
            "useOSProber": False}
    vals.update(over)
    out = ["<?xml version='1.0' encoding='utf-8'?>", "<expr>", "  <attrs>"]
    for k in sorted(vals):
        v = vals[k]
        out.append('    <attr name="%s">' % k)
        if isinstance(v, bool):
            out.append('      <bool value="%s" />' % ("true" if v else "false"))
        elif isinstance(v, int):
            out.append('      <int value="%d" />' % v)
        elif isinstance(v, list):
            out.append("      <list>")
            out.extend('        <string value="%s" />' % xml_escape(x) for x in v)
            out.append("      </list>")
        else:
            out.append('      <string value="%s" />' % xml_escape(v))
        out.append("    </attr>")
    out += ["  </attrs>", "</expr>", ""]
    return "\n".join(out)


def state_text(x):
    return "grub\n2.14\nno\n%s\n%s\n%s\n" % (",".join(x["devices"]), x["efiSysMountPoint"], json.dumps(
        {"extraGrubInstallArgs": x["extraGrubInstallArgs"], "grub": x["grub"], "grubEfi": x["grubEfi"]}))


def real_installer():
    """(script text, xml bytes) of the PVE image's real install-grub.sh."""
    with open(PVE_INSTALLER) as f:
        text = f.read()
    _perl, _pl, xml = T.parse_installer_script(text)
    with open(xml, "rb") as f:
        return text, f.read()


def tree_hash(root):
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            h.update(os.path.relpath(p, root).encode() + b"\0" + oct(st.st_mode).encode())
            if stat.S_ISLNK(st.st_mode):
                h.update(os.readlink(p).encode())
            elif stat.S_ISREG(st.st_mode):
                with open(p, "rb") as f:
                    h.update(f.read())
    return h.hexdigest()


PARAMS = "console=ttyS0 root=fstab loglevel=4 net.ifnames=0 boot.panic_on_fail panic=10"
GCROOTS = "/nix/var/nix/gcroots/cogworx-pve-upgrade"
CANDIDATE = "/nix/var/nix/profiles/system-profiles/cogworx_candidate"
ROLLBACK = "/nix/var/nix/profiles/system-profiles/cogworx_rollback"
FETCH_CGROUP = "0::/system.slice/cogworx-pve-upgrade-fetch.service\n"


class World:
    """A fake guest booted on system A, as a freshly cloned template."""

    def __init__(self, xml_text=None):
        self.dir = tempfile.mkdtemp(prefix="cwx-upg-")
        self.root = os.path.join(self.dir, "root")
        self.bin = os.path.join(self.dir, "bin")
        self.cache = os.path.join(self.dir, "cache")
        self.sw = os.path.join(self.dir, "switch")
        self.logs = os.path.join(self.dir, "log")
        self.dbfile = os.path.join(self.dir, "db.json")
        for d in (self.bin, self.cache, self.sw, self.logs):
            os.makedirs(d)
        for d in ("nix/store", "nix/var/nix/profiles", "nix/var/nix/gcroots", "run", "boot/grub", "dev",
                  "proc/self", "proc/sys/kernel/random", "var/lib"):
            os.makedirs(os.path.join(self.root, d))
        self.free = 100 * GiB
        self.gc_frees = 0
        # The fake systemd-run starts no worker, so the launcher does not wait
        # for one to register unless a test asks for it.
        self.register_wait = 0.0
        self.db = {}
        self.sys = {}
        self.nonce = 0
        self.boots = 0

        # The bootloader: the PVE image's real grub-config.xml when the check
        # provides it, else a synthetic one of the same shape.
        if xml_text is None:
            xml_text = real_installer()[1].decode() if PVE_INSTALLER else make_xml("/nix/store/%s-grub-2.14" % h32("grub"))
        self.xml_values = T.parse_grub_xml(xml_text.encode())
        self.grub = self.xml_values["grub"]
        self.perl = "/nix/store/%s-perl-5.42.3-env/bin/perl" % h32("perl")
        self.pl = "/nix/store/%s-install-grub.pl" % h32("pl")
        self.xml = "/nix/store/%s-grub-config.xml" % h32("xml")
        self.installer = "/nix/store/%s-install-grub.sh" % h32("sh")
        self._write(self.xml, xml_text)
        self._write(self.pl, "# not run: the fake perl renders grub.cfg itself\n")
        self._write(self.installer, "#!/nix/store/%s-bash-5.3p15/bin/bash\nset -e\n\n%s %s %s $@\n"
                    % (h32("bash"), self.perl, self.pl, self.xml))
        self.write_fakes()
        os.makedirs(self.p(self.grub + "/bin"))
        os.symlink(GRUB_EDITENV, self.p(self.grub + "/bin/grub-editenv"))
        self._write("/boot/grub/state", state_text(self.xml_values))
        self._write_bytes("/dev/vda", bytes(range(256)) * 4096)
        self._write("/proc/locks", "")
        self._write("/proc/self/cgroup", "0::/system.slice/cogworx-pve-upgrade-fetch.service\n")
        self._write("/proc/sys/kernel/random/boot_id", "b0000000-0000-4000-8000-000000000000\n")

        self.dep = "/nix/store/%s-dep-base" % h32("dep")
        os.makedirs(self.p(self.dep))
        self.register(self.dep, [self.dep])
        self.add_system("A", in_store=True, release=None)
        self.add_system("B")
        self.add_system("C")

        # The bake: system profile generation 1, booted A, grub.cfg, grubenv.
        os.makedirs(self.p("/nix/var/nix/profiles"), exist_ok=True)
        os.symlink(self.sys["A"], self.p("/nix/var/nix/profiles/system-1-link"))
        os.symlink("system-1-link", self.p("/nix/var/nix/profiles/system"))
        self.set_booted(self.sys["A"])
        r = subprocess.run([self.p(self.perl), self.pl, self.xml, self.sys["A"]], capture_output=True)
        assert r.returncode == 0, r.stderr
        self.editenv("create")
        os.unlink(os.path.join(self.logs, "installer.jsonl"))

    # --- tree helpers ---
    def p(self, path):
        return self.root + path

    def _write(self, path, text):
        self._write_bytes(path, text.encode())

    def _write_bytes(self, path, data):
        os.makedirs(os.path.dirname(self.p(path)), exist_ok=True)
        with open(self.p(path), "wb") as f:
            f.write(data)

    def read(self, path):
        with open(self.p(path), "rb") as f:
            return f.read()

    def write_fakes(self):
        cfg = {"root": self.root, "switch": self.sw, "logs": self.logs, "db": self.dbfile, "cache": self.cache,
               "distro": DISTRO}
        src = "#!%s -I\n%s" % (sys.executable, FAKE_SRC)
        for d in (self.bin, os.path.dirname(self.p(self.perl))):
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "fake.json"), "w") as f:
                json.dump(cfg, f)
            fake = os.path.join(d, "fake")
            with open(fake, "w") as f:
                f.write(src)
            os.chmod(fake, 0o755)
        for name in ("nix-env", "nix-store", "systemd-run", "systemctl"):
            if not os.path.lexists(os.path.join(self.bin, name)):
                os.symlink("fake", os.path.join(self.bin, name))
        if not os.path.lexists(self.p(self.perl)):
            os.symlink("fake", self.p(self.perl))

    def switch(self, name, text=""):
        with open(os.path.join(self.sw, name), "w") as f:
            f.write(text)

    def unswitch(self, name):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(os.path.join(self.sw, name))

    def log(self, name):
        try:
            with open(os.path.join(self.logs, name + ".jsonl")) as f:
                return [json.loads(l) for l in f if l.strip()]
        except FileNotFoundError:
            return []

    def register(self, path, refs, size=4096):
        raw = hashlib.sha256(("nar " + path).encode()).digest()
        self.db[path] = {"refs": refs, "hash": sha_forms(raw), "size": size}
        with open(self.dbfile, "w") as f:
            json.dump(self.db, f)

    def invalidate(self, label):
        """What a GC cut between invalidating a path and deleting it leaves:
        the directory, but no database row."""
        del self.db[self.sys[label]]
        with open(self.dbfile, "w") as f:
            json.dump(self.db, f)

    def compat(self, label, release=True, **over):
        doc = {"schema": 1, "kind": "cogworx-pve-system", "toolProto": 1, "txnSchema": 1, "bootProof": 1,
               "stateFormat": 1, "bootConfigVersions": [1], "smbiosSelector": "S", "guestAttrsVersion": 1,
               "release": {"id": "test-" + label.lower(), "builtAt": "2026-10-18T00:00:00Z"} if release else None,
               "controlCAKeys": [], "controlCAFingerprints": [], "controlPlaneCIDRs": ["198.51.100.0/24"],
               "controlUser": "root", "hostKeyPath": "/var/lib/cogworx/sshd/ssh_host_ed25519_key",
               "stateDevice": "/dev/disk/by-id/virtio-cogworx-state",
               "guestDevice": "/dev/disk/by-id/virtio-cogworx-guest", "interface": "eth0",
               "substituters": [], "trustedPublicKeys": [], "specialisations": [],
               "bootloader": {"installer": self.installer, "grub": self.grub, "devices": ["/dev/vda"],
                              "distroName": DISTRO, "guard": T.guard_of(self.xml_values)}}
        doc.update(over)
        return doc

    def add_system(self, label, in_store=False, release=True, params=PARAMS, version=None, drop=(),
                   compat=None, raw_compat=None, specialisation=False, tool_mode=0o755, extra_files=None):
        path = "/nix/store/%s-nixos-system-t-%s" % (h32("sys-" + label), label)
        base = self.root + "/nix/store" if in_store else self.cache
        d = os.path.join(base, path[len("/nix/store/"):])
        os.makedirs(os.path.join(d, "sw/bin"))
        files = {"kernel": "kernel " + label, "initrd": "initrd " + label, "init": "#!/bin/sh\n",
                 "kernel-params": params, "nixos-version": version or "26.11.20261008-t" + label,
                 "sw/bin/cogworx-pve-upgrade": "the tool of " + label}
        if raw_compat is None:
            raw_compat = json.dumps(compat if compat is not None else self.compat(label, release))
        files["cogworx-pve-compat.json"] = raw_compat
        files.update(extra_files or {})
        for name, text in files.items():
            if name in drop:
                continue
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        if "sw/bin/cogworx-pve-upgrade" not in drop:
            os.chmod(os.path.join(d, "sw/bin/cogworx-pve-upgrade"), tool_mode)
        if specialisation:
            os.makedirs(os.path.join(d, "specialisation", "x"))
        self.sys[label] = path
        self.register(path, [path, self.dep])
        return path

    def set_booted(self, path):
        for link in ("/run/booted-system", "/run/current-system"):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(self.p(link))
            os.symlink(path, self.p(link))

    def editenv(self, *args):
        r = subprocess.run([GRUB_EDITENV, self.p("/boot/grub/grubenv")] + list(args), capture_output=True)
        assert r.returncode == 0, r.stderr
        return r

    def env(self):
        return T.parse_grubenv(self.read("/boot/grub/grubenv"))

    def cfg(self):
        return T.parse_grub_cfg(self.read("/boot/grub/grub.cfg").decode("latin-1"), DISTRO)

    def doc(self):
        with open(self.p("/var/lib/cogworx-pve-upgrade/txn.json")) as f:
            return json.load(f)

    def resolve(self, path):
        old = T.ROOT
        T.ROOT = self.root
        try:
            return T.resolve(path)
        finally:
            T.ROOT = old

    # --- the tool ---
    def configure(self):
        T.ROOT = self.root
        T.CHILD_PATH = self.bin
        T.MIN_FREE_BYTES = str(MIN_FREE)
        T.RESERVE_BYTES = str(RESERVE)
        T.STEP_HOOK = None
        T.WORKER_LOCK_WAIT = 2.0
        T.WORKER_REGISTER_WAIT = self.register_wait
        T.statvfs_free = self.statvfs

    def statvfs(self, path):
        gc = os.path.exists(os.path.join(self.sw, "gc-ran"))
        return self.free + (self.gc_frees if gc else 0)

    def tool(self, label):
        return self.sys[label] + "/sw/bin/cogworx-pve-upgrade"

    def run(self, argv0, *args, env=None, hook=None):
        """One in-process invocation: (exit code, the parsed envelope). `hook`
        is its STEP_HOOK(verb, n, name)."""
        self.configure()
        T.STEP_HOOK = hook
        out, err = io.StringIO(), io.StringIO()
        saved = dict(os.environ)
        os.environ.pop("INVOCATION_ID", None)
        os.environ.update(env or {})
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = T.main([argv0] + list(args))
        finally:
            T.STEP_HOOK = None
            os.environ.clear()
            os.environ.update(saved)
        text = out.getvalue()
        self.last_stderr = err.getvalue()
        assert text.endswith("\n") and text.count("\n") == 1, "not exactly one line: %r" % text
        assert all(ord(c) < 128 for c in text), "non-ASCII output"
        doc = json.loads(text)
        assert doc["exit"] == code and doc["ok"] == (code == 0), doc
        assert json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n" == text, "keys not sorted"
        return code, doc

    def status(self, label="A"):
        code, env = self.run("/somewhere/cogworx-pve-upgrade", "status")
        assert code == 0, env
        return env["status"]

    def digest(self, label):
        """The closure digest, computed here independently of the tool."""
        path = self.sys[label]
        seen, todo = [], [path]
        while todo:
            q = todo.pop()
            if q not in seen:
                seen.append(q)
                todo.extend(self.db[q]["refs"])
        lines = "".join("%s %s\n" % (q, self.db[q]["hash"]["nix32"]) for q in sorted(seen, key=str.encode))
        return hashlib.sha256(lines.encode()).hexdigest()

    def fetch(self, by, label, tid, closure=None, extra=()):
        return self.run(self.tool(by), "fetch", "--txn", tid, "--target", self.sys[label],
                        "--closure", closure or self.digest(label), *extra)

    def work(self, tid, hook=None):
        """Run the worker the launcher asked systemd-run for, in-process."""
        argv = self.log("systemd-run")[-1]["argv"]
        sep = argv.index("--")
        return self.run(argv[sep + 1], *argv[sep + 2:], env={"INVOCATION_ID": "0123456789abcdef"}, hook=hook)

    def fetched(self, by, label, tid, extra=()):
        code, env = self.fetch(by, label, tid, extra=extra)
        assert code == 0, env
        code, env = self.work(tid)
        assert code == 0 and env["status"]["txn"]["state"] == "fetched", env
        return env

    def armed(self, by, label, tid):
        self.fetched(by, label, tid)
        code, env = self.run(self.tool(by), "arm", "--txn", tid)
        assert code == 0 and env["status"]["txn"]["state"] == "armed", env
        return env

    def cycle(self, frm, to, tid, retain=True):
        """A full switch frm -> to with a trial boot; returns the commit envelope."""
        self.armed(frm, to, tid)
        assert self.boot("c") == self.sys[to]
        args = ("--retain-until", RETAIN) if retain else ("--no-rollback",)
        code, env = self.run(self.tool(frm), "commit", "--txn", tid, *args)
        assert code == 0 and env["status"]["txn"]["state"] == "committed", env
        return env

    # --- GRUB and the guard, modelled ---
    def boot(self, serial=None):
        """A reboot: GRUB consumes the one-shot and the guard decides (serial
        None: no SMBIOS serial; "c"/"r": a v1 blob with S=c/S=r; "m": a v1
        blob without S), then /run is fresh. Returns the booted toplevel."""
        self.boots += 1
        self.nonce += 1
        nonce = "00000000-0000-4000-8000-%012d" % self.nonce
        env = self.env() or {}
        cfg = self.cfg()
        default, once = "0", False
        if env.get("next_entry"):
            default, once = env["next_entry"], True
            self.editenv("set", "next_entry=")
        if once:
            if serial == "c":
                self.editenv("set", "cwx_once=c:" + nonce)
            elif serial is not None:
                default = "0"
                self.editenv("set", "cwx_once=d:" + nonce)
            else:
                self.editenv("set", "cwx_once=u:")
        if serial == "r" and env.get("cwx_rollback_entry"):
            default = env["cwx_rollback_entry"]
        target = cfg["entry0"]["init"]
        if default != "0":
            sub, _, ent = default.partition(">")
            for s in cfg["submenus"]:
                for e in s["entries"]:
                    if s["title"] == sub and e["title"] == ent:
                        target = e["init"]
        self.set_booted(target)
        for f in ("/run/cogworx-pve-upgrade.lock", "/run/cogworx-pve-upgrade.holder"):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(self.p(f))
        shutil.rmtree(self.p("/run/cogworx-pve-upgrade"), ignore_errors=True)
        self._write("/proc/sys/kernel/random/boot_id", "b0000000-0000-4000-8000-%012d\n" % self.boots)
        return target

    def crash_after(self, by, verb, k, *args):
        """Run `verb` in a subprocess that dies right after step k."""
        cfgfile = os.path.join(self.dir, "driver.json")
        with open(cfgfile, "w") as f:
            json.dump({"tool": TOOL_SRC, "root": self.root, "bin": self.bin, "min_free": MIN_FREE,
                       "reserve": RESERVE, "free": self.free, "verb": verb, "k": k,
                       "argv": [self.tool(by), verb] + list(args)}, f)
        driver = os.path.join(self.dir, "driver.py")
        with open(driver, "w") as f:
            f.write(DRIVER_SRC)
        r = subprocess.run([sys.executable, "-I", driver, cfgfile], capture_output=True)
        assert r.returncode == 99, "step %s %d was not reached (exit %d): %s %s" % (
            verb, k, r.returncode, r.stdout.decode(), r.stderr.decode()[-2000:])

    def clone(self):
        """A copy of this world in a new directory (paths rewritten)."""
        new = World.__new__(World)
        new.__dict__.update({k: v for k, v in self.__dict__.items()})
        new.dir = tempfile.mkdtemp(prefix="cwx-upg-")
        os.rmdir(new.dir)
        shutil.copytree(self.dir, new.dir, symlinks=True)
        for k in ("root", "bin", "cache", "sw", "logs", "dbfile"):
            setattr(new, k, getattr(self, k).replace(self.dir, new.dir, 1))
        new.db = json.loads(json.dumps(self.db))
        new.sys = dict(self.sys)
        new.write_fakes()
        return new

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class Base(unittest.TestCase):
    def world(self, **kw):
        w = World(**kw)
        self.addCleanup(w.close)
        w.configure()
        return w

    def assertInvariants(self, w, committed=None):
        st = w.status()
        if committed:
            self.assertEqual(st["committed"], w.sys[committed])
        self.assertEqual(st["system_head"], st["committed"], st)
        self.assertEqual(st["entry0_init"], st["committed"], st)
        self.assertIsNone(st["candidate"], st)
        self.assertIsNone(st["next_entry"], st)
        self.assertTrue(st["grubcfg"]["ok"], st["grubcfg"])
        self.assertEqual(st["rollback"]["path"], st["rollback"]["recorded"], st["rollback"])
        self.assertTrue(st["grubenv_ok"])
        self.assertEqual(st["crash_state"], [], st)
        rb = st["grubcfg"]["rollback_entry"]
        self.assertEqual(st["cwx_rollback_entry"], rb["path"] if rb else None)
        if rb:
            self.assertEqual(rb["init"], st["rollback"]["recorded"])
        self.assertFalse(os.path.lexists(w.p("/nix/var/nix/profiles/system-profiles/cogworx_candidate")))
        gens = [e for e in os.listdir(w.p("/nix/var/nix/profiles")) if re.fullmatch(r"system-[0-9]+-link", e)]
        self.assertEqual(len(gens), 1, gens)
        # No leftover generation link: each one is a GC root the menu never shows.
        sp = w.p("/nix/var/nix/profiles/system-profiles")
        names = sorted(os.listdir(sp)) if os.path.isdir(sp) else []
        if st["rollback"]["recorded"]:
            self.assertEqual(len(names), 2, names)
            self.assertEqual(names[0], "cogworx_rollback")
            self.assertRegex(names[1], r"^cogworx_rollback-[0-9]+-link$")
        else:
            self.assertEqual(names, [])
        return st


# --- 1. grammar ---------------------------------------------------------------------


class GrammarTest(Base):
    def test_every_violation_is_64_and_touches_nothing(self):
        w = self.world()
        A, t = w.sys["A"], txid(1)
        c = "0" * 64
        a0 = w.tool("A")
        cases = [
            [], ["bogus"], ["Status"], ["status", "--txn", t], ["proto", "x"],
            ["closure-digest"], ["closure-digest", "--target", "/nix/store/" + "e" * 32 + "-nixos-system-x"],
            ["closure-digest", "--target", A + "/"],
            ["fetch", "--txn", t, "--target", A], ["fetch", "--txn", t, "--target", A, "--closure", c, "--txn", t],
            ["fetch", "--txn", t, "--target", A, "--closure", c[:-1]],
            ["fetch", "--txn", t, "--target", A, "--closure", c.upper().replace("0", "A")],
            ["fetch", "--txn", t, "--target", A, "--closure", c, "--closure-bytes", "0"],
            ["fetch", "--txn", t, "--target", A, "--closure", c, "--closure-bytes", "01"],
            ["fetch", "--txn", t, "--target", A, "--closure", c, "--closure-bytes", "1" * 17],
            ["fetch", "--txn", t, "--target", "/nix/store/x-nixos-system-y", "--closure", c],
            ["fetch", "--txn", t, "--target", A, "--closure", c, "--release-rollback", "yes"],
            ["arm"], ["arm", "--txn"], ["arm", t], ["arm", "--txn=" + t], ["arm", "--txn", t + "\n"],
            ["arm", "--txn", "0000000a-0000-4000-8000-00000000000b".upper()], ["arm", "--txn", t, "--txn", t], ["arm", "--txn", t, "--force"],
            ["arm", "--txn", "\u00e9" + t[1:]], ["arm", "--txn", t, "-x"], ["arm", "--txn", t + "junk"],
            ["commit", "--txn", t], ["commit", "--txn", t, "--retain-until", RETAIN, "--no-rollback"],
            ["commit", "--txn", t, "--retain-until", "2026-13-01T00:00:00Z"],
            ["commit", "--txn", t, "--retain-until", "2026-11-01T24:00:00Z"],
            ["commit", "--txn", t, "--retain-until", "2026-11-01 00:00:00Z"],
            ["abort", "--txn", t, "--release-staged", "x"], ["abort", "--release-staged"],
            ["revert-commit", "--txn", t, "--no-rollback"], ["release", "--txn", t, "--release-staged"],
            ["_fetch"], ["_fetch", "--txn", t, "--target", A],
            ["status"] + ["--x"] * 12, ["arm", "--txn", "x" * 321],
        ]
        before = tree_hash(w.root)
        for args in cases:
            with self.subTest(args=args):
                code, env = w.run(a0, *args)
                self.assertEqual(code, 64, env)
                self.assertEqual(env["reason_class"], "usage")
                self.assertNotIn("status", env)
                self.assertFalse(env["mutated"])
                self.assertIsNone(env["txn_id"])
        self.assertEqual(tree_hash(w.root), before)

    def test_fetch_worker_outside_its_unit_is_64(self):
        w = self.world()
        code, env = w.run(w.tool("A"), "_fetch", "--txn", txid(1))
        self.assertEqual(code, 64)
        w._write("/proc/self/cgroup", "0::/user.slice/session-1.scope\n")
        code, env = w.run(w.tool("A"), "_fetch", "--txn", txid(1), env={"INVOCATION_ID": "1"})
        self.assertEqual(code, 64)

    def test_parse_argv_accepts_every_documented_shape(self):
        A, t, c = "/nix/store/%s-nixos-system-unnamed-26.11" % ("0" * 32), txid(3), "a" * 64
        good = [
            ["proto"], ["status"], ["closure-digest", "--target", A],
            ["fetch", "--release-rollback", "--closure-bytes", "123", "--closure", c, "--target", A, "--txn", t],
            ["_fetch", "--txn", t], ["arm", "--txn", t], ["commit", "--no-rollback", "--txn", t],
            ["commit", "--txn", t, "--retain-until", "2026-02-29T23:59:59Z"], ["abort", "--txn", t, "--release-staged"],
            ["revert-commit", "--txn", t], ["release", "--txn", t],
        ]
        for args in good:
            with self.subTest(args=args):
                verb, opts = T.parse_argv(["x"] + args)
                self.assertEqual(verb, args[0])


# --- 2. envelope ---------------------------------------------------------------------


class EnvelopeTest(Base):
    def test_shapes_per_verb(self):
        w = self.world()
        code, env = w.run("/anywhere/tool", "proto")
        self.assertEqual(code, 0)
        self.assertNotIn("status", env)
        self.assertEqual(env["proto"]["verbs"], ["proto", "status", "closure-digest", "fetch", "arm", "commit",
                                                 "abort", "revert-commit", "release"])
        self.assertEqual((env["proto"]["proto"], env["proto"]["txn_schema"], env["proto"]["compat_schema"]), (1, [1], [1]))
        self.assertEqual(env["proto"]["guard"], T.guard_of(w.xml_values))
        self.assertEqual(env["cogworx_pve_upgrade"], 1)
        code, env = w.run("/anywhere/tool", "status")
        self.assertEqual(code, 0)
        self.assertIn("status", env)
        self.assertEqual(set(env), {"cogworx_pve_upgrade", "verb", "ok", "exit", "reason_class", "reason",
                                    "txn_id", "mutated", "status"})
        self.assertEqual(set(env["status"]), {
            "booted", "current", "system_head", "committed", "committed_source", "entry0_init", "candidate",
            "rollback", "next_entry", "cwx_rollback_entry", "cwx_once", "grubenv_ok", "grubcfg",
            "bootloader_pin", "txn", "compat", "free_bytes", "lock", "worker", "trial", "crash_state"})
        code, env = w.run(w.tool("A"), "closure-digest", "--target", w.sys["A"])
        self.assertEqual(code, 0)
        self.assertNotIn("status", env)
        # Failing too: a workstation's /run is not a guest's.
        code, env = w.run(w.tool("A"), "closure-digest", "--target", "/nix/store/%s-nixos-system-gone" % ("0" * 32))
        self.assertEqual((code, env["reason_class"]), (69, "unavailable"), env)
        self.assertNotIn("status", env)
        code, env = w.run(w.tool("A"), "arm", "--txn", txid(1))
        self.assertEqual((code, env["reason_class"]), (65, "state"))
        self.assertIn("status", env)
        self.assertEqual(env["txn_id"], txid(1))

    def test_reason_is_clean_and_bounded(self):
        self.assertEqual(T.clean('a"b\\c\nd\u00e9'), "a?b?c?d?")
        self.assertEqual(len(T.clean("x" * 2000)), 512)

    def test_output_bound_drops_compat_and_exits_70(self):
        env = {"cogworx_pve_upgrade": 1, "verb": "status", "ok": True, "exit": 0, "reason_class": None,
               "reason": None, "txn_id": None, "mutated": False,
               "status": {"compat": {"committed": {"x": "y" * 70000}, "target": None}, "booted": None}}
        code, text = T.render(env)
        self.assertEqual(code, 70)
        doc = json.loads(text)
        self.assertEqual((doc["reason_class"], doc["reason"]), ("internal", "output-too-large"))
        self.assertNotIn("compat", doc["status"])
        self.assertLessEqual(len(text), 65536)

    def test_internal_errors_are_70_never_a_traceback(self):
        w = self.world()
        old = T.build_status
        T.build_status = lambda ctx: 1 / 0
        try:
            code, env = w.run("/anywhere/tool", "status")
        finally:
            T.build_status = old
        self.assertEqual(code, 0)  # status itself succeeded; only its body failed
        self.assertNotIn("status", env)
        old = T.h_status
        T.HANDLERS["status"] = lambda ctx: [][1]
        try:
            code, env = w.run("/anywhere/tool", "status")
        finally:
            T.HANDLERS["status"] = old
        self.assertEqual((code, env["reason_class"]), (70, "internal"))

    def test_broken_pipe_is_swallowed(self):
        rd, wr = os.pipe()
        os.close(rd)
        try:
            r = subprocess.run([sys.executable, "-I", TOOL_SRC, "proto"], stdout=wr, stderr=subprocess.PIPE)
        finally:
            os.close(wr)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(b"Traceback", r.stderr)

    def test_module_is_stdlib_only(self):
        tree = ast.parse(Path(TOOL_SRC).read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.add(node.module.split(".")[0])
        self.assertTrue(names <= set(sys.stdlib_module_names), names - set(sys.stdlib_module_names))


# --- 3. argv[0] -----------------------------------------------------------------------


class Argv0Test(Base):
    def test_rule_per_verb(self):
        w = self.world()
        t = txid(1)
        # Read verbs from any path.
        for a0 in ("/tmp/x/cogworx-pve-upgrade", w.tool("B"), "relative/tool"):
            self.assertEqual(w.run(a0, "status")[0], 0)
            self.assertEqual(w.run(a0, "proto")[0], 0)
        # Mutating verbs from anything but the committed system's path.
        for a0 in (w.tool("B"), "/run/current-system/sw/bin/cogworx-pve-upgrade", w.sys["A"] + "/bin/cogworx-pve-upgrade",
                   w.sys["A"] + "/sw/bin/../bin/cogworx-pve-upgrade"):
            for args in (["fetch", "--txn", t, "--target", w.sys["B"], "--closure", w.digest("B")],
                         ["arm", "--txn", t], ["abort", "--txn", t], ["release", "--txn", t],
                         ["commit", "--txn", t, "--no-rollback"]):
                with self.subTest(a0=a0, verb=args[0]):
                    code, env = w.run(a0, *args)
                    self.assertEqual((code, env["reason_class"]), (65, "not-committed-tool"), env)
                    self.assertFalse(env["mutated"])
        self.assertFalse(os.path.exists(w.p("/var/lib/cogworx-pve-upgrade/txn.json")))
        # revert-commit needs a rollback, and then only the rollback's tool.
        code, env = w.run(w.tool("A"), "revert-commit", "--txn", t)
        self.assertEqual((code, env["reason_class"]), (65, "state"))
        w.cycle("A", "B", t)
        seq = w.doc()["seq"]
        for a0, verb in ((w.tool("A"), "arm"), (w.tool("B"), "revert-commit"), (w.tool("A"), "release")):
            code, env = w.run(a0, verb, "--txn", txid(2))
            self.assertEqual((code, env["reason_class"]), (65, "not-committed-tool"), (verb, env))
        self.assertEqual(w.doc()["seq"], seq)

    def test_rereport_wins_over_the_rule(self):
        w = self.world()
        t = txid(1)
        w.cycle("A", "B", t)
        seq = w.doc()["seq"]
        for a0 in (w.tool("A"), w.tool("B")):
            code, env = w.run(a0, "commit", "--txn", t, "--retain-until", RETAIN)
            self.assertEqual(code, 0, env)
            self.assertFalse(env["mutated"])
        self.assertEqual(w.doc()["seq"], seq)
        # A different id is not a re-report.
        code, env = w.run(w.tool("A"), "commit", "--txn", txid(9), "--retain-until", RETAIN)
        self.assertEqual((code, env["reason_class"]), (65, "not-committed-tool"))


# --- 4. grub.cfg vectors ----------------------------------------------------------------


class GrubCfgTest(unittest.TestCase):
    def test_vectors(self):
        d = VECTORS / "grubcfg-v1"
        cfgs = sorted(d.glob("*.cfg"))
        self.assertGreaterEqual(len(cfgs), 7)
        for name in ("base", "armed", "committed-with-rollback", "armed-with-rollback", "empty-candidate-submenu",
                     "bad-title", "entry-title", "nested-entry", "unbalanced",
                     # captured in pve-upgrade-vm (install-grub.pl's real output)
                     "vm-base", "vm-armed", "vm-committed-with-rollback", "vm-armed-with-rollback"):
            self.assertTrue((d / (name + ".cfg")).exists(), name)
        for cfg in cfgs:
            with self.subTest(cfg=cfg.name):
                want = json.loads(cfg.with_suffix(".json").read_text())
                self.assertEqual(T.parse_grub_cfg(cfg.read_bytes().decode("latin-1"), DISTRO), want)
        for js in d.glob("*.json"):
            self.assertTrue(js.with_suffix(".cfg").exists(), js.name)

    def test_title_path_survives_the_candidate_submenu(self):
        d = VECTORS / "grubcfg-v1"
        a = T.parse_grub_cfg((d / "committed-with-rollback.cfg").read_text(), DISTRO)
        b = T.parse_grub_cfg((d / "armed-with-rollback.cfg").read_text(), DISTRO)
        self.assertEqual(a["profiles"]["cogworx_rollback"], b["profiles"]["cogworx_rollback"])
        titles = lambda p: [s["title"] for s in p["submenus"]]
        self.assertNotEqual(titles(a).index("NixOS - Profile 'cogworx_rollback'"),
                            titles(b).index("NixOS - Profile 'cogworx_rollback'"))

    def test_title_path_survives_the_candidate_submenu_in_the_vm(self):
        # The same on install-grub.pl's real output: commit B (rollback A),
        # then arm C. The rollback submenu moves; its title path does not.
        d = VECTORS / "grubcfg-v1"
        a = T.parse_grub_cfg((d / "vm-committed-with-rollback.cfg").read_text(), DISTRO)
        b = T.parse_grub_cfg((d / "vm-armed-with-rollback.cfg").read_text(), DISTRO)
        self.assertEqual(a["profiles"]["cogworx_rollback"], b["profiles"]["cogworx_rollback"])
        self.assertNotIn("cogworx_candidate", a["profiles"])
        self.assertEqual(b["entry0"], a["entry0"])
        titles = lambda p: [s["title"] for s in p["submenus"]]
        self.assertEqual(titles(a).index("NixOS - Profile 'cogworx_rollback'") + 1,
                         titles(b).index("NixOS - Profile 'cogworx_rollback'"))
        # The grubenv the tool wrote at that arm names the rollback by that path.
        env = T.parse_grubenv((VECTORS / "grubenv-v1" / "vm-armed-with-rollback.env").read_bytes())
        self.assertEqual(env["cwx_rollback_entry"], b["profiles"]["cogworx_rollback"]["path"])
        self.assertEqual(env["next_entry"], b["profiles"]["cogworx_candidate"]["path"])

    def test_the_real_header_bytes_parse(self):
        # install-grub.pl's header comment quotes grub-reboot with U+2018/U+2019.
        base = (VECTORS / "grubcfg-v1" / "base.cfg").read_bytes()
        real = base.replace(b"'grub-reboot'", b"\xe2\x80\x98grub-reboot\xe2\x80\x99")
        self.assertNotEqual(real, base)
        self.assertEqual(T.parse_grub_cfg(real.decode("latin-1"), DISTRO), json.loads((VECTORS / "grubcfg-v1" / "base.json").read_text()))

    def test_errors(self):
        sysp = "/nix/store/%s-nixos-system-x" % ("0" * 32)
        ent = lambda title, init=sysp: 'menuentry "%s" {\n  linux /k init=%s/init\n}\n' % (title, init)
        cases = [
            ("", ["no-entry0"]),
            (ent("Other"), ["entry0-title"]),
            (ent("NixOS", "/nix/store/bad"), ["init:NixOS"]),
            (ent("NixOS") + "}\n", ["unbalanced"]),
            (ent("NixOS") + 'submenu "a" {\nsubmenu "b" {\n}\n}\n', ["nested-submenu:b", "empty-submenu:a"]),
            (ent("NixOS") + 'submenu "NixOS - Profile \'cogworx_x\'" {\n' + ent("NixOS - Configuration 1 (2026-10-18 - v)")
             + ent("NixOS - Configuration 2 (2026-10-18 - v)") + "}\n", ["profile-entries:cogworx_x:2"]),
            (ent("NixOS") + 'submenu "NixOS - Profile \'cogworx_x\'" {\n' + ent("NixOS - Gen 1") + "}\n",
             ["entry-title:NixOS - Gen 1"]),
            (ent("NixOS") + 'submenu "NixOS - Profile \'cogworx_x\'" {\n' + ent("NixOS - Configuration 1 (2026-10-18 - 1\\2)") + "}\n",
             ["title-chars:NixOS - Configuration 1 (2026-10-18 - 1\\2)"]),
        ]
        for text, want in cases:
            with self.subTest(want=want):
                self.assertEqual(T.parse_grub_cfg(text, DISTRO)["errors"], want)
        ok = ent("NixOS") + 'submenu "NixOS - Profile \'cogworx_x\'" {\n' + ent("NixOS - Configuration 7 (2026-10-18 - 26.11 (Tapir))") + "}\n"
        p = T.parse_grub_cfg(ok, DISTRO)
        self.assertEqual(p["errors"], [])
        self.assertEqual(p["profiles"]["cogworx_x"]["path"],
                         "NixOS - Profile 'cogworx_x'>NixOS - Configuration 7 (2026-10-18 - 26.11 (Tapir))")


# --- 5. grubenv ---------------------------------------------------------------------------


class GrubEnvTest(Base):
    def editenv(self, path, *args):
        r = subprocess.run([GRUB_EDITENV, path] + list(args), capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_blocks_from_the_real_grub_editenv(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        f = os.path.join(d, "grubenv")
        def read():
            with open(f, "rb") as fh:
                return fh.read()

        self.editenv(f, "create")
        self.assertEqual(T.parse_grubenv(read()), {})
        title = "NixOS - Profile 'cogworx_candidate'>NixOS - Configuration 3 (2026-10-18 - 26.11 (Tapir))"
        self.editenv(f, "set", "next_entry=" + title, "cwx_once=c:00000000-0000-4000-8000-000000000001")
        self.assertEqual(T.parse_grubenv(read()), {"next_entry": title, "cwx_once": "c:00000000-0000-4000-8000-000000000001"})
        self.editenv(f, "set", "next_entry=")
        self.assertEqual(T.parse_grubenv(read())["next_entry"], "")
        self.editenv(f, "set", "b=a\\b", "n=x\ny")
        self.assertEqual(T.parse_grubenv(read())["b"], "a\\b")
        self.assertEqual(T.parse_grubenv(read())["n"], "x\ny")
        self.editenv(f, "unset", "b", "n", "next_entry")
        self.assertEqual(T.parse_grubenv(read()), {"cwx_once": "c:00000000-0000-4000-8000-000000000001"})
        data = read()
        self.assertEqual(T.env_used(data), data.rfind(b"\n") + 1)
        self.assertIsNone(T.parse_grubenv(data[:-1]))
        self.assertIsNone(T.parse_grubenv(data + b"#"))
        self.assertIsNone(T.parse_grubenv(b"# GRUB Environment Bloc\n" + data[24:] + b"#"))
        u = T.env_used(data)
        self.assertIsNone(T.parse_grubenv(data[:u] + b"noequals\n" + data[u + 9:]))
        self.assertIsNotNone(T.parse_grubenv(data[:u] + b"#comment\n" + data[u + 9:]))
        # Exactly 1024 bytes each, so only the content can make them invalid
        # (the header is 25 bytes with its newline).
        def block(body):
            out = T.ENV_HEADER + body + b"#" * (1024 - len(T.ENV_HEADER) - len(body))
            self.assertEqual(len(out), 1024)
            return out

        self.assertEqual(T.parse_grubenv(block(b"a=1\nb=2\n")), {"a": "1", "b": "2"})
        self.assertIsNone(T.parse_grubenv(block(b"a=1\na=2\n")))
        self.assertIsNone(T.parse_grubenv(block(b"a=1")))
        self.assertIsNone(T.parse_grubenv(None))

    def test_vectors_captured_in_the_vm_test(self):
        # Real blocks from pve-upgrade-vm: grub-install's (base, with its
        # WARNING comment line), the tool's grub-editenv runs (armed,
        # armed-with-rollback, committed-with-rollback) and GRUB's own
        # save_env at a trial boot (trial: next_entry cleared, cwx_once set).
        # Hand-made ones (no vm- prefix) pin the invalid shapes; their
        # expected JSON is null.
        d = VECTORS / "grubenv-v1"
        envs = sorted(d.glob("*.env"))
        names = [e.stem for e in envs]
        for name in ("vm-base", "vm-armed", "vm-trial", "vm-committed-with-rollback", "vm-armed-with-rollback"):
            self.assertIn(name, names)
        for e in envs:
            with self.subTest(env=e.name):
                data = e.read_bytes()
                self.assertEqual(len(data), 1024)
                self.assertEqual(T.parse_grubenv(data), json.loads(e.with_suffix(".json").read_text()))
        for js in d.glob("*.json"):
            self.assertTrue(js.with_suffix(".env").exists(), js.name)
        trial = T.parse_grubenv((d / "vm-trial.env").read_bytes())
        self.assertEqual(trial["next_entry"], "")
        self.assertRegex(trial["cwx_once"], r"^c:[0-9a-f-]{36}$")

    def test_overflow_is_refused_before_grub_editenv_runs(self):
        w = self.world()
        w.fetched("A", "B", txid(1))
        doc = w.doc()
        ctx = T.Ctx(["x"])
        room = 1024 - T.env_used(w.read("/boot/grub/grubenv"))
        # Leave exactly 4 bytes free: `k2=v\n` (5) is refused, by the tool's
        # own accounting (grub-editenv never runs), one byte over the edge.
        T.env_write(ctx, doc, sets={"k": "v" * (room - 3 - 4)})
        before = w.read("/boot/grub/grubenv")
        self.assertEqual(T.env_used(before), 1020)
        with self.assertRaises(T.Fail) as cm:
            T.env_write(ctx, doc, sets={"k2": "v"})
        self.assertEqual((cm.exception.code, cm.exception.cls), (65, "grubenv"))
        self.assertIn("overflow", cm.exception.reason)
        self.assertEqual(w.read("/boot/grub/grubenv"), before)
        # The real grub-editenv agrees that it does not fit ...
        r = subprocess.run([GRUB_EDITENV, w.p("/boot/grub/grubenv"), "set", "k2=v"], capture_output=True)
        self.assertNotEqual(r.returncode, 0)
        # ... and that 4 bytes do: a line of exactly the free room fits.
        T.env_write(ctx, doc, sets={"k3": ""})
        full = w.read("/boot/grub/grubenv")
        self.assertEqual(T.env_used(full), 1024)
        self.assertEqual(T.parse_grubenv(full)["k3"], "")
        # Replacing a value in place within the room still works, and so does
        # making room by unsetting in the same write.
        T.env_write(ctx, doc, sets={"k": "w" * (room - 3 - 4)})
        T.env_write(ctx, doc, sets={"k2": "v"}, unsets=["k", "k3"])
        self.assertEqual(T.parse_grubenv(w.read("/boot/grub/grubenv")), {"k2": "v"})
        with self.assertRaises(T.Fail):
            T.env_write(ctx, doc, sets={"k3": "a\\b"})


# --- 6. closure digest ---------------------------------------------------------------------


class DigestTest(Base):
    def test_vector_in_every_hash_form(self):
        vec = json.loads((VECTORS / "closure-digest-v1.json").read_text())
        w = self.world()
        for e in vec["paths"]:
            os.makedirs(w.p(e["path"]), exist_ok=True)
            refs = [x["path"] for x in vec["paths"]] if e["path"] == vec["target"] else [e["path"]]
            w.db[e["path"]] = {"refs": refs, "size": e["nar_size"],
                               "hash": {"nix32": e["nix32"], "base16": e["base16"], "sri": e["sri"],
                                        "bare32": e["nix32"][7:]}}
        with open(w.dbfile, "w") as f:
            json.dump(w.db, f)
        self.assertNotEqual([e["path"] for e in vec["paths"]], sorted(e["path"] for e in vec["paths"]))
        for form in ("nix32", "base16", "sri", "bare32"):
            with self.subTest(form=form):
                w.switch("hash-form", form)
                code, env = w.run("/workstation/cogworx-pve-upgrade", "closure-digest", "--target", vec["target"])
                self.assertEqual(code, 0, env)
                self.assertEqual(env["closure_digest"], {"target": vec["target"], "closure": vec["expected"],
                                                         "paths": len(vec["paths"]), "nar_bytes": vec["nar_bytes"]})
        self.assertEqual(hashlib.sha256(vec["lines"].encode()).hexdigest(), vec["expected"])
        code, env = w.run("/w/t", "closure-digest", "--target", "/nix/store/%s-nixos-system-gone" % ("1" * 32))
        self.assertEqual((code, env["reason_class"]), (69, "unavailable"))

    def test_hash_forms_and_nix32(self):
        vec = json.loads((VECTORS / "closure-digest-v1.json").read_text())
        for f in vec["hash_forms"]:
            want = "sha256:" + f["nix32"]
            for form in (f["nix32"], "sha256:" + f["nix32"], f["base16"], "sha256:" + f["base16"], f["sri"]):
                self.assertEqual(T.normalize_hash(form), want)
        for n in range(64):
            raw = hashlib.sha256(bytes([n])).digest()
            self.assertEqual(T.nix32_decode(T.nix32_encode(raw), 32), raw)
            self.assertEqual(T.nix32_decode(T.nix32_encode(raw[:20]), 20), raw[:20])
        for bad in ("sha256:" + "e" * 52, "z" * 52, "md5:abc", "sha256-AAAA", "sha256:" + "0" * 51):
            with self.assertRaises(T.Fail):
                T.normalize_hash(bad)


# --- 7. the bootloader pin ------------------------------------------------------------------


@unittest.skipUnless(PVE_INSTALLER or IN_CHECK, "PVE_INSTALLER not set")
class RealPinTest(unittest.TestCase):
    def setUp(self):
        self.text, self.xml = real_installer()
        self.x = T.parse_grub_xml(self.xml)

    def test_fields_and_state(self):
        perl, pl, xml = T.parse_installer_script(self.text)
        self.assertTrue(perl.endswith("/bin/perl") and pl.endswith("-install-grub.pl") and xml.endswith("-grub-config.xml"))
        self.assertIsNone(T.check_xml(self.x))
        self.assertEqual(self.x["grub"], PVE_GRUB)
        self.assertEqual(self.x["devices"], ["/dev/vda"])
        self.assertIsNone(T.compare_state(self.x, state_text(self.x)))
        # The guard is detected from extraConfig, whatever this tree ships.
        want = "cwx-guard-v1" if "# cwx-guard-v1" in (self.x["extraConfig"] or "").split("\n") else None
        self.assertEqual(T.guard_of(self.x), want)

    def test_each_requirenewinstall_input(self):
        good = state_text(self.x).split("\n")
        js = json.loads(good[5])
        variants = {
            "devices": (3, "/dev/vdb"), "efi": (2, "both"), "efiMountPoint": (4, "/efi"),
            "extraGrubInstallArgs": (5, json.dumps(dict(js, extraGrubInstallArgs=["--force"]))),
            "grub": (5, json.dumps(dict(js, grub=js["grub"] + "-other"))),
            "grubEfi": (5, json.dumps(dict(js, grubEfi="/nix/store/%s-grub-efi" % ("0" * 32)))),
        }
        for name, (i, value) in variants.items():
            lines = list(good)
            lines[i] = value
            with self.subTest(field=name):
                self.assertIsNotNone(T.compare_state(self.x, "\n".join(lines)))
        self.assertIsNotNone(T.compare_state(self.x, "\n".join(good[:5])))
        self.assertIsNone(T.compare_state(self.x, "\n".join(good[:5] + [json.dumps(dict(js, extra="x"))]) + "\n"))

    def test_script_shapes_refused(self):
        lines = self.text.split("\n")
        perl_line = [l for l in lines if "/bin/perl " in l][0]
        bad = [
            self.text.replace(perl_line, perl_line + "\n" + perl_line),
            self.text.replace("set -e", "set -e\nexport GRUB_ENABLE_CRYPTODISK=y"),
            self.text + "echo extraInstallCommands\n",
            "\n".join(lines[1:]),
            self.text.replace("$@", '"$@"'),
        ]
        for text in bad:
            with self.subTest(text=text[-60:]):
                with self.assertRaises(T.PinError):
                    T.parse_installer_script(text)

    def test_xml_settings_refused(self):
        s = self.xml.decode()

        def setv(name, tag, value):
            return re.sub(r'(<attr name="%s">\s*<%s value=")[^"]*(")' % (name, tag), r"\g<1>%s\g<2>" % value, s)

        bad = [setv("useOSProber", "bool", "true"), setv("extraPrepareConfig", "string", "x"),
               setv("extraEntries", "string", "menuentry"), setv("copyKernels", "bool", "true"),
               setv("default", "string", "1"), setv("default", "string", "saved"),
               setv("configurationLimit", "int", "0"), setv("grubEfi", "string", "/nix/store/%s-grub" % ("0" * 32))]
        for text in bad:
            self.assertNotEqual(text, s)
            self.assertIsNotNone(T.check_xml(T.parse_grub_xml(text.encode())))


class PinTest(Base):
    def test_guard_marker_detection(self):
        g = "/nix/store/%s-grub-2.14" % ("0" * 32)
        guard = Path(TOOL_SRC).parent / "grub-guard.cfg"
        text = guard.read_text() if guard.exists() else "# cwx-guard-v1\ninsmod smbios\n"
        self.assertEqual(T.guard_of(T.parse_grub_xml(make_xml(g, extraConfig=text).encode())), "cwx-guard-v1")
        self.assertEqual(T.guard_of(T.parse_grub_xml(make_xml(g, extraConfig="serial\n" + text).encode())), "cwx-guard-v1")
        self.assertIsNone(T.guard_of(T.parse_grub_xml(make_xml(g, extraConfig="# cwx-guard-v1x\n").encode())))
        self.assertIsNone(T.guard_of(T.parse_grub_xml(make_xml(g).encode())))

    def test_derive_pin_and_boot_area(self):
        w = self.world()
        pin = T.derive_pin(w.sys["A"])
        self.assertEqual({k: pin[k] for k in ("installer", "perl", "script", "xml", "grub", "devices", "distro")},
                         {"installer": w.installer, "perl": w.perl, "script": w.pl, "xml": w.xml, "grub": w.grub,
                          "devices": ["/dev/vda"], "distro": DISTRO})
        disk = bytearray(w.read("/dev/vda"))
        want = hashlib.sha256(bytes(disk[0:446]) + bytes(disk[510:512]) + bytes(disk[512:1048576])).hexdigest()
        self.assertEqual(pin["boot_area_sha256"], {"/dev/vda": want})
        disk[450:500] = b"\x00" * 50  # the partition table: growpart rewrites it
        w._write_bytes("/dev/vda", bytes(disk))
        self.assertEqual(T.boot_area_hash("/dev/vda"), want)
        for off in (100, 511, 700, 1048575):
            d2 = bytearray(disk)
            d2[off] ^= 0xFF
            w._write_bytes("/dev/vda", bytes(d2))
            self.assertNotEqual(T.boot_area_hash("/dev/vda"), want, off)
        w._write_bytes("/dev/vda", bytes(disk))

    def test_unpinnable_installer_is_69_and_writes_nothing(self):
        w = self.world()
        w._write(w.installer, w.read(w.installer).decode() + "echo tail\n")
        code, env = w.fetch("A", "B", txid(1))
        self.assertEqual((code, env["reason_class"]), (69, "unavailable"), env)
        self.assertFalse(env["mutated"])
        self.assertFalse(os.path.exists(w.p("/var/lib/cogworx-pve-upgrade/txn.json")))

    def test_state_drift_refuses_arm_and_installer_runs(self):
        w = self.world()
        w.fetched("A", "B", txid(1))
        good = w.read("/boot/grub/state")
        w._write("/boot/grub/state", good.decode().replace("/dev/vda", "/dev/vdb"))
        code, env = w.run(w.tool("A"), "arm", "--txn", txid(1))
        self.assertEqual((code, env["reason_class"]), (65, "bootloader"))
        self.assertFalse(env["mutated"])
        self.assertIn("bootloader_pin_mismatch", env["status"]["crash_state"])
        self.assertEqual(env["status"]["bootloader_pin"]["state"], "mismatch")
        w._write_bytes("/boot/grub/state", good)
        self.assertEqual(w.status()["bootloader_pin"]["state"], "pinned")

    def test_grub_install_or_boot_area_change_during_a_run(self):
        for switch in ("installer-rewrite-state", "installer-touch-boot-area", "installer-fail"):
            with self.subTest(switch=switch):
                w = self.world()
                w.fetched("A", "B", txid(1))
                w.switch(switch)
                code, env = w.run(w.tool("A"), "arm", "--txn", txid(1))
                self.assertEqual((code, env["reason_class"]), (65, "bootloader"), env)
                self.assertTrue(env["mutated"])
                self.assertEqual(env["status"]["txn"]["state"], "arming")

    def test_every_installer_run_verifies_the_pin_first(self):
        # The verbs check the pin before their first step too; installer()
        # must not rely on that (the headroom release runs it from the worker).
        w = self.world()
        w.fetched("A", "B", txid(1))
        doc = T.read_doc()
        good = w.read("/boot/grub/state")
        w._write("/boot/grub/state", good.decode().replace("/dev/vda", "/dev/vdb"))
        runs = len(w.log("installer"))
        with self.assertRaises(T.Fail) as cm:
            T.installer(T.Ctx(["x"]), doc, w.sys["A"])
        self.assertEqual((cm.exception.code, cm.exception.cls), (65, "bootloader"))
        self.assertEqual(len(w.log("installer")), runs)

    def test_grubenv_writes_are_read_back(self):
        # A grub-editenv that exits 0 and writes nothing.
        w = self.world()
        w.fetched("A", "B", txid(1))
        doc = T.read_doc()
        exe = w.p(w.grub + "/bin/grub-editenv")
        os.unlink(exe)
        with open(exe, "w") as f:
            f.write("#!%s -I\nimport sys\nsys.exit(0)\n" % sys.executable)
        os.chmod(exe, 0o755)
        for kw in ({"sets": {"next_entry": "x"}}, {"unsets": ["cwx_once"]}):
            with self.subTest(kw=kw):
                w.editenv("set", "cwx_once=u:")
                with self.assertRaises(T.Fail) as cm:
                    T.env_write(T.Ctx(["x"]), doc, **kw)
                self.assertEqual((cm.exception.code, cm.exception.cls), (65, "grubenv"))
                self.assertIn("read-back", cm.exception.reason)


# --- 8. compat rules ---------------------------------------------------------------------------


class CompatTest(Base):
    def test_matrix(self):
        w = self.world()
        A = w.sys["A"]
        cases = [
            ("vi-host", dict(compat=w.compat("X", hostKeyPath="/var/lib/other/k")), "compat:vi:hostKeyPath"),
            ("vi-state", dict(compat=w.compat("X", stateDevice="/dev/sdb")), "compat:vi:stateDevice"),
            ("vi-guest", dict(compat=w.compat("X", guestDevice="/dev/sdc")), "compat:vi:guestDevice"),
            ("vi-iface", dict(compat=w.compat("X", interface="ens3")), "compat:vi:interface"),
            ("vi-user", dict(compat=w.compat("X", controlUser="cogworx")), "compat:vi:controlUser"),
            ("viii", dict(compat=w.compat("X", stateFormat=2)), "compat:viii:stateFormat"),
            ("ix", dict(compat=w.compat("X", txnSchema=2)), "compat:ix:txnSchema"),
            ("x-release", dict(release=False), "compat:x:release"),
            ("x-kind", dict(compat=w.compat("X", kind="other")), "compat:x:kind"),
            ("x-schema", dict(compat=w.compat("X", schema=2)), "compat:x:schema"),
            ("xi-list", dict(compat=w.compat("X", specialisations=["s"])), "compat:xi:specialisations"),
            ("xi-dir", dict(specialisation=True), "compat:xi:specialisation"),
            ("xii-fail", dict(params="console=ttyS0 panic=10"), "compat:xii:boot.panic_on_fail"),
            ("xii-zero", dict(params="boot.panic_on_fail panic=0"), "compat:xii:panic"),
            ("xii-last", dict(params="panic=1 boot.panic_on_fail panic=0"), "compat:xii:panic"),
            ("xii-none", dict(params="boot.panic_on_fail"), "compat:xii:panic"),
            ("xii-neg", dict(params="boot.panic_on_fail panic=-1"), "compat:xii:panic"),
            ("xii-ok", dict(params="panic=0 boot.panic_on_fail panic=10"), None),
            ("xiii-v", dict(version="26.11$x"), "compat:xiii:nixos-version"),
            ("xiii-v2", dict(version="a>b"), "compat:xiii:nixos-version"),
            ("xiii-long", dict(version="v" * 129), "compat:xiii:nixos-version"),
            ("xiii-max", dict(version="v" * 128), None),
            # After a commit only the target's own tool may abort, release or
            # move it on (the argv[0] rule): no tool, no switch.
            ("xiii-tool", dict(drop=("sw/bin/cogworx-pve-upgrade",)), "compat:xiii:sw/bin/cogworx-pve-upgrade"),
            ("xiii-tool-noexec", dict(tool_mode=0o644), "compat:xiii:sw/bin/cogworx-pve-upgrade"),
            # install-grub.pl would run it as root at arm, before any trial,
            # and fail commit step 5 on it (fatal for entry 0).
            ("xiii-initrd-secrets", dict(extra_files={"append-initrd-secrets": "#!/bin/sh\n"}),
             "compat:xiii:append-initrd-secrets"),
            ("doc-big", dict(raw_compat=json.dumps(dict(w.compat("X"), pad="x" * 16400))), "compat:doc"),
            ("doc-bad", dict(raw_compat="{not json"), "compat:doc"),
            ("doc-none", dict(drop=("cogworx-pve-compat.json",)), "compat:doc"),
        ] + [("xiii-" + f, dict(drop=(f,)), "compat:xiii:" + f) for f in ("kernel", "initrd", "init", "kernel-params", "nixos-version")]
        for name, kw, want in cases:
            with self.subTest(case=name):
                tgt = w.add_system("X-" + name, in_store=True, **kw)
                self.assertEqual(T.compat_problem(tgt, A), want)
        # A real toplevel's shape: sw -> <system-path>, whose bin entry links
        # to the tool package's file. Resolved, it must be an executable file.
        pkg = "/nix/store/%s-cogworx-pve-upgrade" % h32("tool-pkg")
        w._write(pkg + "/bin/cogworx-pve-upgrade", "the tool\n")
        os.chmod(w.p(pkg + "/bin/cogworx-pve-upgrade"), 0o555)
        spath = "/nix/store/%s-system-path" % h32("system-path")
        os.makedirs(w.p(spath + "/bin"))
        os.symlink(pkg + "/bin/cogworx-pve-upgrade", w.p(spath + "/bin/cogworx-pve-upgrade"))
        for name, shape, want in (("linked", "link", None), ("dangling", "dangling", "compat:xiii:sw/bin/cogworx-pve-upgrade"),
                                  ("directory", "dir", "compat:xiii:sw/bin/cogworx-pve-upgrade")):
            with self.subTest(case="xiii-tool-" + name):
                tgt = w.add_system("X-tool-" + name, in_store=True, drop=("sw/bin/cogworx-pve-upgrade",))
                shutil.rmtree(w.p(tgt + "/sw"))
                if shape == "link":
                    os.symlink(spath, w.p(tgt + "/sw"))
                elif shape == "dangling":
                    os.makedirs(w.p(tgt + "/sw/bin"))
                    os.symlink(pkg + "-gone/bin/cogworx-pve-upgrade", w.p(tgt + "/sw/bin/cogworx-pve-upgrade"))
                else:
                    os.makedirs(w.p(tgt + "/sw/bin/cogworx-pve-upgrade"))
                self.assertEqual(T.compat_problem(tgt, A), want)
        os.unlink(w.p(A + "/cogworx-pve-compat.json"))
        with self.assertRaises(T.Fail) as cm:
            T.compat_problem(w.sys["X-xii-ok"], A)
        self.assertEqual(cm.exception.code, 69)


# --- 9. fetch: classification, sizes, headroom ---------------------------------------------------

# nix 2.34.8, captured with LC_ALL=C against local file:// caches.
NIX_SIG = ("warning: ignoring substitute for '/nix/store/lcxc2z1h2g8wq8dxfpizy1di85kyxnqx-hello-2.12.3' from "
           "'file:///tmp/cache', as it's not signed by any of the keys in 'trusted-public-keys'\n"
           "error: path '/nix/store/lcxc2z1h2g8wq8dxfpizy1di85kyxnqx-hello-2.12.3' is required, but there is no "
           "substituter that can build it\n")
NIX_NOT_FOUND = ("don't know how to build these paths:\n  /nix/store/00000000000000000000000000000000-nixos-system-x\n"
                 "error: path '/nix/store/00000000000000000000000000000000-nixos-system-x' is required, but there is "
                 "no substituter that can build it\n")
NIX_DRY = ("these 5 paths will be fetched (36.2 MiB download, 36.2 MiB unpacked):\n"
           "  /nix/store/0d8g8n0a11v6f5m2h416ajyxmnkwc3md-glibc-2.42-67\n")


class FetchTest(Base):
    def test_classification(self):
        cases = [
            (NIX_SIG, "signature"), (NIX_NOT_FOUND, "not-found"),
            ("don't know how to build these paths:\n  /nix/store/x\n", "not-found"),
            ("error: writing to file: No space left on device\n" + NIX_SIG, "enospc"),
            ("error: hash mismatch importing path '/nix/store/x';\n  specified: sha256:0\n  got: sha256:1\n", "integrity"),
            ("error: ca hash mismatch importing path '/nix/store/x'\n", "integrity"),
            ("error: hash mismatch for '/nix/store/x'\n", "integrity"),
            ("error: unable to download 'https://cache.example/x.narinfo': Couldn't resolve host name (6)\n", "unreachable"),
            ("error: unable to download 'https://cache.example/x.narinfo': HTTP error 503\n", "unreachable"),
            ("error: Connection refused\n", "unreachable"), ("error: operation timed out\n", "unreachable"),
            ("error: something else entirely\n", "internal"), ("", "internal"),
        ]
        for text, want in cases:
            with self.subTest(want=want, text=text[:40]):
                self.assertEqual(T.classify(text), want)

    def test_dry_run_sizes(self):
        cases = [
            (NIX_DRY, (5, int(36.2 * (1 << 20)) + 1, True)),
            ("these 3 paths will be fetched (1.50 MiB download, 6.25 MiB unpacked):\n", (3, int(6.25 * (1 << 20)), True)),
            ("this path will be fetched (0.5 KiB download, 1.0 KiB unpacked):\n  /nix/store/x\n", (1, 1024, True)),
            ("these 2 paths will be fetched (1.0 GiB download, 2.0 GiB unpacked):\n", (2, 2 << 30, True)),
            ("these 2 paths will be fetched (1.0 TiB download, 1.5 TiB unpacked):\n", (2, 3 << 39, True)),
            ("these 2 paths will be fetched (10 B download, 20 B unpacked):\n", (2, 20, True)),
            ("", (0, 0, True)),
            ("these 2 paths will be fetched (lots download, more unpacked):\n", (0, 0, False)),
        ]
        for text, want in cases:
            with self.subTest(text=text[:50]):
                self.assertEqual(T.parse_dry_run(text), want)

    def test_headroom_arithmetic(self):
        self.assertTrue(T.headroom_ok(MIN_FREE + RESERVE, 0, MIN_FREE, RESERVE))
        self.assertFalse(T.headroom_ok(MIN_FREE + RESERVE - 1, 0, MIN_FREE, RESERVE))
        self.assertTrue(T.headroom_ok(MIN_FREE + RESERVE + 3 * GiB, 2 * GiB, MIN_FREE, RESERVE))
        self.assertFalse(T.headroom_ok(MIN_FREE + RESERVE + 3 * GiB - 1, 2 * GiB, MIN_FREE, RESERVE))

    def worker_verdict(self, w, tid, label="B", closure=None, extra=()):
        code, env = w.fetch("A", label, tid, closure=closure, extra=extra)
        self.assertEqual(code, 0, env)
        code, env = w.work(tid)
        self.assertEqual(code, 0, env)
        t = env["status"]["txn"]
        return t["state"], t["reason_class"], t["reason"]

    def test_worker_verdicts(self):
        cases = [
            ("dryrun-out", NIX_NOT_FOUND, "not-found"),
            ("realise-err", NIX_SIG, "signature"),
            ("realise-err", "error: writing: No space left on device\n", "enospc"),
            ("realise-err", "error: unable to download 'https://cache.example/x': HTTP error 502\n", "unreachable"),
            ("realise-err", "error: weird\n", "internal"),
        ]
        for switch, text, want in cases:
            with self.subTest(want=want):
                w = self.world()
                w.switch(switch, text)
                state, cls, _ = self.worker_verdict(w, txid(1))
                self.assertEqual((state, cls), ("fetch_failed", want))
                self.assertFalse(os.path.lexists(w.p("/nix/var/nix/gcroots/cogworx-pve-upgrade/staged")))
        w = self.world()
        w.switch("dryrun-out", "these 2 paths will be fetched (x download, y unpacked):\n")
        self.assertEqual(self.worker_verdict(w, txid(1))[:2], ("fetch_failed", "internal"))
        w = self.world()
        w.switch("dryrun-out", "these 2 paths will be fetched (x download, y unpacked):\n")
        self.assertEqual(self.worker_verdict(w, txid(1), extra=("--closure-bytes", "1000"))[:2], ("fetched", None))

    def test_integrity_and_compat_verdicts_unroot_the_target(self):
        w = self.world()
        state, cls, reason = self.worker_verdict(w, txid(1), closure=w.digest("C"))
        self.assertEqual((state, cls), ("fetch_failed", "integrity"))
        self.assertFalse(os.path.lexists(w.p("/nix/var/nix/gcroots/cogworx-pve-upgrade/staged")))
        self.assertIsNone(w.doc()["staged"])
        self.assertEqual(w.run(w.tool("A"), "abort", "--txn", txid(1))[0], 0)
        w.add_system("X", compat=w.compat("X", hostKeyPath="/var/lib/other/ssh_host_ed25519_key"))
        state, cls, reason = self.worker_verdict(w, txid(2), label="X")
        self.assertEqual((state, cls, reason), ("fetch_failed", "compat", "compat:vi:hostKeyPath"))
        self.assertFalse(os.path.lexists(w.p("/nix/var/nix/gcroots/cogworx-pve-upgrade/staged")))

    def test_fetched_records_progress_and_roots(self):
        w = self.world()
        state, cls, _ = self.worker_verdict(w, txid(1))
        self.assertEqual((state, cls), ("fetched", None))
        self.assertEqual(os.readlink(w.p("/nix/var/nix/gcroots/cogworx-pve-upgrade/staged")), w.sys["B"])
        self.assertEqual(os.readlink(w.p("/nix/var/nix/gcroots/cogworx-pve-upgrade/committed")), w.sys["A"])
        self.assertEqual(os.readlink(w.p("/nix/var/nix/gcroots/cogworx-pve-upgrade/bootloader")), w.installer)
        d = w.doc()
        self.assertEqual(d["staged"], w.sys["B"])
        self.assertEqual(d["txn"]["fetch"]["missing_at_start"]["paths"], 1)
        self.assertEqual(d["txn"]["fetch"]["attempts"], 1)
        realise = [r["argv"] for r in w.log("nix-store") if r["argv"][0] == "--realise" and "--dry-run" not in r["argv"]][0]
        for opt in ("require-sigs true", "narinfo-cache-negative-ttl 0", "max-jobs 0", "builders ", "fallback false",
                    "fsync-store-paths true"):
            k, v = opt.split(" ")
            self.assertIn(["--option", k, v], [realise[i:i + 3] for i in range(len(realise))], opt)
        st = w.status()
        self.assertEqual(st["txn"]["progress"]["phase"], "done")
        self.assertFalse(st["worker"]["active"])
        run = w.log("systemd-run")[-1]["argv"]
        self.assertEqual(run[:run.index("--")], ["--unit=cogworx-pve-upgrade-fetch", "--collect", "--quiet",
                                                 "-p", "Nice=19", "-p", "IOSchedulingClass=idle",
                                                 "-p", "TimeoutStopSec=20s", "-p", "KillMode=control-group"])
        # A second fetch of the same txn re-reports.
        code, env = w.fetch("A", "B", txid(1))
        self.assertEqual(code, 0)
        self.assertFalse(env["mutated"])

    def test_headroom(self):
        w = self.world()
        w.free = MIN_FREE + RESERVE + 1000
        state, cls, _ = self.worker_verdict(w, txid(1))
        self.assertEqual((state, cls), ("fetch_failed", "headroom"))
        self.assertFalse(os.path.exists(w.p(w.sys["B"])))
        self.assertFalse([r for r in w.log("nix-store") if r["argv"][0] == "--realise" and "--dry-run" not in r["argv"]])

    def test_release_rollback_for_headroom(self):
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        w.free = MIN_FREE + RESERVE
        w.gc_frees = 10 * GiB
        # Without the permission: refused, the rollback stays.
        code, env = w.fetch("B", "C", txid(2))
        self.assertEqual(w.work(txid(2))[1]["status"]["txn"]["reason_class"], "headroom")
        self.assertEqual(w.status()["rollback"]["path"], w.sys["A"])
        self.assertEqual(w.run(w.tool("B"), "abort", "--txn", txid(2))[0], 0)
        # With it: release, collect, re-measure, fetch.
        code, env = w.fetch("B", "C", txid(3), extra=("--release-rollback",))
        code, env = w.work(txid(3))
        st = env["status"]
        self.assertEqual(st["txn"]["state"], "fetched", st["txn"])
        self.assertEqual((st["rollback"]["path"], st["rollback"]["recorded"]), (None, None))
        self.assertIsNone(st["grubcfg"]["rollback_entry"])
        self.assertIsNone(st["cwx_rollback_entry"])
        self.assertEqual(w.doc()["history"][0]["outcome"], "released-for-headroom")
        with open(os.path.join(w.sw, "gc-ran")) as f:
            self.assertIn("--max-freed", f.read())
        self.assertEqual(st["crash_state"], [])

    def released_for_headroom(self):
        """A->B committed, then B->C fetched under --release-rollback: the
        inline release wrote a history entry under the OPEN switch txn's id."""
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        w.free = MIN_FREE + RESERVE
        w.gc_frees = 10 * GiB
        code, env = w.fetch("B", "C", txid(3), extra=("--release-rollback",))
        self.assertEqual(code, 0, env)
        code, env = w.work(txid(3))
        self.assertEqual(env["status"]["txn"]["state"], "fetched", env["status"]["txn"])
        self.assertEqual((w.doc()["history"][0]["id"], w.doc()["history"][0]["outcome"]),
                         (txid(3), "released-for-headroom"))
        return w

    def test_abort_after_a_headroom_release(self):
        # The closed-id guard must not see that history entry while the txn
        # is open: refusing this abort would leave nothing to end the txn.
        w = self.released_for_headroom()
        code, env = w.run(w.tool("B"), "abort", "--txn", txid(3), "--release-staged")
        self.assertEqual((code, env["status"]["txn"]["state"]), (0, "aborted"), env)
        self.assertInvariants(w, "B")

    def test_abort_after_a_headroom_release_from_the_trial(self):
        # The failed-trial path: armed, S=c booted C, abort from C.
        w = self.released_for_headroom()
        code, env = w.run(w.tool("B"), "arm", "--txn", txid(3))
        self.assertEqual(code, 0, env)
        self.assertEqual(w.boot("c"), w.sys["C"])
        code, env = w.run(w.tool("B"), "abort", "--txn", txid(3))
        self.assertEqual((code, env["status"]["txn"]["state"]), (0, "aborted"), env)
        w.boot()
        self.assertInvariants(w, "B")

    def test_resume_and_mismatch(self):
        w = self.world()
        w.switch("realise-err", NIX_SIG)
        self.assertEqual(self.worker_verdict(w, txid(1))[1], "signature")
        w.unswitch("realise-err")
        code, env = w.fetch("A", "C", txid(1))
        self.assertEqual((code, env["reason_class"]), (65, "txn-mismatch"))
        code, env = w.fetch("A", "B", txid(2))
        self.assertEqual((code, env["reason_class"]), (65, "txn-mismatch"))
        code, env = w.fetch("A", "B", txid(1))
        self.assertEqual(code, 0)
        self.assertEqual(w.doc()["txn"]["fetch"]["attempts"], 2)
        self.assertEqual(w.work(txid(1))[1]["status"]["txn"]["state"], "fetched")
        # A fetched txn re-reports only for the same target AND closure.
        seq = w.doc()["seq"]
        code, env = w.fetch("A", "B", txid(1), closure=w.digest("C"))
        self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "txn-mismatch", False), env)
        self.assertEqual(w.doc()["seq"], seq)
        code, env = w.fetch("A", "A", txid(3))
        self.assertEqual((code, env["reason_class"]), (65, "state"))

    def test_systemd_run_failure(self):
        w = self.world()
        w.switch("systemd-run-fail")
        code, env = w.fetch("A", "B", txid(1))
        self.assertEqual((code, env["reason_class"]), (69, "unavailable"))
        self.assertTrue(env["mutated"])
        self.assertEqual((env["status"]["txn"]["state"], env["status"]["txn"]["reason_class"]), ("fetch_failed", "internal"))
        self.assertEqual(len(w.log("systemd-run")), 2)

    def test_systemd_run_retries_once_after_the_old_unit_goes(self):
        # The previous worker released the lock but its unit is not collected
        # yet: systemd-run fails with "already loaded" once.
        w = self.world()
        w.switch("systemd-run-fail-once")
        code, env = w.fetch("A", "B", txid(1))
        self.assertEqual(code, 0, env)
        self.assertEqual(env["status"]["txn"]["state"], "fetching")
        self.assertEqual(len(w.log("systemd-run")), 2)
        self.assertIn(["is-active", "cogworx-pve-upgrade-fetch.service"], [r["argv"] for r in w.log("systemctl")])
        self.assertEqual(w.work(txid(1))[1]["status"]["txn"]["state"], "fetched")

    def test_the_launcher_waits_for_the_worker_to_register(self):
        # systemd-run returns at fork; the worker writes progress.json (phase
        # lock-wait, its pid in the worker unit's cgroup) only once it runs.
        # The launcher's own status must not show that healthy txn as
        # interrupted. Here the worker registers 0.5 s after systemd-run.
        def register_later(verb, n, name):
            if verb == "fetch" and n == 2:
                def register():
                    w._write("/proc/4243/cgroup", FETCH_CGROUP)
                    w._write("/run/cogworx-pve-upgrade/progress.json",
                             json.dumps({"pid": 4243, "txn": txid(1), "phase": "lock-wait"}))
                timer = threading.Timer(0.5, register)
                timers.append(timer)
                timer.start()

        w = self.world()
        timers = []
        w.register_wait = 5.0
        code, env = w.run(w.tool("A"), "fetch", "--txn", txid(1), "--target", w.sys["B"], "--closure", w.digest("B"),
                          hook=register_later)
        for t in timers:
            t.join()
        self.assertEqual((code, env["reason"]), (0, "the fetch worker started"), env)
        st = env["status"]
        self.assertEqual(st["worker"], {"active": True, "txn": txid(1)})
        self.assertEqual((st["txn"]["state"], st["crash_state"]), ("fetching", []), st)
        # A worker that never registers: the wait is bounded, and the reason
        # says so (cogworxd re-polls before acting on `interrupted`).
        w = self.world()
        w.register_wait = 0.3
        t0 = time.monotonic()
        code, env = w.fetch("A", "B", txid(1))
        self.assertLess(time.monotonic() - t0, 5)
        self.assertEqual((code, env["reason"]), (0, "the fetch worker started; it has not registered yet"), env)
        self.assertEqual((env["status"]["worker"]["active"], env["status"]["crash_state"]), (False, ["interrupted"]))

    def test_fetch_refuses_on_crash_state(self):
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        os.symlink(w.sys["C"], w.p(CANDIDATE))
        seq = w.doc()["seq"]
        code, env = w.fetch("B", "C", txid(2))
        self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "crash-state", False), env)
        self.assertIn("orphan_candidate", env["reason"])
        self.assertEqual(w.doc()["seq"], seq)

    def test_release_for_headroom_refuses_a_drifted_pin_before_touching_anything(self):
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        w.free = MIN_FREE + RESERVE
        w.gc_frees = 10 * GiB
        self.assertEqual(w.fetch("B", "C", txid(2), extra=("--release-rollback",))[0], 0)
        good = w.read("/boot/grub/state")
        w._write("/boot/grub/state", good.decode().replace("/dev/vda", "/dev/vdb"))
        profiles = tree_hash(w.p("/nix/var/nix/profiles"))
        runs = len(w.log("installer"))
        code, env = w.work(txid(2))
        self.assertEqual(code, 0, env)
        t = env["status"]["txn"]
        self.assertEqual((t["state"], t["reason_class"]), ("fetch_failed", "internal"), t)
        self.assertIn("devices differ", t["reason"])
        self.assertEqual(len(w.log("installer")), runs)
        self.assertEqual(tree_hash(w.p("/nix/var/nix/profiles")), profiles)
        self.assertEqual(w.doc()["rollback"]["path"], w.sys["A"])
        self.assertFalse(os.path.exists(os.path.join(w.sw, "gc-ran")))
        w._write_bytes("/boot/grub/state", good)
        self.assertEqual(w.run(w.tool("B"), "abort", "--txn", txid(2))[0], 0)
        self.assertInvariants(w, "B")

    def live_worker(self, w, tid):
        """The worker the launcher asked for, as a live process parked in a
        realise that never ends; its pid is in the worker unit's cgroup."""
        w.switch("realise-hang")
        argv = w.log("systemd-run")[-1]["argv"]
        cfgfile = os.path.join(w.dir, "driver.json")
        with open(cfgfile, "w") as f:
            json.dump({"tool": TOOL_SRC, "root": w.root, "bin": w.bin, "min_free": MIN_FREE, "reserve": RESERVE,
                       "free": w.free, "verb": "none", "k": 0, "env": {"INVOCATION_ID": "x"},
                       "argv": argv[argv.index("--") + 1:]}, f)
        driver = os.path.join(w.dir, "driver.py")
        with open(driver, "w") as f:
            f.write(DRIVER_SRC)
        proc = subprocess.Popen([sys.executable, "-I", driver, cfgfile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        pidfile = os.path.join(w.sw, "realise-pid")
        deadline = time.monotonic() + 30
        while not os.path.exists(pidfile) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(os.path.exists(pidfile), proc.stderr.read1(4000) if proc.poll() is not None else "")
        time.sleep(0.1)
        w._write("/proc/%d/cgroup" % proc.pid, FETCH_CGROUP)
        with open(pidfile) as f:
            return proc, int(f.read())

    def test_abort_stops_a_live_worker_first(self):
        w = self.world()
        self.assertEqual(w.fetch("A", "B", txid(1))[0], 0)
        proc, nix_pid = self.live_worker(w, txid(1))
        st = w.status()
        self.assertEqual(st["worker"], {"active": True, "txn": txid(1)})
        self.assertNotIn("interrupted", st["crash_state"])
        w.switch("worker-pid", str(proc.pid))
        code, env = w.run(w.tool("A"), "abort", "--txn", txid(1), "--release-staged")
        self.assertEqual(code, 0, env)
        self.assertIn(["stop", "cogworx-pve-upgrade-fetch.service"], [r["argv"] for r in w.log("systemctl")])
        out, err = proc.communicate(timeout=25)
        self.assertEqual(proc.returncode, 0, err)
        with self.assertRaises(ProcessLookupError):
            os.kill(nix_pid, 0)
        t = w.doc()["txn"]
        # The worker recorded its own verdict before the abort ran.
        self.assertEqual((t["state"], t["aborted_from"], t["reason_class"]), ("aborted", "fetch_failed", "interrupted"))
        w.boot()
        self.assertInvariants(w, "A")

    def test_a_reused_worker_pid_is_not_the_worker(self):
        # A SIGKILLed worker leaves its holder note and progress.json behind;
        # a live pid outside the worker unit's cgroup is not the worker.
        w = self.world()
        self.assertEqual(w.fetch("A", "B", txid(1))[0], 0)
        w._write("/run/cogworx-pve-upgrade.holder", json.dumps({"pid": 4242, "what": "fetch-worker", "txn": txid(1)}))
        w._write("/run/cogworx-pve-upgrade/progress.json", json.dumps({"pid": 4242, "txn": txid(1), "phase": "realise"}))
        w._write("/proc/4242/cgroup", "0::/user.slice/user-0.slice/session-3.scope\n")
        st = w.status()
        self.assertEqual(st["worker"], {"active": False, "txn": None})
        self.assertIn("interrupted", st["crash_state"])
        code, env = w.fetch("A", "B", txid(1))
        # Nor does it count as the new worker registering (the fake
        # systemd-run starts none).
        self.assertEqual((code, env["mutated"], env["reason"]),
                         (0, True, "the fetch worker started; it has not registered yet"), env)
        self.assertEqual(w.doc()["txn"]["fetch"]["attempts"], 2)
        w._write("/proc/4242/cgroup", FETCH_CGROUP)
        self.assertEqual(w.status()["worker"], {"active": True, "txn": txid(1)})

    def test_sigterm_stops_the_worker_and_records_interrupted(self):
        w = self.world()
        self.assertEqual(w.fetch("A", "B", txid(1))[0], 0)
        w.switch("realise-hang")
        argv = w.log("systemd-run")[-1]["argv"]
        cfgfile = os.path.join(w.dir, "driver.json")
        with open(cfgfile, "w") as f:
            json.dump({"tool": TOOL_SRC, "root": w.root, "bin": w.bin, "min_free": MIN_FREE, "reserve": RESERVE,
                       "free": w.free, "verb": "none", "k": 0, "env": {"INVOCATION_ID": "x"},
                       "argv": argv[argv.index("--") + 1:]}, f)
        driver = os.path.join(w.dir, "driver.py")
        with open(driver, "w") as f:
            f.write(DRIVER_SRC)
        proc = subprocess.Popen([sys.executable, "-I", driver, cfgfile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pidfile = os.path.join(w.sw, "realise-pid")
        deadline = time.monotonic() + 30
        while not os.path.exists(pidfile) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(os.path.exists(pidfile), proc.stderr.read1(4000) if proc.poll() is not None else "")
        time.sleep(0.1)
        with open(pidfile) as f:
            nix_pid = int(f.read())
        t0 = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=25)
        self.assertLess(time.monotonic() - t0, 20)
        self.assertEqual(proc.returncode, 0, err)
        with self.assertRaises(ProcessLookupError):
            os.kill(nix_pid, 0)
        t = w.doc()["txn"]
        self.assertEqual((t["state"], t["reason_class"]), ("fetch_failed", "interrupted"))

    def test_a_late_worker_never_reopens_a_closed_txn(self):
        # The launcher started the worker; abort closed the txn before the
        # worker took the lock (it was not yet visible as the worker); then
        # the worker runs. It must find nothing to fetch.
        w = self.world()
        self.assertEqual(w.fetch("A", "B", txid(1))[0], 0)
        code, env = w.run(w.tool("A"), "abort", "--txn", txid(1))
        self.assertEqual(code, 0, env)
        seq = w.doc()["seq"]
        code, env = w.work(txid(1))
        self.assertEqual((code, env["reason_class"]), (65, "state"), env)
        self.assertEqual((w.doc()["txn"]["state"], w.doc()["seq"]), ("aborted", seq))
        self.assertFalse([r for r in w.log("nix-store") if r["argv"][0] == "--realise"])

    def test_a_stop_outside_the_realise_is_interrupted(self):
        # cogworxd ends a fetch slice with `systemctl stop` (KillMode=
        # control-group): the worker's handler flags the stop and every child
        # in the unit gets SIGTERM too, so whatever step was running fails.
        # The verdict is still `interrupted`, which a resume keys on.
        def stop_at(k, then=None):
            def hook(verb, n, name):
                if verb == "_fetch" and n == k:
                    T._on_term(signal.SIGTERM, None)
                    if then:
                        then()
            return hook

        # The digest's nix-store killed under it.
        w = self.world()
        self.assertEqual(w.fetch("A", "B", txid(1))[0], 0)
        code, env = w.work(txid(1), hook=stop_at(5, lambda: w.switch("hash-fail")))
        self.assertEqual(code, 0, env)
        t = env["status"]["txn"]
        self.assertEqual((t["state"], t["reason_class"]), ("fetch_failed", "interrupted"), t)
        self.assertFalse(os.path.lexists(w.p("/nix/var/nix/gcroots/cogworx-pve-upgrade/staged")))
        # The digest finished, the stop came during it.
        w = self.world()
        self.assertEqual(w.fetch("A", "B", txid(1))[0], 0)
        t = w.work(txid(1), hook=stop_at(5))[1]["status"]["txn"]
        self.assertEqual((t["state"], t["reason_class"]), ("fetch_failed", "interrupted"), t)
        self.assertEqual(w.fetch("A", "B", txid(1))[0], 0)
        self.assertEqual(w.work(txid(1))[1]["status"]["txn"]["state"], "fetched")
        # The headroom release's installer killed under it.
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        w.free = MIN_FREE + RESERVE
        w.gc_frees = 10 * GiB
        self.assertEqual(w.fetch("B", "C", txid(2), extra=("--release-rollback",))[0], 0)
        code, env = w.work(txid(2), hook=stop_at(2, lambda: w.switch("installer-fail")))
        self.assertEqual(code, 0, env)
        t = env["status"]["txn"]
        self.assertEqual((t["state"], t["reason_class"]), ("fetch_failed", "interrupted"), t)
        w.unswitch("installer-fail")
        self.assertEqual(w.run(w.tool("B"), "abort", "--txn", txid(2))[0], 0)
        st = self.assertInvariants(w, "B")
        self.assertEqual(st["rollback"]["recorded"], w.sys["A"])


# --- 10. the state machine -------------------------------------------------------------------------


class StateMachineTest(Base):
    def test_bootstrap(self):
        w = self.world()
        st = w.status()
        self.assertEqual((st["committed"], st["committed_source"], st["crash_state"]), (w.sys["A"], "bootstrap", []))
        self.assertEqual(st["bootloader_pin"]["state"], "unpinned")
        self.assertEqual(st["bootloader_pin"]["installer"], w.installer)
        for name, breaker in (
                ("head", lambda w: os.symlink(w.sys["A"], w.p("/nix/var/nix/profiles/system-2-link")) or
                 os.replace(w.p("/nix/var/nix/profiles/system"), w.p("/nix/var/nix/profiles/x")) or
                 os.symlink("/nix/store/%s-nixos-system-t-other" % ("1" * 32), w.p("/nix/var/nix/profiles/system"))),
                ("booted", lambda w: w.set_booted(w.sys["B"]) if os.makedirs(w.p(w.sys["B"]), exist_ok=True) is None else None),
                ("entry0", lambda w: w._write("/boot/grub/grub.cfg", w.read("/boot/grub/grub.cfg").decode().replace(
                    "init=" + w.sys["A"], "init=" + w.sys["C"], 1))),
                ("profile", lambda w: os.makedirs(w.p("/nix/var/nix/profiles/system-profiles/cogworx_x")))):
            with self.subTest(breaks=name):
                v = self.world()
                breaker(v)
                code, env = v.fetch("A", "B", txid(1))
                self.assertEqual((code, env["reason_class"]), (65, "bootstrap-inconsistent"), env)
                self.assertFalse(os.path.exists(v.p("/var/lib/cogworx-pve-upgrade/txn.json")))
                self.assertTrue({"bootstrap_inconsistent", "untracked_profile"} & set(env["status"]["crash_state"]))

    def test_switch_with_rollback_then_next_switch(self):
        w = self.world()
        env = w.armed("A", "B", txid(1))
        st = env["status"]
        cand = st["grubcfg"]["candidate_entry"]
        self.assertEqual(cand["init"], w.sys["B"])
        self.assertEqual(st["next_entry"], cand["path"])
        self.assertTrue(cand["path"].startswith("NixOS - Profile 'cogworx_candidate'>NixOS - Configuration 1 ("))
        self.assertIsNone(st["cwx_once"])
        self.assertEqual((st["entry0_init"], st["bootloader_pin"]["state"]), (w.sys["A"], "pinned"))
        self.assertEqual(st["crash_state"], [])
        # Re-arm re-reports.
        code, env = w.run(w.tool("A"), "arm", "--txn", txid(1))
        self.assertEqual((code, env["mutated"]), (0, False))
        self.assertEqual(w.boot("c"), w.sys["B"])
        st = w.status()
        self.assertTrue(st["trial"])
        self.assertIsNone(st["next_entry"])
        self.assertTrue(st["cwx_once"].startswith("c:"))
        code, env = w.run(w.tool("A"), "commit", "--txn", txid(1), "--retain-until", RETAIN)
        self.assertEqual(code, 0, env)
        st = env["status"]
        self.assertEqual((st["committed"], st["rollback"]["recorded"], st["rollback"]["retain_until"]),
                         (w.sys["B"], w.sys["A"], RETAIN))
        self.assertFalse(os.path.lexists(w.p("/nix/var/nix/gcroots/cogworx-pve-upgrade/staged")))
        self.assertEqual(os.readlink(w.p("/nix/var/nix/gcroots/cogworx-pve-upgrade/committed")), w.sys["B"])
        self.assertEqual(w.doc()["history"][0]["outcome"], "committed")
        self.assertEqual(w.boot(), w.sys["B"])
        self.assertInvariants(w, "B")
        rb_before = w.status()["cwx_rollback_entry"]
        # The next switch: the candidate submenu sorts before the rollback's,
        # and cwx_rollback_entry still names the rollback by title.
        self.assertTrue(w.env()["cwx_once"].startswith("c:"))
        env = w.armed("B", "C", txid(2))
        st = env["status"]
        self.assertIsNone(st["cwx_once"])
        self.assertEqual(st["cwx_rollback_entry"], rb_before)
        self.assertEqual(st["grubcfg"]["rollback_entry"]["init"], w.sys["A"])
        self.assertEqual(st["grubcfg"]["candidate_entry"]["init"], w.sys["C"])
        self.assertEqual(w.boot("m"), w.sys["B"])
        st = w.status()
        self.assertTrue(st["cwx_once"].startswith("d:"))
        self.assertEqual(w.run(w.tool("B"), "abort", "--txn", txid(2))[0], 0)
        self.assertInvariants(w, "B")
        self.assertEqual(w.status()["rollback"]["recorded"], w.sys["A"])

    def test_commit_no_rollback(self):
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        w.cycle("B", "C", txid(2), retain=False)
        self.assertEqual(w.boot(), w.sys["C"])
        st = self.assertInvariants(w, "C")
        self.assertIsNone(st["rollback"]["recorded"])
        self.assertFalse(os.listdir(w.p("/nix/var/nix/profiles/system-profiles")))

    def test_arm_refuses_an_unbootable_target_before_any_profile(self):
        w = self.world()
        w.add_system("I", drop=("initrd",))
        w.fetch("A", "I", txid(1))
        self.assertEqual(w.work(txid(1))[1]["status"]["txn"]["reason"], "compat:xiii:initrd")
        w.run(w.tool("A"), "abort", "--txn", txid(1), "--release-staged")
        w.fetched("A", "B", txid(2))
        os.unlink(w.p(w.sys["B"] + "/initrd"))
        before = tree_hash(w.p("/nix/var/nix/profiles"))
        code, env = w.run(w.tool("A"), "arm", "--txn", txid(2))
        self.assertEqual((code, env["reason_class"], env["reason"]), (65, "compat", "compat:xiii:initrd"))
        self.assertFalse(env["mutated"])
        self.assertEqual(tree_hash(w.p("/nix/var/nix/profiles")), before)

    def test_arm_self_repairs_an_empty_submenu(self):
        w = self.world()
        w.fetched("A", "B", txid(1))
        w.switch("installer-skip", w.sys["B"])
        code, env = w.run(w.tool("A"), "arm", "--txn", txid(1))
        self.assertEqual((code, env["reason_class"]), (65, "grub-parse"), env)
        self.assertTrue(env["mutated"])
        st = env["status"]
        self.assertEqual((st["txn"]["state"], st["txn"]["reason_class"]), ("fetched", "grub-parse"))
        self.assertIsNone(st["candidate"])
        self.assertTrue(st["grubcfg"]["ok"])
        self.assertEqual(st["crash_state"], [])
        w.unswitch("installer-skip")
        self.assertEqual(w.run(w.tool("A"), "arm", "--txn", txid(1))[0], 0)

    def test_arm_self_repair_that_cannot_repair_stays_arming(self):
        # The cause is outside the candidate (the rollback toplevel renders an
        # empty submenu): the render without the candidate is still a menu
        # GRUB rejects, so the txn must not go back to `fetched`.
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        w.fetched("B", "C", txid(2))
        w.switch("installer-skip", w.sys["A"])
        code, env = w.run(w.tool("B"), "arm", "--txn", txid(2))
        self.assertEqual((code, env["reason_class"]), (65, "grub-parse"), env)
        self.assertIn("without the candidate", env["reason"])
        st = env["status"]
        self.assertEqual(st["txn"]["state"], "arming")
        self.assertIsNone(st["candidate"])
        self.assertIsNone(st["next_entry"])
        self.assertIn("grubcfg_invalid", st["crash_state"])
        self.assertIn("interrupted", st["crash_state"])
        w.unswitch("installer-skip")
        self.assertEqual(w.run(w.tool("B"), "abort", "--txn", txid(2))[0], 0)
        self.assertInvariants(w, "B")

    def test_arm_rereport_needs_a_pending_one_shot(self):
        w = self.world()
        w.armed("A", "B", txid(1))
        code, env = w.run(w.tool("A"), "arm", "--txn", txid(1))
        self.assertEqual((code, env["mutated"]), (0, False))
        # A boot consumed the one-shot (here GRUB refused it): the txn is still
        # armed, but nothing is armed in GRUB any more.
        self.assertEqual(w.boot("m"), w.sys["A"])
        code, env = w.run(w.tool("A"), "arm", "--txn", txid(1))
        self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "state", False), env)
        self.assertIn("one-shot was consumed", env["reason"])
        self.assertEqual(w.run(w.tool("A"), "abort", "--txn", txid(1))[0], 0)

    def test_arm_clears_a_stale_saved_boot_once(self):
        w = self.world()
        w.fetched("A", "B", txid(1))
        w.editenv("set", "boot_once=true")
        self.assertEqual(w.run(w.tool("A"), "arm", "--txn", txid(1))[0], 0)
        self.assertNotIn("boot_once", w.env())

    def test_commit_closing_write_failure_keeps_the_committed_root(self):
        # --no-rollback: step 3 removed the rollback profile and the booted
        # system is the target. If the closing write fails (ENOSPC), txn.json
        # still names B as committed, and only B's tool may repair, so the
        # `committed` root must still keep B in the store.
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        w.armed("B", "C", txid(2))
        self.assertEqual(w.boot("c"), w.sys["C"])
        real = T.atomic_write

        def failing(path, data, mode=0o600):
            if path.endswith("/txn.json") and b'"state": "committed"' in data:
                raise OSError(errno.ENOSPC, "No space left on device")
            return real(path, data, mode)

        T.atomic_write = failing
        try:
            code, env = w.run(w.tool("B"), "commit", "--txn", txid(2), "--no-rollback")
        finally:
            T.atomic_write = real
        self.assertEqual((code, env["reason_class"]), (70, "internal"), env)
        d = w.doc()
        self.assertEqual((d["txn"]["state"], d["committed"]["path"]), ("committing", w.sys["B"]))
        self.assertFalse(os.path.lexists(w.p(ROLLBACK)))
        self.assertEqual(os.readlink(w.p(GCROOTS + "/committed")), w.sys["B"])
        self.assertTrue(os.path.lexists(w.p(GCROOTS + "/staged")))
        # The step table's repair: commit again with B's tool.
        code, env = w.run(w.tool("B"), "commit", "--txn", txid(2), "--no-rollback")
        self.assertEqual(code, 0, env)
        self.assertEqual(os.readlink(w.p(GCROOTS + "/committed")), w.sys["C"])
        self.assertFalse(os.path.lexists(w.p(GCROOTS + "/staged")))
        w.boot()
        self.assertInvariants(w, "C")

    def test_commit_refuses_a_base_version_the_rollback_title_cannot_carry(self):
        # The base (bootstrap) system never passed rule xiii. Its
        # nixos-version first reaches a checked title when commit step 5
        # renders it as the rollback entry, after entry 0 moved to the target,
        # where abort refuses (the target booted mid-commit) and every redo
        # fails the same way. commit checks it before any step instead:
        # nothing changes, and --no-rollback still finishes.
        for version in ("26.11." + "x" * 140, ""):
            with self.subTest(length=len(version)):
                w = self.world()
                with open(w.p(w.sys["A"] + "/nixos-version"), "w") as f:
                    f.write(version)
                w.armed("A", "B", txid(1))
                self.assertEqual(w.boot("c"), w.sys["B"])
                seq = w.doc()["seq"]
                before = tree_hash(w.p("/nix/var/nix/profiles"))
                cfg = w.read("/boot/grub/grub.cfg")
                code, env = w.run(w.tool("A"), "commit", "--txn", txid(1), "--retain-until", RETAIN)
                self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "grub-parse", False), env)
                self.assertEqual(env["status"]["txn"]["state"], "armed")
                self.assertEqual(w.doc()["seq"], seq)
                self.assertEqual(tree_hash(w.p("/nix/var/nix/profiles")), before)
                self.assertEqual(w.read("/boot/grub/grub.cfg"), cfg)
                code, env = w.run(w.tool("A"), "commit", "--txn", txid(1), "--no-rollback")
                self.assertEqual(code, 0, env)
                self.assertEqual(w.boot(), w.sys["B"])
                self.assertInvariants(w, "B")

    def test_abort_from_every_open_state(self):
        def fetching(w):
            w.fetch("A", "B", txid(1))

        def fetch_failed(w):
            w.switch("realise-err", NIX_SIG)
            w.fetch("A", "B", txid(1))
            w.work(txid(1))

        def fetched(w):
            w.fetched("A", "B", txid(1))

        def arming(w):
            w.fetched("A", "B", txid(1))
            w.crash_after("A", "arm", 3, "--txn", txid(1))

        def armed(w):
            w.armed("A", "B", txid(1))

        def armed_trial(w):
            w.armed("A", "B", txid(1))
            w.boot(None)

        for setup in (fetching, fetch_failed, fetched, arming, armed, armed_trial):
            with self.subTest(state=setup.__name__):
                w = self.world()
                setup(w)
                code, env = w.run(w.tool("A"), "abort", "--txn", txid(1), "--release-staged")
                self.assertEqual(code, 0, env)
                self.assertEqual(env["status"]["txn"]["state"], "aborted")
                w.boot()
                self.assertInvariants(w, "A")
                self.assertFalse(os.path.lexists(w.p("/nix/var/nix/gcroots/cogworx-pve-upgrade/staged")))
                code, env = w.run(w.tool("A"), "abort", "--txn", txid(1))
                self.assertEqual((code, env["mutated"]), (0, False))

    def test_repair_kind_and_txn_rules(self):
        w = self.world()
        code, env = w.run(w.tool("A"), "abort", "--txn", txid(5))
        self.assertEqual(code, 0, env)
        self.assertEqual((env["status"]["txn"]["kind"], env["status"]["txn"]["state"]), ("repair", "repaired"))
        w.fetched("A", "B", txid(1))
        self.assertEqual(w.run(w.tool("A"), "abort", "--txn", txid(2))[1]["reason_class"], "txn-mismatch")
        self.assertEqual(w.run(w.tool("A"), "arm", "--txn", txid(2))[1]["reason_class"], "txn-mismatch")
        self.assertEqual(w.run(w.tool("A"), "commit", "--txn", txid(1), "--no-rollback")[1]["reason_class"], "state")
        self.assertEqual(w.run(w.tool("A"), "release", "--txn", txid(2))[1]["reason_class"], "state")
        w.run(w.tool("A"), "arm", "--txn", txid(1))
        code, env = w.run(w.tool("A"), "commit", "--txn", txid(1), "--no-rollback")
        self.assertEqual((code, env["reason_class"]), (65, "booted-mismatch"))
        w.boot("c")
        self.assertEqual(w.run(w.tool("A"), "fetch", "--txn", txid(3), "--target", w.sys["C"], "--closure",
                               w.digest("C"))[1]["reason_class"], "booted-mismatch")
        # abort runs booted on the committed system, the target or the
        # rollback, never on something else.
        os.makedirs(w.p(w.sys["C"]))
        w.set_booted(w.sys["C"])
        seq = w.doc()["seq"]
        code, env = w.run(w.tool("A"), "abort", "--txn", txid(1))
        self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "booted-mismatch", False), env)
        self.assertEqual(w.doc()["seq"], seq)

    def test_abort_of_committing_restores_pre(self):
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        w.armed("B", "C", txid(2))
        w.boot("c")
        w.crash_after("B", "commit", 3, "--txn", txid(2), "--no-rollback")
        self.assertFalse(os.path.lexists(w.p("/nix/var/nix/profiles/system-profiles/cogworx_rollback")))
        self.assertEqual(w.boot("m"), w.sys["B"])
        code, env = w.run(w.tool("B"), "abort", "--txn", txid(2))
        self.assertEqual(code, 0, env)
        w.boot()
        st = self.assertInvariants(w, "B")
        self.assertEqual(st["rollback"]["path"], w.sys["A"])
        self.assertEqual(st["grubcfg"]["rollback_entry"]["init"], w.sys["A"])

    def test_revert_and_release(self):
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        code, env = w.run(w.tool("B"), "release", "--txn", txid(2))
        self.assertEqual(code, 0, env)
        st = self.assertInvariants(w, "B")
        self.assertIsNone(st["rollback"]["recorded"])
        self.assertEqual(w.run(w.tool("B"), "release", "--txn", txid(3))[1]["reason_class"], "state")
        w.cycle("B", "C", txid(4))
        self.assertEqual(w.boot("r"), w.sys["B"])
        code, env = w.run(w.tool("B"), "revert-commit", "--txn", txid(5))
        self.assertEqual(code, 0, env)
        self.assertEqual(env["status"]["txn"]["state"], "reverted")
        self.assertEqual(w.doc()["history"][0]["reverted_from"], w.sys["C"])
        self.assertEqual(os.readlink(w.p("/nix/var/nix/gcroots/cogworx-pve-upgrade/committed")), w.sys["B"])
        self.assertEqual(w.boot(), w.sys["B"])
        st = self.assertInvariants(w, "B")
        self.assertIsNone(st["rollback"]["recorded"])
        self.assertIsNone(st["cwx_rollback_entry"])

    def test_revert_reasserts_the_committed_root_a_lost_commit_flip_left(self):
        # A cut inside commit step 9, after `staged` went and before the
        # `committed` root flipped: txn.json names B while the root still
        # names A. revert-commit step 7 deletes B's last generation link and
        # txn.json names B until step 8, so step 1 must re-assert the root
        # (as fetch, arm, abort and release do), or a GC in that window could
        # collect the system whose tool is the only repair.
        w = self.world()
        w.cycle("A", "B", txid(1))
        os.unlink(w.p(GCROOTS + "/committed"))
        os.symlink(w.sys["A"], w.p(GCROOTS + "/committed"))
        self.assertFalse(os.path.lexists(w.p(GCROOTS + "/staged")))
        self.assertEqual(w.boot("r"), w.sys["A"])
        for k in (1, 7):
            with self.subTest(k=k):
                v = w.clone()
                self.addCleanup(v.close)
                v.crash_after("A", "revert-commit", k, "--txn", txid(2))
                self.assertEqual(v.doc()["committed"]["path"], v.sys["B"])
                self.assertEqual(os.readlink(v.p(GCROOTS + "/committed")), v.sys["B"])
                if k == 7:
                    P = "/nix/var/nix/profiles"
                    links = [os.readlink(v.p(P + "/" + e)) for e in os.listdir(v.p(P))
                             if re.fullmatch(r"system-[0-9]+-link", e)]
                    self.assertNotIn(v.sys["B"], links)
                code, env = v.run(v.tool("A"), "revert-commit", "--txn", txid(2))
                self.assertEqual(code, 0, env)
                self.assertEqual(os.readlink(v.p(GCROOTS + "/committed")), v.sys["A"])
                self.assertInvariants(v, "A")

    def test_crash_state_tokens(self):
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        base = w.clone()
        self.addCleanup(base.close)
        P = "/nix/var/nix/profiles"

        def tok(mutate):
            v = base.clone()
            self.addCleanup(v.close)
            mutate(v)
            return v.status()["crash_state"]

        def relink(v, link, target):
            os.unlink(v.p(link))
            os.symlink(target, v.p(link))

        self.assertEqual(tok(lambda v: None), [])
        self.assertIn("head_mismatch", tok(lambda v: relink(v, P + "/system", "/nix/store/%s-nixos-system-x" % ("2" * 32))))
        self.assertIn("orphan_candidate", tok(lambda v: os.symlink(v.sys["C"], v.p(P + "/system-profiles/cogworx_candidate"))))
        self.assertIn("orphan_next_entry", tok(lambda v: v.editenv("set", "next_entry=x")))

        def armed_then_relinked(v):
            v.armed("B", "C", txid(6))
            relink(v, P + "/system-profiles/cogworx_candidate", v.sys["A"])

        self.assertIn("candidate_mismatch", tok(armed_then_relinked))
        self.assertIn("rollback_mismatch", tok(lambda v: relink(v, P + "/system-profiles/cogworx_rollback", "cogworx_rollback-9-link")))
        self.assertIn("untracked_profile", tok(lambda v: os.symlink(v.sys["A"], v.p(P + "/system-profiles/cogworx_other"))))
        self.assertIn("grubenv_invalid", tok(lambda v: v._write("/boot/grub/grubenv", "garbage")))
        self.assertIn("grubcfg_invalid", tok(lambda v: v._write("/boot/grub/grub.cfg", "submenu \"x\" {\n")))
        self.assertIn("entry0_mismatch", tok(lambda v: v._write("/boot/grub/grub.cfg", v.read("/boot/grub/grub.cfg").decode().replace(
            "init=" + v.sys["B"], "init=" + v.sys["C"], 1))))
        self.assertIn("booted_unknown", tok(lambda v: v.set_booted(v.sys["C"]) if os.makedirs(v.p(v.sys["C"])) is None else None))
        self.assertIn("current_differs", tok(lambda v: relink(v, "/run/current-system", v.sys["A"])))
        self.assertIn("bootloader_pin_mismatch", tok(lambda v: v._write("/boot/grub/state", "x\n")))
        self.assertIn("interrupted", tok(lambda v: v.crash_after("B", "release", 1, "--txn", txid(7))))
        self.assertEqual(tok(lambda v: v._write("/var/lib/cogworx-pve-upgrade/txn.json", "{")), ["txn_unreadable"])
        # a newer schema: refused, never overwritten
        v = base.clone()
        self.addCleanup(v.close)
        d = v.doc()
        d["schema"] = 2
        v._write("/var/lib/cogworx-pve-upgrade/txn.json", json.dumps(d))
        code, env = v.run(v.tool("B"), "release", "--txn", txid(8))
        self.assertEqual((code, env["reason_class"]), (65, "schema"))
        self.assertEqual(json.loads(v.read("/var/lib/cogworx-pve-upgrade/txn.json"))["schema"], 2)
        v._write("/var/lib/cogworx-pve-upgrade/txn.json", "[]")
        self.assertEqual(v.run(v.tool("B"), "release", "--txn", txid(8))[0], 70)
        # arm refuses on any token but current_differs
        v = base.clone()
        self.addCleanup(v.close)
        v.fetched("B", "C", txid(9))
        relink(v, "/run/current-system", v.sys["A"])
        os.symlink(v.sys["A"], v.p(P + "/system-profiles/cogworx_other"))
        code, env = v.run(v.tool("B"), "arm", "--txn", txid(9))
        self.assertEqual((code, env["reason_class"]), (65, "crash-state"))
        os.unlink(v.p(P + "/system-profiles/cogworx_other"))
        self.assertEqual(v.run(v.tool("B"), "arm", "--txn", txid(9))[0], 0)

    def test_lock_busy_and_status_while_held(self):
        import fcntl
        w = self.world()
        w.fetched("A", "B", txid(1))
        fd = os.open(w.p("/run/cogworx-pve-upgrade.lock"), os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        st = os.fstat(fd)
        line = "1: FLOCK  ADVISORY  WRITE %d %02x:%02x:%d 0 EOF\n" % (4242, os.major(st.st_dev), os.minor(st.st_dev), st.st_ino)
        w._write("/proc/locks", "2: -> FLOCK  ADVISORY  WRITE 99 00:00:1 0 EOF\n" + line)
        self.assertEqual(w.status()["lock"], {"held": True, "holder": "unknown", "pid": 4242})
        w._write("/proc/4242/comm", "flock\n")
        self.assertEqual(w.status()["lock"]["holder"], "gc")
        w._write("/run/cogworx-pve-upgrade.holder", json.dumps({"pid": 4242, "what": "fetch-worker", "txn": txid(1)}))
        w._write("/proc/4242/cgroup", FETCH_CGROUP)
        st = w.status()
        self.assertEqual(st["lock"]["holder"], "fetch-worker")
        self.assertEqual(st["worker"], {"active": True, "txn": txid(1)})
        self.assertNotIn("interrupted", st["crash_state"])
        os.unlink(w.p("/run/cogworx-pve-upgrade.holder"))
        code, env = w.run(w.tool("A"), "arm", "--txn", txid(1))
        self.assertEqual((code, env["reason_class"], env["mutated"]), (75, "busy", False))
        fcntl.flock(fd, fcntl.LOCK_UN)
        w._write("/proc/locks", "")
        self.assertEqual(w.run(w.tool("A"), "arm", "--txn", txid(1))[0], 0)

    def test_the_lock_excludes_a_second_tool_process(self):
        # The holder takes the lock through the tool's own Lock class (the
        # fetch worker, or a second cogworxd verb racing): a verb is busy.
        w = self.world()
        w.fetched("A", "B", txid(1))
        holder = (
            "import importlib.machinery, importlib.util, sys, time\n"
            "loader = importlib.machinery.SourceFileLoader('cwx', sys.argv[1])\n"
            "mod = importlib.util.module_from_spec(importlib.util.spec_from_loader('cwx', loader))\n"
            "loader.exec_module(mod)\n"
            "mod.ROOT = sys.argv[2]\n"
            "mod.Lock().acquire('verb:abort', None)\n"
            "print('held', flush=True)\n"
            "time.sleep(60)\n")
        p = subprocess.Popen([sys.executable, "-I", "-c", holder, TOOL_SRC, w.root], stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (p.kill(), p.wait(), p.stdout.close()))
        self.assertEqual(p.stdout.readline().strip(), "held")
        seq = w.doc()["seq"]
        code, env = w.run(w.tool("A"), "arm", "--txn", txid(1))
        self.assertEqual((code, env["reason_class"], env["mutated"]), (75, "busy", False), env)
        self.assertEqual(w.doc()["seq"], seq)

    def test_a_target_without_its_tool_is_never_armed(self):
        # Once committed, <target>/sw/bin/cogworx-pve-upgrade is the only tool
        # the argv[0] rule lets abort, release or move on: a composition that
        # dropped it (environment.systemPackages = mkForce [ ... ]) must be
        # refused at fetch end, and again by arm before any profile points at
        # it, or a --no-rollback commit would strand the guest there.
        w = self.world()
        w.add_system("D", drop=("sw/bin/cogworx-pve-upgrade",))
        self.assertEqual(w.fetch("A", "D", txid(1))[0], 0)
        t = w.work(txid(1))[1]["status"]["txn"]
        self.assertEqual((t["state"], t["reason_class"], t["reason"]),
                         ("fetch_failed", "compat", "compat:xiii:sw/bin/cogworx-pve-upgrade"))
        self.assertEqual(w.run(w.tool("A"), "abort", "--txn", txid(1), "--release-staged")[0], 0)
        w.fetched("A", "B", txid(2))
        os.unlink(w.p(w.tool("B")))
        before = tree_hash(w.p("/nix/var/nix/profiles"))
        code, env = w.run(w.tool("A"), "arm", "--txn", txid(2))
        self.assertEqual((code, env["reason_class"], env["reason"]),
                         (65, "compat", "compat:xiii:sw/bin/cogworx-pve-upgrade"), env)
        self.assertFalse(env["mutated"])
        self.assertEqual(tree_hash(w.p("/nix/var/nix/profiles")), before)
        self.assertFalse(w.env().get("next_entry"))
        self.assertEqual(env["status"]["txn"]["state"], "fetched")

    def test_abort_refuses_a_committing_txn_with_the_target_booted(self):
        # A commit cut after step 5: entry 0 is the target, and the target
        # boots. Only re-running commit finishes; an abort would move entry 0
        # back under the running target.
        w = self.world()
        w.armed("A", "B", txid(1))
        self.assertEqual(w.boot("c"), w.sys["B"])
        w.crash_after("A", "commit", 5, "--txn", txid(1), "--retain-until", RETAIN)
        self.assertEqual(w.boot(), w.sys["B"])
        seq = w.doc()["seq"]
        code, env = w.run(w.tool("A"), "abort", "--txn", txid(1))
        self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "booted-mismatch", False), env)
        self.assertEqual(w.doc()["seq"], seq)
        self.assertEqual(w.run(w.tool("A"), "commit", "--txn", txid(1), "--retain-until", RETAIN)[0], 0)
        self.assertInvariants(w, "B")

    def test_commit_abort_revert_and_release_refuse_a_drifted_pin_before_any_step(self):
        # /boot/grub/state no longer matches the pin: refused with nothing
        # changed (the installer would refuse too, but only after the verb's
        # first steps had moved profiles and the txn).
        def drift(w):
            w._write("/boot/grub/state", w.read("/boot/grub/state").decode().replace("/dev/vda", "/dev/vdb"))

        def commit(w):
            w.armed("A", "B", txid(1))
            self.assertEqual(w.boot("c"), w.sys["B"])
            return w.tool("A"), ("commit", "--txn", txid(1), "--retain-until", RETAIN)

        def abort(w):
            w.armed("A", "B", txid(1))
            return w.tool("A"), ("abort", "--txn", txid(1))

        def revert(w):
            w.cycle("A", "B", txid(1))
            self.assertEqual(w.boot("r"), w.sys["A"])
            return w.tool("A"), ("revert-commit", "--txn", txid(2))

        def release(w):
            w.cycle("A", "B", txid(1))
            w.boot()
            return w.tool("B"), ("release", "--txn", txid(2))

        for setup in (commit, abort, revert, release):
            with self.subTest(verb=setup.__name__):
                w = self.world()
                exe, args = setup(w)
                drift(w)
                seq = w.doc()["seq"]
                before = tree_hash(w.p("/nix/var/nix/profiles"))
                code, env = w.run(exe, *args)
                self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "bootloader", False), env)
                self.assertEqual(w.doc()["seq"], seq)
                self.assertEqual(tree_hash(w.p("/nix/var/nix/profiles")), before)

    def test_abort_after_commit_with_the_same_id_is_never_done(self):
        # A re-issued abort for a txn that COMMITTED is refused, never
        # answered "already done": only abort's own outcomes re-report.
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        code, env = w.run(w.tool("B"), "abort", "--txn", txid(1))
        self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "state", False), env)
        code, env = w.run(w.tool("A"), "abort", "--txn", txid(1))
        self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "not-committed-tool", False), env)

    def test_abort_repairs_an_invalid_grubenv_without_a_rollback(self):
        # A power cut inside grub-editenv (it rewrites the file in place) can
        # leave no valid block; with no rollback recorded, abort must still
        # create a fresh one.
        w = self.world()
        w.fetched("A", "B", txid(1))
        w._write("/boot/grub/grubenv", "")
        self.assertIn("grubenv_invalid", w.status()["crash_state"])
        code, env = w.run(w.tool("A"), "abort", "--txn", txid(1))
        self.assertEqual(code, 0, env)
        st = self.assertInvariants(w, "A")
        self.assertTrue(st["grubenv_ok"])

    def rollback_lost_by_a_gc(self, lose):
        """A commit cut after step 3 (the old rollback A lost its last root),
        then `lose(w)` (what a GC did to A), then the repairing abort."""
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        w.armed("B", "C", txid(2))
        self.assertEqual(w.boot("c"), w.sys["C"])
        w.crash_after("B", "commit", 3, "--txn", txid(2), "--retain-until", RETAIN)
        self.assertEqual(w.boot("m"), w.sys["B"])
        lose(w)
        return w

    def test_abort_drops_a_collected_rollback(self):
        w = self.rollback_lost_by_a_gc(lambda w: shutil.rmtree(w.p(w.sys["A"])))
        code, env = w.run(w.tool("B"), "abort", "--txn", txid(2))
        self.assertEqual(code, 0, env)
        self.assertEqual(w.doc()["history"][0].get("rollback_lost"), w.sys["A"])
        st = self.assertInvariants(w, "B")
        self.assertIsNone(st["rollback"]["recorded"])

    def test_abort_drops_a_rollback_a_cut_gc_invalidated(self):
        # nix invalidates a path before deleting it: a cut in between leaves
        # the directory, which presence alone would take for the rollback.
        w = self.rollback_lost_by_a_gc(lambda w: w.invalidate("A"))
        self.assertTrue(os.path.isdir(w.p(w.sys["A"])))
        code, env = w.run(w.tool("B"), "abort", "--txn", txid(2))
        self.assertEqual(code, 0, env)
        self.assertEqual(w.doc()["history"][0].get("rollback_lost"), w.sys["A"])
        st = self.assertInvariants(w, "B")
        self.assertIsNone(st["rollback"]["recorded"])

    def test_a_failing_validity_check_never_drops_the_rollback(self):
        w = self.rollback_lost_by_a_gc(lambda w: w.switch("check-validity-fail"))
        code, env = w.run(w.tool("B"), "abort", "--txn", txid(2))
        self.assertEqual((code, env["reason_class"]), (70, "internal"), env)
        self.assertEqual(w.doc()["txn"]["state"], "aborting")
        w.unswitch("check-validity-fail")
        code, env = w.run(w.tool("B"), "abort", "--txn", txid(2))
        self.assertEqual(code, 0, env)
        self.assertNotIn("rollback_lost", w.doc()["history"][0])
        st = self.assertInvariants(w, "B")
        self.assertEqual(st["rollback"]["recorded"], w.sys["A"])

    def test_abort_with_the_rollback_booted(self):
        # An S=r boot over an armed candidate lands on the rollback (the VM
        # suite's S9): abort with the committed tool must work from there.
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        w.armed("B", "C", txid(2))
        self.assertEqual(w.boot("r"), w.sys["A"])
        code, env = w.run(w.tool("B"), "abort", "--txn", txid(2))
        self.assertEqual((code, env["status"]["txn"]["state"]), (0, "aborted"), env)
        self.assertEqual(env["status"]["rollback"]["recorded"], w.sys["A"])
        self.assertEqual(w.boot(), w.sys["B"])
        self.assertInvariants(w, "B")

    def test_revert_needs_the_rollback_booted(self):
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        code, env = w.run(w.tool("A"), "revert-commit", "--txn", txid(2))
        self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "booted-mismatch", False), env)

    def test_closed_ids_are_never_reused(self):
        # Every verb refuses a new txn under the id of a closed one: cogworxd
        # mints a fresh id per switch, and a reused id would make its fence
        # (and every re-report) ambiguous.
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        seq = w.doc()["seq"]
        for args in (("fetch", "--txn", txid(1), "--target", w.sys["C"], "--closure", w.digest("C")),
                     ("abort", "--txn", txid(1)), ("release", "--txn", txid(1))):
            with self.subTest(verb=args[0]):
                code, env = w.run(w.tool("B"), *args)
                self.assertEqual((code, env["mutated"]), (65, False), env)
                self.assertEqual(w.doc()["seq"], seq)
        self.assertEqual(w.boot("r"), w.sys["A"])
        code, env = w.run(w.tool("A"), "revert-commit", "--txn", txid(1))
        self.assertEqual((code, env["mutated"]), (65, False), env)
        self.assertEqual(w.doc()["seq"], seq)

    def test_ids_in_history_are_never_reused(self):
        # Not only the newest txn: an id `history` still holds is refused too.
        # cogworxd adopts a crashed operation by re-issuing its leg under the
        # recorded id, and a stale `release` that opened a fresh txn would drop
        # the rollback (and with it S=r and revert-commit) of a newer commit.
        w = self.world()
        w.cycle("A", "B", txid(1))
        w.boot()
        self.assertEqual(w.run(w.tool("B"), "release", "--txn", txid(2))[0], 0)
        w.cycle("B", "C", txid(3))
        self.assertEqual(w.boot(), w.sys["C"])
        self.assertEqual([h["id"] for h in w.doc()["history"]], [txid(3), txid(2), txid(1)])
        seq = w.doc()["seq"]
        cases = [("fetch", "--txn", tid, "--target", w.sys["A"], "--closure", w.digest("A"))
                 for tid in (txid(1), txid(2))]
        cases += [("abort", "--txn", txid(1)), ("abort", "--txn", txid(2)), ("release", "--txn", txid(2)),
                  ("release", "--txn", txid(1))]
        for args in cases:
            with self.subTest(args=args[:3]):
                code, env = w.run(w.tool("C"), *args)
                self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "state", False), env)
                self.assertEqual(w.doc()["seq"], seq)
        self.assertEqual(w.doc()["rollback"]["path"], w.sys["B"])
        self.assertEqual(w.boot("r"), w.sys["B"])
        for tid in (txid(1), txid(2)):
            with self.subTest(verb="revert-commit", txn=tid):
                code, env = w.run(w.tool("B"), "revert-commit", "--txn", tid)
                self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "state", False), env)
                self.assertEqual(w.doc()["seq"], seq)
        # A fresh id still works, and is not refused for sharing history with
        # the ids above.
        self.assertEqual(w.run(w.tool("B"), "revert-commit", "--txn", txid(4))[0], 0)

    def test_arm_and_release_refuse_the_rollback_booted(self):
        # Both run on the committed system only: an S=r boot must refuse them
        # with nothing written.
        w = self.world()
        w.cycle("A", "B", txid(1))
        self.assertEqual(w.boot("r"), w.sys["A"])
        seq = w.doc()["seq"]
        code, env = w.run(w.tool("B"), "release", "--txn", txid(2))
        self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "booted-mismatch", False), env)
        self.assertEqual(w.doc()["seq"], seq)
        self.assertEqual(w.doc()["rollback"]["path"], w.sys["A"])
        self.assertEqual(w.boot(), w.sys["B"])
        w.fetched("B", "C", txid(3))
        self.assertEqual(w.boot("r"), w.sys["A"])
        seq = w.doc()["seq"]
        code, env = w.run(w.tool("B"), "arm", "--txn", txid(3))
        self.assertEqual((code, env["reason_class"], env["mutated"]), (65, "booted-mismatch", False), env)
        self.assertEqual(w.doc()["seq"], seq)
        self.assertEqual(w.doc()["txn"]["state"], "fetched")
        self.assertFalse(os.path.lexists(w.p("/nix/var/nix/profiles/system-profiles/cogworx_candidate")))

    def test_an_unknown_txn_state_or_kind_is_an_unreadable_file(self):
        # Within schema 1 a reader accepts only the txn states and kinds it
        # knows (a new value needs a schema bump): any other is an unreadable
        # file, never overwritten. This is what keeps revert-commit's OLDER
        # tool from acting on a state a newer tool invented.
        for key, value in (("state", "verifying"), ("kind", "rebase")):
            with self.subTest(key=key):
                w = self.world()
                w.cycle("A", "B", txid(1))
                w.boot()
                path = w.p("/var/lib/cogworx-pve-upgrade/txn.json")
                doc = w.doc()
                doc["txn"][key] = value
                with open(path, "w") as f:
                    json.dump(doc, f)
                with open(path, "rb") as f:
                    before = f.read()
                self.assertEqual(w.status()["crash_state"], ["txn_unreadable"])
                for args in (("release", "--txn", txid(2)), ("abort", "--txn", txid(2)),
                             ("abort", "--txn", txid(1))):
                    code, env = w.run(w.tool("B"), *args)
                    self.assertEqual((code, env["reason_class"]), (70, "internal"), env)
                    with open(path, "rb") as f:
                        self.assertEqual(f.read(), before)


class WrongMenuTest(Base):
    """After EVERY installer run the fresh parse must be the expected menu:
    entry 0, the cogworx submenus present and nothing else, each entry's
    init. The real install-grub.pl always renders the right one, so only a
    fake that renders a wrong one can show the checks are there."""

    def test_commit_abort_release_and_headroom_release_refuse_a_wrong_menu(self):
        base = World()
        self.addCleanup(base.close)
        base.configure()
        base.cycle("A", "B", txid(1))
        base.boot()
        A, B = base.sys["A"], base.sys["B"]

        def armed(w):
            w.armed("B", "C", txid(2))

        def trial(w):
            armed(w)
            assert w.boot("c") == w.sys["C"]

        def low(w):
            w.free = MIN_FREE + RESERVE
            w.gc_frees = 10 * GiB
            assert w.fetch("B", "C", txid(2), extra=("--release-rollback",))[0] == 0

        commit = ("B", "commit", "--txn", txid(2), "--retain-until", RETAIN)
        abort = ("B", "abort", "--txn", txid(2))
        release = ("B", "release", "--txn", txid(3))
        # (verb, setup, args, switch, value); commit renders C with rollback
        # B, abort and release render B (with rollback A, resp. none).
        cases = [
            ("commit", trial, commit, "installer-entry0-as", B),
            ("commit", trial, commit, "installer-profile-as", "cogworx_rollback " + A),
            ("commit", trial, commit, "installer-extra-profile", "cogworx_extra"),
            ("abort", armed, abort, "installer-entry0-as", A),
            ("abort", armed, abort, "installer-profile-as", "cogworx_rollback " + B),
            ("abort", armed, abort, "installer-extra-profile", "cogworx_extra"),
            ("release", lambda w: None, release, "installer-entry0-as", A),
            ("release", lambda w: None, release, "installer-extra-profile", "cogworx_extra"),
            ("headroom", low, None, "installer-entry0-as", A),
            ("headroom", low, None, "installer-extra-profile", "cogworx_extra"),
        ]
        for verb, setup, args, switch, value in cases:
            with self.subTest(verb=verb, switch=switch):
                w = base.clone()
                self.addCleanup(w.close)
                w.configure()
                setup(w)
                w.switch(switch, value)
                if verb == "headroom":
                    code, env = w.work(txid(2))
                    self.assertEqual(code, 0, env)
                    t = env["status"]["txn"]
                    self.assertEqual((t["state"], t["reason_class"]), ("fetch_failed", "internal"), t)
                    self.assertIn("grub.cfg", t["reason"])
                    self.assertFalse([r for r in w.log("nix-store") if r["argv"][0] == "--realise"
                                      and "--dry-run" not in r["argv"] and w.sys["C"] in r["argv"]])
                    self.assertEqual(w.doc()["rollback"]["path"], A)
                    w.unswitch(switch)
                    code, env = w.run(w.tool("B"), "abort", "--txn", txid(2))
                else:
                    code, env = w.run(w.tool(args[0]), *args[1:])
                    self.assertEqual((code, env["reason_class"]), (65, "grub-parse"), env)
                    self.assertTrue(env["mutated"])
                    # The same verb, re-run once the installer renders the right
                    # menu, completes.
                    w.unswitch(switch)
                    code, env = w.run(w.tool(args[0]), *args[1:])
                self.assertEqual(code, 0, env)
                w.boot()
                self.assertInvariants(w, "C" if verb == "commit" else "B")


# --- 11. power cuts --------------------------------------------------------------------------------


class PowerCutTest(Base):
    """A power cut after EVERY numbered step: the next boot is what the step
    tables say, and the repair verb restores every invariant."""

    _cache = {}

    def prepared(self, name, build):
        cache = PowerCutTest._cache
        if name not in cache:
            w = World()
            build(w)
            cache[name] = w
        w = cache[name].clone()
        self.addCleanup(w.close)
        w.configure()
        return w

    @classmethod
    def tearDownClass(cls):
        for w in cls._cache.values():
            w.close()
        cls._cache.clear()

    def test_fetch_launcher(self):
        for k in (1, 2):
            with self.subTest(k=k):
                w = self.prepared("fresh", lambda w: None)
                w.crash_after("A", "fetch", k, "--txn", txid(1), "--target", w.sys["B"], "--closure", w.digest("B"))
                self.assertEqual(w.boot(), w.sys["A"])
                st = w.status()
                self.assertEqual(st["txn"]["state"], "fetching")
                self.assertIn("interrupted", st["crash_state"])
                self.assertEqual(w.run(w.tool("A"), "abort", "--txn", txid(1))[0], 0)
                self.assertInvariants(w, "A")

    def test_arm(self):
        for k in range(1, 8):
            with self.subTest(k=k):
                w = self.prepared("fetched", lambda w: (w.configure(), w.fetched("A", "B", txid(1))))
                w.crash_after("A", "arm", k, "--txn", txid(1))
                self.assertEqual(w.boot("m"), w.sys["A"])
                st = w.status()
                self.assertEqual(st["txn"]["state"], "armed" if k == 7 else "arming")
                code, env = w.run(w.tool("A"), "abort", "--txn", txid(1))
                self.assertEqual(code, 0, env)
                self.assertInvariants(w, "A")

    def test_commit(self):
        def build(w):
            w.configure()
            w.cycle("A", "B", txid(1))
            w.boot()
            w.armed("B", "C", txid(2))
            assert w.boot("c") == w.sys["C"]
            w.pre_rb = w.status()["rollback"]["recorded"]

        for k in range(1, 10):
            with self.subTest(k=k):
                w = self.prepared("trial", build)
                w.crash_after("B", "commit", k, "--txn", txid(2), "--retain-until", RETAIN)
                if k < 8:
                    self.assertEqual(w.doc()["txn"]["pre"]["rollback"]["path"], w.sys["A"])
                # Until step 9 the `committed` root names B, whom txn.json
                # names until step 8.
                self.assertEqual(os.readlink(w.p(GCROOTS + "/committed")), w.sys["C" if k == 9 else "B"])
                booted = w.boot("m")
                self.assertEqual(booted, w.sys["B"] if k <= 4 else w.sys["C"], k)
                st = w.status()
                self.assertEqual(st["txn"]["state"], "committed" if k >= 8 else "committing")
                if k < 8:
                    self.assertIn("interrupted", st["crash_state"])
                if k == 2:
                    self.assertEqual((st["system_head"], st["entry0_init"]), (w.sys["C"], w.sys["B"]))
                if k <= 4:
                    code, env = w.run(w.tool("B"), "abort", "--txn", txid(2))
                    self.assertEqual(code, 0, env)
                    w.boot()
                    st = self.assertInvariants(w, "B")
                    self.assertEqual(st["rollback"]["recorded"], w.sys["A"])
                    self.assertEqual(st["grubcfg"]["rollback_entry"]["init"], w.sys["A"])
                else:
                    code, env = w.run(w.tool("B"), "commit", "--txn", txid(2), "--retain-until", RETAIN)
                    self.assertEqual(code, 0, env)
                    self.assertEqual(env["mutated"], k < 8)
                    w.boot()
                    st = self.assertInvariants(w, "C")
                    self.assertEqual(st["rollback"]["recorded"], w.sys["B"])
                    if k == 8:
                        # The lost flip only leaked a root: fetch, abort and
                        # release (and arm) re-assert it at their step 1.
                        self.assertEqual(os.readlink(w.p(GCROOTS + "/committed")), w.sys["B"])
                        for args in (("fetch", "--txn", txid(9), "--target", w.sys["B"], "--closure", w.digest("B")),
                                     ("abort", "--txn", txid(9)), ("release", "--txn", txid(9))):
                            v = w.clone()
                            self.addCleanup(v.close)
                            code, env = v.run(v.tool("C"), *args)
                            self.assertEqual(code, 0, env)
                            self.assertEqual(os.readlink(v.p(GCROOTS + "/committed")), v.sys["C"], args[0])

    def test_abort(self):
        def build(w):
            w.configure()
            w.cycle("A", "B", txid(1))
            w.boot()
            w.armed("B", "C", txid(2))

        for k in range(1, 11):
            with self.subTest(k=k):
                w = self.prepared("armed", build)
                w.crash_after("B", "abort", k, "--txn", txid(2))
                self.assertEqual(bool((w.env() or {}).get("next_entry")), k < 2, k)
                self.assertEqual(w.boot("m"), w.sys["B"])
                st = w.status()
                if k == 1:
                    self.assertTrue(st["cwx_once"].startswith("d:"))
                self.assertEqual(st["txn"]["state"], "aborted" if k == 10 else "aborting")
                code, env = w.run(w.tool("B"), "abort", "--txn", txid(2))
                self.assertEqual(code, 0, env)
                st = self.assertInvariants(w, "B")
                self.assertEqual(st["rollback"]["recorded"], w.sys["A"])

    def test_revert_commit(self):
        def build(w):
            w.configure()
            w.cycle("A", "B", txid(1))
            assert w.boot("r") == w.sys["A"]

        for k in range(1, 10):
            with self.subTest(k=k):
                w = self.prepared("on-rollback", build)
                w.crash_after("A", "revert-commit", k, "--txn", txid(3))
                self.assertEqual(os.readlink(w.p(GCROOTS + "/committed")), w.sys["A" if k == 9 else "B"])
                booted = w.boot()
                self.assertEqual(booted, w.sys["B"] if k < 5 else w.sys["A"], k)
                if k < 5:
                    code, env = w.run(w.tool("B"), "abort", "--txn", txid(3))
                    self.assertEqual(code, 0, env)
                    w.boot()
                    st = self.assertInvariants(w, "B")
                    self.assertEqual(st["rollback"]["recorded"], w.sys["A"])
                else:
                    code, env = w.run(w.tool("A"), "revert-commit", "--txn", txid(3))
                    self.assertEqual(code, 0, env)
                    st = self.assertInvariants(w, "A")
                    self.assertIsNone(st["rollback"]["recorded"])

    def test_release(self):
        def build(w):
            w.configure()
            w.cycle("A", "B", txid(1))
            w.boot()

        for k in range(1, 6):
            with self.subTest(k=k):
                w = self.prepared("committed", build)
                w.crash_after("B", "release", k, "--txn", txid(4))
                self.assertEqual(w.boot(), w.sys["B"])
                code, env = w.run(w.tool("B"), "release", "--txn", txid(4))
                self.assertEqual(code, 0, env)
                st = self.assertInvariants(w, "B")
                self.assertIsNone(st["rollback"]["recorded"])


# --- 12. the child environment ----------------------------------------------------------------------


class ChildEnvTest(Base):
    def test_installer_gets_exactly_path_lc_all_home(self):
        w = self.world()
        w.fetched("A", "B", txid(1))
        code, env = w.run(w.tool("A"), "arm", "--txn", txid(1),
                          env={"NIXOS_INSTALL_BOOTLOADER": "1", "NIXOS_INSTALL_GRUB": "1", "PATH": "/evil"})
        self.assertEqual(code, 0, env)
        runs = w.log("installer")
        self.assertTrue(runs)
        for r in runs:
            self.assertEqual(r["env"], {"PATH": w.bin, "LC_ALL": "C", "HOME": "/root"})
            self.assertEqual(r["argv"][:2], [w.pl, w.xml])
        for name in ("nix-env", "nix-store"):
            self.assertTrue(w.log(name))


# --- 13. the built package ------------------------------------------------------------------------


@unittest.skipUnless(TOOL_BIN or IN_CHECK, "COGWORX_PVE_UPGRADE_BIN not set")
class PackageTest(unittest.TestCase):
    def test_built_tool(self):
        with open(TOOL_BIN, "rb") as f:
            text = f.read().decode()
        self.assertRegex(text.split("\n", 1)[0], r"^#!/nix/store/[0-9a-z]{32}-python3-[^/ ]+/bin/python3 -I$")
        self.assertIsNone(re.search(r"@[A-Za-z]+@", text))
        mod = load_tool(TOOL_BIN, "cwx_built")
        self.assertTrue(all(os.path.isabs(p) and p.startswith("/nix/store/") for p in mod.CHILD_PATH.split(":")))
        self.assertEqual((int(mod.MIN_FREE_BYTES), int(mod.RESERVE_BYTES)), (12 * GiB, 4 * GiB))
        for name in ("nix-env", "nix-store", "systemd-run", "systemctl"):
            self.assertTrue(shutil.which(name, path=mod.CHILD_PATH), name)
        r = subprocess.run([TOOL_BIN, "proto"], capture_output=True, env={})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["proto"]["proto"], 1)
        r = subprocess.run([TOOL_BIN, "status"], capture_output=True, env={})
        lines = r.stdout.decode().split("\n")
        self.assertEqual((len(lines), lines[1]), (2, ""))
        doc = json.loads(lines[0])
        if not os.path.exists("/run/booted-system"):
            self.assertEqual((r.returncode, doc["exit"], doc["reason_class"]), (69, 69, "unavailable"))
        self.assertIn("status", doc)


if __name__ == "__main__":
    if GRUB_EDITENV is None:
        sys.exit("test_upgrade.py: no grub-editenv (set GRUB_EDITENV)")
    unittest.main(verbosity=1)
