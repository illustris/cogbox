"""Crash-at-step driver for the pve-upgrade-vm powercut suite (test only).

    crashat.py <tool file> <argv0> <verb> <k> [args...]

Loads the upgrade tool from <tool file> (the store file its path resolves to)
as a module and sets its STEP_HOOK: right after step <k> of <verb>, which the
tool has already synced, the hook records /run/cwx-crash-point (tmpfs, so
nothing reaches the disk) and parks WITHOUT syncing. Then it runs
main([argv0, verb] + args), argv0 being the unresolved tool path the argv[0]
rule checks. The VM test pulls the plug at the crash point (QEMU quits): what
reached the virtual disk survives and the guest's page cache does not, which
is a power cut from the guest's point of view.

The park ends only when the test creates /run/cwx-crash-release: the hook
removes it and returns, and the verb carries on. The VM test uses that to
hold a real `_fetch` worker (run in the worker's own transient unit) inside
the lock while nix-gc tries to collect.

The shipped tool has no crash hook of its own; STEP_HOOK is import-only.
"""

import importlib.machinery
import importlib.util
import os
import signal
import sys
import time

CRASH_POINT = "/run/cwx-crash-point"
RELEASE = "/run/cwx-crash-release"


def main():
    path, argv0, verb, k = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    rest = sys.argv[5:]
    loader = importlib.machinery.SourceFileLoader("cogworx_pve_upgrade", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)

    def hook(v, n, name):
        sys.stderr.write("crashat: %s step %d (%s) done\n" % (v, n, name))
        sys.stderr.flush()
        if v == verb and n == k:
            fd = os.open(CRASH_POINT, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            os.write(fd, ("%s %d %s\n" % (v, n, name)).encode("ascii"))
            os.close(fd)
            while not os.path.exists(RELEASE):
                time.sleep(0.2)
            os.unlink(RELEASE)
            sys.stderr.write("crashat: released after %s step %d\n" % (v, n))
            sys.stderr.flush()

    mod.STEP_HOOK = hook
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    return mod.main([argv0, verb] + rest)


if __name__ == "__main__":
    sys.exit(main())
