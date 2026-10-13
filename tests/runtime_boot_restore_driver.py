# Driver for tests/runtime-boot-restore.nix. Steps follow the hosted guest's
# lifecycle: a guest-only reboot, a store-loss boot, a slow restore that boot
# must not wait for, a damaged archive, the kill switch, and last (because it
# discards the work disk) a pool-absent boot. Step 1b runs the skill's offline
# lock and stale-lock update recipes and a flake prepare on the guest's own Nix.
import json

STATE = "/var/lib/cogbox/work/.cogbox/runtime"
UNIT = "cogbox-runtime-restore.service"
STORE_DISK = "empty0.qcow2"
WORK_DISK = "empty1.qcow2"


def envelope(command, ok=True):
    """Run one cogbox-env command and return its JSON envelope."""
    code, out = machine.execute(f"cogbox-env {command} 2>/dev/null")
    result = json.loads(out)
    assert result["ok"] == ok, (command, result)
    assert (code == 0) == ok, (command, code, result)
    return result


def status():
    return envelope("status")["status"]


def unit():
    out = machine.succeed(f"systemctl show -p ActiveState,Result,ConditionResult,ExecMainStatus {UNIT}")
    return dict(line.split("=", 1) for line in out.strip().splitlines())


def prop(name, target=UNIT):
    return machine.succeed(f"systemctl show -p {name} --value {target}").strip()


def boot():
    machine.start()
    machine.wait_for_unit("multi-user.target")
    # The restore is part of the boot transaction; this returns once every
    # boot job, the background restore included, has finished.
    machine.execute("systemctl is-system-running --wait")


def reboot(delete=None):
    machine.shutdown()
    if delete:
        (machine.state_dir / delete).unlink()
    boot()


def boot_id():
    return machine.succeed("cat /proc/sys/kernel/random/boot_id").strip()


def pre_restore():
    return machine.succeed("cat /run/runtime-test-pre").split()


def make_bundle():
    # Same bytes every time, so the store path is the same after a reboot
    # emptied /tmp.
    machine.succeed(
        "rm -rf /tmp/bundle && mkdir -p /tmp/bundle/bin",
        "printf '#!/bin/sh\\necho hi-from-bundle\\n' > /tmp/bundle/bin/hi",
        "chmod 0555 /tmp/bundle/bin/hi",
    )
    return machine.succeed("nix-store --add /tmp/bundle").strip()


def tool_works():
    assert machine.succeed("cogbox-env exec -- hi").strip() == "hi-from-bundle"


def rooted(bundle, generation):
    # The boot's fresh database forgot the GC root that roots/<gen> still
    # names; the restore must register it again, or the next garbage
    # collection deletes the selected bundle.
    machine.succeed(f"nix-store --query --roots {bundle} | grep -qxF '{STATE}/roots/{generation} -> {bundle}'")
    machine.fail(f"nix-store --delete {bundle}")


def journal_summary_only(generation, outcome, error=None):
    # The unit discards the JSON envelope on stdout; the summary on stderr
    # stays, followed on failure by the message no persisted record carries.
    log = machine.succeed(f"journalctl -b -u {UNIT} -o cat")
    assert f"cogbox-runtime-restore: outcome={outcome} " in log and f"generation={generation} " in log, log
    assert '"version"' not in log and '"status"' not in log, log
    errors = [line for line in log.splitlines() if line.startswith("cogbox-runtime-restore: error: ")]
    assert errors == ([f"cogbox-runtime-restore: error: {error}"] if error else []), log


def restored_this_boot(generation, outcome):
    s = status()
    record = s["boot_restore"]
    assert record is not None, s
    assert record["outcome"] == outcome, record
    assert record["generation"] == generation, record
    assert record["boot_id"] == boot_id(), record
    return s


with subtest("first boot: blank work disk degrades, then becomes the work tree"):
    boot()
    machine.fail("mountpoint -q /var/lib/cogbox/work")
    u = unit()
    assert u["ConditionResult"] == "no" and u["ActiveState"] == "inactive", u
    machine.succeed(
        "mkfs.ext4 -q -L rt-work /dev/disk/by-id/virtio-rt-work",
        "systemctl start var-lib-cogbox-work.mount",
        "mountpoint -q /var/lib/cogbox/work",
        "systemctl restart cogbox-brain-materialize",
        "test -d /root/work/.cogbox",
    )
    caps = envelope("capabilities")["capabilities"]
    assert caps["protocol_versions"] == [2], caps
    s = status()
    assert s["selection"] is None and s["generations"] == [], s
    # Neither read created any state.
    machine.succeed(f"test ! -e {STATE}")

with subtest("1: prepare, apply and run a bundle"):
    bundle = make_bundle()
    machine.succeed(f"echo {bundle} > /var/lib/cogbox/work/.test-probe")
    generation = envelope(f"prepare --import-store-path {bundle}")["generation"]
    applied = envelope(f"apply --generation {generation} --expected-selection none")
    assert applied["status"]["active_generation"] == generation, applied
    tool_works()

with subtest("1b: the skill's lock and stale-lock recipes and a structured-attrs flake bundle, offline"):
    # The recipe the baked skill teaches, on the guest's own Nix: the indirect
    # `nixpkgs` input locks through /etc/nix/registry.json to exactly the path
    # that file maps, `original` stays indirect, and prepare (which reads no
    # registry) accepts the lock and reads the system of a derivation whose
    # environment has no `system` binding.
    machine.succeed(
        "mkdir -p /root/work/tools",
        "cp /etc/runtime-test/indirect/flake.nix /root/work/tools/flake.nix",
        'nix flake lock --flake-registry /etc/nix/registry.json "path:$(realpath ~/work/tools)"',
    )
    registry = json.loads(machine.succeed("cat /etc/nix/registry.json"))
    mapped = [f["to"] for f in registry["flakes"] if f["from"] == {"id": "nixpkgs", "type": "indirect"}]
    assert len(mapped) == 1 and mapped[0]["type"] == "path", registry
    node = json.loads(machine.succeed("cat /var/lib/cogbox/work/tools/flake.lock"))["nodes"]["nixpkgs"]
    assert node["locked"]["type"] == "path" and node["locked"]["path"] == mapped[0]["path"], node
    assert node["original"] == {"id": "nixpkgs", "type": "indirect"}, node
    flaked = envelope('prepare --flake "path:$(realpath ~/work/tools)" --attribute packages.x86_64-linux.default')
    listed = next(g for g in flaked["status"]["generations"] if g["id"] == flaked["generation"])
    assert listed["system"] == "x86_64-linux" and listed["provenance"]["kind"] == "flake", listed
    machine.fail(f"nix-store --query --binding system {listed['derivation']}")
    assert flaked["status"]["selected_generation"] == generation, flaked
    envelope(f"prune --generation {flaked['generation']}")
    # The skill's stale-lock recipe: a flake.lock written against another
    # nixpkgs (another sandbox's image, or this one before an upgrade) survives
    # `nix flake lock`, and `nix flake update nixpkgs --flake-registry` moves it
    # back, offline, to exactly the entry the first lock wrote.
    machine.succeed(
        "mkdir /tmp/other-nixpkgs /tmp/elsewhere",
        f"cat {mapped[0]['path']}/flake.nix > /tmp/other-nixpkgs/flake.nix",
        "echo '# another image' >> /tmp/other-nixpkgs/flake.nix",
    )
    other = json.loads(machine.succeed("nix flake archive --json path:/tmp/other-nixpkgs"))["path"]
    assert other != mapped[0]["path"], other
    other_registry = {"flakes": [{"exact": True, "from": {"id": "nixpkgs", "type": "indirect"},
                                  "to": {"path": other, "type": "path"}}], "version": 2}
    machine.succeed(
        f"echo '{json.dumps(other_registry)}' > /tmp/other-registry.json",
        "cp /etc/runtime-test/indirect/flake.nix /tmp/elsewhere/flake.nix",
        "nix flake lock --flake-registry /tmp/other-registry.json path:/tmp/elsewhere",
        "cp /tmp/elsewhere/flake.lock /root/work/tools/flake.lock",
        'nix flake lock --flake-registry /etc/nix/registry.json "path:$(realpath ~/work/tools)"',
    )
    stale = json.loads(machine.succeed("cat /var/lib/cogbox/work/tools/flake.lock"))["nodes"]["nixpkgs"]
    assert stale["locked"]["path"] == other, stale
    machine.succeed('nix flake update nixpkgs --flake-registry /etc/nix/registry.json --flake "path:$(realpath ~/work/tools)"')
    updated = json.loads(machine.succeed("cat /var/lib/cogbox/work/tools/flake.lock"))["nodes"]["nixpkgs"]
    assert updated == node, (updated, node)
    again = envelope('prepare --flake "path:$(realpath ~/work/tools)" --attribute packages.x86_64-linux.default')
    envelope(f"prune --generation {again['generation']}")
    machine.succeed("rm -r /root/work/tools /tmp/other-nixpkgs /tmp/elsewhere /tmp/other-registry.json")

with subtest("2: guest-only reboot restores present-but-invalid paths"):
    reboot()
    assert pre_restore() == ["present", "invalid"], pre_restore()
    u = unit()
    assert u["ActiveState"] == "active" and u["Result"] == "success", u
    s = restored_this_boot(generation, "restored")
    assert s["active_generation"] == generation, s
    journal_summary_only(generation, "restored")
    machine.succeed(f"nix-store --check-validity {bundle}")
    rooted(bundle, generation)
    tool_works()

with subtest("3: store-loss boot restores missing paths"):
    reboot(delete=STORE_DISK)
    assert pre_restore() == ["missing", "invalid"], pre_restore()
    u = unit()
    assert u["ActiveState"] == "active" and u["Result"] == "success", u
    s = restored_this_boot(generation, "restored")
    assert s["active_generation"] == generation, s
    machine.succeed(f"nix-store --check-validity {bundle}")
    rooted(bundle, generation)
    tool_works()

with subtest("4: the boot never waits for the restore"):
    machine.succeed("touch /var/lib/cogbox/work/.test-slow-restore")
    machine.shutdown()
    machine.start()
    machine.wait_for_unit("multi-user.target")
    # The wait the skill documents: the restore's boot job stays listed until
    # it has finished, while login already works.
    machine.succeed(f"systemctl list-jobs --no-legend {UNIT} | grep -qF {UNIT}")
    machine.wait_until_succeeds(f"systemctl list-jobs {UNIT} | grep -qF 'No jobs'", timeout=120)
    machine.execute("systemctl is-system-running --wait")
    reached = int(prop("ActiveEnterTimestampMonotonic", "multi-user.target"))
    started = int(prop("InactiveExitTimestampMonotonic"))
    finished = int(prop("ExecMainExitTimestampMonotonic"))
    assert 0 < reached < started < finished, (reached, started, finished)
    # The probe sleeps 20 s before the restore itself starts.
    assert finished - reached >= 20_000_000, (reached, finished)
    restored_this_boot(generation, "restored")
    machine.succeed("rm /var/lib/cogbox/work/.test-slow-restore")

with subtest("5: a damaged archive fails the unit, not the boot"):
    machine.succeed(f"truncate -s 4096 {STATE}/generations/{generation}/closure.nar")
    reboot(delete=STORE_DISK)
    u = unit()
    assert u["ActiveState"] == "failed" and u["ExecMainStatus"] == "1", u
    machine.succeed("systemctl is-active multi-user.target")
    s = restored_this_boot(generation, "failed")
    assert s["boot_restore"]["code"] == "invalid_archive", s
    assert s["selected_generation"] == generation and s["active_generation"] is None, s
    machine.succeed(
        f"journalctl -b -u {UNIT} | grep -F 'cogbox-runtime-restore: outcome=failed code=invalid_archive generation={generation}'"
    )
    journal_summary_only(generation, "failed",
                         "invalid_archive: missing or corrupt retained closure archive; run prepare again to repair it")
    failed_boot = boot_id()
    # Recovery as documented: prepare again (it repairs the archive from the
    # re-delivered closure), then restore.
    assert make_bundle() == bundle
    repaired = envelope(f"prepare --import-store-path {bundle}")
    assert repaired["generation"] == generation and repaired["changed"], repaired
    envelope("restore")
    assert status()["active_generation"] == generation
    tool_works()

with subtest("6: the kill switch skips the boot restore"):
    machine.succeed(f"touch {STATE}/disable-boot-restore")
    reboot()
    u = unit()
    assert u["ConditionResult"] == "no" and u["ActiveState"] == "inactive" and u["Result"] == "success", u
    machine.succeed(f"journalctl -b -u {UNIT} | grep -F 'ConditionPathExists=!{STATE}/disable-boot-restore'")
    machine.succeed("test ! -e /run/runtime-test-pre")
    s = status()
    # The record is still the last boot that ran a restore.
    assert s["boot_restore"]["boot_id"] == failed_boot, s
    assert s["active_generation"] is None, s
    machine.succeed(f"rm {STATE}/disable-boot-restore")
    # A manual restore still works with the kill switch gone.
    assert envelope("restore")["changed"]
    assert status()["active_generation"] == generation
    tool_works()

with subtest("7: pool-absent boot skips the restore and writes nothing"):
    reboot(delete=WORK_DISK)
    machine.succeed("systemctl is-active multi-user.target")
    machine.fail("mountpoint -q /var/lib/cogbox/work")
    u = unit()
    assert u["ConditionResult"] == "no" and u["ActiveState"] == "inactive" and u["Result"] == "success", u
    # The stub brain-materialize wrote .cogbox onto the uncovered directory,
    # as the real one does on a pool-absent boot; runtime state never appears.
    machine.succeed("test -d /var/lib/cogbox/work/.cogbox", f"test ! -e {STATE}")
    # Prove the mount-point condition is the guard: plant a selection on the
    # uncovered directory, start the unit again, and it still neither runs nor
    # writes.
    machine.succeed(
        f"mkdir -p {STATE}/selections/0123456789abcdef0123456789abcdef",
        f"ln -s selections/0123456789abcdef0123456789abcdef {STATE}/current",
        f"systemctl start {UNIT}",
    )
    u = unit()
    assert u["ConditionResult"] == "no" and u["ActiveState"] == "inactive", u
    machine.succeed(f"journalctl -b -u {UNIT} | grep -F 'ConditionPathIsMountPoint=/var/lib/cogbox/work'")
    machine.succeed(f"test ! -e {STATE}/lock", f"test ! -e {STATE}/boot-restore.json", "test ! -e /run/runtime-test-pre")
