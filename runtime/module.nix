{ config, lib, pkgs, options, ... }:
let
  cfg = config.cogbox.runtimeEnvironment;
  work = "/var/lib/cogbox/work";
  # The literal path, never /root/work: that symlink exists only once
  # brain-materialize has run, and both resolve to the same directory.
  state = "${work}/.cogbox/runtime";
  # Hosted guests bind the work tree from the data pool with `nofail`, which
  # strips Before=local-fs.target from the mount, so a unit writing through it
  # must order on the mount itself. Keyed on the fileSystems entry rather than
  # on the flake-internal storage profile, so this module also evaluates on its
  # own (the runtime-boot-restore VM test imports it alone).
  pooledWork = config.fileSystems ? ${work};
  workMount = "var-lib-cogbox-work.mount";
in {
  options.cogbox.runtimeEnvironment = {
    enable = lib.mkEnableOption "guest-owned tool generations (cogbox-env), restored offline at boot";
    package = lib.mkOption {
      type = lib.types.package;
      readOnly = true;
      internal = true;
      visible = false;
      default = pkgs.callPackage ./package.nix { nix = config.nix.package; };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { nix = config.nix.package; }";
      description = "The cogbox-env helper, built against the guest's own Nix.";
    };
  };
  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      environment.systemPackages = [ cfg.package ];
      # Restore the SELECTED generation offline after a restart reset the store
      # database or the writable store itself. A background unit in the house
      # pattern (After= the target it is wanted by): it never gates login,
      # sshd, brain-materialize or readiness, and a failure is visible in
      # `systemctl --failed`, the journal and `cogbox-env status`
      # (status.boot_restore) instead of in the boot. Deliberately no Before=,
      # Requires=, RequiresMountsFor= or Restart=; checks.runtime-environment
      # asserts the realized unit.
      systemd.services.cogbox-runtime-restore = {
        description = "Restore the selected cogbox runtime tool generation";
        wantedBy = [ "multi-user.target" ];
        # Ordering only. After=multi-user.target already implies
        # brain-materialize (Before=multi-user.target); naming it keeps the
        # dependency explicit if that ever changes.
        after = [ "multi-user.target" "cogbox-brain-materialize.service" ]
          ++ lib.optional pooledWork workMount;
        # The softMounts class rule: Wants=+After= on the pool-backed mount,
        # never a hard dependency, so a pool-absent boot degrades instead of
        # failing the unit. After= holds the start until the mount job has
        # finished either way; the mount-point condition then skips the unit
        # cleanly (inactive, not failed) over an unmounted pool, so it never
        # reads or writes the shadowed directory underneath.
        # cogbox-guest-pool-degradable pins this pair and rejects any
        # RequiresMountsFor= on a pool path.
        wants = lib.optional pooledWork workMount;
        unitConfig = {
          ConditionPathIsSymbolicLink = "${state}/current";
          # Per-box kill switch: touch this file to skip every boot restore.
          ConditionPathExists = "!${state}/disable-boot-restore";
        } // lib.optionalAttrs pooledWork {
          ConditionPathIsMountPoint = work;
        };
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${cfg.package}/bin/cogbox-env restore --boot --state-dir ${state} --timeout 900";
          TimeoutStartSec = 960;
          TimeoutStopSec = 30;
          Nice = 10;
          IOSchedulingClass = "best-effort";
          IOSchedulingPriority = 7;
          # A pathological import is killed before user processes are.
          OOMScoreAdjust = 500;
        };
      };
    }
    # The baked skill rides on the cogbox.* brain contract, which only the
    # cogbox guest module tree declares. Guarded so the module still evaluates
    # where that tree is absent (the VM test, standalone imports).
    (lib.optionalAttrs (options ? cogbox.skills) {
      cogbox.skills.cogbox-runtime = lib.mkDefault ../skills/cogbox-runtime;
    })
  ]);
}
