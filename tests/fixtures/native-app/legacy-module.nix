# The legacy plugin's plain-priority service fields, retained as a migration
# fixture. A differently packaged executable must win over the native defaults.
{ config, pkgs, ... }:
let
  oldRelay = pkgs.writeShellScriptBin "app-relay" "exit 0";
  stateUnit = if config.boot.isContainer then "cogbox-container-state.service" else "var-lib-cogbox.mount";
in {
  cogbox.contents = ./legacy-contents;
  users.users.app-relay = { isSystemUser = true; group = "app-relay"; description = "cogbox app relay"; };
  users.groups.app-relay = {};
  networking.firewall.allowedTCPPorts = [ 8080 ];
  systemd.services.cogbox-app-relay = {
    description = "legacy app relay";
    wantedBy = [ "multi-user.target" ];
    after = [ stateUnit ];
    wants = [ stateUnit ];
    unitConfig.StartLimitIntervalSec = 0;
    serviceConfig = {
      EnvironmentFile = [ "-/var/lib/cogbox/app-relay.env" "-/var/lib/cogbox-state/app-relay.env" ];
      ExecStart = "${oldRelay}/bin/app-relay --listen 0.0.0.0:8080";
      User = "app-relay";
      Group = "app-relay";
      Restart = "always";
      RestartSec = 2;
      NoNewPrivileges = true;
    };
  };
}
