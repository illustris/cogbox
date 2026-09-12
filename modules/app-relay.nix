{ config, lib, pkgs, ... }:
let
  relay = import ../app-relay/package.nix { inherit pkgs; command = "relay"; };
  stateUnit = if config.boot.isContainer then "cogbox-container-state.service" else "var-lib-cogbox.mount";
  state = if config.boot.isContainer then "/var/lib/cogbox-state" else "/var/lib/cogbox";
in {
  # Explicit entries replace the old plugin's discovered guidance. Static
  # paths keep the capability index evaluable without import-from-derivation.
  cogbox.skills.app-relay = lib.mkDefault ../skills/app-relay;
  cogbox.skills.cogbox-environment = lib.mkDefault ../skills/cogbox-environment;
  users.users.app-relay = {
    isSystemUser = lib.mkDefault true;
    group = lib.mkDefault "app-relay";
    description = lib.mkDefault "cogbox app relay";
  };
  users.groups.app-relay = {};
  networking.firewall.allowedTCPPorts = [ 8080 ];
  # Defaults allow an already-pinned legacy plugin to supply the same v1
  # service until it is removed. Never run a second relay on the same port.
  systemd.services.cogbox-app-relay = {
    description = lib.mkDefault "cogbox app relay";
    wantedBy = lib.mkDefault [ "multi-user.target" ];
    after = lib.mkDefault [ stateUnit ];
    wants = lib.mkDefault [ stateUnit ];
    unitConfig.StartLimitIntervalSec = lib.mkDefault 0;
    serviceConfig = {
      EnvironmentFile = lib.mkDefault [ "-/var/lib/cogbox/app-relay.env" "-/var/lib/cogbox-state/app-relay.env" ];
      ExecStart = lib.mkDefault "${relay}/bin/cogbox-app-relay --listen 0.0.0.0:8080";
      User = lib.mkDefault "app-relay";
      Group = lib.mkDefault "app-relay";
      Restart = lib.mkDefault "always";
      RestartSec = lib.mkDefault 2;
      NoNewPrivileges = lib.mkDefault true;
    };
  };
  # Descriptive only: guest root can change the state mirror. Host-side app
  # provisioning reads the separate host configuration record instead.
  systemd.services.cogbox-environment = {
    description = "Expose sandbox environment guidance";
    wantedBy = [ "multi-user.target" ];
    after = [ stateUnit ];
    wants = [ stateUnit ];
    before = [ "sshd.service" ];
    serviceConfig.Type = "oneshot";
    serviceConfig.PassEnvironment = lib.optionals config.boot.isContainer [ "COGBOX_ENVIRONMENT" "COGBOX_INSTANCE" ];
    path = [ pkgs.coreutils pkgs.jq ];
    script = lib.optionalString config.boot.isContainer ''
      # Containers have no host launcher. Stamp only an explicit managed
      # declaration; no declaration leaves existing context intact/unknown.
      if [ "''${COGBOX_ENVIRONMENT:-}" = cogworx ]; then
        instance="''${COGBOX_INSTANCE:-default}"
        case "$instance" in
          ""|*[!a-zA-Z0-9-]*) echo "invalid environment instance" >&2; exit 1 ;;
        esac
        dir=${state}/config/cogbox/instances/$instance
        install -d -m 0700 "$dir"
        tmp=$(mktemp "$dir/environment.XXXXXX")
        jq -n --arg instance "$instance" '{version:1,mode:"cogworx",instance:$instance}' > "$tmp"
        chmod 0600 "$tmp"
        mv -f "$tmp" "$dir/environment.json"
        tmp=$(mktemp ${state}/environment.XXXXXX)
        jq -n --arg instance "$instance" '{version:1,mode:"cogworx",instance:$instance}' > "$tmp"
        chmod 0644 "$tmp"
        mv -f "$tmp" ${state}/environment.json
      fi
    '' + ''
      install -d -m 0755 /run/cogbox
      record=${state}/environment.json
      tmp=$(mktemp /run/cogbox/environment.XXXXXX)
      if [ -f "$record" ] && jq -e '(.version == 1) and (.mode == "local" or .mode == "cogworx" or .mode == "unknown") and (.instance | type == "string")' "$record" >/dev/null 2>&1; then
        jq '{version, mode, instance, workspace:"/root/work", appAccess:(if .mode == "local" then "local-cli" elif .mode == "cogworx" then "cogworx" else "unknown" end)}' "$record" > "$tmp"
      else
        printf '%s\n' '{"version":1,"mode":"unknown","instance":"","workspace":"/root/work","appAccess":"unknown"}' > "$tmp"
      fi
      chmod 0644 "$tmp"
      mv -f "$tmp" /run/cogbox/environment.json
    '';
  };
}
