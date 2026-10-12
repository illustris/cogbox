{ config, lib, pkgs, ... }:
{
  options.cogbox.runtimeEnvironment.enable = lib.mkEnableOption "experimental guest-owned tool generations";
  config = lib.mkIf config.cogbox.runtimeEnvironment.enable {
    environment.systemPackages = [ (pkgs.callPackage ./package.nix {}) ];
  };
}
