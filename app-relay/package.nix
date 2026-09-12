{ pkgs, command }:
pkgs.buildGoModule {
  pname = "cogbox-app-${command}";
  version = "1.0.0";
  src = ./.;
  vendorHash = null;
  subPackages = [ "cmd/${command}" ];
  postInstall = ''
    mv $out/bin/${command} $out/bin/${if command == "relay" then "cogbox-app-relay" else "cogbox-app"}
  '';
}
