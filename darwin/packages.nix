{ self, nixpkgs, lib, runtimeDir, mkHarnesses, runner }:
let
  pkgs = nixpkgs.legacyPackages.aarch64-darwin;
  powerdown = pkgs.writeShellApplication {
    name = "cogbox-powerdown";
    runtimeInputs = [ pkgs.socat pkgs.coreutils ];
    text = builtins.readFile ./powerdown.sh;
  };
  tools = pkgs.stdenv.mkDerivation {
    pname = "cogbox-tools";
    version = "0.1.0";
    src = lib.cleanSource ../zig;
    nativeBuildInputs = [ pkgs.zig ];
    dontConfigure = true;
    dontInstall = true;
    buildPhase = ''
      export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-cache
      zig build --prefix $out -Doptimize=ReleaseSafe \
        --global-cache-dir $TMPDIR/zig-cache
    '';
  };
  slirp = pkgs.stdenv.mkDerivation {
    pname = "cogbox-slirp";
    version = "0.1.0";
    dontUnpack = true;
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ pkgs.libslirp pkgs.glib ];
    buildPhase = ''
      $CC -std=c11 -O2 -Wall -Wextra -Werror -Wno-deprecated-declarations \
        ${./slirp.c} $(pkg-config --cflags --libs slirp) -o cogbox-slirp
    '';
    installPhase = ''mkdir -p $out/bin; cp cogbox-slirp $out/bin/'';
  };
  # A host-only package makes CLI/network checks buildable without realizing
  # the Linux guest. The default package always carries the real guest runner.
  mkCogbox = selectedRunner: pkgs.runCommand "cogbox" {
    nativeBuildInputs = [ pkgs.makeWrapper ];
    meta = { mainProgram = "cogbox"; platforms = [ "aarch64-darwin" ]; };
  } ''
    mkdir -p $out/bin $out/lib $out/libexec
    cp ${tools}/bin/cogbox $out/bin/cogbox
    cp ${tools}/lib/libnetfilter.dylib $out/lib/
    cp ${../cogbox-launch.sh} $out/libexec/cogbox-launch.sh
    cp ${../cogbox-shutdown.sh} $out/libexec/cogbox-shutdown.sh
    cp ${../l7-mitm-addon.py} $out/libexec/l7-mitm-addon.py
    chmod +w $out/bin/cogbox $out/libexec/*.sh
    cat ${./shutdown.sh} >> $out/libexec/cogbox-shutdown.sh
    substituteInPlace $out/libexec/cogbox-launch.sh \
      --replace-fail '@runtimeDir@' '${runtimeDir}' \
      --replace-fail '@runner@' '${selectedRunner}' \
      --replace-fail '@shutdown@' "$out/libexec/cogbox-shutdown.sh" \
      --replace-fail '@netfilter@' "$out/lib/libnetfilter.dylib" \
      --replace-fail '@cogbox@' "$out/bin/cogbox" \
      --replace-fail '@harnesses@' '${lib.concatStringsSep " " (lib.attrNames (mkHarnesses "aarch64-linux" nixpkgs.legacyPackages.aarch64-linux))}' \
      --replace-fail '@mitmdump@' '${pkgs.mitmproxy}/bin/mitmdump' \
      --replace-fail '@l7addon@' "$out/libexec/l7-mitm-addon.py" \
      --replace-fail '@flock@' '${tools}/bin/cogbox-platform flock' \
      --replace-fail '@dumpe2fs@' '${pkgs.e2fsprogs}/bin/dumpe2fs' \
      --replace-fail '@flakeSource@' '${self}' \
      --replace-fail '@reexecPackage@' 'cogbox' \
      --replace-fail '@nixpkgsSource@' '${nixpkgs}'
    chmod +x $out/libexec/cogbox-launch.sh
    wrapProgram $out/bin/cogbox \
      --set COGBOX_LAUNCH_SCRIPT $out/libexec/cogbox-launch.sh \
      --set COGBOX_HOST_SYSTEM aarch64-darwin \
      --set COGBOX_PLATFORM ${tools}/bin/cogbox-platform \
      --set COGBOX_SHUTDOWN_HELPER ${powerdown}/bin/cogbox-powerdown \
      --set COGBOX_NET_BACKEND ${slirp}/bin/cogbox-slirp \
      --set-default COGBOX_DEFAULT_VCPU 4 \
      --set-default COGBOX_DEFAULT_MEM 8192 \
      --set-default COGBOX_FLAKE_SOURCE '${self}' \
      --set-default COGBOX_NIXPKGS_SOURCE '${nixpkgs}' \
      --set-default COGBOX_REEXEC_PACKAGE cogbox \
      --prefix PATH : '${lib.makeBinPath (with pkgs; [
        coreutils gnused gnugrep jq diffutils nix bashInteractive openssh
      ])}'
    ln -s cogbox $out/bin/cbx
  '';
in {
  cogbox = mkCogbox runner;
  default = self.packages.aarch64-darwin.cogbox;
  cogbox-tools = tools;
  cogbox-slirp = slirp;
  cogbox-host-tools = mkCogbox "/var/empty/cogbox-host-tools-has-no-guest";
}
