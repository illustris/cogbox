{ self, nixpkgs, lib }:
let
  pkgs = nixpkgs.legacyPackages.aarch64-darwin;
in {
  zig-tests = pkgs.stdenv.mkDerivation {
    name = "cogbox-zig-tests";
    src = lib.cleanSource ../zig;
    nativeBuildInputs = [ pkgs.zig ];
    dontConfigure = true;
    dontInstall = true;
    buildPhase = ''
      export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-cache
      zig build test --global-cache-dir $TMPDIR/zig-cache
      touch $out
    '';
  };
  native-tools = self.packages.aarch64-darwin.cogbox-host-tools;
  native-runtime = pkgs.runCommand "cogbox-darwin-runtime-tests" {
    nativeBuildInputs = [ pkgs.python3 pkgs.stdenv.cc ];
    __darwinAllowLocalNetworking = true;
  } ''
    $CC -Wall -Wextra -Werror ${../tests/darwin-net-probe.c} -o probe
    export COGBOX_NET_PROBE=$PWD/probe
    export COGBOX_NETFILTER=${self.packages.aarch64-darwin.cogbox-tools}/lib/libnetfilter.dylib
    export COGBOX_PLATFORM=${self.packages.aarch64-darwin.cogbox-tools}/bin/cogbox-platform
    export COGBOX_SLIRP=${self.packages.aarch64-darwin.cogbox-slirp}/bin/cogbox-slirp
    export COGBOX=${self.packages.aarch64-darwin.cogbox-host-tools}/bin/cogbox
    python3 ${../tests/test_darwin.py} -v
    touch $out
  '';
}
