{ lib, stdenvNoCC, python3Minimal, nix, makeWrapper }:
# python3Minimal, not python3: the helper needs only the standard library
# python3Minimal ships, and its closure is about 76 MiB against python3's
# 212 MiB (3.14.7, measured with nix path-info -S).
# `nix` is the guest's own config.nix.package when the module builds this, so
# the helper drives the same Nix the guest's store and daemon run.
stdenvNoCC.mkDerivation {
  pname = "cogbox-env";
  version = "0.2.0";
  src = ./cogbox-env.py;
  dontUnpack = true;
  nativeBuildInputs = [ makeWrapper ];
  installPhase = ''
    mkdir -p $out/libexec $out/bin
    cp $src $out/libexec/cogbox-env.py
    makeWrapper ${python3Minimal}/bin/python3 $out/bin/cogbox-env \
      --add-flags $out/libexec/cogbox-env.py \
      --prefix PATH : ${lib.makeBinPath [ nix ]}
  '';
  meta = {
    description = "Guest-owned immutable tool generations";
    platforms = lib.platforms.linux;
    mainProgram = "cogbox-env";
  };
}
