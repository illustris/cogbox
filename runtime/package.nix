{ lib, stdenvNoCC, python3, nix, makeWrapper }:
stdenvNoCC.mkDerivation {
  pname = "cogbox-env";
  version = "0.1.0";
  src = ./cogbox-env.py;
  dontUnpack = true;
  nativeBuildInputs = [ makeWrapper ];
  installPhase = ''
    mkdir -p $out/libexec $out/bin
    cp $src $out/libexec/cogbox-env.py
    makeWrapper ${python3}/bin/python3 $out/bin/cogbox-env \
      --add-flags $out/libexec/cogbox-env.py \
      --prefix PATH : ${lib.makeBinPath [ nix ]}
  '';
  meta = {
    description = "Experimental guest-owned immutable tool generations";
    platforms = lib.platforms.linux;
    mainProgram = "cogbox-env";
  };
}
