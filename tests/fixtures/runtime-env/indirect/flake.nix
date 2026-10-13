{
  description = "A bundle locked the way the cogbox-runtime skill teaches";
  # Indirect, as in the skill's recipe. Nix resolves an indirect input through
  # the global and --flake-registry registries only, so this locks offline
  # only with `--flake-registry FILE`, FILE mapping nixpkgs to a store path:
  # the image's nixpkgs on a guest; in the tests a stand-in that exposes what
  # this flake builds with (bash, coreutils, system), like the materialized
  # fixture's tools flake.
  inputs.nixpkgs.url = "nixpkgs";
  outputs = { self, nixpkgs }: {
    # __structuredAttrs, the pkgs.buildEnv shape: no `system` environment
    # binding, so prepare must read the system from `nix derivation show`.
    packages.${nixpkgs.system}.default = builtins.derivation {
      name = "runtime-bundle-indirect";
      inherit (nixpkgs) system;
      __structuredAttrs = true;
      builder = "${nixpkgs.bash}/bin/bash";
      args = [ "-euc" ''
        . "$NIX_ATTRS_SH_FILE"
        out="''${outputs[out]}"
        ${nixpkgs.coreutils}/bin/mkdir -p "$out/bin"
        printf '#!${nixpkgs.bash}/bin/bash\necho indirect\n' > "$out/bin/runtime-indirect"
        ${nixpkgs.coreutils}/bin/chmod +x "$out/bin/runtime-indirect"
      '' ];
    };
  };
}
