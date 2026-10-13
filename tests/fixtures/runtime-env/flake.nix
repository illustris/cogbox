{
  description = "Locked small tool bundles for the runtime environment POC";
  inputs.tools.url = "path:./tools";
  outputs = { self, tools }: let
    system = tools.system;
    mk = name: script: builtins.derivation {
      inherit name system;
      builder = "${tools.bash}/bin/bash";
      args = [ "-euc" script ];
    };
    probe = version: mk "runtime-probe-${version}" ''
      ${tools.coreutils}/bin/mkdir -p "$out/bin"
      printf '#!${tools.bash}/bin/bash\necho ${version}\n' > "$out/bin/runtime-probe"
      ${tools.coreutils}/bin/chmod +x "$out/bin/runtime-probe"
    '';
    aOnly = mk "runtime-a-only" ''
      ${tools.coreutils}/bin/mkdir -p "$out/bin"
      printf '#!${tools.bash}/bin/bash\necho a-only\n' > "$out/bin/runtime-a-only"
      ${tools.coreutils}/bin/chmod +x "$out/bin/runtime-a-only"
    '';
    # A bundle may not provide the helper itself (prepare refuses it).
    shadow = mk "cogbox-env-shadow" ''
      ${tools.coreutils}/bin/mkdir -p "$out/bin"
      printf '#!${tools.bash}/bin/bash\necho shadow\n' > "$out/bin/cogbox-env"
      ${tools.coreutils}/bin/chmod +x "$out/bin/cogbox-env"
    '';
    # Minimal bin-only merge to keep the offline stage fixture's build inputs
    # tiny. Real projects can use pkgs.buildEnv with ignoreCollisions = false.
    bundle = name: paths: mk name (''
      ${tools.coreutils}/bin/mkdir -p "$out/bin"
    '' + builtins.concatStringsSep "\n" (map (path: ''
      for executable in ${path}/bin/*; do
        name="''${executable##*/}"
        if [ -e "$out/bin/$name" ]; then
          echo "conflicting executable: $name" >&2
          exit 1
        fi
        ${tools.coreutils}/bin/ln -s "$executable" "$out/bin/$name"
      done
    '') paths));
  in {
    packages.${system} = {
      a = bundle "runtime-bundle-a" [ (probe "v1") aOnly ];
      b = bundle "runtime-bundle-b" [ (probe "v2") ];
      collision = bundle "runtime-bundle-collision" [ (probe "v1") (probe "v2") ];
      reserved = bundle "runtime-bundle-reserved" [ (probe "v1") shadow ];
    };
  };
}
