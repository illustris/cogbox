{ config, lib, pkgs, ... }:
let
  # The guest helper that lists the git hosts this sandbox reaches through git
  # grants (the git-hosts.json the `cogbox l7` verbs publish; docs/authproxy.md
  # "Host discovery"). The file sits at a different guest path per target, so the
  # helper is target-dependent: it goes on the system PATH, never into
  # cogbox.packages, which would put it in the brain, and the brain must stay
  # the same for the VM and the container (checks.native-app-module).
  gitHosts = pkgs.writeShellApplication {
    name = "cogbox-git-hosts";
    runtimeInputs = [ pkgs.coreutils pkgs.curl pkgs.jq ];
    text = ''
      summary_layout=${if config.boot.isContainer then "container" else "vm"}
    '' + builtins.readFile ../cogbox-git-hosts.sh;
  };
in {
  # Baked agent-facing guidance that belongs to no single service: where to
  # write so work survives a restart, how to obtain a missing tool, and how
  # the sandbox reaches git hosts, Vault-delivered credentials, the network and
  # remote clients. Kept out of app-relay.nix because none of these skills has
  # anything to do with the relay. Static paths, like the relay's, keep the
  # capability index evaluable without import-from-derivation.
  #
  # Also the one baked always-on rule, cogbox-git (three lines pointing at
  # the cogbox-git-hosts helper, for harnesses that read only AGENTS.md), and
  # that helper on the PATH.
  cogbox.skills.cogbox-filesystem = lib.mkDefault ../skills/cogbox-filesystem;
  cogbox.skills.cogbox-packages = lib.mkDefault ../skills/cogbox-packages;
  cogbox.skills.cogbox-git = lib.mkDefault ../skills/cogbox-git;
  cogbox.skills.cogbox-network = lib.mkDefault ../skills/cogbox-network;
  cogbox.skills.cogbox-remote-access = lib.mkDefault ../skills/cogbox-remote-access;
  cogbox.skills.cogbox-vault = lib.mkDefault ../skills/cogbox-vault;
  cogbox.rules.cogbox-git = lib.mkDefault ../rules/cogbox-git.md;
  environment.systemPackages = [ gitHosts ];
}
