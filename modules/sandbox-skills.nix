{ lib, ... }: {
  # Baked agent-facing guidance that belongs to no single service: where to
  # write so work survives a restart, how to obtain a missing tool, and how
  # the sandbox reaches git hosts, Vault-delivered credentials, the network and
  # remote clients. Kept out of app-relay.nix because none of these skills has
  # anything to do with the relay. Static paths, like the relay's, keep the
  # capability index evaluable without import-from-derivation.
  cogbox.skills.cogbox-filesystem = lib.mkDefault ../skills/cogbox-filesystem;
  cogbox.skills.cogbox-packages = lib.mkDefault ../skills/cogbox-packages;
  cogbox.skills.cogbox-git = lib.mkDefault ../skills/cogbox-git;
  cogbox.skills.cogbox-network = lib.mkDefault ../skills/cogbox-network;
  cogbox.skills.cogbox-remote-access = lib.mkDefault ../skills/cogbox-remote-access;
  cogbox.skills.cogbox-vault = lib.mkDefault ../skills/cogbox-vault;
}
