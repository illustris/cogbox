{ lib, ... }: {
  # Baked agent-facing guidance that belongs to no single service: where to
  # write so work survives a restart, and how to obtain a missing tool. Kept
  # out of app-relay.nix because neither skill has anything to do with the
  # relay. Static paths, like the relay's, keep the capability index evaluable
  # without import-from-derivation.
  cogbox.skills.cogbox-filesystem = lib.mkDefault ../skills/cogbox-filesystem;
  cogbox.skills.cogbox-packages = lib.mkDefault ../skills/cogbox-packages;
}
