# The sandbox-side mosh UDP port range: the ports mosh-server may bind INSIDE
# a sandbox (VM guest or container pod). ONE source of truth for this repo;
# the cogworx control plane mirrors it in internal/agent/mosh.go (the
# COGWORX_MOSH_SANDBOX_UDP_PORTS default) and injects `-p port:port+count-1`
# into every mosh-server exec it relays, so the two must agree or every
# session lands outside the admitted range.
#
# Read by: flake.nix (guest firewall allowedUDPPortRanges), gce/cogbox-host.nix
# (moshUDPPort/moshUDPPortRange defaults -> passt -u forward). NOT read by
# cogbox-nft-divert.sh: the nft-init image carries no nix at runtime, so that
# script spells the range as a literal with a comment naming this file, and
# tests/nft_floor_bypass_driver.py grep-pins the literal.
#
# last port = port + count - 1 (60031 today).
{ port = 60000; count = 32; }
