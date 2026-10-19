# Compatibility shim: the PVE host system is flake.lib.mkPveHost now. Kept so
# a bake that imports "${cogbox}/pve/eval.nix" with this signature keeps
# working (impure: builtins.getFlake on a local checkout is).
{
	flake ? builtins.getFlake (toString ../.),
	system ? "x86_64-linux",
	extraModules ? [ ],
}:
flake.lib.mkPveHost system { inherit extraModules; }
