# Build the PVE host system from this checkout's flake inputs, the way
# flake.nix's mkGceHost builds the GCE one: same specialArgs (`self` for the
# cogbox-hosted package and the hosted guest configuration, `inputs` for the
# input source trees the launcher's offline re-exec needs, `system`).
#
# flake.nix does not export a mkPveHost yet -- it is held unchanged while a
# concurrent batch edits it -- so this file is the seam until it does. Impure
# because builtins.getFlake on a local checkout is.
#
#   # evaluate the toplevel (fast; builds nothing):
#   nix eval --impure --raw --expr '(import ./pve/eval.nix { }).config.system.build.toplevel.drvPath'
#
#   # build the template disk:
#   nix build --impure --expr '(import ./pve/eval.nix { }).config.system.build.pveImage'
#
#   # compose a site module (resolver, control CA, floor CIDRs) on top:
#   nix eval --impure --raw --expr '(import ./pve/eval.nix { extraModules = [ ./site.nix ]; }).config.system.build.toplevel.drvPath'
#
# A bake that pins a flake reference passes it as `flake` instead:
#   import "${cogbox}/pve/eval.nix" { flake = builtins.getFlake "git+file:///path/to/cogbox?rev=..."; }
{
	flake ? builtins.getFlake (toString ../.),
	system ? "x86_64-linux",
	extraModules ? [ ],
}:
flake.inputs.nixpkgs.lib.nixosSystem {
	inherit system;
	specialArgs = {
		self = flake;
		inputs = flake.inputs // { self = flake; };
		inherit system;
	};
	modules = [ ./pve-host.nix ] ++ extraModules;
}
