{
	description = "cogbox live-apply test plugin";
	outputs = { self }: {
		cogboxPlugins.default = {
			module = import ./module.nix;
			networkRules = [ ];
		};
	};
}
