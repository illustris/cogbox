{
	description = "cogbox live-apply test plugin";
	outputs = { self }: {
		cogboxPlugins.default = {
			module = import ./module.nix;
			networkRules = [
				{ deny = "10.99.0.2/32"; comment = "la-deny deny"; }
			];
		};
	};
}
