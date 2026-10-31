{
	description = "cogbox live-apply test plugin";
	outputs = { self }: {
		cogboxPlugins.default = {
			module = import ./module.nix;
			networkRules = [
				{ allow = "10.99.0.6/32"; comment = "la-hang allow"; }
				{ deny = "10.99.0.7/32"; comment = "la-hang deny"; }
			];
		};
	};
}
