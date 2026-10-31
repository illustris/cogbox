{
	description = "cogbox live-apply test plugin";
	outputs = { self }: {
		cogboxPlugins.default = {
			module = import ./module.nix;
			networkRules = [
				{ allow = "10.99.0.8/32"; comment = "la-x allow"; }
				{ deny = "10.99.0.9/32"; comment = "la-x deny"; }
			];
		};
	};
}
