{
	description = "cogbox live-apply test plugin";
	outputs = { self }: {
		cogboxPlugins.default = {
			module = import ./module.nix;
			networkRules = [
				{ allow = "10.99.0.1/32"; comment = "la-kit common allow"; }
				{ allow = "10.99.0.5/32"; comment = "la-kit v3 only allow"; }
			];
		};
	};
}
