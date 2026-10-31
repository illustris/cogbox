{
	description = "cogbox live-apply test plugin";
	outputs = { self }: {
		cogboxPlugins.default = {
			module = import ./module.nix;
			networkRules = [
				{ allow = "10.99.0.1/32"; comment = "la-kit common allow"; }
			];
		};
	};
}
