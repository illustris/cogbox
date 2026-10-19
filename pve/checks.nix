# The PVE host image's checks. The flake carries every one of them as
# checks.x86_64-linux.pve-<name>, the heavy ones included (`all` is left out
# there), and this file still works standalone over eval.nix:
#
#   nix build -L .#checks.x86_64-linux.pve-unit-graph    # one check, flake
#   nix build --impure -f pve/checks.nix all              # everything cheap
#   nix build --impure -f pve/checks.nix unit-graph       # one check
#   nix build --impure -f pve/checks.nix offline-closure  # not in `all`: it
#                                                         # builds the system
#   nix build --impure -f pve/checks.nix upgrade-vm       # not in `all`: KVM
#   nix build --impure -f pve/checks.nix upgrade-vm-powercut  # NixOS VM tests
#
# Every check reads the REALIZED system: unit files as NixOS renders them, the
# scripts the units run, the ruleset the floor loads. Unit texts are read at
# eval time with their store context discarded, so the unit-graph and
# config-values checks build nothing heavy; the behavioural checks build only
# the small scripts they run (never the cogbox package or the guest).
#
# The fixture system is a PUBLISHABLE-shaped bake (a control CA, a resolver,
# the floor CIDRs) made entirely of fictional values (RFC 5737/2544 ranges and
# a key generated for these checks), so the publish gates are exercised on the
# image shape that ships. The CA-less default is evaluated too.
{
	flake ? builtins.getFlake (toString ../.),
	system ? "x86_64-linux",
}:
let
	pkgs = flake.inputs.nixpkgs.legacyPackages.${system};
	inherit (pkgs) lib;

	evalPve = extraModules: import ./eval.nix { inherit flake system extraModules; };

	# A real ed25519 PUBLIC key generated for these checks, whose private half
	# was deleted: the upgrade compat doc's builder decodes every control CA
	# key and fingerprints it, so a placeholder blob would fail the build.
	fixtureCAKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJMmGv60w43igyko8BEEnvP2PPu01MPlwi9Zamq2j/LC control-ca";
	fixtureCAFingerprint = "SHA256:4fR1sXmorUlWspPK0W8CKAc2aQmmRM9X/JSYyLPQ9GY";
	fixtureSite = {
		cogworx.gce.controlCAPublicKey = fixtureCAKey;
		cogworx.gce.vpcResolver = "192.0.2.1";
		# The same values tests/test_floor_site.sh's golden ruleset is rendered
		# from, so the realized ruleset can be compared to it byte for byte.
		cogworx.pve.floor = {
			controlPlaneCIDRs = [ "198.18.7.0/24" ];
			infraDenyCIDRs = [ "198.18.0.0/15" "203.0.113.0/24" ];
			infraAllow = [ { address = "203.0.113.80"; protocol = "tcp"; port = 443; } ];
		};
	};
	sys = evalPve [ fixtureSite ];
	cfg = sys.config;
	plain = evalPve [ ];
	# flake.nix exports the CA-less default ("CA-less, fail-closed") as
	# nixosConfigurations.cogbox-x86_64-pve. publish-gates pins it to `plain`,
	# so a module added to that entry alone cannot drift from what is tested.
	exported = flake.nixosConfigurations.cogbox-x86_64-pve;

	discard = builtins.unsafeDiscardStringContext;
	svc = cfg.systemd.services;
	pve = cfg.cogworx.pve;
	gce = cfg.cogworx.gce;

	# --- which units talk to the metadata emulator ---------------------------
	#
	# Every cogworx-* service is classified, at eval time, as a metadata client
	# (route coverage scans its scripts; the unit graph asserts its socket
	# edges and root-ness) or as one that does not use the emulator over HTTP.
	# A new cogworx-* unit -- from a later change to gce/, say -- fails here
	# until someone decides which it is.
	nonClients = [
		"cogworx-state-disk"
		"cogworx-guest-disk"
		"cogworx-nix-gc"
		"cogworx-pve-md-addr"
		"cogworx-pve-metadata"
		"cogworx-pve-hostname"     # reads DMI via --print-attr, before the network
		"cogworx-pve-kvm"
		"cogworx-pve-serial-cap"
	];
	cogworxServices = lib.filter (n: lib.hasPrefix "cogworx-" n) (lib.attrNames svc);
	unclassified = lib.subtractLists (pve.metadataClients ++ nonClients) cogworxServices;
	staleClassification = lib.subtractLists cogworxServices (pve.metadataClients ++ nonClients);
	socketClients = lib.remove "cogworx-supervisor" pve.metadataClients;
	# README.md's "Units and ordering" names these, so they are spelled here
	# rather than read back from the config under test: a client dropped from
	# metadata.nix's list would otherwise vanish from the assertions together
	# with its edges.
	specSocketClients = [
		"cogworx-control-principal"
		"cogworx-attr-scrub"
		"cogworx-floor"
		"cogworx-resolver-deadline"
		"cogworx-cogbox-log"
		"cogworx-pve-self-refresh"
		"cogworx-pve-floor"
	];

	# The programs a client unit runs, first token of each Exec line. ExecStop
	# is left out on purpose: the supervisor's carries the cogbox package as an
	# argument, and it never talks to the metadata server.
	execPaths = n: lib.concatMap (k:
		map (s: builtins.head (lib.splitString " " s)) (lib.toList (svc.${n}.serviceConfig.${k} or [ ])))
		[ "ExecStart" "ExecStartPost" "ExecStopPost" ];
	clientScripts = lib.concatMap execPaths pve.metadataClients;

	# metadata.nix gives every socket client its edges with genAttrs, which
	# DEFINES the unit. So a gce/ client that is later removed does not
	# vanish: it survives as an edge-only stub, which the classification
	# above still sees, whose edges the unit graph still finds, and in which
	# route coverage scans nothing. Every client must still run something.
	stubClients = lib.filter
		(n: lib.all (s: s == "") (lib.toList (svc.${n}.serviceConfig.ExecStart or [ ])))
		(lib.unique (specSocketClients ++ pve.metadataClients));

	# --- the format units' mke2fs profile (mkfs-nodiscard.nix) -----------------
	#
	# Spelled here, like specSocketClients, rather than read back from the
	# module under test.
	formatUnits = [ "cogworx-state-disk" "cogworx-guest-disk" ];
	mke2fsProfile = discard "${cfg.system.build.pveMke2fsConfig}";
	mke2fsValue = n: discard (toString (svc.${n}.environment.MKE2FS_CONFIG or ""));
	mke2fsCarriers = lib.filter (n: (svc.${n}.environment or { }) ? MKE2FS_CONFIG) (lib.attrNames svc);
	# The SYSTEM's e2fsprogs, not this file's nixpkgs: the profile is derived
	# from it and the units run it, so an overlay cannot split the two.
	sysE2fsprogs = sys.pkgs.e2fsprogs;
	# Every non-comment line under gce/ that runs mkfs or mke2fs, as its file
	# name. A format leg added there runs with mke2fs's whole-device discard
	# until its unit joins mkfs-nodiscard.nix's list (and formatUnits).
	gceSrc = "${flake}/gce";
	gceFormatLines = lib.concatMap (f:
		map (_: lib.removePrefix "${gceSrc}/" f)
			(lib.filter (l: builtins.match "[[:space:]]*#.*" l == null && builtins.match ".*(mkfs|mke2fs).*" l != null)
				(lib.splitString "\n" (builtins.readFile f))))
		(lib.filter (f: lib.hasSuffix ".nix" f || lib.hasSuffix ".sh" f) (map toString (lib.filesystem.listFilesRecursive gceSrc)));
	# The negative control for mkfs-nodiscard.nix's assertion: a format unit
	# reduced to an environment-only stub.
	formatStub = failedAssertions (evalPve [ fixtureSite { systemd.services.cogworx-state-disk.serviceConfig.ExecStart = lib.mkForce ""; } ]);

	# Every rendered unit, context discarded: grepping them builds nothing.
	unitsJson = pkgs.writeText "pve-units.json"
		(builtins.toJSON (lib.mapAttrs (_: u: discard (toString (u.text or ""))) cfg.systemd.units));

	# --- eval-time facts --------------------------------------------------------
	# The test scripts as one directory, because test_floor_site.sh runs its
	# sibling netprobe.py. Bytecode caches from local runs are left out.
	tests = builtins.path {
		name = "pve-tests";
		path = ./tests;
		filter = path: type: baseNameOf path != "__pycache__";
	};

	# The in-guest upgrade tool, built with the production headroom floor and
	# reserve (the module pins those to gce/nix-gc.nix's floor).
	gib = 1024 * 1024 * 1024;
	upgradeTool = pkgs.callPackage ./upgrade/package.nix {
		minFreeBytes = 12 * gib;
		reserveBytes = 4 * gib;
	};

	# --- the upgrade module (upgrade/module.nix), spelled from its parts ------
	#
	# gce/nix-gc.nix's floor, which the tool's headroom floor must equal.
	gceMinFreeGB = lib.toInt (builtins.head (builtins.match ".*minFreeGB = ([0-9]+);.*" (builtins.readFile "${gceSrc}/nix-gc.nix")));
	# The gc unit's realized ExecStart: the gce program, wrapped in the upgrade
	# lock. The gce program is taken from gce/nix-gc.nix itself (its function
	# never reads `config`), not from the module under test.
	gceGcProgram = discard (import "${gceSrc}/nix-gc.nix" { config = cfg; inherit lib; pkgs = sys.pkgs; }).config.systemd.services.cogworx-nix-gc.serviceConfig.ExecStart;
	gcExecStart = "ExecStart=${discard "${sys.pkgs.util-linux}"}/bin/flock --nonblock --conflict-exit-code 75 /run/cogworx-pve-upgrade.lock ${gceGcProgram}";
	upgradePackagePath = discard "${pve.upgrade.package}";
	# The compat doc's substituter lists, from the evaluated nix.settings and
	# normalized as compat_doc.py does (an http(s) URL loses its trailing
	# slashes; sorted, unique): a module that stopped writing them, or wrote
	# something else, fails compat-doc.
	httpUrl = u: builtins.match "https?://[^/]+(/.*)?" u != null;
	stripSlashes = u: let s = lib.removeSuffix "/" u; in if s != u && httpUrl s then stripSlashes s else u;
	sortedUnique = l: lib.unique (lib.sort lib.lessThan l);
	nixSettings = cfg.nix.settings;
	expectedSubstituters = sortedUnique (map (u: if httpUrl u then stripSlashes u else u)
		(nixSettings.substituters ++ (nixSettings.extra-substituters or [ ])));
	expectedTrustedKeys = sortedUnique (nixSettings.trusted-public-keys ++ (nixSettings.extra-trusted-public-keys or [ ]));

	failedAssertions = s: map (a: a.message) (lib.filter (a: !a.assertion) s.config.assertions);
	evaluates = s: (builtins.tryEval s.config.system.build.toplevel.drvPath).success;
	gate = name: extra: { inherit name; messages = failedAssertions (evalPve ([ fixtureSite ] ++ extra)); };
	# The same over the CA-less default: platform.nix's assertions hold on
	# every image, CA-baked or not.
	plainGate = name: extra: { name = "CA-less: ${name}"; messages = failedAssertions (evalPve extra); };

	# Each one differs from the fixture by ONE thing and must trip ONE named
	# assertion. Matched on the message, not on "evaluation failed": a gate
	# that fails for some other reason would otherwise look like a pass.
	gateCases = [
		((gate "no controlPlaneCIDRs (no open-ingress escape)" [ { cogworx.pve.floor.controlPlaneCIDRs = lib.mkForce [ ]; } ]) // { want = "cogworx.pve.floor.controlPlaneCIDRs is empty"; })
		((gate "no infraDenyCIDRs" [ { cogworx.pve.floor.infraDenyCIDRs = lib.mkForce [ ]; } ]) // { want = "cogworx.pve.floor.infraDenyCIDRs is empty"; })
		# The CA reaches sshd's TrustedUserCAKeys file by a route other than
		# controlCAPublicKey: the gates must still see a published image.
		((gate "a CA only through extraTrustedUserCAKeys, no infraDenyCIDRs" [ {
			cogworx.gce.controlCAPublicKey = lib.mkForce "";
			cogworx.gce.extraTrustedUserCAKeys = [ fixtureCAKey ];
			cogworx.pve.floor.infraDenyCIDRs = lib.mkForce [ ];
		} ]) // { want = "cogworx.pve.floor.infraDenyCIDRs is empty"; })
		((gate "a CA only appended to the trusted-CA file, no controlPlaneCIDRs" [ {
			cogworx.gce.controlCAPublicKey = lib.mkForce "";
			environment.etc."ssh/cogworx-control-ca.pub".text = fixtureCAKey;
			cogworx.pve.floor.controlPlaneCIDRs = lib.mkForce [ ];
		} ]) // { want = "cogworx.pve.floor.controlPlaneCIDRs is empty"; })
		((gate "a link-local resolver, even affirmed for GCE" [ { cogworx.gce.vpcResolver = lib.mkForce "169.254.169.254"; cogworx.gce.allowMetadataResolver = true; } ]) // { want = "cogworx.gce.allowMetadataResolver does not apply on PVE"; })
		((gate "a fleet AuthorizedKeysCommand" [ { services.openssh.authorizedKeysCommand = "/run/current-system/sw/bin/true"; } ]) // { want = "services.openssh.authorizedKeysCommand"; })
		((gate "a metadata client with User=" [ { systemd.services.cogworx-attr-scrub.serviceConfig.User = "nobody"; } ]) // { want = "cogworx-attr-scrub talks to the metadata emulator but sets User=nobody"; })
		((gate "a metadata client with DynamicUser=" [ { systemd.services.cogworx-pve-self-refresh.serviceConfig.DynamicUser = true; } ]) // { want = "cogworx-pve-self-refresh talks to the metadata emulator but sets DynamicUser="; })
		((gate "a NixOS firewall a profile forces on" [ { networking.firewall.enable = lib.mkOverride 10 true; } ]) // { want = "networking.firewall.enable is true"; })
		((gate "console root autologin without the opt-in" [ { services.getty.autologinUser = "root"; } ]) // { want = "services.getty.autologinUser"; })
		((gate "cloud-init a profile forces on" [ { services.cloud-init.enable = lib.mkOverride 10 true; } ]) // { want = "services.cloud-init.enable is true"; })
		((gate "systemd-networkd from a profile" [ { systemd.network.enable = true; } ]) // { want = "systemd.network.enable is true"; })
		((gate "a static hostname" [ { networking.hostName = lib.mkForce "x"; } ]) // { want = "networking.hostName is set"; })
		# The label type allows ':', the upgrade tool's system path grammar
		# does not (upgrade/module.nix).
		((gate "a system label the upgrade tool would refuse" [ { system.nixos.label = lib.mkForce "x:y"; } ]) // { want = "does not match the upgrade tool's system path grammar"; })
		# A composition that replaces extraConfig drops the GRUB guard (and
		# its fallback) silently; the upgrade module refuses that.
		((gate "a composition that replaces the GRUB guard" [ { boot.loader.grub.extraConfig = lib.mkForce ""; } ]) // { want = "does not contain the GRUB guard"; })
		# A composition that replaces systemPackages drops the upgrade tool:
		# committed, that generation could never be aborted, released or
		# moved on (the tool's argv[0] rule).
		((gate "a composition that replaces environment.systemPackages" [ { environment.systemPackages = lib.mkForce [ ]; } ]) // { want = "environment.systemPackages does not contain the upgrade tool"; })
		# The upgrade tool pins the distro name and refuses one outside its
		# grammar (a quote would also break install-grub.pl's titles).
		((gate "a distroName the upgrade tool cannot pin" [ { system.nixos.distroName = lib.mkForce "Acme'OS"; } ]) // { want = "is not a name the upgrade tool can pin"; })
		((plainGate "cloud-init a profile forces on" [ { services.cloud-init.enable = lib.mkOverride 10 true; } ]) // { want = "services.cloud-init.enable is true"; })
		((plainGate "systemd-networkd from a profile" [ { systemd.network.enable = true; } ]) // { want = "systemd.network.enable is true"; })
		((plainGate "a static hostname" [ { networking.hostName = lib.mkForce "x"; } ]) // { want = "networking.hostName is set"; })
	];
	# Console autologin is the one gate with an escape, an explicit operator
	# opt-in: with it, the fixture plus autologin evaluates cleanly and says
	# nothing new (a bake may pin warnings == [ ]).
	autologinOptIn = evalPve [ fixtureSite { services.getty.autologinUser = "root"; cogworx.pve.allowConsoleAutologin = true; } ];
	# The gate applies to CA-baked images only: a CA-less dev image keeps its
	# console without the opt-in.
	autologinCALess = evalPve [ { services.getty.autologinUser = "root"; } ];
	# cloud-init is FORCED off, not merely asserted off: a base profile that
	# enables it at default priority (nixpkgs' proxmox-image.nix does) is
	# neutralized, and the image still evaluates cleanly.
	cloudInitDefault = evalPve [ fixtureSite { services.cloud-init.enable = true; } ];
	# Any distro name in the tool's grammar works: grub.nix substitutes it
	# into install-grub.pl's titles and the compat doc records the same one.
	otherDistro = evalPve [ fixtureSite { system.nixos.distroName = lib.mkForce "AcmeOS"; } ];
	gateFailures =
		lib.optional (failedAssertions sys != [ ]) "the fixture (publishable) system itself fails assertions: ${lib.concatStringsSep " | " (failedAssertions sys)}"
		++ lib.optional (!(evaluates sys)) "the fixture (publishable) system's toplevel does not evaluate"
		++ lib.optional (failedAssertions plain != [ ]) "the CA-less default fails assertions; a dev image must evaluate: ${lib.concatStringsSep " | " (failedAssertions plain)}"
		++ lib.optional (!(evaluates plain)) "the CA-less default's toplevel does not evaluate"
		++ lib.optional (system == "x86_64-linux" && exported.config.system.build.toplevel.drvPath != plain.config.system.build.toplevel.drvPath)
			"nixosConfigurations.cogbox-x86_64-pve is not the CA-less default these checks evaluate (mkPveHost with no extra modules)"
		++ lib.optional (system == "x86_64-linux" && exported.config.cogworx.pve.upgrade.hostContract.controlCAKeys != [ ])
			"nixosConfigurations.cogbox-x86_64-pve bakes a control CA; the exported default must stay fail-closed"
		++ lib.optional (evaluates (evalPve [ fixtureSite { cogworx.pve.floor.controlPlaneCIDRs = lib.mkForce [ ]; } ]))
			"a CA-baked image with no controlPlaneCIDRs still EVALUATES its toplevel"
		++ lib.optional (failedAssertions autologinOptIn != [ ])
			"console autologin WITH cogworx.pve.allowConsoleAutologin = true still fails assertions: ${lib.concatStringsSep " | " (failedAssertions autologinOptIn)}"
		++ lib.optional (autologinOptIn.config.warnings != cfg.warnings)
			"console autologin with the opt-in changes the warnings (got: ${lib.concatStringsSep " | " autologinOptIn.config.warnings})"
		++ lib.optional (failedAssertions autologinCALess != [ ])
			"console autologin on the CA-less default (no opt-in) fails assertions; only a CA-baked image needs the opt-in: ${lib.concatStringsSep " | " (failedAssertions autologinCALess)}"
		++ lib.optional (failedAssertions cloudInitDefault != [ ])
			"a default-priority services.cloud-init.enable = true fails assertions instead of being forced off: ${lib.concatStringsSep " | " (failedAssertions cloudInitDefault)}"
		++ lib.optional cloudInitDefault.config.services.cloud-init.enable
			"a default-priority services.cloud-init.enable = true is not forced off"
		++ lib.optional (failedAssertions otherDistro != [ ])
			"a system.nixos.distroName other than NixOS, in the upgrade tool's grammar, fails assertions: ${lib.concatStringsSep " | " (failedAssertions otherDistro)}"
		++ lib.concatMap (c:
			lib.optional (!(lib.any (m: lib.hasInfix c.want m) c.messages))
				"gate '${c.name}' did not trip (wanted '${c.want}'; got: ${lib.concatStringsSep " | " c.messages})") gateCases;

	# The @cp / rule 4 coupling (pve-host.nix): a controlPlaneCIDRs entry that
	# covers an infraDenyCIDRs entry opens it to passt-uid UDP from the mosh
	# port range (rule 4's mosh-reply accept) and to rule 5's control ingress,
	# so evaluation must say so -- and stay quiet for the normal shape (a
	# narrow @cp inside the internal ranges, as in the fixture). Each case replaces
	# the fixture's @cp and lists the substrings of EXACTLY the floor warnings
	# it must produce.
	floorWarnings = s: lib.filter (lib.hasInfix "controlPlaneCIDRs entry") s.config.warnings;
	warnCase = name: cp: want: { inherit name want; got = floorWarnings (evalPve [ fixtureSite { cogworx.pve.floor.controlPlaneCIDRs = lib.mkForce cp; } ]); };
	warnCases = [
		(warnCase "the fixture's narrow @cp inside @infra4" [ "198.18.7.0/24" ] [ ])
		(warnCase "a /16 inside, but not covering, an infraDenyCIDRs /15" [ "198.18.0.0/16" ] [ ])
		(warnCase "@cp equal to an infraDenyCIDRs entry" [ "203.0.113.0/24" ]
			[ "rule 4 only partly applies to infraDenyCIDRs entry 203.0.113.0/24: controlPlaneCIDRs entry 203.0.113.0/24 covers" ])
		(warnCase "@cp containing an infraDenyCIDRs entry" [ "203.0.0.0/16" ]
			[ "rule 4 only partly applies to infraDenyCIDRs entry 203.0.113.0/24: controlPlaneCIDRs entry 203.0.0.0/16 covers" ])
		(warnCase "a /8 @cp covering one entry" [ "198.0.0.0/8" ] [
			"rule 4 only partly applies to infraDenyCIDRs entry 198.18.0.0/15: controlPlaneCIDRs entry 198.0.0.0/8 covers"
			"controlPlaneCIDRs entry 198.0.0.0/8 is wider than /16"
		])
		(warnCase "a wide @cp clear of every infraDenyCIDRs entry" [ "100.64.0.0/10" ] [ "controlPlaneCIDRs entry 100.64.0.0/10 is wider than /16" ])
		# Malformed entries are the renderer's to refuse at build time; the
		# warning must neither throw first nor warn about them.
		(warnCase "malformed entries" [ "git.example.com" "198.018.7.0/24" "300.1.1.0/24" "198.18.7.0/33" "2001:db8::/32" ] [ ])
	];
	warnFailures = lib.concatMap (c:
		let
			r = builtins.tryEval (builtins.deepSeq c.got c.got);
			got = if r.success then r.value else [ ];
			shown = lib.concatStringsSep " | " got;
		in
		lib.optional (!r.success) "floor warnings for '${c.name}' do not evaluate"
		++ lib.concatMap (w: lib.optional (!(lib.any (lib.hasInfix w) got)) "'${c.name}': no warning containing '${w}' (got: ${shown})") c.want
		++ lib.optional (r.success && builtins.length got != builtins.length c.want)
			"'${c.name}': expected ${toString (builtins.length c.want)} floor warning(s), got ${toString (builtins.length got)}: ${shown}") warnCases;

	sysctl = cfg.boot.kernel.sysctl;
	sysctlConf = discard cfg.environment.etc."sysctl.d/60-nixos.conf".text;
	valueFailures = lib.concatLists [
		(lib.optional cfg.networking.firewall.enable "networking.firewall.enable is true")
		(lib.optional (gce.stateDevice != "/dev/disk/by-id/virtio-cogworx-state") "stateDevice is ${gce.stateDevice}")
		(lib.optional (gce.guestDevice != "/dev/disk/by-id/virtio-cogworx-guest") "guestDevice is ${gce.guestDevice}")
		(lib.optional (cfg.fileSystems.${gce.stateDir}.device != "/dev/disk/by-id/virtio-cogworx-state") "the state mount is on ${cfg.fileSystems.${gce.stateDir}.device}")
		(lib.optional (gce.serialDevice != "/run/cogworx/serial.log") "serialDevice is ${gce.serialDevice}")
		(lib.optional (svc.cogworx-supervisor.environment.COGWORX_SERIAL != "/run/cogworx/serial.log") "the supervisor's COGWORX_SERIAL is ${svc.cogworx-supervisor.environment.COGWORX_SERIAL}")
		(lib.optional (!(lib.elem "d /run/cogworx 0700 root root -" cfg.systemd.tmpfiles.rules)) "no tmpfiles 'd /run/cogworx 0700'")
		(lib.optional (!(lib.elem "f /run/cogworx/serial.log 0600 root root -" cfg.systemd.tmpfiles.rules)) "the serial log is not pre-created 0600")
		(lib.optional (!(lib.elem "console=ttyS0" cfg.boot.kernelParams)) "no console=ttyS0")
		(lib.optional (!(lib.elem "net.ifnames=0" cfg.boot.kernelParams)) "no net.ifnames=0")
		(lib.optional (cfg.boot.loader.grub.devices != [ "/dev/vda" ]) "grub is not on /dev/vda")
		(lib.optional (cfg.boot.loader.timeout != 0) "the boot loader waits")
		# No check builds the image, so the grub.cfg shape is pinned here: a
		# limit of 0 makes install-grub.pl write an empty submenu, a GRUB
		# syntax error (image.nix).
		(lib.optional (cfg.boot.loader.grub.configurationLimit < 1) "grub.configurationLimit is ${toString cfg.boot.loader.grub.configurationLimit}; below 1 the rendered grub.cfg has an empty submenu, which GRUB rejects")
		(lib.optional (!cfg.fileSystems."/".autoResize || !cfg.boot.growPartition) "the root filesystem does not grow")
		(lib.optional (cfg.fileSystems."/".device != "/dev/disk/by-label/nixos") "root is not mounted by label")
		(lib.optional (!(lib.elem "virtio_blk" cfg.boot.initrd.kernelModules)) "virtio_blk is not in the initrd")
		(lib.optional (!(lib.elem "kvm-intel" cfg.boot.kernelModules)) "kvm-intel is not loaded")
		(lib.optional (cfg.networking.hostName != "") "a static hostname is set (${cfg.networking.hostName}); hostname.nix owns it")
		(lib.optional (cfg.networking.dhcpcd.setHostname) "dhcpcd may set the hostname")
		(lib.optional (cfg.networking.dhcpcd.wait != "ipv4") "dhcpcd does not wait for IPv4")
		(lib.optional (!(cfg.networking.interfaces.eth0.useDHCP or false) || cfg.networking.useDHCP) "DHCP is not eth0-only")
		(lib.optional (!(lib.elem "metadata.google.internal" (cfg.networking.hosts."169.254.169.254" or [ ]))) "metadata.google.internal is not pinned in /etc/hosts")
		(lib.concatMap (kv: lib.optional ((sysctl.${kv.name} or null) != kv.value) "sysctl ${kv.name} is ${toString (sysctl.${kv.name} or "unset")}, expected ${toString kv.value}")
			(lib.mapAttrsToList lib.nameValuePair {
				"net.ipv4.conf.all.arp_ignore" = 1;
				"net.ipv4.conf.all.arp_announce" = 2;
				"net.ipv6.conf.eth0.disable_ipv6" = 1;
				"net.ipv4.conf.all.rp_filter" = 1;
				"net.ipv4.conf.all.accept_redirects" = 0;
				"net.ipv4.conf.all.accept_source_route" = 0;
				"net.ipv4.ip_forward" = 0;
				"net.ipv4.tcp_syncookies" = 1;
			}))
		(lib.concatMap (l: lib.optional (!(lib.hasInfix l sysctlConf)) "the rendered sysctl.d file lacks '${l}'")
			[ "net.ipv4.conf.all.arp_ignore=1" "net.ipv4.conf.all.arp_announce=2" "net.ipv6.conf.eth0.disable_ipv6=1" ])
		(lib.concatMap (u: lib.optional ((cfg.systemd.units."${u}.service".enable or false)) "${u}.service is rendered")
			[ "google-guest-agent" "google-startup-scripts" "google-shutdown-scripts" "firewall" ])
		(lib.optional (!(cfg.system.build ? pveImage)) "system.build.pveImage is missing")
		(lib.optional (unclassified != [ ]) "cogworx-* unit(s) not classified as metadata client or not: ${toString unclassified}")
		(lib.optional (staleClassification != [ ]) "classified unit(s) that no longer exist: ${toString staleClassification}")
		(lib.optional (stubClients != [ ]) "metadata client unit(s) with no ExecStart, i.e. edge-only stubs that metadata.nix keeps defined after the real unit is gone: ${toString stubClients}")
		# Fail closed on rule 5: sshd must not listen on eth0 without it.
		(lib.optional (!(lib.elem "sshd.service" svc.cogworx-pve-floor.requiredBy)) "cogworx-pve-floor is not RequiredBy= sshd.service; a floor that fails to load would leave sshd open to the shared L2")
		# The format units run mke2fs with the no-discard profile, and they are
		# the only units that do and the only format legs gce/ has.
		(lib.concatMap (n: lib.optional (mke2fsValue n != mke2fsProfile)
			"${n}: MKE2FS_CONFIG is '${mke2fsValue n}', not the no-discard profile ${mke2fsProfile}; its mkfs.ext4 would discard the whole device") formatUnits)
		(lib.optional (lib.sort lib.lessThan mke2fsCarriers != lib.sort lib.lessThan formatUnits)
			"the units carrying MKE2FS_CONFIG are [${toString mke2fsCarriers}], not exactly [${toString formatUnits}]")
		(lib.optional (lib.sort lib.lessThan gceFormatLines != [ "guest-disk.nix" "guest-disk.nix" "state-disk.nix" ])
			"gce/ runs mkfs/mke2fs on non-comment lines in [${toString gceFormatLines}], not exactly state-disk.nix's one and guest-disk.nix's two; a new format leg discards the whole device until its unit joins pve/mkfs-nodiscard.nix's list")
		(lib.optional (!(lib.any (lib.hasInfix "pve/mkfs-nodiscard.nix: cogworx-state-disk has no ExecStart") formatStub))
			"a format unit with no ExecStart does not trip mkfs-nodiscard.nix's assertion (got: ${lib.concatStringsSep " | " formatStub})")
		# The upgrade module (upgrade/module.nix): what every system
		# generation must carry for the tool and the guard to work.
		(lib.concatMap (p: lib.optional (!(lib.elem p cfg.boot.kernelParams))
			"${p} is not in boot.kernelParams; a candidate whose stage 1 fails would hang instead of rebooting onto entry 0") [ "panic=10" "boot.panic_on_fail" ])
		(lib.optional (cfg.boot.loader.grub.extraConfig != builtins.readFile ./upgrade/grub-guard.cfg)
			"boot.loader.grub.extraConfig is not exactly upgrade/grub-guard.cfg")
		(lib.optional cfg.services.cloud-init.enable "services.cloud-init.enable is true")
		(lib.optional cfg.systemd.network.enable "systemd.network.enable is true")
		(lib.optional (!(lib.any (p: p == pve.upgrade.package) cfg.environment.systemPackages))
			"the upgrade tool is not in environment.systemPackages, so <system>/sw/bin/cogworx-pve-upgrade does not exist")
		(lib.optional (!(lib.hasInfix "cogworx-pve-compat.json" cfg.system.systemBuilderCommands))
			"the toplevel does not carry cogworx-pve-compat.json")
		(lib.optional (pve.upgrade.minFreeBytes != 12 * gib)
			"cogworx.pve.upgrade.minFreeBytes is ${toString pve.upgrade.minFreeBytes}, not 12 GiB")
		(lib.optional (pve.upgrade.minFreeBytes != gceMinFreeGB * gib)
			"cogworx.pve.upgrade.minFreeBytes (${toString pve.upgrade.minFreeBytes}) is not gce/nix-gc.nix's minFreeGB (${toString gceMinFreeGB} GiB); a fetch would leave the store below the floor the collector defends")
		(lib.optional (pve.upgrade.reserveBytes != 4 * gib)
			"cogworx.pve.upgrade.reserveBytes is ${toString pve.upgrade.reserveBytes}, not 4 GiB")
		(lib.optional (pve.release != null) "cogworx.pve.release is set on the fixture; only a release bake sets it")
		(lib.optional (!(lib.elem "f /run/cogworx-pve-upgrade.lock 0600 root root -" cfg.systemd.tmpfiles.rules))
			"the upgrade lock file is not pre-created root-owned 0600; its first opener would create it (flock(1) in the gc wrapper: 0644) and any local uid could hold a read-only flock on it forever")
		# mkPveHost's revision (flake.nix): a mkDefault definition (a bake may
		# override it) of self.rev, else self.dirtyRev, else null.
		(lib.optional (sys.options.system.configurationRevision.highestPrio != 1000 || cfg.system.configurationRevision != (flake.rev or flake.dirtyRev or null))
			"system.configurationRevision is not mkPveHost's lib.mkDefault (self.rev or self.dirtyRev or null)")
	];

	failureList = name: failures: pkgs.runCommand name {
		failures = builtins.toJSON failures;
		passAsFile = [ "failures" ];
		nativeBuildInputs = [ pkgs.jq ];
	} ''
		n=$(jq length "$failuresPath")
		if [ "$n" -gt 0 ]; then
			jq -r '.[] | "FAIL: " + .' "$failuresPath" >&2
			exit 1
		fi
		echo "${name}: all eval-time assertions hold"
		touch $out
	'';

	hostnameScript = builtins.head (execPaths "cogworx-pve-hostname");
	# The mosh range as floor_render.py spells a port range.
	moshSports =
		if gce.moshUDPPortRange == 1 then toString gce.moshUDPPort
		else "${toString gce.moshUDPPort}-${toString (gce.moshUDPPort + gce.moshUDPPortRange - 1)}";

	checks = {
		# The orderings and properties README.md calls the contract, on the
		# unit files NixOS renders.
		unit-graph = pkgs.runCommand "pve-unit-graph" {
			nativeBuildInputs = [ pkgs.jq pkgs.gnugrep ];
		} ''
			fails=0
			fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
			unit() { jq -r --arg u "$1" '.[$u] // empty' ${unitsJson}; }
			# The values of one directive, space-joined across repeated lines.
			dir() { unit "$1" | grep "^$2=" | cut -d= -f2- | tr '\n' ' '; }
			has() { case " $(dir "$1" "$2") " in *" $3 "*) ;; *) fail "$1: $2= lacks $3 ($(dir "$1" "$2"))" ;; esac; }
			hasnt() { case " $(dir "$1" "$2") " in *" $3 "*) fail "$1: $2= has $3" ;; esac; }
			line() { unit "$1" | grep -qxF -- "$2" || fail "$1: no line '$2'"; }
			sock=cogworx-pve-metadata.socket

			# md-addr -> socket -> every client.
			line cogworx-pve-md-addr.service 'DefaultDependencies=false'
			has cogworx-pve-md-addr.service Before "$sock"
			has cogworx-pve-md-addr.service Before sockets.target
			unit cogworx-pve-md-addr.service | grep -q '^ExecStart=.*/bin/ip addr replace 169.254.169.254/32 scope host dev lo$' \
				|| fail "md-addr does not put 169.254.169.254/32 scope host on lo"
			has "$sock" Requires cogworx-pve-md-addr.service
			has "$sock" After cogworx-pve-md-addr.service
			line "$sock" 'ListenStream=169.254.169.254:80'
			line "$sock" 'FreeBind=true'
			for c in ${toString (lib.unique (specSocketClients ++ socketClients))}; do
				has "$c.service" After "$sock"
				has "$c.service" Requires "$sock"
			done
			# Root, every one of them (rule 4a; the emulator's peer-uid check).
			for c in ${toString pve.metadataClients} cogworx-pve-metadata; do
				if unit "$c.service" | grep -qE '^(User|DynamicUser)='; then
					fail "$c runs as $(unit "$c.service" | grep -E '^(User|DynamicUser)=')"
				fi
			done
			unit cogworx-pve-metadata.service | grep -q '^ExecStart=.*/bin/cogworx-pve-metadata serve --iface eth0 --state-dir /run/cogworx$' \
				|| fail "the emulator does not serve eth0 into /run/cogworx"

			# The supervisor: the gce edges survive and the pve ones are added.
			# Nothing depends on the emulator SERVICE beyond ordering, so an
			# emulator restart never propagates (clients Require the socket).
			s=cogworx-supervisor.service
			for u in cogworx-pve-metadata.service "$sock" cogworx-pve-floor.service cogworx-pve-self-refresh.service cogworx-floor.service cogworx-attr-scrub.service; do
				has "$s" After "$u"
			done
			has "$s" Wants cogworx-pve-self-refresh.service
			has "$s" Requires cogworx-pve-floor.service
			has "$s" Requires cogworx-floor.service
			has "$s" Requires cogworx-attr-scrub.service
			hasnt "$s" Requires cogworx-pve-self-refresh.service
			for u in $(jq -r 'keys[] | select(endswith(".service"))' ${unitsJson}); do
				case " $(dir "$u" Requires) $(dir "$u" BindsTo) " in
					*" cogworx-pve-metadata.service "*) fail "$u Requires=/BindsTo= the emulator service; an emulator restart would propagate to it" ;;
				esac
			done

			# self-refresh: after the lease and the state mount, before the launch.
			r=cogworx-pve-self-refresh.service
			has "$r" After network-online.target
			has "$r" Wants network-online.target
			has "$r" Before cogworx-supervisor.service
			line "$r" 'RequiresMountsFor=${gce.stateDir}'
			line "$r" 'Environment="XDG_CONFIG_HOME=${gce.stateDir}/config"'

			# The format units: mke2fs with the no-discard profile
			# (mkfs-nodiscard.nix), and no other unit with it.
			for u in ${toString formatUnits}; do
				line "$u.service" 'Environment="MKE2FS_CONFIG=${mke2fsProfile}"'
			done
			for u in $(jq -r 'to_entries[] | select(.value | contains("MKE2FS_CONFIG")) | .key' ${unitsJson}); do
				case " ${toString formatUnits} " in
					*" ''${u%.service} "*) ;;
					*) fail "$u carries MKE2FS_CONFIG" ;;
				esac
			done

			# hostname: before anything reads or sends it.
			h=cogworx-pve-hostname.service
			line "$h" 'DefaultDependencies=false'
			for u in dhcpcd.service consul.service network-pre.target; do has "$h" Before "$u"; done
			has "$h" Wants network-pre.target
			has "$h" WantedBy sysinit.target

			# The site floor: before every guarded surface opens.
			has cogworx-pve-floor.service Before sshd.service
			has cogworx-pve-floor.service Before cogworx-supervisor.service
			has cogworx-pve-kvm.service Before cogworx-supervisor.service
			has cogworx-pve-serial-cap.timer WantedBy timers.target

			# The collector waits for nobody: it skips (exit 75, a success)
			# while the upgrade tool holds its lock (upgrade/module.nix).
			line cogworx-nix-gc.service ${lib.escapeShellArg gcExecStart}
			line cogworx-nix-gc.service 'SuccessExitStatus=75'
			# Nothing on the VM runs the upgrade tool; cogworxd runs it by path.
			if jq -r '.[]' ${unitsJson} | grep -qF ${upgradePackagePath}; then
				fail "a rendered unit references the upgrade tool package ${upgradePackagePath}"
			fi

			# qemu-ga: an allow-list, with nothing that executes or writes.
			ga=$(dir qemu-guest-agent.service ExecStart)
			case "$ga" in *' --allow-rpcs='*) ;; *) fail "qemu-ga has no --allow-rpcs: $ga" ;; esac
			for rpc in guest-exec guest-file-write guest-file-seek guest-set-user-password guest-ssh-add-authorized-keys; do
				case ",''${ga#*--allow-rpcs=}" in *",$rpc,"*|*",$rpc "*) fail "qemu-ga allows $rpc" ;; esac
			done
			case "$ga" in *--block-rpcs*) fail "qemu-ga also has a block-list" ;; esac

			# Serial discipline (gce-image-serial-classes' rule, for the pve units).
			for u in $(jq -r 'keys[] | select(startswith("cogworx-pve-"))' ${unitsJson}); do
				if unit "$u" | grep -E '^Standard(Output|Error)=' | grep -Eq 'console|tty'; then
					fail "$u sends a standard stream to console/tty"
				fi
			done

			[ "$fails" -eq 0 ] || exit 1
			echo "unit-graph: all orderings and unit properties hold"
			touch $out
		'';

		config-values = failureList "pve-config-values" valueFailures;
		publish-gates = failureList "pve-publish-gates" gateFailures;
		floor-warnings = failureList "pve-floor-warnings" warnFailures;

		# The ExecStart is passed whole (builtins.match would drop its store
		# context, and with it the dependency on the config file).
		dhcpcd-conf = pkgs.runCommand "pve-dhcpcd-conf" { execStart = svc.dhcpcd.serviceConfig.ExecStart; } ''
			conf=$(printf '%s' "$execStart" | sed -n 's/.*--config \([^ ]*\).*/\1/p')
			[ -r "$conf" ] || { echo "FAIL: cannot find dhcpcd.conf in: $execStart" >&2; exit 1; }
			fails=0
			for l in 'nohook hostname' 'nohook resolv.conf' 'noipv4ll' 'noipv6' 'clientid' 'waitip 4' 'allowinterfaces eth0'; do
				grep -qxF "$l" "$conf" || { echo "FAIL: dhcpcd.conf lacks '$l'" >&2; fails=$((fails + 1)); }
			done
			if grep -q '^option host_name' "$conf"; then
				echo "FAIL: dhcpcd.conf asks the server for a hostname" >&2; fails=$((fails + 1))
			fi
			[ "$fails" -eq 0 ] || exit 1
			touch $out
		'';

		hosts-pin = pkgs.runCommand "pve-hosts-pin" { } ''
			grep -qE '^169\.254\.169\.254[[:space:]]+metadata\.google\.internal metadata$' ${cfg.environment.etc.hosts.source} \
				|| { echo "FAIL: /etc/hosts does not pin metadata.google.internal to 169.254.169.254" >&2; cat ${cfg.environment.etc.hosts.source} >&2; exit 1; }
			touch $out
		'';

		qga-allowlist = pkgs.runCommand "pve-qga-allowlist" { nativeBuildInputs = [ pkgs.python3 ]; } ''
			python3 -I ${tests}/test_qga_allowlist.py ${lib.escapeShellArg svc.qemu-guest-agent.serviceConfig.ExecStart}
			touch $out
		'';

		route-coverage = pkgs.runCommand "pve-route-coverage" { nativeBuildInputs = [ pkgs.python3 pkgs.curl ]; } ''
			python3 -I ${tests}/test_route_coverage.py \
				--emulator ${./metadata/cogworx_pve_metadata.py} \
				--vectors ${./testdata/bootcfg-v1.json} \
				${lib.escapeShellArgs clientScripts}
			touch $out
		'';

		floor-site = pkgs.runCommand "pve-floor-site" {
			nativeBuildInputs = with pkgs; [ bash coreutils gnugrep gnused gawk util-linux nftables iproute2 python3 systemd ];
		} ''
			export HOME=$TMPDIR
			# On the REALIZED ruleset, independent of the golden file and of
			# whether this sandbox can host the live probes:
			#  - rule 4a's input leg is the FIRST rule of the input chain, so it
			#    precedes rule 5's @cp accept (a frame for 169.254/16 that
			#    arrives on eth0 is dropped whatever its source);
			#  - rule 4 accepts @cp ONLY for passt's mosh replies: every rule
			#    naming @cp in the output chain carries the passt uid, udp and
			#    the mosh source range, so no uid rule 4 drops gets a blanket
			#    pass to a @cp inside @infra4.
			# The rules of one chain, its hook line left out.
			chain() { awk -v c="chain $1 {" 'index($0, c) { f = 1; next } f && /^\t}/ { f = 0 } f && !/type filter hook/' ${pve.floor.ruleset}; }
			first=$(chain input | sed -n 1p)
			case "$first" in
				*'iifname != "lo" ip daddr 169.254.0.0/16 counter drop'*'rule4a-input'*) echo "ok   - realized: rule 4a's input drop is the first rule of the input chain" ;;
				*) echo "FAIL: the realized input chain does not open with rule 4a's input drop: $first" >&2; exit 1 ;;
			esac
			mosh='meta skuid "${gce.passtUser}" ip daddr @cp udp sport ${moshSports} counter accept'
			cpLines=$(chain output | grep -F '@cp' || true)
			if [ "$(printf '%s\n' "$cpLines" | grep -c . || true)" != 1 ] || ! printf '%s\n' "$cpLines" | grep -qF -- "$mosh"; then
				echo "FAIL: the realized output chain names @cp other than in exactly one '$mosh' rule:" >&2
				printf '%s\n' "$cpLines" >&2
				exit 1
			fi
			echo "ok   - realized: rule 4's only @cp accept is passt's mosh replies"
			bash ${tests}/test_floor_site.sh ${./floor_render.py} ${pve.floor.ruleset} \
				${svc.cogworx-floor.serviceConfig.ExecStart} ${svc.cogworx-floor.serviceConfig.ExecStartPost}
			touch $out
		'';

		self-refresh = pkgs.runCommand "pve-self-refresh" {
			nativeBuildInputs = with pkgs; [ bash coreutils jq curl util-linux gnugrep gnused findutils ];
		} ''
			bash ${tests}/test_self_refresh.sh ${builtins.head (execPaths "cogworx-pve-self-refresh")}
			touch $out
		'';

		hostname = pkgs.runCommand "pve-hostname" { nativeBuildInputs = with pkgs; [ bash coreutils gnugrep gnused python3 ]; } ''
			if grep -v '^[[:space:]]*#' ${hostnameScript} | grep -q 'cogworx-instance'; then
				echo "FAIL: the hostname unit reads cogworx-instance (a user-chosen name)" >&2
				exit 1
			fi
			grep -q -- '--print-attr cogworx-hostname' ${hostnameScript} || { echo "FAIL: the hostname unit does not read cogworx-hostname from DMI" >&2; exit 1; }
			bash ${tests}/test_hostname.sh ${hostnameScript} ${./testdata/bootcfg-v1.json}
			touch $out
		'';

		serial-cap = pkgs.runCommand "pve-serial-cap" { nativeBuildInputs = with pkgs; [ bash coreutils gnugrep findutils ]; } ''
			bash ${tests}/test_serial_cap.sh ${builtins.head (execPaths "cogworx-pve-serial-cap")}
			touch $out
		'';

		metadata-unittests = pkgs.runCommand "pve-metadata-unittests" { nativeBuildInputs = [ pkgs.python3 ]; } ''
			COGWORX_PVE_METADATA=${./metadata/cogworx_pve_metadata.py} \
			COGWORX_PVE_VECTORS=${./testdata/bootcfg-v1.json} \
				python3 -I ${tests}/test_metadata.py
			touch $out
		'';

		# The upgrade tool (pve/upgrade/): argv grammar, the envelope, the
		# grub.cfg/grubenv parsers and their shared vectors, the closure digest
		# vector, the bootloader pin on the image's REAL install-grub.sh, the
		# guest compat rules, fetch classification on nix 2.34's strings, the
		# state machine on a fake guest (the real grub-editenv, a fake
		# installer and fake nix commands) with a power cut after every
		# numbered step, and the built package itself. Plus compat_doc.py.
		upgrade-unittests = pkgs.runCommand "pve-upgrade-unittests" {
			nativeBuildInputs = [ pkgs.python3 pkgs.grub2 pkgs.openssh pkgs.util-linux ];
		} ''
			COGWORX_PVE_UPGRADE=${./upgrade/cogworx_pve_upgrade.py} \
			COGWORX_PVE_UPGRADE_BIN=${upgradeTool}/bin/cogworx-pve-upgrade \
			GRUB_EDITENV=${pkgs.grub2}/bin/grub-editenv \
			PVE_INSTALLER=${plain.config.system.build.installBootLoader} \
			PVE_GRUB_STATE_GRUB=${plain.config.system.build.grub} \
			UPGRADE_VECTORS=${./testdata} \
				python3 -I ${tests}/test_upgrade.py
			COGWORX_PVE_COMPAT_DOC=${./upgrade/compat_doc.py} \
				python3 -I ${tests}/test_compat_doc.py
			touch $out
		'';

		# The GRUB guard (upgrade/grub-guard.cfg) parses as GRUB script, with a
		# negative control (the same file cut short must not), and carries the
		# marker the tool's bootloader pin looks for. GRUB's regexp returns
		# the same failure for a bad pattern as for no match, so a typo in a
		# pattern would fail closed silently; the VM test boots the positive
		# cases.
		grub-guard-syntax = pkgs.runCommand "pve-grub-guard-syntax" {
			nativeBuildInputs = [ pkgs.grub2 pkgs.gnugrep pkgs.coreutils ];
		} ''
			guard=${./upgrade/grub-guard.cfg}
			grep -qx '# cwx-guard-v1' "$guard" || { echo "FAIL: the guard has no '# cwx-guard-v1' marker line" >&2; exit 1; }
			grub-script-check "$guard" || { echo "FAIL: grub-script-check rejects the guard" >&2; exit 1; }
			head -n -1 "$guard" > truncated.cfg
			if grub-script-check truncated.cfg 2>/dev/null; then
				echo "FAIL: grub-script-check accepts the guard without its last line; the check above proves nothing" >&2
				exit 1
			fi
			echo "grub-guard-syntax: the guard parses, a truncated copy does not"
			touch $out
		'';

		# The fixture's compat doc (<toplevel>/cogworx-pve-compat.json), built
		# and pinned WHOLE (its key set is the expected object's, and every
		# key's value is compared): the host contract equals the fixture's
		# values, the CA key is decoded and fingerprinted, the protocol values
		# come from gce/protocol.nix, the substituter lists from nix.settings,
		# the boot loader fields name the system's own installer and the
		# guard, and the document stays within the readers' 16 KiB cap.
		compat-doc = pkgs.runCommand "pve-compat-doc" {
			nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
			passAsFile = [ "expected" ];
			expected = builtins.toJSON {
				schema = 1;
				kind = "cogworx-pve-system";
				toolProto = 1;
				txnSchema = 1;
				inherit (import "${gceSrc}/protocol.nix") bootProof stateFormat;
				bootConfigVersions = [ 1 ];
				smbiosSelector = "S";
				guestAttrsVersion = 1;
				release = null;
				hostKeyPath = "${gce.stateDir}/sshd/ssh_host_ed25519_key";
				stateDevice = "/dev/disk/by-id/virtio-cogworx-state";
				guestDevice = "/dev/disk/by-id/virtio-cogworx-guest";
				interface = "eth0";
				controlUser = "root";
				controlPlaneCIDRs = [ "198.18.7.0/24" ];
				controlCAKeys = [ (lib.concatStringsSep " " (lib.take 2 (lib.splitString " " fixtureCAKey))) ];
				controlCAFingerprints = [ fixtureCAFingerprint ];
				specialisations = [ ];
				substituters = expectedSubstituters;
				trustedPublicKeys = expectedTrustedKeys;
				bootloader = {
					installer = discard "${cfg.system.build.installBootLoader}";
					grub = discard "${cfg.system.build.grub}";
					devices = [ "/dev/vda" ];
					distroName = "NixOS";
					guard = "cwx-guard-v1";
				};
			};
		} ''
			doc=${pve.upgrade.compatDoc}
			fails=0
			fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
			jq -e 'type == "object"' "$doc" > /dev/null || { echo "FAIL: $doc is not a JSON object" >&2; exit 1; }
			wantKeys=$(jq -cS 'keys' "$expectedPath")
			gotKeys=$(jq -cS 'keys' "$doc")
			[ "$wantKeys" = "$gotKeys" ] || fail "the doc's keys are $gotKeys, expected $wantKeys"
			for k in $(jq -r 'keys[]' "$expectedPath"); do
				want=$(jq -cS --arg k "$k" '.[$k]' "$expectedPath")
				got=$(jq -cS --arg k "$k" '.[$k]' "$doc")
				[ "$want" = "$got" ] || fail "$k is $got, expected $want"
			done
			size=$(stat -c %s "$doc")
			[ "$size" -le 16384 ] || fail "the doc is $size bytes, over the readers' 16384-byte cap"
			[ "$(tr -d '\000-\177' < "$doc" | wc -c)" -eq 0 ] || fail "the doc is not ASCII"
			[ "$fails" -eq 0 ] || exit 1
			echo "compat-doc: the fixture's compat doc holds"
			touch $out
		'';

		# The format units' mke2fs profile, built and RUN: the package default
		# plus `discard = false` and nothing else, derived from the file the
		# units' own mke2fs compiles in, and every realized mkfs line of those
		# units discarding under the default profile but not under theirs
		# (strace on a sparse file, with a control that must discard). Builds
		# the two small unit scripts.
		mkfs-nodiscard = pkgs.runCommand "pve-mkfs-nodiscard" {
			nativeBuildInputs = with pkgs; [ bash coreutils diffutils gnugrep gnused strace ];
		} ''
			bash ${tests}/test_mkfs_nodiscard.sh ${sysE2fsprogs} ${sysE2fsprogs.out}/etc/mke2fs.conf ${cfg.system.build.pveMke2fsConfig} \
				${lib.concatMapStringsSep " " (n: lib.escapeShellArg "${n}=${builtins.head (execPaths n)}=${toString (svc.${n}.environment.MKE2FS_CONFIG or "")}") formatUnits}
			touch $out
		'';

		# Every program a cogworx-pve-* unit runs, BUILT: writeShellApplication
		# shellchecks at build time, which an evaluation never reaches.
		unit-scripts = pkgs.runCommand "pve-unit-scripts" {
			programs = lib.concatMap execPaths (lib.filter (lib.hasPrefix "cogworx-pve-") cogworxServices);
		} ''
			for p in $programs; do
				[ -x "$p" ] || { echo "FAIL: $p is not an executable" >&2; exit 1; }
			done
			touch $out
		'';

		# Evaluation only: the default and fixture toplevels and the image.
		eval = pkgs.writeText "pve-eval" ''
			default toplevel: ${discard plain.config.system.build.toplevel.drvPath}
			fixture toplevel: ${discard sys.config.system.build.toplevel.drvPath}
			fixture image: ${discard sys.config.system.build.pveImage.drvPath}
		'';
	};

	# Checks that REALIZE the system, kept out of `all` for their build cost.
	heavy = {
		# THE offline-boot property, as flake.nix's gce-image-offline-closure
		# states it for GCE: cogbox-launch.sh's custom-flake re-exec EVALUATES
		# the guest configuration, which forces every flake input SOURCE tree,
		# and a non-resident one aborts the eval offline and drops the guest
		# half. image.nix's make-disk-image registers exactly the toplevel's
		# closure (its basePaths), so that closure is what must hold them.
		offline-closure = pkgs.runCommand "pve-offline-closure" { } ''
			paths=${pkgs.closureInfo { rootPaths = [ cfg.system.build.toplevel ]; }}/store-paths
			fails=0
			for src in \
				'${flake.inputs.microvm}' \
				'${flake.inputs.llm-agents}' \
				'${flake.inputs.nix-mcp}' \
				'${flake.inputs.illustris-lib}'; do
				if ! grep -qxF "$src" "$paths"; then
					echo "FAIL: flake input source $src is NOT in the PVE image's registered closure;" >&2
					echo "      the launcher's re-exec will abort offline and drop the guest half" >&2
					fails=$((fails + 1))
				fi
			done
			# The cogbox package itself, and with it the microvm runner and the
			# guest kernel/initrd/toplevel.
			if ! grep -q 'cogbox' "$paths"; then
				echo "FAIL: no cogbox path in the PVE image closure" >&2
				fails=$((fails + 1))
			fi
			# The upgrade compat doc is a regular file in the toplevel, the
			# one the module built; the tool is in the system path.
			top=${cfg.system.build.toplevel}
			if [ -L "$top/cogworx-pve-compat.json" ] || ! cmp -s "$top/cogworx-pve-compat.json" ${pve.upgrade.compatDoc}; then
				echo "FAIL: $top/cogworx-pve-compat.json is not a regular file equal to ${pve.upgrade.compatDoc}" >&2
				fails=$((fails + 1))
			fi
			if [ ! -x "$top/sw/bin/cogworx-pve-upgrade" ]; then
				echo "FAIL: $top/sw/bin/cogworx-pve-upgrade is missing" >&2
				fails=$((fails + 1))
			fi
			[ "$fails" -eq 0 ] || exit 1
			touch $out
		'';

		# The upgrade path on a real boot loader (legacy MBR, SeaBIOS, GRUB on
		# /dev/vda) with the REAL tool, the guard and the panic parameters:
		# tests/upgrade-vm.nix. KVM. `main` boots every guard path and every
		# verb; `powercut` cuts the power after every commit and abort step and
		# repairs from txn.json. They share the disk image and run in parallel.
		upgrade-vm = pkgs.testers.runNixOSTest (import ./tests/upgrade-vm.nix { suite = "main"; });
		upgrade-vm-powercut = pkgs.testers.runNixOSTest (import ./tests/upgrade-vm.nix { suite = "powercut"; });
	};
in
checks // heavy // {
	all = pkgs.linkFarm "pve-checks" (lib.mapAttrsToList (name: path: { inherit name path; }) checks);
}
