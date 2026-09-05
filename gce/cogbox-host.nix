# The cogworx GCE backend image: the cogbox host half as a NixOS system that
# boots on Google Compute Engine under nested virtualization.
#
# This module is layered ON TOP of nixpkgs' google-compute-image.nix, and most
# of what it does is UNDO that profile's defaults. The stock GCE image is built
# for a general-purpose VM whose operator drives it through instance metadata;
# this one is built for a VM whose metadata surface must be inert, because the
# lifecycle credential that can write
# metadata is deliberately NOT trusted with code execution on the trusted half.
#
# Everything that is not "undo a GCE default" lives in the sibling modules:
#   state-disk.nix       the /var/lib/cogbox-state filesystem every other path
#                        already assumed existed
#   scrub.nix            cogworx-attr-scrub.service, the floor-INDEPENDENT
#                        stale-guest-attribute scrub
#   floor.nix            cogworx-floor.service, the nftables floor plus its
#                        eight live probes
#   supervisor.nix       cogworx-supervisor.service + cogworx-cogbox-log.service
#   nix-gc.nix           bound boot-disk growth from in-VM plugin builds
#   resolver-deadline.nix the in-VM belt for the resolver self-destruct
{
	config,
	options,
	lib,
	pkgs,
	self,
	inputs,
	system,
	...
}:
let
	cfg = config.cogworx.gce;

	# GCE's VPC resolver, read from `vpcResolver`'s own DECLARATION below rather
	# than repeated as another literal. The publishability assertion has to
	# recognise "the default was left in place", and a copy of the address here
	# would go stale the moment the declared default moved. (`options` is the
	# merged option TREE passed to every module -- not the `options` attribute
	# this file returns.)
	declaredVpcResolver = options.cogworx.gce.vpcResolver.default;

	# The sshd ACCOUNT stack, minus our own rule: the floor the control user's
	# exemption has to stay below, and the value the assertion compares against.
	# Read from the OPTION set rather than the rendered file, so a rule a composed
	# profile has declared but not enabled still counts -- it is one option flip
	# away from being above us. `removeAttrs` by name is what keeps this from
	# recursing: nothing below reads cogworx-control's own order.
	#
	# The empty case is real, not defensive: security.pam.services.<n>.rules are
	# declared under `lib.optionalAttrs cfg.useDefaultRules`, so a config with
	# useDefaultRules = false has NO other account rules -- and the previous
	# anchor (rules.account.unix.order) made that combination an eval error rather
	# than a supported one. 10100 is nixpkgs' first built-in slot
	# (autoOrderRules numbers from 10000 in steps of 100), so the fallback puts us
	# at the same 10000 we occupy with the defaults present.
	sshdOtherAccountOrders = map (r: r.order) (lib.attrValues
		(removeAttrs config.security.pam.services.sshd.rules.account [ "cogworx-control" ]));
	sshdAccountOrderFloor =
		if sshdOtherAccountOrders == [ ]
		then 10100
		else lib.foldl' lib.min (lib.head sshdOtherAccountOrders) sshdOtherAccountOrders;
	pamControl = config.security.pam.services.sshd.rules.account.cogworx-control;

	# THIS IMAGE IS HOSTED-ONLY. There is ONE guest storage profile on the GCE
	# backend, it is baked, and nothing at runtime selects between two.
	#
	# An earlier revision put a chooser in front of `cogbox` that tested the two
	# guest volume device nodes and fell back to the WORKSTATION runner when
	# either was missing, so that the four cases guest-disk.nix refuses to carve
	# still yielded a bootable guest. It was removed deliberately, and the reason
	# is not the closure it cost: it was that the image could then run in two
	# modes while every piece of per-instance state -- the state disk, the
	# instance config dir, the recorded runner path, the retained 9p work tree,
	# the harness overlay image -- persisted ACROSS the flip. Four separate
	# blocker rounds each found one instance of that: an ordering-dependent brain
	# materialisation, two occupancy tests that read a fallback boot's own
	# scaffolding as user data, and a fast-path runner record keyed on something
	# identical in both modes and therefore reused across the flip. They were not
	# four bugs; they were one structural fact. Removing the flip removes the
	# class.
	#
	# WHAT REPLACES THE FALLBACK is not a second mode but VISIBILITY, because the
	# failure mode the chooser was written against was bad for a specific
	# reason: there was no recovery path. The instance sat in Booting with no
	# sshd and no control channel, so nobody could look. That is a property of
	# the HOST half, and the host half is untouched by any of this:
	#
	#   - guest-disk.nix declares NO fileSystems entry, so no host mount unit
	#     exists that could hold local-fs.target, and nothing on the host's boot
	#     path waits for the guest disk;
	#   - cogworx-supervisor merely Wants= cogworx-guest-disk (never Requires=),
	#     and that unit carries an explicit finite TimeoutStartSec, so a refusal
	#     or a wedged probe LANDS IN `systemctl --failed` instead of parking a
	#     job in `activating`;
	#   - sshd, the control CA and the state disk are all upstream of every one
	#     of those, so `ssh <vm> cogbox <verb>` answers on exactly the boots
	#     where the guest does not come up.
	#
	# A guest that will not launch is an acceptable outcome; an unreachable VM is
	# not. gce-image-hosted-guest-profile asserts each of those three legs.
	#
	# The device list below survives the chooser it used to feed. It is handed to
	# the supervisor as COGWORX_GUEST_VOLUMES so supervise.sh can name the
	# missing volume on serial before it tries to launch -- a classified line the
	# control plane's Backend.Log reads -- instead of the generic "sandbox start
	# failed" a failed QEMU drive open produces. The paths are READ OFF the
	# hosted guest configuration rather than re-spelled here, so they cannot
	# drift from the volumes the runner actually declares.
	hostedGuestVolumeDevices = map (v: v.image) (lib.filter (v: !v.autoCreate)
		self.nixosConfigurations."cogbox-${lib.head (lib.splitString "-" system)}-hosted"
			.config.microvm.volumes);

	# cogbox, re-wrapped so that a NON-INTERACTIVE `ssh <vm> cogbox <verb>`
	# carries the three path variables. This is not a nicety: `ssh host cmd`
	# runs a non-login, non-interactive shell, which sources neither
	# /etc/profile nor ~/.bashrc, so environment.variables and
	# programs.bash.loginShellInit both miss it -- and cogbox with no
	# XDG_CONFIG_HOME/COGBOX_DATA exits 66 on every verb. Wrapping the binary
	# makes the environment a property of the program instead of a property of
	# the login path, so it holds for the supervisor, for a control-channel
	# exec, and for a serial break-glass session alike.
	#
	# --set vs --set-default is a per-variable decision. NixOS gives sshd
	# `security.pam.services.sshd.startSession = true` whenever UsePAM
	# (nixpkgs nixos/modules/services/networking/ssh/sshd.nix), so pam_systemd
	# opens a session for every `ssh <vm> cogbox <verb>` and exports
	# XDG_RUNTIME_DIR=/run/user/0 into it before the wrapper ever runs -- and
	# makeWrapper's --set-default emits `export VAR=${VAR-'...'}`, which cannot
	# override an already-set variable. cogbox then resolved its runtime base
	# from /run/user/0 and looked for /run/user/0/cogbox-<name>/pid while the
	# supervisor's runtime lives under /run/cogbox (supervisor.nix's
	# XDG_RUNTIME_DIR + RuntimeDirectory=cogbox, supervise.sh leg e). Against a
	# HEALTHY sandbox that took out the whole control-verb surface: `cogbox
	# status` answered 3 (stopped) rather than 64 (unknown instance), so
	# Terminal and Console reported "instance is not running", the liveness
	# probe demoted the instance to degraded, and every rule / secret / plugin
	# mutation refused behind that. So, one line of reasoning per name:
	#
	#   XDG_RUNTIME_DIR  --set. PAM owns this name and always sets it, so a
	#                    default is a no-op on exactly the path this wrapper
	#                    exists for. It is also not an operator knob: it must
	#                    agree with the supervisor unit or the two halves
	#                    address different sandboxes.
	#   XDG_CONFIG_HOME  --set-default. Nothing in an ssh session sets it --
	#                    pam_systemd exports only XDG_RUNTIME_DIR, XDG_SESSION_*,
	#                    XDG_SEAT and XDG_VTNR, and this image's
	#                    environment.sessionVariables (the pam_env source)
	#                    carries XDG_CONFIG_DIRS but no XDG_CONFIG_HOME. The
	#                    the failure is visible in-band: status exits 3,
	#                    not 64, so the instance WAS found and its config read.
	#                    Leaving it a default keeps a break-glass operator able
	#                    to point cogbox at another state tree.
	#   COGBOX_DATA      --set-default, same reasoning and more strongly: the
	#                    name is cogbox-private, so no PAM module, no unit and
	#                    no login path knows it exists to set it.
	#   COGBOX_PROXY_RUNAS  --set-default, and it is here for a REASON, not for
	#                    symmetry. This image runs the L7 proxy on its own uid
	#                    (the floor's `meta skuid` selector needs it), so that
	#                    uid is not the one that owns the 0600 secret store --
	#                    and the inject render is what has to grant it read on
	#                    the cred files it names (zig/src/rules/credgrant.zig).
	#                    Binds are RUNTIME events on the control channel (`cogbox
	#                    secret add -n <inst>` + `secret reload`), which is
	#                    exactly the non-interactive `ssh <vm> cogbox ...` path
	#                    that carries no unit Environment=. Without this the
	#                    boot render would grant and every later bind would not,
	#                    so a Claude connect on a running sandbox stayed dead
	#                    until a restart. Default rather than forced for the same
	#                    reason as the other two: a break-glass operator may need
	#                    to run the proxies undropped.
	#
	# The supervisor unit's own Environment= sets all four to these same
	# values, so forcing XDG_RUNTIME_DIR changes nothing there.
	# gce-cogbox-wrapper-env asserts both directions against the real wrapper,
	# and asserts this one agrees with the unit (a divergence would mean the boot
	# render and the bind render grant to different groups).
	#
	# It wraps packages.cogbox-hosted DIRECTLY -- no chooser, no indirection --
	# and that package is the only cogbox this image contains. Read the two names
	# carefully, because they are unrelated and nearly identical: this
	# derivation's `cogboxHosted` has always meant "cogbox as HOSTED ON this GCE
	# machine" (the wrapper), while `cogbox-hosted` is the package whose baked
	# guest runner uses the HOSTED STORAGE PROFILE -- work/, machine-state and the
	# harness overlay uppers on one dedicated block volume the host never mounts,
	# instead of the workstation layout's RAM-backed machine-state.
	#
	# A second PACKAGE (rather than an option) is still required, and that is
	# unchanged by dropping the chooser: mkGceHost's extraModules configure THIS
	# system, while the guest closure is baked inside packages.cogbox* (mkCogbox
	# substitutes the runner's store path into cogbox-launch.sh), so a host module
	# cannot reach the guest config at all. Hence a second nixosConfiguration and
	# a second package -- exactly one of which ships in this image.
	# gce-image-hosted-guest-profile asserts every leg of it.
	cogboxHosted = pkgs.runCommand "cogbox-gce" {
		nativeBuildInputs = [ pkgs.makeWrapper ];
		meta = { mainProgram = "cogbox"; };
	} ''
		mkdir -p $out/bin
		makeWrapper ${self.packages.${system}.cogbox-hosted}/bin/cogbox $out/bin/cogbox \
			--set-default XDG_CONFIG_HOME ${cfg.stateDir}/config \
			--set-default COGBOX_DATA ${cfg.stateDir}/data/cogbox \
			--set-default COGBOX_PROXY_RUNAS ${cfg.proxyUser}:${cfg.proxyUser} \
			--set XDG_RUNTIME_DIR /run/cogbox
		ln -s cogbox $out/bin/cbx
	'';
in
{
	imports = [
		./state-disk.nix
		./guest-disk.nix
		./scrub.nix
		./floor.nix
		./supervisor.nix
		./nix-gc.nix
		./resolver-deadline.nix
	];

	options.cogworx.gce = {
		stateDir = lib.mkOption {
			type = lib.types.path;
			default = "/var/lib/cogbox-state";
			description = "Mount point of the per-instance state disk. Every cogbox path variable is derived from it.";
		};
		stateDevice = lib.mkOption {
			type = lib.types.str;
			default = "/dev/disk/by-id/google-cogworx-state";
			description = ''
				The attached state disk, resolved through its FIXED provider
				deviceName. `cogworx-state` is a cross-repo wire contract with
				the control plane's `stateDiskDevice` constant, not a
				provider-assigned value: the guest can only find the disk if
				both halves spell it the same way.
			'';
		};
		guestDevice = lib.mkOption {
			type = lib.types.str;
			default = "/dev/disk/by-id/google-cogworx-guest";
			description = ''
				The ONE dedicated per-instance guest disk -- the user's work
				tree, tool caches and guest journal, plus the guest's writable
				/nix/store overlay -- resolved through its FIXED provider
				deviceName, exactly as stateDevice is. `cogworx-guest` is the
				same shape of cross-repo wire contract with the control plane's
				`guestDiskDevice` constant.

				This host puts an LVM volume group on it, carves the two
				logical volumes the guest needs, keeps them grown to the disk,
				and lays a filesystem on each (guest-disk.nix). It NEVER MOUNTS
				a guest filesystem: the volumes carry the untrusted half's data
				and are passed straight through to QEMU as virtio-blk devices,
				which the guest mounts by label. An operator override here
				changes only where this host looks for the disk, never the
				volume-group, logical-volume or label names the guest looks for
				-- see guest-disk.nix.
			'';
		};
		storeOverlaySizeMiB = lib.mkOption {
			type = lib.types.int;
			default = 16384;
			description = ''
				Size, in MiB, of the logical volume carved out of the guest disk
				for the guest's writable /nix/store overlay. The data pool takes
				whatever is left, so this is the ONE number that divides the
				disk; raising it on an existing instance moves free space from
				the pool to the overlay on the next boot, and lowering it does
				nothing until the instance is recreated (guest-disk.nix never
				shrinks a volume).

				16 GiB matches the size the guest has always been TOLD it has
				(the "16G" every instance's config.json carried), so the hosted
				profile is not a quiet reduction of the ceiling a plugin install
				or brain rebuild fits inside today -- and unlike the tmpfs it
				replaces, 16 GiB here is deliverable rather than a number larger
				than the guest's whole RAM. It costs the pool 16 GiB of the
				provider disk outright, because a logical volume is not sparse;
				size the disk for both halves.

				It is a HOST option because the host is what carves the volume.
				The guest sets autoCreate = false on both volumes and therefore
				sizes neither, so there is deliberately no guest-side twin of
				this knob to drift out of step with it.
			'';
		};
		controlUser = lib.mkOption {
			type = lib.types.str;
			default = "root";
			description = ''
				The account cogworxd's control channel lands on, and the one
				uid exempted from floor rule 2 for the guest SSH forward.

				It is root, and the control plane's COGWORX_GCP_CONTROL_USER
				defaults to root for the same reason -- the two are one
				decision, not two defaults that happen to agree, and drift
				between them means no control connection can authenticate at
				all, because this image creates no other account and stages
				only /etc/ssh/cogworx-principals/root. Hot policy activation is
				delivered by `cogbox rules` /
				`cogbox l7` / `cogbox secret` SIGUSR1-ing passt and SIGHUP-ing
				the L7 proxy by pid; with dedicated drop uids those
				processes no longer share the caller's uid, and Linux permits
				a signal only from a privileged sender or a matching uid. A
				non-root control user would therefore leave every rule and
				secret edit silently un-activated until the next VM restart.
				The security boundary on this channel is the short-TTL,
				per-instance-principal certificate, not a uid inside a
				single-tenant trusted half -- the same trust statement
				`kubectl exec` into today's privileged sandbox pod makes.
			'';
		};
		passtUser = lib.mkOption {
			type = lib.types.str;
			default = "cogbox-passt";
			description = "Dedicated uid passt drops to (COGBOX_PASST_RUNAS); floor rule 1's skuid selector.";
		};
		proxyUser = lib.mkOption {
			type = lib.types.str;
			default = "cogbox-proxy";
			description = "Dedicated uid l7proxy and the mitmproxy terminate tier run under (COGBOX_PROXY_RUNAS).";
		};
		guestSSHPort = lib.mkOption {
			type = lib.types.port;
			default = 2222;
			description = "cogbox's default guest SSH forward port (cogbox-launch.sh `.sshPort // 2222`).";
		};
		guestSSHPortRange = lib.mkOption {
			type = lib.types.ints.positive;
			default = 16;
			description = ''
				Width of the guest SSH forward port range the floor's rule-2
				exception admits for the control uid. cogbox slides the
				forward port upward when the configured one is taken, so a
				single-port exception can silently break `cogbox ssh` (and
				with it Terminal) after a slide -- and the obvious remedy for
				a broken exception is to widen rule 2, which is exactly what
				the eight ExecStartPost probes exist to prevent. This mirrors
				the guest SSH forward port range.
			'';
		};
		guestHTTPPort = lib.mkOption {
			type = lib.types.port;
			default = 8080;
			description = "cogbox's default guest HTTP forward port (cogbox-launch.sh `.httpPort // 8080`).";
		};
		moshUDPPort = lib.mkOption {
			type = lib.types.port;
			default = (import ../mosh-udp-range.nix).port;
			description = ''
				First guest mosh UDP port passt forwards (`-u`, via
				COGBOX_MOSH_UDP_FORWARD). mosh-server binds a port in this
				range inside the guest; the cogworx gateway injects the same
				range into the exec, so the default comes from the repo's
				single source of truth (mosh-udp-range.nix).
			'';
		};
		moshUDPPortRange = lib.mkOption {
			type = lib.types.ints.positive;
			default = (import ../mosh-udp-range.nix).count;
			description = ''
				Width of the guest mosh UDP range (last port = moshUDPPort +
				moshUDPPortRange - 1). Mirrors cogworx's
				COGWORX_MOSH_SANDBOX_UDP_PORTS: a narrower forward than the
				range the gateway injects would leave sessions on the missing
				ports unreachable.
			'';
		};
		hostResolver = lib.mkOption {
			type = lib.types.str;
			default = "127.0.0.53";
			description = ''
				The LOOPBACK address of the VM's own DNS forwarder --
				systemd-resolved's stub listener, enabled below. passt re-emits
				the guest's intercepted queries here (`--dns-host`), resolved
				forwards them to `vpcResolver`, and the guest therefore resolves
				exactly what the host resolves, internal names included.

				This is a NAMING SEAM, not a tuning knob: 127.0.0.53 is where
				systemd-resolved's stub listens, and the value exists so the
				floor's rule-3 accept, the floor's probe, the passt forwarding
				target and the L4 shim's `dns-host` seed are ONE value rather
				than four literals that can drift apart. Pointing it at a socket
				resolved does not bind fails the BOOT rather than guest DNS: the
				floor unit's probe demands a completed connection to it.
			'';
		};
		hostResolverPort = lib.mkOption {
			type = lib.types.port;
			default = 53;
			description = "Port of the forwarder named by `hostResolver`. Same naming-seam reasoning; systemd-resolved's stub binds 53.";
		};
		vpcResolver = lib.mkOption {
			type = lib.types.str;
			default = "169.254.169.254";
			description = ''
				The full recursive resolver systemd-resolved uses for all names.
				The guest reaches it indirectly through the host-side forwarder.
				The default is GCE's VPC resolver.
			'';
		};
		allowMetadataResolver = lib.mkOption {
			type = lib.types.bool;
			default = false;
			description = ''
				Affirms that GCE's VPC/metadata resolver -- `vpcResolver`'s own
				default -- is the INTENDED upstream for a PUBLISHABLE image.

				It changes nothing at runtime. It exists because leaving the
				default in place and CHOOSING it are indistinguishable in the
				built image, and the difference is not small: the VPC resolver
				NXDOMAINs split-horizon internal names, and returns EMPTY
				answers for public names a peering zone shadows. A deployment
				that needs either kind of name must point `vpcResolver` at a
				full recursive resolver that serves both -- and because the
				guest resolves through the host's forwarder, a bake that misses
				that address leaves EVERY sandbox up and healthy resolving
				neither, with nothing failing loudly.

				That is exactly how the address gets lost: it comes from an
				operator-side module (the internal resolver's address is not in
				this tree), so a bake composed WITHOUT that module falls back to
				this default silently. Hence an affirmation rather than prose:
				the assertion below refuses a bake that sets
				`controlCAPublicKey` -- the publishability gate -- while
				`vpcResolver` still names the VPC resolver, unless this is true.
				It is an ACKNOWLEDGEMENT, not a ban: the link-local default is a
				supported configuration (see the DNS-upstream section of the
				README), and a deployment that genuinely wants it sets one
				boolean once.
			'';
		};
		l7PortBase = lib.mkOption {
			type = lib.types.port;
			default = 18443;
			description = "cogbox's default L7 loopback triple base; the floor's proxy-leg probe target.";
		};
		l7PortTriples = lib.mkOption {
			type = lib.types.ints.positive;
			default = 16;
			description = ''
				Number of contiguous L7 loopback TRIPLES the floor's rule-3
				funnel exception admits, counting from l7PortBase. Same reason
				guestSSHPortRange is a range and not a port: cogbox probes the
				triple at launch and slides upward by 3 when it is taken
				(`cogbox-launch.sh` next_free_l7_base), so a single-base
				exception would silently kill the L7 funnel after a slide -- and
				the obvious remedy for a dead funnel is to widen rule 3 to all of
				loopback, which is exactly what the rule exists to prevent.

				Only the FIRST TWO ports of each triple are admitted. The third
				is the mitmproxy SOCKS5 terminate hop, which l7proxy dials under
				the PROXY uid; admitting it to the passt uid would hand a guest
				the terminate tier's raw upstream with no vetting.
			'';
		};
		controlCAPublicKey = lib.mkOption {
			type = lib.types.str;
			default = "";
			description = ''
				The CONTROL CA public key, baked into the image as sshd's
				TrustedUserCAKeys. It must be baked and never delivered through
				instance metadata.
				Empty is fail-closed: sshd trusts no CA and no control
				connection can authenticate.
			'';
		};
		extraTrustedUserCAKeys = lib.mkOption {
			type = lib.types.listOf lib.types.str;
			default = [ ];
			description = ''
				ADDITIONAL user-CA public keys to trust, one key line per entry,
				appended to the same file `controlCAPublicKey` is written to.
				Entries are normalized and empty lines are dropped. Use
				`map builtins.readFile` when the keys come from files.
			'';
		};
		serialDevice = lib.mkOption {
			type = lib.types.str;
			default = "/dev/ttyS0";
			description = "Serial port 1, the channel Backend.Log reads. ONLY the supervisor's classified boot/lifecycle lines go here.";
		};
		cogboxPackage = lib.mkOption {
			type = lib.types.package;
			internal = true;
			description = "cogbox re-wrapped with the three path variables a non-interactive control exec needs. Read by supervisor.nix.";
		};
	};

	config = {
		cogworx.gce.cogboxPackage = cogboxHosted;

		# The hosted guest's autoCreate = false volume paths, handed to
		# supervise.sh so leg (e2) can say WHICH volume is missing before it tries
		# to launch. Without it the only symptom of an uncarved guest disk is
		# `cogbox start` failing to open a drive, which reaches serial as the
		# generic "sandbox start failed" -- true, useless, and indistinguishable
		# from half a dozen unrelated causes. With one baked runner there is
		# nothing to fall back TO, so naming the cause is the whole of the
		# recovery path an operator gets.
		#
		# Space-separated because supervise.sh iterates it with word splitting;
		# the paths are store-free device nodes with no spaces in them, and
		# gce-image-hosted-guest-profile asserts this env is exactly the volume
		# set the hosted runner declares.
		systemd.services.cogworx-supervisor.environment.COGWORX_GUEST_VOLUMES =
			lib.concatStringsSep " " hostedGuestVolumeDevices;

		# --- GCE metadata handling: absent, not merely unused ---------------
		#
		# `instances.setMetadata` is normally root-equivalent on GCE. The
		# lifecycle credential holds it, so this module makes the three things
		# it could reach inert rather than pretending the permission is
		# narrow. Two of the three are this module's business: startup-script
		# execution and ssh-keys/OS Login key management. (The third,
		# `serial-port-enable`, is an org-policy preflight item no image can
		# close.) The supervisor reads its own operational flags straight from
		# the metadata endpoint, so nothing here needs the guest agent.
		security.googleOsLogin.enable = lib.mkForce false;
		systemd.services.google-guest-agent.wantedBy = lib.mkForce [ ];
		systemd.services.google-startup-scripts.wantedBy = lib.mkForce [ ];
		systemd.services.google-shutdown-scripts.wantedBy = lib.mkForce [ ];

		# --- The cogbox host half ------------------------------------------
		#
		# Dragging in the cogbox package drags in the microvm runner, the guest
		# kernel/initrd/toplevel, closure-info, ${self}, ${nixpkgs} and the
		# mkCogbox PATH prefix -- INCLUDING passt-cc, the EXTRA_SYSCALLS=rt_sigreturn
		# build without which SIGUSR1 hot reload dies inside passt's seccomp
		# sandbox. Do NOT add a system-wide pkgs.passt: it would shadow it.
		#
		# pkgs.git is NOT dead weight and NOT a developer convenience -- do not
		# prune it while trimming boot-disk closure. Nothing in this image
		# REFERENCES it, because its caller is nix at runtime: nix's
		# git+http(s)/ssh flake fetcher execs the `git` CLI off PATH, so without
		# it every `cogbox plugin add git+http://git.example.com/...` dies at
		# resolve time with
		#     error: could not resolve flake 'git+http://.../plugin.git?ref=master':
		#     error: executing "git": No such file or directory
		# Without it, every curated catalog entry fails because each is a git+
		# URL. The same requirement is documented in the pod image's contents
		# list (flake.nix, cogbox-pod-image).
		# Two paths need it, not one: the host-half plugin add/update over the
		# control channel, and the ephemeral resolver VM, whose entire
		# job is `cogbox plugin resolve` of a git+ URL.
		#
		# The pod image pairs git with pkgs.cacert + SSL_CERT_FILE for the
		# https variant's TLS trust; here that half is discharged by NixOS
		# itself -- security.pki writes /etc/ssl/certs/ca-certificates.crt,
		# which is where git's curl looks, so no package is needed. That makes
		# it invisible, hence assert-worthy: do not mkForce environment.etc or
		# strip security.pki, or `git+https://` starts failing with a
		# certificate error instead of a missing binary. An internal git host
		# behind a private CA needs security.pki.certificateFiles at bake time.
		#
		# gce-image-flake-fetch asserts both halves against the realized system.
		environment.systemPackages = [ cogboxHosted pkgs.git ];

		# The launcher's re-exec evaluates the VM
		# config (cogbox-launch.sh's `nix run ... __launch` path), which forces
		# every flake INPUT SOURCE TREE. A non-resident input aborts the eval
		# and silently drops the whole guest half on a VM with no egress
		# guarantee at boot.
		#
		# google-compute-image.nix does not thread `additionalPaths` through to
		# make-disk-image.nix, so system.extraDependencies is the only route
		# into the image's REGISTERED store (it lands in `basePaths`, and from
		# there in the closureInfo the image loads with `nix-store --load-db`).
		# gce-image-offline-closure asserts each of these at build time.
		system.extraDependencies = [
			inputs.microvm
			inputs.llm-agents
			inputs.nix-mcp
			inputs.illustris-lib
		];

		# The launcher shells out to `nix run`/`nix build` for the per-instance
		# runner, so the host half needs the same experimental features the
		# guest config sets.
		#
		# Both substituters are SIGNED and their keys are pinned here:
		# require-sigs stays at the NixOS default (true) and no unsigned
		# substituter is configured. In-VM plugin builds process
		# attacker-controlled flakes, so an unsigned cache would be a
		# cross-instance code-injection path, not a convenience. numtide is
		# where the harness closures are published; without it a plugin add
		# that touches one would source-build inside the sandbox VM.
		# gce-image-nix-conf asserts all of this against the realized
		# /etc/nix/nix.conf.
		nix.settings = {
			experimental-features = [ "nix-command" "flakes" ];
			substituters = [ "https://cache.nixos.org" "https://cache.numtide.com" ];
			trusted-public-keys = [
				"cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
				"niks3.numtide.com-1:DTx8wZduET09hRmMtKdQDxNNthLQETkc/yaX7M4qK0g="
			];
		};

		# --- Enforcement uids ----------------------------------------------
		#
		# passt's default drop is to the ambient `nobody`, which is not a
		# usable nftables selector: it cannot distinguish guest-originated
		# traffic from anything else on the box that also happens to be
		# nobody. Dedicated named uids are what make floor rules 1 and 2
		# expressible at all, which is why they are created here even though
		# nothing in the image runs as them until cogbox-launch.sh drops to
		# them via COGBOX_PASST_RUNAS / COGBOX_PROXY_RUNAS.
		users.groups.${cfg.passtUser} = { };
		users.groups.${cfg.proxyUser} = { };
		users.users.${cfg.passtUser} = {
			isSystemUser = true;
			group = cfg.passtUser;
			description = "passt (guest network path) drop target";
		};
		users.users.${cfg.proxyUser} = {
			isSystemUser = true;
			group = cfg.proxyUser;
			home = "/var/empty";
			description = "l7proxy and the mitmproxy terminate tier drop target";
		};

		# --- The metadata server is PINNED, not resolved -------------------
		#
		# Every leg of the boot and control path addresses the metadata server
		# by NAME: the supervisor's readiness guest-attribute write and its
		# cogworx-instance read (supervisor.nix), the control-cert principal
		# fetch below, the floor's first-boot self-address fallback (floor.nix),
		# the stale-attribute scrub (scrub.nix), the resolver self-destruct belt
		# (resolver-deadline.nix), supervise.sh's MD base -- and, not ours,
		# google-compute-config.nix's networking.timeServers. All of them go
		# through getaddrinfo, and the only resolver they can reach is the ONE
		# upstream `vpcResolver` names, which `Domains = [ "~." ]` below makes
		# authoritative for every name with an EMPTY FallbackDNS behind it.
		#
		# So without this pin the reachability of the metadata server is a
		# property of the DNS upstream, and an upstream that does not happen to
		# serve metadata.google.internal takes out host-key bootstrap, readiness
		# reporting, the control-cert principal, the floor's first-boot fallback
		# and the scrub at once: those VMs wedge in Booting with a name-lookup
		# error as the only clue. That is not hypothetical -- it is what a SITE
		# recursive resolver does (`vpcResolver`'s second case), because the
		# name is GCE-internal and only the VPC resolver serves it.
		#
		# And wedging is the BENIGN half. The legs above fail closed: an instance
		# that cannot publish readiness never reaches Running. The resolver
		# self-destruct belt (resolver-deadline.nix) is the leg that does not --
		# an unresolvable metadata name is a failed metadata read, and that unit
		# has to decide from a failed read whether this is even a resolver boot.
		# Guess "no" and it exits 0, which RemainAfterExit=true latches for the
		# rest of the boot, so the deadline never arms on a VM whose whole
		# containment argument is that it goes away while it evaluates
		# attacker-controlled flakes. That unit now discriminates unreachable
		# from absent for exactly this reason, but a resolver-independent
		# metadata name is what keeps the question from arising at all.
		#
		# 169.254.169.254 is a documented, stable GCE constant -- the same one
		# floor rule 1 denies the guest wholesale -- so pinning it takes the
		# whole boot/control path off DNS ENTIRELY. Neither resolver availability
		# nor upstream configuration can then block metadata access, and
		# is why the pin is UNCONDITIONAL rather than gated on which resolver is
		# configured.
		#
		# Deliberately DUPLICATED: google-compute-config.nix already ships this
		# same mapping through networking.extraHosts. Inheriting a boot-critical
		# invariant from another module's default is how it silently disappears
		# in a nixpkgs bump, and two identical /etc/hosts lines are inert.
		#
		# TWO consumers have to honour it, and only the second one carries a
		# running system:
		#   - nss `files`. This image's order is
		#     `hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns`
		#     (nixpkgs' resolved module), so `files` is reached only when
		#     resolved is UNAVAIL -- i.e. NOT running. Real, but it is the
		#     resolved-is-down case, not the normal one.
		#   - systemd-resolved itself, which reads /etc/hosts (ReadEtcHosts,
		#     default yes) and answers from it BEFORE opening any upstream
		#     transaction. This is the leg that holds on a healthy VM, so a
		#     ReadEtcHosts=no would silently undo the pin while /etc/hosts still
		#     looked right.
		# gce-image-metadata-pin asserts the realized /etc/hosts and refuses a
		# resolved that has been told to ignore it.
		networking.hosts."169.254.169.254" = [ "metadata.google.internal" "metadata" ];

		# --- The VM's own DNS forwarder (guest/host resolution parity) -----
		#
		# A cogbox guest must resolve names the way the host does. The default
		# upstream is link-local, while floor rule 1 denies the passt uid the
		# whole link-local range. Passt therefore forwards through a host-side
		# resolver rather than exposing the upstream directly.
		#
		# Run the forwarder on the host
		# half, bound to LOOPBACK, as ROOT. passt's re-emitted query then goes to
		# 127.0.0.53:53 instead of the upstream; the forwarder -- a different
		# process under a uid rule 1 does not name -- is what talks to
		# `vpcResolver`. So rule 1 is untouched and the guest still cannot reach
		# any link-local address on any port; the only new permission anywhere is
		# that the passt uid may reach ONE loopback socket, added to the port
		# allow-list rule 3 already carries for the L7 funnel.
		#
		# That shape is NOT contingent on the upstream being link-local. Routing
		# the hop through the host
		# forwarder is still the right one: it keeps the choice of upstream a
		# trusted-half decision, keeps guest DNS working on an instance whose own
		# network rules deny that address, and avoids handing every sandbox a
		# standing hole to an upstream resolver merely to resolve names.
		#
		# systemd-resolved is the forwarder because it is the stub this platform
		# already has, its listener address is a fixed well-known constant, and
		# enabling it is also what makes passt's advertisement work: passt reads
		# /etc/resolv.conf, finds a LOOPBACK nameserver there, and per its own
		# add_dns_resolv4() special case for "--dns-forward and --no-map-gw"
		# advertises the --dns-forward address to the guest in its place. NixOS
		# points /etc/resolv.conf at the stub whenever resolved is enabled, and
		# gce-image-guest-dns asserts that at build time.
		#
		# The upstream is PINNED rather than taken from DHCP. dhcpcd's DNS would
		# reach resolved only through a polkit/D-Bus path this hardened image
		# should not depend on for a security-relevant address, and the default's
		# address is a documented GCE constant. FallbackDNS is deliberately
		# EMPTY: a VM whose upstream is unreachable must fail to resolve, not
		# quietly resolve internal names somewhere public.
		services.resolved = {
			enable = true;
			settings.Resolve = {
				DNS = [ cfg.vpcResolver ];
				# `~.` makes the pinned upstream authoritative for every name,
				# so nothing falls through to another route.
				Domains = [ "~." ];
				# Explicitly EMPTY, not merely unset: unset leaves systemd's
				# compiled-in public resolver list in place. It is unreachable
				# today (resolved consults FallbackDNS only when no DNS= is
				# configured at all), so this is belt for the case where a later
				# edit empties DNS= -- at which point silently resolving through
				# a public resolver is the exact failure this whole change fixed.
				FallbackDNS = "";
				DNSSEC = false;
				DNSOverTLS = false;
				# No listeners on the network: this resolver exists for the
				# trusted half and for passt's loopback hop, nothing else.
				LLMNR = false;
				MulticastDNS = false;
				DNSStubListener = true;
			};
		};

		# --- Control channel -----------------------------------------------
		services.openssh.enable = true;
		# The VM's OWN host key lives on the STATE disk, not the root
		# filesystem. This placement is load-bearing rather than tidy: Stop and
		# a boot-disk swap replaces the root filesystem, and a host
		# key that lived there would be regenerated on the next boot.
		services.openssh.hostKeys = lib.mkForce [
			{
				path = "${cfg.stateDir}/sshd/ssh_host_ed25519_key";
				type = "ed25519";
			}
		];
		# Certificate-only. A bare public key must be refused, so there
		# is no authorized_keys path at all -- not an empty one, which an
		# operator or a compromised metadata write could later populate.
		services.openssh.authorizedKeysInHomedir = false;
		services.openssh.authorizedKeysFiles = lib.mkForce [ "none" ];
		services.openssh.settings = {
			PasswordAuthentication = lib.mkForce false;
			KbdInteractiveAuthentication = lib.mkForce false;
			PermitRootLogin = lib.mkForce "prohibit-password";
			# TrustedUserCAKeys names one file rather than a mergeable list.
			# Additional keys belong in extraTrustedUserCAKeys.
			TrustedUserCAKeys = lib.mkForce "/etc/ssh/cogworx-control-ca.pub";
			# cogworxd mints a cert whose principal is the INSTANCE ID, so a
			# cert issued for one instance cannot replay against another. sshd
			# only accepts such a cert when the principal is listed here; the
			# file is written at boot from instance metadata by
			# cogworx-control-principal.service below.
			#
			# "only this instance's id" is a statement about THIS file, and the
			# file is not the only source sshd will consult: AuthorizedPrincipals
			# COMMAND is additive, not an alternative -- OpenSSH tries it when the
			# file matched nothing (auth2-pubkey.c, `if (!found_principal &&
			# match_principals_command(...)`) -- so a composed profile setting one
			# ADDS principals rather than being bounded by this file. No profile
			# baked here sets it. This option is deliberately NOT forced, so a
			# profile defining the FILE conflicts loudly instead.
			AuthorizedPrincipalsFile = "/etc/ssh/cogworx-principals/%u";
			# BOUND THE UNAUTHENTICATED PHASE. Nothing here is set by default:
			# sshd_config carries no LoginGraceTime, so the compiled-in 120s
			# applies, and MaxStartups is likewise the compiled-in 10:30:100.
			#
			# A control login whose certificate is refused does not end there:
			# sshd goes on to any
			# AuthorizedKeysCommand a composed profile defined, and neither sshd
			# nor such a command's own HTTP client is required to carry a timeout.
			# The only bound is then this grace period, per attempt. Unauthenticated connection
			# slots are a SHARED, exhaustible resource (MaxStartups' first field is
			# 10), so stuck attempts can refuse new connections to the same sshd.
			# A 30-second grace period bounds that exposure while leaving room for
			# PAM and key-lookup commands.
			#
			# Not forced: a composed profile with a considered opinion
			# on the grace period should conflict LOUDLY here rather than be
			# silently overridden, which is the same lesson TrustedUserCAKeys
			# above had to learn the hard way.
			LoginGraceTime = 30;
		};
		# THE CONTROL CHANNEL'S PAM ACCOUNT PHASE MUST NOT DEPEND ON A NETWORK
		# SERVICE. sshd runs with UsePAM, so even a pure certificate login goes
		# through pam_acct_mgmt() -- and nixpkgs' account stack is where a
		# directory-backed module may be added by a composed profile
		# composed in at bake time. Those modules are not optional by default:
		# sssd's is `[default=bad success=ok user_unknown=ignore]` under
		# security.pam.services.sshd.sssdStrictAccess, and OS Login's is
		# `[success=ok ignore=ignore default=die]`. `default=bad`/`die` covers
		# PAM_AUTHINFO_UNAVAIL, which is what such a module returns when its
		# daemon or directory is unavailable. The control account therefore
		# cannot depend on a remote account service.
		#
		# So the control user's account phase is decided FIRST and LOCALLY.
		# pam_succeed_if matching on the PAM user NAME needs no NSS lookup and no
		# daemon; `sufficient` ends the account phase successfully right there,
		# for this one account.
		#
		# WHAT IT ACTUALLY EXEMPTS, stated exactly, because "the control channel"
		# is narrower than the truth: PAM's account phase cannot see which method
		# authenticated, so this is an exemption for the ACCOUNT, not for the
		# certificate. Any other way that same account can authenticate also lands
		# in the same exempted
		# account phase. And a directory that later wanted to DENY this account
		# would find its denial skipped: this rule ends the phase before the
		# directory module is consulted at all. Both are accepted here, because
		# the alternative is a control channel a remote directory can switch off,
		# but neither should be discovered later by someone reading only the
		# sentence above.
		#
		# Every other user is unaffected: they never match, so they traverse
		# whatever account modules the composed profile installs.
		#
		# The order is DERIVED from the other account rules rather than anchored
		# on one of them. An offset from pam_unix (what this did first) breaks
		# quietly the moment nixpkgs inserts rules ahead of pam_unix -- its order
		# rises, the offset follows it up, and a directory module that stayed put
		# is suddenly above the exemption. Taking the minimum over every OTHER
		# rule in the set cannot drift that way, and it reads the option set (not
		# the rendered file), so rules a composed profile has not enabled YET are
		# still counted. No recursion: nothing here reads this rule's own order.
		security.pam.services.sshd.rules.account.cogworx-control = {
			order = sshdAccountOrderFloor - 100;
			control = "sufficient";
			modulePath = "${pkgs.pam}/lib/security/pam_succeed_if.so";
			args = [ "quiet" "user" "=" cfg.controlUser ];
		};

		# ASSERTED IN THE MODULE, not only in a flake check, and that placement is
		# the point: `nix flake check` can only see the default host, while an
		# assertion also covers configurations built with extra modules.
		assertions = [
			{
				assertion = pamControl.enable
					&& pamControl.control == "sufficient"
					&& (sshdOtherAccountOrders == [ ] || pamControl.order < sshdAccountOrderFloor);
				message = lib.concatStringsSep "\n\n" [
					("cogworx.gce: the control user's PAM account exemption is no longer first-and-local in security.pam.services.sshd.rules.account (enable=${lib.boolToString pamControl.enable}, control=\"${pamControl.control}\", order=${toString pamControl.order}, lowest other order=${toString sshdAccountOrderFloor}).")
					("A directory-backed account module above it can refuse the control certificate whenever its daemon or directory is unavailable.")
				];
			}
			{
				# A PUBLISHABLE image must have CHOSEN its DNS upstream, and for
				# the same placement reason as the rule above: the address of a
				# full recursive resolver comes from an operator-side module, so
				# an assertion living in THAT module would disappear together
				# with the address it guards -- which is precisely the bake that
				# went out resolving neither internal nor shadowed public names.
				#
				# Gated on `controlCAPublicKey == ""` because that is already the
				# publishability gate (see the `warnings` entry below: a CA-less
				# image is fail-closed and cannot authenticate a control
				# connection, so it is not publishable). So this fires only on a
				# bake meant for publication, and the default `packages.gce-image`
				# output -- CA-less on purpose -- keeps evaluating.
				assertion = cfg.controlCAPublicKey == ""
					|| cfg.vpcResolver != declaredVpcResolver
					|| cfg.allowMetadataResolver;
				message = lib.concatStringsSep "\n\n" [
					("cogworx.gce: this image bakes a control CA -- it is meant to be PUBLISHED -- while its DNS upstream is still GCE's VPC/metadata resolver (cogworx.gce.vpcResolver = \"${cfg.vpcResolver}\").")
					("That resolver NXDOMAINs split-horizon internal names and returns EMPTY answers for public names a peering zone shadows, and the guest resolves through the host's forwarder, so every sandbox created from this image comes up healthy resolving neither -- with nothing failing loudly.")
					("Set cogworx.gce.vpcResolver to a full recursive resolver that serves both kinds of name, or set cogworx.gce.allowMetadataResolver = true to affirm that the VPC resolver is the intended upstream for this image.")
				];
			}
			{
				# The mosh forward range must fit in the UDP port space. supervisor.nix
				# renders COGBOX_MOSH_UDP_FORWARD = "${moshUDPPort}-${moshUDPPort +
				# moshUDPPortRange - 1}"; cogbox-launch.sh validates `lo <= hi <= 65535`
				# and dies 64 otherwise, so without this an out-of-range option pair
				# builds a fine image whose every sandbox launch loops on exit 64 at
				# VM boot -- visible only on the serial console. Catch it at eval.
				assertion = cfg.moshUDPPort + cfg.moshUDPPortRange - 1 <= 65535;
				message = "cogworx.gce.moshUDPPort + moshUDPPortRange - 1 must be <= 65535 (got ${toString cfg.moshUDPPort} + ${toString cfg.moshUDPPortRange} - 1 = ${toString (cfg.moshUDPPort + cfg.moshUDPPortRange - 1)}); cogbox-launch.sh would reject the rendered COGBOX_MOSH_UDP_FORWARD with exit 64 at every VM boot.";
			}
		];

		# One file, every trusted user CA: the baked control CA first, then
		# whatever a composed profile contributed. sshd walks the file line by
		# line, skipping blanks and `#` comments (`sshkey_in_file`, OpenSSH
		# authfile.c), so a multi-key file is the format's own shape rather than a
		# trick.
		#
		# NORMALIZED to one key per line rather than concatenated as given, because
		# the natural way to supply a contributed CA is to read a FILE -- and a
		# file's contents carry a trailing newline, which a naive `k + "\n"` turns
		# into a blank line, and a key list built from several files into a
		# ragged one. Splitting and dropping empties makes every entry -- a bare
		# key line, a key line with its newline, or several at once -- render the
		# same way. sshd would tolerate the blanks; the next reader of this file
		# should not have to know that.
		environment.etc."ssh/cogworx-control-ca.pub".text =
			lib.concatMapStrings (l: l + "\n")
				(lib.filter (l: l != "")
					(lib.concatMap (lib.splitString "\n")
						([ cfg.controlCAPublicKey ] ++ cfg.extraTrustedUserCAKeys)));

		# Warn only about the actionable fail-closed default.
		warnings = lib.optional (cfg.controlCAPublicKey == "")
			"cogworx.gce.controlCAPublicKey is empty: this image trusts no control CA and no control connection can authenticate. Set it at bake time.";

		# The cert principal is per-instance and therefore cannot be baked.
		# Fail closed: an absent metadata key leaves an EMPTY principals file,
		# which admits nothing, rather than a stale one from a previous
		# instance that would admit the wrong principal.
		systemd.services.cogworx-control-principal = {
			description = "Stage the control-channel certificate principal for sshd";
			wantedBy = [ "multi-user.target" ];
			before = [ "sshd.service" ];
			requiredBy = [ "sshd.service" ];
			after = [ "network-online.target" ];
			wants = [ "network-online.target" ];
			serviceConfig = {
				Type = "oneshot";
				RemainAfterExit = true;
				ExecStart = "${pkgs.writeShellApplication {
					name = "cogworx-control-principal";
					runtimeInputs = [ pkgs.curl pkgs.coreutils ];
					text = ''
						dir=/etc/ssh/cogworx-principals
						mkdir -p "$dir"
						chmod 0755 "$dir"
						principal=""
						if out=$(curl -fsS -H 'Metadata-Flavor: Google' --max-time 10 \
							"http://metadata.google.internal/computeMetadata/v1/instance/attributes/cogworx-ssh-principal" 2>/dev/null); then
							principal="$out"
						fi
						umask 022
						if [ -n "$principal" ]; then
							printf '%s\n' "$principal" > "$dir/${cfg.controlUser}"
							echo "cogworx-control-principal: staged principal for ${cfg.controlUser}"
						else
							: > "$dir/${cfg.controlUser}"
							echo "cogworx-control-principal: no cogworx-ssh-principal attribute; staged an EMPTY principals file (fail closed)" >&2
						fi
					'';
				}}/bin/cogworx-control-principal";
			};
		};

		# --- What is deliberately NOT here ---------------------------------
		#
		# No CoW/copy /nix machinery and no /etc/cogbox/base-reginfo: on this
		# backend the boot disk IS the store, there is no node-shared lower to
		# seed from, and the control plane's NixGCReconciler capability is
		# unsupported. In-VM store growth is bounded by nix-gc.nix instead.
		#
		# require-sigs is left at the NixOS default (enabled) and no unsigned
		# substituter is configured; gce-image-nix-conf turns that from
		# prose into a build-time assertion.
		#
		# boot.kernelParams already carries console=ttyS0 from
		# google-compute-config.nix, so Backend.Log has a channel for free.
		#
		# NOT DONE, and named rather than hidden: the guest's /nix/.rw-store is
		# a 16 GB tmpfs (`.storeOverlaySize`, cogbox-launch.sh) and nothing
		# here clamps it against the VM's real memory budget. cogbox exposes no
		# `init` flag for it, so the only
		# lever this image has is the control plane's host-headroom sizing
		# (COGWORX_GCP_HOST_HEADROOM_MB / _VCPU). Recorded as a residual.

		system.stateVersion = "25.11";
	};
}
