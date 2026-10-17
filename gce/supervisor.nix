# cogworx-supervisor.service -- the GCE transcription of the k8s sandbox pod
# entrypoint, plus cogworx-cogbox-log.service, the unit that exists purely so
# the cogbox runtime log CANNOT reach serial.
#
# The Requires= on both cogworx-attr-scrub.service and cogworx-floor.service is
# the shape that preserves the identity contract: the sandbox is never started and the
# unit reports failure" if either fails. `After=` alone would order the units
# and then start the sandbox anyway on a floor-failed boot -- and a full-mode
# guest on a floorless VM can reach the metadata API and FORGE the very guest
# trusted attributes, so an unverified floor must be unable to
# yield a Running sandbox.
#
# Serial classification. The earlier shape of this unit was
# StandardOutput=journal+console with leg (g) piping `tail -F cogbox.log` into
# the same stdout. On GCE `console` is ttyS0 -- the exact port Backend.Log reads
# through instances.getSerialPortOutput, a provider-retained channel readable
# under a coarser, separate grant from the control channel, and optionally
# exported to Cloud Logging. cogbox.log is not a boot log: cogbox-launch.sh
# redirects its whole process group there, so every backgrounded child inherits
# it -- passt, QEMU stderr, l7proxy with its per-request allow/deny decisions,
# and mitmdump running the credential-injection addon. That is the guest's full
# L7 request stream plus the injection addon's output. On k8s the same leg was
# safe because the pod log sits behind the same RBAC as exec; on GCE the
# channel's trust domain changed, so:
#
#   - this unit is journal-only on both streams;
#   - only classified boot/lifecycle lines reach serial, written explicitly by
#     supervise.sh's emit() helper, never by stream inheritance;
#   - the cogbox.log tail lives in its own journal-only unit below.
#
# The control plane deliberately does NOT compensate downstream with a scrubber
# in Backend.Log, because a scrubber over a provider-retained channel is a false
# sense of safety. That deferral is only legitimate because the source control
# is here, so do not reintroduce `journal+console` or a tail on this stdout.
{ config, lib, pkgs, ... }:
let
	cfg = config.cogworx.gce;
	# The readiness wire contract with the cogworx control plane. See the file.
	proto = import ./protocol.nix;

	supervise = pkgs.runCommand "cogworx-supervise" { } ''
		mkdir -p $out/bin
		install -m0755 ${./supervise.sh} $out/bin/cogworx-supervise
		install -m0755 ${./stop-supervisor.sh} $out/bin/cogworx-stop-supervisor
		patchShebangs $out/bin/cogworx-supervise
		patchShebangs $out/bin/cogworx-stop-supervisor
	'';

	# Level-held readiness: this covers the crash paths the poll loop cannot
	# (unit stop, failure past the restart limit, a killed supervisor). Without
	# it a dead sandbox coasts on a stamped attribute for the rest of the start
	# epoch, which is exactly what the kubelet's level-checked pod readiness
	# does not do. The boot proof is level-held the same way, for the same
	# reason. The two DELETEs run concurrently, so the post-stop leg stays one
	# ten-second bound inside GCE's shutdown window (docs/graceful-guest-shutdown.md);
	# both are best-effort, and `wait` with no operand always succeeds.
	stopPost = pkgs.writeShellApplication {
		name = "cogworx-supervisor-stop";
		runtimeInputs = [ pkgs.curl ];
		text = ''
			curl -fsS -o /dev/null -X DELETE -H 'Metadata-Flavor: Google' --max-time 10 \
				"http://metadata.google.internal/computeMetadata/v1/instance/guest-attributes/cogworx/ready" \
				2>/dev/null &
			curl -fsS -o /dev/null -X DELETE -H 'Metadata-Flavor: Google' --max-time 10 \
				"http://metadata.google.internal/computeMetadata/v1/instance/guest-attributes/cogworx/boot-proof" \
				2>/dev/null &
			wait
			echo "cogworx-supervisor: readiness and boot-proof attributes unpublished"
		'';
	};

	cogboxLog = pkgs.writeShellApplication {
		name = "cogworx-cogbox-log";
		runtimeInputs = [ pkgs.curl pkgs.coreutils ];
		text = ''
			inst=$(curl -fsS -H 'Metadata-Flavor: Google' --max-time 10 \
				"http://metadata.google.internal/computeMetadata/v1/instance/attributes/cogworx-instance" 2>/dev/null || true)
			if [ -z "$inst" ]; then
				echo "cogworx-cogbox-log: no cogworx-instance attribute; nothing to tail" >&2
				exit 0
			fi
			log="''${XDG_RUNTIME_DIR:-/run/cogbox}/cogbox-$inst/cogbox.log"
			# -F so the tail survives the file being created after this unit
			# starts and re-created across a sandbox restart.
			exec tail -n +1 -F "$log"
		'';
	};
in
{
	config = {
		systemd.services.cogworx-supervisor = {
			description = "cogworx sandbox supervisor";
			wantedBy = [ "multi-user.target" ];
			# Requires=, not merely After=. See the header.
			requires = [ "cogworx-attr-scrub.service" "cogworx-floor.service" ];
			after = [
				"cogworx-attr-scrub.service"
				"cogworx-floor.service"
				"network-online.target"
				# The VM host key leg (a2) reads the key sshd-keygen writes.
				"sshd.service"
				# passt reads /etc/resolv.conf at launch and must find the
				# resolved STUB there: that is what makes it advertise the
				# --dns-forward address to the guest instead of the host's real
				# resolver. NixOS points /etc/resolv.conf at a file resolved
				# creates, so before resolved is up the symlink dangles and passt
				# would fall back to advertising nothing at all.
				"systemd-resolved.service"
			];
			wants = [ "network-online.target" "sshd.service" "systemd-resolved.service" ];
			path = [
				cfg.cogboxPackage
				pkgs.curl
				pkgs.coreutils
				pkgs.util-linux
				pkgs.gawk
				pkgs.gnugrep
				pkgs.gnused
				pkgs.jq
				pkgs.bash
			];
			environment = {
				# Host-integration knobs. Both passt invocations (rules
				# AND full mode) pick these up; full mode is the one with no L4
				# filter at all, so the uid split is its only floor.
				COGBOX_PASST_RUNAS = cfg.passtUser;
				COGBOX_PROXY_RUNAS = "${cfg.proxyUser}:${cfg.proxyUser}";
				# Bind the guest forwards at .bindAddr (the VM's own address)
				# rather than every address. Opt-in in cogbox because the local
				# and k8s backends leave bindAddr at loopback and depend on the
				# forwards being reachable at the pod address.
				COGBOX_PASST_BIND_FORWARDS = "1";
				# mosh: also forward the guest's mosh UDP range. With
				# COGBOX_PASST_BIND_FORWARDS=1 passt renders `-u <VM_IP>/60000-60031`
				# (the -t forwards take the same prefix). The LD_PRELOAD shim reads
				# the SAME variable to exempt passt's inbound reply sockets for
				# this range from the rules-mode deny (docs/network-filtering.md),
				# so the forward and the exemption cannot drift apart. No floor
				# change: gce/floor.nix is OUTPUT-only and the reply sockets
				# target the cogworxd relay, which none of its rules name.
				COGBOX_MOSH_UDP_FORWARD = "${toString cfg.moshUDPPort}-${toString (cfg.moshUDPPort + cfg.moshUDPPortRange - 1)}";
				# The loopback socket passt re-emits the guest's intercepted DNS
				# queries to (`--dns-host`), which is also what supervise.sh
				# hands `cogbox init --dns-host` so the L4 shim admits that one
				# socket. Both consumers read THIS value, and gce/floor.nix
				# renders rule 3's accept and its probe from the same option, so
				# the four cannot name different sockets.
				COGBOX_HOST_RESOLVER = cfg.hostResolver;
				XDG_CONFIG_HOME = "${cfg.stateDir}/config";
				COGBOX_DATA = "${cfg.stateDir}/data/cogbox";
				XDG_RUNTIME_DIR = "/run/cogbox";
				COGWORX_STATE_DIR = cfg.stateDir;
					COGBOX_ENVIRONMENT = "cogworx";
				COGWORX_SERIAL = cfg.serialDevice;
				# The readiness protocol version and state format THIS image speaks
				# (gce/protocol.nix), which supervise.sh reports in cogworx/ready's
				# `bp=` tail and in cogworx/boot-proof. They travel inside the image
				# tarball, so no re-registration or setLabels call can change what a
				# booted image reports about itself: they are the content truth the
				# control plane checks the image's labels against.
				COGWORX_IMAGE_BOOT_PROOF = toString proto.bootProof;
				COGWORX_IMAGE_STATE_FORMAT = toString proto.stateFormat;
				HOME = "/root";
			};
			serviceConfig = {
				Type = "simple";
				ExecStart = "${supervise}/bin/cogworx-supervise";
				ExecStop = "${supervise}/bin/cogworx-stop-supervisor ${cfg.cogboxPackage}/bin/cogbox";
				ExecStopPost = "${stopPost}/bin/cogworx-supervisor-stop";
				# ExecStop owns the graceful window on a REQUESTED stop. Only AFTER
				# it returns (or times out) may systemd signal the remaining service
				# cgroup. KillSignal deliberately stays at its SIGTERM default: when
				# the main process exits nonzero on its own (supervise.sh leg (j),
				# an in-guest reboot included) systemd SKIPS ExecStop, and the
				# cgroup TERM permits signal handling. It also reaches QEMU and its
				# supporting processes, so the launcher's orderly attempt has no
				# guaranteed guest drain window. FinalKillSignal/SendSIGKILL defaults
				# (SIGKILL once TimeoutStopSec expires) remain the backstop.
				KillMode = "control-group";
				TimeoutStopFailureMode = "kill";
				TimeoutStopSec = "75s";
				Restart = "always";
				# FLAT, and deliberately so. The obvious way to stop a permanently
				# broken box that restarts without bound (the failure mode
				# behind gce/supervise.sh's init classification) is
				# RestartSteps= + RestartMaxDelaySec= here -- but systemd's restart
				# counter is NOT reset by a run that succeeded, and leg (j) of
				# supervise.sh exits 1 on EVERY ordinary sandbox exit, an in-guest
				# `reboot` included. Measured on systemd 257: after four one-second
				# runs the delay pins to the cap, and a subsequent 30 s healthy run
				# still restarts at the cap. So a unit-level backoff throttles the
				# NORMAL restart path -- a user who has rebooted inside their
				# sandbox eight times would wait five minutes for the ninth, with
				# nothing anywhere saying why. The backoff therefore lives in
				# supervise.sh, which can tell a failed boot from a finished one.
				RestartSec = 5;
				# HOST OOM POSTURE. Every process in this unit inherits the adj --
				# QEMU, passt, l7proxy, mitmdump, authproxy and supervise.sh itself
				# -- so on a host OOM the kernel takes an unprotected process first:
				# a nix-daemon builder, a control-session command, the log tail.
				# -900 and NOT -1000: at -1000 QEMU becomes unkillable, so a host
				# whose only large consumer is the guest would panic instead of
				# losing the guest. Among this unit's processes QEMU usually scores
				# highest once nothing else is left, but not always: guest RAM that
				# zram has swapped out stops counting toward its score, and mitmdump
				# buffers whole response bodies, so a helper can be picked first.
				# See the OOM-kill watch below for what then happens.
				#
				# The flip side: this unit's own `cogbox init` and `cogbox start` run
				# their nix evaluations and builds (the composition re-pin, the
				# runner build, a cold-store rebuild after an image Upgrade) as root
				# inside this cgroup, so they inherit -900 too. An OOM during one of
				# them takes the host's adj-0 services (resolved, logind, the
				# control sessions, the log tail) before the build. That is
				# transient -- those units restart -- and confined to the owner's own
				# VM. Demoting only the builds would need a change in the launcher:
				# `cogbox start` both builds and becomes QEMU's parent, so a choom
				# around it here would demote QEMU as well.
				#
				# OOMPolicy=continue is LOAD-BEARING for supervise.sh leg (j). Under
				# systemd's default (DefaultOOMPolicy=stop), a kernel OOM kill of
				# QEMU makes systemd stop the whole unit: it runs ExecStop
				# (cogworx-stop-supervisor creates the $STOPPING marker) and then
				# TERMs supervise.sh, usually while it sits in `sleep`. Leg (j) then
				# either never runs or classifies the death as a requested stop, and
				# the OOM kill -- the one death the inner-exit forensics exist for --
				# leaves no record. With `continue`, the launcher's `wait` returns,
				# its EXIT trap records stop-result `exited`, and supervise.sh's poll
				# takes leg (j) like any other inner exit; Restart=always still
				# re-runs it.
				#
				# The cost of `continue` is that systemd no longer reacts to ANY OOM
				# kill in the unit, and nothing else waits on the helpers (passt,
				# l7proxy, mitmdump, the auth proxy): the launcher waits only on
				# QEMU and `cogbox status` checks only QEMU. So supervise.sh watches
				# the kernel's oom_kill count in this unit's memory.events -- the
				# counter OOMPolicy itself acts on -- and takes leg (j) as `oom-kill`
				# when it rises. Every OOM kill in the unit once the sandbox has
				# started therefore still ends in a restart, and now leaves a record.
				# The guest drain is kept too, but by a different route: leg (j)'s
				# nonzero exit skips ExecStop (see KillSignal above), so when QEMU
				# is still alive (a helper was the victim) supervise.sh itself runs
				# the same bounded `cogbox stop` that ExecStop would, before leg (j),
				# without the $STOPPING marker. A drain that fails or times out is
				# only noted; the cgroup TERM after leg (j) is then the backstop, as
				# for any exit with a live QEMU.
				#
				# The sshd listener needs no unit change: OpenSSH's
				# LINUX_OOM_ADJUST sets its own oom_score_adj to -1000, and the
				# NixOS sshd unit is Restart=always. Session children reset to 0,
				# but they are tiny. Deliberately no MemoryMin/MemoryLow either: see
				# the zram block in gce/cogbox-host.nix.
				OOMScoreAdjust = -900;
				OOMPolicy = "continue";
				# journal, NOT journal+console. See the header.
				StandardOutput = "journal";
				StandardError = "journal";
				RuntimeDirectory = "cogbox";
				RuntimeDirectoryPreserve = "yes";
			};
			unitConfig = {
				# Keep retrying instead of allowing a systemd start limit to
				# silently stop the supervisor. This stays 0 even with the
				# script-side backoff: the INTERVAL between failed attempts may
				# grow, but a box that would eventually recover must never be
				# given up on -- the supervisor is the only thing that starts the
				# sandbox.
				StartLimitIntervalSec = 0;
			};
		};

		systemd.services.cogworx-cogbox-log = {
			description = "cogbox runtime log -> journal (never serial)";
			wantedBy = [ "multi-user.target" ];
			after = [ "cogworx-supervisor.service" ];
			bindsTo = [ "cogworx-supervisor.service" ];
			environment = {
				XDG_RUNTIME_DIR = "/run/cogbox";
			};
			serviceConfig = {
				Type = "simple";
				ExecStart = "${cogboxLog}/bin/cogworx-cogbox-log";
				Restart = "always";
				RestartSec = 5;
				StandardOutput = "journal";
				StandardError = "journal";
			};
		};
	};
}
