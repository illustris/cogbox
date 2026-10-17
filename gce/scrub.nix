# cogworx-attr-scrub.service -- delete the previous boot's readiness, host-key
# and boot-proof guest attributes, as early as the metadata endpoint is
# reachable. cogworx/boot-error is deliberately NOT in the list: it is cleared
# only by an init that ran and succeeded (gce/supervise.sh leg (b)).
#
# Two properties are the entire point of this unit, and both are easy to lose
# by "tidying" the dependency graph:
#
#   1. It is NOT ordered on and NOT gated by cogworx-floor.service. The case
#      the per-start nonce alone does not close is a guest-internal reboot or
#      a provider automatic restart WITHIN the same start epoch that lands on a
#      boot whose floor check fails: the previous boot's attribute still
#      carries the current epoch's nonce, so Status would read Running off a
#      floorless boot. A scrub sequenced after the floor check would never run
#      to remove it. Independence is what deletes it anyway.
#
#   2. It retries forever (Restart=on-failure with StartLimitIntervalSec=0). A
#      failed scrub is a PENDING scrub, not a terminal state: the supervisor
#      Requires= it, so until it lands nothing re-stamps readiness over
#      unscrubbed state, and the residual window is bounded by the retry
#      cadence rather than open-ended. A start limit would convert that bounded
#      window into a permanent one.
#
#      RestartMode=direct is what makes property 2 actually hold, and it is not
#      a tuning knob. Under the default RestartMode=normal a unit transits
#      through failed/inactive on its way into auto-restart, and systemd cancels
#      the start job of anything that Requires= + After= it. `direct`
#      transitions straight into activating, so the dependent start job stays
#      queued across retries.
#
# It runs on every boot class, maintenance and resolver boots included.
{ config, lib, pkgs, ... }:
{
	config = {
		systemd.services.cogworx-attr-scrub = {
			description = "Scrub stale cogworx readiness, host-key and boot-proof guest attributes";
			wantedBy = [ "multi-user.target" ];
			# network-online only; deliberately no relationship to
			# cogworx-floor.service (see the header).
			after = [ "network-online.target" ];
			wants = [ "network-online.target" ];
			unitConfig = {
				# Retry until success. See property 2 above.
				StartLimitIntervalSec = 0;
			};
			serviceConfig = {
				Type = "oneshot";
				RemainAfterExit = true;
				Restart = "on-failure";
				# See property 2 in the header: without this, ONE transient
				# failure cancels the supervisor's start job for the whole boot.
				RestartMode = "direct";
				RestartSec = 2;
				ExecStart = "${pkgs.writeShellApplication {
					name = "cogworx-attr-scrub";
					runtimeInputs = [ pkgs.curl pkgs.coreutils ];
					text = ''
						MD=http://metadata.google.internal/computeMetadata/v1
						GA="$MD/instance/guest-attributes"
						hdr='Metadata-Flavor: Google'

						# Reachability first, so "attribute absent" and
						# "endpoint down" are never confused: the second is a
						# retry, the first is success.
						if ! curl -fsS -o /dev/null -H "$hdr" --max-time 10 "$MD/instance/id"; then
							echo "cogworx-attr-scrub: metadata endpoint unreachable; will retry" >&2
							exit 1
						fi

						for key in cogworx/ready cogworx/vm-host-key cogworx/boot-proof; do
							curl -fsS -o /dev/null -X DELETE -H "$hdr" --max-time 10 "$GA/$key" || true
							if curl -fsS -o /dev/null -H "$hdr" --max-time 10 "$GA/$key"; then
								echo "cogworx-attr-scrub: $key still present after DELETE; will retry" >&2
								exit 1
							fi
						done
						echo "cogworx-attr-scrub: stale readiness, host-key and boot-proof attributes removed"
					'';
				}}/bin/cogworx-attr-scrub";
			};
		};
	};
}
