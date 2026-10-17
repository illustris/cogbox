# The readiness wire contract between this GCE host image and the cogworx
# control plane (readiness protocol v2, wire tag `bp=`). ONE source, read by
# two consumers:
#
#   - the flake lib (lib.gceBootProof, lib.gceStateFormat, lib.gceImageLabels),
#     which push-gce-image stamps onto the registered image as the labels
#     cogworx-boot-proof and cogworx-state-format. Labels are OPERATOR metadata:
#     the control plane reads them before a boot, and a re-registration or a
#     setLabels call can change them;
#   - gce/supervisor.nix, which bakes bootProof and stateFormat into the
#     supervisor unit's environment (COGWORX_IMAGE_BOOT_PROOF,
#     COGWORX_IMAGE_STATE_FORMAT). That copy lives in the host toplevel INSIDE
#     the image tarball, so it is the content truth: gce/supervise.sh reports it
#     in cogworx/ready's `bp=` tail and in cogworx/boot-proof, and the control
#     plane checks the labels against it after the boot.
#
# bootProof is the integer protocol version. Changing what an existing key of
# cogworx/ready or cogworx/boot-proof means needs a new key, or a bump here that
# keeps the old keys. The generic boot-error literal in supervise.sh's
# init_error_summary is frozen by the same contract.
#
# stateFormat MUST be bumped whenever any of stateFormatInputs changes:
# cogboxEnv is STATE_FORMAT in runtime/cogbox-env.py, and poolLayout is the
# guest data pool's layout -- a hand-maintained number nothing ties to the real
# layout, so bump it by hand when the layout changes. The control plane uses
# stateFormat to refuse a fallback to an older image after the newer one may
# already have converted a sandbox's data.
#
# stateFormatHistory is how the gce-state-format-pin check enforces the bump. It
# records every stateFormat with the inputs it was cut for, oldest first, and is
# APPEND-ONLY: never edit an existing entry. The check requires cogboxEnv to
# equal cogbox-env.py's STATE_FORMAT, the last entry to equal the current
# stateFormat and stateFormatInputs, and stateFormat to strictly increase along
# the list. So a changed input that comes with no newly appended entry fails, and
# so does an appended entry that reuses the old stateFormat. The check cannot
# see an existing entry edited in place to match a changed input; only the
# append-only rule stops that.
{
	bootProof = 1;
	stateFormat = 1;
	stateFormatInputs = {
		cogboxEnv = 1;
		poolLayout = 1;
	};
	stateFormatHistory = [
		{ stateFormat = 1; cogboxEnv = 1; poolLayout = 1; }
	];
}
