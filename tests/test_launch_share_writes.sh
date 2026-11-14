#!/usr/bin/env bash
# Behavioural test: cogbox-launch.sh never writes into the guest's data share
# through a name the guest made. Runs without a VM.
#
# The instance data dir (<data>/instances/<name>) is the guest's read-write 9p
# share (security_model=none), so every name below its root is the guest's,
# and a symlink, FIFO or device node there is a real one on the host, where the
# launcher runs as root on GCE, PVE, in the k8s pod and under sudo. The old
# launcher wrote that share with `mkdir -p`, shell redirects and `mv` without
# -T, all of which follow such a name. Each case plants one shape in the share,
# as a guest of an earlier run would have left it, with an `outside` tree beside
# it standing in for the host paths it aims at, then runs an init pass and/or a
# daemon pass of the real launcher (`--network none`, a fake runner, stub
# nix/nix-store/cogbox/dumpe2fs, `date` and `mv` shims) and checks:
#
#   - on a fresh share the launcher's files keep the bytes and names the old
#     writes gave them, mode 0644, with no temp file beside them, and it boots;
#   - a symlink at any file it writes (.config/active-harnesses, overlay-size,
#     store-overlay-size, authorized_keys, environment.json), to a host file, a
#     dangling path or a host directory, is replaced, never written through or
#     moved into; a FIFO there is replaced without being opened, so no pass
#     wedges;
#   - a .config that is a symlink (to a host directory, or dangling) is left as
#     the guest made it, nothing is created, written or removed below its
#     target, and the daemon pass's warning lands in the cogbox.log it reopens
#     after winning the lifetime lock, not before;
#   - a real directory at a file's name fails that file's rename, leaves no
#     temp file, warns, and costs neither pass the boot; so does a rename that
#     fails outright;
#   - the legacy claude-overlay.img rename and the machine-state.img aside
#     rename replace a link at their destination instead of moving into it, and
#     a machine-state.img that is not a regular file is renamed aside before the
#     runner can create or open the pool through it;
#   - while the instance runs (its lifetime lock held) neither an init pass nor
#     a daemon pass rewrites .config, and once it stops a daemon pass does.
#
# Every pass runs with HOME and every XDG dir under the test's own temp dir, so
# it never reaches a real cogbox setup, even outside a nix build.
#
# Usage: test_launch_share_writes.sh <path-to-cogbox-launch.sh> <path-to-cogbox-shutdown.sh>
# Needs: bash, jq, coreutils, findutils, sed, util-linux (flock). NOT
# passt/qemu/nix/e2fsprogs: the runner is fake and the rest are stubs.

set -uo pipefail
export LC_ALL=C

LAUNCH="${1:?usage: test_launch_share_writes.sh <cogbox-launch.sh> <cogbox-shutdown.sh>}"
[ -f "$LAUNCH" ] || { echo "FAIL: no such script: $LAUNCH" >&2; exit 1; }
SHUTDOWN="${2:?usage: test_launch_share_writes.sh <cogbox-launch.sh> <cogbox-shutdown.sh>}"
[ -f "$SHUTDOWN" ] || { echo "FAIL: no such script: $SHUTDOWN" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

fails=0
ok()   { echo "ok   - $*"; }
bad()  { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

# --- fixture ----------------------------------------------------------------
# Resolved, not `#!/usr/bin/env bash`: this test runs inside a nix build
# sandbox, which has no /usr/bin/env.
BASH_BIN=$(command -v bash)
bin="$WORK/bin"
mkdir -p "$bin"
# No pass here may re-exec or build: any nix call is logged and fails.
{ echo "#!$BASH_BIN"; echo 'echo "nix $*" >> "$SW_MARK.calls"; exit 1'; } > "$bin/nix"
# The booted-runner gcroot.
{ echo "#!$BASH_BIN"; cat <<'STUB_EOF'
link="" path=""
while [ $# -gt 0 ]; do
	case "$1" in
		--add-root) link=$2; shift 2 ;;
		--realise|-r) shift ;;
		*) path=$1; shift ;;
	esac
done
[ -e "$path" ] || exit 1
[ -z "$link" ] || ln -sfn "$path" "$link"
STUB_EOF
} > "$bin/nix-store"
{ echo "#!$BASH_BIN"; echo 'exit 0'; } > "$bin/cogbox"
# Every regular machine-state.img reads as having no ext4 superblock.
{ echo "#!$BASH_BIN"; echo 'exit 1'; } > "$bin/dumpe2fs"
# `date -u +%Y%m%d%H%M%S` (the machine-state aside's stamp) prints SW_DATE when
# it is set, so a case can plant a link at the name the aside will take.
{ echo "#!$BASH_BIN"; cat <<'SHIM_EOF'
if [ -n "${SW_DATE:-}" ] && [ "$#" = 2 ] && [ "$1" = -u ] && [ "$2" = +%Y%m%d%H%M%S ]; then
	echo "$SW_DATE"
	exit 0
fi
exec REALDATE "$@"
SHIM_EOF
} | sed "s|REALDATE|$(command -v date)|" > "$bin/date"
# An `mv` whose destination's basename is SW_MV_FAIL fails: a publish rename
# the disk refuses.
{ echo "#!$BASH_BIN"; cat <<'SHIM_EOF'
dst="${*: -1}"
if [ -n "${SW_MV_FAIL:-}" ] && [ "${dst##*/}" = "$SW_MV_FAIL" ]; then
	echo "mv: cannot move to '$dst': Input/output error" >&2
	exit 1
fi
exec REALMV "$@"
SHIM_EOF
} | sed "s|REALMV|$(command -v mv)|" > "$bin/mv"
chmod +x "$bin"/*

# The fake runner: "QEMU" records that it booted, and whether the pool image
# name it would create or open is anything but a regular file. Its cwd is the
# runtime dir, where data/ is the instance's share.
runner="$WORK/runner"
mkdir -p "$runner/bin"
{ echo "#!$BASH_BIN"; cat <<'RUNNER_EOF'
echo booted >> "$SW_MARK"
if [ -L data/machine-state.img ] || { [ -e data/machine-state.img ] && [ ! -f data/machine-state.img ]; }; then
	echo machine-state-not-a-file >> "$SW_MARK"
fi
exit 0
RUNNER_EOF
} > "$runner/bin/microvm-run"
chmod +x "$runner/bin/microvm-run"

# The launcher with the build-time substitutions a package makes.
L="$WORK/launch.sh"
sed -e "1s|^#!/usr/bin/env bash\$|#!$BASH_BIN|" \
	-e "s|@flock@|$(command -v flock)|g" \
	-e "s|@shutdown@|$SHUTDOWN|g" \
	-e "s|@harnesses@||g" \
	-e "s|@cogbox@|$bin/cogbox|g" \
	-e "s|@runner@|$runner|g" \
	-e "s|@dumpe2fs@|$bin/dumpe2fs|g" \
	"$LAUNCH" > "$L"
chmod +x "$L"

# pass TAG init|daemon [VAR=val ...] [-- launcher args]: one launcher pass for
# instance "demo" with HOME and every XDG dir under $WORK/TAG, no ssh agent and
# no sudo context, bounded at 60 s. Prints its exit status (124: it hit the
# bound, recorded in $WORK/wedged); its output is $WORK/TAG.log, and a daemon
# pass's output after it reopens onto the runtime's cogbox.log is there.
pass() {
	local tag="$1" kind="$2" rc
	shift 2
	local mode=(--init-only --network none) envs=() extra=()
	if [ "$kind" = daemon ]; then
		mode=(--network none)
		envs=(COGBOX_SKIP_REPIN=1)
	fi
	while [ $# -gt 0 ]; do
		if [ "$1" = -- ]; then
			shift
			extra=("$@")
			break
		fi
		envs+=("$1")
		shift
	done
	rm -f "$WORK/$tag.mark"
	env -u SSH_AUTH_SOCK -u SUDO_USER HOME="$WORK/$tag" COGBOX_DATA="$WORK/$tag/data" \
		XDG_CONFIG_HOME="$WORK/$tag/config" XDG_DATA_HOME="$WORK/$tag/xdgdata" \
		XDG_STATE_HOME="$WORK/$tag/state" XDG_RUNTIME_DIR="$WORK/$tag/run" \
		PATH="$bin:$PATH" SW_MARK="$WORK/$tag.mark" "${envs[@]}" \
		timeout -k 5 60 "$L" "${mode[@]}" --yes --name demo "${extra[@]}" > "$WORK/$tag.log" 2>&1
	rc=$?
	[ "$rc" != 124 ] || echo "$tag $kind" >> "$WORK/wedged"
	echo "$rc"
}
# The cogbox.log the last daemon pass of TAG reopened onto.
daemon_log() { printf '%s' "$WORK/$1/run/cogbox-demo/cogbox.log"; }
# Everything the last pass of TAG said. Always status 0: under pipefail,
# `said T | grep -q X` must be grep's verdict, not cat's.
said() { cat "$WORK/$1.log" "$(daemon_log "$1")" 2>/dev/null; return 0; }
booted() { grep -qx booted "$WORK/$1.mark" 2>/dev/null; }
set_cfg() { jq --tab "$1" "$icd/config.json" > "$icd/c.tmp" && mv "$icd/c.tmp" "$icd/config.json"; }
KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE3test test@example.com"
# fresh TAG: a new instance under $WORK/TAG. Its runtime dir comes first (with
# XDG_RUNTIME_DIR missing the launcher would use /tmp/cogbox-runtime-<uid>,
# outside $WORK); then a first init without cogbox's own key, so the guest's
# authorized_keys is exactly the one test key below; ports in 29400-29499. Sets
# sd (the share), icd (the instance config dir) and out (a host tree beside
# them, standing in for the rest of the host).
fresh() {
	local tag="$1" rc
	mkdir -p "$WORK/$tag" && mkdir -m 700 "$WORK/$tag/run" || bad "cannot make $WORK/$tag/run"
	rc=$(pass "$tag" init -- --no-auto-keys)
	[ "$rc" = 0 ] || bad "the first init of $tag exited $rc: $(tail -3 "$WORK/$tag.log" | tr '\n' '|')"
	icd="$WORK/$tag/config/cogbox/instances/demo"
	printf '%s\n' "$KEY" > "$WORK/$tag/config/cogbox/authorized_keys"
	set_cfg '.sshPort = 29401 | .httpPort = 29402 | .l7PortBase = 29410'
	sd="$WORK/$tag/data/instances/demo"
	out="$WORK/$tag/outside"
	mkdir -p "$out"
}
# holds <path> <bytes>: <path> reads exactly <bytes>. Only ever reached for a
# regular file: a FIFO would block it.
holds() { [ "$(cat -- "$1" 2>/dev/null; printf x)" = "$2"x ]; }
# staged <path> <bytes>: a regular file, not a link, mode 0644, holding <bytes>.
staged() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %a "$1")" = 644 ] && holds "$1" "$2"; }
# mirrored <path>: environment.json staged as a byte copy of the host record.
mirrored() { [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %a "$1")" = 644 ] && cmp -s "$1" "$icd/environment.json"; }
# listing <dir>: its entries, dot-names included, on one line.
listing() { (cd "$1" 2>/dev/null && ls -A | tr '\n' ' '); }
# tree <dir>: every entry below it, with its type and a link's target.
tree() { (cd "$1" 2>/dev/null && find . -mindepth 1 -printf '%y %p%l\n' | sort | tr '\n' '|'); }
AH=$'\n'
OS=$'128M\n'
AK="$KEY"$'\n'
STAMP=20261114000000

# --- a. a fresh share -------------------------------------------------------
# The bytes, names and mode the old writes produced (an empty harness list is
# one newline), nothing else beside them, and the boot. Then a configured
# storeOverlaySize is staged, and an unset one removes the file again.
fresh fresh
ri=$(pass fresh init)
rd=$(pass fresh daemon)
if [ "$ri$rd" = 00 ] && booted fresh \
	&& staged "$sd/.config/active-harnesses" "$AH" && staged "$sd/.config/overlay-size" "$OS" \
	&& staged "$sd/.config/authorized_keys" "$AK" \
	&& [ "$(listing "$sd/.config")" = "active-harnesses authorized_keys overlay-size " ] \
	&& [ "$(listing "$sd")" = ".app-launch .config environment.json " ] \
	&& mirrored "$sd/environment.json"; then
	ok "a fresh share gets the .config files and environment.json (exact bytes, 0644, no temp file left), and boots"
else
	bad "fresh share: rc=$ri/$rd booted=$(booted fresh && echo y || echo n) share: $(tree "$sd") said: $(said fresh | tail -3 | tr '\n' '|')"
fi
set_cfg '.storeOverlaySize = "1G"'
rd=$(pass fresh daemon)
if [ "$rd" = 0 ] && booted fresh && staged "$sd/.config/store-overlay-size" $'1G\n' \
	&& [ "$(listing "$sd/.config")" = "active-harnesses authorized_keys overlay-size store-overlay-size " ]; then
	ok "a configured storeOverlaySize is staged, and the pass boots"
else
	bad "storeOverlaySize set: rc=$rd booted=$(booted fresh && echo y || echo n) .config: $(tree "$sd/.config") said: $(said fresh | tail -3 | tr '\n' '|')"
fi
set_cfg 'del(.storeOverlaySize)'
rd=$(pass fresh daemon)
if [ "$rd" = 0 ] && booted fresh && [ ! -e "$sd/.config/store-overlay-size" ] && [ ! -L "$sd/.config/store-overlay-size" ]; then
	ok "an unset storeOverlaySize removes the file, and the pass boots"
else
	bad "storeOverlaySize unset: rc=$rd booted=$(booted fresh && echo y || echo n) .config: $(tree "$sd/.config") said: $(said fresh | tail -3 | tr '\n' '|')"
fi

# --- b. a symlink at each file ----------------------------------------------
# To an existing host file, which a redirect truncated and overwrote (root on
# GCE/PVE), or dangling (overlay-size), which a redirect created. Every target
# is untouched, nothing new appears beside them, and each name holds the
# staged file instead.
fresh link
printf 'sentinel-a\n' > "$out/a"
printf 'sentinel-k\n' > "$out/k"
printf 'sentinel-s\n' > "$out/s"
printf 'sentinel-e\n' > "$out/e"
rm -f "$sd/.config/active-harnesses" "$sd/environment.json"
ln -s "$out/a" "$sd/.config/active-harnesses"
ln -s "$out/created-by-root" "$sd/.config/overlay-size"
ln -s "$out/k" "$sd/.config/authorized_keys"
ln -s "$out/s" "$sd/.config/store-overlay-size"
ln -s "$out/e" "$sd/environment.json"
set_cfg '.storeOverlaySize = "1G"'
ri=$(pass link init)
rd=$(pass link daemon)
if holds "$out/a" $'sentinel-a\n' && holds "$out/k" $'sentinel-k\n' && holds "$out/s" $'sentinel-s\n' \
	&& holds "$out/e" $'sentinel-e\n' && [ "$(listing "$out")" = "a e k s " ] \
	&& staged "$sd/.config/active-harnesses" "$AH" && staged "$sd/.config/overlay-size" "$OS" \
	&& staged "$sd/.config/authorized_keys" "$AK" && staged "$sd/.config/store-overlay-size" $'1G\n' \
	&& mirrored "$sd/environment.json" && booted link; then
	ok "a symlink at any file (existing or dangling target) is replaced and never written through"
else
	bad "a symlink at a file: rc=$ri/$rd outside: $(tree "$out") [a=$(head -c 20 "$out/a") k=$(head -c 20 "$out/k") s=$(head -c 20 "$out/s") e=$(head -c 20 "$out/e")] share: $(tree "$sd")"
fi

# --- c. a FIFO at each file -------------------------------------------------
# A redirect blocked on it with no reader until the pass was killed. No pass
# opens it: neither hits the bound, and each name holds the staged file.
fresh fifo
rm -f "$sd/.config/active-harnesses" "$sd/environment.json"
for n in active-harnesses overlay-size authorized_keys store-overlay-size; do
	mkfifo "$sd/.config/$n"
done
mkfifo "$sd/environment.json"
set_cfg '.storeOverlaySize = "1G"'
ri=$(pass fifo init)
rd=$(pass fifo daemon)
if [ "$ri" != 124 ] && [ "$rd" != 124 ] \
	&& staged "$sd/.config/active-harnesses" "$AH" && staged "$sd/.config/overlay-size" "$OS" \
	&& staged "$sd/.config/authorized_keys" "$AK" && staged "$sd/.config/store-overlay-size" $'1G\n' \
	&& mirrored "$sd/environment.json" && booted fifo; then
	ok "a FIFO at any file is replaced without being opened, and no pass wedges"
else
	bad "a FIFO at a file: rc=$ri/$rd (124 = wedged until killed) share: $(tree "$sd")"
fi

# --- d. a symlink to a host DIRECTORY at a file -----------------------------
# A rename without -T moves the file INTO the directory: environment.json,
# overlay-size, and the legacy rename's harness-overlay.img (the guest's old
# claude-overlay.img would have moved into the host directory). Each directory
# stays empty, and the legacy image moves to its new name, bytes intact.
fresh dirlink
mkdir -p "$out/env" "$out/ovl" "$out/img"
rm -f "$sd/environment.json"
ln -s "$out/env" "$sd/environment.json"
ln -s "$out/ovl" "$sd/.config/overlay-size"
printf 'guest-bytes\n' > "$sd/claude-overlay.img"
ln -s "$out/img" "$sd/harness-overlay.img"
ri=$(pass dirlink init)
rd=$(pass dirlink daemon)
if [ -z "$(listing "$out/env")$(listing "$out/ovl")$(listing "$out/img")" ] \
	&& [ -f "$sd/harness-overlay.img" ] && [ ! -L "$sd/harness-overlay.img" ] \
	&& holds "$sd/harness-overlay.img" $'guest-bytes\n' \
	&& [ ! -e "$sd/claude-overlay.img" ] && [ ! -L "$sd/claude-overlay.img" ] \
	&& mirrored "$sd/environment.json" && staged "$sd/.config/overlay-size" "$OS" && booted dirlink; then
	ok "a symlink to a host directory at environment.json, overlay-size or the legacy rename's target receives nothing"
else
	bad "a directory link at a file: rc=$ri/$rd outside: $(tree "$out") share: $(tree "$sd")"
fi

# --- e. a symlink at .config ------------------------------------------------
# To a host directory holding a file at the store-overlay-size name, with no
# storeOverlaySize configured, so the old code removed it. Nothing is created,
# written or removed below the target, the link stays as the guest made it, the
# init pass says so, and the daemon pass says so in the cogbox.log it reopens
# after winning the lifetime lock -- not before it, in its own output -- and
# still boots. Locally and hosted.
for envset in local hosted; do
	tag="cfg-$envset"
	fresh "$tag"
	mkdir -p "$out/cfg"
	printf 'host-file\n' > "$out/cfg/store-overlay-size"
	rm -rf "$sd/.config"
	ln -s "$out/cfg" "$sd/.config"
	e=()
	[ "$envset" = local ] || e=(COGBOX_ENVIRONMENT=cogworx)
	ri=$(pass "$tag" init "${e[@]}")
	said_init=$(cat "$WORK/$tag.log")
	rd=$(pass "$tag" daemon "${e[@]}")
	refusal="$sd/.config is a symlink or not a directory; overlay-size, store-overlay-size and authorized_keys were not written"
	if [ "$ri$rd" = 00 ] && [ "$(listing "$out/cfg")" = "store-overlay-size " ] \
		&& holds "$out/cfg/store-overlay-size" $'host-file\n' \
		&& [ -L "$sd/.config" ] && [ "$(readlink "$sd/.config")" = "$out/cfg" ] \
		&& grep -qF "warning: $sd/.config is a symlink or not a directory; the active harnesses were not recorded" <<<"$said_init" \
		&& grep -qF "$refusal" "$(daemon_log "$tag")" && ! grep -qF "$refusal" "$WORK/$tag.log" \
		&& booted "$tag"; then
		ok "a symlinked .config ($envset) is left alone, nothing below its target changes, the daemon pass warns in cogbox.log, and it boots"
	else
		bad "a symlinked .config ($envset): rc=$ri/$rd outside: $(tree "$out/cfg") .config: $(readlink "$sd/.config"); init said: $(grep -i 'config' <<<"$said_init" | tr '\n' '|'); daemon output: $(grep -i 'config' "$WORK/$tag.log" | tr '\n' '|'); cogbox.log: $(grep -i 'config' "$(daemon_log "$tag")" 2>/dev/null | tr '\n' '|')"
	fi
done

# --- f. a dangling .config ---------------------------------------------------
# Nothing is made at its target (mkdir never follows a link), the link stays as
# the guest made it, and the boot goes on.
fresh dangle
rm -rf "$sd/.config"
ln -s "$out/made-by-root" "$sd/.config"
ri=$(pass dangle init)
rd=$(pass dangle daemon)
if [ "$ri$rd" = 00 ] && [ ! -e "$out/made-by-root" ] && [ ! -L "$out/made-by-root" ] \
	&& [ "$(readlink "$sd/.config")" = "$out/made-by-root" ] && booted dangle; then
	ok "a dangling .config makes nothing at its target, stays as it is, and the boot goes on"
else
	bad "a dangling .config: rc=$ri/$rd outside: $(tree "$out") .config: $(readlink "$sd/.config")"
fi

# --- g. a real DIRECTORY at a file ------------------------------------------
# A rename without -T moves the file INTO it. The rename fails instead: the
# directory stays empty, the temp file goes with it, the pass says which file,
# and the boot goes on -- for overlay-size (a daemon pass) and for
# environment.json (an init pass, then a daemon pass).
fresh dir
mkdir "$sd/.config/overlay-size"
rd=$(pass dir daemon)
if [ "$rd" = 0 ] && booted dir && [ -d "$sd/.config/overlay-size" ] && [ -z "$(listing "$sd/.config/overlay-size")" ] \
	&& [ "$(listing "$sd/.config")" = "active-harnesses authorized_keys overlay-size " ] \
	&& grep -qF "warning: could not write $sd/.config/overlay-size" "$(daemon_log dir)"; then
	ok "a directory at overlay-size fails its rename, leaves no temp file, says so in cogbox.log, and boots"
else
	bad "a directory at overlay-size: rc=$rd .config: $(tree "$sd/.config") said: $(said dir | grep -i overlay | tr '\n' '|')"
fi
fresh envdir
rm -f "$sd/environment.json"
mkdir "$sd/environment.json"
ri=$(pass envdir init)
said_init=$(cat "$WORK/envdir.log")
rd=$(pass envdir daemon)
if [ "$ri$rd" = 00 ] && [ -d "$sd/environment.json" ] && [ -z "$(listing "$sd/environment.json")" ] \
	&& [ "$(listing "$sd")" = ".app-launch .config environment.json " ] \
	&& grep -qF "warning: could not publish the guest environment context at $sd/environment.json" <<<"$said_init" \
	&& booted envdir; then
	ok "a directory at environment.json fails its rename, leaves no temp file, warns, and costs neither pass"
else
	bad "a directory at environment.json: rc=$ri/$rd share: $(tree "$sd") init said: $(grep -i environment <<<"$said_init" | tr '\n' '|')"
fi

# --- h. a publish rename that fails -----------------------------------------
# On a plain share, with the disk refusing the rename onto authorized_keys:
# no temp file outlives it, the pass names the file, and it boots.
fresh mvfail
rd=$(pass mvfail daemon SW_MV_FAIL=authorized_keys)
if [ "$rd" = 0 ] && booted mvfail && [ "$(listing "$sd/.config")" = "active-harnesses overlay-size " ] \
	&& grep -qF "warning: could not write $sd/.config/authorized_keys" "$(daemon_log mvfail)"; then
	ok "a failed publish rename leaves no temp file, names the file in cogbox.log, and boots"
else
	bad "a failed publish rename: rc=$rd .config: $(tree "$sd/.config") said: $(said mvfail | grep -i authorized | tr '\n' '|')"
fi

# --- i. the legacy rename, regression ---------------------------------------
# A plain claude-overlay.img with nothing at the new name still moves there,
# bytes intact.
fresh legacy
printf 'guest-bytes\n' > "$sd/claude-overlay.img"
ri=$(pass legacy init)
if [ "$ri" = 0 ] && [ -f "$sd/harness-overlay.img" ] && [ ! -L "$sd/harness-overlay.img" ] \
	&& holds "$sd/harness-overlay.img" $'guest-bytes\n' && [ ! -e "$sd/claude-overlay.img" ]; then
	ok "a plain claude-overlay.img is still renamed to harness-overlay.img"
else
	bad "the legacy rename: rc=$ri share: $(tree "$sd")"
fi

# --- j. the corrupt machine-state aside -------------------------------------
# A machine-state.img with no ext4 superblock is renamed to a name predictable
# to the second, machine-state.img.corrupt-<UTC stamp>, where the guest left a
# link to a host directory: a rename without -T moves the image INTO it. The
# link is replaced by the image instead, and the boot goes on.
fresh corrupt
mkdir -p "$out/ms"
printf 'garbage\n' > "$sd/machine-state.img"
ln -s "$out/ms" "$sd/machine-state.img.corrupt-$STAMP"
rd=$(pass corrupt daemon SW_DATE=$STAMP)
if [ "$rd" = 0 ] && booted corrupt && [ -z "$(listing "$out/ms")" ] \
	&& [ -f "$sd/machine-state.img.corrupt-$STAMP" ] && [ ! -L "$sd/machine-state.img.corrupt-$STAMP" ] \
	&& holds "$sd/machine-state.img.corrupt-$STAMP" $'garbage\n' \
	&& [ ! -e "$sd/machine-state.img" ] && [ ! -L "$sd/machine-state.img" ]; then
	ok "the corrupt machine-state aside replaces a link at its predictable name instead of moving into it"
else
	bad "the corrupt machine-state aside: rc=$rd outside: $(tree "$out") share: $(tree "$sd")"
fi

# --- k. a machine-state.img that is not a regular file ----------------------
# The runner creates the pool when the name does not exist (`[ ! -e ]`, which
# follows a link) and QEMU opens it: a dangling link would get the pool made at
# a host path the guest chose, and a link to a host file would be opened as the
# guest's disk. Each is renamed aside to machine-state.img.not-a-file-<stamp>,
# the link itself, before the runner sees the name; neither target is touched.
for kind in dangling victim; do
	tag="ms-$kind"
	fresh "$tag"
	if [ "$kind" = dangling ]; then
		target="$out/pool"
	else
		target="$out/victim"
		printf 'victim-bytes\n' > "$target"
	fi
	ln -s "$target" "$sd/machine-state.img"
	rd=$(pass "$tag" daemon SW_DATE=$STAMP)
	untouched=n
	if [ "$kind" = dangling ]; then
		[ -e "$target" ] || [ -L "$target" ] || untouched=y
	else
		! holds "$target" $'victim-bytes\n' || untouched=y
	fi
	if [ "$rd" = 0 ] && booted "$tag" && ! grep -qx machine-state-not-a-file "$WORK/$tag.mark" && [ "$untouched" = y ] \
		&& [ -L "$sd/machine-state.img.not-a-file-$STAMP" ] \
		&& [ "$(readlink "$sd/machine-state.img.not-a-file-$STAMP")" = "$target" ] \
		&& [ ! -e "$sd/machine-state.img" ] && [ ! -L "$sd/machine-state.img" ]; then
		ok "a $kind link at machine-state.img is renamed aside before the runner sees it, and its target is untouched"
	else
		bad "a $kind link at machine-state.img: rc=$rd mark: $(tr '\n' ' ' < "$WORK/$tag.mark" 2>/dev/null) outside: $(tree "$out") share: $(tree "$sd")"
	fi
done

# --- l. a running instance --------------------------------------------------
# While the instance's lifetime lock is held (a running guest, which could
# swap .config for a link between a check and a write), an init pass leaves
# .config alone and a daemon pass loses the lock (75) without rewriting it.
# Once the instance stops, a daemon pass boots and writes all three again.
fresh live
rd=$(pass live daemon)
[ "$rd" = 0 ] && booted live || bad "the first boot of live exited $rd: $(said live | tail -3 | tr '\n' '|')"
for n in active-harnesses overlay-size authorized_keys; do
	printf 'sentinel\n' > "$sd/.config/$n"
done
unchanged() {
	holds "$sd/.config/active-harnesses" $'sentinel\n' && holds "$sd/.config/overlay-size" $'sentinel\n' \
		&& holds "$sd/.config/authorized_keys" $'sentinel\n'
}
exec {live_lock}>"$WORK/live/run/cogbox-demo.lock"
flock -n "$live_lock" || bad "could not take the lifetime lock of live"
ri=$(pass live init)
after_init=$(unchanged && echo kept || echo rewritten)
rd=$(pass live daemon)
after_daemon=$(unchanged && echo kept || echo rewritten)
exec {live_lock}>&-
rs=$(pass live daemon)
if [ "$ri" = 0 ] && [ "$after_init" = kept ] && [ "$rd" = 75 ] && [ "$after_daemon" = kept ]; then
	ok "with the instance running, an init pass (0) and a daemon pass (75) leave .config alone"
else
	bad "a running instance: init rc=$ri ($after_init), daemon rc=$rd ($after_daemon); .config: $(tree "$sd/.config")"
fi
if [ "$rs" = 0 ] && booted live && staged "$sd/.config/active-harnesses" "$AH" \
	&& staged "$sd/.config/overlay-size" "$OS" && staged "$sd/.config/authorized_keys" "$AK"; then
	ok "once the instance stops, a daemon pass boots and writes .config again"
else
	bad "after the stop: rc=$rs booted=$(booted live && echo y || echo n) .config: $(tree "$sd/.config") said: $(said live | tail -3 | tr '\n' '|')"
fi

if [ -s "$WORK/wedged" ]; then
	bad "passes hit the test's 60 s bound: $(tr '\n' ' ' < "$WORK/wedged")"
fi

if [ "$fails" -gt 0 ]; then
	echo "$fails check(s) failed" >&2
	exit 1
fi
echo "all launch share-write checks passed"
