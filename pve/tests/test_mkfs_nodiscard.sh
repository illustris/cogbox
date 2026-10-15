#!/usr/bin/env bash
# Behavioural test for pve/mkfs-nodiscard.nix: the format units' mke2fs
# profile is the package default plus `discard = false` under [defaults] and
# nothing else, it is derived from the file the units' own mke2fs compiles in,
# and every realized `mkfs.ext4` line of those units discards under the
# default profile but not under theirs.
#
# Usage: test_mkfs_nodiscard.sh E2FSPROGS UPSTREAM PROFILE UNIT=SCRIPT=CONFIG...
#   E2FSPROGS  the system's e2fsprogs (its bin output)
#   UPSTREAM   that package's compiled-in mke2fs.conf
#   PROFILE    system.build.pveMke2fsConfig
#   UNIT=SCRIPT=CONFIG  per format unit: its realized ExecStart program and
#              the MKE2FS_CONFIG value its unit carries
#
# The discard is observed on a sparse regular FILE, where mke2fs issues it as
# fallocate(PUNCH_HOLE) (BLKDISCARD on a block device; both are counted).
# UNIX_IO_NOZEROOUT=1 keeps mke2fs's zero-out from ever falling back to
# PUNCH_HOLE, so a punched hole can only be a discard. Every run is paired
# with a control under the default profile that MUST discard: a fixture that
# shows no discard either way (strace not tracing, or an mke2fs that no longer
# discards by default) fails instead of passing.
set -uo pipefail

fails=0
ok()  { echo "ok   - $*"; }
bad() { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

E2FSPROGS="${1:?usage: test_mkfs_nodiscard.sh E2FSPROGS UPSTREAM PROFILE UNIT=SCRIPT=CONFIG...}"
UPSTREAM="${2:?}"
PROFILE="${3:?}"
shift 3
units=("$@")
[ "${#units[@]}" -gt 0 ] || { echo "test_mkfs_nodiscard: no format units given" >&2; exit 1; }

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
IMG="$ROOT/disk.img"
export UNIX_IO_NOZEROOUT=1

# --- the profile ------------------------------------------------------------
n=$(grep -c '^[[:space:]]*discard[[:space:]]*=' "$PROFILE" || true)
k=$(grep -n '^[[:space:]]*discard[[:space:]]*=' "$PROFILE" | cut -d: -f1 | head -n1)
if [ "$n" = 1 ] && [ "$(sed -n "${k}p" "$PROFILE")" = $'\tdiscard = false' ]; then
	ok "the profile sets discard once, to false"
else
	bad "the profile has $n discard line(s): $(grep -n 'discard' "$PROFILE" | tr '\n' ' ')"
fi
if [ -n "$k" ] && [ "$k" -gt 1 ] && [ "$(sed -n "$((k - 1))p" "$PROFILE")" = '[defaults]' ]; then
	ok "it sits directly under [defaults]"
else
	bad "the discard line does not follow [defaults]"
fi
if [ -n "$k" ] && sed "${k}d" "$PROFILE" | cmp -s - "$UPSTREAM"; then
	ok "without that line it is byte-identical to the package default"
else
	bad "it differs from the package default by more than the discard line: $(diff "$UPSTREAM" "$PROFILE" | tr '\n' ' ')"
fi
# Derived from the file this mke2fs reads when MKE2FS_CONFIG is unset, not
# from some other e2fsprogs' copy.
if grep -aqF "$UPSTREAM" "$E2FSPROGS/bin/mke2fs"; then
	ok "the package default is the profile path $E2FSPROGS/bin/mke2fs compiles in"
else
	bad "$E2FSPROGS/bin/mke2fs does not compile in $UPSTREAM"
fi

# --- one mke2fs run under strace --------------------------------------------
# run NAME CONFIG ARGV...: a fresh 1 GiB sparse image (the default size class,
# 4 KiB blocks, like the real disks), the given profile (empty: the default
# one), discards counted. Leaves rc, punch, blkdiscard and $ROOT/NAME.out.
run() {
	local name="$1" config="$2"
	shift 2
	rm -f "$IMG"
	truncate -s 1G "$IMG"
	if [ -n "$config" ]; then
		MKE2FS_CONFIG="$config" strace -f -qq -o "$ROOT/$name.trace" -e trace=fallocate,ioctl "$@" > "$ROOT/$name.out" 2>&1
	else
		env -u MKE2FS_CONFIG strace -f -qq -o "$ROOT/$name.trace" -e trace=fallocate,ioctl "$@" > "$ROOT/$name.out" 2>&1
	fi
	rc=$?
	punch=$(grep -c 'PUNCH_HOLE' "$ROOT/$name.trace" || true)
	blkdiscard=$(grep -c 'BLKDISCARD' "$ROOT/$name.trace" || true)
}

# --- every realized format line, as its unit runs it --------------------------
for spec in "${units[@]}"; do
	unit="${spec%%=*}"
	rest="${spec#*=}"
	script="${rest%%=*}"
	config="${rest#*=}"

	if [ "$config" = "$PROFILE" ]; then
		ok "$unit: MKE2FS_CONFIG is the profile"
	else
		bad "$unit: MKE2FS_CONFIG is '$config', not $PROFILE"
	fi

	# The mkfs.ext4 the script resolves is this e2fsprogs' own.
	# shellcheck disable=SC2016 # a literal $PATH, as writeShellApplication writes it
	path=$(sed -n 's/^export PATH="\(.*\):\$PATH"$/\1/p' "$script" | head -n1)
	resolved=
	IFS=: read -ra dirs <<< "$path"
	for d in "${dirs[@]}"; do
		if [ -x "$d/mkfs.ext4" ]; then resolved="$d/mkfs.ext4"; break; fi
	done
	if [ "$resolved" = "$E2FSPROGS/bin/mkfs.ext4" ]; then
		ok "$unit: its PATH resolves mkfs.ext4 to $resolved"
	else
		bad "$unit: its PATH resolves mkfs.ext4 to '${resolved:-nothing}', not $E2FSPROGS/bin/mkfs.ext4 (PATH=$path)"
	fi

	# Every non-comment line that names mkfs/mke2fs must be a plain invocation
	# this test can run; anything else needs a look before it can pass.
	mentions=$(grep -vE '^[[:space:]]*#' "$script" | grep -cE 'mkfs|mke2fs' || true)
	lines=$(grep -E '^[[:space:]]*(mkfs\.ext[234]|mke2fs)[[:space:]]' "$script" | sed -E 's/^[[:space:]]+//')
	count=$(printf '%s' "$lines" | grep -c . || true)
	if [ "$count" -gt 0 ] && [ "$count" = "$mentions" ]; then
		ok "$unit: $count format line(s), all plain invocations"
	else
		bad "$unit: $mentions non-comment line(s) name mkfs/mke2fs, $count of them plain invocations"
	fi

	while IFS= read -r line; do
		[ -n "$line" ] || continue
		# An -E discard would be parsed after the profile and turn discard back
		# on. Other -E options are harmless; the run below catches any discard.
		if printf '%s\n' "$line" | grep -qE '[[:space:]]-[A-Za-z]*E[[:space:]]*[^[:space:]]*discard'; then
			bad "$unit: '$line' passes an -E discard option"
		fi
		# The line's own words, with its device variables naming the image.
		# shellcheck disable=SC2034 # read by the eval below
		dev="$IMG" storedev="$IMG" pooldev="$IMG"
		eval "set -- $line"
		set -- "$E2FSPROGS/bin/$1" "${@:2}"

		run control "" "$@"
		if [ "$rc" = 0 ] && [ "$punch" -gt 0 ]; then
			ok "$unit: '$line' discards under the default profile ($punch PUNCH_HOLE)"
		else
			bad "$unit: the control run of '$line' shows no discard (rc $rc, $punch PUNCH_HOLE); this fixture cannot tell the profile's effect: $(cat "$ROOT/control.out")"
		fi

		run profile "$config" "$@"
		if [ "$rc" = 0 ] && [ "$punch" = 0 ] && [ "$blkdiscard" = 0 ] && "$E2FSPROGS/bin/dumpe2fs" -h "$IMG" > /dev/null 2>&1; then
			ok "$unit: '$line' makes the filesystem and discards nothing under MKE2FS_CONFIG"
		else
			bad "$unit: '$line' under MKE2FS_CONFIG: rc $rc, $punch PUNCH_HOLE, $blkdiscard BLKDISCARD: $(cat "$ROOT/profile.out")"
		fi
	done <<< "$lines"
done

# --- a second witness, and nothing else changes --------------------------------
mkfs="$E2FSPROGS/bin/mkfs.ext4"
run verbose-control "" "$mkfs" -L t "$IMG"
if grep -q 'Discarding device blocks' "$ROOT/verbose-control.out"; then ok "a verbose control run reports 'Discarding device blocks'"; else bad "a verbose control run does not report discarding: $(cat "$ROOT/verbose-control.out")"; fi
run verbose-profile "$PROFILE" "$mkfs" -L t "$IMG"
if [ "$rc" = 0 ] && ! grep -q 'Discarding' "$ROOT/verbose-profile.out"; then ok "a verbose run under the profile does not"; else bad "a verbose run under the profile: rc $rc: $(cat "$ROOT/verbose-profile.out")"; fi

# The same filesystem either way, its random and time inputs fixed.
export E2FSPROGS_FAKE_TIME=1700000000
fixed=(-q -U 01234567-89ab-4def-8123-456789abcdef -E hash_seed=fedcba98-7654-4321-8fed-cba987654321 -L cogworx-state "$IMG")
for p in control profile; do
	cfg=; [ "$p" = profile ] && cfg="$PROFILE"
	run "fixed-$p" "$cfg" "$mkfs" "${fixed[@]}"
	[ "$rc" = 0 ] || bad "the fixed $p run failed: $(cat "$ROOT/fixed-$p.out")"
	# Otherwise the comparison below would pass vacuously, both runs alike.
	case "$p:$punch" in
		control:0) bad "the fixed control run did not discard; the comparison proves nothing" ;;
		profile:0) ;;
		profile:*) bad "the fixed profile run discarded ($punch PUNCH_HOLE)" ;;
	esac
	"$E2FSPROGS/bin/dumpe2fs" -h "$IMG" > "$ROOT/$p.h" 2>&1
	"$E2FSPROGS/bin/dumpe2fs" "$IMG" > "$ROOT/$p.full" 2>/dev/null
done
if cmp -s "$ROOT/control.h" "$ROOT/profile.h"; then ok "dumpe2fs -h is identical with and without the profile"; else bad "the superblocks differ: $(diff "$ROOT/control.h" "$ROOT/profile.h" | tr '\n' ' ')"; fi
# The group descriptors differ in one flag, and only on a FILE: unix_io says a
# file's discard zeroes, so the control marks every inode table ITABLE_ZEROED
# (and re-checksums the descriptor). A block device says it does not
# (BLKDISCARDZEROES is 0), so on the real disks this difference does not arise.
norm() { sed -E 's/ csum 0x[0-9a-f]+//; s/, ITABLE_ZEROED\]/]/; s/ \[ITABLE_ZEROED\]//' "$1"; }
if diff <(norm "$ROOT/control.full") <(norm "$ROOT/profile.full") > "$ROOT/full.diff"; then
	ok "the full dumpe2fs differs only in the file-only ITABLE_ZEROED flag"
else
	bad "the full dumpe2fs differs beyond ITABLE_ZEROED: $(head -n 20 "$ROOT/full.diff" | tr '\n' ' ')"
fi

if [ "$fails" -gt 0 ]; then
	echo "test_mkfs_nodiscard: $fails failure(s)" >&2
	exit 1
fi
echo "test_mkfs_nodiscard: all passed"
