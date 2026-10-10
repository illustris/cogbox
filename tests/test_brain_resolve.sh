#!/usr/bin/env bash
# Behavioural test for the container brain resolve's UNCONFIRMED RE-PIN FALLBACK
# (flake.nix brainResolveContainer), run against the REAL rendered
# cogbox-brain-materialize script with its nix swapped for a stub.
#
# `cogbox plugin` re-pins a composition's stale path: inputs and leaves the
# pre-re-pin lock in composition.lock.prev until a prebuild seeds the new pin.
# If that op was killed (the control plane's install budget) or the new content
# does not build, the egress-less boot must fall back to the previous lock --
# not to the plugin-less base brain, which is what an instance that was serving
# stale-but-present plugins would otherwise get.
#
# Usage: test_brain_resolve.sh <cogbox-brain-materialize script>
# Needs: bash, coreutils, gnused, gnugrep, jq.

set -uo pipefail

MAT="${1:?usage: test_brain_resolve.sh <cogbox-brain-materialize>}"
[ -f "$MAT" ] || { echo "FAIL: no such script: $MAT" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

fails=0
ok()   { echo "ok   - $*"; }
bad()  { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

# The stub: `build` succeeds iff the composition it is pointed at
# (--override-input userExtensions path:<dir>) has a flake.lock containing
# "BUILDS", printing $STUB_OUT as the brain; everything else fails.
# (No /usr/bin/env in the nix build sandbox: the shebang names this bash.)
{ echo "#!$(command -v bash)"; cat <<'STUB_EOF'
comp=""
sub=""
prev=""
for a in "$@"; do
	[ -z "$sub" ] && case "$a" in build|eval) sub="$a" ;; esac
	[ "$prev" = userExtensions ] && comp="${a#path:}"
	prev="$a"
done
echo "$sub $comp" >> "$STUB_LOG"
[ "$sub" = build ] && grep -q BUILDS "$comp/flake.lock" 2>/dev/null && { echo "$STUB_OUT"; exit 0; }
exit 1
STUB_EOF
} > "$WORK/nix"
chmod +x "$WORK/nix"

# The resolve half only (the script is tab-indented): cut before the materialization (which writes to
# /var/lib/cogbox), print the chosen brain, and route the baked nix to the stub.
nixbin=$(grep -o '/nix/store/[a-z0-9]*-nix-[^/]*/bin/nix ' "$MAT" | head -n1)
[ -n "$nixbin" ] || { echo "FAIL: could not find the baked nix in $MAT" >&2; exit 1; }
base=$(grep -m1 -o '^[[:space:]]*brain=/nix/store/[^ ]*' "$MAT" | cut -d= -f2)
[ -n "$base" ] || { echo "FAIL: could not find the baked base brain in $MAT" >&2; exit 1; }
sed -n '1,/^[[:space:]]*WORK=\/var\/lib\/cogbox\/work$/p' "$MAT" | sed '$d' \
	| sed "s|$nixbin|$WORK/nix |g" > "$WORK/resolve.sh"
echo 'echo "BRAIN=$brain"' >> "$WORK/resolve.sh"
grep -q "$WORK/nix " "$WORK/resolve.sh" || { echo "FAIL: stub substitution did not take" >&2; exit 1; }
# The stub's "brain": any existing store path (the resolve keeps only a
# /nix/store/ out-path that exists) -- the baked nix package itself.
fake=${nixbin%/bin/nix }

# run TAG LIVE_LOCK [PREV_LOCK]: one instance with one plugin.
run() {
	local tag="$1" live="$2" prev="${3-}"
	local cfg="$WORK/$tag/config"
	icd="$cfg/cogbox/instances/demo"
	mkdir -p "$icd/plugins-flake"
	echo '{"plugins":[{"name":"a"}]}' > "$icd/config.json"
	echo '{}' > "$icd/plugins-flake/flake.nix"
	echo "$live" > "$icd/plugins-flake/flake.lock"
	[ -z "$prev" ] || echo "$prev" > "$icd/composition.lock.prev"
	: > "$WORK/$tag.nix.log"
	COGBOX_INSTANCE=demo XDG_CONFIG_HOME="$cfg" STUB_LOG="$WORK/$tag.nix.log" STUB_OUT="$fake" \
		TMPDIR="$WORK/$tag" bash "$WORK/resolve.sh" > "$WORK/$tag.out" 2> "$WORK/$tag.err"
	brain=$(sed -n 's/^BRAIN=//p' "$WORK/$tag.out")
}

# (a) the live lock builds: used directly, no fallback attempted
run live-ok '{"x":"BUILDS"}' '{"x":"BUILDS-prev"}'
if [ "$brain" = "$fake" ] && [ "$(grep -c '^build ' "$WORK/live-ok.nix.log")" = 1 ] \
	&& ! grep -q 'pre-re-pin' "$WORK/live-ok.err"; then
	ok "a buildable live lock is used without touching the snapshot"
else
	bad "live-ok (brain=$brain, nix: $(cat "$WORK/live-ok.nix.log"), err: $(cat "$WORK/live-ok.err"))"
fi

# (b) the live (re-pinned) lock cannot build offline but the snapshot can:
# the snapshot's brain is used, loudly, and its scratch copy is cleaned up
run prev-ok '{"x":"unseeded"}' '{"x":"BUILDS"}'
if [ "$brain" = "$fake" ] && grep -q 'using the pre-re-pin lock' "$WORK/prev-ok.err" \
	&& [ "$(cat "$icd/plugins-flake/flake.lock")" = '{"x":"unseeded"}' ] \
	&& [ -z "$(find "$WORK/prev-ok" -mindepth 1 -maxdepth 1 -name 'tmp.*')" ] \
	&& [ ! -e "$icd/brain.fallback" ]; then
	ok "an unbuildable re-pin falls back to the pre-re-pin lock, not the base brain"
else
	bad "prev-ok (brain=$brain, nix: $(cat "$WORK/prev-ok.nix.log"), err: $(cat "$WORK/prev-ok.err"))"
fi

# (c) no snapshot: unchanged behaviour, the base brain with a fallback marker
run no-prev '{"x":"unseeded"}'
if [ "$brain" = "$base" ] && [ "$(grep -c '^build ' "$WORK/no-prev.nix.log")" = 1 ] \
	&& [ -e "$icd/brain.fallback" ]; then
	ok "without a snapshot a failed rebuild keeps the base-brain fallback"
else
	bad "no-prev (brain=$brain, nix: $(cat "$WORK/no-prev.nix.log"), err: $(cat "$WORK/no-prev.err"))"
fi

# (d) the snapshot does not build either: base brain, scratch copy cleaned up
run both-fail '{"x":"unseeded"}' '{"x":"also-unseeded"}'
if [ "$brain" = "$base" ] && [ "$(grep -c '^build ' "$WORK/both-fail.nix.log")" = 2 ] \
	&& [ -z "$(find "$WORK/both-fail" -mindepth 1 -maxdepth 1 -name 'tmp.*')" ] \
	&& [ -e "$icd/brain.fallback" ]; then
	ok "a snapshot that does not build either ends at the base brain"
else
	bad "both-fail (brain=$brain, nix: $(cat "$WORK/both-fail.nix.log"), err: $(cat "$WORK/both-fail.err"))"
fi

if [ "$fails" -gt 0 ]; then
	echo "$fails check(s) failed" >&2
	exit 1
fi
echo "all brain-resolve checks passed"
