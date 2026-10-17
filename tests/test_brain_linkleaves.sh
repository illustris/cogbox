#!/usr/bin/env bash
# Behavioural test for the brain materializer's STALE-LINK PRUNE (flake.nix
# brainMaterializeScript), run against the REAL rendered VM
# cogbox-brain-materialize script with its paths relocated under a scratch root.
#
# The materializer links each brain leaf into ~/work's harness trees one by one,
# so a leaf the NEW brain no longer has (a removed plugin's skill, command,
# agent or rule) used to keep pointing into the PREVIOUS brain's store path --
# which still resolves, so the harness kept loading it. The same held for the
# single-file links (.claude/settings.json, .mcp.json, .omp/mcp.json): a removed
# plugin's hooks/model pin kept applying, and an old-brain .mcp.json blocked the
# only-if-absent relink. A link is pruned iff its target is inside an EARLIER
# /nix/store/*-cogbox-brain; anything else (user files, dirs, links) is kept.
#
# Usage: test_brain_linkleaves.sh <cogbox-brain-materialize script> <fixture brain>
# Needs: bash, coreutils, gnused, gnugrep, findutils.

set -uo pipefail

MAT="${1:?usage: test_brain_linkleaves.sh <cogbox-brain-materialize> <fixture brain>}"
FIX="${2:?usage: test_brain_linkleaves.sh <cogbox-brain-materialize> <fixture brain>}"
[ -f "$MAT" ] || { echo "FAIL: no such script: $MAT" >&2; exit 1; }
[ -d "$FIX" ] || { echo "FAIL: no such fixture brain: $FIX" >&2; exit 1; }

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

fails=0
ok()   { echo "ok   - $*"; }
bad()  { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

# The baked (plugin-less) base brain the VM script links by default.
base=$(grep -m1 -o '^[[:space:]]*brain=/nix/store/[^ ]*' "$MAT" | cut -d= -f2)
[ -n "$base" ] && [ -d "$base" ] || { echo "FAIL: could not find the baked base brain in $MAT" >&2; exit 1; }
[ "$base" != "$FIX" ] || { echo "FAIL: the fixture brain IS the base brain; nothing to prune" >&2; exit 1; }
case "$base:$FIX" in
	/nix/store/*-cogbox-brain:/nix/store/*-cogbox-brain) ;;
	*) echo "FAIL: brains are not named *-cogbox-brain ($base, $FIX); the prune pattern would not apply" >&2; exit 1 ;;
esac

# mkscript ROOT: the materialize script with the brain taken from $TEST_BRAIN and
# every absolute guest path moved under ROOT (the script is tab-indented).
mkscript() {
	local R="$1"
	mkdir -p "$R/root"
	sed -e "s|^\([[:space:]]*\)brain=/nix/store/[^ ]*\$|\1brain=\"\$TEST_BRAIN\"|" \
		-e "s|WORK=/var/lib/cogbox/work|WORK=$R/work|" \
		-e "s| /root/| $R/root/|g" \
		"$MAT" > "$R.sh"
	grep -q '^[[:space:]]*brain="$TEST_BRAIN"$' "$R.sh" \
		|| { echo "FAIL: the brain= substitution did not take" >&2; exit 1; }
	grep -qx "[[:space:]]*WORK=$R/work" "$R.sh" \
		|| { echo "FAIL: the WORK= substitution did not take" >&2; exit 1; }
	if grep -v '^[[:space:]]*#' "$R.sh" | sed "s|$R/||g" | grep -q '/root/\|/var/lib/cogbox'; then
		echo "FAIL: a non-comment line still writes outside the scratch root:" >&2
		grep -v '^[[:space:]]*#' "$R.sh" | sed "s|$R/||g" | grep '/root/\|/var/lib/cogbox' >&2
		exit 1
	fi
}
# materialize ROOT BRAIN TAG: one boot's materialization; $rc.
materialize() {
	TEST_BRAIN="$2" bash "$1.sh" > "$W/$3.out" 2> "$W/$3.err"
	rc=$?
}
# points PATH BRAIN: PATH is a symlink whose (unresolved) target is inside BRAIN.
points() { [ -L "$1" ] && case "$(readlink "$1")" in "$2"/*) true ;; *) false ;; esac; }
gone() { [ ! -L "$1" ] && [ ! -e "$1" ]; }

# Every (brain subdir, destination) pair the materializer links leaf by leaf.
R="$W/r1"
mkscript "$R"
pairs="claude/skills:work/.claude/skills claude/agents:work/.claude/agents
claude/commands:work/.claude/commands rules:work/.claude/rules
opencode/skills:work/.opencode/skills opencode/agents:work/.opencode/agents
opencode/commands:work/.opencode/commands omp/skills:work/.omp/skills
omp/agents:work/.omp/agents omp/commands:work/.omp/commands omp/rules:work/.omp/rules
agents/skills:work/.agents/skills hermes/skills:root/.hermes/skills"

# --- boot 1: the fixture brain (a plugin with skills/commands/agents/rules) ---
materialize "$R" "$FIX" run1
[ "$rc" = 0 ] && ok "boot 1 (fixture brain) exits 0" || bad "boot 1 exited $rc: $(cat "$W/run1.err")"
# Non-vacuity: the plugin's leaves and single-file links really landed, so the
# prune below has something to remove.
for p in work/.claude/skills/demo-es work/.claude/commands/demo-rca.md \
	work/.claude/agents/demo-investigator.md work/.claude/rules/demo-readonly.md \
	work/.opencode/commands/demo-rca.md work/.omp/rules/demo-readonly.md \
	root/.hermes/skills/demo-overview work/.claude/settings.json work/.mcp.json work/.omp/mcp.json; do
	points "$R/$p" "$FIX" || bad "boot 1 did not link $p into the fixture brain ($(readlink "$R/$p" 2>/dev/null || echo absent))"
done
[ -L "$R/work/AGENTS.md" ] || bad "boot 1 did not link AGENTS.md (fixture brain has rules)"

# The user's own content, beside the brain's links.
fake32=abcdefghijklmnopqrstuvwxyz012345
mkdir -p "$R/work/.claude/skills/my-skill"
echo mine > "$R/work/.claude/skills/my-skill/SKILL.md"
ln -s /opt/elsewhere "$R/work/.claude/skills/my-link"
ln -s "/nix/store/$fake32-cogbox-brain-extra/claude/skills/x" "$R/work/.claude/skills/near-miss"
ln -s "/nix/store/$fake32-not-a-brain/x" "$R/work/.claude/skills/other-store"
# Deeper near misses: "-cogbox-brain/" in a LATER path component is not a brain.
ln -s "/nix/store/$fake32-mytool/share/foo-cogbox-brain/x" "$R/work/.claude/skills/deep-miss"
ln -s "/nix/store/$fake32-cogbox-brain-extra/sub-cogbox-brain/y" "$R/work/.claude/skills/deep-miss2"
echo mine > "$R/work/.claude/commands/mine.md"
# ...a dangling link into a brain that has since been garbage-collected, and
# one in a tree whose brain subdir the new brain does not have at all (the base
# brain ships no agents/skills), which must be pruned all the same.
ln -s /nix/store/00000000000000000000000000000000-cogbox-brain/claude/skills/gone "$R/work/.claude/skills/old-gone"
mkdir -p "$R/work/.agents/skills"
ln -s /nix/store/00000000000000000000000000000000-cogbox-brain/agents/skills/gone "$R/work/.agents/skills/old-codex"
[ -d "$base/agents/skills" ] && bad "the base brain now ships agents/skills; pick another absent layout for the old-codex case"

# --- boot 2: the plugin was removed -> the base brain ---
materialize "$R" "$base" run2
[ "$rc" = 0 ] && ok "boot 2 (base brain) exits 0" || bad "boot 2 exited $rc: $(cat "$W/run2.err")"
checked=0
stale=""
for pr in $pairs; do
	sub=${pr%%:*} dest=$R/${pr#*:}
	[ -d "$FIX/$sub" ] || continue
	for leaf in "$FIX/$sub"/*; do
		[ -e "$leaf" ] || continue
		n=$(basename "$leaf")
		if [ -e "$base/$sub/$n" ]; then
			points "$dest/$n" "$base" || stale="$stale ${pr#*:}/$n(not-rebased:$(readlink "$dest/$n"))"
		else
			gone "$dest/$n" || stale="$stale ${pr#*:}/$n"
		fi
		checked=$((checked + 1))
	done
done
if [ -z "$stale" ] && [ "$checked" -ge 20 ]; then
	ok "every fixture-only leaf is pruned and every base leaf points into the base brain ($checked leaves)"
else
	bad "after the plugin was removed, leaves still point into the old brain ($checked checked):$stale"
fi
for p in work/.claude/skills/demo-es work/.claude/commands/demo-rca.md \
	work/.claude/agents/demo-investigator.md work/.claude/rules/demo-readonly.md \
	work/.opencode/commands/demo-rca.md work/.omp/rules/demo-readonly.md root/.hermes/skills/demo-overview; do
	gone "$R/$p" || bad "stale $p survived ($(readlink "$R/$p"))"
done
for p in work/.claude/settings.json work/.mcp.json work/.omp/mcp.json work/AGENTS.md; do
	gone "$R/$p" && ok "stale $p removed" || bad "stale $p survived ($(readlink "$R/$p"))"
done
[ "$(readlink "$R/work/.claude/skills/cogbox-plugins")" = "$base/claude/skills/cogbox-plugins" ] \
	&& ok "the base brain's own skills are linked" \
	|| bad "cogbox-plugins reads $(readlink "$R/work/.claude/skills/cogbox-plugins" 2>/dev/null || echo absent)"
# The user's content is untouched; only the old-brain link goes.
if [ -d "$R/work/.claude/skills/my-skill" ] && [ ! -L "$R/work/.claude/skills/my-skill" ] \
	&& [ "$(cat "$R/work/.claude/skills/my-skill/SKILL.md")" = mine ] \
	&& [ "$(readlink "$R/work/.claude/skills/my-link")" = /opt/elsewhere ] \
	&& [ "$(readlink "$R/work/.claude/skills/near-miss")" = "/nix/store/$fake32-cogbox-brain-extra/claude/skills/x" ] \
	&& [ "$(readlink "$R/work/.claude/skills/other-store")" = "/nix/store/$fake32-not-a-brain/x" ] \
	&& [ "$(readlink "$R/work/.claude/skills/deep-miss")" = "/nix/store/$fake32-mytool/share/foo-cogbox-brain/x" ] \
	&& [ "$(readlink "$R/work/.claude/skills/deep-miss2")" = "/nix/store/$fake32-cogbox-brain-extra/sub-cogbox-brain/y" ] \
	&& [ -f "$R/work/.claude/commands/mine.md" ] && [ ! -L "$R/work/.claude/commands/mine.md" ] \
	&& [ "$(cat "$R/work/.claude/commands/mine.md")" = mine ]; then
	ok "user dirs, files, non-brain links and the -cogbox-brain near misses are untouched"
else
	bad "user content was touched: $(ls -la "$R/work/.claude/skills" "$R/work/.claude/commands" 2>&1)"
fi
gone "$R/work/.claude/skills/old-gone" && ok "a dangling link into a collected brain is pruned" \
	|| bad "dangling old-brain link survived"
gone "$R/work/.agents/skills/old-codex" && ok "an old-brain link is pruned even where the new brain has no such subdir" \
	|| bad "old-brain link in a layout the new brain lacks survived"

# --- boot 3: the plugin is re-added -> the fixture again, all relinked ---
# A user's own alias into the brain that is CURRENT at that boot is theirs.
ln -s "$FIX/claude/skills/demo-es" "$R/work/.claude/skills/my-alias"
materialize "$R" "$FIX" run3
[ "$rc" = 0 ] || bad "boot 3 exited $rc: $(cat "$W/run3.err")"
relinked=1
for p in work/.claude/skills/demo-es work/.claude/commands/demo-rca.md work/.omp/rules/demo-readonly.md \
	root/.hermes/skills/demo-overview work/.claude/settings.json work/.mcp.json work/.omp/mcp.json; do
	points "$R/$p" "$FIX" || { relinked=0; bad "boot 3 did not relink $p into the fixture brain"; }
done
[ "$relinked" = 1 ] && ok "re-adding the plugin relinks its leaves and single-file links"
[ "$(readlink "$R/work/.claude/skills/my-alias")" = "$FIX/claude/skills/demo-es" ] \
	&& ok "a user link into the current brain is kept" \
	|| bad "a user link into the current brain was touched ($(readlink "$R/work/.claude/skills/my-alias" 2>/dev/null || echo absent))"

# --- a user's own regular .mcp.json is never replaced or removed ---
R2="$W/r2"
mkscript "$R2"
mkdir -p "$R2/work"
echo '{"user":true}' > "$R2/work/.mcp.json"
materialize "$R2" "$FIX" user-mcp
if [ "$rc" = 0 ] && [ -f "$R2/work/.mcp.json" ] && [ ! -L "$R2/work/.mcp.json" ] \
	&& [ "$(cat "$R2/work/.mcp.json")" = '{"user":true}' ]; then
	ok "a user's regular .mcp.json survives"
else
	bad "user .mcp.json was touched (rc=$rc, $(ls -la "$R2/work/.mcp.json" 2>&1))"
fi

# --- a stale link the prune cannot remove never fails the unit ---
# Only the prune touches this dir: the base brain has no agents/skills (pinned
# above), so nothing is linked into it afterwards.
R3="$W/r3"
mkscript "$R3"
mkdir -p "$R3/work/.agents/skills"
ln -s /nix/store/00000000000000000000000000000000-cogbox-brain/agents/skills/gone "$R3/work/.agents/skills/old-codex"
chmod 555 "$R3/work/.agents/skills"
if touch "$R3/work/.agents/skills/.probe" 2>/dev/null; then
	echo "skip - a read-only dir is writable here (running as root?); rm-failure case not exercised"
else
	materialize "$R3" "$base" rmfail
	if [ "$rc" = 0 ] && grep -q 'could not remove stale link' "$W/rmfail.err" \
		&& [ -L "$R3/work/.agents/skills/old-codex" ]; then
		ok "a stale link that cannot be removed is logged and the unit still exits 0"
	else
		bad "unremovable stale link (rc=$rc err=$(cat "$W/rmfail.err"))"
	fi
fi
chmod 755 "$R3/work/.agents/skills"

if [ "$fails" -gt 0 ]; then
	echo "$fails check(s) failed" >&2
	exit 1
fi
echo "all brain-linkleaves checks passed"
