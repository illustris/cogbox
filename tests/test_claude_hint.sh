#!/usr/bin/env bash
# Behavioural test for the VM `c` launcher's Claude connect hint (flake.nix
# mkLauncher claudeConnectHint), run against the REAL rendered launcher with
# the harness, the marker and the credential file relocated.
#
# On a control-plane-managed VM, cogworx writes the claude-oauth.bound marker
# as "1" (owner connected) or "0" (owner NOT connected; absent = unmanaged).
# With "0" claude-code boots with no credential, and its /login is usually a
# dead end in the sandbox (the sign-in hosts are not on the default l7
# allow-list). `c` must say what to do instead -- once, on an interactive
# stderr only, and never when the user already has a credential file of their
# own or claude-code's auth comes from the env -- and then launch the harness
# exactly as before.
#
# Usage: test_claude_hint.sh <c launcher>
# Needs: bash, coreutils, gnused, gnugrep.

set -uo pipefail

C="${1:?usage: test_claude_hint.sh <c launcher>}"
[ -f "$C" ] || { echo "FAIL: no such launcher: $C" >&2; exit 1; }

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

fails=0
ok()   { echo "ok   - $*"; }
bad()  { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

claude=$(grep -o '/nix/store/[^ ]*/bin/claude' "$C" | head -n1)
[ -n "$claude" ] || { echo "FAIL: could not find the claude executable in $C" >&2; exit 1; }
# (No /usr/bin/env in the nix build sandbox: the shebang names this bash.)
printf '#!%s\necho "STUB $*"\n' "$(command -v bash)" > "$W/claude"
chmod +x "$W/claude"

# mk OUT [tty]: the launcher relocated; with "tty", [ -t 2 ] reads $HINT_TTY
# instead, so the hint's TTY gate can be driven from a build sandbox.
mk() {
	local out="$1" tty="${2-}"
	sed -e "s|$claude|$W/claude|g" \
		-e "s|/var/lib/cogbox/claude-oauth.bound|$W/marker|g" \
		-e "s|/root/.claude/.credentials.json|$W/creds.json|g" \
		"$C" > "$out"
	[ -z "$tty" ] || sed -i 's/\[ -t 2 \]/[ -n "${HINT_TTY-}" ]/' "$out"
	grep -q "$W/claude" "$out" || { echo "FAIL: the claude substitution did not take" >&2; exit 1; }
	grep -q "$W/marker" "$out" || { echo "FAIL: the marker substitution did not take (no claude-oauth.bound in $C)" >&2; exit 1; }
	grep -q "$W/creds.json" "$out" || { echo "FAIL: the credentials substitution did not take" >&2; exit 1; }
	if [ -n "$tty" ]; then
		grep -qF '[ -n "${HINT_TTY-}" ]' "$out" || { echo "FAIL: the [ -t 2 ] substitution did not take" >&2; exit 1; }
	fi
	if grep -q 'claude-oauth.bound\|/root/.claude/.credentials.json' "$out"; then
		echo "FAIL: the relocated launcher still reads a real guest path" >&2
		exit 1
	fi
}
mk "$W/a.sh" tty
mk "$W/b.sh"

# setmark CONTENT|absent, setcreds CONTENT|absent (CONTENT via printf %b)
setmark()  { rm -f "$W/marker";     [ "$1" = absent ] || printf '%b' "$1" > "$W/marker"; }
setcreds() { rm -f "$W/creds.json"; [ "$1" = absent ] || printf '%b' "$1" > "$W/creds.json"; }
# claude-code auth routes that make the managed connection irrelevant.
ALT_AUTH="ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_OAUTH_TOKEN CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX"
unset_alt=()
for v in $ALT_AUTH; do unset_alt+=(-u "$v"); done
# launch TAG [VAR=value...]: copy A on a "TTY", with one user argument, the
# caller's alt-auth env cleared then the given assignments; $rc, $hints.
launch() {
	local tag="$1"; shift
	env "${unset_alt[@]}" HINT_TTY=1 "$@" bash "$W/a.sh" x > "$W/$tag.out" 2> "$W/$tag.err"
	rc=$?
	hints=$(grep -c 'Claude is not connected' "$W/$tag.err")
}
harness_ran() { [ "$rc" = 0 ] && [ "$(cat "$W/$1.out")" = "STUB --dangerously-skip-permissions x" ]; }

# hint TAG MARKER CREDS DESC [VAR=value...]: expect exactly one hint, and the harness launched
hint() {
	setmark "$2"; setcreds "$3"; launch "$1" "${@:5}"
	if [ "$hints" = 1 ] && grep -q 'Settings' "$W/$1.err" && grep -q '/login' "$W/$1.err" \
		&& grep -q 'owner' "$W/$1.err" && harness_ran "$1"; then
		ok "$4: one hint, then the harness"
	else
		bad "$4 (rc=$rc hints=$hints out=$(cat "$W/$1.out") err=$(cat "$W/$1.err"))"
	fi
}
# quiet TAG MARKER CREDS DESC [VAR=value...]: expect no hint, and the harness launched
quiet() {
	setmark "$2"; setcreds "$3"; launch "$1" "${@:5}"
	if [ "$hints" = 0 ] && [ ! -s "$W/$1.err" ] && harness_ran "$1"; then
		ok "$4: no hint"
	else
		bad "$4 (rc=$rc hints=$hints out=$(cat "$W/$1.out") err=$(cat "$W/$1.err"))"
	fi
}

hint  m0       '0'   absent       'managed, owner not connected (marker "0", no newline)'
hint  m0nl     '0\n' absent       'managed, owner not connected (marker "0\n")'
quiet m1       '1'   absent       'owner connected (marker "1")'
quiet mempty   ''    absent       'empty marker'
quiet mabsent  absent absent      'unmanaged VM (no marker)'
quiet ownlogin '0'   '{"x":1}\n'  "the user's own /login credential exists"
hint  emptycr  '0'   ''           'an EMPTY credential file is no credential'
# claude-code authenticated from the env: the owner's connection does not matter
for v in $ALT_AUTH; do
	quiet "env-$v" '0' absent "$v set in the caller's env" "$v=fixture-not-a-secret"
done
hint  envempty '0'   absent       'an EMPTY auth env var is no auth' ANTHROPIC_API_KEY=

# Copy B keeps the real [ -t 2 ]: stderr is a file here, so no hint at all.
setmark '0'; setcreds absent
env "${unset_alt[@]}" bash "$W/b.sh" x > "$W/notty.out" 2> "$W/notty.err"
rc=$?
if [ "$(grep -c 'Claude is not connected' "$W/notty.err")" = 0 ] && harness_ran notty; then
	ok "a non-TTY stderr gets no hint, and the harness still runs"
else
	bad "non-TTY (rc=$rc out=$(cat "$W/notty.out") err=$(cat "$W/notty.err"))"
fi

if [ "$fails" -gt 0 ]; then
	echo "$fails check(s) failed" >&2
	exit 1
fi
echo "all claude-hint checks passed"
