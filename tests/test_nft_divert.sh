#!/usr/bin/env bash
# Behavioural test for cogbox-nft-divert.sh (the container-mode nft-init
# sidecar), run without a VM or NET_ADMIN.
#
# The script feeds its nft program through UNQUOTED heredocs, on purpose: the
# shell must expand $PORT / $ENFORCER_IP / $ENFORCER_PORT / $DNS_ALLOW inside
# them. The flip side is that the shell ALSO command-substitutes any backtick or
# $(...) it finds there -- including inside nft comments. nft ignores the comment
# so the loaded ruleset is intact, but the sidecar's stderr fills with
# "oif: command not found" noise that reads like a broken floor (field, 9/05:
# the mosh rule's rationale quoted rule fragments in backticks). Neither `bash -n`
# nor the KVM bypass suite catches that, so this pins it:
#
#   1. STATIC: every `nft -f - <<EOF` body carries no backtick, no `$(`, and
#      references only the four intended variables.
#   2. BEHAVIOURAL: running the script against a stub `nft` produces no
#      "command not found" on stderr, on BOTH the normal path and the
#      fail-closed fallback path, and the captured programs still carry the
#      rules they are supposed to (so a rewrite cannot silently drop a rule).
#   3. PARSE (when a real nft is on PATH and can run -c here): the captured
#      programs are still valid nft syntax.
#
# Usage: test_nft_divert.sh <path-to-cogbox-nft-divert.sh>
# Needs: bash, gawk, coreutils, grep. nftables optional (case 3 skips without it).

set -uo pipefail

SCRIPT="${1:?usage: test_nft_divert.sh <cogbox-nft-divert.sh>}"
[ -f "$SCRIPT" ] || { echo "FAIL: no such script: $SCRIPT" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

fails=0
ok()   { echo "ok   - $*"; }
bad()  { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

# Resolve a REAL nft before the stub dir shadows PATH (case 3).
REAL_NFT=$(command -v nft 2>/dev/null || true)

# --- 0. the script still parses -----------------------------------------------

if bash -n "$SCRIPT" 2>"$WORK/syntax.log"; then
	ok "bash -n accepts the script"
else
	bad "bash -n rejected the script: $(cat "$WORK/syntax.log")"
fi

# --- 1. static: heredoc bodies are shell-inert apart from the four vars -------

# Emit every `nft -f - <<EOF` body, one file per heredoc, numbered in order.
awk -v dir="$WORK" '
	/^[[:space:]]*nft -f - <<EOF$/ { n++; out = dir "/heredoc." n; inb = 1; next }
	inb && /^EOF$/ { inb = 0; close(out); next }
	inb { print > out }
	END { print n > (dir "/heredoc.count") }
' "$SCRIPT"
count=$(cat "$WORK/heredoc.count")
# Two today: the fail-closed fallback floor and the divert + floor program. A
# third would need its own behavioural case below; a miss means the awk anchor
# rotted and the static check is asserting over nothing.
[ "$count" = 2 ] || bad "expected 2 nft heredocs, awk found $count"

for f in "$WORK"/heredoc.[0-9]*; do
	tag=$(basename "$f")
	if grep -n '`' "$f" >"$WORK/$tag.bt"; then
		bad "$tag: backtick inside an unquoted heredoc (shell command-substitutes it): $(cat "$WORK/$tag.bt")"
	else
		ok "$tag: no backtick"
	fi
	if grep -n '\$(' "$f" >"$WORK/$tag.sub"; then
		bad "$tag: \$( inside an unquoted heredoc: $(cat "$WORK/$tag.sub")"
	else
		ok "$tag: no \$("
	fi
	# Every $NAME / ${NAME must be one of the four the script means to expand.
	stray=$(grep -o '\$[{]*[A-Za-z_][A-Za-z0-9_]*' "$f" \
		| sed 's/^\$[{]*//' \
		| grep -v -x -e PORT -e ENFORCER_IP -e ENFORCER_PORT -e DNS_ALLOW || true)
	if [ -n "$stray" ]; then
		bad "$tag: unexpected variable reference(s): $(echo "$stray" | tr '\n' ' ')"
	else
		ok "$tag: only the intended variables are referenced"
	fi
done

# --- 2. behavioural: the script runs clean against a stub nft -----------------

# Stub nft: record the program it was handed, succeed. Stub sleep: the script
# ends in `exec sleep infinity`; make that return so the run terminates.
# (Shebangs name THIS bash by absolute path: the nix sandbox has no /usr/bin/env.)
mkdir -p "$WORK/bin"
printf '#!%s\ncat >>"${NFT_CAPTURE:?}"\n' "$BASH" >"$WORK/bin/nft"
printf '#!%s\nexit 0\n' "$BASH" >"$WORK/bin/sleep"
chmod +x "$WORK/bin/nft" "$WORK/bin/sleep"

# Run the script with the stubs first on PATH. Echoes the exit status; the
# caller reads $WORK/<tag>.err and $WORK/<tag>.nft.
run_divert() {
	local tag="$1"; shift
	: >"$WORK/$tag.nft"
	env -i PATH="$WORK/bin:$PATH" NFT_CAPTURE="$WORK/$tag.nft" "$@" \
		bash "$SCRIPT" >"$WORK/$tag.out" 2>"$WORK/$tag.err"
	echo $?
}

no_shell_noise() {
	local tag="$1"
	if grep -q 'command not found\|syntax error\|unbound variable' "$WORK/$tag.err"; then
		bad "$tag: shell noise on stderr: $(grep 'command not found\|syntax error\|unbound variable' "$WORK/$tag.err" | head -3)"
	else
		ok "$tag: no shell noise on stderr"
	fi
}

# 2a. the normal path: divert + floor.
rc=$(run_divert normal COGBOX_ENFORCER_IP=10.96.7.8 COGBOX_ENFORCER_PORT=1080 COGBOX_DIVERT_PORT=18443)
[ "$rc" = 0 ] || bad "normal run exited $rc (stderr: $(cat "$WORK/normal.err"))"
no_shell_noise normal
grep -q 'default-drop floor + REDIRECT(:18443) loaded; enforcer carve-out 10.96.7.8:1080' "$WORK/normal.err" \
	&& ok "normal: loaded line names the port and carve-out" \
	|| bad "normal: missing/incorrect loaded line: $(cat "$WORK/normal.err")"
# The rules the comments were explaining must still be there, expanded.
for want in \
	'ip daddr 10.96.7.8 tcp dport 1080 counter return' \
	'meta l4proto tcp redirect to :18443' \
	'iif != "lo" udp dport 60000-60031 ct state new ct mark set 0x6d' \
	'udp sport 60000-60031 ct state established ct direction reply ct mark 0x6d counter accept' \
	'type filter hook output priority mangle; policy drop;' \
	'chain forward { type filter hook forward priority filter; policy drop; }'
do
	grep -qF -- "$want" "$WORK/normal.nft" \
		&& ok "normal: program carries: $want" \
		|| bad "normal: program lost: $want"
done
grep -q '^flush ruleset$' "$WORK/normal.nft" \
	&& ok "normal: program is flush-ruleset-first (atomic, idempotent)" \
	|| bad "normal: program does not flush ruleset"

# 2b. the fail-closed path: missing carve-out coordinates load the floor and exit 64.
rc=$(run_divert failclosed COGBOX_DIVERT_PORT=18443)
[ "$rc" = 64 ] || bad "fail-closed run exited $rc, want 64 (stderr: $(cat "$WORK/failclosed.err"))"
no_shell_noise failclosed
grep -q 'FATAL: COGBOX_ENFORCER_IP/PORT unset' "$WORK/failclosed.err" \
	&& ok "fail-closed: FATAL line present" \
	|| bad "fail-closed: FATAL line missing: $(cat "$WORK/failclosed.err")"
grep -q 'table inet cogbox_floor' "$WORK/failclosed.nft" \
	&& grep -q 'policy drop' "$WORK/failclosed.nft" \
	&& ok "fail-closed: deny-all floor was loaded" \
	|| bad "fail-closed: floor program missing/incomplete: $(cat "$WORK/failclosed.nft")"
grep -q 'cogbox_divert\|redirect to' "$WORK/failclosed.nft" \
	&& bad "fail-closed: divert table leaked into the fallback floor" \
	|| ok "fail-closed: no divert table in the fallback floor"
grep -q '60000-60031' "$WORK/failclosed.nft" \
	&& bad "fail-closed: mosh rule leaked into the fallback floor" \
	|| ok "fail-closed: no mosh rule in the fallback floor"

# --- 3. parse: real nft accepts both captured programs (if it can run here) ---

# `nft -c` is not a pure parser: once the program declares a table it runs the
# netlink dry-run, which needs CAP_NET_ADMIN over SOME netns. Probe with a real
# table (a bare `flush ruleset` passes unprivileged and proves nothing); if the
# direct run is refused, retry inside a fresh user+net namespace. No usable
# route -> skip loudly; the KVM `nft-floor-bypass` check loads the real script
# on a real kernel and remains the authoritative parse proof.
NFT_RUN=()
if [ -n "$REAL_NFT" ]; then
	cat >"$WORK/probe.nft" <<'PROBE'
table inet cbx_probe {
  chain output { type filter hook output priority mangle; policy accept; }
}
PROBE
	if "$REAL_NFT" -c -f "$WORK/probe.nft" >/dev/null 2>&1; then
		NFT_RUN=("$REAL_NFT")
	elif command -v unshare >/dev/null 2>&1 \
		&& unshare -rn "$REAL_NFT" -c -f "$WORK/probe.nft" >/dev/null 2>&1; then
		NFT_RUN=(unshare -rn "$REAL_NFT")
	fi
fi
if [ "${#NFT_RUN[@]}" -gt 0 ]; then
	# Negative control first: a runner that accepts garbage proves nothing.
	printf 'table inet cbx_bad {\n  chain output { type filter hook output priority mangle; policy accept; bogus verb here; }\n}\n' >"$WORK/bad.nft"
	if "${NFT_RUN[@]}" -c -f "$WORK/bad.nft" >/dev/null 2>&1; then
		bad "parse: real nft -c ACCEPTED a deliberately broken program; the parse case is not discriminating"
	else
		ok "parse: real nft -c rejects a deliberately broken program (control)"
	fi
	for tag in normal failclosed; do
		# An empty capture parses trivially; it means the run never reached nft.
		[ -s "$WORK/$tag.nft" ] || { bad "$tag: captured program is empty, nothing to parse"; continue; }
		if "${NFT_RUN[@]}" -c -f "$WORK/$tag.nft" >"$WORK/$tag.parse" 2>&1; then
			ok "$tag: real nft -c accepts the program (via: ${NFT_RUN[*]})"
		else
			bad "$tag: real nft -c rejected the program: $(cat "$WORK/$tag.parse")"
		fi
	done
else
	echo "skip - no nft on PATH that can run -c here (${REAL_NFT:-none}); parse is proven by the nft-floor-bypass KVM check"
fi

# --- result ----------------------------------------------------------------

if [ "$fails" -eq 0 ]; then
	echo "all nft-divert checks passed"
	exit 0
fi
echo "$fails nft-divert check(s) failed" >&2
exit 1
