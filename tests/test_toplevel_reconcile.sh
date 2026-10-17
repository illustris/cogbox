#!/usr/bin/env bash
# Behavioural test for the container's post-boot cogbox-toplevel-reconcile
# oneshot (flake.nix), run against the REAL rendered unit script with its
# cogbox swapped for a stub and nix's sentinel HOME relocated.
#
# `cogbox plugin reconcile` exits 0 even when the toplevel build fails: every
# failure path only warns, and every such warning says "(boot uses baked
# base)". The unit used to `|| true` the verb, so a failed reconcile was
# invisible. It must now print a FAILED line and leave a marker beside the
# instance's toplevel.path (time/rc/attempts, then the tail of the verb's
# output, which carries nix's error), while still never failing the unit.
#
# /homeless-shelter: the pod's nix builds without a sandbox, so a Go
# derivation can create nix's sentinel HOME mid-build and every LATER
# derivation aborts on it. The unit removes it before each attempt and after
# the last, and retries (at most 3 attempts) a failure that left it behind.
#
# Usage: test_toplevel_reconcile.sh <cogbox-toplevel-reconcile unit script>
# Needs: bash, coreutils, gnused, gnugrep.

set -uo pipefail

UNIT="${1:?usage: test_toplevel_reconcile.sh <cogbox-toplevel-reconcile script>}"
[ -f "$UNIT" ] || { echo "FAIL: no such script: $UNIT" >&2; exit 1; }

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

fails=0
ok()   { echo "ok   - $*"; }
bad()  { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

# The verb's real shape: the warning line, then the tail of nix's stderr on the
# lines AFTER it -- so the error itself never carries the matched phrase.
WARN='cogbox plugin: warning: toplevel build: failed (boot uses baked base): building demo-tool'
ERR='error: builder for demo-tool failed with exit code 1'

# The stub cogbox: logs its argv (one line per call) and behaves per
# $STUB_MODE. Warnings go to stderr, as the real verb's do.
# (No /usr/bin/env in the nix build sandbox: the shebang names this bash.)
{ echo "#!$(command -v bash)"; cat <<'STUB_EOF'
echo "$*" >> "$STUB_LOG"
n=$(wc -l < "$STUB_LOG")
warnfail() { echo "$STUB_WARN" >&2; echo "$STUB_ERR" >&2; exit 0; }
case "$STUB_MODE" in
	ok)       echo "cogbox plugin: warning: toplevel build: seeded 3 base narinfo stubs" >&2; exit 0 ;;
	warnfail) warnfail ;;
	exitfail) echo "cogbox plugin: error: no config found" >&2; exit 66 ;;
	go)       [ -e "$STUB_SHELTER" ] && warnfail
	          mkdir -p "$STUB_SHELTER/.config/go/telemetry"; exit 0 ;;
	once)     if [ "$n" = 1 ]; then mkdir -p "$STUB_SHELTER"; warnfail; fi; exit 0 ;;
	killonce) if [ "$n" = 1 ]; then mkdir -p "$STUB_SHELTER"; exit 137; fi; exit 0 ;;
	always)   mkdir -p "$STUB_SHELTER"; warnfail ;;
	long)     for i in $(seq 1 100); do echo "noise $i" >&2; done; warnfail ;;
esac
echo "stub: unknown mode '$STUB_MODE'" >&2
exit 99
STUB_EOF
} > "$W/cogbox"
chmod +x "$W/cogbox"

# Relocate the baked cogbox and the sentinel (the script is tab-indented).
sed -e "s|^\([[:space:]]*\)cbx=.*\$|\1cbx=$W/cogbox|" \
	-e "s|^\([[:space:]]*\)shelter=/homeless-shelter\$|\1shelter=$W/shelter|" \
	"$UNIT" > "$W/unit.sh"
grep -qx "[[:space:]]*cbx=$W/cogbox" "$W/unit.sh" \
	|| { echo "FAIL: the cbx= substitution did not take" >&2; exit 1; }
grep -qx "[[:space:]]*shelter=$W/shelter" "$W/unit.sh" \
	|| { echo "FAIL: the shelter= substitution did not take (no standalone shelter=/homeless-shelter line)" >&2; exit 1; }
if grep -v '^[[:space:]]*#' "$W/unit.sh" | grep -q '/homeless-shelter'; then
	echo "FAIL: a non-comment line still names /homeless-shelter; the test would touch the real root" >&2
	exit 1
fi

CFG="$W/cfg"
mkdir -p "$CFG/cogbox/instances/demo" "$CFG/cogbox/instances/default"

# run TAG MODE [env assignments...]: one unit run; $rc, $W/TAG.{log,out,err}.
run() {
	local tag="$1" mode="$2"; shift 2
	: > "$W/$tag.log"
	env -u COGBOX_INSTANCE XDG_CONFIG_HOME="$CFG" \
		STUB_MODE="$mode" STUB_LOG="$W/$tag.log" STUB_SHELTER="$W/shelter" STUB_WARN="$WARN" STUB_ERR="$ERR" \
		"$@" bash "$W/unit.sh" > "$W/$tag.out" 2> "$W/$tag.err"
	rc=$?
	calls=$(wc -l < "$W/$tag.log")
}
diag() { echo "rc=$rc calls=$calls argv=[$(paste -sd'|' "$W/$1.log")] err: $(cat "$W/$1.err")"; }

mark_demo="$CFG/cogbox/instances/demo/toplevel.reconcile-failed"
mark_default="$CFG/cogbox/instances/default/toplevel.reconcile-failed"

# (a) a clean run: -n <instance>, a stale marker from an earlier failure removed
echo 'time=old rc=1 attempts=1' > "$mark_demo"
run a ok COGBOX_INSTANCE=demo
if [ "$rc" = 0 ] && [ "$(cat "$W/a.log")" = "plugin reconcile -n demo" ] && [ ! -e "$mark_demo" ] \
	&& ! grep -q FAILED "$W/a.err" && grep -q 'seeded 3 base narinfo stubs' "$W/a.err"; then
	ok "a clean reconcile passes -n, re-emits the verb's output and clears a stale marker"
else
	bad "clean run ($(diag a))"
fi

# (b) the default instance: no -n (the verb rejects the reserved name), and the
# marker lands under instances/default -- both with the env unset and =default
rm -f "$mark_default"
run b-unset warnfail
if [ "$rc" = 0 ] && [ "$(cat "$W/b-unset.log")" = "plugin reconcile" ] && [ -f "$mark_default" ]; then
	ok "an unset COGBOX_INSTANCE reconciles the default instance without -n"
else
	bad "unset instance ($(diag b-unset))"
fi
rm -f "$mark_default"
run b-default warnfail COGBOX_INSTANCE=default
if [ "$rc" = 0 ] && [ "$(cat "$W/b-default.log")" = "plugin reconcile" ] && [ -f "$mark_default" ]; then
	ok "COGBOX_INSTANCE=default reconciles without -n"
else
	bad "default instance ($(diag b-default))"
fi
rm -f "$mark_default"

# (c) the verb exits 0 but warned "(boot uses baked base)": a failure, loudly
run c warnfail COGBOX_INSTANCE=demo
if [ "$rc" = 0 ] && [ "$calls" = 1 ] && grep -q 'cogbox-toplevel-reconcile: FAILED rc=0 attempts=1' "$W/c.err" \
	&& grep -qxF "$WARN" "$W/c.err" && [ -f "$mark_demo" ] \
	&& head -n1 "$mark_demo" | grep -qx 'time=.* rc=0 attempts=1' && grep -qxF "$WARN" "$mark_demo" \
	&& grep -qxF "$ERR" "$mark_demo"; then
	ok "a warn-only build failure prints FAILED and writes the marker (time, rc, attempts, warning, nix's error)"
else
	bad "warn-only failure ($(diag c); marker: $(cat "$mark_demo" 2>/dev/null))"
fi

# (d) the verb exits nonzero: a failure too, its rc recorded
rm -f "$mark_demo"
run d exitfail COGBOX_INSTANCE=demo
if [ "$rc" = 0 ] && [ "$calls" = 1 ] && grep -q 'cogbox-toplevel-reconcile: FAILED rc=66 attempts=1' "$W/d.err" \
	&& head -n1 "$mark_demo" 2>/dev/null | grep -qx 'time=.* rc=66 attempts=1' \
	&& grep -qxF 'cogbox plugin: error: no config found' "$mark_demo"; then
	ok "a nonzero exit prints FAILED rc=66 and records it with the verb's reason, and the unit still exits 0"
else
	bad "nonzero exit ($(diag d); marker: $(cat "$mark_demo" 2>/dev/null))"
fi
rm -f "$mark_demo"

# (e) a sentinel left by an EARLIER build is removed before the run
mkdir -p "$W/shelter"
run e go COGBOX_INSTANCE=demo
if [ "$rc" = 0 ] && [ "$calls" = 1 ] && ! grep -q FAILED "$W/e.err" && [ ! -e "$mark_demo" ] \
	&& [ ! -e "$W/shelter" ]; then
	ok "a pre-existing /homeless-shelter is removed before the build, and the one it leaves after"
else
	bad "pre-existing sentinel ($(diag e); shelter: $([ -e "$W/shelter" ] && echo present || echo absent))"
fi
rm -rf "$W/shelter"

# (f) the first attempt fails AND leaves the sentinel: one retry, which succeeds
run f once COGBOX_INSTANCE=demo
if [ "$rc" = 0 ] && [ "$calls" = 2 ] && grep -q 'left .* behind; retrying' "$W/f.err" \
	&& ! grep -q FAILED "$W/f.err" && [ ! -e "$mark_demo" ] && [ ! -e "$W/shelter" ]; then
	ok "a failure that left the sentinel behind is retried once and succeeds"
else
	bad "retry ($(diag f))"
fi
rm -rf "$W/shelter" "$mark_demo"

# (f2) the same for a NONZERO exit (an OOM-killed verb mid-build): retried too
run f2 killonce COGBOX_INSTANCE=demo
if [ "$rc" = 0 ] && [ "$calls" = 2 ] && grep -q 'left .* behind; retrying' "$W/f2.err" \
	&& ! grep -q FAILED "$W/f2.err" && [ ! -e "$mark_demo" ] && [ ! -e "$W/shelter" ]; then
	ok "a nonzero exit that left the sentinel behind is retried once and succeeds"
else
	bad "retry after a nonzero exit ($(diag f2))"
fi
rm -rf "$W/shelter" "$mark_demo"

# (g) bounded: the sentinel reappears every time -> exactly 3 attempts, then FAILED
run g always COGBOX_INSTANCE=demo
if [ "$rc" = 0 ] && [ "$calls" = 3 ] && grep -q 'cogbox-toplevel-reconcile: FAILED rc=0 attempts=3' "$W/g.err" \
	&& head -n1 "$mark_demo" 2>/dev/null | grep -qx 'time=.* rc=0 attempts=3' && [ ! -e "$W/shelter" ]; then
	ok "the retry is bounded at 3 attempts and the sentinel is still cleaned up"
else
	bad "bounded retry ($(diag g); shelter: $([ -e "$W/shelter" ] && echo present || echo absent))"
fi
rm -rf "$W/shelter" "$mark_demo"

# (g2) the marker holds a BOUNDED tail of the output, ending with nix's error
run g2 long COGBOX_INSTANCE=demo
if [ "$rc" = 0 ] && [ "$calls" = 1 ] && [ "$(wc -l < "$mark_demo")" = 41 ] \
	&& [ "$(tail -n1 "$mark_demo")" = "$ERR" ] && grep -qxF "$WARN" "$mark_demo" \
	&& ! grep -qx 'noise 1' "$mark_demo"; then
	ok "the marker keeps the last 40 output lines (the warning and nix's error), not the whole log"
else
	bad "bounded marker ($(diag g2); marker lines: $(wc -l < "$mark_demo" 2>/dev/null))"
fi
rm -f "$mark_demo"

# (h) the marker cannot be written (no config dir): still never fails the unit,
# and the failed redirect adds no shell noise after the FAILED line
run h warnfail COGBOX_INSTANCE=demo XDG_CONFIG_HOME="$W/missing"
if [ "$rc" = 0 ] && [ "$calls" = 1 ] && grep -q 'cogbox-toplevel-reconcile: FAILED' "$W/h.err" \
	&& ! grep -q 'No such file' "$W/h.err" && [ ! -e "$W/missing" ]; then
	ok "an unwritable marker still leaves the unit green with the FAILED line, and nothing else"
else
	bad "unwritable marker ($(diag h))"
fi

if [ "$fails" -gt 0 ]; then
	echo "$fails check(s) failed" >&2
	exit 1
fi
echo "all toplevel-reconcile checks passed"
