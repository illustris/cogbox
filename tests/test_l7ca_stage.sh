#!/usr/bin/env bash
# Behavioural test for cogbox-launch.sh's L7 terminate CA: the pre-mint, the
# wait for mitmdump, and the fw_cfg staging, run without a VM.
#
# The guest reads the fw_cfg CA slot (opt/system-l7ca) exactly ONCE per boot,
# so whatever start_l7mitm leaves in $RUNTIME/system-l7ca when it returns is
# what the guest trusts for that whole boot. A cold first boot used to wait on
# mitmproxy's own CA mint, which sits behind a cold Python import, time out,
# stage nothing and print a warning that was not true; every terminate-tier
# HTTPS host then failed certificate verification until a restart. This test
# runs the launcher's REAL start_l7mitm region (with the l7ca_premint helper it
# calls) against stub and real mitmdumps and pins:
#
#   T1  a cold start with a mitmdump that never mints returns quickly with the
#       pre-minted cert staged: mitmproxy's confdir layout (key then cert, key
#       0600), a CA cert with the right extensions and a backdated notBefore,
#       no warning, no openssl noise, no temp files. Fails on the old launcher.
#   T2  a rerun never rotates the CA (existing instances keep their
#       fingerprint).
#   T3  a store with only mitmproxy-ca.pem gets its cert derived and staged.
#   T4a a failed pre-mint plus a mitmdump that exits at once: both warnings say
#       what happened, nothing is staged, and the old "blocked" text is gone.
#   T4b a mitmdump that exits at once after a working pre-mint: the CA is
#       still staged.
#   T5  a real mitmdump adopts the pre-minted store byte-identical, and a
#       client trusting only the staged cert completes a terminate-tier
#       request (an unrelated CA gets curl exit 60).
#   T6  a failed pre-mint falls back to mitmproxy minting, which is staged.
#   T7  under a runas wrapper (how the gcp and PVE images run the proxies)
#       every openssl call, the mitmdump launch and the staging read run as the
#       proxy uid.
#   T8  a cert file that contains a private key is refused and never staged.
#   T9  Darwin's listener wait running out still stages the pre-minted CA and
#       says mitmproxy is still starting.
#   T10 no CA at all by the end of the wait says the guest will not trust
#       terminate-tier hosts.
#
# T9 and T10 run the wait loop to the end of its budget; the driver stubs
# `sleep` for those two cases only, so the 100 or 400 passes take no time.
#
# Usage: test_l7ca_stage.sh <path-to-cogbox-launch.sh>
# Needs: bash, coreutils, gnugrep, gawk, openssl, mitmproxy (mitmdump), curl.

set -uo pipefail

LAUNCH="${1:?usage: test_l7ca_stage.sh <cogbox-launch.sh>}"
[ -f "$LAUNCH" ] || { echo "FAIL: no such script: $LAUNCH" >&2; exit 1; }
for tool in gawk openssl mitmdump curl sha256sum; do
	command -v "$tool" >/dev/null 2>&1 || { echo "FAIL: $tool is not on PATH" >&2; exit 1; }
done
REAL_OPENSSL=$(command -v openssl)
REAL_MITMDUMP=$(command -v mitmdump)

WORK=$(mktemp -d)
cleanup() {
	local f
	for f in "$WORK"/*/rt/l7mitm.pid; do
		[ -s "$f" ] && kill "$(cat "$f")" 2>/dev/null
	done
	rm -rf "$WORK"
}
trap cleanup EXIT

fails=0
ok()   { echo "ok   - $*"; }
bad()  { echo "FAIL - $*" >&2; fails=$((fails + 1)); }
# expect <ok text> <fail text> <command...>
expect() {
	local yes="$1" no="$2"
	shift 2
	if "$@"; then ok "$yes"; else bad "$no"; fi
}

# The region under test, cut out of the launcher by string index (the pattern
# tests/test_runtime_base.py uses): from the L7 terminate backend header to the
# auth proxy header. That span holds l7ca_premint and start_l7mitm.
START_MARK='# -- Helper: start the L7 terminate backend'
END_MARK='# -- Helper: start the per-sandbox auth proxy'
gawk -v s="$START_MARK" -v e="$END_MARK" 'BEGIN { RS = "^$" } {
	i = index($0, s); if (!i) exit 3
	r = substr($0, i); j = index(r, e); if (!j) exit 4
	printf "%s", substr(r, 1, j - 1)
}' "$LAUNCH" > "$WORK/region.sh" \
	|| { echo "FAIL: could not cut the start_l7mitm region out of $LAUNCH" >&2; exit 1; }
grep -q '^start_l7mitm() {' "$WORK/region.sh" \
	|| { echo "FAIL: the cut region does not define start_l7mitm; this test is vacuous" >&2; exit 1; }

# -- Stubs ---------------------------------------------------------------------
STUBS="$WORK/stubs"
mkdir -p "$STUBS"
shebang() { printf '#!%s\n' "$BASH"; }

# A mitmdump that stays alive and never mints: a cold import that has not got
# as far as the CA yet.
{ shebang; echo 'exec sleep 30'; } > "$STUBS/mitm-alive"
# A mitmdump that dies at once.
{ shebang; echo 'exit 1'; } > "$STUBS/mitm-exit"
# A mitmdump that mints its own cert (cert only) 0.3 s in, then stays alive.
{ shebang; cat <<'STUB'
confdir=""
for a in "$@"; do
	case "$a" in confdir=*) confdir="${a#confdir=}" ;; esac
done
sleep 0.3
"$REAL_OPENSSL" req -quiet -config /dev/null -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
	-noenc -days 1 -subj /CN=stub-minted -keyout "$confdir/stub.key" -out "$confdir/.stub-cert.tmp" 2>/dev/null
mv -f "$confdir/.stub-cert.tmp" "$confdir/mitmproxy-ca-cert.pem"
exec sleep 30
STUB
} > "$STUBS/mitm-mint"
# The runas wrapper T7 puts in PROXY_RUNAS_ARGS: logs its argv, then marks
# everything it runs.
{ shebang; cat <<'STUB'
printf '%s\n' "$*" >> "$RUNAS_LOG"
RUNAS_ACTIVE=1 exec "$@"
STUB
} > "$STUBS/runas"
# An openssl that logs whether it runs under the runas wrapper.
{ shebang; cat <<'STUB'
printf 'runas=%s\n' "${RUNAS_ACTIVE:-0}" >> "$OPENSSL_LOG"
exec "$REAL_OPENSSL" "$@"
STUB
} > "$STUBS/openssl-logged"
chmod 0755 "$STUBS"/*
export REAL_OPENSSL

# A 3-line addon for the real mitmdump: answer every request with 200, so a
# terminate-tier request completes without any upstream.
cat > "$WORK/addon.py" <<'PY'
from mitmproxy import http
def request(flow):
    flow.response = http.Response.make(200, b"ok\n", {"content-type": "text/plain"})
PY

# -- Driver --------------------------------------------------------------------
# The region runs in its own bash, without set -e/-u (the launcher has neither),
# with the launcher globals it reads and stubs for the three functions it calls
# that live elsewhere in the launcher.
cat > "$WORK/driver.sh" <<'DRIVER'
cogbox_control_poll() { :; }
port_taken() { return 1; }
die() { printf '%s\n' "$1" > "$RUNTIME/die.msg"; exit "${2:-70}"; }
if [ -n "$TEST_FAST_SLEEP" ]; then sleep() { :; }; fi
HOST_DARWIN="$TEST_DARWIN"
PROXY_RUNAS_ARGS=()
[ -n "${TEST_RUNAS:-}" ] && PROXY_RUNAS_ARGS=("$TEST_RUNAS")
unset COGBOX_L7_INJECT_CONF
. "$TEST_REGION"
start_l7mitm
DRIVER

# run_case <tag> <icd> <openssl> <mitmdump> [<runas>]
# Runs start_l7mitm with a fresh runtime dir and the given instance config dir.
# CASE_DARWIN=1 runs the Darwin branch, CASE_FAST_SLEEP=1 stubs the loop's sleep.
# Sets RT, CA, ERR, RC and MS (wall time in ms).
CASE_DARWIN=0 CASE_FAST_SLEEP=""
run_case() {
	local tag="$1" icd="$2" openssl="$3" mitmdump="$4" runas="${5:-}"
	RT="$WORK/$tag/rt"
	CA="$icd/l7-ca"
	ERR="$WORK/$tag/stderr"
	mkdir -p "$RT" "$icd"
	: > "$RT/system-l7ca"
	local sub
	sub=$(cat "$WORK/region.sh")
	sub=${sub//@openssl@/"$openssl"}
	sub=${sub//@mitmdump@/"$mitmdump"}
	sub=${sub//@l7addon@/"$WORK/addon.py"}
	if grep -qE '@[A-Za-z0-9]+@' <<< "$sub"; then
		bad "$tag: the region carries an unsubstituted placeholder: $(grep -oE '@[A-Za-z0-9]+@' <<< "$sub" | sort -u | tr '\n' ' ')"
	fi
	printf '%s\n' "$sub" > "$WORK/$tag/region.sh"
	local t0
	t0=$(date +%s%N)
	RUNTIME="$RT" INSTANCE_CONFIG_DIR="$icd" L7_MITM_PORT="${MITM_PORT:-1}" L7_AUTH_PORT=2 \
	TEST_REGION="$WORK/$tag/region.sh" TEST_RUNAS="$runas" \
	TEST_DARWIN="$CASE_DARWIN" TEST_FAST_SLEEP="$CASE_FAST_SLEEP" \
		bash "$WORK/driver.sh" > "$WORK/$tag/stdout" 2> "$ERR" < /dev/null
	RC=$?
	MS=$(( ($(date +%s%N) - t0) / 1000000 ))
}

stop_mitm() {
	local pid
	pid=$(cat "$RT/l7mitm.pid" 2>/dev/null) || return 0
	[ -n "$pid" ] || return 0
	kill "$pid" 2>/dev/null
	local _
	for _ in $(seq 1 50); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	: > "$RT/l7mitm.pid"
}

staged_is_cert() { # <tag>
	if [ ! -s "$RT/system-l7ca" ]; then
		bad "$1: nothing was staged into system-l7ca"
	elif ! cmp -s "$RT/system-l7ca" "$CA/mitmproxy-ca-cert.pem"; then
		bad "$1: system-l7ca differs from l7-ca/mitmproxy-ca-cert.pem"
	elif ! grep -q 'BEGIN CERTIFICATE' "$RT/system-l7ca" || grep -q 'PRIVATE KEY' "$RT/system-l7ca"; then
		bad "$1: system-l7ca is not a bare certificate"
	else
		ok "$1: the CA cert is staged into system-l7ca"
	fi
}

no_word() { # <tag> <word>
	if grep -q -- "$2" "$ERR"; then
		bad "$1: stderr says '$2': $(cat "$ERR")"
	else
		ok "$1: stderr never says '$2'"
	fi
}

has_line() { # <tag> <fixed text> <what>
	if grep -qF -- "$2" "$ERR"; then
		ok "$1: $3"
	else
		bad "$1: $3 -- missing '$2' in stderr: $(cat "$ERR")"
	fi
}

PREMINT_WARN='could not pre-mint the L7 CA; mitmproxy will mint it'

# --- T1: cold start, mitmdump alive but has not minted ------------------------

ICD1="$WORK/t1/icd"
run_case t1 "$ICD1" "$REAL_OPENSSL" "$STUBS/mitm-alive"
stop_mitm
[ "$RC" = 0 ] || bad "t1: start_l7mitm exited $RC"
if [ "$MS" -lt 3000 ]; then
	ok "t1: start_l7mitm returned in ${MS} ms"
else
	bad "t1: start_l7mitm took ${MS} ms waiting for a mitmdump that never mints (expected < 3000)"
fi
staged_is_cert t1
store="$CA/mitmproxy-ca.pem"
if [ ! -s "$store" ]; then
	bad "t1: no mitmproxy-ca.pem was minted"
else
	mode=$(stat -c %a "$store")
	expect "t1: mitmproxy-ca.pem is mode 0600" "t1: mitmproxy-ca.pem is mode $mode, expected 600" \
		[ "$mode" = 600 ]
	if head -n1 "$store" | grep -q -- '-----BEGIN .*PRIVATE KEY-----'; then
		ok "t1: mitmproxy-ca.pem starts with the private key"
	else
		bad "t1: mitmproxy-ca.pem does not start with a PRIVATE KEY block (mitmproxy loads the key from it)"
	fi
	if [ "$(grep -c 'BEGIN CERTIFICATE' "$store")" = 1 ] \
		&& sed -n '/-----BEGIN CERTIFICATE-----/,$p' "$store" | cmp -s - "$CA/mitmproxy-ca-cert.pem"; then
		ok "t1: mitmproxy-ca.pem ends with exactly the staged cert (key then cert)"
	else
		bad "t1: mitmproxy-ca.pem does not end with exactly mitmproxy-ca-cert.pem"
	fi
fi
if [ -s "$CA/mitmproxy-ca-cert.pem" ]; then
	exts=$("$REAL_OPENSSL" x509 -in "$CA/mitmproxy-ca-cert.pem" -noout -ext basicConstraints,keyUsage 2>&1)
	if grep -q 'CA:TRUE' <<< "$exts" && grep -q 'Certificate Sign' <<< "$exts"; then
		ok "t1: the cert is a CA (CA:TRUE, Certificate Sign)"
	else
		bad "t1: the cert is not a signing CA: $exts"
	fi
	nb=$("$REAL_OPENSSL" x509 -in "$CA/mitmproxy-ca-cert.pem" -noout -startdate | cut -d= -f2-)
	nb_s=$(date -u -d "$nb" +%s 2>/dev/null || echo 0)
	if [ "$nb_s" -gt 0 ] && [ $(( $(date -u +%s) - nb_s )) -ge 86400 ]; then
		ok "t1: notBefore ($nb) is backdated at least a day"
	else
		bad "t1: notBefore ($nb) is not backdated at least a day; a host clock stepping back would make the CA not yet valid"
	fi
fi
if [ -s "$ERR" ]; then
	bad "t1: stderr is not empty: $(cat "$ERR")"
else
	ok "t1: stderr is empty (no warning, no openssl output)"
fi
leftover=$(compgen -G "$CA/.mitmproxy-ca*.tmp")
expect "t1: no temp files left in l7-ca" "t1: temp files left behind: $leftover" [ -z "$leftover" ]
[ ! -e "$RT/die.msg" ] || bad "t1: died: $(cat "$RT/die.msg")"

# --- T2: rerun never rotates --------------------------------------------------

if [ -s "$ICD1/l7-ca/mitmproxy-ca.pem" ]; then
	h_key=$(sha256sum < "$ICD1/l7-ca/mitmproxy-ca.pem")
	h_cert=$(sha256sum < "$ICD1/l7-ca/mitmproxy-ca-cert.pem")
	run_case t2 "$ICD1" "$REAL_OPENSSL" "$STUBS/mitm-alive"
	stop_mitm
	if [ "$h_key" = "$(sha256sum < "$CA/mitmproxy-ca.pem")" ] \
		&& [ "$h_cert" = "$(sha256sum < "$CA/mitmproxy-ca-cert.pem")" ]; then
		ok "t2: a rerun keeps mitmproxy-ca.pem and the cert byte-identical (no rotation)"
	else
		bad "t2: a rerun rewrote the CA store; existing instances would lose their CA fingerprint"
	fi
	staged_is_cert t2
	[ -s "$ERR" ] && bad "t2: stderr is not empty: $(cat "$ERR")"
else
	bad "t2: skipped, T1 minted no store"
fi

# --- T3: partial store, cert derived ------------------------------------------

if [ -s "$ICD1/l7-ca/mitmproxy-ca.pem" ]; then
	ICD3="$WORK/t3/icd"
	mkdir -p "$ICD3/l7-ca"
	cp "$ICD1/l7-ca/mitmproxy-ca.pem" "$ICD3/l7-ca/"
	h_key=$(sha256sum < "$ICD3/l7-ca/mitmproxy-ca.pem")
	run_case t3 "$ICD3" "$REAL_OPENSSL" "$STUBS/mitm-alive"
	stop_mitm
	if [ -s "$CA/mitmproxy-ca-cert.pem" ] \
		&& cmp -s "$CA/mitmproxy-ca-cert.pem" <("$REAL_OPENSSL" x509 -in "$CA/mitmproxy-ca.pem"); then
		ok "t3: the missing cert is derived from mitmproxy-ca.pem"
	else
		bad "t3: the cert was not derived from mitmproxy-ca.pem"
	fi
	[ "$h_key" = "$(sha256sum < "$CA/mitmproxy-ca.pem")" ] \
		|| bad "t3: deriving the cert rewrote mitmproxy-ca.pem"
	staged_is_cert t3
	[ -s "$ERR" ] && bad "t3: stderr is not empty: $(cat "$ERR")"
else
	bad "t3: skipped, T1 minted no store"
fi

# --- T4a: failed pre-mint, mitmdump exits at once -----------------------------

run_case t4a "$WORK/t4a/icd" false "$STUBS/mitm-exit"
stop_mitm
has_line t4a "$PREMINT_WARN" "a failed pre-mint says mitmproxy will mint"
has_line t4a "L7 terminate backend (mitmproxy) exited during startup" "the exit is reported"
has_line t4a "terminate-tier HTTPS hosts will be refused" "the exit warning says hosts are refused"
no_word t4a blocked
expect "t4a: system-l7ca stays empty" "t4a: something was staged with no CA: $(head -c 200 "$RT/system-l7ca")" \
	[ ! -s "$RT/system-l7ca" ]

# --- T4b: mitmdump exits at once after a working pre-mint ---------------------

run_case t4b "$WORK/t4b/icd" "$REAL_OPENSSL" "$STUBS/mitm-exit"
stop_mitm
staged_is_cert t4b
no_word t4b blocked

# --- T5: a real mitmdump adopts the store and serves with it ------------------

MITM_PORT=$(( 20000 + RANDOM % 20000 ))
run_case t5 "$WORK/t5/icd" "$REAL_OPENSSL" "$REAL_MITMDUMP"
staged_is_cert t5
h_key=$(sha256sum < "$CA/mitmproxy-ca.pem" 2>/dev/null)
code="" deadline=$(( $(date +%s) + 30 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
	code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
		--socks5-hostname "127.0.0.1:$MITM_PORT" --cacert "$RT/system-l7ca" \
		https://example.test/ 2>/dev/null)
	[ "$code" = 200 ] && break
	sleep 0.2
done
if [ "$code" = 200 ]; then
	ok "t5: curl trusting only the staged cert gets 200 through the real mitmdump"
	"$REAL_OPENSSL" req -quiet -config /dev/null -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
		-noenc -days 1 -subj /CN=unrelated -keyout "$WORK/t5/other.key" -out "$WORK/t5/other.pem" 2>/dev/null
	curl -sS -o /dev/null --max-time 10 --socks5-hostname "127.0.0.1:$MITM_PORT" \
		--cacert "$WORK/t5/other.pem" https://example.test/ 2>/dev/null
	rc=$?
	expect "t5: curl trusting an unrelated CA fails verification (exit 60)" \
		"t5: curl trusting an unrelated CA exited $rc, expected 60" [ "$rc" = 60 ]
else
	bad "t5: no 200 through the real mitmdump within 30 s (last code '$code'); mitmdump stderr: $(cat "$ERR")"
fi
if [ -n "$h_key" ] && [ "$h_key" = "$(sha256sum < "$CA/mitmproxy-ca.pem")" ]; then
	ok "t5: mitmdump adopted mitmproxy-ca.pem byte-identical"
else
	bad "t5: mitmproxy-ca.pem changed after mitmdump ran (it re-minted instead of adopting)"
fi
stop_mitm
MITM_PORT=1

# --- T6: failed pre-mint falls back to mitmproxy's own mint -------------------

run_case t6 "$WORK/t6/icd" false "$STUBS/mitm-mint"
stop_mitm
has_line t6 "$PREMINT_WARN" "a failed pre-mint says mitmproxy will mint"
if grep -v -F -- "$PREMINT_WARN" "$ERR" | grep -q .; then
	bad "t6: unexpected stderr after the pre-mint warning: $(cat "$ERR")"
else
	ok "t6: no further warning once mitmproxy minted"
fi
if grep -q 'stub-minted' <("$REAL_OPENSSL" x509 -in "$RT/system-l7ca" -noout -subject 2>/dev/null); then
	ok "t6: the mitmproxy-minted cert is staged"
else
	bad "t6: the mitmproxy-minted cert was not staged"
fi
staged_is_cert t6

# --- T7: the runas path -------------------------------------------------------

export RUNAS_LOG="$WORK/t7.runas.log" OPENSSL_LOG="$WORK/t7.openssl.log"
: > "$RUNAS_LOG"; : > "$OPENSSL_LOG"
ICD7="$WORK/t7/icd"
run_case t7 "$ICD7" "$STUBS/openssl-logged" "$STUBS/mitm-alive" "$STUBS/runas"
stop_mitm
if [ -s "$OPENSSL_LOG" ] && ! grep -qv '^runas=1$' "$OPENSSL_LOG"; then
	ok "t7: every openssl call ran under the runas wrapper ($(wc -l < "$OPENSSL_LOG") calls)"
else
	bad "t7: openssl ran outside the runas wrapper: $(tr '\n' ' ' < "$OPENSSL_LOG")"
fi
expect "t7: the pre-mint script ran under the runas wrapper" \
	"t7: no 'l7ca-premint $ICD7/l7-ca' invocation in the runas log" \
	grep -qF "l7ca-premint $ICD7/l7-ca " "$RUNAS_LOG"
expect "t7: mitmdump ran under the runas wrapper" "t7: no mitmdump invocation in the runas log" \
	grep -qF "$STUBS/mitm-alive --mode socks5@" "$RUNAS_LOG"
expect "t7: the staging read ran under the runas wrapper" \
	"t7: no 'cat $ICD7/l7-ca/mitmproxy-ca-cert.pem' in the runas log" \
	grep -qxF "cat $ICD7/l7-ca/mitmproxy-ca-cert.pem" "$RUNAS_LOG"
staged_is_cert t7
[ -s "$ERR" ] && bad "t7: stderr is not empty: $(cat "$ERR")"

# --- T8: a cert file holding a private key is never staged --------------------

if [ -s "$ICD1/l7-ca/mitmproxy-ca.pem" ]; then
	ICD8="$WORK/t8/icd"
	mkdir -p "$ICD8/l7-ca"
	cp "$ICD1/l7-ca/mitmproxy-ca.pem" "$ICD8/l7-ca/mitmproxy-ca.pem"
	cp "$ICD1/l7-ca/mitmproxy-ca.pem" "$ICD8/l7-ca/mitmproxy-ca-cert.pem"
	run_case t8 "$ICD8" "$REAL_OPENSSL" "$STUBS/mitm-alive"
	stop_mitm
	if [ "$RC" = 70 ] && grep -q 'refusing to stage L7 CA' "$RT/die.msg" 2>/dev/null; then
		ok "t8: a cert file holding a private key is refused"
	else
		bad "t8: no refusal for a cert file holding a private key (rc $RC)"
	fi
	expect "t8: system-l7ca stays empty" "t8: system-l7ca holds the refused file" [ ! -s "$RT/system-l7ca" ]
else
	bad "t8: skipped, T1 minted no store"
fi

# --- T9: Darwin listener wait runs out, CA pre-minted -------------------------

CASE_DARWIN=1 CASE_FAST_SLEEP=1
run_case t9 "$WORK/t9/icd" "$REAL_OPENSSL" "$STUBS/mitm-alive"
CASE_DARWIN=0 CASE_FAST_SLEEP=""
stop_mitm
staged_is_cert t9
has_line t9 "L7 terminate backend (mitmproxy) is still starting; terminate-tier HTTPS hosts are refused until it listens" \
	"a listener timeout says mitmproxy is still starting"
if [ "$(grep -c . "$ERR")" = 1 ]; then
	ok "t9: that is the only warning"
else
	bad "t9: expected exactly one warning, got: $(cat "$ERR")"
fi
no_word t9 blocked

# --- T10: no CA by the end of the wait ----------------------------------------

CASE_FAST_SLEEP=1
run_case t10 "$WORK/t10/icd" false "$STUBS/mitm-alive"
CASE_FAST_SLEEP=""
stop_mitm
has_line t10 "$PREMINT_WARN" "a failed pre-mint says mitmproxy will mint"
has_line t10 "L7 terminate CA did not appear in time; the guest will not trust terminate-tier HTTPS hosts (certificate verification fails)" \
	"a missing CA says the guest will not trust terminate-tier hosts"
no_word t10 blocked
expect "t10: system-l7ca stays empty" "t10: something was staged with no CA" [ ! -s "$RT/system-l7ca" ]

echo
if [ "$fails" -eq 0 ]; then
	echo "all L7 CA staging checks passed"
else
	echo "$fails L7 CA staging check(s) FAILED" >&2
	exit 1
fi
