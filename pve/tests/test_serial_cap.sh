#!/usr/bin/env bash
# Behavioural test for cogworx-pve-serial-cap (pve/platform.nix): the serial
# log FILE cogworxd reads through QGA is trimmed past 256 KiB to (at most) the
# last 128 KiB, starting on a line boundary, keeping its newest line and mode
# 0600; below the cap it is left alone.
#
# Usage: test_serial_cap.sh SCRIPT   (the realized cogworx-pve-serial-cap)
set -uo pipefail

fails=0
ok()  { echo "ok   - $*"; }
bad() { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

SCRIPT="${1:?usage: test_serial_cap.sh SCRIPT}"
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
LOG="$ROOT/serial.log"
cap() { COGWORX_SERIAL="$LOG" "$SCRIPT" > "$ROOT/out" 2>&1; }

# Below the cap: untouched.
for i in $(seq 1 100); do printf 'cogworx: line %06d of a short log\n' "$i"; done > "$LOG"
chmod 0600 "$LOG"
cp "$LOG" "$ROOT/before"
if cap && cmp -s "$LOG" "$ROOT/before"; then ok "a log below the cap is left alone"; else bad "a short log was changed: $(cat "$ROOT/out")"; fi

# Above the cap: ~300 KiB of 40-byte lines.
for i in $(seq 1 7700); do printf 'cogworx: line %06d xxxxxxxxxxxxxxxxxx\n' "$i"; done > "$LOG"
chmod 0644 "$LOG"
before=$(stat -c %s "$LOG")
if cap; then ok "a $before-byte log is capped"; else bad "the cap failed: $(cat "$ROOT/out")"; fi
after=$(stat -c %s "$LOG")
if [ "$after" -le $((128 * 1024)) ] && [ "$after" -gt $((120 * 1024)) ]; then ok "it keeps about the last 128 KiB ($after bytes)"; else bad "it kept $after bytes"; fi
if head -n1 "$LOG" | grep -qx 'cogworx: line [0-9]\{6\} x\{18\}'; then ok "the kept tail starts on a whole line"; else bad "the first kept line is a fragment: $(head -n1 "$LOG")"; fi
if [ "$(tail -n1 "$LOG")" = 'cogworx: line 007700 xxxxxxxxxxxxxxxxxx' ]; then ok "the newest line is kept"; else bad "the last line is $(tail -n1 "$LOG")"; fi
if [ "$(stat -c %a "$LOG")" = 600 ]; then ok "the capped file is 0600"; else bad "the capped file is $(stat -c %a "$LOG")"; fi
left=$(find "$ROOT" -name 'serial.log.*')
if [ -z "$left" ]; then ok "no temp file left behind"; else bad "temp file(s) left: $left"; fi
# An absent log is not an error (nothing has been emitted yet this boot).
rm -f "$LOG"
if cap && [ ! -e "$LOG" ]; then ok "an absent log is a no-op"; else bad "an absent log: $(cat "$ROOT/out")"; fi

if [ "$fails" -gt 0 ]; then
	echo "test_serial_cap: $fails failure(s)" >&2
	exit 1
fi
echo "test_serial_cap: all passed"
