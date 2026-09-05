#!/usr/bin/env bash
set -euo pipefail

# Test harness for rule reloading via SIGUSR1.
# Starts passt with LD_PRELOAD (no VM), triggers reload, checks survival.
# Requires passt built with EXTRA_SYSCALLS=rt_sigreturn.
#
# Usage: test-reload.sh <libnetfilter.so> <passt-binary>
#
# Manual check for the mosh reply-socket exemption (not scripted here: it
# needs a routable non-loopback address on the box). Run passt under the
# shim with the knob and a matching forward, e.g.
#   COGBOX_MOSH_UDP_FORWARD=60000-60031 NETFILTER_RULES=<deny-all rules> \
#   LD_PRELOAD=<libnetfilter.so> passt --foreground -u <addr>/60000-60031 ...
# then from another host `echo hi | nc -u <addr> 60005`: passt's stderr must
# NOT show "Couldn't connect flow socket" (the reply socket is bound to
# <addr>:60005, so the shim let its connect through). A guest-side
# `nc -u -p 60005 <off-range host>` is bound to 0.0.0.0:60005, which the
# exemption rejects: passt's connect gets ENETUNREACH from the shim, logs
# "Couldn't connect flow socket" at debug, and silently drops the guest's
# datagram -- the guest sees no reply, not an errno of its own. With the knob
# unset the first probe logs the connect failure exactly as before.

if [ $# -lt 2 ]; then
	echo "Usage: $0 <path-to-libnetfilter.so> <path-to-passt>"
	exit 1
fi

LIB="$1"
PASST="$2"

TESTDIR=$(mktemp -d)
trap 'kill "$PASST_PID" 2>/dev/null || true; rm -rf "$TESTDIR"' EXIT

RULES="$TESTDIR/rules"
SOCK="$TESTDIR/passt.sock"

echo "=== Test 1: passt starts with initial rules ==="
echo "deny 0.0.0.0/0" > "$RULES"

NETFILTER_RULES="$RULES" LD_PRELOAD="$LIB" \
	"$PASST" --foreground --socket "$SOCK" &
PASST_PID=$!
sleep 2

if ! kill -0 "$PASST_PID" 2>/dev/null; then
	echo "FAIL: passt died during startup"
	exit 1
fi
echo "PASS: passt started (PID $PASST_PID)"

echo ""
echo "=== Test 2: SIGUSR1 reload ==="
echo "allow 0.0.0.0/0" > "$RULES"
kill -USR1 "$PASST_PID"
sleep 1

if ! kill -0 "$PASST_PID" 2>/dev/null; then
	echo "FAIL: passt died after SIGUSR1"
	wait "$PASST_PID" 2>/dev/null || true
	exit 1
fi
echo "PASS: passt survived SIGUSR1 reload"

echo ""
echo "=== Test 3: multiple rapid reloads ==="
for i in 1 2 3 4 5; do
	printf 'deny 10.0.0.0/8\nallow 0.0.0.0/0\n' > "$RULES"
	kill -USR1 "$PASST_PID"
done
sleep 1

if ! kill -0 "$PASST_PID" 2>/dev/null; then
	echo "FAIL: passt died after rapid reloads"
	wait "$PASST_PID" 2>/dev/null || true
	exit 1
fi
echo "PASS: passt survived 5 rapid reloads"

echo ""
echo "=== Test 4: clean shutdown ==="
kill "$PASST_PID" 2>/dev/null || true
wait "$PASST_PID" 2>/dev/null || true
echo "PASS: passt shut down"

echo ""
echo "All tests passed."
