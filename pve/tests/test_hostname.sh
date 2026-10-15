#!/usr/bin/env bash
# Behavioural test for cogworx-pve-hostname (pve/hostname.nix): the hostname is
# the control plane's VM name from the SMBIOS blob (`h`), else `cwx-` plus 12
# hex digits of the SMBIOS uuid -- and NEVER the user-chosen instance name.
#
# Usage: test_hostname.sh SCRIPT VECTORS
#   SCRIPT   the realized cogworx-pve-hostname (it carries the emulator for
#            --print-attr); its DMI and hostname paths are redirected through
#            its test seams, so nothing on this machine is renamed
#   VECTORS  pve/testdata/bootcfg-v1.json, for a real encoded serial
set -uo pipefail

fails=0
ok()  { echo "ok   - $*"; }
bad() { echo "FAIL - $*" >&2; fails=$((fails + 1)); }

SCRIPT="${1:?usage: test_hostname.sh SCRIPT VECTORS}"
VECTORS="${2:?usage: test_hostname.sh SCRIPT VECTORS}"
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

UUID=0A1B2C3D-4E5F-4A6B-8C7D-8E9FA0B15010
# The "typical" vector's raw blob carries both i=demo and h=cwx-5010.
python3 -c 'import json,sys; c=[c for c in json.load(open(sys.argv[1]))["cases"] if c["name"]=="typical"][0]; print(c["serial_blob"], end="")' "$VECTORS" > "$ROOT/typical"
grep -q '&h=cwx-5010&i=demo&' "$ROOT/typical" || bad "the typical vector no longer carries both h and i: $(cat "$ROOT/typical")"
# The same blob without `h`: the instance name is still there to be (wrongly) used.
sed 's/&h=cwx-5010//' "$ROOT/typical" > "$ROOT/no-h"
printf '%s\n' "$UUID" > "$ROOT/uuid"

run() {
	: > "$ROOT/hostname"
	COGWORX_DMI_SERIAL_PATH="$1" COGWORX_DMI_UUID_PATH="$2" COGWORX_HOSTNAME_PATH="$ROOT/hostname" \
		"$SCRIPT" > "$ROOT/out" 2>&1
}

if run "$ROOT/typical" "$ROOT/uuid" && [ "$(cat "$ROOT/hostname")" = cwx-5010 ]; then
	ok "the hostname is the blob's cogworx-hostname (the VM name)"
else
	bad "with h=cwx-5010 the hostname became '$(cat "$ROOT/hostname")': $(cat "$ROOT/out")"
fi
if run "$ROOT/no-h" "$ROOT/uuid" && [ "$(cat "$ROOT/hostname")" = cwx-0a1b2c3d4e5f ]; then
	ok "without h, the fallback is cwx- + 12 hex digits of the SMBIOS uuid -- not the instance name the blob still carries"
else
	bad "without h the hostname became '$(cat "$ROOT/hostname")': $(cat "$ROOT/out")"
fi
if run "$ROOT/absent" "$ROOT/uuid" && [ "$(cat "$ROOT/hostname")" = cwx-0a1b2c3d4e5f ]; then
	ok "with no SMBIOS serial at all, the uuid fallback applies"
else
	bad "with no serial the hostname became '$(cat "$ROOT/hostname")': $(cat "$ROOT/out")"
fi
if run "$ROOT/absent" "$ROOT/absent"; then
	bad "with neither a serial nor a uuid the unit succeeded and set '$(cat "$ROOT/hostname")'"
elif [ -s "$ROOT/hostname" ]; then
	bad "with neither a serial nor a uuid the unit still wrote a hostname"
else
	ok "with neither a serial nor a uuid the unit fails loudly and sets nothing"
fi

if [ "$fails" -gt 0 ]; then
	echo "test_hostname: $fails failure(s)" >&2
	exit 1
fi
echo "test_hostname: all passed"
