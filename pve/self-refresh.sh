# shellcheck shell=bash
# cogworx-pve-self-refresh: make cogbox's recorded bindAddr and selfAddrs match
# THIS boot's DHCP address, before the supervisor launches the sandbox.
#
# WHY. `cogbox init` writes .bindAddr (the address passt binds the guest SSH
# and HTTP forwards on) and .network.selfAddrs (l7proxy's self-address floor)
# ONLY into a fresh config.json, and `cogbox start` reads .bindAddr back at
# every launch. On GCE the address is stable for the instance's life. On PVE it
# is a DHCP lease, so a lease that changes across a stop/start would leave
# every forward bound to an address the VM no longer has: the sandbox comes up
# "healthy" and unreachable. supervise.sh hands init the current address, but
# init does not rewrite an existing config, so the refresh has to happen here.
#
# WHAT. Under the SAME per-instance config lock cogbox's launcher and CLI take
# ($XDG_CONFIG_HOME/cogbox/.locks/<instance>.lock, flock exclusive), rewrite
# config.json atomically (temp file in the same directory, fsync, rename):
#   .bindAddr              = the current address
#   .network.selfAddrs     = the old entries plus "<address>/32" (a UNION:
#                            dropping an old address would only narrow
#                            l7proxy's refusal set, never widen what the guest
#                            can reach -- keeping it is the safe direction)
# selfAddrs is a rules-mode key; in full/none mode .network is a bare string
# and is left alone, as `cogbox init` does.
#
# The address comes from the same place supervise.sh's BIND_ADDR and the
# floor's rule 2 come from on PVE: the emulator's network-interfaces/0/ip.
# One source, so the three cannot disagree.
#
# NO-OP when config.json does not exist yet (first boot): `cogbox init`, run by
# the supervisor right after this, records the current address itself.
#
# Test seams (tests/test_self_refresh.sh), like gce/supervise.sh's: a systemd
# unit starts from a clean environment, so none is set in production except
# the three the unit sets itself (XDG_CONFIG_HOME, COGWORX_STATE_DIR,
# COGWORX_SERIAL).

set -euo pipefail

MD="${COGWORX_MD_BASE:-http://metadata.google.internal/computeMetadata/v1}"
MDHDR='Metadata-Flavor: Google'
STATE_DIR="${COGWORX_STATE_DIR:-/var/lib/cogbox-state}"
CONFIG_ROOT="${XDG_CONFIG_HOME:-$STATE_DIR/config}/cogbox"
SERIAL="${COGWORX_SERIAL:-/run/cogworx/serial.log}"
ATTEMPTS="${COGWORX_REFRESH_ATTEMPTS:-6}"
RETRY_SLEEP="${COGWORX_REFRESH_RETRY_SLEEP:-2}"
LOCK_WAIT="${COGWORX_REFRESH_LOCK_WAIT:-300}"

note() { printf 'cogworx-pve-self-refresh: %s\n' "$*"; }
# Classified serial line, in supervise.sh emit()'s format.
emit() { printf 'cogworx: %s\n' "$*" >>"$SERIAL" 2>/dev/null || true; }
fail() {
	note "$*" >&2
	emit "FAILED: bindAddr refresh: $*"
	exit 1
}

md_get() { curl -fsS -H "$MDHDR" --max-time 10 "$MD/instance/attributes/$1" 2>/dev/null; }
md_path() { curl -fsS -H "$MDHDR" --max-time 10 "$MD/$1" 2>/dev/null; }

# Retried, because the emulator is socket-activated and the lease may land a
# moment after network-online on a slow DHCP server; bounded, because the
# supervisor is ordered after this unit.
retry() {
	local i=0 out
	while :; do
		if out=$("$@"); then
			printf '%s' "$out"
			return 0
		fi
		i=$((i + 1))
		[ "$i" -lt "$ATTEMPTS" ] || return 1
		sleep "$RETRY_SLEEP"
	done
}

inst=$(retry md_get cogworx-instance) \
	|| fail "could not read cogworx-instance from the metadata emulator; the instance's forwards keep their recorded bindAddr"
# The same grammar supervise.sh enforces, and the same reserved name: the value
# becomes a path component below.
if ! [[ "$inst" =~ ^[a-zA-Z][a-zA-Z0-9-]{0,63}$ ]] || [ "$inst" = default ]; then
	fail "invalid instance name in metadata"
fi

cfg="$CONFIG_ROOT/instances/$inst/config.json"
if [ ! -f "$cfg" ]; then
	note "no config.json for $inst yet (first boot); cogbox init records the current address itself"
	exit 0
fi

ip=$(retry md_path instance/network-interfaces/0/ip) \
	|| fail "the metadata emulator named no IPv4 address for eth0; $inst keeps its recorded bindAddr"
if ! [[ "$ip" =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ ]]; then
	fail "the metadata emulator's address '$ip' is not a dotted-quad IPv4 address"
fi

# The launcher's lock, the launcher's lock order (config first; nothing else is
# held here). Created 0600 like cogbox's own config_lock.zig, never truncated.
lockdir="$CONFIG_ROOT/.locks"
mkdir -p "$lockdir"
(umask 077 && : >>"$lockdir/$inst.lock")
exec {lockfd}>>"$lockdir/$inst.lock"
flock -w "$LOCK_WAIT" "$lockfd" \
	|| fail "could not take the cogbox config lock for $inst within ${LOCK_WAIT}s"

# Re-checked under the lock: `cogbox delete` removes the instance tree while
# holding it.
if [ ! -f "$cfg" ]; then
	note "config.json for $inst disappeared while waiting for the lock; nothing to refresh"
	exit 0
fi

old_bind=$(jq -r '.bindAddr // "127.0.0.1"' "$cfg") \
	|| fail "config.json for $inst is not valid JSON; left untouched"
# Normalised through the same formatter cogbox writes with (jq --tab), so a
# no-op refresh is recognised as one and the file is not rewritten.
old=$(jq --tab . "$cfg") \
	|| fail "config.json for $inst is not valid JSON; left untouched"
new=$(jq --tab --arg addr "$ip" --arg cidr "$ip/32" '
	.bindAddr = $addr
	| if (.network | type) == "object" then
		.network.selfAddrs = ((.network.selfAddrs // []) as $s
			| if any($s[]; . == $cidr) then $s else $s + [$cidr] end)
	  else . end' "$cfg") \
	|| fail "could not rewrite config.json for $inst (unexpected .network shape); left untouched"

if [ "$new" = "$old" ]; then
	note "$inst already records bindAddr $ip; nothing to do"
	exit 0
fi

tmp=$(mktemp "$cfg.XXXXXX")
trap 'rm -f "$tmp"' EXIT
printf '%s\n' "$new" >"$tmp"
chmod --reference="$cfg" "$tmp"
chown --reference="$cfg" "$tmp"
sync "$tmp"
mv -f "$tmp" "$cfg"
trap - EXIT

selfs=$(jq -c '.network.selfAddrs? // empty' "$cfg" 2>/dev/null || true)
note "$inst: bindAddr $old_bind -> $ip${selfs:+; selfAddrs $selfs}"
emit "bindAddr refreshed to $ip (was $old_bind)"
