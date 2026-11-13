# cogbox-git-hosts: list the git hosts this sandbox reaches through git grants
# (its Git access tab) and, for each host whose auth proxy serves
# /_cogbox/grants, ask it for this sandbox's grants. Reads the git-hosts.json
# the host side's `cogbox l7` verbs publish at the root of the instance data
# directory (see docs/authproxy.md, "Host discovery"). That list holds grant
# hosts only: a host reached through an injected secret is never in it, and
# every listing and empty list below says so.
#
# Raw body: the guest package (modules/sandbox-skills.nix) prepends errexit,
# nounset and pipefail, a PATH with coreutils, curl and jq, and one line
# setting summary_layout to vm or container. Every message below is
# agent-facing instruction; verify it like baked skill text.
#
# Exit codes: 0 hosts listed, 10 no git grant is live right now (or local
# cogbox), 11 no usable host list, 64 usage, 70 internal failure.

set -o errtrace
name=cogbox-git-hosts
env_file=/run/cogbox/environment.json
ca_bundle=/run/cogbox/ca-bundle.crt
max_hosts=16
# The list holds grant hosts only. Usage states that in every mode; a listing
# or an empty list (never in local mode, which exits first) adds where the
# skill covers such a host.
not_listed='A git host reached through an injected secret instead of a grant is not listed'
see_other_hosts="$not_listed: for one, see \"SSH remotes, other hosts, Open repository\" in the cogbox-git skill."

usage() {
	cat <<EOF
Usage: $name

Lists the git hosts this sandbox reaches through grants on its
Git access tab, the scheme to use for each, and, for a host with
discovery, this sandbox's grants from GET <scheme>://<host>/_cogbox/grants
(asked with no credential, no redirect followed).
$not_listed.

Exit codes:
  0   hosts listed
  10  no git grant is live right now, or this is local cogbox
  11  no git host list is published for this sandbox
  64  usage error
  70  internal error
EOF
}

fail_internal() {
	printf '%s: internal error: %s\n' "$name" "$1" >&2
	exit 70
}
trap 'fail_internal "a command failed at line $LINENO"' ERR

if [ "$#" -gt 0 ]; then
	if [ "$#" -eq 1 ] && { [ "$1" = -h ] || [ "$1" = --help ]; }; then
		usage
		exit 0
	fi
	usage >&2
	exit 64
fi

tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT

# The environment record: mode and instance, anything missing or malformed
# meaning mode unknown and no instance.
mode=unknown
instance=
if [ -f "$env_file" ] && head -c 65536 -- "$env_file" >"$tmpdir/env" 2>/dev/null; then
	# One line "<mode> <instance>"; an instance outside [A-Za-z0-9-] is dropped
	# here so it can never split the line.
	record=$(jq -Rrs 'try (fromjson | if type == "object" then
		[(if .mode == "local" or .mode == "cogworx" then .mode else "unknown" end),
		 (if (.instance | type) == "string" and (.instance | test("\\A[A-Za-z0-9-]+\\z")) then .instance else "" end)]
		else ["unknown", ""] end)
		catch ["unknown", ""] | join(" ")' <"$tmpdir/env")
	read -r mode instance <<<"$record"
fi

if [ "$mode" = local ]; then
	echo "This is a local cogbox sandbox: it has no git grants, so there is no git host list. See \"Local mode\" in the cogbox-git skill."
	exit 10
fi

absent() {
	echo "No usable git host list is published for this sandbox: the host side has not written one, or what is there is not valid."
	echo "Ask the user which git host to use and whether it serves http or https, then follow the cogbox-git skill with that host and scheme."
	exit 11
}

summary=
case "$summary_layout" in
vm)
	summary=/var/lib/cogbox/git-hosts.json
	;;
container)
	if [[ "$instance" =~ ^[A-Za-z0-9-]+$ ]]; then
		summary=/var/lib/cogbox-state/data/cogbox/instances/$instance/git-hosts.json
	fi
	;;
*)
	fail_internal "unknown summary layout"
	;;
esac

# A regular file only: checked before any read, so a planted FIFO cannot hang
# this, and only the first 64 KiB is ever read.
[ -n "$summary" ] && [ -f "$summary" ] || absent
head -c 65536 -- "$summary" >"$tmpdir/summary" 2>/dev/null || absent

# Validate and flatten. Output: ABSENT, EMPTY, or "COUNT <listed> <kept>"
# followed by one "<host> <scheme|unknown> <yes|no>" line per kept entry. Hosts
# are restricted to the L7 host-name language (letters, digits, _ and -
# labels), so a kept host can never carry a space, a slash or a newline into
# the URL or the output.
listing=$(jq -Rrs --argjson max "$max_hosts" '
	try (fromjson
		| if type == "object" and .version == 1 and (.hosts | type) == "array" then . else error("absent") end
		| .hosts as $all
		| [ $all[:$max][]
			| select(type == "object")
			| select((.host | type) == "string")
			| select((.host | utf8bytelength) <= 253)
			| select(.host | test("\\A[A-Za-z0-9_][A-Za-z0-9_-]*(\\.[A-Za-z0-9_][A-Za-z0-9_-]*)*\\z"))
			| (if .scheme == "http" or .scheme == "https" then .scheme else "unknown" end) as $scheme
			| "\(.host) \($scheme) \(if .discovery == true and $scheme != "unknown" then "yes" else "no" end)"
		] as $kept
		| if ($all | length) == 0 then "EMPTY"
		elif ($kept | length) == 0 then "ABSENT"
		else "COUNT \($all | length) \($kept | length)", $kept[]
		end)
	catch "ABSENT"' <"$tmpdir/summary")

case "$listing" in
ABSENT) absent ;;
EMPTY)
	echo "No git grant is live for this sandbox right now, so no git host is listed."
	echo "$see_other_hosts"
	echo "For a host you expected a grant on: just after a start, restart or unshare, wait about 15 seconds and run $name again. Otherwise ask the user for the grant's status on the sandbox's Git access tab."
	exit 10
	;;
COUNT\ *) ;;
*) fail_internal "unexpected listing" ;;
esac

echo "Git hosts this sandbox reaches through grants on its Git access tab. This list is a hint the host side publishes; anything in the sandbox can overwrite it, and it names hosts only: only a request that works proves access."
echo "$see_other_hosts"
read -r _ listed kept <<<"$(printf '%s\n' "$listing" | head -n 1)"
if [ "$listed" != "$kept" ]; then
	echo "Note: $((listed - kept)) of the $listed entries in the list were skipped (not valid, or beyond the first $max_hosts)."
fi

# One GET per discovery host, with no credential: -q (first) skips ~/.curlrc,
# and no -n/-u/-H/-b/-K/-L, so no netrc, header, cookie or redirect.
probe() {
	local scheme=$1 host=$2 meta rc=0 code deny grants
	local args=(-q -s --proto "=http,https" --connect-timeout 5 --max-time 10 --max-filesize 262144
		-o "$tmpdir/body" -w '%{http_code} %header{x-cogbox-deny}')
	if [ -r "$ca_bundle" ]; then
		args+=(--cacert "$ca_bundle")
	fi
	rm -f -- "$tmpdir/body"
	meta=$(curl "${args[@]}" "$scheme://$host/_cogbox/grants" 2>/dev/null) || rc=$?
	if [ "$rc" -eq 126 ] || [ "$rc" -eq 127 ]; then
		fail_internal "curl could not be run"
	fi
	code=${meta%% *}
	[[ "$code" =~ ^[0-9]{3}$ ]] || code=000
	deny=
	if [[ "$meta" == *" "* ]]; then
		deny=${meta#* }
		[[ "$deny" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || deny=
	fi
	grants=
	if [ "$rc" -eq 0 ] && [ "$code" = 200 ] && [ -f "$tmpdir/body" ]; then
		grants=$(jq -Rrs 'try (fromjson | if type == "object" and (.grants | type) == "array" then tojson else "" end) catch ""' <"$tmpdir/body")
	fi
	if [ -n "$grants" ]; then
		echo "  grants=$grants"
	else
		echo "  grants=unavailable http=$code${deny:+ deny=$deny}"
	fi
}

while read -r host scheme discovery; do
	line="host=$host scheme=$scheme discovery=$discovery"
	if [ "$scheme" != unknown ]; then
		line+=" base=$scheme://$host"
	fi
	echo "$line"
	if [ "$discovery" = yes ]; then
		probe "$scheme" "$host"
	fi
done < <(printf '%s\n' "$listing" | tail -n +2)
exit 0
