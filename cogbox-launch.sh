#!/usr/bin/env bash
# Bash side of cogbox: handles VM init, on-disk migration, runtime
# preparation, and the actual microvm launch. Invoked by the Zig
# `cogbox` binary with already-validated arguments; see the
# argument-parsing block below for the contract. Not meant to be invoked
# directly by users.
#
# Intentionally NO `set -e`: the script's EXIT trap is the canonical
# cleanup path (kill passt, remove runtime dir). With `set -e`, any
# transient subshell failure during long migrations would short-circuit
# bash before the VM gets a chance to launch -- and the original
# cogbox.sh ran without it for the same reason.

# -- Argument parsing (Zig has already validated everything) -------
# Inputs (all optional):
#   --name NAME           Instance name. Empty/absent = default instance.
#   --vcpu N              vCPU count override.
#   --mem N               Memory MB override.
#   --network MODE        full|none|rules. If absent, fall back to config.json.
#   --init-only           Run init steps but do not start the VM.
#   --no-auto-keys        On first init, leave authorized_keys empty and skip
#                         generating cogbox's own SSH identity.
#   --yes                 Skip the interactive harness-selection prompt.
#   --bind-addr ADDR      Seed `.bindAddr` (the address the guest's port
#                         forwards are advertised at; default 127.0.0.1).
#   --no-implicit-dns     Seed `.network.implicitDns = false`, so port 53 stops
#                         escaping the L4 rule walk. Needed wherever the host
#                         resolver IS an address the sandbox must not reach
#                         (on GCE the VPC resolver is the metadata address).
#   --dns-host ADDR       Seed `.network.dnsHost`: the loopback address the
#                         ENCLOSING host runs its own DNS forwarder on. Re-admits
#                         that ONE address on port 53 to the L4 walk, which is
#                         what keeps guest DNS alive under --no-implicit-dns when
#                         passt forwards the guest's queries there.
#   --self-addr CIDR      Seed one `.network.selfAddrs` entry (repeatable): an
#                         address of the ENCLOSING host, which the L7 proxy
#                         adds to its non-overridable floor.
#   --add-dir DIR        Grant read-write access to one host directory for this
#                        launch only (repeatable; order is preserved).
#   --add-dir-ro DIR     Grant read-only access to one host directory for this
#                        launch only (repeatable; order is preserved).
# The last four seed config.json on FIRST init only, like every other init
# flag. All four are absent by default, so a config written without them is
# byte-identical to one written before they existed.
INIT_ONLY=0
FLAG_VCPU=""
FLAG_MEM=""
FLAG_NETWORK=""
FLAG_BIND_ADDR=""
FLAG_NO_IMPLICIT_DNS=0
FLAG_DNS_HOST=""
FLAG_SELF_ADDRS=()
FLAG_ADDITIONAL_DIR_PATHS=()
FLAG_ADDITIONAL_DIR_MODES=()
INSTANCE_NAME=""
AUTO_KEYS=1
ASSUME_YES=0
while [ $# -gt 0 ]; do
	case "$1" in
		--init-only) INIT_ONLY=1; shift ;;
		--no-auto-keys) AUTO_KEYS=0; shift ;;
		--yes|-y) ASSUME_YES=1; shift ;;
		--name) INSTANCE_NAME="$2"; shift 2 ;;
		--vcpu) FLAG_VCPU="$2"; shift 2 ;;
		--mem) FLAG_MEM="$2"; shift 2 ;;
		--network) FLAG_NETWORK="$2"; shift 2 ;;
		--bind-addr) FLAG_BIND_ADDR="$2"; shift 2 ;;
		--no-implicit-dns) FLAG_NO_IMPLICIT_DNS=1; shift ;;
		--dns-host) FLAG_DNS_HOST="$2"; shift 2 ;;
		--self-addr) FLAG_SELF_ADDRS+=("$2"); shift 2 ;;
		--add-dir) FLAG_ADDITIONAL_DIR_PATHS+=("$2"); FLAG_ADDITIONAL_DIR_MODES+=(rw); shift 2 ;;
		--add-dir-ro) FLAG_ADDITIONAL_DIR_PATHS+=("$2"); FLAG_ADDITIONAL_DIR_MODES+=(ro); shift 2 ;;
		*) echo "cogbox-launch: error: unexpected argument $1 (Zig wrapper should have rejected this)" >&2; exit 70 ;;
	esac
done

# Reconstruct the cogbox argv for the custom-flake re-exec path below. The
# verb mirrors the current mode so the re-exec'd cogbox does the same thing
# without re-forking or re-prompting: `init` for --init-only, otherwise the
# hidden `__launch` verb (exec the launch script in place -- the
# daemonization was already done by the `start` verb that forked us, so we
# must not fork again).
if [ "$INIT_ONLY" -eq 1 ]; then
	ORIG_ARGS=(init)
else
	ORIG_ARGS=(__launch)
fi
[ -n "$INSTANCE_NAME" ] && ORIG_ARGS+=(--name "$INSTANCE_NAME")
[ -n "$FLAG_VCPU" ]     && ORIG_ARGS+=(--vcpu "$FLAG_VCPU")
[ -n "$FLAG_MEM" ]      && ORIG_ARGS+=(--mem "$FLAG_MEM")
[ -n "$FLAG_NETWORK" ]  && ORIG_ARGS+=(--network "$FLAG_NETWORK")
[ -n "$FLAG_BIND_ADDR" ] && ORIG_ARGS+=(--bind-addr "$FLAG_BIND_ADDR")
[ "$FLAG_NO_IMPLICIT_DNS" -eq 1 ] && ORIG_ARGS+=(--no-implicit-dns)
[ -n "$FLAG_DNS_HOST" ] && ORIG_ARGS+=(--dns-host "$FLAG_DNS_HOST")
for _self_addr in "${FLAG_SELF_ADDRS[@]}"; do
	ORIG_ARGS+=(--self-addr "$_self_addr")
done
FLAG_ADDITIONAL_DIR_ORIG_INDEXES=()
for _additional_i in "${!FLAG_ADDITIONAL_DIR_PATHS[@]}"; do
	if [ "${FLAG_ADDITIONAL_DIR_MODES[_additional_i]}" = ro ]; then
		ORIG_ARGS+=(--add-dir-ro)
	else
		ORIG_ARGS+=(--add-dir)
	fi
	FLAG_ADDITIONAL_DIR_ORIG_INDEXES+=("${#ORIG_ARGS[@]}")
	ORIG_ARGS+=("${FLAG_ADDITIONAL_DIR_PATHS[_additional_i]}")
done
[ "$AUTO_KEYS" -eq 0 ]  && ORIG_ARGS+=(--no-auto-keys)
[ "$ASSUME_YES" -eq 1 ] && ORIG_ARGS+=(--yes)

# Scaffold written into each instance's config dir on first init. Also used
# by the re-exec check below: if the user hasn't edited flake.nix, the
# resulting microvm closure is identical to the baked-in default and we can
# skip the (network-dependent) `nix run` re-eval entirely.
# shellcheck disable=SC2016
SCAFFOLD_FLAKE='{
	description = "cogbox per-instance extensions";

	# `pkgs` in nixosModules.default below comes from cogbox'\''s nixpkgs.
	# To use a different nixpkgs, add an input here (e.g.
	# inputs.nixpkgs-custom.url = "...";) and reference it explicitly.
	# cogbox always overrides any "nixpkgs" input you declare to its
	# own, so use a different name (like nixpkgs-custom) to escape that.

	outputs = { self }: {
		nixosModules.default = { pkgs, lib, ... }: {
			# Add per-instance packages and modules here. Examples:
			#   environment.systemPackages = with pkgs; [ hbase openjdk21 ];
			#   system.extraDependencies  = with pkgs; [ hbase openjdk21 ];
		};
	};
}
'

die() {
	echo "cogbox-launch: error: $*" >&2
	exit "${2:-70}"
}

# Generate cogbox's own SSH keypair ($COGBOX_SSH_KEY{,.pub}) once, host-side, so
# `cogbox ssh` has a default identity that works out of the box without relying
# on the user's personal keys or agent. Idempotent: a no-op if the key already
# exists. Tolerant of a missing ssh-keygen (just contributes nothing). The
# pubkey is unioned into each VM's authorized_keys at launch time; the private
# key stays on the host (the data-dir root is never mounted into a VM).
ensure_cogbox_key() {
	[ -f "$COGBOX_SSH_KEY" ] && return 0
	command -v ssh-keygen >/dev/null 2>&1 || return 0
	mkdir -p "$BASE_DATA"
	ssh-keygen -t ed25519 -N '' -C "cogbox" -f "$COGBOX_SSH_KEY" >/dev/null 2>&1 || true
}

# -- Resolve real user for sudo context ----------------------------
# Trust SUDO_USER ONLY when we are actually running as root: that is the genuine
# `sudo cogbox` case, where we act on behalf of the invoking user and chown the
# files back to them. `sudo` exports SUDO_USER for EVERY invocation (even
# `sudo -u other`), and a non-login `su other` preserves it -- so without the
# euid==0 guard, running as one user with another's stale SUDO_USER in the env
# would resolve to the wrong home/uid (writing into a dir we can't touch). When
# not root, our own identity (id/$HOME) is authoritative. SUDO_INVOCATION is the
# single source of truth downstream (runtime dir, chown-back).
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
	SUDO_INVOCATION=1
	REAL_USER="$SUDO_USER"
	REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
	REAL_UID=$(getent passwd "$SUDO_USER" | cut -d: -f3)
else
	SUDO_INVOCATION=0
	REAL_USER="$(id -un)"
	REAL_HOME="$HOME"
	REAL_UID="$(id -u)"
fi

# -- Paths (XDG basedir spec) --------------------------------------
CONFIG_DIR="${XDG_CONFIG_HOME:-$REAL_HOME/.config}/cogbox"
BASE_DATA="${COGBOX_DATA:-${XDG_DATA_HOME:-$REAL_HOME/.local/share}/cogbox}"
# cogbox's own SSH identity, used as the default key for `cogbox ssh`. It lives
# in the data-dir root -- a sibling of instances/, which is the only subtree
# mounted into a VM -- so the private key never enters the sandbox. The Zig
# `ssh`/`start` verbs derive the same path; keep the basename in sync.
COGBOX_SSH_KEY="$BASE_DATA/cogbox_ed25519"
# Marker written when --no-auto-keys is chosen at first init. It makes that
# opt-out durable: without it a later plain `cogbox start` (AUTO_KEYS defaults
# to 1) would silently generate and authorize the key, re-enabling SSH the user
# opted out of. To opt in later, remove this file; to rotate, remove the key.
COGBOX_KEY_OPTOUT="$CONFIG_DIR/no-cogbox-key"

# Fail fast on an identity/permission mismatch instead of cascading mkdir/write
# failures into a corrupt half-init (and a misleading "invalid JSON" at start).
# The classic trigger is `sudo su <user>` WITHOUT `-`: that keeps the invoker's
# HOME/SUDO_USER, so the resolved home isn't writable by the user we now are.
if [ ! -d "$REAL_HOME" ] || [ ! -w "$REAL_HOME" ]; then
	die "resolved home '$REAL_HOME' (user '$REAL_USER') is not writable by uid $(id -u). If you switched users, use a login shell -- 'sudo su - $REAL_USER' (or 'sudo -u $REAL_USER env -u SUDO_USER HOME=$REAL_HOME ...') -- not 'sudo su $REAL_USER'." 78
fi

# -- Harness shape -------------------------------------------------
# The HARNESSES list is GENERATED from flake.nix's `mkHarnesses` set at
# build time: the cogbox package substitutes the harness-name sentinel below
# with the enabled-harness names, so this list always matches which harnesses
# the VM was built with -- including the opt-in `enableCodex`. The per-harness
# shape below (H_KIND, H_HOST, pathkeys, summaries, inject specs) is still
# hand-maintained and must mirror the matching harness attrs in flake.nix;
# names are used as 9p tags, fw_cfg keys, and runtime symlinks.
HARNESSES=(@harnesses@)
declare -A H_KIND
declare -A H_HOST
declare -A H_FW_DEFAULT
declare -A H_FW_MODE

H_KIND[claude-code:config]=overlay
H_HOST[claude-code:config]="${COGBOX_CLAUDE_CONFIG:-$REAL_HOME/.claude}"

H_KIND[claude-code:auth]=fw_cfg
H_HOST[claude-code:auth]="${COGBOX_CLAUDE_AUTH:-$REAL_HOME/.claude.json}"
H_FW_DEFAULT[claude-code:auth]='{}'
H_FW_MODE[claude-code:auth]=600

H_KIND[opencode:config]=overlay
H_HOST[opencode:config]="${COGBOX_OPENCODE_CONFIG:-${XDG_CONFIG_HOME:-$REAL_HOME/.config}/opencode}"

H_KIND[opencode:data]=overlay
H_HOST[opencode:data]="${COGBOX_OPENCODE_DATA:-${XDG_DATA_HOME:-$REAL_HOME/.local/share}/opencode}"

H_KIND[opencode:cache]=ephemeral
H_KIND[opencode:state]=ephemeral

H_KIND[codex:home]=overlay
H_HOST[codex:home]="${COGBOX_CODEX_HOME:-$REAL_HOME/.codex}"

H_KIND[hermes-agent:home]=overlay
H_HOST[hermes-agent:home]="${COGBOX_HERMES_HOME:-$REAL_HOME/.hermes}"

H_KIND[pi:home]=overlay
H_HOST[pi:home]="${COGBOX_PI_HOME:-$REAL_HOME/.pi}"

H_KIND[omp:home]=overlay
H_HOST[omp:home]="${COGBOX_OMP_HOME:-$REAL_HOME/.omp}"
H_KIND[dsh:home]=overlay
H_HOST[dsh:home]="${COGBOX_DSH_HOME:-$REAL_HOME/.dsh}"

# Path keys per harness, in declared order.
harness_pathkeys() {
	case "$1" in
		claude-code) printf '%s\n' config auth ;;
		opencode) printf '%s\n' config data cache state ;;
		codex) printf '%s\n' home ;;
		hermes-agent) printf '%s\n' home ;;
		omp) printf '%s\n' home ;;
		pi) printf '%s\n' home ;;
		dsh) printf '%s\n' home ;;
	esac
}

# Human-readable summary of what creating a harness's host state will
# do, used in the "set up which?" prompt.
harness_summary() {
	case "$1" in
		claude-code) echo "creates ~/.claude/, ~/.claude.json" ;;
		opencode)    echo "creates ~/.config/opencode/, ~/.local/share/opencode/" ;;
		codex)       echo "creates ~/.codex/" ;;
		hermes-agent) echo "creates ~/.hermes/" ;;
		omp)           echo "creates ~/.omp/" ;;
		pi)           echo "creates ~/.pi/" ;;
		dsh)          echo "creates ~/.dsh/" ;;
	esac
}

# -- Host-side credential injection (keep tokens out of the sandbox) ---
# Credential-injection specs per harness, one per line:
#   provider_host|style|cred_file|token_path|account_id_path|refresh_token_path|expires_at_path|token_url|client_id
# The terminate-tier mitmproxy addon reads token_path out of cred_file
# (host-side) and rewrites the request's auth header for provider_host, so the
# guest only ever carries a stub. cred_file is resolved from the same H_HOST
# paths used everywhere else. The trailing 4 fields are OPTIONAL and opt the
# host into host-side token refresh (the addon does the OAuth refresh-token
# grant when the access token nears expiry and writes the rotated tokens back
# to cred_file): needed for harnesses whose token is EVICTED from the guest
# (claude-code), since the guest then cannot refresh on its own. Harnesses that
# still carry their token in-guest refresh there and leave these blank. The
# OAuth login/refresh host (platform.claude.com) is deliberately NOT listed: the
# guest reaches it via the default L4 splice (passthrough), so an in-guest
# `/login` works AND the guest can refresh its OWN token there -- we never MITM
# or capture the login. See docs/network-filtering.md.
harness_inject_specs() {
	case "$1" in
		claude-code)
			printf '%s\n' \
				"api.anthropic.com|anthropic-oauth|${H_HOST[claude-code:config]}/.credentials.json|claudeAiOauth.accessToken||claudeAiOauth.refreshToken|claudeAiOauth.expiresAt|https://platform.claude.com/v1/oauth/token|9d1c250a-e61b-44d9-88ed-5944d1962f5e"
			;;
		codex)
			printf '%s\n' \
				"chatgpt.com|openai-chatgpt|${H_HOST[codex:home]}/auth.json|tokens.access_token|tokens.account_id" \
				"api.openai.com|openai-chatgpt|${H_HOST[codex:home]}/auth.json|tokens.access_token|tokens.account_id"
			;;
		opencode)
			# opencode is multi-provider; the anthropic OAuth provider is the
			# common case. API-key providers (openrouter/kimi) are not yet
			# auto-injected -- they keep the legacy guest-carries-token path.
			printf '%s\n' \
				"api.anthropic.com|anthropic-oauth|${H_HOST[opencode:data]}/auth.json|anthropic.access|"
			;;
	esac
}

# Deduped, cred-present inject specs for the active harnesses -- one TSV row per
# provider host, the single source both active_inject_hosts (the rule seed) and
# gen_inject_conf (the addon conf) project from, so their selection can't drift.
# Gating on cred existence (not just harness-active) avoids terminating a provider
# host for a harness with no token (the `--yes` init activates all harnesses, but
# most have no creds). First such harness wins a shared host (claude-code precedes
# opencode for api.anthropic.com in HARNESSES order). Fields, tab-separated:
#   host style cred token acct rtok exp turl cid stub_token
inject_specs_deduped() {
	local h host style cred token acct rtok exp turl cid
	declare -A seen
	for h in "${ACTIVE_HARNESSES[@]}"; do
		while IFS='|' read -r host style cred token acct rtok exp turl cid; do
			[ -z "$host" ] && continue
			[ -n "${seen[$host]:-}" ] && continue
			[ -f "$cred" ] || continue
			seen[$host]=1
			printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
				"$host" "$style" "$cred" "$token" "$acct" "$rtok" "$exp" "$turl" "$cid" \
				"$(harness_stub_token "$h")"
		done < <(harness_inject_specs "$h")
	done
}

# Unique provider hosts to terminate+inject for the active harnesses the user is
# actually LOGGED INTO (host-side cred file present) -- the seed for a new
# instance's L7 rules.
active_inject_hosts() {
	inject_specs_deduped | cut -f1
}

# Emit the inject-conf (JSON array) for the active harnesses to stdout: one spec
# per deduped provider host whose host-side cred file EXISTS. `[]` if none -- the
# caller then writes no conf and the addon leaves auth untouched.
gen_inject_conf() {
	inject_specs_deduped | jq -R -s '
		[ split("\n")[] | select(length > 0) | split("\t")
		  | { host: .[0], style: .[1], cred_file: .[2], token_path: .[3] }
		  + (if (.[4] // "") != "" then { account_id_path: .[4] } else {} end)
		  + (if (.[5] // "") != "" and (.[6] // "") != ""
		         and (.[7] // "") != "" and (.[8] // "") != ""
		       then { refresh: { refresh_token_path: .[5], expires_at_path: .[6],
		                         token_url: .[7], client_id: .[8],
		                         expires_at_unit: "ms" } }
		       else {} end)
		  + (if (.[9] // "") != "" then { stub_token: .[9] } else {} end) ]
	'
}

# The secret file to scrub from the guest when injection is active, as
# "<overlay-pathkey> <basename>". When the harness defines a redactor (below) the
# file is REWRITTEN with its tokens replaced by placeholders but its non-secret
# fields kept; otherwise it is dropped wholesale. Either way the real
# access/refresh tokens never enter the sandbox -- the addon injects the real
# token host-side on the wire. Only claude-code is handled for now; codex
# (account id lives in the same file) and opencode (multi-provider, non-injected
# API-key providers) keep the mounted-token path until their redactors are built.
harness_secret_file() {
	case "$1" in
		claude-code) echo "config .credentials.json" ;;
	esac
}

# The placeholder access token harness_secret_redact_jq writes in place of the
# real one -- a recognizable SENTINEL. The inject addon stamps the real token
# ONLY over this exact stub (or an absent credential), so a SECONDARY credential
# the guest legitimately obtains through an injected call -- e.g. claude-code
# Remote Control's per-session "bridge credentials" used on
# /v1/code/sessions/<id>/worker + the SSE transport -- reaches the upstream
# UNTOUCHED instead of being clobbered with the OAuth token (which yields 401 /
# worker_register_failed -> "Transport closed (code 403)"). Emitted into the
# inject-conf as `stub_token` (gen_inject_conf). Empty => harness not redacted.
harness_stub_token() {
	case "$1" in
		claude-code) echo "sk-ant-oat01-cogbox-host-injected-placeholder" ;;
	esac
}

# jq program to REDACT (rather than drop) the secret file for a harness, or empty
# to fall back to full eviction. Keeping the non-secret fields -- the OAuth
# `scopes` and subscriptionType -- lets the harness still present a logged-in
# identity inside the guest (claude-code's `/remote-control`, for one, gates on a
# local full-scope credential), while the token fields become inert placeholders:
# the host proxy overwrites the access token on the wire (ONLY over the stub --
# see harness_stub_token), and a far-future expiry stops the guest from ever
# trying (and failing) to refresh the placeholder locally. The accessToken stub
# MUST equal harness_stub_token so the addon recognizes it. Fail-safe: if jq
# errors on an unexpected cred shape, staging drops the file entirely rather than
# risk writing a real token (see stage_overlay_source).
harness_secret_redact_jq() {
	local stub; stub="$(harness_stub_token "$1")"
	[ -z "$stub" ] && return
	case "$1" in
		claude-code) cat <<-JQ
		if (.claudeAiOauth | type) != "object" then error("unexpected cred shape")
		else .claudeAiOauth.accessToken = "$stub"
		   | .claudeAiOauth.refreshToken = "cogbox-evicted-no-refresh-token-in-guest"
		   | .claudeAiOauth.expiresAt = 9999999999000
		end
		JQ
		;;
	esac
}

# Write a minimal redacted-scoped PLACEHOLDER credential for a harness to $2.
# The staging-failure fallback: the guest must ALWAYS have a present, scoped,
# logged-in identity -- the addon injects the real token over the stub, and BOTH
# /remote-control (gates on a local full-scope cred file) and an in-guest /login
# need a present scoped file on disk. The accessToken is single-sourced from
# harness_stub_token (the SAME string the redactor writes and the addon matches),
# so it can never drift. Returns non-zero if the harness has no stub identity or
# the write fails; the caller then evicts the file (legacy behavior).
write_stub_cred() {
	local h=$1 dest=$2 stub
	stub="$(harness_stub_token "$h")"
	[ -z "$stub" ] && return 1
	case "$h" in
		claude-code)
			jq -n --arg t "$stub" '{claudeAiOauth: {accessToken: $t,
				refreshToken: "cogbox-evicted-no-refresh-token-in-guest",
				expiresAt: 9999999999000,
				scopes: ["user:inference", "user:profile"]}}' > "$dest" 2>/dev/null \
				|| return 1
			chmod 600 "$dest" 2>/dev/null || return 1
			;;
		*) return 1 ;;
	esac
}

# Stage the 9p source for an active harness overlay path: normally the real host
# dir, but when injection is active AND this path holds the harness's secret
# file, a per-instance hardlink-mirror in which that file is REDACTED -- tokens
# replaced by placeholders, non-secret fields kept (or omitted entirely if it
# can't be safely redacted; no bulk data copy -- the dir can be large). The
# mirror lives host-only under the cogbox data root
# ($BASE_DATA/mirrors/<instance>/); it must NOT go under REAL_DATA, which is
# shared RW into the guest -- the hardlinks alias the real host dir, so a guest
# write would corrupt it. Hardlinks need same-fs as the source (true when both
# sit under $HOME); a copy fallback covers the rare separate-mount case, and we
# fail closed to an empty dir, never the real dir. Echoes the path to share.
stage_overlay_source() {
	local h=$1 k=$2 host=$3
	local skey sfile
	read -r skey sfile <<< "$(harness_secret_file "$h")"
	if [ "$INJECT_ACTIVE" != "1" ] || [ -z "$sfile" ] || [ "$skey" != "$k" ] \
		|| [ ! -e "$host/$sfile" ]; then
		printf '%s' "$host"
		return
	fi
	local redact; redact="$(harness_secret_redact_jq "$h")"
	local mirror; mirror="$BASE_DATA/mirrors/${EFFECTIVE_NAME}/${h}-${k}"
	rm -rf "$mirror"; mkdir -p "$mirror"
	if cp -al "$host/." "$mirror/" 2>/dev/null || cp -a "$host/." "$mirror/" 2>/dev/null; then
		# Break the hardlink to the real cred file before touching it: the mirror
		# entry aliases the host's inode, so writing through it would corrupt the
		# user's real credential. rm drops only the mirror's link.
		rm -f "$mirror/$sfile"
		# Redact-in-place when the harness defines a redactor: rewrite the cred
		# file with its tokens replaced by placeholders but its non-secret fields
		# (OAuth scopes, ...) kept, so the harness still sees a logged-in identity
		# while the real tokens stay host-side. No redactor -- or a jq error on an
		# unexpected cred shape -- leaves the file GONE (full eviction), never the
		# real tokens. Direct-to-target then rm-on-failure is safe: the mirror is
		# host-only and not yet shared into any guest at staging time.
		if [ -n "$redact" ]; then
			if jq "$redact" "$host/$sfile" > "$mirror/$sfile" 2>/dev/null; then
				chmod 600 "$mirror/$sfile"
			else
				# Unexpected cred shape: stage a minimal scoped PLACEHOLDER rather
				# than evict -- a present scoped file keeps the inherit-default path
				# and /rc working (the addon injects the real token over the stub),
				# and lets the guest log in to its OWN account on top. Only if even
				# the placeholder can't be written do we evict (fail-safe: never the
				# real token).
				rm -f "$mirror/$sfile"
				if write_stub_cred "$h" "$mirror/$sfile"; then
					echo "cogbox-launch: warning: could not redact $h/$k secret; staged a placeholder identity instead (real token withheld)." >&2
				else
					rm -f "$mirror/$sfile"
					echo "cogbox-launch: warning: could not redact or stub $h/$k secret; evicting it entirely (token withheld)." >&2
				fi
			fi
		fi
		# Strip any token-bearing refresh write-temp the host-side refresh may
		# have left in the cred dir (crash residue, or a temp created during
		# this cp): it is a COMPLETE rotated credential (access + refresh token)
		# and must never reach the guest. Pattern matches CRED_TMP_PREFIX in
		# l7-mitm-addon.py. (The addon prefers a host-only temp dir off the
		# mirrored tree; this is the backstop for the same-fs fallback path.)
		rm -f "$mirror"/.cogbox-refresh-*.tmp 2>/dev/null || true
		printf '%s' "$mirror"
	else
		# Mirror failed: fail CLOSED -- never fall back to sharing the real dir
		# (that would leak the token). Stage a minimal scoped PLACEHOLDER cred so
		# the guest still has a present logged-in identity (host-side injection
		# fills in the real token over the stub); a harness with no stub identity
		# gets an empty dir.
		rm -rf "$mirror"; mkdir -p "$mirror"
		if [ -n "$redact" ] && write_stub_cred "$h" "$mirror/$sfile"; then
			echo "cogbox-launch: warning: could not mirror $h/$k dir; staged a placeholder identity only (real token withheld)." >&2
		else
			echo "cogbox-launch: warning: could not stage sanitized $h/$k mirror; sharing empty dir (token withheld)." >&2
		fi
		printf '%s' "$mirror"
	fi
}

# Microvm runner has runtime paths baked in at flake build time using this
# sentinel; the sed substitution below rewrites them to BASE_RUNTIME.
RUNTIME_TEMPLATE="@runtimeDir@"

# Per-user runtime dir per the XDG basedir spec. Under sudo, XDG_RUNTIME_DIR
# typically points at root's tree (or is unset); use the invoking user's
# /run/user/$UID instead. If that doesn't exist (no active logind session),
# fall back to /tmp/cogbox-runtime-$UID per the spec's "replacement
# directory with similar capabilities" guidance.
if [ "$SUDO_INVOCATION" = 1 ] || [ -z "${XDG_RUNTIME_DIR:-}" ]; then
	XDG_RUNTIME_BASE="/run/user/$REAL_UID"
else
	XDG_RUNTIME_BASE="$XDG_RUNTIME_DIR"
fi
if [ ! -d "$XDG_RUNTIME_BASE" ]; then
	XDG_RUNTIME_BASE="/tmp/cogbox-runtime-$REAL_UID"
	mkdir -p "$XDG_RUNTIME_BASE"
	chmod 700 "$XDG_RUNTIME_BASE"
fi
BASE_RUNTIME="$XDG_RUNTIME_BASE/cogbox"

EFFECTIVE_NAME="${INSTANCE_NAME:-default}"
INSTANCE_CONFIG_DIR="$CONFIG_DIR/instances/$EFFECTIVE_NAME"
# The flake lives in its own subdir so unrelated edits to config.json /
# authorized_keys don't bust the userExtensions flake's source hash.
INSTANCE_FLAKE_DIR="$INSTANCE_CONFIG_DIR/flake"
# Generated by `cogbox plugin` (DO NOT EDIT): composes every plugin's
# nixosModules.default plus the user flake above. Same own-subdir rationale.
PLUGINS_FLAKE_DIR="$INSTANCE_CONFIG_DIR/plugins-flake"
# Populated by `cogbox plugin` (file:// binary cache): the plugins re-exec
# below uses it as an extra substituter so a fresh-store launch resolves the
# composition's transitive tarball/narHash inputs offline.
PLUGIN_CACHE_DIR="$INSTANCE_CONFIG_DIR/plugin-cache"
REAL_DATA="$BASE_DATA/instances/$EFFECTIVE_NAME"
if [ -n "$INSTANCE_NAME" ]; then
	RUNTIME="${BASE_RUNTIME}-${INSTANCE_NAME}"
else
	RUNTIME="$BASE_RUNTIME"
fi

# Resolve launch-only directory grants while the caller's cwd is still active,
# before either custom-runner re-exec. Paths are replaced in ORIG_ARGS so every
# later pass sees one canonical absolute source and the original mixed mode
# order. This is also the host-side security boundary: no grant may overlap
# Cogbox state, harness material, credentials, or host-special filesystems.
has_ascii_control() {
	local LC_ALL=C value=$1 i code
	for ((i = 0; i < ${#value}; i++)); do
		printf -v code '%d' "'${value:i:1}"
		if [ "$code" -lt 32 ] || [ "$code" -eq 127 ]; then
			return 0
		fi
	done
	return 1
}
path_at_or_below() {
	[ "$1" = "$2" ] || [[ "$1" == "$2/"* ]]
}
paths_overlap() {
	[ "$1" = "$2" ] || [[ "$1" == "$2/"* ]] || [[ "$2" == "$1/"* ]]
}

if [ "$INIT_ONLY" -eq 0 ] && [ "${#FLAG_ADDITIONAL_DIR_PATHS[@]}" -gt 0 ]; then
	PROTECTED_ADDITIONAL_DIR_PATHS=("$CONFIG_DIR" "$BASE_DATA" "$RUNTIME")
	for _host_path in "${H_HOST[@]}"; do
		PROTECTED_ADDITIONAL_DIR_PATHS+=("$_host_path")
	done
	[ -n "${COGBOX_L7_INJECT_CONF:-}" ] && PROTECTED_ADDITIONAL_DIR_PATHS+=("$COGBOX_L7_INJECT_CONF")
	[ -n "${COGBOX_NETRC_FILE:-}" ] && PROTECTED_ADDITIONAL_DIR_PATHS+=("$COGBOX_NETRC_FILE")

	for _additional_i in "${!FLAG_ADDITIONAL_DIR_PATHS[@]}"; do
		_raw_path=${FLAG_ADDITIONAL_DIR_PATHS[_additional_i]}
		if has_ascii_control "$_raw_path"; then
			die "additional directory path contains an ASCII control character" 65
		fi
		if ! _canonical_path=$(realpath -e -- "$_raw_path" 2>/dev/null); then
			die "additional directory is missing or inaccessible: $_raw_path" 66
		fi
		if [ ! -d "$_canonical_path" ]; then
			die "additional directory option requires a directory: $_raw_path" 65
		fi
		if [ "$_canonical_path" = / ]; then
			die "additional directory is not permitted: $_canonical_path" 65
		fi
		for _special_root in /dev /proc /sys /run /nix; do
			if path_at_or_below "$_canonical_path" "$_special_root"; then
				die "additional directory is at or below protected host path $_special_root: $_canonical_path" 65
			fi
		done
		for _prior_i in "${!FLAG_ADDITIONAL_DIR_PATHS[@]}"; do
			[ "$_prior_i" -ge "$_additional_i" ] && break
			if paths_overlap "$_canonical_path" "${FLAG_ADDITIONAL_DIR_PATHS[_prior_i]}"; then
				die "additional directory selections overlap: ${FLAG_ADDITIONAL_DIR_PATHS[_prior_i]} and $_canonical_path" 65
			fi
		done
		for _protected_path in "${PROTECTED_ADDITIONAL_DIR_PATHS[@]}"; do
			if ! _protected_canonical=$(realpath -m -- "$_protected_path" 2>/dev/null); then
				die "cannot resolve protected host path $_protected_path" 70
			fi
			if paths_overlap "$_canonical_path" "$_protected_canonical"; then
				die "additional directory overlaps protected host path $_protected_canonical: $_canonical_path" 65
			fi
		done

		FLAG_ADDITIONAL_DIR_PATHS[_additional_i]="$_canonical_path"
		ORIG_ARGS[${FLAG_ADDITIONAL_DIR_ORIG_INDEXES[_additional_i]}]="$_canonical_path"
	done
fi

# Detect pre-fix layouts where the default instance's config and data
# lived at the top level of $CONFIG_DIR / $BASE_DATA, which nested every
# named instance inside the default (and exposed named-instance data to
# the default guest via 9p).
if [ -z "$INSTANCE_NAME" ]; then
	OLD_CFG=""; OLD_DATA=""
	[ -f "$CONFIG_DIR/config.json" ] && [ ! -f "$INSTANCE_CONFIG_DIR/config.json" ] && OLD_CFG=1
	[ -e "$BASE_DATA/claude-overlay.img" ] && [ ! -d "$REAL_DATA" ] && OLD_DATA=1
	if [ -n "$OLD_CFG" ] || [ -n "$OLD_DATA" ]; then
		{
			echo "cogbox-launch: error: cogbox layout changed. The default instance now lives at:"
			echo "  config: $INSTANCE_CONFIG_DIR/"
			echo "  data:   $REAL_DATA/"
			echo "Migrate with:"
			if [ -n "$OLD_CFG" ]; then
				echo "  mkdir -p '$INSTANCE_CONFIG_DIR'"
				echo "  mv '$CONFIG_DIR/config.json' '$INSTANCE_CONFIG_DIR/'"
			fi
			if [ -n "$OLD_DATA" ]; then
				echo "  mkdir -p '$REAL_DATA'"
				echo "  mv '$BASE_DATA/claude-overlay.img' '$REAL_DATA/'"
				echo "  [ -d '$BASE_DATA/.config' ] && mv '$BASE_DATA/.config' '$REAL_DATA/'"
			fi
		} >&2
		exit 70
	fi
fi

# Detect pre-fix layouts where the per-instance flake.nix lived directly in
# the instance config dir. Sharing that dir with config.json meant any edit
# to config.json re-keyed the userExtensions flake input and busted the
# eval cache; the flake now lives in a "flake/" subdir.
if [ -d "$CONFIG_DIR/instances" ]; then
	OLD_FLAKES=()
	for dir in "$CONFIG_DIR/instances"/*/; do
		[ -d "$dir" ] || continue
		if [ -f "$dir/flake.nix" ] && [ ! -f "$dir/flake/flake.nix" ]; then
			OLD_FLAKES+=("${dir%/}")
		fi
	done
	if [ "${#OLD_FLAKES[@]}" -gt 0 ]; then
		{
			echo "cogbox-launch: error: cogbox flake layout changed. The per-instance flake now lives at:"
			echo "  <instance>/flake/flake.nix  (was: <instance>/flake.nix)"
			echo "Migrate with:"
			for d in "${OLD_FLAKES[@]}"; do
				echo "  mkdir -p '$d/flake'"
				if [ -f "$d/flake.lock" ]; then
					echo "  mv '$d/flake.nix' '$d/flake.lock' '$d/flake/'"
				else
					echo "  mv '$d/flake.nix' '$d/flake/'"
				fi
			done
		} >&2
		exit 70
	fi
fi

# Multi-harness migration: rename the per-instance overlay image from
# the old single-harness name. The image's content is preserved
# verbatim; the in-image upper/work shuffle into claude-code/config/
# is handled by harness-setup-dirs.service inside the guest.
if [ -d "$REAL_DATA" ] && [ -f "$REAL_DATA/claude-overlay.img" ] && [ ! -f "$REAL_DATA/harness-overlay.img" ]; then
	mv "$REAL_DATA/claude-overlay.img" "$REAL_DATA/harness-overlay.img"
fi

# -- Auto-port assignment -----------------------------------------
next_available_ports() {
	# Seeded one below the default's canonical 2222/8080, so the first
	# named instance auto-assigns to 2223/8081 even if the default does
	# not yet exist (i.e. 2222/8080 stays reserved for the default).
	local max_ssh=2222
	local max_http=8080
	# Seed one triple below the canonical L7 base so the first named instance
	# auto-assigns to 18446 (the default keeps 18443/18444/18445).
	local max_l7=18440

	if [ -d "$CONFIG_DIR/instances" ]; then
		for cfg in "$CONFIG_DIR/instances"/*/config.json; do
			[ -f "$cfg" ] || continue
			local s h l
			s=$(jq -r '.sshPort // 0' "$cfg")
			h=$(jq -r '.httpPort // 0' "$cfg")
			l=$(jq -r '.l7PortBase // 0' "$cfg")
			[ "$s" -gt "$max_ssh" ] && max_ssh=$s
			[ "$h" -gt "$max_http" ] && max_http=$h
			[ "$l" -gt "$max_l7" ] && max_l7=$l
		done
	fi

	# Each instance gets a contiguous L7 port triple (base / base+1 / base+2 =
	# TLS funnel / HTTP funnel / mitmproxy hop), so multiple L7 instances never
	# share a port. Step by 3 to keep triples disjoint.
	echo "$(( max_ssh + 1 )) $(( max_http + 1 )) $(( max_l7 + 3 ))"
}

# -- Harness state detection ---------------------------------------
# Active harnesses are those whose host state already exists. If none
# exist (fresh install), prompt the user to choose. The chosen list
# governs which harnesses' host paths get created during init.
ACTIVE_HARNESSES_FILE="$REAL_DATA/.config/active-harnesses"
ACTIVE_HARNESSES=()

# Detect harnesses that already have *any* host-side state (overlay or
# fw_cfg path present on disk, or already-active per a prior init).
for h in "${HARNESSES[@]}"; do
	active=0
	if [ -f "$ACTIVE_HARNESSES_FILE" ] && grep -qx "$h" "$ACTIVE_HARNESSES_FILE"; then
		active=1
	fi
	if [ "$active" -eq 0 ]; then
		while IFS= read -r k; do
			[ -z "$k" ] && continue
			kind=${H_KIND[$h:$k]}
			[ "$kind" = "ephemeral" ] && continue
			host=${H_HOST[$h:$k]}
			if [ "$kind" = "overlay" ] && [ -d "$host" ]; then
				active=1; break
			fi
			if [ "$kind" = "fw_cfg" ] && [ -e "$host" ]; then
				active=1; break
			fi
		done < <(harness_pathkeys "$h")
	fi
	if [ "$active" -eq 1 ]; then
		ACTIVE_HARNESSES+=("$h")
	fi
done

# -- First-time init: collect missing items, prompt once -----------
ITEMS=()
if [ ! -f "$INSTANCE_CONFIG_DIR/config.json" ]; then
	if [ -z "$INSTANCE_NAME" ]; then
		ITEMS+=("$INSTANCE_CONFIG_DIR/config.json  (default settings)")
	else
		ITEMS+=("$INSTANCE_CONFIG_DIR/config.json  (instance \"$INSTANCE_NAME\" settings)")
	fi
fi
if [ ! -f "$INSTANCE_FLAKE_DIR/flake.nix" ]; then
	ITEMS+=("$INSTANCE_FLAKE_DIR/flake.nix  (per-instance NixOS extensions, no-op default)")
fi
if [ ! -f "$CONFIG_DIR/authorized_keys" ]; then
	if [ "$AUTO_KEYS" -eq 1 ]; then
		ITEMS+=("$CONFIG_DIR/authorized_keys  (SSH public keys, seeded from ~/.ssh/*.pub + ssh-add -L)")
	else
		ITEMS+=("$CONFIG_DIR/authorized_keys  (SSH public keys, empty)")
	fi
fi
if [ "$AUTO_KEYS" -eq 1 ] && [ ! -f "$COGBOX_SSH_KEY" ] && command -v ssh-keygen >/dev/null 2>&1; then
	ITEMS+=("$COGBOX_SSH_KEY  (cogbox's own SSH key, the default identity for \`cogbox ssh\`)")
fi
if [ ! -d "$REAL_DATA" ]; then
	ITEMS+=("$REAL_DATA/  (VM data${INSTANCE_NAME:+ for \"$INSTANCE_NAME\"})")
fi

# If no harness has host state yet, prompt the user to pick which to
# set up. This avoids polluting $HOME with config dirs for tools the
# user doesn't use. Under a non-interactive stdin or with --yes, default
# to all harnesses.
if [ "${#ACTIVE_HARNESSES[@]}" -eq 0 ]; then
	if [ "$ASSUME_YES" -eq 0 ] && [ -t 0 ]; then
		echo "No harness state detected. Set up which?"
		idx=1
		for h in "${HARNESSES[@]}"; do
			echo "  [$idx] $h     ($(harness_summary "$h"))"
			idx=$((idx + 1))
		done
		all_idx=$idx
		echo "  [$all_idx] all"
		num_harnesses=${#HARNESSES[@]}
		read -rp "Choice [1-$all_idx, comma-separated for multiple]: " choice
		# Strip whitespace.
		choice="${choice// /}"
		if [ -z "$choice" ]; then
			die "Invalid choice." 64
		fi
		if [ "$choice" = "$all_idx" ]; then
			ACTIVE_HARNESSES=("${HARNESSES[@]}")
		else
			# Comma-separated indices, deduped while preserving order.
			IFS=',' read -ra picks <<< "$choice"
			declare -A seen=()
			for p in "${picks[@]}"; do
				case "$p" in ''|*[!0-9]*) die "Invalid choice." 64 ;; esac
				if [ "$p" -lt 1 ] || [ "$p" -gt "$num_harnesses" ]; then
					die "Invalid choice." 64
				fi
				h="${HARNESSES[$((p - 1))]}"
				if [ -z "${seen[$h]:-}" ]; then
					ACTIVE_HARNESSES+=("$h")
					seen[$h]=1
				fi
			done
		fi
	else
		ACTIVE_HARNESSES=("${HARNESSES[@]}")
	fi
fi

# Collect host paths to be created for active harnesses.
for h in "${ACTIVE_HARNESSES[@]}"; do
	while IFS= read -r k; do
		[ -z "$k" ] && continue
		kind=${H_KIND[$h:$k]}
		[ "$kind" = "ephemeral" ] && continue
		host=${H_HOST[$h:$k]}
		case "$kind" in
			overlay)
				if [ ! -d "$host" ]; then
					ITEMS+=("$host/  ($h $k)")
				fi
				;;
			fw_cfg)
				if [ ! -e "$host" ]; then
					ITEMS+=("$host  ($h $k)")
				fi
				;;
		esac
	done < <(harness_pathkeys "$h")
done

if [ "${#ITEMS[@]}" -gt 0 ]; then
	echo "The following paths will be created:"
	for item in "${ITEMS[@]}"; do
		echo "  $item"
	done
	echo ""
	if [ "$ASSUME_YES" -eq 1 ] || [ ! -t 0 ]; then
		confirm=y
	else
		read -rp "Continue? [y/N] " confirm
	fi
	if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
		echo "Aborted."
		exit 70
	fi

	mkdir -p "$INSTANCE_CONFIG_DIR" "$INSTANCE_FLAKE_DIR" "$REAL_DATA"

	# Create host-side directories for active harnesses' overlay paths.
	for h in "${ACTIVE_HARNESSES[@]}"; do
		while IFS= read -r k; do
			[ -z "$k" ] && continue
			kind=${H_KIND[$h:$k]}
			[ "$kind" = "overlay" ] || continue
			host=${H_HOST[$h:$k]}
			[ -d "$host" ] || mkdir -p "$host"
		done < <(harness_pathkeys "$h")
	done

	INIT_VCPU="${FLAG_VCPU:-16}"
	INIT_MEM="${FLAG_MEM:-32768}"
	INIT_NETWORK="${FLAG_NETWORK:-rules}"

	# Build network value for config: "full"/"none" as string, rules as object.
	# Default rules seed denies private/bogon ranges then allows public internet,
	# so a fresh install gets working internet without exposing LAN or cloud
	# metadata services to the sandbox. Loopback is omitted -- already denied
	# implicitly in filter.zig.
	if [ "$INIT_NETWORK" = "rules" ]; then
		# Seed L7 terminate+inject rules for the provider hosts of harnesses the
		# user is logged into (cred file present), so a new rules-mode instance
		# keeps tokens host-side by default (the chosen posture). Nothing is
		# seeded for a harness with no token yet; log in on the host first, or add
		# the rule later. Opt out by `cogbox l7 mode passthrough`, per-host
		# `cogbox l7 add allow <host> --passthrough`, or editing `.network.l7`.
		L7_SEED_JQ='null'
		if [ "${#ACTIVE_HARNESSES[@]}" -gt 0 ]; then
			_inject_hosts=$(active_inject_hosts)
			if [ -n "$_inject_hosts" ]; then
				L7_SEED_JQ=$(printf '%s\n' "$_inject_hosts" | jq -R -s '
					{ inject: true,
					  rules: [ split("\n")[] | select(length > 0)
					           | { allow: ., terminate: true, comment: "cred-inject (host-side)" } ] }')
			fi
		fi
		NETWORK_JQ=$(jq -nc --argjson l7 "$L7_SEED_JQ" '{
			rules: [
				{deny:  "0.0.0.0/8",        comment: "this network (RFC 1122)"},
				{deny:  "10.0.0.0/8",       comment: "RFC1918 private"},
				{deny:  "100.64.0.0/10",    comment: "carrier-grade NAT (RFC 6598)"},
				{deny:  "169.254.0.0/16",   comment: "link-local incl. cloud metadata 169.254.169.254"},
				{deny:  "172.16.0.0/12",    comment: "RFC1918 private"},
				{deny:  "192.0.0.0/24",     comment: "IETF protocol assignments (RFC 6890)"},
				{deny:  "192.0.2.0/24",     comment: "TEST-NET-1 documentation (RFC 5737)"},
				{deny:  "192.168.0.0/16",   comment: "RFC1918 private"},
				{deny:  "198.18.0.0/15",    comment: "benchmark testing (RFC 2544)"},
				{deny:  "198.51.100.0/24",  comment: "TEST-NET-2 documentation (RFC 5737)"},
				{deny:  "203.0.113.0/24",   comment: "TEST-NET-3 documentation (RFC 5737)"},
				{deny:  "224.0.0.0/4",      comment: "multicast (RFC 5771)"},
				{deny:  "240.0.0.0/4",      comment: "reserved/broadcast incl. 255.255.255.255"},
				{allow: "0.0.0.0/0",        comment: "public internet"}
			]
		} + (if $l7 != null then { l7: $l7 } else {} end)')
	else
		NETWORK_JQ="\"$INIT_NETWORK\""
	fi

	# Host-topology hardening, seeded into `.network` from --no-implicit-dns /
	# --dns-host / --self-addr. RULES MODE ONLY: in `full`/`none` the value is a
	# bare string, there is no L4 filter to parameterize and no l7proxy to give a
	# floor to -- the enclosing host's own packet filter is the only control
	# there, by design. Say so rather than writing keys nothing reads. (--dns-host
	# is rules-mode-only for the same reason and loses nothing by it: it exists to
	# re-admit one socket to the L4 walk, and full mode has no L4 walk. passt's
	# own --dns-host is a separate, mode-independent knob; see PASST_DNS_ARGS.)
	if [ "$FLAG_NO_IMPLICIT_DNS" -eq 1 ] || [ -n "$FLAG_DNS_HOST" ] || [ "${#FLAG_SELF_ADDRS[@]}" -gt 0 ]; then
		if [ "$INIT_NETWORK" = "rules" ]; then
			IMPLICIT_DNS_JQ='{}'
			[ "$FLAG_NO_IMPLICIT_DNS" -eq 1 ] && IMPLICIT_DNS_JQ='{"implicitDns":false}'
			SELF_ADDRS_JQ=$(printf '%s\n' "${FLAG_SELF_ADDRS[@]}" \
				| jq -R -s 'split("\n") | map(select(length > 0))')
			NETWORK_JQ=$(jq -nc \
				--argjson network "$NETWORK_JQ" \
				--argjson implicit "$IMPLICIT_DNS_JQ" \
				--arg dnshost "$FLAG_DNS_HOST" \
				--argjson self "$SELF_ADDRS_JQ" \
				'$network + $implicit
				 + (if ($dnshost | length) > 0 then { dnsHost: $dnshost } else {} end)
				 + (if ($self | length) > 0 then { selfAddrs: $self } else {} end)')
		else
			echo "cogbox-launch: warning: --no-implicit-dns/--dns-host/--self-addr apply to \"rules\" mode only; ignored for network mode \"$INIT_NETWORK\"." >&2
		fi
	fi

	if [ ! -f "$INSTANCE_CONFIG_DIR/config.json" ]; then
		if [ -z "$INSTANCE_NAME" ]; then
			INIT_SSH=2222
			INIT_HTTP=8080
			INIT_L7=18443
		else
			read -r INIT_SSH INIT_HTTP INIT_L7 <<< "$(next_available_ports)"
		fi
		# NOTE: no storeOverlaySize key. It used to be seeded as "16G", which
		# resize-store-overlay.service then remounted /nix/.rw-store to on every
		# boot -- larger than the guest's entire RAM, so a large `nix build`
		# OOM-killed the guest instead of failing cleanly with ENOSPC. Absent, the
		# guest keeps whatever the flake declares (a fraction of RAM on the
		# workstation profile, a block volume on the hosted one); an operator who
		# sets the key explicitly still wins.
		jq -n --tab \
			--argjson vcpu "$INIT_VCPU" \
			--argjson mem "$INIT_MEM" \
			--argjson network "$NETWORK_JQ" \
			--argjson ssh "$INIT_SSH" \
			--argjson http "$INIT_HTTP" \
			--argjson l7base "$INIT_L7" \
			--arg bindaddr "${FLAG_BIND_ADDR:-127.0.0.1}" \
			'{
				vcpu: $vcpu,
				mem: $mem,
				sshPort: $ssh,
				httpPort: $http,
				l7PortBase: $l7base,
				overlaySize: "128M",
				bindAddr: $bindaddr,
				network: $network
			}' > "$INSTANCE_CONFIG_DIR/config.json"
		[ -n "$INSTANCE_NAME" ] && echo "Instance \"$INSTANCE_NAME\" ports: SSH=$INIT_SSH HTTP=$INIT_HTTP L7=$INIT_L7"
	fi

	if [ ! -f "$INSTANCE_FLAKE_DIR/flake.nix" ]; then
		printf '%s' "$SCAFFOLD_FLAKE" > "$INSTANCE_FLAKE_DIR/flake.nix"
	fi

	if [ ! -f "$CONFIG_DIR/authorized_keys" ]; then
		if [ "$AUTO_KEYS" -eq 1 ]; then
			# Seed from the host user's existing pubkeys and any keys loaded
			# in their running ssh-agent (if SSH_AUTH_SOCK is set). Errors
			# are tolerated: missing ~/.ssh, no .pub files, or no agent all
			# just contribute zero lines. Result is sorted/deduped so the
			# same key from both sources doesn't appear twice.
			{
				if [ -d "$REAL_HOME/.ssh" ]; then
					for f in "$REAL_HOME/.ssh"/*.pub; do
						[ -f "$f" ] && cat "$f"
					done
				fi
				if [ -n "${SSH_AUTH_SOCK:-}" ] && command -v ssh-add >/dev/null; then
					ssh-add -L 2>/dev/null || true
				fi
			} | grep -v '^[[:space:]]*\(#\|$\)' | sort -u > "$CONFIG_DIR/authorized_keys"
		else
			touch "$CONFIG_DIR/authorized_keys"
			# Record the opt-out so subsequent plain launches don't generate the
			# cogbox key and re-authorize SSH access against the user's intent.
			touch "$COGBOX_KEY_OPTOUT"
		fi
	fi
	# Seed default content for fw_cfg paths (e.g. ~/.claude.json = '{}').
	for h in "${ACTIVE_HARNESSES[@]}"; do
		while IFS= read -r k; do
			[ -z "$k" ] && continue
			[ "${H_KIND[$h:$k]}" = "fw_cfg" ] || continue
			host=${H_HOST[$h:$k]}
			[ -e "$host" ] && continue
			printf '%s' "${H_FW_DEFAULT[$h:$k]}" > "$host"
			chmod "${H_FW_MODE[$h:$k]}" "$host"
		done < <(harness_pathkeys "$h")
	done
fi

# Persist the active-harness list so subsequent runs don't re-prompt.
mkdir -p "$REAL_DATA/.config"
printf '%s\n' "${ACTIVE_HARNESSES[@]}" > "$ACTIVE_HARNESSES_FILE"

# Generate cogbox's own SSH key (idempotent). Runs every launch, not just first
# init, so instances created before this feature gain it on the next start and a
# deleted key is regenerated (rotation). Skipped under --no-auto-keys for this
# launch, and permanently for a setup that opted out at init (the marker).
if [ "$AUTO_KEYS" -eq 1 ] && [ ! -f "$COGBOX_KEY_OPTOUT" ]; then
	ensure_cogbox_key
fi

# -- Fix file ownership after init under sudo ----------------------
if [ "$SUDO_INVOCATION" = 1 ]; then
	chown -R "$REAL_USER" "$CONFIG_DIR" "$REAL_DATA"
	# The key lives in the data-dir root, outside the chown -R above; without
	# this it would stay root-owned and ssh would refuse it as the real user.
	[ -f "$COGBOX_SSH_KEY" ] && chown "$REAL_USER" "$COGBOX_SSH_KEY" "$COGBOX_SSH_KEY.pub"
	for h in "${ACTIVE_HARNESSES[@]}"; do
		while IFS= read -r k; do
			[ -z "$k" ] && continue
			kind=${H_KIND[$h:$k]}
			[ "$kind" = "ephemeral" ] && continue
			host=${H_HOST[$h:$k]}
			[ -e "$host" ] || continue
			if [ -d "$host" ]; then
				chown -R "$REAL_USER" "$host"
			else
				chown "$REAL_USER" "$host"
			fi
		done < <(harness_pathkeys "$h")
	done
fi

# -- Re-exec with per-instance extensions overlaid ----------------
# Two sources of guest extension, checked in priority order; both fold
# in via --override-input userExtensions so the rebuilt microvm runner
# includes the extra modules. COGBOX_REEXECED breaks the loop after the
# first hop.
#
#  1. plugins-flake/ -- generated by `cogbox plugin` whenever config.json
#     has a non-empty .plugins array. It composes every plugin (inputs
#     pinned by rev and/or narHash) PLUS the user flake, so it subsumes
#     case 2.
#     The user flake's "nixpkgs" input is still forced to cogbox's
#     nixpkgs, now one level deeper (userExtensions/user/nixpkgs).
#  2. flake/flake.nix edited away from the scaffold. Skipped while the
#     scaffold is pristine: its nixosModules.default is empty, so the
#     microvm closure would be identical to the baked-in one anyway --
#     and re-evaluating the cogbox flake requires its inputs to be
#     fetchable, which a fresh "nix profile install" or
#     NixOS-systemPackages setup may not have locally cached. Users who
#     customize flake.nix (or add plugins) opt into the re-eval. `cmp`
#     is byte-exact and avoids the trailing-newline trim that command
#     substitution does.
#
# Where the runner comes from: the microvm "run" script (line ~1326) is
# generated from "$RUNNER_DIR/bin/microvm-run". RUNNER_DIR defaults to the
# baked @runner@ sentinel (the plugin-less, image-default runner). The
# re-exec below rebuilds cogbox with the plugins overlaid so the rebuilt
# wrapper's @runner@ is the plugin-composed runner; that pass then points
# RUNNER_DIR at it. The plugins re-exec re-evaluates the ENTIRE cogbox NixOS
# config every boot (~100s cold) because --override-input marks the flake
# mutable and disables nix's eval cache.
#
# @reexecPackage@ is the flake PACKAGE ATTRIBUTE to re-exec through, baked in by
# mkCogbox, and it is not decoration: `nix run path:<flake>` with no attribute
# resolves packages.default, which is always the WORKSTATION `cogbox`. On the GCE
# backend the image bakes cogbox-hosted, whose guest keeps work/ and
# machine-state on a dedicated block volume -- so an attribute-less re-exec would
# rebuild the workstation guest instead, and the first plugin add would silently
# unmount the user's data pool and show them the stale retained 9p work tree.
# @reexecPackage@ is "cogbox" for every non-GCE build, i.e. exactly what
# packages.default already resolved to.
RUNNER_DIR="${RUNNER_DIR:-@runner@}"
# Self-recorded fast path (plugins only). Once a plugins re-exec has built the
# composed runner, it writes its out-path here so the NEXT boot can realize
# that store path directly -- no flake eval. The file lives on the state PVC
# (under INSTANCE_CONFIG_DIR), so it persists across boots. Two lines:
#   line1 = the RECORD KEY, "<flakeSource>#<reexecPackage>";
#   line2 = the composed runner out-path.
#
# The key carries the package attribute and not just the image rev, and that is
# not decoration. @flakeSource@ is BYTE-IDENTICAL for cogbox and cogbox-hosted
# -- they are two packages built from one flake source -- while @runner@ and the
# composed runner built from it are not. Keyed on the rev alone, a record
# written by one package validated for the other, so a boot could realize a
# runner composed against a DIFFERENT guest storage layout and skip the re-exec
# that would have rebuilt it. That is a whole-instance failure in both
# directions (a guest that cannot open its drives, or one that mounts the wrong
# ones and shows an empty work tree), and it is sticky, because FAST_PATH=1 is
# precisely the path that does not rewrite the record.
#
# The GCE image now bakes exactly one package, so the collision has no live
# instance to happen on; this closes it at the source anyway, because the record
# outlives any single image and the cost is one string.
#
# A record written by an OLDER cogbox carries the bare flakeSource on line 1 and
# therefore no longer matches. That is the intended and only behaviour: the boot
# falls through to the normal re-exec, which rewrites the record in the new form.
# It costs one eval boot, and every such instance was going to pay one anyway --
# changing this file changes ${self}, so @flakeSource@ itself moved and the old
# record would have missed on the rev alone.
RUNNER_KEY="@flakeSource@#@reexecPackage@"
RUNNER_PATH_FILE="$INSTANCE_CONFIG_DIR/runner.path"
FAST_PATH=0

if [ -z "${COGBOX_REEXECED:-}" ]; then
	PLUGIN_COUNT=0
	if [ -f "$INSTANCE_CONFIG_DIR/config.json" ]; then
		PLUGIN_COUNT=$(jq -r '(.plugins // []) | length' "$INSTANCE_CONFIG_DIR/config.json" 2>/dev/null || echo 0)
	fi
	# Substituter options shared by both re-exec branches and the fast-path
	# realise below (this nix invocation only). The per-instance file:// plugin
	# cache resolves transitive tarball/narHash inputs offline; require-sigs
	# false is safe there: a file:// cache is content-addressed and nix still
	# verifies narHash; a local trusted cache is just unsigned. When cogworx
	# configured a remote runner cache (COGBOX_EXTRA_* / COGBOX_NETRC_FILE) the
	# worker pod pre-built and pushed the microvm runner closure there, so boot
	# substitutes it instead of rebuilding from source. Each remote knob is a
	# no-op when its env var is empty/unset (byte-identical to the pre-cache
	# behavior).
	PLUGIN_SUBST_OPTS=()
	SUBSTITUTERS=""
	if [ -d "$PLUGIN_CACHE_DIR" ]; then
		SUBSTITUTERS="file://$PLUGIN_CACHE_DIR"
	fi
	if [ -n "${COGBOX_EXTRA_SUBSTITUTERS:-}" ]; then
		SUBSTITUTERS="${SUBSTITUTERS:+$SUBSTITUTERS }$COGBOX_EXTRA_SUBSTITUTERS"
	fi
	if [ -n "$SUBSTITUTERS" ]; then
		PLUGIN_SUBST_OPTS+=(--option extra-substituters "$SUBSTITUTERS" --option require-sigs false)
	fi
	if [ -n "${COGBOX_EXTRA_TRUSTED_PUBLIC_KEYS:-}" ]; then
		PLUGIN_SUBST_OPTS+=(--option extra-trusted-public-keys "$COGBOX_EXTRA_TRUSTED_PUBLIC_KEYS")
	fi
	if [ -n "${COGBOX_NETRC_FILE:-}" ]; then
		PLUGIN_SUBST_OPTS+=(--option netrc-file "$COGBOX_NETRC_FILE")
	fi

	# -- Skip-eval fast path (plugins only) ---------------------------
	# If a previous plugins re-exec recorded a runner out-path for THIS image
	# rev, realize that store path directly and skip the re-exec/eval entirely.
	# This is strictly an optimization and MUST be fail-safe: on any problem
	# (no record, rev marker mismatch, realise fails, run script absent) we
	# leave FAST_PATH=0 and fall through to the normal re-exec/eval path, which
	# re-records the (possibly new) rev -- so the path self-heals across image
	# upgrades.
	if [ "$PLUGIN_COUNT" -gt 0 ] && [ -f "$RUNNER_PATH_FILE" ]; then
		FP_REV="" FP_RUNNER=""
		{ IFS= read -r FP_REV; IFS= read -r FP_RUNNER; } < "$RUNNER_PATH_FILE" || true
		# Only trust the record when it was written against the current image
		# rev AND the same package attribute -- see RUNNER_KEY above for why the
		# rev alone is not a key.
		if [ "$FP_REV" = "$RUNNER_KEY" ] && [ -n "$FP_RUNNER" ]; then
			if [ -e "$FP_RUNNER/bin/microvm-run" ]; then
				RUNNER_DIR="$FP_RUNNER"
				FAST_PATH=1
			elif nix-store --realise "${PLUGIN_SUBST_OPTS[@]}" "$FP_RUNNER" >/dev/null 2>&1 \
				&& [ -e "$FP_RUNNER/bin/microvm-run" ]; then
				RUNNER_DIR="$FP_RUNNER"
				FAST_PATH=1
			fi
		fi
	fi
fi

if [ -z "${COGBOX_REEXECED:-}" ] && [ "$FAST_PATH" -ne 1 ]; then
	if [ "$PLUGIN_COUNT" -gt 0 ] && [ -f "$PLUGINS_FLAKE_DIR/flake.nix" ]; then
		exec env COGBOX_REEXECED=1 nix \
			--extra-experimental-features "nix-command flakes" \
			"${PLUGIN_SUBST_OPTS[@]}" \
			run "path:@flakeSource@#@reexecPackage@" \
			--override-input userExtensions "path:$PLUGINS_FLAKE_DIR" \
			--override-input userExtensions/user/nixpkgs "path:@nixpkgsSource@" \
			-- "${ORIG_ARGS[@]}"
	elif [ "$PLUGIN_COUNT" -gt 0 ]; then
		echo "Error: config.json lists $PLUGIN_COUNT plugin(s) but $PLUGINS_FLAKE_DIR/flake.nix is missing." >&2
		echo "Run 'cogbox plugin update' to regenerate it." >&2
		exit 70
	elif [ -f "$INSTANCE_FLAKE_DIR/flake.nix" ] \
		&& ! printf '%s' "$SCAFFOLD_FLAKE" | cmp -s - "$INSTANCE_FLAKE_DIR/flake.nix"; then
		exec env COGBOX_REEXECED=1 nix \
			--extra-experimental-features "nix-command flakes" \
			"${PLUGIN_SUBST_OPTS[@]}" \
			run "path:@flakeSource@#@reexecPackage@" \
			--override-input userExtensions "path:$INSTANCE_FLAKE_DIR" \
			--override-input userExtensions/nixpkgs "path:@nixpkgsSource@" \
			-- "${ORIG_ARGS[@]}"
	fi
fi

# -- Self-record the composed runner for the next boot's fast path -
# Reached here in the re-exec'd (eval) pass, @runner@/@flakeSource@ have been
# substituted to THIS rev's freshly-built values, so the record is always
# correct for the current image. Only the plugins case is fast-pathed, so only
# record when the plugins flake drove this re-exec (a customized 0-plugin flake
# re-exec stays on the eval path). Best-effort: a write failure must not abort
# boot, hence the `|| true`.
if [ -n "${COGBOX_REEXECED:-}" ] && [ -f "$PLUGINS_FLAKE_DIR/flake.nix" ]; then
	printf '%s\n%s\n' "$RUNNER_KEY" "@runner@" > "$RUNNER_PATH_FILE" 2>/dev/null || true
fi

# -- init-only stops here ------------------------------------------
# By this point host state is seeded and (for a customized per-instance
# flake) the runner has been built via the re-exec above, warming the cache
# for the daemon launch. Runtime-dir setup and the VM launch belong to the
# daemon, so `cogbox init` and the foreground init step both stop here.
if [ "$INIT_ONLY" -eq 1 ]; then
	echo "Init complete${INSTANCE_NAME:+ (instance \"$INSTANCE_NAME\")}."
	exit 0
fi

# -- Validate and read runtime config -----------------------------
ACTIVE_CONFIG="$INSTANCE_CONFIG_DIR/config.json"
if ! jq empty "$ACTIVE_CONFIG" 2>/dev/null; then
	die "invalid JSON in $ACTIVE_CONFIG" 70
fi

VCPU="${FLAG_VCPU:-$(jq -r '.vcpu // 16' "$ACTIVE_CONFIG")}"
MEM="${FLAG_MEM:-$(jq -r '.mem // 32768' "$ACTIVE_CONFIG")}"
SSH_PORT=$(jq -r '.sshPort // 2222' "$ACTIVE_CONFIG")
HTTP_PORT=$(jq -r '.httpPort // 8080' "$ACTIVE_CONFIG")
# Per-instance L7 loopback port base (default = canonical 18443 for instances
# created before per-instance ports existed). The proxy binds base/base+1 and
# reaches the mitmproxy terminate backend on base+2; mirrors filter.l7PortsForBase.
L7_BASE=$(jq -r '.l7PortBase // 18443' "$ACTIVE_CONFIG")
L7_MITM_PORT=$(( L7_BASE + 2 ))
# The per-sandbox auth proxy listens DOWNWARD from the base (mirrors
# filter.l7AuthPortForBase: auth = base - 400). Topology, never policy: it lives
# only in env (COGBOX_L7_AUTH_PORT), never in config.json or a wire file.
L7_AUTH_PORT=$(( L7_BASE - 400 ))
OVERLAY_SIZE=$(jq -r '.overlaySize // "128M"' "$ACTIVE_CONFIG")
# Empty, not "16G": the size file this writes is what resize-store-overlay.service
# remounts /nix/.rw-store to, and 16G exceeds the guest's whole RAM, so the old
# default turned a large in-guest `nix build` into an OOM instead of an ENOSPC. No
# file => the guest keeps the size the flake declares. An explicit config value is
# still honoured, so an operator can pin one per instance.
STORE_OVERLAY_SIZE=$(jq -r '.storeOverlaySize // ""' "$ACTIVE_CONFIG")
BIND_ADDR=$(jq -r '.bindAddr // "127.0.0.1"' "$ACTIVE_CONFIG")

# -- Host-integration knobs (all empty/off by default) --------------
# Set by the enclosing platform, never by a user rule verb. Every one of them
# appends nothing when unset, so a local or k8s launch runs the exact argv it
# ran before they existed.
#
# COGBOX_PASST_RUNAS   passt --runas <user>: give passt a DEDICATED uid instead
#                      of the ambient `nobody` it self-drops to, so a packet
#                      filter on the host can express "guest-originated" as a
#                      uid match. Needs initial euid 0 or CAP_SETUID; when the
#                      launcher runs as root (the k8s pod already does) that
#                      holds. Applied in BOTH rules and full mode: full mode is
#                      the one with no L4 filter at all, so the host's uid-scoped
#                      rule is its only floor.
# COGBOX_PROXY_RUNAS   run l7proxy and the mitmproxy terminate backend under
#                      <user>:<group> (setpriv). Same reason from the other
#                      side: in rules mode the proxy re-resolves an allowed
#                      vhost and opens the upstream socket under ITS uid, not
#                      passt's, so a passt-only rule leaves the proxy as an
#                      unscoped relay. The runtime dir, the per-instance CA dir
#                      and the mitmproxy confdir must be writable by that uid.
# COGBOX_GUEST_RESOLVER  passt --dns-forward <addr> AND --no-map-gw: advertise
#                      <addr> to the guest as its nameserver and INTERCEPT the
#                      guest's queries to it, re-emitting them host-side to
#                      passt's --dns-host address; and stop mapping the gateway
#                      address to the host. <addr> is therefore a handle, not a
#                      destination: the guest's DNS packets never leave the tap,
#                      so the address needs no routability and faces no L4 rule.
#                      What the guest actually resolves is whatever the HOST's
#                      resolver resolves -- internal names included, which is the
#                      parity the local and k8s backends have for free.
#
#                      The two flags are ONE knob on purpose. --no-map-gw is
#                      what closes the DNS carve-out: passt normally maps the
#                      gateway to the host, and traffic to that address on port
#                      53 is NOT translated to loopback but handled as
#                      --dns-forward to the host's own resolver -- so the guest
#                      reaches the host resolver at a destination `evaluate`
#                      never sees as loopback. Where the host resolver is an
#                      address the sandbox must not reach, that is the hole, in
#                      BOTH modes (full mode has no L4 filter at all). But
#                      --no-map-gw ALSO disables the remap of loopback resolvers
#                      from /etc/resolv.conf, which is how a dev box running
#                      systemd-resolved gives its guests DNS at all. Dropping
#                      the mapping is therefore safe exactly when an explicit
#                      guest resolver replaces it -- which is why this knob
#                      carries both flags and neither is applied without it.
#
#                      NOT `-D`, and the difference is the whole mechanism.
#                      passt applies -D BEFORE reading /etc/resolv.conf and then
#                      SKIPS reading it (conf.c get_dns(): `dns4_set` short-
#                      circuits), so dns_host is left unspecified and passt's own
#                      DNS forwarding is silently disarmed -- the guest gets a
#                      raw address it must then reach on its own, which on a host
#                      whose resolver is fenced off means a PUBLIC resolver and
#                      no internal names. With --dns-forward and no -D, passt
#                      reads resolv.conf, sees the host's LOOPBACK forwarder
#                      there, and (per its own add_dns_resolv4 comment for
#                      "--dns-forward and --no-map-gw") advertises the
#                      --dns-forward address in its place while mapping it to the
#                      forwarder. That requires the host's first resolv.conf
#                      nameserver to BE a loopback address; where it is not,
#                      COGBOX_HOST_RESOLVER below pins the target explicitly.
# COGBOX_HOST_RESOLVER  passt --dns-host <addr>: the address passt re-emits the
#                      intercepted queries to, i.e. the loopback forwarder on the
#                      enclosing host. Only applied together with
#                      COGBOX_GUEST_RESOLVER, because alone it would pin a
#                      forwarding target for a forwarding path nothing enabled.
#                      passt takes a bare address here (conf.c parses it with
#                      inet_pton, so a `host:port` spelling is rejected outright)
#                      and, unlike --dns-forward, it accepts a loopback one.
#                      The L4 shim needs the matching `cogbox init --dns-host`
#                      seed to let that loopback socket through in rules mode;
#                      the enclosing host's own packet filter needs a rule for
#                      it too. Nothing sets this on a local, k8s or container
#                      launch, so their argv is unchanged.
# COGBOX_PASST_BIND_FORWARDS  bind the guest port forwards to $BIND_ADDR
#                      instead of every address. Opt-in because the k8s and
#                      local backends leave `.bindAddr` at 127.0.0.1 and depend
#                      on the forwards being reachable at the pod/host address.
# COGBOX_MOSH_UDP_FORWARD  <lo>-<hi>: also forward this guest UDP port range
#                      through passt (`-u`), for mosh. mosh-server binds a
#                      port in this range inside the guest (the cogworx
#                      gateway injects `-p lo:hi` into the exec) and the
#                      gateway relays the client's datagrams to the host
#                      address, so the forward must exist for the session to
#                      reach the guest at all. Digits only, dash-separated;
#                      anything else is a usage error (exit 64). Composes with
#                      COGBOX_PASST_BIND_FORWARDS exactly like the -t forwards
#                      (`-u <bind>/lo-hi`). The LD_PRELOAD netfilter shim reads
#                      the SAME variable to exempt passt's inbound reply
#                      sockets (docs/network-filtering.md), so the two never
#                      name different ranges. Unset => no -u and the passt argv
#                      is byte-identical to before the knob existed. `none`
#                      mode (SLIRP) ignores it: mosh is unsupported there.
PASST_RUNAS_ARGS=()
[ -n "${COGBOX_PASST_RUNAS:-}" ] && PASST_RUNAS_ARGS=(--runas "$COGBOX_PASST_RUNAS")
PASST_DNS_ARGS=()
if [ -n "${COGBOX_GUEST_RESOLVER:-}" ]; then
	PASST_DNS_ARGS=(--no-map-gw --dns-forward "$COGBOX_GUEST_RESOLVER")
	[ -n "${COGBOX_HOST_RESOLVER:-}" ] && PASST_DNS_ARGS+=(--dns-host "$COGBOX_HOST_RESOLVER")
fi
# PHASE-0: passt(1) documents `-t 22:23` (port pair) and `-t 192.0.2.1/22`
# (address-scoped) separately and never in combination; prove the composition
# on the target passt build before relying on this knob.
PASST_FWD_PREFIX=""
[ -n "${COGBOX_PASST_BIND_FORWARDS:-}" ] && PASST_FWD_PREFIX="${BIND_ADDR}/"
# mosh UDP forward. Validated to <digits>-<digits> so a stray colon (the
# mosh-server `-p lo:hi` spelling) or a bare port can never reach passt, whose
# own parse error would only surface as a boot-loop; the passt(1) range form
# is `-u lo-hi`, and the bind prefix composes as for -t. Never add
# `--outbound-addr`/`-o` here: the shim's reply exemption keys on
# guest-originated UDP binding the unspecified address.
PASST_MOSH_ARGS=()
if [ -n "${COGBOX_MOSH_UDP_FORWARD:-}" ]; then
	case "$COGBOX_MOSH_UDP_FORWARD" in
		# reject first (non-digit, leading/trailing/doubled dash), then require
		# exactly one dash so a bare port is refused too
		*[!0-9-]*|-*|*-|*-*-*|'') die "COGBOX_MOSH_UDP_FORWARD must be <lo>-<hi> (digits), got '$COGBOX_MOSH_UDP_FORWARD'" 64 ;;
		*-*) ;;
		*) die "COGBOX_MOSH_UDP_FORWARD must be <lo>-<hi> (digits), got '$COGBOX_MOSH_UDP_FORWARD'" 64 ;;
	esac
	# same bounds as the shim's parsePortRange (zig/src/filter.zig): 1 <= lo <=
	# hi <= 65535, so a range the shim would silently refuse never reaches passt
	mosh_lo="${COGBOX_MOSH_UDP_FORWARD%-*}"
	mosh_hi="${COGBOX_MOSH_UDP_FORWARD#*-}"
	if [ "${#mosh_lo}" -gt 5 ] || [ "${#mosh_hi}" -gt 5 ] \
		|| [ "$mosh_lo" -lt 1 ] || [ "$mosh_hi" -gt 65535 ] || [ "$mosh_lo" -gt "$mosh_hi" ]; then
		die "COGBOX_MOSH_UDP_FORWARD must be <lo>-<hi> with 1 <= lo <= hi <= 65535, got '$COGBOX_MOSH_UDP_FORWARD'" 64
	fi
	unset mosh_lo mosh_hi
	PASST_MOSH_ARGS=(-u "${PASST_FWD_PREFIX}${COGBOX_MOSH_UDP_FORWARD}")
fi
# Run a host-half helper under the proxy uid when one is configured. Expands to
# nothing when it is not, so the command line is unchanged.
# Accepts `user` (group of the same name) or `user:group`.
PROXY_RUNAS_ARGS=()
if [ -n "${COGBOX_PROXY_RUNAS:-}" ]; then
	command -v setpriv >/dev/null 2>&1 \
		|| die "COGBOX_PROXY_RUNAS is set but setpriv is not on PATH; refusing to run the proxies as the launching user instead." 70
	PROXY_RUNAS_ARGS=(setpriv --reuid "${COGBOX_PROXY_RUNAS%%:*}" --regid "${COGBOX_PROXY_RUNAS#*:}" --clear-groups)
fi

# -- Classify network mode -----------------------------------------
if [ -n "$FLAG_NETWORK" ]; then
	NETWORK_MODE="$FLAG_NETWORK"
else
	NETWORK_RAW=$(jq -c '.network // "full"' "$ACTIVE_CONFIG")
	if [ "$NETWORK_RAW" = '"full"' ] || [ "$NETWORK_RAW" = '"none"' ]; then
		NETWORK_MODE=$(echo "$NETWORK_RAW" | tr -d '"')
	else
		NETWORK_MODE="rules"
	fi
fi

# -- Write VM-side config into the data directory ------------------
mkdir -p "$REAL_DATA/.config"
echo "$OVERLAY_SIZE" > "$REAL_DATA/.config/overlay-size"
# Only write the store-overlay size when one was actually configured. An ABSENT
# file means "use the size the flake declared"; a present file means "remount to
# this", and resize-store-overlay.service reads it on every boot. Writing an empty
# file would make that unit remount to size= (invalid), so remove instead -- and
# removing it is also how an instance created before this change stops being
# pinned to the old 16G once its config.json no longer names a size.
# Note the reach: an instance created BEFORE this change still has an explicit
# storeOverlaySize in its config.json, so it keeps being pinned to whatever that
# says until the key is removed. Deliberate -- silently rewriting a user's instance
# config is worse than a stale size, and the hosted profile is covered anyway
# because resize-store-overlay.service is gated off there.
if [ -n "$STORE_OVERLAY_SIZE" ]; then
	echo "$STORE_OVERLAY_SIZE" > "$REAL_DATA/.config/store-overlay-size"
else
	rm -f "$REAL_DATA/.config/store-overlay-size"
fi
# The VM's authorized_keys is the user-managed file (per-instance override, else
# the shared one) unioned with cogbox's own pubkey, so `cogbox ssh` works out of
# the box. The union is keyed on the key file's existence, not the AUTO_KEYS
# flag: once generated the key is always honored, and a --no-auto-keys-only
# setup (no key file) gets exactly its user-provided keys.
if [ -n "$INSTANCE_NAME" ] && [ -f "$INSTANCE_CONFIG_DIR/authorized_keys" ]; then
	AUTHKEYS_SRC="$INSTANCE_CONFIG_DIR/authorized_keys"
else
	AUTHKEYS_SRC="$CONFIG_DIR/authorized_keys"
fi
# The `echo` between the two sources forces a record boundary: a user-managed
# authorized_keys with no trailing newline would otherwise splice its last key
# onto the cogbox pubkey, corrupting both. The grep then drops the resulting
# blank line(s) (and any comment/blank lines); sort -u dedupes.
{
	[ -f "$AUTHKEYS_SRC" ] && cat "$AUTHKEYS_SRC"
	echo
	[ -f "$COGBOX_SSH_KEY.pub" ] && cat "$COGBOX_SSH_KEY.pub"
} | grep -v '^[[:space:]]*\(#\|$\)' | sort -u > "$REAL_DATA/.config/authorized_keys"

# -- Set up runtime symlink directory for QEMU ---------------------
# Single-starter guard. The lock lives beside (not inside) $RUNTIME so the
# rm -rf below cannot clear it. Two near-simultaneous `cogbox start` for the
# same instance would otherwise both wipe + recreate $RUNTIME and boot two
# QEMUs against the same overlay image (corruption).
#
# We hold an exclusive flock on $LOCK for this daemon's ENTIRE lifetime: the
# fd stays open through the final `wait "$QEMU_PID"`, so the kernel keeps the
# lock until the daemon (and the QEMU/passt it spawned, which inherit the fd)
# is gone. flock -n fails immediately for any concurrent or already-running
# starter -> exit 75. This is race-free where the old pid-file dance was not:
# the kernel arbitrates the single winner atomically, and a crashed start
# releases the lock automatically (fd closed on death) with no stale-pid
# bookkeeping to get wrong.
LOCK="${RUNTIME}.lock"
exec {LOCK_FD}>"$LOCK" || die "cannot open start lock $LOCK" 70
if ! @flock@ -n "$LOCK_FD"; then
	die "instance${INSTANCE_NAME:+ \"$INSTANCE_NAME\"} is already running or starting." 75
fi

if [ -e "$RUNTIME" ]; then
	if [ -f "$RUNTIME/pid" ] && kill -0 "$(cat "$RUNTIME/pid")" 2>/dev/null; then
		die "instance${INSTANCE_NAME:+ \"$INSTANCE_NAME\"} is already running (PID $(cat "$RUNTIME/pid"))." 75
	fi
	rm -rf "$RUNTIME"
fi
mkdir -p "$RUNTIME"

# `cogbox start` opened our stdout/stderr on $RUNTIME/cogbox.log before
# exec'ing us, but the rm -rf above unlinked that inode. Reopen the fresh
# cogbox.log so daemon diagnostics (passt, QEMU stderr, errors below) are
# actually captured. Only when daemonized (stdout is the log file, not a
# tty); a hand-run launch keeps writing to its terminal.
if [ ! -t 1 ]; then
	exec >>"$RUNTIME/cogbox.log" 2>&1
fi

echo "$$" > "$RUNTIME/pid"

# -- Ensure the host ports we are about to bind are actually free ----
# next_available_ports keeps ports disjoint among THIS user's instances, but
# passt forwards SSH/HTTP and the L7 proxy + mitmproxy bind on the host's
# SHARED loopback -- so on a multi-user host a DIFFERENT user's instance (or
# any unrelated process) may already hold them. The bind would then fail and
# the start abort (fail-closed). Probe what we are about to bind and, if taken,
# slide to the next free port/triple, then persist so __render-rules (which
# reads l7PortBase back from config.json) and future launches agree.
# The probe is a loopback connect, so it catches the common conflict (another
# instance's passt/proxy listening on 0.0.0.0 or 127.0.0.1). A listener bound to
# ONLY a specific non-loopback host IP isn't seen here; passt's own bind would
# still surface that as a (now diagnosable) failure rather than a silent boot.
port_taken() {
	# 0 (true) when a TCP listener answers at $1:$2 within ~1s -- i.e. we could
	# not bind it. bash's /dev/tcp connect succeeds iff something is listening;
	# a refused connect (free port) returns immediately. The 1s timeout bounds
	# the case where bindAddr is a non-loopback host IP and a DROP (not REJECT)
	# firewall rule silently swallows the SYN -- an un-timed connect would then
	# block for the full kernel retry window (~2 min) per port, stalling the
	# (flock-holding) daemon. An indeterminate probe is treated as free; a real
	# late conflict is still caught by the bind itself, which now fails loud.
	timeout 1 bash -c '(exec 3<>"/dev/tcp/$1/$2")' _ "$1" "$2" 2>/dev/null
}
next_free_port() {
	# First free port >= $1 on address $2, scanning upward.
	local p=$1 addr=$2
	while [ "$p" -le 65500 ] && port_taken "$addr" "$p"; do p=$((p + 1)); done
	echo "$p"
}
next_free_l7_base() {
	# First base >= $1 (stepping by 3 so triples stay disjoint, mirroring
	# next_available_ports) whose whole loopback triple base/+1/+2 AND the auth
	# proxy's downward port (base-400) are all free. The auth port shares the
	# loopback with the triple, so a base is only usable when its auth slot is
	# free too -- otherwise the retarget would collide with a foreign listener.
	local b=$1
	while [ "$b" -le 65000 ] && { port_taken 127.0.0.1 "$b" || port_taken 127.0.0.1 $((b + 1)) || port_taken 127.0.0.1 $((b + 2)) || port_taken 127.0.0.1 $((b - 400)); }; do
		b=$((b + 3))
	done
	echo "$b"
}
PORTS_CHANGED=0
_new=$(next_free_port "$SSH_PORT" "$BIND_ADDR")
if [ "$_new" != "$SSH_PORT" ]; then
	echo "cogbox-launch: SSH port $SSH_PORT ($BIND_ADDR) in use; using $_new instead." >&2
	SSH_PORT=$_new; PORTS_CHANGED=1
fi
_new=$(next_free_port "$HTTP_PORT" "$BIND_ADDR")
if [ "$_new" != "$HTTP_PORT" ]; then
	echo "cogbox-launch: HTTP port $HTTP_PORT ($BIND_ADDR) in use; using $_new instead." >&2
	HTTP_PORT=$_new; PORTS_CHANGED=1
fi
if [ "$NETWORK_MODE" = "rules" ]; then
	_new=$(next_free_l7_base "$L7_BASE")
	if [ "$_new" != "$L7_BASE" ]; then
		echo "cogbox-launch: L7 port base $L7_BASE in use; using $_new instead." >&2
		L7_BASE=$_new; L7_MITM_PORT=$((L7_BASE + 2)); L7_AUTH_PORT=$((L7_BASE - 400)); PORTS_CHANGED=1
	fi
fi
if [ "$PORTS_CHANGED" -eq 1 ]; then
	# Persist atomically. __render-rules below reads l7PortBase from config, so
	# config MUST reflect the new base before it runs -- otherwise the netfilter
	# funnel and the proxy would point at different ports.
	_cfg_tmp=$(mktemp "${ACTIVE_CONFIG}.XXXXXX") || die "cannot create temp file to persist reallocated ports"
	if jq --tab --argjson ssh "$SSH_PORT" --argjson http "$HTTP_PORT" --argjson l7 "$L7_BASE" \
		'.sshPort = $ssh | .httpPort = $http | .l7PortBase = $l7' "$ACTIVE_CONFIG" > "$_cfg_tmp"; then
		mv "$_cfg_tmp" "$ACTIVE_CONFIG"
		[ "$SUDO_INVOCATION" = 1 ] && chown "$REAL_USER" "$ACTIVE_CONFIG"
	else
		rm -f "$_cfg_tmp"
		die "failed to persist reallocated ports to $ACTIVE_CONFIG"
	fi
fi

# Snapshot the active SSH endpoint for the `ssh` subcommand to read.
# Bound to runtime, not config, so post-boot edits to config.json don't
# misdirect connections to a port the VM isn't listening on.
echo "$SSH_PORT $BIND_ADDR" > "$RUNTIME/ssh-endpoint"
PASST_PID=""
L7PROXY_PID=""
L7MITM_PID=""
L7AUTH_PID=""
QEMU_PID=""
CLEANED=0
# The VM is always a background daemon now, so this script's only job after
# launch is to babysit QEMU and clean up. Forwarding the signal to QEMU (the
# wait target) is what makes `cogbox stop` tear the VM down: previously QEMU
# ran in this script's foreground and a SIGTERM here never reached it. We
# SIGTERM QEMU, give it a few seconds to flush + exit, then SIGKILL, and only
# then remove the runtime dir -- so we never rm the overlay/sockets out from
# under a still-running QEMU.
cogbox_cleanup() {
	# Capture the status that triggered the EXIT trap BEFORE any command below
	# overwrites $? -- it tells us whether the start succeeded.
	local rc=$?
	[ "$CLEANED" -eq 1 ] && return
	CLEANED=1
	if [ -n "$QEMU_PID" ]; then
		kill -TERM "$QEMU_PID" 2>/dev/null
		for _ in $(seq 1 50); do
			kill -0 "$QEMU_PID" 2>/dev/null || break
			sleep 0.1
		done
		kill -KILL "$QEMU_PID" 2>/dev/null
		wait "$QEMU_PID" 2>/dev/null
	fi
	[ -n "$PASST_PID" ] && kill "$PASST_PID" 2>/dev/null
	[ -n "$L7PROXY_PID" ] && kill "$L7PROXY_PID" 2>/dev/null
	[ -n "$L7MITM_PID" ] && kill "$L7MITM_PID" 2>/dev/null
	# A leaked auth proxy holds its per-instance loopback port and perturbs the
	# next start's probe, so tear it down with the other children.
	[ -n "$L7AUTH_PID" ] && kill "$L7AUTH_PID" 2>/dev/null
	# Dynamic 9p sources and their manifest may contain caller path bytes. QEMU
	# is dead before these are removed; retained failed-launch runtimes keep only
	# diagnostics, never stale grants for a later launch.
	rm -rf "$RUNTIME/additional-dirs"
	rm -f "$RUNTIME/additional-dir-args" "$RUNTIME/system-additional-dirs"
	# Remove this instance's sanitized cred-inject mirrors (QEMU is dead now, so
	# the 9p source is no longer in use). The mirror is hardlinks/no secret, but
	# tidy it rather than leave it under the data root until the next boot.
	rm -rf "$BASE_DATA/mirrors/${EFFECTIVE_NAME}"
	rmdir "$BASE_DATA/mirrors" 2>/dev/null
	# Remove the transient runtime dir only on a CLEAN exit: a deliberate stop
	# (143, from the TERM/INT trap below) or a clean QEMU shutdown (0). On any
	# other status the start FAILED -- a die() before the VM came up, or QEMU
	# dying during boot -- so keep $RUNTIME (and its cogbox.log) intact: that is
	# the very file `cogbox start` tells the user to read ("VM did not come up.
	# See .../cogbox.log"), and blowing it away here left them with a dangling
	# pointer. A stale dir is harmless -- the next start removes it (its pid is
	# dead) before recreating, so failed-start logs never accumulate.
	if [ "$rc" -eq 0 ] || [ "$rc" -eq 143 ]; then
		rm -rf "$RUNTIME"
	elif [ -n "$QEMU_PID" ]; then
		# QEMU had launched, so the start itself succeeded -- this is the VM
		# dying later (a crash, an external SIGKILL, a guest fault). Keep the
		# dir: cogbox.log/console.log are the post-mortem for that exit.
		echo "cogbox-launch: VM terminated unexpectedly (status $rc); keeping runtime dir for diagnosis: $RUNTIME/cogbox.log" >&2
	else
		# Failed before QEMU ever launched (passt/L7/persist) -- the "VM did not
		# come up" case; keep the log the start error points the user at.
		echo "cogbox-launch: start failed (status $rc); keeping runtime dir for diagnosis: $RUNTIME/cogbox.log" >&2
	fi
	# Leave $LOCK in place: it is an flock target, not a pid file. Our held
	# fd is released when this process exits (kernel-managed); unlinking it
	# here would only risk a new starter racing on a fresh inode. The empty
	# file lingers harmlessly in the tmpfs runtime base (cleared on logout).
}
trap cogbox_cleanup EXIT
# SIGTERM/SIGINT -> exit -> EXIT trap fires cogbox_cleanup. Interrupts the
# `wait "$QEMU_PID"` at the end of the script.
trap 'exit 143' TERM INT

# Stage dynamic sources behind numeric aliases. Caller paths appear only as
# symlink targets and JSON strings; QEMU's unquoted extra-argument expansion
# sees fixed tokens containing relative aliases, never caller-controlled bytes.
mkdir -m 0700 "$RUNTIME/additional-dirs" \
	|| die "cannot create additional-directory staging area" 70
_additional_qemu_tokens=()
_additional_manifest='[]'
for _additional_i in "${!FLAG_ADDITIONAL_DIR_PATHS[@]}"; do
	_additional_path=${FLAG_ADDITIONAL_DIR_PATHS[_additional_i]}
	if ! _staged_canonical=$(realpath -e -- "$_additional_path" 2>/dev/null); then
		die "additional directory is missing or inaccessible: $_additional_path" 66
	fi
	if [ ! -d "$_staged_canonical" ]; then
		die "additional directory option requires a directory: $_additional_path" 65
	fi
	if [ "$_staged_canonical" != "$_additional_path" ]; then
		die "additional directory changed while the launch was being prepared: $_additional_path" 65
	fi
	ln -s -- "$_additional_path" "$RUNTIME/additional-dirs/$_additional_i" \
		|| die "cannot stage additional directory $_additional_path" 70

	_readonly=false
	[ "${FLAG_ADDITIONAL_DIR_MODES[_additional_i]}" = ro ] && _readonly=true
	_additional_qemu_tokens+=(
		"-fsdev"
		"local,id=cogboxadddir${_additional_i},path=additional-dirs/${_additional_i},security_model=none,readonly=${_readonly}"
		"-device"
		"virtio-9p-pci,fsdev=cogboxadddir${_additional_i},mount_tag=cogbox-add-dir-${_additional_i}"
	)
	if ! _additional_manifest=$(jq -cn \
		--argjson entries "$_additional_manifest" \
		--arg tag "cogbox-add-dir-${_additional_i}" \
		--arg target "$_additional_path" \
		--argjson readOnly "$_readonly" \
		'$entries + [{tag: $tag, target: $target, readOnly: $readOnly}]'); then
		die "cannot encode additional-directory manifest" 70
	fi
done

_args_tmp="$RUNTIME/.additional-dir-args.tmp"
{
	echo '#!/usr/bin/env bash'
	if [ "${#_additional_qemu_tokens[@]}" -gt 0 ]; then
		printf "printf '%%s\\n' '%s'\n" "${_additional_qemu_tokens[*]}"
	else
		echo ':'
	fi
} > "$_args_tmp" || die "cannot write additional-directory QEMU arguments" 70
chmod 0700 "$_args_tmp" || die "cannot protect additional-directory QEMU arguments" 70
mv "$_args_tmp" "$RUNTIME/additional-dir-args" \
	|| die "cannot install additional-directory QEMU arguments" 70

_manifest_tmp="$RUNTIME/.system-additional-dirs.tmp"
printf '%s\n' "$_additional_manifest" > "$_manifest_tmp" \
	|| die "cannot write additional-directory manifest" 70
chmod 0600 "$_manifest_tmp" || die "cannot protect additional-directory manifest" 70
mv "$_manifest_tmp" "$RUNTIME/system-additional-dirs" \
	|| die "cannot install additional-directory manifest" 70

ln -sfn "$REAL_DATA" "$RUNTIME/data"

# The machine-state pool image (workstation profile with
# `cogbox.storage.machineState = "persist"`; the path does not exist otherwise).
# It has an `[ ! -e "$image" ]` autoCreate hazard -- a first mkfs interrupted by a
# Ctrl-C, a host reboot or a full disk leaves the file present with a garbage
# superblock, autoCreate skips it forever, and /var/lib/cogbox-guest then fails to
# mount on every subsequent boot.
#
# Nothing analogous is needed for the HOSTED profile's two volumes: they are
# logical volumes on the dedicated per-instance disk, both autoCreate = false, and
# the GCE host half owns creating, sizing and formatting them before this script
# ever runs. There is no image file in the instance data dir for either of them.
#
# It CANNOT be handled by deleting the image, because this one holds the USER'S
# DATA: ~/.cache, ~/.local, ~/.config, /var/lib/docker and the
# guest journal, up to the whole configured pool size. `dumpe2fs -h` reads ONLY
# the primary superblock, and a damaged primary superblock is the ordinary
# recoverable case -- ext4 keeps backups, and `e2fsck -b 32768 <img>` is the
# standard repair -- so this test cannot tell a never-formatted image from a
# populated one with one bad block. Deleting on that test would destroy a
# recoverable filesystem, unprompted, on every `cogbox start`.
#
# So RENAME, never remove. The runner's createVolumesScript then finds no image
# and creates a fresh one, so the self-heal is the same; the difference is that
# the old bytes are still there to fsck. The timestamp suffix is deliberate: a
# second interruption must not overwrite the first casualty.
#
# harness-overlay-img does delete-and-recreate on this same test, and that stays
# as it is: it is a 128 MiB guest-side overlay whose contents the read-only 9p
# lower can supply again, and its history is a boot that WEDGED because a corrupt
# image was kept. This is a host-side data pool. Different bytes, different rule.
MACHINE_STATE_IMG="$RUNTIME/data/machine-state.img"
if [ -f "$MACHINE_STATE_IMG" ] && ! @dumpe2fs@ -h "$MACHINE_STATE_IMG" >/dev/null 2>&1; then
	MACHINE_STATE_ASIDE="$MACHINE_STATE_IMG.corrupt-$(date -u +%Y%m%d%H%M%S)"
	if mv "$MACHINE_STATE_IMG" "$MACHINE_STATE_ASIDE"; then
		echo "cogbox: $MACHINE_STATE_IMG has no readable ext4 primary superblock (interrupted first format, or a crash mid-write); moved it to $MACHINE_STATE_ASIDE and letting the runner create a fresh one. It is NOT deleted -- if it was a populated pool, ext4 keeps backup superblocks and 'e2fsck -b 32768 $MACHINE_STATE_ASIDE' is the repair." >&2
	else
		echo "cogbox: $MACHINE_STATE_IMG has no readable ext4 primary superblock and could not be moved aside; refusing to start rather than booting a guest whose data pool cannot mount" >&2
		exit 1
	fi
fi

# -- Per-harness runtime sources -----------------------------------
# The QEMU runner expects a 9p source path or fw_cfg file at
# $RUNTIME/<harness>-<pathkey> for every overlay/fw_cfg path declared
# in the harness shape. For active harnesses, we symlink to the host
# state. For inactive harnesses, we materialize an empty stub so the
# QEMU runner doesn't fail to start.
HARNESS_STUBS="$RUNTIME/.harness-stubs"
mkdir -p "$HARNESS_STUBS"
# Is host-side credential injection active for this instance? If so, secret
# files are evicted from the guest overlays below (stage_overlay_source).
INJECT_ACTIVE=0
# Accept both the legacy bool (.network.l7.inject == true) and the object form
# (.network.l7.inject.enabled == true). The object form is written by the Zig
# verbs (e.g. `cogbox plugin add` merging inject specs); the bool form keeps
# working for instances inited before it. Gates harness cred eviction +
# harness inject-conf generation; plugin/operator specs render independently.
if [ "$NETWORK_MODE" = "rules" ] \
	&& jq -e '(.network.l7.inject == true) or (.network.l7.inject.enabled == true)' "$ACTIVE_CONFIG" >/dev/null 2>&1; then
	INJECT_ACTIVE=1
fi
is_active() {
	for active in "${ACTIVE_HARNESSES[@]}"; do
		[ "$active" = "$1" ] && return 0
	done
	return 1
}
for h in "${HARNESSES[@]}"; do
	while IFS= read -r k; do
		[ -z "$k" ] && continue
		kind=${H_KIND[$h:$k]}
		[ "$kind" = "ephemeral" ] && continue
		target="$RUNTIME/${h}-${k}"
		if is_active "$h"; then
			host=${H_HOST[$h:$k]}
			if [ "$kind" = "overlay" ]; then
				host="$(stage_overlay_source "$h" "$k" "$host")"
			fi
			ln -sfn "$host" "$target"
		else
			stub="$HARNESS_STUBS/${h}-${k}"
			case "$kind" in
				overlay)
					mkdir -p "$stub"
					;;
				fw_cfg)
					if [ ! -e "$stub" ]; then
						printf '%s' "${H_FW_DEFAULT[$h:$k]}" > "$stub"
						chmod "${H_FW_MODE[$h:$k]}" "$stub"
					fi
					;;
			esac
			ln -sfn "$stub" "$target"
		fi
	done < <(harness_pathkeys "$h")
done

# -- Generate runtime rule files -----------------------------------
# Render BOTH the LD_PRELOAD filter's netfilter-rules (CIDR + remap +
# the auto-injected L7 funnel lines) and the L7 proxy's l7-rules from
# config.json, using the same Zig renderer the hot-reload path uses --
# so boot output and edit output can never drift.
# The fw_cfg CA device is ALWAYS present (the flake emits it unconditionally),
# so seed an empty stub; rules mode overwrites it with the real cert.
: > "$RUNTIME/system-l7ca"
if [ "$NETWORK_MODE" = "rules" ]; then
	@cogbox@ __render-rules "$ACTIVE_CONFIG" "$RUNTIME"
	# Host-side credential injection. __render-rules already wrote the
	# PLUGIN/OPERATOR inject specs (resolved from the secret store, audience-
	# gated) to l7-inject-conf.json. Merge the HARNESS specs (cred-file +
	# OAuth-refresh, gated on the harness opt-in INJECT_ACTIVE) on top into the
	# single conf start_l7mitm reads -- harness specs win a host collision.
	# Plugin specs render independently of INJECT_ACTIVE (their own bound state
	# gates them). An explicit COGBOX_L7_INJECT_CONF overrides the whole thing.
	if [ -z "${COGBOX_L7_INJECT_CONF:-}" ]; then
		_plugin_conf=$(cat "$RUNTIME/l7-inject-conf.json" 2>/dev/null)
		[ -z "$_plugin_conf" ] && _plugin_conf='[]'
		_harness_conf='[]'
		if [ "$INJECT_ACTIVE" = 1 ]; then
			_harness_conf=$(gen_inject_conf)
			[ -z "$_harness_conf" ] && _harness_conf='[]'
		fi
		# jq -s slurps both arrays; `add` concatenates (plugin first, harness
		# last -> harness wins the addon's last-write-by-host).
		if printf '%s\n%s' "$_plugin_conf" "$_harness_conf" \
			| jq -s 'add' > "$RUNTIME/l7-inject-conf.json.tmp" 2>/dev/null; then
			mv "$RUNTIME/l7-inject-conf.json.tmp" "$RUNTIME/l7-inject-conf.json"
		else
			rm -f "$RUNTIME/l7-inject-conf.json.tmp"
		fi
		# l7-inject-hosts (the L7 proxy's plain-HTTP inject-routing list) was
		# already written by __render-rules from the PLUGIN/OPERATOR specs only.
		# We deliberately do NOT add the HARNESS hosts to it: their providers are
		# HTTPS-only, and routing their plain-HTTP egress through the injector
		# would let the guest force a cleartext send of the real OAuth token.
	else
		# Operator override: the addon reads exactly $COGBOX_L7_INJECT_CONF, so
		# the proxy's HTTP inject-routing list must mirror ITS hosts (replacing
		# the config-rendered plugin set __render-rules just wrote). Capture jq
		# on its OWN (no pipe) so its exit status is observed: a malformed or
		# unreadable conf (jq non-zero) fails CLOSED to an empty list -- no
		# routing, never a wrong one. (Piping jq into sort would mask the failure
		# behind sort's always-zero exit.)
		if _override_hosts=$(jq -r '.[].host // empty' "$COGBOX_L7_INJECT_CONF" 2>/dev/null); then
			printf '%s\n' "$_override_hosts" | sort -u > "$RUNTIME/l7-inject-hosts"
		else
			: > "$RUNTIME/l7-inject-hosts"
		fi
	fi
fi

# -- Patch the microvm runner with runtime QEMU settings -----------
PASST_SOCK="$RUNTIME/passt.sock"
SED_ARGS=(
	-e "s/( )-smp [0-9]+/\1-smp $VCPU/"
	-e "s/( )-m [0-9]+/\1-m $MEM/"
	-e "s/(memory-backend-memfd,id=mem,size=)[0-9]+(M)/\1${MEM}\2/"
	-e "s|${RUNTIME_TEMPLATE}/|${RUNTIME}/|g"
	-e "s|@cogbox-instance@|${EFFECTIVE_NAME}|g"
	# Move the guest serial console off QEMU's stdio onto a persistent unix
	# socket so it can be attached/detached at will (cogbox console) while
	# the VM runs in the background. Keeping id=stdio means microvm's
	# `-serial chardev:stdio` keeps resolving. logfile= captures the full
	# session's serial output for replay on attach. The replacement targets
	# only the chardev descriptor, so it is agnostic to how microvm quotes
	# the arg. The runtime dir is recreated per launch, so no logappend.
	-e "s|stdio,id=stdio,signal=off|socket,id=stdio,path=${RUNTIME}/console.sock,server=on,wait=off,logfile=${RUNTIME}/console.log|"
)
if [ "$NETWORK_MODE" = "none" ]; then
	# SLIRP with restrict=on -- blocks all outbound, keeps port forwards
	SED_ARGS+=(
		-e "s/hostfwd=tcp:[^-]*-:22/hostfwd=tcp:$BIND_ADDR:$SSH_PORT-:22/g"
		-e "s/hostfwd=tcp:[^-]*-:8080/hostfwd=tcp:$BIND_ADDR:$HTTP_PORT-:8080/g"
		-e "s/(user,id=usernet)/\1,restrict=on/"
	)
else
	# full and rules: connect to passt via unix socket (launched separately)
	SED_ARGS+=(-e "s|-netdev '[^']*'|-netdev 'stream,id=usernet,server=off,addr.type=unix,addr.path=${PASST_SOCK}'|")
fi

sed -E "${SED_ARGS[@]}" "$RUNNER_DIR/bin/microvm-run" > "$RUNTIME/run"
chmod +x "$RUNTIME/run"

# Fail loud if the serial-console rewrite did not take (e.g. microvm changed
# the chardev string): otherwise the console would silently fall back to
# stdio (the daemon log) and `cogbox console` would find no socket.
if ! grep -q "console.sock" "$RUNTIME/run"; then
	echo "cogbox-launch: warning: serial console socket rewrite did not apply; 'cogbox console' will not work for this instance." >&2
fi

# -- Launch --------------------------------------------------------
if [ "$NETWORK_MODE" = "none" ]; then
	echo "Warning: network mode is \"none\" -- all outbound traffic is blocked."
	echo "Harnesses that need outbound API access (claude-code, opencode) won't"
	echo "function unless you provide it via SSH tunnel or similar."
fi

# -- Helper: wait for passt socket ---------------------------------
wait_for_passt() {
	while [ ! -S "$PASST_SOCK" ] && kill -0 "$PASST_PID" 2>/dev/null; do
		sleep 0.1
	done
	if [ ! -S "$PASST_SOCK" ]; then
		die "passt failed to start." 70
	fi
}

# -- Helper: start the host-side L7 proxy --------------------------
# Runs WITHOUT the LD_PRELOAD shim (so it reaches the internet directly to
# re-resolve allowed vhosts) and writes its pid for the hot-reload SIGHUP
# path. Started for EVERY rules-mode instance (it is a cheap, idle loopback
# listener until the funnel diverts to it), so that enabling L7 on an
# already-running instance via `cogbox l7 add` works without a restart -- the
# funnel hot-reloads into passt and the proxy is already listening. Failure to
# bind is FATAL: we abort the start (per-instance ports mean a bind failure is a
# real conflict, not a benign race), so the instance never boots with a funnel
# that can't reach its proxy.
start_l7proxy() {
	"${PROXY_RUNAS_ARGS[@]}" @cogbox@ __l7proxy "$RUNTIME" "$L7_BASE" &
	L7PROXY_PID=$!
	echo "$L7PROXY_PID" > "$RUNTIME/l7proxy.pid"
	# Brief liveness check, then FAIL CLOSED. The proxy binds this instance's
	# per-instance loopback ports ($L7_BASE / +1); if it can't (a stale proxy
	# or another process holds them) we abort the start rather than boot a VM
	# whose L7 funnel points at a dead/foreign port. die() trips the cleanup
	# trap, tearing down passt/mitmproxy/QEMU.
	sleep 0.2
	if ! kill -0 "$L7PROXY_PID" 2>/dev/null; then
		L7PROXY_PID=""
		die "L7 proxy failed to bind 127.0.0.1:${L7_BASE}/$(( L7_BASE + 1 )) -- is a stale proxy or another process holding those ports? Aborting start." 75
	fi
}

# -- Helper: start the L7 terminate backend (mitmproxy) ------------
# Runs mitmdump in SOCKS5 mode with a PERSISTENT per-instance CA confdir (so
# the guest-trusted cert survives reboots) and our enforcement addon. The Zig
# proxy hands vetted terminate-host connections here. After the CA materializes
# we stage its CERT (never the key) into the fw_cfg slot for guest injection.
start_l7mitm() {
	local ca_dir="$INSTANCE_CONFIG_DIR/l7-ca"
	mkdir -p "$ca_dir"
	# connection_strategy=lazy: defer the upstream connection until AFTER the
	# addon has decided, so a denied request never opens a connection to the
	# upstream (and a deny to an unreachable upstream still returns 403 rather
	# than dropping the client's TLS handshake).
	#
	# Host-side credential injection: when an inject-conf is present, the addon
	# replaces a harness's request auth header with the real token read off the
	# host FS (mitmdump runs host-side as the launching user), so the guest only
	# ever carries a stub and the long-lived token never enters the sandbox. The
	# conf maps host -> {cred_file, token_path, style} and lives host-side only.
	# Resolution: an explicit COGBOX_L7_INJECT_CONF wins; otherwise a launch-time
	# step may drop the conf at the runtime default below. A missing file blanks
	# the var so the addon falls back to legacy "guest carries its own token".
	local inject_conf="${COGBOX_L7_INJECT_CONF:-$RUNTIME/l7-inject-conf.json}"
	[ -f "$inject_conf" ] || inject_conf=""
	# The auth-proxy retarget vars are passed UNCONDITIONALLY -- deliberately NOT
	# blanked the way inject_conf is above. The addon's AuthHosts reader tolerates
	# a missing l7-auth-hosts (os.stat -> empty set, keeps the path) and mtime-
	# reloads once a render creates it; blanking the path would wedge it never
	# reading the file, so a host migrated to the auth proxy after boot would
	# never be retargeted (the bug cogbox-enforce.sh:93-102 records for the inject
	# conf). COGBOX_L7_AUTH_PORT is the loopback the addon retargets those hosts
	# to; the auth proxy listens there (start_l7auth below).
	COGBOX_L7_RULES="$RUNTIME/l7-rules" \
	COGBOX_L7_INJECT_CONF="$inject_conf" \
	COGBOX_L7_AUTH_PORT="$L7_AUTH_PORT" \
	COGBOX_L7_AUTH_HOSTS="$RUNTIME/l7-auth-hosts" \
	"${PROXY_RUNAS_ARGS[@]}" \
	@mitmdump@ --mode "socks5@${L7_MITM_PORT}" --listen-host 127.0.0.1 \
		--set confdir="$ca_dir" --set http2=false --set connection_strategy=lazy \
		-s "@l7addon@" -q &
	L7MITM_PID=$!
	echo "$L7MITM_PID" > "$RUNTIME/l7mitm.pid"
	# Wait for mitmproxy to generate its CA (first run) or confirm it exists.
	for _ in $(seq 1 100); do
		[ -s "$ca_dir/mitmproxy-ca-cert.pem" ] && break
		kill -0 "$L7MITM_PID" 2>/dev/null || break
		sleep 0.1
	done
	if ! kill -0 "$L7MITM_PID" 2>/dev/null || [ ! -s "$ca_dir/mitmproxy-ca-cert.pem" ]; then
		echo "cogbox-launch: warning: L7 terminate backend failed to start; terminate hosts will be blocked." >&2
		L7MITM_PID=""
		return
	fi
	# Stage the CA CERT (cert only) for fw_cfg. Guard against ever leaking the
	# private key into the guest.
	if grep -q "PRIVATE KEY" "$ca_dir/mitmproxy-ca-cert.pem"; then
		die "refusing to stage L7 CA: mitmproxy-ca-cert.pem contains a private key" 70
	fi
	cp "$ca_dir/mitmproxy-ca-cert.pem" "$RUNTIME/system-l7ca"
}

# -- Helper: start the per-sandbox auth proxy ----------------------
# The fourth trusted-half process (cogbox __authproxy). The mitmproxy addon
# retargets a host in l7-auth-hosts to 127.0.0.1:$L7_AUTH_PORT, where this
# proxy classifies/authorizes the request against the rendered l7-auth-conf.json
# and stamps the owner's credential itself -- so a migrated git provider needs
# no in-guest token and no addon-side injection. Runs under the SAME
# COGBOX_PROXY_RUNAS uid:gid as mitmproxy and l7proxy (credgrant grants the cred
# files to that gid, the GCE l7-ca is chowned to it, and gce/floor.nix classes
# that uid as trusted-half on loopback), started BETWEEN start_l7mitm and
# start_l7proxy. Unlike start_l7proxy, a bind failure here is WARN-not-die (it
# copies start_l7mitm's semantics, not start_l7proxy's): l7proxy's absence breaks
# ALL :80/:443 egress, but the auth proxy's absence breaks only migrated hosts,
# and fail-closed -- mitmproxy's retarget to a dead port yields an error to the
# guest with no credential, never an open path. Escalating that to a fatal die
# would turn "git access to one provider is down" into "the sandbox won't boot".
#
# The pid file ($RUNTIME/authproxy.pid, the v1 health signal) is never given a
# pid by this script: the Zig side writes its CONTENTS itself, only after its
# listener bound AND its first conf parse succeeded, so it can never name a
# process that died on a bind failure. Health is therefore "exists AND is
# non-empty" (`test -s`), never mere existence -- because this script does
# PRE-CREATE the file, empty, owned by the proxy uid (precreate_authproxy_pidfile
# below): under COGBOX_PROXY_RUNAS the auth proxy cannot create anything in
# $RUNTIME (on GCE that is a root-owned 0755 dir under RuntimeDirectory=cogbox,
# and nothing chowns it -- only l7-ca is handed over), whereas truncate-writing
# into an existing file it owns needs no directory permission. The warn branch
# removes the file again, for the same reason as above.
#
# Kept as its own function with no free variables beyond $RUNTIME and
# $COGBOX_PROXY_RUNAS so tests/test_launch_flags.sh can extract and exercise
# it without a VM.
precreate_authproxy_pidfile() {
	: > "$RUNTIME/authproxy.pid" && chmod 0644 "$RUNTIME/authproxy.pid" || {
		echo "cogbox-launch: warning: cannot pre-create $RUNTIME/authproxy.pid; the auth proxy's health signal will be unavailable." >&2
		return 0
	}
	if [ -n "${COGBOX_PROXY_RUNAS:-}" ]; then
		chown "$COGBOX_PROXY_RUNAS" "$RUNTIME/authproxy.pid" 2>/dev/null \
			|| echo "cogbox-launch: warning: could not chown $RUNTIME/authproxy.pid to $COGBOX_PROXY_RUNAS; the auth proxy's health signal will be unavailable." >&2
	fi
	return 0
}
start_l7auth() {
	precreate_authproxy_pidfile
	"${PROXY_RUNAS_ARGS[@]}" @cogbox@ __authproxy "$RUNTIME" "$L7_BASE" &
	L7AUTH_PID=$!
	sleep 0.2
	if ! kill -0 "$L7AUTH_PID" 2>/dev/null; then
		echo "cogbox-launch: warning: auth proxy failed to bind 127.0.0.1:${L7_AUTH_PORT}; migrated git providers will be blocked (fail-closed)." >&2
		L7AUTH_PID=""
		rm -f "$RUNTIME/authproxy.pid"
	fi
}

# Launch QEMU as a background child and wait for it. Backgrounding (rather
# than a bare foreground exec) is what lets the TERM/INT traps above signal
# QEMU so `cogbox stop` shuts the VM down cleanly.
launch_vm() {
	cd "$RUNTIME" || die "cannot enter runtime dir $RUNTIME" 70
	"$RUNTIME/run" &
	QEMU_PID=$!
	# Readiness/liveness marker the parent (`cogbox start`) waits on. Written
	# the instant QEMU is launched, regardless of whether the serial console
	# rewrite applied, so a console-less VM (e.g. a flake that disables
	# serialConsole) is still detected as up rather than timing out.
	echo "$QEMU_PID" > "$RUNTIME/qemu.pid"
	wait "$QEMU_PID"
}

if [ "$NETWORK_MODE" = "rules" ]; then
	# Rules mode: passt with LD_PRELOAD netfilter. The RUNAS / guest-DNS /
	# forward-prefix / mosh-forward pieces expand to NOTHING unless their knob is set (see the
	# block near the config reads), so an unconfigured host runs the argv it
	# ran before they existed. Guest DNS is a floor concern in BOTH modes, so
	# the same pieces are applied to the full-mode invocation below.
	NETFILTER_RULES="$RUNTIME/netfilter-rules" \
	LD_PRELOAD="@netfilter@" \
	passt --foreground --socket "$PASST_SOCK" \
		"${PASST_RUNAS_ARGS[@]}" "${PASST_DNS_ARGS[@]}" \
		-t "${PASST_FWD_PREFIX}${SSH_PORT}:22" -t "${PASST_FWD_PREFIX}${HTTP_PORT}:8080" "${PASST_MOSH_ARGS[@]}" &
	PASST_PID=$!
	echo "$PASST_PID" > "$RUNTIME/passt.pid"
	wait_for_passt
	# Start the terminate backend first so its CA is staged into the fw_cfg
	# slot BEFORE QEMU reads fw_cfg at launch. It runs for EVERY rules-mode
	# instance, not just those with L7 rules at boot: rules are hot-addable
	# (`cogbox l7 add` on a live instance), terminate is the default tier,
	# and the CA can only enter the guest trust store at launch -- so gating
	# this on boot-time rule presence broke the first hot-added rule (the
	# proxy handed TLS to a backend that was never started and failed
	# closed). An idle backend on L4-only instances is the accepted cost.
	start_l7mitm
	# The auth proxy sits BETWEEN mitm and l7proxy: mitm must be up so its
	# retarget target exists, and it is started before l7proxy so the retarget
	# port is already listening the first time the funnel diverts a migrated
	# host. Warn-not-die, so its absence never blocks the boot.
	start_l7auth
	# Always run the L7 proxy in rules mode so L7 can be enabled on a live
	# instance without a restart (the funnel only diverts to it once a rule
	# exists; until then it idles).
	start_l7proxy
	launch_vm
elif [ "$NETWORK_MODE" != "none" ]; then
	# Full mode: unrestricted passt. This is the mode with NO L4 filter, so
	# whatever the host's own packet filter expresses about the guest is the
	# only floor -- which is exactly why the uid and guest-DNS knobs must be
	# applied here too, not only in rules mode.
	passt --foreground --socket "$PASST_SOCK" \
		"${PASST_RUNAS_ARGS[@]}" "${PASST_DNS_ARGS[@]}" \
		-t "${PASST_FWD_PREFIX}${SSH_PORT}:22" -t "${PASST_FWD_PREFIX}${HTTP_PORT}:8080" "${PASST_MOSH_ARGS[@]}" &
	PASST_PID=$!
	echo "$PASST_PID" > "$RUNTIME/passt.pid"
	wait_for_passt
	launch_vm
else
	launch_vm
fi
