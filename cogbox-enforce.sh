#!/usr/bin/env bash
# cogbox enforce supervisor -- PID1 of the SEPARATE enforcer pod.
#
# Reached via `cogbox enforce -n <name>` (the enforce verb execs us). For ONE
# instance, with NO VM/passt/QEMU: render the wire files, run the L7 terminate
# backend (mitmdump) + the host-side L7 proxy in SOCKS5 accept mode bound on
# 0.0.0.0 (so the agent pod's in-pod divert shim reaches it cross-pod), and
# publish the per-instance CA CERT (never the key) so the agent's egress trust
# bundle and the pod readinessProbe unblock.
#
# Re-architecture note: the enforcer is now its OWN pod. The agent pod's nft-init
# REDIRECTs egress to an in-pod shim (`cogbox __divertshim`) which recovers the
# orig dst and SOCKS5-CONNECTs it here. So the l7proxy runs in the EXISTING socks5
# accept mode (NOT the redirect mode of the old shared-netns design), with
# FUNNEL_ALL=1 so its socks5 front door handles every funneled port (not just
# HTTP/TLS). There is no in-pod cgroup handshake anymore.
#
# Cross-pod contract (cogworx renders the enforcer pod to these EXACT paths/env;
# build to them):
#   env     COGBOX_L7_ACCEPT=socks5  COGBOX_L7_LISTEN_ADDR=0.0.0.0
#           COGBOX_L7_FUNNEL_ALL=1   COGBOX_DIVERT_PORT=<base>
#           XDG_CONFIG_HOME=<state>/config  COGBOX_INSTANCE=<name>
#           COGBOX_GLOBAL_SECRETS_DIR / COGBOX_INSTANCE_SECRETS_DIR (enforcer-private, on the enf PVC)
#   mounts  enf PVC (secret store + the mitmproxy confdir CA), rules emptyDir=/run/cogbox-rt,
#           ca-pub=/run/cogbox-capub, secrets=/run/cogbox-secrets, ca-conf (mitmproxy confdir)=/run/cogbox-ca-conf
#   probe   readinessProbe = test -f /run/cogbox-capub/ca.crt
#
# Substituted by mkCogbox: @cogbox@ @mitmdump@ @l7addon@.
#
# Intentionally NO `set -e`: this is a long-lived supervisor; a transient child
# failure must restart the child, not abort PID1. The critical setup steps are
# guarded by hand.
set -uo pipefail

log() { echo "cogbox-enforce: $*" >&2; }
die() { log "error: $1"; exit "${2:-70}"; }

# -- Resolve the instance + paths ----------------------------------
# The enforce verb passes the resolved name as $1; $COGBOX_INSTANCE is the
# fallback (what the verb itself falls back to), default "default".
NAME="${1:-${COGBOX_INSTANCE:-default}}"

: "${XDG_CONFIG_HOME:?XDG_CONFIG_HOME must be set (the state PVC config dir)}"
CONFIG="$XDG_CONFIG_HOME/cogbox/instances/$NAME/config.json"

# Enforcer-local runtime (the rules emptyDir) + the contract mount points.
RUNTIME=/run/cogbox-rt
CAPUB_DIR=/run/cogbox-capub
CA_CONF=/run/cogbox-ca-conf

# Port base == the l7proxy SOCKS5 listener (on 0.0.0.0); the mitmdump terminate
# hop sits at base+2 on loopback (mirrors the VM's L7_MITM_PORT).
BASE="${COGBOX_DIVERT_PORT:-18443}"
MITM_PORT=$(( BASE + 2 ))
# The per-sandbox auth proxy listens DOWNWARD from the base (mirrors
# filter.l7AuthPortForBase: auth = base - 400). The mitmproxy addon retargets a
# migrated host to it; the auth proxy authenticates the request itself.
AUTH_PORT=$(( BASE - 400 ))

mkdir -p "$RUNTIME" "$CAPUB_DIR" "$CA_CONF"

# L7 proxy accept mode for the separate-pod enforcer: socks5 front door on
# 0.0.0.0 (cross-pod reachable for the agent's shim), funnel ALL ports (the shim
# carries every diverted port over one socks5 hop). Honor the pod env if it sets
# these (the contract does); default to the enforcer-correct values otherwise so
# the supervisor is right even if one is omitted.
export COGBOX_L7_ACCEPT="${COGBOX_L7_ACCEPT:-socks5}"
export COGBOX_L7_LISTEN_ADDR="${COGBOX_L7_LISTEN_ADDR:-0.0.0.0}"
export COGBOX_L7_FUNNEL_ALL="${COGBOX_L7_FUNNEL_ALL:-1}"

# -- Render the wire files (config OPTIONAL at start) ---------------
# The same renderer the hot-reload path uses (no jq/Zig drift). Writes l7-rules
# + l7-inject-conf.json + l7-inject-hosts; the secret-store reads honor the
# COGBOX_*_SECRETS_DIR overrides (enforcer-private store).
#
# The config may not exist yet: cogworx creates the enforcer pod FIRST (to read
# the ClusterIP), so it can come up before the agent pod has couriered a config.
# Start default-deny (the proxy reads absent wire files as an empty ruleset =
# deny) and continue; cogworx reconciles (courier config -> __render-rules ->
# SIGHUP) right after the enforcer is Ready. A present config is rendered now so a
# restart re-enforces immediately without waiting on cogworx.
#
# SINGLE-WRITER CONTRACT: this renderer is the ONLY writer of
# $RUNTIME/l7-inject-conf.json on the container path -- there is no
# gen_inject_conf half here (that lives in cogbox-launch.sh, VM path only), and
# `cogbox secret reload` renders into paths.instanceRuntime, not this pod's
# /run/cogbox-rt. That is why __render-rules (reload.boot_foreign_specs =
# .replace) is correct here. If a harness merge -- or any second writer of that
# file -- is ever added on this path, every LIVE re-render must switch to
# renderFiles(..., .preserve); a live .replace beside a second writer strips its
# specs while leaving l7-rules' terminate-allow and the :443 funnel standing.
# See docs/network-filtering.md, "Where the two-writer contract actually applies".
if [ -f "$CONFIG" ]; then
	@cogbox@ __render-rules "$CONFIG" "$RUNTIME" || die "render of $CONFIG failed"
else
	log "no config at $CONFIG yet -> starting default-deny (empty wire files); the control plane will deliver config + SIGHUP"
fi

# -- Child management ----------------------------------------------
MITM_PID=""
L7PROXY_PID=""
AUTH_PID=""

# mitmdump = the L7 terminate backend, SOCKS5 mode + our enforcement addon.
# confdir is the enforcer-PRIVATE ca-conf volume: mitmproxy self-generates the
# per-instance CA there (cert + key); we publish only the cert below.
# connection_strategy=lazy defers the upstream connect until the addon decides,
# so a denied request never opens an upstream socket. An explicit
# COGBOX_L7_INJECT_CONF wins; else the addon reads the rendered conf. Pass the
# PATH UNCONDITIONALLY, even when the file does not exist yet: in the separate-pod
# topology the enforcer boots BEFORE the control plane delivers a config, so
# l7-inject-conf.json is created only later (by the reconcile render). The addon's
# CredStore tolerates a missing file (os.stat -> empty specs, keeps the path) and
# hot-reloads on mtime once it appears, picking up injects with NO restart -- and
# an absent file still means "guest carries its own token", the same fallback as
# before. Blanking the path here (the old `[ -f ] || inject_conf=""`) wedged the
# addon with CredStore("") which never reloads, so host-side injection NEVER took
# effect on a freshly-booted enforcer (the file is always created after launch).
start_l7mitm() {
	local inject_conf="${COGBOX_L7_INJECT_CONF:-$RUNTIME/l7-inject-conf.json}"
	# COGBOX_L7_AUTH_PORT / COGBOX_L7_AUTH_HOSTS are passed UNCONDITIONALLY, even
	# when l7-auth-hosts does not exist yet -- the same reasoning as inject_conf
	# above (:93-102): the addon's AuthHosts reader tolerates a missing file
	# (os.stat -> empty set, keeps the path) and mtime-reloads once the reconcile
	# render creates it, so a host migrated to the auth proxy after boot is still
	# retargeted with no restart. Blanking the path would wedge the reader never
	# reading the file.
	COGBOX_L7_RULES="$RUNTIME/l7-rules" \
	COGBOX_L7_INJECT_CONF="$inject_conf" \
	COGBOX_L7_AUTH_PORT="$AUTH_PORT" \
	COGBOX_L7_AUTH_HOSTS="$RUNTIME/l7-auth-hosts" \
	@mitmdump@ --mode "socks5@${MITM_PORT}" --listen-host 127.0.0.1 \
		--set confdir="$CA_CONF" --set http2=false --set connection_strategy=lazy \
		-s "@l7addon@" -q &
	MITM_PID=$!
	echo "$MITM_PID" > "$RUNTIME/l7mitm.pid"
}

# The host-side L7 proxy. It reads COGBOX_L7_ACCEPT=socks5 + COGBOX_L7_LISTEN_ADDR
# + COGBOX_L7_FUNNEL_ALL from the env we exported above: a SOCKS5 front door on
# 0.0.0.0:$BASE (the agent pod's shim CONNECTs here carrying the orig dst), with
# the funnel-all gate for non-HTTP/TLS flows. Writes l7proxy.pid so the hot-reload
# verbs (rule/secret edits kubectl-exec'd into this pod) can SIGHUP it.
#
# Optional tuning: COGBOX_L7_PEEK_MS (default 300) bounds the pre-connect
# classification peek for raw-L4-allowed flows, so a silent server-speaks-first
# client (SSH/SMTP/...) doesn't stall on the general I/O timeout before its flow
# falls through to the raw-L4 splice. Left unset here to use the built-in default.
start_l7proxy() {
	@cogbox@ __l7proxy "$RUNTIME" "$BASE" &
	L7PROXY_PID=$!
	echo "$L7PROXY_PID" > "$RUNTIME/l7proxy.pid"
}

# The per-sandbox auth proxy (cogbox __authproxy): the fourth trusted-half
# process, listening on 127.0.0.1:$AUTH_PORT. The mitmproxy addon retargets a
# host in l7-auth-hosts here; the auth proxy classifies/authorizes the request
# against l7-auth-conf.json and stamps the owner's credential itself, so a
# migrated git provider needs no in-guest token and no addon injection. No runas
# on the enforcer path (this pod already runs as the enforcer uid). Its own
# wait -n arm below restarts it after a crash, exactly like the other two.
#
# Unlike the other two children, this script never writes a PID into the pid
# file: $RUNTIME/authproxy.pid is the auth proxy's v1 health signal and its
# CONTENTS are written by the Zig side itself, only after its listener bound AND
# its first conf parse succeeded. A pid written here from $! would name a process
# that may already have died on a bind failure -- exactly what the file exists to
# rule out. The file IS pre-created EMPTY, mirroring the VM launcher's
# precreate_authproxy_pidfile: the enforcer uid owns $RUNTIME, so the Zig side
# could create it itself, but one contract on both paths ("exists and empty" =
# starting, non-empty = bound + parsed, `test -s` = healthy) means a supervised
# restart truncates the dead child's stale pid away instead of leaving it to be
# read as live. Warn-not-die, like everything else about this child.
start_l7auth() {
	: > "$RUNTIME/authproxy.pid" && chmod 0644 "$RUNTIME/authproxy.pid" \
		|| log "warning: cannot pre-create $RUNTIME/authproxy.pid; the auth proxy's health signal will be unavailable"
	@cogbox@ __authproxy "$RUNTIME" "$BASE" &
	AUTH_PID=$!
}

# Publish the CA CERT ONLY (never the key) once mitmproxy mints it, so the
# agent's cogbox-l7-trust + the pod readinessProbe (test -f .../ca.crt) unblock.
# Atomic rename so a reader never sees a half-written cert.
publish_ca() {
	local src="$CA_CONF/mitmproxy-ca-cert.pem"
	local dst="$CAPUB_DIR/ca.crt"
	local i
	for i in $(seq 1 100); do
		[ -s "$src" ] && break
		kill -0 "$MITM_PID" 2>/dev/null || { log "warning: mitmdump exited before minting a CA"; return 1; }
		sleep 0.1
	done
	[ -s "$src" ] || { log "warning: mitmproxy CA cert never appeared at $src"; return 1; }
	# Guard against ever publishing the private key into the agent-readable cert.
	if grep -q "PRIVATE KEY" "$src"; then
		die "refusing to publish CA: $src contains a private key"
	fi
	if cp "$src" "$dst.tmp" && mv "$dst.tmp" "$dst"; then
		log "published CA cert -> $dst"
	else
		log "warning: failed to publish CA cert to $dst"
		return 1
	fi
}

# -- signal handling: forward SIGTERM, tear down -------------------
terminate() {
	log "received termination signal; stopping children"
	[ -n "$L7PROXY_PID" ] && kill "$L7PROXY_PID" 2>/dev/null
	[ -n "$MITM_PID" ] && kill "$MITM_PID" 2>/dev/null
	[ -n "$AUTH_PID" ] && kill "$AUTH_PID" 2>/dev/null
	wait 2>/dev/null
	exit 0
}
trap terminate TERM INT

# -- Bring-up + supervise ------------------------------------------
start_l7mitm
publish_ca
# Between publish_ca and start_l7proxy: mitm must be up (its retarget target)
# and the auth port must be listening before the funnel first diverts a migrated
# host to it.
start_l7auth
start_l7proxy

# Restart whichever child dies. Edits need no restart (the addon mtime-reloads;
# the proxy reloads on SIGHUP) -- only a crash does. `wait -n` returns on any
# child exit OR a trapped signal; on a signal `terminate` has already exited.
# Re-publish the CA after a mitmdump restart (idempotent: the confdir CA
# persists across restarts).
while true; do
	wait -n 2>/dev/null
	if [ -n "$MITM_PID" ] && ! kill -0 "$MITM_PID" 2>/dev/null; then
		log "mitmdump (pid $MITM_PID) exited; restarting"
		start_l7mitm
		publish_ca
	fi
	if [ -n "$L7PROXY_PID" ] && ! kill -0 "$L7PROXY_PID" 2>/dev/null; then
		log "l7proxy (pid $L7PROXY_PID) exited; restarting"
		start_l7proxy
	fi
	# The auth proxy gets its own restart arm -- the correctness obligation of
	# this whole change. Omit it and the enforcer silently runs without the auth
	# proxy after one crash: mitmproxy keeps retargeting migrated hosts to a dead
	# port, so every migrated git provider fails closed with no self-heal until
	# the pod restarts. It supervises exactly like the other two.
	if [ -n "$AUTH_PID" ] && ! kill -0 "$AUTH_PID" 2>/dev/null; then
		log "auth proxy (pid $AUTH_PID) exited; restarting"
		start_l7auth
	fi
	sleep 0.2
done
