# Overrides for cogbox-shutdown.sh. Process identity uses libproc's microsecond
# start timestamp; gone/zombie checks distinguish ESRCH from inspection errors.
cogbox_shutdown_now() {
    COGBOX_SHUTDOWN_NOW=$("$COGBOX_PLATFORM" now)
}
cogbox_process_start() {
    local info
    info=$("$COGBOX_PLATFORM" process "$1") || return 1
    printf '%s\n' "${info%% *}"
}
cogbox_child_live() {
    local info start parent zombie
    [ -n "$1" ] || return 1
    info=$("$COGBOX_PLATFORM" process "$1") || return 1
    read -r start parent zombie <<< "$info"
    [ "$parent" = "$$" ] && [ "$zombie" = 0 ] || return 1
    [ -z "${2:-}" ] || [ "$start" = "$2" ]
}
cogbox_child_gone() {
    local info rc
    [ -n "$1" ] || return 0
    info=$("$COGBOX_PLATFORM" process "$1"); rc=$?
    [ "$rc" = 3 ] && return 0
    [ "$rc" = 0 ] || return 1
    [ "${info##* }" = 1 ]
}
cogbox_stop_init() {
    local nonce start
    nonce=$("$COGBOX_PLATFORM" uuid) || return 1
    start=$(cogbox_process_start "$$") || return 1
    STOP_ID="v1 $nonce $$ $start"
    STOP_NONCE=$nonce
    CONTROL_PARTIAL=""
    CONTROL_DISCARD=0
    mkfifo -m 600 "$RUNTIME/control" || return 1
    exec {CONTROL_FD}<>"$RUNTIME/control" || return 1
    (umask 077; printf '%s\n' "$STOP_ID" > "$RUNTIME/launch.tmp") &&
        mv -f "$RUNTIME/launch.tmp" "$RUNTIME/launch"
}
cogbox_control_poll() {
    local chunk="" complete=0 nonce action
    IFS= read -r -t "${1:-0.1}" -u "$CONTROL_FD" chunk && complete=1
    # A timed Bash read can consume part of a line before returning failure.
    # Preserve those bytes across polls, including requests arriving exactly
    # at the deadline. Discard oversized records through their next newline.
    if [ "$CONTROL_DISCARD" = 0 ]; then
        CONTROL_PARTIAL+=$chunk
        if [ "${#CONTROL_PARTIAL}" -gt 128 ]; then
            CONTROL_PARTIAL=""
            CONTROL_DISCARD=1
        fi
    fi
    [ "$complete" = 1 ] || return 0
    if [ "$CONTROL_DISCARD" = 1 ]; then
        CONTROL_DISCARD=0
        return 0
    fi
    IFS=' ' read -r nonce action <<< "$CONTROL_PARTIAL"
    CONTROL_PARTIAL=""
    [ "$nonce" = "$STOP_NONCE" ] || return 0
    case "$action" in
        stop) cogbox_request_stop ;;
        force) cogbox_request_stop force ;;
    esac
    return 0
}
