#!/usr/bin/env bash
# Behavioral test of the supervisor's systemd stop policy. NEVER run on the
# development host or an existing user's sandbox. Run only on an explicitly
# authorized, disposable stage candidate, as root, through reviewed transport.
#
# The operator must bind these values to the authenticated candidate host:
#   COGBOX_SHUTDOWN_FIXTURE_GO=stage-only
#   COGBOX_SHUTDOWN_FIXTURE_HOSTNAME=<exact hostname>
#   COGBOX_SHUTDOWN_FIXTURE_BOOT_ID=<exact /proc/sys/kernel/random/boot_id>
#   bash /absolute/path/test_shutdown_systemd.sh --run
#
# This creates only uniquely named transient fixture units and private /run
# artifacts. It never stops cogbox, changes installed units, or runs QMP. The
# production 65s command / 75s unit / 10s post-stop bounds are deliberately scaled
# down: normal command about 0.8s, hung command 3s, bounded post-stop at most 1.2s.
# Keep the artifacts for inspection; /run disappears at host reboot.
set -euo pipefail
export LC_ALL=C
# Transient systemd roles do not inherit the invoking shell's search path.
# Establish the candidate's trusted tools before readlink or any other command.
export PATH=/run/current-system/sw/bin

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

guard_host() {
    [[ ${COGBOX_SHUTDOWN_FIXTURE_GO:-} == stage-only ]] || die 'explicit stage-only GO required'
    [[ $EUID == 0 ]] || die 'requires root on the authorized disposable candidate'
    [[ -d /run/systemd/system ]] || die 'requires a running systemd host'
    [[ -n ${COGBOX_SHUTDOWN_FIXTURE_HOSTNAME:-} && $(hostname) == "$COGBOX_SHUTDOWN_FIXTURE_HOSTNAME" ]] || die 'hostname guard mismatch'
    local actual_boot
    read -r actual_boot </proc/sys/kernel/random/boot_id
    [[ ${COGBOX_SHUTDOWN_FIXTURE_BOOT_ID:-} == "$actual_boot" ]] || die 'boot identity guard mismatch'
}

monotonic_ms() {
    local uptime _unused
    read -r uptime _unused </proc/uptime
    awk -v uptime="$uptime" 'BEGIN { printf "%.0f\n", uptime * 1000 }'
}

live_pid_file() {
    local pid state
    [[ -f $1 ]] || return 1
    read -r pid <"$1"
    [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/stat ]] || return 1
    # Fixture process comm values contain no ')' characters. Zombies have
    # exited; init may not yet have reaped them when ExecStopPost begins.
    state=$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null) || return 1
    [[ ${state%% *} != Z && ${state%% *} != X ]]
}

event() { printf '%s|%s|%s\n' "$1" "$(monotonic_ms)" "$$" >>"$case_dir/events"; }

wait_event() {
    local wanted=$1 deadline=$(( $(monotonic_ms) + 1800 ))
    while ! grep -q "^${wanted}|" "$case_dir/events"; do
        (( $(monotonic_ms) < deadline )) || die "timed out waiting for $wanted"
        sleep 0.02
    done
}

fixture_role() {
    local role=$1 root=$2 case_name=$3
    [[ $root =~ ^/run/cogbox-shutdown-fixture\.[A-Za-z0-9]+$ && -d $root && ! -L $root ]] || die 'invalid fixture directory'
    [[ $(stat -c '%u:%a' "$root") == 0:700 ]] || die 'unsafe fixture directory'
    case "$case_name" in success|main-exit|failed-stop|hung-stop|no-guest|bounded-post) ;; *) die 'invalid case';; esac
    case_dir=$root/$case_name
    [[ -d $case_dir && ! -L $case_dir && -f $root/authorized ]] || die 'missing fixture authorization record'
    [[ $(<"$root/authorized") == "$COGBOX_SHUTDOWN_FIXTURE_BOOT_ID" ]] || die 'stale fixture authorization'
    case "$role" in
        main)
            printf '%s\n' "$$" >"$case_dir/main.pid"
            event main-start
            if [[ $case_name != no-guest ]]; then
                /run/current-system/sw/bin/bash "$script_path" --fixture-role child "$root" "$case_name" &
                printf '%s\n' "$!" >"$case_dir/child.pid"
                wait_event child-start
            fi
            trap 'event main-term; exit 90' TERM
            event main-ready
            while [[ ! -f $case_dir/exit-request ]]; do sleep 0.02; done
            event main-exit
            # The real supervisor returns one when its guest disappears while
            # synchronous ExecStop is still awaiting the launcher's outcome.
            exit 1
            ;;
        child)
            trap 'event child-term; exit 91' TERM
            trap 'event child-int; exit 92' INT
            event child-start
            while :; do sleep 0.1; done
            ;;
        stop)
            printf '%s\n' "$$" >"$case_dir/stop.pid"
            event stop-enter
            case "$case_name" in
                no-guest) [[ ! -f $case_dir/child.pid ]] || die 'unexpected guest'; event stop-no-guest; exit 0 ;;
                failed-stop) sleep 0.2; event stop-failure; exit 42 ;;
                hung-stop)
                    trap 'event stop-term' TERM
                    event stop-hanging
                    while :; do sleep 0.1; done
                    ;;
                main-exit)
                    : >"$case_dir/exit-request"
                    wait_event main-exit
                    ;;
            esac
            sleep 0.8
            live_pid_file "$case_dir/child.pid" || die 'child was killed while synchronous ExecStop waited'
            if [[ $case_name == main-exit ]]; then
                ! live_pid_file "$case_dir/main.pid" || die 'main did not exit during ExecStop'
            else
                live_pid_file "$case_dir/main.pid" || die 'main was killed before ExecStop finished'
            fi
            [[ $(grep -c '^main-start|' "$case_dir/events") == 1 ]] || die 'service restarted during stop transaction'
            event stop-wait-proved
            event stop-exit
            ;;
        post)
            event post-enter
            local file
            for file in main.pid child.pid stop.pid; do
                ! live_pid_file "$case_dir/$file" || die "$file survived into ExecStopPost"
            done
            event post-cgroup-gone
            if [[ $case_name == bounded-post ]]; then
                # Model the production post-stop leg's independent best-effort
                # deadline, not another complete TimeoutStopSec allowance.
                local timeout_rc=0
                timeout --signal=TERM --kill-after=0.2s 1s sleep 30 || timeout_rc=$?
                [[ $timeout_rc == 124 ]] || die 'post-stop deadline was not exercised'
                event post-deadline
            else
                sleep 0.4
            fi
            event post-end
            ;;
        *) die 'invalid internal role' ;;
    esac
}

script_path=$(readlink -f "${BASH_SOURCE[0]}")
[[ $script_path =~ ^/[A-Za-z0-9_./-]+$ ]] || die 'use an absolute script path without whitespace or unit syntax'
guard_host
if [[ ${1:-} == --fixture-role && $# == 4 ]]; then
    fixture_role "$2" "$3" "$4"
    exit
fi
[[ $# == 1 && $1 == --run ]] || die 'usage: test_shutdown_systemd.sh --run'

for command in systemd-run systemctl journalctl timeout awk sed grep stat mktemp; do
    command -v "$command" >/dev/null || die "required command missing: $command"
done
[[ -x /run/current-system/sw/bin/bash ]] || die 'requires the candidate NixOS system bash'
fixture_root=$(mktemp -d /run/cogbox-shutdown-fixture.XXXXXXXX)
chmod 700 "$fixture_root"
printf '%s\n' "$COGBOX_SHUTDOWN_FIXTURE_BOOT_ID" >"$fixture_root/authorized"
read -r fixture_uuid </proc/sys/kernel/random/uuid
fixture_tag=${fixture_uuid//-/}
declare -a fixture_units=()

cleanup() {
    local rc=$? unit
    trap - EXIT INT TERM
    for unit in "${fixture_units[@]}"; do
        # Only names this invocation created are eligible. Never enumerate or
        # use a wildcard against the host's existing units.
        timeout --kill-after=1s 8s systemctl stop "$unit" >/dev/null 2>&1 || true
        systemctl kill --kill-whom=all --signal=KILL "$unit" >/dev/null 2>&1 || true
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    done
    printf 'Fixture artifacts retained: %s\n' "$fixture_root"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

has_event() { grep -q "^$1|" "$case_dir/events"; }
event_time() { awk -F '|' -v wanted="$1" '$1 == wanted { print $2; exit }' "$case_dir/events"; }
ordered() {
    if ! has_event "$1" || ! has_event "$2"; then
        die "missing order evidence: $1 -> $2"
    fi
    local first second
    first=$(grep -n "^$1|" "$case_dir/events"); first=${first%%:*}
    second=$(grep -n "^$2|" "$case_dir/events"); second=${second%%:*}
    (( first < second )) || die "bad order: $1 -> $2"
}
property_is() {
    local actual
    actual=$(systemctl show "$unit" --property="$1" --value)
    [[ $actual == "$2" ]] || die "realized $1 was $actual, expected $2"
}

printf 'Testing only transient units prefixed cogbox-shutdown-fixture-%s-\n' "$fixture_tag"
for case_name in success main-exit failed-stop hung-stop no-guest bounded-post; do
    case_dir=$fixture_root/$case_name
    mkdir -m 700 "$case_dir"
    : >"$case_dir/events"
    unit=cogbox-shutdown-fixture-$fixture_tag-$case_name.service
    [[ $(systemctl show "$unit" --property=LoadState --value) == not-found ]] || die 'generated unit already exists'
    fixture_units+=("$unit")
    systemd-run --quiet --unit="$unit" \
        --property=Type=simple \
        --property=Restart=always --property=RestartSec=100ms \
        --property=KillMode=control-group --property=KillSignal=SIGKILL \
        --property=FinalKillSignal=SIGKILL --property=SendSIGKILL=yes \
        --property=TimeoutStopFailureMode=kill --property=TimeoutStopSec=3s \
        --property=StandardOutput=journal --property=StandardError=journal \
        --property="ExecStop=/run/current-system/sw/bin/bash $script_path --fixture-role stop $fixture_root $case_name" \
        --property="ExecStopPost=/run/current-system/sw/bin/bash $script_path --fixture-role post $fixture_root $case_name" \
        --setenv=COGBOX_SHUTDOWN_FIXTURE_GO=stage-only \
        --setenv="COGBOX_SHUTDOWN_FIXTURE_HOSTNAME=$COGBOX_SHUTDOWN_FIXTURE_HOSTNAME" \
        --setenv="COGBOX_SHUTDOWN_FIXTURE_BOOT_ID=$COGBOX_SHUTDOWN_FIXTURE_BOOT_ID" \
        /run/current-system/sw/bin/bash "$script_path" --fixture-role main "$fixture_root" "$case_name"
    wait_event main-ready
    property_is KillMode control-group
    property_is KillSignal 9
    property_is FinalKillSignal 9
    property_is SendSIGKILL yes
    property_is TimeoutStopFailureMode kill
    property_is TimeoutStopUSec 3s
    property_is Restart always
    systemctl show "$unit" --property=ExecStart,ExecStop,ExecStopPost,KillMode,KillSignal,FinalKillSignal,TimeoutStopFailureMode,TimeoutStopUSec,Restart >"$case_dir/realized-unit.txt"
    start_ms=$(monotonic_ms)
    stop_rc=0
    timeout --kill-after=1s 8s systemctl stop "$unit" >"$case_dir/stop.stdout" 2>"$case_dir/stop.stderr" || stop_rc=$?
    elapsed_ms=$(( $(monotonic_ms) - start_ms ))
    [[ $stop_rc != 124 && $stop_rc != 137 ]] || die "$case_name exceeded independent fixture backstop"
    has_event post-end || die "$case_name did not complete the independently bounded post-stop leg"
    ordered stop-enter post-enter
    ordered post-enter post-cgroup-gone
    ordered post-cgroup-gone post-end
    [[ $(grep -c '^main-start|' "$case_dir/events") == 1 ]] || die "$case_name restarted during stop"
    ! grep -Eq '^(main-term|child-term|child-int|stop-term)\|' "$case_dir/events" || die "$case_name received a soft signal instead of final SIGKILL"
    for pid_file in main.pid child.pid stop.pid; do
        ! live_pid_file "$case_dir/$pid_file" || die "$case_name still has a live $pid_file"
    done
    case "$case_name" in
        success|main-exit|bounded-post)
            [[ $stop_rc == 0 ]] || die "$case_name stop failed with $stop_rc"
            ordered stop-enter stop-wait-proved
            ordered stop-wait-proved stop-exit
            ordered stop-exit post-enter
            (( $(event_time stop-exit) - $(event_time stop-enter) >= 700 )) || die 'synchronous stop did not actually wait'
            if [[ $case_name == main-exit ]]; then
                ordered stop-enter main-exit
                ordered main-exit stop-wait-proved
                property_is ExecMainCode 1
                property_is ExecMainStatus 1
            fi
            if [[ $case_name == bounded-post ]]; then
                ordered post-cgroup-gone post-deadline
                ordered post-deadline post-end
                (( elapsed_ms >= 1700 && elapsed_ms < 3200 )) || die 'bounded post-stop aggregate exceeded scaled deadline'
            else
                (( elapsed_ms >= 1100 && elapsed_ms < 3000 )) || die 'normal aggregate exceeded scaled deadline'
            fi
            ;;
        failed-stop)
            ordered stop-enter stop-failure
            ordered stop-failure post-enter
            ! has_event stop-exit || die 'failed stop became success'
            (( elapsed_ms >= 500 && elapsed_ms < 2500 )) || die 'failed ExecStop incurred another full unit wait'
            ;;
        hung-stop)
            ordered stop-enter stop-hanging
            ordered stop-hanging post-enter
            ! has_event stop-exit || die 'hung stop became success'
            (( elapsed_ms >= 3200 && elapsed_ms < 5500 )) || die 'hung ExecStop did not enforce one timeout plus bounded post-stop'
            ;;
        no-guest)
            ordered stop-enter stop-no-guest
            ordered stop-no-guest post-enter
            [[ $stop_rc == 0 && ! -f $case_dir/child.pid ]] || die 'no-guest path failed'
            (( elapsed_ms >= 300 && elapsed_ms < 2200 )) || die 'no-guest aggregate exceeded scaled deadline'
            ;;
    esac
    # Delay beyond RestartSec only after measuring the stop aggregate, to catch
    # a replacement main process after ExecStopPost as well as during ExecStop.
    sleep 0.25
    [[ $(grep -c '^main-start|' "$case_dir/events") == 1 ]] || die 'unexpected post-stop automatic restart'
    ! systemctl is-active --quiet "$unit" || die 'fixture remained active after stop'
    journalctl --no-pager --unit="$unit" --output=short-monotonic >"$case_dir/journal.txt"
    printf 'PASS case=%s elapsed_ms=%s stop_rc=%s main_starts=1 all_owned_processes_gone=yes\n' "$case_name" "$elapsed_ms" "$stop_rc"
done
printf 'PASS: all six realized-systemd cases; no installed host services changed\n'
