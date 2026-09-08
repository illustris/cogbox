# Graceful guest shutdown

## Scope and evidence

Repair ordinary VM stop/restart by draining the inner NixOS guest before killing
QEMU. Keep this runtime-only: no control-plane lifecycle, authorization, provider
API, disk-layout, container-native, plugin, or dependency-pin changes.

Before this change the launcher responded to TERM by sending QEMU TERM, waiting about five
seconds, then sending KILL. This does not shut down the guest operating system.
The GCE supervisor had no synchronous `ExecStop`, so stopping the outer host could
signal its whole service cgroup before the guest has flushed buffered writes.
The observed loss of recent unsynced edits, absent guest shutdown journal, and
successful explicitly synced control are consistent with that mechanism; they
do not establish immunity to every storage or external-host failure.

The pinned microvm dependency already provides `bin/microvm-shutdown`. Its QEMU
implementation sends one Ctrl-Alt-Delete event through the private QMP socket and
waits for that socket to stop accepting connections. The runner uses `-no-reboot`
and `reboot=t`, so an orderly guest reboot exits QEMU rather than booting another
guest. Reuse the helper belonging to the launcher's actual `RUNNER_DIR`; do not
substitute an SSH command, add a guest agent, or depend on generic ACPI defaults.
The helper has no deadline, emits raw QMP replies, and returns success when its
socket is absent. Those are caller-side obligations, not completion proof.

The runner also keeps `panic=-1`: Linux immediately reboots after a panic. With
`-no-reboot`, an unclean panic and an orderly reboot can both end QEMU with exit
zero. This launcher has no guest shutdown witness or panic-notification device.
It therefore reports confirmed termination as **unverified**, not graceful.
A QMP `query-status` preflight would only sample the current emulator state; it
cannot reject an unreported panic or one after the query. A `guest-reset` event
is ambiguous too. Keep the existing panic/automatic-recovery policy unchanged;
`panic=0` would instead leave an unreported panic running indefinitely.

## Runtime shutdown contract

The launcher owns shutdown of the QEMU child it actually spawned. Neither the
CLI nor supervisor may kill a QEMU PID guessed from a stale file or enumerate
other sandboxes. Preserve the existing per-instance lifetime flock and retain
its backing inode. Keep passt, enforcement processes, storage, runtime sources,
and mirrors available until that child has really exited.

Normal TERM/INT requests one orderly attempt:

1. If no QEMU was launched, clean up this launch without claiming guest shutdown.
   If the child already exited, reap its actual status; distinguish an already
   ended/crashed guest from a successful new graceful request.
2. For a live child, require the selected helper and expected runtime QMP socket,
   invoke the helper from the runtime directory, and suppress its raw output.
   Bound the attempt to 45 seconds, including a bounded helper termination tail.
   No request-controlled command, executable lookup, or new credential is used.
3. Helper success alone is insufficient. Independently confirm and reap the
   owned QEMU child. Successful helper execution, a successful child exit,
   and no fallback qualify only as `unverified` termination. No current path
   claims graceful completion, and neither a zero exit nor a generic QMP state
   is a guest-filesystem shutdown acknowledgment.
4. If termination through the orderly attempt cannot be established, retain the existing ability to
   stop an unhealthy VM: a classified forced fallback sends the owned child
   TERM for at most five seconds, then KILL with at most five seconds to confirm
   exit. Reap the child before deleting anything it can still use.
5. If the child cannot be confirmed gone, report failure and retain all runtime
   sources/mirrors and diagnostics. Do not announce stopped or delete paths
   beneath a surviving QEMU. Kernel-uninterruptible I/O cannot be made safe by
   pretending a signal delivery was successful termination.
6. After confirmed child termination, stop/reap owned supporting processes and
   perform the existing scoped cleanup and remove active `pid` and `qemu.pid`
   hints. Preserve the run/result and diagnostic logs, including unexpected
   zero/nonzero guest exits. Do not change persistent guest/user data.

Repeated normal stop signals must not issue repeated Ctrl-Alt-Delete events or
reenter cleanup. A force request during an orderly attempt must cancel/reap the
owned helper and enter the same child-first fallback, never exit halfway through
the cleanup guard or kill only the launcher.

## CLI force semantics and truthful outcomes

Keep normal stop's bounded fallback behavior, but make it visible:

- Unverified termination: exit success with a warning that clean guest shutdown
  could not be verified and recent writes might have been lost. Retained legacy
  `graceful` records are accepted but rendered with the same conservative warning.
- Confirmed forced termination: exit success with an explicit warning that the
  graceful request failed or was skipped and recent writes might have been lost.
  This preserves stop/restart availability without claiming graceful completion.
- Child still running, changed launch, or inability to confirm termination:
  return a nonzero error. Do not proceed with `cogbox restart`.
- Already stopped/no guest: idempotent success, explicitly not a graceful claim.
- Guest ended on its own (`exited`): the launcher saw QEMU end with NO stop
  request -- an in-guest reboot/poweroff or a panic (both exit zero under
  `-no-reboot`), a crash, an external kill. A later stop reports "was not
  running (guest exited on its own)" and exits 0; it stopped nothing and claims
  nothing. This is deliberately a different token from `unverified`, which
  only ever records a stop this caller requested.
- Start failed before QEMU (`start-failed`): the launcher died in the port
  probe, passt, the L7 stack or persistence. A later stop reports "not running
  (start failed; see cogbox.log)" and exits 0, so `restart` is not blocked by a
  guest that never existed. The generic `failed` stays an error: it means a
  child's termination could not be confirmed.

Handler ordering inside the launcher: the shutdown functions, the EXIT/TERM
traps and the run identity (`launch`, written atomically) are installed right
after the runtime directory exists -- BEFORE the host-port probe. The legacy
`pid` marker alone stays after the probe, because `cogbox ssh` reads it and
then requires `ssh-endpoint`, which the probe's result determines. A stop that
lands during the probe is therefore fenced (via the identity's pid), honored
and recorded, instead of TERMing a handler-less shell. CLI liveness checks
(`start`, `stop`-adjacent verbs, `delete`, `list`, `status`, `console`,
`monitor`, `ssh`, the plugin restart hint) all consult the lifetime flock, not
the `pid` file; `ssh` additionally reports "still starting" while the lock is
held but `pid` is not yet published. Start readiness requires `qemu.start`
(the child's starttime, persisted before `qemu.pid`) to match a live,
launcher-parented `/proc/<pid>/stat`; a zombie or reused PID is never ready.

`stop --force` requests the launcher's bounded hard-stop lane without waiting
45 seconds. It must not retain the current orphan-prone behavior of KILLing only
the launcher. A dedicated launcher signal is acceptable, but send it only after
the per-run protocol confirms support. An older launcher without that protocol
receives its legacy TERM request; classify the result as unverified, never
graceful. Do not add force handling to unrelated verbs or a public web force UI.

Use a small runtime-only outcome protocol, not a job engine:

- Before publishing the launcher's PID, initialize a private per-run record
  containing a protocol version, fresh unpredictable run identifier, and that
  launcher PID. All records live inside the existing instance runtime directory.
- A stop caller captures this identity and signals only that launcher. The
  launcher atomically records the same identity plus a fixed terminal outcome
  after confirming child termination, or a fixed failure outcome otherwise.
  Records contain no executable paths, guest output, credentials, or user data.
  Linux process starttime validates the captured PID; a pidfd binds signal
  delivery to that process rather than a subsequently reused PID.
- Retain the runtime directory after a requested stop or unexpected guest exit so callers can read the
  outcome; continue removing the existing transient sources and mirrors only
  after QEMU exits. The next start already removes the old runtime while holding
  the single-starter flock. Do not introduce a persistent history or new GC.
- Admission trusts the held lifetime flock, not stale PID hints. CLI readiness
  requires the new launch identity and its live QEMU child, not mere existence
  of `qemu.pid`. A reused unrelated PID is never signalled when consuming a
  completed run's matching terminal result.
- Concurrent stop callers may consume the same immutable terminal result.
  Reading a result must not delete it. A new launch's identifier cannot satisfy
  an old stop. If the next start removes/replaces the runtime before a caller
  observes completion, return an outcome-unavailable/changed-launch error rather
  than borrowing the replacement run's result. Missing records never imply
  graceful success. Do not widen PID-file handling into a general PID framework.

The CLI's total wait is at most 65 seconds; it must not time out at the current
ten-second limit while the legitimate orderly attempt is still running. Forced
and missing-helper cases should finish substantially sooner. Update CLI help
with the bounded attempt, warning, and force behavior.

## Outer supervisor integration

Add a synchronous GCE `ExecStop` using the same trusted cogbox package and XDG
config/data/runtime settings as `ExecStart`. It stops exactly the validated
instance captured by this supervisor before it launched the guest. Store that
name in a private, fixed supervisor runtime record; clear stale identity at
supervisor start. Do not refetch metadata or require network/SSH/credentials at
shutdown. Never fall back to the unnamed/default instance. An early boot with
no recorded/started guest is an explicit safe no-op; a malformed record is a
classified failure, leaving systemd's bounded cgroup cleanup as the backstop.
Serialize start admission and this stop check with a short lock that daemon
children do not inherit. A still-in-flight start after one second is an explicit
unconfirmed failure to the unit backstop, not a claim that no guest exists.
Keep the separate instance lifetime-lock inode intact even when the supervisor
clears stale runtime, and acquire that lock before removing those paths.

Keep `KillMode=control-group` (the default), not `none` or an unbounded exception.
Systemd must run the stop command to completion before signaling the remaining
cgroup; merely sending the request and returning is insufficient. Leave
`KillSignal` at its SIGTERM default -- do NOT set `KillSignal=SIGKILL`. A
requested stop is covered by ExecStop, but when the supervisor's main process
exits nonzero on its own (every `supervise.sh` exit is nonzero, including the
ordinary in-guest reboot on leg (j)) systemd SKIPS ExecStop and goes straight
to signaling the cgroup. TERM lets the launcher and remaining processes run
their signal handlers, but also reaches QEMU and its supporting processes;
it does not reserve a guest drain window. SIGKILL in that position prevents
signal handling entirely; the realized-unit check asserts the ABSENCE of any
`KillSignal=` line. Set `TimeoutStopFailureMode=kill` for command timeout.
`FinalKillSignal`/`SendSIGKILL` stay at their defaults (SIGKILL once
`TimeoutStopSec` expires) as the backstop. Consequence to accept: after a
FAILED or timed-out ExecStop the leftover phase gets its own `TimeoutStopSec`
of TERM grace before that final kill, so the aggregate worst case is roughly
two unit timeouts plus post-stop -- the same policy as before this work, not a
regression. Preserve the existing ordering after the state mount, floor,
resolver and network so their reverse stop order keeps guest storage and
supporting services available.

On an unexpected supervisor exit while QEMU is still alive -- for example,
`supervise.sh` leg (j) after a readiness timeout on a healthy guest, or a
`cogbox status` failure that outruns the guest -- the cgroup TERM reaches the
launcher's trap, which sets a stop request and attempts the orderly lane before
TERM/KILL fallback, all inside `TimeoutStopSec=75s`.
With `KillMode=control-group`, however, QEMU and its supporting processes
receive TERM at the same time, so they can exit before the launcher's orderly
attempt completes. The full 45-second guest drain window is not guaranteed on
this path. The systemd fixture's `main-exit-unrequested` case proves TERM
delivery, cleanup and restart with a synthetic child that exits immediately
on TERM; it does not run QEMU or prove guest flushing or orderly shutdown.
On the current image both an in-guest `reboot` and an in-guest `poweroff` end
the QEMU process before the supervisor notices (observed live 2026-09-07:
`poweroff` -> launcher cleanup records `exited` -> leg (j) exits 1 with an
empty cgroup -> restart in ~7 s), so neither triggers a requested stop and
both land on the `exited` outcome. A future runner that keeps QEMU
halted-but-alive on power-off would need separate validation of this path.

Retain `Restart=always` for ordinary guest exits/reboots. During a systemd stop
transaction, automatic restart is suppressed by systemd itself; do not manually
restart the supervisor or write persistent restart-disable flags. Test the case
where its status loop exits while `ExecStop` is waiting, and prove no replacement
guest starts until the stop transaction is complete.

Set `TimeoutStopSec=75s`; the synchronous command must honor its own 65-second
bound. Keep the existing best-effort ten-second `ExecStopPost` readiness removal.
On the normal path (ExecStop completes) the 75-second command backstop plus the
ten-second post-stop leg fits inside GCE's default 90-second host shutdown
window (unverified against the provider; Spot/preemptible windows are shorter).
`TimeoutStopSec` is not itself an aggregate bound: a failed or hung ExecStop
hands leftovers a second `TimeoutStopSec` of TERM grace (see above), which can
exceed that window; kernel-uninterruptible I/O exceeds any window. Test the
realized aggregate, including helper termination, auxiliary cleanup, failed/hung
ExecStop, unit fallback, and post-stop time; an individual timeout assertion is
not enough.
Kernel-uninterruptible tasks remain a failure case, not a promised finite reap.
Keep classified lifecycle output journal-only; never stream raw QMP replies or
runtime logs to the provider serial channel.

## Verification and staged rollout

Behavioral tests must execute the real shutdown/launcher logic with owned fixture
children and helper stubs: healthy delayed completion, helper absent/nonzero/
stalled, socket missing, helper success while QEMU survives, already exited child,
nonzero child exit, TERM-resistant child, forced stop, force during graceful wait,
duplicate callers/signals, stale/different run outcomes, and missing outcomes.
Run the actual CLI and full launcher through start, stop, and the next start
using hermetic external runner/helper substitutes. Cover both nonzero crashes
and panic-equivalent zero exits, retained PID reuse, stale readiness, and a held
lifetime lock. These integration cases must not copy launcher lifecycle wiring.
Assert ordering: guest request before QEMU signals; QEMU gone before supporting
processes or runtime sources disappear; forced/failure diagnostics survive.
Use short test-only deadlines without exposing a caller-controlled production
shutdown executable or arbitrary timeout environment override.

Add a realized-unit check for exact ExecStop/env, finite aggregate deadlines,
preserved mount/network ordering, restart policy and output classes. Add a
systemd behavioral fixture that stops the service with live child processes and
proves they are not signaled while the synchronous graceful helper is waiting.
Cover successful, failed and timed-out stop commands, main-process exit one during
the wait, main-process exit one with NO stop job (the in-guest reboot path: no
ExecStop, leftovers TERMed promptly, ExecStopPost, automatic restart), and
startup/maintenance with no guest. Run real-process, CLI and
supervisor tests locally. A local host without KVM cannot run a NixOS VM test;
execute the systemd fixture on the authorized disposable stage candidate and
capture actual unit/journal ordering and aggregate elapsed time. Do not mutate
the development host's system services to run it. Run Zig tests, launcher tests,
supervisor tests, applicable realized GCE checks, Zig formatting and shell syntax
checks. Run the unchanged control-plane lifecycle regression gate as a
cross-check.

After two independent reviews, bake a uniquely named stage candidate using the
operator's existing image build, preserving its current pins and overlays. Do
not move an image family, publish a default/latest tag, push Git, or touch prod.
Use the approved brief stage-only image configuration override to create two
fresh test-owned instances; verify their write-once numeric image pins, then
restore the original configuration exactly. Existing instances remain pinned
to their original images. Preserve the original failed durability fixture.

On fresh candidate instances, verify provenance and repository readiness. Write
tracked and untracked markers without sync/fsync, capture exact bytes/hashes,
sizes, mtimes, inodes and HEAD, then immediately use ordinary Restart. Repeat
with ordinary Stop, wait for provider termination, then Start. Require unchanged
data and disk/image identity, a new guest boot ID, actual orderly guest shutdown
journal evidence, conservative `unverified` runtime completion, and no repository
worker replay. Exercise force/unhealthy behavior only on the second disposable
candidate using the actual changed runtime seam. Never call a forced result a
graceful pass.

## Residuals

This is not a power-loss guarantee. Sudden host loss, provider hard reset,
unresponsive guest/storage, explicit force, and the shorter Spot/preemptible
shutdown window can still lose recent writes. Those cases remain classified
fallback/failure paths, not claimed graceful durability. Existing pinned images
do not gain the fix on a normal restart; any later migration requires a separate
explicitly authorized image-update workflow.

An affirmative shutdown witness and a panic-aware guest/host protocol are
deliberately deferred. Existing healthy guest journal and data-preservation
tests support those individual shutdowns; they do not turn the runtime's
exit-zero heuristic into a universal clean-shutdown guarantee.
