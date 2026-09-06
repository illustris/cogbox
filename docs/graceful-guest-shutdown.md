# Graceful guest shutdown

## Scope and evidence

Repair ordinary VM stop/restart by draining the inner NixOS guest before killing
QEMU. Keep this runtime-only: no control-plane lifecycle, authorization, provider
API, disk-layout, container-native, plugin, or dependency-pin changes.

The launcher currently responds to TERM by sending QEMU TERM, waiting about five
seconds, then sending KILL. This does not shut down the guest operating system.
The GCE supervisor has no synchronous `ExecStop`, so stopping the outer host can
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
   owned QEMU child. Only successful helper execution, a successful child exit,
   and no fallback qualify as completion through the graceful path. Missing
   socket/helper, errors, timeout, unknown exit, and generic `status=stopped`
   must never become graceful success. In particular, `guest-panicked` and
   `internal-error` are not orderly shutdown acknowledgments.
4. If orderly completion cannot be established, retain the existing ability to
   stop an unhealthy VM: a classified forced fallback sends the owned child
   TERM for at most five seconds, then KILL with at most five seconds to confirm
   exit. Reap the child before deleting anything it can still use.
5. If the child cannot be confirmed gone, report failure and retain all runtime
   sources/mirrors and diagnostics. Do not announce stopped or delete paths
   beneath a surviving QEMU. Kernel-uninterruptible I/O cannot be made safe by
   pretending a signal delivery was successful termination.
6. After confirmed child termination, stop/reap owned supporting processes and
   perform the existing scoped cleanup. Preserve diagnostic logs on forced or
   failed shutdown. Do not change persistent guest/user data.

Repeated normal stop signals must not issue repeated Ctrl-Alt-Delete events or
reenter cleanup. A force request during an orderly attempt must cancel/reap the
owned helper and enter the same child-first fallback, never exit halfway through
the cleanup guard or kill only the launcher.

## CLI force semantics and truthful outcomes

Keep normal stop's bounded fallback behavior, but make it visible:

- Graceful-path completion: exit success, classified completion message.
- Confirmed forced termination: exit success with an explicit warning that the
  graceful request failed or was skipped and recent writes might have been lost.
  This preserves stop/restart availability without claiming graceful completion.
- Child still running, changed launch, or inability to confirm termination:
  return a nonzero error. Do not proceed with `cogbox restart`.
- Already stopped/no guest: idempotent success, explicitly not a graceful claim.

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
- Retain the runtime directory after a requested stop so callers can read the
  outcome; continue removing the existing transient sources and mirrors only
  after QEMU exits. The next start already removes the old runtime while holding
  the single-starter flock. Do not introduce a persistent history or new GC.
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
cgroup; merely sending the request and returning is insufficient. Set
`KillSignal=SIGKILL` for leftovers AFTER the synchronous command, and
`TimeoutStopFailureMode=kill` for command timeout. The graceful window is owned
by ExecStop; do not accidentally grant another full unit timeout to leftover
processes afterward. Preserve the existing ordering after the state mount,
floor, resolver and network so their reverse stop order keeps guest storage and
supporting services available.

Retain `Restart=always` for ordinary guest exits/reboots. During a systemd stop
transaction, automatic restart is suppressed by systemd itself; do not manually
restart the supervisor or write persistent restart-disable flags. Test the case
where its status loop exits while `ExecStop` is waiting, and prove no replacement
guest starts until the stop transaction is complete.

Set `TimeoutStopSec=75s`; the synchronous command must honor its own 65-second
bound. Keep the existing best-effort ten-second `ExecStopPost` readiness removal.
For killable processes the 75-second command backstop plus ten-second post-stop
leg leaves margin inside the standard provider's 120-second shutdown window.
`TimeoutStopSec` is not itself an aggregate bound: the explicit final-kill policy
above prevents its reuse as another graceful-wait interval. Test the realized
aggregate, including helper termination, auxiliary cleanup, failed/hung ExecStop,
unit fallback, and post-stop time; an individual timeout assertion is not enough.
Kernel-uninterruptible tasks remain a failure case, not a promised finite reap.
Keep classified lifecycle output journal-only; never stream raw QMP replies or
runtime logs to the provider serial channel.

## Verification and staged rollout

Behavioral tests must execute the real shutdown/launcher logic with owned fixture
children and helper stubs: healthy delayed completion, helper absent/nonzero/
stalled, socket missing, helper success while QEMU survives, already exited child,
nonzero child exit, TERM-resistant child, forced stop, force during graceful wait,
duplicate callers/signals, stale/different run outcomes, and missing outcomes.
Assert ordering: guest request before QEMU signals; QEMU gone before supporting
processes or runtime sources disappear; forced/failure diagnostics survive.
Use short test-only deadlines without exposing a caller-controlled production
shutdown executable or arbitrary timeout environment override.

Add a realized-unit check for exact ExecStop/env, finite aggregate deadlines,
preserved mount/network ordering, restart policy and output classes. Add a
systemd behavioral fixture that stops the service with live child processes and
proves they are not signaled while the synchronous graceful helper is waiting.
Cover successful, failed and timed-out stop commands, main-process exit during
the wait, and startup/maintenance with no guest. Run real-process, CLI and
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
journal evidence, classified no-fallback runtime completion, and no repository
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
