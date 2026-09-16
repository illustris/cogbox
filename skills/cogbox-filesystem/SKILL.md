---
name: cogbox-filesystem
description: Decide where to write inside the sandbox so work survives a restart, and check a path's lifetime instead of assuming it.
---

`~/work` (`/root/work`, a symlink to `/var/lib/cogbox/work`) is the persistent
workspace. Keep repositories, generated artifacts, notes and anything else worth
keeping there. The path is the same on both backends: the VM reaches it through
the host-backed share (bound onto the persistent pool under the hosted storage
profile), and on the container `cogbox-container-state.service` links
`/var/lib/cogbox` onto the state volume before the workspace is used.

These do not survive a restart:

- The root filesystem. On the VM backend `/` is a RAM tmpfs; on the container it
  is the ephemeral writable layer, and the previous boot's `/root` is already
  gone by the time the next boot runs.
- `/tmp`, and anything else written outside `~/work` on that root.

The writable `/nix` store layer is backend-dependent; do not state one rule for
it. On a VM-backed sandbox the host re-creates that filesystem before each
launch, and a package realized at runtime is fetched again after a restart. On
the container backend the per-instance overlay upper is node-local and usually
survives a restart, but a reschedule onto another node loses it. Treat neither
as storage: if a tool has to be there next time, extend the sandbox, as
`cogbox-packages` describes.

Paths under `/root` are not uniformly one or the other, and they differ between
sandboxes rather than only between paths. `/root/.cache`, `/root/.config` and
`/root/.local` are symlinked onto the state volume on the container backend, and
bound onto a persistent pool on a VM configured for one, but on the default VM
profile no such pool exists and all three sit on the tmpfs root like everything
else; a bind or symlink that could not be set up lands there too, with a line in
the journal. The harness homes proper -- `/root/.claude`, `/root/.hermes`,
`/root/.config/opencode` -- are overlays with uppers of their own, independent
of whatever their parent directory is doing. Do not guess any of this:
`findmnt -T <path>` shows whether a path sits on a mount of its own, and
`readlink -f <path>` resolves it through symlinks. If a file matters, put it in
`~/work` and stop reasoning about the rest.

`~/work/.cogbox/brain`, and the skill, agent, command and rule entries under
`~/work/.claude/`, are symlinks into a Nix store path. Never edit them in place,
and do not take a successful write as permission to: you are root over a
writable store overlay, so the write copies the file up and looks like it
worked. The mutated file then lives in that writable layer, with the lifetime
described above, and nix knows nothing about it: the change is invisible, never
reproducible, and gone whenever that layer is. Changing what this sandbox can do
means changing the extension that provides it, which is `cogbox-packages`.

Load `cogbox-environment` to identify the sandbox before giving host-side
instructions, and `app-relay` for ports and browser previews.
