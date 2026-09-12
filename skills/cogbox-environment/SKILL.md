---
name: cogbox-environment
description: Identify whether this sandbox runs locally or through cogworx before giving host, browser, or lifecycle instructions.
---

Read `/run/cogbox/environment.json`. Its `mode` is `local`, `cogworx`, or
`unknown`; `instance` is the instance name. This file describes the environment,
not permissions or credentials. A missing or malformed file means unknown.

- In local mode, host commands run on the user's workstation, outside this
  guest. The workstation may be Linux or macOS; the guest is Linux in either
  case. Do not assume guest `localhost` is the browser's localhost.
- In cogworx mode, use the sandbox's cogworx interface for browser access and
  lifecycle operations. Do not replace control-plane credentials or advise
  local provisioning on its host.
- In unknown mode, explain that environment information is unavailable. Ask
  whether the user is operating a local cogbox or a managed cogworx sandbox
  before giving environment-specific instructions. Missing API credentials,
  VM rather than container, and a loopback address do not prove local mode.

For web previews, load the `app-relay` skill. Never read or print relay secrets
to discover a URL. Report observed readiness separately from configuration.

Keep project work in `~/work` (`/root/work`), the sandbox's persistent workspace.
Other root filesystem paths have different lifetimes: some caches and harness
homes are persisted or overlaid, while other paths belong to the disposable
guest/container system. Do not assume arbitrary files under `/root`, `/tmp`,
or the system filesystem survive a restart. Installed Nix packages and guest
configuration are managed by the base and per-instance extensions.

Network mode determines egress: `none` blocks outbound access, `full` permits
it, and `rules` applies the host's configured policy. A connection failure can
be policy, DNS, credentials or an unavailable service; inspect the actual error.
Host-managed credential injection keeps the host credential outside the guest
and may use placeholders inside it. Do not replace a placeholder with a host
secret or claim missing local credentials prove an unauthenticated connection.
Changes to host network policy or credential bindings belong to the local host
CLI or managed cogworx interface for the identified environment.
