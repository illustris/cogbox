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

Keep project work in `~/work` (`/root/work`), the sandbox's persistent
workspace, and load the `cogbox-filesystem` skill for path lifetimes.

Never replace a placeholder credential or add your own for a host the host side authenticates, and do not take a missing local credential as proof a request is unauthenticated.

For outbound network access, blocked connections, certificate errors and credentials the host adds to requests, load the `cogbox-network` skill; for git hosts, `cogbox-git`; for credentials delivered from Vault, `cogbox-vault`; and for SSH, editors, file copy, port forwards and sharing, `cogbox-remote-access`.
