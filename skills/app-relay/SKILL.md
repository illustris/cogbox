---
name: app-relay
description: Start a loopback web service and explain browser access in local cogbox or managed cogworx, including previews, notebooks and dev servers, and who can open it.
---

Start the application on guest `127.0.0.1`, using a free port other than 8080.
Port 8080 belongs to the native relay. IPv6-only `::1` is not reachable through
the relay. If Python is installed, for example:
`python3 -m http.server 3080 --bind 127.0.0.1`. Check that the chosen server tool
is available; the base relay does not install application runtimes.

Verify the application itself responds, then read
`/run/cogbox/environment.json` as described by `cogbox-environment`.

- `local`: tell the user to run `cogbox app open --port 3080 --name NAME` on their host,
  substituting the recorded instance name. Omit `--name` for `default`. The command
  prints the actual browser URL and stays in the foreground; Ctrl-C closes
  that proxy. `--background` leaves it running; `cogbox app list` and
  `cogbox app stop` manage host proxies. Do not invent a localhost URL or run
  the host command inside this guest.
- `cogworx`: tell the user to open port 3080 from this sandbox's page: the `app` row on its Overview tab, or the "Open an app" panel on its Apps tab, opens the app in a new browser tab at an address of its own. By default only people who can open the sandbox can open its apps. The owner or an admin can pin a port under "Port access" on the Apps tab (the port, a level, "Pin port"): `sandbox` (only who can open this sandbox), `teams` (plus the teams listed on the port), `all` (anyone signed in to cogworx) or `none` (anyone on the network, no sign-in), and the operator may withhold levels. Every level but `sandbox` reaches people the sandbox is not shared with, so leave widening to the user. To let a teammate open it, prefer pinning the port at `teams` with a team they are in over sharing the sandbox: sharing gives them a shell and suspends its git grants and Vault bindings (`cogbox-remote-access`). Port 8080 can be neither opened nor pinned. In network mode `none` the app proxy cannot open any port; on a container sandbox an `ssh -L` forward still works (`cogbox-remote-access`). If the page has no `app` row and no Apps tab, this deployment has no app proxy: load `cogbox-remote-access` for an `ssh -L` forward. Do not replace relay credentials, construct an app URL, or suggest local provisioning.
- `unknown`, missing or malformed context: report the working guest port and
  ask whether the user uses local cogbox or cogworx before choosing instructions.

`curl -fsS http://127.0.0.1:8080/healthz` checks relay liveness only. It does not
prove a provisioned secret, working application, or browser authorization.
If an app does not load, verify its startup port and IPv4 loopback listener.
An application-generated error is not necessarily a relay failure. Never print
or embed a relay secret in a URL. WebSockets, SSE and streaming are supported.
