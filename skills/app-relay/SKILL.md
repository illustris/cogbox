---
name: app-relay
description: Start a loopback web service and explain browser access in local cogbox or managed cogworx, including previews, notebooks and dev servers.
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
- `cogworx`: tell the user to open port 3080 from this sandbox's Apps interface.
  App access follows its configured cogworx permissions. Do not replace relay
  credentials, construct an internal relay URL, or suggest local provisioning.
- `unknown`, missing or malformed context: report the working guest port and
  ask whether the user uses local cogbox or cogworx before choosing instructions.

`curl -fsS http://127.0.0.1:8080/healthz` checks relay liveness only. It does not
prove a provisioned secret, working application, or browser authorization.
If an app does not load, verify its startup port and IPv4 loopback listener.
An application-generated error is not necessarily a relay failure. Never print
or embed a relay secret in a URL. WebSockets, SSE and streaming are supported.
