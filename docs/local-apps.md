# Local browser previews

Start the guest application on `127.0.0.1` and any free port except `8080`,
which the native app relay reserves. On the host:

```sh
cogbox app open --name work --port 3080
```

The command prints a clean `http://127.0.0.1:<allocated-port>/` URL, attempts to
open a browser, and serves until Ctrl-C. `--no-browser` prints the URL without
opening it. `--background` returns after the frontend is ready:

```sh
cogbox app open --name work --port 3080 --background --no-browser
cogbox app list --name work
cogbox app list --json
cogbox app stop --name work --port 3080
```

Omit `--name` to use the default instance; `-n` is also accepted. Repeated opens
reuse the same frontend. Stopping a frontend leaves its guest application and
instance running. Frontends exit when their instance stops or restarts; open
again after a restart. A dead application produces a `502` while the frontend
stays available, so starting the server afterward requires only a browser reload.

Local HTTP ports are allocated automatically and do not need to match the guest
port. The frontend uses the launched instance's endpoint snapshot, so editing
`config.json` while the VM runs does not redirect an existing preview. WebSockets,
server-sent events, streaming responses, escaped paths, and root-relative assets
pass through. The relay credential stays on the host-to-guest hop, outside browser
URLs and app requests.

All local previews use `127.0.0.1`, so browsers share cookies across their ports.
Use separate browser profiles if applications need independent cookie storage.
The frontend accepts its exact advertised Host and same-origin browser requests;
cross-origin embedding and access from other machines are not supported.

New local instances receive local environment metadata. For an older instance
whose ownership is unknown, explicitly adopt it while opening:

```sh
cogbox app open --name work --port 3080 --adopt-local
```

Adoption refuses cogworx-managed state and existing foreign relay credentials.
It never disables relay authentication. Local ownership and the persistent
credential live under the instance's host configuration, outside the guest mount.
Initial provisioning uses the host's cogbox SSH key, pins the instance's existing
SSH host public key, and sends the credential over stdin. A launch marker rejects
commands delivered after that instance restarted. Guest credential files use
mode `0600` and guest root ownership; the local
shared filesystem maps them to the host user outside the VM. A retry
repairs an interrupted first provisioning without rotating a healthy credential
or restarting a healthy relay on every open.

If the guest was built from an older pin without the relay, update that pin and
restart the instance. Existing plugin-based guests that have foreign relay
credentials are not silently adopted. Managed cogworx instances continue to use
their App view and control-plane credential delivery.

Background frontend logs and private control records live beside the instance
runtime directories in `cogbox-apps`. `list` reports only live frontends. `stop`
authenticates over a private Unix socket and never kills a PID from a stale file.
