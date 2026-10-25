---
name: cogbox-remote-access
description: Connect to this sandbox from outside with SSH, VS Code, scp, sftp, port forwards or mosh, and explain what users it is shared with can and cannot do.
---

Read `/run/cogbox/environment.json` as `cogbox-environment` describes.

- `local`: the user connects from their host with `cogbox ssh` (add `-n <name>` unless the instance is `default`; `cogbox ssh -n <name> -- <command>` runs one command). It uses cogbox's own key and adds no agent forwarding, and mosh does not connect to a local cogbox. Never run `cogbox` inside this guest.
- `unknown`, missing or malformed: ask whether the user runs local cogbox or cogworx.
- `cogworx`: the rest of this skill applies.

## The SSH command and keys

Copy the command from the `ssh` row on the sandbox's Overview tab; it has the form `ssh <account-id>-<sandbox-name>@<gateway-host> -p <port>`. The user name is the owner's full instance id, which this sandbox's `instance` name alone does not give, so never build it yourself. Compare the fingerprint under "host key" on first connect. "SSH available once running" means the sandbox is not running yet (stopped or still starting); no `ssh` row at all means the gateway is off or this backend has no SSH. Users the sandbox is shared with use the same command with their own keys.

Keys: the user pastes public keys under "Add public keys" in the SSH keys section of the account Settings page and presses "Add keys", or uses "Import from <provider>". Certificates are refused, and RSA keys under 2048 bits and unregistered keys fail authentication. Never generate a key for the user or ask for their private key.

## What works over it

- Shells, `ssh ... <command>`, `scp`, `sftp`, `rsync` (it is in the image) and `ssh -L` local forwards. A forward is opened inside the sandbox: `-L 3080:127.0.0.1:3080` reaches a service listening there, and a forward to another host obeys this sandbox's network rules.
- Refused: `ssh -R`, X11, Unix-socket forwards and every other channel type.
- VS Code Remote-SSH: a `Host` entry in the user's `~/.ssh/config` with `HostName`, `Port` and `User` taken from that command. Keep VS Code's `remote.SSH.remoteServerListenOnSocket` setting off, because Unix-socket forwards are refused, and the sandbox must be able to download the VS Code server (a public host, allowed by default in `rules` mode).

## Agent forwarding

Agent forwarding (`ssh -A`) works unless the operator turned it off. The agent is usable only while that connection is open and only by processes that inherit its `SSH_AUTH_SOCK`: check with `ssh-add -l` in the shell that needs it; a shell started elsewhere, such as the web console's, does not have it. While it is open anyone with a shell in the sandbox can use it, so forward it only into a sandbox the user trusts. It is what makes an `ssh` git remote work (`cogbox-git`).

## mosh

When the Overview row also shows a `mosh --ssh='ssh -p <port>' ...` command, use that. It works on container, gcp and proxmox sandboxes, never in network mode `none`. If it never connects, a container sandbox needs a restart, and a gcp sandbox built from an older image needs an image upgrade.

## Limits and errors

At most 8 connections per account at once (`too many concurrent SSH sessions; close one and retry`), and every connection ends after 24 hours, so run long jobs in tmux inside the sandbox. `access denied or instance not found` means a wrong user name or no access to that sandbox; `sandbox not running; start it first` means it is stopped or still booting; `could not reach sandbox` or `could not establish sandbox connection` means the gateway could not get through to it (retry; if it persists, tell the user).

## Network mode none

On gcp and proxmox there is no SSH (`SSH is unavailable for this sandbox: its network mode is none`), no mosh and no app access, and the web console is the serial console on the Overview tab. On the container backend SSH still works, but mosh and app access do not.

## Apps without an Apps tab

When this deployment has no Apps tab (no app proxy), the user adds `-L 3080:127.0.0.1:3080` to the command from the Overview `ssh` row and opens `http://127.0.0.1:3080/` in their own browser; load `app-relay` for starting the app.

## Sharing

The owner (or an admin) shares and unshares on the Sharing tab. People it is shared with can open its console and shell (including over SSH, as above), reach its app ports at the `sandbox` level and request network rules. They cannot start, stop or restart it, change sharing, resources, plugins, git access or app port levels, or delete network rules. Every session runs as root, so everything in the sandbox, `~/work` and a forwarded agent included, is reachable by everyone it is shared with. Sharing suspends every git grant and Vault binding until it is private again (`cogbox-git`, `cogbox-vault`); setting an app port's level is not sharing. Sharing does not pause credentials bound for injection (Secrets page, plugin credentials) or the owner's Claude connection: requests from anyone it is shared with get them added, and a shared user who starts a harness uses the owner's Claude account unless they log in themselves.
