---
name: cogbox-vault
description: Find and use the Vault credentials cogworx delivers under /run/cogworx/vault (KV files, database logins and passwords, SSH certificates), and handle missing, rotated or suspended ones.
---

Read `/run/cogbox/environment.json` as `cogbox-environment` describes. `local`: cogbox itself has no Vault delivery and nothing appears under `/run/cogworx/vault`; credentials there are the user's host-side choice (load `cogbox-network`). `unknown`, missing or malformed: ask whether the user runs local cogbox or cogworx. `cogworx`: list what was delivered with `ls /run/cogworx/vault/kv /run/cogworx/vault/db /run/cogworx/vault/ssh 2>/dev/null` (names only) and use the file you need if it is there. If it is not, delivery exists only when the sandbox's page has a Vault tab (the operator enables it, and only the container, gcp and proxmox backends support it); ask the user whether it has one and what the binding's status says (below).

## Where deliveries land

Each binding writes under a name equal to the binding's name (lowercase letters, digits and `-`):

| Binding | In the sandbox |
|---|---|
| KV, file | `/run/cogworx/vault/kv/<name>` |
| database | `/run/cogworx/vault/db/<name>.env` and `/run/cogworx/vault/db/<name>.json` |
| SSH | `/run/cogworx/vault/ssh/<name>` (private key), `<name>.pub`, `<name>-cert.pub` (the signed certificate) |
| KV, inject into requests | nothing; the host adds it to requests |

Files are root's, mode 0600 (`.pub` files 0644), in 0700 directories. Ignore dot-prefixed staging names, and never touch `/run/cogworx/vault/.epoch`.

## Using them

- KV file: when the binding names a field holding a string, the file is that string's raw bytes with no trailing newline; otherwise it is JSON (that field's value, or the whole secret as a key/value object). `jq -r 'if type == "object" then keys[] else type end' /run/cogworx/vault/kv/<name> 2>/dev/null` shows its shape without a value: an object's key names, else only a type word such as `string`, and nothing for raw text. Never inspect one with `cat`, `head`, `jq .` or `curl -v`, and never use `set -x` while a value is on a command line.
- Database: the `.env` holds exactly two lines, `DB_USERNAME='...'` and `DB_PASSWORD='...'`; the files hold only the login, so ask the user for the host, port and database. Load the `.env` in a subshell around the one command that uses it, for example `( set -a; . /run/cogworx/vault/db/<name>.env; set +a; PGPASSWORD="$DB_PASSWORD" exec nix shell nixpkgs#postgresql -c psql -h <db-host> -p <port> -U "$DB_USERNAME" -d <database> -c '<sql>' )`, so the password does not stay in your shell. The `.json` is `{"version":1,"username":...,"password":...,"issued_at":...}`; neither file carries an expiry. No database client is installed; run the one you need from nixpkgs as `cogbox-packages` describes.
- SSH: `ssh -i /run/cogworx/vault/ssh/<name> -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new <principal>@<host>`; ssh uses `<name>-cert.pub` next to the key by itself. `<principal>` is one the owner set on the binding, else the SSH role's default user. `ssh-keygen -L -f /run/cogworx/vault/ssh/<name>-cert.pub` shows the principals and validity. The target must trust the Vault SSH CA; cogworx manages neither host keys nor `~/.ssh/config`.
- Inject into requests: the value never enters the sandbox; requests to the binding's host get it added on the host side. Call `https://<host>/...` with no credential of your own; load `cogbox-network` for how injected credentials behave.

## Rules

Read the files in place, when you need them. Never print, echo, copy (into `~`, `~/work` or anywhere else), commit or paste their contents: a copy outlives every teardown. Never edit, move or delete them or `.epoch`; a deleted file may not come back until the owner presses "Retry".

## Lifetime and refresh

The files exist only while the sandbox runs and vanish when it stops or restarts; every start delivers new database credentials and a new SSH key and certificate. While it runs, KV files are re-read every few minutes and rewritten only when the value changed; database credentials can be replaced (both files, a new `issued_at`); SSH certificates are re-signed before they expire, keeping the key. When a login starts failing, read the files again and reconnect: a process that loaded a value earlier keeps the old one.

A new binding on a running sandbox normally arrives within seconds; after a start, files can take a few minutes to appear (never, in network mode `none` on gcp and proxmox: see below). `/run/cogworx/vault` itself appears only with the first file this boot and can stay after bindings are removed, so its presence or absence proves nothing.

## When a file is missing

Nothing in the sandbox records why a file is missing; ask the user what the binding's status says on the Vault tab.

| Status | Meaning | Next step |
|---|---|---|
| `pending` | not delivered yet; "delivered once this sandbox is running" when it is stopped | wait, or start it |
| `active` | delivered and kept current; just after a start the file may still be on its way, otherwise it was deleted | wait a few minutes after a start, else the owner presses "Retry" |
| `reconnect needed` | the owner's Vault session ended; delivered files were removed | the owner connects Vault again (Vault tab, or the Vault section of the account Settings page); as the same Vault identity the bindings resume by themselves |
| `error` | delivery stopped and files were removed; the row's last error says why; it never retries by itself | the owner fixes the cause and presses "Retry" |
| `suspended (shared)` | the sandbox is shared; nothing is delivered | resumes when it is private again |
| `removing` | being removed | none |
| no row | no such binding | the owner adds one |

If Vault itself is unreachable, delivered files stay, but database logins and SSH certificates still expire on schedule and nothing new is issued, so logins can fail and, after a restart, files can be missing until Vault answers.

## Network for database and SSH targets

cogworx adds no network rule for a database or SSH target. One on a private or reserved address needs an IP-range rule (tcp and its port) on the Network tab; load `cogbox-network` to ask for it. In `none` network mode: on the container backend the files still arrive but no target is reachable; on gcp and proxmox nothing is delivered (bindings stay `pending`), because delivery there goes through the guest's SSH forward, which `none` does not have. On a container sandbox the host side ends any connection idle for 2 minutes: use `ssh -o ServerAliveInterval=30` and recycle pooled database connections sooner (`cogbox-network`).

## Asking for a binding

Only the owner can add a binding or press "Retry", from the cogworx web page, after connecting their Vault account ("Connect Vault" in the Vault section of the account Settings page); an admin acting as another user cannot. On the sandbox's Vault tab they fill in the binding's name, its source (a KV path with an optional field, or a database or SSH role), "file in the sandbox" or "inject into requests" with the host, and for SSH the principals and ttl, then press "Bind". Tell the user which engine, path or role and field you need; never ask for the value.
