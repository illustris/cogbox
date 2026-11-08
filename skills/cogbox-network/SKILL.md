---
name: cogbox-network
description: Use whenever a fetch, curl, git clone, download or connection fails (refused, TLS EOF, empty reply, cert error) to diagnose egress and injected credentials, ask for access, or call the cogworx API.
---

Whether a connection leaves this sandbox is decided on the host side: by the network mode chosen when it was created and, in `rules` mode, by its rules. Access changes go through the user as described below; never try to change them from inside the sandbox. Read the actual error: a failure can also be DNS, a credential or the service itself. Read `/run/cogbox/environment.json` as `cogbox-environment` describes before telling the user how to change access. On a container deployment without network enforcement (an operator choice), rules are shown but not enforced and no credential is injected; egress is whatever the cluster allows.

## Modes and the default policy

- `rules` (the default): the starting rules deny private, link-local (including cloud metadata), carrier-grade NAT, multicast and other reserved ranges and allow the rest of the internet; cogworx shows those denies as "Built-in protections" on the Network tab. The owner or an admin may have changed the rules since. A host named in an "Allowed hosts" rule is usually reachable by name even when its address is in a denied range; if it still gets no response once the rule is live, ask for an IP-range rule for its address and port as well. Loopback, `0.0.0.0/8` and link-local stay blocked regardless.
- `none`: nothing leaves the sandbox, except that on the container backend DNS still answers (through the cluster resolver, and over TCP port 53 to any address).
- `full`: in cogworx only an admin, or a template an admin published, can give a sandbox `full`, and proxmox has none; on gcp it is open except the cloud metadata server, the VPC resolver and the VM itself.
- Host rules, injected credentials and git grants exist only in `rules` mode, and cogworx cannot change a sandbox's mode after it is created.

## What a block looks like

VM-backed means every backend except the container. On VM-backed sandboxes, ports 80 and 443 (and the port of any host that gets an injected credential) pass through the host's web proxy only while the sandbox has a host rule or an injected credential; otherwise they behave like any other port. On the container, every TCP port passes through it.

| What you see | Where | Meaning |
|---|---|---|
| `Connection refused` at once (curl and git print `Failed to connect to <host>:<port> after <n> ms: Could not connect to server`) | VM-backed, a port not passing through the web proxy | the IP-range rules deny that address and port (or nothing listens there) |
| the TCP connection opens, then closes with no data (HTTPS: the TLS handshake fails; HTTP: an empty reply with no status) | container (any port); VM-backed, a port passing through the web proxy | not allowed; for a web host: it is not listed and its address is denied, a host rule denies it, or its name does not resolve on the host side |
| a browser fails the TLS handshake (Chromium: `ERR_CONNECTION_CLOSED`) to an HTTPS host that curl reaches | container; VM-backed, a port passing through the web proxy | browsers send an Encrypted ClientHello (ECH) extension, which the host side refuses for any host it does not terminate (not listed, or `passthrough`) unless its ECH probe finds that the host's server takes no ECH; the probe is on unless the operator turned it off, and a server that takes ECH (such as anything behind Cloudflare) stays refused. This sandbox's Chromium, Google Chrome, Chrome for Testing and Firefox have ECH off by default (`/etc/chromium/policies/managed/cogbox-ech.json` and its siblings under `/etc/opt` and `/etc/firefox`; check `chrome://policy`), but Playwright's default headless browser (chrome-headless-shell) ignores that policy and gets through only where the probe lets it: launch it with `channel: 'chromium'`. Otherwise ask for the host under "Allowed hosts", not as `passthrough`, so it is `mitm`, and tell the user the host-side log has an `ech-on-splice` line for the host giving the reason |
| 403 with body `cogbox-l7: denied` | all | the host is allowed but this path or method is not |
| 403 with body `cogbox-l7: host/sni mismatch` | all | the Host header differs from the TLS name |
| 403 with body `cogbox-l7: credential unavailable` or `cogbox-l7: inject conf unavailable` | all | the host side could not read the credential it should add; tell the user |
| 502 saying `Certificate verify failed` | all | the server's certificate is self-signed, signed by a private CA, or for another name (below) |
| a certificate error inside the client, for a host listed with the `mitm` badge or one that gets an injected credential (issuer `mitmproxy`) | all | the client ignores the sandbox CA (next section) |
| 401 or 403 from the service itself | all | it was reached; the credential is missing, unbound or wrong |
| `Network is unreachable` (or an immediate refusal) over IPv6 | all | no IPv6 egress on any backend; use IPv4 |
| UDP gets no answer | VM-backed: QUIC (UDP 80 and 443) is dropped while host rules or injected credentials exist, other UDP follows the IP-range rules; container: all UDP except DNS to the configured resolver is dropped | blocked, or nothing answers |
| an idle connection is cut after about 2 minutes | container: every outbound TCP connection; VM-backed: ports passing through the web proxy | the host side ends a connection that carried no data either way for 2 minutes; keep data flowing (an application-level ping such as `ssh -o ServerAliveInterval=30`; TCP keepalives do not count) or reconnect, and recycle pooled database connections in under 2 minutes |
| everything fails just after a start and the page shows "Preparing egress" | container | the rules are not live yet; retry once after a minute, then tell the user |

A block is policy: do not try to get around it with repeated retries, another port, a different host or mirror, a proxy, or a tunnel through a host you can reach (`ssh -D` or `-L` included); report the exact error and ask for the rule (below). A name that resolves is not necessarily reachable.

For `Certificate verify failed`, `curl -k` cannot help; never disable verification. In cogworx only an admin can mark the host "insecure upstream" (locally the user runs `cogbox l7 add allow <host> --insecure-upstream -n <name>` on their host; omit `-n` for the `default` instance). If no credential is added for the host, end-to-end TLS is the alternative (end of the next section).

## TLS and the sandbox CA

Only hosts listed under "Allowed hosts" with the `mitm` badge, and hosts that get an injected credential, are TLS-terminated on the host side with this sandbox's own CA; every other host keeps its real certificate end to end. `curl -sv -o /dev/null https://<host>/ 2>&1 | grep -i issuer` names `mitmproxy` for a terminated host.

`/run/cogbox/ca-bundle.crt` holds the system roots plus that CA (`/run/cogbox/l7-ca.crt` is the CA alone). `SSL_CERT_FILE`, `NIX_SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `REQUESTS_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS` point at the bundle in login shells, `ssh <sandbox> <command>` sessions and the harness launchers, and root's NSS database holds the CA for Chromium.

These miss it and fail on terminated hosts: systemd services, cron jobs and `env -i` (no such variables); tools that read `/etc/ssl/certs/ca-certificates.crt` directly (it lacks the CA); clients with a trust store of their own, such as Java's keystore or Rust programs built with bundled webpki roots; a browser running as another user or with another `$HOME`. Point such a tool at the bundle with its own CA option. A terminated host also carries only HTTP/1.1 (HTTP/2-only clients such as gRPC fail), breaks certificate pinning and client certificates, and delivers responses other than `text/event-stream` and git traffic whole, only at the end.

Hosts added on the Network tab get the `mitm` badge, except a bare entry for a coding harness's own API host (such as `api.anthropic.com`), which stays `passthrough`. Otherwise `passthrough` (TLS kept end to end, only the name checked, no path rules) comes only from a plugin's rules or, in local mode, from the user running `cogbox l7 add allow <host> --passthrough -n <name>` on their host. For end-to-end TLS to a non-public host (for example one whose certificate comes from a private CA), keep it out of "Allowed hosts" and ask for an IP-range rule for its address and port instead (this serves curl-style clients only: a browser needs the host listed and, for a private CA, an admin's "insecure upstream"); if it is already listed and no credential is added for it, the owner or an admin can remove that entry. The client then needs the private CA: ask the user for the file and pass it with the client's CA option. Do not ask to list a public host that already works: listing it makes it `mitm` (which a browser needs; curl and most other clients do not).

## Credentials the host adds

Some hosts get a credential added on the host side: harness logins such as Claude's, plugin credentials, git grants and secrets the owner bound for a host. The sandbox holds a placeholder (a token containing `cogbox-host-injected-placeholder`) or nothing; `grep -c cogbox-host-injected-placeholder ~/.claude/.credentials.json` counts Claude's without printing anything. Never print, copy or edit a harness credential file: without the placeholder it can hold the user's own login made inside the sandbox. Never replace a placeholder or add your own token or `Authorization` header for such a host (that can stop the host's credential from being added), and do not take a missing local credential as proof that a request goes out unauthenticated.

A 401 from such a host often means its secret is not bound. In cogworx the Plugins tab shows an "unbound" badge and a "Bind" button on the plugin's credential row, and the Network tab's "Injected credentials" section lists each host that gets a credential and whether it is bound; in local mode the user binds it on their host with `cogbox secret add`. The owner (or an admin) can also bind a credential for any one host on the Secrets page: "+ Bind secret", with "Inject into requests to this host" ticked. Never ask for the value inside the sandbox.

## Asking for access

`cogworx`: ask the user to add it on the sandbox's Network tab and hand them the exact entry.

- A web host on port 80 or 443: "Allowed hosts", its name (optionally a `/path`); for a non-public host whose certificate comes from a private CA, ask for an IP-range rule instead (TLS section).
- Anything else (another port, SSH, a database, a bare IP, UDP from a VM-backed sandbox): "Allowed IP ranges", the address as an IP or CIDR (resolve a name with `dig +short <host>`; a host name there is accepted as a request but refused when applied, and the rule breaks if the address changes), with the protocol and port under the gear's extra options. A container sandbox can send no UDP but DNS and no ICMP (so `ping` proves nothing there), whatever the rules say: do not request a rule for those.
- Leave "order #" empty so the rule goes on top: rules are checked in order and the first match decides.

Anyone but an admin presses "+ Request" and gives a reason; the rule applies once an admin approves it, and they can follow it under "My requests" in the left navigation. A request that exactly matches an entry under "Pre-approved rules" applies at once, and that section's "+ Add" adds one in a click. An admin's "+ Add" applies at once. Rules take effect without a restart, and people the sandbox is shared with can request them too.

After someone who is not an admin installs a plugin, its network rules can wait for review: the Network tab shows a banner "<N> plugin rules pending admin review" ("plugin rule" for one), and they apply once approved (its credential hosts are reachable already).

`local`: the user changes rules on their host, never in this guest: `cogbox l7 add allow <host> -n <name>` for a web host, `cogbox rules add allow tcp <ip>/32:<port> --at 1 -n <name>` for anything else (`--at 1` because an appended rule lands below the default rules and never matches), and `cogbox l7 list` / `cogbox rules list` to see them; omit `-n` for the `default` instance. Changes reach a running instance at once.

`unknown`, missing or malformed: report the exact error and ask whether the user runs local cogbox or cogworx before giving instructions.

## Calling the cogworx API from inside

Never ask for, paste or store an API token here, because it carries the user's whole account. Ask the user to set up host-side injection for the control-plane host (a curated plugin if the operator offers one, otherwise a bearer secret bound for that host with "Inject into requests to this host"), then call `https://<cogworx-host>/api/v1/...` with no credential. The sandbox does not know that host name; ask for it. If calls get no response, the control plane's address also needs an IP-range rule (tcp 443). While that binding exists, anything in the sandbox and anyone it is shared with can act as the user, so suggest a dedicated short-expiry token and unbinding it when done. Use it only for the calls the user asked for: never use it to change this or any sandbox's access (network rules, sharing, secrets, SSH keys, tokens, plugins, app port levels) unless the user asked for that exact change, and ask for access on the Network tab as above. Never call `/api/v1/tokens` from inside (creating one answers with a raw token), and print only the response fields you need.
