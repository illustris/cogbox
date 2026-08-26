# The per-sandbox auth proxy

A dedicated per-sandbox process, in the sandbox's trusted half, **inline on the data path**, that classifies and authorizes each request to a *migrated* provider against a typed route table and stamps the owner's credential itself. It is **pluggable per service** — gitlab is plugin #1; forgejo and harbor (whose docker-registry token dance *requires* inline mediation) slot in later without interface changes.

This document is the design and the operator reference. For where it sits in the egress chain and the wire-file/verb summary, see [network-filtering.md](network-filtering.md#the-per-sandbox-auth-proxy).

## Why it exists

The git integration used to compile per-user grants into generic L7 path-prefix rules shipped into each sandbox's enforcer. That whitelist paradigm has three structural problems the auth proxy replaces for a migrated provider:

- **Path-prefix escapes.** The enforcer decides on a *decoded, flattened* path and forwards a *different* (raw) one, matched left-anchored only. An encoded slash inflates one addressed segment into several, so an `allow …/projects/*/issues` rule is escaped by `…/projects/mygroup%2Fissues/access_tokens` — the tail lands on the id's own last component and absorbs the mint endpoint. The concrete resolved-id tier (`…/projects/1234/issues`) has the same escape with *no wildcard at all*, which is the one an auditor misses. The vector table pins six such live rows; under the auth proxy they all flip to **deny**.
- **Dual-matcher coupling.** Two independent matchers (the Zig proxy and the mitmproxy addon) had to agree byte-for-byte on one path language, kept in step only by a shared oracle. The auth proxy has its own typed engine with its own oracle (`zig/src/authproxy/route_vectors.tsv`); the shared table stays for the *generic* L7 language (network-tab rules, plugins, templates), which does not move.
- **Language-capped capability granularity.** With no mid-path wildcard, an `mr` capability necessarily includes self-`/approve` and self-`/merge`. A typed route table makes finer capabilities expressible (a v2 item).

A **per-sandbox** process (rather than a central gateway) keeps token custody exactly where it is today — one enforcer holds one owner's credential — instead of concentrating every owner's token into one fleet-wide availability dependency, and needs no new sandbox→control-plane data channel.

## Chain position

```
guest :443 ─▶ l7proxy (vet + pin upstream IP) ─▶ mitmdump (TLS terminate,
   Host==SNI, dot-segment refusal, method-override strip — all unchanged)
        │
        ├── host NOT in l7-auth-hosts  → LEGACY path, byte-identical (evaluate
        │                                 + rules_tag gating + addon injection)
        └── host IN l7-auth-hosts      → RETARGET to 127.0.0.1:<auth-port>,
                                          scheme=http, three reserved headers,
                                          NO addon injection
                                              ▼
                                    ┌── cogbox __authproxy ───────────────────┐
                                    │ core: framing, canonicalize, allowlist, │
                                    │       host-allowlist gate, streaming     │
                                    │ plugin: classify → authorize → upstream  │
                                    │         → authenticate | mediate         │
                                    │ upstream leg: to X-Cogbox-Vetted's IP,   │
                                    │   scheme + Host from the conf            │
                                    └──────────────────────────────────────────┘
```

The addon keeps TLS termination, per-SNI leaf minting, `Host == SNI`, dot-segment refusal, method-override stripping and streaming. The auth proxy is a plain-HTTP, Host-routed, per-request reverse proxy on a loopback port. The retarget is **opt-in per host** from `l7-auth-hosts`, never derived from the existing terminate or inject sets, so every un-migrated host keeps the unchanged legacy path.

## The three retarget traps

The addon retarget is subtle enough that all three of these are load-bearing:

1. **Use `flow.request.data.host` / `.data.port`, never the `.host`/`.port` properties.** Both property setters call mitmproxy's `_update_host_and_authority()`, which rewrites the `Host`/`:authority` header — destroying the routing signal the auth proxy needs and breaking the `Host == SNI` story. mitmproxy's own transparent-mode code uses `.data` for exactly this reason. The vetted upstream address lives in `.data.host/.data.port` (the SOCKS5 CONNECT address = l7proxy's vetted, pinned IP); it is captured **before** the retarget overwrites it and handed forward in `X-Cogbox-Vetted`.
2. **Force `flow.request.scheme = "http"` on the loopback hop.** Left as `https`, mitmproxy takes the retarget as a new upstream, sets the loopback IP as the SNI, and fails verification. The `scheme` setter has no side effects. Plaintext on loopback is the same trust level as the existing l7proxy→mitm no-auth SOCKS5 hop, and on GCE that loopback is already fenced from the guest.
3. **The hop is connection-POOLED across upstream hosts.** mitmproxy keys the loopback connection on `(address, tls, via, transport)` only, so flows for different upstream hosts retargeted to the same `(127.0.0.1, auth, tls=False)` share one keep-alive connection. The auth proxy therefore routes **per request** off `X-Cogbox-Host`, never binds a connection to a service or a credential, and refuses a request whose host is not a configured entry — so a pooled connection cannot smuggle one service's request under another's session.

### The reserved-header channel

The addon strips **every** `X-Cogbox-*` request header unconditionally, on every flow, allowed or denied, migrated or not — at the same point and for the same reason `strip_method_override` runs unconditionally. Only then may it author the three:

| header | value | consumer |
|---|---|---|
| `X-Cogbox-Host` | `pretty_host` captured before the retarget | the route key; must equal `Host`, else refuse |
| `X-Cogbox-Vetted` | l7proxy's pinned `ip:port`, captured before the retarget | the upstream socket target |
| `X-Cogbox-Proto` | the guest's original scheme | **audit only**; the upstream scheme comes from the conf |

The auth proxy refuses a request carrying zero or more than one of any of these, whose `Host` differs from `X-Cogbox-Host`, or whose `X-Cogbox-Vetted` is not a bare IP literal + non-zero port. A request with **no** `Host` (HTTP/1.0) on a migrated host is refused: `pretty_host` would have fallen back to the retargeted `.data.host`.

## The plugin contract

One plugin per service, registered by the `plugin` string in the policy document. Selection is exact match; an unknown value drops the entry at load with a loud line and refuses the host (fail closed). The interface (see `zig/src/authproxy/plugin.zig`):

- `compile(entry) → Policy` — once per conf generation, on that generation's arena. **Must fail** on anything it does not fully understand (unknown cap, missing required field); the core then drops the entry and refuses the host. No I/O.
- `classify(req) → ?Route` — gate 1, routing. Pure. `null` denies (`no route`). A `Route` carries a stable audit id, a layer, a method class, typed params, and `stream`.
- `authorize(route, req) → Decision` — gate 2. Pure, over the compiled policy only — never the raw grant rows, never a live lookup in v1.
- `upstream(route, req) → Upstream` — the upstream request, **constructed** from the route's typed params and the route's query allowlist, never copied from the request. The **core** then refuses any `Upstream` whose host is not in `entry.hosts` — a gate the plugin cannot bypass.
- `authenticate(route, req, cred) → headers` — headers to **set** (never append). `cred.token()` reads the store file lazily and fails closed (403) when unreadable.
- `mediate(route, req, cred, io) → ?Response` *(optional)* — the inline data-plane case (harbor's token dance). Drives the exchange through the core's client, which enforces the host allowlist, timeouts, in-flight cap and header allowlist on every leg.
- `onUpstreamStatus(route, status, headers, cred)` *(optional)* — derived-token invalidation (drop a minted token on 401).

`Request` is the core's canonical value object and the only view a plugin gets: `method`, `segments` (segment-first, single-decoded — a segment may contain `/`), parsed `query`, allowlisted `headers`, `content_type`, a bounded `body`, `host` (from `X-Cogbox-Host`), and `raw_target` **for audit only** — a plugin that reads `raw_target` for a decision is a review finding.

`mediate` and `onUpstreamStatus` are genuinely absent (null) for gitlab; they exist in v1 so harbor slots in with no interface change.

## The gitlab plugin (v1)

Typed route table, first match wins, unmatched ⇒ gate-1 deny. Exactly parity's surface plus one addition (the archive route):

| route id | methods | shape |
|---|---|---|
| `git-refs` | GET | `<project-ref>[.git]/info/refs`, required `?service ∈ {git-upload-pack, git-receive-pack}` — the **only** route that consults `service`, and the only place one exists |
| `git-upload` | POST | `<project-ref>[.git]/git-upload-pack` |
| `git-receive` | POST | `<project-ref>[.git]/git-receive-pack` |
| `api-user` | GET, HEAD | `/api/v4/user` |
| `api-version` | GET, HEAD | `/api/v4/version` |
| `api-project` | GET, HEAD | `/api/v4/projects/:id` — `simple=true` **forced** |
| `api-group-projects` | GET, HEAD | `/api/v4/groups/<group-path>/projects` — `simple=true` + `include_subgroups=true` **forced** — v1.1 addition |
| `api-issues` | GET, HEAD, POST, PUT | `/api/v4/projects/:id/issues[/…]` |
| `api-mr` | GET, HEAD, POST, PUT | `/api/v4/projects/:id/merge_requests[/…]` |
| `api-archive` | GET, HEAD | `/api/v4/projects/:id/repository/archive[.<ext>]` — v1 addition |

`:id` is accepted in **both** forms: a numeric id (`^[0-9]{1,19}$`, ASCII digits only, no sign, no leading zero, compared as i64) or a single segment whose decoded value is a project path. A **group path** for `api-group-projects` is a single decoded segment whose value is a well-formed group path — unlike a project id a single top-level component (`acme`) is well-formed, because a group need not be namespaced; a numeric group form is recognized but always scope-denied (the policy document carries no group id). Archive extensions are a **closed set** (`tar.gz`, `tar.bz2`, `tar`, `tar.zst`, `zip`), never a wildcard suffix.

The two read routes **force `simple=true`** because response bodies stream unfiltered (the plugin never sees them) and only the *non-simple* project/group representation carries `runners_token` and other secret fields — `simple=true` is the single place that leak is closed, and a client `simple=false` can never override it. This also closes the previously-documented `runners_token` residual on `api-project` (it is now unconditional). `api-group-projects` additionally forces `include_subgroups=true` and drops every query key but a small pagination/search allowlist (`per_page`, `page`, `page_token`, `search`); `issues`/`mr` keep the raw pass-through.

Everything else — `access_tokens`, `variables`, `deploy_keys`, every *other* `groups` tail **and the group node itself** (`/api/v4/groups/:id`), `/-/**`, `/uploads`, `/assets`, `raw`, registries, `/oauth/**`, `/admin`, `info/lfs/**`, `gitlab-lfs/**`, `git-upload-archive` — routes **nowhere** (a *named* 403), and `DELETE` is in no capability's method set.

Capability → route:

| cap | routes |
|---|---|
| `git-read` | `git-refs` (`service=git-upload-pack`), `git-upload`, `api-archive`, `api-group-projects`, `api-project`, the ambient two |
| `git-write` | `git-refs` (`service=git-receive-pack`), `git-receive` |
| `issues` | the ambient two (`api-user`/`api-version`) + `api-project` + `api-issues` |
| `mr` | the ambient two + `api-project` + `api-mr` |

The **"read = discover + inspect"** decision: a `git-read` grant no longer means clone-without-discovery. It reaches the ambient two, inspects concrete project metadata (`api-project`), and — for a **namespace-scope** grant only — enumerates its group's projects (`api-group-projects`). Discovery is what makes a namespace read grant usable; without it the agent could clone a *known* repo but had no way to *list* the names.

Only `api-user` and `api-version` are **ambient** (allowed by any `issues`/`mr`/`git-read` grant with no scope test — they name no project). `api-project` names one, and `api-group-projects` names a namespace: both take the scope test like every other `:id` route. An ambient project lookup would let any grant use the owner's token as an enumeration oracle over every project it can see; an ambient group listing would hand out instance-wide enumeration.

Scope tests reuse the existing predicates' semantics: `project` ⇒ the project ref equals the normalized `repo`, or the numeric id equals `project_id`; `namespace` ⇒ the path form is under the **slash-terminated** `prefix` (so `grp-secret` stays excluded), or the numeric id is in `projects[]`; `instance` ⇒ any well-formed project reference. **`api-group-projects` has its own scope test**: **namespace-scope grants only** (a concrete or instance grant never authorizes it — preserving the no-instance-wide-enumeration-oracle property), the group path **equal-to or under** the slash-terminated `prefix` (equals-or-under, not strictly-under, so the grant lists its *own* group node as well as any subgroup, while a sibling, the parent and `grp-secret` still fail), and **path form only** (a numeric group fails closed). `authenticate` returns `Authorization: Basic base64(git_user:token)` on the three git routes and `Authorization: Bearer <token>` on the API routes — byte-identical to the addon's git-vs-API split, so upstream behaviour does not change.

## The policy document

Delivered by `cogbox l7 policy --from-stdin` into `.network.l7.authpolicy` inside `config.json`. It is a **compiled artifact, not a mirror of the grant table**: inert grants are already dropped, suspension already applied, unresolved API caps already withheld, the `COGWORX_GIT_ALLOW_ALL` kill switch already applied by omission. **Route knowledge never appears in it** — no path prefixes, no method lists, no `service=`, no wildcards. Semantic tuples only; the routes are the plugin's table.

```json
{ "version": 1, "providers": [
  { "provider": "GitLab", "plugin": "gitlab", "hosts": ["git.example.com"],
    "secret": "git-gitlab", "git_user": "oauth2", "scheme": "https",
    "grants": [
      { "id": "gg-…", "scope": "project", "repo": "grp/proj", "project_id": "1234",
        "caps": ["git-read", "git-write", "issues"] },
      { "id": "gg-…", "scope": "namespace", "repo": "grp/sub/*", "prefix": "/grp/sub/",
        "caps": ["git-read", "issues", "mr"],
        "projects": [ {"id": 42, "path": "grp/sub/a"} ] },
      { "id": "gg-…", "scope": "instance", "caps": ["git-read", "mr"] } ] } ] }
```

`caps` is exactly four values — `git-read`, `git-write`, `issues`, `mr` — and the plugin fails closed on anything else. `scheme` comes from the provider's token URL (never hardcode https — a live http-only host exists). The verb refuses a malformed document or an unknown `version` **before** writing anything, refuses a document over 64 KiB, and **accepts** the empty document `{"version":1,"providers":[]}` (share teardown pushes it to withdraw a policy). Canonical rendering (sorted keys, providers by name, grants by id, `projects[]` id-ascending, no insignificant whitespace) is what keeps an unchanged policy skippable tick after tick; the control-plane fingerprint hashes those bytes.

## The three gates (enforcer side)

`renderAuthProxyConf` walks the bound secrets and emits an `l7-auth-conf.json` element only when **all three** hold:

1. the resolved secret is **bound**, its kind is `gitlab-authproxy`, and its `audience` is set;
2. `.network.l7.authpolicy` (version 1) carries a provider entry whose `hosts[]` include that audience;
3. an L7 rule **names** the audience (the funnel rule).

Gate 3 is the mirror of the addon's fail-closed inject gate: it covers the window before the funnel lands and a control plane that withdrew the rules but left the bind (no rule → no element → 403s). A stale document after a mode **flip-back** is neutralised by gate 1, not gate 3: the flip-back re-applies the legacy rules (which do name the host) and re-binds under the legacy kind, so the kind check is what makes that document **dead text**. The emitted element carries `host`, `plugin`, `scheme`, `insecure`, `cred_file`, `cred_format`, `git_user` and the doc's `grants[]` verbatim. `cred_file` is the store's value path, noted into the credential-grant transaction at the statement that writes it, so what the auth proxy may read and what the conf names it can never diverge. `insecure` is single-sourced from the same rule scan the addon's upstream-verification toggle uses.

## Version gate and skew

A migrated provider's token is bound under kind `gitlab-authproxy`. Two independent refusals, both enforced by the **old** binary, make a mixed fleet safe:

| gate | old-binary answer | consequence |
|---|---|---|
| the verb `cogbox l7 policy` | exit 64, stderr exactly `cogbox l7: error: UnknownSubcommand` | classified → the instance falls back to the **unchanged** legacy per-grant rules this pass |
| the kind `--kind gitlab-authproxy` | exit 65 (`validKind` refuses it) | the bind fails by the old binary's own hand — no credential exists, no control-plane bookkeeping |

The kind does double duty: it is the version gate **and** the inject suppressor. The addon's inject-spec seeding keys on `gitlab-oauth`, so a token bound under the new kind is never seeded as an inject spec → no inject → the addon cannot double-stamp a host the auth proxy authenticates. The catastrophic skew this avoids: a whole-host tagged allow plus a still-bound `gitlab-oauth` secret would inject the owner token on every path. Sequencing is document → funnel → token, bound under the new kind; the addon additionally skips its injection block unconditionally for any host in `l7-auth-hosts`, and logs once per host per conf generation if both a spec and an auth entry exist (a control-plane bug).

Every skew fails closed: an old cogbox + new control plane falls back byte-identically; a buggy control plane that withdrew the rules but left the bind is saved by gate 3 (no rule names the host → no element → 403s, not owner-token-on-every-path); a new cogbox + old control plane has no document → the auth proxy refuses every host.

## Hardening

Enforced once in the core, so the escape classes close for all plugins:

- **Caller identity is structural, never claimed.** Which sandbox is calling is answered by *which* auth proxy the request reached — one process per sandbox, on a loopback port fenced from the guest. No instance-id header, query parameter or path segment exists anywhere in the design.
- **No request-derived upstream.** `scheme` and `Host` come only from the conf entry; the socket target only from `X-Cogbox-Vetted` (l7proxy's vetted, pinned IP — the auth proxy never re-resolves). The core refuses any plugin-returned upstream whose host is not in `entry.hosts`. This is the entire SSRF control on this leg; the provider is on RFC1918, so private-range refusal is not available as a second line.
- **No redirect following.** A 3xx is returned to the guest verbatim; following one is how a config-only host becomes a request-derived host.
- **Inbound header allowlist, not a denylist.** `Authorization`, `Private-Token`, `Cookie`, hop-by-hop headers and every `X-Cogbox-*` are dropped; `X-Forwarded-For` is never synthesized. Operational consequence, because the addon retargets **every** allowed flow for a host in `l7-auth-hosts`: while a grant is active for a host, the grant's policy governs all of that host's traffic from the guest — a credential the guest holds itself (a netrc, a PAT in a header) and a credential another plugin's inject spec would have stamped are both superseded, not merged. They apply again only once no grant names the host.
- **Responses:** stream status + body; strip `Set-Cookie` (an owner session cookie would be a credential escape) and all hop-by-hop headers; bodies are never filtered. An upstream **1xx is never relayed** (502 to the guest — the final response this client never reads is dropped with the connection). A **bodyless** response (a HEAD response, 204, 304) is relayed head-only with the origin's `Content-Length` as a plain header — except on a 204, where RFC 9110 §8.6 forbids one, so a non-conforming origin's `Content-Length: 0` is dropped rather than relayed a hop further — and the connection closed after it; never through a content-length framed body writer, which would assert on the unwritten length. A content-length body the origin cuts short is relayed as far as it came and the connection is then cut, so the guest sees the truncation instead of a clean terminator. An origin head the relay cannot carry **whole** refuses the exchange — a 502 to the guest with `reason=BadResponseHeader` on the audit line, never a partial relay: a header name or value carrying CR, LF, NUL, another C0 byte (HTAB excepted) or DEL (std's response parser never inspects header bytes, and a bare LF would reach the guest as a header-splitting sequence — the response-side mirror of the request emitter's guard), a duplicated **singleton** (`Content-Length`, `Content-Type`, `Location` — std keeps one copy silently), or more forwardable headers than the relay's 64-slot set holds. Multi-valued headers (`Vary`, `WWW-Authenticate`, `Link`) are relayed copy for copy.
- **Framing** (HTTP/1.1 only): refuse h2/h2c, `CONNECT`, absolute-form with authority ≠ Host, asterisk-form, authority-form, HTTP/1.0 without Host, `Content-Length` together with `Transfer-Encoding`, duplicate `Content-Length`, duplicate `Host`, **a duplicate of any forwarded header** (the forwarded set keeps one value per name while a policy check might read the other copy — a `Content-Type: json` then `Content-Type: x-www-form-urlencoded` pair would pass the 415 gate and hand the origin the form body), any control byte in the request line (a lone CR survives a bare-LF scan), obs-fold headers, bare-LF line endings, trailers on a chunked body (refused once the body has ended: a 400, the connection closed). Every framing refusal closes the connection. A head over the 16 KiB bound is a 431 whichever guard sees it first (the standard library's head bound on a trickled head, the core's copy guard on one that arrived in a single fill). An `Expect: 100-continue` on a request with **no** body is ignored (RFC 9110 §10.1.1) — and cleared before the body reader is taken, because the standard library asserts on a still-set expectation there; a duplicated `Expect` is exactly what mitmproxy folds, does not answer, and forwards, so the bare form reaches the auth proxy in the field. Any other expectation is a 417.
- **The constructed head is guarded at the emitter, too.** Every line of the upstream head is printed verbatim, so the one byte source framing never saw — the credential — is checked where it is read: a store value carrying any control byte (an interior CR/LF the trailing trim cannot reach, which `Bearer <value>` would splice raw into an `Authorization` line under the owner's identity) is refused as `credential unavailable` (403), never emitted. The conf `host` must be a plain DNS name (it becomes the `Host:` line and the SNI). Under both, the emitter refuses any header name that is not a token, any value or host with a control byte, and any control byte or space in the rebuilt path/query, **before** dialing (502, reason `BadHeader`) — the belt that also covers a plugin's or a mediate leg's own headers.
- **Canonicalization, fail-closed at every step:** split the target at the first `?` and parse the query separately; split the path on `/` **first**, then percent-decode each segment exactly once (so `grp%2Fproj` stays *one* segment whose value contains `/` — the segment positions stay stable and an encoded slash becomes a typed fact rather than structural inflation); refuse an invalid `%`-escape, a C0/C1 byte, a `.`/`..` segment, an over-long segment or too many segments; no second decode pass, ever. Query **values** are re-emitted raw on pass-through routes, so they are validated by the same byte rules (a raw or `%`-decoded control byte, an invalid escape, invalid UTF-8 → refused): a CR in a value would be header injection on the constructed upstream request line.
- **Streaming, no buffering** on pack/archive/blob routes — a multi-GB clone must not buffer. Timeouts: 10 s for the request head, 10 s upstream connect, 30 s for the upstream response head, and a 60 s **idle** bound on both sockets for the body relay **in either direction** — the request body (a `git push` pack, which the addon streams) moves both sockets to the idle bound before the upload and the upstream socket back to the 30 s head bound for the head wait once it is out; the response body moves both to the idle bound again once the head is in. API routes additionally carry a 60 s **total** relay deadline that starts ahead of the request-body upload and spans both directions, checked between 64 KiB slices: an upload still trickling past it is refused with a 408 (no response head is out yet, and the connection closes), a response still streaming past it is cut mid-body. Stream routes (pack, archive) carry none.
- **Audit: one line per request, metadata only** — the matched **route id**, never the raw path; coarse reasons from a fixed enum, never free text; never a credential byte, a header value or a body byte; `bytes_in`/`bytes_out`/`dur_ms` measured. A raw path is logged only behind `COGBOX_L7_AUTH_DEBUG_PATH=1`, quoted and length-capped, with query values dropped except `service`. The counters rollup (`authproxy stats …`) is emitted on the accept-loop tick at most once a minute, and only when the request counter moved.
- **A coarse deny reason to the guest: `X-Cogbox-Deny`.** Every deny carries a response header `X-Cogbox-Deny: <reason>` whose value is the *same* fixed enum the audit line records (`no_route`, `no_grant`, `cap_missing`, `scope_mismatch`, `method_not_allowed`, `service_invalid`, and the pre-plugin framing/`no-policy`/`forbidden-query`/`overloaded`/… reasons). It is a fixed vocabulary — **never free text, never a secret, never a tenant-supplied byte** — added only to the empty-body deny response; the body, the `keep_alive=false` close and the framing-ambiguity posture are untouched. It exists so the in-sandbox agent (and grant-check clients) can tell a *scoped* denial under a live grant (`scope_mismatch`/`cap_missing`) apart from "no grant at all" (`no_grant`/`no-policy`), instead of reading a bare empty-body 403 as "no access."
- **Custody:** the owner credential lives in memory for the duration of one upstream request, sourced from the enforcer-private store, never written anywhere, never in a log or an error string. Every buffer it passes through — the plugin's token copy, the header set that carries it to the origin, the connection buffers it is serialized through — lives in ONE per-request heap block (`RequestScratch`) scrubbed by one call on every exit path, and that scrub is pinned by an end-to-end test that serves a request through a retaining allocator and scans the retired block for the token in both its raw and base64 forms. A buffer that carries the credential and does not live in that block is a custody bug by construction.

### TLS limitations (OSS generality)

The current deployment's provider is plain HTTP, so none of these affects it, but an OSS user can hit them (documented rather than hidden). The upstream TLS client is `std.crypto.tls.Client`, which supports **TLS 1.3 and 1.2 only** and:

1. **No ALPN** anywhere in the standard library — the auth proxy speaks HTTP/1.1, so an origin that requires ALPN to negotiate HTTP/1.1 is unreachable.
2. **No TLS-1.2 ECDSA** — a TLS-1.2-only origin with an ECDSA leaf is unreachable (TLS 1.3 with ECDSA is fine).
3. **No session resumption, no client certificates, no renegotiation.**

**CA trust is resolved explicitly** rather than relying on the standard library's fixed probe list (which ignores `SSL_CERT_FILE` and, on the enforcer image's `pkgs.cacert` layout, only works by accident via the directory arm). The auth proxy honours `SSL_CERT_FILE` if set (via `addCertsFromFilePathAbsolute`), else falls back to the library's `rescan`, and **refuses an `https` upstream leg on an empty trust bundle** with a named 502 — silently trusting nothing (opaque handshake failures) or, worse, a future permissive-on-empty change, are both worse than an explicit refusal. A rule marked `--insecure-upstream` carries `insecure: true` into the conf and skips verification on that host's leg, exactly as it did under mitmproxy.

## Failure modes — every one fail-closed

| failure | behaviour |
|---|---|
| auth proxy never started / dead | mitmproxy's retarget connect fails → an error to the guest; no credential, no upstream |
| `l7-auth-conf.json` missing / malformed / unknown version | reader falls to an empty entry set → every host refused with `no policy` |
| torn render, hosts ahead of conf | addon retargets, auth proxy has no entry → 403 |
| torn render, conf ahead of hosts | addon does not retarget → anonymous → the provider 401s |
| cred file unreadable (EACCES / unbound / revoked) | 403 `credential unavailable` — never forward the guest's stub as auth |
| cred file value carries a control byte (an interior CR/LF) | 403 `credential unavailable` — never spliced into the `Authorization` line; not cached |
| a stale `gitlab-oauth` bind on a migrated host | the addon skips its injection block unconditionally for any host in `l7-auth-hosts`, so no double-stamp |

## Supervision and lifecycle

- **VM path** (`cogbox-launch.sh`): `start_l7auth` runs between `start_l7mitm` and `start_l7proxy` under the same `COGBOX_PROXY_RUNAS` uid:gid as the other proxies. Its liveness check **warns and continues** (never `die`) — its absence breaks only migrated hosts, fail-closed. `L7AUTH_PID` is torn down by `cogbox_cleanup`. There is no crash-supervision on this path (as for mitmdump and l7proxy today); a dead auth proxy there stays dead until the sandbox restarts.
- **Container path** (`cogbox-enforce.sh`): `start_l7auth` runs between `publish_ca` and `start_l7proxy`, and gets its own arm in the `wait -n` restart loop and its own `terminate()` kill — the correctness obligation, because otherwise the enforcer would silently run without the auth proxy after one crash and every migrated provider would fail closed with no self-heal.
- **Health, v1: a pid file only** (`<runtime>/authproxy.pid`), whose contents are written by the auth proxy **itself**, once, only after its listener has bound **and** its first conf parse has succeeded (a failed first parse leaves it empty/absent until a later poll parses one). **Healthy means the file exists AND is non-empty (`test -s`), never mere existence**: the VM launcher pre-creates it *empty*, owned by the `COGBOX_PROXY_RUNAS` uid, because under that uid the auth proxy cannot create anything in the root-owned runtime dir on GCE (only `l7-ca` is handed to that uid), while truncate-writing into an existing owned file needs no directory permission; the enforcer path (no runas) pre-creates it too, un-chowned, so both paths share one contract and a supervised restart truncates the dead child's stale pid away rather than leaving it to be read as live. Neither launch script ever writes a pid into it — a pid taken from `$!` would name a process that may already have died on a bind failure, exactly what the file exists to rule out; the VM launcher's warn branch removes the file. The auth proxy logs the two failure causes separately and once each: a withheld file names the failed conf parse, a failed write names the write error (never the other way round). No `readinessProbe` change — adding one would strand every old enforcer pod NotReady and has no enforcer-image freshness gate.
- **Reload is mtime polling, not SIGHUP** — zero changes to the reload paths, and a missed signal cannot leave stale policy. Both readers re-stat `(mtime, size)` after reading (a non-atomic truncate-then-rewrite of the same length within one tick moves neither mtime nor ctime but moves size), never cache a failed parse, and fall to the empty set.

## Verifying a build before it ships

`zig build test` covers the canonicalizer, the route engine, the framing pre-parse and an in-memory end-to-end (a fake client and a fake upstream behind the transport seam) — but none of that runs the **process** on the real clock. An early build passed 506 tests and died on its first accept-loop tick: `Store.maybePoll` subtracted `now_ms - last` before testing that `last` was still the `minInt(i64)` startup sentinel, an i64 overflow no in-memory test reached because every test drove `poll()` directly. Fail-closed held (every request 502, nothing reached the origin), but every migrated provider was dead on every launch. The accept tick is now factored into `tickOnce` with a test that runs the real first tick against a fresh store, and the gate for this component additionally includes running the binary once, locally, on the real clock:

```sh
cd zig && zig build
rt=$(mktemp -d); echo '{"version":1,"providers":[]}' > "$rt/l7-auth-conf.json"; : > "$rt/authproxy.pid"
timeout 12 ./zig-out/bin/cogbox __authproxy "$rt" 18443 &   # listens on 127.0.0.1:18043
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: x' http://127.0.0.1:18043/api/v4/version           # 400 (reserved_header)
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: git.example.com' -H 'X-Cogbox-Host: git.example.com' \
     -H 'X-Cogbox-Vetted: 192.0.2.10:80' http://127.0.0.1:18043/api/v4/version                        # 403 (no-policy)
wait; test -s "$rt/authproxy.pid"                           # pid written; the log must show no `panic`
```

The process must survive the whole window (its exit is the `timeout`'s 124, never a trap), the pid file must be non-empty, and both probes must be refused with the audit line's fixed reason — a machine that boots the proxy for ten seconds catches the class of bug the suite structurally cannot.

## Known residuals

Found on the first live run and deliberately not fixed in v1; none is an authorization gap.

- A request carrying a forbidden query key (`private_token`, `access_token`, `job_token`, `_method`) is refused with **400**, not the 403 the design text predicts. Denied and never forwarded either way; the status code is the only difference.
- A path carrying a literal `..` component (`/api/v4/projects/1/access_tokens/..%2Fissues` and the like) never reaches the auth proxy: l7proxy's request-line classifier rejects it one layer earlier (`reason=unclassifiable-or-no-sni`) with a bare connection close. Fail-closed and nothing reaches the origin — but there is **no `authproxy request` audit line** for such a request, so the auth proxy's audit trail alone under-counts these attempts; correlate with l7proxy's `reject` lines.
- An auth proxy killed from outside (a signal, an OOM) leaves its non-empty `authproxy.pid` in place: on the VM path nothing supervises it, so `test -s authproxy.pid` reads as healthy over a dead process until the sandbox restarts. `test -s` is a *started-and-parsed* signal, not liveness; a liveness probe needs `kill -0` on the recorded pid.

## Deliberately deferred

- No live project-identity resolution in v1 — the namespace snapshot stays the numeric-form authorizer; path-form addressing is *better* than today with no resolver.
- **Namespace enumeration is path-form and namespace-scope only.** A numeric group id (`/api/v4/groups/<n>/projects`) fails closed — the policy document ships no group id to verify it against — and enumeration is *not* offered under an `instance` (`*`) scope grant, which keeps the no-instance-wide-enumeration-oracle property. A numeric group form would need the control plane to ship a group id.
- The `*`-scope read **narrows** to the routed read set (deny-by-default over-blocking rather than over-allowing); the route table becomes a versioned artifact needing a per-provider-release review.
- The `gitNSProjectCap = 20` cap is kept although its stated derivation no longer applies.
- forgejo and harbor plugins, finer capabilities-as-data, a pooled upstream connection, and an `authproxy-strict` delivery mode that publishes `restart-required` instead of falling back — all v2.
