# The per-sandbox auth proxy

A dedicated per-sandbox process, in the sandbox's trusted half, **inline on the data path**, that classifies and authorizes each request to a *migrated* provider against a typed route table and stamps the owner's credential itself. It is **pluggable per service** — gitlab is plugin #1; forgejo and harbor (whose docker-registry token dance *requires* inline mediation) slot in later without interface changes.

This document is the design and the operator reference. For where it sits in the egress chain and the wire-file/verb summary, see [network-filtering.md](network-filtering.md#the-per-sandbox-auth-proxy).

## Why it exists

The git integration used to compile per-user grants into generic L7 path-prefix rules shipped into each sandbox's enforcer. That whitelist paradigm has three structural problems the auth proxy replaces for a migrated provider:

- **Path-prefix escapes.** The enforcer decides on a *decoded, flattened* path and forwards a *different* (raw) one, matched left-anchored only. An encoded slash inflates one addressed segment into several, so an `allow …/projects/*/issues` rule is escaped by `…/projects/mygroup%2Fissues/access_tokens` — the tail lands on the id's own last component and absorbs the mint endpoint. The concrete resolved-id tier (`…/projects/1234/issues`) has the same escape with *no wildcard at all*, which is the one an auditor misses. The vector table pins six such live rows; under the auth proxy they all flip to **deny**.
- **Dual-matcher coupling.** Two independent matchers (the Zig proxy and the mitmproxy addon) had to agree byte-for-byte on one path language, kept in step only by a shared oracle. The auth proxy has its own typed engine with its own oracle (`zig/src/authproxy/route_vectors.tsv`); the shared table stays for the *generic* L7 language (network-tab rules, plugins, templates), which does not move.
- **Language-capped capability granularity.** With no mid-path wildcard, an `mr` capability necessarily includes self-`/approve` and self-`/merge`. A typed route table makes finer capabilities expressible — **shipped in v2**: twelve caps instead of four, `mr:merge` split out of `mr:write`, and four API areas (pipelines, jobs, the repository read API, wikis) that the rule language could not reach at all.

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
- `mediate(route, req, cred, io) → bool` *(optional)* — the inline data-plane case: the only hook that sees the request **body**. It drives its exchange through the core's client, which enforces the host allowlist, timeouts, in-flight cap and header allowlist on every leg. Returning `false` falls back to the default single round trip **with the body reader untouched**; returning `true` hands back either an open exchange or a `deny` — a refusal reached over the body, **before any dial** (gate 3). gitlab uses it for push rules (below); the harbor token dance is its other intended shape.
- `onUpstreamStatus(route, status, headers, cred)` *(optional)* — derived-token invalidation (drop a minted token on 401).

`Request` is the core's canonical value object and the only view a plugin gets: `method`, `segments` (segment-first, single-decoded — a segment may contain `/`), parsed `query`, allowlisted `headers`, `content_type`, a bounded `body`, `host` (from `X-Cogbox-Host`), and `raw_target` **for audit only** — a plugin that reads `raw_target` for a decision is a review finding.

`onUpstreamStatus` is genuinely absent (null) for gitlab — the owner token is refreshed only by the control plane, so there is no derived token to invalidate. `mediate` is present for exactly one route (push rules, below) and answers `false` for every other, so the interface's "absent, not a no-op" discipline still reads off the vtable.

## The gitlab plugin (v2)

Typed route table, first match wins, unmatched ⇒ gate-1 deny. Parity's surface plus the archive route, the namespace-enumeration route, and the v2 additions (the merge-class split and four new API areas):

| route id | methods | shape |
|---|---|---|
| `git-refs` | GET | `<project-ref>[.git]/info/refs`, required `?service ∈ {git-upload-pack, git-receive-pack}` — the **only** route that consults `service`, and the only place one exists |
| `git-upload` | POST | `<project-ref>[.git]/git-upload-pack` |
| `git-receive` | POST | `<project-ref>[.git]/git-receive-pack` — the one **mediated** route: under a grant carrying `push` rules its command section is read and matched before any dial (see [Branch rules on push](#branch-rules-on-push-the-mediate-hook)) |
| `api-user` | GET, HEAD | `/api/v4/user` |
| `api-version` | GET, HEAD | `/api/v4/version` |
| `api-project` | GET, HEAD | `/api/v4/projects/:id` — response **projected** to the ProjectSimpleEntity allowlist (see Responses under Hardening); `simple=true` forced but **inert** on a single-project GET |
| `api-group-projects` | GET, HEAD | `/api/v4/groups/<group-path>/projects` — `simple=true` + `include_subgroups=true` **forced** — v1.1 addition |
| `api-issues` | GET, HEAD, POST, PUT | `/api/v4/projects/:id/issues[/…]` |
| `api-mr` | GET, HEAD, POST, PUT | `/api/v4/projects/:id/merge_requests[/…]` — everything **not** in the merge class |
| `api-mr-merge` | GET, HEAD, POST, PUT | `.../merge_requests/<iid>/<tail>[/…]`, tail ∈ {`merge`, `approve`, `unapprove`, `approvals`, `approval_rules`, `reset_approvals`, `rebase`, `cancel_merge_when_pipeline_succeeds`} — v2 addition |
| `api-pipelines` | GET, HEAD; POST only at `<id>/{retry,cancel}` | `.../pipelines[/…]` — `.../pipelines/<id>/variables` is a **named `no_route`** — v2 addition |
| `api-pipeline-trigger` | POST | `.../pipeline` (a leaf, no subtree) — v2 addition |
| `api-jobs` | GET, HEAD; POST only at `<id>/{retry,cancel,play}` | `.../jobs[/…]` (`trace`, `artifacts`); `erase` is **not** in the write set — v2 addition |
| `api-repo` | GET, HEAD | `.../repository/<collection>[/…]`, collection ∈ {`tree`, `branches`, `commits`, `compare`, `tags`, `blobs`, `files`, `contributors`, `merge_base`, `changelog`} — v2 addition |
| `api-wiki` | GET, HEAD, POST, PUT | `.../wikis[/…]`, `/wikis/attachments` included — v2 addition |
| `api-archive` | GET, HEAD | `/api/v4/projects/:id/repository/archive[.<ext>]` — v1 addition |
| `cogbox-grants` | GET, HEAD | `/_cogbox/grants` — **plugin-owned LOCAL route**, matched **before** the table above and answered locally (never proxied); see [Self-discovery](#self-discovery-_cogboxgrants) |

Three invariants the table encodes, each pinned by `route_vectors.tsv`:

1. **`DELETE` is in no capability's method set, on any route.** It is irreversible and nothing in the headline flows needs it; a future `*:delete` cap is the extension point.
2. **Repository writes through the API are unroutable.** `api-repo` is clamped to GET/HEAD, so `POST /repository/commits`, `POST|PUT /repository/files/*` and the branch/tag write endpoints are refused with `method_not_allowed` however wide the grant — a `git-write` one included. They would otherwise write a branch without passing through receive-pack, i.e. straight past the per-grant push rules; repository mutation goes through `git push`, where those rules live.
3. **`/pipelines/:id/variables` is a named `no_route`, not a method clamp** — a pipeline's variables are secrets a `pipelines:read` grant must not read, so a GET must find no route at all rather than an admitted method.

**API writes carry JSON bodies only.** The allowed write routes — `api-issues`, `api-mr`, `api-mr-merge`, `api-wiki` and the pipeline/job actions — take `Content-Type: application/json`; a `POST`/`PUT` whose type is `application/x-www-form-urlencoded` is refused **415** in the core *before* the route is even matched, however wide the grant, and a body-bearing method that declares neither `Content-Length` nor chunked framing is refused **411** in the pre-parse. Both are pre-plugin refusals that say nothing about capabilities — read `X-Cogbox-Deny` rather than the status code (see the deny vocabulary under Hardening).

The merge class splits off `api-mr` **by its tail, not its depth**: any path whose second tail component is a merge-class name is `api-mr-merge`, deeper ones included, so a sub-resource of `/approvals` is an approvals write too (fail closed). Reading the merge class (`GET /approvals`, the merge status) is ordinary `mr:read`; only the act of approving/merging/rebasing needs `mr:merge`. `approval_rules` sits in the class for the same reason `approvals` does — it is GitLab's current API for the *same* protection, so leaving it in `api-mr` would let a deliberately merge-less `mr:read + mr:write` grant set `approvals_required: 0` and relax the requirement `mr:merge` exists to hold. Two endpoints for one protection belong to one class.

`:id` is accepted in **both** forms: a numeric id (`^[0-9]{1,19}$`, ASCII digits only, no sign, no leading zero, compared as i64) or a single segment whose decoded value is a project path. A **group path** for `api-group-projects` is a single decoded segment whose value is a well-formed group path — unlike a project id a single top-level component (`acme`) is well-formed, because a group need not be namespaced; a numeric group form is recognized but always scope-denied (the policy document carries no group id). Archive extensions are a **closed set** (`tar.gz`, `tar.bz2`, `tar`, `tar.zst`, `zip`), never a wildcard suffix.

Both read routes **force `simple=true`**, but it does different work on each. On **`api-group-projects`** (a LIST) GitLab honours `simple`, so `simple=true` is what strips `runners_token` and the other secret fields from every listed project, and a client `simple=false` can never override it. On **`api-project`** (a single-project GET) GitLab does **not** honour `simple` — a single-project GET returns the full object regardless — so `simple=true` is **inert** for the leak there and kept only as belt-and-braces; the `runners_token` (and `import_url`/`permissions`/`_links`/CI-registry) leak on that route is closed proxy-side by a **response-body projection** (see Responses under Hardening), not by the query. `api-group-projects` additionally forces `include_subgroups=true` and drops every query key but a small pagination/search allowlist (`per_page`, `page`, `page_token`, `search`); `issues`/`mr` keep the raw pass-through.

Everything else — the instance-wide project LIST (`/api/v4/projects` with no id, `?membership=true` included; `api-group-projects` is the only enumeration this proxy offers), `access_tokens`, `variables` (the CI/CD kind **and** `/pipelines/:id/variables`), `deploy_keys`, every *other* `groups` tail **and the group node itself** (`/api/v4/groups/:id`), `/-/**`, `/uploads`, `/assets`, `raw`, registries, `/oauth/**`, `/admin`, `info/lfs/**`, `gitlab-lfs/**`, `git-upload-archive`, GraphQL, snippets, packages, the repository *write* endpoints and every group-level API — routes **nowhere** (a *named* 403).

Capability → route. The twelve are **orthogonal**: `issues:write` does not imply `issues:read`, `mr:merge` does not imply `mr:write`. The document is a compiled artifact whose meaning must be readable without an implication table three codebases could drift on, and the v1 narrowing is only well-defined with orthogonal caps; the control plane's UI auto-ticks the read half as a **client courtesy**, never enforced here.

| cap | routes (method half) |
|---|---|
| `git-read` | `git-refs` (`service=git-upload-pack`), `git-upload`, `api-archive`, `api-group-projects` |
| `git-write` | `git-refs` (`service=git-receive-pack`), `git-receive` — narrowed further by the grant's `push` rules, if it has any |
| `issues:read` / `issues:write` | `api-issues`, GET/HEAD / POST/PUT |
| `mr:read` / `mr:write` | `api-mr`, GET/HEAD / POST/PUT; `mr:read` also reads `api-mr-merge` |
| `mr:merge` | `api-mr-merge`, POST/PUT |
| `pipelines:read` / `pipelines:write` | `api-pipelines` and `api-jobs`, GET/HEAD / POST; `pipelines:write` alone reaches `api-pipeline-trigger` |
| `repo:read` | `api-repo`, and `api-archive` (the bulk form of the same read) |
| `wiki:read` / `wiki:write` | `api-wiki`, GET/HEAD / POST/PUT |
| *any capability* | the ambient two (`api-user`, `api-version`) + `api-project` (scope-tested) |

**The legacy dialect still expands.** A grant row the owner has not edited still ships `issues` / `mr`, and `compile` expands them — `issues` → `issues:read`+`issues:write`, `mr` → `mr:read`+`mr:write`+`mr:merge` (v1 `mr` *included* approve/merge) — the mirror of the control plane's `NormalizeGitCaps`. Anything else in `caps` still fails the **whole** conf, as it always has. `/_cogbox/grants` reflects the **expanded** v2 names, because the reflection states what this binary enforces rather than echoing the document.

The **"read = discover + inspect"** decision: a `git-read` grant no longer means clone-without-discovery. It reaches the ambient two, inspects concrete project metadata (`api-project`), and — for a **namespace-scope** grant only — enumerates its group's projects (`api-group-projects`). Discovery is what makes a namespace read grant usable; without it the agent could clone a *known* repo but had no way to *list* the names.

Only `api-user` and `api-version` are **ambient** (allowed by **any** capability, with no scope test — they name the owner's identity and the server version, nothing resource-scoped). `api-project` names one project, and `api-group-projects` names a namespace: both take the scope test like every other `:id` route. An ambient project lookup would let any grant use the owner's token as an enumeration oracle over every project it can see; an ambient group listing would hand out instance-wide enumeration.

**That row WIDENED on this roll, and it is by design.** Under v1 the ambient two and `api-project` hung off `git-read`, `issues` and `mr` specifically, so a `git-write`-only grant reached none of them; from this build every capability does, and grants nobody edited gain the owner's identity, the server version and one project's metadata the moment the enforcer image rolls. Three reasons it is the intended shape rather than an oversight. It is what makes the v2 caps usable at all: `pipelines:read`, `repo:read` and `wiki:read` all address a project and need to resolve it, and hanging their prerequisites off a *different* cap would put an implication table back into a vocabulary whose whole point is orthogonality. It is scope-bounded where it can be: `api-project` still takes the same scope test as any `:id` route, so a grant only inspects the project (or namespace) it already covers. And it is not a leak surface: the `api-project` response is projected through the ProjectSimpleEntity allowlist, so `runners_token` and friends never reach the guest whatever cap opened the route. The widest thing any grant gains here is the owner's own login and metadata for a project it could already act on.

Scope tests reuse the existing predicates' semantics: `project` ⇒ the project ref equals the normalized `repo`, or the numeric id equals `project_id`; `namespace` ⇒ the path form is under the **slash-terminated** `prefix` (so `grp-secret` stays excluded), or the numeric id is in `projects[]`; `instance` ⇒ any well-formed project reference. **`api-group-projects` has its own scope test**: **namespace-scope grants only** (a concrete or instance grant never authorizes it — preserving the no-instance-wide-enumeration-oracle property), the group path **equal-to or under** the slash-terminated `prefix` (equals-or-under, not strictly-under, so the grant lists its *own* group node as well as any subgroup, while a sibling, the parent and `grp-secret` still fail), and **path form only** (a numeric group fails closed). `authenticate` returns `Authorization: Basic base64(git_user:token)` on the three git routes and `Authorization: Bearer <token>` on the API routes — byte-identical to the addon's git-vs-API split, so upstream behaviour does not change.

### Self-discovery: `/_cogbox/grants`

An in-sandbox agent needs to answer *"what repos do I have access to"* without a human naming the group. The `cogbox-grants` route reflects **this sandbox's own grants** back to the guest, so the agent can discover its access from inside the box. It is a **plugin-owned local route**, not a GitLab surface:

- **Reserved first segment.** `classify` recognizes a `_cogbox` first segment **before any GitLab route/segment matching**, so it can never collide with — or fall through to — a real GitLab path. A real GitLab top-level group named `_cogbox` is implausible and is intentionally shadowed; any `_cogbox/**` path other than `/_cogbox/grants` is a named gate-1 deny.
- **Answered locally.** The route is marked `Route.local`; the core answers it from the plugin's `localResponse` hook — rendering the body **from the already-compiled in-memory policy** — with **no upstream round-trip and no credential use** (the deny path's local-answer idiom, a body instead of empty, and **no `X-Cogbox-Deny`** on the success path). `authorize` still runs the method clamp (**GET/HEAD only**; any other method is the same `method_not_allowed` deny the API tier gives), but `upstream`/`authenticate` never do.
- **Non-secret policy reflection.** The response is the sandbox's grants as the *policy shape only*, built from the same typed grants `authorize` enforces (zero drift). It **never** emits a token, a numeric project id (`project_id`/`projects[]` stay internal), or any upstream byte — only what the policy document already carries as non-secret prefixes and caps.

Response — `200`, `Content-Type: application/json` (an empty/ungranted sandbox is `{"grants":[]}`, still `200`):

```json
{ "grants": [
  { "scope": "namespace", "repo": "acme/iac/*", "prefix": "acme/iac", "caps": ["git-read"] },
  { "scope": "project",   "repo": "acme/app",   "caps": ["git-read", "issues:read", "issues:write"] },
  { "scope": "project",   "repo": "acme/svc",   "caps": ["git-read", "git-write"],
    "push_refs": ["refs/heads/agent/*"], "push_deny_delete": true, "push_deny_tags": true },
  { "scope": "instance",  "caps": ["git-read", "mr:read", "mr:write", "mr:merge"] } ] }
```

- `scope` is `namespace | project | instance`.
- `repo` is the grant's repo (the wildcard `grp/sub/*` on a namespace grant, the concrete `grp/proj` on a project grant); it is **omitted** on an `instance`-scope grant, which names no repo.
- `prefix` is the **path form** of a namespace grant's slash-terminated internal prefix (`"/grp/sub/"` → `"grp/sub"`, no leading/trailing slash); it appears on **namespace-scope grants only**.
- `caps` is the grant's capability subset, always in the **v2 vocabulary and canonical order** (`git-read`, `git-write`, `issues:read`, `issues:write`, `mr:read`, `mr:write`, `mr:merge`, `pipelines:read`, `pipelines:write`, `repo:read`, `wiki:read`, `wiki:write`) whatever dialect the document used — a v1 `mr` really is the mr triple here.
- The push rules ride as **flat** keys — `push_refs`, `push_deny_delete`, `push_deny_tags` — and appear only on a grant that carries them (absent means *unrestricted*, which an empty `push_refs` array would not say). Flat, never a nested `push` object: the deployed `treemn-check` splits this body on braces and a nested one would break every copy in the field.

### Branch rules on push: the `mediate` hook

Every other decision in this proxy is made on the request **head**. Branch rules cannot be: *which* refs a push moves is in the **body**, so they live in the one hook that sees it — `mediate`, on the `git-receive` route only, and only when a covering grant carries a `push` object. `zig/src/authproxy/pktline.zig` reads the command section; `mediateReceivePack` in the plugin decides.

**The wire, and what it does and does not allow.** A smart-HTTP push is `POST <repo>.git/git-receive-pack` whose body is `*shallow-line (command-list | push-cert) [push-options] [packfile]`. Every line is a pkt-line — a 4-hex length **including** the four bytes, at most 65520 — and the command list ends at the first flush-pkt `0000`:

```
PKT-LINE(<old-oid> SP <new-oid> SP <refname> [NUL capability-list] [LF])
```

- **Protocol v2 has no receive-pack.** `git -c protocol.version=2 push` negotiates v2 on `info/refs` and the server answers v0, so the POST body is always the v0/v1 command list. `0001` (delim) and `0002` (response-end) are v2-only framing and are **refused** here rather than skipped.
- **A push is never gzipped.** git's `remote-curl.c` sets `gzip_request` only in `fetch_git`, and `Content-Encoding` is not in the forward allowlist anyway — an encoded body simply fails the hex-length check as `push_malformed`.
- **A push over `http.postBuffer` (1 MiB) is chunked, and is preceded by a probe POST whose body is a lone `0000`.** Zero commands is a legitimate parse, not an error: it forwards untouched, or every large push would break. `Expect: 100-continue` is already answered by the core before the hook runs.
- **A signed push (`push-cert`) is refused** (`push_cert_unsupported`): the commands live inside a certificate this parser does not read, GitLab does not verify push certs, and waving one through would be a rule bypass.
- **sha256 repositories use 64-hex oids.** 40 and 64 are both accepted and the zero-oid (a delete) is per length; a command mixing the two lengths is malformed.
- **Force-push is not distinguishable.** A non-fast-forward update is `<old ≠ 0> <new ≠ 0> <ref>` exactly like a fast-forward and the proxy has no object graph. GitLab **protected branches remain the backstop** for force-push, whatever the rules say — the confirmation copy in the control plane says so, and so does the skill.

**Evaluation.** A refname is matched **component-wise** against the grant's patterns after splitting on `/`: a literal component matches itself, `*` matches **exactly one** component, `**` matches **one or more** (never zero, so `refs/heads/**` does not match `refs/heads`). Both wildcards are whole components — `compile` already refused a partial-component pattern like `ag*ent`, so `refs/heads/agent/*` never matches `refs/heads/agent-x`. No patterns at all means "any refname" (the rule object then carries only the deny flags). `deny_tags` **short-circuits** the patterns for any `refs/tags/…` command and `deny_delete` for any all-zero new oid, so a listed tag pattern plus `deny_tags` refuses the tag. Refnames themselves pass a subset of `git check-ref-format` (anchored at `refs/`, no empty component, no `..`, no dot-leading component, no `.lock` suffix, no `@{`, no `\`, none of `` ~^:?*[ ``, no space or control byte, at most 64 components); a violation is `push_malformed`, never a pattern match attempt.

**Grants are a UNION, exactly as in `authorize`.** A command passes if **any** covering `git-write` grant admits it, so a rule-free project grant is not narrowed by a namespace grant that happens to carry rules — a narrower grant can only ever add reach. And a push is **all or nothing**: one refused command refuses the whole push (it is one transaction to the client, and its commands share one packfile).

**The three properties the implementation is shaped around**, each pinned by a test:

1. **The fast path costs one string compare.** Every route but `git-receive`, and every push no covering grant restricts, returns `false` before the body reader is touched — the core then runs the ordinary single round trip, byte for byte what it ran before the hook existed.
2. **A refusal happens before any dial.** Nothing of a rejected push reaches the origin: not the commands, not the packfile. The audit line records `gate=3`, and the counters rollup carries `deny_gate3`.
3. **An admitted push is forwarded unchanged.** The buffered command section is replayed ahead of the live body through a `PrefixReader`, so `Content-Length` still describes the bytes, the pack's own framing is untouched, and a chunked body is re-framed by the emitter with its prefix intact.

**Bounds.** The command section is buffered whole before a verdict exists: at most **256 KiB** (one pkt-line may be 65520 bytes, and 1024 commands of a realistic size already exceed 64 KiB) and at most **1024 commands**; over either is `too_many_refs` (413), never a truncated — and therefore weaker — evaluation. Worst case that is ~310 KiB per in-flight mediated push, ×8 in-flight ≈ 2.5 MiB. The buffer carries oids and refnames, never a credential, so it lives outside the scratch block and is freed as soon as `open` returns; the mediate leg's **header** set (which does carry `Authorization`) is `ConnStorage.mediate_headers`, inside the scratch block and covered by its scrub.

## The policy document

Delivered by `cogbox l7 policy --from-stdin` into `.network.l7.authpolicy` inside `config.json`. It is a **compiled artifact, not a mirror of the grant table**: inert grants are already dropped, suspension already applied, unresolved API caps already withheld, the `COGWORX_GIT_ALLOW_ALL` kill switch already applied by omission. **Route knowledge never appears in it** — no path prefixes, no method lists, no `service=`, no wildcards. Semantic tuples only; the routes are the plugin's table.

```json
{ "version": 2, "providers": [
  { "provider": "GitLab", "plugin": "gitlab", "hosts": ["git.example.com"],
    "secret": "git-gitlab", "git_user": "oauth2", "scheme": "https",
    "grants": [
      { "id": "gg-…", "scope": "project", "repo": "grp/proj", "project_id": "1234",
        "caps": ["git-read", "git-write", "issues:read", "issues:write"],
        "push": { "deny_delete": true, "deny_tags": true, "refs": ["refs/heads/agent/*"] } },
      { "id": "gg-…", "scope": "namespace", "repo": "grp/sub/*", "prefix": "/grp/sub/",
        "caps": ["git-read", "pipelines:read", "repo:read", "wiki:read"],
        "projects": [ {"id": 42, "path": "grp/sub/a"} ] },
      { "id": "gg-…", "scope": "instance", "caps": ["git-read", "mr:read", "mr:write", "mr:merge"] } ] } ] }
```

**Two versions are live, `1` and `2`.** Version 1 is the four coarse caps and no `push`; version 2 adds the twelve fine caps and per-grant push rules. The control plane renders the **lowest version that carries the grant set losslessly**, so an unchanged coarse grant set stays byte-identical v1 (its fingerprint never moves, and an older agent is only ever probed with v2 when a v2 feature is actually in use), and the empty share-suspension document stays `{"version":1,"providers":[]}` forever. `caps` is the twelve v2 names plus the two legacy coarse ones, which **expand**; the plugin fails closed on anything else. `push` is accepted only on a grant carrying `git-write`, with at most 8 patterns of at most 128 bytes each, every pattern anchored at `refs/heads/` or `refs/tags/` and built from whole components (`*` = one component, `**` = one or more) — a violation of any of that fails the **whole** conf, never a silently relaxed rule.

`scheme` comes from the provider's token URL (never hardcode https — a live http-only host exists). The verb refuses a malformed document or an unknown `version` **before** writing anything, refuses a document over 64 KiB, and **accepts** the empty document (share teardown pushes it to withdraw a policy). Canonical rendering (sorted keys, providers by name, grants by id, `projects[]` id-ascending, no insignificant whitespace) is what keeps an unchanged policy skippable tick after tick; the control-plane fingerprint hashes those bytes.

**Withdrawal is a no-route state, not a 403.** Share teardown, a revoke and the **expiry** of the last grant on a provider all end the same way: the empty document lands, the funnel rule naming the host is withdrawn and the token bind goes with it — gate 3 stops holding, so no conf element is emitted. The guest does not see the 403 that implies, though: with no rule admitting the host there is no route out at all, so the connection is closed a layer earlier at l7proxy and git or curl report an empty reply with **no HTTP status**, `/_cogbox/grants` included. That is exactly the state a never-granted sandbox is in, and it is the fail-closed one. Renewing an expired grant re-binds within seconds.

The document version and the rendered **conf** version are independent. The document version says what vocabulary the control plane sent; the conf version (`l7-auth-conf.json`) says what its *reader* must understand to enforce what the render just wrote — and the render (`cogbox l7 policy`, the **agent** image) and the reader (`authproxy/conf.zig`, the **enforcer** image) roll on separate tags, so the conf version is the only whole-file fail-closed lever across that skew. It is `1` for every conf that needs nothing newer — byte-identical to the pre-v2 render — and `2` for exactly one reason: some emitted grant carries `push`. A pre-v2 `parseGrants` reads only the fields it knows, so an unknown `push` object would be **silently dropped** and a branch-restricted grant would relay every ref; bumping the file version makes that reader refuse the whole conf (empty policy → 403 `no-policy`) instead. Fine cap *names* need no bump — the plugin's `compile` already refuses an unknown cap and fails the whole conf. The grants otherwise ride in **verbatim**: the render never learns the cap vocabulary, so a fine cap or a `push` object reaches `compile` untouched.

## The three gates (enforcer side)

`renderAuthProxyConf` walks the bound secrets and emits an `l7-auth-conf.json` element only when **all three** hold:

1. the resolved secret is **bound**, its kind is `gitlab-authproxy`, and its `audience` is set;
2. `.network.l7.authpolicy` (version 1 **or** 2 — an out-of-range version is dead text, not live policy) carries a provider entry whose `hosts[]` include that audience;
3. an L7 rule **names** the audience (the funnel rule).

Gate 3 is the mirror of the addon's fail-closed inject gate: it covers the window before the funnel lands and a control plane that withdrew the rules but left the bind (no rule → no element → 403s). A stale document after a mode **flip-back** is neutralised by gate 1, not gate 3: the flip-back re-applies the legacy rules (which do name the host) and re-binds under the legacy kind, so the kind check is what makes that document **dead text**. The emitted element carries `host`, `plugin`, `scheme`, `insecure`, `cred_file`, `cred_format`, `git_user` and the doc's `grants[]` verbatim. `cred_file` is the store's value path, noted into the credential-grant transaction at the statement that writes it, so what the auth proxy may read and what the conf names it can never diverge. `insecure` is single-sourced from the same rule scan the addon's upstream-verification toggle uses.

## Version gate and skew

A migrated provider's token is bound under kind `gitlab-authproxy`. Two independent refusals, both enforced by the **old** binary, make a mixed fleet safe:

| gate | old-binary answer | consequence |
|---|---|---|
| the verb `cogbox l7 policy` | exit 64, stderr exactly `cogbox l7: error: UnknownSubcommand` | classified → the instance falls back to the **unchanged** legacy per-grant rules this pass |
| the kind `--kind gitlab-authproxy` | exit 65 (`validKind` refuses it) | the bind fails by the old binary's own hand — no credential exists, no control-plane bookkeeping |
| a **version-2 document** on a pre-v2 binary | exit 65, stderr `cogbox l7: error: unknown policy document version (expected 1)`, refused **before** any write | classified → the control plane re-delivers the **narrowed v1** document (fine caps that are not a full coarse set, push rules and the new areas are dropped, never widened) and marks the grant "limited on this sandbox agent" |
| a **version-2 conf** (some grant carries `push`) on a pre-v2 **enforcer** — a v2 agent rendering for an older enforcer image | the reader refuses the unknown conf version and falls to the **empty** entry set | every request to that host is denied `no-policy` (403). The alternative is the bug this row exists to prevent: a pre-v2 reader that accepted the file would drop the `push` object it does not know and relay **every** ref. Note the agent's exit-65 gate cannot catch this — the document is delivered to a v2-capable *agent*; only the conf version reaches the enforcer |

The refusal's **prefix** `cogbox l7: error: unknown policy document version` is a cross-repo contract — the control plane's classifier keys on it as a substring, so only the parenthetical moves as versions land (this binary says `(expected 1 or 2)`). The two independent version gates are `validatePolicyDoc` in the delivery verb (`zig/src/l7/main.zig`, `policy_doc_versions`) and `authPolicyProviders` in the conf render (`zig/src/rules/reload.zig`): the verb refuses an unknown version at delivery, the render makes one that got in by a hand edit or a rollback dead text. A **newer** binary reading an older document is always fine — v1 is accepted forever.

The kind does double duty: it is the version gate **and** the inject suppressor. The addon's inject-spec seeding keys on `gitlab-oauth`, so a token bound under the new kind is never seeded as an inject spec → no inject → the addon cannot double-stamp a host the auth proxy authenticates. The catastrophic skew this avoids: a whole-host tagged allow plus a still-bound `gitlab-oauth` secret would inject the owner token on every path. Sequencing is document → funnel → token, bound under the new kind; the addon additionally skips its injection block unconditionally for any host in `l7-auth-hosts`, and logs once per host per conf generation if both a spec and an auth entry exist (a control-plane bug).

Every skew fails closed: an old cogbox + new control plane falls back byte-identically; a buggy control plane that withdrew the rules but left the bind is saved by gate 3 (no rule names the host → no element → 403s, not owner-token-on-every-path); a new cogbox + old control plane has no document → the auth proxy refuses every host; and a **new agent + old enforcer** (the container backend's two images roll on independent tags) is caught by the conf version, not by the document version — a push-rule conf an old enforcer cannot read denies with `no-policy` rather than relaying every ref. Pin agent and enforcer from one cc-sandbox build where you can; where they can diverge, roll the enforcer first. A GCE bake puts both in one image, so no window exists there.

## Hardening

Enforced once in the core, so the escape classes close for all plugins:

- **Caller identity is structural, never claimed.** Which sandbox is calling is answered by *which* auth proxy the request reached — one process per sandbox, on a loopback port fenced from the guest. No instance-id header, query parameter or path segment exists anywhere in the design.
- **No request-derived upstream.** `scheme` and `Host` come only from the conf entry; the socket target only from `X-Cogbox-Vetted` (l7proxy's vetted, pinned IP — the auth proxy never re-resolves). The core refuses any plugin-returned upstream whose host is not in `entry.hosts`. This is the entire SSRF control on this leg; the provider is on RFC1918, so private-range refusal is not available as a second line.
- **No redirect following.** A 3xx is returned to the guest verbatim; following one is how a config-only host becomes a request-derived host.
- **Inbound header allowlist, not a denylist.** `Authorization`, `Private-Token`, `Cookie`, hop-by-hop headers and every `X-Cogbox-*` are dropped; `X-Forwarded-For` is never synthesized. Operational consequence, because the addon retargets **every** allowed flow for a host in `l7-auth-hosts`: while a grant is active for a host, the grant's policy governs all of that host's traffic from the guest — a credential the guest holds itself (a netrc, a PAT in a header) and a credential another plugin's inject spec would have stamped are both superseded, not merged. They apply again only once no grant names the host.
- **Responses:** stream status + body; strip `Set-Cookie` (an owner session cookie would be a credential escape) and all hop-by-hop headers; bodies are streamed unfiltered on every route **except the `api-project` projection** (its own bullet below). An upstream **1xx is never relayed** (502 to the guest — the final response this client never reads is dropped with the connection). A **bodyless** response (a HEAD response, 204, 304) is relayed head-only with the origin's `Content-Length` as a plain header — except on a 204, where RFC 9110 §8.6 forbids one, so a non-conforming origin's `Content-Length: 0` is dropped rather than relayed a hop further — and the connection closed after it; never through a content-length framed body writer, which would assert on the unwritten length. A content-length body the origin cuts short is relayed as far as it came and the connection is then cut, so the guest sees the truncation instead of a clean terminator. An origin head the relay cannot carry **whole** refuses the exchange — a 502 to the guest with `reason=BadResponseHeader` on the audit line, never a partial relay: a header name or value carrying CR, LF, NUL, another C0 byte (HTAB excepted) or DEL (std's response parser never inspects header bytes, and a bare LF would reach the guest as a header-splitting sequence — the response-side mirror of the request emitter's guard), a duplicated **singleton** (`Content-Length`, `Content-Type`, `Location` — std keeps one copy silently), or more forwardable headers than the relay's 64-slot set holds. Multi-valued headers (`Vary`, `WWW-Authenticate`, `Link`) are relayed copy for copy.
- **The `api-project` response is projected, not streamed.** A single-project `GET /api/v4/projects/:id` returns GitLab's *full* project object — `runners_token` (a CI runner-registration secret), plus `import_url`, `permissions`, `_links` and CI/registry config — and `simple=true` does **not** strip it on a single-project GET (GitLab honours `simple` only on LIST endpoints), so streaming the body unfiltered leaks the secret. On this route alone (`route.project_response`) the core reads the **success** body into a **bounded 256 KiB** buffer, parses it with `std.json`, and re-emits a *new* object carrying only the GitLab 18.5 **ProjectSimpleEntity allowlist** — `id, description, name, name_with_namespace, path, path_with_namespace, created_at, default_branch, tag_list, topics, ssh_url_to_repo, http_url_to_repo, web_url, readme_url, avatar_url, forks_count, star_count, last_activity_at, visibility, archived, empty_repo, namespace`, with the nested `namespace` projected through its own allowlist (`id, name, path, kind, full_path, parent_id, avatar_url, web_url`) — with a recomputed `Content-Length`. It is an **allowlist**, not a denylist (a new secret field GitLab adds is dropped by default), and a **versioned artifact** reviewed per GitLab release, like the route table. **Fail-closed:** a 200 body over the cap is a **502** (`X-Cogbox-Deny: response_too_large`) and unparseable/non-object JSON a **502** (`bad_upstream_json`) — the unprojected body is **never** relayed. A **non-200** (403/404) carries no project secret and is relayed unchanged; a `HEAD`/`204`/`304` carries no body to project. To keep the projection sound rather than trust the origin, on this route the core also strips the guest-forwarded **`accept-encoding`** and **`range`** headers before the upstream call: without them GitLab returns a full, identity-encoded 200 the projection can parse, closing a gzip 200 that would 502 (`bad_upstream_json`) and a `206 Partial Content` that — sitting outside the `status==200` guard — would stream the raw secret-bearing partial body. Within the projection, a `namespace` that is not an object and any field nested deeper than the re-emit bound are **dropped** (never passed through whole, and never re-serialized — `std.json`'s re-emit recurses natively), consistent with the allowlist's drop-by-default posture. Every other route streams its body unfiltered — the group-projects LIST included, since GitLab's own `simple=true` already stripped it upstream. The projection is **route-driven, not cap-driven**, so it also closes the pre-existing **S9** residual — the same `runners_token` leak on `api-project` when the route is reached by an `issues`/`mr` grant — once rolled.
- **Framing** (HTTP/1.1 only): refuse h2/h2c, `CONNECT`, absolute-form with authority ≠ Host, asterisk-form, authority-form, HTTP/1.0 without Host, `Content-Length` together with `Transfer-Encoding`, duplicate `Content-Length`, duplicate `Host`, **a duplicate of any forwarded header** (the forwarded set keeps one value per name while a policy check might read the other copy — a `Content-Type: json` then `Content-Type: x-www-form-urlencoded` pair would pass the 415 gate and hand the origin the form body), any control byte in the request line (a lone CR survives a bare-LF scan), obs-fold headers, bare-LF line endings, trailers on a chunked body (refused once the body has ended: a 400, the connection closed). Every framing refusal closes the connection. A head over the 16 KiB bound is a 431 whichever guard sees it first (the standard library's head bound on a trickled head, the core's copy guard on one that arrived in a single fill). An `Expect: 100-continue` on a request with **no** body is ignored (RFC 9110 §10.1.1) — and cleared before the body reader is taken, because the standard library asserts on a still-set expectation there; a duplicated `Expect` is exactly what mitmproxy folds, does not answer, and forwards, so the bare form reaches the auth proxy in the field. Any other expectation is a 417.
- **The constructed head is guarded at the emitter, too.** Every line of the upstream head is printed verbatim, so the one byte source framing never saw — the credential — is checked where it is read: a store value carrying any control byte (an interior CR/LF the trailing trim cannot reach, which `Bearer <value>` would splice raw into an `Authorization` line under the owner's identity) is refused as `credential unavailable` (403), never emitted. The conf `host` must be a plain DNS name (it becomes the `Host:` line and the SNI). Under both, the emitter refuses any header name that is not a token, any value or host with a control byte, and any control byte or space in the rebuilt path/query, **before** dialing (502, reason `BadHeader`) — the belt that also covers a plugin's or a mediate leg's own headers.
- **Canonicalization, fail-closed at every step:** split the target at the first `?` and parse the query separately; split the path on `/` **first**, then percent-decode each segment exactly once (so `grp%2Fproj` stays *one* segment whose value contains `/` — the segment positions stay stable and an encoded slash becomes a typed fact rather than structural inflation); refuse an invalid `%`-escape, a C0/C1 byte, a `.`/`..` segment, an over-long segment or too many segments; no second decode pass, ever. Query **values** are re-emitted raw on pass-through routes, so they are validated by the same byte rules (a raw or `%`-decoded control byte, an invalid escape, invalid UTF-8 → refused): a CR in a value would be header injection on the constructed upstream request line.
- **Streaming, no buffering** on pack/archive/blob routes — a multi-GB clone must not buffer. Timeouts: 10 s for the request head, 10 s upstream connect, 30 s for the upstream response head, and a 60 s **idle** bound on both sockets for the body relay **in either direction** — the request body (a `git push` pack, which the addon streams) moves both sockets to the idle bound before the upload and the upstream socket back to the 30 s head bound for the head wait once it is out; the response body moves both to the idle bound again once the head is in. API routes additionally carry a 60 s **total** relay deadline that starts ahead of the request-body upload and spans both directions, checked between 64 KiB slices: an upload still trickling past it is refused with a 408 (no response head is out yet, and the connection closes), a response still streaming past it is cut mid-body. Stream routes (pack, archive) carry none.
- **Audit: one line per request, metadata only** — the matched **route id**, never the raw path; coarse reasons from a fixed enum, never free text; never a credential byte, a header value or a body byte (a rejected push's **refnames** are body bytes and never appear); `gate` names which of the four decided (0 framing/canon, 1 classify, 2 authorize, 3 mediate); `bytes_in`/`bytes_out`/`dur_ms` measured. A raw path is logged only behind `COGBOX_L7_AUTH_DEBUG_PATH=1`, quoted and length-capped, with query values dropped except `service`. The counters rollup (`authproxy stats …`) is emitted on the accept-loop tick at most once a minute, and only when the request counter moved.
- **A coarse deny reason to the guest: `X-Cogbox-Deny`.** Every deny carries a response header `X-Cogbox-Deny: <reason>` whose value is the *same* fixed enum the audit line records (`no_route`, `no_grant`, `cap_missing`, `scope_mismatch`, `method_not_allowed`, `service_invalid`, and the pre-plugin framing/`no-policy`/`forbidden-query`/`overloaded`/… reasons). Two pre-plugin reasons are the ones a well-formed client meets by accident, both decided **before** classify and authorize ever run: `form-body` (415 — a `POST`/`PUT` carrying `application/x-www-form-urlencoded`) and `missing_length_on_body_method` (411 — a body-bearing method that declares neither `Content-Length` nor chunked framing). Neither says anything about the grant, so an agent reading only the status code files them as a capability denial — which is what the header is for. The v2 **areas** add no new reason — they reuse the three that already say what happened: a cap half the grant lacks is `cap_missing`, a verb outside a route's clamp (a repository write, a job `erase`, any `DELETE`) is `method_not_allowed`, and a named exclusion (`/pipelines/:id/variables`) is `no_route`. Push **rules** add four, all of them gate-3 verdicts over a request body: `ref_denied` (403 — a pushed ref the rules do not admit, a delete under `deny_delete`, a tag under `deny_tags`; git surfaces it as `error: RPC failed; HTTP 403`), `push_malformed` (400 — a command section this proxy cannot parse, an unusable refname included), `too_many_refs` (413 — over the 256 KiB / 1024-command bounds) and `push_cert_unsupported` (403 — a signed push). It is a fixed vocabulary — **never free text, never a secret, never a tenant-supplied byte** — added only to the empty-body deny response; the body, the `keep_alive=false` close and the framing-ambiguity posture are untouched. It exists so the in-sandbox agent (and `treemn-check`) can tell a *scoped* denial under a live grant (`scope_mismatch`/`cap_missing`) apart from "no grant at all" (`no_grant`/`no-policy`), instead of reading a bare empty-body 403 as "no access."
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
| a push whose command section is unparseable, signed, or over the 256 KiB / 1024-command bounds | 400 / 403 / 413 with the reason in `X-Cogbox-Deny`, decided **before any dial** — never forwarded on the theory that the origin will sort it out |
| the guest's body read fails mid-command-section | 502, the connection closed — a transport failure is never reported to the guest as a malformed push |

## Supervision and lifecycle

- **VM path** (`cogbox-launch.sh`): `start_l7auth` runs between `start_l7mitm` and `start_l7proxy` under the same `COGBOX_PROXY_RUNAS` uid:gid as the other proxies. Its liveness check **warns and continues** (never `die`) — its absence breaks only migrated hosts, fail-closed. `L7AUTH_PID` is torn down by `cogbox_cleanup`. There is no crash-supervision on this path (as for mitmdump and l7proxy today); a dead auth proxy there stays dead until the sandbox restarts.
- **Container path** (`cogbox-enforce.sh`): `start_l7auth` runs between `publish_ca` and `start_l7proxy`, and gets its own arm in the `wait -n` restart loop and its own `terminate()` kill — the correctness obligation, because otherwise the enforcer would silently run without the auth proxy after one crash and every migrated provider would fail closed with no self-heal.
- **Health, v1: a pid file only** (`<runtime>/authproxy.pid`), whose contents are written by the auth proxy **itself**, once, only after its listener has bound **and** its first conf parse has succeeded (a failed first parse leaves it empty/absent until a later poll parses one). **Healthy means the file exists AND is non-empty (`test -s`), never mere existence**: the VM launcher pre-creates it *empty*, owned by the `COGBOX_PROXY_RUNAS` uid, because under that uid the auth proxy cannot create anything in the root-owned runtime dir on GCE (only `l7-ca` is handed to that uid), while truncate-writing into an existing owned file needs no directory permission; the enforcer path (no runas) pre-creates it too, un-chowned, so both paths share one contract and a supervised restart truncates the dead child's stale pid away rather than leaving it to be read as live. Neither launch script ever writes a pid into it — a pid taken from `$!` would name a process that may already have died on a bind failure, exactly what the file exists to rule out; the VM launcher's warn branch removes the file. The auth proxy logs the two failure causes separately and once each: a withheld file names the failed conf parse, a failed write names the write error (never the other way round). No `readinessProbe` change — adding one would strand every old enforcer pod NotReady and has no enforcer-image freshness gate.
- **Reload is stat polling, not SIGHUP** — zero changes to the reload paths, and a missed signal cannot leave stale policy. Every polled runtime file — the auth proxy's own conf (`authproxy/conf.zig`) and all three the mitm addon reads (`l7-rules`, `l7-inject-conf.json`, `l7-auth-hosts`, sharing `_PolledFile`) — follows one contract: key the cache on `(mtime_ns, size)`, **both** halves (a truncate-then-rewrite of the same length within one tick moves neither mtime nor ctime but moves size; the nanosecond mtime closes the same-size case), **re-stat after the read and discard it if the key moved** (a torn file usually still parses — an empty rule list or JSON array is valid syntax — so the moving key is the only tell), and **never advance the key on a failed open/parse**, so the next poll retries on settled bytes rather than caching the tear until some unrelated render moves the file again. The renderer now writes all four of these files **atomically** (tmp + rename, see [network-filtering.md](network-filtering.md#the-per-sandbox-auth-proxy)), which retires the torn read on the current pair of images — the hardening stays anyway, and is not belt-and-braces: an **enforcer image runs ahead of an agent image** that still truncates in place (the two roll on independent tags), and a reader that trusts one writer's implementation detail is one image skew away from caching an empty policy. The inject conf's **second writer** — `cogbox-launch.sh` merges the harness specs in at boot — is *not* one of those reasons: it publishes with `mv`, a same-directory rename, which cannot tear. That writer's hazard is **content**, not tearing, and it is answered on the renderer side (see [network-filtering.md](network-filtering.md#the-per-sandbox-auth-proxy)). Failures are logged once per distinct cause, naming which way the reader fell.
- **What a failed read falls back to is per-reader, and the two failure kinds fall different ways.** A failed **stat** (the file is gone or unreadable — there may be no current contents at all) is the fail-**closed** one: every reader drops to the empty set *and* drops its cache key, so `l7-rules` empties to deny-all, `l7-auth-hosts` retargets nothing (migrated hosts take the legacy path and the provider 401s), and `l7-inject-conf.json` loses its specs. A failed or **torn read** (the file is there, the bytes are not usable) is fail-**static** instead: `l7-rules` and `l7-inject-conf.json` keep the **previous** contents for that poll (never a partial list, never `{}`) — installing a truncated rule set would silently un-widen policy and a truncated spec set would silently un-inject — and the next poll retries on settled bytes, while `l7-auth-hosts` still keeps nothing, because retargeting nothing is its closed direction. The inject conf's **disappearance** — the stat case — is fail-closed at the injection seam too: a request to a host named by the last conf that parsed is denied `403 inject conf unavailable` rather than having the guest's placeholder bearer forwarded upstream, which would 401 and read to claude-code as an expired login. The deny is as narrow as the healthy path — it asks `should_inject`'s question, off the non-secret half of that host's last good spec (style, `stub_token`, cookie name, git user), so a request carrying a real *secondary* credential the guest obtained through an already-injected call is forwarded untouched, exactly as it would be with the conf readable. Otherwise a conf that is persistently unreadable (an `EACCES` after a permissions regression: the stale mark has no timeout and only a successful read clears it) would be a total outage for the host rather than the loss of injection. A host that never had a spec is unaffected.

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

Run it a **second** time with a populated **v2** conf (`"version": 2` — mandatory once a grant carries `push`; fine caps plus a `push` object, a `cred_file` holding a fake token) and probe the three deny shapes, the local reflection and one **refused push** — the last is the only real-clock probe of the mediate arm that needs no reachable origin, precisely because the verdict is reached before any dial:

```sh
h=(-H 'Host: git.example.com' -H 'X-Cogbox-Host: git.example.com' -H 'X-Cogbox-Vetted: 192.0.2.10:80')
curl -s "${h[@]}" http://127.0.0.1:18043/_cogbox/grants
                              # v2 cap names + flat push_refs/push_deny_delete/push_deny_tags
#  GET  .../pipelines/9/variables          -> 403 no_route
#  POST .../repository/commits             -> 403 method_not_allowed   (Content-Length: 0)
#  POST .../issues without issues:write    -> 403 cap_missing

# a push to a ref the grant's rules do not admit: 403 X-Cogbox-Deny: ref_denied,
# `gate=3` on the audit line, and NO upstream connection attempt in the log
old=$(printf '1%.0s' $(seq 40)); new=$(printf '2%.0s' $(seq 40))
line="$old $new refs/heads/main"; printf -v pkt '%04x%s0000' $(( ${#line} + 4 )) "$line"
curl -s -D- -o /dev/null "${h[@]}" -H 'Content-Type: application/x-git-receive-pack-request' \
     --data-binary "$pkt" http://127.0.0.1:18043/grp/proj.git/git-receive-pack
```

A conf whose grants the plugin refuses falls the whole entry set to empty, so "the v2 conf parsed" is exactly the `conf generation 1 loaded (1 entries)` line — a silent `(0 entries)` is the failure this second run exists to catch.

## Known residuals

Known and deliberately not fixed here. None is an authorization gap.

- A request carrying a forbidden query key (`private_token`, `access_token`, `job_token`, `_method`) is refused with **400**, not the 403 the design text predicts. Denied and never forwarded either way; the status code is the only difference.
- A path carrying a literal `..` component (`/api/v4/projects/1/access_tokens/..%2Fissues` and the like) never reaches the auth proxy: l7proxy's request-line classifier rejects it one layer earlier (`reason=unclassifiable-or-no-sni`) with a bare connection close. Fail-closed and nothing reaches the origin — but there is **no `authproxy request` audit line** for such a request, so the auth proxy's audit trail alone under-counts these attempts; correlate with l7proxy's `reject` lines.
- An auth proxy killed from outside (a signal, an OOM) leaves its non-empty `authproxy.pid` in place: on the VM path nothing supervises it, so `test -s authproxy.pid` reads as healthy over a dead process until the sandbox restarts. `test -s` is a *started-and-parsed* signal, not liveness; a liveness probe needs `kill -0` on the recorded pid.

## Deliberately deferred

- No live project-identity resolution in v1 — the namespace snapshot stays the numeric-form authorizer; path-form addressing is *better* than today with no resolver.
- **Namespace enumeration is path-form and namespace-scope only.** A numeric group id (`/api/v4/groups/<n>/projects`) fails closed — the policy document ships no group id to verify it against — and enumeration is *not* offered under an `instance` (`*`) scope grant, which keeps the no-instance-wide-enumeration-oracle property. A numeric group form would need the control plane to ship a group id.
- The `*`-scope read **narrows** to the routed read set (deny-by-default over-blocking rather than over-allowing); the route table is a versioned artifact needing a per-provider-release review.
- The `gitNSProjectCap = 20` cap is kept although its stated derivation no longer applies.
- **DELETE stays globally denied**, and GraphQL, snippets, packages, the registry and the group-level APIs stay unrouted. `pipelines:read` does expose job traces, which can carry secrets the owner can see, and `pipelines:write` lets the sandbox trigger a pipeline as the owner; `/pipelines/:id/variables` is named-denied for that reason and the cap is opt-in per grant.
- **Force-push is not distinguishable in-proxy** (a non-fast-forward update looks exactly like a fast-forward on the wire and the proxy has no object graph), so GitLab protected branches remain the backstop for it whatever the push rules say — see [Branch rules on push](#branch-rules-on-push-the-mediate-hook). Push **options** (the pkt-lines after the command flush) are likewise not inspected: the parser stops at that flush by design, so they stream to the origin unread.
- forgejo and harbor plugins, a pooled upstream connection, and an `authproxy-strict` delivery mode that publishes `restart-required` instead of falling back — still deferred. Finer capabilities-as-data **landed** (v2, above).
