---
name: cogbox-git
description: Clone, fetch or push repositories, call the git host API (merge requests, issues, pipelines) through host-held credentials, find granted repos, decode denials and know what to ask the owner for.
---

Read `/run/cogbox/environment.json` as `cogbox-environment` describes. `cogworx`: everything below applies except the last section. `local`: only the last section applies. `unknown`, missing or malformed: ask whether the user runs local cogbox or a managed cogworx sandbox before giving git-access instructions.

If an installed plugin ships a skill for a particular git host (the `cogbox-plugins` skill lists them with their plugin), use it for that host's specifics; the credential rules in this skill still apply to every host.

## Remotes and credentials

In cogworx, repository access comes from grants the sandbox's owner makes on its Git access tab, for git hosts the operator connected to cogworx (GitLab API hosts). The host side adds the owner's credential to each request a grant allows; no token enters the sandbox and none is needed. If the user sees no Git access tab on the sandbox's page, this deployment gives sandboxes no managed git access. Grants work only in `rules` network mode.

- Use a plain remote with no credential in it: `<scheme>://<git-host>/<group>/<project>.git`. Always end it in `.git`, give at least group and project (nested groups are fine), and use the path's exact casing as the grant shows it.
- Use the scheme the git host itself serves (`http` or `https`): the host side keeps the port your remote names, so the other scheme fails. Take it from the host's own clone URL, or from `git -C ~/work/repository remote get-url origin` on a sandbox created with Open repository.
- Never put a token in the URL, `~/.netrc`, a credential helper, a git config or an `Authorization` or `PRIVATE-TOKEN` header for a granted host: depending on the host it is discarded or it stops the owner's credential from being added.
- The base image has no `glab` or `gh`; use `git`, `curl` and `jq`.
- Run git with `GIT_TERMINAL_PROMPT=0` (the sandbox does not set it), so an authentication failure ends the command instead of waiting for a username.
- Git LFS is not supported: its requests are refused.

## What is granted

Run `curl -s -w '\n%{http_code}\n' <scheme>://<git-host>/_cogbox/grants`. A `200` with a JSON `grants` list is this sandbox's live grants on that host, answered on the host side with no secret in it. Each grant has `scope` (`project`, `namespace` or `instance`), `repo` (`group/project` or `group/*`; absent on `instance`), `caps` (such as `git-read` and `git-write`) and, only when push rules apply, `push_refs`, `push_deny_delete` and `push_deny_tags`.

A `403` whose body is `cogbox-l7: denied`, or an empty `403` with `X-Cogbox-Deny: no_route`, means this host has no discovery: try the repository with `GIT_TERMINAL_PROMPT=0 git ls-remote <remote>`, and ask the owner what is granted only if that fails. A page from the git host itself (no `X-Cogbox-Deny`) means the request reached the git host directly, usually because no grant is live for that host name: check that you used the exact host name the grant names, try `git ls-remote` the same way, then ask the owner. `000` (no HTTP response at all; git says `TLS connect error` or `Empty reply from server`) means either the remote uses a scheme the git host does not serve (an `https` remote to an `http` git host gets no response at all) or no grant is live for this sandbox on that host and its address is blocked: retry with the scheme from the host's own clone URL, then ask for the grant's status (below). Just after a start, a restart or an unshare, `000` and then a page from the git host itself can last a few seconds even while the tab reads `active`: wait about 15 seconds and retry once before acting on either.

Under a namespace grant with git read, on a host with discovery, `curl -s '<scheme>://<git-host>/api/v4/groups/<group-path>/projects?per_page=100&page=1' | jq -r '.[].path_with_namespace'` lists its projects, with every `/` in the group path written as `%2F` (for `acme/iac/*`, `acme%2Fiac`). Raise `page` until a page lists fewer than 100; `&search=<name>` narrows it.

## Pushing

The base image sets no commit identity: if `git config user.email` prints nothing, ask the user which name and email to commit as and set them with `git config` in that repository; never invent one.

Pushing needs `git-write` on a grant that covers the repository. Push rules exist only on hosts with discovery. A `push_refs` pattern matches whole `/` components (`*` exactly one, `**` one or more), starts with `refs/heads/` or `refs/tags/`, and is case-sensitive; push to a ref that matches, for example `git push origin HEAD:refs/heads/agent/<topic>`. With no `push_refs` any branch may be pushed. Under a grant with push rules, a signed push (`--signed`) is refused, `push_deny_delete` and `push_deny_tags` refuse deletions and tags, and one refused ref refuses the whole push.

Push rules cannot tell a force-push from a normal push, and merging a merge request through the API moves its target branch with no push at all; the git host's protected branches are the only guard. Do not force-push, rewrite pushed history or merge unless the user asked for it.

## The git host API

Call it as `curl -s <scheme>://<git-host>/api/v4/...` with no credential. Send request bodies as JSON with `-H 'Content-Type: application/json'`, always send a body on POST and PUT (`--data '{}'` when there is nothing else), and never use `private_token`, `access_token` or `job_token` query parameters.

Resolve a project's numeric id with `curl -s '<scheme>://<git-host>/api/v4/projects/<path>' | jq '{id, default_branch}'`, with every `/` in the project path written as `%2F` (`acme%2Fiac%2Fapp`), and address it by that id; if the id is refused with `scope_mismatch`, use the encoded path form instead. Print only the fields you need: a project object, job logs and artifacts can carry secrets, so never dump them whole. Change repository content with `git push`: API writes to commits, files, branches or tags, and every DELETE, are refused.

## When a request fails

`curl -s -o /dev/null -D - '<url>' | grep -i -e '^HTTP/' -e '^x-cogbox-deny'` prints the status and, when the sandbox's host side refused it, the reason. For a push: `GIT_TRACE_CURL=1 GIT_TERMINAL_PROMPT=0 git push <args> 2>&1 | grep -i 'x-cogbox-deny'`. Never print whole traces or header dumps.

| What you see | Meaning | Do |
|---|---|---|
| `X-Cogbox-Deny: cap_missing` | no grant has that capability (e.g. push without git write) | ask the owner to extend the grant |
| `X-Cogbox-Deny: scope_mismatch` | grants have the capability, none covers this repository | check path and casing, then ask the owner |
| `ref_denied`, `push_cert_unsupported`, `too_many_refs`, `push_malformed` | a push rule refused the whole push | push to an allowed ref, unsigned, fewer refs at once |
| `no_route`, `method_not_allowed`, `service_invalid` | that path or method is not forwarded (LFS, the instance-wide project list, GraphQL, DELETE, API repository writes) | use git or a forwarded endpoint |
| `form-body`, `missing_length_on_body_method`, `forbidden-query` | request shape refused | JSON body with its content type, a body on POST and PUT, no token in the query |
| `no_grant`, `no-policy`, `cred-unavailable`, `CredentialUnavailable` | nothing is live for this host now | just after a start, wait a little and retry once; if it persists, ask for the grant's status on the Git access tab and act on it (below), and if it reads `active`, ask the owner to restart the sandbox |
| `overloaded` (503) | more than 8 requests at once | retry one at a time |
| 403 with body `cogbox-l7: denied` | a host without discovery: URL not covered (missing `.git`, wrong casing) or capability missing | fix the URL, then ask the owner |
| 403 with body `cogbox-l7: auth proxy unavailable` or `cogbox-l7: credential unavailable` | the host side refused to send the request without the owner's credential | do not retry in a loop; ask for the grant's status (below), and if it is `active`, ask the owner to restart the sandbox |
| no HTTP response (`curl -w '%{http_code}'` prints `000`; git says `TLS connect error` or `Empty reply from server`) | a scheme the git host does not serve, or no grant is live on this host and its address is blocked | switch to the host's own scheme; if it is right, ask the user for the grant's status |
| the git host's own 401, 403 or 404, no `X-Cogbox-Deny` | the git host decided: no grant reached it, the owner's account lacks access, or a protected branch refused | ask the owner |
| a 502 on every request | (on any backend but the container) the host side's git proxy has stopped or failed upstream, which a scheme mismatch can also cause; its `X-Cogbox-Deny`, if any, names the upstream error | check the scheme against the host's clone URL; if it is right, ask the owner to restart the sandbox |

Under a grant reading `limited, restart needed`, a refusal of anything the grant allows, whatever it says (`no_route`, `cap_missing` or `cogbox-l7: denied`), is lifted by a restart.

## Status on the Git access tab and what to ask for

Ask the user for the grant's status on the Git access tab and act on it: `active` (live); `activating` or `activates on start` (wait, or start the sandbox); `pending` (the owner is not connected yet, or the sandbox is not running); `expired` (the owner extends it with "Edit"); `suspended (shared)` (sharing the sandbox pauses every grant until it is private again); `reconnect needed` (the owner presses "Reconnect" on that grant's row); `not found` (the owner's account cannot see that path); `restart needed` or `limited, restart needed` (restart the sandbox); `error, retrying` (wait, and restart only if it persists). A brief 401 right after the owner's token is refreshed heals by itself. The suspension while shared is deliberate, so that people the sandbox is shared with cannot act as the owner: never suggest a token or an injected secret to get around it; the owner unshares it, or the work moves to a sandbox that is not shared.

Only the owner adds or changes grants, with no admin approval; users the sandbox is shared with cannot. Tell the owner exactly what to grant: the repository as `group/project` or `group/*` (every project in the group and its subgroups); the capabilities, each `read` or `write` (`git`, `issues`, `merge requests`, `pipelines`, `wiki`; `repository API` is read only); for pushes optionally "only refs matching" with whole-component patterns such as `refs/heads/agent/*` (`refs/tags/v*` is not valid); and an expiry; they save it with "Grant". To open a merge request, ask for `merge requests` write plus `git` write to push its source branch; `merge requests` also offers `merge`, which approves and merges as the owner, so ask for it only when the user wants that. If the provider shows "coarse access" on the Git access tab, only `git` read or write, `issues` and `merge requests` exist (the last includes merge) and there are no push rules; ask for those.

## SSH remotes, other hosts, Open repository

SSH remotes (`git@<git-host>:...`, `ssh://...`) never get a host credential. They work only with the user's own SSH agent forwarded over the cogworx SSH gateway (`ssh -A`; load `cogbox-remote-access`) and when the git host's port 22 is reachable (public addresses are by default; a private one needs an IP-range rule, load `cogbox-network`). Prefer a granted `http`/`https` remote.

A git host cogworx does not manage gets no grants: public repositories clone anonymously, and for private ones the owner can bind a credential for that host as an injected secret (Secrets page "+ Bind secret": "Kind" `basic` with a user name as "Username" and a token as "Password", and "Inject into requests to this host"; load `cogbox-network`).

A sandbox created with Open repository (container, gcp and proxmox sandboxes only) has the project's default branch checked out at `~/work/repository` and a read-only grant for that project; pushing from it needs the owner to add git write to that grant.

## Local mode

There are no grants and no `/_cogbox/grants`. Public repositories clone anonymously over https; a git host on a private address is blocked until the user adds a rule on their host (load `cogbox-network`). For private repositories the user binds a credential on their workstation with `cogbox secret add <secret> --from-file <file> --audience <git-host> --kind basic --inject -n <name>` (value `user:token`; it applies to the whole host; for the `default` instance omit `-n <name>` and run `cogbox secret reload` afterwards). Never ask for the token here and never run `cogbox` in this guest.
