"""cogbox L7 terminate-tier enforcement addon for mitmproxy.

The Zig proxy (cogbox __l7proxy) hands terminate-marked hosts to mitmproxy
over SOCKS5, carrying the already-SSRF/CIDR-VETTED upstream IP as the CONNECT
target. mitmproxy mints a per-SNI leaf from the instance CA and decrypts; this
addon then, on every decrypted request:

  1. forces the upstream TLS SNI to the client's negotiated SNI -- we were
     handed a bare IP, so without this mitmproxy would send the IP as SNI and
     upstream cert validation would fail;
  2. enforces Host == SNI (anti-fronting / HTTP-2 cross-authority);
  3. allow/deny by host pattern + boundary-aware path prefix, first match,
     default deny -- mirroring filter.zig's L7RuleSet ENFORCEMENT semantics
     (tier selection -- terminate vs passthrough -- stays in the Zig proxy,
     so the `terminate`/`passthrough` rule tokens are ignored here).

Separately, on the upstream TLS handshake (`tls_start_server`), it disables
proxy->upstream cert verification for hosts explicitly marked `insecure` in
the rules -- the operator's per-host equivalent of `curl -k` on the
proxy<->upstream leg, for internal services with self-signed/mismatched certs.
Every other host keeps the default verification (fail closed).

SSRF/CIDR vetting is NOT repeated here; it stayed authoritative in the Zig
proxy. Rules are read from the same l7-rules file (path in COGBOX_L7_RULES)
and hot-reloaded by stat polling under the _PolledFile contract below, so
`cogbox l7 add/del` takes effect without restarting mitmproxy -- and a poll that
lands inside a render never installs torn or partial bytes.
"""

import base64
import fcntl
import glob
import hashlib
import json
import os
import pwd
import re
import sys
import tempfile
import time
import urllib.parse
import urllib.request

try:
    from mitmproxy import http, ctx
except ImportError:  # allow importing the pure helpers without mitmproxy
    http = None
    ctx = None

RULES_PATH = os.environ.get("COGBOX_L7_RULES", "")
# Host-side credential injection (keeps tokens out of the guest). Path to a
# JSON inject-conf written by cogbox-launch.sh; absent/empty => injection off,
# preserving the legacy "guest carries its own token end-to-end" behavior.
INJECT_CONF_PATH = os.environ.get("COGBOX_L7_INJECT_CONF", "")
# Per-sandbox auth proxy retargeting. A host listed one-per-line in
# COGBOX_L7_AUTH_HOSTS (the render's l7-auth-hosts) is RETARGETED on the loopback
# hop to 127.0.0.1:COGBOX_L7_AUTH_PORT, where the auth proxy (cogbox __authproxy)
# classifies/authorizes the request and stamps the owner's credential itself.
# Both are passed UNCONDITIONALLY by the launcher/enforcer even when the hosts
# file does not exist yet; AuthHosts tolerates that (empty set) and mtime-reloads
# once a render creates it. Absent/empty => no retargeting, the legacy path runs.
AUTH_HOSTS_PATH = os.environ.get("COGBOX_L7_AUTH_HOSTS", "")
AUTH_PORT = os.environ.get("COGBOX_L7_AUTH_PORT", "")


def _is_methods_token(tk):
    """A METHODS token is all uppercase ASCII letters and commas with at least
    one letter (GET / GET,POST) -- mirrors filter.zig's isMethodsToken. The
    keyword tokens (terminate/passthrough/insecure/exact) and `service=` are all
    lowercase, so an all-uppercase token is unambiguously the method list."""
    if not tk:
        return False
    saw_letter = False
    for c in tk:
        if "A" <= c <= "Z":
            saw_letter = True
        elif c != ",":
            return False
    return saw_letter


def _log(line):
    """The single logging seam: mitmproxy's logger when we run inside it,
    stderr otherwise (so importing the pure helpers -- tests -- still logs)."""
    if ctx is not None:
        try:
            ctx.log.warn(line)
            return
        except Exception:
            pass
    sys.stderr.write(line + "\n")


def _stat_key(path):
    """Cache key for a polled runtime file: (mtime_ns, size). BOTH halves are
    load-bearing -- a rewrite of the same length inside one timestamp tick moves
    neither mtime nor ctime, but any real content change moves the size;
    nanosecond mtime closes the converse (same size, new content). Mirrors the
    Zig conf reader (authproxy/conf.zig)."""
    st = os.stat(path)
    return (st.st_mtime_ns, st.st_size)


class _PolledFile:
    """Shared reload bookkeeping for the three runtime files this addon polls
    (l7-rules, l7-inject-conf.json, l7-auth-hosts). ONE contract, because they
    are all written by the same renderer and read the same way:

      1. key the cache on `_stat_key` -- (mtime_ns, size), never mtime alone;
      2. RE-STAT after the read and discard it if the key moved: a torn file
         often still parses (an empty or truncated rule list / JSON array is
         valid syntax), so the key moving under the read is the only tell;
      3. NEVER advance the cache key on a failed open/parse -- leave the
         previous key so the next poll retries on settled bytes;
      4. NEVER install a partial result, and mind that the two failure kinds
         fall DIFFERENT ways. A failed/torn READ (the file is there, the bytes
         are not usable): the rules and inject-conf readers keep the PREVIOUS
         contents -- an empty rule set silently un-widens policy and an empty
         spec set silently un-injects -- while AuthHosts keeps nothing, since
         retargeting nothing is its closed direction. A failed STAT (the file
         is gone / unreadable, i.e. there may BE no current contents): every
         reader drops to the empty set and drops its cache key, and the
         inject-conf reader additionally remembers which hosts the last good
         conf named so the injection seam can 403 them (see conf_unavailable_for)
         instead of forwarding the guest's placeholder as if it were real auth.

    The renderer writes these files ATOMICALLY now (rules/reload.zig
    writeRuntimeFile: sibling tmp, fsync, rename), which retires the torn read
    on a matched pair of images -- and none of the above is thereby belt-and-
    braces. The addon ships in the ENFORCER/agent image and the renderer in the
    cogbox binary, which roll on independent tags, so this reader can be running
    against an older writer that still truncates in place; and a multi-file
    render is still not atomic across files, which is why the renderer pins the
    write ORDER (see reload.writeWireFiles) and why these readers still have to
    be told which way to fail. Same reasoning, and the same wording, as the Zig
    reader's header in authproxy/conf.zig.

    The inject conf's SECOND writer (cogbox-launch.sh merges the harness specs
    into it at boot with `jq -s add` + `mv`) is not one of those reasons: a
    rename within the runtime dir is atomic and cannot tear. What that writer
    owns is CONTENT this reader cannot get anywhere else -- the harness cred_file
    + refresh block for the provider host -- which is a contract on the RENDERER
    (reload.writeL7Inject preserves the specs it did not author on every live
    render), not on this reader.

    Failures are logged ONCE per distinct cause -- these are polled on every
    request, so a persistent failure must not become a log flood."""

    def __init__(self):
        self.stat = None       # _stat_key of the last GOOD read
        self._fail_key = None  # last distinct failure logged

    def _fail(self, what, kind, effect, err=None):
        """Log a reload failure ONCE per distinct cause. `effect` states what the
        reader is serving meanwhile -- these lines are the only externally
        visible sign of a torn render, so they have to say which way it failed."""
        key = (kind, str(err))
        if self._fail_key == key:
            return
        self._fail_key = key
        _log("cogbox-l7: %s not reloaded (%s%s); %s"
             % (what, kind, ": %s" % err if err is not None else "", effect))

    def _ok(self):
        self._fail_key = None


class Rules(_PolledFile):
    def __init__(self):
        super().__init__()
        self.mode_terminate = False
        # list of (action, host_pattern, path_or_None, insecure_bool,
        #          methods_frozenset_or_None, exact_bool, service_or_None,
        #          tag_or_None)
        self.rules = []

    def maybe_reload(self):
        try:
            key = _stat_key(RULES_PATH)
        except OSError as e:
            # Missing/unreadable path: the EMPTY rule set is this reader's
            # fail-closed direction (evaluate() defaults to deny), and we DROP
            # the key so the next poll re-stats once the render creates it.
            self.rules, self.mode_terminate, self.stat = [], False, None
            self._fail("l7-rules", "stat failed",
                       "falling back to the empty, deny-all rule set", e)
            return
        if key == self.stat:
            return
        rules, mode_t = [], False
        try:
            with open(RULES_PATH) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    toks = line.split()
                    if toks[0] == "mode":
                        mode_t = len(toks) > 1 and toks[1] == "terminate"
                        continue
                    if toks[0] not in ("allow", "deny") or len(toks) < 2:
                        continue
                    action, host = toks[0], toks[1]
                    path, insecure, methods, exact, service, tag, bad = \
                        None, False, None, False, None, None, False
                    for tk in toks[2:]:
                        if tk.startswith("/"):
                            path = tk
                        elif tk == "insecure":
                            insecure = True
                        elif tk == "exact":
                            exact = True
                        elif tk in ("terminate", "passthrough"):
                            # Tier tokens: the Zig proxy owns tier selection; the
                            # addon only enforces allow/deny, so these are ignored
                            # here (but must NOT trip the unknown-token guard).
                            pass
                        elif tk.startswith("service="):
                            service = tk[len("service="):]
                            if not service:
                                bad = True
                                break
                        elif tk.startswith("tag="):
                            # Injection-gating tag (renderL7 emits tag=git-grants).
                            # No `bad` and no empty-value reject: an empty tag can
                            # never equal a non-empty spec rules_tag, and the
                            # enforcer never emits one. A genuinely-unknown token
                            # still trips the else guard; `tagx=...` (not matching
                            # `tag=`) is unknown -> line dropped (parity w/ Zig).
                            tag = tk[len("tag="):]
                        elif _is_methods_token(tk):
                            methods = frozenset(m for m in tk.split(",") if m)
                        else:
                            # Fail closed, matching the Zig parser: an unknown
                            # token rejects the whole line rather than silently
                            # widening it (the rolling-upgrade parity guard).
                            bad = True
                            break
                    if bad:
                        continue
                    rules.append((action, host, path, insecure, methods, exact, service, tag))
            key2 = _stat_key(RULES_PATH)
        except OSError as e:
            # A failed read installs NOTHING: not the partial list parsed so far
            # and not the key. Previous rules stand; the next poll retries.
            self._fail("l7-rules", "read failed", "keeping the previous rules", e)
            return
        if key2 != key:
            # The file moved under the read -- the bytes we parsed are torn.
            # Keep the previous rules and the previous key (a partial rule list
            # is a silent policy change in EITHER direction).
            self._fail("l7-rules", "changed under the read",
                       "keeping the previous rules")
            return
        self.rules, self.mode_terminate, self.stat = rules, mode_t, key
        self._ok()


def host_match(pattern, host):
    host = host.rstrip(".").lower()
    pattern = pattern.lower()
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        # >=1 subdomain label, matched at a dot boundary
        return host.endswith("." + suffix) and len(host) > len(suffix) + 1
    return host == pattern


def path_match(rule_path, req_path):
    # Boundary-aware left-anchored prefix with two single-segment wildcards
    # (mirrors filter.pathPrefixMatches -- BYTE-FOR-BYTE the same semantics;
    # this tier is authoritative for HTTPS terminate, so a divergence is a
    # security bug). A rule segment that is exactly `*` matches EXACTLY ONE
    # request segment and never spans a `/`; a rule segment that is exactly `#`
    # is the same narrowed to ASCII DIGITS. Either character outside a whole rule
    # segment is a literal, and either in the REQUEST is always literal.
    #
    # The rule stays a PREFIX, so a rule ending in a wildcard still matches
    # deeper paths -- an ALLOW must therefore terminate at a literal segment.
    # That is necessary but NOT sufficient, which is why `#` exists: req_path is
    # percent-DECODED before it gets here, so an encoded slash inflates one
    # addressed segment into several and `*` absorbs the first of them --
    # rule `/a/*/tail` matches raw `/a/x%2Ftail/anything`, the literal tail
    # landing on the id's OWN last component. `#` closes that for an identifier
    # that is numeric by construction. Oracle: zig/src/l7proxy/path_vectors.tsv.
    ri = qi = 0
    n, m_len = len(rule_path), len(req_path)
    while ri < n:
        c = rule_path[ri]
        if (c in ("*", "#")
                and (ri == 0 or rule_path[ri - 1] == "/")
                and (ri + 1 == n or rule_path[ri + 1] == "/")):
            seg_start = qi
            while qi < m_len and req_path[qi] != "/":
                # ASCII digits ONLY -- deliberately not str.isdigit(), which is
                # true for Arabic-Indic and superscript digits and would diverge
                # from the Zig matcher on a UTF-8 decoded segment.
                if c == "#" and not ("0" <= req_path[qi] <= "9"):
                    return False
                qi += 1
            if qi == seg_start:
                return False  # never matches an empty segment
            ri += 1
            continue
        if qi >= m_len or c != req_path[qi]:
            return False
        ri += 1
        qi += 1
    if qi == m_len:
        return True
    if rule_path.endswith("/"):
        return True
    return req_path[qi] == "/"


def normalize_path(p):
    """Strip query/fragment, percent-decode, collapse empty segments.

    Returns None -- meaning DENY -- when the decoded path carries a `.` or `..`
    segment. Mirrors l7proxy/http.zig normalizePath byte for byte, including the
    trailing-slash handling and this refusal; oracle:
    zig/src/l7proxy/path_vectors.tsv.

    WHY A DOT SEGMENT IS REFUSED RATHER THAN COLLAPSED. Enforcement decides on
    this normalized path but mitmproxy forwards the ORIGINAL raw one upstream, so
    the two strings must not be able to name different resources. Decoding alone
    is safe in that respect -- a `%2F` becomes a real separator, so it can only
    ever ADD segments, which NARROWS a left-anchored rule (an allow anchored at a
    literal tail stops matching: fail closed). Popping `..` is the one step that
    SUBTRACTS, and `..%2F` puts it under the client's control: a raw path
    lexically under a deny (`/api/v4/projects/1234/access_tokens/..%2Fissues`)
    normalizes INTO an allow (`/api/v4/projects/1234/issues`), so the request
    would be authorized -- and the owner's token injected -- as one resource
    while the origin stays free to route the raw form as another. No GitLab REST
    or git smart-HTTP request needs a dot segment.
    """
    p = p.split("?", 1)[0].split("#", 1)[0]
    p = urllib.parse.unquote(p)
    if not p.startswith("/"):
        p = "/" + p
    trailing = p.endswith("/")
    parts = []
    for seg in p.split("/"):
        if seg == "":
            continue  # collapse `//`; an empty segment names nothing
        if seg == "." or seg == "..":
            return None
        parts.append(seg)
    if not parts:
        return "/"
    out = "/" + "/".join(parts)
    if trailing:
        out += "/"
    return out


_GIT_SERVICES = ("git-upload-pack", "git-receive-pack")


def effective_git_service(path, query_service=None):
    """The request's effective git smart-HTTP service.

    PATH WINS: derive from the path's final segment first -- a POST to a
    `git-upload-pack` / `git-receive-pack` pack endpoint IS that service,
    regardless of any client-supplied `?service=` query. This mirrors
    filter.effectiveGitService (path-only) and is what keeps read/write
    separation intact: a `service=git-upload-pack` (read) allow rule must NOT
    match `POST .../git-receive-pack?service=git-upload-pack` -- the query
    cannot launder a push into the clone service.

    Only when the path is NOT itself a pack endpoint do we consult the query,
    and then only on the `info/refs` advertisement -- the sole request in the
    smart-HTTP protocol where the service lives in the query string. Trusting
    the query on any other path would let a wildcard read grant (a `/group/`
    prefix rule) authorize the owner's token onto arbitrary non-repo group
    resources (archives, artifacts, raw files) simply by appending
    `?service=git-upload-pack`. Constraining it to `.../info/refs` closes that.
    Returns None otherwise."""
    seg = path.rstrip("/").rsplit("/", 1)[-1]
    if seg in _GIT_SERVICES:
        return seg
    if path.rstrip("/").endswith("/info/refs") and query_service in _GIT_SERVICES:
        return query_service
    return None


def is_pack_endpoint(path):
    """True when the path's final segment is a git POST pack endpoint (the
    large-body clone/push requests we stream instead of buffering)."""
    return path.rstrip("/").rsplit("/", 1)[-1] in _GIT_SERVICES


def evaluate(rules, host, path, method=None, query_service=None, require_tag=None):
    h = host.rstrip(".")
    for action, pattern, rpath, _insecure, methods, exact, service, tag in rules.rules:
        # Tag gate: when require_tag is set (credential-injection's second,
        # restricted pass), consider ONLY rules bearing that tag. require_tag
        # None (the default) reproduces the unrestricted allow/deny decision.
        if require_tag is not None and tag != require_tag:
            continue
        if not host_match(pattern, h):
            continue
        if methods is not None:
            if method is None or method.upper() not in methods:
                continue
        if rpath is not None:
            if exact:
                if path != rpath:
                    continue
            elif not path_match(rpath, path):
                continue
        if service is not None:
            if effective_git_service(path, query_service) != service:
                continue
        return action
    return "deny"


def host_insecure(rules, host):
    """True if `host` matches an `allow` rule flagged insecure-upstream.

    Upstream cert verification is a host-level property (it governs the
    proxy<->upstream TLS leg, independent of the request path), so we match on
    the host pattern only -- the `request` hook already enforced allow + path.
    """
    h = host.rstrip(".")
    for action, pattern, rpath, insecure, methods, exact, service, _tag in rules.rules:
        if action == "allow" and insecure and host_match(pattern, h):
            return True
    return False


RULES = Rules()


class AuthHosts(_PolledFile):
    """The set of hosts the per-sandbox auth proxy owns, read one-per-line from
    COGBOX_L7_AUTH_HOSTS and hot-reloaded on change under the _PolledFile
    contract: (mtime_ns, size) key, re-stat after the read, never cache a failed
    read. This reader's fail direction is the EMPTY set (never a partial one),
    so a torn render can only ever un-retarget a host (fail closed to the legacy
    path -> the provider 401s), never retarget against half a file.

    An absent/empty path or a missing file yields the empty set: no host is
    retargeted, and every flow takes the unchanged legacy path."""

    def __init__(self, path):
        super().__init__()
        self.path = path
        self.hosts = frozenset()

    def maybe_reload(self):
        if not self.path:
            self.hosts, self.stat = frozenset(), None
            return
        try:
            key = _stat_key(self.path)
        except OSError:
            # Missing/unreadable: empty set, and DROP the cache so the next poll
            # re-stats once the render creates the file (fail closed meanwhile).
            # Not logged: an absent file is the NORMAL state for a sandbox with
            # no migrated host, on every request.
            self.hosts, self.stat = frozenset(), None
            return
        if key == self.stat:
            return
        try:
            with open(self.path) as f:
                hosts = frozenset(
                    line for line in (ln.strip().rstrip(".").lower() for ln in f)
                    if line and not line.startswith("#")
                )
            # RE-STAT AFTER THE READ (the spec's mandatory hardening, mirrored
            # by the Zig conf reader). IMAGE SKEW is the one reason this file
            # can tear: reload.writeL7Inject is its ONLY writer (the launcher's
            # merge pass writes l7-inject-conf.json, never this), and it renames
            # -- but the addon and the renderer roll on independent tags, so an
            # older cogbox that still truncates and rewrites in place leaves a
            # window in which a read sees an empty or partial file. If the key
            # moved while we read, the bytes are torn -- keep the PREVIOUS set
            # and the previous key (never a partial set, never a cache advance),
            # and let the next poll retry on settled bytes.
            key2 = _stat_key(self.path)
        except OSError as e:
            # Do NOT advance the cache on a failed read: retry next poll, empty
            # set for now (never a partial one).
            self.hosts = frozenset()
            self._fail("l7-auth-hosts", "read failed",
                       "no host is retargeted meanwhile", e)
            return
        if key2 != key:
            self._fail("l7-auth-hosts", "changed under the read",
                       "keeping the previously retargeted hosts")
            return
        self.hosts, self.stat = hosts, key
        self._ok()

    def contains(self, host):
        self.maybe_reload()
        return host.rstrip(".").lower() in self.hosts


AUTH_HOSTS = AuthHosts(AUTH_HOSTS_PATH)


# Reserved request headers the auth proxy consumes -- ALL of them are stripped
# unconditionally on every flow before any is set (the namespace is proxy-owned;
# a guest must never be able to forge one). X-Cogbox-Host is the auth proxy's
# route key, X-Cogbox-Vetted its upstream socket target (l7proxy's pinned IP,
# captured BEFORE the retarget), X-Cogbox-Proto the guest's original scheme
# (audit only).
COGBOX_RESERVED_PREFIX = "x-cogbox-"


def strip_cogbox_headers(headers):
    """Remove every X-Cogbox-* request header, in place. Runs unconditionally on
    EVERY flow -- allowed or denied, migrated or not -- for the same reason
    strip_method_override does: only the addon may author these, so a guest-set
    one has to be gone before the proxy ever authors its own. Returns the names
    removed (for the debug log)."""
    removed = [h for h in list(headers) if h.lower().startswith(COGBOX_RESERVED_PREFIX)]
    for h in removed:
        del headers[h]
    return removed


# The one-shot conflict log: a host that has BOTH an inject spec and an auth
# entry is a control-plane bug (the version gate should make them mutually
# exclusive). Log it once per host per conf generation, keyed on the CredStore
# conf mtime so a re-render re-arms it.
_auth_conflict_logged = {}  # host -> conf generation (CredStore.stat)


# --- Host-side credential injection ---------------------------------------
# The terminate tier decrypts a harness's TLS to its model-provider host, so
# this addon can REPLACE the request's auth header with the real token read
# from a host-side cred file -- the guest then only ever holds a stub. The
# real (long-lived refresh) token never enters the sandbox. The inject-conf
# and cred files live host-side; nothing here is shared into the guest, and
# tokens are never logged.

ANTHROPIC_OAUTH_BETA = "oauth-2025-04-20"


def json_path_raw(obj, dotted):
    """Fetch the leaf at a dotted path (e.g. claudeAiOauth.accessToken) at any
    type -- e.g. the numeric expiresAt or the refresh-token string the refresh
    path needs. Returns None if any segment is missing or not a dict. Mirrors
    the cred-file shapes in docs/harnesses.md."""
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def json_path_get(obj, dotted):
    """Like json_path_raw but only for string leaves: returns the string, or
    None if the path is missing or the leaf isn't a string."""
    v = json_path_raw(obj, dotted)
    return v if isinstance(v, str) else None


def json_path_set(obj, dotted, value):
    """Set the leaf at a dotted path in an existing nested dict, in place.
    Returns True on success. Refuses to FABRICATE structure: if any
    intermediate segment is missing or not a dict, returns False and changes
    nothing -- so a malformed cred file is never half-rewritten."""
    parts = dotted.split(".")
    cur = obj
    for part in parts[:-1]:
        if not isinstance(cur, dict) or not isinstance(cur.get(part), dict):
            return False
        cur = cur[part]
    if not isinstance(cur, dict):
        return False
    cur[parts[-1]] = value
    return True


def merge_beta(existing, marker):
    """Add `marker` to a comma-separated anthropic-beta header if absent,
    preserving any feature betas the guest already sent (order-stable)."""
    toks = [t.strip() for t in (existing or "").split(",") if t.strip()]
    if marker not in toks:
        toks.append(marker)
    return ",".join(toks)


def _parse_cookies(raw):
    """Split a Cookie request-header value into [(name, raw_pair)], preserving
    order and the exact original pair text for cookies we pass through (so a
    cookie we don't touch is never reflowed/normalized)."""
    out = []
    for part in (raw or "").split(";"):
        s = part.strip()
        if not s:
            continue
        out.append((s.split("=", 1)[0].strip(), s))
    return out


def get_cookie(headers, name):
    """Value of the named cookie in the request `Cookie` header, or None if
    absent (used for cookie-style stub-gating)."""
    for n, pair in _parse_cookies(headers.get("cookie", "")):
        if n == name:
            return pair.split("=", 1)[1].strip() if "=" in pair else ""
    return None


def set_cookie(headers, name, value):
    """Set the named cookie in the request `Cookie` header to `value`, REPLACING
    only that cookie (and dropping any duplicate of it) while preserving every
    other cookie the guest sent verbatim; appends if absent. SET semantics
    mirror apply_injection -- a guest stub for this cookie is overwritten and
    never reaches the upstream."""
    pairs, replaced = [], False
    for n, pair in _parse_cookies(headers.get("cookie", "")):
        if n == name:
            if not replaced:
                pairs.append(name + "=" + value)
                replaced = True
        else:
            pairs.append(pair)
    if not replaced:
        pairs.append(name + "=" + value)
    headers["cookie"] = "; ".join(pairs)


# Headers that make an origin execute a DIFFERENT method than the one on the
# wire. Rack::MethodOverride (GitLab's Rails stack) rewrites a POST into the
# method named by `X-HTTP-Method-Override`; other stacks honour the two spellings
# beside it. Enforcement is decided on `flow.request.method`, so leaving one of
# these in place would let a method the rules allow (POST) be executed as one
# they exclude (DELETE) -- with the host-side credential already injected.
#
# STRIPPED, not rejected, and stripped for EVERY request that reaches the
# enforcer (allowed or denied, injected or not): the header carries no
# information the wire method does not, so removing it can only ever make the
# origin agree with the string the decision was made on.
#
# RESIDUAL, accepted explicitly: Rack::MethodOverride also honours a `_method`
# field in an `application/x-www-form-urlencoded` BODY. This addon is header-only
# by construction -- pack endpoints are enforced in `requestheaders` and their
# bodies are STREAMED, never buffered -- so inspecting bodies here would mean
# buffering every request body in the proxy. GitLab's REST API does not accept
# form-encoded writes for the endpoints this reaches (they are JSON), so the
# reachable form of this residual is small; it is named rather than silently
# assumed away.
METHOD_OVERRIDE_HEADERS = (
    "x-http-method-override",
    "x-method-override",
    "x-http-method",
)


def strip_method_override(headers):
    """Remove every method-override header, in place. Returns the names removed
    (for the debug log), so a caller can see that a guest tried it."""
    removed = []
    for h in METHOD_OVERRIDE_HEADERS:
        if h in headers:
            del headers[h]
            removed.append(h)
    return removed


def apply_injection(headers, style, token, account_id=None, cookie_name=None):
    """Mutate `headers` in place to carry the real `token` per `style`. Always
    SET (never append) the credential header so a guest-supplied placeholder is
    overwritten and never reaches the upstream as-is. `headers` is a mitmproxy
    Headers multidict (case-insensitive) or any dict-like with the same API."""
    if style == "anthropic-oauth":
        headers["authorization"] = "Bearer " + token
        if "x-api-key" in headers:
            del headers["x-api-key"]
        headers["anthropic-beta"] = merge_beta(
            headers.get("anthropic-beta"), ANTHROPIC_OAUTH_BETA
        )
    elif style == "anthropic-apikey":
        headers["x-api-key"] = token
        if "authorization" in headers:
            del headers["authorization"]
    elif style == "openai-chatgpt":
        headers["authorization"] = "Bearer " + token
        if account_id:
            headers["chatgpt-account-id"] = account_id
    elif style == "basic":
        headers["authorization"] = "Basic " + base64.b64encode(token.encode()).decode()
    elif style == "cookie":
        # `token` is the session-cookie VALUE; replace only the named cookie.
        if cookie_name:
            set_cookie(headers, cookie_name, token)
    else:  # "bearer" and any unknown style: plain Bearer
        headers["authorization"] = "Bearer " + token


def should_inject(headers, style, stub_token, cookie_name=None):
    """Whether to overwrite this request's credential with the injected token.

    When the spec carries a `stub_token` (the recognizable placeholder the
    launcher redacted into the guest's cred file), inject ONLY when the request
    presents that stub -- or no credential at all -- i.e. the guest is using its
    stubbed PRIMARY identity. A request bearing any OTHER credential is using a
    SECONDARY token it legitimately obtained through an already-injected call
    (e.g. claude-code Remote Control's per-session "bridge credentials" on
    /v1/code/sessions/<id>/worker + the SSE event stream); clobbering that with
    the OAuth token breaks it (401 -> worker_register_failed -> "Transport closed
    (code 403)"). With no stub_token (harnesses that still mount their real token
    in-guest), keep the legacy always-inject behavior."""
    if not stub_token:
        return True
    if style == "cookie":
        cur = get_cookie(headers, cookie_name)
        return cur is None or cur == "" or cur == stub_token
    if style == "anthropic-apikey":
        cur = headers.get("x-api-key", "")
        return cur == "" or cur == stub_token
    if style == "basic":
        cur = headers.get("authorization", "")
        encoded_stub = "Basic " + base64.b64encode(stub_token.encode()).decode()
        return cur == "" or cur == encoded_stub
    cur = headers.get("authorization", "")
    return cur == "" or cur == "Bearer " + stub_token


# --- Host-side token refresh -----------------------------------------------
# After credential eviction the guest carries only a placeholder env token and
# can NEVER refresh (claude-code does not refresh an env token, and the refresh
# token was deliberately kept out of the sandbox). So the host token this addon
# injects must be kept fresh HOST-SIDE, or a long-running guest session starts
# getting 401s the moment the access token lapses. When a spec carries a
# `refresh` block, ensure_fresh() does the OAuth refresh-token grant here, on
# the host, and writes the rotated tokens back to the SAME canonical cred file
# the harness's own CLI uses (single refresh-token lineage -- a separate copy
# would fork the lineage and the provider's rotation would invalidate one
# side). It is serialized with flock across cogbox instances, gated on
# near-expiry, and -- because the host's own CLI does NOT take this lock -- it
# also re-checks the file just before writing and refuses to clobber a rotation
# that landed concurrently (so a host-CLI refresh during our POST can't fork the
# lineage / lock the user out).

# Refresh when the access token has less than this many seconds of life left
# (or is already expired). We trigger PROACTIVELY so the request that pays for
# the refresh still holds a valid token -- it never 401s. Env-overridable.
REFRESH_WINDOW_SEC = int(os.environ.get("COGBOX_L7_REFRESH_WINDOW_SEC", "600"))
# Bound on the blocking refresh POST. A refresh stalls mitmproxy's event loop
# for its duration, but happens at most ~once per token lifetime (hours), so a
# brief stall is invisible; the timeout caps the worst case (hung endpoint).
REFRESH_HTTP_TIMEOUT = int(os.environ.get("COGBOX_L7_REFRESH_TIMEOUT_SEC", "15"))
# Per-process floor between refresh ATTEMPTS for a given cred file (set before
# the POST, so it also throttles failures). Stops a slow/failing endpoint from
# turning every in-window request into a blocking POST, and caps the blast
# radius of a misconfiguration where the window exceeds the token lifetime.
REFRESH_COOLDOWN_SEC = int(os.environ.get("COGBOX_L7_REFRESH_COOLDOWN_SEC", "60"))
# Prefix for the write-temp. Namespaced so the launcher's eviction mirror can
# strip any stale copy by glob (see stage_overlay_source) -- crash residue must
# never reach a guest.
CRED_TMP_PREFIX = ".cogbox-refresh-"
# User-Agent for the refresh POST. The provider's OAuth host sits behind a
# Cloudflare WAF that returns 403 "Error 1010: browser_signature_banned" to the
# stock `Python-urllib/...` UA, so we must present a real harness-like UA. A
# spec's refresh block may override per-provider; this default mirrors
# claude-code's CLI UA (the exact version isn't load-bearing -- the WAF filters
# on the UA *shape*, and claude-code refreshes against this same host).
DEFAULT_REFRESH_UA = "claude-cli/2.1.177 (external, cli)"
# Cross-process lock dir. MUST be host-only (never an overlay/mirror path) and
# SHARED across instances so two proxies refreshing the same cred file
# serialize. Keyed by a hash of the cred-file path. We never put the lock (or
# any token copy) next to the cred file: the eviction mirror omits only the
# cred file itself, so a sibling there could leak into the guest.
CRED_LOCK_DIR = os.environ.get("COGBOX_L7_CRED_LOCK_DIR") or os.path.join(
    tempfile.gettempdir(), "cogbox-cred-refresh"
)


def _cred_log(msg):
    """Log a refresh event. NEVER pass a token here -- callers log only host
    names, field names and error classes."""
    _log("cogbox-cred: " + msg)


def _http_post_json(url, payload, timeout, user_agent):
    """POST `payload` as JSON and return the parsed JSON response. `user_agent`
    is set explicitly -- the stock urllib UA is WAF-banned (see
    DEFAULT_REFRESH_UA). Factored out as a module-level function so tests can
    monkeypatch it without a network or a live token rotation. Runs host-side
    over the host's own (unrestricted) egress and default trust store -- NOT
    through this proxy."""
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "User-Agent": user_agent or DEFAULT_REFRESH_UA},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


class CredStore(_PolledFile):
    """Maps a request host to the real token read from a host cred file,
    hot-reloaded on change under the _PolledFile contract. So when the
    host-side refresh (ensure_fresh) or the host's own CLI rotates the on-disk
    access token, the next request picks it up with no addon restart. The
    refresh token is read only inside ensure_fresh, under the lock, and never
    leaves the host."""

    def __init__(self, path):
        super().__init__()
        self.path = path
        self.specs = {}  # host(lower) -> spec dict
        # Hosts named by the last conf we successfully parsed. Kept separately
        # from `specs` because it must survive the conf becoming unreadable:
        # that is exactly when _enforce_and_inject has to know a host WAS
        # injected-for, so it can fail closed instead of forwarding the guest's
        # placeholder credential (see conf_unavailable_for).
        self.known_hosts = frozenset()
        # host(lower) -> the NON-SECRET half of that host's last good spec
        # (style / stub_token / cookie_name / git_user): everything
        # should_inject needs to tell "the guest is presenting the placeholder"
        # from "the guest is presenting a real secondary credential", and
        # nothing that could stamp anything (no cred_file, no token_path). It
        # outlives the conf for the same reason known_hosts does -- deciding
        # what to do while the conf is unreadable is precisely when it is needed.
        self.known_stubs = {}
        # True while `specs` is NOT confirmed by a successful read of the file
        # as it stands now (missing / torn / unparseable).
        self.conf_stale = False
        self._file_cache = {}  # cred_file -> (_stat_key, parsed_json)
        self._raw_cache = {}  # cred_file -> (_stat_key, first-non-empty-line|None)
        self._last_attempt = {}  # cred_file -> monotonic ts of last refresh attempt

    def _load_conf(self):
        if not self.path:
            # Injection is not configured at all: no specs, and nothing to fail
            # closed about (the legacy end-to-end path is the intended one).
            self.specs, self.stat = {}, None
            self.known_hosts, self.known_stubs, self.conf_stale = frozenset(), {}, False
            return
        try:
            key = _stat_key(self.path)
        except OSError as e:
            # Configured but not statable (deleted, EACCES, mid-teardown). Drop
            # the specs AND the key, but keep `known_hosts`/`known_stubs` and mark
            # the conf stale so the injection seam DENIES the requests it would
            # have injected into, for the hosts the last good conf named, rather
            # than forwarding the guest's stub upstream as if it were real auth.
            self.specs, self.stat, self.conf_stale = {}, None, True
            self._fail("l7-inject-conf.json", "stat failed",
                       "denying the injectable requests to every host the last "
                       "good conf named", e)
            return
        if key == self.stat:
            return
        specs = {}
        try:
            with open(self.path) as f:
                data = json.load(f)
            for spec in data:
                host = (spec.get("host") or "").rstrip(".").lower()
                # Admit a spec that has a host + cred_file and a way to read the
                # value: a JSON token_path (harness creds), a raw single-line file
                # (cred_format=="raw": a plain bearer / session cookie), or a
                # cookie/basic style (whose cred file is naturally a raw single
                # line -- a cookie value, or `user:pass` for basic -- so neither
                # needs an explicit token_path/cred_format; see token_for).
                if host and spec.get("cred_file") and (
                    spec.get("token_path")
                    or spec.get("cred_format") == "raw"
                    or spec.get("style") in ("cookie", "basic")
                ):
                    specs[host] = spec
            key2 = _stat_key(self.path)
        except (OSError, ValueError, TypeError, AttributeError) as e:
            # Torn or unparseable read (TypeError/AttributeError: valid JSON of
            # the wrong SHAPE -- not a list of objects -- which a truncated
            # write cannot produce but a bad renderer can, and which used to
            # escape into the request hook). A read landing inside a
            # truncate-then-rewrite -- an older cogbox than this addon's image --
            # sees an empty or half-written file,
            # and an empty JSON array PARSES, which is why this must never
            # install what it got. Keep the PREVIOUS specs and the PREVIOUS key
            # (never {}, never the partial map built above) and retry next poll.
            self.conf_stale = True
            self._fail("l7-inject-conf.json", "read failed",
                       "keeping the previous specs", e)
            return
        if key2 != key:
            # The file moved under the read: same treatment as a parse failure.
            self.conf_stale = True
            self._fail("l7-inject-conf.json", "changed under the read",
                       "keeping the previous specs")
            return
        # A conf reload invalidates the cached credential READS too, not just the
        # specs. Those caches are keyed on the cred file's (mtime_ns, size), and
        # the change that makes a bound credential readable moves NEITHER: the
        # host grants the proxy gid group-read with a chmod (rules/credgrant.zig),
        # and chmod moves ctime only. The readers no longer cache a FAILED read at
        # all (see _read_json), so a grant transition can no longer wedge a
        # negative entry -- but a POSITIVE entry read before a rebind is still
        # stale after one, and this flush is what retires it: writeL7Inject
        # applies the grants and rewrites this conf in the same pass, so the
        # conf's key is a trigger that covers every grant transition, including
        # one that FAILED and only succeeded on a later render (which the
        # host-side mtime bump cannot cover). Cheap: at most one small re-read per
        # cred file the conf names, on the next request that needs it, and the
        # conf changes only when a render runs (a bind, a reload, an `l7 add/del`)
        # -- never per request, so there is no re-read storm. `_last_attempt` is
        # deliberately NOT cleared: it throttles refresh POSTs, and a render must
        # not reset that.
        self._file_cache.clear()
        self._raw_cache.clear()
        self.specs, self.stat = specs, key
        self.known_hosts, self.conf_stale = frozenset(specs), False
        # Only the keys the spec actually carried, so `.get(k, default)` behaves
        # here exactly as it does on the healthy path (a present-but-None style
        # would defeat resolve_gitlab_style's "bearer" default).
        self.known_stubs = {
            h: {k: sp[k] for k in ("style", "stub_token", "cookie_name", "git_user")
                if k in sp}
            for h, sp in specs.items()
        }
        self._ok()

    def conf_unavailable_for(self, host, headers=None, path="/"):
        """True when injection IS configured, the conf as it stands now could
        not be read (missing / torn / unparseable), `host` was named by the last
        conf we did read, and THIS request is one the healthy path would have
        injected into -- i.e. the credential it carries is the placeholder (or
        it carries none) and we currently cannot know what to replace it with.
        The caller must DENY.

        Forwarding instead is the fail-OPEN direction and it is not harmless:
        with no spec the guest's placeholder Bearer goes upstream as if it were
        real auth, the provider 401s, and claude-code reads that as "your login
        expired" and drops into a re-auth -- a transient render window surfacing
        to the user as a lost credential. A 403 from us is visible and correct.

        But only for those requests. The healthy path is surgical -- it replaces
        a credential only when `should_inject` says the guest is presenting its
        stubbed PRIMARY identity, and forwards a SECONDARY credential the guest
        legitimately obtained through an already-injected call untouched (e.g.
        claude-code Remote Control's per-session bridge creds). Denying those too
        would turn a persistently unreadable conf (an EACCES after a permissions
        regression, say -- `conf_stale` has no timeout and only a successful read
        clears it) into a total outage for the host instead of the loss of
        injection, so this asks the same question with the same inputs, off the
        remembered non-secret half of the last good spec (`known_stubs`).

        `headers` omitted (a caller that cannot answer the question) keeps the
        conservative behaviour: deny every request to a known injected host.

        A host that never had a spec is unaffected either way: it keeps the
        legacy end-to-end path, where the guest's own credential is the real
        one."""
        if not self.path or not self.conf_stale:
            return False
        h = host.rstrip(".").lower()
        if h not in self.known_hosts:
            return False
        if headers is None:
            return True
        stub = self.known_stubs.get(h)
        if stub is None:
            # Named by the last conf but with no remembered shape (a conf that
            # parsed before this field existed): deny, as before.
            return True
        style, _prefix = resolve_gitlab_style(stub, path)
        return should_inject(headers, style, stub.get("stub_token"),
                             stub.get("cookie_name"))

    def _read_json(self, cred_file):
        """The parsed JSON cred file, cached on `_stat_key` -- the same
        (mtime_ns, size) key the polled wire files use, and for the same two
        reasons: second-resolution mtime cannot see a rotation that lands in the
        same second as the last read, and the render's grant pass only bumps the
        mtime on a real 0600 -> 0640 transition (with the bind now staging that
        grant, the steady state is `want == mode` and nothing bumps anything).

        A FAILED read is never cached. Caching it under a key a later successful
        read would not move is how a transient error (EACCES during the render's
        revoke-then-regrant, EMFILE, ENOMEM) on a file whose mtime never changes
        again turned into a permanent 403 `credential unavailable` for that host
        with no self-heal. Re-opening a few-hundred-byte file per request on the
        failing path is the cheap side of that trade."""
        try:
            key = _stat_key(cred_file)
        except OSError:
            self._file_cache.pop(cred_file, None)
            return None
        cached = self._file_cache.get(cred_file)
        if cached is not None and cached[0] == key:
            return cached[1]
        try:
            with open(cred_file) as f:
                data = json.load(f)
        except (OSError, ValueError):
            self._file_cache.pop(cred_file, None)
            return None
        self._file_cache[cred_file] = (key, data)
        return data

    def spec_for(self, host):
        self._load_conf()
        return self.specs.get(host.rstrip(".").lower())

    def value_for(self, spec, path_key):
        dotted = spec.get(path_key)
        if not dotted:
            return None
        data = self._read_json(spec.get("cred_file"))
        if data is None:
            return None
        return json_path_get(data, dotted)

    def _read_raw(self, cred_file):
        """First non-empty stripped line of a raw single-line cred file (a bare
        bearer token or a session-cookie value), cached exactly like _read_json
        -- on `_stat_key`, and never on a failure. Returns None (fail closed) if
        the file is missing/unreadable/blank."""
        try:
            key = _stat_key(cred_file)
        except OSError:
            self._raw_cache.pop(cred_file, None)
            return None
        cached = self._raw_cache.get(cred_file)
        if cached is not None and cached[0] == key:
            return cached[1]
        val = None
        try:
            with open(cred_file) as f:
                for line in f:
                    s = line.strip()
                    if s:
                        val = s
                        break
        except OSError:
            # A read that FAILED is not an answer: drop any entry and let the
            # next request retry (see _read_json). A file that is present but
            # blank IS an answer -- None, cached under its own key.
            self._raw_cache.pop(cred_file, None)
            return None
        self._raw_cache[cred_file] = (key, val)
        return val

    def token_for(self, spec):
        """The credential value for `spec`, independent of cred-file format: a
        raw single-line file (cred_format=="raw", or a cookie/basic style with no
        token_path) or a JSON cred file read at token_path. Returns None (fail
        closed) when unreadable. For `basic` the raw line is the `user:pass`
        pair (apply_injection base64-encodes it), so -- like `cookie` -- a basic
        spec needs no explicit token_path/cred_format to be read."""
        if spec.get("cred_format") == "raw" or (
            spec.get("style") in ("cookie", "basic") and not spec.get("token_path")
        ):
            return self._read_raw(spec.get("cred_file"))
        return self.value_for(spec, "token_path")

    # -- host-side refresh --------------------------------------------------

    @staticmethod
    def _expires_sec(data, expires_at_path, unit):
        """Epoch SECONDS at which the access token expires, or None if the
        field is missing/non-numeric (in which case we never refresh -- we
        cannot tell, so we leave the file alone)."""
        if not expires_at_path:
            return None
        raw = json_path_raw(data, expires_at_path)
        if not isinstance(raw, (int, float)) or isinstance(raw, bool):
            return None
        return raw / 1000.0 if unit == "ms" else float(raw)

    def _read_uncached(self, cred_file):
        """Parse the cred file fresh (bypassing the mtime cache) -- used for the
        re-check under the lock, where another refresher may have just written."""
        try:
            with open(cred_file) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    @staticmethod
    def _lock_file(cred_file):
        try:
            os.makedirs(CRED_LOCK_DIR, 0o700, exist_ok=True)
        except OSError:
            return None
        h = hashlib.sha256(cred_file.encode()).hexdigest()[:16]
        try:
            return open(os.path.join(CRED_LOCK_DIR, h + ".lock"), "w")
        except OSError:
            return None

    @staticmethod
    def _owner_home(cred_file):
        """Home dir of the cred file's OWNER, not $HOME. Under `sudo cogbox
        start` the addon runs as root with HOME=/root, but the cred file is the
        invoking user's; we want the user's ~/.cache, on the same filesystem as
        their cred file. Falls back to $HOME if the passwd lookup fails."""
        try:
            return pwd.getpwuid(os.stat(cred_file).st_uid).pw_dir
        except (OSError, KeyError):
            return os.path.expanduser("~")

    @classmethod
    def _staging_dir(cls, cred_file):
        """A HOST-ONLY directory on the same filesystem as cred_file, for the
        write-temp. os.replace must be same-fs, but the cred dir itself is the
        eviction mirror's source -- a token-bearing temp there can leak into the
        guest (the mirror strips only the cred file's basename). So we prefer
        <owner-home>/.cache/cogbox-cred-refresh when it shares the cred file's
        filesystem, keeping the rotated-token temp entirely out of any mirrored
        path. Returns None if no same-fs host-only dir is available; the caller
        then falls back to the cred dir, where the launcher's mirror-scrub + the
        under-lock stale-temp sweep are the backstop."""
        try:
            cred_dev = os.stat(os.path.dirname(cred_file) or ".").st_dev
        except OSError:
            return None
        cand = os.path.join(cls._owner_home(cred_file), ".cache", "cogbox-cred-refresh")
        try:
            os.makedirs(cand, 0o700, exist_ok=True)
            if os.stat(cand).st_dev == cred_dev:
                return cand
        except OSError:
            pass
        return None

    @classmethod
    def _atomic_write(cls, cred_file, data):
        """Replace cred_file with `data` atomically (temp + fsync + rename),
        preserving 0600 AND the original owner. The temp goes in a host-only
        same-fs dir when possible (never a guest-mirrored path), else the cred
        dir as a same-fs fallback. Owner preservation matters under `sudo cogbox
        start`: the addon runs as root, and without it the rewritten file would
        become root-owned and lock the invoking user's own CLI out of its
        credentials. Never leaves a partial file: a crash mid-write leaves the
        original intact, so no backup copy is made (a backup would be a second
        on-disk token, which we refuse to create)."""
        try:
            st = os.stat(cred_file)
            want_uid, want_gid = st.st_uid, st.st_gid
        except OSError:
            want_uid = want_gid = None
        stage = cls._staging_dir(cred_file) or (os.path.dirname(cred_file) or ".")
        fd, tmp = tempfile.mkstemp(dir=stage, prefix=CRED_TMP_PREFIX, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            # Restore the cred file's original owner (no-op when already ours,
            # e.g. rootless; under sudo this keeps the user owning their file).
            if want_uid is not None:
                try:
                    os.chown(tmp, want_uid, want_gid)
                except OSError:
                    pass
            os.replace(tmp, cred_file)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def ensure_fresh(self, spec):
        """If `spec` opts into refresh and its access token is within the expiry
        window, refresh it host-side and write the rotated tokens back to the
        canonical cred file. Best-effort and FAIL-SAFE: any problem leaves the
        file untouched and the caller injects whatever token is currently on
        disk (which, since we trigger before expiry, is still valid). Never
        raises into the request hook; never logs a token."""
        try:
            rc = spec.get("refresh")
            cred_file = spec.get("cred_file")
            if not rc or not cred_file:
                return
            unit = rc.get("expires_at_unit", "ms")
            data = self._read_json(cred_file)
            if data is None:
                return
            exp = self._expires_sec(data, rc.get("expires_at_path"), unit)
            if exp is None or exp - time.time() >= REFRESH_WINDOW_SEC:
                return  # fresh enough, or expiry unknown -> don't touch

            # Throttle attempts per cred file so a slow/failing endpoint (or a
            # window-exceeds-lifetime misconfig) can't make every in-window
            # request a blocking POST. Checked before the lock to avoid even
            # contending for it.
            last = self._last_attempt.get(cred_file)
            if last is not None and time.monotonic() - last < REFRESH_COOLDOWN_SEC:
                return

            lf = self._lock_file(cred_file)
            if lf is None:
                return
            try:
                fcntl.flock(lf, fcntl.LOCK_EX)
                # Re-read under the lock: the host CLI or a sibling instance may
                # have refreshed while we waited. If it's fresh now, we're done.
                data = self._read_uncached(cred_file)
                if data is None:
                    return
                exp = self._expires_sec(data, rc.get("expires_at_path"), unit)
                if exp is not None and exp - time.time() >= REFRESH_WINDOW_SEC:
                    return
                # Sweep any token-bearing temp a previously-crashed refresh left
                # in the cred dir (safe under the lock -- no concurrent cogbox
                # writer). The launcher's mirror-scrub is the guest-facing
                # backstop; this keeps the real dir tidy and the window minimal.
                cred_dir = os.path.dirname(cred_file) or "."
                for stale in glob.glob(os.path.join(cred_dir, CRED_TMP_PREFIX + "*.tmp")):
                    try:
                        os.unlink(stale)
                    except OSError:
                        pass
                # Snapshot mtime for the post-POST clobber guard (the host CLI,
                # which doesn't take our lock, may rotate during the POST).
                try:
                    mtime0 = os.stat(cred_file).st_mtime
                except OSError:
                    return
                refresh_token = json_path_raw(data, rc.get("refresh_token_path"))
                if not isinstance(refresh_token, str) or not refresh_token:
                    _cred_log("refresh skipped for %s: no refresh token on disk"
                              % spec.get("host"))
                    return
                self._last_attempt[cred_file] = time.monotonic()
                try:
                    resp = _http_post_json(
                        rc["token_url"],
                        {"grant_type": "refresh_token",
                         "refresh_token": refresh_token,
                         "client_id": rc["client_id"]},
                        REFRESH_HTTP_TIMEOUT,
                        rc.get("user_agent") or DEFAULT_REFRESH_UA,
                    )
                except Exception as e:  # network / HTTP / parse
                    _cred_log("refresh POST failed for %s: %s"
                              % (spec.get("host"), type(e).__name__))
                    return
                new_access = resp.get("access_token") if isinstance(resp, dict) else None
                expires_in = resp.get("expires_in") if isinstance(resp, dict) else None
                if not isinstance(new_access, str) or not new_access \
                        or not isinstance(expires_in, (int, float)) \
                        or isinstance(expires_in, bool):
                    _cred_log("refresh response missing fields for %s"
                              % spec.get("host"))
                    return
                # Rotation: providers may return a new refresh token; if absent,
                # keep the current one.
                new_refresh = resp.get("refresh_token") or refresh_token
                new_exp = time.time() + expires_in
                stored_exp = int(new_exp * 1000) if unit == "ms" else int(new_exp)
                placed = (
                    json_path_set(data, spec.get("token_path"), new_access)
                    and json_path_set(data, rc.get("refresh_token_path"), new_refresh)
                    and json_path_set(data, rc.get("expires_at_path"), stored_exp)
                )
                if not placed:
                    _cred_log("refresh: could not place fields for %s (unexpected cred shape)"
                              % spec.get("host"))
                    return
                # Don't clobber a rotation that landed during our POST: if the
                # file changed, the on-disk token is newer than ours -- drop
                # ours (single-use grants mean theirs is the valid one) and let
                # the next request re-evaluate. Avoids forking the lineage /
                # locking out the host CLI.
                try:
                    if os.stat(cred_file).st_mtime != mtime0:
                        _cred_log("refresh: %s rotated concurrently during POST; not clobbering"
                                  % spec.get("host"))
                        return
                except OSError:
                    return
                try:
                    self._atomic_write(cred_file, data)
                except OSError as e:
                    _cred_log("refresh write failed for %s: %s"
                              % (spec.get("host"), type(e).__name__))
                    return
                # Drop the cache so the imminent value_for() reads the new token.
                self._file_cache.pop(cred_file, None)
                _cred_log("refreshed %s token host-side (expires in ~%ds)"
                          % (spec.get("host"), int(expires_in)))
            finally:
                try:
                    fcntl.flock(lf, fcntl.LOCK_UN)
                except Exception:
                    pass
                lf.close()
        except Exception as e:  # absolute backstop: refresh must never break inject
            _cred_log("refresh unexpected error for %s: %s"
                      % (spec.get("host"), type(e).__name__))


CREDS = CredStore(INJECT_CONF_PATH)


def _deny(flow, msg):
    flow.response = http.Response.make(
        403, ("cogbox-l7: " + msg + "\n").encode(), {"Content-Type": "text/plain"}
    )


# git smart-HTTP endpoints that take basic auth (`git_user:<token>`); every other
# path on a gitlab-oauth host (the REST API) takes a Bearer. Mirrors the docstring
# used by the compiled git-grant rules.
GIT_SMART_HTTP_RE = re.compile(r"\.git/(info/refs|git-upload-pack|git-receive-pack)$")


def resolve_gitlab_style(spec, path):
    """For a `gitlab-oauth` spec, resolve the per-request effective injection:
    (style, token_prefix). git smart-HTTP paths -> ("basic", "<git_user>:") so the
    injected token becomes `git_user:<token>`; every other path (REST API) ->
    ("bearer", ""). Returns (spec_style, "") unchanged for non-gitlab specs."""
    if spec.get("style") != "gitlab-oauth":
        return spec.get("style", "bearer"), ""
    if GIT_SMART_HTTP_RE.search(path):
        return "basic", (spec.get("git_user") or "oauth2") + ":"
    return "bearer", ""


def retarget_to_authproxy(flow, host, sni):
    """Retarget an allowed flow whose host the auth proxy owns to the loopback
    hop 127.0.0.1:AUTH_PORT, carrying l7proxy's vetted address in a reserved
    header. Returns True on retarget, False when it could not (AUTH_PORT unusable
    or the flow carries no vetted upstream) -- in which case the caller must fail
    closed rather than forward.

    The three traps, all load-bearing:
      * capture pretty_host and the vetted `.data.host/.data.port` BEFORE
        overwriting them -- the vetted host/port IS the SOCKS5 CONNECT address
        l7proxy already SSRF-vetted and pinned, the auth proxy's ONLY upstream
        target (it never re-resolves);
      * write `.data.host` / `.data.port` DIRECTLY, never the `.host`/`.port`
        properties -- those setters call _update_host_and_authority() and would
        rewrite the Host header, destroying the routing signal and the Host==SNI
        story;
      * force `flow.request.scheme = "http"` -- left https, mitmproxy would take
        the retarget as a new upstream, set the loopback IP as SNI and fail
        verification; the scheme setter has no side effects. The loopback hop is
        plaintext, the same trust level as the existing l7proxy->mitm SOCKS5 hop.
    """
    try:
        port = int(AUTH_PORT)
    except (TypeError, ValueError):
        return False
    if port <= 0:
        return False
    data = getattr(flow.request, "data", None)
    if data is None:
        return False
    vetted_host = getattr(data, "host", None)
    vetted_port = getattr(data, "port", None)
    if not vetted_host or not vetted_port:
        return False
    # X-Cogbox-* were stripped unconditionally at the top of _enforce_and_inject,
    # so setting them here cannot append to a guest-forged value.
    flow.request.headers["X-Cogbox-Host"] = host  # the auth proxy's route key
    flow.request.headers["X-Cogbox-Vetted"] = "%s:%s" % (vetted_host, vetted_port)
    # The guest's ORIGINAL scheme, audit only -- the auth proxy's upstream scheme
    # comes from its conf, never this header. A terminated flow has an SNI (TLS);
    # a plain-HTTP inject-routed flow does not.
    flow.request.headers["X-Cogbox-Proto"] = "https" if sni else "http"
    # DIRECT .data assignment (never the properties); scheme forced to http.
    flow.request.data.host = "127.0.0.1"
    flow.request.data.port = port
    flow.request.scheme = "http"
    return True


def _enforce_and_inject(flow, path, query_service=None):
    """Shared enforcement + injection for a decrypted (or plain-HTTP) request:
    force the upstream SNI, enforce Host==SNI + allow/deny, then inject the
    host-side credential LAST (only on an allowed, non-fronted request). Sets
    `flow.response` (403) on any denial. Header-only, so it is safe to run from
    either `requestheaders` (pack endpoints, before the body) or `request`."""
    RULES.maybe_reload()

    # BEFORE anything reads the method: the rules are matched on the wire method,
    # so a surviving override header would let the origin run a different one.
    overrides = strip_method_override(flow.request.headers)
    if overrides and os.environ.get("COGBOX_L7_DEBUG_INJECT"):
        _cred_log("method-override stripped host=%s headers=%s"
                  % (flow.request.pretty_host, ",".join(overrides)))

    # Strip every X-Cogbox-* request header UNCONDITIONALLY, on every flow,
    # allowed or denied, migrated or not -- the same reason strip_method_override
    # runs unconditionally: only the addon may author these, so a guest-forged
    # one must be gone before the retarget block below can set its own.
    cogbox_stripped = strip_cogbox_headers(flow.request.headers)
    if cogbox_stripped and os.environ.get("COGBOX_L7_DEBUG_INJECT"):
        _cred_log("x-cogbox-* stripped host=%s headers=%s"
                  % (flow.request.pretty_host, ",".join(cogbox_stripped)))

    sni = flow.client_conn.sni
    # We connected to the upstream by vetted IP, so use the client's SNI for
    # the upstream TLS handshake + cert validation.
    if sni:
        flow.server_conn.sni = sni

    host = flow.request.pretty_host
    if sni and host and sni.rstrip(".").lower() != host.rstrip(".").lower():
        _deny(flow, "host/sni mismatch")
        return

    method = getattr(flow.request, "method", None)
    if evaluate(RULES, host, path, method, query_service) != "allow":
        _deny(flow, "denied")
        return

    # RETARGET: a host the auth proxy owns is steered to the loopback hop AFTER
    # the allow decision (the addon's rule set stays the outer gate -- an
    # operator deny still denies before any retarget) and BEFORE the injection
    # block, which it then bypasses entirely. This is the unconditional injection
    # skip: the auth proxy stamps the credential itself, so a stale gitlab-oauth
    # bind lingering through a mode flip must never let the addon double-stamp.
    if AUTH_HOSTS.contains(host):
        # One-shot per-host-per-conf-generation warning when a host has BOTH an
        # inject spec and an auth entry -- a control-plane bug the version gate
        # is supposed to make impossible (the new kind is never seeded as a
        # spec). We retarget regardless: the auth entry wins, the spec is
        # ignored, no token is stamped here.
        if CREDS.spec_for(host) is not None:
            gen = CREDS.stat
            if _auth_conflict_logged.get(host) != gen:
                _auth_conflict_logged[host] = gen
                _cred_log("CONFLICT host=%s has both an inject spec and an auth "
                          "entry; retargeting to the auth proxy and ignoring the "
                          "spec (control-plane bug)" % host)
        if not retarget_to_authproxy(flow, host, sni):
            # Could not retarget (auth port unusable / no vetted upstream): fail
            # closed rather than forward the request unauthenticated.
            _deny(flow, "auth proxy unavailable")
        return

    # Credential injection runs LAST, only on an allowed + host==SNI request,
    # so a denied/fronted request never gets a real token stamped on it.
    spec = CREDS.spec_for(host)
    if spec is None and CREDS.conf_unavailable_for(host, flow.request.headers, path):
        # This host IS injected-for, the conf naming its credential is currently
        # unreadable, and this request is one the healthy path would have stamped
        # (it carries the placeholder, or no credential at all). Fail closed:
        # never forward the guest's placeholder Bearer as if it were real auth
        # (see conf_unavailable_for). A request carrying a real SECONDARY
        # credential falls through and is forwarded untouched, exactly as it
        # would be with the conf readable.
        _deny(flow, "inject conf unavailable")
        return
    if spec is not None:
        # gitlab-oauth resolves basic-vs-bearer per request path; other styles
        # pass straight through.
        style, token_prefix = resolve_gitlab_style(spec, path)
        do_inject = should_inject(flow.request.headers, style,
                                  spec.get("stub_token"), spec.get("cookie_name"))
        if os.environ.get("COGBOX_L7_DEBUG_INJECT"):
            # Safe to log: host + path + decision only, never any token material.
            has_auth = bool(flow.request.headers.get("authorization")
                            or flow.request.headers.get("x-api-key"))
            _cred_log("inject host=%s path=%s inject=%s had_auth=%s"
                      % (host, path, do_inject, has_auth))
        rules_tag = spec.get("rules_tag")
        if do_inject and rules_tag and \
                evaluate(RULES, host, path, method, query_service, require_tag=rules_tag) != "allow":
            # Reachability was allowed by the full rule set, but no git-grant-tagged
            # rule covers THIS request -- inject NOTHING (the owner's token stays out
            # of a path only a generic whole-host allow reached). The request still
            # proceeds upstream with whatever the guest presented (stub / none); the
            # git host rejects it. Specs without rules_tag (anthropic-oauth) are
            # unaffected -- they keep replacing on every allowed request.
            do_inject = False
            if os.environ.get("COGBOX_L7_DEBUG_INJECT"):
                _cred_log("inject gated-out host=%s path=%s tag=%s" % (host, path, rules_tag))
        if do_inject:
            # Refresh the host token first if it's near expiry (no-op unless the
            # spec opts in). Keeps a long-running guest -- which can't refresh, by
            # design -- from being handed a lapsed token.
            CREDS.ensure_fresh(spec)
            token = CREDS.token_for(spec)
            if not token:
                # Injection is configured for this host but the host-side token is
                # unreadable: fail closed rather than forward the guest's stub as
                # if it were real auth. (Atomic-rename writeback means this is not
                # a transient race -- the file is always whole.)
                _deny(flow, "credential unavailable")
                return
            account_id = CREDS.value_for(spec, "account_id_path")
            apply_injection(flow.request.headers, style, token_prefix + token,
                            account_id, spec.get("cookie_name"))
        # else: the guest is presenting a SECONDARY credential it legitimately
        # obtained through an injected call (e.g. Remote Control per-session
        # bridge creds) -- forward it to the upstream untouched.


def _decision_path(flow):
    """The normalized path every decision is made on, or None once the flow has
    been 403'd because it carries a dot segment (normalize_path's refusal). The
    flow is marked handled so the later hook does not re-decide it."""
    path = normalize_path(flow.request.path)
    if path is None:
        flow.cogbox_handled = True
        _deny(flow, "dot segment in path")
        return None
    return path


def requestheaders(flow):
    """Decide + inject for git pack endpoints BEFORE the (possibly huge)
    clone/push body is read, and stream the body through instead of buffering it
    in the proxy. The decision inputs (host, path, method) are all header-only,
    and injection only touches headers, so doing it here is safe. Non-pack flows
    are left to the `request` hook (unchanged); we mark handled flows so `request`
    skips them (and so a streamed request -- where `request` may not fire -- is
    still enforced)."""
    path = _decision_path(flow)
    if path is None:
        return  # already 403'd: refused before any body is read
    if not is_pack_endpoint(path):
        return
    flow.cogbox_handled = True
    _enforce_and_inject(flow, path, query_service=_query_service(flow))
    if flow.response is None:  # allowed (not denied) -> stream the body
        try:
            flow.request.stream = True
        except Exception:
            pass


def request(flow):
    # Pack endpoints are already fully handled (enforced + injected + streamed)
    # in requestheaders; skip them here to avoid double-processing. A dot-segment
    # refusal marks the flow handled too, so it is caught by the same guard.
    if getattr(flow, "cogbox_handled", False):
        return
    path = _decision_path(flow)
    if path is None:
        return
    _enforce_and_inject(flow, path, query_service=_query_service(flow))


def _query_service(flow):
    """The `service` query parameter of the request (the git info/refs
    advertisement), or None. Read defensively so the pure-helper tests -- whose
    fake request carries no query multidict -- work too."""
    try:
        q = flow.request.query
        return q.get("service") if q is not None else None
    except Exception:
        return None


def responseheaders(flow):
    """Stream (don't buffer) Server-Sent-Events responses so the guest receives
    them incrementally.

    mitmproxy buffers the ENTIRE response body before forwarding it to the client
    by default. For an open-ended SSE stream that body never ends, so the bytes
    pile up in the proxy and never reach the guest. Remote Control's INBOUND
    channel is exactly such a stream -- SSE `GET /v1/code/sessions/<id>/worker/
    events/stream` -- so without streaming the guest gets nothing from the
    controller: the session looks "connected" and OUTBOUND POSTs work, but
    phone/web -> guest is dead (a one-way channel). Setting `flow.response.stream`
    in `responseheaders` (before the body is read) passes the body through
    chunk-by-chunk. It also makes ordinary streaming inference (also
    text/event-stream) truly stream instead of arriving all at once on close.
    We never read or rewrite response bodies, so streaming them is free."""
    if flow.response is None:
        return
    resp_ct = flow.response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    req_accept = flow.request.headers.get("accept", "").lower()
    # Stream when the response IS an event stream, or the client ASKED for one
    # (covers a content-type the server labels differently). Streaming a non-SSE
    # body that slips through is harmless -- we never read response bodies.
    # Also stream git pack-endpoint responses: a clone's git-upload-pack response
    # body can be gigabytes and must not buffer in the proxy.
    # `or ""` because normalize_path REFUSES a dot-segment path (returns None);
    # such a flow was already 403'd in requestheaders, so it is never a pack
    # endpoint and this hook must not raise on it.
    if (resp_ct == "text/event-stream" or "text/event-stream" in req_accept
            or is_pack_endpoint(normalize_path(flow.request.path) or "")):
        flow.response.stream = True


def tls_start_server(data):
    """Per-host upstream cert verification toggle.

    mitmproxy's built-in TlsConfig decides proxy->upstream verification purely
    from the global `ssl_insecure` option, and -- because ScriptLoader is
    registered ahead of TlsConfig -- this hook runs FIRST, before that option
    is read. We flip it per connection keyed on the client SNI so that only
    hosts explicitly marked `insecure` skip upstream verification; every other
    flow keeps the default VERIFY_PEER. We (re)assign on every call, so the
    toggle never leaks to a subsequent connection.

    Fail-safe: if a future mitmproxy ever ran this hook AFTER TlsConfig, the
    option flip would simply have no effect on the already-built connection --
    insecure hosts would 502 (verification stays on), never silently weaker.
    """
    if ctx is None:
        return
    RULES.maybe_reload()
    client = data.context.client if data.context else None
    sni = (client.sni if client else None) or getattr(data.conn, "sni", None) or ""
    want = bool(sni) and host_insecure(RULES, sni)
    if ctx.options.ssl_insecure != want:
        ctx.options.ssl_insecure = want
