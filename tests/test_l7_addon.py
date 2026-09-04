#!/usr/bin/env python3
"""Parity unit tests for the mitmproxy L7 addon's pure helpers.

These must match filter.zig's L7 semantics (host pattern, boundary-aware path
prefix, path normalization) so HTTPS-terminate enforcement behaves identically
to the Zig proxy's HTTP/passthrough enforcement. Run: python3 test_l7_addon.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON = os.path.join(HERE, "..", "l7-mitm-addon.py")
spec = importlib.util.spec_from_file_location("l7addon", ADDON)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)


# host_match: exact / *.suffix / *
check(m.host_match("vhost-a.test", "vhost-a.test"), "exact")
check(m.host_match("vhost-a.test", "VHOST-A.TEST"), "case-insensitive")
check(m.host_match("vhost-a.test", "vhost-a.test."), "trailing dot")
check(not m.host_match("vhost-a.test", "vhost-b.test"), "sibling denied")
check(m.host_match("*.cdn.test", "x.cdn.test"), "wildcard one label")
check(m.host_match("*.cdn.test", "a.b.cdn.test"), "wildcard multi label")
check(not m.host_match("*.cdn.test", "cdn.test"), "wildcard needs subdomain")
check(not m.host_match("*.cdn.test", "evilcdn.test"), "wildcard boundary")
check(m.host_match("*", "anything.test"), "bare star")

# path_match: boundary-aware prefix
check(m.path_match("/api", "/api"), "path eq")
check(m.path_match("/api", "/api/"), "path slash boundary")
check(m.path_match("/api", "/api/v1"), "path subpath")
check(not m.path_match("/api", "/apifoo"), "path no false prefix")
check(m.path_match("/v1/", "/v1/x"), "path trailing slash rule")
check(not m.path_match("/v1/", "/v1"), "path trailing slash strict")

# ---- the SHARED path-matching vector table -------------------------------
#
# zig/src/l7proxy/path_vectors.tsv is the single oracle for the two matchers
# that must agree: this addon's normalize_path + path_match (HTTPS terminate --
# which is ALL git API traffic, so this tier is the authoritative one) and the
# Zig proxy's http.normalizePath + filter.pathPrefixMatches (cleartext HTTP +
# passthrough). The Zig suite (zig/src/l7proxy/path_vectors_test.zig) reads the
# SAME file, so a semantics change in either matcher fails its own suite, and
# "fixing" the table for one matcher instantly fails the other. There is
# deliberately no second copy to drift.
VECTORS = os.path.join(HERE, "..", "zig", "src", "l7proxy", "path_vectors.tsv")

_vec_norm = _vec_match = _vec_reject = 0
with open(VECTORS, encoding="utf-8") as _fh:
    for _line in _fh:
        _line = _line.rstrip("\r\n")
        if not _line or _line.startswith("#"):
            continue
        _row = _line.split("\t")
        if _row[0] == "norm":
            _got = m.normalize_path(_row[1])
            check(_got == _row[2],
                  "vector norm %r -> %r (got %r)" % (_row[1], _row[2], _got))
            _vec_norm += 1
        elif _row[0] == "reject":
            # The normalizer must REFUSE these outright (the hooks then 403).
            # Refusal is what keeps the string the decision is made on and the
            # string forwarded upstream from naming different resources.
            _got = m.normalize_path(_row[1])
            check(_got is None,
                  "vector reject %r: normalize_path ACCEPTED it as %r -- the decision "
                  "path and the forwarded path can now differ" % (_row[1], _got))
            _vec_reject += 1
        elif _row[0] == "match":
            check(_row[1] in ("yes", "no"), "vector expect %r" % _row[1])
            _want = _row[1] == "yes"
            _norm = m.normalize_path(_row[3])
            _got = m.path_match(_row[2], _norm)
            check(_got == _want,
                  "vector match rule=%r req=%r (normalized %r) want=%s got=%s -- %s"
                  % (_row[2], _row[3], _norm, _want, _got,
                     _row[4] if len(_row) > 4 else ""))
            _vec_match += 1
        else:
            # A typo'd kind would silently skip a whole class of vectors in BOTH
            # suites -- the one way the table could stop asserting unnoticed.
            check(False, "unknown vector kind %r" % _row[0])
# Floors, so a truncated or mis-parsed table cannot pass by asserting nothing.
check(_vec_norm >= 12, "vector table normalization rows (%d)" % _vec_norm)
check(_vec_match >= 40, "vector table match rows (%d)" % _vec_match)
check(_vec_reject >= 8, "vector table reject rows (%d)" % _vec_reject)

# normalize_path: percent-decode + empty-segment collapse + query strip
check(m.normalize_path("/v1/x?q=1") == "/v1/x", "strip query")
check(m.normalize_path("/%61dmin/x") == "/admin/x", "percent-decode")
check(m.normalize_path("/v1/") == "/v1/", "trailing slash preserved")
check(m.normalize_path("//a") == "/a", "collapse double slash")
# A dot segment is REFUSED, not collapsed: the decision is made on the
# normalized path while the RAW one is forwarded upstream, so a step that
# REMOVES segments would let a request be authorized as one resource and routed
# as another (`..%2F` walks INTO an anchored allow from under a deny).
check(m.normalize_path("/api/../%61dmin/./x") is None, "dot segments refused")
check(m.normalize_path("/v1/%2e%2e/secret") is None, "%2e%2e traversal refused")
check(m.normalize_path("/../..") is None, "pop past root refused")
check(m.normalize_path("/a/..b/c...") == "/a/..b/c...", "dots inside a segment are data")


# evaluate: first-match, default-deny, path-gated
# Rule tuple: (action, host, path, insecure, methods, exact, service, tag).
class _R:
    def __init__(self, rules, mode_terminate=False):
        self.rules = rules
        self.mode_terminate = mode_terminate


def _rule(action, host, path=None, insecure=False, methods=None, exact=False, service=None, tag=None):
    return (action, host, path, insecure, methods, exact, service, tag)


rs = _R([
    _rule("allow", "api.example.com", "/v1/"),
    _rule("allow", "plain.test"),
    _rule("deny", "*"),
])
check(m.evaluate(rs, "api.example.com", "/v1/x") == "allow", "path allow")
check(m.evaluate(rs, "api.example.com", "/v2/x") == "deny", "path deny")
check(m.evaluate(rs, "plain.test", "/anything") == "allow", "host allow")
check(m.evaluate(rs, "other.test", "/") == "deny", "default deny via catch-all")
check(m.evaluate(_R([_rule("allow", "only.test")]), "x.test", "/") == "deny", "default deny")

# host_insecure: only allow-rules flagged insecure match; host-level (path-independent)
ri = _R([
    _rule("allow", "internal.svc", "/api/", True),
    _rule("allow", "secure.svc"),
    _rule("deny", "nope.svc", None, True),
    _rule("allow", "*.lab.test", None, True),
])
check(m.host_insecure(ri, "internal.svc"), "insecure host flagged")
check(m.host_insecure(ri, "internal.svc."), "insecure host flagged (trailing dot)")
check(not m.host_insecure(ri, "secure.svc"), "non-insecure host not flagged")
check(not m.host_insecure(ri, "nope.svc"), "deny rule never insecure-allows")
check(not m.host_insecure(ri, "unlisted.svc"), "unlisted host not insecure")
check(m.host_insecure(ri, "box.lab.test"), "insecure wildcard host")

# --- method / exact / service matching (git-grant rule extensions) --------
# Parity with filter.zig: METHODS token is all-uppercase-and-comma; unknown
# tokens reject the whole line; evaluate honors methods + exact + service.

check(m._is_methods_token("GET"), "methods token: single")
check(m._is_methods_token("GET,POST"), "methods token: list")
check(not m._is_methods_token("get"), "methods token: lowercase rejected")
check(not m._is_methods_token("service=x"), "methods token: service= not a method")
check(not m._is_methods_token(",,"), "methods token: needs a letter")

# effective_git_service: PATH WINS over the query; query only on the info/refs advertisement
check(m.effective_git_service("/g/p.git/git-upload-pack") == "git-upload-pack", "git svc: upload endpoint")
check(m.effective_git_service("/g/p.git/git-receive-pack") == "git-receive-pack", "git svc: receive endpoint")
check(m.effective_git_service("/g/p.git/info/refs", "git-upload-pack") == "git-upload-pack", "git svc: from query on info/refs")
check(m.effective_git_service("/g/p.git/info/refs") is None, "git svc: info/refs has no endpoint service")
check(m.is_pack_endpoint("/g/p.git/git-upload-pack"), "pack endpoint: upload")
check(not m.is_pack_endpoint("/g/p.git/info/refs"), "pack endpoint: info/refs is not one")
# a client-supplied ?service= CANNOT launder a receive-pack (push) into upload (clone):
# the pack-endpoint path segment wins over the query (round-2 blocker fix).
check(m.effective_git_service("/g/p.git/git-receive-pack", "git-upload-pack") == "git-receive-pack",
      "git svc: pack-endpoint path wins over spoofed query")
# a ?service= on a NON-info/refs, non-pack path is ignored (round-2 should-fix): a wildcard
# read grant must not authorize arbitrary group resources via an appended ?service= query.
check(m.effective_git_service("/grp/proj/-/archive/main/proj.tar.gz", "git-upload-pack") is None,
      "git svc: query ignored on non-info/refs path")
check(m.effective_git_service("/grp/proj.git/info/refs", "git-upload-pack") == "git-upload-pack",
      "git svc: query honored on wildcard info/refs advertisement")

# maybe_reload: parse the new tokens; reject a line with a genuinely-unknown token
import tempfile as _tf1
_rd = _tf1.mkdtemp()
_rp = os.path.join(_rd, "l7-rules")
with open(_rp, "w") as f:
    f.write(
        "mode terminate\n"
        "allow git.example.internal POST /g/p.git/git-upload-pack exact\n"
        "allow git.example.internal GET,POST /grp/ service=git-upload-pack\n"
        "allow git.example.internal GET /grp/ tag=git-grants\n"  # tagged, kept
        "allow bad.test bogustoken\n"          # unknown token -> whole line dropped
        "allow tier.test terminate passthrough\n"  # tier tokens ignored, line kept
        "allow both.test GET /x/ tag=git-grants bogustoken\n"  # tag + unknown -> dropped
        "allow look.test tagx=foo\n"           # lookalike prefix -> dropped (parity w/ zig)
    )
m.RULES_PATH = _rp
_R2 = m.Rules()
_R2.maybe_reload()
# 4 kept (exact, service, tagged, tier-token rules); the 3 bad/lookalike lines dropped
check(len(_R2.rules) == 4, "maybe_reload: unknown-token line dropped, others kept")
_exact = _R2.rules[0]
check(_exact[4] == frozenset({"POST"}) and _exact[5] is True and _exact[6] is None,
      "maybe_reload: exact rule methods+exact parsed")
check(_exact[7] is None, "maybe_reload: an untagged rule's tag is None")
_svc = _R2.rules[1]
check(_svc[4] == frozenset({"GET", "POST"}) and _svc[6] == "git-upload-pack",
      "maybe_reload: method list + service parsed")
_tagged = _R2.rules[2]
check(_tagged[7] == "git-grants", "maybe_reload: tag=git-grants parsed into the tuple")
# the tag+unknown line and the tagx= lookalike are both dropped: no rule for those hosts
check(not any(r[1] == "both.test" for r in _R2.rules),
      "maybe_reload: tag + genuinely-unknown token still drops the whole line")
check(not any(r[1] == "look.test" for r in _R2.rules),
      "maybe_reload: tagx= lookalike is a genuinely-unknown token -> line dropped")

# evaluate: method + exact + endpoint-derived service (mirrors the zig test)
_git = _R([
    _rule("allow", "git.example.internal", "/g/p.git/git-upload-pack", methods=frozenset({"POST"}), exact=True),
    _rule("allow", "git.example.internal", "/grp/", methods=frozenset({"GET", "POST"}), service="git-upload-pack"),
])
check(m.evaluate(_git, "git.example.internal", "/g/p.git/git-upload-pack", "POST") == "allow",
      "git evaluate: exact clone POST allowed")
check(m.evaluate(_git, "git.example.internal", "/g/p.git/git-upload-pack", "GET") == "deny",
      "git evaluate: wrong method fails closed")
check(m.evaluate(_git, "git.example.internal", "/g/p.git/git-upload-pack/x", "POST") == "deny",
      "git evaluate: exact rejects a longer path")
# wildcard prefix + service: clone POST allowed, push POST (receive-pack) denied
check(m.evaluate(_git, "git.example.internal", "/grp/proj.git/git-upload-pack", "POST") == "allow",
      "git evaluate: wildcard clone allowed")
check(m.evaluate(_git, "git.example.internal", "/grp/proj.git/git-receive-pack", "POST") == "deny",
      "git evaluate: wildcard push (receive-pack) denied by endpoint-derived service")
# info/refs advertisement matched via the ?service= query
check(m.evaluate(_R([_rule("allow", "git.example.internal", "/g/p.git/info/refs",
                           methods=frozenset({"GET"}), exact=True, service="git-upload-pack")]),
                 "git.example.internal", "/g/p.git/info/refs", "GET", "git-upload-pack") == "allow",
      "git evaluate: info/refs allowed via query service")
# ADVERSARIAL (round-2 blocker): a spoofed ?service=git-upload-pack on a git-receive-pack POST
# must NOT match the wildcard read rule -- the enforcer must deny the push on a read-only grant.
check(m.evaluate(_git, "git.example.internal", "/grp/victim.git/git-receive-pack", "POST", "git-upload-pack") == "deny",
      "git evaluate: spoofed ?service= cannot push under a wildcard read grant")
# ADVERSARIAL (round-2 should-fix): a wildcard read grant must NOT reach arbitrary non-repo
# group resources by appending ?service=git-upload-pack to a non-info/refs path.
check(m.evaluate(_git, "git.example.internal", "/grp/proj/-/archive/main/proj.tar.gz", "GET", "git-upload-pack") == "deny",
      "git evaluate: wildcard read does not leak group archives via spoofed ?service=")
check(m.evaluate(_git, "git.example.internal", "/grp/proj.git/info/refs", "GET", "git-upload-pack") == "allow",
      "git evaluate: wildcard read still allows the info/refs advertisement")

# --- evaluate tag gate: reachability vs credential delegation -------------
# THE HOLE: a generic whole-host allow (untagged) coexists with a narrow
# git-grant-tagged rule. The full rule set (require_tag=None) still allows
# everything (reachability). require_tag="git-grants" considers ONLY the tagged
# rule -> the token is inject-eligible on exactly the granted method+path, never
# on the paths only the whole-host allow reached.
_gate = _R([
    _rule("allow", "git.example.internal"),  # untagged whole-host allow (the hole)
    _rule("allow", "git.example.internal", "/grp/proj.git/",
          methods=frozenset({"GET"}), tag="git-grants"),  # narrow tagged grant
    _rule("deny", "*"),
])
check(m.evaluate(_gate, "git.example.internal", "/anything") == "allow",
      "gate: whole-host allow grants reachability (no require_tag)")
check(m.evaluate(_gate, "git.example.internal", "/grp/proj.git/info/refs", "GET",
                 require_tag="git-grants") == "allow",
      "gate: a git-grant-tagged rule covers the request -> credential-eligible")
check(m.evaluate(_gate, "git.example.internal", "/api/v4/projects/other", "GET",
                 require_tag="git-grants") == "deny",
      "gate: THE HOLE CLOSED -- the untagged whole-host allow is skipped, so a "
      "path only it reached is NOT credential-eligible")
# require_tag=None default is byte-for-byte today's behavior (regression guard).
check(m.evaluate(_gate, "git.example.internal", "/api/v4/projects/other", "GET") == "allow",
      "gate: require_tag=None reproduces the unrestricted allow/deny decision")

# --- credential injection (host-side; keeps tokens out of the guest) ---

# Case-insensitive header shim mirroring mitmproxy's Headers multidict, so the
# tests catch case bugs in apply_injection (a guest may send `X-Api-Key`).
class CIDict:
    def __init__(self, init=None):
        self._d = {}
        for k, v in (init or {}).items():
            self[k] = v

    def __setitem__(self, k, v):
        self._d[k.lower()] = v

    def __getitem__(self, k):
        return self._d[k.lower()]

    def __delitem__(self, k):
        del self._d[k.lower()]

    def __contains__(self, k):
        return k.lower() in self._d

    def __iter__(self):
        # mitmproxy's real Headers multidict is iterable over its field names;
        # strip_cogbox_headers relies on that to find X-Cogbox-* by prefix.
        return iter(list(self._d.keys()))

    def get(self, k, default=None):
        return self._d.get(k.lower(), default)


# json_path_get: dotted-path string-leaf fetch
check(m.json_path_get({"a": {"b": "x"}}, "a.b") == "x", "json_path nested")
check(m.json_path_get({"a": {"b": "x"}}, "a.c") is None, "json_path missing leaf")
check(m.json_path_get({"a": "x"}, "a.b") is None, "json_path descend non-dict")
check(m.json_path_get({"a": {"b": 5}}, "a.b") is None, "json_path non-string leaf")
check(
    m.json_path_get({"claudeAiOauth": {"accessToken": "sk-ant-oat01-Z"}},
                    "claudeAiOauth.accessToken") == "sk-ant-oat01-Z",
    "json_path claude shape",
)

# merge_beta: append oauth marker, idempotent, trim, preserve feature betas
check(m.merge_beta(None, "oauth-2025-04-20") == "oauth-2025-04-20", "beta from None")
check(m.merge_beta("", "oauth-2025-04-20") == "oauth-2025-04-20", "beta from blank")
check(
    m.merge_beta("claude-code-20250219", "oauth-2025-04-20")
    == "claude-code-20250219,oauth-2025-04-20",
    "beta append",
)
check(
    m.merge_beta("a, oauth-2025-04-20 ,b", "oauth-2025-04-20") == "a,oauth-2025-04-20,b",
    "beta idempotent + trim",
)

# apply_injection: anthropic-oauth replaces stub Bearer, drops x-api-key, merges beta
h = CIDict({"Authorization": "Bearer PLACEHOLDER", "X-Api-Key": "guest-key",
            "anthropic-beta": "claude-code-20250219"})
m.apply_injection(h, "anthropic-oauth", "REAL-OAT")
check(h["authorization"] == "Bearer REAL-OAT", "oauth sets real bearer")
check("x-api-key" not in h, "oauth drops x-api-key")
check(h["anthropic-beta"] == "claude-code-20250219,oauth-2025-04-20", "oauth merges beta")

# anthropic-apikey: sets x-api-key, drops Authorization
h = CIDict({"Authorization": "Bearer guest"})
m.apply_injection(h, "anthropic-apikey", "REAL-KEY")
check(h["x-api-key"] == "REAL-KEY", "apikey sets x-api-key")
check("authorization" not in h, "apikey drops authorization")

# openai-chatgpt: sets bearer + chatgpt-account-id
h = CIDict({"Authorization": "Bearer stub"})
m.apply_injection(h, "openai-chatgpt", "REAL-ACC", account_id="acct_123")
check(h["authorization"] == "Bearer REAL-ACC", "chatgpt sets bearer")
check(h["chatgpt-account-id"] == "acct_123", "chatgpt sets account id")
h = CIDict({})
m.apply_injection(h, "openai-chatgpt", "T")  # no account id -> header omitted
check("chatgpt-account-id" not in h, "chatgpt omits account id when absent")

# bearer (and unknown style) -> plain Bearer replace
h = CIDict({"Authorization": "Bearer stub"})
m.apply_injection(h, "bearer", "T")
check(h["authorization"] == "Bearer T", "bearer style")
h = CIDict({})
m.apply_injection(h, "weird-unknown", "T")
check(h["authorization"] == "Bearer T", "unknown style falls back to bearer")

# basic -> Authorization: Basic base64(user:password)
import base64 as _b64
h = CIDict({})
m.apply_injection(h, "basic", "user:pass")
check(h["authorization"] == "Basic " + _b64.b64encode(b"user:pass").decode(), "basic style sets Basic header")
h = CIDict({"Authorization": "Basic old"})
m.apply_injection(h, "basic", "user:pass")
check(h["authorization"] == "Basic " + _b64.b64encode(b"user:pass").decode(), "basic style replaces existing Basic header")

# should_inject: with a stub_token, inject ONLY over that stub (or an absent
# credential); pass a secondary credential the guest legitimately holds straight
# through (e.g. claude-code Remote Control's per-session worker_jwt on
# /v1/code/sessions/<id>/worker -- clobbering it yields 401/worker_register_failed).
STUB = "sk-ant-oat01-cogbox-host-injected-placeholder"
check(m.should_inject(CIDict({"Authorization": "Bearer " + STUB}), "anthropic-oauth", STUB),
      "should_inject: inject over the stub bearer")
check(not m.should_inject(CIDict({"Authorization": "Bearer eyJ.worker.jwt"}), "anthropic-oauth", STUB),
      "should_inject: pass through a non-stub bearer (RC worker_jwt)")
check(m.should_inject(CIDict({}), "anthropic-oauth", STUB),
      "should_inject: inject when no credential present")
check(m.should_inject(CIDict({"Authorization": "Bearer " + STUB}), "anthropic-oauth", None),
      "should_inject: no stub_token -> legacy always-inject")
check(m.should_inject(CIDict({"Authorization": "Bearer whatever"}), "anthropic-oauth", None),
      "should_inject: no stub_token -> inject even a non-stub cred")
check(m.should_inject(CIDict({"X-Api-Key": STUB}), "anthropic-apikey", STUB),
      "should_inject: apikey inject over stub key")
check(not m.should_inject(CIDict({"X-Api-Key": "real-secondary"}), "anthropic-apikey", STUB),
      "should_inject: apikey pass through non-stub key")
BSTUB = "cogbox-stub:cogbox-stub"
_bstub_encoded = "Basic " + _b64.b64encode(BSTUB.encode()).decode()
check(m.should_inject(CIDict({}), "basic", BSTUB),
      "should_inject: basic inject when no credential present")
check(m.should_inject(CIDict({"Authorization": _bstub_encoded}), "basic", BSTUB),
      "should_inject: basic inject over the stub")
check(not m.should_inject(CIDict({"Authorization": "Basic cmVhbDpjcmVk"}), "basic", BSTUB),
      "should_inject: basic pass through non-stub credential")
check(m.should_inject(CIDict({"Authorization": "Basic cmVhbDpjcmVk"}), "basic", None),
      "should_inject: basic no stub_token -> legacy always-inject")

# Single-source the stub token. The placeholder the redactor writes, the
# fallback write_stub_cred, and the inject-conf stub_token MUST all derive from
# harness_stub_token -- a drift (as the old ANTHROPIC_AUTH_TOKEN env stub had,
# missing the sk-ant-oat01- prefix) makes should_inject fail to recognize the
# guest's placeholder, breaking the inherit-only-over-placeholder invariant. The
# literal must appear exactly once in the launcher (harness_stub_token's def);
# everything else references the function. And it must not survive in flake.nix.
with open(os.path.join(HERE, "..", "cogbox-launch.sh")) as _f:
    _launch = _f.read()
check(_launch.count("sk-ant-oat01-cogbox-host-injected-placeholder") == 1,
      "stub token literal is single-sourced in harness_stub_token (no drift)")
with open(os.path.join(HERE, "..", "flake.nix")) as _f:
    _flake = _f.read()
check("ANTHROPIC_AUTH_TOKEN" not in _flake,
      "no ANTHROPIC_AUTH_TOKEN env stub in the launcher (would shadow the cred file)")

# The ZIG side must carry the SAME literal. The sentinel is duplicated out of
# necessity -- the VM launcher is shell, the container stub-staging is Zig -- and
# the two copies were coupled only by a comment. Drift used to self-heal: the
# container bind leg overwrote the in-guest credential blindly, so a stub written
# with a stale sentinel was simply replaced by the current one. It now refuses to
# write over a credential it does not recognize as its own, which turns drift
# PERMANENT: the old-sentinel stub stays, should_inject stops recognizing it, and
# the box 401s silently with only a journal warning to show for it. Both values
# are EXTRACTED from their sources, never retyped, or this test just becomes the
# third copy that can drift.
import re as _re

with open(os.path.join(HERE, "..", "zig", "src", "secret", "main.zig")) as _f:
    _secret_zig = _f.read()
_zig_stub = _re.search(r'pub const claude_stub_token = "([^"]*)";', _secret_zig)
# Anchor to harness_stub_token's body: several other per-harness case statements
# also carry a `claude-code)` arm, so an unanchored match reads the wrong one.
_stub_fn = _re.search(r"harness_stub_token\(\) \{(.*?)\n\}", _launch, _re.S)
_sh_stub = _re.search(r'claude-code\)\s*echo\s*"([^"]*)"', _stub_fn.group(1)) if _stub_fn else None
check(_zig_stub is not None, "zig claude_stub_token literal found in secret/main.zig")
check(_sh_stub is not None, "launcher claude-code stub literal found in harness_stub_token")
check(bool(_zig_stub) and bool(_sh_stub) and _zig_stub.group(1) == _sh_stub.group(1),
      "stub token agrees between cogbox-launch.sh and zig/src/secret/main.zig (no drift)")

# CredStore: conf + cred file, host normalization, mtime hot-reload, fail-closed
import json as _json
import tempfile

_d = tempfile.mkdtemp()
_cred = os.path.join(_d, "creds.json")
_conf = os.path.join(_d, "inject.json")


def _write(path, obj, mtime):
    with open(path, "w") as f:
        _json.dump(obj, f)
    os.utime(path, (mtime, mtime))


_write(_cred, {"claudeAiOauth": {"accessToken": "OAT-1"}}, 1000)
_write(_conf, [{"host": "api.anthropic.com", "style": "anthropic-oauth",
                "cred_file": _cred, "token_path": "claudeAiOauth.accessToken"}], 1000)
cs = m.CredStore(_conf)
spec = cs.spec_for("api.anthropic.com")
check(spec is not None, "credstore spec found")
check(cs.spec_for("API.ANTHROPIC.COM.") is not None, "credstore host case/dot normalize")
check(cs.spec_for("other.host") is None, "credstore no spec for unlisted host")
check(cs.value_for(spec, "token_path") == "OAT-1", "credstore reads token v1")
check(cs.value_for(spec, "account_id_path") is None, "credstore missing path key -> None")
_write(_cred, {"claudeAiOauth": {"accessToken": "OAT-2"}}, 2000)  # rotate
check(cs.value_for(spec, "token_path") == "OAT-2", "credstore hot-reloads rotated token")
check(m.CredStore("").spec_for("api.anthropic.com") is None, "credstore disabled when no conf")
_write(_conf, [{"host": "x.test", "style": "bearer",
                "cred_file": os.path.join(_d, "nope.json"), "token_path": "k"}], 3000)
cs2 = m.CredStore(_conf)
sp2 = cs2.spec_for("x.test")
check(sp2 is not None, "credstore spec for a host whose cred file is missing")
check(cs2.value_for(sp2, "token_path") is None, "credstore missing cred file -> None (fail closed)")


# --- cookie style + raw cred file (plugin-driven injection primitives) ----

# get_cookie / set_cookie: replace only the named cookie, preserve the rest
hc = CIDict({"Cookie": "a=1; app.sid=STUB; b=2"})
check(m.get_cookie(hc, "app.sid") == "STUB", "get_cookie reads named value")
check(m.get_cookie(hc, "missing") is None, "get_cookie absent -> None")
m.set_cookie(hc, "app.sid", "REAL")
check(hc["cookie"] == "a=1; app.sid=REAL; b=2", "set_cookie replaces only named, preserves order")
hc2 = CIDict({"Cookie": "a=1"})
m.set_cookie(hc2, "app.sid", "REAL")
check(hc2["cookie"] == "a=1; app.sid=REAL", "set_cookie appends when absent")
hc3 = CIDict({})
m.set_cookie(hc3, "app.sid", "REAL")
check(hc3["cookie"] == "app.sid=REAL", "set_cookie creates header when none")
hc4 = CIDict({"Cookie": "app.sid=OLD; x=9; app.sid=DUP"})
m.set_cookie(hc4, "app.sid", "REAL")
check(hc4["cookie"] == "app.sid=REAL; x=9", "set_cookie drops a duplicate of the named cookie")

# apply_injection cookie style: SET only the named cookie; no-op without a name
h = CIDict({"Cookie": "app.sid=STUB; keep=1"})
m.apply_injection(h, "cookie", "REALSID", cookie_name="app.sid")
check(h["cookie"] == "app.sid=REALSID; keep=1", "cookie style replaces session cookie, preserves others")
h = CIDict({})
m.apply_injection(h, "cookie", "REALSID", cookie_name="app.sid")
check(h["cookie"] == "app.sid=REALSID", "cookie style injects when absent")
h = CIDict({"Cookie": "keep=1"})
m.apply_injection(h, "cookie", "REALSID")  # no cookie_name -> misconfig guard, no-op
check(h.get("cookie") == "keep=1", "cookie style without cookie_name is a no-op")

# should_inject cookie arm: inject over absent/stub; pass a real session cookie through
CSTUB = "cogbox-app-stub"
check(m.should_inject(CIDict({}), "cookie", CSTUB, cookie_name="app.sid"),
      "should_inject cookie: inject when absent")
check(m.should_inject(CIDict({"Cookie": "app.sid=" + CSTUB}), "cookie", CSTUB, cookie_name="app.sid"),
      "should_inject cookie: inject over the stub")
check(not m.should_inject(CIDict({"Cookie": "app.sid=realsession"}), "cookie", CSTUB, cookie_name="app.sid"),
      "should_inject cookie: pass through a real (non-stub) session cookie")
check(m.should_inject(CIDict({"Cookie": "app.sid=anything"}), "cookie", None, cookie_name="app.sid"),
      "should_inject cookie: no stub_token -> legacy always-inject")


def _write_raw(path, text, mtime):
    with open(path, "w") as f:
        f.write(text)
    os.utime(path, (mtime, mtime))


# CredStore raw read: a cookie spec is admitted with NO token_path; token_for
# reads the first non-empty stripped line, hot-reloads, and fails closed.
_raw = os.path.join(_d, "cookie.txt")
_write_raw(_raw, "\n  SID-RAW-1  \nignored\n", 1000)  # leading blank + surrounding whitespace
_write(_conf, [{"host": "app.example.com", "style": "cookie", "cookie_name": "app.sid",
                "cred_file": _raw, "cred_format": "raw"}], 4000)
csr = m.CredStore(_conf)
spr = csr.spec_for("app.example.com")
check(spr is not None, "credstore admits a cookie spec with no token_path")
check(csr.token_for(spr) == "SID-RAW-1", "credstore token_for reads first non-empty raw line, stripped")
_write_raw(_raw, "SID-RAW-2\n", 5000)  # rotate
check(csr.token_for(spr) == "SID-RAW-2", "credstore raw read hot-reloads on mtime change")
os.remove(_raw)
check(csr.token_for(spr) is None, "credstore raw read fail-closed on missing file")

# A raw anthropic-oauth secret (the per-user Claude setup-token bind) is the exact
# shape renderL7Inject emits for a kind=anthropic-oauth secret: style
# anthropic-oauth, cred_format raw (the token is the whole value, NOT a jq path),
# the shared stub sentinel, and NO refresh block. The addon must admit it, raw-read
# the token, stub-gate against the sentinel, and stamp the Bearer. This is the
# end-to-end path.
_oauthraw = os.path.join(_d, "claude-oauth")
_write_raw(_oauthraw, "sk-ant-oat01-REAL-SETUP-TOKEN\n", 1000)
_write(_conf, [{"host": "api.anthropic.com", "style": "anthropic-oauth",
                "cred_file": _oauthraw, "cred_format": "raw", "stub_token": STUB}], 8000)
cso = m.CredStore(_conf)
spo = cso.spec_for("api.anthropic.com")
check(spo is not None, "credstore admits a raw anthropic-oauth spec (no token_path)")
check(cso.token_for(spo) == "sk-ant-oat01-REAL-SETUP-TOKEN",
      "credstore raw-reads the anthropic-oauth setup-token value directly")
check("refresh" not in spo, "raw anthropic-oauth spec carries no refresh block (long-lived token)")
# stub-gating: inject over the redacted in-guest stub (or no auth), pass a secondary through
check(m.should_inject(CIDict({"Authorization": "Bearer " + STUB}), "anthropic-oauth", spo.get("stub_token")),
      "raw anthropic-oauth: inject over the host stub sentinel")
check(not m.should_inject(CIDict({"Authorization": "Bearer eyJ.secondary.jwt"}), "anthropic-oauth", spo.get("stub_token")),
      "raw anthropic-oauth: pass a non-stub secondary credential through untouched")
# apply: SET the real Bearer from the raw value, drop x-api-key, merge the oauth beta
_ho = CIDict({"Authorization": "Bearer " + STUB, "x-api-key": "guest-key"})
m.apply_injection(_ho, "anthropic-oauth", cso.token_for(spo))
check(_ho["authorization"] == "Bearer sk-ant-oat01-REAL-SETUP-TOKEN",
      "raw anthropic-oauth: real setup-token stamped as Bearer over the stub")
check("x-api-key" not in _ho, "raw anthropic-oauth: x-api-key dropped")
check(m.ANTHROPIC_OAUTH_BETA in _ho["anthropic-beta"], "raw anthropic-oauth: oauth beta merged")

# A raw bearer (cred_format=="raw") is admitted + read the same way (no token_path)
_rawb = os.path.join(_d, "bearer.txt")
_write_raw(_rawb, "tok-abc123\n", 1000)
_write(_conf, [{"host": "api.example.com", "style": "bearer",
                "cred_file": _rawb, "cred_format": "raw"}], 6000)
csb = m.CredStore(_conf)
spb = csb.spec_for("api.example.com")
check(spb is not None, "credstore admits a raw bearer spec with no token_path")
check(csb.token_for(spb) == "tok-abc123", "credstore token_for reads a raw bearer line")

# A `basic` spec is admitted + raw-read with NO cred_format AND NO token_path,
# exactly like `cookie`: the raw line is the `user:pass` pair that apply_injection
# base64-encodes. (Before this, a hand-rolled basic spec lacking cred_format was
# silently dropped -> no injection.)
_basic = os.path.join(_d, "userpass")
_write_raw(_basic, "alice:s3cr3t\n", 1000)
_write(_conf, [{"host": "basic.example.com", "style": "basic",
                "cred_file": _basic}], 7000)
csbasic = m.CredStore(_conf)
spbasic = csbasic.spec_for("basic.example.com")
check(spbasic is not None, "credstore admits a basic spec with no token_path/cred_format")
check(csbasic.token_for(spbasic) == "alice:s3cr3t",
      "credstore token_for raw-reads a basic user:pass line")
_hb = CIDict({})
m.apply_injection(_hb, "basic", csbasic.token_for(spbasic))
check(_hb.get("authorization") == "Basic " + _b64.b64encode(b"alice:s3cr3t").decode(),
      "basic style injects base64(user:pass) from a raw cred file")


# --- a conf reload flushes the cred-value caches -------------------------
# The cred caches are keyed on the cred file's MTIME, so any change that leaves
# the mtime alone is invisible to them -- and the change that makes a bound
# credential readable is exactly that: the host grants the proxy gid group-read
# with a chmod (rules/credgrant.zig), and chmod moves ctime only. A rebind resets
# the file to 0600 and the re-grant is a separate render, so a request landing in
# that window caches (mtime, None) and every later request 403s forever. The
# render writes the conf in the same pass as the grant, so a conf reload has to
# drop the cred caches. Modelled below as a same-mtime VALUE change, which is the
# same cache-key blindness without needing to fake an EACCES.
_fc = os.path.join(_d, "flush.json")
_fconf = os.path.join(_d, "flush-conf.json")
_fspec = [{"host": "flush.example.com", "style": "bearer",
           "cred_file": _fc, "token_path": "k"}]
_write(_fc, {"k": "V1"}, 5000)
_write(_fconf, _fspec, 5000)
csf = m.CredStore(_fconf)
check(csf.value_for(csf.spec_for("flush.example.com"), "token_path") == "V1",
      "conf-reload flush: reads the initial json value")
check(csf._file_cache, "conf-reload flush: the read populated the json cache")
_write(_fc, {"k": "V2"}, 5000)  # new value, SAME mtime (as a chmod would leave it)
check(csf.value_for(csf.spec_for("flush.example.com"), "token_path") == "V1",
      "conf-reload flush: a same-mtime change is invisible while the conf is unchanged")
_write(_fconf, _fspec, 6000)  # the render rewrites the conf, as writeL7Inject does
_spf = csf.spec_for("flush.example.com")  # the reload happens on this next lookup
check(csf._file_cache == {} and csf._raw_cache == {},
      "conf-reload flush: a conf reload clears both cred caches")
check(csf.value_for(_spf, "token_path") == "V2",
      "conf-reload flush: the json cred is re-read after a conf reload")

# Same for the raw path -- the arm the per-user Claude / git binds actually use.
_fr = os.path.join(_d, "flush-raw")
_rconf = os.path.join(_d, "flush-raw-conf.json")
_rspec = [{"host": "raw-flush.example.com", "style": "bearer", "cred_format": "raw",
           "cred_file": _fr}]
_write_raw(_fr, "RAW-1\n", 5000)
_write(_rconf, _rspec, 5000)
csrf = m.CredStore(_rconf)
check(csrf.token_for(csrf.spec_for("raw-flush.example.com")) == "RAW-1",
      "conf-reload flush: reads the initial raw value")
check(csrf._raw_cache, "conf-reload flush: the read populated the raw cache")
_write_raw(_fr, "RAW-2\n", 5000)
check(csrf.token_for(csrf.spec_for("raw-flush.example.com")) == "RAW-1",
      "conf-reload flush: raw same-mtime change invisible while the conf is unchanged")
_write(_rconf, _rspec, 6000)
check(csrf.spec_for("raw-flush.example.com") is not None,
      "conf-reload flush: the spec survives the reload")
check(csrf._raw_cache == {}, "conf-reload flush: a conf reload clears the raw cache")
check(csrf.token_for(csrf.spec_for("raw-flush.example.com")) == "RAW-2",
      "conf-reload flush: the raw cred is re-read after a conf reload")
# The refresh throttle is NOT part of the flush: clearing it would let a render
# reset the per-cred-file cooldown that keeps a failing token endpoint from being
# POSTed on every in-window request.
csrf._last_attempt["sentinel"] = 1.0
_write(_rconf, _rspec, 7000)
csrf.spec_for("raw-flush.example.com")
check(csrf._last_attempt.get("sentinel") == 1.0,
      "conf-reload flush: leaves the refresh cooldown alone")


# --- gitlab-oauth: path-dependent basic (git) vs bearer (API) injection ----
# renderL7Inject emits a gitlab-oauth spec: style gitlab-oauth, cred_format raw,
# git_user, the git stub sentinel, NO refresh block. The addon must raw-read the
# token, pick basic auth (`git_user:<token>`) on git smart-HTTP paths and Bearer
# on the REST API, and -- for credential-less `git` -- inject over the absent auth.
GIT_STUB = "glpat-cogbox-host-injected-placeholder"  # gitleaks:allow
_gitcred = os.path.join(_d, "git-gitlab")
_write_raw(_gitcred, "glpat-REAL-ACCESS-TOKEN\n", 1000)
_write(_conf, [{"host": "git.example.internal", "style": "gitlab-oauth",
                "cred_file": _gitcred, "cred_format": "raw",
                "git_user": "oauth2", "stub_token": GIT_STUB}], 9000)
csg = m.CredStore(_conf)
spg = csg.spec_for("git.example.internal")
check(spg is not None, "credstore admits a raw gitlab-oauth spec (no token_path)")
check(csg.token_for(spg) == "glpat-REAL-ACCESS-TOKEN",
      "credstore raw-reads the gitlab-oauth access token value")
check("refresh" not in spg, "gitlab-oauth spec carries no refresh block (central re-bind, single-use tokens)")

# resolve_gitlab_style: git smart-HTTP paths -> basic + `git_user:` prefix; else bearer
_st, _pref = m.resolve_gitlab_style(spg, "/g/p.git/git-upload-pack")
check(_st == "basic" and _pref == "oauth2:", "gitlab-oauth: pack POST -> basic w/ git_user prefix")
_st, _pref = m.resolve_gitlab_style(spg, "/g/p.git/info/refs")
check(_st == "basic" and _pref == "oauth2:", "gitlab-oauth: info/refs -> basic")
_st, _pref = m.resolve_gitlab_style(spg, "/g/p.git/git-receive-pack")
check(_st == "basic", "gitlab-oauth: push POST -> basic")
_st, _pref = m.resolve_gitlab_style(spg, "/api/v4/projects/1234/issues")
check(_st == "bearer" and _pref == "", "gitlab-oauth: REST API path -> bearer")
# a non-gitlab spec is unchanged
check(m.resolve_gitlab_style({"style": "cookie"}, "/x") == ("cookie", ""), "resolve: non-gitlab unchanged")

# credential-less git presents no auth -> should_inject True for both effective styles
check(m.should_inject(CIDict({}), "basic", GIT_STUB), "gitlab-oauth: inject basic when no auth")
check(m.should_inject(CIDict({}), "bearer", GIT_STUB), "gitlab-oauth: inject bearer when no auth")
# a legitimately-obtained secondary Bearer passes through untouched
check(not m.should_inject(CIDict({"Authorization": "Bearer real.secondary"}), "bearer", GIT_STUB),
      "gitlab-oauth: pass a non-stub secondary bearer through")

# apply: git path stamps Basic base64(oauth2:token); API path stamps Bearer
_hg = CIDict({})
m.apply_injection(_hg, "basic", "oauth2:" + csg.token_for(spg))
check(_hg["authorization"] == "Basic " + _b64.b64encode(b"oauth2:glpat-REAL-ACCESS-TOKEN").decode(),
      "gitlab-oauth: git path -> Basic base64(oauth2:token)")
_ha = CIDict({})
m.apply_injection(_ha, "bearer", csg.token_for(spg))
check(_ha["authorization"] == "Bearer glpat-REAL-ACCESS-TOKEN",
      "gitlab-oauth: API path -> Bearer token")


# --- json_path_raw / json_path_set (refresh write-back helpers) ----------
check(m.json_path_raw({"a": {"b": 5}}, "a.b") == 5, "json_path_raw numeric leaf")
check(m.json_path_raw({"a": {"b": "x"}}, "a.b") == "x", "json_path_raw string leaf")
check(m.json_path_raw({"a": {"b": 5}}, "a.c") is None, "json_path_raw missing")
check(m.json_path_raw({"a": "x"}, "a.b") is None, "json_path_raw descend non-dict")

_o = {"claudeAiOauth": {"accessToken": "OLD", "expiresAt": 1}}
check(m.json_path_set(_o, "claudeAiOauth.accessToken", "NEW") and
      _o["claudeAiOauth"]["accessToken"] == "NEW", "json_path_set existing leaf")
check(m.json_path_set(_o, "claudeAiOauth.expiresAt", 99) and
      _o["claudeAiOauth"]["expiresAt"] == 99, "json_path_set numeric leaf")
# refuses to fabricate structure on a malformed/missing intermediate
_bad = {"claudeAiOauth": "not-a-dict"}
check(m.json_path_set(_bad, "claudeAiOauth.accessToken", "X") is False, "json_path_set non-dict intermediate -> False")
check(_bad == {"claudeAiOauth": "not-a-dict"}, "json_path_set no mutation on failure")
check(m.json_path_set({"a": {}}, "a.b.c", "X") is False, "json_path_set missing intermediate -> False")

# --- host-side token refresh (ensure_fresh) ------------------------------
import time as _time

# Keep the cross-process lock out of the shared system temp dir during tests.
m.CRED_LOCK_DIR = os.path.join(_d, "locks")
m.REFRESH_WINDOW_SEC = 600


def _now_ms(delta_sec=0):
    return int((_time.time() + delta_sec) * 1000)


def _mk_cred(name, expires_at_ms, access="OLD-ACCESS", refresh="OLD-REFRESH"):
    p = os.path.join(_d, name)
    with open(p, "w") as f:
        _json.dump({"claudeAiOauth": {
            "accessToken": access, "refreshToken": refresh,
            "expiresAt": expires_at_ms,
            "scopes": ["user:inference"], "subscriptionType": "max"}}, f)
    return p


_REFRESH = {
    "refresh_token_path": "claudeAiOauth.refreshToken",
    "expires_at_path": "claudeAiOauth.expiresAt",
    "token_url": "https://example.invalid/oauth/token",
    "client_id": "CID",
    "expires_at_unit": "ms",
}


def _spec_for(path, refresh=True):
    s = {"host": "api.anthropic.com", "style": "anthropic-oauth",
         "cred_file": path, "token_path": "claudeAiOauth.accessToken"}
    if refresh:
        s["refresh"] = dict(_REFRESH)
    return s


def _load(path):
    with open(path) as f:
        return _json.load(f)["claudeAiOauth"]


posts = []


def _ok_post(url, payload, timeout, user_agent=None):
    posts.append((url, payload, timeout, user_agent))
    return {"access_token": "NEW-ACCESS", "refresh_token": "NEW-REFRESH", "expires_in": 28800}


cs_r = m.CredStore("")
m._http_post_json = _ok_post

# 1. Fresh token -> no POST, file unchanged
posts.clear()
p = _mk_cred("fresh.json", _now_ms(10000))
cs_r.ensure_fresh(_spec_for(p))
check(len(posts) == 0, "refresh: fresh token makes no POST")
check(_load(p)["accessToken"] == "OLD-ACCESS", "refresh: fresh token unchanged")

# 2. Near-expiry token -> refresh, correct payload, rotation, others preserved
posts.clear()
p = _mk_cred("near.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p))
check(len(posts) == 1, "refresh: near-expiry triggers one POST")
check(posts[0][0] == "https://example.invalid/oauth/token", "refresh: posts to token_url")
check(posts[0][1] == {"grant_type": "refresh_token", "refresh_token": "OLD-REFRESH", "client_id": "CID"},
      "refresh: correct grant payload")
check(posts[0][3] == m.DEFAULT_REFRESH_UA, "refresh: sends a harness-like UA (stock urllib UA is WAF-banned)")
d = _load(p)
check(d["accessToken"] == "NEW-ACCESS", "refresh: access token rotated")
check(d["refreshToken"] == "NEW-REFRESH", "refresh: refresh token rotated")
check(_now_ms(28000) < d["expiresAt"] < _now_ms(29000), "refresh: expiresAt set from expires_in (ms)")
check(d["subscriptionType"] == "max" and d["scopes"] == ["user:inference"], "refresh: preserves other fields")
check(not os.path.exists(p + ".cogbox-bak"), "refresh: no token-bearing backup file written")

# 3. Already-expired token still refreshes (refresh token long-lived)
posts.clear()
p = _mk_cred("expired.json", _now_ms(-100))
cs_r.ensure_fresh(_spec_for(p))
check(len(posts) == 1 and _load(p)["accessToken"] == "NEW-ACCESS", "refresh: expired token refreshes")

# 4. No refresh config -> never touches anything
posts.clear()
p = _mk_cred("norefresh.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p, refresh=False))
check(len(posts) == 0 and _load(p)["accessToken"] == "OLD-ACCESS", "refresh: no config is a no-op")

# 5. HTTP failure -> file untouched (fail-safe)
posts.clear()


def _boom(url, payload, timeout, user_agent=None):
    raise OSError("network down")


m._http_post_json = _boom
p = _mk_cred("httpfail.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p))
d = _load(p)
check(d["accessToken"] == "OLD-ACCESS" and d["refreshToken"] == "OLD-REFRESH", "refresh: HTTP failure leaves file untouched")

# 6. Bad response (missing fields) -> file untouched
m._http_post_json = lambda url, payload, timeout, user_agent=None: {"error": "invalid_grant"}
p = _mk_cred("badresp.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p))
check(_load(p)["accessToken"] == "OLD-ACCESS", "refresh: bad response leaves file untouched")

# 7. Response without a rotated refresh token -> keep the existing one
m._http_post_json = lambda url, payload, timeout, user_agent=None: {"access_token": "NEW2", "expires_in": 100}
p = _mk_cred("norotate.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p))
d = _load(p)
check(d["accessToken"] == "NEW2" and d["refreshToken"] == "OLD-REFRESH", "refresh: missing rotated token keeps old refresh token")

# 8. No refresh token on disk -> no POST (cannot refresh)
posts.clear()
m._http_post_json = _ok_post
p = os.path.join(_d, "nortok.json")
with open(p, "w") as f:
    _json.dump({"claudeAiOauth": {"accessToken": "A", "expiresAt": _now_ms(60), "subscriptionType": "max"}}, f)
cs_r.ensure_fresh(_spec_for(p))
check(len(posts) == 0 and _load(p)["accessToken"] == "A", "refresh: no on-disk refresh token -> no POST")

# 9. Non-numeric/absent expiry -> never refreshes (cannot judge freshness)
posts.clear()
p = os.path.join(_d, "noexp.json")
with open(p, "w") as f:
    _json.dump({"claudeAiOauth": {"accessToken": "A", "refreshToken": "R", "subscriptionType": "max"}}, f)
cs_r.ensure_fresh(_spec_for(p))
check(len(posts) == 0, "refresh: missing expiresAt -> no POST")

# 10. No token-bearing write-temp is left in the cred dir after a successful refresh
import glob as _glob
m._http_post_json = _ok_post
p = _mk_cred("clean.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p))
check(_glob.glob(os.path.join(_d, m.CRED_TMP_PREFIX + "*.tmp")) == [],
      "refresh: no write-temp left in cred dir after success")

# 11. A stale write-temp (crash residue) is swept on the next refresh
p = _mk_cred("sweep.json", _now_ms(60))
stale = os.path.join(_d, m.CRED_TMP_PREFIX + "deadbeef.tmp")
with open(stale, "w") as f:
    f.write('{"claudeAiOauth":{"refreshToken":"LEAKED"}}')
cs_r.ensure_fresh(_spec_for(p))
check(not os.path.exists(stale), "refresh: stale write-temp swept from cred dir")

# 12. Cooldown: a failed attempt throttles the next attempt within the window
calls = []


def _count_fail(url, payload, timeout, user_agent=None):
    calls.append(1)
    raise OSError("down")


m._http_post_json = _count_fail
p = _mk_cred("cooldown.json", _now_ms(60))
cs_r.ensure_fresh(_spec_for(p))  # attempts, fails, records attempt
cs_r.ensure_fresh(_spec_for(p))  # within cooldown -> must not POST again
check(len(calls) == 1, "refresh: cooldown throttles repeat attempts after a failure")

# 13. Clobber guard: a rotation that lands DURING our POST is not overwritten
p = _mk_cred("clobber.json", _now_ms(60))
_mt0 = os.stat(p).st_mtime


def _post_then_rotate(url, payload, timeout, user_agent=None):
    # simulate the host CLI rotating the file mid-POST
    with open(p, "w") as f:
        _json.dump({"claudeAiOauth": {"accessToken": "CLI-ACCESS", "refreshToken": "CLI-REFRESH",
                                      "expiresAt": _now_ms(28800), "subscriptionType": "max"}}, f)
    os.utime(p, (_mt0 + 10, _mt0 + 10))  # guarantee a distinct mtime
    return {"access_token": "ADDON-ACCESS", "refresh_token": "ADDON-REFRESH", "expires_in": 28800}


m._http_post_json = _post_then_rotate
cs_r.ensure_fresh(_spec_for(p))
check(_load(p)["accessToken"] == "CLI-ACCESS", "refresh: concurrent rotation not clobbered")

# 14. Write-back preserves the cred file's owner (no-op rootless; guards the
# sudo case where a root-owned rewrite would lock out the user's own CLI).
m._http_post_json = _ok_post
p = _mk_cred("owner.json", _now_ms(60))
_uid_before = os.stat(p).st_uid
cs_r.ensure_fresh(_spec_for(p))
check(_load(p)["accessToken"] == "NEW-ACCESS" and os.stat(p).st_uid == _uid_before,
      "refresh: write-back preserves cred file owner")


# --- request() over PLAIN HTTP (no SNI): injection still fires -------------
# The L7 proxy now routes an http:// inject host through this addon (a plain
# http:// vhost otherwise bypasses it via the native splice, so its cred would
# never be stamped). On such a flow there is NO client SNI, so the addon must
# skip the upstream-SNI set + the Host==SNI guard (both gated on `sni`) and
# still enforce allow/deny on the Host header + inject the host-side credential.
class _Conn:
    def __init__(self, sni=None):
        self.sni = sni


class _Req:
    def __init__(self, host, path, headers):
        self.pretty_host = host
        self.path = path
        self.headers = headers


class _Flow:
    def __init__(self, host, path, headers, sni=None):
        self.client_conn = _Conn(sni)
        self.server_conn = _Conn(None)
        self.request = _Req(host, path, headers)
        self.response = None


_hd = tempfile.mkdtemp()
_http_rules = os.path.join(_hd, "l7-rules")
with open(_http_rules, "w") as f:
    f.write("mode terminate\nallow notes.internal.test\n")
m.RULES_PATH = _http_rules
m.RULES = m.Rules()  # fresh: maybe_reload() loads from the path above

_sid = os.path.join(_hd, "sid")
_write_raw(_sid, "REAL-SESSION-COOKIE\n", 1000)
_http_conf = os.path.join(_hd, "inject.json")
_write(_http_conf, [{"host": "notes.internal.test", "style": "cookie",
                     "cookie_name": "connect.sid", "cred_file": _sid,
                     "cred_format": "raw"}], 1000)
m.CREDS = m.CredStore(_http_conf)

# plain HTTP request (sni=None), no cookie yet -> the session cookie is injected
_h = CIDict({"Host": "notes.internal.test"})
_fl = _Flow("notes.internal.test", "/", _h, sni=None)
m.request(_fl)
check(_fl.response is None, "http inject: allowed no-SNI request is not denied")
check(_h.get("cookie") == "connect.sid=REAL-SESSION-COOKIE",
      "http inject: session cookie injected over plain HTTP (no SNI)")
check(_fl.server_conn.sni is None, "http inject: no upstream SNI set on a no-SNI flow")

# a no-SNI request to an UNLISTED host is denied (default-deny), not injected.
# (Build the flow but assert via evaluate() to avoid _deny -> http.Response,
# which is unavailable without mitmproxy imported.)
check(m.evaluate(m.RULES, "evil.internal.test", "/") == "deny",
      "http inject: unlisted host stays default-deny")


# --- _enforce_and_inject: tag-gated injection end-to-end ------------------
# The hole closed at the injection seam: a spec carrying rules_tag injects the
# owner's token ONLY when a git-grant-tagged rule also allows the request. A
# coexisting whole-host allow grants reachability (no 403) but not the token.
class _GConn:
    def __init__(self, sni=None):
        self.sni = sni


class _GReq:
    def __init__(self, host, method, headers):
        self.pretty_host = host
        self.method = method
        self.headers = headers


class _GFlow:
    def __init__(self, host, method, headers, sni):
        self.client_conn = _GConn(sni)
        self.server_conn = _GConn(None)
        self.request = _GReq(host, method, headers)
        self.response = None


_gd = tempfile.mkdtemp()
_GTOK = "glpat-FAKEFAKEGATE"          # fictional owner token (OSS-clean)
_gcred = os.path.join(_gd, "git-gitlab")
_write_raw(_gcred, _GTOK + "\n", 1000)
_ghost = "git.example.internal"


def _mk_git_flow(path_method="GET"):
    return _GFlow(_ghost, path_method, CIDict({"Host": _ghost}), sni=_ghost)


def _set_rules(text):
    p = os.path.join(_gd, "l7-rules-%d" % (len(text)))
    with open(p, "w") as f:
        f.write(text)
    m.RULES_PATH = p
    m.RULES = m.Rules()  # _enforce_and_inject's maybe_reload() loads from RULES_PATH


def _set_spec(with_tag):
    spec = {"host": _ghost, "style": "gitlab-oauth", "cred_file": _gcred,
            "cred_format": "raw", "git_user": "oauth2",
            "stub_token": "glpat-cogbox-host-injected-placeholder"}  # gitleaks:allow
    if with_tag:
        spec["rules_tag"] = "git-grants"
    conf = os.path.join(_gd, "inject-%s.json" % with_tag)
    _write(conf, [spec], 1000)
    m.CREDS = m.CredStore(conf)


# Scenario A: spec WITH rules_tag, path NOT covered by any tagged rule.
# Rules: untagged whole-host allow (reachability) + a tagged narrow allow that
# does NOT cover /api/v4/projects/other. Injection must be gated OFF.
_set_rules("mode terminate\n"
           "allow git.example.internal\n"
           "allow git.example.internal GET /api/v4/projects/1234/ tag=git-grants\n")
_set_spec(with_tag=True)
_flA = _mk_git_flow("GET")
m._enforce_and_inject(_flA, "/api/v4/projects/other")
check(_flA.response is None, "inject gate A: request still ALLOWED (reachability), not 403")
check(_flA.request.headers.get("authorization") is None,
      "inject gate A: owner token NOT injected on a path only the whole-host allow reached")

# Scenario B: spec WITH rules_tag, path IS covered by a tagged rule -> inject.
_set_spec(with_tag=True)
_flB = _mk_git_flow("GET")
m._enforce_and_inject(_flB, "/api/v4/projects/1234/issues")
check(_flB.response is None, "inject gate B: tagged request allowed")
check(_flB.request.headers.get("authorization") == "Bearer " + _GTOK,
      "inject gate B: a git-grant-tagged rule covers the request -> owner token injected")

# Scenario C: spec WITHOUT rules_tag (legacy / non-git) -> whole-host injection.
_set_rules("mode terminate\nallow git.example.internal\n")
_set_spec(with_tag=False)
_flC = _mk_git_flow("GET")
m._enforce_and_inject(_flC, "/api/v4/projects/1234/issues")
check(_flC.response is None, "inject gate C: allowed")
check(_flC.request.headers.get("authorization") == "Bearer " + _GTOK,
      "inject gate C: a spec with no rules_tag keeps whole-host injection (ungated)")


# --- method-override headers are stripped -----------------------------------
# Rules are matched on the WIRE method (flow.request.method); Rack::MethodOverride
# and friends rewrite the request to the method one of these headers names. A
# surviving header would let a POST the rules allow be executed as the DELETE they
# exclude, with the owner's token already injected. Stripping is unconditional --
# allowed or denied, injected or not -- so the origin always acts on the same
# method the decision was made on.
_set_rules("mode terminate\n"
           "allow git.example.internal POST,PUT /api/v4/projects/#/issues tag=git-grants\n")
_set_spec(with_tag=True)
_flD = _GFlow(_ghost, "POST", CIDict({
    "Host": _ghost,
    "X-HTTP-Method-Override": "DELETE",
    "X-Method-Override": "DELETE",
    "X-HTTP-Method": "DELETE",
}), sni=_ghost)
m._enforce_and_inject(_flD, "/api/v4/projects/1234/issues/9")
check(_flD.response is None, "method override: the POST itself is still allowed")
for _h in m.METHOD_OVERRIDE_HEADERS:
    check(_flD.request.headers.get(_h) is None,
          "method override: %s stripped before the request is forwarded" % _h)
check(_flD.request.headers.get("authorization") == "Bearer " + _GTOK,
      "method override: injection is unaffected")

# The primitive on its own: every spelling, case-insensitively, and it reports
# what it removed. (_enforce_and_inject calls it as its FIRST act, before the
# method is read, so the denied path is covered by construction -- a denied flow
# cannot be exercised here because _deny needs mitmproxy's http module.)
_ovh = CIDict({"x-http-method-override": "DELETE", "X-Method-Override": "PATCH",
               "X-HTTP-METHOD": "PUT", "Authorization": "Bearer keep-me"})
check(sorted(m.strip_method_override(_ovh)) == sorted(m.METHOD_OVERRIDE_HEADERS),
      "strip_method_override: reports every removed spelling")
for _h in m.METHOD_OVERRIDE_HEADERS:
    check(_h not in _ovh, "strip_method_override: %s gone" % _h)
check(_ovh.get("authorization") == "Bearer keep-me",
      "strip_method_override: touches nothing else")
check(m.strip_method_override(CIDict({})) == [], "strip_method_override: no-op on a clean request")

# The numeric wildcard, end to end through the real rule parser and evaluator:
# the tail-absorption shape a `*` rule would have ALLOWED must be denied here.
check(m.evaluate(m.RULES, _ghost, m.normalize_path(
    "/api/v4/projects/mygroup%2Fissues/access_tokens"), "POST") == "deny",
      "numeric wildcard: a %2F-encoded id whose last component is the literal tail is DENIED")
check(m.evaluate(m.RULES, _ghost, m.normalize_path(
    "/api/v4/projects/1234/issues"), "POST") == "allow",
      "numeric wildcard: the numeric-id form is still allowed")


# --- auth-proxy retargeting (X-Cogbox-* strip + retarget + injection skip) ---
# A host in l7-auth-hosts is steered to the loopback auth-proxy hop instead of
# being injected here: the addon strips every X-Cogbox-* header, sets the three
# reserved ones (route key, vetted upstream, original scheme), rewrites the
# DATA host/port (never the properties), forces scheme=http, and returns BEFORE
# the injection block. A host NOT in the set takes the unchanged legacy path.

# strip_cogbox_headers: every X-Cogbox-* spelling gone, nothing else touched.
_ch = CIDict({"X-Cogbox-Host": "forged.test", "x-cogbox-vetted": "1.2.3.4:443",
              "X-COGBOX-Proto": "https", "Authorization": "Bearer keep",
              "X-Other": "keep"})
_removed = m.strip_cogbox_headers(_ch)
check(sorted(x.lower() for x in _removed) ==
      ["x-cogbox-host", "x-cogbox-proto", "x-cogbox-vetted"],
      "strip_cogbox_headers: reports every X-Cogbox-* spelling removed")
for _h in ("x-cogbox-host", "x-cogbox-vetted", "x-cogbox-proto"):
    check(_h not in _ch, "strip_cogbox_headers: %s gone" % _h)
check(_ch.get("authorization") == "Bearer keep" and _ch.get("x-other") == "keep",
      "strip_cogbox_headers: touches no non-cogbox header")
check(m.strip_cogbox_headers(CIDict({})) == [], "strip_cogbox_headers: no-op on a clean request")


# A fake mitmproxy request .data carrier (the SOCKS5 CONNECT address lives here;
# transparent mode seeds .data.host/.data.port from it).
class _Data:
    def __init__(self, host, port):
        self.host = host
        self.port = port


class _ARq:
    def __init__(self, host, method, headers, vetted_ip, vetted_port):
        self.pretty_host = host
        self.method = method
        self.headers = headers
        self.scheme = "https"
        self.data = _Data(vetted_ip, vetted_port)


class _AFlow:
    def __init__(self, host, method, headers, sni, vetted_ip, vetted_port):
        self.client_conn = _GConn(sni)
        self.server_conn = _GConn(None)
        self.request = _ARq(host, method, headers, vetted_ip, vetted_port)
        self.response = None


_ad = tempfile.mkdtemp()
_ahost = "git.example.internal"

# AuthHosts reader: absent path -> empty; a real file -> its hosts; a torn
# (removed) file falls back to empty and re-reads once it reappears.
_ah_none = m.AuthHosts("")
check(not _ah_none.contains(_ahost), "AuthHosts: empty path -> nothing retargeted")
_ahp = os.path.join(_ad, "l7-auth-hosts")
_ahr = m.AuthHosts(_ahp)
check(not _ahr.contains(_ahost), "AuthHosts: missing file -> empty (fail closed)")
with open(_ahp, "w") as f:
    f.write("# migrated providers\n" + _ahost + "\n")
os.utime(_ahp, (2000, 2000))
check(_ahr.contains(_ahost), "AuthHosts: a listed host is owned by the auth proxy")
check(_ahr.contains(_ahost.upper() + "."), "AuthHosts: match is case/trailing-dot insensitive")
check(not _ahr.contains("other.internal"), "AuthHosts: an unlisted host is not owned")
# A removed file drops the cache and falls to empty (fail closed), not stale.
os.remove(_ahp)
check(not _ahr.contains(_ahost), "AuthHosts: a vanished file falls back to empty")

# TORN WRITE (the re-stat-after-read hardening): IMAGE SKEW is the one reason
# this file can tear -- reload.writeL7Inject is its only writer and it renames,
# but an older cogbox than this addon's image still truncates and rewrites in
# place (the two roll on independent tags), leaving a window a read can land
# in. Simulate it by making the PRE-read os.stat of one reload report a
# different (mtime, size) than the post-read one: the reader must keep its
# previous set AND its previous key (no cache advance), so the next poll
# retries on settled bytes.
with open(_ahp, "w") as f:
    f.write(_ahost + "\n")
os.utime(_ahp, (2100, 2100))
check(_ahr.contains(_ahost), "AuthHosts (torn): the settled file loads")
_prev_key = _ahr.stat
_real_stat = m.os.stat
_stat_calls = {"n": 0}


def _torn_stat(p, *a, **kw):
    st = _real_stat(p, *a, **kw)
    if p == _ahp:
        _stat_calls["n"] += 1
        if _stat_calls["n"] == 1:
            # the pre-read stat: pretend the file is a NEW, larger version
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                                   st.st_uid, st.st_gid, st.st_size + 40,
                                   st.st_atime, 2200, st.st_ctime))
    return st


m.os.stat = _torn_stat
try:
    _ahr.maybe_reload()
finally:
    m.os.stat = _real_stat
check(_ahr.stat == _prev_key,
      "AuthHosts (torn): a read whose post-read stat disagrees does NOT advance the cache")
check(_ahr.contains(_ahost) and _ahr.stat == _prev_key,
      "AuthHosts (torn): the previous (settled) set stays live meanwhile")
# ...and once the file really changes, the next poll commits the new bytes.
with open(_ahp, "w") as f:
    f.write(_ahost + "\nother.example.com\n")
os.utime(_ahp, (2300, 2300))
check(_ahr.contains("other.example.com") and _ahr.stat != _prev_key,
      "AuthHosts (torn): the next settled change is picked up")


def _set_auth(port, hosts):
    p = os.path.join(_ad, "auth-hosts-%s" % ("-".join(hosts) or "none"))
    with open(p, "w") as f:
        f.write("".join(h + "\n" for h in hosts))
    os.utime(p, (3000, 3000))
    m.AUTH_HOSTS = m.AuthHosts(p)
    m.AUTH_PORT = str(port)


# The retarget decision end to end: a migrated host is retargeted, NOT injected.
m.RULES_PATH = os.path.join(_ad, "l7-rules")
with open(m.RULES_PATH, "w") as f:
    f.write("mode terminate\nallow git.example.internal --path /\n"
            .replace(" --path /", " /"))  # `allow <host> /` (funnel shape)
m.RULES = m.Rules()
# A stale gitlab-oauth spec ALSO names the host (the mode-flip conflict): the
# retarget must win and NOT inject, and the conflict must be logged once.
_acred = os.path.join(_ad, "git-gitlab")
_write_raw(_acred, "glpat-STALE\n", 5000)
_aconf = os.path.join(_ad, "auth-inject.json")
_write(_aconf, [{"host": _ahost, "style": "gitlab-oauth", "cred_file": _acred,
                 "cred_format": "raw", "git_user": "oauth2",
                 "rules_tag": "git-grants",
                 "stub_token": "glpat-cogbox-host-injected-placeholder"}],  # gitleaks:allow
       5000)
m.CREDS = m.CredStore(_aconf)
_set_auth(19999, [_ahost])

_conflicts = []
_orig_cred_log = m._cred_log
m._cred_log = lambda msg: _conflicts.append(msg)
try:
    _afl = _AFlow(_ahost, "GET", CIDict({
        "Host": _ahost,
        "X-Cogbox-Host": "forged-by-guest.test",  # must be stripped, then re-set
    }), sni=_ahost, vetted_ip="203.0.113.9", vetted_port=443)
    m._enforce_and_inject(_afl, "/api/v4/projects/1234/issues")
finally:
    m._cred_log = _orig_cred_log

check(_afl.response is None, "retarget: an allowed migrated host is not denied")
check(_afl.request.headers.get("x-cogbox-host") == _ahost,
      "retarget: X-Cogbox-Host is the real host (the guest's forged one was stripped first)")
check(_afl.request.headers.get("x-cogbox-vetted") == "203.0.113.9:443",
      "retarget: X-Cogbox-Vetted carries l7proxy's pinned upstream captured before the retarget")
check(_afl.request.headers.get("x-cogbox-proto") == "https",
      "retarget: X-Cogbox-Proto records the guest's original (TLS) scheme")
check(_afl.request.data.host == "127.0.0.1" and _afl.request.data.port == 19999,
      "retarget: .data host/port point at the loopback auth-proxy hop")
check(_afl.request.scheme == "http", "retarget: the loopback hop is forced to http")
check(_afl.request.headers.get("authorization") is None,
      "retarget: NO credential is injected here (the auth proxy stamps it) even with a stale spec")
check(any("CONFLICT" in c and _ahost in c for c in _conflicts),
      "retarget: a host with both a spec and an auth entry logs a one-shot conflict")

# The conflict log is one-shot per conf generation: a second flow does not re-log.
_conflicts2 = []
m._cred_log = lambda msg: _conflicts2.append(msg)
try:
    _afl2 = _AFlow(_ahost, "GET", CIDict({"Host": _ahost}),
                   sni=_ahost, vetted_ip="203.0.113.9", vetted_port=443)
    m._enforce_and_inject(_afl2, "/api/v4/projects/1234/issues")
finally:
    m._cred_log = _orig_cred_log
check(not any("CONFLICT" in c for c in _conflicts2),
      "retarget: the conflict warning is one-shot per conf generation")

# Auth port unusable / no vetted upstream -> retarget refuses (the caller then
# fails closed via _deny, which needs mitmproxy; assert the primitive directly).
m.AUTH_PORT = ""
_afl3 = _AFlow(_ahost, "GET", CIDict({"Host": _ahost}),
               sni=_ahost, vetted_ip="203.0.113.9", vetted_port=443)
check(not m.retarget_to_authproxy(_afl3, _ahost, _ahost),
      "retarget: an unusable auth port refuses (caller fails closed)")
check(_afl3.request.data.host == "203.0.113.9",
      "retarget: a refused retarget leaves the upstream untouched")
m.AUTH_PORT = "19999"
_afl4 = _AFlow(_ahost, "GET", CIDict({"Host": _ahost}), sni=_ahost,
               vetted_ip="", vetted_port=0)
check(not m.retarget_to_authproxy(_afl4, _ahost, _ahost),
      "retarget: a flow with no vetted upstream refuses (never resolves the host itself)")

# LEGACY PATH UNCHANGED: with the hosts file absent/empty, a NON-migrated host
# is injected exactly as before -- byte-identical to Scenario C above, and the
# request is never retargeted.
_set_auth(19999, [])  # empty auth set
_set_spec(with_tag=False)  # from the tag-gate block: a plain whole-host spec
m.RULES_PATH = os.path.join(_ad, "legacy-rules")
with open(m.RULES_PATH, "w") as f:
    f.write("mode terminate\nallow git.example.internal\n")
m.RULES = m.Rules()
_leg = _AFlow(_ahost, "GET", CIDict({"Host": _ahost}),
              sni=_ahost, vetted_ip="203.0.113.9", vetted_port=443)
m._enforce_and_inject(_leg, "/api/v4/projects/1234/issues")
check(_leg.response is None, "legacy path: allowed")
check(_leg.request.data.host == "203.0.113.9" and _leg.request.scheme == "https",
      "legacy path: a non-migrated host is NOT retargeted (data/scheme untouched)")
check(_leg.request.headers.get("authorization") == "Bearer " + _GTOK,
      "legacy path: a non-migrated host is injected here, exactly as before")
check(_leg.request.headers.get("x-cogbox-host") is None,
      "legacy path: no reserved header is set on a non-migrated flow")


# --- the polled-file contract: CredStore + Rules ----------------------------
# The renderer publishes these files atomically now (writeRuntimeFile: sibling
# tmp, fsync, rename), but the readers keep the torn-read hardening, because the
# addon's image and the cogbox binary that renders roll on INDEPENDENT tags -- this
# reader can be running against an older writer that still truncates in place.
# (The inject conf's second writer, cogbox-launch.sh's merge, is NOT a reason: it
# publishes with `mv`, which cannot tear. Its hazard is content, and it is the
# renderer that answers for it -- see reload.writeL7Inject.) Neither reader may
# install what it got from a torn read: the previous specs/rules stay live and
# the cache key must NOT advance, or the torn state sticks until the next
# unrelated render.
_pd = tempfile.mkdtemp()
_phost = "git.example.com"
_pcred = os.path.join(_pd, "git-token")
_write_raw(_pcred, "glpat-FAKEPOLLED\n", 1000)  # fictional owner token (OSS-clean)
_pspec = {"host": _phost, "style": "gitlab-oauth", "cred_file": _pcred,
          "cred_format": "raw", "git_user": "oauth2",
          "stub_token": "glpat-cogbox-host-injected-placeholder"}  # gitleaks:allow
_pconf = os.path.join(_pd, "inject.json")
_write(_pconf, [_pspec], 1000)

_pcs = m.CredStore(_pconf)
check(_pcs.spec_for(_phost) is not None, "CredStore (torn): the settled conf loads")
check(not _pcs.conf_stale, "CredStore (torn): a settled conf is not stale")
_pkey = _pcs.stat

# TORN READ: the renderer has truncated and not yet rewritten -- the poll sees an
# EMPTY file (a size+mtime change, so the cache misses, and a parse failure).
with open(_pconf, "w") as f:
    f.write("")
os.utime(_pconf, (1100, 1100))
check(_pcs.spec_for(_phost) is not None,
      "CredStore (torn): an empty file mid-write keeps the PREVIOUS specs (never {})")
check(_pcs.stat == _pkey,
      "CredStore (torn): a failed parse does NOT advance the cache key")
check(_pcs.conf_stale,
      "CredStore (torn): the conf is marked stale while it cannot be read")

# ...and the settled rewrite that follows is picked up on the very next poll.
_write(_pconf, [_pspec, dict(_pspec, host="api.example.com")], 1200)
check(_pcs.spec_for("api.example.com") is not None,
      "CredStore (torn): the next settled write is picked up")
check(_pcs.stat != _pkey and not _pcs.conf_stale,
      "CredStore (torn): a good read advances the key and clears the stale mark")

# The renderer's provenance stamp (rules/reload.zig render_origin_field) rides in
# the same spec objects: it tells a rendered spec from one the launcher merged in,
# on the WRITE side only. This reader must ignore it like any unknown key -- if it
# ever became load-bearing here, a spec would stop injecting the moment the two
# images disagreed about the field.
_write(_pconf, [dict(_pspec, origin="render")], 1300)
check(_pcs.spec_for(_phost) is not None,
      "CredStore: an unknown `origin` field (the renderer's provenance stamp) is ignored")
check(_pcs.token_for(_pcs.spec_for(_phost)) == "glpat-FAKEPOLLED",
      "CredStore: a stamped spec still resolves its credential")

# Rules: a torn read still PARSES (a truncated rule list is valid syntax), so the
# post-read stat is the only tell -- same simulation as the AuthHosts case above.
_prules = os.path.join(_pd, "l7-rules")
with open(_prules, "w") as f:
    f.write("mode terminate\nallow git.example.com\n")
os.utime(_prules, (2100, 2100))
m.RULES_PATH = _prules
_pr = m.Rules()
_pr.maybe_reload()
check(len(_pr.rules) == 1, "Rules (torn): the settled file loads")
_prkey = _pr.stat
with open(_prules, "w") as f:
    f.write("mode terminate\nallow git.example.com\nallow api.example.com\n")
os.utime(_prules, (2200, 2200))

_real_stat2 = m.os.stat
_pstat_calls = {"n": 0}


def _torn_stat2(p, *a, **kw):
    st = _real_stat2(p, *a, **kw)
    if p == _prules:
        _pstat_calls["n"] += 1
        if _pstat_calls["n"] == 1:
            # the pre-read stat: pretend a NEWER, larger version is on disk, so
            # the post-read stat disagrees and the bytes we parsed are torn
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                                   st.st_uid, st.st_gid, st.st_size + 40,
                                   st.st_atime, 2300, st.st_ctime))
    return st


m.os.stat = _torn_stat2
try:
    _pr.maybe_reload()
finally:
    m.os.stat = _real_stat2
check(len(_pr.rules) == 1,
      "Rules (torn): the PREVIOUS rule list stays live (never partial, never [])")
check(_pr.stat == _prkey,
      "Rules (torn): a read whose post-read stat disagrees does NOT advance the cache")
_pr.maybe_reload()
check(len(_pr.rules) == 2,
      "Rules (torn): the next settled poll commits the new rules (the key never stuck)")


# --- fail CLOSED when the inject conf is unreadable --------------------------
# With no spec for a host the addon used to forward the guest's PLACEHOLDER
# bearer upstream: the provider 401s and claude-code reads that as "log in
# again". A host the last good conf named must get a 403 instead. (_deny needs
# mitmproxy's http module; stub the one call it makes.)
class _RespStub:
    def __init__(self, status_code, content, headers):
        self.status_code = status_code
        self.content = content
        self.headers = headers


class _HttpStub:
    class Response:
        @staticmethod
        def make(status_code, content, headers):
            return _RespStub(status_code, content, headers)


with open(_prules, "w") as f:
    f.write("mode terminate\nallow git.example.com\nallow other.example.com\n")
os.utime(_prules, (2400, 2400))
m.RULES = m.Rules()
m.CREDS = _pcs
m.AUTH_HOSTS = m.AuthHosts("")  # no retargeting on this path
_STUB = "Bearer " + _pspec["stub_token"]
_orig_http = m.http
m.http = _HttpStub
try:
    # baseline: with a readable conf the placeholder is REPLACED by the real token
    _fok = _GFlow(_phost, "GET", CIDict({"Host": _phost, "Authorization": _STUB}),
                  sni=_phost)
    m._enforce_and_inject(_fok, "/api/v4/projects/1234/issues")
    check(_fok.response is None and _fok.request.headers.get("authorization")
          == "Bearer glpat-FAKEPOLLED",
          "fail-closed: a readable conf still injects the real token")

    os.remove(_pconf)  # the conf goes away under a live proxy
    _f403 = _GFlow(_phost, "GET", CIDict({"Host": _phost, "Authorization": _STUB}),
                   sni=_phost)
    m._enforce_and_inject(_f403, "/api/v4/projects/1234/issues")
    check(_f403.response is not None and _f403.response.status_code == 403,
          "fail-closed: an unreadable conf 403s a host the last good conf named")
    check(b"inject conf unavailable" in _f403.response.content,
          "fail-closed: the 403 names the cause")
    check(_f403.request.headers.get("authorization") == _STUB,
          "fail-closed: the guest's placeholder is NOT forwarded as real auth "
          "(the request is denied before it leaves the proxy)")

    # a host that was NEVER in any spec set is unaffected: legacy end-to-end.
    _fleg = _GFlow("other.example.com", "GET",
                   CIDict({"Host": "other.example.com",
                           "Authorization": "Bearer GUEST-OWN"}), sni="other.example.com")
    m._enforce_and_inject(_fleg, "/api/v4/projects/1234/issues")
    check(_fleg.response is None,
          "fail-closed: a host that never had a spec is not denied by a stale conf")
    check(_fleg.request.headers.get("authorization") == "Bearer GUEST-OWN",
          "fail-closed: that host's own credential is forwarded untouched")

    # ...but the deny is exactly as SURGICAL as the healthy path. A request on an
    # injected host carrying a REAL secondary credential (the one the guest
    # legitimately obtained through an already-injected call) is one should_inject
    # would have left alone, so a conf that cannot be read must cost injection --
    # not the host. Otherwise a persistently unreadable conf (EACCES after a
    # permissions regression: conf_stale has no timeout) is a total outage.
    _fsec = _GFlow(_phost, "GET",
                   CIDict({"Host": _phost,
                           "Authorization": "Bearer bridge-cred-not-the-stub"}),
                   sni=_phost)
    m._enforce_and_inject(_fsec, "/api/v4/projects/1234/issues")
    check(_fsec.response is None,
          "fail-closed: an unreadable conf does NOT deny a request bearing a real "
          "secondary credential")
    check(_fsec.request.headers.get("authorization") == "Bearer bridge-cred-not-the-stub",
          "fail-closed: that secondary credential is forwarded untouched")

    # The remembered shape carries the gitlab per-path style resolution too: the
    # question asked here is should_inject's, with should_inject's inputs, so on a
    # git smart-HTTP path the stub is compared the BASIC way (a bearer-only
    # comparison would forward the placeholder and 401 the user out of git).
    _basic_stub = "Basic " + _b64.b64encode(_pspec["stub_token"].encode()).decode()
    _fgit = _GFlow(_phost, "GET",
                   CIDict({"Host": _phost, "Authorization": _basic_stub}), sni=_phost)
    m._enforce_and_inject(_fgit, "/grp/repo.git/info/refs")
    check(_fgit.response is not None and _fgit.response.status_code == 403,
          "fail-closed: the BASIC-spelled placeholder on a git path is denied too")
    # ...and a git-path request carrying NO credential is denied as well (that is
    # a request the healthy path would have stamped).
    _fbare = _GFlow(_phost, "GET", CIDict({"Host": _phost}), sni=_phost)
    m._enforce_and_inject(_fbare, "/grp/repo.git/git-upload-pack")
    check(_fbare.response is not None and _fbare.response.status_code == 403,
          "fail-closed: an uncredentialed request to an injected host is denied")
finally:
    m.http = _orig_http


# --- the credential-value readers never cache a FAILED read ------------------
# _read_json/_read_raw used to store (mtime, None) on a transient open failure,
# under a key a later successful read would not move: one EACCES (the render's
# revoke-then-regrant window), EMFILE or ENOMEM on a file whose mtime then stays
# put turned into a permanent 403 "credential unavailable" for that host with no
# self-heal. They also keyed on second-resolution st_mtime, so a rotation landing
# in the same second as the last read was invisible.
_kd = tempfile.mkdtemp()
_kraw = os.path.join(_kd, "raw-token")
_write_raw(_kraw, "tok-first\n", 3000)
_kspec = {"host": "api.example.com", "style": "bearer",
          "cred_file": _kraw, "cred_format": "raw"}
_kcs = m.CredStore("")  # injection not configured; the value readers are standalone
check(_kcs.token_for(_kspec) == "tok-first", "cred cache: the settled value reads")

# A rotation lands (new key), and the read that would pick it up fails.
_write_raw(_kraw, "tok-second\n", 3100)


def _boom_open(*a, **kw):
    raise OSError(13, "Permission denied")


_real_open = m.open if "open" in vars(m) else None
m.open = _boom_open
try:
    check(_kcs.token_for(_kspec) is None,
          "cred cache: a failed read fails closed (no value)")
finally:
    if _real_open is None:
        del m.open
    else:
        m.open = _real_open
check(_kcs.token_for(_kspec) == "tok-second",
      "cred cache: the failure was NOT cached -- the next request re-reads and "
      "self-heals to the rotated value")

# Same for the JSON reader.
_kjson = os.path.join(_kd, "creds.json")
_write(_kjson, {"claudeAiOauth": {"accessToken": "OAT-A"}}, 3000)
_kjspec = {"host": "api.anthropic.com", "style": "anthropic-oauth",
           "cred_file": _kjson, "token_path": "claudeAiOauth.accessToken"}
check(_kcs.token_for(_kjspec) == "OAT-A", "cred cache (json): the settled value reads")
_write(_kjson, {"claudeAiOauth": {"accessToken": "OAT-B"}}, 3100)
m.open = _boom_open
try:
    check(_kcs.token_for(_kjspec) is None, "cred cache (json): a failed read fails closed")
finally:
    if _real_open is None:
        del m.open
    else:
        m.open = _real_open
check(_kcs.token_for(_kjspec) == "OAT-B",
      "cred cache (json): the failure was NOT cached -- the next request self-heals")

# A file that is present but BLANK is an answer, not a failure: cached as None
# under its own key, and re-read once the key moves.
_kblank = os.path.join(_kd, "blank")
_write_raw(_kblank, "\n", 3200)
_kbspec = {"host": "api.example.com", "style": "bearer",
           "cred_file": _kblank, "cred_format": "raw"}
check(_kcs.token_for(_kbspec) is None, "cred cache: a blank cred file is None (fail closed)")
_write_raw(_kblank, "tok-late\n", 3300)
check(_kcs.token_for(_kbspec) == "tok-late",
      "cred cache: a value written later is picked up on the next key change")


if fails:
    print("FAIL:", *fails, sep="\n  ")
    sys.exit(1)
print("all addon parity tests passed")
