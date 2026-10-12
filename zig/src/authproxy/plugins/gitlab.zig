// gitlab -- plugin #1, at parity with the compiled-rule tier plus the approved
// v1 archive route (plan decision 3), the v1.1 namespace-enumeration route and
// the v2 fine-capability split (the four coarse caps become twelve, and four
// new API areas -- pipelines, jobs, the repository READ API and wikis -- become
// expressible).
//
// The 16-route table, first match wins, unmatched => gate-1 deny:
//
//   git-refs             GET        <project-ref>[.git]/info/refs?service=...   stream
//   git-upload           POST       <project-ref>[.git]/git-upload-pack         stream
//   git-receive          POST       <project-ref>[.git]/git-receive-pack        stream
//   api-user             GET,HEAD   /api/v4/user
//   api-version          GET,HEAD   /api/v4/version
//   api-project          GET,HEAD   /api/v4/projects/:id
//   api-group-projects   GET,HEAD   /api/v4/groups/<group-path>/projects
//   api-issues           GET,HEAD,POST,PUT  /api/v4/projects/:id/issues[/...]
//   api-mr               GET,HEAD,POST,PUT  .../merge_requests[/...], NOT the merge class
//   api-mr-merge         GET,HEAD,POST,PUT  .../merge_requests/<iid>/<merge-class tail>[/...]
//   api-pipelines        GET,HEAD + POST on <id>/{retry,cancel}   .../pipelines[/...]
//   api-pipeline-trigger POST       .../pipeline
//   api-jobs             GET,HEAD + POST on <id>/{retry,cancel,play}  .../jobs[/...]
//   api-repo             GET,HEAD   .../repository/<collection>[/...]
//   api-wiki             GET,HEAD,POST,PUT  .../wikis[/...]
//   api-archive          GET,HEAD   .../repository/archive[.<ext>]              stream
//
// Everything else -- access_tokens, variables (the CI/CD kind AND
// `/pipelines/:id/variables`), deploy_keys, every OTHER groups tail (and the
// group node itself), /-/**, /uploads, /assets, raw, registries, /oauth/**,
// /admin, info/lfs/**, gitlab-lfs/**, git-upload-archive, GraphQL, snippets and
// packages -- routes NOWHERE. `service` is a parameter of exactly ONE route
// (git-refs), and /api/** can never be a git route, so the service-laundering
// class closes structurally.
//
// Three invariants the table encodes, each load-bearing:
//
//   1. DELETE is in NO capability's method set, on any route. It is
//      irreversible and nothing in the headline flows needs it; a future
//      `*:delete` cap is the extension point.
//   2. REPOSITORY WRITES THROUGH THE API ARE UNROUTABLE. `api-repo` is clamped
//      to GET/HEAD, so `POST /repository/commits`, `POST|PUT
//      /repository/files/*` and the branch/tag write endpoints are refused
//      (`method_not_allowed`) no matter how wide the grant -- including a
//      `git-write` one. They would otherwise write to a branch without ever
//      passing through receive-pack, i.e. straight past the per-grant push
//      rules. Repository mutation goes through `git push`, where the rules
//      live. `archive` stays its own streaming route (`api-archive`).
//   3. `/pipelines/:id/variables` is a NAMED no_route, not a method clamp: the
//      variables of a pipeline are secrets the sandbox may not read even with
//      `pipelines:read`.
//
// Plus ONE plugin-owned LOCAL route, matched BEFORE the table above and NEVER
// proxied upstream (Route.local, answered by localResponse):
//
//   cogbox-grants       GET,HEAD   /_cogbox/grants   local self-discovery JSON
//
// `_cogbox` is a RESERVED first segment: the guest reaches it through the
// retargeted host, but it reflects THIS sandbox's own grants back as JSON from
// the compiled policy -- no credential, no upstream. Any other `_cogbox/**`
// path is a named gate-1 deny.
//
// ONE route is additionally MEDIATED: `git-receive`, and only under a grant
// that carries push rules. The receive-pack command list is read out of the
// request body and matched against the grant's ref patterns BEFORE any dial
// (see "push rules" below). Every other route -- and every push no covering
// grant restricts -- takes the pure-passthrough arm with the body untouched.

const std = @import("std");
const canon = @import("../canon.zig");
const conf = @import("../conf.zig");
const plugin_mod = @import("../plugin.zig");
const pktline = @import("../pktline.zig");
const upstream_mod = @import("../upstream.zig");

pub const plugin: plugin_mod.Plugin = .{
	.name = "gitlab",
	.compile = compile,
};

const vtable: plugin_mod.Policy.VTable = .{
	.classify = classify,
	.authorize = authorize,
	.upstream = upstream,
	.authenticate = authenticate,
	// The ONE body-aware seam: per-grant push rules, which can only be decided
	// over a receive-pack command list. It answers `false` -- pure passthrough,
	// body reader untouched -- for every other route AND for a push no covering
	// grant restricts, so the unrestricted relay is byte-identical to what it
	// was when this was null.
	.mediate = mediateReceivePack,
	// Genuinely ABSENT, not no-op: the owner token is refreshed only by cogworx
	// (spec §3.2), so there is no derived token to invalidate on a 401.
	.onUpstreamStatus = null,
	// The /_cogbox/grants self-discovery reflection route (Route.local).
	.localResponse = localResponse,
};

/// The twelve v2 capabilities, ORTHOGONAL: `issues:write` does not imply
/// `issues:read`, `mr:merge` does not imply `mr:write`. The document is a
/// compiled artifact whose meaning must be readable without an implication
/// table three codebases could drift on; the control plane's UI auto-ticks the
/// read half as a client courtesy, and that courtesy is never enforced here.
const Caps = struct {
	git_read: bool = false,
	git_write: bool = false,
	issues_read: bool = false,
	issues_write: bool = false,
	mr_read: bool = false,
	mr_write: bool = false,
	mr_merge: bool = false,
	pipelines_read: bool = false,
	pipelines_write: bool = false,
	repo_read: bool = false,
	wiki_read: bool = false,
	wiki_write: bool = false,

	/// Any capability at all -- the gate on the routes that name no resource
	/// class of their own (the ambient two and api-project, which additionally
	/// takes the scope test).
	fn anyCap(self: Caps) bool {
		inline for (@typeInfo(Caps).@"struct".fields) |f| {
			if (@field(self, f.name)) return true;
		}
		return false;
	}
};

/// One `refs/...` glob from a grant's push rules, pre-split into components.
/// `raw` is kept for the self-discovery reflection, which echoes the pattern
/// the owner typed rather than a re-joined normalization.
const RefPattern = struct {
	raw: []const u8,
	comps: []const []const u8,
};

/// A grant's compiled push rules. `refs` empty means "any refname"; the two
/// deny flags are independent of the patterns. Evaluated against the
/// receive-pack command list, never against a route.
const PushRules = struct {
	refs: []const RefPattern,
	deny_delete: bool,
	deny_tags: bool,
};

/// At most this many ref patterns per grant, each at most this many bytes: the
/// mirror of the control plane's admission check, so a document that somehow
/// got past it still fails closed here rather than costing an unbounded walk
/// per pushed command.
const max_push_patterns = 8;
const max_push_pattern_bytes = 128;

const Scope = enum { project, namespace, instance };

const CGrant = struct {
	id: []const u8,
	scope: Scope,
	repo: ?[]const u8,
	prefix: ?[]const u8,
	project_id: ?i64,
	projects: []const conf.Project,
	caps: Caps,
	/// null == unrestricted push (and the receive-pack fast path).
	push: ?PushRules,
};

const Compiled = struct {
	host: []const u8,
	scheme: plugin_mod.Scheme,
	git_user: []const u8,
	grants: []CGrant,
};

/// Fold one capability string into the set. Accepts the twelve v2 names and
/// the two LEGACY coarse ones, which EXPAND (the mirror of cogworx's
/// NormalizeGitCaps): `issues` was read+write, and v1 `mr` INCLUDED
/// approve/merge, so it becomes the whole mr triple. Returns false on anything
/// unrecognized -- api-read/api-full do not exist in the code and never did.
fn applyCap(caps: *Caps, cap: []const u8) bool {
	if (std.mem.eql(u8, cap, "git-read")) {
		caps.git_read = true;
	} else if (std.mem.eql(u8, cap, "git-write")) {
		caps.git_write = true;
	} else if (std.mem.eql(u8, cap, "issues:read")) {
		caps.issues_read = true;
	} else if (std.mem.eql(u8, cap, "issues:write")) {
		caps.issues_write = true;
	} else if (std.mem.eql(u8, cap, "mr:read")) {
		caps.mr_read = true;
	} else if (std.mem.eql(u8, cap, "mr:write")) {
		caps.mr_write = true;
	} else if (std.mem.eql(u8, cap, "mr:merge")) {
		caps.mr_merge = true;
	} else if (std.mem.eql(u8, cap, "pipelines:read")) {
		caps.pipelines_read = true;
	} else if (std.mem.eql(u8, cap, "pipelines:write")) {
		caps.pipelines_write = true;
	} else if (std.mem.eql(u8, cap, "repo:read")) {
		caps.repo_read = true;
	} else if (std.mem.eql(u8, cap, "wiki:read")) {
		caps.wiki_read = true;
	} else if (std.mem.eql(u8, cap, "wiki:write")) {
		caps.wiki_write = true;
	} else if (std.mem.eql(u8, cap, "issues")) {
		caps.issues_read = true;
		caps.issues_write = true;
	} else if (std.mem.eql(u8, cap, "mr")) {
		caps.mr_read = true;
		caps.mr_write = true;
		caps.mr_merge = true;
	} else {
		return false;
	}
	return true;
}

/// A ref pattern's grammar, checked at COMPILE time so a malformed one can
/// never be evaluated per push: at most `max_push_pattern_bytes`, anchored at
/// `refs/heads/` or `refs/tags/` (nothing else is pushable through
/// receive-pack that a branch rule should speak about), no trailing `/`, and
/// every component either `*` (exactly one component), `**` (one or more) or a
/// literal drawn from `[A-Za-z0-9._-]` that is not `.`/`..`, does not begin
/// with `.` and does not end in `.lock` -- the pattern-side subset of
/// `git check-ref-format`. Returns the split components (arena-owned) or null.
fn compileRefPattern(arena: std.mem.Allocator, raw: []const u8) plugin_mod.CompileError!?RefPattern {
	if (raw.len == 0 or raw.len > max_push_pattern_bytes) return null;
	if (!std.mem.startsWith(u8, raw, "refs/heads/") and !std.mem.startsWith(u8, raw, "refs/tags/")) return null;
	if (raw[raw.len - 1] == '/') return null;
	var n: usize = 1;
	for (raw) |b| {
		if (b == '/') n += 1;
	}
	const comps = try arena.alloc([]const u8, n);
	var it = std.mem.splitScalar(u8, raw, '/');
	var i: usize = 0;
	while (it.next()) |comp| : (i += 1) {
		if (!refPatternComponentOk(comp)) return null;
		comps[i] = comp;
	}
	return .{ .raw = raw, .comps = comps };
}

fn refPatternComponentOk(comp: []const u8) bool {
	if (comp.len == 0) return false;
	if (std.mem.eql(u8, comp, "*") or std.mem.eql(u8, comp, "**")) return true;
	if (comp[0] == '.') return false; // `.`, `..` and any dotfile component
	if (std.mem.endsWith(u8, comp, ".lock")) return false;
	for (comp) |b| {
		const ok = (b >= 'A' and b <= 'Z') or (b >= 'a' and b <= 'z') or
			(b >= '0' and b <= '9') or b == '.' or b == '_' or b == '-';
		if (!ok) return false;
	}
	return true;
}

/// Compile a grant's `push` object. Refused (fail closed, whole conf) when the
/// grant has no `git-write` -- a rule on a grant that cannot push is either a
/// control-plane bug or a document someone hand-edited into a false sense of
/// restriction -- when there are more than `max_push_patterns`, or when any
/// pattern fails the grammar.
fn compilePush(arena: std.mem.Allocator, p: conf.Grant.Push, caps: Caps) plugin_mod.CompileError!PushRules {
	if (!caps.git_write) return error.InvalidEntry;
	if (p.refs.len > max_push_patterns) return error.InvalidEntry;
	const refs = try arena.alloc(RefPattern, p.refs.len);
	for (p.refs, 0..) |raw, i| {
		refs[i] = (try compileRefPattern(arena, raw)) orelse return error.InvalidEntry;
	}
	return .{ .refs = refs, .deny_delete = p.deny_delete, .deny_tags = p.deny_tags };
}

/// Compile the entry's grants[] into scope tests + cap sets + push rules. Fails
/// closed on an unknown cap, an unknown scope, a malformed prefix or
/// project_id, a scope missing its required field, or a push rule set that is
/// unusable (see compilePush). It never sees an empty project_id on a concrete
/// grant carrying an API cap -- the cogworx compiler already filtered those
/// caps (spec §4.3's error-resolve rule); re-deriving that rule here would put
/// grant policy in every plugin.
fn compile(arena: std.mem.Allocator, entry: *const conf.Entry) plugin_mod.CompileError!plugin_mod.Policy {
	const c = try arena.create(Compiled);
	const grants = try arena.alloc(CGrant, entry.grants.len);
	for (entry.grants, 0..) |g, i| {
		var caps: Caps = .{};
		for (g.caps) |cap| {
			if (!applyCap(&caps, cap)) return error.InvalidEntry;
		}
		const push: ?PushRules = if (g.push) |p| try compilePush(arena, p, caps) else null;
		const scope: Scope = if (std.mem.eql(u8, g.scope, "project"))
			.project
		else if (std.mem.eql(u8, g.scope, "namespace"))
			.namespace
		else if (std.mem.eql(u8, g.scope, "instance"))
			.instance
		else
			return error.InvalidEntry;
		var project_id: ?i64 = null;
		if (g.project_id) |pid| {
			if (pid.len > 0) project_id = canon.numericId(pid) orelse return error.InvalidEntry;
		}
		switch (scope) {
			.project => {
				// A concrete grant must be addressable at least one way.
				if (g.repo == null and project_id == null) return error.InvalidEntry;
			},
			.namespace => {
				// The prefix is pre-computed and slash-terminated by the
				// compiler ("/grp/sub/") so the grp-secret exclusion cannot be
				// re-derived wrong per plugin (spec §4.3). Refuse a malformed one.
				const p = g.prefix orelse return error.InvalidEntry;
				if (p.len < 3 or p[0] != '/' or p[p.len - 1] != '/') return error.InvalidEntry;
			},
			.instance => {},
		}
		grants[i] = .{
			.id = g.id,
			.scope = scope,
			.repo = g.repo,
			.prefix = g.prefix,
			.project_id = project_id,
			.projects = g.projects,
			.caps = caps,
			.push = push,
		};
	}
	c.* = .{
		.host = entry.host,
		.scheme = entry.scheme,
		.git_user = entry.git_user,
		.grants = grants,
	};
	return .{ .ctx = c, .vtable = &vtable };
}

fn compiled(ctx: *const anyopaque) *const Compiled {
	return @ptrCast(@alignCast(ctx));
}

// Route ids: stable literals (the audit label), never a formatted path.
const rid_git_refs = "git-refs";
const rid_git_upload = "git-upload";
const rid_git_receive = "git-receive";
const rid_api_user = "api-user";
const rid_api_version = "api-version";
const rid_api_project = "api-project";
const rid_api_group_projects = "api-group-projects";
const rid_api_issues = "api-issues";
const rid_api_mr = "api-mr";
const rid_api_mr_merge = "api-mr-merge";
const rid_api_pipelines = "api-pipelines";
const rid_api_pipeline_trigger = "api-pipeline-trigger";
const rid_api_jobs = "api-jobs";
const rid_api_repo = "api-repo";
const rid_api_wiki = "api-wiki";
const rid_api_archive = "api-archive";
// The plugin-owned LOCAL self-discovery route -- NOT a GitLab surface. A
// reserved `_cogbox` first segment, answered locally from the compiled policy,
// never proxied upstream and never touching a credential.
const rid_cogbox_grants = "cogbox-grants";

/// The closed archive extension set -- never a wildcard suffix.
const archive_exts = [_][]const u8{ "tar.gz", "tar.bz2", "tar", "tar.zst", "zip" };

/// The merge-request tails that belong to the MERGE class (`mr:merge`), split
/// out of `api-mr` so `mr:write` can mean "comment, edit, label" without also
/// meaning "approve and merge" -- the granularity the compiled-rule tier could
/// not express. `approvals` is here in both directions: reading it is
/// `mr:read`, writing it (setting approvals_required) is `mr:merge`.
///
/// `approval_rules` rides with `approvals` because it is the SAME protection
/// through GitLab's current API: `POST|PUT .../merge_requests/:iid/approval_rules`
/// sets the MR's required-approvals configuration, so leaving it in `api-mr`
/// would let a deliberately merge-less `mr:read + mr:write` grant relax the
/// requirement `mr:merge` was carved out to hold. Two endpoints for one
/// protection must sit in one class; reading the rules stays `mr:read` for free
/// through this route's own read/write split.
const mr_merge_tails = [_][]const u8{
	"merge",
	"approve",
	"unapprove",
	"approvals",
	"approval_rules",
	"reset_approvals",
	"rebase",
	"cancel_merge_when_pipeline_succeeds",
};

/// The repository READ collections (`repo:read`). A CLOSED set, and the whole
/// of `api-repo`: every write verb on these is refused by the method clamp
/// (invariant 2 in the file header). `archive` is deliberately absent -- it
/// keeps its own streaming route.
const repo_collections = [_][]const u8{
	"tree",
	"branches",
	"commits",
	"compare",
	"tags",
	"blobs",
	"files",
	"contributors",
	"merge_base",
	"changelog",
};

/// The pipeline/job tails a `pipelines:write` grant may POST. `erase` is
/// deliberately absent from the job set: erasing a job destroys its artifacts
/// and trace irreversibly, which is the DELETE argument in a POST's clothing.
const pipeline_write_tails = [_][]const u8{ "retry", "cancel" };
const job_write_tails = [_][]const u8{ "retry", "cancel", "play" };

fn inSet(set: []const []const u8, s: []const u8) bool {
	for (set) |e| {
		if (std.mem.eql(u8, e, s)) return true;
	}
	return false;
}

fn classify(ctx: *const anyopaque, req: *const plugin_mod.Request) ?plugin_mod.Route {
	_ = ctx;
	const segs = req.segments;
	if (segs.len == 0) return null;

	// The plugin-owned LOCAL self-discovery surface, recognized BEFORE any
	// GitLab route/segment matching so a `_cogbox` first segment can never
	// collide with, or fall through to, a real GitLab path. `_cogbox` is a
	// RESERVED first segment (a real GitLab top-level group named `_cogbox` is
	// implausible and is intentionally shadowed). The one route,
	// `/_cogbox/grants`, reflects THIS sandbox's grants back as JSON, answered
	// LOCALLY (Route.local) with no upstream round-trip and no credential use;
	// every OTHER `_cogbox` path is a NAMED gate-1 deny that likewise never
	// reaches the origin. Method-agnostic here (like the API routes); authorize
	// clamps it to GET/HEAD.
	if (std.mem.eql(u8, segs[0], "_cogbox")) {
		if (segs.len == 2 and std.mem.eql(u8, segs[1], "grants")) {
			return .{
				.id = rid_cogbox_grants,
				.layer = .api,
				.method_class = .read,
				.params = .{},
				.stream = false,
				.local = true,
			};
		}
		return null;
	}

	if (std.mem.eql(u8, segs[0], "api")) {
		// /api/** can never be a git route (spec §6.1); only the v4 REST
		// surface below is routed.
		if (segs.len < 3 or !std.mem.eql(u8, segs[1], "v4")) return null;
		if (segs.len == 3 and std.mem.eql(u8, segs[2], "user")) {
			return apiRoute(rid_api_user, .{}, false);
		}
		if (segs.len == 3 and std.mem.eql(u8, segs[2], "version")) {
			return apiRoute(rid_api_version, .{}, false);
		}
		if (segs.len >= 4 and std.mem.eql(u8, segs[2], "projects")) {
			const pid = parseProjectId(segs[3]) orelse return null;
			if (segs.len == 4) {
				return apiRoute(rid_api_project, .{ .project = pid }, false);
			}
			// Everything below the `:id` is one collection segment plus a tail;
			// `rest` is that tail, re-emitted (re-encoded) by `upstream`.
			const rest = segs[5..];
			if (std.mem.eql(u8, segs[4], "issues")) {
				return apiRoute(rid_api_issues, .{ .project = pid, .rest = rest }, false);
			}
			if (std.mem.eql(u8, segs[4], "merge_requests")) {
				// The merge class splits off by its TAIL, not by its depth: any
				// path whose second rest component is a merge-class tail needs
				// `mr:merge` to write, deeper ones included (fail closed -- a
				// sub-resource of `/approvals` is an approvals write too).
				if (rest.len >= 2 and inSet(&mr_merge_tails, rest[1])) {
					return apiRoute(rid_api_mr_merge, .{ .project = pid, .rest = rest }, false);
				}
				return apiRoute(rid_api_mr, .{ .project = pid, .rest = rest }, false);
			}
			if (std.mem.eql(u8, segs[4], "pipelines")) {
				// A pipeline's variables are secrets, so `/pipelines/:id/variables`
				// (and anything under it) is a NAMED no_route -- never merely a
				// method clamp, which a GET would pass.
				if (rest.len >= 2 and std.mem.eql(u8, rest[1], "variables")) return null;
				return apiRoute(rid_api_pipelines, .{ .project = pid, .rest = rest }, false);
			}
			if (segs.len == 5 and std.mem.eql(u8, segs[4], "pipeline")) {
				// The trigger endpoint: a leaf, POST-only, no tail of its own.
				return apiRoute(rid_api_pipeline_trigger, .{ .project = pid }, false);
			}
			if (std.mem.eql(u8, segs[4], "jobs")) {
				return apiRoute(rid_api_jobs, .{ .project = pid, .rest = rest }, false);
			}
			if (std.mem.eql(u8, segs[4], "wikis")) {
				return apiRoute(rid_api_wiki, .{ .project = pid, .rest = rest }, false);
			}
			if (std.mem.eql(u8, segs[4], "repository")) {
				// archive keeps its own streaming route and is matched FIRST, so
				// the closed extension set still governs it.
				if (segs.len == 6) {
					if (archiveExt(segs[5])) |ext| {
						return apiRoute(rid_api_archive, .{ .project = pid, .archive_ext = ext }, true);
					}
				}
				if (segs.len >= 6 and inSet(&repo_collections, segs[5])) {
					// `rest` deliberately INCLUDES the collection segment: the
					// upstream path is rebuilt as `/repository/<coll>[/...]`.
					return apiRoute(rid_api_repo, .{ .project = pid, .rest = rest }, false);
				}
				return null;
			}
			return null;
		}
		if (segs.len >= 4 and std.mem.eql(u8, segs[2], "groups")) {
			// ONE group route: the namespace-enumeration listing
			// `/api/v4/groups/<group-path>/projects`. Every reserved group tail
			// (access_tokens, deploy_tokens, variables, ...) and the group node
			// itself stay unrouted -- a NAMED gate-1 deny, exactly as before. The
			// numeric group form is recognized here but authorize scope-denies it
			// (the policy doc carries no group id to verify it against).
			if (segs.len == 5 and std.mem.eql(u8, segs[4], "projects")) {
				const gid = parseGroupId(segs[3]) orelse return null;
				return apiRoute(rid_api_group_projects, .{ .project = gid }, false);
			}
			return null;
		}
		return null;
	}

	// git smart-HTTP. The recognized suffix decides the route; the leading
	// segments are the project reference (both `.git` and bare forms accepted,
	// the `.git` form re-emitted). info/lfs/**, gitlab-lfs/** and
	// git-upload-archive match none of these and stay unrouted.
	if (segs.len >= 3 and std.mem.eql(u8, segs[segs.len - 2], "info") and std.mem.eql(u8, segs[segs.len - 1], "refs")) {
		const ref = refView(segs[0 .. segs.len - 2]) orelse return null;
		const svc = serviceParam(req.query);
		return .{
			.id = rid_git_refs,
			.layer = .git,
			.method_class = if (svc == .receive_pack) .write else .read,
			.params = .{
				.project_ref_segs = ref.head,
				.project_ref_last = ref.last,
				.service = svc,
			},
			.stream = true,
		};
	}
	if (segs.len >= 2 and std.mem.eql(u8, segs[segs.len - 1], "git-upload-pack")) {
		const ref = refView(segs[0 .. segs.len - 1]) orelse return null;
		return gitPackRoute(rid_git_upload, .read, ref);
	}
	if (segs.len >= 2 and std.mem.eql(u8, segs[segs.len - 1], "git-receive-pack")) {
		const ref = refView(segs[0 .. segs.len - 1]) orelse return null;
		return gitPackRoute(rid_git_receive, .write, ref);
	}
	return null;
}

fn apiRoute(id: []const u8, params: plugin_mod.Params, stream: bool) plugin_mod.Route {
	return .{
		.id = id,
		.layer = .api,
		.method_class = .read, // authorize decides per method; the class is informational for API routes
		.params = params,
		.stream = stream,
		// api-project alone gets the response-body projection: its single-project
		// GET returns the FULL project object (runners_token et al.), which
		// `simple=true` does NOT strip on a single-project GET.
		.project_response = std.mem.eql(u8, id, rid_api_project),
	};
}

fn gitPackRoute(id: []const u8, mc: plugin_mod.MethodClass, ref: RefView) plugin_mod.Route {
	return .{
		.id = id,
		.layer = .git,
		.method_class = mc,
		.params = .{ .project_ref_segs = ref.head, .project_ref_last = ref.last },
		.stream = true,
	};
}

/// `:id` in both accepted forms: numeric (`^[0-9]{1,19}$`, no leading zero) or
/// a single segment whose decoded value is a well-formed project path (which,
/// GitLab projects being namespaced, means it contains at least one `/`).
fn parseProjectId(seg: []const u8) ?plugin_mod.ProjectId {
	if (canon.numericId(seg)) |n| return .{ .numeric = n };
	const view = RefView{ .head = &.{}, .last = seg };
	if (!view.wellFormed()) return null;
	return .{ .path = seg };
}

/// A group `:id` for the enumeration route. Numeric (`^[0-9]{1,19}$`) is
/// recognized but always scope-denied downstream -- the policy doc carries no
/// group id, so a numeric group can never be verified against a grant and
/// fails closed. Otherwise a single decoded segment whose value is a
/// well-formed group PATH: unlike a project reference a single top-level
/// component (`acme`) is well-formed, because a group need not be namespaced,
/// while the per-component refusals (empty / `.` / `..` / the reserved `-`
/// infix) are shared with the project form.
fn parseGroupId(seg: []const u8) ?plugin_mod.ProjectId {
	if (canon.numericId(seg)) |n| return .{ .numeric = n };
	const view = RefView{ .head = &.{}, .last = seg };
	if (!view.wellFormedGroup()) return null;
	return .{ .path = seg };
}

/// The validated `?service=`: exactly ONE occurrence, decoded once, and one of
/// the two literals. Anything else -- absent, duplicated, arbitrary, malformed
/// -- is null, which authorize turns into a `service_invalid` deny. This is
/// the ONLY route parameter read from the query.
fn serviceParam(query: []const canon.QueryParam) ?plugin_mod.Service {
	var found: ?plugin_mod.Service = null;
	var count: usize = 0;
	for (query) |p| {
		if (!std.mem.eql(u8, p.key, "service")) continue;
		count += 1;
		var vbuf: [64]u8 = undefined;
		const v = canon.decodeOnce(p.value_raw, &vbuf) orelse return null;
		if (std.mem.eql(u8, v, "git-upload-pack")) {
			found = .upload_pack;
		} else if (std.mem.eql(u8, v, "git-receive-pack")) {
			found = .receive_pack;
		} else {
			return null;
		}
	}
	if (count != 1) return null;
	return found;
}

/// The last segment is exactly `archive` or `archive.<ext>` with `<ext>` from
/// the closed set. Returns the ext ("" for the bare form) or null (no route).
fn archiveExt(seg: []const u8) ?[]const u8 {
	if (std.mem.eql(u8, seg, "archive")) return "";
	if (!std.mem.startsWith(u8, seg, "archive.")) return null;
	const ext = seg["archive.".len..];
	for (&archive_exts) |e| {
		if (std.mem.eql(u8, ext, e)) return ext;
	}
	return null;
}

/// A project reference viewed as flattened path components: the decoded
/// segments may CONTAIN `/` (that is the whole point of segment-first
/// canonicalization), so matching walks components, never re-joined strings.
/// `head` borrows req.segments; `last` is the final segment with a `.git`
/// suffix stripped.
const RefView = struct {
	head: []const []const u8,
	last: []const u8,

	const Iter = struct {
		view: *const RefView,
		seg_idx: usize = 0,
		split: ?std.mem.SplitIterator(u8, .scalar) = null,
		done: bool = false,

		fn next(self: *Iter) ?[]const u8 {
			while (true) {
				if (self.split) |*sp| {
					if (sp.next()) |comp| return comp;
					self.split = null;
				}
				if (self.seg_idx < self.view.head.len) {
					self.split = std.mem.splitScalar(u8, self.view.head[self.seg_idx], '/');
					self.seg_idx += 1;
					continue;
				}
				if (!self.done) {
					self.done = true;
					self.split = std.mem.splitScalar(u8, self.view.last, '/');
					continue;
				}
				return null;
			}
		}
	};

	fn iter(self: *const RefView) Iter {
		return .{ .view = self };
	}

	/// A well-formed project reference: at least namespace/name (>= 2
	/// components), every component non-empty and none of `.`, `..` (an
	/// embedded `%2F.` would otherwise smuggle one past the whole-segment
	/// dot refusal) or GitLab's reserved `-` infix.
	fn wellFormed(self: *const RefView) bool {
		return self.componentsSane(2);
	}

	/// A well-formed group reference: like wellFormed but a single top-level
	/// component is legitimate (a group need not be namespaced). Same
	/// per-component refusals.
	fn wellFormedGroup(self: *const RefView) bool {
		return self.componentsSane(1);
	}

	/// Every component non-empty and none of `.`, `..` or the reserved `-`
	/// infix, and at least `min` of them.
	fn componentsSane(self: *const RefView, min: usize) bool {
		var it = self.iter();
		var n: usize = 0;
		while (it.next()) |comp| {
			if (comp.len == 0) return false;
			if (std.mem.eql(u8, comp, ".") or std.mem.eql(u8, comp, "..")) return false;
			if (std.mem.eql(u8, comp, "-")) return false;
			n += 1;
		}
		return n >= min;
	}

	/// Component-wise equality against a `/`-joined path string, ASCII
	/// case-insensitive per component. GitLab resolves namespace and project
	/// paths case-insensitively (and keeps them case-insensitively unique), and
	/// the upstream here is always the configured GitLab host, so `GRP/Proj`
	/// and `grp/proj` name the SAME project: folding admits nothing a grant
	/// does not already cover. Component boundaries are unaffected. The safety
	/// argument rests on that uniqueness: a legacy instance still carrying
	/// case-colliding routes (`Grp/x` and `grp/x` as two projects) would have
	/// both folded under one grant.
	fn eqlPath(self: *const RefView, path: []const u8) bool {
		var it = self.iter();
		var pit = std.mem.splitScalar(u8, path, '/');
		while (true) {
			const a = it.next();
			const b = pit.next();
			if (a == null and b == null) return true;
			if (a == null or b == null) return false;
			if (!std.ascii.eqlIgnoreCase(a.?, b.?)) return false;
		}
	}

	/// STRICTLY under the slash-terminated namespace prefix ("/grp/sub/"): all
	/// prefix components match AND at least one more component follows, so
	/// `grp-secret` stays excluded and the namespace path itself is not a
	/// member of its own subtree. Components compare ASCII case-insensitively,
	/// as in eqlPath (GitLab paths are case-insensitive and case-insensitively
	/// unique); a folded compare still matches whole components, so `GRP-secret`
	/// is as excluded as `grp-secret`.
	fn underPrefix(self: *const RefView, prefix: []const u8) bool {
		const trimmed = std.mem.trim(u8, prefix, "/");
		if (trimmed.len == 0) return false;
		var it = self.iter();
		var pit = std.mem.splitScalar(u8, trimmed, '/');
		while (pit.next()) |want| {
			const got = it.next() orelse return false;
			if (!std.ascii.eqlIgnoreCase(got, want)) return false;
		}
		return it.next() != null;
	}

	/// EQUAL-to or strictly-under the slash-terminated namespace prefix
	/// ("/grp/sub/"): all prefix components match, and the reference either ends
	/// exactly there (the namespace group node itself) OR carries more (a
	/// subgroup). This is the enumeration boundary: a namespace read grant must
	/// list its OWN group as well as any subgroup, which strict underPrefix
	/// would exclude. `grp-secret`, a sibling and a bare parent still fail --
	/// a component that only shares a string prefix is a different component.
	/// ASCII case-insensitive per component, for the same reason as eqlPath.
	fn groupUnderOrEqualPrefix(self: *const RefView, prefix: []const u8) bool {
		const trimmed = std.mem.trim(u8, prefix, "/");
		if (trimmed.len == 0) return false;
		var it = self.iter();
		var pit = std.mem.splitScalar(u8, trimmed, '/');
		while (pit.next()) |want| {
			const got = it.next() orelse return false;
			if (!std.ascii.eqlIgnoreCase(got, want)) return false;
		}
		return true; // equal (no trailing component) or under (some follow)
	}
};

fn refView(segs: []const []const u8) ?RefView {
	if (segs.len == 0) return null;
	var last = segs[segs.len - 1];
	if (std.mem.endsWith(u8, last, ".git")) last = last[0 .. last.len - ".git".len];
	const view = RefView{ .head = segs[0 .. segs.len - 1], .last = last };
	if (!view.wellFormed()) return null;
	return view;
}

/// Read (GET/HEAD) vs write (everything else the clamp lets through). The one
/// place the method becomes a capability question.
fn methodClassOf(method: std.http.Method) plugin_mod.MethodClass {
	return if (method == .GET or method == .HEAD) .read else .write;
}

/// The per-route method clamp. It takes the whole ROUTE, not just its id,
/// because on the pipeline and job routes the admissible write set depends on
/// the TAIL: a POST is a retry/cancel (a control action) only at
/// `<id>/<verb>`, and every other POST under those trees -- creating,
/// deleting, erasing -- is refused here rather than left to the origin.
/// DELETE is in no route's set anywhere (file-header invariant 1).
fn methodAllowed(route: *const plugin_mod.Route, method: std.http.Method) bool {
	const id = route.id;
	if (std.mem.eql(u8, id, rid_cogbox_grants)) return method == .GET or method == .HEAD;
	if (std.mem.eql(u8, id, rid_git_refs)) return method == .GET;
	if (std.mem.eql(u8, id, rid_git_upload) or std.mem.eql(u8, id, rid_git_receive)) {
		return method == .POST;
	}
	if (std.mem.eql(u8, id, rid_api_issues) or std.mem.eql(u8, id, rid_api_mr) or
		std.mem.eql(u8, id, rid_api_mr_merge) or std.mem.eql(u8, id, rid_api_wiki))
	{
		return method == .GET or method == .HEAD or method == .POST or method == .PUT;
	}
	if (std.mem.eql(u8, id, rid_api_pipelines)) {
		if (method == .GET or method == .HEAD) return true;
		return method == .POST and route.params.rest.len == 2 and
			inSet(&pipeline_write_tails, route.params.rest[1]);
	}
	if (std.mem.eql(u8, id, rid_api_jobs)) {
		if (method == .GET or method == .HEAD) return true;
		return method == .POST and route.params.rest.len == 2 and
			inSet(&job_write_tails, route.params.rest[1]);
	}
	if (std.mem.eql(u8, id, rid_api_pipeline_trigger)) return method == .POST;
	// The ambient two + api-project + api-group-projects + api-archive +
	// api-repo. api-repo lands here BY DESIGN: repository writes through the API
	// are unroutable (file-header invariant 2).
	return method == .GET or method == .HEAD;
}

fn authorize(ctx: *const anyopaque, route: *const plugin_mod.Route, req: *const plugin_mod.Request) plugin_mod.Decision {
	const c = compiled(ctx);
	if (!methodAllowed(route, req.method)) return .{ .deny = .method_not_allowed };
	// The local self-discovery route authorizes on method alone: it reflects
	// THIS sandbox's grants (an EMPTY sandbox included -> {"grants":[]}), reads
	// no credential and takes no scope test, so it must run BEFORE the no_grant
	// gate below. The audit grant label is "-": there is no single grant behind
	// it, and the body it renders enumerates them all.
	if (route.local) return .{ .allow = "-" };
	if (std.mem.eql(u8, route.id, rid_git_refs) and route.params.service == null) {
		return .{ .deny = .service_invalid };
	}
	if (c.grants.len == 0) return .{ .deny = .no_grant };

	// The ambient TWO -- /user and /version, which name no project -- are
	// allowed under ANY capability (they carry the owner's identity and the
	// server version, nothing resource-scoped), with no scope test. api-project
	// and api-group-projects are NOT ambient: they name a project / a namespace,
	// and take the scope test like every other :id route. Making api-project ambient
	// would let any grant read the metadata of ANY project the owner's token can
	// see -- an enumeration oracle -- and making the group route ambient would
	// hand out instance-wide enumeration.
	const ambient = std.mem.eql(u8, route.id, rid_api_user) or
		std.mem.eql(u8, route.id, rid_api_version);

	var saw_cap = false;
	for (c.grants) |*g| {
		if (!grantHasCap(g, route, req.method)) continue;
		saw_cap = true;
		if (ambient or scopeOk(g, route)) return .{ .allow = g.id };
	}
	return .{ .deny = if (saw_cap) .scope_mismatch else .cap_missing };
}

/// The cap -> (route, method class) map. The METHOD is a parameter because v2
/// splits every API area into a read and a write half: the same route id means
/// `issues:read` under GET/HEAD and `issues:write` under POST/PUT. The method
/// clamp has already run in `authorize`, so anything reaching here is a method
/// the route admits.
///
/// api-archive rides `git-read` OR `repo:read`: it is the tarball form of a
/// clone (the v1 addition that closed the container-vs-VM fetch asymmetry) and
/// equally the bulk form of the repository read API.
fn grantHasCap(g: *const CGrant, route: *const plugin_mod.Route, method: std.http.Method) bool {
	const write = methodClassOf(method) == .write;
	if (std.mem.eql(u8, route.id, rid_git_refs)) {
		return switch (route.params.service orelse return false) {
			.upload_pack => g.caps.git_read,
			.receive_pack => g.caps.git_write,
		};
	}
	if (std.mem.eql(u8, route.id, rid_git_upload)) return g.caps.git_read;
	if (std.mem.eql(u8, route.id, rid_git_receive)) return g.caps.git_write;
	if (std.mem.eql(u8, route.id, rid_api_archive)) return g.caps.git_read or g.caps.repo_read;
	if (std.mem.eql(u8, route.id, rid_api_group_projects)) return g.caps.git_read;
	if (std.mem.eql(u8, route.id, rid_api_issues)) {
		return if (write) g.caps.issues_write else g.caps.issues_read;
	}
	if (std.mem.eql(u8, route.id, rid_api_mr)) {
		return if (write) g.caps.mr_write else g.caps.mr_read;
	}
	if (std.mem.eql(u8, route.id, rid_api_mr_merge)) {
		// Reading the merge class (`/approvals`, the merge status) is ordinary
		// mr:read; only the ACT of approving/merging/rebasing needs mr:merge.
		return if (write) g.caps.mr_merge else g.caps.mr_read;
	}
	if (std.mem.eql(u8, route.id, rid_api_pipelines) or std.mem.eql(u8, route.id, rid_api_jobs)) {
		return if (write) g.caps.pipelines_write else g.caps.pipelines_read;
	}
	if (std.mem.eql(u8, route.id, rid_api_pipeline_trigger)) return g.caps.pipelines_write;
	if (std.mem.eql(u8, route.id, rid_api_repo)) return g.caps.repo_read;
	if (std.mem.eql(u8, route.id, rid_api_wiki)) {
		return if (write) g.caps.wiki_write else g.caps.wiki_read;
	}
	// The ambient two (api-user/api-version) + api-project: any capability at
	// all reaches them. They name the OWNER's identity, the server version and
	// (scope-tested, never ambient) one project's metadata -- nothing a grant
	// holder is not already entitled to see somewhere in its own subtree.
	return g.caps.anyCap();
}

/// The three scope tests, reusing the existing predicates' semantics verbatim
/// (spec §3.2): project => ref equals the normalized repo or the numeric id
/// equals project_id; namespace => the path form is strictly under the
/// slash-terminated prefix or the numeric id is in projects[]; instance =>
/// any well-formed reference (classify already enforced well-formedness).
fn scopeOk(g: *const CGrant, route: *const plugin_mod.Route) bool {
	// The group-enumeration route has its OWN scope test: namespace-scope
	// grants only, path form only, equals-or-under the prefix.
	if (std.mem.eql(u8, route.id, rid_api_group_projects)) return groupScopeOk(g, route);

	var view: ?RefView = null;
	var numeric: ?i64 = null;
	if (route.params.project) |pid| switch (pid) {
		.numeric => |n| numeric = n,
		.path => |p| view = RefView{ .head = &.{}, .last = p },
	} else if (route.params.project_ref_last.len > 0) {
		view = RefView{ .head = route.params.project_ref_segs, .last = route.params.project_ref_last };
	} else {
		return false;
	}

	switch (g.scope) {
		.project => {
			if (view) |*v| {
				if (g.repo) |repo| return v.eqlPath(repo);
				return false;
			}
			return g.project_id != null and numeric.? == g.project_id.?;
		},
		.namespace => {
			if (view) |*v| return v.underPrefix(g.prefix.?);
			for (g.projects) |p| {
				if (p.id == numeric.?) return true;
			}
			return false;
		},
		.instance => return true,
	}
}

/// The enumeration route's scope test. NAMESPACE-scope grants only (a concrete
/// or instance grant never authorizes it -- which is what preserves the "no
/// instance-wide enumeration oracle" property), the group id in PATH form only
/// (a numeric group fails closed: the policy doc carries no group id to verify
/// it against), and the group path EQUAL-to or UNDER the grant's
/// slash-terminated prefix.
fn groupScopeOk(g: *const CGrant, route: *const plugin_mod.Route) bool {
	if (g.scope != .namespace) return false;
	const pid = route.params.project orelse return false;
	const path = switch (pid) {
		.numeric => return false,
		.path => |p| p,
	};
	const view = RefView{ .head = &.{}, .last = path };
	return view.groupUnderOrEqualPrefix(g.prefix.?);
}

/// RFC 3986 unreserved bytes pass; everything else is %XX-encoded. Used for
/// every re-emitted path component, so a decoded byte can never corrupt the
/// constructed request line, and an embedded `/` in a component re-encodes as
/// %2F (GitLab's one-segment path-form addressing).
fn appendEncoded(out: *plugin_mod.Upstream, bytes: []const u8) plugin_mod.UpstreamError!void {
	for (bytes) |b| {
		const unreserved = (b >= 'A' and b <= 'Z') or (b >= 'a' and b <= 'z') or
			(b >= '0' and b <= '9') or b == '-' or b == '.' or b == '_' or b == '~';
		if (unreserved) {
			try out.appendPath(&[_]u8{b});
		} else {
			var esc: [3]u8 = undefined;
			_ = std.fmt.bufPrint(&esc, "%{X:0>2}", .{b}) catch unreachable;
			try out.appendPath(&esc);
		}
	}
}

/// Emit a git project reference: components joined by REAL `/` separators,
/// each component percent-encoded (an embedded `/` inside a component was a
/// typed fact -- re-emitting it as %2F preserves exactly what was addressed).
fn appendRef(out: *plugin_mod.Upstream, view: *const RefView) plugin_mod.UpstreamError!void {
	var it = view.iter();
	var first = true;
	while (it.next()) |comp| {
		if (!first) try out.appendPath("/");
		first = false;
		try appendEncoded(out, comp);
	}
}

/// Emit an API `:id`: the numeric form as digits, the path form as ONE
/// segment with %2F separators.
fn appendId(out: *plugin_mod.Upstream, pid: plugin_mod.ProjectId) plugin_mod.UpstreamError!void {
	switch (pid) {
		.numeric => |n| {
			var buf: [20]u8 = undefined;
			const s = std.fmt.bufPrint(&buf, "{d}", .{n}) catch unreachable;
			try out.appendPath(s);
		},
		.path => |p| try appendEncoded(out, p),
	}
}

/// CONSTRUCT the upstream request: scheme/host from the entry's config, the
/// path from the route's typed params, the query from the route's allowlist
/// (`service` re-emitted canonically on git-refs; API routes pass their raw
/// pairs through -- v1's one named non-allowlisted spot; pack routes carry
/// none). Never the inbound Host, never the raw target.
fn upstream(ctx: *const anyopaque, route: *const plugin_mod.Route, req: *const plugin_mod.Request, out: *plugin_mod.Upstream) plugin_mod.UpstreamError!void {
	const c = compiled(ctx);
	out.scheme = c.scheme;
	out.host = c.host;
	out.port = 0; // the vetted port (addendum I.2 item 11)

	if (route.layer == .git) {
		const view = RefView{ .head = route.params.project_ref_segs, .last = route.params.project_ref_last };
		try out.appendPath("/");
		try appendRef(out, &view);
		if (std.mem.eql(u8, route.id, rid_git_refs)) {
			try out.appendPath(".git/info/refs");
			try out.appendQuery(switch (route.params.service.?) {
				.upload_pack => "service=git-upload-pack",
				.receive_pack => "service=git-receive-pack",
			});
		} else if (std.mem.eql(u8, route.id, rid_git_upload)) {
			try out.appendPath(".git/git-upload-pack");
		} else {
			try out.appendPath(".git/git-receive-pack");
		}
		return;
	}

	if (std.mem.eql(u8, route.id, rid_api_user)) {
		try out.appendPath("/api/v4/user");
	} else if (std.mem.eql(u8, route.id, rid_api_version)) {
		try out.appendPath("/api/v4/version");
	} else if (std.mem.eql(u8, route.id, rid_api_group_projects)) {
		try out.appendPath("/api/v4/groups/");
		try appendId(out, route.params.project.?);
		try out.appendPath("/projects");
	} else {
		try out.appendPath("/api/v4/projects/");
		try appendId(out, route.params.project.?);
		// The collection segment is a LITERAL of this table, never a copied
		// byte: `rest` (which upstream re-encodes below) starts after it -- except
		// on api-repo, whose `rest` begins WITH its collection so the closed set
		// is what the path carries.
		if (std.mem.eql(u8, route.id, rid_api_issues)) {
			try out.appendPath("/issues");
		} else if (std.mem.eql(u8, route.id, rid_api_mr) or std.mem.eql(u8, route.id, rid_api_mr_merge)) {
			try out.appendPath("/merge_requests");
		} else if (std.mem.eql(u8, route.id, rid_api_pipelines)) {
			try out.appendPath("/pipelines");
		} else if (std.mem.eql(u8, route.id, rid_api_pipeline_trigger)) {
			try out.appendPath("/pipeline");
		} else if (std.mem.eql(u8, route.id, rid_api_jobs)) {
			try out.appendPath("/jobs");
		} else if (std.mem.eql(u8, route.id, rid_api_wiki)) {
			try out.appendPath("/wikis");
		} else if (std.mem.eql(u8, route.id, rid_api_repo)) {
			try out.appendPath("/repository");
		} else if (std.mem.eql(u8, route.id, rid_api_archive)) {
			try out.appendPath("/repository/archive");
			if (route.params.archive_ext.?.len > 0) {
				try out.appendPath(".");
				try out.appendPath(route.params.archive_ext.?);
			}
		}
		for (route.params.rest) |seg| {
			try out.appendPath("/");
			try appendEncoded(out, seg);
		}
	}
	// The query is route-specific. Both READ routes FORCE `simple=true`, but it
	// means DIFFERENT things on the two:
	//   - api-group-projects (a LIST): GitLab honours `simple` on list
	//     endpoints, so `simple=true` is what strips `runners_token` and the
	//     other secret fields from every listed project, and a client
	//     `simple=false` must never override it.
	//   - api-project (a single-project GET): GitLab does NOT honour `simple`
	//     here -- a single-project GET returns the FULL object regardless -- so
	//     `simple=true` is INERT for the leak and kept only as belt-and-braces.
	//     The runners_token leak on this route is closed proxy-side by the
	//     RESPONSE-BODY projection (route.project_response -> main.zig
	//     projectProjectResponse), not by this query, and that same projection
	//     closes the pre-existing issues/mr residual once rolled.
	// The group-enumeration route additionally forces `include_subgroups=true`
	// and drops everything but a small pagination/search allowlist (so a client
	// cannot append an order_by/owned/... that changes the response shape).
	// Every other API route -- issues, both mr routes, pipelines, the trigger,
	// jobs, the repository read collections, wikis, archive, user, version --
	// keeps the blanket pass-through (v1's one named non-allowlisted spot); the
	// forbidden keys were already refused by the core.
	if (std.mem.eql(u8, route.id, rid_api_group_projects)) {
		try out.appendQuery("simple=true&include_subgroups=true");
		for (req.query) |p| {
			if (!groupProjectsQueryAllowed(p.key)) continue;
			try out.appendQuery("&");
			try out.appendQuery(p.raw);
		}
	} else if (std.mem.eql(u8, route.id, rid_api_project)) {
		try out.appendQuery("simple=true");
		for (req.query) |p| {
			if (std.mem.eql(u8, p.key, "simple")) continue; // forced above
			try out.appendQuery("&");
			try out.appendQuery(p.raw);
		}
	} else {
		for (req.query, 0..) |p, i| {
			if (i > 0) try out.appendQuery("&");
			try out.appendQuery(p.raw);
		}
	}
}

/// The group-enumeration route's query allowlist: pagination and search only,
/// so a client cannot re-open `simple=false`/`include_subgroups=false` (both
/// forced above) or steer the listing with an owned/order_by/... parameter.
fn groupProjectsQueryAllowed(key: []const u8) bool {
	const allowed = [_][]const u8{ "per_page", "page", "page_token", "search" };
	for (&allowed) |a| {
		if (std.mem.eql(u8, key, a)) return true;
	}
	return false;
}

/// Basic on the three git routes (base64(git_user ":" token), byte-identical
/// to resolve_gitlab_style) and Bearer on the API routes, api-archive
/// included. The inbound Authorization was dropped by the core's allowlist
/// before this runs.
fn authenticate(ctx: *const anyopaque, route: *const plugin_mod.Route, req: *const plugin_mod.Request, cred: *plugin_mod.Cred, out: *plugin_mod.HeaderSet) plugin_mod.AuthError!void {
	_ = req;
	const c = compiled(ctx);
	const tok = try cred.token();
	if (route.layer == .git) {
		var raw: [10 * 1024]u8 = undefined;
		defer std.crypto.secureZero(u8, &raw);
		const userinfo = std.fmt.bufPrint(&raw, "{s}:{s}", .{ c.git_user, tok }) catch return error.AuthFailed;
		var value: [14 * 1024]u8 = undefined;
		defer std.crypto.secureZero(u8, &value);
		const prefix = "Basic ";
		@memcpy(value[0..prefix.len], prefix);
		const enc_len = std.base64.standard.Encoder.calcSize(userinfo.len);
		if (prefix.len + enc_len > value.len) return error.AuthFailed;
		_ = std.base64.standard.Encoder.encode(value[prefix.len .. prefix.len + enc_len], userinfo);
		out.set("authorization", value[0 .. prefix.len + enc_len]) catch return error.AuthFailed;
	} else {
		var value: [10 * 1024]u8 = undefined;
		defer std.crypto.secureZero(u8, &value);
		const v = std.fmt.bufPrint(&value, "Bearer {s}", .{tok}) catch return error.AuthFailed;
		out.set("authorization", v) catch return error.AuthFailed;
	}
}

// --- push rules: the receive-pack mediate hook ---------------------------
//
// Everything above decides on the request HEAD. Branch rules cannot: which
// refs a push moves is in the BODY, so they live in the one hook that sees it.
// The shape of that hook is chosen so the blast radius stays at "a push under a
// grant that carries rules":
//
//   - Every other route, and every push no covering grant restricts, returns
//     `false` before the body reader is touched -- the core then runs its
//     ordinary single round trip, byte for byte what it ran before this
//     existed. A clone, an API call and an unrestricted push cost one string
//     compare.
//   - A refusal is decided BEFORE any dial. Nothing of a rejected push reaches
//     the origin: not the commands, not the packfile.
//   - An admitted push is forwarded UNCHANGED -- the buffered command section
//     is replayed ahead of the live body through `PrefixReader`, so
//     `Content-Length` still describes the bytes and the pack's own framing is
//     untouched.
//
// The rules are a fail-closed FILTER, never a promise: a force-push is
// indistinguishable from a fast-forward on the wire (a non-fast-forward update
// is `<old != 0> <new != 0> <ref>` exactly like any other and the proxy has no
// object graph), so GitLab protected branches remain the backstop for that.

/// Component-wise glob. `*` matches EXACTLY one component, `**` one or more --
/// never zero, so `refs/heads/**` does not match `refs/heads`. Both are WHOLE
/// components; `compileRefPattern` already refused a partial-component wildcard
/// (`ag*ent`), so no byte-level matching is needed or wanted here. The
/// backtracking is the classic star walk: `**` first takes one component and
/// grows only when the rest of the pattern fails.
fn globComps(pat: []const []const u8, name: []const []const u8) bool {
	var pi: usize = 0;
	var ni: usize = 0;
	var star_pi: ?usize = null; // the last `**` seen
	var star_ni: usize = 0; // how far it currently reaches into `name`
	while (true) {
		if (ni < name.len and pi < pat.len) {
			if (std.mem.eql(u8, pat[pi], "**")) {
				// the mandatory first component of a `**`
				star_pi = pi;
				ni += 1;
				star_ni = ni;
				pi += 1;
				continue;
			}
			if (std.mem.eql(u8, pat[pi], "*") or std.mem.eql(u8, pat[pi], name[ni])) {
				pi += 1;
				ni += 1;
				continue;
			}
		} else if (ni == name.len and pi == pat.len) {
			return true;
		}
		// A mismatch, or one side ran out: extend the last `**` by one component
		// and retry the pattern behind it.
		const sp = star_pi orelse return false;
		if (star_ni >= name.len) return false;
		star_ni += 1;
		ni = star_ni;
		pi = sp + 1;
	}
}

/// Whether any of the grant's patterns admits this refname. NO patterns means
/// "any refname" -- the rule object then carries only the two deny flags.
fn refMatches(rules: *const PushRules, name: []const []const u8) bool {
	if (rules.refs.len == 0) return true;
	for (rules.refs) |p| {
		if (globComps(p.comps, name)) return true;
	}
	return false;
}

/// Split a refname into its `/` components. `pktline` already bounded the
/// count, so the null arm is unreachable defence-in-depth (and fails closed).
fn splitRef(ref: []const u8, out: *[pktline.max_ref_components][]const u8) ?[]const []const u8 {
	var n: usize = 0;
	var it = std.mem.splitScalar(u8, ref, '/');
	while (it.next()) |comp| {
		if (n == out.len) return null;
		out[n] = comp;
		n += 1;
	}
	return out[0..n];
}

/// UNION semantics: one command passes if ANY covering git-write grant admits
/// it. A rule-free project grant is therefore NOT narrowed by a namespace grant
/// that happens to carry rules -- the tuples are additive, exactly as they are
/// in `authorize`, and a narrower grant can only ever add reach.
fn commandAdmitted(grants: []const CGrant, route: *const plugin_mod.Route, cmd: *const pktline.Command, comps: []const []const u8) bool {
	for (grants) |*g| {
		if (!g.caps.git_write) continue;
		const p = g.push orelse {
			// unrestricted: any ref, delete and tag included
			if (scopeOk(g, route)) return true;
			continue;
		};
		if (cmd.is_delete and p.deny_delete) continue;
		// deny_tags short-circuits the patterns: a `refs/tags/*` pattern plus
		// deny_tags is a contradiction the flag wins.
		if (cmd.is_tag and p.deny_tags) continue;
		if (!refMatches(&p, comps)) continue;
		if (scopeOk(g, route)) return true;
	}
	return false;
}

fn mediateReceivePack(
	ctx: *const anyopaque,
	route: *const plugin_mod.Route,
	req: *const plugin_mod.Request,
	cred: *plugin_mod.Cred,
	io: *upstream_mod.UpstreamIO,
	out: *plugin_mod.Response,
) plugin_mod.MediateError!bool {
	const c = compiled(ctx);
	if (!std.mem.eql(u8, route.id, rid_git_receive)) return false;

	// THE FAST PATH. `authorize` already proved some git-write grant covers this
	// project; if none of THOSE carries rules there is nothing to enforce, so
	// the body is never read and the core relays it exactly as before. The scope
	// test is what makes this per-project: a rules-bearing grant on another
	// repository must not drag this push onto the slow path.
	var any_rules = false;
	for (c.grants) |*g| {
		if (g.caps.git_write and g.push != null and scopeOk(g, route)) {
			any_rules = true;
			break;
		}
	}
	if (!any_rules) return false;
	// A receive-pack POST with no body at all is GitLab's to answer, not ours.
	const body = req.body orelse return false;

	// The command section is buffered whole before a verdict exists. It carries
	// no credential (only oids and refnames), so it lives outside the scratch
	// block -- and it is freed the moment `open` returns, which is after `open`
	// has pumped the entire body synchronously.
	const buf = io.gpa.alloc(u8, pktline.max_prefix_bytes) catch return error.MediateFailed;
	defer io.gpa.free(buf);
	const cmds = io.gpa.alloc(pktline.Command, pktline.max_commands) catch return error.MediateFailed;
	defer io.gpa.free(cmds);

	const section = switch (pktline.readCommandSection(body, buf, cmds) catch return error.MediateFailed) {
		.refuse => |r| {
			// The mapping is written out rather than passed through @tagName so
			// the two vocabularies are compile-checked against each other.
			const reason: plugin_mod.DenyReason = switch (r) {
				.push_malformed => .push_malformed,
				.too_many_refs => .too_many_refs,
				.push_cert_unsupported => .push_cert_unsupported,
			};
			out.deny = @tagName(reason);
			out.deny_status = switch (r) {
				.push_malformed => 400,
				.too_many_refs => 413,
				.push_cert_unsupported => 403,
			};
			return true;
		},
		.ok => |s| s,
	};

	// ALL-OR-NOTHING: one refused command refuses the whole push. A push is a
	// single transaction to the client and the packfile is shared across its
	// commands, so there is no honest way to forward a subset.
	var comps_buf: [pktline.max_ref_components][]const u8 = undefined;
	for (section.commands) |cmd| {
		const comps = splitRef(cmd.ref, &comps_buf);
		if (comps == null or !commandAdmitted(c.grants, route, &cmd, comps.?)) {
			out.deny = @tagName(plugin_mod.DenyReason.ref_denied);
			out.deny_status = 403;
			return true;
		}
	}

	// Admitted. From here it is the default round trip, hand-rolled because the
	// body reader is no longer at byte zero: the same constructed upstream, the
	// same `authenticate`, and the ORIGINAL byte stream (buffered prefix, then
	// the live body) under the unchanged Content-Length -- null when the guest
	// chunked it, which `open` then re-frames as chunked upstream.
	var up: plugin_mod.Upstream = .{};
	upstream(ctx, route, req, &up) catch return error.MediateFailed;
	const hs = &io.storage.mediate_headers;
	hs.copyFrom(req.headers);
	authenticate(ctx, route, req, cred, hs) catch |err| switch (err) {
		error.CredentialUnavailable => return error.CredentialUnavailable,
		error.AuthFailed => return error.MediateFailed,
	};
	var pr = pktline.PrefixReader.init(buf[0..section.prefix_len], body);
	out.exchange = io.open(&up, req.method, hs, &pr.interface, req.content_length) catch return error.UpstreamFailed;
	return true;
}

/// Render THIS sandbox's grants as the `/_cogbox/grants` self-discovery JSON --
/// `{"grants":[{"scope":..,"repo":..,"prefix":..,"caps":[..]},..]}` -- built
/// from the already-compiled in-memory grants, so it is zero upstream, zero
/// credential and zero drift from what `authorize` enforces. It reflects only
/// the NON-SECRET policy shape and NEVER emits a token, a numeric project id
/// (`project_id`/`projects[]` stay internal) or any upstream byte. `repo` is
/// emitted whenever the grant carries one (absent on an instance-scope grant,
/// which names no repo). `prefix` is the CLEAN path form -- the internal
/// slash-terminated `"/grp/sub/"` trimmed to `"grp/sub"`, no leading/trailing
/// slash -- and appears on namespace-scope grants only. An empty/ungranted
/// sandbox renders `{"grants":[]}`.
///
/// `caps` is always the v2 vocabulary, in the canonical order, whatever
/// dialect the document used: the reflection states what this binary
/// ENFORCES, and a v1 `mr` really is the mr triple here. A grant's push rules
/// ride as FLAT keys -- `push_refs`, `push_deny_delete`, `push_deny_tags` --
/// never a nested object: the deployed `treemn-check` splits this body on
/// braces and a nested one would break every copy in the field.
fn localResponse(ctx: *const anyopaque, route: *const plugin_mod.Route, req: *const plugin_mod.Request, out: *std.Io.Writer) plugin_mod.LocalError!void {
	_ = route;
	_ = req;
	const c = compiled(ctx);
	var jw: std.json.Stringify = .{ .writer = out };
	try jw.beginObject();
	try jw.objectField("grants");
	try jw.beginArray();
	for (c.grants) |*g| {
		try jw.beginObject();
		try jw.objectField("scope");
		try jw.write(@tagName(g.scope));
		if (g.repo) |repo| {
			try jw.objectField("repo");
			try jw.write(repo);
		}
		if (g.scope == .namespace) {
			if (g.prefix) |p| {
				try jw.objectField("prefix");
				try jw.write(std.mem.trim(u8, p, "/"));
			}
		}
		try jw.objectField("caps");
		try jw.beginArray();
		if (g.caps.git_read) try jw.write("git-read");
		if (g.caps.git_write) try jw.write("git-write");
		if (g.caps.issues_read) try jw.write("issues:read");
		if (g.caps.issues_write) try jw.write("issues:write");
		if (g.caps.mr_read) try jw.write("mr:read");
		if (g.caps.mr_write) try jw.write("mr:write");
		if (g.caps.mr_merge) try jw.write("mr:merge");
		if (g.caps.pipelines_read) try jw.write("pipelines:read");
		if (g.caps.pipelines_write) try jw.write("pipelines:write");
		if (g.caps.repo_read) try jw.write("repo:read");
		if (g.caps.wiki_read) try jw.write("wiki:read");
		if (g.caps.wiki_write) try jw.write("wiki:write");
		try jw.endArray();
		if (g.push) |p| {
			try jw.objectField("push_refs");
			try jw.beginArray();
			for (p.refs) |r| try jw.write(r.raw);
			try jw.endArray();
			try jw.objectField("push_deny_delete");
			try jw.write(p.deny_delete);
			try jw.objectField("push_deny_tags");
			try jw.write(p.deny_tags);
		}
		try jw.endObject();
	}
	try jw.endArray();
	try jw.endObject();
}

// --- Tests ---
//
// The full route/authz matrix lives in route_vectors.tsv (the new engine's
// oracle); these units cover the pieces the table cannot express directly.

const t = std.testing;

fn mkReq(method: std.http.Method, segments: []const []const u8, query: []const canon.QueryParam) plugin_mod.Request {
	return .{
		.method = method,
		.segments = segments,
		.query = query,
		.headers = &empty_headers,
		.content_type = null,
		.content_length = null,
		.body = null,
		.host = "git.example.com",
		.raw_target = "",
	};
}

const empty_headers: plugin_mod.HeaderSet = .{};
const svc_upload = [_]canon.QueryParam{.{ .key = "service", .value_raw = "git-upload-pack", .raw = "service=git-upload-pack" }};
const svc_receive = [_]canon.QueryParam{.{ .key = "service", .value_raw = "git-receive-pack", .raw = "service=git-receive-pack" }};

test "RefView: component iteration spans embedded slashes" {
	const segs = [_][]const u8{ "grp", "proj.git" };
	const v = refView(&segs).?;
	try t.expectEqualStrings("proj", v.last); // .git stripped
	try t.expect(v.eqlPath("grp/proj"));
	try t.expect(!v.eqlPath("grp/proj2"));
	try t.expect(!v.eqlPath("grp"));
	// an embedded slash flattens to the same components
	const one = [_][]const u8{"grp/proj"};
	const v2 = refView(&one).?;
	try t.expect(v2.eqlPath("grp/proj"));
	try t.expect(v2.underPrefix("/grp/"));
	try t.expect(!v2.underPrefix("/grp/proj/")); // not strictly under itself
	// grp-secret stays excluded by the slash-terminated prefix
	const secret = [_][]const u8{ "grp-secret", "x" };
	const v3 = refView(&secret).?;
	try t.expect(!v3.underPrefix("/grp/"));
	// GitLab paths are case-insensitive: components fold, boundaries do not
	try t.expect(v.eqlPath("GRP/Proj"));
	try t.expect(!v.eqlPath("GRP/Proj2"));
	try t.expect(v2.underPrefix("/GRP/"));
	try t.expect(!v2.underPrefix("/Grp/PROJ/")); // still not strictly under itself
	try t.expect(v2.groupUnderOrEqualPrefix("/Grp/PROJ/")); // ...but equal for enumeration
	try t.expect(!v3.underPrefix("/GRP/"));
	const mixed_secret = [_][]const u8{ "GRP-Secret", "x" };
	try t.expect(!refView(&mixed_secret).?.underPrefix("/grp/"));
}

test "RefView: malformed references are not well-formed" {
	const single = [_][]const u8{"proj"};
	try t.expect(refView(&single) == null); // no namespace
	const dash = [_][]const u8{ "grp", "-", "raw" };
	try t.expect(refView(&dash) == null); // reserved infix
	const dot = [_][]const u8{"grp/."};
	try t.expect(refView(&dot) == null); // embedded dot component
	const empty = [_][]const u8{"grp//x"};
	try t.expect(refView(&empty) == null); // embedded empty component
	const none = [_][]const u8{};
	try t.expect(refView(&none) == null);
}

test "gitlab: compile fails closed on unknown cap, unknown scope, malformed prefix/project_id" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cases = [_][]const u8{
		// unknown cap
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2","grants":[{"id":"g","scope":"instance","caps":["admin"]}]}]}
		,
		// unknown scope
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2","grants":[{"id":"g","scope":"global","caps":["mr"]}]}]}
		,
		// namespace without a prefix
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2","grants":[{"id":"g","scope":"namespace","caps":["mr"]}]}]}
		,
		// a prefix that is not slash-terminated
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2","grants":[{"id":"g","scope":"namespace","prefix":"/grp","caps":["mr"]}]}]}
		,
		// a malformed project_id
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2","grants":[{"id":"g","scope":"project","repo":"a/b","project_id":"01","caps":["mr"]}]}]}
		,
		// a project grant with no repo and no project_id
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2","grants":[{"id":"g","scope":"project","caps":["mr"]}]}]}
		,
	};
	for (cases) |json| {
		try t.expectError(error.BadConf, conf.parseGeneration(t.allocator, io, json, 1, .skip, null));
	}
}

test "gitlab: upstream construction re-encodes, canonicalizes the .git form, clamps the query" {
	const g = try conf.parseGeneration(t.allocator, undefined, conf.test_conf_json, 1, .skip, null);
	defer {
		g.arena.deinit();
		t.allocator.destroy(g);
	}
	const policy = g.entries[0].policy;

	// bare-form clone URL -> canonical .git form re-emitted
	const segs = [_][]const u8{ "grp", "proj", "info", "refs" };
	const req = mkReq(.GET, &segs, &svc_upload);
	const route = policy.vtable.classify(policy.ctx, &req).?;
	try t.expectEqualStrings("git-refs", route.id);
	var up: plugin_mod.Upstream = .{};
	try policy.vtable.upstream(policy.ctx, &route, &req, &up);
	try t.expectEqualStrings("/grp/proj.git/info/refs", up.path());
	try t.expectEqualStrings("service=git-upload-pack", up.query());
	try t.expectEqualStrings("git.example.com", up.host);

	// path-form :id re-emitted as ONE segment (%2F), rest segments re-encoded
	const segs2 = [_][]const u8{ "api", "v4", "projects", "grp/proj", "issues", "9" };
	const req2 = mkReq(.GET, &segs2, &.{});
	const route2 = policy.vtable.classify(policy.ctx, &req2).?;
	try t.expectEqualStrings("api-issues", route2.id);
	var up2: plugin_mod.Upstream = .{};
	try policy.vtable.upstream(policy.ctx, &route2, &req2, &up2);
	try t.expectEqualStrings("/api/v4/projects/grp%2Fproj/issues/9", up2.path());
	try t.expectEqualStrings("", up2.query());

	// archive: closed ext set, GET/HEAD, git-read
	const segs3 = [_][]const u8{ "api", "v4", "projects", "1234", "repository", "archive.tar.gz" };
	const req3 = mkReq(.GET, &segs3, &.{});
	const route3 = policy.vtable.classify(policy.ctx, &req3).?;
	try t.expectEqualStrings("api-archive", route3.id);
	var up3: plugin_mod.Upstream = .{};
	try policy.vtable.upstream(policy.ctx, &route3, &req3, &up3);
	try t.expectEqualStrings("/api/v4/projects/1234/repository/archive.tar.gz", up3.path());

	// an unlisted ext is unrouted
	const segs4 = [_][]const u8{ "api", "v4", "projects", "1234", "repository", "archive.rar" };
	const req4 = mkReq(.GET, &segs4, &.{});
	try t.expect(policy.vtable.classify(policy.ctx, &req4) == null);
}

test "gitlab: authenticate is Basic on git routes, Bearer on API routes" {
	const g = try conf.parseGeneration(t.allocator, undefined, conf.test_conf_json, 1, .skip, null);
	defer {
		g.arena.deinit();
		t.allocator.destroy(g);
	}
	const policy = g.entries[0].policy;

	const FakeCred = struct {
		fn token(_: *anyopaque) plugin_mod.Cred.TokenError![]const u8 {
			return "glpat-FAKEFAKEFAKE";
		}
	};
	var dummy: u8 = 0;
	var cred: plugin_mod.Cred = .{ .ctx = &dummy, .tokenFn = FakeCred.token };

	const segs = [_][]const u8{ "grp", "proj.git", "git-upload-pack" };
	const req = mkReq(.POST, &segs, &.{});
	const route = policy.vtable.classify(policy.ctx, &req).?;
	var hdrs: plugin_mod.HeaderSet = .{};
	try policy.vtable.authenticate(policy.ctx, &route, &req, &cred, &hdrs);
	// base64("oauth2:glpat-FAKEFAKEFAKE") -- byte-identical to resolve_gitlab_style
	try t.expectEqualStrings("Basic b2F1dGgyOmdscGF0LUZBS0VGQUtFRkFLRQ==", hdrs.get("authorization").?);

	const segs2 = [_][]const u8{ "api", "v4", "projects", "1234", "issues" };
	const req2 = mkReq(.GET, &segs2, &.{});
	const route2 = policy.vtable.classify(policy.ctx, &req2).?;
	var hdrs2: plugin_mod.HeaderSet = .{};
	try policy.vtable.authenticate(policy.ctx, &route2, &req2, &cred, &hdrs2);
	try t.expectEqualStrings("Bearer glpat-FAKEFAKEFAKE", hdrs2.get("authorization").?);
}

test "gitlab: service validation -- present/absent/duplicated/arbitrary, and non-refs routes ignore it" {
	const g = try conf.parseGeneration(t.allocator, undefined, conf.test_conf_json, 1, .skip, null);
	defer {
		g.arena.deinit();
		t.allocator.destroy(g);
	}
	const policy = g.entries[0].policy;
	const segs = [_][]const u8{ "grp", "proj.git", "info", "refs" };

	// valid upload service on a git-read grant -> allowed
	const req = mkReq(.GET, &segs, &svc_upload);
	const route = policy.vtable.classify(policy.ctx, &req).?;
	try t.expect(policy.vtable.authorize(policy.ctx, &route, &req) == .allow);

	// absent
	const req2 = mkReq(.GET, &segs, &.{});
	const route2 = policy.vtable.classify(policy.ctx, &req2).?;
	const d2 = policy.vtable.authorize(policy.ctx, &route2, &req2);
	try t.expectEqual(plugin_mod.DenyReason.service_invalid, d2.deny);

	// duplicated
	const dup = [_]canon.QueryParam{ svc_upload[0], svc_upload[0] };
	const req3 = mkReq(.GET, &segs, &dup);
	const route3 = policy.vtable.classify(policy.ctx, &req3).?;
	try t.expectEqual(plugin_mod.DenyReason.service_invalid, policy.vtable.authorize(policy.ctx, &route3, &req3).deny);

	// arbitrary
	const arb = [_]canon.QueryParam{.{ .key = "service", .value_raw = "git-upload-archive", .raw = "service=git-upload-archive" }};
	const req4 = mkReq(.GET, &segs, &arb);
	const route4 = policy.vtable.classify(policy.ctx, &req4).?;
	try t.expectEqual(plugin_mod.DenyReason.service_invalid, policy.vtable.authorize(policy.ctx, &route4, &req4).deny);

	// service on a non-info/refs route is not consulted: the pack route's cap
	// governs, and its constructed upstream carries NO query at all.
	const psegs = [_][]const u8{ "grp", "proj.git", "git-upload-pack" };
	const req5 = mkReq(.POST, &psegs, &svc_receive);
	const route5 = policy.vtable.classify(policy.ctx, &req5).?;
	try t.expectEqualStrings("git-upload", route5.id);
	try t.expect(policy.vtable.authorize(policy.ctx, &route5, &req5) == .allow);
	var up: plugin_mod.Upstream = .{};
	try policy.vtable.upstream(policy.ctx, &route5, &req5, &up);
	try t.expectEqualStrings("", up.query());
}

test "gitlab: DELETE is denied on every route; the ambient two take ANY capability but only GET/HEAD" {
	const g = try conf.parseGeneration(t.allocator, undefined, conf.test_conf_json, 1, .skip, null);
	defer {
		g.arena.deinit();
		t.allocator.destroy(g);
	}
	const policy = g.entries[0].policy;

	const segs = [_][]const u8{ "api", "v4", "projects", "1234", "issues" };
	const req = mkReq(.DELETE, &segs, &.{});
	const route = policy.vtable.classify(policy.ctx, &req).?;
	try t.expectEqual(plugin_mod.DenyReason.method_not_allowed, policy.vtable.authorize(policy.ctx, &route, &req).deny);

	const usegs = [_][]const u8{ "api", "v4", "user" };
	const ureq = mkReq(.GET, &usegs, &.{});
	const uroute = policy.vtable.classify(policy.ctx, &ureq).?;
	try t.expect(policy.vtable.authorize(policy.ctx, &uroute, &ureq) == .allow);
	const upost = mkReq(.POST, &usegs, &.{});
	const uroute2 = policy.vtable.classify(policy.ctx, &upost).?;
	try t.expectEqual(plugin_mod.DenyReason.method_not_allowed, policy.vtable.authorize(policy.ctx, &uroute2, &upost).deny);

	// A grant carrying ONLY git-write reaches the ambient two under v2 (they
	// name the owner's identity and the server version -- nothing a grant that
	// can already push as the owner is not entitled to), but is still
	// cap_missing on every route that names a resource class.
	const wo = try conf.parseGeneration(t.allocator, undefined,
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2",
		\\"grants":[{"id":"gg-w","scope":"instance","caps":["git-write"]}]}]}
	, 1, .skip, null);
	defer {
		wo.arena.deinit();
		t.allocator.destroy(wo);
	}
	const wp = wo.entries[0].policy;
	const wroute = wp.vtable.classify(wp.ctx, &ureq).?;
	try t.expect(wp.vtable.authorize(wp.ctx, &wroute, &ureq) == .allow);
	const ireq = mkReq(.GET, &segs, &.{});
	const iroute = wp.vtable.classify(wp.ctx, &ireq).?;
	try t.expectEqual(plugin_mod.DenyReason.cap_missing, wp.vtable.authorize(wp.ctx, &iroute, &ireq).deny);
}

test "gitlab: api-project is SCOPED, not ambient -- a non-granted project denies in both id forms (B2)" {
	// A concrete issues grant on grp/proj#1234 and NO instance grant: the
	// owner's token can see other projects, but this sandbox may not.
	const g = try conf.parseGeneration(t.allocator, undefined,
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2",
		\\"grants":[{"id":"gg-p","scope":"project","repo":"grp/proj","project_id":"1234","caps":["issues"]},
		\\{"id":"gg-n","scope":"namespace","repo":"grp/sub/*","prefix":"/grp/sub/","caps":["mr"],"projects":[{"id":42,"path":"grp/sub/a"}]}]}]}
	, 1, .skip, null);
	defer {
		g.arena.deinit();
		t.allocator.destroy(g);
	}
	const policy = g.entries[0].policy;

	const Case = struct { segs: []const []const u8, want_allow: bool, grant: []const u8 = "" };
	const cases = [_]Case{
		// the granted project, both forms
		.{ .segs = &.{ "api", "v4", "projects", "1234" }, .want_allow = true, .grant = "gg-p" },
		.{ .segs = &.{ "api", "v4", "projects", "grp/proj" }, .want_allow = true, .grant = "gg-p" },
		// the namespace grant, both forms
		.{ .segs = &.{ "api", "v4", "projects", "42" }, .want_allow = true, .grant = "gg-n" },
		.{ .segs = &.{ "api", "v4", "projects", "grp/sub/child" }, .want_allow = true, .grant = "gg-n" },
		// a NON-granted project: denied in both forms (scope_mismatch)
		.{ .segs = &.{ "api", "v4", "projects", "999" }, .want_allow = false },
		.{ .segs = &.{ "api", "v4", "projects", "other/secret" }, .want_allow = false },
		.{ .segs = &.{ "api", "v4", "projects", "grp/sub-secret/x" }, .want_allow = false },
		// GitLab paths are case-insensitive: a mixed-case reference to a granted
		// project/namespace names the same thing, while the component boundary
		// and a non-granted project stay out whatever their case
		.{ .segs = &.{ "api", "v4", "projects", "Grp/PROJ" }, .want_allow = true, .grant = "gg-p" },
		.{ .segs = &.{ "api", "v4", "projects", "GRP/Sub/child" }, .want_allow = true, .grant = "gg-n" },
		.{ .segs = &.{ "api", "v4", "projects", "GRP/SUB-secret/x" }, .want_allow = false },
		.{ .segs = &.{ "api", "v4", "projects", "Other/Secret" }, .want_allow = false },
		.{ .segs = &.{ "api", "v4", "projects", "GRP/SUB" }, .want_allow = false },
	};
	for (cases) |c| {
		const req = mkReq(.GET, c.segs, &.{});
		const route = policy.vtable.classify(policy.ctx, &req).?;
		try t.expectEqualStrings("api-project", route.id);
		const d = policy.vtable.authorize(policy.ctx, &route, &req);
		if (c.want_allow) {
			try t.expectEqualStrings(c.grant, d.allow);
		} else {
			try t.expectEqual(plugin_mod.DenyReason.scope_mismatch, d.deny);
		}
	}
	// The two truly ambient routes still need no scope.
	const usegs = [_][]const u8{ "api", "v4", "user" };
	const ureq = mkReq(.GET, &usegs, &.{});
	const uroute = policy.vtable.classify(policy.ctx, &ureq).?;
	try t.expect(policy.vtable.authorize(policy.ctx, &uroute, &ureq) == .allow);
}

test "gitlab: numeric-form namespace authorization rides projects[], concrete rides project_id" {
	const g = try conf.parseGeneration(t.allocator, undefined, conf.test_conf_json, 1, .skip, null);
	defer {
		g.arena.deinit();
		t.allocator.destroy(g);
	}
	const policy = g.entries[0].policy;

	// 42 is in gg-0002's projects[] (namespace grant, mr cap)
	const segs = [_][]const u8{ "api", "v4", "projects", "42", "merge_requests" };
	const req = mkReq(.GET, &segs, &.{});
	const route = policy.vtable.classify(policy.ctx, &req).?;
	const d = policy.vtable.authorize(policy.ctx, &route, &req);
	try t.expectEqualStrings("gg-0002", d.allow);

	// 1234 is gg-0001's project_id (issues cap)
	const segs2 = [_][]const u8{ "api", "v4", "projects", "1234", "issues" };
	const req2 = mkReq(.GET, &segs2, &.{});
	const route2 = policy.vtable.classify(policy.ctx, &req2).?;
	try t.expectEqualStrings("gg-0001", policy.vtable.authorize(policy.ctx, &route2, &req2).allow);

	// 999 is covered by NO grant's numeric authorization -> scope_mismatch
	const segs3 = [_][]const u8{ "api", "v4", "projects", "999", "issues" };
	const req3 = mkReq(.GET, &segs3, &.{});
	const route3 = policy.vtable.classify(policy.ctx, &req3).?;
	try t.expectEqual(plugin_mod.DenyReason.scope_mismatch, policy.vtable.authorize(policy.ctx, &route3, &req3).deny);
}

test "gitlab: api-group-projects classifies a group path/subgroup/numeric, never a reserved tail or the group node" {
	const g = try conf.parseGeneration(t.allocator, undefined, conf.test_conf_json, 1, .skip, null);
	defer {
		g.arena.deinit();
		t.allocator.destroy(g);
	}
	const policy = g.entries[0].policy;

	const Case = struct { segs: []const []const u8, want: ?[]const u8 };
	const cases = [_]Case{
		// a single top-level group is well-formed here (unlike a project ref)
		.{ .segs = &.{ "api", "v4", "groups", "acme", "projects" }, .want = "api-group-projects" },
		// a subgroup path form (one segment whose value holds a slash)
		.{ .segs = &.{ "api", "v4", "groups", "grp/sub", "projects" }, .want = "api-group-projects" },
		// the numeric form is recognized at classify (authorize scope-denies it)
		.{ .segs = &.{ "api", "v4", "groups", "77", "projects" }, .want = "api-group-projects" },
		// a reserved tail routes NOWHERE, exactly as before the enumeration route
		.{ .segs = &.{ "api", "v4", "groups", "77", "access_tokens" }, .want = null },
		// the group NODE itself is not a route (probe a repo under it, or enumerate)
		.{ .segs = &.{ "api", "v4", "groups", "77" }, .want = null },
		// a `-` infix component is refused, so no route
		.{ .segs = &.{ "api", "v4", "groups", "-", "projects" }, .want = null },
	};
	for (cases) |c| {
		const req = mkReq(.GET, c.segs, &.{});
		const route = policy.vtable.classify(policy.ctx, &req);
		if (c.want) |w| {
			try t.expectEqualStrings(w, route.?.id);
		} else {
			try t.expect(route == null);
		}
	}
}

test "gitlab: api-group-projects is namespace-scoped, equals-or-under, path-form only" {
	// The fixture's gg-0002 is a namespace grant on /grp/sub/ carrying git-read.
	const g = try conf.parseGeneration(t.allocator, undefined, conf.test_conf_json, 1, .skip, null);
	defer {
		g.arena.deinit();
		t.allocator.destroy(g);
	}
	const policy = g.entries[0].policy;

	const Case = struct { group: []const u8, want_allow: bool, grant: []const u8 = "" };
	const cases = [_]Case{
		// the namespace node itself (equal) and a subgroup (strictly under)
		.{ .group = "grp/sub", .want_allow = true, .grant = "gg-0002" },
		.{ .group = "grp/sub/team", .want_allow = true, .grant = "gg-0002" },
		// a sibling, the parent, and a string-prefix sibling all stay OUT
		.{ .group = "grp/other", .want_allow = false },
		.{ .group = "grp", .want_allow = false },
		.{ .group = "grp/sub-secret", .want_allow = false },
		// GitLab group paths are case-insensitive: folded components still match
		// whole components only
		.{ .group = "Grp/SUB", .want_allow = true, .grant = "gg-0002" },
		.{ .group = "GRP/sub/Team", .want_allow = true, .grant = "gg-0002" },
		.{ .group = "GRP/Other", .want_allow = false },
		.{ .group = "GRP", .want_allow = false },
		.{ .group = "Grp/Sub-Secret", .want_allow = false },
		// the numeric form fails closed even though 77 is in gg-0002's projects[]
		// (those are project ids, never a group id)
		.{ .group = "77", .want_allow = false },
	};
	for (cases) |c| {
		const segs = [_][]const u8{ "api", "v4", "groups", c.group, "projects" };
		const req = mkReq(.GET, &segs, &.{});
		const route = policy.vtable.classify(policy.ctx, &req).?;
		try t.expectEqualStrings("api-group-projects", route.id);
		const d = policy.vtable.authorize(policy.ctx, &route, &req);
		if (c.want_allow) {
			try t.expectEqualStrings(c.grant, d.allow);
		} else {
			try t.expectEqual(plugin_mod.DenyReason.scope_mismatch, d.deny);
		}
	}

	// A concrete grant and an instance grant never authorize enumeration, so the
	// no-instance-wide-enumeration-oracle property holds even under the widest
	// fixture (which carries an instance git-read grant, gg-0003).
	const only_ns = try conf.parseGeneration(t.allocator, undefined,
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2",
		\\"grants":[{"id":"gg-inst","scope":"instance","caps":["git-read"]},
		\\{"id":"gg-proj","scope":"project","repo":"grp/sub/a","project_id":"42","caps":["git-read"]}]}]}
	, 1, .skip, null);
	defer {
		only_ns.arena.deinit();
		t.allocator.destroy(only_ns);
	}
	const pol2 = only_ns.entries[0].policy;
	const segs = [_][]const u8{ "api", "v4", "groups", "grp/sub", "projects" };
	const req = mkReq(.GET, &segs, &.{});
	const route = pol2.vtable.classify(pol2.ctx, &req).?;
	// git-read IS present (cap seen), but neither scope authorizes the group route
	try t.expectEqual(plugin_mod.DenyReason.scope_mismatch, pol2.vtable.authorize(pol2.ctx, &route, &req).deny);
}

test "gitlab: the two read routes FORCE simple=true in the constructed upstream query" {
	const g = try conf.parseGeneration(t.allocator, undefined, conf.test_conf_json, 1, .skip, null);
	defer {
		g.arena.deinit();
		t.allocator.destroy(g);
	}
	const policy = g.entries[0].policy;

	// group enumeration: simple + include_subgroups forced; a pagination param
	// kept; an off-allowlist order_by and a client simple=false both dropped.
	const q = [_]canon.QueryParam{
		.{ .key = "per_page", .value_raw = "100", .raw = "per_page=100" },
		.{ .key = "order_by", .value_raw = "id", .raw = "order_by=id" },
		.{ .key = "simple", .value_raw = "false", .raw = "simple=false" },
	};
	const segs = [_][]const u8{ "api", "v4", "groups", "grp/sub", "projects" };
	const req = mkReq(.GET, &segs, &q);
	const route = policy.vtable.classify(policy.ctx, &req).?;
	var up: plugin_mod.Upstream = .{};
	try policy.vtable.upstream(policy.ctx, &route, &req, &up);
	try t.expectEqualStrings("/api/v4/groups/grp%2Fsub/projects", up.path());
	try t.expectEqualStrings("simple=true&include_subgroups=true&per_page=100", up.query());

	// concrete project metadata: simple forced (belt-and-braces only -- GitLab
	// does NOT honour `simple` on a single-project GET, so the runners_token leak
	// here is closed by the response projection, not this query), a client
	// simple=false dropped, an unrelated statistics=true kept.
	const q2 = [_]canon.QueryParam{
		.{ .key = "simple", .value_raw = "false", .raw = "simple=false" },
		.{ .key = "statistics", .value_raw = "true", .raw = "statistics=true" },
	};
	const segs2 = [_][]const u8{ "api", "v4", "projects", "grp/proj" };
	const req2 = mkReq(.GET, &segs2, &q2);
	const route2 = policy.vtable.classify(policy.ctx, &req2).?;
	try t.expectEqualStrings("api-project", route2.id);
	var up2: plugin_mod.Upstream = .{};
	try policy.vtable.upstream(policy.ctx, &route2, &req2, &up2);
	try t.expectEqualStrings("/api/v4/projects/grp%2Fproj", up2.path());
	try t.expectEqualStrings("simple=true&statistics=true", up2.query());
}

test "gitlab: /_cogbox/grants is a local route -- classify marks it, authorize allows GET/HEAD on method alone, clamps the rest" {
	const g = try conf.parseGeneration(t.allocator, undefined, conf.test_conf_json, 1, .skip, null);
	defer {
		g.arena.deinit();
		t.allocator.destroy(g);
	}
	const policy = g.entries[0].policy;

	// classify recognizes the reserved surface and marks it local
	const segs = [_][]const u8{ "_cogbox", "grants" };
	for ([_]std.http.Method{ .GET, .HEAD, .POST, .DELETE }) |method| {
		const req = mkReq(method, &segs, &.{});
		const route = policy.vtable.classify(policy.ctx, &req).?;
		try t.expectEqualStrings("cogbox-grants", route.id);
		try t.expect(route.local);
		try t.expectEqual(plugin_mod.Layer.api, route.layer);
		try t.expect(!route.stream);
		const d = policy.vtable.authorize(policy.ctx, &route, &req);
		if (method == .GET or method == .HEAD) {
			// allowed on method alone -- no scope, the grant label is "-"
			try t.expectEqualStrings("-", d.allow);
		} else {
			try t.expectEqual(plugin_mod.DenyReason.method_not_allowed, d.deny);
		}
	}

	// any OTHER _cogbox path (and the node itself) routes NOWHERE
	const other = [_][]const u8{ "_cogbox", "secrets" };
	try t.expect(policy.vtable.classify(policy.ctx, &mkReq(.GET, &other, &.{})) == null);
	const node = [_][]const u8{"_cogbox"};
	try t.expect(policy.vtable.classify(policy.ctx, &mkReq(.GET, &node, &.{})) == null);
	const deeper = [_][]const u8{ "_cogbox", "grants", "x" };
	try t.expect(policy.vtable.classify(policy.ctx, &mkReq(.GET, &deeper, &.{})) == null);
}

test "gitlab: /_cogbox/grants renders the grants JSON -- every scope, path-form prefix, and NO numeric id or token" {
	// The fixture carries all three scopes: a project (repo grp/proj, project_id
	// 1234, projects[] 42/77 internal), a namespace (/grp/sub/), an instance.
	const g = try conf.parseGeneration(t.allocator, undefined, conf.test_conf_json, 1, .skip, null);
	defer {
		g.arena.deinit();
		t.allocator.destroy(g);
	}
	const policy = g.entries[0].policy;
	const segs = [_][]const u8{ "_cogbox", "grants" };
	const req = mkReq(.GET, &segs, &.{});
	const route = policy.vtable.classify(policy.ctx, &req).?;

	var buf: [4096]u8 = undefined;
	var w: std.Io.Writer = .fixed(&buf);
	try policy.vtable.localResponse.?(policy.ctx, &route, &req, &w);
	const body = w.buffered();

	// structural parse: three grants, path-form prefix on the namespace only
	var arena = std.heap.ArenaAllocator.init(t.allocator);
	defer arena.deinit();
	const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), body, .{});
	const grants = parsed.object.get("grants").?.array;
	try t.expectEqual(@as(usize, 3), grants.items.len);
	var saw_ns = false;
	var saw_instance = false;
	for (grants.items) |gv| {
		const o = gv.object;
		const scope = o.get("scope").?.string;
		if (std.mem.eql(u8, scope, "namespace")) {
			saw_ns = true;
			try t.expectEqualStrings("grp/sub", o.get("prefix").?.string); // clean path form
			try t.expectEqualStrings("grp/sub/*", o.get("repo").?.string);
		} else {
			try t.expect(o.get("prefix") == null); // prefix is namespace-only
			if (std.mem.eql(u8, scope, "instance")) {
				saw_instance = true;
				try t.expect(o.get("repo") == null); // an instance grant names no repo
			}
		}
	}
	try t.expect(saw_ns and saw_instance);

	// NEVER a numeric project id (project_id 1234 / projects[] 42,77), a
	// credential, or a projected upstream secret -- only the non-secret shape.
	for ([_][]const u8{ "1234", "project_id", "\"42\"", "\"77\"", "glpat", "runners_token" }) |needle| {
		if (std.mem.indexOf(u8, body, needle) != null) {
			std.debug.print("/_cogbox/grants body leaked {s}: {s}\n", .{ needle, body });
			return error.GrantsBodyLeak;
		}
	}
}

// --- v2 units: the twelve caps, the push-rule grammar, the new clamps ---

/// Parse a conf and hand back the generation; the caller deinits. `undefined`
/// io is safe under `.skip` (no trust store is loaded), matching the units
/// above.
fn testGen(json: []const u8) !*conf.Generation {
	return conf.parseGeneration(t.allocator, undefined, json, 1, .skip, null);
}

fn freeGen(g: *conf.Generation) void {
	g.arena.deinit();
	t.allocator.destroy(g);
}

/// One instance-scope grant with the given caps and (optional) push object.
fn testCapConf(caps_json: []const u8, push_json: ?[]const u8) ![]u8 {
	return std.fmt.allocPrint(t.allocator,
		"{{\"version\":1,\"providers\":[{{\"host\":\"git.example.com\",\"plugin\":\"gitlab\"," ++
			"\"scheme\":\"http\",\"cred_file\":\"/x\",\"git_user\":\"oauth2\"," ++
			"\"grants\":[{{\"id\":\"g\",\"scope\":\"instance\",\"caps\":{s}{s}{s}}}]}}]}}",
		.{ caps_json, if (push_json != null) ",\"push\":" else "", push_json orelse "" });
}

test "gitlab: compile takes the v2 cap names and EXPANDS the v1 coarse ones; anything else fails closed" {
	const g = try testGen(conf.test_conf_v2_json);
	defer freeGen(g);
	// gg-v2a names all twelve, so every field of the set must be on -- the one
	// assertion that catches a cap string added to the doc but not to applyCap.
	const all = compiled(g.entries[0].policy.ctx).grants[0].caps;
	inline for (@typeInfo(Caps).@"struct".fields) |f| {
		if (!@field(all, f.name)) {
			std.debug.print("v2 fixture did not set caps.{s}\n", .{f.name});
			return error.CapNotCompiled;
		}
	}

	// The LEGACY dialect expands, and expands EXACTLY: `issues` is the two
	// halves, and v1 `mr` included approve/merge so it is the whole triple.
	const v1 = try testGen(conf.test_conf_json);
	defer freeGen(v1);
	const gr = compiled(v1.entries[0].policy.ctx).grants;
	try t.expect(gr[0].caps.issues_read and gr[0].caps.issues_write); // gg-0001 ["...","issues"]
	try t.expect(!gr[0].caps.mr_read and !gr[0].caps.mr_merge); // and nothing it did not name
	const mr = gr[2].caps; // gg-0003 ["git-read","mr"]
	try t.expect(mr.mr_read and mr.mr_write and mr.mr_merge);
	try t.expect(!mr.issues_read and !mr.pipelines_read and !mr.repo_read and !mr.wiki_read);
	try t.expect(gr[2].push == null); // no push key, no rules -- the fast path

	// An unrecognized cap still fails the WHOLE conf (the four-cap era's
	// posture, unchanged): a near-miss of a v2 name is not a v2 name.
	for ([_][]const u8{ "admin", "api-full", "issues:admin", "mr:", "ISSUES:READ", "repo:write" }) |bad| {
		const caps = try std.fmt.allocPrint(t.allocator, "[\"{s}\"]", .{bad});
		defer t.allocator.free(caps);
		const json = try testCapConf(caps, null);
		defer t.allocator.free(json);
		try t.expectError(error.BadConf, conf.parseGeneration(t.allocator, undefined, json, 1, .skip, null));
	}
}

test "gitlab: push rules compile only on a git-write grant, bounded and grammar-checked" {
	const g = try testGen(conf.test_conf_v2_json);
	defer freeGen(g);
	const grants = compiled(g.entries[0].policy.ctx).grants;
	const p = grants[0].push.?;
	try t.expect(p.deny_delete and p.deny_tags);
	try t.expectEqual(@as(usize, 2), p.refs.len);
	try t.expectEqualStrings("refs/heads/agent/*", p.refs[0].raw);
	try t.expectEqual(@as(usize, 4), p.refs[0].comps.len);
	try t.expectEqualStrings("refs", p.refs[0].comps[0]);
	try t.expectEqualStrings("heads", p.refs[0].comps[1]);
	try t.expectEqualStrings("agent", p.refs[0].comps[2]);
	try t.expectEqualStrings("*", p.refs[0].comps[3]);
	try t.expectEqualStrings("**", p.refs[1].comps[3]);
	try t.expect(grants[1].push == null); // a grant without the key is unrestricted

	// Every refusal fails the WHOLE conf: a push rule that cannot be evaluated
	// must never degrade into "no restriction".
	const Bad = struct { caps: []const u8, push: []const u8, why: []const u8 };
	const bad = [_]Bad{
		.{ .caps = "[\"git-read\"]", .push = "{\"refs\":[\"refs/heads/x\"]}", .why = "rules on a grant that cannot push" },
		.{ .caps = "[\"git-read\"]", .push = "{\"deny_delete\":true}", .why = "...even flags alone" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"refs/heads/a\",\"refs/heads/b\",\"refs/heads/c\",\"refs/heads/d\",\"refs/heads/e\",\"refs/heads/f\",\"refs/heads/g\",\"refs/heads/h\",\"refs/heads/i\"]}", .why = "nine patterns, one over the cap" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"main\"]}", .why = "not anchored at refs/" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"refs/remotes/x\"]}", .why = "anchored, but not heads/tags" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"refs/heads/\"]}", .why = "a trailing slash" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"refs/heads//x\"]}", .why = "an empty component" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"refs/heads/..\"]}", .why = "a dot-dot component" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"refs/heads/.hidden\"]}", .why = "a component starting with a dot" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"refs/heads/x.lock\"]}", .why = "a .lock suffix" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"refs/heads/a b\"]}", .why = "whitespace" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"refs/heads/a^b\"]}", .why = "a revision-syntax byte" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"refs/heads/a?b\"]}", .why = "a glob byte outside the two wildcards" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"refs/heads/ag*ent\"]}", .why = "a wildcard must be a WHOLE component" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"refs/tags/v*\"]}", .why = "...a trailing one too" },
		.{ .caps = "[\"git-write\"]", .push = "{\"refs\":[\"\"]}", .why = "an empty pattern" },
		.{
			.caps = "[\"git-write\"]",
			.push = "{\"refs\":[\"refs/heads/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]}",
			.why = "129 bytes, one over the cap",
		},
	};
	for (bad) |b| {
		const json = try testCapConf(b.caps, b.push);
		defer t.allocator.free(json);
		if (conf.parseGeneration(t.allocator, undefined, json, 1, .skip, null)) |accepted| {
			freeGen(accepted);
			std.debug.print("push rule ACCEPTED that must fail closed: {s}\n", .{b.why});
			return error.PushRuleAccepted;
		} else |err| {
			try t.expect(err == error.BadConf);
		}
	}

	// The accepted grammar, end to end: both wildcards (WHOLE components only --
	// `refs/tags/v*` is in the refusal list above), a tag anchor, and the eighth
	// pattern still inside the cap.
	const okj = try testCapConf("[\"git-write\"]",
		"{\"refs\":[\"refs/heads/main\",\"refs/heads/*\",\"refs/heads/**\",\"refs/tags/*\"," ++
			"\"refs/heads/a-b\",\"refs/heads/a_b\",\"refs/heads/a.b\",\"refs/heads/*/sub/**\"]}");
	defer t.allocator.free(okj);
	const okg = try testGen(okj);
	defer freeGen(okg);
	try t.expectEqual(@as(usize, 8), compiled(okg.entries[0].policy.ctx).grants[0].push.?.refs.len);
}

test "gitlab: the method clamps -- pipeline/job POSTs only on the control tails, repository writes nowhere, DELETE nowhere" {
	// The v2 fixture's first grant is a CONCRETE grant on 1234 carrying all
	// twelve caps, so a deny here is the clamp's and never a missing cap.
	const g = try testGen(conf.test_conf_v2_json);
	defer freeGen(g);
	const policy = g.entries[0].policy;

	const Case = struct { m: std.http.Method, segs: []const []const u8, allow: bool };
	const cases = [_]Case{
		// pipelines: retry/cancel at <id>/<verb>, and nothing else
		.{ .m = .POST, .segs = &.{ "api", "v4", "projects", "1234", "pipelines", "9", "retry" }, .allow = true },
		.{ .m = .POST, .segs = &.{ "api", "v4", "projects", "1234", "pipelines", "9", "cancel" }, .allow = true },
		.{ .m = .POST, .segs = &.{ "api", "v4", "projects", "1234", "pipelines" }, .allow = false },
		.{ .m = .POST, .segs = &.{ "api", "v4", "projects", "1234", "pipelines", "9" }, .allow = false },
		.{ .m = .POST, .segs = &.{ "api", "v4", "projects", "1234", "pipelines", "9", "retry", "x" }, .allow = false },
		.{ .m = .PUT, .segs = &.{ "api", "v4", "projects", "1234", "pipelines", "9", "retry" }, .allow = false },
		.{ .m = .GET, .segs = &.{ "api", "v4", "projects", "1234", "pipelines", "9" }, .allow = true },
		// jobs: retry/cancel/play, but never erase (irreversible)
		.{ .m = .POST, .segs = &.{ "api", "v4", "projects", "1234", "jobs", "7", "play" }, .allow = true },
		.{ .m = .POST, .segs = &.{ "api", "v4", "projects", "1234", "jobs", "7", "erase" }, .allow = false },
		// the trigger leaf is POST-only
		.{ .m = .POST, .segs = &.{ "api", "v4", "projects", "1234", "pipeline" }, .allow = true },
		.{ .m = .GET, .segs = &.{ "api", "v4", "projects", "1234", "pipeline" }, .allow = false },
		// repository: reads yes, WRITES never (file-header invariant 2)
		.{ .m = .GET, .segs = &.{ "api", "v4", "projects", "1234", "repository", "tree" }, .allow = true },
		.{ .m = .POST, .segs = &.{ "api", "v4", "projects", "1234", "repository", "commits" }, .allow = false },
		.{ .m = .PUT, .segs = &.{ "api", "v4", "projects", "1234", "repository", "files", "x" }, .allow = false },
		.{ .m = .POST, .segs = &.{ "api", "v4", "projects", "1234", "repository", "branches" }, .allow = false },
		// wikis take the full read/write method set...
		.{ .m = .PUT, .segs = &.{ "api", "v4", "projects", "1234", "wikis", "home" }, .allow = true },
		// ...and DELETE is in no route's set anywhere (invariant 1)
		.{ .m = .DELETE, .segs = &.{ "api", "v4", "projects", "1234", "wikis", "home" }, .allow = false },
		.{ .m = .DELETE, .segs = &.{ "api", "v4", "projects", "1234", "repository", "tree" }, .allow = false },
		.{ .m = .DELETE, .segs = &.{ "api", "v4", "projects", "1234", "merge_requests", "5", "merge" }, .allow = false },
	};
	for (cases) |c| {
		const req = mkReq(c.m, c.segs, &.{});
		const route = policy.vtable.classify(policy.ctx, &req).?;
		const d = policy.vtable.authorize(policy.ctx, &route, &req);
		if (c.allow) {
			if (d != .allow) {
				std.debug.print("clamp denied {s} on {s}: {s}\n", .{ @tagName(c.m), route.id, @tagName(d.deny) });
				return error.UnexpectedDeny;
			}
		} else {
			try t.expectEqual(plugin_mod.DenyReason.method_not_allowed, d.deny);
		}
	}

	// `/pipelines/:id/variables` is a NAMED no_route, not a clamp: even a GET
	// under the all-twelve grant never gets a route at all.
	const vars = [_][]const u8{ "api", "v4", "projects", "1234", "pipelines", "9", "variables" };
	try t.expect(policy.vtable.classify(policy.ctx, &mkReq(.GET, &vars, &.{})) == null);
	const vars_deep = [_][]const u8{ "api", "v4", "projects", "1234", "pipelines", "9", "variables", "K" };
	try t.expect(policy.vtable.classify(policy.ctx, &mkReq(.GET, &vars_deep, &.{})) == null);
}

test "gitlab: upstream rebuilds the new collections from LITERALS and re-encodes the %2F-bearing tails" {
	const g = try testGen(conf.test_conf_v2_json);
	defer freeGen(g);
	const policy = g.entries[0].policy;

	const Case = struct { m: std.http.Method, segs: []const []const u8, id: []const u8, path: []const u8 };
	const cases = [_]Case{
		.{
			.m = .POST,
			.segs = &.{ "api", "v4", "projects", "1234", "pipelines", "9", "retry" },
			.id = "api-pipelines",
			.path = "/api/v4/projects/1234/pipelines/9/retry",
		},
		.{
			.m = .POST,
			.segs = &.{ "api", "v4", "projects", "1234", "pipeline" },
			.id = "api-pipeline-trigger",
			.path = "/api/v4/projects/1234/pipeline",
		},
		.{
			.m = .GET,
			.segs = &.{ "api", "v4", "projects", "1234", "jobs", "7", "trace" },
			.id = "api-jobs",
			.path = "/api/v4/projects/1234/jobs/7/trace",
		},
		.{
			.m = .PUT,
			.segs = &.{ "api", "v4", "projects", "1234", "merge_requests", "5", "merge" },
			.id = "api-mr-merge",
			.path = "/api/v4/projects/1234/merge_requests/5/merge",
		},
		// A file path is ONE segment holding slashes: it must come back out as
		// %2F under the /repository/files/ literal, never as real separators.
		.{
			.m = .GET,
			.segs = &.{ "api", "v4", "projects", "1234", "repository", "files", "src/main.go", "raw" },
			.id = "api-repo",
			.path = "/api/v4/projects/1234/repository/files/src%2Fmain.go/raw",
		},
		// The same for a wiki slug, under a path-form project id.
		.{
			.m = .GET,
			.segs = &.{ "api", "v4", "projects", "grp/proj", "wikis", "home/sub" },
			.id = "api-wiki",
			.path = "/api/v4/projects/grp%2Fproj/wikis/home%2Fsub",
		},
	};
	for (cases) |c| {
		const req = mkReq(c.m, c.segs, &.{});
		const route = policy.vtable.classify(policy.ctx, &req).?;
		try t.expectEqualStrings(c.id, route.id);
		var up: plugin_mod.Upstream = .{};
		try policy.vtable.upstream(policy.ctx, &route, &req, &up);
		try t.expectEqualStrings(c.path, up.path());
		try t.expectEqualStrings("", up.query());
	}
}

test "gitlab: /_cogbox/grants reflects the TWELVE v2 names in canonical order and FLAT push keys" {
	const g = try testGen(conf.test_conf_v2_json);
	defer freeGen(g);
	const policy = g.entries[0].policy;
	const segs = [_][]const u8{ "_cogbox", "grants" };
	const req = mkReq(.GET, &segs, &.{});
	const route = policy.vtable.classify(policy.ctx, &req).?;

	var buf: [4096]u8 = undefined;
	var w: std.Io.Writer = .fixed(&buf);
	try policy.vtable.localResponse.?(policy.ctx, &route, &req, &w);
	const body = w.buffered();

	// The push rules are FLAT: treemn-check's grant splitter assumes no nested
	// braces, so a `"push":{...}` object would break every deployed copy.
	try t.expect(std.mem.indexOf(u8, body, "\"push\":") == null);

	var arena = std.heap.ArenaAllocator.init(t.allocator);
	defer arena.deinit();
	const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), body, .{});
	const grants = parsed.object.get("grants").?.array;
	try t.expectEqual(@as(usize, 2), grants.items.len);

	const want_order = [_][]const u8{
		"git-read",
		"git-write",
		"issues:read",
		"issues:write",
		"mr:read",
		"mr:write",
		"mr:merge",
		"pipelines:read",
		"pipelines:write",
		"repo:read",
		"wiki:read",
		"wiki:write",
	};
	const first = grants.items[0].object;
	const caps = first.get("caps").?.array;
	try t.expectEqual(want_order.len, caps.items.len);
	for (want_order, 0..) |want, i| try t.expectEqualStrings(want, caps.items[i].string);
	const refs = first.get("push_refs").?.array;
	try t.expectEqual(@as(usize, 2), refs.items.len);
	try t.expectEqualStrings("refs/heads/agent/*", refs.items[0].string);
	try t.expect(first.get("push_deny_delete").?.bool);
	try t.expect(first.get("push_deny_tags").?.bool);

	// A grant with no rules emits NO push keys at all (absent means
	// unrestricted; an empty array would read as "no ref is allowed").
	const second = grants.items[1].object;
	try t.expect(second.get("push_refs") == null);
	try t.expect(second.get("push_deny_delete") == null);
	try t.expectEqualStrings("grp/sub", second.get("prefix").?.string);

	// Still no numeric id and no credential, exactly as under v1.
	for ([_][]const u8{ "1234", "project_id", "\"42\"", "glpat", "runners_token" }) |needle| {
		if (std.mem.indexOf(u8, body, needle) != null) {
			std.debug.print("/_cogbox/grants body leaked {s}: {s}\n", .{ needle, body });
			return error.GrantsBodyLeak;
		}
	}
}

test "gitlab: /_cogbox/grants reflects what this binary ENFORCES -- a v1 coarse doc comes back expanded" {
	// The reflection is the enforcement surface, not an echo of the document:
	// an unedited `mr` grant enforces the mr triple here, so it must SAY so or
	// the in-sandbox agent (and treemn-check) reads a stale vocabulary.
	const g = try testGen(conf.test_conf_json);
	defer freeGen(g);
	const policy = g.entries[0].policy;
	const segs = [_][]const u8{ "_cogbox", "grants" };
	const req = mkReq(.GET, &segs, &.{});
	const route = policy.vtable.classify(policy.ctx, &req).?;

	var buf: [4096]u8 = undefined;
	var w: std.Io.Writer = .fixed(&buf);
	try policy.vtable.localResponse.?(policy.ctx, &route, &req, &w);
	const body = w.buffered();
	try t.expect(std.mem.indexOf(u8, body, "\"issues:read\"") != null);
	try t.expect(std.mem.indexOf(u8, body, "\"issues:write\"") != null);
	try t.expect(std.mem.indexOf(u8, body, "\"mr:merge\"") != null);
	// the coarse spellings are gone from the wire
	try t.expect(std.mem.indexOf(u8, body, "\"issues\"") == null);
	try t.expect(std.mem.indexOf(u8, body, "\"mr\"") == null);
	// and no push keys anywhere: a v1 document carries none
	try t.expect(std.mem.indexOf(u8, body, "push_") == null);
}

// --- push-rule units: the glob, the two deny flags, the union, the fast path ---

const oid_x = "1" ** 40;
const oid_y = "2" ** 40;
const oid_zero = "0" ** 40;

/// A `git-receive` route for `<segs>` -- the shape the mediate hook runs on.
/// The returned route borrows `segs`, which the caller keeps alive.
fn pushRoute(policy: plugin_mod.Policy, segs: []const []const u8) plugin_mod.Route {
	const req = mkReq(.POST, segs, &.{});
	return policy.vtable.classify(policy.ctx, &req).?;
}

fn mkCmd(ref: []const u8, is_delete: bool) pktline.Command {
	return .{
		.old_oid = oid_x,
		.new_oid = if (is_delete) oid_zero else oid_y,
		.ref = ref,
		.is_delete = is_delete,
		.is_tag = std.mem.startsWith(u8, ref, "refs/tags/"),
	};
}

/// Evaluate one refname against one compiled pattern.
fn matchOne(arena: std.mem.Allocator, pat: []const u8, ref: []const u8) !bool {
	const p = (try compileRefPattern(arena, pat)) orelse return error.PatternRefused;
	const one = [_]RefPattern{p};
	const rules = PushRules{ .refs = &one, .deny_delete = false, .deny_tags = false };
	var buf: [pktline.max_ref_components][]const u8 = undefined;
	return refMatches(&rules, splitRef(ref, &buf).?);
}

test "gitlab: refMatches is component-wise -- * is exactly one, ** is one or more, and neither matches a partial component" {
	var arena = std.heap.ArenaAllocator.init(t.allocator);
	defer arena.deinit();
	const a = arena.allocator();

	const Case = struct { pat: []const u8, ref: []const u8, want: bool };
	const cases = [_]Case{
		// literals
		.{ .pat = "refs/heads/main", .ref = "refs/heads/main", .want = true },
		.{ .pat = "refs/heads/main", .ref = "refs/heads/main2", .want = false },
		.{ .pat = "refs/heads/main", .ref = "refs/heads/main/x", .want = false },
		// `*` is EXACTLY one component
		.{ .pat = "refs/heads/*", .ref = "refs/heads/x", .want = true },
		.{ .pat = "refs/heads/*", .ref = "refs/heads/a/b", .want = false },
		.{ .pat = "refs/heads/*", .ref = "refs/heads", .want = false },
		// ...and a component boundary is a boundary: agent-x is not under agent/
		.{ .pat = "refs/heads/agent/*", .ref = "refs/heads/agent/x", .want = true },
		.{ .pat = "refs/heads/agent/*", .ref = "refs/heads/agent-x", .want = false },
		.{ .pat = "refs/heads/agent/*", .ref = "refs/heads/agent", .want = false },
		.{ .pat = "refs/heads/agent/*", .ref = "refs/heads/agent/a/b", .want = false },
		// `**` is one or more -- never zero
		.{ .pat = "refs/heads/**", .ref = "refs/heads/a", .want = true },
		.{ .pat = "refs/heads/**", .ref = "refs/heads/a/b/c", .want = true },
		.{ .pat = "refs/heads/**", .ref = "refs/heads", .want = false },
		.{ .pat = "refs/heads/**", .ref = "refs/tags/a", .want = false },
		// a `**` in the middle backtracks until the tail lines up
		.{ .pat = "refs/heads/**/sub", .ref = "refs/heads/a/sub", .want = true },
		.{ .pat = "refs/heads/**/sub", .ref = "refs/heads/a/b/sub", .want = true },
		.{ .pat = "refs/heads/**/sub", .ref = "refs/heads/sub", .want = false },
		.{ .pat = "refs/heads/**/sub", .ref = "refs/heads/a/sub/x", .want = false },
		.{ .pat = "refs/heads/*/sub/**", .ref = "refs/heads/x/sub/a", .want = true },
		.{ .pat = "refs/heads/*/sub/**", .ref = "refs/heads/x/sub", .want = false },
		// the tag anchor is a different subtree, not a prefix
		.{ .pat = "refs/tags/*", .ref = "refs/tags/v1.0", .want = true },
		.{ .pat = "refs/tags/*", .ref = "refs/heads/v1.0", .want = false },
	};
	for (cases) |c| {
		const got = try matchOne(a, c.pat, c.ref);
		if (got != c.want) {
			std.debug.print("refMatches({s}, {s}) = {}, want {}\n", .{ c.pat, c.ref, got, c.want });
			return error.WrongMatch;
		}
	}

	// Several patterns are a union, and NO pattern means "any refname" (the
	// rule object then carries only the deny flags).
	const p1 = (try compileRefPattern(a, "refs/heads/agent/*")).?;
	const p2 = (try compileRefPattern(a, "refs/tags/*")).?;
	const two = [_]RefPattern{ p1, p2 };
	const union_rules = PushRules{ .refs = &two, .deny_delete = false, .deny_tags = false };
	var buf: [pktline.max_ref_components][]const u8 = undefined;
	try t.expect(refMatches(&union_rules, splitRef("refs/tags/v1", &buf).?));
	try t.expect(refMatches(&union_rules, splitRef("refs/heads/agent/x", &buf).?));
	try t.expect(!refMatches(&union_rules, splitRef("refs/heads/main", &buf).?));
	const anyref = PushRules{ .refs = &.{}, .deny_delete = false, .deny_tags = false };
	try t.expect(refMatches(&anyref, splitRef("refs/heads/main", &buf).?));
}

test "gitlab: deny_delete and deny_tags short-circuit the patterns" {
	// gg-v2a: push rules refs/heads/agent/* + refs/heads/release/**, BOTH deny
	// flags on, on the concrete project grp/proj.
	const g = try testGen(conf.test_conf_v2_json);
	defer freeGen(g);
	const grants = compiled(g.entries[0].policy.ctx).grants;
	const segs = [_][]const u8{ "grp", "proj.git", "git-receive-pack" };
	const route = pushRoute(g.entries[0].policy, &segs);

	const Case = struct { ref: []const u8, del: bool, want: bool, why: []const u8 };
	const cases = [_]Case{
		.{ .ref = "refs/heads/agent/x", .del = false, .want = true, .why = "an update on a matched ref" },
		.{ .ref = "refs/heads/release/1/2", .del = false, .want = true, .why = "** spans two components" },
		.{ .ref = "refs/heads/main", .del = false, .want = false, .why = "an unmatched ref" },
		.{ .ref = "refs/heads/agent/x", .del = true, .want = false, .why = "a DELETE of a matched ref under deny_delete" },
		// deny_tags wins even though refs/tags/* would be reachable if the owner
		// had listed it -- and here no tag pattern is listed either.
		.{ .ref = "refs/tags/v1", .del = false, .want = false, .why = "a tag under deny_tags" },
	};
	for (cases) |c| {
		const cmd = mkCmd(c.ref, c.del);
		var buf: [pktline.max_ref_components][]const u8 = undefined;
		const got = commandAdmitted(grants, &route, &cmd, splitRef(c.ref, &buf).?);
		if (got != c.want) {
			std.debug.print("commandAdmitted({s}) = {}, want {} -- {s}\n", .{ c.ref, got, c.want, c.why });
			return error.WrongVerdict;
		}
	}

	// The flags are independent of the patterns: a grant that lists a tag
	// pattern but sets deny_tags still refuses the tag, and one with no patterns
	// at all still refuses a delete.
	const g2 = try testGen(
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2",
		\\"grants":[{"id":"gg-flags","scope":"instance","caps":["git-write"],
		\\ "push":{"refs":["refs/tags/*"],"deny_delete":true,"deny_tags":true}}]}]}
	);
	defer freeGen(g2);
	const grants2 = compiled(g2.entries[0].policy.ctx).grants;
	const route2 = pushRoute(g2.entries[0].policy, &segs);
	var buf2: [pktline.max_ref_components][]const u8 = undefined;
	const tag = mkCmd("refs/tags/v1", false);
	try t.expect(!commandAdmitted(grants2, &route2, &tag, splitRef("refs/tags/v1", &buf2).?));
}

test "gitlab: push rules are a UNION -- a rule-free covering grant admits what a rules-bearing one denies" {
	// Two grants over the same project: a namespace grant fenced to
	// refs/heads/agent/*, and a concrete grant with no rules at all. The
	// tuples are additive in `authorize`, and they are additive here too.
	const g = try testGen(
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2",
		\\"grants":[{"id":"gg-ns","scope":"namespace","repo":"grp/*","prefix":"/grp/","caps":["git-read","git-write"],
		\\ "push":{"refs":["refs/heads/agent/*"],"deny_delete":true,"deny_tags":true}},
		\\{"id":"gg-free","scope":"project","repo":"grp/proj","project_id":"1234","caps":["git-read","git-write"]}]}]}
	);
	defer freeGen(g);
	const grants = compiled(g.entries[0].policy.ctx).grants;
	var buf: [pktline.max_ref_components][]const u8 = undefined;

	// grp/proj is covered by BOTH: the rule-free one admits main, the delete and
	// the tag the namespace rules refuse.
	const covered = [_][]const u8{ "grp", "proj.git", "git-receive-pack" };
	const route_both = pushRoute(g.entries[0].policy, &covered);
	for ([_]pktline.Command{
		mkCmd("refs/heads/main", false),
		mkCmd("refs/heads/main", true),
		mkCmd("refs/tags/v1", false),
	}) |cmd| {
		try t.expect(commandAdmitted(grants, &route_both, &cmd, splitRef(cmd.ref, &buf).?));
	}

	// grp/other is covered by the NAMESPACE grant only, so its rules bind there.
	const ns_only = [_][]const u8{ "grp", "other.git", "git-receive-pack" };
	const route_ns = pushRoute(g.entries[0].policy, &ns_only);
	const agent = mkCmd("refs/heads/agent/x", false);
	try t.expect(commandAdmitted(grants, &route_ns, &agent, splitRef(agent.ref, &buf).?));
	for ([_]pktline.Command{
		mkCmd("refs/heads/main", false),
		mkCmd("refs/heads/agent/x", true),
		mkCmd("refs/tags/v1", false),
	}) |cmd| {
		try t.expect(!commandAdmitted(grants, &route_ns, &cmd, splitRef(cmd.ref, &buf).?));
	}

	// GitLab resolves paths case-insensitively, so a mixed-case push names the
	// same projects: GRP/Proj still rides the rule-free grant, and GRP/Other is
	// still fenced by the namespace rules (folding never sheds them).
	const covered_mc = [_][]const u8{ "GRP", "Proj.git", "git-receive-pack" };
	const route_both_mc = pushRoute(g.entries[0].policy, &covered_mc);
	const main_cmd = mkCmd("refs/heads/main", false);
	try t.expect(commandAdmitted(grants, &route_both_mc, &main_cmd, splitRef(main_cmd.ref, &buf).?));
	const ns_only_mc = [_][]const u8{ "Grp", "OTHER.git", "git-receive-pack" };
	const route_ns_mc = pushRoute(g.entries[0].policy, &ns_only_mc);
	try t.expect(commandAdmitted(grants, &route_ns_mc, &agent, splitRef(agent.ref, &buf).?));
	try t.expect(!commandAdmitted(grants, &route_ns_mc, &main_cmd, splitRef(main_cmd.ref, &buf).?));
	// a ref NAME is case-sensitive (git refnames are): Agent/ is not agent/
	const agent_mc = mkCmd("refs/heads/Agent/x", false);
	try t.expect(!commandAdmitted(grants, &route_ns_mc, &agent_mc, splitRef(agent_mc.ref, &buf).?));

	// A grant WITHOUT git-write is not a candidate at all, however wide its
	// scope: the fixture's namespace grant covers grp/sub but reads only.
	const g2 = try testGen(conf.test_conf_v2_json);
	defer freeGen(g2);
	const sub = [_][]const u8{ "grp", "sub", "a.git", "git-receive-pack" };
	const route_sub = pushRoute(g2.entries[0].policy, &sub);
	const any = mkCmd("refs/heads/main", false);
	try t.expect(!commandAdmitted(compiled(g2.entries[0].policy.ctx).grants, &route_sub, &any, splitRef(any.ref, &buf).?));
}

// The mediate hook itself, driven directly: a refusing transport proves every
// verdict is reached BEFORE any dial, and a credential that would error proves
// none of them read one.

var mediate_test_bundle: std.crypto.Certificate.Bundle = .empty;
var mediate_test_lock: std.Io.RwLock = .init;

fn testUio(tr: *const upstream_mod.Transport, storage: *upstream_mod.ConnStorage) upstream_mod.UpstreamIO {
	return .{
		.transport = tr,
		.gpa = t.allocator,
		.io = undefined, // the refusing transport never touches io
		.entry_host = "git.example.com",
		.insecure = false,
		.vetted_ip = .{ .ipv4 = .{ 10, 0, 0, 5 } },
		.vetted_port = 443,
		.bundle = &mediate_test_bundle,
		.bundle_lock = &mediate_test_lock,
		.bundle_empty = false,
		.storage = storage,
	};
}

fn neverToken(_: *anyopaque) plugin_mod.Cred.TokenError![]const u8 {
	return error.CredentialUnavailable;
}

/// Run `mediate` over `body` on a `git-receive` route for `segs`, with a
/// transport that refuses every dial. Returns whether the hook took the request
/// over; the caller inspects `out`, `refusing.calls` and the body's seek.
fn runMediate(
	policy: plugin_mod.Policy,
	segs: []const []const u8,
	method: std.http.Method,
	body: ?*std.Io.Reader,
	refusing: *upstream_mod.RefusingTransport,
	out: *plugin_mod.Response,
) !bool {
	const storage = try t.allocator.create(upstream_mod.ConnStorage);
	defer t.allocator.destroy(storage);
	storage.* = .{};
	var uio = testUio(refusing.t(), storage);
	var dummy: u8 = 0;
	var cred: plugin_mod.Cred = .{ .ctx = &dummy, .tokenFn = neverToken };
	var req = mkReq(method, segs, &.{});
	req.body = body;
	const route = policy.vtable.classify(policy.ctx, &req).?;
	return policy.vtable.mediate.?(policy.ctx, &route, &req, &cred, &uio, out);
}

test "gitlab: mediate is a pure passthrough unless a covering grant carries push rules (fast-path pin)" {
	const push_body = pktline.frame(oid_x ++ " " ++ oid_y ++ " refs/heads/main\x00report-status") ++
		pktline.flush_pkt ++ "PACKDATA";

	// (a) the v1 fixture: git-write grants, NO push rules anywhere.
	{
		const g = try testGen(conf.test_conf_json);
		defer freeGen(g);
		var body: std.Io.Reader = .fixed(push_body);
		var refusing = upstream_mod.RefusingTransport{};
		var out: plugin_mod.Response = .{};
		const segs = [_][]const u8{ "grp", "proj.git", "git-receive-pack" };
		try t.expect(!try runMediate(g.entries[0].policy, &segs, .POST, &body, &refusing, &out));
		// the body reader is EXACTLY where the core left it: the default round
		// trip relays byte-identically to what it did before mediate existed
		try t.expectEqual(@as(usize, 0), body.seek);
		try t.expectEqual(@as(usize, 0), refusing.calls);
		try t.expect(out.deny == null and out.exchange == null);
	}

	// (b) the v2 fixture (gg-v2a DOES carry rules) on a route that is not
	// git-receive: the hook answers false on the id alone.
	{
		const g = try testGen(conf.test_conf_v2_json);
		defer freeGen(g);
		var body: std.Io.Reader = .fixed(push_body);
		var refusing = upstream_mod.RefusingTransport{};
		var out: plugin_mod.Response = .{};
		const segs = [_][]const u8{ "grp", "proj.git", "git-upload-pack" };
		try t.expect(!try runMediate(g.entries[0].policy, &segs, .POST, &body, &refusing, &out));
		try t.expectEqual(@as(usize, 0), body.seek);
	}

	// (c) the v2 fixture on a project its rules-bearing grant does NOT cover:
	// gg-v2b (grp/sub) has no git-write, so no candidate carries rules.
	{
		const g = try testGen(conf.test_conf_v2_json);
		defer freeGen(g);
		var body: std.Io.Reader = .fixed(push_body);
		var refusing = upstream_mod.RefusingTransport{};
		var out: plugin_mod.Response = .{};
		const segs = [_][]const u8{ "grp", "sub", "a.git", "git-receive-pack" };
		try t.expect(!try runMediate(g.entries[0].policy, &segs, .POST, &body, &refusing, &out));
		try t.expectEqual(@as(usize, 0), body.seek);
	}

	// (d) the scope test inside the fast-path scan: rules on ONE project must not
	// drag a push to a DIFFERENT project (covered by a rule-free grant) onto the
	// slow path -- and, since the rules there would have refused `main`, this is
	// the arm where getting the scope test wrong would show up as a spurious 403.
	{
		const g = try testGen(
			\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2",
			\\"grants":[{"id":"gg-fenced","scope":"project","repo":"grp/proj","project_id":"1234","caps":["git-write"],
			\\ "push":{"refs":["refs/heads/agent/*"]}},
			\\{"id":"gg-open","scope":"project","repo":"grp/other","project_id":"5678","caps":["git-write"]}]}]}
		);
		defer freeGen(g);
		var body: std.Io.Reader = .fixed(push_body);
		var refusing = upstream_mod.RefusingTransport{};
		var out: plugin_mod.Response = .{};
		const segs = [_][]const u8{ "grp", "other.git", "git-receive-pack" };
		try t.expect(!try runMediate(g.entries[0].policy, &segs, .POST, &body, &refusing, &out));
		try t.expectEqual(@as(usize, 0), body.seek);
		// ...while the fenced project itself DOES take the slow path and refuses
		var body2: std.Io.Reader = .fixed(push_body);
		var out2: plugin_mod.Response = .{};
		const fenced = [_][]const u8{ "grp", "proj.git", "git-receive-pack" };
		try t.expect(try runMediate(g.entries[0].policy, &fenced, .POST, &body2, &refusing, &out2));
		try t.expectEqualStrings("ref_denied", out2.deny.?);
		try t.expectEqual(@as(usize, 0), refusing.calls);
		// ...and so does the fenced project in another CASE: GitLab resolves
		// GRP/Proj to grp/proj, so the rules must bind it too (a case-sensitive
		// scan here would wave it through the fast path)
		var body3: std.Io.Reader = .fixed(push_body);
		var out3: plugin_mod.Response = .{};
		const fenced_mc = [_][]const u8{ "GRP", "Proj.git", "git-receive-pack" };
		try t.expect(try runMediate(g.entries[0].policy, &fenced_mc, .POST, &body3, &refusing, &out3));
		try t.expectEqualStrings("ref_denied", out3.deny.?);
		try t.expectEqual(@as(usize, 0), refusing.calls);
	}
}

test "gitlab: every mediate verdict is reached before any dial and without a credential" {
	const g = try testGen(conf.test_conf_v2_json);
	defer freeGen(g);
	const policy = g.entries[0].policy;
	const segs = [_][]const u8{ "grp", "proj.git", "git-receive-pack" };

	const Case = struct { body: []const u8, reason: []const u8, status: u16, why: []const u8 };
	const cases = [_]Case{
		.{
			.body = pktline.frame(oid_x ++ " " ++ oid_y ++ " refs/heads/main\x00report-status") ++
				pktline.flush_pkt ++ "PACK",
			.reason = "ref_denied",
			.status = 403,
			.why = "a ref outside the patterns",
		},
		.{
			// one allowed, one denied: the WHOLE push goes, never a subset
			.body = pktline.frame(oid_x ++ " " ++ oid_y ++ " refs/heads/agent/x") ++
				pktline.frame(oid_x ++ " " ++ oid_y ++ " refs/heads/main") ++
				pktline.flush_pkt ++ "PACK",
			.reason = "ref_denied",
			.status = 403,
			.why = "a mixed push",
		},
		.{
			.body = pktline.frame(oid_x ++ " " ++ oid_zero ++ " refs/heads/agent/x") ++ pktline.flush_pkt,
			.reason = "ref_denied",
			.status = 403,
			.why = "a delete under deny_delete",
		},
		.{
			.body = pktline.frame(oid_x ++ " " ++ oid_y ++ " refs/tags/v1") ++ pktline.flush_pkt ++ "PACK",
			.reason = "ref_denied",
			.status = 403,
			.why = "a tag under deny_tags",
		},
		.{
			.body = "0001" ++ pktline.flush_pkt,
			.reason = "push_malformed",
			.status = 400,
			.why = "a protocol-v2 delim pkt in a receive-pack body",
		},
		.{
			.body = pktline.frame("push-cert\x00atomic") ++ pktline.flush_pkt,
			.reason = "push_cert_unsupported",
			.status = 403,
			.why = "a signed push",
		},
	};
	for (cases) |c| {
		var body: std.Io.Reader = .fixed(c.body);
		var refusing = upstream_mod.RefusingTransport{};
		var out: plugin_mod.Response = .{};
		try t.expect(try runMediate(policy, &segs, .POST, &body, &refusing, &out));
		if (out.deny == null or !std.mem.eql(u8, out.deny.?, c.reason) or out.deny_status != c.status) {
			std.debug.print("mediate verdict for {s}: {?s}/{d}, want {s}/{d}\n", .{ c.why, out.deny, out.deny_status, c.reason, c.status });
			return error.WrongVerdict;
		}
		try t.expect(out.exchange == null);
		try t.expectEqual(@as(usize, 0), refusing.calls); // BEFORE any dial
	}

	// The command cap is the same refusal, one status up.
	{
		var line = std.Io.Writer.Allocating.init(t.allocator);
		defer line.deinit();
		var i: usize = 0;
		while (i < pktline.max_commands + 1) : (i += 1) {
			const payload = try std.fmt.allocPrint(t.allocator, "{s} {s} refs/heads/agent/b{d}", .{ oid_x, oid_y, i });
			defer t.allocator.free(payload);
			try line.writer.print("{x:0>4}{s}", .{ payload.len + 4, payload });
		}
		try line.writer.writeAll(pktline.flush_pkt);
		var body: std.Io.Reader = .fixed(line.written());
		var refusing = upstream_mod.RefusingTransport{};
		var out: plugin_mod.Response = .{};
		try t.expect(try runMediate(policy, &segs, .POST, &body, &refusing, &out));
		try t.expectEqualStrings("too_many_refs", out.deny.?);
		try t.expectEqual(@as(u16, 413), out.deny_status);
		try t.expectEqual(@as(usize, 0), refusing.calls);
	}
}
