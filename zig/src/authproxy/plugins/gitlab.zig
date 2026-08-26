// gitlab -- plugin #1, at parity with the compiled-rule tier plus the approved
// v1 archive route (plan decision 3) and the v1.1 namespace-enumeration route.
//
// The 10-route table (addendum E.4), first match wins, unmatched => gate-1 deny:
//
//   git-refs            GET        <project-ref>[.git]/info/refs?service=...   stream
//   git-upload          POST       <project-ref>[.git]/git-upload-pack         stream
//   git-receive         POST       <project-ref>[.git]/git-receive-pack        stream
//   api-user            GET,HEAD   /api/v4/user
//   api-version         GET,HEAD   /api/v4/version
//   api-project         GET,HEAD   /api/v4/projects/:id
//   api-group-projects  GET,HEAD   /api/v4/groups/<group-path>/projects
//   api-issues          GET,HEAD,POST,PUT  /api/v4/projects/:id/issues[/...]
//   api-mr              GET,HEAD,POST,PUT  /api/v4/projects/:id/merge_requests[/...]
//   api-archive         GET,HEAD   /api/v4/projects/:id/repository/archive[.<ext>]  stream
//
// Everything else -- access_tokens, variables, deploy_keys, every OTHER groups
// tail (and the group node itself), /-/**, /uploads, /assets, raw, registries,
// /oauth/**, /admin, info/lfs/**, gitlab-lfs/**, git-upload-archive -- routes
// NOWHERE, and DELETE is in no capability's method set. `service` is a parameter
// of exactly ONE route (git-refs), and /api/** can never be a git route, so the
// service-laundering class closes structurally.

const std = @import("std");
const canon = @import("../canon.zig");
const conf = @import("../conf.zig");
const plugin_mod = @import("../plugin.zig");

pub const plugin: plugin_mod.Plugin = .{
	.name = "gitlab",
	.compile = compile,
};

const vtable: plugin_mod.Policy.VTable = .{
	.classify = classify,
	.authorize = authorize,
	.upstream = upstream,
	.authenticate = authenticate,
	// Genuinely ABSENT, not no-op: gitlab needs no inline mediation and the
	// owner token is refreshed only by cogworx (spec §3.2).
	.mediate = null,
	.onUpstreamStatus = null,
};

const Caps = struct {
	git_read: bool = false,
	git_write: bool = false,
	issues: bool = false,
	mr: bool = false,
};

const Scope = enum { project, namespace, instance };

const CGrant = struct {
	id: []const u8,
	scope: Scope,
	repo: ?[]const u8,
	prefix: ?[]const u8,
	project_id: ?i64,
	projects: []const conf.Project,
	caps: Caps,
};

const Compiled = struct {
	host: []const u8,
	scheme: plugin_mod.Scheme,
	git_user: []const u8,
	grants: []CGrant,
};

/// Compile the entry's grants[] into scope tests + cap sets. Fails closed on
/// an unknown cap, an unknown scope, a malformed prefix or project_id, or a
/// scope missing its required field. It never sees an empty project_id on a
/// concrete grant carrying issues/mr -- the cogworx compiler already filtered
/// those caps (spec §4.3's error-resolve rule); re-deriving that rule here
/// would put grant policy in every plugin.
fn compile(arena: std.mem.Allocator, entry: *const conf.Entry) plugin_mod.CompileError!plugin_mod.Policy {
	const c = try arena.create(Compiled);
	const grants = try arena.alloc(CGrant, entry.grants.len);
	for (entry.grants, 0..) |g, i| {
		var caps: Caps = .{};
		for (g.caps) |cap| {
			// Four caps, no more (contract H#12): api-read/api-full do not
			// exist in the code and anything unrecognized fails closed.
			if (std.mem.eql(u8, cap, "git-read")) {
				caps.git_read = true;
			} else if (std.mem.eql(u8, cap, "git-write")) {
				caps.git_write = true;
			} else if (std.mem.eql(u8, cap, "issues")) {
				caps.issues = true;
			} else if (std.mem.eql(u8, cap, "mr")) {
				caps.mr = true;
			} else {
				return error.InvalidEntry;
			}
		}
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
const rid_api_archive = "api-archive";

/// The closed archive extension set -- never a wildcard suffix.
const archive_exts = [_][]const u8{ "tar.gz", "tar.bz2", "tar", "tar.zst", "zip" };

fn classify(ctx: *const anyopaque, req: *const plugin_mod.Request) ?plugin_mod.Route {
	_ = ctx;
	const segs = req.segments;
	if (segs.len == 0) return null;

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
			if (std.mem.eql(u8, segs[4], "issues")) {
				return apiRoute(rid_api_issues, .{ .project = pid, .rest = segs[5..] }, false);
			}
			if (std.mem.eql(u8, segs[4], "merge_requests")) {
				return apiRoute(rid_api_mr, .{ .project = pid, .rest = segs[5..] }, false);
			}
			if (segs.len == 6 and std.mem.eql(u8, segs[4], "repository")) {
				if (archiveExt(segs[5])) |ext| {
					return apiRoute(rid_api_archive, .{ .project = pid, .archive_ext = ext }, true);
				}
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

	/// Component-wise equality against a `/`-joined path string.
	fn eqlPath(self: *const RefView, path: []const u8) bool {
		var it = self.iter();
		var pit = std.mem.splitScalar(u8, path, '/');
		while (true) {
			const a = it.next();
			const b = pit.next();
			if (a == null and b == null) return true;
			if (a == null or b == null) return false;
			if (!std.mem.eql(u8, a.?, b.?)) return false;
		}
	}

	/// STRICTLY under the slash-terminated namespace prefix ("/grp/sub/"): all
	/// prefix components match AND at least one more component follows, so
	/// `grp-secret` stays excluded and the namespace path itself is not a
	/// member of its own subtree.
	fn underPrefix(self: *const RefView, prefix: []const u8) bool {
		const trimmed = std.mem.trim(u8, prefix, "/");
		if (trimmed.len == 0) return false;
		var it = self.iter();
		var pit = std.mem.splitScalar(u8, trimmed, '/');
		while (pit.next()) |want| {
			const got = it.next() orelse return false;
			if (!std.mem.eql(u8, got, want)) return false;
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
	fn groupUnderOrEqualPrefix(self: *const RefView, prefix: []const u8) bool {
		const trimmed = std.mem.trim(u8, prefix, "/");
		if (trimmed.len == 0) return false;
		var it = self.iter();
		var pit = std.mem.splitScalar(u8, trimmed, '/');
		while (pit.next()) |want| {
			const got = it.next() orelse return false;
			if (!std.mem.eql(u8, got, want)) return false;
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

fn methodAllowed(route_id: []const u8, method: std.http.Method) bool {
	if (std.mem.eql(u8, route_id, rid_git_refs)) return method == .GET;
	if (std.mem.eql(u8, route_id, rid_git_upload) or std.mem.eql(u8, route_id, rid_git_receive)) {
		return method == .POST;
	}
	if (std.mem.eql(u8, route_id, rid_api_issues) or std.mem.eql(u8, route_id, rid_api_mr)) {
		// DELETE is in no capability's method set, matching today's clamp.
		return method == .GET or method == .HEAD or method == .POST or method == .PUT;
	}
	// the ambient three + api-archive
	return method == .GET or method == .HEAD;
}

fn authorize(ctx: *const anyopaque, route: *const plugin_mod.Route, req: *const plugin_mod.Request) plugin_mod.Decision {
	const c = compiled(ctx);
	if (!methodAllowed(route.id, req.method)) return .{ .deny = .method_not_allowed };
	if (std.mem.eql(u8, route.id, rid_git_refs) and route.params.service == null) {
		return .{ .deny = .service_invalid };
	}
	if (c.grants.len == 0) return .{ .deny = .no_grant };

	// The ambient TWO -- /user and /version, which name no project -- are
	// allowed when the instance holds ANY grant carrying issues, mr or git-read
	// (any read grant reaches them), with no scope test. api-project and
	// api-group-projects are NOT ambient: they name a project / a namespace, and
	// take the scope test like every other :id route. Making api-project ambient
	// would let any grant read the metadata of ANY project the owner's token can
	// see -- an enumeration oracle -- and making the group route ambient would
	// hand out instance-wide enumeration.
	const ambient = std.mem.eql(u8, route.id, rid_api_user) or
		std.mem.eql(u8, route.id, rid_api_version);

	var saw_cap = false;
	for (c.grants) |*g| {
		if (!grantHasCap(g, route)) continue;
		saw_cap = true;
		if (ambient or scopeOk(g, route)) return .{ .allow = g.id };
	}
	return .{ .deny = if (saw_cap) .scope_mismatch else .cap_missing };
}

/// The cap -> route map (addendum E.4). api-archive rides git-read: it is the
/// tarball form of a clone, and the v1 addition that closes the
/// container-vs-VM fetch asymmetry.
fn grantHasCap(g: *const CGrant, route: *const plugin_mod.Route) bool {
	if (std.mem.eql(u8, route.id, rid_git_refs)) {
		return switch (route.params.service orelse return false) {
			.upload_pack => g.caps.git_read,
			.receive_pack => g.caps.git_write,
		};
	}
	if (std.mem.eql(u8, route.id, rid_git_upload)) return g.caps.git_read;
	if (std.mem.eql(u8, route.id, rid_git_receive)) return g.caps.git_write;
	if (std.mem.eql(u8, route.id, rid_api_archive)) return g.caps.git_read;
	if (std.mem.eql(u8, route.id, rid_api_group_projects)) return g.caps.git_read;
	if (std.mem.eql(u8, route.id, rid_api_issues)) return g.caps.issues;
	if (std.mem.eql(u8, route.id, rid_api_mr)) return g.caps.mr;
	// The ambient two (api-user/api-version) + api-project. `git-read` now
	// unlocks discovery/inspection (the "read = discover + inspect" decision),
	// so it joins issues/mr here; api-project additionally takes the scope test.
	return g.caps.issues or g.caps.mr or g.caps.git_read;
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
		if (std.mem.eql(u8, route.id, rid_api_issues)) {
			try out.appendPath("/issues");
		} else if (std.mem.eql(u8, route.id, rid_api_mr)) {
			try out.appendPath("/merge_requests");
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
	// issues/mr/archive/user/version keep the blanket pass-through (v1's one
	// named non-allowlisted spot); the forbidden keys were already refused by
	// the core.
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

test "gitlab: DELETE is denied on every route; the ambient three need issues|mr" {
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
