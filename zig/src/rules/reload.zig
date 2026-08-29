// Regenerate the runtime rules file (read by the LD_PRELOAD filter) and
// signal a running passt to re-read it. Emits both the CIDR allow/deny
// section AND the remap section from the loaded .network object, so the
// `rules` and `remap` verbs can each rewrite the file independently
// without dropping the other layer.

const std = @import("std");
const rule = @import("rule.zig");
const config = @import("config.zig");
const filter = @import("filter");
const secret_mod = @import("secret_module");
const secret_store = secret_mod.store;
pub const credgrant = @import("credgrant.zig");

/// The plugin tag every compiled git-grant L7 rule carries (cogworx stamps it
/// via `l7 add/clear --plugin git-grants`; see cogworx gitgrants.go). It is a
/// CROSS-REPO CONTRACT string. renderL7 emits it as the wire token `tag=` and
/// renderL7Inject emits it as the inject-spec field `rules_tag`, so the mitmproxy
/// addon injects the owner's token ONLY on a request a git-grant-tagged rule
/// allows -- a coexisting whole-host allow grants reachability, not the credential.
pub const git_grants_tag = "git-grants";

/// True when L7 vhost filtering is active for this instance: `.network.l7` is
/// an object with a non-empty `rules` array OR a non-empty
/// `inject.specs` array. An inject spec implies a terminate-allow for its host
/// (see renderL7), so an inject-only plugin still funnels web egress. An empty
/// L7 config must NOT activate the funnel (it would blackhole all web egress).
pub fn l7Active(network: std.json.Value) bool {
	if (network != .object) return false;
	const l7 = network.object.getPtr("l7") orelse return false;
	if (l7.* != .object) return false;
	if (l7.object.getPtr("rules")) |rules| {
		if (rules.* == .array and rules.array.items.len > 0) return true;
	}
	if (injectSpecs(network)) |specs| {
		if (specs.items.len > 0) return true;
	}
	return false;
}

/// `.network.l7.inject.specs` array (by value; shares the items pointer), or
/// null when absent / not an array / inject is the legacy bool form / the
/// master `enabled` toggle is explicitly false. Gating here means all three
/// consumers (l7Active, renderL7's terminate-allow union, renderL7Inject)
/// honor `enabled:false` consistently -- no funnel, no terminate, no inject.
fn injectSpecs(network: std.json.Value) ?std.json.Array {
	if (network != .object) return null;
	const l7 = network.object.getPtr("l7") orelse return null;
	if (l7.* != .object) return null;
	const inj = l7.object.getPtr("inject") orelse return null;
	if (inj.* != .object) return null; // legacy bool form carries no plugin specs
	if (inj.object.getPtr("enabled")) |en| {
		if (en.* == .bool and !en.bool) return null;
	}
	const specs = inj.object.getPtr("specs") orelse return null;
	if (specs.* != .array) return null;
	return specs.array;
}

fn strField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
	const v = obj.get(key) orelse return null;
	if (v != .string) return null;
	return v.string;
}

/// An inject spec's optional non-standard service port (the port the guest
/// actually connects to). Accepts a JSON integer (a Nix manifest yields one)
/// or a numeric string (a hand-rolled conf may use one). Out-of-range / zero /
/// unparseable -> null: the spec simply isn't funnelled on a custom port and
/// falls back to the standard-port (80/443) assumption -- fail closed, never a
/// bogus remap. The funnel reads the port from HERE (renderRules is secret-free
/// and runs in the netfilter-rules path) rather than from the secret's audience.
fn injectPort(obj: std.json.ObjectMap) ?u16 {
	const v = obj.get("port") orelse return null;
	switch (v) {
		.integer => |n| {
			if (n < 1 or n > 65535) return null;
			return @intCast(n);
		},
		.string => |s| {
			const n = std.fmt.parseInt(u16, s, 10) catch return null;
			return if (n == 0) null else n;
		},
		else => return null,
	}
}

/// `.network.l7.rules` array (by value; shares the items pointer), or null when
/// absent / not an array. Shared by the seedGitInjectSpecs fail-closed gate.
fn l7Rules(network: std.json.Value) ?std.json.Array {
	if (network != .object) return null;
	const l7 = network.object.getPtr("l7") orelse return null;
	if (l7.* != .object) return null;
	const r = l7.object.getPtr("rules") orelse return null;
	if (r.* != .array) return null;
	return r.array;
}

fn hostNamedInRules(rules: ?std.json.Array, host: []const u8) bool {
	const r = rules orelse return false;
	for (r.items) |item| {
		if (item != .object) continue;
		if (strField(item.object, "allow")) |h| {
			if (std.mem.eql(u8, h, host)) return true;
		}
		if (strField(item.object, "deny")) |h| {
			if (std.mem.eql(u8, h, host)) return true;
		}
	}
	return false;
}

/// The inject-spec hosts renderL7 UNIONS into the terminate-allow set: every
/// `.l7.inject.specs[].host` that no `.l7.rules[]` entry already names.
///
/// This exists so the count and the render share ONE predicate. renderL7 emits
/// exactly one `allow <host> terminate` LINE per host this yields, which is why
/// the rendered document is LONGER than `.l7.rules[]`, and it is rendered lines
/// -- not array entries -- that filter.parseL7Rules caps (it compiles the first
/// filter.max_l7_rules and silently drops the rest, while the terminate-tier
/// addon reading the same document has no cap). Anything budgeting against that
/// cap must count these lines too; iterating them here rather than re-deriving
/// the predicate is what keeps the two from drifting.
pub const InjectUnionIter = struct {
	specs: ?std.json.Array,
	rules: ?std.json.Array,
	i: usize = 0,

	pub fn next(self: *InjectUnionIter) ?[]const u8 {
		const specs = self.specs orelse return null;
		while (self.i < specs.items.len) {
			const spec = specs.items[self.i];
			self.i += 1;
			if (spec != .object) continue;
			const h = strField(spec.object, "host") orelse continue;
			if (hostNamedInRules(self.rules, h)) continue;
			return h;
		}
		return null;
	}
};

pub fn injectUnionIter(network: std.json.Value) InjectUnionIter {
	return .{ .specs = injectSpecs(network), .rules = l7Rules(network) };
}

/// How many rendered `l7-rules` lines renderL7 appends BEYOND `.l7.rules[]` --
/// i.e. the delta between the config array's length and the rule-line count the
/// enforcer's cap applies to. See InjectUnionIter.
pub fn injectUnionCount(network: std.json.Value) usize {
	var it = injectUnionIter(network);
	var n: usize = 0;
	while (it.next()) |_| n += 1;
	return n;
}

/// Render `.network` to wire-format rule lines for the LD_PRELOAD shim. Pure
/// -- no I/O. Ordering on disk: host-topology directives (`no-implicit-dns`,
/// `hard-deny`), L7 fail-closed denies, user CIDR rules, user remaps, then the
/// auto-injected L7 funnel remaps.
///
/// The host-topology directives are written by whoever provisions the instance
/// (`cogbox init --no-implicit-dns --self-addr --dns-host`), not by a user rule
/// verb, and all default to absent: an instance whose `.network` carries none of
/// those keys renders exactly what it rendered before they existed.
///
/// When L7 is active we funnel all guest 80/443 to the host-side proxy and
/// force everything else on those ports to fail closed:
///   - all guest IPv6 TCP/UDP is denied (the funnel is IPv4-only in v1, so
///     v6 web egress would otherwise bypass the proxy entirely; DNS on port
///     53 stays implicitly allowed by the shim);
///   - guest UDP/443 + UDP/80 (QUIC / HTTP-3) is denied, forcing a downgrade
///     to inspectable TCP;
///   - guest TCP/443 + TCP/80 is remapped to the proxy (remap-implies-allow).
pub fn renderRules(allocator: std.mem.Allocator, network: std.json.Value, l7_base: u16, out: *std.ArrayList(u8)) !void {
	if (network != .object) return;
	const l7 = l7Active(network);

	// Host-topology directives, emitted FIRST -- ahead of the L7 fail-closed
	// prologue, because `no-implicit-dns` is what subjects port 53 to it.
	// Both keys are absent from every config this feature did not write, so a
	// local or k8s instance renders byte-for-byte what it rendered before.
	if (network.object.getPtr("implicitDns")) |v| {
		if (v.* == .bool and !v.bool) try out.appendSlice(allocator, "no-implicit-dns\n");
	}
	// The enclosing host's own DNS forwarder, emitted next because it and the
	// directive above are ONE mechanism: `no-implicit-dns` puts loopback DNS
	// back under the shim's loopback deny, and passt's `--dns-forward` then
	// re-emits every guest query as a loopback connect that the deny would eat.
	// Absent by default, like every key in this block.
	if (network.object.getPtr("dnsHost")) |v| {
		if (v.* == .string and v.string.len > 0) {
			try out.appendSlice(allocator, "dns-host ");
			try out.appendSlice(allocator, v.string);
			try out.append(allocator, '\n');
		}
	}
	// One `hard-deny` per `.network.selfAddrs` entry: the enclosing host's own
	// addresses, which the proxy's built-in floor cannot know. Placement is
	// immaterial (the hard table is a set, not a first-match walk); they sit
	// here for readability next to the directive above.
	if (network.object.getPtr("selfAddrs")) |v| {
		if (v.* == .array) {
			for (v.array.items) |a| {
				if (a != .string or a.string.len == 0) continue;
				try out.appendSlice(allocator, "hard-deny ");
				try out.appendSlice(allocator, a.string);
				try out.append(allocator, '\n');
			}
		}
	}

	if (l7) {
		// IPv6 fail-closed (all v6 TCP/UDP; DNS:53 still implicitly allowed)
		// + IPv4 QUIC fail-closed on the funneled ports. These go FIRST so
		// they win first-match over any broad user allow.
		try out.appendSlice(allocator,
			\\deny tcp ::/0
			\\deny udp ::/0
			\\deny udp 0.0.0.0/0:443
			\\deny udp 0.0.0.0/0:80
			\\
		);
	}

	if (network.object.getPtr("rules")) |rules_val| {
		if (rules_val.* == .array) {
			for (rules_val.array.items) |r| {
				if (r != .object) continue;
				const p = rule.ruleAction(r.object) orelse continue;
				const action_str = switch (p.action) {
					.allow => "allow",
					.deny => "deny",
				};
				try out.appendSlice(allocator, action_str);
				try out.append(allocator, ' ');
				try out.appendSlice(allocator, p.cidr);
				try out.append(allocator, '\n');
			}
		}
	}

	if (network.object.getPtr("remap")) |remap_val| {
		if (remap_val.* == .array) {
			for (remap_val.array.items) |r| {
				if (r != .object) continue;
				const from_v = r.object.getPtr("from") orelse continue;
				const to_v = r.object.getPtr("to") orelse continue;
				if (from_v.* != .string or to_v.* != .string) continue;
				try out.appendSlice(allocator, "remap ");
				try out.appendSlice(allocator, from_v.string);
				try out.appendSlice(allocator, " -> ");
				try out.appendSlice(allocator, to_v.string);
				try out.append(allocator, '\n');
			}
		}
	}

	if (l7) {
		// Funnel remaps LAST so a power user's explicit per-host remap above
		// wins by first-match and can deliberately route around the proxy.
		// Targets are this instance's per-instance loopback ports so multiple
		// L7 instances coexist without funnelling into each other's proxy.
		const ports = filter.l7PortsForBase(l7_base);
		var buf: [96]u8 = undefined;
		const tls_line = try std.fmt.bufPrint(&buf, "remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:{d}\n", .{ports.tls});
		try out.appendSlice(allocator, tls_line);
		const http_line = try std.fmt.bufPrint(&buf, "remap tcp 0.0.0.0/0:80 -> tcp 127.0.0.1:{d}\n", .{ports.http});
		try out.appendSlice(allocator, http_line);

		// Plus a funnel remap for every DISTINCT non-standard port an inject host
		// is served on. A host reached on e.g. :9200 (Elasticsearch) is otherwise
		// invisible to the proxy -- the guest's connect clears only the L4 CIDR
		// layer and egresses untouched, so its credential is never stamped (a 401
		// at the upstream). 80/443 are already funnelled above. We route the extra
		// port to the SAME http entry: peekClassify sniffs TLS vs plain HTTP by the
		// first byte, so one entry serves both, and the proxy preserves the real
		// dest port (carried over SOCKS5) when it dials upstream. NB this funnels
		// ALL guest TCP on that port through the proxy (as :80/:443 already are), so
		// the port must speak HTTP/TLS; a non-inject host on it is L7-evaluated and
		// spliced, never injected (the needs_inject gate stays host-scoped).
		if (injectSpecs(network)) |specs| {
			var seen: [32]u16 = undefined;
			var nseen: usize = 0;
			for (specs.items) |spec| {
				if (spec != .object) continue;
				const p = injectPort(spec.object) orelse continue;
				if (p == 80 or p == 443) continue; // already funnelled
				var dup = false;
				for (seen[0..nseen]) |q| {
					if (q == p) {
						dup = true;
						break;
					}
				}
				if (dup) continue;
				if (nseen < seen.len) {
					seen[nseen] = p;
					nseen += 1;
				}
				const inj_line = try std.fmt.bufPrint(&buf, "remap tcp 0.0.0.0/0:{d} -> tcp 127.0.0.1:{d}\n", .{ p, ports.http });
				try out.appendSlice(allocator, inj_line);
			}
		}
	}
}

/// Render `.network.l7` to the proxy's `l7-rules` wire format. Pure -- no I/O.
///   mode passthrough|terminate
///   allow|deny  <host>  [<path>]  [terminate|passthrough]  [insecure]
pub fn renderL7(allocator: std.mem.Allocator, network: std.json.Value, out: *std.ArrayList(u8)) !void {
	if (network != .object) return;
	const l7 = network.object.getPtr("l7") orelse return;
	if (l7.* != .object) return;

	// Terminate is the default tier; only an explicit `mode: passthrough`
	// opts the whole instance out.
	var mode_terminate = true;
	if (l7.object.getPtr("mode")) |m| {
		if (m.* == .string and std.mem.eql(u8, m.string, "passthrough")) mode_terminate = false;
	}
	try out.appendSlice(allocator, if (mode_terminate) "mode terminate\n" else "mode passthrough\n");

	const rules: ?std.json.Array = blk: {
		const r = l7.object.getPtr("rules") orelse break :blk null;
		if (r.* != .array) break :blk null;
		break :blk r.array;
	};
	if (rules) |rs| {
		for (rs.items) |r| {
			if (r != .object) continue;
			var action: []const u8 = undefined;
			var host: []const u8 = undefined;
			if (r.object.getPtr("allow")) |v| {
				if (v.* != .string) continue;
				action = "allow";
				host = v.string;
			} else if (r.object.getPtr("deny")) |v| {
				if (v.* != .string) continue;
				action = "deny";
				host = v.string;
			} else continue;

			try out.appendSlice(allocator, action);
			try out.append(allocator, ' ');
			try out.appendSlice(allocator, host);
			// Order (mirrors the zig parser's order-independent tokenizer, but we
			// emit deterministically): methods, /path, exact, service=<svc>.
			if (r.object.getPtr("methods")) |mv| {
				if (mv.* == .string and mv.string.len > 0) {
					try out.append(allocator, ' ');
					try out.appendSlice(allocator, mv.string);
				}
			}
			if (r.object.getPtr("path")) |p| {
				if (p.* == .string and p.string.len > 0) {
					try out.append(allocator, ' ');
					try out.appendSlice(allocator, p.string);
				}
			}
			if (r.object.getPtr("pathmode")) |pm| {
				if (pm.* == .string and std.mem.eql(u8, pm.string, "exact")) {
					try out.appendSlice(allocator, " exact");
				}
			}
			if (r.object.getPtr("service")) |sv| {
				if (sv.* == .string and sv.string.len > 0) {
					try out.appendSlice(allocator, " service=");
					try out.appendSlice(allocator, sv.string);
				}
			}
			if (r.object.getPtr("terminate")) |tv| {
				if (tv.* == .bool and tv.bool) try out.appendSlice(allocator, " terminate");
			}
			if (r.object.getPtr("passthrough")) |pv| {
				if (pv.* == .bool and pv.bool) try out.appendSlice(allocator, " passthrough");
			}
			if (r.object.getPtr("insecure_upstream")) |iv| {
				if (iv.* == .bool and iv.bool) try out.appendSlice(allocator, " insecure");
			}
			// Injection-gating tag: a rule compiled from a git-grant carries
			// plugin=="git-grants" -> emit the wire token `tag=git-grants`. Any
			// other plugin value (or absent) renders untagged. The addon injects
			// the owner's token only on a tagged rule's allow, so a coexisting
			// whole-host allow yields reachability, not the credential.
			if (r.object.getPtr("plugin")) |pv| {
				if (pv.* == .string and std.mem.eql(u8, pv.string, git_grants_tag)) {
					try out.appendSlice(allocator, " tag=");
					try out.appendSlice(allocator, git_grants_tag);
				}
			}
			try out.append(allocator, '\n');
		}
	}

	// Union inject-spec hosts into the terminate-allow set: a host that gets a
	// credential injected MUST be MITM-terminated (a header/cookie can't be
	// added on a spliced TLS flow), and it need not be separately allow-listed.
	// Emit `allow <host> terminate` for each inject host not already named by an
	// l7 rule. Whether injection actually fires for that host is decided
	// separately by renderL7Inject (only when the secret is bound + audience
	// matches); an unbound host still terminates and simply isn't injected.
	//
	// The selection is InjectUnionIter's, not a loop of its own: these lines are
	// why the rendered document is longer than `.l7.rules[]`, and injectUnionCount
	// -- what the `l7 replace` cap budgets with -- counts exactly what this emits.
	var inject_it = injectUnionIter(network);
	while (inject_it.next()) |h| {
		try out.appendSlice(allocator, "allow ");
		try out.appendSlice(allocator, h);
		try out.appendSlice(allocator, " terminate\n");
	}
}

/// Render the host-side credential-injection conf (the
/// `COGBOX_L7_INJECT_CONF` the mitmproxy addon reads as a JSON list). For each
/// `.network.l7.inject.specs[]` entry, resolve its NAMED secret host-side
/// (instance store first, then global) and emit a conf element ONLY when the
/// secret is bound AND its audience matches the spec host. Unbound or
/// audience-mismatched specs render nothing -- fail closed: the addon then has
/// no spec for that host and never stamps a stale/foreign credential. The
/// cred_file is the store's value path; cred_format "raw" (the addon's
/// token_for reads its first non-empty line). NOT pure -- reads the store.
///
/// A bound secret whose meta.kind == anthropic-oauth (the per-user Claude
/// `setup-token` bind) FORCES style
/// "anthropic-oauth" + the shared host stub_token sentinel, overriding whatever
/// the spec declared: the addon's anthropic-oauth branch then stamps the real
/// Bearer ONLY over that placeholder. No `refresh` block is ever emitted here --
/// a setup-token is long-lived and bound once. Every other kind keeps its
/// existing spec-driven style + optional spec `stub` rendering unchanged.
///
/// `grants`, when non-null, collects the cred file of every EMITTED spec so the
/// caller can make exactly those readable by the L7 proxy uid (credgrant.zig).
/// It is noted at the same statement that writes `cred_file`, so what the proxy
/// may read and what the conf names it can never diverge. Pass null to render
/// without touching any store permissions.
pub fn renderL7Inject(
	allocator: std.mem.Allocator,
	io: std.Io,
	network: std.json.Value,
	global_secrets_dir: []const u8,
	instance_secrets_dir: []const u8,
	out: *std.ArrayList(u8),
	hosts_out: *std.ArrayList(u8),
	grants: ?*credgrant.Grants,
) !void {
	var arena_inst = std.heap.ArenaAllocator.init(allocator);
	defer arena_inst.deinit();
	const arena = arena_inst.allocator();

	var arr = std.json.Array.init(arena);
	if (injectSpecs(network)) |specs| {
		for (specs.items) |spec| {
			if (spec != .object) continue;
			const host = strField(spec.object, "host") orelse continue;
			const secret_name = strField(spec.object, "secret") orelse continue;
			var style = strField(spec.object, "style") orelse "bearer";

			const resolved = (try resolveSecret(arena, io, instance_secrets_dir, global_secrets_dir, secret_name)) orelse continue;
			if (!resolved.bound) continue;
			const audience = resolved.meta.audience orelse continue; // unset -> not injectable
			if (!std.mem.eql(u8, audience, host)) continue; // exfiltration gate

			// A kind=anthropic-oauth secret (the per-user Claude setup-token bind)
			// forces the anthropic-oauth inject style + the shared host stub
			// sentinel, overriding the spec's style/stub. The audience pin above
			// already proved this secret is bound for THIS host.
			const oauth_kind = std.mem.eql(u8, resolved.meta.kind, secret_mod.anthropic_oauth_kind);
			if (oauth_kind) style = secret_mod.anthropic_oauth_kind;

			// A kind=gitlab-oauth secret (the per-user GitLab access-token bind)
			// forces the gitlab-oauth inject style: the addon then picks basic auth
			// (`git_user:<token>`) on git smart-HTTP paths and Bearer elsewhere.
			const git_kind = std.mem.eql(u8, resolved.meta.kind, secret_mod.gitlab_oauth_kind);
			if (git_kind) style = secret_mod.gitlab_oauth_kind;

			var el: std.json.ObjectMap = .empty;
			try el.put(arena, "host", .{ .string = host });
			try el.put(arena, "style", .{ .string = style });
			try el.put(arena, "cred_file", .{ .string = resolved.value_path });
			// The proxy that will open that file may not be the uid that owns it
			// (COGBOX_PROXY_RUNAS). Note it HERE, not from a later pass over the
			// rendered conf: the only paths that can ever be granted are then the
			// store paths this resolver produced, never a cred_file a config,
			// plugin manifest or operator override supplied.
			if (grants) |g| try g.note(resolved.value_path);
			try el.put(arena, "cred_format", .{ .string = "raw" });
			if (strField(spec.object, "cookieName")) |cn| {
				try el.put(arena, "cookie_name", .{ .string = cn });
			}
			if (oauth_kind) {
				// A setup-token is long-lived/static -> NO refresh block, just the
				// stub the host redacted into the guest's cred file.
				try el.put(arena, "stub_token", .{ .string = secret_mod.claude_stub_token });
			} else if (git_kind) {
				// The git username the addon pairs with the token for basic auth
				// (default `oauth2`; a per-provider override may set spec.git_user).
				// The git stub sentinel is wired for future glab staging; a
				// credential-less `git` presents no auth, which should_inject also
				// treats as inject-eligible. NO refresh block: cogworx is the single
				// refresher and re-binds fresh tokens (GitLab refresh tokens are
				// single-use), so an enforcer-side refresh would fork the lineage.
				try el.put(arena, "git_user", .{ .string = strField(spec.object, "git_user") orelse secret_mod.default_git_user });
				try el.put(arena, "stub_token", .{ .string = secret_mod.gitlab_stub_token });
				// Gate injection on the git-grant tag: the addon injects this
				// bound owner token ONLY on a request a `tag=git-grants` rule
				// allows. A coexisting whole-host allow (network tab / admin /
				// template / curated) then grants anonymous reachability, not the
				// credential. Only the gitlab-oauth (git_kind) spec carries this;
				// anthropic-oauth's whole-host allow-on-bound stays ungated.
				try el.put(arena, "rules_tag", .{ .string = git_grants_tag });
			} else if (strField(spec.object, "stub")) |st| {
				try el.put(arena, "stub_token", .{ .string = st });
			}
			try arr.append(.{ .object = el });

			// Mirror the host into the proxy's inject-host list (one per line):
			// it routes this host's PLAIN-HTTP egress through the terminate
			// backend too, so an `http://` vhost's credential is still stamped.
			// Only EMITTED (bound + audience-matched) hosts go here, so an
			// unbound/mismatched spec neither injects nor reroutes HTTP.
			try hosts_out.appendSlice(allocator, host);
			try hosts_out.append(allocator, '\n');
		}
	}
	try config.writeJqTab(allocator, out, .{ .array = arr });
}

/// Whether a VALUE FILE EXISTS for the reserved per-user `claude-oauth` secret in
/// this instance's store (instance store shadowing global -- the same precedence
/// renderL7Inject uses). This is the SOLE gate on the claude seed
/// (seedClaudeInjectSpec) so renderL7 / renderRules terminate-allow + funnel
/// api.anthropic.com ONLY for a sandbox that HAS that file -- which cogworx writes
/// on connect and removes on disconnect, hence "connected owner" in the prose below.
///
/// PRESENCE, not validity -- store.lookup derives `bound` from a bare access() on
/// the value path, so a zero-byte value with no `.meta` also answers true and the
/// terminate-allow is seeded for it. That is deliberate (it matches the
/// pre-existing container semantics), and the injection itself still fails closed
/// a layer down: renderL7Inject skips a spec whose secret has no audience, so such
/// a secret yields a terminated host with an EMPTY inject conf -- the host is
/// funnelled, nothing is ever stamped.
///
/// 5a review gap #1: seeding on every enforce-ON container render made renderL7
/// terminate-allow api.anthropic.com on EVERY container sandbox (superseding the L4
/// deny-list) even for never-connected / non-claude owners. Binding claude-oauth
/// already triggers a re-render (secret-add hot-reload + the enforcer reconcile), so
/// gating the seed on `bound` has no race -- a connect re-renders with the secret
/// present, a disconnect re-renders with it gone. Reads the store, so NOT pure.
///
/// It used to be paired with a second gate -- "both COGBOX_*_SECRETS_DIR overrides
/// are set" -- as a proxy for "am I the container enforcer". That proxy silently
/// excluded the VM-family backends (gcp / k8s microVM): cogworx binds claude-oauth
/// host-side there and stages the guest stub, but nothing seeded a spec naming the
/// secret, so the bind was INERT and every VM sandbox reported "Not logged in".
/// The bound-check alone is what carries the never-connected property, so the
/// proxy gate is gone and every render path seeds.
pub fn claudeOAuthBound(
	arena: std.mem.Allocator,
	io: std.Io,
	instance_secrets_dir: []const u8,
	global_secrets_dir: []const u8,
) !bool {
	const resolved = (try resolveSecret(arena, io, instance_secrets_dir, global_secrets_dir, secret_mod.claude_oauth_secret)) orelse return false;
	return resolved.bound;
}

/// Seed the harness-owned Claude inject spec into `network.l7.inject.specs[]` so a
/// bound per-user `claude-oauth` setup-token actually renders. The step-3 reconcile BINDS the `claude-oauth` secret (kind=anthropic-oauth,
/// audience=api.anthropic.com), but renderL7Inject only iterates specs the config
/// declares -- with nothing naming that secret the bind is INERT. This is the
/// load-bearing link the step-4 review flagged.
///
/// Called on EVERY render path (VM boot render, `secret reload`, the container
/// enforcer render, and the rule/plugin-mutation reload), gated only on
/// claudeOAuthBound. The spec is
/// HARMLESS when the secret is unbound: renderL7Inject emits an element ONLY when the
/// named secret is bound AND its audience == host, so a sandbox whose owner never
/// connected Claude (or a non-claude harness) renders nothing for it. It is also
/// additive -- a plugin/seed spec already targeting the host is left untouched
/// (idempotent), so re-renders and plugin-contributed specs are undisturbed.
///
/// Creates `.l7` / `.l7.inject` / `.l7.inject.specs` on demand and folds a legacy
/// bool `inject` (which carries no specs) into the object form. Mutates `network`
/// in place; new values are allocated in `arena` (the config tree's arena).
pub fn seedClaudeInjectSpec(arena: std.mem.Allocator, network: *std.json.Value) !void {
	if (network.* != .object) return; // "full"/"none" mode carries no L7 object

	// .network.l7 (object), created on demand.
	const l7 = blk: {
		if (network.object.getPtr("l7")) |v| {
			if (v.* == .object) break :blk v;
		}
		try network.object.put(arena, "l7", .{ .object = .empty });
		break :blk network.object.getPtr("l7").?;
	};

	// .network.l7.inject (object). A legacy bool `inject: true`/`false` carries no
	// specs, so replace it with the object form the seed can land in.
	const inj = blk: {
		if (l7.object.getPtr("inject")) |v| {
			if (v.* == .object) break :blk v;
		}
		try l7.object.put(arena, "inject", .{ .object = .empty });
		break :blk l7.object.getPtr("inject").?;
	};

	// .network.l7.inject.specs (array), created on demand.
	const specs = blk: {
		if (inj.object.getPtr("specs")) |v| {
			if (v.* == .array) break :blk &v.array;
		}
		try inj.object.put(arena, "specs", .{ .array = std.json.Array.init(arena) });
		break :blk &inj.object.getPtr("specs").?.array;
	};

	// Idempotent BUT shadow-safe (5a review gap #2): skip ONLY when a spec already
	// names OUR reserved claude-oauth secret for this host (a prior seed / re-render
	// -- never add a duplicate). A pre-existing spec that targets api.anthropic.com
	// under a DIFFERENT secret name (e.g. a plugin's) must NOT suppress the per-user
	// bind: appending ours anyway guarantees the connected owner's claude-oauth still
	// renders, instead of being silently shadowed by the plugin spec.
	for (specs.items) |s| {
		if (s != .object) continue;
		const h = strField(s.object, "host") orelse continue;
		if (!std.ascii.eqlIgnoreCase(h, secret_mod.anthropic_api_host)) continue;
		const sn = strField(s.object, "secret") orelse continue;
		if (std.mem.eql(u8, sn, secret_mod.claude_oauth_secret)) return; // our seed already present
	}

	// {host, style, secret}: the secret's kind=anthropic-oauth drives the actual
	// style/stub override in renderL7Inject, but declare style explicitly so the
	// config reads truthfully. No value/path/stub here -- a spec only NAMES a
	// credential (the same constraint plugin inject specs carry).
	var spec: std.json.ObjectMap = .empty;
	try spec.put(arena, "host", .{ .string = secret_mod.anthropic_api_host });
	try spec.put(arena, "style", .{ .string = secret_mod.anthropic_oauth_kind });
	try spec.put(arena, "secret", .{ .string = secret_mod.claude_oauth_secret });
	try specs.append(.{ .object = spec });
}

/// Ensure `.network.l7.inject.specs` exists as an array and return a pointer to
/// it, creating `.l7` / `.l7.inject` / `.l7.inject.specs` on demand and folding a
/// legacy bool `inject` into the object form. Returns null when `network` is not
/// an object ("full"/"none" mode). Shared by the claude + git seeds.
fn ensureInjectSpecs(arena: std.mem.Allocator, network: *std.json.Value) !?*std.json.Array {
	if (network.* != .object) return null;
	const l7 = blk: {
		if (network.object.getPtr("l7")) |v| {
			if (v.* == .object) break :blk v;
		}
		try network.object.put(arena, "l7", .{ .object = .empty });
		break :blk network.object.getPtr("l7").?;
	};
	const inj = blk: {
		if (l7.object.getPtr("inject")) |v| {
			if (v.* == .object) break :blk v;
		}
		try l7.object.put(arena, "inject", .{ .object = .empty });
		break :blk l7.object.getPtr("inject").?;
	};
	if (inj.object.getPtr("specs")) |v| {
		if (v.* == .array) return &v.array;
	}
	try inj.object.put(arena, "specs", .{ .array = std.json.Array.init(arena) });
	return &inj.object.getPtr("specs").?.array;
}

/// Seed an inject spec into `network.l7.inject.specs[]` for every BOUND secret
/// of kind=gitlab-oauth in the GLOBAL + instance stores, so a per-user git
/// access-token bind actually renders (renderL7Inject only iterates specs the
/// config names -- the bind alone is inert). cogworx's `secret bind` writes the
/// enforcer's GLOBAL store (COGBOX_GLOBAL_SECRETS_DIR) -- on the enforcer the
/// instance dir typically doesn't even exist -- so both stores are enumerated,
/// with an instance secret shadowing a global one of the same name (the same
/// precedence resolveSecret / renderL7Inject use). Unlike the single reserved
/// claude-oauth secret, the enforcer can't know the provider secret names a
/// priori (they are `git-<provider>`), so it enumerates the stores. HARMLESS
/// when nothing is bound.
///
/// Called on every render path (same as the claude seed -- the VM-family backends
/// apply git-grant rules too, so gating this on "am I the enforcer" left the bind
/// equally inert there). Its own gates are what keep it safe: kind, a bound value,
/// an audience, and an l7 rule naming that host.
/// Each spec NAMES the secret + declares style/host; renderL7Inject's audience
/// pin + kind override drive the actual injection. Idempotent AND shadow-safe:
/// skips only when a spec already names THAT secret for THAT host (a prior seed),
/// so a foreign spec targeting the same host never suppresses the per-user bind.
/// FAIL CLOSED: a bound gitlab-oauth secret whose host NO l7 rule names is NOT
/// seeded at all (see the gate below) — unlike claude-oauth, whose whole-host
/// allow-on-bound is intended. Mutates `network` in place; new values allocated
/// in `arena`. Reads the store, so NOT pure.
pub fn seedGitInjectSpecs(
	arena: std.mem.Allocator,
	io: std.Io,
	network: *std.json.Value,
	instance_secrets_dir: []const u8,
	global_secrets_dir: []const u8,
) !void {
	// Union of both stores' bound names. A name present in both resolves to the
	// instance value below (resolveSecret shadows), and the second occurrence is
	// dropped by the shadow-safe idempotency check (same secret name + host), so
	// no explicit dedupe is needed.
	const instance_names = try secret_store.listBound(arena, io, instance_secrets_dir);
	const global_names = try secret_store.listBound(arena, io, global_secrets_dir);
	for ([_][]const []const u8{ instance_names, global_names }) |names| for (names) |name| {
		const resolved = (try resolveSecret(arena, io, instance_secrets_dir, global_secrets_dir, name)) orelse continue;
		if (!resolved.bound) continue;
		if (!std.mem.eql(u8, resolved.meta.kind, secret_mod.gitlab_oauth_kind)) continue;
		const audience = resolved.meta.audience orelse continue; // unset -> not injectable

		// FAIL CLOSED: an inject-eligible host is not blanket-allowed. A
		// gitlab-oauth bind is only ever meaningful TOGETHER with its compiled
		// grant rules — a seeded spec whose host no L7 rule names would make
		// renderL7 union a WHOLE-HOST `allow <host> terminate` (no path/service
		// constraint), injecting the owner's token on every path. That state is
		// reachable when a racy/buggy control plane clears the grant rules before
		// removing the bound secret, so the enforcer must not trust the bind
		// alone: skip the seed entirely (no spec -> no allow union, no inject
		// conf; worst case 403s until the next render re-seeds it). The
		// claude-oauth (anthropic-oauth) seed intentionally keeps its whole-host
		// allow-on-bound behavior — this gate is gitlab-oauth-only.
		if (!hostNamedInRules(l7Rules(network.*), audience)) continue;

		const specs = (try ensureInjectSpecs(arena, network)) orelse return;
		// Shadow-safe idempotency: skip only when OUR secret already names this host.
		var already = false;
		for (specs.items) |s| {
			if (s != .object) continue;
			const sn = strField(s.object, "secret") orelse continue;
			if (!std.mem.eql(u8, sn, name)) continue;
			const h = strField(s.object, "host") orelse continue;
			if (std.mem.eql(u8, h, audience)) {
				already = true;
				break;
			}
		}
		if (already) continue;

		var spec: std.json.ObjectMap = .empty;
		try spec.put(arena, "host", .{ .string = try arena.dupe(u8, audience) });
		try spec.put(arena, "style", .{ .string = secret_mod.gitlab_oauth_kind });
		try spec.put(arena, "secret", .{ .string = try arena.dupe(u8, name) });
		try spec.put(arena, "git_user", .{ .string = secret_mod.default_git_user });
		try spec.put(arena, "stub", .{ .string = secret_mod.gitlab_stub_token });
		try specs.append(.{ .object = spec });
	};
}

/// The auth-policy document schema versions this binary interprets. DUPLICATED
/// from l7/main.zig `policy_doc_versions` on purpose: the l7 verb module
/// imports rules_module, so importing it back would close a module cycle. Keep
/// the two lists in step -- the verb refuses an unknown version at delivery,
/// this gate makes one that got in anyway dead text.
const auth_policy_doc_versions = [_]i64{ 1, 2 };

fn authPolicyVersionKnown(v: i64) bool {
	for (auth_policy_doc_versions) |known| {
		if (v == known) return true;
	}
	return false;
}

/// The rendered CONF's schema version -- INDEPENDENT of the policy DOCUMENT's
/// version above. The document's version says what vocabulary cogworx sent;
/// the conf's says what its READER must understand to enforce what this render
/// wrote. This render runs in the AGENT image, authproxy/conf.zig runs in the
/// ENFORCER image, and those two roll on independent tags -- so the conf
/// version is the only whole-file fail-closed lever across that skew.
///
/// Base 1 is the shape every enforcer since the feature landed reads, and it
/// stays byte-identical for every conf that needs nothing newer. It moves to 2
/// for exactly ONE reason: some emitted grant carries `push` rules. A pre-v2
/// `parseGrants` reads only the fields it knows, so an unknown `push` object
/// would be silently DROPPED and a branch-restricted grant would relay every
/// ref -- widening. Fine CAP NAMES need no bump: the plugin's `compile`
/// already refuses an unknown cap and fails the whole conf. A dropped object
/// is the one lossy case, so the version carries it and an old reader refuses
/// the conf (empty policy, 403 `no-policy`) instead of enforcing less.
const conf_version_base: i64 = 1;
const conf_version_push: i64 = 2;

/// Whether any grant in a policy-doc `grants[]` carries a `push` object -- the
/// one field whose silent loss on an old reader would WIDEN the grant.
fn grantsCarryPush(grants_v: std.json.Value) bool {
	if (grants_v != .array) return false;
	for (grants_v.array.items) |g| {
		if (g != .object) continue;
		if (g.object.get("push") != null) return true;
	}
	return false;
}

/// The `providers[]` array of a KNOWN-VERSION `.network.l7.authpolicy`
/// document, or null when the section is absent / malformed / carries an
/// unknown version. The version gate makes a document this binary is too new or
/// too old to interpret DEAD TEXT rather than live policy (the delivery verb
/// refuses an unknown version before writing, but a hand-edited or rolled-back
/// config can still carry one -- fail closed here too). The accepted set is the
/// cross-repo schema version list (l7/main.zig policy_doc_versions; cogworx's
/// renderer): v2 adds fine caps and per-grant push rules, which ride into the
/// conf inside the grants[] this render copies VERBATIM -- the vocabulary is
/// the auth proxy plugin's to gate, not this render's.
fn authPolicyProviders(network: std.json.Value) ?std.json.Array {
	if (network != .object) return null;
	const l7 = network.object.getPtr("l7") orelse return null;
	if (l7.* != .object) return null;
	const ap = l7.object.getPtr("authpolicy") orelse return null;
	if (ap.* != .object) return null;
	const v = ap.object.get("version") orelse return null;
	if (v != .integer or !authPolicyVersionKnown(v.integer)) return null;
	const p = ap.object.getPtr("providers") orelse return null;
	if (p.* != .array) return null;
	return p.array;
}

/// The policy-doc provider entry whose `hosts[]` names `host` (gate 2 of
/// renderAuthProxyConf), or null. First match wins.
fn authPolicyEntryForHost(network: std.json.Value, host: []const u8) ?std.json.ObjectMap {
	const providers = authPolicyProviders(network) orelse return null;
	for (providers.items) |p| {
		if (p != .object) continue;
		const hosts = p.object.get("hosts") orelse continue;
		if (hosts != .array) continue;
		for (hosts.array.items) |h| {
			if (h != .string) continue;
			if (std.mem.eql(u8, h.string, host)) return p.object;
		}
	}
	return null;
}

/// Whether `host` is named by an allow rule flagged `insecure_upstream` in
/// `.network.l7.rules[]` -- the enforcer-side mirror of the addon's
/// host_insecure scan, single-sourced from the SAME rule set (finding N2):
/// after a retarget the upstream TLS leg belongs to the auth proxy, which never
/// sees mitmproxy's per-host verification toggle, so the flag must ride the
/// conf or a rule marked insecure silently stops applying to a migrated host.
/// Exact-host compare, like hostNamedInRules: the funnel rule a migrated host
/// rides is exact by construction, and a WILDCARD insecure rule not propagating
/// here fails CLOSED (verification stays on -> a named 502, never a silently
/// unverified leg).
fn hostInsecureInRules(rules: ?std.json.Array, host: []const u8) bool {
	const r = rules orelse return false;
	for (r.items) |item| {
		if (item != .object) continue;
		const h = strField(item.object, "allow") orelse continue;
		if (!std.mem.eql(u8, h, host)) continue;
		const iv = item.object.get("insecure_upstream") orelse continue;
		if (iv == .bool and iv.bool) return true;
	}
	return false;
}

/// Whether `host` is already one of the newline-delimited lines in `lines`
/// (the shape both l7-inject-hosts and l7-auth-hosts carry).
fn hostInLines(lines: []const u8, host: []const u8) bool {
	var it = std.mem.splitScalar(u8, lines, '\n');
	while (it.next()) |l| {
		if (std.mem.eql(u8, l, host)) return true;
	}
	return false;
}

/// Render the per-sandbox auth proxy's conf (`l7-auth-conf.json`) and its
/// retarget-host list (`l7-auth-hosts`). Walks the BOUND secrets exactly as
/// seedGitInjectSpecs does and emits a conf element ONLY when all three gates
/// hold:
///
///   1. the resolved secret is bound, its kind == gitlab_authproxy_kind, and
///      its audience is set;
///   2. `.network.l7.authpolicy` (version 1 or 2) carries a provider entry
///      whose `hosts[]` include that audience;
///   3. an L7 rule NAMES the audience (hostNamedInRules) -- the mirror of
///      seedGitInjectSpecs' fail-closed gate: it covers the window before the
///      funnel lands and a control plane that withdrew the rules but left the
///      bind (no rule, no conf element, 403s -- never owner-token-on-every-
///      path). NOTE: a stale document after a mode FLIP-BACK is neutralised
///      by gate 1, not this one -- the flip-back re-applies the legacy rules
///      (which DO name the host) and re-binds under the legacy kind, so the
///      kind check is what makes the document dead text there.
///
/// `grants`, when non-null, collects the cred file of every EMITTED element --
/// noted at the exact statement that writes `cred_file`, exactly as
/// renderL7Inject does, so what the auth proxy may read and what the conf names
/// it can never diverge. MUST run inside the same credgrant.Grants transaction
/// as renderL7Inject (see writeL7Inject): Grants.apply revokes group-read on
/// every bound value file and re-grants only the noted ones, so a render pass
/// that noted only the inject conf's files would silently revoke the auth
/// proxy's read access on the next `secret reload`. NOT pure -- reads the store.
///
/// Finding N1: every emitted host is ALSO appended to `inject_hosts_out` (the
/// l7-inject-hosts buffer), deduped against the inject-spec hosts already
/// there. That file is what routes a host's PLAIN-HTTP egress through the
/// terminate backend; under the authproxy kind no inject spec exists, so
/// without this append an `http://` request to a migrated host takes the
/// raw-L4 splice governed only by the whole-host funnel rule -- anonymous
/// whole-host reach with no path enforcement. The cleartext-exfil argument
/// that deliberately keeps HARNESS hosts out of that file (a guest forcing a
/// cleartext send of the real OAuth token, cogbox-launch.sh) does not apply
/// here: the guest holds no token at all, and the upstream scheme is
/// config-derived, never request-derived.
pub fn renderAuthProxyConf(
	allocator: std.mem.Allocator,
	io: std.Io,
	network: std.json.Value,
	global_secrets_dir: []const u8,
	instance_secrets_dir: []const u8,
	out: *std.ArrayList(u8),
	auth_hosts_out: *std.ArrayList(u8),
	inject_hosts_out: *std.ArrayList(u8),
	grants: ?*credgrant.Grants,
) !void {
	var arena_inst = std.heap.ArenaAllocator.init(allocator);
	defer arena_inst.deinit();
	const arena = arena_inst.allocator();

	var providers_arr = std.json.Array.init(arena);
	// Raised to conf_version_push by the first emitted entry carrying push
	// rules; a conf with none stays byte-identical to the pre-v2 render.
	var conf_version: i64 = conf_version_base;

	// Union of both stores' bound names, instance shadowing global -- the same
	// walk (and the same shadow semantics) as seedGitInjectSpecs.
	const instance_names = try secret_store.listBound(arena, io, instance_secrets_dir);
	const global_names = try secret_store.listBound(arena, io, global_secrets_dir);
	for ([_][]const []const u8{ instance_names, global_names }) |names| for (names) |name| {
		const resolved = (try resolveSecret(arena, io, instance_secrets_dir, global_secrets_dir, name)) orelse continue;
		// GATE 1: bound, the authproxy kind, audience set.
		if (!resolved.bound) continue;
		if (!std.mem.eql(u8, resolved.meta.kind, secret_mod.gitlab_authproxy_kind)) continue;
		const audience = resolved.meta.audience orelse continue; // unset -> not routable
		// One element per host: a name bound in both stores resolves to the
		// same instance value twice, and two binds sharing one audience would
		// hand the conf two ambiguous entries -- first (instance-shadowed) wins.
		if (hostInLines(auth_hosts_out.items, audience)) continue;
		// GATE 2: a policy-doc provider entry claims this host. The element's
		// plugin/scheme/git_user/grants all come from the DOC (the compiled,
		// decided policy), never from the secret or a request.
		const entry = authPolicyEntryForHost(network, audience) orelse continue;
		const plugin = strField(entry, "plugin") orelse continue;
		const scheme = strField(entry, "scheme") orelse continue;
		// GATE 3: an L7 rule names the host (the funnel). A doc without ANY
		// rule naming its host -- the window before the funnel lands, a
		// partial transaction, a control plane that withdrew the rules --
		// emits nothing: the request never reaches the addon's retarget
		// anyway, and a conf element for it would be policy with no delivery
		// path. (A mode flip-back is gate 1's case, not this one: the legacy
		// rules it re-applies name the host, and the legacy-kind re-bind is
		// what fails.)
		if (!hostNamedInRules(l7Rules(network), audience)) continue;

		var el: std.json.ObjectMap = .empty;
		try el.put(arena, "host", .{ .string = audience });
		try el.put(arena, "plugin", .{ .string = plugin });
		try el.put(arena, "scheme", .{ .string = scheme });
		try el.put(arena, "insecure", .{ .bool = hostInsecureInRules(l7Rules(network), audience) });
		try el.put(arena, "cred_file", .{ .string = resolved.value_path });
		// Note the cred file HERE, at the statement that writes it into the
		// conf, for the same reason renderL7Inject does: the only paths the
		// Grants pass can ever make proxy-readable are then the store paths
		// this resolver produced, never a cred_file a config or operator
		// override supplied.
		if (grants) |g| try g.note(resolved.value_path);
		try el.put(arena, "cred_format", .{ .string = "raw" });
		try el.put(arena, "git_user", .{ .string = strField(entry, "git_user") orelse secret_mod.default_git_user });
		// The provider entry's grants[] VERBATIM from the doc -- semantic
		// tuples the plugin evaluates; never route-shaped, never re-derived.
		// An entry without them gets an empty array: the plugin then compiles
		// zero grants and denies everything (fail closed), rather than the
		// whole conf being refused for every host.
		const grants_v = entry.get("grants") orelse std.json.Value{ .array = std.json.Array.init(arena) };
		// The ONE thing the render must notice about the grant vocabulary (see
		// conf_version_push): a `push` object an old reader would drop.
		if (grantsCarryPush(grants_v)) conf_version = conf_version_push;
		try el.put(arena, "grants", grants_v);
		try providers_arr.append(.{ .object = el });

		// The addon's retarget set: one EMITTED host per line, nothing else.
		try auth_hosts_out.appendSlice(allocator, audience);
		try auth_hosts_out.append(allocator, '\n');
		// Finding N1 (see the doc comment): route this host's plain-HTTP
		// egress through the terminate backend too, deduped against the
		// inject-spec hosts renderL7Inject already emitted.
		if (!hostInLines(inject_hosts_out.items, audience)) {
			try inject_hosts_out.appendSlice(allocator, audience);
			try inject_hosts_out.append(allocator, '\n');
		}
	};

	var root: std.json.ObjectMap = .empty;
	try root.put(arena, "version", .{ .integer = conf_version });
	try root.put(arena, "providers", .{ .array = providers_arr });
	try config.writeJqTab(allocator, out, .{ .object = root });
}

/// Resolve a named secret: an instance-produced secret (e.g. a sidecar-minted
/// session) shadows a global operator-bound one of the same name.
fn resolveSecret(
	arena: std.mem.Allocator,
	io: std.Io,
	instance_dir: []const u8,
	global_dir: []const u8,
	name: []const u8,
) !?secret_store.Resolved {
	if (try secret_store.lookup(arena, io, instance_dir, name)) |r| {
		if (r.bound) return r;
	}
	return try secret_store.lookup(arena, io, global_dir, name);
}

pub fn writeRuntimeRules(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8, network: std.json.Value, l7_base: u16) !void {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	try renderRules(allocator, network, l7_base, &out);
	try writeRuntimeFile(allocator, io, runtime_dir, "netfilter-rules", out.items);
}

/// Write `<runtime>/l7-rules` (the host-side proxy's rule file).
pub fn writeL7Rules(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8, network: std.json.Value) !void {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	try renderL7(allocator, network, &out);
	try writeRuntimeFile(allocator, io, runtime_dir, "l7-rules", out.items);
}

/// Write `<runtime>/l7-inject-conf.json` (the mitmproxy addon's
/// COGBOX_L7_INJECT_CONF), `<runtime>/l7-auth-conf.json` (the auth proxy's
/// conf), `<runtime>/l7-inject-hosts` (the L7 proxy's plain-HTTP
/// inject-routing list) AND `<runtime>/l7-auth-hosts` (the addon's retarget
/// set). Resolves each spec's named secret against the per-instance then
/// global store. All four are written from ONE pass, under ONE
/// credgrant.Grants transaction, so the proxy's HTTP routing, the addon's
/// injection, the auth proxy's policy and the store's read grants can never
/// drift from each other.
///
/// `proxy_gid` is the gid the L7 proxy was dropped to (COGBOX_PROXY_RUNAS,
/// resolved by credgrant.proxyGidFromEnv), or null where reader and store owner
/// are the same uid (container, k8s, local -- an exact no-op there). When set,
/// this reconciles the store's permissions so that gid can read EXACTLY the cred
/// files the confs being written name, and nothing else in the store.
pub fn writeL7Inject(
	allocator: std.mem.Allocator,
	io: std.Io,
	runtime_dir: []const u8,
	network: std.json.Value,
	global_secrets_dir: []const u8,
	instance_secrets_dir: []const u8,
	proxy_gid: ?credgrant.Gid,
) !void {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	var hosts: std.ArrayList(u8) = .empty;
	defer hosts.deinit(allocator);
	var auth_out: std.ArrayList(u8) = .empty;
	defer auth_out.deinit(allocator);
	var auth_hosts: std.ArrayList(u8) = .empty;
	defer auth_hosts.deinit(allocator);
	var grants = credgrant.Grants.init(allocator, proxy_gid);
	defer grants.deinit();
	try renderL7Inject(allocator, io, network, global_secrets_dir, instance_secrets_dir, &out, &hosts, &grants);
	// The auth-proxy conf renders inside the SAME Grants transaction, and it
	// must: grants.apply below revokes group-read on every bound value file
	// and re-grants only the ones noted in THIS pass, so rendering the auth
	// conf in a second pass would revoke the auth proxy's cred-file access on
	// every `secret reload`. It also appends the auth hosts to `hosts` (the
	// l7-inject-hosts buffer -- finding N1) before that file is written.
	try renderAuthProxyConf(allocator, io, network, global_secrets_dir, instance_secrets_dir, &auth_out, &auth_hosts, &hosts, &grants);
	// BEFORE the confs are written, deliberately: the addon and the auth proxy
	// re-read their confs when the mtime changes, so a cred file they are
	// about to be told about has to be readable already or the first requests
	// after a live bind fail closed on a file that is one syscall away from
	// being readable. The revoke direction is safe in this order too -- both
	// readers can only end up denying, never stamping a credential this render
	// just took away.
	try grants.apply(io, &.{ instance_secrets_dir, global_secrets_dir });
	// The four wire files, written in l7_inject_write_order (see the constant
	// for why the order is load-bearing and how a test pins it).
	const files = [l7_inject_write_order.len][]const u8{ out.items, auth_out.items, hosts.items, auth_hosts.items };
	for (l7_inject_write_order, files) |name, bytes| {
		try writeRuntimeFile(allocator, io, runtime_dir, name, bytes);
	}
}

/// The ORDER writeL7Inject writes its four wire files in -- a single pinned
/// list (asserted by a test) rather than four calls whose sequence nothing
/// checks. Renders are NOT atomic (writeRuntimeFile truncates in place), so
/// each conf must land before the hosts file that routes traffic to its
/// consumer, and l7-auth-hosts must land LAST: a torn state is then always
/// the fail-closed one -- hosts ahead of conf can only 403 (the auth proxy
/// has no entry yet), never retarget-and-stamp against a stale conf.
pub const l7_inject_write_order = [_][]const u8{
	"l7-inject-conf.json",
	"l7-auth-conf.json",
	"l7-inject-hosts",
	"l7-auth-hosts",
};

fn writeRuntimeFile(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8, name: []const u8, bytes: []const u8) !void {
	const path = try std.fs.path.join(allocator, &.{ runtime_dir, name });
	defer allocator.free(path);

	const cwd = std.Io.Dir.cwd();
	const f = try cwd.createFile(io, path, .{ .truncate = true });
	defer f.close(io);
	var write_buf: [4096]u8 = undefined;
	var writer = f.writer(io, &write_buf);
	try writer.interface.writeAll(bytes);
	try writer.flush();
}

/// If <runtime>/passt.pid exists and the process is alive, send SIGUSR1.
/// Returns true if a signal was sent.
pub fn maybeSignalPasst(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8) !bool {
	return signalPidfile(allocator, io, runtime_dir, "passt.pid", std.posix.SIG.USR1);
}

/// If <runtime>/l7proxy.pid exists and the process is alive, send SIGHUP so
/// the L7 proxy re-reads netfilter-rules + l7-rules. No-op if not running.
pub fn maybeSignalL7proxy(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8) !bool {
	return signalPidfile(allocator, io, runtime_dir, "l7proxy.pid", std.posix.SIG.HUP);
}

fn signalPidfile(allocator: std.mem.Allocator, io: std.Io, runtime_dir: []const u8, pidfile: []const u8, sig: std.posix.SIG) !bool {
	const path = try std.fs.path.join(allocator, &.{ runtime_dir, pidfile });
	defer allocator.free(path);

	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(io, path, .{}) catch |err| switch (err) {
		error.FileNotFound => return false,
		else => return err,
	};
	defer file.close(io);

	var read_buf: [64]u8 = undefined;
	var reader = file.reader(io, &read_buf);
	const contents = reader.interface.allocRemaining(allocator, .limited(64)) catch return false;
	defer allocator.free(contents);

	const trimmed = std.mem.trim(u8, contents, " \t\r\n");
	const pid = std.fmt.parseInt(std.posix.pid_t, trimmed, 10) catch return false;

	const sig_zero: std.posix.SIG = @enumFromInt(0);
	std.posix.kill(pid, sig_zero) catch return false;
	std.posix.kill(pid, sig) catch return false;
	return true;
}

test "renderL7 wire format incl. insecure token" {
	const gpa = std.testing.allocator;
	const src =
		\\{"l7":{"mode":"terminate","rules":[
		\\  {"allow":"plain.test"},
		\\  {"allow":"api.test","path":"/v1/"},
		\\  {"allow":"internal.svc","terminate":true,"insecure_upstream":true},
		\\  {"allow":"lab.svc","path":"/api/","insecure_upstream":true}
		\\]}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderL7(gpa, parsed.value, &out);
	const s = out.items;

	const has = struct {
		fn f(hay: []const u8, needle: []const u8) bool {
			return std.mem.indexOf(u8, hay, needle) != null;
		}
	}.f;
	try std.testing.expect(has(s, "mode terminate\n"));
	// insecure (no path) -> emitted after the terminate marker
	try std.testing.expect(has(s, "allow internal.svc terminate insecure\n"));
	// insecure + path -> path carries terminate, insecure trails
	try std.testing.expect(has(s, "allow lab.svc /api/ insecure\n"));
	// plain / path-only rules carry no insecure token
	try std.testing.expect(has(s, "allow plain.test\n"));
	try std.testing.expect(has(s, "allow api.test /v1/\n"));
	try std.testing.expect(!has(s, "plain.test insecure"));
}

test "l7Active counts inject specs (inject-only instance still funnels)" {
	const gpa = std.testing.allocator;
	{
		const src = "{\"l7\":{\"rules\":[],\"inject\":{\"enabled\":true,\"specs\":[{\"host\":\"a.test\",\"secret\":\"s\"}]}}}";
		var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
		defer parsed.deinit();
		try std.testing.expect(l7Active(parsed.value));
	}
	{
		const src = "{\"l7\":{\"rules\":[],\"inject\":{\"enabled\":true,\"specs\":[]}}}";
		var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
		defer parsed.deinit();
		try std.testing.expect(!l7Active(parsed.value));
	}
}

test "injectSpecs honors the enabled:false master toggle" {
	const gpa = std.testing.allocator;
	const src = "{\"l7\":{\"rules\":[],\"inject\":{\"enabled\":false,\"specs\":[{\"host\":\"a.test\",\"secret\":\"s\"}]}}}";
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	try std.testing.expect(!l7Active(parsed.value)); // disabled -> no funnel
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderL7(gpa, parsed.value, &out); // and no terminate-allow union
	try std.testing.expect(std.mem.indexOf(u8, out.items, "a.test") == null);
}

test "renderL7 unions inject hosts as terminate-allows, deduped against existing rules" {
	const gpa = std.testing.allocator;
	const src =
		\\{"l7":{"mode":"terminate","rules":[{"allow":"already.test","terminate":true}],
		\\ "inject":{"enabled":true,"specs":[
		\\   {"host":"api.example.com","style":"bearer","secret":"s1"},
		\\   {"host":"already.test","style":"bearer","secret":"s2"}]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderL7(gpa, parsed.value, &out);
	const s = out.items;
	// an inject host not already named gets a terminate allow appended
	try std.testing.expect(std.mem.indexOf(u8, s, "allow api.example.com terminate\n") != null);
	// a host already named by an l7 rule is NOT duplicated by the union
	try std.testing.expect(std.mem.count(u8, s, "already.test") == 1);
}

test "injectUnionCount is exactly what renderL7 appends beyond .l7.rules[]" {
	const gpa = std.testing.allocator;
	const src =
		\\{"l7":{"mode":"terminate","rules":[{"allow":"already.test"},{"deny":"blocked.test"}],
		\\ "inject":{"enabled":true,"specs":[
		\\   {"host":"api.example.com","style":"bearer","secret":"api-token"},
		\\   {"host":"already.test","style":"bearer","secret":"app-session"},
		\\   {"host":"app.example.com","style":"bearer","secret":"api-token"},
		\\   {"style":"bearer","secret":"api-token"},
		\\   "not-an-object"]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	// Two unnamed hosts; the rule-named one and the two malformed entries yield
	// no line.
	try std.testing.expectEqual(@as(usize, 2), injectUnionCount(parsed.value));

	// And that is literally the delta between the config array and the rendered
	// rule-line count -- the quantity filter.parseL7Rules caps. Counting the array
	// instead is how a replace can pass its own cap check and still render a
	// document whose tail the enforcer silently drops.
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderL7(gpa, parsed.value, &out);
	var rendered: usize = 0;
	var lines = std.mem.splitScalar(u8, out.items, '\n');
	while (lines.next()) |line| {
		if (std.mem.startsWith(u8, line, "allow ") or std.mem.startsWith(u8, line, "deny ")) rendered += 1;
	}
	const array_len = l7Rules(parsed.value).?.items.len;
	try std.testing.expectEqual(array_len + injectUnionCount(parsed.value), rendered);
}

test "renderL7 overflows filter.max_l7_rules on an at-cap array (the inject-union delta the l7-replace cap must budget for)" {
	const gpa = std.testing.allocator;
	var src: std.ArrayList(u8) = .empty;
	defer src.deinit(gpa);
	try src.appendSlice(gpa, "{\"l7\":{\"mode\":\"terminate\",\"rules\":[");
	for (0..filter.max_l7_rules) |i| {
		if (i > 0) try src.appendSlice(gpa, ",");
		try src.appendSlice(gpa, "{\"allow\":\"a.test\"}");
	}
	// One inject spec whose host no rule names -- e.g. the claude-oauth audience on
	// an instance that never allow-listed it. renderL7 appends its terminate-allow
	// AFTER the array, so the document carries max+1 rule lines.
	try src.appendSlice(gpa, "],\"inject\":{\"enabled\":true,\"specs\":[{\"host\":\"api.example.com\",\"style\":\"bearer\",\"secret\":\"api-token\"}]}}}");

	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src.items, .{});
	defer parsed.deinit();
	try std.testing.expectEqual(@as(usize, 1), injectUnionCount(parsed.value));

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderL7(gpa, parsed.value, &out);
	try std.testing.expect(std.mem.indexOf(u8, out.items, "allow api.example.com terminate\n") != null);

	// The enforcer compiles the first max_l7_rules and DROPS the rest in silence,
	// while the terminate-tier addon parsing the same document has no cap: the
	// inject-union line is gone from one layer and honoured by the other.
	var set: filter.L7RuleSet = undefined;
	filter.parseL7Rules(out.items, &set);
	try std.testing.expectEqual(filter.max_l7_rules, set.len);
	var compiled_injected = false;
	for (set.rules[0..set.len]) |r| {
		if (std.mem.eql(u8, r.host.slice(), "api.example.com")) compiled_injected = true;
	}
	try std.testing.expect(!compiled_injected);
}

test "renderRules funnel targets the per-instance base ports" {
	const gpa = std.testing.allocator;
	const src = "{\"l7\":{\"mode\":\"passthrough\",\"rules\":[{\"allow\":\"x.test\"}]}}";
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	// A named instance's base (default keeps 18443); funnel must target it.
	try renderRules(gpa, parsed.value, 18446, &out);
	const s = out.items;
	try std.testing.expect(std.mem.indexOf(u8, s, "remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:18446\n") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "remap tcp 0.0.0.0/0:80 -> tcp 127.0.0.1:18447\n") != null);
	// this instance's render never mentions the default base
	try std.testing.expect(std.mem.indexOf(u8, s, "18443") == null);
}

// The producer half of the port-53 parameterization and the l7proxy
// self-address floor. Without these emissions the
// parser and consumer sides are dead code and the realized image ships the
// permissive defaults -- arbitrary-destination DNS and a floor that rests on
// nftables alone.

test "renderRules emits no-implicit-dns FIRST, ahead of the L7 fail-closed prologue" {
	const gpa = std.testing.allocator;
	const src = "{\"implicitDns\":false,\"l7\":{\"mode\":\"passthrough\",\"rules\":[{\"allow\":\"x.test\"}]}}";
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderRules(gpa, parsed.value, 18443, &out);
	const s = out.items;
	// First line, not merely present: the directive is what subjects port 53
	// to the v6 fail-close below it, and parseRules is order-independent only
	// because this is a directive rather than a rule -- keep the file readable
	// in the order a human reasons about it.
	try std.testing.expect(std.mem.startsWith(u8, s, "no-implicit-dns\n"));
	try std.testing.expect(std.mem.indexOf(u8, s, "no-implicit-dns\n").? < std.mem.indexOf(u8, s, "deny tcp ::/0").?);
	// And it round-trips through the parser the shim and the proxy both use.
	try std.testing.expect(!filter.parseRules(s).implicit_dns_allow);
}

test "renderRules emits exactly one hard-deny per selfAddrs entry" {
	const gpa = std.testing.allocator;
	const src = "{\"selfAddrs\":[\"10.0.0.7/32\",\"10.0.0.8\"],\"rules\":[{\"allow\":\"0.0.0.0/0\"}]}";
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderRules(gpa, parsed.value, 18443, &out);
	const s = out.items;
	try std.testing.expect(std.mem.indexOf(u8, s, "hard-deny 10.0.0.7/32\n") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "hard-deny 10.0.0.8\n") != null);
	try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, s, "hard-deny "));

	// End to end: the rendered line reaches the proxy's floor.
	const rs = filter.parseRules(s);
	try std.testing.expectEqual(@as(usize, 2), rs.hard_len);
	try std.testing.expect(rs.hardBlocked(.{ .ipv4 = .{ 10, 0, 0, 7 } }));
	try std.testing.expect(rs.hardBlocked(.{ .ipv4 = .{ 10, 0, 0, 8 } }));
	// The user rule layer is untouched by the floor emission.
	try std.testing.expect(std.mem.indexOf(u8, s, "allow 0.0.0.0/0\n") != null);
}

test "renderRules ignores malformed selfAddrs entries" {
	const gpa = std.testing.allocator;
	const src = "{\"selfAddrs\":[\"\",42,{\"x\":1},\"10.0.0.7\"]}";
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderRules(gpa, parsed.value, 18443, &out);
	try std.testing.expectEqualStrings("hard-deny 10.0.0.7\n", out.items);
}

test "renderRules output is byte-identical to today when neither key is set" {
	// The default-preserving guarantee that keeps the local and k8s backends
	// untouched: same JSON in, same bytes out as before the two keys existed.
	// A regression here changes what every existing instance enforces on its
	// next hot reload, silently.
	const gpa = std.testing.allocator;
	const src =
		\\{"rules":[{"deny":"169.254.0.0/16"},{"allow":"0.0.0.0/0"}],
		\\ "remap":[{"from":"tcp 1.2.3.0/24:25","to":"tcp 127.0.0.1:12525"}],
		\\ "l7":{"mode":"terminate","rules":[{"allow":"api.example.com","terminate":true}]}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderRules(gpa, parsed.value, 18443, &out);
	try std.testing.expectEqualStrings(
		\\deny tcp ::/0
		\\deny udp ::/0
		\\deny udp 0.0.0.0/0:443
		\\deny udp 0.0.0.0/0:80
		\\deny 169.254.0.0/16
		\\allow 0.0.0.0/0
		\\remap tcp 1.2.3.0/24:25 -> tcp 127.0.0.1:12525
		\\remap tcp 0.0.0.0/0:443 -> tcp 127.0.0.1:18443
		\\remap tcp 0.0.0.0/0:80 -> tcp 127.0.0.1:18444
		\\
	, out.items);
	// And the parsed result keeps every permissive default.
	const rs = filter.parseRules(out.items);
	try std.testing.expect(rs.implicit_dns_allow);
	try std.testing.expectEqual(@as(usize, 0), rs.hard_len);
	try std.testing.expect(rs.dns_host == null);
}

// THE GUEST-DNS REGRESSION, renderer half. The GCE backend hands the guest a
// resolver address passt INTERCEPTS (`--dns-forward`) and re-emits to a
// loopback forwarder on the trusted half, so the guest resolves what the HOST
// resolves -- internal names included. That re-emitted socket is a loopback
// connect under the passt uid, and `no-implicit-dns` (which this backend always
// passes) puts loopback DNS back under the shim's loopback deny. Without this
// line the rules-mode guest has no DNS at all and nothing says so.
test "renderRules emits dns-host beside no-implicit-dns and the pair round-trips" {
	const gpa = std.testing.allocator;
	const src = "{\"implicitDns\":false,\"dnsHost\":\"127.0.0.53\"," ++
		"\"rules\":[{\"deny\":\"169.254.0.0/16\"},{\"allow\":\"0.0.0.0/0\"}]}";
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderRules(gpa, parsed.value, 18443, &out);
	const s = out.items;
	try std.testing.expect(std.mem.indexOf(u8, s, "dns-host 127.0.0.53\n") != null);
	try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, s, "dns-host "));

	// End to end through the parser the shim uses: the forwarder's socket is
	// reachable, and nothing else about port 53 or loopback moved.
	const rs = filter.parseRules(s);
	try std.testing.expect(!rs.implicit_dns_allow);
	try std.testing.expectEqual(filter.Action.allow, rs.evaluate(.udp, .{ .ipv4 = .{ 127, 0, 0, 53 } }, 53));
	try std.testing.expectEqual(filter.Action.deny, rs.evaluate(.udp, .{ .ipv4 = .{ 169, 254, 169, 254 } }, 53));
	try std.testing.expectEqual(filter.Action.deny, rs.evaluate(.tcp, .{ .ipv4 = .{ 127, 0, 0, 1 } }, 18445));
}

test "renderRules ignores an empty or non-string dnsHost" {
	// Fail CLOSED on a malformed value rather than emitting `dns-host ` with an
	// empty body, which parseDnsHostBody would drop anyway -- but silently, one
	// layer further from whoever wrote the config.
	const gpa = std.testing.allocator;
	for ([_][]const u8{ "{\"dnsHost\":\"\"}", "{\"dnsHost\":42}", "{\"dnsHost\":null}" }) |src| {
		var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
		defer parsed.deinit();
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(gpa);
		try renderRules(gpa, parsed.value, 18443, &out);
		try std.testing.expectEqualStrings("", out.items);
	}
}

test "renderRules funnels non-standard inject-host ports (deduped, 80/443 excluded)" {
	const gpa = std.testing.allocator;
	const src =
		\\{"l7":{"mode":"terminate","rules":[],"inject":{"enabled":true,"specs":[
		\\  {"host":"es.internal","style":"basic","secret":"es","port":9200},
		\\  {"host":"es2.internal","style":"basic","secret":"es2","port":9200},
		\\  {"host":"kibana.internal","style":"basic","secret":"kb","port":"5601"},
		\\  {"host":"std-https.internal","style":"bearer","secret":"h","port":443},
		\\  {"host":"std-http.internal","style":"bearer","secret":"p","port":80},
		\\  {"host":"no-port.internal","style":"bearer","secret":"n"}]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderRules(gpa, parsed.value, 18443, &out);
	const s = out.items;

	// :9200 funnels to the http entry (base+1); declared twice but emitted once.
	try std.testing.expect(std.mem.indexOf(u8, s, "remap tcp 0.0.0.0/0:9200 -> tcp 127.0.0.1:18444\n") != null);
	try std.testing.expect(std.mem.count(u8, s, "0.0.0.0/0:9200 ->") == 1);
	// a numeric-string port is honored too.
	try std.testing.expect(std.mem.indexOf(u8, s, "remap tcp 0.0.0.0/0:5601 -> tcp 127.0.0.1:18444\n") != null);
	// 80/443 are already the standard funnel -- no duplicate custom remap for them.
	try std.testing.expect(std.mem.count(u8, s, "0.0.0.0/0:443 ->") == 1);
	try std.testing.expect(std.mem.count(u8, s, "0.0.0.0/0:80 ->") == 1);
}

// A self-made instance store dir (relative to cwd) for the renderL7Inject IO
// tests; the caller owns teardown. Returns the dir name allocated in `gpa`.
fn tmpStoreDir(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	const dir = try std.fmt.allocPrint(gpa, "zig-inject-test-{s}", .{hexb});
	try std.Io.Dir.cwd().createDirPath(io, dir);
	return dir;
}

test "renderL7Inject: kind=anthropic-oauth forces style + the shared stub sentinel, no refresh" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const inst_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(inst_dir);
	defer cwd.deleteTree(io, inst_dir) catch {};

	// Bind the reserved claude-oauth secret: kind=anthropic-oauth, audience pinned
	// to the spec host. The VALUE is a fictional (OSS-clean) setup-token.
	try secret_store.add(gpa, io, inst_dir, "claude-oauth", "sk-ant-oat01-FAKEFAKEFAKEFAKEFAKE", .{
		.audience = "api.anthropic.com",
		.kind = secret_mod.anthropic_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	});

	// The spec deliberately declares a DIFFERENT style + stub: the secret's kind
	// must override both.
	const src =
		\\{"l7":{"mode":"terminate","inject":{"enabled":true,"specs":[
		\\  {"host":"api.anthropic.com","style":"bearer","secret":"claude-oauth","stub":"ignored-spec-stub"}]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	var hosts: std.ArrayList(u8) = .empty;
	defer hosts.deinit(gpa);
	// No global store needed (the instance store binds the secret).
	try renderL7Inject(gpa, io, parsed.value, "zig-inject-test-no-global", inst_dir, &out, &hosts, null);
	const s = out.items;

	try std.testing.expect(std.mem.indexOf(u8, s, "\"style\": \"anthropic-oauth\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"cred_format\": \"raw\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, secret_mod.claude_stub_token) != null);
	// the spec's declared bearer style + stub did NOT win
	try std.testing.expect(std.mem.indexOf(u8, s, "ignored-spec-stub") == null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"style\": \"bearer\"") == null);
	// a setup-token is static -> no refresh block is ever emitted here
	try std.testing.expect(std.mem.indexOf(u8, s, "refresh") == null);
	// gating is gitlab-only: an anthropic-oauth spec carries NO rules_tag, so its
	// whole-host allow-on-bound injection stays ungated (regression guard).
	try std.testing.expect(std.mem.indexOf(u8, s, "rules_tag") == null);
	// the host is mirrored into the plain-HTTP inject-routing list
	try std.testing.expect(std.mem.indexOf(u8, hosts.items, "api.anthropic.com") != null);
}

test "renderL7Inject: a bearer-kind secret keeps the spec's style + spec stub (other kinds unchanged)" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const inst_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(inst_dir);
	defer cwd.deleteTree(io, inst_dir) catch {};

	try secret_store.add(gpa, io, inst_dir, "api-token", "tok-abc123", .{
		.audience = "api.example.com",
		.kind = "bearer",
		.tier = "durable",
		.bound_at = 1,
	});

	const src =
		\\{"l7":{"mode":"terminate","inject":{"enabled":true,"specs":[
		\\  {"host":"api.example.com","style":"bearer","secret":"api-token","stub":"spec-stub-keeps"}]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	var hosts: std.ArrayList(u8) = .empty;
	defer hosts.deinit(gpa);
	try renderL7Inject(gpa, io, parsed.value, "zig-inject-test-no-global", inst_dir, &out, &hosts, null);
	const s = out.items;

	// Unchanged from before this feature: the spec's style + its own stub are used,
	// and the claude sentinel is NOT stamped onto a non-claude kind.
	try std.testing.expect(std.mem.indexOf(u8, s, "\"style\": \"bearer\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "spec-stub-keeps") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, secret_mod.claude_stub_token) == null);
	try std.testing.expect(std.mem.indexOf(u8, s, "anthropic-oauth") == null);
}

test "seedClaudeInjectSpec seeds the claude-oauth spec into l7.inject.specs (idempotent)" {
	const gpa = std.testing.allocator;
	// A rules-mode network with NO l7 yet (the container default before the seed).
	const src =
		\\{"rules":[{"allow":"0.0.0.0/0","comment":"public"}]}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	var net = parsed.value;

	try seedClaudeInjectSpec(parsed.arena.allocator(), &net);

	const specs = net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array;
	try std.testing.expectEqual(@as(usize, 1), specs.items.len);
	const s0 = specs.items[0].object;
	try std.testing.expectEqualStrings(secret_mod.anthropic_api_host, s0.get("host").?.string);
	try std.testing.expectEqualStrings(secret_mod.anthropic_oauth_kind, s0.get("style").?.string);
	try std.testing.expectEqualStrings(secret_mod.claude_oauth_secret, s0.get("secret").?.string);
	// A spec only NAMES a credential: no value/path/stub leaks into config.
	try std.testing.expect(s0.get("stub") == null);
	try std.testing.expect(s0.get("cred_file") == null);

	// Idempotent: re-seeding the same network adds nothing.
	try seedClaudeInjectSpec(parsed.arena.allocator(), &net);
	const specs2 = net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array;
	try std.testing.expectEqual(@as(usize, 1), specs2.items.len);
}

test "seedClaudeInjectSpec is additive: keeps an existing plugin inject spec" {
	const gpa = std.testing.allocator;
	// A plugin already contributed a spec for a different host (OSS-clean fictionals).
	const src =
		\\{"l7":{"inject":{"specs":[
		\\  {"host":"api.example.com","style":"bearer","secret":"api-token","plugin":"obs-plugin"}]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	var net = parsed.value;

	try seedClaudeInjectSpec(parsed.arena.allocator(), &net);

	const specs = net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array;
	try std.testing.expectEqual(@as(usize, 2), specs.items.len);
	// the plugin spec is untouched (still first)
	try std.testing.expectEqualStrings("api.example.com", specs.items[0].object.get("host").?.string);
	try std.testing.expectEqualStrings("obs-plugin", specs.items[0].object.get("plugin").?.string);
	// the harness claude spec was appended
	try std.testing.expectEqualStrings(secret_mod.anthropic_api_host, specs.items[1].object.get("host").?.string);
	try std.testing.expectEqualStrings(secret_mod.claude_oauth_secret, specs.items[1].object.get("secret").?.string);
}

test "seeded claude-oauth spec: renderL7Inject silent when unbound, emits when bound" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const inst_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(inst_dir);
	defer cwd.deleteTree(io, inst_dir) catch {};

	// The container default: a rules-mode network with no l7 -> seed it, exactly as
	// the enforcer render does before writing the inject conf.
	const src =
		\\{"rules":[{"allow":"0.0.0.0/0","comment":"public"}]}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	var net = parsed.value;
	try seedClaudeInjectSpec(parsed.arena.allocator(), &net);

	// Unbound: claude-oauth isn't in the store -> renderL7Inject emits NO element
	// and routes NO host, the fail-closed "guest carries its own token" fallback.
	{
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(gpa);
		var hosts: std.ArrayList(u8) = .empty;
		defer hosts.deinit(gpa);
		try renderL7Inject(gpa, io, net, "zig-inject-test-no-global", inst_dir, &out, &hosts, null);
		try std.testing.expect(std.mem.indexOf(u8, out.items, "anthropic-oauth") == null);
		try std.testing.expect(std.mem.indexOf(u8, out.items, secret_mod.anthropic_api_host) == null);
		try std.testing.expect(std.mem.indexOf(u8, hosts.items, secret_mod.anthropic_api_host) == null);
	}

	// Bind the reserved secret the way cogworx's reconcile does: kind=anthropic-oauth,
	// audience pinned to the host. The VALUE is a fictional (OSS-clean) setup-token.
	try secret_store.add(gpa, io, inst_dir, secret_mod.claude_oauth_secret, "sk-ant-oat01-FAKEFAKEFAKEFAKEFAKE", .{
		.audience = secret_mod.anthropic_api_host,
		.kind = secret_mod.anthropic_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	});

	// Bound: the seeded spec now resolves -> an anthropic-oauth element carrying the
	// shared stub sentinel, NO refresh block, and the host mirrored into the
	// plain-HTTP inject-routing list.
	{
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(gpa);
		var hosts: std.ArrayList(u8) = .empty;
		defer hosts.deinit(gpa);
		try renderL7Inject(gpa, io, net, "zig-inject-test-no-global", inst_dir, &out, &hosts, null);
		try std.testing.expect(std.mem.indexOf(u8, out.items, "\"style\": \"anthropic-oauth\"") != null);
		try std.testing.expect(std.mem.indexOf(u8, out.items, "\"cred_format\": \"raw\"") != null);
		try std.testing.expect(std.mem.indexOf(u8, out.items, secret_mod.claude_stub_token) != null);
		try std.testing.expect(std.mem.indexOf(u8, out.items, "refresh") == null);
		try std.testing.expect(std.mem.indexOf(u8, hosts.items, secret_mod.anthropic_api_host) != null);
	}
}

test "claudeOAuthBound: false when unbound, true once the claude-oauth secret is bound" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const inst_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(inst_dir);
	defer cwd.deleteTree(io, inst_dir) catch {};

	var arena = std.heap.ArenaAllocator.init(gpa);
	defer arena.deinit();

	// Never connected: nothing in the store -> not bound.
	try std.testing.expect(!(try claudeOAuthBound(arena.allocator(), io, inst_dir, "zig-inject-test-no-global")));

	// Connect (the reconcile's bind). Now bound.
	try secret_store.add(gpa, io, inst_dir, secret_mod.claude_oauth_secret, "sk-ant-oat01-FAKEFAKEFAKEFAKEFAKE", .{
		.audience = secret_mod.anthropic_api_host,
		.kind = secret_mod.anthropic_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	});
	try std.testing.expect(try claudeOAuthBound(arena.allocator(), io, inst_dir, "zig-inject-test-no-global"));
}

test "gap #1: renderL7 terminate-allows api.anthropic.com ONLY when the seed is applied (bound)" {
	const gpa = std.testing.allocator;

	// UNBOUND -> the seed is NOT applied (main.zig gates seedClaudeInjectSpec on
	// claudeOAuthBound), so the container default network carries no claude spec and
	// renderL7 must NOT terminate-allow api.anthropic.com (the L4 deny-list governs).
	{
		const src =
			\\{"rules":[{"allow":"0.0.0.0/0","comment":"public"}]}
		;
		var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
		defer parsed.deinit();
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(gpa);
		try renderL7(gpa, parsed.value, &out);
		try std.testing.expect(std.mem.indexOf(u8, out.items, secret_mod.anthropic_api_host) == null);
	}

	// BOUND -> the seed IS applied; renderL7 then terminate-allows the host so the
	// injected Bearer can be stamped on a MITM-terminated flow.
	{
		const src =
			\\{"rules":[{"allow":"0.0.0.0/0","comment":"public"}]}
		;
		var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
		defer parsed.deinit();
		var net = parsed.value;
		try seedClaudeInjectSpec(parsed.arena.allocator(), &net);
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(gpa);
		try renderL7(gpa, net, &out);
		var allow_buf: [64]u8 = undefined;
		const allow_line = std.fmt.bufPrint(&allow_buf, "allow {s} terminate", .{secret_mod.anthropic_api_host}) catch unreachable;
		try std.testing.expect(std.mem.indexOf(u8, out.items, allow_line) != null);
	}
}

test "gap #2: seed is shadow-safe -- appends when a DIFFERENT secret already claims the host" {
	const gpa = std.testing.allocator;
	// A plugin spec already targets api.anthropic.com under a DIFFERENT secret name.
	// The old idempotency check (host-only) would have skipped, silently shadowing
	// the per-user bind. The guard must append the claude-oauth spec anyway.
	const src =
		\\{"l7":{"inject":{"specs":[
		\\  {"host":"api.anthropic.com","style":"bearer","secret":"plugin-anthropic","plugin":"obs-plugin"}]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	var net = parsed.value;

	try seedClaudeInjectSpec(parsed.arena.allocator(), &net);

	const specs = net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array;
	try std.testing.expectEqual(@as(usize, 2), specs.items.len);
	// the plugin spec is untouched (still first, still its own secret)
	try std.testing.expectEqualStrings("plugin-anthropic", specs.items[0].object.get("secret").?.string);
	// the per-user bind STILL renders: our claude-oauth spec was appended
	try std.testing.expectEqualStrings(secret_mod.claude_oauth_secret, specs.items[1].object.get("secret").?.string);
	try std.testing.expectEqualStrings(secret_mod.anthropic_api_host, specs.items[1].object.get("host").?.string);

	// True idempotency is preserved: re-seeding now that OUR secret names the host
	// adds nothing (only our own seed -- not a foreign spec -- suppresses a re-add).
	try seedClaudeInjectSpec(parsed.arena.allocator(), &net);
	const specs2 = net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array;
	try std.testing.expectEqual(@as(usize, 2), specs2.items.len);
}

test "renderL7 emits methods / exact (pathmode) / service tokens (git grant rule)" {
	const gpa = std.testing.allocator;
	const src =
		\\{"l7":{"mode":"terminate","rules":[
		\\  {"allow":"git.example.internal","methods":"POST","path":"/g/p.git/git-upload-pack","pathmode":"exact","plugin":"git-grants"},
		\\  {"allow":"git.example.internal","methods":"GET,POST","path":"/grp/","service":"git-upload-pack","plugin":"git-grants"},
		\\  {"allow":"cdn.example.internal","path":"/assets/"}
		\\]}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	try renderL7(gpa, parsed.value, &out);
	const s = out.items;
	// exact rule: methods, path, exact -- in that order; a git-grant rule now
	// ALSO carries the injection-gating `tag=git-grants` token (last).
	try std.testing.expect(std.mem.indexOf(u8, s, "allow git.example.internal POST /g/p.git/git-upload-pack exact tag=git-grants\n") != null);
	// prefix rule with a service constraint + comma method list, likewise tagged.
	try std.testing.expect(std.mem.indexOf(u8, s, "allow git.example.internal GET,POST /grp/ service=git-upload-pack tag=git-grants\n") != null);
	// a NON-git-grant rule (no plugin=="git-grants") renders UNTAGGED: it grants
	// plain reachability and must never make the owner's token inject-eligible.
	try std.testing.expect(std.mem.indexOf(u8, s, "allow cdn.example.internal /assets/ tag=") == null);
	// The rendered (tagged) lines round-trip through the zig proxy parser
	// unchanged -- proves the proxy tolerates `tag=` (parity guard).
	var rs: filter.L7RuleSet = undefined;
	filter.parseL7Rules(s, &rs);
	try std.testing.expectEqual(filter.L7Verdict.allow, rs.evaluateFull("git.example.internal", "/g/p.git/git-upload-pack", "POST"));
	try std.testing.expectEqual(filter.L7Verdict.deny, rs.evaluateFull("git.example.internal", "/grp/proj.git/git-receive-pack", "POST"));
}

test "renderL7Inject: kind=gitlab-oauth forces style + git_user + git stub, no refresh" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const inst_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(inst_dir);
	defer cwd.deleteTree(io, inst_dir) catch {};

	// Bind a per-user git access token the way cogworx's reconcile does: a
	// git-<provider> secret, kind=gitlab-oauth, audience pinned to the git host.
	// The VALUE is a fictional (OSS-clean) token.
	try secret_store.add(gpa, io, inst_dir, "git-gitlab", "glpat-FAKEFAKEFAKEFAKE", .{
		.audience = "git.example.internal",
		.kind = secret_mod.gitlab_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	});

	// The spec deliberately declares a DIFFERENT style: the kind must override it.
	const src =
		\\{"l7":{"mode":"terminate","inject":{"enabled":true,"specs":[
		\\  {"host":"git.example.internal","style":"bearer","secret":"git-gitlab"}]}}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();

	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(gpa);
	var hosts: std.ArrayList(u8) = .empty;
	defer hosts.deinit(gpa);
	try renderL7Inject(gpa, io, parsed.value, "zig-inject-test-no-global", inst_dir, &out, &hosts, null);
	const s = out.items;

	try std.testing.expect(std.mem.indexOf(u8, s, "\"style\": \"gitlab-oauth\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"cred_format\": \"raw\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"git_user\": \"oauth2\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, secret_mod.gitlab_stub_token) != null);
	// the gitlab-oauth spec carries the injection-gating rules_tag so the addon
	// injects only on a git-grant-tagged rule's allow.
	try std.testing.expect(std.mem.indexOf(u8, s, "\"rules_tag\": \"git-grants\"") != null);
	// the declared bearer style did NOT win
	try std.testing.expect(std.mem.indexOf(u8, s, "\"style\": \"bearer\"") == null);
	// a re-bind token is refreshed host-side by cogworx -> NO refresh block here
	try std.testing.expect(std.mem.indexOf(u8, s, "refresh") == null);
	// the host is mirrored into the plain-HTTP inject-routing list
	try std.testing.expect(std.mem.indexOf(u8, hosts.items, "git.example.internal") != null);
}

test "seedGitInjectSpecs: seeds gitlab-oauth secrets bound in the GLOBAL store only (the cogworx `secret bind` shape; host named by a grant rule), idempotent + shadow-safe, silent when unbound" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	// Cogworx's `cogbox secret bind` writes the enforcer's GLOBAL store; the
	// instance dir does not even exist on the enforcer. This test pins the
	// global-only path.
	const glob_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(glob_dir);
	defer cwd.deleteTree(io, glob_dir) catch {};
	const inst_dir = "zig-inject-test-no-instance";

	// Nothing bound yet -> the seed adds no spec.
	{
		const src = "{\"rules\":[{\"allow\":\"0.0.0.0/0\"}]}";
		var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
		defer parsed.deinit();
		var net = parsed.value;
		try seedGitInjectSpecs(parsed.arena.allocator(), io, &net, inst_dir, glob_dir);
		// No git secret bound -> no l7 object need be created with specs.
		if (net.object.getPtr("l7")) |l7| {
			if (l7.object.getPtr("inject")) |inj| {
				if (inj.object.getPtr("specs")) |sp| {
					try std.testing.expectEqual(@as(usize, 0), sp.array.items.len);
				}
			}
		}
	}

	// Bind a git secret (+ a non-git secret that must be ignored) -- GLOBAL only.
	try secret_store.add(gpa, io, glob_dir, "git-gitlab", "glpat-FAKE", .{
		.audience = "git.example.internal",
		.kind = secret_mod.gitlab_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	});
	try secret_store.add(gpa, io, glob_dir, "api-token", "tok", .{
		.audience = "api.example.com",
		.kind = "bearer",
		.tier = "durable",
		.bound_at = 1,
	});

	{
		// A grant rule NAMES the git host (the compiled-rules + bind pair cogworx
		// materializes together) -> the bound secret is seeded.
		const src =
			\\{"rules":[{"allow":"0.0.0.0/0"}],"l7":{"rules":[
			\\  {"allow":"git.example.internal","methods":"GET","path":"/grp/","service":"git-upload-pack","plugin":"git-grants"}]}}
		;
		var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
		defer parsed.deinit();
		var net = parsed.value;
		try seedGitInjectSpecs(parsed.arena.allocator(), io, &net, inst_dir, glob_dir);
		const specs = net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array;
		// Exactly one spec: the git secret (the bearer secret is not seeded).
		try std.testing.expectEqual(@as(usize, 1), specs.items.len);
		const s0 = specs.items[0].object;
		try std.testing.expectEqualStrings("git.example.internal", s0.get("host").?.string);
		try std.testing.expectEqualStrings(secret_mod.gitlab_oauth_kind, s0.get("style").?.string);
		try std.testing.expectEqualStrings("git-gitlab", s0.get("secret").?.string);
		try std.testing.expectEqualStrings("oauth2", s0.get("git_user").?.string);

		// The seeded spec drives BOTH inject outputs: the addon conf names the
		// host and the plain-HTTP routing list carries it.
		{
			var out: std.ArrayList(u8) = .empty;
			defer out.deinit(gpa);
			var hosts: std.ArrayList(u8) = .empty;
			defer hosts.deinit(gpa);
			try renderL7Inject(gpa, io, net, glob_dir, inst_dir, &out, &hosts, null);
			try std.testing.expect(std.mem.indexOf(u8, out.items, "git.example.internal") != null);
			try std.testing.expect(std.mem.indexOf(u8, hosts.items, "git.example.internal") != null);
		}

		// Idempotent: re-seeding adds nothing.
		try seedGitInjectSpecs(parsed.arena.allocator(), io, &net, inst_dir, glob_dir);
		try std.testing.expectEqual(@as(usize, 1), net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array.items.len);
	}

	// Shadow-safe: a foreign spec already targeting the git host under a DIFFERENT
	// secret name must NOT suppress the per-user seed.
	{
		const src =
			\\{"l7":{"rules":[
			\\  {"allow":"git.example.internal","methods":"GET","path":"/grp/","service":"git-upload-pack","plugin":"git-grants"}],
			\\ "inject":{"specs":[
			\\  {"host":"git.example.internal","style":"bearer","secret":"plugin-git","plugin":"obs-plugin"}]}}}
		;
		var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
		defer parsed.deinit();
		var net = parsed.value;
		try seedGitInjectSpecs(parsed.arena.allocator(), io, &net, inst_dir, glob_dir);
		const specs = net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array;
		try std.testing.expectEqual(@as(usize, 2), specs.items.len);
		try std.testing.expectEqualStrings("plugin-git", specs.items[0].object.get("secret").?.string);
		try std.testing.expectEqualStrings("git-gitlab", specs.items[1].object.get("secret").?.string);
	}
}

test "seedGitInjectSpecs: unions both stores; an instance secret shadows a global one of the same name (single spec, instance audience wins)" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const glob_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(glob_dir);
	defer cwd.deleteTree(io, glob_dir) catch {};
	const inst_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(inst_dir);
	defer cwd.deleteTree(io, inst_dir) catch {};

	// Same name in BOTH stores with different audiences: the instance bind must
	// win (resolveSecret precedence) and the name must be seeded exactly once.
	try secret_store.add(gpa, io, glob_dir, "git-gitlab", "glpat-FAKE-GLOBAL", .{
		.audience = "git.example.com",
		.kind = secret_mod.gitlab_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	});
	try secret_store.add(gpa, io, inst_dir, "git-gitlab", "glpat-FAKE-INSTANCE", .{
		.audience = "git.example.internal",
		.kind = secret_mod.gitlab_oauth_kind,
		.tier = "durable",
		.bound_at = 2,
	});
	// And an instance-ONLY bind: the union must pick it up too.
	try secret_store.add(gpa, io, inst_dir, "git-other", "glpat-FAKE-OTHER", .{
		.audience = "git-alt.example.internal",
		.kind = secret_mod.gitlab_oauth_kind,
		.tier = "durable",
		.bound_at = 3,
	});

	// Grant rules name ALL the candidate hosts so only precedence decides.
	const src =
		\\{"l7":{"rules":[
		\\  {"allow":"git.example.com","methods":"GET","path":"/grp/","service":"git-upload-pack","plugin":"git-grants"},
		\\  {"allow":"git.example.internal","methods":"GET","path":"/grp/","service":"git-upload-pack","plugin":"git-grants"},
		\\  {"allow":"git-alt.example.internal","methods":"GET","path":"/grp/","service":"git-upload-pack","plugin":"git-grants"}]}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	var net = parsed.value;
	try seedGitInjectSpecs(parsed.arena.allocator(), io, &net, inst_dir, glob_dir);
	const specs = net.object.getPtr("l7").?.object.getPtr("inject").?.object.getPtr("specs").?.array;
	try std.testing.expectEqual(@as(usize, 2), specs.items.len);
	// git-gitlab resolved through the INSTANCE store: its audience, not the
	// global one, and no duplicate for the global entry.
	var saw_gitlab = false;
	var saw_other = false;
	for (specs.items) |s| {
		const name = s.object.get("secret").?.string;
		const host = s.object.get("host").?.string;
		if (std.mem.eql(u8, name, "git-gitlab")) {
			try std.testing.expectEqualStrings("git.example.internal", host);
			saw_gitlab = true;
		} else if (std.mem.eql(u8, name, "git-other")) {
			try std.testing.expectEqualStrings("git-alt.example.internal", host);
			saw_other = true;
		}
	}
	try std.testing.expect(saw_gitlab);
	try std.testing.expect(saw_other);
}

test "seedGitInjectSpecs fails closed: GLOBAL-bound gitlab-oauth + NO rule naming the host => no spec, no allow, no inject entry; anthropic-oauth unchanged" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	// Global store (the cogworx bind target), no instance dir -- the gate must
	// hold on the production path too, not just for instance-bound secrets.
	const glob_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(glob_dir);
	defer cwd.deleteTree(io, glob_dir) catch {};
	const inst_dir = "zig-inject-test-no-instance";

	// The exploit precondition a racy control plane can produce: the token still
	// BOUND while the grant rules are already cleared (or never named the host).
	try secret_store.add(gpa, io, glob_dir, "git-gitlab", "glpat-FAKE", .{
		.audience = "git.example.internal",
		.kind = secret_mod.gitlab_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	});

	// L7 rules exist but none names the git host -> the seed must SKIP: no spec,
	// so renderL7 never unions a whole-host `allow <host> terminate` and
	// renderL7Inject emits no conf entry / routed host. Worst case is 403s until
	// the next render re-seeds against a correct rule set.
	const src =
		\\{"l7":{"mode":"terminate","rules":[{"allow":"api.example.com"}]}}
	;
	var parsed = try std.json.parseFromSlice(std.json.Value, gpa, src, .{});
	defer parsed.deinit();
	var net = parsed.value;
	try seedGitInjectSpecs(parsed.arena.allocator(), io, &net, inst_dir, glob_dir);

	// No spec was seeded for the git host.
	if (net.object.getPtr("l7").?.object.getPtr("inject")) |inj| {
		if (inj.object.getPtr("specs")) |sp| {
			try std.testing.expectEqual(@as(usize, 0), sp.array.items.len);
		}
	}

	// The rendered l7-rules carry NO allow line for the git host.
	{
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(gpa);
		try renderL7(gpa, net, &out);
		try std.testing.expect(std.mem.indexOf(u8, out.items, "git.example.internal") == null);
	}

	// The inject conf + routed-host list carry NO entry for it either.
	{
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(gpa);
		var hosts: std.ArrayList(u8) = .empty;
		defer hosts.deinit(gpa);
		try renderL7Inject(gpa, io, net, glob_dir, inst_dir, &out, &hosts, null);
		try std.testing.expect(std.mem.indexOf(u8, out.items, "git.example.internal") == null);
		try std.testing.expect(std.mem.indexOf(u8, hosts.items, "git.example.internal") == null);
	}

	// CONTRAST (must stay EXACTLY as today): a bound anthropic-oauth secret with
	// zero rules naming its host still gets its whole-host terminate-allow — the
	// gate above is gitlab-oauth-only. (Bound global, like a cogworx bind.)
	try secret_store.add(gpa, io, glob_dir, secret_mod.claude_oauth_secret, "sk-ant-oat01-FAKEFAKEFAKEFAKEFAKE", .{
		.audience = secret_mod.anthropic_api_host,
		.kind = secret_mod.anthropic_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	});
	try seedClaudeInjectSpec(parsed.arena.allocator(), &net);
	{
		var out: std.ArrayList(u8) = .empty;
		defer out.deinit(gpa);
		try renderL7(gpa, net, &out);
		var allow_buf: [64]u8 = undefined;
		const allow_line = std.fmt.bufPrint(&allow_buf, "allow {s} terminate", .{secret_mod.anthropic_api_host}) catch unreachable;
		try std.testing.expect(std.mem.indexOf(u8, out.items, allow_line) != null);
		// and still nothing for the git host
		try std.testing.expect(std.mem.indexOf(u8, out.items, "git.example.internal") == null);
	}
}

// --- renderAuthProxyConf (the per-sandbox auth proxy's policy render) --------

// A rules-mode network fixture for the auth-proxy render: the funnel rule
// (naming the host, optionally insecure) and a version-`ver` authpolicy doc
// whose one provider entry claims `doc_host`. Caller deinits.
fn authNetFixture(
	gpa: std.mem.Allocator,
	rule_host: []const u8,
	insecure: bool,
	ver: []const u8,
	doc_host: []const u8,
) !std.json.Parsed(std.json.Value) {
	return authNetFixtureGrants(gpa, rule_host, insecure, ver, doc_host,
		"[{\"id\":\"gg-1\",\"scope\":\"project\",\"repo\":\"grp/proj\"," ++
			"\"project_id\":\"1234\",\"caps\":[\"git-read\",\"issues\"]}]");
}

/// authNetFixture with a caller-supplied `grants[]` payload: the v2 arm needs
/// fine caps and a `push` object to show they ride into the conf VERBATIM (the
/// render never interprets the grant vocabulary -- that is the plugin's job).
fn authNetFixtureGrants(
	gpa: std.mem.Allocator,
	rule_host: []const u8,
	insecure: bool,
	ver: []const u8,
	doc_host: []const u8,
	grants_json: []const u8,
) !std.json.Parsed(std.json.Value) {
	var src: std.ArrayList(u8) = .empty;
	defer src.deinit(gpa);
	try src.appendSlice(gpa, "{\"l7\":{\"mode\":\"terminate\",\"rules\":[{\"allow\":\"");
	try src.appendSlice(gpa, rule_host);
	try src.appendSlice(gpa, "\",\"path\":\"/\",\"plugin\":\"git-grants\"");
	if (insecure) try src.appendSlice(gpa, ",\"insecure_upstream\":true");
	try src.appendSlice(gpa, "}],\"authpolicy\":{\"version\":");
	try src.appendSlice(gpa, ver);
	try src.appendSlice(gpa, ",\"providers\":[{\"provider\":\"GitLab\",\"plugin\":\"gitlab\",\"hosts\":[\"");
	try src.appendSlice(gpa, doc_host);
	try src.appendSlice(gpa, "\"],\"secret\":\"git-gitlab\",\"git_user\":\"oauth2\",\"scheme\":\"https\",\"grants\":");
	try src.appendSlice(gpa, grants_json);
	try src.appendSlice(gpa, "}]}}}");
	return std.json.parseFromSlice(std.json.Value, gpa, src.items, .{});
}

const AuthRender = struct {
	out: std.ArrayList(u8) = .empty,
	auth_hosts: std.ArrayList(u8) = .empty,
	inject_hosts: std.ArrayList(u8) = .empty,

	fn deinit(self: *AuthRender, gpa: std.mem.Allocator) void {
		self.out.deinit(gpa);
		self.auth_hosts.deinit(gpa);
		self.inject_hosts.deinit(gpa);
	}
};

fn runAuthRender(gpa: std.mem.Allocator, io: std.Io, net: std.json.Value, glob: []const u8, inst: []const u8, r: *AuthRender) !void {
	try renderAuthProxyConf(gpa, io, net, glob, inst, &r.out, &r.auth_hosts, &r.inject_hosts, null);
}

test "renderAuthProxyConf: all three gates hold -> one element with the doc's fields, both hosts files fed" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const glob_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(glob_dir);
	defer cwd.deleteTree(io, glob_dir) catch {};

	// The cogworx bind shape: global store, the NEW kind, audience = the host.
	try secret_store.add(gpa, io, glob_dir, "git-gitlab", "glpat-FAKE", .{
		.audience = "git.example.com",
		.kind = secret_mod.gitlab_authproxy_kind,
		.tier = "durable",
		.bound_at = 1,
	});

	var parsed = try authNetFixture(gpa, "git.example.com", false, "1", "git.example.com");
	defer parsed.deinit();

	var r: AuthRender = .{};
	defer r.deinit(gpa);
	try runAuthRender(gpa, io, parsed.value, glob_dir, "zig-inject-test-no-instance", &r);
	const s = r.out.items;

	// The element carries exactly the contract fields, sourced from the DOC
	// (plugin/scheme/git_user/grants) and the STORE (cred_file), never a mix.
	try std.testing.expect(std.mem.indexOf(u8, s, "\"host\": \"git.example.com\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"plugin\": \"gitlab\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"scheme\": \"https\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"insecure\": false") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"cred_format\": \"raw\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"git_user\": \"oauth2\"") != null);
	// grants[] verbatim from the doc.
	try std.testing.expect(std.mem.indexOf(u8, s, "\"id\": \"gg-1\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"git-read\"") != null);
	// the conf is a version-1 document its reader can gate on
	try std.testing.expect(std.mem.indexOf(u8, s, "\"version\": 1") != null);
	// the retarget set carries exactly the emitted host...
	try std.testing.expectEqualStrings("git.example.com\n", r.auth_hosts.items);
	// ...and finding N1: the host is ALSO routed for plain HTTP.
	try std.testing.expectEqualStrings("git.example.com\n", r.inject_hosts.items);
}

test "renderAuthProxyConf: each gate failing ALONE yields no element" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const glob_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(glob_dir);
	defer cwd.deleteTree(io, glob_dir) catch {};
	const inst_dir = "zig-inject-test-no-instance";

	// GATE 1 (kind): a bound gitlab-OAUTH secret must not render an auth
	// element even with the doc and the rule in place -- the legacy kind stays
	// the addon's, the new kind stays the auth proxy's, never both.
	try secret_store.add(gpa, io, glob_dir, "git-gitlab", "glpat-FAKE", .{
		.audience = "git.example.com",
		.kind = secret_mod.gitlab_oauth_kind,
		.tier = "durable",
		.bound_at = 1,
	});
	{
		var parsed = try authNetFixture(gpa, "git.example.com", false, "1", "git.example.com");
		defer parsed.deinit();
		var r: AuthRender = .{};
		defer r.deinit(gpa);
		try runAuthRender(gpa, io, parsed.value, glob_dir, inst_dir, &r);
		try std.testing.expect(std.mem.indexOf(u8, r.out.items, "git.example.com") == null);
		try std.testing.expectEqualStrings("", r.auth_hosts.items);
		try std.testing.expectEqualStrings("", r.inject_hosts.items);
	}

	// Re-bind under the NEW kind for the remaining gates.
	try secret_store.add(gpa, io, glob_dir, "git-gitlab", "glpat-FAKE", .{
		.audience = "git.example.com",
		.kind = secret_mod.gitlab_authproxy_kind,
		.tier = "durable",
		.bound_at = 2,
	});

	// GATE 2 (doc): no provider entry claims the audience -> nothing. This is
	// what keeps a bound token inert when the doc leg failed or was withdrawn
	// (the empty share-suspension document).
	{
		var parsed = try authNetFixture(gpa, "git.example.com", false, "1", "git-other.example.com");
		defer parsed.deinit();
		var r: AuthRender = .{};
		defer r.deinit(gpa);
		try runAuthRender(gpa, io, parsed.value, glob_dir, inst_dir, &r);
		try std.testing.expect(std.mem.indexOf(u8, r.out.items, "git.example.com") == null);
		try std.testing.expectEqualStrings("", r.auth_hosts.items);
	}

	// GATE 2, version arm: an unknown doc version is DEAD TEXT, not live
	// policy (a rolled-back binary or a hand-edited config must fail closed).
	// 3 is the next unlanded schema version; 1 and 2 are both live below.
	{
		var parsed = try authNetFixture(gpa, "git.example.com", false, "3", "git.example.com");
		defer parsed.deinit();
		var r: AuthRender = .{};
		defer r.deinit(gpa);
		try runAuthRender(gpa, io, parsed.value, glob_dir, inst_dir, &r);
		try std.testing.expect(std.mem.indexOf(u8, r.out.items, "git.example.com") == null);
	}

	// GATE 3 (rule): the doc claims the host but NO rule names it (the window
	// before the funnel lands, or a control plane that withdrew the rules but
	// left the bind) -> the doc is dead text; nothing is emitted and nothing
	// is routed. (A mode flip-back is gate 1's case above: its legacy rules
	// DO name the host, and the legacy-kind re-bind is what fails.)
	{
		var parsed = try authNetFixture(gpa, "api.example.com", false, "1", "git.example.com");
		defer parsed.deinit();
		var r: AuthRender = .{};
		defer r.deinit(gpa);
		try runAuthRender(gpa, io, parsed.value, glob_dir, inst_dir, &r);
		try std.testing.expect(std.mem.indexOf(u8, r.out.items, "git.example.com") == null);
		try std.testing.expectEqualStrings("", r.auth_hosts.items);
		try std.testing.expectEqualStrings("", r.inject_hosts.items);
	}
}

test "renderAuthProxyConf: a VERSION-2 document renders, fine caps and push rules riding the grants[] verbatim; push rules raise the CONF version" {
	// The two version numbers are independent: the DOCUMENT schema is 2 (fine
	// caps + push rules), and the CONF version is decided by what its READER
	// must understand -- here 2, because a grant carries `push` and a pre-v2
	// reader would silently drop that object and relay every ref (the render
	// and the reader ship in independently-rolled images). The render still
	// does not learn the grant vocabulary: it copies grants[] across, and the
	// plugin's `compile` fails closed on anything it does not understand.
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const glob_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(glob_dir);
	defer cwd.deleteTree(io, glob_dir) catch {};

	try secret_store.add(gpa, io, glob_dir, "git-gitlab", "glpat-FAKE", .{
		.audience = "git.example.com",
		.kind = secret_mod.gitlab_authproxy_kind,
		.tier = "durable",
		.bound_at = 1,
	});

	var parsed = try authNetFixtureGrants(gpa, "git.example.com", false, "2", "git.example.com",
		"[{\"id\":\"gg-2\",\"scope\":\"project\",\"repo\":\"grp/proj\",\"project_id\":\"1234\"," ++
			"\"caps\":[\"git-read\",\"git-write\",\"mr:read\",\"mr:merge\",\"wiki:write\"]," ++
			"\"push\":{\"deny_delete\":true,\"deny_tags\":true,\"refs\":[\"refs/heads/agent/*\"]}}]");
	defer parsed.deinit();

	var r: AuthRender = .{};
	defer r.deinit(gpa);
	try runAuthRender(gpa, io, parsed.value, glob_dir, "zig-inject-test-no-instance", &r);
	const s = r.out.items;
	try std.testing.expect(std.mem.indexOf(u8, s, "\"host\": \"git.example.com\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"version\": 2") != null); // the CONF version, raised by `push`
	try std.testing.expect(std.mem.indexOf(u8, s, "\"mr:merge\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"wiki:write\"") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"deny_delete\": true") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"refs/heads/agent/*\"") != null);
	try std.testing.expectEqualStrings("git.example.com\n", r.auth_hosts.items);
}

test "renderAuthProxyConf: a version-2 document WITHOUT push rules leaves the conf at version 1" {
	// The other half of the version-bump contract: fine cap NAMES alone do not
	// move the conf version, because an old reader's `compile` refuses an
	// unknown cap and fails the whole conf by itself. Only a droppable object
	// (`push`) needs the file-level lever -- so every fine-caps-only sandbox
	// keeps the byte-identical version-1 conf an old enforcer still reads.
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const glob_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(glob_dir);
	defer cwd.deleteTree(io, glob_dir) catch {};

	try secret_store.add(gpa, io, glob_dir, "git-gitlab", "glpat-FAKE", .{
		.audience = "git.example.com",
		.kind = secret_mod.gitlab_authproxy_kind,
		.tier = "durable",
		.bound_at = 1,
	});

	var parsed = try authNetFixtureGrants(gpa, "git.example.com", false, "2", "git.example.com",
		"[{\"id\":\"gg-3\",\"scope\":\"project\",\"repo\":\"grp/proj\",\"project_id\":\"1234\"," ++
			"\"caps\":[\"git-read\",\"pipelines:read\"]}]");
	defer parsed.deinit();

	var r: AuthRender = .{};
	defer r.deinit(gpa);
	try runAuthRender(gpa, io, parsed.value, glob_dir, "zig-inject-test-no-instance", &r);
	const s = r.out.items;
	try std.testing.expect(std.mem.indexOf(u8, s, "\"version\": 1") != null);
	try std.testing.expect(std.mem.indexOf(u8, s, "\"pipelines:read\"") != null);
}

test "renderAuthProxyConf: insecure is single-sourced from the rule scan (finding N2)" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const glob_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(glob_dir);
	defer cwd.deleteTree(io, glob_dir) catch {};

	try secret_store.add(gpa, io, glob_dir, "git-gitlab", "glpat-FAKE", .{
		.audience = "git.example.com",
		.kind = secret_mod.gitlab_authproxy_kind,
		.tier = "durable",
		.bound_at = 1,
	});

	// The funnel rule carries insecure_upstream -> the conf element must carry
	// insecure:true, or the flag silently stops applying the moment the
	// upstream TLS leg moves from mitmproxy to the auth proxy.
	var parsed = try authNetFixture(gpa, "git.example.com", true, "1", "git.example.com");
	defer parsed.deinit();
	var r: AuthRender = .{};
	defer r.deinit(gpa);
	try runAuthRender(gpa, io, parsed.value, glob_dir, "zig-inject-test-no-instance", &r);
	try std.testing.expect(std.mem.indexOf(u8, r.out.items, "\"insecure\": true") != null);
}

test "renderAuthProxyConf: the N1 inject-hosts append dedupes against spec-emitted hosts" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const glob_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(glob_dir);
	defer cwd.deleteTree(io, glob_dir) catch {};

	try secret_store.add(gpa, io, glob_dir, "git-gitlab", "glpat-FAKE", .{
		.audience = "git.example.com",
		.kind = secret_mod.gitlab_authproxy_kind,
		.tier = "durable",
		.bound_at = 1,
	});

	var parsed = try authNetFixture(gpa, "git.example.com", false, "1", "git.example.com");
	defer parsed.deinit();

	// The inject-hosts buffer already names the host (an inject spec emitted
	// it in the same pass) -> no duplicate line.
	var r: AuthRender = .{};
	defer r.deinit(gpa);
	try r.inject_hosts.appendSlice(gpa, "git.example.com\n");
	try runAuthRender(gpa, io, parsed.value, glob_dir, "zig-inject-test-no-instance", &r);
	try std.testing.expectEqualStrings("git.example.com\n", r.inject_hosts.items);
	// the auth conf and retarget set are unaffected by the dedupe
	try std.testing.expect(std.mem.indexOf(u8, r.out.items, "\"host\": \"git.example.com\"") != null);
	try std.testing.expectEqualStrings("git.example.com\n", r.auth_hosts.items);
}

test "writeL7Inject: the wire-file write order is pinned -- each conf before its hosts file, l7-auth-hosts LAST" {
	// The order is data (l7_inject_write_order) and writeL7Inject iterates it,
	// so asserting the list IS asserting the sequence. Conf-before-hosts for
	// both consumers; the retarget set last of all.
	try std.testing.expectEqual(@as(usize, 4), l7_inject_write_order.len);
	try std.testing.expectEqualStrings("l7-inject-conf.json", l7_inject_write_order[0]);
	try std.testing.expectEqualStrings("l7-auth-conf.json", l7_inject_write_order[1]);
	try std.testing.expectEqualStrings("l7-inject-hosts", l7_inject_write_order[2]);
	try std.testing.expectEqualStrings("l7-auth-hosts", l7_inject_write_order[3]);
}

test "writeL7Inject: one pass writes all four wire files; empty auth state renders a valid empty conf" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const glob_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(glob_dir);
	defer cwd.deleteTree(io, glob_dir) catch {};
	const rt_dir = try tmpStoreDir(gpa, io);
	defer gpa.free(rt_dir);
	defer cwd.deleteTree(io, rt_dir) catch {};

	const readFile = struct {
		fn f(a: std.mem.Allocator, io_: std.Io, dir: []const u8, name: []const u8) ![]u8 {
			const p = try std.fs.path.join(a, &.{ dir, name });
			defer a.free(p);
			const file = try std.Io.Dir.cwd().openFile(io_, p, .{});
			defer file.close(io_);
			var buf: [512]u8 = undefined;
			var rd = file.reader(io_, &buf);
			return rd.interface.allocRemaining(a, .limited(1 << 16));
		}
	}.f;

	// NOTHING bound: the auth conf must still be a VALID empty version-1
	// document (not an empty file), so the auth proxy's reader caches it
	// cleanly instead of re-parsing a refusal every poll; the retarget set is
	// empty, so the addon touches nothing.
	{
		var parsed = try std.json.parseFromSlice(std.json.Value, gpa, "{\"l7\":{\"mode\":\"terminate\",\"rules\":[]}}", .{});
		defer parsed.deinit();
		try writeL7Inject(gpa, io, rt_dir, parsed.value, glob_dir, "zig-inject-test-no-instance", null);
		const conf = try readFile(gpa, io, rt_dir, "l7-auth-conf.json");
		defer gpa.free(conf);
		try std.testing.expect(std.mem.indexOf(u8, conf, "\"version\": 1") != null);
		try std.testing.expect(std.mem.indexOf(u8, conf, "\"providers\": []") != null);
		const ah = try readFile(gpa, io, rt_dir, "l7-auth-hosts");
		defer gpa.free(ah);
		try std.testing.expectEqualStrings("", ah);
	}

	// Bound + doc + rule: every file carries its half, from ONE pass.
	try secret_store.add(gpa, io, glob_dir, "git-gitlab", "glpat-FAKE", .{
		.audience = "git.example.com",
		.kind = secret_mod.gitlab_authproxy_kind,
		.tier = "durable",
		.bound_at = 1,
	});
	{
		var parsed = try authNetFixture(gpa, "git.example.com", false, "1", "git.example.com");
		defer parsed.deinit();
		try writeL7Inject(gpa, io, rt_dir, parsed.value, glob_dir, "zig-inject-test-no-instance", null);
		const conf = try readFile(gpa, io, rt_dir, "l7-auth-conf.json");
		defer gpa.free(conf);
		try std.testing.expect(std.mem.indexOf(u8, conf, "\"host\": \"git.example.com\"") != null);
		const ah = try readFile(gpa, io, rt_dir, "l7-auth-hosts");
		defer gpa.free(ah);
		try std.testing.expectEqualStrings("git.example.com\n", ah);
		// finding N1: the plain-HTTP routing list carries the auth host even
		// though no inject SPEC names it (the new kind seeds none).
		const ih = try readFile(gpa, io, rt_dir, "l7-inject-hosts");
		defer gpa.free(ih);
		try std.testing.expect(std.mem.indexOf(u8, ih, "git.example.com") != null);
		// and the addon's own conf exists (empty: no inject spec was seeded).
		const ic = try readFile(gpa, io, rt_dir, "l7-inject-conf.json");
		defer gpa.free(ic);
		try std.testing.expect(std.mem.indexOf(u8, ic, "git.example.com") == null);
	}
}
