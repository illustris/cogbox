// Tests for rollback.zig: the restores of a rolled-back add, update and del,
// the per-name policy rule, idempotence after a crash at each step, the
// fail-closed tier, intents, records and --abandon-rollback. Every fixture is
// an instance config dir under the cwd, laid out as the plugin verb lays it
// out; no nix and no child process runs.

const std = @import("std");
const plugin = @import("main.zig");
const rollback = @import("rollback.zig");
const snapshot = @import("snapshot.zig");
const t = std.testing;

const flake_source = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-cogbox-source";
const current_key = flake_source ++ "#cogbox";
const old_key = "/nix/store/oooooooooooooooooooooooooooooooo-cogbox-source#cogbox";
const runner_b = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-microvm-run";
const runner_k = "/nix/store/kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk-microvm-run";
const gen1 = "1111111111111111";
const gen2 = "2222222222222222";
const gen3 = "3333333333333333";

const Fx = struct {
	arena_state: std.heap.ArenaAllocator,
	io: std.Io,
	root: []const u8,
	icd: []const u8,
	runtime: []const u8,
	env: std.process.Environ.Map,

	fn init(io: std.Io, tag: []const u8) !Fx {
		var arena_state = std.heap.ArenaAllocator.init(t.allocator);
		errdefer arena_state.deinit();
		const a = arena_state.allocator();
		var rnd: [8]u8 = undefined;
		io.random(&rnd);
		const rel = try std.fmt.allocPrint(a, "zig-rollback-test-{s}-{x}", .{ tag, &rnd });
		const cwd = std.Io.Dir.cwd();
		try cwd.createDirPath(io, rel);
		const root = try cwd.realPathFileAlloc(io, rel, a);
		const icd = try std.fmt.allocPrint(a, "{s}/icd", .{root});
		const runtime = try std.fmt.allocPrint(a, "{s}/run", .{root});
		try cwd.createDirPath(io, icd);
		try cwd.createDirPath(io, runtime);
		var env = std.process.Environ.Map.init(t.allocator);
		try env.put("COGBOX_FLAKE_SOURCE", flake_source);
		return .{ .arena_state = arena_state, .io = io, .root = root, .icd = icd, .runtime = runtime, .env = env };
	}

	fn deinit(fx: *Fx) void {
		// Give a planted read-only runtime dir its write bit back for teardown.
		std.Io.Dir.cwd().setFilePermissions(fx.io, fx.runtime, .fromMode(0o755), .{}) catch {};
		std.Io.Dir.cwd().deleteTree(fx.io, fx.root) catch {};
		fx.env.deinit();
		fx.arena_state.deinit();
	}

	fn mem(fx: *Fx) std.mem.Allocator {
		return fx.arena_state.allocator();
	}

	fn path(fx: *Fx, rel: []const u8) []const u8 {
		return std.fmt.allocPrint(fx.mem(), "{s}/{s}", .{ fx.icd, rel }) catch @panic("oom");
	}

	fn ctx(fx: *Fx) plugin.Ctx {
		return .{
			.allocator = t.allocator,
			.io = fx.io,
			.parent_env = &fx.env,
			.instance = "web",
			.config_path = fx.path("config.json"),
			.runtime_path = fx.runtime,
			.user_flake_dir = fx.path("flake"),
			.plugins_flake_dir = fx.path("plugins-flake"),
			.sources_dir = fx.path("plugin-sources"),
			.cache_dir = fx.path("plugin-cache"),
		};
	}

	/// Write `rel` as a new file (a new inode, as every cogbox writer does).
	fn write(fx: *Fx, rel: []const u8, bytes: []const u8) !void {
		const p = fx.path(rel);
		const cwd = std.Io.Dir.cwd();
		if (std.fs.path.dirname(p)) |d| try cwd.createDirPath(fx.io, d);
		cwd.deleteFile(fx.io, p) catch {};
		const f = try cwd.createFile(fx.io, p, .{});
		defer f.close(fx.io);
		var buf: [512]u8 = undefined;
		var w = f.writer(fx.io, &buf);
		try w.interface.writeAll(bytes);
		try w.flush();
	}

	fn read(fx: *Fx, rel: []const u8) ?[]u8 {
		return std.Io.Dir.cwd().readFileAlloc(fx.io, fx.path(rel), fx.mem(), .limited(1 << 20)) catch null;
	}

	fn has(fx: *Fx, rel: []const u8) bool {
		std.Io.Dir.cwd().access(fx.io, fx.path(rel), .{}) catch return false;
		return true;
	}

	fn remove(fx: *Fx, rel: []const u8) void {
		std.Io.Dir.cwd().deleteTree(fx.io, fx.path(rel)) catch {};
	}

	/// plugin-sources/<name> at `version`, replaced wholesale as
	/// materializeSource does (new inodes; a snapshot's links keep the old).
	fn source(fx: *Fx, name: []const u8, version: []const u8) !void {
		fx.remove(std.fmt.allocPrint(fx.mem(), "plugin-sources/{s}", .{name}) catch unreachable);
		try fx.write(std.fmt.allocPrint(fx.mem(), "plugin-sources/{s}/flake.nix", .{name}) catch unreachable, std.fmt.allocPrint(fx.mem(), "{s} {s}\n", .{ name, version }) catch unreachable);
		try fx.write(std.fmt.allocPrint(fx.mem(), "plugin-sources/{s}/sub/a.txt", .{name}) catch unreachable, version);
	}

	fn sourceOf(fx: *Fx, name: []const u8) ?[]u8 {
		return fx.read(std.fmt.allocPrint(fx.mem(), "plugin-sources/{s}/sub/a.txt", .{name}) catch unreachable);
	}

	fn composition(fx: *Fx, nix: ?[]const u8, lock: ?[]const u8) !void {
		fx.remove("plugins-flake/flake.nix");
		fx.remove("plugins-flake/flake.lock");
		if (nix) |n| try fx.write("plugins-flake/flake.nix", n);
		if (lock) |l| try fx.write("plugins-flake/flake.lock", l);
	}

	fn config(fx: *Fx) !std.json.Value {
		const bytes = fx.read("config.json") orelse return error.FileNotFound;
		return std.json.parseFromSliceLeaky(std.json.Value, fx.mem(), bytes, .{});
	}

	fn take(fx: *Fx) !snapshot.Id {
		return snapshot.take(fx.mem(), fx.io, fx.icd, try fx.config(), .{});
	}

	fn snap(fx: *Fx, id: []const u8) !snapshot.Snapshot {
		return snapshot.read(fx.mem(), fx.io, fx.icd, id);
	}

	/// The intent a live verb writes for `gen`: the scope from S to the target.
	fn intent(fx: *Fx, gen: []const u8, reason: rollback.Reason, target: rollback.Target, target_id: []const u8, s_id: []const u8) !void {
		const s = try fx.snap(s_id);
		const z = try fx.snap(target_id);
		const sc = try snapshot.scope(fx.mem(), s.plugins, z.plugins);
		const r = try rollback.writeIntent(t.allocator, fx.io, fx.icd, .{ .G = gen, .op = "7", .reason = reason, .target = target, .target_id = target_id, .scope = sc }, .{});
		try t.expectEqual(rollback.WriteIntentResult.written, r);
	}

	fn finish(fx: *Fx, opts: rollback.FinishOptions) rollback.FinishResult {
		var c = fx.ctx();
		return rollback.finishPending(fx.mem(), &c, opts);
	}

	fn records(fx: *Fx) !rollback.Records {
		return rollback.readRecords(fx.mem(), fx.io, fx.icd);
	}

	/// The rules array at `.network.<l4|l7|inject>` of the current config.
	fn list(fx: *Fx, comptime which: enum { l4, l7, inject }) ![]const std.json.Value {
		const net = (try fx.config()).object.get("network").?;
		return switch (which) {
			.l4 => net.object.get("rules").?.array.items,
			.l7 => net.object.get("l7").?.object.get("rules").?.array.items,
			.inject => net.object.get("l7").?.object.get("inject").?.object.get("specs").?.array.items,
		};
	}
};

fn finished(r: rollback.FinishResult) !rollback.Finished {
	try t.expectEqual(@as(usize, 1), r.outcomes.len);
	try t.expectEqual(@as(usize, 0), r.pending);
	return switch (r.outcomes[0].result) {
		.finished => |f| f,
		else => error.TestUnexpectedResult,
	};
}

/// `"<action> <value>"` for each rule (L4, L7) or `host[:port] secret` for each
/// injection, with `+approved` when marked: a compact view of a list's order.
fn view(a: std.mem.Allocator, items: []const std.json.Value) ![]const u8 {
	var out: std.ArrayList(u8) = .empty;
	for (items, 0..) |v, i| {
		if (i > 0) try out.appendSlice(a, ", ");
		const o = v.object;
		if (o.get("allow")) |x| try out.print(a, "allow {s}", .{x.string});
		if (o.get("deny")) |x| try out.print(a, "deny {s}", .{x.string});
		if (o.get("host")) |x| {
			try out.print(a, "{s}", .{x.string});
			if (o.get("port")) |p| try out.print(a, ":{d}", .{p.integer});
			if (o.get("cookieName")) |cn| try out.print(a, " cookie={s}", .{cn.string});
		}
		if (o.get("plugin")) |x| try out.print(a, " [{s}]", .{x.string});
		if (o.get("approved")) |x| if (x == .bool and x.bool) try out.appendSlice(a, " +approved");
	}
	return out.items;
}

fn lockOf(a: std.mem.Allocator, inputs: []const [2][]const u8) ![]const u8 {
	var out: std.ArrayList(u8) = .empty;
	try out.appendSlice(a, "{\"nodes\": {\"root\": {\"inputs\": {\"user\": \"user\"");
	for (inputs) |in| try out.print(a, ", \"p-{s}\": \"p-{s}\"", .{ in[0], in[0] });
	try out.appendSlice(a, "}}, \"user\": {\"locked\": {\"narHash\": \"sha256-user\", \"type\": \"path\"}, \"original\": {\"type\": \"path\"}}");
	for (inputs) |in| try out.print(a, ", \"p-{s}\": {{\"locked\": {{\"narHash\": \"{s}\", \"type\": \"path\"}}, \"original\": {{\"type\": \"path\"}}}}", .{ in[0], in[1] });
	try out.appendSlice(a, "}, \"root\": \"root\", \"version\": 7}\n");
	return out.items;
}

// --- the update scenario ---------------------------------------------------------
//
// B (the boot snapshot): obs-plugin at v1 and other-plugin, each with tagged
// policy. Then `plugin update obs-plugin` (non-deferred) to v2, and an admin
// approval (`rules add allow 192.0.2.0/24 --plugin obs-plugin`) during the
// apply; S is taken. The change is rejected live.

const entry_v1 = "{\"name\": \"obs-plugin\", \"url\": \"git+https://git.example.com/acme/obs-plugin\", \"lockedUrl\": \"git+https://git.example.com/acme/obs-plugin?rev=1111\", \"rev\": \"1111\", \"narHash\": \"sha256-v1\"}";
const entry_v2 = "{\"name\": \"obs-plugin\", \"url\": \"git+https://git.example.com/acme/obs-plugin\", \"lockedUrl\": \"git+https://git.example.com/acme/obs-plugin?rev=2222\", \"rev\": \"2222\", \"narHash\": \"sha256-v2\"}";
const entry_other = "{\"name\": \"other-plugin\", \"url\": \"path:/src/other-plugin\", \"lockedUrl\": \"path:/src/other-plugin?narHash=sha256-o1\", \"narHash\": \"sha256-o1\"}";

const config_b =
	\\{"network": {
	\\  "rules": [
	\\    {"allow": "203.0.113.10/32", "plugin": "obs-plugin"},
	\\    {"deny": "198.51.100.0/24", "plugin": "obs-plugin"},
	\\    {"deny": "198.18.0.0/15", "plugin": "obs-plugin"},
	\\    {"allow": "203.0.113.99/32", "plugin": "other-plugin"},
	\\    {"deny": "10.0.0.0/8"},
	\\    {"allow": "0.0.0.0/0"}],
	\\  "l7": {
	\\    "rules": [{"allow": "api.example.com", "plugin": "obs-plugin", "comment": "b"}],
	\\    "inject": {"enabled": true, "specs": [
	\\      {"host": "api.example.com", "secret": "api-token", "plugin": "obs-plugin"},
	\\      {"host": "app.example.com", "style": "cookie", "secret": "app-session", "cookieName": "session", "stub": "b-stub", "plugin": "obs-plugin"},
	\\      {"host": "git.example.com", "style": "cookie", "secret": "app-session", "cookieName": "session", "plugin": "obs-plugin"}]}}},
	\\ "plugins": [
++ entry_v1 ++ ", " ++ entry_other ++
	\\]}
;

const config_s =
	\\{"network": {
	\\  "rules": [
	\\    {"allow": "192.0.2.0/24", "plugin": "obs-plugin", "approved": true},
	\\    {"allow": "203.0.113.20/32", "plugin": "obs-plugin"},
	\\    {"allow": "203.0.113.10/32", "plugin": "obs-plugin"},
	\\    {"deny": "198.51.100.128/25", "plugin": "obs-plugin"},
	\\    {"deny": "198.18.0.0/15", "plugin": "obs-plugin"},
	\\    {"allow": "203.0.113.99/32", "plugin": "other-plugin"},
	\\    {"deny": "10.0.0.0/8"},
	\\    {"allow": "0.0.0.0/0"}],
	\\  "l7": {
	\\    "rules": [{"allow": "app.example.com", "plugin": "obs-plugin"}, {"allow": "api.example.com", "plugin": "obs-plugin", "comment": "c"}],
	\\    "inject": {"enabled": true, "specs": [
	\\      {"host": "api.example.com", "secret": "api-token", "port": 9200, "plugin": "obs-plugin"},
	\\      {"host": "app.example.com", "style": "cookie", "secret": "app-session", "cookieName": "session", "stub": "c-stub", "plugin": "obs-plugin"},
	\\      {"host": "git.example.com", "style": "cookie", "secret": "app-session", "cookieName": "other", "plugin": "obs-plugin"}]}}},
	\\ "plugins": [
++ entry_v2 ++ ", " ++ entry_other ++
	\\]}
;

const Scenario = struct { b: snapshot.Id, s: snapshot.Id, comp_b: snapshot.Comp };

/// B and S of the update scenario, with B as `base` (its runner recorded under
/// `b_key`), S's composition and a runner record for S on disk, and the intent
/// for gen1 (a live rejection targeting B) written.
fn updateScenario(fx: *Fx, b_key: []const u8) !Scenario {
	const lock_b = try lockOf(fx.mem(), &.{ .{ "obs-plugin", "sha256-v1" }, .{ "other-plugin", "sha256-o1" } });
	const lock_s = try lockOf(fx.mem(), &.{ .{ "obs-plugin", "sha256-v2" }, .{ "other-plugin", "sha256-o1" } });
	try fx.write("config.json", config_b);
	try fx.source("obs-plugin", "v1");
	try fx.source("other-plugin", "o1");
	try fx.composition("B-nix\n", lock_b);
	const b = try fx.take();
	try snapshot.setRole(fx.io, fx.icd, .base, &b, null);
	try snapshot.recordRunner(t.allocator, fx.io, fx.icd, &b, runner_b, b_key, null);

	try fx.write("config.json", config_s);
	try fx.source("obs-plugin", "v2");
	try fx.composition("S-nix\n", lock_s);
	const s = try fx.take();
	// An earlier restart_required left K (and its runner record).
	try snapshot.setRole(fx.io, fx.icd, .built, &s, null);
	try fx.write("runner.path", current_key ++ "\n" ++ runner_k ++ "\nccc\n");
	try fx.write("composition.lock.prev", "prev");
	try fx.intent(gen1, .activation_failed, .base, &b, &s);
	return .{ .b = b, .s = s, .comp_b = snapshot.compOfBytes("B-nix\n", lock_b) };
}

test "update rolled back (restored): entries, tree, composition and runner wholesale; policy narrowed per name" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "update");
	defer fx.deinit();
	const sc = try updateScenario(&fx, current_key);
	const a = fx.mem();

	const r = fx.finish(.{ .holds_apply_flock = true });
	const f = try finished(r);
	try t.expect(f.fresh);
	try t.expectEqual(rollback.Status.done, f.record.status);
	try t.expect(f.normal_error == null);
	try t.expectEqual(rollback.RunnerRecord.target, f.runner_record);
	try t.expectEqual(rollback.Reload.reloaded, f.reload);

	// Entries: B's, wholesale.
	const plugins = (try fx.config()).object.get("plugins").?.array.items;
	try t.expectEqual(@as(usize, 2), plugins.len);
	try t.expectEqualStrings("1111", plugins[0].object.get("rev").?.string);
	try t.expectEqualStrings("sha256-v1", plugins[0].object.get("narHash").?.string);
	try t.expectEqualStrings("other-plugin", plugins[1].object.get("name").?.string);
	// The source tree: B's (v1), and the untouched plugin's too.
	try t.expectEqualStrings("v1", fx.sourceOf("obs-plugin").?);
	try t.expectEqualStrings("o1", fx.sourceOf("other-plugin").?);
	// Composition bytes: B's, so p-obs-plugin locks v1's narHash again.
	try t.expectEqualStrings("B-nix\n", fx.read("plugins-flake/flake.nix").?);
	try t.expectEqualStrings(&sc.comp_b, &snapshot.compOfDir(fx.io, fx.path("plugins-flake")).?);
	// Runner record: B's runner under the current key, with B's comp; the
	// prev lock (the update's re-pin left one) is cleared with it.
	const want_rec = try std.fmt.allocPrint(a, "{s}\n{s}\n{s}\n", .{ current_key, runner_b, &sc.comp_b });
	try t.expectEqualStrings(want_rec, fx.read("runner.path").?);
	try t.expect(!fx.has("composition.lock.prev"));

	// Policy: approved allow kept; the allow the update merged removed; an allow
	// in both kept; the update's new deny kept (C union Z) and the deny it
	// dropped prepended back; the other plugin and untagged rules untouched.
	try t.expectEqualStrings(
		"deny 198.51.100.0/24 [obs-plugin], allow 192.0.2.0/24 [obs-plugin] +approved, allow 203.0.113.10/32 [obs-plugin], deny 198.51.100.128/25 [obs-plugin], deny 198.18.0.0/15 [obs-plugin], allow 203.0.113.99/32 [other-plugin], deny 10.0.0.0/8, allow 0.0.0.0/0",
		try view(a, try fx.list(.l4)),
	);
	// L7: C's element of the rule in both (its comment), the new host gone.
	const l7 = try fx.list(.l7);
	try t.expectEqualStrings("allow api.example.com [obs-plugin]", try view(a, l7));
	try t.expectEqualStrings("c", l7[0].object.get("comment").?.string);
	// Injections: a port or cookieName change is another injection, so C
	// intersect Z keeps only the one whose identity is unchanged, as C has it.
	const inj = try fx.list(.inject);
	try t.expectEqualStrings("app.example.com cookie=session [obs-plugin]", try view(a, inj));
	try t.expectEqualStrings("c-stub", inj[0].object.get("stub").?.string);
	// B's port-less and cookieName=session injections are not re-granted.
	try t.expectEqual(@as(u64, 2), f.record.policy_not_restored);

	// K may hold the rolled-back content: unlinked. Base untouched.
	try t.expect(snapshot.roleId(fx.io, fx.icd, .built) == null);
	try t.expectEqualStrings(&sc.b, &snapshot.roleId(fx.io, fx.icd, .base).?);
	// The record, the intent, the GC.
	try t.expectEqual(@as(usize, 0), (try rollback.pendingIntents(a, fx.io, fx.icd)).len);
	const recs = try fx.records();
	try t.expect(recs.id != null);
	try t.expectEqual(@as(usize, 1), recs.items.len);
	const rec = recs.items[0];
	try t.expectEqual(@as(u64, 1), rec.seq);
	try t.expectEqualStrings(gen1, rec.gen);
	try t.expectEqualStrings("7", rec.op.?);
	try t.expectEqual(rollback.Reason.activation_failed, rec.reason);
	try t.expectEqual(rollback.Target.base, rec.target);
	try t.expectEqualStrings(&sc.b, rec.target_id);
	try t.expectEqual(@as(usize, 1), rec.names.len);
	try t.expectEqualStrings("obs-plugin", rec.names[0].name);
	try t.expectEqual(snapshot.Action.restored, rec.names[0].action);
	try t.expectEqualStrings("2222", rec.names[0].from_rev.?);
	try t.expectEqualStrings("1111", rec.names[0].to_rev.?);
	try t.expect(std.mem.indexOf(u8, fx.read("apply/audit.log").?, "\"event\":\"rollback\"") != null);
	try t.expect(fx.has(try std.fmt.allocPrint(a, "apply/trash/{s}", .{&sc.s})));
	const rep = f.report();
	try t.expectEqual(rollback.RunnerRecord.target, rep.runner_record.?);
	try t.expectEqual(@as(u64, 1), rep.seq);

	// Finishing again is a no-op.
	const before = fx.read("config.json").?;
	const again = fx.finish(.{ .holds_apply_flock = true });
	try t.expectEqual(@as(usize, 0), again.outcomes.len);
	try t.expectEqualStrings(before, fx.read("config.json").?);
	try t.expectEqual(@as(usize, 1), (try fx.records()).items.len);
}

test "the rules verbs during the apply: a deleted tagged allow stays deleted, a deleted tagged deny comes back" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "rules-verbs");
	defer fx.deinit();
	_ = try updateScenario(&fx, current_key);
	// `rules del` of 203.0.113.10/32 (an allow B and S both have) and of
	// 198.18.0.0/15 (a deny B and S both have), after S was taken.
	try fx.write("config.json", try std.mem.replaceOwned(u8, fx.mem(), try std.mem.replaceOwned(u8, fx.mem(), config_s,
		\\    {"allow": "203.0.113.10/32", "plugin": "obs-plugin"},
		\\
	, ""),
		\\    {"deny": "198.18.0.0/15", "plugin": "obs-plugin"},
		\\
	, ""));
	_ = try finished(fx.finish(.{}));
	try t.expectEqualStrings(
		"deny 198.51.100.0/24 [obs-plugin], deny 198.18.0.0/15 [obs-plugin], allow 192.0.2.0/24 [obs-plugin] +approved, deny 198.51.100.128/25 [obs-plugin], allow 203.0.113.99/32 [other-plugin], deny 10.0.0.0/8, allow 0.0.0.0/0",
		try view(fx.mem(), try fx.list(.l4)),
	);
}

test "add rolled back (removed): entry and source gone, every tagged entry gone (approved and denies too)" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "add");
	defer fx.deinit();
	const a = fx.mem();
	// B: a fresh instance with no plugin yet (no plugin-sources/, no composition).
	try fx.write("config.json",
		\\{"network": {"rules": [{"deny": "10.0.0.0/8"}, {"allow": "0.0.0.0/0"}], "l7": {"rules": []}}, "plugins": []}
	);
	const b = try fx.take();
	try snapshot.setRole(fx.io, fx.icd, .base, &b, null);
	try snapshot.recordRunner(t.allocator, fx.io, fx.icd, &b, runner_b, current_key, null);
	// add obs-plugin (and its approval during the apply).
	try fx.write("config.json", "{\"network\": {\"rules\": [" ++
		"{\"allow\": \"192.0.2.0/24\", \"plugin\": \"obs-plugin\", \"approved\": true}, " ++
		"{\"allow\": \"203.0.113.10/32\", \"plugin\": \"obs-plugin\"}, {\"deny\": \"198.51.100.0/24\", \"plugin\": \"obs-plugin\"}, " ++
		"{\"deny\": \"10.0.0.0/8\"}, {\"allow\": \"0.0.0.0/0\"}], " ++
		"\"l7\": {\"rules\": [{\"allow\": \"api.example.com\", \"plugin\": \"obs-plugin\"}], " ++
		"\"inject\": {\"enabled\": true, \"specs\": [{\"host\": \"api.example.com\", \"secret\": \"api-token\", \"plugin\": \"obs-plugin\"}]}}}, " ++
		"\"plugins\": [" ++ entry_v1 ++ "]}");
	try fx.source("obs-plugin", "v1");
	try fx.composition("S-nix\n", try lockOf(a, &.{.{ "obs-plugin", "sha256-v1" }}));
	try fx.write("runner.path", current_key ++ "\n" ++ runner_k ++ "\nccc\n");
	const s = try fx.take();
	try fx.intent(gen1, .breaks_base, .base, &b, &s);

	const f = try finished(fx.finish(.{}));
	try t.expectEqual(rollback.Status.done, f.record.status);
	try t.expectEqual(snapshot.Action.removed, f.record.names[0].action);
	try t.expectEqualStrings("1111", f.record.names[0].from_rev.?);
	try t.expect(f.record.names[0].to_rev == null);
	try t.expectEqual(@as(usize, 0), (try fx.config()).object.get("plugins").?.array.items.len);
	try t.expect(fx.has("plugin-sources"));
	try t.expect(!fx.has("plugin-sources/obs-plugin"));
	try t.expect(!fx.has("plugins-flake/flake.nix"));
	try t.expect(!fx.has("plugins-flake/flake.lock"));
	// B's runner has no composition to vouch for: removed, the next boot evaluates.
	try t.expectEqual(rollback.RunnerRecord.removed, f.runner_record);
	try t.expect(!fx.has("runner.path"));
	try t.expectEqualStrings("deny 10.0.0.0/8, allow 0.0.0.0/0", try view(a, try fx.list(.l4)));
	try t.expectEqual(@as(usize, 0), (try fx.list(.l7)).len);
	try t.expectEqual(@as(usize, 0), (try fx.list(.inject)).len);
	try t.expectEqual(@as(u64, 0), f.record.policy_not_restored);
}

/// B of the update scenario as `base`, then `plugin del obs-plugin` (entry,
/// tagged entries, approved ones included, and source gone, the composition
/// regenerated without it) as S, and the intent for gen1 (a live rejection
/// targeting B) written. Returns B's lock.
fn delScenario(fx: *Fx) ![]const u8 {
	const a = fx.mem();
	try fx.write("config.json", config_b);
	try fx.source("obs-plugin", "v1");
	try fx.source("other-plugin", "o1");
	const lock_b = try lockOf(a, &.{ .{ "obs-plugin", "sha256-v1" }, .{ "other-plugin", "sha256-o1" } });
	try fx.composition("B-nix\n", lock_b);
	const b = try fx.take();
	try snapshot.setRole(fx.io, fx.icd, .base, &b, null);
	try snapshot.recordRunner(t.allocator, fx.io, fx.icd, &b, runner_b, current_key, null);
	try fx.write("config.json",
		\\{"network": {"rules": [{"allow": "203.0.113.99/32", "plugin": "other-plugin"}, {"deny": "10.0.0.0/8"}, {"allow": "0.0.0.0/0"}],
		\\  "l7": {"rules": [], "inject": {"enabled": true, "specs": []}}},
		\\ "plugins": [
	++ entry_other ++ "]}");
	fx.remove("plugin-sources/obs-plugin");
	try fx.composition("S-nix\n", try lockOf(a, &.{.{ "other-plugin", "sha256-o1" }}));
	const s = try fx.take();
	try fx.intent(gen1, .unit_hang, .base, &b, &s);
	return lock_b;
}

test "del rolled back (reinserted): entry and tree back, its denies back, no allow or injection re-granted" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "del");
	defer fx.deinit();
	const a = fx.mem();
	const lock_b = try delScenario(&fx);

	const f = try finished(fx.finish(.{}));
	try t.expectEqual(snapshot.Action.reinserted, f.record.names[0].action);
	try t.expect(f.record.names[0].from_rev == null);
	try t.expectEqualStrings("1111", f.record.names[0].to_rev.?);
	const plugins = (try fx.config()).object.get("plugins").?.array.items;
	try t.expectEqual(@as(usize, 2), plugins.len);
	try t.expectEqualStrings("obs-plugin", plugins[0].object.get("name").?.string);
	try t.expectEqualStrings("v1", fx.sourceOf("obs-plugin").?);
	try t.expectEqualStrings("B-nix\n", fx.read("plugins-flake/flake.nix").?);
	try t.expectEqualStrings(lock_b, fx.read("plugins-flake/flake.lock").?);
	try t.expectEqual(rollback.RunnerRecord.target, f.runner_record);
	// Its denies back, prepended in B's order; none of its allows or injections.
	try t.expectEqualStrings(
		"deny 198.51.100.0/24 [obs-plugin], deny 198.18.0.0/15 [obs-plugin], allow 203.0.113.99/32 [other-plugin], deny 10.0.0.0/8, allow 0.0.0.0/0",
		try view(a, try fx.list(.l4)),
	);
	try t.expectEqual(@as(usize, 0), (try fx.list(.l7)).len);
	try t.expectEqual(@as(usize, 0), (try fx.list(.inject)).len);
	// B's allow, its L7 allow and its three injections stay withdrawn.
	try t.expectEqual(@as(u64, 5), f.record.policy_not_restored);
}

test "the restore reads snap/<target_id> even after the role symlinks moved" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "moved");
	defer fx.deinit();
	const sc = try updateScenario(&fx, current_key);
	try snapshot.setRole(fx.io, fx.icd, .base, &sc.s, null);
	const f = try finished(fx.finish(.{}));
	try t.expectEqual(rollback.Status.done, f.record.status);
	try t.expectEqualStrings(&sc.b, f.record.target_id);
	try t.expectEqualStrings("v1", fx.sourceOf("obs-plugin").?);
	try t.expectEqualStrings("B-nix\n", fx.read("plugins-flake/flake.nix").?);
	// A rollback never moves base.
	try t.expectEqualStrings(&sc.s, &snapshot.roleId(fx.io, fx.icd, .base).?);
}

test "a target runner recorded under another key is never filed under the current one" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "key");
	defer fx.deinit();
	_ = try updateScenario(&fx, old_key);
	const f = try finished(fx.finish(.{}));
	try t.expectEqual(rollback.Status.done, f.record.status);
	try t.expectEqual(rollback.RunnerRecord.removed, f.runner_record);
	try t.expect(!fx.has("runner.path"));
	// Without a flake source nothing is recorded either.
	var fx2 = try Fx.init(threaded.io(), "nokey");
	defer fx2.deinit();
	_ = try updateScenario(&fx2, current_key);
	_ = fx2.env.swapRemove("COGBOX_FLAKE_SOURCE");
	try t.expectEqual(rollback.RunnerRecord.removed, (try finished(fx2.finish(.{}))).runner_record);
	try t.expect(!fx2.has("runner.path"));
}

test "eval_error: targets K and keeps it; after a live rejection unlinked K, the next eval_error targets B" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "eval");
	defer fx.deinit();
	const a = fx.mem();
	const lock_b = try lockOf(a, &.{.{ "obs-plugin", "sha256-v1" }});
	const lock_k = try lockOf(a, &.{.{ "obs-plugin", "sha256-v2" }});
	const cfg = struct {
		fn of(al: std.mem.Allocator, entries: []const u8) []const u8 {
			return std.fmt.allocPrint(al, "{{\"network\": \"full\", \"plugins\": [{s}]}}", .{entries}) catch unreachable;
		}
	}.of;
	const entry_y = "{\"name\": \"y-plugin\", \"url\": \"path:/src/y\", \"lockedUrl\": \"path:/src/y?narHash=sha256-y\", \"narHash\": \"sha256-y\"}";

	// B: obs-plugin v1.
	try fx.write("config.json", cfg(a, entry_v1));
	try fx.source("obs-plugin", "v1");
	try fx.composition("B-nix\n", lock_b);
	const b = try fx.take();
	try snapshot.setRole(fx.io, fx.icd, .base, &b, null);
	try snapshot.recordRunner(t.allocator, fx.io, fx.icd, &b, runner_b, current_key, null);
	// update to v2 ends restart_required: K := S1, R_K recorded.
	try fx.write("config.json", cfg(a, entry_v2));
	try fx.source("obs-plugin", "v2");
	try fx.composition("K-nix\n", lock_k);
	const k = try fx.take();
	try snapshot.setRole(fx.io, fx.icd, .built, &k, null);
	try snapshot.recordRunner(t.allocator, fx.io, fx.icd, &k, runner_k, current_key, null);
	const comp_k = snapshot.compOfBytes("K-nix\n", lock_k);
	try fx.write("runner.path", try std.fmt.allocPrint(a, "{s}\n{s}\n{s}\n", .{ current_key, runner_k, &comp_k }));

	// add y-plugin, which fails to evaluate: the eval_error targets K (else B),
	// and its scope against K holds only y-plugin.
	try fx.write("config.json", cfg(a, entry_v2 ++ ", " ++ entry_y));
	try fx.source("y-plugin", "y1");
	try fx.composition("S-nix\n", try lockOf(a, &.{ .{ "obs-plugin", "sha256-v2" }, .{ "y-plugin", "sha256-y" } }));
	const s1 = try fx.take();
	const target = snapshot.roleId(fx.io, fx.icd, .built) orelse snapshot.roleId(fx.io, fx.icd, .base).?;
	try t.expectEqualStrings(&k, &target);
	try fx.intent(gen1, .eval_error, .built, &target, &s1);
	const sc_k = try snapshot.scope(a, (try fx.snap(&s1)).plugins, (try fx.snap(&k)).plugins);
	try t.expectEqual(@as(usize, 1), sc_k.len);
	try t.expectEqualStrings("y-plugin", sc_k[0].name);
	const f1 = try finished(fx.finish(.{}));
	try t.expectEqual(rollback.Target.built, f1.record.target);
	try t.expectEqualStrings("v2", fx.sourceOf("obs-plugin").?);
	try t.expect(fx.sourceOf("y-plugin") == null);
	try t.expectEqualStrings("K-nix\n", fx.read("plugins-flake/flake.nix").?);
	// An eval_error leaves K: it is still proven to evaluate.
	try t.expectEqualStrings(&k, &snapshot.roleId(fx.io, fx.icd, .built).?);
	try t.expectEqual(rollback.RunnerRecord.target, f1.runner_record);
	try t.expect(std.mem.indexOf(u8, fx.read("runner.path").?, runner_k) != null);

	// A forced apply of v2 rejected with activation_hang: back to B, K unlinked.
	const s2 = try fx.take();
	try fx.intent(gen2, .activation_hang, .base, &b, &s2);
	_ = try finished(fx.finish(.{}));
	try t.expectEqualStrings("v1", fx.sourceOf("obs-plugin").?);
	try t.expect(snapshot.roleId(fx.io, fx.icd, .built) == null);

	// add y-plugin again, failing to evaluate: with no K the target is B, so
	// obs-plugin stays at v1 and runner.path is B's runner, never R_K.
	try fx.write("config.json", cfg(a, entry_v1 ++ ", " ++ entry_y));
	try fx.source("y-plugin", "y1");
	try fx.composition("S3-nix\n", try lockOf(a, &.{ .{ "obs-plugin", "sha256-v1" }, .{ "y-plugin", "sha256-y" } }));
	const s3 = try fx.take();
	const target3 = snapshot.roleId(fx.io, fx.icd, .built) orelse snapshot.roleId(fx.io, fx.icd, .base).?;
	try t.expectEqualStrings(&b, &target3);
	try fx.intent(gen3, .eval_error, .base, &target3, &s3);
	const f3 = try finished(fx.finish(.{}));
	try t.expectEqual(rollback.Target.base, f3.record.target);
	try t.expectEqualStrings("v1", fx.sourceOf("obs-plugin").?);
	try t.expect(fx.sourceOf("y-plugin") == null);
	const rec = fx.read("runner.path").?;
	try t.expect(std.mem.indexOf(u8, rec, runner_b) != null);
	try t.expect(std.mem.indexOf(u8, rec, runner_k) == null);
	try t.expectEqual(@as(usize, 3), (try fx.records()).items.len);
}

test "network=full: the reload is skipped and the rollback completes" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "full");
	defer fx.deinit();
	const a = fx.mem();
	// passt runs (its pid file exists; the pid does not parse, so nothing is
	// signalled), but .network is a string: maybeReload would answer
	// NotInRulesMode.
	try fx.write("../run/passt.pid", "not-a-pid\n");
	try fx.write("config.json", "{\"network\": \"full\", \"plugins\": [" ++ entry_v1 ++ "]}");
	try fx.source("obs-plugin", "v1");
	try fx.composition("B-nix\n", try lockOf(a, &.{.{ "obs-plugin", "sha256-v1" }}));
	const b = try fx.take();
	try fx.write("config.json", "{\"network\": \"full\", \"plugins\": [" ++ entry_v2 ++ "]}");
	try fx.source("obs-plugin", "v2");
	const s = try fx.take();
	try fx.intent(gen1, .breaks_base, .base, &b, &s);
	const f = try finished(fx.finish(.{}));
	try t.expectEqual(rollback.Status.done, f.record.status);
	try t.expectEqual(rollback.Reload.skipped, f.reload);
	try t.expectEqualStrings("v1", fx.sourceOf("obs-plugin").?);
}

test "a reload that fails after config.save only warns; the rollback is done" {
	if (std.c.geteuid() == 0) return error.SkipZigTest; // root ignores the directory mode
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "reload-fail");
	defer fx.deinit();
	_ = try updateScenario(&fx, current_key);
	try fx.write("../run/passt.pid", "not-a-pid\n");
	try std.Io.Dir.cwd().setFilePermissions(fx.io, fx.runtime, .fromMode(0o555), .{});
	const r = fx.finish(.{});
	const f = try finished(r);
	try t.expectEqual(rollback.Status.done, f.record.status);
	try t.expectEqual(rollback.Reload.failed, f.reload);
	try t.expectEqual(@as(usize, 1), r.warnings.len);
	var buf: [512]u8 = undefined;
	var w: std.Io.Writer = .fixed(&buf);
	try rollback.writeWarnings(&w, r.warnings);
	try t.expect(std.mem.startsWith(u8, w.buffered(), "cogbox plugin: warning: rollback: could not reload the restored network policy ("));
	try t.expectEqualStrings("v1", fx.sourceOf("obs-plugin").?);
	try t.expectEqualStrings("1111", (try fx.config()).object.get("plugins").?.array.items[0].object.get("rev").?.string);
}

/// What a finished rollback leaves, for comparing runs.
const FinalState = struct {
	config: []const u8,
	obs_source: ?[]const u8,
	other_source: ?[]const u8,
	flake_nix: ?[]const u8,
	flake_lock: ?[]const u8,
	runner: ?[]const u8,
	built: bool,
	intents: usize,
	records: usize,

	fn of(fx: *Fx) !FinalState {
		return .{
			.config = fx.read("config.json").?,
			.obs_source = fx.sourceOf("obs-plugin"),
			.other_source = fx.sourceOf("other-plugin"),
			.flake_nix = fx.read("plugins-flake/flake.nix"),
			.flake_lock = fx.read("plugins-flake/flake.lock"),
			.runner = fx.read("runner.path"),
			.built = snapshot.roleId(fx.io, fx.icd, .built) != null,
			.intents = (try rollback.pendingIntents(fx.mem(), fx.io, fx.icd)).len,
			.records = (try fx.records()).items.len,
		};
	}

	fn expectEqual(want: FinalState, got: FinalState) !void {
		try t.expectEqualStrings(want.config, got.config);
		try expectOpt(want.obs_source, got.obs_source);
		try expectOpt(want.other_source, got.other_source);
		try expectOpt(want.flake_nix, got.flake_nix);
		try expectOpt(want.flake_lock, got.flake_lock);
		try expectOpt(want.runner, got.runner);
		try t.expectEqual(want.built, got.built);
		try t.expectEqual(want.intents, got.intents);
		try t.expectEqual(want.records, got.records);
	}
};

fn expectOpt(want: ?[]const u8, got: ?[]const u8) !void {
	if (want == null or got == null) return t.expect(want == null and got == null);
	try t.expectEqualStrings(want.?, got.?);
}

test "idempotence: a crash after each step, then a finish from the intent, ends in the same state" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	var ref = try Fx.init(io, "crash-ref");
	defer ref.deinit();
	_ = try updateScenario(&ref, current_key);
	_ = try finished(ref.finish(.{}));
	const want = try FinalState.of(&ref);
	try t.expectEqual(@as(usize, 1), want.records);

	inline for (std.meta.fields(rollback.Step)) |field| {
		const step: rollback.Step = @enumFromInt(field.value);
		var fx = try Fx.init(io, "crash");
		defer fx.deinit();
		_ = try updateScenario(&fx, current_key);
		const crashed = fx.finish(.{ .hooks = .{ .crash_after = step } });
		try t.expect(crashed.crashed);
		const retry = fx.finish(.{});
		try t.expect(!retry.crashed);
		try t.expectEqual(@as(usize, 0), retry.pending);
		const got = try FinalState.of(&fx);
		FinalState.expectEqual(want, got) catch |err| {
			std.debug.print("crash after {s}\n", .{@tagName(step)});
			return err;
		};
		switch (step) {
			// The record was appended before the crash: the retry discards the
			// intent and appends no second record.
			.record => try t.expect(!(try finished(retry)).fresh),
			// Nothing was left to finish, only the GC.
			.intent => try t.expectEqual(@as(usize, 0), retry.outcomes.len),
			else => {
				const f = try finished(retry);
				try t.expect(f.fresh);
				// A crash between config.save and the reload still reloads.
				try t.expectEqual(rollback.Reload.reloaded, f.reload);
			},
		}
	}
}

test "fail-closed: an unreadable target removes the rolled-back plugin, keeps its denies, edits the lock" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "fail-closed");
	defer fx.deinit();
	const a = fx.mem();
	const sc = try updateScenario(&fx, current_key);
	// B's meta.json is gone (a host-disk fault): the snapshot is incomplete.
	fx.remove(try std.fmt.allocPrint(a, "apply/snap/{s}/meta.json", .{&sc.b}));

	const r = fx.finish(.{});
	const f = try finished(r);
	// The tier switch is said, for the caller to print.
	try t.expectEqual(@as(usize, 1), r.warnings.len);
	try t.expect(std.mem.indexOf(u8, r.warnings[0], "removing the rolled-back plugins instead") != null);
	try t.expectEqual(rollback.Status.removed, f.record.status);
	try t.expectEqual(error.Incomplete, f.normal_error.?);
	try t.expectEqual(rollback.RunnerRecord.removed, f.runner_record);
	try t.expect(f.record.names[0].to_rev == null);
	const plugins = (try fx.config()).object.get("plugins").?.array.items;
	try t.expectEqual(@as(usize, 1), plugins.len);
	try t.expectEqualStrings("other-plugin", plugins[0].object.get("name").?.string);
	try t.expect(fx.sourceOf("obs-plugin") == null);
	try t.expectEqualStrings("o1", fx.sourceOf("other-plugin").?);
	// A restored name keeps its denies; its allows (approved ones too) and
	// injections go.
	try t.expectEqualStrings(
		"deny 198.51.100.128/25 [obs-plugin], deny 198.18.0.0/15 [obs-plugin], allow 203.0.113.99/32 [other-plugin], deny 10.0.0.0/8, allow 0.0.0.0/0",
		try view(a, try fx.list(.l4)),
	);
	try t.expectEqual(@as(usize, 0), (try fx.list(.l7)).len);
	try t.expectEqual(@as(usize, 0), (try fx.list(.inject)).len);
	// flake.nix regenerated for the remaining plugin; its lock keeps it and
	// drops the removed one (and the node only it reached).
	const nix_bytes = fx.read("plugins-flake/flake.nix").?;
	try t.expect(std.mem.indexOf(u8, nix_bytes, "p-other-plugin") != null);
	try t.expect(std.mem.indexOf(u8, nix_bytes, "p-obs-plugin") == null);
	const lock = fx.read("plugins-flake/flake.lock").?;
	try t.expect(std.mem.indexOf(u8, lock, "p-other-plugin") != null);
	try t.expect(std.mem.indexOf(u8, lock, "obs-plugin") == null);
	try t.expect(std.mem.indexOf(u8, lock, "sha256-v2") == null);
	try t.expect(!fx.has("runner.path"));
	try t.expect(snapshot.roleId(fx.io, fx.icd, .built) == null);
	try t.expectEqual(@as(usize, 0), (try rollback.pendingIntents(a, fx.io, fx.icd)).len);
}

test "fail-closed: a failed source restore switches tiers in the same call; an unparseable lock is unlinked" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "fail-sources");
	defer fx.deinit();
	_ = try updateScenario(&fx, current_key);
	try fx.write("plugins-flake/flake.lock", "{\"nodes\": tor");
	const f = try finished(fx.finish(.{ .hooks = .{ .fail_at = .sources } }));
	try t.expectEqual(rollback.Status.removed, f.record.status);
	try t.expectEqual(error.InjectedFailure, f.normal_error.?);
	try t.expect(!fx.has("plugins-flake/flake.lock"));
	try t.expect(fx.has("plugins-flake/flake.nix"));
	try t.expect(!fx.has("runner.path"));
}

test "fail-closed after (b) put a del back: the reinserted name stays deleted (entry, source, lock input), its policy as (b) left it" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	// (c) fails with B's entries saved; (d) fails with B's composition too.
	for ([_]rollback.Step{ .composition, .runner }) |step| {
		var fx = try Fx.init(threaded.io(), "fail-del");
		defer fx.deinit();
		const a = fx.mem();
		_ = try delScenario(&fx);
		const f = try finished(fx.finish(.{ .hooks = .{ .fail_at = step } }));
		try t.expectEqual(rollback.Status.removed, f.record.status);
		try t.expectEqual(snapshot.Action.reinserted, f.record.names[0].action);
		const plugins = (try fx.config()).object.get("plugins").?.array.items;
		try t.expectEqual(@as(usize, 1), plugins.len);
		try t.expectEqualStrings("other-plugin", plugins[0].object.get("name").?.string);
		try t.expect(fx.sourceOf("obs-plugin") == null);
		try t.expectEqualStrings("o1", fx.sourceOf("other-plugin").?);
		const nix_bytes = fx.read("plugins-flake/flake.nix").?;
		try t.expect(std.mem.indexOf(u8, nix_bytes, "p-other-plugin") != null);
		try t.expect(std.mem.indexOf(u8, nix_bytes, "p-obs-plugin") == null);
		const lock = fx.read("plugins-flake/flake.lock").?;
		try t.expect(std.mem.indexOf(u8, lock, "p-other-plugin") != null);
		try t.expect(std.mem.indexOf(u8, lock, "obs-plugin") == null);
		// The denies (b) put back stay (they only narrow); nothing re-granted.
		try t.expectEqualStrings(
			"deny 198.51.100.0/24 [obs-plugin], deny 198.18.0.0/15 [obs-plugin], allow 203.0.113.99/32 [other-plugin], deny 10.0.0.0/8, allow 0.0.0.0/0",
			try view(a, try fx.list(.l4)),
		);
		try t.expectEqual(@as(usize, 0), (try fx.list(.l7)).len);
		try t.expectEqual(@as(usize, 0), (try fx.list(.inject)).len);
		try t.expect(!fx.has("runner.path"));
	}
}

test "fail-closed fails too: the intent stays, pending, and a later finish completes it" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "fail-both");
	defer fx.deinit();
	const a = fx.mem();
	_ = try updateScenario(&fx, current_key);
	const r = fx.finish(.{ .hooks = .{ .fail_at = .config, .fail_closed_fails = true } });
	try t.expectEqual(@as(usize, 1), r.pending);
	try t.expectEqual(@as(usize, 2), r.warnings.len);
	try t.expectEqual(error.InjectedFailure, r.pending_error.?);
	const pending = try rollback.pendingIntents(a, fx.io, fx.icd);
	try t.expectEqual(@as(usize, 1), pending.len);
	try t.expectEqualStrings(gen1 ++ ".intent", pending[0]);
	try t.expectEqual(@as(usize, 0), (try fx.records()).items.len);
	var buf: [512]u8 = undefined;
	var w: std.Io.Writer = .fixed(&buf);
	try rollback.writePendingMessage(&w, r.pending_error.?, "web");
	try t.expectEqualStrings("cogbox: an automatic plugin rollback could not be finished (InjectedFailure); free disk space, or run 'cogbox plugin apply --abandon-rollback -n web'\n", w.buffered());

	_ = try finished(fx.finish(.{}));
	try t.expectEqualStrings("v1", fx.sourceOf("obs-plugin").?);
	try t.expectEqual(@as(usize, 1), (try fx.records()).items.len);
}

test "intents: a SIGKILL at any point of the write leaves no intent or a complete one" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	inline for (std.meta.fields(rollback.IntentWriteStep)) |field| {
		const step: rollback.IntentWriteStep = @enumFromInt(field.value);
		var fx = try Fx.init(io, "intent-kill");
		defer fx.deinit();
		const scope = [_]snapshot.ScopeEntry{.{ .name = "obs-plugin", .action = .restored, .from_rev = "2222", .to_rev = "1111" }};
		const intent: rollback.Intent = .{ .G = gen1, .reason = .unit_hang, .target = .base, .target_id = "0123456789abcdef", .scope = &scope };
		try t.expectError(error.SimulatedCrash, rollback.writeIntent(t.allocator, io, fx.icd, intent, .{ .crash_after = step }));
		const bytes = fx.read("apply/rollback/" ++ gen1 ++ ".intent");
		switch (step) {
			.tmp_created, .tmp_written, .tmp_synced => try t.expect(bytes == null),
			.linked, .tmp_unlinked => {
				const got = try rollback.parseIntent(fx.mem(), bytes.?, gen1 ++ ".intent");
				try t.expectEqualStrings("obs-plugin", got.scope[0].name);
				try t.expectEqual(rollback.Reason.unit_hang, got.reason);
			},
		}
		// A leftover tmp name is never an intent, and only an apply-flock
		// holder's finish removes it.
		try t.expectEqual(@as(usize, if (bytes == null) 0 else 1), (try rollback.pendingIntents(fx.mem(), io, fx.icd)).len);
	}
}

test "intents: a finish without the apply flock leaves a tmp name, one with it sweeps it" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "intent-sweep");
	defer fx.deinit();
	try fx.write("config.json", "{\"plugins\": []}");
	try fx.write("apply/rollback/." ++ gen1 ++ ".intent.0a0b.tmp", "{\"G\": \"" ++ gen1);
	const r1 = fx.finish(.{ .holds_apply_flock = false });
	try t.expectEqual(@as(usize, 0), r1.pending);
	try t.expectEqual(@as(usize, 0), r1.swept_tmp);
	try t.expect(fx.has("apply/rollback/." ++ gen1 ++ ".intent.0a0b.tmp"));
	const r2 = fx.finish(.{ .holds_apply_flock = true });
	try t.expectEqual(@as(usize, 1), r2.swept_tmp);
	try t.expect(!fx.has("apply/rollback/." ++ gen1 ++ ".intent.0a0b.tmp"));
}

test "intents: one per generation, never after its record; a deleted instance's is discarded" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	var fx = try Fx.init(io, "intent-once");
	defer fx.deinit();
	const sc = try updateScenario(&fx, current_key);
	const intent: rollback.Intent = .{ .G = gen1, .reason = .unit_hang, .target = .base, .target_id = &sc.b, .scope = &.{} };
	try t.expectEqual(rollback.WriteIntentResult.exists, try rollback.writeIntent(t.allocator, io, fx.icd, intent, .{}));
	_ = try finished(fx.finish(.{}));
	try t.expectEqual(rollback.WriteIntentResult.recorded, try rollback.writeIntent(t.allocator, io, fx.icd, intent, .{}));
	try t.expectEqual(@as(usize, 0), (try rollback.pendingIntents(fx.mem(), io, fx.icd)).len);
	try t.expectError(error.InvalidIntent, rollback.writeIntent(t.allocator, io, fx.icd, .{ .G = "bad", .reason = .unit_hang, .target = .base, .target_id = &sc.b, .scope = &.{} }, .{}));
	try t.expectError(error.InvalidIntent, rollback.writeIntent(t.allocator, io, fx.icd, .{ .G = gen2, .reason = .unit_hang, .target = .base, .target_id = &sc.b, .scope = &.{.{ .name = "../x", .action = .removed }} }, .{}));

	// The instance was deleted (config.json gone): the intent is discarded and
	// nothing is created or restored.
	var fx2 = try Fx.init(io, "intent-deleted");
	defer fx2.deinit();
	_ = try updateScenario(&fx2, current_key);
	fx2.remove("config.json");
	const r = fx2.finish(.{});
	try t.expectEqual(@as(usize, 1), r.outcomes.len);
	try t.expect(r.outcomes[0].result == .discarded);
	try t.expectEqual(@as(usize, 0), r.pending);
	try t.expectEqual(@as(usize, 0), (try rollback.pendingIntents(fx2.mem(), io, fx2.icd)).len);
	try t.expect(!fx2.has("config.json"));
	try t.expectEqualStrings("v2", fx2.sourceOf("obs-plugin").?);
	try t.expectEqual(@as(usize, 0), (try fx2.records()).items.len);
}

test "an unparseable intent counts as unfinished; --abandon-rollback moves it, refused while the apply flock is held" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	var fx = try Fx.init(io, "abandon");
	defer fx.deinit();
	const a = fx.mem();
	try fx.write("config.json", "{\"plugins\": []}");
	try fx.write("apply/rollback/" ++ gen1 ++ ".intent", "");
	try fx.write("apply/rollback/" ++ gen2 ++ ".intent", "garbage");
	// Valid JSON naming another generation than its file is no better.
	try fx.write("apply/rollback/" ++ gen3 ++ ".intent", "{\"G\": \"" ++ gen1 ++ "\", \"reason\": \"unit_hang\", \"target\": \"base\", \"target_id\": \"0123456789abcdef\", \"scope\": []}");
	const r = fx.finish(.{ .holds_apply_flock = true });
	try t.expectEqual(@as(usize, 3), r.pending);
	try t.expectEqual(error.UnparseableIntent, r.pending_error.?);
	try t.expectEqual(@as(usize, 3), (try rollback.pendingIntents(a, io, fx.icd)).len);

	// Two open file descriptions of the apply lock stand in for two processes.
	const lock_path = fx.path("apply.lock");
	const holder = try std.Io.Dir.cwd().createFile(io, lock_path, .{ .truncate = false });
	defer holder.close(io);
	const mine = try std.Io.Dir.cwd().createFile(io, lock_path, .{ .truncate = false });
	defer mine.close(io);
	try t.expectEqual(@as(c_int, 0), std.c.flock(holder.handle, std.posix.LOCK.EX | std.posix.LOCK.NB));
	try t.expectError(error.ApplyBusy, rollback.abandon(a, io, fx.icd, mine.handle, null));
	try t.expectEqual(@as(usize, 3), (try rollback.pendingIntents(a, io, fx.icd)).len);

	try t.expectEqual(@as(c_int, 0), std.c.flock(holder.handle, std.posix.LOCK.UN));
	const ab = try rollback.abandon(a, io, fx.icd, mine.handle, null);
	try t.expectEqual(@as(usize, 3), ab.moved.len);
	try t.expectEqual(@as(usize, 0), (try rollback.pendingIntents(a, io, fx.icd)).len);
	var abandoned = try std.Io.Dir.cwd().openDir(io, fx.path("apply/abandoned"), .{ .iterate = true });
	defer abandoned.close(io);
	var it = abandoned.iterate();
	var n: usize = 0;
	while (try it.next(io)) |_| n += 1;
	try t.expectEqual(@as(usize, 3), n);
	const audit = fx.read("apply/audit.log").?;
	try t.expectEqual(@as(usize, 3), std.mem.count(u8, audit, "\"event\":\"abandon\""));
	try t.expectEqual(@as(usize, 0), fx.finish(.{}).pending);
}

test "--abandon-rollback needs no new directory: the intent write created apply/abandoned/ before it" {
	if (std.c.geteuid() == 0) return error.SkipZigTest; // root ignores the directory mode
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	const io = threaded.io();
	var fx = try Fx.init(io, "abandon-full");
	defer fx.deinit();
	const a = fx.mem();
	_ = try updateScenario(&fx, current_key);
	try t.expect(fx.has("apply/abandoned"));
	// apply/ takes no new entry, as on a disk too full for a mkdir: the
	// intent still moves (a rename into the existing directory), and the
	// audit line it cannot write is only a warning.
	const apply_dir = fx.path("apply");
	try std.Io.Dir.cwd().setFilePermissions(io, apply_dir, .fromMode(0o555), .{});
	defer std.Io.Dir.cwd().setFilePermissions(io, apply_dir, .fromMode(0o755), .{}) catch {};
	const lock = try std.Io.Dir.cwd().createFile(io, fx.path("apply.lock"), .{ .truncate = false });
	defer lock.close(io);
	const ab = try rollback.abandon(a, io, fx.icd, lock.handle, null);
	try t.expectEqual(@as(usize, 1), ab.moved.len);
	try t.expectEqualStrings(gen1 ++ ".intent", ab.moved[0]);
	try t.expectEqual(@as(usize, 1), ab.warnings.len);
	try t.expectEqual(@as(usize, 0), (try rollback.pendingIntents(a, io, fx.icd)).len);
	var abandoned = try std.Io.Dir.cwd().openDir(io, fx.path("apply/abandoned"), .{ .iterate = true });
	defer abandoned.close(io);
	var it = abandoned.iterate();
	var n: usize = 0;
	while (try it.next(io)) |e| : (n += 1) try t.expect(std.mem.startsWith(u8, e.name, gen1 ++ ".intent."));
	try t.expectEqual(@as(usize, 1), n);
}

test "records: rollbacks.id before the first record; a recreated file gets a new id; 64 kept; repeat" {
	var threaded: std.Io.Threaded = .init(t.allocator, .{});
	defer threaded.deinit();
	var fx = try Fx.init(threaded.io(), "records");
	defer fx.deinit();
	const a = fx.mem();
	const sc = try updateScenario(&fx, current_key);
	_ = try finished(fx.finish(.{}));
	const first = try fx.records();
	const id1 = first.id.?;
	try t.expectEqual(@as(u64, 0), first.items[0].repeat);

	// The same update rejected again (S taken anew from the same state).
	try fx.write("config.json", config_s);
	try fx.source("obs-plugin", "v2");
	const s2 = try fx.take();
	try fx.intent(gen2, .activation_failed, .base, &sc.b, &s2);
	_ = try finished(fx.finish(.{}));
	const second = try fx.records();
	try t.expectEqualStrings(&id1, &second.id.?);
	try t.expectEqual(@as(usize, 2), second.items.len);
	try t.expectEqual(@as(u64, 2), second.items[1].seq);
	// The same name at the same narHash vetoed before.
	try t.expectEqual(@as(u64, 1), second.items[1].repeat);

	// A recreated records file: seq restarts and the id changes, so a reader
	// that saw seq 2 still notices seq 1 of the new file.
	fx.remove("apply/" ++ rollback.records_file);
	fx.remove("apply/" ++ rollback.records_id_file);
	try fx.write("config.json", config_s);
	try fx.source("obs-plugin", "v2");
	const s3 = try fx.take();
	try fx.intent(gen3, .activation_failed, .base, &sc.b, &s3);
	_ = try finished(fx.finish(.{}));
	const third = try fx.records();
	try t.expectEqual(@as(u64, 1), third.items[0].seq);
	try t.expect(!std.mem.eql(u8, &id1, &third.id.?));

	// A records file that is gone while its id stayed (a crash between the two
	// writes, or a hand-removed file) is a new file too: a reader that kept the
	// old id would never see its seq 1.
	const id3 = third.id.?;
	fx.remove("apply/" ++ rollback.records_file);
	try fx.write("config.json", config_s);
	try fx.source("obs-plugin", "v2");
	const s5 = try fx.take();
	try fx.intent("5555555555555555", .activation_failed, .base, &sc.b, &s5);
	_ = try finished(fx.finish(.{}));
	const fourth = try fx.records();
	try t.expectEqual(@as(u64, 1), fourth.items[0].seq);
	try t.expect(!std.mem.eql(u8, &id3, &fourth.id.?));

	// At most 64 records: the oldest drop off.
	var lines: std.ArrayList(u8) = .empty;
	for (0..64) |i| try lines.print(a, "{{\"seq\":{d},\"gen\":\"{x:0>16}\",\"reason\":\"unit_hang\",\"at\":0,\"target\":\"base\",\"target_id\":\"0123456789abcdef\",\"status\":\"done\",\"names\":[]}}\n", .{ i + 1, i + 0x100 });
	try fx.write("apply/" ++ rollback.records_file, lines.items);
	try fx.write("config.json", config_s);
	try fx.source("obs-plugin", "v2");
	const s4 = try fx.take();
	try fx.intent("4444444444444444", .activation_failed, .base, &sc.b, &s4);
	_ = try finished(fx.finish(.{}));
	const capped = try fx.records();
	try t.expectEqual(@as(usize, rollback.max_records), capped.items.len);
	try t.expectEqual(@as(u64, 2), capped.items[0].seq);
	try t.expectEqual(@as(u64, 65), capped.items[63].seq);
}

test "editLock: drops root inputs and the nodes only they reached; follows are not nodes" {
	const lock =
		\\{"nodes": {
		\\  "root": {"inputs": {"p-a": "p-a", "p-b": "p-b", "user": "user"}},
		\\  "p-a": {"inputs": {"nixpkgs": "nixpkgs", "f": ["user"]}, "locked": {"narHash": "sha256-a"}},
		\\  "p-b": {"inputs": {"nixpkgs": "nixpkgs_2"}, "locked": {"narHash": "sha256-b"}},
		\\  "nixpkgs": {"locked": {}}, "nixpkgs_2": {"locked": {}}, "user": {"locked": {}}},
		\\ "root": "root", "version": 7}
	;
	var arena_state = std.heap.ArenaAllocator.init(t.allocator);
	defer arena_state.deinit();
	const a = arena_state.allocator();
	const out = try rollback.editLock(a, lock, &.{"p-b"});
	const v = try std.json.parseFromSliceLeaky(std.json.Value, a, out, .{});
	const nodes = v.object.get("nodes").?.object;
	try t.expect(nodes.get("p-b") == null);
	try t.expect(nodes.get("nixpkgs_2") == null);
	try t.expect(nodes.get("p-a") != null and nodes.get("nixpkgs") != null and nodes.get("user") != null);
	try t.expect(nodes.get("root").?.object.get("inputs").?.object.get("p-b") == null);
	try t.expectError(error.InvalidLock, rollback.editLock(a, "[1]", &.{}));
	try t.expectError(error.InvalidLock, rollback.editLock(a, "{\"nodes\": tor", &.{}));
}
