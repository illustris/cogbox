// l7-auth-conf.json -> typed entries, plus the credential-file reader.
//
// The write side (rules/reload.zig renderAuthProxyConf) is NOT atomic
// (writeRuntimeFile is createFile(truncate)+writeAll+flush), so the reader is
// Rules.maybe_reload's shape with the spec's mandatory hardenings (addendum
// F.1): stat -> read -> re-stat over BOTH (mtime, size); never cache a failed
// parse (the next poll retries); on any failure fall to the EMPTY entry set,
// never a partial one -- every host then refuses with `no policy`.
//
// Generations are arena-owned and refcounted: a worker that picked one up sees
// a coherent policy for its whole request even while a new conf swaps in; the
// retired arena is destroyed by whoever drops the last reference.
//
// File shape (the cross-repo contract, addendum H#16/#18 and F.1 step 4):
//   { "version": 1, "providers": [ { "host", "plugin", "scheme", "insecure",
//     "cred_file", "cred_format", "git_user", "grants": [...] } ] }
// An unknown "version" is refused before building any entry.
//
// Conf version 2 means "some grant carries `push` rules". It exists purely as
// a whole-file fail-closed lever across an agent/enforcer image skew: the
// render (rules/reload.zig, the AGENT image) and this reader (the ENFORCER
// image) roll on independent tags, and a pre-v2 reader's parseGrants would
// silently DROP an unknown `push` object -- turning a branch-restricted grant
// into an unrestricted one. Bumping the conf version instead makes that reader
// refuse the whole conf and fall to the empty policy (403 `no-policy`).

const std = @import("std");
const builtin = @import("builtin");
const filter = @import("filter");
const plugin_mod = @import("plugin.zig");
const upstream_mod = @import("upstream.zig");

/// Operational log line -- silent under `zig test` so the unit suites stay
/// readable (the l7proxy logging convention: stderr in production).
fn opLog(comptime fmt: []const u8, args: anytype) void {
	if (builtin.is_test) return;
	std.debug.print(fmt, args);
}

pub const max_conf_bytes: usize = 1 << 20; // 1 MiB, the readStdinAll cap's twin
pub const cred_value_cap: usize = 64 * 1024;

/// The conf-file schema versions this reader interprets. Keep in step with
/// rules/reload.zig `conf_version_push` (the writer): a version this binary
/// does not know is the whole-file fail-closed lever described in the header.
pub const conf_versions = [_]i64{ 1, 2 };

fn confVersionKnown(v: i64) bool {
	for (conf_versions) |known| {
		if (v == known) return true;
	}
	return false;
}

pub const Project = struct {
	id: i64,
	path: []const u8,
};

/// One grant tuple, verbatim from the policy document (spec §4.3). `scope` and
/// `caps` stay STRINGS here: their vocabularies belong to the plugin, whose
/// `compile` fails closed on anything it does not recognize.
pub const Grant = struct {
	id: []const u8,
	scope: []const u8,
	repo: ?[]const u8 = null,
	prefix: ?[]const u8 = null,
	project_id: ?[]const u8 = null,
	projects: []const Project = &.{},
	caps: []const []const u8 = &.{},
	/// Policy-document v2's per-grant push rules. null == absent == the grant
	/// is unrestricted on push (the FAST PATH: the receive-pack body is never
	/// inspected). Shape only here -- whether the patterns are well-formed, and
	/// whether the grant may carry rules at all, is the plugin's `compile`.
	push: ?Push = null,

	/// Branch/tag rules on `git push`, evaluated against the receive-pack
	/// command list. Empty `refs` means "any ref" (the deny flags can still
	/// restrict); the flags are independent of the patterns.
	pub const Push = struct {
		refs: []const []const u8 = &.{},
		deny_delete: bool = false,
		deny_tags: bool = false,
	};
};

/// One rendered conf element (one host). `cred_file` is an absolute store
/// value path produced by the render's own resolver -- the auth proxy never
/// resolves a secret name and never walks the store (spec §2.5).
pub const Entry = struct {
	host: []const u8,
	plugin_name: []const u8,
	scheme: plugin_mod.Scheme,
	insecure: bool,
	cred_file: []const u8,
	cred_format: []const u8,
	git_user: []const u8,
	grants: []const Grant,
	policy: plugin_mod.Policy,
};

pub const Generation = struct {
	arena: std.heap.ArenaAllocator,
	/// Includes the store's own reference while this generation is current.
	refs: std.atomic.Value(usize),
	gen: u64,
	entries: []Entry,
	/// Trust store snapshot for https upstream legs, loaded per generation
	/// (arena-owned, freed with it). Empty when no entry needs TLS -- and an
	/// EMPTY bundle beside an https entry means the core refuses that leg with
	/// a named reason rather than failing every handshake opaquely (D.3).
	bundle: std.crypto.Certificate.Bundle,
	/// tls.Client's Options.ca wants an Io.RwLock; the bundle is immutable
	/// after build, so this lock is never contended.
	bundle_lock: std.Io.RwLock,
	/// Once-per-generation loud log for the empty-bundle https refusal.
	https_refusal_logged: std.atomic.Value(bool),

	pub fn findEntry(self: *Generation, host: []const u8) ?*Entry {
		for (self.entries) |*e| {
			if (std.ascii.eqlIgnoreCase(e.host, host)) return e;
		}
		return null;
	}

	pub fn bundleEmpty(self: *Generation) bool {
		return self.bundle.map.count() == 0;
	}

	/// The empty-bundle https refusal (addendum D.3 item 3): log LOUDLY, once
	/// per generation -- every https leg is being answered 502 with a named
	/// reason, and an operator reading cogbox.log must see why without one line
	/// per request. A new conf generation re-arms it. Returns whether this call
	/// was the one that logged.
	pub fn noteHttpsRefusal(self: *Generation, host: []const u8) bool {
		if (self.https_refusal_logged.swap(true, .acq_rel)) return false;
		opLog("authproxy: trust store EMPTY (SSL_CERT_FILE unset or unreadable, rescan found nothing); refusing every https upstream leg with 502 -- first refused host {s}, conf generation {d}\n", .{ host, self.gen });
		return true;
	}
};

pub const BundleMode = enum {
	/// Load the trust store iff some entry has scheme https without insecure.
	auto,
	/// Never load (unit tests; the fake transport does no TLS).
	skip,
};

pub const ParseError = error{ BadConf, OutOfMemory };

/// Parse one conf generation. ANY failure -- malformed JSON, unknown version,
/// a missing required field, an unknown plugin name, a plugin's compile
/// refusing -- fails the WHOLE parse (the caller then falls to the empty set;
/// addendum F.1 step 5 supersedes the spec's per-entry drop).
pub fn parseGeneration(
	gpa: std.mem.Allocator,
	io: std.Io,
	bytes: []const u8,
	gen_no: u64,
	bundle_mode: BundleMode,
	ssl_cert_file: ?[]const u8,
) ParseError!*Generation {
	const g = try gpa.create(Generation);
	errdefer gpa.destroy(g);
	g.* = .{
		.arena = std.heap.ArenaAllocator.init(gpa),
		.refs = .init(1),
		.gen = gen_no,
		.entries = &.{},
		.bundle = .empty,
		.bundle_lock = .init,
		.https_refusal_logged = .init(false),
	};
	errdefer g.arena.deinit();
	const arena = g.arena.allocator();

	const root = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch |err| switch (err) {
		error.OutOfMemory => return error.OutOfMemory,
		else => return error.BadConf,
	};
	if (root != .object) return error.BadConf;
	// Refuse an unknown version BEFORE building any entry (contract H#9).
	const version = root.object.get("version") orelse return error.BadConf;
	if (version != .integer or !confVersionKnown(version.integer)) return error.BadConf;
	const providers = root.object.get("providers") orelse return error.BadConf;
	if (providers != .array) return error.BadConf;

	const entries = try arena.alloc(Entry, providers.array.items.len);
	var want_tls = false;
	for (providers.array.items, 0..) |pv, i| {
		if (pv != .object) return error.BadConf;
		const o = pv.object;
		const scheme_s = strField(o, "scheme") orelse return error.BadConf;
		const scheme: plugin_mod.Scheme = if (std.mem.eql(u8, scheme_s, "https"))
			.https
		else if (std.mem.eql(u8, scheme_s, "http"))
			.http
		else
			return error.BadConf;
		// The host is re-emitted verbatim as the upstream `Host:` line (and as
		// the TLS SNI), so it must be a plain DNS name: a control byte or a
		// space in it would be header injection into the constructed head.
		const host = strField(o, "host") orelse return error.BadConf;
		if (!filter.isValidHostName(host)) return error.BadConf;
		entries[i] = .{
			.host = host,
			.plugin_name = strField(o, "plugin") orelse return error.BadConf,
			.scheme = scheme,
			.insecure = boolField(o, "insecure") orelse false,
			.cred_file = strField(o, "cred_file") orelse return error.BadConf,
			.cred_format = strField(o, "cred_format") orelse "raw",
			.git_user = strField(o, "git_user") orelse return error.BadConf,
			.grants = try parseGrants(arena, o),
			.policy = undefined,
		};
		const p = plugin_mod.find(entries[i].plugin_name) orelse return error.BadConf;
		entries[i].policy = p.compile(arena, &entries[i]) catch |err| switch (err) {
			error.OutOfMemory => return error.OutOfMemory,
			error.InvalidEntry => return error.BadConf,
		};
		if (scheme == .https and !entries[i].insecure) want_tls = true;
	}
	g.entries = entries;

	if (bundle_mode == .auto and want_tls) {
		// Explicit trust-store resolution (addendum D.3): Bundle.rescan ignores
		// SSL_CERT_FILE and the enforcer image's pkgs.cacert layout only works
		// via rescan's directory arm by accident. Arena-allocated: freed with
		// the generation. A load failure leaves the bundle EMPTY -- the core
		// then refuses https legs loudly instead of trusting nothing opaquely.
		g.bundle = upstream_mod.loadTrustStore(arena, io, ssl_cert_file) catch .empty;
	}
	return g;
}

fn parseGrants(arena: std.mem.Allocator, o: std.json.ObjectMap) ParseError![]Grant {
	const gv = o.get("grants") orelse return error.BadConf;
	if (gv != .array) return error.BadConf;
	const grants = try arena.alloc(Grant, gv.array.items.len);
	for (gv.array.items, 0..) |item, i| {
		if (item != .object) return error.BadConf;
		const go = item.object;
		grants[i] = .{
			.id = strField(go, "id") orelse return error.BadConf,
			.scope = strField(go, "scope") orelse return error.BadConf,
			.repo = strField(go, "repo"),
			.prefix = strField(go, "prefix"),
			.project_id = strField(go, "project_id"),
			.projects = try parseProjects(arena, go),
			.caps = try parseCaps(arena, go),
			.push = try parsePush(arena, go),
		};
	}
	return grants;
}

fn parseProjects(arena: std.mem.Allocator, go: std.json.ObjectMap) ParseError![]Project {
	const pv = go.get("projects") orelse return &.{};
	if (pv != .array) return error.BadConf;
	const projects = try arena.alloc(Project, pv.array.items.len);
	for (pv.array.items, 0..) |item, i| {
		if (item != .object) return error.BadConf;
		const id = item.object.get("id") orelse return error.BadConf;
		if (id != .integer) return error.BadConf;
		projects[i] = .{
			.id = id.integer,
			.path = strField(item.object, "path") orelse return error.BadConf,
		};
	}
	return projects;
}

/// The v2 `push` object, or null when the grant carries none. ABSENT is the
/// only tolerated shape: a `push` that is present but not an object, whose
/// `refs` is not an array of strings, or whose deny flags are not booleans, is
/// `BadConf` for the WHOLE conf (never a silently dropped restriction -- a
/// half-read push rule would relax a grant the owner tightened).
fn parsePush(arena: std.mem.Allocator, go: std.json.ObjectMap) ParseError!?Grant.Push {
	const pv = go.get("push") orelse return null;
	if (pv != .object) return error.BadConf;
	const po = pv.object;
	var out: Grant.Push = .{};
	if (po.get("refs")) |rv| {
		if (rv != .array) return error.BadConf;
		const refs = try arena.alloc([]const u8, rv.array.items.len);
		for (rv.array.items, 0..) |item, i| {
			if (item != .string) return error.BadConf;
			refs[i] = item.string;
		}
		out.refs = refs;
	}
	if (po.get("deny_delete")) |v| {
		if (v != .bool) return error.BadConf;
		out.deny_delete = v.bool;
	}
	if (po.get("deny_tags")) |v| {
		if (v != .bool) return error.BadConf;
		out.deny_tags = v.bool;
	}
	return out;
}

fn parseCaps(arena: std.mem.Allocator, go: std.json.ObjectMap) ParseError![]const []const u8 {
	const cv = go.get("caps") orelse return error.BadConf;
	if (cv != .array) return error.BadConf;
	const caps = try arena.alloc([]const u8, cv.array.items.len);
	for (cv.array.items, 0..) |item, i| {
		if (item != .string) return error.BadConf;
		caps[i] = item.string;
	}
	return caps;
}

fn strField(o: std.json.ObjectMap, name: []const u8) ?[]const u8 {
	const v = o.get(name) orelse return null;
	if (v != .string) return null;
	return v.string;
}

fn boolField(o: std.json.ObjectMap, name: []const u8) ?bool {
	const v = o.get(name) orelse return null;
	if (v != .bool) return null;
	return v.bool;
}

/// The store: owns the current generation and the conf-file poll cache.
/// Shared state is guarded by the l7proxy-style test-and-set spinlock
/// (std.Thread has no Mutex in 0.16; Io.Mutex is the wrong tool for raw
/// std.Thread workers). Critical sections are pointer swaps; file IO happens
/// OUTSIDE the lock.
pub const Store = struct {
	gpa: std.mem.Allocator,
	io: std.Io,
	/// Empty for a static (test) store: poll() is then a no-op.
	path: []const u8 = "",
	ssl_cert_file: ?[]const u8 = null,
	bundle_mode: BundleMode = .auto,
	lock: std.atomic.Value(bool) = .init(false),
	current: ?*Generation = null,
	has_cache: bool = false,
	cached_mtime: i96 = 0,
	cached_size: u64 = 0,
	/// Set once we have fallen to the empty set for a persisting failure, so a
	/// still-broken conf does not churn a fresh empty generation every poll
	/// (the parse itself IS retried every poll -- has_cache stays false).
	failed_empty: bool = false,
	gen_counter: u64 = 0,
	last_poll_ms: std.atomic.Value(i64) = .init(std.math.minInt(i64)),
	cred: CredCache,

	pub fn init(gpa: std.mem.Allocator, io: std.Io, path: []const u8, ssl_cert_file: ?[]const u8) Store {
		return .{ .gpa = gpa, .io = io, .path = path, .ssl_cert_file = ssl_cert_file, .cred = .{ .gpa = gpa } };
	}

	/// Test seam: a fixed generation, no file behind it.
	pub fn initStatic(gpa: std.mem.Allocator, io: std.Io, gen: *Generation) Store {
		return .{ .gpa = gpa, .io = io, .current = gen, .cred = .{ .gpa = gpa } };
	}

	pub fn deinit(self: *Store) void {
		if (self.current) |g| {
			self.current = null;
			releaseGeneration(self.gpa, g);
		}
		self.cred.deinit();
	}

	/// Rate-gated poll: at most one stat per second (the accept-loop tick, and
	/// a worker about to serve a request on a connection that sat idle).
	///
	/// The sentinel is tested FIRST and the subtraction only reached once a
	/// real timestamp is in hand (the shape main.zig's stats tick uses): `and`
	/// short-circuits its RIGHT operand only, so testing it second still
	/// evaluated `now_ms - minInt(i64)` on the very first tick -- an i64
	/// overflow that killed the proxy on every launch before it accepted a
	/// connection.
	pub fn maybePoll(self: *Store, now_ms: i64) void {
		const last = self.last_poll_ms.load(.monotonic);
		if (last != std.math.minInt(i64) and now_ms - last < 1000) return;
		self.last_poll_ms.store(now_ms, .monotonic);
		_ = self.poll();
	}

	/// stat -> read -> re-stat over (mtime, size) -- BOTH, because a truncate-
	/// then-rewrite of the same length within one timestamp tick is exactly
	/// what the non-atomic writer produces (addendum F.1 step 3).
	///
	/// Returns whether the store now holds a generation PARSED FROM THE FILE
	/// (true also when the cached one is still current). False means the
	/// fail-closed EMPTY set is live -- the verdict the pid-file gate reads
	/// (spec §2.2: written only after the first conf parse SUCCEEDS).
	pub fn poll(self: *Store) bool {
		if (self.path.len == 0) return self.current != null; // static store
		const cwd = std.Io.Dir.cwd();
		const st = cwd.statFile(self.io, self.path, .{}) catch {
			self.fallToEmpty("conf unreadable");
			return false;
		};
		if (self.has_cache and st.mtime.nanoseconds == self.cached_mtime and st.size == self.cached_size) return true;

		const bytes = self.readConf() orelse {
			self.fallToEmpty("conf read failed");
			return false;
		};
		defer self.gpa.free(bytes);

		const st2 = cwd.statFile(self.io, self.path, .{}) catch {
			self.fallToEmpty("conf unreadable");
			return false;
		};
		if (st2.mtime.nanoseconds != st.mtime.nanoseconds or st2.size != st.size) {
			// Torn write in progress: keep the current generation and do NOT
			// advance the cache -- the next poll retries on settled bytes.
			return self.has_cache;
		}

		self.gen_counter += 1;
		const g = parseGeneration(self.gpa, self.io, bytes, self.gen_counter, self.bundle_mode, self.ssl_cert_file) catch {
			self.fallToEmpty("conf parse failed");
			return false;
		};
		self.install(g);
		self.has_cache = true;
		self.cached_mtime = st.mtime.nanoseconds;
		self.cached_size = st.size;
		self.failed_empty = false;
		opLog("authproxy: conf generation {d} loaded ({d} entries)\n", .{ g.gen, g.entries.len });
		return true;
	}

	fn readConf(self: *Store) ?[]u8 {
		const cwd = std.Io.Dir.cwd();
		const f = cwd.openFile(self.io, self.path, .{}) catch return null;
		defer f.close(self.io);
		var rbuf: [8192]u8 = undefined;
		var r = f.reader(self.io, &rbuf);
		return r.interface.allocRemaining(self.gpa, .limited(max_conf_bytes)) catch null;
	}

	/// Fall to the EMPTY entry set (every host refuses with `no policy`) and
	/// leave the cache unadvanced so the next poll retries. Never a partial
	/// set. Idempotent while the failure persists.
	fn fallToEmpty(self: *Store, reason: []const u8) void {
		self.has_cache = false;
		if (self.failed_empty) return;
		self.gen_counter += 1;
		const g = parseGeneration(self.gpa, self.io, "{\"version\":1,\"providers\":[]}", self.gen_counter, .skip, null) catch return;
		self.install(g);
		self.failed_empty = true;
		opLog("authproxy: {s}; falling to the EMPTY policy (all hosts refused)\n", .{reason});
	}

	fn install(self: *Store, g: *Generation) void {
		self.lockSpin();
		const old = self.current;
		self.current = g;
		self.unlockSpin();
		// A generation move invalidates the cred cache (F.2): flush + zero.
		self.cred.flush();
		if (old) |o| releaseGeneration(self.gpa, o);
	}

	pub fn acquire(self: *Store) ?*Generation {
		self.lockSpin();
		defer self.unlockSpin();
		const g = self.current orelse return null;
		_ = g.refs.fetchAdd(1, .monotonic);
		return g;
	}

	pub fn release(self: *Store, g: *Generation) void {
		releaseGeneration(self.gpa, g);
	}

	fn lockSpin(self: *Store) void {
		while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
	}
	fn unlockSpin(self: *Store) void {
		self.lock.store(false, .release);
	}
};

fn releaseGeneration(gpa: std.mem.Allocator, g: *Generation) void {
	if (g.refs.fetchSub(1, .acq_rel) == 1) {
		g.arena.deinit();
		gpa.destroy(g);
	}
}

/// Credential-file reader + cache. Keyed by the absolute `cred_file` path the
/// conf names (never a path from config.json, a manifest or an operator
/// override -- spec §2.5). Cached on (path, mtime, size); the WHOLE cache is
/// flushed when the conf generation moves; value buffers are zeroed on retire.
/// Any failure is `CredentialUnavailable` -> 403, never a fallthrough.
pub const CredCache = struct {
	gpa: std.mem.Allocator,
	lock: std.atomic.Value(bool) = .init(false),
	entries: [max_entries]?CredEntry = @splat(null),

	const max_entries = 16;

	const CredEntry = struct {
		path: []u8,
		mtime: i96,
		size: u64,
		value: []u8,
	};

	pub fn read(self: *CredCache, io: std.Io, path: []const u8, out: []u8) error{CredentialUnavailable}!usize {
		const cwd = std.Io.Dir.cwd();
		const st = cwd.statFile(io, path, .{}) catch return error.CredentialUnavailable;

		// Cache hit under the spinlock (no IO inside it).
		self.lockSpin();
		for (&self.entries) |*slot| {
			if (slot.*) |*e| {
				if (std.mem.eql(u8, e.path, path) and e.mtime == st.mtime.nanoseconds and e.size == st.size) {
					if (e.value.len > out.len) {
						self.unlockSpin();
						return error.CredentialUnavailable;
					}
					@memcpy(out[0..e.value.len], e.value);
					const n = e.value.len;
					self.unlockSpin();
					return n;
				}
			}
		}
		self.unlockSpin();

		// Miss: read the file (64 KiB cap), re-stat, install.
		const f = cwd.openFile(io, path, .{}) catch return error.CredentialUnavailable;
		defer f.close(io);
		var rbuf: [4096]u8 = undefined;
		var r = f.reader(io, &rbuf);
		const raw = r.interface.allocRemaining(self.gpa, .limited(cred_value_cap)) catch return error.CredentialUnavailable;
		defer {
			std.crypto.secureZero(u8, raw);
			self.gpa.free(raw);
		}
		const st2 = cwd.statFile(io, path, .{}) catch return error.CredentialUnavailable;
		if (st2.mtime.nanoseconds != st.mtime.nanoseconds or st2.size != st.size) {
			// Torn write: unavailable now, the next request retries.
			return error.CredentialUnavailable;
		}
		const value = std.mem.trimEnd(u8, raw, " \t\r\n");
		if (value.len == 0 or value.len > out.len) return error.CredentialUnavailable;
		// The value is spliced RAW into an Authorization line by the plugin
		// (`Bearer <value>`) -- the one byte source in the constructed upstream
		// head that framing never saw. An INTERIOR control byte (a CR/LF the
		// trim above cannot reach) would be header injection under the owner's
		// identity; such a credential is unusable, so it is refused as
		// unavailable (403), never emitted.
		if (!credValueClean(value)) return error.CredentialUnavailable;

		self.lockSpin();
		defer self.unlockSpin();
		var free_slot: ?*?CredEntry = null;
		for (&self.entries) |*slot| {
			if (slot.*) |*e| {
				if (std.mem.eql(u8, e.path, path)) {
					free_slot = slot;
					retire(self.gpa, slot);
					break;
				}
			} else if (free_slot == null) {
				free_slot = slot;
			}
		}
		if (free_slot) |slot| {
			const p = self.gpa.dupe(u8, path) catch null;
			const v = self.gpa.dupe(u8, value) catch null;
			if (p != null and v != null) {
				slot.* = .{ .path = p.?, .mtime = st.mtime.nanoseconds, .size = st.size, .value = v.? };
			} else {
				if (p) |x| self.gpa.free(x);
				if (v) |x| {
					std.crypto.secureZero(u8, x);
					self.gpa.free(x);
				}
			}
		}
		@memcpy(out[0..value.len], value);
		return value.len;
	}

	pub fn flush(self: *CredCache) void {
		self.lockSpin();
		defer self.unlockSpin();
		for (&self.entries) |*slot| retire(self.gpa, slot);
	}

	pub fn deinit(self: *CredCache) void {
		self.flush();
	}

	fn retire(gpa: std.mem.Allocator, slot: *?CredEntry) void {
		const e = slot.* orelse return;
		std.crypto.secureZero(u8, e.value);
		gpa.free(e.value);
		gpa.free(e.path);
		slot.* = null;
	}

	fn lockSpin(self: *CredCache) void {
		while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
	}
	fn unlockSpin(self: *CredCache) void {
		self.lock.store(false, .release);
	}
};

/// A credential value may carry no C0 control byte and no DEL (the same set
/// framing.check refuses in an inbound header value, minus HTAB: no provider
/// token contains a tab, and admitting one buys nothing).
pub fn credValueClean(value: []const u8) bool {
	for (value) |ch| {
		if (ch < 0x20 or ch == 0x7f) return false;
	}
	return true;
}

// --- Tests ---

const t = std.testing;

// A minimal, OSS-clean fixture conf (fictional host/names per the repo's
// convention). Kept here so several test files can share it.
pub const test_conf_json =
	\\{"version":1,"providers":[{
	\\  "host":"git.example.com","plugin":"gitlab","scheme":"http","insecure":false,
	\\  "cred_file":"/nonexistent/store/git-gitlab","cred_format":"raw","git_user":"oauth2",
	\\  "grants":[
	\\    {"id":"gg-0001","scope":"project","repo":"grp/proj","project_id":"1234",
	\\     "caps":["git-read","git-write","issues"]},
	\\    {"id":"gg-0002","scope":"namespace","repo":"grp/sub/*","prefix":"/grp/sub/",
	\\     "caps":["git-read","git-write","issues","mr"],
	\\     "projects":[{"id":42,"path":"grp/sub/a"},{"id":77,"path":"grp/sub/b"}]},
	\\    {"id":"gg-0003","scope":"instance","caps":["git-read","mr"]}
	\\  ]}]}
;

// The v2 fixture: the fine-grained cap vocabulary plus a push-rule grant, on
// the same fictional host. The conf version is 2 here for one reason only --
// a grant carries `push`, which a pre-v2 reader would silently drop (see the
// header). The GRANT vocabulary is otherwise the plugin's to gate, and rides
// in verbatim from a version-2 policy document; a fine-caps-only conf stays at
// version 1. Shared so the plugin units and the end-to-end suites pin one shape.
pub const test_conf_v2_json =
	\\{"version":2,"providers":[{
	\\  "host":"git.example.com","plugin":"gitlab","scheme":"http","insecure":false,
	\\  "cred_file":"/nonexistent/store/git-gitlab","cred_format":"raw","git_user":"oauth2",
	\\  "grants":[
	\\    {"id":"gg-v2a","scope":"project","repo":"grp/proj","project_id":"1234",
	\\     "caps":["git-read","git-write","issues:read","issues:write","mr:read","mr:write",
	\\             "mr:merge","pipelines:read","pipelines:write","repo:read","wiki:read","wiki:write"],
	\\     "push":{"deny_delete":true,"deny_tags":true,"refs":["refs/heads/agent/*","refs/heads/release/**"]}},
	\\    {"id":"gg-v2b","scope":"namespace","repo":"grp/sub/*","prefix":"/grp/sub/",
	\\     "caps":["git-read","pipelines:read","repo:read","wiki:read"],
	\\     "projects":[{"id":42,"path":"grp/sub/a"}]}
	\\  ]}]}
;

fn testIo() std.Io.Threaded {
	return .init(t.allocator, .{});
}

test "parseGeneration: the fixture conf compiles; fields land typed" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	const g = try parseGeneration(t.allocator, io, test_conf_json, 1, .skip, null);
	defer releaseGeneration(t.allocator, g);
	try t.expectEqual(@as(usize, 1), g.entries.len);
	const e = g.entries[0];
	try t.expectEqualStrings("git.example.com", e.host);
	try t.expectEqualStrings("gitlab", e.plugin_name);
	try t.expectEqual(plugin_mod.Scheme.http, e.scheme);
	try t.expect(!e.insecure);
	try t.expectEqualStrings("oauth2", e.git_user);
	try t.expectEqual(@as(usize, 3), e.grants.len);
	try t.expectEqualStrings("/grp/sub/", e.grants[1].prefix.?);
	try t.expectEqual(@as(i64, 42), e.grants[1].projects[0].id);
	try t.expect(g.findEntry("GIT.example.com") != null);
	try t.expect(g.findEntry("api.example.com") == null);
}

test "parseGrants: the v2 push object lands typed; absent stays null" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	const g = try parseGeneration(t.allocator, io, test_conf_v2_json, 1, .skip, null);
	defer releaseGeneration(t.allocator, g);
	const grants = g.entries[0].grants;
	try t.expectEqual(@as(usize, 2), grants.len);
	const push = grants[0].push.?;
	try t.expect(push.deny_delete);
	try t.expect(push.deny_tags);
	try t.expectEqual(@as(usize, 2), push.refs.len);
	try t.expectEqualStrings("refs/heads/agent/*", push.refs[0]);
	try t.expectEqualStrings("refs/heads/release/**", push.refs[1]);
	// A grant with no `push` key is unrestricted, not empty-restricted: the
	// plugin's fast path keys on the null.
	try t.expect(grants[1].push == null);

	// A v1 document's grants carry no push key at all.
	const v1 = try parseGeneration(t.allocator, io, test_conf_json, 1, .skip, null);
	defer releaseGeneration(t.allocator, v1);
	for (v1.entries[0].grants) |gr| try t.expect(gr.push == null);
}

test "parseGrants: a malformed push object fails the WHOLE parse (never a silently dropped restriction)" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	// Every case keeps git-write in caps, so the refusal is parsePush's and not
	// the plugin's "push without git-write" arm.
	const cases = [_][]const u8{
		// push is not an object
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2","grants":[{"id":"g","scope":"instance","caps":["git-write"],"push":["refs/heads/x"]}]}]}
		,
		// refs is not an array
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2","grants":[{"id":"g","scope":"instance","caps":["git-write"],"push":{"refs":"refs/heads/x"}}]}]}
		,
		// a refs element is not a string
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2","grants":[{"id":"g","scope":"instance","caps":["git-write"],"push":{"refs":[7]}}]}]}
		,
		// a deny flag is not a boolean
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2","grants":[{"id":"g","scope":"instance","caps":["git-write"],"push":{"deny_delete":"true"}}]}]}
		,
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2","grants":[{"id":"g","scope":"instance","caps":["git-write"],"push":{"deny_tags":1}}]}]}
		,
	};
	for (cases) |json| {
		try t.expectError(error.BadConf, parseGeneration(t.allocator, io, json, 1, .skip, null));
	}
	// An EMPTY push object is well-formed (no patterns, no denials): the plugin
	// then compiles a rule set that restricts nothing.
	const ok = try parseGeneration(t.allocator, io,
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http","cred_file":"/x","git_user":"oauth2","grants":[{"id":"g","scope":"instance","caps":["git-write"],"push":{}}]}]}
	, 1, .skip, null);
	defer releaseGeneration(t.allocator, ok);
	const p = ok.entries[0].grants[0].push.?;
	try t.expectEqual(@as(usize, 0), p.refs.len);
	try t.expect(!p.deny_delete and !p.deny_tags);
}

test "parseGeneration: refusals fail the WHOLE parse, never a partial set" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	// unknown version -- 1 and 2 are both live (conf_versions), 3 is the next
	// unlanded one, and a reader too old for what it is handed must refuse the
	// WHOLE file rather than enforce the subset it happens to understand.
	try t.expectError(error.BadConf, parseGeneration(t.allocator, io, "{\"version\":3,\"providers\":[]}", 1, .skip, null));
	// malformed JSON
	try t.expectError(error.BadConf, parseGeneration(t.allocator, io, "{\"version\":1,", 1, .skip, null));
	// unknown plugin name
	try t.expectError(error.BadConf, parseGeneration(t.allocator, io,
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"nosuch","scheme":"http",
		\\"cred_file":"/x","git_user":"oauth2","grants":[]}]}
	, 1, .skip, null));
	// unknown scheme
	try t.expectError(error.BadConf, parseGeneration(t.allocator, io,
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"gopher",
		\\"cred_file":"/x","git_user":"oauth2","grants":[]}]}
	, 1, .skip, null));
	// a plugin compile refusal (unknown cap) also fails the whole parse
	try t.expectError(error.BadConf, parseGeneration(t.allocator, io,
		\\{"version":1,"providers":[{"host":"git.example.com","plugin":"gitlab","scheme":"http",
		\\"cred_file":"/x","git_user":"oauth2",
		\\"grants":[{"id":"gg-1","scope":"instance","caps":["api-full"]}]}]}
	, 1, .skip, null));
	// a host that is not a plain DNS name -- it is re-emitted verbatim as the
	// upstream `Host:` line, so a control byte or a space in it would be header
	// injection into the constructed head (F1)
	try t.expectError(error.BadConf, parseGeneration(t.allocator, io,
		"{\"version\":1,\"providers\":[{\"host\":\"git.example.com\\r\\nx-injected: 1\",\"plugin\":\"gitlab\",\"scheme\":\"http\"," ++
			"\"cred_file\":\"/x\",\"git_user\":\"oauth2\",\"grants\":[]}]}", 1, .skip, null));
	try t.expectError(error.BadConf, parseGeneration(t.allocator, io,
		\\{"version":1,"providers":[{"host":"git.example.com evil","plugin":"gitlab","scheme":"http",
		\\"cred_file":"/x","git_user":"oauth2","grants":[]}]}
	, 1, .skip, null));
	// an empty document is ACCEPTED (contract H#30)
	const g = try parseGeneration(t.allocator, io, "{\"version\":1,\"providers\":[]}", 1, .skip, null);
	defer releaseGeneration(t.allocator, g);
	try t.expectEqual(@as(usize, 0), g.entries.len);
}

fn tmpName(gpa: std.mem.Allocator, io: std.Io, comptime prefix: []const u8) ![]u8 {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	return std.fmt.allocPrint(gpa, "{s}-{s}", .{ prefix, hexb });
}

test "Store.poll: loads, skips on unchanged (mtime,size), falls to empty on a bad conf, recovers" {
	const gpa = t.allocator;
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const dir = try tmpName(gpa, io, "zig-authproxy-conf-test");
	defer gpa.free(dir);
	try cwd.createDirPath(io, dir);
	defer cwd.deleteTree(io, dir) catch {};
	const path = try std.fs.path.join(gpa, &.{ dir, "l7-auth-conf.json" });
	defer gpa.free(path);

	var store = Store.init(gpa, io, path, null);
	store.bundle_mode = .skip;
	defer store.deinit();

	// Missing file -> the empty set (fail closed), retried every poll. The
	// verdict is FALSE: nothing parsed from the file yet (the pid-file gate
	// stays shut on it).
	try t.expect(!store.poll());
	{
		const g = store.acquire().?;
		defer store.release(g);
		try t.expectEqual(@as(usize, 0), g.entries.len);
	}

	// A real conf appears -> a parsed generation, verdict true.
	try writeFileRaw(io, path, test_conf_json);
	try t.expect(store.poll());
	var gen_loaded: u64 = 0;
	{
		const g = store.acquire().?;
		defer store.release(g);
		try t.expectEqual(@as(usize, 1), g.entries.len);
		gen_loaded = g.gen;
	}

	// Unchanged (mtime,size): the poll is a no-op (same generation object),
	// and still a parsed one.
	try t.expect(store.poll());
	{
		const g = store.acquire().?;
		defer store.release(g);
		try t.expectEqual(gen_loaded, g.gen);
	}

	// The conf goes bad -> the empty set, never a partial one, and the cache
	// is NOT advanced (has_cache false) so the next poll retries the parse.
	try writeFileRaw(io, path, "{\"version\":1,\"providers\":[{");
	try t.expect(!store.poll());
	{
		const g = store.acquire().?;
		defer store.release(g);
		try t.expectEqual(@as(usize, 0), g.entries.len);
	}
	try t.expect(!store.has_cache);

	// Recovery is automatic once the file parses again.
	try writeFileRaw(io, path, test_conf_json);
	try t.expect(store.poll());
	{
		const g = store.acquire().?;
		defer store.release(g);
		try t.expectEqual(@as(usize, 1), g.entries.len);
	}
}

test "Store.maybePoll: the FIRST tick polls instead of trapping on the minInt sentinel (field: the proxy died on every launch)" {
	const gpa = t.allocator;
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const dir = try tmpName(gpa, io, "zig-authproxy-maybepoll-test");
	defer gpa.free(dir);
	try cwd.createDirPath(io, dir);
	defer cwd.deleteTree(io, dir) catch {};
	const path = try std.fs.path.join(gpa, &.{ dir, "l7-auth-conf.json" });
	defer gpa.free(path);
	try writeFileRaw(io, path, test_conf_json);

	var store = Store.init(gpa, io, path, null);
	store.bundle_mode = .skip;
	defer store.deinit();

	// The failing shape: a FRESH store (last_poll_ms still the sentinel) ticked
	// with the very clock the accept loop feeds it. The first tick must poll,
	// not subtract.
	const now = upstream_mod.nowMs(io);
	try t.expect(now > 0);
	store.maybePoll(now);
	try t.expectEqual(now, store.last_poll_ms.load(.monotonic));
	const gen_first = store.gen_counter;
	try t.expect(gen_first > 0); // it really polled

	// Inside the second: no re-poll. The conf is changed underneath first, so
	// a poll would be VISIBLE as a generation bump rather than inferred.
	try writeFileRaw(io, path, "{\"version\":1,\"providers\":[]}");
	store.maybePoll(now + 999);
	try t.expectEqual(now, store.last_poll_ms.load(.monotonic));
	try t.expectEqual(gen_first, store.gen_counter);

	// A second on, it polls again and picks the new conf up.
	store.maybePoll(now + 1000);
	try t.expectEqual(now + 1000, store.last_poll_ms.load(.monotonic));
	try t.expectEqual(gen_first + 1, store.gen_counter);
	{
		const g = store.acquire().?;
		defer store.release(g);
		try t.expectEqual(@as(usize, 0), g.entries.len);
	}

	// The sentinel is arithmetic-free from either end of the clock: a fresh
	// store must poll, never subtract, whatever `now` it is handed -- an
	// epoch-scale wall clock, zero, or a far-negative one.
	for ([_]i64{ 1_756_000_000_000, 0, std.math.minInt(i64) + 1 }) |clock| {
		var fresh = Store.init(gpa, io, path, null);
		fresh.bundle_mode = .skip;
		defer fresh.deinit();
		fresh.maybePoll(clock);
		try t.expectEqual(clock, fresh.last_poll_ms.load(.monotonic));
		try t.expect(fresh.gen_counter > 0);
	}
}

test "Generation.noteHttpsRefusal logs once per generation" {
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	const g = try parseGeneration(t.allocator, io, "{\"version\":1,\"providers\":[]}", 1, .skip, null);
	defer releaseGeneration(t.allocator, g);
	try t.expect(g.noteHttpsRefusal("git.example.com")); // the first call logs
	try t.expect(!g.noteHttpsRefusal("git.example.com")); // the second is silent
	try t.expect(g.https_refusal_logged.load(.acquire));
}

test "Store: an in-flight reference outlives a generation swap" {
	const gpa = t.allocator;
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	const g1 = try parseGeneration(gpa, io, test_conf_json, 1, .skip, null);
	var store = Store.initStatic(gpa, io, g1);
	defer store.deinit();

	const held = store.acquire().?; // a worker picked up generation 1
	const g2 = try parseGeneration(gpa, io, "{\"version\":1,\"providers\":[]}", 2, .skip, null);
	store.install(g2); // the conf moved underneath it
	// The held generation is still fully readable (the arena lives until the
	// last reference drops).
	try t.expectEqualStrings("git.example.com", held.entries[0].host);
	store.release(held);
	const now = store.acquire().?;
	defer store.release(now);
	try t.expectEqual(@as(u64, 2), now.gen);
}

test "CredCache: reads, caps, trims, flushes on generation move, fails closed" {
	const gpa = t.allocator;
	var threaded = testIo();
	defer threaded.deinit();
	const io = threaded.io();
	const cwd = std.Io.Dir.cwd();

	const dir = try tmpName(gpa, io, "zig-authproxy-cred-test");
	defer gpa.free(dir);
	try cwd.createDirPath(io, dir);
	defer cwd.deleteTree(io, dir) catch {};
	const path = try std.fs.path.join(gpa, &.{ dir, "git-gitlab" });
	defer gpa.free(path);

	var cache = CredCache{ .gpa = gpa };
	defer cache.deinit();
	var out: [cred_value_cap]u8 = undefined;

	// Missing file -> unavailable, never a fallthrough.
	try t.expectError(error.CredentialUnavailable, cache.read(io, path, &out));

	try writeFileRaw(io, path, "glpat-FAKEFAKEFAKE\n");
	const n = try cache.read(io, path, &out);
	try t.expectEqualStrings("glpat-FAKEFAKEFAKE", out[0..n]); // trailing newline trimmed

	// Cached: a second read returns the same bytes.
	const n2 = try cache.read(io, path, &out);
	try t.expectEqual(n, n2);

	// A rotate is picked up via (mtime, size).
	try writeFileRaw(io, path, "glpat-ROTATEDROTATED\n");
	const n3 = try cache.read(io, path, &out);
	try t.expectEqualStrings("glpat-ROTATEDROTATED", out[0..n3]);

	// Flush (the conf-generation-move hook) drops every entry.
	cache.flush();
	for (cache.entries) |slot| try t.expect(slot == null);

	// An empty value is unavailable, not an empty credential.
	try writeFileRaw(io, path, "\n");
	try t.expectError(error.CredentialUnavailable, cache.read(io, path, &out));

	// An INTERIOR control byte survives the tail trim and would be spliced raw
	// into `Bearer <value>` -- header injection into the constructed upstream
	// head (F1). Refused as unavailable, and never cached.
	try writeFileRaw(io, path, "glpat-AAA\r\nx-injected-by-cred: 1\r\n");
	try t.expectError(error.CredentialUnavailable, cache.read(io, path, &out));
	for (cache.entries) |slot| try t.expect(slot == null);
	try writeFileRaw(io, path, "glpat-A\x7fB\n");
	try t.expectError(error.CredentialUnavailable, cache.read(io, path, &out));
	// the trailing CRLF alone is still just a trimmed terminator
	try writeFileRaw(io, path, "glpat-CLEAN\r\n");
	const n4 = try cache.read(io, path, &out);
	try t.expectEqualStrings("glpat-CLEAN", out[0..n4]);
}

test "credValueClean: C0 and DEL refused, printable ASCII and high bytes admitted" {
	try t.expect(credValueClean("glpat-abc_DEF-123"));
	try t.expect(credValueClean("with space and ~!"));
	try t.expect(!credValueClean("a\rb"));
	try t.expect(!credValueClean("a\nb"));
	try t.expect(!credValueClean("a\tb"));
	try t.expect(!credValueClean("a\x00b"));
	try t.expect(!credValueClean("a\x7fb"));
}

fn writeFileRaw(io: std.Io, path: []const u8, bytes: []const u8) !void {
	const cwd = std.Io.Dir.cwd();
	const f = try cwd.createFile(io, path, .{ .truncate = true });
	defer f.close(io);
	var wbuf: [4096]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll(bytes);
	try w.flush();
}
