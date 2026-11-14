// `cogbox remap` verb dispatcher. Shares config/save/reload with the
// `rules` verb via the rules_module re-exports, so a `remap` edit also
// re-renders the runtime rules file (which carries BOTH CIDR allow/deny
// and remap lines) and SIGUSR1s a running passt.

const std = @import("std");
pub const cli = @import("cli.zig");
pub const rule = @import("rule.zig");

const rules_module = @import("rules_module");
const config = rules_module.config;

pub fn dispatch(
	allocator: std.mem.Allocator,
	io: std.Io,
	config_path: []const u8,
	runtime_path: []const u8,
	rest: []const []const u8,
) !void {
	var argv = try allocator.alloc([]const u8, 4 + rest.len);
	defer allocator.free(argv);
	argv[0] = "--config";
	argv[1] = config_path;
	argv[2] = "--runtime";
	argv[3] = runtime_path;
	for (rest, 0..) |a, i| argv[4 + i] = a;

	const args = cli.parse(argv) catch |err| {
		try writeStderr(io, try std.fmt.allocPrint(allocator, "cogbox remap: error: {s}\n", .{@errorName(err)}));
		std.process.exit(64);
	};

	var loaded = config.load(allocator, io, args.config_path) catch |err| switch (err) {
		error.FileNotFound => return die(allocator, io, "no config found at {s}", .{args.config_path}, 66),
		error.InvalidJson => return die(allocator, io, "invalid JSON in {s}", .{args.config_path}, 65),
		else => return err,
	};
	defer loaded.deinit();

	const net = loaded.network() catch |err| switch (err) {
		error.NotInRulesMode => return die(
			allocator,
			io,
			"instance is not in rules mode. Set network to rules mode first: edit {s} or reinit with --network rules.",
			.{args.config_path},
			65,
		),
		else => return err,
	};

	const remap_arr = try ensureRemapArray(net, loaded.treeAllocator());

	switch (args.cmd) {
		.list => try cmdList(allocator, io, remap_arr.*),
		.add => |a| try cmdAdd(allocator, io, args, remap_arr, a, &loaded),
		.del => |d| try cmdDel(allocator, io, args, remap_arr, d, &loaded),
		.set => try cmdSet(allocator, io, args, remap_arr, &loaded),
	}
}

/// Ensure .network.remap exists and is an array; create empty if missing.
fn ensureRemapArray(net: *std.json.Value, arena: std.mem.Allocator) !*std.json.Array {
	if (net.object.getPtr("remap") == null) {
		try net.object.put(arena, try arena.dupe(u8, "remap"), .{ .array = std.json.Array.init(arena) });
	}
	const v = net.object.getPtr("remap").?;
	if (v.* != .array) return error.InvalidJson;
	return &v.array;
}

fn cmdList(allocator: std.mem.Allocator, io: std.Io, remap_arr: std.json.Array) !void {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);

	for (remap_arr.items, 0..) |r, i| {
		if (r != .object) continue;
		var line_buf: [32]u8 = undefined;
		const idx_str = std.fmt.bufPrint(&line_buf, "{d}: ", .{i + 1}) catch unreachable;
		try out.appendSlice(allocator, idx_str);

		const p = rule.ruleSpec(r.object) orelse {
			try out.appendSlice(allocator, "unknown\n");
			continue;
		};
		try out.appendSlice(allocator, p.from);
		try out.appendSlice(allocator, " -> ");
		try out.appendSlice(allocator, p.to);
		if (rule.ruleComment(r.object)) |c| {
			try out.appendSlice(allocator, "  # ");
			try out.appendSlice(allocator, c);
		}
		try out.append(allocator, '\n');
	}

	try writeStdout(io, out.items);
}

fn cmdAdd(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	remap_arr: *std.json.Array,
	a: cli.AddArgs,
	loaded: *config.Loaded,
) !void {
	const refused = addRemapAndSave(allocator, io, args.config_path, remap_arr, a, loaded) catch |err| switch (err) {
		error.IndexOutOfRange => return die(allocator, io, "position out of range (must be 1..{d})", .{remap_arr.items.len + 1}, 65),
		error.InvalidSpec => return die(allocator, io, "invalid remap spec: {s} -> {s}", .{ a.from, a.to }, 65),
		else => return err,
	};
	if (refused) |r| dieRefused(allocator, io, r);

	if (a.pos) |p| {
		try announce(allocator, io, "Added: {s} -> {s} at position {d}", .{ a.from, a.to, p });
	} else {
		try announce(allocator, io, "Added: {s} -> {s}", .{ a.from, a.to });
	}
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

fn cmdDel(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	remap_arr: *std.json.Array,
	d: cli.DelArgs,
	loaded: *config.Loaded,
) !void {
	rule.delete(remap_arr, d.index) catch {
		return die(allocator, io, "index {d} out of range (1..{d})", .{ d.index, remap_arr.items.len }, 65);
	};

	try config.save(allocator, io, args.config_path, loaded.root().*);
	try announce(allocator, io, "Deleted remap rule {d}.", .{d.index});
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

fn cmdSet(
	allocator: std.mem.Allocator,
	io: std.Io,
	args: cli.Args,
	remap_arr: *std.json.Array,
	loaded: *config.Loaded,
) !void {
	const stdin = std.Io.File.stdin();
	var stdin_buf: [4096]u8 = undefined;
	var stdin_reader = stdin.readerStreaming(io, &stdin_buf);

	var pairs: std.ArrayList(rule.Pair) = .empty;
	defer pairs.deinit(allocator);
	var owned: std.ArrayList(u8) = .empty;
	defer owned.deinit(allocator);
	const Slot = struct { from_off: usize, from_len: usize, to_off: usize, to_len: usize };
	var slots: std.ArrayList(Slot) = .empty;
	defer slots.deinit(allocator);

	while (true) {
		const maybe_line = try stdin_reader.interface.takeDelimiter('\n');
		const line = maybe_line orelse break;
		const parsed = rule.parseSetLine(line) catch {
			return die(allocator, io, "invalid line: {s}", .{line}, 65);
		};
		if (parsed) |p| {
			const from_off = owned.items.len;
			try owned.appendSlice(allocator, p.from);
			const to_off = owned.items.len;
			try owned.appendSlice(allocator, p.to);
			try slots.append(allocator, .{
				.from_off = from_off,
				.from_len = p.from.len,
				.to_off = to_off,
				.to_len = p.to.len,
			});
			try pairs.append(allocator, .{ .from = "", .to = "" });
		}
	}
	for (pairs.items, slots.items) |*p, s| {
		p.from = owned.items[s.from_off .. s.from_off + s.from_len];
		p.to = owned.items[s.to_off .. s.to_off + s.to_len];
	}

	if (try replaceRemapsAndSave(allocator, io, args.config_path, remap_arr, pairs.items, loaded)) |r| dieRefused(allocator, io, r);
	try announce(allocator, io, "Remap rules replaced.", .{});
	try rules_module.maybeReload(allocator, io, args.runtime_path, loaded);
}

/// `remap add` past argument parsing: the edit (at `a.pos`, else last), then
/// the save behind the `rules` verb's growth guard
/// (rules_module.saveUnlessGrownOver). A refusal comes back with the config
/// unsaved. The funnel remaps are rendered after the user's own, so the guard is
/// also what keeps a `remap add` from pushing them out of the filter's remap
/// table.
fn addRemapAndSave(allocator: std.mem.Allocator, io: std.Io, config_path: []const u8, remap_arr: *std.json.Array, a: cli.AddArgs, loaded: *config.Loaded) !?rules_module.Refusal {
	const tree_alloc = loaded.treeAllocator();
	const before = try rules_module.measureRuleFile(allocator, loaded);
	if (a.pos) |p| {
		try rule.insertAt(tree_alloc, remap_arr, p, a.from, a.to);
	} else {
		_ = try rule.append(tree_alloc, remap_arr, a.from, a.to);
	}
	return rules_module.saveUnlessGrownOver(allocator, io, config_path, before, loaded);
}

/// `remap set` past stdin parsing: replace the table, then the save behind the
/// growth guard. A refusal comes back with the config unsaved.
fn replaceRemapsAndSave(allocator: std.mem.Allocator, io: std.Io, config_path: []const u8, remap_arr: *std.json.Array, pairs: []const rule.Pair, loaded: *config.Loaded) !?rules_module.Refusal {
	const before = try rules_module.measureRuleFile(allocator, loaded);
	try rule.replaceAll(loaded.treeAllocator(), remap_arr, pairs);
	return rules_module.saveUnlessGrownOver(allocator, io, config_path, before, loaded);
}

fn dieRefused(allocator: std.mem.Allocator, io: std.Io, r: rules_module.Refusal) noreturn {
	var msg_buf: [256]u8 = undefined;
	die(allocator, io, "{s}", .{rules_module.ruleFileRefusalMessage(&msg_buf, r.err, r.after)}, 65);
}

fn writeStdout(io: std.Io, bytes: []const u8) !void {
	const stdout = std.Io.File.stdout();
	var buf: [4096]u8 = undefined;
	var w = stdout.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn writeStderr(io: std.Io, bytes: []const u8) !void {
	const stderr = std.Io.File.stderr();
	var buf: [4096]u8 = undefined;
	var w = stderr.writer(io, &buf);
	try w.interface.writeAll(bytes);
	try w.flush();
}

fn announce(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype) !void {
	const msg = try std.fmt.allocPrint(allocator, fmt ++ "\n", args);
	defer allocator.free(msg);
	try writeStdout(io, msg);
}

fn die(allocator: std.mem.Allocator, io: std.Io, comptime fmt: []const u8, args: anytype, code: u8) noreturn {
	const msg = std.fmt.allocPrint(allocator, "cogbox remap: error: " ++ fmt ++ "\n", args) catch "cogbox remap: error: (message too long)\n";
	writeStderr(io, msg) catch {};
	std.process.exit(code);
}

/// A config.json holding `{"network": <network_json>}` under a fresh relative
/// scratch dir (caller deletes `root`, frees both). Mirrors the rules verb's
/// tmpInstanceLayout, minus the runtime dir no test here renders into.
fn tmpConfig(gpa: std.mem.Allocator, io: std.Io, network_json: []const u8) !struct { root: []u8, path: []u8 } {
	var rnd: [8]u8 = undefined;
	io.random(&rnd);
	var hexb: [16]u8 = undefined;
	_ = std.fmt.bufPrint(&hexb, "{x}", .{&rnd}) catch unreachable;
	const root = try std.fmt.allocPrint(gpa, "zig-remap-test-{s}", .{hexb});
	errdefer gpa.free(root);
	const cwd = std.Io.Dir.cwd();
	try cwd.createDirPath(io, root);
	const path = try std.fs.path.join(gpa, &.{ root, "config.json" });
	errdefer gpa.free(path);
	const body = try std.fmt.allocPrint(gpa, "{{\"network\":{s}}}\n", .{network_json});
	defer gpa.free(body);
	const f = try cwd.createFile(io, path, .{ .truncate = true });
	defer f.close(io);
	var wbuf: [4096]u8 = undefined;
	var w = f.writer(io, &wbuf);
	try w.interface.writeAll(body);
	try w.flush();
	return .{ .root = root, .path = path };
}

fn readWholeFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
	const f = try std.Io.Dir.cwd().openFile(io, path, .{});
	defer f.close(io);
	var rbuf: [4096]u8 = undefined;
	var r = f.reader(io, &rbuf);
	return r.interface.allocRemaining(gpa, .limited(1 << 20));
}

test "remap add and remap set run the growth guard before config.save: an edit that overflows the remap table is refused and the saved config is unchanged" {
	const gpa = std.testing.allocator;
	var threaded: std.Io.Threaded = .init(gpa, .{});
	defer threaded.deinit();
	const io = threaded.io();
	const max_remap_rules = @import("filter").max_remap_rules;

	const tmp = try tmpConfig(gpa, io, "{\"rules\":[{\"allow\":\"0.0.0.0/0\"}],\"remap\":[],\"l7\":{\"rules\":[{\"allow\":\"a.example.com\"}]}}");
	defer gpa.free(tmp.root);
	defer gpa.free(tmp.path);
	defer std.Io.Dir.cwd().deleteTree(io, tmp.root) catch {};

	// 63 user remaps, owned for the test: with the two funnel remaps L7 renders
	// after them that is one over the filter's table. The first 62 fill it.
	var from_bufs: [max_remap_rules - 1][32]u8 = undefined;
	var to_bufs: [max_remap_rules - 1][32]u8 = undefined;
	var pairs: [max_remap_rules - 1]rule.Pair = undefined;
	for (&from_bufs, &to_bufs, &pairs, 0..) |*fb, *tb, *p, i| p.* = .{
		.from = try std.fmt.bufPrint(fb, "tcp 192.0.2.{d}/32:{d}", .{ i, 8000 + i }),
		.to = try std.fmt.bufPrint(tb, "tcp 127.0.0.1:{d}", .{9000 + i}),
	};
	const full = pairs[0 .. max_remap_rules - 2];
	const over = pairs[max_remap_rules - 2];

	// Save the table exactly full, through the verb's own set path.
	{
		var loaded = try config.load(gpa, io, tmp.path);
		defer loaded.deinit();
		const remap_arr = &(try loaded.network()).object.getPtr("remap").?.array;
		try std.testing.expect((try replaceRemapsAndSave(gpa, io, tmp.path, remap_arr, full, &loaded)) == null);
	}
	const saved = try readWholeFile(gpa, io, tmp.path);
	defer gpa.free(saved);

	// `remap add` of a 63rd, appended and at a position: refused, file unchanged.
	for ([_]?usize{ null, 1 }) |pos| {
		var loaded = try config.load(gpa, io, tmp.path);
		defer loaded.deinit();
		const remap_arr = &(try loaded.network()).object.getPtr("remap").?.array;
		const r = (try addRemapAndSave(gpa, io, tmp.path, remap_arr, .{ .from = over.from, .to = over.to, .pos = pos }, &loaded)) orelse return error.TestUnexpectedResult;
		try std.testing.expectEqual(error.RemapTableFull, r.err);
		const now = try readWholeFile(gpa, io, tmp.path);
		defer gpa.free(now);
		try std.testing.expectEqualSlices(u8, saved, now);
	}

	// `remap set` of all 63: refused, file unchanged.
	{
		var loaded = try config.load(gpa, io, tmp.path);
		defer loaded.deinit();
		const remap_arr = &(try loaded.network()).object.getPtr("remap").?.array;
		const r = (try replaceRemapsAndSave(gpa, io, tmp.path, remap_arr, &pairs, &loaded)) orelse return error.TestUnexpectedResult;
		try std.testing.expectEqual(error.RemapTableFull, r.err);
		const now = try readWholeFile(gpa, io, tmp.path);
		defer gpa.free(now);
		try std.testing.expectEqualSlices(u8, saved, now);
	}

	// And `remap add` still saves one that fits: the guard sits in front of the
	// save, it does not replace it.
	{
		var loaded = try config.load(gpa, io, tmp.path);
		defer loaded.deinit();
		const remap_arr = &(try loaded.network()).object.getPtr("remap").?.array;
		try std.testing.expect((try replaceRemapsAndSave(gpa, io, tmp.path, remap_arr, full[0..1], &loaded)) == null);
		try std.testing.expect((try addRemapAndSave(gpa, io, tmp.path, remap_arr, .{ .from = over.from, .to = over.to }, &loaded)) == null);
	}
	{
		var loaded = try config.load(gpa, io, tmp.path);
		defer loaded.deinit();
		const remap_arr = &(try loaded.network()).object.getPtr("remap").?.array;
		try std.testing.expectEqual(@as(usize, 2), remap_arr.items.len);
		try std.testing.expectEqualStrings(over.from, remap_arr.items[1].object.get("from").?.string);
	}
}
