// Load and save cogbox config.json files. Preserves arbitrary fields on
// rule objects (specifically `comment`) by keeping the document as a
// std.json.Value tree and serializing it back with a jq --tab compatible
// pretty printer.

const std = @import("std");

pub const LoadError = error{
	FileNotFound,
	InvalidJson,
	NotInRulesMode,
	OutOfMemory,
};

pub const Loaded = struct {
	parsed: std.json.Parsed(std.json.Value),
	/// The config.json path this tree came from, duped into the tree's arena
	/// (so it frees with `deinit`). The secret-store directories are derived
	/// from this path (rules_module.resolveSecretDirs), so a reload path that
	/// only holds a `*Loaded` can still resolve the store -- without every
	/// verb dispatcher threading the path through to maybeReload.
	path: []const u8,

	pub fn deinit(self: *Loaded) void {
		self.parsed.deinit();
	}

	pub fn root(self: *Loaded) *std.json.Value {
		return &self.parsed.value;
	}

	/// Allocator tied to the parsed document's lifetime. New strings
	/// inserted into the tree should be duplicated via this allocator so
	/// they free with the rest of the document on `deinit`.
	pub fn treeAllocator(self: *Loaded) std.mem.Allocator {
		return self.parsed.arena.allocator();
	}

	/// Returns a pointer to .network.rules (an array). Errors if the
	/// instance is not in rules mode (network is "full" or "none").
	pub fn rules(self: *Loaded) !*std.json.Array {
		const r = self.root();
		if (r.* != .object) return error.InvalidJson;
		const net = r.object.getPtr("network") orelse return error.NotInRulesMode;
		switch (net.*) {
			.string => return error.NotInRulesMode,
			.object => |*obj| {
				const arr = obj.getPtr("rules") orelse return error.InvalidJson;
				if (arr.* != .array) return error.InvalidJson;
				return &arr.array;
			},
			else => return error.InvalidJson,
		}
	}

	/// Returns a pointer to the .network object itself (in rules mode).
	/// Used by verbs that need to read sibling sub-objects -- e.g. the
	/// remap verb wants to mutate .network.remap, but rule rendering also
	/// has to read .network.rules so neither sub-verb clobbers the other.
	pub fn network(self: *Loaded) !*std.json.Value {
		const r = self.root();
		if (r.* != .object) return error.InvalidJson;
		const net = r.object.getPtr("network") orelse return error.NotInRulesMode;
		if (net.* != .object) return error.NotInRulesMode;
		return net;
	}
};

pub fn load(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Loaded {
	const cwd = std.Io.Dir.cwd();
	const file = cwd.openFile(io, path, .{}) catch |err| switch (err) {
		error.FileNotFound => return error.FileNotFound,
		else => return err,
	};
	defer file.close(io);

	var read_buf: [8192]u8 = undefined;
	var reader = file.reader(io, &read_buf);
	const buf = try reader.interface.allocRemaining(allocator, .limited(1 << 20));
	defer allocator.free(buf);

	const parsed = std.json.parseFromSlice(std.json.Value, allocator, buf, .{}) catch {
		return error.InvalidJson;
	};
	return .{ .parsed = parsed, .path = try parsed.arena.allocator().dupe(u8, path) };
}

/// Atomically write `value` as jq --tab formatted JSON to `path`.
pub fn save(allocator: std.mem.Allocator, io: std.Io, path: []const u8, value: std.json.Value) !void {
	var out: std.ArrayList(u8) = .empty;
	defer out.deinit(allocator);
	try writeJqTab(allocator, &out, value);

	var nonce: [16]u8 = undefined;
	io.random(&nonce);
	const tmp_path = try std.fmt.allocPrint(allocator, "{s}.{x}.tmp", .{ path, nonce });
	defer allocator.free(tmp_path);

	const cwd = std.Io.Dir.cwd();
	defer cwd.deleteFile(io, tmp_path) catch {};
	{
		const f = try cwd.createFile(io, tmp_path, .{ .exclusive = true });
		defer f.close(io);
		var write_buf: [4096]u8 = undefined;
		var writer = f.writer(io, &write_buf);
		try writer.interface.writeAll(out.items);
		try writer.flush();
		try f.sync(io);
	}

	try cwd.rename(tmp_path, cwd, path, io);
}

/// jq --tab compatible pretty printer.
/// Format details (matched by inspection of jq output):
///   - tab indentation, one tab per level
///   - empty objects/arrays render as `{}` / `[]` on one line
///   - non-empty: opening brace, newline, members one per line, closing brace
///   - "key": value with a single space after the colon
///   - trailing newline at end of document
///   - object keys preserve insertion order (std.json.ObjectMap is ordered)
pub fn writeJqTab(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: std.json.Value) !void {
	try writeValue(allocator, out, value, 0);
	try out.append(allocator, '\n');
}

fn writeIndent(allocator: std.mem.Allocator, out: *std.ArrayList(u8), level: usize) !void {
	var i: usize = 0;
	while (i < level) : (i += 1) try out.append(allocator, '\t');
}

fn writeValue(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: std.json.Value, level: usize) !void {
	switch (value) {
		.null => try out.appendSlice(allocator, "null"),
		.bool => |b| try out.appendSlice(allocator, if (b) "true" else "false"),
		.integer => |i| {
			var buf: [32]u8 = undefined;
			const s = std.fmt.bufPrint(&buf, "{d}", .{i}) catch unreachable;
			try out.appendSlice(allocator, s);
		},
		.float => |f| {
			var buf: [64]u8 = undefined;
			const s = std.fmt.bufPrint(&buf, "{d}", .{f}) catch unreachable;
			try out.appendSlice(allocator, s);
		},
		.number_string => |s| try out.appendSlice(allocator, s),
		.string => |s| try writeJsonString(allocator, out, s),
		.array => |arr| {
			if (arr.items.len == 0) {
				try out.appendSlice(allocator, "[]");
				return;
			}
			try out.append(allocator, '[');
			try out.append(allocator, '\n');
			for (arr.items, 0..) |item, i| {
				try writeIndent(allocator, out, level + 1);
				try writeValue(allocator, out, item, level + 1);
				if (i + 1 < arr.items.len) try out.append(allocator, ',');
				try out.append(allocator, '\n');
			}
			try writeIndent(allocator, out, level);
			try out.append(allocator, ']');
		},
		.object => |obj| {
			if (obj.count() == 0) {
				try out.appendSlice(allocator, "{}");
				return;
			}
			try out.append(allocator, '{');
			try out.append(allocator, '\n');
			const total = obj.count();
			var it = obj.iterator();
			var i: usize = 0;
			while (it.next()) |entry| {
				try writeIndent(allocator, out, level + 1);
				try writeJsonString(allocator, out, entry.key_ptr.*);
				try out.appendSlice(allocator, ": ");
				try writeValue(allocator, out, entry.value_ptr.*, level + 1);
				if (i + 1 < total) try out.append(allocator, ',');
				try out.append(allocator, '\n');
				i += 1;
			}
			try writeIndent(allocator, out, level);
			try out.append(allocator, '}');
		},
	}
}

fn writeJsonString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
	try out.append(allocator, '"');
	for (s) |c| {
		switch (c) {
			'"' => try out.appendSlice(allocator, "\\\""),
			'\\' => try out.appendSlice(allocator, "\\\\"),
			'\n' => try out.appendSlice(allocator, "\\n"),
			'\r' => try out.appendSlice(allocator, "\\r"),
			'\t' => try out.appendSlice(allocator, "\\t"),
			0x08 => try out.appendSlice(allocator, "\\b"),
			0x0c => try out.appendSlice(allocator, "\\f"),
			0...0x07, 0x0b, 0x0e...0x1f => {
				var buf: [8]u8 = undefined;
				const esc = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c}) catch unreachable;
				try out.appendSlice(allocator, esc);
			},
			else => try out.append(allocator, c),
		}
	}
	try out.append(allocator, '"');
}
