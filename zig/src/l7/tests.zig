const std = @import("std");

test {
	std.testing.refAllDecls(@import("cli.zig"));
	std.testing.refAllDecls(@import("rule.zig"));
	std.testing.refAllDecls(@import("main.zig"));
}

/// The text of the function body that starts at `marker` (up to the next
/// top-level closing brace).
fn fnBody(src: []const u8, marker: []const u8) ![]const u8 {
	const start = std.mem.indexOf(u8, src, marker) orelse return error.TestUnexpectedResult;
	const end = std.mem.indexOfPos(u8, src, start, "\n}\n") orelse return error.TestUnexpectedResult;
	return src[start..end];
}

// Every mutating l7 verb must republish the guest's git host list after it
// saves config.json, so main.zig saves in exactly ONE place (saveAndPublish,
// which publishes after the save) and every verb goes through it. A verb that
// calls the save directly, or a wrapper that stops publishing, fails here.
test "l7 main.zig: every config save goes through saveAndPublish, which publishes" {
	const src = @embedFile("main.zig");
	const save = "config" ++ ".save(";
	const call = "try " ++ "saveAndPublish(";
	try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, src, save));
	// add, del, clear, replace, policy, set, mode. A new mutating verb bumps this
	// on purpose.
	try std.testing.expectEqual(@as(usize, 7), std.mem.count(u8, src, call));

	const wrapper = try fnBody(src, "fn " ++ "saveAndPublish(");
	const save_at = std.mem.indexOf(u8, wrapper, save) orelse return error.TestUnexpectedResult;
	const publish_at = std.mem.indexOf(u8, wrapper, "publishGitHosts(") orelse return error.TestUnexpectedResult;
	try std.testing.expect(save_at < publish_at);

	// cmdPolicy publishes before its not-running early return.
	const policy = try fnBody(src, "fn " ++ "cmdPolicy(");
	const call_at = std.mem.indexOf(u8, policy, call) orelse return error.TestUnexpectedResult;
	const access_at = std.mem.indexOf(u8, policy, "cwd.access(io, args.runtime_path") orelse return error.TestUnexpectedResult;
	try std.testing.expect(call_at < access_at);
}
