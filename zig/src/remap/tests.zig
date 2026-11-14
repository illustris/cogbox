const std = @import("std");

test {
	std.testing.refAllDecls(@import("cli.zig"));
	std.testing.refAllDecls(@import("rule.zig"));
	// The verb itself: its add/set guard tests (main.zig reaches the rules module).
	_ = @import("main.zig");
}
