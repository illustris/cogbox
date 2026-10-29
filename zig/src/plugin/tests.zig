// Aggregator file pulling unit tests from every module.
// Run via `zig build test`.

const std = @import("std");

test {
	std.testing.refAllDecls(@import("cli.zig"));
	std.testing.refAllDecls(@import("name.zig"));
	std.testing.refAllDecls(@import("compose.zig"));
	std.testing.refAllDecls(@import("mutate.zig"));
	std.testing.refAllDecls(@import("units.zig"));
	std.testing.refAllDecls(@import("nix.zig"));
	std.testing.refAllDecls(@import("gitcred.zig"));
	std.testing.refAllDecls(@import("main.zig"));
	std.testing.refAllDecls(@import("snapshot.zig"));
	std.testing.refAllDecls(@import("preboot.zig"));
	_ = @import("name_test.zig");
	_ = @import("compose_test.zig");
	_ = @import("mutate_test.zig");
	_ = @import("units_test.zig");
	_ = @import("nix_test.zig");
	_ = @import("main.zig");
	_ = @import("snapshot.zig");
	_ = @import("preboot.zig");
}
