const std = @import("std");

// refAllDecls(main) forces full analysis of the proxy's server code (so its
// compile errors surface in `zig build test`, not just at exe link) and pulls
// in tls.zig + http.zig so their unit tests run.
test {
	std.testing.refAllDecls(@import("main.zig"));
	std.testing.refAllDecls(@import("tls.zig"));
	std.testing.refAllDecls(@import("http.zig"));
	_ = @import("redirect_test.zig"); // Part 2 redirect/raw-L4 conformance tests
	_ = @import("path_vectors_test.zig"); // shared Zig<->addon path-matcher vectors
	_ = @import("reload_test.zig"); // netfilter-rules torn-read contract
}
