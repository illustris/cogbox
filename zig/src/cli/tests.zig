//! Test aggregator for cogbox CLI verbs.
//!
//! Rooted at src/cli/ (not inside verbs/) so that verb files which reach up to
//! ../util.zig, ../parse.zig, etc. resolve within the module root. Each
//! `_ = @import(...)` pulls that file's `test` blocks into the test binary.

test {
    _ = @import("launch.zig");
    _ = @import("verbs/ssh.zig");
    _ = @import("verbs/status.zig");
    _ = @import("verbs/stop.zig");
    _ = @import("verbs/claude_stub.zig");
    _ = @import("verbs/secret.zig");
}
