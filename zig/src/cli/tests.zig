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

test "CLI TCP and Unix sockets are close-on-exec" {
    const std = @import("std");
    for ([_]c_int{ std.posix.AF.INET, std.posix.AF.UNIX }) |domain| {
        const fd = try @import("platform").streamSocket(domain);
        defer _ = std.c.close(fd);
        const flags = std.c.fcntl(fd, std.posix.F.GETFD);
        try std.testing.expect(flags >= 0);
        try std.testing.expect(flags & std.posix.FD_CLOEXEC != 0);
    }
}
