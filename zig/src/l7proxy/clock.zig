// The l7proxy's monotonic clock, shared by the worker (main.zig: the
// classification-peek deadline) and the ECH-capability probe (echprobe.zig:
// the probe deadline and the result cache's TTLs). main.zig re-exports
// monotonicMs, so its callers and tests are unchanged.

const std = @import("std");

const c = @cImport({
	// Same preamble as main.zig's cImport (see the FORTIFY note there).
	@cDefine("_GNU_SOURCE", "1");
	@cDefine("_FORTIFY_SOURCE", "0");
	@cInclude("time.h"); // clock_gettime / struct timespec
});

// CLOCK_MONOTONIC uses different ABI values on Linux and Darwin.
const CLOCK_MONOTONIC: c_int = if (@import("platform").darwin) 6 else 1;

/// Monotonic milliseconds, used to bound the fast-path classification peek and
/// the ECH probe, and to age the probe cache. Monotonic (not wall-clock) so a
/// clock step can't lengthen or shorten either.
pub fn monotonicMs() i64 {
	var ts: c.struct_timespec = std.mem.zeroes(c.struct_timespec);
	_ = c.clock_gettime(CLOCK_MONOTONIC, &ts);
	return @as(i64, ts.tv_sec) * 1000 + @divTrunc(@as(i64, ts.tv_nsec), std.time.ns_per_ms);
}
