// Sysexits-style exit codes used across the cogbox CLI.
//
// Codes 64-78 follow sysexits.h conventions (BSD). The smaller codes
// 0/2/3 are cogbox-specific:
//   0  - success
//   2  - reserved for legacy Zig parse-error path (kept for compatibility
//        with anything still scripting against `cogbox-rules` exit 2)
//   3  - `status` reports a stopped instance, so `if cogbox status; ...`
//        works when "stopped" is the only difference from "running"
//
// A separate code for "unknown instance" would be useful but `status`
// already distinguishes it as exit 64 (EX_USAGE) since the user gave a
// name that doesn't resolve.

pub const ok: u8 = 0;
pub const status_stopped: u8 = 3;

pub const usage: u8 = 64; // EX_USAGE - bad CLI args, unknown verb, unknown flag
pub const dataerr: u8 = 65; // EX_DATAERR - bad CIDR, integer, name regex
pub const noinput: u8 = 66; // EX_NOINPUT - missing config.json
pub const unavailable: u8 = 69; // EX_UNAVAILABLE - a plugin change gave up waiting for a finishing live apply
pub const software: u8 = 70; // EX_SOFTWARE - internal error, runner failed, daemon timeout
pub const tempfail: u8 = 75; // EX_TEMPFAIL - already running, port collision
pub const config: u8 = 78; // EX_CONFIG - an automatic plugin rollback could not be finished
