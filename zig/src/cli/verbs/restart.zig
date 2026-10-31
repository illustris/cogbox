// `cogbox restart` - stop then start.

const std = @import("std");
const util = @import("../util.zig");
const parse = @import("../parse.zig");
const help = @import("../help.zig");
const paths = @import("../paths.zig");
const stop = @import("stop.zig");
const start = @import("start.zig");

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	env: *std.process.Environ.Map,
	p: *const paths.Paths,
	argv: []const []const u8,
) !void {
	// Detect --help without consuming the rest of argv.
	for (argv) |a| {
		if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
			try help.print(io, help.RESTART);
			return;
		}
	}

	// stop accepts (--name [--force]); pass --name through if present, but
	// not --vcpu/--mem/--network/etc which stop's parser rejects.
	var stop_argv: std.ArrayList([]const u8) = .empty;
	defer stop_argv.deinit(allocator);
	var i: usize = 0;
	while (i < argv.len) : (i += 1) {
		const a = argv[i];
		if (std.mem.eql(u8, a, "--name") or std.mem.eql(u8, a, "-n")) {
			try stop_argv.append(allocator, a);
			i += 1;
			if (i < argv.len) try stop_argv.append(allocator, argv[i]);
		} else if (std.mem.startsWith(u8, a, "--name=") or std.mem.startsWith(u8, a, "-n=")) {
			try stop_argv.append(allocator, a);
		}
	}

	try stop.run(allocator, io, env, p, stop_argv.items);
	try start.run(allocator, io, env, p, argv);
}
