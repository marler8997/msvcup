const Payload = struct {
    url: []const u8,
    sha: []const u8,
    ex: extra.Payload,
};

pub fn main(init: std.process.Init.Minimal) !void {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const arena = arena_instance.allocator();
    var threaded: std.Io.Threaded = .init(arena, .{ .environ = init.environ, .argv0 = .init(init.args) });
    defer threaded.deinit();
    const io = threaded.io();
    var args = try init.args.iterateAllocator(arena);
    _ = args.skip();
    const in_path = args.next() orelse errExit("expected 2 cmdline args but got 0", .{});
    const out_path = args.next() orelse errExit("expected 2 cmdline args but got 1", .{});
    if (args.next() != null) errExit("expected 2 cmdline args but got more", .{});

    var payloads: std.ArrayList(Payload) = .empty;

    const in = try std.Io.Dir.cwd().readFileAlloc(io, in_path, arena, .unlimited);
    var line_it = std.mem.tokenizeScalar(u8, in, '\n');
    var lineno: u32 = 0;
    while (line_it.next()) |url| {
        lineno += 1;
        if (url.len == 0) continue;
        const ex = switch (extra.parseUrl(url)) {
            .ok => |p| p,
            .unexpected => |u| std.debug.panic(
                "{s}:{d}: invalid package url '{s}' expected {s} at offset {} but got '{s}'",
                .{ in_path, lineno, url, u.what, u.offset, url[u.offset..] },
            ),
        };
        const sha = line_it.next() orelse std.debug.panic(
            "{s}:{d}: last URL is missing a hash",
            .{ in_path, lineno },
        );
        lineno += 1;
        if (sha.len != 64) std.debug.panic(
            "{s}:{d}: hash should be 64 hex chars but got {} '{s}'",
            .{ in_path, lineno, sha.len, sha },
        );
        try payloads.append(arena, .{ .url = url, .sha = sha, .ex = ex });
    }

    var out_file = try std.Io.Dir.cwd().createFile(io, out_path, .{});
    defer out_file.close(io);
    var out_file_buf: [1000]u8 = undefined;
    var out_file_writer = out_file.writer(io, &out_file_buf);
    writeCode(payloads.items, &out_file_writer.interface) catch |err| switch (err) {
        error.WriteFailed => return out_file_writer.err.?,
    };
}
fn writeCode(payloads: []const Payload, writer: *std.Io.Writer) error{WriteFailed}!void {
    try writer.writeAll(
        \\pub const Payload = struct {
        \\    url: []const u8,
        \\    sha256: [64]u8,
        \\};
        \\pub const Package = struct {
        \\    id: []const u8,
        \\    payloads: []const Payload,
        \\};
        \\
    );

    var end_pkg: []const u8 = "pub const all = [_]Package{";
    var current_pkg: ?extra.Package = null;
    var payload_sep: FirstOnce("", ", ") = .{};
    for (payloads) |payload| {
        if (!equalsPackage(payload.ex.package, current_pkg)) {
            try writer.print(
                "{s}.{{ .id = \"{s}-{s}\", .payloads = &.{{",
                .{ end_pkg, @tagName(payload.ex.package.kind), payload.ex.package.version },
            );
            end_pkg = "},},";
            current_pkg = payload.ex.package;
            payload_sep = .{};
        }
        try writer.print("{s}.{{\n", .{payload_sep.next()});
        try writer.print("    .url = \"{s}\",\n", .{payload.url});
        try writer.print("    .sha256 = \"{s}\".*,\n", .{payload.sha});
        try writer.print("}}", .{});
    }
    try writer.print("{s}}};\n", .{end_pkg});
    try writer.flush();
}

fn FirstOnce(comptime first: []const u8, comptime separator: []const u8) type {
    return struct {
        at_first: bool = true,
        const Self = @This();
        pub fn next(self: *Self) []const u8 {
            if (self.at_first) {
                self.at_first = false;
                return first;
            }
            return separator;
        }
    };
}

fn equalsPackage(a: extra.Package, maybe_b: ?extra.Package) bool {
    const b = maybe_b orelse return false;
    return a.kind == b.kind and std.mem.eql(u8, a.version, b.version);
}

fn errExit(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}

const std = @import("std");
const extra = @import("extra.zig");
