pub fn main() !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_instance.allocator();
    const args_array = try std.process.argsAlloc(arena);
    // no need to free, os will do it
    const all_args = if (args_array.len == 0) args_array else args_array[1..];
    if (all_args.len != 2) errExit("expected 2 cmdline args but got {}", .{all_args.len});
    const in_path = all_args[0];
    const out_path = all_args[1];

    const Payload = struct {
        url: []const u8,
        sha: []const u8,
        ex: extra.Payload,
    };
    var payloads: std.ArrayListUnmanaged(Payload) = .{};

    const in = try std.fs.cwd().readFileAlloc(arena, in_path, std.math.maxInt(usize));
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

    var out_file = try std.fs.cwd().createFile(out_path, .{});
    defer out_file.close();
    var buffered_writer = std.io.bufferedWriter(out_file.writer());
    const writer = &buffered_writer.writer();

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
    for (payloads.items) |payload| {
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
    try buffered_writer.flush();
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
