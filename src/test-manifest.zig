//! Tests how msvcup reads a VS manifest that's already in its data directory, which needs no
//! network access. msvcup is given a data directory inside WORK_DIR through the environment
//! variables it looks at on each system.
//!
//! Usage: test-manifest MSVCUP_EXE WORK_DIR

pub fn main(init: std.process.Init.Minimal) !void {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const arena = arena_instance.allocator();
    var threaded: std.Io.Threaded = .init(arena, .{ .environ = init.environ, .argv0 = .init(init.args) });
    defer threaded.deinit();
    const io = threaded.io();
    var args = try init.args.iterateAllocator(arena);
    _ = args.skip();
    const msvcup_arg = args.next() orelse fail("expected MSVCUP_EXE WORK_DIR", .{});
    const work_arg = args.next() orelse fail("expected MSVCUP_EXE WORK_DIR", .{});
    if (args.next() != null) fail("expected only MSVCUP_EXE WORK_DIR", .{});
    // msvcup runs in the work directory and the build gives us a relative path
    const msvcup_exe = try std.Io.Dir.cwd().realPathFileAlloc(io, msvcup_arg, arena);

    try std.Io.Dir.cwd().deleteTree(io, work_arg);
    var work_dir = try std.Io.Dir.cwd().createDirPathOpen(io, work_arg, .{});
    defer work_dir.close(io);
    const work_path = try work_dir.realPathFileAlloc(io, ".", arena);

    // where the data directory is on each system, see MsvcupDir in msvcup.zig
    const data_sub_path = switch (builtin.os.tag) {
        .windows => "localappdata/msvcup",
        .macos => "home/Library/Application Support/msvcup",
        else => "xdg/msvcup",
    };
    var env_map = try init.environ.createMap(arena);
    try env_map.put("LOCALAPPDATA", try std.fs.path.join(arena, &.{ work_path, "localappdata" }));
    try env_map.put("HOME", try std.fs.path.join(arena, &.{ work_path, "home" }));
    try env_map.put("XDG_DATA_HOME", try std.fs.path.join(arena, &.{ work_path, "xdg" }));

    const manifest_sub_path = try std.fs.path.join(arena, &.{ data_sub_path, "manifest", "vs-release", "latest" });
    try work_dir.createDirPath(io, std.fs.path.dirname(manifest_sub_path).?);

    const complete =
        \\{"packages":[{"id":"Microsoft.VisualCpp.DIA.SDK","version":"1.2.3","payloads":[
        \\{"fileName":"a.vsix","sha256":"0000000000000000000000000000000000000000000000000000000000000000",
        \\"size":1,"url":"https://example.com/a.vsix"}]}]}
    ;

    // this one shows that msvcup reads the manifest we wrote and not one from the real data
    // directory, without it the cases below could pass for the wrong reason
    {
        try work_dir.writeFile(io, .{ .sub_path = manifest_sub_path, .data = complete });
        const result = try list(io, arena, msvcup_exe, work_path, &env_map);
        if (result.term != .exited or result.term.exited != 0) fail("list failed with {}:\n{s}", .{ result.term, result.stderr });
        if (std.mem.indexOf(u8, result.stdout, "diasdk-1.2.3\n") == null) fail("list didn't print the package from the manifest:\n{s}", .{result.stdout});
        if (std.mem.indexOf(u8, result.stdout, "msvc-") != null) fail("list printed a package that isn't in the manifest:\n{s}", .{result.stdout});
    }

    // A manifest that was cut short, as a download that ended early without an error would
    // leave it, and an empty one. Both are an error that names the file.
    for ([_][]const u8{ complete[0 .. complete.len / 2], "" }) |content| {
        try work_dir.writeFile(io, .{ .sub_path = manifest_sub_path, .data = content });
        const result = try list(io, arena, msvcup_exe, work_path, &env_map);
        if (result.term != .exited or result.term.exited != 0xff) fail("expected list to fail with a {}-byte manifest but got {}:\n{s}", .{ content.len, result.term, result.stderr });
        for ([_][]const u8{ "latest", "not a VS manifest we can read", "delete it" }) |expected| {
            if (std.mem.indexOf(u8, result.stderr, expected) == null) fail("the error for a {}-byte manifest doesn't have '{s}':\n{s}", .{ content.len, expected, result.stderr });
        }
    }
}

fn list(
    io: std.Io,
    arena: std.mem.Allocator,
    msvcup_exe: []const u8,
    work_path: []const u8,
    env_map: *const std.process.Environ.Map,
) !std.process.RunResult {
    return std.process.run(arena, io, .{
        .cwd = .{ .path = work_path },
        .environ_map = env_map,
        .argv = &.{ msvcup_exe, "list" },
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("test-manifest: " ++ fmt ++ "\n", args);
    std.process.exit(0xff);
}

const builtin = @import("builtin");
const std = @import("std");
