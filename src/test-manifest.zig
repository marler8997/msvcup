//! Tests how msvcup reads a VS manifest that's already in its data directory, and the recipes
//! it's given for it, which needs no network access. msvcup is given a data directory inside WORK_DIR through the environment
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
        \\"size":1,"url":"http://127.0.0.1:1/a.vsix"}]},
        \\{"id":"Other.Tool","version":"4.5","payloads":[
        \\{"fileName":"b.vsix","sha256":"0000000000000000000000000000000000000000000000000000000000000000",
        \\"size":1,"url":"http://127.0.0.1:1/b.vsix"},
        \\{"fileName":"c.cab","sha256":"0000000000000000000000000000000000000000000000000000000000000000",
        \\"size":1,"url":"http://127.0.0.1:1/c.cab"}]}]}
    ;
    const a_line = "|http://127.0.0.1:1/a.vsix|0000000000000000000000000000000000000000000000000000000000000000\n";
    const b_line = "|http://127.0.0.1:1/b.vsix|0000000000000000000000000000000000000000000000000000000000000000\n";

    // this one shows that msvcup reads the manifest we wrote and not one from the real data
    // directory, without it the cases below could pass for the wrong reason
    {
        try work_dir.writeFile(io, .{ .sub_path = manifest_sub_path, .data = complete });
        const result = try msvcup(io, arena, msvcup_exe, work_path, &env_map, &.{"list"});
        if (result.term != .exited or result.term.exited != 0) fail("list failed with {}:\n{s}", .{ result.term, result.stderr });
        if (std.mem.indexOf(u8, result.stdout, "diasdk-1.2.3\n") == null) fail("list didn't print the package from the manifest:\n{s}", .{result.stdout});
        if (std.mem.indexOf(u8, result.stdout, "msvc-") != null) fail("list printed a package that isn't in the manifest:\n{s}", .{result.stdout});
    }

    // A manifest that was cut short, as a download that ended early without an error would
    // leave it, and an empty one. Both are an error that names the file.
    for ([_][]const u8{ complete[0 .. complete.len / 2], "" }) |content| {
        try work_dir.writeFile(io, .{ .sub_path = manifest_sub_path, .data = content });
        const result = try msvcup(io, arena, msvcup_exe, work_path, &env_map, &.{"list"});
        if (result.term != .exited or result.term.exited != 0xff) fail("expected list to fail with a {}-byte manifest but got {}:\n{s}", .{ content.len, result.term, result.stderr });
        for ([_][]const u8{ "latest", "not a VS manifest we can read", "delete it" }) |expected| {
            if (std.mem.indexOf(u8, result.stderr, expected) == null) fail("the error for a {}-byte manifest doesn't have '{s}':\n{s}", .{ content.len, expected, result.stderr });
        }
    }

    // Recipes from files, against the complete manifest.
    try work_dir.writeFile(io, .{ .sub_path = manifest_sub_path, .data = complete });
    const tool_rule = "-{version} id=Microsoft.VisualCpp.DIA.SDK version={version}\n";
    try work_dir.writeFile(io, .{ .sub_path = "tool.recipes", .data = "# a package only this file makes\ntool" ++ tool_rule });
    // a name longer than any buffer msvcup might format a package into
    const long_name: [300]u8 = @splat('a');
    try work_dir.writeFile(io, .{ .sub_path = "long.recipes", .data = &long_name ++ tool_rule });
    try work_dir.writeFile(io, .{ .sub_path = "bad.recipes", .data = "# comment\ntool-1 chip=x\n" });
    try work_dir.writeFile(io, .{ .sub_path = "empty.recipes", .data = "# only a comment\n" });
    // what some Windows editors and Windows PowerShell's redirection write
    try work_dir.writeFile(io, .{ .sub_path = "bom.recipes", .data = "\xEF\xBB\xBFtool" ++ tool_rule });
    try work_dir.writeFile(io, .{ .sub_path = "utf16.recipes", .data = "\xFF\xFEt\x00o\x00o\x00l\x00" });
    try work_dir.createDirPath(io, "dir.recipes");
    {
        const result = try msvcup(io, arena, msvcup_exe, work_path, &env_map, &.{ "list", "--no-builtin-recipes", "--add-recipes", "tool.recipes" });
        if (result.term != .exited or result.term.exited != 0) fail("list with tool.recipes failed with {}:\n{s}", .{ result.term, result.stderr });
        if (std.mem.indexOf(u8, result.stdout, "tool-1.2.3\n") == null) fail("list didn't print the package tool.recipes makes:\n{s}", .{result.stdout});
        if (std.mem.indexOf(u8, result.stdout, "diasdk-") != null) fail("list printed a builtin package with --no-builtin-recipes:\n{s}", .{result.stdout});
    }
    {
        const result = try msvcup(io, arena, msvcup_exe, work_path, &env_map, &.{ "list", "--no-builtin-recipes", "--add-recipes", "bom.recipes" });
        if (result.term != .exited or result.term.exited != 0) fail("list with bom.recipes failed with {}:\n{s}", .{ result.term, result.stderr });
        if (std.mem.indexOf(u8, result.stdout, "tool-1.2.3\n") == null) fail("list didn't print the package bom.recipes makes:\n{s}", .{result.stdout});
    }
    {
        const result = try msvcup(io, arena, msvcup_exe, work_path, &env_map, &.{ "list-payloads", "--no-builtin-recipes", "--add-recipes", "long.recipes" });
        if (result.term != .exited or result.term.exited != 0) fail("list-payloads with long.recipes failed with {}:\n{s}", .{ result.term, result.stderr });
        if (!std.mem.startsWith(u8, result.stdout, &long_name ++ "-1.2.3 ")) fail("list-payloads didn't print the package long.recipes makes:\n{s}", .{result.stdout});
    }
    // rules that select a payload msvcup can't install as their package
    try work_dir.writeFile(io, .{ .sub_path = "cab.recipes", .data = "extra-{version} version={version} fileName=c.cab\n" });
    try work_dir.writeFile(io, .{ .sub_path = "ninja.recipes", .data = "# not a ninja release\nninja-{version} version={version} fileName=b.vsix\n" });
    // lock files someone edited
    try work_dir.writeFile(io, .{ .sub_path = "recipe-last.lock", .data = "diasdk-1.2.3" ++ a_line ++ "no-builtin-recipes\n" });
    try work_dir.writeFile(io, .{ .sub_path = "bad-recipe.lock", .data = "recipe diasdk-1 chip=x\ndiasdk-1.2.3" ++ a_line });
    try work_dir.writeFile(io, .{ .sub_path = "autoenv-payload.lock", .data = "autoenv" ++ a_line });
    // each is an error, not a panic, that says which file and what's wrong with it
    for ([_]struct { args: []const []const u8, expected: []const []const u8 }{
        .{
            .args = &.{ "install", "out", "extra-4.5", "--manifest-update-off", "--lock-file", "cab.lock", "--add-recipes", "cab.recipes" },
            .expected = &.{ "cab.recipes:1: selects payload 'c.cab' of package 'Other.Tool'", "select the msi" },
        },
        .{
            .args = &.{ "install", "out", "ninja-4.5", "--manifest-update-off", "--lock-file", "ninja.lock", "--no-builtin-recipes", "--add-recipes", "ninja.recipes" },
            .expected = &.{ "ninja.recipes:2: selects payload 'b.vsix' of package 'Other.Tool'", "a ninja payload's url must have " },
        },
        .{
            .args = &.{ "install", "out", "diasdk-1.2.3", "--manifest-update-off", "--lock-file", "recipe-last.lock" },
            .expected = &.{"recipe-last.lock:2: the recipes must come before the payloads"},
        },
        .{
            .args = &.{ "install", "out", "diasdk-1.2.3", "--manifest-update-off", "--lock-file", "bad-recipe.lock" },
            .expected = &.{"bad-recipe.lock:1: invalid recipe: unknown predicate"},
        },
        .{
            .args = &.{ "install", "out", "diasdk-1.2.3", "--manifest-update-off", "--lock-file", "autoenv-payload.lock" },
            .expected = &.{"autoenv-payload.lock:1: invalid msvcup pkg 'autoenv'"},
        },
        // the payload the builtin recipes give to diasdk
        .{ .args = &.{ "list", "--add-recipes", "tool.recipes" }, .expected = &.{ "matches multiple rules", "builtin recipes.txt:", "tool.recipes:2" } },
        .{ .args = &.{ "list", "--add-recipes", "bad.recipes" }, .expected = &.{ "bad.recipes:2: ", "unknown predicate" } },
        .{ .args = &.{ "list", "--add-recipes", "empty.recipes" }, .expected = &.{ "empty.recipes", "has no rules" } },
        .{ .args = &.{ "list", "--add-recipes", "utf16.recipes" }, .expected = &.{ "utf16.recipes:1: ", "is UTF-16" } },
        .{ .args = &.{ "list", "--add-recipes", "missing.recipes" }, .expected = &.{ "missing.recipes", "FileNotFound" } },
        .{ .args = &.{ "list", "--add-recipes", "dir.recipes" }, .expected = &.{"recipes 'dir.recipes' failed with "} },
        .{ .args = &.{ "list", "--add-recipes" }, .expected = &.{"--add-recipes missing argument"} },
        .{ .args = &.{ "list", "--no-builtin-recipes" }, .expected = &.{"leaves no recipes"} },
        .{
            .args = &.{ "install", "out", "other-1.2.3", "--manifest-update-off", "--no-builtin-recipes", "--add-recipes", "tool.recipes" },
            .expected = &.{ "unknown package 'other-1.2.3'", "no recipe makes it" },
        },
    }) |case| {
        const result = try msvcup(io, arena, msvcup_exe, work_path, &env_map, case.args);
        const cmdline = try std.mem.join(arena, " ", case.args);
        if (result.term != .exited or result.term.exited != 0xff) fail("expected 'msvcup {s}' to exit with 255 but got {}:\n{s}", .{ cmdline, result.term, result.stderr });
        for (case.expected) |expected| {
            if (std.mem.indexOf(u8, result.stderr, expected) == null) fail("the error of 'msvcup {s}' doesn't have '{s}':\n{s}", .{ cmdline, expected, result.stderr });
        }
    }

    // The lock file records the recipes it was made with and is only used with the same ones.
    // Every install here fails, nothing listens where the manifest says the payload is, but
    // that's after the lock file is checked and if it's not used, written again.
    try work_dir.writeFile(io, .{ .sub_path = "spaced.recipes", .data = "\n# the same rule as tool.recipes\n  tool-{version}   version={version}   id=Microsoft.VisualCpp.DIA.SDK\n" });
    try work_dir.writeFile(io, .{ .sub_path = "other.recipes", .data = "tool-{version} version={version} \"fileName=a.vsix\"\n" });
    try work_dir.writeFile(io, .{ .sub_path = "diasdk.recipes", .data = "diasdk-{version} version={version} fileName=a.vsix\n" });
    try work_dir.writeFile(io, .{ .sub_path = "extra.recipes", .data = "extra-{version} id=Other.Tool version={version} fileName=b.vsix\n" });
    const tool_lock = "no-builtin-recipes\nrecipe tool" ++ tool_rule ++ "tool-1.2.3" ++ a_line;
    const extra_lock = "recipe extra-{version} id=Other.Tool version={version} fileName=b.vsix\nextra-4.5" ++ b_line;
    // `not_used` is why msvcup says it's writing the lock file again, null if it uses it
    for ([_]struct { pkg: []const u8, recipe_args: []const []const u8, not_used: ?[]const u8, lock: []const u8 }{
        .{ .pkg = "tool-1.2.3", .recipe_args = &.{ "--no-builtin-recipes", "--add-recipes", "tool.recipes" }, .not_used = "lock file NOT found", .lock = tool_lock },
        .{ .pkg = "tool-1.2.3", .recipe_args = &.{ "--no-builtin-recipes", "--add-recipes", "tool.recipes" }, .not_used = null, .lock = tool_lock },
        // comments, spacing and the order of a rule's predicates aren't a different rule
        .{ .pkg = "tool-1.2.3", .recipe_args = &.{ "--no-builtin-recipes", "--add-recipes", "spaced.recipes" }, .not_used = null, .lock = tool_lock },
        .{
            .pkg = "tool-1.2.3",
            .recipe_args = &.{ "--no-builtin-recipes", "--add-recipes", "other.recipes" },
            .not_used = "lock file was made with different --add-recipes rules",
            .lock = "no-builtin-recipes\nrecipe tool-{version} version={version} fileName=a.vsix\ntool-1.2.3" ++ a_line,
        },
        // the same package from the builtin recipes and from a file's
        .{ .pkg = "diasdk-1.2.3", .recipe_args = &.{}, .not_used = "lock file was made with different --add-recipes rules", .lock = "diasdk-1.2.3" ++ a_line },
        .{ .pkg = "diasdk-1.2.3", .recipe_args = &.{}, .not_used = null, .lock = "diasdk-1.2.3" ++ a_line },
        .{
            .pkg = "diasdk-1.2.3",
            .recipe_args = &.{ "--no-builtin-recipes", "--add-recipes", "diasdk.recipes" },
            .not_used = "lock file was made with msvcup's builtin recipes",
            .lock = "no-builtin-recipes\nrecipe diasdk-{version} version={version} fileName=a.vsix\ndiasdk-1.2.3" ++ a_line,
        },
        // the same rules with and without the builtin recipes
        .{ .pkg = "extra-4.5", .recipe_args = &.{ "--add-recipes", "extra.recipes" }, .not_used = "lock file was made with different --add-recipes rules", .lock = extra_lock },
        .{ .pkg = "extra-4.5", .recipe_args = &.{ "--add-recipes", "extra.recipes" }, .not_used = null, .lock = extra_lock },
        .{
            .pkg = "extra-4.5",
            .recipe_args = &.{ "--no-builtin-recipes", "--add-recipes", "extra.recipes" },
            .not_used = "lock file was made with msvcup's builtin recipes",
            .lock = "no-builtin-recipes\n" ++ extra_lock,
        },
        .{ .pkg = "extra-4.5", .recipe_args = &.{ "--no-builtin-recipes", "--add-recipes", "extra.recipes" }, .not_used = null, .lock = "no-builtin-recipes\n" ++ extra_lock },
        .{ .pkg = "extra-4.5", .recipe_args = &.{ "--add-recipes", "extra.recipes" }, .not_used = "lock file was made without msvcup's builtin recipes", .lock = extra_lock },
    }) |case| {
        const argv = try std.mem.concat(arena, []const u8, &.{ &.{ "install", "out", case.pkg, "--manifest-update-off", "--lock-file", "recipes.lock" }, case.recipe_args });
        const cmdline = try std.mem.join(arena, " ", argv);
        const result = try msvcup(io, arena, msvcup_exe, work_path, &env_map, argv);
        if (result.term != .exited or result.term.exited == 0) fail("expected 'msvcup {s}' to fail downloading but got {}:\n{s}", .{ cmdline, result.term, result.stderr });
        if (std.mem.indexOf(u8, result.stderr, "fetch: http://127.0.0.1:1/") == null) fail("'msvcup {s}' didn't get to downloading the payload:\n{s}", .{ cmdline, result.stderr });
        // msvcup only says how many payloads it selected when it writes the lock file
        const wrote_lock = std.mem.indexOf(u8, result.stderr, "1 payloads:") != null;
        if (case.not_used) |why| {
            if (std.mem.indexOf(u8, result.stderr, why) == null) fail("'msvcup {s}' didn't say '{s}':\n{s}", .{ cmdline, why, result.stderr });
            if (!wrote_lock) fail("'msvcup {s}' didn't write the lock file again:\n{s}", .{ cmdline, result.stderr });
        } else if (wrote_lock) {
            fail("'msvcup {s}' didn't use the lock file:\n{s}", .{ cmdline, result.stderr });
        }
        const lock = try work_dir.readFileAlloc(io, "recipes.lock", arena, .limited(1024 * 1024));
        if (!std.mem.eql(u8, case.lock, lock)) fail("after 'msvcup {s}' the lock file is:\n{s}\nbut expected:\n{s}", .{ cmdline, lock, case.lock });
    }
}

fn msvcup(
    io: std.Io,
    arena: std.mem.Allocator,
    msvcup_exe: []const u8,
    work_path: []const u8,
    env_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !std.process.RunResult {
    return std.process.run(arena, io, .{
        .cwd = .{ .path = work_path },
        .environ_map = env_map,
        .argv = try std.mem.concat(arena, []const u8, &.{ &.{msvcup_exe}, args }),
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
