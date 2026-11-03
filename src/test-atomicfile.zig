//! Processes race for many files with AtomicFile, arriving at nearly the same time, doing every
//! way a holder can finish. Each file's final content has to be whole and from one writer, and
//! only finished files can be left at the end.
//!
//! Usage: test-atomicfile WORK_DIR

const process_count = 8;
const round_count = 150;
const round_ms = 12;
const content_len = 8192;

pub fn main() !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_instance.allocator();
    const args = try std.process.argsAlloc(arena);
    (try std.Thread.spawn(.{}, watchdog, .{})).detach();
    if (args.len == 5 and std.mem.eql(u8, args[1], "child")) {
        return child(arena, args[2], try std.fmt.parseInt(i64, args[3], 10), try std.fmt.parseInt(u8, args[4], 10));
    }
    if (args.len != 2) fail("expected WORK_DIR but got {} args", .{args.len - 1});

    try std.fs.cwd().deleteTree(args[1]);
    var work_dir = try std.fs.cwd().makeOpenPath(args[1], .{ .iterate = true });
    defer work_dir.close();
    const work_path = try work_dir.realpathAlloc(arena, ".");

    try testOneProcess(arena, work_dir, work_path);

    const start_ms = try std.fmt.allocPrint(arena, "{}", .{std.time.milliTimestamp() + 400});
    var children: [process_count]std.process.Child = undefined;
    for (&children, 0..) |*c, i| {
        c.* = .init(&.{ args[0], "child", work_path, start_ms, try std.fmt.allocPrint(arena, "{}", .{i}) }, arena);
        try c.spawn();
    }
    for (&children) |*c| {
        const term = try c.wait();
        if (term != .Exited or term.Exited != 0) fail("child failed with {}", .{term});
    }

    var final_count: u32 = 0;
    var it = work_dir.iterate();
    while (try it.next()) |entry| {
        // nothing in this test exits without calling deinit
        if (std.mem.endsWith(u8, entry.name, ".fetching")) fail("'{s}' was left behind", .{entry.name});
        if (std.mem.endsWith(u8, entry.name, ".holder")) fail("'{s}' was left behind", .{entry.name});
        expectWhole(work_dir, entry.name);
        final_count += 1;
    }
    if (final_count == 0) fail("nothing was created", .{});
}

/// What a holder can rely on, without any other process involved.
fn testOneProcess(arena: std.mem.Allocator, work_dir: std.fs.Dir, work_path: []const u8) !void {
    try work_dir.makeDir("one");
    const tmp = try std.fs.path.join(arena, &.{ work_path, "one", "f.fetching" });
    const dest = try std.fs.path.join(arena, &.{ work_path, "one", "f" });

    // what a process that died left behind doesn't end up in the file
    try work_dir.writeFile(.{ .sub_path = "one/f.fetching", .data = "left by a process that died" });
    var leftover = (try AtomicFile.lock(tmp, dest)).locked;
    if (try leftover.file.getEndPos() != 0) fail("lock didn't truncate what was left in the file", .{});

    // holding the lock can't stop others reading the file, it could already be the destination
    try leftover.file.writeAll("content");
    {
        var buf: [20]u8 = undefined;
        const content = work_dir.readFile("one/f.fetching", &buf) catch |e|
            fail("reading a file with the lock held failed with {s}", .{@errorName(e)});
        if (!std.mem.eql(u8, content, "content")) fail("read '{s}' with the lock held", .{content});
    }

    // giving up leaves nothing behind
    leftover.deinit();
    expectMissing(work_dir, "one/f.fetching", "deinit left the file behind");

    // a failed rename leaves the holder able to give up, and doesn't get in the way of the next one
    {
        const missing_dir_dest = try std.fs.path.join(arena, &.{ work_path, "one", "missing", "f" });
        var atomic_file = (try AtomicFile.lock(tmp, dest)).locked;
        // finish logs the failure, which is what it should do
        std.debug.print("info: expecting one failed rename to be logged\n", .{});
        if (atomic_file.finish(missing_dir_dest)) |_| {
            fail("finish to a missing directory succeeded", .{});
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => |e| fail("finish to a missing directory failed with {s}", .{@errorName(e)}),
        }
        atomic_file.deinit();
        expectMissing(work_dir, "one/f.fetching", "deinit left the file behind after finish failed");
        var next = (try AtomicFile.lock(tmp, dest)).locked;
        next.deinit();
    }

    // nothing to do if the destination exists, and that leaves nothing behind either
    try work_dir.writeFile(.{ .sub_path = "one/f", .data = "finished" });
    if ((try AtomicFile.lock(tmp, dest)) != .exists) fail("lock didn't notice the destination", .{});
    expectMissing(work_dir, "one/f.fetching", "lock left the file behind when the destination exists");
    try work_dir.deleteTree("one");
}

const Finish = enum {
    /// to the destination that was given to lock
    dest,
    /// to some other name, what happens with a SHA mismatch
    other_name,
    /// not at all, deinit deletes it
    abort,
};

fn child(arena: std.mem.Allocator, work_path: []const u8, start_ms: i64, id: u8) !void {
    var prng = std.Random.DefaultPrng.init(@as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())))) ^ id);
    const rand = prng.random();
    for (0..round_count) |round| {
        const when = start_ms + @as(i64, @intCast(round)) * round_ms;
        const now = std.time.milliTimestamp();
        if (when > now) std.Thread.sleep(@intCast((when - now) * std.time.ns_per_ms));
        // spread the arrivals out a bit, they all land inside each other's critical sections
        const until = std.time.nanoTimestamp() + rand.intRangeLessThan(i64, 0, 6000) * std.time.ns_per_us;
        while (std.time.nanoTimestamp() < until) {}

        var round_arena_instance = std.heap.ArenaAllocator.init(arena);
        defer round_arena_instance.deinit();
        const a = round_arena_instance.allocator();
        const dest = try std.fs.path.join(a, &.{ work_path, try std.fmt.allocPrint(a, "r{}", .{round}) });
        const tmp = try std.fmt.allocPrint(a, "{s}.fetching", .{dest});
        const holder = try std.fmt.allocPrint(a, "{s}.holder", .{dest});

        // every other round has no destination, like "msvcup fetch" which doesn't know the name
        // until it has downloaded the file
        const has_dest = round % 2 == 0;
        if (has_dest) {
            if (std.fs.cwd().access(dest, .{})) {
                expectWhole(std.fs.cwd(), dest);
                continue;
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => |e| fail("access '{s}' failed with {s}", .{ dest, @errorName(e) }),
            }
        }
        var atomic_file = switch (try AtomicFile.lock(tmp, if (has_dest) dest else null)) {
            .exists => {
                expectWhole(std.fs.cwd(), dest);
                continue;
            },
            .locked => |locked| locked,
        };
        defer atomic_file.deinit();

        // this exclusive create failing means someone else thinks they have the lock
        const holder_file = std.fs.cwd().createFile(holder, .{ .exclusive = true }) catch |e|
            fail("two processes have the lock on '{s}': {s}", .{ tmp, @errorName(e) });
        holder_file.close();

        var content: [content_len]u8 = undefined;
        @memset(&content, 'a' + id);
        try atomic_file.file.writeAll(&content);

        try std.fs.cwd().deleteFile(holder);
        const finish: Finish = if (has_dest) switch (rand.uintLessThan(u8, 10)) {
            0 => .abort,
            1 => .other_name,
            else => .dest,
        } else .other_name;
        switch (finish) {
            .dest => try atomic_file.finish(dest),
            .other_name => try atomic_file.finish(try std.fmt.allocPrint(a, "{s}.other{}-{}", .{ dest, id, rand.int(u32) })),
            .abort => {},
        }
    }
}

fn expectMissing(dir: std.fs.Dir, path: []const u8, message: []const u8) void {
    if (dir.access(path, .{})) {
        fail("{s}", .{message});
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => |e| fail("access '{s}' failed with {s}", .{ path, @errorName(e) }),
    }
}

/// Has to be the full length with every byte from one writer.
fn expectWhole(dir: std.fs.Dir, path: []const u8) void {
    var buf: [content_len + 1]u8 = undefined;
    const content = dir.readFile(path, &buf) catch |e| fail("read '{s}' failed with {s}", .{ path, @errorName(e) });
    if (content.len != content_len) fail("'{s}' is {} bytes, expected {}", .{ path, content.len, content_len });
    for (content) |c| {
        if (c != content[0]) fail("'{s}' has content from multiple writers", .{path});
    }
}

/// A bug here could easily be a hang, this fails with a clear message rather than waiting for CI
/// to time out.
fn watchdog() void {
    std.Thread.sleep(120 * std.time.ns_per_s);
    fail("still running after 120 seconds", .{});
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("error: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

const std = @import("std");
const AtomicFile = @import("AtomicFile.zig");
