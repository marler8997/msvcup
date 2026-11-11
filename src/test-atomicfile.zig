//! Processes race for many files with AtomicFile, arriving at nearly the same time, doing every
//! way a holder can finish. Each file's final content has to be whole and from one writer, and
//! only finished files can be left at the end.
//!
//! Usage: test-atomicfile WORK_DIR

const process_count = 8;
const round_count = 150;
const round_ms = 12;
const content_len = 8192;

pub fn main(init: std.process.Init.Minimal) !void {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const arena = arena_instance.allocator();
    var threaded: std.Io.Threaded = .init(arena, .{ .environ = init.environ, .argv0 = .init(init.args) });
    defer threaded.deinit();
    const io = threaded.io();
    const args = try init.args.toSlice(arena);
    (try std.Thread.spawn(.{}, watchdog, .{io})).detach();
    if (args.len == 5 and std.mem.eql(u8, args[1], "child")) {
        return child(io, arena, args[2], try std.fmt.parseInt(i64, args[3], 10), try std.fmt.parseInt(u8, args[4], 10));
    }
    if (args.len != 2) fail("expected WORK_DIR but got {} args", .{args.len - 1});

    try std.Io.Dir.cwd().deleteTree(io, args[1]);
    var work_dir = try std.Io.Dir.cwd().createDirPathOpen(io, args[1], .{ .open_options = .{ .iterate = true } });
    defer work_dir.close(io);
    const work_path = try work_dir.realPathFileAlloc(io, ".", arena);

    try testOneProcess(io, arena, work_dir, work_path);

    const start_ms = try std.fmt.allocPrint(arena, "{}", .{milliTimestamp(io) + 400});
    var children: [process_count]std.process.Child = undefined;
    for (&children, 0..) |*c, i| {
        c.* = try std.process.spawn(io, .{
            .argv = &.{ args[0], "child", work_path, start_ms, try std.fmt.allocPrint(arena, "{}", .{i}) },
        });
    }
    for (&children) |*c| {
        const term = try c.wait(io);
        if (term != .exited or term.exited != 0) fail("child failed with {}", .{term});
    }

    var final_count: u32 = 0;
    var it = work_dir.iterate();
    while (try it.next(io)) |entry| {
        // nothing in this test exits without calling deinit
        if (std.mem.endsWith(u8, entry.name, ".fetching")) fail("'{s}' was left behind", .{entry.name});
        if (std.mem.endsWith(u8, entry.name, ".holder")) fail("'{s}' was left behind", .{entry.name});
        expectWhole(io, work_dir, entry.name);
        final_count += 1;
    }
    if (final_count == 0) fail("nothing was created", .{});
}

/// What a holder can rely on, without any other process involved.
fn testOneProcess(io: std.Io, arena: std.mem.Allocator, work_dir: std.Io.Dir, work_path: []const u8) !void {
    try work_dir.createDir(io, "one", .default_dir);
    const tmp = try std.Io.Dir.path.join(arena, &.{ work_path, "one", "f.fetching" });
    const dest = try std.Io.Dir.path.join(arena, &.{ work_path, "one", "f" });

    // what a process that died left behind doesn't end up in the file
    try work_dir.writeFile(io, .{ .sub_path = "one/f.fetching", .data = "left by a process that died" });
    var leftover = (try AtomicFile.lock(io, tmp, dest)).locked;
    if (try leftover.file.length(io) != 0) fail("lock didn't truncate what was left in the file", .{});

    // holding the lock can't stop others reading the file, it could already be the destination
    try leftover.file.writeStreamingAll(io, "content");
    {
        var buf: [20]u8 = undefined;
        const content = work_dir.readFile(io, "one/f.fetching", &buf) catch |e|
            fail("reading a file with the lock held failed with {t}", .{e});
        if (!std.mem.eql(u8, content, "content")) fail("read '{s}' with the lock held", .{content});
    }

    // giving up leaves nothing behind
    leftover.deinit(io);
    expectMissing(io, work_dir, "one/f.fetching", "deinit left the file behind");

    // a failed rename leaves the holder able to give up, and doesn't get in the way of the next one
    {
        const missing_dir_dest = try std.Io.Dir.path.join(arena, &.{ work_path, "one", "missing", "f" });
        var atomic_file = (try AtomicFile.lock(io, tmp, dest)).locked;
        // finish logs the failure, which is what it should do
        std.debug.print("info: expecting one failed rename to be logged\n", .{});
        if (atomic_file.finish(io, missing_dir_dest)) |_| {
            fail("finish to a missing directory succeeded", .{});
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => |e| fail("finish to a missing directory failed with {t}", .{e}),
        }
        atomic_file.deinit(io);
        expectMissing(io, work_dir, "one/f.fetching", "deinit left the file behind after finish failed");
        var next = (try AtomicFile.lock(io, tmp, dest)).locked;
        next.deinit(io);
    }

    // nothing to do if the destination exists, and that leaves nothing behind either
    try work_dir.writeFile(io, .{ .sub_path = "one/f", .data = "finished" });
    if ((try AtomicFile.lock(io, tmp, dest)) != .exists) fail("lock didn't notice the destination", .{});
    expectMissing(io, work_dir, "one/f.fetching", "lock left the file behind when the destination exists");
    try work_dir.deleteTree(io, "one");
}

const Finish = enum {
    /// to the destination that was given to lock
    dest,
    /// to some other name, what happens with a SHA mismatch
    other_name,
    /// not at all, deinit deletes it
    abort,
};

fn child(io: std.Io, arena: std.mem.Allocator, work_path: []const u8, start_ms: i64, id: u8) !void {
    var prng = std.Random.DefaultPrng.init(@as(u64, @truncate(@as(u96, @bitCast(nanoTimestamp(io))))) ^ id);
    const rand = prng.random();
    for (0..round_count) |round| {
        const when = start_ms + @as(i64, @intCast(round)) * round_ms;
        const now = milliTimestamp(io);
        if (when > now) try io.sleep(.fromMilliseconds(when - now), .awake);
        // spread the arrivals out a bit, they all land inside each other's critical sections
        const until = nanoTimestamp(io) + rand.intRangeLessThan(i64, 0, 6000) * std.time.ns_per_us;
        while (nanoTimestamp(io) < until) {}

        var round_arena_instance = std.heap.ArenaAllocator.init(arena);
        defer round_arena_instance.deinit();
        const a = round_arena_instance.allocator();
        const dest = try std.Io.Dir.path.join(a, &.{ work_path, try std.fmt.allocPrint(a, "r{}", .{round}) });
        const tmp = try std.fmt.allocPrint(a, "{s}.fetching", .{dest});
        const holder = try std.fmt.allocPrint(a, "{s}.holder", .{dest});

        // every other round has no destination, like "msvcup fetch" which doesn't know the name
        // until it has downloaded the file
        const has_dest = round % 2 == 0;
        if (has_dest) {
            if (std.Io.Dir.cwd().access(io, dest, .{})) {
                expectWhole(io, .cwd(), dest);
                continue;
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => |e| fail("access '{s}' failed with {t}", .{ dest, e }),
            }
        }
        var atomic_file = switch (try AtomicFile.lock(io, tmp, if (has_dest) dest else null)) {
            .exists => {
                expectWhole(io, .cwd(), dest);
                continue;
            },
            .locked => |locked| locked,
        };
        defer atomic_file.deinit(io);

        // this exclusive create failing means someone else thinks they have the lock
        const holder_file = std.Io.Dir.cwd().createFile(io, holder, .{ .exclusive = true }) catch |e|
            fail("two processes have the lock on '{s}': {t}", .{ tmp, e });
        holder_file.close(io);

        var content: [content_len]u8 = undefined;
        @memset(&content, 'a' + id);
        try atomic_file.file.writeStreamingAll(io, &content);

        try std.Io.Dir.cwd().deleteFile(io, holder);
        const finish: Finish = if (has_dest) switch (rand.uintLessThan(u8, 10)) {
            0 => .abort,
            1 => .other_name,
            else => .dest,
        } else .other_name;
        switch (finish) {
            .dest => try atomic_file.finish(io, dest),
            .other_name => try atomic_file.finish(io, try std.fmt.allocPrint(a, "{s}.other{}-{}", .{ dest, id, rand.int(u32) })),
            .abort => {},
        }
    }
}

fn expectMissing(io: std.Io, dir: std.Io.Dir, path: []const u8, message: []const u8) void {
    if (dir.access(io, path, .{})) {
        fail("{s}", .{message});
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => |e| fail("access '{s}' failed with {t}", .{ path, e }),
    }
}

/// Has to be the full length with every byte from one writer.
fn expectWhole(io: std.Io, dir: std.Io.Dir, path: []const u8) void {
    var buf: [content_len + 1]u8 = undefined;
    const content = dir.readFile(io, path, &buf) catch |e| fail("read '{s}' failed with {t}", .{ path, e });
    if (content.len != content_len) fail("'{s}' is {} bytes, expected {}", .{ path, content.len, content_len });
    for (content) |c| {
        if (c != content[0]) fail("'{s}' has content from multiple writers", .{path});
    }
}

/// A bug here could easily be a hang, this fails with a clear message rather than waiting for CI
/// to time out.
fn watchdog(io: std.Io) void {
    io.sleep(.fromSeconds(120), .awake) catch {};
    fail("still running after 120 seconds", .{});
}

fn nanoTimestamp(io: std.Io) i96 {
    return std.Io.Clock.real.now(io).toNanoseconds();
}

fn milliTimestamp(io: std.Io) i64 {
    return std.Io.Clock.real.now(io).toMilliseconds();
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("error: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

const std = @import("std");
const AtomicFile = @import("AtomicFile.zig");
