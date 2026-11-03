//! Checks that LockFile lets only one process in at a time. Processes take turns incrementing a
//! counter in a file while holding the lock, if two ever hold it together then an increment gets
//! lost and the count comes up short.
//!
//! Usage: test-lockfile WORK_DIR

const process_count = 8;
const increments_per_process = 200;

pub fn main() !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_instance.allocator();
    const args = try std.process.argsAlloc(arena);
    (try std.Thread.spawn(.{}, watchdog, .{})).detach();
    if (args.len == 3 and std.mem.eql(u8, args[1], "child")) return child(args[2]);
    if (args.len != 2) fail("expected WORK_DIR but got {} args", .{args.len - 1});

    try std.fs.cwd().deleteTree(args[1]);
    var work_dir = try std.fs.cwd().makeOpenPath(args[1], .{});
    defer work_dir.close();
    try work_dir.writeFile(.{ .sub_path = "counter", .data = "0" });
    const work_path = try work_dir.realpathAlloc(arena, ".");

    var children: [process_count]std.process.Child = undefined;
    for (&children) |*c| {
        c.* = .init(&.{ args[0], "child", work_path }, arena);
        try c.spawn();
    }
    var failed = false;
    for (&children) |*c| {
        const term = try c.wait();
        if (term != .Exited or term.Exited != 0) {
            std.debug.print("error: child failed with {}\n", .{term});
            failed = true;
        }
    }
    if (failed) std.process.exit(1);

    var buf: [20]u8 = undefined;
    const count = try std.fmt.parseInt(u32, try work_dir.readFile("counter", &buf), 10);
    const expected = process_count * increments_per_process;
    if (count != expected) fail("counter is {} but expected {}, processes held the lock at the same time", .{ count, expected });

    // the lock file has to outlive unlock, see the comment there
    work_dir.access(".lock", .{}) catch |e| fail("lock file after unlock: {s}", .{@errorName(e)});
}

/// A bug here could easily be a hang, this fails with a clear message rather than waiting for CI
/// to time out.
fn watchdog() void {
    std.Thread.sleep(120 * std.time.ns_per_s);
    fail("still running after 120 seconds", .{});
}

fn child(work_path: []const u8) !void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const lock_path = try std.fmt.bufPrint(&path_buf, "{s}{c}.lock", .{ work_path, std.fs.path.sep });
    var work_dir = try std.fs.cwd().openDir(work_path, .{});
    defer work_dir.close();
    for (0..increments_per_process) |_| {
        var lock = try LockFile.lock(lock_path);
        defer lock.unlock();
        var buf: [20]u8 = undefined;
        const count = try std.fmt.parseInt(u32, try work_dir.readFile("counter", &buf), 10);
        // give another process that wrongly got the lock time to read the same value
        std.Thread.sleep(50 * std.time.ns_per_us);
        const text = try std.fmt.bufPrint(&buf, "{}", .{count + 1});
        try work_dir.writeFile(.{ .sub_path = "counter", .data = text });
    }
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("error: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

const std = @import("std");
const LockFile = @import("LockFile.zig");
