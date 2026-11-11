//! Creates a file atomically, without any separate lock file. The content goes in a temporary
//! file next to the destination with a fixed name, which is also the lock for creating it.
//! Whoever has its lock is the only one writing it, everyone else waits and then either finds the
//! destination or takes their turn. A process that exits without calling deinit leaves the temporary file behind and
//! the next process to want the destination takes it over. Readers of the destination never wait,
//! they only ever see no file or the complete one.
pub const AtomicFile = @This();

file: std.Io.File,
tmp_path: []const u8,
state: enum { open, finished },

pub const Result = union(enum) {
    /// the destination exists, there's nothing to do
    exists,
    /// we have the lock, call deinit when done
    locked: AtomicFile,
};

/// Waits for the lock on tmp_path. If there's a destination and it now exists then there's nothing
/// to do, this never happens without a destination. tmp_path must remain valid as long as the
/// result is used.
pub fn lock(io: std.Io, tmp_path: []const u8, maybe_dest_path: ?[]const u8) !Result {
    return lockInner(io, tmp_path, maybe_dest_path) catch |err| {
        std.log.err("failed to lock '{s}' with {t}", .{ tmp_path, err });
        return err;
    };
}

fn lockInner(io: std.Io, tmp_path: []const u8, maybe_dest_path: ?[]const u8) !Result {
    globalfilelocks.aboutToLock(tmp_path);
    if (std.Io.Dir.path.dirname(tmp_path)) |dir| try std.Io.Dir.cwd().createDirPath(io, dir);
    while (true) {
        const file = try createOrOpen(io, tmp_path) orelse continue;
        errdefer file.close(io);
        try lockFile(io, file);
        // This comes before anything else. While we waited, the process that had the lock could
        // have renamed this file to where it belongs or deleted it, and either way it isn't
        // ours to change, we'd be overwriting a finished file. Someone could also already have
        // the lock on a new file with this name.
        if (!try isCurrent(io, file, tmp_path)) {
            file.close(io);
            continue;
        }
        if (maybe_dest_path) |dest_path| {
            if (std.Io.Dir.cwd().access(io, dest_path, .{})) {
                // we might have just created this, nobody else is going to clean it up
                try std.Io.Dir.cwd().deleteFile(io, tmp_path);
                file.close(io);
                return .exists;
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => |e| return e,
            }
        }
        // anything in it was left by a process that didn't finish
        try file.setLength(io, 0);
        globalfilelocks.took(tmp_path);
        return .{ .locked = .{ .file = file, .tmp_path = tmp_path, .state = .open } };
    }
}

/// Deletes the temporary file if finish wasn't called or failed.
pub fn deinit(self: *AtomicFile, io: std.Io) void {
    switch (self.state) {
        .open => {
            // delete before closing, so that if anyone is waiting they see it was deleted
            std.Io.Dir.cwd().deleteFile(io, self.tmp_path) catch |err| std.log.warn(
                "failed to delete '{s}' with {t}",
                .{ self.tmp_path, err },
            );
            self.file.close(io);
            globalfilelocks.released();
        },
        .finished => {},
    }
    self.* = undefined;
}

/// Renames the temporary file to dest_path. The destination's directory must exist.
pub fn finish(self: *AtomicFile, io: std.Io, dest_path: []const u8) !void {
    std.debug.assert(self.state == .open);
    self.finishInner(io, dest_path) catch |err| {
        std.log.err(
            "failed to rename '{s}' to '{s}' with {t}",
            .{ self.tmp_path, dest_path, err },
        );
        return err;
    };
}

fn finishInner(self: *AtomicFile, io: std.Io, dest_path: []const u8) !void {
    // without this the rename can reach the disk before the content, leaving an empty or
    // zero-filled file after a power loss
    try self.file.sync(io);
    // the file stays open so that we have the lock until after the rename
    try std.Io.Dir.rename(.cwd(), self.tmp_path, .cwd(), dest_path, io);
    self.file.close(io);
    globalfilelocks.released();
    self.state = .finished;
}

/// On macOS, when multiple processes open the same nonexistent file with O_CREAT (and not
/// O_EXCL) at once, some fail with ENOENT. With O_EXCL exactly one creates it and the others
/// get EEXIST, then open the existing file without O_CREAT. Returns null if whoever had the file
/// renamed or deleted it between the two. FileNotFound from creating it isn't that, it means the
/// directory is gone, and waiting won't bring it back.
fn createOrOpen(io: std.Io, path: []const u8) !?std.Io.File {
    // these aren't write only because on windows that wouldn't allow stat
    if (std.Io.Dir.cwd().createFile(io, path, .{ .exclusive = true, .read = true })) |file| {
        return file;
    } else |err| switch (err) {
        error.PathAlreadyExists => {},
        else => |e| return e,
    }
    return std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => |e| return e,
    };
}

/// On windows we lock a single byte far beyond the end of the file instead of using File.lock,
/// which locks byte 0. Windows locks are mandatory, so locking real content would make reads fail
/// once the file has been renamed to the destination and we're still waiting to close it, or
/// someone waiting on it gets the lock before noticing it's the destination.
fn lockFile(io: std.Io, file: std.Io.File) !void {
    if (builtin.os.tag != .windows) return file.lock(io, .exclusive);
    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    const offset: windows.LARGE_INTEGER = std.math.maxInt(windows.LARGE_INTEGER) - 1;
    const len: windows.LARGE_INTEGER = 1;
    while (true) switch (windows.ntdll.NtLockFile(
        file.handle,
        null,
        null,
        null,
        &io_status_block,
        &offset,
        &len,
        null,
        .FALSE, // wait
        .TRUE, // exclusive
    )) {
        .SUCCESS => return,
        .CANCELLED => continue,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |status| return windows.unexpectedStatus(status),
    };
}

/// Whether file is still the file with this name.
fn isCurrent(io: std.Io, file: std.Io.File, path: []const u8) !bool {
    // Check this first. On windows opening a name whose file is pending deletion waits until it's
    // closed, which would be waiting on ourselves.
    if (try isDeleted(io, file)) return false;
    const path_stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => |e| return e,
    };
    return (try file.stat(io)).inode == path_stat.inode;
}

fn isDeleted(io: std.Io, file: std.Io.File) !bool {
    if (builtin.os.tag != .windows) return (try file.stat(io)).nlink == 0;
    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var info: windows.FILE.STANDARD_INFORMATION = undefined;
    const status = windows.ntdll.NtQueryInformationFile(
        file.handle,
        &io_status_block,
        &info,
        @sizeOf(windows.FILE.STANDARD_INFORMATION),
        .Standard,
    );
    if (status != .SUCCESS) return windows.unexpectedStatus(status);
    return info.DeletePending.toBool() or info.NumberOfLinks == 0;
}

const builtin = @import("builtin");
const std = @import("std");
const windows = std.os.windows;
const globalfilelocks = @import("globalfilelocks.zig");
