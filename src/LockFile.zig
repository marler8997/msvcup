/// A file-based locking mechanism for synchronizing operations between multiple processes
pub const LockFile = @This();

file: std.Io.File,

/// path must remain valid until unlock
pub fn lock(io: std.Io, path: []const u8) !LockFile {
    return lockInner(io, path) catch |err| {
        std.log.err("failed to lock '{s}' with {t}", .{ path, err });
        return err;
    };
}

fn lockInner(io: std.Io, path: []const u8) !LockFile {
    globalfilelocks.aboutToLock(path);
    if (std.Io.Dir.path.dirname(path)) |dir| {
        try std.Io.Dir.cwd().createDirPath(io, dir);
    }
    const file = try createOrOpen(io, path);
    errdefer file.close(io);

    try file.lock(io, .exclusive);
    globalfilelocks.took(path);
    return LockFile{
        .file = file,
    };
}

/// The lock file is never deleted. If it was, a process waiting for the lock would get it on the
/// deleted file, and another process could create a new file with the same name and lock that,
/// so they'd both think they have it.
pub fn unlock(self: *LockFile, io: std.Io) void {
    self.file.unlock(io);
    self.file.close(io);
    globalfilelocks.released();
}

/// Creates the file or opens it if it already exists.
///
/// On macOS, when multiple processes open the same nonexistent file with O_CREAT (and not
/// O_EXCL) at once, some fail with ENOENT. With O_EXCL exactly one creates it and the others
/// get EEXIST, then open the existing file without O_CREAT.
fn createOrOpen(io: std.Io, path: []const u8) !std.Io.File {
    if (std.Io.Dir.cwd().createFile(io, path, .{ .exclusive = true })) |file| {
        return file;
    } else |err| switch (err) {
        error.PathAlreadyExists => {},
        else => |e| return e,
    }
    // not read only, on NFS flock is emulated and an exclusive lock needs a handle open for writing
    return std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
}

const std = @import("std");
const globalfilelocks = @import("globalfilelocks.zig");
