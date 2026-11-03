/// A file-based locking mechanism for synchronizing operations between multiple processes
pub const LockFile = @This();

file: std.fs.File,

/// path must remain valid until unlock
pub fn lock(path: []const u8) !LockFile {
    errdefer |err| std.log.err("failed to lock '{s}' with {s}", .{ path, @errorName(err) });
    globalfilelocks.aboutToLock(path);
    if (std.fs.path.dirname(path)) |dir| {
        try std.fs.cwd().makePath(dir);
    }
    const file = try createOrOpen(path);
    errdefer file.close();

    try file.lock(.exclusive);
    globalfilelocks.took(path);
    return LockFile{
        .file = file,
    };
}

/// The lock file is never deleted. If it was, a process waiting for the lock would get it on the
/// deleted file, and another process could create a new file with the same name and lock that,
/// so they'd both think they have it.
pub fn unlock(self: *LockFile) void {
    self.file.unlock();
    self.file.close();
    globalfilelocks.released();
}

/// Creates the file or opens it if it already exists.
///
/// On macOS, when multiple processes open the same nonexistent file with O_CREAT (and not
/// O_EXCL) at once, some fail with ENOENT. With O_EXCL exactly one creates it and the others
/// get EEXIST, then open the existing file without O_CREAT.
fn createOrOpen(path: []const u8) !std.fs.File {
    if (std.fs.cwd().createFile(path, .{ .exclusive = true })) |file| {
        return file;
    } else |err| switch (err) {
        error.PathAlreadyExists => {},
        else => |e| return e,
    }
    // not read only, on NFS flock is emulated and an exclusive lock needs a handle open for writing
    return std.fs.cwd().openFile(path, .{ .mode = .read_write });
}

const std = @import("std");
const globalfilelocks = @import("globalfilelocks.zig");
