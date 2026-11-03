//! Enforces that a process holds at most one file lock at a time. Two processes taking the same
//! two locks in opposite orders would wait on each other forever, with nothing to say why. All
//! file locks go through LockFile or AtomicFile, which use this. msvcup is single threaded, so
//! this isn't synchronized.
//!
//! Any function with a "Locking" suffix might take a file lock, depending on the state of the
//! filesystem or its input. They call enteredLockingFunction first, so calling one while holding
//! a lock always panics, even on runs where it wouldn't have needed its lock. That way a mistake
//! can't hide until someone runs with an empty cache. Every function that can reach a lock has
//! the suffix except the commands, which are where a run starts so nothing can be held yet.

var global_held_path: ?[]const u8 = null;

/// Call first thing in any function with a "Locking" suffix.
pub fn enteredLockingFunction(fn_name: []const u8) void {
    if (global_held_path) |held| std.debug.panic(
        "{s} was called while holding a file lock on '{s}'",
        .{ fn_name, held },
    );
}

/// Call before waiting for a lock, so that a mistake is a panic naming both files instead of a hang.
pub fn aboutToLock(path: []const u8) void {
    if (global_held_path) |held| std.debug.panic(
        "tried to lock '{s}' while holding a file lock on '{s}'",
        .{ path, held },
    );
}

/// path must remain valid until released is called
pub fn took(path: []const u8) void {
    std.debug.assert(global_held_path == null);
    global_held_path = path;
}

pub fn released() void {
    std.debug.assert(global_held_path != null);
    global_held_path = null;
}

const std = @import("std");
