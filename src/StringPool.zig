/// Takes an allocator and manages a set of strings.
/// Every string in the pool is owned by the pool.
const StringPool = @This();

const std = @import("std");
const StringHashMap = std.hash_map.StringHashMap;

pub const Val = struct {
    slice: []const u8,
    pub fn eql(self: Val, other: Val) bool {
        return self.slice.ptr == other.slice.ptr;
    }
    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        return writer.writeAll(self.slice);
    }
};

allocator: std.mem.Allocator,
map: StringHashMap(Val),
pub fn init(allocator: std.mem.Allocator) @This() {
    return @This(){
        .allocator = allocator,
        .map = StringHashMap(Val).init(allocator),
    };
}

pub fn deinit(self: *StringPool) void {
    var it = self.map.iterator();
    while (it.next()) |entry| {
        self.allocator.free(entry.value_ptr.slice);
    }
    self.map.deinit();
}

/// If the pool already contains this a string that matches the contents
/// of the given string, return the existing string from this pool.
/// Otherwise, create a copy of this string, add it to the pool and return
/// the new copy.
pub fn add(self: *@This(), s: []const u8) error{OutOfMemory}!Val {
    if (self.map.get(s)) |entry| {
        return entry;
    }
    const newString = try self.allocator.alloc(u8, s.len);
    @memcpy(newString, s);
    const val = Val{ .slice = newString };
    _ = try self.map.put(newString, val);
    return val;
}

pub fn addFormatted(self: *@This(), comptime fmt: []const u8, args: anytype) error{OutOfMemory}!Val {
    const s = try std.fmt.allocPrint(self.allocator, fmt, args);
    errdefer self.allocator.free(s);

    const val = try self.add(s);
    if (val.slice.ptr != s.ptr) {
        self.allocator.free(s);
    }
    return val;
}

pub const HashContext = struct {
    pub fn hash(self: HashContext, s: Val) u64 {
        _ = self;
        return std.hash.Wyhash.hash(0, @as([*]const u8, @ptrCast(&s.slice.ptr))[0..@sizeOf(usize)]);
    }
    pub fn eql(self: HashContext, a: Val, b: Val) bool {
        _ = self;
        return a.slice.ptr == b.slice.ptr;
    }
};
pub const ArrayHashContext = struct {
    pub fn hash(self: @This(), s: Val) u32 {
        _ = self;
        return @as(u32, @truncate(std.hash.Wyhash.hash(0, @as([*]const u8, @ptrCast(&s.slice.ptr))[0..@sizeOf(usize)])));
    }
    pub fn eql(self: @This(), a: Val, b: Val, index: usize) bool {
        _ = self;
        _ = index;
        return a.slice.ptr == b.slice.ptr;
    }
};

pub fn HashMap(comptime V: type) type {
    return std.HashMap(Val, V, HashContext, std.hash_map.default_max_load_percentage);
}
pub fn HashMapUnmanaged(comptime V: type) type {
    return std.HashMapUnmanaged(Val, V, HashContext, std.hash_map.default_max_load_percentage);
}

pub fn asciiLessThanIgnoreCase(_: void, lhs: Val, rhs: Val) bool {
    return std.ascii.lessThanIgnoreCase(lhs.slice, rhs.slice);
}

test "stringpool" {
    var pool = StringPool.init(std.testing.allocator);
    defer pool.deinit();
    const s = try pool.add("hello");
    {
        var buf: [5]u8 = undefined;
        std.mem.copy(u8, buf[0..], "hello");
        const s2 = try pool.add(buf[0..]);
        try std.testing.expect(s.slice.ptr == s2.slice.ptr);
    }
}
