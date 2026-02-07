pub const Package = struct {
    kind: Kind,
    version: []const u8,
};
pub const Payload = struct {
    package: Package,
    arch: Arch,
};

pub const Kind = enum {
    ninja,
    cmake,
};

pub fn parseUrl(url: []const u8) union(enum) {
    ok: Payload,
    unexpected: struct {
        offset: usize,
        what: [:0]const u8,
    },
} {
    const ninja_prefix = "https://github.com/ninja-build/ninja/releases/download/v";
    if (std.mem.startsWith(u8, url, ninja_prefix)) {
        const version_start = ninja_prefix.len;
        const version_end = scanVersion(url, version_start);
        if (version_end == version_start) return .{ .unexpected = .{
            .offset = version_start,
            .what = "a version",
        } };
        const arch: Arch = blk: {
            const remaining = url[version_end..];
            const x64 = "/ninja-win.zip";
            const arm64 = "/ninja-winarm64.zip";
            if (std.mem.eql(u8, remaining, x64)) break :blk .x64;
            if (std.mem.eql(u8, remaining, arm64)) break :blk .arm64;
            return .{ .unexpected = .{
                .offset = version_end,
                .what = "either '" ++ x64 ++ "' or '" ++ arm64 ++ "'",
            } };
        };
        return .{ .ok = .{
            .package = .{ .kind = .ninja, .version = url[version_start..version_end] },
            .arch = arch,
        } };
    }
    const cmake_prefix = "https://github.com/Kitware/CMake/releases/download/v";
    if (std.mem.startsWith(u8, url, cmake_prefix)) {
        const version_start = cmake_prefix.len;
        const version_end = scanVersion(url, version_start);
        if (version_end == version_start) return .{ .unexpected = .{
            .offset = version_start,
            .what = "a version",
        } };
        const version = url[version_start..version_end];
        // Expect "/cmake-{version}-windows-"
        var offset = version_end;
        const mid = "/cmake-";
        if (!matchLiteral(url, &offset, mid) or
            !matchLiteral(url, &offset, version) or
            !matchLiteral(url, &offset, "-windows-"))
            return .{ .unexpected = .{
                .offset = version_end,
                .what = "'" ++ mid ++ "<version>-windows-<arch>.zip'",
            } };
        const remaining = url[offset..];
        const arch: Arch = blk: {
            if (std.mem.eql(u8, remaining, "x86_64.zip")) break :blk .x64;
            if (std.mem.eql(u8, remaining, "i386.zip")) break :blk .x86;
            if (std.mem.eql(u8, remaining, "arm64.zip")) break :blk .arm64;
            return .{ .unexpected = .{
                .offset = offset,
                .what = "'x86_64.zip', 'i386.zip', or 'arm64.zip'",
            } };
        };
        return .{ .ok = .{
            .package = .{ .kind = .cmake, .version = version },
            .arch = arch,
        } };
    }
    return .{ .unexpected = .{
        .offset = 0,
        .what = "either '" ++ ninja_prefix ++ "' or '" ++ cmake_prefix ++ "'",
    } };
}

fn scanVersion(str: []const u8, start: usize) usize {
    var offset = start;
    while (offset < str.len) : (offset += 1) {
        switch (str[offset]) {
            '.' => {},
            '0'...'9' => {},
            else => break,
        }
    }
    return offset;
}

fn matchLiteral(str: []const u8, offset: *usize, expected: []const u8) bool {
    const end = offset.* + expected.len;
    if (end > str.len) return false;
    if (!std.mem.eql(u8, str[offset.*..end], expected)) return false;
    offset.* = end;
    return true;
}

const std = @import("std");
const Arch = @import("arch.zig").Arch;
