pub const Arch = enum {
    x64,
    x86,
    arm,
    arm64,

    pub const native: Arch = switch (builtin.os.tag) {
        .windows => switch (builtin.cpu.arch) {
            .x86_64 => .x64,
            .x86 => .x86,
            .arm => .arm,
            .aarch64 => .arm64,
            else => @compileError("unsupported windows cpu arch"),
        },
        // for now we'll just assume host x64 as that seems to
        // be what wine wants
        else => .x64,
    };

    pub fn fromString(s: []const u8) ?Arch {
        if (std.mem.eql(u8, s, "x64")) return .x64;
        if (std.mem.eql(u8, s, "x86")) return .x86;
        if (std.mem.eql(u8, s, "arm")) return .arm;
        if (std.mem.eql(u8, s, "arm64")) return .arm64;
        return null;
    }
    pub fn fromStringIgnoreCase(s: []const u8) ?Arch {
        if (std.ascii.eqlIgnoreCase(s, "x64")) return .x64;
        if (std.ascii.eqlIgnoreCase(s, "x86")) return .x86;
        if (std.ascii.eqlIgnoreCase(s, "arm")) return .arm;
        if (std.ascii.eqlIgnoreCase(s, "arm64")) return .arm64;
        return null;
    }
};
pub const Arches = packed struct {
    x64: bool,
    x86: bool,
    arm: bool,
    arm64: bool,

    pub const none: Arches = .{ .x64 = false, .x86 = false, .arm = false, .arm64 = false };
    pub const all: Arches = .{ .x64 = true, .x86 = true, .arm = true, .arm64 = true };

    pub fn get(self: Arches, arch: Arch) bool {
        return switch (arch) {
            .x64 => self.x64,
            .x86 => self.x86,
            .arm => self.arm,
            .arm64 => self.arm64,
        };
    }
    pub fn set(self: *Arches, arch: Arch, value: bool) void {
        switch (arch) {
            .x64 => self.x64 = value,
            .x86 => self.x86 = value,
            .arm => self.arm = value,
            .arm64 => self.arm64 = value,
        }
    }
};

const builtin = @import("builtin");
const std = @import("std");
