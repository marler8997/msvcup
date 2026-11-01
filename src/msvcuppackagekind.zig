pub const MsvcupPackageKind = enum {
    msvc,
    sdk,
    msbuild,
    diasdk,
    ninja,
    cmake,
    pub fn order(_: void, lhs: MsvcupPackageKind, rhs: MsvcupPackageKind) std.math.Order {
        return std.math.order(@intFromEnum(lhs), @intFromEnum(rhs));
    }
};

const std = @import("std");
