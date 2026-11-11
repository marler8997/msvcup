pub const MsvcupPackageKind = enum {
    msvc,
    sdk,
    msbuild,
    diasdk,
    ninja,
    cmake,
    pub fn order(_: void, lhs: MsvcupPackageKind, rhs: MsvcupPackageKind) std.math.Order {
        return std.math.order(@backingInt(lhs), @backingInt(rhs));
    }
};

const std = @import("std");
