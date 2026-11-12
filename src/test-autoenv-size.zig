//! autoenv.exe is copied next to every tool it wraps, so its size is checked here: a change
//! that makes it bigger or smaller has to update this table, which makes it a decision.
//! build.zig provides each exe as an import named "autoenv-<arch>".

const expected_sizes = .{
    .{ "x86_64", 81_920 },
    .{ "x86", 33_280 },
    .{ "aarch64", 35_328 },
};

test "autoenv.exe is the size this file says" {
    var ok = true;
    inline for (expected_sizes) |entry| {
        const arch, const expected: usize = entry;
        const actual = @embedFile("autoenv-" ++ arch).len;
        if (actual != expected) {
            std.debug.print(
                "autoenv.exe for {s} is {d} bytes, {s} says {d}\n",
                .{ arch, actual, @src().file, expected },
            );
            ok = false;
        }
    }
    if (!ok) return error.TestUnexpectedResult;
}

const std = @import("std");
