const std = @import("std");

/// A channel is how Microsoft publishes Visual Studio's packages and their payloads, msvcup
/// finds the packages and payloads in the channel's manifest. Microsoft doesn't publish a
/// list of channels and the URLs don't follow a pattern, VS 18 renamed its channels to
/// stable/insiders, so the known channels each get a value here.
pub const Channel = union(enum) {
    @"vs17-release",
    @"vs17-preview",
    @"vs18-stable",
    @"vs18-insiders",
    url: []const u8,

    pub const known = [_]Channel{ .@"vs17-release", .@"vs17-preview", .@"vs18-stable", .@"vs18-insiders" };
    pub const default: Channel = .@"vs17-release";

    /// Takes the name of a known channel or an https url. The url of a known channel gives
    /// that channel. The result can reference arg, so arg must remain valid as long as the
    /// result is used.
    pub fn fromArg(arg: []const u8) ?Channel {
        for (known) |channel| {
            if (std.mem.eql(u8, arg, channel.asArg()) or std.mem.eql(u8, arg, channel.httpsUrl())) return channel;
        }
        if (!std.mem.startsWith(u8, arg, "https://")) return null;
        return .{ .url = arg };
    }

    pub fn asArg(self: Channel) []const u8 {
        return switch (self) {
            .url => |url| url,
            else => @tagName(self),
        };
    }

    pub fn httpsUrl(self: Channel) []const u8 {
        return switch (self) {
            .@"vs17-release" => "https://aka.ms/vs/17/release/channel",
            .@"vs17-preview" => "https://aka.ms/vs/17/pre/channel",
            .@"vs18-stable" => "https://aka.ms/vs/18/stable/channel",
            .@"vs18-insiders" => "https://aka.ms/vs/18/insiders/channel",
            .url => |url| url,
        };
    }

    /// Whether url, which a channel url redirects to, is a channel manifest.
    pub fn isManifestUrl(url: []const u8) bool {
        const path_end = std.mem.indexOfAny(u8, url, "?#") orelse url.len;
        return std.mem.endsWith(u8, url[0..path_end], ".chman");
    }

    /// The directory name for this channel's cached manifests. It comes from the url so that
    /// a channel's name and its url share a cache.
    pub fn cacheKey(self: Channel) [16]u8 {
        var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.httpsUrl(), &digest, .{});
        var key: [16]u8 = undefined;
        _ = std.fmt.bufPrint(&key, "{}", .{std.fmt.fmtSliceHexLower(digest[0 .. key.len / 2])}) catch unreachable;
        return key;
    }
};

test "fromArg accepts a known name" {
    try std.testing.expectEqual(Channel.@"vs18-stable", Channel.fromArg("vs18-stable").?);
}

test "fromArg maps a known url to its channel" {
    try std.testing.expectEqual(Channel.@"vs18-stable", Channel.fromArg("https://aka.ms/vs/18/stable/channel").?);
}

test "fromArg accepts any https url" {
    const channel = Channel.fromArg("https://example.com/channel").?;
    try std.testing.expectEqualStrings("https://example.com/channel", channel.url);
    try std.testing.expectEqualStrings("https://example.com/channel", channel.asArg());
    try std.testing.expectEqualStrings("https://example.com/channel", channel.httpsUrl());
}

test "fromArg rejects anything else" {
    try std.testing.expectEqual(null, Channel.fromArg("vs19-stable"));
    try std.testing.expectEqual(null, Channel.fromArg("http://example.com/channel"));
    try std.testing.expectEqual(null, Channel.fromArg(""));
}

test "isManifestUrl" {
    try std.testing.expect(Channel.isManifestUrl("https://example.com/a/VisualStudio.18.Release.chman"));
    try std.testing.expect(Channel.isManifestUrl("https://example.com/a.chman?b=c"));
    try std.testing.expect(Channel.isManifestUrl("https://example.com/a.chman#b"));
    // where an unknown aka.ms url redirects to
    try std.testing.expect(!Channel.isManifestUrl("https://www.bing.com?ref=aka&shorturl=vs/18/release/channel"));
    try std.testing.expect(!Channel.isManifestUrl("https://example.com/a.chman/b"));
    try std.testing.expect(!Channel.isManifestUrl("https://example.com/a?b=c.chman"));
    try std.testing.expect(!Channel.isManifestUrl(""));
}

test "cacheKey differs per url" {
    const a = Channel.fromArg("vs17-release").?.cacheKey();
    const b = Channel.fromArg("vs18-stable").?.cacheKey();
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}
