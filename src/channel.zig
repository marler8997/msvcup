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

    /// Every channel with a name, in the order they're declared.
    pub const known = blk: {
        const fields = @typeInfo(Channel).@"union".fields;
        var channels: [fields.len - 1]Channel = undefined;
        var count: usize = 0;
        for (fields) |field| {
            if (std.mem.eql(u8, field.name, "url")) continue;
            channels[count] = @unionInit(Channel, field.name, {});
            count += 1;
        }
        std.debug.assert(count == channels.len);
        break :blk channels;
    };
    pub const default: Channel = .@"vs17-release";

    /// Takes the name of a known channel or anything starting with https://, which is taken
    /// as a url without checking that it's a valid one. The url of a known channel gives that
    /// channel. The result can reference arg, so arg must remain valid as long as the result
    /// is used.
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

    /// Whether uri is a channel manifest, which is what a channel url redirects to.
    pub fn isManifestUri(uri: std.Uri) bool {
        const path = switch (uri.path) {
            inline else => |path| path,
        };
        return std.ascii.endsWithIgnoreCase(path, ".chman");
    }

    pub const Manifest = enum { vs, channel, @"channel-url" };

    pub const ManifestDir = struct {
        buf: [max_len]u8,
        len: u8,
        const max_len = cache_key_len + 1 + "channel-url".len;
        pub fn slice(self: *const ManifestDir) []const u8 {
            return self.buf[0..self.len];
        }
    };

    /// Where one of this channel's manifests is cached, relative to the manifest cache. The
    /// vs17 channels keep the directories they had before there were other channels. A new
    /// directory would make everyone download the manifest again, and an install without a
    /// lock file would pick up newer packages than the ones it already installed.
    pub fn manifestDir(self: Channel, manifest: Manifest) ManifestDir {
        var result: ManifestDir = .{ .buf = undefined, .len = 0 };
        const dir = switch (self) {
            .@"vs17-release" => switch (manifest) {
                .vs => "vs-release",
                .channel => "channel-release",
                .@"channel-url" => "channel-release-url",
            },
            .@"vs17-preview" => switch (manifest) {
                .vs => "vs-preview",
                .channel => "channel-preview",
                .@"channel-url" => "channel-preview-url",
            },
            .@"vs18-stable", .@"vs18-insiders", .url => {
                const dir = std.fmt.bufPrint(
                    &result.buf,
                    "{s}" ++ std.fs.path.sep_str ++ "{s}",
                    .{ &self.cacheKey(), @tagName(manifest) },
                ) catch unreachable;
                result.len = @intCast(dir.len);
                return result;
            },
        };
        @memcpy(result.buf[0..dir.len], dir);
        result.len = @intCast(dir.len);
        return result;
    }

    const cache_key_len = 16;

    /// Identifies this channel in the manifest cache. It comes from the url so that a
    /// channel's name and its url share a cache.
    fn cacheKey(self: Channel) [cache_key_len]u8 {
        var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.httpsUrl(), &digest, .{});
        var key: [cache_key_len]u8 = undefined;
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
    try std.testing.expectEqual(null, Channel.fromArg("https:example.com/channel"));
    try std.testing.expectEqual(null, Channel.fromArg("HTTPS://example.com/channel"));
}

test "fromArg doesn't validate a url" {
    try std.testing.expectEqualStrings("https://", Channel.fromArg("https://").?.url);
}

fn testIsManifestUri(url: []const u8) !bool {
    return Channel.isManifestUri(try std.Uri.parse(url));
}

test "isManifestUri" {
    try std.testing.expect(try testIsManifestUri("https://example.com/a/VisualStudio.18.Release.chman"));
    try std.testing.expect(try testIsManifestUri("https://example.com/a.chman?b=c"));
    try std.testing.expect(try testIsManifestUri("https://example.com/a.chman#b"));
    try std.testing.expect(try testIsManifestUri("https://example.com/A.CHMAN"));
    // where an unknown aka.ms url redirects to
    try std.testing.expect(!try testIsManifestUri("https://www.bing.com?ref=aka&shorturl=vs/18/release/channel"));
    try std.testing.expect(!try testIsManifestUri("https://example.com/a.chman/b"));
    try std.testing.expect(!try testIsManifestUri("https://example.com/a?b=c.chman"));
    // only the path counts
    try std.testing.expect(!try testIsManifestUri("https://example.chman"));
    try std.testing.expect(!try testIsManifestUri("https://example.com/a#b.chman"));
}

test "manifestDir keeps the vs17 directories" {
    const release: Channel = .@"vs17-release";
    try std.testing.expectEqualStrings("vs-release", release.manifestDir(.vs).slice());
    try std.testing.expectEqualStrings("channel-release", release.manifestDir(.channel).slice());
    try std.testing.expectEqualStrings("channel-release-url", release.manifestDir(.@"channel-url").slice());
    const preview: Channel = .@"vs17-preview";
    try std.testing.expectEqualStrings("vs-preview", preview.manifestDir(.vs).slice());
    try std.testing.expectEqualStrings("channel-preview", preview.manifestDir(.channel).slice());
    try std.testing.expectEqualStrings("channel-preview-url", preview.manifestDir(.@"channel-url").slice());
    // the url of a known channel is that channel
    const by_url = Channel.fromArg("https://aka.ms/vs/17/release/channel").?;
    try std.testing.expectEqualStrings("vs-release", by_url.manifestDir(.vs).slice());
}

test "manifestDir differs per channel and manifest" {
    const stable: Channel = .@"vs18-stable";
    const insiders: Channel = .@"vs18-insiders";
    const url = Channel.fromArg("https://example.com/channel").?;
    var dirs: [9]Channel.ManifestDir = undefined;
    var count: usize = 0;
    for ([_]Channel{ stable, insiders, url }) |channel| {
        for (std.enums.values(Channel.Manifest)) |manifest| {
            dirs[count] = channel.manifestDir(manifest);
            for (dirs[0..count]) |*other| {
                try std.testing.expect(!std.mem.eql(u8, dirs[count].slice(), other.slice()));
            }
            count += 1;
        }
    }
    try std.testing.expect(std.mem.endsWith(u8, stable.manifestDir(.vs).slice(), std.fs.path.sep_str ++ "vs"));
}

test "manifestDir doesn't change, it would orphan everyone's cached manifests" {
    const stable: Channel = .@"vs18-stable";
    try std.testing.expectEqualStrings("59f8addd4cd3886e" ++ std.fs.path.sep_str ++ "vs", stable.manifestDir(.vs).slice());
}
