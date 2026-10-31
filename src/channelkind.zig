pub const ChannelKind = enum {
    release,
    preview,

    pub fn httpsUrl(self: ChannelKind) []const u8 {
        return switch (self) {
            .release => "https://aka.ms/vs/17/release/channel",
            .preview => "https://aka.ms/vs/17/pre/channel",
        };
    }
    pub fn name(self: ChannelKind) []const u8 {
        return switch (self) {
            .release => "vs17-release",
            .preview => "vs17-preview",
        };
    }
};
