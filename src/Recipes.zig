//! Parses and matches the rules that select which manifest payloads belong to
//! which msvcup package. The format is documented above parseBuiltinRecipes in
//! msvcup.zig.
//!
//! Recipes reference the text they were parsed from rather than copying it, so
//! the text must stay in memory, i.e. the embedded builtin recipes or a file
//! that's been read into memory. The text is untrusted, parse must report any
//! problem with it through the diagnostic.
const Recipes = @This();

rules: []const Rule,

pub const Rule = struct {
    line: u32,
    package: MsvcupPackageKind,
    /// The version of the msvcup package, null to use the {version} capture.
    package_version: ?[]const u8,
    // patterns, validated by parse
    id: ?[]const u8,
    version: ?[]const u8,
    file_name: ?[]const u8,
};

const version_placeholder = "{version}";
const arch_placeholder = "{arch}";

pub const Diagnostic = struct {
    line: u32 = 0,
    message: []const u8 = "",
};

/// The attributes of a payload that rules can match.
pub const Attributes = struct {
    id: []const u8,
    version: []const u8,
    file_name: []const u8,
};

pub const Match = union(enum) {
    none,
    one: One,
    multiple: [2]*const Rule,

    pub const One = struct {
        rule: *const Rule,
        package_version: []const u8,
    };
};

/// The returned Recipes references `text`, which must stay in memory.
pub fn parse(
    arena: std.mem.Allocator,
    text: []const u8,
    diagnostic: *Diagnostic,
) error{ OutOfMemory, InvalidRecipes }!Recipes {
    // count the rules first so this one allocation is exactly the right size
    var rule_count: usize = 0;
    var count_lines: RuleLines = .init(text);
    while (count_lines.next()) |_| rule_count += 1;

    const rules = try arena.alloc(Rule, rule_count);
    var lines: RuleLines = .init(text);
    for (rules) |*rule| {
        const line = lines.next().?;
        rule.* = try parseRule(line, lines.number, diagnostic);
    }
    return .{ .rules = rules };
}

/// Iterates over the lines that contain a rule, skipping blank lines and comments.
const RuleLines = struct {
    lines: std.mem.SplitIterator(u8, .scalar),
    number: u32 = 0,

    fn init(text: []const u8) RuleLines {
        return .{ .lines = std.mem.splitScalar(u8, text, '\n') };
    }
    fn next(self: *RuleLines) ?[]const u8 {
        while (self.lines.next()) |line_with_ending| {
            self.number += 1;
            const line = std.mem.trim(u8, line_with_ending, " \t\r");
            if (line.len != 0 and line[0] != '#') return line;
        }
        return null;
    }
};

fn fail(diagnostic: *Diagnostic, line: u32, message: []const u8) error{InvalidRecipes} {
    diagnostic.* = .{ .line = line, .message = message };
    return error.InvalidRecipes;
}

fn nextField(fields: *Fields, line: u32, diagnostic: *Diagnostic) error{InvalidRecipes}!?[]const u8 {
    return fields.next() catch |err| fail(diagnostic, line, switch (err) {
        error.MissingClosingQuote => "missing closing quote",
        error.EmptyQuotes => "empty quotes",
        error.UnexpectedQuote => "a quote must wrap a whole field",
    });
}

/// Iterates over the whitespace-separated fields of a line. A field can be
/// wrapped in double quotes to contain whitespace, there's no way to escape a
/// quote. A returned field is never empty.
const Fields = struct {
    line: []const u8,
    index: usize = 0,

    fn next(self: *Fields) error{ MissingClosingQuote, EmptyQuotes, UnexpectedQuote }!?[]const u8 {
        while (self.index < self.line.len and isSpace(self.line[self.index])) self.index += 1;
        if (self.index == self.line.len) return null;
        if (self.line[self.index] == '"') {
            const start = self.index + 1;
            const end = std.mem.indexOfScalarPos(u8, self.line, start, '"') orelse return error.MissingClosingQuote;
            if (end == start) return error.EmptyQuotes;
            self.index = end + 1;
            if (self.index < self.line.len and !isSpace(self.line[self.index])) return error.UnexpectedQuote;
            return self.line[start..end];
        }
        const start = self.index;
        while (self.index < self.line.len and !isSpace(self.line[self.index])) {
            if (self.line[self.index] == '"') return error.UnexpectedQuote;
            self.index += 1;
        }
        return self.line[start..self.index];
    }
    fn isSpace(c: u8) bool {
        return c == ' ' or c == '\t';
    }
};

fn parseRule(text: []const u8, line: u32, diagnostic: *Diagnostic) error{InvalidRecipes}!Rule {
    var fields: Fields = .{ .line = text };
    // RuleLines only returns lines that aren't blank
    const owner = (try nextField(&fields, line, diagnostic)).?;
    const dash = std.mem.indexOfScalar(u8, owner, '-') orelse
        return fail(diagnostic, line, "expected an owner like PACKAGE-VERSION");
    const package = std.meta.stringToEnum(MsvcupPackageKind, owner[0..dash]) orelse
        return fail(diagnostic, line, "unknown msvcup package");
    const owner_version = owner[dash + 1 ..];
    if (owner_version.len == 0) return fail(diagnostic, line, "owner is missing a version");
    const package_version: ?[]const u8 = if (std.mem.eql(u8, owner_version, version_placeholder)) null else blk: {
        if (versionEnd(owner_version) != owner_version.len)
            return fail(diagnostic, line, "owner version must be digits separated by dots or {version}");
        break :blk owner_version;
    };

    var rule: Rule = .{
        .line = line,
        .package = package,
        .package_version = package_version,
        .id = null,
        .version = null,
        .file_name = null,
    };
    var version_captures: usize = 0;
    while (try nextField(&fields, line, diagnostic)) |predicate| {
        const equals = std.mem.indexOfScalar(u8, predicate, '=') orelse return fail(diagnostic, line, "expected NAME=PATTERN");
        const name = predicate[0..equals];
        const field: *?[]const u8 = blk: {
            if (std.mem.eql(u8, name, "id")) break :blk &rule.id;
            if (std.mem.eql(u8, name, "version")) break :blk &rule.version;
            if (std.mem.eql(u8, name, "fileName")) break :blk &rule.file_name;
            return fail(diagnostic, line, "unknown predicate, expected id, version or fileName");
        };
        if (field.* != null) return fail(diagnostic, line, "duplicate predicate");
        const pattern = predicate[equals + 1 ..];
        version_captures += try validatePattern(pattern, line, diagnostic);
        field.* = pattern;
    }
    if (rule.id == null and rule.version == null and rule.file_name == null) return fail(diagnostic, line, "rule has no predicates");
    if (version_captures > 1) return fail(diagnostic, line, "rule has more than one {version}");
    if (package_version == null and version_captures == 0) return fail(diagnostic, line, "owner uses {version} but no pattern captures it");
    if (package_version != null and version_captures != 0) return fail(diagnostic, line, "pattern captures {version} but the owner doesn't use it");
    return rule;
}

/// Returns the number of {version} placeholders in the pattern. Patterns are
/// matched without backtracking, so this rejects any pattern where a placeholder
/// would consume what comes after it, which could never match.
fn validatePattern(pattern: []const u8, line: u32, diagnostic: *Diagnostic) error{InvalidRecipes}!usize {
    if (pattern.len == 0) return fail(diagnostic, line, "empty pattern");
    const consumed = "a placeholder would consume what comes after it";
    var version_captures: usize = 0;
    var index: usize = 0;
    while (index < pattern.len) {
        switch (pattern[index]) {
            '*' => {
                if (index + 1 != pattern.len) return fail(diagnostic, line, "'*' must be at the end of a pattern");
                index += 1;
            },
            '{' => {
                const rest = pattern[index..];
                if (std.mem.startsWith(u8, rest, version_placeholder)) {
                    version_captures += 1;
                    index += version_placeholder.len;
                    const after = pattern[index..];
                    if (after.len > 0 and std.ascii.isDigit(after[0])) return fail(diagnostic, line, consumed);
                    if (after.len > 1 and after[0] == '.' and std.ascii.isDigit(after[1])) return fail(diagnostic, line, consumed);
                } else if (std.mem.startsWith(u8, rest, arch_placeholder)) {
                    index += arch_placeholder.len;
                    const after = pattern[index..];
                    if (after.len > 0 and (std.ascii.isAlphanumeric(after[0]) or after[0] == '{')) return fail(diagnostic, line, consumed);
                } else return fail(diagnostic, line, "unknown placeholder, expected {version} or {arch}");
            },
            '}' => return fail(diagnostic, line, "unexpected '}' in pattern"),
            else => index += 1,
        }
    }
    return version_captures;
}

/// Checks every rule so that a payload matching more than one is always caught.
pub fn match(self: *const Recipes, attributes: Attributes) Match {
    var found: ?Match.One = null;
    for (self.rules) |*rule| {
        var capture: ?[]const u8 = null;
        if (!matchOptional(rule.id, attributes.id, &capture)) continue;
        if (!matchOptional(rule.version, attributes.version, &capture)) continue;
        if (!matchOptional(rule.file_name, attributes.file_name, &capture)) continue;
        if (found) |one| return .{ .multiple = .{ one.rule, rule } };
        found = .{ .rule = rule, .package_version = rule.package_version orelse capture.? };
    }
    return if (found) |one| .{ .one = one } else .none;
}

fn matchOptional(pattern: ?[]const u8, value: []const u8, capture: *?[]const u8) bool {
    return matchPattern(pattern orelse return true, value, capture);
}

/// Each placeholder consumes as much as it can, there's no backtracking.
fn matchPattern(pattern_start: []const u8, value_start: []const u8, capture: *?[]const u8) bool {
    var pattern = pattern_start;
    var value = value_start;
    while (pattern.len > 0) {
        switch (pattern[0]) {
            // validatePattern ensures this is the end of the pattern
            '*' => return true,
            '{' => {
                const end = if (std.mem.startsWith(u8, pattern, version_placeholder)) blk: {
                    const end = versionEnd(value);
                    if (end == 0) return false;
                    capture.* = value[0..end];
                    pattern = pattern[version_placeholder.len..];
                    break :blk end;
                } else blk: {
                    std.debug.assert(std.mem.startsWith(u8, pattern, arch_placeholder));
                    const end = alphanumericEnd(value);
                    if (Arch.fromStringIgnoreCase(value[0..end]) == null) return false;
                    pattern = pattern[arch_placeholder.len..];
                    break :blk end;
                };
                value = value[end..];
            },
            else => {
                const end = std.mem.indexOfAny(u8, pattern, "*{") orelse pattern.len;
                if (!std.mem.startsWith(u8, value, pattern[0..end])) return false;
                pattern = pattern[end..];
                value = value[end..];
            },
        }
    }
    return value.len == 0;
}

/// Returns the length of the longest prefix that's digits separated by single dots.
fn versionEnd(value: []const u8) usize {
    var end: usize = 0;
    for (value, 0..) |c, i| {
        if (std.ascii.isDigit(c)) {
            end = i + 1;
        } else if (c != '.' or i == 0 or end != i) break;
    }
    return end;
}

fn alphanumericEnd(value: []const u8) usize {
    for (value, 0..) |c, i| {
        if (!std.ascii.isAlphanumeric(c)) return i;
    }
    return value.len;
}

const TestAttributes = struct {
    id: []const u8 = "some.id",
    version: []const u8 = "1.2.3",
    file_name: []const u8 = "file.msi",
};

fn testMatch(recipes: *const Recipes, attributes: TestAttributes) Match {
    return recipes.match(.{
        .id = attributes.id,
        .version = attributes.version,
        .file_name = attributes.file_name,
    });
}

fn testParse(arena: std.mem.Allocator, text: []const u8) !Recipes {
    var diagnostic: Diagnostic = .{};
    return parse(arena, text, &diagnostic) catch |err| {
        std.debug.print("recipes:{}: {s}\n", .{ diagnostic.line, diagnostic.message });
        return err;
    };
}

fn testExpectOwner(
    package: MsvcupPackageKind,
    package_version: []const u8,
    recipes: *const Recipes,
    attributes: TestAttributes,
) !void {
    switch (testMatch(recipes, attributes)) {
        .none, .multiple => return error.TestUnexpectedResult,
        .one => |one| {
            try std.testing.expectEqual(package, one.rule.package);
            try std.testing.expectEqualStrings(package_version, one.package_version);
        },
    }
}

fn testExpectNone(recipes: *const Recipes, attributes: TestAttributes) !void {
    switch (testMatch(recipes, attributes)) {
        .none => {},
        .one, .multiple => return error.TestUnexpectedResult,
    }
}

fn testExpectParseError(line: u32, message: []const u8, text: []const u8) !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_instance.deinit();
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(
        error.InvalidRecipes,
        parse(arena_instance.allocator(), text, &diagnostic),
    );
    try std.testing.expectEqual(line, diagnostic.line);
    try std.testing.expectEqualStrings(message, diagnostic.message);
}

test "the builtin recipes are valid" {
    var arena_instance = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_instance.deinit();
    _ = try testParse(arena_instance.allocator(), @embedFile("recipes.txt"));
}

test "the {version} capture and arch placeholder" {
    var arena_instance = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_instance.deinit();
    const recipes = try testParse(arena_instance.allocator(),
        \\msvc-{version} id=Microsoft.VC.{version}.Tools.Host{arch}.Target{arch}.base
    );
    try testExpectOwner(.msvc, "14.44.17.14", &recipes, .{ .id = "Microsoft.VC.14.44.17.14.Tools.HostX64.TargetX64.base" });
    // the manifest is inconsistent about the case of the arch
    try testExpectOwner(.msvc, "14.44.17.14", &recipes, .{ .id = "Microsoft.VC.14.44.17.14.Tools.Hostx86.Targetarm64.base" });
    try testExpectOwner(.msvc, "14.44.17.14", &recipes, .{ .id = "Microsoft.VC.14.44.17.14.Tools.HostARM64.TargetARM.base" });
    // literals are case sensitive
    try testExpectNone(&recipes, .{ .id = "Microsoft.VC.14.44.17.14.Tools.HostX64.TargetX64.BASE" });
    // a bigger arch isn't an arch
    try testExpectNone(&recipes, .{ .id = "Microsoft.VC.14.44.17.14.Tools.HostX64.TargetARM64EC.base" });
    // doesn't match extra parts or a partial value
    try testExpectNone(&recipes, .{ .id = "Microsoft.VC.14.44.17.14.Tools.HostX64.TargetX64.Res.base" });
    try testExpectNone(&recipes, .{ .id = "Microsoft.VC.14.44.17.14.Tools.HostX64.TargetX64.base.more" });
    // a version must be present and start with a digit
    try testExpectNone(&recipes, .{ .id = "Microsoft.VC..Tools.HostX64.TargetX64.base" });
    try testExpectNone(&recipes, .{ .id = "Microsoft.VC.Preview.Tools.HostX64.TargetX64.base" });
    // a version can't have consecutive dots
    try testExpectNone(&recipes, .{ .id = "Microsoft.VC.14..44.Tools.HostX64.TargetX64.base" });
}

test "a version capture at the end of a value" {
    var arena_instance = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_instance.deinit();
    const recipes = try testParse(arena_instance.allocator(),
        \\ninja-{version} id=ninja-{version}
        \\diasdk-{version} id=dia version={version}
    );
    try testExpectOwner(.ninja, "1.13.2", &recipes, .{ .id = "ninja-1.13.2" });
    try testExpectNone(&recipes, .{ .id = "ninja-1.13.2-beta" });
    try testExpectNone(&recipes, .{ .id = "ninja-1.13." });
    try testExpectNone(&recipes, .{ .id = "ninja-1..2" });
    try testExpectNone(&recipes, .{ .id = "ninja-.1" });
    try testExpectOwner(.diasdk, "7.8", &recipes, .{ .id = "dia", .version = "7.8" });
}

test "stars, quotes and literal owner versions" {
    var arena_instance = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_instance.deinit();
    const recipes = try testParse(arena_instance.allocator(),
        \\# a comment
        \\
        \\sdk-{version}   version={version} "fileName=Installers\Windows SDK Desktop Headers *"
        \\msbuild-170 id=Microsoft.Build
        \\msbuild-170 id=Microsoft.VisualStudio.VC.MSBuild.v170.*
    );
    try testExpectOwner(.sdk, "10.0.1", &recipes, .{ .version = "10.0.1", .file_name = "Installers\\Windows SDK Desktop Headers x64-x86_en-us.msi" });
    try testExpectNone(&recipes, .{ .version = "10.0.1", .file_name = "Installers\\Windows SDK Desktop Libs x64.msi" });
    try testExpectOwner(.msbuild, "170", &recipes, .{ .id = "Microsoft.Build" });
    try testExpectNone(&recipes, .{ .id = "Microsoft.Build.Arm64" });
    try testExpectOwner(.msbuild, "170", &recipes, .{ .id = "Microsoft.VisualStudio.VC.MSBuild.v170.X64.UWP" });
    try testExpectNone(&recipes, .{ .id = "Microsoft.VisualStudio.VC.MSBuild.v1700" });
}

test "a payload matching more than one rule" {
    var arena_instance = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_instance.deinit();
    const recipes = try testParse(arena_instance.allocator(),
        \\msbuild-170 id=Microsoft.*
        \\diasdk-1 id=Microsoft.Build
        \\ninja-1 id=ninja
    );
    switch (testMatch(&recipes, .{ .id = "Microsoft.Build" })) {
        .multiple => |rules| {
            try std.testing.expectEqual(@as(u32, 1), rules[0].line);
            try std.testing.expectEqual(@as(u32, 2), rules[1].line);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "comments can contain anything and still count as lines" {
    var arena_instance = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_instance.deinit();
    const recipes = try testParse(arena_instance.allocator(),
        \\#"quoted comment"
        \\  # it's "unbalanced
        \\msbuild-170 id=foo
    );
    try std.testing.expectEqual(@as(usize, 1), recipes.rules.len);
    try std.testing.expectEqual(@as(u32, 3), recipes.rules[0].line);
}

test "crlf line endings" {
    var arena_instance = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_instance.deinit();
    const recipes = try testParse(arena_instance.allocator(), "# comment\r\n\r\nmsbuild-170 id=foo\r\n");
    try testExpectOwner(.msbuild, "170", &recipes, .{ .id = "foo" });
}

test "the text is referenced and parsing allocates exactly the rules" {
    var arena_instance = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_instance.deinit();
    var failing: std.testing.FailingAllocator = .init(arena_instance.allocator(), .{});
    const text = @embedFile("recipes.txt");
    var diagnostic: Diagnostic = .{};
    const recipes = try parse(failing.allocator(), text, &diagnostic);
    try std.testing.expect(recipes.rules.len > 0);
    try std.testing.expectEqual(@as(usize, 1), failing.allocations);
    try std.testing.expectEqual(recipes.rules.len * @sizeOf(Rule), failing.allocated_bytes);
    try std.testing.expectEqual(@as(usize, 0), failing.freed_bytes);
    const id = recipes.rules[0].id.?;
    try std.testing.expect(@intFromPtr(id.ptr) >= @intFromPtr(text.ptr));
    try std.testing.expect(@intFromPtr(id.ptr) < @intFromPtr(text.ptr) + text.len);
}

test "parse errors" {
    try testExpectParseError(2, "expected an owner like PACKAGE-VERSION", "# comment\nfoo id=a");
    try testExpectParseError(1, "unknown msvcup package", "foo-1 id=a");
    try testExpectParseError(1, "owner is missing a version", "msvc- id=a");
    try testExpectParseError(1, "owner version must be digits separated by dots or {version}", "msvc-* id=a");
    try testExpectParseError(1, "owner version must be digits separated by dots or {version}", "msvc-1.x id=a");
    try testExpectParseError(1, "owner version must be digits separated by dots or {version}", "msvc-1. id=a");
    try testExpectParseError(1, "owner version must be digits separated by dots or {version}", "msvc-1..2 id=a");
    try testExpectParseError(1, "rule has no predicates", "msvc-1");
    try testExpectParseError(1, "expected NAME=PATTERN", "msvc-1 id");
    try testExpectParseError(1, "unknown predicate, expected id, version or fileName", "msvc-1 chip=x");
    try testExpectParseError(1, "duplicate predicate", "msvc-1 id=a id=b");
    try testExpectParseError(1, "empty pattern", "msvc-1 id=");
    try testExpectParseError(1, "missing closing quote", "msvc-1 \"id=a b");
    // a line of only empty quotes must be an error rather than crash
    try testExpectParseError(1, "empty quotes", "\"\"");
    try testExpectParseError(1, "empty quotes", "msvc-1 \"\"");
    try testExpectParseError(1, "a quote must wrap a whole field", "msvc-1 \"id=a\"b");
    try testExpectParseError(1, "a quote must wrap a whole field", "msvc-1 id=a\"b\"");
    try testExpectParseError(1, "'*' must be at the end of a pattern", "msvc-1 id=a**");
    try testExpectParseError(1, "'*' must be at the end of a pattern", "msvc-1 id=a*b");
    try testExpectParseError(1, "'*' must be at the end of a pattern", "msvc-{version} id=a*{version}");
    try testExpectParseError(1, "a placeholder would consume what comes after it", "msvc-{version} id={version}4");
    try testExpectParseError(1, "a placeholder would consume what comes after it", "msvc-{version} id={version}.4");
    try testExpectParseError(1, "a placeholder would consume what comes after it", "msvc-1 id={arch}64");
    try testExpectParseError(1, "a placeholder would consume what comes after it", "msvc-{version} id={arch}{version}");
    try testExpectParseError(1, "unknown placeholder, expected {version} or {arch}", "msvc-1 id=a{version");
    try testExpectParseError(1, "unexpected '}' in pattern", "msvc-1 id=a}");
    try testExpectParseError(1, "unknown placeholder, expected {version} or {arch}", "msvc-1 id={foo}");
    try testExpectParseError(1, "rule has more than one {version}", "msvc-{version} id={version} version={version}");
    try testExpectParseError(1, "owner uses {version} but no pattern captures it", "msvc-{version} id=a");
    try testExpectParseError(1, "pattern captures {version} but the owner doesn't use it", "msvc-1 id={version}");
}

const std = @import("std");
const Arch = @import("arch.zig").Arch;
const MsvcupPackageKind = @import("msvcuppackagekind.zig").MsvcupPackageKind;
