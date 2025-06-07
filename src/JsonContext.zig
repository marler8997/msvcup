const JsonContext = @This();

parent: ?*const JsonContext,
format_fn: *const fn (*const JsonContext, std.io.AnyWriter, FormatDepth) anyerror!void,
get_file_path_fn: *const fn (*const JsonContext) ?[]const u8,

pub fn getFilePath(self: *const JsonContext) ?[]const u8 {
    if (self.get_file_path_fn(self)) |p| return p;
    return (self.parent orelse return null).getFilePath();
}
fn formatParent(self: *const JsonContext, writer: std.io.AnyWriter) anyerror!void {
    if (self.parent) |p| try p.formatParent(writer);
    try self.format_fn(self, writer, .parent);
}
pub fn format(
    self: *const JsonContext,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: std.io.AnyWriter,
) !void {
    _ = fmt;
    _ = options;
    if (self.parent) |p| try p.formatParent(writer);
    try self.format_fn(self, writer, .self);
}

fn aJsonValue(value: std.json.Value) []const u8 {
    return switch (value) {
        .null => "null",
        .bool => "a bool",
        .integer, .number_string => "an integer",
        .float => "a float",
        .string => "a string",
        .array => "an array",
        .object => "an object",
    };
}

const JsonType = enum {
    null,
    bool,
    integer,
    float,
    number_string,
    string,
    array,
    object,

    pub fn fromValue(value: std.json.Value) JsonType {
        return switch (value) {
            .null => .null,
            .bool => .bool,
            .integer => .integer,
            .float => .float,
            .number_string => .number_string,
            .string => .string,
            .array => .array,
            .object => .object,
        };
    }

    pub fn an(self: JsonType) []const u8 {
        return switch (self) {
            .null => "null",
            .bool => "a bool",
            .integer, .number_string => "an integer",
            .float => "a float",
            .string => "a string",
            .array => "an array",
            .object => "an object",
        };
    }

    pub fn Context(self: JsonType) type {
        return switch (self) {
            .null => @panic("todo"),
            .bool => @panic("todo"),
            .integer => i64,
            .float => @panic("todo"),
            .number_string => @panic("todo"),
            .string => []const u8,
            .array => Array,
            .object => Object,
        };
    }

    pub fn contextFromValue(
        comptime self: JsonType,
        out_err: *Error,
        context: *const JsonContext,
        value: std.json.Value,
    ) error{Json}!self.Context() {
        switch (self) {
            .integer => return switch (value) {
                .integer => |i| i,
                else => return out_err.set(context, .{ .unexpected_type = .{
                    .expected = .integer,
                    .actual = .fromValue(value),
                } }),
            },
            .string => return switch (value) {
                .string => |s| s,
                else => return out_err.set(context, .{ .unexpected_type = .{
                    .expected = .string,
                    .actual = .fromValue(value),
                } }),
            },
            .array => return switch (value) {
                .array => |a| .{ .parent_context = context, .items = a.items },
                else => return out_err.set(context, .{ .unexpected_type = .{
                    .expected = .array,
                    .actual = .fromValue(value),
                } }),
            },
            .object => return switch (value) {
                .object => |map| .{ .parent_context = context, .map = map },
                else => return out_err.set(context, .{ .unexpected_type = .{
                    .expected = .object,
                    .actual = .fromValue(value),
                } }),
            },
            else => @panic("todo"),
        }
    }
};

const ErrorPayload = union(enum) {
    unexpected_type: struct {
        expected: JsonType,
        actual: JsonType,
    },
    missing_field: []const u8,
    array_index_out_of_bounds: usize,
};
pub const Error = struct {
    context: *const JsonContext,
    payload: ErrorPayload,
    pub fn set(self: *Error, context: *const JsonContext, payload: ErrorPayload) error{Json} {
        self.* = .{ .context = context, .payload = payload };
        return error.Json;
    }
    pub fn format(
        self: Error,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: std.io.AnyWriter,
    ) !void {
        _ = fmt;
        _ = options;
        if (self.context.getFilePath()) |file_path| {
            try writer.print("{s}: ", .{file_path});
        }
        switch (self.payload) {
            .unexpected_type => |u| try writer.print(
                "at {}, expected {s} but got {s}",
                .{ self.context, u.expected.an(), u.actual.an() },
            ),
            .missing_field => |name| try writer.print(
                "{} is missing field '{s}'",
                .{ self.context, name },
            ),
            .array_index_out_of_bounds => |index| try writer.print(
                "index {} is out of bounds for {}",
                .{ index, self.context },
            ),
        }
    }
};

const FormatDepth = enum { self, parent };

pub const File = struct {
    context: JsonContext = .{
        .parent = null,
        .get_file_path_fn = getFilePath2,
        .format_fn = format2,
    },
    file_path: []const u8,

    pub fn as(
        self: *const File,
        comptime json_type: JsonType,
        out_err: *Error,
        value: std.json.Value,
    ) error{Json}!json_type.Context() {
        return json_type.contextFromValue(out_err, &self.context, value);
    }

    fn getFilePath2(context: *const JsonContext) ?[]const u8 {
        const self: *const File = @alignCast(@fieldParentPtr("context", context));
        return self.file_path;
    }
    fn format2(context: *const JsonContext, writer: std.io.AnyWriter, depth: FormatDepth) anyerror!void {
        _ = context;
        switch (depth) {
            .self => try writer.writeAll("the file's root value"),
            .parent => {},
        }
    }
};

pub const Object = struct {
    parent_context: *const JsonContext,
    map: std.json.ObjectMap,

    pub fn getOptionalField(self: *const Object, name: []const u8) ?Field {
        const field_node = self.map.get(name) orelse return null;
        return .init(self.parent_context, name, field_node);
    }
    pub fn getField(
        self: *const Object,
        out_err: *Error,
        name: []const u8,
    ) error{Json}!Field {
        const field_node = self.map.get(name) orelse return out_err.set(
            self.parent_context,
            .{ .missing_field = name },
        );
        return .init(self.parent_context, name, field_node);
    }
};

pub const Field = struct {
    context: JsonContext,
    name: []const u8,
    value: std.json.Value,

    pub fn init(parent: *const JsonContext, name: []const u8, value: std.json.Value) Field {
        return .{
            .context = .{
                .parent = parent,
                .get_file_path_fn = getFilePath2,
                .format_fn = format2,
            },
            .name = name,
            .value = value,
        };
    }

    pub fn as(
        self: *const Field,
        comptime json_type: JsonType,
        out_err: *Error,
    ) error{Json}!json_type.Context() {
        return json_type.contextFromValue(out_err, &self.context, self.value);
    }

    pub fn format(
        self: *const Field,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: std.io.AnyWriter,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("{}", .{&self.context});
    }

    fn getFilePath2(context: *const JsonContext) ?[]const u8 {
        _ = context;
        return null;
    }
    fn format2(context: *const JsonContext, writer: std.io.AnyWriter, depth: FormatDepth) anyerror!void {
        const self: *const Field = @alignCast(@fieldParentPtr("context", context));
        _ = depth;
        try writer.print(".{s}", .{self.name});
    }
};

pub const Array = struct {
    parent_context: *const JsonContext,
    items: []const std.json.Value,

    pub fn getElement(
        self: *const Array,
        out_err: *Error,
        index: usize,
    ) error{Json}!Element {
        if (index >= self.items.len) return out_err.set(
            self.parent_context,
            .{ .array_index_out_of_bounds = index },
        );
        return .init(self.parent_context, index, self.items[index]);
    }
};

pub const Element = struct {
    context: JsonContext,
    index: usize,
    value: std.json.Value,

    pub fn init(parent: *const JsonContext, index: usize, value: std.json.Value) Element {
        return .{
            .context = .{
                .parent = parent,
                .get_file_path_fn = getFilePath2,
                .format_fn = format2,
            },
            .index = index,
            .value = value,
        };
    }

    pub fn as(
        self: *const Element,
        comptime json_type: JsonType,
        out_err: *Error,
    ) error{Json}!json_type.Context() {
        return json_type.contextFromValue(out_err, &self.context, self.value);
    }

    fn getFilePath2(context: *const JsonContext) ?[]const u8 {
        _ = context;
        return null;
    }
    fn format2(context: *const JsonContext, writer: std.io.AnyWriter, depth: FormatDepth) anyerror!void {
        const self: *const Element = @alignCast(@fieldParentPtr("context", context));
        _ = depth;
        try writer.print("[{}]", .{self.index});
    }
};

const std = @import("std");
