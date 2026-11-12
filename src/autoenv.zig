const builtin = @import("builtin");
const std = @import("std");
const wintrace = @import("wintrace");
const L = std.unicode.utf8ToUtf16LeStringLiteral;

pub const panic = wintrace.panic;
pub const wintrace_options: wintrace.Options = .{ .mode = .small };
pub const std_options: std.Options = .{ .enable_segfault_handler = false };

pub fn main() noreturn {
    if (wintrace.SetUnhandledExceptionFilter(&wintrace.unhandledExceptionFilter) != null) unreachable;
    run() catch |err| wintrace.exitWithErrorTrace(err, @errorReturnTrace());
}

fn run() !noreturn {
    // it looks like we don't even need to update command_line
    const command_line = getCommandLine();

    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // arena_instance.deinit();
    const arena = arena_instance.allocator();

    const self_exe_file = getImagePathName() orelse @panic("no image path name");
    const self_exe_paths = splitDirBasename(self_exe_file) orelse errExit(
        "self exe path '{f}' has no parent directory",
        .{std.unicode.fmtUtf16Le(self_exe_file)},
    );
    std.debug.assert(self_exe_paths.basename.len > 0);

    const exe = blk_exe: {
        {
            const env_file_path = try resolvePath(arena, self_exe_paths.dir, "env");
            defer arena.free(env_file_path);
            const env_file_content = content: {
                const env_file = openFile(env_file_path) orelse errExit(
                    "unable to load environment, '{f}' does not exist",
                    .{std.unicode.fmtUtf16Le(env_file_path)},
                );
                defer _ = std.os.windows.ntdll.NtClose(env_file);
                break :content try readFile(arena, env_file, env_file_path);
            };
            defer arena.free(env_file_content);
            var line_it = std.mem.tokenizeAny(u8, env_file_content, "\r\n");
            while (line_it.next()) |line| {
                var scratch: std.heap.ArenaAllocator = .init(arena);
                defer scratch.deinit();
                const vcvars_path = try resolvePath(scratch.allocator(), self_exe_paths.dir, line);
                try loadVcVars(scratch.allocator(), vcvars_path);
            }
        }
        std.debug.assert(arena_instance.reset(.retain_capacity));

        break :blk_exe (try findExe(arena, self_exe_paths.basename)) orelse errExit(
            "unable to find '{f}' in PATH",
            .{std.unicode.fmtUtf16Le(self_exe_paths.basename)},
        );
    };

    var startup_info = std.mem.zeroes(std.os.windows.STARTUPINFOW);
    var process_info: PROCESS_INFORMATION = undefined;

    // for some reason, using a JOB in the exewrapper for cl.exe intermittently causes this error:
    //     fatal error C1090: PDB API call failed, error code '23': (0x000006BA)
    const use_job = !std.mem.eql(u16, self_exe_paths.basename, L("cl.exe"));

    const CREATE_SUSPENDED = 0x00000004;
    const create_process_flags: u32 = if (use_job) CREATE_SUSPENDED else 0;
    if (0 == CreateProcessW(
        // L(exe_basename),
        exe,
        command_line,
        null,
        null,
        1, // inherit handles
        create_process_flags,
        null,
        null, // keep currnet directory
        &startup_info,
        &process_info,
    )) errExit(
        "CreateProcess for '{f}' failed, error={f}\n",
        .{ std.unicode.fmtUtf16Le(self_exe_paths.basename), fmtError(std.os.windows.GetLastError()) },
    );

    if (use_job) {
        var job: std.os.windows.HANDLE = undefined;
        check("NtCreateJobObject", NtCreateJobObject(&job, JOB_OBJECT_ALL_ACCESS, null));

        var info = std.mem.zeroes(JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
        info.BasicLimitInformation.LimitFlags = .{ .LIMIT_KILL_ON_JOB_CLOSE = 1 };
        check("NtSetInformationJobObject", NtSetInformationJobObject(
            job,
            .JobObjectExtendedLimitInformation,
            &info,
            @sizeOf(@TypeOf(info)),
        ));
        check("NtAssignProcessToJobObject", NtAssignProcessToJobObject(job, process_info.hProcess));
        check("NtResumeThread", std.os.windows.ntdll.NtResumeThread(process_info.hThread, null));
    }
    _ = std.os.windows.ntdll.NtClose(process_info.hThread);
    switch (std.os.windows.ntdll.NtWaitForSingleObject(process_info.hProcess, .FALSE, null)) {
        .WAIT_0 => {},
        else => |status| errExit("NtWaitForSingleObject failed, status=0x{x}", .{@backingInt(status)}),
    }

    var basic_info: std.os.windows.PROCESS.BASIC_INFORMATION = undefined;
    check("NtQueryInformationProcess", std.os.windows.ntdll.NtQueryInformationProcess(
        process_info.hProcess,
        .BasicInformation,
        &basic_info,
        @sizeOf(std.os.windows.PROCESS.BASIC_INFORMATION),
        null,
    ));
    std.os.windows.ntdll.RtlExitUserProcess(@backingInt(basic_info.ExitStatus));
}

fn check(what: []const u8, status: std.os.windows.NTSTATUS) void {
    if (isFailure(status)) errExit("{s} failed, status=0x{x}", .{ what, @backingInt(status) });
}

fn isFailure(status: std.os.windows.NTSTATUS) bool {
    return @backingInt(status) >= 0x80000000;
}

fn getCommandLine() ?[*:0]u16 {
    const str = &std.os.windows.peb().ProcessParameters.CommandLine;
    const buffer = str.Buffer orelse return null;
    const len = str.Length / 2;
    // CreateProcessW takes it 0-terminated, which a UNICODE_STRING doesn't have to be
    if (str.MaximumLength < @as(u32, str.Length) + 2 or buffer[len] != 0) errExit(
        "the command line isn't 0-terminated: '{f}'",
        .{std.unicode.fmtUtf16Le(buffer[0..len])},
    );
    return buffer[0..len :0];
}

fn getImagePathName() ?[]const u16 {
    const str = &std.os.windows.peb().ProcessParameters.ImagePathName;
    if (str.Buffer) |buffer|
        return buffer[0..@divTrunc(str.Length, 2)];
    return null;
}

fn splitDirBasename(path: []const u16) ?struct {
    dir: []const u16,
    basename: []const u16,
} {
    if (std.mem.lastIndexOfAny(u16, path, &[_]u16{ '\\', '/' })) |i| return .{
        .dir = path[0..@max(i, 1)],
        .basename = path[i + 1 ..],
    };
    return null;
}

/// sub_path if it's absolute, otherwise dir joined with it.
fn resolvePath(allocator: std.mem.Allocator, dir: []const u16, sub_path: []const u8) ![:0]u16 {
    const prefix_len = blk: {
        if (std.fs.path.isAbsolute(sub_path)) break :blk 0;
        break :blk switch (dir[dir.len - 1]) {
            '\\', '/' => dir.len,
            else => dir.len + 1,
        };
    };
    const sub_path_len = try std.unicode.calcWtf16LeLen(sub_path);
    const path = try allocator.allocSentinel(u16, prefix_len + sub_path_len, 0);
    if (prefix_len != 0) {
        path[prefix_len - 1] = '\\';
        @memcpy(path[0..dir.len], dir);
    }
    const written = try std.unicode.wtf8ToWtf16Le(path[prefix_len..], sub_path);
    std.debug.assert(written == sub_path_len);
    return path;
}

const dp0 = "%~dp0";

fn loadVcVars(scratch: std.mem.Allocator, vcvars_path_w: [:0]const u16) !void {
    const vcvars_path = std.unicode.fmtUtf16Le(vcvars_path_w);

    const vcvars = content: {
        const file = openFile(vcvars_path_w) orelse errExit("'{f}' does not exist", .{vcvars_path});
        defer _ = std.os.windows.ntdll.NtClose(file);
        break :content try readFile(scratch, file, vcvars_path_w);
    };

    const root_dir = (splitDirBasename(vcvars_path_w) orelse errExit(
        "invalid vcvars path '{f}' missing directory",
        .{vcvars_path},
    )).dir;

    var line_it = std.mem.tokenizeAny(u8, vcvars, "\r\n");
    var lineno: u32 = 0;
    while (line_it.next()) |line| {
        lineno += 1;
        const prefix = "set \"";
        if (!std.mem.startsWith(u8, line, prefix)) errExit(
            "{f}:{}: line did not start with '{s}'",
            .{ vcvars_path, lineno, prefix },
        );
        const eq_index = std.mem.indexOfScalarPos(u8, line, prefix.len, '=') orelse errExit(
            "{f}:{}: missing '=' to end name",
            .{ vcvars_path, lineno },
        );
        const name = line[prefix.len..eq_index];
        const suffix_len = 4 + name.len;
        const expected_end = blk: {
            if (line.len < suffix_len) break :blk false;
            const suffix = line[line.len - suffix_len ..];
            break :blk std.mem.eql(u8, suffix[0..2], ";%") and
                std.mem.eql(u8, suffix[2..][0..name.len], name) and
                std.mem.eql(u8, suffix[2 + name.len ..], "%\"");
        };
        if (!expected_end) errExit(
            "{f}:{}: line did not end with ';%{s}%\"', it ended with '{s}'",
            .{ vcvars_path, lineno, name, if (suffix_len <= line.len) line[line.len - suffix_len ..] else line },
        );
        const paths_start = eq_index + 1;
        const paths_limit = line.len - suffix_len;

        var new_paths_len: usize = 0;
        {
            var offset: usize = paths_start;
            while (scanPath(line, offset, paths_limit)) |scan| {
                if (!std.mem.startsWith(u8, line[offset..], dp0)) errExit(
                    "{f}:{}: invalid path list, expected '{s}' at offset {} but got '{s}'",
                    .{ vcvars_path, lineno, dp0, offset, line[offset..scan.path_end] },
                );
                if (offset != paths_start) new_paths_len += 1; // ';' separator
                new_paths_len += root_dir.len + 1;
                const path_len_wtf16 = try std.unicode.calcWtf16LeLen(line[offset + dp0.len .. scan.path_end]);
                new_paths_len += path_len_wtf16;
                offset = scan.next_offset;
            }
        }

        const name16 = try std.unicode.wtf8ToWtf16LeAllocZ(scratch, name);

        SetLastError(0);
        const get_env_result = GetEnvironmentVariableW(name16, null, 0);
        const current_value_len = if (get_env_result == 0) switch (std.os.windows.GetLastError()) {
            .ENVVAR_NOT_FOUND => 0,
            else => |e| errExit(
                "GetEnvironmentVariable '{s}' failed, error={f}",
                .{ name, fmtError(e) },
            ),
        } else get_env_result - 1;
        const new_current_sep: u1 = if (current_value_len == 0) 0 else 1;
        const new_value_len =
            new_paths_len +
            @as(usize, new_current_sep) +
            current_value_len +
            1; // terminating null

        const new_value = try scratch.alloc(u16, new_value_len);
        defer scratch.free(new_value);

        {
            var new_value_offset: usize = 0;
            var offset: usize = paths_start;
            while (scanPath(line, offset, paths_limit)) |scan| {
                // already checked above
                if (!std.mem.startsWith(u8, line[offset..], dp0)) unreachable;
                if (offset != paths_start) {
                    new_value[new_value_offset] = ';';
                    new_value_offset += 1;
                }
                @memcpy(new_value[new_value_offset..][0..root_dir.len], root_dir);
                new_value_offset += root_dir.len;
                new_value[new_value_offset] = '\\';
                new_value_offset += 1;
                const path_len_wtf16 = try std.unicode.wtf8ToWtf16Le(new_value[new_value_offset..], line[offset + dp0.len .. scan.path_end]);
                new_value_offset += path_len_wtf16;
                offset = scan.next_offset;
            }
            std.debug.assert(new_value_offset == new_paths_len);
        }
        switch (new_current_sep) {
            0 => {},
            1 => new_value[new_paths_len] = ';',
        }
        if (current_value_len > 0) {
            new_value[new_value.len - 1] = 0xcc; // for sanity check
            const final_len = GetEnvironmentVariableW(
                name16,
                @ptrCast(new_value[new_paths_len + @as(usize, new_current_sep) ..].ptr),
                get_env_result,
            );
            std.debug.assert(final_len + 1 == get_env_result);
        } else {
            new_value[new_paths_len + @as(usize, new_current_sep)] = 0;
        }
        std.debug.assert(new_value[new_value.len - 1] == 0);
        if (false) std.log.debug(
            "Env '{s}' setting to '{}'",
            .{ name, std.unicode.fmtUtf16Le(new_value[0 .. new_value.len - 1]) },
        );
        if (0 == SetEnvironmentVariableW(name16, @ptrCast(new_value.ptr))) errExit(
            "SetEnvironmentVariable failed, error={f}",
            .{fmtError(std.os.windows.GetLastError())},
        );
    }
}

fn findExe(allocator: std.mem.Allocator, exe_basename: []const u16) !?[:0]u16 {
    SetLastError(0);
    const len_with_null = GetEnvironmentVariableW(L("PATH"), null, 0);
    if (len_with_null == 0) switch (std.os.windows.GetLastError()) {
        .ENVVAR_NOT_FOUND => errExit("no PATH environment variable to find {f}", .{std.unicode.fmtUtf16Le(exe_basename)}),
        else => |e| errExit(
            "failed to get the PATH environment variable, error={f}",
            .{fmtError(e)},
        ),
    };
    const env_path_buf: []u16 = try allocator.alloc(u16, len_with_null);
    defer allocator.free(env_path_buf);
    {
        const final_len = GetEnvironmentVariableW(
            L("PATH"),
            @ptrCast(env_path_buf.ptr),
            len_with_null,
        );
        std.debug.assert(final_len + 1 == len_with_null);
    }
    const env_path = env_path_buf[0 .. len_with_null - 1];
    var it = std.mem.splitScalar(u16, env_path, ';');
    while (it.next()) |path| {
        const candidate_z = try std.mem.concat(allocator, u16, &.{ path, &[_]u16{'\\'}, exe_basename, &[_]u16{0} });
        var free_candidate = true;
        defer if (free_candidate) allocator.free(candidate_z);

        const candidate_slice: [:0]u16 = candidate_z[0 .. candidate_z.len - 1 :0];
        if (GetFileAttributesW(candidate_slice.ptr) != INVALID_FILE_ATTRIBUTES) {
            free_candidate = false;
            return candidate_slice;
        }
        switch (std.os.windows.GetLastError()) {
            .FILE_NOT_FOUND, .PATH_NOT_FOUND, .ACCESS_DENIED => {},
            else => |e| errExit(
                "GetFileAttributes for '{f}' failed, error={f}",
                .{ std.unicode.fmtUtf16Le(candidate_slice), fmtError(e) },
            ),
        }
    }

    return null;
}

fn scanPath(line: []const u8, offset: usize, limit: usize) ?struct {
    path_end: usize,
    next_offset: usize,
} {
    if (offset >= limit) return null;
    if (std.mem.indexOfScalarPos(u8, line, offset, ';')) |semi_index| {
        return .{ .path_end = semi_index, .next_offset = semi_index + 1 };
    }
    return .{ .path_end = line.len, .next_offset = line.len };
}

/// The NT path for a Win32 path, written to buf. Not RtlDosPathNameToNtPathName_U, which fails
/// for a path of MAX_PATH or more unless the exe's manifest says it's long path aware.
fn ntPath(path: [:0]const u16, buf: *[std.os.windows.PATH_MAX_WIDE]u16) []u16 {
    const prefix = L("\\??\\");
    if (std.mem.startsWith(u16, path, L("\\\\?\\")) or std.mem.startsWith(u16, path, prefix)) {
        // a verbatim path is used as it is
        if (path.len > buf.len) errExit("path '{f}' is too long", .{std.unicode.fmtUtf16Le(path)});
        @memcpy(buf[0..path.len], path);
        buf[0..prefix.len].* = prefix.*;
        return buf[0..path.len];
    }
    // The full path goes where its longest prefix leaves it room: a UNC path's "\\" becomes
    // "\??\UNC\", which is 6 longer.
    const unc_prefix = L("\\??\\UNC\\");
    const full_offset = unc_prefix.len - 2;
    const full_buf = buf[full_offset..];
    const full_byte_len = std.os.windows.ntdll.RtlGetFullPathName_U(path, @intCast(full_buf.len * 2), full_buf.ptr, null);
    if (full_byte_len == 0) errExit("invalid path '{f}'", .{std.unicode.fmtUtf16Le(path)});
    // when the buffer is too small it's the size needed
    if (full_byte_len > full_buf.len * 2) errExit("path '{f}' is too long", .{std.unicode.fmtUtf16Le(path)});
    const full = full_buf[0 .. full_byte_len / 2];
    const end = full_offset + full.len;
    if (std.mem.startsWith(u16, full, L("\\\\.\\"))) {
        // a name like NUL or COM1 becomes a device path, opening it would succeed and read nothing
        if (!isDevicePath(path)) errExit(
            "'{f}' is a device, not a file",
            .{std.unicode.fmtUtf16Le(path)},
        );
        full[0..prefix.len].* = prefix.*;
        return full;
    }
    if (std.mem.startsWith(u16, full, L("\\\\"))) {
        buf[0..unc_prefix.len].* = unc_prefix.*;
        return buf[0..end];
    }
    const start = full_offset - prefix.len;
    buf[start..][0..prefix.len].* = prefix.*;
    return buf[start..end];
}

/// Whether a path starts with "\\.\", with either separator.
fn isDevicePath(path: []const u16) bool {
    if (path.len < 4 or path[2] != '.') return false;
    for ([_]u16{ path[0], path[1], path[3] }) |c| switch (c) {
        '\\', '/' => {},
        else => return false,
    };
    return true;
}

/// Opens a file for reading, null if it doesn't exist. Close it with NtClose.
fn openFile(path: [:0]const u16) ?std.os.windows.HANDLE {
    var nt_path_buf: [std.os.windows.PATH_MAX_WIDE]u16 = undefined;
    const nt_path_slice = ntPath(path, &nt_path_buf);
    var nt_path: std.os.windows.UNICODE_STRING = .{
        .Length = @intCast(nt_path_slice.len * 2),
        .MaximumLength = @intCast(nt_path_slice.len * 2),
        .Buffer = nt_path_slice.ptr,
    };

    var file: std.os.windows.HANDLE = undefined;
    var io_status: std.os.windows.IO_STATUS_BLOCK = undefined;
    switch (std.os.windows.ntdll.NtCreateFile(
        &file,
        .{ .GENERIC = .{ .READ = true }, .STANDARD = .{ .SYNCHRONIZE = true } },
        &.{ .ObjectName = &nt_path },
        &io_status,
        null,
        .{ .NORMAL = true },
        .VALID_FLAGS,
        .OPEN,
        .{ .NON_DIRECTORY_FILE = true, .IO = .SYNCHRONOUS_NONALERT },
        null,
        0,
    )) {
        .SUCCESS => return file,
        .OBJECT_NAME_NOT_FOUND, .OBJECT_PATH_NOT_FOUND => return null,
        else => |status| errExit("open '{f}' failed, status=0x{x}", .{ std.unicode.fmtUtf16Le(path), @backingInt(status) }),
    }
}

/// Reads all of an open file, path is for the error messages.
fn readFile(allocator: std.mem.Allocator, file: std.os.windows.HANDLE, path: []const u16) ![]u8 {
    var io_status: std.os.windows.IO_STATUS_BLOCK = undefined;
    var info: std.os.windows.FILE.STANDARD_INFORMATION = undefined;
    switch (std.os.windows.ntdll.NtQueryInformationFile(file, &io_status, &info, @sizeOf(@TypeOf(info)), .Standard)) {
        .SUCCESS => {},
        else => |status| errExit("get size of '{f}' failed, status=0x{x}", .{ std.unicode.fmtUtf16Le(path), @backingInt(status) }),
    }
    const content = try allocator.alloc(u8, @intCast(info.EndOfFile));
    errdefer allocator.free(content);
    var total: usize = 0;
    while (total < content.len) {
        const remaining = content[total..];
        switch (std.os.windows.ntdll.NtReadFile(file, null, null, null, &io_status, remaining.ptr, @intCast(@min(remaining.len, std.math.maxInt(u32))), null, null)) {
            .SUCCESS => {},
            else => |status| errExit(
                "read '{f}' failed after {} of {} bytes, status=0x{x}",
                .{ std.unicode.fmtUtf16Le(path), total, content.len, @backingInt(status) },
            ),
        }
        total += io_status.Information;
    }
    return content;
}

fn writeStderr(bytes: []const u8) error{WriteFailed}!void {
    const stderr = std.os.windows.peb().ProcessParameters.hStdError;
    var rest = bytes;
    while (rest.len > 0) {
        var io_status: std.os.windows.IO_STATUS_BLOCK = undefined;
        var status = std.os.windows.ntdll.NtWriteFile(
            stderr,
            null,
            null,
            null,
            &io_status,
            rest.ptr,
            @intCast(@min(rest.len, std.math.maxInt(u32))),
            null,
            null,
        );
        if (status == .PENDING) {
            // a handle opened for overlapped io, which is signaled when the write is done
            switch (std.os.windows.ntdll.NtWaitForSingleObject(stderr, .FALSE, null)) {
                .WAIT_0 => {},
                else => return error.WriteFailed,
            }
            status = io_status.u.Status;
        }
        if (isFailure(status) or io_status.Information == 0) return error.WriteFailed;
        rest = rest[io_status.Information..];
    }
}

fn stderrWriter(buffer: []u8) std.Io.Writer {
    return .{ .vtable = &.{ .drain = drainStderr }, .buffer = buffer };
}

fn drainStderr(w: *std.Io.Writer, data: []const []const u8, splat: usize) error{WriteFailed}!usize {
    try writeStderr(w.buffered());
    w.end = 0;
    var written: usize = 0;
    for (data[0 .. data.len - 1]) |bytes| {
        try writeStderr(bytes);
        written += bytes.len;
    }
    const last = data[data.len - 1];
    for (0..splat) |_| try writeStderr(last);
    return written + splat * last.len;
}

/// Writes straight to stderr with ntdll, as does everything else in this file that could go
/// through std.Io. This exe is copied next to every tool it wraps and std.Io more than
/// doubled its size.
fn errExit(comptime fmt: []const u8, args: anytype) noreturn {
    var buf: [1000]u8 = undefined;
    var stderr = stderrWriter(&buf);
    stderr.print(fmt ++ "\n", args) catch {};
    stderr.flush() catch {};
    std.os.windows.ntdll.RtlExitUserProcess(0xff);
}

/// Returns a formatter that will print the given error in the following format:
///
///   <error-code> (<message-string>[...])
///
/// For example:
///
///   2 (The system cannot find the file specified.)
///   5 (Access is denied.)
///
/// The error is formatted using FormatMessage into a stack allocated buffer
/// of 300 bytes. If the message exceeds 300 bytes (Messages can be arbitrarily
/// long) then "..." is appended to the message.  The message may contain newlines
/// and carriage returns but any trailing ones are trimmed.
pub fn fmtError(error_code: std.os.windows.Win32Error) FormatError(300) {
    return .{ .error_code = error_code };
}
pub fn FormatError(comptime max_len: usize) type {
    return struct {
        error_code: std.os.windows.Win32Error,
        pub fn format(self: @This(), writer: *std.Io.Writer) error{WriteFailed}!void {
            try writer.print("{} (", .{@backingInt(self.error_code)});
            var buf: [max_len]u8 = undefined;
            const len = FormatMessageA(
                .{ .FROM_SYSTEM = 1, .IGNORE_INSERTS = 1 },
                null,
                @backingInt(self.error_code),
                0,
                @ptrCast(&buf),
                buf.len,
                null,
            );
            if (len == 0) {
                try writer.writeAll("unknown error");
            }
            const msg = std.mem.trimEnd(u8, buf[0..len], "\r\n");
            try writer.writeAll(msg);
            if (len + 1 >= buf.len) {
                try writer.writeAll("...");
            }
            try writer.writeAll(")");
        }
    };
}

extern "kernel32" fn GetEnvironmentVariableW(
    lpName: ?[*:0]const u16,
    lpBuffer: ?[*:0]u16,
    nSize: u32,
) callconv(.winapi) u32;
extern "kernel32" fn SetEnvironmentVariableW(
    lpName: ?[*:0]const u16,
    lpValue: ?[*:0]const u16,
) callconv(.winapi) BOOL;

const PSTR = [*:0]u8;
extern "kernel32" fn FormatMessageA(
    dwFlags: FORMAT_MESSAGE_OPTIONS,
    lpSource: ?*const anyopaque,
    dwMessageId: u32,
    dwLanguageId: u32,
    lpBuffer: ?PSTR,
    nSize: u32,
    Arguments: ?*?*i8,
) callconv(.winapi) u32;

pub const FORMAT_MESSAGE_OPTIONS = packed struct(u32) {
    _reserved1: u8 = 0,
    ALLOCATE_BUFFER: u1 = 0,
    IGNORE_INSERTS: u1 = 0,
    FROM_STRING: u1 = 0,
    FROM_HMODULE: u1 = 0,
    FROM_SYSTEM: u1 = 0,
    ARGUMENT_ARRAY: u1 = 0,
    _reserved2: u18 = 0,
};

const JOB_OBJECT_ALL_ACCESS = 0x1F003F;
extern "ntdll" fn NtCreateJobObject(
    JobHandle: *std.os.windows.HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: ?*anyopaque,
) callconv(.winapi) std.os.windows.NTSTATUS;

pub const JOBOBJECTINFOCLASS = enum(i32) {
    JobObjectExtendedLimitInformation = 9,
    _,
};

pub const IO_COUNTERS = extern struct {
    ReadOperationCount: u64,
    WriteOperationCount: u64,
    OtherOperationCount: u64,
    ReadTransferCount: u64,
    WriteTransferCount: u64,
    OtherTransferCount: u64,
};

pub const JOB_OBJECT_LIMIT = packed struct(u32) {
    LIMIT_WORKINGSET: u1 = 0,
    LIMIT_PROCESS_TIME: u1 = 0,
    LIMIT_JOB_TIME: u1 = 0,
    LIMIT_ACTIVE_PROCESS: u1 = 0,
    LIMIT_AFFINITY: u1 = 0,
    LIMIT_PRIORITY_CLASS: u1 = 0,
    LIMIT_PRESERVE_JOB_TIME: u1 = 0,
    LIMIT_SCHEDULING_CLASS: u1 = 0,
    LIMIT_PROCESS_MEMORY: u1 = 0,
    LIMIT_JOB_MEMORY: u1 = 0,
    LIMIT_DIE_ON_UNHANDLED_EXCEPTION: u1 = 0,
    LIMIT_BREAKAWAY_OK: u1 = 0,
    LIMIT_SILENT_BREAKAWAY_OK: u1 = 0,
    LIMIT_KILL_ON_JOB_CLOSE: u1 = 0,
    LIMIT_SUBSET_AFFINITY: u1 = 0,
    LIMIT_JOB_MEMORY_LOW: u1 = 0,
    LIMIT_JOB_READ_BYTES: u1 = 0,
    LIMIT_JOB_WRITE_BYTES: u1 = 0,
    LIMIT_RATE_CONTROL: u1 = 0,
    LIMIT_IO_RATE_CONTROL: u1 = 0,
    LIMIT_NET_RATE_CONTROL: u1 = 0,
    _reserved: u11 = 0,
};
pub const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
    PerProcessUserTimeLimit: std.os.windows.LARGE_INTEGER,
    PerJobUserTimeLimit: std.os.windows.LARGE_INTEGER,
    LimitFlags: JOB_OBJECT_LIMIT,
    MinimumWorkingSetSize: usize,
    MaximumWorkingSetSize: usize,
    ActiveProcessLimit: u32,
    Affinity: usize,
    PriorityClass: u32,
    SchedulingClass: u32,
};

const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    IoInfo: IO_COUNTERS,
    ProcessMemoryLimit: usize,
    JobMemoryLimit: usize,
    PeakProcessMemoryUsed: usize,
    PeakJobMemoryUsed: usize,
};

extern "ntdll" fn NtSetInformationJobObject(
    JobHandle: std.os.windows.HANDLE,
    JobObjectInformationClass: JOBOBJECTINFOCLASS,
    JobObjectInformation: *const anyopaque,
    JobObjectInformationLength: u32,
) callconv(.winapi) std.os.windows.NTSTATUS;

extern "ntdll" fn NtAssignProcessToJobObject(
    JobHandle: std.os.windows.HANDLE,
    ProcessHandle: std.os.windows.HANDLE,
) callconv(.winapi) std.os.windows.NTSTATUS;

// zig 0.17 removed most of std.os.windows.kernel32, and what is left of std.os.windows
// uses a BOOL type that can't be compared with 0
const BOOL = i32;
const INVALID_FILE_ATTRIBUTES = 0xffffffff;
const PROCESS_INFORMATION = extern struct {
    hProcess: std.os.windows.HANDLE,
    hThread: std.os.windows.HANDLE,
    dwProcessId: u32,
    dwThreadId: u32,
};
extern "kernel32" fn CreateProcessW(
    lpApplicationName: ?[*:0]const u16,
    lpCommandLine: ?[*:0]u16,
    lpProcessAttributes: ?*std.os.windows.SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*std.os.windows.SECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: u32,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?[*:0]const u16,
    lpStartupInfo: *std.os.windows.STARTUPINFOW,
    lpProcessInformation: *PROCESS_INFORMATION,
) callconv(.winapi) BOOL;
extern "kernel32" fn SetLastError(dwErrCode: u32) callconv(.winapi) void;
extern "kernel32" fn GetFileAttributesW(lpFileName: [*:0]const u16) callconv(.winapi) u32;
