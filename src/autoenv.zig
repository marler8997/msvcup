const builtin = @import("builtin");
const std = @import("std");
const std15 = if (zig_atleast_15) std else @import("std15");

pub const zig_atleast_15 = @import("builtin").zig_version.order(.{ .major = 0, .minor = 15, .patch = 0 }) != .lt;

const File15 = if (zig_atleast_15) std.fs.File else std15.fs.File15;

const win32 = std.os.windows;
const GetLastError = win32.kernel32.GetLastError;
const L = std.unicode.utf8ToUtf16LeStringLiteral;

pub fn main() !u8 {
    // it looks like we don't even need to update command_line
    const command_line = std.mem.span(GetCommandLineW());

    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // arena_instance.deinit();
    const arena = arena_instance.allocator();

    const self_exe_file = getImagePathName() orelse @panic("no image path name");
    const self_exe_paths = splitDirBasename(self_exe_file) orelse errExit(
        "self exe path '{}' has no parent directory",
        .{std.unicode.fmtUtf16Le(self_exe_file)},
    );
    std.debug.assert(self_exe_paths.basename.len > 0);

    const exe = blk_exe: {
        {
            const self_exe_dir_utf8 = try std.unicode.wtf16LeToWtf8Alloc(arena, self_exe_paths.dir);
            defer arena.free(self_exe_dir_utf8);

            const env_file_path = try std.fs.path.join(arena, &.{ self_exe_dir_utf8, "env" });
            defer arena.free(env_file_path);
            const env_file_content = blk: {
                var file = std.fs.cwd().openFile(env_file_path, .{}) catch |err| switch (err) {
                    error.FileNotFound => errExit(
                        "unable to load environment, '{s}' does not exist",
                        .{env_file_path},
                    ),
                    else => |e| return e,
                };
                defer file.close();
                break :blk try file.readToEndAlloc(arena, std.math.maxInt(usize));
            };
            defer arena.free(env_file_content);
            var line_it = std.mem.tokenizeAny(u8, env_file_content, "\r\n");
            while (line_it.next()) |line| {
                var scratch: std.heap.ArenaAllocator = .init(arena);
                defer scratch.deinit();

                const is_absolute = std.fs.path.isAbsolute(line);
                const file_path = if (is_absolute) line else try std.fs.path.join(arena, &.{ self_exe_dir_utf8, line });
                defer if (!is_absolute) arena.free(file_path);

                try loadVcVars(scratch.allocator(), file_path);
            }
        }
        std.debug.assert(arena_instance.reset(.retain_capacity));

        break :blk_exe (try findExe(arena, self_exe_paths.basename)) orelse errExit(
            "unable to find '{f}' in PATH",
            .{std.unicode.fmtUtf16Le(self_exe_paths.basename)},
        );
    };

    var startup_info = std.mem.zeroes(win32.STARTUPINFOW);
    var process_info: win32.PROCESS_INFORMATION = undefined;

    // for some reason, using a JOB in the exewrapper for cl.exe intermittently causes this error:
    //     fatal error C1090: PDB API call failed, error code '23': (0x000006BA)
    const use_job = !std.mem.eql(u16, self_exe_paths.basename, L("cl.exe"));

    const CREATE_SUSPENDED = 0x00000004;
    const create_process_flags: u32 = if (use_job) CREATE_SUSPENDED else 0;
    if (0 == win32.kernel32.CreateProcessW(
        // L(exe_basename),
        exe,
        if (command_line) |cl| cl.ptr else null,
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
        .{ std.unicode.fmtUtf16Le(self_exe_paths.basename), fmtError(GetLastError()) },
    );

    if (use_job) {
        const job = CreateJobObjectW(null, null) orelse errExit(
            "CreateJobObject failed, error={f}",
            .{fmtError(GetLastError())},
        );

        {
            var info = std.mem.zeroes(JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
            info.BasicLimitInformation.LimitFlags = .{ .LIMIT_KILL_ON_JOB_CLOSE = 1 };
            if (0 == SetInformationJobObject(
                job,
                .JobObjectExtendedLimitInformation,
                &info,
                @sizeOf(@TypeOf(info)),
            )) errExit(
                "SetInformationJobObject failed, error={f}",
                .{fmtError(GetLastError())},
            );
        }

        if (0 == AssignProcessToJobObject(
            job,
            process_info.hProcess,
        )) errExit(
            "AssignProcessToJobObject failed, error={f}",
            .{fmtError(GetLastError())},
        );

        {
            const suspend_count = ResumeThread(process_info.hThread);
            if (suspend_count == -1) return errExit(
                "ResumeThread failed, error={f}",
                .{fmtError(win32.GetLastError())},
            );
        }
    }
    win32.CloseHandle(process_info.hThread);
    try win32.WaitForSingleObject(process_info.hProcess, win32.INFINITE);

    var exit_code: u32 = undefined;
    if (0 == win32.kernel32.GetExitCodeProcess(process_info.hProcess, &exit_code)) errExit(
        "GetExitCodeProcess failed, error={f}",
        .{fmtError(GetLastError())},
    );
    win32.kernel32.ExitProcess(exit_code);
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

const dp0 = "%~dp0";

fn loadVcVars(scratch: std.mem.Allocator, vcvars_path: []const u8) !void {
    if (false) std.log.debug("loading vcvars from '{s}'...", .{vcvars_path});

    const vcvars = blk: {
        var file = std.fs.cwd().openFile(vcvars_path, .{}) catch |e|
            errExit("open '{s}' failed with {s}", .{ vcvars_path, @errorName(e) });
        defer file.close();
        break :blk try file.readToEndAlloc(scratch, std.math.maxInt(usize));
    };

    const root_dir = std.fs.path.dirname(vcvars_path) orelse errExit(
        "invalid vcvars path '{s}' missing directory",
        .{vcvars_path},
    );
    const root_dir_len = try std.unicode.calcWtf16LeLen(root_dir);

    var line_it = std.mem.tokenizeAny(u8, vcvars, "\r\n");
    var lineno: u32 = 0;
    while (line_it.next()) |line| {
        lineno += 1;
        const prefix = "set \"";
        if (!std.mem.startsWith(u8, line, prefix)) errExit(
            "{s}:{}: line did not start with '{s}'",
            .{ vcvars_path, lineno, prefix },
        );
        const eq_index = std.mem.indexOfScalarPos(u8, line, prefix.len, '=') orelse errExit(
            "{s}:{}: missing '=' to end name",
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
            "{s}:{}: line did not end with ';%{s}%\"', it ended with '{s}'",
            .{ vcvars_path, lineno, name, if (suffix_len <= line.len) line[line.len - suffix_len ..] else line },
        );
        const paths_start = eq_index + 1;
        const paths_limit = line.len - suffix_len;

        var new_paths_len: usize = 0;
        {
            var offset: usize = paths_start;
            while (scanPath(line, offset, paths_limit)) |scan| {
                if (!std.mem.startsWith(u8, line[offset..], dp0)) errExit(
                    "{s}:{}: invalid path list, expected '{s}' at offset {} but got '{s}'",
                    .{ vcvars_path, lineno, dp0, offset, line[offset..scan.path_end] },
                );
                if (offset != paths_start) new_paths_len += 1; // ';' separator
                new_paths_len += root_dir_len + 1;
                const path_len_wtf16 = try std.unicode.calcWtf16LeLen(line[offset + dp0.len .. scan.path_end]);
                new_paths_len += path_len_wtf16;
                offset = scan.next_offset;
            }
        }

        const name16 = try std.unicode.wtf8ToWtf16LeAllocZ(scratch, name);

        win32.kernel32.SetLastError(.SUCCESS);
        const get_env_result = GetEnvironmentVariableW(name16, null, 0);
        const current_value_len = if (get_env_result == 0) switch (GetLastError()) {
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
                {
                    const len = try std.unicode.wtf8ToWtf16Le(new_value[new_value_offset..], root_dir);
                    std.debug.assert(len == root_dir_len);
                    new_value_offset += len;
                }
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
            .{fmtError(GetLastError())},
        );
    }
}

fn findExe(allocator: std.mem.Allocator, exe_basename: []const u16) !?[:0]u16 {
    win32.kernel32.SetLastError(.SUCCESS);
    const len_with_null = GetEnvironmentVariableW(L("PATH"), null, 0);
    if (len_with_null == 0) switch (GetLastError()) {
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
        if (win32.GetFileAttributesW(candidate_slice.ptr)) |attr| {
            _ = attr;
            free_candidate = false;
            return candidate_slice;
        } else |err| switch (err) {
            error.FileNotFound, error.PermissionDenied => {},
            error.Unexpected => |e| return e,
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

fn errExit(comptime fmt: []const u8, args: anytype) noreturn {
    var stderr_buf: [1000]u8 = undefined;
    var stderr: File15.Writer = .init(stderrFile(), &stderr_buf);
    const maybe_err: ?File15.WriteError = blk: {
        stderr.interface.print(fmt ++ "\n", args) catch break :blk stderr.err.?;
        stderr.interface.flush() catch break :blk stderr.err.?;
        break :blk null;
    };
    if (maybe_err) |e| std.debug.panic(
        "error {s} printing another error to stdout",
        .{@errorName(e)},
    );
    std.process.exit(0xff);
}

pub fn stderrFile() std.fs.File {
    return if (zig_atleast_15) std.fs.File.stderr() else std.io.getStdErr();
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
pub fn fmtError(error_code: win32.Win32Error) FormatError(300) {
    return .{ .error_code = error_code };
}
pub fn FormatError(comptime max_len: usize) type {
    return struct {
        error_code: win32.Win32Error,
        pub fn format(
            self: @This(),
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            _ = fmt;
            _ = options;
            try writer.print("{} (", .{@intFromEnum(self.error_code)});
            var buf: [max_len]u8 = undefined;
            const len = FormatMessageA(
                .{ .FROM_SYSTEM = 1, .IGNORE_INSERTS = 1 },
                null,
                @intFromEnum(self.error_code),
                0,
                @ptrCast(&buf),
                buf.len,
                null,
            );
            if (len == 0) {
                try writer.writeAll("unknown error");
            }
            const msg = std.mem.trimRight(u8, buf[0..len], "\r\n");
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
) callconv(.winapi) win32.BOOL;

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

extern "kernel32" fn CreateJobObjectW(
    lpJobAttributes: ?*win32.SECURITY_ATTRIBUTES,
    lpName: ?[*:0]const u16,
) callconv(.winapi) ?win32.HANDLE;

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
    PerProcessUserTimeLimit: win32.LARGE_INTEGER,
    PerJobUserTimeLimit: win32.LARGE_INTEGER,
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

extern "kernel32" fn SetInformationJobObject(
    hJob: ?win32.HANDLE,
    JobObjectInformationClass: JOBOBJECTINFOCLASS,
    lpJobObjectInformation: ?*anyopaque,
    cbJobObjectInformationLength: u32,
) callconv(.winapi) win32.BOOL;

extern "kernel32" fn AssignProcessToJobObject(
    hJob: ?win32.HANDLE,
    hProcess: ?win32.HANDLE,
) callconv(.winapi) win32.BOOL;

extern "kernel32" fn ResumeThread(
    hThread: ?win32.HANDLE,
) callconv(.winapi) u32;

extern "kernel32" fn GetCommandLineW() callconv(.winapi) ?[*:0]u16;
