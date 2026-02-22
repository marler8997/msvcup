// TODO: maybe  manifests file should go in the cache directory?
//       maybe the packages should go in a subdirectory of the cache?
const log = std.log.scoped(.msvcup);

const global = struct {
    var string_pool: StringPool = undefined;
    var active_file_lock_fn_name: ?[]const u8 = null;

    // Any function with a "Locking" suffix might take a file lock. We want to avoid
    // taking multiple file locks at a time to avoid deadlock. We enforce this with the
    // following functions.
    fn enteredLockingFunction(fn_name: []const u8) void {
        if (active_file_lock_fn_name) |active_fn_name| std.debug.panic(
            "{s} was called while {s} had a file lock",
            .{ fn_name, active_fn_name },
        );
    }
    fn tookFileLock(fn_name: []const u8) void {
        if (active_file_lock_fn_name) |active_fn_name| std.debug.panic(
            "{s} took a file lock while {s} had a file lock",
            .{ fn_name, active_fn_name },
        );
        active_file_lock_fn_name = fn_name;
    }
    fn releasedFileLock(fn_name: []const u8) void {
        std.debug.assert(active_file_lock_fn_name.?.ptr == fn_name.ptr);
        active_file_lock_fn_name = null;
    }
};

pub fn main() !u8 {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_instance.allocator();
    global.string_pool = .init(arena);

    const args_array = try std.process.argsAlloc(arena);
    // no need to free, os will do it
    //defer std.process.argsFree(arena, argsArray);
    const all_args = if (args_array.len == 0) args_array else args_array[1..];

    const cmd, const args = cmd_args_blk: {
        const cmd_arg_index: usize = cmd_arg_index_blk: {
            var arg_index: usize = 0;
            while (true) : (arg_index += 1) {
                if (arg_index == all_args.len) try usage(arena);
                const arg = all_args[arg_index];
                if (!std.mem.startsWith(u8, arg, "-")) break :cmd_arg_index_blk arg_index;
                errExit("TODO: add support for specifying options before command", .{});
            }
        };
        const cmd = all_args[cmd_arg_index];
        for (cmd_arg_index + 1..all_args.len) |i| {
            all_args[i - 1] = all_args[i];
        }
        break :cmd_args_blk .{ cmd, all_args[0 .. all_args.len - 1] };
    };
    if (std.mem.eql(u8, cmd, "install")) return install(arena, args);
    if (std.mem.eql(u8, cmd, "list")) return listCommand(arena, args);
    if (std.mem.eql(u8, cmd, "list-payloads")) return listPayloads(arena, args);
    if (std.mem.eql(u8, cmd, "fetch")) return fetchCommand(arena, args);
    log.err("unknown command '{s}'", .{cmd});
    return 0xff;
}

fn usage(arena: std.mem.Allocator) !noreturn {
    const msvcup_dir: MsvcupDir = try .alloc(arena);
    try std.io.getStdErr().writer().print(
        \\msvcup version {[version]s}
        \\
        \\Usage: msvcup COMMAND ARGS...
        \\
        \\Commands:
        \\--------------------------------------------------------------------------------
        \\
        \\  list                      | List all PKGS.
        \\  install DIR PKGS...       | Install the given PKGS to the given DIR. PKGS are
        \\                            | are of the form:
        \\                            |
        \\                            |      <PKG_NAME>-<VERSION>
        \\                            |
        \\                            | installed to {[install_dir]s}.
        \\  list-payloads             | List all the payloads.
        \\
        \\InstallOptions:
        \\--------------------------------------------------------------------------------
        \\  --lock-file PATH          | A manifest to hold all payloads/urls installed.
        \\  --manifest-update-<OPT>   | Controls whether to update to the latest manifest
        \\                            | if it's already been downloaded. This option will
        \\                            | control whether it's updated to the latest, OPT
        \\                            | can be set to "off", "daily", or "always".
        \\
    ,
        .{
            .version = @embedFile("version"),
            .install_dir = msvcup_dir.root_path,
        },
    );
    std.process.exit(0xff);
}

const MsvcupDir = struct {
    root_path: []const u8,
    pub fn alloc(allocator: std.mem.Allocator) !MsvcupDir {
        return .{
            .root_path = switch (builtin.os.tag) {
                .windows => "C:\\msvcup",
                else => try std.fs.getAppDataDir(allocator, "msvcup"),
            },
        };
    }
    pub fn path(self: MsvcupDir, allocator: std.mem.Allocator, sub_path_tuple: anytype) error{OutOfMemory}![]const u8 {
        var args: [sub_path_tuple.len + 1][]const u8 = undefined;
        args[0] = self.root_path;
        inline for (args[1..], 0..) |*arg, i| {
            arg.* = sub_path_tuple[i];
        }
        return try std.fs.path.join(allocator, &args);
    }
};

const ScratchAllocator = struct {
    arena: std.heap.ArenaAllocator,
    pub fn init() ScratchAllocator {
        return .{ .arena = std.heap.ArenaAllocator.init(std.heap.page_allocator) };
    }
    pub fn allocator(self: *ScratchAllocator) std.mem.Allocator {
        return self.arena.allocator();
    }
    pub fn reset(self: *ScratchAllocator) void {
        std.debug.assert(self.arena.reset(.retain_capacity));
    }
};

fn arenaIsEmpty(arena: std.heap.ArenaAllocator) bool {
    const first_node = arena.state.buffer_list.first orelse return true;
    if (first_node.next != null) return false;
    return arena.state.end_index == 0;
}

fn listCommand(arena: std.mem.Allocator, args: []const []const u8) !u8 {
    // TODO: accept the "--preview" argument
    // TODO: accept the "--manifest-update-*" arguments
    if (args.len != 0) errExit("the 'list-versions' command does not take any arguments", .{});

    const root_node = std.Progress.start(.{ .root_name = "msvcup list-versions" });
    defer root_node.end();

    var scratch_instance: ScratchAllocator = .init();
    const scratch = scratch_instance.allocator();

    const msvcup_dir: MsvcupDir = try .alloc(arena);

    const vsman = try readVsManifestLocking(arena, root_node, scratch, msvcup_dir, .release, .off);
    defer vsman.freeConst(arena);
    scratch_instance.reset();

    const pkgs = try getPackages(arena, scratch, vsman);
    // defer arena.free(pkgs);
    scratch_instance.reset();

    var msvcup_pkgs: std.ArrayListUnmanaged(MsvcupPackage) = .{};
    for (pkgs.slice, 0..) |pkg, pkg_index| {
        switch (identifyPackage(pkg.id)) {
            .unknown => {},
            .unexpected => |u| try std.debug.panic(
                "unexpected package id '{s}' (expected {s} at offset {} '{s}')\n",
                .{ pkg.id, @tagName(u.expected), u.offset, pkg.id[u.offset..] },
            ),
            .msvc_version_something => {},
            .msvc_version_tools_something => {},
            .msvc_version_host_target => |p| {
                const msvcup_pkg: MsvcupPackage = .initStr(.msvc, p.build_version);
                insertSorted(MsvcupPackage, arena, &msvcup_pkgs, msvcup_pkg, {}, MsvcupPackage.order) catch |e| oom(e);
            },
            .msbuild => |version| {
                const msvcup_pkg: MsvcupPackage = .initStr(.msbuild, version);
                insertSorted(MsvcupPackage, arena, &msvcup_pkgs, msvcup_pkg, {}, MsvcupPackage.order) catch |e| oom(e);
            },
            .diasdk => {
                const msvcup_pkg: MsvcupPackage = .initStr(.diasdk, pkg.version);
                insertSorted(MsvcupPackage, arena, &msvcup_pkgs, msvcup_pkg, {}, MsvcupPackage.order) catch |e| oom(e);
            },
            .ninja => |version| {
                const msvcup_pkg: MsvcupPackage = .initStr(.ninja, version);
                insertSorted(MsvcupPackage, arena, &msvcup_pkgs, msvcup_pkg, {}, MsvcupPackage.order) catch |e| oom(e);
            },
            .cmake => |version| {
                const msvcup_pkg: MsvcupPackage = .initStr(.cmake, version);
                insertSorted(MsvcupPackage, arena, &msvcup_pkgs, msvcup_pkg, {}, MsvcupPackage.order) catch |e| oom(e);
            },
        }

        for (pkgs.payloadsFromPkgIndex(.fromInt(pkg_index))) |payload| {
            switch (identifyPayload(payload.file_name)) {
                .unknown => {},
                .sdk => {
                    const msvcup_pkg: MsvcupPackage = .initStr(.sdk, pkg.version);
                    insertSorted(MsvcupPackage, arena, &msvcup_pkgs, msvcup_pkg, {}, MsvcupPackage.order) catch |e| oom(e);
                },
            }
        }
    }

    var bw = std.io.bufferedWriter(std.io.getStdOut().writer());
    try bw.writer().writeAll("autoenv\n");
    for (msvcup_pkgs.items) |msvcup_pkg| {
        try bw.writer().print("{}\n", .{msvcup_pkg});
    }
    try bw.flush();
    return 0;
}

fn listPayloads(arena: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len != 0) errExit("list-payloads does not take any arguments", .{});

    const root_node = std.Progress.start(.{ .root_name = "msvcup list-versions" });
    defer root_node.end();

    var scratch_instance: ScratchAllocator = .init();
    const scratch = scratch_instance.allocator();

    const msvcup_dir: MsvcupDir = try .alloc(arena);

    const vsman = try readVsManifestLocking(arena, root_node, scratch, msvcup_dir, .release, .off);
    defer vsman.freeConst(arena);
    scratch_instance.reset();

    var payload_indices: std.ArrayListUnmanaged(PayloadIndex) = .{};

    const pkgs = try getPackages(arena, scratch, vsman);
    // defer arena.free(pkgs);
    scratch_instance.reset();

    for (pkgs.slice, 0..) |pkg, pkg_index| {
        switch (pkg.language) {
            .neutral => {},
            .en_us => {},
            .other => continue,
        }
        // just a sanity check
        switch (identifyPackage(pkg.id)) {
            .unexpected => |u| try std.debug.panic(
                "unexpected package id '{s}' (expected {s} at offset {} '{s}')\n",
                .{ pkg.id, @tagName(u.expected), u.offset, pkg.id[u.offset..] },
            ),
            else => {},
        }
        const payload_range = pkgs.payloadRangeFromPkgIndex(.fromInt(pkg_index));
        for (payload_range.start..payload_range.limit) |payload_index| {
            insertSorted(
                PayloadIndex,
                arena,
                &payload_indices,
                .fromInt(payload_index),
                pkgs.payloads,
                PayloadIndex.order,
            ) catch |e| oom(e);
        }
    }

    var bw = std.io.bufferedWriter(std.io.getStdOut().writer());
    for (payload_indices.items) |payload_index| {
        const pkg_index = pkgs.pkgIndexFromPayloadIndex(payload_index);
        const payload = &pkgs.payloads[payload_index.int()];
        const pkg = &pkgs.slice[pkg_index.int()];
        try bw.writer().print("{s} ({s})\n", .{ payload.file_name, pkg.id });
    }
    try bw.flush();
    return 0;
}

fn fetchCommand(arena: std.mem.Allocator, args: []const []const u8) !u8 {
    const root_node = std.Progress.start(.{ .root_name = "msvcup fetch" });
    defer root_node.end();

    const Config = struct {
        url: []const u8,
        cache_dir: ?[]const u8,
    };
    const config: Config = blk_config: {
        var url: ?[]const u8 = null;
        var cache_dir: ?[]const u8 = null;
        var arg_index: usize = 0;
        while (arg_index < args.len) : (arg_index += 1) {
            const arg = args[arg_index];
            if (!std.mem.startsWith(u8, arg, "-")) {
                if (url != null) errExit("too many cmdline args, expected 1 URL", .{});
                url = arg;
            } else if (std.mem.eql(u8, arg, "--cache-dir")) {
                arg_index += 1;
                if (arg_index == args.len) errExit("--cache-dir missing argument", .{});
                cache_dir = args[arg_index];
            } else errExit("unknown cmdline argument '{s}'", .{arg});
        }
        break :blk_config .{
            .url = url orelse errExit("missing URL to fetch", .{}),
            .cache_dir = cache_dir,
        };
    };

    const uri = std.Uri.parse(config.url) catch |err| errExit(
        "invalid uri '{s}': {s}",
        .{ config.url, @errorName(err) },
    );
    const pkg = switch (extra.parseUrl(config.url)) {
        .ok => |pkg| pkg,
        .unexpected => |u| errExit(
            "invalid package url '{s}' expected {s} at offset {} but got '{s}'",
            .{ config.url, u.what, u.offset, config.url[u.offset..] },
        ),
    };
    _ = pkg;

    const msvcup_dir: MsvcupDir = try .alloc(arena);

    const cache_dir: []const u8 = config.cache_dir orelse msvcup_dir.path(
        arena,
        &.{"cache"},
    ) catch |e| oom(e);

    var scratch_instance: ScratchAllocator = .init();
    const scratch = scratch_instance.allocator();

    {
        const cache_path = std.fs.path.join(scratch, &.{ cache_dir, "nohash" }) catch |e| oom(e);
        defer scratch.free(cache_path);

        const cache_lock_path = std.mem.concat(scratch, u8, &.{ cache_path, ".lock" }) catch |e| oom(e);
        defer scratch.free(cache_lock_path);
        var cache_lock = try LockFile.lock(cache_lock_path);
        defer cache_lock.unlock();

        const sha256 = try fetch(root_node, scratch, uri, cache_path, .{});
        try finishCacheFetch(scratch, cache_dir, config.url, sha256, cache_path);
        try std.io.getStdOut().writer().print("{f}", .{sha256});
        try std.io.getStdOut().writer().writeAll("\n");
    }
    return 0;
}

const Sha = struct {
    bytes: [32]u8,
    pub fn parseHex(hex: *const [64]u8) ?Sha {
        var result: Sha = undefined;
        for (&result.bytes, 0..) |*byte, i| {
            const high: u8 = nibbleFromHex(hex[i * 2]) orelse return null;
            const low: u8 = nibbleFromHex(hex[i * 2 + 1]) orelse return null;
            byte.* = (high << 4) | low;
        }
        return result;
    }
    fn nibbleFromHex(c: u8) ?u4 {
        return switch (c) {
            '0'...'9' => @intCast(c - '0'),
            'a'...'f' => @intCast(c - 'a' + 10),
            else => null,
        };
    }
    pub fn eql(sha: *const Sha, other: *const Sha) bool {
        return std.mem.eql(u8, &sha.bytes, &other.bytes);
    }
    pub fn toHex(sha: *const Sha) [64]u8 {
        var buf: [64]u8 = undefined;
        std.debug.assert(64 == (std.fmt.bufPrint(&buf, "{f}", .{sha}) catch unreachable).len);
        return buf;
    }
    pub fn format(
        value: Sha,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("{f}", .{std.fmt.fmtSliceHexLower(&value.bytes)});
    }
};

fn lowerShaHex(sha: *const [64]u8) [64]u8 {
    var result: [64]u8 = undefined;
    for (&result, sha) |*dst, src| {
        dst.* = std.ascii.toLower(src);
    }
    return result;
}

fn finishCacheFetch(
    scratch: std.mem.Allocator,
    cache_dir: []const u8,
    url: []const u8,
    sha256: Sha,
    cache_path: []const u8,
) !void {
    const entry = CacheEntry.alloc(scratch, scratch, cache_dir, sha256, basenameFromUrl(url));
    defer entry.free(scratch);
    const already_exists = if (std.fs.accessAbsolute(entry.path, .{})) true else |err| switch (err) {
        error.FileNotFound => false,
        else => |e| return e,
    };
    if (already_exists) {
        std.log.info("{s}: already exists", .{entry.path});
        try std.fs.cwd().deleteFile(cache_path);
    } else {
        std.log.info("{s}: newly fetched", .{entry.path});
        try std.fs.cwd().rename(cache_path, entry.path);
    }
}

const MsvcupPackageKind = enum {
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
const MsvcupPackage = struct {
    kind: MsvcupPackageKind,
    version: StringPool.Val,
    pub fn initStr(kind: MsvcupPackageKind, version: []const u8) MsvcupPackage {
        return .{ .kind = kind, .version = global.string_pool.add(version) catch |e| oom(e) };
    }
    pub fn fromString(pkg: []const u8) union(enum) {
        ok: MsvcupPackage,
        autoenv,
        unknown_name,
        invalid_version: []const u8,
    } {
        if (std.mem.eql(u8, pkg, "autoenv")) return .autoenv;
        const kind: MsvcupPackageKind, const version: []const u8 = blk: {
            if (startsWith(u8, pkg, "msvc-")) |version| break :blk .{ .msvc, version };
            if (startsWith(u8, pkg, "sdk-")) |version| break :blk .{ .sdk, version };
            if (startsWith(u8, pkg, "msbuild-")) |version| break :blk .{ .msbuild, version };
            if (startsWith(u8, pkg, "diasdk-")) |version| break :blk .{ .diasdk, version };
            if (startsWith(u8, pkg, "ninja-")) |version| break :blk .{ .ninja, version };
            if (startsWith(u8, pkg, "cmake-")) |version| break :blk .{ .cmake, version };
            return .unknown_name;
        };
        return if (isValidVersion(version)) .{ .ok = .{
            .kind = kind,
            .version = global.string_pool.add(version) catch |e| oom(e),
        } } else .{ .invalid_version = version };
    }
    pub fn poolString(self: MsvcupPackage) StringPool.Val {
        var buf: [100]u8 = undefined;
        const name = std.fmt.bufPrint(&buf, "{}", .{self}) catch @panic("version too long");
        return global.string_pool.add(name) catch |e| oom(e);
    }
    pub fn order(_: void, lhs: MsvcupPackage, rhs: MsvcupPackage) std.math.Order {
        return switch (MsvcupPackageKind.order({}, lhs.kind, rhs.kind)) {
            .lt, .gt => |o| o,
            .eq => orderDottedNumeric({}, lhs.version.slice, rhs.version.slice),
        };
    }
    pub fn format(
        self: MsvcupPackage,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("{s}-{s}", .{ @tagName(self.kind), self.version.slice });
    }
};

fn defaultLockFile(allocator: std.mem.Allocator, install_dir: []const u8) error{OutOfMemory}![]const u8 {
    const dir = std.mem.trimRight(u8, install_dir, "\\/");
    return try std.fmt.allocPrint(allocator, "{s}.lock", .{dir});
}

fn install(arena: std.mem.Allocator, args: []const []const u8) !u8 {
    const Config = struct {
        install_dir: []const u8,
        autoenv: bool,
        msvcup_pkgs: []const MsvcupPackage,
        lock_file: []const u8,
        manifest_update: ManifestUpdate,
        cache_dir: ?[]const u8,
    };
    const config: Config = blk_config: {
        var maybe_install_dir: ?[]const u8 = null;
        var autoenv: bool = false;
        var msvcup_pkgs: std.ArrayListUnmanaged(MsvcupPackage) = .{};
        var maybe_lock_file: ?[]const u8 = null;
        var maybe_manifest_update: ?ManifestUpdate = null;
        var cache_dir: ?[]const u8 = null;

        var arg_index: usize = 0;
        while (arg_index < args.len) : (arg_index += 1) {
            const arg = args[arg_index];
            if (!std.mem.startsWith(u8, arg, "-")) {
                if (maybe_install_dir == null) {
                    maybe_install_dir = arg;
                } else switch (MsvcupPackage.fromString(arg)) {
                    .ok => |pkg| insertSorted(
                        MsvcupPackage,
                        arena,
                        &msvcup_pkgs,
                        pkg,
                        {},
                        MsvcupPackage.order,
                    ) catch |e| oom(e),
                    .autoenv => autoenv = true,
                    .unknown_name => errExit("unknown package '{s}'", .{arg}),
                    .invalid_version => |v| errExit("package '{s}' has invalid version '{s}'", .{ arg, v }),
                }
            } else if (std.mem.eql(u8, arg, "--lock-file")) {
                arg_index += 1;
                if (arg_index == args.len) errExit("--lock-file missing argument", .{});
                maybe_lock_file = args[arg_index];
            } else if (std.mem.eql(u8, arg, "--manifest-update-off")) {
                maybe_manifest_update = .off;
            } else if (std.mem.eql(u8, arg, "--manifest-update-daily")) {
                maybe_manifest_update = .daily;
            } else if (std.mem.eql(u8, arg, "--manifest-update-always")) {
                maybe_manifest_update = .always;
            } else if (std.mem.eql(u8, arg, "--cache-dir")) {
                arg_index += 1;
                if (arg_index == args.len) errExit("--cache-dir missing argument", .{});
                cache_dir = args[arg_index];
            } else errExit("unknown cmdline argument '{s}'", .{arg});
        }

        // sanity check everything is sorted
        if (msvcup_pkgs.items.len > 0) for (1..msvcup_pkgs.items.len) |i| {
            std.debug.assert(.lt == MsvcupPackage.order({}, msvcup_pkgs.items[i - 1], msvcup_pkgs.items[i]));
        };

        const install_dir = maybe_install_dir orelse errExit(
            "cmdline missing DIR to install to",
            .{},
        );

        break :blk_config .{
            .install_dir = install_dir,
            .autoenv = autoenv,
            .msvcup_pkgs = msvcup_pkgs.toOwnedSlice(arena) catch |e| oom(e),
            .lock_file = maybe_lock_file orelse try defaultLockFile(arena, install_dir),
            .manifest_update = maybe_manifest_update orelse errExit(
                "missing one of --manifest-update-off, --manifest-update-daily or --manifest-update-always",
                .{},
            ),
            .cache_dir = cache_dir,
        };
    };

    const msvcup_dir: MsvcupDir = try .alloc(arena);

    if (config.msvcup_pkgs.len == 0) errExit(
        "no packages were given to install, use 'list' to list the available packages",
        .{},
    );

    const cache_dir: []const u8 = config.cache_dir orelse msvcup_dir.path(
        arena,
        &.{"cache"},
    ) catch |e| oom(e);

    const root_node = std.Progress.start(.{ .root_name = "msvcup install" });
    defer root_node.end();

    var scratch_instance: ScratchAllocator = .init();
    const scratch = scratch_instance.allocator();

    const try_no_update = switch (config.manifest_update) {
        .off => true,
        .daily => @panic("todo"),
        .always => false,
    };
    if (try_no_update) {
        const maybe_lock_file_content: ?[]const u8 = blk: {
            if (std.fs.cwd().openFile(config.lock_file, .{})) |lock_file| {
                defer lock_file.close();
                log.info("lock file found: '{s}'", .{config.lock_file});
                break :blk try lock_file.readToEndAlloc(arena, std.math.maxInt(usize));
            } else |err| switch (err) {
                error.FileNotFound => {
                    log.info("lock file NOT found: '{s}'", .{config.lock_file});
                    break :blk null;
                },
                else => |e| return e,
            }
        };
        if (maybe_lock_file_content) |content| {
            if (checkLockFilePkgs(
                config.lock_file,
                content,
                config.autoenv,
                config.msvcup_pkgs,
            )) |mismatch| {
                std.log.info("{}", .{mismatch});
            } else {
                const result = try installFromLockFile(
                    scratch,
                    root_node,
                    config.install_dir,
                    cache_dir,
                    config.lock_file,
                    content,
                );
                scratch_instance.reset();
                switch (result) {
                    .success => return 0,
                    .version_mismatch => {},
                }
            }
        }
    }

    const vsman = try readVsManifestLocking(arena, root_node, scratch, msvcup_dir, .release, .off);
    defer vsman.freeConst(arena);
    scratch_instance.reset();

    const pkgs = try getPackages(arena, scratch, vsman);
    // defer arena.free(pkgs);
    scratch_instance.reset();

    try updateLockFile(
        scratch,
        root_node,
        config.autoenv,
        config.msvcup_pkgs,
        config.lock_file,
        pkgs,
        cache_dir,
    );
    scratch_instance.reset();

    const lock_file_content = blk: {
        const lock_file = std.fs.cwd().openFile(config.lock_file, .{}) catch |e| std.debug.panic(
            "failed to open lock file '{s}' with {s} just after updating it",
            .{ config.lock_file, @errorName(e) },
        );
        defer lock_file.close();
        break :blk try lock_file.readToEndAlloc(arena, std.math.maxInt(usize));
    };

    if (checkLockFilePkgs(
        config.lock_file,
        lock_file_content,
        config.autoenv,
        config.msvcup_pkgs,
    )) |mismatch| errExit(
        "lock file '{s}' still doesn't match what we're installing even after it's been updated: {s}",
        .{ config.lock_file, mismatch },
    );
    switch (try installFromLockFile(
        scratch,
        root_node,
        config.install_dir,
        cache_dir,
        config.lock_file,
        lock_file_content,
    )) {
        .success => return 0,
        .version_mismatch => @panic("lock file version mismatch even after update"),
    }
}

const native_arch: ?Arch = switch (builtin.cpu.arch) {
    .x86_64 => .x64,
    .x86 => .x86,
    .arm => .arm,
    .aarch64 => .arm64,
    .powerpc64le, .riscv64, .s390x => null,
    else => |a| @compileError("unhandled host cpu: " ++ @tagName(a)),
};

const Tool = struct {
    name: []const u8,
    cmake_names: []const []const u8,
};
const msvc_tools = [_]Tool{
    .{ .name = "cl", .cmake_names = &.{ "C_COMPILER", "CXX_COMPILER" } },
    .{ .name = "ml64", .cmake_names = &.{"ASM_COMPILER"} },
    .{ .name = "link", .cmake_names = &.{"LINKER"} },
    .{ .name = "lib", .cmake_names = &.{"AR"} },
} ++ switch (builtin.cpu.arch) {
    .aarch64 => [_]Tool{
        .{ .name = "armasm64", .cmake_names = &.{} },
    },
    else => [_]Tool{},
};
const sdk_tools = [_]Tool{
    .{ .name = "rc", .cmake_names = &.{"RC_COMPILER"} },
    .{ .name = "mt", .cmake_names = &.{"MT"} },
};

fn updateAutoenv(
    scratch: std.mem.Allocator,
    install_path: []const u8,
    unique_pkgs: *const UniquePackages,
) !void {
    const autoenv_path = try std.fs.path.join(scratch, &.{ install_path, "autoenv" });
    defer scratch.free(autoenv_path);

    if (!unique_pkgs.autoenv) {
        try std.fs.cwd().deleteTree(autoenv_path);
        return;
    }

    const install_path_absolute: AbsolutePath = try .init(scratch, install_path);
    defer install_path_absolute.deinit(scratch);

    var autoenv_dir = try std.fs.cwd().makeOpenPath(autoenv_path, .{});
    defer autoenv_dir.close();
    inline for (std.meta.fields(Arch)) |arch_field| {
        const target_cpu: Arch = @enumFromInt(arch_field.value);
        var autoenv_arch_dir = try autoenv_dir.makeOpenPath(@tagName(target_cpu), .{});
        defer autoenv_arch_dir.close();
        try installAutoenvArch(scratch, &install_path_absolute, unique_pkgs, target_cpu, autoenv_arch_dir);
    }
}

fn installAutoenvArch(
    scratch: std.mem.Allocator,
    install_path: *const AbsolutePath,
    unique_pkgs: *const UniquePackages,
    target_cpu: Arch,
    out_dir: std.fs.Dir,
) !void {
    {
        var content_buf: [100]u8 = undefined;
        const content = try std.fmt.bufPrint(&content_buf, "..\\..\\vcvars-{s}.bat\n", .{@tagName(target_cpu)});
        try updateFile(out_dir, "env", content);
    }

    if (unique_pkgs.msvc) |_| {
        inline for (msvc_tools) |tool| {
            try updateFile(out_dir, tool.name ++ ".exe", @embedFile("autoenv_exe"));
        }
    }
    if (unique_pkgs.sdk) |_| {
        inline for (sdk_tools) |tool| {
            try updateFile(out_dir, tool.name ++ ".exe", @embedFile("autoenv_exe"));
        }
    }

    {
        const cmake = generateToolchainCmake(scratch, unique_pkgs, target_cpu) catch |e| oom(e);
        defer scratch.free(cmake);
        try updateFile(out_dir, "toolchain.cmake", cmake);
    }

    {
        const libc_txt = generateLibcTxt(scratch, install_path, unique_pkgs, target_cpu) catch |e| oom(e);
        defer scratch.free(libc_txt);
        try updateFile(out_dir, "libc.txt", libc_txt);
    }
}

fn updateFile(dir: std.fs.Dir, sub_path: []const u8, content: []const u8) !void {
    const needs_update = !try fileMatches(dir, sub_path, content);
    {
        const status: []const u8 = if (needs_update) "updating..." else "already up-to-date";
        std.log.info("{s}: {s}", .{ sub_path, status });
    }
    if (needs_update) {
        var file = try dir.createFile(sub_path, .{});
        defer file.close();
        try file.writer().writeAll(content);
    }
}

const LockFileMismatch = union(enum) {
    msvc: struct { requested: []const u8, lockfile: []const u8 },
    autoenv: bool, // lockfile value
    missing_pkg: MsvcupPackage,
    extra_pkg: MsvcupPackage,
    pub fn format(
        self: LockFileMismatch,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .msvc => |v| try writer.print(
                "lock file is for msvc version '{s}' but '{s}' was requested",
                .{ v.lockfile, v.requested },
            ),
            .autoenv => |lockfile_value| try writer.print(
                "lock file {s} autoenv",
                .{@as([]const u8, if (lockfile_value) "has" else "does not have")},
            ),
            .missing_pkg => |pkg| try writer.print("lock file is missing package '{}'", .{pkg}),
            .extra_pkg => |pkg| try writer.print("lock file has extra package '{}' that was not given on cmdline", .{pkg}),
        }
    }
};
fn checkLockFilePkgs(
    lock_file_path: []const u8,
    lock_file_content: []const u8,
    autoenv: bool,
    msvcup_pkgs: []const MsvcupPackage,
) ?LockFileMismatch {
    std.debug.assert(msvcup_pkgs.len > 0);
    var line_it = std.mem.tokenizeAny(u8, lock_file_content, "\r\n");
    var lineno: u32 = 0;
    var has_autoenv: bool = false;
    var msvcup_pkg_index: usize = 0;
    var msvcup_pkg_match_count: usize = 0;
    while (line_it.next()) |line| {
        lineno += 1;
        if (line.len == 0) continue;
        const payload = switch (parseLockFileLine(lock_file_path, lineno, line)) {
            .autoenv => {
                has_autoenv = true;
                continue;
            },
            .payload => |payload| payload,
        };
        while (true) {
            switch (payload.url_kind) {
                .top_level => |payload_msvcup_pkg| switch (MsvcupPackage.order(
                    {},
                    msvcup_pkgs[msvcup_pkg_index],
                    payload_msvcup_pkg,
                )) {
                    .eq => {
                        msvcup_pkg_match_count += 1;
                        break;
                    },
                    .lt => {
                        if (msvcup_pkg_match_count == 0) return .{
                            .missing_pkg = msvcup_pkgs[msvcup_pkg_index],
                        };
                        if (msvcup_pkg_index + 1 == msvcup_pkgs.len) return .{
                            .extra_pkg = payload_msvcup_pkg,
                        };
                        msvcup_pkg_index += 1;
                        msvcup_pkg_match_count = 0;
                        continue;
                    },
                    .gt => return .{ .extra_pkg = payload_msvcup_pkg },
                },
                .cab => break,
            }
        }
    }
    if (msvcup_pkg_index + 1 < msvcup_pkgs.len or
        msvcup_pkg_match_count == 0) return .{
        .missing_pkg = msvcup_pkgs[msvcup_pkg_index],
    };
    if (autoenv != has_autoenv) return .{ .autoenv = has_autoenv };
    return null;
}

const LockFilePayload = struct {
    url_decoded: []const u8,
    sha256: Sha,
    url_kind: union(enum) {
        top_level: MsvcupPackage,
        cab: []const u8,
    },

    pub fn stripRootDir(payload: *const LockFilePayload) bool {
        return switch (payload.url_kind) {
            .top_level => |pkg| switch (pkg.kind) {
                .cmake => true,
                else => false,
            },
            .cab => false,
        };
    }

    pub fn hostArchLimit(payload: *const LockFilePayload) ?Arch {
        return switch (payload.url_kind) {
            .top_level => |pkg| switch (pkg.kind) {
                .msvc, .sdk, .msbuild, .diasdk => null,
                .ninja, .cmake => switch (extra.parseUrl(payload.url_decoded)) {
                    .ok => |p| p.arch,
                    .unexpected => |u| errExit(
                        "invalid package url '{s}' expected {s} at offset {} but got '{s}'",
                        .{ payload.url_decoded, u.what, u.offset, payload.url_decoded[u.offset..] },
                    ),
                },
            },
            .cab => null,
        };
    }
};

const LockFileLine = union(enum) {
    autoenv,
    payload: LockFilePayload,
};

fn parseLockFileLine(
    lock_file_path: []const u8,
    lineno: u32,
    line: []const u8,
) LockFileLine {
    if (std.mem.eql(u8, line, "autoenv")) return .autoenv;
    const msvcup_pkg_end = std.mem.indexOfScalar(u8, line, '|') orelse errExit(
        "{s}:{}: this line has no '|' character separate the pkg/URL/hash '{s}'",
        .{ lock_file_path, lineno, line },
    );
    const msvcup_pkg_str = line[0..msvcup_pkg_end];
    const maybe_msvcup_pkg = if (msvcup_pkg_str.len == 0) null else switch (MsvcupPackage.fromString(msvcup_pkg_str)) {
        .ok => |pkg| pkg,
        .autoenv => @panic("todo"),
        .unknown_name, .invalid_version => errExit(
            "{s}:{}: invalid msvcup pkg '{s}'",
            .{ lock_file_path, lineno, msvcup_pkg_str },
        ),
    };
    const url_start = msvcup_pkg_end + 1;
    const url_end = std.mem.indexOfScalarPos(u8, line, url_start, '|') orelse errExit(
        "{s}:{}: this line has no '|' character separate the URL/hash specifier '{s}'",
        .{ lock_file_path, lineno, line },
    );
    const url_decoded = line[url_start..url_end];
    _ = uriFromUrlDecoded(url_decoded) catch errExit(
        "{s}:{}: invalid uri '{s}'",
        .{ lock_file_path, lineno, url_decoded },
    );
    const url_kind = getLockFileUrlKind(url_decoded) orelse errExit(
        "{s}:{}: unable to determine payload kind from url '{s}'",
        .{ lock_file_path, lineno, url_decoded },
    );
    const hash_spec = scanTo(line, url_end + 1, ' ');
    const sha256_hex: [64]u8 = blk: {
        if (hash_spec.slice.len == 64) {
            break :blk hash_spec.slice[0..64].*;
        }
        const hash_index: usize = std.fmt.parseInt(usize, hash_spec.slice, 10) catch errExit(
            "{s}:{}: expected a sh256 hash or unsigned integer but got '{s}'",
            .{ lock_file_path, lineno, hash_spec.slice },
        );
        if (hash_index + 64 > url_decoded.len) errExit(
            "{s}:{}: invalid hash index {} (url is only {} chars)",
            .{ lock_file_path, lineno, hash_index, url_decoded.len },
        );
        break :blk lowerShaHex(url_decoded[hash_index..][0..64]);
    };
    const sha256 = Sha.parseHex(&sha256_hex) orelse errExit(
        "{s}:{}: invalid sha256 hash '{s}'",
        .{ lock_file_path, lineno, &sha256_hex },
    );
    switch (url_kind) {
        .vsix, .msi, .zip => |install_kind| {
            if (hash_spec.end != line.len) errExit(
                "{s}:{}: a payload of kind '{s}' should not contain anything after the hash",
                .{ lock_file_path, lineno, @tagName(install_kind) },
            );
            return .{ .payload = .{
                .url_decoded = url_decoded,
                .sha256 = sha256,
                .url_kind = .{ .top_level = maybe_msvcup_pkg orelse errExit(
                    "{s}:{}: missing msvcup package",
                    .{ lock_file_path, lineno },
                ) },
            } };
        },
        .cab => {
            if (hash_spec.end == line.len) errExit(
                "{s}:{}: missing ' PATH' after hash (required for .cab payloads)",
                .{ lock_file_path, lineno },
            );
            if (maybe_msvcup_pkg) |p| errExit(
                "{s}:{}: cab payloads should not have an associated msvcup package ('{}' in this case)",
                .{ lock_file_path, lineno, p },
            );
            return .{ .payload = .{
                .url_decoded = url_decoded,
                .sha256 = sha256,
                .url_kind = .{ .cab = line[hash_spec.end..] },
            } };
        },
    }
}

const UniquePackages = struct {
    autoenv: bool = false,
    msvc: ?StringPool.Val = null,
    sdk: ?StringPool.Val = null,
};

fn installFromLockFile(
    scratch: std.mem.Allocator,
    progress_node: std.Progress.Node,
    install_path: []const u8,
    cache_dir: []const u8,
    lock_file_path: []const u8,
    lock_file_content: []const u8,
) !enum { success, version_mismatch } {
    var line_it = std.mem.tokenizeAny(u8, lock_file_content, "\r\n");
    var lineno: u32 = 0;
    var save_cab_pos: ?struct { lineno: u32, offset: usize } = null;

    var unique_pkgs: UniquePackages = .{};

    while (line_it.next()) |line| {
        lineno += 1;
        if (line.len == 0) continue;
        const payload = switch (parseLockFileLine(lock_file_path, lineno, line)) {
            .autoenv => {
                if (unique_pkgs.autoenv) errExit("lock file contains multiple 'autoenv' entries", .{});
                unique_pkgs.autoenv = true;
                continue;
            },
            .payload => |payload| payload,
        };
        if (payload.hostArchLimit()) |host_arch_limit| {
            if (native_arch != host_arch_limit) {
                const name = basenameFromUrl(payload.url_decoded);
                std.log.info(
                    "skipping payload '{s}' arch {s} != host arch {s}",
                    .{ name, @tagName(host_arch_limit), if (native_arch) |a| @tagName(a) else "null" },
                );
                continue;
            }
        }
        switch (payload.url_kind) {
            .top_level => |payload_msvcup_pkg| {
                const maybe_version_ref: ?*?StringPool.Val = switch (payload_msvcup_pkg.kind) {
                    .msvc => &unique_pkgs.msvc,
                    .sdk => &unique_pkgs.sdk,
                    .msbuild, .diasdk, .ninja, .cmake => null,
                };
                if (maybe_version_ref) |version_ref| {
                    if (version_ref.*) |v| {
                        if (!v.eql(payload_msvcup_pkg.version)) {
                            errExit(
                                "lock file contains multiple {s} package versions ('{f}' and '{f}')",
                                .{ @tagName(payload_msvcup_pkg.kind), v, payload_msvcup_pkg.version },
                            );
                        }
                    } else {
                        version_ref.* = payload_msvcup_pkg.version;
                    }
                }

                const cabs_lineno, const cabs: []const u8 = if (save_cab_pos) |pos|
                    .{ pos.lineno, lock_file_content[pos.offset .. line.ptr - lock_file_content.ptr] }
                else
                    .{ lineno, line[0..0] };
                save_cab_pos = null;

                try installPayload(
                    scratch,
                    progress_node,
                    install_path,
                    lock_file_path,
                    cache_dir,
                    payload.url_decoded,
                    payload.sha256,
                    payload.stripRootDir(),
                    cabs_lineno,
                    cabs,
                );
            },
            .cab => {
                if (save_cab_pos == null) {
                    save_cab_pos = .{ .lineno = lineno, .offset = line.ptr - lock_file_content.ptr };
                    std.debug.assert(save_cab_pos.?.offset < lock_file_content.len);
                }
            },
        }
    }

    try updateVcvars(scratch, install_path, &unique_pkgs);
    try updateAutoenv(scratch, install_path, &unique_pkgs);

    return .success;
}

fn updateVcvars(
    scratch: std.mem.Allocator,
    install_path: []const u8,
    unique_pkgs: *const UniquePackages,
) !void {
    const msvc_install_version: ?[]const u8 = if (unique_pkgs.msvc != null) try queryInstallVersion(scratch, scratch, .msvc, install_path) else null;
    const sdk_install_version: ?[]const u8 = if (unique_pkgs.sdk != null) try queryInstallVersion(scratch, scratch, .sdk, install_path) else null;
    if (msvc_install_version) |v| std.log.info("MSVC install version '{s}'", .{v});
    if (sdk_install_version) |v| std.log.info("SDK  install version '{s}'", .{v});

    {
        var install_dir = try std.fs.cwd().makeOpenPath(install_path, .{});
        defer install_dir.close();
        inline for (std.meta.fields(Arch)) |arch_field| {
            const arch: Arch = @enumFromInt(arch_field.value);
            const env_bat = generateVcvarsBat(scratch, msvc_install_version, sdk_install_version, arch) catch |e| oom(e);
            defer scratch.free(env_bat);
            const env_basename = std.fmt.allocPrint(scratch, "vcvars-{s}.bat", .{@tagName(arch)}) catch |e| oom(e);
            defer scratch.free(env_basename);
            try updateFile(install_dir, env_basename, env_bat);
        }
    }
}

// The actual directory version can and does differ from both the
// package id build version and the package version itself, so, we just
// have to go in and look at the directory that was actually created to
// get the "install version".
fn queryInstallVersion(
    allocator: std.mem.Allocator,
    scratch: std.mem.Allocator,
    kind: enum { msvc, sdk },
    install_path: []const u8,
) ![]u8 {
    const query_path = switch (kind) {
        .msvc => std.fs.path.join(scratch, &.{ install_path, "VC", "Tools", "MSVC" }) catch |e| oom(e),
        .sdk => std.fs.path.join(scratch, &.{ install_path, "Windows Kits", "10", "Include" }) catch |e| oom(e),
    };
    defer scratch.free(query_path);
    var query_dir = std.fs.cwd().openDir(query_path, .{ .iterate = true }) catch |e| std.debug.panic(
        "open directory '{s}' failed with {s}",
        .{ query_path, @errorName(e) },
    );
    defer query_dir.close();
    var version_entry: ?[]u8 = null;
    var it = query_dir.iterate();
    while (try it.next()) |entry| {
        if (!isValidVersion(entry.name)) {
            std.log.info("entry '{s}' in directory '{s}' is not a valid version", .{ entry.name, query_path });
        } else if (version_entry) |existing| std.debug.panic(
            "directory '{s}' has multiple version entries '{s}' and '{s}'",
            .{ query_path, existing, entry.name },
        ) else {
            version_entry = allocator.dupe(u8, entry.name) catch |e| oom(e);
        }
    }
    return version_entry orelse std.debug.panic(
        "directory '{s}' did not contain any version subdirectories",
        .{query_path},
    );
}

fn generateVcvarsBat(
    allocator: std.mem.Allocator,
    msvc_install_version: ?[]const u8,
    sdk_install_version: ?[]const u8,
    target_arch: Arch,
) error{OutOfMemory}![]u8 {
    var bat: std.ArrayListUnmanaged(u8) = .{};
    defer bat.deinit(allocator);
    const writer = bat.writer(allocator);

    try writer.writeAll("set \"INCLUDE=");
    if (msvc_install_version) |install_version| {
        try writer.print(
            "%~dp0VC\\Tools\\MSVC\\{s}\\include;",
            .{install_version},
        );
    }
    if (sdk_install_version) |install_version| {
        try writer.print(
            "%~dp0Windows Kits\\10\\Include\\{s}\\ucrt;" ++
                "%~dp0Windows Kits\\10\\Include\\{0s}\\shared;" ++
                "%~dp0Windows Kits\\10\\Include\\{0s}\\um;" ++
                "%~dp0Windows Kits\\10\\Include\\{0s}\\winrt;" ++
                "%~dp0Windows Kits\\10\\Include\\{0s}\\cppwinrt;",
            .{install_version},
        );
    }
    try writer.writeAll("%INCLUDE%\"\n");

    try writer.writeAll("set \"PATH=");
    if (msvc_install_version) |install_version| {
        try writer.print(
            "%~dp0VC\\Tools\\MSVC\\{s}\\bin\\Host{s}\\{s};",
            .{ install_version, @tagName(Arch.native), @tagName(target_arch) },
        );
    }
    if (sdk_install_version) |install_version| {
        try writer.print(
            "%~dp0Windows Kits\\10\\bin\\{[version]s}\\{[host_arch]s};",
            .{ .version = install_version, .host_arch = @tagName(Arch.native) },
        );
    }
    try writer.writeAll("%PATH%\"\n");

    try writer.writeAll("set \"LIB=");
    if (msvc_install_version) |install_version| {
        try writer.print(
            "%~dp0VC\\Tools\\MSVC\\{s}\\lib\\{s};",
            .{ install_version, @tagName(target_arch) },
        );
    }
    if (sdk_install_version) |install_version| {
        try writer.print(
            "%~dp0Windows Kits\\10\\Lib\\{[version]s}\\ucrt\\{[target_arch]s};" ++
                "%~dp0Windows Kits\\10\\Lib\\{[version]s}\\um\\{[target_arch]s};",
            .{ .version = install_version, .target_arch = @tagName(target_arch) },
        );
    }
    try writer.writeAll("%LIB%\"\n");

    return bat.toOwnedSlice(allocator) catch |e| oom(e);
}

fn generateToolchainCmake(
    allocator: std.mem.Allocator,
    unique_pkgs: *const UniquePackages,
    target_cpu: Arch,
) error{OutOfMemory}![]u8 {
    var content: std.ArrayListUnmanaged(u8) = .{};
    defer content.deinit(allocator);
    const writer = content.writer(allocator);

    try writer.writeAll("set(CMAKE_SYSTEM_NAME Windows)\n");
    if (switch (target_cpu) {
        .x64 => "AMD64",
        .x86 => "X86",
        .arm => null,
        .arm64 => "ARM64",
    }) |processor| {
        try writer.print("set(CMAKE_SYSTEM_PROCESSOR {s})\n", .{processor});
    }

    if (unique_pkgs.msvc != null) {
        inline for (msvc_tools) |tool| {
            for (tool.cmake_names) |cmake_name| {
                try writer.print("set(CMAKE_{s} \"${{CMAKE_CURRENT_LIST_DIR}}/{s}.exe\")\n", .{ cmake_name, tool.name });
            }
        }
    }
    if (unique_pkgs.sdk != null) {
        inline for (sdk_tools) |tool| {
            for (tool.cmake_names) |cmake_name| {
                try writer.print("set(CMAKE_{s} \"${{CMAKE_CURRENT_LIST_DIR}}/{s}.exe\")\n", .{ cmake_name, tool.name });
            }
        }
    }
    return content.toOwnedSlice(allocator) catch |e| oom(e);
}

const AbsolutePath = struct {
    slice: []const u8,
    allocated: bool,

    pub fn init(allocator: std.mem.Allocator, p: []const u8) !AbsolutePath {
        if (std.fs.path.isAbsolute(p)) return .{ .slice = p, .allocated = false };
        return .{
            .slice = try std.fs.realpathAlloc(allocator, p),
            .allocated = true,
        };
    }
    pub fn deinit(p: *const AbsolutePath, allocator: std.mem.Allocator) void {
        if (p.allocated) allocator.free(p.slice);
    }
};

fn generateLibcTxt(
    allocator: std.mem.Allocator,
    install_path: *const AbsolutePath,
    unique_pkgs: *const UniquePackages,
    target_cpu: Arch,
) error{OutOfMemory}![]u8 {
    var content: std.ArrayListUnmanaged(u8) = .{};
    defer content.deinit(allocator);
    const writer = content.writer(allocator);
    if (unique_pkgs.msvc) |msvc_version| {
        try writer.print(
            \\sys_include_dir={[install]s}\VC\Tools\MSVC\{[version]s}\include
            \\msvc_lib_dir={[install]s}\VC\Tools\MSVC\{[version]s}\lib\{[target]s}
            \\
        , .{
            .install = install_path.slice,
            .version = msvc_version,
            .target = @tagName(target_cpu),
        });
    }
    if (unique_pkgs.sdk) |sdk_version| {
        try writer.print(
            \\include_dir={[install]s}\Windows Kits\10\Include\{[version]s}\ucrt
            \\kernel32_lib_dir={[install]s}\Windows Kits\10\lib\{[version]s}\um\{[target]s}
            \\crt_dir={[install]s}\Windows Kits\10\Lib\{[version]s}\ucrt\{[target]s}
            \\
        , .{
            .install = install_path.slice,
            .version = sdk_version,
            .target = @tagName(target_cpu),
        });
    }
    try writer.writeAll(
        \\gcc_dir=
        \\
    );
    return content.toOwnedSlice(allocator) catch |e| oom(e);
}

const CacheEntry = struct {
    path: []const u8,
    basename: []const u8,
    pub fn alloc(
        allocator: std.mem.Allocator,
        scratch: std.mem.Allocator,
        cache_dir: []const u8,
        sha256: Sha,
        name: []const u8,
    ) CacheEntry {
        const cache_basename = std.fmt.allocPrint(scratch, "{s}-{s}", .{ sha256, name }) catch |e| oom(e);
        defer scratch.free(cache_basename);
        const path = std.fs.path.join(allocator, &.{ cache_dir, cache_basename }) catch |e| oom(e);
        const new_basename = path[path.len - cache_basename.len ..];
        std.debug.assert(std.mem.eql(u8, cache_basename, new_basename));
        return .{ .path = path, .basename = new_basename };
    }
    pub fn free(self: CacheEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
    }
};

fn installPayload(
    scratch: std.mem.Allocator,
    progress_node: std.Progress.Node,
    install_dir_path: []const u8,
    lock_file_path: []const u8,
    cache_dir: []const u8,
    url_decoded: []const u8,
    sha256: Sha,
    strip_root_dir: bool,
    cabs_lineno: u32,
    cabs: []const u8,
) !void {
    const install_kind: enum { vsix, msi, zip } = blk: {
        switch (getLockFileUrlKind(url_decoded) orelse errExit(
            "unable to determine install kind from payload url '{s}'",
            .{url_decoded},
        )) {
            .vsix => {
                if (cabs.len != 0) @panic("vsix payloads should not have cab files");
                break :blk .vsix;
            },
            .msi => break :blk .msi,
            .cab => unreachable,
            .zip => {
                if (cabs.len != 0) @panic("zip payloads should not have cab files");
                break :blk .zip;
            },
        }
    };

    const cache_entry = CacheEntry.alloc(scratch, scratch, cache_dir, sha256, basenameFromUrl(url_decoded));
    defer cache_entry.free(scratch);

    const installed_basename = std.mem.concat(scratch, u8, &.{ cache_entry.basename, ".files" }) catch |e| oom(e);
    defer scratch.free(installed_basename);
    const installed_manifest_path = std.fs.path.join(scratch, &.{ install_dir_path, "install", installed_basename }) catch |e| oom(e);
    defer scratch.free(installed_manifest_path);
    if (std.fs.cwd().access(installed_manifest_path, .{})) {
        log.info("ALREADY INSTALLED | {s} {s}", .{ basenameFromUrl(url_decoded), &sha256 });
        return;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    }

    {
        var line_it = std.mem.tokenizeAny(u8, cabs, "\r\n");
        var lineno: u32 = cabs_lineno - 1;
        while (line_it.next()) |line| {
            lineno += 1;
            if (line.len == 0) continue;
            const payload = switch (parseLockFileLine(lock_file_path, lineno, line)) {
                .autoenv => continue,
                .payload => |payload| payload,
            };
            const cab_cache_entry = CacheEntry.alloc(scratch, scratch, cache_dir, payload.sha256, basenameFromUrl(payload.url_decoded));
            defer cab_cache_entry.free(scratch);
            try fetchPayload(scratch, progress_node, cache_dir, payload.sha256, payload.url_decoded, cab_cache_entry.path);
        }
    }
    try fetchPayload(scratch, progress_node, cache_dir, sha256, url_decoded, cache_entry.path);

    const install_lock_path = std.fs.path.join(scratch, &.{ install_dir_path, ".lock" }) catch |e| oom(e);
    defer scratch.free(install_lock_path);
    const current_install_path = std.fs.path.join(scratch, &.{ install_dir_path, "install", "current" }) catch |e| oom(e);
    defer scratch.free(current_install_path);

    var install_lock = try LockFile.lock(install_lock_path);
    defer install_lock.unlock();

    var install_dir_handle = try std.fs.cwd().openDir(install_dir_path, .{});
    defer install_dir_handle.close();

    const pre_start_data: union(enum) {
        vsix,
        msi: struct {
            staging_dir: []const u8,
        },
        zip,
    } = switch (install_kind) {
        .vsix => .vsix,
        .msi => .{ .msi = .{ .staging_dir = std.fs.path.join(
            scratch,
            &.{ install_dir_path, ".msi-staging" },
        ) catch |e| oom(e) } },
        .zip => .zip,
    };
    defer switch (pre_start_data) {
        .vsix => {},
        .msi => |msi| scratch.free(msi.staging_dir),
        .zip => {},
    };
    switch (pre_start_data) {
        .vsix => {},
        .msi => |msi| {
            try deleteTree(std.fs.cwd(), msi.staging_dir);
            const installer_path = std.fs.path.join(scratch, &.{ msi.staging_dir, "installer" }) catch |e| oom(e);
            defer scratch.free(installer_path);
            try std.fs.cwd().makeDir(msi.staging_dir);
            try std.fs.cwd().makeDir(installer_path);
            const msi_copy = std.fs.path.join(scratch, &.{ installer_path, basenameFromUrl(url_decoded) }) catch |e| oom(e);
            defer scratch.free(msi_copy);
            try std.fs.cwd().copyFile(cache_entry.path, std.fs.cwd(), msi_copy, .{});
            {
                var installer_dir = try std.fs.cwd().openDir(installer_path, .{});
                defer installer_dir.close();
                var line_it = std.mem.tokenizeAny(u8, cabs, "\r\n");
                var lineno: u32 = cabs_lineno - 1;
                while (line_it.next()) |line| {
                    lineno += 1;
                    if (line.len == 0) continue;
                    const payload = switch (parseLockFileLine(lock_file_path, lineno, line)) {
                        .autoenv => unreachable,
                        .payload => |payload| payload,
                    };
                    const installer_sub_path = switch (payload.url_kind) {
                        .top_level => unreachable,
                        .cab => |path| path,
                    };
                    const cab_cache_entry = CacheEntry.alloc(
                        scratch,
                        scratch,
                        cache_dir,
                        payload.sha256,
                        basenameFromUrl(payload.url_decoded),
                    );
                    defer cab_cache_entry.free(scratch);
                    if (std.fs.path.dirname(installer_sub_path)) |dir| try installer_dir.makePath(dir);
                    try std.fs.cwd().copyFile(cab_cache_entry.path, installer_dir, installer_sub_path, .{});
                }
            }
            const target_dir = std.fs.path.join(scratch, &.{ msi.staging_dir, "target" }) catch |e| oom(e);
            defer scratch.free(target_dir);
            try populateStagingMsi(scratch, msi_copy, target_dir);
            std.log.info("removing '{s}'...", .{installer_path});
            try deleteTree(std.fs.cwd(), installer_path);
        },
        .zip => {},
    }

    {
        const current_install = try startInstall(scratch, install_dir_handle, current_install_path);
        defer current_install.close();
        // this will always starts with the cache basename
        try current_install.writer().print("{s}\n", .{cache_entry.basename});
        switch (pre_start_data) {
            .vsix => try installPayloadZip(
                scratch,
                cache_entry.path,
                install_dir_handle,
                current_install,
                .vsix,
                strip_root_dir,
            ),
            .msi => |msi| {
                const target_dir = std.fs.path.join(scratch, &.{ msi.staging_dir, "target" }) catch |e| oom(e);
                defer scratch.free(target_dir);
                _ = try installDir(
                    scratch,
                    .{ .path = install_dir_path, .handle = install_dir_handle },
                    target_dir,
                    current_install,
                    basenameFromUrl(url_decoded),
                );
                try deleteTree(std.fs.cwd(), msi.staging_dir);
            },
            .zip => try installPayloadZip(
                scratch,
                cache_entry.path,
                install_dir_handle,
                current_install,
                .zip,
                strip_root_dir,
            ),
        }
    }

    try endInstall(scratch, installed_manifest_path, current_install_path);
}

fn normalizePathSeps(path: []u8) void {
    for (path) |*char| char.* = switch (char.*) {
        '/' => '\\',
        else => |other| other,
    };
}

fn populateStagingMsi(scratch: std.mem.Allocator, msi_file_path: []const u8, staging_dir: []const u8) !void {
    // msi has problem with paths that contain forward slaces
    const msi_path_fixed = try scratch.dupe(u8, msi_file_path);
    defer scratch.free(msi_path_fixed);
    normalizePathSeps(msi_path_fixed);

    // at least some MSI files require TARGETDIR to be an absolute path
    // also, realpath requires the directory to exist to work
    try std.fs.cwd().makePath(staging_dir);
    const staging_dir_abs = try std.fs.cwd().realpathAlloc(scratch, staging_dir);
    defer scratch.free(staging_dir_abs);
    normalizePathSeps(staging_dir_abs);

    const target_dir_arg = try std.mem.concat(scratch, u8, &.{ "TARGETDIR=", staging_dir_abs });
    defer scratch.free(target_dir_arg);
    std.log.info("running msiexec for '{s}'...", .{msi_file_path});
    const argv = [_][]const u8{
        "msiexec.exe",
        "/a",
        msi_path_fixed,
        "/quiet",
        "/qn",
        //"/?",
        //"/lv", "C:\\temp\\log.txt",
        target_dir_arg,
    };
    const result = try std.process.Child.run(.{
        .allocator = scratch,
        .argv = &argv,
    });
    defer {
        scratch.free(result.stdout);
        scratch.free(result.stderr);
    }
    switch (result.term) {
        .Exited => |exit_code| {
            if (exit_code != 0) {
                try std.io.getStdErr().writer().writeAll(result.stdout);
                try std.io.getStdErr().writer().writeAll(result.stderr);
                errExit(
                    "msiexec for '{s}' failed with exit code {} (output stdout={} bytes stderr={} bytes)",
                    .{ msi_file_path, exit_code, result.stdout.len, result.stderr.len },
                );
            }
        },
        inline else => |e| {
            try std.io.getStdErr().writer().writeAll(result.stdout);
            try std.io.getStdErr().writer().writeAll(result.stderr);
            errExit("msiexec for '{s}' terminated with {}", .{ msi_file_path, e });
        },
    }
}

fn installPayloadZip(
    scratch: std.mem.Allocator,
    cache_path: []const u8,
    install_dir: std.fs.Dir,
    installing_manifest: std.fs.File,
    kind: enum { vsix, zip },
    strip_root_dir: bool,
) !void {
    var payload_file = try std.fs.cwd().openFile(cache_path, .{});
    defer payload_file.close();

    var last_root_dir: ?[]const u8 = null;

    {
        var zip_it = try zip.Iterator.init(payload_file.seekableStream());
        while (try zip_it.next()) |entry| {
            var filename_buf: [std.fs.max_path_bytes]u8 = undefined;
            const filename = filename_buf[0..entry.filename_len];
            try payload_file.seekableStream().seekTo(entry.header_zip_offset + @sizeOf(std.zip.CentralDirectoryFileHeader));
            const len = try payload_file.reader().readAll(filename);
            if (len != filename.len)
                return error.ZipBadFileOffset;
            const other_sep = switch (std.fs.path.sep) {
                '/' => '\\',
                '\\' => '/',
                else => @compileError("todo"),
            };
            for (filename) |*c| {
                if (c.* == other_sep) c.* = std.fs.path.sep;
            }
            if (filename.len == 0) return error.ZipEmptyFilename;
            if (filename[0] == std.fs.path.sep) return error.ZipAbsoluteFilename;
            {
                var it = std.mem.splitScalar(u8, filename, std.fs.path.sep);
                while (it.next()) |part| {
                    if (std.mem.eql(u8, part, ".")) return error.ZipFilenameContainsDot;
                    if (std.mem.eql(u8, part, "..")) return error.ZipFilenameContainsDots;
                }
            }

            const prefix: []const u8 = switch (kind) {
                .vsix => "Contents" ++ std.fs.path.sep_str,
                .zip => "",
            };
            if (!std.ascii.startsWithIgnoreCase(filename, prefix)) {
                // log.info("ignore '{s}'", .{filename});
                continue;
            }
            if (filename[filename.len - 1] == std.fs.path.sep) {
                // log.info("ignore directory '{s}'", .{filename});
                continue;
            }

            // for some reason, the VSIX filenames can be URL percent encoded?!?
            const sub_path_encoded = filename[prefix.len..];
            const sub_path_decoded = allocUrlPercentDecoded(scratch, sub_path_encoded) catch |e| oom(e);
            defer scratch.free(sub_path_decoded);

            const sub_path = blk: {
                if (strip_root_dir) {
                    const root_dir_end = std.mem.indexOfScalar(
                        u8,
                        sub_path_decoded,
                        std.fs.path.sep,
                    ) orelse std.debug.panic(
                        "no root dir to strip from  '{s}'",
                        .{sub_path_decoded},
                    );
                    const root_dir = sub_path_decoded[0..root_dir_end];
                    if (last_root_dir) |last| if (!std.mem.eql(u8, last, root_dir)) std.debug.panic(
                        "root dir has changed from '{s}' to '{s}', cannot strip",
                        .{ last, root_dir },
                    );
                    last_root_dir = root_dir;
                    std.debug.assert(sub_path_decoded[root_dir.len] == std.fs.path.sep);
                    const sub_path = sub_path_decoded[root_dir.len + 1 ..];
                    std.debug.assert(sub_path.len > 0);
                    break :blk sub_path;
                }
                break :blk sub_path_decoded;
            };

            switch (try updateInstallingManifest(install_dir, installing_manifest, sub_path)) {
                .already_installed => {
                    // TODO: for zip, we could probably just take a CRC of the current file and compre
                    //       it to our expected CRC
                    std.debug.panic("'{s}' already installed (TODO: check if it's the same)", .{sub_path});
                },
                .ready => {
                    const file = try install_dir.createFile(sub_path, .{});
                    defer file.close();
                    const crc = try zip.extract(entry, payload_file.seekableStream(), file.writer());
                    if (crc != entry.crc32) std.debug.panic(
                        "file '{s}' expected CRC32 0x{x} but got 0x{x}",
                        .{ sub_path, entry.crc32, crc },
                    );
                },
            }
        }
    }
}

fn updateInstallingManifest(
    install_dir: std.fs.Dir,
    installing_manifest: std.fs.File,
    install_path: []const u8,
) !enum { already_installed, ready } {
    if (install_dir.openFile(install_path, .{})) |file| {
        defer file.close();
        try installing_manifest.writer().print("add {s}\n", .{install_path});
        return .already_installed;
    } else |err| switch (err) {
        error.FileNotFound => {
            try installing_manifest.writer().print("new {s}\n", .{install_path});
            if (std.fs.path.dirname(install_path)) |d| try install_dir.makePath(d);
            return .ready;
        },
        else => |e| return e,
    }
}

fn fileMatches(dir: std.fs.Dir, sub_path: []const u8, content: []const u8) !bool {
    const file = dir.openFile(sub_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer file.close();
    {
        const file_size = try file.getEndPos();
        if (file_size != content.len) return false;
    }
    const chunk_size = @max(4096, std.heap.page_size_min);
    var buffer: [chunk_size]u8 = undefined;
    var content_offset: usize = 0;
    while (content_offset < content.len) {
        const bytes_to_read = @min(chunk_size, content.len - content_offset);
        const bytes_read = try file.readAll(buffer[0..bytes_to_read]);
        if (bytes_read != bytes_to_read) return false;
        if (!std.mem.eql(u8, buffer[0..bytes_read], content[content_offset .. content_offset + bytes_read])) {
            return false;
        }
        content_offset += bytes_read;
    }
    return true;
}
fn filesAreIdentical(path1: []const u8, path2: []const u8) !bool {
    const file1 = try std.fs.cwd().openFile(path1, .{});
    defer file1.close();
    const file2 = try std.fs.cwd().openFile(path2, .{});
    defer file2.close();
    {
        const file1_end_pos = try file1.getEndPos();
        const file2_end_pos = try file2.getEndPos();
        if (file1_end_pos != file2_end_pos) return false;
    }
    const chunk_size = @max(4096, std.heap.page_size_min);
    var buffer1: [chunk_size]u8 = undefined;
    var buffer2: [chunk_size]u8 = undefined;
    while (true) {
        const bytes_read1 = try file1.readAll(&buffer1);
        const bytes_read2 = try file2.readAll(&buffer2);
        if (bytes_read1 != bytes_read2) return false;
        if (bytes_read1 == 0) return true;
        if (!std.mem.eql(u8, buffer1[0..bytes_read1], buffer2[0..bytes_read2]))
            return false;
    }
}

const OpenDir = struct {
    path: []const u8,
    handle: std.fs.Dir,
};

fn installDir(
    scratch: std.mem.Allocator,
    install_dir: OpenDir,
    source_dir_path: []const u8,
    installing_manifest: std.fs.File,
    root_exclude: []const u8,
) !struct { root_excluded: bool } {
    var source_dir = try std.fs.cwd().openDir(source_dir_path, .{ .iterate = true });
    defer source_dir.close();

    var it = try source_dir.walk(scratch);
    defer it.deinit();

    var root_excluded = false;
    while (try it.next()) |entry| {
        if (std.mem.eql(u8, entry.path, root_exclude)) {
            root_excluded = true;
            continue;
        }
        switch (entry.kind) {
            .file => {},
            .directory => continue, // ignore directories
            else => |kind| std.debug.panic("unsupported file type {s} '{s}'", .{ @tagName(kind), entry.path }),
        }
        const install_path = std.fs.path.join(scratch, &.{ install_dir.path, entry.path }) catch |e| oom(e);
        defer scratch.free(install_path);
        const source_path = std.fs.path.join(scratch, &.{ source_dir_path, entry.path }) catch |e| oom(e);
        defer scratch.free(source_path);
        switch (try updateInstallingManifest(install_dir.handle, installing_manifest, entry.path)) {
            .already_installed => {
                if (!try filesAreIdentical(source_path, install_path)) {
                    std.log.err("file conflict!", .{});
                    std.log.err("new source       : {s}", .{source_path});
                    std.log.err("already installed: {s}", .{install_path});
                    @panic("file conflict");
                }
            },
            .ready => try std.fs.cwd().copyFile(source_path, std.fs.cwd(), install_path, .{}),
        }
    }
    return .{ .root_excluded = root_excluded };
}

pub fn deleteTree(dir: std.fs.Dir, sub_path: []const u8) !void {
    if (builtin.os.tag != .windows) {
        return dir.deleteTree(sub_path);
    }

    // workaround issue on windows where it just doesn't delete things
    const MAX_ATTEMPTS = 10;
    var attempt: u8 = 0;
    while (true) : (attempt += 1) {
        if (dir.deleteTree(sub_path)) {
            return;
        } else |err| {
            if (attempt == MAX_ATTEMPTS) return err;
            switch (err) {
                error.FileBusy => {
                    std.log.warn("path '{s}' is busy (attempt {}), will retry", .{ sub_path, attempt });
                    std.time.sleep(std.time.ns_per_ms * 100); // sleep for 100 ms
                },
                else => |e| return e,
            }
        }
    }
}

fn startInstall(
    scratch: std.mem.Allocator,
    install_dir: std.fs.Dir,
    current_install_path: []const u8,
) !std.fs.File {
    if (std.fs.cwd().openFile(current_install_path, .{})) |current_install_file| {
        const content = blk: {
            defer current_install_file.close();
            // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            log.info(" opened '{s}'", .{current_install_path});
            break :blk try current_install_file.readToEndAlloc(scratch, std.math.maxInt(usize));
        };
        defer scratch.free(content);
        var line_it = std.mem.splitScalar(u8, content, '\n');
        if (line_it.next()) |cache_basename| {
            log.info("previous install was for '{s}'", .{cache_basename});
            var lineno: u32 = 1;
            while (line_it.next()) |line| {
                lineno += 1;
                if (line.len == 0) continue;
                if (std.mem.startsWith(u8, line, "new ")) {
                    const sub_path = line[4..];
                    log.info("removing file '{s}'", .{sub_path});
                    install_dir.deleteFile(sub_path) catch |err| switch (err) {
                        error.FileNotFound => {},
                        else => |e| return e,
                    };
                } else if (std.mem.startsWith(u8, line, "add ")) {
                    // don't remove file, it was added by another payload
                } else std.debug.panic(
                    "{s}:{}: line did not start with 'new ' nor 'add ': '{s}'",
                    .{ current_install_path, lineno, line },
                );
            }
        } else {
            log.info("current-install was empty", .{});
        }
        try std.fs.cwd().deleteFile(current_install_path);
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    }

    if (std.fs.path.dirname(current_install_path)) |d| try std.fs.cwd().makePath(d);
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    log.info("creating '{s}'...", .{current_install_path});
    return try std.fs.cwd().createFile(current_install_path, .{});
}

fn endInstall(
    scratch: std.mem.Allocator,
    installed_manifest_path: []const u8,
    current_install_path: []const u8,
) !void {
    const installed_manifest_path_tmp = std.mem.concat(scratch, u8, &.{ installed_manifest_path, ".tmp" }) catch |e| oom(e);
    defer scratch.free(installed_manifest_path_tmp);

    {
        const installed_manifest = try std.fs.cwd().createFile(installed_manifest_path_tmp, .{});
        defer installed_manifest.close();
        var bw = std.io.bufferedWriter(installed_manifest.writer());

        const content = blk: {
            const current_install_file = try std.fs.cwd().openFile(current_install_path, .{});
            defer current_install_file.close();
            // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            log.info(" opened '{s}'", .{current_install_path});
            break :blk try current_install_file.readToEndAlloc(scratch, std.math.maxInt(usize));
        };
        defer scratch.free(content);
        var line_it = std.mem.splitScalar(u8, content, '\n');
        const manifest_cache_basename = line_it.next() orelse std.debug.panic("{s} was empty", .{current_install_path});
        const actual_basename = std.fs.path.basename(installed_manifest_path);
        std.debug.assert(std.mem.endsWith(u8, actual_basename, ".files"));
        if (!std.mem.startsWith(u8, actual_basename, manifest_cache_basename)) std.debug.panic(
            "manifest basename '{s}' does not begin with what was in the installing manifest '{s}'",
            .{ actual_basename, manifest_cache_basename },
        );
        std.debug.assert(actual_basename.len - 6 == manifest_cache_basename.len);
        var lineno: u32 = 1;
        while (line_it.next()) |line| {
            lineno += 1;
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "new ")) {
                const sub_path = line[4..];
                try bw.writer().print("{s}\n", .{sub_path});
            } else if (std.mem.startsWith(u8, line, "add ")) {
                const sub_path = line[4..];
                try bw.writer().print("{s}\n", .{sub_path});
            } else std.debug.panic(
                "{s}:{}: line did not start with 'new ' nor 'add ': '{s}'",
                .{ current_install_path, lineno, line },
            );
        }
        try bw.flush();
    }
    try std.fs.cwd().deleteFile(current_install_path);
    try std.fs.cwd().rename(installed_manifest_path_tmp, installed_manifest_path);
}

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// TODO: make this take an array of patterns instead
//       it would be great to be ale to see which patterns pulled in packages/payloads
fn getInstallPkg(id: []const u8) ?union(enum) {
    msvc: []const u8,
    msbuild: []const u8,
    diasdk,
    ninja: []const u8,
    cmake: []const u8,
} {
    return switch (identifyPackage(id)) {
        .unknown => null,
        .unexpected => |u| try std.debug.panic(
            "unexpected package id '{s}' (expected {s} at offset {} '{s}')\n",
            .{ id, @tagName(u.expected), u.offset, id[u.offset..] },
        ),
        .msvc_version_something => |p| {
            const crt = scanIdPart(id, p.something.ptr - id.ptr);
            if (!std.mem.eql(u8, crt.slice, "CRT")) return null;
            // contains vcruntime.h
            if (std.mem.eql(u8, id[crt.end..], "Headers.base")) return .{ .msvc = p.build_version };

            const after_crt_part = scanIdPart(id, crt.end);

            if (std.mem.eql(u8, after_crt_part.slice, "Redist")) {
                const arch_part = scanIdPart(id, after_crt_part.end);
                _ = Arch.fromStringIgnoreCase(arch_part.slice) orelse return null;
                const after_arch = id[arch_part.end..];
                // Redist.ARCH.base contains Visual C++ runtime libraries, i.e.
                //     vcruntime140.dll and msvcp140.dll - Essential C++ runtime components
                //     concrt140.dll - Concurrency runtime for parallel programming
                //     vccorlib140.dll - Core library components
                // it also contains debug versions, which are files ending in "d.dll"
                if (std.mem.eql(u8, after_arch, "base")) return .{ .msvc = p.build_version };
            } else {
                _ = Arch.fromStringIgnoreCase(after_crt_part.slice) orelse return null;
                const after_arch = id[after_crt_part.end..];
                // contains libcmt.lib
                if (std.mem.eql(u8, after_arch, "Desktop.base")) return .{ .msvc = p.build_version };
                if (std.mem.eql(u8, after_arch, "Desktop.debug.base")) return .{ .msvc = p.build_version };
                // contains oldnames.lib
                if (std.mem.eql(u8, after_arch, "Store.base")) return .{ .msvc = p.build_version };
            }
            return null;
        },
        .msvc_version_tools_something => null,
        .msvc_version_host_target => |p| {
            // "base" contains cl.exe
            if (std.mem.eql(u8, p.name, "base")) return .{ .msvc = p.build_version };
            // "Res.base" contains clui.dll required by cl.exe
            if (std.mem.eql(u8, p.name, "Res.base")) return .{ .msvc = p.build_version };
            return null;
        },
        .msbuild => |version| return .{ .msbuild = version },
        .diasdk => return .diasdk,
        .ninja => |version| return .{ .ninja = version },
        .cmake => |version| return .{ .cmake = version },
    };
}

const InstallPayload = struct {
    target: MsvcupPackage,
    index: PayloadIndex,
    pub fn init(target: MsvcupPackage, index: usize) InstallPayload {
        return .{ .target = target, .index = .fromInt(index) };
    }
    pub fn order(payloads: []const Payload, lhs: InstallPayload, rhs: InstallPayload) std.math.Order {
        switch (MsvcupPackage.order({}, lhs.target, rhs.target)) {
            .lt, .gt => |o| return o,
            .eq => {},
        }
        return PayloadIndex.order(payloads, lhs.index, rhs.index);
    }
};
const InstallPackage = struct {
    target: MsvcupPackage,
    index: PackageIndex,
    pub fn init(target: MsvcupPackage, index: usize) InstallPackage {
        return .{ .target = target, .index = .fromInt(index) };
    }
    pub fn order(pkgs: []const Package, lhs: InstallPackage, rhs: InstallPackage) std.math.Order {
        switch (MsvcupPackage.order({}, lhs.target, rhs.target)) {
            .lt, .gt => |o| return o,
            .eq => {},
        }
        return PackageIndex.order(pkgs, lhs.index, rhs.index);
    }
};

fn updateLockFile(
    scratch: std.mem.Allocator,
    progress_node: std.Progress.Node,
    autoenv: bool,
    msvcup_pkgs: []const MsvcupPackage,
    lock_file_path: []const u8,
    pkgs: Packages,
    cache_dir: []const u8,
) !void {
    const payloads: []const InstallPayload = blk_payloads: {
        var payloads: std.ArrayListUnmanaged(InstallPayload) = .{};
        var install_pkgs: std.ArrayListUnmanaged(InstallPackage) = .{};

        for (pkgs.slice, 0..) |pkg, pkg_index| {
            switch (pkg.language) {
                .neutral => {},
                .en_us => {},
                .other => continue,
            }

            if (getInstallPkg(pkg.id)) |install_pkg| switch (install_pkg) {
                .msvc => |pkg_msvc_version| for (msvcup_pkgs) |msvcup_pkg| {
                    if (msvcup_pkg.kind != .msvc) continue;
                    if (std.mem.eql(u8, msvcup_pkg.version.slice, pkg_msvc_version)) {
                        insertSorted(
                            InstallPackage,
                            scratch,
                            &install_pkgs,
                            .init(msvcup_pkg, pkg_index),
                            pkgs.slice,
                            InstallPackage.order,
                        ) catch |e| oom(e);
                        break;
                    }
                },
                .msbuild => |pkg_msbuild_version| for (msvcup_pkgs) |msvcup_pkg| {
                    if (msvcup_pkg.kind != .msbuild) continue;
                    if (!std.mem.eql(u8, msvcup_pkg.version.slice, pkg_msbuild_version)) continue;
                    insertSorted(
                        InstallPackage,
                        scratch,
                        &install_pkgs,
                        .init(msvcup_pkg, pkg_index),
                        pkgs.slice,
                        InstallPackage.order,
                    ) catch |e| oom(e);
                    break;
                },
                .diasdk => for (msvcup_pkgs) |msvcup_pkg| {
                    if (msvcup_pkg.kind != .diasdk) continue;
                    if (std.mem.eql(u8, msvcup_pkg.version.slice, pkg.version)) {
                        insertSorted(
                            InstallPackage,
                            scratch,
                            &install_pkgs,
                            .init(msvcup_pkg, pkg_index),
                            pkgs.slice,
                            InstallPackage.order,
                        ) catch |e| oom(e);
                        break;
                    }
                },
                .ninja => |pkg_ninja_version| for (msvcup_pkgs) |msvcup_pkg| {
                    if (msvcup_pkg.kind != .ninja) continue;
                    if (!std.mem.eql(u8, msvcup_pkg.version.slice, pkg_ninja_version)) continue;
                    insertSorted(
                        InstallPackage,
                        scratch,
                        &install_pkgs,
                        .init(msvcup_pkg, pkg_index),
                        pkgs.slice,
                        InstallPackage.order,
                    ) catch |e| oom(e);
                    break;
                },
                .cmake => |pkg_cmake_version| for (msvcup_pkgs) |msvcup_pkg| {
                    if (msvcup_pkg.kind != .cmake) continue;
                    if (!std.mem.eql(u8, msvcup_pkg.version.slice, pkg_cmake_version)) continue;
                    insertSorted(
                        InstallPackage,
                        scratch,
                        &install_pkgs,
                        .init(msvcup_pkg, pkg_index),
                        pkgs.slice,
                        InstallPackage.order,
                    ) catch |e| oom(e);
                    break;
                },
            };

            const payload_range = pkgs.payloadRangeFromPkgIndex(.fromInt(pkg_index));
            for (payload_range.start..payload_range.limit) |payload_index| {
                const payload = &pkgs.payloads[payload_index];
                switch (identifyPayload(payload.file_name)) {
                    .unknown => {},
                    .sdk => {
                        for (msvcup_pkgs) |msvcup_pkg| {
                            if (msvcup_pkg.kind != .sdk) continue;
                            if (std.mem.eql(u8, pkg.version, msvcup_pkg.version.slice)) {
                                insertSorted(
                                    InstallPayload,
                                    scratch,
                                    &payloads,
                                    .init(msvcup_pkg, payload_index),
                                    pkgs.payloads,
                                    InstallPayload.order,
                                ) catch |e| oom(e);
                                break;
                            }
                        }
                    },
                }
            }
        }

        // if (msvc_pkgs.items.len == 0) {
        //     var bw = std.io.bufferedWriter(std.io.getStdErr().writer());
        //     try bw.writer().print("error: MSVC version '{s}' NOT FOUND, pick one of:\n", .{msvc_version});
        //     var msvc_versions: std.ArrayListUnmanaged([]const u8) = .{};
        //     defer msvc_versions.deinit(scratch);
        //     for (pkgs.slice) |pkg| {
        //         switch (pkg.language) {
        //             .neutral => {},
        //             .en_us => {},
        //             .other => continue,
        //         }
        //         switch (identifyPackage(pkg.id)) {
        //             .unknown => {},
        //             .unexpected => {},
        //             .msvc_version_something => {},
        //             .msvc_version_tools_something => {},
        //             .msvc_version_host_target => |p| {
        //                 insertSorted(
        //                     []const u8,
        //                     scratch,
        //                     &msvc_versions,
        //                     p.build_version,
        //                     {},
        //                     orderDottedNumeric,
        //                 ) catch |e| oom(e);
        //             },
        //         }
        //     }
        //     for (msvc_versions.items, 0..) |version, i| {
        //         const suffix: []const u8 = if (i + 1 == msvc_versions.items.len) " (latest)" else "";
        //         try bw.writer().print("    {s}{s}\n", .{ version, suffix });
        //     }
        //     try bw.flush();
        //     std.process.exit(0xff);
        // }

        // ensure all the packages have 1 or more payloads
        // for (msvcup_pkgs) |msvcup_pkg| switch (msvcup_pkg.kind) {
        //     .msvc => {
        //         // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        //         // TODO
        //     },
        //     .sdk => |sdk| {
        //         for (payloads.items) |install_payload| {
        //             const payload = &pkgs.payloads[install_payload.index.int()];
        //             switch (identifyPayload(payload.file_name)) {
        //                 .unknown => {},
        //                 .sdk => {
        //                     const pkg_index = pkgs.pkgIndexFromPayloadIndex(install_payload.index);
        //                     const pkg = &pkgs.slice[pkg_index.int()];
        //                     if (std.mem.eql(u8, sdk_version, pkg.version)) break;
        //                 },
        //             }
        //         } else {
        //             var bw = std.io.bufferedWriter(std.io.getStdErr().writer());
        //             try bw.writer().print("error: --sdk version '{s}' NOT FOUND, pick one of:\n", .{sdk_version});
        //             var found_sdk_versions: std.ArrayListUnmanaged([]const u8) = .{};
        //             defer found_sdk_versions.deinit(scratch);
        //             for (pkgs.slice, 0..) |pkg, pkg_index| {
        //                 switch (pkg.language) {
        //                     .neutral => {},
        //                     .en_us => {},
        //                     .other => continue,
        //                 }
        //                 for (pkgs.payloadsFromPkgIndex(.fromInt(pkg_index))) |payload| {
        //                     switch (identifyPayload(payload.file_name)) {
        //                         .unknown => {},
        //                         .sdk => {
        //                             insertSorted(
        //                                 []const u8,
        //                                 scratch,
        //                                 &found_sdk_versions,
        //                                 pkg.version,
        //                                 {},
        //                                 orderDottedNumeric,
        //                             ) catch |e| oom(e);
        //                         },
        //                     }
        //                 }
        //             }
        //             for (found_sdk_versions.items, 0..) |version, i| {
        //                 const suffix: []const u8 = if (i + 1 == found_sdk_versions.items.len) " (latest)" else "";
        //                 try bw.writer().print("    {s}{s}\n", .{ version, suffix });
        //             }
        //             try bw.flush();
        //             std.process.exit(0xff);
        //         }
        //     },
        // };

        log.warn("TODO: add the dependencies for all the packages we've added", .{});

        for (install_pkgs.items) |install_pkg| {
            const r = pkgs.payloadRangeFromPkgIndex(install_pkg.index);
            for (r.start..r.limit) |payload_index| {
                insertSorted(
                    InstallPayload,
                    scratch,
                    &payloads,
                    .init(install_pkg.target, payload_index),
                    pkgs.payloads,
                    InstallPayload.order,
                ) catch |e| oom(e);
            }
        }

        break :blk_payloads payloads.toOwnedSlice(scratch) catch |e| oom(e);
    };

    // sanity check that our payloads are sorted
    if (payloads.len > 0) for (1..payloads.len) |i| {
        std.debug.assert(switch (MsvcupPackage.order({}, payloads[i - 1].target, payloads[i].target)) {
            .lt, .eq => true,
            .gt => false,
        });
        std.debug.assert(.lt == InstallPayload.order(pkgs.payloads, payloads[i - 1], payloads[i]));
    };

    var cabs: std.ArrayListUnmanaged(PayloadIndex) = .{};
    defer cabs.deinit(scratch);
    const CabOffset = struct { cab_offset: usize };
    var payload_cab_offsets: []CabOffset = scratch.alloc(CabOffset, payloads.len) catch |e| oom(e);
    defer scratch.free(payload_cab_offsets);

    // download msi payloads so we can see which cab files they require
    // TODO: we should eventually loop through and gather all the MSI files
    //       so we can install them all at once
    for (payloads, 0..) |install_payload, payload_cab_offsets_index| {
        const cab_offset = cabs.items.len;
        payload_cab_offsets[payload_cab_offsets_index] = .{ .cab_offset = cab_offset };
        const payload = pkgs.payloads[install_payload.index.int()];
        switch (getLockFileUrlKind(payload.url_decoded) orelse errExit(
            "unable to determine the payload kind from url '{s}'",
            .{payload.url_decoded},
        )) {
            .vsix, .cab, .zip => {},
            .msi => {
                _ = uriFromUrlDecoded(payload.url_decoded) catch errExit(
                    "payload url '{s}' is not a valid uri",
                    .{payload.url_decoded},
                );
                const cache_entry = CacheEntry.alloc(
                    scratch,
                    scratch,
                    cache_dir,
                    payload.sha256,
                    basenameFromUrl(payload.url_decoded),
                );
                defer cache_entry.free(scratch);
                try fetchPayload(
                    scratch,
                    progress_node,
                    cache_dir,
                    payload.sha256,
                    payload.url_decoded,
                    cache_entry.path,
                );
                const msi_content = blk: {
                    const file = try std.fs.cwd().openFile(cache_entry.path, .{});
                    defer file.close();
                    break :blk try file.readToEndAlloc(scratch, std.math.maxInt(usize));
                };
                const pkg_index = pkgs.pkgIndexFromPayloadIndex(install_payload.index);
                const pkg_payload_range = pkgs.payloadRangeFromPkgIndex(pkg_index);

                const start = std.time.nanoTimestamp();
                var indexof_elapsed: i128 = 0;
                var loop_elapsed: i128 = 0;

                {
                    var offset: usize = 0;
                    while (true) {
                        const before_indexof: i128 = std.time.nanoTimestamp();
                        const index = indexOfCab2(msi_content, offset) orelse break;
                        indexof_elapsed += std.time.nanoTimestamp() - before_indexof;
                        offset = index + 4;
                        const before_loop = std.time.nanoTimestamp();
                        for (pkg_payload_range.start..pkg_payload_range.limit) |pkg_payload_index| {
                            if (pkg_payload_index == install_payload.index.int()) continue;
                            const pkg_payload = &pkgs.payloads[pkg_payload_index];
                            if (std.mem.endsWith(u8, pkg_payload.file_name, ".cab")) {
                                const cab_payload = std.fs.path.basename(pkg_payload.file_name);
                                if (index + 4 < cab_payload.len) continue;
                                const cab_msi = msi_content[index + 4 - cab_payload.len ..][0..cab_payload.len];
                                if (std.ascii.indexOfIgnoreCase(cab_payload, cab_msi)) |_| {
                                    cabs.append(scratch, .fromInt(pkg_payload_index)) catch |e| oom(e);
                                    break;
                                }
                            }
                        }
                        const now = std.time.nanoTimestamp();
                        loop_elapsed += now - before_loop;
                    }
                }
                const elapsed = std.time.nanoTimestamp() - start;
                std.log.info(
                    "FindCabs took {d:.6} ms (loop took {d:.6} ms) (indexof took {d:.6} ms)",
                    .{
                        @as(f32, @floatFromInt(elapsed)) / @as(f32, std.time.ns_per_ms),
                        @as(f32, @floatFromInt(loop_elapsed)) / @as(f32, std.time.ns_per_ms),
                        @as(f32, @floatFromInt(indexof_elapsed)) / @as(f32, std.time.ns_per_ms),
                    },
                );
                std.sort.heap(PayloadIndex, cabs.items[cab_offset..], pkgs.payloads, PayloadIndex.lessThan);
            },
        }
    }

    log.info("{} payloads:", .{payloads.len});
    if (std.fs.path.dirname(lock_file_path)) |dir| try std.fs.cwd().makePath(dir);
    const lock_file = try std.fs.cwd().createFile(lock_file_path, .{});
    defer lock_file.close();
    var bw = std.io.bufferedWriter(lock_file.writer());
    // try bw.writer().print("msvc {s}\n", .{msvc_version});
    // for (sdk_versions) |sdk_version| {
    //     try bw.writer().print("sdk {s}\n", .{sdk_version});
    // }
    // try bw.writer().writeAll("payloads:\n");
    if (autoenv) {
        try bw.writer().writeAll("autoenv\n");
    }
    for (payloads, 0..) |install_payload, payload_cab_offsets_index| {
        const payload = pkgs.payloads[install_payload.index.int()];
        _ = uriFromUrlDecoded(payload.url_decoded) catch errExit(
            "payload url '{s}' is not a valid uri",
            .{payload.url_decoded},
        );
        const url_kind = getLockFileUrlKind(payload.url_decoded) orelse errExit(
            "unable to determine the payload kind from url '{s}'",
            .{payload.url_decoded},
        );
        const pkg_index = pkgs.pkgIndexFromPayloadIndex(install_payload.index);
        const pkg = &pkgs.slice[pkg_index.int()];
        _ = pkg;

        const cabs_start = payload_cab_offsets[payload_cab_offsets_index].cab_offset;
        const cabs_limit = if (payload_cab_offsets_index + 1 >= payload_cab_offsets.len)
            cabs.items.len
        else
            payload_cab_offsets[payload_cab_offsets_index + 1].cab_offset;
        for (cabs.items[cabs_start..cabs_limit]) |cab_payload_index| {
            const cab_payload = pkgs.payloads[cab_payload_index.int()];
            std.debug.assert(.cab == getLockFileUrlKind(cab_payload.url_decoded).?);
            try writePayload(bw.writer(), null, .cab, cab_payload.url_decoded, cab_payload.sha256, cab_payload.file_name);
        }
        try writePayload(bw.writer(), install_payload.target, url_kind, payload.url_decoded, payload.sha256, payload.file_name);
    }
    try bw.flush();
}

fn indexOfCab(msi_content: []const u8, pos: usize) ?usize {
    return std.mem.indexOfPos(u8, msi_content, pos, ".cab");
}
// this results in a significant performance difference (at least in Debug mode)
// for example processing the ucrt msi goes from 9.6 ms to 1.6 ms
fn indexOfCab2(msi_content: []const u8, pos: usize) ?usize {
    if (msi_content.len < 4) return null;
    const end = msi_content.len - 3;
    var i: usize = pos;
    while (i < end) : (i += 1) {
        if (msi_content[i + 3] == 'b') {
            if (msi_content[i + 2] == 'a' and
                msi_content[i + 1] == 'c' and
                msi_content[i] == '.')
            {
                return i;
            }
        }
    }
    return null;
}

fn writePayload(
    writer: anytype,
    maybe_target: ?MsvcupPackage,
    url_kind: LockFileUrlKind,
    url: []const u8,
    sha256: Sha,
    file_name: []const u8,
) !void {
    std.debug.assert(url_kind == getLockFileUrlKind(url));
    if (std.mem.indexOfScalar(u8, url, '\n')) |_| @panic("urls cannot contain newlines");
    if (std.mem.indexOfScalar(u8, file_name, '\n')) |_| @panic("file names cannot contain newlines");
    const space, const out_file_name = switch (url_kind) {
        .vsix, .msi, .zip => .{ "", "" },
        .cab => .{ " ", file_name },
    };
    const expect_target_string = switch (url_kind) {
        .vsix, .msi, .zip => true,
        .cab => false,
    };
    std.debug.assert(expect_target_string == (maybe_target != null));
    const target_str: []const u8 = if (maybe_target) |t| t.poolString().slice else "";

    const sha_hex = sha256.toHex();
    if (std.ascii.indexOfIgnoreCase(url, &sha_hex)) |hash_index| {
        try writer.print("{s}|{s}|{d}{s}{s}\n", .{ target_str, url, hash_index, space, out_file_name });
    } else {
        try writer.print("{s}|{s}|{s}{s}{s}\n", .{ target_str, url, sha256, space, std.fs.path.basenameWindows(out_file_name) });
    }
}

const PackageId = union(enum) {
    unknown,
    unexpected: struct {
        offset: usize,
        expected: enum {
            version,
            anything,
            arch,
            target_arch,
            end,
        },
    },
    msvc_version_something: struct {
        build_version: []const u8,
        something: []const u8,
    },
    msvc_version_tools_something: struct {
        build_version: []const u8,
        something: []const u8,
    },
    msvc_version_host_target: struct {
        build_version: []const u8,
        host_arch: Arch,
        target_arch: Arch,
        name: []const u8,
    },
    msbuild: []const u8, // version
    diasdk,
    ninja: []const u8, // version
    cmake: []const u8, // version
};

fn isVersionDigit(c: u8) bool {
    return switch (c) {
        '0'...'9' => true,
        else => false,
    };
}

const Scan = struct {
    slice: []const u8,
    end: usize,
};
fn scanTo(s: []const u8, start: usize, to: u8) Scan {
    if (std.mem.indexOfScalarPos(u8, s, start, to)) |i| {
        if (i > start) return .{ .slice = s[start..i], .end = i + 1 };
    }
    return .{ .slice = s[start..], .end = s.len };
}
fn scanIdPart(id: []const u8, start: usize) Scan {
    return scanTo(id, start, '.');
}
fn scanIdVersion(id: []const u8, start: usize) Scan {
    var offset = start;
    while (true) : (offset += 1) {
        if (offset == id.len) return .{
            .slice = id[start..],
            .end = id.len,
        };
        switch (id[offset]) {
            '.' => {},
            '0'...'9' => {},
            else => break,
        }
    }
    while (offset > start) : (offset -= 1) {
        if (id[offset - 1] == '.') break;
    }
    while (true) {
        if (offset == start) return .{
            .slice = id[start..start],
            .end = start,
        };
        if (id[offset - 1] == '.') return .{
            .slice = id[start .. offset - 1],
            .end = offset,
        };
    }
}

fn isDigits(s: []const u8) bool {
    for (s) |c| switch (c) {
        '0'...'9' => {},
        else => return false,
    };
    return true;
}

fn identifyPackage(id: []const u8) PackageId {
    // NOTE: we're assuming this package is currently at version 170
    if (std.mem.eql(u8, id, "Microsoft.Build")) return .{ .msbuild = "170" };
    // NOTE: we're assuming this package is currently at version 170
    if (std.mem.eql(u8, id, "Microsoft.Build.Arm64")) return .{ .msbuild = "170" };
    const msbuild_prefix = "Microsoft.VisualStudio.VC.MSBuild.";
    if (std.mem.startsWith(u8, id, msbuild_prefix)) {
        const version = scanIdPart(id, msbuild_prefix.len);
        // if (std.mem.startsWith(u8, version.slice, "v") and isDigits(version.slice[1..])) {
        //     return .{ .msbuild = version.slice[1..] };
        // }
        // right now only v170 really works
        if (std.mem.eql(u8, version.slice, "v170")) {
            return .{ .msbuild = "170" };
        }
    }

    if (std.mem.eql(u8, id, "Microsoft.VisualCpp.DIA.SDK")) {
        return .diasdk;
    }

    const msvc_prefix = "Microsoft.VC.";

    if (std.mem.startsWith(u8, id, msvc_prefix)) {
        const version = scanIdVersion(id, msvc_prefix.len);
        if (version.slice.len == 0) return .{ .unexpected = .{
            .offset = msvc_prefix.len,
            .expected = .version,
        } };
        const tools_part = scanIdPart(id, version.end);
        if (tools_part.slice.len == 0) return .{ .unexpected = .{
            .offset = version.end,
            .expected = .anything,
        } };
        if (!std.mem.eql(u8, tools_part.slice, "Tools")) return .{ .msvc_version_something = .{
            .build_version = version.slice,
            .something = id[version.end..],
        } };
        const host_part = scanIdPart(id, tools_part.end);
        if (host_part.slice.len == 0) return .{ .unexpected = .{
            .offset = tools_part.end,
            .expected = .anything,
        } };
        if (!std.mem.startsWith(u8, host_part.slice, "Host")) return .{ .msvc_version_tools_something = .{
            .build_version = version.slice,
            .something = id[version.end..],
        } };
        const host_arch: Arch = blk: {
            const arch_str = host_part.slice[4..];
            break :blk Arch.fromStringIgnoreCase(arch_str) orelse return .{ .unexpected = .{
                .offset = tools_part.end + 4,
                .expected = .arch,
            } };
        };
        const target_part = scanIdPart(id, host_part.end);
        if (!std.mem.startsWith(u8, target_part.slice, "Target")) return .{ .unexpected = .{
            .offset = host_part.end,
            .expected = .target_arch,
        } };
        const target_arch: Arch = blk: {
            const arch_str = target_part.slice[6..];
            break :blk Arch.fromStringIgnoreCase(arch_str) orelse return .{ .unexpected = .{
                .offset = tools_part.end + 6,
                .expected = .arch,
            } };
        };
        return .{ .msvc_version_host_target = .{
            .build_version = version.slice,
            .host_arch = host_arch,
            .target_arch = target_arch,
            .name = id[target_part.end..],
        } };
    }

    {
        const ninja_prefix = "ninja-";
        if (std.mem.startsWith(u8, id, ninja_prefix)) {
            const version = scanIdVersion(id, ninja_prefix.len);
            if (version.slice.len == 0) return .{ .unexpected = .{
                .offset = ninja_prefix.len,
                .expected = .version,
            } };
            if (version.end != id.len) return .{ .unexpected = .{
                .offset = version.end,
                .expected = .end,
            } };
            return .{ .ninja = version.slice };
        }
    }
    {
        const cmake_prefix = "cmake-";
        if (std.mem.startsWith(u8, id, cmake_prefix)) {
            const version = scanIdVersion(id, cmake_prefix.len);
            if (version.slice.len == 0) return .{ .unexpected = .{
                .offset = cmake_prefix.len,
                .expected = .version,
            } };
            if (version.end != id.len) return .{ .unexpected = .{
                .offset = version.end,
                .expected = .end,
            } };
            return .{ .cmake = version.slice };
        }
    }

    return .unknown;
}

const sdk11_min_version = "22000";

const PayloadId = enum { unknown, sdk };
fn identifyPayload(payload_filename: []const u8) PayloadId {
    const ucrt_prefix = "Installers\\Universal CRT Headers Libraries and Sources-";
    if (startsWith(u8, payload_filename, ucrt_prefix)) |arch_lang| {
        // I *think the arch_lang string here is meaningless, the actual arch
        // in the containing package metadata
        _ = arch_lang;
        return .sdk;
    }

    // contains the headers in "Windows Kits\10\Include\VERSION" subdirectories
    // 'shared', 'um' and 'winrt'
    if (std.mem.startsWith(u8, payload_filename, "Installers\\Windows SDK Desktop Headers "))
        return .sdk;
    // contains a bunch of ".lib" file in the um directory
    if (std.mem.startsWith(u8, payload_filename, "Installers\\Windows SDK Desktop Libs "))
        return .sdk;

    // includes tools like signtool.exe
    if (std.mem.startsWith(u8, payload_filename, "Installers\\Windows SDK Signing Tools-"))
        return .sdk;

    // contains cppwinrt and winrt headers
    if (std.mem.startsWith(u8, payload_filename, "Installers\\Windows SDK for Windows Store Apps Headers-"))
        return .sdk;

    // contains a bunch of core windows ".lib" files like ntdll, kernel32, etc, but also
    // others like the DirectX libraries.
    if (std.mem.startsWith(u8, payload_filename, "Installers\\Windows SDK for Windows Store Apps Libs-"))
        return .sdk;

    // this package contains a bunch of executables like dxc.exe, fxc.exe, inspect.exe, certmgr.exe,
    // cppwinrt.exe, mc.exe, midl.exe, mt.exe, rc.exe
    if (std.mem.startsWith(u8, payload_filename, "Installers\\Windows SDK for Windows Store Apps Tools-"))
        return .sdk;

    // if (std.mem.startsWith(u8, payload_filename, "Installers\\Windows SDK for Windows Store Apps Headers-"))
    //     return .sdk;

    // def getSdkInstallers(targets, sdk_include_signing, sdk_pkg):
    //     installers = getSdkInstallersBase(targets)
    //     if sdk_include_signing:
    //         installers += [findSigningInstaller(sdk_pkg)]
    //     return installers

    // def getSdkInstallersBase(targets):
    //     pkgs = [
    //         f"Windows SDK for Windows Store Apps Tools-x86_en-us.msi",
    //         f"Windows SDK for Windows Store Apps Headers-x86_en-us.msi",
    //         f"Windows SDK for Windows Store Apps Headers OnecoreUap-x86_en-us.msi",
    //         f"Windows SDK for Windows Store Apps Libs-x86_en-us.msi",
    //         f"Universal CRT Headers Libraries and Sources-x86_en-us.msi",
    //     ]
    //     for target in ALL_TARGETS:
    //         pkgs += [
    //             f"Windows SDK Desktop Headers {target}-x86_en-us.msi",
    //             f"Windows SDK OnecoreUap Headers {target}-x86_en-us.msi",
    //         ]
    //     for target in targets:
    //         pkgs += [f"Windows SDK Desktop Libs {target}-x86_en-us.msi"]
    //     return pkgs
    return .unknown;
}

const LockFileUrlKind = enum { vsix, msi, cab, zip };
fn getLockFileUrlKind(url: []const u8) ?LockFileUrlKind {
    if (std.mem.endsWith(u8, url, ".vsix")) return .vsix;
    if (std.mem.endsWith(u8, url, ".msi")) return .msi;
    if (std.mem.endsWith(u8, url, ".cab")) return .cab;
    if (std.mem.endsWith(u8, url, ".zip")) return .zip;
    return null;
}

const Language = enum { neutral, en_us, other };
const Package = struct {
    id: []const u8,
    version: []const u8,
    payloads_offset: usize,
    language: Language,
};
const Payload = struct {
    url_decoded: []const u8,
    sha256: Sha,
    file_name: []const u8,
    pub fn nameDecoded(self: *const Payload) []const u8 {
        return basenameFromUrl(self.url_decoded);
    }
};

fn basenameFromUrl(url: []const u8) []const u8 {
    var i: usize = url.len;
    while (i > 0 and url[i - 1] != '/') : (i -= 1) {}
    return url[i..];
}

fn readVsManifestLocking(
    allocator: std.mem.Allocator,
    progress_node: std.Progress.Node,
    scratch: std.mem.Allocator,
    msvcup_dir: MsvcupDir,
    channel_kind: ChannelKind,
    update: ManifestUpdate,
) !PathAndContent {
    global.enteredLockingFunction(@src().fn_name);

    const subdir = switch (channel_kind) {
        .release => "vs-release",
        .preview => "vs-preview",
    };
    var vsman_latest_owning: OwningPath = .{
        .owning_path = msvcup_dir.path(allocator, .{ "manifest", subdir, "latest" }) catch |e| oom(e),
    };
    defer vsman_latest_owning.deinit(allocator);

    const vsman_lock_path = msvcup_dir.path(scratch, .{ "manifest", subdir, ".lock" }) catch |e| oom(e);
    defer scratch.free(vsman_lock_path);

    {
        var vsman_lock = try LockFile.lock(vsman_lock_path);
        defer vsman_lock.unlock();
        global.tookFileLock(@src().fn_name);
        defer global.releasedFileLock(@src().fn_name);
        switch (update) {
            .off => {
                if (try readFile(allocator, vsman_latest_owning.borrow())) |content| return .{
                    .path = vsman_latest_owning.take(),
                    .content = content,
                };
            },
            .daily => @panic("todo: daily update"),
            .always => {},
        }
    }

    // we release the vsman_lock lock before doing another locking operation to avoid deadlock
    var chman = try readChManifestLocking(scratch, progress_node, scratch, msvcup_dir, channel_kind, update);
    defer chman.freeConst(scratch);

    {
        var vsman_lock = try LockFile.lock(vsman_lock_path);
        defer vsman_lock.unlock();
        global.tookFileLock(@src().fn_name);
        defer global.releasedFileLock(@src().fn_name);
        // we have to check if the file exists again because we released our lock
        // to resolve the URL and avoid deadlock
        switch (update) {
            .off => {
                if (try readFile(allocator, vsman_latest_owning.borrow())) |content| return .{
                    .path = vsman_latest_owning.take(),
                    .content = content,
                };
            },
            .daily => @panic("todo: daily update"),
            .always => @panic("todo: check if the file has been updated (this is the second check)"),
        }

        const payload = try vsManifestPayloadFromChManifest(scratch, scratch, channel_kind, chman);
        defer payload.free(scratch);
        const uri = uriFromUrlDecoded(payload.url_decoded) catch |e| errExit(
            "failed to parse vs manifest url '{s}' taken from file '{s}' with {s}",
            .{ payload.url_decoded, chman.path, @errorName(e) },
        );

        // log.info("payload size {} url '{s}' sha256 '{s}'", .{ payload.size, payload.url, payload.sha256 });
        // if (true) @panic("hash the URI and don't redownload it");

        // NOTE: for some reason the size/sha256 is not right for this?!?
        // try fetch(scratch, uri, vsman_latest_owning.borrow(), payload.size, payload.sha256);
        const sha256 = try fetch(progress_node, scratch, uri, vsman_latest_owning.borrow(), .{});
        _ = sha256;
        const content = try readFile(allocator, vsman_latest_owning.borrow()) orelse errExit(
            "{s} still doesn't exist",
            .{vsman_latest_owning.borrow()},
        );
        return .{ .path = vsman_latest_owning.take(), .content = content };
    }
}

fn sha256FromUri(uri: std.Uri) Sha {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    uri.format("", .{}, hasher.writer()) catch |e| switch (e) {};
    const digest = hasher.finalResult();
    var hex_result: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex_result, "{}", .{std.fmt.fmtSliceHexLower(&digest)}) catch unreachable;
    return hex_result;
}

const VsManifestPayload = struct {
    url_decoded: []const u8,
    sha256: Sha,
    size: u63,
    pub fn free(self: VsManifestPayload, allocator: std.mem.Allocator) void {
        allocator.free(self.url_decoded);
    }
};

fn allocUrlPercentDecoded(allocator: std.mem.Allocator, url: []const u8) error{OutOfMemory}![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = try .initCapacity(allocator, url.len);
    buf.expandToCapacity();
    @memcpy(buf.items[0..url.len], url);
    const decoded = std.Uri.percentDecodeInPlace(buf.items);
    std.mem.copyForwards(u8, buf.items[0..decoded.len], decoded);
    buf.shrinkRetainingCapacity(decoded.len);
    return try buf.toOwnedSlice(allocator);
}

fn vsManifestPayloadFromChManifest(
    allocator: std.mem.Allocator,
    scratch: std.mem.Allocator,
    channel_kind: ChannelKind,
    chman: PathAndContent,
) !VsManifestPayload {
    const parsed = try std.json.parseFromSlice(std.json.Value, scratch, chman.content, .{});
    defer parsed.deinit();
    const json_file: JsonContext.File = .{ .file_path = chman.path };
    var json_error: JsonContext.Error = undefined;
    const file_obj = json_file.as(.object, &json_error, parsed.value) catch errExit("{}", .{json_error});
    const channel_items_field = file_obj.getField(&json_error, "channelItems") catch errExit("{}", .{json_error});
    const channel_items = channel_items_field.as(.array, &json_error) catch errExit("{}", .{json_error});
    const payload = blk: {
        const vs_manifest_channel_id = switch (channel_kind) {
            .release => "Microsoft.VisualStudio.Manifests.VisualStudio",
            .preview => "Microsoft.VisualStudio.Manifests.VisualStudioPreview",
        };
        for (0..channel_items.items.len) |index| {
            const channel_item_element = channel_items.getElement(&json_error, index) catch errExit("{}", .{json_error});
            const channel_item = channel_item_element.as(.object, &json_error) catch errExit("{}", .{json_error});
            const id_field = channel_item.getField(&json_error, "id") catch errExit("{}", .{json_error});
            const id = id_field.as(.string, &json_error) catch errExit("{}", .{json_error});
            if (std.mem.eql(u8, id, vs_manifest_channel_id)) {
                const payloads_field = channel_item.getField(&json_error, "payloads") catch errExit("{}", .{json_error});
                const payloads = payloads_field.as(.array, &json_error) catch errExit("{}", .{json_error});
                if (payloads.items.len != 1) errExit(
                    "{s}: channelItem with id \"{s}\" has {} payloads instead of 1",
                    .{ chman.path, id, payloads.items.len },
                );
                const payload_element = payloads.getElement(&json_error, 0) catch unreachable;
                const payload_object = payload_element.as(.object, &json_error) catch errExit("{}", .{json_error});
                break :blk PayloadJson.init(payload_object);
            }
        }
        errExit(
            "channel manifest '{s}' is missing vs manifest id '{s}'",
            .{ chman.path, vs_manifest_channel_id },
        );
    };
    return .{
        .url_decoded = allocUrlPercentDecoded(allocator, payload.url) catch |e| oom(e),
        .sha256 = payload.sha256,
        .size = payload.size,
    };
}

const PayloadJson = struct {
    fileName: []const u8,
    sha256: Sha,
    size: u63,
    url: []const u8,
    pub fn init(obj: JsonContext.Object) PayloadJson {
        var err: JsonContext.Error = undefined;

        const file_name = blk: {
            const field = obj.getField(&err, "fileName") catch errExit("{}", .{err});
            break :blk field.as(.string, &err) catch errExit("{}", .{err});
        };
        const sha256: Sha = blk: {
            const field = obj.getField(&err, "sha256") catch errExit("{}", .{err});
            const str = field.as(.string, &err) catch errExit("{}", .{err});
            if (str.len != 64) {
                const file_path: []const u8 = if (obj.parent_context.getFilePath()) |p| p else "?";
                errExit(
                    "{s}: {} value '{s}' is {} chars but expected 64",
                    .{ file_path, field, str, str.len },
                );
            }
            const sha_hex = lowerShaHex(str[0..64]);
            break :blk Sha.parseHex(&sha_hex) orelse {
                const file_path: []const u8 = if (obj.parent_context.getFilePath()) |p| p else "?";
                errExit("{s}: invalid sha '{s}'", .{ file_path, &sha_hex });
            };
        };
        const size: u63 = blk: {
            const field = obj.getField(&err, "size") catch errExit("{}", .{err});
            const size = field.as(.integer, &err) catch errExit("{}", .{err});
            if (size < 0) {
                const file_path: []const u8 = if (obj.parent_context.getFilePath()) |p| p else "?";
                errExit(
                    "{s}: {} size {} is negative",
                    .{ file_path, field, size },
                );
            }
            break :blk @intCast(size);
        };
        const url = blk: {
            const field = obj.getField(&err, "url") catch errExit("{}", .{err});
            break :blk field.as(.string, &err) catch errExit("{}", .{err});
        };

        return .{
            .fileName = file_name,
            .sha256 = sha256,
            .size = size,
            .url = url,
        };
    }
};

const PathAndContent = struct {
    path: []const u8,
    content: []const u8,
    pub fn freeConst(self: PathAndContent, allocator: std.mem.Allocator) void {
        allocator.free(self.content);
        allocator.free(self.path);
    }
};

const OwningPath = struct {
    owning_path: ?[]const u8 = null,
    pub fn deinit(self: *OwningPath, allocator: std.mem.Allocator) void {
        if (self.owning_path) |path| allocator.free(path);
        self.owning_path = undefined;
    }
    pub fn borrow(self: *OwningPath) []const u8 {
        return self.owning_path orelse @panic("called borrow with no path");
    }
    pub fn take(self: *OwningPath) []const u8 {
        const copy = self.owning_path orelse @panic("called take with no path");
        self.owning_path = null;
        return copy;
    }
};

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// TODO: we should save the original channel manifest, but, I *think* we
//       should also process the channel manifest into just the data we need.
//       NOTE: this transformation should take as input both the original channel
//             manifest, and, it should take a string that represents the entire
//             transformation, which, means that if we need to modify our transformation,
//             then we can re-transform old manifests if we need new data.
fn readChManifestLocking(
    allocator: std.mem.Allocator,
    progress_node: std.Progress.Node,
    scratch: std.mem.Allocator,
    msvcup_dir: MsvcupDir,
    channel_kind: ChannelKind,
    update: ManifestUpdate,
) !PathAndContent {
    global.enteredLockingFunction(@src().fn_name);

    const subdir = switch (channel_kind) {
        .release => "channel-release",
        .preview => "channel-preview",
    };
    var chman_latest_owning: OwningPath = .{
        .owning_path = msvcup_dir.path(allocator, .{ "manifest", subdir, "latest" }) catch |e| oom(e),
    };
    defer chman_latest_owning.deinit(allocator);
    const chman_lock_path = msvcup_dir.path(scratch, .{ "manifest", subdir, ".lock" }) catch |e| oom(e);
    defer scratch.free(chman_lock_path);

    {
        var chman_lock = try LockFile.lock(chman_lock_path);
        defer chman_lock.unlock();
        global.tookFileLock(@src().fn_name);
        defer global.releasedFileLock(@src().fn_name);
        switch (update) {
            .off => {
                if (try readFile(allocator, chman_latest_owning.borrow())) |content| return .{
                    .path = chman_latest_owning.take(),
                    .content = content,
                };
            },
            .daily => @panic("todo: daily update"),
            .always => {},
        }
    }

    const chman_url_encoded = try resolveChManifestUrlLocking(scratch, scratch, msvcup_dir, channel_kind, update);
    defer chman_url_encoded.freeConst(scratch);
    const uri = std.Uri.parse(chman_url_encoded.content) catch |e| errExit(
        "failed to parse latest channel manifest url '{s}' from file '{s}' with {s}",
        .{ chman_url_encoded.content, chman_url_encoded.path, @errorName(e) },
    );

    {
        var chman_lock = try LockFile.lock(chman_lock_path);
        defer chman_lock.unlock();
        global.tookFileLock(@src().fn_name);
        defer global.releasedFileLock(@src().fn_name);

        // we have to check if the file exists again because we released our lock
        // to resolve the URL and avoid deadlock
        switch (update) {
            .off => {
                if (try readFile(allocator, chman_latest_owning.borrow())) |content| return .{
                    .path = chman_latest_owning.take(),
                    .content = content,
                };
            },
            .daily => @panic("todo: daily update"),
            .always => @panic("todo: check if the file has been updated (this is the second check)"),
        }

        // const uri_sha = sha256FromUri(uri);
        // // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        // // TODO: don't perform the fetch if we already have!!!
        // //       hash the URI and see if we've already fetched it?
        // //       ALSO, I'd like to see if
        // if (true) std.debug.panic("check uri sha '{s}'", .{uri_sha});

        const sha256 = try fetch(progress_node, scratch, uri, chman_latest_owning.borrow(), .{});
        _ = sha256;
        const content = try readFile(allocator, chman_latest_owning.borrow()) orelse errExit(
            "{s} still doesn't exist",
            .{chman_latest_owning.borrow()},
        );
        return .{ .path = chman_latest_owning.take(), .content = content };
    }
}

fn resolveChManifestUrlLocking(
    allocator: std.mem.Allocator,
    scratch: std.mem.Allocator,
    msvcup_dir: MsvcupDir,
    channel_kind: ChannelKind,
    update: ManifestUpdate,
) !PathAndContent {
    global.enteredLockingFunction(@src().fn_name);

    const subdir = switch (channel_kind) {
        .release => "channel-release-url",
        .preview => "channel-preview-url",
    };
    var chman_latest_url_path_owning: OwningPath = .{
        .owning_path = msvcup_dir.path(allocator, .{ "manifest", subdir, "latest" }) catch |e| oom(e),
    };
    defer chman_latest_url_path_owning.deinit(allocator);
    const chman_lock_path = msvcup_dir.path(scratch, .{ "manifest", subdir, ".lock" }) catch |e| oom(e);
    defer scratch.free(chman_lock_path);
    {
        var chman_url_lock = try LockFile.lock(chman_lock_path);
        defer chman_url_lock.unlock();
        global.tookFileLock(@src().fn_name);
        defer global.releasedFileLock(@src().fn_name);
        switch (update) {
            .off => {
                if (try readFile(allocator, chman_latest_url_path_owning.borrow())) |content| return .{
                    .path = chman_latest_url_path_owning.take(),
                    .content = content,
                };
            },
            .daily => @panic("todo: daily update"),
            .always => {},
        }
        try resolveChannelManifestUrlToFile(
            scratch,
            std.Uri.parse(channel_kind.httpsUrl()) catch unreachable,
            chman_latest_url_path_owning.borrow(),
        );
        const content = try readFile(allocator, chman_latest_url_path_owning.borrow()) orelse errExit(
            "{s} still doesn't exist",
            .{chman_latest_url_path_owning.borrow()},
        );
        return .{
            .path = chman_latest_url_path_owning.take(),
            .content = content,
        };
    }
}

fn resolveChannelManifestUrlToFile(
    scratch: std.mem.Allocator,
    uri: std.Uri,
    out_path: []const u8,
) !void {
    // TODO: progres report
    log.info("resolving URL '{}'...", .{uri});

    var client = std.http.Client{ .allocator = scratch };
    defer client.deinit();
    client.initDefaultProxies(scratch) catch |err| switch (err) {
        error.OutOfMemory => oom(error.OutOfMemory),
        error.InvalidWtf8,
        error.UnexpectedCharacter,
        error.InvalidFormat,
        error.InvalidPort,
        error.HttpProxyMissingHost,
        => |e| errExit("init proxy failed with {s}", .{@errorName(e)}),
    };
    var header_buffer: [8196]u8 = undefined;

    var request = try client.open(.GET, uri, .{
        .server_header_buffer = &header_buffer,
        .keep_alive = false,
        .redirect_behavior = .not_allowed,
    });
    defer request.deinit();
    try request.send();
    request.wait() catch |err| switch (err) {
        error.TooManyHttpRedirects => {
            if (request.response.location) |redirect_url| {
                _ = std.Uri.parse(redirect_url) catch |e| errExit(
                    "failed to parse the redirect url '{s}' with {s}",
                    .{ redirect_url, @errorName(e) },
                );
                // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                // TODO: don't download directly to this file, download to a temp file and rename
                // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                const out_file = try std.fs.cwd().createFile(out_path, .{});
                defer out_file.close();
                try out_file.writer().writeAll(redirect_url);
                return;
            }
            errExit("redirect response missing Location header", .{});
        },
        else => |e| return e,
    };
    errExit("GET '{s}' HTTP status {} \"{s}\"", .{
        uri,
        @intFromEnum(request.response.status),
        request.response.status.phrase() orelse "",
    });
}

fn uriFromUrlDecoded(url_decoded: []const u8) !std.Uri {
    const uri_invalid = try std.Uri.parse(url_decoded);
    const f = struct {
        pub fn fixUriNotEncoded(component: std.Uri.Component) std.Uri.Component {
            return switch (component) {
                .raw => component,
                .percent_encoded => |pe| .{ .raw = pe },
            };
        }
        pub fn fixUriNotEncodedOpt(maybe_component: ?std.Uri.Component) ?std.Uri.Component {
            const component = maybe_component orelse return null;
            return switch (component) {
                .raw => component,
                .percent_encoded => |pe| .{ .raw = pe },
            };
        }
    };
    return .{
        .scheme = uri_invalid.scheme,
        .user = f.fixUriNotEncodedOpt(uri_invalid.user),
        .password = f.fixUriNotEncodedOpt(uri_invalid.password),
        .host = f.fixUriNotEncodedOpt(uri_invalid.host),
        .port = uri_invalid.port,
        .path = f.fixUriNotEncoded(uri_invalid.path),
        .query = f.fixUriNotEncodedOpt(uri_invalid.query),
        .fragment = f.fixUriNotEncodedOpt(uri_invalid.fragment),
    };
}

fn fetchPayload(
    scratch: std.mem.Allocator,
    progress_node: std.Progress.Node,
    cache_dir: []const u8,
    sha256: Sha,
    url_decoded: []const u8,
    cache_path: []const u8,
) !void {
    const cache_lock_path = std.mem.concat(scratch, u8, &.{ cache_path, ".lock" }) catch |e| oom(e);
    defer scratch.free(cache_lock_path);
    var cache_lock = try LockFile.lock(cache_lock_path);
    defer cache_lock.unlock();
    if (std.fs.cwd().access(cache_path, .{})) {
        log.info("ALREADY FETCHED  | {s} {f}", .{ url_decoded, sha256 });
    } else |err| switch (err) {
        error.FileNotFound => {
            log.info("FETCHING         | {s} {f}", .{ url_decoded, sha256 });
            const fetch_path = std.mem.concat(scratch, u8, &.{ cache_path, ".fetching" }) catch |e| oom(e);
            defer scratch.free(fetch_path);
            const actual_sha256 = try fetch(
                progress_node,
                scratch,
                try uriFromUrlDecoded(url_decoded),
                fetch_path,
                .{},
            );
            if (!sha256.eql(&actual_sha256)) {
                std.log.err(
                    "SHA256 mismatch:\nexpected: {f}\nactual  : {f}\n",
                    .{ sha256, actual_sha256 },
                );
                try finishCacheFetch(scratch, cache_dir, url_decoded, actual_sha256, fetch_path);
                std.process.exit(0xff);
            }
            try std.fs.cwd().rename(fetch_path, cache_path);
        },
        else => |e| return e,
    }
}

fn fetch(
    progress_node: std.Progress.Node,
    scratch: std.mem.Allocator,
    uri: std.Uri,
    out_path: []const u8,
    opt: struct {
        size: ?u64 = null,
    },
) !Sha {
    log.info("fetch: {}", .{uri});
    const progress_node_name = std.fmt.allocPrint(scratch, "fetch {}", .{uri}) catch |e| oom(e);
    defer scratch.free(progress_node_name);
    const node = progress_node.start(progress_node_name, 1);
    defer node.end();

    var client = std.http.Client{ .allocator = scratch };
    defer client.deinit();
    client.initDefaultProxies(scratch) catch |err| switch (err) {
        error.OutOfMemory => oom(error.OutOfMemory),
        error.InvalidWtf8,
        error.UnexpectedCharacter,
        error.InvalidFormat,
        error.InvalidPort,
        error.HttpProxyMissingHost,
        => |e| errExit("init proxy failed with {s}", .{@errorName(e)}),
    };

    var header_buffer: [8196]u8 = undefined;
    var request = try client.open(.GET, uri, .{
        .server_header_buffer = &header_buffer,
        .keep_alive = false,
    });
    defer request.deinit();
    try request.send();
    try request.wait();
    if (request.response.status != .ok) return errExit(
        "fetch '{}': HTTP response {} \"{?s}\"",
        .{ uri, @intFromEnum(request.response.status), request.response.status.phrase() },
    );

    const file = try std.fs.cwd().createFile(out_path, .{});
    defer file.close();
    const maybe_expected_size = blk: {
        if (request.response.content_length) |content_length| {
            if (opt.size) |size| {
                if (size != content_length) errExit(
                    "fetch '{}': Content-Length {} != expected size {}",
                    .{ uri, content_length, size },
                );
            }
            break :blk content_length;
        }
        break :blk opt.size;
    };
    if (maybe_expected_size) |size| try file.setEndPos(size);

    var hasher: std.crypto.hash.sha2.Sha256 = .init(.{});
    var total_received: u64 = 0;

    while (true) {
        var buf: [@max(std.heap.page_size_min, 4096)]u8 = undefined;
        const len = request.reader().read(&buf) catch |e| std.debug.panic(
            "fetch '{}': read failed with {s}",
            .{ uri, @errorName(e) },
        );
        if (len == 0) break;
        total_received += len;
        if (request.response.content_length) |content_length| {
            if (total_received > content_length) errExit(
                "fetch '{}': read more than Content-Length ({})",
                .{ uri, content_length },
            );
        }
        hasher.update(buf[0..len]);
        // NOTE: not going through a buffered writer since we're writing
        //       large chunks
        file.writer().writeAll(buf[0..len]) catch |err| std.debug.panic(
            "fetch '{}': write {} bytes of HTTP response failed with {s}",
            .{ uri, len, @errorName(err) },
        );
    }

    if (request.response.content_length) |content_length| {
        if (total_received != content_length) errExit(
            "fetch '{}': Content-Length is {} but only read {}",
            .{ uri, content_length, total_received },
        );
    } else if (opt.size) |size| if (total_received != size) errExit(
        "fetch '{}': expected size {} but read {}",
        .{ uri, size, total_received },
    );

    var sha: Sha = undefined;
    hasher.final(&sha.bytes);
    return sha;
}

fn readFile(allocator: std.mem.Allocator, path: []const u8) !?[]const u8 {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => |e| return e,
    };
    defer file.close();
    return try file.readToEndAlloc(allocator, std.math.maxInt(usize));
}

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// Resolve ChannelManifest URL
// DownloadChannelManifest
// Download Vs Manifest
// TODO: URL Resolution!
// For sure, I want to track the history of ALL the resolutions for the URLs!
// c:\msvcup\channel-manifest-url\release\latest
// c:\msvcup\channel-manifest-url\release\?
// c:\msvcup\channel-manifest-url\release\1
// c:\msvcup\channel-manifest-url\preview\

const Range = struct { start: usize, limit: usize };

const Packages = struct {
    slice: []const Package,
    payloads: []const Payload,
    pub fn payloadRangeFromPkgIndex(self: *const Packages, pkg_index: PackageIndex) Range {
        return .{
            .start = self.slice[pkg_index.int()].payloads_offset,
            .limit = if (pkg_index.int() == self.slice.len - 1)
                self.payloads.len
            else
                self.slice[pkg_index.int() + 1].payloads_offset,
        };
    }
    pub fn payloadsFromPkgIndex(self: *const Packages, pkg_index: PackageIndex) []const Payload {
        const range = self.payloadRangeFromPkgIndex(pkg_index);
        return self.payloads[range.start..range.limit];
    }
    pub fn pkgIndexFromPayloadIndex(self: *const Packages, payload_index: PayloadIndex) PackageIndex {
        std.debug.assert(self.slice.len > 0);
        var pkg_index_min: usize = 0;
        var pkg_index_max: usize = self.slice.len - 1;
        if (false) std.log.info("find payload {}", .{payload_index.int()});
        var iteration: u32 = 0;
        while (true) {
            if (pkg_index_min == pkg_index_max) return .fromInt(pkg_index_min);
            std.debug.assert(pkg_index_min < pkg_index_max);
            const remaining_pkg_count = pkg_index_max - pkg_index_min + 1;
            const min_range = self.payloadRangeFromPkgIndex(.fromInt(pkg_index_min));
            const max_range = self.payloadRangeFromPkgIndex(.fromInt(pkg_index_max));
            const remaining_payload_count = max_range.limit - min_range.start;
            if (remaining_payload_count == 0) std.debug.panic("payload index {} not found?", .{payload_index.int()});
            std.debug.assert(remaining_payload_count >= 1);
            const payload_offset_ratio: f32 = @as(f32, @floatFromInt(payload_index.int() - min_range.start)) / @as(f32, @floatFromInt(remaining_payload_count));
            const pkg_offset_guess = @min(remaining_pkg_count - 1, @as(usize, @intFromFloat(payload_offset_ratio * @as(f32, @floatFromInt(remaining_pkg_count)))));
            const pkg_index = pkg_index_min + pkg_offset_guess;
            std.debug.assert(pkg_index >= pkg_index_min);
            std.debug.assert(pkg_index <= pkg_index_max);
            const range = self.payloadRangeFromPkgIndex(.fromInt(pkg_index));
            if (false) std.log.info(
                "{}: pkg {}[{},{}) - pkg {}[{},{}) --> guess {d:.2}% pkg {}[{},{})",
                .{
                    iteration,
                    pkg_index_min,
                    min_range.start,
                    min_range.limit,
                    pkg_index_max,
                    max_range.start,
                    max_range.limit,
                    100 * payload_offset_ratio,
                    pkg_index,
                    range.start,
                    range.limit,
                },
            );
            iteration += 1;
            if (payload_index.int() < range.start) {
                pkg_index_max = pkg_index - 1;
            } else if (payload_index.int() < range.limit) {
                return .fromInt(pkg_index);
            } else {
                pkg_index_min = pkg_index + 1;
            }
        }
    }
};

const PackageIndex = enum(usize) {
    _,
    pub fn fromInt(i: usize) PackageIndex {
        return @enumFromInt(i);
    }
    pub fn int(self: PackageIndex) usize {
        return @intFromEnum(self);
    }
    pub fn order(pkgs: []const Package, lhs: PackageIndex, rhs: PackageIndex) std.math.Order {
        return orderDottedAlphabetical({}, pkgs[lhs.int()].id, pkgs[rhs.int()].id);
    }
};
const PayloadIndex = enum(usize) {
    _,
    pub fn fromInt(i: usize) PayloadIndex {
        return @enumFromInt(i);
    }
    pub fn int(self: PayloadIndex) usize {
        return @intFromEnum(self);
    }
    pub fn order(payloads: []const Payload, lhs: PayloadIndex, rhs: PayloadIndex) std.math.Order {
        switch (orderAlphabetical({}, payloads[lhs.int()].nameDecoded(), payloads[rhs.int()].nameDecoded())) {
            .lt, .gt => |o| return o,
            .eq => {},
        }
        return orderNumeric({}, &payloads[lhs.int()].sha256.bytes, &payloads[rhs.int()].sha256.bytes);
    }
    pub fn lessThan(payloads: []const Payload, lhs: PayloadIndex, rhs: PayloadIndex) bool {
        return order(payloads, lhs, rhs) == .lt;
    }
};

const other_languages = std.StaticStringMap(void).initComptime(.{
    .{ "cs-CZ", {} },
    .{ "de-DE", {} },
    .{ "es-ES", {} },
    .{ "fr-FR", {} },
    .{ "it-IT", {} },
    .{ "ja-JP", {} },
    .{ "ko-KR", {} },
    .{ "pl-PL", {} },
    .{ "pt-BR", {} },
    .{ "ru-RU", {} },
    .{ "tr-TR", {} },
    .{ "zh-CN", {} },
    .{ "zh-TW", {} },
});

fn getPackages(
    allocator: std.mem.Allocator,
    scratch: std.mem.Allocator,
    vsman: PathAndContent,
) !Packages {
    // // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // // TODO: filtering/sorting all the packages should be it's own step
    // //       and we should cache the result
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    log.debug("parsing '{s}'...", .{vsman.path});
    const parsed = try std.json.parseFromSlice(std.json.Value, scratch, vsman.content, .{});
    defer parsed.deinit();
    const json_file: JsonContext.File = .{ .file_path = vsman.path };
    var json_error: JsonContext.Error = undefined;
    const file_obj = json_file.as(.object, &json_error, parsed.value) catch errExit("{}", .{json_error});
    const packages_field = file_obj.getField(&json_error, "packages") catch errExit("{}", .{json_error});
    const packages = packages_field.as(.array, &json_error) catch errExit("{}", .{json_error});
    const out_packages = allocator.alloc(Package, packages.items.len + extrapkgs.all.len) catch |e| oom(e);
    var out_package_count: usize = 0;
    errdefer {
        for (out_packages[0..out_package_count]) |out_package| {
            out_package.deinit(allocator);
        }
        allocator.free(out_packages);
    }

    const payload_count: usize = payload_count_blk: {
        var payload_count: usize = 0;
        for (0..packages.items.len) |pkg_index| {
            const pkg_obj_element = packages.getElement(&json_error, pkg_index) catch errExit("{}", .{json_error});
            const pkg_obj = pkg_obj_element.as(.object, &json_error) catch errExit("{}", .{json_error});
            const id_field = pkg_obj.getField(&json_error, "id") catch errExit("{}", .{json_error});
            const id = id_field.as(.string, &json_error) catch errExit("{}", .{json_error});
            const version_field = pkg_obj.getField(&json_error, "version") catch errExit("{}", .{json_error});
            const version = version_field.as(.string, &json_error) catch errExit("{}", .{json_error});
            const language: Language = language_blk: {
                const language_field = pkg_obj.getOptionalField("language") orelse break :language_blk .neutral;
                const language = language_field.as(.string, &json_error) catch errExit("{}", .{json_error});
                const en_us = "en-US";
                if (std.mem.eql(u8, language, "neutral")) break :language_blk .neutral;
                if (std.mem.eql(u8, language, en_us)) break :language_blk .en_us;
                if (other_languages.get(language)) |_| break :language_blk .other;
                if (std.ascii.eqlIgnoreCase(language, en_us)) std.debug.panic("new {s} casing '{s}'", .{ en_us, language });
                std.debug.panic("unknown language '{s}'", .{language});
            };
            const payloads_offset = payload_count;
            if (pkg_obj.map.get("payloads")) |payloads_field_node| {
                const payloads_field: JsonContext.Field = .init(pkg_obj.parent_context, "payloads", payloads_field_node);
                const payloads = payloads_field.as(.array, &json_error) catch errExit("{}", .{json_error});
                payload_count += payloads.items.len;
            }
            out_packages[pkg_index] = .{
                .id = allocator.dupe(u8, id) catch |e| oom(e),
                // TODO: maybe we should have a string pool for versions?
                .version = allocator.dupe(u8, version) catch |e| oom(e),
                .language = language,
                .payloads_offset = payloads_offset,
            };
            out_package_count += 1;
        }

        for (extrapkgs.all) |pkg| {
            const id = identifyPackage(pkg.id);
            out_packages[out_package_count] = .{
                .id = allocator.dupe(u8, pkg.id) catch |e| oom(e),
                .version = allocator.dupe(u8, switch (id) {
                    .ninja => |version| version,
                    .cmake => |version| version,
                    else => unreachable,
                }) catch |e| oom(e),
                .language = .neutral,
                .payloads_offset = payload_count,
            };
            out_package_count += 1;
            payload_count += pkg.payloads.len;
        }

        std.debug.assert(out_package_count == out_packages.len);
        break :payload_count_blk payload_count;
    };

    const out_payloads = allocator.alloc(Payload, payload_count) catch |e| oom(e);
    var out_payload_count: usize = 0;
    errdefer {
        for (out_payloads[0..out_payload_count]) |out_payload| {
            out_payload.deinit(allocator);
        }
        allocator.free(out_payloads);
    }

    for (0..packages.items.len) |pkg_index| {
        std.debug.assert(out_packages[pkg_index].payloads_offset == out_payload_count);
        const pkg_obj_element = packages.getElement(&json_error, pkg_index) catch errExit("{}", .{json_error});
        const pkg_obj = pkg_obj_element.as(.object, &json_error) catch errExit("{}", .{json_error});
        if (pkg_obj.map.get("payloads")) |payloads_field_node| {
            const payloads_field: JsonContext.Field = .init(pkg_obj.parent_context, "payloads", payloads_field_node);
            const payloads = payloads_field.as(.array, &json_error) catch errExit("{}", .{json_error});
            // payload_count += payloads.items.len;
            for (0..payloads.items.len) |payload_index| {
                const payload_element = payloads.getElement(&json_error, payload_index) catch errExit("{}", .{json_error});
                const payload_object = payload_element.as(.object, &json_error) catch errExit("{}", .{json_error});
                const payload_json = PayloadJson.init(payload_object);
                out_payloads[out_payload_count] = .{
                    .url_decoded = allocUrlPercentDecoded(allocator, payload_json.url) catch |e| oom(e),
                    .sha256 = payload_json.sha256,
                    .file_name = allocator.dupe(u8, payload_json.fileName) catch |e| oom(e),
                };
                out_payload_count += 1;
            }
        }
    }
    for (extrapkgs.all) |pkg| {
        for (pkg.payloads) |p| {
            const filename = basenameFromUrl(p.url);
            std.debug.assert(filename.len > 0);
            out_payloads[out_payload_count] = .{
                .url_decoded = allocator.dupe(u8, p.url) catch |e| oom(e),
                .sha256 = Sha.parseHex(&p.sha256).?,
                .file_name = allocator.dupe(u8, filename) catch |e| oom(e),
            };
            out_payload_count += 1;
        }
    }
    std.debug.assert(out_payload_count == out_payloads.len);

    return .{
        .slice = out_packages,
        .payloads = out_payloads,
    };
}

fn isValidVersion(version: []const u8) bool {
    const scan_version = scanIdVersion(version, 0);
    return scan_version.end == version.len;
}

fn startsWith(comptime T: type, s: []const T, needle: []const T) ?[]const T {
    return if (std.mem.startsWith(T, s, needle)) s[needle.len..] else null;
}

fn getDefaultInstallDir() []const u8 {
    if (builtin.os.tag == .windows) {
        return "C:\\msvcup";
    }
    @panic("todo");
}

const ManifestUpdate = enum {
    off,
    daily,
    always,
};

fn dottedNumericLessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
    return orderDottedNumeric({}, lhs, rhs) == .lt;
}

fn orderDottedNumeric(_: void, lhs: []const u8, rhs: []const u8) std.math.Order {
    var lhs_it = std.mem.splitScalar(u8, lhs, '.');
    var rhs_it = std.mem.splitScalar(u8, rhs, '.');
    while (true) {
        const lhs_part = lhs_it.next() orelse {
            return if (rhs_it.next()) |_| .lt else return .eq;
        };
        const rhs_part = rhs_it.next() orelse return .gt;
        switch (orderNumeric({}, lhs_part, rhs_part)) {
            .gt, .lt => |order| return order,
            .eq => {},
        }
    }
}
test orderDottedNumeric {
    try std.testing.expectEqual(.eq, orderDottedNumeric({}, "0.1", "0.1"));
    try std.testing.expectEqual(.lt, orderDottedNumeric({}, "0", "0.1"));
    try std.testing.expectEqual(.gt, orderDottedNumeric({}, "0.1", "0"));
    try std.testing.expectEqual(.lt, orderDottedNumeric({}, "9", "10"));
}

fn orderDottedAlphabetical(_: void, lhs: []const u8, rhs: []const u8) std.math.Order {
    var lhs_it = std.mem.splitScalar(u8, lhs, '.');
    var rhs_it = std.mem.splitScalar(u8, rhs, '.');
    while (true) {
        const lhs_part = lhs_it.next() orelse {
            return if (rhs_it.next()) |_| .lt else return .eq;
        };
        const rhs_part = rhs_it.next() orelse return .gt;
        switch (orderAlphabetical({}, lhs_part, rhs_part)) {
            .gt, .lt => |order| return order,
            .eq => {},
        }
    }
}
test orderDottedAlphabetical {
    try std.testing.expectEqual(.eq, orderDottedAlphabetical({}, "a.b", "a.b"));
    try std.testing.expectEqual(.lt, orderDottedAlphabetical({}, "a", "a.b"));
    try std.testing.expectEqual(.gt, orderDottedAlphabetical({}, "a.b", "a"));
}

fn orderNumeric(_: void, lhs: []const u8, rhs: []const u8) std.math.Order {
    const lhs_int = std.fmt.parseInt(u64, lhs, 10) catch {
        return if (std.fmt.parseInt(u64, rhs, 10)) |_| .gt else |_| orderAlphabetical({}, lhs, rhs);
    };
    const rhs_int = std.fmt.parseInt(u64, rhs, 10) catch return .lt;
    return std.math.order(lhs_int, rhs_int);
}
test orderNumeric {
    try std.testing.expectEqual(.eq, orderNumeric({}, "0", "0"));
    try std.testing.expectEqual(.lt, orderNumeric({}, "0", "1"));
    try std.testing.expectEqual(.gt, orderNumeric({}, "1", "0"));
    try std.testing.expectEqual(.lt, orderNumeric({}, "9", "10"));
    try std.testing.expectEqual(.gt, orderNumeric({}, "10", "9"));
    try std.testing.expectEqual(.lt, orderNumeric({}, "0", "a"));
    try std.testing.expectEqual(.gt, orderNumeric({}, "a", "0"));
}

fn orderAlphabetical(_: void, lhs: []const u8, rhs: []const u8) std.math.Order {
    const n = @min(lhs.len, rhs.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        switch (std.math.order(lhs[i], rhs[i])) {
            .eq => continue,
            .lt => return .lt,
            .gt => return .gt,
        }
    }
    return std.math.order(lhs.len, rhs.len);
}

fn findSortedIndex(
    comptime T: type,
    list: *std.ArrayListUnmanaged(T),
    item: T,
    context: anytype,
    comptime orderFn: fn (@TypeOf(context), T, T) std.math.Order,
) union(enum) {
    already_inserted,
    not_inserted: usize,
} {
    var left: usize = 0;
    var right: usize = list.items.len;
    while (left < right) {
        const mid = left + (right - left) / 2;
        switch (orderFn(context, list.items[mid], item)) {
            .eq => return .already_inserted,
            .lt => left = mid + 1,
            .gt => right = mid,
        }
    }
    return .{ .not_inserted = left };
}
fn insertSorted(
    comptime T: type,
    allocator: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(T),
    item: T,
    context: anytype,
    comptime orderFn: fn (@TypeOf(context), T, T) std.math.Order,
) error{OutOfMemory}!void {
    switch (findSortedIndex(T, list, item, context, orderFn)) {
        .already_inserted => return,
        .not_inserted => |i| try list.insert(allocator, i, item),
    }
}

fn errExit(comptime fmt: []const u8, args: anytype) noreturn {
    log.err(fmt, args);
    std.process.exit(0xff);
}
fn oom(e: error{OutOfMemory}) noreturn {
    @panic(@errorName(e));
}

const builtin = @import("builtin");
const std = @import("std");
const extrapkgs = @import("extrapkgs");
const ChannelKind = @import("channelkind.zig").ChannelKind;
const Arch = @import("arch.zig").Arch;
const Arches = @import("arch.zig").Arches;
const extra = @import("extra.zig");
const LockFile = @import("LockFile.zig");
const JsonContext = @import("JsonContext.zig");
const StringPool = @import("StringPool.zig");
const zip = @import("zip.zig");
