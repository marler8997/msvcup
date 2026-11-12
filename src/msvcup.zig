// TODO: maybe  manifests file should go in the cache directory?
//       maybe the packages should go in a subdirectory of the cache?
const log = std.log.scoped(.msvcup);

const global = struct {
    var string_pool: StringPool = undefined;
};

pub const panic = if (builtin.os.tag == .windows) wintrace.panic else std.debug.FullPanic(std.debug.defaultPanic);
pub const wintrace_options: wintrace.Options = .{ .mode = .symbolize };
pub const std_options: std.Options = .{ .enable_segfault_handler = builtin.os.tag != .windows };

pub fn main(init: std.process.Init.Minimal) !u8 {
    if (builtin.os.tag == .windows) {
        if (wintrace.SetUnhandledExceptionFilter(&wintrace.unhandledExceptionFilter) != null) unreachable;
        var guarantee: u32 = wintrace.stack_guarantee;
        if (wintrace.SetThreadStackGuarantee(&guarantee) == 0) std.debug.panic(
            "SetThreadStackGuarantee failed, error={d}",
            .{std.os.windows.GetLastError()},
        );
    }
    return run(init) catch |err| {
        if (builtin.os.tag == .windows) wintrace.exitWithErrorTrace(err, @errorReturnTrace());
        return err;
    };
}

fn run(init: std.process.Init.Minimal) !u8 {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_instance.allocator();
    global.string_pool = .init(arena);
    const environ = init.environ;
    var threaded: std.Io.Threaded = .init(arena, .{ .environ = environ, .argv0 = .init(init.args) });
    defer threaded.deinit();
    const io = threaded.io();

    if (builtin.os.tag == .windows) {
        // std.log, errExit and panics write through this writer, see withIoMode
        std.debug.lockStderr(&.{}).file_writer.file = stderrFile();
        std.debug.unlockStderr();
    }

    const all_args: [][]const u8 = blk: {
        const args_array = try init.args.toSlice(arena);
        const all_args = try arena.alloc([]const u8, args_array.len -| 1);
        for (all_args, args_array[@min(1, args_array.len)..]) |*dst, src| dst.* = src;
        break :blk all_args;
    };

    const cmd, const args = cmd_args_blk: {
        const cmd_arg_index: usize = cmd_arg_index_blk: {
            var arg_index: usize = 0;
            while (true) : (arg_index += 1) {
                if (arg_index == all_args.len) try usage(io, environ, arena);
                const arg = all_args[arg_index];
                if (isHelpArg(arg)) return help(io, environ, arena, for (all_args[arg_index + 1 ..]) |a| {
                    if (!std.mem.startsWith(u8, a, "-")) break a;
                } else null);
                if (!std.mem.startsWith(u8, arg, "-")) break :cmd_arg_index_blk arg_index;
                errExit("TODO: add support for specifying options before command", .{});
            }
        };
        const cmd = all_args[cmd_arg_index];
        for (cmd_arg_index + 1..all_args.len) |i| {
            if (isHelpArg(all_args[i])) return help(io, environ, arena, cmd);
            all_args[i - 1] = all_args[i];
        }
        break :cmd_args_blk .{ cmd, all_args[0 .. all_args.len - 1] };
    };
    if (std.mem.eql(u8, cmd, "install")) return install(io, environ, arena, args);
    if (std.mem.eql(u8, cmd, "list")) return listCommand(io, environ, arena, args);
    if (std.mem.eql(u8, cmd, "list-channels")) return listChannels(io, args);
    if (std.mem.eql(u8, cmd, "list-payloads")) return listPayloads(io, environ, arena, args);
    if (std.mem.eql(u8, cmd, "msi")) return msiCommand(io, arena, args);
    if (std.mem.eql(u8, cmd, "fetch")) return fetchCommand(io, environ, arena, args);
    log.err("unknown command '{s}'", .{cmd});
    return 0xff;
}

fn usage(io: std.Io, environ: std.process.Environ, arena: std.mem.Allocator) !noreturn {
    const msvcup_dir: MsvcupDir = try .alloc(environ, arena);
    var stderr_buf: [1000]u8 = undefined;
    var stderr = stderrFile().writerStreaming(io, &stderr_buf);
    writeUsage(&stderr.interface, msvcup_dir) catch return stderr.err.?;
    std.process.exit(0xff);
}

fn isHelpArg(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help");
}

/// Called when a help option appears anywhere in the args. Prints the detailed
/// help for the command if there is one and it has detailed help, otherwise
/// the main usage.
fn help(io: std.Io, environ: std.process.Environ, arena: std.mem.Allocator, cmd: ?[]const u8) !u8 {
    const detailed: ?[]const u8 = if (cmd) |c|
        (if (std.mem.eql(u8, c, "list-payloads")) list_payloads_help else null)
    else
        null;
    var stdout_buf: [1000]u8 = undefined;
    var stdout = stdoutFile().writerStreaming(io, &stdout_buf);
    if (detailed) |text| {
        stdout.interface.writeAll(text) catch return stdout.err.?;
        stdout.interface.flush() catch return stdout.err.?;
    } else {
        const msvcup_dir: MsvcupDir = try .alloc(environ, arena);
        writeUsage(&stdout.interface, msvcup_dir) catch return stdout.err.?;
    }
    return 0;
}

fn writeUsage(w: *std.Io.Writer, msvcup_dir: MsvcupDir) error{WriteFailed}!void {
    try w.print(
        \\msvcup version {[version]s}
        \\
        \\Usage: msvcup COMMAND ARGS...
        \\
        \\Commands:
        \\--------------------------------------------------------------------------------
        \\
        \\  list [--channel CHANNEL]  | List all PKGS.
        \\  list-channels             | List the known channels with their URLs.
        \\  install DIR PKGS...       | Install the given PKGS to the given DIR. PKGS are
        \\                            | are of the form:
        \\                            |
        \\                            |      <PKG_NAME>-<VERSION>
        \\                            |
        \\                            | installed to {[install_dir]s}.
        \\  list-payloads [--channel CHANNEL]
        \\                            | List all payloads and their msvcup package.
        \\  msi MSI DIR               | Invoke builtin msi installer.
        \\
        \\InstallOptions:
        \\--------------------------------------------------------------------------------
        \\  --channel CHANNEL         | Where to find packages. Microsoft publishes the
        \\                            | packages of each Visual Studio version in a
        \\                            | channel. CHANNEL is a name from list-channels or
        \\                            | an https URL, of a channel or of a channel manifest
        \\                            | (.chman). Not used when the lock file already has
        \\                            | the packages being installed.
        \\                            | default: {[channel]s}
        \\  --lock-file PATH          | A manifest to hold all payloads/urls installed.
        \\  --manifest-update-<OPT>   | Controls whether to update to the latest manifest
        \\                            | if it's already been downloaded. This option will
        \\                            | control whether it's updated to the latest, OPT
        \\                            | can be set to "off", "daily", or "always".
        \\  --msiexec                 | use msiexec.exe rather than builtin msi installer
        \\
    ,
        .{
            .version = @embedFile("version"),
            .install_dir = msvcup_dir.root_path,
            .channel = Channel.default.asArg(),
        },
    );
    try w.flush();
}

const MsvcupDir = struct {
    root_path: []const u8,
    /// The same directories std.fs.getAppDataDir gave before zig removed it.
    pub fn alloc(environ: std.process.Environ, allocator: std.mem.Allocator) !MsvcupDir {
        const join = std.fs.path.join;
        switch (builtin.os.tag) {
            .windows => {
                const local_app_data = getEnv(environ, allocator, "LOCALAPPDATA") orelse errExit(
                    "can't find msvcup's data directory, LOCALAPPDATA is not set",
                    .{},
                );
                return .{ .root_path = try join(allocator, &.{ local_app_data, "msvcup" }) };
            },
            .macos => {
                const home = getEnv(environ, allocator, "HOME") orelse errExit(
                    "can't find msvcup's data directory, HOME is not set",
                    .{},
                );
                return .{ .root_path = try join(allocator, &.{ home, "Library", "Application Support", "msvcup" }) };
            },
            else => {
                if (getEnv(environ, allocator, "XDG_DATA_HOME")) |xdg| return .{
                    .root_path = try join(allocator, &.{ xdg, "msvcup" }),
                };
                const home = getEnv(environ, allocator, "HOME") orelse errExit(
                    "can't find msvcup's data directory, neither XDG_DATA_HOME nor HOME is set",
                    .{},
                );
                return .{ .root_path = try join(allocator, &.{ home, ".local", "share", "msvcup" }) };
            },
        }
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

fn listCommand(io: std.Io, environ: std.process.Environ, arena: std.mem.Allocator, args: []const []const u8) !u8 {
    // TODO: accept the "--manifest-update-*" arguments
    var channel = Channel.default;
    {
        var arg_index: usize = 0;
        while (arg_index < args.len) : (arg_index += 1) {
            const arg = args[arg_index];
            if (std.mem.eql(u8, arg, "--channel")) {
                arg_index += 1;
                if (arg_index == args.len) errExit("--channel missing argument", .{});
                channel = parseChannel(args[arg_index]);
            } else errExit("list: unknown argument '{s}'", .{arg});
        }
    }

    const recipes = parseBuiltinRecipes(arena);

    const root_node = std.Progress.start(io, .{ .root_name = "msvcup list-versions" });
    defer root_node.end();

    var scratch_instance: ScratchAllocator = .init();
    const scratch = scratch_instance.allocator();

    const msvcup_dir: MsvcupDir = try .alloc(environ, arena);

    const vsman = try readVsManifestLocking(io, environ, arena, root_node, scratch, msvcup_dir, channel, .off);
    defer vsman.freeConst(arena);
    scratch_instance.reset();

    const pkgs = try getPackages(arena, scratch, vsman);
    // defer arena.free(pkgs);
    scratch_instance.reset();

    var msvcup_pkgs: std.ArrayList(MsvcupPackage) = .empty;
    for (pkgs.slice, 0..) |*pkg, pkg_index| {
        for (pkgs.payloadsFromPkgIndex(.fromInt(pkg_index))) |*payload| {
            const owner = recipeOwner(&recipes, pkg, payload) orelse continue;
            const msvcup_pkg: MsvcupPackage = .initStr(owner.rule.package, owner.package_version);
            insertSorted(MsvcupPackage, arena, &msvcup_pkgs, msvcup_pkg, {}, MsvcupPackage.order) catch |e| oom(e);
        }
    }

    var stdout_buf: [2000]u8 = undefined;
    var stdout = stdoutFile().writerStreaming(io, &stdout_buf);
    const w = &stdout.interface;
    w.writeAll("autoenv\n") catch return stdout.err.?;
    for (msvcup_pkgs.items) |msvcup_pkg| {
        w.print("{f}\n", .{msvcup_pkg}) catch return stdout.err.?;
    }
    w.flush() catch return stdout.err.?;
    return 0;
}

fn parseChannel(arg: []const u8) Channel {
    const channel = Channel.fromArg(arg) orelse errExit(
        "unknown channel '{s}', 'msvcup list-channels' shows the known channels, a URL must start with https://",
        .{arg},
    );
    const uri = std.Uri.parse(channel.httpsUrl()) catch |e| errExit(
        "invalid channel URL '{s}': {s}",
        .{ channel.httpsUrl(), @errorName(e) },
    );
    const host_len: usize = if (uri.host) |host| switch (host) {
        inline else => |h| h.len,
    } else 0;
    if (host_len == 0) errExit("channel URL '{s}' has no host", .{channel.httpsUrl()});
    return channel;
}

fn listChannels(io: std.Io, args: []const []const u8) !u8 {
    if (args.len != 0) errExit("list-channels: unknown argument '{s}'", .{args[0]});
    var stdout_buf: [1000]u8 = undefined;
    var stdout = stdoutFile().writerStreaming(io, &stdout_buf);
    const w = &stdout.interface;
    for (Channel.known) |channel| {
        w.print("{s: <16}{s}\n", .{ channel.asArg(), channel.httpsUrl() }) catch return stdout.err.?;
    }
    w.flush() catch return stdout.err.?;
    return 0;
}

const list_payloads_help =
    \\Usage: msvcup list-payloads [--channel CHANNEL]
    \\
    \\Lists every payload in the Visual Studio manifest (plus msvcup's builtin
    \\extra packages) along with the msvcup package that owns it, one payload
    \\per line, sorted by package id and then by the name in the payload url.
    \\
    \\Line format:
    \\
    \\    OWNER ATTRIBUTE...
    \\
    \\  OWNER      The msvcup package the payload belongs to (e.g. msvc-14.44.17.14),
    \\             or '-' if msvcup doesn't select it directly. A '-' payload can
    \\             still be installed, the .cab files of a selected .msi are found
    \\             by scanning the .msi at install time. A payload belongs to at
    \\             most one msvcup package.
    \\  ATTRIBUTE  NAME=VALUE pairs describing the payload, in this order:
    \\
    \\               channel   where the payload comes from, i.e. vs17-release,
    \\                         or 'extra' for msvcup's builtin packages (ninja/cmake)
    \\               lang      the package language (e.g. neutral, en-US, de-DE)
    \\               id        the package id
    \\               version   the package version
    \\               fileName  the payload file name
    \\
    \\             If a NAME=VALUE pair contains whitespace, the entire pair is
    \\             wrapped in double quotes, i.e. "fileName=Installers\Some File.msi".
    \\
    \\Columns are separated by one or more spaces (OWNER is padded for
    \\readability). The output is meant to be diffed, e.g. to see how a change to
    \\payload selection affects which payloads are installed.
    \\
    \\CHANNEL is a name shown by list-channels or an https URL.
    \\
    \\Example:
    \\
    \\  sdk-10.0.22621.7     channel=vs17-release lang=neutral id=Win11SDK_10.0.22621 version=10.0.22621.7 "fileName=Installers\Windows SDK Desktop Headers x64-x86_en-us.msi"
    \\
;

fn listPayloads(io: std.Io, environ: std.process.Environ, arena: std.mem.Allocator, args: []const []const u8) !u8 {
    var channel = Channel.default;
    {
        var arg_index: usize = 0;
        while (arg_index < args.len) : (arg_index += 1) {
            const arg = args[arg_index];
            if (std.mem.eql(u8, arg, "--channel")) {
                arg_index += 1;
                if (arg_index == args.len) errExit("--channel missing argument", .{});
                channel = parseChannel(args[arg_index]);
            } else errExit("list-payloads: unknown argument '{s}'", .{arg});
        }
    }

    const recipes = parseBuiltinRecipes(arena);

    const root_node = std.Progress.start(io, .{ .root_name = "msvcup list-payloads" });
    defer root_node.end();

    var scratch_instance: ScratchAllocator = .init();
    const scratch = scratch_instance.allocator();

    const msvcup_dir: MsvcupDir = try .alloc(environ, arena);

    const vsman = try readVsManifestLocking(io, environ, arena, root_node, scratch, msvcup_dir, channel, .off);
    defer vsman.freeConst(arena);
    scratch_instance.reset();

    const pkgs = try getPackages(arena, scratch, vsman);
    // defer arena.free(pkgs);
    scratch_instance.reset();

    // Every payload in the manifest, sorted by package id and then by payload, so
    // the output is stable and diffable across changes to the selection logic.
    const sorted = arena.alloc(PayloadIndex, pkgs.payloads.len) catch |e| oom(e);
    for (sorted, 0..) |*p, i| p.* = .fromInt(i);
    std.sort.pdq(PayloadIndex, sorted, &pkgs, PayloadListingOrder.lessThan);

    var stdout_buf: [4096]u8 = undefined;
    var stdout = stdoutFile().writerStreaming(io, &stdout_buf);
    const w = &stdout.interface;
    for (sorted) |payload_index| {
        const pkg = &pkgs.slice[pkgs.pkgIndexFromPayloadIndex(payload_index).int()];
        const payload = &pkgs.payloads[payload_index.int()];
        const owner: []const u8 = if (recipeOwner(&recipes, pkg, payload)) |o|
            MsvcupPackage.initStr(o.rule.package, o.package_version).poolString().slice
        else
            "-";
        writePayloadListing(w, owner, switch (pkg.source) {
            .manifest => channel.asArg(),
            .extra => "extra",
        }, pkg, payload) catch return stdout.err.?;
    }
    w.flush() catch return stdout.err.?;
    return 0;
}

fn writePayloadListing(
    w: *std.Io.Writer,
    owner: []const u8,
    channel_arg: []const u8,
    pkg: *const Package,
    payload: *const Payload,
) error{WriteFailed}!void {
    try w.print("{s: <20}", .{owner});
    try writeListingAttr(w, "channel", channel_arg, pkg, payload);
    try writeListingAttr(w, "lang", pkg.language.name(), pkg, payload);
    try writeListingAttr(w, "id", pkg.id, pkg, payload);
    try writeListingAttr(w, "version", pkg.version, pkg, payload);
    try writeListingAttr(w, "fileName", payload.file_name, pkg, payload);
    try w.writeByte('\n');
}

fn writeListingAttr(
    w: *std.Io.Writer,
    name: []const u8,
    value: []const u8,
    pkg: *const Package,
    payload: *const Payload,
) error{WriteFailed}!void {
    // we don't support escaping, so fail loudly if a value ever needs it
    if (std.mem.indexOfAny(u8, value, "\"\r\n")) |_| std.debug.panic(
        "package '{s}' payload '{s}' has a {s} value that contains a quote or newline: '{s}'",
        .{ pkg.id, payload.file_name, name, value },
    );
    const quote: []const u8 = if (std.mem.indexOfAny(u8, value, " \t")) |_| "\"" else "";
    try w.print(" {s}{s}={s}{s}", .{ quote, name, value, quote });
}

const PayloadListingOrder = struct {
    fn lessThan(pkgs: *const Packages, lhs: PayloadIndex, rhs: PayloadIndex) bool {
        const lhs_pkg = &pkgs.slice[pkgs.pkgIndexFromPayloadIndex(lhs).int()];
        const rhs_pkg = &pkgs.slice[pkgs.pkgIndexFromPayloadIndex(rhs).int()];
        switch (orderDottedAlphabetical({}, lhs_pkg.id, rhs_pkg.id)) {
            .lt => return true,
            .gt => return false,
            .eq => {},
        }
        return PayloadIndex.order(pkgs.payloads, lhs, rhs) == .lt;
    }
};

// TODO: expose this documentation in a follow-up when we expose the ability to
//       read/add recipes
//
// Recipes select which manifest payloads belong to which msvcup package.
//
// Each rule is one line, an owner followed by predicates that must all match:
//
//     OWNER NAME=PATTERN...
//
// OWNER is PACKAGE-VERSION where VERSION is either a literal or {version}, which
// takes the value captured by the {version} in one of the patterns. NAME is one of
// the attributes shown by "msvcup list-payloads": id, version or fileName. A
// NAME=PATTERN containing whitespace is wrapped in double quotes.
//
// Patterns must match the whole value and are case sensitive, except for:
//
//     *          any characters, including none, only at the end of a pattern
//     {version}  digits separated by dots, i.e. 14.44.17.14
//     {arch}     x64, x86, arm or arm64, in any case
//
// Placeholders consume as much as they can, there's no backtracking. So a.{version}.*
// matches a.14.44.Tools but not a.14.44.17, where {version} takes all of 14.44.17, and
// {arch}* matches x64.foo but not x64foo.
//
// Lines starting with # are comments.
//
// Only payloads of neutral and en-US packages can match. A payload can belong to at
// most one msvcup package, it's an error if more than one rule matches it.
fn parseBuiltinRecipes(arena: std.mem.Allocator) Recipes {
    var diagnostic: Recipes.Diagnostic = .{};
    return Recipes.parse(arena, @embedFile("recipes.txt"), &diagnostic) catch |err| switch (err) {
        error.OutOfMemory => |e| oom(e),
        error.InvalidRecipes => std.debug.panic(
            "builtin recipes.txt:{}: {s}",
            .{ diagnostic.line, diagnostic.message },
        ),
    };
}

/// Returns the msvcup package that the given payload belongs to, if any. A
/// payload can belong to at most one msvcup package.
fn recipeOwner(recipes: *const Recipes, pkg: *const Package, payload: *const Payload) ?Recipes.Match.One {
    switch (pkg.language) {
        .neutral, .en_us => {},
        .other => return null,
    }
    return switch (recipes.match(.{
        .id = pkg.id,
        .version = pkg.version,
        .file_name = payload.file_name,
    })) {
        .none => null,
        .one => |one| one,
        .multiple => |rules| std.debug.panic(
            "payload '{s}' of package '{s}' matches multiple rules, recipes.txt lines {} and {}",
            .{ payload.file_name, pkg.id, rules[0].line, rules[1].line },
        ),
    };
}

fn msiCommand(io: std.Io, arena: std.mem.Allocator, args: []const []const u8) !u8 {
    const root_node = std.Progress.start(io, .{ .root_name = "msvcup msi" });
    defer root_node.end();

    const msi_path, const install_path = blk: {
        var maybe_msi_path: ?[]const u8 = null;
        var maybe_install_path: ?[]const u8 = null;

        var arg_index: usize = 0;
        while (arg_index < args.len) : (arg_index += 1) {
            const arg = args[arg_index];
            if (!std.mem.startsWith(u8, arg, "-")) {
                if (maybe_msi_path == null) {
                    maybe_msi_path = arg;
                } else if (maybe_install_path == null) {
                    maybe_install_path = arg;
                } else errExit("too many cmdline args, expected only MSI_FILE and INSTALL_DIR", .{});
            } else errExit("unknown cmdline argument '{s}'", .{arg});
        }
        break :blk .{
            maybe_msi_path orelse errExit("missing cmdline args MSI_FILE and INSTALL_DIR", .{}),
            maybe_install_path orelse errExit("missing cmdline arg INSTALL_DIR", .{}),
        };
    };

    const msi_content = blk: {
        const file = std.Io.Dir.cwd().openFile(io, msi_path, .{}) catch |err| errExit(
            "open '{s}' failed with {s}",
            .{ msi_path, @errorName(err) },
        );
        defer file.close(io);
        break :blk try readToEndAlloc(io, file, arena);
    };
    // defer arena.free(msi_content);
    try @import("msi").install(io, arena, .{
        .cabs_dir = std.fs.path.dirname(msi_path) orelse ".",
        .msi_content = msi_content,
        .install_path = install_path,
    });
    return 0;
}

fn fetchCommand(io: std.Io, environ: std.process.Environ, arena: std.mem.Allocator, args: []const []const u8) !u8 {
    const root_node = std.Progress.start(io, .{ .root_name = "msvcup fetch" });
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

    const msvcup_dir: MsvcupDir = try .alloc(environ, arena);

    const cache_dir: []const u8 = config.cache_dir orelse msvcup_dir.path(
        arena,
        &.{"cache"},
    ) catch |e| oom(e);

    var scratch_instance: ScratchAllocator = .init();
    const scratch = scratch_instance.allocator();

    {
        // we don't know the hash so there's no name for this download to have until it's done
        const fetch_path = std.fs.path.join(scratch, &.{ cache_dir, "nohash" }) catch |e| oom(e);
        defer scratch.free(fetch_path);
        var atomic_file = (try AtomicFile.lock(io, fetch_path, null)).locked;
        defer atomic_file.deinit(io);

        const sha256 = try fetch(io, environ, root_node, scratch, uri, atomic_file.file, .{});
        try finishCacheFetch(io, scratch, cache_dir, config.url, sha256, &atomic_file);
        var stdout_buf: [80]u8 = undefined;
        var stdout = stdoutFile().writerStreaming(io, &stdout_buf);
        stdout.interface.print("{f}\n", .{sha256}) catch return stdout.err.?;
        stdout.interface.flush() catch return stdout.err.?;
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
    pub fn format(value: Sha, writer: *std.Io.Writer) error{WriteFailed}!void {
        try writer.print("{x}", .{&value.bytes});
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
    io: std.Io,
    scratch: std.mem.Allocator,
    cache_dir: []const u8,
    url: []const u8,
    sha256: Sha,
    atomic_file: *AtomicFile,
) !void {
    const entry = CacheEntry.alloc(scratch, scratch, cache_dir, sha256, basenameFromUrl(url));
    defer entry.free(scratch);
    const already_exists = if (std.Io.Dir.cwd().access(io, entry.path, .{})) true else |err| switch (err) {
        error.FileNotFound => false,
        else => |e| return e,
    };
    if (already_exists) {
        // the caller's deinit deletes the temporary file
        std.log.info("{s}: already exists", .{entry.path});
    } else {
        std.log.info("{s}: newly fetched", .{entry.path});
        try atomic_file.finish(io, entry.path);
    }
}

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
        const name = std.fmt.bufPrint(&buf, "{f}", .{self}) catch @panic("version too long");
        return global.string_pool.add(name) catch |e| oom(e);
    }
    pub fn order(_: void, lhs: MsvcupPackage, rhs: MsvcupPackage) std.math.Order {
        return switch (MsvcupPackageKind.order({}, lhs.kind, rhs.kind)) {
            .lt, .gt => |o| o,
            .eq => orderDottedNumeric({}, lhs.version.slice, rhs.version.slice),
        };
    }
    pub fn format(self: MsvcupPackage, writer: *std.Io.Writer) error{WriteFailed}!void {
        try writer.print("{t}-{s}", .{ self.kind, self.version.slice });
    }
};

fn defaultLockFile(allocator: std.mem.Allocator, install_dir: []const u8) error{OutOfMemory}![]const u8 {
    const dir = std.mem.trimEnd(u8, install_dir, "\\/");
    return try std.fmt.allocPrint(allocator, "{s}.lock", .{dir});
}

fn install(io: std.Io, environ: std.process.Environ, arena: std.mem.Allocator, args: []const []const u8) !u8 {
    const Config = struct {
        install_dir: []const u8,
        autoenv: bool,
        msvcup_pkgs: []const MsvcupPackage,
        lock_file: []const u8,
        manifest_update: ManifestUpdate,
        channel: Channel,
        cache_dir: ?[]const u8,
        msiexec: bool = false,
    };
    const config: Config = blk_config: {
        var maybe_install_dir: ?[]const u8 = null;
        var autoenv: bool = false;
        var msvcup_pkgs: std.ArrayList(MsvcupPackage) = .empty;
        var maybe_lock_file: ?[]const u8 = null;
        var maybe_manifest_update: ?ManifestUpdate = null;
        var channel = Channel.default;
        var cache_dir: ?[]const u8 = null;
        var msiexec: bool = false;

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
            } else if (std.mem.eql(u8, arg, "--channel")) {
                arg_index += 1;
                if (arg_index == args.len) errExit("--channel missing argument", .{});
                channel = parseChannel(args[arg_index]);
            } else if (std.mem.eql(u8, arg, "--cache-dir")) {
                arg_index += 1;
                if (arg_index == args.len) errExit("--cache-dir missing argument", .{});
                cache_dir = args[arg_index];
            } else if (std.mem.eql(u8, arg, "--msiexec")) {
                msiexec = true;
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
            .channel = channel,
            .cache_dir = cache_dir,
            .msiexec = msiexec,
        };
    };

    const msvcup_dir: MsvcupDir = try .alloc(environ, arena);

    if (config.msvcup_pkgs.len == 0) errExit(
        "no packages were given to install, use 'list' to list the available packages",
        .{},
    );

    const cache_dir: []const u8 = config.cache_dir orelse msvcup_dir.path(
        arena,
        &.{"cache"},
    ) catch |e| oom(e);

    const root_node = std.Progress.start(io, .{ .root_name = "msvcup install" });
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
            if (std.Io.Dir.cwd().openFile(io, config.lock_file, .{})) |lock_file| {
                defer lock_file.close(io);
                log.info("lock file found: '{s}'", .{config.lock_file});
                break :blk try readToEndAlloc(io, lock_file, arena);
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
                std.log.info("{f}", .{mismatch});
            } else {
                const result = try installFromLockFileLocking(
                    io,
                    environ,
                    scratch,
                    root_node,
                    config.install_dir,
                    cache_dir,
                    config.lock_file,
                    content,
                    .{ .msiexec = config.msiexec },
                );
                scratch_instance.reset();
                switch (result) {
                    .success => return 0,
                    .version_mismatch => {},
                }
            }
        }
    }

    const recipes = parseBuiltinRecipes(arena);

    const vsman = try readVsManifestLocking(io, environ, arena, root_node, scratch, msvcup_dir, config.channel, .off);
    defer vsman.freeConst(arena);
    scratch_instance.reset();

    const pkgs = try getPackages(arena, scratch, vsman);
    // defer arena.free(pkgs);
    scratch_instance.reset();

    try updateLockFileLocking(
        io,
        environ,
        scratch,
        root_node,
        &recipes,
        config.channel,
        config.autoenv,
        config.msvcup_pkgs,
        config.lock_file,
        pkgs,
        cache_dir,
    );
    scratch_instance.reset();

    const lock_file_content = blk: {
        const lock_file = std.Io.Dir.cwd().openFile(io, config.lock_file, .{}) catch |e| std.debug.panic(
            "failed to open lock file '{s}' with {s} just after updating it",
            .{ config.lock_file, @errorName(e) },
        );
        defer lock_file.close(io);
        break :blk try readToEndAlloc(io, lock_file, arena);
    };

    if (checkLockFilePkgs(
        config.lock_file,
        lock_file_content,
        config.autoenv,
        config.msvcup_pkgs,
    )) |mismatch| errExit(
        "lock file '{s}' still doesn't match what we're installing even after it's been updated: {f}",
        .{ config.lock_file, mismatch },
    );
    switch (try installFromLockFileLocking(
        io,
        environ,
        scratch,
        root_node,
        config.install_dir,
        cache_dir,
        config.lock_file,
        lock_file_content,
        .{ .msiexec = config.msiexec },
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
    io: std.Io,
    scratch: std.mem.Allocator,
    install_path: []const u8,
    unique_pkgs: *const UniquePackages,
    install_versions: *const InstallVersions,
) !void {
    const autoenv_path = try std.fs.path.join(scratch, &.{ install_path, "autoenv" });
    defer scratch.free(autoenv_path);

    if (!unique_pkgs.autoenv) {
        try deleteTree(io, std.Io.Dir.cwd(), autoenv_path);
        return;
    }

    const install_path_absolute: AbsolutePath = try .init(io, scratch, install_path);
    defer install_path_absolute.deinit(scratch);

    var autoenv_dir = try std.Io.Dir.cwd().createDirPathOpen(io, autoenv_path, .{});
    defer autoenv_dir.close(io);
    inline for (comptime std.enums.values(Arch)) |target_cpu| {
        var autoenv_arch_dir = try autoenv_dir.createDirPathOpen(io, @tagName(target_cpu), .{});
        defer autoenv_arch_dir.close(io);
        try installAutoenvArch(
            io,
            scratch,
            &install_path_absolute,
            unique_pkgs,
            install_versions,
            target_cpu,
            autoenv_arch_dir,
        );
    }
}

const InstallVersions = struct {
    msvc: ?[]const u8,
    sdk: ?[]const u8,
};

fn installAutoenvArch(
    io: std.Io,
    scratch: std.mem.Allocator,
    install_path: *const AbsolutePath,
    unique_pkgs: *const UniquePackages,
    install_versions: *const InstallVersions,
    target_cpu: Arch,
    out_dir: std.Io.Dir,
) !void {
    {
        var content_buf: [100]u8 = undefined;
        const content = try std.fmt.bufPrint(&content_buf, "..\\..\\vcvars-{s}.bat\n", .{@tagName(target_cpu)});
        try updateFile(io, out_dir, "env", content);
    }

    if (unique_pkgs.msvc) |_| {
        inline for (msvc_tools) |tool| {
            try updateFile(io, out_dir, tool.name ++ ".exe", @embedFile("autoenv_exe"));
        }
    }
    if (unique_pkgs.sdk) |_| {
        inline for (sdk_tools) |tool| {
            try updateFile(io, out_dir, tool.name ++ ".exe", @embedFile("autoenv_exe"));
        }
    }

    // cleanup this file from an old version of msvcup
    out_dir.deleteFile(io, "toolchain.cmake") catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    };

    {
        const cmake = generateToolchainCmake(scratch, unique_pkgs, target_cpu, .native) catch |e| oom(e);
        defer scratch.free(cmake);
        try updateFile(io, out_dir, "toolchain-native.cmake", cmake);
    }

    {
        const cmake = generateToolchainCmake(scratch, unique_pkgs, target_cpu, .cross) catch |e| oom(e);
        defer scratch.free(cmake);
        try updateFile(io, out_dir, "toolchain-cross.cmake", cmake);
    }

    {
        const libc_txt = generateLibcTxt(scratch, install_path, install_versions, target_cpu) catch |e| oom(e);
        defer scratch.free(libc_txt);
        try updateFile(io, out_dir, "libc.txt", libc_txt);
    }
}

fn updateFile(io: std.Io, dir: std.Io.Dir, sub_path: []const u8, content: []const u8) !void {
    const needs_update = !try fileMatches(io, dir, sub_path, content);
    {
        const status: []const u8 = if (needs_update) "updating..." else "already up-to-date";
        std.log.info("{s}: {s}", .{ sub_path, status });
    }
    if (needs_update) {
        var file = try dir.createFile(io, sub_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, content);
    }
}

const LockFileMismatch = union(enum) {
    msvc: struct { requested: []const u8, lockfile: []const u8 },
    autoenv: bool, // lockfile value
    missing_pkg: MsvcupPackage,
    extra_pkg: MsvcupPackage,

    pub fn format(self: LockFileMismatch, writer: *std.Io.Writer) error{WriteFailed}!void {
        switch (self) {
            .msvc => |v| try writer.print(
                "lock file is for msvc version '{s}' but '{s}' was requested",
                .{ v.lockfile, v.requested },
            ),
            .autoenv => |lockfile_value| try writer.print(
                "lock file {s} autoenv",
                .{@as([]const u8, if (lockfile_value) "has" else "does not have")},
            ),
            .missing_pkg => |pkg| try writer.print("lock file is missing package '{f}'", .{pkg}),
            .extra_pkg => |pkg| try writer.print("lock file has extra package '{f}' that was not given on cmdline", .{pkg}),
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
                "{s}:{}: cab payloads should not have an associated msvcup package ('{f}' in this case)",
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

fn installFromLockFileLocking(
    io: std.Io,
    environ: std.process.Environ,
    scratch: std.mem.Allocator,
    progress_node: std.Progress.Node,
    install_path: []const u8,
    cache_dir: []const u8,
    lock_file_path: []const u8,
    lock_file_content: []const u8,
    named: struct { msiexec: bool },
) !enum { success, version_mismatch } {
    globalfilelocks.enteredLockingFunction(@src().fn_name);

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

                try installPayloadLocking(
                    io,
                    environ,
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
                    .{ .msiexec = named.msiexec },
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

    const install_versions: InstallVersions = .{
        .msvc = if (unique_pkgs.msvc != null) try queryInstallVersion(io, scratch, scratch, .msvc, install_path) else null,
        .sdk = if (unique_pkgs.sdk != null) try queryInstallVersion(io, scratch, scratch, .sdk, install_path) else null,
    };
    if (install_versions.msvc) |v| std.log.info("MSVC install version '{s}'", .{v});
    if (install_versions.sdk) |v| std.log.info("SDK  install version '{s}'", .{v});

    try updateVcvars(io, scratch, install_path, &install_versions);
    try updateAutoenv(io, scratch, install_path, &unique_pkgs, &install_versions);

    return .success;
}

fn updateVcvars(
    io: std.Io,
    scratch: std.mem.Allocator,
    install_path: []const u8,
    install_versions: *const InstallVersions,
) !void {
    var install_dir = try std.Io.Dir.cwd().createDirPathOpen(io, install_path, .{});
    defer install_dir.close(io);
    inline for (comptime std.enums.values(Arch)) |arch| {
        const env_bat = generateVcvarsBat(scratch, install_versions, arch) catch |e| oom(e);
        defer scratch.free(env_bat);
        const env_basename = std.fmt.allocPrint(scratch, "vcvars-{s}.bat", .{@tagName(arch)}) catch |e| oom(e);
        defer scratch.free(env_basename);
        try updateFile(io, install_dir, env_basename, env_bat);
    }
}

// The actual directory version can and does differ from both the
// package id build version and the package version itself, so, we just
// have to go in and look at the directory that was actually created to
// get the "install version".
fn queryInstallVersion(
    io: std.Io,
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
    var query_dir = std.Io.Dir.cwd().openDir(io, query_path, .{ .iterate = true }) catch |e| std.debug.panic(
        "open directory '{s}' failed with {s}",
        .{ query_path, @errorName(e) },
    );
    defer query_dir.close(io);
    var version_entry: ?[]u8 = null;
    var it = query_dir.iterate();
    while (try it.next(io)) |entry| {
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
    install_versions: *const InstallVersions,
    target_arch: Arch,
) error{OutOfMemory}![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    // running out of memory is the only way writing to memory fails
    writeVcvarsBat(&aw.writer, install_versions, target_arch) catch return error.OutOfMemory;
    return aw.toOwnedSlice();
}

fn writeVcvarsBat(
    writer: *std.Io.Writer,
    install_versions: *const InstallVersions,
    target_arch: Arch,
) error{WriteFailed}!void {
    try writer.writeAll("set \"INCLUDE=");
    if (install_versions.msvc) |install_version| {
        try writer.print(
            "%~dp0VC\\Tools\\MSVC\\{s}\\include;",
            .{install_version},
        );
    }
    if (install_versions.sdk) |install_version| {
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
    if (install_versions.msvc) |install_version| {
        try writer.print(
            "%~dp0VC\\Tools\\MSVC\\{s}\\bin\\Host{s}\\{s};",
            .{ install_version, @tagName(Arch.native), @tagName(target_arch) },
        );
    }
    if (install_versions.sdk) |install_version| {
        try writer.print(
            "%~dp0Windows Kits\\10\\bin\\{[version]s}\\{[host_arch]s};",
            .{ .version = install_version, .host_arch = @tagName(Arch.native) },
        );
    }
    try writer.writeAll("%PATH%\"\n");

    try writer.writeAll("set \"LIB=");
    if (install_versions.msvc) |install_version| {
        try writer.print(
            "%~dp0VC\\Tools\\MSVC\\{s}\\lib\\{s};",
            .{ install_version, @tagName(target_arch) },
        );
    }
    if (install_versions.sdk) |install_version| {
        try writer.print(
            "%~dp0Windows Kits\\10\\Lib\\{[version]s}\\ucrt\\{[target_arch]s};" ++
                "%~dp0Windows Kits\\10\\Lib\\{[version]s}\\um\\{[target_arch]s};",
            .{ .version = install_version, .target_arch = @tagName(target_arch) },
        );
    }
    try writer.writeAll("%LIB%\"\n");
}

fn generateToolchainCmake(
    allocator: std.mem.Allocator,
    unique_pkgs: *const UniquePackages,
    target_cpu: Arch,
    variant: ToolchainVariant,
) error{OutOfMemory}![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    // running out of memory is the only way writing to memory fails
    writeToolchainCmake(&aw.writer, unique_pkgs, target_cpu, variant) catch return error.OutOfMemory;
    return aw.toOwnedSlice();
}

const ToolchainVariant = enum { native, cross };

fn writeToolchainCmake(
    writer: *std.Io.Writer,
    unique_pkgs: *const UniquePackages,
    target_cpu: Arch,
    variant: ToolchainVariant,
) error{WriteFailed}!void {
    switch (variant) {
        .native => {},
        .cross => {
            try writer.writeAll("# settings CMAKE_SYSTEM_NAME and/or CMAKE_SYSTEM_PROCESSOR in a\n");
            try writer.writeAll("# toolchain file also sets CMAKE_CROSSCOMPILING to TRUE\n");
            try writer.writeAll("set(CMAKE_SYSTEM_NAME Windows)\n");
            if (switch (target_cpu) {
                .x64 => "AMD64",
                .x86 => "X86",
                .arm => null,
                .arm64 => "ARM64",
            }) |processor| {
                try writer.print("set(CMAKE_SYSTEM_PROCESSOR {s})\n", .{processor});
            }
        },
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
}

const AbsolutePath = struct {
    slice: []const u8,
    allocated: bool,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, p: []const u8) !AbsolutePath {
        if (std.fs.path.isAbsolute(p)) return .{ .slice = p, .allocated = false };
        return .{
            .slice = try std.Io.Dir.cwd().realPathFileAlloc(io, p, allocator),
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
    install_versions: *const InstallVersions,
    target_cpu: Arch,
) error{OutOfMemory}![]u8 {
    var aw: std.Io.Writer.Allocating = try .initCapacity(allocator, 1000);
    defer aw.deinit();
    if (install_versions.msvc) |msvc_version| {
        aw.writer.print(
            \\sys_include_dir={[install]s}\VC\Tools\MSVC\{[version]s}\include
            \\msvc_lib_dir={[install]s}\VC\Tools\MSVC\{[version]s}\lib\{[target]s}
            \\
        , .{
            .install = install_path.slice,
            .version = msvc_version,
            .target = @tagName(target_cpu),
        }) catch return error.OutOfMemory;
    }
    if (install_versions.sdk) |sdk_version| {
        aw.writer.print(
            \\include_dir={[install]s}\Windows Kits\10\Include\{[version]s}\ucrt
            \\kernel32_lib_dir={[install]s}\Windows Kits\10\lib\{[version]s}\um\{[target]s}
            \\crt_dir={[install]s}\Windows Kits\10\Lib\{[version]s}\ucrt\{[target]s}
            \\
        , .{
            .install = install_path.slice,
            .version = sdk_version,
            .target = @tagName(target_cpu),
        }) catch return error.OutOfMemory;
    }
    aw.writer.writeAll(
        \\gcc_dir=
        \\
    ) catch return error.OutOfMemory;
    return aw.toOwnedSlice() catch return error.OutOfMemory;
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
        const cache_basename = std.fmt.allocPrint(scratch, "{f}-{s}", .{ sha256, name }) catch |e| oom(e);
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

fn installPayloadLocking(
    io: std.Io,
    environ: std.process.Environ,
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
    named: struct {
        msiexec: bool,
    },
) !void {
    globalfilelocks.enteredLockingFunction(@src().fn_name);

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
    if (std.Io.Dir.cwd().access(io, installed_manifest_path, .{})) {
        log.info("ALREADY INSTALLED | {s} {f}", .{ basenameFromUrl(url_decoded), sha256 });
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
            try fetchPayloadLocking(io, environ, scratch, progress_node, cache_dir, payload.sha256, payload.url_decoded, cab_cache_entry.path);
        }
    }
    try fetchPayloadLocking(io, environ, scratch, progress_node, cache_dir, sha256, url_decoded, cache_entry.path);

    const install_lock_path = std.fs.path.join(scratch, &.{ install_dir_path, ".lock" }) catch |e| oom(e);
    defer scratch.free(install_lock_path);
    const current_install_path = std.fs.path.join(scratch, &.{ install_dir_path, "install", "current" }) catch |e| oom(e);
    defer scratch.free(current_install_path);

    var install_lock = try LockFile.lock(io, install_lock_path);
    defer install_lock.unlock(io);

    var install_dir_handle = try std.Io.Dir.cwd().openDir(io, install_dir_path, .{});
    defer install_dir_handle.close(io);

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
            try deleteTree(io, std.Io.Dir.cwd(), msi.staging_dir);
            const installer_path = std.fs.path.join(scratch, &.{ msi.staging_dir, "installer" }) catch |e| oom(e);
            defer scratch.free(installer_path);
            try std.Io.Dir.cwd().createDir(io, msi.staging_dir, .default_dir);
            try std.Io.Dir.cwd().createDir(io, installer_path, .default_dir);
            const msi_copy = std.fs.path.join(scratch, &.{ installer_path, basenameFromUrl(url_decoded) }) catch |e| oom(e);
            defer scratch.free(msi_copy);
            try copyFile(io, cache_entry.path, std.Io.Dir.cwd(), msi_copy);
            {
                var installer_dir = try std.Io.Dir.cwd().openDir(io, installer_path, .{});
                defer installer_dir.close(io);
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
                    if (std.fs.path.dirname(installer_sub_path)) |dir| try installer_dir.createDirPath(io, dir);
                    try copyFile(io, cab_cache_entry.path, installer_dir, installer_sub_path);
                }
            }
            const target_dir = std.fs.path.join(scratch, &.{ msi.staging_dir, "target" }) catch |e| oom(e);
            defer scratch.free(target_dir);
            try populateStagingMsi(io, scratch, msi_copy, target_dir, .{ .msiexec = named.msiexec });
            std.log.info("removing '{s}'...", .{installer_path});
            try deleteTree(io, std.Io.Dir.cwd(), installer_path);
        },
        .zip => {},
    }

    {
        const current_install_file = try startInstall(io, scratch, install_dir_handle, current_install_path);
        defer current_install_file.close(io);
        var write_buf: [1000]u8 = undefined;
        var file_writer = current_install_file.writer(io, &write_buf);
        var writer: FileWriter = .{
            .error_ref = &file_writer.err,
            .interface = &file_writer.interface,
        };
        // this will always starts with the cache basename
        try writer.printFlush("{s}\n", .{cache_entry.basename});
        switch (pre_start_data) {
            .vsix => try installPayloadZip(
                io,
                scratch,
                cache_entry.path,
                install_dir_handle,
                &writer,
                .vsix,
                strip_root_dir,
            ),
            .msi => |msi| {
                const target_dir = std.fs.path.join(scratch, &.{ msi.staging_dir, "target" }) catch |e| oom(e);
                defer scratch.free(target_dir);
                _ = try installDir(
                    io,
                    scratch,
                    .{ .path = install_dir_path, .handle = install_dir_handle },
                    target_dir,
                    &writer,
                    basenameFromUrl(url_decoded),
                );
                try deleteTree(io, std.Io.Dir.cwd(), msi.staging_dir);
            },
            .zip => try installPayloadZip(
                io,
                scratch,
                cache_entry.path,
                install_dir_handle,
                &writer,
                .zip,
                strip_root_dir,
            ),
        }
    }

    try endInstall(io, scratch, installed_manifest_path, current_install_path);
}

const FileWriter = struct {
    error_ref: *?std.Io.File.Writer.Error,
    interface: *std.Io.Writer,
    fn printFlush(
        file_writer: *const FileWriter,
        comptime fmt: []const u8,
        args: anytype,
    ) std.Io.File.Writer.Error!void {
        file_writer.interface.print(fmt, args) catch return file_writer.error_ref.*.?;
        file_writer.interface.flush() catch return file_writer.error_ref.*.?;
    }
};

fn normalizePathSeps(path: []u8) void {
    for (path) |*char| char.* = switch (char.*) {
        '/' => '\\',
        else => |other| other,
    };
}

fn populateStagingMsi(
    io: std.Io,
    scratch: std.mem.Allocator,
    msi_file_path: []const u8,
    staging_dir: []const u8,
    named: struct { msiexec: bool },
) !void {
    if (!named.msiexec) {
        const msi_content = blk: {
            const file = std.Io.Dir.cwd().openFile(io, msi_file_path, .{}) catch |err| errExit(
                "open '{s}' failed with {s}",
                .{ msi_file_path, @errorName(err) },
            );
            defer file.close(io);
            break :blk try readToEndAlloc(io, file, scratch);
        };
        defer scratch.free(msi_content);
        @import("msi").install(io, scratch, .{
            .cabs_dir = std.fs.path.dirname(msi_file_path) orelse ".",
            .msi_content = msi_content,
            .install_path = staging_dir,
        }) catch |err| {
            std.log.err("failed to install msi \"{s}\" (error={s}). On windows, try the --msiexec flag to fallback to using the system msi installer. If that works, please file an issue that includes the name of this msi and the contents of your lock file. ", .{ std.fs.path.basename(msi_file_path), @errorName(err) });
            return err;
        };
        return;
    }

    // msi has problem with paths that contain forward slaces
    const msi_path_fixed = try scratch.dupe(u8, msi_file_path);
    defer scratch.free(msi_path_fixed);
    normalizePathSeps(msi_path_fixed);

    // at least some MSI files require TARGETDIR to be an absolute path
    // also, realpath requires the directory to exist to work
    try std.Io.Dir.cwd().createDirPath(io, staging_dir);
    const staging_dir_abs = try std.Io.Dir.cwd().realPathFileAlloc(io, staging_dir, scratch);
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
    const result = try std.process.run(scratch, io, .{
        .argv = &argv,
    });
    defer {
        scratch.free(result.stdout);
        scratch.free(result.stderr);
    }
    switch (result.term) {
        .exited => |exit_code| {
            if (exit_code != 0) {
                var stderr = stderrFile().writerStreaming(io, &.{});
                stderr.interface.writeAll(result.stdout) catch return stderr.err.?;
                stderr.interface.writeAll(result.stderr) catch return stderr.err.?;
                errExit(
                    "msiexec for '{s}' failed with exit code {} (output stdout={} bytes stderr={} bytes)",
                    .{ msi_file_path, exit_code, result.stdout.len, result.stderr.len },
                );
            }
        },
        inline else => |e| {
            var stderr = stderrFile().writerStreaming(io, &.{});
            stderr.interface.writeAll(result.stdout) catch return stderr.err.?;
            stderr.interface.writeAll(result.stderr) catch return stderr.err.?;
            errExit("msiexec for '{s}' terminated with {}", .{ msi_file_path, e });
        },
    }
}

fn installPayloadZip(
    io: std.Io,
    scratch: std.mem.Allocator,
    cache_path: []const u8,
    install_dir: std.Io.Dir,
    installing_manifest: *const FileWriter,
    kind: enum { vsix, zip },
    strip_root_dir: bool,
) !void {
    var payload_file = try std.Io.Dir.cwd().openFile(io, cache_path, .{});
    defer payload_file.close(io);
    var payload_buf: [4096]u8 = undefined;
    var payload_reader = payload_file.reader(io, &payload_buf);

    var last_root_dir: ?[]const u8 = null;

    {
        var zip_it = try std.zip.Iterator.init(&payload_reader);
        while (try zip_it.next()) |entry| {
            var filename_buf: [std.fs.max_path_bytes]u8 = undefined;
            const filename = filename_buf[0..entry.filename_len];
            try payload_reader.seekTo(entry.header_zip_offset + @sizeOf(std.zip.CentralDirectoryFileHeader));
            payload_reader.interface.readSliceAll(filename) catch |err| switch (err) {
                error.ReadFailed => return payload_reader.err.?,
                error.EndOfStream => return error.ZipBadFileOffset,
            };
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

            switch (try updateInstallingManifest(io, install_dir, installing_manifest, sub_path)) {
                .already_installed => {
                    // TODO: for zip, we could probably just take a CRC of the current file and compre
                    //       it to our expected CRC
                    std.debug.panic("'{s}' already installed (TODO: check if it's the same)", .{sub_path});
                },
                .ready => {
                    const file = try install_dir.createFile(io, sub_path, .{});
                    defer file.close(io);
                    var file_writer = file.writer(io, &.{});
                    var hash_buf: [16 * 4096]u8 = undefined;
                    var hashed = file_writer.interface.hashed(std.hash.Crc32.init(), &hash_buf);
                    entry.extractTo(&payload_reader, &hashed.writer) catch |err| switch (err) {
                        error.WriteFailed => return file_writer.err.?,
                        else => |e| return e,
                    };
                    hashed.writer.flush() catch return file_writer.err.?;
                    const crc = hashed.hasher.final();
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
    io: std.Io,
    install_dir: std.Io.Dir,
    installing_manifest: *const FileWriter,
    install_path: []const u8,
) !enum { already_installed, ready } {
    if (install_dir.openFile(io, install_path, .{})) |file| {
        defer file.close(io);
        try installing_manifest.printFlush("add {s}\n", .{install_path});
        return .already_installed;
    } else |err| switch (err) {
        error.FileNotFound => {
            try installing_manifest.printFlush("new {s}\n", .{install_path});
            if (std.fs.path.dirname(install_path)) |d| try install_dir.createDirPath(io, d);
            return .ready;
        },
        else => |e| return e,
    }
}

fn fileMatches(io: std.Io, dir: std.Io.Dir, sub_path: []const u8, content: []const u8) !bool {
    const file = dir.openFile(io, sub_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer file.close(io);
    {
        const file_size = try file.length(io);
        if (file_size != content.len) return false;
    }
    const chunk_size = @max(4096, std.heap.page_size_min);
    var buffer: [chunk_size]u8 = undefined;
    var content_offset: usize = 0;
    while (content_offset < content.len) {
        const bytes_to_read = @min(chunk_size, content.len - content_offset);
        const bytes_read = try file.readPositionalAll(io, buffer[0..bytes_to_read], content_offset);
        if (bytes_read != bytes_to_read) return false;
        if (!std.mem.eql(u8, buffer[0..bytes_read], content[content_offset .. content_offset + bytes_read])) {
            return false;
        }
        content_offset += bytes_read;
    }
    return true;
}
fn filesAreIdentical(io: std.Io, path1: []const u8, path2: []const u8) !bool {
    const file1 = try std.Io.Dir.cwd().openFile(io, path1, .{});
    defer file1.close(io);
    const file2 = try std.Io.Dir.cwd().openFile(io, path2, .{});
    defer file2.close(io);
    {
        const file1_end_pos = try file1.length(io);
        const file2_end_pos = try file2.length(io);
        if (file1_end_pos != file2_end_pos) return false;
    }
    const chunk_size = @max(4096, std.heap.page_size_min);
    var buffer1: [chunk_size]u8 = undefined;
    var buffer2: [chunk_size]u8 = undefined;
    var offset: u64 = 0;
    while (true) {
        const bytes_read1 = try file1.readPositionalAll(io, &buffer1, offset);
        const bytes_read2 = try file2.readPositionalAll(io, &buffer2, offset);
        offset += bytes_read1;
        if (bytes_read1 != bytes_read2) return false;
        if (bytes_read1 == 0) return true;
        if (!std.mem.eql(u8, buffer1[0..bytes_read1], buffer2[0..bytes_read2]))
            return false;
    }
}

const OpenDir = struct {
    path: []const u8,
    handle: std.Io.Dir,
};

fn installDir(
    io: std.Io,
    scratch: std.mem.Allocator,
    install_dir: OpenDir,
    source_dir_path: []const u8,
    installing_manifest: *const FileWriter,
    root_exclude: []const u8,
) !struct { root_excluded: bool } {
    var source_dir = try std.Io.Dir.cwd().openDir(io, source_dir_path, .{ .iterate = true });
    defer source_dir.close(io);

    var it = try source_dir.walk(scratch);
    defer it.deinit();

    var root_excluded = false;
    while (try it.next(io)) |entry| {
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
        switch (try updateInstallingManifest(io, install_dir.handle, installing_manifest, entry.path)) {
            .already_installed => {
                if (!try filesAreIdentical(io, source_path, install_path)) {
                    std.log.err("file conflict!", .{});
                    std.log.err("new source       : {s}", .{source_path});
                    std.log.err("already installed: {s}", .{install_path});
                    @panic("file conflict");
                }
            },
            .ready => try copyFile(io, source_path, std.Io.Dir.cwd(), install_path),
        }
    }
    return .{ .root_excluded = root_excluded };
}

pub fn deleteTree(io: std.Io, dir: std.Io.Dir, sub_path: []const u8) !void {
    if (builtin.os.tag != .windows) {
        return dir.deleteTree(io, sub_path);
    }

    // workaround issue on windows where it just doesn't delete things
    const MAX_ATTEMPTS = 10;
    var attempt: u8 = 0;
    while (true) : (attempt += 1) {
        if (dir.deleteTree(io, sub_path)) {
            return;
        } else |err| {
            if (attempt == MAX_ATTEMPTS) return err;
            switch (err) {
                error.FileBusy => {
                    std.log.warn("path '{s}' is busy (attempt {}), will retry", .{ sub_path, attempt });
                    try io.sleep(.fromMilliseconds(100), .awake);
                },
                else => |e| return e,
            }
        }
    }
}

fn startInstall(
    io: std.Io,
    scratch: std.mem.Allocator,
    install_dir: std.Io.Dir,
    current_install_path: []const u8,
) !std.Io.File {
    if (std.Io.Dir.cwd().openFile(io, current_install_path, .{})) |current_install_file| {
        const content = blk: {
            defer current_install_file.close(io);
            // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            log.info(" opened '{s}'", .{current_install_path});
            break :blk try readToEndAlloc(io, current_install_file, scratch);
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
                    install_dir.deleteFile(io, sub_path) catch |err| switch (err) {
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
        try std.Io.Dir.cwd().deleteFile(io, current_install_path);
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    }

    if (std.fs.path.dirname(current_install_path)) |d| try std.Io.Dir.cwd().createDirPath(io, d);
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    log.info("creating '{s}'...", .{current_install_path});
    return try std.Io.Dir.cwd().createFile(io, current_install_path, .{});
}

fn endInstall(
    io: std.Io,
    scratch: std.mem.Allocator,
    installed_manifest_path: []const u8,
    current_install_path: []const u8,
) !void {
    const installed_manifest_path_tmp = std.mem.concat(scratch, u8, &.{ installed_manifest_path, ".tmp" }) catch |e| oom(e);
    defer scratch.free(installed_manifest_path_tmp);

    {
        const installed_manifest = try std.Io.Dir.cwd().createFile(io, installed_manifest_path_tmp, .{});
        defer installed_manifest.close(io);
        var buf: [8192]u8 = undefined;
        var file_writer = installed_manifest.writer(io, &buf);
        const w = &file_writer.interface;

        const content = blk: {
            const current_install_file = try std.Io.Dir.cwd().openFile(io, current_install_path, .{});
            defer current_install_file.close(io);
            // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            log.info(" opened '{s}'", .{current_install_path});
            break :blk try readToEndAlloc(io, current_install_file, scratch);
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
                w.print("{s}\n", .{sub_path}) catch return file_writer.err.?;
            } else if (std.mem.startsWith(u8, line, "add ")) {
                const sub_path = line[4..];
                w.print("{s}\n", .{sub_path}) catch return file_writer.err.?;
            } else std.debug.panic(
                "{s}:{}: line did not start with 'new ' nor 'add ': '{s}'",
                .{ current_install_path, lineno, line },
            );
        }
        w.flush() catch return file_writer.err.?;
    }
    try std.Io.Dir.cwd().deleteFile(io, current_install_path);
    try std.Io.Dir.rename(.cwd(), installed_manifest_path_tmp, .cwd(), installed_manifest_path, io);
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
const CabOffset = struct { cab_offset: usize };

fn updateLockFileLocking(
    io: std.Io,
    environ: std.process.Environ,
    scratch: std.mem.Allocator,
    progress_node: std.Progress.Node,
    recipes: *const Recipes,
    channel: Channel,
    autoenv: bool,
    msvcup_pkgs: []const MsvcupPackage,
    lock_file_path: []const u8,
    pkgs: Packages,
    cache_dir: []const u8,
) !void {
    globalfilelocks.enteredLockingFunction(@src().fn_name);

    const payloads: []const InstallPayload = blk_payloads: {
        var payloads: std.ArrayList(InstallPayload) = .empty;

        for (pkgs.slice, 0..) |*pkg, pkg_index| {
            const payload_range = pkgs.payloadRangeFromPkgIndex(.fromInt(pkg_index));
            for (payload_range.start..payload_range.limit) |payload_index| {
                const owner = recipeOwner(recipes, pkg, &pkgs.payloads[payload_index]) orelse continue;
                for (msvcup_pkgs) |msvcup_pkg| {
                    if (msvcup_pkg.kind != owner.rule.package) continue;
                    if (!std.mem.eql(u8, msvcup_pkg.version.slice, owner.package_version)) continue;
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
        }

        for (msvcup_pkgs) |msvcup_pkg| {
            for (payloads.items) |payload| {
                if (MsvcupPackage.order({}, payload.target, msvcup_pkg) == .eq) break;
            } else errExit(
                "package '{f}' has no payloads in the manifest of channel '{s}', 'msvcup list --channel {s}' shows the available packages",
                .{ msvcup_pkg, channel.asArg(), channel.asArg() },
            );
        }

        log.warn("TODO: add the dependencies for all the packages we've added", .{});

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

    var cabs: std.ArrayList(PayloadIndex) = .empty;
    defer cabs.deinit(scratch);
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
                try fetchPayloadLocking(
                    io,
                    environ,
                    scratch,
                    progress_node,
                    cache_dir,
                    payload.sha256,
                    payload.url_decoded,
                    cache_entry.path,
                );
                const msi_content = blk: {
                    const file = try std.Io.Dir.cwd().openFile(io, cache_entry.path, .{});
                    defer file.close(io);
                    break :blk try readToEndAlloc(io, file, scratch);
                };
                const pkg_index = pkgs.pkgIndexFromPayloadIndex(install_payload.index);
                const pkg_payload_range = pkgs.payloadRangeFromPkgIndex(pkg_index);

                const start = nanoTimestamp(io);
                var indexof_elapsed: i128 = 0;
                var loop_elapsed: i128 = 0;

                {
                    var offset: usize = 0;
                    while (true) {
                        const before_indexof: i128 = nanoTimestamp(io);
                        const index = indexOfCab2(msi_content, offset) orelse break;
                        indexof_elapsed += nanoTimestamp(io) - before_indexof;
                        offset = index + 4;
                        const before_loop = nanoTimestamp(io);
                        for (pkg_payload_range.start..pkg_payload_range.limit) |pkg_payload_index| {
                            if (pkg_payload_index == install_payload.index.int()) continue;
                            const pkg_payload = &pkgs.payloads[pkg_payload_index];
                            if (std.mem.endsWith(u8, pkg_payload.file_name, ".cab")) {
                                const cab_payload = std.fs.path.basenameWindows(pkg_payload.file_name);
                                if (index + 4 < cab_payload.len) continue;
                                const cab_msi = msi_content[index + 4 - cab_payload.len ..][0..cab_payload.len];
                                if (std.ascii.findIgnoreCase(cab_payload, cab_msi)) |_| {
                                    cabs.append(scratch, .fromInt(pkg_payload_index)) catch |e| oom(e);
                                    break;
                                }
                            }
                        }
                        const now = nanoTimestamp(io);
                        loop_elapsed += now - before_loop;
                    }
                }
                const elapsed = nanoTimestamp(io) - start;
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
    if (std.fs.path.dirname(lock_file_path)) |dir| try std.Io.Dir.cwd().createDirPath(io, dir);
    const lock_file = try std.Io.Dir.cwd().createFile(io, lock_file_path, .{});
    defer lock_file.close(io);
    var write_buf: [8192]u8 = undefined;
    var lock_file_writer = lock_file.writer(io, &write_buf);
    writeLockFile(
        autoenv,
        pkgs,
        payloads,
        cabs.items,
        payload_cab_offsets,
        &lock_file_writer.interface,
    ) catch |err| switch (err) {
        error.WriteFailed => return lock_file_writer.err.?,
    };
}
fn writeLockFile(
    autoenv: bool,
    pkgs: Packages,
    payloads: []const InstallPayload,
    cabs: []const PayloadIndex,
    payload_cab_offsets: []const CabOffset,
    writer: *std.Io.Writer,
) error{WriteFailed}!void {
    if (autoenv) {
        try writer.writeAll("autoenv\n");
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
        const cabs_start = payload_cab_offsets[payload_cab_offsets_index].cab_offset;
        const cabs_limit = if (payload_cab_offsets_index + 1 >= payload_cab_offsets.len)
            cabs.len
        else
            payload_cab_offsets[payload_cab_offsets_index + 1].cab_offset;
        for (cabs[cabs_start..cabs_limit]) |cab_payload_index| {
            const cab_payload = pkgs.payloads[cab_payload_index.int()];
            std.debug.assert(.cab == getLockFileUrlKind(cab_payload.url_decoded).?);
            try writePayload(writer, null, .cab, cab_payload.url_decoded, cab_payload.sha256, cab_payload.file_name);
        }
        try writePayload(writer, install_payload.target, url_kind, payload.url_decoded, payload.sha256, payload.file_name);
    }
    try writer.flush();
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
    if (std.ascii.findIgnoreCase(url, &sha_hex)) |hash_index| {
        try writer.print(
            "{s}|{s}|{d}{s}{s}\n",
            .{ target_str, url, hash_index, space, out_file_name },
        );
    } else {
        try writer.print(
            "{s}|{s}|{f}{s}{s}\n",
            .{ target_str, url, sha256, space, std.fs.path.basenameWindows(out_file_name) },
        );
    }
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

const LockFileUrlKind = enum { vsix, msi, cab, zip };
fn getLockFileUrlKind(url: []const u8) ?LockFileUrlKind {
    if (std.mem.endsWith(u8, url, ".vsix")) return .vsix;
    if (std.mem.endsWith(u8, url, ".msi")) return .msi;
    if (std.mem.endsWith(u8, url, ".cab")) return .cab;
    if (std.mem.endsWith(u8, url, ".zip")) return .zip;
    return null;
}

const Language = union(enum) {
    neutral,
    en_us,
    /// a key from other_languages
    other: []const u8,
    pub fn name(self: Language) []const u8 {
        return switch (self) {
            .neutral => "neutral",
            .en_us => "en-US",
            .other => |n| n,
        };
    }
};
const PackageSource = enum {
    /// from the visual studio channel manifest
    manifest,
    /// from msvcup's builtin extra packages (i.e. ninja/cmake)
    extra,
};
const Package = struct {
    id: []const u8,
    version: []const u8,
    payloads_offset: usize,
    language: Language,
    source: PackageSource,
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
    io: std.Io,
    environ: std.process.Environ,
    allocator: std.mem.Allocator,
    progress_node: std.Progress.Node,
    scratch: std.mem.Allocator,
    msvcup_dir: MsvcupDir,
    channel: Channel,
    update: ManifestUpdate,
) !PathAndContent {
    globalfilelocks.enteredLockingFunction(@src().fn_name);

    const manifest_dir = channel.manifestDir(.vs);
    var vsman_latest_owning: OwningPath = .{
        .owning_path = msvcup_dir.path(allocator, .{ "manifest", manifest_dir.slice(), "latest" }) catch |e| oom(e),
    };
    defer vsman_latest_owning.deinit(allocator);

    switch (update) {
        .off => {
            if (try readFile(io, allocator, vsman_latest_owning.borrow())) |content| return .{
                .path = vsman_latest_owning.take(),
                .content = content,
            };
        },
        .daily => @panic("todo: daily update"),
        .always => @panic("todo: replace the existing manifest"),
    }

    var chman = try readChManifestLocking(io, environ, scratch, progress_node, scratch, msvcup_dir, channel, update);
    defer chman.freeConst(scratch);

    const fetch_path = msvcup_dir.path(scratch, .{ "manifest", manifest_dir.slice(), "latest.fetching" }) catch |e| oom(e);
    defer scratch.free(fetch_path);
    switch (try AtomicFile.lock(io, fetch_path, vsman_latest_owning.borrow())) {
        .exists => {},
        .locked => |locked| {
            var atomic_file = locked;
            defer atomic_file.deinit(io);
            const payload = try vsManifestPayloadFromChManifest(scratch, scratch, chman);
            defer payload.free(scratch);
            const uri = uriFromUrlDecoded(payload.url_decoded) catch |e| errExit(
                "failed to parse vs manifest url '{s}' taken from file '{s}' with {s}",
                .{ payload.url_decoded, chman.path, @errorName(e) },
            );
            // nothing verifies the vs manifest's content, see the note below
            if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) errExit(
                "vs manifest url '{s}' taken from file '{s}' is not an https URL",
                .{ payload.url_decoded, chman.path },
            );

            // log.info("payload size {} url '{s}' sha256 '{s}'", .{ payload.size, payload.url, payload.sha256 });
            // if (true) @panic("hash the URI and don't redownload it");

            // NOTE: for some reason the size/sha256 is not right for this?!?
            // const sha256 = try fetch(progress_node, scratch, uri, atomic_file.file, .{ .size = payload.size });
            const sha256 = try fetch(io, environ, progress_node, scratch, uri, atomic_file.file, .{ .redirects = .https_only });
            _ = sha256;
            try checkFetchedManifest(io, scratch, &atomic_file, uri, "vs manifest", "packages");
            try atomic_file.finish(io, vsman_latest_owning.borrow());
        },
    }
    const content = try readFile(io, allocator, vsman_latest_owning.borrow()) orelse errExit(
        "{s} still doesn't exist",
        .{vsman_latest_owning.borrow()},
    );
    return .{ .path = vsman_latest_owning.take(), .content = content };
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
    var buf: std.ArrayList(u8) = try .initCapacity(allocator, url.len);
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
    chman: PathAndContent,
) !VsManifestPayload {
    const parsed = try std.json.parseFromSlice(std.json.Value, scratch, chman.content, .{});
    defer parsed.deinit();
    const json_file: JsonContext.File = .{ .file_path = chman.path };
    var json_error: JsonContext.Error = undefined;
    const file_obj = json_file.as(.object, &json_error, parsed.value) catch errExit("{f}", .{json_error});
    const channel_items_field = file_obj.getField(&json_error, "channelItems") catch errExit("{f}", .{json_error});
    const channel_items = channel_items_field.as(.array, &json_error) catch errExit("{f}", .{json_error});
    // the id depends on the channel, i.e. "Microsoft.VisualStudio.Manifests.VisualStudioPreview",
    // but a channel has exactly one
    const vs_manifest_id_prefix = "Microsoft.VisualStudio.Manifests.";
    var maybe_payload: ?PayloadJson = null;
    for (0..channel_items.items.len) |index| {
        const channel_item_element = channel_items.getElement(&json_error, index) catch errExit("{f}", .{json_error});
        const channel_item = channel_item_element.as(.object, &json_error) catch errExit("{f}", .{json_error});
        const id_field = channel_item.getField(&json_error, "id") catch errExit("{f}", .{json_error});
        const id = id_field.as(.string, &json_error) catch errExit("{f}", .{json_error});
        if (!std.mem.startsWith(u8, id, vs_manifest_id_prefix)) continue;
        if (maybe_payload != null) errExit(
            "channel manifest '{s}' has more than one channelItem with an id starting with '{s}'",
            .{ chman.path, vs_manifest_id_prefix },
        );
        const payloads_field = channel_item.getField(&json_error, "payloads") catch errExit("{f}", .{json_error});
        const payloads = payloads_field.as(.array, &json_error) catch errExit("{f}", .{json_error});
        if (payloads.items.len != 1) errExit(
            "{s}: channelItem with id \"{s}\" has {} payloads instead of 1",
            .{ chman.path, id, payloads.items.len },
        );
        const payload_element = payloads.getElement(&json_error, 0) catch unreachable;
        const payload_object = payload_element.as(.object, &json_error) catch errExit("{f}", .{json_error});
        maybe_payload = PayloadJson.init(payload_object);
    }
    const payload = maybe_payload orelse errExit(
        "channel manifest '{s}' has no channelItem with an id starting with '{s}'",
        .{ chman.path, vs_manifest_id_prefix },
    );
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
            const field = obj.getField(&err, "fileName") catch errExit("{f}", .{err});
            break :blk field.as(.string, &err) catch errExit("{f}", .{err});
        };
        const sha256: Sha = blk: {
            const field = obj.getField(&err, "sha256") catch errExit("{f}", .{err});
            const str = field.as(.string, &err) catch errExit("{f}", .{err});
            if (str.len != 64) {
                const file_path: []const u8 = if (obj.parent_context.getFilePath()) |p| p else "?";
                errExit(
                    "{s}: {f} value '{s}' is {} chars but expected 64",
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
            const field = obj.getField(&err, "size") catch errExit("{f}", .{err});
            const size = field.as(.integer, &err) catch errExit("{f}", .{err});
            if (size < 0) {
                const file_path: []const u8 = if (obj.parent_context.getFilePath()) |p| p else "?";
                errExit(
                    "{s}: {f} size {} is negative",
                    .{ file_path, field, size },
                );
            }
            break :blk @intCast(size);
        };
        const url = blk: {
            const field = obj.getField(&err, "url") catch errExit("{f}", .{err});
            break :blk field.as(.string, &err) catch errExit("{f}", .{err});
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
    io: std.Io,
    environ: std.process.Environ,
    allocator: std.mem.Allocator,
    progress_node: std.Progress.Node,
    scratch: std.mem.Allocator,
    msvcup_dir: MsvcupDir,
    channel: Channel,
    update: ManifestUpdate,
) !PathAndContent {
    globalfilelocks.enteredLockingFunction(@src().fn_name);

    const manifest_dir = channel.manifestDir(.channel);
    var chman_latest_owning: OwningPath = .{
        .owning_path = msvcup_dir.path(allocator, .{ "manifest", manifest_dir.slice(), "latest" }) catch |e| oom(e),
    };
    defer chman_latest_owning.deinit(allocator);

    switch (update) {
        .off => {
            if (try readFile(io, allocator, chman_latest_owning.borrow())) |content| return .{
                .path = chman_latest_owning.take(),
                .content = content,
            };
        },
        .daily => @panic("todo: daily update"),
        .always => @panic("todo: replace the existing manifest"),
    }

    // the url of a channel manifest is what a channel url redirects to, so there's nothing
    // to resolve
    const manifest_uri: ?std.Uri = switch (channel) {
        .url => |url| blk: {
            // parseChannel checked it
            const uri = std.Uri.parse(url) catch unreachable;
            break :blk if (Channel.isManifestUri(uri)) uri else null;
        },
        else => null,
    };
    const maybe_resolved: ?PathAndContent = if (manifest_uri == null)
        try resolveChManifestUrlLocking(io, environ, scratch, scratch, msvcup_dir, channel, update)
    else
        null;
    defer if (maybe_resolved) |resolved| resolved.freeConst(scratch);
    const uri = manifest_uri orelse std.Uri.parse(maybe_resolved.?.content) catch |e| errExit(
        "failed to parse latest channel manifest url '{s}' from file '{s}' with {s}",
        .{ maybe_resolved.?.content, maybe_resolved.?.path, @errorName(e) },
    );

    const fetch_path = msvcup_dir.path(scratch, .{ "manifest", manifest_dir.slice(), "latest.fetching" }) catch |e| oom(e);
    defer scratch.free(fetch_path);
    switch (try AtomicFile.lock(io, fetch_path, chman_latest_owning.borrow())) {
        .exists => {},
        .locked => |locked| {
            var atomic_file = locked;
            defer atomic_file.deinit(io);

            // const uri_sha = sha256FromUri(uri);
            // // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            // // TODO: don't perform the fetch if we already have!!!
            // //       hash the URI and see if we've already fetched it?
            // //       ALSO, I'd like to see if
            // if (true) std.debug.panic("check uri sha '{s}'", .{uri_sha});

            const sha256 = try fetch(io, environ, progress_node, scratch, uri, atomic_file.file, .{ .redirects = .https_only });
            _ = sha256;
            try checkFetchedManifest(io, scratch, &atomic_file, uri, "channel manifest", "channelItems");
            try atomic_file.finish(io, chman_latest_owning.borrow());
        },
    }
    const content = try readFile(io, allocator, chman_latest_owning.borrow()) orelse errExit(
        "{s} still doesn't exist",
        .{chman_latest_owning.borrow()},
    );
    return .{ .path = chman_latest_owning.take(), .content = content };
}

/// Exits unless what was just downloaded is a json object with the given field. A manifest
/// has no hash to check it against and once it's cached it isn't downloaded again, so a url
/// that gave us something else would fail every run until the file is deleted by hand.
fn checkFetchedManifest(
    io: std.Io,
    scratch: std.mem.Allocator,
    atomic_file: *AtomicFile,
    uri: std.Uri,
    what: []const u8,
    required_field: []const u8,
) !void {
    const content = try readToEndAlloc(io, atomic_file.file, scratch);
    defer scratch.free(content);

    const problem: []const u8 = blk: {
        const parsed = std.json.parseFromSlice(std.json.Value, scratch, content, .{}) catch |err| switch (err) {
            error.OutOfMemory => |e| oom(e),
            else => break :blk "it isn't json",
        };
        defer parsed.deinit();
        switch (parsed.value) {
            .object => |object| if (object.contains(required_field)) return,
            else => break :blk "it isn't a json object",
        }
        // exit doesn't run defers, delete the file before the message that names the field
        atomic_file.deinit(io);
        errExit("'{f}' is not a {s}, it has no \"{s}\" field", .{ uri, what, required_field });
    };
    atomic_file.deinit(io);
    errExit("'{f}' is not a {s}, {s}", .{ uri, what, problem });
}

/// A Location longer than this fails to resolve.
const max_location_len = 8192;

/// Gives the url a redirect leads to, its Location can be relative to the url that
/// redirected. The result references buf.
fn resolveLocation(
    base: std.Uri,
    location: []const u8,
    buf: *[2 * max_location_len]u8,
) std.Uri.ResolveInPlaceError!std.Uri {
    if (location.len > max_location_len) return error.NoSpaceLeft;
    @memcpy(buf[0..location.len], location);
    var unused: []u8 = buf;
    return base.resolveInPlace(location.len, &unused);
}

fn resolveChManifestUrlLocking(
    io: std.Io,
    environ: std.process.Environ,
    allocator: std.mem.Allocator,
    scratch: std.mem.Allocator,
    msvcup_dir: MsvcupDir,
    channel: Channel,
    update: ManifestUpdate,
) !PathAndContent {
    globalfilelocks.enteredLockingFunction(@src().fn_name);

    const manifest_dir = channel.manifestDir(.@"channel-url");
    var chman_latest_url_path_owning: OwningPath = .{
        .owning_path = msvcup_dir.path(allocator, .{ "manifest", manifest_dir.slice(), "latest" }) catch |e| oom(e),
    };
    defer chman_latest_url_path_owning.deinit(allocator);

    switch (update) {
        .off => {
            if (try readFile(io, allocator, chman_latest_url_path_owning.borrow())) |content| return .{
                .path = chman_latest_url_path_owning.take(),
                .content = content,
            };
        },
        .daily => @panic("todo: daily update"),
        .always => @panic("todo: replace the existing url file"),
    }

    const fetch_path = msvcup_dir.path(scratch, .{ "manifest", manifest_dir.slice(), "latest.fetching" }) catch |e| oom(e);
    defer scratch.free(fetch_path);
    switch (try AtomicFile.lock(io, fetch_path, chman_latest_url_path_owning.borrow())) {
        .exists => {},
        .locked => |locked| {
            var atomic_file = locked;
            defer atomic_file.deinit(io);
            try resolveChannelManifestUrlToFile(
                io,
                environ,
                scratch,
                std.Uri.parse(channel.httpsUrl()) catch unreachable,
                atomic_file.file,
            );
            try atomic_file.finish(io, chman_latest_url_path_owning.borrow());
        },
    }
    const content = try readFile(io, allocator, chman_latest_url_path_owning.borrow()) orelse errExit(
        "{s} still doesn't exist",
        .{chman_latest_url_path_owning.borrow()},
    );
    return .{
        .path = chman_latest_url_path_owning.take(),
        .content = content,
    };
}

fn resolveChannelManifestUrlToFile(
    io: std.Io,
    environ: std.process.Environ,
    scratch: std.mem.Allocator,
    uri: std.Uri,
    out_file: std.Io.File,
) !void {
    // TODO: progres report
    log.info("resolving URL '{f}'...", .{uri});

    var client: std.http.Client = .{ .allocator = scratch, .io = io };
    defer client.deinit();
    initProxies(environ, &client, scratch);
    var request = try client.request(.GET, uri, .{
        .keep_alive = false,
        // we want the redirect itself, not what it leads to
        .redirect_behavior = .unhandled,
    });
    defer request.deinit();
    try request.sendBodiless();
    const response = try request.receiveHead(&.{});
    if (response.head.status.class() == .redirect) {
        if (response.head.location) |location| {
            var resolve_buf: [2 * max_location_len]u8 = undefined;
            const redirect_uri = resolveLocation(uri, location, &resolve_buf) catch |e| errExit(
                "channel URL '{f}' redirects to '{s}', which failed to parse with {t}",
                .{ uri, location, e },
            );
            if (!std.ascii.eqlIgnoreCase(redirect_uri.scheme, "https")) errExit(
                "channel URL '{f}' redirects to '{f}', which is not an https URL",
                .{ uri, redirect_uri },
            );
            // an unknown aka.ms url redirects to a search page with a success status,
            // check this before it gets cached
            if (!Channel.isManifestUri(redirect_uri)) errExit(
                "channel URL '{f}' redirects to '{f}', which is not a channel manifest (.chman)",
                .{ uri, redirect_uri },
            );
            var file_writer = out_file.writerStreaming(io, &.{});
            file_writer.interface.print("{f}", .{redirect_uri}) catch return file_writer.err.?;
            return;
        }
    }
    errExit("GET '{f}' HTTP status {} \"{s}\", expected a redirect to a channel manifest", .{
        uri,
        @backingInt(response.head.status),
        response.head.status.phrase() orelse "",
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

fn fetchPayloadLocking(
    io: std.Io,
    environ: std.process.Environ,
    scratch: std.mem.Allocator,
    progress_node: std.Progress.Node,
    cache_dir: []const u8,
    sha256: Sha,
    url_decoded: []const u8,
    cache_path: []const u8,
) !void {
    globalfilelocks.enteredLockingFunction(@src().fn_name);

    // AtomicFile.lock checks this too, but it has to create and lock a file to get there. This
    // is what lets a process that wants a cached payload skip waiting on a download.
    if (std.Io.Dir.cwd().access(io, cache_path, .{})) {
        log.info("ALREADY FETCHED  | {s} {f}", .{ url_decoded, sha256 });
        return;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    }

    const fetch_path = std.mem.concat(scratch, u8, &.{ cache_path, ".fetching" }) catch |e| oom(e);
    defer scratch.free(fetch_path);
    var atomic_file = switch (try AtomicFile.lock(io, fetch_path, cache_path)) {
        .exists => {
            log.info("ALREADY FETCHED  | {s} {f}", .{ url_decoded, sha256 });
            return;
        },
        .locked => |locked| locked,
    };
    defer atomic_file.deinit(io);

    log.info("FETCHING         | {s} {f}", .{ url_decoded, sha256 });
    const actual_sha256 = try fetch(
        io,
        environ,
        progress_node,
        scratch,
        try uriFromUrlDecoded(url_decoded),
        atomic_file.file,
        .{},
    );
    if (!sha256.eql(&actual_sha256)) {
        std.log.err(
            "SHA256 mismatch:\nexpected: {f}\nactual  : {f}\n",
            .{ sha256, actual_sha256 },
        );
        try finishCacheFetch(io, scratch, cache_dir, url_decoded, actual_sha256, &atomic_file);
        // exit doesn't run the defer above
        atomic_file.deinit(io);
        std.process.exit(0xff);
    }
    try atomic_file.finish(io, cache_path);
}

const FetchOptions = struct {
    size: ?u64 = null,
    /// What a redirect is allowed to lead to. Payloads are checked against a hash from the
    /// manifest so it doesn't matter where they come from. Nothing checks a manifest, so
    /// every url on the way to one has to be https.
    redirects: enum { any, https_only } = .any,
};

const max_fetch_redirects = 3;

/// The Visual Studio CDN sometimes ends a response early, curl sees it too. The connection
/// closes normally so the only sign is that we received fewer bytes than Content-Length.
const max_fetch_attempts = 3;

fn fetch(
    io: std.Io,
    environ: std.process.Environ,
    progress_node: std.Progress.Node,
    scratch: std.mem.Allocator,
    uri: std.Uri,
    out_file: std.Io.File,
    opt: FetchOptions,
) !Sha {
    log.info("fetch: {f}", .{uri});
    const progress_node_name = std.fmt.allocPrint(scratch, "fetch {f}", .{uri}) catch |e| oom(e);
    defer scratch.free(progress_node_name);
    const node = progress_node.start(progress_node_name, 1);
    defer node.end();

    var attempt: u32 = 1;
    while (true) : (attempt += 1) {
        switch (try fetchAttempt(io, environ, scratch, uri, out_file, opt)) {
            .sha => |sha| return sha,
            .wrong_size => |size| {
                if (attempt == max_fetch_attempts) errExit(
                    "fetch '{f}': expected {} bytes but read {}, gave up after {} attempts",
                    .{ uri, size.expected, size.received, attempt },
                );
                log.warn(
                    "fetch '{f}': expected {} bytes but read {}, retrying (attempt {} of {} failed)",
                    .{ uri, size.expected, size.received, attempt, max_fetch_attempts },
                );
            },
        }
    }
}

const FetchAttemptResult = union(enum) {
    sha: Sha,
    wrong_size: struct { expected: u64, received: u64 },
};

fn fetchAttempt(
    io: std.Io,
    environ: std.process.Environ,
    scratch: std.mem.Allocator,
    uri: std.Uri,
    out_file: std.Io.File,
    opt: FetchOptions,
) !FetchAttemptResult {
    var client: std.http.Client = .{ .allocator = scratch, .io = io };
    defer client.deinit();
    initProxies(environ, &client, scratch);

    var redirect_buffer: [8196]u8 = undefined;
    // the url we end up at when we follow the redirects ourselves, each one is allocated
    // because it can reference the one before it
    var redirect_uri = uri;
    var redirect_count: u8 = 0;
    // a response points to its request, so the request can't move once it has one
    var request: std.http.Client.Request = undefined;
    var response: std.http.Client.Response = undefined;
    while (true) {
        request = try client.request(.GET, redirect_uri, .{
            .keep_alive = false,
            // the body is written as it arrives, so it must not be compressed
            .headers = .{ .accept_encoding = .omit },
            .redirect_behavior = switch (opt.redirects) {
                .any => .init(max_fetch_redirects),
                .https_only => .unhandled,
            },
        });
        errdefer request.deinit();
        try request.sendBodiless();
        response = try request.receiveHead(&redirect_buffer);
        if (opt.redirects == .any or response.head.status.class() != .redirect) break;

        const location = response.head.location orelse errExit(
            "fetch '{f}': HTTP response {} has no Location",
            .{ redirect_uri, @backingInt(response.head.status) },
        );
        if (redirect_count == max_fetch_redirects) errExit(
            "fetch '{f}': more than {} redirects, the last one to '{s}'",
            .{ uri, max_fetch_redirects, location },
        );
        redirect_count += 1;
        const resolve_buf = scratch.create([2 * max_location_len]u8) catch |e| oom(e);
        const next_uri = resolveLocation(redirect_uri, location, resolve_buf) catch |e| errExit(
            "fetch '{f}': redirects to '{s}', which failed to parse with {t}",
            .{ redirect_uri, location, e },
        );
        if (!std.ascii.eqlIgnoreCase(next_uri.scheme, "https")) errExit(
            "fetch '{f}': redirects to '{f}', which is not an https URL",
            .{ redirect_uri, next_uri },
        );
        redirect_uri = next_uri;
        request.deinit();
    }
    defer request.deinit();
    if (response.head.status != .ok) return errExit(
        "fetch '{f}': HTTP response {} \"{?s}\"",
        .{ uri, @backingInt(response.head.status), response.head.status.phrase() },
    );

    // a previous attempt could have written some of it
    try out_file.setLength(io, 0);
    const maybe_expected_size = blk: {
        if (response.head.content_length) |content_length| {
            if (opt.size) |size| {
                if (size != content_length) errExit(
                    "fetch '{f}': Content-Length {} != expected size {}",
                    .{ uri, content_length, size },
                );
            }
            break :blk content_length;
        }
        break :blk opt.size;
    };
    if (maybe_expected_size) |size| try out_file.setLength(io, size);

    var hasher: std.crypto.hash.sha2.Sha256 = .init(.{});
    var total_received: u64 = 0;

    // The body reader stops at Content-Length, and ends early without an error if the
    // connection closes before that, which the size check below turns into a retry.
    var transfer_buffer: [64]u8 = undefined;
    const body = response.reader(&transfer_buffer);
    while (true) {
        var buf: [@max(std.heap.page_size_min, 4096)]u8 = undefined;
        const len = body.readSliceShort(&buf) catch |err| switch (err) {
            error.ReadFailed => {
                const read_err: anyerror = if (response.bodyErr()) |e|
                    e
                else if (request.connection) |connection|
                    connection.getReadError() orelse err
                else
                    err;
                std.debug.panic("fetch '{f}': read failed with {t}", .{ uri, read_err });
            },
        };
        hasher.update(buf[0..len]);
        // NOTE: not going through a buffered writer since we're writing
        //       large chunks
        out_file.writePositionalAll(io, buf[0..len], total_received) catch |err| std.debug.panic(
            "fetch '{f}': write {} bytes of HTTP response failed with {t}",
            .{ uri, len, err },
        );
        total_received += len;
        if (len < buf.len) break;
    }

    if (maybe_expected_size) |expected| if (total_received != expected) return .{
        .wrong_size = .{ .expected = expected, .received = total_received },
    };

    var sha: Sha = undefined;
    hasher.final(&sha.bytes);
    return .{ .sha = sha };
}

/// The same as std's copyFile with a bigger buffer. Windows can't copy from one file to another
/// in the kernel, so there the buffer is the size of each read and write, and std's is 1KiB.
fn copyFile(io: std.Io, source_path: []const u8, dest_dir: std.Io.Dir, dest_path: []const u8) !void {
    const source = try std.Io.Dir.cwd().openFile(io, source_path, .{});
    defer source.close(io);
    var reader: std.Io.File.Reader = .init(source, io, &.{});
    const stat = try source.stat(io);
    reader.size = stat.size;

    var atomic_file = try dest_dir.createFileAtomic(io, dest_path, .{
        .permissions = stat.permissions,
        .replace = true,
    });
    defer atomic_file.deinit(io);

    var buffer: [64 * 1024]u8 = undefined;
    var writer = atomic_file.file.writer(io, &buffer);
    _ = writer.interface.sendFileAll(&reader, .unlimited) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        error.WriteFailed => return writer.err.?,
    };
    try writer.flush();
    try atomic_file.replace(io);
}

fn readFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !?[]const u8 {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => |e| return e,
    };
    defer file.close(io);
    return try readToEndAlloc(io, file, allocator);
}

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// Resolve ChannelManifest URL
// DownloadChannelManifest
// Download Vs Manifest
// TODO: URL Resolution!
// For sure, I want to track the history of ALL the resolutions for the URLs!
// channel-manifest-url\release\latest
// channel-manifest-url\release\?
// channel-manifest-url\release\1
// channel-manifest-url\preview\

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
        return @fromBackingInt(@intCast(i));
    }
    pub fn int(self: PackageIndex) usize {
        return @backingInt(self);
    }
};
const PayloadIndex = enum(usize) {
    _,
    pub fn fromInt(i: usize) PayloadIndex {
        return @fromBackingInt(@intCast(i));
    }
    pub fn int(self: PayloadIndex) usize {
        return @backingInt(self);
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
    const file_obj = json_file.as(.object, &json_error, parsed.value) catch errExit("{f}", .{json_error});
    const packages_field = file_obj.getField(&json_error, "packages") catch errExit("{f}", .{json_error});
    const packages = packages_field.as(.array, &json_error) catch errExit("{f}", .{json_error});
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
            const pkg_obj_element = packages.getElement(&json_error, pkg_index) catch errExit("{f}", .{json_error});
            const pkg_obj = pkg_obj_element.as(.object, &json_error) catch errExit("{f}", .{json_error});
            const id_field = pkg_obj.getField(&json_error, "id") catch errExit("{f}", .{json_error});
            const id = id_field.as(.string, &json_error) catch errExit("{f}", .{json_error});
            const version_field = pkg_obj.getField(&json_error, "version") catch errExit("{f}", .{json_error});
            const version = version_field.as(.string, &json_error) catch errExit("{f}", .{json_error});
            const language: Language = language_blk: {
                const language_field = pkg_obj.getOptionalField("language") orelse break :language_blk .neutral;
                const language = language_field.as(.string, &json_error) catch errExit("{f}", .{json_error});
                const en_us = "en-US";
                if (std.mem.eql(u8, language, "neutral")) break :language_blk .neutral;
                if (std.mem.eql(u8, language, en_us)) break :language_blk .en_us;
                if (other_languages.getIndex(language)) |i| break :language_blk .{ .other = other_languages.keys()[i] };
                if (std.ascii.eqlIgnoreCase(language, en_us)) std.debug.panic("new {s} casing '{s}'", .{ en_us, language });
                std.debug.panic("unknown language '{s}'", .{language});
            };
            const payloads_offset = payload_count;
            if (pkg_obj.map.get("payloads")) |payloads_field_node| {
                const payloads_field: JsonContext.Field = .init(pkg_obj.parent_context, "payloads", payloads_field_node);
                const payloads = payloads_field.as(.array, &json_error) catch errExit("{f}", .{json_error});
                payload_count += payloads.items.len;
            }
            out_packages[pkg_index] = .{
                .id = allocator.dupe(u8, id) catch |e| oom(e),
                // TODO: maybe we should have a string pool for versions?
                .version = allocator.dupe(u8, version) catch |e| oom(e),
                .language = language,
                .source = .manifest,
                .payloads_offset = payloads_offset,
            };
            out_package_count += 1;
        }

        for (extrapkgs.all) |pkg| {
            // the id of an extra package is PACKAGE-VERSION
            const version = pkg.id[std.mem.indexOfScalar(u8, pkg.id, '-').? + 1 ..];
            out_packages[out_package_count] = .{
                .id = allocator.dupe(u8, pkg.id) catch |e| oom(e),
                .version = allocator.dupe(u8, version) catch |e| oom(e),
                .language = .neutral,
                .source = .extra,
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
        const pkg_obj_element = packages.getElement(&json_error, pkg_index) catch errExit("{f}", .{json_error});
        const pkg_obj = pkg_obj_element.as(.object, &json_error) catch errExit("{f}", .{json_error});
        if (pkg_obj.map.get("payloads")) |payloads_field_node| {
            const payloads_field: JsonContext.Field = .init(pkg_obj.parent_context, "payloads", payloads_field_node);
            const payloads = payloads_field.as(.array, &json_error) catch errExit("{f}", .{json_error});
            // payload_count += payloads.items.len;
            for (0..payloads.items.len) |payload_index| {
                const payload_element = payloads.getElement(&json_error, payload_index) catch errExit("{f}", .{json_error});
                const payload_object = payload_element.as(.object, &json_error) catch errExit("{f}", .{json_error});
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
    list: *std.ArrayList(T),
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
    list: *std.ArrayList(T),
    item: T,
    context: anytype,
    comptime orderFn: fn (@TypeOf(context), T, T) std.math.Order,
) error{OutOfMemory}!void {
    switch (findSortedIndex(T, list, item, context, orderFn)) {
        .already_inserted => return,
        .not_inserted => |i| try list.insert(allocator, i, item),
    }
}

pub fn stdoutFile() std.Io.File {
    return withIoMode(.stdout());
}
pub fn stderrFile() std.Io.File {
    return withIoMode(.stderr());
}

/// std says its stdout and stderr files are opened for synchronous io, which isn't true of the
/// pipes that Git Bash and the other MSYS2 and Cygwin shells make. A write to one of those that
/// can't finish at once is pending when NtWriteFile returns, which std treats as unreachable
/// for a synchronous file.
fn withIoMode(file: std.Io.File) std.Io.File {
    if (builtin.os.tag != .windows) return file;
    var io_status: std.os.windows.IO_STATUS_BLOCK = undefined;
    var info: std.os.windows.FILE.MODE.INFORMATION = undefined;
    switch (std.os.windows.ntdll.NtQueryInformationFile(file.handle, &io_status, &info, @sizeOf(@TypeOf(info)), .Mode)) {
        .SUCCESS => {},
        // there's no file, such as when the handle was closed, and a write to it fails either way
        else => return file,
    }
    var result = file;
    result.flags.nonblocking = info.Mode.IO == .ASYNCHRONOUS;
    return result;
}

fn errExit(comptime fmt: []const u8, args: anytype) noreturn {
    var stderr_buf: [1000]u8 = undefined;
    // through std's debug io, like std.log, so reporting an error doesn't need an Io
    const stderr = std.debug.lockStderr(&stderr_buf).file_writer;
    const maybe_err: ?std.Io.File.Writer.Error = blk: {
        stderr.interface.print(fmt ++ "\n", args) catch break :blk stderr.err.?;
        stderr.interface.flush() catch break :blk stderr.err.?;
        break :blk null;
    };
    std.debug.unlockStderr();
    if (maybe_err) |e| std.debug.panic(
        "error {s} printing another error to stdout",
        .{@errorName(e)},
    );
    std.process.exit(0xff);
}
fn oom(e: error{OutOfMemory}) noreturn {
    @panic(@errorName(e));
}

/// Returns null if the variable isn't set or is empty.
fn getEnv(environ: std.process.Environ, allocator: std.mem.Allocator, comptime name: []const u8) ?[]const u8 {
    if (builtin.os.tag == .windows) {
        const value_w = environ.getWindows(comptime std.unicode.wtf8ToWtf16LeStringLiteral(name)) orelse return null;
        if (value_w.len == 0) return null;
        return std.unicode.wtf16LeToWtf8Alloc(allocator, value_w) catch |e| oom(e);
    }
    const value = environ.getPosix(name) orelse return null;
    if (value.len == 0) return null;
    return value;
}

fn nanoTimestamp(io: std.Io) i96 {
    return std.Io.Clock.real.now(io).toNanoseconds();
}

fn readToEndAlloc(io: std.Io, file: std.Io.File, allocator: std.mem.Allocator) ![]u8 {
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .unlimited) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        error.OutOfMemory => |e| return e,
        error.StreamTooLong => unreachable,
    };
}

fn initProxies(environ: std.process.Environ, client: *std.http.Client, arena: std.mem.Allocator) void {
    var environ_map: std.process.Environ.Map = .init(arena);
    defer environ_map.deinit();
    inline for (.{ "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY" }) |name| {
        if (getEnv(environ, arena, name)) |value| environ_map.put(name, value) catch |e| oom(e);
    }
    client.initDefaultProxies(arena, &environ_map) catch |err| switch (err) {
        error.OutOfMemory => |e| oom(e),
        else => |e| errExit("init proxy failed with {t}", .{e}),
    };
}

const builtin = @import("builtin");
const std = @import("std");
const extrapkgs = @import("extrapkgs");
const wintrace = @import("wintrace");
const Channel = @import("channel.zig").Channel;
const Arch = @import("arch.zig").Arch;
const Arches = @import("arch.zig").Arches;
const MsvcupPackageKind = @import("msvcuppackagekind.zig").MsvcupPackageKind;
const extra = @import("extra.zig");
const AtomicFile = @import("AtomicFile.zig");
const LockFile = @import("LockFile.zig");
const globalfilelocks = @import("globalfilelocks.zig");
const Recipes = @import("Recipes.zig");
const JsonContext = @import("JsonContext.zig");
const StringPool = @import("StringPool.zig");
