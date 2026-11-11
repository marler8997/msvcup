//! Tests downloading payloads into the cache with msvcup against a local http server, so it needs
//! no network access.
//!
//! Usage: test-fetch MSVCUP_EXE WORK_DIR

const Response = enum {
    payload,
    /// says it has more bytes than it sends and closes the connection, like the Visual Studio CDN
    short,
    /// a different file than the lock file expects
    wrong,
};

const Route = struct {
    path: []const u8,
    /// the responses for the first requests, then it's always payload
    first: []const Response = &.{},
    /// how long to wait before responding, so that processes overlap
    delay_ms: u64 = 0,
    request_count: std.atomic.Value(u32) = .init(0),
};

const payload_zip = makeZip("payload");
const wrong_zip = makeZip("this is not the expected payload");

pub fn main(init: std.process.Init.Minimal) !void {
    var arena_instance: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const arena = arena_instance.allocator();
    var threaded: std.Io.Threaded = .init(arena, .{ .environ = init.environ, .argv0 = .init(init.args) });
    defer threaded.deinit();
    const io = threaded.io();
    const args = try init.args.toSlice(arena);
    if (args.len != 3) fail("expected MSVCUP_EXE WORK_DIR but got {} args", .{args.len - 1});
    // msvcup runs in the work directory and the build gives us a relative path
    const msvcup_exe = try std.Io.Dir.cwd().realPathFileAlloc(io, args[1], arena);
    (try std.Thread.spawn(.{}, watchdog, .{io})).detach();
    var env_map_instance = try init.environ.createMap(arena);
    const env_map = &env_map_instance;
    // the requests are all local
    for ([_][]const u8{ "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY" }) |name| _ = env_map.swapRemove(name);
    var routes = [_]Route{
        .{ .path = "/concurrent/p.vsix", .delay_ms = 500 },
        .{ .path = "/retry/p.vsix", .first = &.{.short} },
        // msvcup tries 3 times
        .{ .path = "/gives-up/p.vsix", .first = &.{ .short, .short, .short } },
        .{ .path = "/mismatch/p.vsix", .first = &.{.wrong} },
        .{ .path = "/concurrent-mismatch/p.vsix", .first = &.{.wrong}, .delay_ms = 500 },
        .{ .path = "/crash/p.vsix" },
    };
    const payload_sha = shaHex(&payload_zip);
    const wrong_sha = shaHex(&wrong_zip);

    try std.Io.Dir.cwd().deleteTree(io, args[2]);
    var work_dir = try std.Io.Dir.cwd().createDirPathOpen(io, args[2], .{});
    defer work_dir.close(io);
    const work_path = try work_dir.realPathFileAlloc(io, ".", arena);

    const address: std.Io.net.IpAddress = try .parseIp4("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    (try std.Thread.spawn(.{}, serve, .{ io, &server, &routes })).detach();

    const test_env: Env = .{
        .io = io,
        .arena = arena,
        .msvcup_exe = msvcup_exe,
        .work_path = work_path,
        .work_dir = work_dir,
        .port = port,
        .env_map = env_map,
        .routes = &routes,
        .payload_sha = payload_sha,
        .wrong_sha = wrong_sha,
        .payload_name = try std.fmt.allocPrint(arena, "{s}-p.vsix", .{&payload_sha}),
    };
    try test_env.concurrent();
    try test_env.concurrentMismatch();
    try test_env.retry();
    try test_env.givesUp();
    try test_env.mismatch();
    try test_env.crashLeftover();

    // the server thread is blocked in accept, closing its socket from here can hang
    std.process.exit(0);
}

const Env = struct {
    io: std.Io,
    arena: std.mem.Allocator,
    msvcup_exe: []const u8,
    work_path: []const u8,
    work_dir: std.Io.Dir,
    port: u16,
    env_map: *const std.process.Environ.Map,
    routes: []Route,
    payload_sha: [64]u8,
    wrong_sha: [64]u8,
    payload_name: []const u8,

    fn writeLock(env: Env, name: []const u8, url_path: []const u8) !void {
        try env.work_dir.writeFile(env.io, .{ .sub_path = name, .data = try std.fmt.allocPrint(
            env.arena,
            "diasdk-1.0|http://127.0.0.1:{}{s}|{s}\n",
            .{ env.port, url_path, &env.payload_sha },
        ) });
    }

    fn argv(env: Env, cache: []const u8, inst: []const u8, lock: []const u8) ![]const []const u8 {
        return env.arena.dupe([]const u8, &.{
            env.msvcup_exe, "install",               inst,         "--cache-dir", cache, "--lock-file",
            lock,           "--manifest-update-off", "diasdk-1.0",
        });
    }

    fn run(env: Env, cache: []const u8, inst: []const u8, lock: []const u8) !std.process.RunResult {
        return std.process.run(env.arena, env.io, .{
            .cwd = .{ .path = env.work_path },
            .environ_map = env.env_map,
            .argv = try env.argv(cache, inst, lock),
            .stdout_limit = .limited(10 * 1024 * 1024),
            .stderr_limit = .limited(10 * 1024 * 1024),
        });
    }

    fn expectInstalled(env: Env, cache: []const u8, inst: []const u8, lock: []const u8) !void {
        const result = try env.run(cache, inst, lock);
        if (result.term != .exited or result.term.exited != 0) fail("install '{s}' failed with {}:\n{s}", .{ inst, result.term, result.stderr });
        try env.expectFile(try std.fmt.allocPrint(env.arena, "{s}/pkg/file.txt", .{inst}), zip_content);
    }

    /// Starts an install without waiting for it, for overlapping with others. Call waitInstall on it.
    fn spawnInstall(env: Env, cache: []const u8, inst: []const u8, lock: []const u8) !std.process.Child {
        return std.process.spawn(env.io, .{
            .argv = try env.argv(cache, inst, lock),
            .cwd = .{ .path = env.work_path },
            .environ_map = env.env_map,
            .stdout = .ignore,
            .stderr = .pipe,
        });
    }

    /// Reading these one at a time is ok, an install of one payload logs far less than a pipe holds.
    fn waitInstall(env: Env, child: *std.process.Child) !struct { term: std.process.Child.Term, stderr: []const u8 } {
        var reader = child.stderr.?.reader(env.io, &.{});
        const stderr = reader.interface.allocRemaining(env.arena, .limited(10 * 1024 * 1024)) catch |err| switch (err) {
            error.ReadFailed => return reader.err.?,
            else => |e| return e,
        };
        return .{ .term = try child.wait(env.io), .stderr = stderr };
    }

    fn expectFile(env: Env, path: []const u8, expected: []const u8) !void {
        var buf: [1000]u8 = undefined;
        const actual = env.work_dir.readFile(env.io, path, &buf) catch |e| fail("read '{s}' failed with {t}", .{ path, e });
        if (!std.mem.eql(u8, actual, expected)) fail("'{s}' has the wrong content", .{path});
    }

    /// Checks the cache contains exactly these names, which leaves out any lock or temporary file.
    fn expectCache(env: Env, cache: []const u8, expected: []const []const u8) !void {
        var dir = try env.work_dir.openDir(env.io, cache, .{ .iterate = true });
        defer dir.close(env.io);
        var count: usize = 0;
        var it = dir.iterate();
        while (try it.next(env.io)) |entry| {
            count += 1;
            for (expected) |name| {
                if (std.mem.eql(u8, entry.name, name)) break;
            } else fail("unexpected file '{s}' in cache '{s}'", .{ entry.name, cache });
        }
        if (count != expected.len) fail("cache '{s}' has {} files but expected {}", .{ cache, count, expected.len });
    }

    /// Only one process downloads a payload, the others wait for it.
    fn concurrent(env: Env) !void {
        const process_count = 8;
        try env.work_dir.createDir(env.io, "concurrent", .default_dir);
        try env.writeLock("concurrent.lock", "/concurrent/p.vsix");
        var children: [process_count]std.process.Child = undefined;
        var insts: [process_count][]const u8 = undefined;
        for (&children, &insts, 0..) |*child, *inst, i| {
            inst.* = try std.fmt.allocPrint(env.arena, "concurrent-inst{}", .{i});
            child.* = try env.spawnInstall("concurrent", inst.*, "concurrent.lock");
        }
        for (&children, insts) |*child, inst| {
            const result = try env.waitInstall(child);
            if (result.term != .exited or result.term.exited != 0) fail("process installing '{s}' failed with {}:\n{s}", .{ inst, result.term, result.stderr });
            try env.expectFile(try std.fmt.allocPrint(env.arena, "{s}/pkg/file.txt", .{inst}), zip_content);
        }
        const count = routeNamed(env.routes, "/concurrent/p.vsix").request_count.load(.acquire);
        if (count != 1) fail("{} processes made {} downloads, expected 1", .{ process_count, count });
        try env.expectCache("concurrent", &.{env.payload_name});
    }

    /// Whoever gets the wrong file keeps it under its actual hash. The ones waiting on it can't
    /// touch that file, one of them downloads the payload and the others find it.
    fn concurrentMismatch(env: Env) !void {
        const process_count = 4;
        try env.work_dir.createDir(env.io, "concurrent-mismatch", .default_dir);
        try env.writeLock("concurrent-mismatch.lock", "/concurrent-mismatch/p.vsix");
        var children: [process_count]std.process.Child = undefined;
        var insts: [process_count][]const u8 = undefined;
        for (&children, &insts, 0..) |*child, *inst, i| {
            inst.* = try std.fmt.allocPrint(env.arena, "concurrent-mismatch-inst{}", .{i});
            child.* = try env.spawnInstall("concurrent-mismatch", inst.*, "concurrent-mismatch.lock");
        }
        var failed: u32 = 0;
        for (&children, insts) |*child, inst| {
            const result = try env.waitInstall(child);
            if (result.term != .exited or (result.term.exited != 0 and result.term.exited != 0xff)) fail("process installing '{s}' failed with {}:\n{s}", .{ inst, result.term, result.stderr });
            if (result.term.exited != 0) {
                failed += 1;
                if (std.mem.indexOf(u8, result.stderr, "SHA256 mismatch") == null) fail("wrong error:\n{s}", .{result.stderr});
                continue;
            }
            try env.expectFile(try std.fmt.allocPrint(env.arena, "{s}/pkg/file.txt", .{inst}), zip_content);
        }
        if (failed != 1) fail("{} processes got the mismatch, expected 1", .{failed});
        const count = routeNamed(env.routes, "/concurrent-mismatch/p.vsix").request_count.load(.acquire);
        if (count != 2) fail("{} downloads, expected 2", .{count});
        const wrong_name = try std.fmt.allocPrint(env.arena, "{s}-p.vsix", .{&env.wrong_sha});
        try env.expectCache("concurrent-mismatch", &.{ wrong_name, env.payload_name });
        try env.expectFile(try std.fmt.allocPrint(env.arena, "concurrent-mismatch/{s}", .{wrong_name}), &wrong_zip);
        try env.expectFile(try std.fmt.allocPrint(env.arena, "concurrent-mismatch/{s}", .{env.payload_name}), &payload_zip);
    }

    /// A download that ends early gets tried again.
    fn retry(env: Env) !void {
        try env.work_dir.createDir(env.io, "retry", .default_dir);
        try env.writeLock("retry.lock", "/retry/p.vsix");
        try env.expectInstalled("retry", "retry-inst", "retry.lock");
        const count = routeNamed(env.routes, "/retry/p.vsix").request_count.load(.acquire);
        if (count != 2) fail("retry made {} requests, expected 2", .{count});
        try env.expectCache("retry", &.{env.payload_name});
        // nothing from the short attempt can be left in it
        try env.expectFile(try std.fmt.allocPrint(env.arena, "retry/{s}", .{env.payload_name}), &payload_zip);
    }

    /// Failing leaves no payload, and the next run can still get it.
    fn givesUp(env: Env) !void {
        try env.work_dir.createDir(env.io, "gives-up", .default_dir);
        try env.writeLock("gives-up.lock", "/gives-up/p.vsix");
        const result = try env.run("gives-up", "gives-up-inst", "gives-up.lock");
        if (result.term != .exited or result.term.exited != 0xff) fail("expected failure but got {}:\n{s}", .{ result.term, result.stderr });
        if (std.mem.indexOf(u8, result.stderr, "gave up") == null) fail("wrong error:\n{s}", .{result.stderr});
        var cache = try env.work_dir.openDir(env.io, "gives-up", .{});
        defer cache.close(env.io);
        if (cache.access(env.io, env.payload_name, .{})) {
            fail("a failed download is in the cache", .{});
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => |e| fail("access '{s}' failed with {t}", .{ env.payload_name, e }),
        }
        try env.expectInstalled("gives-up", "gives-up-inst", "gives-up.lock");
        try env.expectCache("gives-up", &.{env.payload_name});
    }

    /// The wrong file is kept under its actual hash, never the hash we were expecting.
    fn mismatch(env: Env) !void {
        try env.work_dir.createDir(env.io, "mismatch", .default_dir);
        try env.writeLock("mismatch.lock", "/mismatch/p.vsix");
        const result = try env.run("mismatch", "mismatch-inst", "mismatch.lock");
        if (result.term != .exited or result.term.exited != 0xff) fail("expected failure but got {}:\n{s}", .{ result.term, result.stderr });
        if (std.mem.indexOf(u8, result.stderr, "SHA256 mismatch") == null) fail("wrong error:\n{s}", .{result.stderr});
        const wrong_name = try std.fmt.allocPrint(env.arena, "{s}-p.vsix", .{&env.wrong_sha});
        try env.expectCache("mismatch", &.{wrong_name});
        try env.expectInstalled("mismatch", "mismatch-inst", "mismatch.lock");
        try env.expectCache("mismatch", &.{ wrong_name, env.payload_name });
    }

    /// A process that died partway through a download leaves its temporary file behind.
    fn crashLeftover(env: Env) !void {
        try env.work_dir.createDir(env.io, "crash", .default_dir);
        try env.writeLock("crash.lock", "/crash/p.vsix");
        var cache = try env.work_dir.openDir(env.io, "crash", .{});
        defer cache.close(env.io);
        // bigger than the payload to make sure it gets truncated
        try cache.writeFile(env.io, .{
            .sub_path = try std.fmt.allocPrint(env.arena, "{s}.fetching", .{env.payload_name}),
            .data = &@as([7000]u8, @splat('x')),
        });
        try env.expectInstalled("crash", "crash-inst", "crash.lock");
        try env.expectCache("crash", &.{env.payload_name});
        try env.expectFile(try std.fmt.allocPrint(env.arena, "crash/{s}", .{env.payload_name}), &payload_zip);
    }
};

/// A bug here could easily be a hang, this fails with a clear message rather than waiting for CI
/// to time out.
fn watchdog(io: std.Io) void {
    io.sleep(.fromSeconds(120), .awake) catch {};
    fail("still running after 120 seconds", .{});
}

fn routeNamed(routes: []Route, path: []const u8) *Route {
    for (routes) |*route| {
        if (std.mem.eql(u8, route.path, path)) return route;
    }
    fail("unknown route '{s}'", .{path});
}

fn serve(io: std.Io, server: *std.Io.net.Server, routes: []Route) void {
    while (true) {
        const stream = server.accept(io) catch |e| fail("accept failed with {t}", .{e});
        const thread = std.Thread.spawn(.{}, handle, .{ io, stream, routes }) catch |e|
            fail("spawning a thread failed with {t}", .{e});
        thread.detach();
    }
}

fn handle(io: std.Io, stream: std.Io.net.Stream, routes: []Route) void {
    defer stream.close(io);
    var recv_buf: [8192]u8 = undefined;
    var reader = stream.reader(io, &recv_buf);
    var writer = stream.writer(io, &.{});
    handleRequest(io, &reader.interface, &writer.interface, routes) catch |err| switch (err) {
        // msvcup is allowed to go away, it's the one that reports if that's wrong
        error.ReadFailed, error.WriteFailed, error.EndOfStream => {},
        else => |e| fail("handling a request failed with {t}", .{e}),
    };
}

fn handleRequest(io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer, routes: []Route) !void {
    const request_line = try reader.takeDelimiterInclusive('\n');
    var parts = std.mem.splitScalar(u8, request_line, ' ');
    _ = parts.next();
    const route = routeNamed(routes, parts.next() orelse fail("bad request '{s}'", .{request_line}));
    // the rest of the headers
    while ((try reader.takeDelimiterInclusive('\n')).len > 2) {}
    const request_index = route.request_count.fetchAdd(1, .acq_rel);
    try io.sleep(.fromMilliseconds(@intCast(route.delay_ms)), .awake);

    const response: Response = if (request_index < route.first.len) route.first[request_index] else .payload;
    const body: []const u8 = switch (response) {
        .payload, .short => &payload_zip,
        .wrong => &wrong_zip,
    };
    var header_buf: [200]u8 = undefined;
    const header = try std.fmt.bufPrint(
        &header_buf,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        .{if (response == .short) body.len + 1000 else body.len},
    );
    try writer.writeAll(header);
    try writer.writeAll(body);
    try writer.flush();
}

fn shaHex(data: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

const zip_name = "Contents/pkg/file.txt";
const zip_content = "payload";

/// A vsix, which is a zip whose installed files are under "Contents/", with one file stored
/// without compression. The test only needs it to install "payload" at pkg/file.txt so both zips
/// have that content, the wrong one just has a different comment so its hash differs.
fn makeZip(comptime comment: []const u8) [zipLen(comment)]u8 {
    comptime {
        @setEvalBranchQuota(100000);
        const content = zip_content;
        var out: [zipLen(comment)]u8 = undefined;
        var offset: usize = 0;
        const put = struct {
            fn bytes(o: *[zipLen(comment)]u8, i: *usize, data: []const u8) void {
                @memcpy(o[i.*..][0..data.len], data);
                i.* += data.len;
            }
            fn int(o: *[zipLen(comment)]u8, i: *usize, comptime T: type, value: T) void {
                std.mem.writeInt(T, o[i.*..][0..@sizeOf(T)], value, .little);
                i.* += @sizeOf(T);
            }
        };
        const crc = std.hash.Crc32.hash(content);
        put.int(&out, &offset, u32, 0x04034b50);
        put.int(&out, &offset, u16, 20);
        put.int(&out, &offset, u16, 0);
        put.int(&out, &offset, u16, 0);
        put.int(&out, &offset, u32, 0);
        put.int(&out, &offset, u32, crc);
        put.int(&out, &offset, u32, content.len);
        put.int(&out, &offset, u32, content.len);
        put.int(&out, &offset, u16, zip_name.len);
        put.int(&out, &offset, u16, 0);
        put.bytes(&out, &offset, zip_name);
        put.bytes(&out, &offset, content);
        const central_offset = offset;
        put.int(&out, &offset, u32, 0x02014b50);
        put.int(&out, &offset, u16, 20);
        put.int(&out, &offset, u16, 20);
        put.int(&out, &offset, u16, 0);
        put.int(&out, &offset, u16, 0);
        put.int(&out, &offset, u32, 0);
        put.int(&out, &offset, u32, crc);
        put.int(&out, &offset, u32, content.len);
        put.int(&out, &offset, u32, content.len);
        put.int(&out, &offset, u16, zip_name.len);
        put.int(&out, &offset, u16, 0);
        put.int(&out, &offset, u16, 0);
        put.int(&out, &offset, u16, 0);
        put.int(&out, &offset, u16, 0);
        put.int(&out, &offset, u32, 0);
        put.int(&out, &offset, u32, 0);
        put.bytes(&out, &offset, zip_name);
        const central_len = offset - central_offset;
        put.int(&out, &offset, u32, 0x06054b50);
        put.int(&out, &offset, u16, 0);
        put.int(&out, &offset, u16, 0);
        put.int(&out, &offset, u16, 1);
        put.int(&out, &offset, u16, 1);
        put.int(&out, &offset, u32, central_len);
        put.int(&out, &offset, u32, central_offset);
        put.int(&out, &offset, u16, comment.len);
        put.bytes(&out, &offset, comment);
        const result = out;
        return result;
    }
}

fn zipLen(comptime comment: []const u8) usize {
    return 30 + zip_name.len + zip_content.len + 46 + zip_name.len + 22 + comment.len;
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("error: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

const std = @import("std");
