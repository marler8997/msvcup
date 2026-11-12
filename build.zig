pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const autoenv_cpu: Arch = b.option(Arch, "autoenv-target", "") orelse switch (target.result.cpu.arch) {
        .x86_64 => .x64,
        .x86 => .x64,
        .aarch64 => .arm64,
        .arm => .arm,
        // whatever, we'll just use x64 for now
        else => .x64,
    };

    const release_version = try makeCalVersion(b.graph.io);
    const dev_version = b.fmt("{s}-dev", .{release_version});
    const write_files_version = b.addWriteFiles();
    const release_version_file = write_files_version.add("version-release", &release_version);
    const release_version_embed = b.createModule(.{
        .root_source_file = release_version_file,
    });
    const dev_version_embed = b.createModule(.{
        .root_source_file = write_files_version.add("version-dev", dev_version),
    });

    const extrapkgs_mod = blk: {
        const generate_exe = b.addExecutable(.{
            .name = "generate-extrapkgs",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/generate-extrapkgs.zig"),
                .target = b.graph.host,
                .optimize = .Debug,
                .single_threaded = true,
            }),
        });
        const run = b.addRunArtifact(generate_exe);
        run.addFileArg(b.path("extrapkgs.lock"));
        break :blk b.createModule(.{
            .root_source_file = run.addOutputFileArg("extrapkgs.zig"),
        });
    };

    const msi = b.dependency("msi", .{}).module("msi");
    // msi includes the decompression code which we need to be fast
    msi.optimize = .ReleaseFast;

    const msvcup = b.addExecutable(.{
        .name = "msvcup",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/msvcup.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = &.{
                .{ .name = "version", .module = dev_version_embed },
                .{ .name = "extrapkgs", .module = extrapkgs_mod },
                .{ .name = "autoenv_exe", .module = b.createModule(.{
                    .root_source_file = addAutoenvExe(b, autoenv_cpu).getEmittedBin(),
                }) },
                .{ .name = "msi", .module = msi },
            },
        }),
    });
    if (target.result.os.tag == .windows) {
        if (b.lazyDependency("wintrace", .{})) |dep| msvcup.root_module.addImport("wintrace", dep.module("wintrace"));
    }
    b.installArtifact(msvcup);

    {
        const run = b.addRunArtifact(msvcup);
        run.addPassthruArgs();
        b.step("run", "").dependOn(&run.step);
    }

    const test_step = b.step("test", "");
    addTests(b, msvcup, test_step);
    {
        const step = b.step("test-atomicfile", "Stress AtomicFile with multiple processes");
        test_step.dependOn(step);
        // Native builds on windows get POSIX delete and rename, a build for the default minimum
        // windows version like our releases doesn't, and files behave differently without them.
        const targets: []const std.Build.ResolvedTarget = if (builtin.os.tag == .windows)
            &.{ b.graph.host, b.resolveTargetQuery(.{ .cpu_arch = builtin.cpu.arch, .os_tag = .windows }) }
        else
            &.{b.graph.host};
        for (targets) |stress_target| {
            const exe = b.addExecutable(.{
                .name = "test-atomicfile",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("src/test-atomicfile.zig"),
                    .target = stress_target,
                    .optimize = .Debug,
                }),
            });
            const run = b.addRunArtifact(exe);
            _ = run.addOutputDirectoryArg("atomicfile");
            run.has_side_effects = true;
            step.dependOn(&run.step);
        }
    }
    {
        const exe = b.addExecutable(.{
            .name = "test-fetch",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/test-fetch.zig"),
                .target = b.graph.host,
                .optimize = .Debug,
            }),
        });
        const run = b.addRunArtifact(exe);
        run.addArtifactArg(msvcup);
        _ = run.addOutputDirectoryArg("fetch");
        run.has_side_effects = true;
        const step = b.step("test-fetch", "Download payloads from a local server");
        step.dependOn(&run.step);
        test_step.dependOn(step);
    }
    {
        const exe = b.addExecutable(.{
            .name = "test-lockfile",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/test-lockfile.zig"),
                .target = b.graph.host,
                .optimize = .Debug,
            }),
        });
        const run = b.addRunArtifact(exe);
        _ = run.addOutputDirectoryArg("lockfile");
        run.has_side_effects = true;
        const step = b.step("test-lockfile", "Check that only one process can hold a LockFile");
        step.dependOn(&run.step);
        test_step.dependOn(step);
    }
    for ([_][]const u8{ "src/Recipes.zig", "src/channel.zig" }) |path| {
        const unit_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(path),
                .target = target,
                .optimize = optimize,
            }),
        });
        test_step.dependOn(&b.addRunArtifact(unit_tests).step);
    }

    for ([_]struct { name: []const u8, files: []const []const u8 }{
        .{ .name = "handmade", .files = &.{ "build.bat", "hello.c", "msvc.lock" } },
        .{ .name = "cmake", .files = &.{ "build.bat", "CMakeLists.txt", "hello.c", "msvc.lock" } },
    }) |example| {
        const example_dir = b.fmt("examples/{s}", .{example.name});
        {
            // runs the example in place, build.bat downloads the msvcup release if it's
            // not already there
            const run = addExampleRun(b, example_dir);
            const step = b.step(b.fmt("test-example-{s}-release", .{example.name}), "");
            step.dependOn(&run.step);
            if (builtin.os.tag == .windows) test_step.dependOn(step);
        }
        {
            // runs a copy of the example with the msvcup we just built next to build.bat,
            // which it uses instead of downloading the release. The directory doesn't
            // depend on a hash so each new msvcup reuses the install rather than leaving
            // another one in the cache.
            const copy_dir = b.fmt(".zig-cache/examples/{s}", .{example.name});
            const copy = b.addUpdateSourceFiles();
            for (example.files) |file| copy.addCopyFileToSource(
                b.path(b.fmt("{s}/{s}", .{ example_dir, file })),
                b.fmt("{s}/{s}", .{ copy_dir, file }),
            );
            copy.addCopyFileToSource(msvcup.getEmittedBin(), b.fmt("{s}/msvcup.exe", .{copy_dir}));
            const run = addExampleRun(b, copy_dir);
            run.step.dependOn(&copy.step);
            const step = b.step(b.fmt("test-example-{s}-head", .{example.name}), "");
            step.dependOn(&run.step);
            if (builtin.os.tag == .windows) test_step.dependOn(step);
        }
    }

    const release_step = b.step("release", "Build/archive release executables for all targets and test the native one");
    release_step.dependOn(&b.addInstallFile(release_version_file, "version-release").step);
    try addRelease(b, release_version_embed, msi, extrapkgs_mod, autoenv_cpu, release_step);
}

fn addAutoenvExe(b: *std.Build, cpu: Arch) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = "autoenv",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/autoenv.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = switch (cpu) {
                    .x64 => .x86_64,
                    .x86 => .x86,
                    .arm => .arm,
                    .arm64 => .aarch64,
                },
                .os_tag = .windows,
            }),
            .optimize = .ReleaseSmall,
            .single_threaded = true,
            .pic = true,
        }),
    });
    if (b.lazyDependency("wintrace", .{})) |dep| exe.root_module.addImport("wintrace", dep.module("wintrace"));
    return exe;
}

fn addExampleRun(b: *std.Build, dir: []const u8) *std.Build.Step.Run {
    const run = b.addSystemCommand(&.{ "cmd.exe", "/c", "build.bat" });
    run.cwd = b.path(dir);
    run.has_side_effects = true;
    return run;
}

fn addTests(b: *std.Build, msvcup: *std.Build.Step.Compile, test_step: *std.Build.Step) void {
    {
        const run = b.addRunArtifact(msvcup);
        run.addArg("list");
        test_step.dependOn(&run.step);
    }
    {
        const run = b.addRunArtifact(msvcup);
        run.addArg("list-channels");
        run.expectStdOutEqual(
            \\vs17-release    https://aka.ms/vs/17/release/channel
            \\vs17-preview    https://aka.ms/vs/17/pre/channel
            \\vs18-stable     https://aka.ms/vs/18/stable/channel
            \\vs18-insiders   https://aka.ms/vs/18/insiders/channel
            \\
        );
        test_step.dependOn(&run.step);
    }
    const unknown_channel = "unknown channel '{s}', 'msvcup list-channels' shows the known channels, a URL must start with https://\n";
    for ([_]struct { args: []const []const u8, stderr: []const u8 }{
        .{ .args = &.{ "list", "--channel", "vs19-stable" }, .stderr = b.fmt(unknown_channel, .{"vs19-stable"}) },
        .{ .args = &.{ "list", "--channel", "http://example.com/channel" }, .stderr = b.fmt(unknown_channel, .{"http://example.com/channel"}) },
        .{ .args = &.{ "list-payloads", "--channel", "vs19-stable" }, .stderr = b.fmt(unknown_channel, .{"vs19-stable"}) },
        .{ .args = &.{ "install", "--channel", "vs19-stable" }, .stderr = b.fmt(unknown_channel, .{"vs19-stable"}) },
        .{ .args = &.{ "list", "--channel" }, .stderr = "--channel missing argument\n" },
        .{ .args = &.{ "list-payloads", "--channel" }, .stderr = "--channel missing argument\n" },
        .{ .args = &.{ "install", "--channel" }, .stderr = "--channel missing argument\n" },
        .{ .args = &.{ "list", "foo" }, .stderr = "list: unknown argument 'foo'\n" },
        .{ .args = &.{ "list-payloads", "foo" }, .stderr = "list-payloads: unknown argument 'foo'\n" },
        .{ .args = &.{ "list-channels", "foo" }, .stderr = "list-channels: unknown argument 'foo'\n" },
        // starts with https:// so it's a URL, the error says what's wrong with it
        .{ .args = &.{ "list", "--channel", "https://example.com:port/channel" }, .stderr = "invalid channel URL 'https://example.com:port/channel': InvalidPort\n" },
        .{ .args = &.{ "install", "--channel", "https:///channel" }, .stderr = "channel URL 'https:///channel' has no host\n" },
    }) |case| {
        const run = b.addRunArtifact(msvcup);
        run.addArgs(case.args);
        run.expectExitCode(0xff);
        run.expectStdErrEqual(case.stderr);
        test_step.dependOn(&run.step);
    }
    {
        const run = b.addRunArtifact(msvcup);
        run.addArg("list-payloads");
        // this prints about 20,000 lines, capture it to keep it out of the CI logs
        _ = run.captureStdOut(.{});
        // capturing makes the step cacheable, we still want it to run every time
        run.has_side_effects = true;
        test_step.dependOn(&run.step);
    }
}

fn makeCalVersion(io: std.Io) ![11]u8 {
    const now = std.time.epoch.EpochSeconds{ .secs = @intCast(std.Io.Clock.real.now(io).toSeconds()) };
    const day = now.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    var buf: [11]u8 = undefined;
    const formatted = try std.fmt.bufPrint(&buf, "v{d}_{d:0>2}_{d:0>2}", .{
        year_day.year,
        @backingInt(month_day.month),
        month_day.day_index + 1,
    });
    std.debug.assert(formatted.len == buf.len);
    return buf;
}

fn addRelease(
    b: *std.Build,
    release_version_embed: *std.Build.Module,
    msi: *std.Build.Module,
    extrapkgs_mod: *std.Build.Module,
    autoenv_cpu: Arch,
    release_step: *std.Build.Step,
) !void {
    // zipcmdline builds its exes with a patched std, so use its artifact, its source doesn't
    // compile on its own
    const host_zip_exe = b.dependency("zipcmdline", .{}).artifact("zip");

    const ci_targets = [_][]const u8{
        "aarch64-linux",
        "aarch64-macos",
        "aarch64-windows",
        "arm-linux",
        "powerpc64le-linux",
        "riscv64-linux",
        "s390x-linux",
        "x86-linux",
        "x86-windows",
        "x86_64-linux",
        "x86_64-macos",
        "x86_64-windows",
    };

    const make_archive_step = b.step("archive", "Create release archives");
    release_step.dependOn(make_archive_step);

    for (ci_targets) |ci_target_str| {
        const target = b.resolveTargetQuery(try std.Target.Query.parse(
            .{ .arch_os_abi = ci_target_str },
        ));
        const optimize: std.builtin.OptimizeMode = .ReleaseSafe;

        const target_dest_dir: std.Build.InstallDir = .{ .custom = ci_target_str };

        const install_exes = b.step(b.fmt("install-{s}", .{ci_target_str}), "");
        release_step.dependOn(install_exes);
        const msvcup_exe = b.addExecutable(.{
            .name = "msvcup",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/msvcup.zig"),
                .target = target,
                .optimize = optimize,
                .single_threaded = true,
                .imports = &.{
                    .{ .name = "version", .module = release_version_embed },
                    .{ .name = "extrapkgs", .module = extrapkgs_mod },
                    .{ .name = "autoenv_exe", .module = b.createModule(.{
                        .root_source_file = addAutoenvExe(b, autoenv_cpu).getEmittedBin(),
                    }) },
                    .{ .name = "msi", .module = msi },
                },
            }),
        });
        if (target.result.os.tag == .windows) {
            if (b.lazyDependency("wintrace", .{})) |dep| msvcup_exe.root_module.addImport("wintrace", dep.module("wintrace"));
        }
        install_exes.dependOn(
            &b.addInstallArtifact(msvcup_exe, .{ .dest_dir = .{ .override = target_dest_dir } }).step,
        );

        const target_test_step = b.step(b.fmt("test-{s}", .{ci_target_str}), "");
        addTests(b, msvcup_exe, target_test_step);
        const os_compatible = (builtin.os.tag == target.result.os.tag);
        const arch_compatible = (builtin.cpu.arch == target.result.cpu.arch);
        if (os_compatible and arch_compatible) {
            release_step.dependOn(target_test_step);
        }

        if (builtin.os.tag == .linux and builtin.cpu.arch == .x86_64) {
            make_archive_step.dependOn(makeCiArchiveStep(
                b,
                ci_target_str,
                target.result,
                target_dest_dir,
                install_exes,
                host_zip_exe,
            ));
        }
    }
}

fn makeCiArchiveStep(
    b: *std.Build,
    ci_target_str: []const u8,
    target: std.Target,
    target_install_dir: std.Build.InstallDir,
    install_exes: *std.Build.Step,
    host_zip_exe: *std.Build.Step.Compile,
) *std.Build.Step {
    const archive_dir: std.Build.LazyPath = .{ .relative = .{
        .base = .install_prefix,
        .sub_path = target_install_dir.custom,
    } };

    if (target.os.tag == .windows) {
        const zip = b.addRunArtifact(host_zip_exe);
        zip.addFileArg(.{ .relative = .{
            .base = .install_prefix,
            .sub_path = b.fmt("msvcup-{s}.zip", .{ci_target_str}),
        } });
        zip.addArg("msvcup.exe");
        zip.addArg("msvcup.pdb");
        zip.setCwd(archive_dir);
        zip.step.dependOn(install_exes);
        return &zip.step;
    }

    const tar = b.addSystemCommand(&.{ "tar", "-czf" });
    tar.addFileArg(.{ .relative = .{
        .base = .install_prefix,
        .sub_path = b.fmt("msvcup-{s}.tar.gz", .{ci_target_str}),
    } });
    tar.addArg("msvcup");
    tar.setCwd(archive_dir);
    tar.step.dependOn(install_exes);
    return &tar.step;
}

const builtin = @import("builtin");
const std = @import("std");
const Arch = @import("src/arch.zig").Arch;
const Arches = @import("src/arch.zig").Arches;
