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

    const release_version = try makeCalVersion();
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
        if (!zig_atleast_15) {
            if (b.lazyDependency("iobackport", .{})) |iobackport| {
                generate_exe.root_module.addImport("std15", iobackport.module("std15"));
            }
        }
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
    if (!zig_atleast_15) {
        if (b.lazyDependency("iobackport", .{})) |iobackport| {
            msvcup.root_module.addImport("std15", iobackport.module("std15"));
        }
    }
    b.installArtifact(msvcup);

    {
        const run = b.addRunArtifact(msvcup);
        if (b.args) |args| run.addArgs(args);
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
    {
        const unit_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/Recipes.zig"),
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
    if (!zig_atleast_15) {
        if (b.lazyDependency("iobackport", .{})) |iobackport| {
            exe.root_module.addImport("std15", iobackport.module("std15"));
        }
    }
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
        run.addArg("list-payloads");
        // this prints about 20,000 lines, capture it to keep it out of the CI logs
        _ = run.captureStdOut();
        // capturing makes the step cacheable, we still want it to run every time
        run.has_side_effects = true;
        test_step.dependOn(&run.step);
    }
}

fn makeCalVersion() ![11]u8 {
    const now = std.time.epoch.EpochSeconds{ .secs = @intCast(std.time.timestamp()) };
    const day = now.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    var buf: [11]u8 = undefined;
    const formatted = try std.fmt.bufPrint(&buf, "v{d}_{d:0>2}_{d:0>2}", .{
        year_day.year,
        @intFromEnum(month_day.month),
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
    const zip_dep = b.dependency("zipcmdline", .{});
    const host_zip_exe = b.addExecutable(.{
        .name = "zip",
        .root_module = b.createModule(.{
            .root_source_file = zip_dep.path("src/zip.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });

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
        if (!zig_atleast_15) {
            if (b.lazyDependency("iobackport", .{})) |iobackport| {
                msvcup_exe.root_module.addImport("std15", iobackport.module("std15"));
            }
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
    const install_path = b.getInstallPath(.prefix, ".");

    if (target.os.tag == .windows) {
        const out_zip_file = b.pathJoin(&.{
            install_path,
            b.fmt("msvcup-{s}.zip", .{ci_target_str}),
        });
        const zip = b.addRunArtifact(host_zip_exe);
        zip.addArg(out_zip_file);
        zip.addArg("msvcup.exe");
        zip.addArg("msvcup.pdb");
        zip.cwd = .{ .cwd_relative = b.getInstallPath(
            target_install_dir,
            ".",
        ) };
        zip.step.dependOn(install_exes);
        return &zip.step;
    }

    const targz = b.pathJoin(&.{
        install_path,
        b.fmt("msvcup-{s}.tar.gz", .{ci_target_str}),
    });
    const tar = b.addSystemCommand(&.{
        "tar",
        "-czf",
        targz,
        "msvcup",
    });
    tar.cwd = .{ .cwd_relative = b.getInstallPath(
        target_install_dir,
        ".",
    ) };
    tar.step.dependOn(install_exes);
    return &tar.step;
}

pub const zig_atleast_15 = @import("builtin").zig_version.order(.{ .major = 0, .minor = 15, .patch = 0 }) != .lt;

const builtin = @import("builtin");
const std = @import("std");
const ChannelKind = @import("src/channelkind.zig").ChannelKind;
const Arch = @import("src/arch.zig").Arch;
const Arches = @import("src/arch.zig").Arches;
