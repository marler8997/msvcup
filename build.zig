pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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
    b.getInstallStep().dependOn(&b.addInstallFile(release_version_file, "version-release").step);

    const msvcup = b.addExecutable(.{
        .name = "msvcup",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/msvcup.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = &.{
                .{ .name = "version", .module = dev_version_embed },
            },
        }),
    });
    b.installArtifact(msvcup);

    {
        const run = b.addRunArtifact(msvcup);
        if (b.args) |args| run.addArgs(args);
        b.step("run", "").dependOn(&run.step);
    }

    const test_step = b.step("test", "");
    addTests(b, msvcup, test_step);

    const ci_step = b.step("ci", "The build/test step to run on the CI");
    ci_step.dependOn(b.getInstallStep());
    ci_step.dependOn(test_step);
    try ci(b, release_version_embed, ci_step);
}

fn addTests(b: *std.Build, msvcup: *std.Build.Step.Compile, test_step: *std.Build.Step) void {
    {
        const run = b.addRunArtifact(msvcup);
        run.addArg("list");
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
        month_day.day_index,
    });
    std.debug.assert(formatted.len == buf.len);
    return buf;
}

fn ci(
    b: *std.Build,
    release_version_embed: *std.Build.Module,
    ci_step: *std.Build.Step,
) !void {
    const zip_dep = b.dependency("zipcmdline", .{});
    const host_zip_exe = b.addExecutable(.{
        .name = "zip",
        .root_source_file = zip_dep.path("src/zip.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
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

    const make_archive_step = b.step("archive", "Create CI archives");
    ci_step.dependOn(make_archive_step);

    for (ci_targets) |ci_target_str| {
        const target = b.resolveTargetQuery(try std.Target.Query.parse(
            .{ .arch_os_abi = ci_target_str },
        ));
        const optimize: std.builtin.OptimizeMode = .ReleaseSafe;

        const target_dest_dir: std.Build.InstallDir = .{ .custom = ci_target_str };

        const install_exes = b.step(b.fmt("install-{s}", .{ci_target_str}), "");
        ci_step.dependOn(install_exes);
        const msvcup_exe = b.addExecutable(.{
            .name = "msvcup",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/msvcup.zig"),
                .target = target,
                .optimize = optimize,
                .single_threaded = true,
                .imports = &.{
                    .{ .name = "version", .module = release_version_embed },
                },
            }),
        });
        install_exes.dependOn(
            &b.addInstallArtifact(msvcup_exe, .{ .dest_dir = .{ .override = target_dest_dir } }).step,
        );

        const target_test_step = b.step(b.fmt("test-{s}", .{ci_target_str}), "");
        addTests(b, msvcup_exe, target_test_step);
        const os_compatible = (builtin.os.tag == target.result.os.tag);
        const arch_compatible = (builtin.cpu.arch == target.result.cpu.arch);
        if (os_compatible and arch_compatible) {
            ci_step.dependOn(target_test_step);
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

const builtin = @import("builtin");
const std = @import("std");
const ChannelKind = @import("src/channelkind.zig").ChannelKind;
const Arch = @import("src/arch.zig").Arch;
const Arches = @import("src/arch.zig").Arches;
