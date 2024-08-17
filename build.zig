const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zigwin32_dep = b.dependency("zigwin32", .{});

    const exe = b.addExecutable(.{
        .name = "keymap",
        .root_source_file = b.path("keymap.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = true,
    });
    exe.root_module.addImport("win32", zigwin32_dep.module("zigwin32"));
    b.installArtifact(exe);
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
