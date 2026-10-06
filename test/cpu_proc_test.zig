const std = @import("std");
const linux = @import("platform_linux");

test "cpu usage is calculated from proc stat delta" {
    const previous = linux.parseCpuStat("cpu  100 0 100 800 0 0 0 0 0 0\n").?;
    const current = linux.parseCpuStat("cpu  150 0 150 900 0 0 0 0 0 0\n").?;
    try std.testing.expectEqual(@as(f64, 50.0), linux.cpuUsagePercent(previous, current));
}

test "connection parser counts tcp and udp entries excluding headers" {
    const table =
        \\  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
        \\   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
        \\   1: 0100007F:9C4C 0100007F:0016 01 00000000:00000000 00:00000000 00000000  1000        0 2 1 0000000000000000 20 4 30 10 -1
    ;
    try std.testing.expectEqual(@as(u64, 2), linux.countProcNetConnections(table));
}

const guard = linux.cpu_guard;

test "proc stat parser counts per-cpu lines and excludes guest from accounted ticks" {
    const stat = linux.parseCpuStat(
        \\cpu  100 0 100 800 0 0 0 0 50 0
        \\cpu0 50 0 50 400 0 0 0 0 25 0
        \\cpu1 50 0 50 400 0 0 0 0 25 0
        \\intr 0
        \\
    ).?;
    try std.testing.expectEqual(@as(u32, 2), stat.cpu_lines);
    try std.testing.expectEqual(@as(u64, 1000), stat.accounted);
    try std.testing.expectEqual(@as(u64, 1050), stat.total);
}

test "cpu guard accepts real kernel windows and rejects counters that lag wall time" {
    // 4 CPUs for 3 s on a real kernel: ~1200 ticks.
    try std.testing.expect(guard.plausible(.{ .accounted_delta = 1198, .cpu_lines = 4, .elapsed_ns = 3 * std.time.ns_per_s }));
    // Cloud phone sample: 4 CPUs for 30 s grew by only 3323 ticks (~28%).
    try std.testing.expect(!guard.plausible(.{ .accounted_delta = 3323, .cpu_lines = 4, .elapsed_ns = 30 * std.time.ns_per_s }));
    try std.testing.expect(!guard.plausible(.{ .accounted_delta = 2000, .cpu_lines = 4, .elapsed_ns = 3 * std.time.ns_per_s }));
    // Unknown CPU count or a window too short to judge never flags a host.
    try std.testing.expect(guard.plausible(.{ .accounted_delta = 0, .cpu_lines = 0, .elapsed_ns = 3 * std.time.ns_per_s }));
    try std.testing.expect(guard.plausible(.{ .accounted_delta = 0, .cpu_lines = 1, .elapsed_ns = 100 * std.time.ns_per_ms }));
    try std.testing.expect(guard.plausible(.{ .accounted_delta = 0, .cpu_lines = 4, .elapsed_ns = 0 }));
}

test "pid stat parser handles command names with spaces and parentheses" {
    const times = guard.parsePidStat("42 (a) b (c) S 1 42 42 0 -1 4194560 100 0 0 0 30 12 0 0 20 0 1 0 5555 1000 100\n").?;
    try std.testing.expectEqual(@as(u64, 42), times.ticks);
    try std.testing.expectEqual(@as(u64, 5555), times.start);
    try std.testing.expect(guard.parsePidStat("42 (short) S 1 2 3\n") == null);
    try std.testing.expect(guard.parsePidStat("no parenthesis") == null);
    try std.testing.expect(guard.parsePidStat("42 (x) S 1 42 42 0 -1 0 0 0 0 0 bad 12 0 0 20 0 1 0 5555\n") == null);
}

test "process usage is normalised by cores and clamped" {
    try std.testing.expectEqual(@as(f64, 25.0), guard.processUsagePercent(300, 3 * std.time.ns_per_s, 4));
    try std.testing.expectEqual(@as(f64, 100.0), guard.processUsagePercent(5000, 3 * std.time.ns_per_s, 4));
    try std.testing.expectEqual(@as(f64, 0.001), guard.processUsagePercent(0, 3 * std.time.ns_per_s, 4));
    try std.testing.expectEqual(@as(f64, 0.001), guard.processUsagePercent(10, 0, 4));
    try std.testing.expectEqual(@as(f64, 0.001), guard.processUsagePercent(10, std.time.ns_per_s, 0));
}

fn writePidStat(dir: std.Io.Dir, pid: []const u8, utime: u64, start: u64) !void {
    var path_buf: [64]u8 = undefined;
    var line_buf: [256]u8 = undefined;
    try dir.createDirPath(std.testing.io, pid);
    const path = try std.fmt.bufPrint(&path_buf, "{s}/stat", .{pid});
    const line = try std.fmt.bufPrint(&line_buf, "{s} (worker) S 1 1 1 0 -1 0 0 0 0 0 {d} 0 0 0 20 0 1 0 {d} 0 0\n", .{ pid, utime, start });
    var file = try dir.createFile(std.testing.io, path, .{ .truncate = true });
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, line);
}

fn tmpRoot(tmp: *std.testing.TmpDir, buf: []u8) ![]const u8 {
    const n = try tmp.dir.realPath(std.testing.io, buf);
    return buf[0..n];
}

test "process sampler tracks pid reuse, new and exited processes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try tmpRoot(&tmp, &root_buf);

    var sampler: guard.ProcessSampler = .{};
    defer sampler.reset();

    try writePidStat(tmp.dir, "10", 100, 1);
    try writePidStat(tmp.dir, "11", 50, 2);
    try writePidStat(tmp.dir, "12", 70, 3);
    try tmp.dir.createDirPath(std.testing.io, "self");
    try std.testing.expect(sampler.sample(root, std.time.ns_per_s, 1) == null);

    // pid 10 used 20 ticks, pid 11 was reused (counts fully: 5), pid 12 exited,
    // pid 13 is new (10). 35 ticks over 1 s on 1 core.
    try writePidStat(tmp.dir, "10", 120, 1);
    try writePidStat(tmp.dir, "11", 5, 9);
    try tmp.dir.deleteTree(std.testing.io, "12");
    try writePidStat(tmp.dir, "13", 10, 8);
    try std.testing.expectEqual(@as(f64, 35.0), sampler.sample(root, 2 * std.time.ns_per_s, 1).?);

    // A missing proc root drops the baseline.
    try std.testing.expect(sampler.sample("/nonexistent-komari-proc", 3 * std.time.ns_per_s, 1) == null);
    try std.testing.expect(sampler.previous_ns == null);
}

test "cpu monitor keeps proc stat on healthy hosts and switches only after sustained bad windows" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try tmpRoot(&tmp, &root_buf);

    const good: guard.Window = .{ .accounted_delta = 1200, .cpu_lines = 4, .elapsed_ns = 3 * std.time.ns_per_s };
    const bad: guard.Window = .{ .accounted_delta = 330, .cpu_lines = 4, .elapsed_ns = 3 * std.time.ns_per_s };
    const s = std.time.ns_per_s;

    var monitor: guard.Monitor = .{};
    defer monitor.reset();

    // Healthy host: never scans processes (the missing root would not matter).
    for (0..5) |_| try std.testing.expectEqual(@as(f64, 37.5), monitor.resolve(37.5, good, "/nonexistent-komari-proc", 0, 4));
    try std.testing.expect(!monitor.use_processes);

    // One odd window keeps the /proc/stat value.
    try writePidStat(tmp.dir, "1", 0, 1);
    try std.testing.expectEqual(@as(f64, 100.0), monitor.resolve(100.0, bad, root, 3 * s, 4));
    try std.testing.expectEqual(@as(f64, 37.5), monitor.resolve(37.5, good, root, 6 * s, 4));
    try std.testing.expect(!monitor.use_processes);

    // Sustained implausible counters: the third bad window reports process time.
    try std.testing.expectEqual(@as(f64, 100.0), monitor.resolve(100.0, bad, root, 9 * s, 4));
    try writePidStat(tmp.dir, "1", 12, 1);
    try std.testing.expectEqual(@as(f64, 61.5), monitor.resolve(61.5, bad, root, 12 * s, 4));
    try writePidStat(tmp.dir, "1", 24, 1);
    try std.testing.expectEqual(@as(f64, 1.0), monitor.resolve(100.0, bad, root, 15 * s, 4));
    try std.testing.expect(monitor.use_processes);

    // Recovery needs the same number of plausible windows.
    try writePidStat(tmp.dir, "1", 36, 1);
    try std.testing.expectEqual(@as(f64, 1.0), monitor.resolve(80.0, good, root, 18 * s, 4));
    try writePidStat(tmp.dir, "1", 48, 1);
    try std.testing.expectEqual(@as(f64, 1.0), monitor.resolve(80.0, good, root, 21 * s, 4));
    try std.testing.expectEqual(@as(f64, 80.0), monitor.resolve(80.0, good, root, 24 * s, 4));
    try std.testing.expect(!monitor.use_processes);
    try std.testing.expect(monitor.sampler.previous_ns == null);
}
