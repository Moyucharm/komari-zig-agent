//! Regression tests for the cgroup resource collector (`linux.cgroup`).
//!
//! Every case builds a real temporary file tree (cgroup control files plus
//! `/proc` metadata) and injects it through `SourcePaths`, so no host `/proc`
//! or `/sys` state can influence the result. Collectors are independent per
//! case and all time values are supplied explicitly.
const std = @import("std");
const linux = @import("platform_linux");
const cgroup = linux.cgroup;

const msg_unavailable = "Container resource metrics unavailable";
const msg_cache_missing = "Container memory cache statistics unavailable; reporting charged usage";
const msg_v1_swap = "Cgroup v1 swap total is a shared memory+swap upper bound";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Owns the scratch buffers that back every `SourcePaths` slice. The buffers
/// live in the caller's frame, so the returned slices stay valid as long as
/// the `Paths` value does.
const Paths = struct {
    proc: [512]u8 = undefined,
    cpu_online: [512]u8 = undefined,
    systemd: [512]u8 = undefined,
    docker: [512]u8 = undefined,
    podman: [512]u8 = undefined,
    lxc: [512]u8 = undefined,
    agent: [512]u8 = undefined,

    /// Point every source at the temporary tree. Marker/systemd paths default
    /// to files that do not exist unless a test creates them.
    fn init(self: *Paths, root: []const u8) !cgroup.SourcePaths {
        return .{
            .proc_root = try absPath(root, "/proc", &self.proc),
            .cpu_online = try absPath(root, "/online", &self.cpu_online),
            .systemd_container = try absPath(root, "/systemd-container", &self.systemd),
            .docker_marker = try absPath(root, "/dockerenv", &self.docker),
            .podman_marker = try absPath(root, "/containerenv", &self.podman),
            .lxc_marker = try absPath(root, "/lxc-boot-id", &self.lxc),
            .agent_marker = try absPath(root, "/komari-agent-container", &self.agent),
        };
    }
};

fn absPath(root: []const u8, rel: []const u8, out: []u8) ![]const u8 {
    return std.fmt.bufPrint(out, "{s}{s}", .{ root, rel });
}

fn rootOf(tmp: *std.testing.TmpDir, buf: []u8) ![]const u8 {
    const n = try tmp.dir.realPath(std.testing.io, buf);
    return buf[0..n];
}

fn writeFile(dir: std.Io.Dir, sub_path: []const u8, content: []const u8) !void {
    // The cgroup tree is nested, so the parent directory is created on demand.
    if (std.mem.lastIndexOfScalar(u8, sub_path, '/')) |index| {
        try dir.createDirPath(std.testing.io, sub_path[0..index]);
    }
    var file = try dir.createFile(std.testing.io, sub_path, .{ .truncate = true });
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, content);
}

fn makeDir(dir: std.Io.Dir, sub_path: []const u8) !void {
    try dir.createDirPath(std.testing.io, sub_path);
}

fn newCollector(sources: cgroup.SourcePaths) !*cgroup.Collector {
    const collector = try std.testing.allocator.create(cgroup.Collector);
    collector.* = cgroup.Collector.init(sources);
    return collector;
}

fn expectApprox(expected: f64, actual: f64, tolerance: f64) !void {
    try std.testing.expect(std.math.approxEqAbs(f64, expected, actual, tolerance));
}

/// Write a `mountinfo` line for a cgroup2 mount.
fn writeMountInfoV2(tmp: *std.testing.TmpDir, root: []const u8, extra: []const u8) !void {
    var buf: [4096]u8 = undefined;
    const content = try std.fmt.bufPrint(&buf, "29 23 0:26 / {s} rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate\n{s}", .{ root, extra });
    try writeFile(tmp.dir, "proc/self/mountinfo", content);
}

// ---------------------------------------------------------------------------
// 1. Rainyun-style v2 namespace root view
// ---------------------------------------------------------------------------

test "v2 namespace root view reports container quota not host totals" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);

    var paths = Paths{};
    const sources = try paths.init(root);

    // Container clue: a Docker marker file (the root-view heuristic alone is
    // not relied upon here).
    try writeFile(tmp.dir, "dockerenv", "");
    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/self/cgroup", "0::/\n");
    try writeFile(tmp.dir, "proc/1/cgroup", "0::/\n");
    try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 263701976 kB\nSwapTotal: 4294967296 kB\n");
    try writeFile(tmp.dir, "online", "0-39\n");

    // cgroup v2 control files live directly in the mount root.
    try writeFile(tmp.dir, "cpu.max", "2000000 1000000\n");
    try writeFile(tmp.dir, "cpuset.cpus.effective", "0-39\n");
    try writeFile(tmp.dir, "memory.current", "104857600\n");
    try writeFile(tmp.dir, "memory.max", "4294967296\n");
    try writeFile(tmp.dir, "memory.stat", "inactive_file 20971520\n");
    try writeFile(tmp.dir, "memory.swap.current", "26804224\n");
    try writeFile(tmp.dir, "memory.swap.max", "4294967296\n");
    try writeFile(tmp.dir, "cpu.stat", "usage_usec 0\n");

    try writeMountInfoV2(&tmp, root, "");

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);

    const sample = collector.read(.{ .resource_mode = "auto" }, 1_000_000_000, true);

    try std.testing.expect(sample.scope == .container);
    try expectApprox(2.0, sample.cpu_capacity.?, 1e-9);
    try std.testing.expectEqual(@as(u32, 2), sample.cpu_cores);
    try expectApprox(0.001, sample.cpu_usage, 1e-9);
    // RAM total is capped by the 4 GiB cgroup limit, never the ~251 GiB host.
    try std.testing.expectEqual(@as(u64, 4294967296), sample.ram.total);
    try std.testing.expectEqual(@as(u64, 83886080), sample.ram.used);
    try std.testing.expectEqual(@as(?u64, 104857600), sample.charged_memory);
    try std.testing.expectEqual(@as(?u64, 20971520), sample.inactive_file);
    try std.testing.expectEqual(@as(u64, 4294967296), sample.swap.total);
    try std.testing.expectEqual(@as(u64, 26804224), sample.swap.used);
    try std.testing.expect(sample.swap_limit_kind == .independent);
    try std.testing.expectEqualStrings("", sample.message);

    // `memory_include_cache = true` reports the full charged figure.
    const include_cache = collector.read(.{
        .resource_mode = "auto",
        .memory_include_cache = true,
    }, 1_000_000_000, true);
    try std.testing.expectEqual(@as(u64, 104857600), include_cache.ram.used);
}

// ---------------------------------------------------------------------------
// 2. Kubernetes cri-containerd scope (not pod, not QoS, not kubepods)
// ---------------------------------------------------------------------------

const pod_slice =
    "kubepods.slice/kubepods-burstable.slice/" ++
    "kubepods-burstable-podc04eec61_a300_4dd0_924f_f0fc6a843149.slice";
const ide_scope = pod_slice ++ "/" ++
    "cri-containerd-70503fa4a4c8428a08f453bfa598c32ebadc7853459b5ad3b63597915d9e29d7.scope";

test "kubernetes cri-containerd scope ignores pod and qos parents" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);

    var paths = Paths{};
    const sources = try paths.init(root);

    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/self/cgroup", "0::/" ++ ide_scope ++ "\n");
    try writeFile(tmp.dir, "proc/1/cgroup", "0::/" ++ ide_scope ++ "\n");
    try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 64411492 kB\nSwapTotal: 0 kB\n");

    // kubepods.slice limits memory only; cpu is unlimited at that level.
    try makeDir(tmp.dir, "kubepods.slice");
    try writeFile(tmp.dir, "kubepods.slice/memory.max", "64409669632\n");
    try writeFile(tmp.dir, "kubepods.slice/cpu.max", "max 100000\n");

    try makeDir(tmp.dir, pod_slice);
    try writeFile(tmp.dir, pod_slice ++ "/cpu.max", "100000 100000\n");
    try writeFile(tmp.dir, pod_slice ++ "/memory.max", "2147483648\n");

    try makeDir(tmp.dir, ide_scope);
    try writeFile(tmp.dir, ide_scope ++ "/cpu.max", "100000 100000\n");
    try writeFile(tmp.dir, ide_scope ++ "/memory.max", "2147483648\n");
    try writeFile(tmp.dir, ide_scope ++ "/memory.current", "1048576\n");
    try writeFile(tmp.dir, ide_scope ++ "/memory.stat", "inactive_file 0\n");
    try writeFile(tmp.dir, ide_scope ++ "/memory.swap.max", "0\n");
    try writeFile(tmp.dir, ide_scope ++ "/memory.swap.current", "0\n");
    try writeFile(tmp.dir, ide_scope ++ "/cpuset.cpus.effective", "0-31\n");
    try writeFile(tmp.dir, ide_scope ++ "/cpu.stat", "usage_usec 0\n");

    var mi_buf: [4096]u8 = undefined;
    const extra = try std.fmt.bufPrint(&mi_buf, "101 23 0:44 {s}/proc rw,nosuid,nodev,relatime - fuse.lxcfs lxcfs rw,user_id=0,group_id=0\n", .{root});
    try writeMountInfoV2(&tmp, root, extra);

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);

    const sample = collector.read(.{ .resource_mode = "auto" }, 5_000_000_000, true);
    try std.testing.expect(sample.scope == .container);
    try expectApprox(1.0, sample.cpu_capacity.?, 1e-9);
    try std.testing.expectEqual(@as(u32, 1), sample.cpu_cores);
    try std.testing.expectEqual(@as(u64, 2147483648), sample.ram.total);
    try std.testing.expectEqual(@as(u64, 0), sample.swap.total);
    try std.testing.expectEqual(@as(?u64, 1048576), sample.charged_memory);

    // Contrast: the container level becomes unlimited; the pod stays finite, so
    // capacity and RAM total are unchanged (the Pod is a valid ancestor cap).
    try writeFile(tmp.dir, ide_scope ++ "/cpu.max", "max 100000\n");
    try writeFile(tmp.dir, ide_scope ++ "/memory.max", "max\n");

    const second = try newCollector(sources);
    defer std.testing.allocator.destroy(second);
    const relaxed = second.read(.{ .resource_mode = "auto" }, 5_000_000_000, true);
    try std.testing.expect(relaxed.scope == .container);
    try expectApprox(1.0, relaxed.cpu_capacity.?, 1e-9);
    try std.testing.expectEqual(@as(u32, 1), relaxed.cpu_cores);
    try std.testing.expectEqual(@as(u64, 2147483648), relaxed.ram.total);
}

// ---------------------------------------------------------------------------
// 3. LXC with systemd: whole container, not the agent service
// ---------------------------------------------------------------------------

test "lxc systemd container boundary prefers the container over the service" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);

    var paths = Paths{};
    const sources = try paths.init(root);

    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/1/comm", "systemd\n");
    try writeFile(tmp.dir, "proc/1/cgroup", "0::/lxc/demo/init.scope\n");
    try writeFile(tmp.dir, "proc/self/cgroup", "0::/lxc/demo/system.slice/komari-agent.service\n");
    try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 16777216 kB\nSwapTotal: 0 kB\n");

    // Container level (/lxc/demo): 2 CPUs, 2 GiB, 1 GiB charged.
    try makeDir(tmp.dir, "lxc/demo");
    try writeFile(tmp.dir, "lxc/demo/cpu.max", "200000 100000\n");
    try writeFile(tmp.dir, "lxc/demo/cpuset.cpus.effective", "0-3\n");
    try writeFile(tmp.dir, "lxc/demo/memory.max", "2147483648\n");
    try writeFile(tmp.dir, "lxc/demo/memory.current", "1073741824\n");
    try writeFile(tmp.dir, "lxc/demo/memory.stat", "inactive_file 0\n");
    try writeFile(tmp.dir, "lxc/demo/cpu.stat", "usage_usec 0\n");

    // Agent service level: much smaller limits and accounting.
    try makeDir(tmp.dir, "lxc/demo/system.slice/komari-agent.service");
    try writeFile(tmp.dir, "lxc/demo/system.slice/komari-agent.service/cpu.max", "10000 100000\n");
    try writeFile(tmp.dir, "lxc/demo/system.slice/komari-agent.service/memory.max", "67108864\n");
    try writeFile(tmp.dir, "lxc/demo/system.slice/komari-agent.service/memory.current", "3145728\n");

    try writeMountInfoV2(&tmp, root, "");

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{ .resource_mode = "auto" }, 9_000_000_000, false);
    try std.testing.expect(sample.scope == .container);
    try expectApprox(2.0, sample.cpu_capacity.?, 1e-9);
    try std.testing.expectEqual(@as(u32, 2), sample.cpu_cores);
    try std.testing.expectEqual(@as(u64, 2147483648), sample.ram.total);
    try std.testing.expectEqual(@as(?u64, 1073741824), sample.charged_memory);
}

test "lxc subtree mount maps the member path without duplicating it" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);

    var paths = Paths{};
    const sources = try paths.init(root);

    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/1/comm", "systemd\n");
    try writeFile(tmp.dir, "proc/1/cgroup", "0::/lxc/demo/init.scope\n");
    try writeFile(tmp.dir, "proc/self/cgroup", "0::/lxc/demo/system.slice/komari-agent.service\n");
    try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 16777216 kB\nSwapTotal: 0 kB\n");

    // The mount root is /lxc/demo and the mountpoint already contains its
    // contents, so nothing must be re-appended.
    try writeFile(tmp.dir, "cpu.max", "200000 100000\n");
    try writeFile(tmp.dir, "cpuset.cpus.effective", "0-3\n");
    try writeFile(tmp.dir, "memory.max", "2147483648\n");
    try writeFile(tmp.dir, "memory.current", "1073741824\n");
    try writeFile(tmp.dir, "memory.stat", "inactive_file 0\n");
    try writeFile(tmp.dir, "cpu.stat", "usage_usec 0\n");

    var mi_buf: [4096]u8 = undefined;
    const content = try std.fmt.bufPrint(&mi_buf, "29 23 0:26 /lxc/demo {s} rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate\n", .{root});
    try writeFile(tmp.dir, "proc/self/mountinfo", content);

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{ .resource_mode = "auto" }, 9_000_000_000, false);
    try std.testing.expect(sample.scope == .container);
    try expectApprox(2.0, sample.cpu_capacity.?, 1e-9);
    try std.testing.expectEqual(@as(u32, 2), sample.cpu_cores);
    try std.testing.expectEqual(@as(u64, 2147483648), sample.ram.total);
    try std.testing.expectEqual(@as(?u64, 1073741824), sample.charged_memory);
}

// ---------------------------------------------------------------------------
// 4. Fractional capacity and online CPU set
// ---------------------------------------------------------------------------

test "cpu quota parsers and cpuset counter" {
    try expectApprox(0.5, (try cgroup.parseCpuMaxV2("50000 100000")).?, 1e-9);
    try expectApprox(1.5, (try cgroup.parseCpuMaxV2("150000 100000")).?, 1e-9);
    try expectApprox(2.25, (try cgroup.parseCpuMaxV2("225000 100000")).?, 1e-9);
    try std.testing.expect((try cgroup.parseCpuMaxV2("max 100000")) == null);

    try std.testing.expectEqual(@as(u32, 40), try cgroup.parseCpuSet("0-39"));
    try std.testing.expectEqual(@as(u32, 2), try cgroup.parseCpuSet("0-1"));
    try std.testing.expectEqual(@as(u32, 1), try cgroup.parseCpuSet("0-0"));
}

test "fractional capacity drives the usage denominator" {
    // Capacity 0.5 (quota 0.5, one CPU): 250000 usec over 1s is 50%.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const root = try rootOf(&tmp, &root_buf);
        var paths = Paths{};
        const sources = try paths.init(root);

        try writeFile(tmp.dir, "dockerenv", "");
        try makeDir(tmp.dir, "proc/1");
        try writeFile(tmp.dir, "proc/self/cgroup", "0::/\n");
        try writeFile(tmp.dir, "proc/1/cgroup", "0::/\n");
        try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 16777216 kB\nSwapTotal: 0 kB\n");
        try writeFile(tmp.dir, "cpu.max", "50000 100000\n");
        try writeFile(tmp.dir, "cpuset.cpus.effective", "0-0\n");
        try writeFile(tmp.dir, "cpu.stat", "usage_usec 0\n");
        try writeFile(tmp.dir, "memory.current", "1048576\n");
        try writeFile(tmp.dir, "memory.max", "4294967296\n");
        try writeFile(tmp.dir, "memory.stat", "inactive_file 0\n");
        try writeFile(tmp.dir, "memory.swap.max", "0\n");
        try writeFile(tmp.dir, "memory.swap.current", "0\n");
        try writeMountInfoV2(&tmp, root, "");

        const collector = try newCollector(sources);
        defer std.testing.allocator.destroy(collector);

        const first = collector.read(.{ .resource_mode = "auto" }, 1_000, true);
        try expectApprox(0.5, first.cpu_capacity.?, 1e-9);
        try std.testing.expectEqual(@as(u32, 1), first.cpu_cores);
        try expectApprox(0.001, first.cpu_usage, 1e-9);

        try writeFile(tmp.dir, "cpu.stat", "usage_usec 250000\n");
        const second = collector.read(.{ .resource_mode = "auto" }, 1_000 + std.time.ns_per_s, true);
        try expectApprox(50.0, second.cpu_usage, 0.5);
    }

    // Capacity 1.5 (quota 1.5, two CPUs): 1500000 usec over 1s is 100%.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const root = try rootOf(&tmp, &root_buf);
        var paths = Paths{};
        const sources = try paths.init(root);

        try writeFile(tmp.dir, "dockerenv", "");
        try makeDir(tmp.dir, "proc/1");
        try writeFile(tmp.dir, "proc/self/cgroup", "0::/\n");
        try writeFile(tmp.dir, "proc/1/cgroup", "0::/\n");
        try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 16777216 kB\nSwapTotal: 0 kB\n");
        try writeFile(tmp.dir, "cpu.max", "150000 100000\n");
        try writeFile(tmp.dir, "cpuset.cpus.effective", "0-1\n");
        try writeFile(tmp.dir, "cpu.stat", "usage_usec 0\n");
        try writeFile(tmp.dir, "memory.current", "1048576\n");
        try writeFile(tmp.dir, "memory.max", "4294967296\n");
        try writeFile(tmp.dir, "memory.stat", "inactive_file 0\n");
        try writeFile(tmp.dir, "memory.swap.max", "0\n");
        try writeFile(tmp.dir, "memory.swap.current", "0\n");
        try writeMountInfoV2(&tmp, root, "");

        const collector = try newCollector(sources);
        defer std.testing.allocator.destroy(collector);

        _ = collector.read(.{ .resource_mode = "auto" }, 1_000, true);
        try writeFile(tmp.dir, "cpu.stat", "usage_usec 1500000\n");
        const second = collector.read(.{ .resource_mode = "auto" }, 1_000 + std.time.ns_per_s, true);
        try expectApprox(1.5, second.cpu_capacity.?, 1e-9);
        try std.testing.expectEqual(@as(u32, 2), second.cpu_cores);
        try expectApprox(100.0, second.cpu_usage, 0.5);
    }

    // Quota 4 with only 2 runnable CPUs caps at 2, not 4.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const root = try rootOf(&tmp, &root_buf);
        var paths = Paths{};
        const sources = try paths.init(root);

        try writeFile(tmp.dir, "dockerenv", "");
        try makeDir(tmp.dir, "proc/1");
        try writeFile(tmp.dir, "proc/self/cgroup", "0::/\n");
        try writeFile(tmp.dir, "proc/1/cgroup", "0::/\n");
        try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 16777216 kB\nSwapTotal: 0 kB\n");
        try writeFile(tmp.dir, "cpu.max", "400000 100000\n");
        try writeFile(tmp.dir, "cpuset.cpus.effective", "0-1\n");
        try writeFile(tmp.dir, "cpu.stat", "usage_usec 0\n");
        try writeFile(tmp.dir, "memory.current", "1048576\n");
        try writeFile(tmp.dir, "memory.max", "4294967296\n");
        try writeFile(tmp.dir, "memory.stat", "inactive_file 0\n");
        try writeFile(tmp.dir, "memory.swap.max", "0\n");
        try writeFile(tmp.dir, "memory.swap.current", "0\n");
        try writeMountInfoV2(&tmp, root, "");

        const collector = try newCollector(sources);
        defer std.testing.allocator.destroy(collector);
        const sample = collector.read(.{ .resource_mode = "auto" }, 1_000, false);
        try expectApprox(2.0, sample.cpu_capacity.?, 1e-9);
        try std.testing.expectEqual(@as(u32, 2), sample.cpu_cores);
    }
}

// ---------------------------------------------------------------------------
// 5. cgroup v1 and mixed v1/v2 controllers
// ---------------------------------------------------------------------------

test "cgroup v1 docker limits and shared memory+swap bound" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);
    var paths = Paths{};
    const sources = try paths.init(root);

    try writeFile(tmp.dir, "dockerenv", "");
    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/self/cgroup",
        "2:cpu:/docker/abc\n3:cpuacct:/docker/abc\n4:cpuset:/docker/abc\n5:memory:/docker/abc\n");
    try writeFile(tmp.dir, "proc/1/cgroup",
        "2:cpu:/docker/abc\n3:cpuacct:/docker/abc\n4:cpuset:/docker/abc\n5:memory:/docker/abc\n");
    try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 8589934592 kB\nSwapTotal: 8589934592 kB\n");

    var mp_buf: [512]u8 = undefined;
    const mp = try absPath(root, "/cgv1", &mp_buf);

    try makeDir(tmp.dir, "cgv1/docker/abc");
    // Unlimited at the target, finite at the mount root (the ancestor cap).
    try writeFile(tmp.dir, "cgv1/cpu.cfs_quota_us", "200000\n");
    try writeFile(tmp.dir, "cgv1/cpu.cfs_period_us", "100000\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpu.cfs_quota_us", "-1\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpu.cfs_period_us", "100000\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpuset.effective_cpus", "0-3\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpuacct.usage", "500000000\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.usage_in_bytes", "1073741824\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.limit_in_bytes", "2147483648\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.memsw.limit_in_bytes", "3221225472\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.memsw.usage_in_bytes", "2147483648\n");
    // local vs. hierarchical cache stats differ on purpose: only total_* applies.
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.stat",
        "inactive_file 999\n" ++
            "total_inactive_file 0\n" ++
            "total_swap 2147483648\n" ++
            "hierarchical_memory_limit 2147483648\n" ++
            "hierarchical_memsw_limit 3221225472\n");

    var mi_buf: [4096]u8 = undefined;
    const content = try std.fmt.bufPrint(&mi_buf,
        "31 23 0:27 / {s} rw,relatime - cgroup cgroup rw,cpu\n" ++
            "32 23 0:28 / {s} rw,relatime - cgroup cgroup rw,cpuacct\n" ++
            "33 23 0:29 / {s} rw,relatime - cgroup cgroup rw,cpuset\n" ++
            "34 23 0:30 / {s} rw,relatime - cgroup cgroup rw,memory\n",
        .{ mp, mp, mp, mp });
    try writeFile(tmp.dir, "proc/self/mountinfo", content);

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{ .resource_mode = "auto" }, 1_000, false);

    try std.testing.expect(sample.scope == .container);
    try expectApprox(2.0, sample.cpu_capacity.?, 1e-9);
    try std.testing.expectEqual(@as(u32, 2), sample.cpu_cores);
    try std.testing.expectEqual(@as(u64, 2147483648), sample.ram.total);
    // total_inactive_file (0) is used, not the local inactive_file (999).
    try std.testing.expectEqual(@as(?u64, 0), sample.inactive_file);
    try std.testing.expectEqual(@as(u64, 1073741824), sample.ram.used);
    try std.testing.expectEqual(@as(u64, 3221225472), sample.swap.total);
    try std.testing.expectEqual(@as(u64, 2147483648), sample.swap.used);
    try std.testing.expect(sample.swap_limit_kind == .shared_memsw_upper_bound);
    try std.testing.expectEqualStrings(msg_v1_swap, sample.message);
}

test "mixed v1 cpu and v2 memory controllers use their own targets" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);
    var paths = Paths{};
    const sources = try paths.init(root);

    try writeFile(tmp.dir, "dockerenv", "");
    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/self/cgroup",
        "2:cpu:/docker/abc\n3:cpuacct:/docker/abc\n4:cpuset:/docker/abc\n0::/\n");
    try writeFile(tmp.dir, "proc/1/cgroup",
        "2:cpu:/docker/abc\n3:cpuacct:/docker/abc\n4:cpuset:/docker/abc\n0::/\n");
    try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 17179869184 kB\nSwapTotal: 0 kB\n");

    var v1_buf: [512]u8 = undefined;
    var v2_buf: [512]u8 = undefined;
    const v1mp = try absPath(root, "/cgv1", &v1_buf);
    const v2mp = try absPath(root, "/cgv2", &v2_buf);

    // v1 CPU side: cpu 2.0, cpuset 8.
    try makeDir(tmp.dir, "cgv1/docker/abc");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpu.cfs_quota_us", "200000\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpu.cfs_period_us", "100000\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpuset.effective_cpus", "0-7\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpuacct.usage", "0\n");
    // A memory controller also sits at the v1 member path, but there is no v1
    // memory mount, so its values must be ignored.
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.limit_in_bytes", "8589934592\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.usage_in_bytes", "4294967296\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.stat", "total_inactive_file 0\n");

    // v2 memory side: 2 GiB, and a CPU max that must NOT be used for CPU.
    try makeDir(tmp.dir, "cgv2");
    try writeFile(tmp.dir, "cgv2/cpu.max", "50000 100000\n");
    try writeFile(tmp.dir, "cgv2/memory.current", "1048576\n");
    try writeFile(tmp.dir, "cgv2/memory.max", "2147483648\n");
    try writeFile(tmp.dir, "cgv2/memory.stat", "inactive_file 0\n");
    try writeFile(tmp.dir, "cgv2/memory.swap.max", "0\n");
    try writeFile(tmp.dir, "cgv2/memory.swap.current", "0\n");
    try writeFile(tmp.dir, "cgv2/cpu.stat", "usage_usec 0\n");

    var mi_buf: [4096]u8 = undefined;
    const content = try std.fmt.bufPrint(&mi_buf,
        "29 23 0:26 / {s} rw - cgroup2 cgroup2 rw,nsdelegate\n" ++
            "31 23 0:27 / {s} rw,relatime - cgroup cgroup rw,cpu\n" ++
            "32 23 0:28 / {s} rw,relatime - cgroup cgroup rw,cpuacct\n" ++
            "33 23 0:29 / {s} rw,relatime - cgroup cgroup rw,cpuset\n",
        .{ v2mp, v1mp, v1mp, v1mp });
    try writeFile(tmp.dir, "proc/self/mountinfo", content);

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{ .resource_mode = "auto" }, 1_000, false);

    try std.testing.expect(sample.scope == .container);
    // CPU comes from v1 (2.0), not the v2 cpu.max of 0.5.
    try expectApprox(2.0, sample.cpu_capacity.?, 1e-9);
    try std.testing.expectEqual(@as(u32, 2), sample.cpu_cores);
    // Memory comes from v2 (2 GiB), not the 8 GiB v1 limit.
    try std.testing.expectEqual(@as(u64, 2147483648), sample.ram.total);
    try std.testing.expectEqual(@as(?u64, 1048576), sample.charged_memory);
}

// ---------------------------------------------------------------------------
// 6. Differential CPU baseline and location cache
// ---------------------------------------------------------------------------

test "cpu differential resets, cache ttl and inode change" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);
    var paths = Paths{};
    const sources = try paths.init(root);

    try writeFile(tmp.dir, "dockerenv", "");
    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/self/cgroup", "0::/\n");
    try writeFile(tmp.dir, "proc/1/cgroup", "0::/\n");
    try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 16777216 kB\nSwapTotal: 0 kB\n");
    try writeFile(tmp.dir, "cpu.max", "200000 100000\n");
    try writeFile(tmp.dir, "cpuset.cpus.effective", "0-1\n");
    try writeFile(tmp.dir, "cpu.stat", "usage_usec 0\n");
    try writeFile(tmp.dir, "memory.current", "1048576\n");
    try writeFile(tmp.dir, "memory.max", "4294967296\n");
    try writeFile(tmp.dir, "memory.stat", "inactive_file 0\n");
    try writeFile(tmp.dir, "memory.swap.max", "0\n");
    try writeFile(tmp.dir, "memory.swap.current", "0\n");
    try writeMountInfoV2(&tmp, root, "");

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);

    const step: i128 = std.time.ns_per_s;
    const ttl: i128 = 30 * std.time.ns_per_s;

    // A basic-info style call with update=false must not consume the baseline.
    const probe = collector.read(.{ .resource_mode = "auto" }, 1_000_000_000, false);
    try expectApprox(0.001, probe.cpu_usage, 1e-9);

    // First updating frame establishes the baseline and reports the floor.
    try writeFile(tmp.dir, "cpu.stat", "usage_usec 1000000\n");
    const first = collector.read(.{ .resource_mode = "auto" }, 1_000_000_000 + step, true);
    try expectApprox(0.001, first.cpu_usage, 1e-9);

    // 2000000 usec over 1s at capacity 2 is 100%.
    try writeFile(tmp.dir, "cpu.stat", "usage_usec 3000000\n");
    const second = collector.read(.{ .resource_mode = "auto" }, 1_000_000_000 + 2 * step, true);
    try expectApprox(100.0, second.cpu_usage, 0.5);

    // Counter rollback resets the baseline.
    try writeFile(tmp.dir, "cpu.stat", "usage_usec 2000000\n");
    const rolled_back = collector.read(.{ .resource_mode = "auto" }, 1_000_000_000 + 3 * step, true);
    try expectApprox(0.001, rolled_back.cpu_usage, 1e-9);

    // Non-increasing timestamp resets the baseline.
    try writeFile(tmp.dir, "cpu.stat", "usage_usec 4000000\n");
    const stalled = collector.read(.{ .resource_mode = "auto" }, 1_000_000_000 + 3 * step, true);
    try expectApprox(0.001, stalled.cpu_usage, 1e-9);

    // Past the 30s TTL the location is re-resolved. The quota drops to 0.5, so
    // capacity changes and the baseline is reset once.
    try writeFile(tmp.dir, "cpu.max", "50000 100000\n");
    const relocated = collector.read(.{ .resource_mode = "auto" }, 1_000_000_000 + 3 * step + ttl, true);
    try expectApprox(0.5, relocated.cpu_capacity.?, 1e-9);
    try std.testing.expectEqual(@as(u32, 1), relocated.cpu_cores);
    try expectApprox(0.001, relocated.cpu_usage, 1e-9);

    // 400000 usec over 1s at capacity 0.5 is 80%.
    try writeFile(tmp.dir, "cpu.stat", "usage_usec 4400000\n");
    const after = collector.read(.{ .resource_mode = "auto" }, 1_000_000_000 + 3 * step + ttl + step, true);
    try expectApprox(80.0, after.cpu_usage, 0.5);

    // Replacing the accounting file changes its inode, resetting the baseline.
    try tmp.dir.deleteFile(std.testing.io, "cpu.stat");
    try writeFile(tmp.dir, "cpu.stat", "usage_usec 5000000\n");
    const replaced = collector.read(.{ .resource_mode = "auto" }, 1_000_000_000 + 3 * step + ttl + 2 * step, true);
    try expectApprox(0.001, replaced.cpu_usage, 1e-9);

    // Recovery: the next increment is measured again.
    try writeFile(tmp.dir, "cpu.stat", "usage_usec 5200000\n");
    const recovered = collector.read(.{ .resource_mode = "auto" }, 1_000_000_000 + 3 * step + ttl + 3 * step, true);
    try expectApprox(40.0, recovered.cpu_usage, 0.5);
}

// ---------------------------------------------------------------------------
// 7. Parsers, unavailable fallback, host mode and escaped mountpoints
// ---------------------------------------------------------------------------

test "invalid cpuset, quota, and memory-limit inputs" {
    try std.testing.expectError(error.InvalidCpuSet, cgroup.parseCpuSet("3-1"));
    try std.testing.expectError(error.InvalidCpuSet, cgroup.parseCpuSet("1-2,2-3"));
    try std.testing.expectError(error.InvalidCpuSet, cgroup.parseCpuSet("5,3"));
    try std.testing.expectError(error.InvalidCpuSet, cgroup.parseCpuSet("1,,2"));
    try std.testing.expectError(error.InvalidCpuSet, cgroup.parseCpuSet("1-2-3"));
    try std.testing.expectError(error.InvalidCpuSet, cgroup.parseCpuSet("a"));
    try std.testing.expectEqual(@as(u32, 0), try cgroup.parseCpuSet(""));

    try std.testing.expect((try cgroup.parseCpuMaxV2("max 100000")) == null);
    try std.testing.expectError(error.InvalidCgroupValue, cgroup.parseCpuMaxV2("0 100000"));
    try std.testing.expectError(error.InvalidCgroupValue, cgroup.parseCpuMaxV2("100000 0"));
    try std.testing.expectError(error.InvalidCgroupValue, cgroup.parseCpuMaxV2("junk 100000"));

    try std.testing.expect((try cgroup.parseCpuQuotaV1("-1", "100000")) == null);
    try std.testing.expectError(error.InvalidCgroupValue, cgroup.parseCpuQuotaV1("0", "100000"));

    try std.testing.expect((try cgroup.parseMemoryLimit("max", .v2)) == null);
    try std.testing.expectEqual(@as(?u64, 0), try cgroup.parseMemoryLimit("0", .v2));
    // v1 sentinel written in decimal: unlimited.
    try std.testing.expect((try cgroup.parseMemoryLimit("9223372036854771712", .v1)) == null);
    try std.testing.expectEqual(@as(?u64, 0), try cgroup.parseMemoryLimit("0", .v1));
}

test "missing memory.stat keeps charged usage with a degraded message" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);
    var paths = Paths{};
    const sources = try paths.init(root);

    try writeFile(tmp.dir, "dockerenv", "");
    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/self/cgroup", "0::/\n");
    try writeFile(tmp.dir, "proc/1/cgroup", "0::/\n");
    try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 16777216 kB\nSwapTotal: 0 kB\n");
    try writeFile(tmp.dir, "cpu.max", "200000 100000\n");
    try writeFile(tmp.dir, "cpuset.cpus.effective", "0-1\n");
    try writeFile(tmp.dir, "cpu.stat", "usage_usec 0\n");
    try writeFile(tmp.dir, "memory.current", "104857600\n");
    try writeFile(tmp.dir, "memory.max", "4294967296\n");
    try writeFile(tmp.dir, "memory.swap.max", "0\n");
    try writeFile(tmp.dir, "memory.swap.current", "0\n");
    try writeMountInfoV2(&tmp, root, "");

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{ .resource_mode = "auto" }, 1_000, false);

    try std.testing.expect(sample.scope == .container);
    try std.testing.expectEqual(@as(?u64, 104857600), sample.charged_memory);
    try std.testing.expect(sample.inactive_file == null);
    try std.testing.expectEqual(@as(u64, 104857600), sample.ram.used);
    try std.testing.expectEqualStrings(msg_cache_missing, sample.message);
}

test "known container with missing target never falls back to host data" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);
    var paths = Paths{};
    const sources = try paths.init(root);

    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/self/cgroup", "0::/docker/missing\n");
    try writeFile(tmp.dir, "proc/1/cgroup", "0::/docker/missing\n");
    // No cgroup target directory, no /proc/meminfo, no cpu_online file.
    try writeMountInfoV2(&tmp, root, "");

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{ .resource_mode = "auto" }, 1_000, true);

    try std.testing.expect(sample.scope == .unavailable);
    try std.testing.expectEqualStrings(msg_unavailable, sample.message);
    try std.testing.expect(sample.cpu_capacity == null);
    try std.testing.expectEqual(@as(u32, 0), sample.cpu_cores);
    try std.testing.expectEqual(@as(u64, 0), sample.ram.total);
    try std.testing.expect(sample.charged_memory == null);
}

test "host mode forces the host scope" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);
    var paths = Paths{};
    const sources = try paths.init(root);

    // Even with a container marker present, an explicit host mode wins.
    try writeFile(tmp.dir, "dockerenv", "");
    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/self/cgroup", "0::/\n");
    try writeFile(tmp.dir, "proc/1/cgroup", "0::/\n");
    try writeFile(tmp.dir, "cpu.max", "200000 100000\n");
    try writeMountInfoV2(&tmp, root, "");

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{ .resource_mode = "host" }, 1_000, true);

    try std.testing.expect(sample.scope == .host);
    try std.testing.expectEqual(@as(u64, 0), sample.ram.total);
    try std.testing.expectEqual(@as(u32, 0), sample.cpu_cores);
    try std.testing.expectEqualStrings("", sample.message);
}

test "plain systemd host without container clues stays host" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);
    var paths = Paths{};
    const sources = try paths.init(root);

    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/1/comm", "systemd\n");
    try writeFile(tmp.dir, "proc/1/cgroup", "0::/init.scope\n");
    try writeFile(tmp.dir, "proc/self/cgroup", "0::/init.scope\n");
    // A finite cpu.max exists but there is no container clue, so the collector
    // must keep the whole-machine behaviour and ignore cgroup files.
    try writeFile(tmp.dir, "cpu.max", "200000 100000\n");
    try writeMountInfoV2(&tmp, root, "");

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{ .resource_mode = "auto" }, 1_000, true);

    try std.testing.expect(sample.scope == .host);
    try std.testing.expect(sample.cpu_capacity == null);
    try std.testing.expectEqual(@as(u64, 0), sample.ram.total);
}

test "explicit cgroup_path forces container resolution" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);
    var paths = Paths{};
    const sources = try paths.init(root);

    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/self/cgroup", "0::/init.scope\n");
    try writeFile(tmp.dir, "proc/1/cgroup", "0::/init.scope\n");
    try writeFile(tmp.dir, "proc/1/comm", "systemd\n");
    try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 16777216 kB\nSwapTotal: 0 kB\n");

    try makeDir(tmp.dir, "docker/abc");
    try writeFile(tmp.dir, "docker/abc/cpu.max", "200000 100000\n");
    try writeFile(tmp.dir, "docker/abc/cpuset.cpus.effective", "0-1\n");
    try writeFile(tmp.dir, "docker/abc/cpu.stat", "usage_usec 0\n");
    try writeFile(tmp.dir, "docker/abc/memory.current", "1048576\n");
    try writeFile(tmp.dir, "docker/abc/memory.max", "2147483648\n");
    try writeFile(tmp.dir, "docker/abc/memory.stat", "inactive_file 0\n");
    try writeFile(tmp.dir, "docker/abc/memory.swap.max", "0\n");
    try writeFile(tmp.dir, "docker/abc/memory.swap.current", "0\n");
    try writeMountInfoV2(&tmp, root, "");

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{
        .resource_mode = "auto",
        .cgroup_path = "/docker/abc",
    }, 1_000, false);

    try std.testing.expect(sample.scope == .container);
    try expectApprox(2.0, sample.cpu_capacity.?, 1e-9);
    try std.testing.expectEqual(@as(u32, 2), sample.cpu_cores);
    try std.testing.expectEqual(@as(u64, 2147483648), sample.ram.total);
}

test "oversized mountinfo is treated as unavailable, not partial" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);
    var paths = Paths{};
    const sources = try paths.init(root);

    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/self/cgroup", "0::/\n");
    try writeFile(tmp.dir, "proc/1/cgroup", "0::/\n");

    // A filled read buffer must be a truncation failure, never partial data.
    const big = try std.testing.allocator.alloc(u8, 70 * 1024);
    defer std.testing.allocator.free(big);
    @memset(big, 'x');
    try writeFile(tmp.dir, "proc/self/mountinfo", big);

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{ .resource_mode = "auto" }, 1_000, true);

    try std.testing.expect(sample.scope == .unavailable);
    try std.testing.expectEqualStrings(msg_unavailable, sample.message);
    try std.testing.expectEqual(@as(u64, 0), sample.ram.total);
}

test "escaped mountpoint with a space resolves correctly" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);
    var paths = Paths{};
    const sources = try paths.init(root);

    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/self/cgroup", "0::/docker/abc\n");
    try writeFile(tmp.dir, "proc/1/cgroup", "0::/docker/abc\n");
    try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 16777216 kB\nSwapTotal: 0 kB\n");

    // Real directory name contains a space; mountinfo escapes it as \040.
    try makeDir(tmp.dir, "a b/docker/abc");
    try writeFile(tmp.dir, "a b/docker/abc/cpu.max", "200000 100000\n");
    try writeFile(tmp.dir, "a b/docker/abc/cpuset.cpus.effective", "0-1\n");
    try writeFile(tmp.dir, "a b/docker/abc/cpu.stat", "usage_usec 0\n");
    try writeFile(tmp.dir, "a b/docker/abc/memory.current", "104857600\n");
    try writeFile(tmp.dir, "a b/docker/abc/memory.max", "4294967296\n");
    try writeFile(tmp.dir, "a b/docker/abc/memory.stat", "inactive_file 0\n");

    var mi_buf: [4096]u8 = undefined;
    const content = try std.fmt.bufPrint(&mi_buf,
        "29 23 0:26 / {s}/a\\040b rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate\n",
        .{root});
    try writeFile(tmp.dir, "proc/self/mountinfo", content);

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{ .resource_mode = "auto" }, 1_000, false);

    try std.testing.expect(sample.scope == .container);
    try expectApprox(2.0, sample.cpu_capacity.?, 1e-9);
    try std.testing.expectEqual(@as(u32, 2), sample.cpu_cores);
    try std.testing.expectEqual(@as(u64, 4294967296), sample.ram.total);
    try std.testing.expectEqual(@as(?u64, 104857600), sample.charged_memory);
}

test "v1 empty cpuset inherits the ancestor set and intersects online CPUs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);
    var paths = Paths{};
    const sources = try paths.init(root);

    try writeFile(tmp.dir, "dockerenv", "");
    // Only two CPUs are online while the inherited cpuset spans four.
    try writeFile(tmp.dir, "online", "0-1\n");
    try writeFile(tmp.dir, "proc/self/cgroup",
        "2:cpu:/docker/abc\n3:cpuacct:/docker/abc\n4:cpuset:/docker/abc\n5:memory:/docker/abc\n");
    try writeFile(tmp.dir, "proc/1/cgroup",
        "2:cpu:/docker/abc\n3:cpuacct:/docker/abc\n4:cpuset:/docker/abc\n5:memory:/docker/abc\n");
    try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 8589934592 kB\nSwapTotal: 0 kB\n");

    var mp_buf: [512]u8 = undefined;
    const mp = try absPath(root, "/cgv1", &mp_buf);

    try writeFile(tmp.dir, "cgv1/docker/abc/cpuset.cpus", "\n");
    try writeFile(tmp.dir, "cgv1/cpuset.cpus", "0-3\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpu.cfs_quota_us", "-1\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpu.cfs_period_us", "100000\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpuacct.usage", "0\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.limit_in_bytes", "2147483648\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.usage_in_bytes", "1048576\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.stat", "total_inactive_file 0\ntotal_swap 0\n");

    var mi_buf: [4096]u8 = undefined;
    try writeFile(tmp.dir, "proc/self/mountinfo", try std.fmt.bufPrint(&mi_buf,
        "31 23 0:27 / {s} rw,relatime - cgroup cgroup rw,cpu\n" ++
            "32 23 0:28 / {s} rw,relatime - cgroup cgroup rw,cpuacct\n" ++
            "33 23 0:29 / {s} rw,relatime - cgroup cgroup rw,cpuset\n" ++
            "34 23 0:30 / {s} rw,relatime - cgroup cgroup rw,memory\n",
        .{ mp, mp, mp, mp }));

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{ .resource_mode = "auto" }, 1_000, false);

    try std.testing.expect(sample.scope == .container);
    // 4 inherited CPUs intersected with 2 online CPUs.
    try expectApprox(2.0, sample.cpu_capacity.?, 1e-9);
    try std.testing.expectEqual(@as(u32, 2), sample.cpu_cores);

    // Now make the inherited set disjoint from the online set: the runnable set
    // is empty, so the capacity must stay unknown instead of counting 4.
    try writeFile(tmp.dir, "cgv1/cpuset.cpus", "4-7\n");
    const collector2 = try newCollector(sources);
    defer std.testing.allocator.destroy(collector2);
    const disjoint = collector2.read(.{ .resource_mode = "auto" }, 1_000, false);
    try std.testing.expect(disjoint.cpu_capacity == null);
    try std.testing.expectEqual(@as(u32, 0), disjoint.cpu_cores);

    // Unreadable online file: fall back to the inherited set size.
    try tmp.dir.deleteFile(std.testing.io, "online");
    const collector3 = try newCollector(sources);
    defer std.testing.allocator.destroy(collector3);
    const offline = collector3.read(.{ .resource_mode = "auto" }, 1_000, false);
    try expectApprox(4.0, offline.cpu_capacity.?, 1e-9);
}

test "v1-only container is detected from its cgroup path without markers" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);
    var paths = Paths{};
    const sources = try paths.init(root);

    // No marker files, no /run/systemd/container, no container= in environ.
    try writeFile(tmp.dir, "proc/self/cgroup",
        "2:cpu:/docker/abc\n3:cpuacct:/docker/abc\n4:cpuset:/docker/abc\n5:memory:/docker/abc\n");
    try writeFile(tmp.dir, "proc/1/cgroup",
        "2:cpu:/docker/abc\n3:cpuacct:/docker/abc\n4:cpuset:/docker/abc\n5:memory:/docker/abc\n");
    try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 8589934592 kB\nSwapTotal: 0 kB\n");
    try writeFile(tmp.dir, "online", "0-7\n");

    var mp_buf: [512]u8 = undefined;
    const mp = try absPath(root, "/cgv1", &mp_buf);

    try writeFile(tmp.dir, "cgv1/docker/abc/cpu.cfs_quota_us", "200000\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpu.cfs_period_us", "100000\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpuset.effective_cpus", "0-3\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/cpuacct.usage", "0\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.limit_in_bytes", "4294967296\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.usage_in_bytes", "1048576\n");
    try writeFile(tmp.dir, "cgv1/docker/abc/memory.stat", "total_inactive_file 0\ntotal_swap 0\n");

    var mi_buf: [4096]u8 = undefined;
    try writeFile(tmp.dir, "proc/self/mountinfo", try std.fmt.bufPrint(&mi_buf,
        "31 23 0:27 / {s} rw,relatime - cgroup cgroup rw,cpu\n" ++
            "32 23 0:28 / {s} rw,relatime - cgroup cgroup rw,cpuacct\n" ++
            "33 23 0:29 / {s} rw,relatime - cgroup cgroup rw,cpuset\n" ++
            "34 23 0:30 / {s} rw,relatime - cgroup cgroup rw,memory\n",
        .{ mp, mp, mp, mp }));

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{ .resource_mode = "auto" }, 1_000, false);

    try std.testing.expect(sample.scope == .container);
    try expectApprox(2.0, sample.cpu_capacity.?, 1e-9);
    try std.testing.expectEqual(@as(u64, 4294967296), sample.ram.total);
}

test "unreadable quota level leaves the capacity unknown" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root = try rootOf(&tmp, &root_buf);
    var paths = Paths{};
    const sources = try paths.init(root);

    try writeFile(tmp.dir, "dockerenv", "");
    try makeDir(tmp.dir, "proc/1");
    try writeFile(tmp.dir, "proc/self/cgroup", "0::/\n");
    try writeFile(tmp.dir, "proc/1/cgroup", "0::/\n");
    try writeFile(tmp.dir, "proc/meminfo", "MemTotal: 16777216 kB\nSwapTotal: 0 kB\n");

    // A directory where cpu.max should be: opening succeeds, reading fails.
    try makeDir(tmp.dir, "cg2/cpu.max");
    try writeFile(tmp.dir, "cg2/cpuset.cpus.effective", "0-3\n");
    try writeFile(tmp.dir, "cg2/cpu.stat", "usage_usec 0\n");
    try writeFile(tmp.dir, "cg2/memory.current", "1048576\n");
    try writeFile(tmp.dir, "cg2/memory.max", "4294967296\n");
    try writeFile(tmp.dir, "cg2/memory.stat", "inactive_file 0\n");
    try writeFile(tmp.dir, "cg2/memory.swap.max", "0\n");
    try writeFile(tmp.dir, "cg2/memory.swap.current", "0\n");

    var mp_buf: [512]u8 = undefined;
    const mp = try absPath(root, "/cg2", &mp_buf);
    try writeMountInfoV2(&tmp, mp, "");

    const collector = try newCollector(sources);
    defer std.testing.allocator.destroy(collector);
    const sample = collector.read(.{ .resource_mode = "auto" }, 1_000, false);

    // The unreadable level must not be treated as unlimited.
    try std.testing.expect(sample.cpu_capacity == null);
    try std.testing.expectEqual(@as(u32, 0), sample.cpu_cores);
    // Memory is still usable, so the container itself is not unavailable.
    try std.testing.expect(sample.scope == .container);
    try std.testing.expectEqual(@as(u64, 4294967296), sample.ram.total);
    try std.testing.expectEqualStrings(msg_unavailable, sample.message);

    // Once the value is readable again the capacity returns.
    try tmp.dir.deleteDir(std.testing.io, "cg2/cpu.max");
    try writeFile(tmp.dir, "cg2/cpu.max", "200000 100000\n");
    const collector2 = try newCollector(sources);
    defer std.testing.allocator.destroy(collector2);
    const recovered = collector2.read(.{ .resource_mode = "auto" }, 1_000, false);
    try expectApprox(2.0, recovered.cpu_capacity.?, 1e-9);
}
