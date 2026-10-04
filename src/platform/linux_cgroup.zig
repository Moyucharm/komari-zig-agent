//! Cgroup-aware CPU and memory resource accounting for Linux containers.
//!
//! The collector resolves the cgroup boundary of the whole container (never the
//! agent's own service group, never an entire Kubernetes pod), reads only
//! cgroup control files plus `/proc` metadata, and needs no host API, no
//! privileges and no directory scans. Every read is bounded and a filled
//! buffer is treated as a truncation failure instead of partial data.
const std = @import("std");
const common = @import("common.zig");
const compat = @import("compat");

/// Upper bound for scalar control files such as `cpu.max` or `cpu.stat`.
pub const scalar_bytes: usize = 4 * 1024;
/// Upper bound for list-like control files such as `memory.stat`.
pub const list_bytes: usize = 16 * 1024;
/// Upper bound for `/proc/<pid>/mountinfo`.
pub const mountinfo_bytes: usize = 64 * 1024;

const max_path = std.Io.Dir.max_path_bytes;
const max_mounts = 16;
const max_ranges = 256;
const max_controllers = 4;
const max_notes = 8;
const resolve_ttl_ns: i128 = 30 * std.time.ns_per_s;
const cpu_report_floor: f64 = 0.001;

const msg_unavailable = "Container resource metrics unavailable";
const msg_cache_missing = "Container memory cache statistics unavailable; reporting charged usage";
const msg_v1_shared_swap = "Cgroup v1 swap total is a shared memory+swap upper bound";

/// Filesystem locations the collector is allowed to read. Injected at
/// construction time so tests can point them at a temporary tree.
pub const SourcePaths = struct {
    proc_root: []const u8 = "/proc",
    cpu_online: []const u8 = "/sys/devices/system/cpu/online",
    systemd_container: []const u8 = "/run/systemd/container",
    docker_marker: []const u8 = "/.dockerenv",
    podman_marker: []const u8 = "/run/.containerenv",
    lxc_marker: []const u8 = "/dev/.lxc-boot-id",
    agent_marker: []const u8 = "/.komari-agent-container",
};

pub const Scope = enum { host, container, unavailable };

pub const SwapLimitKind = enum { independent, shared_memsw_upper_bound, unknown };

/// Outcome of one collection pass. Missing items never abort the other ones.
pub const ResourceSample = struct {
    scope: Scope = .host,
    cpu_capacity: ?f64 = null,
    cpu_cores: u32 = 0,
    cpu_usage: f64 = cpu_report_floor,
    ram: common.MemInfo = .{},
    swap: common.MemInfo = .{},
    charged_memory: ?u64 = null,
    inactive_file: ?u64 = null,
    swap_limit_kind: SwapLimitKind = .unknown,
    message: []const u8 = "",
};

const Hierarchy = enum { v1, v2 };

const Controller = enum {
    cpu,
    cpuacct,
    cpuset,
    memory,

    fn index(self: Controller) usize {
        return @intFromEnum(self);
    }
};

const controller_names = [_][]const u8{ "cpu", "cpuacct", "cpuset", "memory" };

const Version = enum { none, v1, v2 };

const MountInfo = struct {
    root: [max_path]u8 = undefined,
    root_len: usize = 0,
    mountpoint: [max_path]u8 = undefined,
    mountpoint_len: usize = 0,
    hierarchy: Hierarchy = .v2,
    controllers: [max_controllers]Controller = undefined,
    controller_count: usize = 0,

    fn rootSlice(self: *const MountInfo) []const u8 {
        return self.root[0..self.root_len];
    }

    fn mountpointSlice(self: *const MountInfo) []const u8 {
        return self.mountpoint[0..self.mountpoint_len];
    }

    fn hasController(self: *const MountInfo, controller: Controller) bool {
        if (self.hierarchy != .v1) return true;
        for (self.controllers[0..self.controller_count]) |entry| {
            if (entry == controller) return true;
        }
        return false;
    }
};

/// Absolute cgroup directory a controller is read from, plus the mount point
/// that bounds upward traversal.
const Target = struct {
    version: Version = .none,
    dir: [max_path]u8 = undefined,
    dir_len: usize = 0,
    base_len: usize = 0,

    fn slice(self: *const Target) []const u8 {
        return self.dir[0..self.dir_len];
    }

    fn set(self: *Target, source: []const u8, base_len: usize) bool {
        if (source.len > max_path) return false;
        @memcpy(self.dir[0..source.len], source);
        self.dir_len = source.len;
        self.base_len = base_len;
        return true;
    }
};

const Members = struct {
    v2: ?[]const u8 = null,
    paths: [max_controllers]?[]const u8 = .{ null, null, null, null },

    fn forController(self: *const Members, controller: Controller) ?[]const u8 {
        return self.paths[controller.index()];
    }
};

const Missing = struct {
    cpu: bool = false,
    ram: bool = false,
    swap: bool = false,
    cache_stats: bool = false,
};

const Notes = struct {
    items: [max_notes][]const u8 = .{ "", "", "", "", "", "", "", "" },
    count: usize = 0,

    fn add(self: *Notes, note: []const u8) void {
        if (self.count == self.items.len) return;
        self.items[self.count] = note;
        self.count += 1;
    }
};

const Diagnostics = struct {
    mode: Scope = .host,
    cpu_quota_source: []const u8 = "unknown",
    cpu_cpuset_source: []const u8 = "unknown",
    cpu_accounting_source: []const u8 = "unknown",
    memory_source: []const u8 = "unknown",
    swap_source: []const u8 = "unknown",
    ram_total_known: bool = false,
    swap_total_known: bool = false,
    notes: Notes = .{},
};

const Scratch = struct {
    mountinfo: [mountinfo_bytes]u8 = undefined,
    self_cgroup: [list_bytes]u8 = undefined,
    pid1_cgroup: [list_bytes]u8 = undefined,
    pid1_comm: [256]u8 = undefined,
    pid1_environ: [list_bytes]u8 = undefined,
    list: [list_bytes]u8 = undefined,
    small: [scalar_bytes]u8 = undefined,
    path: [max_path]u8 = undefined,
};

const CpuBaseline = struct {
    counter: u64,
    unit_ns: u32,
    monotonic_ns: i128,
    capacity: f64,
    inode: u128,
    target_hash: u64,
    target_len: usize,
};

const OptionKey = struct {
    mode_len: usize = 0,
    mode_hash: u64 = 0,
    path_len: usize = 0,
    path_hash: u64 = 0,
    proc_len: usize = 0,
    proc_hash: u64 = 0,

    fn of(options: common.SnapshotOptions) OptionKey {
        return .{
            .mode_len = options.resource_mode.len,
            .mode_hash = std.hash.Wyhash.hash(0, options.resource_mode),
            .path_len = options.cgroup_path.len,
            .path_hash = std.hash.Wyhash.hash(0, options.cgroup_path),
            .proc_len = options.host_proc.len,
            .proc_hash = std.hash.Wyhash.hash(0, options.host_proc),
        };
    }

    fn eql(a: OptionKey, b: OptionKey) bool {
        return a.mode_len == b.mode_len and a.mode_hash == b.mode_hash and
            a.path_len == b.path_len and a.path_hash == b.path_hash and
            a.proc_len == b.proc_len and a.proc_hash == b.proc_hash;
    }
};

// ---------------------------------------------------------------------------
// Pure parsers (no filesystem access, no allocation)
// ---------------------------------------------------------------------------

const CpuRange = struct {
    start: u32,
    end: u32,
};

fn parseCpuNumber(token: []const u8) ?u32 {
    if (token.len == 0) return null;
    for (token) |ch| {
        if (!std.ascii.isDigit(ch)) return null;
    }
    return std.fmt.parseInt(u32, token, 10) catch null;
}

fn parseCpuRanges(bytes: []const u8, out: *[max_ranges]CpuRange) !usize {
    const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
    if (trimmed.len == 0) return 0;

    var count: usize = 0;
    var previous_end: ?u32 = null;
    var it = std.mem.splitScalar(u8, trimmed, ',');
    while (it.next()) |token_raw| {
        const token = std.mem.trim(u8, token_raw, " \t");
        if (token.len == 0) return error.InvalidCpuSet;

        var start: u32 = undefined;
        var end: u32 = undefined;
        if (std.mem.indexOfScalar(u8, token, '-')) |dash| {
            start = parseCpuNumber(token[0..dash]) orelse return error.InvalidCpuSet;
            end = parseCpuNumber(token[dash + 1 ..]) orelse return error.InvalidCpuSet;
            if (end < start) return error.InvalidCpuSet;
        } else {
            start = parseCpuNumber(token) orelse return error.InvalidCpuSet;
            end = start;
        }

        if (previous_end) |prev| {
            if (start <= prev) return error.InvalidCpuSet;
        }
        if (count == out.len) return error.InvalidCpuSet;
        out[count] = .{ .start = start, .end = end };
        count += 1;
        previous_end = end;
    }
    return count;
}

/// Count CPUs in a cpuset list such as `0-3,8,10-11`. An empty list is a valid
/// empty set and yields 0; malformed, unsorted or overlapping input is an error.
pub fn parseCpuSet(bytes: []const u8) !u32 {
    var ranges: [max_ranges]CpuRange = undefined;
    const count = try parseCpuRanges(bytes, &ranges);
    var total: u64 = 0;
    for (ranges[0..count]) |range| {
        total += @as(u64, range.end - range.start) + 1;
        if (total > std.math.maxInt(u32)) return error.InvalidCpuSet;
    }
    return @intCast(total);
}

/// Number of CPUs covered by a parsed range list.
fn countCpuRanges(ranges: []const CpuRange) u32 {
    var total: u64 = 0;
    for (ranges) |range| total += @as(u64, range.end - range.start) + 1;
    return @intCast(@min(total, std.math.maxInt(u32)));
}

/// Size of the intersection of two sorted, non-overlapping range lists.
fn intersectCpuRanges(a: []const CpuRange, b: []const CpuRange) u32 {
    var i: usize = 0;
    var j: usize = 0;
    var total: u64 = 0;
    while (i < a.len and j < b.len) {
        const start = @max(a[i].start, b[j].start);
        const end = @min(a[i].end, b[j].end);
        if (start <= end) total += @as(u64, end - start) + 1;
        if (a[i].end < b[j].end) {
            i += 1;
        } else if (b[j].end < a[i].end) {
            j += 1;
        } else {
            i += 1;
            j += 1;
        }
    }
    return @intCast(@min(total, std.math.maxInt(u32)));
}

/// Parse cgroup v2 `cpu.max` (`<quota> <period>` / `max <period>`).
/// Returns null for an unlimited quota.
pub fn parseCpuMaxV2(bytes: []const u8) !?f64 {
    var it = std.mem.tokenizeAny(u8, bytes, " \t\r\n");
    const quota_token = it.next() orelse return error.InvalidCgroupValue;
    if (std.mem.eql(u8, quota_token, "max")) return null;
    const quota = std.fmt.parseInt(u64, quota_token, 10) catch return error.InvalidCgroupValue;
    const period_token = it.next() orelse return error.InvalidCgroupValue;
    const period = std.fmt.parseInt(u64, period_token, 10) catch return error.InvalidCgroupValue;
    if (quota == 0 or period == 0) return error.InvalidCgroupValue;
    return @as(f64, @floatFromInt(quota)) / @as(f64, @floatFromInt(period));
}

/// Parse cgroup v1 `cpu.cfs_quota_us` and `cpu.cfs_period_us`.
/// `-1` (and only `-1`) means unlimited.
pub fn parseCpuQuotaV1(quota_bytes: []const u8, period_bytes: []const u8) !?f64 {
    const quota_text = std.mem.trim(u8, quota_bytes, " \t\r\n");
    const period_text = std.mem.trim(u8, period_bytes, " \t\r\n");
    if (std.mem.eql(u8, quota_text, "-1")) return null;
    const quota = std.fmt.parseInt(i64, quota_text, 10) catch return error.InvalidCgroupValue;
    if (quota <= 0) return error.InvalidCgroupValue;
    const period = std.fmt.parseInt(u64, period_text, 10) catch return error.InvalidCgroupValue;
    if (period == 0) return error.InvalidCgroupValue;
    return @as(f64, @floatFromInt(quota)) / @as(f64, @floatFromInt(period));
}

fn isUnlimitedMemoryV1(value: u64) bool {
    return value == 0x7ffff000 or value >= 0x7ffffffffffff000;
}

/// Parse `memory.max` (v2) or `memory.limit_in_bytes` (v1).
/// `max` (v2) and the v1 page-counter sentinels mean unlimited; 0 is a valid
/// hard limit in both versions.
pub fn parseMemoryLimit(bytes: []const u8, version: enum { v1, v2 }) !?u64 {
    const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidCgroupValue;
    if (version == .v2 and std.mem.eql(u8, trimmed, "max")) return null;
    const value = std.fmt.parseInt(u64, trimmed, 10) catch return error.InvalidCgroupValue;
    if (version == .v1 and isUnlimitedMemoryV1(value)) return null;
    return value;
}

// ---------------------------------------------------------------------------
// Bounded filesystem helpers
// ---------------------------------------------------------------------------

const ReadResult = union(enum) {
    ok: []const u8,
    missing,
    failed,
};

/// Read at most `buf.len` bytes. A completely filled buffer may hide more
/// data, so it is reported as a failure instead of partial content.
fn readBounded(path: []const u8, buf: []u8) ReadResult {
    const file = compat.openFile(path, .{}) catch |err| return switch (err) {
        error.FileNotFound => .missing,
        else => .failed,
    };
    defer file.close(std.Options.debug_io);
    const n = compat.readAll(file, buf) catch return .failed;
    if (n == buf.len) return .failed;
    return .{ .ok = buf[0..n] };
}

/// Content of one control file together with the inode of the handle it was
/// read from. The inode is taken from the same open handle, so a cgroup
/// directory recreated at the same path is detected without a second call.
const Content = struct {
    bytes: []const u8,
    inode: u128,
};

const ContentResult = union(enum) {
    ok: Content,
    missing,
    failed,
};

fn readContentWithInode(path: []const u8, buf: []u8) ContentResult {
    const file = compat.openFile(path, .{}) catch |err| return switch (err) {
        error.FileNotFound => .missing,
        else => .failed,
    };
    defer file.close(std.Options.debug_io);
    const stat = file.stat(std.Options.debug_io) catch return .failed;
    const n = compat.readAll(file, buf) catch return .failed;
    if (n == buf.len) return .failed;
    return .{ .ok = .{ .bytes = buf[0..n], .inode = @intCast(stat.inode) } };
}

fn joinPath(out: []u8, dir: []const u8, name: []const u8) ?[]const u8 {
    if (dir.len + name.len > out.len) return null;
    @memcpy(out[0..dir.len], dir);
    @memcpy(out[dir.len..][0..name.len], name);
    return out[0 .. dir.len + name.len];
}

fn fileExists(path: []const u8) bool {
    _ = compat.statFile(path) catch return false;
    return true;
}

fn memInfoValue(bytes: []const u8, key: []const u8) ?u64 {
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.mem.eql(u8, name, key)) continue;
        var fields = std.mem.tokenizeAny(u8, line[colon + 1 ..], " \t\r");
        const raw = fields.next() orelse return null;
        const value = std.fmt.parseInt(u64, raw, 10) catch return null;
        return std.math.mul(u64, value, 1024) catch null;
    }
    return null;
}

fn statValue(bytes: []const u8, key: []const u8) ?u64 {
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        const name = fields.next() orelse continue;
        if (!std.mem.eql(u8, name, key)) continue;
        const raw = fields.next() orelse return null;
        return std.fmt.parseInt(u64, raw, 10) catch null;
    }
    return null;
}

// ---------------------------------------------------------------------------
// mountinfo and cgroup membership parsing
// ---------------------------------------------------------------------------

fn decodeOctalEscapes(src: []const u8, out: []u8) ?[]const u8 {
    var len: usize = 0;
    var i: usize = 0;
    while (i < src.len) {
        const ch = src[i];
        if (ch == '\\' and i + 3 < src.len) {
            const octal = src[i + 1 .. i + 4];
            var value: u32 = 0;
            var valid = true;
            for (octal) |digit| {
                if (digit < '0' or digit > '7') {
                    valid = false;
                    break;
                }
                value = value * 8 + (digit - '0');
            }
            if (valid and value <= 0xff) {
                if (len == out.len) return null;
                out[len] = @intCast(value);
                len += 1;
                i += 4;
                continue;
            }
        }
        if (len == out.len) return null;
        out[len] = ch;
        len += 1;
        i += 1;
    }
    return out[0..len];
}

fn normalizeRoot(root: []const u8) []const u8 {
    if (root.len > 1 and root[root.len - 1] == '/') return root[0 .. root.len - 1];
    return root;
}

fn parseControllerToken(token: []const u8) ?Controller {
    for (controller_names, 0..) |name, i| {
        if (std.mem.eql(u8, token, name)) return @enumFromInt(i);
    }
    return null;
}

fn parseMountInfo(bytes: []const u8, out: *[max_mounts]MountInfo) usize {
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const separator = std.mem.indexOf(u8, line, " - ") orelse continue;
        const left = line[0..separator];
        const right = line[separator + 3 ..];

        var left_fields = std.mem.tokenizeScalar(u8, left, ' ');
        _ = left_fields.next() orelse continue;
        _ = left_fields.next() orelse continue;
        _ = left_fields.next() orelse continue;
        const root_raw = left_fields.next() orelse continue;
        const mountpoint_raw = left_fields.next() orelse continue;

        var right_fields = std.mem.tokenizeScalar(u8, right, ' ');
        const fstype = right_fields.next() orelse continue;
        _ = right_fields.next() orelse continue;
        const super_options = right_fields.rest();

        const hierarchy: Hierarchy = if (std.mem.eql(u8, fstype, "cgroup2"))
            .v2
        else if (std.mem.eql(u8, fstype, "cgroup"))
            .v1
        else
            continue;

        if (count == out.len) return count;
        var entry = &out[count];
        const root = decodeOctalEscapes(root_raw, &entry.root) orelse continue;
        entry.root_len = root.len;
        const mountpoint = decodeOctalEscapes(mountpoint_raw, &entry.mountpoint) orelse continue;
        entry.mountpoint_len = mountpoint.len;
        entry.hierarchy = hierarchy;
        entry.controller_count = 0;

        if (hierarchy == .v1) {
            var options = std.mem.splitScalar(u8, std.mem.trim(u8, super_options, " \t\r"), ',');
            while (options.next()) |option| {
                const controller = parseControllerToken(std.mem.trim(u8, option, " \t")) orelse continue;
                if (entry.controller_count == max_controllers) break;
                entry.controllers[entry.controller_count] = controller;
                entry.controller_count += 1;
            }
        }
        count += 1;
    }
    return count;
}

fn parseMembers(bytes: []const u8, out: *Members) void {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        const first = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const rest = line[first + 1 ..];
        const second = std.mem.indexOfScalar(u8, rest, ':') orelse continue;
        const controllers = rest[0..second];
        const path = std.mem.trim(u8, rest[second + 1 ..], " \t\r");
        if (path.len == 0 or path[0] != '/') continue;

        if (controllers.len == 0) {
            if (out.v2 == null) out.v2 = path;
            continue;
        }
        var list = std.mem.splitScalar(u8, controllers, ',');
        while (list.next()) |token| {
            const controller = parseControllerToken(std.mem.trim(u8, token, " \t")) orelse continue;
            if (out.paths[controller.index()] == null) out.paths[controller.index()] = path;
        }
    }
}

// ---------------------------------------------------------------------------
// Container boundary selection
// ---------------------------------------------------------------------------

fn isSegmentAncestor(ancestor: []const u8, path: []const u8) bool {
    if (ancestor.len == 0) return true;
    if (std.mem.eql(u8, ancestor, "/")) return true;
    if (std.mem.eql(u8, ancestor, path)) return true;
    if (!std.mem.startsWith(u8, path, ancestor)) return false;
    return path.len > ancestor.len and path[ancestor.len] == '/';
}

fn hasScopeSuffix(segment: []const u8, prefix: []const u8) bool {
    return std.mem.startsWith(u8, segment, prefix) and
        std.mem.endsWith(u8, segment, ".scope") and
        segment.len >= prefix.len + ".scope".len + 1;
}

fn isContainerComponent(segment: []const u8) bool {
    return hasScopeSuffix(segment, "docker-") or
        hasScopeSuffix(segment, "cri-containerd-") or
        hasScopeSuffix(segment, "containerd-") or
        hasScopeSuffix(segment, "libpod-") or
        hasScopeSuffix(segment, "podman-") or
        hasScopeSuffix(segment, "machine-") or
        std.mem.startsWith(u8, segment, "lxc.payload.") or
        std.mem.eql(u8, segment, "docker") or
        std.mem.eql(u8, segment, "lxc");
}

/// Innermost container boundary inside a cgroup membership path. Pod slices are
/// deliberately not treated as a boundary.
fn containerBoundary(path: []const u8) ?[]const u8 {
    var boundary: ?[]const u8 = null;
    var index: usize = 0;
    while (index < path.len) {
        const start = if (path[index] == '/') index + 1 else index;
        if (start >= path.len) break;
        const next = std.mem.indexOfScalarPos(u8, path, start, '/') orelse path.len;
        const segment = path[start..next];
        if (isContainerComponent(segment)) {
            // `/docker/<id>` and `/lxc/<name>` include the following segment.
            if ((std.mem.eql(u8, segment, "docker") or std.mem.eql(u8, segment, "lxc")) and next < path.len) {
                const id_end = std.mem.indexOfScalarPos(u8, path, next + 1, '/') orelse path.len;
                boundary = path[0..id_end];
            } else {
                boundary = path[0..next];
            }
        }
        index = next;
    }
    return boundary;
}

/// True when any recorded membership path (v2 or v1 controller rows) contains a
/// container component. Plain hosts do not use these path shapes for their own
/// service groups.
fn membersHaveContainerPath(members: *const Members) bool {
    if (members.v2) |path| {
        if (containerBoundary(path) != null) return true;
    }
    for (members.paths) |maybe_path| {
        if (maybe_path) |path| {
            if (containerBoundary(path) != null) return true;
        }
    }
    return false;
}

fn stripInitScope(path: []const u8) []const u8 {
    if (std.mem.eql(u8, path, "/init.scope")) return "/";
    if (std.mem.endsWith(u8, path, "/init.scope")) return path[0 .. path.len - "/init.scope".len];
    return path;
}

/// Pick the cgroup membership path that represents the whole container.
/// Prefers the PID 1 boundary, falls back to the agent process path when PID 1
/// is not an ancestor. Returns null when the relationship cannot be explained.
fn boundaryMember(self_path: []const u8, pid1_path: ?[]const u8, pid1_is_systemd: bool) ?[]const u8 {
    var candidate = pid1_path orelse self_path;
    if (pid1_path != null and pid1_is_systemd) candidate = stripInitScope(candidate);

    if (containerBoundary(candidate)) |boundary| return boundary;
    if (containerBoundary(self_path)) |boundary| return boundary;
    if (std.mem.eql(u8, candidate, "/") or candidate.len == 0) return "/";
    if (isSegmentAncestor(candidate, self_path)) return candidate;
    return null;
}

const Mapped = struct {
    dir_len: usize,
    base_len: usize,
};

/// Map a cgroup membership path onto a cgroup mount. Chooses the most specific
/// (longest) mount root that covers the path and never leaves that mount.
fn mapMember(
    mounts: []const MountInfo,
    member: []const u8,
    selector: union(enum) { v2, controller: Controller },
    out: []u8,
) ?Mapped {
    var best: ?usize = null;
    var best_root_len: usize = 0;
    for (mounts, 0..) |mount, i| {
        switch (selector) {
            .v2 => if (mount.hierarchy != .v2) continue,
            // A controller selector means "the v1 hierarchy that actually owns
            // this controller", so unified v2 mounts never match it.
            .controller => |controller| if (mount.hierarchy != .v1 or !mount.hasController(controller)) continue,
        }
        const root = normalizeRoot(mount.rootSlice());
        const covers = std.mem.eql(u8, root, "/") or
            std.mem.eql(u8, member, root) or
            (std.mem.startsWith(u8, member, root) and member.len > root.len and member[root.len] == '/');
        if (!covers) continue;
        if (best != null and root.len <= best_root_len) continue;
        best = i;
        best_root_len = root.len;
    }

    const mount_index = best orelse return null;
    const mount = &mounts[mount_index];
    const root = normalizeRoot(mount.rootSlice());
    // An exact membership match maps to the mount point itself; a `/` root does
    // not push a trailing slash onto the mount point.
    const suffix = if (std.mem.eql(u8, root, member))
        ""
    else if (std.mem.eql(u8, root, "/"))
        member
    else
        member[root.len..];
    const mountpoint = normalizeRoot(mount.mountpointSlice());
    const dir = joinPath(out, mountpoint, suffix) orelse return null;
    return .{ .dir_len = dir.len, .base_len = mountpoint.len };
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

const RamResult = struct {
    charged: ?u64 = null,
    inactive: ?u64 = null,
    used: ?u64 = null,
    total: u64 = 0,
    total_known: bool = false,
    cache_stats: bool = false,
    total_source: []const u8 = "unknown",
};

const SwapResult = struct {
    used: ?u64 = null,
    total: u64 = 0,
    total_known: bool = false,
    kind: SwapLimitKind = .unknown,
    source: []const u8 = "unknown",
};

const CpuResult = struct {
    capacity: ?f64 = null,
    cores: u32 = 0,
    usage: f64 = cpu_report_floor,
    quota_source: []const u8 = "unknown",
    cpuset_source: []const u8 = "unknown",
    accounting_source: []const u8 = "unknown",
};

const CpuCounter = struct {
    counter: u64,
    unit_ns: u32,
    inode: u128,
};

pub const Collector = struct {
    sources: SourcePaths = .{},
    located: bool = false,
    located_ns: i128 = 0,
    option_key: OptionKey = .{},
    scope: Scope = .host,
    hint: []const u8 = "",
    locate_failed: bool = false,
    mount_count: usize = 0,
    mounts: [max_mounts]MountInfo = undefined,
    targets: [max_controllers]Target = .{ .{}, .{}, .{}, .{} },
    cpu_baseline: ?CpuBaseline = null,
    missing: Missing = .{},
    diag: Diagnostics = .{},
    last: ResourceSample = .{},
    scratch: Scratch = .{},

    pub fn init(sources: SourcePaths) Collector {
        return .{ .sources = sources };
    }

    pub fn describe(self: *const Collector, writer: anytype) !void {
        try writer.print("--- Container Resource Scope ---\n", .{});
        try writer.print("Resource scope: {s}\n", .{@tagName(self.scope)});
        if (self.scope == .host) {
            try writer.writeAll("Resource mode: host view (no container cgroup applied)\n");
            return;
        }
        if (self.hint.len != 0) try writer.print("Container hint: {s}\n", .{self.hint});
        if (self.last.cpu_capacity) |capacity| {
            try writer.print("CPU capacity: {d:.3} (cores {d})\n", .{ capacity, self.last.cpu_cores });
        } else {
            try writer.print("CPU capacity: unavailable (cores 0)\n", .{});
        }
        try writer.print("CPU quota source: {s}\n", .{self.diag.cpu_quota_source});
        try writer.print("CPU cpuset source: {s}\n", .{self.diag.cpu_cpuset_source});
        try writer.print("CPU accounting: {s}\n", .{self.diag.cpu_accounting_source});
        try writer.print("Memory source: {s}\n", .{self.diag.memory_source});
        if (self.last.charged_memory) |charged| {
            try writer.print("Memory charged: {d}\n", .{charged});
        } else {
            try writer.writeAll("Memory charged: unavailable\n");
        }
        if (self.last.inactive_file) |inactive| {
            try writer.print("Memory inactive_file: {d}\n", .{inactive});
        } else {
            try writer.writeAll("Memory inactive_file: unavailable\n");
        }
        try writer.print("Swap source: {s}\n", .{self.diag.swap_source});
        try writer.print("Swap limit kind: {s}\n", .{@tagName(self.last.swap_limit_kind)});
        try writer.print("RAM total: {d} used: {d} (known total: {s})\n", .{
            self.last.ram.total,
            self.last.ram.used,
            if (self.diag.ram_total_known) "yes" else "no",
        });
        try writer.print("Swap total: {d} used: {d} (known total: {s})\n", .{
            self.last.swap.total,
            self.last.swap.used,
            if (self.diag.swap_total_known) "yes" else "no",
        });
        if (self.targets[0].version != .none) {
            try writer.print("CPU target: {s} {s}\n", .{ @tagName(self.targets[0].version), self.targets[0].slice() });
        }
        if (self.targets[Controller.cpuacct.index()].version != .none) {
            try writer.print("CPU accounting target: {s} {s}\n", .{ @tagName(self.targets[Controller.cpuacct.index()].version), self.targets[Controller.cpuacct.index()].slice() });
        }
        if (self.targets[Controller.cpuset.index()].version != .none) {
            try writer.print("CPU cpuset target: {s} {s}\n", .{ @tagName(self.targets[Controller.cpuset.index()].version), self.targets[Controller.cpuset.index()].slice() });
        }
        if (self.targets[Controller.memory.index()].version != .none) {
            try writer.print("Memory target: {s} {s}\n", .{ @tagName(self.targets[Controller.memory.index()].version), self.targets[Controller.memory.index()].slice() });
        }
        if (self.missing.cpu) try writer.writeAll("Missing: CPU capacity\n");
        if (self.missing.ram) try writer.writeAll("Missing: RAM accounting\n");
        if (self.missing.swap) try writer.writeAll("Missing: swap accounting\n");
        if (self.missing.cache_stats) try writer.writeAll("Degraded: memory cache statistics\n");
        for (self.diag.notes.items[0..self.diag.notes.count]) |note| {
            if (note.len != 0) try writer.print("Note: {s}\n", .{note});
        }
        try writer.writeAll("-------------------------------\n");
    }

    /// Collect one resource sample. `update_cpu_sample` must be false for the
    /// basic-info and diagnostic paths so they never consume the live CPU
    /// baseline.
    pub fn read(
        self: *Collector,
        options: common.SnapshotOptions,
        now_ns: i128,
        update_cpu_sample: bool,
    ) ResourceSample {
        const key = OptionKey.of(options);
        if (isHostMode(options)) {
            self.located = false;
            self.scope = .host;
            self.hint = "";
            self.last = .{ .scope = .host };
            return self.last;
        }

        const was_cached = self.located and OptionKey.eql(self.option_key, key) and
            now_ns >= self.located_ns and now_ns - self.located_ns < resolve_ttl_ns;
        if (!was_cached) self.locate(options, now_ns, key);

        if (self.scope == .host) {
            self.last = .{ .scope = .host };
            return self.last;
        }

        var sample = self.collect(options, now_ns, update_cpu_sample);
        if (self.locate_failed and was_cached) {
            // A required control file disappeared or turned unreadable: drop the
            // cached location and relocate exactly once.
            self.locate(options, now_ns, key);
            if (self.scope != .host) sample = self.collect(options, now_ns, update_cpu_sample);
        }
        self.last = sample;
        // Diagnostics must describe what was actually reported: a container
        // whose CPU/RAM/Swap are all unusable is `unavailable`, not `container`.
        self.scope = sample.scope;
        return sample;
    }

    fn locate(self: *Collector, options: common.SnapshotOptions, now_ns: i128, key: OptionKey) void {
        self.located = true;
        self.located_ns = now_ns;
        self.option_key = key;
        self.locate_failed = false;
        self.scope = .host;
        self.hint = "";
        self.diag = .{};
        self.mount_count = 0;
        for (&self.targets) |*target| target.* = .{};

        var path_buf: [max_path]u8 = undefined;
        const mountinfo_path = joinPath(&path_buf, self.sources.proc_root, "/self/mountinfo") orelse {
            self.locate_failed = true;
            self.scope = .unavailable;
            return;
        };
        const mountinfo = switch (readBounded(mountinfo_path, &self.scratch.mountinfo)) {
            .ok => |bytes| bytes,
            else => {
                self.locate_failed = true;
                self.scope = .unavailable;
                return;
            },
        };
        self.mount_count = parseMountInfo(mountinfo, &self.mounts);
        if (self.mount_count == 0) {
            self.locate_failed = true;
            self.scope = .unavailable;
            return;
        }

        var self_members = Members{};
        var pid1_members = Members{};
        const self_path = joinPath(&path_buf, self.sources.proc_root, "/self/cgroup") orelse return;
        switch (readBounded(self_path, &self.scratch.self_cgroup)) {
            .ok => |bytes| parseMembers(bytes, &self_members),
            else => {},
        }
        var pid1_path_buf: [max_path]u8 = undefined;
        const pid1_path = joinPath(&pid1_path_buf, self.sources.proc_root, "/1/cgroup") orelse return;
        switch (readBounded(pid1_path, &self.scratch.pid1_cgroup)) {
            .ok => |bytes| parseMembers(bytes, &pid1_members),
            else => {},
        }

        const pid1_is_systemd = blk: {
            const comm_path = joinPath(&path_buf, self.sources.proc_root, "/1/comm") orelse break :blk false;
            const comm = switch (readBounded(comm_path, &self.scratch.pid1_comm)) {
                .ok => |bytes| std.mem.trim(u8, bytes, " \t\r\n"),
                else => break :blk false,
            };
            break :blk std.mem.eql(u8, comm, "systemd");
        };

        const explicit = options.cgroup_path.len != 0;
        const forced = std.mem.eql(u8, options.resource_mode, "container") or explicit;
        if (!forced) {
            if (!self.detectHints(&self_members, &pid1_members, &path_buf)) {
                self.scope = .host;
                return;
            }
        }

        if (!self.locateTargets(options, &self_members, &pid1_members, pid1_is_systemd)) {
            self.scope = .unavailable;
            return;
        }
        self.scope = .container;
    }

    /// Container clues only. A plain systemd host has none of these, so it keeps
    /// the original whole-machine behaviour.
    fn detectHints(
        self: *Collector,
        self_members: *const Members,
        pid1_members: *const Members,
        path_buf: *[max_path]u8,
    ) bool {
        const markers = [_][]const u8{
            self.sources.docker_marker,
            self.sources.podman_marker,
            self.sources.lxc_marker,
            self.sources.agent_marker,
        };
        for (markers) |marker| {
            if (fileExists(marker)) {
                self.hint = "container marker file";
                return true;
            }
        }

        switch (readBounded(self.sources.systemd_container, &self.scratch.small)) {
            .ok => |bytes| if (std.mem.trim(u8, bytes, " \t\r\n").len != 0) {
                self.hint = "systemd container detection";
                return true;
            },
            else => {},
        }

        const environ_path = joinPath(path_buf, self.sources.proc_root, "/1/environ") orelse "";
        if (environ_path.len != 0) {
            switch (readBounded(environ_path, &self.scratch.pid1_environ)) {
                .ok => |bytes| if (hasContainerEnvironment(bytes)) {
                    self.hint = "container environment";
                    return true;
                },
                else => {},
            }
        }

        if (membersHaveContainerPath(self_members) or membersHaveContainerPath(pid1_members)) {
            self.hint = "container cgroup path";
            return true;
        }

        // A real cgroup v2 root never exposes a finite quota, so a root view
        // that reports one means the mount is scoped to the container.
        if (self_members.v2) |path| {
            if (mapMember(self.mounts[0..self.mount_count], path, .v2, &self.scratch.path)) |mapped| {
                const dir = self.scratch.path[0..mapped.dir_len];
                if (mapped.dir_len == mapped.base_len and self.mountRootHasFiniteLimit(dir)) {
                    self.hint = "restricted cgroup root view";
                    return true;
                }
            }
        }
        return false;
    }

    fn mountRootHasFiniteLimit(self: *Collector, dir: []const u8) bool {
        var path_buf: [max_path]u8 = undefined;
        if (joinPath(&path_buf, dir, "/cpu.max")) |path| {
            switch (readBounded(path, &self.scratch.small)) {
                .ok => |bytes| if (parseCpuMaxV2(bytes) catch null) |_| return true,
                else => {},
            }
        }
        if (joinPath(&path_buf, dir, "/memory.max")) |path| {
            switch (readBounded(path, &self.scratch.small)) {
                .ok => |bytes| if (parseMemoryLimit(bytes, .v2) catch null) |_| return true,
                else => {},
            }
        }
        return false;
    }

    fn locateTargets(
        self: *Collector,
        options: common.SnapshotOptions,
        self_members: *const Members,
        pid1_members: *const Members,
        pid1_is_systemd: bool,
    ) bool {
        const v2_available = self.hasV2Mount();
        const explicit = options.cgroup_path;

        if (explicit.len != 0) {
            return self.assignExplicit(explicit);
        }

        var any = false;
        for (0..max_controllers) |i| {
            const controller: Controller = @enumFromInt(i);
            const member = self.controllerMember(self_members, pid1_members, pid1_is_systemd, controller);
            if (member == null) continue;
            if (self.assignMember(controller, member.?, v2_available)) any = true;
        }
        return any;
    }

    fn hasV2Mount(self: *Collector) bool {
        for (self.mounts[0..self.mount_count]) |*mount| {
            if (mount.hierarchy == .v2) return true;
        }
        return false;
    }

    fn controllerMember(
        self: *Collector,
        self_members: *const Members,
        pid1_members: *const Members,
        pid1_is_systemd: bool,
        controller: Controller,
    ) ?[]const u8 {
        _ = self;
        const self_path = self_members.forController(controller) orelse self_members.v2;
        const pid1_path = pid1_members.forController(controller) orelse pid1_members.v2;
        if (self_path == null and pid1_path == null) return null;
        return boundaryMember(self_path orelse "", pid1_path, pid1_is_systemd);
    }

    fn assignExplicit(self: *Collector, member: []const u8) bool {
        var any = false;
        for (0..max_controllers) |i| {
            const controller: Controller = @enumFromInt(i);
            if (self.assignMember(controller, member, self.hasV2Mount())) any = true;
        }
        return any;
    }

    fn assignMember(self: *Collector, controller: Controller, member: []const u8, v2_available: bool) bool {
        // Hybrid hierarchies: when this controller has a v1 binding, that
        // binding is where the container actually lives; a unified mount covers
        // the path but holds no controller data for it.
        if (mapMember(self.mounts[0..self.mount_count], member, .{ .controller = controller }, &self.scratch.path)) |mapped| {
            const target = &self.targets[controller.index()];
            if (!target.set(self.scratch.path[0..mapped.dir_len], mapped.base_len)) return false;
            target.version = .v1;
            return true;
        }

        if (v2_available) {
            if (mapMember(self.mounts[0..self.mount_count], member, .v2, &self.scratch.path)) |mapped| {
                const target = &self.targets[controller.index()];
                if (!target.set(self.scratch.path[0..mapped.dir_len], mapped.base_len)) return false;
                target.version = .v2;
                return true;
            }
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Sampling
    // -----------------------------------------------------------------------

    fn collect(
        self: *Collector,
        options: common.SnapshotOptions,
        now_ns: i128,
        update_cpu_sample: bool,
    ) ResourceSample {
        self.locate_failed = false;
        self.missing = .{};

        const cpu = self.sampleCpu(now_ns, update_cpu_sample);
        const ram = self.sampleRam(options);
        const swap = self.sampleSwap();

        self.diag.cpu_quota_source = cpu.quota_source;
        self.diag.cpu_cpuset_source = cpu.cpuset_source;
        self.diag.cpu_accounting_source = cpu.accounting_source;
        self.diag.memory_source = ram.total_source;
        self.diag.swap_source = swap.source;
        self.diag.ram_total_known = ram.total_known;
        self.diag.swap_total_known = swap.total_known;
        self.diag.mode = .container;

        self.missing.cpu = cpu.capacity == null;
        self.missing.ram = !ram.total_known or ram.charged == null;
        self.missing.swap = !swap.total_known or swap.used == null;
        self.missing.cache_stats = !ram.cache_stats;

        const any_available = !self.missing.cpu or !self.missing.ram or !self.missing.swap;
        var sample = ResourceSample{
            .scope = if (any_available) .container else .unavailable,
            .cpu_capacity = cpu.capacity,
            .cpu_cores = cpu.cores,
            .cpu_usage = cpu.usage,
            .ram = .{ .total = ram.total, .used = ram.used orelse 0 },
            .swap = .{ .total = swap.total, .used = swap.used orelse 0 },
            .charged_memory = ram.charged,
            .inactive_file = ram.inactive,
            .swap_limit_kind = swap.kind,
        };

        if (self.missing.cpu or self.missing.ram or self.missing.swap) {
            // Any unavailable component is surfaced explicitly; the remaining
            // components still report their real values.
            sample.message = msg_unavailable;
        } else if (!ram.cache_stats) {
            sample.message = msg_cache_missing;
        } else if (swap.kind == .shared_memsw_upper_bound) {
            sample.message = msg_v1_shared_swap;
        }
        return sample;
    }

    fn sampleCpu(self: *Collector, now_ns: i128, update_cpu_sample: bool) CpuResult {
        var result = CpuResult{};
        const cpu_target = &self.targets[Controller.cpu.index()];
        const cpuset_target = &self.targets[Controller.cpuset.index()];

        var quota_unknown = false;
        var quota: ?f64 = null;
        if (cpu_target.version == .v2) {
            quota = self.quotaV2(cpu_target, &quota_unknown);
            result.quota_source = "cgroup v2 cpu.max";
        } else if (cpu_target.version == .v1) {
            quota = self.quotaV1(cpu_target, &quota_unknown);
            result.quota_source = "cgroup v1 cpu.cfs_quota_us";
        }

        const set_count = self.runnableCpus(cpuset_target, &result.cpuset_source);
        // An explicitly empty effective set means the capacity is unknown; it is
        // never patched from the host online list.
        if (set_count == 0) return result;
        // An unreadable level is not an unlimited one: a nearer finite value
        // cannot be trusted as the container ceiling.
        if (quota_unknown) return result;

        const available: ?f64 = if (set_count == std.math.maxInt(u32)) null else @floatFromInt(set_count);
        const capacity: ?f64 = if (available) |count|
            if (quota) |ratio| @min(ratio, count) else count
        else
            null;
        if (capacity == null) return result;

        result.capacity = capacity;
        result.cores = coresForCapacity(capacity.?);

        if (!update_cpu_sample) return result;

        const counter = self.readCpuCounter(&result) orelse return result;
        result.usage = self.cpuUsage(counter, capacity.?, now_ns);
        return result;
    }

    fn readCpuCounter(self: *Collector, result: *CpuResult) ?CpuCounter {
        var path_buf: [max_path]u8 = undefined;
        const cpu_target = &self.targets[Controller.cpu.index()];
        const acct_target = &self.targets[Controller.cpuacct.index()];

        if (cpu_target.version == .v2) {
            const path = joinPath(&path_buf, cpu_target.slice(), "/cpu.stat") orelse {
                self.locate_failed = true;
                return null;
            };
            const content = switch (readContentWithInode(path, &self.scratch.list)) {
                .ok => |value| value,
                .missing => {
                    self.locate_failed = true;
                    return null;
                },
                .failed => return null,
            };
            const usec = statValue(content.bytes, "usage_usec") orelse return null;
            result.accounting_source = "cgroup v2 cpu.stat usage_usec";
            return .{ .counter = usec, .unit_ns = 1000, .inode = content.inode };
        }

        if (acct_target.version == .v1) {
            const path = joinPath(&path_buf, acct_target.slice(), "/cpuacct.usage") orelse {
                self.locate_failed = true;
                return null;
            };
            const content = switch (readContentWithInode(path, &self.scratch.small)) {
                .ok => |value| value,
                .missing => {
                    self.locate_failed = true;
                    return null;
                },
                .failed => return null,
            };
            const text = std.mem.trim(u8, content.bytes, " \t\r\n");
            const value = std.fmt.parseInt(u64, text, 10) catch return null;
            result.accounting_source = "cgroup v1 cpuacct.usage";
            return .{ .counter = value, .unit_ns = 1, .inode = content.inode };
        }
        return null;
    }

    fn cpuUsage(self: *Collector, counter: CpuCounter, capacity: f64, now_ns: i128) f64 {
        const is_v2 = self.targets[Controller.cpu.index()].version == .v2;
        const target = if (is_v2)
            self.targets[Controller.cpu.index()].slice()
        else
            self.targets[Controller.cpuacct.index()].slice();
        const target_hash = std.hash.Wyhash.hash(0, target);

        const previous = self.cpu_baseline;
        self.cpu_baseline = .{
            .counter = counter.counter,
            .unit_ns = counter.unit_ns,
            .monotonic_ns = now_ns,
            .capacity = capacity,
            .inode = counter.inode,
            .target_hash = target_hash,
            .target_len = target.len,
        };

        const baseline = previous orelse return cpu_report_floor;
        if (baseline.unit_ns != counter.unit_ns) return cpu_report_floor;
        if (baseline.target_len != target.len or baseline.target_hash != target_hash) return cpu_report_floor;
        if (baseline.inode != counter.inode) return cpu_report_floor;
        if (baseline.capacity != capacity) return cpu_report_floor;
        if (counter.counter <= baseline.counter) return cpu_report_floor;
        const elapsed = now_ns - baseline.monotonic_ns;
        if (elapsed <= 0) return cpu_report_floor;
        return cpuPercent(counter.counter - baseline.counter, counter.unit_ns, elapsed, capacity);
    }

    fn quotaV2(self: *Collector, target: *const Target, unknown: *bool) ?f64 {
        var best: ?f64 = null;
        var it = AncestorIter{ .dir = target.slice(), .base_len = target.base_len };
        var path_buf: [max_path]u8 = undefined;
        while (it.next()) |dir| {
            const path = joinPath(&path_buf, dir, "/cpu.max") orelse {
                unknown.* = true;
                return best;
            };
            switch (readBounded(path, &self.scratch.small)) {
                .ok => |bytes| {
                    const value = parseCpuMaxV2(bytes) catch {
                        unknown.* = true;
                        return best;
                    };
                    if (value) |ratio| best = if (best) |current| @min(current, ratio) else ratio;
                },
                .missing => {},
                .failed => {
                    unknown.* = true;
                    return best;
                },
            }
        }
        return best;
    }

    fn quotaV1(self: *Collector, target: *const Target, unknown: *bool) ?f64 {
        _ = self;
        var best: ?f64 = null;
        var it = AncestorIter{ .dir = target.slice(), .base_len = target.base_len };
        var path_buf: [max_path]u8 = undefined;
        while (it.next()) |dir| {
            const quota_path = joinPath(&path_buf, dir, "/cpu.cfs_quota_us") orelse {
                unknown.* = true;
                return best;
            };
            // The two scalars need separate buffers: the second read would
            // otherwise overwrite the first one.
            var quota_buf: [64]u8 = undefined;
            var period_buf: [64]u8 = undefined;
            const quota_bytes = switch (readBounded(quota_path, &quota_buf)) {
                .ok => |bytes| bytes,
                .missing => continue,
                .failed => {
                    unknown.* = true;
                    return best;
                },
            };
            const period_path = joinPath(&path_buf, dir, "/cpu.cfs_period_us") orelse {
                unknown.* = true;
                return best;
            };
            const period_bytes = switch (readBounded(period_path, &period_buf)) {
                .ok => |bytes| bytes,
                .missing => continue,
                .failed => {
                    unknown.* = true;
                    return best;
                },
            };
            const value = parseCpuQuotaV1(quota_bytes, period_bytes) catch {
                unknown.* = true;
                return best;
            };
            if (value) |ratio| best = if (best) |current| @min(current, ratio) else ratio;
        }
        return best;
    }

    /// CPU set size for capacity. Returns `maxInt(u32)` when the set is unknown
    /// and must fall back to the online CPU list, and 0 when the set is
    /// explicitly empty (capacity unknown, never patched from the host).
    fn runnableCpus(self: *Collector, target: *const Target, source: *[]const u8) u32 {
        var path_buf: [max_path]u8 = undefined;
        if (target.version == .v2) {
            const path = joinPath(&path_buf, target.slice(), "/cpuset.cpus.effective") orelse return self.onlineCpus(source);
            switch (readBounded(path, &self.scratch.small)) {
                .ok => |bytes| {
                    const count = parseCpuSet(bytes) catch return self.onlineCpus(source);
                    source.* = cgroupLabel("v2", "cpuset.cpus.effective");
                    return count;
                },
                .missing => return self.onlineCpus(source),
                .failed => return self.onlineCpus(source),
            }
        }
        if (target.version == .v1) {
            const effective = joinPath(&path_buf, target.slice(), "/cpuset.effective_cpus") orelse return self.onlineCpus(source);
            switch (readBounded(effective, &self.scratch.small)) {
                .ok => |bytes| {
                    const count = parseCpuSet(bytes) catch return self.onlineCpus(source);
                    source.* = cgroupLabel("v1", "cpuset.effective_cpus");
                    return count;
                },
                .missing => return self.v1ConfiguredCpus(target, source),
                .failed => return self.onlineCpus(source),
            }
        }
        return self.onlineCpus(source);
    }

    /// cgroup v1 fallback: an empty `cpuset.cpus` inherits the nearest
    /// non-empty ancestor set, which is then intersected with the online CPU
    /// set. An empty intersection means the capacity is unknown, not zero-free
    /// guessing from the host.
    fn v1ConfiguredCpus(self: *Collector, target: *const Target, source: *[]const u8) u32 {
        var inherited_buf: [max_ranges]CpuRange = undefined;
        var inherited_count: usize = 0;
        var it = AncestorIter{ .dir = target.slice(), .base_len = target.base_len };
        var path_buf: [max_path]u8 = undefined;
        while (it.next()) |dir| {
            const path = joinPath(&path_buf, dir, "/cpuset.cpus") orelse break;
            switch (readBounded(path, &self.scratch.list)) {
                .ok => |bytes| {
                    const count = parseCpuRanges(bytes, &inherited_buf) catch return self.onlineCpus(source);
                    if (count != 0) {
                        inherited_count = count;
                        source.* = cgroupLabel("v1", "cpuset.cpus");
                        break;
                    }
                },
                .missing => {},
                .failed => return self.onlineCpus(source),
            }
        }
        if (inherited_count == 0) return self.onlineCpus(source);

        var online_buf: [max_ranges]CpuRange = undefined;
        const online_count = self.readCpuRangeSet(self.sources.cpu_online, &online_buf) orelse
            return countCpuRanges(inherited_buf[0..inherited_count]);
        const intersected = intersectCpuRanges(inherited_buf[0..inherited_count], online_buf[0..online_count]);
        if (intersected != 0) return intersected;
        // Either the sets do not overlap or the online set is empty: the
        // runnable set is empty, so the capacity stays unknown.
        return 0;
    }

    fn readCpuRangeSet(self: *Collector, path: []const u8, out: *[max_ranges]CpuRange) ?usize {
        switch (readBounded(path, &self.scratch.list)) {
            .ok => |bytes| return parseCpuRanges(bytes, out) catch null,
            else => return null,
        }
    }

    fn onlineCpus(self: *Collector, source: *[]const u8) u32 {
        switch (readBounded(self.sources.cpu_online, &self.scratch.small)) {
            .ok => |bytes| {
                const count = parseCpuSet(bytes) catch return std.math.maxInt(u32);
                source.* = "sysfs online CPUs";
                return count;
            },
            else => return std.math.maxInt(u32),
        }
    }

    fn sampleRam(self: *Collector, options: common.SnapshotOptions) RamResult {
        var result = RamResult{};
        const target = &self.targets[Controller.memory.index()];

        var path_buf: [max_path]u8 = undefined;
        var limit_unknown = false;
        var limit: ?u64 = null;
        var hierarchy_disabled = false;

        if (target.version == .v2) {
            const current_path = joinPath(&path_buf, target.slice(), "/memory.current") orelse {
                self.locate_failed = true;
                return result;
            };
            switch (readBounded(current_path, &self.scratch.small)) {
                .ok => |bytes| {
                    const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
                    result.charged = std.fmt.parseInt(u64, trimmed, 10) catch null;
                },
                .missing => {
                    self.locate_failed = true;
                    return result;
                },
                .failed => return result,
            }
            result.total_source = if (result.charged != null)
                cgroupLabel("v2", "memory.max")
            else
                "memory.current unreadable";

            var it = AncestorIter{ .dir = target.slice(), .base_len = target.base_len };
            while (it.next()) |dir| {
                const path = joinPath(&path_buf, dir, "/memory.max") orelse break;
                switch (readBounded(path, &self.scratch.small)) {
                    .ok => |bytes| {
                        const value = parseMemoryLimit(bytes, .v2) catch {
                            limit_unknown = true;
                            break;
                        };
                        if (value) |bytes_limit| limit = if (limit) |current| @min(current, bytes_limit) else bytes_limit;
                    },
                    .missing => {},
                    .failed => {
                        limit_unknown = true;
                        break;
                    },
                }
            }

            if (joinPath(&path_buf, target.slice(), "/memory.stat")) |stat_path| {
                switch (readBounded(stat_path, &self.scratch.list)) {
                    .ok => |bytes| {
                        result.inactive = statValue(bytes, "inactive_file");
                        result.cache_stats = result.inactive != null;
                        if (!result.cache_stats) self.diag.notes.add("memory.stat has no inactive_file entry");
                    },
                    .missing => self.diag.notes.add("memory.stat is missing"),
                    .failed => self.diag.notes.add("memory.stat is unreadable or truncated"),
                }
            }
        } else if (target.version == .v1) {
            const usage_path = joinPath(&path_buf, target.slice(), "/memory.usage_in_bytes") orelse {
                self.locate_failed = true;
                return result;
            };
            switch (readBounded(usage_path, &self.scratch.small)) {
                .ok => |bytes| {
                    const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
                    result.charged = std.fmt.parseInt(u64, trimmed, 10) catch null;
                },
                .missing => {
                    self.locate_failed = true;
                    return result;
                },
                .failed => return result,
            }
            result.total_source = cgroupLabel("v1", "memory.limit_in_bytes");

            const hierarchy_path = joinPath(&path_buf, target.slice(), "/memory.use_hierarchy") orelse "";
            if (hierarchy_path.len != 0) {
                switch (readBounded(hierarchy_path, &self.scratch.small)) {
                    .ok => |bytes| {
                        const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
                        if (std.mem.eql(u8, trimmed, "0")) hierarchy_disabled = true;
                    },
                    else => {},
                }
            }

            var it = AncestorIter{ .dir = target.slice(), .base_len = target.base_len };
            while (it.next()) |dir| {
                const path = joinPath(&path_buf, dir, "/memory.limit_in_bytes") orelse break;
                switch (readBounded(path, &self.scratch.small)) {
                    .ok => |bytes| {
                        const value = parseMemoryLimit(bytes, .v1) catch {
                            limit_unknown = true;
                            break;
                        };
                        if (value) |bytes_limit| limit = if (limit) |current| @min(current, bytes_limit) else bytes_limit;
                    },
                    .missing => {},
                    .failed => {
                        limit_unknown = true;
                        break;
                    },
                }
            }

            if (joinPath(&path_buf, target.slice(), "/memory.stat")) |stat_path| {
                switch (readBounded(stat_path, &self.scratch.list)) {
                    .ok => |bytes| {
                        result.inactive = statValue(bytes, "total_inactive_file");
                        result.cache_stats = result.inactive != null;
                        if (statValue(bytes, "hierarchical_memory_limit")) |value| {
                            if (!isUnlimitedMemoryV1(value)) limit = if (limit) |current| @min(current, value) else value;
                        }
                    },
                    .missing => self.diag.notes.add("memory.stat is missing"),
                    .failed => self.diag.notes.add("memory.stat is unreadable or truncated"),
                }
            }
        } else {
            return result;
        }

        if (hierarchy_disabled) {
            self.diag.notes.add("memory.use_hierarchy is 0; container-wide RAM accounting is not guaranteed");
            return .{ .total_source = result.total_source };
        }

        // A level that cannot be read is not an unlimited level: without a
        // trusted ceiling the reported total stays unknown instead of falling
        // back to a host-sized value.
        const effective_limit: ?u64 = if (limit_unknown) null else limit;

        var meminfo_buf: [list_bytes]u8 = undefined;
        var proc_total: ?u64 = null;
        var inform_path_buf: [max_path]u8 = undefined;
        if (joinPath(&inform_path_buf, self.sources.proc_root, "/meminfo")) |path| {
            switch (readBounded(path, &meminfo_buf)) {
                .ok => |bytes| proc_total = memInfoValue(bytes, "MemTotal"),
                else => {},
            }
        }

        if (limit_unknown) {
            self.diag.notes.add("memory limit level is unreadable; total left unknown");
        }
        if (effective_limit) |bytes_limit| {
            result.total = if (proc_total) |phys| @min(bytes_limit, phys) else bytes_limit;
            result.total_known = true;
        } else if (!limit_unknown) {
            if (proc_total) |phys| {
                result.total = phys;
                result.total_known = true;
            }
        } else {
            result.total_source = "memory limit unreadable";
        }

        if (result.charged) |charged| {
            result.used = if (options.memory_include_cache)
                charged
            else if (result.inactive) |inactive|
                charged -| inactive
            else
                charged;
        }
        return result;
    }

    fn sampleSwap(self: *Collector) SwapResult {
        var result = SwapResult{};
        const target = &self.targets[Controller.memory.index()];
        if (target.version == .none) return result;

        var path_buf: [max_path]u8 = undefined;
        var proc_swap_total: ?u64 = null;
        var meminfo_buf: [list_bytes]u8 = undefined;
        var meminfo_path_buf: [max_path]u8 = undefined;
        if (joinPath(&meminfo_path_buf, self.sources.proc_root, "/meminfo")) |path| {
            switch (readBounded(path, &meminfo_buf)) {
                .ok => |bytes| proc_swap_total = memInfoValue(bytes, "SwapTotal"),
                else => {},
            }
        }

        if (target.version == .v2) {
            result.source = cgroupLabel("v2", "memory.swap.current");
            result.kind = .independent;
            const current_path = joinPath(&path_buf, target.slice(), "/memory.swap.current") orelse return result;
            switch (readBounded(current_path, &self.scratch.small)) {
                .ok => |bytes| {
                    const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
                    result.used = std.fmt.parseInt(u64, trimmed, 10) catch null;
                },
                .missing => result.used = 0,
                .failed => {},
            }

            var limit: ?u64 = null;
            var limit_unknown = false;
            var it = AncestorIter{ .dir = target.slice(), .base_len = target.base_len };
            while (it.next()) |dir| {
                const path = joinPath(&path_buf, dir, "/memory.swap.max") orelse break;
                switch (readBounded(path, &self.scratch.small)) {
                    .ok => |bytes| {
                        const value = parseMemoryLimit(bytes, .v2) catch {
                            limit_unknown = true;
                            break;
                        };
                        if (value) |bytes_limit| limit = if (limit) |current| @min(current, bytes_limit) else bytes_limit;
                    },
                    .missing => {},
                    .failed => {
                        limit_unknown = true;
                        break;
                    },
                }
            }

            if (limit) |bytes_limit| {
                result.total = if (proc_swap_total) |phys| @min(bytes_limit, phys) else bytes_limit;
                result.total_known = true;
            } else if (!limit_unknown) {
                if (proc_swap_total) |phys| {
                    result.total = phys;
                    result.total_known = true;
                }
            } else {
                self.diag.notes.add("memory.swap.max is unreadable; swap total left unknown");
            }
            if (result.used) |used| {
                if (proc_swap_total != null and proc_swap_total.? == 0 and used > 0) {
                    // Keep the cgroup-visible usage; never mask it with a zero
                    // host swap view.
                    if (limit == null) result.total_known = false;
                }
            }
            return result;
        }

        // cgroup v1 swap accounting.
        result.source = cgroupLabel("v1", "memory.stat total_swap");
        var hierarchy_disabled = false;
        const hierarchy_path = joinPath(&path_buf, target.slice(), "/memory.use_hierarchy") orelse "";
        if (hierarchy_path.len != 0) {
            switch (readBounded(hierarchy_path, &self.scratch.small)) {
                .ok => |bytes| {
                    if (std.mem.eql(u8, std.mem.trim(u8, bytes, " \t\r\n"), "0")) hierarchy_disabled = true;
                },
                else => {},
            }
        }
        if (hierarchy_disabled) {
            self.diag.notes.add("memory.use_hierarchy is 0; container-wide swap accounting is not guaranteed");
            return .{ .source = result.source };
        }

        var stat_available = false;
        if (joinPath(&path_buf, target.slice(), "/memory.stat")) |stat_path| {
            switch (readBounded(stat_path, &self.scratch.list)) {
                .ok => |bytes| {
                    stat_available = true;
                    result.used = statValue(bytes, "total_swap");
                    if (result.used == null) result.used = statValue(bytes, "swap");
                },
                else => {},
            }
        }
        if (result.used == null) {
            const memsw_usage_path = joinPath(&path_buf, target.slice(), "/memory.memsw.usage_in_bytes") orelse "";
            var memsw_used: ?u64 = null;
            if (memsw_usage_path.len != 0) {
                switch (readBounded(memsw_usage_path, &self.scratch.small)) {
                    .ok => |bytes| {
                        memsw_used = std.fmt.parseInt(u64, std.mem.trim(u8, bytes, " \t\r\n"), 10) catch null;
                    },
                    else => {},
                }
            }
            const usage_path = joinPath(&path_buf, target.slice(), "/memory.usage_in_bytes") orelse "";
            var mem_used: ?u64 = null;
            if (usage_path.len != 0) {
                switch (readBounded(usage_path, &self.scratch.small)) {
                    .ok => |bytes| {
                        mem_used = std.fmt.parseInt(u64, std.mem.trim(u8, bytes, " \t\r\n"), 10) catch null;
                    },
                    else => {},
                }
            }
            if (memsw_used) |total_used| {
                result.used = if (mem_used) |memory_used| total_used -| memory_used else total_used;
                result.source = cgroupLabel("v1", "memory.memsw.usage_in_bytes");
            }
        }
        if (result.used == null and proc_swap_total != null and proc_swap_total.? == 0) {
            result.used = 0;
        }

        var memsw_limit: ?u64 = null;
        var memsw_unknown = false;
        if (joinPath(&path_buf, target.slice(), "/memory.stat")) |stat_path| {
            switch (readBounded(stat_path, &self.scratch.list)) {
                .ok => |bytes| if (statValue(bytes, "hierarchical_memsw_limit")) |value| {
                    if (!isUnlimitedMemoryV1(value)) memsw_limit = value;
                },
                else => {},
            }
        }
        var it = AncestorIter{ .dir = target.slice(), .base_len = target.base_len };
        while (it.next()) |dir| {
            const path = joinPath(&path_buf, dir, "/memory.memsw.limit_in_bytes") orelse break;
            switch (readBounded(path, &self.scratch.small)) {
                .ok => |bytes| {
                    if (parseMemoryLimit(bytes, .v1) catch null) |value| {
                        memsw_limit = if (memsw_limit) |current| @min(current, value) else value;
                    }
                },
                .missing => {},
                .failed => {
                    memsw_unknown = true;
                    break;
                },
            }
        }

        if (memsw_limit) |bytes_limit| {
            result.kind = .shared_memsw_upper_bound;
            result.total = if (proc_swap_total) |phys| @min(bytes_limit, phys) else bytes_limit;
            result.total_known = true;
        } else if (!memsw_unknown) {
            if (proc_swap_total) |phys| {
                result.total = phys;
                result.total_known = true;
                if (phys == 0 and (result.used orelse 0) > 0) result.total_known = false;
            }
        } else {
            self.diag.notes.add("memory.memsw.limit_in_bytes is unreadable; swap total left unknown");
        }
        if (!stat_available and result.used != null) {
            self.diag.notes.add("memory.stat is unavailable; swap charged from memsw counters");
        }
        return result;
    }
};

fn coresForCapacity(capacity: f64) u32 {
    if (!(capacity > 0) or !std.math.isFinite(capacity)) return 0;
    const rounded = @ceil(capacity);
    if (rounded < 1) return 1;
    const max_cores: f64 = @floatFromInt(std.math.maxInt(u32));
    if (rounded >= max_cores) return std.math.maxInt(u32);
    return @intFromFloat(rounded);
}

fn cpuPercent(delta_counter: u64, unit_ns: u32, elapsed_ns: i128, capacity: f64) f64 {
    if (elapsed_ns <= 0 or !(capacity > 0) or !std.math.isFinite(capacity)) return cpu_report_floor;
    if (delta_counter == 0) return cpu_report_floor;
    const elapsed: f64 = @floatFromInt(elapsed_ns);
    const consumed: f64 = @as(f64, @floatFromInt(delta_counter)) * @as(f64, @floatFromInt(unit_ns));
    const value = consumed / (elapsed * capacity) * 100.0;
    if (!std.math.isFinite(value) or value <= cpu_report_floor) return cpu_report_floor;
    return value;
}

const AncestorIter = struct {
    dir: []const u8,
    base_len: usize,
    started: bool = false,

    fn next(self: *AncestorIter) ?[]const u8 {
        if (!self.started) {
            self.started = true;
            return self.dir;
        }
        if (self.dir.len <= self.base_len) return null;
        const index = std.mem.lastIndexOfScalar(u8, self.dir, '/') orelse return null;
        if (index <= self.base_len) {
            self.dir = self.dir[0 .. self.base_len];
            return self.dir;
        }
        self.dir = self.dir[0..index];
        return self.dir;
    }
};

fn isHostMode(options: common.SnapshotOptions) bool {
    if (std.mem.eql(u8, options.resource_mode, "host")) return true;
    if (std.mem.eql(u8, options.resource_mode, "container")) return false;
    return options.host_proc.len != 0;
}

fn hasContainerEnvironment(bytes: []const u8) bool {
    var it = std.mem.splitScalar(u8, bytes, 0);
    while (it.next()) |entry| {
        if (std.mem.startsWith(u8, entry, "container=")) {
            if (std.mem.trim(u8, entry["container=".len..], " \t\r\n").len != 0) return true;
        }
    }
    return false;
}

/// Static diagnostics label. The version tag and field are compile-time
/// known, so this never allocates and never contains a local path.
fn cgroupLabel(comptime version: []const u8, comptime field: []const u8) []const u8 {
    return "cgroup " ++ version ++ " " ++ field;
}
