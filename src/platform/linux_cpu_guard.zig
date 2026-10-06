//! Plausibility guard for the whole-machine `/proc/stat` CPU counters.
//!
//! On a real Linux kernel the aggregate `cpu` line of `/proc/stat` advances by
//! `online CPUs x USER_HZ` ticks per second of wall time. Some virtualised
//! kernels (for example Android "cloud phone" instances sharing one host)
//! present a per-instance `/proc/stat` that does not: its ticks grow far slower
//! than wall time, idle can run backwards and per-CPU lines trade idle between
//! each other. Usage derived from such counters swings between 0 and 100%
//! regardless of the real load.
//!
//! The guard checks every reporting window against the monotonic clock. Only
//! after several consecutive implausible windows does it switch to summing the
//! CPU time of the visible processes from `/proc/<pid>/stat`, and it switches
//! back after several plausible ones. A kernel with sane counters never leaves
//! the `/proc/stat` path, so ordinary hosts keep their existing numbers.
const std = @import("std");
const compat = @import("compat");

/// Ticks per CPU-second in `/proc/stat` and `/proc/<pid>/stat`. `USER_HZ` is
/// fixed at 100 by the Linux ABI on every architecture this agent ships for.
pub const user_hz: u64 = 100;
/// Consecutive windows needed before switching source in either direction, so
/// one odd window (VM pause, CPU hotplug) never flips a healthy host.
pub const switch_after: u8 = 3;
/// Windows shorter than this many expected ticks are too coarse to judge.
const min_expected_ticks: f64 = 50;
/// Accepted ratio of observed to expected ticks.
const min_ratio: f64 = 0.5;
const max_ratio: f64 = 1.5;
const report_floor: f64 = 0.001;
/// `/proc/<pid>/stat` stays well below this; a full buffer is ignored.
const pid_stat_bytes = 2048;

/// One `/proc/stat` delta window used for the plausibility check.
pub const Window = struct {
    /// Growth of user..steal ticks (guest time excluded: it is already in user).
    accounted_delta: u64,
    /// Online CPUs listed as `cpuN` lines in `/proc/stat`; 0 means unknown.
    cpu_lines: u32,
    elapsed_ns: i128,
};

/// True when the window's tick growth matches wall time and the CPU count, or
/// when the window cannot be judged (unknown CPU count, too short).
pub fn plausible(window: Window) bool {
    if (window.cpu_lines == 0 or window.elapsed_ns <= 0) return true;
    const elapsed_s = @as(f64, @floatFromInt(window.elapsed_ns)) / std.time.ns_per_s;
    const expected = elapsed_s * @as(f64, @floatFromInt(window.cpu_lines)) * @as(f64, @floatFromInt(user_hz));
    if (expected < min_expected_ticks) return true;
    const ratio = @as(f64, @floatFromInt(window.accounted_delta)) / expected;
    return ratio >= min_ratio and ratio <= max_ratio;
}

/// Accumulated CPU ticks and start time of one process.
pub const ProcTimes = struct {
    ticks: u64,
    start: u64,
};

/// Parse utime+stime and starttime from a `/proc/<pid>/stat` line. The command
/// name may contain spaces and parentheses, so fields are counted after the
/// last `)`.
pub fn parsePidStat(bytes: []const u8) ?ProcTimes {
    const close = std.mem.lastIndexOfScalar(u8, bytes, ')') orelse return null;
    var fields = std.mem.tokenizeAny(u8, bytes[close + 1 ..], " \t\n");
    // Field 3 (state) is index 0; utime=14, stime=15, starttime=22.
    var index: usize = 0;
    var utime: ?u64 = null;
    var stime: ?u64 = null;
    while (fields.next()) |field| : (index += 1) {
        switch (index) {
            11 => utime = std.fmt.parseInt(u64, field, 10) catch return null,
            12 => stime = std.fmt.parseInt(u64, field, 10) catch return null,
            19 => return .{
                .ticks = (utime orelse return null) +| (stime orelse return null),
                .start = std.fmt.parseInt(u64, field, 10) catch return null,
            },
            else => {},
        }
    }
    return null;
}

/// Convert process ticks consumed in a window to a percentage of `cores`.
pub fn processUsagePercent(delta_ticks: u64, elapsed_ns: i128, cores: u32) f64 {
    if (elapsed_ns <= 0 or cores == 0) return report_floor;
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    const capacity = elapsed_s * @as(f64, @floatFromInt(cores)) * @as(f64, @floatFromInt(user_hz));
    const value = @as(f64, @floatFromInt(delta_ticks)) / capacity * 100.0;
    if (!std.math.isFinite(value) or value <= report_floor) return report_floor;
    return @min(value, 100.0);
}

/// Sums per-process CPU time between scans of a proc root.
pub const ProcessSampler = struct {
    previous: std.AutoHashMapUnmanaged(u32, ProcTimes) = .empty,
    previous_ns: ?i128 = null,

    const allocator = std.heap.page_allocator;

    /// Drop the baseline and release its memory.
    pub fn reset(self: *ProcessSampler) void {
        self.previous.deinit(allocator);
        self.previous = .empty;
        self.previous_ns = null;
    }

    /// Scan `proc_root` and return the usage since the previous scan, or null
    /// when there is no baseline yet (or the scan failed).
    pub fn sample(self: *ProcessSampler, proc_root: []const u8, now_ns: i128, cores: u32) ?f64 {
        var current: std.AutoHashMapUnmanaged(u32, ProcTimes) = .empty;
        const delta = self.scan(proc_root, &current) catch {
            current.deinit(allocator);
            self.reset();
            return null;
        };
        const previous_ns = self.previous_ns;
        self.previous.deinit(allocator);
        self.previous = current;
        self.previous_ns = now_ns;
        const since = previous_ns orelse return null;
        return processUsagePercent(delta, now_ns - since, cores);
    }

    /// Fill `current` and return ticks consumed since the previous scan. A
    /// process absent from the baseline (or with a reused pid) started after
    /// it, so all of its ticks fall inside the window.
    fn scan(self: *ProcessSampler, proc_root: []const u8, current: *std.AutoHashMapUnmanaged(u32, ProcTimes)) !u64 {
        var dir = try compat.openDir(proc_root, .{ .iterate = true });
        defer dir.close(std.Options.debug_io);
        var delta: u64 = 0;
        var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        var stat_buf: [pid_stat_bytes]u8 = undefined;
        var it = dir.iterate();
        while (try it.next(std.Options.debug_io)) |entry| {
            if (entry.kind != .directory) continue;
            const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
            const path = std.fmt.bufPrint(&path_buf, "{s}/{s}/stat", .{ proc_root, entry.name }) catch continue;
            const bytes = readSmall(path, &stat_buf) orelse continue;
            const times = parsePidStat(bytes) orelse continue;
            try current.put(allocator, pid, times);
            if (self.previous.get(pid)) |before| {
                if (before.start == times.start) {
                    delta +|= times.ticks -| before.ticks;
                    continue;
                }
            }
            delta +|= times.ticks;
        }
        return delta;
    }
};

fn readSmall(path: []const u8, buf: []u8) ?[]const u8 {
    const file = compat.openFile(path, .{}) catch return null;
    defer file.close(std.Options.debug_io);
    const n = compat.readAll(file, buf) catch return null;
    if (n == buf.len) return null;
    return buf[0..n];
}

/// Hysteresis between the `/proc/stat` source and the per-process source.
pub const Monitor = struct {
    bad_streak: u8 = 0,
    good_streak: u8 = 0,
    use_processes: bool = false,
    sampler: ProcessSampler = .{},

    /// Forget all history, e.g. when the proc root changes.
    pub fn reset(self: *Monitor) void {
        self.sampler.reset();
        self.bad_streak = 0;
        self.good_streak = 0;
        self.use_processes = false;
    }

    /// Pick the usage to report for one window. `stat_usage` is the value
    /// derived from `/proc/stat`; it is returned unchanged unless the counters
    /// have been implausible for `switch_after` consecutive windows.
    pub fn resolve(self: *Monitor, stat_usage: f64, window: Window, proc_root: []const u8, now_ns: i128, cores: u32) f64 {
        if (plausible(window)) {
            self.bad_streak = 0;
            self.good_streak +|= 1;
            if (self.use_processes and self.good_streak >= switch_after) self.use_processes = false;
        } else {
            self.good_streak = 0;
            self.bad_streak +|= 1;
            if (!self.use_processes and self.bad_streak >= switch_after) self.use_processes = true;
        }
        // Keep a process baseline warm while the counters look suspect so the
        // first window after switching already has a value.
        if (!self.use_processes and self.bad_streak == 0) {
            self.sampler.reset();
            return stat_usage;
        }
        const process_usage = self.sampler.sample(proc_root, now_ns, cores);
        if (!self.use_processes) return stat_usage;
        return process_usage orelse report_floor;
    }
};
