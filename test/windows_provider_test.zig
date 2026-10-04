const builtin = @import("builtin");
const std = @import("std");

test "windows provider basic info reports windows data" {
    if (builtin.os.tag != .windows) return;
    const provider = @import("platform_provider");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const info = try provider.basicInfo(arena.allocator(), .{});
    try std.testing.expect(info.mem_total > 0);
    try std.testing.expect(info.disk_total > 0);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(info.os_name, "windows") != null);
    try std.testing.expect(!std.mem.eql(u8, info.os_name, "Linux"));
    try std.testing.expect(info.gpu_name.len > 0);
    try std.testing.expect(info.virtualization.len > 0);
    try std.testing.expect(info.ipv4.len > 0 or info.ipv6.len > 0);
}

test "windows provider snapshot does not use linux collector" {
    if (builtin.os.tag != .windows) return;
    const provider = @import("platform_provider");

    const snap = try provider.snapshot();
    try std.testing.expect(snap.ram.total > 0);
    try std.testing.expect(snap.disk.total > 0);
    try std.testing.expect(snap.uptime > 0);
    try std.testing.expect(snap.connections.tcp + snap.connections.udp >= 0);
}

test "windows provider exposes filtered interfaces" {
    if (builtin.os.tag != .windows) return;
    const provider = @import("platform_provider");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const nics = try provider.interfaceList(arena.allocator(), "", "");
    try std.testing.expect(nics.len > 0);
}
