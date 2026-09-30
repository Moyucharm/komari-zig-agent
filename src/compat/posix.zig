const std = @import("std");
const builtin = @import("builtin");

/// Low-level POSIX wrappers kept narrow for Zig 0.16 cross-target support.
/// 解码 `std.os.linux.*` 裸系统调用的返回值，得到真实的 errno。
///
/// **绝不要用 `std.posix.errno()` 去解读 `std.os.linux.*` 的返回值。**
///
/// 链接 libc 时（musl 与 glibc，也就是全部 11 个 Linux 构建目标），
/// `std.posix.errno` 绑定到 `std/c.zig` 的这个实现：
///
///     pub fn errno(rc: anytype) E {
///         return if (rc == -1) @enumFromInt(_errno().*) else .SUCCESS;
///     }
///
/// 而 `std.os.linux.*` 的返回类型是 `usize`。Zig **不允许**把 comptime 整数字面量
/// `-1` 隐式转换成 `usize`（`@as(usize, -1)` 是编译错误），所以这里的
/// `rc == -1` 对任何 `usize` 取值都**恒为 false**，`_errno()` 那个分支永远走不到。
/// 结果：`std.posix.errno` 对裸系统调用的返回值**一律返回 `.SUCCESS`**，
/// 成功失败不分。失败之后 `@intCast(rc)` 又会把 `0xFFFF...FF` 截断成 `-1`，
/// 调用方拿着一份「成功但 fd = -1」的结果继续跑。
///
/// `std.os.linux.errno` 才是对的：它先 `@bitCast` 成 `isize` 再比较。
///
/// 真实事故：容器内没有 `CAP_NET_RAW` 时，`socket(SOCK_RAW, IPPROTO_ICMP)` 返回
/// EPERM 却被判成成功且 `fd = -1`，于是 `ping.zig` 里 ICMP 的 raw→datagram
/// 自动降级永不触发，每次采样都是 -1；面板前端把负值映射成 `null`，
/// 延迟监测图表全程空白。同一类错误还会让 `statfs` 失败被当成成功，
/// 把未初始化的栈内存当磁盘数据上报。
///
/// 反之，走 `std.c.*` 的调用返回的是有符号类型，`rc == -1` 成立，
/// 继续用 `std.posix.errno` 即可。
pub fn rawErrno(rc: usize) std.posix.E {
    return std.os.linux.errno(rc);
}

pub fn closeFd(fd: std.posix.fd_t) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.close(fd);
    } else {
        _ = std.c.close(fd);
    }
}

pub fn pipe() ![2]std.posix.fd_t {
    var fds: [2]i32 = undefined;
    if (builtin.os.tag == .linux) {
        const rc = std.os.linux.pipe(&fds);
        return switch (rawErrno(rc)) {
            .SUCCESS => .{ fds[0], fds[1] },
            .MFILE => error.ProcessFdQuotaExceeded,
            .NFILE => error.SystemFdQuotaExceeded,
            else => |err| std.posix.unexpectedErrno(err),
        };
    }
    const rc = std.c.pipe(&fds);
    return switch (std.posix.errno(rc)) {
        .SUCCESS => .{ fds[0], fds[1] },
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        else => |err| std.posix.unexpectedErrno(err),
    };
}

pub fn socket(domain: std.posix.sa_family_t, socket_type: u32, protocol: u32) !std.posix.fd_t {
    if (builtin.os.tag == .linux) {
        const rc = std.os.linux.socket(@intCast(domain), socket_type, protocol);
        return switch (rawErrno(rc)) {
            .SUCCESS => @intCast(rc),
            .ACCES, .PERM => error.AccessDenied,
            else => |err| std.posix.unexpectedErrno(err),
        };
    }
    const rc = std.c.socket(@intCast(domain), socket_type, protocol);
    return switch (std.posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .ACCES, .PERM => error.AccessDenied,
        else => |err| std.posix.unexpectedErrno(err),
    };
}

pub fn sendTo(fd: std.posix.fd_t, bytes: []const u8, addr: *const std.posix.sockaddr, len: std.posix.socklen_t) !usize {
    if (builtin.os.tag == .linux) {
        const rc = std.os.linux.sendto(fd, bytes.ptr, bytes.len, 0, addr, len);
        return switch (rawErrno(rc)) {
            .SUCCESS => rc,
            else => |err| std.posix.unexpectedErrno(err),
        };
    }
    const rc = std.c.sendto(fd, bytes.ptr, bytes.len, 0, addr, len);
    return switch (std.posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => |err| std.posix.unexpectedErrno(err),
    };
}

pub fn recvFrom(fd: std.posix.fd_t, buf: []u8) !usize {
    if (builtin.os.tag == .linux) {
        const rc = std.os.linux.recvfrom(fd, buf.ptr, buf.len, 0, null, null);
        return switch (rawErrno(rc)) {
            .SUCCESS => rc,
            else => |err| std.posix.unexpectedErrno(err),
        };
    }
    const rc = std.c.recvfrom(fd, buf.ptr, buf.len, 0, null, null);
    return switch (std.posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => |err| std.posix.unexpectedErrno(err),
    };
}

pub fn fork() !std.posix.pid_t {
    if (builtin.os.tag == .linux) {
        const rc = std.os.linux.fork();
        return switch (rawErrno(rc)) {
            .SUCCESS => @intCast(rc),
            else => |err| std.posix.unexpectedErrno(err),
        };
    }
    const rc = std.c.fork();
    return switch (std.posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => |err| std.posix.unexpectedErrno(err),
    };
}

pub fn dup2(old_fd: std.posix.fd_t, new_fd: std.posix.fd_t) !void {
    if (builtin.os.tag == .linux) {
        const rc = std.os.linux.dup2(old_fd, new_fd);
        return switch (rawErrno(rc)) {
            .SUCCESS => {},
            else => |err| std.posix.unexpectedErrno(err),
        };
    }
    const rc = std.c.dup2(old_fd, new_fd);
    return switch (std.posix.errno(rc)) {
        .SUCCESS => {},
        else => |err| std.posix.unexpectedErrno(err),
    };
}

pub fn execveZ(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) !void {
    if (builtin.os.tag == .linux) {
        const rc = std.os.linux.execve(path, argv, envp);
        return switch (rawErrno(rc)) {
            .SUCCESS => unreachable,
            else => |err| std.posix.unexpectedErrno(err),
        };
    }
    const rc = std.c.execve(path, argv, envp);
    return switch (std.posix.errno(rc)) {
        .SUCCESS => unreachable,
        else => |err| std.posix.unexpectedErrno(err),
    };
}

pub const WaitPidResult = struct {
    pid: std.posix.pid_t,
    status: u32,
};

pub fn waitPid(pid: std.posix.pid_t, flags: u32) !WaitPidResult {
    if (builtin.os.tag == .linux) {
        var status: u32 = 0;
        const rc = std.os.linux.waitpid(pid, &status, flags);
        return switch (rawErrno(rc)) {
            .SUCCESS => .{ .pid = @intCast(rc), .status = status },
            else => |err| std.posix.unexpectedErrno(err),
        };
    }
    var status: c_int = 0;
    const rc = std.c.waitpid(pid, &status, @intCast(flags));
    return switch (std.posix.errno(rc)) {
        .SUCCESS => .{ .pid = @intCast(rc), .status = @intCast(status) },
        else => |err| std.posix.unexpectedErrno(err),
    };
}

pub fn setsid() !std.posix.pid_t {
    if (builtin.os.tag == .linux) {
        const rc = std.os.linux.setsid();
        return switch (rawErrno(rc)) {
            .SUCCESS => @intCast(rc),
            else => |err| std.posix.unexpectedErrno(err),
        };
    }
    const rc = std.c.setsid();
    return switch (std.posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => |err| std.posix.unexpectedErrno(err),
    };
}
