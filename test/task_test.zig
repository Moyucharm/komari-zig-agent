const std = @import("std");
const builtin = @import("builtin");
const config = @import("config");
const local_http = @import("local_http.zig");
const task = @import("protocol_task");

test "empty exec task matches go result text" {
    const result = try task.runCommandDetailed(std.testing.allocator, "");
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("No command provided", result.output);
    try std.testing.expectEqual(@as(i32, 0), result.exit_code);
}

test "crlf output is normalized to lf" {
    const normalized = try task.normalizeCommandOutput(std.testing.allocator, "a\r\nb\r\n");
    defer std.testing.allocator.free(normalized);
    try std.testing.expectEqualStrings("a\nb\n", normalized);
}

test "disabled remote control result does not execute command" {
    const result = try task.disabledRemoteControlResult(std.testing.allocator);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("Remote control is disabled.", result.output);
    try std.testing.expectEqual(@as(i32, -1), result.exit_code);
}

test "command failure result is uploadable" {
    const result = try task.commandFailureResult(std.testing.allocator, error.OutOfMemory);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("Command failed: OutOfMemory", result.output);
    try std.testing.expectEqual(@as(i32, -1), result.exit_code);
}

test "runCommand returns command stdout" {
    const output = try task.runCommandWithRunner(std.testing.allocator, "stdout", stdoutRunner);
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualStrings("hello", output);
}

test "runCommandDetailed executes real shell command on posix" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const result = try task.runCommandDetailed(std.testing.allocator, "printf e2e-exec-ok");
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("e2e-exec-ok", result.output);
    try std.testing.expectEqual(@as(i32, 0), result.exit_code);
}

test "runCommandDetailed executes real shell command on windows" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    const result = try task.runCommandDetailed(std.testing.allocator, "[Console]::Out.Write('e2e-exec-ok')");
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("e2e-exec-ok", result.output);
    try std.testing.expectEqual(@as(i32, 0), result.exit_code);
}

test "runCommandDetailed merges stderr and exit code" {
    const result = try task.runCommandDetailedWithRunner(std.testing.allocator, "stderr", stdoutStderrRunner);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("out\nerr", result.output);
    try std.testing.expectEqual(@as(i32, 7), result.exit_code);
}

test "runCommandDetailed maps signaled shell exit" {
    const result = try task.runCommandDetailedWithRunner(std.testing.allocator, "signal", signalRunner);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(i32, 143), result.exit_code);
}

test "runCommandDetailed reports oversized output" {
    const result = try task.runCommandDetailedWithRunner(std.testing.allocator, "long", streamTooLongRunner);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("Command output exceeded 4194304 bytes", result.output);
    try std.testing.expectEqual(@as(i32, -1), result.exit_code);
}

test "runCommandDetailed returns runner errors" {
    try std.testing.expectError(
        error.UnexpectedTestError,
        task.runCommandDetailedWithRunner(std.testing.allocator, "err", errorRunner),
    );
}

test "runCommandDetailed maps unknown term to failure" {
    const result = try task.runCommandDetailedWithRunner(std.testing.allocator, "unknown", unknownRunner);
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(i32, -1), result.exit_code);
}

test "utc timestamp formats as unsigned rfc3339" {
    const text = try task.utcFromTimestamp(std.testing.allocator, 0);
    defer std.testing.allocator.free(text);
    try std.testing.expectEqualStrings("1970-01-01T00:00:00Z", text);
}

test "uploadExecResult posts agent.taskResult over v2 rpc for v2 sessions" {
    const response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 47\r\nConnection: close\r\n\r\n{\"jsonrpc\":\"2.0\",\"result\":{\"status\":\"success\"}}";
    const responses = [_][]const u8{response};
    var server = try local_http.Server.start(std.testing.allocator, &responses);
    errdefer server.join() catch unreachable;

    const endpoint = try server.url(std.testing.allocator, "");
    defer std.testing.allocator.free(endpoint);
    try task.uploadExecResult(std.testing.allocator, uploadTestConfig(endpoint), 2, "task-1", "ignored");

    var completed = try server.finish();
    defer completed.deinit();

    try std.testing.expectEqual(@as(usize, 1), completed.requests.len);
    const request = completed.requests[0];
    try std.testing.expectEqualStrings("POST /api/clients/v2/rpc?token=tok HTTP/1.1", request.requestLine());
    try std.testing.expectEqualStrings("application/json", request.header("Content-Type").?);
    try std.testing.expect(request.header("Content-Encoding") == null);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, request.body, .{});
    defer parsed.deinit();
    const root = try expectObject(parsed.value);
    try expectStringField(root, "jsonrpc", "2.0");
    try expectStringField(root, "method", "agent.taskResult");
    try std.testing.expect(root.get("id") == null);
    try expectTaskResultFields(try expectObjectValue(root, "params"));
}

test "uploadExecResult falls back to legacy endpoint when v2 rpc rejects agent.taskResult" {
    const rejected = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const ok = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const responses = [_][]const u8{ rejected, ok };
    var server = try local_http.Server.start(std.testing.allocator, &responses);
    errdefer server.join() catch unreachable;

    const endpoint = try server.url(std.testing.allocator, "");
    defer std.testing.allocator.free(endpoint);
    try task.uploadExecResult(std.testing.allocator, uploadTestConfig(endpoint), 2, "task-1", "ignored");

    var completed = try server.finish();
    defer completed.deinit();

    try std.testing.expectEqual(@as(usize, 2), completed.requests.len);
    try std.testing.expectEqualStrings("POST /api/clients/v2/rpc?token=tok HTTP/1.1", completed.requests[0].requestLine());
    try expectLegacyTaskResultRequest(completed.requests[1]);
}

test "uploadExecResult keeps legacy task result upload for v1 sessions" {
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const responses = [_][]const u8{response};
    var server = try local_http.Server.start(std.testing.allocator, &responses);
    errdefer server.join() catch unreachable;

    const endpoint = try server.url(std.testing.allocator, "");
    defer std.testing.allocator.free(endpoint);
    try task.uploadExecResult(std.testing.allocator, uploadTestConfig(endpoint), 1, "task-1", "ignored");

    var completed = try server.finish();
    defer completed.deinit();

    try std.testing.expectEqual(@as(usize, 1), completed.requests.len);
    try expectLegacyTaskResultRequest(completed.requests[0]);
}

fn uploadTestConfig(endpoint: []const u8) config.Config {
    return .{
        .endpoint = endpoint,
        .token = "tok",
        .disable_compression = true,
        .disable_web_ssh = true,
        .max_retries = 0,
    };
}

fn expectLegacyTaskResultRequest(request: local_http.RecordedRequest) !void {
    try std.testing.expectEqualStrings("POST /api/clients/task/result?token=tok HTTP/1.1", request.requestLine());
    try std.testing.expectEqualStrings("komari-zig-agent", request.header("User-Agent").?);
    try std.testing.expectEqualStrings("application/json", request.header("Content-Type").?);
    try std.testing.expect(request.header("Content-Encoding") == null);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, request.body, .{});
    defer parsed.deinit();
    try expectTaskResultFields(try expectObject(parsed.value));
}

fn expectTaskResultFields(object: std.json.ObjectMap) !void {
    try expectStringField(object, "task_id", "task-1");
    try expectStringField(object, "result", "Remote control is disabled.");
    try expectIntField(object, "exit_code", -1);
    const finished_at = object.get("finished_at") orelse return error.TestUnexpectedResult;
    if (finished_at != .string) return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.endsWith(u8, finished_at.string, "Z"));
}

fn expectObject(value: std.json.Value) !std.json.ObjectMap {
    if (value != .object) return error.TestUnexpectedResult;
    return value.object;
}

fn expectObjectValue(object: std.json.ObjectMap, key: []const u8) !std.json.ObjectMap {
    const value = object.get(key) orelse return error.TestUnexpectedResult;
    return expectObject(value);
}

fn expectStringField(object: std.json.ObjectMap, key: []const u8, expected: []const u8) !void {
    const value = object.get(key) orelse return error.TestUnexpectedResult;
    if (value != .string) return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(expected, value.string);
}

fn expectIntField(object: std.json.ObjectMap, key: []const u8, expected: i64) !void {
    const value = object.get(key) orelse return error.TestUnexpectedResult;
    if (value != .integer) return error.TestUnexpectedResult;
    try std.testing.expectEqual(expected, value.integer);
}

fn stdoutRunner(allocator: std.mem.Allocator, env: *std.process.Environ.Map, command: []const u8) !std.process.RunResult {
    _ = env;
    try std.testing.expectEqualStrings("stdout", command);
    return .{
        .stdout = try allocator.dupe(u8, "hello"),
        .stderr = try allocator.dupe(u8, ""),
        .term = .{ .exited = 0 },
    };
}

fn stdoutStderrRunner(allocator: std.mem.Allocator, env: *std.process.Environ.Map, command: []const u8) !std.process.RunResult {
    _ = env;
    try std.testing.expectEqualStrings("stderr", command);
    return .{
        .stdout = try allocator.dupe(u8, "out"),
        .stderr = try allocator.dupe(u8, "err"),
        .term = .{ .exited = 7 },
    };
}

fn signalRunner(allocator: std.mem.Allocator, env: *std.process.Environ.Map, command: []const u8) !std.process.RunResult {
    _ = env;
    _ = command;
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try allocator.dupe(u8, ""),
        .term = .{ .signal = @enumFromInt(15) },
    };
}

fn streamTooLongRunner(allocator: std.mem.Allocator, env: *std.process.Environ.Map, command: []const u8) !std.process.RunResult {
    _ = allocator;
    _ = env;
    _ = command;
    return error.StreamTooLong;
}

fn errorRunner(allocator: std.mem.Allocator, env: *std.process.Environ.Map, command: []const u8) !std.process.RunResult {
    _ = allocator;
    _ = env;
    _ = command;
    return error.UnexpectedTestError;
}

fn unknownRunner(allocator: std.mem.Allocator, env: *std.process.Environ.Map, command: []const u8) !std.process.RunResult {
    _ = env;
    _ = command;
    return .{
        .stdout = try allocator.dupe(u8, ""),
        .stderr = try allocator.dupe(u8, ""),
        .term = .{ .unknown = 1 },
    };
}
