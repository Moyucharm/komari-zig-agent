const std = @import("std");
const version = @import("version");

test "default version is compatible" {
    try std.testing.expectEqualStrings("0.0.1", version.current);
}
