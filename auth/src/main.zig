const std = @import("std");
const net = std.net;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const address = net.Address.parseIp("0.0.0.0", 8080) catch unreachable;
    var server = try address.listen(.{});
    defer server.deinit();

    std.log.info("ape-auth listening on :8080", .{});

    while (true) {
        const conn = try server.accept();
        _ = try std.Thread.spawn(.{ .allocator = allocator }, handleConnection, .{conn});
    }
}

fn handleConnection(conn: net.Server.Connection) void {
    defer conn.stream.close();
    // TODO: parse HTTP request, route to handlers
}

test "placeholder" {
    try std.testing.expect(true);
}
