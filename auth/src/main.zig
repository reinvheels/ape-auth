const std = @import("std");
const net = std.net;
const Server = @import("Server.zig");

const port: u16 = 8080;
const data_dir = "/tmp/ape-auth";

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Ensure data and keys directories exist
    std.fs.makeDirAbsolute(data_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    std.fs.makeDirAbsolute(data_dir ++ "/keys") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    var server = Server.init(allocator, data_dir);

    const address = net.Address.parseIp("0.0.0.0", port) catch unreachable;
    var tcp = try address.listen(.{ .reuse_address = true });
    defer tcp.deinit();

    std.log.info("ape-auth listening on :{d}", .{port});

    while (true) {
        const conn = try tcp.accept();
        _ = std.Thread.spawn(.{ .allocator = allocator }, Server.handleConnection, .{ &server, conn }) catch |err| {
            std.log.err("failed to spawn thread: {}", .{err});
            conn.stream.close();
            continue;
        };
    }
}

// Pull in tests from all modules
comptime {
    _ = @import("Store.zig");
    _ = Server;
    _ = @import("auth.zig");
    _ = @import("json.zig");
    _ = @import("persist.zig");
}

test "smoke" {
    try std.testing.expect(true);
}
