const std = @import("std");
const net = std.net;
const Store = @import("Store.zig");
const Server = @import("Server.zig");
const persist = @import("persist.zig");

const port: u16 = 8080;
const data_dir = "/tmp/ape-auth";

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize store
    var store = Store.init(allocator);
    defer store.deinit();
    store.base_dir = data_dir;

    // Ensure data directory exists
    std.fs.makeDirAbsolute(data_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Load persisted accounts
    persist.loadAll(allocator, &store, data_dir) catch |err| {
        std.log.err("failed to load persisted data: {}, starting fresh", .{err});
    };

    // Start TCP server
    var server = Server.init(allocator, &store);

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
    _ = Store;
    _ = Server;
    _ = @import("auth.zig");
    _ = @import("json.zig");
    _ = @import("persist.zig");
}

test "smoke" {
    try std.testing.expect(true);
}
