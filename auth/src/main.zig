const std = @import("std");
const net = std.net;
const Store = @import("Store.zig");
const Server = @import("Server.zig");
const backup = @import("backup.zig");

const port: u16 = 8080;
const backup_dir = "/tmp/ape-auth";

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize store
    var store = Store.init(allocator);
    defer store.deinit();

    // Ensure backup directory exists
    std.fs.makeDirAbsolute(backup_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Rehydrate from backup
    backup.rehydrate(allocator, &store, backup_dir) catch |err| {
        std.log.err("rehydration failed: {}, starting fresh", .{err});
    };

    // Start backup thread
    _ = try backup.startBackupThread(allocator, &store, backup_dir);

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
    _ = @import("backup.zig");
}

test "smoke" {
    try std.testing.expect(true);
}
