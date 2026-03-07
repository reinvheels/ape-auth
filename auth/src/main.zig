const std = @import("std");
const net = std.net;
const Server = @import("Server.zig");

const port: u16 = 8080;

fn getDataDir(allocator: std.mem.Allocator) ![]const u8 {
    // 1. CLI arg
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name
    if (args.next()) |arg| {
        return try allocator.dupe(u8, arg);
    }

    // 2. Environment variable
    if (std.posix.getenv("APE_AUTH_DATA_DIR")) |env| {
        return try allocator.dupe(u8, env);
    }

    // 3. Default: ~/.ape-auth
    if (std.posix.getenv("HOME")) |home| {
        return try std.fmt.allocPrint(allocator, "{s}/.ape-auth", .{home});
    }

    return error.NoHomeDir;
}

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const data_dir = try getDataDir(allocator);
    defer allocator.free(data_dir);

    // Ensure data and keys directories exist
    std.fs.makeDirAbsolute(data_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const keys_dir = try std.fmt.allocPrint(allocator, "{s}/keys", .{data_dir});
    defer allocator.free(keys_dir);
    std.fs.makeDirAbsolute(keys_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    var server = Server.init(allocator, data_dir);

    const address = net.Address.parseIp("0.0.0.0", port) catch unreachable;
    var tcp = try address.listen(.{ .reuse_address = true });
    defer tcp.deinit();

    std.log.info("ape-auth listening on :{d} (data: {s})", .{ port, data_dir });

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
    _ = @import("crypto.zig");
    _ = Server;
    _ = @import("auth.zig");
    _ = @import("schema.zig");
    _ = @import("persist.zig");
}

test "smoke" {
    try std.testing.expect(true);
}
