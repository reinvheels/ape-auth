const std = @import("std");
const net = std.net;
const Ed25519 = std.crypto.sign.Ed25519;
const Server = @import("Server.zig");

const default_port: u16 = 8080;
const default_issuer = "http://localhost:8080";

fn getDataDir(allocator: std.mem.Allocator, args: *std.process.ArgIterator) ![]const u8 {
    if (args.next()) |arg| {
        return try allocator.dupe(u8, arg);
    }
    if (std.posix.getenv("APE_AUTH_DATA_DIR")) |env| {
        return try allocator.dupe(u8, env);
    }
    if (std.posix.getenv("HOME")) |home| {
        return try std.fmt.allocPrint(allocator, "{s}/.ape-auth", .{home});
    }
    return error.NoHomeDir;
}

fn getIssuer(allocator: std.mem.Allocator) ![]const u8 {
    if (std.posix.getenv("APE_AUTH_ISSUER")) |env| {
        return try allocator.dupe(u8, env);
    }
    return try allocator.dupe(u8, default_issuer);
}

fn getPort(args: *std.process.ArgIterator) !u16 {
    if (args.next()) |arg| {
        return std.fmt.parseInt(u16, arg, 10) catch return error.InvalidPort;
    }
    if (std.posix.getenv("APE_AUTH_PORT")) |env| {
        return std.fmt.parseInt(u16, env, 10) catch return error.InvalidPort;
    }
    return default_port;
}

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name

    const data_dir = try getDataDir(allocator, &args);
    defer allocator.free(data_dir);

    const port = try getPort(&args);

    const issuer = try getIssuer(allocator);
    defer allocator.free(issuer);

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

    // Load or generate Ed25519 signing keypair
    const secret_path = try std.fmt.allocPrint(allocator, "{s}/server.key", .{data_dir});
    defer allocator.free(secret_path);

    var key_pair: Ed25519.KeyPair = undefined;
    if (std.fs.openFileAbsolute(secret_path, .{})) |file| {
        defer file.close();
        var sk_bytes: [64]u8 = undefined;
        const n = try file.readAll(&sk_bytes);
        if (n != 64) return error.InvalidServerKey;
        const sk = try Ed25519.SecretKey.fromBytes(sk_bytes);
        key_pair = try Ed25519.KeyPair.fromSecretKey(sk);
    } else |_| {
        key_pair = Ed25519.KeyPair.generate();
        const file = try std.fs.createFileAbsolute(secret_path, .{});
        try file.writeAll(&key_pair.secret_key.toBytes());
        file.close();
        std.log.info("generated new signing keypair", .{});
    }

    var server = Server.init(allocator, data_dir, key_pair, issuer);

    const address = net.Address.parseIp("0.0.0.0", port) catch unreachable;
    var tcp = try address.listen(.{ .reuse_address = true });
    defer tcp.deinit();

    std.log.info("ape-auth listening on :{d} (data: {s}, issuer: {s})", .{ port, data_dir, issuer });

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
