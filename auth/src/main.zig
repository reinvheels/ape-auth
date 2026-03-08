const std = @import("std");
const net = Io.net;
const Ed25519 = std.crypto.sign.Ed25519;
const Server = @import("Server.zig");
const Io = std.Io;

const default_port: u16 = 8080;
const default_issuer = "http://localhost:8080";

fn getenv(environ_map: *std.process.Environ.Map, key: []const u8) ?[]const u8 {
    return environ_map.get(key);
}

fn getDataDir(allocator: std.mem.Allocator, args: *std.process.Args.Iterator, environ_map: *std.process.Environ.Map) ![]const u8 {
    if (args.next()) |arg| {
        return try allocator.dupe(u8, arg);
    }
    if (getenv(environ_map, "APE_AUTH_DATA_DIR")) |env| {
        return try allocator.dupe(u8, env);
    }
    if (getenv(environ_map, "HOME")) |home| {
        return try std.fmt.allocPrint(allocator, "{s}/.ape-auth", .{home});
    }
    return error.NoHomeDir;
}

fn getIssuer(allocator: std.mem.Allocator, environ_map: *std.process.Environ.Map) ![]const u8 {
    if (getenv(environ_map, "APE_AUTH_ISSUER")) |env| {
        return try allocator.dupe(u8, env);
    }
    return try allocator.dupe(u8, default_issuer);
}

fn getPort(args: *std.process.Args.Iterator, environ_map: *std.process.Environ.Map) !u16 {
    if (args.next()) |arg| {
        return std.fmt.parseInt(u16, arg, 10) catch return error.InvalidPort;
    }
    if (getenv(environ_map, "APE_AUTH_PORT")) |env| {
        return std.fmt.parseInt(u16, env, 10) catch return error.InvalidPort;
    }
    return default_port;
}

fn ensureDir(io: Io, path: []const u8) !void {
    Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const environ_map = init.environ_map;
    const io = init.io;

    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next(); // skip program name

    const data_dir = try getDataDir(allocator, &args, environ_map);
    defer allocator.free(data_dir);

    const port = try getPort(&args, environ_map);

    const issuer = try getIssuer(allocator, environ_map);
    defer allocator.free(issuer);

    // Ensure data and keys directories exist
    try ensureDir(io, data_dir);
    const keys_dir = try std.fmt.allocPrint(allocator, "{s}/keys", .{data_dir});
    defer allocator.free(keys_dir);
    try ensureDir(io, keys_dir);

    // Load or generate Ed25519 signing keypair
    const secret_path = try std.fmt.allocPrint(allocator, "{s}/server.key", .{data_dir});
    defer allocator.free(secret_path);

    var key_pair: Ed25519.KeyPair = undefined;
    if (Io.Dir.openFileAbsolute(io, secret_path, .{})) |file| {
        defer file.close(io);
        var sk_bytes: [64]u8 = undefined;
        const n = try file.readPositionalAll(io, &sk_bytes, 0);
        if (n != 64) return error.InvalidServerKey;
        const sk = try Ed25519.SecretKey.fromBytes(sk_bytes);
        key_pair = try Ed25519.KeyPair.fromSecretKey(sk);
    } else |_| {
        key_pair = Ed25519.KeyPair.generate(io);
        const file = try Io.Dir.createFileAbsolute(io, secret_path, .{});
        try file.writePositionalAll(io, &key_pair.secret_key.toBytes(), 0);
        file.close(io);
        std.log.info("generated new signing keypair", .{});
    }

    var server = Server.init(allocator, io, data_dir, key_pair, issuer);

    const address = net.IpAddress.parseIp4("0.0.0.0", port) catch unreachable;
    var tcp = try address.listen(io, .{ .reuse_address = true });
    defer tcp.deinit(io);

    std.log.info("ape-auth listening on :{d} (data: {s}, issuer: {s})", .{ port, data_dir, issuer });

    while (true) {
        const stream = try tcp.accept(io);
        _ = std.Thread.spawn(.{ .allocator = allocator }, Server.handleConnection, .{ &server, stream }) catch |err| {
            std.log.err("failed to spawn thread: {}", .{err});
            stream.close(io);
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
