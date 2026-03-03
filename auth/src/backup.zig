const std = @import("std");
const Store = @import("Store.zig");
const json = @import("json.zig");
const Allocator = std.mem.Allocator;

const default_interval_s: u64 = 60;
const backup_filename = "ape-auth-backup.json";

pub fn rehydrate(allocator: Allocator, store: *Store, dir_path: []const u8) !void {
    const path = try std.fs.path.join(allocator, &.{ dir_path, backup_filename });
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            std.log.info("no backup file found at {s}, starting fresh", .{path});
            return;
        },
        else => return err,
    };
    defer file.close();

    const stat = try file.stat();
    const data = try allocator.alloc(u8, stat.size);
    defer allocator.free(data);
    const n = try file.readAll(data);
    const contents = data[0..n];

    try json.deserializeStore(allocator, store, contents);
    std.log.info("rehydrated store from {s}", .{path});
}

pub fn startBackupThread(allocator: Allocator, store: *Store, dir_path: []const u8) !std.Thread {
    const dir_owned = try allocator.dupe(u8, dir_path);
    return try std.Thread.spawn(.{ .allocator = allocator }, backupLoop, .{ allocator, store, dir_owned });
}

fn backupLoop(allocator: Allocator, store: *Store, dir_path: []const u8) void {
    defer allocator.free(dir_path);

    while (true) {
        std.Thread.sleep(default_interval_s * std.time.ns_per_s);
        performBackup(allocator, store, dir_path) catch |err| {
            std.log.err("backup failed: {}", .{err});
        };
    }
}

fn performBackup(allocator: Allocator, store: *Store, dir_path: []const u8) !void {
    store.lock();
    defer store.unlock();

    const data = try json.serializeStore(allocator, store);
    defer allocator.free(data);

    const path = try std.fs.path.join(allocator, &.{ dir_path, backup_filename });
    defer allocator.free(path);

    // Write to temp file then rename for atomicity
    const tmp_path = try std.fs.path.join(allocator, &.{ dir_path, backup_filename ++ ".tmp" });
    defer allocator.free(tmp_path);

    const dir = try std.fs.openDirAbsolute(dir_path, .{});

    const file = try std.fs.createFileAbsolute(tmp_path, .{});
    try file.writeAll(data);
    file.close();

    dir.rename(backup_filename ++ ".tmp", backup_filename) catch |err| {
        std.log.err("rename failed: {}", .{err});
        // Fallback: direct write
        const f2 = try std.fs.createFileAbsolute(path, .{});
        try f2.writeAll(data);
        f2.close();
    };

    std.log.info("backup written to {s} ({d} bytes)", .{ path, data.len });
}

test "rehydrate handles missing file" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    // Should not error on missing file
    try rehydrate(std.testing.allocator, &store, "/tmp/ape-auth-test-nonexistent");
}
