const std = @import("std");
const Store = @import("Store.zig");
const json = @import("json.zig");
const Allocator = std.mem.Allocator;

/// Build the filesystem path for an account file.
/// Replaces dashes in the UUID with '/' for directory sharding, appends ".json".
/// e.g. "a1b2c3d4-e5f6-7890-abcd-ef1234567890" -> "<base>/a1b2c3d4/e5f6/7890/abcd/ef1234567890.json"
pub fn accountPath(allocator: Allocator, base_dir: []const u8, account_id: *const [Store.uuid_len]u8) ![]const u8 {
    // Replace '-' with '/' in UUID
    var sharded: [Store.uuid_len]u8 = account_id.*;
    for (&sharded) |*c| {
        if (c.* == '-') c.* = '/';
    }

    // Join: base_dir / sharded.json
    return try std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ base_dir, sharded });
}

/// Persist a single account's data to disk. Caller must hold store lock.
pub fn saveAccount(allocator: Allocator, store: *Store, base_dir: []const u8, account_id: *const [Store.uuid_len]u8) !void {
    const data = try json.serializeAccount(allocator, store, account_id);
    defer allocator.free(data);

    const path = try accountPath(allocator, base_dir, account_id);
    defer allocator.free(path);

    // Create parent directories recursively
    const dir_end = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.InvalidPath;
    const dir_path = path[0..dir_end];
    try makeDirsRecursive(dir_path);

    // Atomic write: write to .tmp then rename
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp_path);

    const file = try std.fs.createFileAbsolute(tmp_path, .{});
    try file.writeAll(data);
    file.close();

    std.fs.renameAbsolute(tmp_path, path) catch {
        // Fallback: direct write
        const f2 = try std.fs.createFileAbsolute(path, .{});
        try f2.writeAll(data);
        f2.close();
    };
}

fn makeDirsRecursive(path: []const u8) !void {
    // Try to create the leaf directory first
    std.fs.makeDirAbsolute(path) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            // Parent doesn't exist, recurse up
            const parent_end = std.mem.lastIndexOfScalar(u8, path, '/') orelse return err;
            try makeDirsRecursive(path[0..parent_end]);
            // Now create this level
            std.fs.makeDirAbsolute(path) catch |err2| switch (err2) {
                error.PathAlreadyExists => return,
                else => return err2,
            };
        },
        else => return err,
    };
}

/// Load all account files from the base directory into the store. Used on startup.
pub fn loadAll(allocator: Allocator, store: *Store, base_dir: []const u8) !void {
    store.lock();
    defer store.unlock();

    loadDir(allocator, store, base_dir) catch |err| switch (err) {
        error.FileNotFound => {
            std.log.info("no persist directory found at {s}, starting fresh", .{base_dir});
            return;
        },
        else => return err,
    };
}

fn loadDir(allocator: Allocator, store: *Store, dir_path: []const u8) !void {
    var dir = try std.fs.openDirAbsolute(dir_path, .{ .iterate = true });
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        const full_path = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        defer allocator.free(full_path);

        switch (entry.kind) {
            .directory => {
                try loadDir(allocator, store, full_path);
            },
            .file => {
                if (std.mem.endsWith(u8, entry.name, ".json") and !std.mem.endsWith(u8, entry.name, ".tmp")) {
                    loadFile(allocator, store, full_path) catch |err| {
                        std.log.err("failed to load {s}: {}", .{ full_path, err });
                    };
                }
            },
            else => {},
        }
    }
}

fn loadFile(allocator: Allocator, store: *Store, path: []const u8) !void {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    const stat = try file.stat();
    const data = try allocator.alloc(u8, stat.size);
    defer allocator.free(data);
    const n = try file.readAll(data);

    try json.deserializeAccount(allocator, store, data[0..n]);
}

// --- Tests ---

test "accountPath produces sharded path" {
    const id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890".*;
    const path = try accountPath(std.testing.allocator, "/tmp/ape-auth", &id);
    defer std.testing.allocator.free(path);
    try std.testing.expectEqualStrings("/tmp/ape-auth/a1b2c3d4/e5f6/7890/abcd/ef1234567890.json", path);
}

test "saveAccount and loadAll roundtrip" {
    const allocator = std.testing.allocator;
    const base_dir = "/tmp/ape-auth-test-persist";

    // Clean up from any previous test run
    std.fs.deleteTreeAbsolute(base_dir) catch {};
    defer std.fs.deleteTreeAbsolute(base_dir) catch {};

    var store = Store.init(allocator);
    defer store.deinit();

    const account_id = Store.generateUuid();
    try store.putAccount(.{ .id = account_id, .created_at = Store.timestamp() });

    var pk: [32]u8 = undefined;
    std.crypto.random.bytes(&pk);
    const device_id = Store.generateUuid();
    const name = try allocator.dupe(u8, "test device");
    try store.putDevice(.{
        .id = device_id,
        .account_id = account_id,
        .public_key = pk,
        .name = name,
        .created_at = Store.timestamp(),
    });

    // Save
    try saveAccount(allocator, &store, base_dir, &account_id);

    // Verify file exists
    const path = try accountPath(allocator, base_dir, &account_id);
    defer allocator.free(path);
    const file = try std.fs.openFileAbsolute(path, .{});
    file.close();

    // Load into new store
    var store2 = Store.init(allocator);
    defer store2.deinit();

    try loadAll(allocator, &store2, base_dir);

    try std.testing.expect(store2.accounts.get(&account_id) != null);
    try std.testing.expect(store2.devices.get(&device_id) != null);
}

test "loadAll handles missing directory" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try loadAll(std.testing.allocator, &store, "/tmp/ape-auth-test-nonexistent-persist");
}
