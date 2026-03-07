const std = @import("std");
const Store = @import("Store.zig");
const json = @import("json.zig");
const Allocator = std.mem.Allocator;

pub const LockedAccount = struct {
    allocator: Allocator,
    lock_file: std.fs.File,
    data: std.json.Parsed(json.AccountData),
    file_data: []const u8, // raw JSON — parsed slices reference into this
    account_id: [Store.uuid_len]u8,
    base_dir: []const u8,

    pub fn deinit(self: *LockedAccount) void {
        self.data.deinit();
        self.allocator.free(self.file_data);
        self.lock_file.close();
    }
};

/// Build the filesystem path for an account file.
/// e.g. "a1b2c3d4-e5f6-7890-abcd-ef1234567890" -> "<base>/a1b2c3d4/e5f6/7890/abcd/ef1234567890.json"
pub fn accountPath(allocator: Allocator, base_dir: []const u8, account_id: *const [Store.uuid_len]u8) ![]const u8 {
    var sharded: [Store.uuid_len]u8 = account_id.*;
    for (&sharded) |*c| {
        if (c.* == '-') c.* = '/';
    }
    return try std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ base_dir, sharded });
}

fn makeDirsRecursive(path: []const u8) !void {
    std.fs.makeDirAbsolute(path) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            const parent_end = std.mem.lastIndexOfScalar(u8, path, '/') orelse return err;
            try makeDirsRecursive(path[0..parent_end]);
            std.fs.makeDirAbsolute(path) catch |err2| switch (err2) {
                error.PathAlreadyExists => return,
                else => return err2,
            };
        },
        else => return err,
    };
}

/// Open the lock file with exclusive flock, read and parse the account data.
/// Returns null if the account file doesn't exist.
pub fn openAndLockAccount(allocator: Allocator, base_dir: []const u8, account_id: *const [Store.uuid_len]u8) !?LockedAccount {
    const path = try accountPath(allocator, base_dir, account_id);
    defer allocator.free(path);

    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{path});
    defer allocator.free(lock_path);

    // Open lock file
    const lock_file = std.fs.openFileAbsolute(lock_path, .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    errdefer lock_file.close();

    // Acquire exclusive flock
    lock_file.lock(.exclusive) catch |err| {
        lock_file.close();
        return err;
    };

    // Read the data file
    const data_file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            // Lock file exists but data file doesn't — shouldn't happen normally
            lock_file.close();
            return null;
        },
        else => {
            lock_file.close();
            return err;
        },
    };
    defer data_file.close();

    const stat = try data_file.stat();
    const file_data = try allocator.alloc(u8, stat.size);
    const n = try data_file.readAll(file_data);

    const parsed = json.parseAccountData(allocator, file_data[0..n]) catch |err| {
        allocator.free(file_data);
        lock_file.close();
        return err;
    };

    return .{
        .allocator = allocator,
        .lock_file = lock_file,
        .data = parsed,
        .file_data = file_data,
        .account_id = account_id.*,
        .base_dir = base_dir,
    };
}

/// Write new data to the account file (atomic tmp+rename) and release the lock.
pub fn writeAndUnlockAccount(allocator: Allocator, locked: *LockedAccount, new_data: json.AccountData) !void {
    defer locked.deinit();

    const path = try accountPath(allocator, locked.base_dir, &locked.account_id);
    defer allocator.free(path);

    const serialized = try json.serializeAccountData(allocator, new_data);
    defer allocator.free(serialized);

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp_path);

    const file = try std.fs.createFileAbsolute(tmp_path, .{});
    try file.writeAll(serialized);
    file.close();

    std.fs.renameAbsolute(tmp_path, path) catch {
        const f2 = try std.fs.createFileAbsolute(path, .{});
        try f2.writeAll(serialized);
        f2.close();
    };
}

/// Create a new account: create dirs, lock file, and data file.
pub fn createAccountFile(allocator: Allocator, base_dir: []const u8, account_id: *const [Store.uuid_len]u8, data: json.AccountData) !void {
    const path = try accountPath(allocator, base_dir, account_id);
    defer allocator.free(path);

    // Create parent directories
    const dir_end = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.InvalidPath;
    try makeDirsRecursive(path[0..dir_end]);

    // Create lock file
    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{path});
    defer allocator.free(lock_path);
    const lock_file = try std.fs.createFileAbsolute(lock_path, .{});
    lock_file.close();

    // Write data file
    const serialized = try json.serializeAccountData(allocator, data);
    defer allocator.free(serialized);

    const file = try std.fs.createFileAbsolute(path, .{});
    try file.writeAll(serialized);
    file.close();
}

// --- Key Index ---

/// Create keys/<pk_hex> containing the account_id.
/// Uses O_CREAT|O_EXCL for atomic race-safe duplicate detection.
/// Returns error.DeviceAlreadyExists if the key file already exists.
pub fn writeKeyIndex(allocator: Allocator, base_dir: []const u8, pk_hex: []const u8, account_id: *const [Store.uuid_len]u8) !void {
    const path = try std.fmt.allocPrint(allocator, "{s}/keys/{s}", .{ base_dir, pk_hex });
    defer allocator.free(path);

    const file = std.fs.createFileAbsolute(path, .{ .exclusive = true }) catch |err| switch (err) {
        error.PathAlreadyExists => return error.DeviceAlreadyExists,
        else => return err,
    };
    file.writeAll(account_id) catch {
        file.close();
        std.fs.deleteFileAbsolute(path) catch {};
        return error.WriteFailed;
    };
    file.close();
}

/// Read keys/<pk_hex> to get the account_id.
pub fn readKeyIndex(allocator: Allocator, base_dir: []const u8, pk_hex: []const u8) !?[Store.uuid_len]u8 {
    const path = try std.fmt.allocPrint(allocator, "{s}/keys/{s}", .{ base_dir, pk_hex });
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close();

    var buf: [Store.uuid_len]u8 = undefined;
    const n = try file.readAll(&buf);
    if (n != Store.uuid_len) return null;
    return buf;
}

/// Delete keys/<pk_hex>.
pub fn removeKeyIndex(allocator: Allocator, base_dir: []const u8, pk_hex: []const u8) !void {
    const path = try std.fmt.allocPrint(allocator, "{s}/keys/{s}", .{ base_dir, pk_hex });
    defer allocator.free(path);

    std.fs.deleteFileAbsolute(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

// --- Tests ---

test "accountPath produces sharded path" {
    const id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890".*;
    const path = try accountPath(std.testing.allocator, "/tmp/ape-auth", &id);
    defer std.testing.allocator.free(path);
    try std.testing.expectEqualStrings("/tmp/ape-auth/a1b2c3d4/e5f6/7890/abcd/ef1234567890.json", path);
}

test "createAccountFile and openAndLockAccount roundtrip" {
    const allocator = std.testing.allocator;
    const base_dir = "/tmp/ape-auth-test-persist2";

    std.fs.deleteTreeAbsolute(base_dir) catch {};
    defer std.fs.deleteTreeAbsolute(base_dir) catch {};
    try makeDirsRecursive(base_dir);

    const account_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890".*;
    const device_id = "d1d2d3d4-d5d6-d7d8-d9da-dbdcdddedfee".*;
    const pk_hex: []const u8 = "ab" ** 32;

    const devices = [_]json.DeviceJson{.{
        .id = &device_id,
        .account_id = &account_id,
        .public_key = pk_hex,
        .name = "test device",
        .created_at = 1000,
    }};

    const data = json.AccountData{
        .account = .{ .id = &account_id, .created_at = 1000 },
        .devices = &devices,
        .sessions = &.{},
        .refresh_tokens = &.{},
    };

    try createAccountFile(allocator, base_dir, &account_id, data);

    var locked = (try openAndLockAccount(allocator, base_dir, &account_id)) orelse return error.TestFailed;
    defer locked.deinit();

    try std.testing.expectEqualStrings(&account_id, locked.data.value.account.id);
    try std.testing.expectEqual(@as(usize, 1), locked.data.value.devices.len);
}

test "openAndLockAccount returns null for missing account" {
    const allocator = std.testing.allocator;
    const id = "00000000-0000-0000-0000-000000000000".*;
    const result = try openAndLockAccount(allocator, "/tmp/ape-auth-test-nonexistent", &id);
    try std.testing.expect(result == null);
}

test "writeKeyIndex and readKeyIndex roundtrip" {
    const allocator = std.testing.allocator;
    const base_dir = "/tmp/ape-auth-test-keys";

    std.fs.deleteTreeAbsolute(base_dir) catch {};
    defer std.fs.deleteTreeAbsolute(base_dir) catch {};

    const keys_dir = try std.fmt.allocPrint(allocator, "{s}/keys", .{base_dir});
    defer allocator.free(keys_dir);
    try makeDirsRecursive(keys_dir);

    const pk_hex = "ab" ** 32;
    const account_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890".*;

    try writeKeyIndex(allocator, base_dir, pk_hex[0..], &account_id);

    const result = try readKeyIndex(allocator, base_dir, pk_hex[0..]);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, &account_id, &result.?);
}

test "writeKeyIndex rejects duplicate" {
    const allocator = std.testing.allocator;
    const base_dir = "/tmp/ape-auth-test-keys-dup";

    std.fs.deleteTreeAbsolute(base_dir) catch {};
    defer std.fs.deleteTreeAbsolute(base_dir) catch {};

    const keys_dir = try std.fmt.allocPrint(allocator, "{s}/keys", .{base_dir});
    defer allocator.free(keys_dir);
    try makeDirsRecursive(keys_dir);

    const pk_hex = "cd" ** 32;
    const account_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890".*;

    try writeKeyIndex(allocator, base_dir, pk_hex[0..], &account_id);

    const result = writeKeyIndex(allocator, base_dir, pk_hex[0..], &account_id);
    try std.testing.expectError(error.DeviceAlreadyExists, result);
}

test "removeKeyIndex deletes key file" {
    const allocator = std.testing.allocator;
    const base_dir = "/tmp/ape-auth-test-keys-rm";

    std.fs.deleteTreeAbsolute(base_dir) catch {};
    defer std.fs.deleteTreeAbsolute(base_dir) catch {};

    const keys_dir = try std.fmt.allocPrint(allocator, "{s}/keys", .{base_dir});
    defer allocator.free(keys_dir);
    try makeDirsRecursive(keys_dir);

    const pk_hex = "ef" ** 32;
    const account_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890".*;

    try writeKeyIndex(allocator, base_dir, pk_hex[0..], &account_id);
    try removeKeyIndex(allocator, base_dir, pk_hex[0..]);

    const result = try readKeyIndex(allocator, base_dir, pk_hex[0..]);
    try std.testing.expect(result == null);
}
