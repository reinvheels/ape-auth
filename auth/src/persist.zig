const std = @import("std");
const crypto = @import("crypto.zig");
const schema = @import("schema.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const LockedAccount = struct {
    allocator: Allocator,
    io: Io,
    lock_file: Io.File,
    data: std.json.Parsed(schema.AccountData),
    file_data: []const u8, // raw JSON — parsed slices reference into this
    account_id: [crypto.uuid_len]u8,
    base_dir: []const u8,

    pub fn deinit(self: *LockedAccount) void {
        self.data.deinit();
        self.allocator.free(self.file_data);
        self.lock_file.close(self.io);
    }
};

/// Build the filesystem path for an account file.
/// e.g. "a1b2c3d4-e5f6-7890-abcd-ef1234567890" -> "<base>/a1b2c3d4/e5f6/7890/abcd/ef1234567890.json"
pub fn accountPath(allocator: Allocator, base_dir: []const u8, account_id: *const [crypto.uuid_len]u8) ![]const u8 {
    var sharded: [crypto.uuid_len]u8 = account_id.*;
    for (&sharded) |*c| {
        if (c.* == '-') c.* = '/';
    }
    return try std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ base_dir, sharded });
}

fn makeDirsRecursive(io: Io, path: []const u8) !void {
    Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            const parent_end = std.mem.lastIndexOfScalar(u8, path, '/') orelse return err;
            try makeDirsRecursive(io, path[0..parent_end]);
            Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err2| switch (err2) {
                error.PathAlreadyExists => return,
                else => return err2,
            };
        },
        else => return err,
    };
}

/// Read and parse account data without locking. For read-only access.
/// Returns null if the account file doesn't exist.
pub fn readAccount(allocator: Allocator, io: Io, base_dir: []const u8, account_id: *const [crypto.uuid_len]u8) !?std.json.Parsed(schema.AccountData) {
    const path = try accountPath(allocator, base_dir, account_id);
    defer allocator.free(path);

    const file = Io.Dir.openFileAbsolute(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);

    const stat = try file.stat(io);
    const file_data = try allocator.alloc(u8, stat.size);
    defer allocator.free(file_data);

    const n = try file.readPositionalAll(io, file_data, 0);

    return try std.json.parseFromSlice(schema.AccountData, allocator, file_data[0..n], .{
        .allocate = .alloc_always,
    });

}

/// Open the lock file with exclusive flock, read and parse the account data.
/// Returns null if the account file doesn't exist.
pub fn openAndLockAccount(allocator: Allocator, io: Io, base_dir: []const u8, account_id: *const [crypto.uuid_len]u8) !?LockedAccount {
    const path = try accountPath(allocator, base_dir, account_id);
    defer allocator.free(path);

    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{path});
    defer allocator.free(lock_path);

    const lock_file = Io.Dir.openFileAbsolute(io, lock_path, .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    errdefer lock_file.close(io);

    try lock_file.lock(io, .exclusive);

    const data_file = Io.Dir.openFileAbsolute(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            lock_file.close(io);
            return null;
        },
        else => return err,
    };
    defer data_file.close(io);

    const stat = try data_file.stat(io);
    const file_data = try allocator.alloc(u8, stat.size);
    errdefer allocator.free(file_data);
    const n = try data_file.readPositionalAll(io, file_data, 0);

    const parsed = try schema.parse(allocator, file_data[0..n]);

    return .{
        .allocator = allocator,
        .io = io,
        .lock_file = lock_file,
        .data = parsed,
        .file_data = file_data,
        .account_id = account_id.*,
        .base_dir = base_dir,
    };
}

/// Write new data to the account file (atomic tmp+rename). Caller must deinit locked.
pub fn writeAccountData(allocator: Allocator, io: Io, locked: *LockedAccount, new_data: schema.AccountData) !void {
    const path = try accountPath(allocator, locked.base_dir, &locked.account_id);
    defer allocator.free(path);

    const serialized = try schema.serialize(allocator, new_data);
    defer allocator.free(serialized);

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp_path);

    const file = try Io.Dir.createFileAbsolute(io, tmp_path, .{});
    try file.writePositionalAll(io, serialized, 0);
    file.close(io);

    try Io.Dir.renameAbsolute(tmp_path, path, io);
}

/// Create a new account: create dirs, lock file, and data file.
pub fn createAccountFile(allocator: Allocator, io: Io, base_dir: []const u8, account_id: *const [crypto.uuid_len]u8, data: schema.AccountData) !void {
    const path = try accountPath(allocator, base_dir, account_id);
    defer allocator.free(path);

    // Create parent directories
    const dir_end = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.InvalidPath;
    try makeDirsRecursive(io, path[0..dir_end]);

    // Create lock file
    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{path});
    defer allocator.free(lock_path);
    const lock_file = try Io.Dir.createFileAbsolute(io, lock_path, .{});
    lock_file.close(io);

    // Write data file
    const serialized = try schema.serialize(allocator, data);
    defer allocator.free(serialized);

    const file = try Io.Dir.createFileAbsolute(io, path, .{});
    try file.writePositionalAll(io, serialized, 0);
    file.close(io);
}

// --- Key Index ---

/// Create keys/<pk_hex> containing the account_id.
/// Uses O_CREAT|O_EXCL for atomic race-safe duplicate detection.
/// Returns error.DeviceAlreadyExists if the key file already exists.
pub fn writeKeyIndex(allocator: Allocator, io: Io, base_dir: []const u8, pk_hex: []const u8, account_id: *const [crypto.uuid_len]u8) !void {
    const path = try std.fmt.allocPrint(allocator, "{s}/keys/{s}", .{ base_dir, pk_hex });
    defer allocator.free(path);

    const file = Io.Dir.createFileAbsolute(io, path, .{ .exclusive = true }) catch |err| switch (err) {
        error.PathAlreadyExists => return error.DeviceAlreadyExists,
        else => return err,
    };
    file.writePositionalAll(io, account_id, 0) catch {
        file.close(io);
        Io.Dir.deleteFileAbsolute(io, path) catch {};
        return error.WriteFailed;
    };
    file.close(io);
}

/// Read keys/<pk_hex> to get the account_id.
pub fn readKeyIndex(allocator: Allocator, io: Io, base_dir: []const u8, pk_hex: []const u8) !?[crypto.uuid_len]u8 {
    const path = try std.fmt.allocPrint(allocator, "{s}/keys/{s}", .{ base_dir, pk_hex });
    defer allocator.free(path);

    const file = Io.Dir.openFileAbsolute(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);

    var buf: [crypto.uuid_len]u8 = undefined;
    const n = try file.readPositionalAll(io, &buf, 0);
    if (n != crypto.uuid_len) return null;
    return buf;
}

/// Delete keys/<pk_hex>.
pub fn removeKeyIndex(allocator: Allocator, io: Io, base_dir: []const u8, pk_hex: []const u8) !void {
    const path = try std.fmt.allocPrint(allocator, "{s}/keys/{s}", .{ base_dir, pk_hex });
    defer allocator.free(path);

    Io.Dir.deleteFileAbsolute(io, path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

// --- Credential Index (WebAuthn) ---

/// Create credentials/<credential_id_b64> containing the account_id.
pub fn writeCredentialIndex(allocator: Allocator, io: Io, base_dir: []const u8, credential_id_b64: []const u8, account_id: *const [crypto.uuid_len]u8) !void {
    const path = try std.fmt.allocPrint(allocator, "{s}/credentials/{s}", .{ base_dir, credential_id_b64 });
    defer allocator.free(path);

    const file = Io.Dir.createFileAbsolute(io, path, .{ .exclusive = true }) catch |err| switch (err) {
        error.PathAlreadyExists => return error.DeviceAlreadyExists,
        else => return err,
    };
    file.writePositionalAll(io, account_id, 0) catch {
        file.close(io);
        Io.Dir.deleteFileAbsolute(io, path) catch {};
        return error.WriteFailed;
    };
    file.close(io);
}

/// Read credentials/<credential_id_b64> to get the account_id.
pub fn readCredentialIndex(allocator: Allocator, io: Io, base_dir: []const u8, credential_id_b64: []const u8) !?[crypto.uuid_len]u8 {
    const path = try std.fmt.allocPrint(allocator, "{s}/credentials/{s}", .{ base_dir, credential_id_b64 });
    defer allocator.free(path);

    const file = Io.Dir.openFileAbsolute(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);

    var buf: [crypto.uuid_len]u8 = undefined;
    const n = try file.readPositionalAll(io, &buf, 0);
    if (n != crypto.uuid_len) return null;
    return buf;
}

/// Delete credentials/<credential_id_b64>.
pub fn removeCredentialIndex(allocator: Allocator, io: Io, base_dir: []const u8, credential_id_b64: []const u8) !void {
    const path = try std.fmt.allocPrint(allocator, "{s}/credentials/{s}", .{ base_dir, credential_id_b64 });
    defer allocator.free(path);

    Io.Dir.deleteFileAbsolute(io, path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

// --- WebAuthn Challenge Store ---

pub const WebAuthnChallengeData = struct {
    type: []const u8, // "create" or "get"
    expires_at: i64,
    account_id: []const u8 = "", // pre-generated account ID for registration
    display_name: []const u8 = "",
};

/// Store a WebAuthn challenge. Returns the challenge hex string.
pub fn writeWebAuthnChallenge(allocator: Allocator, io: Io, base_dir: []const u8, challenge_b64: []const u8, data: WebAuthnChallengeData) !void {
    const path = try std.fmt.allocPrint(allocator, "{s}/webauthn_challenges/{s}", .{ base_dir, challenge_b64 });
    defer allocator.free(path);

    const json = try std.json.Stringify.valueAlloc(allocator, data, .{});
    defer allocator.free(json);

    const file = Io.Dir.createFileAbsolute(io, path, .{ .exclusive = true }) catch |err| switch (err) {
        error.PathAlreadyExists => return error.ChallengeExists,
        else => return err,
    };
    file.writePositionalAll(io, json, 0) catch {
        file.close(io);
        Io.Dir.deleteFileAbsolute(io, path) catch {};
        return error.WriteFailed;
    };
    file.close(io);
}

/// Read and consume (delete) a WebAuthn challenge.
pub fn consumeWebAuthnChallenge(allocator: Allocator, io: Io, base_dir: []const u8, challenge_b64: []const u8) !?std.json.Parsed(WebAuthnChallengeData) {
    const path = try std.fmt.allocPrint(allocator, "{s}/webauthn_challenges/{s}", .{ base_dir, challenge_b64 });
    defer allocator.free(path);

    const file = Io.Dir.openFileAbsolute(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);

    const stat = try file.stat(io);
    const file_data = try allocator.alloc(u8, stat.size);
    defer allocator.free(file_data);
    const n = try file.readPositionalAll(io, file_data, 0);

    const parsed = try std.json.parseFromSlice(WebAuthnChallengeData, allocator, file_data[0..n], .{
        .allocate = .alloc_always,
    });

    // Delete after successful parse (consume)
    Io.Dir.deleteFileAbsolute(io, path) catch {};

    return parsed;
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
    const io = std.testing.io;
    const base_dir = "/tmp/ape-auth-test-persist2";

    Io.Dir.cwd().deleteTree(io, base_dir) catch {};
    defer Io.Dir.cwd().deleteTree(io, base_dir) catch {};
    try makeDirsRecursive(io, base_dir);

    const account_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890".*;
    const device_id = "d1d2d3d4-d5d6-d7d8-d9da-dbdcdddedfee".*;
    const pk_hex: []const u8 = "ab" ** 32;

    const devices = [_]schema.Device{.{
        .id = &device_id,
        .public_key = pk_hex,
        .name = "test device",
        .created_at = 1000,
    }};

    const data = schema.AccountData{
        .account = .{ .id = &account_id, .created_at = 1000 },
        .devices = &devices,
        .refresh_tokens = &.{},
    };

    try createAccountFile(allocator, io, base_dir, &account_id, data);

    var locked = (try openAndLockAccount(allocator, io, base_dir, &account_id)) orelse return error.TestFailed;
    defer locked.deinit();

    try std.testing.expectEqualStrings(&account_id, locked.data.value.account.id);
    try std.testing.expectEqual(@as(usize, 1), locked.data.value.devices.len);
}

test "openAndLockAccount returns null for missing account" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const id = "00000000-0000-0000-0000-000000000000".*;
    const result = try openAndLockAccount(allocator, io, "/tmp/ape-auth-test-nonexistent", &id);
    try std.testing.expect(result == null);
}

test "writeKeyIndex and readKeyIndex roundtrip" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const base_dir = "/tmp/ape-auth-test-keys";

    Io.Dir.cwd().deleteTree(io, base_dir) catch {};
    defer Io.Dir.cwd().deleteTree(io, base_dir) catch {};

    const keys_dir = try std.fmt.allocPrint(allocator, "{s}/keys", .{base_dir});
    defer allocator.free(keys_dir);
    try makeDirsRecursive(io, keys_dir);

    const pk_hex = "ab" ** 32;
    const account_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890".*;

    try writeKeyIndex(allocator, io, base_dir, pk_hex[0..], &account_id);

    const result = try readKeyIndex(allocator, io, base_dir, pk_hex[0..]);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, &account_id, &result.?);
}

test "writeKeyIndex rejects duplicate" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const base_dir = "/tmp/ape-auth-test-keys-dup";

    Io.Dir.cwd().deleteTree(io, base_dir) catch {};
    defer Io.Dir.cwd().deleteTree(io, base_dir) catch {};

    const keys_dir = try std.fmt.allocPrint(allocator, "{s}/keys", .{base_dir});
    defer allocator.free(keys_dir);
    try makeDirsRecursive(io, keys_dir);

    const pk_hex = "cd" ** 32;
    const account_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890".*;

    try writeKeyIndex(allocator, io, base_dir, pk_hex[0..], &account_id);

    const result = writeKeyIndex(allocator, io, base_dir, pk_hex[0..], &account_id);
    try std.testing.expectError(error.DeviceAlreadyExists, result);
}

test "removeKeyIndex deletes key file" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const base_dir = "/tmp/ape-auth-test-keys-rm";

    Io.Dir.cwd().deleteTree(io, base_dir) catch {};
    defer Io.Dir.cwd().deleteTree(io, base_dir) catch {};

    const keys_dir = try std.fmt.allocPrint(allocator, "{s}/keys", .{base_dir});
    defer allocator.free(keys_dir);
    try makeDirsRecursive(io, keys_dir);

    const pk_hex = "ef" ** 32;
    const account_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890".*;

    try writeKeyIndex(allocator, io, base_dir, pk_hex[0..], &account_id);
    try removeKeyIndex(allocator, io, base_dir, pk_hex[0..]);

    const result = try readKeyIndex(allocator, io, base_dir, pk_hex[0..]);
    try std.testing.expect(result == null);
}
