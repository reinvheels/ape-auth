const std = @import("std");
const crypto = @import("crypto.zig");
const persist = @import("persist.zig");
const schema = @import("schema.zig");
const Ed25519 = std.crypto.sign.Ed25519;
const Allocator = std.mem.Allocator;

const access_token_ttl: i64 = 3600; // 1 hour
const refresh_token_ttl: i64 = 30 * 24 * 3600; // 30 days
const challenge_ttl: i64 = 60; // 60 seconds

pub const AuthError = error{
    InvalidPublicKey,
    InvalidSignature,
    InvalidChallenge,
    DeviceNotFound,
    DeviceAlreadyExists,
    ChallengeExpired,
    ChallengeNotFound,
    TokenExpired,
    TokenNotFound,
    Unauthorized,
    CannotRemoveLastDevice,
    DeviceNotOwned,
    AccountNotFound,
};

pub const Config = struct {
    allocator: Allocator,
    base_dir: []const u8,
};

pub const TokenPair = struct {
    access_token: [crypto.compound_token_len]u8,
    refresh_token: [crypto.compound_token_len]u8,
    expires_at: i64,
};

pub const RegisterResult = struct {
    account_id: [crypto.uuid_len]u8,
    device_id: [crypto.uuid_len]u8,
    tokens: TokenPair,
};

pub const LoginResult = struct {
    account_id: [crypto.uuid_len]u8,
    tokens: TokenPair,
};

pub const ChallengeResult = struct {
    challenge: [crypto.token_len]u8,
    expires_at: i64,
};

pub const AccountInfo = struct {
    account_id: [crypto.uuid_len]u8,
    created_at: i64,
    devices: []const DeviceInfo,
};

pub const DeviceInfo = struct {
    id: [crypto.uuid_len]u8,
    name: []const u8,
    created_at: i64,
};

/// Register a new account with the given device public key.
pub fn register(config: Config, public_key_hex: []const u8, device_name: []const u8) !RegisterResult {
    if (public_key_hex.len != crypto.key_len) return AuthError.InvalidPublicKey;
    _ = crypto.hexDecode(32, public_key_hex[0..crypto.key_len]) catch return AuthError.InvalidPublicKey;

    const now = crypto.timestamp();
    const account_id = crypto.generateUuid();
    const device_id = crypto.generateUuid();

    // Atomic duplicate check via key index
    persist.writeKeyIndex(config.allocator, config.base_dir, public_key_hex, &account_id) catch |err| switch (err) {
        error.DeviceAlreadyExists => return AuthError.DeviceAlreadyExists,
        else => return err,
    };
    errdefer persist.removeKeyIndex(config.allocator, config.base_dir, public_key_hex) catch {};

    const access_compound = crypto.makeCompoundToken(&account_id);
    const refresh_compound = crypto.makeCompoundToken(&account_id);

    // Extract the token parts (64-char random portion) for storage
    const access_parts = crypto.parseCompoundToken(&access_compound).?;
    const refresh_parts = crypto.parseCompoundToken(&refresh_compound).?;

    const devices = [_]schema.DeviceJson{.{
        .id = &device_id,
        .account_id = &account_id,
        .public_key = public_key_hex,
        .name = device_name,
        .created_at = now,
    }};
    const sessions = [_]schema.SessionJson{.{
        .token = &access_parts.token_part,
        .device_id = &device_id,
        .expires_at = now + access_token_ttl,
    }};
    const rts = [_]schema.RefreshTokenJson{.{
        .token = &refresh_parts.token_part,
        .device_id = &device_id,
        .expires_at = now + refresh_token_ttl,
    }};

    const data = schema.AccountData{
        .account = .{ .id = &account_id, .created_at = now },
        .devices = &devices,
        .sessions = &sessions,
        .refresh_tokens = &rts,
    };

    persist.createAccountFile(config.allocator, config.base_dir, &account_id, data) catch |err| {
        persist.removeKeyIndex(config.allocator, config.base_dir, public_key_hex) catch {};
        return err;
    };

    return .{
        .account_id = account_id,
        .device_id = device_id,
        .tokens = .{
            .access_token = access_compound,
            .refresh_token = refresh_compound,
            .expires_at = now + access_token_ttl,
        },
    };
}

/// Create a challenge for the device identified by the given public key.
pub fn createChallenge(config: Config, public_key_hex: []const u8) !ChallengeResult {
    if (public_key_hex.len != crypto.key_len) return AuthError.InvalidPublicKey;

    const account_id = (try persist.readKeyIndex(config.allocator, config.base_dir, public_key_hex)) orelse
        return AuthError.DeviceNotFound;

    var locked = (try persist.openAndLockAccount(config.allocator, config.base_dir, &account_id)) orelse
        return AuthError.DeviceNotFound;

    // Find device_id for this public key
    const device_id = findDeviceByKey(locked.data.value.devices, public_key_hex) orelse {
        locked.deinit();
        return AuthError.DeviceNotFound;
    };

    const now = crypto.timestamp();
    var nonce: [32]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    const nonce_hex = crypto.hexEncode(32, &nonce);

    // Build new challenges list: existing (pruned) + new
    var challenges = std.ArrayListUnmanaged(schema.ChallengeJson){};
    defer challenges.deinit(config.allocator);

    // Keep unexpired challenges
    for (locked.data.value.challenges) |ch| {
        if (ch.expires_at > now) {
            try challenges.append(config.allocator, ch);
        }
    }

    // Allocate storage for nonce and device_id that outlives this scope
    const nonce_hex_owned = try config.allocator.dupe(u8, &nonce_hex);
    defer config.allocator.free(nonce_hex_owned);
    const device_id_owned = try config.allocator.dupe(u8, &device_id);
    defer config.allocator.free(device_id_owned);

    try challenges.append(config.allocator, .{
        .nonce = nonce_hex_owned,
        .device_id = device_id_owned,
        .expires_at = now + challenge_ttl,
    });

    const new_data = schema.AccountData{
        .account = locked.data.value.account,
        .devices = locked.data.value.devices,
        .sessions = locked.data.value.sessions,
        .refresh_tokens = locked.data.value.refresh_tokens,
        .challenges = challenges.items,
    };

    try persist.writeAndUnlockAccount(config.allocator, &locked, new_data);

    return .{
        .challenge = nonce_hex,
        .expires_at = now + challenge_ttl,
    };
}

/// Verify a login challenge signature and create a session.
pub fn login(config: Config, public_key_hex: []const u8, challenge_hex: []const u8, signature_hex: []const u8) !LoginResult {
    if (public_key_hex.len != crypto.key_len) return AuthError.InvalidPublicKey;
    if (challenge_hex.len != crypto.token_len) return AuthError.InvalidChallenge;
    if (signature_hex.len != crypto.sig_len) return AuthError.InvalidSignature;

    const pk_bytes = crypto.hexDecode(32, public_key_hex[0..crypto.key_len]) catch return AuthError.InvalidPublicKey;
    const sig_bytes = crypto.hexDecode(64, signature_hex[0..crypto.sig_len]) catch return AuthError.InvalidSignature;
    const challenge_bytes = crypto.hexDecode(32, challenge_hex[0..crypto.token_len]) catch return AuthError.InvalidChallenge;

    // Verify Ed25519 signature
    const public_key = Ed25519.PublicKey.fromBytes(pk_bytes) catch return AuthError.InvalidPublicKey;
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    sig.verify(&challenge_bytes, public_key) catch return AuthError.InvalidSignature;

    const account_id = (try persist.readKeyIndex(config.allocator, config.base_dir, public_key_hex)) orelse
        return AuthError.DeviceNotFound;

    var locked = (try persist.openAndLockAccount(config.allocator, config.base_dir, &account_id)) orelse
        return AuthError.DeviceNotFound;

    const now = crypto.timestamp();

    // Find and consume the challenge
    var found_device_id: ?[crypto.uuid_len]u8 = null;
    var challenges = std.ArrayListUnmanaged(schema.ChallengeJson){};
    defer challenges.deinit(config.allocator);

    for (locked.data.value.challenges) |ch| {
        if (found_device_id == null and std.mem.eql(u8, ch.nonce, challenge_hex)) {
            if (ch.expires_at <= now) {
                locked.deinit();
                return AuthError.ChallengeExpired;
            }
            found_device_id = ch.device_id[0..crypto.uuid_len].*;
            // Don't add to new list (consumed)
        } else if (ch.expires_at > now) {
            try challenges.append(config.allocator, ch);
        }
    }

    if (found_device_id == null) {
        locked.deinit();
        return AuthError.ChallengeNotFound;
    }

    const device_id = found_device_id.?;
    const access_compound = crypto.makeCompoundToken(&account_id);
    const refresh_compound = crypto.makeCompoundToken(&account_id);
    const access_parts = crypto.parseCompoundToken(&access_compound).?;
    const refresh_parts = crypto.parseCompoundToken(&refresh_compound).?;

    // Build new sessions and refresh tokens lists
    var sessions = std.ArrayListUnmanaged(schema.SessionJson){};
    defer sessions.deinit(config.allocator);
    var rts = std.ArrayListUnmanaged(schema.RefreshTokenJson){};
    defer rts.deinit(config.allocator);

    // Keep existing unexpired
    for (locked.data.value.sessions) |s| {
        if (s.expires_at > now) try sessions.append(config.allocator, s);
    }
    for (locked.data.value.refresh_tokens) |r| {
        if (r.expires_at > now) try rts.append(config.allocator, r);
    }

    // Allocate owned copies for new tokens
    const at_owned = try config.allocator.dupe(u8, &access_parts.token_part);
    defer config.allocator.free(at_owned);
    const rt_owned = try config.allocator.dupe(u8, &refresh_parts.token_part);
    defer config.allocator.free(rt_owned);
    const did_owned = try config.allocator.dupe(u8, &device_id);
    defer config.allocator.free(did_owned);

    try sessions.append(config.allocator, .{
        .token = at_owned,
        .device_id = did_owned,
        .expires_at = now + access_token_ttl,
    });
    try rts.append(config.allocator, .{
        .token = rt_owned,
        .device_id = did_owned,
        .expires_at = now + refresh_token_ttl,
    });

    const new_data = schema.AccountData{
        .account = locked.data.value.account,
        .devices = locked.data.value.devices,
        .sessions = sessions.items,
        .refresh_tokens = rts.items,
        .challenges = challenges.items,
    };

    try persist.writeAndUnlockAccount(config.allocator, &locked, new_data);

    return .{
        .account_id = account_id,
        .tokens = .{
            .access_token = access_compound,
            .refresh_token = refresh_compound,
            .expires_at = now + access_token_ttl,
        },
    };
}

/// Validate a compound access token. Returns the account_id.
pub fn validateToken(config: Config, token: []const u8) !?[crypto.uuid_len]u8 {
    const parts = crypto.parseCompoundToken(token) orelse return AuthError.TokenNotFound;

    var locked = (try persist.openAndLockAccount(config.allocator, config.base_dir, &parts.account_id)) orelse
        return AuthError.TokenNotFound;
    defer locked.deinit();

    const now = crypto.timestamp();
    for (locked.data.value.sessions) |s| {
        if (std.mem.eql(u8, s.token, &parts.token_part)) {
            if (s.expires_at <= now) return AuthError.TokenExpired;
            return parts.account_id;
        }
    }
    return AuthError.TokenNotFound;
}

/// Refresh tokens using a compound refresh token.
pub fn refreshTokens(config: Config, refresh_token: []const u8) !TokenPair {
    const parts = crypto.parseCompoundToken(refresh_token) orelse return AuthError.TokenNotFound;

    var locked = (try persist.openAndLockAccount(config.allocator, config.base_dir, &parts.account_id)) orelse
        return AuthError.TokenNotFound;

    const now = crypto.timestamp();

    // Find and consume the refresh token
    var found_device_id: ?[]const u8 = null;
    var rts = std.ArrayListUnmanaged(schema.RefreshTokenJson){};
    defer rts.deinit(config.allocator);
    var sessions = std.ArrayListUnmanaged(schema.SessionJson){};
    defer sessions.deinit(config.allocator);

    for (locked.data.value.refresh_tokens) |r| {
        if (found_device_id == null and std.mem.eql(u8, r.token, &parts.token_part)) {
            if (r.expires_at <= now) {
                locked.deinit();
                return AuthError.TokenExpired;
            }
            found_device_id = r.device_id;
            // Consumed — don't add to new list
        } else {
            try rts.append(config.allocator, r);
        }
    }

    if (found_device_id == null) {
        locked.deinit();
        return AuthError.TokenNotFound;
    }

    const device_id = found_device_id.?;

    // Keep existing unexpired sessions
    for (locked.data.value.sessions) |s| {
        if (s.expires_at > now) try sessions.append(config.allocator, s);
    }

    const access_compound = crypto.makeCompoundToken(&parts.account_id);
    const refresh_compound = crypto.makeCompoundToken(&parts.account_id);
    const access_parts = crypto.parseCompoundToken(&access_compound).?;
    const refresh_parts = crypto.parseCompoundToken(&refresh_compound).?;

    const at_owned = try config.allocator.dupe(u8, &access_parts.token_part);
    defer config.allocator.free(at_owned);
    const rt_owned = try config.allocator.dupe(u8, &refresh_parts.token_part);
    defer config.allocator.free(rt_owned);

    try sessions.append(config.allocator, .{
        .token = at_owned,
        .device_id = device_id,
        .expires_at = now + access_token_ttl,
    });
    try rts.append(config.allocator, .{
        .token = rt_owned,
        .device_id = device_id,
        .expires_at = now + refresh_token_ttl,
    });

    // Prune expired challenges
    var challenges = std.ArrayListUnmanaged(schema.ChallengeJson){};
    defer challenges.deinit(config.allocator);
    for (locked.data.value.challenges) |ch| {
        if (ch.expires_at > now) try challenges.append(config.allocator, ch);
    }

    const new_data = schema.AccountData{
        .account = locked.data.value.account,
        .devices = locked.data.value.devices,
        .sessions = sessions.items,
        .refresh_tokens = rts.items,
        .challenges = challenges.items,
    };

    try persist.writeAndUnlockAccount(config.allocator, &locked, new_data);

    return .{
        .access_token = access_compound,
        .refresh_token = refresh_compound,
        .expires_at = now + access_token_ttl,
    };
}

/// Link a new device to an existing account.
pub fn linkDevice(config: Config, account_id: *const [crypto.uuid_len]u8, public_key_hex: []const u8, device_name: []const u8) !?[crypto.uuid_len]u8 {
    if (public_key_hex.len != crypto.key_len) return AuthError.InvalidPublicKey;
    _ = crypto.hexDecode(32, public_key_hex[0..crypto.key_len]) catch return AuthError.InvalidPublicKey;

    var locked = (try persist.openAndLockAccount(config.allocator, config.base_dir, account_id)) orelse
        return AuthError.AccountNotFound;

    // Write key index first (atomic dup check)
    persist.writeKeyIndex(config.allocator, config.base_dir, public_key_hex, account_id) catch |err| switch (err) {
        error.DeviceAlreadyExists => {
            locked.deinit();
            return AuthError.DeviceAlreadyExists;
        },
        else => {
            locked.deinit();
            return err;
        },
    };

    const device_id = crypto.generateUuid();
    const now = crypto.timestamp();

    // Build new devices list
    var devices = std.ArrayListUnmanaged(schema.DeviceJson){};
    defer devices.deinit(config.allocator);
    for (locked.data.value.devices) |d| {
        try devices.append(config.allocator, d);
    }

    const did_owned = try config.allocator.dupe(u8, &device_id);
    defer config.allocator.free(did_owned);
    const aid_owned = try config.allocator.dupe(u8, account_id);
    defer config.allocator.free(aid_owned);

    try devices.append(config.allocator, .{
        .id = did_owned,
        .account_id = aid_owned,
        .public_key = public_key_hex,
        .name = device_name,
        .created_at = now,
    });

    const new_data = schema.AccountData{
        .account = locked.data.value.account,
        .devices = devices.items,
        .sessions = locked.data.value.sessions,
        .refresh_tokens = locked.data.value.refresh_tokens,
        .challenges = locked.data.value.challenges,
    };

    persist.writeAndUnlockAccount(config.allocator, &locked, new_data) catch |err| {
        // Cleanup key index on failure
        persist.removeKeyIndex(config.allocator, config.base_dir, public_key_hex) catch {};
        return err;
    };

    return device_id;
}

/// Unlink a device from an account.
pub fn unlinkDevice(config: Config, account_id: *const [crypto.uuid_len]u8, device_id_hex: []const u8) !void {
    if (device_id_hex.len != crypto.uuid_len) return AuthError.DeviceNotFound;

    var locked = (try persist.openAndLockAccount(config.allocator, config.base_dir, account_id)) orelse
        return AuthError.AccountNotFound;

    if (locked.data.value.devices.len <= 1) {
        locked.deinit();
        return AuthError.CannotRemoveLastDevice;
    }

    // Find the device and build new list without it
    var devices = std.ArrayListUnmanaged(schema.DeviceJson){};
    defer devices.deinit(config.allocator);
    var removed_pk: ?[]const u8 = null;

    for (locked.data.value.devices) |d| {
        if (std.mem.eql(u8, d.id, device_id_hex)) {
            if (!std.mem.eql(u8, d.account_id, account_id)) {
                locked.deinit();
                return AuthError.DeviceNotOwned;
            }
            removed_pk = d.public_key;
        } else {
            try devices.append(config.allocator, d);
        }
    }

    if (removed_pk == null) {
        locked.deinit();
        return AuthError.DeviceNotFound;
    }

    const new_data = schema.AccountData{
        .account = locked.data.value.account,
        .devices = devices.items,
        .sessions = locked.data.value.sessions,
        .refresh_tokens = locked.data.value.refresh_tokens,
        .challenges = locked.data.value.challenges,
    };

    try persist.writeAndUnlockAccount(config.allocator, &locked, new_data);

    // Remove key index after successful write
    persist.removeKeyIndex(config.allocator, config.base_dir, removed_pk.?) catch {};
}

/// Get account info including linked devices.
pub fn getAccountInfo(config: Config, account_id: *const [crypto.uuid_len]u8) !?AccountInfo {
    var locked = (try persist.openAndLockAccount(config.allocator, config.base_dir, account_id)) orelse
        return null;
    defer locked.deinit();

    var devices = try config.allocator.alloc(DeviceInfo, locked.data.value.devices.len);
    var count: usize = 0;
    for (locked.data.value.devices) |d| {
        if (d.id.len >= crypto.uuid_len) {
            devices[count] = .{
                .id = d.id[0..crypto.uuid_len].*,
                .name = try config.allocator.dupe(u8, d.name),
                .created_at = d.created_at,
            };
            count += 1;
        }
    }

    const acc = locked.data.value.account;
    var aid: [crypto.uuid_len]u8 = undefined;
    if (acc.id.len >= crypto.uuid_len) {
        @memcpy(&aid, acc.id[0..crypto.uuid_len]);
    }

    return .{
        .account_id = aid,
        .created_at = acc.created_at,
        .devices = devices[0..count],
    };
}

// --- Internal ---

fn findDeviceByKey(devices: []const schema.DeviceJson, public_key_hex: []const u8) ?[crypto.uuid_len]u8 {
    for (devices) |d| {
        if (std.mem.eql(u8, d.public_key, public_key_hex)) {
            if (d.id.len >= crypto.uuid_len) return d.id[0..crypto.uuid_len].*;
        }
    }
    return null;
}

// --- Tests ---

test "register creates account and returns compound tokens" {
    const allocator = std.testing.allocator;
    const base_dir = "/tmp/ape-auth-test-auth-reg";

    std.fs.deleteTreeAbsolute(base_dir) catch {};
    defer std.fs.deleteTreeAbsolute(base_dir) catch {};

    // Create base and keys dirs
    std.fs.makeDirAbsolute(base_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
    const keys_dir = try std.fmt.allocPrint(allocator, "{s}/keys", .{base_dir});
    defer allocator.free(keys_dir);
    std.fs.makeDirAbsolute(keys_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };

    const config = Config{ .allocator = allocator, .base_dir = base_dir };

    const kp = Ed25519.KeyPair.generate();
    const pk_hex = crypto.hexEncode(32, &kp.public_key.bytes);

    const result = try register(config, &pk_hex, "test device");

    // Compound tokens should be 101 chars with colon at position 36
    try std.testing.expectEqual(@as(usize, crypto.compound_token_len), result.tokens.access_token.len);
    try std.testing.expectEqual(@as(u8, ':'), result.tokens.access_token[crypto.uuid_len]);
    try std.testing.expect(result.tokens.expires_at > crypto.timestamp());

    // Key index should exist
    const read_id = try persist.readKeyIndex(allocator, base_dir, &pk_hex);
    try std.testing.expect(read_id != null);
    try std.testing.expectEqualSlices(u8, &result.account_id, &read_id.?);
}

test "register rejects duplicate public key" {
    const allocator = std.testing.allocator;
    const base_dir = "/tmp/ape-auth-test-auth-dup";

    std.fs.deleteTreeAbsolute(base_dir) catch {};
    defer std.fs.deleteTreeAbsolute(base_dir) catch {};

    std.fs.makeDirAbsolute(base_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
    const keys_dir = try std.fmt.allocPrint(allocator, "{s}/keys", .{base_dir});
    defer allocator.free(keys_dir);
    std.fs.makeDirAbsolute(keys_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };

    const config = Config{ .allocator = allocator, .base_dir = base_dir };

    const kp = Ed25519.KeyPair.generate();
    const pk_hex = crypto.hexEncode(32, &kp.public_key.bytes);

    _ = try register(config, &pk_hex, "device 1");
    const result = register(config, &pk_hex, "device 2");
    try std.testing.expectError(AuthError.DeviceAlreadyExists, result);
}

test "challenge-login flow with compound tokens" {
    const allocator = std.testing.allocator;
    const base_dir = "/tmp/ape-auth-test-auth-login";

    std.fs.deleteTreeAbsolute(base_dir) catch {};
    defer std.fs.deleteTreeAbsolute(base_dir) catch {};

    std.fs.makeDirAbsolute(base_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
    const keys_dir = try std.fmt.allocPrint(allocator, "{s}/keys", .{base_dir});
    defer allocator.free(keys_dir);
    std.fs.makeDirAbsolute(keys_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };

    const config = Config{ .allocator = allocator, .base_dir = base_dir };

    const kp = Ed25519.KeyPair.generate();
    const pk_hex = crypto.hexEncode(32, &kp.public_key.bytes);

    _ = try register(config, &pk_hex, "test device");

    // Create challenge
    const challenge_result = try createChallenge(config, &pk_hex);

    // Sign the challenge nonce
    const nonce = crypto.hexDecode(32, &challenge_result.challenge) catch unreachable;
    const sig = try kp.sign(&nonce, null);
    const sig_hex = crypto.hexEncode(64, &sig.toBytes());

    // Login
    const login_result = try login(config, &pk_hex, &challenge_result.challenge, &sig_hex);
    try std.testing.expectEqual(@as(usize, crypto.compound_token_len), login_result.tokens.access_token.len);
    try std.testing.expect(login_result.tokens.expires_at > crypto.timestamp());
}

test "login rejects bad signature" {
    const allocator = std.testing.allocator;
    const base_dir = "/tmp/ape-auth-test-auth-badsig";

    std.fs.deleteTreeAbsolute(base_dir) catch {};
    defer std.fs.deleteTreeAbsolute(base_dir) catch {};

    std.fs.makeDirAbsolute(base_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
    const keys_dir = try std.fmt.allocPrint(allocator, "{s}/keys", .{base_dir});
    defer allocator.free(keys_dir);
    std.fs.makeDirAbsolute(keys_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };

    const config = Config{ .allocator = allocator, .base_dir = base_dir };

    const kp = Ed25519.KeyPair.generate();
    const pk_hex = crypto.hexEncode(32, &kp.public_key.bytes);
    _ = try register(config, &pk_hex, "test device");

    const challenge_result = try createChallenge(config, &pk_hex);

    // Sign with wrong key
    const bad_kp = Ed25519.KeyPair.generate();
    const nonce = crypto.hexDecode(32, &challenge_result.challenge) catch unreachable;
    const bad_sig = try bad_kp.sign(&nonce, null);
    const bad_sig_hex = crypto.hexEncode(64, &bad_sig.toBytes());

    const result = login(config, &pk_hex, &challenge_result.challenge, &bad_sig_hex);
    try std.testing.expectError(AuthError.InvalidSignature, result);
}
