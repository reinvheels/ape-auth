const std = @import("std");
const Store = @import("Store.zig");
const persist = @import("persist.zig");
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
};

pub const TokenPair = struct {
    access_token: [Store.token_len]u8,
    refresh_token: [Store.token_len]u8,
    expires_at: i64,
};

pub const RegisterResult = struct {
    account_id: [Store.uuid_len]u8,
    device_id: [Store.uuid_len]u8,
    tokens: TokenPair,
};

pub const LoginResult = struct {
    account_id: [Store.uuid_len]u8,
    tokens: TokenPair,
};

pub const ChallengeResult = struct {
    challenge: [Store.token_len]u8,
    expires_at: i64,
};

/// Register a new account with the given device public key.
pub fn register(store: *Store, public_key_hex: []const u8, device_name: []const u8) (AuthError || Allocator.Error)!RegisterResult {
    if (public_key_hex.len != Store.key_len) return AuthError.InvalidPublicKey;

    const pk_bytes = Store.hexDecode(32, public_key_hex[0..Store.key_len]) catch return AuthError.InvalidPublicKey;

    store.lock();
    defer store.unlock();

    // Check if device already exists
    if (store.getDeviceByPublicKey(public_key_hex) != null) {
        return AuthError.DeviceAlreadyExists;
    }

    const now = Store.timestamp();
    const account_id = Store.generateUuid();
    const device_id = Store.generateUuid();

    try store.putAccount(.{ .id = account_id, .created_at = now });

    const name_owned = try store.allocator.dupe(u8, device_name);
    errdefer store.allocator.free(name_owned);

    try store.putDevice(.{
        .id = device_id,
        .account_id = account_id,
        .public_key = pk_bytes,
        .name = name_owned,
        .created_at = now,
    });

    const tokens = try createTokenPair(store, &account_id, &device_id, now);

    persistAccount(store, &account_id);

    return .{
        .account_id = account_id,
        .device_id = device_id,
        .tokens = tokens,
    };
}

/// Create a challenge for the device identified by the given public key.
pub fn createChallenge(store: *Store, public_key_hex: []const u8) (AuthError || Allocator.Error)!ChallengeResult {
    if (public_key_hex.len != Store.key_len) return AuthError.InvalidPublicKey;

    store.lock();
    defer store.unlock();

    const device = store.getDeviceByPublicKey(public_key_hex) orelse return AuthError.DeviceNotFound;

    const now = Store.timestamp();
    var nonce: [32]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    const nonce_hex = Store.hexEncode(32, &nonce);

    const challenge = Store.Challenge{
        .nonce = nonce,
        .device_id = device.id,
        .expires_at = now + challenge_ttl,
    };
    try store.putChallenge(nonce_hex, challenge);

    return .{
        .challenge = nonce_hex,
        .expires_at = now + challenge_ttl,
    };
}

/// Verify a login challenge signature and create a session.
pub fn login(store: *Store, public_key_hex: []const u8, challenge_hex: []const u8, signature_hex: []const u8) (AuthError || Allocator.Error)!LoginResult {
    if (public_key_hex.len != Store.key_len) return AuthError.InvalidPublicKey;
    if (challenge_hex.len != Store.token_len) return AuthError.InvalidChallenge;
    if (signature_hex.len != Store.sig_len) return AuthError.InvalidSignature;

    const pk_bytes = Store.hexDecode(32, public_key_hex[0..Store.key_len]) catch return AuthError.InvalidPublicKey;
    const sig_bytes = Store.hexDecode(64, signature_hex[0..Store.sig_len]) catch return AuthError.InvalidSignature;
    const challenge_bytes = Store.hexDecode(32, challenge_hex[0..Store.token_len]) catch return AuthError.InvalidChallenge;

    // Verify the Ed25519 signature of the challenge nonce
    const public_key = Ed25519.PublicKey.fromBytes(pk_bytes) catch return AuthError.InvalidPublicKey;
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    sig.verify(&challenge_bytes, public_key) catch return AuthError.InvalidSignature;

    store.lock();
    defer store.unlock();

    // Validate challenge exists and is not expired
    const challenge = store.getChallenge(challenge_hex) orelse return AuthError.ChallengeNotFound;
    const now = Store.timestamp();
    if (challenge.expires_at <= now) {
        store.removeChallenge(challenge_hex);
        return AuthError.ChallengeExpired;
    }

    const device_id = challenge.device_id;
    store.removeChallenge(challenge_hex);

    // Get device to find account
    const device = store.devices.get(&device_id) orelse return AuthError.DeviceNotFound;
    const account_id = device.account_id;

    const tokens = try createTokenPair(store, &account_id, &device_id, now);

    persistAccount(store, &account_id);

    return .{
        .account_id = account_id,
        .tokens = tokens,
    };
}

/// Refresh an access token using a refresh token.
pub fn refreshTokens(store: *Store, refresh_token_hex: []const u8) (AuthError || Allocator.Error)!TokenPair {
    if (refresh_token_hex.len != Store.token_len) return AuthError.TokenNotFound;

    store.lock();
    defer store.unlock();

    const rt = store.getRefreshToken(refresh_token_hex) orelse return AuthError.TokenNotFound;
    const now = Store.timestamp();
    if (rt.expires_at <= now) {
        store.removeRefreshToken(refresh_token_hex);
        return AuthError.TokenExpired;
    }

    const account_id = rt.account_id;
    const device_id = rt.device_id;

    // Revoke old refresh token
    store.removeRefreshToken(refresh_token_hex);

    const tokens = try createTokenPair(store, &account_id, &device_id, now);

    persistAccount(store, &account_id);

    return tokens;
}

/// Validate an access token and return the associated account_id. Caller must hold store lock.
pub fn validateToken(store: *Store, token_hex: []const u8) AuthError![Store.uuid_len]u8 {
    if (token_hex.len != Store.token_len) return AuthError.TokenNotFound;

    const session = store.getSession(token_hex) orelse return AuthError.TokenNotFound;
    const now = Store.timestamp();
    if (session.expires_at <= now) {
        store.removeSession(token_hex);
        return AuthError.TokenExpired;
    }

    return session.account_id;
}

/// Link a new device to an existing account. Caller provides the account_id (from auth).
pub fn linkDevice(store: *Store, account_id: *const [Store.uuid_len]u8, public_key_hex: []const u8, device_name: []const u8) (AuthError || Allocator.Error)![Store.uuid_len]u8 {
    if (public_key_hex.len != Store.key_len) return AuthError.InvalidPublicKey;
    const pk_bytes = Store.hexDecode(32, public_key_hex[0..Store.key_len]) catch return AuthError.InvalidPublicKey;

    store.lock();
    defer store.unlock();

    if (store.getDeviceByPublicKey(public_key_hex) != null) {
        return AuthError.DeviceAlreadyExists;
    }

    const device_id = Store.generateUuid();
    const name_owned = try store.allocator.dupe(u8, device_name);
    errdefer store.allocator.free(name_owned);

    try store.putDevice(.{
        .id = device_id,
        .account_id = account_id.*,
        .public_key = pk_bytes,
        .name = name_owned,
        .created_at = Store.timestamp(),
    });

    persistAccount(store, account_id);

    return device_id;
}

/// Unlink a device from an account. Cannot remove the last device.
pub fn unlinkDevice(store: *Store, account_id: *const [Store.uuid_len]u8, device_id_hex: []const u8) AuthError!void {
    if (device_id_hex.len != Store.uuid_len) return AuthError.DeviceNotFound;

    store.lock();
    defer store.unlock();

    // Verify device belongs to account
    const device = store.devices.get(device_id_hex[0..Store.uuid_len]) orelse return AuthError.DeviceNotFound;
    if (!std.mem.eql(u8, &device.account_id, account_id)) {
        return AuthError.DeviceNotOwned;
    }

    // Check this isn't the last device
    const device_ids = store.getDevicesByAccount(account_id) orelse return AuthError.DeviceNotFound;
    if (device_ids.len <= 1) return AuthError.CannotRemoveLastDevice;

    store.removeDevice(device_id_hex[0..Store.uuid_len]) catch {};

    persistAccount(store, account_id);
}

/// Get account info including linked devices. Caller must hold lock if needed.
pub const AccountInfo = struct {
    account_id: [Store.uuid_len]u8,
    created_at: i64,
    devices: []const DeviceInfo,
};

pub const DeviceInfo = struct {
    id: [Store.uuid_len]u8,
    name: []const u8,
    created_at: i64,
};

pub fn getAccountInfo(allocator: Allocator, store: *Store, account_id: *const [Store.uuid_len]u8) !?AccountInfo {
    store.lock();
    defer store.unlock();

    const account = store.accounts.get(account_id) orelse return null;
    const device_ids = store.getDevicesByAccount(account_id) orelse return null;

    var devices = try allocator.alloc(DeviceInfo, device_ids.len);
    var count: usize = 0;
    for (device_ids) |did| {
        if (store.devices.get(&did)) |dev| {
            devices[count] = .{
                .id = dev.id,
                .name = dev.name,
                .created_at = dev.created_at,
            };
            count += 1;
        }
    }

    return .{
        .account_id = account.id,
        .created_at = account.created_at,
        .devices = devices[0..count],
    };
}

// --- Internal ---

fn persistAccount(store: *Store, account_id: *const [Store.uuid_len]u8) void {
    const base_dir = store.base_dir orelse return;
    persist.saveAccount(store.allocator, store, base_dir, account_id) catch |err| {
        std.log.err("persist failed for account {s}: {}", .{ account_id, err });
    };
}

fn createTokenPair(store: *Store, account_id: *const [Store.uuid_len]u8, device_id: *const [Store.uuid_len]u8, now: i64) Allocator.Error!TokenPair {
    const access = Store.generateToken();
    const refresh = Store.generateToken();

    try store.putSession(.{
        .token = access,
        .account_id = account_id.*,
        .device_id = device_id.*,
        .expires_at = now + access_token_ttl,
    });

    try store.putRefreshToken(.{
        .token = refresh,
        .account_id = account_id.*,
        .device_id = device_id.*,
        .expires_at = now + refresh_token_ttl,
    });

    return .{
        .access_token = access,
        .refresh_token = refresh,
        .expires_at = now + access_token_ttl,
    };
}

// --- Tests ---

test "register creates account and returns tokens" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const kp = Ed25519.KeyPair.generate();
    const pk_hex = Store.hexEncode(32, &kp.public_key.bytes);

    const result = try register(&store, &pk_hex, "test device");
    try std.testing.expect(result.tokens.expires_at > Store.timestamp());

    // Account should exist
    store.lock();
    defer store.unlock();
    try std.testing.expect(store.accounts.get(&result.account_id) != null);
}

test "register rejects duplicate public key" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const kp = Ed25519.KeyPair.generate();
    const pk_hex = Store.hexEncode(32, &kp.public_key.bytes);

    _ = try register(&store, &pk_hex, "device 1");
    const result = register(&store, &pk_hex, "device 2");
    try std.testing.expectError(AuthError.DeviceAlreadyExists, result);
}

test "challenge-login flow" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const kp = Ed25519.KeyPair.generate();
    const pk_hex = Store.hexEncode(32, &kp.public_key.bytes);

    // Register first
    _ = try register(&store, &pk_hex, "test device");

    // Create challenge
    const challenge_result = try createChallenge(&store, &pk_hex);

    // Sign the challenge nonce
    const nonce = Store.hexDecode(32, &challenge_result.challenge) catch unreachable;
    const sig = try kp.sign(&nonce, null);
    const sig_hex = Store.hexEncode(64, &sig.toBytes());

    // Login
    const login_result = try login(&store, &pk_hex, &challenge_result.challenge, &sig_hex);
    try std.testing.expect(login_result.tokens.expires_at > Store.timestamp());
}

test "login rejects bad signature" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const kp = Ed25519.KeyPair.generate();
    const pk_hex = Store.hexEncode(32, &kp.public_key.bytes);
    _ = try register(&store, &pk_hex, "test device");

    const challenge_result = try createChallenge(&store, &pk_hex);

    // Sign with wrong key
    const bad_kp = Ed25519.KeyPair.generate();
    const nonce = Store.hexDecode(32, &challenge_result.challenge) catch unreachable;
    const bad_sig = try bad_kp.sign(&nonce, null);
    const bad_sig_hex = Store.hexEncode(64, &bad_sig.toBytes());

    const result = login(&store, &pk_hex, &challenge_result.challenge, &bad_sig_hex);
    try std.testing.expectError(AuthError.InvalidSignature, result);
}
