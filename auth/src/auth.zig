// TODO: Several functions dupe stack-allocated hex strings into heap copies just to
// append to an ArrayList before serialization. If the JSON serializer doesn't require
// heap-owned slices, these allocations (e.g. nonce_hex_owned, rt_owned, did_owned) can
// be removed — the originals live on the stack for the entire serialize scope.

const std = @import("std");
const crypto = @import("crypto.zig");
const persist = @import("persist.zig");
const schema = @import("schema.zig");
const webauthn = @import("webauthn.zig");
const Ed25519 = std.crypto.sign.Ed25519;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

fn timestamp(io: Io) i64 {
    const ts = Io.Clock.real.now(io);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_s));
}

const id_token_ttl: i64 = 3600; // 1 hour
const refresh_token_ttl: i64 = 30 * 24 * 3600; // 30 days
const challenge_ttl: i64 = 300; // 5 minutes
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
    AccountNotFound,
};

pub const Config = struct {
    allocator: Allocator,
    io: Io,
    base_dir: []const u8,
    key_pair: Ed25519.KeyPair,
    issuer: []const u8,
};

pub const TokenPair = struct {
    id_token: []const u8, // JWT — caller must free with config.allocator
    refresh_token: [crypto.compound_token_len]u8,
    expires_in: i64,
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

fn makeTokenPair(config: Config, account_id: *const [crypto.uuid_len]u8) !TokenPair {
    const now = timestamp(config.io);
    const id_token = try crypto.createJwt(
        config.allocator,
        config.key_pair,
        config.issuer,
        account_id,
        now,
        now + id_token_ttl,
    );
    return .{
        .id_token = id_token,
        .refresh_token = crypto.makeCompoundToken(account_id, config.io),
        .expires_in = id_token_ttl,
    };
}

/// Register a new account with the given device public key.
pub fn register(config: Config, public_key_hex: []const u8, device_name: []const u8) !RegisterResult {
    if (public_key_hex.len != crypto.key_len) return AuthError.InvalidPublicKey;
    _ = crypto.hexDecode(32, public_key_hex[0..crypto.key_len]) catch return AuthError.InvalidPublicKey;

    const now = timestamp(config.io);
    const account_id = crypto.generateUuid(config.io);
    const device_id = crypto.generateUuid(config.io);

    // Atomic duplicate check via key index
    persist.writeKeyIndex(config.allocator, config.io, config.base_dir, public_key_hex, &account_id) catch |err| switch (err) {
        error.DeviceAlreadyExists => return AuthError.DeviceAlreadyExists,
        else => return err,
    };
    errdefer persist.removeKeyIndex(config.allocator, config.io, config.base_dir, public_key_hex) catch {};

    const tokens = try makeTokenPair(config, &account_id);
    errdefer config.allocator.free(tokens.id_token);

    const refresh_parts = crypto.parseCompoundToken(&tokens.refresh_token).?;

    const devices = [_]schema.Device{.{
        .id = &device_id,
        .public_key = public_key_hex,
        .name = device_name,
        .created_at = now,
    }};
    const refresh_tokens = [_]schema.Token{.{
        .token = &refresh_parts.token_part,
        .device_id = &device_id,
        .expires_at = now + refresh_token_ttl,
    }};

    const data = schema.AccountData{
        .account = .{ .id = &account_id, .created_at = now },
        .devices = &devices,
        .refresh_tokens = &refresh_tokens,
    };

    persist.createAccountFile(config.allocator, config.io, config.base_dir, &account_id, data) catch |err| {
        config.allocator.free(tokens.id_token);
        persist.removeKeyIndex(config.allocator, config.io, config.base_dir, public_key_hex) catch {};
        return err;
    };

    return .{
        .account_id = account_id,
        .device_id = device_id,
        .tokens = tokens,
    };
}

/// Create a challenge for the device identified by the given public key.
pub fn createChallenge(config: Config, public_key_hex: []const u8) !ChallengeResult {
    if (public_key_hex.len != crypto.key_len) return AuthError.InvalidPublicKey;

    const account_id = (try persist.readKeyIndex(config.allocator, config.io, config.base_dir, public_key_hex)) orelse
        return AuthError.DeviceNotFound;

    var locked = (try persist.openAndLockAccount(config.allocator, config.io, config.base_dir, &account_id)) orelse
        return AuthError.DeviceNotFound;
    defer locked.deinit();

    // Find device_id for this public key
    const device_id = findDeviceByKey(locked.data.value.devices, public_key_hex) orelse
        return AuthError.DeviceNotFound;

    const now = timestamp(config.io);
    var nonce: [32]u8 = undefined;
    config.io.random(&nonce);
    const nonce_hex = crypto.hexEncode(32, &nonce);

    // Build new challenges list: existing (pruned) + new
    var challenges = std.ArrayListUnmanaged(schema.Challenge){};
    defer challenges.deinit(config.allocator);

    for (locked.data.value.challenges) |ch| {
        if (ch.expires_at > now) {
            try challenges.append(config.allocator, ch);
        }
    }

    const nonce_hex_owned = try config.allocator.dupe(u8, &nonce_hex);
    defer config.allocator.free(nonce_hex_owned);
    const device_id_owned = try config.allocator.dupe(u8, &device_id);
    defer config.allocator.free(device_id_owned);

    try challenges.append(config.allocator, .{
        .nonce = nonce_hex_owned,
        .device_id = device_id_owned,
        .expires_at = now + challenge_ttl,
    });

    var new_data = locked.data.value;
    new_data.challenges = challenges.items;

    try persist.writeAccountData(config.allocator, config.io, &locked, new_data);

    return .{
        .challenge = nonce_hex,
        .expires_at = now + challenge_ttl,
    };
}

/// Verify a login challenge signature and create tokens.
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

    const account_id = (try persist.readKeyIndex(config.allocator, config.io, config.base_dir, public_key_hex)) orelse
        return AuthError.DeviceNotFound;

    var locked = (try persist.openAndLockAccount(config.allocator, config.io, config.base_dir, &account_id)) orelse
        return AuthError.DeviceNotFound;
    defer locked.deinit();

    const now = timestamp(config.io);

    // Find and consume the challenge
    var found_device_id: ?[crypto.uuid_len]u8 = null;
    var challenges = std.ArrayListUnmanaged(schema.Challenge){};
    defer challenges.deinit(config.allocator);

    for (locked.data.value.challenges) |ch| {
        if (found_device_id == null and std.mem.eql(u8, ch.nonce, challenge_hex)) {
            if (ch.expires_at <= now) return AuthError.ChallengeExpired;
            found_device_id = ch.device_id[0..crypto.uuid_len].*;
        } else if (ch.expires_at > now) {
            try challenges.append(config.allocator, ch);
        }
    }

    if (found_device_id == null) return AuthError.ChallengeNotFound;

    const device_id = found_device_id.?;

    const tokens = try makeTokenPair(config, &account_id);
    errdefer config.allocator.free(tokens.id_token);

    const refresh_parts = crypto.parseCompoundToken(&tokens.refresh_token).?;

    // Build new refresh token list
    var rts = std.ArrayListUnmanaged(schema.Token){};
    defer rts.deinit(config.allocator);

    for (locked.data.value.refresh_tokens) |r| {
        if (r.expires_at > now) try rts.append(config.allocator, r);
    }

    const rt_owned = try config.allocator.dupe(u8, &refresh_parts.token_part);
    defer config.allocator.free(rt_owned);
    const did_owned = try config.allocator.dupe(u8, &device_id);
    defer config.allocator.free(did_owned);

    try rts.append(config.allocator, .{
        .token = rt_owned,
        .device_id = did_owned,
        .expires_at = now + refresh_token_ttl,
    });

    var new_data = locked.data.value;
    new_data.refresh_tokens = rts.items;
    new_data.challenges = challenges.items;

    try persist.writeAccountData(config.allocator, config.io, &locked, new_data);

    return .{
        .account_id = account_id,
        .tokens = tokens,
    };
}

/// Verify a JWT ID token and return the account_id (sub claim).
pub fn validateToken(config: Config, token: []const u8) !?[crypto.uuid_len]u8 {
    var result = crypto.verifyJwt(config.allocator, config.key_pair.public_key, token, config.io) catch
        return null;
    defer result.deinit();

    if (result.claims.value.sub.len != crypto.uuid_len) return null;
    return result.claims.value.sub[0..crypto.uuid_len].*;
}

/// Refresh tokens using a compound refresh token.
pub fn refreshTokens(config: Config, refresh_token: []const u8) !TokenPair {
    const parts = crypto.parseCompoundToken(refresh_token) orelse return AuthError.TokenNotFound;

    var locked = (try persist.openAndLockAccount(config.allocator, config.io, config.base_dir, &parts.account_id)) orelse
        return AuthError.TokenNotFound;
    defer locked.deinit();

    const now = timestamp(config.io);

    // Find and consume the refresh token
    var found_device_id: ?[]const u8 = null;
    var rts = std.ArrayListUnmanaged(schema.Token){};
    defer rts.deinit(config.allocator);

    for (locked.data.value.refresh_tokens) |r| {
        if (found_device_id == null and std.mem.eql(u8, r.token, &parts.token_part)) {
            if (r.expires_at <= now) return AuthError.TokenExpired;
            found_device_id = r.device_id;
        } else {
            try rts.append(config.allocator, r);
        }
    }

    if (found_device_id == null) return AuthError.TokenNotFound;

    const device_id = found_device_id.?;

    const tokens = try makeTokenPair(config, &parts.account_id);
    errdefer config.allocator.free(tokens.id_token);

    const refresh_parts = crypto.parseCompoundToken(&tokens.refresh_token).?;

    const rt_owned = try config.allocator.dupe(u8, &refresh_parts.token_part);
    defer config.allocator.free(rt_owned);

    try rts.append(config.allocator, .{
        .token = rt_owned,
        .device_id = device_id,
        .expires_at = now + refresh_token_ttl,
    });

    var new_data = locked.data.value;
    new_data.refresh_tokens = rts.items;

    try persist.writeAccountData(config.allocator, config.io, &locked, new_data);

    return tokens;
}

/// Revoke a refresh token (e.g. on logout). Succeeds silently if token not found.
pub fn revokeRefreshToken(config: Config, refresh_token: []const u8) !void {
    const parts = crypto.parseCompoundToken(refresh_token) orelse return;

    var locked = (try persist.openAndLockAccount(config.allocator, config.io, config.base_dir, &parts.account_id)) orelse return;
    defer locked.deinit();

    var rts = std.ArrayListUnmanaged(schema.Token){};
    defer rts.deinit(config.allocator);

    var found = false;
    for (locked.data.value.refresh_tokens) |r| {
        if (!found and std.mem.eql(u8, r.token, &parts.token_part)) {
            found = true;
        } else {
            try rts.append(config.allocator, r);
        }
    }

    if (!found) return;

    var new_data = locked.data.value;
    new_data.refresh_tokens = rts.items;
    try persist.writeAccountData(config.allocator, config.io, &locked, new_data);
}

/// Link a new device to an existing account.
pub fn linkDevice(config: Config, account_id: *const [crypto.uuid_len]u8, public_key_hex: []const u8, device_name: []const u8) !?[crypto.uuid_len]u8 {
    if (public_key_hex.len != crypto.key_len) return AuthError.InvalidPublicKey;
    _ = crypto.hexDecode(32, public_key_hex[0..crypto.key_len]) catch return AuthError.InvalidPublicKey;

    var locked = (try persist.openAndLockAccount(config.allocator, config.io, config.base_dir, account_id)) orelse
        return AuthError.AccountNotFound;
    defer locked.deinit();

    // Write key index first (atomic dup check)
    persist.writeKeyIndex(config.allocator, config.io, config.base_dir, public_key_hex, account_id) catch |err| switch (err) {
        error.DeviceAlreadyExists => return AuthError.DeviceAlreadyExists,
        else => return err,
    };

    const device_id = crypto.generateUuid(config.io);
    const now = timestamp(config.io);

    var devices = std.ArrayListUnmanaged(schema.Device){};
    defer devices.deinit(config.allocator);
    for (locked.data.value.devices) |d| {
        try devices.append(config.allocator, d);
    }

    const did_owned = try config.allocator.dupe(u8, &device_id);
    defer config.allocator.free(did_owned);

    try devices.append(config.allocator, .{
        .id = did_owned,
        .public_key = public_key_hex,
        .name = device_name,
        .created_at = now,
    });

    var new_data = locked.data.value;
    new_data.devices = devices.items;

    persist.writeAccountData(config.allocator, config.io, &locked, new_data) catch |err| {
        persist.removeKeyIndex(config.allocator, config.io, config.base_dir, public_key_hex) catch {};
        return err;
    };

    return device_id;
}

/// Unlink a device from an account.
pub fn unlinkDevice(config: Config, account_id: *const [crypto.uuid_len]u8, device_id_hex: []const u8) !void {
    if (device_id_hex.len != crypto.uuid_len) return AuthError.DeviceNotFound;

    var locked = (try persist.openAndLockAccount(config.allocator, config.io, config.base_dir, account_id)) orelse
        return AuthError.AccountNotFound;
    defer locked.deinit();

    if (locked.data.value.devices.len <= 1) return AuthError.CannotRemoveLastDevice;

    var devices = std.ArrayListUnmanaged(schema.Device){};
    defer devices.deinit(config.allocator);
    var removed_pk: ?[]const u8 = null;

    for (locked.data.value.devices) |d| {
        if (std.mem.eql(u8, d.id, device_id_hex)) {
            removed_pk = d.public_key;
        } else {
            try devices.append(config.allocator, d);
        }
    }

    if (removed_pk == null) return AuthError.DeviceNotFound;

    var new_data = locked.data.value;
    new_data.devices = devices.items;

    try persist.writeAccountData(config.allocator, config.io, &locked, new_data);

    persist.removeKeyIndex(config.allocator, config.io, config.base_dir, removed_pk.?) catch {};
}

/// Get account info including linked devices.
pub fn getAccountInfo(config: Config, account_id: *const [crypto.uuid_len]u8) !?AccountInfo {
    var parsed = (try persist.readAccount(config.allocator, config.io, config.base_dir, account_id)) orelse
        return null;
    defer parsed.deinit();

    var devices = try config.allocator.alloc(DeviceInfo, parsed.value.devices.len);
    var count: usize = 0;
    for (parsed.value.devices) |d| {
        if (d.id.len >= crypto.uuid_len) {
            devices[count] = .{
                .id = d.id[0..crypto.uuid_len].*,
                .name = try config.allocator.dupe(u8, d.name),
                .created_at = d.created_at,
            };
            count += 1;
        }
    }

    const acc = parsed.value.account;
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

// --- WebAuthn ---

pub const WebAuthnRegisterOptions = struct {
    challenge_b64: []const u8, // base64url — caller must free with config.allocator
    account_id: [crypto.uuid_len]u8,
    user_id_b64: []const u8, // base64url — caller must free with config.allocator
};

pub const WebAuthnRegisterResult = struct {
    account_id: [crypto.uuid_len]u8,
    device_id: [crypto.uuid_len]u8,
    tokens: TokenPair,
};

pub const WebAuthnLoginOptions = struct {
    challenge_b64: []const u8, // base64url — caller must free with config.allocator
};

pub fn webauthnRegisterOptions(config: Config, display_name: []const u8) !WebAuthnRegisterOptions {
    const account_id = crypto.generateUuid(config.io);

    // Generate random challenge
    var challenge_bytes: [32]u8 = undefined;
    config.io.random(&challenge_bytes);
    const challenge_b64 = try crypto.base64urlEncodeAlloc(config.allocator, &challenge_bytes);
    errdefer config.allocator.free(challenge_b64);

    const user_id_b64 = try crypto.base64urlEncodeAlloc(config.allocator, &account_id);
    errdefer config.allocator.free(user_id_b64);

    const now = timestamp(config.io);

    // Store challenge for later verification
    persist.writeWebAuthnChallenge(config.allocator, config.io, config.base_dir, challenge_b64, .{
        .type = "create",
        .expires_at = now + challenge_ttl,
        .account_id = &account_id,
        .display_name = display_name,
    }) catch return error.ChallengeStoreFailed;

    return .{
        .challenge_b64 = challenge_b64,
        .account_id = account_id,
        .user_id_b64 = user_id_b64,
    };
}

pub fn webauthnRegisterVerify(
    config: Config,
    credential_id_b64: []const u8,
    client_data_json: []const u8,
    attestation_object_b64: []const u8,
) !WebAuthnRegisterResult {
    // Decode attestation object
    const attestation_object = crypto.base64urlDecodeAlloc(config.allocator, attestation_object_b64) catch
        return AuthError.InvalidSignature;
    defer config.allocator.free(attestation_object);

    // Derive rp_id and origin from issuer
    const rp_id = rpIdFromIssuer(config.issuer);
    const origin = config.issuer;

    // Extract challenge from clientDataJSON to look up stored challenge
    const client_data = parseClientDataChallenge(client_data_json) orelse
        return AuthError.InvalidChallenge;

    // Consume stored challenge
    var challenge_data = (persist.consumeWebAuthnChallenge(
        config.allocator,
        config.io,
        config.base_dir,
        client_data.challenge,
    ) catch return AuthError.InvalidChallenge) orelse return AuthError.ChallengeNotFound;
    defer challenge_data.deinit();

    const now = timestamp(config.io);
    if (challenge_data.value.expires_at <= now) return AuthError.ChallengeExpired;
    if (!std.mem.eql(u8, challenge_data.value.type, "create")) return AuthError.InvalidChallenge;

    // Verify attestation
    const result = webauthn.verifyAttestation(
        client_data_json,
        attestation_object,
        client_data.challenge,
        origin,
        rp_id,
    ) catch return AuthError.InvalidSignature;

    // Get account_id from stored challenge
    if (challenge_data.value.account_id.len != crypto.uuid_len) return AuthError.InvalidChallenge;
    const account_id = challenge_data.value.account_id[0..crypto.uuid_len].*;

    // Write credential index
    persist.writeCredentialIndex(config.allocator, config.io, config.base_dir, credential_id_b64, &account_id) catch |err| switch (err) {
        error.DeviceAlreadyExists => return AuthError.DeviceAlreadyExists,
        else => return err,
    };
    errdefer persist.removeCredentialIndex(config.allocator, config.io, config.base_dir, credential_id_b64) catch {};

    const device_id = crypto.generateUuid(config.io);
    const tokens = try makeTokenPair(config, &account_id);
    errdefer config.allocator.free(tokens.id_token);

    const refresh_parts = crypto.parseCompoundToken(&tokens.refresh_token).?;

    // Encode public key as base64url for storage
    const pk_b64 = try crypto.base64urlEncodeAlloc(config.allocator, &result.public_key);
    defer config.allocator.free(pk_b64);

    const devices = [_]schema.Device{};
    const webauthn_creds = [_]schema.WebAuthnCredential{.{
        .id = &device_id,
        .credential_id = credential_id_b64,
        .public_key = pk_b64,
        .sign_count = result.sign_count,
        .name = challenge_data.value.display_name,
        .created_at = now,
    }};
    const refresh_tokens = [_]schema.Token{.{
        .token = &refresh_parts.token_part,
        .device_id = &device_id,
        .expires_at = now + refresh_token_ttl,
    }};

    const data = schema.AccountData{
        .account = .{ .id = &account_id, .created_at = now },
        .devices = &devices,
        .refresh_tokens = &refresh_tokens,
        .webauthn_credentials = &webauthn_creds,
    };

    persist.createAccountFile(config.allocator, config.io, config.base_dir, &account_id, data) catch |err| {
        config.allocator.free(tokens.id_token);
        persist.removeCredentialIndex(config.allocator, config.io, config.base_dir, credential_id_b64) catch {};
        return err;
    };

    return .{
        .account_id = account_id,
        .device_id = device_id,
        .tokens = tokens,
    };
}

pub fn webauthnLoginOptions(config: Config) !WebAuthnLoginOptions {
    var challenge_bytes: [32]u8 = undefined;
    config.io.random(&challenge_bytes);
    const challenge_b64 = try crypto.base64urlEncodeAlloc(config.allocator, &challenge_bytes);
    errdefer config.allocator.free(challenge_b64);

    const now = timestamp(config.io);

    persist.writeWebAuthnChallenge(config.allocator, config.io, config.base_dir, challenge_b64, .{
        .type = "get",
        .expires_at = now + challenge_ttl,
    }) catch return error.ChallengeStoreFailed;

    return .{
        .challenge_b64 = challenge_b64,
    };
}

pub fn webauthnLoginVerify(
    config: Config,
    credential_id_b64: []const u8,
    client_data_json: []const u8,
    authenticator_data_b64: []const u8,
    signature_b64: []const u8,
) !LoginResult {
    // Decode binary fields
    const authenticator_data = crypto.base64urlDecodeAlloc(config.allocator, authenticator_data_b64) catch
        return AuthError.InvalidSignature;
    defer config.allocator.free(authenticator_data);

    const signature = crypto.base64urlDecodeAlloc(config.allocator, signature_b64) catch
        return AuthError.InvalidSignature;
    defer config.allocator.free(signature);

    const rp_id = rpIdFromIssuer(config.issuer);
    const origin = config.issuer;

    // Extract and consume challenge
    const client_data = parseClientDataChallenge(client_data_json) orelse
        return AuthError.InvalidChallenge;

    var challenge_data = (persist.consumeWebAuthnChallenge(
        config.allocator,
        config.io,
        config.base_dir,
        client_data.challenge,
    ) catch return AuthError.InvalidChallenge) orelse return AuthError.ChallengeNotFound;
    defer challenge_data.deinit();

    const now = timestamp(config.io);
    if (challenge_data.value.expires_at <= now) return AuthError.ChallengeExpired;
    if (!std.mem.eql(u8, challenge_data.value.type, "get")) return AuthError.InvalidChallenge;

    // Look up credential → account
    const account_id = (try persist.readCredentialIndex(config.allocator, config.io, config.base_dir, credential_id_b64)) orelse
        return AuthError.DeviceNotFound;

    // Load account, find credential, get stored public key
    var locked = (try persist.openAndLockAccount(config.allocator, config.io, config.base_dir, &account_id)) orelse
        return AuthError.DeviceNotFound;
    defer locked.deinit();

    const cred = findWebAuthnCredential(locked.data.value.webauthn_credentials, credential_id_b64) orelse
        return AuthError.DeviceNotFound;

    // Decode stored public key
    const stored_pk = crypto.base64urlDecode(65, cred.public_key) catch
        return AuthError.InvalidSignature;

    // Verify assertion
    _ = webauthn.verifyAssertion(
        client_data_json,
        authenticator_data,
        signature,
        client_data.challenge,
        origin,
        rp_id,
        &stored_pk,
    ) catch return AuthError.InvalidSignature;

    // Issue tokens
    const tokens = try makeTokenPair(config, &account_id);
    errdefer config.allocator.free(tokens.id_token);

    const refresh_parts = crypto.parseCompoundToken(&tokens.refresh_token).?;

    var rts = std.ArrayListUnmanaged(schema.Token){};
    defer rts.deinit(config.allocator);
    for (locked.data.value.refresh_tokens) |r| {
        if (r.expires_at > now) try rts.append(config.allocator, r);
    }

    const rt_owned = try config.allocator.dupe(u8, &refresh_parts.token_part);
    defer config.allocator.free(rt_owned);
    const did_owned = try config.allocator.dupe(u8, cred.id);
    defer config.allocator.free(did_owned);

    try rts.append(config.allocator, .{
        .token = rt_owned,
        .device_id = did_owned,
        .expires_at = now + refresh_token_ttl,
    });

    var new_data = locked.data.value;
    new_data.refresh_tokens = rts.items;

    try persist.writeAccountData(config.allocator, config.io, &locked, new_data);

    return .{
        .account_id = account_id,
        .tokens = tokens,
    };
}

pub fn rpIdFromIssuer(issuer: []const u8) []const u8 {
    // Strip protocol prefix and port: "https://domain:443" → "domain"
    var host = issuer;
    if (std.mem.startsWith(u8, host, "https://")) host = host["https://".len..];
    if (std.mem.startsWith(u8, host, "http://")) host = host["http://".len..];
    // Strip port
    if (std.mem.indexOfScalar(u8, host, ':')) |i| host = host[0..i];
    return host;
}

const ClientDataChallenge = struct {
    challenge: []const u8,
};

fn parseClientDataChallenge(client_data_json: []const u8) ?ClientDataChallenge {
    var parsed = std.json.parseFromSlice(ClientDataChallenge, std.heap.page_allocator, client_data_json, .{
        .ignore_unknown_fields = true,
    }) catch return null;
    defer parsed.deinit();
    // Dupe the challenge string since parsed will be freed
    return .{ .challenge = parsed.value.challenge };
}

fn findWebAuthnCredential(creds: []const schema.WebAuthnCredential, credential_id_b64: []const u8) ?schema.WebAuthnCredential {
    for (creds) |c| {
        if (std.mem.eql(u8, c.credential_id, credential_id_b64)) return c;
    }
    return null;
}

// --- Internal ---

fn findDeviceByKey(devices: []const schema.Device, public_key_hex: []const u8) ?[crypto.uuid_len]u8 {
    for (devices) |d| {
        if (std.mem.eql(u8, d.public_key, public_key_hex)) {
            if (d.id.len >= crypto.uuid_len) return d.id[0..crypto.uuid_len].*;
        }
    }
    return null;
}

// --- Tests ---

fn testConfig(allocator: Allocator, base_dir: []const u8) Config {
    return .{
        .allocator = allocator,
        .io = std.testing.io,
        .base_dir = base_dir,
        .key_pair = Ed25519.KeyPair.generate(std.testing.io),
        .issuer = "https://auth.test",
    };
}

fn setupTestDir(allocator: Allocator, base_dir: []const u8) !void {
    const io = std.testing.io;
    Io.Dir.cwd().deleteTree(io, base_dir) catch {};
    Io.Dir.createDirAbsolute(io, base_dir, .default_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
    const keys_dir = try std.fmt.allocPrint(allocator, "{s}/keys", .{base_dir});
    defer allocator.free(keys_dir);
    Io.Dir.createDirAbsolute(io, keys_dir, .default_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
}

test "register creates account and returns JWT" {
    const allocator = std.testing.allocator;
    const base_dir = "/tmp/ape-auth-test-auth-reg";
    try setupTestDir(allocator, base_dir);
    defer Io.Dir.cwd().deleteTree(std.testing.io, base_dir) catch {};

    const config = testConfig(allocator, base_dir);

    const kp = Ed25519.KeyPair.generate(std.testing.io);
    const pk_hex = crypto.hexEncode(32, &kp.public_key.bytes);

    const result = try register(config, &pk_hex, "test device");
    defer allocator.free(result.tokens.id_token);

    // ID token should be a JWT (3 dot-separated parts)
    var dots: usize = 0;
    for (result.tokens.id_token) |c| {
        if (c == '.') dots += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), dots);

    // Should be verifiable
    var jwt_result = try crypto.verifyJwt(allocator, config.key_pair.public_key, result.tokens.id_token, std.testing.io);
    defer jwt_result.deinit();
    try std.testing.expectEqualStrings(&result.account_id, jwt_result.claims.value.sub);
}

test "register rejects duplicate public key" {
    const allocator = std.testing.allocator;
    const base_dir = "/tmp/ape-auth-test-auth-dup";
    try setupTestDir(allocator, base_dir);
    defer Io.Dir.cwd().deleteTree(std.testing.io, base_dir) catch {};

    const config = testConfig(allocator, base_dir);

    const kp = Ed25519.KeyPair.generate(std.testing.io);
    const pk_hex = crypto.hexEncode(32, &kp.public_key.bytes);

    const r1 = try register(config, &pk_hex, "device 1");
    allocator.free(r1.tokens.id_token);

    const result = register(config, &pk_hex, "device 2");
    try std.testing.expectError(AuthError.DeviceAlreadyExists, result);
}

test "challenge-login flow with JWT" {
    const allocator = std.testing.allocator;
    const base_dir = "/tmp/ape-auth-test-auth-login";
    try setupTestDir(allocator, base_dir);
    defer Io.Dir.cwd().deleteTree(std.testing.io, base_dir) catch {};

    const config = testConfig(allocator, base_dir);

    const kp = Ed25519.KeyPair.generate(std.testing.io);
    const pk_hex = crypto.hexEncode(32, &kp.public_key.bytes);

    const reg = try register(config, &pk_hex, "test device");
    allocator.free(reg.tokens.id_token);

    const challenge_result = try createChallenge(config, &pk_hex);

    const nonce = crypto.hexDecode(32, &challenge_result.challenge) catch unreachable;
    const sig = try kp.sign(&nonce, null);
    const sig_hex = crypto.hexEncode(64, &sig.toBytes());

    const login_result = try login(config, &pk_hex, &challenge_result.challenge, &sig_hex);
    defer allocator.free(login_result.tokens.id_token);

    // Verify JWT
    var jwt_result = try crypto.verifyJwt(allocator, config.key_pair.public_key, login_result.tokens.id_token, std.testing.io);
    defer jwt_result.deinit();
    try std.testing.expectEqualStrings(&login_result.account_id, jwt_result.claims.value.sub);
}

test "login rejects bad signature" {
    const allocator = std.testing.allocator;
    const base_dir = "/tmp/ape-auth-test-auth-badsig";
    try setupTestDir(allocator, base_dir);
    defer Io.Dir.cwd().deleteTree(std.testing.io, base_dir) catch {};

    const config = testConfig(allocator, base_dir);

    const kp = Ed25519.KeyPair.generate(std.testing.io);
    const pk_hex = crypto.hexEncode(32, &kp.public_key.bytes);
    const reg = try register(config, &pk_hex, "test device");
    allocator.free(reg.tokens.id_token);

    const challenge_result = try createChallenge(config, &pk_hex);

    const bad_kp = Ed25519.KeyPair.generate(std.testing.io);
    const nonce = crypto.hexDecode(32, &challenge_result.challenge) catch unreachable;
    const bad_sig = try bad_kp.sign(&nonce, null);
    const bad_sig_hex = crypto.hexEncode(64, &bad_sig.toBytes());

    const result = login(config, &pk_hex, &challenge_result.challenge, &bad_sig_hex);
    try std.testing.expectError(AuthError.InvalidSignature, result);
}
