const std = @import("std");

pub const uuid_len = 36; // 16 bytes hex-encoded with dashes (8-4-4-4-12)
pub const token_len = 64; // 32 bytes hex-encoded
pub const key_len = 64; // 32 bytes hex-encoded
pub const sig_len = 128; // 64 bytes hex-encoded
pub const compound_token_len = uuid_len + 1 + token_len; // "uuid:token" = 101
const expires_hex_len = 16; // i64 as hex
const hmac_hex_len = 64; // 32 bytes as hex
pub const access_token_len = uuid_len + 1 + expires_hex_len + 1 + hmac_hex_len; // "uuid:expires:hmac" = 118

// --- Helpers ---

pub fn generateUuid() [uuid_len]u8 {
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    const hex = hexEncode(16, &bytes);
    var out: [uuid_len]u8 = undefined;
    @memcpy(out[0..8], hex[0..8]);
    out[8] = '-';
    @memcpy(out[9..13], hex[8..12]);
    out[13] = '-';
    @memcpy(out[14..18], hex[12..16]);
    out[18] = '-';
    @memcpy(out[19..23], hex[16..20]);
    out[23] = '-';
    @memcpy(out[24..36], hex[20..32]);
    return out;
}

pub fn generateToken() [token_len]u8 {
    var bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    return hexEncode(32, &bytes);
}

/// Create a compound token: "<account_id>:<random_hex>"
pub fn makeCompoundToken(account_id: *const [uuid_len]u8) [compound_token_len]u8 {
    var out: [compound_token_len]u8 = undefined;
    @memcpy(out[0..uuid_len], account_id);
    out[uuid_len] = ':';
    const token = generateToken();
    @memcpy(out[uuid_len + 1 ..], &token);
    return out;
}

/// Parse a compound token into account_id and token_part.
pub const CompoundTokenParts = struct {
    account_id: [uuid_len]u8,
    token_part: [token_len]u8,
};

pub fn parseCompoundToken(token: []const u8) ?CompoundTokenParts {
    if (token.len != compound_token_len) return null;
    if (token[uuid_len] != ':') return null;
    return .{
        .account_id = token[0..uuid_len].*,
        .token_part = token[uuid_len + 1 ..][0..token_len].*,
    };
}

pub fn hexEncode(comptime n: usize, bytes: *const [n]u8) [n * 2]u8 {
    var out: [n * 2]u8 = undefined;
    const charset = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = charset[b >> 4];
        out[i * 2 + 1] = charset[b & 0x0f];
    }
    return out;
}

pub fn hexDecode(comptime n: usize, hex: *const [n * 2]u8) ![n]u8 {
    var out: [n]u8 = undefined;
    for (0..n) |i| {
        const hi = try hexVal(hex[i * 2]);
        const lo = try hexVal(hex[i * 2 + 1]);
        out[i] = (@as(u8, hi) << 4) | @as(u8, lo);
    }
    return out;
}

fn hexVal(c: u8) !u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => error.InvalidHex,
    };
}

pub fn timestamp() i64 {
    return std.time.timestamp();
}

// --- HMAC Access Tokens ---

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub fn makeAccessToken(server_secret: *const [32]u8, account_id: *const [uuid_len]u8, expires_at: i64) [access_token_len]u8 {
    const expires_bytes: [8]u8 = @bitCast(@as(u64, @bitCast(expires_at)));
    const expires_hex = hexEncode(8, &expires_bytes);

    var mac: [32]u8 = undefined;
    var h = HmacSha256.init(server_secret);
    h.update(account_id);
    h.update(&expires_bytes);
    h.final(&mac);
    const mac_hex = hexEncode(32, &mac);

    var out: [access_token_len]u8 = undefined;
    @memcpy(out[0..uuid_len], account_id);
    out[uuid_len] = ':';
    @memcpy(out[uuid_len + 1 ..][0..expires_hex_len], &expires_hex);
    out[uuid_len + 1 + expires_hex_len] = ':';
    @memcpy(out[uuid_len + 1 + expires_hex_len + 1 ..], &mac_hex);
    return out;
}

pub const AccessTokenParts = struct {
    account_id: [uuid_len]u8,
    expires_at: i64,
};

pub fn validateAccessToken(server_secret: *const [32]u8, token: []const u8) ?AccessTokenParts {
    if (token.len != access_token_len) return null;
    if (token[uuid_len] != ':') return null;
    if (token[uuid_len + 1 + expires_hex_len] != ':') return null;

    const account_id = token[0..uuid_len].*;
    const expires_hex = token[uuid_len + 1 ..][0..expires_hex_len];
    const mac_hex = token[uuid_len + 1 + expires_hex_len + 1 ..][0..hmac_hex_len];

    const expires_bytes = hexDecode(8, expires_hex) catch return null;
    const expires_at: i64 = @bitCast(@as(u64, @bitCast(expires_bytes)));

    // Recompute HMAC and compare
    var expected: [32]u8 = undefined;
    var h = HmacSha256.init(server_secret);
    h.update(&account_id);
    h.update(&expires_bytes);
    h.final(&expected);
    const expected_hex = hexEncode(32, &expected);

    if (!std.crypto.timing_safe.eql([hmac_hex_len]u8, mac_hex.*, expected_hex)) return null;

    if (expires_at <= timestamp()) return null;

    return .{
        .account_id = account_id,
        .expires_at = expires_at,
    };
}

// --- Tests ---

test "generateUuid returns valid dashed hex" {
    const uuid = generateUuid();
    try std.testing.expectEqual(@as(u8, '-'), uuid[8]);
    try std.testing.expectEqual(@as(u8, '-'), uuid[13]);
    try std.testing.expectEqual(@as(u8, '-'), uuid[18]);
    try std.testing.expectEqual(@as(u8, '-'), uuid[23]);
    for (uuid, 0..) |c, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) continue;
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "hexEncode/hexDecode roundtrip" {
    const original = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const hex = hexEncode(4, &original);
    try std.testing.expectEqualStrings("deadbeef", &hex);
    const decoded = try hexDecode(4, &hex);
    try std.testing.expectEqualSlices(u8, &original, &decoded);
}

test "makeCompoundToken and parseCompoundToken roundtrip" {
    const account_id = generateUuid();
    const compound = makeCompoundToken(&account_id);
    try std.testing.expectEqual(@as(u8, ':'), compound[uuid_len]);

    const parts = parseCompoundToken(&compound);
    try std.testing.expect(parts != null);
    try std.testing.expectEqualSlices(u8, &account_id, &parts.?.account_id);
    try std.testing.expectEqual(@as(usize, token_len), parts.?.token_part.len);
}

test "parseCompoundToken rejects bad input" {
    try std.testing.expect(parseCompoundToken("too-short") == null);
    var bad: [compound_token_len]u8 = undefined;
    @memset(&bad, 'x');
    try std.testing.expect(parseCompoundToken(&bad) == null); // no colon at right position
}

test "makeAccessToken and validateAccessToken roundtrip" {
    var secret: [32]u8 = undefined;
    std.crypto.random.bytes(&secret);
    const account_id = generateUuid();
    const expires_at = timestamp() + 3600;

    const token = makeAccessToken(&secret, &account_id, expires_at);
    try std.testing.expectEqual(@as(usize, access_token_len), token.len);

    const parts = validateAccessToken(&secret, &token);
    try std.testing.expect(parts != null);
    try std.testing.expectEqualSlices(u8, &account_id, &parts.?.account_id);
    try std.testing.expectEqual(expires_at, parts.?.expires_at);
}

test "validateAccessToken rejects wrong secret" {
    var secret: [32]u8 = undefined;
    std.crypto.random.bytes(&secret);
    var wrong: [32]u8 = undefined;
    std.crypto.random.bytes(&wrong);
    const account_id = generateUuid();

    const token = makeAccessToken(&secret, &account_id, timestamp() + 3600);
    try std.testing.expect(validateAccessToken(&wrong, &token) == null);
}

test "validateAccessToken rejects expired" {
    var secret: [32]u8 = undefined;
    std.crypto.random.bytes(&secret);
    const account_id = generateUuid();

    const token = makeAccessToken(&secret, &account_id, timestamp() - 1);
    try std.testing.expect(validateAccessToken(&secret, &token) == null);
}
