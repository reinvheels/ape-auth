const std = @import("std");
const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;
const Io = std.Io;

pub const uuid_len = 36; // 16 bytes hex-encoded with dashes (8-4-4-4-12)
pub const token_len = 64; // 32 bytes hex-encoded
pub const key_len = 64; // 32 bytes hex-encoded
pub const sig_len = 128; // 64 bytes hex-encoded
pub const compound_token_len = uuid_len + 1 + token_len; // "uuid:token" = 101

// --- Helpers ---

pub fn generateUuid(io: Io) [uuid_len]u8 {
    var bytes: [16]u8 = undefined;
    io.random(&bytes);
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

pub fn generateToken(io: Io) [token_len]u8 {
    var bytes: [32]u8 = undefined;
    io.random(&bytes);
    return hexEncode(32, &bytes);
}

/// Create a compound token: "<account_id>:<random_hex>"
pub fn makeCompoundToken(account_id: *const [uuid_len]u8, io: Io) [compound_token_len]u8 {
    var out: [compound_token_len]u8 = undefined;
    @memcpy(out[0..uuid_len], account_id);
    out[uuid_len] = ':';
    const token = generateToken(io);
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

// --- Base64url ---

const b64url = std.base64.url_safe_no_pad;

fn base64urlEncodeAlloc(allocator: Allocator, data: []const u8) ![]const u8 {
    const len = b64url.Encoder.calcSize(data.len);
    const buf = try allocator.alloc(u8, len);
    return b64url.Encoder.encode(buf, data);
}

// --- JWT (EdDSA / Ed25519) ---

// Pre-encoded: {"alg":"EdDSA","typ":"JWT"}
const jwt_header_b64 = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9";

pub fn createJwt(
    allocator: Allocator,
    key_pair: Ed25519.KeyPair,
    issuer: []const u8,
    subject: *const [uuid_len]u8,
    iat: i64,
    exp: i64,
) ![]const u8 {
    // Build payload JSON
    var payload_buf: [512]u8 = undefined;
    const payload_json = std.fmt.bufPrint(&payload_buf,
        \\{{"iss":"{s}","sub":"{s}","iat":{d},"exp":{d}}}
    , .{ issuer, subject, iat, exp }) catch return error.PayloadTooLarge;

    // Base64url encode payload
    const payload_b64 = try base64urlEncodeAlloc(allocator, payload_json);
    defer allocator.free(payload_b64);

    // Build signing input: header.payload
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ jwt_header_b64, payload_b64 });
    defer allocator.free(signing_input);

    // Sign
    const sig = try key_pair.sign(signing_input, null);
    const sig_b64 = try base64urlEncodeAlloc(allocator, &sig.toBytes());
    defer allocator.free(sig_b64);

    // Build JWT: header.payload.signature
    return try std.fmt.allocPrint(allocator, "{s}.{s}", .{ signing_input, sig_b64 });
}

pub const JwtClaims = struct {
    sub: []const u8,
    iss: []const u8,
    iat: i64,
    exp: i64,
};

pub const JwtParseResult = struct {
    claims: std.json.Parsed(JwtClaims),

    pub fn deinit(self: *JwtParseResult) void {
        self.claims.deinit();
    }
};

/// Verify a JWT signature and extract claims. Caller must call deinit() on result.
pub fn verifyJwt(
    allocator: Allocator,
    public_key: Ed25519.PublicKey,
    token: []const u8,
    io: Io,
) !JwtParseResult {
    // Split into header.payload.signature
    const first_dot = std.mem.indexOfScalar(u8, token, '.') orelse return error.InvalidJwt;
    const rest = token[first_dot + 1 ..];
    const second_dot = std.mem.indexOfScalar(u8, rest, '.') orelse return error.InvalidJwt;

    const signing_input = token[0 .. first_dot + 1 + second_dot];
    const sig_b64 = rest[second_dot + 1 ..];

    // Decode and verify signature
    const sig_len_decoded = b64url.Decoder.calcSizeForSlice(sig_b64) catch return error.InvalidJwt;
    if (sig_len_decoded != 64) return error.InvalidJwt;
    var sig_bytes: [64]u8 = undefined;
    b64url.Decoder.decode(&sig_bytes, sig_b64) catch return error.InvalidJwt;

    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    sig.verify(signing_input, public_key) catch return error.InvalidSignature;

    // Decode payload
    const payload_b64 = rest[0..second_dot];
    const payload_len = b64url.Decoder.calcSizeForSlice(payload_b64) catch return error.InvalidJwt;
    const payload_data = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload_data);
    b64url.Decoder.decode(payload_data, payload_b64) catch return error.InvalidJwt;

    // Parse claims (.alloc_always so strings are arena-owned, not referencing payload_data)
    const parsed = std.json.parseFromSlice(JwtClaims, allocator, payload_data, .{
        .allocate = .alloc_always,
    }) catch return error.InvalidJwt;
    errdefer parsed.deinit();

    // Check expiry
    const now: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    if (parsed.value.exp <= now) return error.TokenExpired;

    return .{
        .claims = parsed,
    };
}

/// Generate JWKS JSON for the public key.
pub fn jwksJson(allocator: Allocator, public_key: Ed25519.PublicKey) ![]const u8 {
    const x_b64 = try base64urlEncodeAlloc(allocator, &public_key.bytes);
    defer allocator.free(x_b64);

    return try std.fmt.allocPrint(allocator,
        \\{{"keys":[{{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","x":"{s}"}}]}}
    , .{x_b64});
}

// --- Tests ---

test "generateUuid returns valid dashed hex" {
    const uuid = generateUuid(std.testing.io);
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
    const account_id = generateUuid(std.testing.io);
    const compound = makeCompoundToken(&account_id, std.testing.io);
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
    try std.testing.expect(parseCompoundToken(&bad) == null);
}

test "createJwt and verifyJwt roundtrip" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const kp = Ed25519.KeyPair.generate(io);
    const account_id = generateUuid(io);
    const now: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));

    const jwt = try createJwt(allocator, kp, "https://auth.example.com", &account_id, now, now + 3600);
    defer allocator.free(jwt);

    // Should have 3 dot-separated parts
    var dots: usize = 0;
    for (jwt) |c| {
        if (c == '.') dots += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), dots);

    // Verify
    var result = try verifyJwt(allocator, kp.public_key, jwt, io);
    defer result.deinit();

    try std.testing.expectEqualStrings(&account_id, result.claims.value.sub);
    try std.testing.expectEqualStrings("https://auth.example.com", result.claims.value.iss);
    try std.testing.expectEqual(now, result.claims.value.iat);
    try std.testing.expectEqual(now + 3600, result.claims.value.exp);
}

test "verifyJwt rejects wrong key" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const kp = Ed25519.KeyPair.generate(io);
    const bad_kp = Ed25519.KeyPair.generate(io);
    const account_id = generateUuid(io);
    const now: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));

    const jwt = try createJwt(allocator, kp, "https://auth.example.com", &account_id, now, now + 3600);
    defer allocator.free(jwt);

    const result = verifyJwt(allocator, bad_kp.public_key, jwt, io);
    try std.testing.expectError(error.InvalidSignature, result);
}

test "verifyJwt rejects expired token" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const kp = Ed25519.KeyPair.generate(io);
    const account_id = generateUuid(io);
    const now: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));

    const jwt = try createJwt(allocator, kp, "https://auth.example.com", &account_id, now - 7200, now - 3600);
    defer allocator.free(jwt);

    const result = verifyJwt(allocator, kp.public_key, jwt, io);
    try std.testing.expectError(error.TokenExpired, result);
}

test "jwksJson produces valid JSON" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const kp = Ed25519.KeyPair.generate(io);

    const json = try jwksJson(allocator, kp.public_key);
    defer allocator.free(json);

    // Should contain expected fields
    try std.testing.expect(std.mem.indexOf(u8, json, "\"kty\":\"OKP\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"crv\":\"Ed25519\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"alg\":\"EdDSA\"") != null);
}
