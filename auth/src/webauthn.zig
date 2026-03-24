const std = @import("std");
const cbor = @import("cbor.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Error = error{
    InvalidClientData,
    InvalidAttestation,
    InvalidAssertion,
    ChallengeMismatch,
    OriginMismatch,
    RpIdMismatch,
    InvalidSignature,
    UnsupportedAlgorithm,
    UserNotPresent,
};

pub const AttestationResult = struct {
    credential_id: []const u8, // slice into attestation_object
    public_key: [65]u8, // uncompressed P-256 SEC1: 0x04 || x || y
    sign_count: u32,
};

pub const AssertionResult = struct {
    sign_count: u32,
};

// --- Attestation (registration) ---

pub fn verifyAttestation(
    client_data_json: []const u8,
    attestation_object: []const u8,
    expected_challenge_b64: []const u8,
    expected_origin: []const u8,
    expected_rp_id: []const u8,
) Error!AttestationResult {
    // 1. Verify clientDataJSON
    try verifyClientData(client_data_json, "webauthn.create", expected_challenge_b64, expected_origin);

    // 2. Parse attestation object (CBOR map with text keys)
    var reader = cbor.Reader.init(attestation_object);
    const map_len = reader.readMapLen() catch return Error.InvalidAttestation;

    var auth_data: ?[]const u8 = null;
    for (0..map_len) |_| {
        const key = reader.readTextString() catch return Error.InvalidAttestation;
        if (std.mem.eql(u8, key, "authData")) {
            auth_data = reader.readByteString() catch return Error.InvalidAttestation;
        } else {
            reader.skipValue() catch return Error.InvalidAttestation;
        }
    }

    const ad = auth_data orelse return Error.InvalidAttestation;

    // 3. Parse authenticator data
    const parsed = parseAuthData(ad) catch return Error.InvalidAttestation;

    // 4. Verify RP ID hash
    var expected_hash: [32]u8 = undefined;
    Sha256.hash(expected_rp_id, &expected_hash, .{});
    if (!std.mem.eql(u8, parsed.rp_id_hash, &expected_hash)) return Error.RpIdMismatch;

    // 5. Verify user present flag
    if (parsed.flags & 0x01 == 0) return Error.UserNotPresent;

    // 6. Attested credential data must be present (flag bit 6)
    if (parsed.flags & 0x40 == 0) return Error.InvalidAttestation;

    const rest = parsed.rest;
    // aaguid (16) + credIdLen (2) + at least 1 byte credential ID
    if (rest.len < 19) return Error.InvalidAttestation;

    const cred_id_len = std.mem.readInt(u16, rest[16..18], .big);
    if (rest.len < 18 + cred_id_len) return Error.InvalidAttestation;

    const credential_id = rest[18 .. 18 + cred_id_len];
    const cose_key_data = rest[18 + cred_id_len ..];

    // 7. Parse COSE public key
    const public_key = parseCoseP256Key(cose_key_data) catch return Error.InvalidAttestation;

    return .{
        .credential_id = credential_id,
        .public_key = public_key,
        .sign_count = parsed.sign_count,
    };
}

// --- Assertion (login) ---

pub fn verifyAssertion(
    client_data_json: []const u8,
    authenticator_data: []const u8,
    signature_der: []const u8,
    expected_challenge_b64: []const u8,
    expected_origin: []const u8,
    expected_rp_id: []const u8,
    stored_public_key: *const [65]u8,
) Error!AssertionResult {
    // 1. Verify clientDataJSON
    try verifyClientData(client_data_json, "webauthn.get", expected_challenge_b64, expected_origin);

    // 2. Parse authenticator data
    const parsed = parseAuthData(authenticator_data) catch return Error.InvalidAssertion;

    // 3. Verify RP ID hash
    var expected_hash: [32]u8 = undefined;
    Sha256.hash(expected_rp_id, &expected_hash, .{});
    if (!std.mem.eql(u8, parsed.rp_id_hash, &expected_hash)) return Error.RpIdMismatch;

    // 4. Verify user present
    if (parsed.flags & 0x01 == 0) return Error.UserNotPresent;

    // 5. Build verification message: authenticatorData || SHA-256(clientDataJSON)
    // ECDSA-P256-SHA256 will hash this message internally with SHA-256
    var msg_buf: [4096]u8 = undefined;
    if (authenticator_data.len + 32 > msg_buf.len) return Error.InvalidAssertion;
    @memcpy(msg_buf[0..authenticator_data.len], authenticator_data);
    var client_data_hash: [32]u8 = undefined;
    Sha256.hash(client_data_json, &client_data_hash, .{});
    @memcpy(msg_buf[authenticator_data.len .. authenticator_data.len + 32], &client_data_hash);
    const message = msg_buf[0 .. authenticator_data.len + 32];

    // 6. Verify ECDSA-P256-SHA256 signature
    const pk = EcdsaP256.PublicKey.fromSec1(stored_public_key) catch return Error.InvalidSignature;
    const sig = EcdsaP256.Signature.fromDer(signature_der) catch return Error.InvalidSignature;
    sig.verify(message, pk) catch return Error.InvalidSignature;

    return .{
        .sign_count = parsed.sign_count,
    };
}

// --- Internals ---

const AuthDataHeader = struct {
    rp_id_hash: *const [32]u8,
    flags: u8,
    sign_count: u32,
    rest: []const u8,
};

fn parseAuthData(auth_data: []const u8) !AuthDataHeader {
    if (auth_data.len < 37) return error.InvalidAttestation;
    return .{
        .rp_id_hash = auth_data[0..32],
        .flags = auth_data[32],
        .sign_count = std.mem.readInt(u32, auth_data[33..37], .big),
        .rest = auth_data[37..],
    };
}

const ClientData = struct {
    type: []const u8,
    challenge: []const u8,
    origin: []const u8,
};

fn verifyClientData(
    client_data_json: []const u8,
    expected_type: []const u8,
    expected_challenge_b64: []const u8,
    expected_origin: []const u8,
) Error!void {
    var parsed = std.json.parseFromSlice(ClientData, std.heap.page_allocator, client_data_json, .{
        .ignore_unknown_fields = true,
    }) catch return Error.InvalidClientData;
    defer parsed.deinit();

    if (!std.mem.eql(u8, parsed.value.type, expected_type)) return Error.InvalidClientData;
    if (!std.mem.eql(u8, parsed.value.challenge, expected_challenge_b64)) return Error.ChallengeMismatch;
    if (!std.mem.eql(u8, parsed.value.origin, expected_origin)) return Error.OriginMismatch;
}

fn parseCoseP256Key(data: []const u8) ![65]u8 {
    var reader = cbor.Reader.init(data);
    const map_len = reader.readMapLen() catch return error.InvalidAttestation;

    var x: ?[]const u8 = null;
    var y: ?[]const u8 = null;
    var kty: ?i64 = null;
    var alg: ?i64 = null;

    for (0..map_len) |_| {
        const key = reader.readInt() catch return error.InvalidAttestation;
        switch (key) {
            1 => kty = reader.readInt() catch return error.InvalidAttestation, // kty
            3 => alg = reader.readInt() catch return error.InvalidAttestation, // alg
            -2 => x = reader.readByteString() catch return error.InvalidAttestation, // x
            -3 => y = reader.readByteString() catch return error.InvalidAttestation, // y
            else => reader.skipValue() catch return error.InvalidAttestation,
        }
    }

    // kty=2 (EC2), alg=-7 (ES256)
    if ((kty orelse return error.UnsupportedAlgorithm) != 2) return error.UnsupportedAlgorithm;
    if ((alg orelse return error.UnsupportedAlgorithm) != -7) return error.UnsupportedAlgorithm;

    const x_val = x orelse return error.InvalidAttestation;
    const y_val = y orelse return error.InvalidAttestation;
    if (x_val.len != 32 or y_val.len != 32) return error.InvalidAttestation;

    // Uncompressed SEC1 point: 0x04 || x || y
    var result: [65]u8 = undefined;
    result[0] = 0x04;
    @memcpy(result[1..33], x_val);
    @memcpy(result[33..65], y_val);
    return result;
}

// --- Tests ---

test "verifyClientData accepts valid data" {
    const json =
        \\{"type":"webauthn.create","challenge":"dGVzdC1jaGFsbGVuZ2U","origin":"https://auth.example.com","crossOrigin":false}
    ;
    try verifyClientData(json, "webauthn.create", "dGVzdC1jaGFsbGVuZ2U", "https://auth.example.com");
}

test "verifyClientData rejects wrong type" {
    const json =
        \\{"type":"webauthn.get","challenge":"dGVzdC1jaGFsbGVuZ2U","origin":"https://auth.example.com"}
    ;
    try std.testing.expectError(Error.InvalidClientData, verifyClientData(json, "webauthn.create", "dGVzdC1jaGFsbGVuZ2U", "https://auth.example.com"));
}

test "verifyClientData rejects wrong challenge" {
    const json =
        \\{"type":"webauthn.create","challenge":"wrong","origin":"https://auth.example.com"}
    ;
    try std.testing.expectError(Error.ChallengeMismatch, verifyClientData(json, "webauthn.create", "dGVzdC1jaGFsbGVuZ2U", "https://auth.example.com"));
}

test "verifyClientData rejects wrong origin" {
    const json =
        \\{"type":"webauthn.create","challenge":"dGVzdC1jaGFsbGVuZ2U","origin":"https://evil.com"}
    ;
    try std.testing.expectError(Error.OriginMismatch, verifyClientData(json, "webauthn.create", "dGVzdC1jaGFsbGVuZ2U", "https://auth.example.com"));
}

test "parseAuthData extracts header fields" {
    // 32 bytes rpIdHash + 1 byte flags + 4 bytes signCount
    var data: [37]u8 = undefined;
    @memset(data[0..32], 0xAA); // rpIdHash
    data[32] = 0x41; // flags: UP + AT
    std.mem.writeInt(u32, data[33..37], 42, .big); // signCount

    const parsed = try parseAuthData(&data);
    try std.testing.expectEqual(@as(u8, 0x41), parsed.flags);
    try std.testing.expectEqual(@as(u32, 42), parsed.sign_count);
    try std.testing.expectEqual(@as(usize, 0), parsed.rest.len);
}

test "parseCoseP256Key extracts uncompressed point" {
    // Build a minimal COSE key map:
    // {1: 2, 3: -7, -1: 1, -2: <32 bytes x>, -3: <32 bytes y>}
    var buf: [256]u8 = undefined;
    var pos: usize = 0;

    // Map of 5 entries
    buf[pos] = 0xA5;
    pos += 1;

    // 1: 2 (kty: EC2)
    buf[pos] = 0x01;
    pos += 1;
    buf[pos] = 0x02;
    pos += 1;

    // 3: -7 (alg: ES256) — negative 7 is major=1, arg=6 → 0x26
    buf[pos] = 0x03;
    pos += 1;
    buf[pos] = 0x26;
    pos += 1;

    // -1: 1 (crv: P-256) — negative 1 is 0x20
    buf[pos] = 0x20;
    pos += 1;
    buf[pos] = 0x01;
    pos += 1;

    // -2: <32 bytes x> — negative 2 is 0x21, byte string of 32 = 0x58 0x20
    buf[pos] = 0x21;
    pos += 1;
    buf[pos] = 0x58;
    pos += 1;
    buf[pos] = 0x20;
    pos += 1;
    var x: [32]u8 = undefined;
    @memset(&x, 0x11);
    @memcpy(buf[pos .. pos + 32], &x);
    pos += 32;

    // -3: <32 bytes y> — negative 3 is 0x22
    buf[pos] = 0x22;
    pos += 1;
    buf[pos] = 0x58;
    pos += 1;
    buf[pos] = 0x20;
    pos += 1;
    var y: [32]u8 = undefined;
    @memset(&y, 0x22);
    @memcpy(buf[pos .. pos + 32], &y);
    pos += 32;

    const pk = try parseCoseP256Key(buf[0..pos]);
    try std.testing.expectEqual(@as(u8, 0x04), pk[0]);
    try std.testing.expectEqualSlices(u8, &x, pk[1..33]);
    try std.testing.expectEqualSlices(u8, &y, pk[33..65]);
}
