const std = @import("std");
const Store = @import("Store.zig");
const Allocator = std.mem.Allocator;

// --- Request Parsing ---

pub const RegisterRequest = struct {
    public_key: []const u8,
    device_name: []const u8,
};

pub const ChallengeRequest = struct {
    public_key: []const u8,
};

pub const LoginRequest = struct {
    public_key: []const u8,
    challenge: []const u8,
    signature: []const u8,
};

pub const RefreshRequest = struct {
    refresh_token: []const u8,
};

pub const LinkDeviceRequest = struct {
    public_key: []const u8,
    device_name: []const u8,
};

pub const UnlinkDeviceRequest = struct {
    device_id: []const u8,
};

pub fn parseRegisterRequest(body: []const u8) !RegisterRequest {
    const parsed = try std.json.parseFromSlice(struct {
        public_key: []const u8,
        device_name: []const u8,
    }, std.heap.page_allocator, body, .{});
    return .{
        .public_key = parsed.value.public_key,
        .device_name = parsed.value.device_name,
    };
}

pub fn parseChallengeRequest(body: []const u8) !ChallengeRequest {
    const parsed = try std.json.parseFromSlice(struct {
        public_key: []const u8,
    }, std.heap.page_allocator, body, .{});
    return .{ .public_key = parsed.value.public_key };
}

pub fn parseLoginRequest(body: []const u8) !LoginRequest {
    const parsed = try std.json.parseFromSlice(struct {
        public_key: []const u8,
        challenge: []const u8,
        signature: []const u8,
    }, std.heap.page_allocator, body, .{});
    return .{
        .public_key = parsed.value.public_key,
        .challenge = parsed.value.challenge,
        .signature = parsed.value.signature,
    };
}

pub fn parseRefreshRequest(body: []const u8) !RefreshRequest {
    const parsed = try std.json.parseFromSlice(struct {
        refresh_token: []const u8,
    }, std.heap.page_allocator, body, .{});
    return .{ .refresh_token = parsed.value.refresh_token };
}

pub fn parseLinkDeviceRequest(body: []const u8) !LinkDeviceRequest {
    const parsed = try std.json.parseFromSlice(struct {
        public_key: []const u8,
        device_name: []const u8,
    }, std.heap.page_allocator, body, .{});
    return .{
        .public_key = parsed.value.public_key,
        .device_name = parsed.value.device_name,
    };
}

pub fn parseUnlinkDeviceRequest(body: []const u8) !UnlinkDeviceRequest {
    const parsed = try std.json.parseFromSlice(struct {
        device_id: []const u8,
    }, std.heap.page_allocator, body, .{});
    return .{ .device_id = parsed.value.device_id };
}

// --- Response Building ---

pub fn buildResponse(buf: []u8, status: std.http.Status, body: []const u8) []const u8 {
    const status_str = statusString(status);
    return std.fmt.bufPrint(buf, "HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status_str, body.len, body }) catch "";
}

pub fn buildErrorBody(buf: []u8, message: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "{{\"error\":\"{s}\"}}", .{message}) catch "{\"error\":\"internal error\"}";
}

fn statusString(status: std.http.Status) []const u8 {
    return switch (status) {
        .ok => "200 OK",
        .bad_request => "400 Bad Request",
        .unauthorized => "401 Unauthorized",
        .not_found => "404 Not Found",
        .conflict => "409 Conflict",
        .internal_server_error => "500 Internal Server Error",
        else => "500 Internal Server Error",
    };
}

// --- Per-Account Serialization ---

pub const AccountData = struct {
    account: AccountJson,
    devices: []const DeviceJson,
    sessions: []const SessionJson,
    refresh_tokens: []const RefreshTokenJson,
    challenges: []const ChallengeJson = &.{},
};

pub const AccountJson = struct {
    id: []const u8,
    created_at: i64,
};

pub const DeviceJson = struct {
    id: []const u8,
    account_id: []const u8,
    public_key: []const u8,
    name: []const u8,
    created_at: i64,
};

pub const SessionJson = struct {
    token: []const u8,
    device_id: []const u8,
    expires_at: i64,
};

pub const RefreshTokenJson = struct {
    token: []const u8,
    device_id: []const u8,
    expires_at: i64,
};

pub const ChallengeJson = struct {
    nonce: []const u8,
    device_id: []const u8,
    expires_at: i64,
};

/// Serialize AccountData to JSON.
pub fn serializeAccountData(allocator: Allocator, data: AccountData) ![]const u8 {
    return try std.json.Stringify.valueAlloc(allocator, data, .{});
}

/// Parse JSON into AccountData.
pub fn parseAccountData(allocator: Allocator, data: []const u8) !std.json.Parsed(AccountData) {
    return try std.json.parseFromSlice(AccountData, allocator, data, .{});
}

// --- Tests ---

test "parse register request" {
    const body =
        \\{"public_key":"aabb","device_name":"test"}
    ;
    const req = try parseRegisterRequest(body);
    try std.testing.expectEqualStrings("aabb", req.public_key);
    try std.testing.expectEqualStrings("test", req.device_name);
}

test "serializeAccountData and parseAccountData roundtrip" {
    const allocator = std.testing.allocator;

    const account_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    const device_id = "d1d2d3d4-d5d6-d7d8-d9da-dbdcdddedfee";
    const pk_hex = "deadbeef" ++ "deadbeef" ++ "deadbeef" ++ "deadbeef" ++ "deadbeef" ++ "deadbeef" ++ "deadbeef" ++ "deadbeef";

    const devices = [_]DeviceJson{.{
        .id = device_id,
        .account_id = account_id,
        .public_key = pk_hex,
        .name = "my device",
        .created_at = 1000,
    }};
    const sessions = [_]SessionJson{.{
        .token = "a" ** Store.token_len,
        .device_id = device_id,
        .expires_at = 9999999999,
    }};

    const data = AccountData{
        .account = .{ .id = account_id, .created_at = 1000 },
        .devices = &devices,
        .sessions = &sessions,
        .refresh_tokens = &.{},
        .challenges = &.{},
    };

    const json_str = try serializeAccountData(allocator, data);
    defer allocator.free(json_str);

    const parsed = try parseAccountData(allocator, json_str);
    defer parsed.deinit();

    try std.testing.expectEqualStrings(account_id, parsed.value.account.id);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.devices.len);
    try std.testing.expectEqualStrings("my device", parsed.value.devices[0].name);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.sessions.len);
}
