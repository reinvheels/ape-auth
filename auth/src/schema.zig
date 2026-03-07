const std = @import("std");
const crypto = @import("crypto.zig");
const Allocator = std.mem.Allocator;

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

pub fn serialize(allocator: Allocator, data: AccountData) ![]const u8 {
    return try std.json.Stringify.valueAlloc(allocator, data, .{});
}

pub fn parse(allocator: Allocator, data: []const u8) !std.json.Parsed(AccountData) {
    return try std.json.parseFromSlice(AccountData, allocator, data, .{});
}

// --- Tests ---

test "serialize and parse roundtrip" {
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
        .token = "a" ** crypto.token_len,
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

    const json_str = try serialize(allocator, data);
    defer allocator.free(json_str);

    const parsed = try parse(allocator, json_str);
    defer parsed.deinit();

    try std.testing.expectEqualStrings(account_id, parsed.value.account.id);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.devices.len);
    try std.testing.expectEqualStrings("my device", parsed.value.devices[0].name);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.sessions.len);
}
