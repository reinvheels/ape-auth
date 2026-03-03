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

/// Build a complete HTTP response into the provided buffer.
/// Returns the slice of the buffer that was written.
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

// --- Backup Serialization ---

pub const BackupData = struct {
    accounts: []const BackupAccount,
    devices: []const BackupDevice,
    sessions: []const BackupSession,
    refresh_tokens: []const BackupRefreshToken,
};

pub const BackupAccount = struct {
    id: []const u8,
    created_at: i64,
};

pub const BackupDevice = struct {
    id: []const u8,
    account_id: []const u8,
    public_key: []const u8,
    name: []const u8,
    created_at: i64,
};

pub const BackupSession = struct {
    token: []const u8,
    account_id: []const u8,
    device_id: []const u8,
    expires_at: i64,
};

pub const BackupRefreshToken = struct {
    token: []const u8,
    account_id: []const u8,
    device_id: []const u8,
    expires_at: i64,
};

pub fn serializeStore(allocator: Allocator, store: *Store) ![]const u8 {
    var accounts_list = std.ArrayListUnmanaged(BackupAccount){};
    defer accounts_list.deinit(allocator);
    var devices_list = std.ArrayListUnmanaged(BackupDevice){};
    defer devices_list.deinit(allocator);
    var sessions_list = std.ArrayListUnmanaged(BackupSession){};
    defer sessions_list.deinit(allocator);
    var rt_list = std.ArrayListUnmanaged(BackupRefreshToken){};
    defer rt_list.deinit(allocator);

    // Temp storage for hex-encoded public keys
    var pk_strs = std.ArrayListUnmanaged([]const u8){};
    defer {
        for (pk_strs.items) |s| allocator.free(s);
        pk_strs.deinit(allocator);
    }

    // Collect accounts
    {
        var it = store.accounts.valueIterator();
        while (it.next()) |acc| {
            try accounts_list.append(allocator, .{ .id = &acc.id, .created_at = acc.created_at });
        }
    }

    // Collect devices
    {
        var it = store.devices.valueIterator();
        while (it.next()) |dev| {
            const pk_hex = Store.hexEncode(32, &dev.public_key);
            const pk_str = try allocator.dupe(u8, &pk_hex);
            try pk_strs.append(allocator, pk_str);
            try devices_list.append(allocator, .{
                .id = &dev.id,
                .account_id = &dev.account_id,
                .public_key = pk_str,
                .name = dev.name,
                .created_at = dev.created_at,
            });
        }
    }

    // Collect sessions
    {
        var it = store.sessions.valueIterator();
        while (it.next()) |sess| {
            try sessions_list.append(allocator, .{
                .token = &sess.token,
                .account_id = &sess.account_id,
                .device_id = &sess.device_id,
                .expires_at = sess.expires_at,
            });
        }
    }

    // Collect refresh tokens
    {
        var it = store.refresh_tokens.valueIterator();
        while (it.next()) |rt| {
            try rt_list.append(allocator, .{
                .token = &rt.token,
                .account_id = &rt.account_id,
                .device_id = &rt.device_id,
                .expires_at = rt.expires_at,
            });
        }
    }

    const backup_data = BackupData{
        .accounts = accounts_list.items,
        .devices = devices_list.items,
        .sessions = sessions_list.items,
        .refresh_tokens = rt_list.items,
    };

    return try std.json.Stringify.valueAlloc(allocator, backup_data, .{});
}

pub fn deserializeStore(allocator: Allocator, store: *Store, data: []const u8) !void {
    const parsed = try std.json.parseFromSlice(BackupData, allocator, data, .{});
    defer parsed.deinit();

    for (parsed.value.accounts) |acc| {
        if (acc.id.len != Store.uuid_len) continue;
        var account = Store.Account{
            .id = undefined,
            .created_at = acc.created_at,
        };
        @memcpy(&account.id, acc.id[0..Store.uuid_len]);
        try store.putAccount(account);
    }

    for (parsed.value.devices) |dev| {
        if (dev.id.len != Store.uuid_len) continue;
        if (dev.account_id.len != Store.uuid_len) continue;
        if (dev.public_key.len != Store.key_len) continue;

        const pk_bytes = Store.hexDecode(32, dev.public_key[0..Store.key_len]) catch continue;
        const name = try allocator.dupe(u8, dev.name);

        var device = Store.Device{
            .id = undefined,
            .account_id = undefined,
            .public_key = pk_bytes,
            .name = name,
            .created_at = dev.created_at,
        };
        @memcpy(&device.id, dev.id[0..Store.uuid_len]);
        @memcpy(&device.account_id, dev.account_id[0..Store.uuid_len]);
        try store.putDevice(device);
    }

    const now = Store.timestamp();

    for (parsed.value.sessions) |sess| {
        if (sess.expires_at <= now) continue;
        if (sess.token.len != Store.token_len) continue;
        if (sess.account_id.len != Store.uuid_len) continue;
        if (sess.device_id.len != Store.uuid_len) continue;

        var session = Store.Session{
            .token = undefined,
            .account_id = undefined,
            .device_id = undefined,
            .expires_at = sess.expires_at,
        };
        @memcpy(&session.token, sess.token[0..Store.token_len]);
        @memcpy(&session.account_id, sess.account_id[0..Store.uuid_len]);
        @memcpy(&session.device_id, sess.device_id[0..Store.uuid_len]);
        try store.putSession(session);
    }

    for (parsed.value.refresh_tokens) |rt| {
        if (rt.expires_at <= now) continue;
        if (rt.token.len != Store.token_len) continue;
        if (rt.account_id.len != Store.uuid_len) continue;
        if (rt.device_id.len != Store.uuid_len) continue;

        var refresh = Store.RefreshToken{
            .token = undefined,
            .account_id = undefined,
            .device_id = undefined,
            .expires_at = rt.expires_at,
        };
        @memcpy(&refresh.token, rt.token[0..Store.token_len]);
        @memcpy(&refresh.account_id, rt.account_id[0..Store.uuid_len]);
        @memcpy(&refresh.device_id, rt.device_id[0..Store.uuid_len]);
        try store.putRefreshToken(refresh);
    }
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

test "serialize and deserialize store roundtrip" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const account_id = Store.generateUuid();
    try store.putAccount(.{ .id = account_id, .created_at = Store.timestamp() });

    var pk: [32]u8 = undefined;
    std.crypto.random.bytes(&pk);
    const device_id = Store.generateUuid();
    const name = try std.testing.allocator.dupe(u8, "my device");
    try store.putDevice(.{
        .id = device_id,
        .account_id = account_id,
        .public_key = pk,
        .name = name,
        .created_at = Store.timestamp(),
    });

    const json_data = try serializeStore(std.testing.allocator, &store);
    defer std.testing.allocator.free(json_data);

    var store2 = Store.init(std.testing.allocator);
    defer store2.deinit();

    try deserializeStore(std.testing.allocator, &store2, json_data);

    try std.testing.expect(store2.accounts.get(&account_id) != null);
    try std.testing.expect(store2.devices.get(&device_id) != null);
}
