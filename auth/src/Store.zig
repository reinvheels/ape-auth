const std = @import("std");
const Allocator = std.mem.Allocator;

const Store = @This();

pub const uuid_len = 36; // 16 bytes hex-encoded with dashes (8-4-4-4-12)
pub const token_len = 64; // 32 bytes hex-encoded
pub const key_len = 64; // 32 bytes hex-encoded
pub const sig_len = 128; // 64 bytes hex-encoded

pub const Account = struct {
    id: [uuid_len]u8,
    created_at: i64,
};

pub const Device = struct {
    id: [uuid_len]u8,
    account_id: [uuid_len]u8,
    public_key: [32]u8,
    name: []const u8,
    created_at: i64,
};

pub const Session = struct {
    token: [token_len]u8,
    account_id: [uuid_len]u8,
    device_id: [uuid_len]u8,
    expires_at: i64,
};

pub const RefreshToken = struct {
    token: [token_len]u8,
    account_id: [uuid_len]u8,
    device_id: [uuid_len]u8,
    expires_at: i64,
};

pub const Challenge = struct {
    nonce: [32]u8,
    device_id: [uuid_len]u8,
    expires_at: i64,
};

mutex: std.Thread.Mutex = .{},
allocator: Allocator,
base_dir: ?[]const u8 = null,
accounts: std.StringHashMapUnmanaged(Account) = .{},
devices: std.StringHashMapUnmanaged(Device) = .{},
// devices indexed by hex-encoded public key -> device id
devices_by_key: std.StringHashMapUnmanaged([uuid_len]u8) = .{},
// devices indexed by account_id -> list of device ids
devices_by_account: std.StringHashMapUnmanaged(std.ArrayListUnmanaged([uuid_len]u8)) = .{},
sessions: std.StringHashMapUnmanaged(Session) = .{},
refresh_tokens: std.StringHashMapUnmanaged(RefreshToken) = .{},
challenges: std.StringHashMapUnmanaged(Challenge) = .{},

pub fn init(allocator: Allocator) Store {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *Store) void {
    // Free device names and keys
    {
        var it = self.devices.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.name);
            self.allocator.free(entry.key_ptr.*);
        }
    }
    // Free devices_by_account lists and keys
    {
        var it = self.devices_by_account.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
    }
    // Free keys for all other maps
    freeKeys(&self.accounts, self.allocator);
    freeKeys(&self.devices_by_key, self.allocator);
    freeKeys(&self.sessions, self.allocator);
    freeKeys(&self.refresh_tokens, self.allocator);
    freeKeys(&self.challenges, self.allocator);

    self.accounts.deinit(self.allocator);
    self.devices.deinit(self.allocator);
    self.devices_by_key.deinit(self.allocator);
    self.devices_by_account.deinit(self.allocator);
    self.sessions.deinit(self.allocator);
    self.refresh_tokens.deinit(self.allocator);
    self.challenges.deinit(self.allocator);
}

fn freeKeys(map: anytype, allocator: Allocator) void {
    var it = map.keyIterator();
    while (it.next()) |key| {
        allocator.free(key.*);
    }
}

pub fn lock(self: *Store) void {
    self.mutex.lock();
}

pub fn unlock(self: *Store) void {
    self.mutex.unlock();
}

// --- Helpers ---

pub fn generateUuid() [uuid_len]u8 {
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    const hex = hexEncode(16, &bytes);
    // Format as xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
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

// --- Store Operations (caller must hold lock) ---

pub fn putAccount(self: *Store, account: Account) !void {
    const key = try self.allocator.dupe(u8, &account.id);
    errdefer self.allocator.free(key);
    try self.accounts.put(self.allocator, key, account);
}

pub fn putDevice(self: *Store, device: Device) !void {
    const key = try self.allocator.dupe(u8, &device.id);
    errdefer self.allocator.free(key);
    try self.devices.put(self.allocator, key, device);

    // Index by public key
    const pk_hex = hexEncode(32, &device.public_key);
    const pk_key = try self.allocator.dupe(u8, &pk_hex);
    errdefer self.allocator.free(pk_key);
    try self.devices_by_key.put(self.allocator, pk_key, device.id);

    // Index by account
    const acc_key = try self.allocator.dupe(u8, &device.account_id);
    const gop = try self.devices_by_account.getOrPut(self.allocator, acc_key);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{};
    } else {
        self.allocator.free(acc_key);
    }
    try gop.value_ptr.append(self.allocator, device.id);
}

pub fn getDeviceByPublicKey(self: *Store, public_key_hex: []const u8) ?*Device {
    const device_id = self.devices_by_key.get(public_key_hex) orelse return null;
    return self.devices.getPtr(&device_id);
}

pub fn getDevicesByAccount(self: *Store, account_id: []const u8) ?[]const [uuid_len]u8 {
    const list = self.devices_by_account.getPtr(account_id) orelse return null;
    return list.items;
}

pub fn removeDevice(self: *Store, device_id: *const [uuid_len]u8) !void {
    const dev = self.devices.get(device_id) orelse return;

    // Remove from devices_by_key
    const pk_hex = hexEncode(32, &dev.public_key);
    if (self.devices_by_key.fetchRemove(&pk_hex)) |kv| {
        self.allocator.free(kv.key);
    }

    // Remove from devices_by_account
    if (self.devices_by_account.getPtr(&dev.account_id)) |list| {
        var i: usize = 0;
        while (i < list.items.len) {
            if (std.mem.eql(u8, &list.items[i], device_id)) {
                _ = list.swapRemove(i);
                break;
            }
            i += 1;
        }
    }

    // Free name and remove from devices map
    self.allocator.free(dev.name);
    if (self.devices.fetchRemove(device_id)) |kv| {
        self.allocator.free(kv.key);
    }
}

pub fn putSession(self: *Store, session: Session) !void {
    const key = try self.allocator.dupe(u8, &session.token);
    errdefer self.allocator.free(key);
    try self.sessions.put(self.allocator, key, session);
}

pub fn getSession(self: *Store, token: []const u8) ?*Session {
    return self.sessions.getPtr(token);
}

pub fn removeSession(self: *Store, token: []const u8) void {
    if (self.sessions.fetchRemove(token)) |kv| {
        self.allocator.free(kv.key);
    }
}

pub fn putRefreshToken(self: *Store, rt: RefreshToken) !void {
    const key = try self.allocator.dupe(u8, &rt.token);
    errdefer self.allocator.free(key);
    try self.refresh_tokens.put(self.allocator, key, rt);
}

pub fn getRefreshToken(self: *Store, token: []const u8) ?*RefreshToken {
    return self.refresh_tokens.getPtr(token);
}

pub fn removeRefreshToken(self: *Store, token: []const u8) void {
    if (self.refresh_tokens.fetchRemove(token)) |kv| {
        self.allocator.free(kv.key);
    }
}

pub fn putChallenge(self: *Store, nonce_hex: [token_len]u8, challenge: Challenge) !void {
    const key = try self.allocator.dupe(u8, &nonce_hex);
    errdefer self.allocator.free(key);
    try self.challenges.put(self.allocator, key, challenge);
}

pub fn getChallenge(self: *Store, nonce_hex: []const u8) ?*Challenge {
    return self.challenges.getPtr(nonce_hex);
}

pub fn removeChallenge(self: *Store, nonce_hex: []const u8) void {
    if (self.challenges.fetchRemove(nonce_hex)) |kv| {
        self.allocator.free(kv.key);
    }
}

// --- Tests ---

test "generateUuid returns valid dashed hex" {
    const uuid = generateUuid();
    // Verify dash positions: 8-4-4-4-12
    try std.testing.expectEqual(@as(u8, '-'), uuid[8]);
    try std.testing.expectEqual(@as(u8, '-'), uuid[13]);
    try std.testing.expectEqual(@as(u8, '-'), uuid[18]);
    try std.testing.expectEqual(@as(u8, '-'), uuid[23]);
    // Verify hex chars everywhere else
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

test "store put and get account" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const id = generateUuid();
    const account = Account{ .id = id, .created_at = timestamp() };
    try store.putAccount(account);

    const got = store.accounts.get(&id);
    try std.testing.expect(got != null);
    try std.testing.expectEqualSlices(u8, &id, &got.?.id);
}

test "store device indexing by public key" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    var pk: [32]u8 = undefined;
    std.crypto.random.bytes(&pk);
    const device_id = generateUuid();
    const account_id = generateUuid();
    const name = try std.testing.allocator.dupe(u8, "test device");

    const device = Device{
        .id = device_id,
        .account_id = account_id,
        .public_key = pk,
        .name = name,
        .created_at = timestamp(),
    };
    try store.putDevice(device);

    const pk_hex = hexEncode(32, &pk);
    const got = store.getDeviceByPublicKey(&pk_hex);
    try std.testing.expect(got != null);
    try std.testing.expectEqualSlices(u8, &device_id, &got.?.id);
}
