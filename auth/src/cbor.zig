const std = @import("std");

pub const Error = error{
    InvalidCbor,
    UnexpectedType,
    Overflow,
};

pub const Major = enum(u3) {
    unsigned = 0,
    negative = 1,
    bytes = 2,
    text = 3,
    array = 4,
    map = 5,
    tag = 6,
    simple = 7,
};

pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data, .pos = 0 };
    }

    fn next(self: *Reader) Error!u8 {
        if (self.pos >= self.data.len) return Error.InvalidCbor;
        const b = self.data[self.pos];
        self.pos += 1;
        return b;
    }

    fn advance(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.data.len) return Error.InvalidCbor;
        const result = self.data[self.pos .. self.pos + n];
        self.pos += n;
        return result;
    }

    fn readHeader(self: *Reader) Error!struct { major: Major, arg: u64 } {
        const b = try self.next();
        const major: Major = @enumFromInt(@as(u3, @truncate(b >> 5)));
        const info: u5 = @truncate(b);
        const arg: u64 = switch (info) {
            0...23 => @as(u64, info),
            24 => try self.next(),
            25 => blk: {
                const bytes = try self.advance(2);
                break :blk std.mem.readInt(u16, bytes[0..2], .big);
            },
            26 => blk: {
                const bytes = try self.advance(4);
                break :blk std.mem.readInt(u32, bytes[0..4], .big);
            },
            27 => blk: {
                const bytes = try self.advance(8);
                break :blk std.mem.readInt(u64, bytes[0..8], .big);
            },
            else => return Error.InvalidCbor,
        };
        return .{ .major = major, .arg = arg };
    }

    pub fn readUint(self: *Reader) Error!u64 {
        const header = try self.readHeader();
        if (header.major != .unsigned) return Error.UnexpectedType;
        return header.arg;
    }

    pub fn readInt(self: *Reader) Error!i64 {
        const header = try self.readHeader();
        return switch (header.major) {
            .unsigned => std.math.cast(i64, header.arg) orelse return Error.Overflow,
            .negative => blk: {
                const n = std.math.cast(i64, header.arg) orelse return Error.Overflow;
                break :blk -1 - n;
            },
            else => Error.UnexpectedType,
        };
    }

    pub fn readByteString(self: *Reader) Error![]const u8 {
        const header = try self.readHeader();
        if (header.major != .bytes) return Error.UnexpectedType;
        const len: usize = std.math.cast(usize, header.arg) orelse return Error.Overflow;
        return try self.advance(len);
    }

    pub fn readTextString(self: *Reader) Error![]const u8 {
        const header = try self.readHeader();
        if (header.major != .text) return Error.UnexpectedType;
        const len: usize = std.math.cast(usize, header.arg) orelse return Error.Overflow;
        return try self.advance(len);
    }

    pub fn readMapLen(self: *Reader) Error!usize {
        const header = try self.readHeader();
        if (header.major != .map) return Error.UnexpectedType;
        return std.math.cast(usize, header.arg) orelse return Error.Overflow;
    }

    pub fn readArrayLen(self: *Reader) Error!usize {
        const header = try self.readHeader();
        if (header.major != .array) return Error.UnexpectedType;
        return std.math.cast(usize, header.arg) orelse return Error.Overflow;
    }

    pub fn skipValue(self: *Reader) Error!void {
        const header = try self.readHeader();
        switch (header.major) {
            .unsigned, .negative, .simple => {},
            .bytes, .text => {
                const len: usize = std.math.cast(usize, header.arg) orelse return Error.Overflow;
                if (self.pos + len > self.data.len) return Error.InvalidCbor;
                self.pos += len;
            },
            .array => {
                const len: usize = std.math.cast(usize, header.arg) orelse return Error.Overflow;
                for (0..len) |_| try self.skipValue();
            },
            .map => {
                const len: usize = std.math.cast(usize, header.arg) orelse return Error.Overflow;
                for (0..len) |_| {
                    try self.skipValue();
                    try self.skipValue();
                }
            },
            .tag => try self.skipValue(),
        }
    }

    pub fn peekMajor(self: *Reader) Error!Major {
        if (self.pos >= self.data.len) return Error.InvalidCbor;
        return @enumFromInt(@as(u3, @truncate(self.data[self.pos] >> 5)));
    }
};

// --- Tests ---

test "read unsigned integers" {
    // Small value (0-23): single byte
    var r = Reader.init(&.{0x05});
    try std.testing.expectEqual(@as(u64, 5), try r.readUint());

    // 1-byte value (24): 0x18 <value>
    r = Reader.init(&.{ 0x18, 0x64 });
    try std.testing.expectEqual(@as(u64, 100), try r.readUint());

    // 2-byte value (25): 0x19 <big-endian u16>
    r = Reader.init(&.{ 0x19, 0x01, 0x00 });
    try std.testing.expectEqual(@as(u64, 256), try r.readUint());
}

test "read negative integers" {
    // -1 is encoded as major=1, arg=0
    var r = Reader.init(&.{0x20});
    try std.testing.expectEqual(@as(i64, -1), try r.readInt());

    // -7 is encoded as major=1, arg=6
    r = Reader.init(&.{0x26});
    try std.testing.expectEqual(@as(i64, -7), try r.readInt());
}

test "read byte string" {
    // 3-byte string: 0x43 <3 bytes>
    var r = Reader.init(&.{ 0x43, 0xAA, 0xBB, 0xCC });
    const bytes = try r.readByteString();
    try std.testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB, 0xCC }, bytes);
}

test "read text string" {
    // "hello" = 0x65 + 5 bytes
    var r = Reader.init(&.{ 0x65, 'h', 'e', 'l', 'l', 'o' });
    const text = try r.readTextString();
    try std.testing.expectEqualStrings("hello", text);
}

test "read map" {
    // {1: 2, 3: 4} = 0xA2 0x01 0x02 0x03 0x04
    var r = Reader.init(&.{ 0xA2, 0x01, 0x02, 0x03, 0x04 });
    const len = try r.readMapLen();
    try std.testing.expectEqual(@as(usize, 2), len);
    try std.testing.expectEqual(@as(u64, 1), try r.readUint());
    try std.testing.expectEqual(@as(u64, 2), try r.readUint());
    try std.testing.expectEqual(@as(u64, 3), try r.readUint());
    try std.testing.expectEqual(@as(u64, 4), try r.readUint());
}

test "skip nested values" {
    // {1: [2, 3], 4: 5} = 0xA2 0x01 0x82 0x02 0x03 0x04 0x05
    var r = Reader.init(&.{ 0xA2, 0x01, 0x82, 0x02, 0x03, 0x04, 0x05 });
    const len = try r.readMapLen();
    try std.testing.expectEqual(@as(usize, 2), len);
    try std.testing.expectEqual(@as(u64, 1), try r.readUint());
    try r.skipValue(); // skip [2, 3]
    try std.testing.expectEqual(@as(u64, 4), try r.readUint());
    try std.testing.expectEqual(@as(u64, 5), try r.readUint());
}

test "type mismatch returns error" {
    var r = Reader.init(&.{0x05}); // unsigned
    try std.testing.expectError(Error.UnexpectedType, r.readByteString());
}
