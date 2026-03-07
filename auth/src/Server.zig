const std = @import("std");
const net = std.net;
const crypto = @import("crypto.zig");
const auth = @import("auth.zig");
const json = @import("json.zig");
const Allocator = std.mem.Allocator;

const Server = @This();

config: auth.Config,

pub fn init(allocator: Allocator, base_dir: []const u8) Server {
    return .{ .config = .{ .allocator = allocator, .base_dir = base_dir } };
}

pub fn handleConnection(self: *Server, conn: net.Server.Connection) void {
    defer conn.stream.close();

    var buf: [8192]u8 = undefined;
    var total: usize = 0;

    while (total < buf.len) {
        const n = conn.stream.read(buf[total..]) catch return;
        if (n == 0) break;
        total += n;
        if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n")) |header_end| {
            const content_length = parseContentLength(buf[0..header_end]);
            const body_start = header_end + 4;
            const body_received = total - body_start;
            if (body_received >= content_length) break;
        }
    }

    const request_data = buf[0..total];
    if (request_data.len == 0) return;

    const header_end = std.mem.indexOf(u8, request_data, "\r\n\r\n") orelse return;
    const first_line_end = std.mem.indexOf(u8, request_data, "\r\n") orelse return;
    const first_line = request_data[0..first_line_end];

    var parts = std.mem.splitScalar(u8, first_line, ' ');
    const method = parts.next() orelse return;
    const path = parts.next() orelse return;
    const headers = request_data[first_line_end + 2 .. header_end];
    const body = request_data[header_end + 4 ..];

    self.route(method, path, headers, body, conn.stream) catch |err| {
        std.log.err("handler error: {}", .{err});
        sendError(conn.stream, .internal_server_error, "internal error");
    };
}

fn route(self: *Server, method: []const u8, path: []const u8, headers: []const u8, body: []const u8, stream: net.Stream) !void {
    if (eql(method, "POST") and eql(path, "/auth/register")) {
        self.handleRegister(body, stream);
    } else if (eql(method, "POST") and eql(path, "/auth/challenge")) {
        self.handleChallenge(body, stream);
    } else if (eql(method, "POST") and eql(path, "/auth/login")) {
        self.handleLogin(body, stream);
    } else if (eql(method, "POST") and eql(path, "/auth/token/refresh")) {
        self.handleRefresh(body, stream);
    } else if (eql(method, "POST") and eql(path, "/auth/devices/link")) {
        self.handleLinkDevice(headers, body, stream);
    } else if (eql(method, "POST") and eql(path, "/auth/devices/unlink")) {
        self.handleUnlinkDevice(headers, body, stream);
    } else if (eql(method, "GET") and eql(path, "/auth/account")) {
        self.handleGetAccount(headers, stream);
    } else if (eql(method, "GET") and eql(path, "/health")) {
        sendJson(stream, .ok, "{\"status\":\"ok\"}");
    } else {
        sendError(stream, .not_found, "not found");
    }
}

fn handleRegister(self: *Server, body: []const u8, stream: net.Stream) void {
    const req = json.parseRegisterRequest(body) catch {
        sendError(stream, .bad_request, "invalid request body");
        return;
    };

    const result = auth.register(self.config, req.public_key, req.device_name) catch |err| {
        switch (err) {
            error.DeviceAlreadyExists => sendError(stream, .conflict, "device already registered"),
            error.InvalidPublicKey => sendError(stream, .bad_request, "invalid public key"),
            else => sendError(stream, .internal_server_error, "internal error"),
        }
        return;
    };

    var body_buf: [600]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"account_id":"{s}","device_id":"{s}","access_token":"{s}","refresh_token":"{s}","expires_at":{d}}}
    , .{
        result.account_id,
        result.device_id,
        result.tokens.access_token,
        result.tokens.refresh_token,
        result.tokens.expires_at,
    }) catch {
        sendError(stream, .internal_server_error, "internal error");
        return;
    };

    sendJson(stream, .ok, resp_body);
}

fn handleChallenge(self: *Server, body: []const u8, stream: net.Stream) void {
    const req = json.parseChallengeRequest(body) catch {
        sendError(stream, .bad_request, "invalid request body");
        return;
    };

    const result = auth.createChallenge(self.config, req.public_key) catch |err| {
        switch (err) {
            error.DeviceNotFound => sendError(stream, .not_found, "device not found"),
            error.InvalidPublicKey => sendError(stream, .bad_request, "invalid public key"),
            else => sendError(stream, .internal_server_error, "internal error"),
        }
        return;
    };

    var body_buf: [256]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"challenge":"{s}","expires_at":{d}}}
    , .{ result.challenge, result.expires_at }) catch {
        sendError(stream, .internal_server_error, "internal error");
        return;
    };

    sendJson(stream, .ok, resp_body);
}

fn handleLogin(self: *Server, body: []const u8, stream: net.Stream) void {
    const req = json.parseLoginRequest(body) catch {
        sendError(stream, .bad_request, "invalid request body");
        return;
    };

    const result = auth.login(self.config, req.public_key, req.challenge, req.signature) catch |err| {
        switch (err) {
            error.InvalidSignature => sendError(stream, .unauthorized, "invalid signature"),
            error.ChallengeNotFound => sendError(stream, .bad_request, "challenge not found"),
            error.ChallengeExpired => sendError(stream, .bad_request, "challenge expired"),
            error.DeviceNotFound => sendError(stream, .not_found, "device not found"),
            error.InvalidPublicKey => sendError(stream, .bad_request, "invalid public key"),
            error.InvalidChallenge => sendError(stream, .bad_request, "invalid challenge"),
            else => sendError(stream, .internal_server_error, "internal error"),
        }
        return;
    };

    var body_buf: [600]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"account_id":"{s}","access_token":"{s}","refresh_token":"{s}","expires_at":{d}}}
    , .{
        result.account_id,
        result.tokens.access_token,
        result.tokens.refresh_token,
        result.tokens.expires_at,
    }) catch {
        sendError(stream, .internal_server_error, "internal error");
        return;
    };

    sendJson(stream, .ok, resp_body);
}

fn handleRefresh(self: *Server, body: []const u8, stream: net.Stream) void {
    const req = json.parseRefreshRequest(body) catch {
        sendError(stream, .bad_request, "invalid request body");
        return;
    };

    const tokens = auth.refreshTokens(self.config, req.refresh_token) catch |err| {
        switch (err) {
            error.TokenNotFound => sendError(stream, .unauthorized, "invalid refresh token"),
            error.TokenExpired => sendError(stream, .unauthorized, "refresh token expired"),
            else => sendError(stream, .internal_server_error, "internal error"),
        }
        return;
    };

    var body_buf: [400]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"access_token":"{s}","refresh_token":"{s}","expires_at":{d}}}
    , .{ tokens.access_token, tokens.refresh_token, tokens.expires_at }) catch {
        sendError(stream, .internal_server_error, "internal error");
        return;
    };

    sendJson(stream, .ok, resp_body);
}

fn handleLinkDevice(self: *Server, headers: []const u8, body: []const u8, stream: net.Stream) void {
    const account_id = self.authenticate(headers) catch {
        sendError(stream, .unauthorized, "unauthorized");
        return;
    };

    const req = json.parseLinkDeviceRequest(body) catch {
        sendError(stream, .bad_request, "invalid request body");
        return;
    };

    const device_id = auth.linkDevice(self.config, &account_id, req.public_key, req.device_name) catch |err| {
        switch (err) {
            error.DeviceAlreadyExists => sendError(stream, .conflict, "device already exists"),
            error.InvalidPublicKey => sendError(stream, .bad_request, "invalid public key"),
            error.AccountNotFound => sendError(stream, .not_found, "account not found"),
            else => sendError(stream, .internal_server_error, "internal error"),
        }
        return;
    } orelse {
        sendError(stream, .internal_server_error, "internal error");
        return;
    };

    var body_buf: [128]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"device_id":"{s}"}}
    , .{device_id}) catch {
        sendError(stream, .internal_server_error, "internal error");
        return;
    };

    sendJson(stream, .ok, resp_body);
}

fn handleUnlinkDevice(self: *Server, headers: []const u8, body: []const u8, stream: net.Stream) void {
    const account_id = self.authenticate(headers) catch {
        sendError(stream, .unauthorized, "unauthorized");
        return;
    };

    const req = json.parseUnlinkDeviceRequest(body) catch {
        sendError(stream, .bad_request, "invalid request body");
        return;
    };

    auth.unlinkDevice(self.config, &account_id, req.device_id) catch |err| {
        switch (err) {
            error.DeviceNotFound => sendError(stream, .not_found, "device not found"),
            error.DeviceNotOwned => sendError(stream, .unauthorized, "device not owned by account"),
            error.CannotRemoveLastDevice => sendError(stream, .bad_request, "cannot remove last device"),
            error.AccountNotFound => sendError(stream, .not_found, "account not found"),
            else => sendError(stream, .internal_server_error, "internal error"),
        }
        return;
    };

    sendJson(stream, .ok, "{\"ok\":true}");
}

fn handleGetAccount(self: *Server, headers: []const u8, stream: net.Stream) void {
    const account_id = self.authenticate(headers) catch {
        sendError(stream, .unauthorized, "unauthorized");
        return;
    };

    const info = auth.getAccountInfo(self.config, &account_id) catch {
        sendError(stream, .internal_server_error, "internal error");
        return;
    } orelse {
        sendError(stream, .not_found, "account not found");
        return;
    };
    defer {
        for (info.devices) |d| self.config.allocator.free(d.name);
        self.config.allocator.free(info.devices);
    }

    var body_buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&body_buf);

    w.writeAll("{\"account_id\":\"") catch return;
    w.writeAll(&info.account_id) catch return;
    w.writeAll("\",\"created_at\":") catch return;
    w.print("{d}", .{info.created_at}) catch return;
    w.writeAll(",\"devices\":[") catch return;

    for (info.devices, 0..) |dev, i| {
        if (i > 0) w.writeAll(",") catch return;
        w.writeAll("{\"id\":\"") catch return;
        w.writeAll(&dev.id) catch return;
        w.writeAll("\",\"name\":\"") catch return;
        w.writeAll(dev.name) catch return;
        w.writeAll("\",\"created_at\":") catch return;
        w.print("{d}", .{dev.created_at}) catch return;
        w.writeAll("}") catch return;
    }

    w.writeAll("]}") catch return;

    sendJson(stream, .ok, w.buffered());
}

fn authenticate(self: *Server, headers: []const u8) auth.AuthError![crypto.uuid_len]u8 {
    const token = extractBearerToken(headers) orelse return auth.AuthError.Unauthorized;
    return (auth.validateToken(self.config, token) catch return auth.AuthError.Unauthorized) orelse return auth.AuthError.Unauthorized;
}

// --- Helpers ---

fn sendJson(stream: net.Stream, status: std.http.Status, body: []const u8) void {
    var resp_buf: [8192]u8 = undefined;
    const response = json.buildResponse(&resp_buf, status, body);
    stream.writeAll(response) catch {};
}

fn sendError(stream: net.Stream, status: std.http.Status, message: []const u8) void {
    var err_buf: [256]u8 = undefined;
    const err_body = json.buildErrorBody(&err_buf, message);
    sendJson(stream, status, err_body);
}

fn extractBearerToken(headers: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        if (asciiStartsWithIgnoreCase(line, "authorization:")) {
            const value = std.mem.trimLeft(u8, line["authorization:".len..], " ");
            if (asciiStartsWithIgnoreCase(value, "bearer ")) {
                return std.mem.trim(u8, value["bearer ".len..], " ");
            }
        }
    }
    return null;
}

fn asciiStartsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    for (haystack[0..needle.len], needle) |h, n| {
        if (std.ascii.toLower(h) != std.ascii.toLower(n)) return false;
    }
    return true;
}

fn parseContentLength(headers: []const u8) usize {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        if (asciiStartsWithIgnoreCase(line, "content-length:")) {
            const value = std.mem.trim(u8, line["content-length:".len..], " ");
            return std.fmt.parseInt(usize, value, 10) catch 0;
        }
    }
    return 0;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

test "extractBearerToken" {
    const headers = "Host: localhost\r\nAuthorization: Bearer abc123\r\nAccept: */*";
    const token = extractBearerToken(headers);
    try std.testing.expect(token != null);
    try std.testing.expectEqualStrings("abc123", token.?);
}

test "extractBearerToken missing" {
    const headers = "Host: localhost\r\nAccept: */*";
    try std.testing.expect(extractBearerToken(headers) == null);
}

test "parseContentLength" {
    const headers = "Host: localhost\r\nContent-Length: 42\r\nAccept: */*";
    try std.testing.expectEqual(@as(usize, 42), parseContentLength(headers));
}
