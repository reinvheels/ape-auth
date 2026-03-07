const std = @import("std");
const net = std.net;
const crypto = @import("crypto.zig");
const auth = @import("auth.zig");
const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;

const Server = @This();

config: auth.Config,

pub fn init(allocator: Allocator, base_dir: []const u8, key_pair: Ed25519.KeyPair, issuer: []const u8) Server {
    return .{ .config = .{
        .allocator = allocator,
        .base_dir = base_dir,
        .key_pair = key_pair,
        .issuer = issuer,
    } };
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
    const is_get = std.mem.eql(u8, method, "GET");
    const is_post = std.mem.eql(u8, method, "POST");

    // OIDC discovery
    if (std.mem.eql(u8, path, "/.well-known/openid-configuration")) {
        if (!is_get) return sendMethodNotAllowed(stream, "GET");
        self.handleDiscovery(stream);
    } else if (std.mem.eql(u8, path, "/.well-known/jwks.json")) {
        if (!is_get) return sendMethodNotAllowed(stream, "GET");
        self.handleJwks(stream);
    }
    // OIDC token + userinfo
    else if (std.mem.eql(u8, path, "/token")) {
        if (!is_post) return sendMethodNotAllowed(stream, "POST");
        if (!hasContentType(headers, "application/x-www-form-urlencoded")) return sendError(stream, .bad_request, "expected content-type: application/x-www-form-urlencoded");
        self.handleToken(body, stream);
    } else if (std.mem.eql(u8, path, "/userinfo")) {
        if (!is_get) return sendMethodNotAllowed(stream, "GET");
        self.handleUserinfo(headers, stream);
    }
    // Device auth
    else if (std.mem.eql(u8, path, "/auth/register")) {
        if (!is_post) return sendMethodNotAllowed(stream, "POST");
        if (!hasContentType(headers, "application/json")) return sendError(stream, .bad_request, "expected content-type: application/json");
        self.handleRegister(body, stream);
    } else if (std.mem.eql(u8, path, "/auth/challenge")) {
        if (!is_post) return sendMethodNotAllowed(stream, "POST");
        if (!hasContentType(headers, "application/json")) return sendError(stream, .bad_request, "expected content-type: application/json");
        self.handleChallenge(body, stream);
    } else if (std.mem.eql(u8, path, "/auth/login")) {
        if (!is_post) return sendMethodNotAllowed(stream, "POST");
        if (!hasContentType(headers, "application/json")) return sendError(stream, .bad_request, "expected content-type: application/json");
        self.handleLogin(body, stream);
    }
    // Device management
    else if (std.mem.eql(u8, path, "/auth/devices/link")) {
        if (!is_post) return sendMethodNotAllowed(stream, "POST");
        if (!hasContentType(headers, "application/json")) return sendError(stream, .bad_request, "expected content-type: application/json");
        self.handleLinkDevice(headers, body, stream);
    } else if (std.mem.eql(u8, path, "/auth/devices/unlink")) {
        if (!is_post) return sendMethodNotAllowed(stream, "POST");
        if (!hasContentType(headers, "application/json")) return sendError(stream, .bad_request, "expected content-type: application/json");
        self.handleUnlinkDevice(headers, body, stream);
    } else if (std.mem.eql(u8, path, "/auth/account")) {
        if (!is_get) return sendMethodNotAllowed(stream, "GET");
        self.handleGetAccount(headers, stream);
    }
    // Health
    else if (std.mem.eql(u8, path, "/health")) {
        if (!is_get) return sendMethodNotAllowed(stream, "GET");
        sendJson(stream, .ok, "{\"status\":\"ok\"}");
    } else {
        sendError(stream, .not_found, "not found");
    }
}

// --- OIDC Discovery ---

fn handleDiscovery(self: *Server, stream: net.Stream) void {
    var buf: [2048]u8 = undefined;
    const body = std.fmt.bufPrint(&buf,
        \\{{"issuer":"{s}","authorization_endpoint":"{s}/authorize","token_endpoint":"{s}/token","userinfo_endpoint":"{s}/userinfo","jwks_uri":"{s}/.well-known/jwks.json","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["EdDSA"],"scopes_supported":["openid"],"grant_types_supported":["authorization_code","refresh_token"]}}
    , .{ self.config.issuer, self.config.issuer, self.config.issuer, self.config.issuer, self.config.issuer }) catch {
        sendError(stream, .internal_server_error, "internal error");
        return;
    };
    sendJson(stream, .ok, body);
}

fn handleJwks(self: *Server, stream: net.Stream) void {
    const json = crypto.jwksJson(self.config.allocator, self.config.key_pair.public_key) catch {
        sendError(stream, .internal_server_error, "internal error");
        return;
    };
    defer self.config.allocator.free(json);
    sendJson(stream, .ok, json);
}

// --- OIDC Token Endpoint ---

fn handleToken(self: *Server, body: []const u8, stream: net.Stream) void {
    // Parse form-urlencoded body
    const grant_type = getFormParam(body, "grant_type") orelse {
        sendError(stream, .bad_request, "missing grant_type");
        return;
    };

    if (std.mem.eql(u8, grant_type, "refresh_token")) {
        const refresh_token = getFormParam(body, "refresh_token") orelse {
            sendError(stream, .bad_request, "missing refresh_token");
            return;
        };
        self.handleRefreshGrant(refresh_token, stream);
    } else {
        sendError(stream, .bad_request, "unsupported grant_type");
    }
}

fn handleRefreshGrant(self: *Server, refresh_token: []const u8, stream: net.Stream) void {
    const tokens = auth.refreshTokens(self.config, refresh_token) catch |err| {
        switch (err) {
            error.TokenNotFound => sendError(stream, .unauthorized, "invalid refresh token"),
            error.TokenExpired => sendError(stream, .unauthorized, "refresh token expired"),
            else => sendError(stream, .internal_server_error, "internal error"),
        }
        return;
    };
    defer self.config.allocator.free(tokens.id_token);

    var body_buf: [2048]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"id_token":"{s}","access_token":"{s}","token_type":"Bearer","expires_in":{d},"refresh_token":"{s}"}}
    , .{ tokens.id_token, tokens.id_token, tokens.expires_in, tokens.refresh_token }) catch {
        sendError(stream, .internal_server_error, "internal error");
        return;
    };

    sendJson(stream, .ok, resp_body);
}

// --- Userinfo ---

fn handleUserinfo(self: *Server, headers: []const u8, stream: net.Stream) void {
    const account_id = self.authenticate(headers) catch {
        sendError(stream, .unauthorized, "unauthorized");
        return;
    };

    var body_buf: [128]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"sub":"{s}"}}
    , .{account_id}) catch {
        sendError(stream, .internal_server_error, "internal error");
        return;
    };

    sendJson(stream, .ok, resp_body);
}

// --- Device Auth Handlers ---

fn handleRegister(self: *Server, body: []const u8, stream: net.Stream) void {
    const req = parseJson(struct { public_key: []const u8, device_name: []const u8 }, body) catch {
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
    defer self.config.allocator.free(result.tokens.id_token);

    var body_buf: [2048]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"account_id":"{s}","device_id":"{s}","id_token":"{s}","access_token":"{s}","refresh_token":"{s}","expires_in":{d}}}
    , .{
        result.account_id,
        result.device_id,
        result.tokens.id_token,
        result.tokens.id_token,
        result.tokens.refresh_token,
        result.tokens.expires_in,
    }) catch {
        sendError(stream, .internal_server_error, "internal error");
        return;
    };

    sendJson(stream, .ok, resp_body);
}

fn handleChallenge(self: *Server, body: []const u8, stream: net.Stream) void {
    const req = parseJson(struct { public_key: []const u8 }, body) catch {
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
    const req = parseJson(struct { public_key: []const u8, challenge: []const u8, signature: []const u8 }, body) catch {
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
    defer self.config.allocator.free(result.tokens.id_token);

    var body_buf: [2048]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"account_id":"{s}","id_token":"{s}","access_token":"{s}","refresh_token":"{s}","expires_in":{d}}}
    , .{
        result.account_id,
        result.tokens.id_token,
        result.tokens.id_token,
        result.tokens.refresh_token,
        result.tokens.expires_in,
    }) catch {
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

    const req = parseJson(struct { public_key: []const u8, device_name: []const u8 }, body) catch {
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

    const req = parseJson(struct { device_id: []const u8 }, body) catch {
        sendError(stream, .bad_request, "invalid request body");
        return;
    };

    auth.unlinkDevice(self.config, &account_id, req.device_id) catch |err| {
        switch (err) {
            error.DeviceNotFound => sendError(stream, .not_found, "device not found"),
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
    const status_str = statusString(status);
    const response = std.fmt.bufPrint(&resp_buf, "HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status_str, body.len, body }) catch "";
    stream.writeAll(response) catch {};
}

fn sendMethodNotAllowed(stream: net.Stream, allowed: []const u8) void {
    var buf: [256]u8 = undefined;
    const status_str = statusString(.method_not_allowed);
    const body = "{\"error\":\"method not allowed\"}";
    const response = std.fmt.bufPrint(&buf, "HTTP/1.1 {s}\r\nAllow: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status_str, allowed, body.len, body }) catch "";
    stream.writeAll(response) catch {};
}

fn sendError(stream: net.Stream, status: std.http.Status, message: []const u8) void {
    var err_buf: [256]u8 = undefined;
    const err_body = std.fmt.bufPrint(&err_buf, "{{\"error\":\"{s}\"}}", .{message}) catch "{\"error\":\"internal error\"}";
    sendJson(stream, status, err_body);
}

fn parseJson(comptime T: type, body: []const u8) !T {
    // Slices in the returned value reference body, not the parse arena,
    // so it's safe to free the arena here. Body outlives the handler scope.
    var parsed = try std.json.parseFromSlice(T, std.heap.page_allocator, body, .{});
    defer parsed.deinit();
    return parsed.value;
}

fn statusString(status: std.http.Status) []const u8 {
    return switch (status) {
        .ok => "200 OK",
        .bad_request => "400 Bad Request",
        .unauthorized => "401 Unauthorized",
        .method_not_allowed => "405 Method Not Allowed",
        .not_found => "404 Not Found",
        .conflict => "409 Conflict",
        .internal_server_error => "500 Internal Server Error",
        else => "500 Internal Server Error",
    };
}

fn hasContentType(headers: []const u8, expected: []const u8) bool {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        if (asciiStartsWithIgnoreCase(line, "content-type:")) {
            const value = std.mem.trim(u8, line["content-type:".len..], " ");
            // Match before any ;params (e.g. "application/json; charset=utf-8")
            const media_type = if (std.mem.indexOfScalar(u8, value, ';')) |i| std.mem.trim(u8, value[0..i], " ") else value;
            return asciiStartsWithIgnoreCase(media_type, expected) and media_type.len == expected.len;
        }
    }
    return false;
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

fn getFormParam(body: []const u8, key: []const u8) ?[]const u8 {
    var pairs = std.mem.splitScalar(u8, body, '&');
    while (pairs.next()) |pair| {
        if (std.mem.indexOfScalar(u8, pair, '=')) |eq_pos| {
            if (std.mem.eql(u8, pair[0..eq_pos], key)) {
                return pair[eq_pos + 1 ..];
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

test "getFormParam" {
    const body = "grant_type=refresh_token&refresh_token=abc123";
    try std.testing.expectEqualStrings("refresh_token", getFormParam(body, "grant_type").?);
    try std.testing.expectEqualStrings("abc123", getFormParam(body, "refresh_token").?);
    try std.testing.expect(getFormParam(body, "missing") == null);
}
