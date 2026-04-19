const std = @import("std");
const Io = std.Io;
const net = Io.net;
const crypto = @import("crypto.zig");
const auth = @import("auth.zig");
const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;

const Server = @This();

config: auth.Config,

pub fn init(allocator: Allocator, io: Io, base_dir: []const u8, key_pair: Ed25519.KeyPair, issuer: []const u8) Server {
    return .{ .config = .{
        .allocator = allocator,
        .io = io,
        .base_dir = base_dir,
        .key_pair = key_pair,
        .issuer = issuer,
    } };
}

pub fn handleConnection(self: *Server, stream: net.Stream) void {
    const io = self.config.io;
    defer stream.close(io);

    var buf: [8192]u8 = undefined;
    var total: usize = 0;

    var read_buf: [4096]u8 = undefined;
    var reader = stream.reader(io, &read_buf);

    while (total < buf.len) {
        var read_slices: [1][]u8 = .{buf[total..]};
        const n = reader.interface.readVec(&read_slices) catch return;
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

    var write_buf: [4096]u8 = undefined;
    var writer = stream.writer(io, &write_buf);

    self.route(method, path, headers, body, &writer.interface) catch |err| {
        std.log.err("handler error: {}", .{err});
        sendError(&writer.interface, .internal_server_error, "internal error");
    };
}

fn route(self: *Server, method: []const u8, path: []const u8, headers: []const u8, body: []const u8, w: *Io.Writer) !void {
    const is_get = std.mem.eql(u8, method, "GET");
    const is_post = std.mem.eql(u8, method, "POST");

    // OIDC discovery
    if (std.mem.eql(u8, path, "/.well-known/openid-configuration")) {
        if (!is_get) return sendMethodNotAllowed(w, "GET");
        self.handleDiscovery(w);
    } else if (std.mem.eql(u8, path, "/.well-known/jwks.json")) {
        if (!is_get) return sendMethodNotAllowed(w, "GET");
        self.handleJwks(w);
    }
    // OIDC token + userinfo
    else if (std.mem.eql(u8, path, "/token")) {
        if (!is_post) return sendMethodNotAllowed(w, "POST");
        if (!hasContentType(headers, "application/x-www-form-urlencoded")) return sendError(w, .bad_request, "expected content-type: application/x-www-form-urlencoded");
        self.handleToken(body, w);
    } else if (std.mem.eql(u8, path, "/userinfo")) {
        if (!is_get) return sendMethodNotAllowed(w, "GET");
        self.handleUserinfo(headers, w);
    }
    // Device auth
    else if (std.mem.eql(u8, path, "/auth/register")) {
        if (!is_post) return sendMethodNotAllowed(w, "POST");
        if (!hasContentType(headers, "application/json")) return sendError(w, .bad_request, "expected content-type: application/json");
        self.handleRegister(body, w);
    } else if (std.mem.eql(u8, path, "/auth/challenge")) {
        if (!is_post) return sendMethodNotAllowed(w, "POST");
        if (!hasContentType(headers, "application/json")) return sendError(w, .bad_request, "expected content-type: application/json");
        self.handleChallenge(body, w);
    } else if (std.mem.eql(u8, path, "/auth/login")) {
        if (!is_post) return sendMethodNotAllowed(w, "POST");
        if (!hasContentType(headers, "application/json")) return sendError(w, .bad_request, "expected content-type: application/json");
        self.handleLogin(body, w);
    }
    // Device management
    else if (std.mem.eql(u8, path, "/auth/devices/link")) {
        if (!is_post) return sendMethodNotAllowed(w, "POST");
        if (!hasContentType(headers, "application/json")) return sendError(w, .bad_request, "expected content-type: application/json");
        self.handleLinkDevice(headers, body, w);
    } else if (std.mem.eql(u8, path, "/auth/devices/unlink")) {
        if (!is_post) return sendMethodNotAllowed(w, "POST");
        if (!hasContentType(headers, "application/json")) return sendError(w, .bad_request, "expected content-type: application/json");
        self.handleUnlinkDevice(headers, body, w);
    } else if (std.mem.eql(u8, path, "/auth/account")) {
        if (!is_get) return sendMethodNotAllowed(w, "GET");
        self.handleGetAccount(headers, w);
    }
    // WebAuthn
    else if (std.mem.eql(u8, path, "/auth/webauthn/register/options")) {
        if (!is_post) return sendMethodNotAllowed(w, "POST");
        if (!hasContentType(headers, "application/json")) return sendError(w, .bad_request, "expected content-type: application/json");
        self.handleWebAuthnRegisterOptions(body, w);
    } else if (std.mem.eql(u8, path, "/auth/webauthn/register/verify")) {
        if (!is_post) return sendMethodNotAllowed(w, "POST");
        if (!hasContentType(headers, "application/json")) return sendError(w, .bad_request, "expected content-type: application/json");
        self.handleWebAuthnRegisterVerify(body, w);
    } else if (std.mem.eql(u8, path, "/auth/webauthn/login/options")) {
        if (!is_post) return sendMethodNotAllowed(w, "POST");
        self.handleWebAuthnLoginOptions(w);
    } else if (std.mem.eql(u8, path, "/auth/webauthn/login/verify")) {
        if (!is_post) return sendMethodNotAllowed(w, "POST");
        if (!hasContentType(headers, "application/json")) return sendError(w, .bad_request, "expected content-type: application/json");
        self.handleWebAuthnLoginVerify(body, w);
    }
    // UI
    else if (std.mem.eql(u8, path, "/")) {
        if (!is_get) return sendMethodNotAllowed(w, "GET");
        sendHtml(w, @embedFile("ui/index.html"));
    }
    // Session (cookie-based)
    else if (std.mem.eql(u8, path, "/session")) {
        if (!is_get) return sendMethodNotAllowed(w, "GET");
        self.handleSession(headers, w);
    } else if (std.mem.eql(u8, path, "/auth/logout")) {
        if (!is_post) return sendMethodNotAllowed(w, "POST");
        self.handleLogout(headers, w);
    }
    // Health
    else if (std.mem.eql(u8, path, "/health")) {
        if (!is_get) return sendMethodNotAllowed(w, "GET");
        sendJson(w, .ok, "{\"status\":\"ok\"}");
    } else {
        sendError(w, .not_found, "not found");
    }
}

// --- OIDC Discovery ---

fn handleDiscovery(self: *Server, w: *Io.Writer) void {
    var buf: [2048]u8 = undefined;
    const body = std.fmt.bufPrint(&buf,
        \\{{"issuer":"{s}","authorization_endpoint":"{s}/authorize","token_endpoint":"{s}/token","userinfo_endpoint":"{s}/userinfo","jwks_uri":"{s}/.well-known/jwks.json","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["EdDSA"],"scopes_supported":["openid"],"grant_types_supported":["authorization_code","refresh_token"]}}
    , .{ self.config.issuer, self.config.issuer, self.config.issuer, self.config.issuer, self.config.issuer }) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };
    sendJson(w, .ok, body);
}

fn handleJwks(self: *Server, w: *Io.Writer) void {
    const json = crypto.jwksJson(self.config.allocator, self.config.key_pair.public_key) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };
    defer self.config.allocator.free(json);
    sendJson(w, .ok, json);
}

// --- OIDC Token Endpoint ---

fn handleToken(self: *Server, body: []const u8, w: *Io.Writer) void {
    // Parse form-urlencoded body
    const grant_type = getFormParam(body, "grant_type") orelse {
        sendError(w, .bad_request, "missing grant_type");
        return;
    };

    if (std.mem.eql(u8, grant_type, "refresh_token")) {
        const raw = getFormParam(body, "refresh_token") orelse {
            sendError(w, .bad_request, "missing refresh_token");
            return;
        };
        var decoded_buf: [256]u8 = undefined;
        const refresh_token = percentDecode(raw, &decoded_buf) orelse {
            sendError(w, .bad_request, "invalid refresh_token encoding");
            return;
        };
        self.handleRefreshGrant(refresh_token, w);
    } else {
        sendError(w, .bad_request, "unsupported grant_type");
    }
}

fn handleRefreshGrant(self: *Server, refresh_token: []const u8, w: *Io.Writer) void {
    const tokens = auth.refreshTokens(self.config, refresh_token) catch |err| {
        switch (err) {
            error.TokenNotFound => sendError(w, .unauthorized, "invalid refresh token"),
            error.TokenExpired => sendError(w, .unauthorized, "refresh token expired"),
            else => sendError(w, .internal_server_error, "internal error"),
        }
        return;
    };
    defer self.config.allocator.free(tokens.id_token);

    var body_buf: [2048]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"id_token":"{s}","access_token":"{s}","token_type":"Bearer","expires_in":{d},"refresh_token":"{s}"}}
    , .{ tokens.id_token, tokens.id_token, tokens.expires_in, tokens.refresh_token }) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    sendJson(w, .ok, resp_body);
}

// --- Userinfo ---

fn handleUserinfo(self: *Server, headers: []const u8, w: *Io.Writer) void {
    const account_id = self.authenticate(headers) catch {
        sendError(w, .unauthorized, "unauthorized");
        return;
    };

    var body_buf: [128]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"sub":"{s}"}}
    , .{account_id}) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    sendJson(w, .ok, resp_body);
}

// --- Device Auth Handlers ---

fn handleRegister(self: *Server, body: []const u8, w: *Io.Writer) void {
    const req = parseJson(struct { public_key: []const u8, device_name: []const u8 }, body) catch {
        sendError(w, .bad_request, "invalid request body");
        return;
    };

    const result = auth.register(self.config, req.public_key, req.device_name) catch |err| {
        switch (err) {
            error.DeviceAlreadyExists => sendError(w, .conflict, "device already registered"),
            error.InvalidPublicKey => sendError(w, .bad_request, "invalid public key"),
            else => sendError(w, .internal_server_error, "internal error"),
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
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    sendJson(w, .ok, resp_body);
}

fn handleChallenge(self: *Server, body: []const u8, w: *Io.Writer) void {
    const req = parseJson(struct { public_key: []const u8 }, body) catch {
        sendError(w, .bad_request, "invalid request body");
        return;
    };

    const result = auth.createChallenge(self.config, req.public_key) catch |err| {
        switch (err) {
            error.DeviceNotFound => sendError(w, .not_found, "device not found"),
            error.InvalidPublicKey => sendError(w, .bad_request, "invalid public key"),
            else => sendError(w, .internal_server_error, "internal error"),
        }
        return;
    };

    var body_buf: [256]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"challenge":"{s}","expires_at":{d}}}
    , .{ result.challenge, result.expires_at }) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    sendJson(w, .ok, resp_body);
}

fn handleLogin(self: *Server, body: []const u8, w: *Io.Writer) void {
    const req = parseJson(struct { public_key: []const u8, challenge: []const u8, signature: []const u8 }, body) catch {
        sendError(w, .bad_request, "invalid request body");
        return;
    };

    const result = auth.login(self.config, req.public_key, req.challenge, req.signature) catch |err| {
        switch (err) {
            error.InvalidSignature => sendError(w, .unauthorized, "invalid signature"),
            error.ChallengeNotFound => sendError(w, .bad_request, "challenge not found"),
            error.ChallengeExpired => sendError(w, .bad_request, "challenge expired"),
            error.DeviceNotFound => sendError(w, .not_found, "device not found"),
            error.InvalidPublicKey => sendError(w, .bad_request, "invalid public key"),
            error.InvalidChallenge => sendError(w, .bad_request, "invalid challenge"),
            else => sendError(w, .internal_server_error, "internal error"),
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
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    sendJson(w, .ok, resp_body);
}

fn handleLinkDevice(self: *Server, headers: []const u8, body: []const u8, w: *Io.Writer) void {
    const account_id = self.authenticate(headers) catch {
        sendError(w, .unauthorized, "unauthorized");
        return;
    };

    const req = parseJson(struct { public_key: []const u8, device_name: []const u8 }, body) catch {
        sendError(w, .bad_request, "invalid request body");
        return;
    };

    const device_id = auth.linkDevice(self.config, &account_id, req.public_key, req.device_name) catch |err| {
        switch (err) {
            error.DeviceAlreadyExists => sendError(w, .conflict, "device already exists"),
            error.InvalidPublicKey => sendError(w, .bad_request, "invalid public key"),
            error.AccountNotFound => sendError(w, .not_found, "account not found"),
            else => sendError(w, .internal_server_error, "internal error"),
        }
        return;
    } orelse {
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    var body_buf: [128]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"device_id":"{s}"}}
    , .{device_id}) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    sendJson(w, .ok, resp_body);
}

fn handleUnlinkDevice(self: *Server, headers: []const u8, body: []const u8, w: *Io.Writer) void {
    const account_id = self.authenticate(headers) catch {
        sendError(w, .unauthorized, "unauthorized");
        return;
    };

    const req = parseJson(struct { device_id: []const u8 }, body) catch {
        sendError(w, .bad_request, "invalid request body");
        return;
    };

    auth.unlinkDevice(self.config, &account_id, req.device_id) catch |err| {
        switch (err) {
            error.DeviceNotFound => sendError(w, .not_found, "device not found"),
            error.CannotRemoveLastDevice => sendError(w, .bad_request, "cannot remove last device"),
            error.AccountNotFound => sendError(w, .not_found, "account not found"),
            else => sendError(w, .internal_server_error, "internal error"),
        }
        return;
    };

    sendJson(w, .ok, "{\"ok\":true}");
}

fn handleGetAccount(self: *Server, headers: []const u8, w: *Io.Writer) void {
    const account_id = self.authenticate(headers) catch {
        sendError(w, .unauthorized, "unauthorized");
        return;
    };

    const info = auth.getAccountInfo(self.config, &account_id) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    } orelse {
        sendError(w, .not_found, "account not found");
        return;
    };
    defer {
        for (info.devices) |d| self.config.allocator.free(d.name);
        self.config.allocator.free(info.devices);
    }

    var body_buf: [4096]u8 = undefined;
    var bw = Io.Writer.fixed(&body_buf);

    bw.writeAll("{\"account_id\":\"") catch return;
    bw.writeAll(&info.account_id) catch return;
    bw.writeAll("\",\"created_at\":") catch return;
    bw.print("{d}", .{info.created_at}) catch return;
    bw.writeAll(",\"devices\":[") catch return;

    for (info.devices, 0..) |dev, i| {
        if (i > 0) bw.writeAll(",") catch return;
        bw.writeAll("{\"id\":\"") catch return;
        bw.writeAll(&dev.id) catch return;
        bw.writeAll("\",\"name\":\"") catch return;
        bw.writeAll(dev.name) catch return;
        bw.writeAll("\",\"created_at\":") catch return;
        bw.print("{d}", .{dev.created_at}) catch return;
        bw.writeAll("}") catch return;
    }

    bw.writeAll("]}") catch return;

    sendJson(w, .ok, bw.buffered());
}

// --- WebAuthn Handlers ---

fn handleWebAuthnRegisterOptions(self: *Server, body: []const u8, w: *Io.Writer) void {
    const req = parseJson(struct { display_name: []const u8 = "Passkey" }, body) catch {
        sendError(w, .bad_request, "invalid request body");
        return;
    };

    const result = auth.webauthnRegisterOptions(self.config, req.display_name) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };
    defer self.config.allocator.free(result.challenge_b64);
    defer self.config.allocator.free(result.user_id_b64);

    const rp_id = auth.rpIdFromIssuer(self.config.issuer);

    var body_buf: [2048]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"publicKey":{{"challenge":"{s}","rp":{{"id":"{s}","name":"{s}"}},"user":{{"id":"{s}","name":"user","displayName":"{s}"}},"pubKeyCredParams":[{{"type":"public-key","alg":-7}}],"authenticatorSelection":{{"residentKey":"required","userVerification":"required"}},"attestation":"none","timeout":300000}}}}
    , .{ result.challenge_b64, rp_id, rp_id, result.user_id_b64, req.display_name }) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    sendJson(w, .ok, resp_body);
}

fn handleWebAuthnRegisterVerify(self: *Server, body: []const u8, w: *Io.Writer) void {
    const req = parseJsonLenient(struct {
        id: []const u8,
        response: struct {
            clientDataJSON: []const u8,
            attestationObject: []const u8,
        },
    }, body) catch {
        sendError(w, .bad_request, "invalid request body");
        return;
    };

    // clientDataJSON comes as base64url from browser — decode it
    const client_data_json = crypto.base64urlDecodeAlloc(self.config.allocator, req.response.clientDataJSON) catch {
        sendError(w, .bad_request, "invalid clientDataJSON encoding");
        return;
    };
    defer self.config.allocator.free(client_data_json);

    const result = auth.webauthnRegisterVerify(
        self.config,
        req.id,
        client_data_json,
        req.response.attestationObject,
    ) catch |err| {
        switch (err) {
            error.DeviceAlreadyExists => sendError(w, .conflict, "credential already registered"),
            error.InvalidSignature => sendError(w, .bad_request, "invalid attestation"),
            error.ChallengeNotFound => sendError(w, .bad_request, "challenge not found"),
            error.ChallengeExpired => sendError(w, .bad_request, "challenge expired"),
            error.InvalidChallenge => sendError(w, .bad_request, "invalid challenge"),
            else => sendError(w, .internal_server_error, "internal error"),
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
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    var cookie_buf: [256]u8 = undefined;
    const cookie = buildSessionCookie(&cookie_buf, &result.tokens.refresh_token, self.config.issuer) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    sendJsonCookie(w, .ok, resp_body, cookie);
}

fn handleWebAuthnLoginOptions(self: *Server, w: *Io.Writer) void {
    const result = auth.webauthnLoginOptions(self.config) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };
    defer self.config.allocator.free(result.challenge_b64);

    const rp_id = auth.rpIdFromIssuer(self.config.issuer);

    var body_buf: [512]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"publicKey":{{"challenge":"{s}","rpId":"{s}","userVerification":"required","timeout":300000}}}}
    , .{ result.challenge_b64, rp_id }) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    sendJson(w, .ok, resp_body);
}

fn handleWebAuthnLoginVerify(self: *Server, body: []const u8, w: *Io.Writer) void {
    const req = parseJsonLenient(struct {
        id: []const u8,
        response: struct {
            clientDataJSON: []const u8,
            authenticatorData: []const u8,
            signature: []const u8,
        },
    }, body) catch {
        sendError(w, .bad_request, "invalid request body");
        return;
    };

    // clientDataJSON comes as base64url from browser — decode it
    const client_data_json = crypto.base64urlDecodeAlloc(self.config.allocator, req.response.clientDataJSON) catch {
        sendError(w, .bad_request, "invalid clientDataJSON encoding");
        return;
    };
    defer self.config.allocator.free(client_data_json);

    const result = auth.webauthnLoginVerify(
        self.config,
        req.id,
        client_data_json,
        req.response.authenticatorData,
        req.response.signature,
    ) catch |err| {
        switch (err) {
            error.InvalidSignature => sendError(w, .unauthorized, "invalid signature"),
            error.ChallengeNotFound => sendError(w, .bad_request, "challenge not found"),
            error.ChallengeExpired => sendError(w, .bad_request, "challenge expired"),
            error.InvalidChallenge => sendError(w, .bad_request, "invalid challenge"),
            error.DeviceNotFound => sendError(w, .not_found, "credential not found"),
            else => sendError(w, .internal_server_error, "internal error"),
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
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    var cookie_buf: [256]u8 = undefined;
    const cookie = buildSessionCookie(&cookie_buf, &result.tokens.refresh_token, self.config.issuer) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    sendJsonCookie(w, .ok, resp_body, cookie);
}

// --- Session / Logout ---

fn handleSession(self: *Server, headers: []const u8, w: *Io.Writer) void {
    const cookie_val = extractCookie(headers, "ape_session") orelse {
        sendError(w, .unauthorized, "no session");
        return;
    };

    const tokens = auth.refreshTokens(self.config, cookie_val) catch |err| {
        switch (err) {
            error.TokenNotFound, error.TokenExpired => {
                // Clear the bad cookie
                sendJsonCookie(w, .unauthorized, "{\"error\":\"session invalid\"}", "ape_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
            },
            else => sendError(w, .internal_server_error, "internal error"),
        }
        return;
    };
    defer self.config.allocator.free(tokens.id_token);

    const parts = crypto.parseCompoundToken(&tokens.refresh_token).?;

    var body_buf: [2048]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"account_id":"{s}","access_token":"{s}","expires_in":{d}}}
    , .{ parts.account_id, tokens.id_token, tokens.expires_in }) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    var cookie_buf: [256]u8 = undefined;
    const cookie = buildSessionCookie(&cookie_buf, &tokens.refresh_token, self.config.issuer) catch {
        sendError(w, .internal_server_error, "internal error");
        return;
    };

    sendJsonCookie(w, .ok, resp_body, cookie);
}

fn handleLogout(self: *Server, headers: []const u8, w: *Io.Writer) void {
    if (extractCookie(headers, "ape_session")) |cookie_val| {
        auth.revokeRefreshToken(self.config, cookie_val) catch {};
    }
    sendJsonCookie(w, .ok, "{\"ok\":true}", "ape_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
}

fn authenticate(self: *Server, headers: []const u8) auth.AuthError![crypto.uuid_len]u8 {
    const token = extractBearerToken(headers) orelse return auth.AuthError.Unauthorized;
    return (auth.validateToken(self.config, token) catch return auth.AuthError.Unauthorized) orelse return auth.AuthError.Unauthorized;
}

// --- Helpers ---

fn sendJson(w: *Io.Writer, status: std.http.Status, body: []const u8) void {
    var resp_buf: [8192]u8 = undefined;
    const status_str = statusString(status);
    const response = std.fmt.bufPrint(&resp_buf, "HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status_str, body.len, body }) catch "";
    w.writeAll(response) catch {};
    w.flush() catch {};
}

fn sendJsonCookie(w: *Io.Writer, status: std.http.Status, body: []const u8, cookie: []const u8) void {
    var resp_buf: [8192]u8 = undefined;
    const status_str = statusString(status);
    const response = std.fmt.bufPrint(&resp_buf, "HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nSet-Cookie: {s}\r\nConnection: close\r\n\r\n{s}", .{ status_str, body.len, cookie, body }) catch "";
    w.writeAll(response) catch {};
    w.flush() catch {};
}

fn buildSessionCookie(buf: []u8, refresh_token: []const u8, issuer: []const u8) ![]const u8 {
    const secure = std.mem.startsWith(u8, issuer, "https://");
    const secure_attr: []const u8 = if (secure) " Secure;" else "";
    return std.fmt.bufPrint(buf, "ape_session={s}; HttpOnly;{s} SameSite=Lax; Path=/; Max-Age=2592000", .{ refresh_token, secure_attr });
}

fn extractCookie(headers: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        if (asciiStartsWithIgnoreCase(line, "cookie:")) {
            const value = std.mem.trimStart(u8, line["cookie:".len..], " ");
            var pairs = std.mem.splitScalar(u8, value, ';');
            while (pairs.next()) |pair_raw| {
                const pair = std.mem.trim(u8, pair_raw, " ");
                if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
                    if (std.mem.eql(u8, pair[0..eq], name)) {
                        return pair[eq + 1 ..];
                    }
                }
            }
        }
    }
    return null;
}

fn sendHtml(w: *Io.Writer, html: []const u8) void {
    var header_buf: [256]u8 = undefined;
    const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{html.len}) catch return;
    w.writeAll(header) catch {};
    w.writeAll(html) catch {};
    w.flush() catch {};
}

fn sendMethodNotAllowed(w: *Io.Writer, allowed: []const u8) void {
    var buf: [256]u8 = undefined;
    const status_str = statusString(.method_not_allowed);
    const body = "{\"error\":\"method not allowed\"}";
    const response = std.fmt.bufPrint(&buf, "HTTP/1.1 {s}\r\nAllow: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status_str, allowed, body.len, body }) catch "";
    w.writeAll(response) catch {};
    w.flush() catch {};
}

fn sendError(w: *Io.Writer, status: std.http.Status, message: []const u8) void {
    var err_buf: [256]u8 = undefined;
    const err_body = std.fmt.bufPrint(&err_buf, "{{\"error\":\"{s}\"}}", .{message}) catch "{\"error\":\"internal error\"}";
    sendJson(w, status, err_body);
}

fn parseJson(comptime T: type, body: []const u8) !T {
    // Slices in the returned value reference body, not the parse arena,
    // so it's safe to free the arena here. Body outlives the handler scope.
    var parsed = try std.json.parseFromSlice(T, std.heap.page_allocator, body, .{});
    defer parsed.deinit();
    return parsed.value;
}

/// Like parseJson but ignores unknown fields. Used for WebAuthn endpoints
/// where the browser credential response includes extra fields (e.g. "type").
fn parseJsonLenient(comptime T: type, body: []const u8) !T {
    var parsed = try std.json.parseFromSlice(T, std.heap.page_allocator, body, .{
        .ignore_unknown_fields = true,
    });
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
            const value = std.mem.trimStart(u8, line["authorization:".len..], " ");
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

/// Decode percent-encoded bytes (e.g. %3A → ':') into a fixed buffer.
/// Returns null if the output buffer is too small or encoding is malformed.
fn percentDecode(input: []const u8, buf: []u8) ?[]const u8 {
    var i: usize = 0;
    var out: usize = 0;
    while (i < input.len) {
        if (out >= buf.len) return null;
        if (input[i] == '%') {
            if (i + 2 >= input.len) return null;
            const hi = hexVal(input[i + 1]) orelse return null;
            const lo = hexVal(input[i + 2]) orelse return null;
            buf[out] = (@as(u8, hi) << 4) | lo;
            i += 3;
        } else if (input[i] == '+') {
            buf[out] = ' ';
            i += 1;
        } else {
            buf[out] = input[i];
            i += 1;
        }
        out += 1;
    }
    return buf[0..out];
}

fn hexVal(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @truncate(c - '0'),
        'a'...'f' => @truncate(c - 'a' + 10),
        'A'...'F' => @truncate(c - 'A' + 10),
        else => null,
    };
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

test "percentDecode" {
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("abc:def", percentDecode("abc%3Adef", &buf).?);
    try std.testing.expectEqualStrings("hello world", percentDecode("hello+world", &buf).?);
    try std.testing.expectEqualStrings("noop", percentDecode("noop", &buf).?);
    try std.testing.expect(percentDecode("%ZZ", &buf) == null); // invalid hex
}
