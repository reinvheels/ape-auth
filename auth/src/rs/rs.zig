//! Example resource server bundled with the IDP for demo purposes.
//!
//! Responsibilities (RS, not IDP):
//!  - Serve the browser UI (index.html)
//!  - Trade a refresh token for an HttpOnly cookie session
//!  - Rotate the cookie on each /rs/session GET
//!  - Clear the cookie and revoke the token on logout

const std = @import("std");
const Io = std.Io;
const crypto = @import("../crypto.zig");
const auth = @import("../auth.zig");

pub const index_html = @embedFile("index.html");

const clear_cookie = "ape_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";

pub fn handleIndex(w: *Io.Writer) void {
    var header_buf: [256]u8 = undefined;
    const header = std.fmt.bufPrint(
        &header_buf,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{index_html.len},
    ) catch return;
    w.writeAll(header) catch {};
    w.writeAll(index_html) catch {};
    w.flush() catch {};
}

/// GET /rs/session — cookie-based session check. Rotates the refresh token.
pub fn handleSessionGet(config: auth.Config, headers: []const u8, w: *Io.Writer) void {
    const cookie_val = extractCookie(headers, "ape_session") orelse {
        sendJson(w, "401 Unauthorized", "{\"error\":\"no session\"}", null);
        return;
    };
    rotateAndRespond(config, cookie_val, w);
}

/// POST /rs/session — trade a refresh_token for an HttpOnly cookie session.
/// The browser calls this right after WebAuthn register/login verify.
pub fn handleSessionCreate(config: auth.Config, body: []const u8, w: *Io.Writer) void {
    const Req = struct { refresh_token: []const u8 };
    const parsed = std.json.parseFromSlice(Req, config.allocator, body, .{ .ignore_unknown_fields = true }) catch {
        sendJson(w, "400 Bad Request", "{\"error\":\"invalid body\"}", null);
        return;
    };
    defer parsed.deinit();
    rotateAndRespond(config, parsed.value.refresh_token, w);
}

/// POST /rs/logout — revoke the cookie's refresh token and clear the cookie.
pub fn handleLogout(config: auth.Config, headers: []const u8, w: *Io.Writer) void {
    if (extractCookie(headers, "ape_session")) |cookie_val| {
        auth.revokeRefreshToken(config, cookie_val) catch {};
    }
    sendJson(w, "200 OK", "{\"ok\":true}", clear_cookie);
}

fn rotateAndRespond(config: auth.Config, refresh_token: []const u8, w: *Io.Writer) void {
    const tokens = auth.refreshTokens(config, refresh_token) catch |err| {
        switch (err) {
            error.TokenNotFound, error.TokenExpired => {
                sendJson(w, "401 Unauthorized", "{\"error\":\"session invalid\"}", clear_cookie);
            },
            else => sendJson(w, "500 Internal Server Error", "{\"error\":\"internal error\"}", null),
        }
        return;
    };
    defer config.allocator.free(tokens.id_token);

    const parts = crypto.parseCompoundToken(&tokens.refresh_token).?;

    var body_buf: [2048]u8 = undefined;
    const resp_body = std.fmt.bufPrint(&body_buf,
        \\{{"account_id":"{s}","access_token":"{s}","expires_in":{d}}}
    , .{ parts.account_id, tokens.id_token, tokens.expires_in }) catch {
        sendJson(w, "500 Internal Server Error", "{\"error\":\"internal error\"}", null);
        return;
    };

    var cookie_buf: [256]u8 = undefined;
    const cookie = buildSessionCookie(&cookie_buf, &tokens.refresh_token, config.issuer) catch {
        sendJson(w, "500 Internal Server Error", "{\"error\":\"internal error\"}", null);
        return;
    };

    sendJson(w, "200 OK", resp_body, cookie);
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

fn sendJson(w: *Io.Writer, status: []const u8, body: []const u8, cookie: ?[]const u8) void {
    var resp_buf: [8192]u8 = undefined;
    const response = if (cookie) |c|
        std.fmt.bufPrint(&resp_buf, "HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nSet-Cookie: {s}\r\nConnection: close\r\n\r\n{s}", .{ status, body.len, c, body }) catch ""
    else
        std.fmt.bufPrint(&resp_buf, "HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status, body.len, body }) catch "";
    w.writeAll(response) catch {};
    w.flush() catch {};
}

fn asciiStartsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    for (haystack[0..needle.len], needle) |h, n| {
        if (std.ascii.toLower(h) != std.ascii.toLower(n)) return false;
    }
    return true;
}
