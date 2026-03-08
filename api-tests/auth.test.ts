import { describe, test, expect } from "bun:test";
import {
  BASE_URL,
  generateDevice,
  post,
  postForm,
  get,
  authHeader,
  registerDevice,
  loginDevice,
} from "./helpers";

console.log(`Testing against: ${BASE_URL}`);

// ─── OIDC Discovery ──────────────────────────────────────────────

describe("OIDC discovery", () => {
  test("GET /.well-known/openid-configuration", async () => {
    const res = await get("/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.issuer).toBeString();
    expect(body.token_endpoint).toContain("/token");
    expect(body.jwks_uri).toContain("/.well-known/jwks.json");
    expect(body.userinfo_endpoint).toContain("/userinfo");
    expect(body.id_token_signing_alg_values_supported).toContain("EdDSA");
  });

  test("GET /.well-known/jwks.json", async () => {
    const res = await get("/.well-known/jwks.json");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.keys).toBeArray();
    expect(body.keys.length).toBeGreaterThanOrEqual(1);
    const key = body.keys[0];
    expect(key.kty).toBe("OKP");
    expect(key.crv).toBe("Ed25519");
    expect(key.alg).toBe("EdDSA");
    expect(key.x).toBeString();
  });
});

// ─── Health ──────────────────────────────────────────────────────

describe("health", () => {
  test("GET /health", async () => {
    const res = await get("/health");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("ok");
  });
});

// ─── Registration ────────────────────────────────────────────────

describe("registration", () => {
  test("register new device", async () => {
    const { res, body } = await registerDevice();
    expect(res.status).toBe(200);
    expect(body.account_id).toBeString();
    expect(body.device_id).toBeString();
    expect(body.id_token).toBeString();
    expect(body.access_token).toBeString();
    expect(body.refresh_token).toBeString();
    expect(body.expires_in).toBe(3600);
  });

  test("duplicate registration returns 409", async () => {
    const { device } = await registerDevice();
    const res = await post("/auth/register", {
      public_key: device.publicKeyHex,
      device_name: "duplicate",
    });
    expect(res.status).toBe(409);
  });

  test("invalid public key returns 400", async () => {
    const res = await post("/auth/register", {
      public_key: "not-valid-hex",
      device_name: "bad",
    });
    expect(res.status).toBe(400);
  });

  test("empty body returns 400", async () => {
    const res = await fetch(`${BASE_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    expect(res.status).toBe(400);
  });
});

// ─── Challenge-Login ─────────────────────────────────────────────

describe("challenge-login", () => {
  test("full challenge-login flow", async () => {
    const { device, body: regBody } = await registerDevice();
    const { loginRes, body } = await loginDevice(device);

    expect(loginRes.status).toBe(200);
    expect(body.account_id).toBe(regBody.account_id);
    expect(body.id_token).toBeString();
    expect(body.access_token).toBeString();
    expect(body.refresh_token).toBeString();
    expect(body.expires_in).toBe(3600);
  });

  test("challenge for unregistered key returns 404", async () => {
    const device = generateDevice();
    const res = await post("/auth/challenge", {
      public_key: device.publicKeyHex,
    });
    expect(res.status).toBe(404);
  });

  test("invalid signature returns 401", async () => {
    const { device } = await registerDevice();
    const challengeRes = await post("/auth/challenge", {
      public_key: device.publicKeyHex,
    });
    const { challenge } = await challengeRes.json();

    const res = await post("/auth/login", {
      public_key: device.publicKeyHex,
      challenge,
      signature: "aa".repeat(64), // wrong signature
    });
    expect(res.status).toBe(401);
  });
});

// ─── Token Refresh ───────────────────────────────────────────────

describe("token refresh", () => {
  test("refresh token returns new tokens", async () => {
    const { body: regBody } = await registerDevice();
    const res = await postForm("/token", {
      grant_type: "refresh_token",
      refresh_token: regBody.refresh_token,
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.id_token).toBeString();
    expect(body.access_token).toBeString();
    expect(body.token_type).toBe("Bearer");
    expect(body.refresh_token).toBeString();
    // new refresh token should differ (single-use)
    expect(body.refresh_token).not.toBe(regBody.refresh_token);
  });

  test("reusing old refresh token returns 401", async () => {
    const { body: regBody } = await registerDevice();
    // use it once
    await postForm("/token", {
      grant_type: "refresh_token",
      refresh_token: regBody.refresh_token,
    });
    // use it again — should fail
    const res = await postForm("/token", {
      grant_type: "refresh_token",
      refresh_token: regBody.refresh_token,
    });
    expect(res.status).toBe(401);
  });

  test("invalid refresh token returns 401", async () => {
    const res = await postForm("/token", {
      grant_type: "refresh_token",
      refresh_token: "bogus",
    });
    expect(res.status).toBe(401);
  });

  test("unsupported grant_type returns 400", async () => {
    const res = await postForm("/token", {
      grant_type: "authorization_code",
      code: "abc",
    });
    expect(res.status).toBe(400);
  });
});

// ─── Userinfo ────────────────────────────────────────────────────

describe("userinfo", () => {
  test("returns sub matching account_id", async () => {
    const { body: regBody } = await registerDevice();
    const res = await get("/userinfo", authHeader(regBody.access_token));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.sub).toBe(regBody.account_id);
  });

  test("missing bearer token returns 401", async () => {
    const res = await get("/userinfo");
    expect(res.status).toBe(401);
  });

  test("invalid bearer token returns 401", async () => {
    const res = await get("/userinfo", authHeader("invalid.jwt.token"));
    expect(res.status).toBe(401);
  });
});

// ─── Device Management ───────────────────────────────────────────

describe("device management", () => {
  test("link, verify, unlink device", async () => {
    const { body: regBody } = await registerDevice("primary");
    const secondary = generateDevice();

    // link second device
    const linkRes = await post(
      "/auth/devices/link",
      { public_key: secondary.publicKeyHex, device_name: "secondary" },
      authHeader(regBody.access_token)
    );
    expect(linkRes.status).toBe(200);
    const { device_id: secondaryId } = await linkRes.json();
    expect(secondaryId).toBeString();

    // verify in account info
    const accountRes = await get(
      "/auth/account",
      authHeader(regBody.access_token)
    );
    expect(accountRes.status).toBe(200);
    const account = await accountRes.json();
    expect(account.devices.length).toBe(2);
    const deviceIds = account.devices.map((d: { id: string }) => d.id);
    expect(deviceIds).toContain(secondaryId);

    // secondary device can log in independently
    const { loginRes } = await loginDevice(secondary);
    expect(loginRes.status).toBe(200);

    // unlink secondary
    const unlinkRes = await post(
      "/auth/devices/unlink",
      { device_id: secondaryId },
      authHeader(regBody.access_token)
    );
    expect(unlinkRes.status).toBe(200);

    // verify removed
    const accountRes2 = await get(
      "/auth/account",
      authHeader(regBody.access_token)
    );
    const account2 = await accountRes2.json();
    expect(account2.devices.length).toBe(1);
  });

  test("cannot unlink last device", async () => {
    const { body: regBody } = await registerDevice();
    const res = await post(
      "/auth/devices/unlink",
      { device_id: regBody.device_id },
      authHeader(regBody.access_token)
    );
    expect(res.status).toBe(400);
  });

  test("link duplicate device returns 409", async () => {
    const { device, body: regBody } = await registerDevice();
    const res = await post(
      "/auth/devices/link",
      { public_key: device.publicKeyHex, device_name: "dup" },
      authHeader(regBody.access_token)
    );
    expect(res.status).toBe(409);
  });
});

// ─── JWKS Verification ──────────────────────────────────────────

describe("JWKS token verification", () => {
  test("JWT from register can be verified via JWKS public key", async () => {
    const { body: regBody } = await registerDevice();
    const jwksRes = await get("/.well-known/jwks.json");
    const { keys } = await jwksRes.json();

    // decode JWT
    const parts = regBody.id_token.split(".");
    expect(parts.length).toBe(3);

    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString()
    );
    expect(payload.sub).toBe(regBody.account_id);
    expect(payload.iss).toBeString();
    expect(payload.iat).toBeNumber();
    expect(payload.exp).toBeNumber();
    expect(payload.exp - payload.iat).toBe(3600);

    // verify signature using JWKS key
    const { createPublicKey, verify } = await import("node:crypto");
    const jwk = { ...keys[0], key_ops: ["verify"] };
    const publicKey = createPublicKey({ key: jwk, format: "jwk" });
    const message = Buffer.from(`${parts[0]}.${parts[1]}`);
    const signature = Buffer.from(parts[2], "base64url");
    const valid = verify(null, message, publicKey, signature);
    expect(valid).toBe(true);
  });
});

// ─── Error Cases ─────────────────────────────────────────────────

describe("error cases", () => {
  test("wrong method returns 405", async () => {
    const res = await fetch(`${BASE_URL}/auth/register`, { method: "GET" });
    expect(res.status).toBe(405);
  });

  test("unknown route returns 404", async () => {
    const res = await get("/nonexistent");
    expect(res.status).toBe(404);
  });

  test("malformed JSON returns 400", async () => {
    const res = await fetch(`${BASE_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{invalid json",
    });
    expect(res.status).toBe(400);
  });
});
