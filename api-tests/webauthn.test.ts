import { describe, test, expect } from "bun:test";
import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { BASE_URL, post, get, postForm, authHeader, generateDevice } from "./helpers";

console.log(`WebAuthn tests against: ${BASE_URL}`);

// --- WebAuthn test helpers ---

function base64url(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString("base64url");
}

function generateP256KeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });

  // Extract raw x,y from uncompressed SEC1 point
  const pubRaw = publicKey.export({ type: "spki", format: "der" });
  // SEC1 uncompressed point is the last 65 bytes of the SPKI DER
  const uncompressed = pubRaw.subarray(-65);

  return {
    publicKey,
    privateKey,
    x: uncompressed.subarray(1, 33),
    y: uncompressed.subarray(33, 65),
    uncompressed,
  };
}

/** Build a CBOR-encoded COSE P-256 public key */
function encodeCoseP256Key(x: Buffer, y: Buffer): Buffer {
  // {1: 2, 3: -7, -1: 1, -2: x, -3: y}
  const parts: number[] = [];

  // Map of 5 entries
  parts.push(0xa5);

  // 1: 2 (kty: EC2)
  parts.push(0x01, 0x02);

  // 3: -7 (alg: ES256) — negative 7 = major 1, arg 6 = 0x26
  parts.push(0x03, 0x26);

  // -1: 1 (crv: P-256)
  parts.push(0x20, 0x01);

  // -2: x (32 bytes)
  parts.push(0x21, 0x58, 0x20);
  parts.push(...x);

  // -3: y (32 bytes)
  parts.push(0x22, 0x58, 0x20);
  parts.push(...y);

  return Buffer.from(parts);
}

/** Build a fake attestation object (fmt=none) */
function buildAttestationObject(
  rpId: string,
  credentialId: Buffer,
  coseKey: Buffer,
  signCount: number = 0,
): Buffer {
  const rpIdHash = createHash("sha256").update(rpId).digest();

  // flags: UP (0x01) | AT (0x40) = 0x41
  const flags = 0x41;

  // authenticator data: rpIdHash(32) + flags(1) + signCount(4) + attestedCredData
  // attestedCredData: aaguid(16) + credIdLen(2) + credId + coseKey
  const aaguid = Buffer.alloc(16);
  const credIdLen = Buffer.alloc(2);
  credIdLen.writeUInt16BE(credentialId.length);

  const authData = Buffer.concat([
    rpIdHash,
    Buffer.from([flags]),
    Buffer.alloc(4), // signCount = 0
    aaguid,
    credIdLen,
    credentialId,
    coseKey,
  ]);
  authData.writeUInt32BE(signCount, 33);

  // CBOR encode: {"fmt": "none", "attStmt": {}, "authData": <bytes>}
  const parts: number[] = [];

  // Map of 3 entries
  parts.push(0xa3);

  // "fmt": "none"
  parts.push(0x63); // text(3)
  parts.push(..."fmt".split("").map((c) => c.charCodeAt(0)));
  parts.push(0x64); // text(4)
  parts.push(..."none".split("").map((c) => c.charCodeAt(0)));

  // "attStmt": {}
  parts.push(0x67); // text(7)
  parts.push(..."attStmt".split("").map((c) => c.charCodeAt(0)));
  parts.push(0xa0); // empty map

  // "authData": <bytes>
  parts.push(0x68); // text(8)
  parts.push(..."authData".split("").map((c) => c.charCodeAt(0)));
  // byte string with 2-byte length prefix
  parts.push(0x59); // bytes with 2-byte length
  parts.push((authData.length >> 8) & 0xff, authData.length & 0xff);
  parts.push(...authData);

  return Buffer.from(parts);
}

function buildClientDataJSON(
  type: string,
  challengeB64: string,
  origin: string,
): Buffer {
  return Buffer.from(
    JSON.stringify({
      type,
      challenge: challengeB64,
      origin,
      crossOrigin: false,
    }),
  );
}

/** Sign assertion: ECDSA-P256-SHA256 over (authenticatorData || SHA256(clientDataJSON)) */
function signAssertion(
  privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"],
  authenticatorData: Buffer,
  clientDataJSON: Buffer,
): Buffer {
  const clientDataHash = createHash("sha256").update(clientDataJSON).digest();
  const message = Buffer.concat([authenticatorData, clientDataHash]);
  const sig = createSign("SHA256").update(message).sign(privateKey);
  return sig; // DER-encoded
}

function buildAuthenticatorData(rpId: string, signCount: number = 1): Buffer {
  const rpIdHash = createHash("sha256").update(rpId).digest();
  // flags: UP (0x01) = 0x01
  const flags = 0x01;
  const buf = Buffer.alloc(37);
  rpIdHash.copy(buf, 0);
  buf[32] = flags;
  buf.writeUInt32BE(signCount, 33);
  return buf;
}

function getRpId(): string {
  const url = new URL(BASE_URL);
  return url.hostname;
}

// --- Tests ---

describe("WebAuthn registration", () => {
  test("get registration options", async () => {
    const res = await post("/auth/webauthn/register/options", {
      display_name: "My Passkey",
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.publicKey).toBeDefined();
    expect(body.publicKey.challenge).toBeString();
    expect(body.publicKey.rp.id).toBeString();
    expect(body.publicKey.user.id).toBeString();
    expect(body.publicKey.user.displayName).toBe("My Passkey");
    expect(body.publicKey.pubKeyCredParams).toEqual([
      { type: "public-key", alg: -7 },
    ]);
    expect(body.publicKey.attestation).toBe("none");
  });

  test("full registration + login flow", async () => {
    const rpId = getRpId();
    const origin = BASE_URL;

    // 1. Get registration options
    const optionsRes = await post("/auth/webauthn/register/options", {
      display_name: "Test Passkey",
    });
    expect(optionsRes.status).toBe(200);
    const { publicKey: regOptions } = await optionsRes.json();

    // 2. Simulate browser credential creation
    const kp = generateP256KeyPair();
    const credentialId = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
    const coseKey = encodeCoseP256Key(
      Buffer.from(kp.x),
      Buffer.from(kp.y),
    );
    const attestationObject = buildAttestationObject(
      rpId,
      credentialId,
      coseKey,
    );
    const clientDataJSON = buildClientDataJSON(
      "webauthn.create",
      regOptions.challenge,
      origin,
    );

    const credentialIdB64 = base64url(credentialId);

    // 3. Verify registration
    const verifyRes = await post("/auth/webauthn/register/verify", {
      id: credentialIdB64,
      type: "public-key",
      response: {
        clientDataJSON: base64url(clientDataJSON),
        attestationObject: base64url(attestationObject),
      },
    });
    expect(verifyRes.status).toBe(200);
    const regBody = await verifyRes.json();
    expect(regBody.account_id).toBeString();
    expect(regBody.device_id).toBeString();
    expect(regBody.id_token).toBeString();
    expect(regBody.access_token).toBeString();
    expect(regBody.refresh_token).toBeString();

    // 4. Verify tokens work — userinfo
    const userinfoRes = await get(
      "/userinfo",
      authHeader(regBody.access_token),
    );
    expect(userinfoRes.status).toBe(200);
    const userinfo = await userinfoRes.json();
    expect(userinfo.sub).toBe(regBody.account_id);

    // 5. Token refresh works
    const refreshRes = await postForm("/token", {
      grant_type: "refresh_token",
      refresh_token: regBody.refresh_token,
    });
    expect(refreshRes.status).toBe(200);
    const refreshBody = await refreshRes.json();
    expect(refreshBody.id_token).toBeString();

    // 6. Login with passkey
    const loginOptRes = await post("/auth/webauthn/login/options", {});
    expect(loginOptRes.status).toBe(200);
    const { publicKey: loginOptions } = await loginOptRes.json();

    const loginClientDataJSON = buildClientDataJSON(
      "webauthn.get",
      loginOptions.challenge,
      origin,
    );
    const authenticatorData = buildAuthenticatorData(rpId);
    const signature = signAssertion(
      kp.privateKey,
      authenticatorData,
      loginClientDataJSON,
    );

    const loginVerifyRes = await post("/auth/webauthn/login/verify", {
      id: credentialIdB64,
      type: "public-key",
      response: {
        clientDataJSON: base64url(loginClientDataJSON),
        authenticatorData: base64url(authenticatorData),
        signature: base64url(signature),
      },
    });
    expect(loginVerifyRes.status).toBe(200);
    const loginBody = await loginVerifyRes.json();
    expect(loginBody.account_id).toBe(regBody.account_id);
    expect(loginBody.id_token).toBeString();
    expect(loginBody.refresh_token).toBeString();
  });
});

describe("passkey account with linked ed25519 device", () => {
  test("/auth/account lists both passkey and ed25519 with kind field", async () => {
    const rpId = getRpId();
    const origin = BASE_URL;

    // 1. Register a passkey (creates account)
    const optionsRes = await post("/auth/webauthn/register/options", {
      display_name: "Bitwarden John",
    });
    const { publicKey: regOptions } = await optionsRes.json();

    const kp = generateP256KeyPair();
    const credentialId = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
    const coseKey = encodeCoseP256Key(Buffer.from(kp.x), Buffer.from(kp.y));
    const attestationObject = buildAttestationObject(rpId, credentialId, coseKey);
    const clientDataJSON = buildClientDataJSON(
      "webauthn.create",
      regOptions.challenge,
      origin,
    );

    const verifyRes = await post("/auth/webauthn/register/verify", {
      id: base64url(credentialId),
      type: "public-key",
      response: {
        clientDataJSON: base64url(clientDataJSON),
        attestationObject: base64url(attestationObject),
      },
    });
    expect(verifyRes.status).toBe(200);
    const regBody = await verifyRes.json();
    const passkeyDeviceId = regBody.device_id;

    // 2. Link an Ed25519 device to that same account
    const cli = generateDevice();
    const linkRes = await post(
      "/auth/devices/link",
      { public_key: cli.publicKeyHex, device_name: "my-cli" },
      authHeader(regBody.access_token),
    );
    expect(linkRes.status).toBe(200);
    const { device_id: cliDeviceId } = await linkRes.json();

    // 3. /auth/account lists both, with correct kind
    const accRes = await get("/auth/account", authHeader(regBody.access_token));
    expect(accRes.status).toBe(200);
    const account = await accRes.json();

    expect(account.devices.length).toBe(2);
    const byId = new Map(
      account.devices.map((d: { id: string; kind: string; name: string }) => [d.id, d]),
    );
    const passkey = byId.get(passkeyDeviceId) as { kind: string; name: string };
    const cliDev = byId.get(cliDeviceId) as { kind: string; name: string };
    expect(passkey.kind).toBe("passkey");
    expect(passkey.name).toBe("Bitwarden John");
    expect(cliDev.kind).toBe("ed25519");
    expect(cliDev.name).toBe("my-cli");
  });
});

describe("WebAuthn error cases", () => {
  test("login with unregistered credential returns 404", async () => {
    const rpId = getRpId();

    const loginOptRes = await post("/auth/webauthn/login/options", {});
    const { publicKey: loginOptions } = await loginOptRes.json();

    const kp = generateP256KeyPair();
    const clientDataJSON = buildClientDataJSON(
      "webauthn.get",
      loginOptions.challenge,
      BASE_URL,
    );
    const authenticatorData = buildAuthenticatorData(rpId);
    const signature = signAssertion(
      kp.privateKey,
      authenticatorData,
      clientDataJSON,
    );

    const res = await post("/auth/webauthn/login/verify", {
      id: base64url(Buffer.from(crypto.getRandomValues(new Uint8Array(32)))),
      type: "public-key",
      response: {
        clientDataJSON: base64url(clientDataJSON),
        authenticatorData: base64url(authenticatorData),
        signature: base64url(signature),
      },
    });
    expect(res.status).toBe(404);
  });

  test("register verify with expired/invalid challenge returns 400", async () => {
    const rpId = getRpId();
    const kp = generateP256KeyPair();
    const credentialId = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
    const coseKey = encodeCoseP256Key(
      Buffer.from(kp.x),
      Buffer.from(kp.y),
    );
    const attestationObject = buildAttestationObject(rpId, credentialId, coseKey);

    // Use a fake challenge that was never issued
    const clientDataJSON = buildClientDataJSON(
      "webauthn.create",
      "fake-challenge-never-issued",
      BASE_URL,
    );

    const res = await post("/auth/webauthn/register/verify", {
      id: base64url(credentialId),
      type: "public-key",
      response: {
        clientDataJSON: base64url(clientDataJSON),
        attestationObject: base64url(attestationObject),
      },
    });
    expect(res.status).toBe(400);
  });

  test("login verify with wrong signature returns 401", async () => {
    const rpId = getRpId();
    const origin = BASE_URL;

    // First register a credential
    const optionsRes = await post("/auth/webauthn/register/options", {
      display_name: "Bad Sig Test",
    });
    const { publicKey: regOptions } = await optionsRes.json();

    const kp = generateP256KeyPair();
    const credentialId = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
    const coseKey = encodeCoseP256Key(Buffer.from(kp.x), Buffer.from(kp.y));
    const attestationObject = buildAttestationObject(rpId, credentialId, coseKey);
    const clientDataJSON = buildClientDataJSON(
      "webauthn.create",
      regOptions.challenge,
      origin,
    );

    await post("/auth/webauthn/register/verify", {
      id: base64url(credentialId),
      type: "public-key",
      response: {
        clientDataJSON: base64url(clientDataJSON),
        attestationObject: base64url(attestationObject),
      },
    });

    // Now login with wrong key
    const wrongKp = generateP256KeyPair();
    const loginOptRes = await post("/auth/webauthn/login/options", {});
    const { publicKey: loginOptions } = await loginOptRes.json();

    const loginClientDataJSON = buildClientDataJSON(
      "webauthn.get",
      loginOptions.challenge,
      origin,
    );
    const authenticatorData = buildAuthenticatorData(rpId);
    const wrongSig = signAssertion(
      wrongKp.privateKey,
      authenticatorData,
      loginClientDataJSON,
    );

    const res = await post("/auth/webauthn/login/verify", {
      id: base64url(credentialId),
      type: "public-key",
      response: {
        clientDataJSON: base64url(loginClientDataJSON),
        authenticatorData: base64url(authenticatorData),
        signature: base64url(wrongSig),
      },
    });
    expect(res.status).toBe(401);
  });
});
