import { sign, generateKeyPairSync, createPublicKey } from "node:crypto";

export const BASE_URL =
  process.env.BASE_URL?.replace(/\/$/, "") || "http://localhost:8080";

export interface KeyPair {
  publicKeyHex: string;
  privateKeyRaw: Buffer;
  signChallenge: (challengeHex: string) => string;
}

export function generateDevice(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  const publicKeyRaw = publicKey
    .export({ type: "spki", format: "der" })
    .subarray(-32);
  const privateKeyRaw = Buffer.from(
    privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32)
  );

  return {
    publicKeyHex: publicKeyRaw.toString("hex"),
    privateKeyRaw,
    signChallenge(challengeHex: string): string {
      const challengeBytes = Buffer.from(challengeHex, "hex");
      const sig = sign(null, challengeBytes, privateKey);
      return Buffer.from(sig).toString("hex");
    },
  };
}

export async function post(
  path: string,
  body: Record<string, unknown>,
  headers?: Record<string, string>
) {
  return fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

export async function postForm(
  path: string,
  params: Record<string, string>,
  headers?: Record<string, string>
) {
  return fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams(params).toString(),
  });
}

export async function get(path: string, headers?: Record<string, string>) {
  return fetch(`${BASE_URL}${path}`, { headers });
}

export function authHeader(token: string) {
  return { Authorization: `Bearer ${token}` };
}

/** Register a new device and return all tokens + metadata. */
export async function registerDevice(deviceName = "test-device") {
  const device = generateDevice();
  const res = await post("/auth/register", {
    public_key: device.publicKeyHex,
    device_name: deviceName,
  });
  const body = await res.json();
  return { device, res, body };
}

/** Full challenge-login flow. Device must already be registered. */
export async function loginDevice(device: KeyPair) {
  const challengeRes = await post("/auth/challenge", {
    public_key: device.publicKeyHex,
  });
  const { challenge } = await challengeRes.json();
  const signature = device.signChallenge(challenge);

  const loginRes = await post("/auth/login", {
    public_key: device.publicKeyHex,
    challenge,
    signature,
  });
  const body = await loginRes.json();
  return { loginRes, body };
}
