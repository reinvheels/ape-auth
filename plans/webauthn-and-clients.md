# WebAuthn + Client Integration Plan

## Overview

Add browser-based passkey authentication (WebAuthn/FIDO2) alongside the existing Ed25519 challenge-response flow. Both paths resolve to the same identity: public key → account_id → tokens.

## Architecture

```
Browser  → WebAuthn  → passkey (P-256)  → /api/auth/webauthn/verify → tokens
Mobile   → Keychain  → Ed25519          → /api/auth/login           → tokens
```

WebAuthn is the browser protocol wrapper. Mobile apps skip it entirely — they have direct secure enclave access.

## Deployment Model

Pulumi component package. Consumer deploys one Ape Auth instance as their shared identity provider. Multiple apps redirect to it via OAuth.

```ts
const auth = new ApeAuth("auth", {
  domain: "auth.myapp.com",
  uiDir: "./my-login-page",  // custom branded UI
});
```

### Routing

Path-based split on the same domain:

```
auth.myapp.com/api/*    → Lambda (Zig)
auth.myapp.com/*        → CloudFront → S3 / Vercel / whatever frontend
```

Zig server owns `/api/*`. Everything else is the consumer's frontend (Next.js, HTMX, static HTML — doesn't matter). Same origin, no CORS.

## Server-Side (Zig)

### New Endpoints

```
POST /api/auth/webauthn/register/options  → PublicKeyCredentialCreationOptions
POST /api/auth/webauthn/register/verify   → verify attestation, store credential
POST /api/auth/webauthn/login/options     → PublicKeyCredentialRequestOptions
POST /api/auth/webauthn/login/verify      → verify assertion, issue tokens
```

### Implementation

- **CBOR decoder** — minimal subset for WebAuthn attestation/assertion parsing (~100-200 lines)
- **ECDSA P-256 verification** — `std.crypto.sign.ecdsa.EcdsaP256Sha256` (Zig std)
- **Authenticator data parsing** — rpIdHash (32B) + flags (1B) + signCount (4B) + attested credential data
- **Credential storage** — extend Device schema with credential_id, cose_public_key, sign_count
- **Credential index** — `credentials/<credential_id_b64>` → account_id (parallel to existing `keys/<pk_hex>`)

### Schema Changes

Device gets a `credential_type` to distinguish:

```
Ed25519 device:  { type: "ed25519", public_key: "<hex>" }
WebAuthn device: { type: "webauthn", credential_id: "<b64>", cose_key: "<b64>", sign_count: N }
```

## Browser UI

The login page needs ~10 lines of JS for the WebAuthn browser API. No way around this — `navigator.credentials.get()` is a JS API, not triggerable from HTML/HTMX alone.

```js
// Login
const options = await fetch("/api/auth/webauthn/login/options").then(r => r.json());
const credential = await navigator.credentials.get({ publicKey: options });
await fetch("/api/auth/webauthn/login/verify", {
  method: "POST",
  body: JSON.stringify(credential),
});
```

Rest of the UI (page layout, navigation, forms) can be anything — HTMX, React, plain HTML.

## Mobile Apps

No WebAuthn needed. Use existing Ed25519 challenge-response directly.

1. Generate Ed25519 keypair, store in secure enclave (iOS Keychain / Android Keystore)
2. Gate key access behind biometrics (Face ID via `LAContext`, fingerprint via `BiometricPrompt`)
3. Sign challenge → `POST /api/auth/login` → tokens

Face ID is a local gate between user and device. Server only sees the Ed25519 signature.

## Multi-Device

- **Passkey sync** — iCloud Keychain / Google Password Manager sync passkeys across devices automatically. Free multi-device for browser users.
- **Ed25519 link** — mobile apps use `POST /api/auth/devices/link` to add devices to an account (existing flow).
- **Cross-type** — a user can have both WebAuthn passkeys (browser) and Ed25519 devices (mobile) on the same account.

## Browser Passkey Picker

When `navigator.credentials.get()` is called without `allowCredentials`, the OS shows a picker listing all passkeys for that domain. User picks which account to sign in with. Multiple accounts in the same browser work natively.
