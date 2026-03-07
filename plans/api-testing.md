# API Testing Plan

## 1. Internal API integration tests

End-to-end tests that hit the HTTP server endpoints. Write as a shell script or Zig test binary against a running server instance.

### Device auth flow

- **Registration** — `POST /auth/register` → response has account_id, device_id, id_token, access_token, refresh_token
- **Challenge-login** — register → `POST /auth/challenge` → sign nonce with Ed25519 → `POST /auth/login` → verify tokens
- **Token refresh** — login → `POST /token` (grant_type=refresh_token) → verify new tokens, old refresh token invalidated (single-use)
- **Device link/unlink** — authenticated `POST /auth/devices/link` → verify in `GET /auth/account` → unlink → verify removed → cannot unlink last device (400)
- **Userinfo** — `GET /userinfo` with bearer token → verify `{"sub":"<account_id>"}`

### OIDC endpoints

- **Discovery** — `GET /.well-known/openid-configuration` → validate required fields (issuer, token_endpoint, jwks_uri, etc.)
- **JWKS** — `GET /.well-known/jwks.json` → validate key format (kty=OKP, crv=Ed25519, alg=EdDSA), use key to verify a JWT from `/token`

### Error cases

- Wrong HTTP method → 405 with Allow header
- Wrong Content-Type → 400
- Invalid signature on login → 401
- Expired challenge → 400
- Expired/invalid refresh token → 401
- Duplicate device registration → 409
- Unlink last device → 400
- Missing/invalid bearer token → 401

### Request validation

- Empty body on POST endpoints → 400
- Malformed JSON → 400
- Missing required fields → 400

## 2. OAuth/OIDC conformance (after authorization code flow is implemented)

Depends on: `GET /authorize`, `POST /token` with authorization_code grant, PKCE, client registration.

### OpenID Connect Conformance Suite

- Official OIDC Foundation test suite: https://www.certification.openid.net/
- Can run locally via Docker
- Tests discovery, token endpoint, userinfo, JWKS, ID token validation

### Auth.js integration test

- Minimal Next.js app with Auth.js configured against our IDP
- Verify full browser OAuth flow: redirect → authenticate → callback → session

### RFC compliance checks

- RFC 6749 (OAuth 2.0) — authorization code grant, error responses, token format
- RFC 7636 (PKCE) — code_verifier/code_challenge
- RFC 6750 (Bearer tokens) — Authorization header, error responses
- OpenID Connect Core 1.0 — ID token claims, userinfo response, discovery document
