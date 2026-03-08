# API Testing Plan

## 1. Internal API integration tests ✓

Implemented in `api-tests/` (bun workspace). 24 tests across 8 describe blocks. Run with `bun test` (local) or `bun run test:prod` (against prod).

All planned cases covered: registration, challenge-login, token refresh (single-use), device link/unlink, userinfo, OIDC discovery, JWKS + JWT verification, error cases (405, 401, 409, 400, 404), request validation (empty body, malformed JSON).

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
