# Standards Assessment: Ape Auth vs Ory Hydra

Comparison of OAuth/OIDC standards implemented by Ory Hydra against Ape Auth's current state and roadmap.

## Currently Implemented (partial)

| Standard | Status |
|----------|--------|
| [RFC 6749 — OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749) | Partial — `/token` endpoint exists (refresh_token grant only). Authorization code flow is TODO |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Partial — `/.well-known/openid-configuration` and `/.well-known/jwks.json` exist |
| [OpenID Connect Core 1.0](http://openid.net/specs/openid-connect-core-1_0.html) | Partial — `id_token` JWTs issued, `/userinfo` endpoint exists, but no full OIDC flows yet |

## Should Add

| Standard | Why |
|----------|-----|
| [RFC 7636 — PKCE](https://tools.ietf.org/html/rfc7636) | Essential for public clients (SPAs, CLIs, native apps). Already in TODO. Required by modern best practices |
| [RFC 6749 — authorization_code grant](https://tools.ietf.org/html/rfc6749) | Already in TODO. Needed for browser-based Auth.js flows |
| [RFC 7009 — Token Revocation](https://tools.ietf.org/html/rfc7009) | Simple endpoint (`POST /revoke`). Refresh token storage already exists — just need the endpoint |
| [OAuth 2.0 for Native Apps (RFC 8252)](https://tools.ietf.org/html/draft-ietf-oauth-native-apps-10) | Guidance for CLI flow. Mostly about using PKCE + loopback redirects — not much code, just following the pattern |

## Not Applicable (for now)

These standards solve problems that don't exist in Ape Auth's trusted-app model. They become relevant if the project expands to support untrusted third-party clients.

| Standard | Why not applicable |
|----------|-----|
| [RFC 7662 — Token Introspection](https://tools.ietf.org/html/rfc7662) | Apps verify JWTs directly via JWKS. Only needed for opaque access tokens |
| [RFC 7591 — Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591) | Trusted app model — no need for dynamic registration unless third-party apps are supported |
| [RFC 7592 — Dynamic Client Registration Management](https://datatracker.ietf.org/doc/html/rfc7592) | Same as above |
| [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html) | Same as above |
| [RFC 7523 — JWT Client Authentication](https://tools.ietf.org/html/rfc7523) | Clients use device keypairs directly, not OAuth client credentials |
| [RFC 6819 — Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819) | Guidance document, not an implementation. Worth reading but nothing to build |
| [OIDC Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html) | Stateless JWT model — no server-side sessions to propagate logout across |
| [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | Same — logout propagation across multiple apps is overkill for trusted-app model |

## Summary

Ory Hydra is a general-purpose OAuth server for multi-tenant, third-party-app scenarios. Ape Auth is purpose-built for a trusted-app model with device-based auth. The priority additions are **authorization_code + PKCE** (already planned) and **token revocation**. Most of the remaining standards only matter if the project expands to untrusted third-party clients.
