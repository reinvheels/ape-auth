# Ape Auth

OAuth 2.0 identity provider built in Zig. Device-based authentication — no passwords, no email/SMS verification. Users authenticate via trusted devices (Ed25519 keypairs) and can link additional devices for account recovery.

## Architecture

```
┌──────────────┐       ┌──────────────────┐       ┌──────────────┐
│  App          │──────►│  Ape Auth (Zig)  │──────►│  Storage     │
│  (Auth.js /  │ OAuth │  Authorization   │       │  (FS per-    │
│   any OAuth  │◄──────│  + Device auth   │◄──────│   account)   │
│   client)    │       │                  │       │              │
└──────────────┘       └──────────────────┘       └──────────────┘
```

### How It Works

- **Standard OAuth 2.0 provider** — implements authorization code flow so any OAuth client (Auth.js, Passport, etc.) can integrate
- **Device-based authentication** — instead of passwords, users prove identity via Ed25519 challenge-response from a trusted device. This is the authentication method *within* the OAuth authorization endpoint
- **File-per-account persistence** — each account persisted to its own JSON file on mutation (atomic tmp+rename). UUID-based directory sharding
- **HMAC-signed access tokens** — access tokens are self-contained (no server-side storage), validated via HMAC-SHA256. Only refresh tokens are persisted (single-use)
- **Multi-device recovery** — users link additional devices; any linked device can restore access
- **Runs in always-warm Lambda** — designed for Lambda + EFS, but runs standalone too

### OAuth Flow

```
1. App redirects user to  GET /authorize?client_id=...&redirect_uri=...
2. Ape Auth presents device auth challenge
3. User's device signs challenge with Ed25519 keypair
4. Ape Auth verifies signature, issues authorization code
5. App exchanges code for tokens  POST /token  (back-channel)
6. App calls  GET /userinfo  with access token to get user identity
7. App creates its own session (e.g. Auth.js JWT)
```

### Device Auth (within authorization endpoint)

```
1. Device generates Ed25519 keypair (first time → register, subsequent → login)
2. POST /auth/challenge  →  server returns nonce
3. Device signs nonce  →  POST /auth/login  →  server verifies, issues tokens
4. User links additional devices  →  POST /auth/devices/link
5. If primary device lost, authenticate from any linked device
```

## Project Structure

pnpm monorepo:

```
ape-auth/
├── CLAUDE.md
├── package.json              # workspace root
├── pnpm-workspace.yaml
├── auth/                     # Zig HTTP server (identity provider)
│   ├── build.zig
│   ├── build.zig.zon
│   └── src/
├── infra/                    # Pulumi (TypeScript) — AWS infrastructure
│   ├── Pulumi.yaml
│   ├── index.ts
│   ├── package.json
│   └── tsconfig.json
└── ...
```

## Implementation

### Auth Server (Zig)

HTTP server exposing OAuth and device auth endpoints. Built with Zig's standard library TCP server.

#### Current endpoints (device auth layer):
- `POST /auth/register` — create account from device keypair
- `POST /auth/challenge` — get a nonce to sign
- `POST /auth/login` — authenticate with signed challenge
- `POST /auth/devices/link` — link additional device to account
- `POST /auth/devices/unlink` — unlink device
- `POST /auth/token/refresh` — refresh tokens (consumes refresh token)
- `GET /auth/account` — get account info + linked devices
- `GET /health` — health check

#### TODO — OAuth 2.0 layer:
- `GET /authorize` — authorization endpoint (renders device auth UI, issues authorization codes)
- `POST /token` — token endpoint (exchanges authorization code for access + refresh tokens)
- `GET /userinfo` — returns user identity (sub/account_id) from access token
- Client registration / management
- PKCE support

#### Data storage:
- File-per-account persistence — each account written to its own JSON file on every mutation (atomic tmp+rename)
- UUID directory sharding: dashes replaced with `/` → 4-level directory tree
- Key index: `keys/<public_key_hex>` → account_id (for device lookup)
- Server secret: `server.key` (HMAC signing key for access tokens, generated on first run)

#### Token model:
- **Access tokens** — HMAC-signed, self-contained (`account_id:expires_hex:hmac_hex`), validated without I/O. Short-lived (1h). Will move to Ed25519-signed for client-verifiable tokens when OAuth layer is added.
- **Refresh tokens** — opaque, stored in account file, single-use (consumed and replaced). Long-lived (30d).

### Infrastructure (Pulumi / TypeScript)

Pulumi project in `infra/`. Package manager: pnpm.

#### Stack Config (`puc` / SSM)

Stack config is managed via `puc` (pulumi-config) and stored in AWS SSM, not in git.

```bash
puc env           # print PULUMI_BACKEND_URL and PULUMI_CONFIG_PASSPHRASE
puc pull prod     # pull config to Pulumi.prod.yaml
puc push prod     # push config to SSM
```

#### Target deployment

- AWS Lambda (always-warm / provisioned concurrency) with function URL or API Gateway
- EFS mount for persistent per-account storage
- Zig binary cross-compiled for `aarch64-linux` (Lambda ARM runtime)

### Files

- `auth/src/main.zig` — entry point, starts TCP server, loads/generates server secret
- `auth/src/crypto.zig` — constants, UUID/token generation, hex encode/decode, HMAC access token create/validate
- `auth/src/auth.zig` — auth logic (register, login, challenge, token refresh, device link/unlink)
- `auth/src/Server.zig` — HTTP request routing, response handling, JSON request parsing
- `auth/src/schema.zig` — persistence data types (Account, Device, Token, Challenge), JSON serialize/parse
- `auth/src/persist.zig` — file-per-account persistence (accountPath, openAndLock, writeAndUnlock, key index)
- `infra/index.ts` — main infrastructure (Lambda, EFS, IAM, API Gateway)
- `infra/Pulumi.yaml` — project config
- `infra/Pulumi.prod.yaml` — stack config (gitignored, managed via `puc`)
