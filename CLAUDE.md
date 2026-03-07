# Ape Auth

Identity provider built in Zig. One thing: prove who you are. Device-based authentication — no passwords, no email/SMS verification. Users authenticate via trusted devices (Ed25519 keypairs) and can link additional devices for account recovery.

Ape Auth answers "this is account X." Apps decide what X is allowed to do.

## Architecture

```
┌──────────────┐ OAuth  ┌──────────────────┐       ┌──────────────┐
│  Browser app │───────►│                  │──────►│              │
│  (Auth.js)   │◄───────│                  │       │   Storage    │
├──────────────┤        │   Ape Auth (Zig) │       │  (FS per-    │
│  CLI / API   │─ HTTP ─│                  │◄──────│   account)   │
│  client      │◄───────│   Ed25519 key    │       │              │
├──────────────┤        │   → account_id   │       │              │
│  Git / SSH   │─ SSH ──│                  │       │              │
│  client      │◄───────│                  │       │              │
└──────────────┘        └──────────────────┘       └──────────────┘
```

### Core Principle

All three entry points resolve the same question: which public key → which account. The transport differs, the identity layer is the same.

### How It Works

- **Ed25519 identity** — each account is a collection of public keys. Any key can prove the account's identity
- **File-per-account persistence** — each account persisted to its own JSON file on mutation (atomic tmp+rename). UUID-based directory sharding
- **HMAC-signed access tokens** — self-contained, validated without I/O. Opaque to clients — apps call `/userinfo` to get identity
- **Multi-device recovery** — users link additional devices; any linked device can restore access
- **Runs in always-warm Lambda** — designed for Lambda + EFS, but runs standalone too

### Entry Points

#### 1. Browser apps — OAuth 2.0 authorization code flow

For web apps using Auth.js, Passport, or any OAuth client library.

```
1. App redirects user to  GET /authorize?client_id=...&redirect_uri=...
2. Ape Auth presents device auth challenge
3. User's device signs challenge with Ed25519 keypair
4. Ape Auth verifies signature, issues authorization code
5. App exchanges code for tokens  POST /token  (back-channel)
6. App calls  GET /userinfo  with access token to get user identity
7. App creates its own session (e.g. Auth.js JWT), discards tokens
```

#### 2. CLI / programmatic clients — direct challenge-response over HTTP

For CLIs and API clients that don't need browser redirects.

```
1. CLI has an Ed25519 keypair (registered or linked to account)
2. POST /auth/challenge  →  server returns nonce
3. CLI signs nonce  →  POST /auth/login  →  gets access token
4. CLI sends token to app API in Authorization header
5. App API calls  GET /userinfo  →  gets account_id
```

#### 3. SSH — key-based authentication

Same model as GitHub SSH. For git operations or any SSH-based tooling.

```
1. User registers SSH public key with account (same as device link)
2. Client connects over SSH, server verifies key signature
3. Server maps public key → account_id via key index
```

### Device Management

```
- First device: POST /auth/register  →  creates account + first key binding
- Additional devices: POST /auth/devices/link  →  adds key to account
- Remove device: POST /auth/devices/unlink  →  removes key (cannot remove last)
- Any linked device can authenticate independently
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
- `GET /authorize` — authorization endpoint (presents device auth, issues authorization codes)
- `POST /token` — token endpoint (exchanges authorization code for access + refresh tokens)
- `GET /userinfo` — returns user identity (sub/account_id) from access token
- Client registration / management
- PKCE support

#### TODO — SSH layer:
- SSH protocol listener
- Public key authentication handler
- Key-to-account resolution (reuses existing key index)

#### Data storage:
- File-per-account persistence — each account written to its own JSON file on every mutation (atomic tmp+rename)
- UUID directory sharding: dashes replaced with `/` → 4-level directory tree
- Key index: `keys/<public_key_hex>` → account_id (for device lookup)
- Server secret: `server.key` (HMAC signing key for access tokens, generated on first run)

#### Token model:
- **Access tokens** — HMAC-signed, self-contained (`account_id:expires_hex:hmac_hex`), validated without I/O. Short-lived (1h). Opaque to clients — apps call `/userinfo` to get identity.
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
