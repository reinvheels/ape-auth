# Ape Auth

Minimal identity provider built in Zig. Device-based authentication — no passwords, no email/SMS verification. Users authenticate via trusted devices (browser or mobile) and can link additional devices for account recovery.

## Architecture

```
┌──────────────┐       ┌──────────────────┐       ┌──────────────┐
│  Client      │──────►│  Ape Auth (Zig)  │──────►│  Storage     │
│  (Browser /  │ HTTP  │  OAuth endpoints │       │  (Memory +   │
│   Mobile)    │◄──────│  Device auth     │◄──────│   FS backup) │
└──────────────┘       └──────────────────┘       └──────────────┘
```

### How It Works

- **In-memory data store** — all auth data lives in memory for fast access
- **Periodic filesystem backup** — state is written to disk on a configurable interval for persistence and rehydration on restart
- **Runs in always-warm Lambda** — designed for Lambda + EFS (or similar), but can run standalone
- **Device-based identity** — each account is created from a device keypair; no passwords or external identity providers
- **Multi-device recovery** — users link additional devices to their account; any linked device can restore access

### Auth Flow (Device Registration)

```
1. Device generates keypair (WebAuthn / platform key)
2. POST /auth/register  →  { publicKey, deviceInfo }
3. Server creates account, stores device binding
4. Returns access token + refresh token

Recovery:
5. User links second device  →  POST /auth/devices/link
6. If primary device lost, authenticate from linked device
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

HTTP server exposing OAuth/auth endpoints. Built with Zig's standard library HTTP server (or `httpz`/`zap` if needed).

Key endpoints:
- `POST /auth/register` — create account from device keypair
- `POST /auth/login` — authenticate with device key challenge
- `POST /auth/devices/link` — link additional device to account
- `POST /auth/devices/unlink` — unlink device
- `POST /auth/token/refresh` — refresh access token
- `GET /auth/account` — get account info + linked devices

Data storage:
- In-memory HashMap for active sessions and accounts
- Periodic JSON/binary dump to filesystem (configurable interval)
- On startup, rehydrate from latest backup file

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
- EFS mount for persistent backup storage
- Zig binary cross-compiled for `aarch64-linux` (Lambda ARM runtime)

### Files

- `auth/` — Zig source for the identity provider
- `infra/index.ts` — main infrastructure (Lambda, EFS, IAM, API Gateway)
- `infra/Pulumi.yaml` — project config
- `infra/Pulumi.prod.yaml` — stack config (gitignored, managed via `puc`)
