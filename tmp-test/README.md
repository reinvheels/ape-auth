# Link a CLI device to a passkey-created account

Scenario: an account was created in the browser via passkey. Now add an Ed25519 CLI device to the same account and verify it can log in independently.

Prereqs: `openssl` (v3+), `curl`, `jq`, `xxd`. Browser is signed in at `http://localhost:8080`.

## Step 0 — Grab the access token from the browser

Open DevTools → Network → refresh the page → click the `session` request → copy the `access_token` from the response body. Then:

```bash
export ACCESS_TOKEN="eyJ...paste here..."
```

(The token is a 1-hour JWT issued by `/session`.)

## Step 1 — Generate Ed25519 keypair for the CLI device

```bash
openssl genpkey -algorithm ed25519 -out cli.pem
openssl pkey -in cli.pem -pubout -outform DER | tail -c 32 | xxd -p -c 32 > cli.pub.hex
cat cli.pub.hex
```

## Step 2 — Link the CLI device to the account

```bash
curl -s http://localhost:8080/auth/devices/link \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"public_key\":\"$(cat cli.pub.hex)\",\"device_name\":\"my-cli\"}" \
  | tee link.json | jq
```

## Step 3 — Challenge for the CLI device

```bash
curl -s http://localhost:8080/auth/challenge \
  -H "Content-Type: application/json" \
  -d "{\"public_key\":\"$(cat cli.pub.hex)\"}" \
  | tee challenge.json | jq

jq -r .challenge challenge.json > cli.challenge
```

## Step 4 — Sign the challenge

```bash
xxd -r -p cli.challenge > cli.challenge.bin
openssl pkeyutl -sign -inkey cli.pem -rawin -in cli.challenge.bin | xxd -p -c 64 > cli.sig
```

## Step 5 — Login as the CLI device

```bash
curl -s http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"public_key\":\"$(cat cli.pub.hex)\",\"challenge\":\"$(cat cli.challenge)\",\"signature\":\"$(cat cli.sig)\"}" \
  | tee login.json | jq

jq -r .access_token login.json > cli.token
```

**Pass if:** `account_id` in `login.json` matches the account you're signed into in the browser.

## Step 6 — Verify the account lists both devices + the passkey

```bash
curl -s http://localhost:8080/auth/account \
  -H "Authorization: Bearer $(cat cli.token)" \
  | tee account.json | jq
```

Should show `account_id`, `devices: [{name: "my-cli", ...}]`, plus whatever the passkey credential was registered as.
