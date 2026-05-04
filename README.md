# hush-hush

[![CI](https://github.com/cjunks94/hush-hush/actions/workflows/security.yml/badge.svg)](https://github.com/cjunks94/hush-hush/actions/workflows/security.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/cjunks94/hush-hush?v=2)](https://goreportcard.com/report/github.com/cjunks94/hush-hush)
[![codecov](https://codecov.io/gh/cjunks94/hush-hush/branch/main/graph/badge.svg)](https://codecov.io/gh/cjunks94/hush-hush)
[![Go Version](https://img.shields.io/github/go-mod/go-version/cjunks94/hush-hush)](go.mod)
[![License: MIT](https://img.shields.io/github/license/cjunks94/hush-hush)](LICENSE)

A minimal self-hosted secret keeper. Single Go binary, SQLite, HTTPS API, AES-256-GCM at rest. Deploys to Railway in five minutes, runs anywhere a Go binary can run.

Built as a personal portfolio project — small enough to read in one sitting (~410 lines + tests), real enough to actually use.

## What this is

A tiny HTTPS API for storing your own API keys, database URLs, and OAuth secrets across personal projects. You `PUT` a value, you `GET` it back. That's the entire feature set.

## What this isn't

- A team password manager (use [Vaultwarden](https://github.com/dani-garcia/vaultwarden))
- A Vault replacement (no policies, no rotation, no PKI)
- Audited or compliant storage for customer data

## Threat model

**Server-side encryption is intentional.** The master key is provided as an environment variable to the running process. If the host is compromised, both key and ciphertext are exposed — this design protects against stolen DB backups / volume snapshots, not host compromise.

If you need client-side encryption (the user types a passphrase to decrypt locally), use Bitwarden / Vaultwarden instead. A future v2 here may add client-side crypto when there's a CLI to drive it.

**Single-user.** A single bearer token guards all routes. No users, no ACLs, no audit log.

## Architecture

```
client                 Railway edge (Fastly + TLS)
  │                              │
  └──── HTTPS ─────────────►     │
                                 ▼
                        ┌──────────────────────┐
                        │  Go HTTP server      │
                        │  (single binary)     │
                        └──────────┬───────────┘
                                   ▼
                        ┌──────────────────────┐
                        │  SQLite + WAL        │
                        │  (Railway Volume)    │
                        └──────────────────────┘
```

- TLS terminated at Railway's edge; Go process speaks HTTP internally.
- AES-256-GCM with `(version_byte || name)` bound as AAD — defeats algorithm-downgrade and cross-name ciphertext rebinding.
- Random 12-byte nonce per write. Ciphertext stored as `version_byte || sealed_payload`.
- Bearer-token auth via SHA-256-then-`subtle.ConstantTimeCompare` (no length oracle).
- SQLite via `modernc.org/sqlite` — pure Go, no CGO, works with any Go buildpack out of the box.
- Structured logging via `log/slog` with a request-ID middleware that honors valid inbound `X-Request-ID` for end-to-end correlation.

## Deploy on Railway in five minutes

### 1. Generate `MASTER_KEY` and `AUTH_TOKEN`

**PowerShell (Windows):**
```powershell
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 32; $rng.GetBytes($bytes)
"MASTER_KEY: " + [Convert]::ToBase64String($bytes)
$rng.GetBytes($bytes)
"AUTH_TOKEN: " + (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
```

**bash / zsh (macOS / Linux / Git Bash):**
```bash
openssl rand -base64 32   # MASTER_KEY  (32 bytes, base64-encoded)
openssl rand -hex 32      # AUTH_TOKEN  (64 hex chars)
```

**Back up the `MASTER_KEY` somewhere safe** (1Password, paper, whatever). Lose it and every secret in the DB is unrecoverable — the DB itself is just ciphertext, useless without the key.

### 2. Create the Railway service

Point a new Railway service at your fork of this repo. Railway's Nixpacks Go buildpack handles the build — no Dockerfile needed.

### 3. Attach a Volume at `/data`

1 GB is plenty (secrets are tiny).

### 4. Set environment variables

```
MASTER_KEY=<base64 string from step 1>
AUTH_TOKEN=<hex string from step 1>
DB_PATH=/data/hush.db
```

`PORT` is auto-injected by Railway — don't set it manually.

### 5. Verify

```bash
curl https://<your-app>.up.railway.app/healthz
# → {"status":"ok"}
```

## API

All routes except `/healthz` require `Authorization: Bearer <AUTH_TOKEN>`. All responses are JSON; all carry `Cache-Control: no-store` and `X-Request-ID`.

| Method | Path | Body | Response |
|---|---|---|---|
| `GET` | `/healthz` | — | `{"status":"ok"}` |
| `GET` | `/v1/secrets` | — | `{"secrets":[{name, created_at, updated_at}, ...]}` (values omitted; capped at 1000 entries) |
| `GET` | `/v1/secrets/{name}` | — | `{name, value, created_at, updated_at}` |
| `PUT` | `/v1/secrets/{name}` | `{"value":"..."}` | `{name, created_at, updated_at}` |
| `DELETE` | `/v1/secrets/{name}` | — | `204` (idempotent — repeat calls and missing names also return 204) |

**Constraints:**
- Name: `^[a-zA-Z0-9_.-]{1,128}$` — no slashes or spaces. Use dots or underscores for hierarchy: `AWS_PROD.db.password`.
- Value: opaque string, max 64 KiB.
- `PUT` requires `Content-Type: application/json` (415 otherwise). Strict JSON parsing rejects unknown fields and trailing data.

### Examples

```bash
URL=https://<your-app>.up.railway.app
TOKEN=<your AUTH_TOKEN>

# Store a secret
curl -X PUT $URL/v1/secrets/openai-key \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"sk-..."}'

# Retrieve
curl $URL/v1/secrets/openai-key \
  -H "Authorization: Bearer $TOKEN"

# List (names only, no values)
curl $URL/v1/secrets \
  -H "Authorization: Bearer $TOKEN"

# Delete
curl -X DELETE $URL/v1/secrets/openai-key \
  -H "Authorization: Bearer $TOKEN"
```

## Local development

```bash
# Generate keys for local use
export MASTER_KEY=$(openssl rand -base64 32)
export AUTH_TOKEN=$(openssl rand -hex 32)
export DB_PATH=./hush.db

# Run
go run .

# Test
go test ./...
go test -cover ./...
```

Requires Go 1.24+ (set in `go.mod`).

## Security tooling

CI runs on every push, every PR, and a weekly Mon 06:00 UTC cron:

| Tool | Purpose |
|---|---|
| `go vet` + `go build` + `go test` | Compile + correctness |
| `go mod verify` | Module checksum integrity |
| [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | Stdlib + dependency CVE scan against the live Go vuln DB |
| [`gosec`](https://github.com/securego/gosec) | Static security analysis (medium+ severity) |
| [`gitleaks`](https://github.com/gitleaks/gitleaks) | Scans git history for committed secrets |
| Dependabot | Weekly grouped updates for `gomod` and `github-actions` ecosystems |
| [CodeRabbit](https://coderabbit.ai) | Per-PR agentic review with project-specific instructions |

Tool versions are pinned to specific tags / commit SHAs to defeat `@latest` supply-chain drift; Dependabot opens PRs to bump them as new releases ship.

## Limitations (deliberately not in v1)

- **No CLI.** HTTP API only. A `hush get FOO` / `hush set FOO bar` wrapper is the natural next addition.
- **No client-side encryption.** Master key sits on the server (see threat model).
- **No rotation tooling.** If the master key leaks, recovery is manual: rotate, decrypt all rows under old key, re-encrypt under new key, swap env var.
- **No rate limiting** beyond Railway's edge default.
- **No audit log** of who-read-what.
- **No multi-user.**
- **No web UI / browser extension.**

If you need any of these, [Vaultwarden](https://github.com/dani-garcia/vaultwarden) and [Infisical](https://github.com/Infisical/infisical) are good self-hosted alternatives.

## License

MIT. See [LICENSE](LICENSE).
