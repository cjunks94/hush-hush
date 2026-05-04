# Security Policy

## Reporting a vulnerability

**Please do not open public issues for security problems.**

Use GitHub's private vulnerability reporting:

1. Go to **[Report a vulnerability](https://github.com/cjunks94/hush-hush/security/advisories/new)**
2. Describe the issue with reproduction steps if possible
3. You'll get an acknowledgement within 7 days; we'll discuss the fix and disclosure timeline together

## Supported versions

This is an active personal project; only the latest commit on `main` is supported. Security fixes land on `main` and are not backported.

| Version | Supported |
| ------- | --------- |
| `main`  | ✅ |
| Tagged releases | Best-effort within the latest minor |

## In scope

- The Go HTTP server in `main.go` — auth, crypto, validation, headers, log injection vectors
- Dependencies in `go.mod` — already scanned weekly via `govulncheck`
- The CI workflow in `.github/workflows/security.yml`

## Out of scope

This is a deliberately minimal single-user personal tool. The following are documented trade-offs in the [threat model](README.md#threat-model), not vulnerabilities:

- **Server-side encryption** — the master key sits in a process env var; host compromise exposes both key and ciphertext. Protects against backup / volume-snapshot leaks, not host compromise. Use Vaultwarden / Bitwarden if you need client-side crypto.
- **No rate limiting** beyond Railway's edge default. The 256-bit `AUTH_TOKEN` makes online brute force infeasible at any sensible request rate, but a determined attacker with sustained access could probe forever.
- **No audit log** of read access.
- **Single-user** — one bearer token, no users / ACLs / rotation.

If your use case requires any of those properties, please pick a different tool — see the [README's "What this isn't" section](README.md#what-this-isnt).

## Security tooling

The following run in CI on every push, PR, and weekly Mon 06:00 UTC cron:

| Tool | Purpose |
|---|---|
| [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | Stdlib + dependency CVE scan against the live Go vuln DB |
| [`gosec`](https://github.com/securego/gosec) | Static security analysis (medium+ severity) |
| [`gitleaks`](https://github.com/gitleaks/gitleaks) | Scans git history for committed secrets |
| Dependabot | Weekly grouped dependency updates |
| [CodeRabbit](https://coderabbit.ai) | Per-PR agentic review |

Tool versions are pinned (specific tags / commit SHAs) to defeat `@latest` supply-chain drift; Dependabot opens PRs to bump them as new releases ship.
