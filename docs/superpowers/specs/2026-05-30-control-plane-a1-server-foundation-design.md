# Redactr v2 — Subsystem A1: Control-Plane Server Foundation Design

**Status:** Design (approved). Implementation plan follows.
**Date:** 2026-05-30
**Parent:** `docs/superpowers/specs/2026-05-30-redactr-v2-architecture-design.md` (subsystem A).
**Part of:** Subsystem A decomposition — **A1 → A2 → (A4 + E) → A5 → A3**, all in v2. This spec covers **A1 only**.

## Subsystem A decomposition (context)

| # | Sub-project | Build order |
|---|---|---|
| **A1** | Server skeleton + multi-tenancy + enrollment/auth (**this spec**) | 1st — foundation |
| A2 | Policy distribution API + client sync (fills B's `internal/policy` SEAM) | 2nd |
| A4 | Monitoring ingestion + aggregation (pairs with subsystem E) | 3rd |
| A5 | Hosted dashboard (multi-tenant, moves v1 dashboard) | 4th |
| A3 | Image build/sign/registry pipeline | 5th (heaviest; in v2) |

**Locked stack decisions (apply to all of A):** Go (reuse `api`/`store`/`hub`/`licensing`); embedded **pure-Go SQLite** (`modernc.org/sqlite`, no CGo); **ECDSA-signed** artifacts reusing the `internal/licensing` pattern; **single self-hosted Go container**; client auth via **signed scoped bearer tokens** (mTLS deferred).

## A1 Goal

Stand up the control-plane server as a deployable Go binary with an embedded SQLite store, the multi-tenant data model (orgs, devices, enrollment tokens), the device enrollment flow, signed device bearer tokens, the auth middleware that injects org/device context, and the admin API to manage orgs/tokens/devices. A2–A5 build on this foundation.

## Non-goals (A1)

- Policy storage/distribution (A2), monitoring ingestion (A4), dashboard UI (A5), image pipeline (A3).
- Token refresh/rotation, short-lived tokens (long-lived + server-side revocation for now).
- Full admin user accounts / SSO (A1 uses a single admin API key; richer admin auth can arrive with A5).
- mTLS device certificates (bearer tokens for v2).

## Shape

A new binary `cmd/redactr-server` — deploys server-side (cloud/container), distinct from the dev-machine `cmd/redactr`. It owns an ECDSA keypair (loaded from disk or generated on first run), an embedded SQLite database, and an HTTP API. The server NEVER receives traffic, code, or redacted values — only org/device/enrollment metadata.

## Data model (SQLite schema)

```sql
CREATE TABLE orgs (
  id          TEXT PRIMARY KEY,        -- random id
  name        TEXT NOT NULL,
  created_at  TIMESTAMP NOT NULL
);

CREATE TABLE enrollment_tokens (
  token_hash  TEXT PRIMARY KEY,        -- sha256 of the random token (token shown once at mint)
  org_id      TEXT NOT NULL REFERENCES orgs(id),
  expires_at  TIMESTAMP NOT NULL,
  max_uses    INTEGER NOT NULL,        -- 0 = unlimited
  used_count  INTEGER NOT NULL DEFAULT 0,
  revoked     INTEGER NOT NULL DEFAULT 0,
  created_at  TIMESTAMP NOT NULL
);

CREATE TABLE devices (
  id            TEXT PRIMARY KEY,      -- random id, embedded in the bearer token
  org_id        TEXT NOT NULL REFERENCES orgs(id),
  name          TEXT NOT NULL,         -- hostname/label from the client
  platform      TEXT NOT NULL,         -- darwin | windows | linux
  enrolled_at   TIMESTAMP NOT NULL,
  last_seen_at  TIMESTAMP,
  revoked       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_devices_org ON devices(org_id);
```

The raw enrollment token is shown only at mint time; the DB stores its SHA-256 (so a DB leak doesn't reveal usable tokens).

## Device bearer token

Reuses the `internal/licensing` ECDSA approach. Format: `base64url(claimsJSON) + "." + base64url(ecdsaSig)`.
- Claims: `{ "device_id": "...", "org_id": "...", "issued_at": <unix> }`.
- The server signs with its ECDSA private key and verifies with the matching public key (server holds both — clients do not verify device tokens; the policy bundle they DO verify is A2's concern).
- Long-lived (no `exp`); trust is withdrawn by setting `devices.revoked = 1`, which the auth middleware checks on every request. A revoked device's token is rejected even though its signature is still valid.

## Enrollment + auth flow

1. **Mint** (admin): `POST /admin/orgs/{id}/enrollment-tokens {expires_in, max_uses}` → returns the raw token **once**; stores its hash.
2. **Enroll** (client): `POST /v1/enroll {enrollment_token, device_name, platform}` → server hashes the presented token, looks it up, validates (exists, not revoked, not expired, `used_count < max_uses` or `max_uses == 0`), then in one transaction: inserts a `devices` row, increments `used_count`, and returns `{ device_id, org_id, token }` where `token` is the signed device bearer token.
3. **Authenticated requests**: `Authorization: Bearer <token>`. The `RequireDevice` middleware: parses the token, verifies the ECDSA signature, loads the device by `device_id`, rejects (401) if missing/revoked or `org_id` mismatch, updates `last_seen_at` (best-effort), and stores `org_id`/`device_id` in the request context for downstream handlers.

## API surface (A1)

**Public**
- `GET /healthz` → `{ "status": "ok" }`
- `POST /v1/enroll` → enrollment (above)
- `GET /v1/whoami` (auth required) → `{ "device_id", "org_id" }` — a trivial authed endpoint to prove the middleware end-to-end (also useful to clients as a token-liveness check)

**Admin** (every `/admin/*` route guarded by `X-Admin-Key` matching the configured admin key)
- `POST /admin/orgs {name}` → `{ id, name }`
- `GET /admin/orgs` → list
- `POST /admin/orgs/{id}/enrollment-tokens {expires_in_hours, max_uses}` → `{ token, expires_at }` (raw token shown once)
- `GET /admin/devices?org={id}` → list devices (no secrets)
- `POST /admin/devices/{id}/revoke` → `{ revoked: true }`

Unknown route → 404; bad admin key → 401; malformed body → 400; JSON throughout.

## Configuration

`redactr-server` config (env + flags; sane defaults):
- `REDACTR_SERVER_ADDR` (default `:8080`)
- `REDACTR_SERVER_DB` (default `./redactr-server.db`)
- `REDACTR_SERVER_KEY_DIR` (default `./keys`; ECDSA keypair generated here on first run if absent)
- `REDACTR_ADMIN_KEY` (if unset, a random key is generated and **printed once** at startup)

## Package structure

| File | Responsibility |
|---|---|
| `cmd/redactr-server/main.go` | parse config, open store, load/generate keys, wire HTTP, serve + graceful shutdown |
| `internal/server/store/store.go` | SQLite open + migrations; `Store` with org/token/device CRUD |
| `internal/server/store/schema.sql` | embedded schema (via `//go:embed`) |
| `internal/server/auth/token.go` | device-token sign/verify (ECDSA), claims type |
| `internal/server/auth/enroll.go` | enrollment validation + device creation (transactional) |
| `internal/server/auth/middleware.go` | `RequireDevice` + admin-key gate; context helpers |
| `internal/server/httpapi/server.go` | `Server` struct, route registration, handlers |
| `internal/server/keys/keys.go` | load-or-generate ECDSA keypair on disk (PEM) |

(Keeps each file to one responsibility; mirrors the existing `internal/api` layout.)

## Error handling

| Case | Behavior |
|---|---|
| Enrollment token unknown/expired/revoked/exhausted | 401 with a generic "enrollment failed" (no oracle on which check failed) |
| Bearer token bad signature / unknown device / revoked | 401 |
| Admin key missing/wrong | 401 |
| DB error | 500, logged (slog), no internal detail leaked |
| First run, no keys/admin key | generate, persist keys, print admin key once, continue |

## Testing

Pure-Go, no external services — temp-file SQLite per test (`t.TempDir()`).
- **Unit:** token sign→verify round-trip + tamper rejection; enrollment validation table (valid, expired, revoked, over-max-uses, unknown) ; `RequireDevice` (valid → context populated; revoked → 401; bad sig → 401); admin-key gate (missing/wrong → 401).
- **Store:** migrations apply on a fresh DB; org/token/device CRUD round-trips; `used_count` increments transactionally.
- **End-to-end (httptest):** mint org+token via admin API → `POST /v1/enroll` → `GET /v1/whoami` with the returned bearer → 200 with correct ids → `POST /admin/devices/{id}/revoke` → `whoami` now 401.

## Build order (A1 tasks)

1. **Store** — SQLite open + embedded schema/migrations + org/device/token CRUD (add `modernc.org/sqlite` dep).
2. **Keys** — load-or-generate ECDSA keypair (PEM on disk).
3. **Device token** — sign/verify + claims (reuse licensing's ECDSA helpers where clean).
4. **Enrollment** — validation + transactional device creation.
5. **Middleware** — `RequireDevice` + admin-key gate + context helpers.
6. **HTTP API + main** — wire routes (`/healthz`, `/v1/enroll`, `/v1/whoami`, `/admin/*`), `cmd/redactr-server`, end-to-end httptest.

## Out of scope / SEAMs for later A sub-pieces

- `// SEAM A2:` policy storage + `GET /v1/policy` (signed bundle, ETag) hangs off the same `RequireDevice` middleware + org context.
- `// SEAM A4:` `POST /v1/events` monitoring ingestion, same auth.
- `// SEAM A5:` dashboard UI wraps the admin API; richer admin auth replaces the single admin key.
- `// SEAM A3:` image build/sign/registry + `ref@digest` in the policy bundle.
