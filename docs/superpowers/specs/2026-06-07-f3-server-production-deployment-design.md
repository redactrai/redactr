# F3 — Server Production Deployment (implementation spec)

**Date:** 2026-06-07
**Subsystem:** F (Fleet Operations) — sub-project F3
**Status:** Implementation spec. Derives from the approved architecture spec `2026-06-05-subsystem-f-fleet-operations-design.md` (decisions 7–8) and folds in two deferred F1 follow-ups. Build order: F1 (done) → **F3 (this)** → F2 → F4.
**Branch:** `subsystem-f-fleet-ops` (continues the F1 branch).

## Problem

A1 produced a server that runs bare: configured by env vars, authenticated by a single static `X-Admin-Key`, schema auto-applied as ad-hoc DDL, no TLS story, no backups. That is fine for a dev box but not for "install this on a server exposed to a fleet over the internet." F3 makes the server **deployable and safe to operate**:

1. **Packaged** — a minimal Linux container image + a turnkey `docker-compose` with automatic TLS.
2. **Authenticated for humans** — OIDC/SSO for admins + one local break-glass super-admin, on server-side sessions; the static key retired for people.
3. **Durable & upgradable** — versioned forward-only migrations + nightly backups with a documented restore.
4. **Fail-fast** — refuse to boot in an unsafe config outside an explicit dev mode.

Folded-in F1 follow-ups: server-side **audit retention sweep** (default 365d) and a **request-body size cap** on ingest/events/enroll.

## Scope & target

Self-hosted, **single-org, single-instance**. SQLite retained (no Postgres/HA). macOS/Windows are client hosts only; the server is Linux/container. Out: multi-tenant, HA, air-gapped distribution, live push channels.

## Decisions (locked)

| # | Area | Decision | Rationale / residual gap |
|---|------|----------|--------------------------|
| 1 | **Migration framework** | Numbered, forward-only SQL migrations in a `schema_migrations(version INTEGER PRIMARY KEY, applied_at)` table. Migrations are embedded `.sql` files applied in order on `Open`, inside a transaction each, recording the version. The existing `schema.sql` becomes migration `0001_init.sql`; the ad-hoc `events.uuid` probe becomes `0002`. | `migrate.go`'s own comment already calls for this once >3 migrations exist; F3 adds more. Forward-only (no down migrations) matches single-instance ops and avoids destructive rollback. Residual: a bad migration requires restore-from-backup, not auto-rollback — acceptable given nightly backups. |
| 2 | **OIDC library** | `github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2`. Authorization-Code flow **with PKCE** and `state`/`nonce`. | De-facto standard, minimal deps, actively maintained. PKCE + state/nonce closes CSRF/replay on the callback. |
| 3 | **Session storage** | **Server-side sessions in a `sessions` table** (opaque 256-bit random ID), referenced by an **HttpOnly, Secure, SameSite=Lax** cookie (`redactr_admin`). Sessions have an absolute expiry (default 12h) and are deletable (logout / revoke). | Server-side (vs signed-cookie) chosen so logout/revocation is immediate and the IdP-issued identity never rides in the client. SameSite=Lax permits the OIDC redirect to return the cookie. Residual: a stolen cookie is valid until expiry or explicit revoke — bounded by short TTL + Secure/HttpOnly. |
| 4 | **Super-admin** | A single local account. Username from `REDACTR_SUPERADMIN_USER`; password supplied as a **bcrypt hash** via `REDACTR_SUPERADMIN_PASSWORD_HASH` (preferred) **or** a plaintext `REDACTR_SUPERADMIN_PASSWORD` that the server hashes on boot (dev convenience, logged as less-preferred). bcrypt cost 12. Login is a server-rendered form posting to `/admin/login`; on success, a session with role `superadmin`. | Break-glass must work with the IdP down, so it cannot depend on OIDC. Hash-in-env avoids storing a plaintext secret. Residual: env-borne secret — documented to use a secrets manager / compose secret. |
| 5 | **Admin (OIDC) authorization** | An OIDC login is only accepted if the verified identity (email, lowercased) is in an **`admins` allowlist table** managed by the super-admin (`POST/DELETE /admin/admins`). Unknown identities get 403 after a valid IdP login. Role `admin`, scoped to org operations (orgs, devices, tokens, policy, audit/fleet views) — **not** super-admin functions (OIDC config, admin management). | Valid SSO login ≠ authorization; the allowlist is the gate. Email as the key (claim `email`, require `email_verified`). Residual: email reuse at the IdP — accepted for single-org self-host. |
| 6 | **Retire `X-Admin-Key` for humans** | Human admin routes move behind session auth (`RequireSession(role)`). A **single optional machine key** (`REDACTR_MACHINE_KEY`, named, revocable by rotating env) may still authorize a *narrow* allowlist of automation endpoints for CI/scripts — **off unless the env var is set**. The old blanket `X-Admin-Key` is removed. | Keeps a CI path without leaving a god-key for humans. Residual: machine key is still a shared secret — scoped narrow + opt-in. |
| 7 | **Config fail-fast** | Outside `REDACTR_DEV_MODE=1`, the server validates required settings on boot and **exits non-zero with a clear message** if: no auth configured (neither super-admin nor OIDC), `REDACTR_PUBLIC_URL` missing/non-https, or key/db dir unwritable. The A1 admin-key **auto-generation fallback is removed**. Dev mode restores permissive behavior and binds loopback only. | "Insecure by accident" is the failure mode we must prevent on an internet-exposed box. |
| 8 | **TLS termination** | TLS is terminated by **Caddy** (automatic Let's Encrypt) in the bundled compose; the Go server listens **HTTP on an internal port** and trusts `X-Forwarded-*` only from the proxy. `Secure` cookies + https `REDACTR_PUBLIC_URL` are required (enforced by #7). A documented alternative shows nginx/Traefik. | Caddy gives zero-config ACME. The server doesn't do ACME itself (keeps the image minimal and the cert lifecycle in the proxy). |
| 9 | **Packaging** | Multi-stage `Dockerfile`: build static binary on golang:1.26, copy into `gcr.io/distroless/static` (non-root). `docker-compose.yml`: `caddy` (ports 80/443, `Caddyfile`, cert volume) + `redactr-server` (internal port, data volume) + named volumes for `db/keys/backups`. Checksums published; signing hooks deferred to F2. | Distroless/static = tiny, no shell, non-root. SQLite file lives on a named volume. |
| 10 | **DB backups** | A goroutine on a daily ticker runs SQLite `VACUUM INTO '<backups>/redactr-YYYYMMDD-HHMMSS.db'`, retaining the newest `REDACTR_BACKUP_RETAIN` (default 14). Documented restore = stop server, copy chosen backup over the live DB, start. | `VACUUM INTO` yields a consistent snapshot without stopping writes. Retention prevents unbounded growth. |
| 11 | **Audit retention sweep** | A daily sweep deletes `audit_records` (and `events`) with `received_at` older than `REDACTR_AUDIT_RETAIN_DAYS` (default 365). Runs in the same maintenance loop as backups; logs counts. | Bounds the central audit log per the F1 design's deferred follow-up. |
| 12 | **Request-body cap** | Wrap `r.Body` with `http.MaxBytesReader` on `/v1/enroll`, `/v1/events`, `/v1/ingest` (and the admin write endpoints), default `REDACTR_MAX_BODY_BYTES` = 1 MiB. Over-limit → 413. | Closes the unbounded-decode DoS the A1 map flagged. Complements the existing `maxEventBatch=500`. |

### Note on overrides
Decisions 4–6 override v2's "SSO deferred" and the A1 static-key model, exactly as authorized in the architecture spec (decision 8) and `[[v2-autonomous-build-mandate]]`.

## Data model deltas

New tables (migrations `0003`+):

```sql
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);

CREATE TABLE admins (
  email      TEXT PRIMARY KEY,         -- lowercased, IdP-verified
  added_by   TEXT NOT NULL,            -- 'superadmin' or an admin email
  created_at TEXT NOT NULL
);

CREATE TABLE sessions (
  id         TEXT PRIMARY KEY,         -- opaque 256-bit base64url
  subject    TEXT NOT NULL,            -- super-admin username or admin email
  role       TEXT NOT NULL,            -- 'superadmin' | 'admin'
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
```

Super-admin is **not** a table row; it is the single env-configured identity, matched at login and represented only by a session with role `superadmin`.

## API deltas

New / changed routes (in `internal/server/httpapi`):

- `GET  /admin/login` — server-rendered login form (super-admin password + "Sign in with SSO" button).
- `POST /admin/login` — super-admin password login → session.
- `GET  /admin/oidc/start` — build auth URL (PKCE/state/nonce in a short-lived cookie), redirect to IdP.
- `GET  /admin/oidc/callback` — verify code+state+nonce, check `admins` allowlist, create session.
- `POST /admin/logout` — delete session + clear cookie.
- `GET/POST/DELETE /admin/admins` — super-admin manages the OIDC allowlist.
- All existing `/admin/*` routes: `RequireAdmin(key)` → **`RequireSession("admin")`** (super-admin implicitly satisfies admin). Optional `RequireMachineKey` narrow path when `REDACTR_MACHINE_KEY` is set.
- `/v1/enroll`, `/v1/events`, `/v1/ingest`: wrapped in `MaxBytesReader`.

## New env vars

| Var | Default | Meaning |
|-----|---------|---------|
| `REDACTR_DEV_MODE` | unset | `1` = permissive, loopback-only, no fail-fast (dev only). |
| `REDACTR_PUBLIC_URL` | — | External https base URL (for OIDC redirect + Secure cookie). Required in prod. |
| `REDACTR_OIDC_ISSUER` / `_CLIENT_ID` / `_CLIENT_SECRET` | — | OIDC provider config. |
| `REDACTR_SUPERADMIN_USER` | — | Break-glass username. |
| `REDACTR_SUPERADMIN_PASSWORD_HASH` | — | bcrypt hash (preferred). |
| `REDACTR_SUPERADMIN_PASSWORD` | — | plaintext (hashed on boot; dev convenience). |
| `REDACTR_SESSION_TTL` | `12h` | Absolute session lifetime. |
| `REDACTR_MACHINE_KEY` | unset | Optional narrow automation key. |
| `REDACTR_BACKUP_RETAIN` | `14` | Nightly backups to keep. |
| `REDACTR_AUDIT_RETAIN_DAYS` | `365` | Audit/event retention. |
| `REDACTR_MAX_BODY_BYTES` | `1048576` | Per-request body cap. |

At least one of {super-admin, OIDC} must be configured in prod, else fail-fast.

## Testing strategy

Per the architecture spec's F3 line: migration apply on fresh + upgrade; backup/restore round-trip; OIDC login happy path; super-admin break-glass with IdP unreachable; rejection of plaintext where TLS is required.

- **Migrations (unit):** fresh DB applies all in order, records versions; a DB already at the A1 schema upgrades without data loss; re-`Open` is a no-op; partial/failed migration rolls back its tx and leaves version unchanged.
- **Sessions (unit):** create/lookup/expire/delete; expired session rejected; sweep removes expired rows.
- **Super-admin (unit):** correct password → session; wrong → 401; works with no OIDC configured (break-glass). bcrypt hash + plaintext-hash-on-boot both accepted.
- **OIDC (unit, mock IdP):** stand up a fake issuer (httptest) serving discovery + JWKS + token; happy-path callback creates an `admin` session iff email is allowlisted and verified; state/nonce mismatch → 400; non-allowlisted verified email → 403. (No real IdP — honest deferral; document a manual happy-path against a real provider.)
- **Auth middleware (unit):** `RequireSession` allows valid cookie, rejects missing/expired/wrong-role; super-admin satisfies admin routes; machine-key path only active when env set.
- **Config fail-fast (unit):** prod mode with missing auth / non-https public URL → constructor returns error; dev mode permissive.
- **Body cap (unit):** body over limit → 413.
- **Backups + retention (unit):** `VACUUM INTO` produces a valid openable DB; retention prunes oldest beyond N; sweep deletes rows older than cutoff and keeps newer. Use an injectable clock + temp dir (apply the macOS short-socket-path lesson: keep temp paths short / no sockets here).
- **Honest deferral (cannot smoke-test here):** Docker image build, compose up, Caddy ACME, real-IdP login. These are config + docs, validated by `docker build`/`compose config` where the tool exists, otherwise reviewed by inspection and documented as untested-here.

## Threat model & residual gaps (delta over F1)

| Vector | F3 outcome |
|--------|-----------|
| Internet-exposed server with shared static key | **Mitigated** — TLS + OIDC + server-side sessions; blanket `X-Admin-Key` removed. |
| Valid SSO user who isn't an authorized admin | **Mitigated** — allowlist gate (403) after IdP login. |
| IdP outage locks everyone out | **Mitigated** — local super-admin break-glass, independent of OIDC. |
| Stolen session cookie | **Bounded** — HttpOnly/Secure/SameSite + short TTL + server-side revoke/logout. |
| Insecure-by-accident deploy (http, no auth) | **Mitigated** — fail-fast refuses to boot outside dev mode. |
| Bad migration corrupts schema | **Bounded** — per-migration tx + nightly backup + documented restore (no auto-rollback). |
| Server DB loss | **Mitigated** — nightly `VACUUM INTO` backups, retention, restore docs. |
| Unbounded request body / audit growth | **Mitigated** — `MaxBytesReader` + retention sweep. |
| Super-admin secret in env | **Residual, documented** — recommend compose secret / secrets manager; hash-not-plaintext preferred. |
| Machine key is a shared secret | **Residual, bounded** — opt-in, narrow endpoint scope, rotate by changing env. |

## Explicitly deferred

- Code-signing identities for the image (hooks land in F2).
- Postgres/HA/multi-tenant; air-gapped image distribution.
- Per-admin RBAC beyond {superadmin, admin}; admin audit log of admin actions (nice-to-have, not now).
- Auto-rollback / down-migrations.

## Build order (this sub-project)

1. **Migration framework** (foundation — everything else adds migrations).
2. **Sessions store + `RequireSession` middleware** (+ super-admin login).
3. **OIDC login + admins allowlist** (depends on sessions).
4. **Config fail-fast + main.go wiring** (depends on auth being available).
5. **Body cap + audit retention sweep + nightly backup** (independent maintenance/server hardening; can parallel 2–4).
6. **Packaging: Dockerfile + compose + Caddyfile + deploy/restore docs** (last; depends on the env contract above).

See `[[subsystem-f-progress]]` for status tracking.
