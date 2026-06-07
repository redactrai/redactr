# Subsystem F — Fleet Operations & Distribution — Architecture Design

**Status:** Architecture spec (approved). Each sub-project (F1–F4) gets its own implementation spec → plan → build afterward.
**Date:** 2026-06-05
**Builds on:** [Redactr v2 — Architecture Design](2026-05-30-redactr-v2-architecture-design.md) (subsystems A–E, the protection mechanism — already built).

## Problem

The v2 protection mechanism (A–E) is implemented: enrollment, signed policy distribution, image pipeline, monitoring ingestion, dashboard, and the hardened sandbox all exist. But v2 **deliberately deferred every operational concern** required to actually run Redactr across a fleet. Concretely, today:

- **There is no packaging or distribution.** You build three Go binaries locally and run them. No installers, no releases, no service supervision — the daemon does not auto-start or survive a reboot.
- **There is no production server deployment.** `redactr-server` is HTTP-only (no TLS), authenticated by a single static `X-Admin-Key`, single SQLite instance, no backups, no formal migrations.
- **Audit/event delivery is at-most-once and fail-open.** `internal/monitor/monitor.go` POSTs `MonitorEvent`s every 60s; on any error `daemon.go` logs a warning and **drops the batch** — no local persistence, no retry, no idempotency. The v2 doc itself called for "queue monitoring, sync later," but the implementation does not. Redaction findings (`ScanReport`s) never leave the machine at all — they sit in local BoltDB.
- **The dashboard cannot answer "which machines are actually using the proxy"** (it shows raw `last_seen` timestamps, no online/offline or bypass rollup) and has **no central toggles** (policy carries image/mount/denylist only; the proxy/scan-layer knobs live in each machine's local `config.yaml`).

This spec defines **Subsystem F**: the operational layer that makes Redactr shippable to, and observable across, a fleet of self-hosted single-org devices.

## Scope & target environment

**Target (locked):** self-hosted, single org. One company runs its own `redactr-server` (single instance, SQLite is sufficient) and distributes the client to its own employees. No multi-tenant SaaS, no HA/Postgres, no air-gapped distribution in this pass.

Subsystem F is purely operational. **It does not touch the proxy/scanner/sandbox data path.** The v2 privacy invariant — *the server never sees traffic, code, or redacted values* — is preserved, with **one deliberate, user-approved widening**: the server additionally receives **redaction-finding metadata** (detector, category, provider, action, timing, timestamp, device) and **never** raw values or request bodies.

## Decisions (locked)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Central audit-log content | **Redaction-finding metadata** (categories/counts/timestamps) shipped to the server, in addition to posture events. Never raw values or bodies. |
| 2 | Delivery durability (F1) | **Generic durable outbox** (Approach A): one append-only store, single sender, UUID idempotency, server-side dedup → **effectively-once**. |
| 3 | Code signing (F2) | **Signing-ready but unsigned for now.** Pipeline has inert, env-gated signing hooks; ships unsigned artifacts + SHA-256 checksums + trust docs until certs exist. |
| 4 | Enrollment (F2) | **Interactive, token-based.** No credential baked into the installer. Admin mints a short-lived, low-max-use, revocable token from the dashboard; user runs `redactr enroll`. Requires server TLS. |
| 5 | Auto-update (F2) | **Deferred.** "Update available" nudge in tray + dashboard; manual re-install. Revisit once code-signing exists. |
| 6 | Client install targets (F2) | **macOS (`.pkg`) + Windows (`.msi`)** only — the native host app per v2. Linux is the container OS, not a client host. |
| 7 | Server packaging (F3) | Minimal **Linux container image** + bundled `docker-compose` with **Caddy** (automatic Let's Encrypt TLS). SQLite retained. |
| 8 | Admin auth (F3) | **OIDC/SSO for normal admins** + a single local **super-admin** username/password account (break-glass/bootstrap, full scope). Overrides v2's "SSO deferred." Static `X-Admin-Key` retired for humans. |
| 9 | Central toggles (F4) | Feature flags ride the **existing signed + versioned policy bundle**; **org-wide only** (per-device overrides stay deferred). Daemon honors policy over local `config.yaml`. |
| 10 | Build order | **F1 → F3 → F2 → F4.** |

### Note on overrides

Decision 8 (OIDC/SSO) overrides the v2 architecture's "User identity / SSO — later" deferral. This is an explicit user choice for Subsystem F because the dashboard becomes internet-facing in a real fleet deployment, where a single static shared key is unsafe to expose. The local super-admin account exists for bootstrap and IdP-outage break-glass.

## Topology delta

Only the new/changed edges relative to v2 are shown.

```
Dev machine (macOS/Windows)                          Linux host
┌───────────────────────────────┐                   ┌─────────────────────────────┐
│ redactr daemon                 │                   │ Caddy (auto-TLS, :443)      │
│  ├─ scanner → ScanReport ──┐   │                   │   └─▶ redactr-server         │
│  ├─ monitor → MonitorEvent ┤   │   HTTPS / TLS     │        ├─ OIDC + super-admin  │
│  │            ▼            │   │   batched POST     │        ├─ dedup (UUID UNIQUE) │
│  │      durable outbox ────┼───┼──────────────────▶│        ├─ audit + events store│
│  │      (BoltDB bucket)    │   │   POST /v1/ingest  │        └─ fleet dashboard      │
│  └─ launchd / Win service  │   │   (acked, idempotent) │     SQLite + nightly backup │
│     keeps daemon alive      │  │                   └─────────────────────────────┘
└───────────────────────────────┘
   installed via signing-ready .pkg / .msi; enrolled via short-lived admin token
```

## Sub-projects

| | Sub-project | Responsibility | Answers original question |
|---|---|---|---|
| **F1** | Durable, effectively-once delivery | Persistent outbox, retry/backoff, idempotency, server dedup, flush-on-restart; ships posture events + redaction-finding metadata | "Guarantee one-time delivery of audit logs" |
| **F2** | Packaging, install & enrollment | Signed-ready installers, service supervision, interactive enrollment, update nudge | "Start locally vs install on a server and share an installable to users" |
| **F3** | Server production deployment | Container image, TLS, OIDC + super-admin, migrations, backups | "Install this on a server" (server side) |
| **F4** | Fleet visibility + central toggles | Online/offline, protected-vs-bypassing rollup, redaction audit view, policy feature flags | "Which machines use the proxy" + "toggleable settings" |

---

### F1 — Durable, effectively-once delivery

**Design: generic durable outbox (Approach A).**

- **Outbox store.** A new append-only bucket in the existing `~/.redactr/data/logs.db` (BoltDB — no new dependency). Both event streams write through it the instant they are generated:
  - `MonitorEvent` — posture metadata (tool, verdict `protected`/`runaway`/`unsandboxed`, reason, `direct_conn_count`, observed_at). Unchanged shape.
  - `AuditRecord` — **new**: ScanReport metadata. Fields: detector, category (e.g. `aws_key`), provider, action (`blocked`/`allowed`), latency_ms, observed_at, device. **Never** the raw value, the redacted value, or any request/response body.
- **Record envelope.** Each outbox record carries a client-generated **UUID**, a **monotonic per-device sequence**, a `kind` discriminator, and the payload. The write is **synchronous and durable** before the generating request is considered "logged" — a scan or monitor tick is not acknowledged complete until its record is in the outbox.
- **Sender.** One background goroutine drains the outbox:
  - Batch up to 500 records → `POST /v1/ingest` over TLS.
  - On `2xx`: delete the acked UUIDs from the bucket.
  - On failure (network/5xx/timeout): exponential backoff (base ~1s, cap ~5 min), retry indefinitely. The 60s monitor tick is decoupled from delivery — generation and sending are independent.
  - On daemon restart: re-read the bucket and resume. Nothing is lost to a crash, a network outage, or an offline laptop. This finally delivers the v2 "queue monitoring, sync later" intent.
- **Server idempotency.** Ingest tables carry `UNIQUE(uuid)`. Ingest is an idempotent insert-or-ignore that returns the set of accepted UUIDs. Retries are harmless → **effectively-once** (at-least-once transport + idempotent sink). The response may include a high-water-mark to let the client prune aggressively.
- **Bounds & safety valve.** The outbox has a max-age/size cap. If the cap is ever hit (server unreachable for a very long time), the oldest records are dropped **and the drop is logged** — never a silent truncation. Default cap sized generously (e.g. weeks of normal volume).
- **Server retention.** Audit + event records retained for a configurable window (default 365 days); a daily sweep prunes older rows.

**Why this shape:** one durable path for all telemetry, reusing existing storage, pure-Go, no new dependency; idempotency makes retries safe; the offline-laptop case is handled for free.

---

### F2 — Packaging, install & enrollment

- **Artifacts & CI.** A `goreleaser`-style release pipeline produces:
  - macOS **`.pkg`** and Windows **`.msi`** for the client (daemon + tray + CLI).
  - SHA-256 **checksums** for every artifact, and a **Homebrew tap** formula.
  - Published via **GitHub Releases**.
  - **Signing hooks are wired but inert**, gated behind CI env/secrets (Apple Developer ID for macOS notarization; an EV/OV cert for Windows). Turning on signing later requires no redesign — only providing the identities. Until then, artifacts are unsigned and shipped with checksums + manual-trust documentation.
- **Service supervision.** The installer registers the daemon to **auto-start on login/boot and survive reboot**, and to **restart on crash**:
  - macOS: a `launchd` LaunchAgent for the daemon; tray as a login item.
  - Windows: a **Windows Service** for the daemon; tray as a login item.
  - `redactr cleanup` remains the firewall/escape-hatch command.
- **Enrollment (interactive, token-based).** The installer ships **generic** — no embedded credential.
  1. Admin mints a **short-lived, low-max-use, revocable** enrollment token in the dashboard (mechanism already exists: `POST /admin/orgs/{id}/enrollment-tokens`).
  2. User runs `redactr enroll --server <url> --token <token>` (existing flow), **hardened to require TLS** (refuse plaintext `http://` except an explicit dev override).
  3. Device appears in the **device registry** (name, platform, enrolled-at, last-seen), giving the admin the "who is registered" view.
  - No credential is ever baked into a widely-distributed installer. Token expiry + max-uses + revocation bound the blast radius.
- **Auto-update (deferred).** No self-updater. The daemon polls the server's published latest version and surfaces an **"update available"** nudge in the tray and dashboard with a download link. Upgrade is a manual re-install. Revisit once code-signing exists (auto-updating unsigned binaries is unsafe).

---

### F3 — Server production deployment

- **Packaging.** `redactr-server` ships as a minimal Linux container image (distroless/scratch base + the static binary). A bundled **`docker-compose.yml`** runs:
  - **Caddy** as a reverse proxy terminating TLS with **automatic Let's Encrypt** on :443.
  - `redactr-server` behind it.
  - A volume holding the SQLite DB, server keys, and backups.
  - Also documented for a pre-existing reverse proxy (nginx/Traefik) instead of Caddy.
  - Single org → single instance; SQLite retained (no Postgres/HA in this pass).
- **Config.** All via environment (existing pattern): `REDACTR_SERVER_ADDR`, `REDACTR_SERVER_DB`, `REDACTR_SERVER_KEY_DIR`, OIDC settings (issuer, client id/secret, redirect), and super-admin bootstrap credentials. The server **fails fast** with a clear error if required TLS/auth settings are missing outside an explicit dev mode.
- **Admin auth (OIDC + super-admin).** Two roles, both backed by **server-side sessions** (HttpOnly, Secure cookies):
  - **super-admin** — a single local username/password account, bcrypt-hashed, bootstrapped from env on first boot. Full scope: configure OIDC, manage admins, break-glass when the IdP is down.
  - **admin** — logs in via **OIDC/SSO**; scoped to org operations (orgs, devices, tokens, policy, audit/fleet views). No local password.
  - The static `X-Admin-Key` is **retired for humans**. A named, revocable machine key path may remain for CI/scripts only.
- **DB lifecycle.** Versioned, forward-only **migrations** applied on startup (formalizing today's auto-applied schema). A **nightly backup** (SQLite `VACUUM INTO` to a timestamped file in the volume, retain N) with a documented restore procedure — the server-side durability backstop for the audit log.

---

### F4 — Fleet visibility + central toggles

- **Online/offline.** Derived from `last_seen_at` (already touched on every authenticated request via the auth middleware). A device is **online** if seen within a threshold (default ≈ 3× the report interval ≈ 3 min), otherwise **offline/stale**. Dashboard shows a per-device badge and a fleet rollup (online / total, platform breakdown).
- **Protected vs. bypassing.** Rolled up **per device** from existing `MonitorEvent.verdict` + `direct_conn_count`: a clear "routing through the proxy" vs. "**bypassing** — AI traffic going direct" indicator, with the runaway count. This is the direct answer to "which machines are using the proxy and which are not."
- **Redaction audit view.** A new dashboard view over F1's `AuditRecord`s: filter by device / category / provider / time; counts and trends (e.g. "7 AWS keys redacted across 3 devices this week"). No values are shown (none are stored).
- **Central toggles (via signed policy).** `control.PolicyBundle` gains a `Features` map. The dashboard Policy tab renders **switches** for: proxy on/off, each scan layer (regex / entropy / GLiNER), file-blocking, and a `strict`/`audit` mode. The daemon honors policy `Features` **over** the local `config.yaml`. Toggles ride the **existing signed + versioned** bundle, so they are tamper-evident and **fail-open with the cached value** when the server is unreachable. **Org-wide only**; per-device overrides remain deferred (consistent with v2).

---

## Cross-cutting

### Data model deltas

**Server (SQLite):**
- `audit_records` — `uuid TEXT UNIQUE`, `org_id`, `device_id`, `detector`, `category`, `provider`, `action`, `latency_ms`, `observed_at`, `received_at`. Index on `(org_id, received_at)`.
- `events` — add `uuid TEXT UNIQUE` for idempotent ingest.
- `admins` — id, email/username, role (`super_admin`/`admin`), password_hash (super-admin only), created_at, disabled.
- `sessions` — id, admin_id, expires_at.

**Client:**
- New BoltDB outbox bucket (envelope: uuid, seq, kind, payload, created_at).
- Per-device monotonic sequence counter (persisted).

**Control structs (`internal/control`):**
- New `AuditRecord`.
- `PolicyBundle` extended with `Features map[string]bool` (still signed + versioned).

### API deltas
- `POST /v1/ingest` — unified, idempotent, batched ingest for `MonitorEvent` + `AuditRecord` (supersedes/extends `POST /v1/events`); returns accepted UUIDs + optional high-water-mark.
- OIDC routes: `/auth/login`, `/auth/callback`, `/auth/logout`; super-admin local login.
- Admin/fleet read endpoints for online/offline rollup, bypass rollup, and the redaction audit view.
- Version endpoint for the client update nudge.

### Testing strategy
- **F1 (heaviest):** outbox durability (write → kill process → reopen → resume); idempotency (duplicate UUID → single row); backoff behavior; offline→online drain; an end-to-end "laptop offline for an hour, then syncs → server has each record exactly once" integration test; safety-valve drop is logged.
- **F3:** migration apply on fresh + upgrade; backup/restore round-trip; OIDC login happy path; super-admin break-glass with IdP unreachable; rejection of plaintext where TLS is required.
- **F2:** installer registers + starts the service; service restarts after kill; enroll refuses plaintext; update nudge appears when server reports a newer version.
- **F4:** online/offline threshold logic; bypass rollup from synthetic events; toggle propagation (dashboard → signed bundle → daemon honors over local config); fail-open to cached features when offline.

### Build order (dependency-driven)
Each is its own spec → plan → build:

1. **F1 — Durable delivery.** Foundational and the user's flagged-critical item. Client outbox + unified idempotent ingest + server dedup.
2. **F3 — Server deployment.** TLS + OIDC/super-admin + ingest dedup storage + migrations + backups. Enrollment-over-internet and trustworthy storage depend on it.
3. **F2 — Packaging & enrollment.** Installers + service supervision + interactive enroll. Needs F3's TLS endpoint to enroll against.
4. **F4 — Fleet view + toggles.** Needs F1's reliable data and F3's auth.

> Note: this revises the earlier off-hand "F1 → F2 → F3 → F4" ordering. F3 precedes F2 because the installer's enrollment step requires a TLS-terminated server to enroll against.

## Threat model & residual gaps

| Vector | F outcome |
|--------|-----------|
| Audit log lost on network outage / crash / offline laptop | **Mitigated** — durable outbox + retry + flush-on-restart (effectively-once). |
| Duplicate delivery on retry | **Mitigated** — UUID idempotency + server `UNIQUE`. |
| Server exposed on the internet with a shared static key | **Mitigated** — TLS + OIDC + sessions; static key retired for humans. |
| Installer leaks an embedded enrollment credential | **Avoided** — no baked-in token; interactive short-lived token only. |
| Server now knows redaction categories per device | **Accepted, bounded** — metadata only (categories/counts), never values/bodies; user-approved widening of the v2 invariant. |
| Server DB loss | **Mitigated** — nightly backup + documented restore. |
| Unsigned installers / no auto-update | **Residual (accepted now)** — checksums + trust docs; signing hooks ready; auto-update deferred until certs exist. |
| Rogue device enrolled with a stolen token | **Residual, bounded** — token expiry/max-use/revocation; device visible in registry and revocable; still fully sandboxed and policy-controlled. |
| Per-device policy/toggle overrides | **Deferred** — org-wide only, consistent with v2. |

## Explicitly deferred (not in Subsystem F)

- Multi-tenant SaaS, HA, Postgres, horizontal scale (target is self-hosted single-org).
- Air-gapped / offline installer & image distribution.
- Client auto-update / self-update.
- OS code-signing identities (pipeline is ready; identities are an ops task).
- Per-device policy and per-device toggle overrides.
- Live push channel (WebSocket) — ingest stays polled/batched, naturally fail-open.

## Open items for sub-project specs

- Exact `AuditRecord` field list and category taxonomy (reconcile with existing `ScanReport`).
- Outbox cap sizing and prune/high-water-mark protocol details.
- OIDC library choice and session storage (DB vs signed cookie) specifics.
- `goreleaser` config, notarization/signing hook shape, and Homebrew tap repo location.
- launchd plist / Windows Service definitions and tray autostart specifics.
- Caddy vs documented-reverse-proxy compose layout and volume/backup paths.
- Feature-flag key names and how the daemon merges policy `Features` over `config.yaml`.
