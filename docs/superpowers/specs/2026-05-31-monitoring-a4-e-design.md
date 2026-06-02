# Redactr v2 — Subsystem A4 + E: Monitoring Design

**Status:** Design (autonomous-build mandate). Implementation plan follows.
**Date:** 2026-05-31
**Parent:** subsystem A (A4 ingestion) + subsystem E (host-scan client). A1/A2 merged.
**Fills SEAM:** A1's `// SEAM A4: POST /v1/events`; extends the existing `internal/sessions` host-process classifier.

## Goal

Give org admins fleet visibility into AI-tool sessions across enrolled devices, **metadata only**: each client periodically scans its host processes (reusing `internal/sessions`), classifies each AI session (protected / runaway / unknown), and pushes a batch of **metadata events** to the control-plane server, which stores and aggregates them per-org. The server never receives command lines, file contents, or raw connection strings.

## Privacy invariant (hard)

An event carries only: `tool` (label, e.g. "Claude Code"), `verdict`, `reason` (the fixed classifier reason string), `observed_at`, and `direct_conn_count` (how many direct-to-AI-provider connections were seen — an integer, not the addresses). **No command lines, no raw `host:port` connection strings, no environment values.** This preserves the architecture's "server only sees metadata" guarantee.

## Components

### A4 — Server (extends `internal/server`)
1. **Store**: `events` table — `id`, `org_id`, `device_id`, `tool`, `verdict`, `reason`, `direct_conn_count`, `observed_at`, `received_at`. Methods:
   - `InsertEvents(orgID, deviceID string, evs []Event) error` (batch insert in one tx).
   - `ListEvents(orgID string, limit int) ([]Event, error)` (recent first).
   - `CountByVerdict(orgID string, since time.Time) (map[string]int, error)` (fleet aggregation for the A5 dashboard).
2. **HTTP**:
   - `POST /v1/events` (RequireDevice): body `{ "events": [ {tool, verdict, reason, direct_conn_count, observed_at} ... ] }`; server stamps `org_id`/`device_id` from the auth context + `received_at`; inserts; returns `{ "accepted": N }`. Caps batch size (e.g. 500) → 400 if exceeded.
   - `GET /admin/orgs/{id}/events?limit=` (admin): recent events for the org (the A5 dashboard wraps this).
   - `GET /admin/orgs/{id}/event-stats?since_hours=` (admin): verdict counts.

### E — Client (extends the desktop client)
3. **`internal/monitor`**: `Event` DTO (in `internal/control`, shared) + `Collect(lister *sessions.Lister) []control.MonitorEvent` — runs `lister.List()`, maps each `sessions.Session` to a privacy-scrubbed `MonitorEvent` (tool, verdict=Status, reason, direct_conn_count=len(DirectAIConn), observed_at=now). `Report(baseDir, evs)` — if enrolled, POST the batch to `<server>/v1/events` with the device bearer token; fail-open (log, never crash); no-op if not enrolled or no events.
4. **Daemon wiring**: a monitor-report loop (enrolled-gated, `!Ephemeral`, ~60s ticker) that collects from the daemon's existing `sessions.Lister` (already constructed in `daemon.Build` for the dashboard) and reports. Cancelled in `Stop`.

## Verdict model

Reuse the existing `sessions` classification: **protected** (REDACTR_BOUND / proxy env / via-proxy, no direct AI conn), **runaway** (direct connection to an AI provider, bypassing the proxy), **unknown** (no AI traffic observed yet). The architecture's finer **"unsandboxed"** verdict (native VS Code redacted-but-not-containerized) needs container-tag + editor detection and is left a **`// SEAM`** — the event schema already carries a free-form `verdict` string so adding it later needs no migration.

## Data flow

```
daemon timer ──Collect(lister.List())──▶ []MonitorEvent (metadata only)
            ──POST /v1/events (Bearer)──▶ server ──InsertEvents(org,device,evs)──▶ events table
admin/dashboard ──GET /admin/orgs/{id}/events / event-stats──▶ fleet view (A5)
```

## Error handling / fail-open

| Case | Behavior |
|---|---|
| Not enrolled | report is a no-op (local scan/dashboard still work, unchanged) |
| No AI sessions found | no events posted (skip the POST) |
| Server unreachable / 401 | log, drop this batch, retry next tick (events are ephemeral; no local queue in v2) |
| Batch > cap | server 400; client logs (shouldn't happen at 60s cadence) |
| Scan error (`lister.List`) | log, skip this tick |

## Testing

Pure-Go, httptest, no external services.
- Store: `InsertEvents` batch round-trips; `ListEvents` ordering + limit; `CountByVerdict` since-filter.
- HTTP: enrolled `POST /v1/events` stamps org/device from context + persists; over-cap → 400; `GET /admin/.../events` returns them; `event-stats` counts; unauth POST → 401.
- `internal/monitor`: `Collect` maps a fake session list to scrubbed events (asserts NO command line / raw connection string leaks into the DTO); `Report` posts to an httptest server with the bearer token; not-enrolled → no-op.
- Daemon: enrolled-gate (reuse `shouldSyncPolicy`-style gate), Ephemeral never starts the loop.

## Build order (A4+E tasks)

1. `control.MonitorEvent` DTO + server `events` store (table + Insert/List/CountByVerdict).
2. Server HTTP: `POST /v1/events`, `GET /admin/orgs/{id}/events`, `.../event-stats`.
3. `internal/monitor`: `Collect` (privacy-scrubbing) + `Report` (enrolled-gated POST, fail-open).
4. Daemon wiring: monitor-report loop (ticker, gated) + smoke.

## Out of scope / SEAMs

- `// SEAM:` "unsandboxed" verdict (needs container-tag + editor detection).
- `// SEAM A5:` dashboard fleet view consumes `GET /admin/.../events` + `event-stats`.
- Local event queue / durable delivery (v2 drops on failure; retry next tick).
- Event retention/rollup (store all for v2; a retention job is future work).
