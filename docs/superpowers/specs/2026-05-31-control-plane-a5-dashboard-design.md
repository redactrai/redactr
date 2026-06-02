# Redactr v2 — Subsystem A5: Hosted Admin Dashboard Design

**Status:** Design (autonomous-build mandate). Implementation plan follows.
**Date:** 2026-05-31
**Parent:** subsystem A (A5). A1/A2/A4 merged — the admin API the dashboard wraps already exists and is tested.

## Goal

A multi-tenant admin web UI served by `redactr-server`, giving an org admin a single place to: create orgs, mint enrollment tokens, view the device registry (and revoke devices), edit the per-org policy, and watch the fleet monitoring feed (events + verdict stats). It is a thin client over the **already-built, already-tested** admin API; no new server business logic, just static-asset serving + the UI.

## What it wraps (existing endpoints, all admin-key-gated)

`GET/POST /admin/orgs` · `POST /admin/orgs/{id}/enrollment-tokens` · `GET/PUT /admin/orgs/{id}/policy` · `GET /admin/orgs/{id}/events` · `GET /admin/orgs/{id}/event-stats` · `GET /admin/devices?org=` · `POST /admin/devices/{id}/revoke`.

## Approach

Follow the **existing v1 dashboard pattern exactly** (`internal/api/embed.go` → `//go:embed static/*` + `http.FileServer`): a static, framework-free vanilla-JS app embedded into the binary and served at `/`. No build step, no npm — consistent with the project's single-binary, zero-runtime-deps ethos.

- **`internal/server/httpapi/dashboard/`** — `index.html`, `app.js`, `style.css` (vanilla JS, `fetch`).
- **`internal/server/httpapi/embed.go`** — `//go:embed dashboard/*` + `dashboardHandler() http.Handler` (`http.FileServer` over an `fs.Sub`).
- **Route** — `s.mux.Handle("GET /", dashboardHandler())`. Go 1.22's pattern mux gives the precise `/v1/*`, `/admin/*`, `/healthz` routes priority; `/` is the fallback that serves the SPA. (Replaces the A5 SEAM comment.)

## Auth model (dashboard)

The admin API is gated by `X-Admin-Key`. The dashboard prompts for the admin key on load, holds it in `sessionStorage` (never localStorage), and sends it as `X-Admin-Key` on every `fetch`. A 401 clears the stored key and re-prompts. This is the A1 "single admin key" model surfaced in the UI; richer admin accounts/SSO remain a later concern (noted in A1).

## UI structure (single page, hash-routed)

1. **Key gate** — if no key in `sessionStorage`, show a key entry; on submit, validate with `GET /admin/orgs` (200 → store, else error).
2. **Orgs** — list orgs; "Create org" (name → `POST /admin/orgs`); select an org → org detail.
3. **Org detail** (tabs):
   - **Overview** — verdict stats from `event-stats` (counts: protected / runaway / unknown) with a prominent **runaway alert** banner if `runaway > 0`.
   - **Devices** — `GET /admin/devices?org=` table (name, platform, enrolled, last-seen, revoked); per-row "Revoke" → `POST /admin/devices/{id}/revoke`.
   - **Enrollment** — "Mint token" (expires-in-hours, max-uses) → `POST .../enrollment-tokens`; show the raw token **once** with a copy button + the exact `redactr enroll --server <thisServer> --token <token>` command.
   - **Policy** — load `GET .../policy`; editable form (image, mountMode select bind/diffback, denylist textarea one-per-line) → `PUT .../policy`; show the resulting version.
   - **Events** — `GET .../events?limit=100` table (device, tool, verdict, reason, conn-count, observed/received); auto-refresh every 10s; runaway rows highlighted.

## Error handling

| Case | Behavior |
|---|---|
| Missing/invalid admin key | gate screen; 401 anywhere → clear key + re-prompt |
| Network error | inline error toast; retry button |
| Empty lists | friendly empty-state text |
| Mint token shown once | explicit "copy now, won't be shown again" note |

## Testing

The UI itself is browser-verified (deferred to a running server). Automated coverage:
- **Go:** `dashboardHandler` serves `GET /` → 200 `text/html` containing a known marker (e.g. `<title>Redactr Control Plane</title>`); `GET /app.js` serves `application/javascript`; the precise API routes still win over `/` (e.g. `GET /healthz` still returns the health JSON, not HTML). One `server_test.go` test.
- **Manual (documented):** run `redactr-server`, open `/`, enter the admin key, exercise create-org → mint → (enroll a device via CLI) → see it in Devices + Events → edit policy.

## Build order (A5 tasks)

1. `embed.go` (`//go:embed dashboard/*` + handler) + the `GET /` route + a placeholder `dashboard/index.html` + the Go serving test (route precedence: `/healthz` still JSON, `/` HTML).
2. The dashboard assets: `index.html` + `style.css` + `app.js` (key gate, orgs, org-detail tabs: overview/devices/enrollment/policy/events).

## Out of scope / SEAMs

- Admin accounts / SSO / per-admin RBAC (A1 single-key model for now).
- Image management UI — deferred to **A3** (image pipeline) which adds the image endpoints; the dashboard gains an Images tab then.
- Charts/graphs beyond simple counts (YAGNI for v2).
- Live websocket push (10s poll is sufficient).
