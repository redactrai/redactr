# Redactr v2 — Subsystem A2: Policy Distribution Design

**Status:** Design (approved under the autonomous-build mandate). Implementation plan follows.
**Date:** 2026-05-31
**Parent:** subsystem A (`...redactr-v2-architecture-design.md`); A1 (server foundation) is merged.
**Fills SEAM:** `internal/policy` ("subsystem A will refresh the persisted policy from the signed server bundle") and the A1 `// SEAM A2: GET /v1/policy` route.

## Goal

Make the desktop client's launch policy **server-driven and tamper-evident**: an org admin sets a policy on the control-plane server; the server distributes it as an **ECDSA-signed bundle**; the client enrolls, fetches the bundle (ETag-cached, fail-open), **verifies the signature against the server's public key**, and refreshes its local `policy.json` cache — which the daemon already serves to `redactr claude` via `/launch-policy`.

## Locked decisions

Inherit subsystem A's stack (Go, embedded SQLite, ECDSA, single self-hosted server, signed bearer-token auth). New:
- **Signed bundle = the A1 token scheme generalized to detached signatures**: `signature = ECDSA-P256(sha256(base64url(bundleJSON)))`. A shared leaf package `internal/signing` provides `Sign`/`Verify`/`PublicKeyPEM`/`ParsePublicKeyPEM` so the server signs with its private key and the client verifies with the server's **public** key only.
- **Server public key reaches the client at enrollment** (added to the A1 enroll response) and via a public `GET /v1/server-key`. The client stores it; no build-time-embedded key (the server generates its own keypair per deployment).
- **Policy bundle shape** mirrors what the client already consumes: `{ image, mountMode, denylist[], version }` (matches `internal/policy.Policy` + `control.LaunchInfo`). Per-repo mount-mode overrides and `ref@digest` are forward-compatible fields (A3 fills digests) — included as optional map/struct, defaulted empty.

## Components

### S — Server side (extends `internal/server`)
1. **`internal/signing`** (new leaf): detached ECDSA sign/verify over `sha256(base64url(payload))`; `PublicKeyPEM(priv)`, `ParsePublicKeyPEM(s)`.
2. **Store**: `policies` table — `org_id PK`, `bundle_json`, `version`, `updated_at`. Methods `GetPolicy(orgID)`, `PutPolicy(orgID, bundleJSON)` (bumps version). Default when unset: the seed bundle (`image=redactr-base:local`, `mountMode=bind`, empty denylist, version 0).
3. **HTTP**:
   - `PUT /admin/orgs/{id}/policy` (admin): replace the org's policy bundle (validates JSON shape), bumps version.
   - `GET /admin/orgs/{id}/policy` (admin): current bundle + version.
   - `GET /v1/policy` (RequireDevice): returns `{ bundle: base64url(bundleJSON), signature: base64url(sig), version: N }` signed with the server key; sets `ETag: "v<N>"`; honors `If-None-Match` → **304**.
   - Enroll response gains `server_public_key` (PEM); add public `GET /v1/server-key` → `{ public_key: PEM }`.

### C — Client side (extends the B desktop client)
4. **`internal/enrollment`** (new): typed `~/.redactr/enrollment.json` `{ server_url, device_token, server_public_key, device_id, org_id }` with `Load`/`Save`/`Exists`.
5. **`redactr enroll --server <url> --token <enrollment-token>`** (new CLI subcommand): POST `/v1/enroll`, capture the device token + `server_public_key`, write `enrollment.json`. Idempotent-ish (re-enroll overwrites).
6. **`internal/policysync`** (new): `Sync(baseDir)` — if enrolled, `GET /v1/policy` with `Authorization: Bearer <device_token>` and `If-None-Match: <cached etag>`; on `200`, **verify the signature** against the stored server public key, decode the bundle, and write it through `internal/policy.Save` + persist the new ETag; on `304` keep cache; on any error (offline, bad signature, 401) **fail-open** (keep the cached policy, return a sentinel/log, never crash the launch path).
7. **Daemon wiring** (`internal/daemon`): if `enrollment.Exists`, run `policysync.Sync` at `Start` and on a ticker (default 10 min). Not enrolled → no-op (today's seeded fail-open behavior, unchanged). The existing `/launch-policy` continues to serve `policy.json` — now server-refreshed.

## Data flow

```
admin ──PUT /admin/orgs/{id}/policy──▶ server (policies table, version++)
client ──POST /v1/enroll──▶ server ──{device_token, server_public_key}──▶ enrollment.json
daemon timer ──GET /v1/policy (Bearer, If-None-Match)──▶ server
        ◀──{bundle_b64, signature, version} (ETag v N) or 304──
        verify sig w/ server_public_key → policy.Save(bundle) → /launch-policy serves it
```

## Error handling / fail-open

| Case | Behavior |
|---|---|
| Not enrolled | sync is a no-op; daemon serves the seeded local policy (unchanged) |
| Server unreachable / timeout | keep cached `policy.json`; log; retry next tick |
| 304 Not Modified | keep cache (no write) |
| Signature verification fails | **reject the bundle**, keep cache, log a security warning (a tampered/forged bundle never reaches `/launch-policy`) |
| 401 (revoked device) | keep cache, log; (re-enroll needed) |
| Admin PUT bad JSON | 400 |

## Testing

Pure-Go, httptest, temp dirs — no external services.
- `internal/signing`: sign→verify round-trip; tamper + foreign-key rejection.
- Store: `PutPolicy` bumps version; `GetPolicy` returns seed when unset; round-trip.
- HTTP: `PUT` then `GET /v1/policy` returns a bundle whose signature verifies with the server pubkey; `If-None-Match` of the current version → 304; `GET /v1/server-key` returns a parseable PEM; enroll response carries the pubkey.
- `internal/enrollment`: save/load round-trip; `Exists`.
- `internal/policysync`: against an httptest server — 200 verifies+caches+writes policy.json; 304 keeps cache; bad signature rejected (cache unchanged); offline → fail-open.
- Daemon: enrolled smoke (sync runs once, policy.json updated from a fake server); not-enrolled smoke (no-op, existing behavior).

## Build order (A2 tasks)

1. `internal/signing` (detached ECDSA + PEM helpers).
2. Server store: `policies` table + `GetPolicy`/`PutPolicy` + seed default.
3. Server HTTP: admin `PUT/GET policy`, `GET /v1/policy` (signed+ETag), `GET /v1/server-key`, enroll response pubkey.
4. `internal/enrollment` (enrollment.json load/save).
5. `redactr enroll` CLI subcommand.
6. `internal/policysync` (fetch+verify+cache, fail-open).
7. Daemon wiring (sync loop on Start + ticker, enrolled-gated) + smoke.

## Out of scope / SEAMs

- `// SEAM A3:` image `ref@digest` populated into the bundle by the image pipeline; the bundle field exists now, empty.
- `// SEAM A4/A5:` monitoring push + dashboard policy editor (A5 wraps the admin policy API).
- Bundle schema migration/versioning beyond the integer `version` (YAGNI for v2).
- mTLS / token refresh (unchanged from A1 decisions).
