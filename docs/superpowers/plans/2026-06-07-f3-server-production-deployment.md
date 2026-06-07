# F3 — Server Production Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `redactr-server` safe to deploy on an internet-exposed host for a fleet: versioned migrations, OIDC + break-glass super-admin on server-side sessions, fail-fast config, nightly backups + audit retention, request-body caps, and a turnkey TLS-terminated container deployment.

**Architecture:** Build on A1's `internal/server/{store,auth,httpapi,keys}` and `cmd/redactr-server`. Introduce a numbered migration runner, a `sessions`/`admins` schema, cookie-based server-side sessions, an OIDC authorization-code (PKCE) flow, a session/role middleware that replaces the static `X-Admin-Key`, and a maintenance loop (backups + retention). Package as a distroless image behind Caddy via docker-compose.

**Tech Stack:** Go 1.26, `modernc.org/sqlite`, `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`, `golang.org/x/crypto/bcrypt`, Caddy, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-06-07-f3-server-production-deployment-design.md`

---

## File Structure

- `internal/server/store/migrate.go` — **replace** ad-hoc probe with a numbered runner over embedded `migrations/*.sql`.
- `internal/server/store/migrations/000{1,2,3}_*.sql` — embedded migration files (init, events.uuid, F3 tables).
- `internal/server/store/sessions.go` + `_test.go` — session/admin CRUD on the store.
- `internal/server/auth/session.go` + `_test.go` — `RequireSession`, cookie helpers, super-admin verify (bcrypt).
- `internal/server/auth/oidc.go` + `_test.go` — OIDC provider wrapper, auth-URL builder, callback verifier (mock-IdP tested).
- `internal/server/httpapi/admin_auth.go` + `_test.go` — login/logout/oidc/admins handlers + login form.
- `internal/server/httpapi/server.go` — wire new routes, swap `RequireAdmin`→`RequireSession`, add `MaxBytesReader`.
- `internal/server/config/config.go` + `_test.go` — typed config + fail-fast validation (new package).
- `internal/server/maint/maint.go` + `_test.go` — backup + retention maintenance loop (new package).
- `cmd/redactr-server/main.go` — load config, build auth, start maintenance loop.
- `deploy/Dockerfile`, `deploy/docker-compose.yml`, `deploy/Caddyfile`, `deploy/README.md` — packaging + ops docs.

---

## Task 1: Numbered migration framework

Replaces the ad-hoc PRAGMA probe with embedded numbered migrations recorded in `schema_migrations`. The existing `schema.sql` content becomes `0001_init.sql`; the `events.uuid` add becomes `0002`.

**Files:**
- Create: `internal/server/store/migrations/0001_init.sql` (move current `schema.sql` body here verbatim)
- Create: `internal/server/store/migrations/0002_events_uuid.sql`
- Create: `internal/server/store/migrations/0003_f3_auth.sql`
- Modify: `internal/server/store/migrate.go` (replace runner), `internal/server/store/store.go` (call new runner; drop `//go:embed schema.sql` if superseded)
- Test: `internal/server/store/migrate_test.go`

- [ ] **Step 1: Write the failing test.** In `migrate_test.go`:

```go
func TestMigrationsFreshDBAppliesAllInOrder(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "t.db"))
	if err != nil { t.Fatalf("Open: %v", err) }
	defer db.Close()
	got := appliedVersions(t, db) // helper: SELECT version FROM schema_migrations ORDER BY version
	want := embeddedVersions(t)   // helper: parse migrations/*.sql filenames
	if !reflect.DeepEqual(got, want) { t.Fatalf("applied=%v want=%v", got, want) }
}

func TestMigrationsReopenIsNoOp(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.db")
	db1, _ := Open(p); db1.Close()
	db2, err := Open(p)
	if err != nil { t.Fatalf("reopen: %v", err) }
	defer db2.Close()
	// no panic, versions unchanged, tables intact
	if !tableExists(t, db2, "admins") { t.Fatal("admins missing after reopen") }
}

func TestMigrationsUpgradeFromA1Schema(t *testing.T) {
	// Seed a DB at the A1 shape (events WITHOUT uuid, no schema_migrations),
	// then Open and assert it upgrades without dropping seeded rows.
	p := filepath.Join(t.TempDir(), "t.db")
	seedA1Schema(t, p) // raw sql.Open + CREATE TABLE events(... no uuid ...) + INSERT 1 row
	db, err := Open(p)
	if err != nil { t.Fatalf("Open upgrade: %v", err) }
	defer db.Close()
	if n := countRows(t, db, "events"); n != 1 { t.Fatalf("lost seeded events: %d", n) }
	if !columnExists(t, db, "events", "uuid") { t.Fatal("uuid not added") }
}
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/server/store/ -run TestMigrations -v` → fails (helpers/runner absent). Add small test helpers (`appliedVersions`, `embeddedVersions`, `tableExists`, `columnExists`, `countRows`, `seedA1Schema`) in the test file.

- [ ] **Step 3: Implement the runner.** In `migrate.go`:

```go
//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct{ version int; name, sql string }

func loadMigrations() ([]migration, error) {
	entries, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil { return nil, err }
	sort.Strings(entries)
	var ms []migration
	for _, e := range entries {
		base := filepath.Base(e)            // e.g. 0003_f3_auth.sql
		v, err := strconv.Atoi(base[:4])
		if err != nil { return nil, fmt.Errorf("bad migration name %q: %w", base, err) }
		b, err := migrationFS.ReadFile(e)
		if err != nil { return nil, err }
		ms = append(ms, migration{v, base, string(b)})
	}
	return ms, nil
}

// migrate applies all embedded migrations whose version is not yet recorded.
// Each migration runs in its own transaction; the version row is written in
// the same tx so a failure leaves schema_migrations unchanged for that version.
func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations(
		version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	// Back-compat: a DB created under A1 (pre-schema_migrations) already has the
	// 0001 tables. If core tables exist but no version is recorded, baseline to 1.
	if err := baselineLegacy(db); err != nil { return err }
	applied, err := appliedSet(db)
	if err != nil { return err }
	ms, err := loadMigrations()
	if err != nil { return err }
	for _, m := range ms {
		if applied[m.version] { continue }
		tx, err := db.Begin()
		if err != nil { return err }
		if _, err := tx.Exec(m.sql); err != nil { tx.Rollback(); return fmt.Errorf("migration %s: %w", m.name, err) }
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`,
			m.version, nowRFC3339()); err != nil { tx.Rollback(); return err }
		if err := tx.Commit(); err != nil { return err }
	}
	return nil
}
```

`baselineLegacy`: if `orgs` table exists AND `schema_migrations` is empty, insert version 1 (and version 2 iff `events.uuid` already exists) so A1 DBs don't re-run `0001`/`0002` destructively. Use an injectable `nowRFC3339` (package var func) for testability. `0001_init.sql` = the current `schema.sql` body. `0002_events_uuid.sql` = `ALTER TABLE events ADD COLUMN uuid TEXT; CREATE UNIQUE INDEX IF NOT EXISTS idx_events_uuid ON events(uuid);` (guard so baseline path is consistent). `0003_f3_auth.sql` = the `schema_migrations` note is already created in Go; put `admins`, `sessions`, `idx_sessions_expires` here.

- [ ] **Step 4: Run, expect PASS.** `go test ./internal/server/store/ -v` (all store tests, incl. existing ingest/idempotency, must still pass).

- [ ] **Step 5: Commit.** `git add internal/server/store && git commit -m "feat(server/store): numbered forward-only migration runner + F3 auth schema"`

---

## Task 2: Sessions store + super-admin verify + RequireSession middleware

**Files:**
- Create: `internal/server/store/sessions.go`, `internal/server/store/sessions_test.go`
- Create: `internal/server/auth/session.go`, `internal/server/auth/session_test.go`
- Test as listed.

- [ ] **Step 1: Failing store test** (`sessions_test.go`):

```go
func TestSessionLifecycle(t *testing.T) {
	db := openTestDB(t) // helper used elsewhere in store tests
	s, err := db.CreateSession("admin@x.com", "admin", time.Hour)
	if err != nil { t.Fatal(err) }
	got, err := db.LookupSession(s.ID)
	if err != nil || got.Subject != "admin@x.com" || got.Role != "admin" { t.Fatalf("lookup=%+v err=%v", got, err) }
	if err := db.DeleteSession(s.ID); err != nil { t.Fatal(err) }
	if _, err := db.LookupSession(s.ID); err != ErrSessionNotFound { t.Fatalf("want ErrSessionNotFound, got %v", err) }
}

func TestExpiredSessionRejectedAndSwept(t *testing.T) {
	db := openTestDB(t)
	db.now = func() time.Time { return time.Unix(1000, 0) }            // injectable clock
	s, _ := db.CreateSession("a@x.com", "admin", time.Second)
	db.now = func() time.Time { return time.Unix(2000, 0) }            // past expiry
	if _, err := db.LookupSession(s.ID); err != ErrSessionExpired { t.Fatalf("got %v", err) }
	n, _ := db.SweepExpiredSessions()
	if n != 1 { t.Fatalf("swept=%d", n) }
}
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/server/store/ -run Session -v`.

- [ ] **Step 3: Implement** `sessions.go`: `Session{ID,Subject,Role,CreatedAt,ExpiresAt}`; `CreateSession` (256-bit `crypto/rand` → base64url ID, insert), `LookupSession` (select; if `expires_at<=now` return `ErrSessionExpired`), `DeleteSession`, `SweepExpiredSessions`, plus `AddAdmin/RemoveAdmin/IsAdmin/ListAdmins` on `admins`. Add `var ErrSessionNotFound, ErrSessionExpired = errors.New(...)`. Reuse the store's existing clock pattern or add `now func() time.Time` defaulting to `time.Now`.

- [ ] **Step 4: Failing auth test** (`session_test.go`): `RequireSession("admin")` wraps a handler; request with a valid cookie (backed by a fake lookup func) → 200; missing cookie → 401 redirect to `/admin/login`; expired/not-found → 401; role `admin` route reached by a `superadmin` session → 200; `superadmin`-only route by `admin` session → 403. Also `VerifySuperadmin(user, pass, cfgUser, bcryptHash)` → true on match, false on wrong pass / wrong user. Use `bcrypt.GenerateFromPassword` in the test to make a hash.

- [ ] **Step 5: Implement** `session.go`: a `SessionLookup func(id string) (Session, error)` injected into `RequireSession(role string, lookup SessionLookup) func(http.Handler) http.Handler`; cookie name `redactr_admin`; `setSessionCookie(w, id, secure)`, `clearSessionCookie(w)`. Role check: `superadmin` satisfies any; `admin` satisfies `admin` only. `VerifySuperadmin` uses `subtle.ConstantTimeCompare` on username + `bcrypt.CompareHashAndPassword`.

- [ ] **Step 6: Run, expect PASS.** `go test ./internal/server/store/ ./internal/server/auth/ -v`.

- [ ] **Step 7: Commit.** `git commit -am "feat(server): server-side sessions, admins store, RequireSession + super-admin verify"`

---

## Task 3: OIDC authorization-code (PKCE) flow

**Files:**
- Create: `internal/server/auth/oidc.go`, `internal/server/auth/oidc_test.go`

- [ ] **Step 1: Failing test with a mock IdP** (`oidc_test.go`): stand up an `httptest.Server` exposing `/.well-known/openid-configuration`, `/jwks`, and `/token`, signing an ID token (RS256) with a test RSA key whose JWK is published at `/jwks`. Then:

```go
func TestOIDCCallbackHappyPath(t *testing.T) {
	idp := newMockIDP(t, "alice@x.com", true /*email_verified*/)
	p, err := NewOIDC(context.Background(), OIDCConfig{Issuer: idp.URL, ClientID: "cid", ClientSecret: "sec", RedirectURL: "https://app/cb"})
	if err != nil { t.Fatal(err) }
	st := p.Start()                       // returns {AuthURL, State, Nonce, Verifier}
	claims, err := p.Exchange(context.Background(), idp.Code(st.Nonce), st)
	if err != nil { t.Fatal(err) }
	if claims.Email != "alice@x.com" || !claims.EmailVerified { t.Fatalf("claims=%+v", claims) }
}

func TestOIDCRejectsBadStateAndUnverifiedEmail(t *testing.T) { /* state mismatch -> ErrState; email_verified=false -> ErrEmailUnverified */ }
```

- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** `oidc.go`: `NewOIDC` uses `oidc.NewProvider` + `oauth2.Config`; `Start()` generates `state`, `nonce`, PKCE `verifier`/`challenge` (`crypto/rand` + S256), returns auth URL with `oauth2.S256ChallengeOption`/`oidc.Nonce`. `Exchange(ctx, code, st)` exchanges, verifies the ID token via the provider verifier, checks nonce, requires `email_verified`, returns `Claims{Email, EmailVerified, Subject}`. Define `ErrState, ErrEmailUnverified, ErrNonce`.
- [ ] **Step 4: Run, expect PASS.** `go test ./internal/server/auth/ -run OIDC -v`.
- [ ] **Step 5: Commit.** `git commit -am "feat(server/auth): OIDC auth-code+PKCE flow with mock-IdP tests"`

---

## Task 4: Admin-auth HTTP handlers + route wiring + body cap

**Files:**
- Create: `internal/server/httpapi/admin_auth.go`, `internal/server/httpapi/admin_auth_test.go`
- Modify: `internal/server/httpapi/server.go`

- [ ] **Step 1: Failing handler tests** (`admin_auth_test.go`): using `httptest` and a store-backed Server: `POST /admin/login` with correct super-admin creds → 303 + `Set-Cookie: redactr_admin`; wrong creds → 401; `POST /admin/logout` deletes session + clears cookie; `GET/POST/DELETE /admin/admins` only reachable by superadmin (403 for plain admin); an existing admin route (e.g. `GET /admin/orgs`) returns 401 without a session cookie and 200 with one. Body-cap: `POST /v1/ingest` with a body over `MaxBodyBytes` → 413.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** `admin_auth.go`: handlers `handleLoginForm` (GET, renders minimal HTML form + SSO link), `handleLogin` (POST, `VerifySuperadmin` → `CreateSession("superadmin")` → cookie → 303 to `/`), `handleLogout`, `handleOIDCStart` (store `{state,nonce,verifier}` in a short-lived signed/HttpOnly cookie, redirect), `handleOIDCCallback` (read cookie, `Exchange`, `store.IsAdmin(email)` else 403, `CreateSession("admin")`), `handleListAdmins/handleAddAdmin/handleDeleteAdmin`. Server gets fields `cfg`, `oidc *auth.OIDC` (nil if unconfigured — hide SSO button), `sessions` lookup.
- [ ] **Step 4: Wire** `server.go`: build `RequireSession` from `store.LookupSession`; replace each `admin(...)` registration's `RequireAdmin(key)` with `RequireSession("admin", lookup)`; register `/admin/admins` under `RequireSession("superadmin", lookup)`; register login/logout/oidc routes unauthenticated; wrap `/v1/enroll`, `/v1/events`, `/v1/ingest` bodies with `http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)` (return 413 on `*http.MaxBytesError`). Keep an optional `RequireMachineKey` wrapper applied only when `cfg.MachineKey != ""` on a narrow allowlist (document which).
- [ ] **Step 5: Run, expect PASS.** `go test ./internal/server/httpapi/ -v` (existing handler tests updated to use a session/cookie helper instead of `X-Admin-Key`).
- [ ] **Step 6: Commit.** `git commit -am "feat(server/httpapi): session-based admin auth, OIDC routes, admins mgmt, body caps; retire X-Admin-Key"`

---

## Task 5: Maintenance loop — nightly backup + audit/event retention

**Files:**
- Create: `internal/server/maint/maint.go`, `internal/server/maint/maint_test.go`
- Add store method: `internal/server/store/maint.go` (`BackupTo(path)`, `PruneOlderThan(cutoff time.Time)`)

- [ ] **Step 1: Failing tests:**

```go
func TestBackupProducesOpenableDB(t *testing.T) {
	db := openTestDB(t)
	dst := filepath.Join(t.TempDir(), "b.db")
	if err := db.BackupTo(dst); err != nil { t.Fatal(err) }       // VACUUM INTO ?
	got, err := Open(dst); if err != nil { t.Fatalf("reopen backup: %v", err) }
	got.Close()
}
func TestRetentionPrunesOldRowsKeepsNew(t *testing.T) {
	db := openTestDB(t)
	insertAuditAt(t, db, "old", time.Unix(0,0)); insertAuditAt(t, db, "new", time.Unix(1e9,0))
	n, _ := db.PruneOlderThan(time.Unix(5e8, 0))
	if n != 1 || rowExists(t, db, "old") || !rowExists(t, db, "new") { t.Fatalf("prune wrong: n=%d", n) }
}
func TestBackupRetentionKeepsNewestN(t *testing.T) { /* maint.pruneBackups keeps newest N files by name */ }
```

- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** `store.BackupTo` = `VACUUM INTO ?` (use a literal-safe path; SQLite requires a string literal — build with parameter binding via `VACUUM INTO ?`). `store.PruneOlderThan` = `DELETE FROM audit_records WHERE received_at < ?` + same for `events` (RFC3339 compare consistent with insert format); returns total rows. `maint.go`: `Loop(ctx, cfg, db, log)` on a 24h ticker (injectable interval + clock): `db.BackupTo(timestamped)`, prune backup files beyond `RETAIN`, `db.PruneOlderThan(now - RETAIN_DAYS)`; log counts; run once immediately on start.
- [ ] **Step 4: Run, expect PASS.** `go test ./internal/server/store/ ./internal/server/maint/ -v`.
- [ ] **Step 5: Commit.** `git commit -am "feat(server): nightly VACUUM-INTO backup + audit/event retention sweep"`

---

## Task 6: Typed config + fail-fast + main wiring + packaging

**Files:**
- Create: `internal/server/config/config.go`, `internal/server/config/config_test.go`
- Modify: `cmd/redactr-server/main.go`
- Create: `deploy/Dockerfile`, `deploy/docker-compose.yml`, `deploy/Caddyfile`, `deploy/README.md`

- [ ] **Step 1: Failing config test:**

```go
func TestConfigFailFastInProd(t *testing.T) {
	_, err := Load(envMap{ /* no auth, http url */ "REDACTR_PUBLIC_URL": "http://x" })
	if err == nil { t.Fatal("expected fail-fast: http url + no auth") }
}
func TestConfigDevModePermissive(t *testing.T) {
	c, err := Load(envMap{"REDACTR_DEV_MODE": "1"})
	if err != nil { t.Fatal(err) }
	if !c.DevMode || c.MaxBodyBytes != 1<<20 { t.Fatalf("dev defaults wrong: %+v", c) }
}
func TestConfigProdHappy(t *testing.T) {
	c, err := Load(envMap{"REDACTR_PUBLIC_URL":"https://x","REDACTR_SUPERADMIN_USER":"root","REDACTR_SUPERADMIN_PASSWORD_HASH":"$2a$..."})
	if err != nil || c.Superadmin.User != "root" { t.Fatalf("c=%+v err=%v", c, err) }
}
```

- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** `config.go`: `Load(getenv func(string)string)` (or a small map type for tests) → typed `Config{DevMode, PublicURL, Addr, DBPath, KeyDir, OIDC OIDCConfig, Superadmin {User,Hash}, SessionTTL, MachineKey, BackupRetain, AuditRetainDays, MaxBodyBytes}`. Validation (skipped when `DevMode`): `PublicURL` parses and is `https`; at least one of {Superadmin.User+hash, full OIDC triple} present; durations parse. If `REDACTR_SUPERADMIN_PASSWORD` set without hash, bcrypt-hash it and log a "prefer _HASH" warning. Return a single aggregated error listing all problems. **Remove** the admin-key auto-gen path.
- [ ] **Step 4: Run, expect PASS.** `go test ./internal/server/config/ -v`.
- [ ] **Step 5: Wire** `main.go`: `cfg, err := config.Load(os.Getenv); if err != nil { log.Fatalf(...) }`; open store; build `OIDC` iff configured; construct `httpapi.Server` with cfg+sessions+oidc; `go maint.Loop(ctx, cfg, store, logger)`; listen on `cfg.Addr` (HTTP — TLS is at the proxy). Build the whole module: `go build ./...`.
- [ ] **Step 6: Packaging.** Write `deploy/Dockerfile` (multi-stage: `golang:1.26` build `CGO_ENABLED=0 go build -o /redactr-server ./cmd/redactr-server` → `gcr.io/distroless/static:nonroot`, `USER nonroot`, `ENTRYPOINT ["/redactr-server"]`). `deploy/Caddyfile` (`{$REDACTR_DOMAIN} { reverse_proxy redactr-server:8080 }`). `deploy/docker-compose.yml` (caddy: ports 80/443, mounts Caddyfile + `caddy_data`,`caddy_config`; redactr-server: env from `.env`, volumes `db`,`keys`,`backups`, `expose: 8080`). `deploy/README.md`: env reference, how to generate a bcrypt hash, OIDC setup, nginx/Traefik alternative, **backup/restore procedure**, checksum verification, "signing deferred to F2" note.
- [ ] **Step 7: Validate as far as the toolchain allows.** Run `docker build -f deploy/Dockerfile .` and `docker compose -f deploy/docker-compose.yml config` **iff** docker is installed; otherwise record in the commit body that these were not smoke-tested here (honest deferral) and were validated by inspection.
- [ ] **Step 8: Commit.** `git commit -am "feat(server): typed fail-fast config, main wiring, distroless+Caddy compose deployment"`

---

## Final verification (before merge)

- [ ] `go build ./...` clean; `go vet ./internal/server/... ./cmd/redactr-server/` clean.
- [ ] `go test ./...` green (full suite, not just server packages).
- [ ] Spec coverage walk: decisions 1–12 each map to a task (1→T1, 3/4/6→T2, 2→T3, 5/6/12→T4, 10/11→T5, 7/8/9→T6).
- [ ] Update `[[subsystem-f-progress]]` memory: F3 done, F2 next.
- [ ] Fast-forward merge `subsystem-f-fleet-ops` → `main` (per autonomy mandate) **only after** the human-visible PR/CI is green, or note if merge is deferred pending CI.

## Self-review notes

- **Spec coverage:** all 12 decisions mapped above. Body cap (12) appears in T4 routing; retention (11) + backup (10) in T5; fail-fast (7) + TLS contract (8) + packaging (9) in T6.
- **Type consistency:** `Session{ID,Subject,Role,CreatedAt,ExpiresAt}`, `Claims{Email,EmailVerified,Subject}`, `RequireSession(role, lookup)`, `VerifySuperadmin`, `CreateSession(subject, role, ttl)`, `LookupSession(id)`, `BackupTo(path)`, `PruneOlderThan(cutoff)`, `config.Load(getenv)` — used identically across tasks.
- **Honest deferral:** real-IdP login and docker/compose/Caddy runtime are not smoke-testable in this environment; covered by mock-IdP tests + inspection + docs, flagged in commits.
