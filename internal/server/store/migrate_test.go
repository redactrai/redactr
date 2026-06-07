package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// appliedVersions returns the migration versions recorded in schema_migrations, in order.
func appliedVersions(t *testing.T, db *sql.DB) []int {
	t.Helper()
	rows, err := db.Query(`SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("appliedVersions query: %v", err)
	}
	defer rows.Close()
	var versions []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("appliedVersions scan: %v", err)
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("appliedVersions rows.Err: %v", err)
	}
	return versions
}

// countRows returns the number of rows in the named table.
func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	// table is always a hardcoded test literal.
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("countRows(%q): %v", table, err)
	}
	return n
}

// openRaw opens a bare SQLite connection (no migrations) for test setup.
func openRaw(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("openRaw: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

// seedA1Schema creates the legacy A1-shaped schema (0001_init tables, no uuid
// column on events, no schema_migrations) on the given raw connection.
func seedA1Schema(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
		CREATE TABLE orgs (
		  id         TEXT PRIMARY KEY,
		  name       TEXT NOT NULL,
		  created_at TIMESTAMP NOT NULL
		);
		CREATE TABLE enrollment_tokens (
		  token_hash TEXT PRIMARY KEY,
		  org_id     TEXT NOT NULL REFERENCES orgs(id),
		  expires_at TIMESTAMP NOT NULL,
		  max_uses   INTEGER NOT NULL,
		  used_count INTEGER NOT NULL DEFAULT 0,
		  revoked    INTEGER NOT NULL DEFAULT 0,
		  created_at TIMESTAMP NOT NULL
		);
		CREATE TABLE devices (
		  id           TEXT PRIMARY KEY,
		  org_id       TEXT NOT NULL REFERENCES orgs(id),
		  name         TEXT NOT NULL,
		  platform     TEXT NOT NULL,
		  enrolled_at  TIMESTAMP NOT NULL,
		  last_seen_at TIMESTAMP,
		  revoked      INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_devices_org ON devices(org_id);
		CREATE TABLE policies (
		  org_id      TEXT PRIMARY KEY REFERENCES orgs(id),
		  bundle_json TEXT NOT NULL,
		  version     INTEGER NOT NULL,
		  updated_at  TIMESTAMP NOT NULL
		);
		CREATE TABLE events (
		  id                TEXT PRIMARY KEY,
		  org_id            TEXT NOT NULL REFERENCES orgs(id),
		  device_id         TEXT NOT NULL,
		  tool              TEXT NOT NULL,
		  verdict           TEXT NOT NULL,
		  reason            TEXT NOT NULL,
		  direct_conn_count INTEGER NOT NULL,
		  observed_at       TIMESTAMP NOT NULL,
		  received_at       TIMESTAMP NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_events_org ON events(org_id, received_at);
		CREATE TABLE audit_records (
		  uuid        TEXT PRIMARY KEY,
		  org_id      TEXT NOT NULL REFERENCES orgs(id),
		  device_id   TEXT NOT NULL,
		  provider    TEXT NOT NULL,
		  source      TEXT NOT NULL,
		  detector    TEXT NOT NULL,
		  category    TEXT NOT NULL,
		  action      TEXT NOT NULL,
		  latency_ms  INTEGER NOT NULL,
		  observed_at TIMESTAMP NOT NULL,
		  received_at TIMESTAMP NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_records(org_id, received_at);
		CREATE TABLE images (
		  id         TEXT PRIMARY KEY,
		  org_id     TEXT NOT NULL REFERENCES orgs(id),
		  tag        TEXT NOT NULL,
		  ref        TEXT NOT NULL DEFAULT '',
		  digest     TEXT NOT NULL DEFAULT '',
		  status     TEXT NOT NULL,
		  created_at TIMESTAMP NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_images_org ON images(org_id, created_at);
	`)
	if err != nil {
		t.Fatalf("seedA1Schema: %v", err)
	}
}

// ---- Tests ----

// TestMigrationsFreshDBAppliesAllInOrder opens a brand-new DB and verifies that
// all three migrations are applied and recorded in the correct order.
func TestMigrationsFreshDBAppliesAllInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	versions := appliedVersions(t, st.db)
	want := []int{1, 2, 3}
	if len(versions) != len(want) {
		t.Fatalf("versions = %v, want %v", versions, want)
	}
	for i, v := range versions {
		if v != want[i] {
			t.Errorf("versions[%d] = %d, want %d", i, v, want[i])
		}
	}

	// Spot-check that all expected tables exist.
	for _, tbl := range []string{"orgs", "events", "admins", "sessions", "schema_migrations"} {
		if !tableExists(st.db, tbl) {
			t.Errorf("table %q missing after fresh open", tbl)
		}
	}
	if !columnExists(st.db, "events", "uuid") {
		t.Error("events.uuid column missing after fresh open")
	}
}

// TestMigrationsReopenIsNoOp opens a DB, closes it, re-opens it, and verifies
// that schema_migrations still has the same versions and no error occurred.
func TestMigrationsReopenIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reopen.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	st.Close()

	st2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer st2.Close()

	versions := appliedVersions(t, st2.db)
	want := []int{1, 2, 3}
	if len(versions) != len(want) {
		t.Fatalf("versions after reopen = %v, want %v", versions, want)
	}
	for i, v := range versions {
		if v != want[i] {
			t.Errorf("versions[%d] = %d, want %d", i, v, want[i])
		}
	}
	if !tableExists(st2.db, "admins") {
		t.Error("admins table missing after reopen")
	}
}

// TestMigrationsUpgradeFromA1Schema simulates an existing A1 database that has
// the 0001 tables (including orgs) but WITHOUT the events.uuid column and WITHOUT
// a schema_migrations table. Open must baseline versions 1 (not 2) and then apply
// 0002 and 0003, preserving existing data.
func TestMigrationsUpgradeFromA1Schema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a1legacy.db")

	// Build a legacy A1-shaped DB: the 0001_init tables (orgs, events without uuid,
	// etc.) but NO schema_migrations table and NO events.uuid column.
	raw := openRaw(t, path)
	seedA1Schema(t, raw)

	// Seed one events row to verify data survival.
	_, err := raw.Exec(`
		INSERT INTO events(id,org_id,device_id,tool,verdict,reason,direct_conn_count,observed_at,received_at)
		VALUES('ev1','org1','dev1','Claude Code','protected','x',0,'2024-01-01T00:00:00Z','2024-01-01T00:00:00Z')
	`)
	if err != nil {
		t.Fatalf("seed events row: %v", err)
	}
	raw.Close()

	// Now open via the store — this is the upgrade path.
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open legacy DB: %v", err)
	}
	defer st.Close()

	// Seeded events row must survive.
	if n := countRows(t, st.db, "events"); n != 1 {
		t.Errorf("events rows = %d, want 1 (row must survive upgrade)", n)
	}

	// events.uuid column must now exist (applied by migration 0002).
	if !columnExists(st.db, "events", "uuid") {
		t.Error("events.uuid column missing after upgrade")
	}

	// F3 auth tables must exist (applied by migration 0003).
	for _, tbl := range []string{"admins", "sessions"} {
		if !tableExists(st.db, tbl) {
			t.Errorf("table %q missing after upgrade", tbl)
		}
	}

	// schema_migrations must record all three versions.
	versions := appliedVersions(t, st.db)
	want := []int{1, 2, 3}
	if len(versions) != len(want) {
		t.Fatalf("versions after upgrade = %v, want %v", versions, want)
	}
	for i, v := range versions {
		if v != want[i] {
			t.Errorf("versions[%d] = %d, want %d", i, v, want[i])
		}
	}
}

// TestMigrationsUpgradeFromF1Schema simulates an existing F1 database that has
// the 0001 tables AND the events.uuid column + idx_events_uuid already present,
// but NO schema_migrations table. Open must baseline versions 1 and 2 (since uuid
// already exists) and then apply only migration 0003, preserving existing data.
// This exercises the baselineLegacy branch that records version 2.
func TestMigrationsUpgradeFromF1Schema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f1legacy.db")

	// Build an F1-shaped DB: A1 tables plus the events.uuid column and its index,
	// but NO schema_migrations table.
	raw := openRaw(t, path)
	seedA1Schema(t, raw)

	// Add the uuid column and index that 0002_events_uuid.sql would have added.
	_, err := raw.Exec(`
		ALTER TABLE events ADD COLUMN uuid TEXT;
		CREATE INDEX IF NOT EXISTS idx_events_uuid ON events(uuid);
	`)
	if err != nil {
		t.Fatalf("add uuid column/index: %v", err)
	}

	// Seed one events row (with a uuid value) to verify data survival.
	_, err = raw.Exec(`
		INSERT INTO events(id,org_id,device_id,tool,verdict,reason,direct_conn_count,observed_at,received_at,uuid)
		VALUES('ev1','org1','dev1','Claude Code','protected','x',0,'2024-01-01T00:00:00Z','2024-01-01T00:00:00Z','uuid-aaa-111')
	`)
	if err != nil {
		t.Fatalf("seed events row: %v", err)
	}
	raw.Close()

	// Now open via the store — this exercises the baselineLegacy path that
	// records both version 1 and version 2 because uuid already exists.
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open F1 legacy DB: %v", err)
	}
	defer st.Close()

	// Seeded row must survive.
	if n := countRows(t, st.db, "events"); n != 1 {
		t.Errorf("events rows = %d, want 1 (row must survive upgrade)", n)
	}

	// schema_migrations must contain exactly versions [1, 2, 3].
	versions := appliedVersions(t, st.db)
	want := []int{1, 2, 3}
	if len(versions) != len(want) {
		t.Fatalf("versions after F1 upgrade = %v, want %v", versions, want)
	}
	for i, v := range versions {
		if v != want[i] {
			t.Errorf("versions[%d] = %d, want %d", i, v, want[i])
		}
	}

	// F3 auth tables must exist (applied by migration 0003).
	for _, tbl := range []string{"admins", "sessions"} {
		if !tableExists(st.db, tbl) {
			t.Errorf("table %q missing after F1 upgrade", tbl)
		}
	}
}
