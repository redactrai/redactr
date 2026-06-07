package store

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// RunMigrations creates the schema_migrations table if needed, baselines any
// legacy DB that already has the 0001 tables but no migration history, and
// then applies every pending numbered migration in order. Each migration runs
// in its own transaction; if it fails the version is left unrecorded so a
// subsequent call will retry it.
func RunMigrations(db *sql.DB) error {
	return runMigrations(db, func() string {
		return time.Now().UTC().Format(time.RFC3339)
	})
}

// runMigrations is the injectable-clock variant; tests exercise it indirectly via Open.
func runMigrations(db *sql.DB, now func() string) error {
	// 1. Ensure the tracking table exists.
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	// 2. Load and sort migration files.
	type migration struct {
		version int
		name    string
		sql     string
	}
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	var migrations []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		// Filename format: NNNN_description.sql
		prefix := strings.SplitN(e.Name(), "_", 2)[0]
		v, err := strconv.Atoi(prefix)
		if err != nil {
			return fmt.Errorf("migration filename %q has non-numeric prefix: %w", e.Name(), err)
		}
		body, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return fmt.Errorf("read migration %q: %w", e.Name(), err)
		}
		migrations = append(migrations, migration{version: v, name: e.Name(), sql: string(body)})
	}
	// Prefixes are unique integers, so sort stability is irrelevant.
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })

	// 3. Baseline a legacy DB that predates the migration runner.
	//    Condition: orgs table exists but schema_migrations is empty.
	if err := baselineLegacy(db, now); err != nil {
		return err
	}

	// 4. Apply pending migrations.
	for _, m := range migrations {
		recorded, err := versionRecorded(db, m.version)
		if err != nil {
			return fmt.Errorf("check version %d: %w", m.version, err)
		}
		if recorded {
			continue
		}
		if err := applyMigration(db, m.version, m.name, m.sql, now); err != nil {
			return err
		}
	}
	return nil
}

// baselineLegacy records already-applied migrations for a DB that has the 0001
// tables but no schema_migrations rows. It writes version 1 unconditionally and
// version 2 only if the events.uuid column already exists, so the runner skips
// migrations that are already in the schema.
func baselineLegacy(db *sql.DB, now func() string) error {
	orgsPresent := tableExists(db, "orgs")
	if !orgsPresent {
		return nil
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		return fmt.Errorf("count schema_migrations: %w", err)
	}
	if count > 0 {
		return nil // already tracked; nothing to baseline
	}

	// Legacy DB: record version 1.
	ts := now()
	if _, err := db.Exec(
		`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`, 1, ts,
	); err != nil {
		return fmt.Errorf("baseline version 1: %w", err)
	}

	// Record version 2 only if the uuid column already exists.
	if columnExists(db, "events", "uuid") {
		if _, err := db.Exec(
			`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`, 2, ts,
		); err != nil {
			return fmt.Errorf("baseline version 2: %w", err)
		}
	}
	return nil
}

// applyMigration runs a single migration SQL in a transaction and records the
// version in schema_migrations within the same transaction. A failure leaves
// the version unrecorded so the next Open call will retry.
func applyMigration(db *sql.DB, version int, name, sqlBody string, now func() string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("migration %s: begin tx: %w", name, err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(sqlBody); err != nil {
		return fmt.Errorf("migration %s: %w", name, err)
	}
	if _, err := tx.Exec(
		`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`, version, now(),
	); err != nil {
		return fmt.Errorf("migration %s: record version: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %s: commit: %w", name, err)
	}
	return nil
}

// versionRecorded reports whether a given migration version is already in
// schema_migrations.
func versionRecorded(db *sql.DB, version int) (bool, error) {
	var v int
	err := db.QueryRow(`SELECT version FROM schema_migrations WHERE version=?`, version).Scan(&v)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// tableExists reports whether the named table is present in the schema.
// The table argument must always be a hardcoded literal (no user input).
func tableExists(db *sql.DB, table string) bool {
	var name string
	err := db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table,
	).Scan(&name)
	return err == nil
}

// columnExists reports whether the named column exists in the named table.
// The table name must be a compile-time constant because PRAGMA does not
// accept bind parameters. Both arguments must always be hardcoded literals.
func columnExists(db *sql.DB, table, col string) bool {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false
		}
		if name == col {
			found = true
			break
		}
	}
	if rows.Err() != nil {
		return false
	}
	return found
}
