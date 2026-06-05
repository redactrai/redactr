package store

import (
	"database/sql"
	"strings"
)

// migrate applies additive, idempotent schema changes that CREATE TABLE IF NOT
// EXISTS cannot express (e.g. adding a column to a pre-existing table). It runs
// after the base schema and before index creation in Open. For F3 (retention
// sweep + new tables), consider switching to a schema_versions table with
// numbered steps once there are more than ~3 migrations; the PRAGMA-probe
// pattern becomes unwieldy beyond that.
func migrate(db *sql.DB) error {
	if columnExists(db, "events", "uuid") {
		return nil
	}
	if _, err := db.Exec(`ALTER TABLE events ADD COLUMN uuid TEXT`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	return nil
}

func columnExists(db *sql.DB, table, col string) bool {
	// table is always a hardcoded literal; PRAGMA does not support parameter binding.
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
		}
	}
	if rows.Err() != nil {
		return false
	}
	return found
}
