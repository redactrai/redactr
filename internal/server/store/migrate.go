package store

import "database/sql"

// migrate applies additive, idempotent schema changes that CREATE TABLE IF NOT
// EXISTS cannot express (e.g. adding a column to a pre-existing table). It runs
// after the base schema and before index creation in Open.
func migrate(db *sql.DB) error {
	if !columnExists(db, "events", "uuid") {
		if _, err := db.Exec(`ALTER TABLE events ADD COLUMN uuid TEXT`); err != nil {
			return err
		}
	}
	return nil
}

func columnExists(db *sql.DB, table, col string) bool {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false
		}
		if name == col {
			return true
		}
	}
	return false
}
