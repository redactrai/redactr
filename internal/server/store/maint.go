package store

import (
	"strings"
	"time"
)

// BackupTo creates a point-in-time copy of the database at path using SQLite's
// VACUUM INTO statement. The destination must not already exist; VACUUM INTO
// will return an error if it does (callers should use timestamped filenames).
//
// modernc.org/sqlite does not support parameter binding for VACUUM INTO, so we
// build the statement with a properly escaped literal path (single quotes
// doubled to prevent injection).
func (s *Store) BackupTo(path string) error {
	// Escape any single-quotes in the path so the literal is safe.
	escaped := strings.ReplaceAll(path, "'", "''")
	_, err := s.db.Exec("VACUUM INTO '" + escaped + "'")
	return err
}

// PruneOlderThan deletes all rows from audit_records and events whose
// received_at is strictly less than cutoff. The two deletes run in a single
// transaction so they are atomic. It returns the total number of rows deleted.
func (s *Store) PruneOlderThan(cutoff time.Time) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res1, err := tx.Exec(`DELETE FROM audit_records WHERE received_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n1, err := res1.RowsAffected()
	if err != nil {
		return 0, err
	}

	res2, err := tx.Exec(`DELETE FROM events WHERE received_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n2, err := res2.RowsAffected()
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(n1 + n2), nil
}
