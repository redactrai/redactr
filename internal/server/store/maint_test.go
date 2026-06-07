package store

import (
	"path/filepath"
	"testing"
	"time"
)

// insertAuditWithTime inserts an audit_record directly with a controlled received_at.
func insertAuditWithTime(t *testing.T, s *Store, orgID, uuid string, receivedAt time.Time) {
	t.Helper()
	_, err := s.db.Exec(
		`INSERT INTO audit_records(uuid,org_id,device_id,provider,source,detector,category,action,latency_ms,observed_at,received_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		uuid, orgID, "dev1", "anthropic", "proxy", "regex", "pii", "blocked", 1,
		receivedAt, receivedAt,
	)
	if err != nil {
		t.Fatalf("insertAuditWithTime: %v", err)
	}
}

// insertEventWithTime inserts an event directly with a controlled received_at.
func insertEventWithTime(t *testing.T, s *Store, orgID, id string, receivedAt time.Time) {
	t.Helper()
	_, err := s.db.Exec(
		`INSERT INTO events(id,org_id,device_id,tool,verdict,reason,direct_conn_count,observed_at,received_at)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		id, orgID, "dev1", "Claude Code", "runaway", "direct", 1,
		receivedAt, receivedAt,
	)
	if err != nil {
		t.Fatalf("insertEventWithTime: %v", err)
	}
}

func TestBackupProducesOpenableDB(t *testing.T) {
	s := openTest(t)
	org, err := s.CreateOrg("BackupOrg")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	insertAuditWithTime(t, s, org.ID, "uuid-backup-1", now)

	dst := filepath.Join(t.TempDir(), "b.db")
	if err := s.BackupTo(dst); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}

	s2, err := Open(dst)
	if err != nil {
		t.Fatalf("Open backup: %v", err)
	}
	defer s2.Close()

	n, err := s2.CountAuditRecords(org.ID)
	if err != nil {
		t.Fatalf("CountAuditRecords on backup: %v", err)
	}
	if n != 1 {
		t.Errorf("backup audit count = %d, want 1", n)
	}
}

func TestRetentionPrunesOldRowsKeepsNew(t *testing.T) {
	s := openTest(t)
	org, err := s.CreateOrg("PruneOrg")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	old := time.Unix(0, 0).UTC()           // epoch — well before cutoff
	recent := time.Unix(1_700_000_000, 0).UTC() // well after cutoff
	cutoff := time.Unix(86400, 0).UTC()    // 1 day after epoch

	// Insert one old and one recent audit record.
	insertAuditWithTime(t, s, org.ID, "uuid-old-audit", old)
	insertAuditWithTime(t, s, org.ID, "uuid-new-audit", recent)

	// Insert one old and one recent event.
	insertEventWithTime(t, s, org.ID, "evt-old", old)
	insertEventWithTime(t, s, org.ID, "evt-new", recent)

	deleted, err := s.PruneOlderThan(cutoff)
	if err != nil {
		t.Fatalf("PruneOlderThan: %v", err)
	}
	// Should have deleted 2 rows (1 old audit + 1 old event).
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}

	// Verify old rows are gone and new rows remain.
	auditCount, err := s.CountAuditRecords(org.ID)
	if err != nil {
		t.Fatalf("CountAuditRecords: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("audit_records after prune = %d, want 1", auditCount)
	}

	evtCount, err := s.CountEvents(org.ID)
	if err != nil {
		t.Fatalf("CountEvents: %v", err)
	}
	if evtCount != 1 {
		t.Errorf("events after prune = %d, want 1", evtCount)
	}
}
