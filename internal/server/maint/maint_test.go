package maint_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/redactrai/redactr/internal/control"
	"github.com/redactrai/redactr/internal/server/maint"
	"github.com/redactrai/redactr/internal/server/store"
)

// discardLogger returns a logger that discards all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// auditRec builds a KindAudit IngestRecord for the given uuid.
func auditRec(uuid string) control.IngestRecord {
	return control.IngestRecord{
		UUID: uuid, Kind: control.KindAudit,
		Audit: &control.AuditRecord{
			Provider: "anthropic", Source: "proxy", Detector: "regex",
			Category: "pii", Action: "blocked", LatencyMs: 1,
			ObservedAt: time.Unix(1, 0).UTC(),
		},
	}
}

// openTestStore opens a fresh store in a temp dir and registers cleanup.
func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// insertAuditAt inserts a single audit record with a controlled received_at.
// It uses IngestRecords, which stores the supplied receivedAt as received_at.
func insertAuditAt(t *testing.T, s *store.Store, orgID, uuid string, receivedAt time.Time) {
	t.Helper()
	if _, err := s.IngestRecords(orgID, "dev1", []control.IngestRecord{auditRec(uuid)}, receivedAt); err != nil {
		t.Fatalf("IngestRecords(%s): %v", uuid, err)
	}
}

// TestRunCycleBacksUpAndPrunes verifies that RunCycle:
//   - creates a backup file with the correct timestamped name, and
//   - prunes old audit rows while keeping recent ones.
//
// fixedNow = 2026-06-07 12:00:00; AuditRetainDays=1 => cutoff 2026-06-06 12:00:00.
// Epoch row (1970-01-01) is older than the cutoff and is deleted.
// Recent row (2026-06-06 23:00) is newer than the cutoff and is kept.
func TestRunCycleBacksUpAndPrunes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "main.db")
	backupDir := filepath.Join(t.TempDir(), "backups")

	// Set up the store and insert rows using explicit close so there is no open
	// handle when RunCycle opens via the main st handle below.
	var orgID string
	{
		s, err := store.Open(dbPath)
		if err != nil {
			t.Fatalf("setup Open: %v", err)
		}
		org, err := s.CreateOrg("RunCycleOrg")
		if err != nil {
			t.Fatalf("CreateOrg: %v", err)
		}
		orgID = org.ID
		// old row: 1970-01-01 — will be older than any realistic cutoff
		insertAuditAt(t, s, orgID, "uuid-old", time.Unix(0, 0).UTC())
		// recent row: 2026-06-06 23:00 — 11 h after the cutoff (2026-06-06 12:00)
		insertAuditAt(t, s, orgID, "uuid-new", time.Date(2026, 6, 6, 23, 0, 0, 0, time.UTC))
		s.Close()
	}

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open main: %v", err)
	}
	defer st.Close()

	fixedNow := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	cfg := maint.Config{
		BackupDir:       backupDir,
		BackupRetain:    10,
		AuditRetainDays: 1, // cutoff = fixedNow - 1d = 2026-06-06 12:00:00
		Interval:        24 * time.Hour,
	}

	if err := maint.RunCycle(st, cfg, discardLogger(), func() time.Time { return fixedNow }); err != nil {
		t.Fatalf("RunCycle: %v", err)
	}

	// Assert the backup file exists with the expected timestamped name.
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("ReadDir backupDir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected backup file in backupDir, got none")
	}
	wantName := "redactr-20260607-120000.db"
	found := false
	for _, e := range entries {
		if e.Name() == wantName {
			found = true
		}
	}
	if !found {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected backup file %q; dir contains: %v", wantName, names)
	}

	// Old row (epoch) pruned; recent row (2026-06-06 23:00) kept.
	n, err := st.CountAuditRecords(orgID)
	if err != nil {
		t.Fatalf("CountAuditRecords: %v", err)
	}
	if n != 1 {
		t.Errorf("audit_records after prune = %d, want 1 (recent row kept)", n)
	}
}

// TestBackupRetentionKeepsNewestN pre-creates 5 fake backup files and verifies
// that PruneBackups(dir, 2) deletes the 3 oldest and keeps the 2 newest.
func TestBackupRetentionKeepsNewestN(t *testing.T) {
	backupDir := t.TempDir()

	fakeNames := []string{
		"redactr-20260101-000000.db",
		"redactr-20260102-000000.db",
		"redactr-20260103-000000.db",
		"redactr-20260104-000000.db",
		"redactr-20260105-000000.db",
	}
	for _, name := range fakeNames {
		if err := os.WriteFile(filepath.Join(backupDir, name), []byte("fake"), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}

	pruned, err := maint.PruneBackups(backupDir, 2)
	if err != nil {
		t.Fatalf("PruneBackups: %v", err)
	}
	if pruned != 3 {
		t.Errorf("pruned = %d, want 3", pruned)
	}

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	wantRemain := []string{
		"redactr-20260104-000000.db",
		"redactr-20260105-000000.db",
	}
	if fmt.Sprintf("%v", names) != fmt.Sprintf("%v", wantRemain) {
		t.Errorf("remaining = %v, want %v", names, wantRemain)
	}
}

// TestLoopRunsAndCancels verifies that Loop runs one immediate cycle then
// returns promptly when its context is cancelled.
func TestLoopRunsAndCancels(t *testing.T) {
	st := openTestStore(t)
	backupDir := t.TempDir()
	fixedNow := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)

	cfg := maint.Config{
		BackupDir:       backupDir,
		BackupRetain:    10,
		AuditRetainDays: 365,
		Interval:        time.Hour, // long enough that the second tick never fires
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		maint.Loop(ctx, st, cfg, discardLogger(), func() time.Time { return fixedNow })
	}()

	// Let the immediate cycle complete, then cancel and wait for Loop to return.
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	// The immediate cycle should have produced a backup file.
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected at least one backup file after Loop ran one cycle")
	}
}
