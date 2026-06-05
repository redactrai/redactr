package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/redactrai/redactr/internal/control"
)

func recMon(uuid, tool string) control.IngestRecord {
	return control.IngestRecord{UUID: uuid, Kind: control.KindMonitor,
		Monitor: &control.MonitorEvent{Tool: tool, Verdict: "runaway", Reason: "x", ObservedAt: time.Unix(1, 0).UTC()}}
}
func recAudit(uuid, cat string) control.IngestRecord {
	return control.IngestRecord{UUID: uuid, Kind: control.KindAudit,
		Audit: &control.AuditRecord{Provider: "anthropic", Source: "proxy", Detector: "regex", Category: cat, Action: "blocked", ObservedAt: time.Unix(1, 0).UTC()}}
}

func TestIngestRecordsDedup(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	batch := []control.IngestRecord{recMon("m1", "a"), recAudit("a1", "aws_key")}

	acc, err := st.IngestRecords("org1", "dev1", batch, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(acc) != 2 {
		t.Fatalf("accepted=%d want 2", len(acc))
	}
	if _, err := st.IngestRecords("org1", "dev1", batch, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountEvents("org1"); n != 1 {
		t.Fatalf("events=%d want 1 (deduped)", n)
	}
	if n, _ := st.CountAuditRecords("org1"); n != 1 {
		t.Fatalf("audit=%d want 1 (deduped)", n)
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	st2.Close()
}

func TestMigrationAddsUUIDToLegacyEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`CREATE TABLE events (
	  id TEXT PRIMARY KEY, org_id TEXT NOT NULL, device_id TEXT NOT NULL,
	  tool TEXT NOT NULL, verdict TEXT NOT NULL, reason TEXT NOT NULL,
	  direct_conn_count INTEGER NOT NULL, observed_at TIMESTAMP NOT NULL, received_at TIMESTAMP NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	raw.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	defer st.Close()
	if _, err := st.IngestRecords("org1", "dev1", []control.IngestRecord{recMon("m1", "a")}, time.Now().UTC()); err != nil {
		t.Fatalf("ingest after migration: %v", err)
	}
	if n, _ := st.CountEvents("org1"); n != 1 {
		t.Fatalf("events=%d want 1", n)
	}
}
