package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/redactrai/redactr/internal/control"
	bolt "go.etcd.io/bbolt"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestEnqueueDrainAck(t *testing.T) {
	s := openTemp(t)
	if err := s.EnqueueMonitor(control.MonitorEvent{Tool: "a", Verdict: "runaway", ObservedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueMonitor(control.MonitorEvent{Tool: "b", Verdict: "protected", ObservedAt: time.Unix(2, 0)}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueAudit(control.AuditRecord{Category: "aws_key", Detector: "regex"}); err != nil {
		t.Fatal(err)
	}

	recs, keys, err := s.Drain(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || len(keys) != 3 {
		t.Fatalf("drain got %d recs / %d keys", len(recs), len(keys))
	}
	if recs[0].Kind != control.KindMonitor || recs[0].Monitor.Tool != "a" {
		t.Fatalf("order wrong: %+v", recs[0])
	}
	if recs[2].Kind != control.KindAudit || recs[2].Audit.Category != "aws_key" {
		t.Fatalf("audit record wrong: %+v", recs[2])
	}
	if recs[0].UUID == "" || recs[0].Seq == 0 {
		t.Fatalf("uuid/seq not assigned: %+v", recs[0])
	}

	if err := s.Ack(keys[:2]); err != nil {
		t.Fatal(err)
	}
	if n := s.OutboxCount(); n != 1 {
		t.Fatalf("after ack count=%d want 1", n)
	}
	rest, _, _ := s.Drain(10)
	if len(rest) != 1 || rest[0].Kind != control.KindAudit {
		t.Fatalf("remaining wrong: %+v", rest)
	}
}

func TestOutboxSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.EnqueueMonitor(control.MonitorEvent{Tool: "x"})
	s.Close()

	s2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	recs, _, _ := s2.Drain(10)
	if len(recs) != 1 || recs[0].Monitor.Tool != "x" {
		t.Fatalf("durability failed: %+v", recs)
	}
}

func TestTrimDropsOldest(t *testing.T) {
	s := openTemp(t)
	for i := 0; i < 5; i++ {
		_ = s.EnqueueMonitor(control.MonitorEvent{Tool: "t", DirectConnCount: i})
	}
	dropped, err := s.Trim(3)
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 2 {
		t.Fatalf("dropped=%d want 2", dropped)
	}
	recs, _, _ := s.Drain(10)
	if len(recs) != 3 {
		t.Fatalf("after trim count=%d want 3", len(recs))
	}
	if recs[0].Monitor.DirectConnCount != 2 {
		t.Fatalf("trim dropped wrong end: first survivor=%d", recs[0].Monitor.DirectConnCount)
	}
}

func TestDrainRespectsMax(t *testing.T) {
	s := openTemp(t)
	for i := 0; i < 3; i++ {
		_ = s.EnqueueMonitor(control.MonitorEvent{Tool: "t"})
	}
	recs, keys, err := s.Drain(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || len(keys) != 2 {
		t.Fatalf("Drain(2) returned %d recs / %d keys, want 2/2", len(recs), len(keys))
	}
}

func TestDrainDropsCorruptEntry(t *testing.T) {
	s := openTemp(t)
	_ = s.EnqueueMonitor(control.MonitorEvent{Tool: "good"})
	// Inject a corrupt (non-JSON) entry directly into the bucket.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(outboxBucket)
		seq, _ := b.NextSequence()
		return b.Put(itob(seq), []byte("not json"))
	}); err != nil {
		t.Fatal(err)
	}
	recs, _, err := s.Drain(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Monitor.Tool != "good" {
		t.Fatalf("expected 1 good record, got %+v", recs)
	}
	if n := s.OutboxCount(); n != 1 {
		t.Fatalf("corrupt entry not self-healed, count=%d want 1", n)
	}
}
