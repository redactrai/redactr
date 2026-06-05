package store

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/redactrai/redactr/internal/control"
	bolt "go.etcd.io/bbolt"
)

var outboxBucket = []byte("outbox")

// newUUID returns a random RFC 4122 v4 UUID string used as the idempotency key.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func itob(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// EnqueueMonitor durably appends a posture event to the outbox.
func (s *Store) EnqueueMonitor(ev control.MonitorEvent) error {
	return s.enqueue(control.IngestRecord{Kind: control.KindMonitor, Monitor: &ev})
}

// EnqueueAudit durably appends a redaction-finding record to the outbox.
func (s *Store) EnqueueAudit(a control.AuditRecord) error {
	return s.enqueue(control.IngestRecord{Kind: control.KindAudit, Audit: &a})
}

func (s *Store) enqueue(rec control.IngestRecord) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(outboxBucket)
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		rec.Seq = seq
		if rec.UUID == "" {
			rec.UUID = newUUID()
		}
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put(itob(seq), data)
	})
}

// Drain returns up to max oldest records (FIFO by seq) along with their bolt
// keys (for a later Ack). Keys are copied so they remain valid after the tx.
// Entries that fail to decode are deleted (self-heal) so they cannot wedge the
// queue; this is logged and never silent.
func (s *Store) Drain(max int) ([]control.IngestRecord, [][]byte, error) {
	var recs []control.IngestRecord
	var keys [][]byte
	var corrupt [][]byte
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(outboxBucket).Cursor()
		for k, v := c.First(); k != nil && len(recs) < max; k, v = c.Next() {
			var r control.IngestRecord
			if err := json.Unmarshal(v, &r); err != nil {
				kc := make([]byte, len(k))
				copy(kc, k)
				corrupt = append(corrupt, kc)
				continue
			}
			recs = append(recs, r)
			kc := make([]byte, len(k))
			copy(kc, k)
			keys = append(keys, kc)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(corrupt) > 0 {
		slog.Warn("dropping corrupt outbox entries", "event", "outbox_corrupt", "count", len(corrupt))
		if derr := s.Ack(corrupt); derr != nil {
			slog.Warn("failed to delete corrupt outbox entries", "error", derr)
		}
	}
	return recs, keys, nil
}

// Ack deletes the given outbox keys after confirmed server delivery.
func (s *Store) Ack(keys [][]byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(outboxBucket)
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// OutboxCount returns the number of pending records.
func (s *Store) OutboxCount() int {
	n := 0
	_ = s.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(outboxBucket).Stats().KeyN
		return nil
	})
	return n
}

// Trim is the safety valve: if the outbox exceeds maxItems, it deletes the
// oldest overflow and returns how many were dropped. A non-positive maxItems is
// treated as no limit (no-op). Callers MUST log a non-zero result — dropping
// is never silent.
func (s *Store) Trim(maxItems int) (int, error) {
	if maxItems <= 0 {
		return 0, nil // no limit configured; never wipe the outbox
	}
	// Read-only pre-check: avoid taking the exclusive write lock on every shipper
	// cycle when the outbox is under capacity. The Update below re-checks under lock.
	if s.OutboxCount() <= maxItems {
		return 0, nil
	}
	dropped := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(outboxBucket)
		toDrop := b.Stats().KeyN - maxItems
		if toDrop <= 0 {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil && dropped < toDrop; k, _ = c.Next() {
			if err := c.Delete(); err != nil {
				return err
			}
			dropped++
		}
		return nil
	})
	return dropped, err
}
