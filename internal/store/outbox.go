package store

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"

	"github.com/redactrai/redactr/internal/control"
	bolt "go.etcd.io/bbolt"
)

// newUUID returns a 16-byte random hex idempotency key.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
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
func (s *Store) Drain(max int) ([]control.IngestRecord, [][]byte, error) {
	var recs []control.IngestRecord
	var keys [][]byte
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(outboxBucket).Cursor()
		for k, v := c.First(); k != nil && len(recs) < max; k, v = c.Next() {
			var r control.IngestRecord
			if err := json.Unmarshal(v, &r); err != nil {
				continue // skip corrupt entry; it will be trimmed eventually
			}
			recs = append(recs, r)
			kc := make([]byte, len(k))
			copy(kc, k)
			keys = append(keys, kc)
		}
		return nil
	})
	return recs, keys, err
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
// oldest overflow and returns how many were dropped. Callers MUST log a
// non-zero result — dropping is never silent.
func (s *Store) Trim(maxItems int) (int, error) {
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
