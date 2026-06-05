package store

import (
	"time"

	"github.com/redactrai/redactr/internal/control"
)

// IngestRecords idempotently stores a batch of telemetry records in one tx.
// Monitor records go to `events`, audit records to `audit_records`; both use
// INSERT ... ON CONFLICT(uuid) DO NOTHING so re-delivered batches dedupe.
// Returns the UUIDs the server now holds (newly inserted or already present).
func (s *Store) IngestRecords(orgID, deviceID string, recs []control.IngestRecord, receivedAt time.Time) ([]string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	accepted := make([]string, 0, len(recs))
	for _, r := range recs {
		switch r.Kind {
		case control.KindMonitor:
			if r.Monitor == nil {
				continue
			}
			if _, err := tx.Exec(
				`INSERT INTO events(id,org_id,device_id,tool,verdict,reason,direct_conn_count,observed_at,received_at,uuid)
				 VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(uuid) DO NOTHING`,
				newID(), orgID, deviceID, r.Monitor.Tool, r.Monitor.Verdict, r.Monitor.Reason,
				r.Monitor.DirectConnCount, r.Monitor.ObservedAt, receivedAt, r.UUID); err != nil {
				return nil, err
			}
		case control.KindAudit:
			if r.Audit == nil {
				continue
			}
			if _, err := tx.Exec(
				`INSERT INTO audit_records(uuid,org_id,device_id,provider,source,detector,category,action,latency_ms,observed_at,received_at)
				 VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(uuid) DO NOTHING`,
				r.UUID, orgID, deviceID, r.Audit.Provider, r.Audit.Source, r.Audit.Detector,
				r.Audit.Category, r.Audit.Action, r.Audit.LatencyMs, r.Audit.ObservedAt, receivedAt); err != nil {
				return nil, err
			}
		default:
			continue
		}
		accepted = append(accepted, r.UUID)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return accepted, nil
}

// CountEvents returns the number of stored events for an org (test/observability helper).
func (s *Store) CountEvents(orgID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE org_id=?`, orgID).Scan(&n)
	return n, err
}

// CountAuditRecords returns the number of stored audit records for an org.
func (s *Store) CountAuditRecords(orgID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_records WHERE org_id=?`, orgID).Scan(&n)
	return n, err
}
