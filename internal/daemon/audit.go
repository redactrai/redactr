package daemon

import (
	"github.com/redactrai/redactr/internal/control"
	"github.com/redactrai/redactr/internal/store"
)

// auditRecordsFromReport derives one privacy-scrubbed AuditRecord per redaction
// finding. It carries the detector and category only — never Redaction.Original
// (the raw value), and never any request/response body.
func auditRecordsFromReport(r *store.ScanReport) []control.AuditRecord {
	if len(r.Redactions) == 0 {
		return nil
	}
	action := "allowed"
	if r.Blocked {
		action = "blocked"
	}
	out := make([]control.AuditRecord, 0, len(r.Redactions))
	for _, red := range r.Redactions {
		out = append(out, control.AuditRecord{
			Provider:   r.Provider,
			Source:     r.Source,
			Detector:   red.Layer,
			Category:   red.Label,
			Action:     action,
			LatencyMs:  r.LatencyMs,
			ObservedAt: r.Timestamp,
		})
	}
	return out
}
