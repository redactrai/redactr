// Package monitor collects privacy-scrubbed host-scan events from the local
// session classifier. The daemon enqueues these into the durable outbox; the
// shipper delivers them. Metadata only: no command lines, connection strings,
// or env values ever leave here.
package monitor

import (
	"time"

	"github.com/redactrai/redactr/internal/control"
	"github.com/redactrai/redactr/internal/sessions"
)

// Collect maps classified sessions to scrubbed monitoring events.
func Collect(list []sessions.Session) []control.MonitorEvent {
	out := make([]control.MonitorEvent, 0, len(list))
	now := time.Now().UTC()
	for _, s := range list {
		out = append(out, control.MonitorEvent{
			Tool:            s.Tool,
			Verdict:         string(s.Status),
			Reason:          s.Reason,
			DirectConnCount: len(s.DirectAIConn),
			ObservedAt:      now,
		})
	}
	return out
}
