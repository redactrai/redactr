// Package monitor collects privacy-scrubbed host-scan events from the local
// session classifier and reports them to the control-plane server. Metadata
// only: no command lines, connection strings, or env values ever leave here.
package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/redactrai/redactr/internal/control"
	"github.com/redactrai/redactr/internal/enrollment"
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

// Report posts a batch of events to the control-plane server if the device is
// enrolled. No-op when not enrolled or when there are no events. Fail-open:
// any network error is returned to the caller (which logs and drops the batch).
func Report(baseDir string, evs []control.MonitorEvent) error {
	if len(evs) == 0 || !enrollment.Exists(baseDir) {
		return nil
	}
	enr, err := enrollment.Load(baseDir)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string][]control.MonitorEvent{"events": evs})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(enr.ServerURL, "/")+"/v1/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+enr.DeviceToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("event post failed: %d", resp.StatusCode)
	}
	return nil
}
