package daemon

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/redactrai/redactr/internal/store"
)

func TestAuditRecordsFromReportStripsValues(t *testing.T) {
	rep := &store.ScanReport{
		Provider:  "anthropic",
		Source:    "proxy",
		LatencyMs: 12,
		Timestamp: time.Unix(100, 0).UTC(),
		Blocked:   true,
		Redactions: []store.Redaction{
			{Label: "aws_key", Original: "AKIAIOSFODNN7EXAMPLE", Layer: "regex"},
			{Label: "email", Original: "alice@secret.example", Layer: "gliner"},
		},
	}
	recs := auditRecordsFromReport(rep)
	if len(recs) != 2 {
		t.Fatalf("len=%d want 2", len(recs))
	}
	if recs[0].Category != "aws_key" || recs[0].Detector != "regex" || recs[0].Action != "blocked" || recs[0].Provider != "anthropic" {
		t.Fatalf("rec0 = %+v", recs[0])
	}
	blob, _ := json.Marshal(recs)
	for _, leak := range []string{"AKIAIOSFODNN7EXAMPLE", "alice@secret.example"} {
		if strings.Contains(string(blob), leak) {
			t.Fatalf("audit records leaked raw value %q: %s", leak, blob)
		}
	}
}

func TestAuditRecordsFromReportEmpty(t *testing.T) {
	if recs := auditRecordsFromReport(&store.ScanReport{}); recs != nil {
		t.Fatalf("no redactions should yield nil, got %+v", recs)
	}
}
