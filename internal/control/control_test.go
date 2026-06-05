package control

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestIngestRecordMonitorOmitsAudit(t *testing.T) {
	rec := IngestRecord{
		UUID: "u1", Seq: 7, Kind: KindMonitor,
		Monitor: &MonitorEvent{Tool: "Claude Code", Verdict: "runaway", DirectConnCount: 1, ObservedAt: time.Unix(0, 0).UTC()},
	}
	blob, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), `"monitor"`) || strings.Contains(string(blob), `"audit"`) {
		t.Fatalf("monitor record should carry monitor and omit audit: %s", blob)
	}
	var back IngestRecord
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if back.Kind != KindMonitor || back.Monitor == nil || back.Audit != nil || back.UUID != "u1" {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
}

func TestAuditRecordCarriesCategoryNotValue(t *testing.T) {
	a := AuditRecord{Provider: "anthropic", Source: "proxy", Detector: "regex", Category: "aws_key", Action: "blocked", LatencyMs: 3}
	blob, _ := json.Marshal(IngestRecord{UUID: "u2", Kind: KindAudit, Audit: &a})
	if !strings.Contains(string(blob), `"category":"aws_key"`) {
		t.Fatalf("expected category in payload: %s", blob)
	}
}
