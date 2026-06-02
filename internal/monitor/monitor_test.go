package monitor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redactrai/redactr/internal/control"
	"github.com/redactrai/redactr/internal/enrollment"
	"github.com/redactrai/redactr/internal/sessions"
)

func TestCollectScrubsMetadata(t *testing.T) {
	in := []sessions.Session{{
		Tool: "Claude Code", Status: sessions.StatusRunaway, Reason: "direct connection",
		Command:      "claude --secret-flag /Users/me/private",
		Connections:  []string{"1.2.3.4:443"},
		DirectAIConn: []string{"1.2.3.4:443"},
	}}
	evs := Collect(in)
	if len(evs) != 1 {
		t.Fatalf("len=%d", len(evs))
	}
	e := evs[0]
	if e.Tool != "Claude Code" || e.Verdict != "runaway" || e.DirectConnCount != 1 {
		t.Fatalf("event = %+v", e)
	}
	blob, _ := json.Marshal(e)
	for _, leak := range []string{"secret-flag", "private", "1.2.3.4"} {
		if strings.Contains(string(blob), leak) {
			t.Errorf("event leaked %q: %s", leak, blob)
		}
	}
}

func TestReportPostsWhenEnrolled(t *testing.T) {
	var gotAuth string
	var gotCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var body struct {
			Events []map[string]any `json:"events"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		gotCount = len(body.Events)
		json.NewEncoder(w).Encode(map[string]int{"accepted": gotCount})
	}))
	defer srv.Close()

	base := t.TempDir()
	_ = enrollment.Save(base, enrollment.Enrollment{ServerURL: srv.URL, DeviceToken: "tok", OrgID: "o", DeviceID: "d", ServerPublicKey: "x"})
	one := []control.MonitorEvent{{Tool: "Claude Code", Verdict: "runaway", Reason: "x", DirectConnCount: 1}}
	if err := Report(base, one); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if gotAuth != "Bearer tok" || gotCount != 1 {
		t.Errorf("auth=%q count=%d", gotAuth, gotCount)
	}
}

func TestReportNoEnrollmentIsNoop(t *testing.T) {
	one := []control.MonitorEvent{{Tool: "Claude Code", Verdict: "runaway", DirectConnCount: 1}}
	if err := Report(t.TempDir(), one); err != nil {
		t.Errorf("unenrolled Report should be a no-op, got %v", err)
	}
}
