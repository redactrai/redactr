package monitor

import (
	"encoding/json"
	"strings"
	"testing"

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
