# Monitoring (A4 + E) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fleet monitoring, metadata-only: each client scans host AI processes (reusing `internal/sessions`), pushes privacy-scrubbed events to `POST /v1/events`; the server stores + aggregates per-org for the (future) dashboard.

**Architecture:** New `control.MonitorEvent` DTO; server `events` table + ingestion/admin routes; client `internal/monitor` (Collect + Report, fail-open, enrolled-gated); daemon report loop. Pure-Go, cross-compiles.

**Tech Stack:** Go 1.26, modernc sqlite, net/http, httptest.

**Verification bar:** `go build ./...`, `go test ./internal/... ` + full suite green, `go vet ./...`, `CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/ ./internal/server/... ./internal/monitor/` + `GOOS=windows`.

---

## Task 1: `MonitorEvent` DTO + server `events` store

**Files:** Modify `internal/control/control.go`, `internal/server/store/schema.sql`, `internal/server/store/store.go`. Test: append to `store_test.go`.

- [ ] **Step 1: append DTO to `internal/control/control.go`**
```go
// MonitorEvent is a single privacy-scrubbed host-scan observation. It carries
// NO command line, raw connection string, or environment value.
type MonitorEvent struct {
	Tool            string    `json:"tool"`
	Verdict         string    `json:"verdict"`
	Reason          string    `json:"reason"`
	DirectConnCount int       `json:"direct_conn_count"`
	ObservedAt      time.Time `json:"observed_at"`
}
```
(Add `"time"` to control.go imports if not present.)

- [ ] **Step 2: add to `internal/server/store/schema.sql`**
```sql
CREATE TABLE IF NOT EXISTS events (
  id                TEXT PRIMARY KEY,
  org_id            TEXT NOT NULL REFERENCES orgs(id),
  device_id         TEXT NOT NULL,
  tool              TEXT NOT NULL,
  verdict           TEXT NOT NULL,
  reason            TEXT NOT NULL,
  direct_conn_count INTEGER NOT NULL,
  observed_at       TIMESTAMP NOT NULL,
  received_at       TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_org ON events(org_id, received_at);
```

- [ ] **Step 3: failing test (append to `internal/server/store/store_test.go`)**
```go
func TestEventsInsertListCount(t *testing.T) {
	s := openTest(t)
	org, _ := s.CreateOrg("Acme")
	now := time.Unix(1_700_000_000, 0).UTC()
	evs := []control.MonitorEvent{
		{Tool: "Claude Code", Verdict: "runaway", Reason: "direct", DirectConnCount: 1, ObservedAt: now},
		{Tool: "Codex", Verdict: "protected", Reason: "via proxy", DirectConnCount: 0, ObservedAt: now},
	}
	if err := s.InsertEvents(org.ID, "dev1", evs, now); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}
	got, err := s.ListEvents(org.ID, 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("ListEvents: %v len=%d", err, len(got))
	}
	if got[0].DeviceID != "dev1" || got[0].OrgID != org.ID {
		t.Errorf("event missing ids: %+v", got[0])
	}
	counts, err := s.CountByVerdict(org.ID, now.Add(-time.Hour))
	if err != nil || counts["runaway"] != 1 || counts["protected"] != 1 {
		t.Fatalf("CountByVerdict: %v %+v", err, counts)
	}
}
```
(Ensure `"github.com/rakeshguha/redactr/internal/control"` is imported in the test.)

- [ ] **Step 4: implement (append to `internal/server/store/store.go`)** — add `"github.com/rakeshguha/redactr/internal/control"` import.
```go
// Event is a stored monitoring event (metadata only).
type Event struct {
	ID              string
	OrgID           string
	DeviceID        string
	Tool            string
	Verdict         string
	Reason          string
	DirectConnCount int
	ObservedAt      time.Time
	ReceivedAt      time.Time
}

// InsertEvents writes a batch of monitoring events for a device in one tx.
func (s *Store) InsertEvents(orgID, deviceID string, evs []control.MonitorEvent, receivedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range evs {
		if _, err := tx.Exec(
			`INSERT INTO events(id,org_id,device_id,tool,verdict,reason,direct_conn_count,observed_at,received_at)
			 VALUES(?,?,?,?,?,?,?,?,?)`,
			newID(), orgID, deviceID, e.Tool, e.Verdict, e.Reason, e.DirectConnCount, e.ObservedAt, receivedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListEvents returns the most recent events for an org (newest first).
func (s *Store) ListEvents(orgID string, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id,org_id,device_id,tool,verdict,reason,direct_conn_count,observed_at,received_at
		 FROM events WHERE org_id=? ORDER BY received_at DESC LIMIT ?`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.OrgID, &e.DeviceID, &e.Tool, &e.Verdict, &e.Reason, &e.DirectConnCount, &e.ObservedAt, &e.ReceivedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountByVerdict returns per-verdict counts for events received since `since`.
func (s *Store) CountByVerdict(orgID string, since time.Time) (map[string]int, error) {
	rows, err := s.db.Query(
		`SELECT verdict, COUNT(*) FROM events WHERE org_id=? AND received_at>=? GROUP BY verdict`, orgID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var v string
		var n int
		if err := rows.Scan(&v, &n); err != nil {
			return nil, err
		}
		out[v] = n
	}
	return out, rows.Err()
}
```

- [ ] **Step 5: verify + commit**
Run: `go test ./internal/server/store/ ./internal/control/ -v && go vet ./internal/server/store/ && CGO_ENABLED=0 GOOS=linux go build ./internal/server/store/`
```bash
git add internal/control/control.go internal/server/store/schema.sql internal/server/store/store.go internal/server/store/store_test.go
git commit -m "feat(server): events store — MonitorEvent DTO + Insert/List/CountByVerdict"
```

---

## Task 2: Server HTTP — ingestion + admin reads

**Files:** Modify `internal/server/httpapi/server.go`. Test: append to `server_test.go`.

- [ ] **Step 1: failing test (append to `internal/server/httpapi/server_test.go`)**
```go
func TestEventIngestionAndAdminRead(t *testing.T) {
	ts := newTestServer(t)
	// org + enroll
	r := postJSON(t, ts, "/admin/orgs", "admin-key", map[string]string{"name": "Acme"})
	var org struct{ ID string `json:"id"` }
	json.NewDecoder(r.Body).Decode(&org); r.Body.Close()
	r = postJSON(t, ts, "/admin/orgs/"+org.ID+"/enrollment-tokens", "admin-key", map[string]int{"max_uses": 0})
	var mint struct{ Token string `json:"token"` }
	json.NewDecoder(r.Body).Decode(&mint); r.Body.Close()
	r = postJSON(t, ts, "/v1/enroll", "", map[string]string{"enrollment_token": mint.Token, "device_name": "d", "platform": "darwin"})
	var enr map[string]string
	json.NewDecoder(r.Body).Decode(&enr); r.Body.Close()

	// Device posts events.
	body := map[string]any{"events": []map[string]any{
		{"tool": "Claude Code", "verdict": "runaway", "reason": "direct", "direct_conn_count": 1, "observed_at": "2026-01-01T00:00:00Z"},
	}}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/events", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+enr["token"])
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("POST /v1/events code = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Unauthenticated POST → 401.
	req2, _ := http.NewRequest("POST", ts.URL+"/v1/events", bytes.NewReader(b))
	u, _ := http.DefaultClient.Do(req2)
	if u.StatusCode != 401 {
		t.Errorf("unauth events code = %d, want 401", u.StatusCode)
	}
	u.Body.Close()

	// Admin reads them back.
	areq, _ := http.NewRequest("GET", ts.URL+"/admin/orgs/"+org.ID+"/events?limit=10", nil)
	areq.Header.Set("X-Admin-Key", "admin-key")
	ar, _ := http.DefaultClient.Do(areq)
	var evs []map[string]any
	json.NewDecoder(ar.Body).Decode(&evs); ar.Body.Close()
	if len(evs) != 1 {
		t.Fatalf("admin events len = %d", len(evs))
	}
}
```
(Imports `bytes` already added in A2.) Run `go test ./internal/server/httpapi/ -run TestEventIngestion -v` → FAIL.

- [ ] **Step 2: extend `internal/server/httpapi/server.go`**
Routes in `New` (remove the `// SEAM A4:` comment):
```go
	s.mux.Handle("POST /v1/events", dev(http.HandlerFunc(s.handlePostEvents)))
	s.mux.Handle("GET /admin/orgs/{id}/events", admin(http.HandlerFunc(s.handleAdminEvents)))
	s.mux.Handle("GET /admin/orgs/{id}/event-stats", admin(http.HandlerFunc(s.handleAdminEventStats)))
```
Handlers (add `"strconv"` and `"time"` imports if not present; `control` already imported):
```go
const maxEventBatch = 500

func (s *Server) handlePostEvents(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Events []control.MonitorEvent `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(in.Events) > maxEventBatch {
		http.Error(w, "batch too large", http.StatusBadRequest)
		return
	}
	if len(in.Events) == 0 {
		writeJSON(w, 200, map[string]int{"accepted": 0})
		return
	}
	if err := s.store.InsertEvents(auth.OrgID(r.Context()), auth.DeviceID(r.Context()), in.Events, time.Now().UTC()); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]int{"accepted": len(in.Events)})
}

func (s *Server) handleAdminEvents(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if _, err := s.store.GetOrg(orgID); err != nil {
		http.Error(w, "unknown org", http.StatusNotFound)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	evs, err := s.store.ListEvents(orgID, limit)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, evs)
}

func (s *Server) handleAdminEventStats(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if _, err := s.store.GetOrg(orgID); err != nil {
		http.Error(w, "unknown org", http.StatusNotFound)
		return
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("since_hours"))
	if hours <= 0 {
		hours = 24
	}
	counts, err := s.store.CountByVerdict(orgID, time.Now().UTC().Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, counts)
}
```

- [ ] **Step 3: verify + commit**
Run: `go test ./internal/server/httpapi/ -v && go vet ./internal/server/httpapi/ && go build ./... && CGO_ENABLED=0 GOOS=linux go build ./internal/server/...`
```bash
git add internal/server/httpapi/server.go internal/server/httpapi/server_test.go
git commit -m "feat(server): monitoring ingestion POST /v1/events + admin event reads"
```

---

## Task 3: Client `internal/monitor` (Collect + Report)

**Files:** Create `internal/monitor/monitor.go`, `internal/monitor/monitor_test.go`.

- [ ] **Step 1: failing test (`internal/monitor/monitor_test.go`)**
```go
package monitor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rakeshguha/redactr/internal/enrollment"
	"github.com/rakeshguha/redactr/internal/sessions"
)

func TestCollectScrubsMetadata(t *testing.T) {
	in := []sessions.Session{{
		Tool: "Claude Code", Status: sessions.StatusRunaway, Reason: "direct connection",
		Command: "claude --secret-flag /Users/me/private", // must NOT leak
		Connections: []string{"1.2.3.4:443"},              // must NOT leak
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
		var body struct{ Events []map[string]any `json:"events"` }
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
```
> The test imports `"github.com/rakeshguha/redactr/internal/control"` (for the `MonitorEvent` literals) in addition to enrollment/sessions/net-http/json/strings/testing.

Run `go test ./internal/monitor/ -v` → FAIL.

- [ ] **Step 2: implement `internal/monitor/monitor.go`**
```go
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

	"github.com/rakeshguha/redactr/internal/control"
	"github.com/rakeshguha/redactr/internal/enrollment"
	"github.com/rakeshguha/redactr/internal/sessions"
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
	req, _ := http.NewRequest(http.MethodPost, strings.TrimRight(enr.ServerURL, "/")+"/v1/events", bytes.NewReader(body))
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
```
Run → PASS. Commit:
```bash
git add internal/monitor/
git commit -m "feat(client): monitor — collect scrubbed events + report to control plane (fail-open)"
```

---

## Task 4: Daemon monitor-report loop

**Files:** Modify `internal/daemon/daemon.go`. Test: append to `daemon_test.go`.

- [ ] **Step 1: failing test (append to `internal/daemon/daemon_test.go`)**
```go
func TestMonitorGate(t *testing.T) {
	base := t.TempDir()
	if shouldReport(base) {
		t.Error("unenrolled should not report")
	}
}
```
Run → FAIL (undefined: shouldReport).

- [ ] **Step 2: implement in `internal/daemon/daemon.go`**
1. Imports: add `"github.com/rakeshguha/redactr/internal/monitor"`. (`sessions`, `enrollment`, `context`, `time`, `slog` already present.)
2. Confirm the daemon holds a `sessions.Lister`. In `Build`, the lister is created (`sessLister := sessions.New(os.Getpid())`) and passed to `apiServer.SetSessions`. Promote it to a struct field `sessLister *sessions.Lister` set in `Build` (replace the local with `d.sessLister = sessions.New(os.Getpid())` and pass `d.sessLister`). Also add a `monitorCancel context.CancelFunc` field.
3. Gate helper:
```go
// shouldReport reports whether this daemon should run the monitor-report loop.
func shouldReport(baseDir string) bool { return enrollment.Exists(baseDir) }
```
4. In `Start`, after the policy-sync loop block, add:
```go
	if !d.opts.Ephemeral && shouldReport(d.opts.BaseDir) {
		ctx, cancel := context.WithCancel(context.Background())
		d.monitorCancel = cancel
		go d.monitorLoop(ctx)
	}
```
5. The loop:
```go
func (d *Daemon) monitorLoop(ctx context.Context) {
	report := func() {
		list, err := d.sessLister.List()
		if err != nil {
			slog.Warn("session scan failed", "error", err)
			return
		}
		if err := monitor.Report(d.opts.BaseDir, monitor.Collect(list)); err != nil {
			slog.Warn("monitor report failed", "error", err)
		}
	}
	report()
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			report()
		}
	}
}
```
6. In `Stop`, add a nil-guarded `if d.monitorCancel != nil { d.monitorCancel() }`.

- [ ] **Step 3: verify + commit**
Run: `go test ./internal/daemon/ -v && go build ./... && go vet ./internal/daemon/ && go test ./internal/... 2>&1 | grep -v "no test files" && CGO_ENABLED=0 GOOS=linux go build ./internal/daemon/ ./internal/monitor/`
Expected: all PASS (Ephemeral smoke unaffected; the gate prevents network in tests).
```bash
git add internal/daemon/daemon.go internal/daemon/daemon_test.go
git commit -m "feat(daemon): monitor-report loop (enrolled-gated, fail-open)"
```

---

## Final verification
```bash
go build ./... && go test ./internal/... 2>&1 | grep -v "no test files" && go vet ./... \
  && CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/ ./internal/server/... ./internal/monitor/ \
  && CGO_ENABLED=0 GOOS=windows go build ./cmd/redactr-server/ ./internal/server/... ./internal/monitor/
```

## Self-Review map
- events store (Insert/List/CountByVerdict) → T1; ingestion+admin reads → T2; client Collect (scrubbing, leak-tested)+Report (fail-open) → T3; daemon loop (gated) → T4. Privacy invariant tested in T3 (`TestCollectScrubsMetadata` asserts no cmdline/addr leak). "unsandboxed" verdict is a free-string SEAM.
