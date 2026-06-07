# F1 — Durable, Effectively-Once Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the daemon's fire-and-forget, at-most-once event reporting with a durable local outbox that ships both posture events and redaction-finding metadata to the control plane with effectively-once semantics (at-least-once transport + idempotent server sink).

**Architecture:** Every telemetry item (`MonitorEvent` from the host scan + a new `AuditRecord` derived from each `ScanReport`, carrying categories but never raw values) is written synchronously to an append-only outbox bucket in the existing client BoltDB (`~/.redactr/data/logs.db`). A single background **shipper** goroutine drains the outbox, POSTs batches to a new unified `POST /v1/ingest` endpoint over the device's bearer token, deletes records only after a `2xx`, and retries with exponential backoff otherwise — surviving restarts and offline periods. Each record carries a client-generated UUID; the server stores via `INSERT ... ON CONFLICT(uuid) DO NOTHING`, so retries dedupe to effectively-once.

**Tech Stack:** Go 1.26, `go.etcd.io/bbolt` (client outbox), `modernc.org/sqlite` (server store), stdlib `net/http`, `log/slog`.

---

## File Structure

**New files:**
- `internal/store/outbox.go` — outbox bucket + `EnqueueMonitor`/`EnqueueAudit`/`Drain`/`Ack`/`OutboxCount`/`Trim` on the existing client `*store.Store` (reuses the one `logs.db` handle).
- `internal/store/outbox_test.go` — outbox durability/ordering/trim tests.
- `internal/shipper/shipper.go` — `Shipper` drain→post→ack loop with backoff; `Drainer`/`Poster` interfaces.
- `internal/shipper/http.go` — `HTTPPoster` that POSTs to `/v1/ingest` using the saved enrollment.
- `internal/shipper/shipper_test.go` — unit test of the drain/retry/ack logic with fakes.
- `internal/shipper/http_test.go` — `HTTPPoster` test against an `httptest` server.
- `internal/shipper/e2e_test.go` — end-to-end effectively-once test (real client outbox + shipper + real control-plane server, with injected transient failures).
- `internal/server/store/ingest.go` — `IngestRecords` (idempotent), `CountEvents`, `CountAuditRecords`.
- `internal/server/store/migrate.go` — additive column migration (`events.uuid`).
- `internal/server/store/ingest_test.go` — server-side dedup + migration tests.
- `internal/daemon/audit.go` — `auditRecordsFromReport` (ScanReport → []AuditRecord, value-stripping).
- `internal/daemon/audit_test.go` — privacy/conversion test.

**Modified files:**
- `internal/control/control.go` — add `AuditRecord`, `IngestRecord`, `IngestRequest`, `IngestResponse`, kind constants.
- `internal/store/store.go` — create the outbox bucket in `New`; add `crypto/rand`, `encoding/hex`, `encoding/binary`, and `control` imports.
- `internal/server/store/store.go` — split index creation out of `schema.sql`; call `migrate` in `Open`.
- `internal/server/store/schema.sql` — add `uuid` column to `events`, add `audit_records` table + index; remove the events-uuid unique index (moves to `indexesSQL`).
- `internal/server/httpapi/server.go` — add `POST /v1/ingest` route + `handleIngest`.
- `internal/server/httpapi/server_test.go` — add ingest endpoint test (append; leave the existing `/v1/events` test intact).
- `internal/daemon/daemon.go` — enqueue audit records in `onScan`; enqueue monitor events in `monitorLoop` (replacing `monitor.Report`); start/stop the shipper.
- `internal/monitor/monitor.go` — remove the obsolete `Report` function (keep `Collect`).
- `internal/monitor/monitor_test.go` — remove the two `Report` tests.

> **Compatibility note:** the existing `POST /v1/events` handler and its server test are left untouched (legacy, no longer called by the client) to minimize churn. Only the client stops using it.

---

## Task 1: Wire types in the control package

**Files:**
- Modify: `internal/control/control.go`
- Test: `internal/control/control_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `internal/control/control_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/control/ -run TestIngest -v`
Expected: FAIL — `undefined: IngestRecord`, `undefined: KindMonitor`, etc.

- [ ] **Step 3: Add the types**

Append to `internal/control/control.go` (after the `MonitorEvent` struct):

```go
// Kinds of telemetry carried in an IngestRecord.
const (
	KindMonitor = "monitor"
	KindAudit   = "audit"
)

// AuditRecord is a single redaction-finding observation derived from a local
// ScanReport. It carries the detector and category of what was redacted, never
// the raw or redacted value and never any request/response body.
type AuditRecord struct {
	Provider   string    `json:"provider"`
	Source     string    `json:"source"`
	Detector   string    `json:"detector"`
	Category   string    `json:"category"`
	Action     string    `json:"action"` // "blocked" | "allowed"
	LatencyMs  int64     `json:"latency_ms"`
	ObservedAt time.Time `json:"observed_at"`
}

// IngestRecord is one durable, idempotent telemetry item. Exactly one of
// Monitor/Audit is set, selected by Kind. UUID is the client-generated
// idempotency key; Seq is the client's monotonic per-device sequence.
type IngestRecord struct {
	UUID    string        `json:"uuid"`
	Seq     uint64        `json:"seq"`
	Kind    string        `json:"kind"`
	Monitor *MonitorEvent `json:"monitor,omitempty"`
	Audit   *AuditRecord  `json:"audit,omitempty"`
}

// IngestRequest is the POST /v1/ingest body.
type IngestRequest struct {
	Records []IngestRecord `json:"records"`
}

// IngestResponse lists the UUIDs the server has durably stored (new or already-present).
type IngestResponse struct {
	Accepted []string `json:"accepted"`
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/control/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/control/control.go internal/control/control_test.go
git commit -m "feat(control): add AuditRecord + IngestRecord wire types for durable delivery"
```

---

## Task 2: Client outbox storage

**Files:**
- Modify: `internal/store/store.go` (imports + bucket creation in `New`)
- Create: `internal/store/outbox.go`
- Test: `internal/store/outbox_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/store/outbox_test.go`:

```go
package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/redactrai/redactr/internal/control"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestEnqueueDrainAck(t *testing.T) {
	s := openTemp(t)
	if err := s.EnqueueMonitor(control.MonitorEvent{Tool: "a", Verdict: "runaway", ObservedAt: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueMonitor(control.MonitorEvent{Tool: "b", Verdict: "protected", ObservedAt: time.Unix(2, 0)}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueAudit(control.AuditRecord{Category: "aws_key", Detector: "regex"}); err != nil {
		t.Fatal(err)
	}

	recs, keys, err := s.Drain(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || len(keys) != 3 {
		t.Fatalf("drain got %d recs / %d keys", len(recs), len(keys))
	}
	// FIFO by seq: first enqueued first out.
	if recs[0].Kind != control.KindMonitor || recs[0].Monitor.Tool != "a" {
		t.Fatalf("order wrong: %+v", recs[0])
	}
	if recs[2].Kind != control.KindAudit || recs[2].Audit.Category != "aws_key" {
		t.Fatalf("audit record wrong: %+v", recs[2])
	}
	if recs[0].UUID == "" || recs[0].Seq == 0 {
		t.Fatalf("uuid/seq not assigned: %+v", recs[0])
	}

	if err := s.Ack(keys[:2]); err != nil {
		t.Fatal(err)
	}
	if n := s.OutboxCount(); n != 1 {
		t.Fatalf("after ack count=%d want 1", n)
	}
	rest, _, _ := s.Drain(10)
	if len(rest) != 1 || rest[0].Kind != control.KindAudit {
		t.Fatalf("remaining wrong: %+v", rest)
	}
}

func TestOutboxSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.EnqueueMonitor(control.MonitorEvent{Tool: "x"})
	s.Close()

	s2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	recs, _, _ := s2.Drain(10)
	if len(recs) != 1 || recs[0].Monitor.Tool != "x" {
		t.Fatalf("durability failed: %+v", recs)
	}
}

func TestTrimDropsOldest(t *testing.T) {
	s := openTemp(t)
	for i := 0; i < 5; i++ {
		_ = s.EnqueueMonitor(control.MonitorEvent{Tool: "t", DirectConnCount: i})
	}
	dropped, err := s.Trim(3)
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 2 {
		t.Fatalf("dropped=%d want 2", dropped)
	}
	recs, _, _ := s.Drain(10)
	if len(recs) != 3 {
		t.Fatalf("after trim count=%d want 3", len(recs))
	}
	// Oldest (DirectConnCount 0,1) dropped; newest survive starting at 2.
	if recs[0].Monitor.DirectConnCount != 2 {
		t.Fatalf("trim dropped wrong end: first survivor=%d", recs[0].Monitor.DirectConnCount)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/ -run 'TestEnqueue|TestOutbox|TestTrim' -v`
Expected: FAIL — `s.EnqueueMonitor undefined`.

- [ ] **Step 3: Create the outbox bucket in `New`**

In `internal/store/store.go`, update the imports block to add the new packages:

```go
import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"crypto/rand"

	"github.com/redactrai/redactr/internal/control"
	bolt "go.etcd.io/bbolt"
)
```

Add the bucket var next to `reportsBucket`:

```go
var outboxBucket = []byte("outbox")
```

In `New`, extend the `CreateBucketIfNotExists` step to also create the outbox bucket:

```go
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(reportsBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(outboxBucket)
		return err
	})
```

- [ ] **Step 4: Create `internal/store/outbox.go`**

```go
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/ -v`
Expected: PASS (new outbox tests + the existing report tests).

- [ ] **Step 6: Commit**

```bash
git add internal/store/store.go internal/store/outbox.go internal/store/outbox_test.go
git commit -m "feat(store): durable append-only outbox in client BoltDB"
```

---

## Task 3: Shipper drain/retry/ack loop

**Files:**
- Create: `internal/shipper/shipper.go`
- Test: `internal/shipper/shipper_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/shipper/shipper_test.go`:

```go
package shipper

import (
	"context"
	"errors"
	"testing"

	"github.com/redactrai/redactr/internal/control"
)

type fakeStore struct {
	recs   []control.IngestRecord
	keys   [][]byte
	acked  [][]byte
	trims  int
}

func (f *fakeStore) Drain(max int) ([]control.IngestRecord, [][]byte, error) {
	return f.recs, f.keys, nil
}
func (f *fakeStore) Ack(keys [][]byte) error { f.acked = keys; f.recs = nil; f.keys = nil; return nil }
func (f *fakeStore) Trim(maxItems int) (int, error) { f.trims++; return 0, nil }

type flakyPoster struct {
	failFirst int
	calls     int
	got       [][]control.IngestRecord
}

func (p *flakyPoster) Post(ctx context.Context, recs []control.IngestRecord) error {
	p.calls++
	p.got = append(p.got, recs)
	if p.calls <= p.failFirst {
		return errors.New("boom")
	}
	return nil
}

func TestRunOnceRetriesThenAcks(t *testing.T) {
	store := &fakeStore{
		recs: []control.IngestRecord{{UUID: "u1", Kind: control.KindMonitor}},
		keys: [][]byte{{0, 0, 0, 0, 0, 0, 0, 1}},
	}
	poster := &flakyPoster{failFirst: 1}
	s := New(store, poster)

	if ok := s.runOnce(context.Background()); ok {
		t.Fatal("first runOnce should fail (poster errored) and not ack")
	}
	if store.acked != nil {
		t.Fatal("must not ack on failed post")
	}

	if ok := s.runOnce(context.Background()); !ok {
		t.Fatal("second runOnce should succeed")
	}
	if len(store.acked) != 1 {
		t.Fatalf("expected ack of 1 key, got %d", len(store.acked))
	}
	// Same records were retried (identical UUIDs) — that is what makes the
	// server-side dedup yield effectively-once.
	if poster.calls != 2 || poster.got[0][0].UUID != "u1" || poster.got[1][0].UUID != "u1" {
		t.Fatalf("expected 2 calls with same uuid, got %d calls", poster.calls)
	}
}

func TestRunOnceEmptyIsOk(t *testing.T) {
	s := New(&fakeStore{}, &flakyPoster{})
	if ok := s.runOnce(context.Background()); !ok {
		t.Fatal("empty drain should report ok")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/shipper/ -v`
Expected: FAIL — `undefined: New` (package does not exist yet).

- [ ] **Step 3: Create `internal/shipper/shipper.go`**

```go
// Package shipper drains the client's durable outbox and delivers records to
// the control plane with at-least-once semantics. Combined with the server's
// UUID-keyed idempotent sink, this yields effectively-once delivery.
package shipper

import (
	"context"
	"log/slog"
	"time"

	"github.com/redactrai/redactr/internal/control"
)

// Drainer is the outbox surface the shipper needs (satisfied by *store.Store).
type Drainer interface {
	Drain(max int) ([]control.IngestRecord, [][]byte, error)
	Ack(keys [][]byte) error
	Trim(maxItems int) (int, error)
}

// Poster delivers a batch to the control plane. A nil error means the batch is
// durably stored server-side and may be acked locally.
type Poster interface {
	Post(ctx context.Context, records []control.IngestRecord) error
}

// Shipper repeatedly drains and delivers the outbox.
type Shipper struct {
	store      Drainer
	poster     Poster
	batch      int
	maxItems   int
	idle       time.Duration
	backoffMax time.Duration
}

// New builds a Shipper with production defaults.
func New(store Drainer, poster Poster) *Shipper {
	return &Shipper{
		store:      store,
		poster:     poster,
		batch:      500,
		maxItems:   50000,
		idle:       2 * time.Second,
		backoffMax: 5 * time.Minute,
	}
}

// runOnce performs a single trim+drain+deliver cycle. It returns true when
// there was nothing to send or the send succeeded, and false when delivery
// failed (so the caller backs off). Records are acked only after a successful
// Post; on failure they remain in the outbox and are retried unchanged.
func (s *Shipper) runOnce(ctx context.Context) bool {
	if dropped, err := s.store.Trim(s.maxItems); err != nil {
		slog.Warn("outbox trim failed", "error", err)
	} else if dropped > 0 {
		slog.Warn("outbox over capacity; dropped oldest records", "event", "outbox_overflow", "dropped", dropped)
	}
	recs, keys, err := s.store.Drain(s.batch)
	if err != nil {
		slog.Warn("outbox drain failed", "error", err)
		return false
	}
	if len(recs) == 0 {
		return true
	}
	if err := s.poster.Post(ctx, recs); err != nil {
		slog.Warn("ingest post failed", "event", "ingest_retry", "error", err, "batch", len(recs))
		return false
	}
	if err := s.store.Ack(keys); err != nil {
		slog.Warn("outbox ack failed", "error", err)
	}
	return true
}

// Run loops runOnce until ctx is cancelled, sleeping `idle` between successful
// cycles and backing off exponentially (capped) after failures.
func (s *Shipper) Run(ctx context.Context) {
	backoff := time.Second
	for {
		var wait time.Duration
		if s.runOnce(ctx) {
			wait = s.idle
			backoff = time.Second
		} else {
			wait = backoff
			backoff = min(backoff*2, s.backoffMax)
		}
		if !sleepCtx(ctx, wait) {
			return
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/shipper/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/shipper/shipper.go internal/shipper/shipper_test.go
git commit -m "feat(shipper): outbox drain/retry/ack loop with backoff"
```

---

## Task 4: HTTP poster

**Files:**
- Create: `internal/shipper/http.go`
- Test: `internal/shipper/http_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/shipper/http_test.go`:

```go
package shipper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redactrai/redactr/internal/control"
	"github.com/redactrai/redactr/internal/enrollment"
)

func TestHTTPPosterSendsToIngest(t *testing.T) {
	var gotPath, gotAuth string
	var gotRecords int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		var in control.IngestRequest
		json.NewDecoder(r.Body).Decode(&in)
		gotRecords = len(in.Records)
		json.NewEncoder(w).Encode(control.IngestResponse{Accepted: []string{"u1"}})
	}))
	defer srv.Close()

	base := t.TempDir()
	if err := enrollment.Save(base, enrollment.Enrollment{ServerURL: srv.URL, DeviceToken: "tok", OrgID: "o", DeviceID: "d", ServerPublicKey: "x"}); err != nil {
		t.Fatal(err)
	}
	p := NewHTTPPoster(base)
	err := p.Post(context.Background(), []control.IngestRecord{{UUID: "u1", Kind: control.KindMonitor, Monitor: &control.MonitorEvent{Tool: "a"}}})
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if gotPath != "/v1/ingest" || gotAuth != "Bearer tok" || gotRecords != 1 {
		t.Fatalf("path=%q auth=%q records=%d", gotPath, gotAuth, gotRecords)
	}
}

func TestHTTPPosterNon200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	base := t.TempDir()
	_ = enrollment.Save(base, enrollment.Enrollment{ServerURL: srv.URL, DeviceToken: "tok"})
	if err := NewHTTPPoster(base).Post(context.Background(), []control.IngestRecord{{UUID: "u", Kind: control.KindMonitor}}); err == nil {
		t.Fatal("expected error on 503")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/shipper/ -run TestHTTPPoster -v`
Expected: FAIL — `undefined: NewHTTPPoster`.

- [ ] **Step 3: Create `internal/shipper/http.go`**

```go
package shipper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/redactrai/redactr/internal/control"
	"github.com/redactrai/redactr/internal/enrollment"
)

// HTTPPoster delivers batches to POST /v1/ingest using the saved enrollment.
type HTTPPoster struct {
	baseDir string
	client  *http.Client
}

// NewHTTPPoster builds a poster reading enrollment from baseDir on each call,
// so a device that enrolls while the daemon runs is picked up without restart.
func NewHTTPPoster(baseDir string) *HTTPPoster {
	return &HTTPPoster{baseDir: baseDir, client: &http.Client{Timeout: 15 * time.Second}}
}

func (p *HTTPPoster) Post(ctx context.Context, records []control.IngestRecord) error {
	enr, err := enrollment.Load(p.baseDir)
	if err != nil {
		return err // not enrolled / unreadable: retain records and retry later
	}
	body, err := json.Marshal(control.IngestRequest{Records: records})
	if err != nil {
		return err
	}
	url := strings.TrimRight(enr.ServerURL, "/") + "/v1/ingest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+enr.DeviceToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ingest failed: %d", resp.StatusCode)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/shipper/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/shipper/http.go internal/shipper/http_test.go
git commit -m "feat(shipper): HTTP poster for POST /v1/ingest"
```

---

## Task 5: Server store — idempotent ingest + migration

**Files:**
- Modify: `internal/server/store/schema.sql`
- Modify: `internal/server/store/store.go` (`Open` adds migrate + indexes)
- Create: `internal/server/store/migrate.go`
- Create: `internal/server/store/ingest.go`
- Test: `internal/server/store/ingest_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/server/store/ingest_test.go`:

```go
package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/redactrai/redactr/internal/control"
)

func recMon(uuid, tool string) control.IngestRecord {
	return control.IngestRecord{UUID: uuid, Kind: control.KindMonitor,
		Monitor: &control.MonitorEvent{Tool: tool, Verdict: "runaway", Reason: "x", ObservedAt: time.Unix(1, 0).UTC()}}
}
func recAudit(uuid, cat string) control.IngestRecord {
	return control.IngestRecord{UUID: uuid, Kind: control.KindAudit,
		Audit: &control.AuditRecord{Provider: "anthropic", Source: "proxy", Detector: "regex", Category: cat, Action: "blocked", ObservedAt: time.Unix(1, 0).UTC()}}
}

func TestIngestRecordsDedup(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	batch := []control.IngestRecord{recMon("m1", "a"), recAudit("a1", "aws_key")}

	acc, err := st.IngestRecords("org1", "dev1", batch, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(acc) != 2 {
		t.Fatalf("accepted=%d want 2", len(acc))
	}
	// Re-ingest the identical batch: must dedupe, not duplicate.
	if _, err := st.IngestRecords("org1", "dev1", batch, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountEvents("org1"); n != 1 {
		t.Fatalf("events=%d want 1 (deduped)", n)
	}
	if n, _ := st.CountAuditRecords("org1"); n != 1 {
		t.Fatalf("audit=%d want 1 (deduped)", n)
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	st2, err := Open(path) // second open must not error (migration is idempotent)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	st2.Close()
}

func TestMigrationAddsUUIDToLegacyEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	// Simulate a pre-F1 DB: an events table with no uuid column.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`CREATE TABLE events (
	  id TEXT PRIMARY KEY, org_id TEXT NOT NULL, device_id TEXT NOT NULL,
	  tool TEXT NOT NULL, verdict TEXT NOT NULL, reason TEXT NOT NULL,
	  direct_conn_count INTEGER NOT NULL, observed_at TIMESTAMP NOT NULL, received_at TIMESTAMP NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	raw.Close()

	st, err := Open(path) // must ALTER events ADD COLUMN uuid + create unique index
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	defer st.Close()
	if _, err := st.IngestRecords("org1", "dev1", []control.IngestRecord{recMon("m1", "a")}, time.Now().UTC()); err != nil {
		t.Fatalf("ingest after migration: %v", err)
	}
	if n, _ := st.CountEvents("org1"); n != 1 {
		t.Fatalf("events=%d want 1", n)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/store/ -run 'TestIngest|TestOpen|TestMigration' -v`
Expected: FAIL — `st.IngestRecords undefined`.

- [ ] **Step 3: Update `schema.sql`**

In `internal/server/store/schema.sql`, change the `events` table to include a `uuid` column and add the `audit_records` table. Replace the events block:

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
  received_at       TIMESTAMP NOT NULL,
  uuid              TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_org ON events(org_id, received_at);
```

Then append, after the events block (before or after `images` — order does not matter):

```sql
CREATE TABLE IF NOT EXISTS audit_records (
  uuid        TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  provider    TEXT NOT NULL,
  source      TEXT NOT NULL,
  detector    TEXT NOT NULL,
  category    TEXT NOT NULL,
  action      TEXT NOT NULL,
  latency_ms  INTEGER NOT NULL,
  observed_at TIMESTAMP NOT NULL,
  received_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_records(org_id, received_at);
```

> Do NOT put the events `uuid` unique index in `schema.sql` — it must be created only after the migration guarantees the column exists. It goes in `indexesSQL` (Step 5).

- [ ] **Step 4: Create `internal/server/store/migrate.go`**

```go
package store

import "database/sql"

// migrate applies additive, idempotent schema changes that CREATE TABLE IF NOT
// EXISTS cannot express (e.g. adding a column to a pre-existing table). It runs
// after the base schema and before index creation in Open.
func migrate(db *sql.DB) error {
	if !columnExists(db, "events", "uuid") {
		if _, err := db.Exec(`ALTER TABLE events ADD COLUMN uuid TEXT`); err != nil {
			return err
		}
	}
	return nil
}

func columnExists(db *sql.DB, table, col string) bool {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false
		}
		if name == col {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Wire migrate + indexes into `Open`**

In `internal/server/store/store.go`, add the index constant near the `//go:embed` block:

```go
// indexesSQL holds indexes that depend on columns added by migrate(); it runs
// after the base schema and after migration so the columns exist.
const indexesSQL = `CREATE UNIQUE INDEX IF NOT EXISTS idx_events_uuid ON events(uuid);`
```

In `Open`, replace the single schema exec:

```go
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
```

with:

```go
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(indexesSQL); err != nil {
		db.Close()
		return nil, err
	}
```

- [ ] **Step 6: Create `internal/server/store/ingest.go`**

```go
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
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/server/store/ -v`
Expected: PASS (new ingest/migration tests + existing store tests).

- [ ] **Step 8: Commit**

```bash
git add internal/server/store/schema.sql internal/server/store/store.go internal/server/store/migrate.go internal/server/store/ingest.go internal/server/store/ingest_test.go
git commit -m "feat(server/store): idempotent ingest, audit_records table, events.uuid migration"
```

---

## Task 6: Server `POST /v1/ingest` endpoint

**Files:**
- Modify: `internal/server/httpapi/server.go`
- Test: `internal/server/httpapi/server_test.go` (append)

- [ ] **Step 1: Write the failing test**

Append to `internal/server/httpapi/server_test.go`:

```go
func TestIngestEndpointDedup(t *testing.T) {
	ts := newTestServer(t)

	// org + token + enroll to get a device bearer token.
	resp := postJSON(t, ts, "/admin/orgs", "admin-key", map[string]string{"name": "Acme"})
	var org struct{ ID string `json:"id"` }
	json.NewDecoder(resp.Body).Decode(&org)
	resp.Body.Close()

	resp = postJSON(t, ts, "/admin/orgs/"+org.ID+"/enrollment-tokens", "admin-key",
		map[string]int{"expires_in_hours": 1, "max_uses": 1})
	var mint struct{ Token string `json:"token"` }
	json.NewDecoder(resp.Body).Decode(&mint)
	resp.Body.Close()

	resp = postJSON(t, ts, "/v1/enroll", "",
		map[string]string{"enrollment_token": mint.Token, "device_name": "laptop", "platform": "darwin"})
	var enr map[string]string
	json.NewDecoder(resp.Body).Decode(&enr)
	resp.Body.Close()
	token := enr["token"]

	body := control.IngestRequest{Records: []control.IngestRecord{
		{UUID: "m1", Kind: control.KindMonitor, Monitor: &control.MonitorEvent{Tool: "Claude Code", Verdict: "runaway", Reason: "x"}},
		{UUID: "a1", Kind: control.KindAudit, Audit: &control.AuditRecord{Provider: "anthropic", Source: "proxy", Detector: "regex", Category: "aws_key", Action: "blocked"}},
	}}
	b, _ := json.Marshal(body)

	post := func() int {
		req, _ := http.NewRequest("POST", ts.URL+"/v1/ingest", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		return r.StatusCode
	}
	if code := post(); code != 200 {
		t.Fatalf("first ingest code=%d", code)
	}
	if code := post(); code != 200 { // idempotent retry
		t.Fatalf("second ingest code=%d", code)
	}

	// Exactly one event survived dedup.
	req, _ := http.NewRequest("GET", ts.URL+"/admin/orgs/"+org.ID+"/events", nil)
	req.Header.Set("X-Admin-Key", "admin-key")
	r, _ := http.DefaultClient.Do(req)
	var evs []map[string]any
	json.NewDecoder(r.Body).Decode(&evs)
	r.Body.Close()
	if len(evs) != 1 {
		t.Fatalf("events after dedup=%d want 1", len(evs))
	}
}
```

(The test uses `bytes` and `control`, both already imported in `server_test.go`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/httpapi/ -run TestIngestEndpointDedup -v`
Expected: FAIL — 404 (route not registered), so the count assertion fails.

- [ ] **Step 3: Register the route**

In `internal/server/httpapi/server.go`, in `New`, after the `/v1/events` line:

```go
	s.mux.Handle("POST /v1/ingest", dev(http.HandlerFunc(s.handleIngest)))
```

- [ ] **Step 4: Add the handler**

In `internal/server/httpapi/server.go`, after `handlePostEvents`:

```go
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	var in control.IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(in.Records) > maxEventBatch {
		http.Error(w, "batch too large", http.StatusBadRequest)
		return
	}
	if len(in.Records) == 0 {
		writeJSON(w, 200, control.IngestResponse{Accepted: []string{}})
		return
	}
	accepted, err := s.store.IngestRecords(auth.OrgID(r.Context()), auth.DeviceID(r.Context()), in.Records, time.Now().UTC())
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, control.IngestResponse{Accepted: accepted})
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/server/httpapi/ -v`
Expected: PASS (new test + existing `/v1/events` and enroll tests).

- [ ] **Step 6: Commit**

```bash
git add internal/server/httpapi/server.go internal/server/httpapi/server_test.go
git commit -m "feat(server): POST /v1/ingest idempotent telemetry endpoint"
```

---

## Task 7: Daemon wiring + retire `monitor.Report`

**Files:**
- Create: `internal/daemon/audit.go`
- Test: `internal/daemon/audit_test.go`
- Modify: `internal/daemon/daemon.go`
- Modify: `internal/monitor/monitor.go`
- Modify: `internal/monitor/monitor_test.go`

- [ ] **Step 1: Write the failing test for the conversion helper**

Create `internal/daemon/audit_test.go`:

```go
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
	// CRITICAL privacy invariant: no raw redacted value may appear anywhere.
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/daemon/ -run TestAuditRecordsFromReport -v`
Expected: FAIL — `undefined: auditRecordsFromReport`.

- [ ] **Step 3: Create `internal/daemon/audit.go`**

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/daemon/ -run TestAuditRecordsFromReport -v`
Expected: PASS

- [ ] **Step 5: Enqueue audit records in `onScan`**

In `internal/daemon/daemon.go` `Build`, just before the `onScan` definition (around line 185), capture enrollment state:

```go
	enrolled := enrollment.Exists(baseDir)
```

Replace the `onScan` closure:

```go
	onScan := func(report *store.ScanReport) {
		logStore.SaveReport(report)
		hub.Broadcast(report)
	}
```

with:

```go
	onScan := func(report *store.ScanReport) {
		logStore.SaveReport(report)
		hub.Broadcast(report)
		if enrolled {
			for _, a := range auditRecordsFromReport(report) {
				if err := logStore.EnqueueAudit(a); err != nil {
					slog.Warn("audit enqueue failed", "error", err)
				}
			}
		}
	}
```

- [ ] **Step 6: Add the shipper field**

In the `Daemon` struct (around line 80-85), add a cancel field next to `monitorCancel`:

```go
	monitorCancel   context.CancelFunc
	shipperCancel   context.CancelFunc
```

Add the import in `internal/daemon/daemon.go`'s import block:

```go
	"github.com/redactrai/redactr/internal/shipper"
```

- [ ] **Step 7: Replace the monitor reporting with enqueue, and start the shipper**

In `monitorLoop`, replace the `report` closure body:

```go
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
```

with:

```go
	report := func() {
		list, err := d.sessLister.List()
		if err != nil {
			slog.Warn("session scan failed", "error", err)
			return
		}
		for _, ev := range monitor.Collect(list) {
			if err := d.store.EnqueueMonitor(ev); err != nil {
				slog.Warn("monitor enqueue failed", "error", err)
			}
		}
	}
```

In `Start`, after the `monitorLoop` goroutine block (around line 378-382), add the shipper start:

```go
	if !d.opts.Ephemeral && isEnrolled(d.opts.BaseDir) {
		ctx, cancel := context.WithCancel(context.Background())
		d.shipperCancel = cancel
		sh := shipper.New(d.store, shipper.NewHTTPPoster(d.opts.BaseDir))
		go sh.Run(ctx)
	}
```

In `Stop`, after the `monitorCancel` block (around line 395-397), add:

```go
	if d.shipperCancel != nil {
		d.shipperCancel()
	}
```

- [ ] **Step 8: Remove the obsolete `monitor.Report`**

Replace the entire contents of `internal/monitor/monitor.go` with:

```go
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
```

- [ ] **Step 9: Remove the obsolete monitor tests**

Replace the entire contents of `internal/monitor/monitor_test.go` with (drops the two `Report` tests and their now-unused imports):

```go
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
```

- [ ] **Step 10: Build and run the full suite**

Run: `go build ./... && go test ./...`
Expected: PASS across all packages, including `internal/daemon`, `internal/monitor`, `internal/shipper`, `internal/store`, `internal/server/...`. If `go vet` flags an unused import in `daemon.go`, ensure `monitor` is still used (it is — `monitor.Collect`).

- [ ] **Step 11: Commit**

```bash
git add internal/daemon/ internal/monitor/
git commit -m "feat(daemon): enqueue audit+monitor telemetry to outbox; run shipper; retire monitor.Report"
```

---

## Task 8: End-to-end effectively-once test

**Files:**
- Create: `internal/shipper/e2e_test.go`

- [ ] **Step 1: Write the test**

Create `internal/shipper/e2e_test.go`:

```go
package shipper

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/redactrai/redactr/internal/control"
	"github.com/redactrai/redactr/internal/enrollment"
	"github.com/redactrai/redactr/internal/server/auth"
	"github.com/redactrai/redactr/internal/server/httpapi"
	srvstore "github.com/redactrai/redactr/internal/server/store"
	clistore "github.com/redactrai/redactr/internal/store"
)

// failingPoster wraps an inner Poster and forces the first failFirst calls to
// error, simulating a transient outage / offline laptop.
type failingPoster struct {
	inner     Poster
	failFirst int
	calls     int
}

func (p *failingPoster) Post(ctx context.Context, recs []control.IngestRecord) error {
	p.calls++
	if p.calls <= p.failFirst {
		return context.DeadlineExceeded
	}
	return p.inner.Post(ctx, recs)
}

func TestEndToEndEffectivelyOnce(t *testing.T) {
	// --- real control-plane server ---
	st, err := srvstore.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ts := httptest.NewServer(httpapi.New(st, auth.NewSigner(priv), "admin-key"))
	defer ts.Close()

	// --- enroll a device to get a bearer token ---
	org, err := st.CreateOrg("Acme")
	if err != nil {
		t.Fatal(err)
	}
	raw := httpapi.NewRawToken()
	if err := st.CreateEnrollmentToken(auth.HashToken(raw), org.ID, time.Now().Add(time.Hour), 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	enrRes, err := auth.Enroll(st, auth.NewSigner(priv), auth.EnrollInput{EnrollmentToken: raw, DeviceName: "laptop", Platform: "darwin"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	// --- client side: outbox + enrollment file + shipper ---
	base := t.TempDir()
	if err := enrollment.Save(base, enrollment.Enrollment{ServerURL: ts.URL, DeviceToken: enrRes.Token, OrgID: org.ID, DeviceID: enrRes.DeviceID, ServerPublicKey: "x"}); err != nil {
		t.Fatal(err)
	}
	cs, err := clistore.New(filepath.Join(base, "data", "logs.db"))
	if err != nil {
		// data dir may not exist yet
		_ = clistore.New
		t.Fatalf("client store: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	for i := 0; i < 3; i++ {
		if err := cs.EnqueueMonitor(control.MonitorEvent{Tool: "Claude Code", Verdict: "runaway", Reason: "x", DirectConnCount: i, ObservedAt: time.Unix(int64(i), 0).UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := cs.EnqueueAudit(control.AuditRecord{Provider: "anthropic", Source: "proxy", Detector: "regex", Category: "aws_key", Action: "blocked"}); err != nil {
		t.Fatal(err)
	}
	if err := cs.EnqueueAudit(control.AuditRecord{Provider: "anthropic", Source: "proxy", Detector: "gliner", Category: "email", Action: "allowed"}); err != nil {
		t.Fatal(err)
	}

	// Poster fails the first 2 attempts (offline), then succeeds.
	poster := &failingPoster{inner: NewHTTPPoster(base), failFirst: 2}
	sh := New(cs, poster)

	// Drive the loop until the outbox drains (bounded iterations).
	ctx := context.Background()
	for i := 0; i < 20 && cs.OutboxCount() > 0; i++ {
		sh.runOnce(ctx)
	}
	if n := cs.OutboxCount(); n != 0 {
		t.Fatalf("outbox not drained: %d remaining after retries", n)
	}
	if poster.calls < 3 {
		t.Fatalf("expected retries (>=3 calls), got %d", poster.calls)
	}

	// Server holds each record exactly once despite the retries.
	if n, _ := st.CountEvents(org.ID); n != 3 {
		t.Fatalf("server events=%d want 3", n)
	}
	if n, _ := st.CountAuditRecords(org.ID); n != 2 {
		t.Fatalf("server audit records=%d want 2", n)
	}

	// A redundant manual re-post of an already-delivered batch must not duplicate.
	_ = NewHTTPPoster(base).Post(ctx, []control.IngestRecord{
		{UUID: "dup-check", Kind: control.KindMonitor, Monitor: &control.MonitorEvent{Tool: "x", ObservedAt: time.Unix(9, 0).UTC()}},
	})
	_ = NewHTTPPoster(base).Post(ctx, []control.IngestRecord{
		{UUID: "dup-check", Kind: control.KindMonitor, Monitor: &control.MonitorEvent{Tool: "x", ObservedAt: time.Unix(9, 0).UTC()}},
	})
	if n, _ := st.CountEvents(org.ID); n != 4 {
		t.Fatalf("after one new + one dup, events=%d want 4", n)
	}

	_ = json.Marshal // keep encoding/json import if unused above
}
```

> Note for the implementer: if `clistore.New` requires the `data/` directory to exist, it does not — `store.New` calls `bolt.Open` which creates the file, and `t.TempDir()/data` path's parent (`t.TempDir()`) exists; bolt creates the file but NOT missing parent dirs. If `clistore.New` fails with "no such file or directory", create the dir first with `os.MkdirAll(filepath.Join(base, "data"), 0o755)` before the call (mirroring what the daemon's `Build` does). Adjust the test accordingly and drop the stray `_ = clistore.New` line.

- [ ] **Step 2: Run the test**

Run: `go test ./internal/shipper/ -run TestEndToEndEffectivelyOnce -v`
Expected: PASS. If it fails on store creation, apply the `os.MkdirAll` fix from the note and remove the `_ = clistore.New` / `_ = json.Marshal` placeholder lines (and the unused `encoding/json` import if it ends up unused).

- [ ] **Step 3: Run the full suite**

Run: `go build ./... && go test ./...`
Expected: PASS everywhere.

- [ ] **Step 4: Commit**

```bash
git add internal/shipper/e2e_test.go
git commit -m "test(shipper): end-to-end effectively-once delivery across transient failures"
```

---

## Self-Review

**1. Spec coverage** (against `2026-06-05-subsystem-f-fleet-operations-design.md`, F1 section):
- Outbox in existing BoltDB → Task 2. ✓
- Both streams (MonitorEvent + AuditRecord, never values) → Tasks 1, 7 (`auditRecordsFromReport` strips `Original`; privacy assertion in `audit_test.go`). ✓
- UUID + monotonic per-device sequence → Task 2 (`newUUID`, `NextSequence`). ✓
- Single background sender, batch ≤500, 2xx-then-delete, exponential backoff capped ~5 min, resume on restart → Tasks 3, 4, 7. ✓
- Server `UNIQUE(uuid)` + idempotent insert → Task 5 (`ON CONFLICT(uuid) DO NOTHING`, `idx_events_uuid`, `audit_records.uuid PRIMARY KEY`). ✓
- Effectively-once (at-least-once + idempotent sink) → Task 8 E2E. ✓
- Safety valve with logged drops (no silent truncation) → Task 2 `Trim` + Task 3 logs `outbox_overflow`. ✓
- Unified `POST /v1/ingest` superseding `/v1/events` for the client → Task 6 (endpoint added) + Task 7 (client switches to it). Legacy `/v1/events` left intact by design. ✓
- Flush-on-restart → Task 2 `TestOutboxSurvivesReopen`. ✓
- Server retention sweep (365d) → **out of F1 scope by design**: retention/pruning belongs with F3 (server lifecycle/migrations). Not implemented here; noted so it is not silently dropped.

**2. Placeholder scan:** The only conditional content is the documented store-dir fix in Task 8 (real, actionable, with exact code), not a TBD. No "add error handling"-style vagueness; every code step is complete.

**3. Type consistency:** `IngestRecord{UUID,Seq,Kind,Monitor,Audit}`, `AuditRecord` fields, `KindMonitor`/`KindAudit`, and method names (`EnqueueMonitor`, `EnqueueAudit`, `Drain`→`([]control.IngestRecord, [][]byte, error)`, `Ack([][]byte)`, `Trim(int)(int,error)`, `IngestRecords`, `CountEvents`, `CountAuditRecords`, `auditRecordsFromReport`) match across Tasks 1–8 and against the real signatures read from the codebase (`store.ScanReport`, `store.Redaction`, `auth.Enroll`, `auth.HashToken`, `httpapi.New`, `httpapi.NewRawToken`). ✓

---

## Out of F1 scope (handled by later sub-projects)
- Server-side retention sweep + nightly backup → **F3**.
- Dashboard redaction-audit view + online/offline + bypass rollup over this data → **F4**.
- TLS enforcement on `enroll`/ingest endpoints → **F2/F3** (the shipper already speaks whatever scheme the enrollment URL specifies).
