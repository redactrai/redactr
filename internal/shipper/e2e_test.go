package shipper

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http/httptest"
	"os"
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

// failingPoster forces the first failFirst Post calls to error, simulating a
// transient outage / offline laptop, then delegates to the real poster.
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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(httpapi.New(st, auth.NewSigner(priv), httpapi.AuthConfig{SessionTTL: time.Hour, MaxBodyBytes: 1 << 20}, nil))
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
	if err := os.MkdirAll(filepath.Join(base, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	cs, err := clistore.New(filepath.Join(base, "data", "logs.db"))
	if err != nil {
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

	if n, _ := st.CountEvents(org.ID); n != 3 {
		t.Fatalf("server events=%d want 3", n)
	}
	if n, _ := st.CountAuditRecords(org.ID); n != 2 {
		t.Fatalf("server audit records=%d want 2", n)
	}

	// A redundant re-post of an already-delivered UUID must not duplicate; a new
	// UUID must insert. Net: exactly one new event row.
	dup := []control.IngestRecord{{UUID: "dup-check", Kind: control.KindMonitor, Monitor: &control.MonitorEvent{Tool: "x", ObservedAt: time.Unix(9, 0).UTC()}}}
	if err := NewHTTPPoster(base).Post(ctx, dup); err != nil {
		t.Fatal(err)
	}
	if err := NewHTTPPoster(base).Post(ctx, dup); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountEvents(org.ID); n != 4 {
		t.Fatalf("after one new + one dup, events=%d want 4", n)
	}
}

// TestOutboxResumesAfterRestart proves the durability guarantee end to end:
// records enqueued before a "crash" (store close) survive, and a fresh Shipper
// on the reopened DB drains them to the server exactly once.
func TestOutboxResumesAfterRestart(t *testing.T) {
	st, err := srvstore.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(httpapi.New(st, auth.NewSigner(priv), httpapi.AuthConfig{SessionTTL: time.Hour, MaxBodyBytes: 1 << 20}, nil))
	defer ts.Close()

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

	base := t.TempDir()
	if err := enrollment.Save(base, enrollment.Enrollment{ServerURL: ts.URL, DeviceToken: enrRes.Token, OrgID: org.ID, DeviceID: enrRes.DeviceID, ServerPublicKey: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(base, "data", "logs.db")

	// Phase 1: enqueue, then simulate a crash by closing the store before any delivery.
	cs1, err := clistore.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := cs1.EnqueueMonitor(control.MonitorEvent{Tool: "Claude Code", Verdict: "runaway", DirectConnCount: i, ObservedAt: time.Unix(int64(i), 0).UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if n := cs1.OutboxCount(); n != 3 {
		t.Fatalf("pre-crash outbox=%d want 3", n)
	}
	cs1.Close()

	// Phase 2: restart — reopen the SAME db and ship.
	cs2, err := clistore.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs2.Close() })
	if n := cs2.OutboxCount(); n != 3 {
		t.Fatalf("records did not survive restart: outbox=%d want 3", n)
	}
	sh := New(cs2, NewHTTPPoster(base))
	ctx := context.Background()
	for i := 0; i < 20 && cs2.OutboxCount() > 0; i++ {
		sh.runOnce(ctx)
	}
	if n := cs2.OutboxCount(); n != 0 {
		t.Fatalf("outbox not drained after restart: %d", n)
	}
	if n, _ := st.CountEvents(org.ID); n != 3 {
		t.Fatalf("server events=%d want 3", n)
	}
}
