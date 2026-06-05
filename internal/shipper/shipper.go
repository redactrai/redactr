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
