package shipper

import (
	"context"
	"errors"
	"testing"

	"github.com/redactrai/redactr/internal/control"
)

type fakeStore struct {
	recs  []control.IngestRecord
	keys  [][]byte
	acked [][]byte
	trims int
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
