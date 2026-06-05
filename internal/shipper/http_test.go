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
