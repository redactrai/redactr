package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeLayer struct {
	name  string
	ready bool
}

func (f *fakeLayer) Name() string { return f.name }
func (f *fakeLayer) Ready() bool  { return f.ready }

func TestHealthAllReady(t *testing.T) {
	s := NewServer([]LayerChecker{
		&fakeLayer{"presidio", true},
		&fakeLayer{"gliner", true},
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", resp["status"])
	}
}

func TestHealthDegraded(t *testing.T) {
	s := NewServer([]LayerChecker{
		&fakeLayer{"presidio", true},
		&fakeLayer{"gliner", false},
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "degraded" {
		t.Errorf("status = %v, want degraded", resp["status"])
	}
	models := resp["models"].(map[string]interface{})
	if models["gliner"] != "not ready" {
		t.Errorf("gliner = %v, want 'not ready'", models["gliner"])
	}
}

func TestMetricsEndpoint(t *testing.T) {
	s := NewServer(nil)
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct == "" {
		t.Error("expected Content-Type header on /metrics")
	}
}
