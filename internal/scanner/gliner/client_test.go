package gliner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGLiNERClientScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/detect" {
			t.Errorf("expected /detect path, got %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		var req DetectRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Text == "" {
			t.Error("expected non-empty text")
		}

		resp := DetectResponse{
			Entities: []Entity{
				{Text: "John Smith", Label: "PERSON", Start: 0, End: 10, Score: 0.95},
				{Text: "123 Main St", Label: "ADDRESS", Start: 20, End: 31, Score: 0.88},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL, WithMinConfidence(0.5), WithSuppressLabels(nil))
	client.SetReady(true)

	result, err := client.Scan("John Smith lives at 123 Main St in Springfield")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "PERSON" {
		t.Errorf("expected PERSON, got %q", result.Findings[0].Label)
	}
	if result.Findings[1].Label != "ADDRESS" {
		t.Errorf("expected ADDRESS, got %q", result.Findings[1].Label)
	}
}

func TestGLiNERNotReady(t *testing.T) {
	client := New("http://localhost:99999", WithMinConfidence(0.5))

	if client.Ready() {
		t.Error("expected not ready")
	}

	result, err := client.Scan("some text")
	if err != nil {
		t.Fatalf("expected no error when not ready, got %v", err)
	}
	if len(result.Findings) != 0 {
		t.Error("expected no findings when not ready")
	}
}

func TestGLiNERFiltering(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := DetectResponse{
			Entities: []Entity{
				{Text: "John Smith", Label: "PERSON", Start: 0, End: 10, Score: 0.95},
				{Text: "Acme Corp", Label: "ORGANIZATION", Start: 20, End: 29, Score: 0.90},
				{Text: "J", Label: "PERSON", Start: 40, End: 41, Score: 0.80},
				{Text: "maybe pii", Label: "PERSON", Start: 50, End: 59, Score: 0.55},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL, WithMinConfidence(0.7), WithMinLength(2))
	client.SetReady(true)

	result, err := client.Scan("test text")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding (only high-confidence, non-org, long enough), got %d", len(result.Findings))
	}
	if result.Findings[0].Value != "John Smith" {
		t.Errorf("expected 'John Smith', got %q", result.Findings[0].Value)
	}
}

func TestGLiNERHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
			return
		}
	}))
	defer server.Close()

	client := New(server.URL)
	ok := client.HealthCheck()
	if !ok {
		t.Error("expected health check to pass")
	}
}

func TestPersonThresholdIs080(t *testing.T) {
	c := New("http://127.0.0.1:0")
	if v := c.labelMinConfidence["PERSON"]; v != 0.80 {
		t.Errorf("expected PERSON min confidence 0.80, got %v", v)
	}
}

func TestSetEnabledLabels(t *testing.T) {
	c := New("http://127.0.0.1:0")
	// Disable PERSON and EMAIL; keep ADDRESS as-is.
	c.SetEnabled(map[string]bool{"PERSON": false, "EMAIL": true})

	suppressLabels := c.state.Load().suppressLabels
	if !suppressLabels["PERSON"] {
		t.Error("PERSON should be suppressed when disabled")
	}
	if suppressLabels["EMAIL"] {
		t.Error("EMAIL should not be suppressed when enabled")
	}
}

func TestReconfigureMapsRuleIDsToLabels(t *testing.T) {
	c := New("http://127.0.0.1:0")
	disabled := map[string]bool{
		"email_gliner":           false,
		"person_gliner":          false,
		"ip_gliner":              true,
		"address_gliner":         true,
		"dob_gliner":             true,
		"gliner_national_id_dup": false,
	}
	c.Reconfigure(func(id string) bool { return disabled[id] })

	suppressLabels := c.state.Load().suppressLabels
	for label, on := range map[string]bool{
		"EMAIL":         false,
		"PERSON":        false,
		"NATIONAL_ID":   false,
		"IP_ADDRESS":    true,
		"ADDRESS":       true,
		"DATE_OF_BIRTH": true,
	} {
		if on && suppressLabels[label] {
			t.Errorf("%s should NOT be suppressed (enabled)", label)
		}
		if !on && !suppressLabels[label] {
			t.Errorf("%s should be suppressed (disabled)", label)
		}
	}
}
