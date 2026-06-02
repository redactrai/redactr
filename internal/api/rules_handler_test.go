package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rakeshguha/redactr/internal/config"
	"github.com/rakeshguha/redactr/internal/store"
)

func newTestServer(t *testing.T) (*Server, func()) {
	t.Helper()
	dir := t.TempDir()
	cfgMgr, err := config.NewManager(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	st, err := store.New(filepath.Join(dir, "logs.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	srv := NewServer(cfgMgr, st, nil, nil, nil)
	cleanup := func() { st.Close() }
	return srv, cleanup
}

func TestGetRulesReturnsCatalogue(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Tiers  []map[string]any `json:"tiers"`
		Groups []map[string]any `json:"groups"`
		Rules  []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if len(resp.Tiers) != 3 {
		t.Errorf("expected 3 tiers, got %d", len(resp.Tiers))
	}
	if len(resp.Groups) != 37 {
		t.Errorf("expected 37 groups, got %d", len(resp.Groups))
	}
	if len(resp.Rules) != 85 {
		t.Errorf("expected 85 rules, got %d", len(resp.Rules))
	}
}

func TestGetRulesEnabledReflectsConfig(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	srv.cfgMgr.Update(func(c *config.Config) {
		c.Scanning.Rules = map[string]bool{"aws_access_key": false}
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	srv.Handler().ServeHTTP(rec, req)

	var resp struct {
		Rules []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
			Default bool   `json:"default"`
			Tier    string `json:"tier"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, r := range resp.Rules {
		if r.ID == "aws_access_key" {
			if r.Enabled {
				t.Error("aws_access_key should be disabled per config override")
			}
			if !r.Default {
				t.Error("aws_access_key default should be true")
			}
			if r.Tier != "always_on" {
				t.Errorf("expected tier always_on, got %q", r.Tier)
			}
			return
		}
	}
	t.Fatal("aws_access_key not found in response")
}

func TestGetRulesIncludesTierMetadata(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	srv.Handler().ServeHTTP(rec, req)

	var resp struct {
		Tiers []struct {
			ID           string `json:"id"`
			Label        string `json:"label"`
			Default      bool   `json:"default"`
			WarningLevel string `json:"warning_level"`
		} `json:"tiers"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	want := map[string]struct {
		Label        string
		Default      bool
		WarningLevel string
	}{
		"always_on":    {"Always On", true, "modal_and_banner"},
		"good_to_have": {"Good to Have", true, "inline_confirm"},
		"to_be_safer":  {"To Be Safer", false, "silent"},
	}
	for _, tier := range resp.Tiers {
		w, ok := want[tier.ID]
		if !ok {
			t.Errorf("unexpected tier id %q", tier.ID)
			continue
		}
		if tier.Label != w.Label || tier.Default != w.Default || tier.WarningLevel != w.WarningLevel {
			t.Errorf("tier %q mismatch: got %+v want %+v", tier.ID, tier, w)
		}
	}
}

func TestPutRulesRejectsUnknownIDs(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	body := `{"rules":{"aws_access_key":false,"definitely_not_a_rule":true}}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Fatalf("expected 400 for unknown rule id, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "definitely_not_a_rule") {
		t.Errorf("response body should name the bad id; got %s", rec.Body.String())
	}
	// Atomicity: the known good rule must NOT have been persisted.
	cfg := srv.cfgMgr.Get()
	if cfg.Scanning.Rules != nil {
		if _, ok := cfg.Scanning.Rules["aws_access_key"]; ok {
			t.Error("aws_access_key must not be persisted when request is rejected")
		}
	}
}

func TestPutRulesNormalisesAndPersists(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	body := `{"rules":{"aws_access_key":false,"ipv4":true,"email_regex":true}}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	saved := srv.cfgMgr.Get().Scanning.Rules
	if v, ok := saved["aws_access_key"]; !ok || v {
		t.Errorf("aws_access_key should be false in saved; got %v ok=%v", v, ok)
	}
	if v, ok := saved["ipv4"]; !ok || !v {
		t.Errorf("ipv4 should be true in saved; got %v ok=%v", v, ok)
	}
	// email_regex matches Tier 2 default true → should be normalised away.
	if _, ok := saved["email_regex"]; ok {
		t.Errorf("email_regex matches default — should be normalised away; got %v", saved["email_regex"])
	}
}

func TestPutRulesEmptyBodyOK(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	body := `{"rules":{}}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200 for empty body, got %d", rec.Code)
	}
}

func TestPutRulesInvalidJSON(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/rules", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
