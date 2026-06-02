package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/redactrai/redactr/internal/config"
	"github.com/redactrai/redactr/internal/store"
)

func setupTestAPI(t *testing.T) (*Server, *config.Manager, *store.Store) {
	dir := t.TempDir()
	cfgMgr, err := config.NewManager(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.New(filepath.Join(dir, "logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(cfgMgr, st, nil, nil, nil)
	return srv, cfgMgr, st
}

func TestGetConfig(t *testing.T) {
	srv, _, _ := setupTestAPI(t)
	req := httptest.NewRequest("GET", "/api/config", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var cfg config.Config
	json.NewDecoder(w.Body).Decode(&cfg)
	if len(cfg.Proxy.InterceptedDomains) == 0 {
		t.Error("expected default intercepted domains")
	}
}

func TestUpdateConfig(t *testing.T) {
	srv, cfgMgr, _ := setupTestAPI(t)

	body := `{"proxy":{"enabled":true,"intercepted_domains":["custom.com"],"blocked_domains":[]},"scanning":{"regex_enabled":true,"entropy_enabled":true,"entropy_threshold":5.0,"gliner_enabled":true,"custom_patterns":[],"custom_blocked_words":[],"cache_max_size":5000},"file_blocking":{"blocked_extensions":[".env"],"content_patterns_enabled":true},"hooks":{"enabled":false,"claude_code":false,"safecmd_overrides":{"added":[],"removed":[]}},"mcp":{"wrapped_servers":{}}}`

	req := httptest.NewRequest("PUT", "/api/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated := cfgMgr.Get()
	if !updated.Proxy.Enabled {
		t.Error("expected proxy enabled after update")
	}
}

func TestGetLogs(t *testing.T) {
	srv, _, st := setupTestAPI(t)

	st.SaveReport(&store.ScanReport{
		Timestamp: time.Now(),
		Provider:  "anthropic",
		Source:    "proxy",
		LatencyMs: 10,
	})

	req := httptest.NewRequest("GET", "/api/logs?limit=10", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var logs []store.ScanReport
	json.NewDecoder(w.Body).Decode(&logs)
	if len(logs) != 1 {
		t.Errorf("expected 1 log, got %d", len(logs))
	}
}

func TestGetStats(t *testing.T) {
	srv, _, st := setupTestAPI(t)

	st.SaveReport(&store.ScanReport{
		Timestamp: time.Now(),
		Provider:  "anthropic",
		LatencyMs: 10,
		Source:    "proxy",
	})

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var stats store.Stats
	json.NewDecoder(w.Body).Decode(&stats)
	if stats.TotalScanned != 1 {
		t.Errorf("expected 1 total, got %d", stats.TotalScanned)
	}
}

func TestProxyToggle(t *testing.T) {
	srv, _, _ := setupTestAPI(t)

	req := httptest.NewRequest("POST", "/api/proxy/enable", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
