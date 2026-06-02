package api

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/redactrai/redactr/internal/config"
	"github.com/redactrai/redactr/internal/sessions"
	"github.com/redactrai/redactr/internal/store"
)

// stateDir returns the directory where redactr writes runtime state files.
func stateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".redactr", "state")
}

func writeProxyState(addr string) {
	dir := stateDir()
	if dir == "" {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "proxy.pid"), []byte(addr), 0o644)
}

func clearProxyState() {
	dir := stateDir()
	if dir == "" {
		return
	}
	_ = os.Remove(filepath.Join(dir, "proxy.pid"))
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /api/config", s.handleGetConfig)
	s.mux.HandleFunc("PUT /api/config", s.handleUpdateConfig)
	s.mux.HandleFunc("GET /api/logs", s.handleGetLogs)
	s.mux.HandleFunc("GET /api/stats", s.handleGetStats)
	s.mux.HandleFunc("POST /api/proxy/enable", s.handleProxyEnable)
	s.mux.HandleFunc("POST /api/proxy/disable", s.handleProxyDisable)
	s.mux.HandleFunc("GET /api/proxy/status", s.handleProxyStatus)
	s.mux.HandleFunc("GET /api/cache/stats", s.handleCacheStats)
	s.mux.HandleFunc("POST /api/cache/clear", s.handleCacheClear)
	s.mux.HandleFunc("POST /api/scan", s.handleScan)
	s.mux.HandleFunc("GET /api/sessions", s.handleListSessions)
	s.mux.HandleFunc("POST /api/sessions/{pid}/stop", s.handleStopSession)
	s.mux.HandleFunc("POST /api/shell/launch", s.handleLaunchShell)
	s.mux.HandleFunc("GET /api/rules", s.handleGetRules)
	s.mux.HandleFunc("PUT /api/rules", s.handlePutRules)
	s.mux.HandleFunc("GET /api/license", s.handleGetLicense)
	if s.hub != nil {
		s.mux.HandleFunc("/api/ws", s.hub.HandleWS())
	}
	s.mux.Handle("/", staticHandler())
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.cfgMgr.Get())
}

func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var cfg config.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err := s.cfgMgr.Update(func(c *config.Config) {
		*c = cfg
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			limit = n
		}
	}
	provider := r.URL.Query().Get("provider")

	reports, err := s.store.QueryReports(store.QueryFilter{
		Provider: provider,
		Limit:    limit,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, reports)
}

func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-24 * time.Hour)
	until := time.Now()

	stats, err := s.store.GetStats(since, until)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, stats)
}

func (s *Server) handleProxyEnable(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		slog.Warn("api: proxy enable requested but proxy controller not configured")
		writeJSON(w, map[string]string{"status": "ok", "message": "proxy controller not configured"})
		return
	}
	addr, err := s.proxy.Start(0)
	if err != nil {
		slog.Error("api: proxy listener start failed", "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.cfgMgr.Update(func(c *config.Config) { c.Proxy.Enabled = true })
	writeProxyState(addr)
	slog.Info("api: proxy listener started", "addr", addr)

	// Install firewall redirect rules. If this fails (e.g. user cancels
	// the sudo prompt), keep the listener up and surface a "listening"
	// state to the dashboard.
	if s.firewall != nil {
		s.mu.Lock()
		transparentAddr := s.transparentAddr
		s.mu.Unlock()
		port := portFromAddr(transparentAddr)
		cfg := s.cfgMgr.Get()
		if err := s.firewall.Enable(r.Context(), cfg.Proxy.InterceptedDomains, addr, port); err != nil {
			slog.Error("api: firewall enable failed — proxy will be in 'listening' state",
				"error", err,
				"transparent_port", port,
				"intercepted_domains", cfg.Proxy.InterceptedDomains)
			writeJSON(w, map[string]any{
				"status":  "listening",
				"addr":    addr,
				"routing": "failed",
				"reason":  err.Error(),
			})
			return
		}
		slog.Info("api: proxy enabled with routing")
	} else {
		slog.Warn("api: proxy enabled but firewall controller is nil — routing not installed")
	}
	writeJSON(w, map[string]any{"status": "ok", "addr": addr, "routing": "active"})
}

func (s *Server) handleProxyDisable(w http.ResponseWriter, r *http.Request) {
	slog.Info("api: proxy disable requested")
	if s.firewall != nil {
		if err := s.firewall.Disable(); err != nil {
			slog.Error("api: firewall disable failed", "error", err)
		}
	}
	if s.proxy != nil {
		s.proxy.Stop()
	}
	s.cfgMgr.Update(func(c *config.Config) { c.Proxy.Enabled = false })
	clearProxyState()
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgMgr.Get()
	status := map[string]any{
		"enabled": cfg.Proxy.Enabled,
	}
	if s.proxy != nil {
		status["addr"] = s.proxy.Addr()
	}
	if s.firewall != nil {
		status["routing"] = s.firewall.IsActive()
	}
	writeJSON(w, status)
}

func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if s.coordinator == nil {
		writeJSON(w, map[string]string{"status": "no coordinator"})
		return
	}
	writeJSON(w, s.coordinator.CacheStats())
}

func (s *Server) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	if s.coordinator != nil {
		s.coordinator.InvalidateCache()
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if s.coordinator == nil {
		http.Error(w, "no coordinator", http.StatusInternalServerError)
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	start := time.Now()
	redacted, report, err := s.coordinator.ScanAndRedact(req.Text)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	scanReport := &store.ScanReport{
		Timestamp: time.Now(),
		Provider:  "api",
		Source:    "scan",
		LatencyMs: time.Since(start).Milliseconds(),
	}
	for _, f := range report.Findings {
		scanReport.Redactions = append(scanReport.Redactions, store.Redaction{
			Label:    f.Label,
			Original: f.Value,
			Start:    f.Start,
			End:      f.End,
			Layer:    f.Layer,
		})
	}
	for _, lr := range report.LayerResults {
		scanReport.Layers = append(scanReport.Layers, store.LayerResult{
			Name:          lr.Name,
			FindingsCount: lr.FindingsCount,
			LatencyMs:     lr.LatencyMs,
		})
	}
	s.store.SaveReport(scanReport)
	if s.hub != nil {
		s.hub.Broadcast(scanReport)
	}

	writeJSON(w, map[string]interface{}{
		"original": req.Text,
		"redacted": redacted,
		"findings": report.Findings,
	})
}

func (s *Server) handleGetLicense(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	lic := s.license
	s.mu.Unlock()

	if lic == nil {
		writeJSON(w, map[string]interface{}{
			"valid":    false,
			"tier":     "free",
			"features": []string{},
		})
		return
	}

	claims := lic.GetClaims()
	if claims == nil {
		writeJSON(w, map[string]interface{}{
			"valid":    false,
			"tier":     "free",
			"features": []string{},
		})
		return
	}

	tier := "paid"
	if claims.Demo {
		tier = "demo"
	}
	writeJSON(w, map[string]interface{}{
		"valid":    lic.Valid(),
		"tier":     tier,
		"customer": claims.Sub,
		"features": claims.Features,
		"expires":  claims.ExpiresAt,
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// portFromAddr extracts the port from a "host:port" string. Returns 0
// on parse failure.
func portFromAddr(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return n
}

// ---- Sessions ----

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	lister := s.sessions
	s.mu.Unlock()

	resp := map[string]interface{}{
		"supported": sessions.PlatformSupported(),
	}
	if lister == nil || !sessions.PlatformSupported() {
		resp["sessions"] = []interface{}{}
		resp["proxy_addr"] = ""
		resp["note"] = "Session discovery is currently macOS-only."
		writeJSON(w, resp)
		return
	}

	if s.proxy != nil {
		lister.SetProxyAddr(s.proxy.Addr())
	}

	list, err := lister.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session scan failed: "+err.Error())
		return
	}
	resp["sessions"] = list
	resp["proxy_addr"] = lister.ProxyAddr()
	writeJSON(w, resp)
}

func (s *Server) handleStopSession(w http.ResponseWriter, r *http.Request) {
	pidStr := r.PathValue("pid")
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 1 {
		writeError(w, http.StatusBadRequest, "invalid pid")
		return
	}
	if err := sessions.Stop(pid); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "pid": pid})
}

func (s *Server) handleLaunchShell(w http.ResponseWriter, r *http.Request) {
	if !sessions.PlatformSupported() {
		writeError(w, http.StatusNotImplemented, "launching a protected shell from the dashboard is currently macOS-only — run `redactr shell` in a terminal instead")
		return
	}
	s.mu.Lock()
	bin := s.redactrBinary
	s.mu.Unlock()
	if bin == "" {
		writeError(w, http.StatusInternalServerError, "redactr binary path is not configured")
		return
	}
	if err := sessions.LaunchProtectedShell(bin); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true})
}
