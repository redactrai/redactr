package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStoreScanReport(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Close()

	report := &ScanReport{
		Timestamp:  time.Now(),
		Provider:   "anthropic",
		Source:     "proxy",
		LatencyMs:  12,
		Redactions: []Redaction{{Label: "[REDACTED-EMAIL]", Original: "test@example.com", Start: 10, End: 26}},
		Layers: []LayerResult{
			{Name: "regex", FindingsCount: 1, LatencyMs: 1},
			{Name: "entropy", FindingsCount: 0, LatencyMs: 0},
		},
		Blocked: false,
		Reason:  "",
	}

	id, err := s.SaveReport(report)
	if err != nil {
		t.Fatalf("SaveReport() error: %v", err)
	}
	if id == "" {
		t.Error("expected non-empty ID")
	}

	retrieved, err := s.GetReport(id)
	if err != nil {
		t.Fatalf("GetReport() error: %v", err)
	}
	if retrieved.Provider != "anthropic" {
		t.Errorf("expected provider 'anthropic', got %q", retrieved.Provider)
	}
	if len(retrieved.Redactions) != 1 {
		t.Errorf("expected 1 redaction, got %d", len(retrieved.Redactions))
	}
}

func TestQueryReports(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Close()

	now := time.Now()
	for i := 0; i < 5; i++ {
		report := &ScanReport{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Provider:  "anthropic",
			Source:    "proxy",
			LatencyMs: int64(i * 10),
			Blocked:   i%2 == 0,
		}
		s.SaveReport(report)
	}

	reports, err := s.QueryReports(QueryFilter{Limit: 3})
	if err != nil {
		t.Fatalf("QueryReports() error: %v", err)
	}
	if len(reports) != 3 {
		t.Errorf("expected 3 reports, got %d", len(reports))
	}
	if reports[0].Timestamp.Before(reports[1].Timestamp) {
		t.Error("expected newest first")
	}
}

func TestQueryReportsFilterByProvider(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Close()

	s.SaveReport(&ScanReport{Timestamp: time.Now(), Provider: "anthropic", Source: "proxy"})
	s.SaveReport(&ScanReport{Timestamp: time.Now(), Provider: "openai", Source: "proxy"})
	s.SaveReport(&ScanReport{Timestamp: time.Now(), Provider: "anthropic", Source: "mcp"})

	reports, err := s.QueryReports(QueryFilter{Provider: "anthropic", Limit: 10})
	if err != nil {
		t.Fatalf("QueryReports() error: %v", err)
	}
	if len(reports) != 2 {
		t.Errorf("expected 2 anthropic reports, got %d", len(reports))
	}
}

func TestGetStats(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Close()

	now := time.Now()
	s.SaveReport(&ScanReport{Timestamp: now, Provider: "anthropic", LatencyMs: 10, Redactions: []Redaction{{Label: "X"}}, Source: "proxy"})
	s.SaveReport(&ScanReport{Timestamp: now.Add(time.Millisecond), Provider: "openai", LatencyMs: 20, Blocked: true, Source: "proxy"})

	stats, err := s.GetStats(now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("GetStats() error: %v", err)
	}
	if stats.TotalScanned != 2 {
		t.Errorf("expected 2 total, got %d", stats.TotalScanned)
	}
	if stats.TotalRedactions != 1 {
		t.Errorf("expected 1 redaction, got %d", stats.TotalRedactions)
	}
	if stats.TotalBlocked != 1 {
		t.Errorf("expected 1 blocked, got %d", stats.TotalBlocked)
	}
}
