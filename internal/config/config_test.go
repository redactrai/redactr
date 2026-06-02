package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Proxy.Enabled {
		t.Error("expected proxy disabled by default")
	}
	if len(cfg.Proxy.InterceptedDomains) == 0 {
		t.Error("expected default intercepted domains")
	}
	if cfg.Scanning.EntropyThreshold != 4.5 {
		t.Errorf("expected entropy threshold 4.5, got %f", cfg.Scanning.EntropyThreshold)
	}
	if len(cfg.FileBlocking.BlockedExtensions) == 0 {
		t.Error("expected default blocked extensions")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("expected config file to be created on first load")
	}
}

func TestLoadExistingConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	yaml := []byte(`proxy:
  enabled: true
  intercepted_domains:
    - custom.api.com
  blocked_domains:
    - evil.com
scanning:
  regex_enabled: false
  entropy_enabled: true
  entropy_threshold: 5.0
  gliner_enabled: true
  custom_patterns: []
  custom_blocked_words: ["secret-project"]
  cache_max_size: 5000
file_blocking:
  blocked_extensions: [".env"]
  content_patterns_enabled: false
hooks:
  enabled: false
  claude_code: false
  safecmd_overrides:
    added: []
    removed: []
mcp:
  wrapped_servers: {}
`)
	os.WriteFile(path, yaml, 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if !cfg.Proxy.Enabled {
		t.Error("expected proxy enabled")
	}
	if cfg.Proxy.InterceptedDomains[0] != "custom.api.com" {
		t.Error("expected custom domain")
	}
	if cfg.Proxy.BlockedDomains[0] != "evil.com" {
		t.Error("expected blocked domain")
	}
	if cfg.Scanning.EntropyThreshold != 5.0 {
		t.Errorf("expected threshold 5.0, got %f", cfg.Scanning.EntropyThreshold)
	}
	if cfg.Scanning.CustomBlockedWords[0] != "secret-project" {
		t.Error("expected custom blocked word")
	}
}

func TestSaveConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	cfg, _ := Load(path)
	cfg.Proxy.Enabled = true
	cfg.Proxy.BlockedDomains = []string{"blocked.com"}

	err := Save(path, cfg)
	if err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload error: %v", err)
	}
	if !reloaded.Proxy.Enabled {
		t.Error("expected proxy enabled after save")
	}
	if reloaded.Proxy.BlockedDomains[0] != "blocked.com" {
		t.Error("expected blocked domain persisted")
	}
}
