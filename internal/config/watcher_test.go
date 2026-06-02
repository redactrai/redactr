package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcherReloadsOnFileChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	mgr, err := NewManager(path)
	if err != nil {
		t.Fatal(err)
	}

	cfg := mgr.Get()
	if cfg.Scanning.InferenceTimeoutMs != 5000 {
		t.Fatalf("default timeout = %d, want 5000", cfg.Scanning.InferenceTimeoutMs)
	}

	reloaded := make(chan *Config, 1)
	w := NewWatcher(mgr, func(c *Config) {
		reloaded <- c
	})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	data, _ := os.ReadFile(path)
	modified := []byte("scanning:\n  inference_timeout_ms: 9999\n  entropy_threshold: 4.5\n  cache_max_size: 10000\n")
	_ = data
	os.WriteFile(path, modified, 0644)

	select {
	case newCfg := <-reloaded:
		if newCfg.Scanning.InferenceTimeoutMs != 9999 {
			t.Errorf("timeout = %d, want 9999", newCfg.Scanning.InferenceTimeoutMs)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for config reload")
	}
}

func TestWatcherReloadBadYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	mgr, err := NewManager(path)
	if err != nil {
		t.Fatal(err)
	}

	oldTimeout := mgr.Get().Scanning.InferenceTimeoutMs

	reloaded := make(chan *Config, 1)
	w := NewWatcher(mgr, func(c *Config) {
		reloaded <- c
	})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	os.WriteFile(path, []byte("{{{{ invalid yaml"), 0644)

	// Bad YAML should NOT trigger onLoad
	select {
	case <-reloaded:
		t.Fatal("should not have called onLoad for bad YAML")
	case <-time.After(500 * time.Millisecond):
		// expected
	}

	// Config should remain unchanged
	if mgr.Get().Scanning.InferenceTimeoutMs != oldTimeout {
		t.Error("config should be unchanged after bad YAML reload")
	}
}
