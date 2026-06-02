package firewall

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestStateRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "firewall.json")
	now := time.Date(2026, 4, 30, 12, 34, 56, 0, time.UTC)
	in := State{
		Active:          true,
		ProxyAddr:       "127.0.0.1:58600",
		TransparentAddr: "127.0.0.1:58601",
		IPs:             []string{"1.2.3.4", "5.6.7.8"},
		LastReconciled:  now,
		CAInstalled:     true,
	}
	if err := SaveState(path, in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := LoadState(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Errorf("roundtrip mismatch:\nin:  %+v\nout: %+v", in, out)
	}
}

func TestLoadStateMissingFileReturnsZero(t *testing.T) {
	out, err := LoadState("/nonexistent/path.json")
	if err != nil {
		t.Errorf("expected nil error for missing file, got %v", err)
	}
	if out.Active {
		t.Error("missing file should produce zero State (Active=false)")
	}
}

func TestSaveStateCreatesDirIfMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "subdir", "firewall.json")
	if err := SaveState(path, State{Active: true}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file should exist: %v", err)
	}
}
