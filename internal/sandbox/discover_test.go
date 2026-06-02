package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscover(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "certs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "state", "proxy.pid"), []byte("0.0.0.0:47474\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "certs", "ca.crt"), []byte("PEM"), 0o644); err != nil {
		t.Fatal(err)
	}

	addr, ca, err := Discover(base)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "127.0.0.1:47474" { // normalized from 0.0.0.0
		t.Errorf("addr = %q, want 127.0.0.1:47474", addr)
	}
	if ca != filepath.Join(base, "certs", "ca.crt") {
		t.Errorf("ca = %q", ca)
	}
}

func TestDiscoverProxyDown(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "certs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "certs", "ca.crt"), []byte("PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Discover(base); err == nil {
		t.Fatal("expected error when proxy.pid missing")
	}
}
