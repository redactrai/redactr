package cli

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/redactrai/redactr/internal/control"
)

// socketTempDir returns a temp dir whose path is short enough that unix sockets
// created within it stay under the macOS 104-byte sun_path limit. The default
// $TMPDIR on macOS (/var/folders/...) is long enough that longer test names
// push the socket path past that limit; rooting under /tmp keeps it short.
// Falls back to t.TempDir() where /tmp is unavailable (e.g. Windows).
func socketTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rdtr")
	if err != nil {
		return t.TempDir()
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// serveFakeSocket spins up a UDS server returning canned control responses.
func serveFakeSocket(t *testing.T, dir string) string {
	t.Helper()
	sock := filepath.Join(dir, "redactr.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(control.Status{Proxy: control.ProxyStatus{Enabled: true, Addr: "127.0.0.1:47474"}})
	})
	mux.HandleFunc("POST /proxy/enable", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(control.Status{Proxy: control.ProxyStatus{Enabled: true, Addr: "127.0.0.1:47474"}})
	})
	mux.HandleFunc("GET /launch-policy", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(control.LaunchInfo{Image: "redactr-base:local", MountMode: "bind", ProxyAddr: "127.0.0.1:47474"})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func TestClientStatusAndPolicy(t *testing.T) {
	dir := socketTempDir(t)
	serveFakeSocket(t, dir)
	c := NewClient(dir)

	st, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Proxy.Enabled || st.Proxy.Addr != "127.0.0.1:47474" {
		t.Errorf("status = %+v", st)
	}

	li, err := c.LaunchPolicy("claude")
	if err != nil {
		t.Fatalf("LaunchPolicy: %v", err)
	}
	if li.Image != "redactr-base:local" {
		t.Errorf("launch image = %q", li.Image)
	}
}

func TestEnableProxyPropagates502(t *testing.T) {
	dir := socketTempDir(t)
	sock := filepath.Join(dir, "redactr.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /proxy/enable", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "dashboard /api/proxy/enable returned 500", http.StatusBadGateway)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	c := NewClient(dir)
	if _, err := c.EnableProxy(); err == nil {
		t.Fatal("expected EnableProxy to return an error on 502")
	}
}

func TestEnsureDaemonSpawnsWhenDown(t *testing.T) {
	dir := socketTempDir(t)
	spawned := false
	err := ensureDaemon(dir, func() error {
		spawned = true
		serveFakeSocket(t, dir)
		return nil
	})
	if err != nil {
		t.Fatalf("ensureDaemon: %v", err)
	}
	if !spawned {
		t.Error("expected spawn to be called when socket absent")
	}
}
