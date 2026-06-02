package sidecar

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFindFreePort(t *testing.T) {
	port, err := FindFreePort()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if port == 0 {
		t.Error("expected non-zero port")
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("port %d not actually free: %v", port, err)
	}
	l.Close()
}

func TestManagerHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ready"}`))
	}))
	defer server.Close()

	m := &Manager{sidecarURL: server.URL}
	if !m.isHealthy() {
		t.Error("expected healthy")
	}
}

func TestManagerHealthCheckFail(t *testing.T) {
	m := &Manager{sidecarURL: "http://localhost:1"}
	if m.isHealthy() {
		t.Error("expected unhealthy")
	}
}
