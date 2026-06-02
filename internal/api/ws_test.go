package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/redactrai/redactr/internal/store"
)

func TestWebSocketBroadcast(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	srv := httptest.NewServer(hub.HandleWS())
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	report := &store.ScanReport{
		Timestamp: time.Now(),
		Provider:  "anthropic",
		LatencyMs: 5,
		Source:    "proxy",
	}
	hub.Broadcast(report)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	var received store.ScanReport
	if err := json.Unmarshal(msg, &received); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if received.Provider != "anthropic" {
		t.Errorf("expected anthropic, got %q", received.Provider)
	}
}
