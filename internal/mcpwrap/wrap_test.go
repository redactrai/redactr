package mcpwrap

import (
	"bytes"
	"testing"
)

func TestScanJSONRPCMessage(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"user email is user@secret.com"}]}}`

	scanner := &mockScanner{
		redacted: `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"user email is [REDACTED-EMAIL]"}]}}`,
	}

	result, err := ScanMessage([]byte(msg), scanner)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !bytes.Contains(result, []byte("[REDACTED-EMAIL]")) {
		t.Errorf("expected redacted output, got %s", string(result))
	}
}

func TestPassthroughWhenNoRedactrRunning(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"result":"hello"}`

	result, err := ScanMessage([]byte(msg), nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(result) != msg {
		t.Errorf("expected passthrough, got %s", string(result))
	}
}

type mockScanner struct {
	redacted string
}

func (m *mockScanner) ScanText(text string) (string, error) {
	return m.redacted, nil
}
