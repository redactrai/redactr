package fileblock

import (
	"testing"
)

func TestBlockByExtension(t *testing.T) {
	fb := New([]string{".env", ".tfstate", ".pem", ".key"}, true)

	tests := []struct {
		path    string
		blocked bool
	}{
		{"/app/.env", true},
		{"/infra/main.tfstate", true},
		{"/certs/server.pem", true},
		{"/certs/server.key", true},
		{"/src/main.go", false},
		{"/config/app.yaml", false},
	}

	for _, tt := range tests {
		result := fb.IsBlockedFile(tt.path)
		if result != tt.blocked {
			t.Errorf("IsBlockedFile(%q) = %v, want %v", tt.path, result, tt.blocked)
		}
	}
}

func TestBlockByContent(t *testing.T) {
	fb := New([]string{".env"}, true)

	envContent := `DB_HOST=localhost
DB_PASSWORD=supersecret
API_KEY=sk-1234567890abcdef`

	result := fb.IsBlockedContent(envContent)
	if !result {
		t.Error("expected .env-like content to be blocked")
	}

	normalCode := `func main() {
	fmt.Println("hello world")
}`
	result = fb.IsBlockedContent(normalCode)
	if result {
		t.Error("expected normal code not blocked")
	}
}

func TestRedactBlockedFile(t *testing.T) {
	fb := New([]string{".env"}, true)
	label := fb.RedactionLabel("/app/.env")
	expected := "[REDACTED-FILE-.env: .env]"
	if label != expected {
		t.Errorf("expected %q, got %q", expected, label)
	}
}

func TestContentPatternsDisabled(t *testing.T) {
	fb := New([]string{".env"}, false)
	envContent := "DB_PASSWORD=secret"
	result := fb.IsBlockedContent(envContent)
	if result {
		t.Error("expected content patterns disabled")
	}
}

func TestReconfigureUpdatesExtensions(t *testing.T) {
	fb := New([]string{".env", ".pem"}, true)
	if !fb.IsBlockedFile("/x.env") {
		t.Fatal("setup: .env should be blocked")
	}
	fb.Reconfigure([]string{".key"}, false)
	if fb.IsBlockedFile("/x.env") {
		t.Error("after reconfigure, .env should no longer block")
	}
	if !fb.IsBlockedFile("/x.key") {
		t.Error("after reconfigure, .key should block")
	}
	// Build a synthetic body that triggers the content-pattern detection
	// when content_patterns is enabled (contentThreshold matches in the file).
	envBody := "KEY=foo\nSECRET=bar\nTOKEN=baz\n"
	if fb.IsBlockedContent(envBody) {
		t.Error("content patterns should now be disabled (got true)")
	}
}
