package domain

import (
	"testing"
)

func TestShouldIntercept(t *testing.T) {
	f := New(
		[]string{"api.anthropic.com", "api.openai.com"},
		[]string{},
	)

	tests := []struct {
		host   string
		expect bool
	}{
		{"api.anthropic.com", true},
		{"api.anthropic.com:443", true},
		{"api.openai.com", true},
		{"google.com", false},
		{"example.com", false},
	}

	for _, tt := range tests {
		got := f.ShouldIntercept(tt.host)
		if got != tt.expect {
			t.Errorf("ShouldIntercept(%q) = %v, want %v", tt.host, got, tt.expect)
		}
	}
}

func TestIsBlocked(t *testing.T) {
	f := New(
		[]string{"api.anthropic.com"},
		[]string{"evil.com", "exfil.io"},
	)

	if !f.IsBlocked("evil.com") {
		t.Error("expected evil.com blocked")
	}
	if !f.IsBlocked("exfil.io:443") {
		t.Error("expected exfil.io blocked")
	}
	if f.IsBlocked("google.com") {
		t.Error("expected google.com not blocked")
	}
}

func TestUpdateDomains(t *testing.T) {
	f := New([]string{"api.anthropic.com"}, []string{})

	if f.ShouldIntercept("api.openai.com") {
		t.Error("should not intercept before update")
	}

	f.SetInterceptDomains([]string{"api.anthropic.com", "api.openai.com"})

	if !f.ShouldIntercept("api.openai.com") {
		t.Error("should intercept after update")
	}
}
