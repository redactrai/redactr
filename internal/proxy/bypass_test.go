package proxy

import (
	"testing"

	"github.com/rakeshguha/redactr/internal/config"
)

func TestBypassMatcher(t *testing.T) {
	m := NewBypassMatcher([]config.BypassRule{
		{Path: "/v1/models"},
		{Prefix: "/.well-known/"},
		{Method: "OPTIONS"},
	})

	tests := []struct {
		method string
		path   string
		want   bool
		rule   string
	}{
		{"GET", "/v1/models", true, "exact_match"},
		{"GET", "/v1/models/gpt-4", false, ""},
		{"GET", "/.well-known/openid-configuration", true, "prefix_match"},
		{"OPTIONS", "/v1/chat/completions", true, "method_match"},
		{"POST", "/v1/chat/completions", false, ""},
		{"GET", "/health", false, ""},
	}

	for _, tt := range tests {
		matched, rule := m.Match(tt.method, tt.path)
		if matched != tt.want {
			t.Errorf("Match(%s, %s) = %v, want %v", tt.method, tt.path, matched, tt.want)
		}
		if rule != tt.rule {
			t.Errorf("Match(%s, %s) rule = %q, want %q", tt.method, tt.path, rule, tt.rule)
		}
	}
}

func TestBypassMatcherNil(t *testing.T) {
	m := NewBypassMatcher(nil)
	matched, _ := m.Match("POST", "/v1/chat/completions")
	if matched {
		t.Error("nil rules should never match")
	}
}
