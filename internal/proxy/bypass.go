package proxy

import (
	"strings"
	"sync"

	"github.com/rakeshguha/redactr/internal/config"
)

type BypassMatcher struct {
	mu    sync.RWMutex
	rules []config.BypassRule
}

func NewBypassMatcher(rules []config.BypassRule) *BypassMatcher {
	return &BypassMatcher{rules: rules}
}

func (b *BypassMatcher) SetRules(rules []config.BypassRule) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rules = rules
}

func (b *BypassMatcher) Match(method, path string) (bool, string) {
	b.mu.RLock()
	rules := b.rules
	b.mu.RUnlock()

	for _, r := range rules {
		if r.Method != "" && strings.EqualFold(r.Method, method) {
			return true, "method_match"
		}
		if r.Path != "" && r.Path == path {
			return true, "exact_match"
		}
		if r.Prefix != "" && strings.HasPrefix(path, r.Prefix) {
			return true, "prefix_match"
		}
	}
	return false, ""
}
