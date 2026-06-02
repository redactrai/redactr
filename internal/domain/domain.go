package domain

import (
	"net"
	"strings"
	"sync"
)

type Filter struct {
	mu               sync.RWMutex
	interceptDomains map[string]bool
	blockedDomains   map[string]bool
}

func New(intercept, blocked []string) *Filter {
	f := &Filter{
		interceptDomains: make(map[string]bool),
		blockedDomains:   make(map[string]bool),
	}
	for _, d := range intercept {
		f.interceptDomains[strings.ToLower(d)] = true
	}
	for _, d := range blocked {
		f.blockedDomains[strings.ToLower(d)] = true
	}
	return f
}

func (f *Filter) ShouldIntercept(host string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.interceptDomains[stripPort(host)]
}

func (f *Filter) IsBlocked(host string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.blockedDomains[stripPort(host)]
}

func (f *Filter) SetInterceptDomains(domains []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.interceptDomains = make(map[string]bool)
	for _, d := range domains {
		f.interceptDomains[strings.ToLower(d)] = true
	}
}

func (f *Filter) SetBlockedDomains(domains []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockedDomains = make(map[string]bool)
	for _, d := range domains {
		f.blockedDomains[strings.ToLower(d)] = true
	}
}

func stripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
}
