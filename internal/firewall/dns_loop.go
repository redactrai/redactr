package firewall

import (
	"context"
	"fmt"
	"net"
	"sort"
)

// Resolver is the DNS interface the reconciler uses. Defaulted to a
// real net.Resolver in production; mocked in tests.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// DefaultResolver is net.DefaultResolver. Exposed for callers and tests.
var DefaultResolver Resolver = net.DefaultResolver

// resolveAll resolves every host in domains, dedupes the results, and
// returns the sorted IP set. If at least one host resolves, the error
// is nil even if others failed (DNS hiccups are common). If all hosts
// fail, an error is returned.
func resolveAll(ctx context.Context, r Resolver, domains []string) ([]string, error) {
	set := make(map[string]struct{})
	failures := 0
	for _, d := range domains {
		addrs, err := r.LookupHost(ctx, d)
		if err != nil {
			failures++
			continue
		}
		for _, a := range addrs {
			set[a] = struct{}{}
		}
	}
	if failures == len(domains) && len(domains) > 0 {
		return nil, fmt.Errorf("all %d host lookups failed", failures)
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out, nil
}

// ipSetsEqual reports whether two IP slices contain the same elements
// regardless of order.
func ipSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	seen := make(map[string]int, len(a))
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
