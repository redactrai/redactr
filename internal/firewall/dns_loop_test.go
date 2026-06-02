package firewall

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
)

type fakeResolver struct {
	results map[string][]string
	errors  map[string]error
	calls   int
}

func (r *fakeResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	r.calls++
	if err, ok := r.errors[host]; ok {
		return nil, err
	}
	return r.results[host], nil
}

func TestResolveAllSuccess(t *testing.T) {
	r := &fakeResolver{results: map[string][]string{
		"api.anthropic.com": {"1.1.1.1", "2.2.2.2"},
		"api.openai.com":    {"3.3.3.3"},
	}}
	ips, err := resolveAll(context.Background(), r, []string{"api.anthropic.com", "api.openai.com"})
	if err != nil {
		t.Fatalf("resolveAll: %v", err)
	}
	sort.Strings(ips)
	want := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	if !reflect.DeepEqual(ips, want) {
		t.Errorf("got %v want %v", ips, want)
	}
}

func TestResolveAllPartialFailure(t *testing.T) {
	r := &fakeResolver{
		results: map[string][]string{"api.openai.com": {"3.3.3.3"}},
		errors:  map[string]error{"api.anthropic.com": errors.New("nxdomain")},
	}
	ips, err := resolveAll(context.Background(), r, []string{"api.anthropic.com", "api.openai.com"})
	if err != nil {
		t.Fatalf("resolveAll should not fail when some hosts succeed: %v", err)
	}
	sort.Strings(ips)
	want := []string{"3.3.3.3"}
	if !reflect.DeepEqual(ips, want) {
		t.Errorf("got %v want %v", ips, want)
	}
}

func TestResolveAllAllFail(t *testing.T) {
	r := &fakeResolver{errors: map[string]error{
		"a": errors.New("fail"),
		"b": errors.New("fail"),
	}}
	_, err := resolveAll(context.Background(), r, []string{"a", "b"})
	if err == nil {
		t.Error("resolveAll should return error when all hosts fail")
	}
}

func TestResolveAllDedupes(t *testing.T) {
	r := &fakeResolver{results: map[string][]string{
		"api.anthropic.com": {"1.1.1.1", "2.2.2.2"},
		"api.openai.com":    {"2.2.2.2", "3.3.3.3"},
	}}
	ips, _ := resolveAll(context.Background(), r, []string{"api.anthropic.com", "api.openai.com"})
	if len(ips) != 3 {
		t.Errorf("expected 3 deduped IPs, got %d: %v", len(ips), ips)
	}
}

func TestIPSetsEqual(t *testing.T) {
	if !ipSetsEqual([]string{"1", "2"}, []string{"2", "1"}) {
		t.Error("order should not matter")
	}
	if ipSetsEqual([]string{"1", "2"}, []string{"1", "2", "3"}) {
		t.Error("different lengths should be unequal")
	}
	if ipSetsEqual([]string{"1"}, []string{"2"}) {
		t.Error("different elements should be unequal")
	}
	if !ipSetsEqual(nil, nil) {
		t.Error("two nil slices should be equal")
	}
}
