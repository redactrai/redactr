package firewall

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
)

type fakeMgr struct {
	redirectCalls   atomic.Int64
	unredirectCalls atomic.Int64
	lastIPs         []string
	lastPort        int
	failNext        error
	active          atomic.Bool
}

func (f *fakeMgr) BlockDirect(_ []string, _ int) error { return nil }
func (f *fakeMgr) Unblock() error                      { return nil }
func (f *fakeMgr) Status() ([]Rule, error)             { return nil, nil }
func (f *fakeMgr) Cleanup() error                      { return nil }
func (f *fakeMgr) Redirect(ips []string, port int) error {
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}
	f.redirectCalls.Add(1)
	f.lastIPs = append([]string(nil), ips...)
	f.lastPort = port
	f.active.Store(true)
	return nil
}
func (f *fakeMgr) Unredirect() error {
	f.unredirectCalls.Add(1)
	f.active.Store(false)
	return nil
}
func (f *fakeMgr) IsActive() (bool, error) { return f.active.Load(), nil }

func TestControllerEnableInstallsRedirectAndPersists(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "firewall.json")
	mgr := &fakeMgr{}
	resolver := &fakeResolver{results: map[string][]string{
		"api.anthropic.com": {"1.1.1.1", "2.2.2.2"},
	}}
	c := NewController(mgr, resolver, statePath)

	if err := c.Enable(context.Background(), []string{"api.anthropic.com"}, "127.0.0.1:58600", 58601); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if mgr.redirectCalls.Load() != 1 {
		t.Errorf("expected 1 Redirect call, got %d", mgr.redirectCalls.Load())
	}
	if mgr.lastPort != 58601 {
		t.Errorf("got port %d, want 58601", mgr.lastPort)
	}
	st, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("loadstate: %v", err)
	}
	if !st.Active {
		t.Error("state should be active after Enable")
	}
	if !ipSetsEqual(st.IPs, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Errorf("state IPs %v don't match resolved", st.IPs)
	}
}

func TestControllerDisableUninstallsAndClearsState(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "firewall.json")
	mgr := &fakeMgr{}
	resolver := &fakeResolver{results: map[string][]string{"a.example.com": {"1.1.1.1"}}}
	c := NewController(mgr, resolver, statePath)

	_ = c.Enable(context.Background(), []string{"a.example.com"}, "127.0.0.1:58600", 58601)
	if err := c.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if mgr.unredirectCalls.Load() != 1 {
		t.Errorf("expected 1 Unredirect call, got %d", mgr.unredirectCalls.Load())
	}
	st, _ := LoadState(statePath)
	if st.Active {
		t.Error("state should be inactive after Disable")
	}
}

func TestControllerEnableFailsWhenRedirectFails(t *testing.T) {
	dir := t.TempDir()
	mgr := &fakeMgr{failNext: errors.New("user cancelled sudo")}
	resolver := &fakeResolver{results: map[string][]string{"a.example.com": {"1.1.1.1"}}}
	c := NewController(mgr, resolver, filepath.Join(dir, "firewall.json"))

	if err := c.Enable(context.Background(), []string{"a.example.com"}, "127.0.0.1:58600", 58601); err == nil {
		t.Fatal("Enable should fail when Redirect fails")
	}
}

func TestControllerReconcileSkipsWhenIPsUnchanged(t *testing.T) {
	dir := t.TempDir()
	mgr := &fakeMgr{}
	resolver := &fakeResolver{results: map[string][]string{"a.example.com": {"1.1.1.1"}}}
	c := NewController(mgr, resolver, filepath.Join(dir, "firewall.json"))
	_ = c.Enable(context.Background(), []string{"a.example.com"}, "127.0.0.1:58600", 58601)
	if mgr.redirectCalls.Load() != 1 {
		t.Fatalf("setup: 1 call expected; got %d", mgr.redirectCalls.Load())
	}
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if mgr.redirectCalls.Load() != 1 {
		t.Errorf("Reconcile should not re-call Redirect when IPs unchanged; got %d total calls",
			mgr.redirectCalls.Load())
	}
}

func TestControllerReconcileReinstallsWhenIPsChange(t *testing.T) {
	dir := t.TempDir()
	mgr := &fakeMgr{}
	resolver := &fakeResolver{results: map[string][]string{"a.example.com": {"1.1.1.1"}}}
	c := NewController(mgr, resolver, filepath.Join(dir, "firewall.json"))
	_ = c.Enable(context.Background(), []string{"a.example.com"}, "127.0.0.1:58600", 58601)
	resolver.results["a.example.com"] = []string{"9.9.9.9"}
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if mgr.redirectCalls.Load() != 2 {
		t.Errorf("Reconcile should re-call Redirect when IPs change; got %d calls", mgr.redirectCalls.Load())
	}
	if !ipSetsEqual(mgr.lastIPs, []string{"9.9.9.9"}) {
		t.Errorf("IPs not updated: %v", mgr.lastIPs)
	}
}
