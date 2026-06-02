package firewall

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Controller orchestrates Manager + DNS reconciliation + state persistence.
// Platform-agnostic: the platform-specific bits live behind the Manager
// interface.
type Controller struct {
	mgr       Manager
	resolver  Resolver
	statePath string

	mu              sync.Mutex
	domains         []string
	proxyAddr       string
	transparentPort int
	currentIPs      []string
	enabled         bool
}

func NewController(mgr Manager, resolver Resolver, statePath string) *Controller {
	if resolver == nil {
		resolver = DefaultResolver
	}
	return &Controller{
		mgr:       mgr,
		resolver:  resolver,
		statePath: statePath,
	}
}

// Enable resolves the supplied domains, installs Redirect rules, and
// persists state. Returns the underlying Manager error if installation
// fails (including when the user cancels the sudo prompt).
func (c *Controller) Enable(ctx context.Context, domains []string, proxyAddr string, transparentPort int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	slog.Info("firewall.Controller.Enable starting",
		"domains", domains,
		"proxy_addr", proxyAddr,
		"transparent_port", transparentPort)

	ips, err := resolveAll(ctx, c.resolver, domains)
	if err != nil {
		slog.Error("firewall.Controller.Enable DNS resolve failed",
			"domains", domains,
			"error", err)
		return err
	}
	slog.Info("firewall.Controller.Enable resolved", "ips", ips)
	if err := c.mgr.Redirect(ips, transparentPort); err != nil {
		slog.Error("firewall.Controller.Enable Redirect failed", "error", err)
		return err
	}
	c.domains = append([]string(nil), domains...)
	c.proxyAddr = proxyAddr
	c.transparentPort = transparentPort
	c.currentIPs = ips
	c.enabled = true
	c.persist()
	slog.Info("firewall.Controller.Enable succeeded", "ip_count", len(ips))
	return nil
}

// Disable removes the Redirect rules and clears persisted state.
func (c *Controller) Disable() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		slog.Info("firewall.Controller.Disable noop (not enabled)")
		return nil
	}
	slog.Info("firewall.Controller.Disable starting")
	if err := c.mgr.Unredirect(); err != nil {
		slog.Error("firewall.Controller.Disable Unredirect failed", "error", err)
		return err
	}
	c.enabled = false
	c.currentIPs = nil
	c.persist()
	slog.Info("firewall.Controller.Disable succeeded")
	return nil
}

// Reconcile re-resolves the configured domains and re-runs Redirect
// only when the IP set has changed. Cheap to call on a 5-min ticker.
func (c *Controller) Reconcile(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return nil
	}
	ips, err := resolveAll(ctx, c.resolver, c.domains)
	if err != nil {
		slog.Warn("firewall.Controller.Reconcile DNS resolve failed (keeping current rules)",
			"error", err)
		return err
	}
	if ipSetsEqual(ips, c.currentIPs) {
		return nil
	}
	slog.Info("firewall.Controller.Reconcile IPs changed, reinstalling",
		"old", c.currentIPs, "new", ips)
	if err := c.mgr.Redirect(ips, c.transparentPort); err != nil {
		slog.Error("firewall.Controller.Reconcile Redirect failed", "error", err)
		return err
	}
	c.currentIPs = ips
	c.persist()
	return nil
}

// IsActive reports whether redirect rules are currently installed.
func (c *Controller) IsActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enabled
}

// RunReconcileLoop ticks every interval and re-reconciles. Honours
// context cancellation. Intended to be run in a dedicated goroutine.
func (c *Controller) RunReconcileLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = c.Reconcile(ctx)
		}
	}
}

func (c *Controller) persist() {
	_ = SaveState(c.statePath, State{
		Active:          c.enabled,
		ProxyAddr:       c.proxyAddr,
		TransparentAddr: "", // set by daemon when starting transparent listener
		IPs:             append([]string(nil), c.currentIPs...),
		LastReconciled:  time.Now(),
		CAInstalled:     c.enabled,
	})
}

// ErrAlreadyEnabled is returned by Enable when called twice without an
// intervening Disable.
var ErrAlreadyEnabled = errors.New("firewall: already enabled")
