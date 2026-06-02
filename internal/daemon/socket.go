package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/rakeshguha/redactr/internal/control"
	"github.com/rakeshguha/redactr/internal/policy"
)

func (d *Daemon) socketPath() string {
	return filepath.Join(d.opts.BaseDir, "state", "redactr.sock")
}

// startControlSocket binds the UDS and serves the control API. Called from Start.
func (d *Daemon) startControlSocket() error {
	path := d.socketPath()
	_ = os.Remove(path) // clear stale socket (singleton lock guarantees no live peer)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0o600)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", d.handleStatus)
	mux.HandleFunc("POST /proxy/enable", d.handleProxyEnable)
	mux.HandleFunc("POST /proxy/disable", d.handleProxyDisable)
	mux.HandleFunc("GET /launch-policy", d.handleLaunchPolicy)

	d.sock = &http.Server{Handler: mux}
	go d.sock.Serve(l)
	return nil
}

func (d *Daemon) stopControlSocket() {
	if d.sock != nil {
		_ = d.sock.Close()
		d.sock = nil
	}
	_ = os.Remove(d.socketPath())
}

func (d *Daemon) statusValue() control.Status {
	cfg := d.cfgMgr.Get()
	return control.Status{
		Proxy:     control.ProxyStatus{Enabled: cfg.Proxy.Enabled, Addr: d.proxy.Addr()},
		Dashboard: d.dashboardAddr,
		Version:   "v2-dev",
	}
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeControlJSON(w, d.statusValue())
}

func (d *Daemon) handleLaunchPolicy(w http.ResponseWriter, r *http.Request) {
	cfg := d.cfgMgr.Get()
	p, err := policy.Load(d.opts.BaseDir, cfg.Proxy.BlockedDomains)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeControlJSON(w, control.LaunchInfo{
		Image:     p.Image,
		MountMode: p.MountMode,
		Denylist:  p.Denylist,
		ProxyAddr: d.proxy.Addr(),
	})
}

// handleProxyEnable/Disable delegate to the dashboard's firewall-aware route to
// avoid duplicating proxy/firewall logic, then return the fresh /status.
func (d *Daemon) handleProxyEnable(w http.ResponseWriter, r *http.Request) {
	if err := d.relayDashboard(r.Context(), "/api/proxy/enable"); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeControlJSON(w, d.statusValue())
}

func (d *Daemon) handleProxyDisable(w http.ResponseWriter, r *http.Request) {
	if err := d.relayDashboard(r.Context(), "/api/proxy/disable"); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeControlJSON(w, d.statusValue())
}

func (d *Daemon) relayDashboard(ctx context.Context, path string) error {
	if d.dashboardAddr == "" {
		return fmt.Errorf("dashboard not available")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+d.dashboardAddr+path, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("dashboard %s returned %d", path, resp.StatusCode)
	}
	return nil
}

func writeControlJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newUnixClient returns an http.Client whose transport dials the given UDS.
func newUnixClient(sockPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
	}
}
