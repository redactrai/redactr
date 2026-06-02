package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/rakeshguha/redactr/internal/control"
)

// Client talks to the daemon's control socket at <sockDir>/redactr.sock.
type Client struct {
	http *http.Client
}

// NewClient builds a control-socket client for the daemon whose socket lives in
// sockDir (i.e. <baseDir>/state).
func NewClient(sockDir string) *Client {
	sock := filepath.Join(sockDir, "redactr.sock")
	return &Client{http: &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
	}}
}

func (c *Client) Status() (control.Status, error) {
	var s control.Status
	return s, c.get("/status", &s)
}

func (c *Client) EnableProxy() (control.Status, error) {
	var s control.Status
	req, err := http.NewRequest(http.MethodPost, "http://unix/proxy/enable", nil)
	if err != nil {
		return s, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return s, fmt.Errorf("proxy enable failed (status %d)", resp.StatusCode)
	}
	return s, json.NewDecoder(resp.Body).Decode(&s)
}

func (c *Client) DisableProxy() (control.Status, error) {
	var s control.Status
	req, err := http.NewRequest(http.MethodPost, "http://unix/proxy/disable", nil)
	if err != nil {
		return s, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return s, fmt.Errorf("proxy disable failed (status %d)", resp.StatusCode)
	}
	return s, json.NewDecoder(resp.Body).Decode(&s)
}

func (c *Client) LaunchPolicy(tool string) (control.LaunchInfo, error) {
	var li control.LaunchInfo
	return li, c.get("/launch-policy?tool="+url.QueryEscape(tool), &li)
}

func (c *Client) get(path string, out any) error {
	resp, err := c.http.Get("http://unix" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s failed (status %d)", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// EnsureDaemon dials the control socket; if unreachable it spawns the daemon and
// waits up to ~10s for the socket to come up.
func EnsureDaemon(sockDir string) error {
	return ensureDaemon(sockDir, spawnDaemon)
}

func ensureDaemon(sockDir string, spawn func() error) error {
	sock := filepath.Join(sockDir, "redactr.sock")
	if dialable(sock) {
		return nil
	}
	if err := spawn(); err != nil {
		return fmt.Errorf("failed to start redactr daemon: %w", err)
	}
	for i := 0; i < 50; i++ { // ~10s at 200ms
		if dialable(sock) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("redactr daemon did not come up (socket %s)", sock)
}

func dialable(sock string) bool {
	c, err := net.DialTimeout("unix", sock, 200*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
