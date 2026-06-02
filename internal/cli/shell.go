// Package cli implements user-facing CLI subcommands for the redactr binary.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/redactrai/redactr/internal/sessions"
)

// RunShell executes the `redactr shell` subcommand. It exports proxy and CA
// environment variables and execs the user's shell so any AI tool launched
// inside that shell is automatically routed through Redactr.
//
// Returns a non-nil error only when the proxy is not running or the shell
// cannot be located. When exec succeeds it does not return.
func RunShell(baseDir string) error {
	proxyAddr, src, err := discoverProxyAddr(baseDir)
	if err != nil {
		return err
	}
	proxyAddr = normalizeAddr(proxyAddr)
	caCert := filepath.Join(baseDir, "certs", "ca.crt")
	if _, err := os.Stat(caCert); err != nil {
		return fmt.Errorf("CA certificate not found at %s — start redactr at least once to generate it", caCert)
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}
	if _, err := os.Stat(shell); err != nil {
		return fmt.Errorf("shell %s not found: %w", shell, err)
	}

	env := append(os.Environ(),
		"HTTP_PROXY=http://"+proxyAddr,
		"HTTPS_PROXY=http://"+proxyAddr,
		"http_proxy=http://"+proxyAddr,
		"https_proxy=http://"+proxyAddr,
		"NODE_EXTRA_CA_CERTS="+caCert,
		"SSL_CERT_FILE="+caCert,
		"REQUESTS_CA_BUNDLE="+caCert,
		sessions.BoundEnvKey+"="+sessions.BoundEnvValue,
		"REDACTR_PROXY_ADDR="+proxyAddr,
		"REDACTR_CA_CERT="+caCert,
	)

	fmt.Fprintf(os.Stderr, "\033[2m• redactr: bound shell — HTTPS_PROXY=%s (%s)\033[0m\n", proxyAddr, src)
	fmt.Fprintf(os.Stderr, "\033[2m• exit this shell to detach.\033[0m\n\n")

	// exec replaces the current process so the shell inherits its tty cleanly.
	return syscall.Exec(shell, []string{filepath.Base(shell), "-i"}, env)
}

func readState(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("state file %s is empty", path)
	}
	return v, nil
}

// normalizeAddr converts addresses like "[::]:61616" or "0.0.0.0:61616" into a
// loopback form clients can actually dial.
func normalizeAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "tcp://")
	switch {
	case strings.HasPrefix(addr, "[::]:"):
		return "127.0.0.1:" + strings.TrimPrefix(addr, "[::]:")
	case strings.HasPrefix(addr, "0.0.0.0:"):
		return "127.0.0.1:" + strings.TrimPrefix(addr, "0.0.0.0:")
	case strings.HasPrefix(addr, "[::1]:"):
		return "127.0.0.1:" + strings.TrimPrefix(addr, "[::1]:")
	}
	return addr
}

// Self returns the absolute path to the running redactr binary.
func Self() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// CommandExists reports whether a binary is on PATH.
func CommandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// discoverProxyAddr finds the running Redactr proxy's address. It first checks
// the proxy.pid state file (written by the daemon on startup or when the
// proxy is toggled on), and falls back to querying the dashboard's
// /api/proxy/status endpoint. Returns the address, a short source label for
// diagnostics, and an error when neither path succeeds.
func discoverProxyAddr(baseDir string) (string, string, error) {
	pidPath := filepath.Join(baseDir, "state", "proxy.pid")
	if v, err := readState(pidPath); err == nil {
		return v, "state file", nil
	}

	dashPath := filepath.Join(baseDir, "state", "dashboard.port")
	dashAddr, err := readState(dashPath)
	if err != nil {
		return "", "", fmt.Errorf(
			"redactr proxy is not running.\n"+
				"  • Start the daemon (`redactr` in another terminal) and enable the proxy from the dashboard.\n"+
				"  • Could not read %s: %v",
			pidPath, err,
		)
	}
	dashAddr = normalizeAddr(dashAddr)

	addr, err := fetchProxyAddrFromDashboard(dashAddr)
	if err != nil {
		return "", "", fmt.Errorf(
			"redactr proxy is not running.\n"+
				"  • The dashboard at %s reports proxy=disabled or is unreachable.\n"+
				"  • Enable the proxy from the dashboard, then re-run `redactr shell`.\n"+
				"  • (%v)",
			dashAddr, err,
		)
	}
	return addr, "dashboard probe", nil
}

func fetchProxyAddrFromDashboard(dashAddr string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	url := "http://" + dashAddr + "/api/proxy/status"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("dashboard returned %d", resp.StatusCode)
	}
	var body struct {
		Enabled bool   `json:"enabled"`
		Addr    string `json:"addr"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if !body.Enabled || body.Addr == "" {
		return "", fmt.Errorf("proxy reported disabled or addr empty")
	}
	return body.Addr, nil
}
