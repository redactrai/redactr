package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Discover returns the local proxy address (loopback-normalized) and the CA
// cert path, reading the state files the running daemon writes under baseDir
// (e.g. ~/.redactr). Returns an error if the proxy is not running.
func Discover(baseDir string) (proxyAddr, caCertPath string, err error) {
	raw, err := os.ReadFile(filepath.Join(baseDir, "state", "proxy.pid"))
	if err != nil {
		return "", "", fmt.Errorf("redactr proxy not running (start `redactr` first): %w", err)
	}
	addr := normalizeLoopback(strings.TrimSpace(string(raw)))
	if addr == "" {
		return "", "", fmt.Errorf("proxy.pid is empty")
	}
	ca := filepath.Join(baseDir, "certs", "ca.crt")
	if _, err := os.Stat(ca); err != nil {
		return "", "", fmt.Errorf("CA cert not found at %s: %w", ca, err)
	}
	return addr, ca, nil
}

// normalizeLoopback rewrites wildcard bind addresses to a dialable loopback.
func normalizeLoopback(addr string) string {
	addr = strings.TrimPrefix(addr, "tcp://")
	for _, p := range []string{"0.0.0.0:", "[::]:", "[::1]:"} {
		if strings.HasPrefix(addr, p) {
			return "127.0.0.1:" + strings.TrimPrefix(addr, p)
		}
	}
	return addr
}
