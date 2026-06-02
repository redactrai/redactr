// Package control holds the wire DTOs exchanged over the daemon's local
// control socket, shared by the daemon (server) and the CLI/tray (clients).
package control

import "time"

// Status is the GET /status response.
type Status struct {
	Proxy     ProxyStatus `json:"proxy"`
	Dashboard string      `json:"dashboard"`
	Version   string      `json:"version"`
}

// ProxyStatus reports the local proxy's liveness.
type ProxyStatus struct {
	Enabled bool   `json:"enabled"`
	Addr    string `json:"addr"`
}

// LaunchInfo is the GET /launch-policy response: persisted policy fields plus
// the live proxy address (runtime state, not cached policy).
type LaunchInfo struct {
	Image     string   `json:"image"`
	MountMode string   `json:"mountMode"`
	Denylist  []string `json:"denylist"`
	ProxyAddr string   `json:"proxyAddr"`
}

// PolicyBundle is the per-org launch policy distributed by the control plane.
type PolicyBundle struct {
	Image     string   `json:"image"`
	MountMode string   `json:"mountMode"`
	Denylist  []string `json:"denylist"`
	Version   int      `json:"version"`
}

// SignedPolicy is the GET /v1/policy response: a base64url(PolicyBundle JSON)
// plus a detached signature over those JSON bytes.
type SignedPolicy struct {
	Bundle    string `json:"bundle"`
	Signature string `json:"signature"`
	Version   int    `json:"version"`
}

// MonitorEvent is a single privacy-scrubbed host-scan observation. It carries
// NO command line, raw connection string, or environment value.
type MonitorEvent struct {
	Tool            string    `json:"tool"`
	Verdict         string    `json:"verdict"`
	Reason          string    `json:"reason"`
	DirectConnCount int       `json:"direct_conn_count"`
	ObservedAt      time.Time `json:"observed_at"`
}
