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

// Kinds of telemetry carried in an IngestRecord.
const (
	KindMonitor = "monitor"
	KindAudit   = "audit"
)

// AuditRecord is a single redaction-finding observation derived from a local
// ScanReport. It carries the detector and category of what was redacted, never
// the raw or redacted value and never any request/response body.
type AuditRecord struct {
	Provider   string    `json:"provider"`
	Source     string    `json:"source"`
	Detector   string    `json:"detector"`
	Category   string    `json:"category"`
	Action     string    `json:"action"` // "blocked" | "allowed"
	LatencyMs  int64     `json:"latency_ms"`
	ObservedAt time.Time `json:"observed_at"`
}

// IngestRecord is one durable, idempotent telemetry item. Exactly one of
// Monitor/Audit is set, selected by Kind. UUID is the client-generated
// idempotency key; Seq is the client's monotonic per-device sequence.
type IngestRecord struct {
	UUID    string        `json:"uuid"`
	Seq     uint64        `json:"seq"`
	Kind    string        `json:"kind"`
	Monitor *MonitorEvent `json:"monitor,omitempty"`
	Audit   *AuditRecord  `json:"audit,omitempty"`
}

// IngestRequest is the POST /v1/ingest body.
type IngestRequest struct {
	Records []IngestRecord `json:"records"`
}

// IngestResponse lists the UUIDs the server has durably stored (new or already-present).
type IngestResponse struct {
	Accepted []string `json:"accepted"`
}
