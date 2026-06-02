// Package sandbox launches AI-tool processes inside hardened, egress-locked
// containers whose run-spec carries the proxy route and CA, so no host
// environment mutation is required.
package sandbox

import "fmt"

// Mode selects how the container is attached to the host.
type Mode string

const (
	ModeEphemeralTTY    Mode = "ephemeral-tty"    // CLI agents (built)
	ModeStdioAttached   Mode = "stdio-attached"   // SEAM: MCP servers (later spec)
	ModeWorkspaceRemote Mode = "workspace-remote" // SEAM: VS Code Dev Containers (later spec)
)

// Spec fully describes a sandbox launch.
type Spec struct {
	Mode       Mode
	Image      string   // image ref; later: ref@digest, signature-verified (SEAM)
	ProjectDir string   // host dir bind-mounted RW at /work
	Entrypoint []string // command + args run inside the container
	ProxyAddr  string   // host:port of the local Redactr proxy (filled by Engine)
	CACertPath string   // host path to ca.crt (filled by Engine)
	// HostAlias is the in-container DNS alias for the host proxy. Filled by the
	// Engine from the detected runtime (Docker -> host.docker.internal, Podman
	// -> host.containers.internal). Empty defaults to the Docker alias.
	HostAlias string
}

// Validate checks required fields and that the mode is implemented.
func (s Spec) Validate() error {
	if s.Mode != ModeEphemeralTTY && s.Mode != ModeStdioAttached {
		return fmt.Errorf("sandbox: mode %q not implemented in this build", s.Mode)
	}
	if s.Image == "" {
		return fmt.Errorf("sandbox: Image is required")
	}
	if s.ProjectDir == "" {
		return fmt.Errorf("sandbox: ProjectDir is required")
	}
	if len(s.Entrypoint) == 0 {
		return fmt.Errorf("sandbox: Entrypoint is required")
	}
	return nil
}
