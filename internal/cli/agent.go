package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rakeshguha/redactr/internal/control"
	"github.com/rakeshguha/redactr/internal/sandbox"
)

// knownAgents maps a subcommand to the in-container entrypoint binary.
var knownAgents = map[string]string{
	"claude":  "claude",
	"codex":   "codex",
	"copilot": "copilot",
}

func knownAgentEntrypoint(tool string) ([]string, bool) {
	bin, ok := knownAgents[tool]
	if !ok {
		return nil, false
	}
	return []string{bin}, true
}

type launchInfo = control.LaunchInfo

// specFromLaunchInfo builds a sandbox Spec from resolved launch policy. It
// rejects mount modes subsystem C does not implement yet.
func specFromLaunchInfo(tool string, extraArgs []string, cwd, caPath string, info launchInfo) (sandbox.Spec, error) {
	entry, ok := knownAgentEntrypoint(tool)
	if !ok {
		return sandbox.Spec{}, fmt.Errorf("unknown agent %q", tool)
	}
	if info.MountMode != "bind" {
		return sandbox.Spec{}, fmt.Errorf("mount mode %q not yet supported (only bind)", info.MountMode) // SEAM: subsystem C diffback
	}
	return sandbox.Spec{
		Mode:       sandbox.ModeEphemeralTTY,
		Image:      info.Image,
		ProjectDir: cwd,
		Entrypoint: append(entry, extraArgs...),
		ProxyAddr:  info.ProxyAddr,
		CACertPath: caPath,
	}, nil
}

// RunAgent ensures the daemon + proxy are up, fetches launch policy over the
// control socket, then launches the agent container in this process (TTY owner).
func RunAgent(baseDir, tool string, extraArgs []string) error {
	if _, ok := knownAgentEntrypoint(tool); !ok {
		return fmt.Errorf("unknown agent %q", tool)
	}
	sockDir := filepath.Join(baseDir, "state")
	if err := EnsureDaemon(sockDir); err != nil {
		return err
	}
	client := NewClient(sockDir)
	if _, err := client.EnableProxy(); err != nil {
		return fmt.Errorf("could not enable proxy: %w", err)
	}
	info, err := client.LaunchPolicy(tool)
	if err != nil {
		return fmt.Errorf("could not fetch launch policy: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	caPath := filepath.Join(baseDir, "certs", "ca.crt")
	spec, err := specFromLaunchInfo(tool, extraArgs, cwd, caPath, info)
	if err != nil {
		return err
	}
	eng, err := sandbox.NewEngine()
	if err != nil {
		return err
	}
	return eng.Launch(context.Background(), spec)
}
