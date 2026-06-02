package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// commandRunner executes a composed argv. Seam for testing.
type commandRunner interface {
	Run(ctx context.Context, argv []string) error
}

// ttyRunner runs the command attached to the current stdio/TTY.
type ttyRunner struct{}

func (ttyRunner) Run(ctx context.Context, argv []string) error {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// Engine composes specs into runtime invocations and runs them.
type Engine struct {
	Runtime Runtime
	Runner  commandRunner
}

// NewEngine detects a runtime and wires the interactive TTY runner.
func NewEngine() (*Engine, error) {
	rt, err := Detect()
	if err != nil {
		return nil, err
	}
	return &Engine{Runtime: rt, Runner: ttyRunner{}}, nil
}

// composeArgs builds the full runtime argv for a spec: the given run flags
// (TTY/stdio mode) followed by the hardening profile, the proxy/CA injection,
// the image, and the entrypoint. Both Launch and StdioRunArgs share it so the
// flag pipeline lives in exactly one place.
func (e *Engine) composeArgs(s Spec, runFlags []string) []string {
	flags := append([]string{}, runFlags...)
	flags = append(flags, HardeningArgs(e.Runtime.Name())...)
	s.HostAlias = hostAliasFor(e.Runtime.Name())
	flags = append(flags, InjectionArgs(s)...)
	return e.Runtime.RunArgs(flags, s.Image, s.Entrypoint)
}

// StdioRunArgs composes the argv for a stdio-attached container (MCP servers):
// `<runtime> run --rm -i` + hardening + injection + image + entrypoint. The
// caller execs this argv and pipes the container's stdin/stdout (no TTY).
func (e *Engine) StdioRunArgs(s Spec) ([]string, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return e.composeArgs(s, []string{"--rm", "-i"}), nil
}

// Launch validates the spec, composes the full argv, and runs it.
func (e *Engine) Launch(ctx context.Context, s Spec) error {
	if err := s.Validate(); err != nil {
		return err
	}
	// SEAM: verify image signature/digest here (subsystem A).
	if s.Mode != ModeEphemeralTTY {
		return fmt.Errorf("sandbox: Launch handles only %q; use StdioRunArgs for %q", ModeEphemeralTTY, s.Mode)
	}
	return e.Runner.Run(ctx, e.composeArgs(s, []string{"--rm", "-it"}))
}
