// Package imagebuild orchestrates the central image pipeline: validate the
// admin Dockerfile extends the hardened base, build it, push it to the
// registry, and cosign-sign the resulting digest. The actual docker/cosign
// execution is behind a command-runner seam; production wires a shell runner.
package imagebuild

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// BuildSpec is one image build request.
type BuildSpec struct {
	Dockerfile string
	BaseRef    string
	TargetRef  string
}

// Result is a completed build.
type Result struct {
	Ref    string
	Digest string
}

// Builder builds, pushes, and signs an image.
type Builder interface {
	Build(ctx context.Context, spec BuildSpec) (Result, error)
}

// CommandRunner runs an external command and returns its combined stdout.
type CommandRunner func(ctx context.Context, name string, args ...string) (string, error)

// ShellBuilder is the production Builder; Run defaults to ExecRunner.
type ShellBuilder struct {
	Run       CommandRunner
	CosignKey string
}

// NewShellBuilder builds a ShellBuilder using the real exec runner.
func NewShellBuilder(cosignKey string) *ShellBuilder {
	return &ShellBuilder{Run: ExecRunner, CosignKey: cosignKey}
}

// ExecRunner is the real command runner (shells out, combined output).
func ExecRunner(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

var fromRe = regexp.MustCompile(`(?im)^\s*FROM\s+(\S+)`)
var digestRe = regexp.MustCompile(`digest:\s*(sha256:[0-9a-f]{64})`)

func (b *ShellBuilder) Build(ctx context.Context, spec BuildSpec) (Result, error) {
	m := fromRe.FindStringSubmatch(spec.Dockerfile)
	if m == nil || !(m[1] == spec.BaseRef || strings.HasPrefix(m[1], spec.BaseRef+":") || strings.HasPrefix(m[1], spec.BaseRef+"@")) {
		return Result{}, fmt.Errorf("Dockerfile must be FROM %s", spec.BaseRef)
	}

	dir, err := os.MkdirTemp("", "redactr-build-*")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(dir)
	dockerfile := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte(spec.Dockerfile), 0o600); err != nil {
		return Result{}, err
	}

	if _, err := b.Run(ctx, "docker", "build", "-t", spec.TargetRef, "-f", dockerfile, dir); err != nil {
		return Result{}, fmt.Errorf("docker build: %w", err)
	}
	pushOut, err := b.Run(ctx, "docker", "push", spec.TargetRef)
	if err != nil {
		return Result{}, fmt.Errorf("docker push: %w", err)
	}
	dm := digestRe.FindStringSubmatch(pushOut)
	if dm == nil {
		return Result{}, fmt.Errorf("could not parse pushed digest from output")
	}
	digest := dm[1]
	if _, err := b.Run(ctx, "cosign", "sign", "--key", b.CosignKey, spec.TargetRef+"@"+digest); err != nil {
		return Result{}, fmt.Errorf("cosign sign: %w", err)
	}
	return Result{Ref: spec.TargetRef, Digest: digest}, nil
}
