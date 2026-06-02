# Sandbox Engine (Subsystem C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the keystone "launch X in a hardened, egress-locked, CA-injected container" primitive and prove it end-to-end with `redactr claude` running the Claude CLI inside a hardened container whose traffic is forced through the existing local Redactr proxy.

**Architecture:** A new `internal/sandbox` package exposes `Engine.Launch(Spec)` over a pluggable container `Runtime` (Docker — which also covers Colima — and Podman, selected by `Detect`). The Spec is assembled from pure functions (hardening flags, CA/mount/env injection, proxy-address discovery) so the bulk is unit-testable without Docker. A thin CLI entrypoint (`redactr claude`) builds an ephemeral-tty Spec and launches. The container reaches the host proxy via `host.docker.internal`; first by `HTTPS_PROXY` env (Task 6 end-to-end), then hardened with an in-container transparent redirect + egress drop (Task 10). The proxy, scanner, and `internal/domain` denylist are reused unchanged from v1.

**Tech Stack:** Go 1.26 (`github.com/redactrai/redactr`), Docker/Podman/Colima CLIs, `iptables` (inside the base image), standard `os/exec`, Go `testing` (unit tests pure; integration tests behind `-tags=integration`, matching `test/integration/`).

**Scope / seams (deferred to later subsystem specs):**
- Only **ephemeral-tty** mode is built. `stdio-attached` (MCP) and `workspace-remote` (Dev Container) are left as explicit `Mode` enum values with a `not implemented` error and a `// SEAM:` comment.
- The base image is **built locally** here (`build/sandbox/Dockerfile.base`) as a stand-in for subsystem A's central build+sign+registry pipeline. Image **signature/digest verification** is a `// SEAM:` no-op stub.
- Runtime coverage: `docker` driver (covers Docker Desktop + Colima) and `podman` driver. Rootless-Podman userns nuances beyond `--userns=keep-id` are noted as a seam.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/sandbox/spec.go` | `Spec`, `Mode` types + `Spec.Validate()` |
| `internal/sandbox/discover.go` | discover local proxy `host:port` + CA cert path from `~/.redactr` state |
| `internal/sandbox/runtime.go` | `Runtime` interface, `cliRuntime` (bin-parameterized), `Detect()` |
| `internal/sandbox/hardening.go` | `HardeningArgs()` — pure: hardening profile → `docker run` flags |
| `internal/sandbox/inject.go` | `InjectionArgs()` — pure: mounts + CA + proxy/env injection → flags |
| `internal/sandbox/engine.go` | `Engine`, `Engine.Launch(Spec)` — compose args, run; `commandRunner` seam |
| `internal/cli/agent.go` | `RunAgent(baseDir, tool, args)` — build ephemeral Spec, launch |
| `cmd/redactr/main.go` | add `claude`/known-agent subcommand dispatch (modify) |
| `build/sandbox/Dockerfile.base` | local `redactr-base` image (node + claude CLI + iptables + su-exec + entrypoint) |
| `build/sandbox/redactr-entrypoint.sh` | container entrypoint: (Task 10) transparent redirect + egress drop, then drop privileges and exec agent |
| `internal/sandbox/*_test.go` | unit tests (pure) |
| `test/integration/sandbox_test.go` | end-to-end (build-tagged) |

---

## Task 1: Scaffold sandbox package — Spec & Mode

**Files:**
- Create: `internal/sandbox/spec.go`
- Test: `internal/sandbox/spec_test.go`

- [ ] **Step 1: Write the failing test**

```go
package sandbox

import "testing"

func TestSpecValidate(t *testing.T) {
	tests := []struct {
		name    string
		spec    Spec
		wantErr bool
	}{
		{"valid ephemeral", Spec{Mode: ModeEphemeralTTY, Image: "redactr-base:local", ProjectDir: "/tmp/p", Entrypoint: []string{"claude"}}, false},
		{"missing image", Spec{Mode: ModeEphemeralTTY, ProjectDir: "/tmp/p", Entrypoint: []string{"claude"}}, true},
		{"missing project dir", Spec{Mode: ModeEphemeralTTY, Image: "redactr-base:local", Entrypoint: []string{"claude"}}, true},
		{"missing entrypoint", Spec{Mode: ModeEphemeralTTY, Image: "redactr-base:local", ProjectDir: "/tmp/p"}, true},
		{"unsupported mode", Spec{Mode: ModeStdioAttached, Image: "redactr-base:local", ProjectDir: "/tmp/p", Entrypoint: []string{"x"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sandbox/ -run TestSpecValidate -v`
Expected: FAIL — `undefined: Spec` / package does not compile.

- [ ] **Step 3: Write minimal implementation**

```go
// Package sandbox launches AI-tool processes inside hardened, egress-locked
// containers whose run-spec carries the proxy route and CA, so no host
// environment mutation is required.
package sandbox

import "fmt"

// Mode selects how the container is attached to the host.
type Mode string

const (
	ModeEphemeralTTY  Mode = "ephemeral-tty"  // CLI agents (built)
	ModeStdioAttached Mode = "stdio-attached" // SEAM: MCP servers (later spec)
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
}

// Validate checks required fields and that the mode is implemented.
func (s Spec) Validate() error {
	if s.Mode != ModeEphemeralTTY {
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sandbox/ -run TestSpecValidate -v`
Expected: PASS (all sub-tests).

- [ ] **Step 5: Commit**

```bash
git add internal/sandbox/spec.go internal/sandbox/spec_test.go
git commit -m "feat(sandbox): Spec and Mode types with validation"
```

---

## Task 2: Discover proxy address + CA path from v1 state

**Files:**
- Create: `internal/sandbox/discover.go`
- Test: `internal/sandbox/discover_test.go`

Reuses v1's state contract: `p.Start(0)` writes `host:port` to `~/.redactr/state/proxy.pid` (see `cmd/redactr/main.go:291`); CA is at `~/.redactr/certs/ca.crt` (see `internal/cli/shell.go`).

- [ ] **Step 1: Write the failing test**

```go
package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscover(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "certs"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(base, "state", "proxy.pid"), []byte("0.0.0.0:47474\n"), 0o644)
	os.WriteFile(filepath.Join(base, "certs", "ca.crt"), []byte("PEM"), 0o644)

	addr, ca, err := Discover(base)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if addr != "127.0.0.1:47474" { // normalized from 0.0.0.0
		t.Errorf("addr = %q, want 127.0.0.1:47474", addr)
	}
	if ca != filepath.Join(base, "certs", "ca.crt") {
		t.Errorf("ca = %q", ca)
	}
}

func TestDiscoverProxyDown(t *testing.T) {
	base := t.TempDir()
	os.MkdirAll(filepath.Join(base, "certs"), 0o755)
	os.WriteFile(filepath.Join(base, "certs", "ca.crt"), []byte("PEM"), 0o644)
	if _, _, err := Discover(base); err == nil {
		t.Fatal("expected error when proxy.pid missing")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sandbox/ -run TestDiscover -v`
Expected: FAIL — `undefined: Discover`.

- [ ] **Step 3: Write minimal implementation**

```go
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
	addr = strings.TrimPrefix(strings.TrimSpace(addr), "tcp://")
	for _, p := range []string{"0.0.0.0:", "[::]:", "[::1]:"} {
		if strings.HasPrefix(addr, p) {
			return "127.0.0.1:" + strings.TrimPrefix(addr, p)
		}
	}
	return addr
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sandbox/ -run TestDiscover -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sandbox/discover.go internal/sandbox/discover_test.go
git commit -m "feat(sandbox): discover proxy addr + CA path from daemon state"
```

---

## Task 3: Runtime detection (docker / podman)

**Files:**
- Create: `internal/sandbox/runtime.go`
- Test: `internal/sandbox/runtime_test.go`

`docker` covers Docker Desktop and Colima (Colima exposes a Docker-compatible socket). `podman` is the second driver. They share `run` flags for our needs, so one `cliRuntime` parameterized by binary name (DRY).

- [ ] **Step 1: Write the failing test**

```go
package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectPrefersDocker(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "docker")
	writeFakeBin(t, dir, "podman")
	t.Setenv("PATH", dir)

	rt, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.Name() != "docker" {
		t.Errorf("Name() = %q, want docker", rt.Name())
	}
}

func TestDetectFallsBackToPodman(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "podman")
	t.Setenv("PATH", dir)

	rt, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.Name() != "podman" {
		t.Errorf("Name() = %q, want podman", rt.Name())
	}
}

func TestDetectNoneFound(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := Detect(); err == nil {
		t.Fatal("expected error when no runtime found")
	}
}

func writeFakeBin(t *testing.T, dir, name string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sandbox/ -run TestDetect -v`
Expected: FAIL — `undefined: Detect`.

- [ ] **Step 3: Write minimal implementation**

```go
package sandbox

import (
	"fmt"
	"os/exec"
)

// Runtime is a container runtime driver.
type Runtime interface {
	Name() string
	// RunArgs returns the full argv (including the binary) to run spec, given
	// the already-composed flag groups.
	RunArgs(flags []string, image string, entrypoint []string) []string
}

type cliRuntime struct{ bin string }

func (r cliRuntime) Name() string { return r.bin }

func (r cliRuntime) RunArgs(flags []string, image string, entrypoint []string) []string {
	argv := []string{r.bin, "run"}
	argv = append(argv, flags...)
	argv = append(argv, image)
	argv = append(argv, entrypoint...)
	return argv
}

// preferredRuntimes is the detection order; docker first (also covers Colima).
var preferredRuntimes = []string{"docker", "podman"}

// Detect returns the first available container runtime on PATH.
func Detect() (Runtime, error) {
	for _, bin := range preferredRuntimes {
		if _, err := exec.LookPath(bin); err == nil {
			return cliRuntime{bin: bin}, nil
		}
	}
	return nil, fmt.Errorf("no container runtime found (install Docker, Colima, or Podman)")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sandbox/ -run TestDetect -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sandbox/runtime.go internal/sandbox/runtime_test.go
git commit -m "feat(sandbox): runtime detection for docker/colima and podman"
```

---

## Task 4: Hardening profile → run flags

**Files:**
- Create: `internal/sandbox/hardening.go`
- Test: `internal/sandbox/hardening_test.go`

Encodes the spec's non-negotiable profile. `--cap-add NET_ADMIN`/`NET_RAW` are the one measured exception, required by the Task 10 entrypoint to install the transparent-redirect rules over the container's **own** netns (safe under rootless userns); everything else is dropped.

- [ ] **Step 1: Write the failing test**

```go
package sandbox

import (
	"strings"
	"testing"
)

func TestHardeningArgs(t *testing.T) {
	got := strings.Join(HardeningArgs("docker"), " ")
	must := []string{
		"--cap-drop ALL",
		"--cap-add NET_ADMIN",
		"--cap-add NET_RAW",
		"--security-opt no-new-privileges",
		"--read-only",
		"--tmpfs /tmp",
		"--pids-limit",
		"--memory",
	}
	for _, m := range must {
		if !strings.Contains(got, m) {
			t.Errorf("hardening args missing %q\ngot: %s", m, got)
		}
	}
	for _, banned := range []string{"--privileged", "docker.sock", "--network host", "--net=host"} {
		if strings.Contains(got, banned) {
			t.Errorf("hardening args must never contain %q\ngot: %s", banned, got)
		}
	}
}

func TestHardeningPodmanKeepID(t *testing.T) {
	got := strings.Join(HardeningArgs("podman"), " ")
	if !strings.Contains(got, "--userns keep-id") {
		t.Errorf("podman hardening should set --userns keep-id\ngot: %s", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sandbox/ -run TestHardening -v`
Expected: FAIL — `undefined: HardeningArgs`.

- [ ] **Step 3: Write minimal implementation**

```go
package sandbox

// HardeningArgs returns the non-negotiable hardening flags for `run`.
// runtime is the driver name ("docker" or "podman") for driver-specific tweaks.
func HardeningArgs(runtime string) []string {
	args := []string{
		"--cap-drop", "ALL",
		// Measured exception: the entrypoint installs the egress redirect over
		// the container's own netns before dropping to an unprivileged user.
		"--cap-add", "NET_ADMIN",
		"--cap-add", "NET_RAW",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp",
		// Writable scratch for the unprivileged agent's HOME (read-only root
		// otherwise leaves CLIs like claude nowhere to write their config).
		"--tmpfs", "/home/redactr:uid=1000,mode=0700",
		"--pids-limit", "512",
		"--memory", "4g",
	}
	if runtime == "podman" {
		// Map the invoking host user into the container (rootless).
		args = append(args, "--userns", "keep-id")
	}
	return args
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sandbox/ -run TestHardening -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sandbox/hardening.go internal/sandbox/hardening_test.go
git commit -m "feat(sandbox): non-negotiable container hardening profile"
```

---

## Task 5: CA + mount + proxy/env injection → run flags

**Files:**
- Create: `internal/sandbox/inject.go`
- Test: `internal/sandbox/inject_test.go`

Injects at launch (not baked into image): bind-mount project at `/work`, mount CA read-only, set `HTTPS_PROXY`/`HTTP_PROXY` + CA env vars pointing at the proxy via `host.docker.internal`, set `REDACTR_BOUND=1` so the monitor (subsystem E) can tag it.

- [ ] **Step 1: Write the failing test**

```go
package sandbox

import (
	"strings"
	"testing"
)

func TestInjectionArgs(t *testing.T) {
	s := Spec{
		Mode:       ModeEphemeralTTY,
		Image:      "redactr-base:local",
		ProjectDir: "/home/u/proj",
		Entrypoint: []string{"claude"},
		ProxyAddr:  "127.0.0.1:47474",
		CACertPath: "/home/u/.redactr/certs/ca.crt",
	}
	got := strings.Join(InjectionArgs(s), " ")

	wants := []string{
		"--add-host host.docker.internal:host-gateway",
		"-v /home/u/proj:/work",                                  // bind-mount RW
		"-w /work",
		"-v /home/u/.redactr/certs/ca.crt:/etc/redactr/ca.crt:ro", // CA read-only
		"-e HTTPS_PROXY=http://host.docker.internal:47474",
		"-e HTTP_PROXY=http://host.docker.internal:47474",
		"-e NODE_EXTRA_CA_CERTS=/etc/redactr/ca.crt",
		"-e REQUESTS_CA_BUNDLE=/etc/redactr/ca.crt",
		"-e SSL_CERT_FILE=/etc/redactr/ca.crt",
		"-e REDACTR_BOUND=1",
		"-e REDACTR_PROXY_HOST=host.docker.internal",
		"-e REDACTR_PROXY_PORT=47474",
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("injection args missing %q\ngot: %s", w, got)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sandbox/ -run TestInjectionArgs -v`
Expected: FAIL — `undefined: InjectionArgs`.

- [ ] **Step 3: Write minimal implementation**

```go
package sandbox

import "strings"

const (
	proxyHostAlias = "host.docker.internal"
	workMount      = "/work"
	caInContainer  = "/etc/redactr/ca.crt"
)

// InjectionArgs returns the launch-time mount/env flags for `run`.
func InjectionArgs(s Spec) []string {
	port := portOf(s.ProxyAddr)
	proxyURL := "http://" + proxyHostAlias + ":" + port
	return []string{
		"--add-host", proxyHostAlias + ":host-gateway",
		"-v", s.ProjectDir + ":" + workMount,
		"-w", workMount,
		"-v", s.CACertPath + ":" + caInContainer + ":ro",
		"-e", "HTTPS_PROXY=" + proxyURL,
		"-e", "HTTP_PROXY=" + proxyURL,
		"-e", "https_proxy=" + proxyURL,
		"-e", "http_proxy=" + proxyURL,
		"-e", "NODE_EXTRA_CA_CERTS=" + caInContainer,
		"-e", "REQUESTS_CA_BUNDLE=" + caInContainer,
		"-e", "SSL_CERT_FILE=" + caInContainer,
		"-e", "REDACTR_BOUND=1",
		"-e", "REDACTR_PROXY_HOST=" + proxyHostAlias,
		"-e", "REDACTR_PROXY_PORT=" + port,
	}
}

func portOf(hostPort string) string {
	if i := strings.LastIndex(hostPort, ":"); i >= 0 {
		return hostPort[i+1:]
	}
	return hostPort
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sandbox/ -run TestInjectionArgs -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sandbox/inject.go internal/sandbox/inject_test.go
git commit -m "feat(sandbox): launch-time CA, mount, and proxy/env injection"
```

---

## Task 6: Engine.Launch (ephemeral-tty) — compose & run

**Files:**
- Create: `internal/sandbox/engine.go`
- Test: `internal/sandbox/engine_test.go`

A `commandRunner` seam makes argv assertable without invoking Docker. Real runs use an interactive TTY runner.

- [ ] **Step 1: Write the failing test**

```go
package sandbox

import (
	"context"
	"strings"
	"testing"
)

type captureRunner struct{ argv []string }

func (c *captureRunner) Run(_ context.Context, argv []string) error {
	c.argv = argv
	return nil
}

func TestEngineLaunchComposesArgv(t *testing.T) {
	cap := &captureRunner{}
	eng := &Engine{Runtime: cliRuntime{bin: "docker"}, Runner: cap}

	spec := Spec{
		Mode:       ModeEphemeralTTY,
		Image:      "redactr-base:local",
		ProjectDir: "/home/u/proj",
		Entrypoint: []string{"claude", "--version"},
		ProxyAddr:  "127.0.0.1:47474",
		CACertPath: "/home/u/.redactr/certs/ca.crt",
	}
	if err := eng.Launch(context.Background(), spec); err != nil {
		t.Fatalf("Launch: %v", err)
	}
	got := strings.Join(cap.argv, " ")

	for _, w := range []string{
		"docker run",
		"--rm",            // ephemeral
		"-it",             // tty
		"--cap-drop ALL",  // hardening present
		"-v /home/u/proj:/work",
		"-e REDACTR_BOUND=1",
		"redactr-base:local claude --version", // image then entrypoint, in order
	} {
		if !strings.Contains(got, w) {
			t.Errorf("argv missing %q\ngot: %s", w, got)
		}
	}
	if strings.Index(got, "redactr-base:local") > strings.Index(got, "claude --version") {
		t.Errorf("image must come before entrypoint\ngot: %s", got)
	}
}

func TestEngineLaunchRejectsUnsupportedMode(t *testing.T) {
	eng := &Engine{Runtime: cliRuntime{bin: "docker"}, Runner: &captureRunner{}}
	err := eng.Launch(context.Background(), Spec{Mode: ModeStdioAttached, Image: "x", ProjectDir: "/p", Entrypoint: []string{"y"}})
	if err == nil {
		t.Fatal("expected error for unsupported mode")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sandbox/ -run TestEngineLaunch -v`
Expected: FAIL — `undefined: Engine`.

- [ ] **Step 3: Write minimal implementation**

```go
package sandbox

import (
	"context"
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

// Launch validates the spec, composes the full argv, and runs it.
func (e *Engine) Launch(ctx context.Context, s Spec) error {
	if err := s.Validate(); err != nil {
		return err
	}
	// SEAM: verify image signature/digest here (subsystem A).

	flags := []string{"--rm", "-it"}
	flags = append(flags, HardeningArgs(e.Runtime.Name())...)
	flags = append(flags, InjectionArgs(s)...)

	argv := e.Runtime.RunArgs(flags, s.Image, s.Entrypoint)
	return e.Runner.Run(ctx, argv)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sandbox/ -run TestEngineLaunch -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sandbox/engine.go internal/sandbox/engine_test.go
git commit -m "feat(sandbox): Engine.Launch composes ephemeral-tty container run"
```

---

## Task 7: Local redactr-base image + entrypoint stub

**Files:**
- Create: `build/sandbox/Dockerfile.base`
- Create: `build/sandbox/redactr-entrypoint.sh`
- Modify: `Makefile` (add `sandbox-image` target)

The entrypoint is a **stub here** (just `exec "$@"`); Task 10 adds the redirect. This stands in for subsystem A's central build (`// SEAM`).

- [ ] **Step 1: Write the Dockerfile**

`build/sandbox/Dockerfile.base`:

```dockerfile
# redactr-base — hardened sandbox base (local stand-in for subsystem A's
# central build+sign+registry pipeline).
FROM node:22-bookworm-slim

# The "few binaries": git, python, build toolchain, iptables (Task 10), su-exec.
RUN apt-get update && apt-get install -y --no-install-recommends \
      git python3 python3-pip build-essential ca-certificates iptables curl gosu \
    && rm -rf /var/lib/apt/lists/*

# Claude CLI (the first agent we prove end-to-end).
RUN npm install -g @anthropic-ai/claude-code

# Unprivileged run user; entrypoint drops to this after netns setup.
RUN useradd -m -u 1000 redactr

COPY redactr-entrypoint.sh /usr/local/bin/redactr-entrypoint
RUN chmod +x /usr/local/bin/redactr-entrypoint

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/redactr-entrypoint"]
```

- [ ] **Step 2: Write the entrypoint stub**

`build/sandbox/redactr-entrypoint.sh`:

```sh
#!/bin/sh
set -e
# SEAM (Task 10): install iptables transparent redirect (80/443 -> proxy) and
# drop all other egress here, while we still hold NET_ADMIN as root.

# Drop privileges to the unprivileged user and exec the agent.
exec gosu redactr "$@"
```

- [ ] **Step 3: Add the Makefile target**

Append to `Makefile`:

```makefile
.PHONY: sandbox-image
sandbox-image:
	docker build -t redactr-base:local -f build/sandbox/Dockerfile.base build/sandbox
```

- [ ] **Step 4: Build the image to verify it succeeds**

Run: `make sandbox-image`
Expected: build completes; `docker run --rm redactr-base:local claude --version` prints a version (network not required for `--version`).

- [ ] **Step 5: Commit**

```bash
git add build/sandbox/Dockerfile.base build/sandbox/redactr-entrypoint.sh Makefile
git commit -m "build(sandbox): local redactr-base image + entrypoint stub"
```

---

## Task 8: Wire `redactr claude` into the CLI

**Files:**
- Create: `internal/cli/agent.go`
- Test: `internal/cli/agent_test.go`
- Modify: `cmd/redactr/main.go:40-58` (subcommand dispatch)

- [ ] **Step 1: Write the failing test**

```go
package cli

import "testing"

func TestKnownAgentImage(t *testing.T) {
	tests := []struct {
		tool    string
		ok      bool
		entry0  string
	}{
		{"claude", true, "claude"},
		{"codex", true, "codex"},
		{"copilot", true, "copilot"},
		{"unknown", false, ""},
	}
	for _, tt := range tests {
		entry, ok := knownAgentEntrypoint(tt.tool)
		if ok != tt.ok {
			t.Fatalf("%s: ok = %v, want %v", tt.tool, ok, tt.ok)
		}
		if ok && entry[0] != tt.entry0 {
			t.Errorf("%s: entry[0] = %q, want %q", tt.tool, entry[0], tt.entry0)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli/ -run TestKnownAgent -v`
Expected: FAIL — `undefined: knownAgentEntrypoint`.

- [ ] **Step 3: Write minimal implementation**

`internal/cli/agent.go`:

```go
package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/redactrai/redactr/internal/sandbox"
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

// RunAgent launches a known agent CLI inside a hardened sandbox container,
// passing through extra args. Returns an error if the agent is unknown or the
// proxy is not running.
func RunAgent(baseDir, tool string, extraArgs []string) error {
	entry, ok := knownAgentEntrypoint(tool)
	if !ok {
		return fmt.Errorf("unknown agent %q", tool)
	}
	proxyAddr, caPath, err := sandbox.Discover(baseDir)
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	eng, err := sandbox.NewEngine()
	if err != nil {
		return err
	}
	spec := sandbox.Spec{
		Mode:       sandbox.ModeEphemeralTTY,
		Image:      "redactr-base:local", // SEAM: from server policy bundle (subsystem A)
		ProjectDir: cwd,
		Entrypoint: append(entry, extraArgs...),
		ProxyAddr:  proxyAddr,
		CACertPath: caPath,
	}
	return eng.Launch(context.Background(), spec)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cli/ -run TestKnownAgent -v`
Expected: PASS.

- [ ] **Step 5: Wire the dispatch in main.go**

In `cmd/redactr/main.go`, inside the `switch os.Args[1]` block (after the `case "shell":` block, around line 57), add:

```go
		case "claude", "codex", "copilot":
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("cannot determine home directory: %v", err)
			}
			if err := cli.RunAgent(filepath.Join(home, ".redactr"), os.Args[1], os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
			return
```

- [ ] **Step 6: Build to verify it compiles**

Run: `go build ./... && go vet ./internal/sandbox/ ./internal/cli/`
Expected: no output (success).

- [ ] **Step 7: Commit**

```bash
git add internal/cli/agent.go internal/cli/agent_test.go cmd/redactr/main.go
git commit -m "feat(cli): redactr claude/codex/copilot launch agents in sandbox"
```

---

## Task 9: End-to-end integration test (proxy transit)

**Files:**
- Create: `test/integration/sandbox_test.go`

Build-tagged like the existing integration suite. Skips cleanly when Docker or the image is absent.

- [ ] **Step 1: Write the test**

```go
//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/redactrai/redactr/internal/sandbox"
)

// TestSandboxReachesProxyAlias verifies a container launched by the engine can
// resolve the host-gateway alias and that HTTPS_PROXY is set inside it.
func TestSandboxReachesProxyAlias(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "image", "inspect", "redactr-base:local").Run(); err != nil {
		t.Skip("redactr-base:local not built (run `make sandbox-image`)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Compose the same way the engine does, but capture stdout.
	flags := []string{"--rm"}
	flags = append(flags, sandbox.HardeningArgs("docker")...)
	flags = append(flags, sandbox.InjectionArgs(sandbox.Spec{
		ProjectDir: t.TempDir(),
		ProxyAddr:  "127.0.0.1:47474",
		CACertPath: caFixture(t),
	})...)
	argv := append(append([]string{"docker", "run"}, flags...),
		"redactr-base:local", "sh", "-c", "echo PROXY=$HTTPS_PROXY")

	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PROXY=http://host.docker.internal:47474") {
		t.Fatalf("HTTPS_PROXY not injected, got: %s", out)
	}
}
```

Add the `caFixture` helper at the bottom of the file:

```go
func caFixture(t *testing.T) string {
	t.Helper()
	p := t.TempDir() + "/ca.crt"
	if err := os.WriteFile(p, []byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
```

- [ ] **Step 2: Build the image (prerequisite)**

Run: `make sandbox-image`
Expected: image `redactr-base:local` exists.

- [ ] **Step 3: Run the integration test**

Run: `go test ./test/integration/ -tags=integration -run TestSandboxReachesProxyAlias -v`
Expected: PASS (or SKIP if docker absent). The container prints `PROXY=http://host.docker.internal:47474`.

- [ ] **Step 4: Commit**

```bash
git add test/integration/sandbox_test.go
git commit -m "test(sandbox): integration test asserts proxy env injection in container"
```

---

## Task 10: Transparent egress redirect + drop (entrypoint)

**Files:**
- Modify: `build/sandbox/redactr-entrypoint.sh`
- Create: `test/integration/sandbox_egress_test.go`

This is the real exfil boundary: even a raw socket (ignoring `HTTPS_PROXY`) is forced through the proxy; all non-proxy, non-DNS egress is dropped. Runs while the entrypoint still holds `NET_ADMIN`, before dropping to `redactr`.

- [ ] **Step 1: Replace the entrypoint with the redirect logic**

`build/sandbox/redactr-entrypoint.sh`:

```sh
#!/bin/sh
set -e

PROXY_HOST="${REDACTR_PROXY_HOST:-host.docker.internal}"
PROXY_PORT="${REDACTR_PROXY_PORT:-47474}"

# Resolve the host-gateway alias to an IP for NAT rules.
PROXY_IP="$(getent hosts "$PROXY_HOST" | awk '{print $1; exit}')"

if [ -n "$PROXY_IP" ]; then
	# Redirect all outbound TCP 80/443 to the local proxy on the host gateway.
	iptables -t nat -A OUTPUT -p tcp --dport 80  -j DNAT --to-destination "$PROXY_IP:$PROXY_PORT"
	iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination "$PROXY_IP:$PROXY_PORT"

	# Allow loopback, DNS, and the proxy itself; drop everything else outbound.
	iptables -A OUTPUT -o lo -j ACCEPT
	iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
	iptables -A OUTPUT -d "$PROXY_IP" -p tcp --dport "$PROXY_PORT" -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 80  -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
	# SEAM: admin port-allowlist (e.g. 22 for SSH git) inserted here from policy.
	iptables -A OUTPUT -p tcp -j DROP
else
	echo "redactr: WARNING could not resolve $PROXY_HOST; egress redirect not installed" >&2
fi

# Drop NET_ADMIN-holding root; run the agent unprivileged.
exec gosu redactr "$@"
```

- [ ] **Step 2: Rebuild the image**

Run: `make sandbox-image`
Expected: build succeeds.

- [ ] **Step 3: Write the egress integration test**

`test/integration/sandbox_egress_test.go`:

```go
//go:build integration

package integration

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestEgressDroppedOnOddPort verifies non-80/443/53 egress is blocked by the
// entrypoint's iptables rules (the raw-socket exfil boundary).
func TestEgressDroppedOnOddPort(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "image", "inspect", "redactr-base:local").Run(); err != nil {
		t.Skip("redactr-base:local not built")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Attempt an outbound TCP connection on an odd port; expect it to fail fast.
	argv := []string{
		"docker", "run", "--rm",
		"--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "REDACTR_PROXY_HOST=host.docker.internal",
		"-e", "REDACTR_PROXY_PORT=47474",
		"redactr-base:local",
		"sh", "-c", "curl -m 5 -s -o /dev/null http://example.com:9999 && echo REACHED || echo BLOCKED",
	}
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "BLOCKED") {
		t.Fatalf("expected odd-port egress to be BLOCKED, got: %s", out)
	}
}
```

- [ ] **Step 4: Run the egress test**

Run: `go test ./test/integration/ -tags=integration -run TestEgressDroppedOnOddPort -v`
Expected: PASS (or SKIP without docker). Output contains `BLOCKED`.

- [ ] **Step 5: Commit**

```bash
git add build/sandbox/redactr-entrypoint.sh test/integration/sandbox_egress_test.go
git commit -m "feat(sandbox): transparent egress redirect + drop in entrypoint"
```

---

## Final verification

- [ ] **Run the full unit suite**

Run: `go test ./internal/sandbox/ ./internal/cli/ -v`
Expected: all PASS.

- [ ] **Run integration (with docker + image)**

Run: `make sandbox-image && go test ./test/integration/ -tags=integration -run TestSandbox -v && go test ./test/integration/ -tags=integration -run TestEgress -v`
Expected: PASS.

- [ ] **Manual smoke**

With the daemon running (`redactr` in another terminal, proxy enabled so `~/.redactr/state/proxy.pid` exists), in a project dir run:

```bash
redactr claude
```

Expected: a Claude session starts inside the container; its API traffic appears in the Redactr dashboard logs (scanned/redacted); `REDACTR_BOUND=1` is set. Files edited in the session appear in the host project dir (bind mount). Nothing outside the project dir is visible to the container.

---

## Self-Review notes (coverage map)

- **Runtime abstraction (Docker/Podman/Colima):** Tasks 3 (Detect), 4 (per-runtime flags). Colima covered by the `docker` driver.
- **Hardening profile:** Task 4 + asserted absence of `--privileged`/`docker.sock`/host-net.
- **Transparent redirect to local proxy:** Task 10 entrypoint + Task 9 env path; reuses v1 proxy (Discover, Task 2).
- **CA + mount injection at launch:** Task 5.
- **`Sandbox.Launch` ephemeral-tty:** Task 6; `redactr claude` end-to-end Tasks 8–9.
- **Reuse v1 proxy/scanner + internal/domain:** Discover reads the proxy the v1 daemon already runs; denylist enforced unchanged at that proxy (no new code here).
- **Deferred seams:** stdio/workspace modes (Task 1 enum + Task 6 reject), central signed image (Tasks 6/8 comments + Task 7 local stand-in), admin port-allowlist (Task 10 comment).
