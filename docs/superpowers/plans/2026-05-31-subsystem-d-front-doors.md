# Front Doors (D) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. **Final v2 subsystem.**

**Goal:** `redactr code <project>` (Dev Container sandboxing every VS Code AI plugin — the Copilot gate) and `redactr-mcp-wrap --container` (MCP server in a redactr container), implementing the sandbox `ModeStdioAttached` SEAM. Orchestration is unit-tested; real `devcontainer up` / VS Code attach / `docker run -i` execution is deferred.

**Architecture:** `internal/devcontainer.Generate` produces a `.devcontainer/devcontainer.json` from the launch policy + CA. `redactr code` preflights (like `RunAgent`), writes that file, and invokes the `devcontainer` CLI via a runner seam. The sandbox engine gains `StdioRunArgs` (`docker run --rm -i …`). `redactr-mcp-wrap --container` builds the stdio container argv and runs it as the child of its existing JSON-RPC redaction MITM.

**Tech Stack:** Go 1.26 stdlib; reuses `internal/sandbox` (HardeningArgs/InjectionArgs/Engine) and `internal/cli` (EnsureDaemon/Client).

**Verification bar:** `go build ./...`, `go test ./internal/... ` + full suite green, `go vet ./...`, `CGO_ENABLED=0 GOOS=windows go build ./cmd/redactr/`. Real devcontainer/Docker execution deferred (documented).

---

## Task 1: `internal/devcontainer.Generate`

**Files:** Create `internal/devcontainer/devcontainer.go`, `internal/devcontainer/devcontainer_test.go`.

- [ ] **Step 1: failing test**
```go
package devcontainer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	raw, err := Generate(GenerateInput{
		Image: "reg/acme/tools@sha256:abc", ProxyAddr: "127.0.0.1:47474", CACertPath: "/home/u/.redactr/certs/ca.crt",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var dc struct {
		Image        string            `json:"image"`
		ContainerEnv map[string]string `json:"containerEnv"`
		Mounts       []string          `json:"mounts"`
		RunArgs      []string          `json:"runArgs"`
	}
	if err := json.Unmarshal(raw, &dc); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, raw)
	}
	if dc.Image != "reg/acme/tools@sha256:abc" {
		t.Errorf("image = %q", dc.Image)
	}
	if dc.ContainerEnv["HTTPS_PROXY"] != "http://host.docker.internal:47474" {
		t.Errorf("HTTPS_PROXY = %q", dc.ContainerEnv["HTTPS_PROXY"])
	}
	if dc.ContainerEnv["REDACTR_BOUND"] != "1" || dc.ContainerEnv["NODE_EXTRA_CA_CERTS"] != "/etc/redactr/ca.crt" {
		t.Errorf("env = %+v", dc.ContainerEnv)
	}
	if len(dc.Mounts) == 0 || !strings.Contains(dc.Mounts[0], "/home/u/.redactr/certs/ca.crt") {
		t.Errorf("mounts = %v", dc.Mounts)
	}
	ra := strings.Join(dc.RunArgs, " ")
	if !strings.Contains(ra, "--cap-drop ALL") || !strings.Contains(ra, "host.docker.internal:host-gateway") {
		t.Errorf("runArgs = %v", dc.RunArgs)
	}
}
```
Run `go test ./internal/devcontainer/ -v` → FAIL.

- [ ] **Step 2: implement `internal/devcontainer/devcontainer.go`**
```go
// Package devcontainer generates a .devcontainer/devcontainer.json that runs a
// project's VS Code workspace (extension host + terminal) inside a redactr
// container: pinned image, proxy/CA env, CA mount, and the hardening profile.
package devcontainer

import (
	"encoding/json"
	"strings"

	"github.com/rakeshguha/redactr/internal/sandbox"
)

// GenerateInput is the resolved launch policy needed to render a devcontainer.
type GenerateInput struct {
	Image      string
	ProxyAddr  string // host:port of the local proxy
	CACertPath string // host path to ca.crt
}

const (
	hostAlias     = "host.docker.internal"
	caInContainer = "/etc/redactr/ca.crt"
)

func portOf(hostPort string) string {
	if i := strings.LastIndex(hostPort, ":"); i >= 0 {
		return hostPort[i+1:]
	}
	return hostPort
}

// Generate renders the devcontainer.json bytes.
func Generate(in GenerateInput) ([]byte, error) {
	port := portOf(in.ProxyAddr)
	proxyURL := "http://" + hostAlias + ":" + port
	runArgs := append([]string{"--add-host", hostAlias + ":host-gateway"}, sandbox.HardeningArgs("docker")...)
	dc := map[string]any{
		"name":  "redactr",
		"image": in.Image,
		"containerEnv": map[string]string{
			"HTTPS_PROXY":         proxyURL,
			"HTTP_PROXY":          proxyURL,
			"https_proxy":         proxyURL,
			"http_proxy":          proxyURL,
			"NODE_EXTRA_CA_CERTS": caInContainer,
			"REQUESTS_CA_BUNDLE":  caInContainer,
			"SSL_CERT_FILE":       caInContainer,
			"REDACTR_BOUND":       "1",
			"REDACTR_PROXY_HOST":  hostAlias,
			"REDACTR_PROXY_PORT":  port,
		},
		"mounts": []string{
			"source=" + in.CACertPath + ",target=" + caInContainer + ",type=bind,readonly",
		},
		"runArgs": runArgs,
	}
	return json.MarshalIndent(dc, "", "  ")
}
```
Run → PASS. Commit:
```bash
git add internal/devcontainer/
git commit -m "feat(devcontainer): generate devcontainer.json (image+proxy+CA+hardening)"
```

---

## Task 2: `redactr code` CLI

**Files:** Create `internal/cli/code.go`, `internal/cli/code_test.go`. Modify `cmd/redactr/main.go`.

- [ ] **Step 1: failing test (`internal/cli/code_test.go`)**
```go
package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteDevcontainerRefusesClobber(t *testing.T) {
	proj := t.TempDir()
	p, err := writeDevcontainer(proj, []byte(`{"x":1}`), false)
	if err != nil || p == "" {
		t.Fatalf("writeDevcontainer: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("file not written: %v", err)
	}
	// Second write without force → refused.
	if _, err := writeDevcontainer(proj, []byte(`{"x":2}`), false); err == nil {
		t.Error("expected clobber refusal without --force")
	}
	// With force → overwrites.
	if _, err := writeDevcontainer(proj, []byte(`{"x":3}`), true); err != nil {
		t.Errorf("force write: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(proj, ".devcontainer", "devcontainer.json"))
	if string(b) != `{"x":3}` {
		t.Errorf("content = %s", b)
	}
}

func TestLaunchDevcontainerInvokesCLI(t *testing.T) {
	var got []string
	run := func(name string, args ...string) error { got = append([]string{name}, args...); return nil }
	if err := launchDevcontainer("/proj", run); err != nil {
		t.Fatalf("launchDevcontainer: %v", err)
	}
	if len(got) < 3 || got[0] != "devcontainer" || got[1] != "up" || got[len(got)-1] != "/proj" {
		t.Fatalf("argv = %v", got)
	}
}
```
Run `go test ./internal/cli/ -run 'TestWriteDevcontainer|TestLaunchDevcontainer' -v` → FAIL.

- [ ] **Step 2: implement `internal/cli/code.go`**
```go
package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/rakeshguha/redactr/internal/devcontainer"
)

type cmdRunner func(name string, args ...string) error

func execRun(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	return cmd.Run()
}

// writeDevcontainer writes content to <project>/.devcontainer/devcontainer.json,
// refusing to overwrite an existing file unless force is set. Returns the path.
func writeDevcontainer(project string, content []byte, force bool) (string, error) {
	dir := filepath.Join(project, ".devcontainer")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "devcontainer.json")
	if !force {
		if _, err := os.Stat(path); err == nil {
			return "", fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
	}
	return path, os.WriteFile(path, content, 0o644)
}

// launchDevcontainer invokes the devcontainer CLI to open the workspace.
func launchDevcontainer(project string, run cmdRunner) error {
	return run("devcontainer", "up", "--workspace-folder", project)
}

// RunCode generates a redactr devcontainer for the project and opens it. It
// preflights the daemon + proxy + launch policy exactly like RunAgent.
func RunCode(baseDir, project string, force bool) error {
	if project == "" {
		project = "."
	}
	abs, err := filepath.Abs(project)
	if err != nil {
		return err
	}
	sockDir := filepath.Join(baseDir, "state")
	if err := EnsureDaemon(sockDir); err != nil {
		return err
	}
	client := NewClient(sockDir)
	if _, err := client.EnableProxy(); err != nil {
		return fmt.Errorf("could not enable proxy: %w", err)
	}
	info, err := client.LaunchPolicy("code")
	if err != nil {
		return fmt.Errorf("could not fetch launch policy: %w", err)
	}
	content, err := devcontainer.Generate(devcontainer.GenerateInput{
		Image: info.Image, ProxyAddr: info.ProxyAddr, CACertPath: filepath.Join(baseDir, "certs", "ca.crt"),
	})
	if err != nil {
		return err
	}
	path, err := writeDevcontainer(abs, content, force)
	if err != nil {
		return err
	}
	if _, err := exec.LookPath("devcontainer"); err != nil {
		fmt.Fprintf(os.Stderr, "wrote %s\nOpen this folder in VS Code and choose \"Reopen in Container\".\n", path)
		return nil
	}
	fmt.Fprintf(os.Stderr, "wrote %s — starting dev container…\n", path)
	return launchDevcontainer(abs, execRun)
}
```

- [ ] **Step 3: wire `cmd/redactr/main.go`** — add a `case "code":` in the subcommand switch (`"flag"` already imported from the enroll subcommand):
```go
		case "code":
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("cannot determine home directory: %v", err)
			}
			fs := flag.NewFlagSet("code", flag.ExitOnError)
			force := fs.Bool("force", false, "overwrite an existing .devcontainer/devcontainer.json")
			_ = fs.Parse(os.Args[2:])
			project := fs.Arg(0)
			if err := cli.RunCode(filepath.Join(home, ".redactr"), project, *force); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
			return
```

- [ ] **Step 4: verify + commit**
Run: `go test ./internal/cli/ -v && go build ./... && go vet ./internal/cli/`
```bash
git add internal/cli/code.go internal/cli/code_test.go cmd/redactr/main.go
git commit -m "feat(cli): redactr code — generate + open a redactr dev container"
```

---

## Task 3: sandbox `StdioRunArgs` (implement the `ModeStdioAttached` SEAM)

**Files:** Modify `internal/sandbox/spec.go` (Validate), `internal/sandbox/engine.go` (StdioRunArgs). Test: append to `engine_test.go`.

- [ ] **Step 1: failing test (append to `internal/sandbox/engine_test.go`)**
```go
func TestStdioRunArgs(t *testing.T) {
	eng := &Engine{Runtime: cliRuntime{bin: "docker"}}
	argv, err := eng.StdioRunArgs(Spec{
		Mode: ModeStdioAttached, Image: "redactr-base:local", ProjectDir: "/home/u/proj",
		Entrypoint: []string{"mcp-server", "--flag"}, ProxyAddr: "127.0.0.1:47474", CACertPath: "/ca.crt",
	})
	if err != nil {
		t.Fatalf("StdioRunArgs: %v", err)
	}
	got := strings.Join(argv, " ")
	if !strings.Contains(got, "docker run --rm -i ") || strings.Contains(got, "-it") {
		t.Errorf("expected --rm -i (no tty): %s", got)
	}
	for _, w := range []string{"--cap-drop ALL", "-v /home/u/proj:/work", "redactr-base:local mcp-server --flag"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in %s", w, got)
		}
	}
}
```
Run `go test ./internal/sandbox/ -run TestStdioRunArgs -v` → FAIL.

- [ ] **Step 2: `internal/sandbox/spec.go` — accept `ModeStdioAttached`**
Change the Validate mode check from:
```go
	if s.Mode != ModeEphemeralTTY {
		return fmt.Errorf("sandbox: mode %q not implemented in this build", s.Mode)
	}
```
to:
```go
	if s.Mode != ModeEphemeralTTY && s.Mode != ModeStdioAttached {
		return fmt.Errorf("sandbox: mode %q not implemented in this build", s.Mode)
	}
```

- [ ] **Step 3: `internal/sandbox/engine.go` — add `StdioRunArgs`**
```go
// StdioRunArgs composes the argv for a stdio-attached container (MCP servers):
// `<runtime> run --rm -i` + hardening + injection + image + entrypoint. The
// caller execs this argv and pipes the container's stdin/stdout (no TTY).
func (e *Engine) StdioRunArgs(s Spec) ([]string, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	flags := []string{"--rm", "-i"}
	flags = append(flags, HardeningArgs(e.Runtime.Name())...)
	s.HostAlias = hostAliasFor(e.Runtime.Name())
	flags = append(flags, InjectionArgs(s)...)
	return e.Runtime.RunArgs(flags, s.Image, s.Entrypoint), nil
}
```

- [ ] **Step 4: verify + commit**
Run: `go test ./internal/sandbox/ -v && go vet ./internal/sandbox/ && go build ./...`
```bash
git add internal/sandbox/spec.go internal/sandbox/engine.go internal/sandbox/engine_test.go
git commit -m "feat(sandbox): StdioRunArgs — stdio-attached container argv (MCP mode)"
```

---

## Task 4: `redactr-mcp-wrap --container`

**Files:** Modify `cmd/redactr-mcp-wrap/main.go`. Test: create `cmd/redactr-mcp-wrap/main_test.go`.

- [ ] **Step 1: failing test (`cmd/redactr-mcp-wrap/main_test.go`)**
```go
package main

import (
	"reflect"
	"testing"
)

func TestResolveChild(t *testing.T) {
	fakeContainer := func(image string, entry []string) ([]string, error) {
		return append([]string{"docker", "run", "--rm", "-i", image}, entry...), nil
	}

	// No --container: the command runs as a host child unchanged.
	got, err := resolveChild([]string{"my-mcp", "--port", "0"}, fakeContainer)
	if err != nil || !reflect.DeepEqual(got, []string{"my-mcp", "--port", "0"}) {
		t.Fatalf("host child argv = %v err=%v", got, err)
	}

	// --container: wrap in a container with the default image.
	got, err = resolveChild([]string{"--container", "my-mcp", "--port", "0"}, fakeContainer)
	if err != nil || !reflect.DeepEqual(got, []string{"docker", "run", "--rm", "-i", "redactr-base:local", "my-mcp", "--port", "0"}) {
		t.Fatalf("container argv = %v err=%v", got, err)
	}

	// --container --image X: custom image.
	got, _ = resolveChild([]string{"--container", "--image", "reg/x@sha256:abc", "my-mcp"}, fakeContainer)
	if got[4] != "reg/x@sha256:abc" || got[5] != "my-mcp" {
		t.Fatalf("custom image argv = %v", got)
	}
}
```
Run `go test ./cmd/redactr-mcp-wrap/ -run TestResolveChild -v` → FAIL.

- [ ] **Step 2: add `resolveChild` to `cmd/redactr-mcp-wrap/main.go`**
```go
// resolveChild decides the child process argv. Default: run the given command
// as a host child (unchanged, backward compatible). With a leading "--container"
// (optionally "--image <ref>"), the command runs inside a redactr container via
// the provided containerArgv builder.
func resolveChild(args []string, containerArgv func(image string, entrypoint []string) ([]string, error)) ([]string, error) {
	if len(args) == 0 || args[0] != "--container" {
		return args, nil
	}
	args = args[1:]
	image := "redactr-base:local" // SEAM: use the daemon's launch-policy image when enrolled
	if len(args) >= 2 && args[0] == "--image" {
		image, args = args[1], args[2:]
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("redactr-mcp-wrap --container: missing MCP server command")
	}
	return containerArgv(image, args)
}
```

- [ ] **Step 3: wire `main()` to use `resolveChild`**
Replace the line that builds the child command:
```go
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
```
with a resolve step that builds the container argv from the sandbox engine + daemon state:
```go
	childArgv, err := resolveChild(os.Args[1:], func(image string, entry []string) ([]string, error) {
		home, _ := os.UserHomeDir()
		base := filepath.Join(home, ".redactr")
		proxyAddr, caPath, derr := sandbox.Discover(base)
		if derr != nil {
			return nil, derr
		}
		cwd, _ := os.Getwd()
		eng, eerr := sandbox.NewEngine()
		if eerr != nil {
			return nil, eerr
		}
		return eng.StdioRunArgs(sandbox.Spec{
			Mode: sandbox.ModeStdioAttached, Image: image, ProjectDir: cwd,
			Entrypoint: entry, ProxyAddr: proxyAddr, CACertPath: caPath,
		})
	})
	if err != nil {
		log.Fatalf("redactr-mcp-wrap: %v", err)
	}
	cmd := exec.Command(childArgv[0], childArgv[1:]...)
```
Add imports `"path/filepath"` and `"github.com/rakeshguha/redactr/internal/sandbox"`. (The MITM loop below — `mcpwrap.ScanMessage` over stdin/stdout — is unchanged.)

- [ ] **Step 4: verify + commit**
Run: `go test ./cmd/redactr-mcp-wrap/ -v && go build ./... && go vet ./cmd/redactr-mcp-wrap/ && go test ./internal/... 2>&1 | grep -v "no test files"`
```bash
git add cmd/redactr-mcp-wrap/main.go cmd/redactr-mcp-wrap/main_test.go
git commit -m "feat(mcp-wrap): --container runs the MCP server in a redactr container (stdio)"
```

---

## Final verification
```bash
go build ./... && go test ./internal/... ./cmd/... 2>&1 | grep -v "no test files" && go vet ./... \
  && CGO_ENABLED=0 GOOS=windows go build ./cmd/redactr/ ./cmd/redactr-mcp-wrap/
```

**Deferred (documented):** real `devcontainer up` / VS Code "Reopen in Container" attach and the `docker run -i` MCP-server container run, on a Docker + VS Code host.

## Self-Review map
- devcontainer.json generation → T1; `redactr code` preflight + write + invoke (clobber-guard + runner seam tested) → T2; sandbox stdio-attached argv (`--rm -i`, Validate accepts the mode) → T3; `redactr-mcp-wrap --container` backward-compatible wiring (resolveChild tested host + container paths) → T4. Real devcontainer/Docker execution deferred. MCP image-pin to A3 policy = a `// SEAM`.
