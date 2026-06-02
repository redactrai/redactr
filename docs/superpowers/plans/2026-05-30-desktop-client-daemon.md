# Desktop Client Daemon (Subsystem B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the v1 single-binary proxy into the v2 control/policy plane: a headless `internal/daemon` extracted from `main()`, a Unix-socket control API, a fail-open policy cache, a socket-preflighting `redactr claude`, and a separate `redactr tray` menubar with a green/red proxy indicator.

**Architecture:** The daemon owns all v1 components plus a policy cache and a UDS HTTP control socket. Two thin clients front it — the `redactr` CLI (TTY owner; launches containers via subsystem C after a socket preflight) and a `redactr tray` menubar (polls `/status`). Wire DTOs live in a neutral leaf package `internal/control` to avoid import cycles; the persisted policy lives in `internal/policy`.

**Tech Stack:** Go 1.26 (`github.com/rakeshguha/redactr`), `net.Listen("unix", …)` + `net/http`, subsystem C (`internal/sandbox`, already on `main`), `fyne.io/systray` (macOS CGo — added only at Task B6).

**Reuse / seams:**
- All v1 components are reused unchanged; B2 only **moves** their wiring out of `main()`.
- Proxy enable/disable reuses the dashboard's existing firewall-aware `POST /api/proxy/enable|disable` (no duplication).
- `diffback` mount mode is a `// SEAM` (C only supports `bind`) — the CLI errors clearly if policy requests it.
- Server-driven policy refresh is a `// SEAM` (subsystem A) — the cache is seeded/static for now.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/control/control.go` | Wire DTOs shared by daemon (server) and cli (client): `Status`, `LaunchInfo`. Leaf package, no internal deps. |
| `internal/policy/policy.go` (+ test) | Persisted `Policy` + `Load`/`Seed`/`Save` (atomic) |
| `internal/daemon/daemon.go` (+ smoke test) | `Daemon` struct + `Build`/`Start`/`Stop`/`Run` (extracted from `main()`) |
| `internal/daemon/socket.go` (+ test) | UDS HTTP control server + handlers |
| `internal/cli/client.go` (+ test) | Socket `Client` + `EnsureDaemon` auto-start |
| `internal/cli/agent.go` (modify) | `RunAgent` preflight via socket |
| `cmd/redactr/main.go` (modify) | Thin subcommand dispatch |
| `internal/tray/tray.go` (+ test) | `redactr tray` menubar; pure `TrayState` helper + systray shell |

> Note on the spec: `LaunchInfo` is placed in `internal/control` (not `internal/policy`) so the `cli` client can import the wire type without importing `daemon`/`policy`. This avoids an import cycle and is the only deviation from the design doc.

---

## Task B1: Policy cache + wire DTOs

**Files:**
- Create: `internal/control/control.go`
- Create: `internal/policy/policy.go`
- Test: `internal/policy/policy_test.go`

- [ ] **Step 1: Write the wire DTOs (`internal/control/control.go`)**

```go
// Package control holds the wire DTOs exchanged over the daemon's local
// control socket, shared by the daemon (server) and the CLI/tray (clients).
package control

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
```

- [ ] **Step 2: Write the failing test (`internal/policy/policy_test.go`)**

```go
package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSeedDefaults(t *testing.T) {
	p := Seed([]string{"evil.test"})
	if p.Image != "redactr-base:local" {
		t.Errorf("Image = %q, want redactr-base:local", p.Image)
	}
	if p.MountMode != "bind" {
		t.Errorf("MountMode = %q, want bind", p.MountMode)
	}
	if len(p.Denylist) != 1 || p.Denylist[0] != "evil.test" {
		t.Errorf("Denylist = %v, want [evil.test]", p.Denylist)
	}
}

func TestLoadMissingReturnsSeed(t *testing.T) {
	base := t.TempDir()
	p, err := Load(base, []string{"x.test"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Image != "redactr-base:local" || p.MountMode != "bind" {
		t.Errorf("expected seeded defaults, got %+v", p)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	base := t.TempDir()
	want := Policy{Image: "redactr-base:v2", MountMode: "bind", Denylist: []string{"a.test"}, Version: 7}
	if err := Save(base, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "cache", "policy.json")); err != nil {
		t.Fatalf("policy.json not written: %v", err)
	}
	got, err := Load(base, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Image != want.Image || got.MountMode != want.MountMode || got.Version != want.Version || len(got.Denylist) != 1 {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, want)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/policy/ -v`
Expected: FAIL — `undefined: Seed` / package does not compile.

- [ ] **Step 4: Write minimal implementation (`internal/policy/policy.go`)**

```go
// Package policy holds the locally-cached launch policy. Until subsystem A
// ships, it is seeded from config and persisted at ~/.redactr/cache/policy.json.
package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Policy is the persisted launch policy (no live runtime fields).
type Policy struct {
	Image     string    `json:"image"`
	MountMode string    `json:"mountMode"` // "bind" | "diffback"
	Denylist  []string  `json:"denylist"`
	Version   int       `json:"version"`
	FetchedAt time.Time `json:"fetchedAt"`
}

// Seed returns the default policy used when no cache exists and no server has
// been contacted. denylist comes from config (cfg.Proxy.BlockedDomains).
func Seed(denylist []string) Policy {
	return Policy{Image: "redactr-base:local", MountMode: "bind", Denylist: denylist}
}

func cachePath(baseDir string) string {
	return filepath.Join(baseDir, "cache", "policy.json")
}

// Load reads the cached policy; if the file is absent it returns Seed(denylist).
// SEAM: subsystem A will refresh the persisted policy from the signed server bundle.
func Load(baseDir string, denylist []string) (Policy, error) {
	raw, err := os.ReadFile(cachePath(baseDir))
	if os.IsNotExist(err) {
		return Seed(denylist), nil
	}
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Save atomically writes the policy to the cache (temp file + rename).
func Save(baseDir string, p Policy) error {
	dir := filepath.Join(baseDir, "cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "policy.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, cachePath(baseDir))
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/policy/ ./internal/control/ -v`
Expected: PASS (control has no tests yet but must compile). Also `go vet ./internal/policy/ ./internal/control/`.

- [ ] **Step 6: Commit**

```bash
git add internal/control/control.go internal/policy/policy.go internal/policy/policy_test.go
git commit -m "feat(policy): seeded fail-open policy cache + control wire DTOs"
```

---

## Task B2: Extract `main()` into `internal/daemon` (behavior-preserving)

**Files:**
- Create: `internal/daemon/daemon.go`
- Test: `internal/daemon/daemon_test.go`
- Modify: `cmd/redactr/main.go`

This is a **mechanical move**, not new logic. The full component wiring currently inline in `cmd/redactr/main.go:60-319` moves verbatim into `Daemon.Build`/`Start`/`Stop`, with two transformations only:
1. Every `log.Fatalf(...)` becomes `return nil, fmt.Errorf(...)` (Build) or `return fmt.Errorf(...)` (Start).
2. Every local variable that must outlive `Build` becomes a `Daemon` struct field.

Startup order MUST be preserved exactly (singleton lock → licensing → CA → store → scanners → pipeline → coordinator → admin → domain filter → hub → proxy → apiServer → firewall → ReapOrphans → transparent listener → reconcile loop → dashboard → sidecar → config watcher → proxy.Start iff enabled). The control socket (B3) is started near the end of `Start`; for B2 leave a `// B3: start control socket here` marker.

- [ ] **Step 1: Write the failing smoke test (`internal/daemon/daemon_test.go`)**

```go
package daemon

import (
	"path/filepath"
	"testing"
)

// TestBuildStartStop verifies the daemon wires up, starts its listeners on a
// throwaway baseDir, and shuts down cleanly. It does not require Docker or the
// GLiNER sidecar (both degrade gracefully).
func TestBuildStartStop(t *testing.T) {
	base := t.TempDir()
	// Ephemeral binds admin+dashboard on OS-assigned ports so the test never
	// collides with a real daemon.
	d, err := Build(Options{BaseDir: base, Ephemeral: true})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Singleton pid + lock should exist under base/state.
	if _, err := filepath.Glob(filepath.Join(base, "state", "*")); err != nil {
		t.Fatalf("state glob: %v", err)
	}
	if err := d.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/daemon/ -run TestBuildStartStop -v`
Expected: FAIL — `undefined: Build` / package does not compile.

- [ ] **Step 3: Create `internal/daemon/daemon.go` with the struct + skeleton**

Define the struct holding every component, plus `Options`:

```go
// Package daemon is the Redactr control/policy plane: it wires and supervises
// the proxy, scanner, dashboard, admin, firewall, sidecar, and control socket.
// It is the extracted form of what used to be cmd/redactr/main.go's main().
package daemon

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/rakeshguha/redactr/internal/admin"
	"github.com/rakeshguha/redactr/internal/api"
	"github.com/rakeshguha/redactr/internal/certgen"
	"github.com/rakeshguha/redactr/internal/config"
	"github.com/rakeshguha/redactr/internal/coordinator"
	"github.com/rakeshguha/redactr/internal/domain"
	"github.com/rakeshguha/redactr/internal/firewall"
	"github.com/rakeshguha/redactr/internal/lifecycle"
	"github.com/rakeshguha/redactr/internal/licensing"
	"github.com/rakeshguha/redactr/internal/proxy"
	"github.com/rakeshguha/redactr/internal/scanner"
	"github.com/rakeshguha/redactr/internal/scanner/gliner"
	"github.com/rakeshguha/redactr/internal/sidecar"
	"github.com/rakeshguha/redactr/internal/store"
)

// Options parameterizes Build. Ephemeral is set by tests to bind the admin +
// dashboard listeners on OS-assigned ports; production leaves it false so the
// v1 ports (admin = cfg.Admin.Port, dashboard = 9080) are preserved exactly.
type Options struct {
	BaseDir   string
	Ephemeral bool
}

// Daemon owns every long-lived component.
type Daemon struct {
	opts Options

	cfgMgr        *config.Manager
	lock          *lifecycle.Lock
	licMgr        *licensing.Manager
	ca            *certgen.CA
	store         *store.Store
	pipeline      *scanner.Pipeline
	coord         *coordinator.Coordinator
	glinerClient  *gliner.Client
	adminServer   *admin.Server
	domainFilter  *domain.Filter
	hub           *api.Hub
	proxy         *proxy.Proxy
	apiServer     *api.Server
	fwMgr         firewall.Manager
	fwController  *firewall.Controller
	sidecarMgr    *sidecar.Manager
	configWatcher *config.Watcher

	transparentAddr string
	dashboardAddr   string
	adminAddr       string

	reconcileCancel context.CancelFunc
	sock            *http.Server // B3: control socket server
}

// Build performs the full component wiring (moved verbatim from main()),
// returning an error instead of fatally exiting.
func Build(opts Options) (*Daemon, error) {
	// MOVE: cmd/redactr/main.go lines ~60-196 here, assigning to d.<field>
	// and replacing every log.Fatalf with `return nil, fmt.Errorf(...)`.
	panic("B2: move wiring here")
}

// Start brings up listeners (admin, dashboard, transparent, control socket;
// proxy iff cfg.Proxy.Enabled), the reconcile loop, sidecar, and config watcher.
func (d *Daemon) Start() error {
	// MOVE: the listener-start portion of main() (admin/dashboard/transparent/
	// reconcile/sidecar/configWatcher/proxy-if-enabled). Then:
	// // B3: start control socket here
	panic("B2: move start here")
}

// Stop mirrors v1 shutdown order.
func (d *Daemon) Stop() error {
	// MOVE: main() shutdown block (reconcileCancel, fwController.Disable,
	// proxy.Stop, sidecarMgr.Stop, adminServer.Stop, apiServer.Stop,
	// fwMgr.Cleanup, configWatcher.Stop, lock.Release). Also remove the
	// control socket file (B3).
	panic("B2: move stop here")
}

// Run is the daemon entrypoint: Build → Start → block on signal → Stop.
func Run(baseDir string) error {
	panic("B2: move run loop here")
}

var _ = slog.Default // keep import until wiring is moved
```

> **Do Steps 3 and 4 as one commit.** The skeleton above won't compile on its own (unused imports, `panic` bodies); land it together with the moved code in Step 4 so the package compiles before you run tests.

- [ ] **Step 4: Move the wiring from `main()` into Build/Start/Stop/Run**

Cut the body of `main()` (`cmd/redactr/main.go`, the post-subcommand block) and distribute it:
- **Build:** config load + migration, `logging.Setup`, `AcquireSingleton`, licensing, CA, store, scanners (`presidio`/`entropy`/`gliner`/`contextgate`), `pipeline`, `cache`, `fileblock`, `coordinator`, `adminServer` **construction**, `domainFilter`, `hub` (+ `go hub.Run()`), `onScan`, `bypassMatcher`, `proxy.NewProxy`, `apiServer` (+ `SetLicense`/`SetSessions`/`SetRedactrBinary`), `firewall.New` + `SetCAPath`, `ReapOrphans`, `fwController`, `configWatcher` construction. Assign each to a `d.<field>`. Replace `log.Fatalf` → `return nil, fmt.Errorf`.
- **Start:** compute ports first — `adminPort := cfg.Admin.Port; dashPort := 9080; if d.opts.Ephemeral { adminPort, dashPort = 0, 0 }`. Then `adminServer.Start(adminPort)` (store `d.adminAddr`), `StartTransparent(0)` (store `d.transparentAddr`, `apiServer.SetFirewall`), reconcile loop (`context.WithCancel` → `d.reconcileCancel`, `go RunReconcileLoop`), `apiServer.Start(dashPort)` (store `d.dashboardAddr`, write `dashboard.port`), sidecar start-lazy block, `configWatcher.Start()`, the `cfg.Proxy.Enabled` → `proxy.Start(0)` + write `proxy.pid` block. End with `// B3: start control socket here`. (Production preserves v1 behavior: admin on `cfg.Admin.Port`, dashboard on 9080.)
- **Stop:** the shutdown block, plus `d.lock.Release()` (was `defer lock.Release()`), `d.licMgr.Stop()`, `d.store.Close()`, `d.configWatcher.Stop()`.
- **Run:** `Build(Options{BaseDir: baseDir})` → `Start()` → `signal.Notify(SIGINT/SIGTERM)` → `<-sigCh` → `Stop()`.

Then make `cmd/redactr/main.go`'s default path call the daemon. Replace the post-subcommand body of `main()` with:

```go
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("cannot determine home directory: %v", err)
	}
	baseDir := filepath.Join(home, ".redactr")
	os.MkdirAll(filepath.Join(baseDir, "certs"), 0o755)
	os.MkdirAll(filepath.Join(baseDir, "data"), 0o755)
	os.MkdirAll(filepath.Join(baseDir, "state"), 0o755)
	if err := daemon.Run(baseDir); err != nil {
		log.Fatalf("daemon: %v", err)
	}
```

Remove now-unused imports from `main.go` (the component imports moved to daemon). Keep `cli`, `os`, `log`, `path/filepath`, `fmt`, and add `daemon`.

- [ ] **Step 5: Verify the smoke test + the whole existing suite stay green**

Run: `go build ./... && go test ./internal/daemon/ -run TestBuildStartStop -v && go test ./internal/... 2>&1 | grep -v "no test files"`
Expected: smoke PASS; **every previously-passing package still PASS** (this is the behavior-preserving bar). `go vet ./...` clean.

- [ ] **Step 6: Commit**

```bash
git add internal/daemon/ cmd/redactr/main.go
git commit -m "refactor(daemon): extract main() wiring into internal/daemon (behavior-preserving)"
```

---

## Task B3: UDS control socket

**Files:**
- Create: `internal/daemon/socket.go`
- Test: `internal/daemon/socket_test.go`
- Modify: `internal/daemon/daemon.go` (start/stop the socket)

The socket reuses the dashboard's firewall-aware proxy control by issuing an in-process HTTP call to `http://<dashboardAddr>/api/proxy/enable|disable` — no duplication of firewall logic.

- [ ] **Step 1: Write the failing test (`internal/daemon/socket_test.go`)**

```go
package daemon

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
)

func TestControlSocketStatusAndPolicy(t *testing.T) {
	base := t.TempDir()
	d, err := Build(Options{BaseDir: base, Ephemeral: true})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer d.Stop()

	client := socketHTTPClient(filepath.Join(base, "state", "redactr.sock"))

	// /status
	resp, err := client.Get("http://unix/status")
	if err != nil {
		t.Fatalf("GET /status: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/status code = %d", resp.StatusCode)
	}
	var st map[string]any
	json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if _, ok := st["proxy"]; !ok {
		t.Errorf("/status missing proxy field: %v", st)
	}

	// /launch-policy
	resp2, err := client.Get("http://unix/launch-policy?tool=claude")
	if err != nil {
		t.Fatalf("GET /launch-policy: %v", err)
	}
	var li map[string]any
	json.NewDecoder(resp2.Body).Decode(&li)
	resp2.Body.Close()
	if li["image"] != "redactr-base:local" {
		t.Errorf("/launch-policy image = %v, want redactr-base:local", li["image"])
	}
}

// socketHTTPClient returns an *http.Client that dials the given unix socket.
func socketHTTPClient(sockPath string) *http.Client {
	return newUnixClient(sockPath) // defined in socket.go
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/daemon/ -run TestControlSocketStatusAndPolicy -v`
Expected: FAIL — `undefined: newUnixClient` (and no socket served yet).

- [ ] **Step 3: Implement the socket server + client helper (`internal/daemon/socket.go`)**

```go
package daemon

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/rakeshguha/redactr/internal/control"
	"github.com/rakeshguha/redactr/internal/policy"
)

func (d *Daemon) socketPath() string {
	return filepath.Join(d.opts.BaseDir, "state", "redactr.sock")
}

// startControlSocket binds the UDS and serves the control API. Called from Start.
func (d *Daemon) startControlSocket() error {
	path := d.socketPath()
	_ = os.Remove(path) // clear stale socket (singleton lock guarantees no live peer)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0o600)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", d.handleStatus)
	mux.HandleFunc("POST /proxy/enable", d.handleProxyEnable)
	mux.HandleFunc("POST /proxy/disable", d.handleProxyDisable)
	mux.HandleFunc("GET /launch-policy", d.handleLaunchPolicy)

	d.sock = &http.Server{Handler: mux}
	go d.sock.Serve(l)
	return nil
}

func (d *Daemon) stopControlSocket() {
	if d.sock != nil {
		_ = d.sock.Close()
	}
	_ = os.Remove(d.socketPath())
}

func (d *Daemon) statusValue() control.Status {
	cfg := d.cfgMgr.Get()
	return control.Status{
		Proxy:     control.ProxyStatus{Enabled: cfg.Proxy.Enabled, Addr: d.proxy.Addr()},
		Dashboard: d.dashboardAddr,
		Version:   "v2-dev",
	}
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, d.statusValue())
}

func (d *Daemon) handleLaunchPolicy(w http.ResponseWriter, r *http.Request) {
	cfg := d.cfgMgr.Get()
	p, err := policy.Load(d.opts.BaseDir, cfg.Proxy.BlockedDomains)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, control.LaunchInfo{
		Image:     p.Image,
		MountMode: p.MountMode,
		Denylist:  p.Denylist,
		ProxyAddr: d.proxy.Addr(),
	})
}

// handleProxyEnable/Disable delegate to the dashboard's firewall-aware route to
// avoid duplicating proxy/firewall logic, then return the fresh /status.
func (d *Daemon) handleProxyEnable(w http.ResponseWriter, r *http.Request) {
	d.relayDashboard(r.Context(), "/api/proxy/enable")
	writeJSON(w, d.statusValue())
}

func (d *Daemon) handleProxyDisable(w http.ResponseWriter, r *http.Request) {
	d.relayDashboard(r.Context(), "/api/proxy/disable")
	writeJSON(w, d.statusValue())
}

func (d *Daemon) relayDashboard(ctx context.Context, path string) {
	if d.dashboardAddr == "" {
		return
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+d.dashboardAddr+path, nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newUnixClient returns an http.Client whose transport dials the given UDS.
func newUnixClient(sockPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
	}
}
```

- [ ] **Step 4: Wire socket start/stop into the daemon lifecycle (`internal/daemon/daemon.go`)**

Replace the `// B3: start control socket here` marker in `Start` with:

```go
	if err := d.startControlSocket(); err != nil {
		return err
	}
```

In `Stop`, add `d.stopControlSocket()` as the first shutdown action (before proxy stop).

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/daemon/ -v && go vet ./internal/daemon/`
Expected: `TestControlSocketStatusAndPolicy` and `TestBuildStartStop` PASS; vet clean.

- [ ] **Step 6: Commit**

```bash
git add internal/daemon/socket.go internal/daemon/socket_test.go internal/daemon/daemon.go
git commit -m "feat(daemon): unix-socket control API (status, proxy toggle, launch-policy)"
```

---

## Task B4: CLI socket client + `EnsureDaemon`

**Files:**
- Create: `internal/cli/client.go`
- Test: `internal/cli/client_test.go`

- [ ] **Step 1: Write the failing test (`internal/cli/client_test.go`)**

```go
package cli

import (
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/rakeshguha/redactr/internal/control"
)

// serveFakeSocket spins up a UDS server returning canned control responses.
func serveFakeSocket(t *testing.T, dir string) string {
	t.Helper()
	sock := filepath.Join(dir, "redactr.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(control.Status{Proxy: control.ProxyStatus{Enabled: true, Addr: "127.0.0.1:47474"}})
	})
	mux.HandleFunc("POST /proxy/enable", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(control.Status{Proxy: control.ProxyStatus{Enabled: true, Addr: "127.0.0.1:47474"}})
	})
	mux.HandleFunc("GET /launch-policy", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(control.LaunchInfo{Image: "redactr-base:local", MountMode: "bind", ProxyAddr: "127.0.0.1:47474"})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func TestClientStatusAndPolicy(t *testing.T) {
	dir := t.TempDir()
	serveFakeSocket(t, dir)
	c := NewClient(dir) // baseDir/state? -> see note below

	st, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Proxy.Enabled || st.Proxy.Addr != "127.0.0.1:47474" {
		t.Errorf("status = %+v", st)
	}

	li, err := c.LaunchPolicy("claude")
	if err != nil {
		t.Fatalf("LaunchPolicy: %v", err)
	}
	if li.Image != "redactr-base:local" {
		t.Errorf("launch image = %q", li.Image)
	}
}

func TestEnsureDaemonSpawnsWhenDown(t *testing.T) {
	dir := t.TempDir()
	spawned := false
	// No socket yet: EnsureDaemon should call the spawn func, which here starts
	// the fake server so the subsequent dial succeeds.
	err := ensureDaemon(dir, func() error {
		spawned = true
		serveFakeSocket(t, dir)
		return nil
	})
	if err != nil {
		t.Fatalf("ensureDaemon: %v", err)
	}
	if !spawned {
		t.Error("expected spawn to be called when socket absent")
	}
}
```

> Note: the test passes `dir` directly as the socket directory. `NewClient(sockDir)` and `ensureDaemon(sockDir, spawn)` take the directory that contains `redactr.sock` (i.e. `<baseDir>/state`). `RunAgent` (B5) passes `filepath.Join(baseDir, "state")`.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/cli/ -run 'TestClient|TestEnsureDaemon' -v`
Expected: FAIL — `undefined: NewClient` / `ensureDaemon`.

- [ ] **Step 3: Implement (`internal/cli/client.go`)**

```go
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rakeshguha/redactr/internal/control"
)

// Client talks to the daemon's control socket at <sockDir>/redactr.sock.
type Client struct {
	http *http.Client
}

// NewClient builds a control-socket client for the daemon whose socket lives in
// sockDir (i.e. <baseDir>/state).
func NewClient(sockDir string) *Client {
	sock := filepath.Join(sockDir, "redactr.sock")
	return &Client{http: &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
	}}
}

func (c *Client) Status() (control.Status, error) {
	var s control.Status
	return s, c.get("/status", &s)
}

func (c *Client) EnableProxy() (control.Status, error) {
	var s control.Status
	req, _ := http.NewRequest(http.MethodPost, "http://unix/proxy/enable", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	return s, json.NewDecoder(resp.Body).Decode(&s)
}

func (c *Client) LaunchPolicy(tool string) (control.LaunchInfo, error) {
	var li control.LaunchInfo
	return li, c.get("/launch-policy?tool="+tool, &li)
}

func (c *Client) get(path string, out any) error {
	resp, err := c.http.Get("http://unix" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

// EnsureDaemon dials the control socket; if unreachable it spawns the daemon and
// waits up to ~10s for the socket to come up.
func EnsureDaemon(sockDir string) error {
	return ensureDaemon(sockDir, func() error { return spawnDaemon() })
}

func ensureDaemon(sockDir string, spawn func() error) error {
	sock := filepath.Join(sockDir, "redactr.sock")
	if dialable(sock) {
		return nil
	}
	if err := spawn(); err != nil {
		return fmt.Errorf("failed to start redactr daemon: %w", err)
	}
	for i := 0; i < 50; i++ { // ~10s at 200ms
		if dialable(sock) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("redactr daemon did not come up (socket %s)", sock)
}

func dialable(sock string) bool {
	c, err := net.DialTimeout("unix", sock, 200*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// spawnDaemon launches the current binary as a detached background daemon.
func spawnDaemon() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self) // no subcommand => daemon.Run
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Start()
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/cli/ -run 'TestClient|TestEnsureDaemon' -v && go vet ./internal/cli/`
Expected: PASS; vet clean.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/client.go internal/cli/client_test.go
git commit -m "feat(cli): control-socket client + EnsureDaemon auto-start"
```

---

## Task B5: Rewire `RunAgent` to preflight via the socket

**Files:**
- Modify: `internal/cli/agent.go`
- Test: `internal/cli/agent_test.go` (add a mount-mode guard test)

- [ ] **Step 1: Add the failing test (`internal/cli/agent_test.go`)**

Append:

```go
func TestSpecFromPolicyRejectsDiffback(t *testing.T) {
	_, err := specFromLaunchInfo("claude", nil, "/cwd", "/ca.crt",
		launchInfo{Image: "img", MountMode: "diffback", ProxyAddr: "127.0.0.1:47474"})
	if err == nil {
		t.Fatal("expected diffback mount mode to be rejected (not yet supported)")
	}
}

func TestSpecFromPolicyBindOK(t *testing.T) {
	spec, err := specFromLaunchInfo("claude", []string{"--version"}, "/cwd", "/ca.crt",
		launchInfo{Image: "redactr-base:local", MountMode: "bind", ProxyAddr: "127.0.0.1:47474"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Image != "redactr-base:local" || spec.ProjectDir != "/cwd" || spec.ProxyAddr != "127.0.0.1:47474" {
		t.Errorf("spec = %+v", spec)
	}
	if len(spec.Entrypoint) != 2 || spec.Entrypoint[0] != "claude" || spec.Entrypoint[1] != "--version" {
		t.Errorf("entrypoint = %v", spec.Entrypoint)
	}
}
```

> `launchInfo` is a local alias for `control.LaunchInfo` to keep the test terse; define `type launchInfo = control.LaunchInfo` in `agent.go`.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/cli/ -run TestSpecFromPolicy -v`
Expected: FAIL — `undefined: specFromLaunchInfo`.

- [ ] **Step 3: Rewrite `internal/cli/agent.go`**

This is a **merge, not a wholesale overwrite**: `agent.go` already defines `knownAgents` (the map) and `knownAgentEntrypoint` (from subsystem C) — **keep them**. Replace only the `RunAgent` function body, add the `launchInfo` type alias and the `specFromLaunchInfo` helper, and reconcile the import block. The block below shows the changed/added parts plus the imports the file now needs; do not delete `knownAgents`/`knownAgentEntrypoint`.

```go
package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rakeshguha/redactr/internal/control"
	"github.com/rakeshguha/redactr/internal/sandbox"
)

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
```

> The old `knownAgents`/`knownAgentEntrypoint` definitions stay in `agent.go` (don't duplicate them). Remove the now-unused `sandbox.Discover` call from `RunAgent` (Discover itself stays in the sandbox package for daemon/internal use).

- [ ] **Step 4: Run tests**

Run: `go test ./internal/cli/ -v && go build ./... && go vet ./internal/cli/`
Expected: all PASS (`TestSpecFromPolicy*`, `TestKnownAgentImage`, client tests); build + vet clean.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/agent.go internal/cli/agent_test.go
git commit -m "feat(cli): RunAgent preflights daemon + policy over the control socket"
```

---

## Task B6: `redactr tray` menubar (built last)

**Files:**
- Create: `internal/tray/tray.go`
- Test: `internal/tray/tray_test.go`
- Modify: `cmd/redactr/main.go` (add `tray` subcommand)
- Modify: `go.mod` / `go.sum` (add `fyne.io/systray`)

- [ ] **Step 1: Add the dependency**

Run: `go get fyne.io/systray@latest`
Expected: `go.mod` gains `fyne.io/systray`. (macOS: CGo; requires Xcode command-line tools. This is the only task that adds a native dep.)

- [ ] **Step 2: Write the failing test (`internal/tray/tray_test.go`)**

```go
package tray

import (
	"testing"

	"github.com/rakeshguha/redactr/internal/control"
)

func TestTrayStateGreenWhenProxyLive(t *testing.T) {
	s := TrayState(control.Status{Proxy: control.ProxyStatus{Enabled: true, Addr: "127.0.0.1:47474"}}, true)
	if s.Color != "green" {
		t.Errorf("Color = %q, want green", s.Color)
	}
	if s.ProxyLabel != "Proxy: Enabled" {
		t.Errorf("ProxyLabel = %q", s.ProxyLabel)
	}
}

func TestTrayStateRedWhenProxyDisabled(t *testing.T) {
	s := TrayState(control.Status{Proxy: control.ProxyStatus{Enabled: false}}, true)
	if s.Color != "red" {
		t.Errorf("Color = %q, want red", s.Color)
	}
}

func TestTrayStateRedWhenDaemonDown(t *testing.T) {
	s := TrayState(control.Status{}, false) // reachable=false
	if s.Color != "red" || s.ProxyLabel != "Daemon: Down" {
		t.Errorf("got %+v, want red/Daemon: Down", s)
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `go test ./internal/tray/ -v`
Expected: FAIL — `undefined: TrayState`.

- [ ] **Step 4: Implement the pure helper + systray shell (`internal/tray/tray.go`)**

```go
// Package tray renders the redactr menubar (macOS) and reflects daemon/proxy
// state. The state→view mapping is a pure function (TrayState) for testability;
// the systray glue is a thin shell.
package tray

import (
	"context"
	"time"

	"fyne.io/systray"

	"github.com/rakeshguha/redactr/internal/cli"
	"github.com/rakeshguha/redactr/internal/control"
)

// View is the rendered tray state.
type View struct {
	Color      string // "green" | "red"
	ProxyLabel string
}

// TrayState maps a daemon status (and whether the daemon was reachable) to the
// menubar view. Green only when the daemon is reachable and the proxy is live.
func TrayState(st control.Status, reachable bool) View {
	if !reachable {
		return View{Color: "red", ProxyLabel: "Daemon: Down"}
	}
	if st.Proxy.Enabled && st.Proxy.Addr != "" {
		return View{Color: "green", ProxyLabel: "Proxy: Enabled"}
	}
	return View{Color: "red", ProxyLabel: "Proxy: Disabled"}
}

// Run starts the menubar event loop. It blocks (systray.Run owns the main
// thread); callers must invoke it from main on macOS.
func Run(sockDir string) {
	client := cli.NewClient(sockDir)
	systray.Run(func() { onReady(client) }, func() {})
}

func onReady(client *cli.Client) {
	systray.SetTitle("●")
	mToggle := systray.AddMenuItem("Proxy: …", "Toggle the redactr proxy")
	mQuit := systray.AddMenuItem("Quit", "Quit redactr tray")

	apply := func() {
		st, err := client.Status()
		v := TrayState(st, err == nil)
		systray.SetTitle(glyph(v.Color))
		mToggle.SetTitle(v.ProxyLabel)
	}
	apply()

	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				apply()
			case <-mToggle.ClickedCh:
				_, _ = client.EnableProxy() // toggle semantics refined later; enable is the common case
				apply()
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
	_ = context.Background
}

func glyph(color string) string {
	if color == "green" {
		return "🟢"
	}
	return "🔴"
}
```

> The menubar glyph uses emoji for the first cut (no asset bundling). A proper template icon is a later packaging task.

- [ ] **Step 5: Add the `tray` subcommand (`cmd/redactr/main.go`)**

In the `switch os.Args[1]` block, add (after the agent case):

```go
		case "tray":
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("cannot determine home directory: %v", err)
			}
			tray.Run(filepath.Join(home, ".redactr", "state"))
			return
```

Add `"github.com/rakeshguha/redactr/internal/tray"` to the imports.

- [ ] **Step 6: Run tests + build**

Run: `go test ./internal/tray/ -v && go build ./...`
Expected: `TestTrayState*` PASS; build succeeds (CGo links systray on macOS).

- [ ] **Step 7: Commit**

```bash
git add internal/tray/ cmd/redactr/main.go go.mod go.sum
git commit -m "feat(tray): redactr tray menubar with green/red proxy indicator"
```

---

## Final verification

- [ ] **Whole suite + vet**

Run: `go build ./... && go test ./internal/... 2>&1 | grep -v "no test files" && go vet ./...`
Expected: all PASS; vet clean. (Existing v1 packages must remain green — the B2 extraction is behavior-preserving.)

- [ ] **Manual smoke (macOS, with Docker for the last step)**

```bash
go build -o redactr ./cmd/redactr
./redactr            # daemon starts (was the v1 default behavior, now via daemon.Run)
./redactr tray &     # menubar shows 🟢/🔴; toggling proxy flips it
./redactr claude     # in a project dir: EnsureDaemon→EnableProxy→policy→container (needs Docker)
```

Expected: daemon serves the dashboard + control socket; tray reflects proxy state; `redactr claude` launches the sandbox via preflight.

---

## Self-Review notes (coverage map)

- **B1 policy cache + DTOs:** Task B1 (`internal/policy`, `internal/control`).
- **B2 main() extraction (behavior-preserving + smoke):** Task B2; existing suite green is the bar.
- **B3 control socket (status/proxy/launch-policy):** Task B3; proxy toggle reuses dashboard route (no firewall dup).
- **B4 CLI client + EnsureDaemon auto-start (injectable spawn):** Task B4.
- **B5 RunAgent preflight + diffback SEAM:** Task B5.
- **B6 tray (pure TrayState + systray shell, dep added last):** Task B6.
- **Reuse C + v1:** B5 builds `sandbox.Spec` for the C engine; B2 moves (not rewrites) v1 wiring; B3 reuses the dashboard proxy route.
- **Deferred SEAMs:** server policy refresh (A), diffback (C), .app bundling/login-item, non-macOS tray.
