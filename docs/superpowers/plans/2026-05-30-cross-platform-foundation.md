# Cross-Platform Foundation (Native Windows Host) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the redactr host app (daemon/proxy/control-socket/tray) build and run natively on Windows with parity to macOS; AI agents stay in Linux containers (Docker Desktop) that self-route to the host proxy.

**Architecture:** Three of five changes are tiny build/platform fixes (firewall interface completion, daemon-spawn build-tag split, runtime-aware container host alias). The fourth makes the tray render a green/red icon natively on Windows (`SetIcon`) as well as macOS. The fifth updates the architecture spec. No host-level traffic redirect — the container self-redirects via the in-container `iptables` entrypoint from subsystem C.

**Tech Stack:** Go 1.26 (`github.com/rakeshguha/redactr`), `fyne.io/systray` (CGo; already a dep), stdlib `image`/`image/png`/`encoding/binary` for programmatic icons.

**Verification reality (developed on macOS, no Windows box, no mingw):**
- `systray` is CGo, so packages that import it (`internal/tray`, `cmd/redactr`) **cannot** cross-compile to Windows from macOS. Their Windows build + runtime smoke are **deferred to a Windows machine**.
- The pure-Go packages — where the actual blockers live — **do** cross-compile: the bar for tasks 1–3 is `CGO_ENABLED=0 GOOS=windows go build <pure-Go pkg list>` (and `GOOS=linux`) clean.
- Throughout: the existing macOS `go test ./internal/...` suite stays green; `go vet` clean.

**Pure-Go package list used below (PKGS):**
```
./internal/firewall/ ./internal/cli/ ./internal/sandbox/ ./internal/daemon/ ./internal/policy/ ./internal/control/ ./internal/lifecycle/
```

---

## File Structure

| File | Change |
|---|---|
| `internal/firewall/redirect_other.go` | add `darwinFirewall` stub `Redirect`/`Unredirect`/`IsActive` (`!darwin`) |
| `internal/cli/client.go` | remove `spawnDaemon` + its unix-only imports |
| `internal/cli/client_unix.go` | create — `spawnDaemon` with `Setsid` (`!windows`) |
| `internal/cli/client_windows.go` | create — `spawnDaemon` with `CreationFlags` (`windows`) |
| `internal/sandbox/spec.go` | add `HostAlias` field to `Spec` |
| `internal/sandbox/inject.go` | runtime-aware alias (`hostAliasFor`, `InjectionArgs` uses `s.HostAlias`) |
| `internal/sandbox/engine.go` | `Launch` sets `s.HostAlias = hostAliasFor(Runtime.Name())` |
| `internal/sandbox/inject_test.go` | add podman-alias + `hostAliasFor` tests |
| `internal/tray/icon.go` | create — programmatic green/red `iconBytes` (no build tag) |
| `internal/tray/icon_test.go` | create — `iconBytes` non-empty test |
| `internal/tray/tray_systray.go` | rename from `tray_darwin.go`; tag `darwin || windows`; `SetIcon`/`SetTooltip` |
| `internal/tray/tray_other.go` | tag → `!darwin && !windows` |
| `docs/.../redactr-v2-architecture-design.md` | revise macOS-first stance |

---

## Task 1: Firewall build fix (unblocks Windows + Linux)

**Files:**
- Modify: `internal/firewall/redirect_other.go`

`firewall.go`'s `New()` switches on `runtime.GOOS` in one unconstrained file, so `return &darwinFirewall{}` is type-checked on every OS, but `darwinFirewall.Redirect/Unredirect/IsActive` live in `redirect_darwin.go` (`//go:build darwin`). Add the non-darwin stubs (the file already exists for exactly this purpose).

- [ ] **Step 1: Confirm the failure**

Run: `CGO_ENABLED=0 GOOS=windows go build ./internal/firewall/`
Expected: FAIL — `*darwinFirewall does not implement Manager (missing method IsActive)`.

- [ ] **Step 2: Add the stubs**

Append to `internal/firewall/redirect_other.go` (it currently has the `//go:build !darwin` tag and a `SetCAPath` no-op — keep those):

```go
// darwinFirewall's redirect methods are only implemented on darwin
// (redirect_darwin.go). On other platforms darwinFirewall is referenced by the
// New() switch but never instantiated, so these stubs only satisfy the Manager
// interface at compile time.
func (f *darwinFirewall) Redirect(ips []string, transparentPort int) error { return ErrNotImplemented }
func (f *darwinFirewall) Unredirect() error                                { return ErrNotImplemented }
func (f *darwinFirewall) IsActive() (bool, error)                          { return false, nil }
```

- [ ] **Step 3: Verify cross-compile (the test for this task)**

Run: `CGO_ENABLED=0 GOOS=windows go build ./internal/firewall/ && CGO_ENABLED=0 GOOS=linux go build ./internal/firewall/`
Expected: both succeed (no output).
Run: `go build ./internal/firewall/ && go test ./internal/firewall/ && go vet ./internal/firewall/`
Expected: macOS build + tests PASS, vet clean (the real darwin methods still win on macOS).

- [ ] **Step 4: Commit**

```bash
git add internal/firewall/redirect_other.go
git commit -m "fix(firewall): darwinFirewall satisfies Manager on non-darwin (unblocks windows/linux build)"
```

---

## Task 2: Daemon spawn build-tag split

**Files:**
- Modify: `internal/cli/client.go`
- Create: `internal/cli/client_unix.go`
- Create: `internal/cli/client_windows.go`

`spawnDaemon` uses `syscall.SysProcAttr{Setsid: true}` — `Setsid` doesn't exist on Windows. Split it.

- [ ] **Step 1: Confirm the failure**

Run: `CGO_ENABLED=0 GOOS=windows go build ./internal/cli/`
Expected: FAIL — `unknown field Setsid in struct literal of type syscall.SysProcAttr`. (`cli` does not import `firewall`, so this is the only error.)

- [ ] **Step 2: Remove `spawnDaemon` from `client.go`**

Delete the entire `spawnDaemon` function from `internal/cli/client.go`. Then remove the now-unused imports from `client.go`: `"os"`, `"os/exec"`, `"syscall"` (verify none are used elsewhere in the file — after removing `spawnDaemon` they are not). Leave `EnsureDaemon`/`ensureDaemon`/`dialable`/`Client` intact; `ensureDaemon` still calls `spawnDaemon` (now provided per-platform).

- [ ] **Step 3: Create `internal/cli/client_unix.go`**

```go
//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"syscall"
)

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

- [ ] **Step 4: Create `internal/cli/client_windows.go`**

```go
//go:build windows

package cli

import (
	"os"
	"os/exec"
	"syscall"
)

// Win32 process-creation flags (see CreateProcess docs) — detach the daemon
// from the launching console so it survives the CLI exiting.
const (
	detachedProcess       = 0x00000008
	createNewProcessGroup = 0x00000200
)

// spawnDaemon launches the current binary as a detached background daemon.
func spawnDaemon() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self) // no subcommand => daemon.Run
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess | createNewProcessGroup}
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Start()
}
```

- [ ] **Step 5: Verify**

Run: `CGO_ENABLED=0 GOOS=windows go build ./internal/cli/ && CGO_ENABLED=0 GOOS=linux go build ./internal/cli/`
Expected: both succeed.
Run: `go build ./internal/cli/ && go test ./internal/cli/ && go vet ./internal/cli/`
Expected: macOS build + all cli tests PASS (the `!windows` file provides `spawnDaemon` on macOS), vet clean.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/client.go internal/cli/client_unix.go internal/cli/client_windows.go
git commit -m "feat(cli): split daemon spawn for windows (CreationFlags) vs unix (Setsid)"
```

---

## Task 3: Runtime-aware container host alias

**Files:**
- Modify: `internal/sandbox/spec.go`, `internal/sandbox/inject.go`, `internal/sandbox/engine.go`
- Test: `internal/sandbox/inject_test.go`

Docker/Colima use `host.docker.internal`; Podman uses `host.containers.internal`. Thread the detected runtime's alias through without breaking the existing single-arg `InjectionArgs` call sites (the integration test and `TestInjectionArgs` call `InjectionArgs(Spec{...})`). Achieve this by adding an optional `HostAlias` field to `Spec` (defaulting to the Docker alias when empty), mirroring how `ProxyAddr`/`CACertPath` are runtime-filled.

- [ ] **Step 1: Write the failing test**

Append to `internal/sandbox/inject_test.go`:

```go
func TestHostAliasFor(t *testing.T) {
	if got := hostAliasFor("podman"); got != "host.containers.internal" {
		t.Errorf("podman alias = %q", got)
	}
	if got := hostAliasFor("docker"); got != "host.docker.internal" {
		t.Errorf("docker alias = %q", got)
	}
}

func TestInjectionArgsPodmanAlias(t *testing.T) {
	got := strings.Join(InjectionArgs(Spec{
		ProjectDir: "/p", ProxyAddr: "127.0.0.1:47474", CACertPath: "/ca.crt",
		HostAlias: "host.containers.internal",
	}), " ")
	if !strings.Contains(got, "host.containers.internal:host-gateway") {
		t.Errorf("missing podman add-host: %s", got)
	}
	if !strings.Contains(got, "REDACTR_PROXY_HOST=host.containers.internal") {
		t.Errorf("missing podman proxy host env: %s", got)
	}
	if strings.Contains(got, "host.docker.internal") {
		t.Errorf("should not contain docker alias: %s", got)
	}
}
```

- [ ] **Step 2: Run to verify fail**

Run: `go test ./internal/sandbox/ -run 'TestHostAliasFor|TestInjectionArgsPodmanAlias' -v`
Expected: FAIL — `undefined: hostAliasFor` / `unknown field HostAlias`.

- [ ] **Step 3: Add `HostAlias` to `Spec` (`internal/sandbox/spec.go`)**

In the `Spec` struct, add after `CACertPath`:

```go
	// HostAlias is the in-container DNS alias for the host proxy. Filled by the
	// Engine from the detected runtime (Docker -> host.docker.internal, Podman
	// -> host.containers.internal). Empty defaults to the Docker alias.
	HostAlias string
```

- [ ] **Step 4: Make `InjectionArgs` alias-aware (`internal/sandbox/inject.go`)**

Replace the file's body so the alias comes from the spec (remove the `proxyHostAlias` const; keep `workMount`/`caInContainer`):

```go
package sandbox

import "strings"

const (
	workMount     = "/work"
	caInContainer = "/etc/redactr/ca.crt"

	dockerHostAlias = "host.docker.internal"
	podmanHostAlias = "host.containers.internal"
)

// hostAliasFor returns the in-container DNS alias for reaching the host proxy,
// per container runtime.
func hostAliasFor(runtime string) string {
	if runtime == "podman" {
		return podmanHostAlias
	}
	return dockerHostAlias
}

// InjectionArgs returns the launch-time mount/env flags. It injects the project
// bind-mount, the CA read-only, proxy env pointing at the host alias, and
// REDACTR_BOUND=1. s.HostAlias selects the runtime alias (empty => Docker).
func InjectionArgs(s Spec) []string {
	alias := s.HostAlias
	if alias == "" {
		alias = dockerHostAlias
	}
	port := portOf(s.ProxyAddr)
	proxyURL := "http://" + alias + ":" + port
	return []string{
		"--add-host", alias + ":host-gateway",
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
		"-e", "REDACTR_PROXY_HOST=" + alias,
		"-e", "REDACTR_PROXY_PORT=" + port,
	}
}

// portOf extracts the port from a host:port string.
func portOf(hostPort string) string {
	if i := strings.LastIndex(hostPort, ":"); i >= 0 {
		return hostPort[i+1:]
	}
	return hostPort
}
```

- [ ] **Step 5: Set the alias in `Engine.Launch` (`internal/sandbox/engine.go`)**

At `engine.go` around line 47, immediately before the `InjectionArgs(s)` call, set the alias from the runtime:

```go
	s.HostAlias = hostAliasFor(e.Runtime.Name())
	flags = append(flags, InjectionArgs(s)...)
```

(The existing line is `flags = append(flags, InjectionArgs(s)...)`; add the `s.HostAlias = ...` line just above it. `s` is the value-receiver copy, so this is local.)

- [ ] **Step 6: Run tests**

Run: `go test ./internal/sandbox/ -v`
Expected: new tests PASS; existing `TestInjectionArgs` (no `HostAlias` → defaults to Docker alias) and `TestEngineLaunchComposesArgv` still PASS.
Run: `CGO_ENABLED=0 GOOS=windows go build ./internal/sandbox/ && go vet ./internal/sandbox/` — clean.

- [ ] **Step 7: Commit**

```bash
git add internal/sandbox/spec.go internal/sandbox/inject.go internal/sandbox/engine.go internal/sandbox/inject_test.go
git commit -m "feat(sandbox): runtime-aware container host alias (docker vs podman)"
```

---

## Task 4: Native Windows tray icon

**Files:**
- Create: `internal/tray/icon.go`, `internal/tray/icon_test.go`
- Rename + modify: `internal/tray/tray_darwin.go` → `internal/tray/tray_systray.go`
- Modify: `internal/tray/tray_other.go`

macOS renders text via `SetTitle`; Windows renders an icon via `SetIcon`. Use `SetIcon`/`SetTooltip` on both, with programmatically-generated icon bytes (PNG for macOS, ICO-wrapping-PNG for Windows). No binary assets committed.

- [ ] **Step 1: Write the failing test (`internal/tray/icon_test.go`)**

```go
package tray

import "testing"

func TestIconBytesNonEmpty(t *testing.T) {
	for _, c := range []string{"green", "red"} {
		if b := iconBytes(c); len(b) == 0 {
			t.Errorf("iconBytes(%q) returned no bytes", c)
		}
	}
}
```

- [ ] **Step 2: Run to verify fail**

Run: `go test ./internal/tray/ -run TestIconBytesNonEmpty -v`
Expected: FAIL — `undefined: iconBytes`.

- [ ] **Step 3: Implement `internal/tray/icon.go`** (no build tag — testable on every OS)

```go
package tray

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"runtime"
)

// iconBytes returns a small filled-circle indicator in the format the current
// platform's system tray expects: PNG on macOS/Linux, ICO (PNG-in-ICO) on
// Windows. color is "green" or "red".
func iconBytes(c string) []byte {
	col := color.RGBA{0xff, 0x41, 0x36, 0xff} // red
	if c == "green" {
		col = color.RGBA{0x2e, 0xcc, 0x40, 0xff}
	}
	p := circlePNG(col)
	if runtime.GOOS == "windows" {
		return icoWrap(p)
	}
	return p
}

func circlePNG(c color.Color) []byte {
	const n = 22
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	cx, cy, r := float64(n)/2, float64(n)/2, float64(n)/2-1
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := float64(x)+0.5-cx, float64(y)+0.5-cy
			if dx*dx+dy*dy <= r*r {
				img.Set(x, y, c)
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// icoWrap packages a PNG into a single-image .ico (Windows Vista+ accepts PNG
// payloads inside ICO).
func icoWrap(pngBytes []byte) []byte {
	var b bytes.Buffer
	// ICONDIR
	_ = binary.Write(&b, binary.LittleEndian, uint16(0)) // reserved
	_ = binary.Write(&b, binary.LittleEndian, uint16(1)) // type: icon
	_ = binary.Write(&b, binary.LittleEndian, uint16(1)) // image count
	// ICONDIRENTRY
	b.WriteByte(22) // width
	b.WriteByte(22) // height
	b.WriteByte(0)  // palette colors
	b.WriteByte(0)  // reserved
	_ = binary.Write(&b, binary.LittleEndian, uint16(1))               // color planes
	_ = binary.Write(&b, binary.LittleEndian, uint16(32))              // bits per pixel
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(pngBytes)))   // image size
	_ = binary.Write(&b, binary.LittleEndian, uint32(6+16))            // offset to image
	b.Write(pngBytes)
	return b.Bytes()
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/tray/ -v`
Expected: `TestIconBytesNonEmpty` + the existing `TestTrayState*` PASS.

- [ ] **Step 5: Rename `tray_darwin.go` → `tray_systray.go` and update it**

```bash
git mv internal/tray/tray_darwin.go internal/tray/tray_systray.go
```

Replace its contents with (tag now `darwin || windows`; icon-based rendering; `glyph` removed):

```go
//go:build darwin || windows

package tray

import (
	"time"

	"fyne.io/systray"

	"github.com/rakeshguha/redactr/internal/cli"
)

// Run starts the menubar/notification-area event loop. It blocks (systray.Run
// owns the main thread); callers must invoke it from main.
func Run(sockDir string) {
	client := cli.NewClient(sockDir)
	systray.Run(func() { onReady(client) }, func() {})
}

func onReady(client *cli.Client) {
	systray.SetIcon(iconBytes("red"))
	systray.SetTooltip("redactr — Proxy: …")
	mToggle := systray.AddMenuItem("Proxy: …", "Toggle the redactr proxy")
	mQuit := systray.AddMenuItem("Quit", "Quit redactr tray")

	apply := func() {
		st, err := client.Status()
		v := TrayState(st, err == nil)
		systray.SetIcon(iconBytes(v.Color))
		systray.SetTooltip("redactr — " + v.ProxyLabel)
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
				if st, err := client.Status(); err == nil && st.Proxy.Enabled {
					_, _ = client.DisableProxy()
				} else {
					_, _ = client.EnableProxy()
				}
				apply()
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}
```

- [ ] **Step 6: Update `internal/tray/tray_other.go` build tag**

Change its first line from `//go:build !darwin` to:

```go
//go:build !darwin && !windows
```

(The stub body — `Run(sockDir string)` printing "redactr tray is only supported on macOS" — stays. Optionally broaden the message to "macOS and Windows"; not required.)

- [ ] **Step 7: Verify (macOS native; Windows build deferred)**

Run: `go build ./... && go test ./internal/tray/ -v && go vet ./internal/tray/`
Expected: macOS build + tray tests PASS, vet clean.
Note: `GOOS=windows go build ./internal/tray/` is **not** run here — `systray` is CGo and there's no Windows cross-compiler on this machine. The Windows tray build + notification-area smoke are deferred to a Windows host. Confirm the build tags are correct by reasoning: `tray_systray.go` = `darwin || windows`, `tray_other.go` = `!darwin && !windows` — exactly one `Run` per platform, none missing.

- [ ] **Step 8: Commit**

```bash
git add internal/tray/icon.go internal/tray/icon_test.go internal/tray/tray_systray.go internal/tray/tray_other.go
git commit -m "feat(tray): native windows notification-area icon (green/red via SetIcon)"
```

---

## Task 5: Architecture spec update

**Files:**
- Modify: `docs/superpowers/specs/2026-05-30-redactr-v2-architecture-design.md`

- [ ] **Step 1: Revise the platform stance**

In the architecture spec's "Explicitly deferred (not in v2)" section, find the line about Cursor/non-macOS and the tray, and replace the Windows/Linux-deferral wording with an accurate cross-platform statement. Specifically, change the deferred bullet:

```
- Cursor and other non-VS-Code editors as first-class targets (Dev Container path generalizes to them later).
```

leave as-is, and **replace** the GUI/platform deferral bullet:

```
- GUI sandboxing beyond Desktop MCP servers.
```

by inserting immediately after it a new bullet:

```
- Host-level transparent redirect on Windows (WFP/WinDivert) and WSL2-hosted daemon — the daemon is a native host app on macOS and Windows; AI agents run in Linux containers (Docker Desktop) that self-redirect to the host proxy, so no host redirect is needed. Native Linux *desktop* host support (tray) is also out of scope — Linux is the container OS only.
```

Then, in the topology/overview prose where it says the client is macOS-first, adjust any "macOS"-only phrasing to "macOS and Windows" for the desktop client / tray. (Search the file for "macOS" and update the host-app references; leave Colima/VM-on-macOS technical notes accurate.)

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-05-30-redactr-v2-architecture-design.md
git commit -m "docs: architecture spec — native host app on macOS+Windows, linux container-only"
```

---

## Final verification

- [ ] **Cross-compile + macOS suite**

Run:
```bash
CGO_ENABLED=0 GOOS=windows go build ./internal/firewall/ ./internal/cli/ ./internal/sandbox/ ./internal/daemon/ ./internal/policy/ ./internal/control/ ./internal/lifecycle/
CGO_ENABLED=0 GOOS=linux   go build ./internal/firewall/ ./internal/cli/ ./internal/sandbox/ ./internal/daemon/ ./internal/policy/ ./internal/control/ ./internal/lifecycle/
go build ./... && go test ./internal/... 2>&1 | grep -v "no test files" && go vet ./...
```
Expected: both cross-compiles succeed; macOS build + full suite PASS; vet clean.

- [ ] **Deferred to a Windows host** (document, don't run): `GOOS=windows` build of `internal/tray` + `cmd/redactr` (needs a Windows C toolchain for systray), then `redactr` (daemon), `redactr tray` (notification-area icon flips green/red), `redactr claude` (Docker Desktop container self-routes to the host proxy).

---

## Self-Review notes (coverage map)

- **Firewall build fix** → Task 1 (cross-compile is the test).
- **Daemon spawn split** → Task 2 (`client_unix.go`/`client_windows.go`).
- **Runtime-aware host alias** → Task 3 (`HostAlias` on `Spec`, `hostAliasFor`, Engine sets it; existing call sites unbroken because the field defaults).
- **Native Windows tray** → Task 4 (`iconBytes` PNG/ICO, `SetIcon`/`SetTooltip`, build-tag flip; pure `TrayState` unchanged).
- **Architecture spec update** → Task 5.
- **Verification honesty** → CGo tray Windows build deferred; pure-Go cross-compile is the achievable bar for the real blockers.
