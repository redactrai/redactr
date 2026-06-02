# Redactr v2 — Cross-Platform Foundation (Native Windows Host) Design

**Status:** Design (approved). Implementation plan follows.
**Date:** 2026-05-30
**Parent:** `docs/superpowers/specs/2026-05-30-redactr-v2-architecture-design.md`
**Touches (already merged on `main`):** `internal/sandbox` (C), `internal/daemon`, `internal/cli`, `internal/tray`, `internal/firewall`.

## Decision: Windows is a v2 target (native host app)

v2 was scoped macOS-first. This revises that: **the redactr proxy + daemon + tray are a native host application on both macOS and Windows.** The AI agents run in **Linux containers** via Docker Desktop. The container controls its **own** egress through the in-container `iptables` redirect built in subsystem C, routing to the host proxy at `host.docker.internal:<proxyPort>`. Therefore **no host-level traffic redirect is required on Windows** — redactr does not intercept native host apps; it runs agents in containers that self-route to the host proxy.

**Linux is only the container OS, never a host target.** (WSL2-hosted daemon, native Linux desktop, and host-level transparent redirect via WFP/WinDivert are all explicitly **out of scope**.)

## Goal

Make the existing host app build and run natively on Windows with parity to macOS: the daemon/proxy/control-socket run as a native Windows process, and the tray shows a green/red proxy indicator in the Windows notification area. `redactr claude` launches the Linux agent container (via Docker Desktop) which self-routes to the host proxy.

## Current blockers (verified)

`GOOS=windows go build ./...` fails with exactly two errors; `GOOS=linux` fails with the first one only:

1. `internal/firewall/firewall.go:40` — `New()` switches on `runtime.GOOS` in one unconstrained file, so its `return &darwinFirewall{}` branch is type-checked on every platform, but `darwinFirewall`'s `Redirect/Unredirect/IsActive` live in `redirect_darwin.go` (`//go:build darwin`). On non-darwin, `darwinFirewall` is missing those methods → does not satisfy `Manager`.
2. `internal/cli/client.go:133` — `syscall.SysProcAttr{Setsid: true}` — `Setsid` is not a field of `syscall.SysProcAttr` on Windows.

`linuxFirewall` and `windowsFirewall` (in unconstrained `linux.go`/`windows.go`) already fully implement `Manager` (with `Redirect/Unredirect` → `ErrNotImplemented`, `IsActive` → `false`). `internal/lifecycle` already has a `_windows.go`. AF_UNIX sockets work on Windows 10+. So everything else already compiles for Windows.

## Components / changes

### 1. Firewall build fix — `internal/firewall/redirect_other.go`
The existing `//go:build !darwin` file (currently only `SetCAPath` no-op) gains the three missing `darwinFirewall` methods so the type satisfies `Manager` on non-darwin (where it is referenced by the `New()` switch but never instantiated — `New()` returns `linuxFirewall`/`windowsFirewall` on those OSes):

```go
func (f *darwinFirewall) Redirect(ips []string, transparentPort int) error { return ErrNotImplemented }
func (f *darwinFirewall) Unredirect() error                                { return ErrNotImplemented }
func (f *darwinFirewall) IsActive() (bool, error)                          { return false, nil }
```

This is the minimal fix matching the file's evident intent. It unblocks **both** Windows and Linux builds. No behavior change on macOS (the real methods in `redirect_darwin.go` still win there).

### 2. Daemon spawn split — `internal/cli/`
`spawnDaemon` (forks the daemon when the control socket is dead) is extracted from `client.go` into two build-tagged files:
- `client_unix.go` (`//go:build !windows`) — current behavior: `SysProcAttr{Setsid: true}`.
- `client_windows.go` (`//go:build windows`) — `SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}` to detach the background daemon. Uses `golang.org/x/sys/windows` (already an indirect dep) for the flag constants, or the raw `syscall` constants if available.

`client.go` keeps everything else (the `Client`, `EnsureDaemon`, `ensureDaemon`, `dialable`) cross-platform; `spawnDaemon` becomes the only platform-split symbol.

### 3. Native Windows tray — `internal/tray/`
The tray indicator differs by platform: macOS renders text via `systray.SetTitle`; **Windows renders an icon via `systray.SetIcon`** (with `SetTooltip` for hover text). To support both:

- Rename `tray_darwin.go` → `tray_systray.go` with `//go:build darwin || windows` (fyne.io/systray supports both natively).
- `tray_other.go` → `//go:build !darwin && !windows` (Linux/other keep the stub — not a host target).
- Embed tiny green/red indicator assets via `//go:embed`: `green.png`/`red.png` (macOS) and `green.ico`/`red.ico` (Windows). A `runtime.GOOS`-aware `iconBytes(color)` returns the right format.
- `apply()` calls `systray.SetIcon(iconBytes(view.Color))` and `systray.SetTooltip(view.ProxyLabel)` on all platforms; macOS additionally keeps `SetTitle` for the menubar text. The pure `TrayState` mapping is unchanged.

`Run` already runs on the main thread; the toggle/poll logic is unchanged. Tests for `TrayState` (pure) are unaffected.

### 4. Runtime-aware container host alias — `internal/sandbox/inject.go`
`InjectionArgs` currently hardcodes `host.docker.internal`. Make the alias runtime-aware:
- Docker / Docker Desktop / Colima → `host.docker.internal` (keep `--add-host host.docker.internal:host-gateway` for native Linux Docker; harmless on Desktop where the alias is built in).
- Podman → `host.containers.internal`.

The detected runtime name (`docker`/`podman`, already known to `Engine`) is threaded into `InjectionArgs` (new parameter or a resolved alias field on `Spec`). The proxy URL and `REDACTR_PROXY_HOST` env use the resolved alias.

### 5. Architecture spec update — `docs/superpowers/specs/2026-05-30-redactr-v2-architecture-design.md`
Revise the "macOS-first / Windows-Linux tray deferred" stance to: "native host app on macOS **and Windows**; Linux is the container OS only; host-level transparent redirect (WFP/WinDivert) remains out of scope because the container self-redirects."

## Out of scope (explicitly deferred)

- Host-level transparent redirect on Windows (WFP / WinDivert / netsh) — the container self-routes; intercepting native host apps is not a v2 goal.
- WSL2-hosted daemon — the daemon is a native host process; Docker Desktop supplies the Linux container VM.
- Native Linux *desktop* host support (tray, etc.) — Linux is container-only.
- A Windows installer / service registration / `.app`/MSI packaging — later packaging task.
- Windows runtime smoke testing — deferred to a Windows machine (see Testing).

## Testing

**Bar for this pass (developed on macOS, no Windows box):**
- `GOOS=windows GOARCH=amd64 go build ./...` — compiles clean.
- `GOOS=windows go vet ./...` — clean (where vet supports the cross GOOS).
- `GOOS=linux go build ./...` — compiles clean (free byproduct of fix #1).
- The existing macOS `go test ./internal/...` suite stays fully green.
- `internal/tray` `TrayState` pure tests pass; a new `iconBytes` test asserts non-empty bytes for green/red on the current platform.
- `internal/sandbox` `InjectionArgs` gains a test asserting the Podman alias (`host.containers.internal`) vs Docker alias.

**Deferred to a Windows host:** actually running `redactr` (daemon + control socket), `redactr tray` (notification-area icon flips green/red), and `redactr claude` (Docker Desktop container self-routes to the host proxy).

## Build order

1. **Firewall build fix** (`redirect_other.go`) — unblocks `GOOS=windows`/`GOOS=linux` build; verify cross-compile.
2. **Daemon spawn split** (`client_unix.go` / `client_windows.go`).
3. **Runtime-aware host alias** (`internal/sandbox/inject.go` + test).
4. **Native Windows tray** (icon assets + `SetIcon`/`SetTooltip`, build-tag change + `iconBytes` test).
5. **Architecture spec update** + final cross-compile verification.
