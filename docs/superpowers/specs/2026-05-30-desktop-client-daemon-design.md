# Redactr v2 — Subsystem B: Desktop Client Daemon Design

**Status:** Design (approved). Implementation plan follows.
**Date:** 2026-05-30
**Parent:** `docs/superpowers/specs/2026-05-30-redactr-v2-architecture-design.md` (subsystem B)
**Depends on:** Subsystem C (Sandbox engine) — done, merged on `main` at `internal/sandbox`.

## Goal

Turn the v1 single-binary proxy daemon into the **control/policy plane** of the v2 desktop client: a long-lived local daemon that supervises the existing proxy/scanner, owns a local policy/image cache (fail-open, server stubbed until subsystem A), exposes a local control socket, and is fronted by two thin clients — the `redactr` CLI and a `redactr tray` macOS menubar with a green/red proxy indicator.

## Key shaping facts

- v1's `cmd/redactr/main.go` is a 356-line `main()` god-function that wires every component then blocks on a signal. Subsystem B extracts that wiring into `internal/daemon`.
- Proxy enable/disable, status, and the `proxy.pid` / `dashboard.port` state files already exist; the tray's green/red simply reflects that state.
- Subsystem C's `redactr claude` launches the container **directly** because an interactive `docker run -it` needs the **caller's TTY**. The daemon therefore cannot own the interactive launch. The daemon is the control/policy plane; the CLI remains the TTY owner.

## Decisions (locked)

| # | Decision | Choice |
|---|---|---|
| 1 | Tray placement | **Separate `redactr tray` process** (fyne.io/systray) that polls the daemon socket. Daemon stays headless. Built **last**. |
| 2 | main.go restructure | **Extract to `internal/daemon`** (`Daemon` struct, Build/Start/Stop); main.go becomes thin subcommand dispatch. |
| 3 | CLI ↔ daemon | **Socket preflight, CLI launches.** `redactr claude` consults the daemon (ensure proxy + fetch policy), then launches the container in its own TTY. |
| 4 | Control transport | **HTTP over a Unix domain socket** at `~/.redactr/state/redactr.sock` (perms 0600). |
| 5 | Policy cache | **`~/.redactr/cache/policy.json`**, typed, seeded from config; fail-open; `// SEAM` for subsystem A refresh. |

## Architecture

```
                 ┌──────────────── redactr daemon (headless service) ───────────────┐
                 │  internal/daemon.Daemon  (extracted from v1 main())               │
                 │   ├─ proxy + scanner + dashboard + admin + firewall + sidecar     │
                 │   │     (all v1 components, behavior-preserving)                   │
                 │   ├─ internal/policy cache  (policy.json, seeded, fail-open)       │
                 │   └─ control socket  ~/.redactr/state/redactr.sock (HTTP/UDS)      │
                 └──────────▲───────────────────────────────────▲───────────────────┘
                            │ /status /proxy/* /launch-policy     │ /status /proxy/*
            ┌───────────────┴────────────────┐         ┌──────────┴─────────────┐
            │  redactr CLI (TTY owner)        │         │  redactr tray (menubar)│
            │  EnsureDaemon→EnsureProxy→Policy│         │  poll /status → 🟢/🔴   │
            │  → sandbox.Engine.Launch (C)    │         │  toggle proxy · dash   │
            └─────────────────────────────────┘         └────────────────────────┘
```

## Components

### B1 — `internal/policy`
Typed policy cache, independent of the server.
- `Policy struct { Image string; MountMode string; Denylist []string; Version int; FetchedAt time.Time }` (`MountMode` ∈ `bind` | `diffback`).
- `Load(baseDir) (Policy, error)` — read `~/.redactr/cache/policy.json`; if missing, return `Seed(cfg)`.
- `Seed(image string, mountMode string, denylist []string) Policy` — defaults: `image="redactr-base:local"`, `mountMode="bind"`, `denylist=cfg.Proxy.BlockedDomains`.
- `Save(baseDir, Policy) error` — atomic write (temp + rename).
- `LaunchInfo struct { Image, MountMode string; Denylist []string; ProxyAddr string }` — the wire type returned by `GET /launch-policy`: the persisted `Policy` fields plus the **live** `ProxyAddr` (which is daemon runtime state, not cached policy). The daemon assembles it from `Policy` + current proxy state.
- `// SEAM:` subsystem A populates/refreshes the persisted `Policy` from the signed server bundle; until then it is seeded/static.

### B2 — `internal/daemon`
- `Daemon` struct owns every component currently constructed in `main()` plus the policy cache and control socket.
- `Build(baseDir string) (*Daemon, error)` — performs the wiring currently inline in `main()` (config, singleton lock, licensing, CA, store, scanners, pipeline, coordinator, admin, domain filter, hub, proxy, dashboard API, firewall controller, transparent listener, sidecar, config watcher), in the **exact same order**.
- `Start() error` — starts listeners (admin, dashboard, transparent, control socket; proxy iff `cfg.Proxy.Enabled`), reconcile loop, sidecar.
- `Stop()` — mirrors v1 shutdown (reconcile cancel, firewall disable, proxy stop, sidecar stop, servers stop, firewall cleanup, lock release, socket removal).
- `Run(baseDir)` — `Build` → `Start` → block on SIGINT/SIGTERM → `Stop`. main.go's default path calls this.
- Behavior-preserving: all existing tests stay green; a new smoke test asserts `Build`+`Start` brings the control socket up and `/status` responds, then `Stop` cleans up.

### B3 — Control socket (in `internal/daemon`)
HTTP server on a `net.Listen("unix", sockPath)` listener; socket file 0600; removed on `Stop`; a stale socket from a crashed predecessor is removed at `Build` (the singleton lock already guarantees only one live daemon).
- `GET /status` → `{ "proxy": {"enabled": bool, "addr": string}, "dashboard": string, "version": string }`
- `POST /proxy/enable` → enables the proxy (writes `proxy.pid`), returns `/status` body
- `POST /proxy/disable` → disables the proxy, returns `/status` body
- `GET /launch-policy?tool=claude` → `{ "image": string, "mountMode": string, "denylist": [string], "proxyAddr": string }` (proxyAddr from live proxy state; rest from the policy cache)
- Unknown routes → 404; malformed → 400; JSON throughout.

### B4 — CLI client + auto-start (`internal/cli`)
- `internal/cli/client.go`: `Client` over the UDS — `Status()`, `EnableProxy()`, `LaunchPolicy(tool) (policy.LaunchInfo, error)`.
- `EnsureDaemon(baseDir) error` — dial the socket; on failure, fork the current binary as a detached daemon (`exec` self with no subcommand, `Setsid`), poll the socket up to ~10s; error clearly if it never comes up.
- `RunAgent` (modify B5) uses these.

### B5 — Rewire `RunAgent` (`internal/cli/agent.go`)
New flow, replacing the direct `Discover`:
1. `EnsureDaemon(baseDir)`.
2. `client.EnableProxy()` (idempotent — ensures the container has a live proxy).
3. `info := client.LaunchPolicy(tool)` → image, mountMode, proxyAddr, denylist.
4. Build `sandbox.Spec{ Mode: ModeEphemeralTTY, Image: info.Image, ProjectDir: cwd, Entrypoint: append(entry, extra...), ProxyAddr: info.ProxyAddr, CACertPath: <baseDir>/certs/ca.crt }`.
5. `eng.Launch(ctx, spec)` (C, in the CLI's TTY).
- `mountMode=diffback` is not implemented in C yet → if policy requests it, return a clear "diff-back mount mode not yet supported" error (SEAM). Default `bind` proceeds.
- `sandbox.Discover` is retained as the fallback the daemon uses internally; the CLI no longer calls it directly.

### B6 — `redactr tray` (built last)
- New subcommand `redactr tray`; new dep `fyne.io/systray` (CGo on macOS).
- `systray.Run(onReady, onExit)` on the main thread; a goroutine polls `GET /status` every 3s.
- Icon: **green** when `proxy.enabled && proxy.addr != ""`, else **red**. Menu: proxy enable/disable toggle (POST), "Open Dashboard" (open `http://<dashboard>`), "Quit".
- Testable seam: `trayState(status) (color, menuLabels)` is a pure function with unit tests; the systray glue is a thin shell. .app bundling is a later packaging task, out of scope here.

## File structure

| File | Responsibility |
|---|---|
| `internal/policy/policy.go` (+ test) | Policy type, Load/Seed/Save |
| `internal/daemon/daemon.go` (+ smoke test) | Daemon struct, Build/Start/Stop/Run (extracted wiring) |
| `internal/daemon/socket.go` (+ test) | UDS HTTP control server + handlers |
| `internal/cli/client.go` (+ test) | CLI socket client + EnsureDaemon |
| `internal/cli/agent.go` (modify) | RunAgent preflight via socket |
| `cmd/redactr/main.go` (modify) | Thin subcommand dispatch → daemon.Run / tray / RunAgent |
| `internal/tray/tray.go` (+ test for pure helper) | `redactr tray` menubar |

## Error handling

| Case | Behavior |
|---|---|
| Socket dial fails | `EnsureDaemon` forks the daemon, waits ~10s; clear error if it never binds |
| Daemon already running (singleton) | Existing lifecycle lock applies; second `daemon.Run` defers to v1's singleton handling |
| Stale socket file after crash | Removed at `Build` (singleton lock guarantees no live peer) |
| `mountMode=diffback` requested | Clear "not yet supported" error (SEAM until C adds it) |
| Server unreachable (no subsystem A) | Fail-open: serve seeded/cached policy |
| Tray can't reach socket | Icon shows red ("daemon down"); menu offers nothing destructive |

## Testing

- **Unit:** `policy` Load/Seed/Save round-trip + missing-file seeding; socket handlers via `httptest`/direct handler calls (status, enable/disable, launch-policy, 404/400); CLI `Client` parsing against a UDS `httptest` server; `EnsureDaemon` with a faked spawn (injectable spawn func); `trayState` pure helper.
- **Integration/smoke:** `daemon.Build`+`Start` on a temp baseDir brings `/status` up over the UDS, then `Stop` removes the socket. (No Docker needed.)
- **Manual:** `redactr` (daemon) running → `redactr tray` shows green; toggle proxy → icon flips red/green; `redactr claude` in a project dir launches the container via preflight (covered end-to-end once Docker is available, per subsystem C).

## Build order

1. **B1** `internal/policy` — cache type + Load/Seed/Save.
2. **B2** `internal/daemon` — behavior-preserving extraction of main() + smoke test.
3. **B3** control socket — UDS HTTP server + handlers, wired into Daemon.
4. **B4** CLI client + `EnsureDaemon` auto-start.
5. **B5** rewire `RunAgent` to preflight via socket.
6. **B6** `redactr tray` — menubar (new dep), built last.

## Out of scope (deferred)

- Server-driven policy refresh, enrollment, device credentials (subsystem A).
- `diffback` mount mode (subsystem C extension).
- macOS `.app` bundling / login-item registration for the tray (packaging task).
- Windows/Linux tray (macOS-first per the architecture spec).
