# Redactr v2 — Architecture Design

**Status:** Architecture spec (approved). Each subsystem (A–E) gets its own implementation spec → plan → build afterward.
**Date:** 2026-05-30

## Problem

Redactr v1 distributes protection by **mutating the host environment**: system-wide `HTTPS_PROXY`/`NODE_EXTRA_CA_CERTS`, host CA trust, and `redactr shell` (which execs a subshell with the proxy env). This is structurally brittle:

- Env-var inheritance only reaches shells launched *after* the var was set. A new terminal window is a coin flip.
- System-wide proxy/CA mutation is fragile and invasive.
- The whole "configure the machine, then hope tools inherit it" model fails the moment a tool starts outside a bound shell.

v1 also only *redacts* (scans API traffic for PII/secrets). It does nothing about the larger threat: an AI agent running **malicious dependencies or files** and compromising the host.

## Core inversion

**Stop mutating the host environment. Instead, every AI agent is born inside a hardened container whose run-spec already contains the proxy route and CA — injected by the client at launch, per-session, deterministic.** A new terminal window is irrelevant because nothing depends on inherited shell state. The same container boundary that fixes distribution also sandboxes execution, protecting the host from malicious code.

The Go binary stops being "a daemon you configure system-wide" and becomes a **desktop client** (menubar/tray app) that pulls policy from a **central control-plane server** and launches hardened containers. Config, dashboard, and monitoring move to the server. The proxy stays **local, per-machine** — the server never sees traffic or code.

## Decisions (locked)

| # | Decision | Choice |
|---|---|---|
| 1 | Audience | **Team/org, central admin.** Multi-tenant server; device-level identity. |
| 2 | Spec strategy | **Architecture spec first** (this doc); subsystems get their own specs. |
| 3 | Proxy location | **Local, per dev machine.** Server is control plane only. |
| 4 | Mount model | **Bind-mount project dir RW** by default; admin can force **copy-in/diff-back** per-org or per-repo. |
| 5 | Egress | **Proxy-forced, open destinations** — single mode for v2. Transparent redirect → local proxy → scan/redact/denylist. Deny-by-default allowlist **deferred**. |
| 6 | Offline behavior | **Fail-open with cached policy + cached images.** Queue monitoring, sync later. |
| 7 | Image pipeline | redactr base image; admins push Dockerfiles; **server builds + signs centrally**, pushes to registry; clients **pull + verify signature/digest**. |
| 8 | Identity | **Device enrollment only** (org token → device credential). Per-machine attribution. SSO **later**. |
| 9 | Tool scope | Claude Code CLI, Codex CLI, **Copilot CLI** (container); Claude/ChatGPT **Desktop MCP servers** (container, in v2); **all VS Code AI plugins incl. Copilot + Claude ext** (Dev Container, in v2). **Cursor out of v2** (mechanism generalizes to it for free later). |
| 10 | VS Code posture | **Carrot.** Dev Container is the protected path; native host VS Code gets traffic redacted via `pf`-redirect + flagged "unsandboxed", not blocked. No managed-policy hardening in v2. |

## Topology

```
┌─────────────────────────── Dev machine ───────────────────────────┐
│   redactr client (one local daemon)                                │
│   ├─ menubar/tray UI  ●  green = proxy up / red = down             │
│   ├─ supervises  →  local MITM proxy (:47474) + scanner pipeline   │
│   ├─ Sandbox engine → Docker | Podman | Colima (pluggable)        │
│   ├─ host-process monitor (runaway detection)                     │
│   └─ policy+image cache (fail-open offline)                        │
│            │ injects at launch: HTTPS_PROXY + CA + REDACTR_BOUND   │
│            ▼                                                        │
│   ┌─ redactr container (per session) ──────────────┐               │
│   │  claude / codex / copilot · bind-mount ./proj   │              │
│   │  egress → transparent redirect → local proxy    │──────────────┼──▶ AI APIs
│   │  hardened: rootless/userns, no docker.sock,     │   scanned,    │   (+ any domain
│   │  dropped caps, seccomp, no-new-privileges       │   redacted,   │    minus denylist)
│   └─────────────────────────────────────────────────┘  denylisted │
└────────────────────────────────┬───────────────────────────────────┘
                                  │  enroll · pull policy/images · push monitoring (metadata only)
                                  ▼
                   Control-plane server (per-org, central admin)
                   dashboard · policy/denylist · Dockerfile build+sign · registry · monitor
```

## The unifying abstraction: execution hosts, not tools

Don't model protection per AI tool. Model it per **execution host**. Everything reduces to one internal primitive:

```
Sandbox.Launch({ imageRef@digest, mode, entrypoint, mounts, envInject, hardeningProfile })
        mode ∈ { ephemeral-tty, stdio-attached, workspace-remote }
```

Three **front doors** map onto it, differing only in entrypoint and host↔container transport:

| Front door | Command | Mode | Covers |
|---|---|---|---|
| CLI agents | `redactr claude` / `codex` / `copilot` | ephemeral-tty | terminal agents |
| Editor plugins | `redactr code <project>` → generates `devcontainer.json` → VS Code remote-attaches | workspace-remote | **all** VS Code AI plugins at once — Copilot, Claude ext, Continue, … |
| Desktop MCP | `redactr-mcp-wrap <server>` (from Desktop app config) → MCP server in container + JSON-RPC redaction MITM | stdio-attached | Claude/ChatGPT Desktop execution surface |

Key insight: **VS Code Dev Containers is an *extension-host* mechanism, not a Copilot mechanism.** Anything in the workspace extension host runs in the container, so one Dev Container sandboxes every VS Code-family AI plugin simultaneously. Cursor (a VS Code fork) is covered by this same path for free when we choose to support it.

All three doors inherit the same hardening + egress redirect + CA/mount injection. The `redactr` CLI is a thin client to the local daemon that owns the `Sandbox` primitive.

## Subsystems

| | Subsystem | Responsibilities | v1 reuse |
|---|---|---|---|
| **A** | **Control-plane server** | enrollment, signed policy distribution, image build/sign/registry, monitoring ingestion, dashboard | new |
| **B** | **Desktop client daemon** | tray + green/red indicator, local proxy supervision, policy/image cache, local socket API | proxy + scanner reused |
| **C** | **Sandbox engine** | runtime abstraction, hardening profile, network redirect, CA/mount injection, `Launch` × 3 modes | new — keystone |
| **D** | **Front doors** | `redactr` CLI agents, `redactr code` Dev Container, `mcp-wrap`→container | `mcpwrap`, `cli` extended |
| **E** | **Monitoring** | host process scan, re-classify (protected/runaway/unsandboxed), push events | `sessions` extended |

### A — Control-plane server

Multi-tenant, one org per customer, device-level identity. Holds five things and **never sees traffic, code, or redacted values — only metadata**:

1. **Enrollment & device registry** — admin mints an org enrollment token; client enrolls a device and receives a device credential (mTLS cert / scoped token). Attribution is per-device.
2. **Policy distribution** — client pulls a **signed policy bundle** (denylist, scan-layer config, per-repo mount-mode overrides, image `ref@digest`s). Polled with ETag; cached locally; **fail-open** when unreachable.
3. **Image pipeline** — admin uploads a Dockerfile (`FROM redactr-base`); server builds it in a sandboxed builder, **signs** it (cosign-style), pushes to a **registry**, publishes `ref@digest` into the policy bundle. Clients pull and **verify signature + digest** before running.
4. **Monitoring ingestion** — clients push session/runaway **events** (metadata only); server aggregates per-org.
5. **Dashboard** — v1's local dashboard moves here: fleet sessions, runaway alerts, redaction stats, policy editor, image management, device registry.

**Transport:** HTTPS REST — `enroll`, `pull-policy` (poll + ETag), `push-events` (batched). A live push channel (websocket) is a later optimization; polling keeps v2 simple and is naturally fail-open.

### B — Desktop client daemon

One long-lived local process. Owns the menubar/tray UI with a **green (proxy up) / red (proxy down)** indicator. Supervises the local MITM proxy + scanner pipeline (reused from v1). Owns the `Sandbox` engine, the host-process monitor, and the policy/image cache. Exposes a **local socket API** that the thin `redactr` CLI talks to (and starts the daemon if it isn't running). Proxy/scanner config is now sourced from the cached server policy instead of `~/.redactr/config.yaml` alone.

### C — Sandbox engine (keystone)

**Runtime abstraction** — a `Runtime` interface with Docker / Podman / Colima(Lima) implementations. Client auto-detects what's installed; admin can pin per-org. On macOS all three are VM-backed, so a container escape lands in a throwaway VM, not the Mac host. The interface supports three launch modes: ephemeral-tty, stdio-attached, workspace-remote.

**Hardening profile** (applied to *every* container, non-negotiable):
- rootless / user-namespace remap where supported
- `--cap-drop ALL` + minimal add-back, `--security-opt no-new-privileges`, seccomp on
- read-only root FS + tmpfs scratch; resource limits (cpu/mem/pids)
- **never** `--privileged`, **never** mount the Docker socket, no host networking

**Networking / egress** — container netns gets a **transparent redirect** (`iptables` DNAT on 80/443 → host proxy via host-gateway) plus `HTTPS_PROXY` env for well-behaved tools. **Default: all non-80/443 outbound dropped** (prevents raw-socket exfil on arbitrary ports); DNS via a controlled resolver. Admin-configurable **port allowlist** carves out exceptions (e.g. port 22 for SSH-based `git`); HTTPS git remotes are recommended inside containers and work through the proxy unchanged. The proxy forwards 80/443 to any destination **minus the denylist** (the "open destinations" choice). **Denylist enforcement reuses v1's `internal/domain` filter** (`Filter.IsBlocked`, already enforced in `internal/proxy/proxy.go`); the only change is the source — today local `config.yaml`/dashboard, in v2 the server policy bundle — now applied to proxy-forced container egress.

**CA & mount injection at launch** — the per-machine MITM CA is mounted in and `NODE_EXTRA_CA_CERTS`/`SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE` are set in the run-spec; project dir bind-mounted RW (or copy-in/diff-back per policy); nothing else of the host is visible. The central signed image stays generic — trust and routing are per-machine, injected at `run`.

**Image layering** — `redactr-base` (hardened; the "few binaries": git, node, python, build toolchain, the agent CLIs) → org overlay (admin Dockerfile `FROM redactr-base`) → signed → registry.

### D — Front doors

The three entrypoints in the table above. `redactr code` generates a `devcontainer.json` pointing at the org's signed redactr image and drives VS Code's Remote/Dev Containers attach. `redactr-mcp-wrap` already exists (`cmd/redactr-mcp-wrap`, `internal/mcpwrap`) as a stdio MITM that redacts JSON-RPC; v2 extends its launch step from `exec.Command(server)` on the host to `Sandbox.Launch(stdio-attached)` so the MCP server runs in a container.

### E — Monitoring

Client keeps the host-process scanner (`internal/sessions`), with v2 verdicts redefined around containers:

- **Protected** — process runs inside a redactr container (launch label + `REDACTR_BOUND`), or native traffic is observed transiting the local proxy.
- **Runaway** — a known AI tool running on the host, outside any redactr container, talking direct to a provider host. Highest-priority alert.
- **Unsandboxed** — native VS Code AI plugin whose traffic *is* redacted (via `pf`-redirect) but whose execution is *not* containerized. Distinct from runaway.

Events (metadata only) are batched to the server → fleet dashboard + alerts. Local remediation (terminate runaway) carries over from v1 and also surfaces for the admin.

## Build order

Dependency-driven; each step is its own spec → plan → build:

1. **C — Sandbox engine.** Prove "launch X in a hardened, egress-locked, CA-injected container" with the simplest door (`redactr claude`, ephemeral). Everything stands on this.
2. **B — Desktop daemon.** Wrap C: tray, green/red indicator, proxy supervision, local cache (server stubbed).
3. **A — Control-plane server.** Enrollment + signed policy + image pipeline + monitor ingest + dashboard; wire client pull/push.
4. **D — Front doors.** `redactr code` Dev Container **(the Copilot gate — v2 does not ship without it)** + `mcp-wrap`→container (Desktop MCP).
5. **E — Monitoring.** Host scan + re-classify + event push, surfaced on the server dashboard.

## Threat model & residual gaps

| Vector | v2 outcome |
|---|---|
| Malware reads host secrets / other repos | **Blocked** — not mounted, not visible |
| Malware damages host | **Blocked** — namespaces + (on macOS) VM boundary |
| Agent runs harmful commands (CLI / editor-in-container / MCP) | **Sandboxed** to the container |
| Secret/PII in egress | **Scanned + redacted** at the proxy |
| Known-bad domains | **Denylisted** |
| Project-dir poisoning / re-infection (run a poisoned file on host later) | **Residual** — mitigated by ephemeral containers + diff-back opt-in |
| Deliberate encoded exfil to an allowed domain | **Residual** — accepted (open egress; deny-by-default deferred) |
| Native VS Code execution | **Residual** — redacted + flagged, not sandboxed (carrot posture) |
| Malicious `extensionKind: ["ui"]` extension running host-side | **Residual** — extension supply-chain, out of scope for v2 |
| Non-containerizable toolchains (iOS, GPU, hardware) | Fall back to redact + monitor, no sandbox |

## Explicitly deferred (not in v2)

- Deny-by-default egress allowlist (v2 is open-destinations only).
- User identity / SSO (v2 is device-enrollment only).
- Cursor and other non-VS-Code editors as first-class targets (Dev Container path generalizes to them later).
- Managed-policy hardening of native VS Code (disabling agent auto-run).
- Live websocket push channel (v2 polls).
- GUI sandboxing beyond Desktop MCP servers.
- Host-level transparent redirect on Windows (WFP/WinDivert) and a WSL2-hosted daemon — the redactr daemon/proxy/tray is a **native host app on macOS and Windows**, and AI agents run in Linux containers (Docker Desktop) that self-redirect to the host proxy via the in-container iptables entrypoint, so no host redirect is needed. Native Linux **desktop** host support (tray) is out of scope — Linux is the container OS only.

## Open items for subsystem specs

- Exact policy-bundle schema and signing/verification scheme.
- Device credential mechanism (mTLS cert vs scoped token) and rotation.
- `devcontainer.json` generation details and how pre-baked extensions are pinned.
- Registry choice (self-hosted vs managed) and image GC/retention.
- macOS bind-mount performance mitigation (VirtioFS / named volumes) for workspace-remote mode.
- Local daemon ↔ CLI socket API surface.
