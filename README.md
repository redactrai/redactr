<div align="center">

# Redactr

**Keep PII and secrets out of your AI coding tools.**

Redactr is a local HTTPS proxy that redacts emails, SSNs, API keys, and other sensitive data from every request your AI tools send — plus an optional hosted control plane that manages a whole team's proxies and runs each AI agent inside a hardened, egress-locked container.

[![CI](https://github.com/redactrai/redactr/actions/workflows/ci.yml/badge.svg)](https://github.com/redactrai/redactr/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/redactrai/redactr)](https://goreportcard.com/report/github.com/redactrai/redactr)
[![Go Version](https://img.shields.io/github/go-mod/go-version/redactrai/redactr)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)](#)
[![Made with Go](https://img.shields.io/badge/made%20with-Go-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)

</div>

---

## Table of Contents

- [Why Redactr](#why-redactr)
- [How it works](#how-it-works)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Install](#install)
  - [Build from source](#build-from-source)
  - [Run it locally end-to-end](#run-it-locally-end-to-end)
- [Front doors](#front-doors-how-each-tool-gets-protected)
- [Dashboards](#dashboards)
- [Configuration](#configuration)
- [Detection](#detection)
- [Benchmarks](#benchmarks)
- [Testing](#testing)
- [Project structure](#project-structure)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why Redactr

AI coding tools (Claude Code, GitHub Copilot, ChatGPT Codex) send your prompts, files, and terminal context to a model provider. That's a lot of trust — and a lot of secrets, customer PII, and proprietary code leaving your machine on every keystroke.

Redactr sits in the middle and scans every outbound request through a four-layer pipeline before it leaves, replacing sensitive data with `[REDACTED-EMAIL]`, `[REDACTED-SSN]`, and friends. In **team mode** it goes further: each AI agent runs inside a hardened container whose network egress is default-deny and force-routed through the proxy, so redaction can't be bypassed and a malicious dependency can't reach your host.

- 🛡️ **Redacts before it leaves** — emails, SSNs, credit cards, phone numbers, API keys, JWTs, connection strings, and ML-detected names/addresses.
- 📦 **Sandboxed agents** — CLI agents and VS Code AI plugins run in egress-locked containers (the Copilot gate via Dev Containers).
- 🏢 **Team control plane** — multi-tenant orgs, device enrollment, signed policy distribution, and fleet monitoring. The server sees **metadata only** — never your traffic, code, or redacted values.
- 🔌 **Zero-config tools** — `redactr claude`, `redactr code ./project`, or a bound `redactr shell`; no per-tool proxy fiddling.
- ⚡ **Fast & dependency-free** — three static Go binaries, no runtime deps (a container runtime is needed only for the sandboxed front doors).
- 🖥️ **Cross-platform** — macOS, Linux, and Windows, with a system-tray client showing a green/red proxy indicator.

## How it works

```
                          ┌─────────────────────────────┐
                          │   redactr-server (hosted)    │  metadata only
                          │  orgs · devices · enrollment │
                          │  signed policy · monitoring  │
                          │  image build/sign · dashboard│
                          └──────────────┬──────────────┘
                  enroll / pull policy /  │  push events
                         report metadata  │
        ┌──────────────────────────────────────────────────┐
        │                  redactr (client daemon)          │
        │                                                   │
  AI agent (container, egress→proxy) ─┐                     │
  redactr shell (host, env-bound)  ───┼─▶ Redactr Proxy (MITM) ─▶ AI Provider API
  VS Code Dev Container          ─────┘        │
                                          [4-Layer Scanner]
                                          1. Regex   (emails, SSNs, API keys, JWTs)
                                          2. Entropy (high-randomness tokens, secrets)
                                          3. GLiNER  (names, addresses — Python sidecar)
                                          4. Context Gate (business rules — extensible)
                                                  │
                                          [Redactor] → [REDACTED-EMAIL], [REDACTED-SSN], …
                                                  │
                                          [BoltDB] scan logs (redaction details + latency)
```

**Privacy invariant:** the control plane only ever receives metadata (session/runaway events, device attribution) — never request bodies, source code, connection strings, env values, or redacted content.

### Components

| Binary | Role |
|--------|------|
| `redactr` | The desktop client: a local daemon (proxy + scanner + dashboard + control socket) and the user-facing subcommands (`claude`, `code`, `enroll`, `shell`, `tray`, …). |
| `redactr-server` | The hosted **control plane**: multi-tenant orgs/devices, device enrollment, signed policy distribution, monitoring ingestion, image build/sign pipeline, and the admin dashboard. |
| `redactr-mcp-wrap` | Wraps a Desktop-app MCP server, scanning its stdio JSON-RPC; with `--container`, runs the MCP server inside a redactr container too. |

## Getting started

### Prerequisites

- **Go 1.26+** (the only requirement to build and run the proxy, scanner, and control plane).
- **A container runtime** — Docker, Podman, or Colima — *only* for the sandboxed agent front doors (`redactr claude`, `redactr code`). Everything else runs without it.
- **Python 3** (optional) — for the GLiNER ML layer (names/addresses). The proxy works without it using the regex + entropy layers.
- `curl` and `jq` for the walkthrough below (`jq` is just for pretty output).

### Install

```bash
# Install the binaries directly with the Go toolchain
go install github.com/redactrai/redactr/cmd/redactr@latest
go install github.com/redactrai/redactr/cmd/redactr-server@latest
go install github.com/redactrai/redactr/cmd/redactr-mcp-wrap@latest
```

> `@latest` resolves once a release is tagged; until then use `@main` for the tip of the default branch.

### Build from source

```bash
git clone https://github.com/redactrai/redactr.git
cd redactr
make build      # → bin/redactr, bin/redactr-mcp-wrap, bin/redactr-server
```

The walkthrough below uses the `./bin/...` paths from a source build; if you installed via `go install`, drop the `./bin/` prefix.

### Run it locally end-to-end

This brings up **both the control-plane server and a client** on your machine and walks an enrollment through to live redaction — no Docker required. Run each block in its own terminal.

**1 · Start the control plane** *(terminal 1)*

```bash
REDACTR_DEV_MODE=1 \
  REDACTR_SUPERADMIN_PASSWORD=dev-password \
  REDACTR_MACHINE_KEY=dev-machine-key \
  ./bin/redactr-server
# → listening on :8080  ·  admin dashboard at http://localhost:8080/
```

Open <http://localhost:8080/> and sign in at the **login page** (`/admin/login`) as
`admin` / `dev-password`. That sets a session cookie the dashboard uses for all
admin actions. (In production you set `REDACTR_SUPERADMIN_PASSWORD_HASH` to a
bcrypt hash instead of a plaintext password, and/or wire up OIDC SSO — see
[deploy/README.md](deploy/README.md).)

**2 · Create an org and an enrollment token** *(terminal 2)*

Admin actions (creating orgs, editing policy, …) are gated by a **session
cookie**, so the easy path is to click through the dashboard: create *Acme Corp*
and mint an enrollment token from the UI.

If you prefer the API, note that the only admin endpoint reachable without a
browser session is enrollment-token minting, which also accepts the
`X-Machine-Key` header (set above via `REDACTR_MACHINE_KEY`). Create the org in
the dashboard, copy its ID, then:

```bash
ORG_ID=<paste-org-id-from-dashboard>

TOKEN=$(curl -s -X POST localhost:8080/admin/orgs/$ORG_ID/enrollment-tokens \
  -H "X-Machine-Key: dev-machine-key" -H 'Content-Type: application/json' \
  -d '{"expires_in_hours":24,"max_uses":0}' | jq -r .token)

echo "Org:   $ORG_ID"
echo "Token: $TOKEN"
```

**3 · Enroll this device, then start the client daemon** *(terminal 2)*

```bash
./bin/redactr enroll --server http://localhost:8080 --token "$TOKEN"
./bin/redactr
# → client daemon: proxy + dashboard :9080 + admin/metrics :9090
```

Now refresh the **server** dashboard (`:8080`): your device appears under *Acme Corp*, the signed policy syncs to the client, and monitoring metadata starts flowing. Open the **client** dashboard at <http://localhost:9080> to toggle the proxy and watch redaction live.

**4 · See redaction immediately** — no external API call *(terminal 3)*

```bash
curl -s localhost:9080/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"text":"contact jane@acme.com, SSN 123-45-6789, key sk-live-abc123XYZ"}' | jq
```

You'll get back the text with the email, SSN, and key replaced, plus a per-finding report (which layer caught what). Check `http://localhost:9090/health` for readiness and `http://localhost:9090/metrics` for Prometheus metrics.

**5 · Sandbox a real agent** *(needs a container runtime)*

```bash
make sandbox-image            # build redactr-base:local (requires Docker)
./bin/redactr claude          # Claude Code inside a hardened container, egress forced to the proxy
./bin/redactr code ./project  # VS Code Dev Container — sandboxes Copilot + every VS Code AI plugin
```

> **Just want the standalone proxy, no server?** Skip steps 1–3: run `./bin/redactr`, then `./bin/redactr shell` (a shell with the proxy + CA env exported) and launch any tool from it. See [startup.md](startup.md) for the standalone deep-dive.

## Front doors (how each tool gets protected)

| Tool surface | Command | Mechanism |
|--------------|---------|-----------|
| CLI agents (Claude Code, Codex, Copilot CLI) | `redactr claude` / `codex` / `copilot` | Hardened container, egress force-routed to the proxy |
| VS Code plugins (Copilot, Claude, …) | `redactr code <project>` | Generates `.devcontainer/devcontainer.json` so the extension host runs in a redactr container |
| Desktop-app MCP servers | `redactr-mcp-wrap [--container] <cmd>` | Scans the MCP stdio JSON-RPC stream; optionally containerizes the server |
| Any host process | `redactr shell` / manual env | Host shell bound to the proxy via `HTTPS_PROXY` + CA env |

`redactr claude\|codex\|copilot` launches the agent inside a container built from the org's signed policy image (`ref@digest`), with the CA mounted read-only, proxy env injected, a default-deny egress firewall that DNATs ports 80/443 to the host proxy, and `--cap-drop ALL` hardening.

## Dashboards

- **Client dashboard** (`http://localhost:9080`): proxy toggle, redaction metrics, 24-hour trend, intercepted tools, safety recommendations, per-entry redaction logs (which layer caught what and why), and live config editing.
- **Server admin dashboard** (`http://<host>:8080/`, gated by session-cookie login at `/admin/login` or OIDC SSO): orgs, device registry, enrollment-token minting, policy editor (denylist + image pinning), fleet monitoring events, and the Dockerfile build/sign image pipeline.

## Configuration

### Client (`~/.redactr/config.yaml`)

Created with defaults on first run, hot-reloaded on edit (also via `SIGHUP`). Common knobs:

```yaml
proxy:
  enabled: true
  intercepted_domains:            # domains to MITM
    - api.anthropic.com
    - api.openai.com
    - api.githubcopilot.com
  blocked_domains: []

scanning:
  inference_timeout_ms: 5000      # per-layer timeout
  entropy_threshold: 4.5          # entropy scanner sensitivity
  cache_max_size: 10000
  bypass:                         # skip scanning for these
    - path: "/v1/models"
    - prefix: "/.well-known/"
    - method: "OPTIONS"

file_blocking:
  blocked_extensions: [".env", ".tfstate", ".pem", ".key", ".p12", ".pfx"]
  content_patterns_enabled: true

admin:
  port: 9090                      # health + metrics

logging:
  level: info                     # debug | info | warn | error
  output: stdout
```

Detection layers are managed per-rule under `scanning.rules` and are most easily edited from the dashboard's **Config** tab. Legacy boolean flags (`regex_enabled`, `entropy_enabled`, `gliner_enabled`) are still honored — they're auto-migrated to the per-rule form on load.

### Server (`redactr-server`, environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `REDACTR_SERVER_ADDR` | `:8080` | Listen address |
| `REDACTR_SERVER_DB` | `./redactr-server.db` | Embedded SQLite path |
| `REDACTR_SERVER_KEY_DIR` | `./keys` | ECDSA signing keypair location |
| `REDACTR_SUPERADMIN_USER` | `admin` | Super-admin login username |
| `REDACTR_SUPERADMIN_PASSWORD_HASH` | _unset_ | bcrypt hash for super-admin login (or set `REDACTR_SUPERADMIN_PASSWORD` plaintext to have it hashed at startup) |
| `REDACTR_MACHINE_KEY` | _unset_ | Automation key accepted via `X-Machine-Key`, only on `POST /admin/orgs/{id}/enrollment-tokens` |
| `REDACTR_REGISTRY` | _unset_ | Enables the image pipeline; registry base for built images |
| `REDACTR_COSIGN_KEY` | `./keys/cosign.key` | cosign key for image signing |

Admin auth uses session-cookie login (`/admin/login`) and/or OIDC SSO. See
[deploy/README.md](deploy/README.md) for the full production setup (Docker,
Caddy, TLS, OIDC, super-admin hashing). At least one auth method
(`REDACTR_SUPERADMIN_PASSWORD_HASH`/`_PASSWORD` or OIDC) is required outside dev
mode.

The image build pipeline (`REDACTR_REGISTRY` set) additionally requires `docker` and `cosign` on the server host.

## Detection

### Scanning layers

| Layer | What it catches | Speed |
|-------|-----------------|-------|
| Regex | Emails, SSNs, credit cards, phone numbers, AWS keys, JWTs, connection strings, IP addresses | ~100ns |
| Entropy | High-entropy tokens, base64 secrets, random API keys that don't match fixed patterns | ~200ns |
| GLiNER | Names, addresses, dates of birth (requires Python sidecar) | ~50ms |
| Context Gate | Business-specific rules (extensible) | ~0ns |

### File blocking

These file types are blocked by default — their contents never reach AI providers: `.env`, `.tfstate`, `.pem`, `.key`, `.p12`, `.pfx`.

## Benchmarks

Measured against the **ai4privacy/pii-masking-300k** dataset (56 English samples, 433 PII entities) through the full proxy pipeline end-to-end. *(The benchmark exercises the local scanner against a labeled dataset — it does not call any LLM.)*

| Configuration | Precision | Recall | F1 | Avg latency/req |
|---------------|-----------|--------|-----|-----------------|
| **Full pipeline** (Regex + Entropy + GLiNER) | 79.5% | 68.8% | 73.8 | 91.5 ms |
| **Regex-only** (no GLiNER sidecar) | 98.6% | 90.9%¹ | — | 0.02 ms |

¹ Recall over regex-detectable PII. Run them yourself:

```bash
make benchmark                                                       # in-process pipeline micro-bench
go test -tags=benchmark ./benchmarks/ -run TestProxyE2EBenchmark -v  # full e2e (GLiNER needs the sidecar)
```

<details>
<summary>Per-type and per-layer detail</summary>

**Per-layer**

| Layer | Caught | False positives | Precision |
|-------|--------|-----------------|-----------|
| Regex | 141 | 2 | 98.6% |
| GLiNER | 154 | 74 | 67.5% |
| Entropy | 3 | 1 | 75.0% |

**Per PII type**

| PII Type | Total | Caught | Rate | Primary layer |
|----------|-------|--------|------|---------------|
| Email | 23 | 23 | 100% | regex |
| SSN | 27 | 27 | 100% | regex |
| Phone (US/UK/NL/intl) | 32 | 32 | 100% | regex |
| IP (v4 + v6) | 5 | 5 | 100% | regex |
| Driver's license | 13 | 13 | 100% | regex + gliner |
| Person names | 70 | 66 | 94.3% | gliner |
| ID cards | 42 | 40 | 95.2% | regex |
| Passport numbers | 18 | 17 | 94.4% | regex + gliner |
| Addresses | 76 | 33 | 43.4% | gliner |
| Dates/times | 45 | 11 | 24.4% | gliner |

Regex handles structured PII with near-perfect precision; GLiNER adds names/addresses that regex can't catch, at the cost of benign over-detections (generic words flagged as names). See [BENCHMARK_REPORT.md](BENCHMARK_REPORT.md) for the full breakdown.

</details>

## Testing

```bash
go test ./...                                          # full unit suite (no setup, all green)
go test ./test/integration/ -tags=integration -v       # full proxy pipeline integration
make benchmark                                          # benchmarks
```

## Project structure

```
cmd/redactr/              — Desktop client binary (daemon + subcommand dispatch)
cmd/redactr-server/       — Control-plane server binary
cmd/redactr-mcp-wrap/     — MCP wrapper (stdio interception, optional containerization)
internal/
  daemon/                 — Long-lived client daemon: wires + supervises every component
  cli/                    — User subcommands: claude/codex/copilot, code, enroll, shell, tray
  sandbox/                — Hardened container engine (spec, hardening, injection, launch argv)
  devcontainer/           — Generates .devcontainer/devcontainer.json for `redactr code`
  tray/                   — System-tray client (green/red proxy indicator; macOS/Windows)
  control/                — Control-socket DTOs (Status, LaunchInfo, PolicyBundle)
  policy/ policysync/     — Fail-open policy cache + signed-bundle fetch/verify
  enrollment/ monitor/    — Device enrollment state + scrubbed event collection/report
  signing/                — Detached ECDSA sign/verify (policy bundles, device tokens)
  api/                    — Client REST API + embedded dashboard
  certgen/                — ECDSA CA and per-domain cert issuance
  config/                 — YAML config with hot-reload
  coordinator/            — Wires scanner pipeline + redactor + cache
  proxy/                  — goproxy HTTPS MITM forward proxy
  redactor/               — [REDACTED-LABEL] replacement engine
  scanner/                — 4-layer scanning pipeline (regex · entropy · gliner · contextgate)
  firewall/               — OS firewall rules (macOS pf, Linux iptables, Windows netsh)
  lifecycle/              — Singleton lock + orphan reaping
  store/                  — BoltDB scan report persistence
  server/                 — Control plane (redactr-server):
    store/                — Embedded pure-Go SQLite (orgs/devices/tokens/policies/events/images)
    auth/                 — Device bearer tokens, enrollment, RequireDevice/RequireAdmin
    keys/                 — Load-or-generate server ECDSA keypair
    httpapi/              — Routes + embedded admin dashboard
    imagebuild/           — Dockerfile build → push → cosign-sign orchestration
build/sandbox/            — redactr-base image + container entrypoint (default-deny egress)
sidecar/gliner/           — Python Flask server for the GLiNER model
benchmarks/               — Benchmark harness + ai4privacy test data
docs/superpowers/         — Architecture spec, subsystem designs, and implementation plans
```

## Roadmap

Shipped and tested in this release: the proxy + scanner, the control plane (enrollment, signed policy, monitoring, image pipeline orchestration), the sandbox engine, and all three binaries with the four front doors.

Runtime integrations validated behind seams and slated for hardware-equipped CI: live `docker build` / `cosign sign` / registry push, VS Code `devcontainer up` attach, and the Windows system-tray (CGo) runtime.

## Contributing

Issues and PRs are welcome. Please run `go build ./...`, `go vet ./...`, and `go test ./...` before opening a PR — CI runs the same on macOS plus Windows/Linux cross-compiles.

## License

[MIT](LICENSE) © 2026 redactrai
